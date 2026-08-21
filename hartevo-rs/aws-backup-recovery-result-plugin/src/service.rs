//! Typed service, proposal, verification, and reversible registration.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsBackupConsumer;
use crate::error::{AwsBackupRecoveryError, AwsBackupTransportError, Result};
use crate::model::{
    AwsBackupRecoveryScope, ConsentScope, Cursor, Digest, EvidenceDigests, PermissionSnapshot,
    ProjectProjection, RecoveryEvidenceState, RecoveryPointFilter, RecoveryPointMetadata,
    RecoveryPointProjection, SecretReference, TransportProvenance, WorkProductProjection,
    mission_projection, project_projection, work_product_projection,
};
use crate::provider::{
    AwsBackupOperation, AwsBackupProvider, AwsBackupProviderDefinition,
    DescribeRecoveryPointRequest, ListRecoveryPointsRequest,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
    contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "aws-backup-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("new", format!("{new_status:?}")),
                ("registration", registration_digest.as_str().to_owned()),
            ],
        );
        Self {
            previous_status,
            new_status,
            registration_digest,
            transition_digest,
        }
    }
}

/// Version/contract/provider/permission/consent/scope/secret-bound
/// registration. The secret handle itself is never retained or serialized.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsBackupRecoveryRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: AwsBackupRecoveryScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl AwsBackupRecoveryRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsBackupRecoveryScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsBackupProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_snapshot,
            consent,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            binding_digest: Digest::from_text("unsealed-aws-backup-registration"),
        };
        registration.binding_digest = registration.calculate_binding_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub fn provider_release(&self) -> &str {
        &self.provider_release
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest()
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn scope(&self) -> &AwsBackupRecoveryScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_id(&self.id)
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(AwsBackupRecoveryError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        if self
            .permission_snapshot
            .permissions
            .iter()
            .any(|permission| !self.consent.permissions().contains(permission))
        {
            return Err(AwsBackupRecoveryError::InvalidConsent);
        }
        self.consent.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsBackupRecoveryError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsBackupRecoveryError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsBackupRecoveryError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-backup-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("consent", self.consent.digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

pub type AwsBackupRegistration = AwsBackupRecoveryRegistration;

impl fmt::Debug for AwsBackupRecoveryRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsBackupRecoveryRegistration")
            .field("id", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for AwsBackupRecoveryRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsBackupRecoveryRegistration", 16)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.binding_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryEvidenceRequest {
    pub scope_digest: Digest,
    pub filter: RecoveryPointFilter,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub max_pages: u16,
    pub observed_at: DateTime<Utc>,
}

impl RecoveryEvidenceRequest {
    pub fn new(
        scope: &AwsBackupRecoveryScope,
        filter: RecoveryPointFilter,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        filter.validate_against(scope)?;
        if max_pages == 0 || max_pages > crate::MAX_PAGES {
            return Err(AwsBackupRecoveryError::InvalidRequest);
        }
        expected_provider_digest.validate()?;
        expected_registration_digest.validate()?;
        Ok(Self {
            scope_digest: scope.digest(),
            filter,
            expected_provider_digest,
            expected_registration_digest,
            max_pages,
            observed_at,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-backup-recovery-evidence-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter.digest().as_str().to_owned()),
                (
                    "provider",
                    self.expected_provider_digest.as_str().to_owned(),
                ),
                (
                    "registration",
                    self.expected_registration_digest.as_str().to_owned(),
                ),
                ("max_pages", self.max_pages.to_string()),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: AwsBackupOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(operation: AwsBackupOperation, error: &AwsBackupTransportError) -> Self {
        let category = match error {
            AwsBackupTransportError::BlockedEnv => "blocked_env",
            AwsBackupTransportError::BadRequest => "bad_request",
            AwsBackupTransportError::Unauthorized => "unauthorized",
            AwsBackupTransportError::Forbidden => "forbidden",
            AwsBackupTransportError::NotFound => "not_found",
            AwsBackupTransportError::Conflict => "conflict",
            AwsBackupTransportError::RateLimited { .. } => "throttled",
            AwsBackupTransportError::ServerError { .. } => "server_error",
            AwsBackupTransportError::Timeout => "timeout",
            AwsBackupTransportError::AccessLost => "access_loss",
            AwsBackupTransportError::Partial => "partial",
            AwsBackupTransportError::InvalidResponse => "invalid_response",
        }
        .to_owned();
        let failure_digest = Digest::from_parts(
            "aws-backup-failure/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("category", category.clone()),
                (
                    "status",
                    error
                        .status_code()
                        .map_or_else(String::new, |status| status.to_string()),
                ),
            ],
        );
        Self {
            operation,
            status_code: error.status_code(),
            category,
            failure_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsBackupRecoveryProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub account_digest: Digest,
    pub region_digest: Digest,
    pub vault_digest: Digest,
    pub recovery_point_digest: Digest,
    pub resource_digest: Digest,
    pub plan_digest: Digest,
    pub mission: crate::model::MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: RecoveryEvidenceState,
    pub list_pages: u16,
    pub list_complete: bool,
    pub recovery_point: Option<RecoveryPointProjection>,
    pub failure: Option<FailureEvidence>,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub recoverability_claim: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsBackupRecoveryProposal {
    fn new(
        registration: &AwsBackupRecoveryRegistration,
        provider: &AwsBackupProviderDefinition,
        request: &RecoveryEvidenceRequest,
        state: RecoveryEvidenceState,
        list_pages: u16,
        list_complete: bool,
        list_digest: Option<Digest>,
        cursor_digest: Option<Digest>,
        describe_digest: Option<Digest>,
        metadata: Option<&RecoveryPointMetadata>,
        failure: Option<FailureEvidence>,
        provenance: TransportProvenance,
    ) -> Self {
        let recovery_point = metadata
            .map(|metadata| RecoveryPointProjection::from_metadata(registration.scope(), metadata));
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_digest: registration.permission_digest(),
            consent_digest: registration.consent_digest(),
            scope_digest: registration.scope_digest.clone(),
            filter_digest: request.filter.digest(),
            cursor_digest,
            list_digest,
            describe_digest,
            evidence_digest: Digest::from_text("unsealed-aws-backup-evidence"),
        };
        evidence.evidence_digest = calculate_evidence_digest(
            &evidence,
            state,
            list_pages,
            list_complete,
            recovery_point.as_ref(),
            failure.as_ref(),
        );
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: registration.scope_digest.clone(),
            account_digest: registration.scope.account().digest(),
            region_digest: registration.scope.region().digest(),
            vault_digest: registration.scope.vault().digest(),
            recovery_point_digest: registration.scope.recovery_point().digest(),
            resource_digest: registration.scope.resource().digest(),
            plan_digest: registration.scope.plan().digest(),
            mission: mission_projection(registration.scope.mission()),
            project: project_projection(registration.scope.project()),
            work_product: work_product_projection(registration.scope.work_product()),
            state,
            list_pages,
            list_complete,
            recovery_point,
            failure,
            evidence,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            recoverability_claim: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-aws-backup-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.contract_digest.validate()?;
        self.evidence.provider_digest.validate()?;
        self.evidence.permission_digest.validate()?;
        self.evidence.consent_digest.validate()?;
        self.evidence.scope_digest.validate()?;
        self.evidence.filter_digest.validate()?;
        self.evidence
            .cursor_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence
            .list_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence
            .describe_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence.evidence_digest.validate()?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.recoverability_claim
            || self.outcome_adopted
            || self.work_product_adopted
            || self.evidence.evidence_digest
                != calculate_evidence_digest(
                    &self.evidence,
                    self.state,
                    self.list_pages,
                    self.list_complete,
                    self.recovery_point.as_ref(),
                    self.failure.as_ref(),
                )
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AwsBackupRecoveryError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-backup-recovery-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("account", self.account_digest.as_str().to_owned()),
                ("region", self.region_digest.as_str().to_owned()),
                ("vault", self.vault_digest.as_str().to_owned()),
                (
                    "recovery_point",
                    self.recovery_point_digest.as_str().to_owned(),
                ),
                ("resource", self.resource_digest.as_str().to_owned()),
                ("plan", self.plan_digest.as_str().to_owned()),
                (
                    "mission",
                    serde_json::to_string(&self.mission).expect("mission projection serializes"),
                ),
                (
                    "project",
                    serde_json::to_string(&self.project).expect("project projection serializes"),
                ),
                (
                    "work_product",
                    serde_json::to_string(&self.work_product)
                        .expect("work product projection serializes"),
                ),
                ("state", format!("{:?}", self.state)),
                ("list_pages", self.list_pages.to_string()),
                ("list_complete", self.list_complete.to_string()),
                (
                    "recovery_point_metadata",
                    self.recovery_point
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            serde_json::to_string(value)
                                .expect("recovery point projection serializes")
                        }),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("failure evidence serializes")
                    }),
                ),
                (
                    "evidence",
                    serde_json::to_string(&self.evidence).expect("evidence digests serialize"),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    PermissionDigestMismatch,
    ConsentDigestMismatch,
    ScopeDigestMismatch,
    FilterDigestMismatch,
    EvidenceDigestMismatch,
    ProposalDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    ExpiredEvidence,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    RecoveryPointReplaced,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn new(valid: bool, review_eligible: bool, failures: Vec<VerificationFailure>) -> Self {
        let verification_digest = Digest::from_parts(
            "aws-backup-verification-report/v1",
            &[
                ("valid", valid.to_string()),
                ("review_eligible", review_eligible.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|failure| format!("{failure:?}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Self {
            valid,
            review_eligible,
            failures,
            verification_digest,
        }
    }
}

pub struct AwsBackupRecoveryService<T: crate::provider::AwsBackupTransport> {
    registration: AwsBackupRecoveryRegistration,
    provider: AwsBackupProvider<T>,
}

impl<T: crate::provider::AwsBackupTransport> fmt::Debug for AwsBackupRecoveryService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsBackupRecoveryService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: crate::provider::AwsBackupTransport> AwsBackupRecoveryService<T> {
    pub fn new(
        scope: AwsBackupRecoveryScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AwsBackupProvider<T>,
        registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        Self::with_registration(
            "aws-backup-registration",
            scope,
            secret_reference,
            PermissionSnapshot::for_layer_one(1),
            consent,
            provider,
            1,
            registration_time,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_registration(
        registration_id: impl Into<String>,
        scope: AwsBackupRecoveryScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: AwsBackupProvider<T>,
        registration_revision: u64,
        _registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = AwsBackupRecoveryRegistration::new(
            registration_id,
            scope,
            secret_reference,
            permission_snapshot,
            consent,
            provider.definition(),
            registration_revision,
        )?;
        Ok(Self {
            registration,
            provider,
        })
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec![
                AwsBackupOperation::ListRecoveryPointsByBackupVault
                    .as_str()
                    .to_owned(),
                AwsBackupOperation::DescribeRecoveryPoint
                    .as_str()
                    .to_owned(),
            ],
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
        }
    }

    pub fn scope(&self) -> &AwsBackupRecoveryScope {
        self.registration.scope()
    }

    pub fn registration(&self) -> &AwsBackupRecoveryRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsBackupRecoveryRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsBackupProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsBackupProvider<T> {
        &mut self.provider
    }

    pub fn request(
        &self,
        filter: RecoveryPointFilter,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<RecoveryEvidenceRequest> {
        RecoveryEvidenceRequest::new(
            self.scope(),
            filter,
            self.provider.definition().provider_digest.clone(),
            self.registration.registration_digest().clone(),
            max_pages,
            observed_at,
        )
    }

    pub fn default_request(&self, observed_at: DateTime<Utc>) -> Result<RecoveryEvidenceRequest> {
        let filter = RecoveryPointFilter::for_scope(self.scope(), 10, None, None)?;
        self.request(filter, 1, observed_at)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn consumer(&self) -> Result<MissionAwsBackupConsumer> {
        MissionAwsBackupConsumer::new(self.scope().clone(), self.registration.clone())
    }

    pub fn verify(&self, proposal: &AwsBackupRecoveryProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.provider_digest != self.provider.definition().provider_digest {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.permission_digest != self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.consent_digest != self.registration.consent_digest() {
            failures.push(VerificationFailure::ConsentDigestMismatch);
        }
        if proposal.scope_digest != *self.registration.scope_digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            RecoveryEvidenceState::Partial => failures.push(VerificationFailure::PartialEvidence),
            RecoveryEvidenceState::Expired => failures.push(VerificationFailure::ExpiredEvidence),
            RecoveryEvidenceState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            RecoveryEvidenceState::Throttled => failures.push(VerificationFailure::Throttled),
            RecoveryEvidenceState::ProviderUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            RecoveryEvidenceState::NotFound => failures.push(VerificationFailure::ProviderUnknown),
            RecoveryEvidenceState::RegistrationRevoked => {
                failures.push(VerificationFailure::RegistrationInactive);
            }
            RecoveryEvidenceState::Completed
            | RecoveryEvidenceState::InProgress
            | RecoveryEvidenceState::Deleting
            | RecoveryEvidenceState::Stopped => {}
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        VerificationReport::new(
            valid,
            valid && proposal.state.is_review_complete(),
            failures,
        )
    }

    pub fn propose(
        &mut self,
        request: RecoveryEvidenceRequest,
    ) -> Result<AwsBackupRecoveryProposal> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsBackupRecoveryError::RegistrationInactive);
        }
        if request.scope_digest != *self.registration.scope_digest()
            || request.expected_provider_digest != self.provider.definition().provider_digest
            || request.expected_registration_digest != *self.registration.registration_digest()
        {
            return Err(AwsBackupRecoveryError::ScopeMismatch);
        }
        request.filter.validate_against(self.scope())?;
        if self.registration.consent().is_revoked() {
            return Err(AwsBackupRecoveryError::ConsentRevoked);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at)
        {
            return Err(AwsBackupRecoveryError::ConsentExpired);
        }

        let mut cursor: Option<Cursor> = None;
        let mut list_pages = 0_u16;
        let mut list_complete = false;
        let mut list_digests = Vec::new();
        let mut target_from_list: Option<RecoveryPointMetadata> = None;
        let mut final_cursor_digest = None;
        loop {
            if list_pages >= request.max_pages {
                break;
            }
            let list_request = ListRecoveryPointsRequest::new(
                self.scope(),
                request.filter.clone(),
                cursor.clone(),
            )?;
            let response = match self.provider.list_recovery_points(&list_request) {
                Ok(response) => response,
                Err(error) => {
                    let state = state_from_transport(&error);
                    let failure = FailureEvidence::from_transport(
                        AwsBackupOperation::ListRecoveryPointsByBackupVault,
                        &error,
                    );
                    return Ok(AwsBackupRecoveryProposal::new(
                        &self.registration,
                        self.provider.definition(),
                        &request,
                        state,
                        list_pages,
                        false,
                        nonempty_digest(&list_digests),
                        final_cursor_digest,
                        None,
                        None,
                        Some(failure),
                        self.provider.provenance(),
                    ));
                }
            };
            list_pages = list_pages.saturating_add(1);
            list_digests.push(response.evidence_digest.clone());
            for point in &response.recovery_points {
                if point.recovery_point().digest() == self.scope().recovery_point().digest() {
                    if let Some(previous) = &target_from_list {
                        if previous.digest() != point.digest() {
                            return Ok(self.proposal_with_state(
                                &request,
                                RecoveryEvidenceState::Partial,
                                list_pages,
                                false,
                                nonempty_digest(&list_digests),
                                final_cursor_digest,
                                None,
                                None,
                                Some(FailureEvidence {
                                    operation: AwsBackupOperation::ListRecoveryPointsByBackupVault,
                                    status_code: None,
                                    category: "recovery_point_replaced".to_owned(),
                                    failure_digest: Digest::from_text(
                                        "aws-backup-recovery-point-replaced",
                                    ),
                                }),
                            ));
                        }
                    }
                    target_from_list = Some(point.clone());
                }
            }
            if response.has_more() {
                final_cursor_digest = response
                    .next_cursor
                    .as_ref()
                    .map(|value| value.token_digest().clone());
                cursor = response.next_cursor.clone();
                if cursor.is_none() {
                    break;
                }
            } else {
                list_complete = true;
                break;
            }
        }

        let list_digest = nonempty_digest(&list_digests);
        if !list_complete {
            final_cursor_digest = cursor.as_ref().map(|value| value.token_digest().clone());
        }

        let describe_request = DescribeRecoveryPointRequest::for_scope(self.scope())?;
        let describe_response = match self.provider.describe_recovery_point(&describe_request) {
            Ok(response) => response,
            Err(error) => {
                let state = state_from_transport(&error);
                let failure = FailureEvidence::from_transport(
                    AwsBackupOperation::DescribeRecoveryPoint,
                    &error,
                );
                return Ok(AwsBackupRecoveryProposal::new(
                    &self.registration,
                    self.provider.definition(),
                    &request,
                    if !list_complete {
                        RecoveryEvidenceState::Partial
                    } else {
                        state
                    },
                    list_pages,
                    list_complete,
                    list_digest,
                    final_cursor_digest,
                    None,
                    None,
                    Some(failure),
                    self.provider.provenance(),
                ));
            }
        };
        let describe_digest = Some(describe_response.evidence_digest.clone());
        let metadata = describe_response.metadata.clone();
        if let Some(listed) = &target_from_list {
            if listed.digest() != metadata.digest() {
                return Ok(self.proposal_with_state(
                    &request,
                    RecoveryEvidenceState::Partial,
                    list_pages,
                    list_complete,
                    list_digest,
                    final_cursor_digest,
                    describe_digest,
                    Some(&metadata),
                    Some(FailureEvidence {
                        operation: AwsBackupOperation::DescribeRecoveryPoint,
                        status_code: None,
                        category: "recovery_point_replaced".to_owned(),
                        failure_digest: Digest::from_text("aws-backup-recovery-point-replaced"),
                    }),
                ));
            }
        } else if list_complete {
            return Ok(self.proposal_with_state(
                &request,
                RecoveryEvidenceState::NotFound,
                list_pages,
                true,
                list_digest,
                final_cursor_digest,
                describe_digest,
                Some(&metadata),
                Some(FailureEvidence {
                    operation: AwsBackupOperation::ListRecoveryPointsByBackupVault,
                    status_code: Some(404),
                    category: "recovery_point_replaced".to_owned(),
                    failure_digest: Digest::from_text("aws-backup-recovery-point-replaced"),
                }),
            ));
        }
        let state = state_from_metadata(&metadata, request.observed_at, !list_complete);
        Ok(self.proposal_with_state(
            &request,
            state,
            list_pages,
            list_complete,
            list_digest,
            final_cursor_digest,
            describe_digest,
            Some(&metadata),
            None,
        ))
    }

    fn proposal_with_state(
        &self,
        request: &RecoveryEvidenceRequest,
        state: RecoveryEvidenceState,
        list_pages: u16,
        list_complete: bool,
        list_digest: Option<Digest>,
        cursor_digest: Option<Digest>,
        describe_digest: Option<Digest>,
        metadata: Option<&RecoveryPointMetadata>,
        failure: Option<FailureEvidence>,
    ) -> AwsBackupRecoveryProposal {
        AwsBackupRecoveryProposal::new(
            &self.registration,
            self.provider.definition(),
            request,
            state,
            list_pages,
            list_complete,
            list_digest,
            cursor_digest,
            describe_digest,
            metadata,
            failure,
            self.provider.provenance(),
        )
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn nonempty_digest(values: &[Digest]) -> Option<Digest> {
    (!values.is_empty()).then(|| {
        Digest::from_parts(
            "aws-backup-list-pages/v1",
            &[(
                "pages",
                values
                    .iter()
                    .map(|digest| digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        )
    })
}

fn state_from_transport(error: &AwsBackupTransportError) -> RecoveryEvidenceState {
    match error {
        AwsBackupTransportError::Unauthorized
        | AwsBackupTransportError::Forbidden
        | AwsBackupTransportError::AccessLost => RecoveryEvidenceState::AccessLoss,
        AwsBackupTransportError::RateLimited { .. } => RecoveryEvidenceState::Throttled,
        AwsBackupTransportError::NotFound => RecoveryEvidenceState::NotFound,
        AwsBackupTransportError::Partial => RecoveryEvidenceState::Partial,
        AwsBackupTransportError::BlockedEnv
        | AwsBackupTransportError::BadRequest
        | AwsBackupTransportError::Conflict
        | AwsBackupTransportError::ServerError { .. }
        | AwsBackupTransportError::Timeout
        | AwsBackupTransportError::InvalidResponse => RecoveryEvidenceState::ProviderUnknown,
    }
}

fn state_from_metadata(
    metadata: &RecoveryPointMetadata,
    observed_at: DateTime<Utc>,
    partial_list: bool,
) -> RecoveryEvidenceState {
    if partial_list {
        return RecoveryEvidenceState::Partial;
    }
    if metadata.lifecycle().is_expired_at(observed_at)
        || matches!(
            metadata.status(),
            crate::model::RecoveryPointStatus::Expired
        )
        || matches!(
            metadata.storage_class(),
            crate::model::StorageClass::Deleted
        )
    {
        return RecoveryEvidenceState::Expired;
    }
    match metadata.status() {
        crate::model::RecoveryPointStatus::Creating => RecoveryEvidenceState::InProgress,
        crate::model::RecoveryPointStatus::Completed
        | crate::model::RecoveryPointStatus::Available => RecoveryEvidenceState::Completed,
        crate::model::RecoveryPointStatus::Partial => RecoveryEvidenceState::Partial,
        crate::model::RecoveryPointStatus::Deleting => RecoveryEvidenceState::Deleting,
        crate::model::RecoveryPointStatus::Stopped => RecoveryEvidenceState::Stopped,
        crate::model::RecoveryPointStatus::Expired => RecoveryEvidenceState::Expired,
    }
}

fn calculate_evidence_digest(
    evidence: &EvidenceDigests,
    state: RecoveryEvidenceState,
    list_pages: u16,
    list_complete: bool,
    metadata: Option<&RecoveryPointProjection>,
    failure: Option<&FailureEvidence>,
) -> Digest {
    Digest::from_parts(
        "aws-backup-recovery-evidence/v1",
        &[
            (
                "plugin_version",
                evidence.plugin_version_digest.as_str().to_owned(),
            ),
            ("contract", evidence.contract_digest.as_str().to_owned()),
            ("provider", evidence.provider_digest.as_str().to_owned()),
            ("permission", evidence.permission_digest.as_str().to_owned()),
            ("consent", evidence.consent_digest.as_str().to_owned()),
            ("scope", evidence.scope_digest.as_str().to_owned()),
            ("filter", evidence.filter_digest.as_str().to_owned()),
            (
                "cursor",
                evidence
                    .cursor_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "list",
                evidence
                    .list_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "describe",
                evidence
                    .describe_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            ("state", format!("{state:?}")),
            ("list_pages", list_pages.to_string()),
            ("list_complete", list_complete.to_string()),
            (
                "metadata",
                metadata.map_or_else(String::new, |value| {
                    serde_json::to_string(value).expect("metadata projection serializes")
                }),
            ),
            (
                "failure",
                failure.map_or_else(String::new, |value| {
                    serde_json::to_string(value).expect("failure evidence serializes")
                }),
            ),
        ],
    )
}
