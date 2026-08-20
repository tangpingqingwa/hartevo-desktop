//! Registration, bounded read/proposal, recording, and verification seams.

use std::{collections::BTreeMap, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::model::{
    ActionExecutionFilter, ActionExecutionsProjection, AwsCodePipelineScope, Digest, EvidenceState,
    FailureMetadata, MissionProjection, PermissionSnapshot, PipelineExecutionFilter,
    PipelineExecutionsProjection, PipelineStateRecord, ProjectProjection, ProviderIdentity,
    RedactionEvidence, RetryEvidence, SecretReference, StageActionTransition, TransportProvenance,
    WorkProductProjection,
};
use crate::provider::AwsCodePipelineProvider;
use crate::{
    AwsCodePipelineReleaseError, AwsCodePipelineTransportError, CONTRACT_DIGEST, CONTRACT_VERSION,
    MAX_PAGE_SIZE, MAX_PAGES, PLUGIN_VERSION, PROVIDER_ID, Result, SERVICE_ID,
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
    pub current_status: RegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        current_status: RegistrationStatus,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "aws-codepipeline-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("current", format!("{current_status:?}")),
                ("registration", registration_digest.as_str().to_owned()),
            ],
        );
        Self {
            previous_status,
            current_status,
            registration_digest,
            transition_digest,
        }
    }
}

/// Registration binds version, contract, provider, permission, scope, secret
/// reference digest, and registration revision. The opaque SecretReference is
/// never serialized; only its digest is emitted.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsCodePipelineRegistration {
    id: crate::model::RegistrationId,
    scope: AwsCodePipelineScope,
    secret_reference: SecretReference,
    permission_snapshot: PermissionSnapshot,
    provider_identity: ProviderIdentity,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    registration_revision: crate::model::Revision,
    status: RegistrationStatus,
    registration_digest: Digest,
    revocation_digest: Option<Digest>,
}

impl fmt::Debug for AwsCodePipelineRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCodePipelineRegistration")
            .field("id", &self.id.digest())
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("scope_digest", self.scope.digest())
            .field("provider_identity", &self.provider_identity)
            .field("permission_digest", self.permission_snapshot.digest())
            .field(
                "secret_reference_digest",
                self.secret_reference.reference_digest(),
            )
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .field("revocation_digest", &self.revocation_digest)
            .finish()
    }
}

impl Serialize for AwsCodePipelineRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsCodePipelineRegistration", 15)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_identity.provider_id)?;
        state.serialize_field(
            "providerRevision",
            &self.provider_identity.provider_revision,
        )?;
        state.serialize_field("providerDigest", &self.provider_identity.provider_digest)?;
        state.serialize_field("permissionDigest", self.permission_snapshot.digest())?;
        state.serialize_field("scopeDigest", self.scope.digest())?;
        state.serialize_field(
            "secretReferenceDigest",
            self.secret_reference.reference_digest(),
        )?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.serialize_field("revocationDigest", &self.revocation_digest)?;
        state.serialize_field("connected", &false)?;
        state.end()
    }
}

impl AwsCodePipelineRegistration {
    pub fn new(
        id: crate::model::RegistrationId,
        scope: AwsCodePipelineScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider_identity: ProviderIdentity,
        registration_revision: u64,
    ) -> Result<Self> {
        scope.validate()?;
        secret_reference.validate()?;
        permission_snapshot.validate()?;
        provider_identity.validate()?;
        let registration_revision = crate::model::Revision::new(registration_revision)?;
        let mut registration = Self {
            id,
            scope,
            secret_reference,
            permission_snapshot,
            provider_identity,
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST)?,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-aws-codepipeline-registration"),
            revocation_digest: None,
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn for_scope(
        scope: AwsCodePipelineScope,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        Self::new(
            crate::model::RegistrationId::new("aws-codepipeline-registration")?,
            scope,
            secret_reference,
            PermissionSnapshot::read_only(1)?,
            ProviderIdentity::layer_one(),
            1,
        )
    }

    pub fn id(&self) -> &crate::model::RegistrationId {
        &self.id
    }

    pub fn scope(&self) -> &AwsCodePipelineScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        self.scope.digest()
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_mut(&mut self) -> &mut SecretReference {
        &mut self.secret_reference
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> &Digest {
        self.permission_snapshot.digest()
    }

    pub fn provider_identity(&self) -> &ProviderIdentity {
        &self.provider_identity
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_identity.provider_digest
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

    pub const fn registration_revision(&self) -> crate::model::Revision {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn revocation_digest(&self) -> Option<&Digest> {
        self.revocation_digest.as_ref()
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.secret_reference.validate()?;
        self.permission_snapshot.validate()?;
        self.provider_identity.validate()?;
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.provider_identity.provider_id != PROVIDER_ID
            || self.registration_revision.get() == 0
            || self.registration_digest != self.calculate_digest()
        {
            return Err(AwsCodePipelineReleaseError::RegistrationDrift);
        }
        if let Some(digest) = &self.revocation_digest {
            digest.validate()?;
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsCodePipelineReleaseError::RegistrationReversed);
        }
        if matches!(self.status, RegistrationStatus::Revoked) {
            return Err(AwsCodePipelineReleaseError::RegistrationRevoked);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.calculate_digest();
        self.revocation_digest = Some(Digest::from_parts(
            "aws-codepipeline-revocation/v1",
            &[
                ("registration", self.registration_digest.as_str().to_owned()),
                ("status", format!("{previous_status:?}->Revoked")),
            ],
        ));
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsCodePipelineReleaseError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsCodePipelineReleaseError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-registration/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("plugin", self.plugin_version.clone()),
                ("contract", self.contract_version.clone()),
                ("contract_digest", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_identity.provider_id.clone()),
                (
                    "provider_revision",
                    self.provider_identity.provider_revision.get().to_string(),
                ),
                (
                    "provider_digest",
                    self.provider_identity.provider_digest.as_str().to_owned(),
                ),
                (
                    "permission",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("scope", self.scope.digest().as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                (
                    "registration_revision",
                    self.registration_revision.get().to_string(),
                ),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCodePipelineRegistrationReceipt {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub status: RegistrationStatus,
    pub registration_revision: crate::model::Revision,
}

pub type RegistrationReceipt = AwsCodePipelineRegistrationReceipt;

#[derive(Clone, Debug, Default)]
pub struct AwsCodePipelineRegistrationRegistry {
    registrations: BTreeMap<crate::model::RegistrationId, AwsCodePipelineRegistration>,
}

impl AwsCodePipelineRegistrationRegistry {
    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }

    pub fn get(&self, id: &crate::model::RegistrationId) -> Option<&AwsCodePipelineRegistration> {
        self.registrations.get(id)
    }

    pub fn register(
        &mut self,
        registration: AwsCodePipelineRegistration,
    ) -> Result<RegistrationReceipt> {
        registration.validate()?;
        if self.registrations.contains_key(registration.id()) {
            return Err(AwsCodePipelineReleaseError::RegistrationAlreadyExists);
        }
        let receipt = RegistrationReceipt {
            registration_digest: registration.registration_digest().clone(),
            scope_digest: registration.scope_digest().clone(),
            status: registration.status(),
            registration_revision: registration.registration_revision(),
        };
        self.registrations
            .insert(registration.id().clone(), registration);
        Ok(receipt)
    }

    pub fn revoke(&mut self, id: &crate::model::RegistrationId) -> Result<RegistrationReceipt> {
        let registration = self
            .registrations
            .get_mut(id)
            .ok_or(AwsCodePipelineReleaseError::RegistrationUnknown)?;
        registration.revoke()?;
        Ok(receipt_for(registration))
    }

    pub fn restore(&mut self, id: &crate::model::RegistrationId) -> Result<RegistrationReceipt> {
        let registration = self
            .registrations
            .get_mut(id)
            .ok_or(AwsCodePipelineReleaseError::RegistrationUnknown)?;
        registration.restore()?;
        Ok(receipt_for(registration))
    }

    pub fn reverse(&mut self, id: &crate::model::RegistrationId) -> Result<RegistrationReceipt> {
        let registration = self
            .registrations
            .get_mut(id)
            .ok_or(AwsCodePipelineReleaseError::RegistrationUnknown)?;
        registration.reverse()?;
        Ok(receipt_for(registration))
    }
}

fn receipt_for(registration: &AwsCodePipelineRegistration) -> RegistrationReceipt {
    RegistrationReceipt {
        registration_digest: registration.registration_digest().clone(),
        scope_digest: registration.scope_digest().clone(),
        status: registration.status(),
        registration_revision: registration.registration_revision(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCodePipelineCapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub artifact_download: bool,
    pub raw_logs: bool,
    pub outcome_adoption: bool,
}

pub type CapabilityDescription = AwsCodePipelineCapabilityDescription;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCodePipelineReadRequest {
    pub scope_digest: Digest,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub pipeline_filter: PipelineExecutionFilter,
    pub action_filter: ActionExecutionFilter,
    pub page_size: usize,
    pub max_pages: usize,
    pub observed_at: u64,
    pub request_digest: Digest,
}

impl AwsCodePipelineReadRequest {
    pub fn new(
        scope: &AwsCodePipelineScope,
        provider_identity: &ProviderIdentity,
        registration: &AwsCodePipelineRegistration,
        page_size: usize,
        max_pages: usize,
        observed_at: u64,
    ) -> Result<Self> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(AwsCodePipelineReleaseError::PaginationLimit);
        }
        if registration.scope_digest() != scope.digest()
            || registration.provider_digest() != &provider_identity.provider_digest
        {
            return Err(AwsCodePipelineReleaseError::ScopeMismatch);
        }
        let pipeline_filter = PipelineExecutionFilter::for_scope(scope);
        let action_filter = ActionExecutionFilter::for_scope(scope);
        let scope_digest = scope.digest().clone();
        let expected_provider_digest = provider_identity.provider_digest.clone();
        let expected_registration_digest = registration.registration_digest().clone();
        let request_digest = Digest::from_parts(
            "aws-codepipeline-release-read-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("provider", expected_provider_digest.as_str().to_owned()),
                (
                    "registration",
                    expected_registration_digest.as_str().to_owned(),
                ),
                (
                    "pipeline_filter",
                    pipeline_filter.digest().as_str().to_owned(),
                ),
                ("action_filter", action_filter.digest().as_str().to_owned()),
                ("page_size", page_size.to_string()),
                ("max_pages", max_pages.to_string()),
                ("observed_at", observed_at.to_string()),
            ],
        );
        Ok(Self {
            scope_digest,
            expected_provider_digest,
            expected_registration_digest,
            pipeline_filter,
            action_filter,
            page_size,
            max_pages,
            observed_at,
            request_digest,
        })
    }

    pub fn validate(&self, registration: &AwsCodePipelineRegistration) -> Result<()> {
        registration.validate()?;
        if self.scope_digest != *registration.scope_digest()
            || self.expected_provider_digest != *registration.provider_digest()
            || self.expected_registration_digest != *registration.registration_digest()
            || self
                .pipeline_filter
                .validate_against(registration.scope())
                .is_err()
            || self
                .action_filter
                .validate_against(registration.scope())
                .is_err()
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.request_digest != self.calculate_digest()
        {
            return Err(AwsCodePipelineReleaseError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-release-read-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "provider",
                    self.expected_provider_digest.as_str().to_owned(),
                ),
                (
                    "registration",
                    self.expected_registration_digest.as_str().to_owned(),
                ),
                (
                    "pipeline_filter",
                    self.pipeline_filter.digest().as_str().to_owned(),
                ),
                (
                    "action_filter",
                    self.action_filter.digest().as_str().to_owned(),
                ),
                ("page_size", self.page_size.to_string()),
                ("max_pages", self.max_pages.to_string()),
                ("observed_at", self.observed_at.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCodePipelineReleaseEvidence {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub pipeline_filter_digest: Digest,
    pub action_filter_digest: Digest,
    pub state: EvidenceState,
    pub pipeline_state: Option<PipelineStateRecord>,
    pub pipeline_execution: Option<PipelineStateRecord>,
    pub pipeline_executions: PipelineExecutionsProjection,
    pub action_executions: ActionExecutionsProjection,
    pub transition: Option<StageActionTransition>,
    pub retry: RetryEvidence,
    pub failure: Option<FailureMetadata>,
    pub redaction: RedactionEvidence,
    pub provenance: TransportProvenance,
    pub response_truncated: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub evidence_digest: Digest,
}

impl AwsCodePipelineReleaseEvidence {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &AwsCodePipelineRegistration,
        request: &AwsCodePipelineReadRequest,
        provider: &ProviderIdentity,
        state: EvidenceState,
        pipeline_state: Option<PipelineStateRecord>,
        pipeline_execution: Option<PipelineStateRecord>,
        pipeline_executions: PipelineExecutionsProjection,
        action_executions: ActionExecutionsProjection,
        transition: Option<StageActionTransition>,
        retry: RetryEvidence,
        failure: Option<FailureMetadata>,
        provenance: TransportProvenance,
    ) -> Self {
        let response_truncated = pipeline_executions.truncated || action_executions.truncated;
        let mut evidence = Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: crate::CONSUMER_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: registration.contract_digest().clone(),
            registration_digest: registration.registration_digest().clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_digest: registration.permission_digest().clone(),
            scope_digest: registration.scope_digest().clone(),
            request_digest: request.request_digest.clone(),
            pipeline_filter_digest: request.pipeline_filter.digest().clone(),
            action_filter_digest: request.action_filter.digest().clone(),
            state,
            pipeline_state,
            pipeline_execution,
            pipeline_executions,
            action_executions,
            transition,
            retry,
            failure,
            redaction: RedactionEvidence::standard(),
            provenance,
            response_truncated,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            evidence_digest: Digest::from_text("unsealed-aws-codepipeline-evidence"),
        };
        evidence.evidence_digest = evidence.calculate_digest();
        evidence
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.contract_digest.validate()?;
        self.registration_digest.validate()?;
        self.provider_digest.validate()?;
        self.permission_digest.validate()?;
        self.scope_digest.validate()?;
        self.request_digest.validate()?;
        self.pipeline_filter_digest.validate()?;
        self.action_filter_digest.validate()?;
        self.retry.validate(&self.request_digest)?;
        self.redaction.validate()?;
        if let Some(state) = &self.pipeline_state {
            state.validate_integrity()?;
        }
        if let Some(execution) = &self.pipeline_execution {
            execution.validate_integrity()?;
        }
        self.pipeline_executions.validate_integrity()?;
        self.action_executions.validate_integrity()?;
        if let Some(failure) = &self.failure {
            failure.validate()?;
        }
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != crate::CONSUMER_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.response_truncated
                != (self.pipeline_executions.truncated || self.action_executions.truncated)
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsCodePipelineReleaseError::InvalidProposal);
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        !self.response_truncated && self.state.is_review_complete()
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-release-evidence/v1",
            &[
                ("service", self.service_id.clone()),
                ("provider", self.provider_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("plugin", self.plugin_version.clone()),
                ("contract", self.contract_version.clone()),
                ("contract_digest", self.contract_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("provider_digest", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "pipeline_filter",
                    self.pipeline_filter_digest.as_str().to_owned(),
                ),
                (
                    "action_filter",
                    self.action_filter_digest.as_str().to_owned(),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "pipeline_state",
                    self.pipeline_state
                        .as_ref()
                        .map_or_else(String::new, |value| value.record_digest.as_str().to_owned()),
                ),
                (
                    "pipeline_execution",
                    self.pipeline_execution
                        .as_ref()
                        .map_or_else(String::new, |value| value.record_digest.as_str().to_owned()),
                ),
                (
                    "pipeline_executions",
                    self.pipeline_executions
                        .projection_digest
                        .as_str()
                        .to_owned(),
                ),
                (
                    "action_executions",
                    self.action_executions.projection_digest.as_str().to_owned(),
                ),
                (
                    "transition",
                    self.transition.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("transition serializes")
                    }),
                ),
                (
                    "retry",
                    serde_json::to_string(&self.retry).expect("retry evidence serializes"),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("failure metadata serializes")
                    }),
                ),
                (
                    "redaction",
                    self.redaction.redaction_digest.as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("truncated", self.response_truncated.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCodePipelineReleaseProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: EvidenceState,
    pub evidence: AwsCodePipelineReleaseEvidence,
    pub response_truncated: bool,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsCodePipelineReleaseProposal {
    fn from_evidence(
        evidence: AwsCodePipelineReleaseEvidence,
        scope: &AwsCodePipelineScope,
    ) -> Result<Self> {
        evidence.validate_integrity()?;
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: crate::CONSUMER_ID.to_owned(),
            registration_digest: evidence.registration_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            mission: MissionProjection::from(scope.mission()),
            project: ProjectProjection::from(scope.project()),
            work_product: WorkProductProjection::from(scope.work_product()),
            state: evidence.state,
            response_truncated: evidence.response_truncated,
            provenance: evidence.provenance,
            connected: false,
            native: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            evidence,
            proposal_digest: Digest::from_text("unsealed-aws-codepipeline-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        Ok(proposal)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate_integrity()?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != crate::CONSUMER_ID
            || self.registration_digest != self.evidence.registration_digest
            || self.scope_digest != self.evidence.scope_digest
            || self.state != self.evidence.state
            || self.response_truncated != self.evidence.response_truncated
            || self.provenance != self.evidence.provenance
            || self.connected
            || self.native
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.calculate_digest()
        {
            Err(AwsCodePipelineReleaseError::InvalidProposal)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-release-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
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
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("truncated", self.response_truncated.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsCodePipelineVerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    PermissionDigestMismatch,
    ScopeDigestMismatch,
    FilterDigestMismatch,
    EvidenceDigestMismatch,
    ProposalDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    AccessLoss,
    Retryable,
    Unknown,
    ExecutionReplaced,
    StageActionReplaced,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCodePipelineVerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<AwsCodePipelineVerificationFailure>,
    pub verification_digest: Digest,
}

impl AwsCodePipelineVerificationReport {
    fn new(
        valid: bool,
        review_eligible: bool,
        mut failures: Vec<AwsCodePipelineVerificationFailure>,
    ) -> Self {
        failures.sort_unstable();
        failures.dedup();
        let verification_digest = Digest::from_parts(
            "aws-codepipeline-verification-report/v1",
            &[
                ("valid", valid.to_string()),
                ("review_eligible", review_eligible.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|value| format!("{value:?}"))
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

pub struct AwsCodePipelineReleaseService<T: crate::provider::AwsCodePipelineTransport> {
    provider: AwsCodePipelineProvider<T>,
}

pub type AwsCodePipelineReleaseResultService<T> = AwsCodePipelineReleaseService<T>;

impl<T: crate::provider::AwsCodePipelineTransport> fmt::Debug for AwsCodePipelineReleaseService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCodePipelineReleaseService")
            .field("registration", self.provider.registration())
            .field("provenance", &self.provider.provenance())
            .finish()
    }
}

impl<T: crate::provider::AwsCodePipelineTransport> AwsCodePipelineReleaseService<T> {
    pub fn new(registration: AwsCodePipelineRegistration, transport: T) -> Result<Self> {
        Ok(Self {
            provider: AwsCodePipelineProvider::new(registration, transport)?,
        })
    }

    pub fn scope(&self) -> &AwsCodePipelineScope {
        self.provider.scope()
    }

    pub fn registration(&self) -> &AwsCodePipelineRegistration {
        self.provider.registration()
    }

    pub fn registration_mut(&mut self) -> &mut AwsCodePipelineRegistration {
        self.provider.registration_mut()
    }

    pub fn provider(&self) -> &AwsCodePipelineProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsCodePipelineProvider<T> {
        &mut self.provider
    }

    pub fn describe_capabilities(&self) -> AwsCodePipelineCapabilityDescription {
        AwsCodePipelineCapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: crate::CONSUMER_ID.to_owned(),
            operations: vec![
                "GetPipelineState".to_owned(),
                "GetPipelineExecution".to_owned(),
                "ListPipelineExecutions".to_owned(),
                "ListActionExecutions".to_owned(),
            ],
            permissions: self
                .registration()
                .permission_snapshot()
                .permissions()
                .iter()
                .cloned()
                .collect(),
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            artifact_download: false,
            raw_logs: false,
            outcome_adoption: false,
        }
    }

    pub fn request(
        &self,
        page_size: usize,
        max_pages: usize,
        observed_at: u64,
    ) -> Result<AwsCodePipelineReadRequest> {
        AwsCodePipelineReadRequest::new(
            self.scope(),
            self.provider.provider_identity(),
            self.registration(),
            page_size,
            max_pages,
            observed_at,
        )
    }

    pub fn register_scope(
        &self,
        registry: &mut AwsCodePipelineRegistrationRegistry,
    ) -> Result<RegistrationReceipt> {
        registry.register(self.registration().clone())
    }

    pub fn default_request(&self, observed_at: u64) -> Result<AwsCodePipelineReadRequest> {
        self.request(MAX_PAGE_SIZE, 1, observed_at)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration_mut().revoke()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration_mut().restore()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration_mut().reverse()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.reverse()
    }

    pub fn consumer(&self) -> Result<crate::consumer::MissionAwsCodePipelineConsumer> {
        crate::consumer::MissionAwsCodePipelineConsumer::new(
            self.scope().clone(),
            self.registration().clone(),
        )
    }

    pub fn read(
        &mut self,
        request: AwsCodePipelineReadRequest,
    ) -> Result<AwsCodePipelineReleaseEvidence> {
        self.read_bounded(request)
    }

    pub fn read_bounded(
        &mut self,
        request: AwsCodePipelineReadRequest,
    ) -> Result<AwsCodePipelineReleaseEvidence> {
        request.validate(self.registration())?;
        if !self.registration().is_active() {
            return Err(AwsCodePipelineReleaseError::RegistrationInactive);
        }
        let provider_identity = self.provider.provider_identity().clone();
        let empty_pipeline = || {
            PipelineExecutionsProjection::new(Vec::new(), 1, false, true, None)
                .expect("empty bounded pipeline projection")
        };
        let empty_actions = || {
            ActionExecutionsProjection::new(Vec::new(), 1, false, true, None)
                .expect("empty bounded action projection")
        };

        let pipeline_state = match self.provider.get_pipeline_state() {
            Ok(response) => Some(response.state),
            Err(error) if recoverable_to_evidence(&error) => {
                return Ok(AwsCodePipelineReleaseEvidence::new(
                    self.registration(),
                    &request,
                    &provider_identity,
                    state_from_error(&error),
                    None,
                    None,
                    empty_pipeline(),
                    empty_actions(),
                    None,
                    retry_from_error(&error, &request.request_digest),
                    failure_from_error(crate::model::ReadOperation::GetPipelineState, &error),
                    self.provider.provenance(),
                ));
            }
            Err(error) => return Err(error),
        };

        let pipeline_execution = match self.provider.get_pipeline_execution() {
            Ok(response) => Some(response.state),
            Err(error) if recoverable_to_evidence(&error) => {
                return Ok(AwsCodePipelineReleaseEvidence::new(
                    self.registration(),
                    &request,
                    &provider_identity,
                    state_from_error(&error),
                    pipeline_state,
                    None,
                    empty_pipeline(),
                    empty_actions(),
                    None,
                    retry_from_error(&error, &request.request_digest),
                    failure_from_error(crate::model::ReadOperation::GetPipelineExecution, &error),
                    self.provider.provenance(),
                ));
            }
            Err(error) => return Err(error),
        };

        let pipeline_executions = match self.provider.list_pipeline_executions(
            request.pipeline_filter.clone(),
            request.page_size,
            request.max_pages,
        ) {
            Ok(value) => value,
            Err(error) if recoverable_to_evidence(&error) => {
                return Ok(AwsCodePipelineReleaseEvidence::new(
                    self.registration(),
                    &request,
                    &provider_identity,
                    state_from_error(&error),
                    pipeline_state,
                    pipeline_execution,
                    empty_pipeline(),
                    empty_actions(),
                    None,
                    retry_from_error(&error, &request.request_digest),
                    failure_from_error(crate::model::ReadOperation::ListPipelineExecutions, &error),
                    self.provider.provenance(),
                ));
            }
            Err(error) => return Err(error),
        };

        let action_executions = match self.provider.list_action_executions(
            request.action_filter.clone(),
            request.page_size,
            request.max_pages,
        ) {
            Ok(value) => value,
            Err(error) if recoverable_to_evidence(&error) => {
                return Ok(AwsCodePipelineReleaseEvidence::new(
                    self.registration(),
                    &request,
                    &provider_identity,
                    state_from_error(&error),
                    pipeline_state,
                    pipeline_execution,
                    pipeline_executions,
                    empty_actions(),
                    None,
                    retry_from_error(&error, &request.request_digest),
                    failure_from_error(crate::model::ReadOperation::ListActionExecutions, &error),
                    self.provider.provenance(),
                ));
            }
            Err(error) => return Err(error),
        };

        let state = if pipeline_executions.truncated || action_executions.truncated {
            EvidenceState::Partial
        } else {
            pipeline_execution
                .as_ref()
                .map_or(EvidenceState::Unknown, state_from_execution)
        };
        let transition = match (&pipeline_state, &pipeline_execution) {
            (Some(previous), Some(current)) => current.transition_from(previous).ok(),
            _ => None,
        };
        Ok(AwsCodePipelineReleaseEvidence::new(
            self.registration(),
            &request,
            &provider_identity,
            state,
            pipeline_state,
            pipeline_execution,
            pipeline_executions,
            action_executions,
            transition,
            RetryEvidence::none(&request.request_digest),
            None,
            self.provider.provenance(),
        ))
    }

    pub fn propose(
        &mut self,
        request: AwsCodePipelineReadRequest,
    ) -> Result<AwsCodePipelineReleaseProposal> {
        let evidence = self.read_bounded(request)?;
        AwsCodePipelineReleaseProposal::from_evidence(evidence, self.scope())
    }

    pub fn compile_proposal(
        &mut self,
        request: AwsCodePipelineReadRequest,
    ) -> Result<AwsCodePipelineReleaseProposal> {
        self.propose(request)
    }

    pub fn record(
        &self,
        log: &mut crate::consumer::AwsCodePipelineRecordingLog,
        proposal: &AwsCodePipelineReleaseProposal,
        idempotency_key: &str,
    ) -> Result<crate::consumer::RecordedAwsCodePipelineResult> {
        let consumer = self.consumer()?;
        consumer.record(log, proposal, idempotency_key)
    }

    pub fn verify(
        &self,
        proposal: &AwsCodePipelineReleaseProposal,
    ) -> AwsCodePipelineVerificationReport {
        let mut failures = Vec::new();
        if !self.registration().is_active() {
            failures.push(AwsCodePipelineVerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration().registration_digest() {
            failures.push(AwsCodePipelineVerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.provider_digest != *self.registration().provider_digest() {
            failures.push(AwsCodePipelineVerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.permission_digest != *self.registration().permission_digest() {
            failures.push(AwsCodePipelineVerificationFailure::PermissionDigestMismatch);
        }
        if proposal.scope_digest != *self.registration().scope_digest() {
            failures.push(AwsCodePipelineVerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.pipeline_filter_digest
            != PipelineExecutionFilter::for_scope(self.scope()).filter_digest
            || proposal.evidence.action_filter_digest
                != ActionExecutionFilter::for_scope(self.scope()).filter_digest
        {
            failures.push(AwsCodePipelineVerificationFailure::FilterDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(AwsCodePipelineVerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            EvidenceState::Partial => {
                failures.push(AwsCodePipelineVerificationFailure::PartialEvidence);
            }
            EvidenceState::AccessLoss => {
                failures.push(AwsCodePipelineVerificationFailure::AccessLoss);
            }
            EvidenceState::Retryable => {
                failures.push(AwsCodePipelineVerificationFailure::Retryable);
            }
            EvidenceState::Unknown => failures.push(AwsCodePipelineVerificationFailure::Unknown),
            EvidenceState::ExecutionReplaced => {
                failures.push(AwsCodePipelineVerificationFailure::ExecutionReplaced);
            }
            EvidenceState::StageActionReplaced => {
                failures.push(AwsCodePipelineVerificationFailure::StageActionReplaced);
            }
            EvidenceState::Complete
            | EvidenceState::Queued
            | EvidenceState::InProgress
            | EvidenceState::Succeeded
            | EvidenceState::Failed
            | EvidenceState::Stopped
            | EvidenceState::Superseded
            | EvidenceState::Canceled
            | EvidenceState::RegistrationRevoked => {}
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        AwsCodePipelineVerificationReport::new(
            valid,
            valid && !proposal.response_truncated,
            failures,
        )
    }
}

fn state_from_execution(value: &PipelineStateRecord) -> EvidenceState {
    match value.execution_status {
        crate::model::PipelineExecutionStatus::Queued => EvidenceState::Queued,
        crate::model::PipelineExecutionStatus::InProgress => EvidenceState::InProgress,
        crate::model::PipelineExecutionStatus::Succeeded => EvidenceState::Succeeded,
        crate::model::PipelineExecutionStatus::Failed => EvidenceState::Failed,
        crate::model::PipelineExecutionStatus::Stopped => EvidenceState::Stopped,
        crate::model::PipelineExecutionStatus::Superseded => EvidenceState::Superseded,
        crate::model::PipelineExecutionStatus::Canceled => EvidenceState::Canceled,
        crate::model::PipelineExecutionStatus::Unknown => EvidenceState::Unknown,
    }
}

fn state_from_error(error: &AwsCodePipelineReleaseError) -> EvidenceState {
    match error {
        AwsCodePipelineReleaseError::Transport(value) if value.is_access_loss() => {
            EvidenceState::AccessLoss
        }
        AwsCodePipelineReleaseError::Transport(value) if value.is_retryable() => {
            EvidenceState::Retryable
        }
        AwsCodePipelineReleaseError::Transport(AwsCodePipelineTransportError::Partial)
        | AwsCodePipelineReleaseError::ResponseTooLarge
        | AwsCodePipelineReleaseError::TruncatedEvidence => EvidenceState::Partial,
        AwsCodePipelineReleaseError::ExecutionReplaced => EvidenceState::ExecutionReplaced,
        AwsCodePipelineReleaseError::StageActionReplaced => EvidenceState::StageActionReplaced,
        _ => EvidenceState::Unknown,
    }
}

fn retry_from_error(error: &AwsCodePipelineReleaseError, request_digest: &Digest) -> RetryEvidence {
    match error {
        AwsCodePipelineReleaseError::Transport(AwsCodePipelineTransportError::RateLimited {
            retry_after_seconds,
        }) => RetryEvidence::retryable(1, *retry_after_seconds, "429", request_digest),
        AwsCodePipelineReleaseError::Transport(value) if value.is_retryable() => {
            RetryEvidence::retryable(
                1,
                None,
                value.status_code().map_or(
                    "retry",
                    |value| {
                        if value >= 500 { "5xx" } else { "timeout" }
                    },
                ),
                request_digest,
            )
        }
        _ => RetryEvidence::none(request_digest),
    }
}

fn failure_from_error(
    operation: crate::model::ReadOperation,
    error: &AwsCodePipelineReleaseError,
) -> Option<FailureMetadata> {
    match error {
        AwsCodePipelineReleaseError::Transport(value) => {
            Some(FailureMetadata::from_transport(operation, value))
        }
        AwsCodePipelineReleaseError::ExecutionReplaced
        | AwsCodePipelineReleaseError::StageActionReplaced => {
            Some(FailureMetadata::from_transport(
                operation,
                &AwsCodePipelineTransportError::InvalidResponse,
            ))
        }
        _ => None,
    }
}

fn recoverable_to_evidence(error: &AwsCodePipelineReleaseError) -> bool {
    matches!(
        error,
        AwsCodePipelineReleaseError::Transport(_)
            | AwsCodePipelineReleaseError::ResponseTooLarge
            | AwsCodePipelineReleaseError::TruncatedEvidence
            | AwsCodePipelineReleaseError::ExecutionReplaced
            | AwsCodePipelineReleaseError::StageActionReplaced
    )
}
