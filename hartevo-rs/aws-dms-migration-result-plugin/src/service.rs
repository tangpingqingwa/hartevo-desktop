//! Bounded AWS DMS read, proposal, recording, registration, and verification.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsDmsConsumer;
use crate::error::{AwsDmsMigrationError, AwsDmsTransportError, Result};
use crate::model::{
    AssessmentResultMetadata, AwsDmsMigrationEvidence, AwsDmsMigrationReadRequest, AwsDmsScope,
    ConsentScope, Digest, DmsOperation, EvidenceDigests, EvidenceState, FailureEvidence,
    MigrationWindow, MissionProjection, OpaqueMarker, PermissionSnapshot, ProjectProjection,
    ReplicationMetadata, ReplicationState, ReplicationTaskMetadata, ReplicationTaskState,
    SecretReference, TransportProvenance, WorkProductProjection,
};
use crate::provider::{AwsDmsProvider, AwsDmsProviderDefinition, AwsDmsTransport};
use crate::{
    AWS_DMS_API_REVISION, AWS_DMS_CONSUMER_ID, AWS_DMS_CONTRACT_VERSION, AWS_DMS_PLUGIN_VERSION,
    AWS_DMS_PROVIDER_ID, AWS_DMS_PROVIDER_VERSION, AWS_DMS_SERVICE_ID,
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

#[derive(Clone, Eq, PartialEq)]
pub struct AwsDmsRegistration {
    scope: AwsDmsScope,
    pub registration_id_digest: Digest,
    pub plugin_version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_api_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: crate::Revision,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
    pub revocation_digest: Option<Digest>,
}

impl AwsDmsRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registration_id: impl Into<String>,
        scope: AwsDmsScope,
        secret_reference: &SecretReference,
        permission_snapshot: &PermissionSnapshot,
        consent: &ConsentScope,
        provider: &AwsDmsProviderDefinition,
        registration_revision: crate::Revision,
    ) -> Result<Self> {
        let registration_id = registration_id.into();
        if registration_id.is_empty() {
            return Err(AwsDmsMigrationError::InvalidRegistration);
        }
        scope.validate()?;
        secret_reference.validate(&scope)?;
        permission_snapshot.validate()?;
        provider.validate()?;
        if permission_snapshot.permissions.len() != crate::LAYER1_PERMISSIONS.len()
            || crate::LAYER1_PERMISSIONS
                .iter()
                .any(|permission| !permission_snapshot.permissions.contains(*permission))
        {
            return Err(AwsDmsMigrationError::InvalidPermissionSnapshot);
        }
        let mut registration = Self {
            registration_id_digest: Digest::from_text(registration_id),
            plugin_version_digest: Digest::from_text(AWS_DMS_PLUGIN_VERSION),
            contract_version: AWS_DMS_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: provider.id.clone(),
            provider_version: provider.version.clone(),
            provider_api_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: permission_snapshot.digest(),
            consent_digest: consent.digest(),
            scope_digest: scope.digest(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::zero(),
            revocation_digest: None,
            scope,
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn scope(&self) -> &AwsDmsScope {
        &self.scope
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-registration/v1",
            &[
                (
                    "registration_id",
                    self.registration_id_digest.as_str().to_owned(),
                ),
                (
                    "plugin_version",
                    self.plugin_version_digest.as_str().to_owned(),
                ),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_version", self.provider_version.clone()),
                ("provider_revision", self.provider_api_revision.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                (
                    "registration_revision",
                    self.registration_revision.get().to_string(),
                ),
                ("status", format!("{:?}", self.status)),
                (
                    "revocation",
                    self.revocation_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        let provider = AwsDmsProviderDefinition::baseline();
        self.plugin_version_digest
            .validate("plugin version digest")?;
        self.contract_digest.validate("contract digest")?;
        self.provider_digest.validate("provider digest")?;
        self.api_digest.validate("API digest")?;
        self.permission_digest.validate("permission digest")?;
        self.consent_digest.validate("consent digest")?;
        self.scope_digest.validate("scope digest")?;
        self.secret_reference_digest
            .validate("secret reference digest")?;
        if self.contract_version != AWS_DMS_CONTRACT_VERSION
            || self.plugin_version_digest != Digest::from_text(AWS_DMS_PLUGIN_VERSION)
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != AWS_DMS_PROVIDER_ID
            || self.provider_version != AWS_DMS_PROVIDER_VERSION
            || self.provider_api_revision != AWS_DMS_API_REVISION
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.registration_revision.get() == 0
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.recomputed_digest()
        {
            Err(AwsDmsMigrationError::InvalidRegistration)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Revoked) {
            return Err(AwsDmsMigrationError::RegistrationRevoked);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.revocation_digest = Some(Digest::from_parts(
            "aws-dms-registration-revocation/v1",
            &[
                ("registration", self.registration_digest.as_str().to_owned()),
                ("previous", format!("{previous_status:?}")),
                ("new", "Revoked".to_owned()),
            ],
        ));
        self.registration_digest = self.recomputed_digest();
        Ok(self.transition(previous_status))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsDmsMigrationError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.revocation_digest = Some(Digest::from_parts(
            "aws-dms-registration-reversal/v1",
            &[
                ("registration", self.registration_digest.as_str().to_owned()),
                ("previous", format!("{previous_status:?}")),
                ("new", "Reversed".to_owned()),
            ],
        ));
        self.registration_digest = self.recomputed_digest();
        Ok(self.transition(previous_status))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Active) {
            return Err(AwsDmsMigrationError::InvalidRegistration);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.revocation_digest = Some(Digest::from_parts(
            "aws-dms-registration-restore/v1",
            &[
                ("registration", self.registration_digest.as_str().to_owned()),
                ("previous", format!("{previous_status:?}")),
                ("new", "Active".to_owned()),
            ],
        ));
        self.registration_digest = self.recomputed_digest();
        Ok(self.transition(previous_status))
    }

    fn transition(&self, previous_status: RegistrationStatus) -> RegistrationTransitionEvidence {
        RegistrationTransitionEvidence {
            previous_status,
            new_status: self.status,
            registration_digest: self.registration_digest.clone(),
            transition_digest: Digest::from_parts(
                "aws-dms-registration-transition/v1",
                &[
                    ("registration", self.registration_digest.as_str().to_owned()),
                    ("previous", format!("{previous_status:?}")),
                    ("new", format!("{:?}", self.status)),
                ],
            ),
        }
    }
}

impl fmt::Debug for AwsDmsRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDmsRegistration")
            .field("scope_digest", &self.scope_digest)
            .field("registration_digest", &self.registration_digest)
            .field("status", &self.status)
            .field("registration_revision", &self.registration_revision)
            .finish()
    }
}

impl Serialize for AwsDmsRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsDmsRegistration", 17)?;
        state.serialize_field("registrationIdDigest", &self.registration_id_digest)?;
        state.serialize_field("pluginVersionDigest", &self.plugin_version_digest)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerVersion", &self.provider_version)?;
        state.serialize_field("providerApiRevision", &self.provider_api_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("consentDigest", &self.consent_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.serialize_field("revocationDigest", &self.revocation_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsDmsCapabilities {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    ReviewOnly,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Revoked,
}

impl From<EvidenceState> for ProposalDisposition {
    fn from(value: EvidenceState) -> Self {
        match value {
            EvidenceState::Partial => Self::Partial,
            EvidenceState::AccessLoss => Self::AccessLoss,
            EvidenceState::ProviderUnknown | EvidenceState::Throttled | EvidenceState::NotFound => {
                Self::ProviderUnknown
            }
            EvidenceState::RegistrationRevoked => Self::Revoked,
            EvidenceState::Completed
            | EvidenceState::InProgress
            | EvidenceState::Stopped
            | EvidenceState::Failed => Self::ReviewOnly,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsDmsMigrationProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: EvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: AwsDmsMigrationEvidence,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsDmsMigrationProposal {
    fn new(registration: &AwsDmsRegistration, evidence: AwsDmsMigrationEvidence) -> Self {
        let state = evidence.state;
        let provenance = evidence.provenance.clone();
        let mut proposal = Self {
            service_id: AWS_DMS_SERVICE_ID.to_owned(),
            consumer_id: AWS_DMS_CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            mission: MissionProjection::from(registration.scope.mission()),
            project: ProjectProjection::from(registration.scope.project()),
            work_product: WorkProductProjection::from(registration.scope.work_product()),
            state,
            disposition: state.into(),
            evidence,
            provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "mission",
                    serde_json::to_string(&self.mission).expect("projection serializes"),
                ),
                (
                    "project",
                    serde_json::to_string(&self.project).expect("projection serializes"),
                ),
                (
                    "work_product",
                    serde_json::to_string(&self.work_product).expect("projection serializes"),
                ),
                ("state", format!("{:?}", self.state)),
                ("disposition", format!("{:?}", self.disposition)),
                (
                    "evidence",
                    self.evidence.digests.evidence_digest.as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("review_only", self.review_only.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("outcome_adopted", self.outcome_adopted.to_string()),
                (
                    "work_product_adopted",
                    self.work_product_adopted.to_string(),
                ),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate_integrity()?;
        if self.service_id != AWS_DMS_SERVICE_ID
            || self.consumer_id != AWS_DMS_CONSUMER_ID
            || self.provenance != self.evidence.provenance
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.recomputed_digest()
        {
            Err(AwsDmsMigrationError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    pub fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    PluginVersionDigestMismatch,
    ContractDigestMismatch,
    ProviderDigestMismatch,
    ApiDigestMismatch,
    PermissionDigestMismatch,
    ConsentDigestMismatch,
    ScopeDigestMismatch,
    EvidenceTampered,
    PartialEvidence,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    RevisionDrift,
    IdentityDrift,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_complete: bool,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn new(valid: bool, review_complete: bool, mut failures: Vec<VerificationFailure>) -> Self {
        failures.sort_unstable();
        failures.dedup();
        let verification_digest = Digest::from_parts(
            "aws-dms-verification/v1",
            &[
                ("valid", valid.to_string()),
                ("review_complete", review_complete.to_string()),
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
            review_complete,
            failures,
            verification_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsDmsRecordReceipt {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub recorded_at: DateTime<Utc>,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub record_digest: Digest,
}

impl AwsDmsRecordReceipt {
    pub(crate) fn for_consumer(
        idempotency_key_digest: Digest,
        proposal: &AwsDmsMigrationProposal,
        recorded_at: DateTime<Utc>,
    ) -> Self {
        Self::new(idempotency_key_digest, proposal, recorded_at, false)
    }

    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsDmsMigrationProposal,
        recorded_at: DateTime<Utc>,
        replayed: bool,
    ) -> Self {
        let mut receipt = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digests.evidence_digest.clone(),
            recorded_at,
            provenance: proposal.provenance.clone(),
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            record_digest: Digest::zero(),
        };
        receipt.record_digest = receipt.recomputed_digest();
        receipt
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dms-record/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("recorded_at", self.recorded_at.to_rfc3339()),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("outcome_adopted", self.outcome_adopted.to_string()),
                (
                    "work_product_adopted",
                    self.work_product_adopted.to_string(),
                ),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.record_digest != self.recomputed_digest()
        {
            Err(AwsDmsMigrationError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

pub struct AwsDmsMigrationService<T: AwsDmsTransport> {
    registration: AwsDmsRegistration,
    secret_reference: SecretReference,
    consent: ConsentScope,
    provider: AwsDmsProvider<T>,
    records: BTreeMap<Digest, AwsDmsRecordReceipt>,
}

impl<T: AwsDmsTransport> fmt::Debug for AwsDmsMigrationService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDmsMigrationService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T: AwsDmsTransport> AwsDmsMigrationService<T> {
    pub fn new(
        scope: AwsDmsScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AwsDmsProvider<T>,
        registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        Self::with_registration(
            "aws-dms-registration",
            scope,
            secret_reference,
            PermissionSnapshot::for_layer_one(crate::Revision::new(1)?),
            consent,
            provider,
            crate::Revision::new(1)?,
            registration_time,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_registration(
        registration_id: impl Into<String>,
        scope: AwsDmsScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: AwsDmsProvider<T>,
        registration_revision: crate::Revision,
        _registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = AwsDmsRegistration::new(
            registration_id,
            scope,
            &secret_reference,
            &permission_snapshot,
            &consent,
            provider.definition(),
            registration_revision,
        )?;
        Ok(Self {
            registration,
            secret_reference,
            consent,
            provider,
            records: BTreeMap::new(),
        })
    }

    pub fn describe_capabilities(&self) -> AwsDmsCapabilities {
        AwsDmsCapabilities {
            service_id: AWS_DMS_SERVICE_ID.to_owned(),
            provider_id: AWS_DMS_PROVIDER_ID.to_owned(),
            consumer_id: AWS_DMS_CONSUMER_ID.to_owned(),
            operations: vec![
                DmsOperation::DescribeReplicationTasks.as_str().to_owned(),
                DmsOperation::DescribeReplications.as_str().to_owned(),
                DmsOperation::DescribeReplicationTaskAssessmentResults
                    .as_str()
                    .to_owned(),
            ],
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
        }
    }

    pub fn scope(&self) -> &AwsDmsScope {
        self.registration.scope()
    }

    pub fn registration(&self) -> &AwsDmsRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsDmsRegistration {
        &mut self.registration
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn revoke_secret_reference(&mut self) {
        self.secret_reference.revoke();
    }

    pub fn provider(&self) -> &AwsDmsProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsDmsProvider<T> {
        &mut self.provider
    }

    pub fn request(
        &self,
        max_records: u16,
        max_pages: u16,
        migration_window: MigrationWindow,
    ) -> Result<AwsDmsMigrationReadRequest> {
        AwsDmsMigrationReadRequest::new(self.scope(), max_records, max_pages, migration_window)
    }

    pub fn default_request(&self) -> Result<AwsDmsMigrationReadRequest> {
        AwsDmsMigrationReadRequest::for_scope(self.scope(), 25, 1)
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

    pub fn consumer(&self) -> Result<MissionAwsDmsConsumer> {
        MissionAwsDmsConsumer::new(self.scope().clone(), self.registration.clone())
    }

    pub fn propose(
        &mut self,
        request: AwsDmsMigrationReadRequest,
    ) -> Result<AwsDmsMigrationProposal> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsDmsMigrationError::RegistrationInactive);
        }
        if self.secret_reference.is_revoked() {
            return Err(AwsDmsMigrationError::InvalidSecretReference);
        }
        self.secret_reference.validate(self.scope())?;
        request.validate_against(self.scope())?;
        if !self
            .consent
            .is_active_at(self.scope().migration_window().starts_at)
        {
            return Err(if self.consent.is_revoked() {
                AwsDmsMigrationError::ConsentRevoked
            } else {
                AwsDmsMigrationError::ConsentExpired
            });
        }

        let mut task_marker = None;
        let mut task_pages = 0_u16;
        let mut task_complete = false;
        let mut task_page_digests = Vec::new();
        let mut task_marker_digests = BTreeSet::new();
        let mut task: Option<ReplicationTaskMetadata> = None;
        loop {
            if task_pages >= request.max_pages {
                break;
            }
            let page_number = task_pages + 1;
            let page_request =
                request.tasks_request(self.scope(), task_marker.clone(), page_number)?;
            let response = match self.provider.describe_replication_tasks(&page_request) {
                Ok(response) => response,
                Err(error) => {
                    return Ok(self.proposal_from_parts(
                        request,
                        EvidenceState::from_transport(&error),
                        task,
                        None,
                        None,
                        task_pages,
                        0,
                        0,
                        false,
                        false,
                        false,
                        task_page_digests,
                        Vec::new(),
                        Vec::new(),
                        task_marker,
                        None,
                        None,
                        Some(FailureEvidence::new(
                            DmsOperation::DescribeReplicationTasks,
                            error_category(&error),
                            error.status_code(),
                        )),
                    ));
                }
            };
            task_pages += 1;
            task_page_digests.push(response.page_digest.clone());
            for item in response.tasks {
                if item.validate_against(self.scope()).is_err() {
                    return Ok(self.proposal_from_parts(
                        request,
                        EvidenceState::Partial,
                        task,
                        None,
                        None,
                        task_pages,
                        0,
                        0,
                        false,
                        false,
                        false,
                        task_page_digests,
                        Vec::new(),
                        Vec::new(),
                        task_marker,
                        None,
                        None,
                        Some(FailureEvidence::new(
                            DmsOperation::DescribeReplicationTasks,
                            "task_or_endpoint_revision_drift",
                            None,
                        )),
                    ));
                }
                if let Some(previous) = &task {
                    if previous.metadata_digest != item.metadata_digest {
                        return Ok(self.proposal_from_parts(
                            request,
                            EvidenceState::Partial,
                            Some(previous.clone()),
                            None,
                            None,
                            task_pages,
                            0,
                            0,
                            false,
                            false,
                            false,
                            task_page_digests,
                            Vec::new(),
                            Vec::new(),
                            task_marker,
                            None,
                            None,
                            Some(FailureEvidence::new(
                                DmsOperation::DescribeReplicationTasks,
                                "task_replaced",
                                None,
                            )),
                        ));
                    }
                }
                task = Some(item);
            }
            match response.next_marker {
                Some(next) => {
                    let marker_digest = next.token_digest().clone();
                    if !task_marker_digests.insert(marker_digest) {
                        return Ok(self.proposal_from_parts(
                            request,
                            EvidenceState::Partial,
                            task,
                            None,
                            None,
                            task_pages,
                            0,
                            0,
                            false,
                            false,
                            false,
                            task_page_digests,
                            Vec::new(),
                            Vec::new(),
                            Some(next),
                            None,
                            None,
                            Some(FailureEvidence::new(
                                DmsOperation::DescribeReplicationTasks,
                                "pagination_loop",
                                None,
                            )),
                        ));
                    }
                    task_marker = Some(next);
                    if task_pages >= request.max_pages {
                        return Ok(self.proposal_from_parts(
                            request,
                            EvidenceState::Partial,
                            task,
                            None,
                            None,
                            task_pages,
                            0,
                            0,
                            false,
                            false,
                            false,
                            task_page_digests,
                            Vec::new(),
                            Vec::new(),
                            task_marker,
                            None,
                            None,
                            Some(FailureEvidence::new(
                                DmsOperation::DescribeReplicationTasks,
                                "page_budget",
                                None,
                            )),
                        ));
                    }
                }
                None => {
                    task_complete = true;
                    break;
                }
            }
        }

        let mut replication_marker = None;
        let mut replication_pages = 0_u16;
        let mut replication_complete = false;
        let mut replication_page_digests = Vec::new();
        let mut replication_marker_digests = BTreeSet::new();
        let mut replication: Option<ReplicationMetadata> = None;
        loop {
            if replication_pages >= request.max_pages {
                break;
            }
            let page_number = replication_pages + 1;
            let page_request = request.replications_request(
                self.scope(),
                replication_marker.clone(),
                page_number,
            )?;
            let response = match self.provider.describe_replications(&page_request) {
                Ok(response) => response,
                Err(error) => {
                    return Ok(self.proposal_from_parts(
                        request,
                        if task_complete {
                            EvidenceState::from_transport(&error)
                        } else {
                            EvidenceState::Partial
                        },
                        task,
                        replication,
                        None,
                        task_pages,
                        replication_pages,
                        0,
                        task_complete,
                        false,
                        false,
                        task_page_digests,
                        replication_page_digests,
                        Vec::new(),
                        task_marker,
                        replication_marker,
                        None,
                        Some(FailureEvidence::new(
                            DmsOperation::DescribeReplications,
                            error_category(&error),
                            error.status_code(),
                        )),
                    ));
                }
            };
            replication_pages += 1;
            replication_page_digests.push(response.page_digest.clone());
            for item in response.replications {
                if item.validate_against(self.scope()).is_err() {
                    return Ok(self.proposal_from_parts(
                        request,
                        EvidenceState::Partial,
                        task,
                        replication,
                        None,
                        task_pages,
                        replication_pages,
                        0,
                        task_complete,
                        false,
                        false,
                        task_page_digests,
                        replication_page_digests,
                        Vec::new(),
                        task_marker,
                        replication_marker,
                        None,
                        Some(FailureEvidence::new(
                            DmsOperation::DescribeReplications,
                            "replication_or_endpoint_revision_drift",
                            None,
                        )),
                    ));
                }
                if let Some(previous) = &replication {
                    if previous.metadata_digest != item.metadata_digest {
                        return Ok(self.proposal_from_parts(
                            request,
                            EvidenceState::Partial,
                            task,
                            Some(previous.clone()),
                            None,
                            task_pages,
                            replication_pages,
                            0,
                            task_complete,
                            false,
                            false,
                            task_page_digests,
                            replication_page_digests,
                            Vec::new(),
                            task_marker,
                            replication_marker,
                            None,
                            Some(FailureEvidence::new(
                                DmsOperation::DescribeReplications,
                                "replication_replaced",
                                None,
                            )),
                        ));
                    }
                }
                replication = Some(item);
            }
            match response.next_marker {
                Some(next) => {
                    let marker_digest = next.token_digest().clone();
                    if !replication_marker_digests.insert(marker_digest) {
                        return Ok(self.proposal_from_parts(
                            request,
                            EvidenceState::Partial,
                            task,
                            replication,
                            None,
                            task_pages,
                            replication_pages,
                            0,
                            task_complete,
                            false,
                            false,
                            task_page_digests,
                            replication_page_digests,
                            Vec::new(),
                            task_marker,
                            Some(next),
                            None,
                            Some(FailureEvidence::new(
                                DmsOperation::DescribeReplications,
                                "pagination_loop",
                                None,
                            )),
                        ));
                    }
                    replication_marker = Some(next);
                    if replication_pages >= request.max_pages {
                        return Ok(self.proposal_from_parts(
                            request,
                            EvidenceState::Partial,
                            task,
                            replication,
                            None,
                            task_pages,
                            replication_pages,
                            0,
                            task_complete,
                            false,
                            false,
                            task_page_digests,
                            replication_page_digests,
                            Vec::new(),
                            task_marker,
                            replication_marker,
                            None,
                            Some(FailureEvidence::new(
                                DmsOperation::DescribeReplications,
                                "page_budget",
                                None,
                            )),
                        ));
                    }
                }
                None => {
                    replication_complete = true;
                    break;
                }
            }
        }

        let mut assessment_marker = None;
        let mut assessment_pages = 0_u16;
        let mut assessment_complete = false;
        let mut assessment_page_digests = Vec::new();
        let mut assessment_marker_digests = BTreeSet::new();
        let mut assessment: Option<AssessmentResultMetadata> = None;
        loop {
            if assessment_pages >= request.max_pages {
                break;
            }
            let page_number = assessment_pages + 1;
            let page_request =
                request.assessment_request(self.scope(), assessment_marker.clone(), page_number)?;
            let response = match self.provider.describe_assessment_results(&page_request) {
                Ok(response) => response,
                Err(error) => {
                    return Ok(self.proposal_from_parts(
                        request,
                        if task_complete && replication_complete {
                            EvidenceState::from_transport(&error)
                        } else {
                            EvidenceState::Partial
                        },
                        task,
                        replication,
                        assessment,
                        task_pages,
                        replication_pages,
                        assessment_pages,
                        task_complete,
                        replication_complete,
                        false,
                        task_page_digests,
                        replication_page_digests,
                        assessment_page_digests,
                        task_marker,
                        replication_marker,
                        assessment_marker,
                        Some(FailureEvidence::new(
                            DmsOperation::DescribeReplicationTaskAssessmentResults,
                            error_category(&error),
                            error.status_code(),
                        )),
                    ));
                }
            };
            assessment_pages += 1;
            assessment_page_digests.push(response.page_digest.clone());
            for item in response.assessments {
                if item.validate_against(self.scope()).is_err() {
                    return Ok(self.proposal_from_parts(
                        request,
                        EvidenceState::Partial,
                        task,
                        replication,
                        assessment,
                        task_pages,
                        replication_pages,
                        assessment_pages,
                        task_complete,
                        replication_complete,
                        false,
                        task_page_digests,
                        replication_page_digests,
                        assessment_page_digests,
                        task_marker,
                        replication_marker,
                        assessment_marker,
                        Some(FailureEvidence::new(
                            DmsOperation::DescribeReplicationTaskAssessmentResults,
                            "assessment_revision_or_digest_drift",
                            None,
                        )),
                    ));
                }
                if let Some(previous) = &assessment {
                    if previous.result_digest != item.result_digest {
                        return Ok(self.proposal_from_parts(
                            request,
                            EvidenceState::Partial,
                            task,
                            replication,
                            Some(previous.clone()),
                            task_pages,
                            replication_pages,
                            assessment_pages,
                            task_complete,
                            replication_complete,
                            false,
                            task_page_digests,
                            replication_page_digests,
                            assessment_page_digests,
                            task_marker,
                            replication_marker,
                            assessment_marker,
                            Some(FailureEvidence::new(
                                DmsOperation::DescribeReplicationTaskAssessmentResults,
                                "assessment_replaced",
                                None,
                            )),
                        ));
                    }
                }
                assessment = Some(item);
            }
            match response.next_marker {
                Some(next) => {
                    let marker_digest = next.token_digest().clone();
                    if !assessment_marker_digests.insert(marker_digest) {
                        return Ok(self.proposal_from_parts(
                            request,
                            EvidenceState::Partial,
                            task,
                            replication,
                            assessment,
                            task_pages,
                            replication_pages,
                            assessment_pages,
                            task_complete,
                            replication_complete,
                            false,
                            task_page_digests,
                            replication_page_digests,
                            assessment_page_digests,
                            task_marker,
                            replication_marker,
                            Some(next),
                            Some(FailureEvidence::new(
                                DmsOperation::DescribeReplicationTaskAssessmentResults,
                                "pagination_loop",
                                None,
                            )),
                        ));
                    }
                    assessment_marker = Some(next);
                    if assessment_pages >= request.max_pages {
                        return Ok(self.proposal_from_parts(
                            request,
                            EvidenceState::Partial,
                            task,
                            replication,
                            assessment,
                            task_pages,
                            replication_pages,
                            assessment_pages,
                            task_complete,
                            replication_complete,
                            false,
                            task_page_digests,
                            replication_page_digests,
                            assessment_page_digests,
                            task_marker,
                            replication_marker,
                            assessment_marker,
                            Some(FailureEvidence::new(
                                DmsOperation::DescribeReplicationTaskAssessmentResults,
                                "page_budget",
                                None,
                            )),
                        ));
                    }
                }
                None => {
                    assessment_complete = true;
                    break;
                }
            }
        }

        let assessment =
            assessment.or_else(|| task.as_ref().and_then(|value| value.assessment.clone()));
        let state = if !task_complete || !replication_complete || !assessment_complete {
            EvidenceState::Partial
        } else if task.is_none() && replication.is_none() {
            EvidenceState::NotFound
        } else {
            state_from_metadata(task.as_ref(), replication.as_ref())
        };
        Ok(self.proposal_from_parts(
            request,
            state,
            task,
            replication,
            assessment,
            task_pages,
            replication_pages,
            assessment_pages,
            task_complete,
            replication_complete,
            assessment_complete,
            task_page_digests,
            replication_page_digests,
            assessment_page_digests,
            task_marker,
            replication_marker,
            assessment_marker,
            None,
        ))
    }

    pub fn read(&mut self, request: AwsDmsMigrationReadRequest) -> Result<AwsDmsMigrationProposal> {
        self.propose(request)
    }

    #[allow(clippy::too_many_arguments)]
    fn proposal_from_parts(
        &self,
        request: AwsDmsMigrationReadRequest,
        state: EvidenceState,
        task: Option<ReplicationTaskMetadata>,
        replication: Option<ReplicationMetadata>,
        assessment: Option<AssessmentResultMetadata>,
        task_pages: u16,
        replication_pages: u16,
        assessment_pages: u16,
        task_complete: bool,
        replication_complete: bool,
        assessment_complete: bool,
        task_page_digests: Vec<Digest>,
        replication_page_digests: Vec<Digest>,
        assessment_page_digests: Vec<Digest>,
        task_marker: Option<OpaqueMarker>,
        replication_marker: Option<OpaqueMarker>,
        assessment_marker: Option<OpaqueMarker>,
        failure: Option<FailureEvidence>,
    ) -> AwsDmsMigrationProposal {
        let task_request = request
            .tasks_request(self.scope(), None, 1)
            .expect("validated DMS task request");
        let replication_request = request
            .replications_request(self.scope(), None, 1)
            .expect("validated DMS replication request");
        let assessment_request = request
            .assessment_request(self.scope(), None, 1)
            .expect("validated DMS assessment request");
        let mut digests = EvidenceDigests {
            plugin_version_digest: Digest::from_text(AWS_DMS_PLUGIN_VERSION),
            contract_digest: crate::contract_digest(),
            provider_digest: self.provider.definition().provider_digest.clone(),
            api_digest: self.provider.definition().api_digest.clone(),
            permission_digest: self.registration.permission_digest.clone(),
            consent_digest: self.registration.consent_digest.clone(),
            scope_digest: self.registration.scope_digest.clone(),
            task_request_digest: task_request.request_digest,
            replication_request_digest: replication_request.request_digest,
            assessment_request_digest: assessment_request.request_digest,
            task_pages_digest: digest_pages(&task_page_digests, "aws-dms-task-pages/v1"),
            replication_pages_digest: digest_pages(
                &replication_page_digests,
                "aws-dms-replication-pages/v1",
            ),
            assessment_pages_digest: digest_pages(
                &assessment_page_digests,
                "aws-dms-assessment-pages/v1",
            ),
            task_marker_digest: task_marker.map(|value| value.token_digest().clone()),
            replication_marker_digest: replication_marker.map(|value| value.token_digest().clone()),
            assessment_marker_digest: assessment_marker.map(|value| value.token_digest().clone()),
            evidence_digest: Digest::zero(),
        };
        let mut evidence = AwsDmsMigrationEvidence {
            state,
            task,
            replication,
            assessment,
            task_pages,
            replication_pages,
            assessment_pages,
            task_complete,
            replication_complete,
            assessment_complete,
            failure,
            provenance: self.provider.provenance(),
            digests: digests.clone(),
        };
        digests.evidence_digest = evidence.recomputed_digest();
        evidence.digests = digests;
        AwsDmsMigrationProposal::new(&self.registration, evidence)
    }

    pub fn verify(&self, proposal: &AwsDmsMigrationProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if self.registration.validate().is_err() || !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != self.registration.registration_digest {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        let provider = self.provider.definition();
        if proposal.evidence.digests.plugin_version_digest
            != Digest::from_text(AWS_DMS_PLUGIN_VERSION)
        {
            failures.push(VerificationFailure::PluginVersionDigestMismatch);
        }
        if proposal.evidence.digests.contract_digest != crate::contract_digest() {
            failures.push(VerificationFailure::ContractDigestMismatch);
        }
        if proposal.evidence.digests.provider_digest != provider.provider_digest {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.digests.api_digest != provider.api_digest {
            failures.push(VerificationFailure::ApiDigestMismatch);
        }
        if proposal.evidence.digests.permission_digest != self.registration.permission_digest {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.digests.consent_digest != self.registration.consent_digest {
            failures.push(VerificationFailure::ConsentDigestMismatch);
        }
        if proposal.scope_digest != self.registration.scope_digest {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.digests.scope_digest != self.registration.scope_digest {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::EvidenceTampered);
        }
        match proposal.state {
            EvidenceState::Partial => failures.push(VerificationFailure::PartialEvidence),
            EvidenceState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            EvidenceState::Throttled => failures.push(VerificationFailure::Throttled),
            EvidenceState::ProviderUnknown => failures.push(VerificationFailure::ProviderUnknown),
            EvidenceState::Failed | EvidenceState::Stopped | EvidenceState::NotFound => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            EvidenceState::Completed
            | EvidenceState::InProgress
            | EvidenceState::RegistrationRevoked => {}
        }
        let valid = failures.is_empty();
        VerificationReport::new(
            valid,
            valid && proposal.state.is_review_complete(),
            failures,
        )
    }

    pub fn record(
        &mut self,
        proposal: &AwsDmsMigrationProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<AwsDmsRecordReceipt> {
        self.record_at(proposal, idempotency_key, Utc::now())
    }

    pub fn record_at(
        &mut self,
        proposal: &AwsDmsMigrationProposal,
        idempotency_key: impl AsRef<str>,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsDmsRecordReceipt> {
        if !self.verify(proposal).valid {
            return Err(AwsDmsMigrationError::VerificationFailed);
        }
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsDmsMigrationError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsDmsMigrationError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.record_digest = replay.recomputed_digest();
            return Ok(replay);
        }
        if !self.registration.is_active() {
            return Err(AwsDmsMigrationError::RegistrationInactive);
        }
        let receipt = AwsDmsRecordReceipt::new(key_digest.clone(), proposal, recorded_at, false);
        self.records.insert(key_digest, receipt.clone());
        Ok(receipt)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

impl EvidenceState {
    fn from_transport(error: &AwsDmsTransportError) -> Self {
        match error {
            AwsDmsTransportError::Unauthorized
            | AwsDmsTransportError::Forbidden
            | AwsDmsTransportError::AccessLost => Self::AccessLoss,
            AwsDmsTransportError::RateLimited { .. } => Self::Throttled,
            AwsDmsTransportError::NotFound => Self::NotFound,
            AwsDmsTransportError::Partial => Self::Partial,
            AwsDmsTransportError::BlockedEnv
            | AwsDmsTransportError::BadRequest
            | AwsDmsTransportError::ServerError { .. }
            | AwsDmsTransportError::Timeout
            | AwsDmsTransportError::InvalidResponse => Self::ProviderUnknown,
        }
    }
}

fn error_category(error: &AwsDmsTransportError) -> &'static str {
    match error {
        AwsDmsTransportError::BlockedEnv => "blocked_env",
        AwsDmsTransportError::BadRequest => "bad_request",
        AwsDmsTransportError::Unauthorized => "unauthorized",
        AwsDmsTransportError::Forbidden => "forbidden",
        AwsDmsTransportError::NotFound => "not_found",
        AwsDmsTransportError::RateLimited { .. } => "throttled",
        AwsDmsTransportError::ServerError { .. } => "server_error",
        AwsDmsTransportError::Timeout => "timeout",
        AwsDmsTransportError::AccessLost => "access_loss",
        AwsDmsTransportError::Partial => "partial",
        AwsDmsTransportError::InvalidResponse => "invalid_response",
    }
}

fn state_from_metadata(
    task: Option<&ReplicationTaskMetadata>,
    replication: Option<&ReplicationMetadata>,
) -> EvidenceState {
    if task.is_some_and(|value| matches!(value.state, ReplicationTaskState::Failed))
        || replication.is_some_and(|value| matches!(value.state, ReplicationState::Failed))
    {
        return EvidenceState::Failed;
    }
    if task.is_some_and(|value| matches!(value.state, ReplicationTaskState::Stopped))
        || replication.is_some_and(|value| matches!(value.state, ReplicationState::Stopped))
    {
        return EvidenceState::Stopped;
    }
    if task.is_some_and(|value| {
        matches!(
            value.state,
            ReplicationTaskState::Running | ReplicationTaskState::Starting
        )
    }) || replication.is_some_and(|value| matches!(value.state, ReplicationState::Running))
    {
        EvidenceState::InProgress
    } else {
        EvidenceState::Completed
    }
}

fn digest_pages(values: &[Digest], domain: &str) -> Option<Digest> {
    (!values.is_empty()).then(|| {
        Digest::from_parts(
            domain,
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
