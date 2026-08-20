//! Typed AWS EBS read, proposal, verification, and reversible registration.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::consumer::MissionAwsEbsConsumer;
use crate::error::{AwsEbsTransportError, AwsEbsVolumeError, Result};
use crate::model::{
    AwsEbsOperation, AwsEbsVolumeScope, ConsentScope, Digest, EvidenceDigests,
    FastSnapshotRestoreInput, FastSnapshotRestorePosture, MissionProjection, PermissionSnapshot,
    ProjectProjection, SecretReference, SnapshotMetadataInput, SnapshotPosture,
    TransportProvenance, VolumeMetadataInput, VolumePosture, VolumeStatusInput,
    VolumeStatusPosture, WorkProductProjection, is_stale, validate_page_count,
};
use crate::provider::{
    AwsEbsProvider, AwsEbsProviderDefinition, AwsEbsTransport, DescribeFastSnapshotRestoresRequest,
    DescribeSnapshotsRequest, DescribeVolumeStatusRequest, DescribeVolumesRequest,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, EVIDENCE_SCHEMA_DIGEST, PLUGIN_VERSION,
    PROVIDER_ID, SERVICE_ID, contract_digest,
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
            "aws-ebs-registration-transition/v1",
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

/// Version/contract/provider/API/permission/volume/snapshot/scope/evidence
/// bound registration. The secret handle itself is never retained.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsEbsVolumeRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_api_revision: String,
    provider_revision: u64,
    provider_digest: Digest,
    evidence_schema_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: AwsEbsVolumeScope,
    volume_allowlist_digest: Digest,
    snapshot_allowlist_digest: Digest,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl AwsEbsVolumeRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsEbsVolumeScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsEbsProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let scope_digest = scope.digest();
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_api_revision: provider.api_revision.clone(),
            provider_revision: provider.provider_revision,
            provider_digest: provider.provider_digest.clone(),
            evidence_schema_digest: provider.evidence_schema_digest.clone(),
            volume_allowlist_digest: scope.volume_allowlist_digest(),
            snapshot_allowlist_digest: scope.snapshot_allowlist_digest(),
            scope_digest,
            scope,
            secret_reference,
            permission_snapshot,
            consent,
            registration_revision,
            status: RegistrationStatus::Active,
            binding_digest: Digest::from_text("unsealed-aws-ebs-registration"),
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

    pub fn provider_api_revision(&self) -> &str {
        &self.provider_api_revision
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn evidence_schema_digest(&self) -> &Digest {
        &self.evidence_schema_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_schema_digest
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

    pub fn scope(&self) -> &AwsEbsVolumeScope {
        &self.scope
    }

    pub fn volume_allowlist_digest(&self) -> &Digest {
        &self.volume_allowlist_digest
    }

    pub fn snapshot_allowlist_digest(&self) -> &Digest {
        &self.snapshot_allowlist_digest
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
        if !valid_registration_id(&self.id)
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_api_revision != crate::API_REVISION
            || self.provider_revision == 0
            || self.provider_digest != AwsEbsProviderDefinition::new().provider_digest
            || self.evidence_schema_digest.as_str() != EVIDENCE_SCHEMA_DIGEST
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.volume_allowlist_digest != self.scope.volume_allowlist_digest()
            || self.snapshot_allowlist_digest != self.scope.snapshot_allowlist_digest()
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(AwsEbsVolumeError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        self.consent.validate()?;
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsEbsVolumeError::RegistrationReversed);
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
            return Err(AwsEbsVolumeError::RegistrationReversed);
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
            return Err(AwsEbsVolumeError::RegistrationReversed);
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
            "aws-ebs-registration/v1",
            &[
                ("id", Digest::from_text(&self.id).as_str().to_owned()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_api_revision", self.provider_api_revision.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider", self.provider_digest.as_str().to_owned()),
                (
                    "evidence_schema",
                    self.evidence_schema_digest.as_str().to_owned(),
                ),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("consent", self.consent_digest().as_str().to_owned()),
                (
                    "volume_allowlist",
                    self.volume_allowlist_digest.as_str().to_owned(),
                ),
                (
                    "snapshot_allowlist",
                    self.snapshot_allowlist_digest.as_str().to_owned(),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest().as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

impl fmt::Debug for AwsEbsVolumeRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEbsVolumeRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_api_revision", &self.provider_api_revision)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("evidence_digest", &self.evidence_schema_digest)
            .field("evidence_schema_digest", &self.evidence_schema_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("volume_allowlist_digest", &self.volume_allowlist_digest)
            .field("snapshot_allowlist_digest", &self.snapshot_allowlist_digest)
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for AwsEbsVolumeRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsEbsVolumeRegistration", 19)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerApiRevision", &self.provider_api_revision)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("evidenceDigest", &self.evidence_schema_digest)?;
        state.serialize_field("evidenceSchemaDigest", &self.evidence_schema_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("volumeAllowlistDigest", &self.volume_allowlist_digest)?;
        state.serialize_field("snapshotAllowlistDigest", &self.snapshot_allowlist_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.binding_digest)?;
        state.end()
    }
}

pub type AwsEbsRegistration = AwsEbsVolumeRegistration;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsEbsEvidenceRequest {
    pub scope_digest: Digest,
    pub expected_registration_digest: Digest,
    pub expected_provider_digest: Digest,
    pub observed_at: i64,
    pub max_pages: u16,
    pub volumes: DescribeVolumesRequest,
    pub volume_status: DescribeVolumeStatusRequest,
    pub snapshots: DescribeSnapshotsRequest,
    pub fast_snapshot_restores: DescribeFastSnapshotRestoresRequest,
}

impl AwsEbsEvidenceRequest {
    pub fn new(
        scope: &AwsEbsVolumeScope,
        registration: &AwsEbsVolumeRegistration,
        provider: &AwsEbsProviderDefinition,
        max_pages: u16,
        observed_at: i64,
    ) -> Result<Self> {
        validate_page_count(max_pages)?;
        let volumes =
            DescribeVolumesRequest::for_scope(scope, crate::MAX_PAGE_SIZE, None, observed_at)?;
        let volume_status =
            DescribeVolumeStatusRequest::for_scope(scope, crate::MAX_PAGE_SIZE, None, observed_at)?;
        let snapshots =
            DescribeSnapshotsRequest::for_scope(scope, crate::MAX_PAGE_SIZE, None, observed_at)?;
        let fast_snapshot_restores = DescribeFastSnapshotRestoresRequest::for_scope(
            scope,
            crate::MAX_PAGE_SIZE,
            None,
            observed_at,
        )?;
        let request = Self {
            scope_digest: scope.digest(),
            expected_registration_digest: registration.registration_digest().clone(),
            expected_provider_digest: provider.provider_digest.clone(),
            observed_at,
            max_pages,
            volumes,
            volume_status,
            snapshots,
            fast_snapshot_restores,
        };
        request.validate(scope, registration, provider)?;
        Ok(request)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-ebs-evidence-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "registration",
                    self.expected_registration_digest.as_str().to_owned(),
                ),
                (
                    "provider",
                    self.expected_provider_digest.as_str().to_owned(),
                ),
                ("observed_at", self.observed_at.to_string()),
                ("max_pages", self.max_pages.to_string()),
                ("volumes", self.volumes.request_digest().as_str().to_owned()),
                (
                    "volume_status",
                    self.volume_status.request_digest().as_str().to_owned(),
                ),
                (
                    "snapshots",
                    self.snapshots.request_digest().as_str().to_owned(),
                ),
                (
                    "fast_snapshot_restores",
                    self.fast_snapshot_restores
                        .request_digest()
                        .as_str()
                        .to_owned(),
                ),
            ],
        )
    }

    fn validate(
        &self,
        scope: &AwsEbsVolumeScope,
        registration: &AwsEbsVolumeRegistration,
        provider: &AwsEbsProviderDefinition,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.expected_registration_digest != *registration.registration_digest()
            || self.expected_provider_digest != provider.provider_digest
            || self.observed_at <= 0
            || self.max_pages == 0
        {
            return Err(AwsEbsVolumeError::ScopeMismatch);
        }
        if self.volumes.allowlist_digest() != scope.volume_allowlist_digest()
            || self.volume_status.allowlist_digest() != scope.volume_allowlist_digest()
            || self.snapshots.allowlist_digest() != scope.snapshot_allowlist_digest()
            || self.fast_snapshot_restores.allowlist_digest() != scope.snapshot_allowlist_digest()
        {
            return Err(AwsEbsVolumeError::VolumeAllowlistMismatch);
        }
        if self.volumes.fence().operation() != AwsEbsOperation::DescribeVolumes
            || self.volume_status.fence().operation() != AwsEbsOperation::DescribeVolumeStatus
            || self.snapshots.fence().operation() != AwsEbsOperation::DescribeSnapshots
            || self.fast_snapshot_restores.fence().operation()
                != AwsEbsOperation::DescribeFastSnapshotRestores
            || self.volumes.fence().scope_digest() != &self.scope_digest
            || self.volume_status.fence().scope_digest() != &self.scope_digest
            || self.snapshots.fence().scope_digest() != &self.scope_digest
            || self.fast_snapshot_restores.fence().scope_digest() != &self.scope_digest
        {
            return Err(AwsEbsVolumeError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Completed,
    Partial,
    StaleStatus,
    ResourceReplaced,
    NotFound,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl EvidenceState {
    pub const fn is_adoptable(self) -> bool {
        false
    }

    pub const fn is_non_adoptable(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: AwsEbsOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(operation: AwsEbsOperation, error: &AwsEbsTransportError) -> Self {
        let category = match error {
            AwsEbsTransportError::BlockedEnv => "blocked_env",
            AwsEbsTransportError::BadRequest => "bad_request",
            AwsEbsTransportError::Unauthorized => "unauthorized",
            AwsEbsTransportError::Forbidden => "forbidden",
            AwsEbsTransportError::NotFound => "not_found",
            AwsEbsTransportError::Conflict => "conflict",
            AwsEbsTransportError::RateLimited { .. } => "throttled",
            AwsEbsTransportError::ServerError { .. } => "server_error",
            AwsEbsTransportError::Timeout => "timeout",
            AwsEbsTransportError::AccessLoss => "access_loss",
            AwsEbsTransportError::Partial => "partial",
            AwsEbsTransportError::InvalidResponse => "invalid_response",
        }
        .to_owned();
        let failure_digest = Digest::from_parts(
            "aws-ebs-failure/v1",
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
pub struct AwsEbsVolumeProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub volume_allowlist_digest: Digest,
    pub snapshot_allowlist_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: EvidenceState,
    pub volume_pages: u16,
    pub volume_complete: bool,
    pub status_pages: u16,
    pub status_complete: bool,
    pub snapshot_pages: u16,
    pub snapshot_complete: bool,
    pub fast_snapshot_restore_pages: u16,
    pub fast_snapshot_restore_complete: bool,
    pub volumes: Vec<VolumePosture>,
    pub statuses: Vec<VolumeStatusPosture>,
    pub snapshots: Vec<SnapshotPosture>,
    pub fast_snapshot_restores: Vec<FastSnapshotRestorePosture>,
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

impl AwsEbsVolumeProposal {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &AwsEbsVolumeRegistration,
        request: &AwsEbsEvidenceRequest,
        state: EvidenceState,
        volume_pages: u16,
        volume_complete: bool,
        status_pages: u16,
        status_complete: bool,
        snapshot_pages: u16,
        snapshot_complete: bool,
        fast_snapshot_restore_pages: u16,
        fast_snapshot_restore_complete: bool,
        volumes: Vec<VolumePosture>,
        statuses: Vec<VolumeStatusPosture>,
        snapshots: Vec<SnapshotPosture>,
        fast_snapshot_restores: Vec<FastSnapshotRestorePosture>,
        failure: Option<FailureEvidence>,
        provenance: TransportProvenance,
        reads: ReadDigests,
    ) -> Self {
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: registration.provider_digest.clone(),
            permission_digest: registration.permission_digest(),
            consent_digest: registration.consent_digest(),
            volume_allowlist_digest: registration.volume_allowlist_digest.clone(),
            snapshot_allowlist_digest: registration.snapshot_allowlist_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            request_digest: request.digest(),
            volume_read_digest: reads.volume,
            status_read_digest: reads.status,
            snapshot_read_digest: reads.snapshot,
            fast_snapshot_restore_read_digest: reads.fast_snapshot_restore,
            evidence_digest: Digest::from_text("unsealed-aws-ebs-evidence"),
        };
        evidence.evidence_digest = calculate_evidence_digest(
            &evidence,
            state,
            volume_pages,
            volume_complete,
            status_pages,
            status_complete,
            snapshot_pages,
            snapshot_complete,
            fast_snapshot_restore_pages,
            fast_snapshot_restore_complete,
            &volumes,
            &statuses,
            &snapshots,
            &fast_snapshot_restores,
            failure.as_ref(),
        );
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: registration.scope_digest.clone(),
            volume_allowlist_digest: registration.volume_allowlist_digest.clone(),
            snapshot_allowlist_digest: registration.snapshot_allowlist_digest.clone(),
            mission: MissionProjection::from(registration.scope.mission()),
            project: ProjectProjection::from(registration.scope.project()),
            work_product: WorkProductProjection::from(registration.scope.work_product()),
            state,
            volume_pages,
            volume_complete,
            status_pages,
            status_complete,
            snapshot_pages,
            snapshot_complete,
            fast_snapshot_restore_pages,
            fast_snapshot_restore_complete,
            volumes,
            statuses,
            snapshots,
            fast_snapshot_restores,
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
            proposal_digest: Digest::from_text("unsealed-aws-ebs-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate()?;
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
                    self.volume_pages,
                    self.volume_complete,
                    self.status_pages,
                    self.status_complete,
                    self.snapshot_pages,
                    self.snapshot_complete,
                    self.fast_snapshot_restore_pages,
                    self.fast_snapshot_restore_complete,
                    &self.volumes,
                    &self.statuses,
                    &self.snapshots,
                    &self.fast_snapshot_restores,
                    self.failure.as_ref(),
                )
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AwsEbsVolumeError::TamperedEvidence);
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
            "aws-ebs-volume-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "volume_allowlist",
                    self.volume_allowlist_digest.as_str().to_owned(),
                ),
                (
                    "snapshot_allowlist",
                    self.snapshot_allowlist_digest.as_str().to_owned(),
                ),
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
                ("volume_pages", self.volume_pages.to_string()),
                ("volume_complete", self.volume_complete.to_string()),
                ("status_pages", self.status_pages.to_string()),
                ("status_complete", self.status_complete.to_string()),
                ("snapshot_pages", self.snapshot_pages.to_string()),
                ("snapshot_complete", self.snapshot_complete.to_string()),
                (
                    "fast_snapshot_restore_pages",
                    self.fast_snapshot_restore_pages.to_string(),
                ),
                (
                    "fast_snapshot_restore_complete",
                    self.fast_snapshot_restore_complete.to_string(),
                ),
                (
                    "volumes",
                    serde_json::to_string(&self.volumes).expect("volume posture serializes"),
                ),
                (
                    "statuses",
                    serde_json::to_string(&self.statuses).expect("status posture serializes"),
                ),
                (
                    "snapshots",
                    serde_json::to_string(&self.snapshots).expect("snapshot posture serializes"),
                ),
                (
                    "fast_snapshot_restores",
                    serde_json::to_string(&self.fast_snapshot_restores)
                        .expect("fast restore posture serializes"),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("failure serializes")
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

#[derive(Clone, Debug, Default)]
struct ReadDigests {
    volume: Option<Digest>,
    status: Option<Digest>,
    snapshot: Option<Digest>,
    fast_snapshot_restore: Option<Digest>,
}

fn calculate_evidence_digest(
    evidence: &EvidenceDigests,
    state: EvidenceState,
    volume_pages: u16,
    volume_complete: bool,
    status_pages: u16,
    status_complete: bool,
    snapshot_pages: u16,
    snapshot_complete: bool,
    fast_snapshot_restore_pages: u16,
    fast_snapshot_restore_complete: bool,
    volumes: &[VolumePosture],
    statuses: &[VolumeStatusPosture],
    snapshots: &[SnapshotPosture],
    fast_snapshot_restores: &[FastSnapshotRestorePosture],
    failure: Option<&FailureEvidence>,
) -> Digest {
    Digest::from_parts(
        "aws-ebs-evidence/v1",
        &[
            ("plugin", evidence.plugin_version_digest.as_str().to_owned()),
            ("contract", evidence.contract_digest.as_str().to_owned()),
            ("provider", evidence.provider_digest.as_str().to_owned()),
            ("permission", evidence.permission_digest.as_str().to_owned()),
            ("consent", evidence.consent_digest.as_str().to_owned()),
            (
                "volume_allowlist",
                evidence.volume_allowlist_digest.as_str().to_owned(),
            ),
            (
                "snapshot_allowlist",
                evidence.snapshot_allowlist_digest.as_str().to_owned(),
            ),
            ("scope", evidence.scope_digest.as_str().to_owned()),
            ("request", evidence.request_digest.as_str().to_owned()),
            (
                "volume_read",
                evidence
                    .volume_read_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "status_read",
                evidence
                    .status_read_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "snapshot_read",
                evidence
                    .snapshot_read_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "fast_snapshot_restore_read",
                evidence
                    .fast_snapshot_restore_read_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            ("state", format!("{state:?}")),
            ("volume_pages", volume_pages.to_string()),
            ("volume_complete", volume_complete.to_string()),
            ("status_pages", status_pages.to_string()),
            ("status_complete", status_complete.to_string()),
            ("snapshot_pages", snapshot_pages.to_string()),
            ("snapshot_complete", snapshot_complete.to_string()),
            (
                "fast_snapshot_restore_pages",
                fast_snapshot_restore_pages.to_string(),
            ),
            (
                "fast_snapshot_restore_complete",
                fast_snapshot_restore_complete.to_string(),
            ),
            (
                "volumes",
                serde_json::to_string(volumes).expect("volume posture serializes"),
            ),
            (
                "statuses",
                serde_json::to_string(statuses).expect("status posture serializes"),
            ),
            (
                "snapshots",
                serde_json::to_string(snapshots).expect("snapshot posture serializes"),
            ),
            (
                "fast_snapshot_restores",
                serde_json::to_string(fast_snapshot_restores)
                    .expect("fast restore posture serializes"),
            ),
            (
                "failure",
                failure.map_or_else(String::new, |value| {
                    serde_json::to_string(value).expect("failure serializes")
                }),
            ),
        ],
    )
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    PermissionDigestMismatch,
    ConsentDigestMismatch,
    VolumeAllowlistDigestMismatch,
    SnapshotAllowlistDigestMismatch,
    ScopeDigestMismatch,
    EvidenceDigestMismatch,
    ProposalDigestMismatch,
    PartialEvidence,
    StaleStatus,
    ResourceReplaced,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    NotFound,
    TamperedEvidence,
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
            "aws-ebs-verification-report/v1",
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

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsEbsServiceError {
    #[error("AWS EBS contract document is invalid")]
    ContractDrift,
    #[error("AWS EBS service registration is revoked")]
    RegistrationRevoked,
    #[error("AWS EBS service registration is inactive")]
    RegistrationInactive,
    #[error("AWS EBS scope or request digest does not verify")]
    ScopeMismatch,
    #[error("AWS EBS volume or snapshot allowlist drifted")]
    AllowlistMismatch,
    #[error("AWS EBS status evidence is stale")]
    StaleStatus,
    #[error("AWS EBS resource was replaced during the read")]
    ResourceReplaced,
    #[error("AWS EBS pagination loop detected")]
    PaginationLoop,
    #[error("AWS EBS evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS EBS transport failed for {operation:?}: {source}")]
    Transport {
        operation: AwsEbsOperation,
        source: AwsEbsTransportError,
    },
    #[error(transparent)]
    Model(#[from] AwsEbsVolumeError),
}

pub struct AwsEbsVolumeService<T: AwsEbsTransport> {
    registration: AwsEbsVolumeRegistration,
    provider: AwsEbsProvider<T>,
}

impl<T: AwsEbsTransport> fmt::Debug for AwsEbsVolumeService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEbsVolumeService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: AwsEbsTransport> AwsEbsVolumeService<T> {
    pub fn new(
        scope: AwsEbsVolumeScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AwsEbsProvider<T>,
        _registration_time: i64,
    ) -> Result<Self> {
        Self::with_registration(
            "aws-ebs-registration",
            scope,
            secret_reference,
            PermissionSnapshot::for_layer_one(1),
            consent,
            provider,
            1,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_registration(
        registration_id: impl Into<String>,
        scope: AwsEbsVolumeScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: AwsEbsProvider<T>,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = AwsEbsVolumeRegistration::new(
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
            operations: AwsEbsOperation::ALL
                .iter()
                .map(|operation| operation.as_str().to_owned())
                .collect(),
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

    pub fn scope(&self) -> &AwsEbsVolumeScope {
        self.registration.scope()
    }

    pub fn registration(&self) -> &AwsEbsVolumeRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsEbsVolumeRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsEbsProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsEbsProvider<T> {
        &mut self.provider
    }

    pub fn default_request(&self, observed_at: i64) -> Result<AwsEbsEvidenceRequest> {
        AwsEbsEvidenceRequest::new(
            self.scope(),
            &self.registration,
            self.provider.definition(),
            crate::MAX_PAGES,
            observed_at,
        )
    }

    pub fn propose(
        &mut self,
        request: AwsEbsEvidenceRequest,
    ) -> std::result::Result<AwsEbsVolumeProposal, AwsEbsServiceError> {
        self.validate_request(&request)?;
        if !self.registration.is_active() {
            return Err(AwsEbsServiceError::RegistrationInactive);
        }
        if self.registration.consent().is_revoked() {
            return Err(AwsEbsServiceError::RegistrationRevoked);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at)
        {
            return Err(AwsEbsServiceError::RegistrationInactive);
        }

        let volumes = match self.read_volumes(&request.volumes, request.max_pages) {
            Ok(value) => value,
            Err(error) => return self.failure_proposal(&request, error),
        };
        let mut volume_fences = BTreeMap::new();
        for item in &volumes.items {
            if !self.scope().allows_volume(&item.volume_id)
                || item
                    .snapshot_id
                    .as_ref()
                    .is_some_and(|snapshot| !self.scope().allows_snapshot(snapshot))
                || item
                    .attachments
                    .iter()
                    .any(|attachment| !self.scope().allows_attachment(&attachment.instance_id))
            {
                return Err(AwsEbsServiceError::AllowlistMismatch);
            }
            if volume_fences
                .insert(item.volume_id.clone(), item.resource_digest.clone())
                .is_some()
            {
                return Err(AwsEbsServiceError::ResourceReplaced);
            }
        }
        if volume_fences.len() != self.scope().volume_allowlist().len() {
            return Ok(self.non_adoptable_proposal(
                &request,
                EvidenceState::NotFound,
                volumes,
                ReadPages::empty(),
                ReadPages::empty(),
                ReadPages::empty(),
                Some(FailureEvidence::missing(
                    AwsEbsOperation::DescribeVolumes,
                    "volume_allowlist_incomplete",
                )),
            ));
        }

        let statuses = match self.read_volume_status(&request.volume_status, request.max_pages) {
            Ok(value) => value,
            Err(error) => return self.failure_with_volumes(&request, volumes, error),
        };
        if statuses
            .items
            .iter()
            .any(|status| is_stale(status.observed_at, request.observed_at))
        {
            return Ok(self.non_adoptable_proposal(
                &request,
                EvidenceState::StaleStatus,
                volumes,
                statuses,
                ReadPages::empty(),
                ReadPages::empty(),
                Some(FailureEvidence::missing(
                    AwsEbsOperation::DescribeVolumeStatus,
                    "stale_status",
                )),
            ));
        }
        if statuses.items.len() != self.scope().volume_allowlist().len()
            || statuses.items.iter().any(|status| {
                volume_fences
                    .get(&status.volume_id)
                    .is_none_or(|digest| digest != &status.resource_digest)
            })
        {
            return Ok(self.non_adoptable_proposal(
                &request,
                EvidenceState::ResourceReplaced,
                volumes,
                statuses,
                ReadPages::empty(),
                ReadPages::empty(),
                Some(FailureEvidence::missing(
                    AwsEbsOperation::DescribeVolumeStatus,
                    "status_resource_fence",
                )),
            ));
        }

        let snapshots = match self.read_snapshots(&request.snapshots, request.max_pages) {
            Ok(value) => value,
            Err(error) => {
                return self.failure_with_volume_status(&request, volumes, statuses, error);
            }
        };
        let mut snapshot_fences = BTreeMap::new();
        for item in &snapshots.items {
            if !self.scope().allows_snapshot(&item.snapshot_id)
                || item
                    .volume_id
                    .as_ref()
                    .is_some_and(|volume| !self.scope().allows_volume(volume))
            {
                return Err(AwsEbsServiceError::AllowlistMismatch);
            }
            if snapshot_fences
                .insert(item.snapshot_id.clone(), item.resource_digest.clone())
                .is_some()
            {
                return Err(AwsEbsServiceError::ResourceReplaced);
            }
        }
        if snapshot_fences.len() != self.scope().snapshot_allowlist().len() {
            return Ok(self.non_adoptable_proposal(
                &request,
                EvidenceState::NotFound,
                volumes,
                statuses,
                snapshots,
                ReadPages::empty(),
                Some(FailureEvidence::missing(
                    AwsEbsOperation::DescribeSnapshots,
                    "snapshot_allowlist_incomplete",
                )),
            ));
        }

        let fast_snapshot_restores = match self
            .read_fast_snapshot_restores(&request.fast_snapshot_restores, request.max_pages)
        {
            Ok(value) => value,
            Err(error) => {
                return self
                    .failure_with_volume_snapshot(&request, volumes, statuses, snapshots, error);
            }
        };
        if fast_snapshot_restores
            .items
            .iter()
            .any(|item| is_stale(item.observed_at, request.observed_at))
        {
            return Ok(self.non_adoptable_proposal(
                &request,
                EvidenceState::ProviderUnknown,
                volumes,
                statuses,
                snapshots,
                fast_snapshot_restores,
                Some(FailureEvidence::missing(
                    AwsEbsOperation::DescribeFastSnapshotRestores,
                    "stale_fast_snapshot_restore_status",
                )),
            ));
        }

        let provenance = volumes
            .provenance
            .clone()
            .unwrap_or(TransportProvenance::BlockedEnv);
        Ok(self.complete_proposal(
            &request,
            volumes,
            statuses,
            snapshots,
            fast_snapshot_restores,
            provenance,
        ))
    }

    pub fn read(
        &mut self,
        request: AwsEbsEvidenceRequest,
    ) -> std::result::Result<AwsEbsVolumeProposal, AwsEbsServiceError> {
        self.propose(request)
    }

    pub fn verify(&self, proposal: &AwsEbsVolumeProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.provider_digest != *self.registration.provider_digest() {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.permission_digest != self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.consent_digest != self.registration.consent_digest() {
            failures.push(VerificationFailure::ConsentDigestMismatch);
        }
        if proposal.volume_allowlist_digest != *self.registration.volume_allowlist_digest() {
            failures.push(VerificationFailure::VolumeAllowlistDigestMismatch);
        }
        if proposal.snapshot_allowlist_digest != *self.registration.snapshot_allowlist_digest() {
            failures.push(VerificationFailure::SnapshotAllowlistDigestMismatch);
        }
        if proposal.scope_digest != *self.registration.scope_digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.evidence_digest
            != calculate_evidence_digest(
                &proposal.evidence,
                proposal.state,
                proposal.volume_pages,
                proposal.volume_complete,
                proposal.status_pages,
                proposal.status_complete,
                proposal.snapshot_pages,
                proposal.snapshot_complete,
                proposal.fast_snapshot_restore_pages,
                proposal.fast_snapshot_restore_complete,
                &proposal.volumes,
                &proposal.statuses,
                &proposal.snapshots,
                &proposal.fast_snapshot_restores,
                proposal.failure.as_ref(),
            )
        {
            failures.push(VerificationFailure::EvidenceDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        if proposal.state != EvidenceState::Completed
            || !proposal.volume_complete
            || !proposal.status_complete
            || !proposal.snapshot_complete
            || !proposal.fast_snapshot_restore_complete
        {
            failures.push(VerificationFailure::PartialEvidence);
        }
        match proposal.state {
            EvidenceState::StaleStatus => failures.push(VerificationFailure::StaleStatus),
            EvidenceState::ResourceReplaced => failures.push(VerificationFailure::ResourceReplaced),
            EvidenceState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            EvidenceState::Throttled => failures.push(VerificationFailure::Throttled),
            EvidenceState::ProviderUnknown => failures.push(VerificationFailure::ProviderUnknown),
            EvidenceState::NotFound => failures.push(VerificationFailure::NotFound),
            EvidenceState::Completed
            | EvidenceState::Partial
            | EvidenceState::RegistrationRevoked => {}
        }
        failures.sort();
        failures.dedup();
        let valid = failures.is_empty();
        VerificationReport::new(valid, valid && proposal.is_review_only(), failures)
    }

    pub fn consumer(&self) -> std::result::Result<MissionAwsEbsConsumer, AwsEbsVolumeError> {
        MissionAwsEbsConsumer::new(self.scope().clone(), self.registration.clone())
    }

    fn validate_request(&self, request: &AwsEbsEvidenceRequest) -> Result<()> {
        request.validate(self.scope(), &self.registration, self.provider.definition())?;
        self.registration.validate()?;
        Ok(())
    }

    fn complete_proposal(
        &self,
        request: &AwsEbsEvidenceRequest,
        volumes: ReadPages<VolumeMetadataInput>,
        statuses: ReadPages<VolumeStatusInput>,
        snapshots: ReadPages<SnapshotMetadataInput>,
        fast_snapshot_restores: ReadPages<FastSnapshotRestoreInput>,
        provenance: TransportProvenance,
    ) -> AwsEbsVolumeProposal {
        AwsEbsVolumeProposal::new(
            &self.registration,
            request,
            EvidenceState::Completed,
            volumes.pages,
            volumes.complete,
            statuses.pages,
            statuses.complete,
            snapshots.pages,
            snapshots.complete,
            fast_snapshot_restores.pages,
            fast_snapshot_restores.complete,
            volumes.items.iter().map(VolumePosture::from).collect(),
            statuses
                .items
                .iter()
                .map(VolumeStatusPosture::from)
                .collect(),
            snapshots
                .items
                .iter()
                .map(|item| SnapshotPosture::from_input(item, request.observed_at))
                .collect(),
            fast_snapshot_restores
                .items
                .iter()
                .map(FastSnapshotRestorePosture::from)
                .collect(),
            None,
            provenance,
            ReadDigests {
                volume: volumes.read_digest,
                status: statuses.read_digest,
                snapshot: snapshots.read_digest,
                fast_snapshot_restore: fast_snapshot_restores.read_digest,
            },
        )
    }

    fn non_adoptable_proposal(
        &self,
        request: &AwsEbsEvidenceRequest,
        state: EvidenceState,
        volumes: ReadPages<VolumeMetadataInput>,
        statuses: ReadPages<VolumeStatusInput>,
        snapshots: ReadPages<SnapshotMetadataInput>,
        fast_snapshot_restores: ReadPages<FastSnapshotRestoreInput>,
        failure: Option<FailureEvidence>,
    ) -> AwsEbsVolumeProposal {
        let provenance = volumes
            .provenance
            .clone()
            .or_else(|| statuses.provenance.clone())
            .or_else(|| snapshots.provenance.clone())
            .or_else(|| fast_snapshot_restores.provenance.clone())
            .unwrap_or(TransportProvenance::BlockedEnv);
        AwsEbsVolumeProposal::new(
            &self.registration,
            request,
            state,
            volumes.pages,
            volumes.complete,
            statuses.pages,
            statuses.complete,
            snapshots.pages,
            snapshots.complete,
            fast_snapshot_restores.pages,
            fast_snapshot_restores.complete,
            volumes.items.iter().map(VolumePosture::from).collect(),
            statuses
                .items
                .iter()
                .map(VolumeStatusPosture::from)
                .collect(),
            snapshots
                .items
                .iter()
                .map(|item| SnapshotPosture::from_input(item, request.observed_at))
                .collect(),
            fast_snapshot_restores
                .items
                .iter()
                .map(FastSnapshotRestorePosture::from)
                .collect(),
            failure,
            provenance,
            ReadDigests {
                volume: volumes.read_digest,
                status: statuses.read_digest,
                snapshot: snapshots.read_digest,
                fast_snapshot_restore: fast_snapshot_restores.read_digest,
            },
        )
    }

    fn failure_proposal(
        &self,
        request: &AwsEbsEvidenceRequest,
        error: AwsEbsServiceError,
    ) -> std::result::Result<AwsEbsVolumeProposal, AwsEbsServiceError> {
        match error {
            AwsEbsServiceError::Transport { operation, source } => Ok(self.non_adoptable_proposal(
                request,
                failure_state(&source),
                ReadPages::empty(),
                ReadPages::empty(),
                ReadPages::empty(),
                ReadPages::empty(),
                Some(FailureEvidence::from_transport(operation, &source)),
            )),
            other => Err(other),
        }
    }

    fn failure_with_volumes(
        &self,
        request: &AwsEbsEvidenceRequest,
        volumes: ReadPages<VolumeMetadataInput>,
        error: AwsEbsServiceError,
    ) -> std::result::Result<AwsEbsVolumeProposal, AwsEbsServiceError> {
        match error {
            AwsEbsServiceError::Transport { operation, source } => Ok(self.non_adoptable_proposal(
                request,
                failure_state(&source),
                volumes,
                ReadPages::empty(),
                ReadPages::empty(),
                ReadPages::empty(),
                Some(FailureEvidence::from_transport(operation, &source)),
            )),
            other => Err(other),
        }
    }

    fn failure_with_volume_status(
        &self,
        request: &AwsEbsEvidenceRequest,
        volumes: ReadPages<VolumeMetadataInput>,
        statuses: ReadPages<VolumeStatusInput>,
        error: AwsEbsServiceError,
    ) -> std::result::Result<AwsEbsVolumeProposal, AwsEbsServiceError> {
        match error {
            AwsEbsServiceError::Transport { operation, source } => Ok(self.non_adoptable_proposal(
                request,
                failure_state(&source),
                volumes,
                statuses,
                ReadPages::empty(),
                ReadPages::empty(),
                Some(FailureEvidence::from_transport(operation, &source)),
            )),
            other => Err(other),
        }
    }

    fn failure_with_volume_snapshot(
        &self,
        request: &AwsEbsEvidenceRequest,
        volumes: ReadPages<VolumeMetadataInput>,
        statuses: ReadPages<VolumeStatusInput>,
        snapshots: ReadPages<SnapshotMetadataInput>,
        error: AwsEbsServiceError,
    ) -> std::result::Result<AwsEbsVolumeProposal, AwsEbsServiceError> {
        match error {
            AwsEbsServiceError::Transport { operation, source } => Ok(self.non_adoptable_proposal(
                request,
                failure_state(&source),
                volumes,
                statuses,
                snapshots,
                ReadPages::empty(),
                Some(FailureEvidence::from_transport(operation, &source)),
            )),
            other => Err(other),
        }
    }

    fn read_volumes(
        &mut self,
        initial: &DescribeVolumesRequest,
        max_pages: u16,
    ) -> std::result::Result<ReadPages<VolumeMetadataInput>, AwsEbsServiceError> {
        let mut request = initial.clone();
        let mut pages = ReadPages::empty();
        let mut seen = BTreeSet::new();
        loop {
            if pages.pages >= max_pages {
                pages.complete = false;
                return Ok(pages);
            }
            let response = self
                .provider
                .describe_volumes(&request)
                .map_err(|error| map_provider_error(AwsEbsOperation::DescribeVolumes, error))?;
            pages.push(
                response.volume_metadata,
                response.read_digest,
                response.provenance,
            );
            if let Some(cursor) = response.next_cursor {
                if !seen.insert(cursor.token_digest().clone()) {
                    return Err(AwsEbsServiceError::PaginationLoop);
                }
                request = request.with_cursor(Some(cursor))?;
            } else {
                pages.complete = true;
                return Ok(pages);
            }
        }
    }

    fn read_volume_status(
        &mut self,
        initial: &DescribeVolumeStatusRequest,
        max_pages: u16,
    ) -> std::result::Result<ReadPages<VolumeStatusInput>, AwsEbsServiceError> {
        let mut request = initial.clone();
        let mut pages = ReadPages::empty();
        let mut seen = BTreeSet::new();
        loop {
            if pages.pages >= max_pages {
                pages.complete = false;
                return Ok(pages);
            }
            let response = self
                .provider
                .describe_volume_status(&request)
                .map_err(|error| {
                    map_provider_error(AwsEbsOperation::DescribeVolumeStatus, error)
                })?;
            pages.push(
                response.volume_status,
                response.read_digest,
                response.provenance,
            );
            if let Some(cursor) = response.next_cursor {
                if !seen.insert(cursor.token_digest().clone()) {
                    return Err(AwsEbsServiceError::PaginationLoop);
                }
                request = request.with_cursor(Some(cursor))?;
            } else {
                pages.complete = true;
                return Ok(pages);
            }
        }
    }

    fn read_snapshots(
        &mut self,
        initial: &DescribeSnapshotsRequest,
        max_pages: u16,
    ) -> std::result::Result<ReadPages<SnapshotMetadataInput>, AwsEbsServiceError> {
        let mut request = initial.clone();
        let mut pages = ReadPages::empty();
        let mut seen = BTreeSet::new();
        loop {
            if pages.pages >= max_pages {
                pages.complete = false;
                return Ok(pages);
            }
            let response = self
                .provider
                .describe_snapshots(&request)
                .map_err(|error| map_provider_error(AwsEbsOperation::DescribeSnapshots, error))?;
            pages.push(
                response.snapshots,
                response.read_digest,
                response.provenance,
            );
            if let Some(cursor) = response.next_cursor {
                if !seen.insert(cursor.token_digest().clone()) {
                    return Err(AwsEbsServiceError::PaginationLoop);
                }
                request = request.with_cursor(Some(cursor))?;
            } else {
                pages.complete = true;
                return Ok(pages);
            }
        }
    }

    fn read_fast_snapshot_restores(
        &mut self,
        initial: &DescribeFastSnapshotRestoresRequest,
        max_pages: u16,
    ) -> std::result::Result<ReadPages<FastSnapshotRestoreInput>, AwsEbsServiceError> {
        let mut request = initial.clone();
        let mut pages = ReadPages::empty();
        let mut seen = BTreeSet::new();
        loop {
            if pages.pages >= max_pages {
                pages.complete = false;
                return Ok(pages);
            }
            let response = self
                .provider
                .describe_fast_snapshot_restores(&request)
                .map_err(|error| {
                    map_provider_error(AwsEbsOperation::DescribeFastSnapshotRestores, error)
                })?;
            pages.push(
                response.fast_snapshot_restores,
                response.read_digest,
                response.provenance,
            );
            if let Some(cursor) = response.next_cursor {
                if !seen.insert(cursor.token_digest().clone()) {
                    return Err(AwsEbsServiceError::PaginationLoop);
                }
                request = request.with_cursor(Some(cursor))?;
            } else {
                pages.complete = true;
                return Ok(pages);
            }
        }
    }
}

impl FailureEvidence {
    fn missing(operation: AwsEbsOperation, category: &str) -> Self {
        let error = AwsEbsTransportError::InvalidResponse;
        let mut evidence = Self::from_transport(operation, &error);
        evidence.category = category.to_owned();
        evidence.failure_digest = Digest::from_parts(
            "aws-ebs-failure/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("category", category.to_owned()),
                ("status", String::new()),
            ],
        );
        evidence
    }
}

#[derive(Clone, Debug)]
struct ReadPages<T> {
    items: Vec<T>,
    pages: u16,
    complete: bool,
    read_digest: Option<Digest>,
    provenance: Option<TransportProvenance>,
}

impl<T> ReadPages<T> {
    fn empty() -> Self {
        Self {
            items: Vec::new(),
            pages: 0,
            complete: false,
            read_digest: None,
            provenance: None,
        }
    }

    fn push(&mut self, items: Vec<T>, read_digest: Digest, provenance: TransportProvenance) {
        self.pages = self.pages.saturating_add(1);
        self.items.extend(items);
        self.read_digest = Some(match self.read_digest.take() {
            Some(previous) => Digest::from_parts(
                "aws-ebs-read-pages/v1",
                &[
                    ("previous", previous.as_str().to_owned()),
                    ("page", read_digest.as_str().to_owned()),
                ],
            ),
            None => read_digest,
        });
        self.provenance = Some(provenance);
    }
}

fn map_provider_error(operation: AwsEbsOperation, error: AwsEbsVolumeError) -> AwsEbsServiceError {
    match error {
        AwsEbsVolumeError::Transport(source) => AwsEbsServiceError::Transport { operation, source },
        other => AwsEbsServiceError::Model(other),
    }
}

fn failure_state(error: &AwsEbsTransportError) -> EvidenceState {
    match error {
        AwsEbsTransportError::NotFound => EvidenceState::NotFound,
        AwsEbsTransportError::Unauthorized
        | AwsEbsTransportError::Forbidden
        | AwsEbsTransportError::AccessLoss => EvidenceState::AccessLoss,
        AwsEbsTransportError::RateLimited { .. } => EvidenceState::Throttled,
        AwsEbsTransportError::Partial => EvidenceState::Partial,
        AwsEbsTransportError::BlockedEnv
        | AwsEbsTransportError::BadRequest
        | AwsEbsTransportError::Conflict
        | AwsEbsTransportError::ServerError { .. }
        | AwsEbsTransportError::Timeout
        | AwsEbsTransportError::InvalidResponse => EvidenceState::ProviderUnknown,
    }
}

fn valid_registration_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}
