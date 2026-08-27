//! Registration, proposal, recording, and verification seams for the
//! bounded AWS Control Tower Layer-1 read contract.

use std::{collections::BTreeMap, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::{
    API_DIGEST, API_REVISION, API_VERSION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION,
    LAYER1_PERMISSIONS, PLUGIN_VERSION, PROVIDER_VERSION, SERVICE_ID,
    consumer::MissionAwsControlTowerConsumer,
    model::{
        AwsControlTowerScope, BaselineStatus, Digest, DriftStatus, EnabledBaselineSummary,
        EvidenceStatus, LandingZoneDetail, LandingZoneOperation, LandingZoneStatus, ModelError,
        OperationId, OperationStatus, OperationType, ReadOperation, SigV4SecretReference,
    },
    provider::{
        AwsControlTowerProvider, AwsControlTowerProviderDefinition,
        AwsControlTowerProviderResponse, AwsControlTowerReadRequest, AwsControlTowerTransport,
        GetLandingZoneOperationRequest, GetLandingZoneRequest, ListEnabledBaselinesRequest,
        ListLandingZonesRequest, ProviderError, ProviderProvenance, TransportError,
    },
};

pub type ServiceResult<T> = std::result::Result<T, AwsControlTowerServiceError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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
    pub status: RegistrationStatus,
    pub registration_revision: u64,
    pub registration_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsControlTowerRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub api_version: String,
    pub api_revision: String,
    pub api_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub account_digest: Digest,
    pub home_region_digest: Digest,
    pub landing_zone_digest: Digest,
    pub baseline_scope_digest: Digest,
    pub target_scope_digest: Digest,
    pub operation_scope_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub secret_reference_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
}

pub type Registration = AwsControlTowerRegistration;

impl AwsControlTowerRegistration {
    pub(crate) fn new(
        scope: &AwsControlTowerScope,
        secret: &SigV4SecretReference,
        provider: &AwsControlTowerProviderDefinition,
    ) -> Self {
        let evidence_digest = Digest::from_parts(
            "aws-control-tower-evidence-registration/v1",
            &[
                CONTRACT_VERSION.to_owned(),
                provider.provider_digest.to_string(),
                provider.api_digest.to_string(),
                scope.permission.permission_digest.to_string(),
                scope.scope_digest.to_string(),
                scope.account_id.digest().to_string(),
                scope.home_region.digest().to_string(),
                scope.landing_zone.digest().to_string(),
                scope.baseline_scope_digest().to_string(),
                scope.target_scope_digest().to_string(),
            ],
        );
        let mut registration = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest_value(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            api_version: provider.api_version.clone(),
            api_revision: provider.api_revision.clone(),
            api_digest: provider.api_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_digest: scope.permission.permission_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            account_digest: scope.account_id.digest(),
            home_region_digest: scope.home_region.digest(),
            landing_zone_digest: scope.landing_zone.digest(),
            baseline_scope_digest: scope.baseline_scope_digest(),
            target_scope_digest: scope.target_scope_digest(),
            operation_scope_digest: Digest::from_parts(
                "aws-control-tower-operation-scope/v1",
                &scope
                    .operation_ids
                    .iter()
                    .map(|value| value.digest().to_string())
                    .collect::<Vec<_>>(),
            ),
            project_digest: scope.project_id.digest(),
            mission_digest: scope.mission_id.digest(),
            work_product_digest: scope.work_product_id.digest(),
            secret_reference_digest: secret.digest(),
            evidence_digest,
            registration_revision: 1,
            status: RegistrationStatus::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        registration
    }

    pub fn validate(&self) -> ServiceResult<()> {
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest_value()
            || self.provider_version != PROVIDER_VERSION
            || self.api_version != API_VERSION
            || self.api_revision != API_REVISION
            || self.api_digest != Digest::from_text(API_DIGEST)
            || self.registration_revision == 0
            || self.registration_digest != self.recomputed_digest()
            || self.evidence_digest.is_zero()
        {
            return Err(AwsControlTowerServiceError::RegistrationMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        self.registration_digest.clone()
    }

    pub fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-registration/v1",
            &[
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.contract_digest.to_string(),
                self.provider_id.clone(),
                self.provider_version.clone(),
                self.api_version.clone(),
                self.api_revision.clone(),
                self.api_digest.to_string(),
                self.provider_digest.to_string(),
                self.permission_digest.to_string(),
                self.scope_digest.to_string(),
                self.account_digest.to_string(),
                self.home_region_digest.to_string(),
                self.landing_zone_digest.to_string(),
                self.baseline_scope_digest.to_string(),
                self.target_scope_digest.to_string(),
                self.operation_scope_digest.to_string(),
                self.project_digest.to_string(),
                self.mission_digest.to_string(),
                self.work_product_digest.to_string(),
                self.secret_reference_digest.to_string(),
                self.evidence_digest.to_string(),
                self.registration_revision.to_string(),
                format!("{:?}", self.status),
            ],
        )
    }

    pub fn revoke(&mut self) -> ServiceResult<RegistrationTransitionEvidence> {
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn reverse(&mut self) -> ServiceResult<RegistrationTransitionEvidence> {
        self.transition(RegistrationStatus::Reversed)
    }

    pub fn restore(&mut self) -> ServiceResult<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsControlTowerServiceError::RegistrationReversed);
        }
        self.transition(RegistrationStatus::Active)
    }

    fn transition(
        &mut self,
        status: RegistrationStatus,
    ) -> ServiceResult<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsControlTowerServiceError::RegistrationReversed);
        }
        if self.status == status && matches!(status, RegistrationStatus::Revoked) {
            return Err(AwsControlTowerServiceError::RegistrationAlreadyRevoked);
        }
        let previous_status = self.status;
        self.status = status;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransitionEvidence {
            previous_status,
            status,
            registration_revision: self.registration_revision,
            registration_digest: self.digest(),
        })
    }
}

impl Serialize for AwsControlTowerRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsControlTowerRegistration", 27)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerIdDigest", &Digest::from_text(&self.provider_id))?;
        state.serialize_field("providerVersion", &self.provider_version)?;
        state.serialize_field("apiVersion", &self.api_version)?;
        state.serialize_field("apiRevisionDigest", &Digest::from_text(&self.api_revision))?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("accountDigest", &self.account_digest)?;
        state.serialize_field("homeRegionDigest", &self.home_region_digest)?;
        state.serialize_field("landingZoneDigest", &self.landing_zone_digest)?;
        state.serialize_field("baselineScopeDigest", &self.baseline_scope_digest)?;
        state.serialize_field("targetScopeDigest", &self.target_scope_digest)?;
        state.serialize_field("operationScopeDigest", &self.operation_scope_digest)?;
        state.serialize_field("projectDigest", &self.project_digest)?;
        state.serialize_field("missionDigest", &self.mission_digest)?;
        state.serialize_field("workProductDigest", &self.work_product_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
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
    pub proposal_only: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityBoundary {
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub durable_receipt: bool,
    pub compliance_claim: bool,
    pub deployment_success_claim: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionSummary {
    pub raw_secret_material_redacted: bool,
    pub raw_next_tokens_redacted: bool,
    pub raw_arns_redacted: bool,
    pub raw_versions_redacted: bool,
    pub raw_timestamps_redacted: bool,
    pub raw_manifest_redacted: bool,
    pub raw_status_messages_redacted: bool,
}

impl Default for RedactionSummary {
    fn default() -> Self {
        Self {
            raw_secret_material_redacted: true,
            raw_next_tokens_redacted: true,
            raw_arns_redacted: true,
            raw_versions_redacted: true,
            raw_timestamps_redacted: true,
            raw_manifest_redacted: true,
            raw_status_messages_redacted: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationEvidence {
    pub pages_observed: u16,
    pub items_observed: usize,
    pub complete: bool,
    pub cursor_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: String,
    pub category: String,
    pub status_code: Option<u16>,
    pub detail_digest: Digest,
}

impl FailureEvidence {
    pub fn new(operation: &str, category: &str, status_code: Option<u16>) -> Self {
        Self {
            operation: operation.to_owned(),
            category: category.to_owned(),
            status_code,
            detail_digest: Digest::from_parts(
                "aws-control-tower-failure/v1",
                &[
                    operation.to_owned(),
                    category.to_owned(),
                    format!("{status_code:?}"),
                ],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub version_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub response_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsControlTowerGovernanceEvidence {
    pub operation: ReadOperation,
    pub state: EvidenceStatus,
    pub account_digest: Digest,
    pub home_region_digest: Digest,
    pub landing_zone_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub landing_zones: Vec<crate::model::LandingZoneSummary>,
    pub landing_zone: Option<LandingZoneDetail>,
    pub operation_detail: Option<LandingZoneOperation>,
    pub enabled_baselines: Vec<EnabledBaselineSummary>,
    pub pagination: PaginationEvidence,
    pub redaction: RedactionSummary,
    pub authority: AuthorityBoundary,
    pub provenance: ProviderProvenance,
    pub failure: Option<FailureEvidence>,
    pub observed_at_digest: Digest,
    pub digests: EvidenceDigests,
}

impl Serialize for AwsControlTowerGovernanceEvidence {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsControlTowerGovernanceEvidence", 21)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("state", &self.state)?;
        state.serialize_field("accountDigest", &self.account_digest)?;
        state.serialize_field("homeRegionDigest", &self.home_region_digest)?;
        state.serialize_field("landingZoneDigest", &self.landing_zone_digest)?;
        state.serialize_field("projectDigest", &self.project_digest)?;
        state.serialize_field("missionDigest", &self.mission_digest)?;
        state.serialize_field("workProductDigest", &self.work_product_digest)?;
        state.serialize_field("landingZones", &self.landing_zones)?;
        state.serialize_field("landingZone", &self.landing_zone)?;
        state.serialize_field("operationDetail", &self.operation_detail)?;
        state.serialize_field("enabledBaselines", &self.enabled_baselines)?;
        state.serialize_field("pagination", &self.pagination)?;
        state.serialize_field("redaction", &self.redaction)?;
        state.serialize_field("authority", &self.authority)?;
        state.serialize_field("provenance", &self.provenance)?;
        state.serialize_field("failure", &self.failure)?;
        state.serialize_field("observedAtDigest", &self.observed_at_digest)?;
        state.serialize_field("digests", &self.digests)?;
        state.end()
    }
}

impl AwsControlTowerGovernanceEvidence {
    pub fn evidence_digest(&self) -> &Digest {
        &self.digests.evidence_digest
    }

    pub fn verify_integrity(&self) -> ServiceResult<()> {
        let rebuilt = self.recomputed_digest();
        if rebuilt != self.digests.evidence_digest {
            return Err(AwsControlTowerServiceError::TamperedEvidence);
        }
        for item in &self.landing_zones {
            item.verify()?;
        }
        if let Some(detail) = &self.landing_zone {
            detail.verify()?;
        }
        if let Some(operation) = &self.operation_detail {
            operation.verify()?;
        }
        for baseline in &self.enabled_baselines {
            baseline.verify()?;
        }
        Ok(())
    }

    fn recomputed_digest(&self) -> Digest {
        let mut parts = vec![
            format!("{:?}", self.operation),
            format!("{:?}", self.state),
            self.account_digest.to_string(),
            self.home_region_digest.to_string(),
            self.landing_zone_digest.to_string(),
            self.project_digest.to_string(),
            self.mission_digest.to_string(),
            self.work_product_digest.to_string(),
            self.pagination.pages_observed.to_string(),
            self.pagination.items_observed.to_string(),
            self.pagination.complete.to_string(),
            format!("{:?}", self.provenance),
            self.observed_at_digest.to_string(),
            self.digests.version_digest.to_string(),
            self.digests.provider_digest.to_string(),
            self.digests.api_digest.to_string(),
            self.digests.contract_digest.to_string(),
            self.digests.permission_digest.to_string(),
            self.digests.scope_digest.to_string(),
            self.digests.response_digest.to_string(),
        ];
        parts.extend(
            self.landing_zones
                .iter()
                .map(|item| item.arn_digest.to_string()),
        );
        if let Some(detail) = &self.landing_zone {
            parts.extend([
                detail.arn_digest.to_string(),
                detail.status_digest.to_string(),
                detail.drift_status_digest.to_string(),
                detail.version_digest.to_string(),
                detail.timestamp_digest.to_string(),
            ]);
        }
        if let Some(operation) = &self.operation_detail {
            parts.extend([
                operation.operation_identifier_digest.to_string(),
                operation.status_digest.to_string(),
                operation.start_timestamp_digest.to_string(),
            ]);
        }
        parts.extend(
            self.enabled_baselines
                .iter()
                .map(|item| item.baseline_identifier_digest.to_string()),
        );
        parts.extend(
            self.pagination
                .cursor_digests
                .iter()
                .map(ToString::to_string),
        );
        Digest::from_parts("aws-control-tower-evidence/v1", &parts)
    }

    pub fn is_connected(&self) -> bool {
        self.authority.connected
    }

    pub fn claims_compliance(&self) -> bool {
        self.authority.compliance_claim
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsControlTowerGovernanceProposal {
    pub operation: ReadOperation,
    pub request: AwsControlTowerReadRequest,
    pub mission: crate::model::MissionBinding,
    pub registration_digest: Digest,
    pub registration_revision: u64,
    pub version_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence: AwsControlTowerGovernanceEvidence,
    pub state: EvidenceStatus,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub proposal_digest: Digest,
}

impl Serialize for AwsControlTowerGovernanceProposal {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsControlTowerGovernanceProposal", 19)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("request", &self.request)?;
        state.serialize_field("mission", &self.mission)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("versionDigest", &self.version_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("evidence", &self.evidence)?;
        state.serialize_field("state", &self.state)?;
        state.serialize_field("connected", &self.connected)?;
        state.serialize_field("native", &self.native)?;
        state.serialize_field("firstParty", &self.first_party)?;
        state.serialize_field("providerReceipt", &self.provider_receipt)?;
        state.serialize_field("proposalDigest", &self.proposal_digest)?;
        state.end()
    }
}

impl AwsControlTowerGovernanceProposal {
    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-proposal/v1",
            &[
                self.operation.api_name().to_owned(),
                self.request.request_digest().to_string(),
                self.mission.digest().to_string(),
                self.registration_digest.to_string(),
                self.registration_revision.to_string(),
                self.version_digest.to_string(),
                self.provider_digest.to_string(),
                self.api_digest.to_string(),
                self.contract_digest.to_string(),
                self.permission_digest.to_string(),
                self.scope_digest.to_string(),
                self.evidence.evidence_digest().to_string(),
                format!("{:?}", self.state),
            ],
        )
    }

    pub fn verify_integrity(&self) -> ServiceResult<()> {
        self.evidence.verify_integrity()?;
        if self.operation != self.request.operation()
            || self.proposal_digest != self.recomputed_digest()
            || self.state != self.evidence.state
        {
            return Err(AwsControlTowerServiceError::TamperedProposal);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsControlTowerRecordReceipt {
    pub recorded: bool,
    pub replayed: bool,
    pub recorded_at: DateTime<Utc>,
    pub recording_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub receipt_digest: Digest,
}

pub type RecordedAwsControlTowerResult = AwsControlTowerRecordReceipt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    ProposalTampered,
    EvidenceTampered,
    RegistrationRevoked,
    SecretRevoked,
    RetentionExpired,
    StateNotReviewEligible,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub state: EvidenceStatus,
    pub failure: Option<VerificationFailure>,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsControlTowerServiceError {
    #[error("AWS Control Tower registration is revoked")]
    RegistrationRevoked,
    #[error("AWS Control Tower registration is reversed")]
    RegistrationReversed,
    #[error("AWS Control Tower registration is already revoked")]
    RegistrationAlreadyRevoked,
    #[error("AWS Control Tower registration does not verify")]
    RegistrationMismatch,
    #[error("AWS Control Tower SecretReference is revoked")]
    SecretRevoked,
    #[error("AWS Control Tower scope does not verify")]
    ScopeMismatch,
    #[error("AWS Control Tower permission is missing or drifted")]
    PermissionLoss,
    #[error("AWS Control Tower request is outside the exact scope")]
    OutOfScope,
    #[error("AWS Control Tower proposal is tampered")]
    TamperedProposal,
    #[error("AWS Control Tower evidence is tampered")]
    TamperedEvidence,
    #[error("AWS Control Tower record is incomplete")]
    IncompleteRecord,
    #[error("AWS Control Tower region or account drifted")]
    RegionOrAccountDrift,
    #[error("AWS Control Tower operation retention expired")]
    RetentionExpired,
    #[error(transparent)]
    Provider(ProviderError),
    #[error(transparent)]
    Model(ModelError),
}

impl From<ModelError> for AwsControlTowerServiceError {
    fn from(value: ModelError) -> Self {
        match value {
            ModelError::OutOfScope { .. } => Self::OutOfScope,
            ModelError::RegionMismatch { .. } | ModelError::AccountMismatch { .. } => {
                Self::RegionOrAccountDrift
            }
            ModelError::OperationRetentionExpired => Self::RetentionExpired,
            other => Self::Model(other),
        }
    }
}

impl From<ProviderError> for AwsControlTowerServiceError {
    fn from(value: ProviderError) -> Self {
        match value {
            ProviderError::ScopeMismatch
            | ProviderError::LandingZoneDrift
            | ProviderError::BaselineDrift
            | ProviderError::ChildBaselineUnexpected => Self::OutOfScope,
            ProviderError::PermissionLoss => Self::PermissionLoss,
            ProviderError::RegionMismatch | ProviderError::AccountMismatch => {
                Self::RegionOrAccountDrift
            }
            ProviderError::RetentionExpired => Self::RetentionExpired,
            other => Self::Provider(other),
        }
    }
}

pub struct AwsControlTowerGovernanceService<T = crate::provider::BlockedEnvTransport> {
    scope: AwsControlTowerScope,
    secret_reference: SigV4SecretReference,
    provider: AwsControlTowerProvider<T>,
    registration: AwsControlTowerRegistration,
    recordings: BTreeMap<String, Digest>,
}

impl<T: AwsControlTowerTransport> fmt::Debug for AwsControlTowerGovernanceService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsControlTowerGovernanceService")
            .field("scope_digest", &self.scope.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

impl<T: AwsControlTowerTransport> AwsControlTowerGovernanceService<T> {
    pub fn new(
        scope: AwsControlTowerScope,
        secret_reference: SigV4SecretReference,
        provider: AwsControlTowerProvider<T>,
    ) -> ServiceResult<Self> {
        scope.verify()?;
        secret_reference
            .ensure_active()
            .map_err(|_| AwsControlTowerServiceError::SecretRevoked)?;
        if secret_reference.scope_digest() != &scope.scope_digest
            || secret_reference.account_id() != &scope.account_id
            || secret_reference.home_region() != &scope.home_region
        {
            return Err(AwsControlTowerServiceError::ScopeMismatch);
        }
        provider.validate()?;
        let registration =
            AwsControlTowerRegistration::new(&scope, &secret_reference, provider.definition());
        registration.validate()?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
            recordings: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsControlTowerScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SigV4SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsControlTowerProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsControlTowerProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsControlTowerRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret_reference.is_revoked()
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: self.provider.definition().provider_id.clone(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: ReadOperation::ALL
                .iter()
                .map(|operation| operation.api_name().to_owned())
                .collect(),
            permissions: LAYER1_PERMISSIONS.iter().map(ToString::to_string).collect(),
            read_only: true,
            proposal_only: true,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }

    pub fn consumer(&self) -> ServiceResult<MissionAwsControlTowerConsumer> {
        MissionAwsControlTowerConsumer::new(self.scope.clone(), self.registration.clone())
            .map_err(crate::consumer::ConsumerError::into_service_error)
    }

    pub fn revoke_registration(&mut self) -> ServiceResult<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse_registration(&mut self) -> ServiceResult<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> ServiceResult<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn revoke_secret_reference(&mut self) -> ServiceResult<()> {
        self.secret_reference
            .revoke()
            .map_err(AwsControlTowerServiceError::from)
    }

    pub fn request(
        &self,
        operation: ReadOperation,
        observed_at: DateTime<Utc>,
    ) -> ServiceResult<AwsControlTowerReadRequest> {
        match operation {
            ReadOperation::ListLandingZones => Ok(AwsControlTowerReadRequest::ListLandingZones(
                ListLandingZonesRequest::for_scope(&self.scope, self.provider.bounds(), None)?,
            )),
            ReadOperation::GetLandingZone => Ok(AwsControlTowerReadRequest::GetLandingZone(
                GetLandingZoneRequest::for_scope(&self.scope)?,
            )),
            ReadOperation::GetLandingZoneOperation => {
                let operation_id = self
                    .scope
                    .operation_ids
                    .iter()
                    .next()
                    .cloned()
                    .ok_or(AwsControlTowerServiceError::OutOfScope)?;
                Ok(AwsControlTowerReadRequest::GetLandingZoneOperation(
                    GetLandingZoneOperationRequest::for_scope(
                        &self.scope,
                        operation_id,
                        observed_at,
                    )?,
                ))
            }
            ReadOperation::ListEnabledBaselines => {
                Ok(AwsControlTowerReadRequest::ListEnabledBaselines(
                    ListEnabledBaselinesRequest::for_scope(
                        &self.scope,
                        true,
                        self.provider.bounds(),
                        None,
                    )?,
                ))
            }
        }
    }

    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> ServiceResult<AwsControlTowerReadRequest> {
        self.request(ReadOperation::ListLandingZones, observed_at)
    }

    pub fn list_landing_zones_request(&self) -> ServiceResult<ListLandingZonesRequest> {
        Ok(ListLandingZonesRequest::for_scope(
            &self.scope,
            self.provider.bounds(),
            None,
        )?)
    }

    pub fn get_landing_zone_request(&self) -> ServiceResult<GetLandingZoneRequest> {
        Ok(GetLandingZoneRequest::for_scope(&self.scope)?)
    }

    pub fn get_landing_zone_operation_request(
        &self,
        operation_id: OperationId,
        observed_at: DateTime<Utc>,
    ) -> ServiceResult<GetLandingZoneOperationRequest> {
        Ok(GetLandingZoneOperationRequest::for_scope(
            &self.scope,
            operation_id,
            observed_at,
        )?)
    }

    pub fn list_enabled_baselines_request(
        &self,
        include_children: bool,
    ) -> ServiceResult<ListEnabledBaselinesRequest> {
        Ok(ListEnabledBaselinesRequest::for_scope(
            &self.scope,
            include_children,
            self.provider.bounds(),
            None,
        )?)
    }

    pub fn propose(
        &mut self,
        request: &AwsControlTowerReadRequest,
    ) -> ServiceResult<AwsControlTowerGovernanceProposal> {
        self.ensure_fences(request)?;
        let response = match self.provider.read(request) {
            Ok(response) => response,
            Err(error) => {
                if let Some(evidence) = self.failure_evidence(request, &error) {
                    let proposal = self.make_proposal(request.clone(), evidence)?;
                    return Ok(proposal);
                }
                return Err(error.into());
            }
        };
        let evidence = self.evidence_from_response(request, response)?;
        self.make_proposal(request.clone(), evidence)
    }

    pub fn read(
        &mut self,
        request: &AwsControlTowerReadRequest,
    ) -> ServiceResult<AwsControlTowerGovernanceProposal> {
        self.propose(request)
    }

    pub fn propose_list_landing_zones(
        &mut self,
    ) -> ServiceResult<AwsControlTowerGovernanceProposal> {
        let request =
            AwsControlTowerReadRequest::ListLandingZones(self.list_landing_zones_request()?);
        self.propose(&request)
    }

    pub fn propose_get_landing_zone(&mut self) -> ServiceResult<AwsControlTowerGovernanceProposal> {
        let request = AwsControlTowerReadRequest::GetLandingZone(self.get_landing_zone_request()?);
        self.propose(&request)
    }

    pub fn propose_get_landing_zone_operation(
        &mut self,
        operation_id: OperationId,
        observed_at: DateTime<Utc>,
    ) -> ServiceResult<AwsControlTowerGovernanceProposal> {
        let request = AwsControlTowerReadRequest::GetLandingZoneOperation(
            self.get_landing_zone_operation_request(operation_id, observed_at)?,
        );
        self.propose(&request)
    }

    pub fn propose_list_enabled_baselines(
        &mut self,
        include_children: bool,
    ) -> ServiceResult<AwsControlTowerGovernanceProposal> {
        let request = AwsControlTowerReadRequest::ListEnabledBaselines(
            self.list_enabled_baselines_request(include_children)?,
        );
        self.propose(&request)
    }

    pub fn record(
        &mut self,
        proposal: &AwsControlTowerGovernanceProposal,
    ) -> ServiceResult<AwsControlTowerRecordReceipt> {
        self.record_at(proposal, "aws-control-tower-default-recording", Utc::now())
    }

    pub fn record_at(
        &mut self,
        proposal: &AwsControlTowerGovernanceProposal,
        recording_key: &str,
        recorded_at: DateTime<Utc>,
    ) -> ServiceResult<AwsControlTowerRecordReceipt> {
        self.ensure_proposal_fences(proposal)?;
        if recording_key.trim().is_empty() || recording_key.chars().any(char::is_control) {
            return Err(AwsControlTowerServiceError::Model(ModelError::Invalid {
                field: "recording key",
            }));
        }
        let key_digest = Digest::from_text(recording_key);
        let key = key_digest.to_string();
        let replayed = self.recordings.contains_key(&key);
        if self
            .recordings
            .get(&key)
            .is_some_and(|digest| digest != &proposal.proposal_digest)
        {
            return Err(AwsControlTowerServiceError::TamperedProposal);
        }
        self.recordings
            .insert(key, proposal.proposal_digest.clone());
        let receipt_digest = Digest::from_parts(
            "aws-control-tower-record-receipt/v1",
            &[
                replayed.to_string(),
                recorded_at.to_rfc3339(),
                key_digest.to_string(),
                proposal.proposal_digest.to_string(),
                proposal.evidence.evidence_digest().to_string(),
                self.registration.digest().to_string(),
            ],
        );
        Ok(AwsControlTowerRecordReceipt {
            recorded: true,
            replayed,
            recorded_at,
            recording_key_digest: key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest().clone(),
            registration_digest: self.registration.digest(),
            durable_receipt: false,
            connected: false,
            native: false,
            receipt_digest,
        })
    }

    pub fn verify(&self, proposal: &AwsControlTowerGovernanceProposal) -> VerificationReport {
        self.verify_at(proposal, Utc::now())
    }

    pub fn verify_at(
        &self,
        proposal: &AwsControlTowerGovernanceProposal,
        observed_at: DateTime<Utc>,
    ) -> VerificationReport {
        let mut report = VerificationReport {
            valid: false,
            review_eligible: false,
            state: proposal.state,
            failure: None,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest().clone(),
        };
        if !self.registration.is_active() {
            report.failure = Some(
                if matches!(self.registration.status, RegistrationStatus::Revoked) {
                    VerificationFailure::RegistrationRevoked
                } else {
                    VerificationFailure::ProposalTampered
                },
            );
            return report;
        }
        if self.secret_reference.is_revoked() {
            report.failure = Some(VerificationFailure::SecretRevoked);
            return report;
        }
        if matches!(proposal.operation, ReadOperation::GetLandingZoneOperation)
            && proposal.evidence.state == EvidenceStatus::RetentionExpired
        {
            report.failure = Some(VerificationFailure::RetentionExpired);
            return report;
        }
        if proposal.verify_integrity().is_err() {
            report.failure = Some(VerificationFailure::ProposalTampered);
            return report;
        }
        if !proposal.evidence.state.review_eligible() {
            report.failure = Some(VerificationFailure::StateNotReviewEligible);
            return report;
        }
        let _ = observed_at;
        report.valid = true;
        report.review_eligible = true;
        report
    }

    fn ensure_fences(&self, request: &AwsControlTowerReadRequest) -> ServiceResult<()> {
        if !self.is_active() {
            return if matches!(self.registration.status, RegistrationStatus::Reversed) {
                Err(AwsControlTowerServiceError::RegistrationReversed)
            } else if !self.registration.is_active() {
                Err(AwsControlTowerServiceError::RegistrationRevoked)
            } else {
                Err(AwsControlTowerServiceError::SecretRevoked)
            };
        }
        self.scope.verify()?;
        if !self.scope.permission.allows(&request.operation())
            || request.scope_digest() != &self.scope.scope_digest
            || request.permission_digest() != &self.scope.permission.permission_digest
        {
            return Err(AwsControlTowerServiceError::PermissionLoss);
        }
        if request.request_digest() == Digest::zero() {
            return Err(AwsControlTowerServiceError::TamperedProposal);
        }
        match request {
            AwsControlTowerReadRequest::ListLandingZones(request) => {
                if request.account_id != self.scope.account_id
                    || request.home_region != self.scope.home_region
                    || request.compute_digest() != request.request_digest
                {
                    return Err(AwsControlTowerServiceError::RegionOrAccountDrift);
                }
            }
            AwsControlTowerReadRequest::GetLandingZone(request) => {
                if request.account_id != self.scope.account_id
                    || request.home_region != self.scope.home_region
                    || request.landing_zone != self.scope.landing_zone
                    || request.compute_digest() != request.request_digest
                {
                    return Err(AwsControlTowerServiceError::OutOfScope);
                }
            }
            AwsControlTowerReadRequest::GetLandingZoneOperation(request) => {
                if request.account_id != self.scope.account_id
                    || request.home_region != self.scope.home_region
                    || request.landing_zone != self.scope.landing_zone
                    || !self.scope.allows_operation(&request.operation_id)
                    || request.compute_digest() != request.request_digest
                {
                    return Err(AwsControlTowerServiceError::OutOfScope);
                }
            }
            AwsControlTowerReadRequest::ListEnabledBaselines(request) => {
                if request.account_id != self.scope.account_id
                    || request.home_region != self.scope.home_region
                    || request.filter.baseline_ids != self.scope.baseline_ids
                    || request.filter.target_ids != self.scope.target_ids
                    || request.compute_digest() != request.request_digest
                {
                    return Err(AwsControlTowerServiceError::OutOfScope);
                }
            }
        }
        Ok(())
    }

    fn ensure_proposal_fences(
        &self,
        proposal: &AwsControlTowerGovernanceProposal,
    ) -> ServiceResult<()> {
        self.ensure_fences(&proposal.request)?;
        proposal.verify_integrity()?;
        if proposal.registration_digest != self.registration.digest()
            || proposal.scope_digest != self.scope.scope_digest
            || proposal.permission_digest != self.scope.permission.permission_digest
        {
            return Err(AwsControlTowerServiceError::TamperedProposal);
        }
        Ok(())
    }

    fn make_proposal(
        &self,
        request: AwsControlTowerReadRequest,
        evidence: AwsControlTowerGovernanceEvidence,
    ) -> ServiceResult<AwsControlTowerGovernanceProposal> {
        let mut proposal = AwsControlTowerGovernanceProposal {
            operation: request.operation(),
            request,
            mission: self.scope.mission.clone(),
            registration_digest: self.registration.digest(),
            registration_revision: self.registration.registration_revision,
            version_digest: Digest::from_text(PLUGIN_VERSION),
            provider_digest: self.provider.definition().provider_digest.clone(),
            api_digest: self.provider.definition().api_digest.clone(),
            contract_digest: contract_digest_value(),
            permission_digest: self.scope.permission.permission_digest.clone(),
            scope_digest: self.scope.scope_digest.clone(),
            state: evidence.state,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            evidence,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        Ok(proposal)
    }

    fn evidence_from_response(
        &self,
        request: &AwsControlTowerReadRequest,
        response: AwsControlTowerProviderResponse,
    ) -> ServiceResult<AwsControlTowerGovernanceEvidence> {
        let (
            state,
            response_digest,
            pages,
            items,
            cursor_digests,
            landing_zones,
            landing_zone,
            operation_detail,
            enabled_baselines,
            provenance,
        ) = match response {
            AwsControlTowerProviderResponse::ListLandingZones(response) => (
                if response.complete {
                    EvidenceStatus::Complete
                } else {
                    EvidenceStatus::PaginationIncomplete
                },
                response.response_digest,
                response.pages_observed,
                response.landing_zones.len(),
                response.cursor_digests,
                response.landing_zones,
                None,
                None,
                Vec::new(),
                response.provenance,
            ),
            AwsControlTowerProviderResponse::GetLandingZone(response) => (
                EvidenceStatus::Complete,
                response.response_digest,
                1,
                1,
                Vec::new(),
                Vec::new(),
                Some(response.landing_zone),
                None,
                Vec::new(),
                response.provenance,
            ),
            AwsControlTowerProviderResponse::GetLandingZoneOperation(response) => (
                EvidenceStatus::Complete,
                response.response_digest,
                1,
                1,
                Vec::new(),
                Vec::new(),
                None,
                Some(response.operation),
                Vec::new(),
                response.provenance,
            ),
            AwsControlTowerProviderResponse::ListEnabledBaselines(response) => (
                if response.complete {
                    EvidenceStatus::Complete
                } else {
                    EvidenceStatus::PaginationIncomplete
                },
                response.response_digest,
                response.pages_observed,
                response.enabled_baselines.len(),
                response.cursor_digests,
                Vec::new(),
                None,
                None,
                response.enabled_baselines,
                response.provenance,
            ),
        };
        let observed_at_digest = Digest::from_parts(
            "aws-control-tower-observation/v1",
            &[request.request_digest().to_string()],
        );
        self.build_evidence(
            request.operation(),
            state,
            response_digest,
            PaginationEvidence {
                pages_observed: pages,
                items_observed: items,
                complete: state == EvidenceStatus::Complete,
                cursor_digests,
            },
            landing_zones,
            landing_zone,
            operation_detail,
            enabled_baselines,
            provenance,
            None,
            observed_at_digest,
        )
    }

    fn failure_evidence(
        &self,
        request: &AwsControlTowerReadRequest,
        error: &ProviderError,
    ) -> Option<AwsControlTowerGovernanceEvidence> {
        let (state, transport) = match error {
            ProviderError::Transport(error) => {
                let state = match error {
                    TransportError::BadRequest => EvidenceStatus::ProviderUnknown,
                    TransportError::Unauthorized | TransportError::Forbidden => {
                        EvidenceStatus::AccessLoss
                    }
                    TransportError::NotFound => EvidenceStatus::NotFound,
                    TransportError::Conflict => EvidenceStatus::Conflict,
                    TransportError::RateLimited { .. } => EvidenceStatus::Throttled,
                    TransportError::ServerFailure { .. }
                    | TransportError::Timeout
                    | TransportError::InvalidResponse => EvidenceStatus::ProviderUnknown,
                    TransportError::BlockedEnv => EvidenceStatus::BlockedEnv,
                };
                (state, Some(error))
            }
            ProviderError::PaginationIncomplete => (EvidenceStatus::PaginationIncomplete, None),
            ProviderError::RetentionExpired => (EvidenceStatus::RetentionExpired, None),
            ProviderError::ScopeMismatch
            | ProviderError::LandingZoneDrift
            | ProviderError::BaselineDrift
            | ProviderError::ChildBaselineUnexpected => (EvidenceStatus::ScopeDrift, None),
            ProviderError::RegionMismatch | ProviderError::AccountMismatch => {
                (EvidenceStatus::RegionMismatch, None)
            }
            _ => return None,
        };
        let failure = transport.map(|transport| {
            FailureEvidence::new(
                request.operation().api_name(),
                transport.category(),
                transport.status_code(),
            )
        });
        self.build_evidence(
            request.operation(),
            state,
            Digest::from_parts("aws-control-tower-failed-response/v1", &[error.to_string()]),
            PaginationEvidence {
                pages_observed: 0,
                items_observed: 0,
                complete: false,
                cursor_digests: Vec::new(),
            },
            Vec::new(),
            None,
            None,
            Vec::new(),
            self.provider.definition().provenance,
            failure,
            Digest::from_parts(
                "aws-control-tower-failed-observation/v1",
                &[request.request_digest().to_string(), error.to_string()],
            ),
        )
        .ok()
    }

    #[allow(clippy::too_many_arguments)]
    fn build_evidence(
        &self,
        operation: ReadOperation,
        state: EvidenceStatus,
        response_digest: Digest,
        pagination: PaginationEvidence,
        landing_zones: Vec<crate::model::LandingZoneSummary>,
        landing_zone: Option<LandingZoneDetail>,
        operation_detail: Option<LandingZoneOperation>,
        enabled_baselines: Vec<EnabledBaselineSummary>,
        provenance: ProviderProvenance,
        failure: Option<FailureEvidence>,
        observed_at_digest: Digest,
    ) -> ServiceResult<AwsControlTowerGovernanceEvidence> {
        let authority = AuthorityBoundary::default();
        let mut evidence = AwsControlTowerGovernanceEvidence {
            operation,
            state,
            account_digest: self.scope.account_id.digest(),
            home_region_digest: self.scope.home_region.digest(),
            landing_zone_digest: self.scope.landing_zone.digest(),
            project_digest: self.scope.project_id.digest(),
            mission_digest: self.scope.mission_id.digest(),
            work_product_digest: self.scope.work_product_id.digest(),
            landing_zones,
            landing_zone,
            operation_detail,
            enabled_baselines,
            pagination,
            redaction: RedactionSummary::default(),
            authority,
            provenance,
            failure,
            observed_at_digest,
            digests: EvidenceDigests {
                version_digest: Digest::from_text(PLUGIN_VERSION),
                provider_digest: self.provider.definition().provider_digest.clone(),
                api_digest: self.provider.definition().api_digest.clone(),
                contract_digest: contract_digest_value(),
                permission_digest: self.scope.permission.permission_digest.clone(),
                scope_digest: self.scope.scope_digest.clone(),
                response_digest,
                evidence_digest: Digest::zero(),
            },
        };
        evidence.digests.evidence_digest = evidence.recomputed_digest();
        Ok(evidence)
    }
}

fn contract_digest_value() -> Digest {
    Digest::parse(CONTRACT_DIGEST).expect("contract digest constant is valid")
}

pub fn contract_digest() -> Digest {
    contract_digest_value()
}

pub fn permission_digest(scope: &AwsControlTowerScope) -> &Digest {
    &scope.permission.permission_digest
}

pub fn operation_status_digest(status: OperationStatus) -> Digest {
    Digest::from_text(format!("{status:?}"))
}

pub fn status_digest(status: LandingZoneStatus) -> Digest {
    Digest::from_text(format!("{status:?}"))
}

pub fn drift_status_digest(status: DriftStatus) -> Digest {
    Digest::from_text(format!("{status:?}"))
}

pub fn baseline_status_digest(status: BaselineStatus) -> Digest {
    Digest::from_text(format!("{status:?}"))
}

pub fn operation_type_digest(operation_type: OperationType) -> Digest {
    Digest::from_text(format!("{operation_type:?}"))
}
