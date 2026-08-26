//! Mission-scoped review-only consumer for Azure Container Apps evidence.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use zeroize::Zeroize;

use crate::error::{AzureContainerAppsRevisionResultError, Result};
use crate::model::{
    AzureContainerAppsEvidenceState, AzureContainerAppsRevisionProjection,
    AzureContainerAppsRevisionScope, Digest, EvidenceDigests, RequestReceipt, TransportProvenance,
};
use crate::service::{AzureContainerAppsRevisionProposal, AzureContainerAppsRevisionRegistration};
use crate::{CONSUMER_ID, EVIDENCE_SCHEMA, MAX_IDENTIFIER_BYTES, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Provisioning,
    Running,
    Healthy,
    Unhealthy,
    Inactive,
    Failed,
    Deprovisioned,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
    NotFound,
    TimedOut,
    Throttled,
    PaginationLoop,
    Truncated,
    Conflict,
}

impl From<AzureContainerAppsEvidenceState> for ProposalDisposition {
    fn from(state: AzureContainerAppsEvidenceState) -> Self {
        match state {
            AzureContainerAppsEvidenceState::Provisioning => Self::Provisioning,
            AzureContainerAppsEvidenceState::Running => Self::Running,
            AzureContainerAppsEvidenceState::Healthy => Self::Healthy,
            AzureContainerAppsEvidenceState::Unhealthy => Self::Unhealthy,
            AzureContainerAppsEvidenceState::Inactive => Self::Inactive,
            AzureContainerAppsEvidenceState::Failed => Self::Failed,
            AzureContainerAppsEvidenceState::Deprovisioned => Self::Deprovisioned,
            AzureContainerAppsEvidenceState::Partial => Self::Partial,
            AzureContainerAppsEvidenceState::AccessLost => Self::AccessLost,
            AzureContainerAppsEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            AzureContainerAppsEvidenceState::Tampered => Self::Tampered,
            AzureContainerAppsEvidenceState::Revoked => Self::Revoked,
            AzureContainerAppsEvidenceState::NotFound => Self::NotFound,
            AzureContainerAppsEvidenceState::TimedOut => Self::TimedOut,
            AzureContainerAppsEvidenceState::Throttled => Self::Throttled,
            AzureContainerAppsEvidenceState::PaginationLoop => Self::PaginationLoop,
            AzureContainerAppsEvidenceState::Truncated => Self::Truncated,
            AzureContainerAppsEvidenceState::Conflict => Self::Conflict,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAzureContainerAppsRevisionResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub projection: Option<AzureContainerAppsRevisionProjection>,
    pub state: AzureContainerAppsEvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: EvidenceDigests,
    pub request_receipts: Vec<RequestReceipt>,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAzureContainerAppsRevisionResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
    pub fn validate(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.evidence.evidence_schema_digest != Digest::from_text(EVIDENCE_SCHEMA)
        {
            return Err(AzureContainerAppsRevisionResultError::TamperedEvidence);
        }
        self.scope_digest.validate()?;
        self.evidence.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAzureContainerAppsRevisionResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: AzureContainerAppsEvidenceState,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedAzureContainerAppsRevisionResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AzureContainerAppsRevisionProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-azure-container-apps-recording"),
        };
        result.recording_digest = recording_digest(&result);
        result
    }
    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || self.provenance.is_first_party()
            || self.recording_digest != recording_digest(self)
        {
            return Err(AzureContainerAppsRevisionResultError::TamperedEvidence);
        }
        self.idempotency_key_digest.validate()?;
        self.proposal_digest.validate()
    }
}

fn recording_digest(result: &RecordedAzureContainerAppsRevisionResult) -> Digest {
    Digest::from_parts(
        "azure-container-apps-local-recording/v1",
        &[
            (
                "idempotency",
                result.idempotency_key_digest.as_str().to_owned(),
            ),
            ("proposal", result.proposal_digest.as_str().to_owned()),
            ("state", format!("{:?}", result.state)),
            ("provenance", result.provenance.as_str().to_owned()),
        ],
    )
}

/// A Mission consumer bound to one exact registration and scope. It records
/// only local, idempotent review artifacts and has no kernel authority.
pub struct MissionAzureContainerAppsRevisionConsumer {
    scope: AzureContainerAppsRevisionScope,
    registration: AzureContainerAppsRevisionRegistration,
    records: BTreeMap<Digest, RecordedAzureContainerAppsRevisionResult>,
}

impl fmt::Debug for MissionAzureContainerAppsRevisionConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAzureContainerAppsRevisionConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAzureContainerAppsRevisionConsumer {
    pub fn new(
        scope: AzureContainerAppsRevisionScope,
        registration: AzureContainerAppsRevisionRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AzureContainerAppsRevisionResultError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AzureContainerAppsRevisionResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }
    pub fn scope(&self) -> &AzureContainerAppsRevisionScope {
        &self.scope
    }
    pub fn registration(&self) -> &AzureContainerAppsRevisionRegistration {
        &self.registration
    }
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AzureContainerAppsRevisionProposal,
    ) -> Result<MissionAzureContainerAppsRevisionResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AzureContainerAppsRevisionResultError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.provider_digest != *self.registration.provider_digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest()
            || proposal.evidence.evidence_schema_digest
                != *self.registration.evidence_schema_digest()
        {
            return Err(AzureContainerAppsRevisionResultError::ScopeMismatch);
        }
        proposal.validate_against_scope(&self.scope)?;
        if let Some(projection) = &proposal.projection
            && (projection.app.app_digest != self.scope.container_app().digest()
                || projection.revision.revision_digest != self.scope.revision().digest()
                || projection.revision.redacted_image_digest.as_ref()
                    != Some(self.scope.image_digest()))
        {
            return Err(AzureContainerAppsRevisionResultError::ScopeMismatch);
        }
        let result = MissionAzureContainerAppsRevisionResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            projection: proposal.projection.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            request_receipts: proposal.request_receipts.clone(),
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn consume_evidence(
        &self,
        proposal: &AzureContainerAppsRevisionProposal,
    ) -> Result<MissionAzureContainerAppsRevisionResult> {
        self.consume(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &AzureContainerAppsRevisionProposal,
        opaque_idempotency_key: impl Into<String>,
    ) -> Result<RecordedAzureContainerAppsRevisionResult> {
        self.consume(proposal)?;
        let mut key = opaque_idempotency_key.into();
        if key.trim().is_empty()
            || key.len() > MAX_IDENTIFIER_BYTES
            || key.chars().any(char::is_control)
        {
            key.zeroize();
            return Err(AzureContainerAppsRevisionResultError::InvalidText {
                field: "idempotency-key",
            });
        }
        let key_digest = Digest::from_parts(
            "azure-container-apps-idempotency-key/v1",
            &[
                ("value", key.clone()),
                ("scope", self.scope.digest().as_str().to_owned()),
            ],
        );
        key.zeroize();
        if let Some(previous) = self.records.get(&key_digest) {
            if previous.proposal_digest != proposal.proposal_digest {
                return Err(AzureContainerAppsRevisionResultError::ReplayConflict);
            }
            let mut replay = previous.clone();
            replay.replayed = true;
            replay.recording_digest = recording_digest(&replay);
            return Ok(replay);
        }
        let recorded =
            RecordedAzureContainerAppsRevisionResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, recorded.clone());
        Ok(recorded)
    }
}

pub type MissionAzureContainerAppsRevisionReadResult = MissionAzureContainerAppsRevisionResult;
