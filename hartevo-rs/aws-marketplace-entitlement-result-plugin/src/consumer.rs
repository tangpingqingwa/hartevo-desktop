//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsMarketplaceEntitlementError, Result};
use crate::model::{
    AwsMarketplaceEntitlementScope, Digest, EntitlementEvidenceState, EntitlementProjection,
    EvidenceDigests, ExpiryProjection, TransportProvenance,
};
use crate::service::{AwsMarketplaceEntitlementProposal, AwsMarketplaceEntitlementRegistration};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Complete,
    Empty,
    EmptyPage,
    Expired,
    FilterMismatch,
    PaginationLoop,
    PageLimitExceeded,
    Partial,
    AccessLoss,
    Throttled,
    NotFound,
    Tampered,
    ProviderUnknown,
    RegistrationRevoked,
    RegistrationReversed,
    ConsentExpired,
    ConsentRevoked,
}

impl From<EntitlementEvidenceState> for ProposalDisposition {
    fn from(state: EntitlementEvidenceState) -> Self {
        match state {
            EntitlementEvidenceState::Complete => Self::Complete,
            EntitlementEvidenceState::Empty => Self::Empty,
            EntitlementEvidenceState::EmptyPage => Self::EmptyPage,
            EntitlementEvidenceState::Expired => Self::Expired,
            EntitlementEvidenceState::FilterMismatch => Self::FilterMismatch,
            EntitlementEvidenceState::PaginationLoop => Self::PaginationLoop,
            EntitlementEvidenceState::PageLimitExceeded => Self::PageLimitExceeded,
            EntitlementEvidenceState::AccessLoss => Self::AccessLoss,
            EntitlementEvidenceState::Throttled => Self::Throttled,
            EntitlementEvidenceState::NotFound => Self::NotFound,
            EntitlementEvidenceState::Partial => Self::Partial,
            EntitlementEvidenceState::Tampered => Self::Tampered,
            EntitlementEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            EntitlementEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
            EntitlementEvidenceState::RegistrationReversed => Self::RegistrationReversed,
            EntitlementEvidenceState::ConsentExpired => Self::ConsentExpired,
            EntitlementEvidenceState::ConsentRevoked => Self::ConsentRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsMarketplaceEntitlementResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub entitlements: Vec<EntitlementProjection>,
    pub expiry_projection: ExpiryProjection,
    pub mission: crate::model::MissionProjection,
    pub project: crate::model::ProjectProjection,
    pub work_product: crate::model::WorkProductProjection,
    pub state: EntitlementEvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsMarketplaceEntitlementResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsMarketplaceEntitlementResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: EntitlementEvidenceState,
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

impl RecordedAwsMarketplaceEntitlementResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsMarketplaceEntitlementProposal,
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
            recording_digest: Digest::from_text("unsealed-aws-marketplace-entitlement-recording"),
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
            || self.recording_digest != recording_digest(self)
        {
            return Err(AwsMarketplaceEntitlementError::TamperedEvidence);
        }
        self.idempotency_key_digest.validate()?;
        self.proposal_digest.validate()
    }
}

fn recording_digest(result: &RecordedAwsMarketplaceEntitlementResult) -> Digest {
    Digest::from_parts(
        "aws-marketplace-entitlement-recording/v1",
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

/// Mission consumer bound to one exact Marketplace entitlement registration and
/// scope. It can review and record proposals but cannot adopt truth, outcomes,
/// or Work Products.
pub struct MissionAwsMarketplaceEntitlementConsumer {
    scope: AwsMarketplaceEntitlementScope,
    registration: AwsMarketplaceEntitlementRegistration,
    records: BTreeMap<Digest, RecordedAwsMarketplaceEntitlementResult>,
}

impl fmt::Debug for MissionAwsMarketplaceEntitlementConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsMarketplaceEntitlementConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsMarketplaceEntitlementConsumer {
    pub fn new(
        scope: AwsMarketplaceEntitlementScope,
        registration: AwsMarketplaceEntitlementRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsMarketplaceEntitlementError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsMarketplaceEntitlementError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &AwsMarketplaceEntitlementRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsMarketplaceEntitlementProposal,
    ) -> Result<MissionAwsMarketplaceEntitlementResult> {
        proposal.validate_for(&self.scope)?;
        if !self.registration.is_active() {
            return Err(AwsMarketplaceEntitlementError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.mission.id_digest != self.scope.mission().id_digest()
            || proposal.project.id_digest != self.scope.project().id_digest()
            || proposal.work_product.id_digest != self.scope.work_product().id_digest()
        {
            return Err(AwsMarketplaceEntitlementError::ScopeMismatch);
        }
        Ok(MissionAwsMarketplaceEntitlementResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            entitlements: proposal.entitlements.clone(),
            expiry_projection: proposal.expiry_projection.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsMarketplaceEntitlementProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsMarketplaceEntitlementResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsMarketplaceEntitlementError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsMarketplaceEntitlementError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = recording_digest(&replay);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result =
            RecordedAwsMarketplaceEntitlementResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}
