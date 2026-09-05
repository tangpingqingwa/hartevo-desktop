//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsDataZoneSubscriptionResultError, Result};
use crate::model::{
    AssetMetadata, AwsDataZoneSubscriptionScope, DataZoneEvidenceState, Digest, EvidenceDigests,
    SubscriptionMetadata, SubscriptionRequestMetadata, TransportProvenance,
};
use crate::service::{
    AwsDataZoneSubscriptionResultProposal, AwsDataZoneSubscriptionResultRegistration,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Pending,
    Accepted,
    Rejected,
    Expired,
    Ready,
    Partial,
    NotFound,
    AccessLost,
    Throttled,
    Tampered,
    Drift,
    ProviderUnknown,
    Revoked,
}

impl From<DataZoneEvidenceState> for ProposalDisposition {
    fn from(state: DataZoneEvidenceState) -> Self {
        match state {
            DataZoneEvidenceState::Pending => Self::Pending,
            DataZoneEvidenceState::Accepted => Self::Accepted,
            DataZoneEvidenceState::Rejected => Self::Rejected,
            DataZoneEvidenceState::Expired => Self::Expired,
            DataZoneEvidenceState::Ready => Self::Ready,
            DataZoneEvidenceState::Partial => Self::Partial,
            DataZoneEvidenceState::NotFound => Self::NotFound,
            DataZoneEvidenceState::AccessLost => Self::AccessLost,
            DataZoneEvidenceState::Throttled => Self::Throttled,
            DataZoneEvidenceState::Tampered => Self::Tampered,
            DataZoneEvidenceState::Drift => Self::Drift,
            DataZoneEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            DataZoneEvidenceState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsDataZoneSubscriptionResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: crate::model::MissionProjection,
    pub project: crate::model::ProjectProjection,
    pub work_product: crate::model::WorkProductProjection,
    pub asset: Option<AssetMetadata>,
    pub subscription_request: Option<SubscriptionRequestMetadata>,
    pub subscription: Option<SubscriptionMetadata>,
    pub state: DataZoneEvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub subscription_effect_claim: bool,
    pub data_access_claim: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsDataZoneSubscriptionResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsDataZoneSubscriptionResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: DataZoneEvidenceState,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub subscription_effect_claim: bool,
    pub data_access_claim: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedAwsDataZoneSubscriptionResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsDataZoneSubscriptionResultProposal,
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
            subscription_effect_claim: false,
            data_access_claim: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-aws-datazone-recording"),
        };
        result.recording_digest = recording_digest(&result);
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.subscription_effect_claim
            || self.data_access_claim
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != recording_digest(self)
        {
            return Err(AwsDataZoneSubscriptionResultError::TamperedEvidence);
        }
        self.idempotency_key_digest.validate()?;
        self.proposal_digest.validate()
    }
}

fn recording_digest(result: &RecordedAwsDataZoneSubscriptionResult) -> Digest {
    Digest::from_parts(
        "aws-datazone-subscription-recording/v1",
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

/// Consumer scoped to one exact DataZone registration and Mission fence.
pub struct MissionAwsDataZoneSubscriptionResultConsumer {
    scope: AwsDataZoneSubscriptionScope,
    registration: AwsDataZoneSubscriptionResultRegistration,
    records: BTreeMap<Digest, RecordedAwsDataZoneSubscriptionResult>,
}

impl fmt::Debug for MissionAwsDataZoneSubscriptionResultConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsDataZoneSubscriptionResultConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsDataZoneSubscriptionResultConsumer {
    pub fn new(
        scope: AwsDataZoneSubscriptionScope,
        registration: AwsDataZoneSubscriptionResultRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsDataZoneSubscriptionResultError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsDataZoneSubscriptionResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &AwsDataZoneSubscriptionResultRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsDataZoneSubscriptionResultProposal,
    ) -> Result<MissionAwsDataZoneSubscriptionResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AwsDataZoneSubscriptionResultError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.account_digest != self.scope.account().digest()
            || proposal.region_digest != self.scope.region().digest()
            || proposal.domain_digest != self.scope.domain().digest()
            || proposal.datazone_project_digest != self.scope.datazone_project().digest()
            || proposal.asset_digest != self.scope.asset().digest()
            || proposal.listing_digest != self.scope.listing().digest()
            || proposal.subscription_request_digest != self.scope.subscription_request().digest()
            || proposal.subscription_digest != self.scope.subscription().digest()
            || proposal.subscription_grant_digest != self.scope.subscription_grant().digest()
            || proposal.revision_digest != self.scope.revision().digest()
            || proposal.mission.id_digest != self.scope.mission().digest()
            || proposal.project.id_digest != self.scope.project().digest()
            || proposal.work_product.id_digest != self.scope.work_product().digest()
        {
            return Err(AwsDataZoneSubscriptionResultError::ScopeMismatch);
        }
        Ok(MissionAwsDataZoneSubscriptionResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            asset: proposal.asset.clone(),
            subscription_request: proposal.subscription_request.clone(),
            subscription: proposal.subscription.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            subscription_effect_claim: false,
            data_access_claim: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsDataZoneSubscriptionResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsDataZoneSubscriptionResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsDataZoneSubscriptionResultError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsDataZoneSubscriptionResultError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = recording_digest(&replay);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result =
            RecordedAwsDataZoneSubscriptionResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}

pub type MissionAwsDataZoneConsumer = MissionAwsDataZoneSubscriptionResultConsumer;
pub type MissionAwsDataZoneResult = MissionAwsDataZoneSubscriptionResult;
