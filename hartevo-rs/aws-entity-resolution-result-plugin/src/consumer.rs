//! Mission-scoped proposal consumption and idempotent redacted recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsEntityResolutionError, Result};
use crate::model::{
    AwsEntityResolutionScope, Digest, EvidenceDigests, MatchStatus, TransportProvenance,
};
use crate::service::{AwsEntityResolutionRegistration, AwsEntityResolutionResultProposal};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Matched,
    Unmatched,
    Ambiguous,
    Invalid,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl From<MatchStatus> for ProposalDisposition {
    fn from(status: MatchStatus) -> Self {
        match status {
            MatchStatus::Matched => Self::Matched,
            MatchStatus::Unmatched => Self::Unmatched,
            MatchStatus::Ambiguous => Self::Ambiguous,
            MatchStatus::Invalid => Self::Invalid,
            MatchStatus::Partial => Self::Partial,
            MatchStatus::AccessLost => Self::AccessLost,
            MatchStatus::ProviderUnknown => Self::ProviderUnknown,
            MatchStatus::Tampered => Self::Tampered,
            MatchStatus::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsEntityResolutionResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub project: crate::model::ProjectScope,
    pub mission: crate::model::MissionScope,
    pub work_product: crate::model::WorkProductScope,
    pub status: MatchStatus,
    pub disposition: ProposalDisposition,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub identity_certainty: bool,
    pub causal_attribution: bool,
    pub identity_map_retained: bool,
    pub s3_output_retained: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsEntityResolutionResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsEntityResolutionResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub status: MatchStatus,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub identity_certainty: bool,
    pub causal_attribution: bool,
    pub identity_map_retained: bool,
    pub s3_output_retained: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedAwsEntityResolutionResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsEntityResolutionResultProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            status: proposal.status,
            disposition: proposal.status.into(),
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            identity_certainty: false,
            causal_attribution: false,
            identity_map_retained: false,
            s3_output_retained: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-aws-entity-resolution-recording"),
        };
        result.recording_digest = result.calculate_digest();
        result
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-entity-resolution-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.identity_certainty
            || self.causal_attribution
            || self.identity_map_retained
            || self.s3_output_retained
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            return Err(AwsEntityResolutionError::TamperedEvidence);
        }
        Ok(())
    }
}

/// Consumer scoped to one exact registration and Project/Mission/Work Product
/// revision fence.
pub struct MissionAwsEntityResolutionConsumer {
    scope: AwsEntityResolutionScope,
    registration: AwsEntityResolutionRegistration,
    records: BTreeMap<Digest, RecordedAwsEntityResolutionResult>,
}

impl fmt::Debug for MissionAwsEntityResolutionConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsEntityResolutionConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsEntityResolutionConsumer {
    pub fn new(
        scope: AwsEntityResolutionScope,
        registration: AwsEntityResolutionRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsEntityResolutionError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsEntityResolutionError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &AwsEntityResolutionRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsEntityResolutionResultProposal,
    ) -> Result<MissionAwsEntityResolutionResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AwsEntityResolutionError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.project != *self.scope.project()
            || proposal.mission != *self.scope.mission()
            || proposal.work_product != *self.scope.work_product()
        {
            return Err(AwsEntityResolutionError::ScopeMismatch);
        }
        if proposal.status == MatchStatus::Tampered {
            return Err(AwsEntityResolutionError::TamperedEvidence);
        }
        if proposal.status == MatchStatus::Revoked {
            return Err(AwsEntityResolutionError::RegistrationRevoked);
        }
        Ok(MissionAwsEntityResolutionResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            project: proposal.project.clone(),
            mission: proposal.mission.clone(),
            work_product: proposal.work_product.clone(),
            status: proposal.status,
            disposition: proposal.status.into(),
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            identity_certainty: false,
            causal_attribution: false,
            identity_map_retained: false,
            s3_output_retained: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsEntityResolutionResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsEntityResolutionResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsEntityResolutionError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsEntityResolutionError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.calculate_digest();
            return Ok(replay);
        }
        let result = RecordedAwsEntityResolutionResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}
