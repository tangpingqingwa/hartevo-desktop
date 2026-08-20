//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsSecurityLakeError, Result};
use crate::model::{
    AwsSecurityLakeOperation, AwsSecurityLakeScope, Digest, EvidenceState, TransportProvenance,
};
use crate::service::{
    AwsSecurityLakeEvidence, AwsSecurityLakeProposal, AwsSecurityLakeRegistration,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Complete,
    Partial,
    PaginationLoop,
    RetentionGap,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    Expired,
    RegistrationRevoked,
    Tampered,
}

impl From<EvidenceState> for ProposalDisposition {
    fn from(state: EvidenceState) -> Self {
        match state {
            EvidenceState::Complete => Self::Complete,
            EvidenceState::Partial => Self::Partial,
            EvidenceState::PaginationLoop => Self::PaginationLoop,
            EvidenceState::RetentionGap => Self::RetentionGap,
            EvidenceState::AccessLoss => Self::AccessLoss,
            EvidenceState::Throttled => Self::Throttled,
            EvidenceState::ProviderUnknown => Self::ProviderUnknown,
            EvidenceState::Expired => Self::Expired,
            EvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
            EvidenceState::Tampered => Self::Tampered,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsSecurityLakeResult {
    pub service_id: String,
    pub consumer_id: String,
    pub operation: AwsSecurityLakeOperation,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub lake_digest: Digest,
    pub state: EvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: AwsSecurityLakeEvidence,
    pub provenance: TransportProvenance,
    pub accepted: bool,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsSecurityLakeResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsSecurityLakeResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub operation: AwsSecurityLakeOperation,
    pub state: EvidenceState,
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

impl RecordedAwsSecurityLakeResult {
    pub(crate) fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsSecurityLakeProposal,
        replayed: bool,
    ) -> Result<Self> {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digest().clone(),
            operation: proposal.operation,
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
            recording_digest: Digest::from_text("unsealed-aws-security-lake-recording"),
        };
        result.recording_digest = result.calculate_recording_digest();
        result.validate_integrity()?;
        Ok(result)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_recording_digest()
        {
            return Err(AwsSecurityLakeError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_recording_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("operation", self.operation.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }
}

/// Consumer scoped to one exact registration and Mission/Project/Work Product
/// fence. It can accept only complete, non-native, review-only proposals.
pub struct MissionAwsSecurityLakeConsumer {
    scope: AwsSecurityLakeScope,
    registration: AwsSecurityLakeRegistration,
    records: BTreeMap<Digest, RecordedAwsSecurityLakeResult>,
}

impl fmt::Debug for MissionAwsSecurityLakeConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsSecurityLakeConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("lake_digest", &self.scope.lake_digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsSecurityLakeConsumer {
    pub fn new(
        scope: AwsSecurityLakeScope,
        registration: AwsSecurityLakeRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsSecurityLakeError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsSecurityLakeError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &AwsSecurityLakeRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &AwsSecurityLakeScope {
        &self.scope
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn is_revoked(&self) -> bool {
        !self.registration.is_active()
    }

    pub fn revoke(&mut self) -> Result<()> {
        self.registration.revoke().map(|_| ())
    }

    pub fn bind_registration(&mut self, registration: AwsSecurityLakeRegistration) -> Result<()> {
        registration.validate()?;
        if !registration.is_active() || registration.scope_digest() != &self.scope.digest() {
            return Err(AwsSecurityLakeError::RegistrationInactive);
        }
        self.registration = registration;
        Ok(())
    }

    pub fn consume(
        &self,
        proposal: &AwsSecurityLakeProposal,
    ) -> Result<MissionAwsSecurityLakeResult> {
        proposal.validate_integrity()?;
        self.check_proposal_fence(proposal)?;
        if !proposal.state.is_complete()
            || !proposal.evidence.complete
            || !proposal.evidence.pagination.complete
            || proposal.evidence.state != EvidenceState::Complete
        {
            return Err(AwsSecurityLakeError::NonAdoptableEvidence);
        }
        let result = MissionAwsSecurityLakeResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operation: proposal.operation,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digest().clone(),
            scope_digest: self.scope.digest(),
            lake_digest: self.scope.lake_digest(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance,
            accepted: true,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        Ok(result)
    }

    pub fn record(
        &mut self,
        proposal: &AwsSecurityLakeProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsSecurityLakeResult> {
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty()
            || idempotency_key.chars().any(char::is_control)
            || idempotency_key.len() > crate::MAX_IDENTIFIER_BYTES
        {
            return Err(AwsSecurityLakeError::InvalidIdempotencyKey);
        }
        self.consume(proposal)?;
        let key_digest = Digest::from_text(idempotency_key);
        if let Some(recorded) = self.records.get(&key_digest) {
            if recorded.proposal_digest != proposal.proposal_digest {
                return Err(AwsSecurityLakeError::TamperedEvidence);
            }
            let mut replayed = recorded.clone();
            replayed.replayed = true;
            replayed.recording_digest = replayed.calculate_recording_digest();
            return Ok(replayed);
        }
        let recorded = RecordedAwsSecurityLakeResult::new(key_digest.clone(), proposal, false)?;
        self.records.insert(key_digest, recorded.clone());
        Ok(recorded)
    }

    pub fn verify_proposal(&self, proposal: &AwsSecurityLakeProposal) -> Result<()> {
        proposal.validate_integrity()?;
        self.check_proposal_fence(proposal)
    }

    fn check_proposal_fence(&self, proposal: &AwsSecurityLakeProposal) -> Result<()> {
        if !self.registration.is_active() {
            return Err(AwsSecurityLakeError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.provider_id != crate::PROVIDER_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
        {
            return Err(AwsSecurityLakeError::ScopeMismatch);
        }
        if proposal.scope_digest != self.scope.digest()
            || proposal.evidence.digests.scope_digest != self.scope.digest()
        {
            return Err(AwsSecurityLakeError::ScopeMismatch);
        }
        if proposal.lake_digest != self.scope.lake_digest()
            || proposal.evidence.digests.lake_digest != self.scope.lake_digest()
        {
            return Err(AwsSecurityLakeError::LakeMismatch);
        }
        if proposal.evidence.digests.permission_digest != self.registration.permission_digest() {
            return Err(AwsSecurityLakeError::PermissionMismatch);
        }
        if proposal.evidence.digests.provider_digest != *self.registration.provider_digest()
            || proposal.evidence.digests.contract_digest
                != Digest::from_text(crate::CONTRACT_DIGEST)
            || proposal.evidence.digests.plugin_version_digest
                != Digest::from_text(crate::PLUGIN_VERSION)
        {
            return Err(AwsSecurityLakeError::EvidenceMismatch);
        }
        if proposal.evidence.digests.evidence_policy_digest != *self.registration.evidence_digest()
        {
            return Err(AwsSecurityLakeError::EvidenceMismatch);
        }
        if proposal.native || proposal.connected || proposal.provider_receipt {
            return Err(AwsSecurityLakeError::TamperedEvidence);
        }
        Ok(())
    }
}
