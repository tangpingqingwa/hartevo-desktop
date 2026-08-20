use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{BigCommerceOrderResultError, Result};
use crate::model::{
    BigCommerceOrderScope, Digest, MissionScope, ProjectScope, TransportProvenance,
    WorkProductScope,
};
use crate::service::{BigCommerceOrderRegistration, BigCommerceOrderResultProposal, EvidenceState};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Completed,
    Partial,
    AccessLoss,
    NotFound,
    Conflict,
    RateLimited,
    ProviderUnknown,
    RegistrationRevoked,
}

impl From<EvidenceState> for ProposalDisposition {
    fn from(state: EvidenceState) -> Self {
        match state {
            EvidenceState::Complete => Self::Completed,
            EvidenceState::Partial => Self::Partial,
            EvidenceState::AccessLost => Self::AccessLoss,
            EvidenceState::NotFound => Self::NotFound,
            EvidenceState::Conflict => Self::Conflict,
            EvidenceState::RateLimited => Self::RateLimited,
            EvidenceState::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBigCommerceOrderResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionScope,
    pub project: ProjectScope,
    pub work_product: WorkProductScope,
    pub state: EvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence_digest: Digest,
    pub revision_digests: Vec<Digest>,
    pub amount_digests: Vec<Digest>,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionBigCommerceOrderResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadBackFence {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub record_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedBigCommerceOrderResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
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
    pub record_digest: Digest,
    pub read_back_fence: ReadBackFence,
}

impl RecordedBigCommerceOrderResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &BigCommerceOrderResultProposal,
        registration_digest: &Digest,
        scope_digest: &Digest,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.status(),
            disposition: proposal.status().into(),
            provenance: proposal.evidence.provider_provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            record_digest: Digest::from_text("unsealed-bigcommerce-record"),
            read_back_fence: ReadBackFence {
                idempotency_key_digest: Digest::from_text("unsealed-bigcommerce-key"),
                proposal_digest: Digest::from_text("unsealed-bigcommerce-proposal"),
                registration_digest: Digest::from_text("unsealed-bigcommerce-registration"),
                scope_digest: Digest::from_text("unsealed-bigcommerce-scope"),
                record_digest: Digest::from_text("unsealed-bigcommerce-record-fence"),
            },
        };
        result.record_digest = result.calculate_record_digest();
        result.read_back_fence = ReadBackFence {
            idempotency_key_digest: result.idempotency_key_digest.clone(),
            proposal_digest: result.proposal_digest.clone(),
            registration_digest: registration_digest.clone(),
            scope_digest: scope_digest.clone(),
            record_digest: result.record_digest.clone(),
        };
        result
    }

    fn calculate_record_digest(&self) -> Digest {
        Digest::from_parts(
            "bigcommerce-recorded-result/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("outcome", self.outcome_adopted.to_string()),
                ("work_product", self.work_product_adopted.to_string()),
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
            || self.record_digest != self.calculate_record_digest()
            || self.read_back_fence.idempotency_key_digest != self.idempotency_key_digest
            || self.read_back_fence.proposal_digest != self.proposal_digest
            || self.read_back_fence.record_digest != self.record_digest
        {
            Err(BigCommerceOrderResultError::InvalidReadBack)
        } else {
            Ok(())
        }
    }
}

pub struct MissionBigCommerceOrderConsumer {
    scope: BigCommerceOrderScope,
    registration: BigCommerceOrderRegistration,
    records: BTreeMap<Digest, RecordedBigCommerceOrderResult>,
}

impl fmt::Debug for MissionBigCommerceOrderConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBigCommerceOrderConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionBigCommerceOrderConsumer {
    pub fn new(
        scope: BigCommerceOrderScope,
        registration: BigCommerceOrderRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(BigCommerceOrderResultError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.scope_digest() {
            return Err(BigCommerceOrderResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &BigCommerceOrderRegistration {
        &self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &BigCommerceOrderScope {
        &self.scope
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &BigCommerceOrderResultProposal,
    ) -> Result<MissionBigCommerceOrderResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(BigCommerceOrderResultError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.registration_revision != self.registration.registration_revision()
            || proposal.scope_digest != self.scope.scope_digest()
            || proposal.evidence.scope_digest != self.scope.scope_digest()
            || proposal.evidence.work_product_revision != self.scope.work_product().revision()
        {
            return Err(BigCommerceOrderResultError::ScopeMismatch);
        }
        Ok(MissionBigCommerceOrderResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: self.scope.mission().clone(),
            project: self.scope.project().clone(),
            work_product: self.scope.work_product().clone(),
            state: proposal.status(),
            disposition: proposal.status().into(),
            evidence_digest: proposal.evidence.digests.evidence_digest.clone(),
            revision_digests: proposal.evidence.digests.revision_digests.clone(),
            amount_digests: proposal.evidence.digests.amount_digests.clone(),
            provenance: proposal.evidence.provider_provenance,
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
        proposal: &BigCommerceOrderResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedBigCommerceOrderResult> {
        let _ = self.consume(proposal)?;
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty()
            || idempotency_key.len() > crate::MAX_IDENTIFIER_BYTES
            || idempotency_key.chars().any(char::is_control)
        {
            return Err(BigCommerceOrderResultError::InvalidRecordingKey);
        }
        let key_digest = Digest::from_text(idempotency_key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(BigCommerceOrderResultError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        if !self.registration.is_active() {
            return Err(BigCommerceOrderResultError::RegistrationInactive);
        }
        let result = RecordedBigCommerceOrderResult::new(
            key_digest.clone(),
            proposal,
            self.registration.registration_digest(),
            &self.scope.scope_digest(),
            false,
        );
        result.validate_integrity()?;
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }

    pub fn read_back(
        &self,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedBigCommerceOrderResult> {
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(BigCommerceOrderResultError::InvalidRecordingKey);
        }
        self.read_back_by_digest(&Digest::from_text(key))
    }

    pub fn read_back_by_digest(
        &self,
        idempotency_key_digest: &Digest,
    ) -> Result<RecordedBigCommerceOrderResult> {
        let result = self
            .records
            .get(idempotency_key_digest)
            .ok_or(BigCommerceOrderResultError::RecordingNotFound)?;
        result.validate_integrity()?;
        if result.read_back_fence.scope_digest != self.scope.scope_digest()
            || result.read_back_fence.registration_digest
                != *self.registration.registration_digest()
        {
            return Err(BigCommerceOrderResultError::InvalidReadBack);
        }
        let mut read_back = result.clone();
        read_back.replayed = true;
        Ok(read_back)
    }
}
