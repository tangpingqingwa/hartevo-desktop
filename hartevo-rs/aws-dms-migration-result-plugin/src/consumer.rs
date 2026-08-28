//! Mission-scoped proposal consumption and idempotent Layer-1 recording.

use std::{collections::BTreeMap, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::error::{AwsDmsMigrationError, Result};
use crate::model::{
    AwsDmsMigrationEvidence, AwsDmsScope, Digest, EvidenceState, MissionProjection,
    ProjectProjection, TransportProvenance, WorkProductProjection,
};
use crate::service::{
    AwsDmsMigrationProposal, AwsDmsRecordReceipt, AwsDmsRegistration, ProposalDisposition,
};
use crate::{AWS_DMS_CONSUMER_ID, AWS_DMS_PLUGIN_VERSION, AWS_DMS_SERVICE_ID, contract_digest};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsDmsResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
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
}

impl MissionAwsDmsResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

pub struct MissionAwsDmsConsumer {
    scope: AwsDmsScope,
    registration: AwsDmsRegistration,
    records: BTreeMap<Digest, AwsDmsRecordReceipt>,
}

impl fmt::Debug for MissionAwsDmsConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsDmsConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsDmsConsumer {
    pub fn new(scope: AwsDmsScope, registration: AwsDmsRegistration) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsDmsMigrationError::RegistrationInactive);
        }
        if registration.scope_digest != scope.digest() {
            return Err(AwsDmsMigrationError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsDmsScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsDmsRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(&self, proposal: &AwsDmsMigrationProposal) -> Result<MissionAwsDmsResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AwsDmsMigrationError::RegistrationInactive);
        }
        if proposal.service_id != AWS_DMS_SERVICE_ID
            || proposal.consumer_id != AWS_DMS_CONSUMER_ID
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.digests.plugin_version_digest
                != Digest::from_text(AWS_DMS_PLUGIN_VERSION)
            || proposal.evidence.digests.contract_digest != contract_digest()
            || proposal.evidence.digests.provider_digest != self.registration.provider_digest
            || proposal.evidence.digests.api_digest != self.registration.api_digest
            || proposal.evidence.digests.permission_digest != self.registration.permission_digest
            || proposal.evidence.digests.consent_digest != self.registration.consent_digest
            || proposal.evidence.digests.scope_digest != self.registration.scope_digest
            || proposal.mission != MissionProjection::from(self.scope.mission())
            || proposal.project != ProjectProjection::from(self.scope.project())
            || proposal.work_product != WorkProductProjection::from(self.scope.work_product())
        {
            return Err(AwsDmsMigrationError::ScopeMismatch);
        }
        Ok(MissionAwsDmsResult {
            service_id: AWS_DMS_SERVICE_ID.to_owned(),
            consumer_id: AWS_DMS_CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance.clone(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn verify_evidence(&self, proposal: &AwsDmsMigrationProposal) -> Result<()> {
        let _ = self.consume(proposal)?;
        Ok(())
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
        let _ = self.consume(proposal)?;
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
        let receipt = AwsDmsRecordReceipt::for_consumer(key_digest.clone(), proposal, recorded_at);
        self.records.insert(key_digest, receipt.clone());
        Ok(receipt)
    }
}
