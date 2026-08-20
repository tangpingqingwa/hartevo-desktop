//! Mission-scoped consumption and bounded local recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::model::{
    CloudSqlInstanceSnapshot, CloudSqlOperationSnapshot, Digest, GcpCloudSqlInstanceScope,
    GcpCloudSqlResultState, ProviderProvenance, Revision,
};
use crate::service::{
    GcpCloudSqlInstanceRegistration, GcpCloudSqlInstanceResultProposal,
    GcpCloudSqlInstanceResultServiceError, GcpCloudSqlLocalRecord, RegistrationState,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Runnable,
    Maintenance,
    Suspended,
    Failed,
    PendingCreate,
    PendingDelete,
    OperationRunning,
    OperationDone,
    OperationFailed,
    Absent,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    Replay,
    ReplayConflict,
    Revoked,
}

impl From<GcpCloudSqlResultState> for ProposalDisposition {
    fn from(state: GcpCloudSqlResultState) -> Self {
        match state {
            GcpCloudSqlResultState::Runnable => Self::Runnable,
            GcpCloudSqlResultState::Maintenance => Self::Maintenance,
            GcpCloudSqlResultState::Suspended => Self::Suspended,
            GcpCloudSqlResultState::Failed => Self::Failed,
            GcpCloudSqlResultState::PendingCreate => Self::PendingCreate,
            GcpCloudSqlResultState::PendingDelete => Self::PendingDelete,
            GcpCloudSqlResultState::OperationRunning => Self::OperationRunning,
            GcpCloudSqlResultState::OperationDone => Self::OperationDone,
            GcpCloudSqlResultState::OperationFailed => Self::OperationFailed,
            GcpCloudSqlResultState::Absent => Self::Absent,
            GcpCloudSqlResultState::Partial => Self::Partial,
            GcpCloudSqlResultState::AccessLoss => Self::AccessLoss,
            GcpCloudSqlResultState::ProviderUnknown => Self::ProviderUnknown,
            GcpCloudSqlResultState::Tampered => Self::Tampered,
            GcpCloudSqlResultState::Replay => Self::Replay,
            GcpCloudSqlResultState::ReplayConflict => Self::ReplayConflict,
            GcpCloudSqlResultState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionGcpCloudSqlInstanceResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub project_id_digest: Digest,
    pub project_revision: Revision,
    pub mission_id_digest: Digest,
    pub mission_revision: Revision,
    pub work_product_id_digest: Digest,
    pub work_product_revision: Revision,
    pub state: GcpCloudSqlResultState,
    pub disposition: ProposalDisposition,
    pub instance: Option<CloudSqlInstanceSnapshot>,
    pub operation: Option<CloudSqlOperationSnapshot>,
    pub evidence: crate::EvidenceDigests,
    pub provenance: ProviderProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionGcpCloudSqlInstanceResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }
}

pub struct MissionGcpCloudSqlInstanceConsumer {
    scope: GcpCloudSqlInstanceScope,
    registration: GcpCloudSqlInstanceRegistration,
    records: BTreeMap<Digest, GcpCloudSqlLocalRecord>,
}

impl fmt::Debug for MissionGcpCloudSqlInstanceConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGcpCloudSqlInstanceConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionGcpCloudSqlInstanceConsumer {
    pub fn new(
        scope: GcpCloudSqlInstanceScope,
        registration: GcpCloudSqlInstanceRegistration,
    ) -> Result<Self, GcpCloudSqlInstanceResultServiceError> {
        scope.validate()?;
        if registration.state() != RegistrationState::Active
            || registration.scope_digest() != scope.digest()
        {
            return Err(GcpCloudSqlInstanceResultServiceError::RegistrationRevoked);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &GcpCloudSqlInstanceScope {
        &self.scope
    }

    pub fn registration(&self) -> &GcpCloudSqlInstanceRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.registration.state(), RegistrationState::Active)
    }

    pub fn consume(
        &self,
        proposal: &GcpCloudSqlInstanceResultProposal,
    ) -> Result<MissionGcpCloudSqlInstanceResult, GcpCloudSqlInstanceResultServiceError> {
        proposal.validate_integrity()?;
        self.ensure_active()?;
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != *self.scope.digest()
            || proposal.project.id_digest != self.scope.project().id().digest()
            || proposal.project.revision != self.scope.project().revision()
            || proposal.mission.id_digest != self.scope.mission().id().digest()
            || proposal.mission.revision != self.scope.mission().revision()
            || proposal.work_product.id_digest != self.scope.work_product().id().digest()
            || proposal.work_product.revision != self.scope.work_product().revision()
        {
            return Err(GcpCloudSqlInstanceResultServiceError::ScopeMismatch);
        }
        Ok(MissionGcpCloudSqlInstanceResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            project_id_digest: proposal.project.id_digest.clone(),
            project_revision: proposal.project.revision,
            mission_id_digest: proposal.mission.id_digest.clone(),
            mission_revision: proposal.mission.revision,
            work_product_id_digest: proposal.work_product.id_digest.clone(),
            work_product_revision: proposal.work_product.revision,
            state: proposal.state.clone(),
            disposition: proposal.state.clone().into(),
            instance: proposal.instance.clone(),
            operation: proposal.operation.clone(),
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
        proposal: &GcpCloudSqlInstanceResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<GcpCloudSqlLocalRecord, GcpCloudSqlInstanceResultServiceError> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty()
            || key.len() > crate::MAX_IDENTIFIER_BYTES
            || key.chars().any(char::is_control)
        {
            return Err(GcpCloudSqlInstanceResultServiceError::InvalidIdempotencyKey);
        }
        let key_digest = Digest::from_text(key.as_bytes());
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(GcpCloudSqlInstanceResultServiceError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.state = GcpCloudSqlResultState::Replay;
            replay.recording_digest = recording_digest(&replay);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let mut record = GcpCloudSqlLocalRecord {
            idempotency_key_digest: key_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state.clone(),
            replayed: false,
            recording_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            durable_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        record.recording_digest = recording_digest(&record);
        record.validate_integrity()?;
        self.records.insert(key_digest, record.clone());
        Ok(record)
    }

    pub fn verify_evidence(
        &self,
        proposal: &GcpCloudSqlInstanceResultProposal,
    ) -> Result<(), GcpCloudSqlInstanceResultServiceError> {
        let _ = self.consume(proposal)?;
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), GcpCloudSqlInstanceResultServiceError> {
        if !self.is_active() {
            Err(GcpCloudSqlInstanceResultServiceError::RegistrationRevoked)
        } else {
            let _ = self.registration.revoke()?;
            Ok(())
        }
    }

    fn ensure_active(&self) -> Result<(), GcpCloudSqlInstanceResultServiceError> {
        if self.is_active() {
            Ok(())
        } else {
            Err(GcpCloudSqlInstanceResultServiceError::RegistrationRevoked)
        }
    }
}

fn recording_digest(record: &GcpCloudSqlLocalRecord) -> Digest {
    Digest::from_parts(
        "gcp-cloud-sql-local-record/v1",
        &[
            (
                "idempotency",
                record.idempotency_key_digest.as_str().to_owned(),
            ),
            ("proposal", record.proposal_digest.as_str().to_owned()),
            ("state", format!("{:?}", record.state)),
            ("replayed", record.replayed.to_string()),
        ],
    )
}

pub type MissionGcpCloudSqlResultConsumer = MissionGcpCloudSqlInstanceConsumer;
pub type MissionGcpCloudSqlResult = MissionGcpCloudSqlInstanceResult;
