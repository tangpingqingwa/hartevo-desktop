use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{GcpMemorystoreError, Result};
use crate::model::{
    Digest, EvidenceDigests, EvidenceState, MissionProjection, ProjectProjection,
    ProposalDisposition, RedisInstanceProjection, RequestReceipt, TransportProvenance,
    WorkProductProjection, mission_projection, project_projection, work_product_projection,
};
use crate::service::{
    GcpMemorystoreInstanceProposal, GcpMemorystoreInstanceRegistration, RegistrationStatus,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionGcpMemorystoreInstanceResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub instance: Option<RedisInstanceProjection>,
    pub state: EvidenceState,
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

impl MissionGcpMemorystoreInstanceResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedGcpMemorystoreInstanceResult {
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
    pub recording_digest: Digest,
}

impl RecordedGcpMemorystoreInstanceResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &GcpMemorystoreInstanceProposal,
        replayed: bool,
    ) -> Self {
        let mut value = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.disposition,
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("uncomputed-recording"),
        };
        value.recording_digest = recording_digest(&value);
        value
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
            return Err(GcpMemorystoreError::TamperedEvidence);
        }
        self.idempotency_key_digest.validate()?;
        self.proposal_digest.validate()
    }
}
fn recording_digest(value: &RecordedGcpMemorystoreInstanceResult) -> Digest {
    Digest::from_parts(
        "gcp-memorystore-recording/v1",
        &[
            (
                "idempotency",
                value.idempotency_key_digest.as_str().to_owned(),
            ),
            ("proposal", value.proposal_digest.as_str().to_owned()),
            ("state", format!("{:?}", value.state)),
            ("provenance", format!("{:?}", value.provenance)),
            ("replayed", value.replayed.to_string()),
        ],
    )
}

pub struct MissionGcpMemorystoreInstanceConsumer {
    scope: crate::model::GcpMemorystoreScope,
    registration: GcpMemorystoreInstanceRegistration,
    records: BTreeMap<Digest, RecordedGcpMemorystoreInstanceResult>,
}
impl fmt::Debug for MissionGcpMemorystoreInstanceConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGcpMemorystoreInstanceConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}
impl MissionGcpMemorystoreInstanceConsumer {
    pub fn new(
        scope: crate::model::GcpMemorystoreScope,
        registration: GcpMemorystoreInstanceRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(GcpMemorystoreError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(GcpMemorystoreError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }
    pub fn registration(&self) -> &GcpMemorystoreInstanceRegistration {
        &self.registration
    }
    pub fn scope(&self) -> &crate::model::GcpMemorystoreScope {
        &self.scope
    }
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
    pub fn consume(
        &self,
        proposal: &GcpMemorystoreInstanceProposal,
    ) -> Result<MissionGcpMemorystoreInstanceResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(GcpMemorystoreError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.registration_revision != self.registration.registration_revision
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != *self.scope.permission_digest()
            || proposal.evidence.api_digest != self.scope.api_digest()
        {
            return Err(GcpMemorystoreError::ScopeMismatch);
        }
        Ok(MissionGcpMemorystoreInstanceResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: mission_projection(self.scope.mission()),
            project: project_projection(self.scope.project()),
            work_product: work_product_projection(self.scope.work_product()),
            instance: proposal.projection.clone(),
            state: proposal.state,
            disposition: proposal.disposition,
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
        })
    }
    pub fn record(
        &mut self,
        proposal: &GcpMemorystoreInstanceProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedGcpMemorystoreInstanceResult> {
        self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty()
            || key.len() > crate::MAX_IDENTIFIER_BYTES
            || key.chars().any(char::is_control)
        {
            return Err(GcpMemorystoreError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(GcpMemorystoreError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = recording_digest(&replay);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let value = RecordedGcpMemorystoreInstanceResult::new(key_digest.clone(), proposal, false);
        value.validate_integrity()?;
        self.records.insert(key_digest, value.clone());
        Ok(value)
    }
    pub fn revoke(&mut self) -> Result<()> {
        self.registration.revoke().map(|_| ())
    }
    pub fn restore(&mut self) -> Result<()> {
        self.registration.restore().map(|_| ())
    }
}

const _: Option<RegistrationStatus> = None;
