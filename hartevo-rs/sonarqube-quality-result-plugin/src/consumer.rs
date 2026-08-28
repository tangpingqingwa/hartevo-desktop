//! Mission-scoped quality-result proposals and local recording only.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, MissionId, ProjectId, ProjectionState, QualityGateStatus, RegistrationId,
    SonarQubeQualityScope, TransportProvenance, WorkProductId,
};
use crate::provider::SonarQubeQualityProjection;
use crate::service::SonarQubeQualityRegistration;
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, MAX_IDEMPOTENCY_KEY_BYTES, Result, SERVICE_ID,
    SonarQubeQualityResultError, validate_text,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityDecision {
    Pass,
    Fail,
    Review,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    PassEvidence,
    FailEvidence,
    ReviewOnly,
    NoAnalysis,
    Stale,
    Partial,
    AccessLoss,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingDisposition {
    Fresh,
    Replay,
}

/// A below-kernel quality decision proposal. It contains exact scope fields,
/// bounded metadata, and digests only; it is not a kernel Outcome, approval,
/// Receipt, Verification, or provider write.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SonarQubeQualityProposal {
    pub proposal_version: String,
    pub service_id: String,
    pub consumer_id: String,
    pub registration_id: RegistrationId,
    pub registration_revision: u64,
    pub registration_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub capability_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub scope_digest: Digest,
    pub scope: SonarQubeQualityScope,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub project_id: ProjectId,
    pub project_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub state: ProjectionState,
    pub quality_gate_status: Option<QualityGateStatus>,
    pub decision: QualityDecision,
    pub disposition: ProposalDisposition,
    pub analysis_digest: Option<Digest>,
    pub quality_gate_digest: Option<Digest>,
    pub measure_digest: Option<Digest>,
    pub measure_selection_digest: Digest,
    pub projection_digest: Digest,
    pub response_digests: Vec<Digest>,
    pub provenance: TransportProvenance,
    pub partial: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
}

impl SonarQubeQualityProposal {
    fn from_projection(
        registration: &SonarQubeQualityRegistration,
        projection: &SonarQubeQualityProjection,
        idempotency_key: &str,
    ) -> Self {
        let decision = match projection.state {
            ProjectionState::Pass => QualityDecision::Pass,
            ProjectionState::Error => QualityDecision::Fail,
            ProjectionState::Warn
            | ProjectionState::NoAnalysis
            | ProjectionState::Stale
            | ProjectionState::Partial
            | ProjectionState::AccessLoss
            | ProjectionState::ProviderUnknown => QualityDecision::Review,
        };
        let disposition = match projection.state {
            ProjectionState::Pass => ProposalDisposition::PassEvidence,
            ProjectionState::Error => ProposalDisposition::FailEvidence,
            ProjectionState::Warn => ProposalDisposition::ReviewOnly,
            ProjectionState::NoAnalysis => ProposalDisposition::NoAnalysis,
            ProjectionState::Stale => ProposalDisposition::Stale,
            ProjectionState::Partial => ProposalDisposition::Partial,
            ProjectionState::AccessLoss => ProposalDisposition::AccessLoss,
            ProjectionState::ProviderUnknown => ProposalDisposition::ProviderUnknown,
        };
        let mut proposal = Self {
            proposal_version: format!("{CONTRACT_VERSION}/quality-result-proposal"),
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_id: registration.id().clone(),
            registration_revision: registration.registration_revision(),
            registration_digest: registration.registration_digest().clone(),
            contract_digest: registration.contract_digest().clone(),
            provider_digest: registration.provider().provider_digest.clone(),
            api_digest: registration.provider().api_digest.clone(),
            capability_digest: registration.capability_digest().clone(),
            permission_digest: registration.permission_snapshot().digest().clone(),
            secret_reference_digest: registration.secret_reference().reference_digest().clone(),
            scope_digest: registration.scope_digest().clone(),
            scope: projection.scope.clone(),
            mission_id: projection.scope.mission.mission_id.clone(),
            mission_revision: projection.scope.mission.mission_revision,
            project_id: projection.scope.mission.project_id.clone(),
            project_revision: projection.scope.mission.project_revision,
            work_product_id: projection.scope.mission.work_product_id.clone(),
            work_product_revision: projection.scope.mission.work_product_revision,
            state: projection.state,
            quality_gate_status: projection.quality_gate_status,
            decision,
            disposition,
            analysis_digest: projection.analysis_digest.clone(),
            quality_gate_digest: projection.quality_gate_digest.clone(),
            measure_digest: projection.measure_digest.clone(),
            measure_selection_digest: projection.scope.measure_selection_digest(),
            projection_digest: projection.projection_digest.clone(),
            response_digests: projection.response_digests.clone(),
            provenance: projection.provenance,
            partial: projection.partial,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            idempotency_key_digest: Digest::from_text(idempotency_key),
            proposal_digest: Digest::from_text("unsealed-sonarqube-quality-proposal"),
        };
        proposal.proposal_digest = proposal.computed_digest();
        proposal
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope.validate()?;
        for digest in [
            Some(&self.registration_digest),
            Some(&self.contract_digest),
            Some(&self.provider_digest),
            Some(&self.api_digest),
            Some(&self.capability_digest),
            Some(&self.permission_digest),
            Some(&self.secret_reference_digest),
            Some(&self.scope_digest),
            self.analysis_digest.as_ref(),
            self.quality_gate_digest.as_ref(),
            self.measure_digest.as_ref(),
            Some(&self.measure_selection_digest),
            Some(&self.projection_digest),
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        for digest in &self.response_digests {
            digest.validate()?;
        }
        if self.proposal_version != format!("{CONTRACT_VERSION}/quality-result-proposal")
            || self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.registration_revision == 0
            || self.mission_revision == 0
            || self.project_revision == 0
            || self.work_product_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.measure_selection_digest != self.scope.measure_selection_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.proposal_digest != self.computed_digest()
        {
            return Err(SonarQubeQualityResultError::ProposalTampered);
        }
        Ok(())
    }

    pub fn computed_digest(&self) -> Digest {
        self.computed_digest_inner()
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    fn computed_digest_inner(&self) -> Digest {
        Digest::from_parts(
            "sonarqube-quality-result-proposal/v1",
            &[
                ("proposal_version", self.proposal_version.clone()),
                ("service_id", self.service_id.clone()),
                ("consumer_id", self.consumer_id.clone()),
                ("registration_id", self.registration_id.as_str().to_owned()),
                (
                    "registration_revision",
                    self.registration_revision.to_string(),
                ),
                (
                    "registration_digest",
                    self.registration_digest.as_str().to_owned(),
                ),
                ("contract_digest", self.contract_digest.as_str().to_owned()),
                ("provider_digest", self.provider_digest.as_str().to_owned()),
                ("api_digest", self.api_digest.as_str().to_owned()),
                (
                    "capability_digest",
                    self.capability_digest.as_str().to_owned(),
                ),
                (
                    "permission_digest",
                    self.permission_digest.as_str().to_owned(),
                ),
                (
                    "secret_reference_digest",
                    self.secret_reference_digest.as_str().to_owned(),
                ),
                ("scope_digest", self.scope_digest.as_str().to_owned()),
                (
                    "scope",
                    serde_json::to_string(&self.scope).expect("scope serializes"),
                ),
                ("mission_id", self.mission_id.as_str().to_owned()),
                ("mission_revision", self.mission_revision.to_string()),
                ("project_id", self.project_id.as_str().to_owned()),
                ("project_revision", self.project_revision.to_string()),
                ("work_product_id", self.work_product_id.as_str().to_owned()),
                (
                    "work_product_revision",
                    self.work_product_revision.to_string(),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "quality_gate_status",
                    self.quality_gate_status
                        .map_or_else(|| "none".to_owned(), |status| format!("{status:?}")),
                ),
                ("decision", format!("{:?}", self.decision)),
                ("disposition", format!("{:?}", self.disposition)),
                (
                    "analysis_digest",
                    optional_digest(self.analysis_digest.as_ref()),
                ),
                (
                    "quality_gate_digest",
                    optional_digest(self.quality_gate_digest.as_ref()),
                ),
                (
                    "measure_digest",
                    optional_digest(self.measure_digest.as_ref()),
                ),
                (
                    "measure_selection_digest",
                    self.measure_selection_digest.as_str().to_owned(),
                ),
                (
                    "projection_digest",
                    self.projection_digest.as_str().to_owned(),
                ),
                (
                    "response_digests",
                    serde_json::to_string(&self.response_digests)
                        .expect("response digests serialize"),
                ),
                ("provenance", format!("{:?}", self.provenance)),
                ("partial", self.partial.to_string()),
                (
                    "idempotency_key_digest",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedSonarQubeQualityResult {
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub state: ProjectionState,
    pub decision: QualityDecision,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedSonarQubeQualityResult {
    fn from_proposal(proposal: &SonarQubeQualityProposal, replayed: bool) -> Self {
        let mut recording = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            decision: proposal.decision,
            disposition: proposal.disposition,
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            recording_digest: Digest::from_text("unsealed-sonarqube-recording"),
        };
        recording.recording_digest = recording.computed_digest();
        recording
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.proposal_digest,
            &self.registration_digest,
            &self.scope_digest,
            self.state,
            self.decision,
            self.disposition,
            self.provenance,
            self.replayed,
            self.connected,
            self.native,
            self.first_party,
            self.provider_receipt,
            self.outcome_adopted,
        ))
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.proposal_digest.validate()?;
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.recording_digest != self.computed_digest()
        {
            Err(SonarQubeQualityResultError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SonarQubeQualityRecordingLog {
    records: BTreeMap<Digest, RecordedSonarQubeQualityResult>,
}

impl SonarQubeQualityRecordingLog {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, idempotency_key_digest: &Digest) -> Option<&RecordedSonarQubeQualityResult> {
        self.records.get(idempotency_key_digest)
    }

    fn record(
        &mut self,
        proposal: &SonarQubeQualityProposal,
    ) -> Result<RecordedSonarQubeQualityResult> {
        proposal.validate_integrity()?;
        if let Some(existing) = self.records.get(&proposal.idempotency_key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(SonarQubeQualityResultError::ReplayConflict);
            }
            let replay = RecordedSonarQubeQualityResult::from_proposal(proposal, true);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result = RecordedSonarQubeQualityResult::from_proposal(proposal, false);
        result.validate_integrity()?;
        self.records
            .insert(proposal.idempotency_key_digest.clone(), result.clone());
        Ok(result)
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionConsumption {
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub project_id: ProjectId,
    pub project_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub state: ProjectionState,
    pub quality_disposition: ProposalDisposition,
    pub disposition: MissionConsumptionDisposition,
    pub replayed: bool,
    pub adopted: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub consumption_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionConsumptionDisposition {
    Fresh,
    Replay,
}

/// A Mission consumer is scoped to exactly one Mission/Project/Work Product
/// revision and can only compile or locally record a below-kernel proposal.
#[derive(Clone, Debug)]
pub struct MissionSonarQubeQualityConsumer {
    scope: SonarQubeQualityScope,
    consumed: BTreeMap<Digest, Digest>,
    active: bool,
}

impl MissionSonarQubeQualityConsumer {
    pub fn new(scope: SonarQubeQualityScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope,
            consumed: BTreeMap::new(),
            active: true,
        })
    }

    pub fn scope(&self) -> &SonarQubeQualityScope {
        &self.scope
    }

    pub fn compile_quality_result_proposal(
        &self,
        registration: &SonarQubeQualityRegistration,
        projection: &SonarQubeQualityProjection,
        idempotency_key: impl Into<String>,
    ) -> Result<SonarQubeQualityProposal> {
        if !self.active {
            return Err(SonarQubeQualityResultError::ConsumerInactive);
        }
        registration.validate()?;
        if !registration.is_active() {
            return if registration.status() == crate::RegistrationStatus::Revoked {
                Err(SonarQubeQualityResultError::RegistrationRevoked)
            } else {
                Err(SonarQubeQualityResultError::RegistrationUnmounted)
            };
        }
        projection.validate_integrity()?;
        if registration.scope() != &self.scope || projection.scope != self.scope {
            return Err(SonarQubeQualityResultError::ScopeMismatch);
        }
        let idempotency_key = idempotency_key.into();
        validate_text(
            &idempotency_key,
            "idempotencyKey",
            MAX_IDEMPOTENCY_KEY_BYTES,
            false,
        )?;
        Ok(SonarQubeQualityProposal::from_projection(
            registration,
            projection,
            &idempotency_key,
        ))
    }

    pub fn compile_proposal(
        &self,
        registration: &SonarQubeQualityRegistration,
        projection: &SonarQubeQualityProjection,
        idempotency_key: impl Into<String>,
    ) -> Result<SonarQubeQualityProposal> {
        self.compile_quality_result_proposal(registration, projection, idempotency_key)
    }

    pub fn record_quality_result(
        &self,
        log: &mut SonarQubeQualityRecordingLog,
        proposal: &SonarQubeQualityProposal,
    ) -> Result<RecordedSonarQubeQualityResult> {
        if proposal.scope_digest != self.scope.digest()
            || proposal.mission_id != self.scope.mission.mission_id
            || proposal.mission_revision != self.scope.mission.mission_revision
            || proposal.project_id != self.scope.mission.project_id
            || proposal.project_revision != self.scope.mission.project_revision
            || proposal.work_product_id != self.scope.mission.work_product_id
            || proposal.work_product_revision != self.scope.mission.work_product_revision
        {
            return Err(SonarQubeQualityResultError::StaleMissionRevision);
        }
        log.record(proposal)
    }

    pub fn record(
        &self,
        log: &mut SonarQubeQualityRecordingLog,
        proposal: &SonarQubeQualityProposal,
    ) -> Result<RecordedSonarQubeQualityResult> {
        self.record_quality_result(log, proposal)
    }

    pub fn consume(&mut self, proposal: &SonarQubeQualityProposal) -> Result<MissionConsumption> {
        if !self.active {
            return Err(SonarQubeQualityResultError::ConsumerInactive);
        }
        proposal.validate_integrity()?;
        if proposal.scope_digest != self.scope.digest()
            || proposal.mission_id != self.scope.mission.mission_id
            || proposal.mission_revision != self.scope.mission.mission_revision
            || proposal.project_id != self.scope.mission.project_id
            || proposal.project_revision != self.scope.mission.project_revision
            || proposal.work_product_id != self.scope.mission.work_product_id
            || proposal.work_product_revision != self.scope.mission.work_product_revision
        {
            return Err(SonarQubeQualityResultError::StaleMissionRevision);
        }
        let replayed = match self.consumed.get(&proposal.idempotency_key_digest) {
            Some(existing) if existing == &proposal.proposal_digest => true,
            Some(_) => return Err(SonarQubeQualityResultError::ReplayConflict),
            None => false,
        };
        self.consumed.insert(
            proposal.idempotency_key_digest.clone(),
            proposal.proposal_digest.clone(),
        );
        let mut consumption = MissionConsumption {
            mission_id: proposal.mission_id.clone(),
            mission_revision: proposal.mission_revision,
            project_id: proposal.project_id.clone(),
            project_revision: proposal.project_revision,
            work_product_id: proposal.work_product_id.clone(),
            work_product_revision: proposal.work_product_revision,
            state: proposal.state,
            quality_disposition: proposal.disposition,
            disposition: if replayed {
                MissionConsumptionDisposition::Replay
            } else {
                MissionConsumptionDisposition::Fresh
            },
            replayed,
            adopted: false,
            connected: false,
            native: false,
            provider_receipt: false,
            consumption_digest: Digest::from_text("unsealed-sonarqube-consumption"),
        };
        consumption.consumption_digest = Digest::from_serialized(&(
            &consumption.mission_id,
            consumption.mission_revision,
            &consumption.project_id,
            consumption.project_revision,
            &consumption.work_product_id,
            consumption.work_product_revision,
            consumption.state,
            consumption.quality_disposition,
            consumption.disposition,
            consumption.replayed,
            consumption.adopted,
            consumption.connected,
            consumption.native,
            consumption.provider_receipt,
        ));
        Ok(consumption)
    }

    pub fn unmount(&mut self) {
        self.active = false;
    }
}

fn optional_digest(value: Option<&Digest>) -> String {
    value.map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned())
}
