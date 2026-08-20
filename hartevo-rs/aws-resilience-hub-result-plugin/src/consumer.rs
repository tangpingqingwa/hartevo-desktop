//! Mission-scoped, redacted proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsResilienceHubError, Result};
use crate::model::{
    ApplicationProjection, AssessmentProjection, AwsResilienceHubScope, Digest, EvidenceDigests,
    MissionProjection, ProjectProjection, TransportProvenance, WorkProductProjection,
};
use crate::service::{
    AwsResilienceHubProposal, AwsResilienceHubRegistration, ResilienceEvidenceState,
};
use crate::{CONSUMER_ID, CONTRACT_DIGEST, PLUGIN_VERSION, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Compliant,
    NonCompliant,
    InProgress,
    Failed,
    Expired,
    Drifted,
    Partial,
    Unknown,
    AccessLoss,
    Throttled,
    NotFound,
    RegistrationRevoked,
}

impl From<ResilienceEvidenceState> for ProposalDisposition {
    fn from(state: ResilienceEvidenceState) -> Self {
        match state {
            ResilienceEvidenceState::Compliant => Self::Compliant,
            ResilienceEvidenceState::NonCompliant => Self::NonCompliant,
            ResilienceEvidenceState::InProgress => Self::InProgress,
            ResilienceEvidenceState::Failed => Self::Failed,
            ResilienceEvidenceState::Expired => Self::Expired,
            ResilienceEvidenceState::Drifted => Self::Drifted,
            ResilienceEvidenceState::Partial => Self::Partial,
            ResilienceEvidenceState::Unknown => Self::Unknown,
            ResilienceEvidenceState::AccessLoss => Self::AccessLoss,
            ResilienceEvidenceState::Throttled => Self::Throttled,
            ResilienceEvidenceState::NotFound => Self::NotFound,
            ResilienceEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsResilienceHubResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub application: Option<ApplicationProjection>,
    pub assessment: Option<AssessmentProjection>,
    pub state: ResilienceEvidenceState,
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
    pub result_digest: Digest,
}

impl MissionAwsResilienceHubResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.evidence.validate().is_err()
            || self.evidence.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.evidence.contract_digest
                != Digest::parse(CONTRACT_DIGEST.to_owned())
                    .expect("contract digest is a checked lowercase SHA-256 digest")
            || self.evidence.scope_digest != self.scope_digest
            || self.result_digest != self.calculate_digest()
        {
            return Err(AwsResilienceHubError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-mission-result/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "mission",
                    serde_json::to_string(&self.mission).expect("mission serializes"),
                ),
                (
                    "project",
                    serde_json::to_string(&self.project).expect("project serializes"),
                ),
                (
                    "work_product",
                    serde_json::to_string(&self.work_product).expect("work product serializes"),
                ),
                (
                    "application",
                    self.application.as_ref().map_or_else(String::new, |value| {
                        value.evidence_digest().as_str().to_owned()
                    }),
                ),
                (
                    "assessment",
                    self.assessment.as_ref().map_or_else(String::new, |value| {
                        value.evidence_digest().as_str().to_owned()
                    }),
                ),
                ("state", format!("{:?}", self.state)),
                ("disposition", format!("{:?}", self.disposition)),
                (
                    "evidence",
                    serde_json::to_string(&self.evidence).expect("evidence serializes"),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsResilienceHubResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: ResilienceEvidenceState,
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

impl RecordedAwsResilienceHubResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsResilienceHubProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            provenance: proposal.provenance.clone(),
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-aws-resilience-hub-recording"),
        };
        result.recording_digest = result.calculate_digest();
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            return Err(AwsResilienceHubError::TamperedEvidence);
        }
        self.idempotency_key_digest.validate()?;
        self.proposal_digest.validate()?;
        self.recording_digest.validate()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("disposition", format!("{:?}", self.disposition)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }
}

pub struct MissionAwsResilienceHubConsumer {
    scope: AwsResilienceHubScope,
    registration: AwsResilienceHubRegistration,
    records: BTreeMap<Digest, RecordedAwsResilienceHubResult>,
}

impl fmt::Debug for MissionAwsResilienceHubConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsResilienceHubConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsResilienceHubConsumer {
    pub fn new(
        scope: AwsResilienceHubScope,
        registration: AwsResilienceHubRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsResilienceHubError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsResilienceHubError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsResilienceHubScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsResilienceHubRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsResilienceHubProposal,
    ) -> Result<MissionAwsResilienceHubResult> {
        self.validate_proposal(proposal)?;
        let mut result = MissionAwsResilienceHubResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: MissionProjection::from(self.scope.mission()),
            project: ProjectProjection::from(self.scope.project()),
            work_product: WorkProductProjection::from(self.scope.work_product()),
            application: proposal.application.clone(),
            assessment: proposal.assessment.clone(),
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
            result_digest: Digest::from_text("unsealed-aws-resilience-hub-result"),
        };
        result.result_digest = result.calculate_digest();
        Ok(result)
    }

    pub fn record(
        &mut self,
        proposal: &AwsResilienceHubProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsResilienceHubResult> {
        self.validate_proposal(proposal)?;
        let key = idempotency_key.as_ref();
        if !valid_idempotency_key(key) {
            return Err(AwsResilienceHubError::InvalidRequest);
        }
        let idempotency_key_digest = Digest::from_parts(
            "aws-resilience-hub-idempotency-key/v1",
            &[("key", key.to_owned())],
        );
        if let Some(existing) = self.records.get(&idempotency_key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsResilienceHubError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.calculate_digest();
            return Ok(replay);
        }
        let result =
            RecordedAwsResilienceHubResult::new(idempotency_key_digest.clone(), proposal, false);
        self.records.insert(idempotency_key_digest, result.clone());
        Ok(result)
    }

    fn validate_proposal(&self, proposal: &AwsResilienceHubProposal) -> Result<()> {
        if !self.registration.is_active() {
            return Err(AwsResilienceHubError::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || proposal.evidence.contract_digest
                != Digest::parse(CONTRACT_DIGEST.to_owned())
                    .expect("contract digest is a checked lowercase SHA-256 digest")
            || proposal.evidence.provider_digest != *self.registration.provider_digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest()
            || proposal.evidence.consent_digest != self.registration.consent_digest()
            || proposal.evidence.application_allowlist_digest
                != self.scope.application_allowlist().digest()
            || proposal.evidence.assessment_allowlist_digest
                != self.scope.assessment_allowlist().digest()
        {
            return Err(AwsResilienceHubError::ScopeMismatch);
        }
        proposal.validate_integrity()
    }
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

pub type MissionAwsResilienceHubResultConsumer = MissionAwsResilienceHubConsumer;
pub type RecordedAwsResilienceHub = RecordedAwsResilienceHubResult;
