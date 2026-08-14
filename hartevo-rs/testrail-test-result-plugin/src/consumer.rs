use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    Digest, TestRailError, TestRailRegistration, TestRailResultProjection, TestRailResultStatus,
    TestRailScope, TransportProvenance,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestRailProposalDecision {
    RecommendPass,
    ReviewRequired,
    EvidenceIncomplete,
    AccessLost,
    ProviderUnknown,
}

pub type ProposalDecision = TestRailProposalDecision;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct TestRailAdoptionProposal {
    pub decision: TestRailProposalDecision,
    pub scope_digest: Digest,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub revision_digest: Digest,
    pub registration_digest: Digest,
    pub host_digest: Digest,
    pub project_digest: Digest,
    pub suite_digest: Digest,
    pub section_digest: Digest,
    pub run_digest: Digest,
    pub test_fingerprint: Digest,
    pub result_fingerprint: Digest,
    pub status_fingerprint: Digest,
    pub source_digest: Digest,
    pub mission_digest: Digest,
    pub hartevo_project_digest: Digest,
    pub work_product_digest: Digest,
    pub mission_revision: u64,
    pub run_revision: u64,
    pub run_updated_on: u64,
    pub provenance: TransportProvenance,
    pub non_mutating: bool,
    pub can_be_adopted: bool,
    pub native: bool,
    pub connected: bool,
    pub verified: bool,
    pub fingerprint: Digest,
}

impl TestRailAdoptionProposal {
    pub(crate) fn from_projection(
        projection: &TestRailResultProjection,
        registration: &TestRailRegistration,
    ) -> Result<Self, TestRailError> {
        projection.validate_integrity()?;
        registration.ensure_active()?;
        let scope = registration.scope();
        if projection.scope_digest != scope.scope_digest()
            || projection.version_digest != scope.version_digest()
            || projection.contract_digest != scope.contract_digest()
            || projection.provider_digest != registration.provider().digest()
            || projection.permission_digest != *registration.permissions().digest()
            || projection.revision_digest != scope.revision_digest()
            || projection.run_revision != scope.run.revision
            || projection.run_updated_on != scope.run.updated_on
            || projection.mission_digest != scope.mission_digest()
            || projection.hartevo_project_digest != scope.hartevo_project_digest()
            || projection.work_product_digest != scope.work_product_digest()
        {
            return Err(TestRailError::RecordingMismatch);
        }
        let decision = decision_for_projection(projection);
        let mut proposal = Self {
            decision,
            scope_digest: projection.scope_digest.clone(),
            version_digest: projection.version_digest.clone(),
            contract_digest: projection.contract_digest.clone(),
            provider_digest: projection.provider_digest.clone(),
            permission_digest: projection.permission_digest.clone(),
            revision_digest: projection.revision_digest.clone(),
            registration_digest: registration.registration_digest().clone(),
            host_digest: projection.host_digest.clone(),
            project_digest: projection.project_digest.clone(),
            suite_digest: projection.suite_digest.clone(),
            section_digest: projection.section_digest.clone(),
            run_digest: projection.run_digest.clone(),
            test_fingerprint: projection.test_fingerprint.clone(),
            result_fingerprint: projection.result_fingerprint.clone(),
            status_fingerprint: projection.status_fingerprint.clone(),
            source_digest: projection.source_digest.clone(),
            mission_digest: projection.mission_digest.clone(),
            hartevo_project_digest: projection.hartevo_project_digest.clone(),
            work_product_digest: projection.work_product_digest.clone(),
            mission_revision: scope.mission.revision,
            run_revision: projection.run_revision,
            run_updated_on: projection.run_updated_on,
            provenance: projection.provenance,
            non_mutating: true,
            can_be_adopted: false,
            native: false,
            connected: false,
            verified: false,
            fingerprint: Digest::from_text("placeholder"),
        };
        proposal.fingerprint = proposal.compute_fingerprint();
        proposal.validate_integrity()?;
        Ok(proposal)
    }

    pub fn validate_integrity(&self) -> Result<(), TestRailError> {
        if self.fingerprint != self.compute_fingerprint()
            || !self.non_mutating
            || self.can_be_adopted
            || self.native
            || self.connected
            || self.verified
            || !self.provenance.is_explicit_non_native()
        {
            return Err(TestRailError::TamperDetected);
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> &Digest {
        &self.fingerprint
    }
    pub fn is_adoptable(&self) -> bool {
        false
    }
    pub fn can_be_adopted(&self) -> bool {
        false
    }

    fn compute_fingerprint(&self) -> Digest {
        Digest::from_serializable(&ProposalMaterial::from_proposal(self))
    }
}

pub type TestRailResultProposal = TestRailAdoptionProposal;
pub type MissionTestRailResultProposal = TestRailAdoptionProposal;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalMaterial {
    decision: TestRailProposalDecision,
    scope_digest: Digest,
    version_digest: Digest,
    contract_digest: Digest,
    provider_digest: Digest,
    permission_digest: Digest,
    revision_digest: Digest,
    registration_digest: Digest,
    host_digest: Digest,
    project_digest: Digest,
    suite_digest: Digest,
    section_digest: Digest,
    run_digest: Digest,
    test_fingerprint: Digest,
    result_fingerprint: Digest,
    status_fingerprint: Digest,
    source_digest: Digest,
    mission_digest: Digest,
    hartevo_project_digest: Digest,
    work_product_digest: Digest,
    mission_revision: u64,
    run_revision: u64,
    run_updated_on: u64,
    provenance: TransportProvenance,
    non_mutating: bool,
}

impl ProposalMaterial {
    fn from_proposal(proposal: &TestRailAdoptionProposal) -> Self {
        Self {
            decision: proposal.decision,
            scope_digest: proposal.scope_digest.clone(),
            version_digest: proposal.version_digest.clone(),
            contract_digest: proposal.contract_digest.clone(),
            provider_digest: proposal.provider_digest.clone(),
            permission_digest: proposal.permission_digest.clone(),
            revision_digest: proposal.revision_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            host_digest: proposal.host_digest.clone(),
            project_digest: proposal.project_digest.clone(),
            suite_digest: proposal.suite_digest.clone(),
            section_digest: proposal.section_digest.clone(),
            run_digest: proposal.run_digest.clone(),
            test_fingerprint: proposal.test_fingerprint.clone(),
            result_fingerprint: proposal.result_fingerprint.clone(),
            status_fingerprint: proposal.status_fingerprint.clone(),
            source_digest: proposal.source_digest.clone(),
            mission_digest: proposal.mission_digest.clone(),
            hartevo_project_digest: proposal.hartevo_project_digest.clone(),
            work_product_digest: proposal.work_product_digest.clone(),
            mission_revision: proposal.mission_revision,
            run_revision: proposal.run_revision,
            run_updated_on: proposal.run_updated_on,
            provenance: proposal.provenance,
            non_mutating: proposal.non_mutating,
        }
    }
}

fn decision_for_projection(projection: &TestRailResultProjection) -> TestRailProposalDecision {
    if projection.status == TestRailResultStatus::AccessLoss {
        return TestRailProposalDecision::AccessLost;
    }
    if projection.status == TestRailResultStatus::ProviderUnknown {
        return TestRailProposalDecision::ProviderUnknown;
    }
    if !projection.complete {
        return TestRailProposalDecision::EvidenceIncomplete;
    }
    if projection.status == TestRailResultStatus::Passed {
        TestRailProposalDecision::RecommendPass
    } else {
        TestRailProposalDecision::ReviewRequired
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedTestRailResult {
    pub proposal_fingerprint: Digest,
    pub proposal: TestRailAdoptionProposal,
    pub recording_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestRailRecordingReceipt {
    pub proposal_fingerprint: Digest,
    pub recording_digest: Digest,
    pub replayed: bool,
    pub provenance: TransportProvenance,
}

pub type RecordingReceipt = TestRailRecordingReceipt;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TestRailRecordingLog {
    records: BTreeMap<Digest, RecordedTestRailResult>,
}

impl TestRailRecordingLog {
    pub fn record(
        &mut self,
        proposal: &TestRailAdoptionProposal,
    ) -> Result<TestRailRecordingReceipt, TestRailError> {
        proposal.validate_integrity()?;
        let fingerprint = proposal.fingerprint.clone();
        let recording_digest = Digest::from_serializable(proposal);
        if let Some(existing) = self.records.get(&fingerprint) {
            if existing.recording_digest != recording_digest || existing.proposal != *proposal {
                return Err(TestRailError::DuplicateRecording);
            }
            return Ok(TestRailRecordingReceipt {
                proposal_fingerprint: fingerprint,
                recording_digest,
                replayed: true,
                provenance: proposal.provenance,
            });
        }
        self.records.insert(
            fingerprint.clone(),
            RecordedTestRailResult {
                proposal_fingerprint: fingerprint.clone(),
                proposal: proposal.clone(),
                recording_digest: recording_digest.clone(),
            },
        );
        Ok(TestRailRecordingReceipt {
            proposal_fingerprint: fingerprint,
            recording_digest,
            replayed: false,
            provenance: proposal.provenance,
        })
    }

    pub fn get(&self, fingerprint: &Digest) -> Option<&RecordedTestRailResult> {
        self.records.get(fingerprint)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[derive(Clone)]
pub struct MissionTestRailResultConsumer {
    scope: TestRailScope,
}

impl fmt::Debug for MissionTestRailResultConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionTestRailResultConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("mission_revision", &self.scope.mission.revision)
            .field("work_product_digest", &self.scope.work_product_digest())
            .finish()
    }
}

impl MissionTestRailResultConsumer {
    pub fn new(scope: TestRailScope) -> Result<Self, TestRailError> {
        scope.validate()?;
        Ok(Self { scope })
    }

    pub fn from_registration(registration: &TestRailRegistration) -> Result<Self, TestRailError> {
        registration.validate_integrity()?;
        Self::new(registration.scope.clone())
    }

    pub fn scope(&self) -> &TestRailScope {
        &self.scope
    }

    pub fn propose(
        &self,
        projection: &TestRailResultProjection,
        mission_revision: u64,
        registration: &TestRailRegistration,
    ) -> Result<TestRailAdoptionProposal, TestRailError> {
        if mission_revision != self.scope.mission.revision {
            return Err(TestRailError::StaleMissionRevision);
        }
        if projection.scope_digest != self.scope.scope_digest()
            || projection.mission_digest != self.scope.mission_digest()
            || projection.hartevo_project_digest != self.scope.hartevo_project_digest()
            || projection.work_product_digest != self.scope.work_product_digest()
        {
            return Err(TestRailError::RecordingMismatch);
        }
        TestRailAdoptionProposal::from_projection(projection, registration)
    }

    pub fn consume(
        &self,
        projection: &TestRailResultProjection,
        registration: &TestRailRegistration,
    ) -> Result<TestRailAdoptionProposal, TestRailError> {
        self.propose(projection, self.scope.mission.revision, registration)
    }

    pub fn record(
        &self,
        log: &mut TestRailRecordingLog,
        proposal: &TestRailAdoptionProposal,
    ) -> Result<TestRailRecordingReceipt, TestRailError> {
        proposal.validate_integrity()?;
        if proposal.scope_digest != self.scope.scope_digest()
            || proposal.mission_revision != self.scope.mission.revision
            || proposal.work_product_digest != self.scope.work_product_digest()
        {
            return Err(TestRailError::RecordingMismatch);
        }
        log.record(proposal)
    }
}
