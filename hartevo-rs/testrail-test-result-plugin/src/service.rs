use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    API_REVISION, CONTRACT_VERSION, Digest, MissionTestRailResultConsumer, PLUGIN_VERSION,
    PROVIDER_ID, ProviderIdentity, SERVICE_ID, TestRailAdoptionProposal, TestRailError,
    TestRailProvider, TestRailRecordingLog, TestRailRecordingReceipt, TestRailRegistration,
    TestRailResultProjection, TestRailTransport, TransportProvenance, Version, contract_digest,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct TestRailCapabilityDescription {
    pub layer: u8,
    pub service_id: String,
    pub provider_id: String,
    pub plugin_version: Version,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub api_revision: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub verified: bool,
    pub transport_provenance: TransportProvenance,
    pub allowed_operations: Vec<String>,
    pub forbidden_operations: Vec<String>,
}

pub type CapabilityDescription = TestRailCapabilityDescription;

pub struct TestRailTestResultService<T> {
    provider: TestRailProvider<T>,
    proposal_fingerprints: BTreeSet<Digest>,
}

impl<T: TestRailTransport> TestRailTestResultService<T> {
    pub fn new(registration: TestRailRegistration, transport: T) -> Result<Self, TestRailError> {
        Ok(Self {
            provider: TestRailProvider::new(registration, transport)?,
            proposal_fingerprints: BTreeSet::new(),
        })
    }

    pub fn from_provider(provider: TestRailProvider<T>) -> Result<Self, TestRailError> {
        provider.registration().validate_integrity()?;
        Ok(Self {
            provider,
            proposal_fingerprints: BTreeSet::new(),
        })
    }

    pub fn registration(&self) -> &TestRailRegistration {
        self.provider.registration()
    }
    pub fn provider(&self) -> &TestRailProvider<T> {
        &self.provider
    }
    pub fn provider_mut(&mut self) -> &mut TestRailProvider<T> {
        &mut self.provider
    }

    pub fn describe_capabilities(&self) -> TestRailCapabilityDescription {
        TestRailCapabilityDescription {
            layer: 1,
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            plugin_version: PLUGIN_VERSION,
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            api_revision: API_REVISION.to_owned(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            verified: false,
            transport_provenance: self.provider.transport_provenance(),
            allowed_operations: vec![
                "describe_capabilities".to_owned(),
                "get_run".to_owned(),
                "get_tests".to_owned(),
                "get_results_for_run".to_owned(),
                "compile_adoption_proposal".to_owned(),
                "record_adoption_proposal".to_owned(),
            ],
            forbidden_operations: vec![
                "add_result".to_owned(),
                "edit_result".to_owned(),
                "add_run".to_owned(),
                "update_test".to_owned(),
                "update_tests".to_owned(),
                "add_attachment".to_owned(),
                "export_raw".to_owned(),
                "dashboard".to_owned(),
                "outcome_adopt".to_owned(),
                "secret_resolve".to_owned(),
            ],
        }
    }

    pub fn read_result(&mut self) -> Result<TestRailResultProjection, TestRailError> {
        self.provider.read_result_projection()
    }

    pub fn read(&mut self) -> Result<TestRailResultProjection, TestRailError> {
        self.read_result()
    }

    pub fn compile_adoption_proposal(
        &mut self,
        projection: &TestRailResultProjection,
    ) -> Result<TestRailAdoptionProposal, TestRailError> {
        let consumer = MissionTestRailResultConsumer::from_registration(self.registration())?;
        let proposal = consumer.consume(projection, self.registration())?;
        if !self
            .proposal_fingerprints
            .insert(proposal.fingerprint().clone())
        {
            return Err(TestRailError::DuplicateProposal);
        }
        Ok(proposal)
    }

    pub fn compile_proposal(
        &mut self,
        projection: &TestRailResultProjection,
    ) -> Result<TestRailAdoptionProposal, TestRailError> {
        self.compile_adoption_proposal(projection)
    }

    pub fn propose_mission_result(
        &mut self,
        projection: &TestRailResultProjection,
    ) -> Result<TestRailAdoptionProposal, TestRailError> {
        self.compile_adoption_proposal(projection)
    }

    pub fn read_and_propose(
        &mut self,
    ) -> Result<(TestRailResultProjection, TestRailAdoptionProposal), TestRailError> {
        let projection = self.read_result()?;
        let proposal = self.compile_adoption_proposal(&projection)?;
        Ok((projection, proposal))
    }

    pub fn record_adoption_proposal(
        &self,
        log: &mut TestRailRecordingLog,
        proposal: &TestRailAdoptionProposal,
    ) -> Result<TestRailRecordingReceipt, TestRailError> {
        let consumer = MissionTestRailResultConsumer::from_registration(self.registration())?;
        consumer.record(log, proposal)
    }

    pub fn record_proposal(
        &self,
        log: &mut TestRailRecordingLog,
        proposal: &TestRailAdoptionProposal,
    ) -> Result<TestRailRecordingReceipt, TestRailError> {
        self.record_adoption_proposal(log, proposal)
    }

    pub fn registration_digest(&self) -> &Digest {
        self.registration().registration_digest()
    }
    pub fn contract_digest(&self) -> Digest {
        contract_digest()
    }
    pub fn provenance(&self) -> TransportProvenance {
        self.provider.transport_provenance()
    }
}

impl<T: TestRailTransport> fmt::Debug for TestRailTestResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestRailTestResultService")
            .field(
                "registration_digest",
                self.registration().registration_digest(),
            )
            .field("provider", &self.provider)
            .field("proposal_count", &self.proposal_fingerprints.len())
            .finish()
    }
}

pub type TestRailService<T> = TestRailTestResultService<T>;
pub type TestRailProviderIdentity = ProviderIdentity;
