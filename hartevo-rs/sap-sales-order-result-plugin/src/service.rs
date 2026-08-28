use serde::Serialize;
use thiserror::Error;

use crate::{
    SAP_SALES_ORDER_RESULT_CONTRACT_JSON, SAP_SALES_ORDER_RESULT_CONTRACT_VERSION,
    SAP_SALES_ORDER_RESULT_PLUGIN_VERSION, SAP_SALES_ORDER_RESULT_PROVIDER_ID,
    SAP_SALES_ORDER_RESULT_SERVICE_ID,
    model::{
        Digest, ModelError, RevisionFence, SapObservationState, SapSalesOrderEvidence,
        SapSalesOrderObservation,
    },
    provider::{
        ProviderDefinitionError, SapODataRequest, SapODataTransport, SapProviderError,
        SapS4HanaProvider,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SapSalesOrderOperation {
    ReadHeader,
    ReadItems,
    ReadDocumentFlow,
    ProposeAdoption,
    RecordRedactedEvidence,
}

impl SapSalesOrderOperation {
    pub const ALL: [Self; 5] = [
        Self::ReadHeader,
        Self::ReadItems,
        Self::ReadDocumentFlow,
        Self::ProposeAdoption,
        Self::RecordRedactedEvidence,
    ];

    pub const fn is_mutation(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SapSalesOrderServiceDefinition {
    pub id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub operations: Vec<SapSalesOrderOperation>,
}

impl SapSalesOrderServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            id: SAP_SALES_ORDER_RESULT_SERVICE_ID.to_owned(),
            plugin_version: SAP_SALES_ORDER_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: SAP_SALES_ORDER_RESULT_CONTRACT_VERSION.to_owned(),
            read_only: true,
            live_execution: false,
            native: false,
            connected: false,
            first_party: false,
            operations: SapSalesOrderOperation::ALL.to_vec(),
        }
    }

    pub fn validate(&self) -> Result<(), SapSalesOrderServiceError> {
        if self.id != SAP_SALES_ORDER_RESULT_SERVICE_ID
            || self.plugin_version != SAP_SALES_ORDER_RESULT_PLUGIN_VERSION
            || self.contract_version != SAP_SALES_ORDER_RESULT_CONTRACT_VERSION
            || !self.read_only
            || self.live_execution
            || self.native
            || self.connected
            || self.first_party
            || self
                .operations
                .iter()
                .any(|operation| operation.is_mutation())
        {
            return Err(SapSalesOrderServiceError::InvalidDefinition);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(serde_json::to_vec(self).expect("SAP service definition is serializable"))
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SapSalesOrderServiceError {
    #[error("SAP sales-order service definition is invalid")]
    InvalidDefinition,
    #[error("SAP contract or provider scope digest is stale or tampered")]
    DigestMismatch,
    #[error("SAP result is outside the registered scope")]
    ScopeMismatch,
    #[error("SAP observation is malformed")]
    InvalidObservation,
    #[error(transparent)]
    Provider(#[from] SapProviderError),
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    ProviderDefinition(#[from] ProviderDefinitionError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SapSalesOrderReadProposal {
    pub service_id: String,
    pub provider_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub service_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub implementation_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub revision_fence: RevisionFence,
    pub entity_sets: Vec<crate::model::SapEntitySet>,
    pub query_digests: Vec<Digest>,
    pub read_only: bool,
    pub external_write: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub proposal_digest: Digest,
}

impl SapSalesOrderReadProposal {
    pub fn validate(&self) -> Result<(), SapSalesOrderServiceError> {
        if self.service_id != SAP_SALES_ORDER_RESULT_SERVICE_ID
            || self.provider_id != SAP_SALES_ORDER_RESULT_PROVIDER_ID
            || self.plugin_version != SAP_SALES_ORDER_RESULT_PLUGIN_VERSION
            || self.contract_version != SAP_SALES_ORDER_RESULT_CONTRACT_VERSION
            || !self.read_only
            || self.external_write
            || self.connected
            || self.native
            || self.first_party
            || self.entity_sets.is_empty()
            || self.query_digests.len() != self.entity_sets.len()
            || self.proposal_digest.as_str().is_empty()
        {
            return Err(SapSalesOrderServiceError::InvalidObservation);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SapSalesOrderRecording {
    pub observation_digest: Digest,
    pub result_digest: Option<Digest>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub state: SapObservationState,
    pub redacted_field_count: usize,
    pub contains_raw_partner_data: bool,
    pub durable_native_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub recording_digest: Digest,
}

impl SapSalesOrderRecording {
    pub fn validate(&self) -> Result<(), SapSalesOrderServiceError> {
        if self.contains_raw_partner_data
            || self.durable_native_receipt
            || self.connected
            || self.native
            || self.first_party
            || self.recording_digest.as_str().is_empty()
        {
            return Err(SapSalesOrderServiceError::InvalidObservation);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.recording_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SapSalesOrderAdoptionProposal {
    pub observation_digest: Digest,
    pub result_digest: Option<Digest>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub state: SapObservationState,
    pub revision_fence: RevisionFence,
    pub non_mutating: bool,
    pub below_kernel_authority: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub independent_read_back: bool,
    pub kernel_outcome_adoption: bool,
    pub proposal_digest: Digest,
}

impl SapSalesOrderAdoptionProposal {
    pub fn validate(&self) -> Result<(), SapSalesOrderServiceError> {
        if !self.non_mutating
            || !self.below_kernel_authority
            || self.connected
            || self.native
            || self.first_party
            || self.independent_read_back
            || self.kernel_outcome_adoption
            || self.proposal_digest.as_str().is_empty()
        {
            return Err(SapSalesOrderServiceError::InvalidObservation);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SapSalesOrderRun {
    pub read_proposal: SapSalesOrderReadProposal,
    pub observation: SapSalesOrderObservation,
    pub recording: SapSalesOrderRecording,
    pub adoption_proposal: SapSalesOrderAdoptionProposal,
}

#[derive(Clone, Debug)]
pub struct SapSalesOrderResultService {
    definition: SapSalesOrderServiceDefinition,
}

impl Default for SapSalesOrderResultService {
    fn default() -> Self {
        Self::new()
    }
}

impl SapSalesOrderResultService {
    pub fn new() -> Self {
        Self {
            definition: SapSalesOrderServiceDefinition::layer1(),
        }
    }

    pub fn definition(&self) -> &SapSalesOrderServiceDefinition {
        &self.definition
    }

    pub fn service_id(&self) -> &str {
        &self.definition.id
    }

    pub fn contract_version(&self) -> &str {
        &self.definition.contract_version
    }

    pub fn plugin_version(&self) -> &str {
        &self.definition.plugin_version
    }

    pub const fn read_only(&self) -> bool {
        true
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }

    pub fn contract_json(&self) -> &'static str {
        SAP_SALES_ORDER_RESULT_CONTRACT_JSON
    }

    pub fn contract_digest(&self) -> Digest {
        Digest::from_text(SAP_SALES_ORDER_RESULT_CONTRACT_JSON)
    }

    pub fn validate(&self) -> Result<(), SapSalesOrderServiceError> {
        self.definition.validate()
    }

    pub fn propose_read<T: SapODataTransport>(
        &self,
        provider: &SapS4HanaProvider<T>,
    ) -> Result<SapSalesOrderReadProposal, SapSalesOrderServiceError> {
        self.validate()?;
        provider.definition().validate()?;
        provider.scope().validate()?;
        if !provider.is_registered() {
            return Err(SapSalesOrderServiceError::Provider(
                SapProviderError::RegistrationRevoked,
            ));
        }
        let mut query_digests = Vec::new();
        for entity_set in provider.scope().entity_sets() {
            query_digests.push(
                SapODataRequest::for_scope(provider.scope(), *entity_set, 0)?
                    .digest()
                    .clone(),
            );
        }
        let contract_digest = self.contract_digest();
        let provider_digest = provider.definition().digest();
        let implementation_digest = provider.registration().implementation_digest().clone();
        let proposal_digest = Digest::from_parts(
            "sap-sales-order-read-proposal/v1",
            [
                self.definition.digest().as_str().to_owned(),
                contract_digest.as_str().to_owned(),
                provider_digest.as_str().to_owned(),
                implementation_digest.as_str().to_owned(),
                provider
                    .registration()
                    .permission_digest()
                    .as_str()
                    .to_owned(),
                provider.registration().scope_digest().as_str().to_owned(),
                provider
                    .registration()
                    .registration_digest()
                    .as_str()
                    .to_owned(),
                query_digests
                    .iter()
                    .map(|digest| digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        );
        let proposal = SapSalesOrderReadProposal {
            service_id: self.definition.id.clone(),
            provider_id: provider.definition().id.clone(),
            plugin_version: self.definition.plugin_version.clone(),
            contract_version: self.definition.contract_version.clone(),
            service_digest: self.definition.digest(),
            contract_digest,
            provider_digest,
            implementation_digest,
            permission_digest: provider.registration().permission_digest().clone(),
            scope_digest: provider.registration().scope_digest().clone(),
            registration_digest: provider.registration().registration_digest().clone(),
            revision_fence: provider.scope().revision_fence(),
            entity_sets: provider.scope().entity_sets().iter().copied().collect(),
            query_digests,
            read_only: true,
            external_write: false,
            connected: false,
            native: false,
            first_party: false,
            proposal_digest,
        };
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn propose<T: SapODataTransport>(
        &self,
        provider: &SapS4HanaProvider<T>,
    ) -> Result<SapSalesOrderReadProposal, SapSalesOrderServiceError> {
        self.propose_read(provider)
    }

    pub fn read<T: SapODataTransport>(
        &self,
        provider: &mut SapS4HanaProvider<T>,
    ) -> Result<SapSalesOrderEvidence, SapSalesOrderServiceError> {
        self.validate()?;
        let evidence = provider.read_sales_order()?;
        Self::validate_evidence(provider, &evidence)?;
        Ok(evidence)
    }

    pub fn read_result<T: SapODataTransport>(
        &self,
        provider: &mut SapS4HanaProvider<T>,
    ) -> Result<SapSalesOrderEvidence, SapSalesOrderServiceError> {
        self.read(provider)
    }

    pub fn observe<T: SapODataTransport>(
        &self,
        provider: &mut SapS4HanaProvider<T>,
    ) -> Result<SapSalesOrderObservation, SapSalesOrderServiceError> {
        self.validate()?;
        let observation = provider.read_observation();
        Self::validate_observation(provider, &observation)?;
        Ok(observation)
    }

    pub fn record(
        &self,
        observation: &SapSalesOrderObservation,
    ) -> Result<SapSalesOrderRecording, SapSalesOrderServiceError> {
        self.validate()?;
        Self::validate_observation_shape(observation)?;
        let redacted_field_count = observation
            .evidence
            .as_ref()
            .map_or(0, |evidence| evidence.redaction.count());
        let result_digest = observation
            .evidence
            .as_ref()
            .map(|evidence| evidence.result_digest.clone());
        let recording_digest = Digest::from_parts(
            "sap-sales-order-recording/v1",
            [
                observation.observation_digest.as_str().to_owned(),
                result_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
                observation.scope_digest.as_str().to_owned(),
                observation.permission_digest.as_str().to_owned(),
                observation.registration_digest.as_str().to_owned(),
                format!("{:?}", observation.state),
                redacted_field_count.to_string(),
            ],
        );
        let recording = SapSalesOrderRecording {
            observation_digest: observation.observation_digest.clone(),
            result_digest,
            scope_digest: observation.scope_digest.clone(),
            permission_digest: observation.permission_digest.clone(),
            registration_digest: observation.registration_digest.clone(),
            state: observation.state,
            redacted_field_count,
            contains_raw_partner_data: false,
            durable_native_receipt: false,
            connected: false,
            native: false,
            first_party: false,
            recording_digest,
        };
        recording.validate()?;
        Ok(recording)
    }

    pub fn record_redacted(
        &self,
        observation: &SapSalesOrderObservation,
    ) -> Result<SapSalesOrderRecording, SapSalesOrderServiceError> {
        self.record(observation)
    }

    pub fn propose_adoption(
        &self,
        observation: &SapSalesOrderObservation,
    ) -> Result<SapSalesOrderAdoptionProposal, SapSalesOrderServiceError> {
        self.validate()?;
        Self::validate_observation_shape(observation)?;
        let result_digest = observation
            .evidence
            .as_ref()
            .map(|evidence| evidence.result_digest.clone());
        let proposal_digest = Digest::from_parts(
            "sap-sales-order-adoption-proposal/v1",
            [
                observation.observation_digest.as_str().to_owned(),
                result_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
                observation.scope_digest.as_str().to_owned(),
                observation.permission_digest.as_str().to_owned(),
                observation.registration_digest.as_str().to_owned(),
                format!("{:?}", observation.state),
                observation
                    .revision_fence
                    .scope_digest()
                    .as_str()
                    .to_owned(),
            ],
        );
        let proposal = SapSalesOrderAdoptionProposal {
            observation_digest: observation.observation_digest.clone(),
            result_digest,
            scope_digest: observation.scope_digest.clone(),
            permission_digest: observation.permission_digest.clone(),
            registration_digest: observation.registration_digest.clone(),
            state: observation.state,
            revision_fence: observation.revision_fence.clone(),
            non_mutating: true,
            below_kernel_authority: true,
            connected: false,
            native: false,
            first_party: false,
            independent_read_back: false,
            kernel_outcome_adoption: false,
            proposal_digest,
        };
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn adoption_proposal(
        &self,
        observation: &SapSalesOrderObservation,
    ) -> Result<SapSalesOrderAdoptionProposal, SapSalesOrderServiceError> {
        self.propose_adoption(observation)
    }

    pub fn run<T: SapODataTransport>(
        &self,
        provider: &mut SapS4HanaProvider<T>,
    ) -> Result<SapSalesOrderRun, SapSalesOrderServiceError> {
        let read_proposal = self.propose_read(provider)?;
        let observation = self.observe(provider)?;
        let recording = self.record(&observation)?;
        let adoption_proposal = self.propose_adoption(&observation)?;
        Ok(SapSalesOrderRun {
            read_proposal,
            observation,
            recording,
            adoption_proposal,
        })
    }

    fn validate_evidence<T: SapODataTransport>(
        provider: &SapS4HanaProvider<T>,
        evidence: &SapSalesOrderEvidence,
    ) -> Result<(), SapSalesOrderServiceError> {
        if evidence.scope_digest != *provider.scope().scope_digest()
            || evidence.permission_digest != *provider.scope().permission_lease().digest()
            || evidence.registration_digest != *provider.registration().registration_digest()
            || evidence.connected()
            || evidence.native()
            || evidence.first_party()
            || evidence.durable_native_receipt()
            || evidence.independent_read_back()
            || evidence.kernel_outcome_adoption()
            || !evidence.revision_fence.matches(
                &provider
                    .scope()
                    .revision_fence()
                    .with_source(evidence.source_revision, evidence.etag.clone()),
            )
        {
            return Err(SapSalesOrderServiceError::DigestMismatch);
        }
        Ok(())
    }

    fn validate_observation<T: SapODataTransport>(
        provider: &SapS4HanaProvider<T>,
        observation: &SapSalesOrderObservation,
    ) -> Result<(), SapSalesOrderServiceError> {
        Self::validate_observation_shape(observation)?;
        if observation.scope_digest != *provider.scope().scope_digest()
            || observation.permission_digest != *provider.scope().permission_lease().digest()
            || observation.registration_digest != *provider.registration().registration_digest()
            || observation.provenance.is_connected()
            || observation.provenance.is_native()
            || observation.provenance.is_first_party()
            || !observation
                .revision_fence
                .scope_digest()
                .eq(provider.scope().scope_digest())
        {
            return Err(SapSalesOrderServiceError::DigestMismatch);
        }
        if let Some(evidence) = &observation.evidence {
            Self::validate_evidence(provider, evidence)?;
        }
        Ok(())
    }

    fn validate_observation_shape(
        observation: &SapSalesOrderObservation,
    ) -> Result<(), SapSalesOrderServiceError> {
        if observation.connected()
            || observation.native()
            || observation.first_party()
            || observation.evidence.is_some() == observation.error.is_some()
            || observation.revision_fence.scope_digest() != &observation.scope_digest
        {
            return Err(SapSalesOrderServiceError::InvalidObservation);
        }
        Ok(())
    }
}
