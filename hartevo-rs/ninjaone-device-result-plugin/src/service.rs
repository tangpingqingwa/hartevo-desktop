//! Typed service, capability description, proposal, and recording seam.

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::model::{
    Digest, NinjaOneDeviceResultEvidence, NinjaOneDeviceResultProposal, NinjaOneError,
    NinjaOneRedactedRecording, NinjaOneRegistration, NinjaOneScope, PermissionLease,
    RegistrationTransition, SecretReference, TransportMode, Version,
};
use crate::provider::{NinjaOneProvider, NinjaOneProviderState};
use crate::transport::{NinjaOneTransport, RecordingNinjaOneTransport};
use crate::{
    CONTRACT_VERSION, IMPLEMENTATION_REVISION, NINJAONE_API_ORIGIN, NINJAONE_API_REVISION,
    PLUGIN_ID, PROVIDER_ID, PROVIDER_NAME, SERVICE_ID, SERVICE_NAME,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneServiceDefinition {
    pub service_id: String,
    pub implementation: String,
    pub contract_version: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub external_writes: bool,
    pub endpoint_control_authority: bool,
    pub kernel_authority: bool,
}

impl NinjaOneServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            service_id: SERVICE_ID.to_owned(),
            implementation: SERVICE_NAME.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            read_only: true,
            proposal_only: true,
            external_writes: false,
            endpoint_control_authority: false,
            kernel_authority: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.implementation != SERVICE_NAME
            || self.contract_version != CONTRACT_VERSION
            || !self.read_only
            || !self.proposal_only
            || self.external_writes
            || self.endpoint_control_authority
            || self.kernel_authority
        {
            return Err(NinjaOneError::MalformedContract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneProviderDefinition {
    pub provider_id: String,
    pub implementation: String,
    pub api_origin: String,
    pub api_revision: String,
    pub method: String,
    pub transport_modes: Vec<TransportMode>,
    pub connected: bool,
    pub native: bool,
    pub live_transport: bool,
    pub required_oauth_access: Vec<String>,
}

impl NinjaOneProviderDefinition {
    pub fn layer1() -> Self {
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            implementation: PROVIDER_NAME.to_owned(),
            api_origin: NINJAONE_API_ORIGIN.to_owned(),
            api_revision: NINJAONE_API_REVISION.to_owned(),
            method: "GET".to_owned(),
            transport_modes: vec![
                TransportMode::Fixture,
                TransportMode::Recording,
                TransportMode::Loopback,
                TransportMode::BlockedEnv,
            ],
            connected: false,
            native: false,
            live_transport: false,
            required_oauth_access: vec!["Monitoring".to_owned()],
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.implementation != PROVIDER_NAME
            || self.api_origin != NINJAONE_API_ORIGIN
            || self.api_revision != NINJAONE_API_REVISION
            || self.method != "GET"
            || self.connected
            || self.native
            || self.live_transport
            || self.transport_modes
                != vec![
                    TransportMode::Fixture,
                    TransportMode::Recording,
                    TransportMode::Loopback,
                    TransportMode::BlockedEnv,
                ]
        {
            return Err(NinjaOneError::MalformedContract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionNinjaOneDeviceConsumerDefinition {
    pub consumer_id: String,
    pub implementation: String,
    pub exact_scope: String,
    pub mutates_external_state: bool,
    pub adopts_work_product: bool,
    pub adopts_outcome: bool,
    pub kernel_authority: bool,
}

impl MissionNinjaOneDeviceConsumerDefinition {
    pub fn layer1() -> Self {
        Self {
            consumer_id: crate::CONSUMER_ID.to_owned(),
            implementation: crate::CONSUMER_NAME.to_owned(),
            exact_scope: "organization_site_device_agent_alert_patch_health_activity_mission_project_consent_revisions".to_owned(),
            mutates_external_state: false,
            adopts_work_product: false,
            adopts_outcome: false,
            kernel_authority: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.consumer_id != crate::CONSUMER_ID
            || self.implementation != crate::CONSUMER_NAME
            || self.mutates_external_state
            || self.adopts_work_product
            || self.adopts_outcome
            || self.kernel_authority
        {
            return Err(NinjaOneError::MalformedContract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneCapabilityDescription {
    pub plugin_id: String,
    pub version: Version,
    pub implementation_revision: String,
    pub service: NinjaOneServiceDefinition,
    pub provider: NinjaOneProviderDefinition,
    pub consumer: MissionNinjaOneDeviceConsumerDefinition,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub endpoint_control_authority: bool,
}

impl NinjaOneCapabilityDescription {
    pub fn validate(&self) -> Result<()> {
        self.service.validate()?;
        self.provider.validate()?;
        self.consumer.validate()?;
        if self.plugin_id != PLUGIN_ID
            || self.implementation_revision != IMPLEMENTATION_REVISION
            || self.connected
            || self.native
            || self.endpoint_control_authority
        {
            return Err(NinjaOneError::MalformedContract);
        }
        Ok(())
    }
}

/// Standalone Layer-1 service. The exact scope is retained in the service,
/// while the provider retains only its scope digest and a bound clone after
/// first use.
pub struct NinjaOneDeviceResultService<T: NinjaOneTransport = RecordingNinjaOneTransport> {
    provider: NinjaOneProvider<T>,
    scope: NinjaOneScope,
    definition: NinjaOneServiceDefinition,
}

impl<T: NinjaOneTransport> std::fmt::Debug for NinjaOneDeviceResultService<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NinjaOneDeviceResultService")
            .field("provider", &self.provider)
            .field("scope", &self.scope)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: NinjaOneTransport> NinjaOneDeviceResultService<T> {
    pub fn new(mut provider: NinjaOneProvider<T>, scope: NinjaOneScope) -> Result<Self> {
        provider.bind_scope(scope.clone())?;
        let definition = NinjaOneServiceDefinition::layer1();
        definition.validate()?;
        Ok(Self {
            provider,
            scope,
            definition,
        })
    }

    pub fn from_provider(provider: NinjaOneProvider<T>, scope: NinjaOneScope) -> Result<Self> {
        Self::new(provider, scope)
    }

    pub fn definition(&self) -> &NinjaOneServiceDefinition {
        &self.definition
    }

    pub fn describe_capabilities(&self) -> Result<NinjaOneCapabilityDescription> {
        let description = NinjaOneCapabilityDescription {
            plugin_id: PLUGIN_ID.to_owned(),
            version: crate::PLUGIN_VERSION,
            implementation_revision: IMPLEMENTATION_REVISION.to_owned(),
            service: self.definition.clone(),
            provider: NinjaOneProviderDefinition::layer1(),
            consumer: MissionNinjaOneDeviceConsumerDefinition::layer1(),
            contract_digest: crate::contract_digest(),
            provider_digest: crate::provider_digest(),
            registration_digest: self.provider.registration().registration_digest().clone(),
            connected: false,
            native: false,
            endpoint_control_authority: false,
        };
        description.validate()?;
        Ok(description)
    }

    pub fn provider(&self) -> &NinjaOneProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut NinjaOneProvider<T> {
        &mut self.provider
    }

    pub fn scope(&self) -> &NinjaOneScope {
        &self.scope
    }

    pub fn registration(&self) -> &NinjaOneRegistration {
        self.provider.registration()
    }

    pub fn secret_reference(&self) -> &SecretReference {
        self.provider.registration().secret_reference()
    }

    pub const fn provider_state(&self) -> NinjaOneProviderState {
        self.provider.provider_state()
    }

    pub fn read_device_result(&mut self) -> Result<NinjaOneDeviceResultEvidence> {
        self.provider.read_device_result(&self.scope)
    }

    pub fn compile_device_result_proposal(
        &self,
        evidence: &NinjaOneDeviceResultEvidence,
    ) -> Result<NinjaOneDeviceResultProposal> {
        NinjaOneDeviceResultProposal::new(evidence, &self.scope, self.registration())
    }

    pub fn record_device_result(
        &self,
        evidence: &NinjaOneDeviceResultEvidence,
    ) -> Result<NinjaOneRedactedRecording> {
        evidence.verify_integrity()?;
        if evidence.scope_digest != *self.scope.scope_digest()
            || evidence.registration_digest != *self.registration().registration_digest()
        {
            return Err(NinjaOneError::ProviderScopeMismatch);
        }
        Ok(NinjaOneRedactedRecording::from_evidence(
            evidence,
            self.registration(),
        ))
    }

    pub fn verify_device_result(
        &self,
        proposal: &NinjaOneDeviceResultProposal,
        evidence: &NinjaOneDeviceResultEvidence,
    ) -> Result<NinjaOneDeviceResultProposal> {
        proposal.validate_against(evidence, &self.scope, self.registration())?;
        Ok(proposal.clone())
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransition> {
        self.provider.unmount()
    }

    pub fn remount(&mut self) -> Result<RegistrationTransition> {
        self.provider.remount()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition> {
        self.provider.revoke()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransition> {
        self.provider.reverse()
    }
}

impl NinjaOneDeviceResultService<RecordingNinjaOneTransport> {
    pub fn register(
        scope: NinjaOneScope,
        lease: PermissionLease,
        secret: SecretReference,
        responses: impl IntoIterator<Item = (crate::NinjaOneEndpoint, crate::NinjaOneResponse)>,
        registration_revision: u64,
    ) -> Result<Self> {
        let provider =
            NinjaOneProvider::recording(&scope, &lease, secret, responses, registration_revision)?;
        Self::new(provider, scope)
    }
}
