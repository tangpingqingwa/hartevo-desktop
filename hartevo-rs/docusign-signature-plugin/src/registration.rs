use std::fmt;

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginDefinitionHandle, PluginError, PluginId,
    PluginRuntime, PluginScope, PluginVersion, ProviderCardinality, ProviderDefinition, ProviderId,
    RegistrationReceipt as RuntimeRegistrationReceipt, ServiceDefinition, ServiceId,
};
use thiserror::Error;

use crate::{
    DOCUSIGN_SIGNATURE_CONTRACT_VERSION, DOCUSIGN_SIGNATURE_SERVICE_ID, Digest, DocuSignScope,
    ModelError, ProviderVersion, RevisionFence, contract_digest,
};

pub const DOCUSIGN_PLUGIN_ID: &str = "docusign.signature";
pub const DOCUSIGN_PROVIDER_DEFINITION_ID: &str = "docusign.signature.provider";
pub const MISSION_SIGNED_RESULT_CONSUMER_ID: &str = "mission.signed-result.consumer";
pub const DOCUSIGN_PLUGIN_VERSION: ProviderVersion = ProviderVersion::new(1, 0, 0);

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RegistrationError {
    #[error("DocuSign registration model is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("plugin runtime rejected DocuSign registration: {0}")]
    Runtime(#[from] PluginError),
    #[error("registration receipt is bound to another DocuSign scope or digest")]
    ReceiptMismatch,
}

#[derive(Clone)]
pub struct DocuSignPluginRegistration {
    definition: PluginDefinition,
    scope: DocuSignScope,
    revision_fence: RevisionFence,
    implementation_digest: Digest,
    registration_digest: Digest,
}

impl fmt::Debug for DocuSignPluginRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DocuSignPluginRegistration")
            .field("plugin_id", &DOCUSIGN_PLUGIN_ID)
            .field("version", &DOCUSIGN_PLUGIN_VERSION)
            .field("scope_digest", &self.scope.digest())
            .field("revision_fence", &self.revision_fence)
            .field("implementation_digest", &self.implementation_digest)
            .field("registration_digest", &self.registration_digest)
            .finish_non_exhaustive()
    }
}

impl DocuSignPluginRegistration {
    pub fn new(
        scope: DocuSignScope,
        revision_fence: RevisionFence,
        implementation_digest: Digest,
    ) -> Result<Self, RegistrationError> {
        scope.validate()?;
        revision_fence.validate()?;
        if !implementation_digest.is_valid() {
            return Err(RegistrationError::Model(ModelError::InvalidSourceDigest));
        }
        DOCUSIGN_PLUGIN_VERSION.validate()?;
        let runtime_scope = PluginScope::new(
            hartevo_plugin_runtime::ProjectId::new(scope.project_id().as_str())?,
            hartevo_plugin_runtime::MissionId::new(scope.mission_id().as_str())?,
            revision_fence.mission_revision(),
        )?;
        let contract_digest = contract_digest();
        let service_id = ServiceId::new(DOCUSIGN_SIGNATURE_SERVICE_ID)?;
        let provider_id = ProviderId::new(DOCUSIGN_PROVIDER_DEFINITION_ID)?;
        let consumer_id = ConsumerId::new(MISSION_SIGNED_RESULT_CONSUMER_ID)?;
        let runtime_version = PluginVersion::new(
            DOCUSIGN_PLUGIN_VERSION.major(),
            DOCUSIGN_PLUGIN_VERSION.minor(),
            DOCUSIGN_PLUGIN_VERSION.patch(),
        );
        let contributions = PluginContributions {
            services: vec![ServiceDefinition::read_only(
                service_id.clone(),
                runtime_version,
                RuntimeDigest::from_text(contract_digest.as_str()),
                ProviderCardinality::Singleton,
                CompatibilityPolicy::Exact,
            )?],
            providers: vec![ProviderDefinition::new(
                provider_id,
                service_id.clone(),
                runtime_version,
                RuntimeDigest::from_text(implementation_digest.as_str()),
            )?],
            consumers: vec![ConsumerDefinition::command(
                consumer_id,
                service_id,
                runtime_version,
                RuntimeDigest::from_text(
                    Digest::from_parts([
                        DOCUSIGN_SIGNATURE_CONTRACT_VERSION,
                        contract_digest.as_str(),
                        MISSION_SIGNED_RESULT_CONSUMER_ID,
                    ])
                    .to_string(),
                ),
            )?],
            events: Vec::new(),
            ui_surfaces: Vec::new(),
        };
        let definition = PluginDefinition::new(
            PluginId::new(DOCUSIGN_PLUGIN_ID)?,
            runtime_version,
            runtime_scope,
            contributions,
        )?;
        let mut registration_parts = vec![
            definition.digest().as_str().to_owned(),
            scope.digest().to_string(),
            revision_fence.digest().to_string(),
            implementation_digest.to_string(),
            DOCUSIGN_SIGNATURE_CONTRACT_VERSION.to_owned(),
        ];
        let registration_digest = Digest::from_parts(registration_parts.drain(..));
        Ok(Self {
            definition,
            scope,
            revision_fence,
            implementation_digest,
            registration_digest,
        })
    }

    pub fn definition(&self) -> &PluginDefinition {
        &self.definition
    }

    pub fn scope(&self) -> &DocuSignScope {
        &self.scope
    }

    pub const fn version(&self) -> ProviderVersion {
        DOCUSIGN_PLUGIN_VERSION
    }

    pub const fn revision_fence(&self) -> RevisionFence {
        self.revision_fence
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn register(
        &self,
        runtime: &mut PluginRuntime,
    ) -> Result<DocuSignRegistrationReceipt, RegistrationError> {
        let handle = runtime.define(self.definition.clone())?;
        let runtime_receipt = runtime.mount_in_scope(&handle, self.definition.scope())?;
        Ok(DocuSignRegistrationReceipt {
            plugin_digest: self.definition.digest().as_str().to_owned(),
            scope_digest: self.scope.digest(),
            version: DOCUSIGN_PLUGIN_VERSION,
            registration_digest: self.registration_digest.clone(),
            handle,
            runtime_receipt,
        })
    }

    pub fn unregister(
        &self,
        runtime: &mut PluginRuntime,
        receipt: &DocuSignRegistrationReceipt,
    ) -> Result<hartevo_plugin_runtime::UnmountReceipt, RegistrationError> {
        receipt.validate_for(self)?;
        Ok(runtime.unmount(&receipt.runtime_receipt)?)
    }

    pub fn revoke(
        &self,
        runtime: &mut PluginRuntime,
        receipt: &DocuSignRegistrationReceipt,
    ) -> Result<hartevo_plugin_runtime::RevocationReceipt, RegistrationError> {
        receipt.validate_for(self)?;
        Ok(runtime.revoke(&receipt.handle)?)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DocuSignRegistrationReceipt {
    plugin_digest: String,
    scope_digest: Digest,
    version: ProviderVersion,
    registration_digest: Digest,
    handle: PluginDefinitionHandle,
    runtime_receipt: RuntimeRegistrationReceipt,
}

impl fmt::Debug for DocuSignRegistrationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DocuSignRegistrationReceipt")
            .field("plugin_digest", &Digest::from_text(&self.plugin_digest))
            .field("scope_digest", &self.scope_digest)
            .field("version", &self.version)
            .field("registration_digest", &self.registration_digest)
            .field("runtime_receipt_digest", &self.runtime_receipt.digest())
            .finish_non_exhaustive()
    }
}

impl DocuSignRegistrationReceipt {
    pub fn plugin_digest(&self) -> &str {
        &self.plugin_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn version(&self) -> ProviderVersion {
        self.version
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn runtime_receipt(&self) -> &RuntimeRegistrationReceipt {
        &self.runtime_receipt
    }

    fn validate_for(
        &self,
        registration: &DocuSignPluginRegistration,
    ) -> Result<(), RegistrationError> {
        if self.plugin_digest != registration.definition.digest().as_str()
            || self.scope_digest != registration.scope.digest()
            || self.version != DOCUSIGN_PLUGIN_VERSION
            || self.registration_digest != registration.registration_digest
        {
            return Err(RegistrationError::ReceiptMismatch);
        }
        Ok(())
    }
}
