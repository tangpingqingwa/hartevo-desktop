use std::collections::BTreeMap;

use crate::digest::Digest;
use crate::error::{BedrockError, Result};
use crate::model::{BedrockScope, ModelCapabilitySnapshot, RegistrationId, SecretReference};
use crate::{
    BEDROCK_INFERENCE_CONTRACT_VERSION, BEDROCK_INFERENCE_PLUGIN_VERSION,
    bedrock_inference_contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RevocationReason {
    Manual,
    PolicyDrift,
    ScopeDrift,
    ProviderAccessChanged,
    CapabilityChanged,
}

impl RevocationReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::PolicyDrift => "policy_drift",
            Self::ScopeDrift => "scope_drift",
            Self::ProviderAccessChanged => "provider_access_changed",
            Self::CapabilityChanged => "capability_changed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RegistrationState {
    Active,
    Revoked { reason: RevocationReason },
}

pub type RegistrationStatus = RegistrationState;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RegistrationSpec {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    adapter_revision: u64,
    capability: ModelCapabilitySnapshot,
    scope: BedrockScope,
    secret_reference: SecretReference,
}

impl RegistrationSpec {
    pub fn new(
        scope: BedrockScope,
        capability: ModelCapabilitySnapshot,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        let spec = Self {
            plugin_version: BEDROCK_INFERENCE_PLUGIN_VERSION.to_owned(),
            contract_version: BEDROCK_INFERENCE_CONTRACT_VERSION.to_owned(),
            contract_digest: bedrock_inference_contract_digest(),
            adapter_revision: 1,
            capability,
            scope,
            secret_reference,
        };
        spec.validate()?;
        Ok(spec)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_metadata(
        plugin_version: impl Into<String>,
        contract_version: impl Into<String>,
        contract_digest: Digest,
        adapter_revision: u64,
        scope: BedrockScope,
        capability: ModelCapabilitySnapshot,
        secret_reference: SecretReference,
    ) -> Self {
        Self {
            plugin_version: plugin_version.into(),
            contract_version: contract_version.into(),
            contract_digest,
            adapter_revision,
            capability,
            scope,
            secret_reference,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.plugin_version != BEDROCK_INFERENCE_PLUGIN_VERSION {
            return Err(BedrockError::ContractVersionMismatch);
        }
        if self.contract_version != BEDROCK_INFERENCE_CONTRACT_VERSION {
            return Err(BedrockError::ContractVersionMismatch);
        }
        if self.contract_digest != bedrock_inference_contract_digest() {
            return Err(BedrockError::ContractDigestMismatch);
        }
        if self.adapter_revision == 0 {
            return Err(BedrockError::AdapterRevisionMismatch);
        }
        if self.capability.scope_digest() != self.scope.digest()
            || self.capability.target() != self.scope.model_or_inference_profile()
        {
            return Err(BedrockError::CapabilityScopeMismatch);
        }
        if self.secret_reference.is_expired_at(0) {
            return Err(BedrockError::SecretReferenceRejected);
        }
        Ok(())
    }

    pub fn validate_at(&self, epoch_seconds: u64) -> Result<()> {
        self.validate()?;
        if self.secret_reference.is_expired_at(epoch_seconds) {
            return Err(BedrockError::SecretReferenceRejected);
        }
        Ok(())
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub const fn contract_digest(&self) -> Digest {
        self.contract_digest
    }

    pub const fn adapter_revision(&self) -> u64 {
        self.adapter_revision
    }

    pub const fn capability(&self) -> &ModelCapabilitySnapshot {
        &self.capability
    }

    pub const fn scope(&self) -> &BedrockScope {
        &self.scope
    }

    pub const fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub(crate) fn canonical_for_generation(&self, generation: u64) -> String {
        format!(
            "plugin={};contract={};contract_digest={};adapter_revision={};capability={};scope={};secret_reference_digest={};generation={generation}",
            self.plugin_version,
            self.contract_version,
            self.contract_digest,
            self.adapter_revision,
            self.capability.digest(),
            self.scope.digest(),
            self.secret_reference.reference_digest()
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RegistrationRecord {
    id: RegistrationId,
    spec: RegistrationSpec,
    generation: u64,
    state: RegistrationState,
}

impl RegistrationRecord {
    pub const fn id(&self) -> RegistrationId {
        self.id
    }

    pub const fn spec(&self) -> &RegistrationSpec {
        &self.spec
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.state
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RegistrationRegistry {
    records: BTreeMap<RegistrationId, RegistrationRecord>,
}

impl RegistrationRegistry {
    pub fn register(&mut self, spec: RegistrationSpec) -> Result<RegistrationId> {
        spec.validate()?;
        let generation = 0;
        let id =
            RegistrationId::from_digest(Digest::of_str(&spec.canonical_for_generation(generation)));
        if self.records.contains_key(&id) {
            return Err(BedrockError::RegistrationAlreadyExists);
        }
        self.records.insert(
            id,
            RegistrationRecord {
                id,
                spec,
                generation,
                state: RegistrationState::Active,
            },
        );
        Ok(id)
    }

    pub fn get(&self, id: RegistrationId) -> Result<&RegistrationRecord> {
        self.records
            .get(&id)
            .ok_or(BedrockError::RegistrationNotFound)
    }

    pub fn validate_active(&self, id: RegistrationId) -> Result<&RegistrationRecord> {
        let record = self.get(id)?;
        if !record.is_active() {
            return Err(BedrockError::RegistrationRevoked);
        }
        Ok(record)
    }

    pub fn revoke(&mut self, id: RegistrationId, reason: RevocationReason) -> Result<()> {
        let record = self
            .records
            .get_mut(&id)
            .ok_or(BedrockError::RegistrationNotFound)?;
        if !record.is_active() {
            return Err(BedrockError::RegistrationInactive);
        }
        record.state = RegistrationState::Revoked { reason };
        Ok(())
    }

    /// Restore a revoked registration as a new generation and id. Old
    /// proposals retain the revoked id and therefore remain fail-closed.
    pub fn restore(&mut self, id: RegistrationId) -> Result<RegistrationId> {
        let record = self
            .records
            .get(&id)
            .ok_or(BedrockError::RegistrationNotFound)?
            .clone();
        if record.is_active() {
            return Err(BedrockError::CannotRestoreRegistration);
        }
        let generation = record.generation.saturating_add(1);
        let new_id = RegistrationId::from_digest(Digest::of_str(
            &record.spec.canonical_for_generation(generation),
        ));
        self.records.insert(
            new_id,
            RegistrationRecord {
                id: new_id,
                spec: record.spec,
                generation,
                state: RegistrationState::Active,
            },
        );
        Ok(new_id)
    }

    pub fn active_count(&self) -> usize {
        self.records
            .values()
            .filter(|record| record.is_active())
            .count()
    }

    pub fn records(&self) -> impl Iterator<Item = &RegistrationRecord> {
        self.records.values()
    }
}
