use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};

use serde::Serialize;
use thiserror::Error;

use crate::{
    CONSUMER_ID, CONTRACT_VERSION, PLUGIN_ID, PROVIDER_ID, PluginVersion, SERVICE_ID,
    canonical::digest_serializable,
    contract_digest,
    types::{Digest, MissionScope, TypeError},
};

const SERVICE_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
const PROVIDER_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
const CONSUMER_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
const ACTIVE: u8 = 1;
const REVOKED: u8 = 2;

/// Registration lifecycle state shared by the service, provider, and Mission
/// consumer handles.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

/// Registration failures are fail-closed and scope-specific.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("registration is revoked")]
    Revoked,
    #[error("registration was already revoked")]
    AlreadyRevoked,
    #[error("registration scope does not match the requested Mission scope")]
    ScopeMismatch,
    #[error("registration digest is invalid")]
    InvalidDigest,
    #[error("registration input is invalid: {0}")]
    InvalidInput(#[from] TypeError),
}

/// Versioned, digest-bound, exact-scope registration for all three plugin
/// planes. Lifecycle state is shared between cheap clones.
pub struct ElevenLabsAudioResultRegistration {
    scope: MissionScope,
    service_version: PluginVersion,
    provider_version: PluginVersion,
    consumer_version: PluginVersion,
    contract_version: String,
    contract_digest: Digest,
    implementation_digest: Digest,
    registration_digest: Digest,
    state: Arc<AtomicU8>,
}

impl ElevenLabsAudioResultRegistration {
    pub fn register(
        scope: MissionScope,
        implementation_digest: Digest,
    ) -> Result<Self, RegistrationError> {
        if !implementation_digest.is_valid() {
            return Err(RegistrationError::InvalidDigest);
        }
        let contract_digest = contract_digest();
        let registration_digest = digest_serializable(&RegistrationBindingMaterial {
            plugin_id: PLUGIN_ID,
            service_id: SERVICE_ID,
            provider_id: PROVIDER_ID,
            consumer_id: CONSUMER_ID,
            service_version: SERVICE_VERSION,
            provider_version: PROVIDER_VERSION,
            consumer_version: CONSUMER_VERSION,
            contract_version: CONTRACT_VERSION,
            contract_digest: contract_digest.clone(),
            implementation_digest: implementation_digest.clone(),
            scope: scope.clone(),
        });
        Ok(Self {
            scope,
            service_version: SERVICE_VERSION,
            provider_version: PROVIDER_VERSION,
            consumer_version: CONSUMER_VERSION,
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest,
            implementation_digest,
            registration_digest,
            state: Arc::new(AtomicU8::new(ACTIVE)),
        })
    }

    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub const fn service_version(&self) -> PluginVersion {
        self.service_version
    }

    pub const fn provider_version(&self) -> PluginVersion {
        self.provider_version
    }

    pub const fn consumer_version(&self) -> PluginVersion {
        self.consumer_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn verify_digest(&self) -> bool {
        digest_serializable(&RegistrationBindingMaterial {
            plugin_id: PLUGIN_ID,
            service_id: SERVICE_ID,
            provider_id: PROVIDER_ID,
            consumer_id: CONSUMER_ID,
            service_version: self.service_version,
            provider_version: self.provider_version,
            consumer_version: self.consumer_version,
            contract_version: CONTRACT_VERSION,
            contract_digest: self.contract_digest.clone(),
            implementation_digest: self.implementation_digest.clone(),
            scope: self.scope.clone(),
        }) == self.registration_digest
    }

    pub fn state(&self) -> RegistrationState {
        if self.state.load(Ordering::Acquire) == ACTIVE {
            RegistrationState::Active
        } else {
            RegistrationState::Revoked
        }
    }

    pub fn is_active(&self) -> bool {
        self.state() == RegistrationState::Active
    }

    pub fn receipt(&self) -> RegistrationReceipt {
        RegistrationReceipt {
            scope: self.scope.clone(),
            service_version: self.service_version,
            provider_version: self.provider_version,
            consumer_version: self.consumer_version,
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            implementation_digest: self.implementation_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            state: self.state(),
        }
    }

    pub fn ensure_active(&self) -> Result<(), RegistrationError> {
        if self.is_active() {
            Ok(())
        } else {
            Err(RegistrationError::Revoked)
        }
    }

    pub fn ensure_scope(&self, scope: &MissionScope) -> Result<(), RegistrationError> {
        if self.scope == *scope {
            Ok(())
        } else {
            Err(RegistrationError::ScopeMismatch)
        }
    }

    pub fn revoke(&self) -> Result<RevocationReceipt, RegistrationError> {
        self.state
            .compare_exchange(ACTIVE, REVOKED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RegistrationError::AlreadyRevoked)?;
        Ok(RevocationReceipt {
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope.digest(),
            revocation_epoch: 1,
        })
    }
}

impl Clone for ElevenLabsAudioResultRegistration {
    fn clone(&self) -> Self {
        Self {
            scope: self.scope.clone(),
            service_version: self.service_version,
            provider_version: self.provider_version,
            consumer_version: self.consumer_version,
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            implementation_digest: self.implementation_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            state: Arc::clone(&self.state),
        }
    }
}

impl fmt::Debug for ElevenLabsAudioResultRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ElevenLabsAudioResultRegistration")
            .field("scope_digest", &self.scope.digest())
            .field("registration_digest", &self.registration_digest)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

/// Immutable registration evidence for the typed service/provider/consumer
/// bundle.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationReceipt {
    scope: MissionScope,
    service_version: PluginVersion,
    provider_version: PluginVersion,
    consumer_version: PluginVersion,
    contract_version: String,
    contract_digest: Digest,
    implementation_digest: Digest,
    registration_digest: Digest,
    state: RegistrationState,
}

impl RegistrationReceipt {
    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }

    pub const fn service_version(&self) -> PluginVersion {
        self.service_version
    }

    pub const fn provider_version(&self) -> PluginVersion {
        self.provider_version
    }

    pub const fn consumer_version(&self) -> PluginVersion {
        self.consumer_version
    }

    pub fn verify_digest(&self) -> bool {
        digest_serializable(&RegistrationBindingMaterial {
            plugin_id: PLUGIN_ID,
            service_id: SERVICE_ID,
            provider_id: PROVIDER_ID,
            consumer_id: CONSUMER_ID,
            service_version: self.service_version,
            provider_version: self.provider_version,
            consumer_version: self.consumer_version,
            contract_version: CONTRACT_VERSION,
            contract_digest: self.contract_digest.clone(),
            implementation_digest: self.implementation_digest.clone(),
            scope: self.scope.clone(),
        }) == self.registration_digest
    }
}

/// Receipt proving that a registration was reversibly revoked.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationReceipt {
    registration_digest: Digest,
    scope_digest: Digest,
    revocation_epoch: u64,
}

impl RevocationReceipt {
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationBindingMaterial {
    plugin_id: &'static str,
    service_id: &'static str,
    provider_id: &'static str,
    consumer_id: &'static str,
    service_version: PluginVersion,
    provider_version: PluginVersion,
    consumer_version: PluginVersion,
    contract_version: &'static str,
    contract_digest: Digest,
    implementation_digest: Digest,
    scope: MissionScope,
}
