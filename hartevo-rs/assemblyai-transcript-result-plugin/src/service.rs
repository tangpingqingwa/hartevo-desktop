use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use serde::{Deserialize, Serialize, Serializer};

use crate::consumer::{
    MissionTranscriptResultConsumer, RecordedTranscriptProposal, TranscriptWorkProductProposal,
};
use crate::error::{AssemblyAiProviderError, AssemblyAiResultError};
use crate::model::{
    AssemblyAiPermissionSnapshot, AssemblyAiProviderIdentity, AssemblyAiScope, Digest,
    PluginVersion, RegistrationId, RegistrationReceipt, RegistrationState, SecretReference,
    TranscriptResultProjection, canonical_digest,
};
use crate::provider::{AssemblyAiCredentialResolver, AssemblyAiProvider};
use crate::{
    CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_API_REVISION,
    PROVIDER_ID, SERVICE_ID, contract_digest,
};

const ACTIVE: u8 = 1;
const REVOKED: u8 = 2;
const REVERSED: u8 = 3;

/// Version/contract/provider/permission/scope/secret-bound registration.
/// Lifecycle state is shared by service, provider, consumer, and registry
/// clones so revocation is immediately observable at every typed boundary.
#[derive(Clone)]
pub struct AssemblyAiRegistration {
    id: RegistrationId,
    plugin_version: PluginVersion,
    contract_version: String,
    contract_digest: Digest,
    provider: AssemblyAiProviderIdentity,
    permission_snapshot: AssemblyAiPermissionSnapshot,
    scope: AssemblyAiScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    state: Arc<AtomicU8>,
    binding_digest: Digest,
}

impl AssemblyAiRegistration {
    pub fn new(
        id: RegistrationId,
        scope: AssemblyAiScope,
        secret_reference: SecretReference,
        permission_snapshot: AssemblyAiPermissionSnapshot,
        provider: AssemblyAiProviderIdentity,
        registration_revision: u64,
    ) -> Result<Self, AssemblyAiResultError> {
        let scope_digest = scope.digest();
        let mut registration = Self {
            id,
            plugin_version: PLUGIN_VERSION,
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider,
            permission_snapshot,
            scope,
            scope_digest,
            secret_reference,
            registration_revision,
            state: Arc::new(AtomicU8::new(ACTIVE)),
            binding_digest: Digest::from_text("unsealed-assemblyai-registration"),
        };
        registration.binding_digest = registration.calculate_binding_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<(), AssemblyAiResultError> {
        self.id.validate()?;
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(AssemblyAiResultError::InvalidRegistration);
        }
        self.provider.validate()?;
        self.permission_snapshot.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate()?;
        if self.secret_reference.scope_digest() != &self.scope_digest
            || self.permission_snapshot.digest() != &self.scope.permission.digest
        {
            return Err(AssemblyAiResultError::InvalidRegistration);
        }
        Ok(())
    }

    #[must_use]
    pub fn id(&self) -> &RegistrationId {
        &self.id
    }

    #[must_use]
    pub const fn plugin_version(&self) -> PluginVersion {
        self.plugin_version
    }

    #[must_use]
    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    #[must_use]
    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    #[must_use]
    pub fn provider(&self) -> &AssemblyAiProviderIdentity {
        &self.provider
    }

    #[must_use]
    pub fn permission_snapshot(&self) -> &AssemblyAiPermissionSnapshot {
        &self.permission_snapshot
    }

    #[must_use]
    pub fn scope(&self) -> &AssemblyAiScope {
        &self.scope
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    /// Revoke the host-owned opaque API-key binding without exposing key
    /// material. Existing provider clones retain the same registration fence;
    /// new reads fail closed once this registration is passed through.
    pub fn revoke_secret_reference(&self) {
        self.secret_reference.revoke();
    }

    #[must_use]
    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    #[must_use]
    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    #[must_use]
    pub fn state(&self) -> RegistrationState {
        match self.state.load(Ordering::Acquire) {
            ACTIVE => RegistrationState::Active,
            REVOKED => RegistrationState::Revoked,
            _ => RegistrationState::Reversed,
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state() == RegistrationState::Active && !self.secret_reference.is_revoked()
    }

    pub fn ensure_active(&self) -> Result<(), AssemblyAiResultError> {
        match self.state() {
            RegistrationState::Active if !self.secret_reference.is_revoked() => Ok(()),
            RegistrationState::Active => Err(AssemblyAiResultError::SecretRevoked),
            RegistrationState::Revoked => Err(AssemblyAiResultError::RegistrationRevoked),
            RegistrationState::Reversed => Err(AssemblyAiResultError::RegistrationReversed),
        }
    }

    /// Revoke future reads while retaining the binding for audit.
    pub fn revoke(&self) -> Result<(), AssemblyAiResultError> {
        self.state
            .compare_exchange(ACTIVE, REVOKED, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|state| match state {
                REVERSED => AssemblyAiResultError::RegistrationReversed,
                _ => AssemblyAiResultError::RegistrationRevoked,
            })
    }

    /// Reverse/unmount the registration without deleting its evidence.
    pub fn reverse(&self) -> Result<(), AssemblyAiResultError> {
        self.state.store(REVERSED, Ordering::Release);
        Ok(())
    }

    pub fn restore(&self) -> Result<(), AssemblyAiResultError> {
        self.state
            .compare_exchange(REVOKED, ACTIVE, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|state| match state {
                REVERSED => AssemblyAiResultError::RegistrationReversed,
                _ => AssemblyAiResultError::InvalidRegistration,
            })
    }

    #[must_use]
    pub fn receipt(&self) -> RegistrationReceipt {
        RegistrationReceipt {
            registration_id: self.id.clone(),
            plugin_version: self.plugin_version,
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            provider: self.provider.clone(),
            permission_digest: self.permission_snapshot.digest().clone(),
            scope_digest: self.scope_digest.clone(),
            secret_reference_digest: self.secret_reference.reference_digest().clone(),
            secret_revision: self.secret_reference.revision(),
            registration_revision: self.registration_revision,
            binding_digest: self.binding_digest.clone(),
            state: self.state(),
        }
    }

    fn calculate_binding_digest(&self) -> Digest {
        canonical_digest(&(
            PLUGIN_ID,
            SERVICE_ID,
            PROVIDER_ID,
            self.id.as_str(),
            self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider,
            self.permission_snapshot.digest(),
            &self.scope_digest,
            self.secret_reference.reference_digest(),
            self.secret_reference.revision(),
            self.registration_revision,
        ))
    }
}

impl fmt::Debug for AssemblyAiRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssemblyAiRegistration")
            .field("id", &self.id)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider", &self.provider)
            .field("permission_digest", &self.permission_snapshot.digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("registration_revision", &self.registration_revision)
            .field("state", &self.state())
            .field("binding_digest", &self.binding_digest)
            .finish_non_exhaustive()
    }
}

impl Serialize for AssemblyAiRegistration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.receipt().serialize(serializer)
    }
}

/// Small in-memory registry with duplicate binding protection and reversible
/// lifecycle operations. It is not a persistent authority or durable store.
#[derive(Clone, Debug, Default)]
pub struct AssemblyAiRegistrationRegistry {
    registrations: BTreeMap<RegistrationId, AssemblyAiRegistration>,
    bindings: BTreeSet<Digest>,
}

impl AssemblyAiRegistrationRegistry {
    pub fn register(
        &mut self,
        registration: AssemblyAiRegistration,
    ) -> Result<(), AssemblyAiResultError> {
        registration.validate()?;
        if self.registrations.contains_key(registration.id())
            || self.bindings.contains(registration.binding_digest())
        {
            return Err(AssemblyAiResultError::RegistrationAlreadyExists);
        }
        self.bindings.insert(registration.binding_digest().clone());
        self.registrations
            .insert(registration.id().clone(), registration);
        Ok(())
    }

    pub fn get(
        &self,
        id: &RegistrationId,
    ) -> Result<&AssemblyAiRegistration, AssemblyAiResultError> {
        self.registrations
            .get(id)
            .ok_or(AssemblyAiResultError::RegistrationUnknown)
    }

    pub fn revoke(&self, id: &RegistrationId) -> Result<(), AssemblyAiResultError> {
        self.get(id)?.revoke()
    }

    pub fn reverse(&self, id: &RegistrationId) -> Result<(), AssemblyAiResultError> {
        self.get(id)?.reverse()
    }

    pub fn restore(&self, id: &RegistrationId) -> Result<(), AssemblyAiResultError> {
        self.get(id)?.restore()
    }
}

/// Descriptive Layer-1 capability boundary. False flags are intentional and
/// are independently checked by contract tests.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub contract_version: String,
    pub read_only: bool,
    pub can_read_transcript: bool,
    pub can_propose_work_product: bool,
    pub can_record_proposal: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub can_upload_audio: bool,
    pub can_fetch_arbitrary_media: bool,
    pub can_submit_transcript: bool,
    pub can_poll_transcript: bool,
    pub can_retain_raw_audio: bool,
    pub can_export_raw_transcript: bool,
    pub can_mutate_speaker_identity: bool,
    pub can_train_model: bool,
    pub can_adopt_work_product: bool,
    pub can_adopt_outcome: bool,
    pub external_write: bool,
    pub durable_provider_receipt: bool,
    pub independent_readback: bool,
}

impl CapabilityDescription {
    #[must_use]
    pub fn layer1() -> Self {
        Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            read_only: true,
            can_read_transcript: true,
            can_propose_work_product: true,
            can_record_proposal: true,
            connected: false,
            native: false,
            first_party: false,
            can_upload_audio: false,
            can_fetch_arbitrary_media: false,
            can_submit_transcript: false,
            can_poll_transcript: false,
            can_retain_raw_audio: false,
            can_export_raw_transcript: false,
            can_mutate_speaker_identity: false,
            can_train_model: false,
            can_adopt_work_product: false,
            can_adopt_outcome: false,
            external_write: false,
            durable_provider_receipt: false,
            independent_readback: false,
        }
    }
}

/// Typed service composing provider reads, Mission proposals, and bounded
/// in-memory recording. It never performs an external side effect.
#[derive(Clone, Debug)]
pub struct AssemblyAiTranscriptResultService {
    registration: AssemblyAiRegistration,
    proposal_fingerprints: BTreeSet<Digest>,
}

impl AssemblyAiTranscriptResultService {
    pub fn new(registration: AssemblyAiRegistration) -> Result<Self, AssemblyAiResultError> {
        registration.validate()?;
        registration.ensure_active()?;
        Ok(Self {
            registration,
            proposal_fingerprints: BTreeSet::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &AssemblyAiRegistration {
        &self.registration
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription::layer1()
    }

    pub fn read_transcript<T, R>(
        &self,
        provider: &mut AssemblyAiProvider<T, R>,
    ) -> Result<TranscriptResultProjection, AssemblyAiProviderError>
    where
        T: crate::transport::AssemblyAiTransport,
        R: AssemblyAiCredentialResolver,
    {
        self.ensure_provider(provider)?;
        provider.read_transcript()
    }

    pub fn compile_work_product_proposal(
        &mut self,
        consumer: &MissionTranscriptResultConsumer,
        projection: &TranscriptResultProjection,
        proposal_id: impl Into<String>,
    ) -> Result<TranscriptWorkProductProposal, AssemblyAiResultError> {
        self.registration.ensure_active()?;
        if consumer
            .registration_digest()
            .is_some_and(|digest| digest != self.registration.binding_digest())
        {
            return Err(AssemblyAiResultError::RegistrationDrift);
        }
        let proposal = consumer.compile_proposal(projection, proposal_id)?;
        if !self
            .proposal_fingerprints
            .insert(proposal.proposal_digest().clone())
        {
            return Err(AssemblyAiResultError::DuplicateProposal);
        }
        Ok(proposal)
    }

    pub fn record_work_product_proposal(
        &self,
        consumer: &mut MissionTranscriptResultConsumer,
        proposal: &TranscriptWorkProductProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<RecordedTranscriptProposal, AssemblyAiResultError> {
        self.registration.ensure_active()?;
        if consumer
            .registration_digest()
            .is_some_and(|digest| digest != self.registration.binding_digest())
            || proposal.registration_digest() != self.registration.binding_digest()
        {
            return Err(AssemblyAiResultError::RegistrationDrift);
        }
        let idempotency_key = idempotency_key.into();
        consumer.record_proposal(proposal, idempotency_key.as_str())
    }

    pub fn verify_transcript_result(
        &self,
        projection: &TranscriptResultProjection,
    ) -> Result<(), AssemblyAiResultError> {
        self.registration.ensure_active()?;
        if projection.registration_digest != *self.registration.binding_digest()
            || projection.scope_digest != *self.registration.scope_digest()
        {
            return Err(AssemblyAiResultError::RegistrationDrift);
        }
        projection.validate_integrity()
    }

    fn ensure_provider<T, R>(
        &self,
        provider: &AssemblyAiProvider<T, R>,
    ) -> Result<(), AssemblyAiProviderError>
    where
        T: crate::transport::AssemblyAiTransport,
        R: AssemblyAiCredentialResolver,
    {
        self.registration
            .ensure_active()
            .map_err(AssemblyAiProviderError::Registration)?;
        if provider.registration().binding_digest() != self.registration.binding_digest() {
            return Err(AssemblyAiProviderError::RegistrationDrift);
        }
        Ok(())
    }
}

// Keep these imports part of the public contract documentation and prevent
// accidental generalization into a model/tool registry.
#[allow(dead_code)]
const _ASSEMBLYAI_ONLY: (&str, &str) = (PLUGIN_ID, PROVIDER_API_REVISION);
