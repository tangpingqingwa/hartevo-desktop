use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use serde::{Deserialize, Serialize, Serializer};

use crate::consumer::{
    DeepgramTranscriptProposalRecording, DeepgramTranscriptResultProposal,
    MissionDeepgramTranscriptConsumer,
};
use crate::error::{DeepgramProviderError, DeepgramResultError};
use crate::model::{
    DeepgramProviderIdentity, DeepgramScope, Digest, PluginVersion, RegistrationId,
    RegistrationReceipt, RegistrationState, SecretReference, canonical_digest,
};
use crate::provider::{DeepgramCredentialResolver, DeepgramProvider};
use crate::{
    CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
    contract_digest,
};

const ACTIVE: u8 = 1;
const REVOKED: u8 = 2;
const REVERSED: u8 = 3;

/// Version/contract/provider/scope/consent/secret-bound registration. The
/// lifecycle state is shared by provider, service, consumer, and registry
/// clones so revocation is immediately observable.
#[derive(Clone)]
pub struct DeepgramRegistration {
    id: RegistrationId,
    plugin_version: PluginVersion,
    contract_version: String,
    contract_digest: Digest,
    provider: DeepgramProviderIdentity,
    scope: DeepgramScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    state: Arc<AtomicU8>,
    binding_digest: Digest,
}

impl DeepgramRegistration {
    pub fn new(
        id: RegistrationId,
        scope: DeepgramScope,
        secret_reference: SecretReference,
        registration_revision: u64,
    ) -> Result<Self, DeepgramResultError> {
        Self::new_with_provider(
            id,
            scope,
            secret_reference,
            DeepgramProviderIdentity::new(1, "layer1-fixture")?,
            registration_revision,
        )
    }

    pub fn new_with_provider(
        id: RegistrationId,
        scope: DeepgramScope,
        secret_reference: SecretReference,
        provider: DeepgramProviderIdentity,
        registration_revision: u64,
    ) -> Result<Self, DeepgramResultError> {
        let scope_digest = scope.digest();
        let mut registration = Self {
            id,
            plugin_version: PLUGIN_VERSION,
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider,
            scope,
            scope_digest,
            secret_reference,
            registration_revision,
            state: Arc::new(AtomicU8::new(ACTIVE)),
            binding_digest: Digest::from_text("unsealed-deepgram-registration"),
        };
        registration.binding_digest = registration.calculate_binding_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn for_scope(
        scope: DeepgramScope,
        secret_reference: SecretReference,
        id: impl Into<String>,
    ) -> Result<Self, DeepgramResultError> {
        Self::new(RegistrationId::new(id)?, scope, secret_reference, 1)
    }

    pub fn simple(
        scope: DeepgramScope,
        secret_reference: SecretReference,
    ) -> Result<Self, DeepgramResultError> {
        Self::for_scope(scope, secret_reference, "deepgram-registration-1")
    }

    pub fn validate(&self) -> Result<(), DeepgramResultError> {
        self.id.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate()?;
        self.provider.validate()?;
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.secret_reference.scope_digest() != &self.scope_digest
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(DeepgramResultError::InvalidRegistration);
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
    pub fn provider(&self) -> &DeepgramProviderIdentity {
        &self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &DeepgramScope {
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

    pub fn ensure_active(&self) -> Result<(), DeepgramResultError> {
        match self.state() {
            RegistrationState::Active if !self.secret_reference.is_revoked() => Ok(()),
            RegistrationState::Active => Err(DeepgramResultError::SecretRevoked),
            RegistrationState::Revoked => Err(DeepgramResultError::RegistrationRevoked),
            RegistrationState::Reversed => Err(DeepgramResultError::RegistrationReversed),
        }
    }

    pub fn revoke(&self) -> Result<(), DeepgramResultError> {
        self.state
            .compare_exchange(ACTIVE, REVOKED, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|state| match state {
                REVERSED => DeepgramResultError::RegistrationReversed,
                _ => DeepgramResultError::RegistrationRevoked,
            })
    }

    pub fn reverse(&self) -> Result<(), DeepgramResultError> {
        self.state.store(REVERSED, Ordering::Release);
        Ok(())
    }

    pub fn restore(&self) -> Result<(), DeepgramResultError> {
        self.state
            .compare_exchange(REVOKED, ACTIVE, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|state| match state {
                REVERSED => DeepgramResultError::RegistrationReversed,
                _ => DeepgramResultError::InvalidRegistration,
            })
    }

    pub fn revoke_secret_reference(&self) {
        self.secret_reference.revoke();
    }

    #[must_use]
    pub fn receipt(&self) -> RegistrationReceipt {
        RegistrationReceipt {
            registration_id: self.id.clone(),
            plugin_version: self.plugin_version,
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            provider: self.provider.clone(),
            scope_digest: self.scope_digest.clone(),
            consent_digest: self.scope.consent.digest(),
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
            &self.id,
            self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider,
            &self.scope_digest,
            self.scope.consent.digest(),
            self.secret_reference.reference_digest(),
            self.secret_reference.revision(),
            self.registration_revision,
        ))
    }
}

impl fmt::Debug for DeepgramRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeepgramRegistration")
            .field("id", &self.id)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider", &self.provider)
            .field("scope_digest", &self.scope_digest)
            .field("consent_digest", &self.scope.consent.digest())
            .field("secret_reference", &self.secret_reference)
            .field("registration_revision", &self.registration_revision)
            .field("state", &self.state())
            .field("binding_digest", &self.binding_digest)
            .finish_non_exhaustive()
    }
}

impl Serialize for DeepgramRegistration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.receipt().serialize(serializer)
    }
}

#[derive(Clone, Debug, Default)]
pub struct DeepgramRegistrationRegistry {
    registrations: BTreeMap<RegistrationId, DeepgramRegistration>,
    bindings: BTreeSet<Digest>,
}

impl DeepgramRegistrationRegistry {
    pub fn register(
        &mut self,
        registration: DeepgramRegistration,
    ) -> Result<(), DeepgramResultError> {
        registration.validate()?;
        if self.registrations.contains_key(registration.id())
            || self.bindings.contains(registration.binding_digest())
        {
            return Err(DeepgramResultError::RegistrationAlreadyExists);
        }
        self.bindings.insert(registration.binding_digest().clone());
        self.registrations
            .insert(registration.id().clone(), registration);
        Ok(())
    }

    pub fn get(&self, id: &RegistrationId) -> Result<&DeepgramRegistration, DeepgramResultError> {
        self.registrations
            .get(id)
            .ok_or(DeepgramResultError::RegistrationUnknown)
    }

    pub fn revoke(&self, id: &RegistrationId) -> Result<(), DeepgramResultError> {
        self.get(id)?.revoke()
    }

    pub fn restore(&self, id: &RegistrationId) -> Result<(), DeepgramResultError> {
        self.get(id)?.restore()
    }

    pub fn reverse(&self, id: &RegistrationId) -> Result<(), DeepgramResultError> {
        self.get(id)?.reverse()
    }
}

/// Descriptive Layer-1 capability boundary; false authority flags are
/// intentional and are checked by contract tests.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub contract_version: String,
    pub read_only: bool,
    pub can_read_result: bool,
    pub can_project_metadata: bool,
    pub can_project_segment_digests: bool,
    pub can_propose_work_product: bool,
    pub can_record_proposal: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub can_upload_audio: bool,
    pub can_download_audio: bool,
    pub can_export_raw_transcript: bool,
    pub can_write_media: bool,
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
            can_read_result: true,
            can_project_metadata: true,
            can_project_segment_digests: true,
            can_propose_work_product: true,
            can_record_proposal: true,
            connected: false,
            native: false,
            first_party: false,
            can_upload_audio: false,
            can_download_audio: false,
            can_export_raw_transcript: false,
            can_write_media: false,
            can_adopt_work_product: false,
            can_adopt_outcome: false,
            external_write: false,
            durable_provider_receipt: false,
            independent_readback: false,
        }
    }
}

/// Typed service composing bounded provider reads, Mission proposals, and
/// in-memory recording. It never performs an external side effect.
#[derive(Clone, Debug)]
pub struct DeepgramTranscriptResultService {
    registration: DeepgramRegistration,
    proposal_digests: BTreeSet<Digest>,
}

impl DeepgramTranscriptResultService {
    pub fn new(registration: DeepgramRegistration) -> Result<Self, DeepgramResultError> {
        registration.validate()?;
        registration.ensure_active()?;
        Ok(Self {
            registration,
            proposal_digests: BTreeSet::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &DeepgramRegistration {
        &self.registration
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription::layer1()
    }

    pub fn read_result<T, R>(
        &self,
        provider: &mut DeepgramProvider<T, R>,
    ) -> Result<crate::model::DeepgramTranscriptResultEvidence, DeepgramProviderError>
    where
        T: crate::transport::DeepgramTransport,
        R: DeepgramCredentialResolver,
    {
        self.ensure_provider(provider)?;
        provider.read_transcript_result()
    }

    pub fn read_transcript_result<T, R>(
        &self,
        provider: &mut DeepgramProvider<T, R>,
    ) -> Result<crate::model::DeepgramTranscriptResultEvidence, DeepgramProviderError>
    where
        T: crate::transport::DeepgramTransport,
        R: DeepgramCredentialResolver,
    {
        self.read_result(provider)
    }

    pub fn compile_proposal(
        &mut self,
        consumer: &MissionDeepgramTranscriptConsumer,
        evidence: &crate::model::DeepgramTranscriptResultEvidence,
        proposal_id: impl Into<String>,
    ) -> Result<DeepgramTranscriptResultProposal, DeepgramResultError> {
        self.registration.ensure_active()?;
        if consumer.registration_digest() != self.registration.binding_digest() {
            return Err(DeepgramResultError::RegistrationDrift);
        }
        let proposal = consumer.compile_proposal(evidence, proposal_id)?;
        if !self.proposal_digests.insert(proposal.digest().clone()) {
            return Err(DeepgramResultError::DuplicateProposal);
        }
        Ok(proposal)
    }

    pub fn compile_work_product_proposal(
        &mut self,
        consumer: &MissionDeepgramTranscriptConsumer,
        evidence: &crate::model::DeepgramTranscriptResultEvidence,
        proposal_id: impl Into<String>,
    ) -> Result<DeepgramTranscriptResultProposal, DeepgramResultError> {
        self.compile_proposal(consumer, evidence, proposal_id)
    }

    pub fn record_proposal(
        &self,
        consumer: &mut MissionDeepgramTranscriptConsumer,
        proposal: &DeepgramTranscriptResultProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<DeepgramTranscriptProposalRecording, DeepgramResultError> {
        self.registration.ensure_active()?;
        if consumer.registration_digest() != self.registration.binding_digest()
            || proposal.registration_digest() != self.registration.binding_digest()
        {
            return Err(DeepgramResultError::RegistrationDrift);
        }
        consumer.record_proposal(proposal, idempotency_key)
    }

    pub fn record_redacted_proposal(
        &self,
        consumer: &mut MissionDeepgramTranscriptConsumer,
        proposal: &DeepgramTranscriptResultProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<DeepgramTranscriptProposalRecording, DeepgramResultError> {
        self.record_proposal(consumer, proposal, idempotency_key)
    }

    pub fn verify(
        &self,
        evidence: &crate::model::DeepgramTranscriptResultEvidence,
    ) -> Result<(), DeepgramResultError> {
        self.registration.ensure_active()?;
        if evidence.registration_digest != *self.registration.binding_digest()
            || evidence.scope_digest != *self.registration.scope_digest()
        {
            return Err(DeepgramResultError::RegistrationDrift);
        }
        evidence.validate_integrity()
    }

    pub fn verify_transcript_result(
        &self,
        evidence: &crate::model::DeepgramTranscriptResultEvidence,
    ) -> Result<(), DeepgramResultError> {
        self.verify(evidence)
    }

    fn ensure_provider<T, R>(
        &self,
        provider: &DeepgramProvider<T, R>,
    ) -> Result<(), DeepgramProviderError>
    where
        T: crate::transport::DeepgramTransport,
        R: DeepgramCredentialResolver,
    {
        self.registration
            .ensure_active()
            .map_err(DeepgramProviderError::Registration)?;
        if provider.registration().binding_digest() != self.registration.binding_digest() {
            return Err(DeepgramProviderError::RegistrationDrift);
        }
        Ok(())
    }
}
