//! A narrow Federation plugin seam for Project/Mission-scoped sessions.
//!
//! This crate owns descriptors, signed capability offers, durable event
//! cursors, and the reversible session lifecycle around the existing typed
//! plugin registry. The transport is intentionally a trait; the included
//! deterministic local peer is a test harness and does not claim remote
//! protocol-native federation.
//!
//! The wire model is deliberately closed: a peer can exchange only a signed
//! capability offer or a signed durable event cursor. No Store, keyring,
//! browser profile, plaintext Project content, or Effect authority is
//! representable in the protocol types.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, EventContribution, EventKind,
    PluginContributions, PluginDefinition, PluginDefinitionHandle, PluginError, PluginId,
    PluginRuntime, ProviderCardinality, ProviderDefinition, ProviderId, RegistrationReceipt,
    ServiceDefinition, ServiceId,
};
use ring::signature::{self, KeyPair};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use hartevo_plugin_runtime::{
    Digest, EventId, MissionId, PluginLifecycle, PluginScope, PluginVersion, ProjectId,
};

pub const FEDERATION_SCHEMA: &str = "hartevo.federation/v1";
pub const FEDERATION_PLUGIN_ID: &str = "federation.session";
pub const FEDERATION_SERVICE_ID: &str = "federation.session.service";
pub const FEDERATION_PROVIDER_ID: &str = "federation.session.provider";
pub const FEDERATION_CONSUMER_ID: &str = "federation.session.consumer";
pub const FEDERATION_CURSOR_EVENT_ID: &str = "federation.session.cursor";
pub const FEDERATION_PLUGIN_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);

/// The Project/Mission scope used by all Federation messages.
pub type FederationScope = PluginScope;

/// The only authority classes that can be offered by this Federation seam.
///
/// Keeping this as a closed enum prevents a caller from smuggling Store,
/// keyring, browser-profile, or Effect authority into a capability offer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationCapability {
    ReadScopedMissionProjection,
    ExchangeDurableEventCursor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationServiceDefinition {
    version: PluginVersion,
    contract_digest: Digest,
}

impl FederationServiceDefinition {
    pub fn v1() -> Self {
        Self {
            version: FEDERATION_PLUGIN_VERSION,
            contract_digest: Digest::from_text(
                "hartevo federation service: signed scoped offer and durable cursor v1",
            ),
        }
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationProviderDefinition {
    version: PluginVersion,
    implementation_digest: Digest,
}

impl FederationProviderDefinition {
    pub fn v1() -> Self {
        Self {
            version: FEDERATION_PLUGIN_VERSION,
            implementation_digest: Digest::from_text(
                "hartevo federation deterministic transport provider v1",
            ),
        }
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationConsumerDefinition {
    version: PluginVersion,
    descriptor_digest: Digest,
}

impl FederationConsumerDefinition {
    pub fn v1() -> Self {
        Self {
            version: FEDERATION_PLUGIN_VERSION,
            descriptor_digest: Digest::from_text(
                "hartevo federation consumer: scoped capability and cursor session v1",
            ),
        }
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn descriptor_digest(&self) -> &Digest {
        &self.descriptor_digest
    }
}

/// Builds the typed plugin-runtime definition for one Federation session.
#[derive(Debug, Default)]
pub struct FederationPlugin;

impl FederationPlugin {
    pub fn definition(scope: &FederationScope) -> Result<PluginDefinition, FederationError> {
        let service_id = ServiceId::new(FEDERATION_SERVICE_ID)?;
        let service_definition = FederationServiceDefinition::v1();
        let provider_definition = FederationProviderDefinition::v1();
        let consumer_definition = FederationConsumerDefinition::v1();
        let service = ServiceDefinition::read_only(
            service_id.clone(),
            service_definition.version(),
            service_definition.contract_digest().clone(),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::Exact,
        )?;
        let provider = ProviderDefinition::new(
            ProviderId::new(FEDERATION_PROVIDER_ID)?,
            service_id.clone(),
            provider_definition.version(),
            provider_definition.implementation_digest().clone(),
        )?;
        let consumer = ConsumerDefinition::tool(
            ConsumerId::new(FEDERATION_CONSUMER_ID)?,
            service_id,
            consumer_definition.version(),
            consumer_definition.descriptor_digest().clone(),
        )?;
        let cursor_event = EventContribution::new(
            EventId::new(FEDERATION_CURSOR_EVENT_ID)?,
            EventKind::Conversation,
            Digest::from_text("hartevo federation durable cursor event v1"),
        )?;
        Ok(PluginDefinition::new(
            PluginId::new(FEDERATION_PLUGIN_ID)?,
            FEDERATION_PLUGIN_VERSION,
            scope.clone(),
            PluginContributions {
                services: vec![service],
                providers: vec![provider],
                consumers: vec![consumer],
                events: vec![cursor_event],
                ui_surfaces: Vec::new(),
            },
        )?)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerIdentityBody<'a> {
    schema: &'static str,
    peer_id: &'a PluginId,
    version: PluginVersion,
    public_key: &'a [u8],
}

/// Public peer identity carried in receipts and messages.
///
/// Only the Ed25519 verification key is exposed. The deterministic local
/// peer keeps its signing seed private to the transport/test harness.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerIdentity {
    peer_id: PluginId,
    version: PluginVersion,
    public_key: Vec<u8>,
    identity_digest: Digest,
}

impl PeerIdentity {
    fn from_public_key(
        peer_id: PluginId,
        version: PluginVersion,
        public_key: Vec<u8>,
    ) -> Result<Self, FederationError> {
        if public_key.len() != 32 {
            return Err(FederationError::InvalidPeerIdentity);
        }
        let mut identity = Self {
            peer_id,
            version,
            public_key,
            identity_digest: Digest::from_text("pending-peer-identity"),
        };
        identity.identity_digest = identity.computed_digest();
        identity.validate()?;
        Ok(identity)
    }

    pub fn peer_id(&self) -> &PluginId {
        &self.peer_id
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn identity_digest(&self) -> &Digest {
        &self.identity_digest
    }

    fn computed_digest(&self) -> Digest {
        digest_of(&PeerIdentityBody {
            schema: FEDERATION_SCHEMA,
            peer_id: &self.peer_id,
            version: self.version,
            public_key: &self.public_key,
        })
    }

    fn validate(&self) -> Result<(), FederationError> {
        if PluginId::new(self.peer_id.as_str().to_owned()).is_err()
            || self.public_key.len() != 32
            || self.identity_digest != self.computed_digest()
        {
            return Err(FederationError::InvalidPeerIdentity);
        }
        Ok(())
    }
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerIdentity")
            .field("peer_id_digest", &Digest::from_text(self.peer_id.as_str()))
            .field("version", &self.version)
            .field("identity_digest", &self.identity_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FederationError {
    #[error("plugin runtime rejected the Federation contribution set: {0}")]
    Plugin(#[from] PluginError),
    #[error("peer identity is invalid")]
    InvalidPeerIdentity,
    #[error("signing key is invalid")]
    InvalidSigningKey,
    #[error("signed message verification failed")]
    InvalidSignature,
    #[error("digest is invalid")]
    InvalidDigest,
    #[error("capability offer is broader than the parent Mission authority")]
    CapabilityEscalation,
    #[error("capability offer must contain at least one typed capability")]
    EmptyCapabilityOffer,
    #[error("Project/Mission scope does not match the mounted session")]
    ScopeMismatch,
    #[error("peer identity does not match the mounted session")]
    PeerIdentityMismatch,
    #[error("message targets a different peer")]
    WrongTargetPeer,
    #[error("session epoch is stale")]
    StaleEpoch,
    #[error("session cursor is a replay or does not advance")]
    CursorReplay,
    #[error("session cursor skips a durable position")]
    CursorGap,
    #[error("capability offer is a replay")]
    OfferReplay,
    #[error("session is unknown to the peer")]
    UnknownSession,
    #[error("session token is stale")]
    StaleSessionToken,
    #[error("session is not active")]
    SessionNotActive,
    #[error("session was unmounted")]
    SessionUnmounted,
    #[error("session was revoked")]
    SessionRevoked,
    #[error("session crashed and must be recovered")]
    SessionCrashed,
    #[error("session epoch overflowed")]
    EpochOverflow,
    #[error("mount receipt is invalid")]
    InvalidMountReceipt,
    #[error("transport returned an invalid protocol receipt")]
    TransportProtocolViolation,
}

#[derive(Clone)]
struct LocalSigner {
    identity: PeerIdentity,
    seed: [u8; 32],
}

impl fmt::Debug for LocalSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalSigner")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl LocalSigner {
    fn from_seed(
        peer_id: PluginId,
        version: PluginVersion,
        seed: [u8; 32],
    ) -> Result<Self, FederationError> {
        let key_pair = signature::Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|_| FederationError::InvalidSigningKey)?;
        let identity = PeerIdentity::from_public_key(
            peer_id,
            version,
            key_pair.public_key().as_ref().to_vec(),
        )?;
        Ok(Self { identity, seed })
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, FederationError> {
        let key_pair = signature::Ed25519KeyPair::from_seed_unchecked(&self.seed)
            .map_err(|_| FederationError::InvalidSigningKey)?;
        Ok(key_pair.sign(message).as_ref().to_vec())
    }
}

/// A deterministic local peer used by contract tests and local integration.
/// It implements the same transport trait that a future remote adapter will
/// implement, but it is not a remote protocol implementation.
pub struct DeterministicLocalPeer {
    signer: LocalSigner,
    sessions: BTreeMap<Digest, RemoteSession>,
}

impl DeterministicLocalPeer {
    pub fn new(
        peer_id: impl Into<String>,
        version: PluginVersion,
        seed: [u8; 32],
    ) -> Result<Self, FederationError> {
        let peer_id = PluginId::new(peer_id.into())?;
        Ok(Self {
            signer: LocalSigner::from_seed(peer_id, version, seed)?,
            sessions: BTreeMap::new(),
        })
    }

    pub fn identity(&self) -> &PeerIdentity {
        &self.signer.identity
    }

    pub fn session_snapshot(&self, session_id: &Digest) -> Option<RemoteSessionSnapshot> {
        self.sessions
            .get(session_id)
            .map(RemoteSessionSnapshot::from_session)
    }
}

impl fmt::Debug for DeterministicLocalPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeterministicLocalPeer")
            .field("identity", &self.signer.identity)
            .field("session_count", &self.sessions.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityOfferBody<'a> {
    schema: &'static str,
    session_id: &'a Digest,
    issuer: &'a PeerIdentity,
    target_peer_id: &'a PluginId,
    scope: &'a FederationScope,
    capabilities: &'a BTreeSet<FederationCapability>,
    epoch: u64,
}

struct CapabilityOfferSpec<'a> {
    session_id: Digest,
    issuer: PeerIdentity,
    target_peer_id: PluginId,
    scope: FederationScope,
    capabilities: BTreeSet<FederationCapability>,
    epoch: u64,
    signer: &'a LocalSigner,
}

/// A signed, scope-bound offer containing only the closed Federation
/// capability set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedCapabilityOffer {
    session_id: Digest,
    issuer: PeerIdentity,
    target_peer_id: PluginId,
    scope: FederationScope,
    capabilities: BTreeSet<FederationCapability>,
    epoch: u64,
    offer_digest: Digest,
    signature: Vec<u8>,
}

impl SignedCapabilityOffer {
    fn new(spec: CapabilityOfferSpec<'_>) -> Result<Self, FederationError> {
        let mut offer = Self {
            session_id: spec.session_id,
            issuer: spec.issuer,
            target_peer_id: spec.target_peer_id,
            scope: spec.scope,
            capabilities: spec.capabilities,
            epoch: spec.epoch,
            offer_digest: Digest::from_text("pending-capability-offer"),
            signature: Vec::new(),
        };
        let bytes = offer.signing_bytes();
        offer.offer_digest = Digest::from_bytes(&bytes);
        offer.signature = spec.signer.sign(&bytes)?;
        offer.validate()?;
        Ok(offer)
    }

    pub fn session_id(&self) -> &Digest {
        &self.session_id
    }

    pub fn issuer(&self) -> &PeerIdentity {
        &self.issuer
    }

    pub fn target_peer_id(&self) -> &PluginId {
        &self.target_peer_id
    }

    pub fn scope(&self) -> &FederationScope {
        &self.scope
    }

    pub fn capabilities(&self) -> &BTreeSet<FederationCapability> {
        &self.capabilities
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn offer_digest(&self) -> &Digest {
        &self.offer_digest
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    fn signing_bytes(&self) -> Vec<u8> {
        canonical_bytes(&CapabilityOfferBody {
            schema: FEDERATION_SCHEMA,
            session_id: &self.session_id,
            issuer: &self.issuer,
            target_peer_id: &self.target_peer_id,
            scope: &self.scope,
            capabilities: &self.capabilities,
            epoch: self.epoch,
        })
    }

    pub fn validate(&self) -> Result<(), FederationError> {
        self.issuer.validate()?;
        validate_scope(&self.scope)?;
        if !valid_digest(&self.session_id)
            || !valid_digest(&self.offer_digest)
            || PluginId::new(self.target_peer_id.as_str().to_owned()).is_err()
            || self.epoch == 0
            || self.capabilities.is_empty()
            || self.offer_digest != Digest::from_bytes(&self.signing_bytes())
            || self.signature.len() != 64
        {
            return Err(FederationError::InvalidSignature);
        }
        signature::UnparsedPublicKey::new(&signature::ED25519, self.issuer.public_key())
            .verify(&self.signing_bytes(), &self.signature)
            .map_err(|_| FederationError::InvalidSignature)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct DurableCursorBody<'a> {
    schema: &'static str,
    session_id: &'a Digest,
    issuer: &'a PeerIdentity,
    target_peer_id: &'a PluginId,
    stream_id: &'a EventId,
    scope: &'a FederationScope,
    epoch: u64,
    position: u64,
    event_digest: &'a Digest,
}

struct DurableCursorSpec<'a> {
    session_id: Digest,
    issuer: PeerIdentity,
    target_peer_id: PluginId,
    stream_id: EventId,
    scope: FederationScope,
    epoch: u64,
    position: u64,
    event_digest: Digest,
    signer: &'a LocalSigner,
}

/// A signed durable cursor. It contains an event digest and position, never
/// the event body or any Project/Mission plaintext.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DurableEventCursor {
    session_id: Digest,
    issuer: PeerIdentity,
    target_peer_id: PluginId,
    stream_id: EventId,
    scope: FederationScope,
    epoch: u64,
    position: u64,
    event_digest: Digest,
    cursor_digest: Digest,
    signature: Vec<u8>,
}

impl DurableEventCursor {
    fn new(spec: DurableCursorSpec<'_>) -> Result<Self, FederationError> {
        let mut cursor = Self {
            session_id: spec.session_id,
            issuer: spec.issuer,
            target_peer_id: spec.target_peer_id,
            stream_id: spec.stream_id,
            scope: spec.scope,
            epoch: spec.epoch,
            position: spec.position,
            event_digest: spec.event_digest,
            cursor_digest: Digest::from_text("pending-durable-cursor"),
            signature: Vec::new(),
        };
        let bytes = cursor.signing_bytes();
        cursor.cursor_digest = Digest::from_bytes(&bytes);
        cursor.signature = spec.signer.sign(&bytes)?;
        cursor.validate()?;
        Ok(cursor)
    }

    pub fn session_id(&self) -> &Digest {
        &self.session_id
    }

    pub fn issuer(&self) -> &PeerIdentity {
        &self.issuer
    }

    pub fn target_peer_id(&self) -> &PluginId {
        &self.target_peer_id
    }

    pub fn stream_id(&self) -> &EventId {
        &self.stream_id
    }

    pub fn scope(&self) -> &FederationScope {
        &self.scope
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn position(&self) -> u64 {
        self.position
    }

    pub fn event_digest(&self) -> &Digest {
        &self.event_digest
    }

    pub fn cursor_digest(&self) -> &Digest {
        &self.cursor_digest
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    fn signing_bytes(&self) -> Vec<u8> {
        canonical_bytes(&DurableCursorBody {
            schema: FEDERATION_SCHEMA,
            session_id: &self.session_id,
            issuer: &self.issuer,
            target_peer_id: &self.target_peer_id,
            stream_id: &self.stream_id,
            scope: &self.scope,
            epoch: self.epoch,
            position: self.position,
            event_digest: &self.event_digest,
        })
    }

    pub fn validate(&self) -> Result<(), FederationError> {
        self.issuer.validate()?;
        validate_scope(&self.scope)?;
        if !valid_digest(&self.session_id)
            || !valid_digest(&self.event_digest)
            || !valid_digest(&self.cursor_digest)
            || PluginId::new(self.target_peer_id.as_str().to_owned()).is_err()
            || self.epoch == 0
            || self.position == 0
            || self.signature.len() != 64
            || self.cursor_digest != Digest::from_bytes(&self.signing_bytes())
        {
            return Err(FederationError::InvalidSignature);
        }
        signature::UnparsedPublicKey::new(&signature::ED25519, self.issuer.public_key())
            .verify(&self.signing_bytes(), &self.signature)
            .map_err(|_| FederationError::InvalidSignature)
    }
}

/// The closed Federation wire envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FederationEnvelope {
    CapabilityOffer(SignedCapabilityOffer),
    DurableEventCursor(DurableEventCursor),
}

impl FederationEnvelope {
    pub fn validate(&self) -> Result<(), FederationError> {
        match self {
            Self::CapabilityOffer(offer) => offer.validate(),
            Self::DurableEventCursor(cursor) => cursor.validate(),
        }
    }

    pub fn digest(&self) -> &Digest {
        match self {
            Self::CapabilityOffer(offer) => offer.offer_digest(),
            Self::DurableEventCursor(cursor) => cursor.cursor_digest(),
        }
    }

    pub fn session_id(&self) -> &Digest {
        match self {
            Self::CapabilityOffer(offer) => offer.session_id(),
            Self::DurableEventCursor(cursor) => cursor.session_id(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionCloseReason {
    Unmounted,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationTransportReceipt {
    pub session_id: Digest,
    pub epoch: u64,
    pub envelope_digest: Digest,
    pub cursor_position: Option<u64>,
}

/// Transport seam for a future remote protocol adapter.
pub trait FederationTransport: fmt::Debug {
    fn peer_identity(&self) -> &PeerIdentity;

    fn deliver(
        &mut self,
        envelope: FederationEnvelope,
    ) -> Result<FederationTransportReceipt, FederationError>;

    fn close(
        &mut self,
        session_id: &Digest,
        epoch: u64,
        reason: SessionCloseReason,
    ) -> Result<(), FederationError>;
}

#[derive(Clone, Debug)]
struct RemoteSession {
    session_id: Digest,
    issuer: PeerIdentity,
    scope: FederationScope,
    capabilities: BTreeSet<FederationCapability>,
    epoch: u64,
    offer_digest: Digest,
    cursor_position: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteSessionSnapshot {
    pub session_id: Digest,
    pub peer_id: PluginId,
    pub peer_version: PluginVersion,
    pub peer_identity_digest: Digest,
    pub scope_digest: Digest,
    pub epoch: u64,
    pub cursor_position: u64,
}

impl RemoteSessionSnapshot {
    fn from_session(session: &RemoteSession) -> Self {
        Self {
            session_id: session.session_id.clone(),
            peer_id: session.issuer.peer_id().clone(),
            peer_version: session.issuer.version(),
            peer_identity_digest: session.issuer.identity_digest().clone(),
            scope_digest: session.scope.digest(),
            epoch: session.epoch,
            cursor_position: session.cursor_position,
        }
    }
}

impl FederationTransport for DeterministicLocalPeer {
    fn peer_identity(&self) -> &PeerIdentity {
        self.identity()
    }

    fn deliver(
        &mut self,
        envelope: FederationEnvelope,
    ) -> Result<FederationTransportReceipt, FederationError> {
        envelope.validate()?;
        let receipt = FederationTransportReceipt {
            session_id: envelope.session_id().clone(),
            epoch: match &envelope {
                FederationEnvelope::CapabilityOffer(offer) => offer.epoch(),
                FederationEnvelope::DurableEventCursor(cursor) => cursor.epoch(),
            },
            envelope_digest: envelope.digest().clone(),
            cursor_position: match &envelope {
                FederationEnvelope::CapabilityOffer(_) => None,
                FederationEnvelope::DurableEventCursor(cursor) => Some(cursor.position()),
            },
        };
        match &envelope {
            FederationEnvelope::CapabilityOffer(offer) => self.accept_offer(offer)?,
            FederationEnvelope::DurableEventCursor(cursor) => self.accept_cursor(cursor)?,
        }
        Ok(receipt)
    }

    fn close(
        &mut self,
        session_id: &Digest,
        epoch: u64,
        _reason: SessionCloseReason,
    ) -> Result<(), FederationError> {
        let Some(session) = self.sessions.get(session_id) else {
            return Err(FederationError::UnknownSession);
        };
        if session.epoch != epoch {
            return Err(FederationError::StaleEpoch);
        }
        self.sessions.remove(session_id);
        Ok(())
    }
}

impl DeterministicLocalPeer {
    fn accept_offer(&mut self, offer: &SignedCapabilityOffer) -> Result<(), FederationError> {
        if offer.target_peer_id() != self.identity().peer_id() {
            return Err(FederationError::WrongTargetPeer);
        }
        let mut preserved_cursor_position = 0;
        if let Some(existing) = self.sessions.get(offer.session_id()) {
            if existing.issuer != *offer.issuer() {
                return Err(FederationError::PeerIdentityMismatch);
            }
            if existing.scope != *offer.scope() {
                return Err(FederationError::ScopeMismatch);
            }
            if offer.epoch() < existing.epoch {
                return Err(FederationError::StaleEpoch);
            }
            if offer.epoch() == existing.epoch {
                if offer.offer_digest() != &existing.offer_digest
                    || offer.capabilities() != &existing.capabilities
                {
                    return Err(FederationError::CapabilityEscalation);
                }
                return Err(FederationError::OfferReplay);
            }
            let next_epoch = existing
                .epoch
                .checked_add(1)
                .ok_or(FederationError::EpochOverflow)?;
            if offer.epoch() != next_epoch {
                return Err(FederationError::StaleEpoch);
            }
            preserved_cursor_position = existing.cursor_position;
        }
        self.sessions.insert(
            offer.session_id().clone(),
            RemoteSession {
                session_id: offer.session_id().clone(),
                issuer: offer.issuer().clone(),
                scope: offer.scope().clone(),
                capabilities: offer.capabilities().clone(),
                epoch: offer.epoch(),
                offer_digest: offer.offer_digest().clone(),
                cursor_position: preserved_cursor_position,
            },
        );
        Ok(())
    }

    fn accept_cursor(&mut self, cursor: &DurableEventCursor) -> Result<(), FederationError> {
        if cursor.target_peer_id() != self.identity().peer_id() {
            return Err(FederationError::WrongTargetPeer);
        }
        let Some(session) = self.sessions.get_mut(cursor.session_id()) else {
            return Err(FederationError::UnknownSession);
        };
        if session.issuer != *cursor.issuer() {
            return Err(FederationError::PeerIdentityMismatch);
        }
        if session.scope != *cursor.scope() {
            return Err(FederationError::ScopeMismatch);
        }
        if session.epoch != cursor.epoch() {
            return Err(FederationError::StaleEpoch);
        }
        if cursor.position() <= session.cursor_position {
            return Err(FederationError::CursorReplay);
        }
        if cursor.position() != session.cursor_position.saturating_add(1) {
            return Err(FederationError::CursorGap);
        }
        session.cursor_position = cursor.position();
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MountReceiptBody<'a> {
    schema: &'static str,
    session_id: &'a Digest,
    peer_id: &'a PluginId,
    peer_version: PluginVersion,
    peer_identity_digest: &'a Digest,
    scope_digest: &'a Digest,
    plugin_digest: &'a Digest,
    registration_digest: &'a Digest,
    epoch: u64,
}

/// Content-free receipt binding the mount to peer identity, plugin version,
/// peer digest, Project/Mission scope, and epoch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationMountReceipt {
    session_id: Digest,
    peer_id: PluginId,
    peer_version: PluginVersion,
    peer_identity_digest: Digest,
    scope_digest: Digest,
    plugin_digest: Digest,
    registration_digest: Digest,
    epoch: u64,
    receipt_digest: Digest,
}

impl FederationMountReceipt {
    fn new(
        session_id: Digest,
        peer: &PeerIdentity,
        scope: &FederationScope,
        registration: &RegistrationReceipt,
        epoch: u64,
    ) -> Self {
        let mut receipt = Self {
            session_id,
            peer_id: peer.peer_id().clone(),
            peer_version: peer.version(),
            peer_identity_digest: peer.identity_digest().clone(),
            scope_digest: scope.digest(),
            plugin_digest: registration.plugin_digest().clone(),
            registration_digest: registration.digest().clone(),
            epoch,
            receipt_digest: Digest::from_text("pending-federation-mount-receipt"),
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt
    }

    pub fn session_id(&self) -> &Digest {
        &self.session_id
    }

    pub fn peer_id(&self) -> &PluginId {
        &self.peer_id
    }

    pub const fn peer_version(&self) -> PluginVersion {
        self.peer_version
    }

    pub fn peer_identity_digest(&self) -> &Digest {
        &self.peer_identity_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn plugin_digest(&self) -> &Digest {
        &self.plugin_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn receipt_digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub fn validate(&self) -> Result<(), FederationError> {
        if !valid_digest(&self.session_id)
            || !valid_digest(&self.peer_identity_digest)
            || !valid_digest(&self.scope_digest)
            || !valid_digest(&self.plugin_digest)
            || !valid_digest(&self.registration_digest)
            || !valid_digest(&self.receipt_digest)
            || PluginId::new(self.peer_id.as_str().to_owned()).is_err()
            || self.epoch == 0
            || self.receipt_digest != self.computed_digest()
        {
            return Err(FederationError::InvalidMountReceipt);
        }
        Ok(())
    }

    fn validate_against(
        &self,
        session_id: &Digest,
        peer: &PeerIdentity,
        scope: &FederationScope,
        epoch: u64,
    ) -> Result<(), FederationError> {
        self.validate()?;
        if self.session_id != *session_id
            || self.peer_id != *peer.peer_id()
            || self.peer_version != peer.version()
            || self.peer_identity_digest != *peer.identity_digest()
            || self.scope_digest != scope.digest()
            || self.epoch != epoch
        {
            return Err(FederationError::InvalidMountReceipt);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        digest_of(&MountReceiptBody {
            schema: FEDERATION_SCHEMA,
            session_id: &self.session_id,
            peer_id: &self.peer_id,
            peer_version: self.peer_version,
            peer_identity_digest: &self.peer_identity_digest,
            scope_digest: &self.scope_digest,
            plugin_digest: &self.plugin_digest,
            registration_digest: &self.registration_digest,
            epoch: self.epoch,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CloseReceiptBody<'a> {
    schema: &'static str,
    session_id: &'a Digest,
    peer_id: &'a PluginId,
    peer_version: PluginVersion,
    peer_identity_digest: &'a Digest,
    scope_digest: &'a Digest,
    epoch: u64,
    reason: SessionCloseReason,
    mount_receipt_digest: &'a Digest,
    plugin_cleanup_digest: &'a Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationCloseReceipt {
    session_id: Digest,
    peer_id: PluginId,
    peer_version: PluginVersion,
    peer_identity_digest: Digest,
    scope_digest: Digest,
    epoch: u64,
    reason: SessionCloseReason,
    mount_receipt_digest: Digest,
    plugin_cleanup_digest: Digest,
    close_digest: Digest,
}

impl FederationCloseReceipt {
    fn new(
        mount: &FederationMountReceipt,
        reason: SessionCloseReason,
        plugin_cleanup_digest: Digest,
    ) -> Self {
        let mut receipt = Self {
            session_id: mount.session_id.clone(),
            peer_id: mount.peer_id.clone(),
            peer_version: mount.peer_version,
            peer_identity_digest: mount.peer_identity_digest.clone(),
            scope_digest: mount.scope_digest.clone(),
            epoch: mount.epoch,
            reason,
            mount_receipt_digest: mount.receipt_digest.clone(),
            plugin_cleanup_digest,
            close_digest: Digest::from_text("pending-federation-close-receipt"),
        };
        receipt.close_digest = digest_of(&CloseReceiptBody {
            schema: FEDERATION_SCHEMA,
            session_id: &receipt.session_id,
            peer_id: &receipt.peer_id,
            peer_version: receipt.peer_version,
            peer_identity_digest: &receipt.peer_identity_digest,
            scope_digest: &receipt.scope_digest,
            epoch: receipt.epoch,
            reason: receipt.reason,
            mount_receipt_digest: &receipt.mount_receipt_digest,
            plugin_cleanup_digest: &receipt.plugin_cleanup_digest,
        });
        receipt
    }

    pub fn session_id(&self) -> &Digest {
        &self.session_id
    }

    pub fn peer_id(&self) -> &PluginId {
        &self.peer_id
    }

    pub const fn peer_version(&self) -> PluginVersion {
        self.peer_version
    }

    pub fn peer_identity_digest(&self) -> &Digest {
        &self.peer_identity_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn reason(&self) -> SessionCloseReason {
        self.reason
    }

    pub fn mount_receipt_digest(&self) -> &Digest {
        &self.mount_receipt_digest
    }

    pub fn plugin_cleanup_digest(&self) -> &Digest {
        &self.plugin_cleanup_digest
    }

    pub fn close_digest(&self) -> &Digest {
        &self.close_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationSessionToken {
    session_id: Digest,
    epoch: u64,
    mount_receipt_digest: Digest,
}

impl FederationSessionToken {
    pub fn session_id(&self) -> &Digest {
        &self.session_id
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn mount_receipt_digest(&self) -> &Digest {
        &self.mount_receipt_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederationSessionCheckpoint {
    session_id: Digest,
    local_peer: PeerIdentity,
    remote_peer: PeerIdentity,
    scope: FederationScope,
    parent_capabilities: BTreeSet<FederationCapability>,
    offered_capabilities: BTreeSet<FederationCapability>,
    stream_id: EventId,
    epoch: u64,
    cursor_position: u64,
    mount_receipt_digest: Digest,
}

impl FederationSessionCheckpoint {
    pub fn session_id(&self) -> &Digest {
        &self.session_id
    }

    pub fn scope(&self) -> &FederationScope {
        &self.scope
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn cursor_position(&self) -> u64 {
        self.cursor_position
    }

    pub fn mount_receipt_digest(&self) -> &Digest {
        &self.mount_receipt_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationSessionLifecycle {
    Active,
    Unmounted,
    Revoked,
    Crashed,
}

/// A mounted typed Federation session.
pub struct FederationSession {
    signer: LocalSigner,
    remote_peer: PeerIdentity,
    scope: FederationScope,
    parent_capabilities: BTreeSet<FederationCapability>,
    offered_capabilities: BTreeSet<FederationCapability>,
    stream_id: EventId,
    session_id: Digest,
    epoch: u64,
    cursor_position: u64,
    offer: SignedCapabilityOffer,
    mount_receipt: FederationMountReceipt,
    runtime: Option<PluginRuntime>,
    definition_handle: Option<PluginDefinitionHandle>,
    registration: Option<RegistrationReceipt>,
    lifecycle: FederationSessionLifecycle,
}

impl fmt::Debug for FederationSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FederationSession")
            .field("local_peer", &self.signer.identity)
            .field("remote_peer", &self.remote_peer)
            .field("scope_digest", &self.scope.digest())
            .field("session_id", &self.session_id)
            .field("epoch", &self.epoch)
            .field("cursor_position", &self.cursor_position)
            .field("lifecycle", &self.lifecycle)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionIdBody<'a> {
    schema: &'static str,
    local_peer_digest: &'a Digest,
    remote_peer_digest: &'a Digest,
    scope: &'a FederationScope,
    capabilities: &'a BTreeSet<FederationCapability>,
    stream_id: &'a EventId,
}

struct MountParams<'a> {
    remote_peer: PeerIdentity,
    scope: FederationScope,
    parent_capabilities: &'a BTreeSet<FederationCapability>,
    offered_capabilities: BTreeSet<FederationCapability>,
    stream_id: EventId,
    session_id: Digest,
    epoch: u64,
    cursor_position: u64,
}

impl FederationSession {
    pub fn mount(
        local_peer: &DeterministicLocalPeer,
        transport: &mut dyn FederationTransport,
        scope: FederationScope,
        parent_capabilities: &BTreeSet<FederationCapability>,
        offered_capabilities: BTreeSet<FederationCapability>,
        stream_id: EventId,
    ) -> Result<Self, FederationError> {
        let remote_peer = transport.peer_identity().clone();
        let session_id = digest_of(&SessionIdBody {
            schema: FEDERATION_SCHEMA,
            local_peer_digest: local_peer.identity().identity_digest(),
            remote_peer_digest: remote_peer.identity_digest(),
            scope: &scope,
            capabilities: &offered_capabilities,
            stream_id: &stream_id,
        });
        Self::mount_at(
            local_peer,
            transport,
            MountParams {
                remote_peer,
                scope,
                parent_capabilities,
                offered_capabilities,
                stream_id,
                session_id,
                epoch: 1,
                cursor_position: 0,
            },
        )
    }

    fn mount_at(
        local_peer: &DeterministicLocalPeer,
        transport: &mut dyn FederationTransport,
        params: MountParams<'_>,
    ) -> Result<Self, FederationError> {
        let MountParams {
            remote_peer,
            scope,
            parent_capabilities,
            offered_capabilities,
            stream_id,
            session_id,
            epoch,
            cursor_position,
        } = params;
        validate_scope(&scope)?;
        validate_capabilities(parent_capabilities, &offered_capabilities)?;
        if local_peer.identity() == &remote_peer
            || transport.peer_identity() != &remote_peer
            || epoch == 0
            || !valid_digest(&session_id)
        {
            return Err(FederationError::PeerIdentityMismatch);
        }
        let signer = local_peer.signer.clone();
        let definition = FederationPlugin::definition(&scope)?;
        let mut runtime = PluginRuntime::new();
        let definition_handle = runtime.define(definition)?;
        let registration = runtime.mount_in_scope(&definition_handle, &scope)?;
        let offer = SignedCapabilityOffer::new(CapabilityOfferSpec {
            session_id: session_id.clone(),
            issuer: signer.identity.clone(),
            target_peer_id: remote_peer.peer_id().clone(),
            scope: scope.clone(),
            capabilities: offered_capabilities.clone(),
            epoch,
            signer: &signer,
        })?;
        let transport_receipt =
            transport.deliver(FederationEnvelope::CapabilityOffer(offer.clone()))?;
        if transport_receipt.session_id != session_id
            || transport_receipt.epoch != epoch
            || transport_receipt.envelope_digest != *offer.offer_digest()
            || transport_receipt.cursor_position.is_some()
        {
            return Err(FederationError::TransportProtocolViolation);
        }
        let mount_receipt = FederationMountReceipt::new(
            session_id.clone(),
            &remote_peer,
            &scope,
            &registration,
            epoch,
        );
        Ok(Self {
            signer,
            remote_peer,
            scope,
            parent_capabilities: parent_capabilities.clone(),
            offered_capabilities,
            stream_id,
            session_id,
            epoch,
            cursor_position,
            offer,
            mount_receipt,
            runtime: Some(runtime),
            definition_handle: Some(definition_handle),
            registration: Some(registration),
            lifecycle: FederationSessionLifecycle::Active,
        })
    }

    pub fn session_id(&self) -> &Digest {
        &self.session_id
    }

    pub fn scope(&self) -> &FederationScope {
        &self.scope
    }

    pub fn remote_peer(&self) -> &PeerIdentity {
        &self.remote_peer
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn cursor_position(&self) -> u64 {
        self.cursor_position
    }

    pub fn offer(&self) -> &SignedCapabilityOffer {
        &self.offer
    }

    pub fn mount_receipt(&self) -> &FederationMountReceipt {
        &self.mount_receipt
    }

    pub const fn lifecycle(&self) -> FederationSessionLifecycle {
        self.lifecycle
    }

    pub fn token(&self) -> FederationSessionToken {
        FederationSessionToken {
            session_id: self.session_id.clone(),
            epoch: self.epoch,
            mount_receipt_digest: self.mount_receipt.receipt_digest.clone(),
        }
    }

    pub fn inspection(&self) -> hartevo_plugin_runtime::RuntimeInspection {
        self.runtime.as_ref().map_or_else(
            || PluginRuntime::new().inspect(&self.scope),
            |runtime| runtime.inspect(&self.scope),
        )
    }

    pub fn prepare_cursor(
        &self,
        token: &FederationSessionToken,
        event_digest: Digest,
    ) -> Result<DurableEventCursor, FederationError> {
        self.ensure_active()?;
        self.ensure_token(token)?;
        if !valid_digest(&event_digest) {
            return Err(FederationError::InvalidDigest);
        }
        let position = self
            .cursor_position
            .checked_add(1)
            .ok_or(FederationError::EpochOverflow)?;
        DurableEventCursor::new(DurableCursorSpec {
            session_id: self.session_id.clone(),
            issuer: self.signer.identity.clone(),
            target_peer_id: self.remote_peer.peer_id().clone(),
            stream_id: self.stream_id.clone(),
            scope: self.scope.clone(),
            epoch: self.epoch,
            position,
            event_digest,
            signer: &self.signer,
        })
    }

    pub fn publish_cursor(
        &mut self,
        transport: &mut dyn FederationTransport,
        token: &FederationSessionToken,
        cursor: &DurableEventCursor,
    ) -> Result<FederationTransportReceipt, FederationError> {
        self.ensure_active()?;
        self.ensure_token(token)?;
        cursor.validate()?;
        if cursor.session_id() != &self.session_id
            || cursor.issuer() != &self.signer.identity
            || cursor.target_peer_id() != self.remote_peer.peer_id()
            || cursor.stream_id() != &self.stream_id
            || cursor.scope() != &self.scope
        {
            return Err(FederationError::ScopeMismatch);
        }
        if cursor.epoch() != self.epoch {
            return Err(FederationError::StaleEpoch);
        }
        if cursor.position() <= self.cursor_position {
            return Err(FederationError::CursorReplay);
        }
        if cursor.position() != self.cursor_position.saturating_add(1) {
            return Err(FederationError::CursorGap);
        }
        if transport.peer_identity() != &self.remote_peer {
            return Err(FederationError::PeerIdentityMismatch);
        }
        let receipt = transport.deliver(FederationEnvelope::DurableEventCursor(cursor.clone()))?;
        if receipt.session_id != self.session_id
            || receipt.epoch != self.epoch
            || receipt.envelope_digest != *cursor.cursor_digest()
            || receipt.cursor_position != Some(cursor.position())
        {
            return Err(FederationError::TransportProtocolViolation);
        }
        self.cursor_position = cursor.position();
        Ok(receipt)
    }

    pub fn unmount(
        &mut self,
        transport: &mut dyn FederationTransport,
    ) -> Result<FederationCloseReceipt, FederationError> {
        self.ensure_active()?;
        if transport.peer_identity() != &self.remote_peer {
            return Err(FederationError::PeerIdentityMismatch);
        }
        let registration = self
            .registration
            .as_ref()
            .ok_or(FederationError::SessionNotActive)?;
        transport.close(&self.session_id, self.epoch, SessionCloseReason::Unmounted)?;
        let cleanup = self
            .runtime
            .as_mut()
            .ok_or(FederationError::SessionNotActive)?
            .unmount(registration)?;
        let receipt = FederationCloseReceipt::new(
            &self.mount_receipt,
            SessionCloseReason::Unmounted,
            cleanup.receipt_digest,
        );
        self.lifecycle = FederationSessionLifecycle::Unmounted;
        self.runtime = None;
        self.definition_handle = None;
        self.registration = None;
        Ok(receipt)
    }

    pub fn revoke(
        &mut self,
        transport: &mut dyn FederationTransport,
    ) -> Result<FederationCloseReceipt, FederationError> {
        self.ensure_active()?;
        if transport.peer_identity() != &self.remote_peer {
            return Err(FederationError::PeerIdentityMismatch);
        }
        let handle = self
            .definition_handle
            .as_ref()
            .ok_or(FederationError::SessionNotActive)?;
        transport.close(&self.session_id, self.epoch, SessionCloseReason::Revoked)?;
        let cleanup = self
            .runtime
            .as_mut()
            .ok_or(FederationError::SessionNotActive)?
            .revoke(handle)?;
        let receipt = FederationCloseReceipt::new(
            &self.mount_receipt,
            SessionCloseReason::Revoked,
            cleanup.receipt_digest,
        );
        self.lifecycle = FederationSessionLifecycle::Revoked;
        self.runtime = None;
        self.definition_handle = None;
        self.registration = None;
        Ok(receipt)
    }

    pub fn crash(&mut self) -> Result<FederationSessionCheckpoint, FederationError> {
        self.ensure_active()?;
        let checkpoint = FederationSessionCheckpoint {
            session_id: self.session_id.clone(),
            local_peer: self.signer.identity.clone(),
            remote_peer: self.remote_peer.clone(),
            scope: self.scope.clone(),
            parent_capabilities: self.parent_capabilities.clone(),
            offered_capabilities: self.offered_capabilities.clone(),
            stream_id: self.stream_id.clone(),
            epoch: self.epoch,
            cursor_position: self.cursor_position,
            mount_receipt_digest: self.mount_receipt.receipt_digest.clone(),
        };
        self.lifecycle = FederationSessionLifecycle::Crashed;
        self.runtime = None;
        self.definition_handle = None;
        self.registration = None;
        Ok(checkpoint)
    }

    pub fn recover_from_checkpoint(
        checkpoint: &FederationSessionCheckpoint,
        local_peer: &DeterministicLocalPeer,
        parent_capabilities: &BTreeSet<FederationCapability>,
        transport: &mut dyn FederationTransport,
    ) -> Result<Self, FederationError> {
        checkpoint.validate()?;
        if checkpoint.local_peer != *local_peer.identity()
            || checkpoint.remote_peer != *transport.peer_identity()
        {
            return Err(FederationError::PeerIdentityMismatch);
        }
        validate_capabilities(parent_capabilities, &checkpoint.offered_capabilities)?;
        let next_epoch = checkpoint
            .epoch
            .checked_add(1)
            .ok_or(FederationError::EpochOverflow)?;
        Self::mount_at(
            local_peer,
            transport,
            MountParams {
                remote_peer: checkpoint.remote_peer.clone(),
                scope: checkpoint.scope.clone(),
                parent_capabilities,
                offered_capabilities: checkpoint.offered_capabilities.clone(),
                stream_id: checkpoint.stream_id.clone(),
                session_id: checkpoint.session_id.clone(),
                epoch: next_epoch,
                cursor_position: checkpoint.cursor_position,
            },
        )
    }

    fn ensure_active(&self) -> Result<(), FederationError> {
        match self.lifecycle {
            FederationSessionLifecycle::Active => Ok(()),
            FederationSessionLifecycle::Unmounted => Err(FederationError::SessionUnmounted),
            FederationSessionLifecycle::Revoked => Err(FederationError::SessionRevoked),
            FederationSessionLifecycle::Crashed => Err(FederationError::SessionCrashed),
        }
    }

    fn ensure_token(&self, token: &FederationSessionToken) -> Result<(), FederationError> {
        self.mount_receipt.validate_against(
            &self.session_id,
            &self.remote_peer,
            &self.scope,
            self.epoch,
        )?;
        if token.session_id != self.session_id
            || token.epoch != self.epoch
            || token.mount_receipt_digest != self.mount_receipt.receipt_digest
        {
            return Err(FederationError::StaleSessionToken);
        }
        Ok(())
    }
}

impl FederationSessionCheckpoint {
    fn validate(&self) -> Result<(), FederationError> {
        self.local_peer.validate()?;
        self.remote_peer.validate()?;
        validate_scope(&self.scope)?;
        validate_capabilities(&self.parent_capabilities, &self.offered_capabilities)?;
        if !valid_digest(&self.session_id)
            || !valid_digest(&self.mount_receipt_digest)
            || self.epoch == 0
        {
            return Err(FederationError::InvalidMountReceipt);
        }
        Ok(())
    }
}

fn validate_scope(scope: &FederationScope) -> Result<(), FederationError> {
    PluginScope::new(
        scope.project_id().clone(),
        scope.mission_id().clone(),
        scope.generation(),
    )?;
    Ok(())
}

fn validate_capabilities(
    parent_capabilities: &BTreeSet<FederationCapability>,
    offered_capabilities: &BTreeSet<FederationCapability>,
) -> Result<(), FederationError> {
    if offered_capabilities.is_empty() {
        return Err(FederationError::EmptyCapabilityOffer);
    }
    if !offered_capabilities.is_subset(parent_capabilities) {
        return Err(FederationError::CapabilityEscalation);
    }
    Ok(())
}

fn canonical_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("Federation canonical values must serialize")
}

fn digest_of<T: Serialize>(value: &T) -> Digest {
    Digest::from_bytes(&canonical_bytes(value))
}

fn valid_digest(digest: &Digest) -> bool {
    digest.as_str().len() == 64
        && digest
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
