//! Scoped, reversible in-process plugin composition for Hartevo.
//!
//! This crate deliberately stops at a typed composition and lifecycle spine.
//! It does not load code, hold host handles, execute commands, or carry plugin
//! payloads. A plugin contributes descriptors; the runtime validates the
//! complete contribution set, stages it copy-on-write, and commits one opaque
//! receipt only after every contribution is compatible with the scoped
//! registry.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
};

use serde::{Deserialize, Serialize, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const PLUGIN_RUNTIME_SCHEMA: &str = "hartevo.plugin-runtime/v1";
pub const PLUGIN_DEFINITION_SCHEMA: &str = "hartevo.plugin-definition/v1";
pub const PLUGIN_RECEIPT_SCHEMA: &str = "hartevo.plugin-registration-receipt/v1";
pub const PLUGIN_INSPECTION_SCHEMA: &str = "hartevo.plugin-inspection/v1";
pub const MAX_IDENTIFIER_BYTES: usize = 128;

pub mod skill_invocation;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginErrorCode {
    InvalidSchema,
    InvalidIdentifier,
    InvalidDigest,
    InvalidScope,
    InvalidDefinition,
    DigestMismatch,
    DefinitionAlreadyExists,
    UnknownDefinition,
    PluginAlreadyMounted,
    LifecycleViolation,
    DuplicateServiceDefinition,
    DuplicateProvider,
    ProviderCardinalityExceeded,
    ProviderIncompatible,
    MissingService,
    DuplicateConsumer,
    ConsumerIncompatible,
    DuplicateEvent,
    DuplicateUiSurface,
    StaleGeneration,
    GenerationRegression,
    ScopeMismatch,
    InvalidReceipt,
    StaleReceipt,
    PluginRevoked,
    UnmountDependency,
    MountFailed,
    MountPanicked,
    RevisionOverflow,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PluginError {
    #[error("plugin runtime schema is invalid")]
    InvalidSchema,
    #[error("plugin identifier is invalid")]
    InvalidIdentifier,
    #[error("plugin digest is invalid")]
    InvalidDigest,
    #[error("plugin scope is invalid")]
    InvalidScope,
    #[error("plugin definition is invalid")]
    InvalidDefinition,
    #[error("plugin definition digest does not match its immutable contents")]
    DigestMismatch,
    #[error("plugin definition already exists")]
    DefinitionAlreadyExists,
    #[error("plugin definition is unknown to this runtime")]
    UnknownDefinition,
    #[error("another version of this plugin is already mounted in the scope")]
    PluginAlreadyMounted,
    #[error("plugin lifecycle does not permit this operation")]
    LifecycleViolation,
    #[error("service definition already exists in the scope")]
    DuplicateServiceDefinition,
    #[error("provider identifier already exists in the scope")]
    DuplicateProvider,
    #[error("service provider cardinality would be exceeded")]
    ProviderCardinalityExceeded,
    #[error("provider version is incompatible with its service")]
    ProviderIncompatible,
    #[error("provider or consumer references an unknown service")]
    MissingService,
    #[error("consumer identifier already exists in the scope")]
    DuplicateConsumer,
    #[error("consumer has no compatible provider")]
    ConsumerIncompatible,
    #[error("event contribution identifier already exists in the scope")]
    DuplicateEvent,
    #[error("UI surface contribution identifier already exists in the scope")]
    DuplicateUiSurface,
    #[error("plugin generation is stale for the Project/Mission")]
    StaleGeneration,
    #[error("plugin generation would regress the Project/Mission")]
    GenerationRegression,
    #[error("plugin scope does not match the requested scope")]
    ScopeMismatch,
    #[error("registration receipt is invalid")]
    InvalidReceipt,
    #[error("registration receipt is stale")]
    StaleReceipt,
    #[error("plugin has been revoked")]
    PluginRevoked,
    #[error("unmount would leave dependent contributions without a service")]
    UnmountDependency,
    #[error("mount transaction failed before commit")]
    MountFailed,
    #[error("mount transaction panicked before commit")]
    MountPanicked,
    #[error("plugin registry revision overflowed")]
    RevisionOverflow,
}

impl PluginError {
    pub const fn code(self) -> PluginErrorCode {
        match self {
            Self::InvalidSchema => PluginErrorCode::InvalidSchema,
            Self::InvalidIdentifier => PluginErrorCode::InvalidIdentifier,
            Self::InvalidDigest => PluginErrorCode::InvalidDigest,
            Self::InvalidScope => PluginErrorCode::InvalidScope,
            Self::InvalidDefinition => PluginErrorCode::InvalidDefinition,
            Self::DigestMismatch => PluginErrorCode::DigestMismatch,
            Self::DefinitionAlreadyExists => PluginErrorCode::DefinitionAlreadyExists,
            Self::UnknownDefinition => PluginErrorCode::UnknownDefinition,
            Self::PluginAlreadyMounted => PluginErrorCode::PluginAlreadyMounted,
            Self::LifecycleViolation => PluginErrorCode::LifecycleViolation,
            Self::DuplicateServiceDefinition => PluginErrorCode::DuplicateServiceDefinition,
            Self::DuplicateProvider => PluginErrorCode::DuplicateProvider,
            Self::ProviderCardinalityExceeded => PluginErrorCode::ProviderCardinalityExceeded,
            Self::ProviderIncompatible => PluginErrorCode::ProviderIncompatible,
            Self::MissingService => PluginErrorCode::MissingService,
            Self::DuplicateConsumer => PluginErrorCode::DuplicateConsumer,
            Self::ConsumerIncompatible => PluginErrorCode::ConsumerIncompatible,
            Self::DuplicateEvent => PluginErrorCode::DuplicateEvent,
            Self::DuplicateUiSurface => PluginErrorCode::DuplicateUiSurface,
            Self::StaleGeneration => PluginErrorCode::StaleGeneration,
            Self::GenerationRegression => PluginErrorCode::GenerationRegression,
            Self::ScopeMismatch => PluginErrorCode::ScopeMismatch,
            Self::InvalidReceipt => PluginErrorCode::InvalidReceipt,
            Self::StaleReceipt => PluginErrorCode::StaleReceipt,
            Self::PluginRevoked => PluginErrorCode::PluginRevoked,
            Self::UnmountDependency => PluginErrorCode::UnmountDependency,
            Self::MountFailed => PluginErrorCode::MountFailed,
            Self::MountPanicked => PluginErrorCode::MountPanicked,
            Self::RevisionOverflow => PluginErrorCode::RevisionOverflow,
        }
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_serialized<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("plugin runtime canonical values serialize");
        Self::from_bytes(&bytes)
    }

    fn validate(&self) -> Result<(), PluginError> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(PluginError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

macro_rules! define_identifier {
    ($name:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, PluginError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(PluginError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            fn validate(&self) -> Result<(), PluginError> {
                if valid_identifier(self.as_str()) {
                    Ok(())
                } else {
                    Err(PluginError::InvalidIdentifier)
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &Digest::from_text(self.as_str()))
                    .finish()
            }
        }
    };
}

define_identifier!(PluginId);
define_identifier!(ProjectId);
define_identifier!(MissionId);
define_identifier!(ServiceId);
define_identifier!(ProviderId);
define_identifier!(ConsumerId);
define_identifier!(EventId);
define_identifier!(UiSurfaceId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl PluginVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn patch(self) -> u16 {
        self.patch
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginScope {
    project_id: ProjectId,
    mission_id: MissionId,
    generation: u64,
}

impl PluginScope {
    pub fn new(
        project_id: ProjectId,
        mission_id: MissionId,
        generation: u64,
    ) -> Result<Self, PluginError> {
        let scope = Self {
            project_id,
            mission_id,
            generation,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    fn validate(&self) -> Result<(), PluginError> {
        if self.generation == 0 {
            return Err(PluginError::InvalidScope);
        }
        self.project_id.validate()?;
        self.mission_id.validate()
    }
}

impl fmt::Debug for PluginScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginScope")
            .field(
                "project_digest",
                &Digest::from_text(self.project_id.as_str()),
            )
            .field(
                "mission_digest",
                &Digest::from_text(self.mission_id.as_str()),
            )
            .field("generation", &self.generation)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAccess {
    ReadOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCardinality {
    Singleton,
    Many,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityPolicy {
    Exact,
    SameMajor,
    Minimum,
}

impl CompatibilityPolicy {
    fn accepts(self, required: PluginVersion, offered: PluginVersion) -> bool {
        match self {
            Self::Exact => offered == required,
            Self::SameMajor => offered.major() == required.major() && offered >= required,
            Self::Minimum => offered >= required,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDefinition {
    id: ServiceId,
    version: PluginVersion,
    access: ServiceAccess,
    cardinality: ProviderCardinality,
    compatibility: CompatibilityPolicy,
    contract_digest: Digest,
}

impl ServiceDefinition {
    pub fn read_only(
        id: ServiceId,
        version: PluginVersion,
        contract_digest: Digest,
        cardinality: ProviderCardinality,
        compatibility: CompatibilityPolicy,
    ) -> Result<Self, PluginError> {
        let definition = Self {
            id,
            version,
            access: ServiceAccess::ReadOnly,
            cardinality,
            compatibility,
            contract_digest,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn id(&self) -> &ServiceId {
        &self.id
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub const fn access(&self) -> ServiceAccess {
        self.access
    }

    pub const fn cardinality(&self) -> ProviderCardinality {
        self.cardinality
    }

    pub const fn compatibility(&self) -> CompatibilityPolicy {
        self.compatibility
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    fn validate(&self) -> Result<(), PluginError> {
        self.id.validate()?;
        self.contract_digest.validate()
    }
}

impl fmt::Debug for ServiceDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceDefinition")
            .field("id_digest", &Digest::from_text(self.id.as_str()))
            .field("version", &self.version)
            .field("access", &self.access)
            .field("cardinality", &self.cardinality)
            .field("compatibility", &self.compatibility)
            .field("contract_digest", &self.contract_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderDefinition {
    id: ProviderId,
    service_id: ServiceId,
    version: PluginVersion,
    implementation_digest: Digest,
}

impl ProviderDefinition {
    pub fn new(
        id: ProviderId,
        service_id: ServiceId,
        version: PluginVersion,
        implementation_digest: Digest,
    ) -> Result<Self, PluginError> {
        let provider = Self {
            id,
            service_id,
            version,
            implementation_digest,
        };
        provider.validate()?;
        Ok(provider)
    }

    pub fn id(&self) -> &ProviderId {
        &self.id
    }

    pub fn service_id(&self) -> &ServiceId {
        &self.service_id
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }

    fn validate(&self) -> Result<(), PluginError> {
        self.id.validate()?;
        self.service_id.validate()?;
        self.implementation_digest.validate()
    }
}

impl fmt::Debug for ProviderDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderDefinition")
            .field("id_digest", &Digest::from_text(self.id.as_str()))
            .field(
                "service_id_digest",
                &Digest::from_text(self.service_id.as_str()),
            )
            .field("version", &self.version)
            .field("implementation_digest", &self.implementation_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumerKind {
    Command,
    Tool,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerDefinition {
    id: ConsumerId,
    service_id: ServiceId,
    kind: ConsumerKind,
    required_version: PluginVersion,
    descriptor_digest: Digest,
}

impl ConsumerDefinition {
    pub fn command(
        id: ConsumerId,
        service_id: ServiceId,
        required_version: PluginVersion,
        descriptor_digest: Digest,
    ) -> Result<Self, PluginError> {
        Self::new(
            id,
            service_id,
            ConsumerKind::Command,
            required_version,
            descriptor_digest,
        )
    }

    pub fn tool(
        id: ConsumerId,
        service_id: ServiceId,
        required_version: PluginVersion,
        descriptor_digest: Digest,
    ) -> Result<Self, PluginError> {
        Self::new(
            id,
            service_id,
            ConsumerKind::Tool,
            required_version,
            descriptor_digest,
        )
    }

    fn new(
        id: ConsumerId,
        service_id: ServiceId,
        kind: ConsumerKind,
        required_version: PluginVersion,
        descriptor_digest: Digest,
    ) -> Result<Self, PluginError> {
        let consumer = Self {
            id,
            service_id,
            kind,
            required_version,
            descriptor_digest,
        };
        consumer.validate()?;
        Ok(consumer)
    }

    pub fn id(&self) -> &ConsumerId {
        &self.id
    }

    pub fn service_id(&self) -> &ServiceId {
        &self.service_id
    }

    pub const fn kind(&self) -> ConsumerKind {
        self.kind
    }

    pub const fn required_version(&self) -> PluginVersion {
        self.required_version
    }

    pub fn descriptor_digest(&self) -> &Digest {
        &self.descriptor_digest
    }

    fn validate(&self) -> Result<(), PluginError> {
        self.id.validate()?;
        self.service_id.validate()?;
        self.descriptor_digest.validate()
    }
}

impl fmt::Debug for ConsumerDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsumerDefinition")
            .field("id_digest", &Digest::from_text(self.id.as_str()))
            .field(
                "service_id_digest",
                &Digest::from_text(self.service_id.as_str()),
            )
            .field("kind", &self.kind)
            .field("required_version", &self.required_version)
            .field("descriptor_digest", &self.descriptor_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    MissionLifecycle,
    Conversation,
    Result,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventContribution {
    id: EventId,
    kind: EventKind,
    descriptor_digest: Digest,
}

impl EventContribution {
    pub fn new(
        id: EventId,
        kind: EventKind,
        descriptor_digest: Digest,
    ) -> Result<Self, PluginError> {
        let contribution = Self {
            id,
            kind,
            descriptor_digest,
        };
        contribution.validate()?;
        Ok(contribution)
    }

    pub fn id(&self) -> &EventId {
        &self.id
    }

    pub const fn kind(&self) -> EventKind {
        self.kind
    }

    pub fn descriptor_digest(&self) -> &Digest {
        &self.descriptor_digest
    }

    fn validate(&self) -> Result<(), PluginError> {
        self.id.validate()?;
        self.descriptor_digest.validate()
    }
}

impl fmt::Debug for EventContribution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventContribution")
            .field("id_digest", &Digest::from_text(self.id.as_str()))
            .field("kind", &self.kind)
            .field("descriptor_digest", &self.descriptor_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UiSurfaceKind {
    ConversationNode,
    ResultSurface,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiSurfaceContribution {
    id: UiSurfaceId,
    kind: UiSurfaceKind,
    descriptor_digest: Digest,
}

impl UiSurfaceContribution {
    pub fn conversation_node(
        id: UiSurfaceId,
        descriptor_digest: Digest,
    ) -> Result<Self, PluginError> {
        Self::new(id, UiSurfaceKind::ConversationNode, descriptor_digest)
    }

    pub fn result_surface(id: UiSurfaceId, descriptor_digest: Digest) -> Result<Self, PluginError> {
        Self::new(id, UiSurfaceKind::ResultSurface, descriptor_digest)
    }

    fn new(
        id: UiSurfaceId,
        kind: UiSurfaceKind,
        descriptor_digest: Digest,
    ) -> Result<Self, PluginError> {
        let contribution = Self {
            id,
            kind,
            descriptor_digest,
        };
        contribution.validate()?;
        Ok(contribution)
    }

    pub fn id(&self) -> &UiSurfaceId {
        &self.id
    }

    pub const fn kind(&self) -> UiSurfaceKind {
        self.kind
    }

    pub fn descriptor_digest(&self) -> &Digest {
        &self.descriptor_digest
    }

    fn validate(&self) -> Result<(), PluginError> {
        self.id.validate()?;
        self.descriptor_digest.validate()
    }
}

impl fmt::Debug for UiSurfaceContribution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UiSurfaceContribution")
            .field("id_digest", &Digest::from_text(self.id.as_str()))
            .field("kind", &self.kind)
            .field("descriptor_digest", &self.descriptor_digest)
            .finish()
    }
}

#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginContributions {
    pub services: Vec<ServiceDefinition>,
    pub providers: Vec<ProviderDefinition>,
    pub consumers: Vec<ConsumerDefinition>,
    pub events: Vec<EventContribution>,
    pub ui_surfaces: Vec<UiSurfaceContribution>,
}

impl PluginContributions {
    pub fn total_count(&self) -> usize {
        self.services.len()
            + self.providers.len()
            + self.consumers.len()
            + self.events.len()
            + self.ui_surfaces.len()
    }

    fn validate(&self) -> Result<(), PluginError> {
        if self.total_count() == 0 {
            return Err(PluginError::InvalidDefinition);
        }
        for service in &self.services {
            service.validate()?;
        }
        for provider in &self.providers {
            provider.validate()?;
        }
        for consumer in &self.consumers {
            consumer.validate()?;
        }
        for event in &self.events {
            event.validate()?;
        }
        for surface in &self.ui_surfaces {
            surface.validate()?;
        }
        ensure_unique(
            self.services.iter().map(|service| &service.id),
            PluginError::DuplicateServiceDefinition,
        )?;
        ensure_unique(
            self.providers.iter().map(|provider| &provider.id),
            PluginError::DuplicateProvider,
        )?;
        ensure_unique(
            self.consumers.iter().map(|consumer| &consumer.id),
            PluginError::DuplicateConsumer,
        )?;
        ensure_unique(
            self.events.iter().map(|event| &event.id),
            PluginError::DuplicateEvent,
        )?;
        ensure_unique(
            self.ui_surfaces.iter().map(|surface| &surface.id),
            PluginError::DuplicateUiSurface,
        )
    }
}

impl fmt::Debug for PluginContributions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginContributions")
            .field("service_count", &self.services.len())
            .field("provider_count", &self.providers.len())
            .field("consumer_count", &self.consumers.len())
            .field("event_count", &self.events.len())
            .field("ui_surface_count", &self.ui_surfaces.len())
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginIdentity {
    plugin_id: PluginId,
    version: PluginVersion,
    digest: Digest,
}

impl PluginIdentity {
    pub fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    fn validate(&self) -> Result<(), PluginError> {
        self.plugin_id.validate()?;
        self.digest.validate()
    }
}

impl fmt::Debug for PluginIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginIdentity")
            .field(
                "plugin_id_digest",
                &Digest::from_text(self.plugin_id.as_str()),
            )
            .field("version", &self.version)
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginDefinition {
    schema: String,
    identity: PluginIdentity,
    scope: PluginScope,
    contributions: PluginContributions,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginDefinitionBody<'a> {
    schema: &'a str,
    plugin_id: &'a PluginId,
    version: PluginVersion,
    scope: &'a PluginScope,
    contributions: &'a PluginContributions,
}

impl PluginDefinition {
    pub fn new(
        plugin_id: PluginId,
        version: PluginVersion,
        scope: PluginScope,
        contributions: PluginContributions,
    ) -> Result<Self, PluginError> {
        let mut definition = Self {
            schema: PLUGIN_DEFINITION_SCHEMA.into(),
            identity: PluginIdentity {
                plugin_id,
                version,
                digest: Digest::from_text("pending-plugin-digest"),
            },
            scope,
            contributions,
        };
        definition.validate_without_digest()?;
        definition.identity.digest = definition.computed_digest();
        definition.validate()?;
        Ok(definition)
    }

    pub fn identity(&self) -> &PluginIdentity {
        &self.identity
    }

    pub fn plugin_id(&self) -> &PluginId {
        self.identity.plugin_id()
    }

    pub const fn version(&self) -> PluginVersion {
        self.identity.version()
    }

    pub fn scope(&self) -> &PluginScope {
        &self.scope
    }

    pub fn contributions(&self) -> &PluginContributions {
        &self.contributions
    }

    pub fn digest(&self) -> &Digest {
        self.identity.digest()
    }

    pub fn validate(&self) -> Result<(), PluginError> {
        self.validate_without_digest()?;
        if self.identity.digest != self.computed_digest() {
            return Err(PluginError::DigestMismatch);
        }
        Ok(())
    }

    fn validate_without_digest(&self) -> Result<(), PluginError> {
        if self.schema != PLUGIN_DEFINITION_SCHEMA {
            return Err(PluginError::InvalidSchema);
        }
        self.identity.validate()?;
        self.scope.validate()?;
        self.contributions.validate()
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&PluginDefinitionBody {
            schema: &self.schema,
            plugin_id: &self.identity.plugin_id,
            version: self.identity.version,
            scope: &self.scope,
            contributions: &self.contributions,
        })
    }
}

impl fmt::Debug for PluginDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginDefinition")
            .field("schema", &self.schema)
            .field("identity", &self.identity)
            .field("scope", &self.scope)
            .field("contributions", &self.contributions)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DefinitionKey {
    plugin_id: PluginId,
    version: PluginVersion,
    digest: Digest,
    scope: PluginScope,
}

impl DefinitionKey {
    fn from_definition(definition: &PluginDefinition) -> Self {
        Self {
            plugin_id: definition.plugin_id().clone(),
            version: definition.version(),
            digest: definition.digest().clone(),
            scope: definition.scope().clone(),
        }
    }
}

/// A runtime-owned handle to a validated definition. It has no public
/// constructor or deserializer, so a caller cannot manufacture a handle for
/// an unregistered definition or another scope.
#[derive(Clone, Eq, PartialEq)]
pub struct PluginDefinitionHandle {
    key: DefinitionKey,
}

impl PluginDefinitionHandle {
    pub fn plugin_id(&self) -> &PluginId {
        &self.key.plugin_id
    }

    pub const fn version(&self) -> PluginVersion {
        self.key.version
    }

    pub fn digest(&self) -> &Digest {
        &self.key.digest
    }

    pub fn scope(&self) -> &PluginScope {
        &self.key.scope
    }
}

impl fmt::Debug for PluginDefinitionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginDefinitionHandle")
            .field(
                "plugin_id_digest",
                &Digest::from_text(self.plugin_id().as_str()),
            )
            .field("version", &self.version())
            .field("definition_digest", &self.digest())
            .field("scope_digest", &self.scope().digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginLifecycle {
    Defined,
    Mounted,
    Stopping,
    Stopped,
    Revoked,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ContributionKey {
    Service(ServiceId),
    Provider(ProviderId),
    Consumer(ConsumerId),
    Event(EventId),
    UiSurface(UiSurfaceId),
}

#[derive(Clone)]
struct RegisteredService {
    owner: Digest,
    definition: ServiceDefinition,
}

#[derive(Clone)]
struct RegisteredProvider {
    owner: Digest,
    definition: ProviderDefinition,
}

#[derive(Clone)]
struct RegisteredConsumer {
    owner: Digest,
    definition: ConsumerDefinition,
}

#[derive(Clone)]
struct RegisteredEvent {
    owner: Digest,
    contribution: EventContribution,
}

#[derive(Clone)]
struct RegisteredUiSurface {
    owner: Digest,
    contribution: UiSurfaceContribution,
}

#[derive(Clone, Default)]
struct ScopeRegistry {
    services: BTreeMap<ServiceId, RegisteredService>,
    providers: BTreeMap<ProviderId, RegisteredProvider>,
    consumers: BTreeMap<ConsumerId, RegisteredConsumer>,
    events: BTreeMap<EventId, RegisteredEvent>,
    ui_surfaces: BTreeMap<UiSurfaceId, RegisteredUiSurface>,
}

impl ScopeRegistry {
    fn stage_mount(
        mut self,
        definition: &PluginDefinition,
        owner: &Digest,
        fault: MountFault,
    ) -> Result<(Self, Vec<ContributionKey>), PluginError> {
        let mut keys = Vec::new();
        let mut progress = 0;

        self.stage_services(definition, owner, &mut keys, &mut progress, fault)?;
        self.stage_providers(definition, owner, &mut keys, &mut progress, fault)?;
        self.stage_consumers(definition, owner, &mut keys, &mut progress, fault)?;
        self.stage_events(definition, owner, &mut keys, &mut progress, fault)?;
        self.stage_ui_surfaces(definition, owner, &mut keys, &mut progress, fault)?;
        self.validate_references()?;
        Ok((self, keys))
    }

    fn stage_services(
        &mut self,
        definition: &PluginDefinition,
        owner: &Digest,
        keys: &mut Vec<ContributionKey>,
        progress: &mut usize,
        fault: MountFault,
    ) -> Result<(), PluginError> {
        for service in &definition.contributions.services {
            if self.services.contains_key(service.id()) {
                return Err(PluginError::DuplicateServiceDefinition);
            }
            self.services.insert(
                service.id().clone(),
                RegisteredService {
                    owner: owner.clone(),
                    definition: service.clone(),
                },
            );
            keys.push(ContributionKey::Service(service.id().clone()));
            if let Some(error) = trip_fault(fault, progress) {
                return Err(error);
            }
        }
        Ok(())
    }

    fn stage_providers(
        &mut self,
        definition: &PluginDefinition,
        owner: &Digest,
        keys: &mut Vec<ContributionKey>,
        progress: &mut usize,
        fault: MountFault,
    ) -> Result<(), PluginError> {
        for provider in &definition.contributions.providers {
            if self.providers.contains_key(provider.id()) {
                return Err(PluginError::DuplicateProvider);
            }
            let service = self
                .services
                .get(provider.service_id())
                .ok_or(PluginError::MissingService)?;
            if !service
                .definition
                .compatibility()
                .accepts(service.definition.version(), provider.version())
            {
                return Err(PluginError::ProviderIncompatible);
            }
            if service.definition.cardinality() == ProviderCardinality::Singleton
                && self
                    .providers
                    .values()
                    .any(|registered| registered.definition.service_id() == provider.service_id())
            {
                return Err(PluginError::ProviderCardinalityExceeded);
            }
            self.providers.insert(
                provider.id().clone(),
                RegisteredProvider {
                    owner: owner.clone(),
                    definition: provider.clone(),
                },
            );
            keys.push(ContributionKey::Provider(provider.id().clone()));
            if let Some(error) = trip_fault(fault, progress) {
                return Err(error);
            }
        }
        Ok(())
    }

    fn stage_consumers(
        &mut self,
        definition: &PluginDefinition,
        owner: &Digest,
        keys: &mut Vec<ContributionKey>,
        progress: &mut usize,
        fault: MountFault,
    ) -> Result<(), PluginError> {
        for consumer in &definition.contributions.consumers {
            if self.consumers.contains_key(consumer.id()) {
                return Err(PluginError::DuplicateConsumer);
            }
            let service = self
                .services
                .get(consumer.service_id())
                .ok_or(PluginError::MissingService)?;
            let has_provider = self.providers.values().any(|registered| {
                registered.definition.service_id() == consumer.service_id()
                    && service
                        .definition
                        .compatibility()
                        .accepts(consumer.required_version(), registered.definition.version())
            });
            if !has_provider {
                return Err(PluginError::ConsumerIncompatible);
            }
            self.consumers.insert(
                consumer.id().clone(),
                RegisteredConsumer {
                    owner: owner.clone(),
                    definition: consumer.clone(),
                },
            );
            keys.push(ContributionKey::Consumer(consumer.id().clone()));
            if let Some(error) = trip_fault(fault, progress) {
                return Err(error);
            }
        }
        Ok(())
    }

    fn stage_events(
        &mut self,
        definition: &PluginDefinition,
        owner: &Digest,
        keys: &mut Vec<ContributionKey>,
        progress: &mut usize,
        fault: MountFault,
    ) -> Result<(), PluginError> {
        for event in &definition.contributions.events {
            if self.events.contains_key(event.id()) {
                return Err(PluginError::DuplicateEvent);
            }
            self.events.insert(
                event.id().clone(),
                RegisteredEvent {
                    owner: owner.clone(),
                    contribution: event.clone(),
                },
            );
            keys.push(ContributionKey::Event(event.id().clone()));
            if let Some(error) = trip_fault(fault, progress) {
                return Err(error);
            }
        }
        Ok(())
    }

    fn stage_ui_surfaces(
        &mut self,
        definition: &PluginDefinition,
        owner: &Digest,
        keys: &mut Vec<ContributionKey>,
        progress: &mut usize,
        fault: MountFault,
    ) -> Result<(), PluginError> {
        for surface in &definition.contributions.ui_surfaces {
            if self.ui_surfaces.contains_key(surface.id()) {
                return Err(PluginError::DuplicateUiSurface);
            }
            self.ui_surfaces.insert(
                surface.id().clone(),
                RegisteredUiSurface {
                    owner: owner.clone(),
                    contribution: surface.clone(),
                },
            );
            keys.push(ContributionKey::UiSurface(surface.id().clone()));
            if let Some(error) = trip_fault(fault, progress) {
                return Err(error);
            }
        }
        Ok(())
    }

    fn remove_reverse(&mut self, keys: &[ContributionKey]) -> Result<(), PluginError> {
        for key in keys.iter().rev() {
            let removed = match key {
                ContributionKey::Service(id) => self.services.remove(id).is_some(),
                ContributionKey::Provider(id) => self.providers.remove(id).is_some(),
                ContributionKey::Consumer(id) => self.consumers.remove(id).is_some(),
                ContributionKey::Event(id) => self.events.remove(id).is_some(),
                ContributionKey::UiSurface(id) => self.ui_surfaces.remove(id).is_some(),
            };
            if !removed {
                return Err(PluginError::InvalidReceipt);
            }
        }
        Ok(())
    }

    fn validate_references(&self) -> Result<(), PluginError> {
        for provider in self.providers.values() {
            let service = self
                .services
                .get(provider.definition.service_id())
                .ok_or(PluginError::MissingService)?;
            if !service
                .definition
                .compatibility()
                .accepts(service.definition.version(), provider.definition.version())
            {
                return Err(PluginError::ProviderIncompatible);
            }
        }
        for consumer in self.consumers.values() {
            let service = self
                .services
                .get(consumer.definition.service_id())
                .ok_or(PluginError::MissingService)?;
            let has_provider = self.providers.values().any(|provider| {
                provider.definition.service_id() == consumer.definition.service_id()
                    && service.definition.compatibility().accepts(
                        consumer.definition.required_version(),
                        provider.definition.version(),
                    )
            });
            if !has_provider {
                return Err(PluginError::ConsumerIncompatible);
            }
        }
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.services.is_empty()
            && self.providers.is_empty()
            && self.consumers.is_empty()
            && self.events.is_empty()
            && self.ui_surfaces.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContributionCounts {
    pub services: usize,
    pub providers: usize,
    pub consumers: usize,
    pub events: usize,
    pub ui_surfaces: usize,
}

impl ContributionCounts {
    pub const fn total(&self) -> usize {
        self.services + self.providers + self.consumers + self.events + self.ui_surfaces
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInspection {
    pub service_id_digest: Digest,
    pub owner_plugin_digest: Digest,
    pub version: PluginVersion,
    pub access: ServiceAccess,
    pub cardinality: ProviderCardinality,
    pub compatibility: CompatibilityPolicy,
    pub contract_digest: Digest,
    pub provider_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInspection {
    pub provider_id_digest: Digest,
    pub service_id_digest: Digest,
    pub owner_plugin_digest: Digest,
    pub version: PluginVersion,
    pub implementation_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerInspection {
    pub consumer_id_digest: Digest,
    pub service_id_digest: Digest,
    pub owner_plugin_digest: Digest,
    pub kind: ConsumerKind,
    pub required_version: PluginVersion,
    pub descriptor_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventInspection {
    pub event_id_digest: Digest,
    pub owner_plugin_digest: Digest,
    pub kind: EventKind,
    pub descriptor_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiSurfaceInspection {
    pub surface_id_digest: Digest,
    pub owner_plugin_digest: Digest,
    pub kind: UiSurfaceKind,
    pub descriptor_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MountedPluginInspection {
    pub plugin_digest: Digest,
    pub scope_digest: Digest,
    pub version: PluginVersion,
    pub receipt_digest: Digest,
    pub contribution_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeInspection {
    pub schema: String,
    pub scope_digest: Digest,
    pub generation: u64,
    pub plugins: Vec<MountedPluginInspection>,
    pub services: Vec<ServiceInspection>,
    pub providers: Vec<ProviderInspection>,
    pub consumers: Vec<ConsumerInspection>,
    pub events: Vec<EventInspection>,
    pub ui_surfaces: Vec<UiSurfaceInspection>,
}

impl RuntimeInspection {
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
            && self.services.is_empty()
            && self.providers.is_empty()
            && self.consumers.is_empty()
            && self.events.is_empty()
            && self.ui_surfaces.is_empty()
    }

    pub fn contribution_counts(&self) -> ContributionCounts {
        ContributionCounts {
            services: self.services.len(),
            providers: self.providers.len(),
            consumers: self.consumers.len(),
            events: self.events.len(),
            ui_surfaces: self.ui_surfaces.len(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginLifecycleInspection {
    pub plugin_digest: Digest,
    pub scope_digest: Digest,
    pub version: PluginVersion,
    pub lifecycle: PluginLifecycle,
    pub failure: Option<PluginErrorCode>,
    pub receipt_digest: Option<Digest>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RegistrationReceipt {
    key: DefinitionKey,
    plugin_digest: Digest,
    scope: PluginScope,
    generation: u64,
    registry_revision: u64,
    contribution_digest: Digest,
    contribution_count: usize,
    receipt_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationReceiptBody<'a> {
    schema: &'static str,
    plugin_digest: &'a Digest,
    scope_digest: &'a Digest,
    generation: u64,
    registry_revision: u64,
    contribution_digest: &'a Digest,
    contribution_count: usize,
}

impl RegistrationReceipt {
    fn new(
        key: DefinitionKey,
        definition: &PluginDefinition,
        registry_revision: u64,
        keys: &[ContributionKey],
    ) -> Self {
        let plugin_digest = definition.digest().clone();
        let scope = definition.scope().clone();
        let contribution_digest = Digest::from_serialized(keys);
        let mut receipt = Self {
            key,
            plugin_digest,
            scope,
            generation: definition.scope().generation(),
            registry_revision,
            contribution_digest,
            contribution_count: keys.len(),
            receipt_digest: Digest::from_text("unsealed-plugin-receipt"),
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt
    }

    pub fn digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub fn plugin_digest(&self) -> &Digest {
        &self.plugin_digest
    }

    pub fn scope_digest(&self) -> Digest {
        self.scope.digest()
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn registry_revision(&self) -> u64 {
        self.registry_revision
    }

    pub const fn contribution_count(&self) -> usize {
        self.contribution_count
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&RegistrationReceiptBody {
            schema: PLUGIN_RECEIPT_SCHEMA,
            plugin_digest: &self.plugin_digest,
            scope_digest: &self.scope.digest(),
            generation: self.generation,
            registry_revision: self.registry_revision,
            contribution_digest: &self.contribution_digest,
            contribution_count: self.contribution_count,
        })
    }

    fn validate(&self) -> Result<(), PluginError> {
        if self.key.digest != self.plugin_digest
            || self.key.scope != self.scope
            || self.generation != self.scope.generation()
            || self.registry_revision == 0
            || self.contribution_count == 0
            || self.plugin_digest.validate().is_err()
            || self.contribution_digest.validate().is_err()
            || self.receipt_digest != self.computed_digest()
        {
            return Err(PluginError::InvalidReceipt);
        }
        Ok(())
    }
}

impl Serialize for RegistrationReceipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("RegistrationReceipt", 8)?;
        state.serialize_field("schema", PLUGIN_RECEIPT_SCHEMA)?;
        state.serialize_field("receiptDigest", &self.receipt_digest)?;
        state.serialize_field("pluginDigest", &self.plugin_digest)?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field("generation", &self.generation)?;
        state.serialize_field("registryRevision", &self.registry_revision)?;
        state.serialize_field("contributionDigest", &self.contribution_digest)?;
        state.serialize_field("contributionCount", &self.contribution_count)?;
        state.end()
    }
}

impl fmt::Debug for RegistrationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistrationReceipt")
            .field("receipt_digest", &self.receipt_digest)
            .field("plugin_digest", &self.plugin_digest)
            .field("scope_digest", &self.scope.digest())
            .field("generation", &self.generation)
            .field("registry_revision", &self.registry_revision)
            .field("contribution_digest", &self.contribution_digest)
            .field("contribution_count", &self.contribution_count)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnmountReceipt {
    pub plugin_digest: Digest,
    pub scope_digest: Digest,
    pub mount_revision: u64,
    pub unmount_revision: u64,
    pub contribution_count: usize,
    pub receipt_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationReceipt {
    pub plugin_digest: Digest,
    pub scope_digest: Digest,
    pub revocation_revision: u64,
    pub receipt_digest: Digest,
}

#[derive(Clone)]
struct PluginRecord {
    definition: PluginDefinition,
    lifecycle: PluginLifecycle,
    failure: Option<PluginErrorCode>,
    receipt: Option<RegistrationReceipt>,
    active_keys: Vec<ContributionKey>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MissionKey {
    project_id: ProjectId,
    mission_id: MissionId,
}

impl MissionKey {
    fn from_scope(scope: &PluginScope) -> Self {
        Self {
            project_id: scope.project_id.clone(),
            mission_id: scope.mission_id.clone(),
        }
    }
}

#[derive(Clone, Copy)]
enum MountFault {
    None,
    #[cfg(test)]
    FailAfter(usize),
    #[cfg(test)]
    PanicAfter(usize),
}

fn trip_fault(fault: MountFault, progress: &mut usize) -> Option<PluginError> {
    *progress += 1;
    match fault {
        MountFault::None => None,
        #[cfg(test)]
        MountFault::FailAfter(step) if step == *progress => Some(PluginError::MountFailed),
        #[cfg(test)]
        MountFault::PanicAfter(step) if step == *progress => {
            panic!("injected plugin mount panic")
        }
        #[cfg(test)]
        MountFault::FailAfter(_) | MountFault::PanicAfter(_) => None,
    }
}

/// The in-process plugin composition kernel. All registries are scoped by the
/// exact Project/Mission/generation tuple; no host object or executable
/// callback is stored here.
pub struct PluginRuntime {
    definitions: BTreeMap<DefinitionKey, PluginRecord>,
    scopes: BTreeMap<PluginScope, ScopeRegistry>,
    generations: BTreeMap<MissionKey, u64>,
    registry_revision: u64,
}

impl Default for PluginRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PluginRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginRuntime")
            .field("schema", &PLUGIN_RUNTIME_SCHEMA)
            .field("definition_count", &self.definitions.len())
            .field("active_scope_count", &self.scopes.len())
            .field("generation_scope_count", &self.generations.len())
            .field("registry_revision", &self.registry_revision)
            .finish_non_exhaustive()
    }
}

impl PluginRuntime {
    pub fn new() -> Self {
        Self {
            definitions: BTreeMap::new(),
            scopes: BTreeMap::new(),
            generations: BTreeMap::new(),
            registry_revision: 0,
        }
    }

    pub fn define(
        &mut self,
        definition: PluginDefinition,
    ) -> Result<PluginDefinitionHandle, PluginError> {
        definition.validate()?;
        let key = DefinitionKey::from_definition(&definition);
        if self.definitions.contains_key(&key) {
            return Err(PluginError::DefinitionAlreadyExists);
        }
        let handle = PluginDefinitionHandle { key: key.clone() };
        self.definitions.insert(
            key,
            PluginRecord {
                definition,
                lifecycle: PluginLifecycle::Defined,
                failure: None,
                receipt: None,
                active_keys: Vec::new(),
            },
        );
        Ok(handle)
    }

    pub fn mount(
        &mut self,
        handle: &PluginDefinitionHandle,
    ) -> Result<RegistrationReceipt, PluginError> {
        self.mount_internal(handle, MountFault::None)
    }

    pub fn mount_in_scope(
        &mut self,
        handle: &PluginDefinitionHandle,
        expected_scope: &PluginScope,
    ) -> Result<RegistrationReceipt, PluginError> {
        if handle.scope() != expected_scope {
            return Err(PluginError::ScopeMismatch);
        }
        self.mount(handle)
    }

    fn mount_internal(
        &mut self,
        handle: &PluginDefinitionHandle,
        fault: MountFault,
    ) -> Result<RegistrationReceipt, PluginError> {
        let record = self
            .definitions
            .get(&handle.key)
            .ok_or(PluginError::UnknownDefinition)?;
        match record.lifecycle {
            PluginLifecycle::Defined => {}
            PluginLifecycle::Mounted => return Err(PluginError::PluginAlreadyMounted),
            PluginLifecycle::Revoked => return Err(PluginError::PluginRevoked),
            PluginLifecycle::Stopping | PluginLifecycle::Stopped | PluginLifecycle::Failed => {
                return Err(PluginError::LifecycleViolation);
            }
        }
        let definition = record.definition.clone();
        let mission_key = MissionKey::from_scope(definition.scope());
        if self
            .generations
            .get(&mission_key)
            .is_some_and(|generation| *generation != definition.scope().generation())
        {
            return Err(self.fail_definition(&handle.key, PluginError::StaleGeneration));
        }
        if self.definitions.values().any(|candidate| {
            candidate.lifecycle == PluginLifecycle::Mounted
                && candidate.definition.plugin_id() == definition.plugin_id()
                && candidate.definition.scope() == definition.scope()
        }) {
            return Err(self.fail_definition(&handle.key, PluginError::PluginAlreadyMounted));
        }

        let current = self
            .scopes
            .get(definition.scope())
            .cloned()
            .unwrap_or_default();
        let staged = catch_unwind(AssertUnwindSafe(|| {
            current.stage_mount(&definition, definition.digest(), fault)
        }));
        let (staged, keys) = match staged {
            Ok(Ok(staged)) => staged,
            Ok(Err(error)) => return Err(self.fail_definition(&handle.key, error)),
            Err(_) => return Err(self.fail_definition(&handle.key, PluginError::MountPanicked)),
        };
        let next_revision = self.next_revision()?;
        let receipt =
            RegistrationReceipt::new(handle.key.clone(), &definition, next_revision, &keys);
        self.scopes.insert(definition.scope().clone(), staged);
        self.generations
            .entry(mission_key)
            .or_insert(definition.scope().generation());
        self.registry_revision = next_revision;
        let record = self
            .definitions
            .get_mut(&handle.key)
            .ok_or(PluginError::UnknownDefinition)?;
        record.lifecycle = PluginLifecycle::Mounted;
        record.failure = None;
        record.receipt = Some(receipt.clone());
        record.active_keys = keys;
        Ok(receipt)
    }

    pub fn unmount(
        &mut self,
        receipt: &RegistrationReceipt,
    ) -> Result<UnmountReceipt, PluginError> {
        receipt.validate()?;
        let key = receipt.key.clone();
        let record = self
            .definitions
            .get(&key)
            .ok_or(PluginError::InvalidReceipt)?;
        if record.receipt.as_ref() != Some(receipt) {
            return Err(PluginError::InvalidReceipt);
        }
        match record.lifecycle {
            PluginLifecycle::Mounted => {}
            PluginLifecycle::Revoked => return Err(PluginError::PluginRevoked),
            PluginLifecycle::Stopping | PluginLifecycle::Stopped => {
                return Err(PluginError::StaleReceipt);
            }
            PluginLifecycle::Defined | PluginLifecycle::Failed => {
                return Err(PluginError::LifecycleViolation);
            }
        }
        let definition = record.definition.clone();
        let active_keys = record.active_keys.clone();
        let mut staged = self
            .scopes
            .get(definition.scope())
            .cloned()
            .ok_or(PluginError::InvalidReceipt)?;
        staged.remove_reverse(&active_keys)?;
        staged
            .validate_references()
            .map_err(|_| PluginError::UnmountDependency)?;
        let next_revision = self.next_revision()?;
        let mount_revision = receipt.registry_revision();
        let unmount = UnmountReceipt {
            plugin_digest: definition.digest().clone(),
            scope_digest: definition.scope().digest(),
            mount_revision,
            unmount_revision: next_revision,
            contribution_count: active_keys.len(),
            receipt_digest: Digest::from_serialized(&(
                PLUGIN_RECEIPT_SCHEMA,
                definition.digest(),
                definition.scope().digest(),
                mount_revision,
                next_revision,
                active_keys.len(),
            )),
        };
        if staged.is_empty() {
            self.scopes.remove(definition.scope());
        } else {
            self.scopes.insert(definition.scope().clone(), staged);
        }
        self.registry_revision = next_revision;
        let record = self
            .definitions
            .get_mut(&key)
            .ok_or(PluginError::InvalidReceipt)?;
        record.lifecycle = PluginLifecycle::Stopped;
        record.active_keys.clear();
        Ok(unmount)
    }

    pub fn revoke(
        &mut self,
        handle: &PluginDefinitionHandle,
    ) -> Result<RevocationReceipt, PluginError> {
        let record = self
            .definitions
            .get(&handle.key)
            .ok_or(PluginError::UnknownDefinition)?;
        if record.lifecycle == PluginLifecycle::Revoked {
            return Err(PluginError::PluginRevoked);
        }
        let definition = record.definition.clone();
        let active_keys = record.active_keys.clone();
        let was_mounted = record.lifecycle == PluginLifecycle::Mounted;
        let staged = if was_mounted {
            let mut staged = self
                .scopes
                .get(definition.scope())
                .cloned()
                .ok_or(PluginError::InvalidReceipt)?;
            staged.remove_reverse(&active_keys)?;
            staged
                .validate_references()
                .map_err(|_| PluginError::UnmountDependency)?;
            Some(staged)
        } else {
            None
        };
        let next_revision = self.next_revision()?;
        if let Some(staged) = staged {
            if staged.is_empty() {
                self.scopes.remove(definition.scope());
            } else {
                self.scopes.insert(definition.scope().clone(), staged);
            }
        }
        self.registry_revision = next_revision;
        let record = self
            .definitions
            .get_mut(&handle.key)
            .ok_or(PluginError::UnknownDefinition)?;
        record.lifecycle = PluginLifecycle::Revoked;
        record.active_keys.clear();
        let scope_digest = definition.scope().digest();
        Ok(RevocationReceipt {
            plugin_digest: definition.digest().clone(),
            scope_digest: scope_digest.clone(),
            revocation_revision: next_revision,
            receipt_digest: Digest::from_serialized(&(
                PLUGIN_RUNTIME_SCHEMA,
                definition.digest(),
                scope_digest,
                next_revision,
            )),
        })
    }

    pub fn advance_generation(
        &mut self,
        project_id: ProjectId,
        mission_id: MissionId,
        next_generation: u64,
    ) -> Result<(), PluginError> {
        if next_generation == 0 {
            return Err(PluginError::InvalidScope);
        }
        let mission = MissionKey {
            project_id,
            mission_id,
        };
        if self
            .generations
            .get(&mission)
            .is_some_and(|current| next_generation <= *current)
        {
            return Err(PluginError::GenerationRegression);
        }
        let next_revision = self.next_revision()?;
        let affected: Vec<DefinitionKey> = self
            .definitions
            .iter()
            .filter(|(_, record)| {
                record.lifecycle == PluginLifecycle::Mounted
                    && record.definition.scope().project_id() == &mission.project_id
                    && record.definition.scope().mission_id() == &mission.mission_id
                    && record.definition.scope().generation() < next_generation
            })
            .map(|(key, _)| key.clone())
            .collect();
        let mut staged_scopes = self.scopes.clone();
        for key in &affected {
            let definition = &self
                .definitions
                .get(key)
                .ok_or(PluginError::UnknownDefinition)?
                .definition;
            let mut staged = staged_scopes
                .get(definition.scope())
                .cloned()
                .ok_or(PluginError::InvalidReceipt)?;
            let active_keys = self
                .definitions
                .get(key)
                .ok_or(PluginError::UnknownDefinition)?
                .active_keys
                .clone();
            staged.remove_reverse(&active_keys)?;
            staged
                .validate_references()
                .map_err(|_| PluginError::UnmountDependency)?;
            if staged.is_empty() {
                staged_scopes.remove(definition.scope());
            } else {
                staged_scopes.insert(definition.scope().clone(), staged);
            }
        }
        self.scopes = staged_scopes;
        self.generations.insert(mission, next_generation);
        for key in affected {
            let record = self
                .definitions
                .get_mut(&key)
                .ok_or(PluginError::UnknownDefinition)?;
            record.lifecycle = PluginLifecycle::Stopped;
            record.active_keys.clear();
        }
        self.registry_revision = next_revision;
        Ok(())
    }

    pub fn inspect(&self, scope: &PluginScope) -> RuntimeInspection {
        let mut inspection = self.scopes.get(scope).map_or_else(
            || empty_inspection(scope),
            |registry| registry.inspection(scope),
        );
        inspection.plugins = self
            .definitions
            .values()
            .filter(|record| {
                record.lifecycle == PluginLifecycle::Mounted && record.definition.scope() == scope
            })
            .filter_map(|record| {
                record
                    .receipt
                    .as_ref()
                    .map(|receipt| MountedPluginInspection {
                        plugin_digest: record.definition.digest().clone(),
                        scope_digest: scope.digest(),
                        version: record.definition.version(),
                        receipt_digest: receipt.digest().clone(),
                        contribution_count: receipt.contribution_count(),
                    })
            })
            .collect();
        inspection
    }

    pub fn lifecycle(
        &self,
        handle: &PluginDefinitionHandle,
    ) -> Result<PluginLifecycleInspection, PluginError> {
        let record = self
            .definitions
            .get(&handle.key)
            .ok_or(PluginError::UnknownDefinition)?;
        Ok(PluginLifecycleInspection {
            plugin_digest: record.definition.digest().clone(),
            scope_digest: record.definition.scope().digest(),
            version: record.definition.version(),
            lifecycle: record.lifecycle,
            failure: record.failure,
            receipt_digest: record
                .receipt
                .as_ref()
                .map(|receipt| receipt.digest().clone()),
        })
    }

    pub fn current_generation(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Option<u64> {
        self.generations
            .get(&MissionKey {
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
            })
            .copied()
    }

    fn fail_definition(&mut self, key: &DefinitionKey, error: PluginError) -> PluginError {
        if let Some(record) = self.definitions.get_mut(key) {
            record.lifecycle = PluginLifecycle::Failed;
            record.failure = Some(error.code());
        }
        error
    }

    fn next_revision(&self) -> Result<u64, PluginError> {
        self.registry_revision
            .checked_add(1)
            .ok_or(PluginError::RevisionOverflow)
    }

    #[cfg(test)]
    fn mount_with_fault(
        &mut self,
        handle: &PluginDefinitionHandle,
        fault: MountFault,
    ) -> Result<RegistrationReceipt, PluginError> {
        self.mount_internal(handle, fault)
    }
}

fn empty_inspection(scope: &PluginScope) -> RuntimeInspection {
    RuntimeInspection {
        schema: PLUGIN_INSPECTION_SCHEMA.into(),
        scope_digest: scope.digest(),
        generation: scope.generation(),
        plugins: Vec::new(),
        services: Vec::new(),
        providers: Vec::new(),
        consumers: Vec::new(),
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    }
}

impl ScopeRegistry {
    fn inspection(&self, scope: &PluginScope) -> RuntimeInspection {
        let mut services = Vec::new();
        for registered in self.services.values() {
            services.push(ServiceInspection {
                service_id_digest: Digest::from_text(registered.definition.id().as_str()),
                owner_plugin_digest: registered.owner.clone(),
                version: registered.definition.version(),
                access: registered.definition.access(),
                cardinality: registered.definition.cardinality(),
                compatibility: registered.definition.compatibility(),
                contract_digest: registered.definition.contract_digest().clone(),
                provider_count: self
                    .providers
                    .values()
                    .filter(|provider| {
                        provider.definition.service_id() == registered.definition.id()
                    })
                    .count(),
            });
        }
        let providers = self
            .providers
            .values()
            .map(|registered| ProviderInspection {
                provider_id_digest: Digest::from_text(registered.definition.id().as_str()),
                service_id_digest: Digest::from_text(registered.definition.service_id().as_str()),
                owner_plugin_digest: registered.owner.clone(),
                version: registered.definition.version(),
                implementation_digest: registered.definition.implementation_digest().clone(),
            })
            .collect();
        let consumers = self
            .consumers
            .values()
            .map(|registered| ConsumerInspection {
                consumer_id_digest: Digest::from_text(registered.definition.id().as_str()),
                service_id_digest: Digest::from_text(registered.definition.service_id().as_str()),
                owner_plugin_digest: registered.owner.clone(),
                kind: registered.definition.kind(),
                required_version: registered.definition.required_version(),
                descriptor_digest: registered.definition.descriptor_digest().clone(),
            })
            .collect();
        let events = self
            .events
            .values()
            .map(|registered| EventInspection {
                event_id_digest: Digest::from_text(registered.contribution.id().as_str()),
                owner_plugin_digest: registered.owner.clone(),
                kind: registered.contribution.kind(),
                descriptor_digest: registered.contribution.descriptor_digest().clone(),
            })
            .collect();
        let ui_surfaces = self
            .ui_surfaces
            .values()
            .map(|registered| UiSurfaceInspection {
                surface_id_digest: Digest::from_text(registered.contribution.id().as_str()),
                owner_plugin_digest: registered.owner.clone(),
                kind: registered.contribution.kind(),
                descriptor_digest: registered.contribution.descriptor_digest().clone(),
            })
            .collect();
        RuntimeInspection {
            schema: PLUGIN_INSPECTION_SCHEMA.into(),
            scope_digest: scope.digest(),
            generation: scope.generation(),
            plugins: Vec::new(),
            services,
            providers,
            consumers,
            events,
            ui_surfaces,
        }
    }
}

pub mod provenance;
pub mod sample;
pub mod skill;

fn ensure_unique<'a, I, T>(values: I, duplicate: PluginError) -> Result<(), PluginError>
where
    I: IntoIterator<Item = &'a T>,
    T: Ord + 'a,
{
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(duplicate);
        }
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.trim() != value {
        return false;
    }
    value.split('.').all(|segment| {
        let mut bytes = segment.bytes();
        matches!(bytes.next(), Some(b'a'..=b'z'))
            && bytes.all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            })
    })
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{sample::SampleReadOnlyPlugin, *};

    fn scope(generation: u64) -> PluginScope {
        PluginScope::new(
            ProjectId::new("project.sample").expect("project"),
            MissionId::new("mission.sample").expect("mission"),
            generation,
        )
        .expect("scope")
    }

    #[test]
    fn panic_during_staging_leaves_no_registry_entries() {
        let definition = SampleReadOnlyPlugin::definition(scope(1), PluginVersion::new(1, 0, 0))
            .expect("sample definition");
        let mut runtime = PluginRuntime::new();
        let handle = runtime.define(definition).expect("defined");

        let error = runtime
            .mount_with_fault(&handle, MountFault::PanicAfter(1))
            .expect_err("panic is contained");
        assert_eq!(error, PluginError::MountPanicked);
        assert!(runtime.inspect(handle.scope()).is_empty());
        assert_eq!(
            runtime.lifecycle(&handle).expect("lifecycle").lifecycle,
            PluginLifecycle::Failed
        );
    }

    #[test]
    fn failure_during_staging_is_atomic() {
        let definition = SampleReadOnlyPlugin::definition(scope(1), PluginVersion::new(1, 0, 0))
            .expect("sample definition");
        let mut runtime = PluginRuntime::new();
        let handle = runtime.define(definition).expect("defined");

        let error = runtime
            .mount_with_fault(&handle, MountFault::FailAfter(2))
            .expect_err("failure is contained");
        assert_eq!(error, PluginError::MountFailed);
        assert!(runtime.inspect(handle.scope()).is_empty());
    }
}
