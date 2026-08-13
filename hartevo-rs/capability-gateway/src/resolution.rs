//! Read-only Mission composition for capability-backed plugin contributions.
//!
//! The snapshot is an inspection contract supplied by the composition owner;
//! this module does not register, mount, unmount, revoke, or execute providers.
//! Resolution only validates the closed service/provider/consumer loop and
//! issues typed, releasable receipts for a later runtime bridge.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use super::{
    CAPABILITY_REQUEST_SCHEMA, CapabilityClass, CapabilityGateway, CapabilityManifest,
    CapabilityRequest, Digest, GatewayError, InvocationPermit, SignedCapabilityManifest,
    digest_serialized,
};
use hartevo_domain_kernel::{MissionId, ProjectId};

pub const CAPABILITY_COMPOSITION_SCHEMA: &str = "hartevo.capability-composition/v1";
pub const CAPABILITY_RESOLUTION_SCHEMA: &str = "hartevo.capability-resolution/v1";
pub const CAPABILITY_RESOLUTION_RECEIPT_SCHEMA: &str = "hartevo.capability-resolution-receipt/v1";
pub const CAPABILITY_RESOLUTION_AUDIT_SCHEMA: &str = "hartevo.capability-resolution-audit/v1";
pub const MAX_COMPOSITION_CONTRIBUTIONS: usize = 1024;

/// A semver-like version used by the typed service/provider/consumer bridge.
/// The resolver intentionally requires an exact version for this slice.
#[derive(Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl CapabilityVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn parse(value: &str) -> Result<Self, CapabilityResolutionError> {
        let mut parts = value.split('.');
        let major = parse_version_part(parts.next())?;
        let minor = parse_version_part(parts.next())?;
        let patch = parse_version_part(parts.next())?;
        if parts.next().is_some() {
            return Err(CapabilityResolutionError::InvalidVersion);
        }
        Ok(Self::new(major, minor, patch))
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

impl fmt::Debug for CapabilityVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityVersion")
            .field("major", &self.major)
            .field("minor", &self.minor)
            .field("patch", &self.patch)
            .finish()
    }
}

impl fmt::Display for CapabilityVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

fn parse_version_part(value: Option<&str>) -> Result<u16, CapabilityResolutionError> {
    let value = value.ok_or(CapabilityResolutionError::InvalidVersion)?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(CapabilityResolutionError::InvalidVersion);
    }
    value
        .parse()
        .map_err(|_| CapabilityResolutionError::InvalidVersion)
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityCompositionScope {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub generation: u64,
    pub scope_digest: Digest,
}

impl CapabilityCompositionScope {
    pub fn new(
        project_id: ProjectId,
        mission_id: MissionId,
        generation: u64,
        scope_digest: Digest,
    ) -> Result<Self, CapabilityResolutionError> {
        let scope = Self {
            project_id,
            mission_id,
            generation,
            scope_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    fn validate(&self) -> Result<(), CapabilityResolutionError> {
        if self.generation == 0
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || !is_digest(&self.scope_digest)
        {
            return Err(CapabilityResolutionError::InvalidComposition);
        }
        Ok(())
    }

    fn matches_scope(&self, other: &Self) -> bool {
        self.project_id == other.project_id
            && self.mission_id == other.mission_id
            && self.generation == other.generation
            && self.scope_digest == other.scope_digest
    }
}

impl Serialize for CapabilityCompositionScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityCompositionScope", 4)?;
        state.serialize_field(
            "projectDigest",
            &Digest::from_text(self.project_id.as_str()),
        )?;
        state.serialize_field(
            "missionDigest",
            &Digest::from_text(self.mission_id.as_str()),
        )?;
        state.serialize_field("generation", &self.generation)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityCompositionScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityCompositionScope")
            .field(
                "project_digest",
                &Digest::from_text(self.project_id.as_str()),
            )
            .field(
                "mission_digest",
                &Digest::from_text(self.mission_id.as_str()),
            )
            .field("generation", &self.generation)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityCompositionLifecycle {
    Mounted,
    Unmounted,
    Revoked,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributionLifecycle {
    Active,
    Unmounted,
    Revoked,
    Stale,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityServiceDefinition {
    pub service_id_digest: Digest,
    pub owner_plugin_digest: Digest,
    pub capability_digest: Digest,
    pub class: CapabilityClass,
    pub version: CapabilityVersion,
    pub contract_digest: Digest,
    pub policy_digest: Digest,
    pub provider_count: usize,
    pub lifecycle: ContributionLifecycle,
}

impl CapabilityServiceDefinition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        service_id_digest: Digest,
        owner_plugin_digest: Digest,
        capability_digest: Digest,
        class: CapabilityClass,
        version: CapabilityVersion,
        contract_digest: Digest,
        policy_digest: Digest,
        provider_count: usize,
        lifecycle: ContributionLifecycle,
    ) -> Result<Self, CapabilityResolutionError> {
        let service = Self {
            service_id_digest,
            owner_plugin_digest,
            capability_digest,
            class,
            version,
            contract_digest,
            policy_digest,
            provider_count,
            lifecycle,
        };
        service.validate()?;
        Ok(service)
    }

    fn validate(&self) -> Result<(), CapabilityResolutionError> {
        validate_digest_set([
            &self.service_id_digest,
            &self.owner_plugin_digest,
            &self.capability_digest,
            &self.contract_digest,
            &self.policy_digest,
        ])
    }
}

impl Serialize for CapabilityServiceDefinition {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityServiceDefinition", 9)?;
        state.serialize_field("serviceIdDigest", &self.service_id_digest)?;
        state.serialize_field("ownerPluginDigest", &self.owner_plugin_digest)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("class", &self.class)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("policyDigest", &self.policy_digest)?;
        state.serialize_field("providerCount", &self.provider_count)?;
        state.serialize_field("lifecycle", &self.lifecycle)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityServiceDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityServiceDefinition")
            .field("service_id_digest", &self.service_id_digest)
            .field("owner_plugin_digest", &self.owner_plugin_digest)
            .field("capability_digest", &self.capability_digest)
            .field("class", &self.class)
            .field("version", &self.version)
            .field("contract_digest", &self.contract_digest)
            .field("policy_digest", &self.policy_digest)
            .field("provider_count", &self.provider_count)
            .field("lifecycle", &self.lifecycle)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityProviderDefinition {
    pub provider_id_digest: Digest,
    pub service_id_digest: Digest,
    pub owner_plugin_digest: Digest,
    pub provider_digest: Digest,
    pub version: CapabilityVersion,
    pub lifecycle: ContributionLifecycle,
}

impl CapabilityProviderDefinition {
    pub fn new(
        provider_id_digest: Digest,
        service_id_digest: Digest,
        owner_plugin_digest: Digest,
        provider_digest: Digest,
        version: CapabilityVersion,
        lifecycle: ContributionLifecycle,
    ) -> Result<Self, CapabilityResolutionError> {
        let provider = Self {
            provider_id_digest,
            service_id_digest,
            owner_plugin_digest,
            provider_digest,
            version,
            lifecycle,
        };
        provider.validate()?;
        Ok(provider)
    }

    fn validate(&self) -> Result<(), CapabilityResolutionError> {
        validate_digest_set([
            &self.provider_id_digest,
            &self.service_id_digest,
            &self.owner_plugin_digest,
            &self.provider_digest,
        ])
    }
}

impl Serialize for CapabilityProviderDefinition {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityProviderDefinition", 6)?;
        state.serialize_field("providerIdDigest", &self.provider_id_digest)?;
        state.serialize_field("serviceIdDigest", &self.service_id_digest)?;
        state.serialize_field("ownerPluginDigest", &self.owner_plugin_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("lifecycle", &self.lifecycle)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityProviderDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityProviderDefinition")
            .field("provider_id_digest", &self.provider_id_digest)
            .field("service_id_digest", &self.service_id_digest)
            .field("owner_plugin_digest", &self.owner_plugin_digest)
            .field("provider_digest", &self.provider_digest)
            .field("version", &self.version)
            .field("lifecycle", &self.lifecycle)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityConsumerDefinition {
    pub consumer_id_digest: Digest,
    pub service_id_digest: Digest,
    pub owner_plugin_digest: Digest,
    pub capability_digest: Digest,
    pub class: CapabilityClass,
    pub required_version: CapabilityVersion,
    pub policy_digest: Digest,
    pub descriptor_digest: Digest,
    pub scope: CapabilityCompositionScope,
    pub lifecycle: ContributionLifecycle,
}

impl CapabilityConsumerDefinition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        consumer_id_digest: Digest,
        service_id_digest: Digest,
        owner_plugin_digest: Digest,
        capability_digest: Digest,
        class: CapabilityClass,
        required_version: CapabilityVersion,
        policy_digest: Digest,
        descriptor_digest: Digest,
        scope: CapabilityCompositionScope,
        lifecycle: ContributionLifecycle,
    ) -> Result<Self, CapabilityResolutionError> {
        let consumer = Self {
            consumer_id_digest,
            service_id_digest,
            owner_plugin_digest,
            capability_digest,
            class,
            required_version,
            policy_digest,
            descriptor_digest,
            scope,
            lifecycle,
        };
        consumer.validate()?;
        Ok(consumer)
    }

    fn validate(&self) -> Result<(), CapabilityResolutionError> {
        validate_digest_set([
            &self.consumer_id_digest,
            &self.service_id_digest,
            &self.owner_plugin_digest,
            &self.capability_digest,
            &self.policy_digest,
            &self.descriptor_digest,
        ])?;
        self.scope.validate()
    }
}

impl Serialize for CapabilityConsumerDefinition {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityConsumerDefinition", 10)?;
        state.serialize_field("consumerIdDigest", &self.consumer_id_digest)?;
        state.serialize_field("serviceIdDigest", &self.service_id_digest)?;
        state.serialize_field("ownerPluginDigest", &self.owner_plugin_digest)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("class", &self.class)?;
        state.serialize_field("requiredVersion", &self.required_version)?;
        state.serialize_field("policyDigest", &self.policy_digest)?;
        state.serialize_field("descriptorDigest", &self.descriptor_digest)?;
        state.serialize_field("scope", &self.scope)?;
        state.serialize_field("lifecycle", &self.lifecycle)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityConsumerDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityConsumerDefinition")
            .field("consumer_id_digest", &self.consumer_id_digest)
            .field("service_id_digest", &self.service_id_digest)
            .field("owner_plugin_digest", &self.owner_plugin_digest)
            .field("capability_digest", &self.capability_digest)
            .field("class", &self.class)
            .field("required_version", &self.required_version)
            .field("policy_digest", &self.policy_digest)
            .field("descriptor_digest", &self.descriptor_digest)
            .field("scope", &self.scope)
            .field("lifecycle", &self.lifecycle)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityCompositionSnapshot {
    pub scope: CapabilityCompositionScope,
    pub revision: u64,
    pub lifecycle: CapabilityCompositionLifecycle,
    pub services: Vec<CapabilityServiceDefinition>,
    pub providers: Vec<CapabilityProviderDefinition>,
    pub consumers: Vec<CapabilityConsumerDefinition>,
    composition_digest: Digest,
}

impl CapabilityCompositionSnapshot {
    pub fn new(
        scope: CapabilityCompositionScope,
        revision: u64,
        lifecycle: CapabilityCompositionLifecycle,
        services: Vec<CapabilityServiceDefinition>,
        providers: Vec<CapabilityProviderDefinition>,
        consumers: Vec<CapabilityConsumerDefinition>,
    ) -> Result<Self, CapabilityResolutionError> {
        let snapshot = Self {
            scope,
            revision,
            lifecycle,
            services,
            providers,
            consumers,
            composition_digest: Digest::from_text("unsealed-capability-composition"),
        };
        snapshot.validate_without_digest()?;
        let composition_digest = snapshot.computed_digest();
        Ok(Self {
            composition_digest,
            ..snapshot
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.composition_digest
    }

    pub fn is_mounted(&self) -> bool {
        self.lifecycle == CapabilityCompositionLifecycle::Mounted
    }

    pub(crate) fn validate(&self) -> Result<(), CapabilityResolutionError> {
        self.validate_without_digest()?;
        if self.composition_digest != self.computed_digest() {
            return Err(CapabilityResolutionError::InvalidComposition);
        }
        Ok(())
    }

    fn validate_without_digest(&self) -> Result<(), CapabilityResolutionError> {
        self.scope.validate()?;
        if self.revision == 0
            || self.services.len() > MAX_COMPOSITION_CONTRIBUTIONS
            || self.providers.len() > MAX_COMPOSITION_CONTRIBUTIONS
            || self.consumers.len() > MAX_COMPOSITION_CONTRIBUTIONS
        {
            return Err(CapabilityResolutionError::InvalidComposition);
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
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        let service_digests = canonical_row_digests(&self.services);
        let provider_digests = canonical_row_digests(&self.providers);
        let consumer_digests = canonical_row_digests(&self.consumers);
        digest_serialized(&(
            CAPABILITY_COMPOSITION_SCHEMA,
            &self.scope,
            self.revision,
            self.lifecycle,
            service_digests,
            provider_digests,
            consumer_digests,
        ))
    }
}

impl Serialize for CapabilityCompositionSnapshot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityCompositionSnapshot", 8)?;
        state.serialize_field("schema", CAPABILITY_COMPOSITION_SCHEMA)?;
        state.serialize_field("compositionDigest", &self.composition_digest)?;
        state.serialize_field("scope", &self.scope)?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("lifecycle", &self.lifecycle)?;
        state.serialize_field("serviceCount", &self.services.len())?;
        state.serialize_field("providerCount", &self.providers.len())?;
        state.serialize_field("consumerCount", &self.consumers.len())?;
        state.end()
    }
}

impl fmt::Debug for CapabilityCompositionSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityCompositionSnapshot")
            .field("schema", &CAPABILITY_COMPOSITION_SCHEMA)
            .field("composition_digest", &self.composition_digest)
            .field("scope", &self.scope)
            .field("revision", &self.revision)
            .field("lifecycle", &self.lifecycle)
            .field("service_count", &self.services.len())
            .field("provider_count", &self.providers.len())
            .field("consumer_count", &self.consumers.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityResolutionSelector {
    pub consumer_id_digest: Digest,
    pub service_id_digest: Digest,
    pub provider_version: CapabilityVersion,
}

impl CapabilityResolutionSelector {
    pub fn new(
        consumer_id_digest: Digest,
        service_id_digest: Digest,
        provider_version: CapabilityVersion,
    ) -> Result<Self, CapabilityResolutionError> {
        let selector = Self {
            consumer_id_digest,
            service_id_digest,
            provider_version,
        };
        validate_digest_set([&selector.consumer_id_digest, &selector.service_id_digest])?;
        Ok(selector)
    }
}

impl Serialize for CapabilityResolutionSelector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityResolutionSelector", 3)?;
        state.serialize_field("consumerIdDigest", &self.consumer_id_digest)?;
        state.serialize_field("serviceIdDigest", &self.service_id_digest)?;
        state.serialize_field("providerVersion", &self.provider_version)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityResolutionSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityResolutionSelector")
            .field("consumer_id_digest", &self.consumer_id_digest)
            .field("service_id_digest", &self.service_id_digest)
            .field("provider_version", &self.provider_version)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityBinding {
    service_id_digest: Digest,
    provider_id_digest: Digest,
    provider_digest: Digest,
    consumer_id_digest: Digest,
    owner_plugin_digest: Digest,
    version: CapabilityVersion,
    scope: CapabilityCompositionScope,
    policy_digest: Digest,
    manifest_digest: Digest,
    authority_digest: Digest,
    composition_digest: Digest,
    composition_revision: u64,
    binding_digest: Digest,
}

impl CapabilityBinding {
    fn new(
        service: &CapabilityServiceDefinition,
        provider: &CapabilityProviderDefinition,
        consumer: &CapabilityConsumerDefinition,
        composition: &CapabilityCompositionSnapshot,
        manifest_digest: Digest,
        authority_digest: Digest,
    ) -> Self {
        let mut binding = Self {
            service_id_digest: service.service_id_digest.clone(),
            provider_id_digest: provider.provider_id_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            consumer_id_digest: consumer.consumer_id_digest.clone(),
            owner_plugin_digest: service.owner_plugin_digest.clone(),
            version: provider.version,
            scope: composition.scope.clone(),
            policy_digest: service.policy_digest.clone(),
            manifest_digest,
            authority_digest,
            composition_digest: composition.digest().clone(),
            composition_revision: composition.revision,
            binding_digest: Digest::from_text("unsealed-capability-binding"),
        };
        binding.binding_digest = binding.computed_digest();
        binding
    }

    pub fn digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn service_id_digest(&self) -> &Digest {
        &self.service_id_digest
    }

    pub fn provider_id_digest(&self) -> &Digest {
        &self.provider_id_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn consumer_id_digest(&self) -> &Digest {
        &self.consumer_id_digest
    }

    pub fn owner_plugin_digest(&self) -> &Digest {
        &self.owner_plugin_digest
    }

    pub const fn version(&self) -> CapabilityVersion {
        self.version
    }

    pub fn scope(&self) -> &CapabilityCompositionScope {
        &self.scope
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }

    pub fn authority_digest(&self) -> &Digest {
        &self.authority_digest
    }

    pub fn composition_digest(&self) -> &Digest {
        &self.composition_digest
    }

    pub const fn composition_revision(&self) -> u64 {
        self.composition_revision
    }

    /// The mounted provider generation is the Project/Mission generation
    /// captured by this binding. Invocation consumers must re-check it before
    /// using the provider again.
    pub const fn provider_generation(&self) -> u64 {
        self.scope.generation
    }

    fn computed_digest(&self) -> Digest {
        digest_serialized(&(
            CAPABILITY_RESOLUTION_SCHEMA,
            &self.service_id_digest,
            &self.provider_id_digest,
            &self.provider_digest,
            &self.consumer_id_digest,
            &self.owner_plugin_digest,
            self.version,
            &self.scope,
            &self.policy_digest,
            &self.manifest_digest,
            &self.authority_digest,
            &self.composition_digest,
            self.composition_revision,
        ))
    }

    pub(crate) fn validate(&self) -> Result<(), CapabilityResolutionError> {
        validate_digest_set([
            &self.service_id_digest,
            &self.provider_id_digest,
            &self.provider_digest,
            &self.consumer_id_digest,
            &self.owner_plugin_digest,
            &self.policy_digest,
            &self.manifest_digest,
            &self.authority_digest,
            &self.composition_digest,
            &self.binding_digest,
        ])?;
        self.scope.validate()?;
        if self.composition_revision == 0 || self.binding_digest != self.computed_digest() {
            return Err(CapabilityResolutionError::InvalidReceipt);
        }
        Ok(())
    }
}

impl Serialize for CapabilityBinding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityBinding", 14)?;
        state.serialize_field("schema", CAPABILITY_RESOLUTION_SCHEMA)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.serialize_field("serviceIdDigest", &self.service_id_digest)?;
        state.serialize_field("providerIdDigest", &self.provider_id_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("consumerIdDigest", &self.consumer_id_digest)?;
        state.serialize_field("ownerPluginDigest", &self.owner_plugin_digest)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("scope", &self.scope)?;
        state.serialize_field("policyDigest", &self.policy_digest)?;
        state.serialize_field("manifestDigest", &self.manifest_digest)?;
        state.serialize_field("authorityDigest", &self.authority_digest)?;
        state.serialize_field("compositionDigest", &self.composition_digest)?;
        state.serialize_field("compositionRevision", &self.composition_revision)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityBinding")
            .field("binding_digest", &self.binding_digest)
            .field("service_id_digest", &self.service_id_digest)
            .field("provider_id_digest", &self.provider_id_digest)
            .field("provider_digest", &self.provider_digest)
            .field("consumer_id_digest", &self.consumer_id_digest)
            .field("owner_plugin_digest", &self.owner_plugin_digest)
            .field("version", &self.version)
            .field("scope", &self.scope)
            .field("policy_digest", &self.policy_digest)
            .field("manifest_digest", &self.manifest_digest)
            .field("authority_digest", &self.authority_digest)
            .field("composition_digest", &self.composition_digest)
            .field("composition_revision", &self.composition_revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityResolutionReceipt {
    query_digest: Digest,
    binding_digest: Digest,
    composition_digest: Digest,
    scope_digest: Digest,
    generation: u64,
    composition_revision: u64,
    receipt_digest: Digest,
}

impl CapabilityResolutionReceipt {
    fn new(query_digest: Digest, binding: &CapabilityBinding) -> Self {
        let mut receipt = Self {
            query_digest,
            binding_digest: binding.digest().clone(),
            composition_digest: binding.composition_digest().clone(),
            scope_digest: binding.scope().scope_digest.clone(),
            generation: binding.scope().generation,
            composition_revision: binding.composition_revision(),
            receipt_digest: Digest::from_text("unsealed-capability-resolution-receipt"),
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt
    }

    pub fn digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn composition_digest(&self) -> &Digest {
        &self.composition_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn composition_revision(&self) -> u64 {
        self.composition_revision
    }

    fn computed_digest(&self) -> Digest {
        digest_serialized(&(
            CAPABILITY_RESOLUTION_RECEIPT_SCHEMA,
            &self.query_digest,
            &self.binding_digest,
            &self.composition_digest,
            &self.scope_digest,
            self.generation,
            self.composition_revision,
        ))
    }

    pub(crate) fn validate(&self) -> Result<(), CapabilityResolutionError> {
        validate_digest_set([
            &self.query_digest,
            &self.binding_digest,
            &self.composition_digest,
            &self.scope_digest,
            &self.receipt_digest,
        ])?;
        if self.generation == 0
            || self.composition_revision == 0
            || self.receipt_digest != self.computed_digest()
        {
            return Err(CapabilityResolutionError::InvalidReceipt);
        }
        Ok(())
    }
}

impl Serialize for CapabilityResolutionReceipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityResolutionReceipt", 8)?;
        state.serialize_field("schema", CAPABILITY_RESOLUTION_RECEIPT_SCHEMA)?;
        state.serialize_field("receiptDigest", &self.receipt_digest)?;
        state.serialize_field("queryDigest", &self.query_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.serialize_field("compositionDigest", &self.composition_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("generation", &self.generation)?;
        state.serialize_field("compositionRevision", &self.composition_revision)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityResolutionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityResolutionReceipt")
            .field("receipt_digest", &self.receipt_digest)
            .field("query_digest", &self.query_digest)
            .field("binding_digest", &self.binding_digest)
            .field("composition_digest", &self.composition_digest)
            .field("scope_digest", &self.scope_digest)
            .field("generation", &self.generation)
            .field("composition_revision", &self.composition_revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityReleaseReceipt {
    resolution_receipt_digest: Digest,
    binding_digest: Digest,
    query_digest: Digest,
    composition_digest: Digest,
    generation: u64,
    composition_revision: u64,
    released_at: DateTime<Utc>,
    release_event_digest: Digest,
}

impl CapabilityReleaseReceipt {
    fn new(
        receipt: &CapabilityResolutionReceipt,
        binding: &CapabilityBinding,
        released_at: DateTime<Utc>,
    ) -> Self {
        let mut release = Self {
            resolution_receipt_digest: receipt.digest().clone(),
            binding_digest: binding.digest().clone(),
            query_digest: receipt.query_digest.clone(),
            composition_digest: receipt.composition_digest.clone(),
            generation: receipt.generation,
            composition_revision: receipt.composition_revision,
            released_at,
            release_event_digest: Digest::from_text("unsealed-capability-release"),
        };
        release.release_event_digest = release.computed_event_digest();
        release
    }

    pub fn resolution_receipt_digest(&self) -> &Digest {
        &self.resolution_receipt_digest
    }

    pub fn release_event_digest(&self) -> &Digest {
        &self.release_event_digest
    }

    pub const fn released_at(&self) -> DateTime<Utc> {
        self.released_at
    }

    fn computed_event_digest(&self) -> Digest {
        digest_serialized(&(
            CAPABILITY_RESOLUTION_AUDIT_SCHEMA,
            "released",
            &self.resolution_receipt_digest,
            &self.binding_digest,
            &self.query_digest,
            &self.composition_digest,
            self.generation,
            self.composition_revision,
            self.released_at,
        ))
    }

    fn validate(&self) -> Result<(), CapabilityResolutionError> {
        validate_digest_set([
            &self.resolution_receipt_digest,
            &self.binding_digest,
            &self.query_digest,
            &self.composition_digest,
            &self.release_event_digest,
        ])?;
        if self.generation == 0
            || self.composition_revision == 0
            || self.release_event_digest != self.computed_event_digest()
        {
            return Err(CapabilityResolutionError::InvalidReleaseReceipt);
        }
        Ok(())
    }
}

impl Serialize for CapabilityReleaseReceipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityReleaseReceipt", 9)?;
        state.serialize_field("schema", CAPABILITY_RESOLUTION_AUDIT_SCHEMA)?;
        state.serialize_field("resolutionReceiptDigest", &self.resolution_receipt_digest)?;
        state.serialize_field("releaseEventDigest", &self.release_event_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.serialize_field("queryDigest", &self.query_digest)?;
        state.serialize_field("compositionDigest", &self.composition_digest)?;
        state.serialize_field("generation", &self.generation)?;
        state.serialize_field("compositionRevision", &self.composition_revision)?;
        state.serialize_field("releasedAt", &self.released_at)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityReleaseReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityReleaseReceipt")
            .field("resolution_receipt_digest", &self.resolution_receipt_digest)
            .field("release_event_digest", &self.release_event_digest)
            .field("binding_digest", &self.binding_digest)
            .field("query_digest", &self.query_digest)
            .field("composition_digest", &self.composition_digest)
            .field("generation", &self.generation)
            .field("composition_revision", &self.composition_revision)
            .field("released_at", &self.released_at)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityResolutionAuditEventKind {
    Resolved,
    Released,
    Reopened,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityResolutionAuditEvent {
    kind: CapabilityResolutionAuditEventKind,
    event_digest: Digest,
    resolution_receipt_digest: Digest,
    binding_digest: Digest,
    query_digest: Digest,
    composition_digest: Digest,
    scope_digest: Digest,
    generation: u64,
    composition_revision: u64,
    observed_at: DateTime<Utc>,
}

impl CapabilityResolutionAuditEvent {
    fn new(
        kind: CapabilityResolutionAuditEventKind,
        receipt: &CapabilityResolutionReceipt,
        binding: &CapabilityBinding,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let mut event = Self {
            kind,
            event_digest: Digest::from_text("unsealed-capability-resolution-audit"),
            resolution_receipt_digest: receipt.digest().clone(),
            binding_digest: binding.digest().clone(),
            query_digest: receipt.query_digest.clone(),
            composition_digest: receipt.composition_digest.clone(),
            scope_digest: receipt.scope_digest.clone(),
            generation: receipt.generation,
            composition_revision: receipt.composition_revision,
            observed_at,
        };
        event.event_digest = event.computed_digest();
        event
    }

    fn computed_digest(&self) -> Digest {
        digest_serialized(&(
            CAPABILITY_RESOLUTION_AUDIT_SCHEMA,
            self.kind,
            &self.resolution_receipt_digest,
            &self.binding_digest,
            &self.query_digest,
            &self.composition_digest,
            &self.scope_digest,
            self.generation,
            self.composition_revision,
            self.observed_at,
        ))
    }

    fn validate(&self) -> Result<(), ResolutionLedgerError> {
        if !is_digest(&self.event_digest)
            || !is_digest(&self.resolution_receipt_digest)
            || !is_digest(&self.binding_digest)
            || !is_digest(&self.query_digest)
            || !is_digest(&self.composition_digest)
            || !is_digest(&self.scope_digest)
            || self.generation == 0
            || self.composition_revision == 0
            || self.event_digest != self.computed_digest()
        {
            return Err(ResolutionLedgerError::InvalidEvent);
        }
        Ok(())
    }

    pub fn kind(&self) -> CapabilityResolutionAuditEventKind {
        self.kind
    }

    pub fn event_digest(&self) -> &Digest {
        &self.event_digest
    }

    pub fn resolution_receipt_digest(&self) -> &Digest {
        &self.resolution_receipt_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

impl Serialize for CapabilityResolutionAuditEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityResolutionAuditEvent", 11)?;
        state.serialize_field("schema", CAPABILITY_RESOLUTION_AUDIT_SCHEMA)?;
        state.serialize_field("eventDigest", &self.event_digest)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("resolutionReceiptDigest", &self.resolution_receipt_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.serialize_field("queryDigest", &self.query_digest)?;
        state.serialize_field("compositionDigest", &self.composition_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("generation", &self.generation)?;
        state.serialize_field("compositionRevision", &self.composition_revision)?;
        state.serialize_field("observedAt", &self.observed_at)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityResolutionAuditEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityResolutionAuditEvent")
            .field("kind", &self.kind)
            .field("event_digest", &self.event_digest)
            .field("resolution_receipt_digest", &self.resolution_receipt_digest)
            .field("binding_digest", &self.binding_digest)
            .field("query_digest", &self.query_digest)
            .field("composition_digest", &self.composition_digest)
            .field("scope_digest", &self.scope_digest)
            .field("generation", &self.generation)
            .field("composition_revision", &self.composition_revision)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

pub trait CapabilityResolutionAuditLedger {
    fn append(
        &mut self,
        event: CapabilityResolutionAuditEvent,
    ) -> Result<(), ResolutionLedgerError>;
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ResolutionLedgerError {
    #[error("resolution audit ledger is unavailable")]
    Unavailable,
    #[error("resolution audit transition conflicts with durable state")]
    Conflict,
    #[error("resolution audit transition is invalid")]
    InvalidTransition,
    #[error("resolution audit event is invalid")]
    InvalidEvent,
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct MemoryCapabilityResolutionLedger {
    events: Vec<CapabilityResolutionAuditEvent>,
    active: std::collections::BTreeSet<Digest>,
    released: std::collections::BTreeSet<Digest>,
}

impl MemoryCapabilityResolutionLedger {
    pub fn events(&self) -> &[CapabilityResolutionAuditEvent] {
        &self.events
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl CapabilityResolutionAuditLedger for MemoryCapabilityResolutionLedger {
    fn append(
        &mut self,
        event: CapabilityResolutionAuditEvent,
    ) -> Result<(), ResolutionLedgerError> {
        event.validate()?;
        let receipt = event.resolution_receipt_digest().clone();
        match event.kind() {
            CapabilityResolutionAuditEventKind::Resolved => {
                if self.active.contains(&receipt) || self.released.contains(&receipt) {
                    return Err(ResolutionLedgerError::Conflict);
                }
                self.active.insert(receipt);
            }
            CapabilityResolutionAuditEventKind::Released => {
                if !self.active.remove(&receipt) {
                    return Err(ResolutionLedgerError::InvalidTransition);
                }
                self.released.insert(receipt);
            }
            CapabilityResolutionAuditEventKind::Reopened => {
                if !self.released.remove(&receipt) {
                    return Err(ResolutionLedgerError::InvalidTransition);
                }
                self.active.insert(receipt);
            }
        }
        self.events.push(event);
        Ok(())
    }
}

impl fmt::Debug for MemoryCapabilityResolutionLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryCapabilityResolutionLedger")
            .field("event_count", &self.events.len())
            .field("active_count", &self.active.len())
            .field("released_count", &self.released.len())
            .field(
                "event_set_digest",
                &digest_serialized(
                    &self
                        .events
                        .iter()
                        .map(CapabilityResolutionAuditEvent::event_digest)
                        .collect::<Vec<_>>(),
                ),
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityResolutionLease {
    binding: CapabilityBinding,
    receipt: CapabilityResolutionReceipt,
    permit: InvocationPermit,
    released: bool,
}

impl CapabilityResolutionLease {
    fn new(
        binding: CapabilityBinding,
        receipt: CapabilityResolutionReceipt,
        permit: InvocationPermit,
    ) -> Self {
        Self {
            binding,
            receipt,
            permit,
            released: false,
        }
    }

    pub fn binding(&self) -> &CapabilityBinding {
        &self.binding
    }

    pub fn receipt(&self) -> &CapabilityResolutionReceipt {
        &self.receipt
    }

    pub fn invocation_permit(&self) -> &InvocationPermit {
        &self.permit
    }

    pub const fn is_released(&self) -> bool {
        self.released
    }

    pub fn release<L: CapabilityResolutionAuditLedger>(
        &mut self,
        released_at: DateTime<Utc>,
        audit: &mut L,
    ) -> Result<CapabilityReleaseReceipt, CapabilityResolutionError> {
        if self.released {
            return Err(CapabilityResolutionError::AlreadyReleased);
        }
        let event = CapabilityResolutionAuditEvent::new(
            CapabilityResolutionAuditEventKind::Released,
            &self.receipt,
            &self.binding,
            released_at,
        );
        audit.append(event.clone())?;
        self.released = true;
        Ok(CapabilityReleaseReceipt::new(
            &self.receipt,
            &self.binding,
            released_at,
        ))
    }
}

impl fmt::Debug for CapabilityResolutionLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityResolutionLease")
            .field("binding", &self.binding)
            .field("receipt", &self.receipt)
            .field("permit", &self.permit)
            .field("released", &self.released)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ResolutionQuery {
    selector: CapabilityResolutionSelector,
    capability_digest: Digest,
    class: CapabilityClass,
    scope: CapabilityCompositionScope,
    manifest_digest: Digest,
    policy_digest: Digest,
    authority_digest: Digest,
    provider_digest: Digest,
    descriptor_digest: Digest,
    request_digest: Digest,
}

impl ResolutionQuery {
    fn from_authorized(
        manifest: &CapabilityManifest,
        request: &CapabilityRequest,
        selector: CapabilityResolutionSelector,
    ) -> Result<Self, CapabilityResolutionError> {
        let provider_version = CapabilityVersion::parse(&manifest.adapter.version)?;
        if selector.provider_version != provider_version {
            return Err(CapabilityResolutionError::VersionMismatch);
        }
        let scope = CapabilityCompositionScope::new(
            manifest.mission.project_id.clone(),
            manifest.mission.mission_id.clone(),
            manifest.mission.generation,
            manifest.mission.scope_digest.clone(),
        )?;
        let manifest_digest = manifest.digest()?;
        let authority_digest = manifest.authority_digest()?;
        Ok(Self {
            selector,
            capability_digest: Digest::from_text(manifest.capability_id.as_str()),
            class: manifest.class,
            scope,
            manifest_digest,
            policy_digest: authority_digest.clone(),
            authority_digest,
            provider_digest: manifest.adapter.implementation_digest.clone(),
            descriptor_digest: Digest::from_text(CAPABILITY_REQUEST_SCHEMA),
            request_digest: request.digest(),
        })
    }

    fn digest(&self) -> Digest {
        digest_serialized(&(
            CAPABILITY_RESOLUTION_SCHEMA,
            &self.selector,
            &self.capability_digest,
            self.class,
            &self.scope,
            &self.manifest_digest,
            &self.policy_digest,
            &self.authority_digest,
            &self.provider_digest,
            &self.descriptor_digest,
            &self.request_digest,
        ))
    }
}

pub struct CapabilityResolver<'a> {
    gateway: &'a CapabilityGateway,
}

impl<'a> CapabilityResolver<'a> {
    pub(crate) const fn new(gateway: &'a CapabilityGateway) -> Self {
        Self { gateway }
    }

    pub fn resolve<L: CapabilityResolutionAuditLedger>(
        &self,
        composition: &CapabilityCompositionSnapshot,
        signed_manifest: &SignedCapabilityManifest,
        request: &CapabilityRequest,
        selector: &CapabilityResolutionSelector,
        now: DateTime<Utc>,
        audit: &mut L,
    ) -> Result<CapabilityResolutionLease, CapabilityResolutionError> {
        let (lease, _query) =
            self.build_lease(composition, signed_manifest, request, selector, now)?;
        let event = CapabilityResolutionAuditEvent::new(
            CapabilityResolutionAuditEventKind::Resolved,
            &lease.receipt,
            &lease.binding,
            now,
        );
        audit.append(event)?;
        Ok(lease)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reopen<L: CapabilityResolutionAuditLedger>(
        &self,
        release: &CapabilityReleaseReceipt,
        composition: &CapabilityCompositionSnapshot,
        signed_manifest: &SignedCapabilityManifest,
        request: &CapabilityRequest,
        selector: &CapabilityResolutionSelector,
        now: DateTime<Utc>,
        audit: &mut L,
    ) -> Result<CapabilityResolutionLease, CapabilityResolutionError> {
        release.validate()?;
        let (lease, _query) =
            self.build_lease(composition, signed_manifest, request, selector, now)?;
        if *lease.receipt.digest() != release.resolution_receipt_digest
            || *lease.binding.digest() != release.binding_digest
            || lease.receipt.query_digest() != &release.query_digest
            || lease.receipt.composition_digest() != &release.composition_digest
            || lease.receipt.generation() != release.generation
            || lease.receipt.composition_revision() != release.composition_revision
        {
            return Err(CapabilityResolutionError::ReopenMismatch);
        }
        let event = CapabilityResolutionAuditEvent::new(
            CapabilityResolutionAuditEventKind::Reopened,
            &lease.receipt,
            &lease.binding,
            now,
        );
        audit.append(event)?;
        Ok(lease)
    }

    fn build_lease(
        &self,
        composition: &CapabilityCompositionSnapshot,
        signed_manifest: &SignedCapabilityManifest,
        request: &CapabilityRequest,
        selector: &CapabilityResolutionSelector,
        now: DateTime<Utc>,
    ) -> Result<(CapabilityResolutionLease, ResolutionQuery), CapabilityResolutionError> {
        composition.validate()?;
        let permit = self
            .gateway
            .authorize(signed_manifest, request, now)
            .map_err(map_gateway_error)?;
        let query =
            ResolutionQuery::from_authorized(&signed_manifest.manifest, request, selector.clone())?;
        validate_composition_scope(composition, &query.scope)?;
        if !composition.is_mounted() {
            return Err(match composition.lifecycle {
                CapabilityCompositionLifecycle::Revoked => CapabilityResolutionError::PluginRevoked,
                CapabilityCompositionLifecycle::Stale => CapabilityResolutionError::StaleGeneration,
                CapabilityCompositionLifecycle::Unmounted => {
                    CapabilityResolutionError::CompositionUnavailable
                }
                CapabilityCompositionLifecycle::Mounted => {
                    CapabilityResolutionError::InvalidComposition
                }
            });
        }

        let service = unique_service(composition, &query)?;
        let provider = unique_provider(composition, service, &query)?;
        let consumer = unique_consumer(composition, service, provider, &query)?;
        let binding = CapabilityBinding::new(
            service,
            provider,
            consumer,
            composition,
            query.manifest_digest.clone(),
            query.authority_digest.clone(),
        );
        binding.validate()?;
        let receipt = CapabilityResolutionReceipt::new(query.digest(), &binding);
        receipt.validate()?;
        Ok((
            CapabilityResolutionLease::new(binding, receipt, permit),
            query,
        ))
    }

    pub(crate) fn validate_binding_for_invocation(
        &self,
        binding: &CapabilityBinding,
        receipt: &CapabilityResolutionReceipt,
        composition: &CapabilityCompositionSnapshot,
        signed_manifest: &SignedCapabilityManifest,
        request: &CapabilityRequest,
        now: DateTime<Utc>,
    ) -> Result<CapabilityResolutionLease, CapabilityResolutionError> {
        binding.validate()?;
        receipt.validate()?;
        composition.validate()?;
        let selector = CapabilityResolutionSelector::new(
            binding.consumer_id_digest().clone(),
            binding.service_id_digest().clone(),
            binding.version(),
        )?;
        let (current, _query) =
            self.build_lease(composition, signed_manifest, request, &selector, now)?;
        if current.binding() != binding || current.receipt() != receipt {
            return Err(CapabilityResolutionError::ReopenMismatch);
        }
        Ok(current)
    }

    pub(crate) fn rebuild_resolution_lease(
        &self,
        composition: &CapabilityCompositionSnapshot,
        signed_manifest: &SignedCapabilityManifest,
        request: &CapabilityRequest,
        selector: &CapabilityResolutionSelector,
        now: DateTime<Utc>,
    ) -> Result<CapabilityResolutionLease, CapabilityResolutionError> {
        let (lease, _query) =
            self.build_lease(composition, signed_manifest, request, selector, now)?;
        Ok(lease)
    }
}

impl fmt::Debug for CapabilityResolver<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityResolver")
            .field("gateway", &self.gateway)
            .finish_non_exhaustive()
    }
}

impl CapabilityGateway {
    pub fn resolver(&self) -> CapabilityResolver<'_> {
        CapabilityResolver::new(self)
    }
}

fn validate_composition_scope(
    composition: &CapabilityCompositionSnapshot,
    expected: &CapabilityCompositionScope,
) -> Result<(), CapabilityResolutionError> {
    if composition.scope.project_id != expected.project_id
        || composition.scope.mission_id != expected.mission_id
    {
        return Err(CapabilityResolutionError::ScopeMismatch);
    }
    if composition.scope.generation != expected.generation {
        return Err(CapabilityResolutionError::StaleGeneration);
    }
    if composition.scope.scope_digest != expected.scope_digest {
        return Err(CapabilityResolutionError::ScopeMismatch);
    }
    Ok(())
}

fn unique_service<'a>(
    composition: &'a CapabilityCompositionSnapshot,
    query: &ResolutionQuery,
) -> Result<&'a CapabilityServiceDefinition, CapabilityResolutionError> {
    let candidates: Vec<_> = composition
        .services
        .iter()
        .filter(|service| service.service_id_digest == query.selector.service_id_digest)
        .collect();
    let service = match candidates.as_slice() {
        [] => return Err(CapabilityResolutionError::MissingService),
        [service] => *service,
        _ => return Err(CapabilityResolutionError::AmbiguousComposition),
    };
    match service.lifecycle {
        ContributionLifecycle::Active => {}
        ContributionLifecycle::Revoked => return Err(CapabilityResolutionError::PluginRevoked),
        ContributionLifecycle::Unmounted => {
            return Err(CapabilityResolutionError::CompositionUnavailable);
        }
        ContributionLifecycle::Stale => return Err(CapabilityResolutionError::StaleGeneration),
    }
    if service.capability_digest != query.capability_digest
        || service.class != query.class
        || service.version != query.selector.provider_version
    {
        return Err(CapabilityResolutionError::BindingMismatch);
    }
    if service.contract_digest != query.manifest_digest {
        return Err(CapabilityResolutionError::BindingMismatch);
    }
    if service.policy_digest != query.policy_digest {
        return Err(CapabilityResolutionError::PolicyMismatch);
    }
    if service.provider_count == 0 {
        return Err(CapabilityResolutionError::MissingProvider);
    }
    if service.provider_count != 1 {
        return Err(CapabilityResolutionError::AmbiguousComposition);
    }
    Ok(service)
}

fn unique_provider<'a>(
    composition: &'a CapabilityCompositionSnapshot,
    service: &CapabilityServiceDefinition,
    query: &ResolutionQuery,
) -> Result<&'a CapabilityProviderDefinition, CapabilityResolutionError> {
    let candidates: Vec<_> = composition
        .providers
        .iter()
        .filter(|provider| provider.service_id_digest == service.service_id_digest)
        .collect();
    let provider = match candidates.as_slice() {
        [] => return Err(CapabilityResolutionError::MissingProvider),
        [provider] => *provider,
        _ => return Err(CapabilityResolutionError::AmbiguousComposition),
    };
    match provider.lifecycle {
        ContributionLifecycle::Active => {}
        ContributionLifecycle::Revoked => return Err(CapabilityResolutionError::ProviderRevoked),
        ContributionLifecycle::Unmounted => {
            return Err(CapabilityResolutionError::CompositionUnavailable);
        }
        ContributionLifecycle::Stale => return Err(CapabilityResolutionError::StaleGeneration),
    }
    if provider.owner_plugin_digest != service.owner_plugin_digest {
        return Err(CapabilityResolutionError::BindingMismatch);
    }
    if provider.provider_digest != query.provider_digest {
        return Err(CapabilityResolutionError::BindingMismatch);
    }
    if provider.version != query.selector.provider_version {
        return Err(CapabilityResolutionError::VersionMismatch);
    }
    Ok(provider)
}

fn unique_consumer<'a>(
    composition: &'a CapabilityCompositionSnapshot,
    service: &CapabilityServiceDefinition,
    provider: &CapabilityProviderDefinition,
    query: &ResolutionQuery,
) -> Result<&'a CapabilityConsumerDefinition, CapabilityResolutionError> {
    let candidates: Vec<_> = composition
        .consumers
        .iter()
        .filter(|consumer| {
            consumer.consumer_id_digest == query.selector.consumer_id_digest
                && consumer.service_id_digest == service.service_id_digest
        })
        .collect();
    let consumer = match candidates.as_slice() {
        [] => return Err(CapabilityResolutionError::MissingConsumer),
        [consumer] => *consumer,
        _ => return Err(CapabilityResolutionError::AmbiguousComposition),
    };
    match consumer.lifecycle {
        ContributionLifecycle::Active => {}
        ContributionLifecycle::Revoked => return Err(CapabilityResolutionError::ConsumerRevoked),
        ContributionLifecycle::Unmounted => {
            return Err(CapabilityResolutionError::CompositionUnavailable);
        }
        ContributionLifecycle::Stale => return Err(CapabilityResolutionError::StaleGeneration),
    }
    if consumer.owner_plugin_digest != service.owner_plugin_digest
        || consumer.owner_plugin_digest != provider.owner_plugin_digest
        || consumer.capability_digest != query.capability_digest
        || consumer.class != query.class
        || consumer.required_version != query.selector.provider_version
        || consumer.policy_digest != query.policy_digest
        || consumer.descriptor_digest != query.descriptor_digest
    {
        return Err(CapabilityResolutionError::BindingMismatch);
    }
    if !consumer.scope.matches_scope(&composition.scope) {
        if consumer.scope.project_id != composition.scope.project_id
            || consumer.scope.mission_id != composition.scope.mission_id
        {
            return Err(CapabilityResolutionError::ScopeMismatch);
        }
        return Err(CapabilityResolutionError::StaleGeneration);
    }
    Ok(consumer)
}

fn map_gateway_error(error: GatewayError) -> CapabilityResolutionError {
    match error {
        GatewayError::AdapterRevoked => CapabilityResolutionError::ProviderRevoked,
        other => CapabilityResolutionError::Gateway(other),
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CapabilityResolutionError {
    #[error("capability gateway authorization failed")]
    Gateway(#[from] GatewayError),
    #[error("capability composition snapshot is invalid")]
    InvalidComposition,
    #[error("capability composition is unavailable")]
    CompositionUnavailable,
    #[error("capability plugin is revoked")]
    PluginRevoked,
    #[error("capability composition generation is stale")]
    StaleGeneration,
    #[error("capability composition scope does not match the Mission")]
    ScopeMismatch,
    #[error("service definition is missing")]
    MissingService,
    #[error("capability provider is missing")]
    MissingProvider,
    #[error("Mission consumer is missing")]
    MissingConsumer,
    #[error("capability composition is ambiguous")]
    AmbiguousComposition,
    #[error("capability provider is revoked")]
    ProviderRevoked,
    #[error("capability consumer is revoked")]
    ConsumerRevoked,
    #[error("capability binding does not match its service/provider/consumer")]
    BindingMismatch,
    #[error("capability provider version does not match")]
    VersionMismatch,
    #[error("capability policy digest does not match")]
    PolicyMismatch,
    #[error("capability version is invalid")]
    InvalidVersion,
    #[error("capability resolution receipt is invalid")]
    InvalidReceipt,
    #[error("capability release receipt is invalid")]
    InvalidReleaseReceipt,
    #[error("capability resolution lease has already been released")]
    AlreadyReleased,
    #[error("capability resolution cannot be reopened against this composition")]
    ReopenMismatch,
    #[error("capability resolution audit could not be committed")]
    Audit(#[from] ResolutionLedgerError),
}

fn validate_digest_set<'a, I>(digests: I) -> Result<(), CapabilityResolutionError>
where
    I: IntoIterator<Item = &'a Digest>,
{
    if digests.into_iter().all(is_digest) {
        Ok(())
    } else {
        Err(CapabilityResolutionError::InvalidComposition)
    }
}

fn canonical_row_digests<T: Serialize>(rows: &[T]) -> Vec<Digest> {
    let mut digests = rows.iter().map(digest_serialized).collect::<Vec<_>>();
    digests.sort_unstable();
    digests
}

fn is_digest(digest: &Digest) -> bool {
    digest.as_str().len() == 64
        && digest
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
