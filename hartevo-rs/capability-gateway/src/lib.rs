//! Hartevo's typed capability boundary.
//!
//! The gateway is deliberately a protocol crate, not an execution runtime. It
//! validates a signed, versioned authority manifest; binds a request to one
//! Project/Mission generation; and hands an already-authorized typed request to
//! an adapter supplied by a trusted host. There is no database handle, process
//! launcher, arbitrary command surface, provider credential, or raw Secret in
//! this crate.

#![forbid(unsafe_code)]

mod invocation;
mod resolution;
pub use invocation::{
    CapabilityInvocationCloseReason, CapabilityInvocationContext,
    CapabilityInvocationEffectReceipt, CapabilityInvocationError, CapabilityInvocationEvent,
    CapabilityInvocationEventKind, CapabilityInvocationLease, CapabilityInvocationLog,
    CapabilityInvocationLogError, CapabilityInvocationLogReference, CapabilityInvocationReceipt,
    CapabilityInvocationReleaseReceipt, CapabilityInvocationResult, CapabilityInvocationVisibility,
    InvocationLease, MAX_INVOCATION_ATTEMPTS, MemoryCapabilityInvocationLog,
    ResolvedCapabilityBinding,
};
pub use resolution::{
    CapabilityBinding, CapabilityCompositionLifecycle, CapabilityCompositionScope,
    CapabilityCompositionSnapshot, CapabilityConsumerDefinition, CapabilityProviderDefinition,
    CapabilityReleaseReceipt, CapabilityResolutionAuditEvent, CapabilityResolutionAuditEventKind,
    CapabilityResolutionAuditLedger, CapabilityResolutionError, CapabilityResolutionLease,
    CapabilityResolutionReceipt, CapabilityResolutionSelector, CapabilityResolver,
    CapabilityServiceDefinition, CapabilityVersion, ContributionLifecycle,
    MemoryCapabilityResolutionLedger, ResolutionLedgerError,
};

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    marker::PhantomData,
};

use chrono::{DateTime, Utc};
pub use hartevo_domain_kernel::{
    ContextBranchId, ContextCapsuleId, ContextWorkspaceId, MissionId, ProjectId, TaskId, TenantId,
    WorkerId, WorkerLeaseId,
};
use ring::signature::{self, KeyPair};
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use url::Url;

pub const CAPABILITY_MANIFEST_SCHEMA: &str = "hartevo.capability-manifest/v1";
pub const CAPABILITY_REQUEST_SCHEMA: &str = "hartevo.capability-request/v1";
pub const CAPABILITY_RESULT_SCHEMA: &str = "hartevo.capability-result/v1";
pub const CAPABILITY_RECOVERY_SCHEMA: &str = "hartevo.capability-recovery/v1";
pub const ADAPTER_REGISTRY_SCHEMA: &str = "hartevo.capability-adapter-registry/v1";
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_PROVENANCE_LINKS: usize = 8;

/// A SHA-256 digest used for all durable and cross-boundary references.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(bytes);
        Self(format!("{:x}", digest.finalize()))
    }

    pub fn from_text(value: &str) -> Self {
        Self::from_bytes(value.as_bytes())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, GatewayError> {
        let value = value.into();
        if is_sha256(&value) {
            Ok(Self(value))
        } else {
            Err(GatewayError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if is_sha256(&value) {
            Ok(Self(value))
        } else {
            Err(D::Error::custom("digest must be lowercase SHA-256"))
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl AsRef<str> for Digest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

macro_rules! opaque_id {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, GatewayError> {
                let value = value.into();
                let identifier = Self(value);
                identifier.validate()?;
                Ok(identifier)
            }

            pub fn validate(&self) -> Result<(), GatewayError> {
                if self.0.trim().is_empty() || self.0.len() > 256 {
                    return Err(GatewayError::InvalidIdentifier);
                }
                Ok(())
            }

            pub fn from_stable(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            fn digest(&self) -> Digest {
                Digest::from_text(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                if value.trim().is_empty() || value.len() > 256 {
                    return Err(D::Error::custom(concat!($label, " is invalid")));
                }
                Ok(Self(value))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct($label)
                    .field("digest", &self.digest())
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

opaque_id!(CapabilityId, "CapabilityId");
opaque_id!(AdapterId, "AdapterId");
opaque_id!(RequestId, "RequestId");
opaque_id!(SecretReferenceId, "SecretReferenceId");
opaque_id!(ResourceId, "ResourceId");
opaque_id!(EffectId, "EffectId");

/// An idempotency key is retained for the exact request but is never printed.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub fn new(value: impl Into<String>) -> Result<Self, GatewayError> {
        let value = value.into();
        let key = Self(value);
        key.validate()?;
        Ok(key)
    }

    pub fn validate(&self) -> Result<(), GatewayError> {
        if self.0.trim().is_empty() || self.0.len() > 256 {
            return Err(GatewayError::InvalidIdempotencyKey);
        }
        Ok(())
    }

    pub fn from_stable(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }
}

impl<'de> Deserialize<'de> for IdempotencyKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.trim().is_empty() || value.len() > 256 {
            return Err(D::Error::custom("idempotency key is invalid"));
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdempotencyKey")
            .field("digest", &self.digest())
            .finish()
    }
}

/// A capability's trust class. `ExternalEffect` is intentionally separate
/// from local mutation even when a provider happens to be reached by browser
/// or API code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityClass {
    Read,
    LocalMutation,
    ExternalEffect,
}

/// Data that may be carried in a Runtime result. Secrets are not a data class
/// here by design: they can only be represented by [`SecretReference`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Public,
    Business,
    Restricted,
}

impl DataClass {
    pub fn is_at_most(self, maximum: Self) -> bool {
        self <= maximum
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    ExternalWrite,
    Outreach,
    Spend,
    Payment,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRequirement {
    Required,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UncertainEffectPolicy {
    ReconcileOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostLimit {
    pub amount_minor: i64,
    pub currency: String,
}

impl CostLimit {
    pub fn validate(&self) -> Result<(), GatewayError> {
        if self.amount_minor < 0
            || self.currency.len() != 3
            || !self.currency.bytes().all(|byte| byte.is_ascii_uppercase())
        {
            return Err(GatewayError::InvalidBudget);
        }
        Ok(())
    }

    fn is_subset_of(&self, parent: &Self) -> bool {
        self.currency == parent.currency && self.amount_minor <= parent.amount_minor
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetAuthority {
    pub max_tokens: u64,
    pub max_cost: CostLimit,
    pub max_request_bytes: u64,
    pub max_result_bytes: u64,
    pub max_external_effects: u32,
    pub deadline_at: DateTime<Utc>,
}

impl BudgetAuthority {
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), GatewayError> {
        self.max_cost.validate()?;
        if self.max_tokens == 0
            || self.max_request_bytes == 0
            || self.max_result_bytes == 0
            || self.deadline_at <= now
        {
            return Err(GatewayError::InvalidBudget);
        }
        if self.max_request_bytes > MAX_PAYLOAD_BYTES as u64
            || self.max_result_bytes > MAX_PAYLOAD_BYTES as u64
        {
            return Err(GatewayError::PayloadLimitExceeded);
        }
        Ok(())
    }

    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.max_tokens <= parent.max_tokens
            && self.max_cost.is_subset_of(&parent.max_cost)
            && self.max_request_bytes <= parent.max_request_bytes
            && self.max_result_bytes <= parent.max_result_bytes
            && self.max_external_effects <= parent.max_external_effects
            && self.deadline_at <= parent.deadline_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetUse {
    pub request_bytes: u64,
    pub result_bytes: u64,
    pub estimated_tokens: u64,
    pub estimated_cost: CostLimit,
    pub external_effect_count: u32,
}

impl BudgetUse {
    fn validate_against(&self, budget: &BudgetAuthority) -> Result<(), GatewayError> {
        self.estimated_cost.validate()?;
        if self.request_bytes > budget.max_request_bytes
            || self.result_bytes > budget.max_result_bytes
            || self.estimated_tokens > budget.max_tokens
            || self.external_effect_count > budget.max_external_effects
            || !self.estimated_cost.is_subset_of(&budget.max_cost)
        {
            return Err(GatewayError::BudgetExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretReference {
    pub id: SecretReferenceId,
    pub provider: String,
    pub purpose: String,
    pub scope_digest: Digest,
    pub version: u64,
}

impl SecretReference {
    pub fn validate(&self) -> Result<(), GatewayError> {
        self.id.validate()?;
        if self.provider.trim().is_empty()
            || self.purpose.trim().is_empty()
            || self.version == 0
            || self.scope_digest.as_str().is_empty()
        {
            return Err(GatewayError::InvalidSecretReference);
        }
        Ok(())
    }

    fn digest(&self) -> Digest {
        Digest::from_bytes(&serde_json::to_vec(self).unwrap_or_default())
    }
}

impl<'de> Deserialize<'de> for SecretReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = SecretReferenceWire::deserialize(deserializer)?;
        let reference = Self {
            id: value.id,
            provider: value.provider,
            purpose: value.purpose,
            scope_digest: value.scope_digest,
            version: value.version,
        };
        reference.validate().map_err(D::Error::custom)?;
        Ok(reference)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretReferenceWire {
    id: SecretReferenceId,
    provider: String,
    purpose: String,
    scope_digest: Digest,
    version: u64,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("digest", &self.digest())
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretAuthority {
    pub references: BTreeSet<SecretReference>,
}

impl SecretAuthority {
    pub fn none() -> Self {
        Self {
            references: BTreeSet::new(),
        }
    }

    pub fn validate(&self) -> Result<(), GatewayError> {
        for reference in &self.references {
            reference.validate()?;
        }
        Ok(())
    }

    pub fn allows(&self, id: &SecretReferenceId) -> bool {
        self.references.iter().any(|reference| &reference.id == id)
    }

    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.references.is_subset(&parent.references)
    }
}

impl<'de> Deserialize<'de> for SecretAuthority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let references = BTreeSet::<SecretReference>::deserialize(deserializer)?;
        let authority = Self { references };
        authority.validate().map_err(D::Error::custom)?;
        Ok(authority)
    }
}

impl fmt::Debug for SecretAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretAuthority")
            .field("reference_count", &self.references.len())
            .field("reference_set_digest", &digest_serialized(&self.references))
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataAuthority {
    pub maximum_class: DataClass,
    pub allowed_resource_digests: BTreeSet<Digest>,
}

impl DataAuthority {
    pub fn validate(&self) -> Result<(), GatewayError> {
        if self
            .allowed_resource_digests
            .iter()
            .any(|digest| !is_sha256(digest.as_str()))
        {
            return Err(GatewayError::InvalidDigest);
        }
        Ok(())
    }

    pub fn permits(&self, class: DataClass, resource_digest: Option<&Digest>) -> bool {
        class.is_at_most(self.maximum_class)
            && (self.allowed_resource_digests.is_empty()
                || resource_digest
                    .is_some_and(|digest| self.allowed_resource_digests.contains(digest)))
    }

    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.maximum_class <= parent.maximum_class
            && if parent.allowed_resource_digests.is_empty() {
                true
            } else {
                !self.allowed_resource_digests.is_empty()
                    && self
                        .allowed_resource_digests
                        .is_subset(&parent.allowed_resource_digests)
            }
    }
}

impl<'de> Deserialize<'de> for DataAuthority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            maximum_class: DataClass,
            #[serde(default)]
            allowed_resource_digests: BTreeSet<Digest>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let authority = Self {
            maximum_class: wire.maximum_class,
            allowed_resource_digests: wire.allowed_resource_digests,
        };
        authority.validate().map_err(D::Error::custom)?;
        Ok(authority)
    }
}

impl fmt::Debug for DataAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataAuthority")
            .field("maximum_class", &self.maximum_class)
            .field("resource_count", &self.allowed_resource_digests.len())
            .field(
                "resource_set_digest",
                &digest_serialized(&self.allowed_resource_digests),
            )
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum NetworkAuthority {
    None,
    ReadOnly { origins: BTreeSet<Origin> },
    EffectBroker { providers: BTreeSet<String> },
}

impl NetworkAuthority {
    pub fn validate(&self) -> Result<(), GatewayError> {
        match self {
            Self::None => Ok(()),
            Self::ReadOnly { origins } => {
                if origins.is_empty() {
                    return Err(GatewayError::InvalidNetworkAuthority);
                }
                Ok(())
            }
            Self::EffectBroker { providers } => {
                if providers.is_empty()
                    || providers
                        .iter()
                        .any(|provider| provider.trim().is_empty() || provider.contains('*'))
                {
                    return Err(GatewayError::InvalidNetworkAuthority);
                }
                Ok(())
            }
        }
    }

    pub fn is_subset_of(&self, parent: &Self) -> bool {
        match (self, parent) {
            (Self::None, _) => true,
            (Self::ReadOnly { origins }, Self::ReadOnly { origins: parent }) => {
                origins.is_subset(parent)
            }
            (Self::EffectBroker { providers }, Self::EffectBroker { providers: parent }) => {
                providers.is_subset(parent)
            }
            _ => false,
        }
    }

    fn allows_provider(&self, provider: &str) -> bool {
        matches!(self, Self::EffectBroker { providers } if providers.contains(provider))
    }
}

/// An exact HTTPS origin. Paths, query strings, fragments, credentials and
/// wildcards are rejected so a capability cannot silently become a URL fetcher.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Origin(String);

impl Origin {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, GatewayError> {
        let url = Url::parse(value.as_ref()).map_err(|_| GatewayError::InvalidOrigin)?;
        let host = url.host_str().ok_or(GatewayError::InvalidOrigin)?;
        if url.scheme() != "https"
            || url.username() != ""
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || host.contains('*')
        {
            return Err(GatewayError::InvalidOrigin);
        }
        let canonical = match url.port() {
            Some(port) => format!("https://{host}:{port}"),
            None => format!("https://{host}"),
        };
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Origin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl fmt::Debug for Origin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Origin")
            .field("digest", &Digest::from_text(&self.0))
            .finish()
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectAuthority {
    pub allowed_kinds: BTreeSet<EffectKind>,
    pub allowed_providers: BTreeSet<String>,
    pub approval: ApprovalRequirement,
    pub uncertain_policy: UncertainEffectPolicy,
    pub max_cost: Option<CostLimit>,
    pub broker_policy_digest: Digest,
}

impl EffectAuthority {
    pub fn proposal_only(broker_policy_digest: Digest) -> Self {
        Self {
            allowed_kinds: BTreeSet::new(),
            allowed_providers: BTreeSet::new(),
            approval: ApprovalRequirement::Required,
            uncertain_policy: UncertainEffectPolicy::ReconcileOnly,
            max_cost: None,
            broker_policy_digest,
        }
    }

    pub fn validate(&self, class: CapabilityClass) -> Result<(), GatewayError> {
        if self.broker_policy_digest.as_str().is_empty()
            || self.approval != ApprovalRequirement::Required
            || self.uncertain_policy != UncertainEffectPolicy::ReconcileOnly
        {
            return Err(GatewayError::InvalidEffectAuthority);
        }
        if class == CapabilityClass::ExternalEffect
            && (self.allowed_kinds.is_empty() || self.allowed_providers.is_empty())
        {
            return Err(GatewayError::InvalidEffectAuthority);
        }
        if let Some(max_cost) = &self.max_cost {
            max_cost.validate()?;
        }
        if self
            .allowed_providers
            .iter()
            .any(|provider| provider.contains('*'))
        {
            return Err(GatewayError::InvalidEffectAuthority);
        }
        Ok(())
    }

    pub fn allows(&self, kind: EffectKind, provider: &str, amount: Option<&CostLimit>) -> bool {
        if !self.allowed_kinds.contains(&kind) || !self.allowed_providers.contains(provider) {
            return false;
        }
        match (&self.max_cost, amount) {
            (Some(maximum), Some(value)) => value.is_subset_of(maximum),
            (Some(_), None) => false,
            _ => true,
        }
    }

    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.allowed_kinds.is_subset(&parent.allowed_kinds)
            && self.allowed_providers.is_subset(&parent.allowed_providers)
            && match (&self.max_cost, &parent.max_cost) {
                (None | Some(_), None) => true,
                (None, Some(_)) => false,
                (Some(value), Some(maximum)) => value.is_subset_of(maximum),
            }
            && self.approval == parent.approval
            && self.uncertain_policy == parent.uncertain_policy
            && self.broker_policy_digest == parent.broker_policy_digest
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectScope {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub workspace_digest: Digest,
    pub resource_scope_digest: Digest,
}

impl ProjectScope {
    pub fn validate(&self) -> Result<(), GatewayError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || !is_sha256(self.workspace_digest.as_str())
            || !is_sha256(self.resource_scope_digest.as_str())
        {
            return Err(GatewayError::InvalidScope);
        }
        Ok(())
    }
}

impl fmt::Debug for ProjectScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectScope")
            .field("tenant_digest", &Digest::from_text(self.tenant_id.as_str()))
            .field(
                "project_digest",
                &Digest::from_text(self.project_id.as_str()),
            )
            .field("workspace_digest", &self.workspace_digest)
            .field("resource_scope_digest", &self.resource_scope_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScope {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub task_id: Option<TaskId>,
    pub worker_id: Option<WorkerId>,
    pub worker_lease_id: Option<WorkerLeaseId>,
    pub context_workspace_id: Option<ContextWorkspaceId>,
    pub context_capsule_id: Option<ContextCapsuleId>,
    pub context_branch_id: Option<ContextBranchId>,
    pub generation: u64,
    pub contract_revision: u64,
    pub scope_digest: Digest,
}

impl MissionScope {
    pub fn validate(&self, project: &ProjectScope) -> Result<(), GatewayError> {
        if self.tenant_id != project.tenant_id
            || self.project_id != project.project_id
            || self.mission_id.as_str().trim().is_empty()
            || self.generation == 0
            || self.contract_revision == 0
            || !is_sha256(self.scope_digest.as_str())
        {
            return Err(GatewayError::InvalidScope);
        }
        if self.worker_lease_id.is_some() != self.worker_id.is_some() {
            return Err(GatewayError::InvalidScope);
        }
        Ok(())
    }

    pub fn same_execution(&self, other: &Self) -> bool {
        self.tenant_id == other.tenant_id
            && self.project_id == other.project_id
            && self.mission_id == other.mission_id
            && self.task_id == other.task_id
            && self.worker_id == other.worker_id
            && self.worker_lease_id == other.worker_lease_id
            && self.context_workspace_id == other.context_workspace_id
            && self.context_capsule_id == other.context_capsule_id
            && self.context_branch_id == other.context_branch_id
            && self.generation == other.generation
            && self.contract_revision == other.contract_revision
            && self.scope_digest == other.scope_digest
    }
}

impl fmt::Debug for MissionScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionScope")
            .field("tenant_digest", &Digest::from_text(self.tenant_id.as_str()))
            .field(
                "project_digest",
                &Digest::from_text(self.project_id.as_str()),
            )
            .field(
                "mission_digest",
                &Digest::from_text(self.mission_id.as_str()),
            )
            .field("task_present", &self.task_id.is_some())
            .field("worker_present", &self.worker_id.is_some())
            .field("generation", &self.generation)
            .field("contract_revision", &self.contract_revision)
            .field("scope_digest", &self.scope_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterBinding {
    pub adapter_id: AdapterId,
    pub implementation_id: String,
    pub implementation_digest: Digest,
    pub binary_digest: Digest,
    pub schema_digest: Digest,
    pub version: String,
    pub revocation_epoch: u64,
}

impl AdapterBinding {
    pub fn validate(&self) -> Result<(), GatewayError> {
        self.adapter_id.validate()?;
        if self.implementation_id.trim().is_empty()
            || self.implementation_id.len() > 256
            || self.version.trim().is_empty()
            || self.version.len() > 256
            || self.revocation_epoch == 0
        {
            return Err(GatewayError::InvalidAdapterBinding);
        }
        Ok(())
    }

    fn exact_digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn digest(&self) -> Digest {
        self.exact_digest()
    }
}

impl fmt::Debug for AdapterBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterBinding")
            .field("adapter_digest", &self.exact_digest())
            .field("version", &self.version)
            .field("revocation_epoch", &self.revocation_epoch)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationBinding {
    pub registry_revision: u64,
    pub revocation_epoch: u64,
    pub status: RevocationStatus,
    pub record_digest: Digest,
}

impl RevocationBinding {
    fn validate(&self) -> Result<(), GatewayError> {
        if self.registry_revision == 0
            || self.revocation_epoch == 0
            || !is_sha256(self.record_digest.as_str())
            || self.status == RevocationStatus::Revoked
        {
            return Err(GatewayError::ManifestRevoked);
        }
        Ok(())
    }
}

impl fmt::Debug for RevocationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RevocationBinding")
            .field("registry_revision", &self.registry_revision)
            .field("revocation_epoch", &self.revocation_epoch)
            .field("status", &self.status)
            .field("record_digest", &self.record_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceSource {
    Runtime,
    BrowserAdapter,
    Application,
    EffectBroker,
    Recovery,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    pub source: ProvenanceSource,
    pub manifest_digest: Digest,
    pub authority_digest: Digest,
    pub parent_digest: Option<Digest>,
    pub input_digest: Digest,
    pub generation: u64,
    pub observed_at: DateTime<Utc>,
    pub links: Vec<Digest>,
}

impl Provenance {
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), GatewayError> {
        if self.manifest_digest.as_str().is_empty()
            || self.authority_digest.as_str().is_empty()
            || self.input_digest.as_str().is_empty()
            || self.generation == 0
            || self.observed_at > now
            || self.links.len() > MAX_PROVENANCE_LINKS
            || self.links.iter().any(|digest| digest.as_str().is_empty())
        {
            return Err(GatewayError::InvalidProvenance);
        }
        Ok(())
    }
}

impl fmt::Debug for Provenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Provenance")
            .field("source", &self.source)
            .field("manifest_digest", &self.manifest_digest)
            .field("authority_digest", &self.authority_digest)
            .field("parent_present", &self.parent_digest.is_some())
            .field("input_digest", &self.input_digest)
            .field("generation", &self.generation)
            .field("link_count", &self.links.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestIssuer {
    Application,
    MissionCompiler,
    RecoveryController,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestProvenance {
    pub issuer: ManifestIssuer,
    pub source_digest: Digest,
    pub parent_manifest_digest: Option<Digest>,
    pub issued_for_generation: u64,
}

impl ManifestProvenance {
    fn validate(&self, generation: u64) -> Result<(), GatewayError> {
        if self.source_digest.as_str().is_empty()
            || self.issued_for_generation == 0
            || self.issued_for_generation != generation
        {
            return Err(GatewayError::InvalidProvenance);
        }
        Ok(())
    }
}

impl fmt::Debug for ManifestProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManifestProvenance")
            .field("issuer", &self.issuer)
            .field("source_digest", &self.source_digest)
            .field("parent_present", &self.parent_manifest_digest.is_some())
            .field("issued_for_generation", &self.issued_for_generation)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityManifest {
    pub schema: String,
    pub manifest_version: u32,
    pub schema_digest: Digest,
    pub capability_id: CapabilityId,
    pub class: CapabilityClass,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub data: DataAuthority,
    pub network: NetworkAuthority,
    pub secrets: SecretAuthority,
    pub budget: BudgetAuthority,
    pub effect: EffectAuthority,
    pub adapter: AdapterBinding,
    pub revocation: RevocationBinding,
    pub provenance: ManifestProvenance,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl CapabilityManifest {
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), GatewayError> {
        if self.schema != CAPABILITY_MANIFEST_SCHEMA
            || self.manifest_version == 0
            || self.schema_digest.as_str().is_empty()
            || self.capability_id.as_str().trim().is_empty()
            || !valid_capability_id(self.capability_id.as_str())
            || self.expires_at <= self.issued_at
            || now < self.issued_at
            || now >= self.expires_at
        {
            return Err(GatewayError::InvalidManifest);
        }
        self.project.validate()?;
        self.mission.validate(&self.project)?;
        self.data.validate()?;
        self.network.validate()?;
        self.secrets.validate()?;
        self.budget.validate(now)?;
        self.effect.validate(self.class)?;
        self.adapter.validate()?;
        self.revocation.validate()?;
        self.provenance.validate(self.mission.generation)?;
        if self.adapter.schema_digest != self.schema_digest
            || self.adapter.revocation_epoch != self.revocation.revocation_epoch
        {
            return Err(GatewayError::ManifestBindingMismatch);
        }
        match self.class {
            CapabilityClass::Read => {
                if !self.effect.allowed_kinds.is_empty()
                    || !self.effect.allowed_providers.is_empty()
                    || !matches!(
                        self.network,
                        NetworkAuthority::None | NetworkAuthority::ReadOnly { .. }
                    )
                {
                    return Err(GatewayError::InvalidEffectAuthority);
                }
            }
            CapabilityClass::LocalMutation => {
                if !matches!(self.network, NetworkAuthority::None)
                    || !self.effect.allowed_kinds.is_empty()
                    || !self.effect.allowed_providers.is_empty()
                {
                    return Err(GatewayError::InvalidNetworkAuthority);
                }
            }
            CapabilityClass::ExternalEffect => {
                if !matches!(self.network, NetworkAuthority::EffectBroker { .. }) {
                    return Err(GatewayError::InvalidNetworkAuthority);
                }
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GatewayError> {
        serde_json::to_vec(self).map_err(|_| GatewayError::CanonicalizationFailed)
    }

    pub fn digest(&self) -> Result<Digest, GatewayError> {
        Ok(Digest::from_bytes(&self.canonical_bytes()?))
    }

    pub fn authority_digest(&self) -> Result<Digest, GatewayError> {
        let authority = (
            &self.project,
            &self.mission,
            self.class,
            &self.data,
            &self.network,
            &self.secrets,
            &self.budget,
            &self.effect,
            &self.adapter,
            &self.revocation,
        );
        Ok(digest_serialized(&authority))
    }

    pub fn is_authority_subset_of(&self, parent: &Self) -> Result<bool, GatewayError> {
        Ok(self.project == parent.project
            && self.mission.same_execution(&parent.mission)
            && self.class == parent.class
            && self.capability_id == parent.capability_id
            && self.adapter == parent.adapter
            && self.revocation == parent.revocation
            && self.data.is_subset_of(&parent.data)
            && self.network.is_subset_of(&parent.network)
            && self.secrets.is_subset_of(&parent.secrets)
            && self.budget.is_subset_of(&parent.budget)
            && self.effect.is_subset_of(&parent.effect))
    }
}

impl fmt::Debug for CapabilityManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digest = self.digest().ok();
        formatter
            .debug_struct("CapabilityManifest")
            .field("schema", &self.schema)
            .field("manifest_version", &self.manifest_version)
            .field("manifest_digest", &digest)
            .field(
                "capability_digest",
                &Digest::from_text(self.capability_id.as_str()),
            )
            .field("class", &self.class)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("data", &self.data)
            .field("network", &self.network)
            .field("secrets", &self.secrets)
            .field("budget", &self.budget)
            .field("effect", &self.effect)
            .field("adapter", &self.adapter)
            .field("revocation", &self.revocation)
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestSignature {
    pub algorithm: String,
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ManifestSignature {
    fn validate(&self) -> Result<(), GatewayError> {
        if self.algorithm != "ed25519"
            || self.key_id.trim().is_empty()
            || self.key_id.len() > 256
            || self.public_key.len() != 32
            || self.signature.len() != 64
        {
            return Err(GatewayError::InvalidSignature);
        }
        Ok(())
    }
}

impl fmt::Debug for ManifestSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManifestSignature")
            .field("algorithm", &self.algorithm)
            .field("key_id_digest", &Digest::from_text(&self.key_id))
            .field("public_key_digest", &Digest::from_bytes(&self.public_key))
            .field("signature_digest", &Digest::from_bytes(&self.signature))
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedCapabilityManifest {
    pub manifest: CapabilityManifest,
    pub signature: ManifestSignature,
}

impl SignedCapabilityManifest {
    pub fn sign(
        manifest: CapabilityManifest,
        key_id: impl Into<String>,
        pkcs8_private_key: &[u8],
    ) -> Result<Self, GatewayError> {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_private_key)
            .map_err(|_| GatewayError::InvalidSigningKey)?;
        let bytes = manifest.canonical_bytes()?;
        let public_key = key_pair.public_key().as_ref().to_vec();
        let signature = key_pair.sign(&bytes).as_ref().to_vec();
        let signed = Self {
            manifest,
            signature: ManifestSignature {
                algorithm: "ed25519".into(),
                key_id: key_id.into(),
                public_key,
                signature,
            },
        };
        signed.signature.validate()?;
        Ok(signed)
    }

    pub fn verify(&self, now: DateTime<Utc>) -> Result<(), GatewayError> {
        self.manifest.validate(now)?;
        self.signature.validate()?;
        let public_key =
            signature::UnparsedPublicKey::new(&signature::ED25519, &self.signature.public_key);
        public_key
            .verify(&self.manifest.canonical_bytes()?, &self.signature.signature)
            .map_err(|_| GatewayError::SignatureVerificationFailed)
    }

    pub fn digest(&self) -> Result<Digest, GatewayError> {
        self.manifest.digest()
    }
}

impl fmt::Debug for SignedCapabilityManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedCapabilityManifest")
            .field("manifest", &self.manifest)
            .field("signature", &self.signature)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterStatus {
    Active,
    Revoked,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterRegistration {
    pub binding: AdapterBinding,
    pub capabilities: BTreeSet<CapabilityId>,
    pub status: AdapterStatus,
    pub registry_revision: u64,
    pub record_digest: Digest,
}

impl AdapterRegistration {
    fn refresh_digest(&mut self) {
        self.record_digest = digest_serialized(&(
            &self.binding,
            &self.capabilities,
            self.status,
            self.registry_revision,
        ));
    }

    fn validate(&self) -> Result<(), GatewayError> {
        self.binding.validate()?;
        if self.capabilities.is_empty()
            || self
                .capabilities
                .iter()
                .any(|capability| !valid_capability_id(capability.as_str()))
            || self.registry_revision == 0
            || self.record_digest
                != digest_serialized(&(
                    &self.binding,
                    &self.capabilities,
                    self.status,
                    self.registry_revision,
                ))
        {
            return Err(GatewayError::InvalidAdapterRegistry);
        }
        Ok(())
    }
}

impl fmt::Debug for AdapterRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterRegistration")
            .field("binding", &self.binding)
            .field("capability_count", &self.capabilities.len())
            .field("status", &self.status)
            .field("registry_revision", &self.registry_revision)
            .field("record_digest", &self.record_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterRegistry {
    pub schema: String,
    pub revision: u64,
    pub registrations: BTreeMap<AdapterId, AdapterRegistration>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self {
            schema: ADAPTER_REGISTRY_SCHEMA.into(),
            revision: 1,
            registrations: BTreeMap::new(),
        }
    }

    pub fn register(
        &mut self,
        binding: AdapterBinding,
        capabilities: BTreeSet<CapabilityId>,
    ) -> Result<Digest, GatewayError> {
        if self.schema != ADAPTER_REGISTRY_SCHEMA
            || capabilities.is_empty()
            || capabilities
                .iter()
                .any(|capability| !valid_capability_id(capability.as_str()))
        {
            return Err(GatewayError::InvalidAdapterRegistry);
        }
        binding.validate()?;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(GatewayError::RevisionOverflow)?;
        let mut registration = AdapterRegistration {
            binding,
            capabilities,
            status: AdapterStatus::Active,
            registry_revision: self.revision,
            record_digest: Digest::from_text("uninitialized"),
        };
        registration.refresh_digest();
        self.registrations.insert(
            registration.binding.adapter_id.clone(),
            registration.clone(),
        );
        Ok(registration.record_digest)
    }

    pub fn revoke(&mut self, adapter_id: &AdapterId) -> Result<Digest, GatewayError> {
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(GatewayError::RevisionOverflow)?;
        let registration = self
            .registrations
            .get_mut(adapter_id)
            .ok_or(GatewayError::AdapterNotRegistered)?;
        if registration.status == AdapterStatus::Revoked {
            return Err(GatewayError::AdapterRevoked);
        }
        self.revision = next_revision;
        registration.status = AdapterStatus::Revoked;
        registration.registry_revision = self.revision;
        registration.binding.revocation_epoch = registration
            .binding
            .revocation_epoch
            .checked_add(1)
            .ok_or(GatewayError::RevisionOverflow)?;
        registration.refresh_digest();
        Ok(registration.record_digest.clone())
    }

    pub fn registration(&self, adapter_id: &AdapterId) -> Option<&AdapterRegistration> {
        self.registrations.get(adapter_id)
    }

    pub fn validate(&self) -> Result<(), GatewayError> {
        if self.schema != ADAPTER_REGISTRY_SCHEMA || self.revision == 0 {
            return Err(GatewayError::InvalidAdapterRegistry);
        }
        for (adapter_id, registration) in &self.registrations {
            if adapter_id != &registration.binding.adapter_id {
                return Err(GatewayError::InvalidAdapterRegistry);
            }
            registration.validate()?;
        }
        Ok(())
    }

    pub fn authorize(
        &self,
        binding: &AdapterBinding,
        capability: &CapabilityId,
        revocation: &RevocationBinding,
    ) -> Result<(), GatewayError> {
        let registration = self
            .registrations
            .get(&binding.adapter_id)
            .ok_or(GatewayError::AdapterNotRegistered)?;
        if registration.status != AdapterStatus::Active
            || registration.binding != *binding
            || !registration.capabilities.contains(capability)
            || revocation.status != RevocationStatus::Active
            || revocation.revocation_epoch != registration.binding.revocation_epoch
            || revocation.record_digest != registration.record_digest
            || revocation.registry_revision != registration.registry_revision
        {
            return Err(if registration.status == AdapterStatus::Revoked {
                GatewayError::AdapterRevoked
            } else {
                GatewayError::AdapterBindingMismatch
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest, GatewayError> {
        self.validate()?;
        Ok(digest_serialized(self))
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AdapterRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterRegistry")
            .field("schema", &self.schema)
            .field("revision", &self.revision)
            .field("adapter_count", &self.registrations.len())
            .field("registry_digest", &self.digest().ok())
            .finish()
    }
}

/// A bounded, non-Secret material envelope. The bytes are available only to
/// the typed adapter call; every Debug/error representation contains metadata
/// and a digest, never the bytes.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundedPayload {
    pub schema: String,
    pub data_class: DataClass,
    pub byte_len: u64,
    pub digest: Digest,
    pub bytes: Vec<u8>,
}

impl BoundedPayload {
    pub fn try_new(
        schema: impl Into<String>,
        data_class: DataClass,
        bytes: Vec<u8>,
        max_bytes: u64,
    ) -> Result<Self, GatewayError> {
        let schema = schema.into();
        let byte_len =
            u64::try_from(bytes.len()).map_err(|_| GatewayError::PayloadLimitExceeded)?;
        if schema.trim().is_empty()
            || byte_len == 0
            || byte_len > max_bytes
            || byte_len > MAX_PAYLOAD_BYTES as u64
        {
            return Err(GatewayError::PayloadLimitExceeded);
        }
        Ok(Self {
            schema,
            data_class,
            byte_len,
            digest: Digest::from_bytes(&bytes),
            bytes,
        })
    }

    pub fn descriptor(&self) -> PayloadDescriptor {
        PayloadDescriptor {
            schema: self.schema.clone(),
            data_class: self.data_class,
            byte_len: self.byte_len,
            digest: self.digest.clone(),
        }
    }

    pub fn validate(&self, max_bytes: u64) -> Result<(), GatewayError> {
        if self.schema.trim().is_empty()
            || self.byte_len == 0
            || self.byte_len != self.bytes.len() as u64
            || self.byte_len > max_bytes
            || self.byte_len > MAX_PAYLOAD_BYTES as u64
            || self.digest != Digest::from_bytes(&self.bytes)
        {
            return Err(GatewayError::PayloadTampered);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for BoundedPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            schema: String,
            data_class: DataClass,
            byte_len: u64,
            digest: Digest,
            bytes: Vec<u8>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let payload = Self::try_new(
            wire.schema,
            wire.data_class,
            wire.bytes,
            MAX_PAYLOAD_BYTES as u64,
        )
        .map_err(D::Error::custom)?;
        if payload.byte_len != wire.byte_len || payload.digest != wire.digest {
            return Err(D::Error::custom(
                "bounded payload digest or length mismatch",
            ));
        }
        Ok(payload)
    }
}

impl fmt::Debug for BoundedPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedPayload")
            .field("schema_digest", &Digest::from_text(&self.schema))
            .field("data_class", &self.data_class)
            .field("byte_len", &self.byte_len)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadDescriptor {
    pub schema: String,
    pub data_class: DataClass,
    pub byte_len: u64,
    pub digest: Digest,
}

impl PayloadDescriptor {
    pub fn validate(&self, max_bytes: u64) -> Result<(), GatewayError> {
        if self.schema.trim().is_empty()
            || self.byte_len == 0
            || self.byte_len > max_bytes
            || self.byte_len > MAX_PAYLOAD_BYTES as u64
            || !is_sha256(self.digest.as_str())
        {
            return Err(GatewayError::PayloadLimitExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceReference {
    pub id: ResourceId,
    pub data_class: DataClass,
    pub content_digest: Digest,
    pub revision: u64,
}

impl ResourceReference {
    fn validate(&self) -> Result<(), GatewayError> {
        self.id.validate()?;
        if self.revision == 0 || !is_sha256(self.content_digest.as_str()) {
            return Err(GatewayError::InvalidResourceReference);
        }
        Ok(())
    }
}

impl fmt::Debug for ResourceReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceReference")
            .field("id_digest", &Digest::from_text(self.id.as_str()))
            .field("data_class", &self.data_class)
            .field("content_digest", &self.content_digest)
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadOperation {
    ProjectSnapshot {
        revision: u64,
    },
    MissionSnapshot {
        revision: u64,
    },
    Resource {
        resource: ResourceReference,
    },
    Query {
        query_schema: String,
        query_digest: Digest,
        max_items: u32,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadRequest {
    pub operation: ReadOperation,
    pub requested_class: DataClass,
    #[serde(default)]
    pub secret_references: BTreeSet<SecretReferenceId>,
}

impl ReadRequest {
    fn validate(&self, manifest: &CapabilityManifest) -> Result<(), GatewayError> {
        let resource_digest = match &self.operation {
            ReadOperation::ProjectSnapshot { revision }
            | ReadOperation::MissionSnapshot { revision } => {
                if *revision == 0 {
                    return Err(GatewayError::InvalidRequest);
                }
                None
            }
            ReadOperation::Resource { resource } => {
                resource.validate()?;
                if resource.data_class != self.requested_class {
                    return Err(GatewayError::DataAuthorityViolation);
                }
                Some(&resource.content_digest)
            }
            ReadOperation::Query {
                query_schema,
                query_digest,
                max_items,
            } => {
                if query_schema.trim().is_empty()
                    || !is_sha256(query_digest.as_str())
                    || *max_items == 0
                {
                    return Err(GatewayError::InvalidRequest);
                }
                None
            }
        };
        if !manifest.data.permits(self.requested_class, resource_digest) {
            return Err(GatewayError::DataAuthorityViolation);
        }
        if self
            .secret_references
            .iter()
            .any(|reference| reference.validate().is_err() || !manifest.secrets.allows(reference))
        {
            return Err(GatewayError::SecretAuthorityViolation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum LocalMutationOperation {
    Draft {
        target: ResourceReference,
        base_revision: u64,
        content: BoundedPayload,
        #[serde(default)]
        evidence_digests: BTreeSet<Digest>,
    },
    Structured {
        target: ResourceReference,
        mutation_schema: String,
        content: BoundedPayload,
    },
    WorkspaceWrite {
        file_grant_digest: Digest,
        content: BoundedPayload,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalMutationRequest {
    pub operation: LocalMutationOperation,
    #[serde(default)]
    pub secret_references: BTreeSet<SecretReferenceId>,
}

impl LocalMutationRequest {
    fn validate(&self, manifest: &CapabilityManifest) -> Result<(), GatewayError> {
        if !matches!(manifest.network, NetworkAuthority::None) {
            return Err(GatewayError::InvalidNetworkAuthority);
        }
        let (data_class, digest) = match &self.operation {
            LocalMutationOperation::Draft {
                target,
                base_revision,
                content,
                evidence_digests,
            } => {
                target.validate()?;
                if *base_revision == 0
                    || evidence_digests
                        .iter()
                        .any(|digest| digest.as_str().is_empty())
                {
                    return Err(GatewayError::InvalidRequest);
                }
                content.validate(manifest.budget.max_request_bytes)?;
                (content.data_class, Some(&target.content_digest))
            }
            LocalMutationOperation::Structured {
                target,
                mutation_schema,
                content,
            } => {
                target.validate()?;
                if mutation_schema.trim().is_empty() {
                    return Err(GatewayError::InvalidRequest);
                }
                content.validate(manifest.budget.max_request_bytes)?;
                (content.data_class, Some(&target.content_digest))
            }
            LocalMutationOperation::WorkspaceWrite {
                file_grant_digest,
                content,
            } => {
                if file_grant_digest.as_str().is_empty() {
                    return Err(GatewayError::InvalidRequest);
                }
                content.validate(manifest.budget.max_request_bytes)?;
                (content.data_class, Some(&content.digest))
            }
        };
        if !manifest.data.permits(data_class, digest) {
            return Err(GatewayError::DataAuthorityViolation);
        }
        if self
            .secret_references
            .iter()
            .any(|reference| reference.validate().is_err() || !manifest.secrets.allows(reference))
        {
            return Err(GatewayError::SecretAuthorityViolation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalEffectRequest {
    pub effect_id: EffectId,
    pub kind: EffectKind,
    pub provider: String,
    pub target_origin: Origin,
    pub target_digest: Digest,
    pub payload: BoundedPayload,
    pub audience_digest: Option<Digest>,
    pub amount: Option<CostLimit>,
    pub approval_required: ApprovalRequirement,
    #[serde(default)]
    pub secret_references: BTreeSet<SecretReferenceId>,
}

impl ExternalEffectRequest {
    fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    fn validate(&self, manifest: &CapabilityManifest) -> Result<(), GatewayError> {
        if !matches!(manifest.network, NetworkAuthority::EffectBroker { .. })
            || !manifest.network.allows_provider(&self.provider)
            || !manifest
                .effect
                .allows(self.kind, &self.provider, self.amount.as_ref())
            || self.approval_required != ApprovalRequirement::Required
            || self.provider.trim().is_empty()
            || !is_sha256(self.target_digest.as_str())
        {
            return Err(GatewayError::EffectAuthorityViolation);
        }
        self.effect_id.validate()?;
        if let Some(amount) = &self.amount {
            amount.validate()?;
        }
        if self
            .secret_references
            .iter()
            .any(|reference| reference.validate().is_err() || !manifest.secrets.allows(reference))
        {
            return Err(GatewayError::SecretAuthorityViolation);
        }
        self.payload.validate(manifest.budget.max_request_bytes)?;
        if !manifest
            .data
            .permits(self.payload.data_class, Some(&self.payload.digest))
        {
            return Err(GatewayError::DataAuthorityViolation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RequestPayload {
    Read(ReadRequest),
    LocalMutation(LocalMutationRequest),
    ExternalEffect(ExternalEffectRequest),
}

impl RequestPayload {
    fn class(&self) -> CapabilityClass {
        match self {
            Self::Read(_) => CapabilityClass::Read,
            Self::LocalMutation(_) => CapabilityClass::LocalMutation,
            Self::ExternalEffect(_) => CapabilityClass::ExternalEffect,
        }
    }

    fn validate(&self, manifest: &CapabilityManifest) -> Result<(), GatewayError> {
        match self {
            Self::Read(request) => request.validate(manifest),
            Self::LocalMutation(request) => request.validate(manifest),
            Self::ExternalEffect(request) => request.validate(manifest),
        }
    }

    fn bounded_bytes(&self) -> u64 {
        match self {
            Self::Read(_) => 0,
            Self::LocalMutation(request) => match &request.operation {
                LocalMutationOperation::Draft { content, .. }
                | LocalMutationOperation::Structured { content, .. }
                | LocalMutationOperation::WorkspaceWrite { content, .. } => content.byte_len,
            },
            Self::ExternalEffect(request) => request.payload.byte_len,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvocationScope {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub task_id: Option<TaskId>,
    pub worker_id: Option<WorkerId>,
    pub worker_lease_id: Option<WorkerLeaseId>,
    pub context_workspace_id: Option<ContextWorkspaceId>,
    pub context_capsule_id: Option<ContextCapsuleId>,
    pub context_branch_id: Option<ContextBranchId>,
    pub generation: u64,
    pub scope_digest: Digest,
}

impl InvocationScope {
    pub fn from_manifest(manifest: &CapabilityManifest) -> Self {
        Self {
            tenant_id: manifest.mission.tenant_id.clone(),
            project_id: manifest.mission.project_id.clone(),
            mission_id: manifest.mission.mission_id.clone(),
            task_id: manifest.mission.task_id.clone(),
            worker_id: manifest.mission.worker_id.clone(),
            worker_lease_id: manifest.mission.worker_lease_id.clone(),
            context_workspace_id: manifest.mission.context_workspace_id.clone(),
            context_capsule_id: manifest.mission.context_capsule_id.clone(),
            context_branch_id: manifest.mission.context_branch_id.clone(),
            generation: manifest.mission.generation,
            scope_digest: manifest.mission.scope_digest.clone(),
        }
    }

    fn exact_match(&self, manifest: &CapabilityManifest) -> bool {
        self == &Self::from_manifest(manifest)
    }
}

impl fmt::Debug for InvocationScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvocationScope")
            .field("tenant_digest", &Digest::from_text(self.tenant_id.as_str()))
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
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityRequest {
    pub schema: String,
    pub request_id: RequestId,
    pub capability_id: CapabilityId,
    pub class: CapabilityClass,
    pub scope: InvocationScope,
    pub generation: u64,
    pub idempotency_key: IdempotencyKey,
    pub manifest_digest: Digest,
    pub provenance: Provenance,
    pub budget_use: BudgetUse,
    pub payload: RequestPayload,
}

impl CapabilityRequest {
    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    fn external_effect_digest(&self) -> Option<Digest> {
        match &self.payload {
            RequestPayload::ExternalEffect(effect) => Some(effect.digest()),
            _ => None,
        }
    }

    pub fn validate_against(
        &self,
        manifest: &CapabilityManifest,
        now: DateTime<Utc>,
    ) -> Result<(), GatewayError> {
        if self.schema != CAPABILITY_REQUEST_SCHEMA
            || self.capability_id != manifest.capability_id
            || self.class != manifest.class
            || self.generation != manifest.mission.generation
            || self.manifest_digest != manifest.digest()?
            || !self.scope.exact_match(manifest)
            || self.payload.class() != self.class
        {
            return Err(GatewayError::ScopeMismatch);
        }
        self.request_id.validate()?;
        self.idempotency_key.validate()?;
        let authority_digest = manifest.authority_digest()?;
        if self.provenance.manifest_digest != self.manifest_digest
            || self.provenance.authority_digest != authority_digest
            || self.provenance.generation != self.generation
        {
            return Err(GatewayError::ProvenanceMismatch);
        }
        self.provenance.validate(now)?;
        self.budget_use.validate_against(&manifest.budget)?;
        self.payload.validate(manifest)?;
        if self.budget_use.request_bytes < self.payload.bounded_bytes() {
            return Err(GatewayError::BudgetExceeded);
        }
        if let RequestPayload::ExternalEffect(effect) = &self.payload {
            effect.payload.validate(manifest.budget.max_request_bytes)?;
        }
        Ok(())
    }
}

impl fmt::Debug for CapabilityRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityRequest")
            .field("schema", &self.schema)
            .field("request_digest", &self.digest())
            .field("request_id_digest", &self.request_id.digest())
            .field(
                "capability_digest",
                &Digest::from_text(self.capability_id.as_str()),
            )
            .field("class", &self.class)
            .field("scope", &self.scope)
            .field("generation", &self.generation)
            .field("idempotency_key", &self.idempotency_key)
            .field("manifest_digest", &self.manifest_digest)
            .field("provenance", &self.provenance)
            .field("budget_use", &self.budget_use)
            .field("payload", &self.payload)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadRecoveryReason {
    TruncatedOutput,
    EmptyResult,
    RetryableRead,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalRecoveryReason {
    StaleLocatorOrPath,
    RetryableLocalMutation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryTarget {
    Read,
    LocalMutation,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryContract {
    pub manifest_digest: Digest,
    pub authority_digest: Digest,
    pub scope_digest: Digest,
    pub generation: u64,
    pub target: RecoveryTarget,
    pub attempt: u32,
    pub max_attempts: u32,
    pub automatic: bool,
    pub preserves_idempotency: bool,
}

impl RecoveryContract {
    fn validate_for(&self, request: &CapabilityRequest) -> Result<(), GatewayError> {
        if self.manifest_digest != request.manifest_digest
            || self.authority_digest != request.provenance.authority_digest
            || self.scope_digest != request.scope.scope_digest
            || self.generation != request.generation
            || self.attempt >= self.max_attempts
            || self.max_attempts == 0
            || self.max_attempts > 8
            || !self.preserves_idempotency
            || request.class == CapabilityClass::ExternalEffect
        {
            return Err(GatewayError::RecoveryScopeViolation);
        }
        let expected_target = match request.class {
            CapabilityClass::Read => RecoveryTarget::Read,
            CapabilityClass::LocalMutation => RecoveryTarget::LocalMutation,
            CapabilityClass::ExternalEffect => return Err(GatewayError::RecoveryScopeViolation),
        };
        if self.target != expected_target
            || self.automatic != (request.class == CapabilityClass::Read)
        {
            return Err(GatewayError::RecoveryScopeViolation);
        }
        Ok(())
    }
}

impl fmt::Debug for RecoveryContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryContract")
            .field("manifest_digest", &self.manifest_digest)
            .field("authority_digest", &self.authority_digest)
            .field("scope_digest", &self.scope_digest)
            .field("generation", &self.generation)
            .field("target", &self.target)
            .field("attempt", &self.attempt)
            .field("max_attempts", &self.max_attempts)
            .field("automatic", &self.automatic)
            .field("preserves_idempotency", &self.preserves_idempotency)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailClosedCode {
    ScopeDrift,
    AuthorityDrift,
    AdapterRevoked,
    PayloadTampered,
    BudgetExceeded,
    GenerationStale,
    UntrustedAdapter,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RecoveryDisposition {
    RetryRead {
        reason: ReadRecoveryReason,
        contract: RecoveryContract,
    },
    RetryLocalMutation {
        reason: LocalRecoveryReason,
        contract: RecoveryContract,
    },
    DuplicateRequest {
        request_digest: Digest,
        result_digest: Option<Digest>,
    },
    UncertainExternalEffect {
        effect_digest: Digest,
        reconciliation_digest: Digest,
    },
    FailClosed {
        code: FailClosedCode,
    },
}

impl RecoveryDisposition {
    pub fn retry_read(
        request: &CapabilityRequest,
        reason: ReadRecoveryReason,
        attempt: u32,
        max_attempts: u32,
    ) -> Result<Self, GatewayError> {
        let contract = RecoveryContract {
            manifest_digest: request.manifest_digest.clone(),
            authority_digest: request.provenance.authority_digest.clone(),
            scope_digest: request.scope.scope_digest.clone(),
            generation: request.generation,
            target: RecoveryTarget::Read,
            attempt,
            max_attempts,
            automatic: true,
            preserves_idempotency: true,
        };
        contract.validate_for(request)?;
        Ok(Self::RetryRead { reason, contract })
    }

    pub fn retry_local_mutation(
        request: &CapabilityRequest,
        reason: LocalRecoveryReason,
        attempt: u32,
        max_attempts: u32,
    ) -> Result<Self, GatewayError> {
        let contract = RecoveryContract {
            manifest_digest: request.manifest_digest.clone(),
            authority_digest: request.provenance.authority_digest.clone(),
            scope_digest: request.scope.scope_digest.clone(),
            generation: request.generation,
            target: RecoveryTarget::LocalMutation,
            attempt,
            max_attempts,
            automatic: false,
            preserves_idempotency: true,
        };
        contract.validate_for(request)?;
        Ok(Self::RetryLocalMutation { reason, contract })
    }

    pub fn duplicate(request: &CapabilityRequest, result_digest: Option<Digest>) -> Self {
        Self::DuplicateRequest {
            request_digest: request.digest(),
            result_digest,
        }
    }

    pub fn uncertain_external_effect(effect_digest: Digest, reconciliation_digest: Digest) -> Self {
        Self::UncertainExternalEffect {
            effect_digest,
            reconciliation_digest,
        }
    }

    pub fn validate_for(&self, request: &CapabilityRequest) -> Result<(), GatewayError> {
        match self {
            Self::RetryRead { contract, .. } | Self::RetryLocalMutation { contract, .. } => {
                contract.validate_for(request)
            }
            Self::DuplicateRequest { .. } | Self::FailClosed { .. } => Ok(()),
            Self::UncertainExternalEffect { .. } => {
                if request.class == CapabilityClass::ExternalEffect {
                    Ok(())
                } else {
                    Err(GatewayError::RecoveryScopeViolation)
                }
            }
        }
    }

    pub fn envelope(self) -> RecoveryEnvelope {
        RecoveryEnvelope {
            schema: CAPABILITY_RECOVERY_SCHEMA.into(),
            disposition: self,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryEnvelope {
    pub schema: String,
    #[serde(flatten)]
    pub disposition: RecoveryDisposition,
}

impl RecoveryEnvelope {
    pub fn validate_for(&self, request: &CapabilityRequest) -> Result<(), GatewayError> {
        if self.schema != CAPABILITY_RECOVERY_SCHEMA {
            return Err(GatewayError::RecoveryScopeViolation);
        }
        self.disposition.validate_for(request)
    }
}

impl fmt::Debug for RecoveryDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RetryRead { reason, contract } => formatter
                .debug_struct("RetryRead")
                .field("reason", reason)
                .field("contract", contract)
                .finish(),
            Self::RetryLocalMutation { reason, contract } => formatter
                .debug_struct("RetryLocalMutation")
                .field("reason", reason)
                .field("contract", contract)
                .finish(),
            Self::DuplicateRequest {
                request_digest,
                result_digest,
            } => formatter
                .debug_struct("DuplicateRequest")
                .field("request_digest", request_digest)
                .field("result_digest", result_digest)
                .finish(),
            Self::UncertainExternalEffect {
                effect_digest,
                reconciliation_digest,
            } => formatter
                .debug_struct("UncertainExternalEffect")
                .field("effect_digest", effect_digest)
                .field("reconciliation_digest", reconciliation_digest)
                .finish(),
            Self::FailClosed { code } => formatter
                .debug_struct("FailClosed")
                .field("code", code)
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadCompleteness {
    Complete,
    Truncated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadResult {
    pub payload: Option<BoundedPayload>,
    pub completeness: ReadCompleteness,
    pub continuation_digest: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalMutationResult {
    pub target_digest: Digest,
    pub new_revision: u64,
    pub mutation_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectDisposition {
    Proposed,
    BrokerAccepted,
    ReceiptPending,
    Uncertain,
    Rejected,
    Verified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalEffectResult {
    pub effect_id: EffectId,
    pub effect_digest: Digest,
    pub disposition: EffectDisposition,
    pub receipt_digest: Option<Digest>,
    pub verification_digest: Option<Digest>,
    pub reconciliation_digest: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ResultPayload {
    Read(ReadResult),
    LocalMutation(LocalMutationResult),
    ExternalEffect(ExternalEffectResult),
}

impl ResultPayload {
    fn class(&self) -> CapabilityClass {
        match self {
            Self::Read(_) => CapabilityClass::Read,
            Self::LocalMutation(_) => CapabilityClass::LocalMutation,
            Self::ExternalEffect(_) => CapabilityClass::ExternalEffect,
        }
    }

    fn bounded_bytes(&self) -> u64 {
        match self {
            Self::Read(result) => result
                .payload
                .as_ref()
                .map_or(0, |payload| payload.byte_len),
            Self::LocalMutation(_) | Self::ExternalEffect(_) => 0,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityResult {
    pub schema: String,
    pub request_id: RequestId,
    pub capability_id: CapabilityId,
    pub class: CapabilityClass,
    pub scope: InvocationScope,
    pub generation: u64,
    pub manifest_digest: Digest,
    pub provenance: Provenance,
    pub budget_use: BudgetUse,
    pub payload: ResultPayload,
}

impl CapabilityResult {
    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn validate_against(
        &self,
        request: &CapabilityRequest,
        manifest: &CapabilityManifest,
        now: DateTime<Utc>,
    ) -> Result<(), GatewayError> {
        if self.schema != CAPABILITY_RESULT_SCHEMA
            || self.request_id != request.request_id
            || self.capability_id != request.capability_id
            || self.class != request.class
            || self.generation != request.generation
            || self.manifest_digest != request.manifest_digest
            || !self.scope.exact_match(manifest)
            || self.payload.class() != self.class
        {
            return Err(GatewayError::ResultScopeMismatch);
        }
        let authority_digest = manifest.authority_digest()?;
        if self.provenance.manifest_digest != request.manifest_digest
            || self.provenance.authority_digest != authority_digest
            || self.provenance.generation != request.generation
        {
            return Err(GatewayError::ProvenanceMismatch);
        }
        self.provenance.validate(now)?;
        self.budget_use.validate_against(&manifest.budget)?;
        if self.budget_use.result_bytes < self.payload.bounded_bytes() {
            return Err(GatewayError::BudgetExceeded);
        }
        match (&request.payload, &self.payload) {
            (RequestPayload::Read(read), ResultPayload::Read(result)) => {
                if let Some(payload) = &result.payload {
                    payload.validate(manifest.budget.max_result_bytes)?;
                    if !manifest
                        .data
                        .permits(payload.data_class, Some(&payload.digest))
                    {
                        return Err(GatewayError::DataAuthorityViolation);
                    }
                }
                if result.completeness == ReadCompleteness::Truncated
                    && result.continuation_digest.is_none()
                {
                    return Err(GatewayError::InvalidResult);
                }
                if result.completeness == ReadCompleteness::Complete
                    && result.continuation_digest.is_some()
                {
                    return Err(GatewayError::InvalidResult);
                }
                if read.requested_class > manifest.data.maximum_class {
                    return Err(GatewayError::DataAuthorityViolation);
                }
            }
            (RequestPayload::LocalMutation(request), ResultPayload::LocalMutation(result)) => {
                let expected_target_digest = match &request.operation {
                    LocalMutationOperation::Draft { target, .. }
                    | LocalMutationOperation::Structured { target, .. } => &target.content_digest,
                    LocalMutationOperation::WorkspaceWrite {
                        file_grant_digest, ..
                    } => file_grant_digest,
                };
                if result.new_revision == 0
                    || !is_sha256(result.mutation_digest.as_str())
                    || &result.target_digest != expected_target_digest
                {
                    return Err(GatewayError::InvalidResult);
                }
            }
            (RequestPayload::ExternalEffect(effect), ResultPayload::ExternalEffect(result)) => {
                if result.effect_digest != effect.digest()
                    || result.effect_id != effect.effect_id
                    || (result.disposition == EffectDisposition::Uncertain
                        && result.reconciliation_digest.is_none())
                {
                    return Err(GatewayError::InvalidResult);
                }
                if result.disposition == EffectDisposition::Verified
                    && (result.receipt_digest.is_none() || result.verification_digest.is_none())
                {
                    return Err(GatewayError::InvalidResult);
                }
                if result.disposition != EffectDisposition::Uncertain
                    && result.reconciliation_digest.is_some()
                {
                    return Err(GatewayError::InvalidResult);
                }
            }
            _ => return Err(GatewayError::ResultScopeMismatch),
        }
        Ok(())
    }
}

impl fmt::Debug for CapabilityResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityResult")
            .field("result_digest", &self.digest())
            .field("request_id_digest", &self.request_id.digest())
            .field(
                "capability_digest",
                &Digest::from_text(self.capability_id.as_str()),
            )
            .field("class", &self.class)
            .field("scope", &self.scope)
            .field("generation", &self.generation)
            .field("manifest_digest", &self.manifest_digest)
            .field("provenance", &self.provenance)
            .field("budget_use", &self.budget_use)
            .field("payload", &self.payload)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerStatus {
    InFlight,
    Completed,
    Recovery,
    UncertainExternalEffect,
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerKey {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub generation: u64,
    pub idempotency_digest: Digest,
}

impl LedgerKey {
    pub fn for_request(request: &CapabilityRequest) -> Self {
        Self {
            project_id: request.scope.project_id.clone(),
            mission_id: request.scope.mission_id.clone(),
            generation: request.generation,
            idempotency_digest: request.idempotency_key.digest(),
        }
    }
}

impl<'de> Deserialize<'de> for LedgerKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            project_id: ProjectId,
            mission_id: MissionId,
            generation: u64,
            idempotency_digest: Digest,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.generation == 0 {
            return Err(D::Error::custom("ledger generation is invalid"));
        }
        Ok(Self {
            project_id: wire.project_id,
            mission_id: wire.mission_id,
            generation: wire.generation,
            idempotency_digest: wire.idempotency_digest,
        })
    }
}

impl fmt::Debug for LedgerKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerKey")
            .field(
                "project_digest",
                &Digest::from_text(self.project_id.as_str()),
            )
            .field(
                "mission_digest",
                &Digest::from_text(self.mission_id.as_str()),
            )
            .field("generation", &self.generation)
            .field("idempotency_digest", &self.idempotency_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvocationRecord {
    pub request_digest: Digest,
    pub result_digest: Option<Digest>,
    pub status: LedgerStatus,
    pub recovery: Option<RecoveryDisposition>,
}

impl InvocationRecord {
    fn in_flight(request: &CapabilityRequest) -> Self {
        Self {
            request_digest: request.digest(),
            result_digest: None,
            status: LedgerStatus::InFlight,
            recovery: None,
        }
    }

    fn completed(request: &CapabilityRequest, result: &CapabilityResult) -> Self {
        Self {
            request_digest: request.digest(),
            result_digest: Some(result.digest()),
            status: LedgerStatus::Completed,
            recovery: None,
        }
    }

    fn recovery(request: &CapabilityRequest, disposition: RecoveryDisposition) -> Self {
        let uncertain = matches!(
            &disposition,
            RecoveryDisposition::UncertainExternalEffect { .. }
        );
        Self {
            request_digest: request.digest(),
            result_digest: None,
            status: if uncertain {
                LedgerStatus::UncertainExternalEffect
            } else {
                LedgerStatus::Recovery
            },
            recovery: Some(disposition),
        }
    }

    fn permits_explicit_retry(&self, request: &CapabilityRequest, request_digest: &Digest) -> bool {
        if self.status != LedgerStatus::Recovery {
            return false;
        }
        match self.recovery.as_ref() {
            Some(RecoveryDisposition::RetryRead { .. }) => {
                request.class == CapabilityClass::Read
                    && (request_digest == &self.request_digest
                        || request.provenance.parent_digest.as_ref() == Some(&self.request_digest))
            }
            Some(RecoveryDisposition::RetryLocalMutation { .. }) => {
                request.class == CapabilityClass::LocalMutation
                    && request.provenance.parent_digest.as_ref() == Some(&self.request_digest)
            }
            _ => false,
        }
    }
}

impl fmt::Debug for InvocationRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvocationRecord")
            .field("request_digest", &self.request_digest)
            .field("result_digest", &self.result_digest)
            .field("status", &self.status)
            .field("recovery", &self.recovery)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerClaim {
    Fresh,
    Existing(InvocationRecord),
}

pub trait InvocationLedger {
    fn claim(
        &mut self,
        key: &LedgerKey,
        request: &CapabilityRequest,
    ) -> Result<LedgerClaim, LedgerError>;

    fn complete(&mut self, key: LedgerKey, record: InvocationRecord) -> Result<(), LedgerError>;
}

#[derive(Clone, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryInvocationLedger {
    records: BTreeMap<LedgerKey, InvocationRecord>,
}

impl MemoryInvocationLedger {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl<'de> Deserialize<'de> for MemoryInvocationLedger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            records: BTreeMap<LedgerKey, InvocationRecord>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            records: wire.records,
        })
    }
}

impl InvocationLedger for MemoryInvocationLedger {
    fn claim(
        &mut self,
        key: &LedgerKey,
        request: &CapabilityRequest,
    ) -> Result<LedgerClaim, LedgerError> {
        let request_digest = request.digest();
        if let Some(record) = self.records.get(key) {
            if record.request_digest != request_digest {
                if record.permits_explicit_retry(request, &request_digest) {
                    self.records
                        .insert(key.clone(), InvocationRecord::in_flight(request));
                    return Ok(LedgerClaim::Fresh);
                }
                return Err(LedgerError::IdempotencyConflict);
            }
            if record.permits_explicit_retry(request, &request_digest) {
                self.records
                    .insert(key.clone(), InvocationRecord::in_flight(request));
                return Ok(LedgerClaim::Fresh);
            }
            return Ok(LedgerClaim::Existing(record.clone()));
        }
        self.records
            .insert(key.clone(), InvocationRecord::in_flight(request));
        Ok(LedgerClaim::Fresh)
    }

    fn complete(&mut self, key: LedgerKey, record: InvocationRecord) -> Result<(), LedgerError> {
        let existing = self.records.get(&key).ok_or(LedgerError::MissingClaim)?;
        if existing.request_digest != record.request_digest
            || existing.status != LedgerStatus::InFlight
        {
            return Err(LedgerError::CommitConflict);
        }
        self.records.insert(key, record);
        Ok(())
    }
}

impl fmt::Debug for MemoryInvocationLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryInvocationLedger")
            .field("record_count", &self.records.len())
            .field(
                "key_set_digest",
                &digest_serialized(&self.records.keys().collect::<Vec<_>>()),
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LedgerError {
    #[error("idempotency conflict")]
    IdempotencyConflict,
    #[error("durable invocation claim is missing")]
    MissingClaim,
    #[error("durable invocation claim changed")]
    CommitConflict,
    #[error("durable invocation ledger unavailable")]
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterFailureCode {
    TruncatedOutput,
    EmptyResult,
    RetryableRead,
    StaleLocatorOrPath,
    SchemaMismatch,
    Rejected,
    UncertainExternalEffect,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum AdapterFailure {
    Recovery {
        disposition: RecoveryDisposition,
    },
    Rejected {
        code: AdapterFailureCode,
    },
    UncertainExternalEffect {
        effect_digest: Digest,
        reconciliation_digest: Digest,
    },
}

impl AdapterFailure {
    pub fn recovery(disposition: RecoveryDisposition) -> Self {
        Self::Recovery { disposition }
    }

    fn debug_code(&self) -> &'static str {
        match self {
            Self::Recovery { .. } => "recovery",
            Self::Rejected { .. } => "rejected",
            Self::UncertainExternalEffect { .. } => "uncertain_external_effect",
        }
    }
}

impl fmt::Debug for AdapterFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recovery { disposition } => formatter
                .debug_struct("AdapterFailure")
                .field("code", &self.debug_code())
                .field("disposition", disposition)
                .finish(),
            Self::Rejected { code } => formatter
                .debug_struct("AdapterFailure")
                .field("code", &self.debug_code())
                .field("reason", code)
                .finish(),
            Self::UncertainExternalEffect {
                effect_digest,
                reconciliation_digest,
            } => formatter
                .debug_struct("AdapterFailure")
                .field("code", &self.debug_code())
                .field("effect_digest", effect_digest)
                .field("reconciliation_digest", reconciliation_digest)
                .finish(),
        }
    }
}

/// The only adapter hook exposed by the gateway. Implementations receive
/// typed, bounded data and return typed result envelopes; arbitrary host
/// commands, database objects and credential values have no representation in
/// this trait.
pub trait CapabilityAdapter {
    fn binding(&self) -> &AdapterBinding;

    fn invoke(&self, request: &CapabilityRequest) -> Result<CapabilityResult, AdapterFailure>;
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvocationPermit {
    pub request_digest: Digest,
    pub manifest_digest: Digest,
    pub authority_digest: Digest,
    pub adapter: AdapterBinding,
    pub class: CapabilityClass,
    pub generation: u64,
    _private: PhantomData<fn()>,
}

impl InvocationPermit {
    fn new(
        request: &CapabilityRequest,
        manifest: &CapabilityManifest,
    ) -> Result<Self, GatewayError> {
        Ok(Self {
            request_digest: request.digest(),
            manifest_digest: request.manifest_digest.clone(),
            authority_digest: manifest.authority_digest()?,
            adapter: manifest.adapter.clone(),
            class: request.class,
            generation: request.generation,
            _private: PhantomData,
        })
    }
}

impl fmt::Debug for InvocationPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvocationPermit")
            .field("request_digest", &self.request_digest)
            .field("manifest_digest", &self.manifest_digest)
            .field("authority_digest", &self.authority_digest)
            .field("adapter", &self.adapter)
            .field("class", &self.class)
            .field("generation", &self.generation)
            .finish()
    }
}

pub struct CapabilityGateway {
    registry: AdapterRegistry,
}

impl CapabilityGateway {
    pub fn new(registry: AdapterRegistry) -> Result<Self, GatewayError> {
        registry.digest()?;
        Ok(Self { registry })
    }

    pub fn registry(&self) -> &AdapterRegistry {
        &self.registry
    }

    pub fn authorize(
        &self,
        signed_manifest: &SignedCapabilityManifest,
        request: &CapabilityRequest,
        now: DateTime<Utc>,
    ) -> Result<InvocationPermit, GatewayError> {
        signed_manifest.verify(now)?;
        let manifest = &signed_manifest.manifest;
        self.registry.authorize(
            &manifest.adapter,
            &manifest.capability_id,
            &manifest.revocation,
        )?;
        request.validate_against(manifest, now)?;
        InvocationPermit::new(request, manifest)
    }

    #[allow(clippy::too_many_lines)]
    pub fn dispatch<A, L>(
        &self,
        signed_manifest: &SignedCapabilityManifest,
        request: &CapabilityRequest,
        adapter: &A,
        ledger: &mut L,
        now: DateTime<Utc>,
    ) -> Result<CapabilityResult, GatewayError>
    where
        A: CapabilityAdapter,
        L: InvocationLedger,
    {
        let permit = self.authorize(signed_manifest, request, now)?;
        Self::dispatch_with_permit(signed_manifest, &permit, request, adapter, ledger, now)
    }

    #[allow(clippy::too_many_lines)]
    pub fn dispatch_with_permit<A, L>(
        signed_manifest: &SignedCapabilityManifest,
        permit: &InvocationPermit,
        request: &CapabilityRequest,
        adapter: &A,
        ledger: &mut L,
        now: DateTime<Utc>,
    ) -> Result<CapabilityResult, GatewayError>
    where
        A: CapabilityAdapter,
        L: InvocationLedger,
    {
        signed_manifest.verify(now)?;
        let manifest_digest = signed_manifest.digest()?;
        let authority_digest = signed_manifest.manifest.authority_digest()?;
        if permit.manifest_digest != manifest_digest
            || permit.authority_digest != authority_digest
            || permit.request_digest != request.digest()
            || permit.manifest_digest != request.manifest_digest
            || permit.class != request.class
            || permit.generation != request.generation
        {
            return Err(GatewayError::InvalidInvocationPermit);
        }
        request.validate_against(&signed_manifest.manifest, now)?;
        if adapter.binding() != &permit.adapter {
            return Err(GatewayError::AdapterBindingMismatch);
        }
        let key = LedgerKey::for_request(request);
        match ledger.claim(&key, request).map_err(GatewayError::Ledger)? {
            LedgerClaim::Existing(record) => {
                if let Some(disposition) = record.recovery {
                    return Err(GatewayError::Recovery(disposition));
                }
                return Err(GatewayError::Recovery(RecoveryDisposition::duplicate(
                    request,
                    record.result_digest,
                )));
            }
            LedgerClaim::Fresh => {}
        }

        let result = match adapter.invoke(request) {
            Ok(result) => result,
            Err(AdapterFailure::Recovery { disposition }) => {
                if let Err(error) = disposition.validate_for(request) {
                    let safe_disposition = if request.class == CapabilityClass::ExternalEffect {
                        RecoveryDisposition::uncertain_external_effect(
                            request
                                .external_effect_digest()
                                .unwrap_or_else(|| request.digest()),
                            Digest::from_text("invalid-recovery-disposition"),
                        )
                    } else {
                        RecoveryDisposition::FailClosed {
                            code: FailClosedCode::UntrustedAdapter,
                        }
                    };
                    ledger
                        .complete(
                            key,
                            InvocationRecord::recovery(request, safe_disposition.clone()),
                        )
                        .map_err(GatewayError::Ledger)?;
                    return if request.class == CapabilityClass::ExternalEffect {
                        Err(GatewayError::Recovery(safe_disposition))
                    } else {
                        Err(error)
                    };
                }
                let record = InvocationRecord::recovery(request, disposition.clone());
                ledger.complete(key, record).map_err(GatewayError::Ledger)?;
                return Err(GatewayError::Recovery(disposition));
            }
            Err(AdapterFailure::UncertainExternalEffect {
                effect_digest: _adapter_effect_digest,
                reconciliation_digest,
            }) => {
                if request.class != CapabilityClass::ExternalEffect {
                    ledger
                        .complete(
                            key,
                            InvocationRecord::recovery(
                                request,
                                RecoveryDisposition::FailClosed {
                                    code: FailClosedCode::UntrustedAdapter,
                                },
                            ),
                        )
                        .map_err(GatewayError::Ledger)?;
                    return Err(GatewayError::RecoveryScopeViolation);
                }
                let effect_digest = request
                    .external_effect_digest()
                    .ok_or(GatewayError::RecoveryScopeViolation)?;
                let disposition = RecoveryDisposition::uncertain_external_effect(
                    effect_digest,
                    reconciliation_digest,
                );
                let record = InvocationRecord::recovery(request, disposition.clone());
                ledger.complete(key, record).map_err(GatewayError::Ledger)?;
                return Err(GatewayError::Recovery(disposition));
            }
            Err(AdapterFailure::Rejected { code }) => {
                let record = InvocationRecord::recovery(
                    request,
                    RecoveryDisposition::FailClosed {
                        code: FailClosedCode::UntrustedAdapter,
                    },
                );
                ledger.complete(key, record).map_err(GatewayError::Ledger)?;
                return Err(GatewayError::AdapterRejected(code));
            }
        };

        let result_validation_now = Utc::now().max(now);
        if let Err(error) =
            result.validate_against(request, &signed_manifest.manifest, result_validation_now)
        {
            let disposition = if request.class == CapabilityClass::ExternalEffect {
                RecoveryDisposition::uncertain_external_effect(
                    request
                        .external_effect_digest()
                        .unwrap_or_else(|| request.digest()),
                    Digest::from_text("gateway-result-validation"),
                )
            } else {
                RecoveryDisposition::FailClosed {
                    code: FailClosedCode::PayloadTampered,
                }
            };
            let record = InvocationRecord::recovery(request, disposition.clone());
            ledger
                .complete(key, record)
                .map_err(|ledger_error| GatewayError::LedgerCommitGap {
                    request_digest: request.digest(),
                    external_effect: request.class == CapabilityClass::ExternalEffect,
                    ledger_error,
                })?;
            return match disposition {
                RecoveryDisposition::UncertainExternalEffect { .. } => {
                    Err(GatewayError::Recovery(disposition))
                }
                _ => Err(error),
            };
        }

        let record = if request.class == CapabilityClass::ExternalEffect
            && matches!(
                &result.payload,
                ResultPayload::ExternalEffect(ExternalEffectResult {
                    disposition: EffectDisposition::Uncertain,
                    ..
                })
            ) {
            if let ResultPayload::ExternalEffect(effect) = &result.payload {
                InvocationRecord::recovery(
                    request,
                    RecoveryDisposition::uncertain_external_effect(
                        effect.effect_digest.clone(),
                        effect
                            .reconciliation_digest
                            .clone()
                            .unwrap_or_else(|| Digest::from_text("missing-reconciliation-digest")),
                    ),
                )
            } else {
                unreachable!("the effect match above is exhaustive")
            }
        } else {
            InvocationRecord::completed(request, &result)
        };
        if record.status == LedgerStatus::UncertainExternalEffect {
            let disposition = record.recovery.clone().ok_or(GatewayError::InvalidResult)?;
            ledger.complete(key, record).map_err(GatewayError::Ledger)?;
            return Err(GatewayError::Recovery(disposition));
        }
        ledger
            .complete(key, record)
            .map_err(|ledger_error| GatewayError::LedgerCommitGap {
                request_digest: request.digest(),
                external_effect: request.class == CapabilityClass::ExternalEffect,
                ledger_error,
            })?;
        Ok(result)
    }
}

impl fmt::Debug for CapabilityGateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityGateway")
            .field("registry", &self.registry)
            .finish()
    }
}

#[derive(Clone, Error, Eq, PartialEq)]
pub enum GatewayError {
    #[error("invalid SHA-256 digest")]
    InvalidDigest,
    #[error("invalid opaque identifier")]
    InvalidIdentifier,
    #[error("invalid idempotency key")]
    InvalidIdempotencyKey,
    #[error("invalid budget authority")]
    InvalidBudget,
    #[error("payload exceeds the bounded capability limit")]
    PayloadLimitExceeded,
    #[error("invalid Secret reference")]
    InvalidSecretReference,
    #[error("invalid data authority")]
    InvalidDataAuthority,
    #[error("invalid network authority")]
    InvalidNetworkAuthority,
    #[error("invalid external Effect authority")]
    InvalidEffectAuthority,
    #[error("invalid exact origin")]
    InvalidOrigin,
    #[error("invalid Project/Mission scope")]
    InvalidScope,
    #[error("invalid adapter binding")]
    InvalidAdapterBinding,
    #[error("manifest is invalid or expired")]
    InvalidManifest,
    #[error("manifest authority binding mismatch")]
    ManifestBindingMismatch,
    #[error("manifest has been revoked")]
    ManifestRevoked,
    #[error("invalid signature envelope")]
    InvalidSignature,
    #[error("invalid signing key")]
    InvalidSigningKey,
    #[error("manifest signature verification failed")]
    SignatureVerificationFailed,
    #[error("canonical boundary serialization failed")]
    CanonicalizationFailed,
    #[error("invalid adapter registry")]
    InvalidAdapterRegistry,
    #[error("adapter is not registered")]
    AdapterNotRegistered,
    #[error("adapter is revoked")]
    AdapterRevoked,
    #[error("adapter implementation, binary, schema, or epoch differs")]
    AdapterBindingMismatch,
    #[error("request is invalid")]
    InvalidRequest,
    #[error("request is outside the manifest scope")]
    ScopeMismatch,
    #[error("request data exceeds its authority")]
    DataAuthorityViolation,
    #[error("request Secret reference is outside its authority")]
    SecretAuthorityViolation,
    #[error("request Effect is outside its authority")]
    EffectAuthorityViolation,
    #[error("request budget is exceeded")]
    BudgetExceeded,
    #[error("request provenance does not match its authority")]
    ProvenanceMismatch,
    #[error("request payload was tampered with")]
    PayloadTampered,
    #[error("invalid provenance")]
    InvalidProvenance,
    #[error("invalid recovery scope")]
    RecoveryScopeViolation,
    #[error("result scope does not match its request")]
    ResultScopeMismatch,
    #[error("result is invalid")]
    InvalidResult,
    #[error("invocation authorization receipt does not match the typed request")]
    InvalidInvocationPermit,
    #[error("resource reference is invalid")]
    InvalidResourceReference,
    #[error("adapter rejected a typed request")]
    AdapterRejected(AdapterFailureCode),
    #[error("capability recovery requires explicit handling")]
    Recovery(RecoveryDisposition),
    #[error("idempotency ledger failure")]
    Ledger(LedgerError),
    #[error("idempotency conflict")]
    IdempotencyConflict,
    #[error("revision overflow")]
    RevisionOverflow,
    #[error("ledger commit gap after capability dispatch")]
    LedgerCommitGap {
        request_digest: Digest,
        external_effect: bool,
        ledger_error: LedgerError,
    },
}

impl fmt::Debug for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recovery(disposition) => formatter
                .debug_struct("GatewayError")
                .field("code", &"recovery")
                .field("disposition", disposition)
                .finish(),
            Self::AdapterRejected(code) => formatter
                .debug_struct("GatewayError")
                .field("code", &"adapter_rejected")
                .field("reason", code)
                .finish(),
            Self::Ledger(error) => formatter
                .debug_struct("GatewayError")
                .field("code", &"ledger")
                .field("reason", error)
                .finish(),
            Self::LedgerCommitGap {
                request_digest,
                external_effect,
                ledger_error,
            } => formatter
                .debug_struct("GatewayError")
                .field("code", &"ledger_commit_gap")
                .field("request_digest", request_digest)
                .field("external_effect", external_effect)
                .field("reason", ledger_error)
                .finish(),
            other => formatter
                .debug_struct("GatewayError")
                .field("code", &other.code())
                .finish(),
        }
    }
}

impl GatewayError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidDigest => "invalid_digest",
            Self::InvalidIdentifier => "invalid_identifier",
            Self::InvalidIdempotencyKey => "invalid_idempotency_key",
            Self::InvalidBudget => "invalid_budget",
            Self::PayloadLimitExceeded => "payload_limit_exceeded",
            Self::InvalidSecretReference => "invalid_secret_reference",
            Self::InvalidDataAuthority => "invalid_data_authority",
            Self::InvalidNetworkAuthority => "invalid_network_authority",
            Self::InvalidEffectAuthority => "invalid_effect_authority",
            Self::InvalidOrigin => "invalid_origin",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidAdapterBinding => "invalid_adapter_binding",
            Self::InvalidManifest => "invalid_manifest",
            Self::ManifestBindingMismatch => "manifest_binding_mismatch",
            Self::ManifestRevoked => "manifest_revoked",
            Self::InvalidSignature => "invalid_signature",
            Self::InvalidSigningKey => "invalid_signing_key",
            Self::SignatureVerificationFailed => "signature_verification_failed",
            Self::CanonicalizationFailed => "canonicalization_failed",
            Self::InvalidAdapterRegistry => "invalid_adapter_registry",
            Self::AdapterNotRegistered => "adapter_not_registered",
            Self::AdapterRevoked => "adapter_revoked",
            Self::AdapterBindingMismatch => "adapter_binding_mismatch",
            Self::InvalidRequest => "invalid_request",
            Self::ScopeMismatch => "scope_mismatch",
            Self::DataAuthorityViolation => "data_authority_violation",
            Self::SecretAuthorityViolation => "secret_authority_violation",
            Self::EffectAuthorityViolation => "effect_authority_violation",
            Self::BudgetExceeded => "budget_exceeded",
            Self::ProvenanceMismatch => "provenance_mismatch",
            Self::PayloadTampered => "payload_tampered",
            Self::InvalidProvenance => "invalid_provenance",
            Self::RecoveryScopeViolation => "recovery_scope_violation",
            Self::ResultScopeMismatch => "result_scope_mismatch",
            Self::InvalidResult => "invalid_result",
            Self::InvalidInvocationPermit => "invalid_invocation_permit",
            Self::InvalidResourceReference => "invalid_resource_reference",
            Self::AdapterRejected(_) => "adapter_rejected",
            Self::Recovery(_) => "recovery",
            Self::Ledger(_) => "ledger",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::RevisionOverflow => "revision_overflow",
            Self::LedgerCommitGap { .. } => "ledger_commit_gap",
        }
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_capability_id(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    value.split('.').all(|segment| {
        let mut bytes = segment.bytes();
        matches!(bytes.next(), Some(b'a'..=b'z'))
            && bytes.all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
            })
    })
}

/// Computes the canonical SHA-256 digest used by cross-crate receipts.
pub fn digest_serialized<T: Serialize>(value: &T) -> Digest {
    match serde_json::to_vec(value) {
        Ok(bytes) => Digest::from_bytes(&bytes),
        Err(_) => Digest::from_text("canonicalization-error"),
    }
}
