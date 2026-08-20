//! Bounded Azure Container Apps revision metadata.
//!
//! Provider identifiers and opaque handles are accepted only at the boundary.
//! Evidence projections retain digests and bounded readiness metadata; they do
//! not retain ARM paths, templates, environment variables, secrets, identity
//! material, endpoints, probes, scale rules, logs, or raw provider errors.

use std::{collections::BTreeSet, fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AzureContainerAppsRevisionResultError, Result};
use crate::{
    EVIDENCE_SCHEMA, LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, MAX_REPLICAS, MAX_RESPONSE_BYTES,
    MAX_TRAFFIC_WEIGHT,
};

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for (name, value) in fields {
            append_field(&mut bytes, name);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AzureContainerAppsRevisionResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AzureContainerAppsRevisionResultError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_text(value: &str, max_bytes: usize, allow_internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_azure_name(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'(' | b')')
        })
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.as_bytes().iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn valid_resource_id(value: &str) -> bool {
    valid_text(value, 4_096, false)
        && value.starts_with('/')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b'(' | b')')
        })
}

macro_rules! bounded_text {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AzureContainerAppsRevisionResultError::InvalidIdentifier { field: $field })
                }
            }

            pub fn parse(value: impl Into<String>) -> Result<Self> {
                Self::new(value)
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("azure-container-apps-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            #[allow(dead_code)]
            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AzureContainerAppsRevisionResultError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&format!("{}:{}", $field, &self.digest().as_str()[..16]))
                    .finish()
            }
        }

        impl FromStr for $name {
            type Err = AzureContainerAppsRevisionResultError;
            fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

bounded_text!(TenantId, "tenant-id", valid_uuid);
bounded_text!(SubscriptionId, "subscription-id", valid_uuid);
bounded_text!(ResourceGroupName, "resource-group", valid_azure_name);
bounded_text!(ContainerAppName, "container-app", valid_azure_name);
bounded_text!(RevisionName, "revision", valid_azure_name);
bounded_text!(ComponentId, "component", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES
));
bounded_text!(ProjectId, "project", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES
));
bounded_text!(MissionId, "mission", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES
));
bounded_text!(WorkProductId, "work-product", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});

#[derive(Clone, Eq, PartialEq)]
pub struct EnvironmentResourceId(String);

impl EnvironmentResourceId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_resource_id(&value) {
            Ok(Self(value))
        } else {
            Err(AzureContainerAppsRevisionResultError::InvalidIdentifier {
                field: "environment-id",
            })
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "azure-container-apps-environment-resource-id/v1",
            &[("value", self.0.clone())],
        )
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if valid_resource_id(&self.0) {
            Ok(())
        } else {
            Err(AzureContainerAppsRevisionResultError::InvalidIdentifier {
                field: "environment-id",
            })
        }
    }
}

impl fmt::Debug for EnvironmentResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("EnvironmentResourceId")
            .field(&format!("environment:{}", &self.digest().as_str()[..16]))
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GenerationIdentity {
    id: String,
    revision: u64,
    kind: &'static str,
}

impl GenerationIdentity {
    pub fn new(id: impl Into<String>, revision: u64, kind: &'static str) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 || kind.is_empty() {
            return Err(AzureContainerAppsRevisionResultError::InvalidScope);
        }
        Ok(Self { id, revision, kind })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub fn id_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-container-apps-generation-id/v1",
            &[("kind", self.kind.to_owned()), ("id", self.id.clone())],
        )
    }
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "azure-container-apps-generation/v1",
            &[
                ("kind", self.kind.to_owned()),
                ("id", self.id_digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
            Ok(())
        } else {
            Err(AzureContainerAppsRevisionResultError::InvalidScope)
        }
    }
}

impl fmt::Debug for GenerationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationIdentity")
            .field("kind", &self.kind)
            .field("id_digest", &self.id_digest())
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AzureContainerAppsRevisionScope {
    tenant_id: TenantId,
    subscription_id: SubscriptionId,
    resource_group: ResourceGroupName,
    environment_id: EnvironmentResourceId,
    container_app: ContainerAppName,
    revision: RevisionName,
    image_digest: Digest,
    component_id: ComponentId,
    project: GenerationIdentity,
    mission: GenerationIdentity,
    work_product: GenerationIdentity,
}

impl AzureContainerAppsRevisionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        subscription_id: SubscriptionId,
        resource_group: ResourceGroupName,
        environment_id: EnvironmentResourceId,
        container_app: ContainerAppName,
        revision: RevisionName,
        image_reference: impl Into<String>,
        component_id: ComponentId,
        project: GenerationIdentity,
        mission: GenerationIdentity,
        work_product: GenerationIdentity,
    ) -> Result<Self> {
        let image_reference = image_reference.into();
        if !valid_text(&image_reference, 4_096, false) {
            return Err(AzureContainerAppsRevisionResultError::InvalidText {
                field: "image-reference",
            });
        }
        let scope = Self {
            tenant_id,
            subscription_id,
            resource_group,
            environment_id,
            container_app,
            revision,
            image_digest: Digest::from_parts(
                "azure-container-apps-image-reference/v1",
                &[("value", image_reference)],
            ),
            component_id,
            project,
            mission,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_revision(
        tenant_id: TenantId,
        subscription_id: SubscriptionId,
        resource_group: ResourceGroupName,
        environment_id: EnvironmentResourceId,
        container_app: ContainerAppName,
        revision: RevisionName,
        image_reference: impl Into<String>,
        component_id: ComponentId,
        project: GenerationIdentity,
        mission: GenerationIdentity,
        work_product: GenerationIdentity,
    ) -> Result<Self> {
        Self::new(
            tenant_id,
            subscription_id,
            resource_group,
            environment_id,
            container_app,
            revision,
            image_reference,
            component_id,
            project,
            mission,
            work_product,
        )
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    pub fn subscription_id(&self) -> &SubscriptionId {
        &self.subscription_id
    }
    pub fn resource_group(&self) -> &ResourceGroupName {
        &self.resource_group
    }
    pub fn environment_id(&self) -> &EnvironmentResourceId {
        &self.environment_id
    }
    pub fn container_app(&self) -> &ContainerAppName {
        &self.container_app
    }
    pub fn revision(&self) -> &RevisionName {
        &self.revision
    }
    pub fn image_digest(&self) -> &Digest {
        &self.image_digest
    }
    pub fn component_id(&self) -> &ComponentId {
        &self.component_id
    }
    pub fn project(&self) -> &GenerationIdentity {
        &self.project
    }
    pub fn mission(&self) -> &GenerationIdentity {
        &self.mission
    }
    pub fn work_product(&self) -> &GenerationIdentity {
        &self.work_product
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "azure-container-apps-revision-scope/v1",
            &[
                ("tenant", self.tenant_id.digest().as_str().to_owned()),
                (
                    "subscription",
                    self.subscription_id.digest().as_str().to_owned(),
                ),
                (
                    "resource_group",
                    self.resource_group.digest().as_str().to_owned(),
                ),
                (
                    "environment",
                    self.environment_id.digest().as_str().to_owned(),
                ),
                (
                    "container_app",
                    self.container_app.digest().as_str().to_owned(),
                ),
                ("revision", self.revision.digest().as_str().to_owned()),
                ("image", self.image_digest.as_str().to_owned()),
                ("component", self.component_id.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.tenant_id.validate()?;
        self.subscription_id.validate()?;
        self.resource_group.validate()?;
        self.environment_id.validate()?;
        self.container_app.validate()?;
        self.revision.validate()?;
        self.image_digest.validate()?;
        self.component_id.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()
    }
}

impl fmt::Debug for AzureContainerAppsRevisionScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureContainerAppsRevisionScope")
            .field("digest", &self.digest())
            .field("tenant", &self.tenant_id)
            .field("subscription", &self.subscription_id)
            .field("resource_group", &self.resource_group)
            .field("environment", &self.environment_id)
            .field("container_app", &self.container_app)
            .field("revision", &self.revision)
            .field("component", &self.component_id)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .finish_non_exhaustive()
    }
}

impl Serialize for AzureContainerAppsRevisionScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AzureContainerAppsRevisionScope", 11)?;
        state.serialize_field("tenantDigest", &self.tenant_id.digest())?;
        state.serialize_field("subscriptionDigest", &self.subscription_id.digest())?;
        state.serialize_field("resourceGroupDigest", &self.resource_group.digest())?;
        state.serialize_field("environmentDigest", &self.environment_id.digest())?;
        state.serialize_field("containerAppDigest", &self.container_app.digest())?;
        state.serialize_field("revisionDigest", &self.revision.digest())?;
        state.serialize_field("imageDigest", &self.image_digest)?;
        state.serialize_field("componentDigest", &self.component_id.digest())?;
        state.serialize_field("projectDigest", &self.project.digest())?;
        state.serialize_field("missionDigest", &self.mission.digest())?;
        state.serialize_field("workProductDigest", &self.work_product.digest())?;
        state.end()
    }
}

pub type AzureContainerAppsScope = AzureContainerAppsRevisionScope;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    EntraBearer,
}

/// Opaque Entra reference. The input handle is hashed and zeroized; the type
/// deliberately has no Serialize, Deserialize, Display, or raw getter.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl Into<String>,
        scope: &AzureContainerAppsRevisionScope,
        revision: u64,
    ) -> Result<Self> {
        let mut handle = opaque_handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            handle.zeroize();
            return Err(AzureContainerAppsRevisionResultError::InvalidSecretReference);
        }
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "azure-container-apps-opaque-entra-reference/v1",
            &[
                ("kind", "entra_bearer".to_owned()),
                ("handle", handle.clone()),
                ("scope", scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            kind: SecretKind::EntraBearer,
            reference_digest,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub fn entra(
        opaque_handle: impl Into<String>,
        scope: &AzureContainerAppsRevisionScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new(opaque_handle, scope, revision)
    }
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self, scope: &AzureContainerAppsRevisionScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::EntraBearer)
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AzureContainerAppsRevisionResultError::InvalidSecretReference);
        }
        self.reference_digest.validate()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
    pub const fn is_connected(self) -> bool {
        false
    }
    pub const fn is_native(self) -> bool {
        false
    }
    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let snapshot = Self {
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn for_layer_one(revision: u64) -> Self {
        Self {
            revision,
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "azure-container-apps-permissions/v1",
            &[
                ("revision", self.revision.to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let expected: BTreeSet<String> = LAYER1_PERMISSIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect();
        if self.revision == 0 || self.permissions != expected {
            Err(AzureContainerAppsRevisionResultError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppProvisioningState {
    Provisioning,
    Succeeded,
    Failed,
    Deprovisioning,
    Deprovisioned,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionProvisioningState {
    Provisioning,
    Provisioned,
    Failed,
    Deprovisioning,
    Deprovisioned,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionHealthState {
    Healthy,
    Unhealthy,
    None,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionRunningState {
    Running,
    Stopped,
    Activating,
    Deactivating,
    Processing,
    Transitioning,
    Degraded,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppMetadata {
    pub app_digest: Digest,
    pub provisioning_state: AppProvisioningState,
    pub latest_revision_digest: Option<Digest>,
}

impl AppMetadata {
    pub fn from_provider(
        scope: &AzureContainerAppsRevisionScope,
        provisioning_state: AppProvisioningState,
        latest_revision_name: Option<String>,
    ) -> Result<Self> {
        let latest_revision_digest = latest_revision_name
            .map(RevisionName::new)
            .transpose()?
            .map(|value| value.digest());
        let metadata = Self {
            app_digest: scope.container_app().digest(),
            provisioning_state,
            latest_revision_digest,
        };
        metadata.validate_against(scope)?;
        Ok(metadata)
    }

    pub fn new(
        scope: &AzureContainerAppsRevisionScope,
        provisioning_state: AppProvisioningState,
        latest_revision_digest: Option<Digest>,
    ) -> Result<Self> {
        let metadata = Self {
            app_digest: scope.container_app().digest(),
            provisioning_state,
            latest_revision_digest,
        };
        metadata.validate_against(scope)?;
        Ok(metadata)
    }

    pub(crate) fn validate_against(&self, scope: &AzureContainerAppsRevisionScope) -> Result<()> {
        if self.app_digest != scope.container_app().digest() {
            return Err(AzureContainerAppsRevisionResultError::ScopeMismatch);
        }
        if let Some(digest) = &self.latest_revision_digest {
            digest.validate()?;
        }
        Ok(())
    }
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("AppMetadata is serializable")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevisionMetadata {
    pub revision_digest: Digest,
    pub active: bool,
    pub health_state: RevisionHealthState,
    pub provisioning_state: RevisionProvisioningState,
    pub running_state: RevisionRunningState,
    pub created_time: Option<DateTime<Utc>>,
    pub last_active_time: Option<DateTime<Utc>>,
    pub replicas: u32,
    pub traffic_weight: u16,
    pub redacted_image_digest: Option<Digest>,
}

impl RevisionMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn from_provider(
        scope: &AzureContainerAppsRevisionScope,
        revision_name: impl Into<String>,
        active: bool,
        health_state: RevisionHealthState,
        provisioning_state: RevisionProvisioningState,
        running_state: RevisionRunningState,
        created_time: Option<DateTime<Utc>>,
        last_active_time: Option<DateTime<Utc>>,
        replicas: u32,
        traffic_weight: u16,
        image_reference: Option<String>,
    ) -> Result<Self> {
        let revision_name = revision_name.into();
        if !valid_azure_name(&revision_name) {
            return Err(AzureContainerAppsRevisionResultError::InvalidIdentifier {
                field: "revision",
            });
        }
        let redacted_image_digest = image_reference.map(|value| {
            Digest::from_parts(
                "azure-container-apps-image-reference/v1",
                &[("value", value)],
            )
        });
        let metadata = Self {
            revision_digest: Digest::from_parts(
                "azure-container-apps-revision/v1",
                &[("value", revision_name)],
            ),
            active,
            health_state,
            provisioning_state,
            running_state,
            created_time,
            last_active_time,
            replicas,
            traffic_weight,
            redacted_image_digest,
        };
        metadata.validate_list_item_against(scope)?;
        Ok(metadata)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_redacted(
        scope: &AzureContainerAppsRevisionScope,
        revision_digest: Digest,
        active: bool,
        health_state: RevisionHealthState,
        provisioning_state: RevisionProvisioningState,
        running_state: RevisionRunningState,
        created_time: Option<DateTime<Utc>>,
        last_active_time: Option<DateTime<Utc>>,
        replicas: u32,
        traffic_weight: u16,
        redacted_image_digest: Option<Digest>,
    ) -> Result<Self> {
        let metadata = Self {
            revision_digest,
            active,
            health_state,
            provisioning_state,
            running_state,
            created_time,
            last_active_time,
            replicas,
            traffic_weight,
            redacted_image_digest,
        };
        metadata.validate_against(scope)?;
        Ok(metadata)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_scope(
        scope: &AzureContainerAppsRevisionScope,
        active: bool,
        health_state: RevisionHealthState,
        provisioning_state: RevisionProvisioningState,
        running_state: RevisionRunningState,
        created_time: Option<DateTime<Utc>>,
        last_active_time: Option<DateTime<Utc>>,
        replicas: u32,
        traffic_weight: u16,
    ) -> Result<Self> {
        Self::from_redacted(
            scope,
            scope.revision().digest(),
            active,
            health_state,
            provisioning_state,
            running_state,
            created_time,
            last_active_time,
            replicas,
            traffic_weight,
            Some(scope.image_digest().clone()),
        )
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("RevisionMetadata is serializable")
    }

    pub(crate) fn validate_against(&self, scope: &AzureContainerAppsRevisionScope) -> Result<()> {
        if self.revision_digest != scope.revision().digest()
            || self.replicas > MAX_REPLICAS
            || self.traffic_weight > MAX_TRAFFIC_WEIGHT
            || self
                .created_time
                .zip(self.last_active_time)
                .is_some_and(|(created, last)| last < created)
        {
            return Err(AzureContainerAppsRevisionResultError::ScopeMismatch);
        }
        self.revision_digest.validate()?;
        if self.redacted_image_digest.as_ref() != Some(scope.image_digest()) {
            return Err(AzureContainerAppsRevisionResultError::ScopeMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_list_item_against(
        &self,
        _scope: &AzureContainerAppsRevisionScope,
    ) -> Result<()> {
        if self.replicas > MAX_REPLICAS
            || self.traffic_weight > MAX_TRAFFIC_WEIGHT
            || self
                .created_time
                .zip(self.last_active_time)
                .is_some_and(|(created, last)| last < created)
        {
            return Err(AzureContainerAppsRevisionResultError::InvalidResponse);
        }
        self.revision_digest.validate()?;
        self.redacted_image_digest
            .as_ref()
            .ok_or(AzureContainerAppsRevisionResultError::InvalidResponse)?
            .validate()
    }
}

pub type AppProjection = AppMetadata;
pub type RevisionProjection = RevisionMetadata;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadinessProjection {
    pub app_provisioning_state: AppProvisioningState,
    pub revision_provisioning_state: RevisionProvisioningState,
    pub health_state: RevisionHealthState,
    pub running_state: RevisionRunningState,
    pub active: bool,
    pub replicas: u32,
    pub traffic_weight: u16,
}

impl ReadinessProjection {
    pub fn from_metadata(app: &AppMetadata, revision: &RevisionMetadata) -> Self {
        Self {
            app_provisioning_state: app.provisioning_state,
            revision_provisioning_state: revision.provisioning_state,
            health_state: revision.health_state,
            running_state: revision.running_state,
            active: revision.active,
            replicas: revision.replicas,
            traffic_weight: revision.traffic_weight,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureContainerAppsRevisionProjection {
    pub app: AppProjection,
    pub revision: RevisionProjection,
    pub readiness: ReadinessProjection,
}

impl AzureContainerAppsRevisionProjection {
    pub fn new(app: AppProjection, revision: RevisionProjection) -> Self {
        let readiness = ReadinessProjection::from_metadata(&app, &revision);
        Self {
            app,
            revision,
            readiness,
        }
    }
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("revision projection is serializable")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureContainerAppsEvidenceState {
    Provisioning,
    Running,
    Healthy,
    Unhealthy,
    Inactive,
    Failed,
    Deprovisioned,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
    NotFound,
    TimedOut,
    Throttled,
    PaginationLoop,
    Truncated,
    Conflict,
}

impl AzureContainerAppsEvidenceState {
    pub const fn is_non_adoptable(self) -> bool {
        true
    }
    pub const fn is_review_complete(self) -> bool {
        matches!(
            self,
            Self::Healthy | Self::Running | Self::Unhealthy | Self::Inactive
        )
    }
}

pub type EvidenceState = AzureContainerAppsEvidenceState;
pub type ResultState = AzureContainerAppsEvidenceState;
pub type AzureContainerAppsRevisionResultState = AzureContainerAppsEvidenceState;
pub type AzureContainerAppsRevisionResult = AzureContainerAppsRevisionProjection;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCategory {
    Unauthorized,
    Forbidden,
    AccessLost,
    NotFound,
    RateLimited,
    TimedOut,
    BadRequest,
    Conflict,
    ServerFailure,
    InvalidResponse,
    Truncated,
    BlockedEnv,
    ProviderUnknown,
    PaginationLoop,
    RevisionReplaced,
    ReadinessConflict,
    RegistrationRevoked,
    Stale,
    Tampered,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: String,
    pub category: FailureCategory,
    pub status_code: Option<u16>,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    pub fn new(
        operation: impl Into<String>,
        category: FailureCategory,
        status_code: Option<u16>,
    ) -> Self {
        let operation = operation.into();
        let failure_digest = Digest::from_parts(
            "azure-container-apps-failure/v1",
            &[
                ("operation", operation.clone()),
                ("category", format!("{category:?}")),
                (
                    "status",
                    status_code.map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        Self {
            operation,
            category,
            status_code,
            failure_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReceipt {
    pub operation: String,
    pub scope_digest: Digest,
    pub page_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub response_bytes: Option<u64>,
    pub response_digest: Option<Digest>,
    pub redacted: bool,
}

impl RequestReceipt {
    pub fn validate(&self) -> Result<()> {
        if !self.redacted
            || self.operation.is_empty()
            || self.scope_digest.validate().is_err()
            || self.request_digest.validate().is_err()
            || self.path_digest.validate().is_err()
            || self
                .page_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
            || self
                .response_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
            || self
                .response_bytes
                .is_some_and(|bytes| bytes > MAX_RESPONSE_BYTES)
        {
            Err(AzureContainerAppsRevisionResultError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_schema_digest: Digest,
    pub app_digest: Option<Digest>,
    pub revision_digest: Option<Digest>,
    pub list_digest: Option<Digest>,
    pub get_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub fn validate(&self) -> Result<()> {
        for digest in [
            &self.plugin_version_digest,
            &self.contract_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.evidence_schema_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        for digest in [
            &self.app_digest,
            &self.revision_digest,
            &self.list_digest,
            &self.get_digest,
            &self.cursor_digest,
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        Ok(())
    }
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| AzureContainerAppsRevisionResultError::InvalidResponse)?;
    Ok(Digest::from_bytes(&bytes))
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn compute_evidence_digest(
    evidence: &EvidenceDigests,
    state: AzureContainerAppsEvidenceState,
    projection: Option<&AzureContainerAppsRevisionProjection>,
    failure: Option<&FailureEvidence>,
    list_complete: bool,
    list_pages: u16,
) -> Digest {
    let projection_digest =
        projection.map_or_else(String::new, |value| value.digest().as_str().to_owned());
    let failure_digest = failure.map_or_else(String::new, |value| {
        value.failure_digest.as_str().to_owned()
    });
    Digest::from_parts(
        EVIDENCE_SCHEMA,
        &[
            (
                "plugin_version",
                evidence.plugin_version_digest.as_str().to_owned(),
            ),
            (
                "contract_version",
                evidence.contract_version_digest.as_str().to_owned(),
            ),
            ("contract", evidence.contract_digest.as_str().to_owned()),
            ("provider", evidence.provider_digest.as_str().to_owned()),
            ("api", evidence.api_digest.as_str().to_owned()),
            ("permission", evidence.permission_digest.as_str().to_owned()),
            ("scope", evidence.scope_digest.as_str().to_owned()),
            (
                "evidence_schema",
                evidence.evidence_schema_digest.as_str().to_owned(),
            ),
            (
                "app",
                evidence
                    .app_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "revision",
                evidence
                    .revision_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "list",
                evidence
                    .list_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "get",
                evidence
                    .get_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "cursor",
                evidence
                    .cursor_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            ("state", format!("{state:?}")),
            ("projection", projection_digest),
            ("failure", failure_digest),
            ("list_complete", list_complete.to_string()),
            ("list_pages", list_pages.to_string()),
        ],
    )
}

pub fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes > MAX_RESPONSE_BYTES {
        Err(AzureContainerAppsRevisionResultError::ResponseTooLarge)
    } else {
        Ok(())
    }
}
