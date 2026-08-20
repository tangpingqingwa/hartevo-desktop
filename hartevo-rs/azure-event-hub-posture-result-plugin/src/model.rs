use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AzureEventHubPostureResultError, Result};
use crate::{
    API_REVISION, LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_PARTITION_COUNT, MAX_RESPONSE_BYTES, MAX_RETENTION_DAYS,
};

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
            Err(AzureEventHubPostureResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AzureEventHubPostureResultError::InvalidDigest)
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
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'$' | b'~')
        })
}

fn classify_status(value: &str) -> PostureStatus {
    match value.to_ascii_lowercase().as_str() {
        "active" | "available" | "succeeded" | "running" | "enabled" => PostureStatus::Active,
        "creating" | "updating" | "deleting" | "inprogress" | "in_progress" | "provisioning" => {
            PostureStatus::InProgress
        }
        "disabled" | "inactive" | "stopped" => PostureStatus::Disabled,
        _ => PostureStatus::Unknown,
    }
}

fn digest_sensitive(domain: &str, value: Option<&str>) -> Option<Digest> {
    value.map(|value| Digest::from_parts(domain, &[("value", value.to_owned())]))
}

macro_rules! redacted_identifier {
    ($name:ident, $alias:ident, $field:literal, $domain:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AzureEventHubPostureResultError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, &[("value", self.0.clone())])
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AzureEventHubPostureResultError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.redacted())
                    .finish()
            }
        }

        pub type $alias = $name;
    };
}

redacted_identifier!(
    AzureTenantId,
    TenantId,
    "tenant-id",
    "azure-event-hub-tenant/v1",
    |value: &str| valid_identifier(value, 128)
);
redacted_identifier!(
    AzureSubscriptionId,
    SubscriptionId,
    "subscription-id",
    "azure-event-hub-subscription/v1",
    |value: &str| valid_identifier(value, 128)
);
redacted_identifier!(
    AzureResourceGroupName,
    ResourceGroupName,
    "resource-group",
    "azure-event-hub-resource-group/v1",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);
redacted_identifier!(
    AzureEventHubNamespaceName,
    NamespaceName,
    "namespace",
    "azure-event-hub-namespace/v1",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);
redacted_identifier!(
    AzureEventHubName,
    EventHubName,
    "event-hub",
    "azure-event-hub-name/v1",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);
redacted_identifier!(
    AzureConsumerGroupName,
    ConsumerGroupName,
    "consumer-group",
    "azure-event-hub-consumer-group/v1",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);

macro_rules! generation_identity {
    ($name:ident, $domain:literal, $field:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            id: String,
            revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                let id = id.into();
                if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
                    return Err(AzureEventHubPostureResultError::InvalidScope);
                }
                Ok(Self { id, revision })
            }

            pub fn id(&self) -> &str {
                &self.id
            }

            pub const fn revision(&self) -> u64 {
                self.revision
            }

            pub fn id_digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("azure-event-hub-", $field, "-id/v1"),
                    &[("id", self.id.clone())],
                )
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        ("id", self.id_digest().as_str().to_owned()),
                        ("revision", self.revision.to_string()),
                    ],
                )
            }

            fn validate(&self) -> Result<()> {
                if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
                    Ok(())
                } else {
                    Err(AzureEventHubPostureResultError::InvalidScope)
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("id_digest", &self.id_digest())
                    .field("revision", &self.revision)
                    .finish()
            }
        }
    };
}

generation_identity!(MissionIdentity, "azure-event-hub-mission/v1", "mission");
generation_identity!(ProjectIdentity, "azure-event-hub-project/v1", "project");
generation_identity!(
    WorkProductIdentity,
    "azure-event-hub-work-product/v1",
    "work-product"
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionFences {
    pub namespace_revision_digest: Option<Digest>,
    pub event_hub_revision_digest: Option<Digest>,
    pub consumer_group_revision_digest: Option<Digest>,
}

impl RevisionFences {
    pub fn none() -> Self {
        Self {
            namespace_revision_digest: None,
            event_hub_revision_digest: None,
            consumer_group_revision_digest: None,
        }
    }

    pub fn new(
        namespace_revision: Option<String>,
        event_hub_revision: Option<String>,
        consumer_group_revision: Option<String>,
    ) -> Result<Self> {
        let fences = Self {
            namespace_revision_digest: namespace_revision.as_deref().map(|value| {
                Digest::from_parts(
                    "azure-event-hub-namespace-revision/v1",
                    &[("value", value.to_owned())],
                )
            }),
            event_hub_revision_digest: event_hub_revision.as_deref().map(|value| {
                Digest::from_parts(
                    "azure-event-hub-event-hub-revision/v1",
                    &[("value", value.to_owned())],
                )
            }),
            consumer_group_revision_digest: consumer_group_revision.as_deref().map(|value| {
                Digest::from_parts(
                    "azure-event-hub-consumer-group-revision/v1",
                    &[("value", value.to_owned())],
                )
            }),
        };
        for value in [
            &fences.namespace_revision_digest,
            &fences.event_hub_revision_digest,
            &fences.consumer_group_revision_digest,
        ]
        .into_iter()
        .flatten()
        {
            value.validate()?;
        }
        Ok(fences)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-revision-fences/v1",
            &[
                (
                    "namespace",
                    self.namespace_revision_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "event_hub",
                    self.event_hub_revision_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "consumer_group",
                    self.consumer_group_revision_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        for value in [
            &self.namespace_revision_digest,
            &self.event_hub_revision_digest,
            &self.consumer_group_revision_digest,
        ]
        .into_iter()
        .flatten()
        {
            value.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AzureEventHubPostureScope {
    tenant: AzureTenantId,
    subscription: AzureSubscriptionId,
    resource_group: AzureResourceGroupName,
    namespace: AzureEventHubNamespaceName,
    event_hub: AzureEventHubName,
    consumer_group: AzureConsumerGroupName,
    api_revision: String,
    revision_fences: RevisionFences,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AzureEventHubPostureScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: AzureTenantId,
        subscription: AzureSubscriptionId,
        resource_group: AzureResourceGroupName,
        namespace: AzureEventHubNamespaceName,
        event_hub: AzureEventHubName,
        consumer_group: AzureConsumerGroupName,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        Self::new_with_api_revision(
            tenant,
            subscription,
            resource_group,
            namespace,
            event_hub,
            consumer_group,
            API_REVISION,
            mission,
            project,
            work_product,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_api_revision(
        tenant: AzureTenantId,
        subscription: AzureSubscriptionId,
        resource_group: AzureResourceGroupName,
        namespace: AzureEventHubNamespaceName,
        event_hub: AzureEventHubName,
        consumer_group: AzureConsumerGroupName,
        api_revision: impl Into<String>,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            tenant,
            subscription,
            resource_group,
            namespace,
            event_hub,
            consumer_group,
            api_revision: api_revision.into(),
            revision_fences: RevisionFences::none(),
            mission,
            project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn with_revision_fences<N, E, C>(
        mut self,
        namespace_revision: Option<N>,
        event_hub_revision: Option<E>,
        consumer_group_revision: Option<C>,
    ) -> Result<Self>
    where
        N: Into<String>,
        E: Into<String>,
        C: Into<String>,
    {
        self.revision_fences = RevisionFences::new(
            namespace_revision.map(Into::into),
            event_hub_revision.map(Into::into),
            consumer_group_revision.map(Into::into),
        )?;
        self.validate()?;
        Ok(self)
    }

    pub fn tenant(&self) -> &AzureTenantId {
        &self.tenant
    }

    pub fn subscription(&self) -> &AzureSubscriptionId {
        &self.subscription
    }

    pub fn resource_group(&self) -> &AzureResourceGroupName {
        &self.resource_group
    }

    pub fn namespace(&self) -> &AzureEventHubNamespaceName {
        &self.namespace
    }

    pub fn event_hub(&self) -> &AzureEventHubName {
        &self.event_hub
    }

    pub fn consumer_group(&self) -> &AzureConsumerGroupName {
        &self.consumer_group
    }

    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    pub fn revision_fences(&self) -> &RevisionFences {
        &self.revision_fences
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    pub fn tenant_digest(&self) -> Digest {
        self.tenant.digest()
    }

    pub fn subscription_digest(&self) -> Digest {
        self.subscription.digest()
    }

    pub fn resource_group_digest(&self) -> Digest {
        self.resource_group.digest()
    }

    pub fn namespace_digest(&self) -> Digest {
        self.namespace.digest()
    }

    pub fn event_hub_digest(&self) -> Digest {
        self.event_hub.digest()
    }

    pub fn consumer_group_digest(&self) -> Digest {
        self.consumer_group.digest()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-posture-scope/v1",
            &[
                ("tenant", self.tenant.digest().as_str().to_owned()),
                (
                    "subscription",
                    self.subscription.digest().as_str().to_owned(),
                ),
                (
                    "resource_group",
                    self.resource_group.digest().as_str().to_owned(),
                ),
                ("namespace", self.namespace.digest().as_str().to_owned()),
                ("event_hub", self.event_hub.digest().as_str().to_owned()),
                (
                    "consumer_group",
                    self.consumer_group.digest().as_str().to_owned(),
                ),
                ("api_revision", self.api_revision.clone()),
                (
                    "revision_fences",
                    self.revision_fences.digest().as_str().to_owned(),
                ),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.tenant.validate()?;
        self.subscription.validate()?;
        self.resource_group.validate()?;
        self.namespace.validate()?;
        self.event_hub.validate()?;
        self.consumer_group.validate()?;
        if self.api_revision != API_REVISION {
            return Err(AzureEventHubPostureResultError::ApiDrift);
        }
        self.revision_fences.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }
}

impl fmt::Debug for AzureEventHubPostureScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureEventHubPostureScope")
            .field("digest", &self.digest())
            .field("tenant", &self.tenant)
            .field("subscription", &self.subscription)
            .field("resource_group", &self.resource_group)
            .field("namespace", &self.namespace)
            .field("event_hub", &self.event_hub)
            .field("consumer_group", &self.consumer_group)
            .field("api_revision", &self.api_revision)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish_non_exhaustive()
    }
}

pub type AzureEventHubScope = AzureEventHubPostureScope;
pub type EventHubPostureScope = AzureEventHubPostureScope;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    EntraAccessToken,
}

/// Opaque Entra reference. The caller-supplied handle is hashed and zeroized;
/// this type deliberately does not implement `Serialize`, `Display`, or
/// `AsRef<str>`.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        let mut handle = opaque_handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            handle.zeroize();
            return Err(AzureEventHubPostureResultError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "azure-event-hub-opaque-entra-reference/v1",
            &[
                ("kind", "entra_access_token".to_owned()),
                ("handle", handle.clone()),
                ("revision", revision.to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            kind: SecretKind::EntraAccessToken,
            reference_digest,
            scope_digest: Digest::from_text("unbound-azure-event-hub-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn entra(
        opaque_handle: impl Into<String>,
        scope: &AzureEventHubPostureScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "azure-event-hub-opaque-entra-reference/v1",
            &[
                ("kind", "entra_access_token".to_owned()),
                ("reference", reference.reference_digest.as_str().to_owned()),
                ("scope", reference.scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(reference)
    }

    pub fn kind(&self) -> SecretKind {
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

    pub(crate) fn validate_binding(&self, scope: &AzureEventHubPostureScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::EntraAccessToken)
            || self.revision == 0
            || self.scope_digest != scope.digest()
        {
            return Err(AzureEventHubPostureResultError::InvalidSecretReference);
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
    Recording,
    Fixture,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
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
            "azure-event-hub-permissions/v1",
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
        if self.revision == 0
            || self.permissions
                != LAYER1_PERMISSIONS
                    .iter()
                    .map(|permission| (*permission).to_owned())
                    .collect::<BTreeSet<_>>()
        {
            Err(AzureEventHubPostureResultError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConsentScope {
    id: String,
    revision: u64,
    permissions: BTreeSet<String>,
    expires_at: DateTime<Utc>,
    revoked: bool,
}

impl ConsentScope {
    pub fn new<I, S>(
        id: impl Into<String>,
        revision: u64,
        permissions: I,
        expires_at: DateTime<Utc>,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let consent = Self {
            id: id.into(),
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
            expires_at,
            revoked: false,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn for_layer_one(
        id: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(id, revision, LAYER1_PERMISSIONS, expires_at)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-consent/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("expires_at", self.expires_at.to_rfc3339()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub fn is_active_at(&self, at: DateTime<Utc>) -> bool {
        !self.revoked && at < self.expires_at
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !valid_identifier(&self.id, MAX_IDENTIFIER_BYTES)
            || self.revision == 0
            || self.permissions
                != LAYER1_PERMISSIONS
                    .iter()
                    .map(|permission| (*permission).to_owned())
                    .collect::<BTreeSet<_>>()
            || self.expires_at <= DateTime::<Utc>::MIN_UTC
        {
            Err(AzureEventHubPostureResultError::InvalidConsent)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for ConsentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsentScope")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureStatus {
    Active,
    InProgress,
    Disabled,
    Unknown,
}

impl PostureStatus {
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NamespacePostureProjection {
    pub namespace_identity_digest: Digest,
    pub status: PostureStatus,
    pub status_digest: Digest,
    pub provisioning_state: PostureStatus,
    pub provisioning_state_digest: Digest,
    pub sku_digest: Digest,
    pub capacity: u32,
    pub service_bus_endpoint_digest: Option<Digest>,
    pub user_metadata_digest: Option<Digest>,
    pub revision_digest: Digest,
    pub projection_digest: Digest,
}

impl NamespacePostureProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        namespace_identity_digest: Digest,
        status: impl Into<String>,
        provisioning_state: impl Into<String>,
        sku: impl Into<String>,
        capacity: u32,
        service_bus_endpoint: Option<String>,
        user_metadata: Option<String>,
        revision: impl Into<String>,
    ) -> Result<Self> {
        namespace_identity_digest.validate()?;
        if capacity == 0 || capacity > 1_000 {
            return Err(AzureEventHubPostureResultError::InvalidResponse);
        }
        let status = status.into();
        let provisioning_state = provisioning_state.into();
        let sku = sku.into();
        let revision = revision.into();
        for (field, value) in [
            ("namespace-status", status.as_str()),
            ("namespace-provisioning-state", provisioning_state.as_str()),
            ("namespace-sku", sku.as_str()),
            ("namespace-revision", revision.as_str()),
        ] {
            if !valid_text(value, MAX_IDENTIFIER_BYTES, true) {
                return Err(AzureEventHubPostureResultError::InvalidText { field });
            }
        }
        let mut projection = Self {
            namespace_identity_digest,
            status_digest: Digest::from_parts(
                "azure-event-hub-namespace-status/v1",
                &[("value", status.clone())],
            ),
            status: classify_status(&status),
            provisioning_state_digest: Digest::from_parts(
                "azure-event-hub-namespace-provisioning-state/v1",
                &[("value", provisioning_state.clone())],
            ),
            provisioning_state: classify_status(&provisioning_state),
            sku_digest: Digest::from_parts("azure-event-hub-namespace-sku/v1", &[("value", sku)]),
            capacity,
            service_bus_endpoint_digest: digest_sensitive(
                "azure-event-hub-service-bus-endpoint/v1",
                service_bus_endpoint.as_deref(),
            ),
            user_metadata_digest: digest_sensitive(
                "azure-event-hub-namespace-user-metadata/v1",
                user_metadata.as_deref(),
            ),
            revision_digest: Digest::from_parts(
                "azure-event-hub-namespace-revision/v1",
                &[("value", revision)],
            ),
            projection_digest: Digest::from_text("unsealed-azure-event-hub-namespace-projection"),
        };
        projection.projection_digest = projection.calculate_digest();
        Ok(projection)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.namespace_identity_digest.validate()?;
        self.status_digest.validate()?;
        self.provisioning_state_digest.validate()?;
        self.sku_digest.validate()?;
        self.service_bus_endpoint_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.user_metadata_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.revision_digest.validate()?;
        if self.capacity == 0
            || self.capacity > 1_000
            || self.projection_digest != self.calculate_digest()
        {
            return Err(AzureEventHubPostureResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-namespace-projection/v1",
            &[
                (
                    "identity",
                    self.namespace_identity_digest.as_str().to_owned(),
                ),
                ("status", format!("{:?}", self.status)),
                ("status_digest", self.status_digest.as_str().to_owned()),
                ("provisioning", format!("{:?}", self.provisioning_state)),
                (
                    "provisioning_digest",
                    self.provisioning_state_digest.as_str().to_owned(),
                ),
                ("sku", self.sku_digest.as_str().to_owned()),
                ("capacity", self.capacity.to_string()),
                (
                    "endpoint",
                    self.service_bus_endpoint_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "metadata",
                    self.user_metadata_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("revision", self.revision_digest.as_str().to_owned()),
            ],
        )
    }
}

pub type NamespaceMetadata = NamespacePostureProjection;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventHubPostureProjection {
    pub event_hub_identity_digest: Digest,
    pub status: PostureStatus,
    pub status_digest: Digest,
    pub partition_count: u32,
    pub partition_ids_digest: Digest,
    pub message_retention_days: u32,
    pub capture_enabled: bool,
    pub capture_configuration_digest: Option<Digest>,
    pub user_metadata_digest: Option<Digest>,
    pub revision_digest: Digest,
    pub projection_digest: Digest,
}

impl EventHubPostureProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_hub_identity_digest: Digest,
        status: impl Into<String>,
        partition_count: u32,
        partition_ids: Vec<String>,
        message_retention_days: u32,
        capture_enabled: bool,
        capture_configuration: Option<String>,
        user_metadata: Option<String>,
        revision: impl Into<String>,
    ) -> Result<Self> {
        event_hub_identity_digest.validate()?;
        if partition_count == 0
            || partition_count > MAX_PARTITION_COUNT
            || message_retention_days == 0
            || message_retention_days > MAX_RETENTION_DAYS
            || partition_ids.len() > MAX_PARTITION_COUNT as usize
        {
            return Err(AzureEventHubPostureResultError::InvalidResponse);
        }
        let status = status.into();
        let revision = revision.into();
        if !valid_text(&status, MAX_IDENTIFIER_BYTES, true)
            || !valid_text(&revision, MAX_IDENTIFIER_BYTES, true)
        {
            return Err(AzureEventHubPostureResultError::InvalidText {
                field: "event-hub-metadata",
            });
        }
        if !partition_ids
            .iter()
            .all(|value| valid_identifier(value, 128))
        {
            return Err(AzureEventHubPostureResultError::InvalidIdentifier {
                field: "partition-id",
            });
        }
        let mut partition_values = partition_ids
            .into_iter()
            .map(|value| Digest::from_text(value).as_str().to_owned())
            .collect::<Vec<_>>();
        partition_values.sort_unstable();
        let mut projection = Self {
            event_hub_identity_digest,
            status: classify_status(&status),
            status_digest: Digest::from_parts(
                "azure-event-hub-event-hub-status/v1",
                &[("value", status)],
            ),
            partition_count,
            partition_ids_digest: Digest::from_parts(
                "azure-event-hub-partition-ids/v1",
                &[("values", partition_values.join("\n"))],
            ),
            message_retention_days,
            capture_enabled,
            capture_configuration_digest: digest_sensitive(
                "azure-event-hub-capture-configuration/v1",
                capture_configuration.as_deref(),
            ),
            user_metadata_digest: digest_sensitive(
                "azure-event-hub-event-hub-user-metadata/v1",
                user_metadata.as_deref(),
            ),
            revision_digest: Digest::from_parts(
                "azure-event-hub-event-hub-revision/v1",
                &[("value", revision)],
            ),
            projection_digest: Digest::from_text("unsealed-azure-event-hub-event-hub-projection"),
        };
        projection.projection_digest = projection.calculate_digest();
        Ok(projection)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.event_hub_identity_digest.validate()?;
        self.status_digest.validate()?;
        self.partition_ids_digest.validate()?;
        self.capture_configuration_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.user_metadata_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.revision_digest.validate()?;
        if self.partition_count == 0
            || self.partition_count > MAX_PARTITION_COUNT
            || self.message_retention_days == 0
            || self.message_retention_days > MAX_RETENTION_DAYS
            || self.projection_digest != self.calculate_digest()
        {
            return Err(AzureEventHubPostureResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-event-hub-projection/v1",
            &[
                (
                    "identity",
                    self.event_hub_identity_digest.as_str().to_owned(),
                ),
                ("status", format!("{:?}", self.status)),
                ("status_digest", self.status_digest.as_str().to_owned()),
                ("partition_count", self.partition_count.to_string()),
                (
                    "partition_ids",
                    self.partition_ids_digest.as_str().to_owned(),
                ),
                ("retention_days", self.message_retention_days.to_string()),
                ("capture_enabled", self.capture_enabled.to_string()),
                (
                    "capture",
                    self.capture_configuration_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "metadata",
                    self.user_metadata_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("revision", self.revision_digest.as_str().to_owned()),
            ],
        )
    }
}

pub type EventHubMetadata = EventHubPostureProjection;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerGroupPostureProjection {
    pub consumer_group_identity_digest: Digest,
    pub status: PostureStatus,
    pub status_digest: Digest,
    pub user_metadata_digest: Option<Digest>,
    pub revision_digest: Digest,
    pub projection_digest: Digest,
}

impl ConsumerGroupPostureProjection {
    pub fn new(
        consumer_group: impl Into<String>,
        status: impl Into<String>,
        user_metadata: Option<String>,
        revision: impl Into<String>,
    ) -> Result<Self> {
        let consumer_group = consumer_group.into();
        if !valid_identifier(&consumer_group, MAX_IDENTIFIER_BYTES) {
            return Err(AzureEventHubPostureResultError::InvalidIdentifier {
                field: "consumer-group",
            });
        }
        let status = status.into();
        let revision = revision.into();
        if !valid_text(&status, MAX_IDENTIFIER_BYTES, true)
            || !valid_text(&revision, MAX_IDENTIFIER_BYTES, true)
        {
            return Err(AzureEventHubPostureResultError::InvalidText {
                field: "consumer-group-metadata",
            });
        }
        let mut projection = Self {
            consumer_group_identity_digest: Digest::from_parts(
                "azure-event-hub-consumer-group-identity/v1",
                &[("name", consumer_group)],
            ),
            status: classify_status(&status),
            status_digest: Digest::from_parts(
                "azure-event-hub-consumer-group-status/v1",
                &[("value", status)],
            ),
            user_metadata_digest: digest_sensitive(
                "azure-event-hub-consumer-group-user-metadata/v1",
                user_metadata.as_deref(),
            ),
            revision_digest: Digest::from_parts(
                "azure-event-hub-consumer-group-revision/v1",
                &[("value", revision)],
            ),
            projection_digest: Digest::from_text(
                "unsealed-azure-event-hub-consumer-group-projection",
            ),
        };
        projection.projection_digest = projection.calculate_digest();
        Ok(projection)
    }

    pub fn for_scope(
        scope: &AzureEventHubPostureScope,
        status: impl Into<String>,
        user_metadata: Option<String>,
        revision: impl Into<String>,
    ) -> Result<Self> {
        let mut projection = Self::new(
            scope.consumer_group.as_str().to_owned(),
            status,
            user_metadata,
            revision,
        )?;
        projection.consumer_group_identity_digest = scope.consumer_group_digest();
        projection.projection_digest = projection.calculate_digest();
        Ok(projection)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.consumer_group_identity_digest.validate()?;
        self.status_digest.validate()?;
        self.user_metadata_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.revision_digest.validate()?;
        if self.projection_digest != self.calculate_digest() {
            return Err(AzureEventHubPostureResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-consumer-group-projection/v1",
            &[
                (
                    "identity",
                    self.consumer_group_identity_digest.as_str().to_owned(),
                ),
                ("status", format!("{:?}", self.status)),
                ("status_digest", self.status_digest.as_str().to_owned()),
                (
                    "metadata",
                    self.user_metadata_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("revision", self.revision_digest.as_str().to_owned()),
            ],
        )
    }
}

pub type ConsumerGroupMetadata = ConsumerGroupPostureProjection;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureEventHubPostureProjection {
    pub namespace: NamespacePostureProjection,
    pub event_hub: EventHubPostureProjection,
    pub consumer_group: ConsumerGroupPostureProjection,
    pub posture_digest: Digest,
}

impl AzureEventHubPostureProjection {
    pub fn new(
        namespace: NamespacePostureProjection,
        event_hub: EventHubPostureProjection,
        consumer_group: ConsumerGroupPostureProjection,
    ) -> Result<Self> {
        namespace.validate_integrity()?;
        event_hub.validate_integrity()?;
        consumer_group.validate_integrity()?;
        let mut projection = Self {
            namespace,
            event_hub,
            consumer_group,
            posture_digest: Digest::from_text("unsealed-azure-event-hub-posture"),
        };
        projection.posture_digest = projection.calculate_digest();
        Ok(projection)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.namespace.validate_integrity()?;
        self.event_hub.validate_integrity()?;
        self.consumer_group.validate_integrity()?;
        if self.posture_digest != self.calculate_digest() {
            return Err(AzureEventHubPostureResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-posture-projection/v1",
            &[
                (
                    "namespace",
                    self.namespace.projection_digest.as_str().to_owned(),
                ),
                (
                    "event_hub",
                    self.event_hub.projection_digest.as_str().to_owned(),
                ),
                (
                    "consumer_group",
                    self.consumer_group.projection_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureEventHubEvidenceState {
    Ready,
    InProgress,
    Disabled,
    Partial,
    StaleState,
    AccessLoss,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    TimedOut,
    ApiDrift,
    ScopeDrift,
    PaginationLoop,
    Tampered,
    ProviderUnknown,
    RegistrationRevoked,
}

impl AzureEventHubEvidenceState {
    pub const fn is_review_complete(self) -> bool {
        matches!(self, Self::Ready | Self::InProgress | Self::Disabled)
    }
}

pub type EventHubPostureEvidenceState = AzureEventHubEvidenceState;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

pub fn mission_projection(identity: &MissionIdentity) -> MissionProjection {
    MissionProjection {
        id_digest: identity.id_digest(),
        revision: identity.revision(),
    }
}

pub fn project_projection(identity: &ProjectIdentity) -> ProjectProjection {
    ProjectProjection {
        id_digest: identity.id_digest(),
        revision: identity.revision(),
    }
}

pub fn work_product_projection(identity: &WorkProductIdentity) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: identity.id_digest(),
        revision: identity.revision(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReceipt {
    pub operation: String,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub response_bytes: u64,
    pub redacted: bool,
    pub receipt_digest: Digest,
}

impl RequestReceipt {
    pub fn new(
        operation: impl Into<String>,
        request_digest: Digest,
        path_digest: Digest,
        query_digest: Digest,
        scope_digest: Digest,
        response_bytes: u64,
    ) -> Result<Self> {
        let mut receipt = Self {
            operation: operation.into(),
            request_digest,
            path_digest,
            query_digest,
            scope_digest,
            response_bytes,
            redacted: true,
            receipt_digest: Digest::from_text("unsealed-azure-event-hub-request-receipt"),
        };
        receipt.receipt_digest = receipt.calculate_digest();
        receipt.validate_integrity()?;
        Ok(receipt)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.request_digest.validate()?;
        self.path_digest.validate()?;
        self.query_digest.validate()?;
        self.scope_digest.validate()?;
        if self.operation.is_empty()
            || !self.redacted
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.receipt_digest != self.calculate_digest()
        {
            return Err(AzureEventHubPostureResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-request-receipt/v1",
            &[
                ("operation", self.operation.clone()),
                ("request", self.request_digest.as_str().to_owned()),
                ("path", self.path_digest.as_str().to_owned()),
                ("query", self.query_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("bytes", self.response_bytes.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostReceipt {
    pub operation: String,
    pub response_bytes: u64,
    pub bounded_request_units: u32,
    pub estimate_only: bool,
    pub durable_provider_receipt: bool,
    pub cost_digest: Digest,
    pub receipt_digest: Digest,
}

impl CostReceipt {
    pub fn new(operation: impl Into<String>, response_bytes: u64) -> Result<Self> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AzureEventHubPostureResultError::PartialEvidence);
        }
        let operation = operation.into();
        let mut receipt = Self {
            operation,
            response_bytes,
            bounded_request_units: 1,
            estimate_only: true,
            durable_provider_receipt: false,
            cost_digest: Digest::from_text("unsealed-azure-event-hub-cost"),
            receipt_digest: Digest::from_text("unsealed-azure-event-hub-cost-receipt"),
        };
        receipt.cost_digest = Digest::from_parts(
            "azure-event-hub-cost/v1",
            &[
                ("operation", receipt.operation.clone()),
                ("bytes", response_bytes.to_string()),
                ("units", receipt.bounded_request_units.to_string()),
            ],
        );
        receipt.receipt_digest = receipt.calculate_digest();
        receipt.validate_integrity()?;
        Ok(receipt)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.cost_digest.validate()?;
        if self.operation.is_empty()
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.bounded_request_units == 0
            || !self.estimate_only
            || self.durable_provider_receipt
            || self.receipt_digest != self.calculate_digest()
        {
            return Err(AzureEventHubPostureResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-cost-receipt/v1",
            &[
                ("operation", self.operation.clone()),
                ("bytes", self.response_bytes.to_string()),
                ("units", self.bounded_request_units.to_string()),
                ("cost", self.cost_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostSummary {
    pub response_bytes: u64,
    pub bounded_request_units: u32,
    pub cost_digest: Digest,
}

impl CostSummary {
    pub fn from_receipts(receipts: &[CostReceipt]) -> Self {
        let response_bytes: u64 = receipts.iter().map(|receipt| receipt.response_bytes).sum();
        let bounded_request_units: u32 = receipts
            .iter()
            .map(|receipt| receipt.bounded_request_units)
            .sum();
        let cost_digest = Digest::from_parts(
            "azure-event-hub-cost-summary/v1",
            &[
                ("bytes", response_bytes.to_string()),
                ("units", bounded_request_units.to_string()),
                (
                    "receipts",
                    receipts
                        .iter()
                        .map(|receipt| receipt.receipt_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Self {
            response_bytes,
            bounded_request_units,
            cost_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub tenant_digest: Digest,
    pub subscription_digest: Digest,
    pub resource_group_digest: Digest,
    pub namespace_digest: Digest,
    pub event_hub_digest: Digest,
    pub consumer_group_digest: Digest,
    pub list_consumer_groups_digest: Option<Digest>,
    pub namespace_get_digest: Option<Digest>,
    pub event_hub_get_digest: Option<Digest>,
    pub consumer_group_get_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub fn validate(&self) -> Result<()> {
        for digest in [
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.scope_digest,
            &self.tenant_digest,
            &self.subscription_digest,
            &self.resource_group_digest,
            &self.namespace_digest,
            &self.event_hub_digest,
            &self.consumer_group_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        for digest in [
            &self.list_consumer_groups_digest,
            &self.namespace_get_digest,
            &self.event_hub_get_digest,
            &self.consumer_group_get_digest,
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        Ok(())
    }
}

pub fn join_digests(values: impl IntoIterator<Item = Digest>) -> String {
    values
        .into_iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn validate_page_size(value: u16) -> Result<()> {
    if value == 0 || value > MAX_PAGE_SIZE {
        Err(AzureEventHubPostureResultError::InvalidRequest)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_page_number(value: u16) -> Result<()> {
    if value == 0 || value > MAX_PAGES {
        Err(AzureEventHubPostureResultError::InvalidRequest)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_response_bytes(value: u64) -> Result<()> {
    if value > MAX_RESPONSE_BYTES {
        Err(AzureEventHubPostureResultError::PartialEvidence)
    } else {
        Ok(())
    }
}
