//! Typed, bounded Azure Service Bus queue posture models.
//!
//! The model deliberately has no Azure SDK payload, credential, message,
//! endpoint, authorization-rule, lock-token, session-state, or PII type. A
//! provider may parse those values transiently, but they cannot cross this
//! module's projection boundary.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_RESOURCE_GROUP_BYTES: usize = 90;
pub const MAX_NAMESPACE_BYTES: usize = 50;
pub const MAX_QUEUE_NAME_BYTES: usize = 260;
pub const MAX_CURSOR_BYTES: usize = 2_048;
pub const MAX_QUEUES_PER_PAGE: usize = 64;
pub const MAX_QUEUES_PER_READ: usize = 1;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 50;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 6;
pub const MAX_RETRIES: u8 = 2;
pub const MAX_COUNT: u64 = 1_000_000_000_000;
pub const MAX_SIZE_BYTES: u64 = 1_099_511_627_776;
pub const MAX_SIZE_MEGABYTES: u32 = 1_048_576;
pub const MAX_DURATION_SECONDS: u64 = 1_000_000_000_000_000;
pub const MAX_DELIVERY_COUNT: u32 = 1_000_000;
pub const MAX_MESSAGE_SIZE_KILOBYTES: u64 = 1_048_576;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a bounded opaque continuation")]
    InvalidContinuation { field: &'static str },
    #[error("{field} exceeds a Layer-1 bound")]
    BoundExceeded { field: &'static str },
    #[error("{field} contains too many entries")]
    TooMany { field: &'static str },
    #[error("{field} is not allowed for this operation")]
    Unsupported { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("{field} is stale")]
    Stale { field: &'static str },
    #[error("the opaque secret reference is revoked")]
    SecretRevoked,
}

fn validate_text(
    value: &str,
    field: &'static str,
    max: usize,
    allowed_extra: &str,
) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    if value.chars().any(|character| {
        !(character.is_ascii_alphanumeric()
            || "-_.".contains(character)
            || allowed_extra.contains(character))
    }) {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_uuid(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.len() != 36
        || value.as_bytes().iter().enumerate().any(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte != b'-'
            } else {
                !byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(ModelError::Invalid { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

fn validate_digest(value: &Digest, field: &'static str) -> Result<(), ModelError> {
    if value.0.len() != 64
        || value
            .0
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(ModelError::InvalidDigest { field });
    }
    Ok(())
}

fn lower_ascii(value: impl Into<String>) -> String {
    value.into().to_ascii_lowercase()
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $max:expr, $extra:literal) => {
        #[derive(
            Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, $max, $extra)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("hartevo-azure-service-bus-", $field, "/v1"),
                    std::slice::from_ref(&self.0),
                )
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
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

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct TenantId(String);

impl TenantId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = lower_ascii(value);
        validate_uuid(&value, "tenant id")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("hartevo-azure-tenant-id/v1", std::slice::from_ref(&self.0))
    }
}

impl fmt::Debug for TenantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantId")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct SubscriptionId(String);

impl SubscriptionId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = lower_ascii(value);
        validate_uuid(&value, "subscription id")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-azure-subscription-id/v1",
            std::slice::from_ref(&self.0),
        )
    }
}

impl fmt::Debug for SubscriptionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubscriptionId")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

bounded_identifier!(
    ResourceGroupName,
    "resource-group-name",
    MAX_RESOURCE_GROUP_BYTES,
    "() "
);
bounded_identifier!(NamespaceName, "namespace-name", MAX_NAMESPACE_BYTES, "");
bounded_identifier!(QueueName, "queue-name", MAX_QUEUE_NAME_BYTES, "$ ");
bounded_identifier!(ProjectId, "project-id", MAX_IDENTIFIER_BYTES, ":/@+");
bounded_identifier!(MissionId, "mission-id", MAX_IDENTIFIER_BYTES, ":/@+");
bounded_identifier!(
    WorkProductId,
    "work-product-id",
    MAX_IDENTIFIER_BYTES,
    ":/@+"
);
bounded_identifier!(PermissionId, "permission-id", MAX_IDENTIFIER_BYTES, ":/@+");
bounded_identifier!(ProviderId, "provider-id", MAX_IDENTIFIER_BYTES, ":/@+");
bounded_identifier!(
    ProviderRevision,
    "provider-revision",
    MAX_IDENTIFIER_BYTES,
    ":/@+"
);

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(Sha256::digest(bytes).as_slice()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(tag: &str, parts: &[String]) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(tag.as_bytes());
        for part in parts {
            bytes.push(0);
            bytes.extend_from_slice(part.len().to_string().as_bytes());
            bytes.push(b':');
            bytes.extend_from_slice(part.as_bytes());
        }
        Self::from_bytes(&bytes)
    }

    pub fn from_fields(tag: &str, fields: &[(&str, String)]) -> Self {
        let parts = fields
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>();
        Self::from_parts(tag, &parts)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(ModelError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value))
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
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

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub const fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub const fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub const fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceBinding {
    pub name: NamespaceName,
    pub revision: Revision,
}

impl NamespaceBinding {
    pub const fn new(name: NamespaceName, revision: Revision) -> Self {
        Self { name, revision }
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueBinding {
    pub name: QueueName,
    pub revision: Revision,
}

impl QueueBinding {
    pub const fn new(name: QueueName, revision: Revision) -> Self {
        Self { name, revision }
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeadLetterScope {
    pub included: bool,
    pub revision: Revision,
}

impl DeadLetterScope {
    pub const fn new(included: bool, revision: Revision) -> Self {
        Self { included, revision }
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionAction {
    GetQueue,
    ListQueues,
}

impl PermissionAction {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::GetQueue => "Microsoft.ServiceBus/namespaces/queues/read",
            Self::ListQueues => "Microsoft.ServiceBus/namespaces/queues/list",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub id: PermissionId,
    pub revision: Revision,
    pub allowed_actions: BTreeSet<PermissionAction>,
}

impl PermissionFence {
    pub fn readonly(id: PermissionId, revision: Revision) -> Result<Self, ModelError> {
        Self::new(
            id,
            revision,
            [PermissionAction::GetQueue, PermissionAction::ListQueues],
        )
    }

    pub fn read_only(id: PermissionId, revision: Revision) -> Result<Self, ModelError> {
        Self::readonly(id, revision)
    }

    pub fn new(
        id: PermissionId,
        revision: Revision,
        allowed_actions: impl IntoIterator<Item = PermissionAction>,
    ) -> Result<Self, ModelError> {
        let allowed_actions = allowed_actions.into_iter().collect::<BTreeSet<_>>();
        let fence = Self {
            id,
            revision,
            allowed_actions,
        };
        fence.validate()?;
        Ok(fence)
    }

    pub fn allows(&self, action: PermissionAction) -> bool {
        self.allowed_actions.contains(&action)
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_text(
            self.id.as_str(),
            "permission id",
            MAX_IDENTIFIER_BYTES,
            ":/@+",
        )?;
        validate_positive(self.revision.get(), "permission revision")?;
        if self.allowed_actions.is_empty() {
            return Err(ModelError::Empty {
                field: "permission allowlist",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AzureServiceBusScope {
    tenant_id: TenantId,
    subscription_id: SubscriptionId,
    resource_group_name: ResourceGroupName,
    namespace: NamespaceBinding,
    queue: QueueBinding,
    dead_letter: DeadLetterScope,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    permission_digest: Digest,
}

impl AzureServiceBusScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        subscription_id: SubscriptionId,
        resource_group_name: ResourceGroupName,
        namespace: NamespaceBinding,
        queue: QueueBinding,
        dead_letter: DeadLetterScope,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            tenant_id,
            subscription_id,
            resource_group_name,
            namespace,
            queue,
            dead_letter,
            project,
            mission,
            work_product,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_values(
        tenant_id: impl Into<String>,
        subscription_id: impl Into<String>,
        resource_group_name: impl Into<String>,
        namespace_name: impl Into<String>,
        namespace_revision: u64,
        queue_name: impl Into<String>,
        queue_revision: u64,
        dead_letter_included: bool,
        dead_letter_revision: u64,
        project_id: impl Into<String>,
        project_revision: u64,
        mission_id: impl Into<String>,
        mission_revision: u64,
        work_product_id: impl Into<String>,
        work_product_revision: u64,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        Self::new(
            TenantId::new(tenant_id)?,
            SubscriptionId::new(subscription_id)?,
            ResourceGroupName::new(resource_group_name)?,
            NamespaceBinding::new(
                NamespaceName::new(namespace_name)?,
                Revision::new(namespace_revision)?,
            ),
            QueueBinding::new(QueueName::new(queue_name)?, Revision::new(queue_revision)?),
            DeadLetterScope::new(dead_letter_included, Revision::new(dead_letter_revision)?),
            ProjectBinding::new(
                ProjectId::new(project_id)?,
                Revision::new(project_revision)?,
            ),
            MissionBinding::new(
                MissionId::new(mission_id)?,
                Revision::new(mission_revision)?,
            ),
            WorkProductBinding::new(
                WorkProductId::new(work_product_id)?,
                Revision::new(work_product_revision)?,
            ),
            permission_digest,
        )
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn subscription_id(&self) -> &SubscriptionId {
        &self.subscription_id
    }

    pub fn resource_group_name(&self) -> &ResourceGroupName {
        &self.resource_group_name
    }

    pub fn namespace(&self) -> &NamespaceBinding {
        &self.namespace
    }

    pub fn queue(&self) -> &QueueBinding {
        &self.queue
    }

    pub fn dead_letter(&self) -> &DeadLetterScope {
        &self.dead_letter
    }

    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo-azure-service-bus-scope/v1",
            &[
                ("tenant", self.tenant_id.digest().to_string()),
                ("subscription", self.subscription_id.digest().to_string()),
                (
                    "resource_group",
                    self.resource_group_name.digest().to_string(),
                ),
                ("namespace", self.namespace.digest().to_string()),
                ("queue", self.queue.digest().to_string()),
                ("dead_letter", self.dead_letter.digest().to_string()),
                ("project", self.project.digest().to_string()),
                ("mission", self.mission.digest().to_string()),
                ("work_product", self.work_product.digest().to_string()),
                ("permission", self.permission_digest.to_string()),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_uuid(self.tenant_id.as_str(), "tenant id")?;
        validate_uuid(self.subscription_id.as_str(), "subscription id")?;
        validate_text(
            self.resource_group_name.as_str(),
            "resource group name",
            MAX_RESOURCE_GROUP_BYTES,
            "() ",
        )?;
        validate_text(
            self.namespace.name.as_str(),
            "namespace name",
            MAX_NAMESPACE_BYTES,
            "",
        )?;
        validate_text(
            self.queue.name.as_str(),
            "queue name",
            MAX_QUEUE_NAME_BYTES,
            "$ ",
        )?;
        validate_text(
            self.project.id.as_str(),
            "project id",
            MAX_IDENTIFIER_BYTES,
            ":/@+",
        )?;
        validate_text(
            self.mission.id.as_str(),
            "mission id",
            MAX_IDENTIFIER_BYTES,
            ":/@+",
        )?;
        validate_text(
            self.work_product.id.as_str(),
            "work product id",
            MAX_IDENTIFIER_BYTES,
            ":/@+",
        )?;
        for (revision, field) in [
            (self.namespace.revision, "namespace revision"),
            (self.queue.revision, "queue revision"),
            (self.dead_letter.revision, "dead-letter revision"),
            (self.project.revision, "project revision"),
            (self.mission.revision, "mission revision"),
            (self.work_product.revision, "work product revision"),
        ] {
            validate_positive(revision.get(), field)?;
        }
        validate_digest(&self.permission_digest, "permission digest")?;
        if self.permission_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "permission digest",
            });
        }
        Ok(())
    }
}

impl fmt::Debug for AzureServiceBusScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureServiceBusScope")
            .field("scope_digest", &self.digest())
            .field("tenant", &self.tenant_id)
            .field("subscription", &self.subscription_id)
            .field("resource_group", &self.resource_group_name.digest())
            .field("namespace", &self.namespace.digest())
            .field("queue", &self.queue.digest())
            .field("dead_letter", &self.dead_letter)
            .field("project", &self.project.digest())
            .field("mission", &self.mission.digest())
            .field("work_product", &self.work_product.digest())
            .field("permission_digest", &self.permission_digest)
            .finish()
    }
}

impl Serialize for AzureServiceBusScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("AzureServiceBusScope", 11)?;
        value.serialize_field("tenantDigest", &self.tenant_id.digest())?;
        value.serialize_field("subscriptionDigest", &self.subscription_id.digest())?;
        value.serialize_field("resourceGroupDigest", &self.resource_group_name.digest())?;
        value.serialize_field("namespaceDigest", &self.namespace.digest())?;
        value.serialize_field("queueDigest", &self.queue.digest())?;
        value.serialize_field("deadLetter", &self.dead_letter)?;
        value.serialize_field("projectDigest", &self.project.digest())?;
        value.serialize_field("missionDigest", &self.mission.digest())?;
        value.serialize_field("workProductDigest", &self.work_product.digest())?;
        value.serialize_field("permissionDigest", &self.permission_digest)?;
        value.serialize_field("scopeDigest", &self.digest())?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    EntraCredential,
}

/// Opaque Entra reference. The caller-supplied handle is hashed and dropped;
/// it is never serializable, displayable, or present in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl Into<String>,
        scope: &AzureServiceBusScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let mut handle = opaque_handle.into();
        if validate_text(
            &handle,
            "Entra secret reference",
            MAX_IDENTIFIER_BYTES,
            ":/@+=",
        )
        .is_err()
        {
            handle.zeroize();
            return Err(ModelError::Invalid {
                field: "Entra secret reference",
            });
        }
        let reference_digest = Digest::from_fields(
            "hartevo-azure-service-bus-opaque-entra-reference/v1",
            &[
                ("handle", handle.clone()),
                ("scope", scope.digest().to_string()),
                ("revision", revision.get().to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            kind: SecretKind::EntraCredential,
            reference_digest,
            scope_digest: scope.digest(),
            revision,
            revoked: false,
        })
    }

    pub fn for_scope(
        opaque_handle: impl Into<String>,
        scope: &AzureServiceBusScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::new(opaque_handle, scope, revision)
    }

    pub fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn validate(&self, scope: &AzureServiceBusScope) -> Result<(), ModelError> {
        if self.kind != SecretKind::EntraCredential
            || self.revoked
            || self.scope_digest != scope.digest()
            || self.reference_digest == Digest::zero()
        {
            return if self.revoked {
                Err(ModelError::SecretRevoked)
            } else {
                Err(ModelError::ScopeMismatch {
                    field: "opaque Entra secret reference",
                })
            };
        }
        Ok(())
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

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("SecretReference", 2)?;
        value.serialize_field("opaque", &true)?;
        value.serialize_field("revoked", &self.revoked)?;
        value.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueContinuation {
    token_digest: Digest,
    binding_digest: Option<Digest>,
}

impl OpaqueContinuation {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidContinuation {
                field: "continuation",
            });
        }
        Ok(Self {
            token_digest: Digest::from_text(value),
            binding_digest: None,
        })
    }

    pub fn bind(&self, binding_digest: &Digest) -> Self {
        Self {
            token_digest: self.token_digest.clone(),
            binding_digest: Some(binding_digest.clone()),
        }
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }
}

impl fmt::Debug for OpaqueContinuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueContinuation")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for OpaqueContinuation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("OpaqueContinuation", 2)?;
        value.serialize_field("opaque", &true)?;
        value.serialize_field("bindingDigest", &self.binding_digest)?;
        value.end()
    }
}

pub type OpaqueCursor = OpaqueContinuation;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum QueueStatus {
    Active,
    Disabled,
    SendDisabled,
    ReceiveDisabled,
    Restoring,
    Creating,
    Deleting,
    Renaming,
    Unknown,
}

impl QueueStatus {
    pub fn parse_api(value: &str) -> Self {
        match value {
            "Active" | "ACTIVE" => Self::Active,
            "Disabled" | "DISABLED" => Self::Disabled,
            "SendDisabled" | "SEND_DISABLED" => Self::SendDisabled,
            "ReceiveDisabled" | "RECEIVE_DISABLED" => Self::ReceiveDisabled,
            "Restoring" => Self::Restoring,
            "Creating" => Self::Creating,
            "Deleting" => Self::Deleting,
            "Renaming" => Self::Renaming,
            _ => Self::Unknown,
        }
    }

    pub const fn is_supported_state(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Disabled | Self::SendDisabled | Self::ReceiveDisabled
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QueuePostureState {
    Active,
    Disabled,
    SendDisabled,
    ReceiveDisabled,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl QueuePostureState {
    pub const fn is_fail_closed(self) -> bool {
        !matches!(
            self,
            Self::Active | Self::Disabled | Self::SendDisabled | Self::ReceiveDisabled
        )
    }

    pub const fn from_queue_status(status: QueueStatus) -> Self {
        match status {
            QueueStatus::Active => Self::Active,
            QueueStatus::Disabled => Self::Disabled,
            QueueStatus::SendDisabled => Self::SendDisabled,
            QueueStatus::ReceiveDisabled => Self::ReceiveDisabled,
            QueueStatus::Restoring
            | QueueStatus::Creating
            | QueueStatus::Deleting
            | QueueStatus::Renaming
            | QueueStatus::Unknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageBudget,
    QueueBudget,
    ResponseTooLarge,
    MissingQueue,
    MissingConfiguration,
    ContinuationReplay,
    ContinuationBindingMismatch,
    ProviderConflict,
    StaleQueueRevision,
    Truncated,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    BlockedEnvironment,
    MalformedResponse,
    ScopeDrift,
    BoundExceeded,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("Azure Service Bus ARM request is invalid")]
    InvalidRequest,
    #[error("Azure Service Bus ARM authentication was rejected")]
    Unauthorized,
    #[error("Azure Service Bus ARM access was denied")]
    Forbidden,
    #[error("Azure Service Bus scope was not found")]
    NotFound,
    #[error("Azure Service Bus provider returned a conflict")]
    Conflict,
    #[error("Azure Service Bus provider rate limited the request")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Azure Service Bus provider returned a server failure")]
    ServerFailure { status_code: Option<u16> },
    #[error("Azure Service Bus provider timed out")]
    Timeout,
    #[error("Azure Service Bus native transport is unavailable in BLOCKED_ENV")]
    BlockedEnvironment,
    #[error("Azure Service Bus provider response was malformed")]
    MalformedResponse,
    #[error("Azure Service Bus response drifted outside the exact scope")]
    ScopeDrift,
    #[error("Azure Service Bus response exceeded a Layer-1 bound")]
    BoundExceeded,
    #[error("Azure Service Bus provider returned an unknown error")]
    Unknown,
}

impl TransportError {
    pub const fn kind(&self) -> ProviderErrorKind {
        match self {
            Self::InvalidRequest => ProviderErrorKind::InvalidRequest,
            Self::Unauthorized => ProviderErrorKind::Unauthorized,
            Self::Forbidden => ProviderErrorKind::Forbidden,
            Self::NotFound => ProviderErrorKind::NotFound,
            Self::Conflict => ProviderErrorKind::Conflict,
            Self::RateLimited { .. } => ProviderErrorKind::RateLimited,
            Self::ServerFailure { .. } => ProviderErrorKind::ServerFailure,
            Self::Timeout => ProviderErrorKind::Timeout,
            Self::BlockedEnvironment => ProviderErrorKind::BlockedEnvironment,
            Self::MalformedResponse => ProviderErrorKind::MalformedResponse,
            Self::ScopeDrift => ProviderErrorKind::ScopeDrift,
            Self::BoundExceeded => ProviderErrorKind::BoundExceeded,
            Self::Unknown => ProviderErrorKind::Unknown,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::InvalidRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerFailure { status_code } => *status_code,
            Self::Timeout
            | Self::BlockedEnvironment
            | Self::MalformedResponse
            | Self::ScopeDrift
            | Self::BoundExceeded
            | Self::Unknown => None,
        }
    }

    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerFailure { .. } | Self::Timeout
        )
    }

    pub const fn evidence(&self) -> ProviderErrorEvidence {
        ProviderErrorEvidence {
            kind: self.kind(),
            status_code: self.status_code(),
            retry_after_seconds: self.retry_after_seconds(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueCountProjection {
    pub message_count: Option<u64>,
    pub active_message_count: Option<u64>,
    pub dead_letter_message_count: Option<u64>,
    pub scheduled_message_count: Option<u64>,
    pub transfer_dead_letter_message_count: Option<u64>,
    pub transfer_message_count: Option<u64>,
}

impl QueueCountProjection {
    pub const fn empty() -> Self {
        Self {
            message_count: None,
            active_message_count: None,
            dead_letter_message_count: None,
            scheduled_message_count: None,
            transfer_dead_letter_message_count: None,
            transfer_message_count: None,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        for (field, value) in [
            ("message count", self.message_count),
            ("active message count", self.active_message_count),
            ("dead-letter message count", self.dead_letter_message_count),
            ("scheduled message count", self.scheduled_message_count),
            (
                "transfer dead-letter message count",
                self.transfer_dead_letter_message_count,
            ),
            ("transfer message count", self.transfer_message_count),
        ] {
            if value.is_some_and(|value| value > MAX_COUNT) {
                return Err(ModelError::BoundExceeded { field });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueConfigurationProjection {
    pub default_message_ttl_seconds: Option<u64>,
    pub auto_delete_on_idle_seconds: Option<u64>,
    pub duplicate_detection_history_window_seconds: Option<u64>,
    pub lock_duration_seconds: Option<u64>,
    pub requires_session: Option<bool>,
    pub enable_partitioning: Option<bool>,
    pub requires_duplicate_detection: Option<bool>,
    pub dead_lettering_on_message_expiration: Option<bool>,
    pub max_delivery_count: Option<u32>,
    pub max_size_in_megabytes: Option<u32>,
    pub max_message_size_in_kilobytes: Option<u64>,
}

impl QueueConfigurationProjection {
    pub const fn empty() -> Self {
        Self {
            default_message_ttl_seconds: None,
            auto_delete_on_idle_seconds: None,
            duplicate_detection_history_window_seconds: None,
            lock_duration_seconds: None,
            requires_session: None,
            enable_partitioning: None,
            requires_duplicate_detection: None,
            dead_lettering_on_message_expiration: None,
            max_delivery_count: None,
            max_size_in_megabytes: None,
            max_message_size_in_kilobytes: None,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        for (field, value) in [
            ("default message TTL", self.default_message_ttl_seconds),
            (
                "auto-delete idle duration",
                self.auto_delete_on_idle_seconds,
            ),
            (
                "duplicate detection duration",
                self.duplicate_detection_history_window_seconds,
            ),
            ("lock duration", self.lock_duration_seconds),
        ] {
            if value.is_some_and(|value| value > MAX_DURATION_SECONDS) {
                return Err(ModelError::BoundExceeded { field });
            }
        }
        if self
            .max_delivery_count
            .is_some_and(|value| value > MAX_DELIVERY_COUNT)
        {
            return Err(ModelError::BoundExceeded {
                field: "max delivery count",
            });
        }
        if self
            .max_size_in_megabytes
            .is_some_and(|value| value > MAX_SIZE_MEGABYTES)
        {
            return Err(ModelError::BoundExceeded {
                field: "max size in megabytes",
            });
        }
        if self
            .max_message_size_in_kilobytes
            .is_some_and(|value| value > MAX_MESSAGE_SIZE_KILOBYTES)
        {
            return Err(ModelError::BoundExceeded {
                field: "max message size",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueuePostureProjection {
    pub queue_name_digest: Digest,
    pub queue_scope_revision: Revision,
    pub status: QueueStatus,
    pub size_in_bytes: Option<u64>,
    pub counts: QueueCountProjection,
    pub configuration: QueueConfigurationProjection,
    pub revision_digest: Digest,
    pub complete: bool,
    pub posture_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QueuePostureBody<'a> {
    queue_name_digest: &'a Digest,
    queue_scope_revision: Revision,
    status: QueueStatus,
    size_in_bytes: Option<u64>,
    counts: &'a QueueCountProjection,
    configuration: &'a QueueConfigurationProjection,
    revision_digest: &'a Digest,
    complete: bool,
}

impl QueuePostureProjection {
    pub fn new(
        scope: &AzureServiceBusScope,
        status: QueueStatus,
        size_in_bytes: Option<u64>,
        counts: QueueCountProjection,
        configuration: QueueConfigurationProjection,
        revision_digest: Digest,
        complete: bool,
    ) -> Result<Self, ModelError> {
        if size_in_bytes.is_some_and(|value| value > MAX_SIZE_BYTES) {
            return Err(ModelError::BoundExceeded {
                field: "queue size",
            });
        }
        counts.validate()?;
        configuration.validate()?;
        validate_digest(&revision_digest, "queue revision digest")?;
        if revision_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "queue revision digest",
            });
        }
        let mut projection = Self {
            queue_name_digest: scope.queue.name.digest(),
            queue_scope_revision: scope.queue.revision,
            status,
            size_in_bytes,
            counts,
            configuration,
            revision_digest,
            complete,
            posture_digest: Digest::zero(),
        };
        projection.posture_digest = projection.recomputed_digest();
        Ok(projection)
    }

    pub fn fixture(scope: &AzureServiceBusScope, status: QueueStatus) -> Self {
        Self::new(
            scope,
            status,
            Some(4_096),
            QueueCountProjection {
                message_count: Some(12),
                active_message_count: Some(9),
                dead_letter_message_count: Some(2),
                scheduled_message_count: Some(1),
                transfer_dead_letter_message_count: Some(0),
                transfer_message_count: Some(0),
            },
            QueueConfigurationProjection {
                default_message_ttl_seconds: Some(86_400),
                auto_delete_on_idle_seconds: Some(3_600),
                duplicate_detection_history_window_seconds: Some(600),
                lock_duration_seconds: Some(60),
                requires_session: Some(false),
                enable_partitioning: Some(true),
                requires_duplicate_detection: Some(true),
                dead_lettering_on_message_expiration: Some(true),
                max_delivery_count: Some(10),
                max_size_in_megabytes: Some(1_024),
                max_message_size_in_kilobytes: Some(1_024),
            },
            Digest::from_fields(
                "hartevo-azure-service-bus-fixture-revision/v1",
                &[("scope", scope.digest().to_string())],
            ),
            true,
        )
        .expect("bounded fixture projection")
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&QueuePostureBody {
            queue_name_digest: &self.queue_name_digest,
            queue_scope_revision: self.queue_scope_revision,
            status: self.status,
            size_in_bytes: self.size_in_bytes,
            counts: &self.counts,
            configuration: &self.configuration,
            revision_digest: &self.revision_digest,
            complete: self.complete,
        })
    }

    pub fn validate_for(&self, scope: &AzureServiceBusScope) -> Result<(), ModelError> {
        validate_digest(&self.queue_name_digest, "queue name digest")?;
        validate_digest(&self.revision_digest, "queue revision digest")?;
        validate_digest(&self.posture_digest, "queue posture digest")?;
        if self.queue_name_digest != scope.queue.name.digest()
            || self.queue_scope_revision != scope.queue.revision
            || self.revision_digest == Digest::zero()
            || self.posture_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "queue posture projection",
            });
        }
        if self
            .size_in_bytes
            .is_some_and(|value| value > MAX_SIZE_BYTES)
        {
            return Err(ModelError::BoundExceeded {
                field: "queue size",
            });
        }
        self.counts.validate()?;
        self.configuration.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionSummary {
    pub raw_provider_payload_dropped: bool,
    pub raw_continuation_dropped: bool,
    pub full_resource_ids_dropped: bool,
    pub endpoint_details_dropped: bool,
    pub authorization_rules_dropped: bool,
    pub connection_strings_dropped: bool,
    pub message_bodies_dropped: bool,
    pub message_properties_dropped: bool,
    pub lock_tokens_dropped: bool,
    pub session_state_dropped: bool,
    pub pii_dropped: bool,
    pub error_messages_dropped: bool,
}

impl RedactionSummary {
    pub const fn layer_one() -> Self {
        Self {
            raw_provider_payload_dropped: true,
            raw_continuation_dropped: true,
            full_resource_ids_dropped: true,
            endpoint_details_dropped: true,
            authorization_rules_dropped: true,
            connection_strings_dropped: true,
            message_bodies_dropped: true,
            message_properties_dropped: true,
            lock_tokens_dropped: true,
            session_state_dropped: true,
            pii_dropped: true,
            error_messages_dropped: true,
        }
    }

    pub const fn is_complete(&self) -> bool {
        self.raw_provider_payload_dropped
            && self.raw_continuation_dropped
            && self.full_resource_ids_dropped
            && self.endpoint_details_dropped
            && self.authorization_rules_dropped
            && self.connection_strings_dropped
            && self.message_bodies_dropped
            && self.message_properties_dropped
            && self.lock_tokens_dropped
            && self.session_state_dropped
            && self.pii_dropped
            && self.error_messages_dropped
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureServiceBusReadOperation {
    GetQueue,
    ListQueues,
}

impl AzureServiceBusReadOperation {
    pub const fn permission(self) -> PermissionAction {
        match self {
            Self::GetQueue => PermissionAction::GetQueue,
            Self::ListQueues => PermissionAction::ListQueues,
        }
    }

    pub const fn api_name(self) -> &'static str {
        match self {
            Self::GetQueue => "Microsoft.ServiceBus/namespaces/queues/read",
            Self::ListQueues => "Microsoft.ServiceBus/namespaces/queues/list",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AzureServiceBusReadRequest {
    operation: AzureServiceBusReadOperation,
    scope: AzureServiceBusScope,
    page_size: u16,
    max_pages: u16,
    max_response_bytes: usize,
    max_retries: u8,
    continuation: Option<OpaqueContinuation>,
    page_number: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadBinding<'a> {
    operation: AzureServiceBusReadOperation,
    scope_digest: &'a Digest,
    page_size: u16,
    max_pages: u16,
    max_response_bytes: usize,
    max_retries: u8,
}

impl AzureServiceBusReadRequest {
    pub fn get_queue(
        scope: &AzureServiceBusScope,
        continuation: Option<OpaqueContinuation>,
    ) -> Result<Self, ModelError> {
        Self::new(AzureServiceBusReadOperation::GetQueue, scope, continuation)
    }

    pub fn list_queues(
        scope: &AzureServiceBusScope,
        continuation: Option<OpaqueContinuation>,
    ) -> Result<Self, ModelError> {
        Self::new(
            AzureServiceBusReadOperation::ListQueues,
            scope,
            continuation,
        )
    }

    pub fn new(
        operation: AzureServiceBusReadOperation,
        scope: &AzureServiceBusScope,
        continuation: Option<OpaqueContinuation>,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        let request = Self {
            operation,
            scope: scope.clone(),
            page_size: PAGE_SIZE,
            max_pages: MAX_PAGES,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_retries: MAX_RETRIES,
            continuation: None,
            page_number: 1,
        };
        request.with_continuation(continuation)
    }

    pub fn operation(&self) -> AzureServiceBusReadOperation {
        self.operation
    }

    pub fn scope(&self) -> &AzureServiceBusScope {
        &self.scope
    }

    pub fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn max_pages(&self) -> u16 {
        self.max_pages
    }

    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    pub const fn max_retries(&self) -> u8 {
        self.max_retries
    }

    pub fn continuation(&self) -> Option<&OpaqueContinuation> {
        self.continuation.as_ref()
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn with_continuation(
        &self,
        continuation: Option<OpaqueContinuation>,
    ) -> Result<Self, ModelError> {
        let mut request = self.clone();
        let query_digest = request.query_digest();
        request.continuation = continuation
            .map(|continuation| {
                if let Some(binding) = continuation.binding_digest()
                    && binding != &query_digest
                {
                    return Err(ModelError::ScopeMismatch {
                        field: "continuation query binding",
                    });
                }
                Ok(continuation.bind(&query_digest))
            })
            .transpose()?;
        if request.continuation.is_some() {
            request.page_number = self.page_number.saturating_add(1);
        }
        if request.page_number > MAX_PAGES {
            return Err(ModelError::BoundExceeded {
                field: "page number",
            });
        }
        Ok(request)
    }

    pub fn with_cursor(
        &self,
        continuation: Option<OpaqueContinuation>,
    ) -> Result<Self, ModelError> {
        self.with_continuation(continuation)
    }

    pub fn with_bounds(
        &self,
        page_size: u16,
        max_pages: u16,
        max_response_bytes: usize,
        max_retries: u8,
    ) -> Result<Self, ModelError> {
        if page_size == 0
            || page_size > PAGE_SIZE
            || max_pages == 0
            || max_pages > MAX_PAGES
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
            || max_retries > MAX_RETRIES
            || self.continuation.is_some()
        {
            return Err(ModelError::Invalid {
                field: "read bounds",
            });
        }
        let mut request = self.clone();
        request.page_size = page_size;
        request.max_pages = max_pages;
        request.max_response_bytes = max_response_bytes;
        request.max_retries = max_retries;
        Ok(request)
    }

    pub fn query_digest(&self) -> Digest {
        digest_serialized(&ReadBinding {
            operation: self.operation,
            scope_digest: &self.scope.digest(),
            page_size: self.page_size,
            max_pages: self.max_pages,
            max_response_bytes: self.max_response_bytes,
            max_retries: self.max_retries,
        })
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo-azure-service-bus-read-request/v1",
            &[
                ("query", self.query_digest().to_string()),
                (
                    "continuation",
                    self.continuation
                        .as_ref()
                        .map_or_else(String::new, |value| value.token_digest().to_string()),
                ),
                ("page", self.page_number.to_string()),
            ],
        )
    }

    pub fn validate_against(
        &self,
        scope: &AzureServiceBusScope,
        permission: &PermissionFence,
    ) -> Result<(), ModelError> {
        if self.scope.digest() != scope.digest() {
            return Err(ModelError::ScopeMismatch {
                field: "scope digest",
            });
        }
        if *self.scope.permission_digest() != permission.digest()
            || self.scope.permission_digest() != scope.permission_digest()
            || !permission.allows(self.operation.permission())
        {
            return Err(ModelError::ScopeMismatch {
                field: "permission fence",
            });
        }
        if self.page_size == 0
            || self.page_size > PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_retries > MAX_RETRIES
            || self.page_number == 0
            || self.page_number > self.max_pages
        {
            return Err(ModelError::BoundExceeded {
                field: "read bounds",
            });
        }
        if let Some(continuation) = &self.continuation
            && continuation.binding_digest() != Some(&self.query_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "continuation query binding",
            });
        }
        Ok(())
    }

    pub fn path_template(&self) -> &'static str {
        match self.operation {
            AzureServiceBusReadOperation::GetQueue => {
                "/subscriptions/<opaque>/resourceGroups/<opaque>/providers/Microsoft.ServiceBus/namespaces/<opaque>/queues/<opaque>"
            }
            AzureServiceBusReadOperation::ListQueues => {
                "/subscriptions/<opaque>/resourceGroups/<opaque>/providers/Microsoft.ServiceBus/namespaces/<opaque>/queues"
            }
        }
    }
}

impl fmt::Debug for AzureServiceBusReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureServiceBusReadRequest")
            .field("operation", &self.operation)
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("max_pages", &self.max_pages)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_retries", &self.max_retries)
            .field("continuation", &self.continuation)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for AzureServiceBusReadRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("AzureServiceBusReadRequest", 8)?;
        value.serialize_field("operation", &self.operation)?;
        value.serialize_field("scopeDigest", &self.scope.digest())?;
        value.serialize_field("pageSize", &self.page_size)?;
        value.serialize_field("maxPages", &self.max_pages)?;
        value.serialize_field("maxResponseBytes", &self.max_response_bytes)?;
        value.serialize_field("maxRetries", &self.max_retries)?;
        value.serialize_field("continuation", &self.continuation)?;
        value.serialize_field("pageNumber", &self.page_number)?;
        value.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureServiceBusReadPage {
    pub operation: AzureServiceBusReadOperation,
    pub query_digest: Digest,
    pub page_number: u16,
    pub queues: Vec<QueuePostureProjection>,
    pub next_continuation: Option<OpaqueContinuation>,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub page_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadPageBody<'a> {
    operation: AzureServiceBusReadOperation,
    query_digest: &'a Digest,
    page_number: u16,
    queues: &'a [QueuePostureProjection],
    next_continuation: &'a Option<OpaqueContinuation>,
    response_bytes: usize,
    provider_revision: &'a ProviderRevision,
    provenance: TransportProvenance,
}

impl AzureServiceBusReadPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &AzureServiceBusReadRequest,
        queues: Vec<QueuePostureProjection>,
        next_continuation: Option<OpaqueContinuation>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        if queues.len() > MAX_QUEUES_PER_PAGE {
            return Err(ModelError::TooMany {
                field: "queues per page",
            });
        }
        if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::BoundExceeded {
                field: "provider response bytes",
            });
        }
        let query_digest = request.query_digest();
        let next_continuation = next_continuation
            .map(|continuation| {
                if let Some(binding) = continuation.binding_digest()
                    && binding != &query_digest
                {
                    return Err(ModelError::ScopeMismatch {
                        field: "next continuation query binding",
                    });
                }
                Ok(continuation.bind(&query_digest))
            })
            .transpose()?;
        let mut page = Self {
            operation: request.operation,
            query_digest,
            page_number: request.page_number,
            queues,
            next_continuation,
            response_bytes,
            provider_revision,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            page_digest: Digest::zero(),
        };
        page.page_digest = page.recomputed_digest();
        Ok(page)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&ReadPageBody {
            operation: self.operation,
            query_digest: &self.query_digest,
            page_number: self.page_number,
            queues: &self.queues,
            next_continuation: &self.next_continuation,
            response_bytes: self.response_bytes,
            provider_revision: &self.provider_revision,
            provenance: self.provenance,
        })
    }

    pub fn validate_for(&self, request: &AzureServiceBusReadRequest) -> Result<(), ModelError> {
        if self.operation != request.operation
            || self.query_digest != request.query_digest()
            || self.page_number != request.page_number()
            || self.page_number == 0
            || self.queues.len() > MAX_QUEUES_PER_PAGE
            || self.response_bytes == 0
            || self.response_bytes > request.max_response_bytes()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.page_digest != self.recomputed_digest()
        {
            return Err(ModelError::Invalid {
                field: "Azure Service Bus page binding",
            });
        }
        if let Some(continuation) = &self.next_continuation
            && continuation.binding_digest() != Some(&request.query_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "next continuation query binding",
            });
        }
        for queue in &self.queues {
            queue.validate_for(request.scope())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureServiceBusQueueEvidence {
    pub state: QueuePostureState,
    pub queue: Option<QueuePostureProjection>,
    pub partial_reason: Option<PartialReason>,
    pub page_count: u16,
    pub request_count: u16,
    pub retry_count: u8,
    pub truncated: bool,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub redactions: RedactionSummary,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub queue_count_is_delivery_verification: bool,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceBody<'a> {
    state: QueuePostureState,
    queue: &'a Option<QueuePostureProjection>,
    partial_reason: Option<PartialReason>,
    page_count: u16,
    request_count: u16,
    retry_count: u8,
    truncated: bool,
    query_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    provider_digest: &'a Digest,
    provider_revision: &'a ProviderRevision,
    api_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_errors: &'a [ProviderErrorEvidence],
    redactions: &'a RedactionSummary,
    provenance: TransportProvenance,
}

impl AzureServiceBusQueueEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: QueuePostureState,
        queue: Option<QueuePostureProjection>,
        partial_reason: Option<PartialReason>,
        page_count: u16,
        request_count: u16,
        retry_count: u8,
        truncated: bool,
        query_digest: Digest,
        scope_digest: Digest,
        permission_digest: Digest,
        provider_digest: Digest,
        provider_revision: ProviderRevision,
        api_digest: Digest,
        contract_digest: Digest,
        provider_errors: Vec<ProviderErrorEvidence>,
        provenance: TransportProvenance,
    ) -> Self {
        let mut evidence = Self {
            state,
            queue,
            partial_reason,
            page_count,
            request_count,
            retry_count,
            truncated,
            query_digest,
            scope_digest,
            permission_digest,
            provider_digest,
            provider_revision,
            api_digest,
            contract_digest,
            provider_errors,
            redactions: RedactionSummary::layer_one(),
            provenance,
            connected: false,
            native: false,
            first_party: false,
            queue_count_is_delivery_verification: false,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.recomputed_digest();
        evidence
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&EvidenceBody {
            state: self.state,
            queue: &self.queue,
            partial_reason: self.partial_reason,
            page_count: self.page_count,
            request_count: self.request_count,
            retry_count: self.retry_count,
            truncated: self.truncated,
            query_digest: &self.query_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            provider_digest: &self.provider_digest,
            provider_revision: &self.provider_revision,
            api_digest: &self.api_digest,
            contract_digest: &self.contract_digest,
            provider_errors: &self.provider_errors,
            redactions: &self.redactions,
            provenance: self.provenance,
        })
    }

    pub fn validate(&self, scope: &AzureServiceBusScope) -> Result<(), ModelError> {
        validate_digest(&self.query_digest, "query digest")?;
        validate_digest(&self.scope_digest, "scope digest")?;
        validate_digest(&self.permission_digest, "permission digest")?;
        validate_digest(&self.provider_digest, "provider digest")?;
        validate_digest(&self.api_digest, "API digest")?;
        validate_digest(&self.contract_digest, "contract digest")?;
        validate_text(
            self.provider_revision.as_str(),
            "provider revision",
            MAX_IDENTIFIER_BYTES,
            ":/@+",
        )?;
        if self.query_digest == Digest::zero()
            || self.scope_digest != scope.digest()
            || self.permission_digest == Digest::zero()
            || self.provider_digest == Digest::zero()
            || self.api_digest == Digest::zero()
            || self.contract_digest == Digest::zero()
            || self.page_count > MAX_PAGES
            || self.request_count > MAX_REQUESTS_PER_READ
            || self.retry_count > MAX_RETRIES
            || self.provider_errors.len() > usize::from(MAX_REQUESTS_PER_READ)
            || self.connected
            || self.native
            || self.first_party
            || self.queue_count_is_delivery_verification
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || !self.redactions.is_complete()
            || self.evidence_digest != self.recomputed_digest()
        {
            return Err(ModelError::Invalid {
                field: "Azure Service Bus evidence binding",
            });
        }
        if let Some(queue) = &self.queue {
            queue.validate_for(scope)?;
        }
        let expected_truncated = self.state.is_fail_closed() || self.partial_reason.is_some();
        if self.truncated != expected_truncated {
            return Err(ModelError::Invalid {
                field: "evidence truncation state",
            });
        }
        match self.state {
            QueuePostureState::Active
            | QueuePostureState::Disabled
            | QueuePostureState::SendDisabled
            | QueuePostureState::ReceiveDisabled => {
                if self.queue.as_ref().is_none_or(|queue| !queue.complete)
                    || self.partial_reason.is_some()
                    || self.page_count == 0
                {
                    return Err(ModelError::Invalid {
                        field: "complete queue evidence",
                    });
                }
            }
            QueuePostureState::Partial => {
                if self.partial_reason.is_none() {
                    return Err(ModelError::Invalid {
                        field: "partial evidence reason",
                    });
                }
            }
            QueuePostureState::AccessLost
            | QueuePostureState::ProviderUnknown
            | QueuePostureState::Tampered
            | QueuePostureState::Revoked => {}
        }
        Ok(())
    }
}

pub fn digest_serialized<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("bounded Azure Service Bus value serializes");
    Digest::from_bytes(&bytes)
}

pub type AzureServiceBusQueueScope = AzureServiceBusScope;
pub type EntraSecretReference = SecretReference;
pub type QueueEvidenceState = QueuePostureState;
pub type AzureServiceBusResultState = QueuePostureState;
pub type AzureServiceBusTransportProvenance = TransportProvenance;
pub type AzureServiceBusProviderErrorEvidence = ProviderErrorEvidence;

/// Used for proposal/record timestamps while keeping the model's timestamp
/// order explicit and deterministic.
pub fn validate_timestamp_order(
    observed_at: DateTime<Utc>,
    recorded_at: DateTime<Utc>,
) -> Result<(), ModelError> {
    if recorded_at < observed_at {
        Err(ModelError::Invalid {
            field: "timestamp ordering",
        })
    } else {
        Ok(())
    }
}
