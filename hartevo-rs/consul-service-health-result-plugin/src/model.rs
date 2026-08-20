use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{CONSUL_API_REVISION, CONSUL_API_VERSION, CONSUL_HEALTH_PROVIDER_ID};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_ENDPOINT_BYTES: usize = 512;
pub(crate) const MAX_DIGEST_BYTES: usize = 64;
pub(crate) const MAX_DIAGNOSTIC_BYTES: usize = 256;
pub(crate) const HARD_MAX_INSTANCES: usize = 128;
pub(crate) const HARD_MAX_CHECKS_PER_INSTANCE: usize = 32;
pub(crate) const HARD_MAX_TAGS_PER_INSTANCE: usize = 8;
pub(crate) const HARD_MAX_RESPONSE_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("endpoint must be a bounded HTTPS origin without a path, query, or fragment")]
    InvalidEndpoint,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("scope is invalid or its digest does not match")]
    InvalidScope,
    #[error("the required Consul permission scope is incomplete")]
    MissingPermission,
    #[error("the read-only consent scope is incomplete")]
    InvalidConsent,
    #[error("opaque secret reference is empty or malformed")]
    InvalidSecretReference,
    #[error("secret reference does not belong to this scope")]
    SecretScopeMismatch,
    #[error("a tag is duplicated")]
    DuplicateTag,
    #[error("a configured bound is outside the Layer-1 maximum")]
    BoundExceeded,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is already active")]
    AlreadyActive,
    #[error("immutable evidence fields do not match their digest")]
    DigestMismatch,
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }

    pub fn from_parts(domain: &str, fields: &[&str]) -> Self {
        let owned = fields
            .iter()
            .map(|field| (*field).to_owned())
            .collect::<Vec<_>>();
        Self::from_fields(domain, &owned)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() == MAX_DIGEST_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
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
        formatter.write_str(&self.0)
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'~')
        })
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn valid_opaque_input(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace())
}

macro_rules! identifier_type {
    ($name:ident) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

identifier_type!(ProjectId);
identifier_type!(MissionId);
identifier_type!(WorkProductId);
identifier_type!(Datacenter);
identifier_type!(AdminPartition);
identifier_type!(Namespace);
identifier_type!(ServiceName);
identifier_type!(NodeId);
identifier_type!(ServiceInstanceId);
identifier_type!(CheckId);

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Tag(String);

impl Tag {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if !value.is_empty()
            && value.len() <= MAX_IDENTIFIER_BYTES
            && value.bytes().all(|byte| !byte.is_ascii_control())
        {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidIdentifier)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Tag {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Tag").field(&self.0).finish()
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn next(self) -> Result<Self, ModelError> {
        self.0
            .checked_add(1)
            .ok_or(ModelError::InvalidRevision)
            .and_then(Self::new)
    }
}

impl From<Revision> for u64 {
    fn from(value: Revision) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Project {
    pub id: ProjectId,
    pub revision: Revision,
    pub identity_digest: Digest,
}

pub type ProjectIdentity = Project;

impl Project {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::from_id(ProjectId::new(id)?, Revision::new(revision)?)
    }

    pub fn from_id(id: ProjectId, revision: Revision) -> Result<Self, ModelError> {
        let identity_digest = Digest::from_parts(
            "consul-project-identity/v1",
            &[id.as_str(), &revision.get().to_string()],
        );
        Ok(Self {
            id,
            revision,
            identity_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::from_id(self.id.clone(), self.revision)?.identity_digest;
        if self.identity_digest == expected {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.identity_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mission {
    pub id: MissionId,
    pub revision: Revision,
    pub identity_digest: Digest,
}

pub type MissionIdentity = Mission;

impl Mission {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::from_id(MissionId::new(id)?, Revision::new(revision)?)
    }

    pub fn from_id(id: MissionId, revision: Revision) -> Result<Self, ModelError> {
        let identity_digest = Digest::from_parts(
            "consul-mission-identity/v1",
            &[id.as_str(), &revision.get().to_string()],
        );
        Ok(Self {
            id,
            revision,
            identity_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::from_id(self.id.clone(), self.revision)?.identity_digest;
        if self.identity_digest == expected {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.identity_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProduct {
    pub id: WorkProductId,
    pub revision: Revision,
    pub identity_digest: Digest,
}

pub type WorkProductIdentity = WorkProduct;

impl WorkProduct {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::from_id(WorkProductId::new(id)?, Revision::new(revision)?)
    }

    pub fn from_id(id: WorkProductId, revision: Revision) -> Result<Self, ModelError> {
        let identity_digest = Digest::from_parts(
            "consul-work-product-identity/v1",
            &[id.as_str(), &revision.get().to_string()],
        );
        Ok(Self {
            id,
            revision,
            identity_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::from_id(self.id.clone(), self.revision)?.identity_digest;
        if self.identity_digest == expected {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.identity_digest
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HttpsEndpoint(String);

impl HttpsEndpoint {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let Some(authority) = value.strip_prefix("https://") else {
            return Err(ModelError::InvalidEndpoint);
        };
        if value.len() > MAX_ENDPOINT_BYTES
            || authority.is_empty()
            || authority.contains(['/', '?', '#', '\\'])
            || authority.bytes().any(|byte| byte.is_ascii_control())
            || authority.ends_with('.')
        {
            return Err(ModelError::InvalidEndpoint);
        }
        if authority.split(':').any(str::is_empty) {
            return Err(ModelError::InvalidEndpoint);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for HttpsEndpoint {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl fmt::Debug for HttpsEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("HttpsEndpoint")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for HttpsEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Permission {
    #[serde(rename = "node:read")]
    NodeRead,
    #[serde(rename = "service:read")]
    ServiceRead,
}

pub type ConsulPermission = Permission;

impl Permission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NodeRead => "node:read",
            Self::ServiceRead => "service:read",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionScope {
    pub permissions: BTreeSet<Permission>,
}

impl PermissionScope {
    pub fn new<I>(permissions: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = Permission>,
    {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        let scope = Self { permissions };
        scope.validate()?;
        Ok(scope)
    }

    pub fn for_layer_one() -> Self {
        let mut permissions = BTreeSet::new();
        permissions.insert(Permission::NodeRead);
        permissions.insert(Permission::ServiceRead);
        Self { permissions }
    }

    pub fn contains(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.contains(Permission::NodeRead) && self.contains(Permission::ServiceRead) {
            Ok(())
        } else {
            Err(ModelError::MissingPermission)
        }
    }

    pub fn digest(&self) -> Digest {
        let values = self
            .permissions
            .iter()
            .map(|permission| permission.as_str().to_owned())
            .collect::<Vec<_>>();
        Digest::from_fields("consul-permission-scope/v1", &values)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsentCapability {
    CatalogRead,
    ServiceHealthRead,
    RedactedObservation,
}

impl ConsentCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CatalogRead => "catalog-read",
            Self::ServiceHealthRead => "service-health-read",
            Self::RedactedObservation => "redacted-observation",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    pub capabilities: BTreeSet<ConsentCapability>,
    pub purpose_digest: Digest,
    pub read_only: bool,
}

impl ConsentScope {
    pub fn new<I>(purpose: impl AsRef<[u8]>, capabilities: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = ConsentCapability>,
    {
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        let purpose_digest = Digest::from_text(purpose);
        let scope = Self {
            capabilities,
            purpose_digest,
            read_only: true,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn read_only(purpose: impl AsRef<[u8]>) -> Self {
        let mut capabilities = BTreeSet::new();
        capabilities.insert(ConsentCapability::CatalogRead);
        capabilities.insert(ConsentCapability::ServiceHealthRead);
        capabilities.insert(ConsentCapability::RedactedObservation);
        Self {
            capabilities,
            purpose_digest: Digest::from_text(purpose),
            read_only: true,
        }
    }

    pub fn contains(&self, capability: ConsentCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    fn expected_digest(&self) -> Digest {
        let values = self
            .capabilities
            .iter()
            .map(|capability| capability.as_str().to_owned())
            .chain([self.read_only.to_string()])
            .collect::<Vec<_>>();
        Digest::from_fields(
            "consul-consent-scope/v1",
            &std::iter::once(self.purpose_digest.as_str().to_owned())
                .chain(values)
                .collect::<Vec<_>>(),
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.read_only
            && self.contains(ConsentCapability::CatalogRead)
            && self.contains(ConsentCapability::ServiceHealthRead)
            && self.contains(ConsentCapability::RedactedObservation)
        {
            Ok(())
        } else {
            Err(ModelError::InvalidConsent)
        }
    }

    pub fn digest(&self) -> Digest {
        self.expected_digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsulServiceHealthScope {
    pub endpoint: HttpsEndpoint,
    pub datacenter: Datacenter,
    pub admin_partition: AdminPartition,
    pub namespace: Namespace,
    pub service: ServiceName,
    pub tag: Option<Tag>,
    pub node: Option<NodeId>,
    pub service_instance: Option<ServiceInstanceId>,
    pub check: Option<CheckId>,
    pub project: Project,
    pub mission: Mission,
    pub work_product: WorkProduct,
    pub permissions: PermissionScope,
    pub consent: ConsentScope,
    pub scope_digest: Digest,
}

pub type Scope = ConsulServiceHealthScope;

impl ConsulServiceHealthScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: impl Into<String>,
        datacenter: impl Into<String>,
        namespace: impl Into<String>,
        service: impl Into<String>,
        project: Project,
        mission: Mission,
        work_product: WorkProduct,
        permissions: PermissionScope,
    ) -> Result<Self, ModelError> {
        Self::new_with_partition(
            endpoint,
            datacenter,
            "default",
            namespace,
            service,
            project,
            mission,
            work_product,
            permissions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_partition(
        endpoint: impl Into<String>,
        datacenter: impl Into<String>,
        admin_partition: impl Into<String>,
        namespace: impl Into<String>,
        service: impl Into<String>,
        project: Project,
        mission: Mission,
        work_product: WorkProduct,
        permissions: PermissionScope,
    ) -> Result<Self, ModelError> {
        let mut scope = Self {
            endpoint: HttpsEndpoint::new(endpoint)?,
            datacenter: Datacenter::new(datacenter)?,
            admin_partition: AdminPartition::new(admin_partition)?,
            namespace: Namespace::new(namespace)?,
            service: ServiceName::new(service)?,
            tag: None,
            node: None,
            service_instance: None,
            check: None,
            project,
            mission,
            work_product,
            permissions,
            consent: ConsentScope::read_only("consul-service-health-result"),
            scope_digest: Digest::from_text("uninitialized-consul-scope"),
        };
        scope.recompute_digest()?;
        Ok(scope)
    }

    pub fn with_admin_partition(mut self, value: impl Into<String>) -> Result<Self, ModelError> {
        self.admin_partition = AdminPartition::new(value)?;
        self.recompute_digest()?;
        Ok(self)
    }

    pub fn with_tag(mut self, value: impl Into<String>) -> Result<Self, ModelError> {
        let tag = Tag::new(value)?;
        if self.tag.as_ref() == Some(&tag) {
            return Err(ModelError::DuplicateTag);
        }
        self.tag = Some(tag);
        self.recompute_digest()?;
        Ok(self)
    }

    pub fn with_node(mut self, value: impl Into<String>) -> Result<Self, ModelError> {
        self.node = Some(NodeId::new(value)?);
        self.recompute_digest()?;
        Ok(self)
    }

    pub fn with_service_instance(mut self, value: impl Into<String>) -> Result<Self, ModelError> {
        self.service_instance = Some(ServiceInstanceId::new(value)?);
        self.recompute_digest()?;
        Ok(self)
    }

    pub fn with_check(mut self, value: impl Into<String>) -> Result<Self, ModelError> {
        self.check = Some(CheckId::new(value)?);
        self.recompute_digest()?;
        Ok(self)
    }

    pub fn with_consent(mut self, consent: ConsentScope) -> Result<Self, ModelError> {
        consent.validate()?;
        self.consent = consent;
        self.recompute_digest()?;
        Ok(self)
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> Digest {
        self.permissions.digest()
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn tag_scope(&self) -> Option<&Tag> {
        self.tag.as_ref()
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        self.permissions.validate()?;
        self.consent.validate()?;
        let expected = self.computed_scope_digest();
        if self.scope_digest == expected {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }

    fn computed_scope_digest(&self) -> Digest {
        let fields = vec![
            self.endpoint.as_str().to_owned(),
            self.datacenter.as_str().to_owned(),
            self.admin_partition.as_str().to_owned(),
            self.namespace.as_str().to_owned(),
            self.service.as_str().to_owned(),
            self.tag
                .as_ref()
                .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            self.node
                .as_ref()
                .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            self.service_instance
                .as_ref()
                .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            self.check
                .as_ref()
                .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            self.project.digest().as_str().to_owned(),
            self.mission.digest().as_str().to_owned(),
            self.work_product.digest().as_str().to_owned(),
            self.permission_digest().as_str().to_owned(),
            self.consent_digest().as_str().to_owned(),
        ];
        Digest::from_fields("consul-service-health-scope/v1", &fields)
    }

    fn recompute_digest(&mut self) -> Result<(), ModelError> {
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        self.permissions.validate()?;
        self.consent.validate()?;
        self.scope_digest = self.computed_scope_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsulServiceHealthScopeInput {
    pub endpoint: String,
    pub datacenter: String,
    pub admin_partition: String,
    pub namespace: String,
    pub service: String,
    pub tag: Option<String>,
    pub node: Option<String>,
    pub service_instance: Option<String>,
    pub check: Option<String>,
    pub project: Project,
    pub mission: Mission,
    pub work_product: WorkProduct,
    pub permissions: PermissionScope,
    pub consent: ConsentScope,
}

impl ConsulServiceHealthScopeInput {
    pub fn build(self) -> Result<ConsulServiceHealthScope, ModelError> {
        let mut scope = ConsulServiceHealthScope::new_with_partition(
            self.endpoint,
            self.datacenter,
            self.admin_partition,
            self.namespace,
            self.service,
            self.project,
            self.mission,
            self.work_product,
            self.permissions,
        )?
        .with_consent(self.consent)?;
        if let Some(tag) = self.tag {
            scope = scope.with_tag(tag)?;
        }
        if let Some(node) = self.node {
            scope = scope.with_node(node)?;
        }
        if let Some(service_instance) = self.service_instance {
            scope = scope.with_service_instance(service_instance)?;
        }
        if let Some(check) = self.check {
            scope = scope.with_check(check)?;
        }
        Ok(scope)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadBounds {
    pub max_instances: usize,
    pub max_checks_per_instance: usize,
    pub max_tags_per_instance: usize,
    pub max_response_bytes: usize,
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            max_instances: HARD_MAX_INSTANCES,
            max_checks_per_instance: HARD_MAX_CHECKS_PER_INSTANCE,
            max_tags_per_instance: HARD_MAX_TAGS_PER_INSTANCE,
            max_response_bytes: HARD_MAX_RESPONSE_BYTES,
        }
    }
}

impl ReadBounds {
    pub fn new(
        max_instances: usize,
        max_checks_per_instance: usize,
        max_tags_per_instance: usize,
        max_response_bytes: usize,
    ) -> Result<Self, ModelError> {
        let bounds = Self {
            max_instances,
            max_checks_per_instance,
            max_tags_per_instance,
            max_response_bytes,
        };
        bounds.validate()?;
        Ok(bounds)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if (1..=HARD_MAX_INSTANCES).contains(&self.max_instances)
            && (1..=HARD_MAX_CHECKS_PER_INSTANCE).contains(&self.max_checks_per_instance)
            && (1..=HARD_MAX_TAGS_PER_INSTANCE).contains(&self.max_tags_per_instance)
            && (1..=HARD_MAX_RESPONSE_BYTES).contains(&self.max_response_bytes)
        {
            Ok(())
        } else {
            Err(ModelError::BoundExceeded)
        }
    }
}

/// An ACL-token handle is intentionally opaque and is not serializable.  The
/// raw reference is hashed and zeroized immediately; it is never retained.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        reference: impl Into<String>,
        scope: &ConsulServiceHealthScope,
        credential_revision: Revision,
    ) -> Result<Self, ModelError> {
        let mut reference = reference.into();
        if !valid_opaque_input(&reference) {
            reference.zeroize();
            return Err(ModelError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "consul-acl-secret-reference/v1",
            &[reference.as_str(), scope.scope_digest().as_str()],
        );
        reference.zeroize();
        Ok(Self {
            reference_digest,
            scope_digest: scope.scope_digest().clone(),
            credential_revision,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn validate_for_scope(&self, scope: &ConsulServiceHealthScope) -> Result<(), ModelError> {
        if !self.revoked && self.scope_digest == *scope.scope_digest() {
            Ok(())
        } else {
            Err(ModelError::SecretScopeMismatch)
        }
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum CheckStatus {
    #[serde(rename = "PASSING")]
    Passing,
    #[serde(rename = "WARNING")]
    Warning,
    #[serde(rename = "CRITICAL")]
    Critical,
    #[serde(rename = "MAINTENANCE")]
    Maintenance,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

impl CheckStatus {
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "PASSING" => Self::Passing,
            "WARNING" => Self::Warning,
            "CRITICAL" => Self::Critical,
            "MAINTENANCE" => Self::Maintenance,
            _ => Self::Unknown,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passing => "PASSING",
            Self::Warning => "WARNING",
            Self::Critical => "CRITICAL",
            Self::Maintenance => "MAINTENANCE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum EvidenceStatus {
    #[serde(rename = "PASSING")]
    Passing,
    #[serde(rename = "WARNING")]
    Warning,
    #[serde(rename = "CRITICAL")]
    Critical,
    #[serde(rename = "MAINTENANCE")]
    Maintenance,
    #[serde(rename = "EMPTY")]
    Empty,
    #[serde(rename = "ACL_FILTERED")]
    AclFiltered,
    #[serde(rename = "PARTIAL")]
    Partial,
    #[serde(rename = "ACCESS_LOST")]
    AccessLost,
    #[serde(rename = "PROVIDER_UNKNOWN")]
    ProviderUnknown,
    #[serde(rename = "TAMPERED")]
    Tampered,
    #[serde(rename = "REPLAY")]
    Replay,
    #[serde(rename = "REVOKED")]
    Revoked,
}

impl EvidenceStatus {
    pub const fn is_review_complete(self) -> bool {
        matches!(
            self,
            Self::Passing | Self::Warning | Self::Critical | Self::Maintenance | Self::Empty
        )
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passing => "PASSING",
            Self::Warning => "WARNING",
            Self::Critical => "CRITICAL",
            Self::Maintenance => "MAINTENANCE",
            Self::Empty => "EMPTY",
            Self::AclFiltered => "ACL_FILTERED",
            Self::Partial => "PARTIAL",
            Self::AccessLost => "ACCESS_LOST",
            Self::ProviderUnknown => "PROVIDER_UNKNOWN",
            Self::Tampered => "TAMPERED",
            Self::Replay => "REPLAY",
            Self::Revoked => "REVOKED",
        }
    }
}

pub(crate) fn status_from_checks(checks: impl IntoIterator<Item = CheckStatus>) -> EvidenceStatus {
    let mut saw_check = false;
    let mut strongest = EvidenceStatus::Passing;
    for status in checks {
        saw_check = true;
        let candidate = match status {
            CheckStatus::Critical => EvidenceStatus::Critical,
            CheckStatus::Maintenance => EvidenceStatus::Maintenance,
            CheckStatus::Warning => EvidenceStatus::Warning,
            CheckStatus::Passing => EvidenceStatus::Passing,
            CheckStatus::Unknown => EvidenceStatus::Partial,
        };
        strongest = stronger_status(strongest, candidate);
    }
    if saw_check {
        strongest
    } else {
        EvidenceStatus::Passing
    }
}

fn stronger_status(left: EvidenceStatus, right: EvidenceStatus) -> EvidenceStatus {
    let rank = |status| match status {
        EvidenceStatus::Critical => 5,
        EvidenceStatus::Maintenance => 4,
        EvidenceStatus::Warning => 3,
        EvidenceStatus::Passing => 2,
        EvidenceStatus::Partial => 1,
        _ => 0,
    };
    if rank(right) > rank(left) {
        right
    } else {
        left
    }
}

pub(crate) fn identity_digest(domain: &str, values: &[String]) -> Digest {
    Digest::from_fields(domain, values)
}

pub(crate) fn api_binding_digest() -> Digest {
    Digest::from_parts(
        "consul-api-binding/v1",
        &[
            CONSUL_HEALTH_PROVIDER_ID,
            CONSUL_API_VERSION,
            CONSUL_API_REVISION,
        ],
    )
}
