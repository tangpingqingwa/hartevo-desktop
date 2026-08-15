use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{DockerHubImageResultError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, MAX_IMAGES, MAX_LAYERS_PER_IMAGE,
    MAX_PLATFORM_TUPLES, MAX_RESPONSE_BYTES,
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
            Err(DockerHubImageResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(DockerHubImageResultError::InvalidDigest)
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

fn valid_component(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ImmutableDigest(String);

impl ImmutableDigest {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let valid = value.strip_prefix("sha256:").is_some_and(is_digest);
        if valid {
            Ok(Self(value))
        } else {
            Err(DockerHubImageResultError::InvalidImmutableDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn deterministic_digest(&self) -> Digest {
        Digest::from_parts(
            "dockerhub-immutable-digest/v1",
            &[("value", self.0.clone())],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for ImmutableDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ImmutableDigest")
            .field(&self.0)
            .finish()
    }
}

macro_rules! scope_text {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(DockerHubImageResultError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("dockerhub-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(DockerHubImageResultError::InvalidIdentifier { field: $field })
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
    };
}

scope_text!(DockerHubNamespace, "namespace", |value: &str| {
    valid_component(value, MAX_IDENTIFIER_BYTES)
});
scope_text!(DockerHubRepository, "repository", |value: &str| {
    valid_component(value, MAX_IDENTIFIER_BYTES)
});
scope_text!(DockerHubTag, "tag", |value: &str| {
    valid_text(value, 128, false)
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-') && index > 0
        })
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
});

macro_rules! revision_binding {
    ($name:ident, $domain:literal, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name {
            id: String,
            revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                let id = id.into();
                if !valid_component(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
                    return Err(DockerHubImageResultError::InvalidScope);
                }
                Ok(Self { id, revision })
            }

            pub fn id(&self) -> &str {
                &self.id
            }

            pub const fn revision(&self) -> u64 {
                self.revision
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        (
                            "id",
                            Digest::from_parts(
                                concat!("dockerhub-", $field, "-id/v1"),
                                &[("id", self.id.clone())],
                            )
                            .as_str()
                            .to_owned(),
                        ),
                        ("revision", self.revision.to_string()),
                    ],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if valid_component(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
                    Ok(())
                } else {
                    Err(DockerHubImageResultError::InvalidScope)
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &self.digest())
                    .field("revision", &self.revision)
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                let mut state = serializer.serialize_struct(stringify!($name), 2)?;
                state.serialize_field("idDigest", &self.digest())?;
                state.serialize_field("revision", &self.revision)?;
                state.end()
            }
        }
    };
}

revision_binding!(MissionBinding, "dockerhub-mission/v1", "mission");
revision_binding!(ProjectBinding, "dockerhub-project/v1", "project");
revision_binding!(
    WorkProductBinding,
    "dockerhub-work-product/v1",
    "work-product"
);

pub type MissionIdentity = MissionBinding;
pub type ProjectIdentity = ProjectBinding;
pub type WorkProductIdentity = WorkProductBinding;

#[derive(Clone, Eq, PartialOrd, Ord, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformTuple {
    os: String,
    architecture: String,
    variant: Option<String>,
}

impl PlatformTuple {
    pub fn new(
        os: impl Into<String>,
        architecture: impl Into<String>,
        variant: Option<impl Into<String>>,
    ) -> Result<Self> {
        let os = os.into();
        let architecture = architecture.into();
        let variant = variant.map(Into::into).filter(|value| !value.is_empty());
        if !valid_component(&os, 64)
            || !valid_component(&architecture, 64)
            || variant
                .as_deref()
                .is_some_and(|value| !valid_component(value, 64))
        {
            return Err(DockerHubImageResultError::InvalidPlatformScope);
        }
        Ok(Self {
            os,
            architecture,
            variant,
        })
    }

    pub fn os(&self) -> &str {
        &self.os
    }

    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    pub fn variant(&self) -> Option<&str> {
        self.variant.as_deref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "dockerhub-platform-tuple/v1",
            &[
                ("os", self.os.clone()),
                ("architecture", self.architecture.clone()),
                ("variant", self.variant.clone().unwrap_or_default()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        Self::new(
            self.os.clone(),
            self.architecture.clone(),
            self.variant.clone(),
        )
        .map(|_| ())
    }
}

impl fmt::Debug for PlatformTuple {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlatformTuple")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerHubPlatformScope {
    platforms: Vec<PlatformTuple>,
    scope_digest: Digest,
}

impl DockerHubPlatformScope {
    pub fn new(platforms: Vec<PlatformTuple>) -> Result<Self> {
        if platforms.len() > MAX_PLATFORM_TUPLES {
            return Err(DockerHubImageResultError::InvalidPlatformScope);
        }
        let mut seen = BTreeSet::new();
        for platform in &platforms {
            platform.validate()?;
            if !seen.insert(platform.clone()) {
                return Err(DockerHubImageResultError::InvalidPlatformScope);
            }
        }
        let scope_digest = Digest::from_parts(
            "dockerhub-platform-scope/v1",
            &[(
                "platforms",
                platforms
                    .iter()
                    .map(|platform| platform.digest().as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        );
        Ok(Self {
            platforms,
            scope_digest,
        })
    }

    pub fn any() -> Self {
        Self::new(Vec::new()).expect("empty platform scope is valid")
    }

    pub fn platforms(&self) -> &[PlatformTuple] {
        &self.platforms
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn allows(&self, platform: &PlatformTuple) -> bool {
        self.platforms.is_empty() || self.platforms.contains(platform)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        Self::new(self.platforms.clone()).map(|_| ())
    }
}

pub type PlatformScope = DockerHubPlatformScope;

#[derive(Clone, Eq, PartialEq)]
pub struct DockerHubImageResultScope {
    namespace: DockerHubNamespace,
    repository: DockerHubRepository,
    tag: DockerHubTag,
    expected_manifest_identity: Option<ImmutableDigest>,
    platform_scope: DockerHubPlatformScope,
    mission: MissionBinding,
    project: ProjectBinding,
    work_product: WorkProductBinding,
}

impl DockerHubImageResultScope {
    pub fn new(
        namespace: DockerHubNamespace,
        repository: DockerHubRepository,
        tag: DockerHubTag,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        platform_scope: DockerHubPlatformScope,
    ) -> Result<Self> {
        let scope = Self {
            namespace,
            repository,
            tag,
            expected_manifest_identity: None,
            platform_scope,
            mission,
            project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn exact(
        namespace: impl Into<String>,
        repository: impl Into<String>,
        tag: impl Into<String>,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        platforms: Vec<PlatformTuple>,
    ) -> Result<Self> {
        Self::new(
            DockerHubNamespace::new(namespace)?,
            DockerHubRepository::new(repository)?,
            DockerHubTag::new(tag)?,
            mission,
            project,
            work_product,
            DockerHubPlatformScope::new(platforms)?,
        )
    }

    pub fn with_manifest_identity(mut self, digest: ImmutableDigest) -> Result<Self> {
        digest.validate()?;
        self.expected_manifest_identity = Some(digest);
        self.validate()?;
        Ok(self)
    }

    pub fn with_manifest_digest(self, digest: ImmutableDigest) -> Result<Self> {
        self.with_manifest_identity(digest)
    }

    pub fn namespace(&self) -> &DockerHubNamespace {
        &self.namespace
    }

    pub fn repository(&self) -> &DockerHubRepository {
        &self.repository
    }

    pub fn tag(&self) -> &DockerHubTag {
        &self.tag
    }

    pub fn expected_manifest_identity(&self) -> Option<&ImmutableDigest> {
        self.expected_manifest_identity.as_ref()
    }

    pub fn expected_manifest_digest(&self) -> Option<&ImmutableDigest> {
        self.expected_manifest_identity()
    }

    pub fn platform_scope(&self) -> &DockerHubPlatformScope {
        &self.platform_scope
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "dockerhub-image-result-scope/v1",
            &[
                ("namespace", self.namespace.digest().as_str().to_owned()),
                ("repository", self.repository.digest().as_str().to_owned()),
                ("tag", self.tag.digest().as_str().to_owned()),
                (
                    "manifest",
                    self.expected_manifest_identity
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            value.deterministic_digest().as_str().to_owned()
                        }),
                ),
                (
                    "platforms",
                    self.platform_scope.digest().as_str().to_owned(),
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
        self.namespace.validate()?;
        self.repository.validate()?;
        self.tag.validate()?;
        self.expected_manifest_identity
            .as_ref()
            .map(ImmutableDigest::validate)
            .transpose()?;
        self.platform_scope.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }
}

impl fmt::Debug for DockerHubImageResultScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerHubImageResultScope")
            .field("digest", &self.digest())
            .field("namespace", &self.namespace)
            .field("repository", &self.repository)
            .field("tag", &self.tag)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    DockerHubBearer,
}

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
            return Err(DockerHubImageResultError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "dockerhub-opaque-secret-reference/v1",
            &[
                ("kind", "docker_hub_bearer".to_owned()),
                ("handle", handle.clone()),
                ("revision", revision.to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            kind: SecretKind::DockerHubBearer,
            reference_digest,
            scope_digest: Digest::from_text("unbound-dockerhub-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn dockerhub(
        opaque_handle: impl Into<String>,
        scope: &DockerHubImageResultScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.bind_scope(scope)?;
        Ok(reference)
    }

    pub fn for_dockerhub(
        opaque_handle: impl Into<String>,
        scope: &DockerHubImageResultScope,
        revision: u64,
    ) -> Result<Self> {
        Self::dockerhub(opaque_handle, scope, revision)
    }

    pub fn bind_scope(&mut self, scope: &DockerHubImageResultScope) -> Result<()> {
        scope.validate()?;
        self.scope_digest = scope.digest();
        self.reference_digest = Digest::from_parts(
            "dockerhub-opaque-secret-reference/v1",
            &[
                ("kind", "docker_hub_bearer".to_owned()),
                ("reference", self.reference_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        );
        Ok(())
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

    pub(crate) fn is_unbound(&self) -> bool {
        self.scope_digest.as_str() == Digest::from_text("unbound-dockerhub-secret-scope").as_str()
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate_against(&self, scope: &DockerHubImageResultScope) -> Result<()> {
        if self.scope_digest != scope.digest() {
            return Err(DockerHubImageResultError::ScopeMismatch);
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    permissions: Vec<String>,
    permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn layer1() -> Self {
        let permissions = LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<Vec<_>>();
        let permission_digest = Digest::from_parts(
            "dockerhub-permission-snapshot/v1",
            &[("permissions", permissions.join("\n"))],
        );
        Self {
            permissions,
            permission_digest,
        }
    }

    pub fn permissions(&self) -> &[String] {
        &self.permissions
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.permissions
            != LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect::<Vec<_>>()
            || self.permission_digest != *Self::layer1().digest()
        {
            return Err(DockerHubImageResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
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

    pub const fn provider_receipt(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DockerHubTagStatus {
    Active,
    Inactive,
    Unknown,
}

impl DockerHubTagStatus {
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "active" => Self::Active,
            "inactive" | "disabled" => Self::Inactive,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DockerHubEvidenceState {
    Ready,
    Partial,
    AccessLoss,
    Unauthorized,
    Forbidden,
    NotFound,
    Throttled,
    TimedOut,
    ConfigDrift,
    Tampered,
    ProviderUnknown,
    RegistrationRevoked,
}

impl DockerHubEvidenceState {
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReceipt {
    pub operation: String,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub scope_digest: Digest,
    pub redacted: bool,
}

impl RequestReceipt {
    pub fn new(
        operation: impl Into<String>,
        request_digest: Digest,
        path_digest: Digest,
        scope_digest: Digest,
    ) -> Result<Self> {
        let receipt = Self {
            operation: operation.into(),
            request_digest,
            path_digest,
            scope_digest,
            redacted: true,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.operation.is_empty() || !self.redacted {
            return Err(DockerHubImageResultError::TamperedEvidence);
        }
        self.request_digest.validate()?;
        self.path_digest.validate()?;
        self.scope_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostReceipt {
    pub operation: String,
    pub response_bytes: u64,
    pub bounded_request_units: u32,
    pub cost_digest: Digest,
    pub estimate_only: bool,
    pub durable_provider_receipt: bool,
}

impl CostReceipt {
    pub fn new(operation: impl Into<String>, response_bytes: u64) -> Result<Self> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(DockerHubImageResultError::PartialEvidence);
        }
        let operation = operation.into();
        let bounded_request_units = 1;
        let cost_digest = Digest::from_parts(
            "dockerhub-cost-receipt/v1",
            &[
                ("operation", operation.clone()),
                ("response_bytes", response_bytes.to_string()),
                ("units", bounded_request_units.to_string()),
            ],
        );
        Ok(Self {
            operation,
            response_bytes,
            bounded_request_units,
            cost_digest,
            estimate_only: true,
            durable_provider_receipt: false,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.response_bytes > MAX_RESPONSE_BYTES
            || !self.estimate_only
            || self.durable_provider_receipt
        {
            return Err(DockerHubImageResultError::TamperedEvidence);
        }
        self.cost_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerHubPlatformImage {
    pub immutable_digest: ImmutableDigest,
    pub platform: PlatformTuple,
    pub image_size_bytes: u64,
    pub layer_count: u16,
    pub layer_size_bytes: u64,
}

impl DockerHubPlatformImage {
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "dockerhub-platform-image/v1",
            &[
                (
                    "immutable_digest",
                    self.immutable_digest
                        .deterministic_digest()
                        .as_str()
                        .to_owned(),
                ),
                ("platform", self.platform.digest().as_str().to_owned()),
                ("image_size", self.image_size_bytes.to_string()),
                ("layer_count", self.layer_count.to_string()),
                ("layer_size", self.layer_size_bytes.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.immutable_digest.validate()?;
        self.platform.validate()?;
        if usize::from(self.layer_count) > MAX_LAYERS_PER_IMAGE {
            return Err(DockerHubImageResultError::PartialEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerHubImageResultProjection {
    pub tag_status: DockerHubTagStatus,
    pub last_updated: DateTime<Utc>,
    pub tag_manifest_identity: Option<ImmutableDigest>,
    pub images: Vec<DockerHubPlatformImage>,
    pub full_size_bytes: Option<u64>,
    pub image_count: u16,
    pub platform_count: u16,
    pub total_layer_count: u32,
    pub tag_digest: Digest,
    pub manifest_digest: Digest,
    pub platform_digest: Digest,
    pub projection_digest: Digest,
}

impl DockerHubImageResultProjection {
    pub fn new(
        tag_status: DockerHubTagStatus,
        last_updated: DateTime<Utc>,
        tag_manifest_identity: Option<ImmutableDigest>,
        mut images: Vec<DockerHubPlatformImage>,
        full_size_bytes: Option<u64>,
    ) -> Result<Self> {
        if images.len() > MAX_IMAGES {
            return Err(DockerHubImageResultError::PartialEvidence);
        }
        if let Some(identity) = tag_manifest_identity.as_ref() {
            identity.validate()?;
        }
        images.sort_by_key(|image| {
            (
                image.platform.clone(),
                image.immutable_digest.clone(),
                image.image_size_bytes,
            )
        });
        let mut platforms = BTreeSet::new();
        let mut total_layer_count = 0_u32;
        for image in &images {
            image.validate()?;
            if !platforms.insert(image.platform.clone()) {
                return Err(DockerHubImageResultError::InvalidResponse);
            }
            total_layer_count = total_layer_count
                .checked_add(u32::from(image.layer_count))
                .ok_or(DockerHubImageResultError::PartialEvidence)?;
        }
        let image_digests = images
            .iter()
            .map(|image| image.digest().as_str().to_owned())
            .collect::<Vec<_>>()
            .join("\n");
        let platform_digests = images
            .iter()
            .map(|image| image.platform.digest().as_str().to_owned())
            .collect::<Vec<_>>()
            .join("\n");
        let tag_digest = Digest::from_parts(
            "dockerhub-tag-projection/v1",
            &[
                ("status", format!("{tag_status:?}")),
                ("last_updated", last_updated.to_rfc3339()),
                (
                    "tag_manifest",
                    tag_manifest_identity
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            value.deterministic_digest().as_str().to_owned()
                        }),
                ),
                (
                    "full_size",
                    full_size_bytes.map_or_else(String::new, |v| v.to_string()),
                ),
                ("images", image_digests.clone()),
            ],
        );
        let manifest_digest = Digest::from_parts(
            "dockerhub-manifest-identities/v1",
            &[
                (
                    "tag_manifest",
                    tag_manifest_identity
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            value.deterministic_digest().as_str().to_owned()
                        }),
                ),
                ("images", image_digests),
            ],
        );
        let platform_digest = Digest::from_parts(
            "dockerhub-platform-projection/v1",
            &[("platforms", platform_digests)],
        );
        let projection_digest = Digest::from_parts(
            "dockerhub-image-result-projection/v1",
            &[
                ("tag", tag_digest.as_str().to_owned()),
                ("manifest", manifest_digest.as_str().to_owned()),
                ("platform", platform_digest.as_str().to_owned()),
                ("image_count", images.len().to_string()),
                ("platform_count", platforms.len().to_string()),
                ("total_layer_count", total_layer_count.to_string()),
            ],
        );
        let projection = Self {
            tag_status,
            last_updated,
            tag_manifest_identity,
            image_count: images.len() as u16,
            platform_count: platforms.len() as u16,
            total_layer_count,
            images,
            full_size_bytes,
            tag_digest,
            manifest_digest,
            platform_digest,
            projection_digest,
        };
        projection.validate()?;
        Ok(projection)
    }

    pub fn image_digests(&self) -> impl Iterator<Item = &ImmutableDigest> {
        self.images.iter().map(|image| &image.immutable_digest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.images.len() > MAX_IMAGES
            || self.image_count != self.images.len() as u16
            || self.platform_count != self.images.len() as u16
        {
            return Err(DockerHubImageResultError::TamperedEvidence);
        }
        for image in &self.images {
            image.validate()?;
        }
        self.tag_manifest_identity
            .as_ref()
            .map(ImmutableDigest::validate)
            .transpose()?;
        self.tag_digest.validate()?;
        self.manifest_digest.validate()?;
        self.platform_digest.validate()?;
        self.projection_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerHubImageResultRequest {
    observed_at: DateTime<Utc>,
    scope_digest: Digest,
    expected_provider_digest: Digest,
    expected_registration_digest: Digest,
    max_response_bytes: u64,
}

impl DockerHubImageResultRequest {
    pub(crate) fn bound(
        scope: &DockerHubImageResultScope,
        observed_at: DateTime<Utc>,
        provider_digest: Digest,
        registration_digest: Digest,
    ) -> Self {
        Self {
            observed_at,
            scope_digest: scope.digest(),
            expected_provider_digest: provider_digest,
            expected_registration_digest: registration_digest,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }

    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn expected_provider_digest(&self) -> &Digest {
        &self.expected_provider_digest
    }

    pub fn expected_registration_digest(&self) -> &Digest {
        &self.expected_registration_digest
    }

    pub const fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "dockerhub-image-result-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "provider",
                    self.expected_provider_digest.as_str().to_owned(),
                ),
                (
                    "registration",
                    self.expected_registration_digest.as_str().to_owned(),
                ),
                ("max_response_bytes", self.max_response_bytes.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(DockerHubImageResultError::InvalidRequest);
        }
        self.scope_digest.validate()?;
        self.expected_provider_digest.validate()?;
        self.expected_registration_digest.validate()?;
        Ok(())
    }
}
