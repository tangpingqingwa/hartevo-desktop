use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use url::Url;

use crate::error::CloudRunDeploymentResultError;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_IMAGE_BYTES: usize = 1_024;
pub const MAX_URI_BYTES: usize = 2_048;
pub const MAX_PAGE_TOKEN_BYTES: usize = 512;
pub const MAX_REVISION_PAGES: usize = 8;
pub const MAX_REVISIONS: usize = 128;
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// A lowercase hexadecimal SHA-256 digest used for all durable fences.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn new(value: impl Into<String>) -> Result<Self, CloudRunDeploymentResultError> {
        let digest = Self(value.into().to_ascii_lowercase());
        digest.validate()?;
        Ok(digest)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("Cloud Run contract values serialize");
        Self::from_bytes(&bytes)
    }

    pub fn pending() -> Self {
        Self::from_bytes(b"pending-cloud-run-deployment-result-digest")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        if self.0.len() == 64 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(())
        } else {
            Err(CloudRunDeploymentResultError::InvalidDigest)
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
        formatter.write_str(&self.0)
    }
}

impl FromStr for Digest {
    type Err = CloudRunDeploymentResultError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

macro_rules! identifier_type {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, CloudRunDeploymentResultError> {
                let value = value.into();
                validate_identifier(&value, $kind)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
                validate_identifier(&self.0, $kind)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = CloudRunDeploymentResultError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier_type!(GoogleProjectId, "Google project");
identifier_type!(CloudRunLocation, "Cloud Run location");
identifier_type!(CloudRunServiceName, "Cloud Run service");
identifier_type!(CloudRunRevisionName, "Cloud Run revision");
identifier_type!(HartevoProjectId, "Hartevo project");
identifier_type!(MissionId, "Mission");
identifier_type!(WorkProductId, "Work Product");
identifier_type!(ServiceUid, "Cloud Run service UID");
identifier_type!(RevisionUid, "Cloud Run revision UID");

fn validate_identifier(
    value: &str,
    kind: &'static str,
) -> Result<(), CloudRunDeploymentResultError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
        || value
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'%'))
    {
        Err(CloudRunDeploymentResultError::InvalidIdentifier { kind })
    } else {
        Ok(())
    }
}

fn validate_bounded_text(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<(), CloudRunDeploymentResultError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(CloudRunDeploymentResultError::InvalidInput {
            field,
            reason: "must be bounded, non-empty, and free of control characters",
        })
    } else {
        Ok(())
    }
}

fn validate_timestamp(value: &str) -> Result<(), CloudRunDeploymentResultError> {
    validate_bounded_text(value, "observed timestamp", 64)
}

/// Exact container source identity. The image is immutable-looking repository
/// syntax without a mutable tag; the digest is the authoritative revision.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunSource {
    pub image: String,
    pub image_digest: Digest,
}

impl CloudRunSource {
    pub fn new(
        image: impl Into<String>,
        image_digest: Digest,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        let source = Self {
            image: image.into(),
            image_digest,
        };
        source.validate()?;
        Ok(source)
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        validate_bounded_text(&self.image, "source image", MAX_IMAGE_BYTES)?;
        let last_component = self.image.rsplit('/').next().unwrap_or_default();
        if self.image.contains('@')
            || last_component.contains(':')
            || self.image.starts_with(['/', '.'])
        {
            return Err(CloudRunDeploymentResultError::InvalidInput {
                field: "source image",
                reason: "must be a bounded repository without a mutable tag or digest suffix",
            });
        }
        self.image_digest.validate()
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// One exact Cloud Run traffic allocation. Percentages and tags are metadata;
/// no method in this crate can apply or mutate them.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunTrafficTarget {
    pub revision: CloudRunRevisionName,
    pub percent: u8,
    pub tag: Option<String>,
}

impl CloudRunTrafficTarget {
    pub fn new(
        revision: CloudRunRevisionName,
        percent: u8,
        tag: Option<String>,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        let target = Self {
            revision,
            percent,
            tag,
        };
        target.validate()?;
        Ok(target)
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        self.revision.validate()?;
        if let Some(tag) = &self.tag {
            validate_bounded_text(tag, "traffic tag", MAX_IDENTIFIER_BYTES)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunTrafficPlan {
    pub targets: Vec<CloudRunTrafficTarget>,
}

impl CloudRunTrafficPlan {
    pub fn new(
        mut targets: Vec<CloudRunTrafficTarget>,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        targets.sort();
        let plan = Self { targets };
        plan.validate()?;
        Ok(plan)
    }

    pub fn single(revision: CloudRunRevisionName) -> Result<Self, CloudRunDeploymentResultError> {
        Self::new(vec![CloudRunTrafficTarget::new(revision, 100, None)?])
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        if self.targets.is_empty() || self.targets.len() > 32 {
            return Err(CloudRunDeploymentResultError::InvalidTraffic);
        }
        let mut seen = BTreeSet::new();
        let mut total = 0_u16;
        for target in &self.targets {
            target.validate()?;
            let key = (target.revision.clone(), target.tag.clone());
            if !seen.insert(key) {
                return Err(CloudRunDeploymentResultError::InvalidTraffic);
            }
            total = total.saturating_add(u16::from(target.percent));
        }
        if total > 100 {
            return Err(CloudRunDeploymentResultError::InvalidTraffic);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn exact_match(&self, other: &Self) -> bool {
        self == other
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudRunPermission {
    GetService,
    ListRevisions,
    GetRevision,
    ReadTraffic,
    GetIamPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunPermissionSnapshot {
    pub revision: String,
    pub permissions: BTreeSet<CloudRunPermission>,
    pub snapshot_digest: Digest,
}

/// Version carried by registration and provider-result fences.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn validate(self) -> Result<(), CloudRunDeploymentResultError> {
        if self.major == 0 {
            Err(CloudRunDeploymentResultError::InvalidInput {
                field: "plugin version",
                reason: "major version must be non-zero",
            })
        } else {
            Ok(())
        }
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl CloudRunPermissionSnapshot {
    pub fn new(
        revision: impl Into<String>,
        permissions: impl IntoIterator<Item = CloudRunPermission>,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        let mut snapshot = Self {
            revision: revision.into(),
            permissions: permissions.into_iter().collect(),
            snapshot_digest: Digest::pending(),
        };
        snapshot.validate_without_digest()?;
        snapshot.snapshot_digest = snapshot.computed_digest();
        Ok(snapshot)
    }

    pub fn read_only_default(
        revision: impl Into<String>,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        Self::new(
            revision,
            [
                CloudRunPermission::GetService,
                CloudRunPermission::ListRevisions,
                CloudRunPermission::GetRevision,
                CloudRunPermission::ReadTraffic,
                CloudRunPermission::GetIamPolicy,
            ],
        )
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        self.validate_without_digest()?;
        if self.snapshot_digest != self.computed_digest() {
            return Err(CloudRunDeploymentResultError::PermissionDrift);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.snapshot_digest
    }

    fn validate_without_digest(&self) -> Result<(), CloudRunDeploymentResultError> {
        validate_bounded_text(&self.revision, "permission snapshot revision", 128)?;
        if self.permissions.is_empty() {
            Err(CloudRunDeploymentResultError::PermissionDrift)
        } else {
            Ok(())
        }
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&(&self.revision, &self.permissions))
    }
}

/// Exact Google Cloud Run resource plus Mission and Work Product scope.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunScope {
    pub google_project_id: GoogleProjectId,
    pub location: CloudRunLocation,
    pub service_name: CloudRunServiceName,
    pub revision_name: CloudRunRevisionName,
    pub source: CloudRunSource,
    pub traffic: CloudRunTrafficPlan,
    pub generation: u64,
    pub hartevo_project_id: HartevoProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub permission_snapshot: CloudRunPermissionSnapshot,
}

impl CloudRunScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        google_project_id: GoogleProjectId,
        location: CloudRunLocation,
        service_name: CloudRunServiceName,
        revision_name: CloudRunRevisionName,
        source: CloudRunSource,
        traffic: CloudRunTrafficPlan,
        generation: u64,
        hartevo_project_id: HartevoProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        mission_revision: u64,
        work_product_revision: u64,
        permission_snapshot: CloudRunPermissionSnapshot,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        let scope = Self {
            google_project_id,
            location,
            service_name,
            revision_name,
            source,
            traffic,
            generation,
            hartevo_project_id,
            mission_id,
            work_product_id,
            mission_revision,
            work_product_revision,
            permission_snapshot,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        self.google_project_id.validate()?;
        self.location.validate()?;
        self.service_name.validate()?;
        self.revision_name.validate()?;
        self.source.validate()?;
        self.traffic.validate()?;
        self.hartevo_project_id.validate()?;
        self.mission_id.validate()?;
        self.work_product_id.validate()?;
        self.permission_snapshot.validate()?;
        if self.generation == 0 || self.mission_revision == 0 || self.work_product_revision == 0 {
            return Err(CloudRunDeploymentResultError::InvalidInput {
                field: "Cloud Run scope revisions",
                reason: "generation and Mission/Work Product revisions must be non-zero",
            });
        }
        if !self
            .traffic
            .targets
            .iter()
            .any(|target| target.revision == self.revision_name && target.percent > 0)
        {
            return Err(CloudRunDeploymentResultError::InvalidTraffic);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn project(&self) -> &GoogleProjectId {
        &self.google_project_id
    }

    pub fn service(&self) -> &CloudRunServiceName {
        &self.service_name
    }

    pub fn revision(&self) -> &CloudRunRevisionName {
        &self.revision_name
    }

    pub fn same_mission_scope(&self, other: &Self) -> bool {
        self.hartevo_project_id == other.hartevo_project_id
            && self.mission_id == other.mission_id
            && self.work_product_id == other.work_product_id
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudRunAuthMethod {
    GoogleOAuth,
    GoogleServiceAccount,
}

/// Opaque host-held Google credential identity.  The caller-supplied
/// reference is hashed immediately; no OAuth token, refresh token, service
/// account JSON, private key, or environment value is stored or serialized.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    pub reference_digest: Digest,
    pub scope_digest: Digest,
    pub credential_revision: u64,
    pub auth_method: CloudRunAuthMethod,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("auth_method", &self.auth_method)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl AsRef<str>,
        scope: &CloudRunScope,
        credential_revision: u64,
        auth_method: CloudRunAuthMethod,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        scope.validate()?;
        let reference_id = reference_id.as_ref();
        validate_bounded_text(reference_id, "secret reference", MAX_IDENTIFIER_BYTES)?;
        if reference_id.chars().any(char::is_whitespace) || credential_revision == 0 {
            return Err(CloudRunDeploymentResultError::InvalidInput {
                field: "secret reference",
                reason: "must be bounded, whitespace-free, and have a non-zero revision",
            });
        }
        Self::for_scope(
            reference_id,
            scope.digest(),
            credential_revision,
            auth_method,
        )
    }

    pub fn for_scope(
        reference_id: impl AsRef<str>,
        scope_digest: Digest,
        credential_revision: u64,
        auth_method: CloudRunAuthMethod,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        let reference_id = reference_id.as_ref();
        validate_bounded_text(reference_id, "secret reference", MAX_IDENTIFIER_BYTES)?;
        if reference_id.chars().any(char::is_whitespace) || credential_revision == 0 {
            return Err(CloudRunDeploymentResultError::InvalidInput {
                field: "secret reference",
                reason: "must be bounded, whitespace-free, and have a non-zero revision",
            });
        }
        scope_digest.validate()?;
        Ok(Self {
            reference_digest: Digest::from_bytes(reference_id.as_bytes()),
            scope_digest,
            credential_revision,
            auth_method,
        })
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        self.reference_digest.validate()?;
        self.scope_digest.validate()?;
        if self.credential_revision == 0 {
            return Err(CloudRunDeploymentResultError::InvalidInput {
                field: "credential revision",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }

    pub fn validate_for_scope(
        &self,
        scope: &CloudRunScope,
    ) -> Result<(), CloudRunDeploymentResultError> {
        self.validate()?;
        if self.scope_digest != scope.digest() {
            return Err(CloudRunDeploymentResultError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeStatus {
    BlockedEnv,
}

impl NativeStatus {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    OfficialHttps,
    Recording,
    Fake,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        matches!(self, Self::OfficialHttps)
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudRunCapability {
    DescribeService,
    ReadServiceIam,
    BoundedRevisionList,
    ReadTrafficStatus,
    ReadinessEvidence,
    DeploymentResultProposal,
    ReceiptRecording,
    ResultFingerprintVerification,
    ReversibleRegistration,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunCapabilitySnapshot {
    pub capabilities: BTreeSet<CloudRunCapability>,
    pub read_only: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub native_status: NativeStatus,
}

impl CloudRunCapabilitySnapshot {
    pub fn layer1() -> Self {
        Self {
            capabilities: BTreeSet::from([
                CloudRunCapability::DescribeService,
                CloudRunCapability::ReadServiceIam,
                CloudRunCapability::BoundedRevisionList,
                CloudRunCapability::ReadTrafficStatus,
                CloudRunCapability::ReadinessEvidence,
                CloudRunCapability::DeploymentResultProposal,
                CloudRunCapability::ReceiptRecording,
                CloudRunCapability::ResultFingerprintVerification,
                CloudRunCapability::ReversibleRegistration,
            ]),
            read_only: true,
            external_writes: false,
            kernel_authority: false,
            native_status: NativeStatus::BlockedEnv,
        }
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        if *self == Self::layer1() {
            Ok(())
        } else {
            Err(CloudRunDeploymentResultError::InvalidRegistration)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunRegistration {
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub service_id: String,
    pub adapter_revision: u64,
    pub capability_snapshot: CloudRunCapabilitySnapshot,
    pub permission_snapshot_digest: Digest,
    pub scope: CloudRunScope,
    pub scope_digest: Digest,
    pub secret_reference: SecretReference,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
}

impl CloudRunRegistration {
    pub fn new(
        scope: CloudRunScope,
        secret_reference: SecretReference,
        adapter_revision: u64,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        let mut registration = Self {
            plugin_id: crate::PLUGIN_ID.to_owned(),
            plugin_version: crate::PLUGIN_VERSION,
            contract_version: crate::CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: crate::PROVIDER_ID.to_owned(),
            provider_version: crate::PROVIDER_VERSION,
            service_id: crate::SERVICE_ID.to_owned(),
            adapter_revision,
            capability_snapshot: CloudRunCapabilitySnapshot::layer1(),
            permission_snapshot_digest: scope.permission_snapshot.digest().clone(),
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision: 1,
            status: RegistrationStatus::Active,
            registration_digest: Digest::pending(),
        };
        registration.registration_digest = registration.computed_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        if self.plugin_id != crate::PLUGIN_ID
            || self.plugin_version != crate::PLUGIN_VERSION
            || self.contract_version != crate::CONTRACT_VERSION
            || self.provider_id != crate::PROVIDER_ID
            || self.provider_version != crate::PROVIDER_VERSION
            || self.service_id != crate::SERVICE_ID
            || self.adapter_revision == 0
            || self.registration_revision == 0
        {
            return Err(CloudRunDeploymentResultError::InvalidRegistration);
        }
        self.plugin_version.validate()?;
        self.provider_version.validate()?;
        self.contract_digest.validate()?;
        self.capability_snapshot.validate()?;
        self.scope.validate()?;
        self.scope_digest.validate()?;
        self.permission_snapshot_digest.validate()?;
        self.secret_reference.validate_for_scope(&self.scope)?;
        if self.contract_digest != crate::contract_digest()
            || self.scope_digest != self.scope.digest()
            || self.permission_snapshot_digest != self.scope.permission_snapshot.digest().clone()
            || self.registration_digest != self.computed_digest()
        {
            return Err(CloudRunDeploymentResultError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.registration_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, CloudRunDeploymentResultError> {
        self.validate()?;
        if self.status != RegistrationStatus::Active {
            return Err(CloudRunDeploymentResultError::RegistrationRevoked);
        }
        let previous_digest = self.registration_digest.clone();
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(CloudRunDeploymentResultError::InvalidRegistration)?;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.computed_digest();
        Ok(RegistrationRevocation {
            previous_digest,
            revoked_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: true,
        })
    }

    pub fn reissue(
        &self,
        scope: CloudRunScope,
        secret_reference: SecretReference,
        adapter_revision: u64,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        Self::new(scope, secret_reference, adapter_revision)
    }
}

pub type CloudRunPluginRegistration = CloudRunRegistration;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub previous_digest: Digest,
    pub revoked_digest: Digest,
    pub registration_revision: u64,
    pub reversible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionWorkProductBinding {
    pub hartevo_project_id: HartevoProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub mission_revision: u64,
    pub work_product_revision: u64,
}

impl MissionWorkProductBinding {
    pub fn new(
        scope: &CloudRunScope,
        mission_revision: u64,
        work_product_revision: u64,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        let binding = Self {
            hartevo_project_id: scope.hartevo_project_id.clone(),
            mission_id: scope.mission_id.clone(),
            work_product_id: scope.work_product_id.clone(),
            mission_revision,
            work_product_revision,
        };
        binding.validate_for(scope)?;
        Ok(binding)
    }

    pub fn validate_for(&self, scope: &CloudRunScope) -> Result<(), CloudRunDeploymentResultError> {
        if self.hartevo_project_id != scope.hartevo_project_id
            || self.mission_id != scope.mission_id
            || self.work_product_id != scope.work_product_id
            || self.mission_revision == 0
            || self.work_product_revision == 0
        {
            Err(CloudRunDeploymentResultError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudRunReadiness {
    Ready,
    Reconciling,
    Failed,
    Partial,
    Deleted,
    AccessLost,
    Unknown,
}

impl CloudRunReadiness {
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudRunResultState {
    Reconciling,
    Ready,
    Failed,
    TrafficDrift,
    Partial,
    Deleted,
    AccessLost,
    ProviderUnknown,
}

impl CloudRunResultState {
    pub const fn is_adoptable(self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunUriMetadata {
    pub scheme: String,
    pub host_digest: Digest,
    pub path_digest: Digest,
}

impl CloudRunUriMetadata {
    pub fn from_uri(uri: impl AsRef<str>) -> Result<Self, CloudRunDeploymentResultError> {
        let uri = uri.as_ref();
        validate_bounded_text(uri, "Cloud Run URI", MAX_URI_BYTES)?;
        let parsed = Url::parse(uri).map_err(|_| CloudRunDeploymentResultError::InvalidInput {
            field: "Cloud Run URI",
            reason: "must be a valid HTTPS URI",
        })?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(CloudRunDeploymentResultError::InvalidInput {
                field: "Cloud Run URI",
                reason: "must be HTTPS without credentials, query, or fragment",
            });
        }
        Ok(Self {
            scheme: parsed.scheme().to_owned(),
            host_digest: Digest::from_bytes(parsed.host_str().unwrap_or_default().as_bytes()),
            path_digest: Digest::from_bytes(parsed.path().as_bytes()),
        })
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        if self.scheme != "https" {
            return Err(CloudRunDeploymentResultError::InvalidInput {
                field: "Cloud Run URI scheme",
                reason: "must be HTTPS",
            });
        }
        self.host_digest.validate()?;
        self.path_digest.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunIamRecord {
    pub policy_digest: Digest,
    pub binding_count: u32,
    pub readable: bool,
}

impl CloudRunIamRecord {
    pub fn new(
        policy_digest: Digest,
        binding_count: u32,
        readable: bool,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        let record = Self {
            policy_digest,
            binding_count,
            readable,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        self.policy_digest.validate()
    }
}

/// Bounded typed projection of a Cloud Run service response. It contains no
/// raw JSON, logs, IAM principals, secret values, or unbounded annotations.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunServiceRecord {
    pub google_project_id: GoogleProjectId,
    pub location: CloudRunLocation,
    pub service_name: CloudRunServiceName,
    pub service_uid: ServiceUid,
    pub generation: u64,
    pub observed_generation: u64,
    pub revision_name: CloudRunRevisionName,
    pub source: CloudRunSource,
    pub traffic: CloudRunTrafficPlan,
    pub readiness: CloudRunReadiness,
    pub iam: CloudRunIamRecord,
    pub uri_metadata: Option<CloudRunUriMetadata>,
    pub request_id: Option<String>,
    pub deleted: bool,
    pub access_lost: bool,
}

impl CloudRunServiceRecord {
    pub fn validate_for(&self, scope: &CloudRunScope) -> Result<(), CloudRunDeploymentResultError> {
        self.google_project_id.validate()?;
        self.location.validate()?;
        self.service_name.validate()?;
        self.service_uid.validate()?;
        self.revision_name.validate()?;
        self.source.validate()?;
        self.traffic.validate()?;
        self.iam.validate()?;
        if let Some(uri) = &self.uri_metadata {
            uri.validate()?;
        }
        if let Some(request_id) = &self.request_id {
            validate_bounded_text(request_id, "provider request identifier", 256)?;
        }
        if self.google_project_id != scope.google_project_id
            || self.location != scope.location
            || self.service_name != scope.service_name
        {
            return Err(CloudRunDeploymentResultError::ScopeMismatch);
        }
        if self.generation == 0 || self.observed_generation == 0 {
            return Err(CloudRunDeploymentResultError::InvalidEvidence);
        }
        Ok(())
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunServiceDescription {
    pub scope: CloudRunScope,
    pub service_uid: ServiceUid,
    pub generation: u64,
    pub observed_generation: u64,
    pub readiness: CloudRunReadiness,
    pub iam_policy_digest: Digest,
    pub uri_metadata: Option<CloudRunUriMetadata>,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub read_digest: Digest,
}

impl CloudRunServiceDescription {
    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.read_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        self.scope.validate()?;
        self.service_uid.validate()?;
        self.iam_policy_digest.validate()?;
        if let Some(uri) = &self.uri_metadata {
            uri.validate()?;
        }
        if self.generation == 0
            || self.observed_generation == 0
            || self.native_connected
            || self.provenance.is_connected()
            || self.read_digest != self.computed_digest()
        {
            return Err(CloudRunDeploymentResultError::InvalidEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunRevisionRecord {
    pub revision_name: CloudRunRevisionName,
    pub revision_uid: RevisionUid,
    pub generation: u64,
    pub observed_generation: u64,
    pub source: CloudRunSource,
    pub readiness: CloudRunReadiness,
    pub condition_digest: Digest,
}

impl CloudRunRevisionRecord {
    pub fn unavailable_for(scope: &CloudRunScope) -> Result<Self, CloudRunDeploymentResultError> {
        Ok(Self {
            revision_name: scope.revision_name.clone(),
            revision_uid: RevisionUid::new("unavailable")?,
            generation: scope.generation,
            observed_generation: scope.generation,
            source: scope.source.clone(),
            readiness: CloudRunReadiness::Unknown,
            condition_digest: Digest::from_bytes(b"cloud-run-revision-unavailable"),
        })
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        self.revision_name.validate()?;
        self.revision_uid.validate()?;
        self.source.validate()?;
        self.condition_digest.validate()?;
        if self.generation == 0 || self.observed_generation == 0 {
            return Err(CloudRunDeploymentResultError::InvalidEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunRevisionPage {
    pub revisions: Vec<CloudRunRevisionRecord>,
    pub next_page_token: Option<String>,
}

impl CloudRunRevisionPage {
    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        if self.revisions.len() > MAX_REVISIONS {
            return Err(CloudRunDeploymentResultError::PaginationBoundExceeded);
        }
        if let Some(token) = &self.next_page_token {
            validate_bounded_text(token, "revision page token", MAX_PAGE_TOKEN_BYTES)?;
        }
        for revision in &self.revisions {
            revision.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunReadRequest {
    pub scope: CloudRunScope,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub max_pages: usize,
    pub max_revisions: usize,
}

impl CloudRunReadRequest {
    pub fn new(
        scope: CloudRunScope,
        mission_revision: u64,
        work_product_revision: u64,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        let request = Self {
            scope,
            mission_revision,
            work_product_revision,
            max_pages: MAX_REVISION_PAGES,
            max_revisions: MAX_REVISIONS,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn with_bounds(
        mut self,
        max_pages: usize,
        max_revisions: usize,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        self.max_pages = max_pages;
        self.max_revisions = max_revisions;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        self.scope.validate()?;
        if self.mission_revision == 0
            || self.work_product_revision == 0
            || self.max_pages == 0
            || self.max_pages > MAX_REVISION_PAGES
            || self.max_revisions == 0
            || self.max_revisions > MAX_REVISIONS
        {
            return Err(CloudRunDeploymentResultError::InvalidInput {
                field: "Cloud Run read bounds",
                reason: "revisions and bounds must be non-zero and within Layer 1 limits",
            });
        }
        if self.mission_revision != self.scope.mission_revision {
            return Err(CloudRunDeploymentResultError::StaleMissionRevision);
        }
        if self.work_product_revision != self.scope.work_product_revision {
            return Err(CloudRunDeploymentResultError::StaleWorkProductRevision);
        }
        Ok(())
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunDeploymentEvidence {
    pub scope: CloudRunScope,
    pub registration_digest: Digest,
    pub service_uid: ServiceUid,
    pub service_generation: u64,
    pub observed_generation: u64,
    pub revision_name: CloudRunRevisionName,
    pub revision_uid: RevisionUid,
    pub source: CloudRunSource,
    pub traffic: CloudRunTrafficPlan,
    pub readiness: CloudRunReadiness,
    pub state: CloudRunResultState,
    pub iam_policy_digest: Digest,
    pub uri_metadata: Option<CloudRunUriMetadata>,
    pub revision_count: usize,
    pub page_count: usize,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub truncated: bool,
    pub observed_at: String,
    pub evidence_digest: Digest,
}

impl CloudRunDeploymentEvidence {
    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.evidence_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn validate(&self) -> Result<(), CloudRunDeploymentResultError> {
        self.scope.validate()?;
        self.registration_digest.validate()?;
        self.service_uid.validate()?;
        self.revision_name.validate()?;
        self.revision_uid.validate()?;
        self.source.validate()?;
        self.traffic.validate()?;
        self.iam_policy_digest.validate()?;
        if let Some(uri) = &self.uri_metadata {
            uri.validate()?;
        }
        validate_timestamp(&self.observed_at)?;
        if self.service_generation == 0
            || self.observed_generation == 0
            || self.revision_count == 0
            || self.revision_count > MAX_REVISIONS
            || self.page_count == 0
            || self.page_count > MAX_REVISION_PAGES
            || self.native_connected
            || self.provenance.is_connected()
            || self.truncated
            || self.evidence_digest != self.computed_digest()
        {
            return Err(if self.truncated {
                CloudRunDeploymentResultError::TruncatedEvidence
            } else {
                CloudRunDeploymentResultError::InvalidEvidence
            });
        }
        if self.revision_name != self.scope.revision_name
            || self.source != self.scope.source
            || self.service_generation != self.scope.generation
            || (self.traffic != self.scope.traffic
                && self.state != CloudRunResultState::TrafficDrift)
        {
            return Err(CloudRunDeploymentResultError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn is_adoptable(&self) -> bool {
        self.state.is_adoptable()
            && self.readiness.is_ready()
            && self.observed_generation == self.scope.generation
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunDeploymentResultProposal {
    pub result_id: String,
    pub result_digest: Digest,
    pub scope: CloudRunScope,
    pub binding: MissionWorkProductBinding,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub service_uid: ServiceUid,
    pub revision_uid: RevisionUid,
    pub source: CloudRunSource,
    pub traffic: CloudRunTrafficPlan,
    pub observed_generation: u64,
    pub state: CloudRunResultState,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub external_effect_performed: bool,
    pub durable_adoption: bool,
    pub kernel_authority: bool,
    pub verification_status: ResultVerificationStatus,
}

impl CloudRunDeploymentResultProposal {
    pub fn from_evidence(
        evidence: &CloudRunDeploymentEvidence,
        registration_digest: Digest,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        evidence.validate()?;
        registration_digest.validate()?;
        if !evidence.is_adoptable() {
            return Err(CloudRunDeploymentResultError::InvalidEvidence);
        }
        let binding = MissionWorkProductBinding::new(
            &evidence.scope,
            evidence.scope.mission_revision,
            evidence.scope.work_product_revision,
        )?;
        let mut proposal = Self {
            result_id: format!(
                "cloud-run-result-{}",
                &evidence.evidence_digest.as_str()[..24]
            ),
            result_digest: Digest::pending(),
            scope: evidence.scope.clone(),
            binding,
            registration_digest,
            evidence_digest: evidence.evidence_digest.clone(),
            service_uid: evidence.service_uid.clone(),
            revision_uid: evidence.revision_uid.clone(),
            source: evidence.source.clone(),
            traffic: evidence.traffic.clone(),
            observed_generation: evidence.observed_generation,
            state: evidence.state,
            provenance: evidence.provenance,
            native_transport: evidence.native_transport,
            native_connected: false,
            external_effect_performed: false,
            durable_adoption: false,
            kernel_authority: false,
            verification_status: ResultVerificationStatus::ProviderFingerprintMatch,
        };
        proposal.result_digest = proposal.computed_digest();
        proposal.validate_for_registration(&proposal.registration_digest.clone())?;
        Ok(proposal)
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.result_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn validate_for_registration(
        &self,
        registration_digest: &Digest,
    ) -> Result<(), CloudRunDeploymentResultError> {
        self.scope.validate()?;
        self.binding.validate_for(&self.scope)?;
        self.registration_digest.validate()?;
        self.evidence_digest.validate()?;
        self.service_uid.validate()?;
        self.revision_uid.validate()?;
        self.source.validate()?;
        self.traffic.validate()?;
        if self.registration_digest != *registration_digest
            || self.state != CloudRunResultState::Ready
            || self.native_connected
            || self.external_effect_performed
            || self.durable_adoption
            || self.kernel_authority
            || self.verification_status != ResultVerificationStatus::ProviderFingerprintMatch
            || self.result_digest != self.computed_digest()
        {
            return Err(CloudRunDeploymentResultError::InvalidEvidence);
        }
        if self.observed_generation != self.scope.generation
            || self.source != self.scope.source
            || self.traffic != self.scope.traffic
        {
            return Err(CloudRunDeploymentResultError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultVerificationStatus {
    ProviderFingerprintMatch,
    NotVerified,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudRunDeploymentReceipt {
    pub scope: CloudRunScope,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub service_uid: ServiceUid,
    pub revision_uid: RevisionUid,
    pub observed_generation: u64,
    pub state: CloudRunResultState,
    pub provenance: ProviderProvenance,
    pub truncated: bool,
    pub receipt_digest: Digest,
}

impl CloudRunDeploymentReceipt {
    pub fn from_evidence(
        evidence: &CloudRunDeploymentEvidence,
        registration_digest: Digest,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        evidence.validate()?;
        let mut receipt = Self {
            scope: evidence.scope.clone(),
            registration_digest,
            evidence_digest: evidence.evidence_digest.clone(),
            service_uid: evidence.service_uid.clone(),
            revision_uid: evidence.revision_uid.clone(),
            observed_generation: evidence.observed_generation,
            state: evidence.state,
            provenance: evidence.provenance,
            truncated: false,
            receipt_digest: Digest::pending(),
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt.validate_against(evidence, &receipt.registration_digest.clone())?;
        Ok(receipt)
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.receipt_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn validate_against(
        &self,
        evidence: &CloudRunDeploymentEvidence,
        registration_digest: &Digest,
    ) -> Result<(), CloudRunDeploymentResultError> {
        evidence.validate()?;
        self.scope.validate()?;
        self.registration_digest.validate()?;
        self.evidence_digest.validate()?;
        self.receipt_digest.validate()?;
        if self.registration_digest != *registration_digest
            || self.scope != evidence.scope
            || self.evidence_digest != evidence.evidence_digest
            || self.service_uid != evidence.service_uid
            || self.revision_uid != evidence.revision_uid
            || self.observed_generation != evidence.observed_generation
            || self.state != evidence.state
            || self.truncated
            || self.receipt_digest != self.computed_digest()
        {
            return Err(CloudRunDeploymentResultError::ReceiptMismatch);
        }
        Ok(())
    }
}

pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_serializable(value)
}
