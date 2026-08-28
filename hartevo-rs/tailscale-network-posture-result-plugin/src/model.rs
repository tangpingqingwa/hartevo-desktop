use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    MAX_ACL_RULES, MAX_DEVICES, MAX_GRANTS, MAX_IDENTIFIER_BYTES, MAX_REQUESTS_PER_MINUTE,
    MAX_RESPONSE_BYTES, MAX_RETRY_AFTER_SECONDS, MAX_TAGS,
};

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    sha256_digest(&serde_json::to_vec(value).expect("bounded Tailscale value serializes"))
}

#[must_use]
pub fn domain_digest<T: Serialize + ?Sized>(domain: &str, value: &T) -> Digest {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(
        &serde_json::to_vec(value).expect("bounded Tailscale domain value serializes"),
    );
    sha256_digest(&bytes)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{0} is empty, malformed, or exceeds the Layer-1 bound")]
    InvalidIdentifier(&'static str),
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("permission snapshot is not the fixed least-privilege read set")]
    InvalidPermissionSnapshot,
    #[error("consent scope is inactive or malformed")]
    InvalidConsent,
    #[error("Tailscale scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("Tailscale read request is outside the exact registered scope")]
    InvalidRequest,
    #[error("secret reference is invalid")]
    InvalidSecretReference,
    #[error("idempotency key is invalid")]
    InvalidIdempotencyKey,
    #[error("response is malformed or exceeds the Layer-1 bound")]
    InvalidResponse,
    #[error("rate-limit receipt is invalid")]
    InvalidRateLimitReceipt,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration or secret reference is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
    #[error("bounded count exceeds the Layer-1 limit")]
    CountExceeded,
}

fn validate_identifier(value: &str, label: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-$~".contains(&byte))
    {
        return Err(ModelError::InvalidIdentifier(label));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), ModelError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ModelError::InvalidDigest)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Identifier(String);

impl Identifier {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "identifier")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        domain_digest("hartevo:tailscale-network-posture:identifier:v1", &self.0)
    }

    fn validate(&self, label: &'static str) -> Result<(), ModelError> {
        validate_identifier(&self.0, label)
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Identifier")
            .field(&self.digest())
            .finish()
    }
}

impl Serialize for Identifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.digest())
    }
}

impl<'de> Deserialize<'de> for Identifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

pub type TailnetId = Identifier;
pub type DeviceId = Identifier;
pub type TagId = Identifier;
pub type PostureId = Identifier;
pub type AclPolicyId = Identifier;
pub type GrantId = Identifier;
pub type ProjectId = Identifier;
pub type MissionId = Identifier;
pub type WorkProductId = Identifier;

pub type TailscaleTailnetId = TailnetId;
pub type TailscaleDeviceId = DeviceId;
pub type TailscaleTagId = TagId;
pub type TailscalePostureId = PostureId;
pub type TailscaleAclPolicyId = AclPolicyId;
pub type TailscaleGrantId = GrantId;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub fn digest(self) -> Digest {
        domain_digest("hartevo:tailscale-network-posture:revision:v1", &self.0)
    }
}

impl From<u64> for Revision {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

macro_rules! scope_binding {
    ($name:ident, $id:ident, $label:literal, $domain:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub id: $id,
            pub revision: Revision,
        }

        impl $name {
            pub fn new(id: $id, revision: Revision) -> Result<Self, ModelError> {
                let binding = Self { id, revision };
                binding.validate()?;
                Ok(binding)
            }

            #[must_use]
            pub fn id(&self) -> &$id {
                &self.id
            }

            #[must_use]
            pub const fn revision(&self) -> Revision {
                self.revision
            }

            #[must_use]
            pub fn id_digest(&self) -> Digest {
                self.id.digest()
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                domain_digest($domain, &(&self.id, self.revision))
            }

            pub fn validate(&self) -> Result<(), ModelError> {
                self.id.validate($label)
            }
        }
    };
}

scope_binding!(
    TailnetScope,
    TailnetId,
    "tailnet_id",
    "hartevo:tailscale-network-posture:tailnet:v1"
);
scope_binding!(
    DeviceScope,
    DeviceId,
    "device_id",
    "hartevo:tailscale-network-posture:device:v1"
);
scope_binding!(
    TagScope,
    TagId,
    "tag_id",
    "hartevo:tailscale-network-posture:tag:v1"
);
scope_binding!(
    PostureScope,
    PostureId,
    "posture_id",
    "hartevo:tailscale-network-posture:posture:v1"
);
scope_binding!(
    AclScope,
    AclPolicyId,
    "acl_policy_id",
    "hartevo:tailscale-network-posture:acl-policy:v1"
);
scope_binding!(
    GrantScope,
    GrantId,
    "grant_id",
    "hartevo:tailscale-network-posture:grant:v1"
);
scope_binding!(
    ProjectScope,
    ProjectId,
    "project_id",
    "hartevo:tailscale-network-posture:project:v1"
);
scope_binding!(
    MissionScope,
    MissionId,
    "mission_id",
    "hartevo:tailscale-network-posture:mission:v1"
);
scope_binding!(
    WorkProductScope,
    WorkProductId,
    "work_product_id",
    "hartevo:tailscale-network-posture:work-product:v1"
);

pub type TailscaleTailnetScope = TailnetScope;
pub type TailscaleDeviceScope = DeviceScope;
pub type TailscaleTagScope = TagScope;
pub type TailscalePostureScope = PostureScope;
pub type TailscaleAclScope = AclScope;
pub type TailscaleGrantScope = GrantScope;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    pub id: Identifier,
    pub revision: Revision,
    pub active: bool,
}

impl ConsentScope {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self, ModelError> {
        let consent = Self {
            id: Identifier::new(id)?,
            revision,
            active: true,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.active {
            return Err(ModelError::InvalidConsent);
        }
        self.id.validate("consent_id")
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        domain_digest(
            "hartevo:tailscale-network-posture:consent:v1",
            &(&self.id, self.revision, self.active),
        )
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TailscalePermission {
    TailnetRead,
    DeviceRead,
    DevicePostureRead,
    TagRead,
    AclRead,
    GrantRead,
    MissionScope,
    WorkProductProposal,
}

impl TailscalePermission {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TailnetRead => "tailnet:read",
            Self::DeviceRead => "device:read",
            Self::DevicePostureRead => "device_posture:read",
            Self::TagRead => "tag:read",
            Self::AclRead => "acl:read",
            Self::GrantRead => "grant:read",
            Self::MissionScope => "mission.scope",
            Self::WorkProductProposal => "work_product.proposal",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    permissions: std::collections::BTreeSet<TailscalePermission>,
    permission_digest: Digest,
    pub revision: Revision,
}

impl PermissionSnapshot {
    pub fn layer_one(revision: Revision) -> Result<Self, ModelError> {
        Ok(Self::new(
            [
                TailscalePermission::TailnetRead,
                TailscalePermission::DeviceRead,
                TailscalePermission::DevicePostureRead,
                TailscalePermission::TagRead,
                TailscalePermission::AclRead,
                TailscalePermission::GrantRead,
                TailscalePermission::MissionScope,
                TailscalePermission::WorkProductProposal,
            ],
            revision,
        ))
    }

    #[must_use]
    pub fn new<I>(permissions: I, revision: Revision) -> Self
    where
        I: IntoIterator<Item = TailscalePermission>,
    {
        let permissions = permissions.into_iter().collect();
        let permission_digest = domain_digest(
            "hartevo:tailscale-network-posture:permissions:v1",
            &permissions,
        );
        Self {
            permissions,
            permission_digest,
            revision,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::layer_one(self.revision)?;
        if self.permissions != expected.permissions
            || self.permission_digest != expected.permission_digest
        {
            Err(ModelError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn permissions(&self) -> &std::collections::BTreeSet<TailscalePermission> {
        &self.permissions
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    #[must_use]
    pub fn allows(&self, permission: TailscalePermission) -> bool {
        self.permissions.contains(&permission)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TailscaleNetworkPostureScope {
    pub tailnet: TailnetScope,
    pub device: DeviceScope,
    pub tag: TagScope,
    pub posture: PostureScope,
    pub acl: AclScope,
    pub grant: GrantScope,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub permissions: PermissionSnapshot,
    pub consent: ConsentScope,
    pub scope_revision: Revision,
}

impl TailscaleNetworkPostureScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tailnet: TailnetScope,
        device: DeviceScope,
        tag: TagScope,
        posture: PostureScope,
        acl: AclScope,
        grant: GrantScope,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        permissions: PermissionSnapshot,
        consent: ConsentScope,
        scope_revision: Revision,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            tailnet,
            device,
            tag,
            posture,
            acl,
            grant,
            project,
            mission,
            work_product,
            permissions,
            consent,
            scope_revision,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.tailnet.validate()?;
        self.device.validate()?;
        self.tag.validate()?;
        self.posture.validate()?;
        self.acl.validate()?;
        self.grant.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        self.permissions.validate()?;
        self.consent.validate()?;
        if self.scope_revision.get() == 0 {
            return Err(ModelError::InvalidScope("scope_revision"));
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        domain_digest("hartevo:tailscale-network-posture:scope:v1", self)
    }

    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }

    #[must_use]
    pub fn device_digest(&self) -> Digest {
        self.device.digest()
    }

    #[must_use]
    pub fn posture_digest(&self) -> Digest {
        self.posture.digest()
    }

    #[must_use]
    pub fn policy_digest(&self) -> Digest {
        domain_digest(
            "hartevo:tailscale-network-posture:policy-scope:v1",
            &(&self.acl, &self.grant),
        )
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        self.permissions.digest()
    }

    #[must_use]
    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    #[must_use]
    pub fn revision_fence_digest(&self) -> Digest {
        domain_digest(
            "hartevo:tailscale-network-posture:revision-fence:v1",
            &(
                self.tailnet.revision,
                self.device.revision,
                self.tag.revision,
                self.posture.revision,
                self.acl.revision,
                self.grant.revision,
                self.project.revision,
                self.mission.revision,
                self.work_product.revision,
                self.permissions.revision,
                self.consent.revision,
                self.scope_revision,
            ),
        )
    }

    #[must_use]
    pub const fn scope_revision(&self) -> Revision {
        self.scope_revision
    }
}

pub type TailscaleScope = TailscaleNetworkPostureScope;

/// Opaque host-owned credential reference. The input is hashed immediately;
/// no API token, OAuth secret, keyring path, or other secret material is kept.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revision: self.revision,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.revision == other.revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SecretReference {
    pub fn for_scope(
        reference: impl AsRef<str>,
        scope: &TailscaleNetworkPostureScope,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        let reference = reference.as_ref();
        if reference.is_empty()
            || reference.len() > MAX_IDENTIFIER_BYTES * 2
            || reference.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidSecretReference);
        }
        Ok(Self {
            reference_digest: domain_digest(
                "hartevo:tailscale-network-posture:secret-reference:v1",
                &reference,
            ),
            scope_digest: scope.digest(),
            revision: scope.scope_revision,
            revoked: false,
        })
    }

    pub fn from_scope_digest(
        reference: impl AsRef<str>,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        validate_digest(&scope_digest)?;
        let reference = reference.as_ref();
        if reference.is_empty()
            || reference.len() > MAX_IDENTIFIER_BYTES * 2
            || reference.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidSecretReference);
        }
        Ok(Self {
            reference_digest: domain_digest(
                "hartevo:tailscale-network-posture:secret-reference:v1",
                &reference,
            ),
            scope_digest,
            revision,
            revoked: false,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.reference_digest.clone()
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if !self.revoked {
            Err(ModelError::NotRevoked)
        } else {
            self.revoked = false;
            Ok(())
        }
    }
}

/// Idempotency keys are also digest-only after construction.
pub struct IdempotencyKey {
    digest: Digest,
}

impl Clone for IdempotencyKey {
    fn clone(&self) -> Self {
        Self {
            digest: self.digest.clone(),
        }
    }
}

impl PartialEq for IdempotencyKey {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

impl Eq for IdempotencyKey {}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdempotencyKey")
            .field("digest", &self.digest)
            .finish()
    }
}

impl IdempotencyKey {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > MAX_IDENTIFIER_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidIdempotencyKey);
        }
        Ok(Self {
            digest: domain_digest("hartevo:tailscale-network-posture:idempotency:v1", &value),
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TailscaleOperation {
    Devices,
    DevicePosture,
    AclPolicy,
    Grants,
}

impl TailscaleOperation {
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Devices => "/api/v2/tailnet/{tailnet}/devices",
            Self::DevicePosture => "/api/v2/device/{deviceId}",
            Self::AclPolicy => "/api/v2/tailnet/{tailnet}/acl",
            Self::Grants => "/api/v2/tailnet/{tailnet}/acl",
        }
    }

    #[must_use]
    pub const fn is_allowlisted(self) -> bool {
        matches!(
            self,
            Self::Devices | Self::DevicePosture | Self::AclPolicy | Self::Grants
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TailscaleReadRequest {
    pub operation: TailscaleOperation,
    pub scope_digest: Digest,
    pub revision_fence_digest: Digest,
    pub device_digest: Digest,
    pub posture_digest: Digest,
    pub policy_digest: Digest,
    pub idempotency_key_digest: Digest,
}

impl TailscaleReadRequest {
    pub fn new(
        operation: TailscaleOperation,
        scope: &TailscaleNetworkPostureScope,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        let request = Self {
            operation,
            scope_digest: scope.digest(),
            revision_fence_digest: scope.revision_fence_digest(),
            device_digest: scope.device_digest(),
            posture_digest: scope.posture_digest(),
            policy_digest: scope.policy_digest(),
            idempotency_key_digest: idempotency_key.digest().clone(),
        };
        request.validate(scope)?;
        Ok(request)
    }

    pub fn devices(
        scope: &TailscaleNetworkPostureScope,
        key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(TailscaleOperation::Devices, scope, key)
    }

    pub fn device_posture(
        scope: &TailscaleNetworkPostureScope,
        key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(TailscaleOperation::DevicePosture, scope, key)
    }

    pub fn acl_policy(
        scope: &TailscaleNetworkPostureScope,
        key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(TailscaleOperation::AclPolicy, scope, key)
    }

    pub fn grants(
        scope: &TailscaleNetworkPostureScope,
        key: &IdempotencyKey,
    ) -> Result<Self, ModelError> {
        Self::new(TailscaleOperation::Grants, scope, key)
    }

    pub fn validate(&self, scope: &TailscaleNetworkPostureScope) -> Result<(), ModelError> {
        scope.validate()?;
        if !self.operation.is_allowlisted()
            || self.scope_digest != scope.digest()
            || self.revision_fence_digest != scope.revision_fence_digest()
            || self.device_digest != scope.device_digest()
            || self.posture_digest != scope.posture_digest()
            || self.policy_digest != scope.policy_digest()
        {
            return Err(ModelError::InvalidRequest);
        }
        validate_digest(&self.idempotency_key_digest)
    }

    #[must_use]
    pub fn request_digest(&self) -> Digest {
        domain_digest("hartevo:tailscale-network-posture:request:v1", self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

pub type TailscaleTransportProvenance = TransportProvenance;
pub type ProviderProvenance = TransportProvenance;

impl TransportProvenance {
    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Allowed,
    Denied,
    Expired,
    Unknown,
    Partial,
    RateLimited,
    ProviderUnknown,
    Tamper,
    AccessLoss,
    RegistrationRevoked,
}

pub type TailscaleEvidenceState = EvidenceState;
pub type TailscaleNetworkPostureEvidenceState = EvidenceState;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessDecision {
    Allowed,
    Denied,
    Expired,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureState {
    Compliant,
    NonCompliant,
    Expired,
    Unknown,
    Partial,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
    Allowed,
    Denied,
    Expired,
    Unknown,
    Partial,
    RateLimited,
    ProviderUnknown,
    Tamper,
    AccessLoss,
}

impl From<TransportProvenance> for EvidenceClassification {
    fn from(value: TransportProvenance) -> Self {
        match value {
            TransportProvenance::Fixture => Self::Fixture,
            TransportProvenance::Recording => Self::Recording,
            TransportProvenance::Fake => Self::Fake,
            TransportProvenance::Loopback => Self::Loopback,
            TransportProvenance::BlockedEnv => Self::BlockedEnv,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevicePostureProjection {
    pub device_digest: Digest,
    pub posture_digest: Digest,
    pub tag_digest: Digest,
    pub device_count: u16,
    pub tag_count: u16,
    pub posture: PostureState,
    pub device_revision: Revision,
    pub raw_node_addresses_retained: bool,
    pub raw_device_name_retained: bool,
    pub raw_tag_values_retained: bool,
}

impl DevicePostureProjection {
    pub fn new(
        scope: &TailscaleNetworkPostureScope,
        posture: PostureState,
        device_count: usize,
        tag_count: usize,
        tag_digest: Digest,
    ) -> Result<Self, ModelError> {
        if device_count > MAX_DEVICES || tag_count > MAX_TAGS {
            return Err(ModelError::CountExceeded);
        }
        validate_digest(&tag_digest)?;
        Ok(Self {
            device_digest: scope.device_digest(),
            posture_digest: scope.posture_digest(),
            tag_digest,
            device_count: u16::try_from(device_count).map_err(|_| ModelError::CountExceeded)?,
            tag_count: u16::try_from(tag_count).map_err(|_| ModelError::CountExceeded)?,
            posture,
            device_revision: scope.device.revision,
            raw_node_addresses_retained: false,
            raw_device_name_retained: false,
            raw_tag_values_retained: false,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        domain_digest("hartevo:tailscale-network-posture:device-evidence:v1", self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyProjection {
    pub policy_digest: Digest,
    pub acl_rule_count: u16,
    pub grant_count: u16,
    pub posture_condition_count: u16,
    pub access_decision: AccessDecision,
    pub acl_revision: Revision,
    pub raw_acl_expressions_retained: bool,
    pub raw_grant_principals_retained: bool,
}

impl PolicyProjection {
    pub fn new(
        scope: &TailscaleNetworkPostureScope,
        acl_rule_count: usize,
        grant_count: usize,
        posture_condition_count: usize,
        access_decision: AccessDecision,
    ) -> Result<Self, ModelError> {
        if acl_rule_count > MAX_ACL_RULES
            || grant_count > MAX_GRANTS
            || posture_condition_count > MAX_ACL_RULES
        {
            return Err(ModelError::CountExceeded);
        }
        Ok(Self {
            policy_digest: scope.policy_digest(),
            acl_rule_count: u16::try_from(acl_rule_count).map_err(|_| ModelError::CountExceeded)?,
            grant_count: u16::try_from(grant_count).map_err(|_| ModelError::CountExceeded)?,
            posture_condition_count: u16::try_from(posture_condition_count)
                .map_err(|_| ModelError::CountExceeded)?,
            access_decision,
            acl_revision: scope.acl.revision,
            raw_acl_expressions_retained: false,
            raw_grant_principals_retained: false,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        domain_digest("hartevo:tailscale-network-posture:policy-evidence:v1", self)
    }
}

pub type AclPolicyProjection = PolicyProjection;
pub type GrantProjection = PolicyProjection;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TailscaleRateLimitReceipt {
    pub limit_per_minute: u16,
    pub remaining: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub exhausted: bool,
}

impl Default for TailscaleRateLimitReceipt {
    fn default() -> Self {
        Self {
            limit_per_minute: MAX_REQUESTS_PER_MINUTE,
            remaining: Some(MAX_REQUESTS_PER_MINUTE - 1),
            retry_after_seconds: None,
            exhausted: false,
        }
    }
}

impl TailscaleRateLimitReceipt {
    pub fn new(
        limit_per_minute: u16,
        remaining: Option<u16>,
        retry_after_seconds: Option<u32>,
        exhausted: bool,
    ) -> Result<Self, ModelError> {
        let receipt = Self {
            limit_per_minute,
            remaining,
            retry_after_seconds,
            exhausted,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.limit_per_minute == 0
            || self.limit_per_minute > MAX_REQUESTS_PER_MINUTE
            || self
                .remaining
                .is_some_and(|value| value > self.limit_per_minute)
            || self
                .retry_after_seconds
                .is_some_and(|value| value > MAX_RETRY_AFTER_SECONDS)
            || (self.exhausted && self.remaining.is_some_and(|value| value != 0))
        {
            Err(ModelError::InvalidRateLimitReceipt)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TailscaleResponse {
    status: u16,
    body: Vec<u8>,
    rate_limit: TailscaleRateLimitReceipt,
}

impl fmt::Debug for TailscaleResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TailscaleResponse")
            .field("status", &self.status)
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl TailscaleResponse {
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>, rate_limit: TailscaleRateLimitReceipt) -> Self {
        Self {
            status,
            body,
            rate_limit,
        }
    }

    #[must_use]
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Self::json_with_rate_limit(status, value, TailscaleRateLimitReceipt::default())
    }

    #[must_use]
    pub fn json_with_rate_limit<T: Serialize>(
        status: u16,
        value: &T,
        rate_limit: TailscaleRateLimitReceipt,
    ) -> Self {
        let body = serde_json::to_vec(value).expect("Tailscale fixture payload serializes");
        Self::new(status, body, rate_limit)
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        sha256_digest(&self.body)
    }

    #[must_use]
    pub fn response_bytes(&self) -> usize {
        self.body.len()
    }

    #[must_use]
    pub fn rate_limit(&self) -> &TailscaleRateLimitReceipt {
        &self.rate_limit
    }

    pub(crate) fn json_value(&self) -> Result<serde_json::Value, ModelError> {
        if self.body.len() > MAX_RESPONSE_BYTES {
            return Err(ModelError::InvalidResponse);
        }
        serde_json::from_slice(&self.body).map_err(|_| ModelError::InvalidResponse)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TailscaleRedactedReceipt {
    pub operation: TailscaleOperation,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub scope_digest: Digest,
    pub revision_fence_digest: Digest,
    pub device_digest: Digest,
    pub posture_digest: Digest,
    pub policy_digest: Digest,
    pub provenance: TransportProvenance,
    pub raw_provider_payload_retained: bool,
    pub raw_node_addresses_retained: bool,
    pub raw_tailnet_name_retained: bool,
    pub raw_tag_values_retained: bool,
    pub raw_acl_expressions_retained: bool,
    pub raw_grant_principals_retained: bool,
    pub credential_material_retained: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub receipt_digest: Digest,
}

impl TailscaleRedactedReceipt {
    #[must_use]
    pub fn new(
        request: &TailscaleReadRequest,
        response: &TailscaleResponse,
        provenance: TransportProvenance,
    ) -> Self {
        let mut receipt = Self {
            operation: request.operation,
            request_digest: request.request_digest(),
            response_digest: response.response_digest(),
            response_bytes: response.response_bytes(),
            scope_digest: request.scope_digest.clone(),
            revision_fence_digest: request.revision_fence_digest.clone(),
            device_digest: request.device_digest.clone(),
            posture_digest: request.posture_digest.clone(),
            policy_digest: request.policy_digest.clone(),
            provenance,
            raw_provider_payload_retained: false,
            raw_node_addresses_retained: false,
            raw_tailnet_name_retained: false,
            raw_tag_values_retained: false,
            raw_acl_expressions_retained: false,
            raw_grant_principals_retained: false,
            credential_material_retained: false,
            connected: false,
            native: false,
            first_party: false,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.calculate_digest();
        receipt
    }

    fn digest_input(
        &self,
    ) -> (
        (
            &TailscaleOperation,
            &Digest,
            &Digest,
            usize,
            &Digest,
            &Digest,
            &Digest,
            &Digest,
            &Digest,
            &TransportProvenance,
        ),
        (bool, bool, bool, bool, bool, bool, bool, bool, bool, bool),
    ) {
        (
            (
                &self.operation,
                &self.request_digest,
                &self.response_digest,
                self.response_bytes,
                &self.scope_digest,
                &self.revision_fence_digest,
                &self.device_digest,
                &self.posture_digest,
                &self.policy_digest,
                &self.provenance,
            ),
            (
                self.raw_provider_payload_retained,
                self.raw_node_addresses_retained,
                self.raw_tailnet_name_retained,
                self.raw_tag_values_retained,
                self.raw_acl_expressions_retained,
                self.raw_grant_principals_retained,
                self.credential_material_retained,
                self.connected,
                self.native,
                self.first_party,
            ),
        )
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        domain_digest(
            "hartevo:tailscale-network-posture:receipt:v1",
            &self.digest_input(),
        )
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self.raw_provider_payload_retained
            || self.raw_node_addresses_retained
            || self.raw_tailnet_name_retained
            || self.raw_tag_values_retained
            || self.raw_acl_expressions_retained
            || self.raw_grant_principals_retained
            || self.credential_material_retained
            || self.connected
            || self.native
            || self.first_party
            || self.receipt_digest != self.calculate_digest()
        {
            Err(ModelError::InvalidResponse)
        } else {
            Ok(())
        }
    }
}
