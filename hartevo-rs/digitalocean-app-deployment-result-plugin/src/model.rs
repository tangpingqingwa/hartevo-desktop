use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fmt::Write as _,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{DigitalOceanAppDeploymentResultError, Result};
use crate::{
    MAX_COMPONENTS, MAX_EVENTS, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES,
};

pub type StatusCounts = BTreeMap<String, u16>;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    #[must_use]
    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut input = String::from(domain);
        for (key, value) in fields {
            input.push('|');
            input.push_str(key);
            input.push('=');
            input.push_str(value);
        }
        Self::from_text(input)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_digest(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        validate_digest(&self.0)
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

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("DigitalOcean typed value serializes");
    sha256_digest(&bytes)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{label} is empty, malformed, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("{label} is empty, malformed, or too long")]
    InvalidText { label: &'static str },
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("DigitalOcean scope is invalid")]
    InvalidScope,
    #[error("DigitalOcean component selector is invalid")]
    InvalidComponent,
    #[error("DigitalOcean permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("DigitalOcean consent scope is invalid")]
    InvalidConsent,
    #[error("DigitalOcean SecretReference is invalid")]
    InvalidSecretReference,
}

impl From<ModelError> for DigitalOceanAppDeploymentResultError {
    fn from(error: ModelError) -> Self {
        match error {
            ModelError::InvalidIdentifier { label } => Self::InvalidIdentifier { field: label },
            ModelError::InvalidText { label } => Self::InvalidText { field: label },
            ModelError::InvalidRevision | ModelError::InvalidScope => Self::InvalidScope,
            ModelError::InvalidDigest => Self::InvalidDigest,
            ModelError::InvalidComponent => Self::InvalidComponent,
            ModelError::InvalidPermissionSnapshot => Self::InvalidPermissionSnapshot,
            ModelError::InvalidConsent => Self::InvalidConsent,
            ModelError::InvalidSecretReference => Self::InvalidSecretReference,
        }
    }
}

fn validate_identifier(value: &str, label: &'static str) -> std::result::Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-/@+$".contains(&byte))
    {
        return Err(ModelError::InvalidIdentifier { label });
    }
    Ok(())
}

fn validate_text(
    value: &str,
    label: &'static str,
    max: usize,
) -> std::result::Result<(), ModelError> {
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(ModelError::InvalidText { label })
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(DigitalOceanAppDeploymentResultError::InvalidDigest)
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Identifier(String);

impl Identifier {
    pub fn new(value: impl Into<String>) -> std::result::Result<Self, ModelError> {
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
        Digest::from_text(self.0.as_bytes())
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Identifier")
            .field("digest", &self.digest())
            .finish()
    }
}

impl Serialize for Identifier {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

pub type AccountId = Identifier;
pub type TeamId = Identifier;
pub type AppId = Identifier;
pub type DeploymentId = Identifier;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Region(String);

impl Region {
    pub fn new(value: impl Into<String>) -> std::result::Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "region")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(self.0.as_bytes())
    }
}

impl fmt::Debug for Region {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Region").field(&self.0).finish()
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentSelector {
    pub name: String,
    pub component_type: String,
}

impl fmt::Debug for ComponentSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentSelector")
            .field("name_digest", &Digest::from_text(self.name.as_bytes()))
            .field("component_type", &self.component_type)
            .finish()
    }
}

impl ComponentSelector {
    pub fn new(name: impl Into<String>, component_type: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let component_type = component_type.into();
        validate_text(&name, "component name", MAX_IDENTIFIER_BYTES)?;
        validate_text(&component_type, "component type", 64)?;
        if !component_type
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        {
            return Err(DigitalOceanAppDeploymentResultError::InvalidComponent);
        }
        Ok(Self {
            name,
            component_type,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "digitalocean-component-selector/v1",
            &[
                ("name", self.name.clone()),
                ("type", self.component_type.clone()),
            ],
        )
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SourceRevision {
    digest: Digest,
}

impl fmt::Debug for SourceRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceRevision")
            .field("digest", &self.digest)
            .finish()
    }
}

impl SourceRevision {
    pub fn new(raw_revision: impl AsRef<str>) -> Result<Self> {
        let raw_revision = raw_revision.as_ref();
        validate_text(raw_revision, "source revision", MAX_IDENTIFIER_BYTES).map_err(|_| {
            DigitalOceanAppDeploymentResultError::InvalidText {
                field: "source revision",
            }
        })?;
        Ok(Self {
            digest: Digest::from_text(raw_revision.as_bytes()),
        })
    }

    pub fn from_digest(digest: Digest) -> Result<Self> {
        digest.validate()?;
        Ok(Self { digest })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    id: Identifier,
    revision: u64,
}

impl fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Identity")
            .field("id_digest", &self.id.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

impl Identity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(DigitalOceanAppDeploymentResultError::InvalidScope);
        }
        Ok(Self {
            id: Identifier::new(id).map_err(DigitalOceanAppDeploymentResultError::from)?,
            revision,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    #[must_use]
    pub fn id_digest(&self) -> Digest {
        self.id.digest()
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "digitalocean-identity/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }
}

pub type ProjectIdentity = Identity;
pub type MissionIdentity = Identity;
pub type WorkProductIdentity = Identity;

#[derive(Clone, Eq, PartialEq)]
pub struct DigitalOceanAppDeploymentScope {
    account: AccountId,
    team: TeamId,
    app: AppId,
    deployment: DeploymentId,
    region: Region,
    components: Vec<ComponentSelector>,
    source_revision: SourceRevision,
    project: ProjectIdentity,
    mission: MissionIdentity,
    work_product: WorkProductIdentity,
}

impl fmt::Debug for DigitalOceanAppDeploymentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigitalOceanAppDeploymentScope")
            .field("account_digest", &self.account.digest())
            .field("team_digest", &self.team.digest())
            .field("app_digest", &self.app.digest())
            .field("deployment_digest", &self.deployment.digest())
            .field("region", &self.region)
            .field("component_count", &self.components.len())
            .field("source_revision_digest", &self.source_revision.digest)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .field("scope_digest", &self.digest())
            .finish()
    }
}

impl Serialize for DigitalOceanAppDeploymentScope {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("DigitalOceanAppDeploymentScope", 12)?;
        state.serialize_field("accountDigest", &self.account.digest())?;
        state.serialize_field("teamDigest", &self.team.digest())?;
        state.serialize_field("appDigest", &self.app.digest())?;
        state.serialize_field("deploymentDigest", &self.deployment.digest())?;
        state.serialize_field("region", &self.region)?;
        state.serialize_field(
            "componentDigests",
            &self
                .components
                .iter()
                .map(ComponentSelector::digest)
                .collect::<Vec<_>>(),
        )?;
        state.serialize_field("sourceRevisionDigest", &self.source_revision.digest)?;
        state.serialize_field("projectDigest", &self.project.digest())?;
        state.serialize_field("missionDigest", &self.mission.digest())?;
        state.serialize_field("workProductDigest", &self.work_product.digest())?;
        state.serialize_field("scopeDigest", &self.digest())?;
        state.end()
    }
}

impl DigitalOceanAppDeploymentScope {
    pub fn new(
        account: AccountId,
        team: TeamId,
        app: AppId,
        deployment: DeploymentId,
        region: Region,
        components: Vec<ComponentSelector>,
        source_revision: SourceRevision,
        project: ProjectIdentity,
        mission: MissionIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        if components.is_empty() || components.len() > MAX_COMPONENTS {
            return Err(DigitalOceanAppDeploymentResultError::InvalidScope);
        }
        let mut names = BTreeSet::new();
        for component in &components {
            if !names.insert(component.name.clone()) {
                return Err(DigitalOceanAppDeploymentResultError::InvalidComponent);
            }
        }
        let scope = Self {
            account,
            team,
            app,
            deployment,
            region,
            components,
            source_revision,
            project,
            mission,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        if self.components.is_empty() || self.components.len() > MAX_COMPONENTS {
            return Err(DigitalOceanAppDeploymentResultError::InvalidScope);
        }
        self.source_revision.digest.validate()?;
        Ok(())
    }

    #[must_use]
    pub fn account(&self) -> &AccountId {
        &self.account
    }
    #[must_use]
    pub fn team(&self) -> &TeamId {
        &self.team
    }
    #[must_use]
    pub fn app(&self) -> &AppId {
        &self.app
    }
    #[must_use]
    pub fn deployment(&self) -> &DeploymentId {
        &self.deployment
    }
    #[must_use]
    pub fn region(&self) -> &Region {
        &self.region
    }
    #[must_use]
    pub fn components(&self) -> &[ComponentSelector] {
        &self.components
    }
    #[must_use]
    pub fn source_revision(&self) -> &SourceRevision {
        &self.source_revision
    }
    #[must_use]
    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }
    #[must_use]
    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }
    #[must_use]
    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "digitalocean-app-deployment-scope/v1",
            &[
                ("account", self.account.as_str().to_owned()),
                ("team", self.team.as_str().to_owned()),
                ("app", self.app.as_str().to_owned()),
                ("deployment", self.deployment.as_str().to_owned()),
                ("region", self.region.as_str().to_owned()),
                (
                    "components",
                    self.components
                        .iter()
                        .map(|component| component.digest().as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("source", self.source_revision.digest.as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OAuth,
    ApiToken,
}

#[derive(Clone)]
pub struct SecretReference {
    kind: SecretKind,
    material: Zeroizing<String>,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
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

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.revision == other.revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretReference", 5)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("referenceDigest", &self.reference_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("revoked", &self.revoked)?;
        state.end()
    }
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl Into<String>,
        scope: &DigitalOceanAppDeploymentScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new_with_kind(opaque_handle, scope, revision, SecretKind::ApiToken)
    }

    pub fn new_with_kind(
        opaque_handle: impl Into<String>,
        scope: &DigitalOceanAppDeploymentScope,
        revision: u64,
        kind: SecretKind,
    ) -> Result<Self> {
        let opaque_handle = opaque_handle.into();
        validate_text(
            &opaque_handle,
            "opaque secret reference",
            MAX_IDENTIFIER_BYTES,
        )
        .map_err(|_| DigitalOceanAppDeploymentResultError::InvalidSecretReference)?;
        if revision == 0 {
            return Err(DigitalOceanAppDeploymentResultError::InvalidSecretReference);
        }
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "digitalocean-secret-reference/v1",
            &[
                ("kind", format!("{kind:?}")),
                ("handle", opaque_handle.clone()),
                ("scope", scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(Self {
            kind,
            material: Zeroizing::new(opaque_handle),
            reference_digest,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub fn oauth(
        opaque_handle: impl Into<String>,
        scope: &DigitalOceanAppDeploymentScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new_with_kind(opaque_handle, scope, revision, SecretKind::OAuth)
    }

    pub fn api_token(
        opaque_handle: impl Into<String>,
        scope: &DigitalOceanAppDeploymentScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new_with_kind(opaque_handle, scope, revision, SecretKind::ApiToken)
    }

    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }
    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }
    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
        self.material.zeroize();
    }

    pub fn validate(&self, scope: &DigitalOceanAppDeploymentScope) -> Result<()> {
        if self.revision == 0
            || self.scope_digest != scope.digest()
            || self.reference_digest.validate().is_err()
        {
            return Err(DigitalOceanAppDeploymentResultError::InvalidSecretReference);
        }
        if self.revoked {
            return Err(DigitalOceanAppDeploymentResultError::SecretRevoked);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }
    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }
    #[must_use]
    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
    pub digest: Digest,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if revision == 0 {
            return Err(DigitalOceanAppDeploymentResultError::InvalidPermissionSnapshot);
        }
        let permissions = permissions
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        if permissions.is_empty() || permissions.iter().any(String::is_empty) {
            return Err(DigitalOceanAppDeploymentResultError::InvalidPermissionSnapshot);
        }
        let digest = Digest::from_parts(
            "digitalocean-permissions/v1",
            &[
                ("revision", revision.to_string()),
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join(","),
                ),
            ],
        );
        Ok(Self {
            revision,
            permissions,
            digest,
        })
    }

    pub fn for_layer_one(revision: u64) -> Self {
        Self::new(revision, ["app:read", "mission.scope"]).expect("layer-one permissions valid")
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.revision, self.permissions.clone())?;
        if expected.digest != self.digest {
            return Err(DigitalOceanAppDeploymentResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScope {
    pub id_digest: Digest,
    pub revision: u64,
    pub expires_at: DateTime<Utc>,
    pub permissions: BTreeSet<String>,
    pub revoked: bool,
    pub digest: Digest,
}

impl ConsentScope {
    pub fn new<I, S>(
        id: impl AsRef<str>,
        revision: u64,
        expires_at: DateTime<Utc>,
        permissions: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let id = id.as_ref();
        validate_text(id, "consent id", MAX_IDENTIFIER_BYTES)
            .map_err(|_| DigitalOceanAppDeploymentResultError::InvalidConsent)?;
        if revision == 0 || expires_at <= DateTime::<Utc>::UNIX_EPOCH {
            return Err(DigitalOceanAppDeploymentResultError::InvalidConsent);
        }
        let permissions = permissions
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        if permissions.is_empty() {
            return Err(DigitalOceanAppDeploymentResultError::InvalidConsent);
        }
        let id_digest = Digest::from_text(id.as_bytes());
        let digest = Digest::from_parts(
            "digitalocean-consent/v1",
            &[
                ("id", id.to_owned()),
                ("revision", revision.to_string()),
                ("expires", expires_at.to_rfc3339()),
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join(","),
                ),
            ],
        );
        Ok(Self {
            id_digest,
            revision,
            expires_at,
            permissions,
            revoked: false,
            digest,
        })
    }

    pub fn for_layer_one(
        id: impl AsRef<str>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(id, revision, expires_at, ["app:read", "mission.scope"])
    }

    #[must_use]
    pub fn is_active_at(&self, at: DateTime<Utc>) -> bool {
        !self.revoked && at < self.expires_at
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn validate(&self) -> Result<()> {
        if self.revision == 0 || self.permissions.is_empty() || self.digest.validate().is_err() {
            return Err(DigitalOceanAppDeploymentResultError::InvalidConsent);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeploymentPhase {
    PendingBuild,
    Building,
    PendingDeploy,
    Deploying,
    Active,
    Superseded,
    Error,
    Canceled,
    Unknown,
}

impl DeploymentPhase {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_uppercase().as_str() {
            "PENDING_BUILD" => Self::PendingBuild,
            "BUILDING" => Self::Building,
            "PENDING_DEPLOY" => Self::PendingDeploy,
            "DEPLOYING" => Self::Deploying,
            "ACTIVE" => Self::Active,
            "SUPERSEDED" => Self::Superseded,
            "ERROR" | "FAILED" => Self::Error,
            "CANCELED" | "CANCELLED" => Self::Canceled,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::PendingBuild => 1,
            Self::Building => 2,
            Self::PendingDeploy => 3,
            Self::Deploying => 4,
            Self::Active => 5,
            Self::Superseded | Self::Error | Self::Canceled | Self::Unknown => 6,
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Superseded | Self::Error | Self::Canceled
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComponentStatus {
    Pending,
    Running,
    Ready,
    Error,
    Canceled,
    Unknown,
}

impl ComponentStatus {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_uppercase().as_str() {
            "PENDING" => Self::Pending,
            "RUNNING" | "BUILDING" | "DEPLOYING" => Self::Running,
            "READY" | "HEALTHY" | "ACTIVE" => Self::Ready,
            "ERROR" | "FAILED" | "UNHEALTHY" => Self::Error,
            "CANCELED" | "CANCELLED" => Self::Canceled,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Running => "RUNNING",
            Self::Ready => "READY",
            Self::Error => "ERROR",
            Self::Canceled => "CANCELED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealthState {
    Unknown,
    Healthy,
    Unhealthy,
}

impl HealthState {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_uppercase().as_str() {
            "HEALTHY" => Self::Healthy,
            "UNHEALTHY" => Self::Unhealthy,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DigitalOceanEvidenceState {
    PendingBuild,
    Building,
    PendingDeploy,
    Deploying,
    Active,
    Superseded,
    Error,
    Canceled,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl From<DeploymentPhase> for DigitalOceanEvidenceState {
    fn from(phase: DeploymentPhase) -> Self {
        match phase {
            DeploymentPhase::PendingBuild => Self::PendingBuild,
            DeploymentPhase::Building => Self::Building,
            DeploymentPhase::PendingDeploy => Self::PendingDeploy,
            DeploymentPhase::Deploying => Self::Deploying,
            DeploymentPhase::Active => Self::Active,
            DeploymentPhase::Superseded => Self::Superseded,
            DeploymentPhase::Error | DeploymentPhase::Unknown => Self::Error,
            DeploymentPhase::Canceled => Self::Canceled,
        }
    }
}

impl DigitalOceanEvidenceState {
    #[must_use]
    pub const fn is_lifecycle(self) -> bool {
        matches!(
            self,
            Self::PendingBuild
                | Self::Building
                | Self::PendingDeploy
                | Self::Deploying
                | Self::Active
                | Self::Superseded
                | Self::Error
                | Self::Canceled
        )
    }

    #[must_use]
    pub const fn is_non_adoptable(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentProjection {
    pub name: String,
    pub component_type: String,
    pub status: ComponentStatus,
    pub desired_count: Option<u32>,
    pub ready_count: Option<u32>,
    pub status_counts: StatusCounts,
    pub source_revision_digest: Option<Digest>,
}

impl ComponentProjection {
    pub fn new(
        name: impl Into<String>,
        component_type: impl Into<String>,
        status: ComponentStatus,
        desired_count: Option<u32>,
        ready_count: Option<u32>,
        source_revision_digest: Option<Digest>,
    ) -> Result<Self> {
        let name = name.into();
        let component_type = component_type.into();
        validate_text(&name, "component name", MAX_IDENTIFIER_BYTES)
            .map_err(|_| DigitalOceanAppDeploymentResultError::InvalidComponent)?;
        validate_text(&component_type, "component type", 64)
            .map_err(|_| DigitalOceanAppDeploymentResultError::InvalidComponent)?;
        if let Some(digest) = &source_revision_digest {
            digest.validate()?;
        }
        let mut status_counts = StatusCounts::new();
        status_counts.insert(status.key().to_owned(), 1);
        Ok(Self {
            name,
            component_type,
            status,
            desired_count,
            ready_count,
            status_counts,
            source_revision_digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthComponentProjection {
    pub name: String,
    pub state: HealthState,
    pub desired_count: Option<u32>,
    pub ready_count: Option<u32>,
    pub status_counts: StatusCounts,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthProjection {
    pub state: HealthState,
    pub components: Vec<HealthComponentProjection>,
    pub status_counts: StatusCounts,
    pub digest: Digest,
}

impl HealthProjection {
    pub fn new(state: HealthState, components: Vec<HealthComponentProjection>) -> Result<Self> {
        if components.len() > MAX_COMPONENTS {
            return Err(DigitalOceanAppDeploymentResultError::InvalidResponse);
        }
        let mut status_counts = StatusCounts::new();
        for component in &components {
            *status_counts
                .entry(format!("{:?}", component.state).to_ascii_uppercase())
                .or_default() += 1;
        }
        let digest = canonical_digest(&(state, &components, &status_counts));
        Ok(Self {
            state,
            components,
            status_counts,
            digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentProjection {
    pub deployment_digest: Digest,
    pub phase: DeploymentPhase,
    pub cause_digest: Option<Digest>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub phase_last_updated_at: Option<DateTime<Utc>>,
    pub superseded_by_digest: Option<Digest>,
    pub source_revision_digest: Option<Digest>,
    pub components: Vec<ComponentProjection>,
    pub component_status_counts: StatusCounts,
    pub digest: Digest,
}

impl DeploymentProjection {
    pub fn new(
        deployment_digest: Digest,
        phase: DeploymentPhase,
        cause_digest: Option<Digest>,
        created_at: Option<DateTime<Utc>>,
        updated_at: Option<DateTime<Utc>>,
        phase_last_updated_at: Option<DateTime<Utc>>,
        superseded_by_digest: Option<Digest>,
        source_revision_digest: Option<Digest>,
        components: Vec<ComponentProjection>,
    ) -> Result<Self> {
        deployment_digest.validate()?;
        if components.len() > MAX_COMPONENTS {
            return Err(DigitalOceanAppDeploymentResultError::InvalidResponse);
        }
        for digest in [
            cause_digest.as_ref(),
            superseded_by_digest.as_ref(),
            source_revision_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        let mut component_status_counts = StatusCounts::new();
        for component in &components {
            *component_status_counts
                .entry(component.status.key().to_owned())
                .or_default() += 1;
        }
        let digest = canonical_digest(&(
            &deployment_digest,
            phase,
            &cause_digest,
            created_at,
            updated_at,
            phase_last_updated_at,
            &superseded_by_digest,
            &source_revision_digest,
            &components,
            &component_status_counts,
        ));
        Ok(Self {
            deployment_digest,
            phase,
            cause_digest,
            created_at,
            updated_at,
            phase_last_updated_at,
            superseded_by_digest,
            source_revision_digest,
            components,
            component_status_counts,
            digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventProjection {
    pub event_id_digest: Digest,
    pub deployment_id_digest: Digest,
    pub event_type: String,
    pub created_at: Option<DateTime<Utc>>,
}

impl EventProjection {
    pub fn new(
        event_id_digest: Digest,
        deployment_id_digest: Digest,
        event_type: impl Into<String>,
        created_at: Option<DateTime<Utc>>,
    ) -> Result<Self> {
        event_id_digest.validate()?;
        deployment_id_digest.validate()?;
        let event_type = event_type.into();
        validate_text(&event_type, "event type", 64)
            .map_err(|_| DigitalOceanAppDeploymentResultError::InvalidResponse)?;
        Ok(Self {
            event_id_digest,
            deployment_id_digest,
            event_type,
            created_at,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppProjection {
    pub account_digest: Digest,
    pub team_digest: Digest,
    pub app_digest: Digest,
    pub region: Region,
    pub active_deployment_digest: Option<Digest>,
    pub digest: Digest,
}

impl AppProjection {
    pub fn new(
        account_digest: Digest,
        team_digest: Digest,
        app_digest: Digest,
        region: Region,
        active_deployment_digest: Option<Digest>,
    ) -> Result<Self> {
        for digest in [&account_digest, &team_digest, &app_digest]
            .into_iter()
            .chain(active_deployment_digest.as_ref())
        {
            digest.validate()?;
        }
        let digest = canonical_digest(&(
            &account_digest,
            &team_digest,
            &app_digest,
            &region,
            &active_deployment_digest,
        ));
        Ok(Self {
            account_digest,
            team_digest,
            app_digest,
            region,
            active_deployment_digest,
            digest,
        })
    }
}

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

#[must_use]
pub fn mission_projection(identity: &MissionIdentity) -> MissionProjection {
    MissionProjection {
        id_digest: identity.id_digest(),
        revision: identity.revision(),
    }
}

#[must_use]
pub fn project_projection(identity: &ProjectIdentity) -> ProjectProjection {
    ProjectProjection {
        id_digest: identity.id_digest(),
        revision: identity.revision(),
    }
}

#[must_use]
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
    pub scope_digest: Digest,
    pub page_digest: Option<Digest>,
    pub redacted: bool,
}

impl RequestReceipt {
    pub fn new(
        operation: impl Into<String>,
        request_digest: Digest,
        path_digest: Digest,
        scope_digest: Digest,
        page_digest: Option<Digest>,
    ) -> Self {
        Self {
            operation: operation.into(),
            request_digest,
            path_digest,
            scope_digest,
            page_digest,
            redacted: true,
        }
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.redacted {
            return Err(DigitalOceanAppDeploymentResultError::TamperedEvidence);
        }
        self.request_digest.validate()?;
        self.path_digest.validate()?;
        self.scope_digest.validate()?;
        if let Some(digest) = &self.page_digest {
            digest.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostReceipt {
    pub operation: String,
    pub response_bytes: u64,
    pub bounded_request_units: u16,
    pub cost_digest: Digest,
    pub redacted: bool,
    pub durable_provider_receipt: bool,
}

impl CostReceipt {
    pub fn new(operation: impl Into<String>, response_bytes: u64) -> Result<Self> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(DigitalOceanAppDeploymentResultError::PartialEvidence);
        }
        let operation = operation.into();
        let cost_digest = Digest::from_parts(
            "digitalocean-cost/v1",
            &[
                ("operation", operation.clone()),
                ("bytes", response_bytes.to_string()),
            ],
        );
        Ok(Self {
            operation,
            response_bytes,
            bounded_request_units: 1,
            cost_digest,
            redacted: true,
            durable_provider_receipt: false,
        })
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.redacted
            || self.durable_provider_receipt
            || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(DigitalOceanAppDeploymentResultError::TamperedEvidence);
        }
        self.cost_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostSummary {
    pub response_bytes: u64,
    pub bounded_request_units: u16,
    pub digest: Digest,
}

impl CostSummary {
    pub fn from_receipts(receipts: &[CostReceipt]) -> Self {
        let response_bytes: u64 = receipts.iter().map(|receipt| receipt.response_bytes).sum();
        let bounded_request_units: u16 = receipts
            .iter()
            .map(|receipt| receipt.bounded_request_units)
            .sum();
        let digest = Digest::from_parts(
            "digitalocean-cost-summary/v1",
            &[
                ("bytes", response_bytes.to_string()),
                ("units", bounded_request_units.to_string()),
                (
                    "receipts",
                    receipts
                        .iter()
                        .map(|receipt| receipt.cost_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Self {
            response_bytes,
            bounded_request_units,
            digest,
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
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_digest: Digest,
    pub app_digest: Digest,
    pub deployment_digest: Digest,
    pub source_revision_digest: Digest,
    pub result_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    #[must_use]
    pub fn calculate(&self) -> Digest {
        Digest::from_parts(
            "digitalocean-evidence/v1",
            &[
                ("plugin", self.plugin_version_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_digest.as_str().to_owned()),
                ("app", self.app_digest.as_str().to_owned()),
                ("deployment", self.deployment_digest.as_str().to_owned()),
                ("source", self.source_revision_digest.as_str().to_owned()),
                ("result", self.result_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        for digest in [
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.request_digest,
            &self.page_digest,
            &self.app_digest,
            &self.deployment_digest,
            &self.source_revision_digest,
            &self.result_digest,
            &self.registration_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        if self.calculate() != self.evidence_digest {
            return Err(DigitalOceanAppDeploymentResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[must_use]
pub fn join_digests(values: impl IntoIterator<Item = Digest>) -> String {
    values
        .into_iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>()
        .join(",")
}

#[must_use]
pub fn percent_encode(value: &str) -> String {
    value.bytes().fold(String::new(), |mut output, byte| {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            output.push(byte as char);
        } else {
            output.push('%');
            let _ = write!(output, "{byte:02X}");
        }
        output
    })
}

pub(crate) fn validate_page_size(page_size: u16) -> Result<()> {
    if page_size == 0 || page_size > MAX_PAGE_SIZE {
        Err(DigitalOceanAppDeploymentResultError::InvalidRequest)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_page_number(page: u32) -> Result<()> {
    if page == 0 || page > u32::from(MAX_PAGES) * 200 {
        Err(DigitalOceanAppDeploymentResultError::InvalidRequest)
    } else {
        Ok(())
    }
}

pub(crate) fn bound_components<T>(values: &[T]) -> Result<()> {
    if values.len() > MAX_COMPONENTS {
        Err(DigitalOceanAppDeploymentResultError::PartialEvidence)
    } else {
        Ok(())
    }
}

pub(crate) fn bound_events<T>(values: &[T]) -> Result<()> {
    if values.len() > MAX_EVENTS {
        Err(DigitalOceanAppDeploymentResultError::PartialEvidence)
    } else {
        Ok(())
    }
}
