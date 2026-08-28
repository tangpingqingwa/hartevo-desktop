use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{RenderDeploymentError, Result};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 512;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RETRY_ATTEMPTS: u8 = 3;
pub const MAX_DEPLOYS_PER_PAGE: usize = 50;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_HEALTH_CHECKS: u32 = 128;
pub const MAX_BACKOFF_SECONDS: u32 = 60;

pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "render:services.read",
    "render:deploys.read",
    "render:health.read",
    "mission.scope",
];

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A validated SHA-256 digest. Provider-owned identifiers and all sensitive
/// values cross the evidence boundary only as this type.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(RenderDeploymentError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(sha256_hex(bytes))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    #[must_use]
    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_component(&mut bytes, domain);
        for (label, value) in fields {
            append_component(&mut bytes, label);
            append_component(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    #[must_use]
    pub fn pending() -> Self {
        Self::from_text("unsealed-render-digest")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(RenderDeploymentError::InvalidDigest)
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

fn append_component(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(value.len().to_string().as_bytes());
    bytes.push(b':');
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(b'|');
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Identifier(String);

impl Identifier {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_identifier(&value) {
            Ok(Self(value))
        } else {
            Err(RenderDeploymentError::InvalidIdentifier {
                field: "identifier",
            })
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts("render-identifier/v1", &[("value", self.0.clone())])
    }
}

impl AsRef<str> for Identifier {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Identifier")
            .field(&format!("id:{}", &self.digest().as_str()[..16]))
            .finish()
    }
}

macro_rules! identifier_aliases {
    ($($name:ident),+ $(,)?) => {
        $(pub type $name = Identifier;)+
    };
}

identifier_aliases!(
    RenderOwnerId,
    RenderWorkspaceId,
    RenderServiceId,
    RenderEnvironmentId,
    RenderDeployId,
    RenderRegion,
    ProjectId,
    MissionId,
    WorkProductId,
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(RenderDeploymentError::InvalidRevision { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn bump(self) -> Result<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(RenderDeploymentError::RevisionOverflow)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Project {
    id: ProjectId,
    revision: Revision,
}

impl Project {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: Identifier::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &ProjectId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "render-project/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mission {
    id: MissionId,
    revision: Revision,
}

impl Mission {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: Identifier::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &MissionId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "render-mission/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProduct {
    id: WorkProductId,
    revision: Revision,
}

impl WorkProduct {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: Identifier::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &WorkProductId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "render-work-product/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl From<&Project> for ProjectProjection {
    fn from(value: &Project) -> Self {
        Self {
            id_digest: value.id.digest(),
            revision: value.revision,
        }
    }
}

impl From<&Mission> for MissionProjection {
    fn from(value: &Mission) -> Self {
        Self {
            id_digest: value.id.digest(),
            revision: value.revision,
        }
    }
}

impl From<&WorkProduct> for WorkProductProjection {
    fn from(value: &WorkProduct) -> Self {
        Self {
            id_digest: value.id.digest(),
            revision: value.revision,
        }
    }
}

/// Exact Render and Hartevo scope. Raw commit content is immediately reduced
/// to a digest; evidence never exposes raw provider or Mission identifiers.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderDeploymentScope {
    owner_id: RenderOwnerId,
    workspace_id: RenderWorkspaceId,
    service_id: RenderServiceId,
    environment_id: RenderEnvironmentId,
    deploy_id: RenderDeployId,
    commit_digest: Digest,
    region: RenderRegion,
    project: Project,
    mission: Mission,
    work_product: WorkProduct,
    service_allowlist: BTreeSet<RenderServiceId>,
    deploy_allowlist: BTreeSet<RenderDeployId>,
}

impl fmt::Debug for RenderDeploymentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderDeploymentScope")
            .field("scope_digest", &self.digest())
            .field("project", &self.project.digest())
            .field("mission", &self.mission.digest())
            .field("work_product", &self.work_product.digest())
            .finish()
    }
}

impl RenderDeploymentScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_id: impl Into<String>,
        workspace_id: impl Into<String>,
        service_id: impl Into<String>,
        environment_id: impl Into<String>,
        deploy_id: impl Into<String>,
        commit: impl AsRef<str>,
        region: impl Into<String>,
        project: Project,
        mission: Mission,
        work_product: WorkProduct,
    ) -> Result<Self> {
        let service_id = Identifier::new(service_id)?;
        let deploy_id = Identifier::new(deploy_id)?;
        let scope = Self {
            owner_id: Identifier::new(owner_id)?,
            workspace_id: Identifier::new(workspace_id)?,
            service_id: service_id.clone(),
            environment_id: Identifier::new(environment_id)?,
            deploy_id: deploy_id.clone(),
            commit_digest: digest_text("commit", commit.as_ref())?,
            region: Identifier::new(region)?,
            project,
            mission,
            work_product,
            service_allowlist: BTreeSet::from([service_id]),
            deploy_allowlist: BTreeSet::from([deploy_id]),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn with_allowlists<I, J>(
        mut self,
        service_allowlist: I,
        deploy_allowlist: J,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = RenderServiceId>,
        J: IntoIterator<Item = RenderDeployId>,
    {
        self.service_allowlist = service_allowlist.into_iter().collect();
        self.deploy_allowlist = deploy_allowlist.into_iter().collect();
        self.validate()?;
        Ok(self)
    }

    #[must_use]
    pub fn owner_id(&self) -> &RenderOwnerId {
        &self.owner_id
    }

    #[must_use]
    pub fn workspace_id(&self) -> &RenderWorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub fn service_id(&self) -> &RenderServiceId {
        &self.service_id
    }

    #[must_use]
    pub fn environment_id(&self) -> &RenderEnvironmentId {
        &self.environment_id
    }

    #[must_use]
    pub fn deploy_id(&self) -> &RenderDeployId {
        &self.deploy_id
    }

    #[must_use]
    pub fn commit_digest(&self) -> &Digest {
        &self.commit_digest
    }

    #[must_use]
    pub fn region(&self) -> &RenderRegion {
        &self.region
    }

    #[must_use]
    pub fn project(&self) -> &Project {
        &self.project
    }

    #[must_use]
    pub fn mission(&self) -> &Mission {
        &self.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProduct {
        &self.work_product
    }

    #[must_use]
    pub fn service_allowlist(&self) -> &BTreeSet<RenderServiceId> {
        &self.service_allowlist
    }

    #[must_use]
    pub fn deploy_allowlist(&self) -> &BTreeSet<RenderDeployId> {
        &self.deploy_allowlist
    }

    #[must_use]
    pub fn service_allowlist_digest(&self) -> Digest {
        digest_identifiers("render-service-allowlist/v1", &self.service_allowlist)
    }

    #[must_use]
    pub fn deploy_allowlist_digest(&self) -> Digest {
        digest_identifiers("render-deploy-allowlist/v1", &self.deploy_allowlist)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "render-deployment-scope/v1",
            &[
                ("owner", self.owner_id.digest().as_str().to_owned()),
                ("workspace", self.workspace_id.digest().as_str().to_owned()),
                ("service", self.service_id.digest().as_str().to_owned()),
                (
                    "environment",
                    self.environment_id.digest().as_str().to_owned(),
                ),
                ("deploy", self.deploy_id.digest().as_str().to_owned()),
                ("commit", self.commit_digest.as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                (
                    "service_allowlist",
                    self.service_allowlist_digest().as_str().to_owned(),
                ),
                (
                    "deploy_allowlist",
                    self.deploy_allowlist_digest().as_str().to_owned(),
                ),
            ],
        )
    }

    #[must_use]
    pub fn service_is_allowed(&self, service_id: &RenderServiceId) -> bool {
        self.service_allowlist.contains(service_id)
    }

    #[must_use]
    pub fn deploy_is_allowed(&self, deploy_id: &RenderDeployId) -> bool {
        self.deploy_allowlist.contains(deploy_id)
    }

    fn validate(&self) -> Result<()> {
        if self.service_allowlist.is_empty() || self.deploy_allowlist.is_empty() {
            return Err(RenderDeploymentError::InvalidScope("empty allowlist"));
        }
        if !self.service_is_allowed(&self.service_id) {
            return Err(RenderDeploymentError::InvalidScope(
                "service is not in the explicit allowlist",
            ));
        }
        if !self.deploy_is_allowed(&self.deploy_id) {
            return Err(RenderDeploymentError::InvalidScope(
                "deployment is not in the explicit allowlist",
            ));
        }
        self.commit_digest.validate()
    }
}

fn digest_text(label: &'static str, value: &str) -> Result<Digest> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(RenderDeploymentError::InvalidScope(label));
    }
    let _ = label;
    Ok(Digest::from_text(value.as_bytes()))
}

fn digest_identifiers<T: AsRef<str> + Ord>(domain: &str, values: &BTreeSet<T>) -> Digest {
    let joined = values
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join("\u{1f}");
    Digest::from_parts(domain, &[("values", joined)])
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OAuth2,
    ApiKey,
}

/// Opaque non-serializing credential reference. The raw reference is hashed
/// and zeroized during construction; no raw material is stored, debug printed,
/// serialized, or placed in a request/receipt.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    kind: SecretKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            kind: self.kind,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.kind == other.kind
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
            .field("credential_revision", &self.credential_revision)
            .field("kind", &self.kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        reference: impl Into<String>,
        scope: &RenderDeploymentScope,
        credential_revision: u64,
        kind: SecretKind,
    ) -> Result<Self> {
        let mut reference = reference.into();
        if reference.is_empty()
            || reference.len() > MAX_SECRET_REFERENCE_BYTES
            || reference.chars().any(char::is_control)
        {
            reference.zeroize();
            return Err(RenderDeploymentError::InvalidSecretReference);
        }
        let credential_revision = match Revision::new(credential_revision) {
            Ok(value) => value,
            Err(error) => {
                reference.zeroize();
                return Err(error);
            }
        };
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "render-secret-reference/v1",
            &[
                ("reference", reference.clone()),
                ("scope", scope_digest.as_str().to_owned()),
                ("credential_revision", credential_revision.get().to_string()),
                ("kind", format!("{kind:?}")),
            ],
        );
        reference.zeroize();
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            kind,
            revoked: false,
        })
    }

    pub fn oauth2(
        reference: impl Into<String>,
        scope: &RenderDeploymentScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new(reference, scope, revision, SecretKind::OAuth2)
    }

    pub fn api_key(
        reference: impl Into<String>,
        scope: &RenderDeploymentScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new(reference, scope, revision, SecretKind::ApiKey)
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
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            return Err(RenderDeploymentError::SecretRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub(crate) fn validate(&self, scope: &RenderDeploymentScope) -> Result<()> {
        if self.revoked || self.scope_digest != scope.digest() {
            return Err(if self.revoked {
                RenderDeploymentError::SecretRevoked
            } else {
                RenderDeploymentError::ScopeMismatch
            });
        }
        self.reference_digest.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn provider_receipt(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderServiceStatus {
    Available,
    Suspended,
    Archived,
    Unknown,
}

impl RenderServiceStatus {
    pub(crate) fn from_wire(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "available" | "active" | "running" => Self::Available,
            "suspended" | "paused" => Self::Suspended,
            "archived" | "deleted" => Self::Archived,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderDeployStatus {
    Created,
    Queued,
    BuildInProgress,
    Live,
    Failed,
    Canceled,
    Deactivated,
    Unknown,
}

impl RenderDeployStatus {
    pub(crate) fn from_wire(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "created" | "new" => Self::Created,
            "queued" => Self::Queued,
            "build_in_progress" | "building" | "preparing" => Self::BuildInProgress,
            "live" | "ready" | "succeeded" => Self::Live,
            "failed" | "error" => Self::Failed,
            "canceled" | "cancelled" => Self::Canceled,
            "deactivated" => Self::Deactivated,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn is_in_progress(self) -> bool {
        matches!(self, Self::Created | Self::Queued | Self::BuildInProgress)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderHealthState {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

impl RenderHealthState {
    pub(crate) fn from_wire(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "healthy" | "passing" | "ok" => Self::Healthy,
            "degraded" | "warning" => Self::Degraded,
            "unhealthy" | "failing" | "failed" => Self::Unhealthy,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderResultState {
    Ready,
    InProgress,
    Failed,
    Canceled,
    Partial,
    AccessLoss,
    RateLimited,
    Timeout,
    NotFound,
    Conflict,
    Tampered,
    StaleRevision,
    PaginationBound,
    PaginationLoop,
    ProviderUnknown,
    RegistrationRevoked,
    ConsentDenied,
    HealthUnknown,
}

impl RenderResultState {
    #[must_use]
    pub const fn is_adoptable(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderHealthProjection {
    pub state: RenderHealthState,
    pub check_count: u32,
    pub passing_count: u32,
    pub last_checked_at: Option<u64>,
    pub detail_digest: Digest,
    pub health_digest: Digest,
}

impl RenderHealthProjection {
    pub(crate) fn new(
        state: RenderHealthState,
        check_count: u32,
        passing_count: u32,
        last_checked_at: Option<u64>,
        detail_digest: Digest,
    ) -> Result<Self> {
        if check_count > MAX_HEALTH_CHECKS || passing_count > check_count {
            return Err(RenderDeploymentError::InvalidResponse);
        }
        let health_digest = Digest::from_parts(
            "render-health-projection/v1",
            &[
                ("state", format!("{state:?}")),
                ("check_count", check_count.to_string()),
                ("passing_count", passing_count.to_string()),
                (
                    "last_checked_at",
                    last_checked_at.map_or_else(String::new, |value| value.to_string()),
                ),
                ("detail", detail_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            state,
            check_count,
            passing_count,
            last_checked_at,
            detail_digest,
            health_digest,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let expected = Self::new(
            self.state,
            self.check_count,
            self.passing_count,
            self.last_checked_at,
            self.detail_digest.clone(),
        )?;
        if expected.health_digest != self.health_digest {
            return Err(RenderDeploymentError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderServiceProjection {
    pub service_id_digest: Digest,
    pub service_uid_digest: Digest,
    pub workspace_id_digest: Digest,
    pub environment_id_digest: Digest,
    pub region_digest: Digest,
    pub status: RenderServiceStatus,
    pub health: RenderHealthProjection,
    pub latest_deploy_id_digest: Option<Digest>,
    pub health_check_path_digest: Option<Digest>,
    pub observed_revision: Revision,
    pub service_digest: Digest,
}

impl RenderServiceProjection {
    pub(crate) fn validate(&self) -> Result<()> {
        self.health.validate()?;
        let expected = Digest::from_parts(
            "render-service-projection/v1",
            &[
                ("service", self.service_id_digest.as_str().to_owned()),
                ("uid", self.service_uid_digest.as_str().to_owned()),
                ("workspace", self.workspace_id_digest.as_str().to_owned()),
                (
                    "environment",
                    self.environment_id_digest.as_str().to_owned(),
                ),
                ("region", self.region_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("health", self.health.health_digest.as_str().to_owned()),
                (
                    "latest_deploy",
                    self.latest_deploy_id_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "health_check_path",
                    self.health_check_path_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("revision", self.observed_revision.get().to_string()),
            ],
        );
        if expected != self.service_digest {
            return Err(RenderDeploymentError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderDeployProjection {
    pub deploy_id_digest: Digest,
    pub service_id_digest: Digest,
    pub environment_id_digest: Digest,
    pub commit_digest: Digest,
    pub status: RenderDeployStatus,
    pub created_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub image_digest: Option<Digest>,
    pub source_digest: Option<Digest>,
    pub health: RenderHealthProjection,
    pub deploy_digest: Digest,
}

impl RenderDeployProjection {
    pub(crate) fn validate(&self) -> Result<()> {
        self.health.validate()?;
        let expected = Digest::from_parts(
            "render-deploy-projection/v1",
            &[
                ("deploy", self.deploy_id_digest.as_str().to_owned()),
                ("service", self.service_id_digest.as_str().to_owned()),
                (
                    "environment",
                    self.environment_id_digest.as_str().to_owned(),
                ),
                ("commit", self.commit_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                (
                    "created_at",
                    self.created_at
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "finished_at",
                    self.finished_at
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "image",
                    self.image_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "source",
                    self.source_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("health", self.health.health_digest.as_str().to_owned()),
            ],
        );
        if expected != self.deploy_digest {
            return Err(RenderDeploymentError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackoffReceipt {
    pub attempt: u8,
    pub retry_after_seconds: u32,
    pub backoff_digest: Digest,
}

impl BackoffReceipt {
    pub(crate) fn new(attempt: u8, retry_after_seconds: u32) -> Self {
        let retry_after_seconds = retry_after_seconds.min(MAX_BACKOFF_SECONDS);
        Self {
            attempt,
            retry_after_seconds,
            backoff_digest: Digest::from_parts(
                "render-rate-limit-backoff/v1",
                &[
                    ("attempt", attempt.to_string()),
                    ("retry_after", retry_after_seconds.to_string()),
                ],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionSnapshot {
    revision: Revision,
    permissions: BTreeSet<String>,
    digest: Digest,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let revision = Revision::new(revision)?;
        let permissions = permissions.into_iter().map(Into::into).collect();
        let snapshot = Self {
            revision,
            permissions,
            digest: Digest::pending(),
        };
        if !LAYER1_PERMISSIONS
            .iter()
            .all(|permission| snapshot.permissions.contains(*permission))
        {
            return Err(RenderDeploymentError::InvalidPermissionSnapshot);
        }
        let mut snapshot = snapshot;
        snapshot.digest = snapshot.compute_digest();
        Ok(snapshot)
    }

    pub fn for_layer_one(revision: u64) -> Result<Self> {
        Self::new(revision, LAYER1_PERMISSIONS)
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision.get() == 0
            || !LAYER1_PERMISSIONS
                .iter()
                .all(|permission| self.permissions.contains(*permission))
            || self.digest != self.compute_digest()
        {
            return Err(RenderDeploymentError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "render-permission-snapshot/v1",
            &[
                ("revision", self.revision.get().to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentScope {
    id_digest: Digest,
    revision: Revision,
    expires_at: u64,
    digest: Digest,
}

impl ConsentScope {
    pub fn new(id: impl AsRef<str>, revision: u64, expires_at: u64) -> Result<Self> {
        if id.as_ref().is_empty() || expires_at == 0 {
            return Err(RenderDeploymentError::InvalidConsent);
        }
        let revision = Revision::new(revision)?;
        let id_digest = Digest::from_text(id.as_ref());
        let digest = Digest::from_parts(
            "render-consent/v1",
            &[
                ("id", id_digest.as_str().to_owned()),
                ("revision", revision.get().to_string()),
                ("expires_at", expires_at.to_string()),
            ],
        );
        Ok(Self {
            id_digest,
            revision,
            expires_at,
            digest,
        })
    }

    pub fn for_layer_one(id: impl AsRef<str>, revision: u64, expires_at: u64) -> Result<Self> {
        Self::new(id, revision, expires_at)
    }

    #[must_use]
    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub const fn is_active_at(&self, observed_at: u64) -> bool {
        observed_at <= self.expires_at
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision.get() == 0 || self.expires_at == 0 {
            return Err(RenderDeploymentError::InvalidConsent);
        }
        let expected = Digest::from_parts(
            "render-consent/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
                ("expires_at", self.expires_at.to_string()),
            ],
        );
        if expected != self.digest {
            return Err(RenderDeploymentError::InvalidConsent);
        }
        Ok(())
    }
}

/// A caller-supplied read fence. The service accepts a read only when the
/// exact Project/Mission/Work Product revisions and registration digests still
/// match the request; it does not refresh or silently widen them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderReadRequest {
    pub scope_digest: Digest,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
}

impl RenderReadRequest {
    pub fn new(
        scope: &RenderDeploymentScope,
        mission_revision: u64,
        work_product_revision: u64,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self> {
        let request = Self {
            scope_digest: scope.digest(),
            mission_revision: Revision::new(mission_revision)?,
            work_product_revision: Revision::new(work_product_revision)?,
            permission_digest,
            consent_digest,
        };
        request.validate_for(scope, &request.permission_digest, &request.consent_digest)?;
        Ok(request)
    }

    pub(crate) fn validate_for(
        &self,
        scope: &RenderDeploymentScope,
        permission_digest: &Digest,
        consent_digest: &Digest,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.mission_revision != scope.mission().revision()
            || self.work_product_revision != scope.work_product().revision()
            || self.permission_digest != *permission_digest
            || self.consent_digest != *consent_digest
        {
            return Err(RenderDeploymentError::StaleRevision);
        }
        self.scope_digest.validate()?;
        self.permission_digest.validate()?;
        self.consent_digest.validate()
    }
}
