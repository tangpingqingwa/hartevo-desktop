use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{NetlifyDeploymentError, Result};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 512;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_LINK_HEADER_BYTES: usize = 4_096;
pub const MAX_PAGES: u16 = 4;
pub const MAX_POLL_ATTEMPTS: u8 = 3;
pub const MAX_DEPLOYS_PER_PAGE: usize = 50;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_MANIFEST_FILES: u64 = 100_000;
pub const MAX_MANIFEST_BYTES: u64 = 1_099_511_627_776;

pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "netlify:sites.read",
    "netlify:deploys.read",
    "netlify:deploys.files.read_metadata",
    "mission.scope",
];

pub type NetlifyTeamId = Identifier;
pub type NetlifySiteId = Identifier;
pub type NetlifyDeployId = Identifier;
pub type ProjectId = Identifier;
pub type MissionId = Identifier;
pub type WorkProductId = Identifier;

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A validated SHA-256 digest used as the only representation of sensitive or
/// provider-owned identifiers in evidence.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(NetlifyDeploymentError::InvalidDigest)
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
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_component(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(value.len().to_string().as_bytes());
    bytes.push(b':');
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(b'|');
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Identifier(String);

impl Identifier {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_identifier(&value) {
            Ok(Self(value))
        } else {
            Err(NetlifyDeploymentError::InvalidIdentifier {
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
        Digest::from_parts("netlify-identifier/v1", &[("value", self.0.clone())])
    }
}

impl AsRef<str> for Identifier {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(NetlifyDeploymentError::InvalidRevision { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! identity_type {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            id: Identifier,
            revision: Revision,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                Ok(Self {
                    id: Identifier::new(id)?,
                    revision: Revision::new(revision)?,
                })
            }

            #[must_use]
            pub fn id(&self) -> &Identifier {
                &self.id
            }

            #[must_use]
            pub const fn revision(&self) -> Revision {
                self.revision
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("netlify-", $label, "/v1"),
                    &[
                        ("id", self.id.digest().as_str().to_owned()),
                        ("revision", self.revision.get().to_string()),
                    ],
                )
            }
        }
    };
}

identity_type!(Project, "project");
identity_type!(Mission, "mission");
identity_type!(WorkProduct, "work-product");

pub type ProjectBinding = Project;
pub type MissionBinding = Mission;
pub type WorkProductBinding = WorkProduct;
pub type ProjectRevision = Revision;
pub type MissionRevision = Revision;
pub type WorkProductRevision = Revision;

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
            id_digest: value.id().digest(),
            revision: value.revision(),
        }
    }
}

impl From<&Mission> for MissionProjection {
    fn from(value: &Mission) -> Self {
        Self {
            id_digest: value.id().digest(),
            revision: value.revision(),
        }
    }
}

impl From<&WorkProduct> for WorkProductProjection {
    fn from(value: &WorkProduct) -> Self {
        Self {
            id_digest: value.id().digest(),
            revision: value.revision(),
        }
    }
}

/// Exact provider scope. Raw branch, commit, and context values are converted
/// to digests at construction and are not retained in evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetlifyDeploymentScope {
    team_id: NetlifyTeamId,
    site_id: NetlifySiteId,
    deploy_id: NetlifyDeployId,
    branch_digest: Digest,
    commit_digest: Digest,
    context_digest: Digest,
    project: Project,
    mission: Mission,
    work_product: WorkProduct,
    site_allowlist: BTreeSet<NetlifySiteId>,
    deploy_allowlist: BTreeSet<NetlifyDeployId>,
}

impl NetlifyDeploymentScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        team_id: impl Into<String>,
        site_id: impl Into<String>,
        deploy_id: impl Into<String>,
        branch: impl AsRef<str>,
        commit: impl AsRef<str>,
        context: impl AsRef<str>,
        project: Project,
        mission: Mission,
        work_product: WorkProduct,
    ) -> Result<Self> {
        let site_id = Identifier::new(site_id)?;
        let deploy_id = Identifier::new(deploy_id)?;
        let scope = Self {
            team_id: Identifier::new(team_id)?,
            site_id: site_id.clone(),
            deploy_id: deploy_id.clone(),
            branch_digest: digest_text("branch", branch.as_ref())?,
            commit_digest: digest_text("commit", commit.as_ref())?,
            context_digest: digest_text("context", context.as_ref())?,
            project,
            mission,
            work_product,
            site_allowlist: BTreeSet::from([site_id]),
            deploy_allowlist: BTreeSet::from([deploy_id]),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn with_allowlists<I, J>(mut self, site_allowlist: I, deploy_allowlist: J) -> Result<Self>
    where
        I: IntoIterator<Item = NetlifySiteId>,
        J: IntoIterator<Item = NetlifyDeployId>,
    {
        self.site_allowlist = site_allowlist.into_iter().collect();
        self.deploy_allowlist = deploy_allowlist.into_iter().collect();
        self.validate()?;
        Ok(self)
    }

    #[must_use]
    pub fn team_id(&self) -> &NetlifyTeamId {
        &self.team_id
    }

    #[must_use]
    pub fn site_id(&self) -> &NetlifySiteId {
        &self.site_id
    }

    #[must_use]
    pub fn deploy_id(&self) -> &NetlifyDeployId {
        &self.deploy_id
    }

    #[must_use]
    pub fn branch_digest(&self) -> &Digest {
        &self.branch_digest
    }

    #[must_use]
    pub fn commit_digest(&self) -> &Digest {
        &self.commit_digest
    }

    #[must_use]
    pub fn context_digest(&self) -> &Digest {
        &self.context_digest
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
    pub fn site_allowlist(&self) -> &BTreeSet<NetlifySiteId> {
        &self.site_allowlist
    }

    #[must_use]
    pub fn deploy_allowlist(&self) -> &BTreeSet<NetlifyDeployId> {
        &self.deploy_allowlist
    }

    #[must_use]
    pub fn site_allowlist_digest(&self) -> Digest {
        digest_identifiers("netlify-site-allowlist/v1", &self.site_allowlist)
    }

    #[must_use]
    pub fn deploy_allowlist_digest(&self) -> Digest {
        digest_identifiers("netlify-deploy-allowlist/v1", &self.deploy_allowlist)
    }

    #[must_use]
    pub fn site_is_allowed(&self, site_id: &NetlifySiteId) -> bool {
        self.site_allowlist.contains(site_id)
    }

    #[must_use]
    pub fn deploy_is_allowed(&self, deploy_id: &NetlifyDeployId) -> bool {
        self.deploy_allowlist.contains(deploy_id)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "netlify-deployment-scope/v1",
            &[
                ("team", self.team_id.digest().as_str().to_owned()),
                ("site", self.site_id.digest().as_str().to_owned()),
                ("deploy", self.deploy_id.digest().as_str().to_owned()),
                ("branch", self.branch_digest.as_str().to_owned()),
                ("commit", self.commit_digest.as_str().to_owned()),
                ("context", self.context_digest.as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                ("sites", self.site_allowlist_digest().as_str().to_owned()),
                (
                    "deploys",
                    self.deploy_allowlist_digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.site_allowlist.is_empty() || self.deploy_allowlist.is_empty() {
            return Err(NetlifyDeploymentError::InvalidScope("empty allowlist"));
        }
        if !self.site_is_allowed(&self.site_id) {
            return Err(NetlifyDeploymentError::InvalidScope(
                "site is not allowlisted",
            ));
        }
        if !self.deploy_is_allowed(&self.deploy_id) {
            return Err(NetlifyDeploymentError::InvalidScope(
                "deploy is not allowlisted",
            ));
        }
        for site in &self.site_allowlist {
            Identifier::new(site.as_str().to_owned())?;
        }
        for deploy in &self.deploy_allowlist {
            Identifier::new(deploy.as_str().to_owned())?;
        }
        Ok(())
    }
}

fn digest_text(label: &'static str, value: &str) -> Result<Digest> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(NetlifyDeploymentError::InvalidScope(label));
    }
    Ok(Digest::from_parts(
        &format!("netlify-{label}/v1"),
        &[("value", value.to_owned())],
    ))
}

fn digest_identifiers<T: AsRef<str> + Ord>(domain: &str, values: &BTreeSet<T>) -> Digest {
    let joined = values
        .iter()
        .map(|value| value.as_ref().to_owned())
        .collect::<Vec<_>>()
        .join("\n");
    Digest::from_parts(domain, &[("values", joined)])
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OAuth2,
    PersonalToken,
}

impl SecretKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OAuth2 => "oauth2",
            Self::PersonalToken => "personal_token",
        }
    }
}

/// Opaque host-owned credential reference. The caller's handle is hashed and
/// zeroized immediately; this type intentionally does not implement Serialize.
#[derive(Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl Into<String>,
        scope: &NetlifyDeploymentScope,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::with_kind(
            SecretKind::OAuth2,
            opaque_handle,
            scope,
            credential_revision,
        )
    }

    pub fn oauth(
        opaque_handle: impl Into<String>,
        scope: &NetlifyDeploymentScope,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::with_kind(
            SecretKind::OAuth2,
            opaque_handle,
            scope,
            credential_revision,
        )
    }

    pub fn personal_token(
        opaque_handle: impl Into<String>,
        scope: &NetlifyDeploymentScope,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::with_kind(
            SecretKind::PersonalToken,
            opaque_handle,
            scope,
            credential_revision,
        )
    }

    pub fn with_kind(
        kind: SecretKind,
        opaque_handle: impl Into<String>,
        scope: &NetlifyDeploymentScope,
        credential_revision: u64,
    ) -> Result<Self> {
        let mut opaque_handle = opaque_handle.into();
        let valid = !opaque_handle.is_empty()
            && opaque_handle.len() <= MAX_SECRET_REFERENCE_BYTES
            && opaque_handle.trim() == opaque_handle
            && !opaque_handle.chars().any(char::is_control);
        if !valid {
            opaque_handle.zeroize();
            return Err(NetlifyDeploymentError::InvalidSecretReference);
        }
        let revision = match Revision::new(credential_revision) {
            Ok(revision) => revision,
            Err(error) => {
                opaque_handle.zeroize();
                return Err(error);
            }
        };
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "netlify-secret-reference/v1",
            &[
                ("kind", kind.as_str().to_owned()),
                ("handle", opaque_handle.clone()),
                ("scope", scope_digest.as_str().to_owned()),
                ("revision", revision.get().to_string()),
            ],
        );
        opaque_handle.zeroize();
        Ok(Self {
            kind,
            reference_digest,
            scope_digest,
            credential_revision: revision,
            revoked: false,
        })
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
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(NetlifyDeploymentError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub(crate) fn validate(&self, scope: &NetlifyDeploymentScope) -> Result<()> {
        if self.revoked
            || self.credential_revision.get() == 0
            || self.scope_digest != scope.digest()
        {
            return Err(NetlifyDeploymentError::InvalidSecretReference);
        }
        Digest::parse(self.reference_digest.as_str().to_owned()).map(|_| ())
    }
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
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
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpaqueCursor {
    digest: Digest,
}

impl OpaqueCursor {
    pub fn from_token(token: impl Into<String>) -> Result<Self> {
        let mut token = token.into();
        let valid = !token.is_empty()
            && token.len() <= MAX_CURSOR_BYTES
            && !token.chars().any(char::is_control);
        if !valid {
            token.zeroize();
            return Err(NetlifyDeploymentError::InvalidResponse);
        }
        let digest =
            Digest::from_parts("netlify-pagination-cursor/v1", &[("token", token.clone())]);
        token.zeroize();
        Ok(Self { digest })
    }

    pub(crate) fn from_digest(digest: Digest) -> Self {
        Self { digest }
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetlifyDeploymentState {
    New,
    Preparing,
    Prepared,
    Uploading,
    Uploaded,
    Ready,
    Error,
    Canceled,
    Unknown,
}

impl NetlifyDeploymentState {
    #[must_use]
    pub fn from_provider(value: &str) -> Self {
        match value {
            "new" => Self::New,
            "preparing" => Self::Preparing,
            "prepared" => Self::Prepared,
            "uploading" => Self::Uploading,
            "uploaded" => Self::Uploaded,
            "ready" => Self::Ready,
            "error" => Self::Error,
            "canceled" => Self::Canceled,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Preparing => "preparing",
            Self::Prepared => "prepared",
            Self::Uploading => "uploading",
            Self::Uploaded => "uploaded",
            Self::Ready => "ready",
            Self::Error => "error",
            Self::Canceled => "canceled",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(
            self,
            Self::New | Self::Preparing | Self::Prepared | Self::Uploading | Self::Uploaded
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetlifyDeploymentEvidenceState {
    New,
    Preparing,
    Prepared,
    Uploading,
    Uploaded,
    Ready,
    Error,
    Canceled,
    Unknown,
    Partial,
    Expired,
    NotFound,
    AccessLoss,
    Throttled,
    Conflict,
    Timeout,
    StaleCommit,
    Tampered,
    ProviderUnknown,
    RegistrationRevoked,
}

impl From<&NetlifyDeploymentState> for NetlifyDeploymentEvidenceState {
    fn from(value: &NetlifyDeploymentState) -> Self {
        match value {
            NetlifyDeploymentState::New => Self::New,
            NetlifyDeploymentState::Preparing => Self::Preparing,
            NetlifyDeploymentState::Prepared => Self::Prepared,
            NetlifyDeploymentState::Uploading => Self::Uploading,
            NetlifyDeploymentState::Uploaded => Self::Uploaded,
            NetlifyDeploymentState::Ready => Self::Ready,
            NetlifyDeploymentState::Error => Self::Error,
            NetlifyDeploymentState::Canceled => Self::Canceled,
            NetlifyDeploymentState::Unknown => Self::Unknown,
        }
    }
}

impl NetlifyDeploymentEvidenceState {
    #[must_use]
    pub const fn is_preview_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileManifestMetadata {
    pub file_count: u64,
    pub total_bytes: u64,
    pub manifest_digest: Digest,
    pub truncated: bool,
}

impl FileManifestMetadata {
    pub fn new(
        file_count: u64,
        total_bytes: u64,
        manifest_digest: impl Into<String>,
        truncated: bool,
    ) -> Result<Self> {
        let manifest_digest = Digest::parse(manifest_digest.into())?;
        let metadata = Self {
            file_count,
            total_bytes,
            manifest_digest,
            truncated,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.file_count > MAX_MANIFEST_FILES || self.total_bytes > MAX_MANIFEST_BYTES {
            return Err(NetlifyDeploymentError::InvalidResponse);
        }
        Digest::parse(self.manifest_digest.as_str().to_owned()).map(|_| ())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "netlify-file-manifest-metadata/v1",
            &[
                ("count", self.file_count.to_string()),
                ("bytes", self.total_bytes.to_string()),
                ("manifest", self.manifest_digest.as_str().to_owned()),
                ("truncated", self.truncated.to_string()),
            ],
        )
    }
}

/// Safe deployment metadata projection. Provider-owned names, URL text, and
/// source identity are represented by digests; no raw file data is retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetlifyDeploymentMetadata {
    pub site_id_digest: Digest,
    pub deploy_id_digest: Digest,
    pub state: NetlifyDeploymentState,
    pub branch_digest: Digest,
    pub commit_digest: Digest,
    pub context_digest: Digest,
    pub deploy_url_digest: Option<Digest>,
    pub deploy_url_is_verified: bool,
    pub file_manifest: FileManifestMetadata,
    pub expires_at: Option<u64>,
}

impl NetlifyDeploymentMetadata {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_wire(
        site_id: &str,
        deploy_id: &str,
        state: &str,
        branch: &str,
        commit: &str,
        context: &str,
        deploy_url: Option<&str>,
        file_manifest: FileManifestMetadata,
        expires_at: Option<u64>,
    ) -> Result<Self> {
        let site_id = Identifier::new(site_id.to_owned())?;
        let deploy_id = Identifier::new(deploy_id.to_owned())?;
        let branch_digest = digest_text("branch", branch)?;
        let commit_digest = digest_text("commit", commit)?;
        let context_digest = digest_text("context", context)?;
        let deploy_url_digest = deploy_url
            .map(|url| digest_text("deploy-url", url))
            .transpose()?;
        if expires_at == Some(0) {
            return Err(NetlifyDeploymentError::InvalidResponse);
        }
        file_manifest.validate()?;
        Ok(Self {
            site_id_digest: site_id.digest(),
            deploy_id_digest: deploy_id.digest(),
            state: NetlifyDeploymentState::from_provider(state),
            branch_digest,
            commit_digest,
            context_digest,
            deploy_url_digest,
            deploy_url_is_verified: false,
            file_manifest,
            expires_at,
        })
    }

    #[must_use]
    pub fn identity_digest(&self) -> Digest {
        Digest::from_parts(
            "netlify-deployment-identity/v1",
            &[
                ("site", self.site_id_digest.as_str().to_owned()),
                ("deploy", self.deploy_id_digest.as_str().to_owned()),
                ("branch", self.branch_digest.as_str().to_owned()),
                ("commit", self.commit_digest.as_str().to_owned()),
                ("context", self.context_digest.as_str().to_owned()),
            ],
        )
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "netlify-deployment-metadata/v1",
            &[
                ("identity", self.identity_digest().as_str().to_owned()),
                ("state", self.state.as_str().to_owned()),
                (
                    "url",
                    self.deploy_url_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("url_verified", self.deploy_url_is_verified.to_string()),
                ("manifest", self.file_manifest.digest().as_str().to_owned()),
                (
                    "expires_at",
                    self.expires_at
                        .map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        )
    }

    #[must_use]
    pub fn is_expired_at(&self, observed_at: u64) -> bool {
        self.expires_at
            .is_some_and(|expires_at| observed_at >= expires_at)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentProjection {
    pub site_id_digest: Digest,
    pub deploy_id_digest: Digest,
    pub state: NetlifyDeploymentState,
    pub branch_digest: Digest,
    pub commit_digest: Digest,
    pub context_digest: Digest,
    pub deploy_url_digest: Option<Digest>,
    pub deploy_url_is_verified: bool,
    pub file_manifest: FileManifestMetadata,
    pub expires_at: Option<u64>,
    pub metadata_digest: Digest,
}

impl From<&NetlifyDeploymentMetadata> for DeploymentProjection {
    fn from(value: &NetlifyDeploymentMetadata) -> Self {
        Self {
            site_id_digest: value.site_id_digest.clone(),
            deploy_id_digest: value.deploy_id_digest.clone(),
            state: value.state.clone(),
            branch_digest: value.branch_digest.clone(),
            commit_digest: value.commit_digest.clone(),
            context_digest: value.context_digest.clone(),
            deploy_url_digest: value.deploy_url_digest.clone(),
            deploy_url_is_verified: value.deploy_url_is_verified,
            file_manifest: value.file_manifest.clone(),
            expires_at: value.expires_at,
            metadata_digest: value.digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: Revision,
    pub permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let snapshot = Self {
            revision: Revision::new(revision)?,
            permissions: permissions.into_iter().map(Into::into).collect(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn for_layer_one(revision: u64) -> Result<Self> {
        Self::new(revision, LAYER1_PERMISSIONS)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "netlify-permissions/v1",
            &[
                ("revision", self.revision.get().to_string()),
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
        if self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            Err(NetlifyDeploymentError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScope {
    id_digest: Digest,
    revision: Revision,
    permissions: BTreeSet<String>,
    expires_at: u64,
    revoked: bool,
}

impl ConsentScope {
    pub fn new<I, S>(
        id: impl Into<String>,
        revision: u64,
        permissions: I,
        expires_at: u64,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let id = id.into();
        if id.is_empty() || id.len() > MAX_IDENTIFIER_BYTES || expires_at == 0 {
            return Err(NetlifyDeploymentError::InvalidConsent);
        }
        let consent = Self {
            id_digest: Digest::from_text(id),
            revision: Revision::new(revision)?,
            permissions: permissions.into_iter().map(Into::into).collect(),
            expires_at,
            revoked: false,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn for_layer_one(id: impl Into<String>, revision: u64, expires_at: u64) -> Result<Self> {
        Self::new(id, revision, LAYER1_PERMISSIONS, expires_at)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "netlify-consent/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("expires_at", self.expires_at.to_string()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
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
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    #[must_use]
    pub fn is_active_at(&self, observed_at: u64) -> bool {
        !self.revoked && observed_at < self.expires_at
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(NetlifyDeploymentError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            Err(NetlifyDeploymentError::InvalidConsent)
        } else {
            Ok(())
        }
    }
}
