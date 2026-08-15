use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{HerokuDeploymentError, Result};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 512;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RETRY_ATTEMPTS: u8 = 3;
pub const MAX_RESOURCES_PER_PAGE: usize = 50;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_BACKOFF_SECONDS: u32 = 60;

pub const LAYER1_PERMISSIONS: [&str; 6] = [
    "heroku:apps.read",
    "heroku:builds.read",
    "heroku:releases.read",
    "heroku:slugs.read",
    "heroku:dynos.read",
    "mission.scope",
];

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A validated SHA-256 digest. Raw provider identifiers and sensitive values
/// cross the evidence boundary only through this type.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(HerokuDeploymentError::InvalidDigest)
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
        Self::from_text("unsealed-heroku-digest")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(HerokuDeploymentError::InvalidDigest)
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
            Err(HerokuDeploymentError::InvalidIdentifier {
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
        Digest::from_parts("heroku-identifier/v1", &[("value", self.0.clone())])
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

pub type AccountId = Identifier;
pub type TeamId = Identifier;
pub type AppId = Identifier;
pub type BuildId = Identifier;
pub type ReleaseId = Identifier;
pub type SlugId = Identifier;
pub type DynoId = Identifier;
pub type HerokuRegion = Identifier;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(HerokuDeploymentError::InvalidRevision { field: "revision" })
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
            .ok_or(HerokuDeploymentError::RevisionOverflow)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Project {
    id: Identifier,
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
            "heroku-project/v1",
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
    id: Identifier,
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
            "heroku-mission/v1",
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
    id: Identifier,
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
            "heroku-work-product/v1",
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

/// Exact Heroku and Hartevo scope. Provider-owned values are reduced to
/// digests before evidence is emitted, while explicit resource allowlists
/// prevent a read from widening beyond the registered Mission.
#[derive(Clone, Eq, PartialEq)]
pub struct HerokuDeploymentScope {
    account_id: AccountId,
    team_id: TeamId,
    app_id: AppId,
    build_id: BuildId,
    release_id: ReleaseId,
    slug_id: SlugId,
    dyno_id: DynoId,
    region: HerokuRegion,
    commit_digest: Digest,
    project: Project,
    mission: Mission,
    work_product: WorkProduct,
    app_allowlist: BTreeSet<AppId>,
    build_allowlist: BTreeSet<BuildId>,
    release_allowlist: BTreeSet<ReleaseId>,
    slug_allowlist: BTreeSet<SlugId>,
    dyno_allowlist: BTreeSet<DynoId>,
}

impl fmt::Debug for HerokuDeploymentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HerokuDeploymentScope")
            .field("scope_digest", &self.digest())
            .field("project", &self.project.digest())
            .field("mission", &self.mission.digest())
            .field("work_product", &self.work_product.digest())
            .finish()
    }
}

impl HerokuDeploymentScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: impl Into<String>,
        team_id: impl Into<String>,
        app_id: impl Into<String>,
        build_id: impl Into<String>,
        release_id: impl Into<String>,
        slug_id: impl Into<String>,
        dyno_id: impl Into<String>,
        region: impl Into<String>,
        commit: impl AsRef<str>,
        project: Project,
        mission: Mission,
        work_product: WorkProduct,
    ) -> Result<Self> {
        let app_id = Identifier::new(app_id)?;
        let build_id = Identifier::new(build_id)?;
        let release_id = Identifier::new(release_id)?;
        let slug_id = Identifier::new(slug_id)?;
        let dyno_id = Identifier::new(dyno_id)?;
        let scope = Self {
            account_id: Identifier::new(account_id)?,
            team_id: Identifier::new(team_id)?,
            app_id: app_id.clone(),
            build_id: build_id.clone(),
            release_id: release_id.clone(),
            slug_id: slug_id.clone(),
            dyno_id: dyno_id.clone(),
            region: Identifier::new(region)?,
            commit_digest: digest_text("commit", commit.as_ref())?,
            project,
            mission,
            work_product,
            app_allowlist: BTreeSet::from([app_id]),
            build_allowlist: BTreeSet::from([build_id]),
            release_allowlist: BTreeSet::from([release_id]),
            slug_allowlist: BTreeSet::from([slug_id]),
            dyno_allowlist: BTreeSet::from([dyno_id]),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn with_allowlists<IA, IB, IR, IS, ID>(
        mut self,
        apps: IA,
        builds: IB,
        releases: IR,
        slugs: IS,
        dynos: ID,
    ) -> Result<Self>
    where
        IA: IntoIterator<Item = AppId>,
        IB: IntoIterator<Item = BuildId>,
        IR: IntoIterator<Item = ReleaseId>,
        IS: IntoIterator<Item = SlugId>,
        ID: IntoIterator<Item = DynoId>,
    {
        self.app_allowlist = apps.into_iter().collect();
        self.build_allowlist = builds.into_iter().collect();
        self.release_allowlist = releases.into_iter().collect();
        self.slug_allowlist = slugs.into_iter().collect();
        self.dyno_allowlist = dynos.into_iter().collect();
        self.validate()?;
        Ok(self)
    }

    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    #[must_use]
    pub fn team_id(&self) -> &TeamId {
        &self.team_id
    }

    #[must_use]
    pub fn app_id(&self) -> &AppId {
        &self.app_id
    }

    #[must_use]
    pub fn build_id(&self) -> &BuildId {
        &self.build_id
    }

    #[must_use]
    pub fn release_id(&self) -> &ReleaseId {
        &self.release_id
    }

    #[must_use]
    pub fn slug_id(&self) -> &SlugId {
        &self.slug_id
    }

    #[must_use]
    pub fn dyno_id(&self) -> &DynoId {
        &self.dyno_id
    }

    #[must_use]
    pub fn region(&self) -> &HerokuRegion {
        &self.region
    }

    #[must_use]
    pub fn commit_digest(&self) -> &Digest {
        &self.commit_digest
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
    pub fn app_allowlist(&self) -> &BTreeSet<AppId> {
        &self.app_allowlist
    }

    #[must_use]
    pub fn build_allowlist(&self) -> &BTreeSet<BuildId> {
        &self.build_allowlist
    }

    #[must_use]
    pub fn release_allowlist(&self) -> &BTreeSet<ReleaseId> {
        &self.release_allowlist
    }

    #[must_use]
    pub fn slug_allowlist(&self) -> &BTreeSet<SlugId> {
        &self.slug_allowlist
    }

    #[must_use]
    pub fn dyno_allowlist(&self) -> &BTreeSet<DynoId> {
        &self.dyno_allowlist
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "heroku-deployment-scope/v1",
            &[
                ("account", self.account_id.digest().as_str().to_owned()),
                ("team", self.team_id.digest().as_str().to_owned()),
                ("app", self.app_id.digest().as_str().to_owned()),
                ("build", self.build_id.digest().as_str().to_owned()),
                ("release", self.release_id.digest().as_str().to_owned()),
                ("slug", self.slug_id.digest().as_str().to_owned()),
                ("dyno", self.dyno_id.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("commit", self.commit_digest.as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                (
                    "apps",
                    digest_identifiers("heroku-app-allowlist/v1", &self.app_allowlist)
                        .as_str()
                        .to_owned(),
                ),
                (
                    "builds",
                    digest_identifiers("heroku-build-allowlist/v1", &self.build_allowlist)
                        .as_str()
                        .to_owned(),
                ),
                (
                    "releases",
                    digest_identifiers("heroku-release-allowlist/v1", &self.release_allowlist)
                        .as_str()
                        .to_owned(),
                ),
                (
                    "slugs",
                    digest_identifiers("heroku-slug-allowlist/v1", &self.slug_allowlist)
                        .as_str()
                        .to_owned(),
                ),
                (
                    "dynos",
                    digest_identifiers("heroku-dyno-allowlist/v1", &self.dyno_allowlist)
                        .as_str()
                        .to_owned(),
                ),
            ],
        )
    }

    #[must_use]
    pub fn app_is_allowed(&self, value: &AppId) -> bool {
        self.app_allowlist.contains(value)
    }

    #[must_use]
    pub fn build_is_allowed(&self, value: &BuildId) -> bool {
        self.build_allowlist.contains(value)
    }

    #[must_use]
    pub fn release_is_allowed(&self, value: &ReleaseId) -> bool {
        self.release_allowlist.contains(value)
    }

    #[must_use]
    pub fn slug_is_allowed(&self, value: &SlugId) -> bool {
        self.slug_allowlist.contains(value)
    }

    #[must_use]
    pub fn dyno_is_allowed(&self, value: &DynoId) -> bool {
        self.dyno_allowlist.contains(value)
    }

    fn validate(&self) -> Result<()> {
        if self.app_allowlist.is_empty()
            || self.build_allowlist.is_empty()
            || self.release_allowlist.is_empty()
            || self.slug_allowlist.is_empty()
            || self.dyno_allowlist.is_empty()
        {
            return Err(HerokuDeploymentError::InvalidScope(
                "empty resource allowlist",
            ));
        }
        if !self.app_is_allowed(&self.app_id)
            || !self.build_is_allowed(&self.build_id)
            || !self.release_is_allowed(&self.release_id)
            || !self.slug_is_allowed(&self.slug_id)
            || !self.dyno_is_allowed(&self.dyno_id)
        {
            return Err(HerokuDeploymentError::InvalidScope(
                "primary resource is not in the explicit allowlist",
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
        return Err(HerokuDeploymentError::InvalidScope(label));
    }
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
    OAuth,
    Token,
}

/// Opaque, non-serializing credential reference. The raw reference is hashed
/// and zeroized during construction; no raw material is retained or emitted.
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

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretReference", 5)?;
        state.serialize_field("referenceDigest", &self.reference_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("credentialRevision", &self.credential_revision)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("revoked", &self.revoked)?;
        state.end()
    }
}

impl SecretReference {
    pub fn new(
        reference: impl Into<String>,
        scope: &HerokuDeploymentScope,
        credential_revision: u64,
        kind: SecretKind,
    ) -> Result<Self> {
        let mut reference = reference.into();
        if reference.is_empty()
            || reference.len() > MAX_SECRET_REFERENCE_BYTES
            || reference.chars().any(char::is_control)
        {
            reference.zeroize();
            return Err(HerokuDeploymentError::InvalidSecretReference);
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
            "heroku-secret-reference/v1",
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

    pub fn oauth(
        reference: impl Into<String>,
        scope: &HerokuDeploymentScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new(reference, scope, revision, SecretKind::OAuth)
    }

    pub fn token(
        reference: impl Into<String>,
        scope: &HerokuDeploymentScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new(reference, scope, revision, SecretKind::Token)
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
            return Err(HerokuDeploymentError::SecretRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub(crate) fn validate(&self, scope: &HerokuDeploymentScope) -> Result<()> {
        if self.revoked {
            return Err(HerokuDeploymentError::SecretRevoked);
        }
        if self.scope_digest != scope.digest() {
            return Err(HerokuDeploymentError::ScopeMismatch);
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
pub enum HerokuAppState {
    Active,
    Maintenance,
    Archived,
    Unknown,
}

impl HerokuAppState {
    pub(crate) fn from_wire(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "active" | "running" => Self::Active,
            "maintenance" | "suspended" => Self::Maintenance,
            "archived" | "deleted" => Self::Archived,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HerokuBuildStatus {
    Pending,
    Building,
    Succeeded,
    Failed,
    Unknown,
}

impl HerokuBuildStatus {
    pub(crate) fn from_wire(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "pending" | "queued" => Self::Pending,
            "building" | "in_progress" | "started" => Self::Building,
            "succeeded" | "successful" | "complete" => Self::Succeeded,
            "failed" | "error" => Self::Failed,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HerokuReleaseStatus {
    Pending,
    Released,
    Failed,
    Unknown,
}

impl HerokuReleaseStatus {
    pub(crate) fn from_wire(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "pending" | "queued" => Self::Pending,
            "released" | "succeeded" | "complete" => Self::Released,
            "failed" | "error" => Self::Failed,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HerokuSlugStatus {
    Ready,
    Pending,
    Unknown,
}

impl HerokuSlugStatus {
    pub(crate) fn from_wire(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "ready" | "available" => Self::Ready,
            "pending" | "building" => Self::Pending,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HerokuDynoState {
    Up,
    Starting,
    Down,
    Crashed,
    Unknown,
}

impl HerokuDynoState {
    pub(crate) fn from_wire(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "up" | "running" => Self::Up,
            "starting" | "pending" => Self::Starting,
            "down" | "stopped" => Self::Down,
            "crashed" | "failed" => Self::Crashed,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HerokuDeploymentState {
    Building,
    Released,
    Failed,
    Unknown,
    Partial,
    Denied,
    RateLimited,
    ProviderUnknown,
    Tampered,
    StaleRevision,
    PaginationLoop,
    PaginationBound,
    RegistrationRevoked,
    ConsentDenied,
    NotFound,
    Conflict,
    Replay,
}

impl HerokuDeploymentState {
    #[must_use]
    pub const fn is_adoptable(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Released | Self::Failed)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HerokuAppProjection {
    pub account_id_digest: Digest,
    pub team_id_digest: Digest,
    pub app_id_digest: Digest,
    pub region_digest: Digest,
    pub state: HerokuAppState,
    pub metadata_digest: Digest,
    pub observed_revision: Revision,
    pub app_digest: Digest,
}

impl HerokuAppProjection {
    pub(crate) fn new(
        account_id_digest: Digest,
        team_id_digest: Digest,
        app_id_digest: Digest,
        region_digest: Digest,
        state: HerokuAppState,
        metadata_digest: Digest,
        observed_revision: Revision,
    ) -> Self {
        let app_digest = Digest::from_parts(
            "heroku-app-projection/v1",
            &[
                ("account", account_id_digest.as_str().to_owned()),
                ("team", team_id_digest.as_str().to_owned()),
                ("app", app_id_digest.as_str().to_owned()),
                ("region", region_digest.as_str().to_owned()),
                ("state", format!("{state:?}")),
                ("metadata", metadata_digest.as_str().to_owned()),
                ("revision", observed_revision.get().to_string()),
            ],
        );
        Self {
            account_id_digest,
            team_id_digest,
            app_id_digest,
            region_digest,
            state,
            metadata_digest,
            observed_revision,
            app_digest,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let expected = Self::new(
            self.account_id_digest.clone(),
            self.team_id_digest.clone(),
            self.app_id_digest.clone(),
            self.region_digest.clone(),
            self.state,
            self.metadata_digest.clone(),
            self.observed_revision,
        );
        if expected.app_digest != self.app_digest {
            return Err(HerokuDeploymentError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HerokuBuildProjection {
    pub app_id_digest: Digest,
    pub build_id_digest: Digest,
    pub status: HerokuBuildStatus,
    pub commit_digest: Digest,
    pub metadata_digest: Digest,
    pub observed_revision: Revision,
    pub build_digest: Digest,
}

impl HerokuBuildProjection {
    pub(crate) fn new(
        app_id_digest: Digest,
        build_id_digest: Digest,
        status: HerokuBuildStatus,
        commit_digest: Digest,
        metadata_digest: Digest,
        observed_revision: Revision,
    ) -> Self {
        let build_digest = Digest::from_parts(
            "heroku-build-projection/v1",
            &[
                ("app", app_id_digest.as_str().to_owned()),
                ("build", build_id_digest.as_str().to_owned()),
                ("status", format!("{status:?}")),
                ("commit", commit_digest.as_str().to_owned()),
                ("metadata", metadata_digest.as_str().to_owned()),
                ("revision", observed_revision.get().to_string()),
            ],
        );
        Self {
            app_id_digest,
            build_id_digest,
            status,
            commit_digest,
            metadata_digest,
            observed_revision,
            build_digest,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let expected = Self::new(
            self.app_id_digest.clone(),
            self.build_id_digest.clone(),
            self.status,
            self.commit_digest.clone(),
            self.metadata_digest.clone(),
            self.observed_revision,
        );
        if expected.build_digest != self.build_digest {
            return Err(HerokuDeploymentError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HerokuReleaseProjection {
    pub app_id_digest: Digest,
    pub release_id_digest: Digest,
    pub version: u64,
    pub status: HerokuReleaseStatus,
    pub commit_digest: Digest,
    pub metadata_digest: Digest,
    pub observed_revision: Revision,
    pub release_digest: Digest,
}

impl HerokuReleaseProjection {
    pub(crate) fn new(
        app_id_digest: Digest,
        release_id_digest: Digest,
        version: u64,
        status: HerokuReleaseStatus,
        commit_digest: Digest,
        metadata_digest: Digest,
        observed_revision: Revision,
    ) -> Self {
        let release_digest = Digest::from_parts(
            "heroku-release-projection/v1",
            &[
                ("app", app_id_digest.as_str().to_owned()),
                ("release", release_id_digest.as_str().to_owned()),
                ("version", version.to_string()),
                ("status", format!("{status:?}")),
                ("commit", commit_digest.as_str().to_owned()),
                ("metadata", metadata_digest.as_str().to_owned()),
                ("revision", observed_revision.get().to_string()),
            ],
        );
        Self {
            app_id_digest,
            release_id_digest,
            version,
            status,
            commit_digest,
            metadata_digest,
            observed_revision,
            release_digest,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let expected = Self::new(
            self.app_id_digest.clone(),
            self.release_id_digest.clone(),
            self.version,
            self.status,
            self.commit_digest.clone(),
            self.metadata_digest.clone(),
            self.observed_revision,
        );
        if expected.release_digest != self.release_digest {
            return Err(HerokuDeploymentError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HerokuSlugProjection {
    pub app_id_digest: Digest,
    pub slug_id_digest: Digest,
    pub checksum_digest: Digest,
    pub size_bytes: u64,
    pub status: HerokuSlugStatus,
    pub metadata_digest: Digest,
    pub observed_revision: Revision,
    pub slug_digest: Digest,
}

impl HerokuSlugProjection {
    pub(crate) fn new(
        app_id_digest: Digest,
        slug_id_digest: Digest,
        checksum_digest: Digest,
        size_bytes: u64,
        status: HerokuSlugStatus,
        metadata_digest: Digest,
        observed_revision: Revision,
    ) -> Self {
        let slug_digest = Digest::from_parts(
            "heroku-slug-projection/v1",
            &[
                ("app", app_id_digest.as_str().to_owned()),
                ("slug", slug_id_digest.as_str().to_owned()),
                ("checksum", checksum_digest.as_str().to_owned()),
                ("size", size_bytes.to_string()),
                ("status", format!("{status:?}")),
                ("metadata", metadata_digest.as_str().to_owned()),
                ("revision", observed_revision.get().to_string()),
            ],
        );
        Self {
            app_id_digest,
            slug_id_digest,
            checksum_digest,
            size_bytes,
            status,
            metadata_digest,
            observed_revision,
            slug_digest,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let expected = Self::new(
            self.app_id_digest.clone(),
            self.slug_id_digest.clone(),
            self.checksum_digest.clone(),
            self.size_bytes,
            self.status,
            self.metadata_digest.clone(),
            self.observed_revision,
        );
        if expected.slug_digest != self.slug_digest {
            return Err(HerokuDeploymentError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HerokuDynoProjection {
    pub app_id_digest: Digest,
    pub dyno_id_digest: Digest,
    pub release_id_digest: Digest,
    pub region_digest: Digest,
    pub state: HerokuDynoState,
    pub metadata_digest: Digest,
    pub observed_revision: Revision,
    pub dyno_digest: Digest,
}

impl HerokuDynoProjection {
    pub(crate) fn new(
        app_id_digest: Digest,
        dyno_id_digest: Digest,
        release_id_digest: Digest,
        region_digest: Digest,
        state: HerokuDynoState,
        metadata_digest: Digest,
        observed_revision: Revision,
    ) -> Self {
        let dyno_digest = Digest::from_parts(
            "heroku-dyno-projection/v1",
            &[
                ("app", app_id_digest.as_str().to_owned()),
                ("dyno", dyno_id_digest.as_str().to_owned()),
                ("release", release_id_digest.as_str().to_owned()),
                ("region", region_digest.as_str().to_owned()),
                ("state", format!("{state:?}")),
                ("metadata", metadata_digest.as_str().to_owned()),
                ("revision", observed_revision.get().to_string()),
            ],
        );
        Self {
            app_id_digest,
            dyno_id_digest,
            release_id_digest,
            region_digest,
            state,
            metadata_digest,
            observed_revision,
            dyno_digest,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let expected = Self::new(
            self.app_id_digest.clone(),
            self.dyno_id_digest.clone(),
            self.release_id_digest.clone(),
            self.region_digest.clone(),
            self.state,
            self.metadata_digest.clone(),
            self.observed_revision,
        );
        if expected.dyno_digest != self.dyno_digest {
            return Err(HerokuDeploymentError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackoffReceipt {
    pub attempt: u8,
    pub retry_after_seconds: u32,
}

impl BackoffReceipt {
    pub(crate) const fn new(attempt: u8, retry_after_seconds: u32) -> Self {
        Self {
            attempt,
            retry_after_seconds,
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
        let permissions = permissions
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        if permissions.is_empty()
            || permissions.iter().any(|value| {
                value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.contains('\n')
            })
        {
            return Err(HerokuDeploymentError::InvalidPermissionSnapshot);
        }
        let digest = Digest::from_parts(
            "heroku-permission-snapshot/v1",
            &[
                ("revision", revision.get().to_string()),
                (
                    "permissions",
                    permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
            ],
        );
        Ok(Self {
            revision,
            permissions,
            digest,
        })
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
        let expected = Self::new(self.revision.get(), self.permissions.clone())?;
        if expected.digest != self.digest {
            return Err(HerokuDeploymentError::InvalidPermissionSnapshot);
        }
        Ok(())
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
        let id = id.as_ref();
        if !valid_identifier(id) || expires_at == 0 {
            return Err(HerokuDeploymentError::InvalidConsent);
        }
        let revision = Revision::new(revision)?;
        let id_digest = Digest::from_text(id);
        let digest = Digest::from_parts(
            "heroku-consent/v1",
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

    pub(crate) fn validate_at(&self, observed_at: u64) -> Result<()> {
        if observed_at > self.expires_at {
            return Err(HerokuDeploymentError::Expired);
        }
        let expected = Digest::from_parts(
            "heroku-consent/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
                ("expires_at", self.expires_at.to_string()),
            ],
        );
        if expected != self.digest {
            return Err(HerokuDeploymentError::InvalidConsent);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HerokuReadRequest {
    pub scope_digest: Digest,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub registration_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
}

impl HerokuReadRequest {
    pub fn new(
        scope: &HerokuDeploymentScope,
        registration_digest: Digest,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Self {
        Self {
            scope_digest: scope.digest(),
            project_revision: scope.project().revision(),
            mission_revision: scope.mission().revision(),
            work_product_revision: scope.work_product().revision(),
            registration_digest,
            permission_digest,
            consent_digest,
        }
    }

    pub(crate) fn validate_for(
        &self,
        scope: &HerokuDeploymentScope,
        registration_digest: &Digest,
        permission_digest: &Digest,
        consent_digest: &Digest,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.project_revision != scope.project().revision()
            || self.mission_revision != scope.mission().revision()
            || self.work_product_revision != scope.work_product().revision()
        {
            return Err(HerokuDeploymentError::StaleRevision);
        }
        if &self.registration_digest != registration_digest
            || &self.permission_digest != permission_digest
            || &self.consent_digest != consent_digest
        {
            return Err(HerokuDeploymentError::TamperedEvidence);
        }
        Ok(())
    }
}

pub fn idempotency_digest(value: impl AsRef<str>) -> Result<Digest> {
    let value = value.as_ref();
    if !valid_identifier(value) || value.len() > 128 {
        return Err(HerokuDeploymentError::InvalidIdentifier {
            field: "idempotency_key",
        });
    }
    Ok(Digest::from_parts(
        "heroku-idempotency/v1",
        &[("key", value.to_owned())],
    ))
}
