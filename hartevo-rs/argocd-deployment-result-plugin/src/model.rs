use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{ArgoCdDeploymentError, Result};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 512;
pub const MAX_RESOURCE_NODES: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_RETRY_ATTEMPTS: u8 = 3;
pub const MAX_BACKOFF_SECONDS: u32 = 60;

pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "argocd:applications.read",
    "argocd:resource-tree.read",
    "argocd:sync-status.read",
    "argocd:operation.read",
    "mission.scope",
];

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A validated SHA-256 digest. Provider identifiers and sensitive values cross
/// the evidence boundary only as this type.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ArgoCdDeploymentError::InvalidDigest)
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
        Self::from_text("unsealed-argocd-digest")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(ArgoCdDeploymentError::InvalidDigest)
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
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+' | b'%')
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
            Err(ArgoCdDeploymentError::InvalidIdentifier {
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
        Digest::from_parts("argocd-identifier/v1", &[("value", self.0.clone())])
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
    ArgoCdInstanceId,
    ArgoCdProjectId,
    ArgoCdApplicationId,
    ArgoCdClusterId,
    ArgoCdNamespace,
    ArgoCdTargetRevision,
    ArgoCdSyncOperationId,
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
            Err(ArgoCdDeploymentError::InvalidRevision { field: "revision" })
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
            .ok_or(ArgoCdDeploymentError::RevisionOverflow)
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
            "argocd-hartevo-project/v1",
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
            "argocd-mission/v1",
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
            "argocd-work-product/v1",
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

/// Exact Argo CD plus Hartevo scope. Raw values are retained only inside the
/// typed registration boundary and every evidence projection is digest-only.
#[derive(Clone, Eq, PartialEq)]
pub struct ArgoCdDeploymentScope {
    pub(crate) instance: ArgoCdInstanceId,
    pub(crate) project: ArgoCdProjectId,
    pub(crate) application: ArgoCdApplicationId,
    pub(crate) cluster: ArgoCdClusterId,
    pub(crate) namespace: ArgoCdNamespace,
    pub(crate) target_revision: ArgoCdTargetRevision,
    pub(crate) sync_operation: ArgoCdSyncOperationId,
    pub(crate) project_context: Project,
    pub(crate) mission: Mission,
    pub(crate) work_product: WorkProduct,
    pub(crate) application_allowlist: BTreeSet<ArgoCdApplicationId>,
}

impl fmt::Debug for ArgoCdDeploymentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArgoCdDeploymentScope")
            .field("scope_digest", &self.digest())
            .field("project", &self.project.digest())
            .field("application", &self.application.digest())
            .field("cluster", &self.cluster.digest())
            .field("target_revision", &self.target_revision.digest())
            .field("sync_operation", &self.sync_operation.digest())
            .field("project_context", &self.project_context.digest())
            .field("mission", &self.mission.digest())
            .field("work_product", &self.work_product.digest())
            .finish_non_exhaustive()
    }
}

impl ArgoCdDeploymentScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance: impl Into<String>,
        project: impl Into<String>,
        application: impl Into<String>,
        cluster: impl Into<String>,
        namespace: impl Into<String>,
        target_revision: impl Into<String>,
        sync_operation: impl Into<String>,
        project_context: Project,
        mission: Mission,
        work_product: WorkProduct,
    ) -> Result<Self> {
        let application = Identifier::new(application)?;
        let project = Identifier::new(project)?;
        let namespace = Identifier::new(namespace)?;
        let sync_operation = Identifier::new(sync_operation)?;
        if !valid_path_segment(project.as_str())
            || !valid_path_segment(application.as_str())
            || !valid_path_segment(namespace.as_str())
            || !valid_path_segment(sync_operation.as_str())
        {
            return Err(ArgoCdDeploymentError::InvalidScope(
                "path-segment scope contains a slash",
            ));
        }
        let scope = Self {
            instance: Identifier::new(instance)?,
            project,
            application: application.clone(),
            cluster: Identifier::new(cluster)?,
            namespace,
            target_revision: Identifier::new(target_revision)?,
            sync_operation,
            project_context,
            mission,
            work_product,
            application_allowlist: BTreeSet::from([application]),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn with_application_allowlist<I>(mut self, application_allowlist: I) -> Result<Self>
    where
        I: IntoIterator<Item = ArgoCdApplicationId>,
    {
        self.application_allowlist = application_allowlist.into_iter().collect();
        self.validate()?;
        Ok(self)
    }

    #[must_use]
    pub fn instance(&self) -> &ArgoCdInstanceId {
        &self.instance
    }

    #[must_use]
    pub fn project(&self) -> &ArgoCdProjectId {
        &self.project
    }

    #[must_use]
    pub fn argocd_project(&self) -> &ArgoCdProjectId {
        &self.project
    }

    #[must_use]
    pub fn application(&self) -> &ArgoCdApplicationId {
        &self.application
    }

    #[must_use]
    pub fn cluster(&self) -> &ArgoCdClusterId {
        &self.cluster
    }

    #[must_use]
    pub fn namespace(&self) -> &ArgoCdNamespace {
        &self.namespace
    }

    #[must_use]
    pub fn target_revision(&self) -> &ArgoCdTargetRevision {
        &self.target_revision
    }

    #[must_use]
    pub fn sync_operation(&self) -> &ArgoCdSyncOperationId {
        &self.sync_operation
    }

    #[must_use]
    pub fn project_context(&self) -> &Project {
        &self.project_context
    }

    #[must_use]
    pub fn hartevo_project(&self) -> &Project {
        &self.project_context
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
    pub fn application_allowlist(&self) -> &BTreeSet<ArgoCdApplicationId> {
        &self.application_allowlist
    }

    #[must_use]
    pub fn target_revision_digest(&self) -> Digest {
        self.target_revision.digest()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "argocd-deployment-scope/v1",
            &[
                ("instance", self.instance.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("application", self.application.digest().as_str().to_owned()),
                ("cluster", self.cluster.digest().as_str().to_owned()),
                ("namespace", self.namespace.digest().as_str().to_owned()),
                (
                    "target_revision",
                    self.target_revision.digest().as_str().to_owned(),
                ),
                (
                    "sync_operation",
                    self.sync_operation.digest().as_str().to_owned(),
                ),
                (
                    "project_context",
                    self.project_context.digest().as_str().to_owned(),
                ),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                (
                    "application_allowlist",
                    digest_identifiers(
                        "argocd-application-allowlist/v1",
                        &self.application_allowlist,
                    )
                    .as_str()
                    .to_owned(),
                ),
            ],
        )
    }

    #[must_use]
    pub fn application_is_allowed(&self, application: &ArgoCdApplicationId) -> bool {
        self.application_allowlist.contains(application)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.application_allowlist.is_empty() {
            return Err(ArgoCdDeploymentError::InvalidScope(
                "empty application allowlist",
            ));
        }
        if !self.application_is_allowed(&self.application) {
            return Err(ArgoCdDeploymentError::InvalidScope(
                "application is not in the explicit allowlist",
            ));
        }
        self.project_context.digest().validate()?;
        self.mission.digest().validate()?;
        self.work_product.digest().validate()
    }
}

fn digest_identifiers<T: AsRef<str> + Ord>(domain: &str, values: &BTreeSet<T>) -> Digest {
    let joined = values
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join("\u{1f}");
    Digest::from_parts(domain, &[("values", joined)])
}

fn valid_path_segment(value: &str) -> bool {
    !value.contains('/') && !value.contains('?') && !value.contains('#') && !value.contains('&')
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    BearerToken,
}

/// Opaque bearer-token reference. The supplied handle is hashed and zeroized
/// during construction; no raw token or handle is stored, serialized, or
/// placed into an Argo CD request or receipt.
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
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("referenceDigest", &self.reference_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("credentialRevision", &self.credential_revision)?;
        state.serialize_field("revoked", &self.revoked)?;
        state.end()
    }
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl Into<String>,
        scope: &ArgoCdDeploymentScope,
        credential_revision: u64,
    ) -> Result<Self> {
        let mut opaque_handle = opaque_handle.into();
        if opaque_handle.is_empty()
            || opaque_handle.len() > MAX_SECRET_REFERENCE_BYTES
            || opaque_handle.chars().any(char::is_control)
        {
            opaque_handle.zeroize();
            return Err(ArgoCdDeploymentError::InvalidSecretReference);
        }
        let credential_revision = match Revision::new(credential_revision) {
            Ok(value) => value,
            Err(error) => {
                opaque_handle.zeroize();
                return Err(error);
            }
        };
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "argocd-bearer-token-reference/v1",
            &[
                ("handle", opaque_handle.clone()),
                ("scope", scope_digest.as_str().to_owned()),
                ("credential_revision", credential_revision.get().to_string()),
            ],
        );
        opaque_handle.zeroize();
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            kind: SecretKind::BearerToken,
            revoked: false,
        })
    }

    pub fn bearer_token(
        opaque_handle: impl Into<String>,
        scope: &ArgoCdDeploymentScope,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::new(opaque_handle, scope, credential_revision)
    }

    pub fn bearer(
        opaque_handle: impl Into<String>,
        scope: &ArgoCdDeploymentScope,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::new(opaque_handle, scope, credential_revision)
    }

    #[must_use]
    pub fn kind(&self) -> SecretKind {
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
    pub const fn revision(&self) -> Revision {
        self.credential_revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self, scope: &ArgoCdDeploymentScope) -> Result<()> {
        if self.kind != SecretKind::BearerToken
            || self.credential_revision.get() == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            if self.revoked {
                return Err(ArgoCdDeploymentError::SecretRevoked);
            }
            return Err(ArgoCdDeploymentError::InvalidSecretReference);
        }
        self.reference_digest.validate()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

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

    #[must_use]
    pub const fn provider_receipt(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    revision: Revision,
    permissions: BTreeSet<String>,
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
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "argocd-permission-snapshot/v1",
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

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision.get() == 0
            || LAYER1_PERMISSIONS
                .iter()
                .any(|permission| !self.permissions.contains(*permission))
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            return Err(ArgoCdDeploymentError::InvalidPermissions);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    id_digest: Digest,
    revision: Revision,
    expires_at: u64,
    permissions: BTreeSet<String>,
    consent_digest: Digest,
}

impl ConsentScope {
    pub fn new<I, S>(
        id: impl AsRef<str>,
        revision: u64,
        expires_at: u64,
        permissions: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let revision = Revision::new(revision)?;
        if id.as_ref().is_empty() || expires_at == 0 {
            return Err(ArgoCdDeploymentError::InvalidConsent);
        }
        let permissions: BTreeSet<String> = permissions.into_iter().map(Into::into).collect();
        let id_digest = Digest::from_text(id.as_ref());
        let consent_digest = Digest::from_parts(
            "argocd-consent/v1",
            &[
                ("id", id_digest.as_str().to_owned()),
                ("revision", revision.get().to_string()),
                ("expires_at", expires_at.to_string()),
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
        let consent = Self {
            id_digest,
            revision,
            expires_at,
            permissions,
            consent_digest,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn for_layer_one(id: impl AsRef<str>, revision: u64, expires_at: u64) -> Result<Self> {
        Self::new(id, revision, expires_at, LAYER1_PERMISSIONS)
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
    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.consent_digest
    }

    #[must_use]
    pub const fn is_active_at(&self, observed_at: u64) -> bool {
        observed_at <= self.expires_at
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision.get() == 0
            || self.expires_at == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
            || self.consent_digest
                != Digest::from_parts(
                    "argocd-consent/v1",
                    &[
                        ("id", self.id_digest.as_str().to_owned()),
                        ("revision", self.revision.get().to_string()),
                        ("expires_at", self.expires_at.to_string()),
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
        {
            return Err(ArgoCdDeploymentError::InvalidConsent);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgoSyncStatus {
    Synced,
    OutOfSync,
    Unknown,
}

impl ArgoSyncStatus {
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "synced" => Self::Synced,
            "outofsync" | "out_of_sync" | "out-of-sync" => Self::OutOfSync,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgoHealthStatus {
    Healthy,
    Progressing,
    Degraded,
    Suspended,
    Missing,
    Unknown,
}

impl ArgoHealthStatus {
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "healthy" => Self::Healthy,
            "progressing" => Self::Progressing,
            "degraded" => Self::Degraded,
            "suspended" => Self::Suspended,
            "missing" => Self::Missing,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgoOperationPhase {
    Running,
    Succeeded,
    Failed,
    Error,
    Terminating,
    Unknown,
}

impl ArgoOperationPhase {
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "running" => Self::Running,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "error" => Self::Error,
            "terminating" => Self::Terminating,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgoCdDeploymentState {
    Ready,
    Syncing,
    OutOfSync,
    Failed,
    Unknown,
    Partial,
    AccessLoss,
    RateLimited,
    Timeout,
    NotFound,
    Conflict,
    Tampered,
    StaleRevision,
    ProviderUnknown,
    RegistrationRevoked,
    ConsentDenied,
    OperationUnknown,
}

pub type ArgoResultState = ArgoCdDeploymentState;

impl ArgoCdDeploymentState {
    #[must_use]
    pub const fn is_adoptable(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArgoApplicationProjection {
    pub instance_digest: Digest,
    pub project_digest: Digest,
    pub application_digest: Digest,
    pub cluster_digest: Digest,
    pub namespace_digest: Digest,
    pub target_revision_digest: Digest,
    pub sync_operation_digest: Option<Digest>,
    pub sync_status: ArgoSyncStatus,
    pub health_status: ArgoHealthStatus,
    pub observed_revision: Revision,
    pub application_digest_fence: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArgoResourceTreeProjection {
    pub node_count: u32,
    pub healthy_count: u32,
    pub synced_count: u32,
    pub unknown_count: u32,
    pub partial: bool,
    pub tree_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArgoSyncStatusProjection {
    pub sync_status: ArgoSyncStatus,
    pub health_status: ArgoHealthStatus,
    pub target_revision_digest: Digest,
    pub observed_revision: Revision,
    pub sync_operation_digest: Option<Digest>,
    pub sync_status_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArgoOperationProjection {
    pub sync_operation_digest: Digest,
    pub target_revision_digest: Digest,
    pub phase: ArgoOperationPhase,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub detail_digest: Option<Digest>,
    pub operation_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgoApplicationSnapshot {
    pub(crate) instance: ArgoCdInstanceId,
    pub(crate) project: ArgoCdProjectId,
    pub(crate) application: ArgoCdApplicationId,
    pub(crate) cluster: ArgoCdClusterId,
    pub(crate) namespace: ArgoCdNamespace,
    pub(crate) target_revision: ArgoCdTargetRevision,
    pub(crate) sync_operation: Option<ArgoCdSyncOperationId>,
    pub(crate) sync_status: ArgoSyncStatus,
    pub(crate) health_status: ArgoHealthStatus,
    pub(crate) observed_revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgoResourceTreeSnapshot {
    pub(crate) node_count: u32,
    pub(crate) healthy_count: u32,
    pub(crate) synced_count: u32,
    pub(crate) unknown_count: u32,
    pub(crate) partial: bool,
    pub(crate) tree_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgoSyncStatusSnapshot {
    pub(crate) sync_status: ArgoSyncStatus,
    pub(crate) health_status: ArgoHealthStatus,
    pub(crate) target_revision: ArgoCdTargetRevision,
    pub(crate) observed_revision: Revision,
    pub(crate) sync_operation: Option<ArgoCdSyncOperationId>,
    pub(crate) sync_status_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgoOperationSnapshot {
    pub(crate) sync_operation: ArgoCdSyncOperationId,
    pub(crate) target_revision: ArgoCdTargetRevision,
    pub(crate) phase: ArgoOperationPhase,
    pub(crate) started_at: Option<u64>,
    pub(crate) finished_at: Option<u64>,
    pub(crate) detail_digest: Option<Digest>,
    pub(crate) operation_digest: Digest,
}

impl ArgoApplicationSnapshot {
    #[must_use]
    pub fn projection(&self) -> ArgoApplicationProjection {
        self.to_projection()
    }

    #[must_use]
    pub fn sync_status(&self) -> ArgoSyncStatus {
        self.sync_status
    }

    #[must_use]
    pub fn health_status(&self) -> ArgoHealthStatus {
        self.health_status
    }

    #[must_use]
    pub fn observed_revision(&self) -> Revision {
        self.observed_revision
    }

    pub(crate) fn to_projection(&self) -> ArgoApplicationProjection {
        let application_digest_fence = Digest::from_parts(
            "argocd-application-projection/v1",
            &[
                ("instance", self.instance.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("application", self.application.digest().as_str().to_owned()),
                ("cluster", self.cluster.digest().as_str().to_owned()),
                ("namespace", self.namespace.digest().as_str().to_owned()),
                (
                    "target_revision",
                    self.target_revision.digest().as_str().to_owned(),
                ),
                (
                    "sync_operation",
                    self.sync_operation
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("sync_status", format!("{:?}", self.sync_status)),
                ("health_status", format!("{:?}", self.health_status)),
                (
                    "observed_revision",
                    self.observed_revision.get().to_string(),
                ),
            ],
        );
        ArgoApplicationProjection {
            instance_digest: self.instance.digest(),
            project_digest: self.project.digest(),
            application_digest: self.application.digest(),
            cluster_digest: self.cluster.digest(),
            namespace_digest: self.namespace.digest(),
            target_revision_digest: self.target_revision.digest(),
            sync_operation_digest: self.sync_operation.as_ref().map(Identifier::digest),
            sync_status: self.sync_status,
            health_status: self.health_status,
            observed_revision: self.observed_revision,
            application_digest_fence,
        }
    }
}

impl ArgoResourceTreeSnapshot {
    #[must_use]
    pub fn projection(&self) -> ArgoResourceTreeProjection {
        self.to_projection()
    }

    #[must_use]
    pub const fn node_count(&self) -> u32 {
        self.node_count
    }

    #[must_use]
    pub const fn partial(&self) -> bool {
        self.partial
    }

    pub(crate) fn to_projection(&self) -> ArgoResourceTreeProjection {
        ArgoResourceTreeProjection {
            node_count: self.node_count,
            healthy_count: self.healthy_count,
            synced_count: self.synced_count,
            unknown_count: self.unknown_count,
            partial: self.partial,
            tree_digest: self.tree_digest.clone(),
        }
    }
}

impl ArgoSyncStatusSnapshot {
    #[must_use]
    pub fn projection(&self) -> ArgoSyncStatusProjection {
        self.to_projection()
    }

    #[must_use]
    pub fn sync_status(&self) -> ArgoSyncStatus {
        self.sync_status
    }

    pub(crate) fn to_projection(&self) -> ArgoSyncStatusProjection {
        ArgoSyncStatusProjection {
            sync_status: self.sync_status,
            health_status: self.health_status,
            target_revision_digest: self.target_revision.digest(),
            observed_revision: self.observed_revision,
            sync_operation_digest: self.sync_operation.as_ref().map(Identifier::digest),
            sync_status_digest: self.sync_status_digest.clone(),
        }
    }
}

impl ArgoOperationSnapshot {
    #[must_use]
    pub fn projection(&self) -> ArgoOperationProjection {
        self.to_projection()
    }

    #[must_use]
    pub fn phase(&self) -> ArgoOperationPhase {
        self.phase
    }

    pub(crate) fn to_projection(&self) -> ArgoOperationProjection {
        ArgoOperationProjection {
            sync_operation_digest: self.sync_operation.digest(),
            target_revision_digest: self.target_revision.digest(),
            phase: self.phase,
            started_at: self.started_at,
            finished_at: self.finished_at,
            detail_digest: self.detail_digest.clone(),
            operation_digest: self.operation_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackoffReceipt {
    pub retry_attempt: u8,
    pub retry_after_seconds: u32,
    pub backoff_digest: Digest,
}

impl BackoffReceipt {
    #[must_use]
    pub fn new(retry_attempt: u8, retry_after_seconds: u32) -> Self {
        let retry_after_seconds = retry_after_seconds.min(MAX_BACKOFF_SECONDS);
        Self {
            retry_attempt,
            retry_after_seconds,
            backoff_digest: Digest::from_parts(
                "argocd-backoff/v1",
                &[
                    ("attempt", retry_attempt.to_string()),
                    ("seconds", retry_after_seconds.to_string()),
                ],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArgoRequestReceipt {
    pub operation: String,
    pub method: String,
    pub status_code: Option<u16>,
    pub response_bytes: Option<usize>,
    pub response_digest: Option<Digest>,
    pub request_digest: Digest,
    pub redacted: bool,
    pub receipt_digest: Digest,
}

impl ArgoRequestReceipt {
    pub(crate) fn new(
        operation: impl Into<String>,
        method: impl Into<String>,
        request_digest: Digest,
        status_code: Option<u16>,
        response_bytes: Option<usize>,
        response_digest: Option<Digest>,
    ) -> Self {
        let operation = operation.into();
        let method = method.into();
        let receipt_digest = Digest::from_parts(
            "argocd-request-receipt/v1",
            &[
                ("operation", operation.clone()),
                ("method", method.clone()),
                ("request", request_digest.as_str().to_owned()),
                (
                    "status",
                    status_code.map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "bytes",
                    response_bytes.map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "response",
                    response_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        );
        Self {
            operation,
            method,
            status_code,
            response_bytes,
            response_digest,
            request_digest,
            redacted: true,
            receipt_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArgoApplicationFixture {
    pub instance_id: String,
    pub project: String,
    pub application: String,
    pub cluster: String,
    pub namespace: String,
    pub target_revision: String,
    pub sync_status: String,
    pub health_status: String,
    #[serde(default = "default_observed_revision")]
    pub observed_revision: u64,
    #[serde(default)]
    pub sync_operation: Option<String>,
}

fn default_observed_revision() -> u64 {
    1
}

impl ArgoApplicationFixture {
    #[must_use]
    pub fn for_scope(scope: &ArgoCdDeploymentScope) -> Self {
        Self {
            instance_id: scope.instance().as_str().to_owned(),
            project: scope.project().as_str().to_owned(),
            application: scope.application().as_str().to_owned(),
            cluster: scope.cluster().as_str().to_owned(),
            namespace: scope.namespace().as_str().to_owned(),
            target_revision: scope.target_revision().as_str().to_owned(),
            sync_status: "Synced".to_owned(),
            health_status: "Healthy".to_owned(),
            observed_revision: 1,
            sync_operation: Some(scope.sync_operation().as_str().to_owned()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArgoResourceTreeFixture {
    pub instance_id: String,
    pub project: String,
    pub application: String,
    pub cluster: String,
    pub namespace: String,
    #[serde(default)]
    pub nodes: Vec<ArgoResourceNodeFixture>,
    #[serde(default)]
    pub partial: bool,
}

impl ArgoResourceTreeFixture {
    #[must_use]
    pub fn for_scope(scope: &ArgoCdDeploymentScope) -> Self {
        Self {
            instance_id: scope.instance().as_str().to_owned(),
            project: scope.project().as_str().to_owned(),
            application: scope.application().as_str().to_owned(),
            cluster: scope.cluster().as_str().to_owned(),
            namespace: scope.namespace().as_str().to_owned(),
            nodes: vec![ArgoResourceNodeFixture::healthy(scope)],
            partial: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArgoResourceNodeFixture {
    pub group: String,
    pub version: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub health_status: String,
    pub sync_status: String,
    #[serde(default)]
    pub resource_version: Option<String>,
}

impl ArgoResourceNodeFixture {
    #[must_use]
    pub fn healthy(scope: &ArgoCdDeploymentScope) -> Self {
        Self {
            group: "apps".to_owned(),
            version: "v1".to_owned(),
            kind: "Deployment".to_owned(),
            namespace: scope.namespace().as_str().to_owned(),
            name: scope.application().as_str().to_owned(),
            health_status: "Healthy".to_owned(),
            sync_status: "Synced".to_owned(),
            resource_version: Some("resource-version-1".to_owned()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArgoSyncStatusFixture {
    pub instance_id: String,
    pub project: String,
    pub application: String,
    pub cluster: String,
    pub namespace: String,
    pub target_revision: String,
    pub sync_status: String,
    pub health_status: String,
    #[serde(default = "default_observed_revision")]
    pub observed_revision: u64,
    #[serde(default)]
    pub sync_operation: Option<String>,
}

impl ArgoSyncStatusFixture {
    #[must_use]
    pub fn for_scope(scope: &ArgoCdDeploymentScope) -> Self {
        Self {
            instance_id: scope.instance().as_str().to_owned(),
            project: scope.project().as_str().to_owned(),
            application: scope.application().as_str().to_owned(),
            cluster: scope.cluster().as_str().to_owned(),
            namespace: scope.namespace().as_str().to_owned(),
            target_revision: scope.target_revision().as_str().to_owned(),
            sync_status: "Synced".to_owned(),
            health_status: "Healthy".to_owned(),
            observed_revision: 1,
            sync_operation: Some(scope.sync_operation().as_str().to_owned()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArgoOperationFixture {
    pub instance_id: String,
    pub project: String,
    pub application: String,
    pub cluster: String,
    pub namespace: String,
    pub sync_operation: String,
    pub target_revision: String,
    pub phase: String,
    #[serde(default)]
    pub started_at: Option<u64>,
    #[serde(default)]
    pub finished_at: Option<u64>,
    #[serde(default)]
    pub detail: Option<String>,
}

impl ArgoOperationFixture {
    #[must_use]
    pub fn for_scope(scope: &ArgoCdDeploymentScope) -> Self {
        Self {
            instance_id: scope.instance().as_str().to_owned(),
            project: scope.project().as_str().to_owned(),
            application: scope.application().as_str().to_owned(),
            cluster: scope.cluster().as_str().to_owned(),
            namespace: scope.namespace().as_str().to_owned(),
            sync_operation: scope.sync_operation().as_str().to_owned(),
            target_revision: scope.target_revision().as_str().to_owned(),
            phase: "Succeeded".to_owned(),
            started_at: Some(1),
            finished_at: Some(2),
            detail: Some("fixture-operation-detail".to_owned()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgoFixtureSet {
    pub application: ArgoApplicationFixture,
    pub resource_tree: ArgoResourceTreeFixture,
    pub sync_status: ArgoSyncStatusFixture,
    pub operation: ArgoOperationFixture,
}

impl ArgoFixtureSet {
    #[must_use]
    pub fn for_scope(scope: &ArgoCdDeploymentScope) -> Self {
        Self {
            application: ArgoApplicationFixture::for_scope(scope),
            resource_tree: ArgoResourceTreeFixture::for_scope(scope),
            sync_status: ArgoSyncStatusFixture::for_scope(scope),
            operation: ArgoOperationFixture::for_scope(scope),
        }
    }
}
