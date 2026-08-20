use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{GcpMemorystoreError, Result};
use crate::{
    API_REVISION, GCP_MEMORYSTORE_OAUTH_SCOPE, LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES,
    MAX_LABELS, MAX_RESPONSE_BYTES,
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
            Err(GcpMemorystoreError::InvalidDigest)
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(GcpMemorystoreError::InvalidDigest)
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

fn valid_text(value: &str, max_bytes: usize, internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_gcp_project(value: &str) -> bool {
    (6..=30).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_location(value: &str) -> bool {
    valid_identifier(value, 64) && value != "-" && !value.contains('*')
}

fn valid_instance(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

macro_rules! identifier {
    ($name:ident, $domain:literal, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(GcpMemorystoreError::InvalidIdentifier { field: $field })
                }
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, &[("value", self.0.clone())])
            }
            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(GcpMemorystoreError::InvalidIdentifier { field: $field })
                }
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.digest())
                    .finish()
            }
        }
    };
}

identifier!(
    GcpProjectId,
    "gcp-memorystore-project/v1",
    "gcp-project",
    valid_gcp_project
);
identifier!(
    GcpLocation,
    "gcp-memorystore-location/v1",
    "location",
    valid_location
);
identifier!(
    GcpInstanceId,
    "gcp-memorystore-instance/v1",
    "instance",
    valid_instance
);
identifier!(
    MissionId,
    "gcp-memorystore-mission/v1",
    "mission",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);
identifier!(
    ProjectId,
    "gcp-memorystore-project-binding/v1",
    "project",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);
identifier!(
    WorkProductId,
    "gcp-memorystore-work-product/v1",
    "work-product",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);
impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(GcpMemorystoreError::InvalidScope)
        } else {
            Ok(Self(value))
        }
    }
    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! binding {
    ($name:ident, $id:ty, $domain:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            id: $id,
            revision: Revision,
        }
        impl $name {
            pub fn new(id: $id, revision: Revision) -> Result<Self> {
                let value = Self { id, revision };
                value.validate()?;
                Ok(value)
            }
            pub fn id(&self) -> &$id {
                &self.id
            }
            pub const fn revision(&self) -> Revision {
                self.revision
            }
            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        ("id", self.id.digest().as_str().to_owned()),
                        ("revision", self.revision.get().to_string()),
                    ],
                )
            }
            fn validate(&self) -> Result<()> {
                self.id.validate()
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("id_digest", &self.id.digest())
                    .field("revision", &self.revision)
                    .finish()
            }
        }
    };
}

binding!(
    MissionBinding,
    MissionId,
    "gcp-memorystore-mission-binding/v1"
);
binding!(
    ProjectBinding,
    ProjectId,
    "gcp-memorystore-project-binding/v1"
);
binding!(
    WorkProductBinding,
    WorkProductId,
    "gcp-memorystore-work-product-binding/v1"
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoogleAuthKind {
    OAuth,
    ServiceAccount,
}

pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: GoogleAuthKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            auth_kind: self.auth_kind.clone(),
            revoked: self.revoked,
        }
    }
}
impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.auth_kind == other.auth_kind
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
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}
impl SecretReference {
    pub fn new(
        opaque_handle: impl Into<String>,
        scope: &GcpMemorystoreScope,
        credential_revision: u64,
        auth_kind: GoogleAuthKind,
    ) -> Result<Self> {
        let mut opaque_handle = opaque_handle.into();
        let revision = match Revision::new(credential_revision) {
            Ok(value) => value,
            Err(error) => {
                opaque_handle.zeroize();
                return Err(error);
            }
        };
        if !valid_text(&opaque_handle, MAX_IDENTIFIER_BYTES, true) {
            opaque_handle.zeroize();
            return Err(GcpMemorystoreError::InvalidSecretReference);
        }
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "gcp-memorystore-opaque-google-secret-reference/v1",
            &[
                ("handle", opaque_handle.clone()),
                ("scope", scope_digest.as_str().to_owned()),
                ("revision", revision.get().to_string()),
                ("auth_kind", format!("{auth_kind:?}")),
            ],
        );
        opaque_handle.zeroize();
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision: revision,
            auth_kind,
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
    pub fn auth_kind(&self) -> &GoogleAuthKind {
        &self.auth_kind
    }
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }
    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(GcpMemorystoreError::SecretRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionSnapshot {
    permissions: BTreeSet<String>,
    oauth_scope: String,
    digest: Digest,
}
impl PermissionSnapshot {
    pub fn least_privilege() -> Self {
        Self::new(
            LAYER1_PERMISSIONS.iter().map(|value| (*value).to_owned()),
            GCP_MEMORYSTORE_OAUTH_SCOPE,
        )
        .expect("least privilege permission snapshot")
    }
    pub fn new(
        permissions: impl IntoIterator<Item = String>,
        oauth_scope: impl Into<String>,
    ) -> Result<Self> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        let oauth_scope = oauth_scope.into();
        let expected = LAYER1_PERMISSIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<BTreeSet<_>>();
        if permissions != expected || oauth_scope != GCP_MEMORYSTORE_OAUTH_SCOPE {
            return Err(GcpMemorystoreError::InvalidPermissionSnapshot);
        }
        let digest = Digest::from_parts(
            "gcp-memorystore-permission-snapshot/v1",
            &[
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join("\n"),
                ),
                ("oauth_scope", oauth_scope.clone()),
            ],
        );
        Ok(Self {
            permissions,
            oauth_scope,
            digest,
        })
    }
    pub fn permissions(&self) -> impl Iterator<Item = &str> {
        self.permissions.iter().map(String::as_str)
    }
    pub fn oauth_scope(&self) -> &str {
        &self.oauth_scope
    }
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let expected = Self::least_privilege();
        if self == &expected {
            Ok(())
        } else {
            Err(GcpMemorystoreError::InvalidPermissionSnapshot)
        }
    }
}
impl Serialize for PermissionSnapshot {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PermissionSnapshot", 3)?;
        state.serialize_field("permissions", &self.permissions)?;
        state.serialize_field("oauthScope", &self.oauth_scope)?;
        state.serialize_field("permissionDigest", &self.digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentScope {
    mission_digest: Digest,
    project_digest: Digest,
    work_product_digest: Digest,
    expires_at: Option<u64>,
    revoked: bool,
    digest: Digest,
}
impl ConsentScope {
    pub fn new(
        mission: &MissionBinding,
        project: &ProjectBinding,
        work_product: &WorkProductBinding,
        expires_at: Option<u64>,
    ) -> Result<Self> {
        if expires_at == Some(0) {
            return Err(GcpMemorystoreError::InvalidConsent);
        }
        let mission_digest = mission.digest();
        let project_digest = project.digest();
        let work_product_digest = work_product.digest();
        let digest = Digest::from_parts(
            "gcp-memorystore-consent/v1",
            &[
                ("mission", mission_digest.as_str().to_owned()),
                ("project", project_digest.as_str().to_owned()),
                ("work_product", work_product_digest.as_str().to_owned()),
                (
                    "expires_at",
                    expires_at.map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        Ok(Self {
            mission_digest,
            project_digest,
            work_product_digest,
            expires_at,
            revoked: false,
            digest,
        })
    }
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
    pub const fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }
    pub fn is_active_at(&self, observed_at: u64) -> bool {
        !self.revoked && self.expires_at.is_none_or(|expiry| observed_at < expiry)
    }
    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(GcpMemorystoreError::ConsentRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
    pub(crate) fn validate_against(&self, scope: &GcpMemorystoreScope) -> Result<()> {
        let expected = Self::new(
            &scope.mission,
            &scope.project,
            &scope.work_product,
            self.expires_at,
        )?;
        if self == &expected {
            Ok(())
        } else {
            Err(GcpMemorystoreError::InvalidConsent)
        }
    }
}
impl Serialize for ConsentScope {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ConsentScope", 3)?;
        state.serialize_field("consentDigest", &self.digest)?;
        state.serialize_field("expiresAt", &self.expires_at)?;
        state.serialize_field("revoked", &self.revoked)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GcpMemorystoreScope {
    gcp_project: GcpProjectId,
    location: GcpLocation,
    instance: GcpInstanceId,
    mission: MissionBinding,
    project: ProjectBinding,
    work_product: WorkProductBinding,
    label_allowlist: BTreeSet<String>,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    digest: Digest,
}
impl fmt::Debug for GcpMemorystoreScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpMemorystoreScope")
            .field("scope_digest", &self.digest)
            .field("gcp_project_digest", &self.gcp_project.digest())
            .field("location_digest", &self.location.digest())
            .field("instance_digest", &self.instance.digest())
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .field("label_allowlist_digest", &self.label_allowlist_digest())
            .finish_non_exhaustive()
    }
}
impl GcpMemorystoreScope {
    pub fn new(
        gcp_project: GcpProjectId,
        location: GcpLocation,
        instance: GcpInstanceId,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
    ) -> Result<Self> {
        let consent = ConsentScope::new(&mission, &project, &work_product, None)?;
        let value = Self {
            gcp_project,
            location,
            instance,
            mission,
            project,
            work_product,
            label_allowlist: BTreeSet::new(),
            permission_snapshot: PermissionSnapshot::least_privilege(),
            consent,
            digest: Digest::from_text("uncomputed-scope"),
        };
        value.with_recomputed_digest()
    }
    #[allow(clippy::too_many_arguments)]
    pub fn from_values(
        gcp_project: impl Into<String>,
        location: impl Into<String>,
        instance: impl Into<String>,
        mission: impl Into<String>,
        mission_revision: u64,
        project: impl Into<String>,
        project_revision: u64,
        work_product: impl Into<String>,
        work_product_revision: u64,
    ) -> Result<Self> {
        Self::new(
            GcpProjectId::new(gcp_project)?,
            GcpLocation::new(location)?,
            GcpInstanceId::new(instance)?,
            MissionBinding::new(MissionId::new(mission)?, Revision::new(mission_revision)?)?,
            ProjectBinding::new(ProjectId::new(project)?, Revision::new(project_revision)?)?,
            WorkProductBinding::new(
                WorkProductId::new(work_product)?,
                Revision::new(work_product_revision)?,
            )?,
        )
    }
    pub fn with_label_allowlist(
        mut self,
        labels: impl IntoIterator<Item = String>,
    ) -> Result<Self> {
        let labels = labels.into_iter().collect::<BTreeSet<_>>();
        if labels.len() > MAX_LABELS
            || labels
                .iter()
                .any(|label| !valid_identifier(label, MAX_IDENTIFIER_BYTES))
        {
            return Err(GcpMemorystoreError::InvalidScope);
        }
        self.label_allowlist = labels;
        self.with_recomputed_digest()
    }
    pub fn with_permission_snapshot(mut self, snapshot: PermissionSnapshot) -> Result<Self> {
        snapshot.validate()?;
        self.permission_snapshot = snapshot;
        self.with_recomputed_digest()
    }
    pub fn with_consent(mut self, consent: ConsentScope) -> Result<Self> {
        consent.validate_against(&self)?;
        self.consent = consent;
        self.with_recomputed_digest()
    }
    fn with_recomputed_digest(mut self) -> Result<Self> {
        self.validate_parts()?;
        self.digest = self.compute_digest();
        Ok(self)
    }
    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-memorystore-scope/v1",
            &[
                ("gcp_project", self.gcp_project.digest().as_str().to_owned()),
                ("location", self.location.digest().as_str().to_owned()),
                ("instance", self.instance.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                ("labels", self.label_allowlist_digest().as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("consent", self.consent.digest().as_str().to_owned()),
                ("api", API_REVISION.to_owned()),
            ],
        )
    }
    fn validate_parts(&self) -> Result<()> {
        self.gcp_project.validate()?;
        self.location.validate()?;
        self.instance.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        self.permission_snapshot.validate()?;
        if self.label_allowlist.len() > MAX_LABELS
            || self
                .label_allowlist
                .iter()
                .any(|label| !valid_identifier(label, MAX_IDENTIFIER_BYTES))
        {
            return Err(GcpMemorystoreError::InvalidScope);
        }
        Ok(())
    }
    pub fn gcp_project(&self) -> &GcpProjectId {
        &self.gcp_project
    }
    pub fn project_id(&self) -> &GcpProjectId {
        &self.gcp_project
    }
    pub fn location(&self) -> &GcpLocation {
        &self.location
    }
    pub fn instance(&self) -> &GcpInstanceId {
        &self.instance
    }
    pub fn instance_id(&self) -> &GcpInstanceId {
        &self.instance
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
    pub fn label_allowlist(&self) -> impl Iterator<Item = &str> {
        self.label_allowlist.iter().map(String::as_str)
    }
    pub fn label_allowlist_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-memorystore-label-allowlist/v1",
            &[(
                "labels",
                self.label_allowlist
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        )
    }
    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }
    pub fn permission_digest(&self) -> &Digest {
        self.permission_snapshot.digest()
    }
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }
    pub fn consent_digest(&self) -> &Digest {
        self.consent.digest()
    }
    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }
    pub fn api_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-memorystore-api/v1",
            &[("revision", API_REVISION.to_owned())],
        )
    }
    pub fn resource_name_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-memorystore-resource-name/v1",
            &[
                ("project", self.gcp_project.digest().as_str().to_owned()),
                ("location", self.location.digest().as_str().to_owned()),
                ("instance", self.instance.digest().as_str().to_owned()),
            ],
        )
    }
    pub(crate) fn raw_resource_name(&self) -> String {
        format!(
            "projects/{}/locations/{}/instances/{}",
            self.gcp_project.as_str(),
            self.location.as_str(),
            self.instance.as_str()
        )
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_parts()?;
        if self.digest != self.compute_digest() {
            Err(GcpMemorystoreError::InvalidScope)
        } else {
            self.consent.validate_against(self)
        }
    }
}
impl Serialize for GcpMemorystoreScope {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("GcpMemorystoreScope", 13)?;
        state.serialize_field("gcpProjectDigest", &self.gcp_project.digest())?;
        state.serialize_field("locationDigest", &self.location.digest())?;
        state.serialize_field("instanceDigest", &self.instance.digest())?;
        state.serialize_field("missionDigest", &self.mission.digest())?;
        state.serialize_field("missionRevision", &self.mission.revision())?;
        state.serialize_field("projectDigest", &self.project.digest())?;
        state.serialize_field("projectRevision", &self.project.revision())?;
        state.serialize_field("workProductDigest", &self.work_product.digest())?;
        state.serialize_field("workProductRevision", &self.work_product.revision())?;
        state.serialize_field("labelAllowlistDigest", &self.label_allowlist_digest())?;
        state.serialize_field("permissionDigest", &self.permission_snapshot.digest())?;
        state.serialize_field("consentDigest", &self.consent.digest())?;
        state.serialize_field("scopeDigest", &self.digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceTier {
    Basic,
    StandardHa,
    Unknown,
}
impl InstanceTier {
    fn parse(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "BASIC" => Self::Basic,
            "STANDARD_HA" | "STANDARD" => Self::StandardHa,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceState {
    Active,
    Creating,
    Updating,
    Maintenance,
    Repairing,
    FailingOver,
    Deleting,
    Error,
    Unknown,
}
impl InstanceState {
    pub(crate) fn parse(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "ACTIVE" => Self::Active,
            "CREATING" => Self::Creating,
            "UPDATING" => Self::Updating,
            "MAINTENANCE" => Self::Maintenance,
            "REPAIRING" => Self::Repairing,
            "FAILING_OVER" => Self::FailingOver,
            "DELETING" => Self::Deleting,
            "ERROR" => Self::Error,
            _ => Self::Unknown,
        }
    }
    pub(crate) const fn is_stable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionMode {
    Disabled,
    ServerSide,
    Transit,
    Unknown,
}
impl EncryptionMode {
    fn parse(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "DISABLED" | "NONE" => Self::Disabled,
            "SERVER_SIDE" | "SERVER-SIDE" => Self::ServerSide,
            "TRANSIT" | "TLS" => Self::Transit,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceMode {
    Disabled,
    Rdb,
    Aof,
    Unknown,
}
impl PersistenceMode {
    fn parse(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "DISABLED" | "NONE" => Self::Disabled,
            "RDB" => Self::Rdb,
            "AOF" => Self::Aof,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionProjection {
    pub mode: EncryptionMode,
    pub auth_enabled: bool,
    pub certificate_digest: Option<Digest>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistenceProjection {
    pub mode: PersistenceMode,
    pub snapshot_digest: Option<Digest>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceProjection {
    pub policy_digest: Option<Digest>,
    pub schedule_digest: Option<Digest>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelProjection {
    pub allowlisted_labels_digest: Digest,
    pub allowlisted_label_count: u16,
    pub dropped_label_count: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisInstanceProjection {
    pub project_digest: Digest,
    pub location_digest: Digest,
    pub instance_id_digest: Digest,
    pub resource_name_digest: Digest,
    pub tier: InstanceTier,
    pub memory_size_gb: u32,
    pub redis_version_digest: Digest,
    pub state: InstanceState,
    pub replica_count: u32,
    pub encryption: EncryptionProjection,
    pub persistence: PersistenceProjection,
    pub maintenance: MaintenanceProjection,
    pub labels: LabelProjection,
    pub projection_digest: Digest,
}
pub type InstanceProjection = RedisInstanceProjection;
impl RedisInstanceProjection {
    pub(crate) fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-memorystore-instance-projection/v1",
            &[
                ("project", self.project_digest.as_str().to_owned()),
                ("location", self.location_digest.as_str().to_owned()),
                ("instance", self.instance_id_digest.as_str().to_owned()),
                ("resource", self.resource_name_digest.as_str().to_owned()),
                ("tier", format!("{:?}", self.tier)),
                ("memory_size_gb", self.memory_size_gb.to_string()),
                (
                    "redis_version",
                    self.redis_version_digest.as_str().to_owned(),
                ),
                ("state", format!("{:?}", self.state)),
                ("replica_count", self.replica_count.to_string()),
                ("encryption", format!("{:?}", self.encryption)),
                ("persistence", format!("{:?}", self.persistence)),
                ("maintenance", format!("{:?}", self.maintenance)),
                ("labels", format!("{:?}", self.labels)),
            ],
        )
    }
    pub(crate) fn validate(&self) -> Result<()> {
        for digest in [
            Some(&self.project_digest),
            Some(&self.location_digest),
            Some(&self.instance_id_digest),
            Some(&self.resource_name_digest),
            Some(&self.redis_version_digest),
            self.encryption.certificate_digest.as_ref(),
            self.persistence.snapshot_digest.as_ref(),
            self.maintenance.policy_digest.as_ref(),
            self.maintenance.schedule_digest.as_ref(),
            Some(&self.labels.allowlisted_labels_digest),
            Some(&self.projection_digest),
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        if self.projection_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(GcpMemorystoreError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct InstanceInput {
    resource_name: String,
    tier: String,
    memory_size_gb: u32,
    redis_version: String,
    state: String,
    replica_count: u32,
    encryption_mode: String,
    auth_enabled: bool,
    certificate_digest: Option<Digest>,
    persistence_mode: String,
    snapshot_digest: Option<Digest>,
    maintenance_policy_digest: Option<Digest>,
    maintenance_schedule_digest: Option<Digest>,
    labels: BTreeMap<String, String>,
}
impl fmt::Debug for InstanceInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstanceInput")
            .field(
                "resource_name_digest",
                &Digest::from_text(&self.resource_name),
            )
            .field("tier", &InstanceTier::parse(&self.tier))
            .field("memory_size_gb", &self.memory_size_gb)
            .field(
                "redis_version_digest",
                &Digest::from_text(&self.redis_version),
            )
            .field("state", &InstanceState::parse(&self.state))
            .field("replica_count", &self.replica_count)
            .field("label_count", &self.labels.len())
            .finish_non_exhaustive()
    }
}
impl InstanceInput {
    pub fn new(
        resource_name: impl Into<String>,
        tier: impl Into<String>,
        memory_size_gb: u32,
        redis_version: impl Into<String>,
        state: impl Into<String>,
        replica_count: u32,
    ) -> Result<Self> {
        let resource_name = resource_name.into();
        let tier = tier.into();
        let redis_version = redis_version.into();
        let state = state.into();
        if !valid_text(&resource_name, 512, false)
            || !valid_text(&tier, 64, false)
            || !valid_text(&redis_version, 64, false)
            || !valid_text(&state, 64, false)
            || memory_size_gb == 0
        {
            return Err(GcpMemorystoreError::InvalidResponse);
        }
        Ok(Self {
            resource_name,
            tier,
            memory_size_gb,
            redis_version,
            state,
            replica_count,
            encryption_mode: "DISABLED".to_owned(),
            auth_enabled: false,
            certificate_digest: None,
            persistence_mode: "DISABLED".to_owned(),
            snapshot_digest: None,
            maintenance_policy_digest: None,
            maintenance_schedule_digest: None,
            labels: BTreeMap::new(),
        })
    }
    pub fn fixture(scope: &GcpMemorystoreScope) -> Self {
        Self {
            resource_name: scope.raw_resource_name(),
            tier: "STANDARD_HA".to_owned(),
            memory_size_gb: 4,
            redis_version: "REDIS_7_2".to_owned(),
            state: "ACTIVE".to_owned(),
            replica_count: 1,
            encryption_mode: "TRANSIT".to_owned(),
            auth_enabled: true,
            certificate_digest: Some(Digest::from_text("fixture-certificate")),
            persistence_mode: "RDB".to_owned(),
            snapshot_digest: Some(Digest::from_text("fixture-rdb-snapshot")),
            maintenance_policy_digest: Some(Digest::from_text("fixture-maintenance-policy")),
            maintenance_schedule_digest: Some(Digest::from_text("fixture-maintenance-schedule")),
            labels: BTreeMap::from([
                (String::from("environment"), String::from("fixture")),
                (String::from("owner"), String::from("layer1")),
            ]),
        }
    }
    pub fn with_encryption(
        mut self,
        mode: impl Into<String>,
        auth_enabled: bool,
        certificate: Option<impl AsRef<str>>,
    ) -> Self {
        self.encryption_mode = mode.into();
        self.auth_enabled = auth_enabled;
        self.certificate_digest = certificate.map(|value| Digest::from_text(value.as_ref()));
        self
    }
    pub fn with_persistence(
        mut self,
        mode: impl Into<String>,
        snapshot_metadata: Option<impl AsRef<str>>,
    ) -> Self {
        self.persistence_mode = mode.into();
        self.snapshot_digest = snapshot_metadata.map(|value| Digest::from_text(value.as_ref()));
        self
    }
    pub fn with_maintenance(
        mut self,
        policy_metadata: Option<impl AsRef<str>>,
        schedule_metadata: Option<impl AsRef<str>>,
    ) -> Self {
        self.maintenance_policy_digest =
            policy_metadata.map(|value| Digest::from_text(value.as_ref()));
        self.maintenance_schedule_digest =
            schedule_metadata.map(|value| Digest::from_text(value.as_ref()));
        self
    }
    pub fn with_labels(mut self, labels: impl IntoIterator<Item = (String, String)>) -> Self {
        self.labels = labels.into_iter().collect();
        self
    }
    #[allow(clippy::too_many_arguments)]
    pub fn with_sensitive_metadata(
        self,
        _endpoints: impl IntoIterator<Item = String>,
        _auth_string: Option<String>,
        _certificates: impl IntoIterator<Item = String>,
        labels: impl IntoIterator<Item = (String, String)>,
        _redis_keys: impl IntoIterator<Item = String>,
        _redis_values: impl IntoIterator<Item = String>,
        _command_output: Option<String>,
        _raw_body: Option<String>,
    ) -> Self {
        self.with_labels(labels)
    }
    pub(crate) fn resource_name(&self) -> &str {
        &self.resource_name
    }
    pub(crate) fn state(&self) -> InstanceState {
        InstanceState::parse(&self.state)
    }
    pub(crate) fn projection(
        &self,
        scope: &GcpMemorystoreScope,
    ) -> Result<RedisInstanceProjection> {
        if self.resource_name != scope.raw_resource_name() {
            return Err(GcpMemorystoreError::ScopeDrift);
        }
        let mut selected = Vec::new();
        let mut dropped = 0_u16;
        for (key, value) in &self.labels {
            if scope.label_allowlist.contains(key) {
                selected.push(format!(
                    "{}={}",
                    Digest::from_text(key).as_str(),
                    Digest::from_text(value).as_str()
                ));
            } else {
                dropped = dropped.saturating_add(1);
            }
        }
        selected.sort_unstable();
        let labels = LabelProjection {
            allowlisted_labels_digest: Digest::from_parts(
                "gcp-memorystore-allowlisted-labels/v1",
                &[("labels", selected.join("\n"))],
            ),
            allowlisted_label_count: u16::try_from(
                self.labels.len().saturating_sub(usize::from(dropped)),
            )
            .map_err(|_| GcpMemorystoreError::TruncatedEvidence)?,
            dropped_label_count: dropped,
        };
        let projection = RedisInstanceProjection {
            project_digest: scope.gcp_project.digest(),
            location_digest: scope.location.digest(),
            instance_id_digest: scope.instance.digest(),
            resource_name_digest: scope.resource_name_digest(),
            tier: InstanceTier::parse(&self.tier),
            memory_size_gb: self.memory_size_gb,
            redis_version_digest: Digest::from_text(&self.redis_version),
            state: self.state(),
            replica_count: self.replica_count,
            encryption: EncryptionProjection {
                mode: EncryptionMode::parse(&self.encryption_mode),
                auth_enabled: self.auth_enabled,
                certificate_digest: self.certificate_digest.clone(),
            },
            persistence: PersistenceProjection {
                mode: PersistenceMode::parse(&self.persistence_mode),
                snapshot_digest: self.snapshot_digest.clone(),
            },
            maintenance: MaintenanceProjection {
                policy_digest: self.maintenance_policy_digest.clone(),
                schedule_digest: self.maintenance_schedule_digest.clone(),
            },
            labels,
            projection_digest: Digest::from_text("uncomputed-projection"),
        };
        let digest = projection.compute_digest();
        Ok(RedisInstanceProjection {
            projection_digest: digest,
            ..projection
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct InstanceSummary {
    resource_name: String,
    state: String,
    tier: String,
}
impl fmt::Debug for InstanceSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstanceSummary")
            .field(
                "resource_name_digest",
                &Digest::from_text(&self.resource_name),
            )
            .field("state", &InstanceState::parse(&self.state))
            .field("tier", &InstanceTier::parse(&self.tier))
            .finish()
    }
}
impl InstanceSummary {
    pub fn new(
        resource_name: impl Into<String>,
        state: impl Into<String>,
        tier: impl Into<String>,
    ) -> Result<Self> {
        let resource_name = resource_name.into();
        let state = state.into();
        let tier = tier.into();
        if !valid_text(&resource_name, 512, false)
            || !valid_text(&state, 64, false)
            || !valid_text(&tier, 64, false)
        {
            return Err(GcpMemorystoreError::InvalidResponse);
        }
        Ok(Self {
            resource_name,
            state,
            tier,
        })
    }
    pub fn fixture(scope: &GcpMemorystoreScope) -> Self {
        Self::new(scope.raw_resource_name(), "ACTIVE", "STANDARD_HA").expect("fixture summary")
    }
    pub(crate) fn resource_name(&self) -> &str {
        &self.resource_name
    }
    pub(crate) fn state(&self) -> InstanceState {
        InstanceState::parse(&self.state)
    }
    pub(crate) fn identity_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-memorystore-instance-summary/v1",
            &[
                (
                    "resource",
                    Digest::from_text(&self.resource_name).as_str().to_owned(),
                ),
                ("state", format!("{:?}", self.state())),
                ("tier", format!("{:?}", InstanceTier::parse(&self.tier))),
            ],
        )
    }
}
impl Serialize for InstanceSummary {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("InstanceSummary", 3)?;
        state.serialize_field(
            "resourceNameDigest",
            &Digest::from_text(&self.resource_name),
        )?;
        state.serialize_field("state", &self.state())?;
        state.serialize_field("tier", &InstanceTier::parse(&self.tier))?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    raw: String,
    digest: Digest,
}
impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let raw = value.into();
        if !valid_text(&raw, MAX_IDENTIFIER_BYTES * 16, true) {
            return Err(GcpMemorystoreError::InvalidRequest);
        }
        Ok(Self {
            digest: Digest::from_parts("gcp-memorystore-page-token/v1", &[("token", raw.clone())]),
            raw,
        })
    }
    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.digest
            == Digest::from_parts(
                "gcp-memorystore-page-token/v1",
                &[("token", self.raw.clone())],
            )
        {
            Ok(())
        } else {
            Err(GcpMemorystoreError::TamperedEvidence)
        }
    }
}
impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}
impl Serialize for OpaquePageToken {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.digest.serialize(serializer)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReceipt {
    pub operation: String,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub location_digest: Digest,
    pub instance_digest: Digest,
    pub page_token_digest: Option<Digest>,
    pub api_digest: Digest,
}
impl RequestReceipt {
    pub(crate) fn validate(&self) -> Result<()> {
        for digest in [
            Some(&self.request_digest),
            Some(&self.path_digest),
            Some(&self.scope_digest),
            Some(&self.project_digest),
            Some(&self.location_digest),
            Some(&self.instance_digest),
            self.page_token_digest.as_ref(),
            Some(&self.api_digest),
        ]
        .into_iter()
        .flatten()
        {
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
    pub bounded_request_units: u32,
    pub cost_digest: Digest,
}
impl CostReceipt {
    pub fn new(operation: impl Into<String>, response_bytes: u64) -> Result<Self> {
        let operation = operation.into();
        let units = 1;
        let cost_digest = Digest::from_parts(
            "gcp-memorystore-cost-receipt/v1",
            &[
                ("operation", operation.clone()),
                ("response_bytes", response_bytes.to_string()),
                ("request_units", units.to_string()),
            ],
        );
        Ok(Self {
            operation,
            response_bytes,
            bounded_request_units: units,
            cost_digest,
        })
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.cost_digest
            == Digest::from_parts(
                "gcp-memorystore-cost-receipt/v1",
                &[
                    ("operation", self.operation.clone()),
                    ("response_bytes", self.response_bytes.to_string()),
                    ("request_units", self.bounded_request_units.to_string()),
                ],
            )
        {
            Ok(())
        } else {
            Err(GcpMemorystoreError::TamperedEvidence)
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
    pub secret_reference_digest: Digest,
    pub list_digest: Option<Digest>,
    pub get_digest: Option<Digest>,
    pub projection_digest: Option<Digest>,
    pub evidence_digest: Digest,
}
impl EvidenceDigests {
    pub(crate) fn compute_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-memorystore-evidence/v1",
            &[
                ("plugin", self.plugin_version_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("list", optional_digest(self.list_digest.as_ref())),
                ("get", optional_digest(self.get_digest.as_ref())),
                (
                    "projection",
                    optional_digest(self.projection_digest.as_ref()),
                ),
            ],
        )
    }
    pub(crate) fn validate(&self) -> Result<()> {
        for digest in [
            Some(&self.plugin_version_digest),
            Some(&self.contract_digest),
            Some(&self.provider_digest),
            Some(&self.api_digest),
            Some(&self.permission_digest),
            Some(&self.scope_digest),
            Some(&self.secret_reference_digest),
            self.list_digest.as_ref(),
            self.get_digest.as_ref(),
            self.projection_digest.as_ref(),
            Some(&self.evidence_digest),
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        if self.evidence_digest == self.compute_evidence_digest() {
            Ok(())
        } else {
            Err(GcpMemorystoreError::TamperedEvidence)
        }
    }
}
pub(crate) fn optional_digest(value: Option<&Digest>) -> String {
    value.map_or_else(String::new, |digest| digest.as_str().to_owned())
}
pub(crate) fn join_digests(values: impl IntoIterator<Item = Digest>) -> String {
    values
        .into_iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Ready,
    Stale,
    Partial,
    AccessLoss,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    TimedOut,
    UnreachableLocation,
    ScopeDrift,
    ApiDrift,
    PaginationLoop,
    Truncated,
    Tampered,
    ProviderUnknown,
    RegistrationRevoked,
    ReplayDetected,
}
impl EvidenceState {
    pub const fn is_review_complete(self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Ready,
    Stale,
    Partial,
    AccessLoss,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    TimedOut,
    UnreachableLocation,
    ScopeDrift,
    ApiDrift,
    PaginationLoop,
    Truncated,
    Tampered,
    ProviderUnknown,
    RegistrationRevoked,
    ReplayDetected,
}
impl From<EvidenceState> for ProposalDisposition {
    fn from(value: EvidenceState) -> Self {
        match value {
            EvidenceState::Ready => Self::Ready,
            EvidenceState::Stale => Self::Stale,
            EvidenceState::Partial => Self::Partial,
            EvidenceState::AccessLoss => Self::AccessLoss,
            EvidenceState::Unauthorized => Self::Unauthorized,
            EvidenceState::Forbidden => Self::Forbidden,
            EvidenceState::NotFound => Self::NotFound,
            EvidenceState::Conflict => Self::Conflict,
            EvidenceState::Throttled => Self::Throttled,
            EvidenceState::TimedOut => Self::TimedOut,
            EvidenceState::UnreachableLocation => Self::UnreachableLocation,
            EvidenceState::ScopeDrift => Self::ScopeDrift,
            EvidenceState::ApiDrift => Self::ApiDrift,
            EvidenceState::PaginationLoop => Self::PaginationLoop,
            EvidenceState::Truncated => Self::Truncated,
            EvidenceState::Tampered => Self::Tampered,
            EvidenceState::ProviderUnknown => Self::ProviderUnknown,
            EvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
            EvidenceState::ReplayDetected => Self::ReplayDetected,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub mission_digest: Digest,
    pub mission_revision: Revision,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub project_digest: Digest,
    pub project_revision: Revision,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub work_product_digest: Digest,
    pub work_product_revision: Revision,
}
pub fn mission_projection(binding: &MissionBinding) -> MissionProjection {
    MissionProjection {
        mission_digest: binding.digest(),
        mission_revision: binding.revision(),
    }
}
pub fn project_projection(binding: &ProjectBinding) -> ProjectProjection {
    ProjectProjection {
        project_digest: binding.digest(),
        project_revision: binding.revision(),
    }
}
pub fn work_product_projection(binding: &WorkProductBinding) -> WorkProductProjection {
    WorkProductProjection {
        work_product_digest: binding.digest(),
        work_product_revision: binding.revision(),
    }
}

const _: u64 = MAX_RESPONSE_BYTES;
