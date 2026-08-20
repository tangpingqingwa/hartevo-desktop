use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::{
    API_REVISION, BLOCKED_ENV, CONTRACT_VERSION, MAX_ACTIVITY_WINDOW_SECONDS, MAX_IDENTIFIER_BYTES,
    MAX_PAGE_SIZE, MAX_PAGES, MAX_REQUEST_AGE_SECONDS, MAX_RESPONSE_BYTES, MAX_SETTINGS_ENTRIES,
    MAX_SQL_ACTIVITY_ENTRIES, PLUGIN_VERSION, PROVIDER_ID,
};
use crate::{CockroachCloudResultError as Error, CockroachCloudTransportError};

/// A lowercase SHA-256 digest used for all externally meaningful bindings.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(hex::encode(Sha256::digest(bytes.as_ref())))
    }

    pub fn from_text(value: impl AsRef<str>) -> Self {
        Self::from_bytes(value.as_ref().as_bytes())
    }

    pub fn from_serializable<T: Serialize>(value: &T) -> Self {
        Self::from_bytes(serde_json::to_vec(value).unwrap_or_default())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(Error::InvalidDigest("digest"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_sha256(&self) -> bool {
        self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

fn domain_digest<T: Serialize>(domain: &str, value: &T) -> Digest {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&serde_json::to_vec(value).unwrap_or_default());
    Digest::from_bytes(bytes)
}

fn validate_text(value: &str, field: &'static str, allow_whitespace: bool) -> Result<(), Error> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
        || (!allow_whitespace && value.chars().any(char::is_whitespace))
    {
        return Err(Error::InvalidInput(field));
    }
    Ok(())
}

fn validate_id(value: &str, field: &'static str) -> Result<(), Error> {
    validate_text(value, field, false)?;
    if value.contains('/') || value.contains('?') || value.contains('#') || value.contains('@') {
        return Err(Error::InvalidInput(field));
    }
    Ok(())
}

macro_rules! identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, Error> {
                let value = value.into();
                validate_id(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                domain_digest(
                    concat!("hartevo:cockroach-cloud-result:", $field, ":v1"),
                    &self.0,
                )
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

identifier!(OrganizationId, "organization_id");
identifier!(CloudProjectId, "cloud_project_id");
identifier!(ClusterId, "cluster_id");
identifier!(RegionId, "region_id");
identifier!(DatabaseId, "database_id");
identifier!(BranchId, "branch_id");
identifier!(ProjectId, "project_id");
identifier!(MissionId, "mission_id");
identifier!(WorkProductId, "work_product_id");

/// Positive revision used for every external and Hartevo scope reference.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, Error> {
        if value == 0 {
            Err(Error::InvalidInput("revision"))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn digest(self) -> Digest {
        domain_digest("hartevo:cockroach-cloud-result:revision:v1", &self.0)
    }
}

impl From<u64> for Revision {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

macro_rules! revision_scope {
    ($name:ident, $id:ident, $field:literal, $domain:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub id: $id,
            pub revision: Revision,
        }

        impl $name {
            pub fn new(id: $id, revision: Revision) -> Result<Self, Error> {
                let binding = Self { id, revision };
                binding.validate()?;
                Ok(binding)
            }

            pub fn id(&self) -> &$id {
                &self.id
            }

            pub const fn revision(&self) -> Revision {
                self.revision
            }

            pub fn digest(&self) -> Digest {
                domain_digest($domain, &(&self.id, self.revision))
            }

            pub fn validate(&self) -> Result<(), Error> {
                validate_id(self.id.as_str(), $field)
            }
        }
    };
}

revision_scope!(
    OrganizationScope,
    OrganizationId,
    "organization_id",
    "hartevo:cockroach-cloud-result:organization:v1"
);
revision_scope!(
    CloudProjectScope,
    CloudProjectId,
    "cloud_project_id",
    "hartevo:cockroach-cloud-result:cloud-project:v1"
);
revision_scope!(
    ClusterScope,
    ClusterId,
    "cluster_id",
    "hartevo:cockroach-cloud-result:cluster:v1"
);
revision_scope!(
    RegionScope,
    RegionId,
    "region_id",
    "hartevo:cockroach-cloud-result:region:v1"
);
revision_scope!(
    DatabaseScope,
    DatabaseId,
    "database_id",
    "hartevo:cockroach-cloud-result:database:v1"
);
revision_scope!(
    BranchScope,
    BranchId,
    "branch_id",
    "hartevo:cockroach-cloud-result:branch:v1"
);
revision_scope!(
    ProjectScope,
    ProjectId,
    "project_id",
    "hartevo:cockroach-cloud-result:hartevo-project:v1"
);
revision_scope!(
    MissionScope,
    MissionId,
    "mission_id",
    "hartevo:cockroach-cloud-result:mission:v1"
);
revision_scope!(
    WorkProductScope,
    WorkProductId,
    "work_product_id",
    "hartevo:cockroach-cloud-result:work-product:v1"
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlActivityKind {
    Statements,
    Transactions,
    Connections,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SqlActivityScope {
    pub kind: SqlActivityKind,
    pub window_start: u64,
    pub window_end: u64,
    pub revision: Revision,
}

impl SqlActivityScope {
    pub fn new(
        kind: SqlActivityKind,
        window_start: u64,
        window_end: u64,
        revision: Revision,
    ) -> Result<Self, Error> {
        if window_end <= window_start || window_end - window_start > MAX_ACTIVITY_WINDOW_SECONDS {
            return Err(Error::InvalidInput("sql_activity_window"));
        }
        Ok(Self {
            kind,
            window_start,
            window_end,
            revision,
        })
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        domain_digest("hartevo:cockroach-cloud-result:sql-activity-scope:v1", self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CockroachCloudPermission {
    OrganizationRead,
    ProjectRead,
    ClusterRead,
    ClusterHealthRead,
    ClusterSettingsRead,
    DatabaseRead,
    BranchRead,
    SqlActivityRead,
    MissionScope,
    WorkProductProposal,
}

impl CockroachCloudPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OrganizationRead => "organization:read",
            Self::ProjectRead => "project:read",
            Self::ClusterRead => "cluster:read",
            Self::ClusterHealthRead => "cluster_health:read",
            Self::ClusterSettingsRead => "cluster_settings:read",
            Self::DatabaseRead => "database:read",
            Self::BranchRead => "branch:read",
            Self::SqlActivityRead => "sql_activity:read",
            Self::MissionScope => "mission.scope",
            Self::WorkProductProposal => "work_product.proposal",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    permissions: BTreeSet<CockroachCloudPermission>,
    permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn least_privilege() -> Self {
        Self::new([
            CockroachCloudPermission::OrganizationRead,
            CockroachCloudPermission::ProjectRead,
            CockroachCloudPermission::ClusterRead,
            CockroachCloudPermission::ClusterHealthRead,
            CockroachCloudPermission::ClusterSettingsRead,
            CockroachCloudPermission::DatabaseRead,
            CockroachCloudPermission::BranchRead,
            CockroachCloudPermission::SqlActivityRead,
            CockroachCloudPermission::MissionScope,
            CockroachCloudPermission::WorkProductProposal,
        ])
    }

    pub fn new<I>(permissions: I) -> Self
    where
        I: IntoIterator<Item = CockroachCloudPermission>,
    {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        let permission_digest = domain_digest(
            "hartevo:cockroach-cloud-result:permissions:v1",
            &permissions,
        );
        Self {
            permissions,
            permission_digest,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.permissions.len() != 10
            || self.permissions != Self::least_privilege().permissions
            || self.permission_digest
                != domain_digest(
                    "hartevo:cockroach-cloud-result:permissions:v1",
                    &self.permissions,
                )
        {
            return Err(Error::PermissionMismatch);
        }
        Ok(())
    }

    pub fn permissions(&self) -> &BTreeSet<CockroachCloudPermission> {
        &self.permissions
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CockroachCloudScope {
    pub organization: OrganizationScope,
    pub cloud_project: CloudProjectScope,
    pub cluster: ClusterScope,
    pub region: RegionScope,
    pub database: DatabaseScope,
    pub branch: BranchScope,
    pub sql_activity: SqlActivityScope,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub permissions: PermissionSnapshot,
    pub scope_revision: Revision,
}

impl CockroachCloudScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization: OrganizationScope,
        cloud_project: CloudProjectScope,
        cluster: ClusterScope,
        region: RegionScope,
        database: DatabaseScope,
        branch: BranchScope,
        sql_activity: SqlActivityScope,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        permissions: PermissionSnapshot,
        scope_revision: Revision,
    ) -> Result<Self, Error> {
        let scope = Self {
            organization,
            cloud_project,
            cluster,
            region,
            database,
            branch,
            sql_activity,
            project,
            mission,
            work_product,
            permissions,
            scope_revision,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.organization.validate()?;
        self.cloud_project.validate()?;
        self.cluster.validate()?;
        self.region.validate()?;
        self.database.validate()?;
        self.branch.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        self.permissions.validate()?;
        if self.scope_revision.get() == 0 {
            return Err(Error::InvalidInput("scope_revision"));
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        domain_digest("hartevo:cockroach-cloud-result:scope:v1", self)
    }

    pub fn permission_digest(&self) -> &Digest {
        self.permissions.digest()
    }

    pub fn revision_fence_digest(&self) -> Digest {
        domain_digest(
            "hartevo:cockroach-cloud-result:revision-fence:v1",
            &(
                self.organization.revision,
                self.cloud_project.revision,
                self.cluster.revision,
                self.region.revision,
                self.database.revision,
                self.branch.revision,
                self.sql_activity.revision,
                self.project.revision,
                self.mission.revision,
                self.work_product.revision,
                self.scope_revision,
            ),
        )
    }

    pub const fn scope_revision(&self) -> Revision {
        self.scope_revision
    }
}

/// Opaque host-keyring reference. The supplied handle is hashed immediately
/// and is never retained, serialized, or printed.
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
    pub fn new(
        opaque_reference: impl AsRef<str>,
        scope: &CockroachCloudScope,
        revision: impl Into<Revision>,
    ) -> Result<Self, Error> {
        let opaque_reference = opaque_reference.as_ref();
        let revision = revision.into();
        validate_text(opaque_reference, "opaque_secret_reference", true)?;
        if revision.get() == 0 {
            return Err(Error::InvalidInput("secret_reference_revision"));
        }
        scope.validate()?;
        Ok(Self {
            reference_digest: domain_digest(
                "hartevo:cockroach-cloud-result:secret-reference:v1",
                &(opaque_reference, scope.digest(), revision),
            ),
            scope_digest: scope.digest(),
            revision,
            revoked: false,
        })
    }

    pub fn for_scope(
        opaque_reference: impl AsRef<str>,
        scope: &CockroachCloudScope,
    ) -> Result<Self, Error> {
        Self::new(opaque_reference, scope, scope.scope_revision())
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), Error> {
        if self.revoked {
            Err(Error::InvalidInput("secret_reference_state"))
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

pub type ProviderProvenance = TransportProvenance;

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

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Healthy,
    Degraded,
    Unavailable,
    Absent,
    Denied,
    Partial,
    Expired,
    AccessLoss,
    RateLimited,
    ProviderUnknown,
    Stale,
    RegistrationRevoked,
}

impl EvidenceState {
    pub const fn is_failure(self) -> bool {
        !matches!(self, Self::Healthy | Self::Degraded)
    }

    pub const fn adoptable(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterState {
    Running,
    Provisioning,
    Paused,
    Draining,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthPosture {
    ProviderHealthy,
    ProviderDegraded,
    ProviderUnavailable,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingsPosture {
    Current,
    Changed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlActivityPosture {
    Quiet,
    Active,
    Elevated,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Reversed,
    Revoked,
}

/// An opaque cursor that retains only its binding digest, page, and expiry.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaqueCursor {
    cursor_digest: Digest,
    scope_digest: Digest,
    revision_fence_digest: Digest,
    query_digest: Digest,
    page: u16,
    expires_at: u64,
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("cursor_digest", &self.cursor_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision_fence_digest", &self.revision_fence_digest)
            .field("query_digest", &self.query_digest)
            .field("page", &self.page)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl OpaqueCursor {
    pub fn new(
        provider_cursor: impl AsRef<str>,
        scope: &CockroachCloudScope,
        query_digest: &Digest,
        page: u16,
        expires_at: u64,
    ) -> Result<Self, Error> {
        let provider_cursor = provider_cursor.as_ref();
        validate_text(provider_cursor, "provider_cursor", true)?;
        if page == 0 || page > MAX_PAGES || expires_at == 0 {
            return Err(Error::PaginationLimit);
        }
        let scope_digest = scope.digest();
        let revision_fence_digest = scope.revision_fence_digest();
        let cursor_digest = domain_digest(
            "hartevo:cockroach-cloud-result:cursor:v1",
            &(
                provider_cursor,
                &scope_digest,
                &revision_fence_digest,
                query_digest,
                page,
                expires_at,
            ),
        );
        Ok(Self {
            cursor_digest,
            scope_digest,
            revision_fence_digest,
            query_digest: query_digest.clone(),
            page,
            expires_at,
        })
    }

    pub fn cursor_digest(&self) -> &Digest {
        &self.cursor_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn revision_fence_digest(&self) -> &Digest {
        &self.revision_fence_digest
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub const fn page(&self) -> u16 {
        self.page
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn validate_for(
        &self,
        scope: &CockroachCloudScope,
        query_digest: &Digest,
        now: u64,
    ) -> Result<(), Error> {
        if self.scope_digest != scope.digest()
            || self.revision_fence_digest != scope.revision_fence_digest()
            || self.query_digest != *query_digest
        {
            return Err(Error::CursorMismatch);
        }
        if now >= self.expires_at {
            return Err(Error::CursorExpired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CockroachCloudReadRequest {
    pub scope: CockroachCloudScope,
    pub page_size: u16,
    pub max_pages: u16,
    pub include_sql_activity: bool,
    pub observed_at: u64,
    pub expires_at: u64,
    pub cursor: Option<OpaqueCursor>,
    pub query_digest: Digest,
    pub request_digest: Digest,
}

impl CockroachCloudReadRequest {
    pub fn new(
        scope: &CockroachCloudScope,
        page_size: u16,
        max_pages: u16,
        include_sql_activity: bool,
        observed_at: u64,
    ) -> Result<Self, Error> {
        scope.validate()?;
        if page_size == 0 || page_size > MAX_PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(Error::PaginationLimit);
        }
        let expires_at = observed_at
            .checked_add(MAX_REQUEST_AGE_SECONDS)
            .ok_or(Error::InvalidInput("request_expiry"))?;
        let query_digest = domain_digest(
            "hartevo:cockroach-cloud-result:query:v1",
            &(
                scope.digest(),
                scope.revision_fence_digest(),
                page_size,
                max_pages,
                include_sql_activity,
            ),
        );
        let request = Self {
            scope: scope.clone(),
            page_size,
            max_pages,
            include_sql_activity,
            observed_at,
            expires_at,
            cursor: None,
            query_digest,
            request_digest: Digest::from_text("pending-request-digest"),
        };
        Ok(Self {
            request_digest: request.calculate_digest(),
            ..request
        })
    }

    pub fn for_scope(scope: &CockroachCloudScope, observed_at: u64) -> Result<Self, Error> {
        Self::new(scope, MAX_PAGE_SIZE, MAX_PAGES, true, observed_at)
    }

    pub fn with_cursor(mut self, cursor: OpaqueCursor, now: u64) -> Result<Self, Error> {
        if cursor.page() > self.max_pages {
            return Err(Error::PaginationLimit);
        }
        cursor.validate_for(&self.scope, &self.query_digest, now)?;
        self.cursor = Some(cursor);
        self.request_digest = self.calculate_digest();
        Ok(self)
    }

    pub fn page(&self) -> u16 {
        self.cursor.as_ref().map_or(1, |cursor| cursor.page())
    }

    pub fn cursor_digest(&self) -> Option<&Digest> {
        self.cursor.as_ref().map(OpaqueCursor::cursor_digest)
    }

    pub fn calculate_digest(&self) -> Digest {
        domain_digest(
            "hartevo:cockroach-cloud-result:read-request:v1",
            &(
                self.scope.digest(),
                self.scope.revision_fence_digest(),
                self.page_size,
                self.max_pages,
                self.include_sql_activity,
                self.observed_at,
                self.expires_at,
                self.cursor_digest(),
                self.query_digest.clone(),
            ),
        )
    }

    pub fn validate_at(&self, now: u64) -> Result<(), Error> {
        self.scope.validate()?;
        if self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.request_digest != self.calculate_digest()
        {
            return Err(Error::InvalidInput("read_request"));
        }
        if now >= self.expires_at {
            return Err(Error::Expired);
        }
        if let Some(cursor) = &self.cursor {
            if cursor.page() > self.max_pages {
                return Err(Error::PaginationLimit);
            }
            cursor.validate_for(&self.scope, &self.query_digest, now)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClusterProjection {
    pub cluster_digest: Digest,
    pub region_digest: Digest,
    pub database_digest: Digest,
    pub branch_digest: Digest,
    pub revision: Revision,
    pub state: ClusterState,
    pub provider_present: bool,
}

impl ClusterProjection {
    pub fn for_scope(scope: &CockroachCloudScope, state: ClusterState) -> Self {
        Self {
            cluster_digest: scope.cluster.id.digest(),
            region_digest: scope.region.id.digest(),
            database_digest: scope.database.id.digest(),
            branch_digest: scope.branch.id.digest(),
            revision: scope.cluster.revision,
            state,
            provider_present: true,
        }
    }

    pub fn digest(&self) -> Digest {
        domain_digest("hartevo:cockroach-cloud-result:cluster-projection:v1", self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HealthProjection {
    pub posture: HealthPosture,
    pub check_count: u16,
    pub status_digest: Digest,
    pub revision: Revision,
    pub provider_reported: bool,
}

impl HealthProjection {
    pub fn for_scope(
        scope: &CockroachCloudScope,
        posture: HealthPosture,
        check_count: u16,
        status: impl AsRef<str>,
    ) -> Result<Self, Error> {
        if usize::from(check_count) > MAX_SETTINGS_ENTRIES {
            return Err(Error::InvalidInput("health_check_count"));
        }
        Ok(Self {
            posture,
            check_count,
            status_digest: Digest::from_text(status),
            revision: scope.cluster.revision,
            provider_reported: true,
        })
    }

    pub fn digest(&self) -> Digest {
        domain_digest("hartevo:cockroach-cloud-result:health-projection:v1", self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettingsMetadataProjection {
    pub entry_count: u16,
    pub names_digest: Digest,
    pub posture: SettingsPosture,
    pub revision: Revision,
    pub values_retained: bool,
    pub provider_reported: bool,
}

impl SettingsMetadataProjection {
    pub fn for_scope(
        scope: &CockroachCloudScope,
        entry_count: u16,
        names: impl AsRef<str>,
        posture: SettingsPosture,
    ) -> Result<Self, Error> {
        if usize::from(entry_count) > MAX_SETTINGS_ENTRIES {
            return Err(Error::InvalidInput("settings_entry_count"));
        }
        Ok(Self {
            entry_count,
            names_digest: Digest::from_text(names),
            posture,
            revision: scope.cluster.revision,
            values_retained: false,
            provider_reported: true,
        })
    }

    pub fn digest(&self) -> Digest {
        domain_digest(
            "hartevo:cockroach-cloud-result:settings-projection:v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SqlActivityProjection {
    pub activity_digest: Digest,
    pub statement_digest: Digest,
    pub posture: SqlActivityPosture,
    pub sample_count: u32,
    pub max_duration_ms: u64,
    pub bytes_read: u64,
    pub revision: Revision,
    pub raw_sql_retained: bool,
    pub raw_result_retained: bool,
}

impl SqlActivityProjection {
    pub fn for_statement(
        scope: &CockroachCloudScope,
        statement: impl AsRef<str>,
        posture: SqlActivityPosture,
        sample_count: u32,
        max_duration_ms: u64,
        bytes_read: u64,
    ) -> Result<Self, Error> {
        let statement = statement.as_ref();
        validate_text(statement, "sql_activity_statement", true)?;
        let statement_digest = Digest::from_text(statement);
        Ok(Self {
            activity_digest: domain_digest(
                "hartevo:cockroach-cloud-result:sql-activity-entry:v1",
                &(
                    &statement_digest,
                    posture,
                    sample_count,
                    max_duration_ms,
                    bytes_read,
                    scope.sql_activity.revision,
                ),
            ),
            statement_digest,
            posture,
            sample_count,
            max_duration_ms,
            bytes_read,
            revision: scope.sql_activity.revision,
            raw_sql_retained: false,
            raw_result_retained: false,
        })
    }

    pub fn digest(&self) -> Digest {
        domain_digest(
            "hartevo:cockroach-cloud-result:sql-activity-projection:v1",
            self,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CockroachCloudPage {
    pub scope_digest: Digest,
    pub revision_fence_digest: Digest,
    pub request_digest: Digest,
    pub page: u16,
    pub request_cursor_digest: Option<Digest>,
    pub cluster: Option<ClusterProjection>,
    pub health: Option<HealthProjection>,
    pub settings: Option<SettingsMetadataProjection>,
    pub sql_activity: Vec<SqlActivityProjection>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl CockroachCloudPage {
    pub fn new(
        request: &CockroachCloudReadRequest,
        cluster: Option<ClusterProjection>,
        health: Option<HealthProjection>,
        settings: Option<SettingsMetadataProjection>,
        sql_activity: Vec<SqlActivityProjection>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self, Error> {
        if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
            return Err(Error::InvalidInput("response_bytes"));
        }
        if sql_activity.len() > MAX_SQL_ACTIVITY_ENTRIES {
            return Err(Error::InvalidInput("sql_activity_entries"));
        }
        if settings
            .as_ref()
            .is_some_and(|settings| usize::from(settings.entry_count) > MAX_SETTINGS_ENTRIES)
        {
            return Err(Error::InvalidInput("settings_entries"));
        }
        if let Some(cursor) = &next_cursor {
            if cursor.scope_digest() != &request.scope.digest()
                || cursor.revision_fence_digest() != &request.scope.revision_fence_digest()
                || cursor.query_digest() != &request.query_digest
                || cursor.page() != request.page() + 1
            {
                return Err(Error::CursorMismatch);
            }
        }
        let mut page = Self {
            scope_digest: request.scope.digest(),
            revision_fence_digest: request.scope.revision_fence_digest(),
            request_digest: request.request_digest.clone(),
            page: request.page(),
            request_cursor_digest: request.cursor_digest().cloned(),
            cluster,
            health,
            settings,
            sql_activity,
            next_cursor,
            response_bytes,
            provenance,
            response_digest: Digest::from_text("pending-response-digest"),
        };
        page.response_digest = page.calculate_digest();
        Ok(page)
    }

    pub fn calculate_digest(&self) -> Digest {
        domain_digest(
            "hartevo:cockroach-cloud-result:page:v1",
            &(
                &self.scope_digest,
                &self.revision_fence_digest,
                &self.request_digest,
                self.page,
                &self.request_cursor_digest,
                &self.cluster,
                &self.health,
                &self.settings,
                &self.sql_activity,
                self.next_cursor.as_ref().map(OpaqueCursor::cursor_digest),
                self.response_bytes,
                self.provenance,
            ),
        )
    }

    pub fn validate_for(&self, request: &CockroachCloudReadRequest) -> Result<(), Error> {
        if self.scope_digest != request.scope.digest()
            || self.revision_fence_digest != request.scope.revision_fence_digest()
            || self.request_digest != request.request_digest
            || self.page != request.page()
            || self.request_cursor_digest.as_ref() != request.cursor_digest()
            || self.response_digest != self.calculate_digest()
        {
            return Err(Error::EvidenceTampered);
        }
        if let Some(cursor) = &self.next_cursor {
            if cursor.scope_digest() != &request.scope.digest()
                || cursor.revision_fence_digest() != &request.scope.revision_fence_digest()
                || cursor.query_digest() != &request.query_digest
                || cursor.page() != request.page() + 1
            {
                return Err(Error::CursorMismatch);
            }
        }
        if self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.sql_activity.len() > MAX_SQL_ACTIVITY_ENTRIES
            || self
                .settings
                .as_ref()
                .is_some_and(|settings| usize::from(settings.entry_count) > MAX_SETTINGS_ENTRIES)
        {
            return Err(Error::InvalidInput("bounded_page"));
        }
        if self
            .sql_activity
            .iter()
            .any(|activity| activity.raw_sql_retained || activity.raw_result_retained)
        {
            return Err(Error::InvalidInput("raw_sql_or_result_retained"));
        }
        Ok(())
    }
}

/// A response projection used by the provider when no raw body is retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderFailureProjection {
    pub state: crate::EvidenceState,
    pub failure_digest: Digest,
    pub retry_after_seconds: Option<u32>,
    pub raw_payload_retained: bool,
}

impl ProviderFailureProjection {
    pub fn new(
        state: crate::EvidenceState,
        reason: impl AsRef<str>,
        retry_after_seconds: Option<u32>,
    ) -> Self {
        Self {
            state,
            failure_digest: Digest::from_text(reason),
            retry_after_seconds,
            raw_payload_retained: false,
        }
    }
}

pub fn provider_manifest_digest() -> Digest {
    domain_digest(
        "hartevo:cockroach-cloud-result:provider-manifest:v1",
        &(
            PROVIDER_ID,
            API_REVISION,
            PLUGIN_VERSION,
            CONTRACT_VERSION,
            BLOCKED_ENV,
            false,
            false,
            false,
        ),
    )
}

pub fn api_digest() -> Digest {
    domain_digest(
        "hartevo:cockroach-cloud-result:api:v1",
        &(
            API_REVISION,
            [
                "GET organization",
                "GET cloud project",
                "GET cluster",
                "GET cluster health",
                "GET settings metadata",
                "GET SQL activity posture",
            ],
        ),
    )
}

pub fn validate_revision_fence(
    scope: &CockroachCloudScope,
    page: &CockroachCloudPage,
) -> Result<(), Error> {
    if page.scope_digest != scope.digest()
        || page.revision_fence_digest != scope.revision_fence_digest()
        || page.cluster.as_ref().is_some_and(|cluster| {
            cluster.revision != scope.cluster.revision
                || !cluster.provider_present
                || cluster.cluster_digest != scope.cluster.id.digest()
                || cluster.region_digest != scope.region.id.digest()
                || cluster.database_digest != scope.database.id.digest()
                || cluster.branch_digest != scope.branch.id.digest()
        })
        || page.health.as_ref().is_some_and(|health| {
            health.revision != scope.cluster.revision || !health.provider_reported
        })
        || page.settings.as_ref().is_some_and(|settings| {
            settings.revision != scope.cluster.revision
                || !settings.provider_reported
                || settings.values_retained
        })
        || page.sql_activity.iter().any(|activity| {
            activity.revision != scope.sql_activity.revision
                || activity.raw_sql_retained
                || activity.raw_result_retained
        })
    {
        return Err(Error::RevisionDrift);
    }
    Ok(())
}

pub fn transport_error_state(error: CockroachCloudTransportError) -> crate::EvidenceState {
    match error {
        CockroachCloudTransportError::Absent => crate::EvidenceState::Absent,
        CockroachCloudTransportError::Denied => crate::EvidenceState::Denied,
        CockroachCloudTransportError::Partial => crate::EvidenceState::Partial,
        CockroachCloudTransportError::AccessLoss => crate::EvidenceState::AccessLoss,
        CockroachCloudTransportError::RateLimited { .. } => crate::EvidenceState::RateLimited,
        CockroachCloudTransportError::BlockedEnv
        | CockroachCloudTransportError::NoRecordedPage
        | CockroachCloudTransportError::InvalidResponse
        | CockroachCloudTransportError::ProviderUnknown
        | CockroachCloudTransportError::TimedOut => crate::EvidenceState::ProviderUnknown,
    }
}

pub fn validate_bounded_counts(
    settings: usize,
    sql_activity: usize,
    response_bytes: u64,
) -> Result<(), Error> {
    if settings > MAX_SETTINGS_ENTRIES
        || sql_activity > MAX_SQL_ACTIVITY_ENTRIES
        || response_bytes == 0
        || response_bytes > MAX_RESPONSE_BYTES
    {
        Err(Error::InvalidInput("bounded_evidence"))
    } else {
        Ok(())
    }
}
