use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsAthenaQueryResultError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGE_TOKEN_BYTES,
    MAX_RESPONSE_BYTES, MAX_RESULT_BYTES, MAX_RESULT_PAGES, MAX_RESULT_ROWS,
};

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
            Err(AwsAthenaQueryResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsAthenaQueryResultError::InvalidDigest)
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

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'$'))
}

macro_rules! redacted_text {
    ($name:ident, $field:literal, $domain:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsAthenaQueryResultError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, &[("value", self.0.clone())])
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsAthenaQueryResultError::InvalidIdentifier { field: $field })
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

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.redacted())
            }
        }
    };
}

redacted_text!(
    AwsAccountId,
    "account",
    "aws-athena-account/v1",
    |value: &str| value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
);
redacted_text!(
    AwsRegion,
    "region",
    "aws-athena-region/v1",
    |value: &str| valid_identifier(value, 64)
);
redacted_text!(
    WorkgroupName,
    "workgroup",
    "aws-athena-workgroup/v1",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);
redacted_text!(
    CatalogName,
    "catalog",
    "aws-athena-catalog/v1",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);
redacted_text!(
    DatabaseName,
    "database",
    "aws-athena-database/v1",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);
redacted_text!(TableName, "table", "aws-athena-table/v1", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
redacted_text!(
    QueryExecutionId,
    "query-execution",
    "aws-athena-query-execution/v1",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);
redacted_text!(
    MissionId,
    "mission",
    "aws-athena-mission/v1",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);
redacted_text!(
    ProjectId,
    "project",
    "aws-athena-project/v1",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);
redacted_text!(
    WorkProductId,
    "work-product",
    "aws-athena-work-product/v1",
    |value: &str| valid_identifier(value, MAX_IDENTIFIER_BYTES)
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(AwsAthenaQueryResultError::InvalidScope)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! revision_identity {
    ($name:ident, $id:ident, $field:literal, $domain:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            id: $id,
            revision: Revision,
        }

        impl $name {
            pub fn new(id: $id, revision: u64) -> Result<Self> {
                let revision = Revision::new(revision)?;
                Ok(Self { id, revision })
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

            pub(crate) fn validate(&self) -> Result<()> {
                self.id.validate()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("id", &self.id)
                    .field("revision", &self.revision)
                    .field("digest", &self.digest())
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                let mut state = serializer.serialize_struct(stringify!($name), 2)?;
                state.serialize_field("idDigest", &self.id.digest())?;
                state.serialize_field("revision", &self.revision)?;
                state.end()
            }
        }
    };
}

revision_identity!(
    MissionIdentity,
    MissionId,
    "mission",
    "aws-athena-mission-identity/v1"
);
revision_identity!(
    ProjectIdentity,
    ProjectId,
    "project",
    "aws-athena-project-identity/v1"
);
revision_identity!(
    WorkProductIdentity,
    WorkProductId,
    "work-product",
    "aws-athena-work-product-identity/v1"
);

#[derive(Clone, Eq, PartialEq)]
pub struct QualifiedTable {
    catalog: CatalogName,
    database: DatabaseName,
    table: TableName,
}

impl QualifiedTable {
    pub fn new(catalog: CatalogName, database: DatabaseName, table: TableName) -> Result<Self> {
        let value = Self {
            catalog,
            database,
            table,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn catalog(&self) -> &CatalogName {
        &self.catalog
    }

    pub fn database(&self) -> &DatabaseName {
        &self.database
    }

    pub fn table(&self) -> &TableName {
        &self.table
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-athena-qualified-table/v1",
            &[
                ("catalog", self.catalog.digest().as_str().to_owned()),
                ("database", self.database.digest().as_str().to_owned()),
                ("table", self.table.digest().as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.catalog.validate()?;
        self.database.validate()?;
        self.table.validate()
    }
}

impl fmt::Debug for QualifiedTable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedTable")
            .field("digest", &self.digest())
            .finish()
    }
}

impl Ord for QualifiedTable {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.digest().cmp(&other.digest())
    }
}

impl PartialOrd for QualifiedTable {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for QualifiedTable {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("table:{}", &self.digest().as_str()[..16]))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsAthenaQueryResultScope {
    account: AwsAccountId,
    region: AwsRegion,
    workgroup: WorkgroupName,
    catalog: CatalogName,
    database: DatabaseName,
    allowlisted_tables: BTreeSet<TableName>,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
    permission_digest: Digest,
    scope_digest: Digest,
}

impl AwsAthenaQueryResultScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        workgroup: WorkgroupName,
        catalog: CatalogName,
        database: DatabaseName,
        allowlisted_tables: impl IntoIterator<Item = TableName>,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
        permission_digest: Digest,
    ) -> Result<Self> {
        let allowlisted_tables = allowlisted_tables.into_iter().collect::<BTreeSet<_>>();
        if allowlisted_tables.is_empty() {
            return Err(AwsAthenaQueryResultError::InvalidScope);
        }
        account.validate()?;
        region.validate()?;
        workgroup.validate()?;
        catalog.validate()?;
        database.validate()?;
        for table in &allowlisted_tables {
            table.validate()?;
        }
        mission.validate()?;
        project.validate()?;
        work_product.validate()?;
        permission_digest.validate()?;
        let scope_digest = Digest::from_parts(
            "aws-athena-query-result-scope/v1",
            &[
                ("account", account.digest().as_str().to_owned()),
                ("region", region.digest().as_str().to_owned()),
                ("workgroup", workgroup.digest().as_str().to_owned()),
                ("catalog", catalog.digest().as_str().to_owned()),
                ("database", database.digest().as_str().to_owned()),
                (
                    "tables",
                    allowlisted_tables
                        .iter()
                        .map(TableName::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("mission", mission.digest().as_str().to_owned()),
                ("project", project.digest().as_str().to_owned()),
                ("work_product", work_product.digest().as_str().to_owned()),
                ("permission", permission_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            account,
            region,
            workgroup,
            catalog,
            database,
            allowlisted_tables,
            mission,
            project,
            work_product,
            permission_digest,
            scope_digest,
        })
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn workgroup(&self) -> &WorkgroupName {
        &self.workgroup
    }

    pub fn catalog(&self) -> &CatalogName {
        &self.catalog
    }

    pub fn database(&self) -> &DatabaseName {
        &self.database
    }

    pub fn allowlisted_tables(&self) -> &BTreeSet<TableName> {
        &self.allowlisted_tables
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission.revision()
    }

    pub const fn project_revision(&self) -> Revision {
        self.project.revision()
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product.revision()
    }

    pub fn contains_table(&self, table: &QualifiedTable) -> bool {
        table.catalog() == &self.catalog
            && table.database() == &self.database
            && self.allowlisted_tables.contains(table.table())
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.allowlisted_tables.is_empty() {
            return Err(AwsAthenaQueryResultError::InvalidScope);
        }
        Self::new(
            self.account.clone(),
            self.region.clone(),
            self.workgroup.clone(),
            self.catalog.clone(),
            self.database.clone(),
            self.allowlisted_tables.clone(),
            self.mission.clone(),
            self.project.clone(),
            self.work_product.clone(),
            self.permission_digest.clone(),
        )
        .map(|scope| {
            if scope.scope_digest != self.scope_digest {
                Err(AwsAthenaQueryResultError::InvalidScope)
            } else {
                Ok(())
            }
        })?
    }
}

impl fmt::Debug for AwsAthenaQueryResultScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAthenaQueryResultScope")
            .field("scope_digest", &self.scope_digest)
            .field("account", &self.account)
            .field("region", &self.region)
            .field("workgroup", &self.workgroup)
            .field("catalog", &self.catalog)
            .field("database", &self.database)
            .field("table_count", &self.allowlisted_tables.len())
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

impl Serialize for AwsAthenaQueryResultScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsAthenaQueryResultScope", 10)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("accountDigest", &self.account.digest())?;
        state.serialize_field("regionDigest", &self.region.digest())?;
        state.serialize_field("workgroupDigest", &self.workgroup.digest())?;
        state.serialize_field("catalogDigest", &self.catalog.digest())?;
        state.serialize_field("databaseDigest", &self.database.digest())?;
        state.serialize_field(
            "tableDigests",
            &self
                .allowlisted_tables
                .iter()
                .map(TableName::digest)
                .collect::<Vec<_>>(),
        )?;
        state.serialize_field("mission", &self.mission)?;
        state.serialize_field("project", &self.project)?;
        state.serialize_field("workProduct", &self.work_product)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    SigV4,
}

/// Opaque, non-serializing reference to host-managed SigV4 credentials.
///
/// The caller-provided handle is hashed and zeroized during construction.  A
/// raw handle, credential, signed header, or secret value is never stored in
/// this type and therefore cannot enter Debug, JSON, or a receipt.
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
        opaque_handle: impl Into<String>,
        scope: &AwsAthenaQueryResultScope,
        credential_revision: u64,
        kind: SecretKind,
    ) -> Result<Self> {
        let mut opaque_handle = opaque_handle.into();
        if !valid_text(&opaque_handle, MAX_IDENTIFIER_BYTES, false) {
            opaque_handle.zeroize();
            return Err(AwsAthenaQueryResultError::InvalidSecretReference);
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
            "aws-athena-secret-reference/v1",
            &[
                ("handle", opaque_handle.clone()),
                ("scope", scope_digest.as_str().to_owned()),
                ("revision", credential_revision.get().to_string()),
                ("kind", format!("{kind:?}")),
            ],
        );
        opaque_handle.zeroize();
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            kind,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsAthenaQueryResultScope,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::new(opaque_handle, scope, credential_revision, SecretKind::SigV4)
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
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

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(AwsAthenaQueryResultError::SecretRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub(crate) fn validate(&self, scope: &AwsAthenaQueryResultScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.credential_revision.get() == 0
            || self.reference_digest.as_str().len() != 64
        {
            Err(AwsAthenaQueryResultError::InvalidSecretReference)
        } else if self.revoked {
            Err(AwsAthenaQueryResultError::SecretRevoked)
        } else {
            Ok(())
        }
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
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
    pub permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if revision == 0 {
            return Err(AwsAthenaQueryResultError::InvalidPermissionSnapshot);
        }
        let permissions = permissions
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        if permissions.is_empty()
            || !permissions
                .iter()
                .all(|permission| LAYER1_PERMISSIONS.contains(&permission.as_str()))
            || !permissions.contains("athena:GetQueryExecution")
        {
            return Err(AwsAthenaQueryResultError::InvalidPermissionSnapshot);
        }
        let permission_digest = Self::compute_digest(revision, &permissions);
        Ok(Self {
            revision,
            permissions,
            permission_digest,
        })
    }

    pub fn for_layer_one(revision: u64) -> Self {
        Self::new(revision, LAYER1_PERMISSIONS)
            .expect("Layer-1 permissions are a valid Athena snapshot")
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        self.permission_digest.clone()
    }

    pub fn allows_results(&self) -> bool {
        self.permissions.contains("athena:GetQueryResults")
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let expected = Self::new(self.revision, self.permissions.clone())?;
        if expected.permission_digest == self.permission_digest {
            Ok(())
        } else {
            Err(AwsAthenaQueryResultError::InvalidPermissionSnapshot)
        }
    }

    fn compute_digest(revision: u64, permissions: &BTreeSet<String>) -> Digest {
        Digest::from_parts(
            "aws-athena-permission-snapshot/v1",
            &[
                ("revision", revision.to_string()),
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join(","),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScope {
    consent_digest: Digest,
    pub revision: u64,
    expires_at: DateTime<Utc>,
    permissions: BTreeSet<String>,
    revoked: bool,
}

impl ConsentScope {
    pub fn new<I, S>(
        consent_id: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
        permissions: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let consent_id = consent_id.into();
        if !valid_text(&consent_id, MAX_IDENTIFIER_BYTES, false) || revision == 0 {
            return Err(AwsAthenaQueryResultError::InvalidConsent);
        }
        let permissions = permissions
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        if permissions.is_empty()
            || !permissions
                .iter()
                .all(|permission| LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            return Err(AwsAthenaQueryResultError::InvalidConsent);
        }
        let consent_digest = Digest::from_parts(
            "aws-athena-consent-scope/v1",
            &[
                ("id", consent_id),
                ("revision", revision.to_string()),
                ("expires", expires_at.to_rfc3339()),
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join(","),
                ),
            ],
        );
        Ok(Self {
            consent_digest,
            revision,
            expires_at,
            permissions,
            revoked: false,
        })
    }

    pub fn for_layer_one(
        consent_id: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(consent_id, revision, expires_at, LAYER1_PERMISSIONS)
    }

    pub fn digest(&self) -> Digest {
        self.consent_digest.clone()
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn is_active_at(&self, at: DateTime<Utc>) -> bool {
        !self.revoked && at <= self.expires_at
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AthenaQueryMode {
    Select,
    Explain,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AthenaExecutionState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Unknown,
}

impl AthenaExecutionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::Running => "RUNNING",
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::Unknown => "UNKNOWN",
        }
    }

    pub fn from_provider_status(status: &str) -> Self {
        match status.to_ascii_uppercase().as_str() {
            "QUEUED" => Self::Queued,
            "RUNNING" => Self::Running,
            "SUCCEEDED" => Self::Succeeded,
            "FAILED" => Self::Failed,
            "CANCELLED" | "CANCELED" => Self::Cancelled,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AthenaQueryResultStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Partial,
    Expired,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
    Stale,
}

impl AthenaQueryResultStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::Running => "RUNNING",
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::Partial => "PARTIAL",
            Self::Expired => "EXPIRED",
            Self::AccessLost => "ACCESS_LOST",
            Self::ProviderUnknown => "PROVIDER_UNKNOWN",
            Self::Tampered => "TAMPERED",
            Self::Revoked => "REVOKED",
            Self::Stale => "STALE",
        }
    }

    pub const fn is_non_adoptable(self) -> bool {
        !matches!(self, Self::Succeeded)
    }

    pub const fn is_review_complete(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Cancelled
                | Self::Partial
                | Self::Expired
                | Self::AccessLost
                | Self::ProviderUnknown
                | Self::Tampered
                | Self::Revoked
                | Self::Stale
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ColumnType {
    Boolean,
    Integer,
    BigInt,
    Double,
    Decimal,
    String,
    Date,
    Timestamp,
    Json,
    Binary,
    Unknown,
}

impl ColumnType {
    pub fn from_provider_type(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "boolean" => Self::Boolean,
            "integer" | "int" => Self::Integer,
            "bigint" | "long" => Self::BigInt,
            "double" | "float" | "real" => Self::Double,
            "decimal" | "numeric" => Self::Decimal,
            "string" | "varchar" | "char" => Self::String,
            "date" => Self::Date,
            "timestamp" | "timestamp with time zone" => Self::Timestamp,
            "json" => Self::Json,
            "varbinary" | "binary" => Self::Binary,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ColumnShape {
    pub ordinal: u16,
    pub name_digest: Digest,
    pub column_type: ColumnType,
    pub nullable: bool,
    pub column_digest: Digest,
}

impl ColumnShape {
    pub fn new(
        ordinal: u16,
        public_name: impl AsRef<str>,
        column_type: ColumnType,
        nullable: bool,
    ) -> Result<Self> {
        let public_name = public_name.as_ref();
        if !valid_text(public_name, MAX_IDENTIFIER_BYTES, false) {
            return Err(AwsAthenaQueryResultError::InvalidIdentifier { field: "column" });
        }
        let name_digest = Digest::from_parts(
            "aws-athena-column-name/v1",
            &[("name", public_name.to_owned())],
        );
        let column_digest = Digest::from_parts(
            "aws-athena-column/v1",
            &[
                ("ordinal", ordinal.to_string()),
                ("name", name_digest.as_str().to_owned()),
                ("type", format!("{column_type:?}")),
                ("nullable", nullable.to_string()),
            ],
        );
        Ok(Self {
            ordinal,
            name_digest,
            column_type,
            nullable,
            column_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.ordinal == 0 || self.name_digest.as_str().len() != 64 {
            Err(AwsAthenaQueryResultError::InvalidResponse)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RowShape {
    pub column_types: Vec<ColumnType>,
    pub row_digest: Digest,
}

impl RowShape {
    pub fn from_digest(column_types: Vec<ColumnType>, row_digest: Digest) -> Result<Self> {
        row_digest.validate()?;
        if column_types.is_empty() {
            return Err(AwsAthenaQueryResultError::InvalidResponse);
        }
        Ok(Self {
            column_types,
            row_digest,
        })
    }

    pub fn from_public_values<I, V>(column_types: Vec<ColumnType>, values: I) -> Result<Self>
    where
        I: IntoIterator<Item = V>,
        V: AsRef<[u8]>,
    {
        let mut bytes = Vec::new();
        for value in values {
            append_field(
                &mut bytes,
                std::str::from_utf8(value.as_ref()).unwrap_or("<binary>"),
            );
        }
        Self::from_digest(column_types, Digest::from_bytes(&bytes))
    }

    pub fn validate(&self) -> Result<()> {
        if self.column_types.is_empty() {
            return Err(AwsAthenaQueryResultError::InvalidResponse);
        }
        self.row_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryResultsProjection {
    pub columns: Vec<ColumnShape>,
    pub rows: Vec<RowShape>,
    pub row_count: u32,
    pub shape_digest: Digest,
}

impl QueryResultsProjection {
    pub fn new(columns: Vec<ColumnShape>, rows: Vec<RowShape>) -> Result<Self> {
        if columns.is_empty()
            || columns.len() > MAX_PAGE_SIZE as usize
            || rows.len() > MAX_RESULT_ROWS as usize
        {
            return Err(AwsAthenaQueryResultError::PartialEvidence);
        }
        let mut ordinals = BTreeSet::new();
        for column in &columns {
            column.validate()?;
            if !ordinals.insert(column.ordinal) {
                return Err(AwsAthenaQueryResultError::InvalidResponse);
            }
        }
        for row in &rows {
            row.validate()?;
            if row.column_types.len() != columns.len() {
                return Err(AwsAthenaQueryResultError::InvalidResponse);
            }
        }
        let shape_digest = Self::compute_digest(&columns, &rows);
        Ok(Self {
            columns,
            row_count: rows.len() as u32,
            rows,
            shape_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.columns.clone(), self.rows.clone())?;
        if expected.shape_digest == self.shape_digest {
            Ok(())
        } else {
            Err(AwsAthenaQueryResultError::EvidenceTampered)
        }
    }

    fn compute_digest(columns: &[ColumnShape], rows: &[RowShape]) -> Digest {
        Digest::from_parts(
            "aws-athena-results-shape/v1",
            &[
                (
                    "columns",
                    columns
                        .iter()
                        .map(|column| column.column_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "rows",
                    rows.iter()
                        .map(|row| row.row_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryExecutionMetadata {
    pub execution_id: QueryExecutionId,
    pub state: AthenaExecutionState,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub workgroup_digest: Digest,
    pub catalog_digest: Digest,
    pub database_digest: Digest,
    pub bytes_scanned: Option<u64>,
    pub execution_time_millis: Option<u64>,
    pub output_location_digest: Option<Digest>,
    pub error_digest: Option<Digest>,
    pub expired: bool,
    pub metadata_digest: Digest,
}

impl QueryExecutionMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &AwsAthenaQueryResultScope,
        query_digest: Digest,
        execution_id: QueryExecutionId,
        state: AthenaExecutionState,
        bytes_scanned: Option<u64>,
        execution_time_millis: Option<u64>,
        output_location: Option<impl AsRef<str>>,
        error_message: Option<impl AsRef<str>>,
        expired: bool,
    ) -> Result<Self> {
        query_digest.validate()?;
        execution_id.validate()?;
        let output_location_digest = output_location.map(|value| {
            Digest::from_parts(
                "aws-athena-output-location/v1",
                &[("location", value.as_ref().to_owned())],
            )
        });
        let error_digest = error_message.map(|value| {
            Digest::from_parts(
                "aws-athena-provider-error/v1",
                &[("message", value.as_ref().to_owned())],
            )
        });
        let mut metadata = Self {
            execution_id,
            state,
            scope_digest: scope.digest(),
            query_digest,
            workgroup_digest: scope.workgroup.digest(),
            catalog_digest: scope.catalog.digest(),
            database_digest: scope.database.digest(),
            bytes_scanned,
            execution_time_millis,
            output_location_digest,
            error_digest,
            expired,
            metadata_digest: Digest::from_text("unsealed-athena-execution-metadata"),
        };
        metadata.metadata_digest = metadata.compute_digest();
        Ok(metadata)
    }

    pub fn validate_against(
        &self,
        scope: &AwsAthenaQueryResultScope,
        query_digest: &Digest,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.query_digest != *query_digest
            || self.workgroup_digest != scope.workgroup.digest()
            || self.catalog_digest != scope.catalog.digest()
            || self.database_digest != scope.database.digest()
            || self
                .validate_against_digest(&scope.digest(), query_digest)
                .is_err()
        {
            Err(AwsAthenaQueryResultError::ExecutionDrift)
        } else {
            Ok(())
        }
    }

    pub(crate) fn validate_against_digest(
        &self,
        scope_digest: &Digest,
        query_digest: &Digest,
    ) -> Result<()> {
        if self.scope_digest != *scope_digest
            || self.query_digest != *query_digest
            || self.metadata_digest != self.compute_digest()
        {
            Err(AwsAthenaQueryResultError::ExecutionDrift)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.metadata_digest
    }

    pub fn execution_id(&self) -> &QueryExecutionId {
        &self.execution_id
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-athena-query-execution-metadata/v1",
            &[
                ("execution", self.execution_id.digest().as_str().to_owned()),
                ("state", self.state.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("query", self.query_digest.as_str().to_owned()),
                ("workgroup", self.workgroup_digest.as_str().to_owned()),
                ("catalog", self.catalog_digest.as_str().to_owned()),
                ("database", self.database_digest.as_str().to_owned()),
                (
                    "bytes_scanned",
                    self.bytes_scanned
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "execution_time_millis",
                    self.execution_time_millis
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "output",
                    self.output_location_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "error",
                    self.error_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("expired", self.expired.to_string()),
            ],
        )
    }
}

pub fn result_page_binding_digest(
    scope: &AwsAthenaQueryResultScope,
    query_digest: &Digest,
    execution_id: &QueryExecutionId,
    bounds: ResultBounds,
) -> Digest {
    Digest::from_parts(
        "aws-athena-results-page-binding/v1",
        &[
            ("scope", scope.digest().as_str().to_owned()),
            ("query", query_digest.as_str().to_owned()),
            ("execution", execution_id.digest().as_str().to_owned()),
            ("max_rows", bounds.max_rows.to_string()),
            ("max_bytes", bounds.max_bytes.to_string()),
            ("max_pages", bounds.max_pages.to_string()),
            ("page_size", bounds.page_size.to_string()),
        ],
    )
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    token_digest: Digest,
    binding_digest: Digest,
    page_number: u16,
}

impl OpaquePageToken {
    pub fn new(
        provider_token: impl Into<String>,
        binding_digest: Digest,
        page_number: u16,
    ) -> Result<Self> {
        let mut provider_token = provider_token.into();
        if !valid_text(&provider_token, MAX_PAGE_TOKEN_BYTES, false)
            || !(2..=MAX_RESULT_PAGES).contains(&page_number)
        {
            provider_token.zeroize();
            return Err(AwsAthenaQueryResultError::InvalidRequest);
        }
        if let Err(error) = binding_digest.validate() {
            provider_token.zeroize();
            return Err(error);
        }
        let token_digest = Digest::from_parts(
            "aws-athena-page-token/v1",
            &[("token", provider_token.clone())],
        );
        provider_token.zeroize();
        Ok(Self {
            token_digest,
            binding_digest,
            page_number,
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn validate_against(&self, binding_digest: &Digest, expected_page: u16) -> Result<()> {
        if self.binding_digest != *binding_digest
            || self.page_number != expected_page
            || self.page_number < 2
        {
            Err(AwsAthenaQueryResultError::PageTokenMismatch)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for OpaquePageToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("OpaquePageToken", 3)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ResultBounds {
    pub max_rows: u32,
    pub max_bytes: u64,
    pub max_pages: u16,
    pub page_size: u16,
}

impl ResultBounds {
    pub fn new(max_rows: u32, max_bytes: u64, max_pages: u16, page_size: u16) -> Result<Self> {
        let bounds = Self {
            max_rows,
            max_bytes,
            max_pages,
            page_size,
        };
        bounds.validate()?;
        Ok(bounds)
    }

    pub fn validate(self) -> Result<()> {
        if self.max_rows == 0
            || self.max_rows > MAX_RESULT_ROWS
            || self.max_bytes == 0
            || self.max_bytes > MAX_RESULT_BYTES
            || self.max_pages == 0
            || self.max_pages > MAX_RESULT_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
        {
            Err(AwsAthenaQueryResultError::InvalidRequest)
        } else {
            Ok(())
        }
    }

    pub const fn max_rows(self) -> u32 {
        self.max_rows
    }

    pub const fn max_bytes(self) -> u64 {
        self.max_bytes
    }

    pub const fn max_pages(self) -> u16 {
        self.max_pages
    }

    pub const fn page_size(self) -> u16 {
        self.page_size
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: Revision,
    pub mission_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: Revision,
    pub project_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: Revision,
    pub work_product_digest: Digest,
}

pub fn mission_projection(scope: &AwsAthenaQueryResultScope) -> MissionProjection {
    MissionProjection {
        id_digest: scope.mission.id.digest(),
        revision: scope.mission.revision,
        mission_digest: scope.mission.digest(),
    }
}

pub fn project_projection(scope: &AwsAthenaQueryResultScope) -> ProjectProjection {
    ProjectProjection {
        id_digest: scope.project.id.digest(),
        revision: scope.project.revision,
        project_digest: scope.project.digest(),
    }
}

pub fn work_product_projection(scope: &AwsAthenaQueryResultScope) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: scope.work_product.id.digest(),
        revision: scope.work_product.revision,
        work_product_digest: scope.work_product.digest(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub evidence_contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_revision_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub execution_digest: Option<Digest>,
    pub results_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReceipt {
    pub operation: String,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub execution_id_digest: Digest,
    pub page_token_digest: Option<Digest>,
    pub response_bytes: u64,
    pub redacted: bool,
    pub receipt_digest: Digest,
}

impl RequestReceipt {
    pub fn new(
        operation: impl Into<String>,
        request_digest: Digest,
        scope_digest: Digest,
        query_digest: Digest,
        execution_id_digest: Digest,
        page_token_digest: Option<Digest>,
        response_bytes: u64,
    ) -> Result<Self> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsAthenaQueryResultError::PartialEvidence);
        }
        let operation = operation.into();
        let receipt_digest = Digest::from_parts(
            "aws-athena-request-receipt/v1",
            &[
                ("operation", operation.clone()),
                ("request", request_digest.as_str().to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
                ("query", query_digest.as_str().to_owned()),
                ("execution", execution_id_digest.as_str().to_owned()),
                (
                    "page_token",
                    page_token_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("response_bytes", response_bytes.to_string()),
            ],
        );
        Ok(Self {
            operation,
            request_digest,
            scope_digest,
            query_digest,
            execution_id_digest,
            page_token_digest,
            response_bytes,
            redacted: true,
            receipt_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if !self.redacted || self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsAthenaQueryResultError::EvidenceTampered);
        }
        let expected = Self::new(
            self.operation.clone(),
            self.request_digest.clone(),
            self.scope_digest.clone(),
            self.query_digest.clone(),
            self.execution_id_digest.clone(),
            self.page_token_digest.clone(),
            self.response_bytes,
        )?;
        if expected.receipt_digest == self.receipt_digest {
            Ok(())
        } else {
            Err(AwsAthenaQueryResultError::EvidenceTampered)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostReceipt {
    pub operation: String,
    pub response_bytes: u64,
    pub bounded_request_units: u32,
    pub estimate_only: bool,
    pub redacted: bool,
    pub cost_digest: Digest,
}

impl CostReceipt {
    pub fn new(operation: impl Into<String>, response_bytes: u64) -> Result<Self> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsAthenaQueryResultError::PartialEvidence);
        }
        let operation = operation.into();
        let bounded_request_units = response_bytes.max(1).div_ceil(64 * 1024) as u32;
        let cost_digest = Digest::from_parts(
            "aws-athena-cost-receipt/v1",
            &[
                ("operation", operation.clone()),
                ("bytes", response_bytes.to_string()),
                ("units", bounded_request_units.to_string()),
            ],
        );
        Ok(Self {
            operation,
            response_bytes,
            bounded_request_units,
            estimate_only: true,
            redacted: true,
            cost_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.operation.clone(), self.response_bytes)?;
        if self.redacted
            && self.estimate_only
            && expected.cost_digest == self.cost_digest
            && expected.bounded_request_units == self.bounded_request_units
        {
            Ok(())
        } else {
            Err(AwsAthenaQueryResultError::EvidenceTampered)
        }
    }
}
