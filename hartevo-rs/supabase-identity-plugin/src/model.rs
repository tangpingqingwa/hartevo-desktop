use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::de::Error as _;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::canonical::{digest_parts, is_sha256, serialized_digest, validate_digest};
use crate::{CONTRACT_VERSION, MAX_COLUMNS_PER_TABLE, MAX_FUNCTIONS, SupabaseIdentityError};
use crate::{MAX_ROLES, MAX_TABLES, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID};

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_CLAIMS: usize = 16;
const MAX_PREDICATE_DIGEST_BYTES: usize = 64;

mod table_column_map {
    use super::TableScope;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Entry {
        table: TableScope,
        columns: BTreeSet<String>,
    }

    pub fn serialize<S>(
        map: &BTreeMap<TableScope, BTreeSet<String>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        map.iter()
            .map(|(table, columns)| Entry {
                table: table.clone(),
                columns: columns.clone(),
            })
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<TableScope, BTreeSet<String>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = Vec::<Entry>::deserialize(deserializer)?;
        Ok(entries
            .into_iter()
            .map(|entry| (entry.table, entry.columns))
            .collect())
    }
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), SupabaseIdentityError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(SupabaseIdentityError::InvalidModel(format!(
            "{field} must be non-empty, bounded, and free of whitespace/control characters"
        )));
    }
    Ok(())
}

fn validate_https_url(value: &str, field: &'static str) -> Result<(), SupabaseIdentityError> {
    validate_identifier(value, field)?;
    if !value.starts_with("https://")
        || value.contains('?')
        || value.contains('#')
        || value.contains('@')
    {
        return Err(SupabaseIdentityError::InvalidModel(format!(
            "{field} must be an HTTPS origin without credentials, query, or fragment"
        )));
    }
    Ok(())
}

/// Mission, Hartevo project, Work Product, tenant, and consent fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub mission_id: String,
    pub mission_revision: u64,
    pub project_id: String,
    pub work_product_id: Option<String>,
    pub consent_reference: String,
    pub consent_revision: u64,
    pub tenant_id: String,
}

impl MissionScope {
    pub fn new(
        mission_id: impl Into<String>,
        mission_revision: u64,
        project_id: impl Into<String>,
        work_product_id: Option<String>,
        consent_reference: impl Into<String>,
        consent_revision: u64,
        tenant_id: impl Into<String>,
    ) -> Result<Self, SupabaseIdentityError> {
        let scope = Self {
            mission_id: mission_id.into(),
            mission_revision,
            project_id: project_id.into(),
            work_product_id,
            consent_reference: consent_reference.into(),
            consent_revision,
            tenant_id: tenant_id.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), SupabaseIdentityError> {
        validate_identifier(&self.mission_id, "mission_id")?;
        validate_identifier(&self.project_id, "project_id")?;
        validate_identifier(&self.consent_reference, "consent_reference")?;
        validate_identifier(&self.tenant_id, "tenant_id")?;
        if self.mission_revision == 0 || self.consent_revision == 0 {
            return Err(SupabaseIdentityError::InvalidModel(
                "mission and consent revisions must be positive".into(),
            ));
        }
        if let Some(work_product_id) = &self.work_product_id {
            validate_identifier(work_product_id, "work_product_id")?;
        }
        Ok(())
    }
}

impl Default for MissionScope {
    fn default() -> Self {
        Self {
            mission_id: "mission-fixture".into(),
            mission_revision: 1,
            project_id: "project-fixture".into(),
            work_product_id: Some("work-product-fixture".into()),
            consent_reference: "consent-fixture".into(),
            consent_revision: 1,
            tenant_id: "tenant-fixture".into(),
        }
    }
}

/// Exact schema/table fence; this is metadata only and never a row query.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TableScope {
    pub schema: String,
    pub table: String,
}

impl TableScope {
    pub fn new(
        schema: impl Into<String>,
        table: impl Into<String>,
    ) -> Result<Self, SupabaseIdentityError> {
        let value = Self {
            schema: schema.into(),
            table: table.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SupabaseIdentityError> {
        validate_identifier(&self.schema, "table schema")?;
        validate_identifier(&self.table, "table name")?;
        Ok(())
    }

    pub fn key(&self) -> String {
        format!("{}.{}", self.schema, self.table)
    }
}

/// Exact project, tenant, JWT, role, table, policy, and Mission fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupabaseScope {
    pub project_id: String,
    pub project_ref: String,
    pub region: String,
    pub management_api_host: String,
    pub auth_api_host: String,
    pub postgrest_api_host: String,
    pub auth_issuer: String,
    pub auth_audience: String,
    pub tenant_id: String,
    pub subject_user_id: Option<String>,
    pub allowed_roles: BTreeSet<String>,
    pub tables: BTreeSet<TableScope>,
    #[serde(with = "table_column_map")]
    pub allowlisted_columns: BTreeMap<TableScope, BTreeSet<String>>,
    pub allowed_functions: BTreeSet<String>,
    pub grant_revision: String,
    pub policy_revision: String,
    pub mission: MissionScope,
}

impl SupabaseScope {
    pub fn new(
        project_id: impl Into<String>,
        project_ref: impl Into<String>,
        region: impl Into<String>,
        mission: MissionScope,
        auth_audience: impl Into<String>,
    ) -> Result<Self, SupabaseIdentityError> {
        let project_ref = project_ref.into();
        let scope = Self {
            project_id: project_id.into(),
            region: region.into(),
            management_api_host: "https://api.supabase.com".into(),
            auth_api_host: format!("https://{project_ref}.supabase.co/auth/v1"),
            postgrest_api_host: format!("https://{project_ref}.supabase.co/rest/v1"),
            auth_issuer: format!("https://{project_ref}.supabase.co/auth/v1"),
            auth_audience: auth_audience.into(),
            tenant_id: mission.tenant_id.clone(),
            project_ref,
            subject_user_id: Some("user-fixture".into()),
            allowed_roles: BTreeSet::from(["authenticated".into()]),
            tables: BTreeSet::from([TableScope::new("public", "profiles")?]),
            allowlisted_columns: BTreeMap::from([(
                TableScope::new("public", "profiles")?,
                BTreeSet::from(["id".into(), "tenant_id".into()]),
            )]),
            allowed_functions: BTreeSet::new(),
            grant_revision: "grant-revision-1".into(),
            policy_revision: "policy-revision-1".into(),
            mission,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn fixture() -> Self {
        Self::default()
    }

    pub fn with_subject_user(
        mut self,
        user_id: impl Into<String>,
    ) -> Result<Self, SupabaseIdentityError> {
        let user_id = user_id.into();
        validate_identifier(&user_id, "subject_user_id")?;
        self.subject_user_id = Some(user_id);
        self.validate()?;
        Ok(self)
    }

    pub fn with_roles(
        mut self,
        roles: impl IntoIterator<Item = String>,
    ) -> Result<Self, SupabaseIdentityError> {
        self.allowed_roles = roles.into_iter().collect();
        self.validate()?;
        Ok(self)
    }

    pub fn with_table(
        mut self,
        table: TableScope,
        columns: impl IntoIterator<Item = String>,
    ) -> Result<Self, SupabaseIdentityError> {
        let columns = columns.into_iter().collect::<BTreeSet<_>>();
        self.tables.insert(table.clone());
        self.allowlisted_columns.insert(table, columns);
        self.validate()?;
        Ok(self)
    }

    pub fn with_revisions(
        mut self,
        grant_revision: impl Into<String>,
        policy_revision: impl Into<String>,
    ) -> Result<Self, SupabaseIdentityError> {
        self.grant_revision = grant_revision.into();
        self.policy_revision = policy_revision.into();
        self.validate()?;
        Ok(self)
    }

    pub fn digest(&self) -> String {
        serialized_digest(self).expect("validated scope is serializable")
    }

    pub fn matches_mission(&self, mission: &MissionScope) -> bool {
        self.mission == *mission
    }

    pub fn expected_auth_issuer(project_ref: &str) -> String {
        format!("https://{project_ref}.supabase.co/auth/v1")
    }

    pub fn validate(&self) -> Result<(), SupabaseIdentityError> {
        validate_identifier(&self.project_id, "project_id")?;
        validate_identifier(&self.project_ref, "project_ref")?;
        validate_identifier(&self.region, "region")?;
        validate_https_url(&self.management_api_host, "management_api_host")?;
        validate_https_url(&self.auth_api_host, "auth_api_host")?;
        validate_https_url(&self.postgrest_api_host, "postgrest_api_host")?;
        validate_https_url(&self.auth_issuer, "auth_issuer")?;
        validate_identifier(&self.auth_audience, "auth_audience")?;
        validate_identifier(&self.tenant_id, "tenant_id")?;
        if self.auth_api_host != self.auth_issuer
            || self.auth_issuer != Self::expected_auth_issuer(&self.project_ref)
        {
            return Err(SupabaseIdentityError::InvalidModel(
                "auth issuer must be the exact project-scoped Supabase Auth issuer".into(),
            ));
        }
        if self.allowed_roles.is_empty() || self.allowed_roles.len() > MAX_ROLES {
            return Err(SupabaseIdentityError::InvalidModel(
                "allowed_roles must be non-empty and bounded".into(),
            ));
        }
        if self.tables.is_empty() || self.tables.len() > MAX_TABLES {
            return Err(SupabaseIdentityError::InvalidModel(
                "tables must be non-empty and bounded".into(),
            ));
        }
        for role in &self.allowed_roles {
            validate_identifier(role, "allowed role")?;
        }
        if let Some(user_id) = &self.subject_user_id {
            validate_identifier(user_id, "subject_user_id")?;
        }
        for table in &self.tables {
            table.validate()?;
            let columns = self.allowlisted_columns.get(table).ok_or_else(|| {
                SupabaseIdentityError::InvalidModel("missing table columns".into())
            })?;
            if columns.len() > MAX_COLUMNS_PER_TABLE {
                return Err(SupabaseIdentityError::InvalidModel(
                    "column allowlist is too large".into(),
                ));
            }
            for column in columns {
                validate_identifier(column, "allowlisted column")?;
            }
        }
        if self
            .allowlisted_columns
            .keys()
            .any(|table| !self.tables.contains(table))
        {
            return Err(SupabaseIdentityError::InvalidModel(
                "column allowlist contains an out-of-scope table".into(),
            ));
        }
        if self.allowed_functions.len() > MAX_FUNCTIONS {
            return Err(SupabaseIdentityError::InvalidModel(
                "function allowlist is too large".into(),
            ));
        }
        for function in &self.allowed_functions {
            validate_identifier(function, "allowed function")?;
        }
        validate_identifier(&self.grant_revision, "grant_revision")?;
        validate_identifier(&self.policy_revision, "policy_revision")?;
        self.mission.validate()?;
        Ok(())
    }
}

impl Default for SupabaseScope {
    fn default() -> Self {
        Self::new(
            "project-fixture",
            "abcdefghijklmnopqrst",
            "us-east-1",
            MissionScope::default(),
            "authenticated",
        )
        .expect("fixture scope is valid")
    }
}

/// The only credential authority metadata that can cross this crate.  It is
/// not the credential material and is never sufficient to mint or use a key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialAuthority {
    ProjectScopedOAuth,
    AnonKey,
    ServiceRole,
    Unknown,
}

/// Opaque, project-bound credential reference.  Its custom serializer omits
/// credential class as well as all material; JWTs and keys cannot be stored in
/// this type.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_id: String,
    project_ref: String,
    scope_digest: String,
    credential_revision: u64,
    authority: CredentialAuthority,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_id", &self.reference_id)
            .field("project_ref", &self.project_ref)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("authority", &self.authority)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        project_ref: impl Into<String>,
        scope_digest: impl Into<String>,
        credential_revision: u64,
        authority: CredentialAuthority,
    ) -> Result<Self, SupabaseIdentityError> {
        let reference = Self {
            reference_id: reference_id.into(),
            project_ref: project_ref.into(),
            scope_digest: scope_digest.into(),
            credential_revision,
            authority,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn oauth(
        reference_id: impl Into<String>,
        scope: &SupabaseScope,
        credential_revision: u64,
    ) -> Result<Self, SupabaseIdentityError> {
        Self::new(
            reference_id,
            scope.project_ref.clone(),
            scope.digest(),
            credential_revision,
            CredentialAuthority::ProjectScopedOAuth,
        )
    }

    pub fn anon_key(
        reference_id: impl Into<String>,
        scope: &SupabaseScope,
        credential_revision: u64,
    ) -> Result<Self, SupabaseIdentityError> {
        Self::new(
            reference_id,
            scope.project_ref.clone(),
            scope.digest(),
            credential_revision,
            CredentialAuthority::AnonKey,
        )
    }

    pub fn service_role(
        reference_id: impl Into<String>,
        scope: &SupabaseScope,
        credential_revision: u64,
    ) -> Result<Self, SupabaseIdentityError> {
        Self::new(
            reference_id,
            scope.project_ref.clone(),
            scope.digest(),
            credential_revision,
            CredentialAuthority::ServiceRole,
        )
    }

    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub fn project_ref(&self) -> &str {
        &self.project_ref
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn authority(&self) -> CredentialAuthority {
        self.authority
    }

    pub const fn is_service_role(&self) -> bool {
        matches!(self.authority, CredentialAuthority::ServiceRole)
    }

    pub fn validate(&self) -> Result<(), SupabaseIdentityError> {
        validate_identifier(&self.reference_id, "secret reference id")?;
        validate_identifier(&self.project_ref, "secret reference project ref")?;
        validate_digest(&self.scope_digest, "secret reference scope digest")?;
        if self.credential_revision == 0 {
            return Err(SupabaseIdentityError::InvalidModel(
                "credential revision must be positive".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecretReferenceWire {
    reference_id: String,
    project_ref: String,
    scope_digest: String,
    credential_revision: u64,
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretReference", 4)?;
        state.serialize_field("referenceId", &self.reference_id)?;
        state.serialize_field("projectRef", &self.project_ref)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("credentialRevision", &self.credential_revision)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SecretReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SecretReferenceWire::deserialize(deserializer)?;
        Self::new(
            wire.reference_id,
            wire.project_ref,
            wire.scope_digest,
            wire.credential_revision,
            CredentialAuthority::Unknown,
        )
        .map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportMode {
    pub const fn native_status(self) -> NativeStatus {
        NativeStatus::BlockedEnv
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_native(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeStatus {
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
    ProviderUnknown,
}

impl From<TransportMode> for EvidenceProvenance {
    fn from(mode: TransportMode) -> Self {
        match mode {
            TransportMode::Fixture => Self::Fixture,
            TransportMode::Recording => Self::Recording,
            TransportMode::Loopback => Self::Loopback,
            TransportMode::BlockedEnv => Self::BlockedEnv,
        }
    }
}

impl EvidenceProvenance {
    pub const fn native_status(self) -> NativeStatus {
        NativeStatus::BlockedEnv
    }

    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Present,
    Absent,
    Denied,
    Expired,
    ScopeMismatch,
    ProviderUnknown,
    Tampered,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum ProjectionReason {
    NoIdentity,
    UserDeleted,
    AccessLost,
    AnonymousCredential,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    Timeout,
    ServerFailure { status: u16 },
    BlockedEnv,
    ProviderUnknown { code: String },
    WrongAudience,
    WrongIssuer,
    JwtExpired,
    JwtNotVerified,
    RoleNotAllowed,
    TenantCrossing,
    ProjectDrift,
    GrantPolicyMismatch,
    GrantRevisionDrift,
    PolicyRevisionDrift,
    ServiceRoleAuthority,
    IntegrityFailure,
    RegistrationRevoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupabaseOperation {
    DescribeCapabilities,
    ProbeRegistration,
    ReadProjectMetadata,
    ReadAuthIdentity,
    ReadJwtClaimEvidence,
    ReadDatabaseGrants,
    ReadRlsPolicyMetadata,
    CompilePolicyDecisionProposal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupabasePermissionSet {
    pub operations: BTreeSet<SupabaseOperation>,
    pub allowlisted_columns_digest: String,
    pub service_role_allowed: bool,
    pub mutation_allowed: bool,
}

impl SupabasePermissionSet {
    pub fn layer1(scope: &SupabaseScope) -> Result<Self, SupabaseIdentityError> {
        let permission_set = Self {
            operations: BTreeSet::from([
                SupabaseOperation::DescribeCapabilities,
                SupabaseOperation::ProbeRegistration,
                SupabaseOperation::ReadProjectMetadata,
                SupabaseOperation::ReadAuthIdentity,
                SupabaseOperation::ReadJwtClaimEvidence,
                SupabaseOperation::ReadDatabaseGrants,
                SupabaseOperation::ReadRlsPolicyMetadata,
                SupabaseOperation::CompilePolicyDecisionProposal,
            ]),
            allowlisted_columns_digest: serialized_digest(scope)?,
            service_role_allowed: false,
            mutation_allowed: false,
        };
        permission_set.validate()?;
        Ok(permission_set)
    }

    pub fn digest(&self) -> String {
        serialized_digest(self).expect("validated permissions are serializable")
    }

    pub fn validate(&self) -> Result<(), SupabaseIdentityError> {
        if self.operations.is_empty()
            || self.service_role_allowed
            || self.mutation_allowed
            || !is_sha256(&self.allowlisted_columns_digest)
        {
            return Err(SupabaseIdentityError::PermissionDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Reversed,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityRegistration {
    pub registration_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: String,
    pub provider_id: String,
    pub provider_api_revision: String,
    pub provider_digest: String,
    pub permission_digest: String,
    pub scope_digest: String,
    pub scope: SupabaseScope,
    pub state: RegistrationState,
    pub registration_digest: String,
}

impl CapabilityRegistration {
    pub fn new(
        registration_id: impl Into<String>,
        scope: SupabaseScope,
        provider_digest: impl Into<String>,
        permissions: &SupabasePermissionSet,
    ) -> Result<Self, SupabaseIdentityError> {
        scope.validate()?;
        permissions.validate()?;
        let registration = Self {
            registration_id: registration_id.into(),
            plugin_version: PLUGIN_VERSION.into(),
            contract_version: CONTRACT_VERSION.into(),
            contract_digest: crate::contract_digest(),
            provider_id: PROVIDER_ID.into(),
            provider_api_revision: PROVIDER_API_REVISION.into(),
            provider_digest: provider_digest.into(),
            permission_digest: permissions.digest(),
            scope_digest: scope.digest(),
            scope,
            state: RegistrationState::Active,
            registration_digest: String::new(),
        };
        registration.with_computed_digest()
    }

    fn with_computed_digest(mut self) -> Result<Self, SupabaseIdentityError> {
        validate_identifier(&self.registration_id, "registration_id")?;
        self.registration_digest = self.expected_registration_digest()?;
        Ok(self)
    }

    fn expected_registration_digest(&self) -> Result<String, SupabaseIdentityError> {
        serialized_digest(&RegistrationDigestMaterial {
            registration_id: &self.registration_id,
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_api_revision: &self.provider_api_revision,
            provider_digest: &self.provider_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
        })
    }

    pub fn validate(
        &self,
        permissions: &SupabasePermissionSet,
    ) -> Result<(), SupabaseIdentityError> {
        self.scope.validate()?;
        permissions.validate()?;
        validate_digest(&self.contract_digest, "contract_digest")?;
        validate_digest(&self.provider_digest, "provider_digest")?;
        validate_digest(&self.permission_digest, "permission_digest")?;
        validate_digest(&self.scope_digest, "scope_digest")?;
        validate_digest(&self.registration_digest, "registration_digest")?;
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_api_revision != PROVIDER_API_REVISION
            || self.scope_digest != self.scope.digest()
            || self.permission_digest != permissions.digest()
            || self.registration_digest != self.expected_registration_digest()?
        {
            return Err(SupabaseIdentityError::RegistrationDrift);
        }
        Ok(())
    }

    pub fn assert_fences(
        &self,
        scope: &SupabaseScope,
        provider_digest: &str,
        permissions: &SupabasePermissionSet,
    ) -> Result<(), SupabaseIdentityError> {
        if self.scope_digest != scope.digest()
            || self.provider_digest != provider_digest
            || self.permission_digest != permissions.digest()
        {
            return Err(SupabaseIdentityError::RegistrationDrift);
        }
        self.validate(permissions)
    }

    pub fn reverse(&mut self) -> Result<(), SupabaseIdentityError> {
        match self.state {
            RegistrationState::Active => {
                self.state = RegistrationState::Reversed;
                Ok(())
            }
            RegistrationState::Reversed => Ok(()),
            RegistrationState::Revoked => Err(SupabaseIdentityError::RegistrationRevoked),
        }
    }

    pub fn restore(&mut self) -> Result<(), SupabaseIdentityError> {
        match self.state {
            RegistrationState::Reversed => {
                self.state = RegistrationState::Active;
                Ok(())
            }
            RegistrationState::Active => Ok(()),
            RegistrationState::Revoked => Err(SupabaseIdentityError::RegistrationRevoked),
        }
    }

    pub fn revoke(&mut self) -> Result<(), SupabaseIdentityError> {
        self.state = RegistrationState::Revoked;
        Ok(())
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }
}

#[derive(Serialize)]
struct RegistrationDigestMaterial<'a> {
    registration_id: &'a str,
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a str,
    provider_id: &'a str,
    provider_api_revision: &'a str,
    provider_digest: &'a str,
    permission_digest: &'a str,
    scope_digest: &'a str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "explicit authority/status flags are part of the external evidence contract"
)]
pub struct CapabilityDescription {
    pub capability_id: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub provider_id: String,
    pub contract_digest: String,
    pub provider_digest: String,
    pub permission_digest: String,
    pub scope_digest: String,
    pub operations: BTreeSet<SupabaseOperation>,
    pub provenance: EvidenceProvenance,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub identity_authority: bool,
    pub truth_authority: bool,
    pub effect_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationProbe {
    pub registration_digest: String,
    pub provider_digest: String,
    pub permission_digest: String,
    pub scope_digest: String,
    pub state: RegistrationState,
    pub observed_at: DateTime<Utc>,
    pub provenance: EvidenceProvenance,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub evidence_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityState {
    Active,
    Deleted,
    AccessLost,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

impl ClaimValue {
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            Self::Integer(_) | Self::Boolean(_) => None,
        }
    }
}

const ALLOWLISTED_JWT_CLAIMS: &[&str] = &[
    "aal",
    "amr",
    "aud",
    "exp",
    "iat",
    "iss",
    "nbf",
    "role",
    "sub",
    "tenant_id",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JwtClaimsEvidence {
    pub issuer: String,
    pub audience: String,
    pub subject: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub not_before: Option<DateTime<Utc>>,
    pub claims: BTreeMap<String, ClaimValue>,
    pub token_digest: String,
    pub signature_verified: bool,
}

impl JwtClaimsEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        subject: impl Into<String>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        not_before: Option<DateTime<Utc>>,
        claims: BTreeMap<String, ClaimValue>,
        token_digest: impl Into<String>,
        signature_verified: bool,
    ) -> Result<Self, SupabaseIdentityError> {
        let evidence = Self {
            issuer: issuer.into(),
            audience: audience.into(),
            subject: subject.into(),
            issued_at,
            expires_at,
            not_before,
            claims,
            token_digest: token_digest.into(),
            signature_verified,
        };
        evidence.validate_shape()?;
        Ok(evidence)
    }

    pub fn fixture(scope: &SupabaseScope, now: DateTime<Utc>, user_id: &str) -> Self {
        let expires_at = now + Duration::hours(1);
        let claims = BTreeMap::from([
            (
                "aud".into(),
                ClaimValue::String(scope.auth_audience.clone()),
            ),
            ("exp".into(), ClaimValue::Integer(expires_at.timestamp())),
            ("iat".into(), ClaimValue::Integer(now.timestamp())),
            ("iss".into(), ClaimValue::String(scope.auth_issuer.clone())),
            ("role".into(), ClaimValue::String("authenticated".into())),
            ("sub".into(), ClaimValue::String(user_id.into())),
            (
                "tenant_id".into(),
                ClaimValue::String(scope.tenant_id.clone()),
            ),
        ]);
        Self::new(
            scope.auth_issuer.clone(),
            scope.auth_audience.clone(),
            user_id,
            now,
            expires_at,
            None,
            claims,
            digest_parts(&["fixture-jwt-opaque", user_id, &scope.digest()]),
            true,
        )
        .expect("fixture claims are valid")
    }

    pub fn validate_for(
        &self,
        scope: &SupabaseScope,
        now: DateTime<Utc>,
    ) -> Result<(), SupabaseIdentityError> {
        self.validate_shape()?;
        if self.issuer != scope.auth_issuer {
            return Err(SupabaseIdentityError::JwtIssuerMismatch);
        }
        if self.audience != scope.auth_audience {
            return Err(SupabaseIdentityError::JwtAudienceMismatch);
        }
        if self.subject.is_empty()
            || scope
                .subject_user_id
                .as_ref()
                .is_some_and(|expected| expected != &self.subject)
        {
            return Err(SupabaseIdentityError::ProjectMismatch);
        }
        if !self.signature_verified {
            return Err(SupabaseIdentityError::JwtNotVerified);
        }
        if now >= self.expires_at
            || self.issued_at > now
            || self.not_before.is_some_and(|time| time > now)
        {
            return Err(SupabaseIdentityError::JwtExpired);
        }
        if self
            .claims
            .get("tenant_id")
            .and_then(ClaimValue::as_string)
            .is_some_and(|tenant| tenant != scope.tenant_id)
        {
            return Err(SupabaseIdentityError::TenantMismatch);
        }
        if self
            .claims
            .get("role")
            .and_then(ClaimValue::as_string)
            .is_some_and(|role| !scope.allowed_roles.contains(role))
        {
            return Err(SupabaseIdentityError::RoleMismatch);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), SupabaseIdentityError> {
        validate_https_url(&self.issuer, "JWT issuer")?;
        validate_identifier(&self.audience, "JWT audience")?;
        validate_identifier(&self.subject, "JWT subject")?;
        validate_digest(&self.token_digest, "token_digest")?;
        if self.expires_at <= self.issued_at || self.claims.len() > MAX_CLAIMS {
            return Err(SupabaseIdentityError::InvalidModel(
                "JWT claim evidence has an invalid time window or claim bound".into(),
            ));
        }
        if self
            .claims
            .keys()
            .any(|claim| !ALLOWLISTED_JWT_CLAIMS.contains(&claim.as_str()))
        {
            return Err(SupabaseIdentityError::InvalidModel(
                "JWT claim is outside the allowlist".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupabaseIdentityRecord {
    pub user_id: String,
    pub tenant_id: String,
    pub role: String,
    pub state: IdentityState,
    pub provider_revision: String,
}

impl SupabaseIdentityRecord {
    pub fn new(
        user_id: impl Into<String>,
        tenant_id: impl Into<String>,
        role: impl Into<String>,
        state: IdentityState,
        provider_revision: impl Into<String>,
    ) -> Result<Self, SupabaseIdentityError> {
        let record = Self {
            user_id: user_id.into(),
            tenant_id: tenant_id.into(),
            role: role.into(),
            state,
            provider_revision: provider_revision.into(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), SupabaseIdentityError> {
        validate_identifier(&self.user_id, "identity user_id")?;
        validate_identifier(&self.tenant_id, "identity tenant_id")?;
        validate_identifier(&self.role, "identity role")?;
        validate_identifier(&self.provider_revision, "identity provider_revision")?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabasePrivilege {
    Select,
    Insert,
    Update,
    Delete,
    References,
    Usage,
    Execute,
}

impl DatabasePrivilege {
    pub const fn is_read(self) -> bool {
        matches!(self, Self::Select | Self::Usage)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatabaseGrant {
    pub role: String,
    pub table: TableScope,
    pub column: Option<String>,
    pub privilege: DatabasePrivilege,
    pub grantable: bool,
    pub tenant_id: Option<String>,
}

impl DatabaseGrant {
    pub fn select(
        role: impl Into<String>,
        table: TableScope,
        tenant_id: impl Into<String>,
    ) -> Result<Self, SupabaseIdentityError> {
        Self::new(
            role,
            table,
            None,
            DatabasePrivilege::Select,
            false,
            Some(tenant_id.into()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: impl Into<String>,
        table: TableScope,
        column: Option<String>,
        privilege: DatabasePrivilege,
        grantable: bool,
        tenant_id: Option<String>,
    ) -> Result<Self, SupabaseIdentityError> {
        let grant = Self {
            role: role.into(),
            table,
            column,
            privilege,
            grantable,
            tenant_id,
        };
        grant.validate()?;
        Ok(grant)
    }

    pub fn validate(&self) -> Result<(), SupabaseIdentityError> {
        validate_identifier(&self.role, "grant role")?;
        self.table.validate()?;
        if let Some(column) = &self.column {
            validate_identifier(column, "grant column")?;
        }
        if let Some(tenant_id) = &self.tenant_id {
            validate_identifier(tenant_id, "grant tenant_id")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCommand {
    Select,
    Insert,
    Update,
    Delete,
    All,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RlsPolicyEvidence {
    pub policy_id: String,
    pub table: TableScope,
    pub role: String,
    pub command: PolicyCommand,
    pub enabled: bool,
    pub permissive: bool,
    pub using_predicate_digest: String,
    pub check_predicate_digest: Option<String>,
    pub tenant_id: Option<String>,
    pub policy_revision: String,
}

impl RlsPolicyEvidence {
    pub fn allow_read(
        policy_id: impl Into<String>,
        table: TableScope,
        role: impl Into<String>,
        tenant_id: impl Into<String>,
        policy_revision: impl Into<String>,
    ) -> Result<Self, SupabaseIdentityError> {
        let policy_id = policy_id.into();
        let role = role.into();
        let tenant_id = tenant_id.into();
        let policy_revision = policy_revision.into();
        Self::new(
            policy_id.clone(),
            table,
            role.clone(),
            PolicyCommand::Select,
            true,
            true,
            digest_parts(&["rls-using-predicate", &policy_id, &role]),
            None,
            Some(tenant_id),
            policy_revision,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_id: impl Into<String>,
        table: TableScope,
        role: impl Into<String>,
        command: PolicyCommand,
        enabled: bool,
        permissive: bool,
        using_predicate_digest: impl Into<String>,
        check_predicate_digest: Option<String>,
        tenant_id: Option<String>,
        policy_revision: impl Into<String>,
    ) -> Result<Self, SupabaseIdentityError> {
        let policy = Self {
            policy_id: policy_id.into(),
            table,
            role: role.into(),
            command,
            enabled,
            permissive,
            using_predicate_digest: using_predicate_digest.into(),
            check_predicate_digest,
            tenant_id,
            policy_revision: policy_revision.into(),
        };
        policy.validate()
    }

    pub fn validate(&self) -> Result<Self, SupabaseIdentityError> {
        validate_identifier(&self.policy_id, "policy_id")?;
        self.table.validate()?;
        validate_identifier(&self.role, "policy role")?;
        validate_digest(&self.using_predicate_digest, "using_predicate_digest")?;
        if self.using_predicate_digest.len() > MAX_PREDICATE_DIGEST_BYTES {
            return Err(SupabaseIdentityError::InvalidModel(
                "using predicate digest is too large".into(),
            ));
        }
        if let Some(digest) = &self.check_predicate_digest {
            validate_digest(digest, "check_predicate_digest")?;
        }
        if let Some(tenant_id) = &self.tenant_id {
            validate_identifier(tenant_id, "policy tenant_id")?;
        }
        validate_identifier(&self.policy_revision, "policy_revision")?;
        Ok(self.clone())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagementMetadataObservation {
    pub scope_digest: String,
    pub project_ref: String,
    pub region: String,
    pub provider_revision: String,
    pub observed_at: DateTime<Utc>,
    pub response_bytes: usize,
    pub response_digest: String,
}

impl ManagementMetadataObservation {
    pub fn new(
        scope: &SupabaseScope,
        provider_revision: impl Into<String>,
        observed_at: DateTime<Utc>,
        response_bytes: usize,
    ) -> Result<Self, SupabaseIdentityError> {
        let mut observation = Self {
            scope_digest: scope.digest(),
            project_ref: scope.project_ref.clone(),
            region: scope.region.clone(),
            provider_revision: provider_revision.into(),
            observed_at,
            response_bytes,
            response_digest: String::new(),
        };
        observation.response_digest = observation.expected_response_digest()?;
        Ok(observation)
    }

    pub fn expected_response_digest(&self) -> Result<String, SupabaseIdentityError> {
        serialized_digest(&ManagementDigestMaterial {
            scope_digest: &self.scope_digest,
            project_ref: &self.project_ref,
            region: &self.region,
            provider_revision: &self.provider_revision,
            observed_at: self.observed_at,
            response_bytes: self.response_bytes,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), SupabaseIdentityError> {
        validate_digest(&self.response_digest, "management response_digest")?;
        if self.response_digest != self.expected_response_digest()? {
            return Err(SupabaseIdentityError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ManagementDigestMaterial<'a> {
    scope_digest: &'a str,
    project_ref: &'a str,
    region: &'a str,
    provider_revision: &'a str,
    observed_at: DateTime<Utc>,
    response_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthIdentityObservation {
    pub scope_digest: String,
    pub project_ref: String,
    pub region: String,
    pub tenant_id: String,
    pub identity: Option<SupabaseIdentityRecord>,
    pub jwt_claims: Option<JwtClaimsEvidence>,
    pub provider_revision: String,
    pub observed_at: DateTime<Utc>,
    pub response_bytes: usize,
    pub response_digest: String,
}

impl AuthIdentityObservation {
    pub fn new(
        scope: &SupabaseScope,
        identity: Option<SupabaseIdentityRecord>,
        jwt_claims: Option<JwtClaimsEvidence>,
        provider_revision: impl Into<String>,
        observed_at: DateTime<Utc>,
        response_bytes: usize,
    ) -> Result<Self, SupabaseIdentityError> {
        let mut observation = Self {
            scope_digest: scope.digest(),
            project_ref: scope.project_ref.clone(),
            region: scope.region.clone(),
            tenant_id: scope.tenant_id.clone(),
            identity,
            jwt_claims,
            provider_revision: provider_revision.into(),
            observed_at,
            response_bytes,
            response_digest: String::new(),
        };
        observation.response_digest = observation.expected_response_digest()?;
        Ok(observation)
    }

    pub fn expected_response_digest(&self) -> Result<String, SupabaseIdentityError> {
        serialized_digest(&AuthIdentityDigestMaterial {
            scope_digest: &self.scope_digest,
            project_ref: &self.project_ref,
            region: &self.region,
            tenant_id: &self.tenant_id,
            identity: self.identity.as_ref(),
            jwt_claims: self.jwt_claims.as_ref(),
            provider_revision: &self.provider_revision,
            observed_at: self.observed_at,
            response_bytes: self.response_bytes,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), SupabaseIdentityError> {
        validate_digest(&self.response_digest, "auth response_digest")?;
        if self.response_digest != self.expected_response_digest()? {
            return Err(SupabaseIdentityError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct AuthIdentityDigestMaterial<'a> {
    scope_digest: &'a str,
    project_ref: &'a str,
    region: &'a str,
    tenant_id: &'a str,
    identity: Option<&'a SupabaseIdentityRecord>,
    jwt_claims: Option<&'a JwtClaimsEvidence>,
    provider_revision: &'a str,
    observed_at: DateTime<Utc>,
    response_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostgrestMetadataObservation {
    pub scope_digest: String,
    pub project_ref: String,
    pub region: String,
    pub tenant_id: String,
    pub grants: Vec<DatabaseGrant>,
    pub policies: Vec<RlsPolicyEvidence>,
    pub grant_revision: String,
    pub policy_revision: String,
    pub provider_revision: String,
    pub observed_at: DateTime<Utc>,
    pub response_bytes: usize,
    pub response_digest: String,
}

impl PostgrestMetadataObservation {
    pub fn new(
        scope: &SupabaseScope,
        grants: Vec<DatabaseGrant>,
        policies: Vec<RlsPolicyEvidence>,
        provider_revision: impl Into<String>,
        observed_at: DateTime<Utc>,
        response_bytes: usize,
    ) -> Result<Self, SupabaseIdentityError> {
        let mut observation = Self {
            scope_digest: scope.digest(),
            project_ref: scope.project_ref.clone(),
            region: scope.region.clone(),
            tenant_id: scope.tenant_id.clone(),
            grants,
            policies,
            grant_revision: scope.grant_revision.clone(),
            policy_revision: scope.policy_revision.clone(),
            provider_revision: provider_revision.into(),
            observed_at,
            response_bytes,
            response_digest: String::new(),
        };
        observation.response_digest = observation.expected_response_digest()?;
        Ok(observation)
    }

    pub fn expected_response_digest(&self) -> Result<String, SupabaseIdentityError> {
        serialized_digest(&PostgrestDigestMaterial {
            scope_digest: &self.scope_digest,
            project_ref: &self.project_ref,
            region: &self.region,
            tenant_id: &self.tenant_id,
            grants: &self.grants,
            policies: &self.policies,
            grant_revision: &self.grant_revision,
            policy_revision: &self.policy_revision,
            provider_revision: &self.provider_revision,
            observed_at: self.observed_at,
            response_bytes: self.response_bytes,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), SupabaseIdentityError> {
        validate_digest(&self.response_digest, "PostgREST response_digest")?;
        if self.response_digest != self.expected_response_digest()? {
            return Err(SupabaseIdentityError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct PostgrestDigestMaterial<'a> {
    scope_digest: &'a str,
    project_ref: &'a str,
    region: &'a str,
    tenant_id: &'a str,
    grants: &'a [DatabaseGrant],
    policies: &'a [RlsPolicyEvidence],
    grant_revision: &'a str,
    policy_revision: &'a str,
    provider_revision: &'a str,
    observed_at: DateTime<Utc>,
    response_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupabaseIdentityEvidence {
    pub scope_digest: String,
    pub registration_digest: String,
    pub provider_digest: String,
    pub identity: SupabaseIdentityRecord,
    pub jwt_claims: JwtClaimsEvidence,
    pub provider_revision: String,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: String,
    pub provenance: EvidenceProvenance,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupabasePolicyEvidence {
    pub scope_digest: String,
    pub registration_digest: String,
    pub provider_digest: String,
    pub grants: Vec<DatabaseGrant>,
    pub policies: Vec<RlsPolicyEvidence>,
    pub grant_revision: String,
    pub policy_revision: String,
    pub provider_revision: String,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: String,
    pub provenance: EvidenceProvenance,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(
    clippy::large_enum_variant,
    reason = "Present carries the typed evidence; the other variants are explicit safe projections"
)]
pub enum IdentityProjection {
    Present(SupabaseIdentityEvidence),
    Absent {
        reason: ProjectionReason,
        scope_digest: String,
        observed_at: DateTime<Utc>,
    },
    Denied {
        reason: ProjectionReason,
        scope_digest: String,
        observed_at: DateTime<Utc>,
    },
    Expired {
        reason: ProjectionReason,
        scope_digest: String,
        observed_at: DateTime<Utc>,
    },
    ScopeMismatch {
        reason: ProjectionReason,
        scope_digest: String,
        observed_at: DateTime<Utc>,
    },
    ProviderUnknown {
        reason: ProjectionReason,
        scope_digest: String,
        observed_at: DateTime<Utc>,
    },
    Tampered {
        reason: ProjectionReason,
        scope_digest: String,
        observed_at: DateTime<Utc>,
    },
    Revoked {
        reason: ProjectionReason,
        scope_digest: String,
        observed_at: DateTime<Utc>,
    },
}

impl IdentityProjection {
    pub const fn status(&self) -> EvidenceStatus {
        match self {
            Self::Present(_) => EvidenceStatus::Present,
            Self::Absent { .. } => EvidenceStatus::Absent,
            Self::Denied { .. } => EvidenceStatus::Denied,
            Self::Expired { .. } => EvidenceStatus::Expired,
            Self::ScopeMismatch { .. } => EvidenceStatus::ScopeMismatch,
            Self::ProviderUnknown { .. } => EvidenceStatus::ProviderUnknown,
            Self::Tampered { .. } => EvidenceStatus::Tampered,
            Self::Revoked { .. } => EvidenceStatus::Revoked,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum PolicyProjection {
    Present(SupabasePolicyEvidence),
    Absent {
        reason: ProjectionReason,
        scope_digest: String,
        observed_at: DateTime<Utc>,
    },
    Denied {
        reason: ProjectionReason,
        scope_digest: String,
        observed_at: DateTime<Utc>,
    },
    Expired {
        reason: ProjectionReason,
        scope_digest: String,
        observed_at: DateTime<Utc>,
    },
    ScopeMismatch {
        reason: ProjectionReason,
        scope_digest: String,
        observed_at: DateTime<Utc>,
    },
    Mismatch {
        reason: ProjectionReason,
        evidence: Option<SupabasePolicyEvidence>,
        scope_digest: String,
        observed_at: DateTime<Utc>,
    },
    ProviderUnknown {
        reason: ProjectionReason,
        scope_digest: String,
        observed_at: DateTime<Utc>,
    },
    Tampered {
        reason: ProjectionReason,
        scope_digest: String,
        observed_at: DateTime<Utc>,
    },
    Revoked {
        reason: ProjectionReason,
        scope_digest: String,
        observed_at: DateTime<Utc>,
    },
}

impl PolicyProjection {
    pub const fn status(&self) -> EvidenceStatus {
        match self {
            Self::Present(_) => EvidenceStatus::Present,
            Self::Absent { .. } => EvidenceStatus::Absent,
            Self::Denied { .. } => EvidenceStatus::Denied,
            Self::Expired { .. } => EvidenceStatus::Expired,
            Self::ScopeMismatch { .. } | Self::Mismatch { .. } => EvidenceStatus::ScopeMismatch,
            Self::ProviderUnknown { .. } => EvidenceStatus::ProviderUnknown,
            Self::Tampered { .. } => EvidenceStatus::Tampered,
            Self::Revoked { .. } => EvidenceStatus::Revoked,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupabaseEvidencePack {
    pub identity: IdentityProjection,
    pub policy: PolicyProjection,
    pub scope_digest: String,
    pub registration_digest: String,
    pub provider_digest: String,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: String,
    pub provenance: EvidenceProvenance,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
}

impl SupabaseEvidencePack {
    pub fn new(
        identity: IdentityProjection,
        policy: PolicyProjection,
        scope_digest: impl Into<String>,
        registration_digest: impl Into<String>,
        provider_digest: impl Into<String>,
        observed_at: DateTime<Utc>,
        provenance: EvidenceProvenance,
    ) -> Result<Self, SupabaseIdentityError> {
        let mut pack = Self {
            identity,
            policy,
            scope_digest: scope_digest.into(),
            registration_digest: registration_digest.into(),
            provider_digest: provider_digest.into(),
            observed_at,
            evidence_digest: String::new(),
            provenance,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
        };
        pack.evidence_digest = pack.expected_digest()?;
        Ok(pack)
    }

    pub fn expected_digest(&self) -> Result<String, SupabaseIdentityError> {
        let mut copy = self.clone();
        copy.evidence_digest.clear();
        serialized_digest(&copy)
    }

    pub fn verify_integrity(&self) -> Result<(), SupabaseIdentityError> {
        validate_digest(&self.evidence_digest, "evidence_digest")?;
        if self.evidence_digest != self.expected_digest()? {
            return Err(SupabaseIdentityError::TamperedEvidence);
        }
        Ok(())
    }

    pub const fn is_positive(&self) -> bool {
        matches!(self.identity, IdentityProjection::Present(_))
            && matches!(self.policy, PolicyProjection::Present(_))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    AllowRead,
    DenyRead,
    ReviewRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "proposal flags make non-durable Layer-1 honesty machine-checkable"
)]
pub struct PolicyDecisionProposal {
    pub proposal_id: String,
    pub requested_decision: PolicyDecision,
    pub effective_decision: PolicyDecision,
    pub reason_code: String,
    pub table: TableScope,
    pub role: String,
    pub privilege: DatabasePrivilege,
    pub mission: MissionScope,
    pub scope_digest: String,
    pub registration_digest: String,
    pub provider_digest: String,
    pub permission_digest: String,
    pub evidence_digest: String,
    pub proposal_digest: String,
    pub provider_authority: String,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub durable_receipt: bool,
    pub adopted: bool,
}

impl PolicyDecisionProposal {
    pub fn expected_digest(&self) -> Result<String, SupabaseIdentityError> {
        let mut copy = self.clone();
        copy.proposal_digest.clear();
        serialized_digest(&copy)
    }

    pub fn verify_integrity(&self) -> Result<(), SupabaseIdentityError> {
        validate_digest(&self.proposal_digest, "proposal_digest")?;
        if self.proposal_digest != self.expected_digest()? {
            return Err(SupabaseIdentityError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionSupabaseIdentityResult {
    pub mission: MissionScope,
    pub evidence: SupabaseEvidencePack,
    pub proposal: Option<PolicyDecisionProposal>,
}

impl MissionSupabaseIdentityResult {
    pub fn digest(&self) -> Result<String, SupabaseIdentityError> {
        serialized_digest(self)
    }
}
