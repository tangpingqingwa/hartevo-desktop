use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::canonical::{digest_parts, valid_digest, valid_identifier, valid_text};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_CURSOR_BYTES: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 8;
pub const MAX_RECORDS: usize = 512;
pub const CURSOR_TTL_SECONDS: u64 = 300;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("invalid {field}: {reason}")]
    Invalid { field: String, reason: String },
    #[error("invalid digest")]
    InvalidDigest,
    #[error("the API-key SecretReference is opaque and cannot contain key material")]
    SecretMaterial,
    #[error("the membership filter must identify exactly one user or group")]
    InvalidMembershipFilter,
    #[error("the pagination cursor is not valid for this scope and operation")]
    InvalidCursor,
    #[error("the pagination cursor has expired")]
    CursorExpired,
}

fn invalid(field: &str, reason: impl Into<String>) -> ModelError {
    ModelError::Invalid {
        field: field.to_owned(),
        reason: reason.into(),
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hex_bytes(&hasher.finalize()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        digest_parts(domain, fields)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_digest(&value) {
            Ok(Self(value.to_ascii_lowercase()))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        valid_digest(&self.0)
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(invalid("revision", "must be positive"))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

impl From<Revision> for u64 {
    fn from(value: Revision) -> Self {
        value.0
    }
}

macro_rules! opaque_id {
    ($name:ident, $field:literal, $prefix:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if !valid_identifier(&value, MAX_IDENTIFIER_BYTES) || !value.starts_with($prefix) {
                    return Err(invalid(
                        $field,
                        concat!(
                            "must be a bounded opaque WorkOS identifier beginning with ",
                            $prefix
                        ),
                    ));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_fields(
                    concat!("workos-", $field, "/v1"),
                    std::slice::from_ref(&self.0),
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
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

opaque_id!(OrganizationId, "organization id", "org_");
opaque_id!(DirectoryId, "directory id", "directory_");
opaque_id!(DirectoryUserId, "directory user id", "directory_user_");
opaque_id!(DirectoryGroupId, "directory group id", "directory_group_");
opaque_id!(ConnectionId, "connection id", "conn_");

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Project {
    pub id: String,
    pub revision: Revision,
}

impl Project {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self, ModelError> {
        let id = id.into();
        validate_scope_id(&id, "project id")?;
        Ok(Self { id, revision })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "workos-project-scope/v1",
            &[self.id.clone(), self.revision.value().to_string()],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mission {
    pub id: String,
    pub revision: Revision,
}

impl Mission {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self, ModelError> {
        let id = id.into();
        validate_scope_id(&id, "mission id")?;
        Ok(Self { id, revision })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "workos-mission-scope/v1",
            &[self.id.clone(), self.revision.value().to_string()],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Consent {
    pub id: String,
    pub revision: Revision,
    pub read_only: bool,
}

impl Consent {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self, ModelError> {
        let id = id.into();
        validate_scope_id(&id, "consent id")?;
        Ok(Self {
            id,
            revision,
            read_only: true,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "workos-consent-scope/v1",
            &[
                self.id.clone(),
                self.revision.value().to_string(),
                self.read_only.to_string(),
            ],
        )
    }
}

fn validate_scope_id(value: &str, field: &str) -> Result<(), ModelError> {
    if valid_identifier(value, MAX_IDENTIFIER_BYTES) {
        Ok(())
    } else {
        Err(invalid(field, "must be a bounded opaque identifier"))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MembershipFilter {
    ByUser(DirectoryUserId),
    ByGroup(DirectoryGroupId),
}

impl MembershipFilter {
    pub const fn is_user_filter(&self) -> bool {
        matches!(self, Self::ByUser(_))
    }

    pub const fn is_group_filter(&self) -> bool {
        matches!(self, Self::ByGroup(_))
    }

    pub fn target_id_digest(&self) -> Digest {
        match self {
            Self::ByUser(id) => id.digest(),
            Self::ByGroup(id) => id.digest(),
        }
    }

    pub fn operation(&self) -> PageOperation {
        match self {
            Self::ByUser(id) => PageOperation::GroupsByUser(id.clone()),
            Self::ByGroup(id) => PageOperation::UsersByGroup(id.clone()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PageDirection {
    Before,
    After,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PageOperation {
    UsersByGroup(DirectoryGroupId),
    GroupsByUser(DirectoryUserId),
}

impl PageOperation {
    pub fn name(&self) -> &'static str {
        match self {
            Self::UsersByGroup(_) => "directory_users_by_group",
            Self::GroupsByUser(_) => "directory_groups_by_user",
        }
    }

    pub fn target_digest(&self) -> Digest {
        match self {
            Self::UsersByGroup(id) => id.digest(),
            Self::GroupsByUser(id) => id.digest(),
        }
    }
}

/// An opaque provider cursor. The raw value is deliberately private and is
/// never serialised or included in Debug output; only its binding digest is
/// exposed to evidence and receipts.
#[derive(Clone, Eq, PartialEq)]
pub struct PageCursor {
    direction: PageDirection,
    raw: String,
    digest: Digest,
    scope_digest: Digest,
    operation: PageOperation,
    issued_at: u64,
    expires_at: u64,
}

impl PageCursor {
    pub fn new(
        direction: PageDirection,
        raw: impl Into<String>,
        scope: &WorkOsDirectoryScope,
        operation: PageOperation,
        issued_at: u64,
        ttl_seconds: u64,
    ) -> Result<Self, ModelError> {
        let raw = raw.into();
        if !valid_text(&raw, MAX_CURSOR_BYTES, false) {
            return Err(invalid("cursor", "must be bounded and opaque"));
        }
        if ttl_seconds == 0 {
            return Err(invalid("cursor TTL", "must be positive"));
        }
        let expires_at = issued_at
            .checked_add(ttl_seconds)
            .ok_or_else(|| invalid("cursor TTL", "overflows the clock bound"))?;
        let scope_digest = scope.scope_digest().clone();
        let digest = Digest::from_fields(
            "workos-directory-cursor/v1",
            &[
                format!("{direction:?}"),
                raw.clone(),
                scope_digest.as_str().to_owned(),
                operation.name().to_owned(),
                operation.target_digest().as_str().to_owned(),
                issued_at.to_string(),
                expires_at.to_string(),
            ],
        );
        Ok(Self {
            direction,
            raw,
            digest,
            scope_digest,
            operation,
            issued_at,
            expires_at,
        })
    }

    pub fn after(
        raw: impl Into<String>,
        scope: &WorkOsDirectoryScope,
        operation: PageOperation,
        issued_at: u64,
        ttl_seconds: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            PageDirection::After,
            raw,
            scope,
            operation,
            issued_at,
            ttl_seconds,
        )
    }

    pub fn before(
        raw: impl Into<String>,
        scope: &WorkOsDirectoryScope,
        operation: PageOperation,
        issued_at: u64,
        ttl_seconds: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            PageDirection::Before,
            raw,
            scope,
            operation,
            issued_at,
            ttl_seconds,
        )
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub const fn direction(&self) -> &PageDirection {
        &self.direction
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn operation(&self) -> &PageOperation {
        &self.operation
    }

    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn validate_against(
        &self,
        scope: &WorkOsDirectoryScope,
        operation: &PageOperation,
        now_epoch_seconds: u64,
    ) -> Result<(), ModelError> {
        if self.scope_digest != *scope.scope_digest() || self.operation != *operation {
            return Err(ModelError::InvalidCursor);
        }
        if now_epoch_seconds > self.expires_at {
            return Err(ModelError::CursorExpired);
        }
        Ok(())
    }
}

impl fmt::Debug for PageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageCursor")
            .field("direction", &self.direction)
            .field("digest", &self.digest)
            .field("scope_digest", &self.scope_digest)
            .field("operation", &self.operation)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadBounds {
    pub limit: u16,
    pub max_pages: u16,
    pub max_records: usize,
    pub max_response_bytes: usize,
    pub cursor_ttl_seconds: u64,
    pub now_epoch_seconds: u64,
    pub initial_cursor: Option<PageCursor>,
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            limit: MAX_PAGE_SIZE,
            max_pages: MAX_PAGES,
            max_records: MAX_RECORDS,
            max_response_bytes: MAX_RESPONSE_BYTES,
            cursor_ttl_seconds: CURSOR_TTL_SECONDS,
            now_epoch_seconds: 1_735_689_600,
            initial_cursor: None,
        }
    }
}

impl ReadBounds {
    pub fn validate(&self) -> Result<(), ModelError> {
        if !(1..=MAX_PAGE_SIZE).contains(&self.limit)
            || !(1..=MAX_PAGES).contains(&self.max_pages)
            || !(1..=MAX_RECORDS).contains(&self.max_records)
            || !(1..=MAX_RESPONSE_BYTES).contains(&self.max_response_bytes)
            || self.cursor_ttl_seconds == 0
        {
            return Err(invalid("read bounds", "exceed the Layer-1 safety bounds"));
        }
        Ok(())
    }

    #[must_use]
    pub fn with_initial_cursor(mut self, cursor: PageCursor) -> Self {
        self.initial_cursor = Some(cursor);
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectoryState {
    Linked,
    Deleting,
    Deleted,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConnectionState {
    Active,
    Inactive,
    Deleting,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum UserState {
    Active,
    Inactive,
    Deactivated,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GroupState {
    Active,
    Inactive,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MembershipState {
    Active,
    Inactive,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProviderRevision(String);

impl ProviderRevision {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_identifier(&value, MAX_IDENTIFIER_BYTES) {
            Ok(Self(value))
        } else {
            Err(invalid(
                "provider revision",
                "must be a bounded opaque revision",
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields("workos-provider-revision/v1", std::slice::from_ref(&self.0))
    }
}

impl fmt::Display for ProviderRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryRecord {
    pub organization_id: OrganizationId,
    pub directory_id: DirectoryId,
    pub state: DirectoryState,
    pub provider_type_digest: Digest,
    pub external_key_digest: Option<Digest>,
    pub active_user_count: Option<u32>,
    pub inactive_user_count: Option<u32>,
    pub group_count: Option<u32>,
    pub provider_revision: ProviderRevision,
}

impl DirectoryRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: OrganizationId,
        directory_id: DirectoryId,
        state: DirectoryState,
        provider_type_digest: Digest,
        external_key_digest: Option<Digest>,
        active_user_count: Option<u32>,
        inactive_user_count: Option<u32>,
        group_count: Option<u32>,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        validate_digest_field(&provider_type_digest, "provider type digest")?;
        validate_optional_digest(external_key_digest.as_ref(), "external key digest")?;
        Ok(Self {
            organization_id,
            directory_id,
            state,
            provider_type_digest,
            external_key_digest,
            active_user_count,
            inactive_user_count,
            group_count,
            provider_revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionRecord {
    pub organization_id: OrganizationId,
    pub connection_id: ConnectionId,
    pub state: ConnectionState,
    pub connection_type_digest: Digest,
    pub name_digest: Option<Digest>,
    pub domains_digest: Option<Digest>,
    pub provider_revision: ProviderRevision,
}

impl ConnectionRecord {
    pub fn new(
        organization_id: OrganizationId,
        connection_id: ConnectionId,
        state: ConnectionState,
        connection_type_digest: Digest,
        name_digest: Option<Digest>,
        domains_digest: Option<Digest>,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        validate_digest_field(&connection_type_digest, "connection type digest")?;
        validate_optional_digest(name_digest.as_ref(), "connection name digest")?;
        validate_optional_digest(domains_digest.as_ref(), "connection domains digest")?;
        Ok(Self {
            organization_id,
            connection_id,
            state,
            connection_type_digest,
            name_digest,
            domains_digest,
            provider_revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryUserRecord {
    pub organization_id: OrganizationId,
    pub directory_id: DirectoryId,
    pub user_id: DirectoryUserId,
    pub state: UserState,
    pub idp_id_digest: Digest,
    pub email_digest: Option<Digest>,
    pub name_digest: Option<Digest>,
    pub custom_attributes_digest: Option<Digest>,
    pub provider_revision: ProviderRevision,
}

impl DirectoryUserRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: OrganizationId,
        directory_id: DirectoryId,
        user_id: DirectoryUserId,
        state: UserState,
        idp_id_digest: Digest,
        email_digest: Option<Digest>,
        name_digest: Option<Digest>,
        custom_attributes_digest: Option<Digest>,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        validate_digest_field(&idp_id_digest, "IdP identifier digest")?;
        validate_optional_digest(email_digest.as_ref(), "email digest")?;
        validate_optional_digest(name_digest.as_ref(), "name digest")?;
        validate_optional_digest(custom_attributes_digest.as_ref(), "custom attribute digest")?;
        Ok(Self {
            organization_id,
            directory_id,
            user_id,
            state,
            idp_id_digest,
            email_digest,
            name_digest,
            custom_attributes_digest,
            provider_revision,
        })
    }

    /// Hashes caller-owned provider fields immediately. The raw values are
    /// not part of this type, its Debug output, or its serialized evidence.
    pub fn from_provider_fields(
        organization_id: OrganizationId,
        directory_id: DirectoryId,
        user_id: DirectoryUserId,
        state: UserState,
        idp_id: &str,
        email: Option<&str>,
        name: Option<&str>,
        custom_attributes: Option<&str>,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        Self::new(
            organization_id,
            directory_id,
            user_id,
            state,
            Digest::from_text(idp_id),
            email.map(Digest::from_text),
            name.map(Digest::from_text),
            custom_attributes.map(Digest::from_text),
            provider_revision,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryGroupRecord {
    pub organization_id: OrganizationId,
    pub directory_id: DirectoryId,
    pub group_id: DirectoryGroupId,
    pub state: GroupState,
    pub idp_id_digest: Digest,
    pub name_digest: Option<Digest>,
    pub custom_attributes_digest: Option<Digest>,
    pub provider_revision: ProviderRevision,
}

impl DirectoryGroupRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: OrganizationId,
        directory_id: DirectoryId,
        group_id: DirectoryGroupId,
        state: GroupState,
        idp_id_digest: Digest,
        name_digest: Option<Digest>,
        custom_attributes_digest: Option<Digest>,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        validate_digest_field(&idp_id_digest, "IdP group identifier digest")?;
        validate_optional_digest(name_digest.as_ref(), "group name digest")?;
        validate_optional_digest(custom_attributes_digest.as_ref(), "group attribute digest")?;
        Ok(Self {
            organization_id,
            directory_id,
            group_id,
            state,
            idp_id_digest,
            name_digest,
            custom_attributes_digest,
            provider_revision,
        })
    }

    pub fn from_provider_fields(
        organization_id: OrganizationId,
        directory_id: DirectoryId,
        group_id: DirectoryGroupId,
        state: GroupState,
        idp_id: &str,
        name: Option<&str>,
        custom_attributes: Option<&str>,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        Self::new(
            organization_id,
            directory_id,
            group_id,
            state,
            Digest::from_text(idp_id),
            name.map(Digest::from_text),
            custom_attributes.map(Digest::from_text),
            provider_revision,
        )
    }
}

fn validate_digest_field(value: &Digest, field: &str) -> Result<(), ModelError> {
    if value.is_valid() {
        Ok(())
    } else {
        Err(invalid(field, "must be a SHA-256 digest"))
    }
}

fn validate_optional_digest(value: Option<&Digest>, field: &str) -> Result<(), ModelError> {
    value.map_or(Ok(()), |digest| validate_digest_field(digest, field))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryProjection {
    pub organization_id: OrganizationId,
    pub directory_id: DirectoryId,
    pub state: DirectoryState,
    pub provider_type_digest: Digest,
    pub external_key_digest: Option<Digest>,
    pub active_user_count: Option<u32>,
    pub inactive_user_count: Option<u32>,
    pub group_count: Option<u32>,
    pub provider_revision: ProviderRevision,
}

impl From<&DirectoryRecord> for DirectoryProjection {
    fn from(record: &DirectoryRecord) -> Self {
        Self {
            organization_id: record.organization_id.clone(),
            directory_id: record.directory_id.clone(),
            state: record.state.clone(),
            provider_type_digest: record.provider_type_digest.clone(),
            external_key_digest: record.external_key_digest.clone(),
            active_user_count: record.active_user_count,
            inactive_user_count: record.inactive_user_count,
            group_count: record.group_count,
            provider_revision: record.provider_revision.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionProjection {
    pub organization_id: OrganizationId,
    pub connection_id: ConnectionId,
    pub state: ConnectionState,
    pub connection_type_digest: Digest,
    pub name_digest: Option<Digest>,
    pub domains_digest: Option<Digest>,
    pub provider_revision: ProviderRevision,
}

impl From<&ConnectionRecord> for ConnectionProjection {
    fn from(record: &ConnectionRecord) -> Self {
        Self {
            organization_id: record.organization_id.clone(),
            connection_id: record.connection_id.clone(),
            state: record.state.clone(),
            connection_type_digest: record.connection_type_digest.clone(),
            name_digest: record.name_digest.clone(),
            domains_digest: record.domains_digest.clone(),
            provider_revision: record.provider_revision.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserProjection {
    pub organization_id: OrganizationId,
    pub directory_id: DirectoryId,
    pub user_id: DirectoryUserId,
    pub state: UserState,
    pub idp_id_digest: Digest,
    pub email_digest: Option<Digest>,
    pub name_digest: Option<Digest>,
    pub custom_attributes_digest: Option<Digest>,
    pub provider_revision: ProviderRevision,
}

impl From<&DirectoryUserRecord> for UserProjection {
    fn from(record: &DirectoryUserRecord) -> Self {
        Self {
            organization_id: record.organization_id.clone(),
            directory_id: record.directory_id.clone(),
            user_id: record.user_id.clone(),
            state: record.state.clone(),
            idp_id_digest: record.idp_id_digest.clone(),
            email_digest: record.email_digest.clone(),
            name_digest: record.name_digest.clone(),
            custom_attributes_digest: record.custom_attributes_digest.clone(),
            provider_revision: record.provider_revision.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupProjection {
    pub organization_id: OrganizationId,
    pub directory_id: DirectoryId,
    pub group_id: DirectoryGroupId,
    pub state: GroupState,
    pub idp_id_digest: Digest,
    pub name_digest: Option<Digest>,
    pub custom_attributes_digest: Option<Digest>,
    pub provider_revision: ProviderRevision,
}

impl From<&DirectoryGroupRecord> for GroupProjection {
    fn from(record: &DirectoryGroupRecord) -> Self {
        Self {
            organization_id: record.organization_id.clone(),
            directory_id: record.directory_id.clone(),
            group_id: record.group_id.clone(),
            state: record.state.clone(),
            idp_id_digest: record.idp_id_digest.clone(),
            name_digest: record.name_digest.clone(),
            custom_attributes_digest: record.custom_attributes_digest.clone(),
            provider_revision: record.provider_revision.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MembershipSource {
    UserFilter,
    GroupFilter,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MembershipProjection {
    pub organization_id: OrganizationId,
    pub directory_id: DirectoryId,
    pub user_id: DirectoryUserId,
    pub group_id: DirectoryGroupId,
    pub state: MembershipState,
    pub source: MembershipSource,
    pub provider_revision: ProviderRevision,
    pub membership_digest: Digest,
}

impl MembershipProjection {
    pub fn new(
        organization_id: OrganizationId,
        directory_id: DirectoryId,
        user_id: DirectoryUserId,
        group_id: DirectoryGroupId,
        state: MembershipState,
        source: MembershipSource,
        provider_revision: ProviderRevision,
    ) -> Self {
        let membership_digest = Digest::from_fields(
            "workos-directory-membership/v1",
            &[
                organization_id.as_str().to_owned(),
                directory_id.as_str().to_owned(),
                user_id.as_str().to_owned(),
                group_id.as_str().to_owned(),
                format!("{state:?}"),
                format!("{source:?}"),
                provider_revision.as_str().to_owned(),
            ],
        );
        Self {
            organization_id,
            directory_id,
            user_id,
            group_id,
            state,
            source,
            provider_revision,
            membership_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_test_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    DirectoryDeactivated,
    UserDeactivated,
    GroupDeactivated,
    Partial,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkOsDirectoryScope {
    pub organization_id: OrganizationId,
    pub directory_id: DirectoryId,
    pub connection_id: ConnectionId,
    pub user_id: Option<DirectoryUserId>,
    pub group_id: Option<DirectoryGroupId>,
    pub membership: MembershipFilter,
    pub project: Project,
    pub mission: Mission,
    pub consent: Consent,
    pub permission_digest: Digest,
    scope_digest: Digest,
}

impl WorkOsDirectoryScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: OrganizationId,
        directory_id: DirectoryId,
        connection_id: ConnectionId,
        membership: MembershipFilter,
        project: Project,
        mission: Mission,
        consent: Consent,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        if !permission_digest.is_valid() {
            return Err(ModelError::InvalidDigest);
        }
        let (user_id, group_id) = match &membership {
            MembershipFilter::ByUser(user_id) => (Some(user_id.clone()), None),
            MembershipFilter::ByGroup(group_id) => (None, Some(group_id.clone())),
        };
        let scope_digest = Digest::from_fields(
            "workos-directory-scope/v1",
            &[
                organization_id.as_str().to_owned(),
                directory_id.as_str().to_owned(),
                connection_id.as_str().to_owned(),
                user_id
                    .as_ref()
                    .map_or_else(String::new, |id| id.as_str().to_owned()),
                group_id
                    .as_ref()
                    .map_or_else(String::new, |id| id.as_str().to_owned()),
                project.digest().as_str().to_owned(),
                mission.digest().as_str().to_owned(),
                consent.digest().as_str().to_owned(),
                permission_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            organization_id,
            directory_id,
            connection_id,
            user_id,
            group_id,
            membership,
            project,
            mission,
            consent,
            permission_digest,
            scope_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.permission_digest.is_valid() || self.scope_digest != self.recompute_digest() {
            return Err(ModelError::InvalidDigest);
        }
        match (&self.membership, &self.user_id, &self.group_id) {
            (MembershipFilter::ByUser(filter), Some(user), None) if filter == user => Ok(()),
            (MembershipFilter::ByGroup(filter), None, Some(group)) if filter == group => Ok(()),
            _ => Err(ModelError::InvalidMembershipFilter),
        }
    }

    fn recompute_digest(&self) -> Digest {
        Digest::from_fields(
            "workos-directory-scope/v1",
            &[
                self.organization_id.as_str().to_owned(),
                self.directory_id.as_str().to_owned(),
                self.connection_id.as_str().to_owned(),
                self.user_id
                    .as_ref()
                    .map_or_else(String::new, |id| id.as_str().to_owned()),
                self.group_id
                    .as_ref()
                    .map_or_else(String::new, |id| id.as_str().to_owned()),
                self.project.digest().as_str().to_owned(),
                self.mission.digest().as_str().to_owned(),
                self.consent.digest().as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
            ],
        )
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn membership_operation(&self) -> PageOperation {
        self.membership.operation()
    }

    pub fn matches_mission_context(
        &self,
        project: &Project,
        mission: &Mission,
        consent: &Consent,
    ) -> bool {
        self.project == *project && self.mission == *mission && self.consent == *consent
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecretReferenceStatus {
    Active,
    Revoked,
}

/// Opaque handle for a host-owned WorkOS API key. No key bytes, token
/// material, resolver, or serialization implementation exists in Layer 1.
pub struct SecretReference {
    reference_id: String,
    revision: Revision,
    scope_digest: Digest,
    status: SecretReferenceStatus,
}

impl SecretReference {
    pub fn new_api_key(
        reference_id: impl Into<String>,
        revision: Revision,
        scope_digest: Digest,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id, MAX_IDENTIFIER_BYTES) {
            return Err(invalid(
                "secret reference id",
                "must be a bounded opaque reference identifier",
            ));
        }
        if !scope_digest.is_valid() {
            return Err(ModelError::SecretMaterial);
        }
        Ok(Self {
            reference_id,
            revision,
            scope_digest,
            status: SecretReferenceStatus::Active,
        })
    }

    pub fn new(
        reference_id: impl Into<String>,
        revision: Revision,
        scope_digest: Digest,
    ) -> Result<Self, ModelError> {
        Self::new_api_key(reference_id, revision, scope_digest)
    }

    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_fields(
            "workos-api-key-secret-reference/v1",
            &[
                self.reference_id.clone(),
                self.revision.value().to_string(),
                self.scope_digest.as_str().to_owned(),
            ],
        )
    }

    pub const fn is_revoked(&self) -> bool {
        matches!(self.status, SecretReferenceStatus::Revoked)
    }

    pub fn revoke(&mut self) {
        self.status = SecretReferenceStatus::Revoked;
    }
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_id: self.reference_id.clone(),
            revision: self.revision,
            scope_digest: self.scope_digest.clone(),
            status: self.status,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_id == other.reference_id
            && self.revision == other.revision
            && self.scope_digest == other.scope_digest
            && self.status == other.status
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_id", &self.reference_id)
            .field("revision", &self.revision)
            .field("scope_digest", &self.scope_digest)
            .field("status", &self.status)
            .finish()
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
