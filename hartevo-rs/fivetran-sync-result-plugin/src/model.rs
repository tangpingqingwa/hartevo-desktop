//! Versioned types and invariants for the Fivetran Layer-1 boundary.

use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    CONTRACT_VERSION, FIVETRAN_API_REVISION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, Result,
    contract_digest,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TIMESTAMP_BYTES: usize = 64;
pub const MAX_TEXT_BYTES: usize = 1_024;

/// Semantic version carried by the plugin registration and proposal fences.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

impl Version {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn patch(self) -> u16 {
        self.patch
    }
}

/// Lowercase SHA-256 used for identity, scope, revision, evidence, and
/// registration fences. Raw provider payloads never enter this type.
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

    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded Fivetran values serialize");
        Self::from_bytes(&bytes)
    }

    pub fn pending() -> Self {
        Self::from_text("pending-fivetran-sync-result-digest")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    pub fn validate(&self) -> Result<()> {
        if self.is_valid() {
            Ok(())
        } else {
            Err(FivetranError::InvalidDigest)
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

impl FromStr for Digest {
    type Err = FivetranError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let digest = Self(value.to_ascii_lowercase());
        digest.validate()?;
        Ok(digest)
    }
}

fn validate_identifier(value: &str, kind: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
        || value
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'%'))
    {
        Err(FivetranError::InvalidIdentifier { kind })
    } else {
        Ok(())
    }
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(FivetranError::InvalidInput {
            field,
            reason: "must be bounded, non-empty, and free of control characters",
        })
    } else {
        Ok(())
    }
}

macro_rules! identifier_type {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_identifier(&value, $kind)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<()> {
                validate_identifier(&self.0, $kind)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = FivetranError;

            fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier_type!(FivetranAccountId, "Fivetran account id");
identifier_type!(FivetranGroupId, "Fivetran group id");
identifier_type!(FivetranDestinationId, "Fivetran destination id");
identifier_type!(FivetranConnectionId, "Fivetran connection id");
identifier_type!(FivetranSyncId, "Fivetran sync id");
identifier_type!(FivetranSchemaName, "Fivetran schema name");
identifier_type!(FivetranTableName, "Fivetran table name");
identifier_type!(ProjectId, "Hartevo Project id");
identifier_type!(MissionId, "Hartevo Mission id");
identifier_type!(WorkProductId, "Hartevo Work Product id");

pub type AccountId = FivetranAccountId;
pub type GroupId = FivetranGroupId;
pub type DestinationId = FivetranDestinationId;
pub type ConnectionId = FivetranConnectionId;
pub type SyncId = FivetranSyncId;
pub type SchemaName = FivetranSchemaName;
pub type TableName = FivetranTableName;

/// Bounded ISO-8601-like timestamp. The provider never interprets it as a
/// clock authority; it is retained only as provider-reported metadata.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MetadataTimestamp(String);

impl MetadataTimestamp {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "timestamp", MAX_TIMESTAMP_BYTES)?;
        if !value.contains('T') || !(value.ends_with('Z') || value.contains('+')) {
            return Err(FivetranError::InvalidTimestamp);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MetadataTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Exact Mission scope carried by every read and proposal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranScope {
    pub account_id: FivetranAccountId,
    pub group_id: FivetranGroupId,
    pub destination_id: FivetranDestinationId,
    pub connection_id: FivetranConnectionId,
    pub sync_id: FivetranSyncId,
    pub schema_name: FivetranSchemaName,
    pub table_name: FivetranTableName,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub account_revision: u64,
    pub destination_revision: u64,
    pub connection_revision: u64,
    pub schema_revision: u64,
    pub sync_revision: u64,
    pub mission_revision: u64,
}

impl FivetranScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: FivetranAccountId,
        group_id: FivetranGroupId,
        destination_id: FivetranDestinationId,
        connection_id: FivetranConnectionId,
        sync_id: FivetranSyncId,
        schema_name: FivetranSchemaName,
        table_name: FivetranTableName,
        project_id: ProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        account_revision: u64,
        destination_revision: u64,
        connection_revision: u64,
        schema_revision: u64,
        sync_revision: u64,
        mission_revision: u64,
    ) -> Result<Self> {
        let scope = Self {
            account_id,
            group_id,
            destination_id,
            connection_id,
            sync_id,
            schema_name,
            table_name,
            project_id,
            mission_id,
            work_product_id,
            account_revision,
            destination_revision,
            connection_revision,
            schema_revision,
            sync_revision,
            mission_revision,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        self.group_id.validate()?;
        self.destination_id.validate()?;
        self.connection_id.validate()?;
        self.sync_id.validate()?;
        self.schema_name.validate()?;
        self.table_name.validate()?;
        self.project_id.validate()?;
        self.mission_id.validate()?;
        self.work_product_id.validate()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn revision_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.account_revision,
            self.destination_revision,
            self.connection_revision,
            self.schema_revision,
            self.sync_revision,
            self.mission_revision,
        ))
    }
}

/// Permissions are explicit and read-only. No write permission is representable.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FivetranPermission {
    #[serde(rename = "account:read")]
    AccountRead,
    #[serde(rename = "group:read")]
    GroupRead,
    #[serde(rename = "destination:read")]
    DestinationRead,
    #[serde(rename = "connection:read")]
    ConnectionRead,
    #[serde(rename = "connection-state:read")]
    ConnectionStateRead,
    #[serde(rename = "connection-schema:read")]
    ConnectionSchemaRead,
}

impl FivetranPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountRead => "account:read",
            Self::GroupRead => "group:read",
            Self::DestinationRead => "destination:read",
            Self::ConnectionRead => "connection:read",
            Self::ConnectionStateRead => "connection-state:read",
            Self::ConnectionSchemaRead => "connection-schema:read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranPermissionSnapshot {
    pub api_revision: String,
    pub permissions: BTreeSet<FivetranPermission>,
    pub revision: u64,
}

impl FivetranPermissionSnapshot {
    pub fn read_only_default(revision: impl Into<String>) -> Result<Self> {
        let snapshot = Self {
            api_revision: revision.into(),
            permissions: [
                FivetranPermission::AccountRead,
                FivetranPermission::GroupRead,
                FivetranPermission::DestinationRead,
                FivetranPermission::ConnectionRead,
                FivetranPermission::ConnectionStateRead,
                FivetranPermission::ConnectionSchemaRead,
            ]
            .into_iter()
            .collect(),
            revision: 1,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<()> {
        validate_identifier(&self.api_revision, "API revision")?;
        if self.api_revision != FIVETRAN_API_REVISION || self.permissions.len() != 6 {
            return Err(FivetranError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ScopedApiKey,
}

/// The external API-key reference is intentionally opaque and not
/// serializable. Only its digest and scope binding are observable.
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    permission_digest: Digest,
    credential_revision: u64,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
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
            .field("permission_digest", &self.permission_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.permission_digest == other.permission_digest
            && self.credential_revision == other.credential_revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_label: impl AsRef<str>,
        scope: &FivetranScope,
        credential_revision: u64,
    ) -> Result<Self> {
        let permissions = FivetranPermissionSnapshot::read_only_default(FIVETRAN_API_REVISION)?;
        Self::scoped_api_key(reference_label, scope, &permissions, credential_revision)
    }

    pub fn scoped_api_key(
        reference_label: impl AsRef<str>,
        scope: &FivetranScope,
        permissions: &FivetranPermissionSnapshot,
        credential_revision: u64,
    ) -> Result<Self> {
        scope.validate()?;
        permissions.validate()?;
        let label = reference_label.as_ref();
        validate_text(label, "API-key reference label", MAX_TEXT_BYTES)?;
        if label.chars().any(char::is_whitespace) {
            return Err(FivetranError::InvalidInput {
                field: "API-key reference label",
                reason: "must not contain whitespace",
            });
        }
        Ok(Self {
            kind: SecretKind::ScopedApiKey,
            reference_digest: Digest::from_text(label),
            scope_digest: scope.digest(),
            permission_digest: permissions.digest(),
            credential_revision,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn validate_for(
        &self,
        scope: &FivetranScope,
        permissions: &FivetranPermissionSnapshot,
    ) -> Result<()> {
        if self.revoked {
            return Err(FivetranError::RegistrationRevoked);
        }
        if self.scope_digest != scope.digest() {
            return Err(FivetranError::ScopeDrift {
                field: "secret reference scope",
            });
        }
        if self.permission_digest != permissions.digest() {
            return Err(FivetranError::ScopeDrift {
                field: "secret reference permissions",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Unmounted,
    Revoked,
    Reversed,
}

impl RegistrationStatus {
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranRegistration {
    pub status: RegistrationStatus,
    pub scope: FivetranScope,
    pub permissions: FivetranPermissionSnapshot,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub credential_digest: Digest,
    pub registration_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
    #[serde(skip)]
    pub(crate) secret_reference: SecretReference,
}

impl FivetranRegistration {
    pub fn new(
        scope: FivetranScope,
        secret_reference: SecretReference,
        provider_revision: u64,
    ) -> Result<Self> {
        let permissions = FivetranPermissionSnapshot::read_only_default(FIVETRAN_API_REVISION)?;
        Self::new_with_permissions(scope, secret_reference, permissions, provider_revision)
    }

    pub fn new_with_permissions(
        scope: FivetranScope,
        secret_reference: SecretReference,
        permissions: FivetranPermissionSnapshot,
        provider_revision: u64,
    ) -> Result<Self> {
        scope.validate()?;
        permissions.validate()?;
        secret_reference.validate_for(&scope, &permissions)?;
        let mut registration = Self {
            status: RegistrationStatus::Active,
            version_digest: Digest::from_serializable(&PLUGIN_VERSION),
            contract_digest: contract_digest(),
            provider_digest: Digest::from_text(PROVIDER_ID),
            api_digest: Digest::from_text(FIVETRAN_API_REVISION),
            permission_digest: permissions.digest(),
            scope_digest: scope.digest(),
            revision_digest: Digest::from_serializable(&(
                scope.revision_digest(),
                provider_revision,
            )),
            credential_digest: secret_reference.reference_digest().clone(),
            registration_digest: Digest::pending(),
            reversible: true,
            revocable: true,
            scope,
            permissions,
            secret_reference,
        };
        registration.refresh_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.permissions.validate()?;
        self.secret_reference
            .validate_for(&self.scope, &self.permissions)
            .or_else(|error| {
                if matches!(
                    self.status,
                    RegistrationStatus::Revoked | RegistrationStatus::Reversed
                ) && self.secret_reference.is_revoked()
                {
                    Ok(())
                } else {
                    Err(error)
                }
            })?;
        for digest in [
            &self.version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.revision_digest,
            &self.credential_digest,
            &self.registration_digest,
        ] {
            digest.validate()?;
        }
        if self.contract_digest != contract_digest()
            || self.provider_digest != Digest::from_text(PROVIDER_ID)
            || self.api_digest != Digest::from_text(FIVETRAN_API_REVISION)
            || self.permission_digest != self.permissions.digest()
            || self.scope_digest != self.scope.digest()
            || self.credential_digest != *self.secret_reference.reference_digest()
            || !self.reversible
            || !self.revocable
        {
            return Err(FivetranError::TamperDetected {
                subject: "registration metadata",
            });
        }
        if self.registration_digest != self.compute_registration_digest() {
            return Err(FivetranError::TamperDetected {
                subject: "registration digest",
            });
        }
        Ok(())
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransition> {
        self.transition(RegistrationStatus::Unmounted, "unmount")
    }

    pub fn remount(&mut self) -> Result<RegistrationTransition> {
        self.transition(RegistrationStatus::Active, "remount")
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition> {
        if !matches!(
            self.status,
            RegistrationStatus::Active | RegistrationStatus::Unmounted
        ) {
            return Err(FivetranError::InvalidRegistrationTransition {
                from: self.status,
                to: RegistrationStatus::Revoked,
            });
        }
        let from = self.status;
        self.secret_reference.revoke();
        self.status = RegistrationStatus::Revoked;
        self.refresh_digest();
        Ok(RegistrationTransition::new(
            from,
            self.status,
            "revoke",
            &self.registration_digest,
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransition> {
        self.transition(RegistrationStatus::Reversed, "reverse")
    }

    fn transition(
        &mut self,
        to: RegistrationStatus,
        operation: &'static str,
    ) -> Result<RegistrationTransition> {
        let allowed = matches!(
            (self.status, to),
            (RegistrationStatus::Active, RegistrationStatus::Unmounted)
                | (RegistrationStatus::Unmounted, RegistrationStatus::Active)
                | (RegistrationStatus::Revoked, RegistrationStatus::Reversed)
        );
        if !allowed {
            return Err(FivetranError::InvalidRegistrationTransition {
                from: self.status,
                to,
            });
        }
        let from = self.status;
        self.status = to;
        self.refresh_digest();
        Ok(RegistrationTransition::new(
            from,
            to,
            operation,
            &self.registration_digest,
        ))
    }

    fn refresh_digest(&mut self) {
        self.registration_digest = self.compute_registration_digest();
    }

    fn compute_registration_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.status,
            &self.version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.revision_digest,
            &self.credential_digest,
            self.reversible,
            self.revocable,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransition {
    pub from: RegistrationStatus,
    pub to: RegistrationStatus,
    pub operation: String,
    pub registration_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

impl RegistrationTransition {
    fn new(
        from: RegistrationStatus,
        to: RegistrationStatus,
        operation: &str,
        registration_digest: &Digest,
    ) -> Self {
        Self {
            from,
            to,
            operation: operation.to_owned(),
            registration_digest: registration_digest.clone(),
            reversible: true,
            revocable: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupState {
    Connected,
    Broken,
    Incomplete,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    Scheduled,
    Syncing,
    Paused,
    Rescheduled,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    OnSchedule,
    Delayed,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SyncMode {
    SoftDelete,
    History,
    Live,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SchemaChangeHandling {
    AllowAll,
    AllowColumns,
    BlockAll,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaStatus {
    Ready,
    Incomplete,
    Broken,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FivetranStatusPayload {
    #[serde(alias = "setup_state")]
    pub setup_state: SetupState,
    #[serde(alias = "sync_state")]
    pub sync_state: SyncState,
    #[serde(alias = "update_state")]
    pub update_state: UpdateState,
    #[serde(default)]
    pub schema_status: Option<SchemaStatus>,
    #[serde(default)]
    #[serde(alias = "rescheduled_for")]
    pub rescheduled_for: Option<MetadataTimestamp>,
    #[serde(default)]
    #[serde(alias = "state_revision")]
    pub state_revision: u64,
}

impl FivetranStatusPayload {
    pub fn new(
        setup_state: SetupState,
        sync_state: SyncState,
        update_state: UpdateState,
        state_revision: u64,
    ) -> Self {
        Self {
            setup_state,
            sync_state,
            update_state,
            schema_status: None,
            rescheduled_for: None,
            state_revision,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FivetranConnectionPayload {
    #[serde(default)]
    #[serde(alias = "account_id")]
    pub account_id: Option<FivetranAccountId>,
    pub id: FivetranConnectionId,
    pub service: String,
    #[serde(alias = "schema", alias = "schema_name")]
    pub schema_name: FivetranSchemaName,
    #[serde(alias = "group_id")]
    pub group_id: FivetranGroupId,
    #[serde(default)]
    #[serde(alias = "destination_id")]
    pub destination_id: Option<FivetranDestinationId>,
    #[serde(default)]
    #[serde(alias = "destination_group_id")]
    pub destination_group_id: Option<FivetranDestinationId>,
    #[serde(default)]
    #[serde(alias = "destination_type")]
    pub destination_type: Option<String>,
    pub status: FivetranStatusPayload,
    #[serde(default)]
    #[serde(alias = "succeeded_at")]
    pub succeeded_at: Option<MetadataTimestamp>,
    #[serde(default)]
    #[serde(alias = "failed_at")]
    pub failed_at: Option<MetadataTimestamp>,
    #[serde(default)]
    #[serde(alias = "created_at")]
    pub created_at: Option<MetadataTimestamp>,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub partial: bool,
}

impl FivetranConnectionPayload {
    pub fn validate(&self) -> Result<()> {
        self.id.validate()?;
        validate_text(&self.service, "connector service", MAX_IDENTIFIER_BYTES)?;
        self.schema_name.validate()?;
        self.group_id.validate()?;
        if let Some(destination_id) = &self.destination_id {
            destination_id.validate()?;
        }
        if let Some(destination_group_id) = &self.destination_group_id {
            destination_group_id.validate()?;
        }
        if let Some(destination_type) = &self.destination_type {
            validate_text(destination_type, "destination type", MAX_IDENTIFIER_BYTES)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FivetranConnectionStatePayload {
    #[serde(default)]
    pub id: Option<FivetranConnectionId>,
    #[serde(alias = "group_id")]
    #[serde(default)]
    pub group_id: Option<FivetranGroupId>,
    #[serde(default)]
    #[serde(alias = "destination_id")]
    pub destination_id: Option<FivetranDestinationId>,
    #[serde(default)]
    pub status: Option<FivetranStatusPayload>,
    #[serde(default)]
    #[serde(alias = "succeeded_at")]
    pub succeeded_at: Option<MetadataTimestamp>,
    #[serde(default)]
    #[serde(alias = "failed_at")]
    pub failed_at: Option<MetadataTimestamp>,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub partial: bool,
    #[serde(default = "Digest::pending")]
    pub state_digest: Digest,
    #[serde(default)]
    pub state_field_count: usize,
}

impl FivetranConnectionStatePayload {
    pub fn opaque_state(state_digest: Digest, state_field_count: usize) -> Self {
        Self {
            id: None,
            group_id: None,
            destination_id: None,
            status: None,
            succeeded_at: None,
            failed_at: None,
            revision: 0,
            partial: false,
            state_digest,
            state_field_count,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FivetranConnectionSummary {
    pub id: FivetranConnectionId,
    pub service: String,
    #[serde(alias = "schema", alias = "schema_name")]
    pub schema_name: FivetranSchemaName,
    #[serde(alias = "group_id")]
    pub group_id: FivetranGroupId,
    #[serde(default)]
    #[serde(alias = "destination_id")]
    pub destination_id: Option<FivetranDestinationId>,
    pub status: FivetranStatusPayload,
    #[serde(default)]
    #[serde(alias = "succeeded_at")]
    pub succeeded_at: Option<MetadataTimestamp>,
    #[serde(default)]
    #[serde(alias = "failed_at")]
    pub failed_at: Option<MetadataTimestamp>,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub partial: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranConnectionListPayload {
    pub items: Vec<FivetranConnectionSummary>,
    #[serde(default)]
    #[serde(alias = "next_cursor")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub partial: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranColumnMetadata {
    pub name: FivetranTableName,
    #[serde(default)]
    pub name_in_destination: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub hashed: Option<bool>,
    #[serde(default)]
    pub is_primary_key: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranTableMetadata {
    pub name: FivetranTableName,
    #[serde(default)]
    pub name_in_destination: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub sync_mode: Option<SyncMode>,
    #[serde(default)]
    pub columns: Vec<FivetranColumnMetadata>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranSchemaMetadata {
    pub name: FivetranSchemaName,
    #[serde(default)]
    pub name_in_destination: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub tables: Vec<FivetranTableMetadata>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranSchemasPayload {
    #[serde(default)]
    pub schema_change_handling: Option<SchemaChangeHandling>,
    pub schemas: Vec<FivetranSchemaMetadata>,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub partial: bool,
}

impl FivetranSchemasPayload {
    pub fn validate_bounds(&self) -> Result<()> {
        if self.schemas.len() > crate::MAX_SCHEMAS {
            return Err(FivetranError::BoundExceeded {
                field: "schemas",
                limit: crate::MAX_SCHEMAS,
            });
        }
        let mut tables = 0_usize;
        let mut columns = 0_usize;
        for schema in &self.schemas {
            schema.name.validate()?;
            if let Some(name) = &schema.name_in_destination {
                validate_text(name, "destination schema name", MAX_IDENTIFIER_BYTES)?;
            }
            if schema.tables.len() > crate::MAX_TABLES {
                return Err(FivetranError::BoundExceeded {
                    field: "tables",
                    limit: crate::MAX_TABLES,
                });
            }
            tables = tables.saturating_add(schema.tables.len());
            for table in &schema.tables {
                table.name.validate()?;
                if let Some(name) = &table.name_in_destination {
                    validate_text(name, "destination table name", MAX_IDENTIFIER_BYTES)?;
                }
                columns = columns.saturating_add(table.columns.len());
                for column in &table.columns {
                    column.name.validate()?;
                    if let Some(name) = &column.name_in_destination {
                        validate_text(name, "destination column name", MAX_IDENTIFIER_BYTES)?;
                    }
                }
            }
        }
        if tables > crate::MAX_TABLES {
            return Err(FivetranError::BoundExceeded {
                field: "tables",
                limit: crate::MAX_TABLES,
            });
        }
        if columns > crate::MAX_COLUMNS {
            return Err(FivetranError::BoundExceeded {
                field: "columns",
                limit: crate::MAX_COLUMNS,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DestinationIdentityProjection {
    pub destination_id: FivetranDestinationId,
    pub group_id: FivetranGroupId,
    pub destination_type_digest: Option<Digest>,
    pub identity_digest: Digest,
    pub provider_reported: bool,
    pub credentials_redacted: bool,
}

impl DestinationIdentityProjection {
    pub fn new(
        destination_id: FivetranDestinationId,
        group_id: FivetranGroupId,
        destination_type: Option<&str>,
        provider_reported: bool,
    ) -> Result<Self> {
        destination_id.validate()?;
        group_id.validate()?;
        let destination_type_digest = destination_type.map(Digest::from_text);
        let identity_digest = Digest::from_serializable(&(
            &destination_id,
            &group_id,
            &destination_type_digest,
            provider_reported,
        ));
        Ok(Self {
            destination_id,
            group_id,
            destination_type_digest,
            identity_digest,
            provider_reported,
            credentials_redacted: true,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.destination_id.validate()?;
        self.group_id.validate()?;
        if let Some(digest) = &self.destination_type_digest {
            digest.validate()?;
        }
        self.identity_digest.validate()?;
        let expected = Digest::from_serializable(&(
            &self.destination_id,
            &self.group_id,
            &self.destination_type_digest,
            self.provider_reported,
        ));
        if self.identity_digest != expected || !self.credentials_redacted {
            return Err(FivetranError::TamperDetected {
                subject: "destination identity",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportMode {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionEvidence {
    pub credentials_redacted: bool,
    pub authorization_headers_redacted: bool,
    pub connector_config_redacted: bool,
    pub raw_response_body_redacted: bool,
    pub row_payloads_redacted: bool,
    pub source_records_redacted: bool,
    pub webhook_payloads_redacted: bool,
}

impl RedactionEvidence {
    pub const fn layer1() -> Self {
        Self {
            credentials_redacted: true,
            authorization_headers_redacted: true,
            connector_config_redacted: true,
            raw_response_body_redacted: true,
            row_payloads_redacted: true,
            source_records_redacted: true,
            webhook_payloads_redacted: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.credentials_redacted
            && self.authorization_headers_redacted
            && self.connector_config_redacted
            && self.raw_response_body_redacted
            && self.row_payloads_redacted
            && self.source_records_redacted
            && self.webhook_payloads_redacted
        {
            Ok(())
        } else {
            Err(FivetranError::RedactionViolation)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranProvenance {
    pub mode: TransportMode,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub recording_only: bool,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub redaction: RedactionEvidence,
}

impl FivetranProvenance {
    pub fn for_mode(mode: TransportMode, request_digest: Digest, response_digest: Digest) -> Self {
        Self {
            mode,
            connected: false,
            native: false,
            first_party: false,
            recording_only: true,
            request_digest,
            response_digest,
            redaction: RedactionEvidence::layer1(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || !self.recording_only
            || self.mode.connected()
            || self.mode.native()
            || self.mode.first_party()
        {
            return Err(FivetranError::NonNativeClaim);
        }
        self.request_digest.validate()?;
        self.response_digest.validate()?;
        self.redaction.validate()
    }

    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    pub const fn is_native(&self) -> bool {
        self.native
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranConnectionProjection {
    pub scope_digest: Digest,
    pub account_id: FivetranAccountId,
    pub group_id: FivetranGroupId,
    pub destination: DestinationIdentityProjection,
    pub connection_id: FivetranConnectionId,
    pub service: String,
    pub schema_name: FivetranSchemaName,
    pub setup_state: SetupState,
    pub sync_state: SyncState,
    pub update_state: UpdateState,
    pub latest_success_at: Option<MetadataTimestamp>,
    pub latest_failure_at: Option<MetadataTimestamp>,
    pub rescheduled_for: Option<MetadataTimestamp>,
    pub connection_revision: u64,
    pub sync_state_revision: u64,
    pub partial: bool,
    pub provenance: FivetranProvenance,
    pub projection_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranConnectionStateProjection {
    pub scope_digest: Digest,
    pub connection_id: FivetranConnectionId,
    pub group_id: FivetranGroupId,
    pub destination: DestinationIdentityProjection,
    pub setup_state: Option<SetupState>,
    pub sync_state: Option<SyncState>,
    pub update_state: Option<UpdateState>,
    pub latest_success_at: Option<MetadataTimestamp>,
    pub latest_failure_at: Option<MetadataTimestamp>,
    pub sync_state_revision: u64,
    pub state_digest: Digest,
    pub state_field_count: usize,
    pub partial: bool,
    pub provenance: FivetranProvenance,
    pub projection_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionListRequest {
    pub group_id: FivetranGroupId,
    pub schema_name: FivetranSchemaName,
    pub cursor: Option<String>,
    pub limit: usize,
    pub max_pages: usize,
}

impl ConnectionListRequest {
    pub fn for_scope(scope: &FivetranScope) -> Self {
        Self {
            group_id: scope.group_id.clone(),
            schema_name: scope.schema_name.clone(),
            cursor: None,
            limit: crate::MAX_PAGE_ITEMS,
            max_pages: crate::MAX_PAGES,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.group_id.validate()?;
        self.schema_name.validate()?;
        if self.limit == 0 || self.limit > crate::MAX_PAGE_ITEMS {
            return Err(FivetranError::InvalidPagination { field: "limit" });
        }
        if self.max_pages == 0 || self.max_pages > crate::MAX_PAGES {
            return Err(FivetranError::InvalidPagination { field: "max_pages" });
        }
        if let Some(cursor) = &self.cursor {
            validate_text(cursor, "cursor", crate::MAX_CURSOR_BYTES)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionListItemProjection {
    pub scope_digest: Digest,
    pub id: FivetranConnectionId,
    pub service: String,
    pub schema_name: FivetranSchemaName,
    pub group_id: FivetranGroupId,
    pub destination: DestinationIdentityProjection,
    pub setup_state: SetupState,
    pub sync_state: SyncState,
    pub update_state: UpdateState,
    pub latest_success_at: Option<MetadataTimestamp>,
    pub latest_failure_at: Option<MetadataTimestamp>,
    pub revision: u64,
    pub partial: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionListProjection {
    pub scope_digest: Digest,
    pub items: Vec<ConnectionListItemProjection>,
    pub pages_read: usize,
    pub next_cursor: Option<String>,
    pub partial: bool,
    pub provenance: FivetranProvenance,
    pub projection_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranSchemaTableProjection {
    pub scope_digest: Digest,
    pub connection_id: FivetranConnectionId,
    pub schema_name: FivetranSchemaName,
    pub table_name: FivetranTableName,
    pub schema_fingerprint: Digest,
    pub table_fingerprint: Digest,
    pub schema_status: Option<SchemaStatus>,
    pub schema_count: usize,
    pub table_count: usize,
    pub column_count: usize,
    pub partial: bool,
    pub provenance: FivetranProvenance,
    pub projection_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FivetranResultState {
    Scheduled,
    Syncing,
    Paused,
    Rescheduled,
    Delayed,
    Broken,
    Incomplete,
    Partial,
    AccessLoss,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranSyncEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub registration_digest: Digest,
    pub scope: FivetranScope,
    pub scope_digest: Digest,
    pub account_id: FivetranAccountId,
    pub group_id: FivetranGroupId,
    pub destination: DestinationIdentityProjection,
    pub connection_id: FivetranConnectionId,
    pub sync_id: FivetranSyncId,
    pub schema_name: FivetranSchemaName,
    pub table_name: FivetranTableName,
    pub setup_state: SetupState,
    pub sync_state: SyncState,
    pub update_state: UpdateState,
    pub result_state: FivetranResultState,
    pub latest_success_at: Option<MetadataTimestamp>,
    pub latest_failure_at: Option<MetadataTimestamp>,
    pub schema_fingerprint: Digest,
    pub table_fingerprint: Digest,
    pub connection_revision: u64,
    pub schema_revision: u64,
    pub sync_state_revision: u64,
    pub mission_revision: u64,
    pub partial: bool,
    pub provenance: FivetranProvenance,
    pub evidence_digest: Digest,
}

impl FivetranSyncEvidence {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.destination.validate()?;
        self.provenance.validate()?;
        for digest in [
            &self.contract_digest,
            &self.registration_digest,
            &self.scope_digest,
            &self.schema_fingerprint,
            &self.table_fingerprint,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        if self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.scope_digest != self.scope.digest()
            || self.account_id != self.scope.account_id
            || self.group_id != self.scope.group_id
            || self.destination.destination_id != self.scope.destination_id
            || self.destination.group_id != self.scope.group_id
            || self.connection_id != self.scope.connection_id
            || self.sync_id != self.scope.sync_id
            || self.schema_name != self.scope.schema_name
            || self.table_name != self.scope.table_name
            || self.mission_revision != self.scope.mission_revision
            || self.evidence_digest != self.compute_digest()
        {
            return Err(FivetranError::TamperDetected {
                subject: "sync evidence",
            });
        }
        Ok(())
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&serde_json::json!([
            &self.contract_version,
            &self.contract_digest,
            &self.registration_digest,
            &self.scope_digest,
            &self.account_id,
            &self.group_id,
            &self.destination,
            &self.connection_id,
            &self.sync_id,
            &self.schema_name,
            &self.table_name,
            self.setup_state,
            self.sync_state,
            self.update_state,
            self.result_state,
            &self.latest_success_at,
            &self.latest_failure_at,
            &self.schema_fingerprint,
            &self.table_fingerprint,
            self.connection_revision,
            self.schema_revision,
            self.sync_state_revision,
            self.mission_revision,
            self.partial,
            &self.provenance,
        ]))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranSyncResultProposal {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub mission_revision: u64,
    pub sync_state_revision: u64,
    pub result_state: FivetranResultState,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_write_performed: bool,
    pub durable_receipt: bool,
    pub destination_read_back: bool,
    pub webhook_reconciled: bool,
    pub kernel_authority: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl FivetranSyncResultProposal {
    pub fn from_evidence(evidence: &FivetranSyncEvidence) -> Self {
        let mut proposal = Self {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            scope_digest: evidence.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            mission_revision: evidence.mission_revision,
            sync_state_revision: evidence.sync_state_revision,
            result_state: evidence.result_state,
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_write_performed: false,
            durable_receipt: false,
            destination_read_back: false,
            webhook_reconciled: false,
            kernel_authority: false,
            work_product_adopted: false,
            proposal_digest: Digest::pending(),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&serde_json::json!([
            &self.contract_version,
            &self.contract_digest,
            &self.scope_digest,
            &self.evidence_digest,
            &self.registration_digest,
            self.mission_revision,
            self.sync_state_revision,
            self.result_state,
            self.read_only,
            self.proposal_only,
            self.recording_only,
            self.external_write_performed,
            self.durable_receipt,
            self.destination_read_back,
            self.webhook_reconciled,
            self.kernel_authority,
            self.work_product_adopted,
        ]))
    }

    pub fn validate(&self, evidence: &FivetranSyncEvidence) -> Result<()> {
        evidence.validate()?;
        if self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.scope_digest != evidence.scope_digest
            || self.evidence_digest != evidence.evidence_digest
            || self.registration_digest != evidence.registration_digest
            || self.mission_revision != evidence.mission_revision
            || self.sync_state_revision != evidence.sync_state_revision
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.external_write_performed
            || self.durable_receipt
            || self.destination_read_back
            || self.webhook_reconciled
            || self.kernel_authority
            || self.work_product_adopted
            || self.proposal_digest != self.compute_digest()
        {
            return Err(FivetranError::TamperDetected {
                subject: "sync result proposal",
            });
        }
        Ok(())
    }

    pub const fn verified(&self) -> bool {
        self.read_only
            && self.proposal_only
            && self.recording_only
            && !self.external_write_performed
            && !self.durable_receipt
            && !self.destination_read_back
            && !self.webhook_reconciled
            && !self.kernel_authority
            && !self.work_product_adopted
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FivetranSyncRecording {
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub recording_digest: Digest,
    pub durable: bool,
    pub external_write_performed: bool,
    pub raw_payload_retained: bool,
    pub redaction: RedactionEvidence,
}

impl FivetranSyncRecording {
    pub fn from_evidence(evidence: &FivetranSyncEvidence) -> Self {
        let redaction = RedactionEvidence::layer1();
        Self {
            scope_digest: evidence.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            recording_digest: Digest::from_serializable(&(
                &evidence.scope_digest,
                &evidence.evidence_digest,
                &redaction,
            )),
            durable: false,
            external_write_performed: false,
            raw_payload_retained: false,
            redaction,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationReport {
    pub verified: bool,
    pub failures: Vec<String>,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
}

impl VerificationReport {
    pub fn success(evidence: &FivetranSyncEvidence, proposal: &FivetranSyncResultProposal) -> Self {
        Self {
            verified: true,
            failures: Vec::new(),
            evidence_digest: evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum FivetranError {
    #[error("invalid {kind} identifier")]
    InvalidIdentifier { kind: &'static str },
    #[error("invalid timestamp")]
    InvalidTimestamp,
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid input for {field}: {reason}")]
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid permission snapshot")]
    InvalidPermissionSnapshot,
    #[error("invalid pagination field: {field}")]
    InvalidPagination { field: &'static str },
    #[error("bound exceeded for {field}; limit {limit}")]
    BoundExceeded { field: &'static str, limit: usize },
    #[error("registration is not active")]
    RegistrationNotActive,
    #[error("registration or secret reference is revoked")]
    RegistrationRevoked,
    #[error("invalid registration transition from {from:?} to {to:?}")]
    InvalidRegistrationTransition {
        from: RegistrationStatus,
        to: RegistrationStatus,
    },
    #[error("scope drift in {field}")]
    ScopeDrift { field: &'static str },
    #[error("account drift")]
    AccountDrift,
    #[error("group drift")]
    GroupDrift,
    #[error("destination drift")]
    DestinationDrift,
    #[error("connection drift")]
    ConnectionDrift,
    #[error("schema drift")]
    SchemaDrift,
    #[error("table drift")]
    TableDrift,
    #[error("stale Mission revision: expected {expected}, observed {observed}")]
    StaleMissionRevision { expected: u64, observed: u64 },
    #[error("non-monotonic sync state revision: previous {previous}, observed {observed}")]
    NonMonotonicSyncState { previous: u64, observed: u64 },
    #[error("pagination cursor repeated")]
    CursorRepeated,
    #[error("pagination limit exceeded")]
    PaginationExceeded,
    #[error("pagination response drifted from requested scope")]
    PaginationScopeDrift,
    #[error("malformed provider payload")]
    MalformedPayload,
    #[error("partial provider payload cannot satisfy the exact scope")]
    PartialPayload,
    #[error("redaction invariant violated")]
    RedactionViolation,
    #[error("fixture/recording transport attempted a native claim")]
    NonNativeClaim,
    #[error("replay detected for {subject}")]
    ReplayDetected { subject: &'static str },
    #[error("tamper detected in {subject}")]
    TamperDetected { subject: &'static str },
    #[error("unauthorized (401)")]
    Unauthorized,
    #[error("forbidden (403)")]
    Forbidden,
    #[error("not found (404)")]
    NotFound,
    #[error("conflict (409)")]
    Conflict,
    #[error("rate limited (429); retry after {retry_after_seconds:?} seconds")]
    RateLimited { retry_after_seconds: Option<u32> },
    #[error("provider timeout")]
    Timeout,
    #[error("provider server failure ({status})")]
    ServerFailure { status: u16 },
    #[error("BLOCKED_ENV: native Fivetran HTTPS and API-key resolution are unavailable")]
    BlockedEnv,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("recording transport has no response")]
    EmptyRecording,
    #[error("recorded response endpoint does not match request")]
    EndpointMismatch,
    #[error("malformed versioned contract")]
    MalformedContract,
    #[error("mutation is forbidden in Layer-1: {operation}")]
    MutationForbidden { operation: &'static str },
}

impl From<serde_json::Error> for FivetranError {
    fn from(_: serde_json::Error) -> Self {
        Self::MalformedPayload
    }
}

impl From<FivetranError> for String {
    fn from(error: FivetranError) -> Self {
        error.to_string()
    }
}

#[allow(dead_code)]
const _: (&str, &str, &str) = (PLUGIN_ID, FIVETRAN_API_REVISION, CONTRACT_VERSION);
