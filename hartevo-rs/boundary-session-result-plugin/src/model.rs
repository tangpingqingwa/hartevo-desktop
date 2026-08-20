//! Typed Boundary scope, redacted metadata, and Layer-1 evidence models.
//!
//! The model deliberately has no field for a host set, host address,
//! connection detail, username, token, credential, recording byte, or raw
//! provider body. Provider JSON is projected into these types in `transport`
//! and is then discarded.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    BOUNDARY_CONTRACT_VERSION, BOUNDARY_MAX_CONNECTIONS, BOUNDARY_MAX_IDENTIFIER_BYTES,
    BOUNDARY_MAX_LIST_TOKEN_BYTES, BOUNDARY_MAX_SESSIONS_PER_PAGE, BOUNDARY_PLUGIN_VERSION,
    BOUNDARY_PROVIDER_ID, BOUNDARY_PROVIDER_IMPLEMENTATION, BOUNDARY_PROVIDER_REVISION,
    BOUNDARY_SERVICE_ID,
};

pub const MAX_SECRET_REFERENCE_BYTES: usize = 4_096;
pub const MAX_TIMESTAMP_BYTES: usize = 64;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BoundaryModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("the Boundary controller origin must be an exact HTTPS origin")]
    InvalidApiHost,
    #[error("the provider response is not a bounded allowlisted shape: {0}")]
    InvalidResponse(String),
    #[error("the bounded {field} list exceeded its maximum")]
    TooMany { field: &'static str },
    #[error("the registration or secret reference is already revoked")]
    AlreadyRevoked,
    #[error("the opaque list token is invalid")]
    InvalidListToken,
    #[error("the response timestamp is invalid")]
    InvalidTimestamp,
    #[error("the response lifecycle state is not recognized")]
    InvalidState,
    #[error("the response is outside the exact registered scope: {0}")]
    ScopeMismatch(&'static str),
    #[error("serialization failed while computing a deterministic digest")]
    Serialization,
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), BoundaryModelError> {
    if value.is_empty() {
        return Err(BoundaryModelError::Empty { field });
    }
    if value.len() > BOUNDARY_MAX_IDENTIFIER_BYTES {
        return Err(BoundaryModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(BoundaryModelError::ControlCharacter { field });
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(BoundaryModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), BoundaryModelError> {
    if value == 0 {
        Err(BoundaryModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, BoundaryModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_fields([$field, self.as_str()])
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

bounded_identifier!(HostId, "host id");
bounded_identifier!(BoundaryScopeId, "Boundary scope id");
bounded_identifier!(OrganizationId, "organization id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(TargetId, "target id");
bounded_identifier!(SessionId, "session id");
bounded_identifier!(AuthMethodId, "auth method id");
bounded_identifier!(AccountId, "account id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(WorkProductId, "Work Product id");

pub type ScopeId = BoundaryScopeId;

#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, BoundaryModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for Revision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Revision").field(&self.0).finish()
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(hex_encode(Sha256::digest(bytes.as_ref()).as_slice()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value)
    }

    pub fn from_fields<I, S>(fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut hasher = Sha256::new();
        for field in fields {
            let field = field.as_ref();
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
            hasher.update([0]);
        }
        Self(hex_encode(hasher.finalize().as_slice()))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, BoundaryModelError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(BoundaryModelError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value))
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self == &Self::zero()
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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

pub fn sha256_digest(bytes: impl AsRef<[u8]>) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    sha256_digest(bytes)
}

#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BoundaryApiHost(String);

impl BoundaryApiHost {
    pub fn new(value: impl Into<String>) -> Result<Self, BoundaryModelError> {
        let value = value.into();
        let without_slash = value.strip_suffix('/').unwrap_or(&value);
        let authority = without_slash.strip_prefix("https://");
        if authority.is_none_or(str::is_empty)
            || without_slash.contains('?')
            || without_slash.contains('#')
            || without_slash.contains('@')
            || without_slash.chars().any(char::is_whitespace)
            || authority.is_some_and(|host| host.contains('/'))
        {
            return Err(BoundaryModelError::InvalidApiHost);
        }
        Ok(Self(without_slash.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(["boundary-api-host", self.as_str()])
    }
}

impl fmt::Debug for BoundaryApiHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BoundaryApiHost")
            .field(&self.digest())
            .finish()
    }
}

impl fmt::Display for BoundaryApiHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretKind {
    Token,
    Oidc,
}

/// An opaque host-owned token/OIDC reference. The supplied reference is
/// hashed and discarded; this type intentionally does not implement
/// serialization.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    revoked: bool,
}

impl SecretReference {
    pub fn new(reference: impl AsRef<str>) -> Result<Self, BoundaryModelError> {
        Self::token(reference)
    }

    pub fn token(reference: impl AsRef<str>) -> Result<Self, BoundaryModelError> {
        Self::with_kind(SecretKind::Token, reference)
    }

    pub fn oidc(reference: impl AsRef<str>) -> Result<Self, BoundaryModelError> {
        Self::with_kind(SecretKind::Oidc, reference)
    }

    pub fn with_kind(
        kind: SecretKind,
        reference: impl AsRef<str>,
    ) -> Result<Self, BoundaryModelError> {
        let reference = reference.as_ref();
        if reference.is_empty() {
            return Err(BoundaryModelError::Empty {
                field: "secret reference",
            });
        }
        if reference.len() > MAX_SECRET_REFERENCE_BYTES {
            return Err(BoundaryModelError::TooLong {
                field: "secret reference",
            });
        }
        if reference.chars().any(char::is_control) {
            return Err(BoundaryModelError::ControlCharacter {
                field: "secret reference",
            });
        }
        Ok(Self {
            kind,
            reference_digest: Digest::from_fields(["boundary-secret-reference", reference]),
            revoked: false,
        })
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), BoundaryModelError> {
        if self.revoked {
            return Err(BoundaryModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("opaque", &true)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryPermission {
    SessionList,
    SessionRead,
    TargetRead,
}

impl BoundaryPermission {
    pub const ALL: [Self; 3] = [Self::SessionList, Self::SessionRead, Self::TargetRead];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionList => "session_list",
            Self::SessionRead => "session_read",
            Self::TargetRead => "target_read",
        }
    }

    pub fn parse(value: &str) -> Result<Self, BoundaryModelError> {
        match value {
            "session_list" => Ok(Self::SessionList),
            "session_read" => Ok(Self::SessionRead),
            "target_read" => Ok(Self::TargetRead),
            _ => Err(BoundaryModelError::Invalid {
                field: "permission",
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    permissions: BTreeSet<BoundaryPermission>,
    digest: Digest,
}

impl PermissionSnapshot {
    pub fn read_only() -> Self {
        Self::from_permissions(BoundaryPermission::ALL)
    }

    pub fn from_permissions<I>(permissions: I) -> Self
    where
        I: IntoIterator<Item = BoundaryPermission>,
    {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        let digest = Digest::from_fields(permissions.iter().map(|permission| permission.as_str()));
        Self {
            permissions,
            digest,
        }
    }

    pub fn from_names<I, S>(permissions: I) -> Result<Self, BoundaryModelError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        permissions
            .into_iter()
            .map(|permission| BoundaryPermission::parse(permission.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map(Self::from_permissions)
    }

    pub fn permissions(&self) -> &BTreeSet<BoundaryPermission> {
        &self.permissions
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn allows(&self, permission: BoundaryPermission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn is_exact_read_only(&self) -> bool {
        self.permissions == BoundaryPermission::ALL.into_iter().collect()
    }
}

macro_rules! binding {
    ($name:ident, $id:ident, $label:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            pub id: $id,
            pub revision: Revision,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, BoundaryModelError> {
                Ok(Self {
                    id: $id::new(id)?,
                    revision: Revision::new(revision)?,
                })
            }

            pub fn digest(&self) -> Digest {
                Digest::from_fields([$label, self.id.as_str(), &self.revision.get().to_string()])
            }
        }
    };
}

binding!(HostBinding, HostId, "host-binding");
binding!(ScopeBinding, BoundaryScopeId, "scope-binding");
binding!(OrganizationBinding, OrganizationId, "organization-binding");
binding!(ProjectBinding, ProjectId, "project-binding");
binding!(TargetBinding, TargetId, "target-binding");
binding!(SessionBinding, SessionId, "session-binding");
binding!(AuthMethodBinding, AuthMethodId, "auth-method-binding");
binding!(AccountBinding, AccountId, "account-binding");
binding!(MissionBinding, MissionId, "mission-binding");
binding!(WorkProductBinding, WorkProductId, "work-product-binding");

#[derive(Clone, Debug)]
pub struct BoundaryScopeInput {
    pub api_host: String,
    pub host_id: String,
    pub host_revision: u64,
    pub scope_id: String,
    pub scope_revision: u64,
    pub organization_id: String,
    pub organization_revision: u64,
    pub project_id: String,
    pub project_revision: u64,
    pub target_id: String,
    pub target_revision: u64,
    pub session_id: String,
    pub session_revision: u64,
    pub auth_method_id: String,
    pub auth_method_revision: u64,
    pub account_id: String,
    pub account_revision: u64,
    pub principal_digest: Digest,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub permission_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundaryScope {
    pub api_host: BoundaryApiHost,
    pub host: HostBinding,
    pub scope: ScopeBinding,
    pub organization: OrganizationBinding,
    pub project: ProjectBinding,
    pub target: TargetBinding,
    pub session: SessionBinding,
    pub auth_method: AuthMethodBinding,
    pub account: AccountBinding,
    pub principal_digest: Digest,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
}

impl BoundaryScope {
    pub fn new(input: BoundaryScopeInput) -> Result<Self, BoundaryModelError> {
        let mut scope = Self {
            api_host: BoundaryApiHost::new(input.api_host)?,
            host: HostBinding::new(input.host_id, input.host_revision)?,
            scope: ScopeBinding::new(input.scope_id, input.scope_revision)?,
            organization: OrganizationBinding::new(
                input.organization_id,
                input.organization_revision,
            )?,
            project: ProjectBinding::new(input.project_id, input.project_revision)?,
            target: TargetBinding::new(input.target_id, input.target_revision)?,
            session: SessionBinding::new(input.session_id, input.session_revision)?,
            auth_method: AuthMethodBinding::new(input.auth_method_id, input.auth_method_revision)?,
            account: AccountBinding::new(input.account_id, input.account_revision)?,
            principal_digest: input.principal_digest,
            mission: MissionBinding::new(input.mission_id, input.mission_revision)?,
            work_product: WorkProductBinding::new(
                input.work_product_id,
                input.work_product_revision,
            )?,
            permission_digest: input.permission_digest,
            scope_digest: Digest::zero(),
        };
        scope.validate_fields()?;
        scope.scope_digest = scope.compute_digest();
        scope.validate()?;
        Ok(scope)
    }

    pub fn fixture() -> Result<Self, BoundaryModelError> {
        Self::new(BoundaryScopeInput {
            api_host: "https://boundary.example.test".to_owned(),
            host_id: "h-1".to_owned(),
            host_revision: 1,
            scope_id: "s-1".to_owned(),
            scope_revision: 1,
            organization_id: "org-1".to_owned(),
            organization_revision: 1,
            project_id: "p-1".to_owned(),
            project_revision: 1,
            target_id: "t-1".to_owned(),
            target_revision: 1,
            session_id: "ss-1".to_owned(),
            session_revision: 1,
            auth_method_id: "amoid-1".to_owned(),
            auth_method_revision: 1,
            account_id: "acct-1".to_owned(),
            account_revision: 1,
            principal_digest: Digest::from_text("principal-1"),
            mission_id: "mission-1".to_owned(),
            mission_revision: 1,
            work_product_id: "work-product-1".to_owned(),
            work_product_revision: 1,
            permission_digest: PermissionSnapshot::read_only().digest().clone(),
        })
    }

    pub fn validate(&self) -> Result<(), BoundaryModelError> {
        self.validate_fields()?;
        if self.scope_digest != self.compute_digest() {
            return Err(BoundaryModelError::Invalid {
                field: "scope digest",
            });
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), BoundaryModelError> {
        if self.permission_digest.is_zero() {
            return Err(BoundaryModelError::Invalid {
                field: "permission digest",
            });
        }
        if self.principal_digest.is_zero() {
            return Err(BoundaryModelError::Invalid {
                field: "principal digest",
            });
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields([
            self.api_host.digest().as_str(),
            self.host.digest().as_str(),
            self.scope.digest().as_str(),
            self.organization.digest().as_str(),
            self.project.digest().as_str(),
            self.target.digest().as_str(),
            self.session.digest().as_str(),
            self.auth_method.digest().as_str(),
            self.account.digest().as_str(),
            self.principal_digest.as_str(),
            self.mission.digest().as_str(),
            self.work_product.digest().as_str(),
            self.permission_digest.as_str(),
        ])
    }

    pub fn recompute_digest(&self) -> Digest {
        self.compute_digest()
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        self.digest()
    }

    pub fn api_host(&self) -> &BoundaryApiHost {
        &self.api_host
    }

    pub fn host_id(&self) -> &HostId {
        &self.host.id
    }

    pub fn scope_id(&self) -> &BoundaryScopeId {
        &self.scope.id
    }

    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization.id
    }

    pub fn org_id(&self) -> &OrganizationId {
        self.organization_id()
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project.id
    }

    pub fn target_id(&self) -> &TargetId {
        &self.target.id
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session.id
    }

    pub fn auth_method_id(&self) -> &AuthMethodId {
        &self.auth_method.id
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account.id
    }

    pub fn principal_digest(&self) -> &Digest {
        &self.principal_digest
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission.id
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product.id
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
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

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundarySessionResultState {
    Pending,
    Active,
    Canceling,
    Terminated,
    Expired,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

pub type BoundarySessionState = BoundarySessionResultState;

impl BoundarySessionResultState {
    pub fn from_wire(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "pending" => Self::Pending,
            "active" => Self::Active,
            "canceling" | "cancelling" => Self::Canceling,
            "terminated" => Self::Terminated,
            "expired" => Self::Expired,
            _ => Self::ProviderUnknown,
        }
    }

    pub const fn is_lifecycle(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Active | Self::Canceling | Self::Terminated | Self::Expired
        )
    }

    pub const fn is_fail_closed(self) -> bool {
        !matches!(self, Self::Active)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminated | Self::Expired)
    }

    pub fn lifecycle_regression(previous: Self, current: Self) -> bool {
        if !previous.is_lifecycle() || !current.is_lifecycle() {
            return false;
        }
        if previous == current {
            return false;
        }
        if previous.is_terminal() {
            return true;
        }
        if current == Self::Pending {
            return true;
        }
        let rank = |state| match state {
            Self::Pending => 0,
            Self::Active => 1,
            Self::Canceling => 2,
            Self::Terminated | Self::Expired => 3,
            Self::Partial
            | Self::AccessLost
            | Self::ProviderUnknown
            | Self::Tampered
            | Self::Revoked => 0,
        };
        rank(current) < rank(previous)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryResponseType {
    Delta,
    Complete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryReadOperation {
    ListSessions,
    ReadSession,
    ReadTarget,
}

impl BoundaryReadOperation {
    pub const fn method(self) -> &'static str {
        "GET"
    }

    pub const fn path_template(self) -> &'static str {
        match self {
            Self::ListSessions => "/v1/sessions",
            Self::ReadSession => "/v1/sessions/{id}",
            Self::ReadTarget => "/v1/targets/{id}",
        }
    }
}

/// Boundary list pagination token. Only a digest is retained, serialized, or
/// exposed in Debug; the provider response's raw token is discarded.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueListToken {
    digest: Digest,
}

impl OpaqueListToken {
    pub fn new(value: impl AsRef<str>) -> Result<Self, BoundaryModelError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > BOUNDARY_MAX_LIST_TOKEN_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(BoundaryModelError::InvalidListToken);
        }
        Ok(Self {
            digest: Digest::from_fields(["boundary-list-token", value]),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }
}

impl Serialize for OpaqueListToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OpaqueListToken", 2)?;
        state.serialize_field("opaque", &true)?;
        state.serialize_field("tokenDigest", &self.digest)?;
        state.end()
    }
}

impl fmt::Debug for OpaqueListToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueListToken")
            .field("token_digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundaryReadRequest {
    pub operation: BoundaryReadOperation,
    pub scope_digest: Digest,
    pub session_id: Option<SessionId>,
    pub target_id: Option<TargetId>,
    pub list_token: Option<OpaqueListToken>,
    pub page_size: u16,
    pub max_response_bytes: usize,
}

impl BoundaryReadRequest {
    pub fn list(
        scope: &BoundaryScope,
        page_size: u16,
        list_token: Option<OpaqueListToken>,
    ) -> Result<Self, BoundaryModelError> {
        if page_size == 0 || usize::from(page_size) > BOUNDARY_MAX_SESSIONS_PER_PAGE {
            return Err(BoundaryModelError::Invalid { field: "page size" });
        }
        Ok(Self {
            operation: BoundaryReadOperation::ListSessions,
            scope_digest: scope.scope_digest().clone(),
            session_id: None,
            target_id: None,
            list_token,
            page_size,
            max_response_bytes: crate::BOUNDARY_MAX_RESPONSE_BYTES,
        })
    }

    pub fn session(scope: &BoundaryScope) -> Self {
        Self {
            operation: BoundaryReadOperation::ReadSession,
            scope_digest: scope.scope_digest().clone(),
            session_id: Some(scope.session.id.clone()),
            target_id: None,
            list_token: None,
            page_size: 1,
            max_response_bytes: crate::BOUNDARY_MAX_RESPONSE_BYTES,
        }
    }

    pub fn target(scope: &BoundaryScope) -> Self {
        Self {
            operation: BoundaryReadOperation::ReadTarget,
            scope_digest: scope.scope_digest().clone(),
            session_id: None,
            target_id: Some(scope.target.id.clone()),
            list_token: None,
            page_size: 1,
            max_response_bytes: crate::BOUNDARY_MAX_RESPONSE_BYTES,
        }
    }

    pub fn path(&self, scope: &BoundaryScope) -> String {
        match self.operation {
            BoundaryReadOperation::ListSessions => format!(
                "/v1/sessions?scope_id={}&recursive=false&include_terminated=true&page_size={}&list_token_digest={}",
                scope.scope_id().as_str(),
                self.page_size,
                self.list_token
                    .as_ref()
                    .map_or("none", |token| token.digest().as_str())
            ),
            BoundaryReadOperation::ReadSession => {
                format!(
                    "/v1/sessions/{}",
                    self.session_id
                        .as_ref()
                        .map_or("missing", SessionId::as_str)
                )
            }
            BoundaryReadOperation::ReadTarget => {
                format!(
                    "/v1/targets/{}",
                    self.target_id.as_ref().map_or("missing", TargetId::as_str)
                )
            }
        }
    }

    pub fn request_digest(&self, scope: &BoundaryScope) -> Digest {
        Digest::from_fields([
            self.operation.path_template(),
            self.operation.method(),
            self.path(scope).as_str(),
            self.scope_digest.as_str(),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundarySessionMetadata {
    pub id: SessionId,
    pub target_id: TargetId,
    pub scope_id: BoundaryScopeId,
    pub host_id: Option<HostId>,
    pub organization_id: Option<OrganizationId>,
    pub project_id: Option<ProjectId>,
    pub auth_method_id: Option<AuthMethodId>,
    pub account_id: Option<AccountId>,
    pub principal_digest: Option<Digest>,
    pub revision: Revision,
    pub session_type_digest: Option<Digest>,
    pub state: BoundarySessionResultState,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub expiration_at: Option<DateTime<Utc>>,
    pub terminated_at: Option<DateTime<Utc>>,
    pub connection_count: u16,
    pub active_connection_count: u16,
    pub lifecycle_digest: Digest,
}

impl BoundarySessionMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: SessionId,
        target_id: TargetId,
        scope_id: BoundaryScopeId,
        revision: Revision,
        state: BoundarySessionResultState,
        created_at: Option<DateTime<Utc>>,
        updated_at: Option<DateTime<Utc>>,
        expiration_at: Option<DateTime<Utc>>,
        terminated_at: Option<DateTime<Utc>>,
        connection_count: u16,
        active_connection_count: u16,
    ) -> Result<Self, BoundaryModelError> {
        if connection_count > BOUNDARY_MAX_CONNECTIONS || active_connection_count > connection_count
        {
            return Err(BoundaryModelError::TooMany {
                field: "connection counts",
            });
        }
        if !state.is_lifecycle() {
            return Err(BoundaryModelError::InvalidState);
        }
        let mut value = Self {
            id,
            target_id,
            scope_id,
            host_id: None,
            organization_id: None,
            project_id: None,
            auth_method_id: None,
            account_id: None,
            principal_digest: None,
            revision,
            session_type_digest: None,
            state,
            created_at,
            updated_at,
            expiration_at,
            terminated_at,
            connection_count,
            active_connection_count,
            lifecycle_digest: Digest::zero(),
        };
        value.lifecycle_digest = value.recompute_lifecycle_digest();
        Ok(value)
    }

    pub fn fixture(
        id: impl Into<String>,
        target_id: impl Into<String>,
        scope_id: impl Into<String>,
        revision: u64,
        state: BoundarySessionResultState,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, BoundaryModelError> {
        Self::new(
            SessionId::new(id)?,
            TargetId::new(target_id)?,
            BoundaryScopeId::new(scope_id)?,
            Revision::new(revision)?,
            state,
            Some(observed_at),
            Some(observed_at),
            None,
            None,
            0,
            0,
        )
    }

    pub fn effective_state(&self, observed_at: DateTime<Utc>) -> BoundarySessionResultState {
        if self
            .expiration_at
            .is_some_and(|expiration| expiration <= observed_at)
            && matches!(
                self.state,
                BoundarySessionResultState::Pending
                    | BoundarySessionResultState::Active
                    | BoundarySessionResultState::Canceling
            )
        {
            BoundarySessionResultState::Expired
        } else {
            self.state
        }
    }

    pub fn recompute_lifecycle_digest(&self) -> Digest {
        Digest::from_fields([
            self.id.as_str(),
            self.target_id.as_str(),
            self.scope_id.as_str(),
            self.host_id.as_ref().map_or("", HostId::as_str),
            self.organization_id
                .as_ref()
                .map_or("", OrganizationId::as_str),
            self.project_id.as_ref().map_or("", ProjectId::as_str),
            self.auth_method_id
                .as_ref()
                .map_or("", AuthMethodId::as_str),
            self.account_id.as_ref().map_or("", AccountId::as_str),
            self.principal_digest.as_ref().map_or("", Digest::as_str),
            &self.revision.get().to_string(),
            &format!("{:?}", self.state),
            &self
                .created_at
                .map_or_else(String::new, |value| value.to_rfc3339()),
            &self
                .updated_at
                .map_or_else(String::new, |value| value.to_rfc3339()),
            &self
                .expiration_at
                .map_or_else(String::new, |value| value.to_rfc3339()),
            &self
                .terminated_at
                .map_or_else(String::new, |value| value.to_rfc3339()),
            &self.connection_count.to_string(),
            &self.active_connection_count.to_string(),
        ])
    }

    pub fn validate_integrity(&self) -> Result<(), BoundaryModelError> {
        if self.lifecycle_digest != self.recompute_lifecycle_digest() {
            return Err(BoundaryModelError::Invalid {
                field: "session lifecycle digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundaryTargetMetadata {
    pub id: TargetId,
    pub scope_id: BoundaryScopeId,
    pub organization_id: Option<OrganizationId>,
    pub project_id: Option<ProjectId>,
    pub revision: Revision,
    pub target_type_digest: Option<Digest>,
    pub name_digest: Option<Digest>,
    pub description_digest: Option<Digest>,
    pub address_digest: Option<Digest>,
    pub session_max_seconds: Option<u32>,
    pub session_connection_limit: Option<u16>,
    pub target_digest: Digest,
}

impl BoundaryTargetMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: TargetId,
        scope_id: BoundaryScopeId,
        revision: Revision,
        target_type_digest: Option<Digest>,
        name_digest: Option<Digest>,
        description_digest: Option<Digest>,
        address_digest: Option<Digest>,
        session_max_seconds: Option<u32>,
        session_connection_limit: Option<u16>,
    ) -> Self {
        let mut value = Self {
            id,
            scope_id,
            organization_id: None,
            project_id: None,
            revision,
            target_type_digest,
            name_digest,
            description_digest,
            address_digest,
            session_max_seconds,
            session_connection_limit,
            target_digest: Digest::zero(),
        };
        value.target_digest = value.recompute_digest();
        value
    }

    pub fn recompute_digest(&self) -> Digest {
        Digest::from_fields([
            self.id.as_str(),
            self.scope_id.as_str(),
            self.organization_id
                .as_ref()
                .map_or("", OrganizationId::as_str),
            self.project_id.as_ref().map_or("", ProjectId::as_str),
            &self.revision.get().to_string(),
            self.target_type_digest.as_ref().map_or("", Digest::as_str),
            self.name_digest.as_ref().map_or("", Digest::as_str),
            self.description_digest.as_ref().map_or("", Digest::as_str),
            self.address_digest.as_ref().map_or("", Digest::as_str),
            &self
                .session_max_seconds
                .map_or_else(String::new, |value| value.to_string()),
            &self
                .session_connection_limit
                .map_or_else(String::new, |value| value.to_string()),
        ])
    }

    pub fn validate_integrity(&self) -> Result<(), BoundaryModelError> {
        if self.target_digest != self.recompute_digest() {
            return Err(BoundaryModelError::Invalid {
                field: "target digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BoundaryResponseBody {
    SessionList {
        sessions: Vec<BoundarySessionMetadata>,
        next_list_token: Option<OpaqueListToken>,
        response_type: BoundaryResponseType,
        estimated_item_count: Option<u32>,
        removed_id_digests: Vec<Digest>,
    },
    Session(BoundarySessionMetadata),
    Target(BoundaryTargetMetadata),
    Empty,
}

impl BoundaryResponseBody {
    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundaryHttpResponse {
    pub status: u16,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub body: BoundaryResponseBody,
}

impl BoundaryHttpResponse {
    pub fn from_body(status: u16, body: BoundaryResponseBody) -> Self {
        let response_digest = body.digest();
        let response_bytes = serde_json::to_vec(&body).map_or(0, |bytes| bytes.len());
        Self {
            status,
            response_bytes,
            response_digest,
            body,
        }
    }

    pub fn empty(status: u16) -> Self {
        Self::from_body(status, BoundaryResponseBody::Empty)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundaryReadEvidence {
    pub operation: BoundaryReadOperation,
    pub state: BoundarySessionResultState,
    pub sessions: Vec<BoundarySessionMetadata>,
    pub target: Option<BoundaryTargetMetadata>,
    pub page_count: u16,
    pub request_count: u16,
    pub partial: bool,
    pub list_token_digests: Vec<Digest>,
    pub removed_id_digests: Vec<Digest>,
    pub request_digests: Vec<Digest>,
    pub response_digests: Vec<Digest>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub provider_revision: String,
    pub contract_digest: Digest,
    pub provenance: TransportProvenance,
    pub source_digest: Digest,
    pub evidence_digest: Digest,
}

pub type BoundarySessionResultEvidence = BoundaryReadEvidence;

impl BoundaryReadEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn success(
        operation: BoundaryReadOperation,
        sessions: Vec<BoundarySessionMetadata>,
        target: Option<BoundaryTargetMetadata>,
        page_count: u16,
        request_count: u16,
        partial: bool,
        list_token_digests: Vec<Digest>,
        removed_id_digests: Vec<Digest>,
        request_digests: Vec<Digest>,
        response_digests: Vec<Digest>,
        scope_digest: Digest,
        permission_digest: Digest,
        provider_digest: Digest,
        provider_revision: String,
        contract_digest: Digest,
        provenance: TransportProvenance,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let state = if partial {
            BoundarySessionResultState::Partial
        } else if let Some(session) = sessions.first() {
            session.effective_state(observed_at)
        } else {
            BoundarySessionResultState::Pending
        };
        Self::with_state(
            operation,
            state,
            sessions,
            target,
            page_count,
            request_count,
            partial,
            list_token_digests,
            removed_id_digests,
            request_digests,
            response_digests,
            scope_digest,
            permission_digest,
            provider_digest,
            provider_revision,
            contract_digest,
            provenance,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn failure(
        operation: BoundaryReadOperation,
        state: BoundarySessionResultState,
        scope_digest: Digest,
        permission_digest: Digest,
        provider_digest: Digest,
        provider_revision: String,
        contract_digest: Digest,
        provenance: TransportProvenance,
    ) -> Self {
        Self::with_state(
            operation,
            state,
            Vec::new(),
            None,
            0,
            0,
            matches!(state, BoundarySessionResultState::Partial),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            scope_digest,
            permission_digest,
            provider_digest,
            provider_revision,
            contract_digest,
            provenance,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_state(
        operation: BoundaryReadOperation,
        state: BoundarySessionResultState,
        sessions: Vec<BoundarySessionMetadata>,
        target: Option<BoundaryTargetMetadata>,
        page_count: u16,
        request_count: u16,
        partial: bool,
        list_token_digests: Vec<Digest>,
        removed_id_digests: Vec<Digest>,
        request_digests: Vec<Digest>,
        response_digests: Vec<Digest>,
        scope_digest: Digest,
        permission_digest: Digest,
        provider_digest: Digest,
        provider_revision: String,
        contract_digest: Digest,
        provenance: TransportProvenance,
    ) -> Self {
        let source_digest = Digest::from_fields(
            response_digests
                .iter()
                .map(Digest::as_str)
                .chain(request_digests.iter().map(Digest::as_str))
                .chain([scope_digest.as_str(), provider_digest.as_str()]),
        );
        let mut evidence = Self {
            operation,
            state,
            sessions,
            target,
            page_count,
            request_count,
            partial,
            list_token_digests,
            removed_id_digests,
            request_digests,
            response_digests,
            scope_digest,
            permission_digest,
            provider_digest,
            provider_revision,
            contract_digest,
            provenance,
            source_digest,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.recompute_digest();
        evidence
    }

    pub fn recompute_digest(&self) -> Digest {
        let mut clone = self.clone();
        clone.evidence_digest = Digest::zero();
        digest_serializable(&clone)
    }

    pub fn validate_integrity(&self) -> Result<(), BoundaryModelError> {
        if self.evidence_digest != self.recompute_digest() {
            return Err(BoundaryModelError::Invalid {
                field: "evidence digest",
            });
        }
        for session in &self.sessions {
            session.validate_integrity()?;
        }
        if let Some(target) = &self.target {
            target.validate_integrity()?;
        }
        Ok(())
    }

    pub fn is_projection_only(&self) -> bool {
        matches!(
            self.state,
            BoundarySessionResultState::Partial
                | BoundarySessionResultState::AccessLost
                | BoundarySessionResultState::ProviderUnknown
                | BoundarySessionResultState::Tampered
                | BoundarySessionResultState::Revoked
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

impl RegistrationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundaryRegistration {
    pub state: RegistrationState,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_implementation: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
}

impl BoundaryRegistration {
    pub fn new(
        scope: &BoundaryScope,
        secret: &SecretReference,
        provider_digest: Digest,
        evidence_digest: Digest,
        contract_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            state: RegistrationState::Active,
            plugin_version: BOUNDARY_PLUGIN_VERSION.to_owned(),
            contract_version: BOUNDARY_CONTRACT_VERSION.to_owned(),
            contract_digest,
            service_id: BOUNDARY_SERVICE_ID.to_owned(),
            provider_id: BOUNDARY_PROVIDER_ID.to_owned(),
            provider_implementation: BOUNDARY_PROVIDER_IMPLEMENTATION.to_owned(),
            provider_version: BOUNDARY_PLUGIN_VERSION.to_owned(),
            provider_revision: BOUNDARY_PROVIDER_REVISION.to_owned(),
            provider_digest,
            permission_digest: scope.permission_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            secret_digest: secret.reference_digest.clone(),
            evidence_digest,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recompute_digest();
        registration
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn revoke(&mut self) -> Result<(), BoundaryModelError> {
        if !self.is_active() {
            return Err(BoundaryModelError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.recompute_digest();
        Ok(())
    }

    pub fn recompute_digest(&self) -> Digest {
        Digest::from_fields([
            self.state.as_str(),
            self.plugin_version.as_str(),
            self.contract_version.as_str(),
            self.contract_digest.as_str(),
            self.service_id.as_str(),
            self.provider_id.as_str(),
            self.provider_implementation.as_str(),
            self.provider_version.as_str(),
            self.provider_revision.as_str(),
            self.provider_digest.as_str(),
            self.permission_digest.as_str(),
            self.scope_digest.as_str(),
            self.secret_digest.as_str(),
            self.evidence_digest.as_str(),
        ])
    }

    pub fn validate(
        &self,
        scope: &BoundaryScope,
        secret: &SecretReference,
        provider_digest: &Digest,
        evidence_digest: &Digest,
        contract_digest: &Digest,
    ) -> Result<(), BoundaryModelError> {
        if self.registration_digest != self.recompute_digest() {
            return Err(BoundaryModelError::Invalid {
                field: "registration digest",
            });
        }
        if self.plugin_version != BOUNDARY_PLUGIN_VERSION
            || self.contract_version != BOUNDARY_CONTRACT_VERSION
            || self.contract_digest != *contract_digest
            || self.service_id != BOUNDARY_SERVICE_ID
            || self.provider_id != BOUNDARY_PROVIDER_ID
            || self.provider_implementation != BOUNDARY_PROVIDER_IMPLEMENTATION
            || self.provider_version != BOUNDARY_PLUGIN_VERSION
            || self.provider_revision != BOUNDARY_PROVIDER_REVISION
            || self.provider_digest != *provider_digest
            || self.permission_digest != *scope.permission_digest()
            || self.scope_digest != *scope.scope_digest()
            || self.secret_digest != *secret.reference_digest()
            || self.evidence_digest != *evidence_digest
        {
            return Err(BoundaryModelError::ScopeMismatch(
                "registration binding drift",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundarySessionResultProjection {
    pub state: BoundarySessionResultState,
    pub partial: bool,
    pub access_lost: bool,
    pub provider_unknown: bool,
    pub tampered: bool,
    pub revoked: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub authorization_correctness_claim: bool,
    pub reachability_claim: bool,
    pub user_activity_claim: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub work_product_adopted: bool,
}

impl BoundarySessionResultProjection {
    pub fn from_evidence(evidence: &BoundaryReadEvidence) -> Self {
        let state = evidence.state;
        Self {
            state,
            partial: matches!(state, BoundarySessionResultState::Partial) || evidence.partial,
            access_lost: matches!(state, BoundarySessionResultState::AccessLost),
            provider_unknown: matches!(state, BoundarySessionResultState::ProviderUnknown),
            tampered: matches!(state, BoundarySessionResultState::Tampered),
            revoked: matches!(state, BoundarySessionResultState::Revoked),
            native: false,
            connected: false,
            first_party: false,
            authorization_correctness_claim: false,
            reachability_claim: false,
            user_activity_claim: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            work_product_adopted: false,
        }
    }

    pub const fn is_fail_closed(&self) -> bool {
        !matches!(self.state, BoundarySessionResultState::Active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundarySessionResultProposal {
    pub operation: BoundaryReadOperation,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence: BoundaryReadEvidence,
    pub projection: BoundarySessionResultProjection,
    pub read_only: bool,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub authorize: bool,
    pub connect: bool,
    pub cancel: bool,
    pub credential_brokering: bool,
    pub target_mutated: bool,
    pub host_mutated: bool,
    pub auth_method_mutated: bool,
    pub adopted_by_kernel: bool,
    pub proposal_digest: Digest,
}

pub type BoundarySessionResult = BoundarySessionResultProposal;

impl BoundarySessionResultProposal {
    pub fn new(
        registration: &BoundaryRegistration,
        evidence: BoundaryReadEvidence,
    ) -> Result<Self, BoundaryModelError> {
        evidence.validate_integrity()?;
        let projection = BoundarySessionResultProjection::from_evidence(&evidence);
        let mut proposal = Self {
            operation: evidence.operation,
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            evidence,
            projection,
            read_only: true,
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            authorize: false,
            connect: false,
            cancel: false,
            credential_brokering: false,
            target_mutated: false,
            host_mutated: false,
            auth_method_mutated: false,
            adopted_by_kernel: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.recompute_digest();
        Ok(proposal)
    }

    pub fn recompute_digest(&self) -> Digest {
        let mut clone = self.clone();
        clone.proposal_digest = Digest::zero();
        digest_serializable(&clone)
    }

    pub fn validate_integrity(&self) -> Result<(), BoundaryModelError> {
        self.evidence.validate_integrity()?;
        if self.scope_digest != self.evidence.scope_digest
            || self.operation != self.evidence.operation
            || self.projection.state != self.evidence.state
            || self.proposal_digest != self.recompute_digest()
        {
            return Err(BoundaryModelError::Invalid {
                field: "proposal digest or binding",
            });
        }
        Ok(())
    }

    pub const fn state(&self) -> BoundarySessionResultState {
        self.projection.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundaryLocalRecord {
    pub recorded: bool,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub durable_provider_receipt: bool,
    pub provider_mutated: bool,
    pub raw_provider_payload_retained: bool,
    pub credential_material_retained: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundaryIntegrityCheck {
    pub valid: bool,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_readback_performed: bool,
    pub authorization_correctness_authority: bool,
    pub reachability_authority: bool,
    pub consent_authority: bool,
    pub outcome_authority: bool,
}
