//! Typed, bounded and redacted values for the Plaid Transactions sync seam.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::{
    PLAID_TRANSACTION_RESULT_CONTRACT_VERSION, PLAID_TRANSACTION_RESULT_PLUGIN_VERSION,
    PLAID_TRANSACTION_RESULT_PROVIDER_ID, PLAID_TRANSACTION_RESULT_SCHEMA_VERSION, digest_bytes,
    digest_serializable,
};

pub const DEFAULT_PLAID_API_VERSION: &str = "2020-09-14";
pub const DEFAULT_PLAID_SYNC_ENDPOINT: &str = "/transactions/sync";
pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_REFERENCE_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 2_048;
pub const MAX_TRANSACTION_COUNT: usize = 500;
pub const MAX_PAGE_COUNT: usize = 64;
pub const MAX_ACCOUNT_FILTERS: usize = 32;
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_UPDATE_WINDOW_SECONDS: u64 = 366 * 24 * 60 * 60;
pub const MAX_DATE_BYTES: usize = 32;
pub const MAX_PROVIDER_FIELD_BYTES: usize = 512;
pub const MAX_FAILURE_BYTES: usize = 256;

/// Every error is a safe projection and contains no provider body or secret.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PlaidTransactionResultError {
    #[error("invalid {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("scope mismatch: {0}")]
    ScopeMismatch(&'static str),
    #[error("provider identity drifted")]
    ProviderIdentityDrift,
    #[error("provider API version drifted")]
    ProviderApiVersionDrift,
    #[error("provider scope fence drifted")]
    ProviderScopeDrift,
    #[error("permission binding drifted")]
    PermissionDrift,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("registration binding is stale or tampered")]
    RegistrationTampered,
    #[error("proposal digest does not match its immutable contents")]
    ProposalTampered,
    #[error("evidence digest does not match its immutable contents")]
    EvidenceTampered,
    #[error("evidence replay was rejected")]
    ReplayDetected,
    #[error("cursor loop detected")]
    CursorLoop,
    #[error("pagination mutation restart limit was exceeded")]
    PaginationMutationRestartExceeded,
    #[error("pagination exceeded its bounded page limit")]
    PageLimitExceeded,
    #[error("transaction count exceeded its configured bound")]
    TransactionCountExceeded,
    #[error("account filter exceeded its configured bound")]
    AccountFilterLimitExceeded,
    #[error("response exceeded its configured byte bound")]
    ResponseTooLarge,
    #[error("provider response is malformed or partial: {0}")]
    MalformedResponse(&'static str),
    #[error("provider response contains a forbidden field: {0}")]
    ForbiddenData(&'static str),
    #[error("Plaid access was lost (HTTP {status})")]
    AccessLost { status: u16 },
    #[error("Plaid returned a conflict (HTTP {status})")]
    Conflict { status: u16 },
    #[error("Plaid rate limited the read (HTTP {status})")]
    RateLimited { status: u16 },
    #[error("Plaid provider is unavailable (HTTP {status})")]
    ProviderUnavailable { status: u16 },
    #[error("Plaid provider returned an unsupported HTTP status: {0}")]
    UnsupportedHttpStatus(u16),
    #[error("provider transport timed out")]
    Timeout,
    #[error("provider transport is unavailable")]
    TransportUnavailable,
    #[error("provider credential resolution is unavailable")]
    CredentialUnavailable,
    #[error("provider returned no usable transaction update")]
    EmptySync,
    #[error("provider returned a partial transaction update")]
    PartialSync,
    #[error("provider transaction update is not ready")]
    NotReady,
    #[error("provider transaction update state is unknown")]
    ProviderUnknown,
    #[error("sync result state {status:?} is not strict-read eligible")]
    NonAdoptableState { status: EvidenceStatus },
    #[error("BLOCKED_ENV: {0}")]
    BlockedEnvironment(&'static str),
    #[error("native Plaid execution is a Layer-2 gap")]
    NativeExecutionUnavailable,
}

/// SHA-256 digest used to fence externally meaningful values.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn sha256(bytes: impl AsRef<[u8]>) -> Self {
        digest_bytes(bytes.as_ref())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_sha256(&self) -> bool {
        self.0.len() == 64 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    pub(crate) fn from_hex(bytes: impl AsRef<[u8]>) -> Self {
        Self(crate::hex_encode(bytes))
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    AccessToken,
    ClientCredentials,
}

/// Opaque host-owned secret binding.
///
/// The input handle is hashed at construction and is never retained,
/// serialized, or displayed. Native credential resolution is a Layer-2 seam.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    kind: SecretKind,
    revision: u64,
}

impl SecretReference {
    pub fn new(
        opaque_reference: impl AsRef<str>,
        revision: u64,
    ) -> Result<Self, PlaidTransactionResultError> {
        Self::with_kind(opaque_reference, SecretKind::AccessToken, revision)
    }

    pub fn with_kind(
        opaque_reference: impl AsRef<str>,
        kind: SecretKind,
        revision: u64,
    ) -> Result<Self, PlaidTransactionResultError> {
        let opaque_reference = opaque_reference.as_ref();
        if opaque_reference.trim().is_empty()
            || opaque_reference.len() > MAX_REFERENCE_BYTES
            || opaque_reference.chars().any(char::is_control)
        {
            return Err(PlaidTransactionResultError::InvalidField {
                field: "opaque_secret_reference",
                reason: "must be a bounded non-empty host handle",
            });
        }
        if revision == 0 {
            return Err(PlaidTransactionResultError::InvalidField {
                field: "secret_reference_revision",
                reason: "must be non-zero",
            });
        }
        let mut material = b"hartevo:plaid-transactions-secret-reference:v1:".to_vec();
        material.extend_from_slice(opaque_reference.as_bytes());
        material.extend_from_slice(&revision.to_be_bytes());
        material.push(match kind {
            SecretKind::AccessToken => 0,
            SecretKind::ClientCredentials => 1,
        });
        Ok(Self {
            reference_digest: digest_bytes(&material),
            kind,
            revision,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("kind", &self.kind)
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaidProduct {
    Transactions,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaidPermission {
    TransactionsRead,
}

/// Products permission plus a redacted host credential reference.
#[derive(Clone, Eq, PartialEq)]
pub struct PermissionScope {
    product: PlaidProduct,
    permission: PlaidPermission,
    secret_reference: SecretReference,
}

impl PermissionScope {
    pub fn new(
        product: PlaidProduct,
        permission: PlaidPermission,
        secret_reference: SecretReference,
    ) -> Result<Self, PlaidTransactionResultError> {
        if product != PlaidProduct::Transactions || permission != PlaidPermission::TransactionsRead
        {
            return Err(PlaidTransactionResultError::PermissionDrift);
        }
        Ok(Self {
            product,
            permission,
            secret_reference,
        })
    }

    pub const fn product(&self) -> PlaidProduct {
        self.product
    }

    pub const fn permission(&self) -> PlaidPermission {
        self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&(
            self.product,
            self.permission,
            self.secret_reference.reference_digest(),
            self.secret_reference.revision(),
        ))
    }
}

impl Serialize for PermissionScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PermissionScope", 4)?;
        state.serialize_field("product", &self.product)?;
        state.serialize_field("permission", &self.permission)?;
        state.serialize_field(
            "secretReferenceDigest",
            self.secret_reference.reference_digest(),
        )?;
        state.serialize_field("secretReferenceRevision", &self.secret_reference.revision())?;
        state.end()
    }
}

impl fmt::Debug for PermissionScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PermissionScope")
            .field("product", &self.product)
            .field("permission", &self.permission)
            .field("secret_reference", &self.secret_reference)
            .field("permission_digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaidEnvironment {
    Development,
    Sandbox,
    Production,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    id: String,
    revision: u64,
}

impl ProjectScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, PlaidTransactionResultError> {
        Ok(Self {
            id: bounded_identifier("project_id", id.into())?,
            revision: non_zero_revision("project_revision", revision)?,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    id: String,
    revision: u64,
}

impl MissionScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, PlaidTransactionResultError> {
        Ok(Self {
            id: bounded_identifier("mission_id", id.into())?,
            revision: non_zero_revision("mission_revision", revision)?,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductScope {
    id: String,
    revision: u64,
}

impl WorkProductScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, PlaidTransactionResultError> {
        Ok(Self {
            id: bounded_identifier("work_product_id", id.into())?,
            revision: non_zero_revision("work_product_revision", revision)?,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ItemScope {
    id_digest: Digest,
    revision: u64,
}

impl ItemScope {
    pub fn new(
        opaque_item_id: impl AsRef<str>,
        revision: u64,
    ) -> Result<Self, PlaidTransactionResultError> {
        let opaque_item_id = bounded_opaque_identifier("item_id", opaque_item_id.as_ref())?;
        Ok(Self {
            id_digest: opaque_digest("item", opaque_item_id),
            revision: non_zero_revision("item_revision", revision)?,
        })
    }

    pub fn from_digest(
        id_digest: Digest,
        revision: u64,
    ) -> Result<Self, PlaidTransactionResultError> {
        if !id_digest.is_sha256() {
            return Err(PlaidTransactionResultError::InvalidField {
                field: "item_id_digest",
                reason: "must be a SHA-256 digest",
            });
        }
        Ok(Self {
            id_digest,
            revision: non_zero_revision("item_revision", revision)?,
        })
    }

    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

impl Serialize for ItemScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ItemScope", 2)?;
        state.serialize_field("idDigest", &self.id_digest)?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

impl fmt::Debug for ItemScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ItemScope")
            .field("id_digest", &self.id_digest)
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AccountScope {
    id_digest: Digest,
    revision: u64,
}

impl AccountScope {
    pub fn new(
        opaque_account_id: impl AsRef<str>,
        revision: u64,
    ) -> Result<Self, PlaidTransactionResultError> {
        let opaque_account_id =
            bounded_opaque_identifier("account_id", opaque_account_id.as_ref())?;
        Ok(Self {
            id_digest: opaque_digest("account-id", opaque_account_id),
            revision: non_zero_revision("account_revision", revision)?,
        })
    }

    pub fn from_digest(
        id_digest: Digest,
        revision: u64,
    ) -> Result<Self, PlaidTransactionResultError> {
        if !id_digest.is_sha256() {
            return Err(PlaidTransactionResultError::InvalidField {
                field: "account_id_digest",
                reason: "must be a SHA-256 digest",
            });
        }
        Ok(Self {
            id_digest,
            revision: non_zero_revision("account_revision", revision)?,
        })
    }

    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

impl Serialize for AccountScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AccountScope", 2)?;
        state.serialize_field("idDigest", &self.id_digest)?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

impl fmt::Debug for AccountScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountScope")
            .field("id_digest", &self.id_digest)
            .field("revision", &self.revision)
            .finish()
    }
}

/// An ephemeral Plaid cursor. Only its digest can cross a serialization or
/// evidence boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct Cursor {
    raw: String,
    digest: Digest,
}

impl Cursor {
    pub fn new(raw: impl Into<String>) -> Result<Self, PlaidTransactionResultError> {
        let raw = raw.into();
        if raw.len() > MAX_CURSOR_BYTES || raw.chars().any(char::is_control) {
            return Err(PlaidTransactionResultError::InvalidField {
                field: "cursor",
                reason: "must be a bounded cursor without control characters",
            });
        }
        let digest = if raw.is_empty() {
            Digest::sha256(b"hartevo:plaid-transactions:initial-cursor:v1")
        } else {
            opaque_digest("cursor", &raw)
        };
        Ok(Self { raw, digest })
    }

    pub fn initial() -> Self {
        Self::new("").expect("empty cursor is valid")
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn is_initial(&self) -> bool {
        self.raw.is_empty()
    }
}

#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("digest", &self.digest)
            .field("initial", &self.is_initial())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CursorScope {
    cursor: Cursor,
    revision: u64,
}

impl CursorScope {
    pub fn new(cursor: Cursor, revision: u64) -> Result<Self, PlaidTransactionResultError> {
        Ok(Self {
            cursor,
            revision: non_zero_revision("cursor_revision", revision)?,
        })
    }

    pub fn initial(revision: u64) -> Result<Self, PlaidTransactionResultError> {
        Self::new(Cursor::initial(), revision)
    }

    pub fn cursor(&self) -> &Cursor {
        &self.cursor
    }

    pub fn cursor_digest(&self) -> &Digest {
        self.cursor.digest()
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&(self.cursor.digest(), self.revision))
    }
}

impl Serialize for CursorScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CursorScope", 2)?;
        state.serialize_field("cursorDigest", self.cursor.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

impl fmt::Debug for CursorScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CursorScope")
            .field("cursor_digest", self.cursor.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateWindow {
    since_unix_seconds: u64,
    until_unix_seconds: u64,
    revision: u64,
}

impl UpdateWindow {
    pub fn new(
        since_unix_seconds: u64,
        until_unix_seconds: u64,
        revision: u64,
    ) -> Result<Self, PlaidTransactionResultError> {
        if until_unix_seconds < since_unix_seconds
            || until_unix_seconds - since_unix_seconds > MAX_UPDATE_WINDOW_SECONDS
        {
            return Err(PlaidTransactionResultError::InvalidField {
                field: "update_window",
                reason: "must be ordered and within the bounded retention window",
            });
        }
        Ok(Self {
            since_unix_seconds,
            until_unix_seconds,
            revision: non_zero_revision("update_window_revision", revision)?,
        })
    }

    pub const fn since_unix_seconds(&self) -> u64 {
        self.since_unix_seconds
    }

    pub const fn until_unix_seconds(&self) -> u64 {
        self.until_unix_seconds
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransactionRevision {
    number: u64,
    high_water_digest: Digest,
}

impl TransactionRevision {
    pub fn new(
        number: u64,
        high_water_digest: Digest,
    ) -> Result<Self, PlaidTransactionResultError> {
        if !high_water_digest.is_sha256() {
            return Err(PlaidTransactionResultError::InvalidField {
                field: "transaction_revision_high_water_digest",
                reason: "must be a SHA-256 digest",
            });
        }
        Ok(Self {
            number: non_zero_revision("transaction_revision", number)?,
            high_water_digest,
        })
    }

    pub const fn number(&self) -> u64 {
        self.number
    }

    pub fn high_water_digest(&self) -> &Digest {
        &self.high_water_digest
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AccountFilter {
    All,
    Only(Vec<Digest>),
}

impl AccountFilter {
    pub fn only<I>(digests: I) -> Result<Self, PlaidTransactionResultError>
    where
        I: IntoIterator<Item = Digest>,
    {
        let mut unique = BTreeSet::new();
        for digest in digests {
            if !digest.is_sha256() {
                return Err(PlaidTransactionResultError::InvalidField {
                    field: "account_filter_digest",
                    reason: "must be a SHA-256 digest",
                });
            }
            unique.insert(digest);
        }
        if unique.is_empty() {
            return Err(PlaidTransactionResultError::InvalidField {
                field: "account_filter",
                reason: "must contain at least one account digest",
            });
        }
        if unique.len() > MAX_ACCOUNT_FILTERS {
            return Err(PlaidTransactionResultError::AccountFilterLimitExceeded);
        }
        Ok(Self::Only(unique.into_iter().collect()))
    }

    pub fn only_accounts<I>(accounts: I) -> Result<Self, PlaidTransactionResultError>
    where
        I: IntoIterator<Item = AccountScope>,
    {
        Self::only(
            accounts
                .into_iter()
                .map(|account| account.id_digest().clone()),
        )
    }

    pub fn contains(&self, account_digest: &Digest) -> bool {
        match self {
            Self::All => true,
            Self::Only(digests) => digests.binary_search(account_digest).is_ok(),
        }
    }

    pub fn count(&self) -> Option<usize> {
        match self {
            Self::All => None,
            Self::Only(digests) => Some(digests.len()),
        }
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PlaidTransactionsScope {
    environment: PlaidEnvironment,
    item: ItemScope,
    account_filter: AccountFilter,
    cursor: CursorScope,
    update_window: UpdateWindow,
    transaction_revision: TransactionRevision,
    project: ProjectScope,
    mission: MissionScope,
    work_product: WorkProductScope,
    permission: PermissionScope,
    api_version: String,
}

impl PlaidTransactionsScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        environment: PlaidEnvironment,
        item: ItemScope,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        permission: PermissionScope,
    ) -> Result<Self, PlaidTransactionResultError> {
        let scope = Self {
            environment,
            item,
            account_filter: AccountFilter::All,
            cursor: CursorScope::initial(1)?,
            update_window: UpdateWindow::new(0, 0, 1)?,
            transaction_revision: TransactionRevision::new(1, Digest::sha256(b"initial"))?,
            project,
            mission,
            work_product,
            permission,
            api_version: DEFAULT_PLAID_API_VERSION.to_owned(),
        };
        scope.validate()?;
        Ok(scope)
    }

    #[must_use]
    pub fn with_account_filter(mut self, account_filter: AccountFilter) -> Self {
        self.account_filter = account_filter;
        self
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: CursorScope) -> Self {
        self.cursor = cursor;
        self
    }

    #[must_use]
    pub fn with_update_window(mut self, update_window: UpdateWindow) -> Self {
        self.update_window = update_window;
        self
    }

    #[must_use]
    pub fn with_transaction_revision(mut self, transaction_revision: TransactionRevision) -> Self {
        self.transaction_revision = transaction_revision;
        self
    }

    pub fn validate(&self) -> Result<(), PlaidTransactionResultError> {
        if self.api_version != DEFAULT_PLAID_API_VERSION {
            return Err(PlaidTransactionResultError::ProviderApiVersionDrift);
        }
        if self.permission.product() != PlaidProduct::Transactions
            || self.permission.permission() != PlaidPermission::TransactionsRead
        {
            return Err(PlaidTransactionResultError::PermissionDrift);
        }
        if matches!(self.account_filter, AccountFilter::Only(ref values) if values.len() > MAX_ACCOUNT_FILTERS)
        {
            return Err(PlaidTransactionResultError::AccountFilterLimitExceeded);
        }
        Ok(())
    }

    pub const fn environment(&self) -> PlaidEnvironment {
        self.environment
    }

    pub fn item(&self) -> &ItemScope {
        &self.item
    }

    pub fn account_filter(&self) -> &AccountFilter {
        &self.account_filter
    }

    pub fn cursor(&self) -> &CursorScope {
        &self.cursor
    }

    pub fn update_window(&self) -> &UpdateWindow {
        &self.update_window
    }

    pub fn transaction_revision(&self) -> &TransactionRevision {
        &self.transaction_revision
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    pub fn permission(&self) -> &PermissionScope {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        self.permission.secret_reference()
    }

    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    pub fn provider_id(&self) -> &'static str {
        PLAID_TRANSACTION_RESULT_PROVIDER_ID
    }

    pub fn provider_digest(&self) -> Digest {
        digest_serializable(&(self.provider_id(), &self.api_version))
    }

    pub fn contract_digest(&self) -> Digest {
        Digest::sha256(crate::PLAID_TRANSACTION_RESULT_CONTRACT_JSON.as_bytes())
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission.digest()
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&ScopeDigestMaterial {
            environment: self.environment,
            item: &self.item,
            account_filter: &self.account_filter,
            cursor: &self.cursor,
            update_window: &self.update_window,
            transaction_revision: &self.transaction_revision,
            project: &self.project,
            mission: &self.mission,
            work_product: &self.work_product,
            permission_digest: self.permission.digest(),
            api_version: &self.api_version,
        })
    }
}

impl Serialize for PlaidTransactionsScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PlaidTransactionsScope", 11)?;
        state.serialize_field("environment", &self.environment)?;
        state.serialize_field("item", &self.item)?;
        state.serialize_field("accountFilter", &self.account_filter)?;
        state.serialize_field("cursor", &self.cursor)?;
        state.serialize_field("updateWindow", &self.update_window)?;
        state.serialize_field("transactionRevision", &self.transaction_revision)?;
        state.serialize_field("project", &self.project)?;
        state.serialize_field("mission", &self.mission)?;
        state.serialize_field("workProduct", &self.work_product)?;
        state.serialize_field("permission", &self.permission)?;
        state.serialize_field("apiVersion", &self.api_version)?;
        state.end()
    }
}

impl fmt::Debug for PlaidTransactionsScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlaidTransactionsScope")
            .field("environment", &self.environment)
            .field("item", &self.item)
            .field("account_filter", &self.account_filter)
            .field("cursor", &self.cursor)
            .field("update_window", &self.update_window)
            .field("transaction_revision", &self.transaction_revision)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .field("permission", &self.permission)
            .field("api_version", &self.api_version)
            .field("scope_digest", &self.digest())
            .finish()
    }
}

#[derive(Serialize)]
struct ScopeDigestMaterial<'a> {
    environment: PlaidEnvironment,
    item: &'a ItemScope,
    account_filter: &'a AccountFilter,
    cursor: &'a CursorScope,
    update_window: &'a UpdateWindow,
    transaction_revision: &'a TransactionRevision,
    project: &'a ProjectScope,
    mission: &'a MissionScope,
    work_product: &'a WorkProductScope,
    permission_digest: Digest,
    api_version: &'a str,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TransactionSyncRequest {
    cursor: Cursor,
    count: usize,
    max_pages: usize,
    max_transactions: usize,
    account_filter: AccountFilter,
    update_window: UpdateWindow,
    transaction_revision: TransactionRevision,
    scope_digest: Digest,
}

impl TransactionSyncRequest {
    pub fn new(
        scope: &PlaidTransactionsScope,
        count: usize,
        max_pages: usize,
        max_transactions: usize,
    ) -> Result<Self, PlaidTransactionResultError> {
        if !(1..=MAX_TRANSACTION_COUNT).contains(&count) {
            return Err(PlaidTransactionResultError::InvalidField {
                field: "count",
                reason: "must be between 1 and 500",
            });
        }
        if !(1..=MAX_PAGE_COUNT).contains(&max_pages) {
            return Err(PlaidTransactionResultError::InvalidField {
                field: "max_pages",
                reason: "must be between 1 and 64",
            });
        }
        if !(1..=MAX_TRANSACTION_COUNT).contains(&max_transactions) {
            return Err(PlaidTransactionResultError::InvalidField {
                field: "max_transactions",
                reason: "must be between 1 and 500",
            });
        }
        scope.validate()?;
        Ok(Self {
            cursor: scope.cursor.cursor.clone(),
            count,
            max_pages,
            max_transactions,
            account_filter: scope.account_filter.clone(),
            update_window: scope.update_window.clone(),
            transaction_revision: scope.transaction_revision.clone(),
            scope_digest: scope.digest(),
        })
    }

    pub fn from_scope(
        scope: &PlaidTransactionsScope,
        count: usize,
    ) -> Result<Self, PlaidTransactionResultError> {
        Self::new(scope, count, MAX_PAGE_COUNT, MAX_TRANSACTION_COUNT)
    }

    pub fn with_account_filter(
        mut self,
        account_filter: AccountFilter,
    ) -> Result<Self, PlaidTransactionResultError> {
        if let AccountFilter::Only(ref values) = account_filter
            && values.len() > MAX_ACCOUNT_FILTERS
        {
            return Err(PlaidTransactionResultError::AccountFilterLimitExceeded);
        }
        self.account_filter = account_filter;
        Ok(self)
    }

    pub fn validate_against(
        &self,
        scope: &PlaidTransactionsScope,
    ) -> Result<(), PlaidTransactionResultError> {
        scope.validate()?;
        if self.scope_digest != scope.digest() {
            return Err(PlaidTransactionResultError::ScopeMismatch(
                "request is bound to a different scope",
            ));
        }
        if self.update_window != scope.update_window
            || self.transaction_revision != scope.transaction_revision
        {
            return Err(PlaidTransactionResultError::ScopeMismatch(
                "request update window or transaction revision drifted",
            ));
        }
        Ok(())
    }

    pub fn cursor(&self) -> &Cursor {
        &self.cursor
    }

    pub fn cursor_digest(&self) -> &Digest {
        self.cursor.digest()
    }

    pub const fn count(&self) -> usize {
        self.count
    }

    pub const fn max_pages(&self) -> usize {
        self.max_pages
    }

    pub const fn max_transactions(&self) -> usize {
        self.max_transactions
    }

    pub fn account_filter(&self) -> &AccountFilter {
        &self.account_filter
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&RequestDigestMaterial {
            cursor_digest: self.cursor.digest().clone(),
            count: self.count,
            max_pages: self.max_pages,
            max_transactions: self.max_transactions,
            account_filter: &self.account_filter,
            update_window: &self.update_window,
            transaction_revision: &self.transaction_revision,
            scope_digest: &self.scope_digest,
        })
    }

    pub(crate) fn with_provider_cursor(&self, cursor: Cursor) -> Self {
        Self {
            cursor,
            count: self.count,
            max_pages: self.max_pages,
            max_transactions: self.max_transactions,
            account_filter: self.account_filter.clone(),
            update_window: self.update_window.clone(),
            transaction_revision: self.transaction_revision.clone(),
            scope_digest: self.scope_digest.clone(),
        }
    }
}

impl fmt::Debug for TransactionSyncRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionSyncRequest")
            .field("cursor_digest", self.cursor.digest())
            .field("count", &self.count)
            .field("max_pages", &self.max_pages)
            .field("max_transactions", &self.max_transactions)
            .field("account_filter", &self.account_filter)
            .field("update_window", &self.update_window)
            .field("transaction_revision", &self.transaction_revision)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

#[derive(Serialize)]
struct RequestDigestMaterial<'a> {
    cursor_digest: Digest,
    count: usize,
    max_pages: usize,
    max_transactions: usize,
    account_filter: &'a AccountFilter,
    update_window: &'a UpdateWindow,
    transaction_revision: &'a TransactionRevision,
    scope_digest: &'a Digest,
}

pub type PlaidSyncRequest = TransactionSyncRequest;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementState {
    Pending,
    Posted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Pending,
    Posted,
    Modified,
    Removed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmountBucket {
    Zero,
    UnderTen,
    UnderHundred,
    UnderThousand,
    UnderTenThousand,
    TenThousandOrMore,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CurrencyCode(String);

impl CurrencyCode {
    pub fn new(value: impl Into<String>) -> Result<Self, PlaidTransactionResultError> {
        let value = value.into().to_ascii_uppercase();
        if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(PlaidTransactionResultError::InvalidField {
                field: "iso_currency_code",
                reason: "must be a three-letter currency code",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BoundedTimestamp(String);

impl BoundedTimestamp {
    pub fn new(value: impl Into<String>) -> Result<Self, PlaidTransactionResultError> {
        let value = value.into();
        if value.trim().is_empty()
            || value.len() > MAX_DATE_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(PlaidTransactionResultError::InvalidField {
                field: "transaction_timestamp",
                reason: "must be a bounded timestamp",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransactionSummary {
    pub transaction_id_digest: Digest,
    pub account_id_digest: Option<Digest>,
    pub state: TransactionState,
    pub settlement_state: Option<SettlementState>,
    pub amount_bucket: AmountBucket,
    pub amount_digest: Option<Digest>,
    pub currency: Option<CurrencyCode>,
    pub transaction_date: Option<BoundedTimestamp>,
    pub authorized_date: Option<BoundedTimestamp>,
    pub category_digest: Option<Digest>,
    pub entity_digest: Option<Digest>,
    pub pending_posted_linkage_digest: Option<Digest>,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionsUpdateStatus {
    Complete,
    InProgress,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Ready,
    NotReady,
    Partial,
    Stale,
    AccessLost,
    Empty,
    BlockedEnv,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDisposition {
    Proposal,
    NotReady,
    Partial,
    Stale,
    AccessLost,
    Empty,
    BlockedEnv,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct EvidenceAuthority {
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub durable_provider_receipt: bool,
    pub independent_read_back: bool,
    pub financial_advice: bool,
    pub kernel_authority: bool,
}

impl EvidenceAuthority {
    pub const fn non_native() -> Self {
        Self {
            connected: false,
            native: false,
            external_writes: false,
            durable_provider_receipt: false,
            independent_read_back: false,
            financial_advice: false,
            kernel_authority: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct RedactionMetadata {
    pub raw_payload_retained: bool,
    pub raw_secret_retained: bool,
    pub raw_cursor_retained: bool,
    pub raw_account_data_retained: bool,
    pub raw_merchant_data_retained: bool,
    pub raw_geolocation_retained: bool,
    pub allowlist_version: String,
}

impl Default for RedactionMetadata {
    fn default() -> Self {
        Self {
            raw_payload_retained: false,
            raw_secret_retained: false,
            raw_cursor_retained: false,
            raw_account_data_retained: false,
            raw_merchant_data_retained: false,
            raw_geolocation_retained: false,
            allowlist_version: "plaid-transaction-result-redaction/v1".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretState {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    UserRequested,
    ScopeChanged,
    SecretRotated,
    TamperDetected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Revocation {
    pub revision: u64,
    pub reason: RevocationReason,
    pub digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginRegistration {
    schema_version: String,
    contract_version: String,
    plugin_version: String,
    provider_id: String,
    api_version: String,
    contract_digest: Digest,
    provider_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    registration_digest: Digest,
    state: RegistrationState,
    secret_state: SecretState,
    revocation: Option<Revocation>,
}

impl PluginRegistration {
    pub fn new(scope: &PlaidTransactionsScope) -> Result<Self, PlaidTransactionResultError> {
        scope.validate()?;
        let contract_digest = scope.contract_digest();
        let provider_digest = scope.provider_digest();
        let permission_digest = scope.permission_digest();
        let scope_digest = scope.digest();
        let registration_digest = digest_serializable(&RegistrationMaterial {
            schema_version: PLAID_TRANSACTION_RESULT_SCHEMA_VERSION,
            contract_version: PLAID_TRANSACTION_RESULT_CONTRACT_VERSION,
            plugin_version: PLAID_TRANSACTION_RESULT_PLUGIN_VERSION,
            provider_id: PLAID_TRANSACTION_RESULT_PROVIDER_ID,
            api_version: scope.api_version(),
            contract_digest: &contract_digest,
            provider_digest: &provider_digest,
            permission_digest: &permission_digest,
            scope_digest: &scope_digest,
        });
        Ok(Self {
            schema_version: PLAID_TRANSACTION_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: PLAID_TRANSACTION_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: PLAID_TRANSACTION_RESULT_PLUGIN_VERSION.to_owned(),
            provider_id: PLAID_TRANSACTION_RESULT_PROVIDER_ID.to_owned(),
            api_version: scope.api_version().to_owned(),
            contract_digest,
            provider_digest,
            permission_digest,
            scope_digest,
            registration_digest,
            state: RegistrationState::Active,
            secret_state: SecretState::Active,
            revocation: None,
        })
    }

    pub fn validate_against(
        &self,
        scope: &PlaidTransactionsScope,
    ) -> Result<(), PlaidTransactionResultError> {
        if self.state != RegistrationState::Active {
            return Err(PlaidTransactionResultError::RegistrationRevoked);
        }
        if self.secret_state != SecretState::Active {
            return Err(PlaidTransactionResultError::SecretRevoked);
        }
        let expected = Self::new(scope)?;
        if self.schema_version != expected.schema_version
            || self.contract_version != expected.contract_version
            || self.plugin_version != expected.plugin_version
            || self.provider_id != expected.provider_id
            || self.api_version != expected.api_version
            || self.contract_digest != expected.contract_digest
            || self.provider_digest != expected.provider_digest
            || self.permission_digest != expected.permission_digest
            || self.scope_digest != expected.scope_digest
            || self.registration_digest != expected.registration_digest
        {
            return Err(PlaidTransactionResultError::RegistrationTampered);
        }
        Ok(())
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn state(&self) -> RegistrationState {
        self.state
    }

    pub fn secret_state(&self) -> SecretState {
        self.secret_state
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active && self.secret_state == SecretState::Active
    }

    pub fn revoke(
        &mut self,
        revision: u64,
        reason: RevocationReason,
    ) -> Result<Revocation, PlaidTransactionResultError> {
        let revision = non_zero_revision("revocation_revision", revision)?;
        if self.state == RegistrationState::Revoked {
            return Err(PlaidTransactionResultError::RegistrationRevoked);
        }
        let revocation = Revocation {
            revision,
            reason,
            digest: digest_serializable(&(self.registration_digest(), revision, reason)),
        };
        self.state = RegistrationState::Revoked;
        self.revocation = Some(revocation.clone());
        Ok(revocation)
    }

    pub fn revoke_secret(
        &mut self,
        revision: u64,
        reason: RevocationReason,
    ) -> Result<Revocation, PlaidTransactionResultError> {
        let revision = non_zero_revision("secret_revocation_revision", revision)?;
        if self.secret_state == SecretState::Revoked {
            return Err(PlaidTransactionResultError::SecretRevoked);
        }
        let revocation = Revocation {
            revision,
            reason,
            digest: digest_serializable(&(self.registration_digest(), revision, reason, "secret")),
        };
        self.secret_state = SecretState::Revoked;
        self.revocation = Some(revocation.clone());
        Ok(revocation)
    }

    pub fn restore(&mut self) -> Result<(), PlaidTransactionResultError> {
        if self.state == RegistrationState::Active && self.secret_state == SecretState::Active {
            return Ok(());
        }
        self.state = RegistrationState::Active;
        self.secret_state = SecretState::Active;
        self.revocation = None;
        Ok(())
    }
}

#[derive(Serialize)]
struct RegistrationMaterial<'a> {
    schema_version: &'static str,
    contract_version: &'static str,
    plugin_version: &'static str,
    provider_id: &'static str,
    api_version: &'a str,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlaidTransactionResultProposal {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub provider_id: String,
    pub api_version: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
    pub cursor_digest: Digest,
    pub count: usize,
    pub max_pages: usize,
    pub max_transactions: usize,
    pub non_mutating: bool,
    pub proposal_digest: Digest,
}

impl PlaidTransactionResultProposal {
    pub(crate) fn new(
        scope: &PlaidTransactionsScope,
        registration: &PluginRegistration,
        request: &TransactionSyncRequest,
    ) -> Self {
        let mut proposal = Self {
            schema_version: PLAID_TRANSACTION_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: PLAID_TRANSACTION_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: PLAID_TRANSACTION_RESULT_PLUGIN_VERSION.to_owned(),
            provider_id: PLAID_TRANSACTION_RESULT_PROVIDER_ID.to_owned(),
            api_version: scope.api_version().to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest(),
            request_digest: request.digest(),
            cursor_digest: request.cursor_digest().clone(),
            count: request.count(),
            max_pages: request.max_pages(),
            max_transactions: request.max_transactions(),
            non_mutating: true,
            proposal_digest: Digest::sha256(b"uninitialized-plaid-proposal"),
        };
        proposal.proposal_digest = digest_serializable(&ProposalDigestMaterial {
            schema_version: &proposal.schema_version,
            contract_version: &proposal.contract_version,
            plugin_version: &proposal.plugin_version,
            provider_id: &proposal.provider_id,
            api_version: &proposal.api_version,
            registration_digest: &proposal.registration_digest,
            scope_digest: &proposal.scope_digest,
            permission_digest: &proposal.permission_digest,
            request_digest: &proposal.request_digest,
            cursor_digest: &proposal.cursor_digest,
            count: proposal.count,
            max_pages: proposal.max_pages,
            max_transactions: proposal.max_transactions,
            non_mutating: proposal.non_mutating,
        });
        proposal
    }

    pub fn verify_integrity(&self) -> Result<(), PlaidTransactionResultError> {
        let expected = digest_serializable(&ProposalDigestMaterial {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            plugin_version: &self.plugin_version,
            provider_id: &self.provider_id,
            api_version: &self.api_version,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            request_digest: &self.request_digest,
            cursor_digest: &self.cursor_digest,
            count: self.count,
            max_pages: self.max_pages,
            max_transactions: self.max_transactions,
            non_mutating: self.non_mutating,
        });
        if self.proposal_digest != expected {
            return Err(PlaidTransactionResultError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ProposalDigestMaterial<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    plugin_version: &'a str,
    provider_id: &'a str,
    api_version: &'a str,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    request_digest: &'a Digest,
    cursor_digest: &'a Digest,
    count: usize,
    max_pages: usize,
    max_transactions: usize,
    non_mutating: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlaidTransactionResultEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub api_version: String,
    pub registration_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub proposal_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub failure_digest: Option<Digest>,
    pub cursor_before_digest: Digest,
    pub cursor_after_digest: Digest,
    pub high_water_digest: Digest,
    pub transaction_revision: TransactionRevision,
    pub update_window: UpdateWindow,
    pub status: EvidenceStatus,
    pub update_status: TransactionsUpdateStatus,
    pub provenance: EvidenceProvenance,
    pub disposition: EvidenceDisposition,
    pub page_count: usize,
    pub restart_count: usize,
    pub transaction_count: usize,
    pub added_count: usize,
    pub modified_count: usize,
    pub removed_count: usize,
    pub has_more: bool,
    pub request_id_digests: Vec<Digest>,
    pub transactions: Vec<TransactionSummary>,
    pub authority: EvidenceAuthority,
    pub redaction: RedactionMetadata,
    pub evidence_digest: Digest,
}

impl PlaidTransactionResultEvidence {
    pub(crate) fn calculate_digest(&self) -> Digest {
        digest_serializable(&EvidenceDigestMaterial {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            plugin_version: &self.plugin_version,
            service_id: &self.service_id,
            provider_id: &self.provider_id,
            api_version: &self.api_version,
            registration_digest: &self.registration_digest,
            contract_digest: &self.contract_digest,
            provider_digest: &self.provider_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            proposal_digest: &self.proposal_digest,
            request_digest: &self.request_digest,
            response_digest: &self.response_digest,
            failure_digest: &self.failure_digest,
            cursor_before_digest: &self.cursor_before_digest,
            cursor_after_digest: &self.cursor_after_digest,
            high_water_digest: &self.high_water_digest,
            transaction_revision: &self.transaction_revision,
            update_window: &self.update_window,
            status: self.status,
            update_status: self.update_status,
            provenance: self.provenance,
            disposition: self.disposition,
            page_count: self.page_count,
            restart_count: self.restart_count,
            transaction_count: self.transaction_count,
            added_count: self.added_count,
            modified_count: self.modified_count,
            removed_count: self.removed_count,
            has_more: self.has_more,
            request_id_digests: &self.request_id_digests,
            transactions: &self.transactions,
            authority: &self.authority,
            redaction: &self.redaction,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), PlaidTransactionResultError> {
        if self.evidence_digest != self.calculate_digest() {
            return Err(PlaidTransactionResultError::EvidenceTampered);
        }
        Ok(())
    }

    pub const fn transaction_count(&self) -> usize {
        self.transaction_count
    }

    pub const fn added_count(&self) -> usize {
        self.added_count
    }

    pub const fn modified_count(&self) -> usize {
        self.modified_count
    }

    pub const fn removed_count(&self) -> usize {
        self.removed_count
    }

    pub fn is_adoptable_proposal(&self) -> bool {
        self.status == EvidenceStatus::Ready
            && self.disposition == EvidenceDisposition::Proposal
            && !self.authority.connected
            && !self.authority.native
            && !self.authority.kernel_authority
    }
}

#[derive(Serialize)]
struct EvidenceDigestMaterial<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    plugin_version: &'a str,
    service_id: &'a str,
    provider_id: &'a str,
    api_version: &'a str,
    registration_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    proposal_digest: &'a Digest,
    request_digest: &'a Digest,
    response_digest: &'a Digest,
    failure_digest: &'a Option<Digest>,
    cursor_before_digest: &'a Digest,
    cursor_after_digest: &'a Digest,
    high_water_digest: &'a Digest,
    transaction_revision: &'a TransactionRevision,
    update_window: &'a UpdateWindow,
    status: EvidenceStatus,
    update_status: TransactionsUpdateStatus,
    provenance: EvidenceProvenance,
    disposition: EvidenceDisposition,
    page_count: usize,
    restart_count: usize,
    transaction_count: usize,
    added_count: usize,
    modified_count: usize,
    removed_count: usize,
    has_more: bool,
    request_id_digests: &'a [Digest],
    transactions: &'a [TransactionSummary],
    authority: &'a EvidenceAuthority,
    redaction: &'a RedactionMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct PlaidTransactionResultRecord {
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub record_digest: Digest,
    pub provenance: EvidenceProvenance,
    pub local_only: bool,
    pub kernel_receipt: bool,
    pub kernel_verification: bool,
    pub kernel_outcome_adoption: bool,
}

fn bounded_identifier(
    field: &'static str,
    value: String,
) -> Result<String, PlaidTransactionResultError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(PlaidTransactionResultError::InvalidField {
            field,
            reason: "must be a bounded non-empty identifier",
        });
    }
    Ok(value)
}

fn bounded_opaque_identifier<'a>(
    field: &'static str,
    value: &'a str,
) -> Result<&'a str, PlaidTransactionResultError> {
    if value.trim().is_empty()
        || value.len() > MAX_REFERENCE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(PlaidTransactionResultError::InvalidField {
            field,
            reason: "must be a bounded non-empty opaque identifier",
        });
    }
    Ok(value)
}

fn non_zero_revision(
    field: &'static str,
    revision: u64,
) -> Result<u64, PlaidTransactionResultError> {
    if revision == 0 {
        return Err(PlaidTransactionResultError::InvalidField {
            field,
            reason: "must be non-zero",
        });
    }
    Ok(revision)
}

fn opaque_digest(namespace: &str, value: &str) -> Digest {
    let mut material = namespace.as_bytes().to_vec();
    material.extend_from_slice(b":v1:");
    material.extend_from_slice(value.as_bytes());
    digest_bytes(&material)
}
