//! Typed, bounded, and redacted NetSuite accounting-result model.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_DATACENTER_BYTES: usize = 253;
pub(crate) const MAX_RECORD_ID_BYTES: usize = 64;
pub(crate) const MAX_WINDOW_SECONDS: i64 = 31 * 24 * 60 * 60;
pub(crate) const MAX_CONSENT_SECONDS: i64 = 90 * 24 * 60 * 60;
pub(crate) const MAX_PAGES: u16 = 4;
pub(crate) const MAX_PAGE_SIZE: u16 = 50;
pub(crate) const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub(crate) const MAX_RECORDS: u32 = 200;
pub(crate) const MAX_RETRY_ATTEMPTS: u8 = 4;
pub(crate) const MAX_SUITEQL_FIELDS: usize = 12;
pub(crate) const MAX_SUITEQL_PARAMETERS: usize = 8;
pub(crate) const MAX_SUITEQL_BYTES: usize = 16 * 1024;

static REVOCATION_TOMBSTONES: OnceLock<RwLock<BTreeSet<Digest>>> = OnceLock::new();

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("data-center host is malformed")]
    InvalidDataCenter,
    #[error("record identifier is empty, malformed, or too long")]
    InvalidRecordId,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("record type is not in the Layer-1 allowlist")]
    InvalidRecordType,
    #[error("collection filter is not in the Layer-1 allowlist")]
    InvalidFilter,
    #[error("observation window is empty or exceeds the Layer-1 safety ceiling")]
    InvalidObservationWindow,
    #[error("consent scope is empty or exceeds the Layer-1 safety ceiling")]
    InvalidConsentScope,
    #[error("bounds are empty or exceed the Layer-1 safety ceiling")]
    InvalidBounds,
    #[error("SuiteQL proposal is not parameterized or is outside the allowlist")]
    InvalidSuiteQl,
    #[error("scope is incomplete or internally inconsistent")]
    InvalidScope,
    #[error("secret reference is malformed")]
    InvalidSecretReference,
    #[error("secret reference is already revoked")]
    AlreadyRevoked,
    #[error("revocation fence is unavailable")]
    RevocationFenceUnavailable,
    #[error("digest does not match immutable fields")]
    DigestMismatch,
    #[error("duplicate field or operation")]
    DuplicateEntry,
    #[error("serialization failed while computing a digest: {0}")]
    Serialization(String),
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
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

fn revocation_tombstones() -> &'static RwLock<BTreeSet<Digest>> {
    REVOCATION_TOMBSTONES.get_or_init(|| RwLock::new(BTreeSet::new()))
}

fn revocation_key(domain: &str, digest: &Digest) -> Digest {
    Digest::from_fields(domain, &[digest.as_str().to_owned()])
}

pub(crate) fn is_revocation_tombstoned(domain: &str, digest: &Digest) -> bool {
    let key = revocation_key(domain, digest);
    revocation_tombstones()
        .read()
        .map_or(true, |tombstones| tombstones.contains(&key))
}

pub(crate) fn tombstone_revocation(domain: &str, digest: &Digest) -> Result<(), ModelError> {
    let key = revocation_key(domain, digest);
    let mut tombstones = revocation_tombstones()
        .write()
        .map_err(|_| ModelError::RevocationFenceUnavailable)?;
    if tombstones.insert(key) {
        Ok(())
    } else {
        Err(ModelError::AlreadyRevoked)
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn valid_record_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RECORD_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_data_center(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_DATACENTER_BYTES
        || value.contains(['/', ':', '?', '#'])
    {
        return false;
    }
    let labels = value.split('.').collect::<Vec<_>>();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

macro_rules! string_identifier {
    ($name:ident, $validator:ident, $error:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if $validator(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::$error)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }
    };
}

string_identifier!(AccountId, valid_identifier, InvalidIdentifier);
string_identifier!(RoleId, valid_identifier, InvalidIdentifier);
string_identifier!(ProjectId, valid_identifier, InvalidIdentifier);
string_identifier!(MissionId, valid_identifier, InvalidIdentifier);
string_identifier!(WorkProductId, valid_identifier, InvalidIdentifier);

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DataCenter(String);

impl DataCenter {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if valid_data_center(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDataCenter)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DataCenter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("DataCenter").field(&self.0).finish()
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RecordId(String);

impl RecordId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_record_id(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidRecordId)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RecordId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("RecordId").field(&self.0).finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NetSuiteRecordType {
    Account,
    Invoice,
    VendorBill,
    JournalEntry,
    Customer,
    Vendor,
    CustomerPayment,
    CreditMemo,
    Subsidiary,
    Department,
    Class,
    Location,
}

impl NetSuiteRecordType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Invoice => "invoice",
            Self::VendorBill => "vendorBill",
            Self::JournalEntry => "journalEntry",
            Self::Customer => "customer",
            Self::Vendor => "vendor",
            Self::CustomerPayment => "customerPayment",
            Self::CreditMemo => "creditMemo",
            Self::Subsidiary => "subsidiary",
            Self::Department => "department",
            Self::Class => "class",
            Self::Location => "location",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ModelError> {
        match value {
            "account" => Ok(Self::Account),
            "invoice" => Ok(Self::Invoice),
            "vendorBill" => Ok(Self::VendorBill),
            "journalEntry" => Ok(Self::JournalEntry),
            "customer" => Ok(Self::Customer),
            "vendor" => Ok(Self::Vendor),
            "customerPayment" => Ok(Self::CustomerPayment),
            "creditMemo" => Ok(Self::CreditMemo),
            "subsidiary" => Ok(Self::Subsidiary),
            "department" => Ok(Self::Department),
            "class" => Ok(Self::Class),
            "location" => Ok(Self::Location),
            _ => Err(ModelError::InvalidRecordType),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetSuiteReadOperation {
    RecordMetadata,
    RecordCollectionFilter,
    SelectedRecord,
    SuiteQlProposal,
}

impl NetSuiteReadOperation {
    pub const fn is_get(self) -> bool {
        matches!(
            self,
            Self::RecordMetadata | Self::RecordCollectionFilter | Self::SelectedRecord
        )
    }

    pub const fn is_suiteql_proposal(self) -> bool {
        matches!(self, Self::SuiteQlProposal)
    }

    pub const fn contract_name(self) -> &'static str {
        match self {
            Self::RecordMetadata => "read_record_metadata",
            Self::RecordCollectionFilter => "read_record_collection",
            Self::SelectedRecord => "read_selected_record",
            Self::SuiteQlProposal => "compile_parameterized_suiteql_proposal",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetSuiteRecordStatus {
    Pending,
    Open,
    PartiallyPaid,
    Paid,
    Closed,
    Voided,
    Approved,
    Rejected,
    Unknown,
}

impl NetSuiteRecordStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Open => "open",
            Self::PartiallyPaid => "partially_paid",
            Self::Paid => "paid",
            Self::Closed => "closed",
            Self::Voided => "voided",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NetSuiteSafeRecordField {
    InternalId,
    RecordType,
    LastModifiedDate,
    TransactionDate,
    DueDate,
    Status,
    Currency,
    Subsidiary,
    Amount,
    TaxAmount,
}

impl NetSuiteSafeRecordField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InternalId => "internalId",
            Self::RecordType => "recordType",
            Self::LastModifiedDate => "lastModifiedDate",
            Self::TransactionDate => "tranDate",
            Self::DueDate => "dueDate",
            Self::Status => "status",
            Self::Currency => "currency",
            Self::Subsidiary => "subsidiary",
            Self::Amount => "amount",
            Self::TaxAmount => "taxAmount",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CollectionFilterField {
    LastModifiedDate,
    TransactionDate,
    InternalId,
    Status,
}

impl CollectionFilterField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LastModifiedDate => "lastModifiedDate",
            Self::TransactionDate => "tranDate",
            Self::InternalId => "internalId",
            Self::Status => "status",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionFilterOperator {
    OnOrAfter,
    OnOrBefore,
    EqualTo,
}

impl CollectionFilterOperator {
    pub const fn as_suiteql(self) -> &'static str {
        match self {
            Self::OnOrAfter => ">=",
            Self::OnOrBefore => "<=",
            Self::EqualTo => "=",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum CollectionFilterValue {
    Timestamp(DateTime<Utc>),
    RecordId(RecordId),
    Status(NetSuiteRecordStatus),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CollectionFilter {
    field: CollectionFilterField,
    operator: CollectionFilterOperator,
    value: CollectionFilterValue,
    filter_digest: Digest,
}

impl CollectionFilter {
    pub fn new(
        field: CollectionFilterField,
        operator: CollectionFilterOperator,
        value: CollectionFilterValue,
    ) -> Result<Self, ModelError> {
        let valid = matches!(
            (field, operator, &value),
            (
                CollectionFilterField::LastModifiedDate | CollectionFilterField::TransactionDate,
                CollectionFilterOperator::OnOrAfter | CollectionFilterOperator::OnOrBefore,
                CollectionFilterValue::Timestamp(_),
            ) | (
                CollectionFilterField::InternalId,
                CollectionFilterOperator::EqualTo,
                CollectionFilterValue::RecordId(_),
            ) | (
                CollectionFilterField::Status,
                CollectionFilterOperator::EqualTo,
                CollectionFilterValue::Status(_),
            )
        );
        if !valid {
            return Err(ModelError::InvalidFilter);
        }
        let filter_digest = digest_serializable_material(
            "netsuite-collection-filter/v1",
            &[
                format!("{field:?}"),
                format!("{operator:?}"),
                format!("{value:?}"),
            ],
        );
        Ok(Self {
            field,
            operator,
            value,
            filter_digest,
        })
    }

    pub const fn field(&self) -> CollectionFilterField {
        self.field
    }

    pub const fn operator(&self) -> CollectionFilterOperator {
        self.operator
    }

    pub fn value(&self) -> &CollectionFilterValue {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        self.filter_digest.clone()
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = digest_serializable_material(
            "netsuite-collection-filter/v1",
            &[
                format!("{:?}", self.field),
                format!("{:?}", self.operator),
                format!("{:?}", self.value),
            ],
        );
        if self.filter_digest == expected {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn validate_for_window(&self, window: &ObservationWindow) -> Result<(), ModelError> {
        self.validate_digest()?;
        let valid = match &self.value {
            CollectionFilterValue::Timestamp(timestamp) => window.contains(*timestamp),
            CollectionFilterValue::RecordId(_) | CollectionFilterValue::Status(_) => true,
        };
        if valid {
            Ok(())
        } else {
            Err(ModelError::InvalidFilter)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationWindow {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

impl ObservationWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self, ModelError> {
        let seconds = end.signed_duration_since(start).num_seconds();
        if seconds <= 0 || seconds > MAX_WINDOW_SECONDS {
            return Err(ModelError::InvalidObservationWindow);
        }
        Ok(Self { start, end })
    }

    pub fn start(&self) -> DateTime<Utc> {
        self.start
    }

    pub fn end(&self) -> DateTime<Utc> {
        self.end
    }

    pub fn contains(&self, timestamp: DateTime<Utc>) -> bool {
        timestamp >= self.start && timestamp <= self.end
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    operations: BTreeSet<NetSuiteReadOperation>,
    expires_at: DateTime<Utc>,
    consent_digest: Digest,
}

impl ConsentScope {
    pub fn new(
        operations: impl IntoIterator<Item = NetSuiteReadOperation>,
        expires_at: DateTime<Utc>,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        let operations = operations.into_iter().collect::<BTreeSet<_>>();
        if operations.is_empty() {
            return Err(ModelError::InvalidConsentScope);
        }
        let now = Utc::now();
        if expires_at.signed_duration_since(now).num_seconds() > MAX_CONSENT_SECONDS {
            return Err(ModelError::InvalidConsentScope);
        }
        Ok(Self {
            operations,
            expires_at,
            consent_digest,
        })
    }

    pub fn operations(&self) -> &BTreeSet<NetSuiteReadOperation> {
        &self.operations
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn permits(&self, operation: NetSuiteReadOperation, at: DateTime<Utc>) -> bool {
        self.operations.contains(&operation) && at < self.expires_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteBounds {
    max_pages: u16,
    page_size: u16,
    max_records: u32,
    max_response_bytes: usize,
    max_retry_attempts: u8,
}

impl NetSuiteBounds {
    pub fn new(
        max_pages: u16,
        page_size: u16,
        max_records: u32,
        max_response_bytes: usize,
        max_retry_attempts: u8,
    ) -> Result<Self, ModelError> {
        if max_pages == 0
            || max_pages > MAX_PAGES
            || page_size == 0
            || page_size > MAX_PAGE_SIZE
            || max_records == 0
            || max_records > MAX_RECORDS
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
            || max_retry_attempts == 0
            || max_retry_attempts > MAX_RETRY_ATTEMPTS
        {
            return Err(ModelError::InvalidBounds);
        }
        Ok(Self {
            max_pages,
            page_size,
            max_records,
            max_response_bytes,
            max_retry_attempts,
        })
    }

    pub const fn max_pages(&self) -> u16 {
        self.max_pages
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn max_records(&self) -> u32 {
        self.max_records
    }

    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    pub const fn max_retry_attempts(&self) -> u8 {
        self.max_retry_attempts
    }
}

impl Default for NetSuiteBounds {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            page_size: MAX_PAGE_SIZE,
            max_records: MAX_RECORDS,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_retry_attempts: MAX_RETRY_ATTEMPTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NetSuiteAuthKind {
    OAuth2,
    Tba,
}

impl NetSuiteAuthKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OAuth2 => "oauth2",
            Self::Tba => "tba",
        }
    }
}

/// Opaque reference into a host-managed credential store.
///
/// The caller-provided reference is hashed immediately and is never retained,
/// serialized, or printed. Layer 1 carries only its digest, scope fence,
/// credential revision, and whether the reference has been revoked.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: NetSuiteAuthKind,
    revoked: bool,
    revocation: Arc<AtomicBool>,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            auth_kind: self.auth_kind,
            revoked: self.revoked,
            revocation: Arc::clone(&self.revocation),
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.is_revoked())
            .field(
                "revocation_fenced",
                &self.revocation.load(Ordering::Acquire),
            )
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.auth_kind == other.auth_kind
            && self.is_revoked() == other.is_revoked()
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &NetSuiteScope,
        credential_revision: Revision,
        auth_kind: NetSuiteAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidSecretReference);
        }
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_fields(
            "netsuite-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                auth_kind.as_str().to_owned(),
            ],
        );
        if is_revocation_tombstoned("netsuite-secret-reference", &reference_digest) {
            return Err(ModelError::AlreadyRevoked);
        }
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            auth_kind,
            revoked: false,
            revocation: Arc::new(AtomicBool::new(false)),
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

    pub const fn auth_kind(&self) -> NetSuiteAuthKind {
        self.auth_kind
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
            || self.revocation.load(Ordering::Acquire)
            || is_revocation_tombstoned("netsuite-secret-reference", &self.reference_digest)
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.is_revoked() {
            return Err(ModelError::AlreadyRevoked);
        }
        if self
            .revocation
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ModelError::AlreadyRevoked);
        }
        self.revoked = true;
        match tombstone_revocation("netsuite-secret-reference", &self.reference_digest) {
            Ok(()) | Err(ModelError::AlreadyRevoked) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteScope {
    account_id: AccountId,
    data_center: DataCenter,
    role_id: RoleId,
    record_type: NetSuiteRecordType,
    record_id: Option<RecordId>,
    collection_filter: CollectionFilter,
    observation_window: ObservationWindow,
    permission_digest: Digest,
    project_id: ProjectId,
    project_revision: Revision,
    mission_id: MissionId,
    mission_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    consent_scope: ConsentScope,
    scope_digest: Digest,
}

impl NetSuiteScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        data_center: DataCenter,
        role_id: RoleId,
        record_type: NetSuiteRecordType,
        record_id: Option<RecordId>,
        collection_filter: CollectionFilter,
        observation_window: ObservationWindow,
        permission_digest: Digest,
        project_id: ProjectId,
        project_revision: Revision,
        mission_id: MissionId,
        mission_revision: Revision,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
        consent_scope: ConsentScope,
    ) -> Result<Self, ModelError> {
        if consent_scope.operations().is_empty() {
            return Err(ModelError::InvalidScope);
        }
        collection_filter.validate_for_window(&observation_window)?;
        let scope_digest = Digest::from_fields(
            "netsuite-accounting-scope/v1",
            &[
                account_id.as_str().to_owned(),
                data_center.as_str().to_owned(),
                role_id.as_str().to_owned(),
                record_type.as_str().to_owned(),
                record_id
                    .as_ref()
                    .map_or_else(|| "<collection>".to_owned(), |id| id.as_str().to_owned()),
                collection_filter.digest().as_str().to_owned(),
                observation_window.start.to_rfc3339(),
                observation_window.end.to_rfc3339(),
                permission_digest.as_str().to_owned(),
                project_id.as_str().to_owned(),
                project_revision.get().to_string(),
                mission_id.as_str().to_owned(),
                mission_revision.get().to_string(),
                work_product_id.as_str().to_owned(),
                work_product_revision.get().to_string(),
                consent_scope
                    .operations()
                    .iter()
                    .map(|operation| format!("{operation:?}"))
                    .collect::<Vec<_>>()
                    .join(","),
                consent_scope.expires_at().to_rfc3339(),
                consent_scope.digest().as_str().to_owned(),
            ],
        );
        Ok(Self {
            account_id,
            data_center,
            role_id,
            record_type,
            record_id,
            collection_filter,
            observation_window,
            permission_digest,
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
            consent_scope,
            scope_digest,
        })
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn data_center(&self) -> &DataCenter {
        &self.data_center
    }

    pub fn role_id(&self) -> &RoleId {
        &self.role_id
    }

    pub const fn record_type(&self) -> NetSuiteRecordType {
        self.record_type
    }

    pub fn record_id(&self) -> Option<&RecordId> {
        self.record_id.as_ref()
    }

    pub fn collection_filter(&self) -> &CollectionFilter {
        &self.collection_filter
    }

    pub fn observation_window(&self) -> &ObservationWindow {
        &self.observation_window
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub fn consent_scope(&self) -> &ConsentScope {
        &self.consent_scope
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if !valid_identifier(self.account_id.as_str())
            || !valid_data_center(self.data_center.as_str())
            || !valid_identifier(self.role_id.as_str())
            || !valid_identifier(self.project_id.as_str())
            || !valid_identifier(self.mission_id.as_str())
            || !valid_identifier(self.work_product_id.as_str())
            || self
                .record_id
                .as_ref()
                .is_some_and(|record_id| !valid_record_id(record_id.as_str()))
            || self.project_revision.get() == 0
            || self.mission_revision.get() == 0
            || self.work_product_revision.get() == 0
            || self.consent_scope.operations().is_empty()
            || !is_digest(self.permission_digest.as_str())
            || !is_digest(self.consent_scope.digest().as_str())
        {
            return Err(ModelError::InvalidScope);
        }
        let expected = Digest::from_fields(
            "netsuite-accounting-scope/v1",
            &[
                self.account_id.as_str().to_owned(),
                self.data_center.as_str().to_owned(),
                self.role_id.as_str().to_owned(),
                self.record_type.as_str().to_owned(),
                self.record_id
                    .as_ref()
                    .map_or_else(|| "<collection>".to_owned(), |id| id.as_str().to_owned()),
                self.collection_filter.digest().as_str().to_owned(),
                self.observation_window.start.to_rfc3339(),
                self.observation_window.end.to_rfc3339(),
                self.permission_digest.as_str().to_owned(),
                self.project_id.as_str().to_owned(),
                self.project_revision.get().to_string(),
                self.mission_id.as_str().to_owned(),
                self.mission_revision.get().to_string(),
                self.work_product_id.as_str().to_owned(),
                self.work_product_revision.get().to_string(),
                self.consent_scope
                    .operations()
                    .iter()
                    .map(|operation| format!("{operation:?}"))
                    .collect::<Vec<_>>()
                    .join(","),
                self.consent_scope.expires_at().to_rfc3339(),
                self.consent_scope.digest().as_str().to_owned(),
            ],
        );
        if self.scope_digest != expected
            || ObservationWindow::new(self.observation_window.start, self.observation_window.end)
                .is_err()
        {
            return Err(ModelError::DigestMismatch);
        }
        self.collection_filter
            .validate_for_window(&self.observation_window)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NetSuiteSuiteQlField {
    InternalId,
    RecordType,
    LastModifiedDate,
    TransactionDate,
    Status,
    Currency,
    Subsidiary,
}

impl NetSuiteSuiteQlField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InternalId => "internalId",
            Self::RecordType => "recordType",
            Self::LastModifiedDate => "lastModifiedDate",
            Self::TransactionDate => "tranDate",
            Self::Status => "status",
            Self::Currency => "currency",
            Self::Subsidiary => "subsidiary",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteSuiteQlParameter {
    name: String,
    value_kind: String,
    value_digest: Digest,
}

impl NetSuiteSuiteQlParameter {
    fn new(name: &str, value_kind: &str, value_digest: Digest) -> Self {
        Self {
            name: name.to_owned(),
            value_kind: value_kind.to_owned(),
            value_digest,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value_kind(&self) -> &str {
        &self.value_kind
    }

    pub fn value_digest(&self) -> &Digest {
        &self.value_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteSuiteQlStatement {
    record_type: NetSuiteRecordType,
    fields: Vec<NetSuiteSuiteQlField>,
    filter: CollectionFilter,
    observation_window: ObservationWindow,
    max_rows: u32,
    parameters: Vec<NetSuiteSuiteQlParameter>,
    query_template: String,
    query_digest: Digest,
    executed: bool,
}

impl NetSuiteSuiteQlStatement {
    pub fn new(
        record_type: NetSuiteRecordType,
        fields: Vec<NetSuiteSuiteQlField>,
        filter: CollectionFilter,
        observation_window: ObservationWindow,
        max_rows: u32,
    ) -> Result<Self, ModelError> {
        if fields.is_empty() || fields.len() > MAX_SUITEQL_FIELDS || max_rows == 0 {
            return Err(ModelError::InvalidSuiteQl);
        }
        filter.validate_for_window(&observation_window)?;
        let mut unique_fields = BTreeSet::new();
        for field in &fields {
            if !unique_fields.insert(*field) {
                return Err(ModelError::DuplicateEntry);
            }
        }
        if !matches!(
            (filter.field(), filter.value()),
            (
                CollectionFilterField::LastModifiedDate | CollectionFilterField::TransactionDate,
                CollectionFilterValue::Timestamp(_)
            ) | (
                CollectionFilterField::InternalId,
                CollectionFilterValue::RecordId(_)
            ) | (
                CollectionFilterField::Status,
                CollectionFilterValue::Status(_)
            )
        ) {
            return Err(ModelError::InvalidSuiteQl);
        }
        let selected_fields = fields
            .iter()
            .map(|field| field.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let query_template = format!(
            "SELECT {selected_fields} FROM {} WHERE {} {} :p_filter AND lastModifiedDate >= :p_window_start AND lastModifiedDate <= :p_window_end FETCH FIRST :p_limit ROWS ONLY",
            record_type.as_str(),
            filter.field().as_str(),
            filter.operator().as_suiteql(),
        );
        if query_template.len() > MAX_SUITEQL_BYTES {
            return Err(ModelError::InvalidSuiteQl);
        }
        let parameters = vec![
            NetSuiteSuiteQlParameter::new("p_filter", "collection_filter", filter.digest()),
            NetSuiteSuiteQlParameter::new(
                "p_window_start",
                "timestamp",
                Digest::from_text(observation_window.start().to_rfc3339()),
            ),
            NetSuiteSuiteQlParameter::new(
                "p_window_end",
                "timestamp",
                Digest::from_text(observation_window.end().to_rfc3339()),
            ),
            NetSuiteSuiteQlParameter::new(
                "p_limit",
                "bounded_integer",
                Digest::from_text(max_rows.to_string()),
            ),
        ];
        if parameters.len() > MAX_SUITEQL_PARAMETERS {
            return Err(ModelError::InvalidSuiteQl);
        }
        let query_digest = digest_serializable_material(
            "netsuite-suiteql-statement/v1",
            &[
                format!("{record_type:?}"),
                fields
                    .iter()
                    .map(|field| format!("{field:?}"))
                    .collect::<Vec<_>>()
                    .join(","),
                filter.digest().as_str().to_owned(),
                observation_window.start().to_rfc3339(),
                observation_window.end().to_rfc3339(),
                max_rows.to_string(),
                query_template.clone(),
            ],
        );
        Ok(Self {
            record_type,
            fields,
            filter,
            observation_window,
            max_rows,
            parameters,
            query_template,
            query_digest,
            executed: false,
        })
    }

    pub const fn record_type(&self) -> NetSuiteRecordType {
        self.record_type
    }

    pub fn fields(&self) -> &[NetSuiteSuiteQlField] {
        &self.fields
    }

    pub fn filter(&self) -> &CollectionFilter {
        &self.filter
    }

    pub fn observation_window(&self) -> &ObservationWindow {
        &self.observation_window
    }

    pub const fn max_rows(&self) -> u32 {
        self.max_rows
    }

    pub fn parameters(&self) -> &[NetSuiteSuiteQlParameter] {
        &self.parameters
    }

    pub fn query_template(&self) -> &str {
        &self.query_template
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub const fn executed(&self) -> bool {
        self.executed
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = digest_serializable_material(
            "netsuite-suiteql-statement/v1",
            &[
                format!("{:?}", self.record_type),
                self.fields
                    .iter()
                    .map(|field| format!("{field:?}"))
                    .collect::<Vec<_>>()
                    .join(","),
                self.filter.digest().as_str().to_owned(),
                self.observation_window.start().to_rfc3339(),
                self.observation_window.end().to_rfc3339(),
                self.max_rows.to_string(),
                self.query_template.clone(),
            ],
        );
        if self.query_digest == expected && !self.executed {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteRecordMetadata {
    record_type: NetSuiteRecordType,
    fields: Vec<NetSuiteSafeRecordField>,
    metadata_revision: Revision,
    observed_at: DateTime<Utc>,
    metadata_digest: Digest,
}

impl NetSuiteRecordMetadata {
    pub fn new(
        record_type: NetSuiteRecordType,
        fields: Vec<NetSuiteSafeRecordField>,
        metadata_revision: Revision,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        if fields.is_empty() || fields.len() > MAX_SUITEQL_FIELDS * 2 {
            return Err(ModelError::InvalidScope);
        }
        let mut unique_fields = BTreeSet::new();
        for field in &fields {
            if !unique_fields.insert(*field) {
                return Err(ModelError::DuplicateEntry);
            }
        }
        let metadata_digest = Digest::from_fields(
            "netsuite-record-metadata/v1",
            &[
                format!("{record_type:?}"),
                fields
                    .iter()
                    .map(|field| format!("{field:?}"))
                    .collect::<Vec<_>>()
                    .join(","),
                metadata_revision.get().to_string(),
                observed_at.to_rfc3339(),
            ],
        );
        Ok(Self {
            record_type,
            fields,
            metadata_revision,
            observed_at,
            metadata_digest,
        })
    }

    pub const fn record_type(&self) -> NetSuiteRecordType {
        self.record_type
    }

    pub fn fields(&self) -> &[NetSuiteSafeRecordField] {
        &self.fields
    }

    pub const fn metadata_revision(&self) -> Revision {
        self.metadata_revision
    }

    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn metadata_digest(&self) -> &Digest {
        &self.metadata_digest
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = Digest::from_fields(
            "netsuite-record-metadata/v1",
            &[
                format!("{:?}", self.record_type),
                self.fields
                    .iter()
                    .map(|field| format!("{field:?}"))
                    .collect::<Vec<_>>()
                    .join(","),
                self.metadata_revision.get().to_string(),
                self.observed_at.to_rfc3339(),
            ],
        );
        if self.metadata_digest == expected {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteCollectionSummary {
    record_type: NetSuiteRecordType,
    page_number: u16,
    returned_records: u32,
    has_more: bool,
    status_counts: BTreeMap<NetSuiteRecordStatus, u32>,
    collection_digest: Digest,
}

impl NetSuiteCollectionSummary {
    pub fn new(
        record_type: NetSuiteRecordType,
        page_number: u16,
        returned_records: u32,
        has_more: bool,
        status_counts: BTreeMap<NetSuiteRecordStatus, u32>,
    ) -> Result<Self, ModelError> {
        if page_number == 0
            || returned_records > MAX_RECORDS
            || status_counts.values().copied().sum::<u32>() > returned_records
        {
            return Err(ModelError::InvalidBounds);
        }
        let collection_digest = Digest::from_fields(
            "netsuite-record-collection/v1",
            &[
                format!("{record_type:?}"),
                page_number.to_string(),
                returned_records.to_string(),
                has_more.to_string(),
                status_counts
                    .iter()
                    .map(|(status, count)| format!("{status:?}:{count}"))
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        );
        Ok(Self {
            record_type,
            page_number,
            returned_records,
            has_more,
            status_counts,
            collection_digest,
        })
    }

    pub const fn record_type(&self) -> NetSuiteRecordType {
        self.record_type
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub const fn returned_records(&self) -> u32 {
        self.returned_records
    }

    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    pub fn status_counts(&self) -> &BTreeMap<NetSuiteRecordStatus, u32> {
        &self.status_counts
    }

    pub fn collection_digest(&self) -> &Digest {
        &self.collection_digest
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = Digest::from_fields(
            "netsuite-record-collection/v1",
            &[
                format!("{:?}", self.record_type),
                self.page_number.to_string(),
                self.returned_records.to_string(),
                self.has_more.to_string(),
                self.status_counts
                    .iter()
                    .map(|(status, count)| format!("{status:?}:{count}"))
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        );
        if self.collection_digest == expected {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteSelectedRecordSummary {
    record_type: NetSuiteRecordType,
    record_id_digest: Digest,
    status: NetSuiteRecordStatus,
    observed_at: DateTime<Utc>,
    record_revision: Revision,
    selected_record_digest: Digest,
}

impl NetSuiteSelectedRecordSummary {
    pub fn new(
        record_type: NetSuiteRecordType,
        record_id: &RecordId,
        status: NetSuiteRecordStatus,
        observed_at: DateTime<Utc>,
        record_revision: Revision,
    ) -> Self {
        let record_id_digest = Digest::from_text(record_id.as_str());
        let selected_record_digest = Digest::from_fields(
            "netsuite-selected-record/v1",
            &[
                format!("{record_type:?}"),
                record_id_digest.as_str().to_owned(),
                format!("{status:?}"),
                observed_at.to_rfc3339(),
                record_revision.get().to_string(),
            ],
        );
        Self {
            record_type,
            record_id_digest,
            status,
            observed_at,
            record_revision,
            selected_record_digest,
        }
    }

    pub const fn record_type(&self) -> NetSuiteRecordType {
        self.record_type
    }

    pub fn record_id_digest(&self) -> &Digest {
        &self.record_id_digest
    }

    pub const fn status(&self) -> NetSuiteRecordStatus {
        self.status
    }

    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn record_revision(&self) -> Revision {
        self.record_revision
    }

    pub fn selected_record_digest(&self) -> &Digest {
        &self.selected_record_digest
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = Digest::from_fields(
            "netsuite-selected-record/v1",
            &[
                format!("{:?}", self.record_type),
                self.record_id_digest.as_str().to_owned(),
                format!("{:?}", self.status),
                self.observed_at.to_rfc3339(),
                self.record_revision.get().to_string(),
            ],
        );
        if self.selected_record_digest == expected {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetSuitePayload {
    RecordMetadata(NetSuiteRecordMetadata),
    RecordCollection(NetSuiteCollectionSummary),
    SelectedRecord(NetSuiteSelectedRecordSummary),
}

pub(crate) fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| ModelError::Serialization(error.to_string()))?;
    Ok(Digest::from_bytes(&bytes))
}

fn digest_serializable_material(domain: &str, fields: &[String]) -> Digest {
    Digest::from_fields(domain, fields)
}
