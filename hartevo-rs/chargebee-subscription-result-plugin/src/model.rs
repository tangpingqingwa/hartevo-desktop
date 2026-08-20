//! Typed, bounded, and redacted Chargebee Layer-1 models.
//!
//! The model layer intentionally contains no HTTP client and no credential
//! material. Customer identity and secret references are digest-only; the
//! allowlist models contain lifecycle state, immutable identifiers, bounded
//! usage metadata, revisions, cursors, and cryptographic receipts only.

use std::{
    collections::{BTreeSet, HashSet},
    fmt,
    hash::Hash,
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    CONTRACT_VERSION, MAX_CURSOR_BYTES, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_RECORDS,
    MAX_RESPONSE_BYTES, PLUGIN_VERSION_TEXT, PROVIDER_ID, PROVIDER_IMPLEMENTATION,
    PROVIDER_REVISION_TEXT,
};

/// Errors raised while constructing or verifying bounded typed values.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChargebeeModelError {
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
    #[error("Chargebee scope digest does not match its fields")]
    ScopeMismatch,
    #[error("Chargebee cursor is not bound to the exact query, scope, or registration")]
    CursorMismatch,
    #[error("Chargebee response contains duplicate immutable identifiers")]
    DuplicateIdentifier,
    #[error("Chargebee response is not valid for the requested operation")]
    OperationMismatch,
    #[error("Chargebee response revision is stale")]
    StaleRevision,
    #[error("Chargebee response exceeds the bounded record budget")]
    TooManyRecords,
    #[error("Chargebee response exceeds the bounded byte budget")]
    ResponseTooLarge,
    #[error("Chargebee registration is already revoked")]
    AlreadyRevoked,
    #[error("canonical Chargebee value could not be serialized: {0}")]
    Serialization(String),
    #[error("Chargebee contract value is invalid: {0}")]
    Contract(String),
}

fn validate_text(
    value: &str,
    field: &'static str,
    max: usize,
    allow_whitespace: bool,
) -> Result<(), ChargebeeModelError> {
    if value.is_empty() {
        return Err(ChargebeeModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ChargebeeModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ChargebeeModelError::ControlCharacter { field });
    }
    if !allow_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ChargebeeModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ChargebeeModelError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES, false)?;
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
    }) {
        Ok(())
    } else {
        Err(ChargebeeModelError::InvalidCharacters { field })
    }
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ChargebeeModelError> {
    if value == 0 {
        Err(ChargebeeModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

/// Lowercase SHA-256 digest used for every cross-boundary binding.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    /// Hash arbitrary bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(Sha256::digest(bytes).as_slice()))
    }

    /// Hash arbitrary text or bytes.
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    /// Hash length-prefixed fields to avoid ambiguous concatenation.
    pub fn from_fields<I, S>(fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut hasher = Sha256::new();
        for field in fields {
            let value = field.as_ref();
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
            hasher.update([0]);
        }
        Self(hex_encode(hasher.finalize().as_slice()))
    }

    /// Hash a serializable value.
    pub fn from_serializable<T: Serialize>(value: &T) -> Result<Self, ChargebeeModelError> {
        let bytes = serde_json::to_vec(value)
            .map_err(|error| ChargebeeModelError::Serialization(error.to_string()))?;
        Ok(Self::from_bytes(&bytes))
    }

    /// Parse and validate an externally supplied digest.
    pub fn parse(value: impl Into<String>) -> Result<Self, ChargebeeModelError> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(ChargebeeModelError::InvalidDigest { field: "digest" })
        }
    }

    /// A deterministic placeholder used while constructing a digest-bound value.
    pub fn pending() -> Self {
        Self::from_text("hartevo.chargebee.pending/v1")
    }

    /// The all-zero digest used for an uninitialized field.
    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    /// Borrow the hexadecimal digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

/// Hash a serializable value, mapping serialization failure into the model error.
pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ChargebeeModelError> {
    Digest::from_serializable(value)
}

macro_rules! identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ChargebeeModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_fields([concat!("hartevo.chargebee.", $field, "/v1"), &self.0])
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ChargebeeModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier!(SiteId, "site_id");
identifier!(SubscriptionId, "subscription_id");
identifier!(PlanId, "plan_id");
identifier!(InvoiceId, "invoice_id");
identifier!(EntitlementId, "entitlement_id");
identifier!(ProjectId, "project_id");
identifier!(MissionId, "mission_id");
identifier!(WorkProductId, "work_product_id");
identifier!(ConsentId, "consent_id");
identifier!(ProviderRevision, "provider_revision");

/// Digest-only customer identity. The customer identifier is hashed and
/// discarded by the constructor, so it cannot appear in evidence or debug
/// output even when a fixture contains a customer identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CustomerId(Digest);

impl CustomerId {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ChargebeeModelError> {
        let value = value.as_ref();
        validate_text(value, "customer_id", MAX_IDENTIFIER_BYTES, false)?;
        Ok(Self(Digest::from_fields([
            "hartevo.chargebee.customer/v1",
            value,
        ])))
    }

    pub fn from_digest(digest: Digest) -> Result<Self, ChargebeeModelError> {
        Digest::parse(digest.as_str().to_owned())?;
        Ok(Self(digest))
    }

    pub fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Debug for CustomerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CustomerId")
            .field("digest", &self.0)
            .field("opaque", &true)
            .finish()
    }
}

impl Serialize for CustomerId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CustomerId", 2)?;
        state.serialize_field("digest", &self.0)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for CustomerId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            digest: Digest,
            opaque: bool,
        }
        let value = Wire::deserialize(deserializer)?;
        if !value.opaque {
            return Err(serde::de::Error::custom("customer id must remain opaque"));
        }
        CustomerId::from_digest(value.digest).map_err(serde::de::Error::custom)
    }
}

/// Positive revision used by provider resources and Hartevo bindings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64, field: &'static str) -> Result<Self, ChargebeeModelError> {
        validate_positive(value, field)?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Exact Project revision bound into the Layer-1 scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Project {
    pub id: ProjectId,
    pub revision: Revision,
}

impl Project {
    pub fn new(id: ProjectId, revision: u64) -> Result<Self, ChargebeeModelError> {
        Ok(Self {
            id,
            revision: Revision::new(revision, "Project revision")?,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields([self.id.as_str(), &self.revision.get().to_string()])
    }
}

/// Exact Mission revision bound into the Layer-1 scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mission {
    pub id: MissionId,
    pub revision: Revision,
}

impl Mission {
    pub fn new(id: MissionId, revision: u64) -> Result<Self, ChargebeeModelError> {
        Ok(Self {
            id,
            revision: Revision::new(revision, "Mission revision")?,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields([self.id.as_str(), &self.revision.get().to_string()])
    }
}

/// Exact Work Product revision bound into the Layer-1 scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProduct {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProduct {
    pub fn new(id: WorkProductId, revision: u64) -> Result<Self, ChargebeeModelError> {
        Ok(Self {
            id,
            revision: Revision::new(revision, "Work Product revision")?,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields([self.id.as_str(), &self.revision.get().to_string()])
    }
}

/// Exact host Consent revision bound into the Layer-1 scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentBinding {
    pub id: ConsentId,
    pub revision: Revision,
    pub digest: Digest,
}

impl ConsentBinding {
    pub fn new(id: ConsentId, revision: u64) -> Result<Self, ChargebeeModelError> {
        let revision = Revision::new(revision, "Consent revision")?;
        let digest = Digest::from_fields([id.as_str(), &revision.get().to_string()]);
        Ok(Self {
            id,
            revision,
            digest,
        })
    }

    pub fn validate(&self) -> Result<(), ChargebeeModelError> {
        if self.digest != self.recomputed_digest() {
            Err(ChargebeeModelError::ScopeMismatch)
        } else {
            Ok(())
        }
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_fields([self.id.as_str(), &self.revision.get().to_string()])
    }
}

/// The exact least-privilege GET permissions available to this provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChargebeePermission {
    SiteRead,
    CustomerRead,
    SubscriptionRead,
    PlanRead,
    EntitlementRead,
    InvoiceRead,
    UsageRead,
}

impl ChargebeePermission {
    pub const ALL: [Self; 7] = [
        Self::SiteRead,
        Self::CustomerRead,
        Self::SubscriptionRead,
        Self::PlanRead,
        Self::EntitlementRead,
        Self::InvoiceRead,
        Self::UsageRead,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SiteRead => "site_read",
            Self::CustomerRead => "customer_read",
            Self::SubscriptionRead => "subscription_read",
            Self::PlanRead => "plan_read",
            Self::EntitlementRead => "entitlement_read",
            Self::InvoiceRead => "invoice_read",
            Self::UsageRead => "usage_read",
        }
    }
}

/// Digest-bound, read-only permission snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeePermissionSnapshot {
    pub permissions: BTreeSet<ChargebeePermission>,
    pub revision: Revision,
    pub digest: Digest,
}

impl ChargebeePermissionSnapshot {
    pub fn read_only() -> Self {
        Self::from_permissions(ChargebeePermission::ALL, 1)
            .expect("static Chargebee permissions are valid")
    }

    pub fn from_permissions(
        permissions: impl IntoIterator<Item = ChargebeePermission>,
        revision: u64,
    ) -> Result<Self, ChargebeeModelError> {
        let revision = Revision::new(revision, "permission revision")?;
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        let digest = Digest::from_fields(
            std::iter::once(revision.get().to_string()).chain(
                permissions
                    .iter()
                    .map(|permission| permission.as_str().to_owned()),
            ),
        );
        Ok(Self {
            permissions,
            revision,
            digest,
        })
    }

    pub fn allows(&self, permission: ChargebeePermission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn is_exact_read_only(&self) -> bool {
        self.permissions == ChargebeePermission::ALL.into_iter().collect()
            && self.digest == self.recomputed_digest()
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_fields(
            std::iter::once(self.revision.get().to_string()).chain(
                self.permissions
                    .iter()
                    .map(|permission| permission.as_str().to_owned()),
            ),
        )
    }
}

/// Opaque host-owned Chargebee credential reference.
///
/// The supplied reference is hashed and discarded immediately. This type has
/// no `Serialize` or `Deserialize` implementation, and its `Debug` output is
/// digest-only. Layer 1 therefore cannot serialize or retain an API key,
/// secret path, environment value, or token.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        reference: impl AsRef<str>,
        scope_digest: Digest,
        credential_revision: u64,
    ) -> Result<Self, ChargebeeModelError> {
        let reference = reference.as_ref();
        validate_text(reference, "secret reference", MAX_CURSOR_BYTES * 8, false)?;
        Digest::parse(scope_digest.as_str().to_owned())?;
        Ok(Self {
            reference_digest: Digest::from_text(reference),
            scope_digest,
            credential_revision: Revision::new(credential_revision, "credential revision")?,
            revoked: false,
        })
    }

    pub fn for_scope(
        reference: impl AsRef<str>,
        scope: &ChargebeeSubscriptionScope,
        credential_revision: u64,
    ) -> Result<Self, ChargebeeModelError> {
        Self::new(reference, scope.scope_digest.clone(), credential_revision)
    }

    pub fn from_reference(reference: impl AsRef<str>) -> Result<Self, ChargebeeModelError> {
        Self::new(reference, Digest::zero(), 1)
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

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ChargebeeModelError> {
        if self.revoked {
            Err(ChargebeeModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
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
            .field("revoked", &self.revoked)
            .finish()
    }
}

/// Read operations exposed by the provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChargebeeReadOperation {
    Subscription,
    Entitlements,
    Invoices,
    Usage,
}

impl ChargebeeReadOperation {
    pub const ALL: [Self; 4] = [
        Self::Subscription,
        Self::Entitlements,
        Self::Invoices,
        Self::Usage,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subscription => "read_subscription",
            Self::Entitlements => "read_entitlements",
            Self::Invoices => "read_invoices",
            Self::Usage => "read_usage",
        }
    }

    pub const fn permission(self) -> ChargebeePermission {
        match self {
            Self::Subscription => ChargebeePermission::SubscriptionRead,
            Self::Entitlements => ChargebeePermission::EntitlementRead,
            Self::Invoices => ChargebeePermission::InvoiceRead,
            Self::Usage => ChargebeePermission::UsageRead,
        }
    }
}

/// Typed fail-closed state for a provider observation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChargebeeObservationState {
    Complete,
    Absent,
    Denied,
    Partial,
    Expired,
    AccessLost,
    ProviderUnknown,
    RateLimited,
    Tampered,
}

impl ChargebeeObservationState {
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub const fn is_fail_closed(self) -> bool {
        !self.is_complete()
    }
}

/// Subscription lifecycle state retained in bounded evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    NonRenewing,
    Trial,
    Future,
    Paused,
    Cancelled,
    Unknown,
}

impl SubscriptionStatus {
    pub fn from_wire(value: Option<&str>) -> Self {
        match value.map(str::to_ascii_lowercase).as_deref() {
            Some("active") => Self::Active,
            Some("non_renewing" | "non-renewing") => Self::NonRenewing,
            Some("in_trial" | "trial") => Self::Trial,
            Some("future") => Self::Future,
            Some("paused") => Self::Paused,
            Some("cancelled" | "canceled") => Self::Cancelled,
            _ => Self::Unknown,
        }
    }
}

/// Entitlement state retained in bounded evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementStatus {
    Active,
    Inactive,
    Expired,
    Denied,
    Unknown,
}

impl EntitlementStatus {
    pub fn from_wire(value: Option<&str>) -> Self {
        match value.map(str::to_ascii_lowercase).as_deref() {
            Some("active") => Self::Active,
            Some("inactive") => Self::Inactive,
            Some("expired") => Self::Expired,
            Some("denied") => Self::Denied,
            _ => Self::Unknown,
        }
    }
}

/// Invoice status retained without amounts or line items.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceStatus {
    Paid,
    PaymentDue,
    Posted,
    NotPaid,
    Voided,
    Pending,
    Unknown,
}

impl InvoiceStatus {
    pub fn from_wire(value: Option<&str>) -> Self {
        match value.map(str::to_ascii_lowercase).as_deref() {
            Some("paid") => Self::Paid,
            Some("payment_due" | "payment-due") => Self::PaymentDue,
            Some("posted") => Self::Posted,
            Some("not_paid" | "not-paid") => Self::NotPaid,
            Some("voided") => Self::Voided,
            Some("pending") => Self::Pending,
            _ => Self::Unknown,
        }
    }
}

/// Bounded usage metadata; values are intentionally not financial amounts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageMetadata {
    pub metric_digest: Digest,
    pub quantity: u64,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
}

impl UsageMetadata {
    pub fn new(
        metric: impl AsRef<str>,
        quantity: u64,
        period_start: Option<String>,
        period_end: Option<String>,
    ) -> Result<Self, ChargebeeModelError> {
        validate_text(metric.as_ref(), "usage metric", MAX_IDENTIFIER_BYTES, false)?;
        for value in [&period_start, &period_end].into_iter().flatten() {
            validate_text(value, "usage period", 64, false)?;
        }
        Ok(Self {
            metric_digest: Digest::from_text(metric.as_ref()),
            quantity,
            period_start,
            period_end,
        })
    }
}

/// Redacted subscription lifecycle observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubscriptionObservation {
    pub id: SubscriptionId,
    pub site_id: SiteId,
    pub customer_id: CustomerId,
    pub plan_id: PlanId,
    pub revision: Revision,
    pub status: SubscriptionStatus,
    pub quantity: u32,
    pub current_term_start: Option<String>,
    pub current_term_end: Option<String>,
    pub cancel_at_end: bool,
    pub usage: Option<UsageMetadata>,
}

/// Redacted entitlement observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntitlementObservation {
    pub id: EntitlementId,
    pub site_id: SiteId,
    pub customer_id: CustomerId,
    pub subscription_id: SubscriptionId,
    pub plan_id: PlanId,
    pub revision: Revision,
    pub status: EntitlementStatus,
    pub feature_digest: Digest,
}

/// Redacted invoice observation. Amounts and line items are deliberately absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvoiceObservation {
    pub id: InvoiceId,
    pub site_id: SiteId,
    pub customer_id: CustomerId,
    pub subscription_id: SubscriptionId,
    pub revision: Revision,
    pub status: InvoiceStatus,
    pub due_at: Option<String>,
    pub paid_at: Option<String>,
}

/// Bounded body accepted by a typed transport.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ChargebeeResponseBody {
    Subscription(SubscriptionObservation),
    Entitlements(Vec<EntitlementObservation>),
    Invoices(Vec<InvoiceObservation>),
    Usage(UsageMetadata),
}

impl ChargebeeResponseBody {
    pub fn operation(&self) -> ChargebeeReadOperation {
        match self {
            Self::Subscription(_) => ChargebeeReadOperation::Subscription,
            Self::Entitlements(_) => ChargebeeReadOperation::Entitlements,
            Self::Invoices(_) => ChargebeeReadOperation::Invoices,
            Self::Usage(_) => ChargebeeReadOperation::Usage,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Subscription(_) | Self::Usage(_) => 1,
            Self::Entitlements(values) => values.len(),
            Self::Invoices(values) => values.len(),
        }
    }

    pub const fn is_empty(&self) -> bool {
        match self {
            Self::Subscription(_) | Self::Usage(_) => false,
            Self::Entitlements(values) => values.is_empty(),
            Self::Invoices(values) => values.is_empty(),
        }
    }

    pub fn normalized(self) -> Result<Self, ChargebeeModelError> {
        match self {
            Self::Subscription(value) => Ok(Self::Subscription(value)),
            Self::Usage(value) => Ok(Self::Usage(value)),
            Self::Entitlements(mut values) => {
                if values.len() > MAX_RECORDS {
                    return Err(ChargebeeModelError::TooManyRecords);
                }
                values.sort_by(|left, right| left.id.cmp(&right.id));
                if values.windows(2).any(|pair| pair[0].id == pair[1].id) {
                    return Err(ChargebeeModelError::DuplicateIdentifier);
                }
                Ok(Self::Entitlements(values))
            }
            Self::Invoices(mut values) => {
                if values.len() > MAX_RECORDS {
                    return Err(ChargebeeModelError::TooManyRecords);
                }
                values.sort_by(|left, right| left.id.cmp(&right.id));
                if values.windows(2).any(|pair| pair[0].id == pair[1].id) {
                    return Err(ChargebeeModelError::DuplicateIdentifier);
                }
                Ok(Self::Invoices(values))
            }
        }
    }

    pub fn keys(&self) -> Vec<String> {
        match self {
            Self::Subscription(value) => vec![value.id.as_str().to_owned()],
            Self::Usage(value) => vec![value.metric_digest.as_str().to_owned()],
            Self::Entitlements(values) => values
                .iter()
                .map(|value| value.id.as_str().to_owned())
                .collect(),
            Self::Invoices(values) => values
                .iter()
                .map(|value| value.id.as_str().to_owned())
                .collect(),
        }
    }
}

/// The exact digest bindings copied into every request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeScopeBindings {
    pub site_digest: Digest,
    pub customer_digest: Digest,
    pub subscription_digest: Digest,
    pub plan_digest: Digest,
    pub invoice_digest: Digest,
    pub entitlement_digest: Digest,
    pub site_revision: Revision,
    pub customer_revision: Revision,
    pub subscription_revision: Revision,
    pub plan_revision: Revision,
    pub invoice_revision: Revision,
    pub entitlement_revision: Revision,
    pub revision_digest: Digest,
    pub scope_digest: Digest,
}

impl ChargebeeScopeBindings {
    pub fn validate(&self) -> Result<(), ChargebeeModelError> {
        for (digest, field) in [
            (&self.site_digest, "site digest"),
            (&self.customer_digest, "customer digest"),
            (&self.subscription_digest, "subscription digest"),
            (&self.plan_digest, "plan digest"),
            (&self.invoice_digest, "invoice digest"),
            (&self.entitlement_digest, "entitlement digest"),
            (&self.revision_digest, "revision digest"),
            (&self.scope_digest, "scope digest"),
        ] {
            validate_digest(digest, field)?;
        }
        if [
            self.site_revision,
            self.customer_revision,
            self.subscription_revision,
            self.plan_revision,
            self.invoice_revision,
            self.entitlement_revision,
        ]
        .into_iter()
        .any(|revision| revision.get() == 0)
        {
            return Err(ChargebeeModelError::MustBePositive {
                field: "resource revision",
            });
        }
        Ok(())
    }
}

/// Exact Chargebee and Hartevo scope for one Mission result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeSubscriptionScope {
    pub site_id: SiteId,
    pub customer_id: CustomerId,
    pub subscription_id: SubscriptionId,
    pub plan_id: PlanId,
    pub invoice_id: InvoiceId,
    pub entitlement_id: EntitlementId,
    pub site_revision: Revision,
    pub customer_revision: Revision,
    pub subscription_revision: Revision,
    pub plan_revision: Revision,
    pub invoice_revision: Revision,
    pub entitlement_revision: Revision,
    pub project: Project,
    pub mission: Mission,
    pub work_product: WorkProduct,
    pub consent: ConsentBinding,
    pub permissions: ChargebeePermissionSnapshot,
    pub scope_digest: Digest,
}

/// Backwards-friendly short name for the exact Chargebee scope.
pub type ChargebeeScope = ChargebeeSubscriptionScope;

/// String-based constructor input for an exact Chargebee scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChargebeeSubscriptionScopeInput {
    pub site_id: String,
    pub customer_id: String,
    pub subscription_id: String,
    pub plan_id: String,
    pub invoice_id: String,
    pub entitlement_id: String,
    pub site_revision: u64,
    pub customer_revision: u64,
    pub subscription_revision: u64,
    pub plan_revision: u64,
    pub invoice_revision: u64,
    pub entitlement_revision: u64,
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub consent_id: String,
    pub consent_revision: u64,
    pub permissions: ChargebeePermissionSnapshot,
}

impl ChargebeeSubscriptionScope {
    pub fn new(input: ChargebeeSubscriptionScopeInput) -> Result<Self, ChargebeeModelError> {
        let scope = Self {
            site_id: SiteId::new(input.site_id)?,
            customer_id: CustomerId::new(input.customer_id)?,
            subscription_id: SubscriptionId::new(input.subscription_id)?,
            plan_id: PlanId::new(input.plan_id)?,
            invoice_id: InvoiceId::new(input.invoice_id)?,
            entitlement_id: EntitlementId::new(input.entitlement_id)?,
            site_revision: Revision::new(input.site_revision, "site revision")?,
            customer_revision: Revision::new(input.customer_revision, "customer revision")?,
            subscription_revision: Revision::new(
                input.subscription_revision,
                "subscription revision",
            )?,
            plan_revision: Revision::new(input.plan_revision, "plan revision")?,
            invoice_revision: Revision::new(input.invoice_revision, "invoice revision")?,
            entitlement_revision: Revision::new(
                input.entitlement_revision,
                "entitlement revision",
            )?,
            project: Project::new(ProjectId::new(input.project_id)?, input.project_revision)?,
            mission: Mission::new(MissionId::new(input.mission_id)?, input.mission_revision)?,
            work_product: WorkProduct::new(
                WorkProductId::new(input.work_product_id)?,
                input.work_product_revision,
            )?,
            consent: ConsentBinding::new(
                ConsentId::new(input.consent_id)?,
                input.consent_revision,
            )?,
            permissions: input.permissions,
            scope_digest: Digest::pending(),
        };
        scope.permissions.validate()?;
        scope.consent.validate()?;
        let scope = Self {
            scope_digest: scope.recomputed_digest(),
            ..scope
        };
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_ids(
        site_id: impl Into<String>,
        customer_id: impl Into<String>,
        subscription_id: impl Into<String>,
        plan_id: impl Into<String>,
        invoice_id: impl Into<String>,
        entitlement_id: impl Into<String>,
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        work_product_id: impl Into<String>,
        consent_id: impl Into<String>,
        revisions: [u64; 10],
    ) -> Result<Self, ChargebeeModelError> {
        Self::new(ChargebeeSubscriptionScopeInput {
            site_id: site_id.into(),
            customer_id: customer_id.into(),
            subscription_id: subscription_id.into(),
            plan_id: plan_id.into(),
            invoice_id: invoice_id.into(),
            entitlement_id: entitlement_id.into(),
            site_revision: revisions[0],
            customer_revision: revisions[1],
            subscription_revision: revisions[2],
            plan_revision: revisions[3],
            invoice_revision: revisions[4],
            entitlement_revision: revisions[5],
            project_id: project_id.into(),
            project_revision: revisions[6],
            mission_id: mission_id.into(),
            mission_revision: revisions[7],
            work_product_id: work_product_id.into(),
            work_product_revision: revisions[8],
            consent_id: consent_id.into(),
            consent_revision: revisions[9],
            permissions: ChargebeePermissionSnapshot::read_only(),
        })
    }

    pub fn bindings(&self) -> ChargebeeScopeBindings {
        ChargebeeScopeBindings {
            site_digest: self.site_id.digest(),
            customer_digest: self.customer_id.digest().clone(),
            subscription_digest: self.subscription_id.digest(),
            plan_digest: self.plan_id.digest(),
            invoice_digest: self.invoice_id.digest(),
            entitlement_digest: self.entitlement_id.digest(),
            site_revision: self.site_revision,
            customer_revision: self.customer_revision,
            subscription_revision: self.subscription_revision,
            plan_revision: self.plan_revision,
            invoice_revision: self.invoice_revision,
            entitlement_revision: self.entitlement_revision,
            revision_digest: self.revision_digest(),
            scope_digest: self.scope_digest.clone(),
        }
    }

    pub fn revision_digest(&self) -> Digest {
        Digest::from_fields([
            &self.site_revision.get().to_string(),
            &self.customer_revision.get().to_string(),
            &self.subscription_revision.get().to_string(),
            &self.plan_revision.get().to_string(),
            &self.invoice_revision.get().to_string(),
            &self.entitlement_revision.get().to_string(),
            &self.project.revision.get().to_string(),
            &self.mission.revision.get().to_string(),
            &self.work_product.revision.get().to_string(),
            &self.consent.revision.get().to_string(),
            self.permissions.digest.as_str(),
        ])
    }

    pub fn recomputed_digest(&self) -> Digest {
        let bindings = self.bindings_without_scope();
        Digest::from_fields([
            bindings.site_digest.as_str(),
            bindings.customer_digest.as_str(),
            bindings.subscription_digest.as_str(),
            bindings.plan_digest.as_str(),
            bindings.invoice_digest.as_str(),
            bindings.entitlement_digest.as_str(),
            bindings.revision_digest.as_str(),
            self.project.digest().as_str(),
            self.mission.digest().as_str(),
            self.work_product.digest().as_str(),
            self.consent.digest.as_str(),
            self.permissions.digest.as_str(),
        ])
    }

    fn bindings_without_scope(&self) -> ChargebeeScopeBindings {
        ChargebeeScopeBindings {
            site_digest: self.site_id.digest(),
            customer_digest: self.customer_id.digest().clone(),
            subscription_digest: self.subscription_id.digest(),
            plan_digest: self.plan_id.digest(),
            invoice_digest: self.invoice_id.digest(),
            entitlement_digest: self.entitlement_id.digest(),
            site_revision: self.site_revision,
            customer_revision: self.customer_revision,
            subscription_revision: self.subscription_revision,
            plan_revision: self.plan_revision,
            invoice_revision: self.invoice_revision,
            entitlement_revision: self.entitlement_revision,
            revision_digest: self.revision_digest(),
            scope_digest: Digest::zero(),
        }
    }

    pub fn validate(&self) -> Result<(), ChargebeeModelError> {
        self.permissions.validate()?;
        self.consent.validate()?;
        for (identifier, field) in [
            (self.site_id.as_str(), "site id"),
            (self.subscription_id.as_str(), "subscription id"),
            (self.plan_id.as_str(), "plan id"),
            (self.invoice_id.as_str(), "invoice id"),
            (self.entitlement_id.as_str(), "entitlement id"),
            (self.project.id.as_str(), "project id"),
            (self.mission.id.as_str(), "mission id"),
            (self.work_product.id.as_str(), "work product id"),
            (self.consent.id.as_str(), "consent id"),
        ] {
            validate_identifier(identifier, field)?;
        }
        validate_digest(self.customer_id.digest(), "customer digest")?;
        if [
            self.site_revision,
            self.customer_revision,
            self.subscription_revision,
            self.plan_revision,
            self.invoice_revision,
            self.entitlement_revision,
            self.project.revision,
            self.mission.revision,
            self.work_product.revision,
            self.consent.revision,
        ]
        .into_iter()
        .any(|revision| revision.get() == 0)
        {
            return Err(ChargebeeModelError::MustBePositive {
                field: "scope revision",
            });
        }
        if self.scope_digest != self.recomputed_digest() {
            Err(ChargebeeModelError::ScopeMismatch)
        } else {
            Ok(())
        }
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permissions.digest
    }
}

impl ChargebeePermissionSnapshot {
    fn validate(&self) -> Result<(), ChargebeeModelError> {
        if self.revision.get() == 0 || !self.is_exact_read_only() {
            Err(ChargebeeModelError::Invalid {
                field: "permissions",
            })
        } else {
            Ok(())
        }
    }
}

/// Query identity excluding the page cursor. Cursor binding is explicit below.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeQuery {
    pub operation: ChargebeeReadOperation,
    pub limit: u16,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub query_digest: Digest,
}

impl ChargebeeQuery {
    pub fn new(
        operation: ChargebeeReadOperation,
        limit: u16,
        scope: &ChargebeeSubscriptionScope,
    ) -> Result<Self, ChargebeeModelError> {
        scope.validate()?;
        if limit == 0 || limit > MAX_PAGE_SIZE {
            return Err(ChargebeeModelError::Invalid { field: "page size" });
        }
        let mut query = Self {
            operation,
            limit,
            scope_digest: scope.scope_digest.clone(),
            revision_digest: scope.revision_digest(),
            query_digest: Digest::pending(),
        };
        query.query_digest = query.recomputed_digest();
        Ok(query)
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_fields([
            self.operation.as_str(),
            &self.limit.to_string(),
            self.scope_digest.as_str(),
            self.revision_digest.as_str(),
        ])
    }

    pub fn validate(&self) -> Result<(), ChargebeeModelError> {
        validate_digest(&self.scope_digest, "query scope digest")?;
        validate_digest(&self.revision_digest, "query revision digest")?;
        if self.limit == 0
            || self.limit > MAX_PAGE_SIZE
            || self.query_digest != self.recomputed_digest()
        {
            Err(ChargebeeModelError::Invalid { field: "query" })
        } else {
            Ok(())
        }
    }
}

/// Digest-bound opaque page cursor. Provider page tokens are never retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeCursor {
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub registration_digest: Digest,
    pub page: u16,
    pub offset: u32,
    pub last_key_digest: Option<Digest>,
    pub anchor_response_digest: Digest,
    pub cursor_digest: Digest,
}

impl ChargebeeCursor {
    pub fn new(
        scope_digest: Digest,
        query_digest: Digest,
        registration_digest: Digest,
        page: u16,
        offset: u32,
        last_key_digest: Option<Digest>,
        anchor_response_digest: Digest,
    ) -> Result<Self, ChargebeeModelError> {
        if page == 0 || offset == 0 {
            return Err(ChargebeeModelError::Invalid {
                field: "cursor position",
            });
        }
        Digest::parse(scope_digest.as_str().to_owned())?;
        Digest::parse(query_digest.as_str().to_owned())?;
        Digest::parse(registration_digest.as_str().to_owned())?;
        Digest::parse(anchor_response_digest.as_str().to_owned())?;
        if let Some(last_key_digest) = &last_key_digest {
            Digest::parse(last_key_digest.as_str().to_owned())?;
        }
        let mut cursor = Self {
            scope_digest,
            query_digest,
            registration_digest,
            page,
            offset,
            last_key_digest,
            anchor_response_digest,
            cursor_digest: Digest::pending(),
        };
        cursor.cursor_digest = cursor.recomputed_digest();
        Ok(cursor)
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_fields([
            self.scope_digest.as_str(),
            self.query_digest.as_str(),
            self.registration_digest.as_str(),
            &self.page.to_string(),
            &self.offset.to_string(),
            self.last_key_digest.as_ref().map_or("", Digest::as_str),
            self.anchor_response_digest.as_str(),
        ])
    }

    pub fn validate_for(
        &self,
        scope_digest: &Digest,
        query_digest: &Digest,
        registration_digest: &Digest,
    ) -> Result<(), ChargebeeModelError> {
        for (digest, field) in [
            (&self.scope_digest, "cursor scope digest"),
            (&self.query_digest, "cursor query digest"),
            (&self.registration_digest, "cursor registration digest"),
            (&self.anchor_response_digest, "cursor anchor digest"),
            (&self.cursor_digest, "cursor digest"),
        ] {
            validate_digest(digest, field)?;
        }
        if let Some(last_key_digest) = &self.last_key_digest {
            validate_digest(last_key_digest, "cursor last key digest")?;
        }
        if self.scope_digest != *scope_digest
            || self.query_digest != *query_digest
            || self.registration_digest != *registration_digest
            || self.cursor_digest != self.recomputed_digest()
            || self.page == 0
            || self.offset == 0
            || self.cursor_digest.as_str().len() > MAX_CURSOR_BYTES * 2
        {
            Err(ChargebeeModelError::CursorMismatch)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.cursor_digest
    }
}

/// A typed, digest-bound read request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeReadRequest {
    pub operation: ChargebeeReadOperation,
    pub limit: u16,
    pub offset: u32,
    pub cursor: Option<ChargebeeCursor>,
    pub bindings: ChargebeeScopeBindings,
    pub registration_digest: Digest,
    pub query: ChargebeeQuery,
    pub idempotency_key: String,
    pub observed_at_ms: u64,
    pub request_digest: Digest,
}

impl ChargebeeReadRequest {
    pub fn new(
        scope: &ChargebeeSubscriptionScope,
        registration_digest: &Digest,
        operation: ChargebeeReadOperation,
        limit: u16,
        cursor: Option<ChargebeeCursor>,
        observed_at_ms: u64,
    ) -> Result<Self, ChargebeeModelError> {
        scope.validate()?;
        let query = ChargebeeQuery::new(operation, limit, scope)?;
        Digest::parse(registration_digest.as_str().to_owned())?;
        if let Some(cursor) = &cursor {
            cursor.validate_for(
                scope.scope_digest(),
                &query.query_digest,
                registration_digest,
            )?;
        }
        let offset = cursor.as_ref().map_or(0, |value| value.offset);
        let cursor_digest = cursor
            .as_ref()
            .map_or_else(Digest::zero, |value| value.cursor_digest.clone());
        let idempotency_key = deterministic_idempotency_key(
            scope.scope_digest(),
            registration_digest,
            &query.query_digest,
            &cursor_digest,
        );
        let bindings = scope.bindings();
        let request_digest = Digest::from_fields([
            operation.as_str(),
            &limit.to_string(),
            &offset.to_string(),
            bindings.scope_digest.as_str(),
            bindings.revision_digest.as_str(),
            registration_digest.as_str(),
            query.query_digest.as_str(),
            cursor_digest.as_str(),
            &observed_at_ms.to_string(),
        ]);
        Ok(Self {
            operation,
            limit,
            offset,
            cursor,
            bindings,
            registration_digest: registration_digest.clone(),
            query,
            idempotency_key,
            observed_at_ms,
            request_digest,
        })
    }

    pub fn http_request(&self) -> ChargebeeHttpRequest {
        ChargebeeHttpRequest::from_read(self)
    }

    pub fn recomputed_digest(&self) -> Digest {
        let cursor_digest = self
            .cursor
            .as_ref()
            .map_or_else(Digest::zero, |cursor| cursor.cursor_digest.clone());
        Digest::from_fields([
            self.operation.as_str(),
            &self.limit.to_string(),
            &self.offset.to_string(),
            self.bindings.scope_digest.as_str(),
            self.bindings.revision_digest.as_str(),
            self.registration_digest.as_str(),
            self.query.query_digest.as_str(),
            cursor_digest.as_str(),
            &self.observed_at_ms.to_string(),
        ])
    }

    pub fn validate(&self) -> Result<(), ChargebeeModelError> {
        self.query.validate()?;
        self.bindings.validate()?;
        validate_digest(&self.registration_digest, "registration digest")?;
        if self.operation != self.query.operation
            || self.limit != self.query.limit
            || self.bindings.scope_digest != self.query.scope_digest
            || self.bindings.revision_digest != self.query.revision_digest
            || self.offset != self.cursor.as_ref().map_or(0, |cursor| cursor.offset)
            || self.idempotency_key
                != deterministic_idempotency_key(
                    &self.bindings.scope_digest,
                    &self.registration_digest,
                    &self.query.query_digest,
                    &self
                        .cursor
                        .as_ref()
                        .map_or_else(Digest::zero, |cursor| cursor.cursor_digest.clone()),
                )
            || self.request_digest != self.recomputed_digest()
        {
            return Err(ChargebeeModelError::Invalid {
                field: "read request",
            });
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate_for(
                &self.bindings.scope_digest,
                &self.query.query_digest,
                &self.registration_digest,
            )?;
        }
        Ok(())
    }
}

/// Sanitized GET-shaped transport request. It contains digests, never raw
/// customer identity or credentials.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeHttpRequest {
    pub method: String,
    pub operation: ChargebeeReadOperation,
    pub path_digest: Digest,
    pub bindings: ChargebeeScopeBindings,
    pub registration_digest: Digest,
    pub query_digest: Digest,
    pub cursor_digest: Digest,
    pub idempotency_key: String,
    pub request_digest: Digest,
    pub limit: u16,
    pub offset: u32,
    pub observed_at_ms: u64,
}

impl ChargebeeHttpRequest {
    pub fn from_read(request: &ChargebeeReadRequest) -> Self {
        let cursor_digest = request
            .cursor
            .as_ref()
            .map_or_else(Digest::zero, |cursor| cursor.cursor_digest.clone());
        let path_digest = Digest::from_fields([
            request.operation.as_str(),
            request.bindings.site_digest.as_str(),
            request.bindings.customer_digest.as_str(),
            request.bindings.subscription_digest.as_str(),
            request.query.query_digest.as_str(),
            cursor_digest.as_str(),
        ]);
        Self {
            method: "GET".to_owned(),
            operation: request.operation,
            path_digest,
            bindings: request.bindings.clone(),
            registration_digest: request.registration_digest.clone(),
            query_digest: request.query.query_digest.clone(),
            cursor_digest,
            idempotency_key: request.idempotency_key.clone(),
            request_digest: request.request_digest.clone(),
            limit: request.limit,
            offset: request.offset,
            observed_at_ms: request.observed_at_ms,
        }
    }
}

/// Redacted request receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeRequestReceipt {
    pub operation: ChargebeeReadOperation,
    pub method: String,
    pub path_digest: Digest,
    pub query_digest: Digest,
    pub cursor_digest: Digest,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub idempotency_key: String,
}

impl ChargebeeRequestReceipt {
    pub fn from_request(request: &ChargebeeHttpRequest) -> Self {
        Self {
            operation: request.operation,
            method: request.method.clone(),
            path_digest: request.path_digest.clone(),
            query_digest: request.query_digest.clone(),
            cursor_digest: request.cursor_digest.clone(),
            request_digest: request.request_digest.clone(),
            scope_digest: request.bindings.scope_digest.clone(),
            idempotency_key: request.idempotency_key.clone(),
        }
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).unwrap_or_else(|_| Digest::zero())
    }
}

/// Redacted provider response receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeResponseReceipt {
    pub status: u16,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub request_digest: Digest,
    pub has_more: bool,
    pub retry_after_seconds: Option<u64>,
}

impl ChargebeeResponseReceipt {
    pub fn digest(&self) -> Digest {
        digest_serializable(self).unwrap_or_else(|_| Digest::zero())
    }
}

/// Typed provider response after raw bytes have been parsed and discarded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeHttpResponse {
    pub operation: ChargebeeReadOperation,
    pub body: ChargebeeResponseBody,
    pub receipt: ChargebeeResponseReceipt,
}

impl ChargebeeHttpResponse {
    pub fn from_body(
        request: &ChargebeeHttpRequest,
        body: ChargebeeResponseBody,
        provider_revision: ProviderRevision,
        has_more: bool,
    ) -> Result<Self, ChargebeeModelError> {
        let body = body.normalized()?;
        if body.operation() != request.operation || body.len() > MAX_RECORDS {
            return Err(ChargebeeModelError::OperationMismatch);
        }
        let bytes = serde_json::to_vec(&body)
            .map_err(|error| ChargebeeModelError::Serialization(error.to_string()))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ChargebeeModelError::ResponseTooLarge);
        }
        Ok(Self {
            operation: request.operation,
            body,
            receipt: ChargebeeResponseReceipt {
                status: 200,
                response_bytes: bytes.len(),
                response_digest: Digest::from_bytes(&bytes),
                provider_revision,
                request_digest: request.request_digest.clone(),
                has_more,
                retry_after_seconds: None,
            },
        })
    }
}

/// Provenance of a Layer-1 transport. Every variant is explicitly non-native
/// and disconnected.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChargebeeTransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ChargebeeTransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

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

/// Progress used to create the next digest-bound cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageProgress {
    pub page: u16,
    pub next_offset: u32,
    pub last_key_digest: Option<Digest>,
}

/// One bounded read result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeReadEvidence {
    pub operation: ChargebeeReadOperation,
    pub body: ChargebeeResponseBody,
    pub request_receipt: ChargebeeRequestReceipt,
    pub response_receipt: ChargebeeResponseReceipt,
    pub provenance: ChargebeeTransportProvenance,
    pub state: ChargebeeObservationState,
    pub source_digest: Digest,
    pub next_cursor: Option<ChargebeeCursor>,
    pub evidence_digest: Digest,
    pub redacted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl ChargebeeReadEvidence {
    pub fn new(
        request: &ChargebeeHttpRequest,
        response: ChargebeeHttpResponse,
        provenance: ChargebeeTransportProvenance,
        progress: PageProgress,
    ) -> Result<Self, ChargebeeModelError> {
        let request_receipt = ChargebeeRequestReceipt::from_request(request);
        let state = if response.body.is_empty() {
            ChargebeeObservationState::Absent
        } else {
            ChargebeeObservationState::Complete
        };
        let source_digest = Digest::from_fields([
            request_receipt.digest().as_str(),
            response.receipt.response_digest.as_str(),
            response.receipt.provider_revision.as_str(),
        ]);
        let next_cursor = if response.receipt.has_more {
            Some(ChargebeeCursor::new(
                request.bindings.scope_digest.clone(),
                request.query_digest.clone(),
                request.registration_digest.clone(),
                progress.page.saturating_add(1),
                progress.next_offset,
                progress.last_key_digest,
                response.receipt.response_digest.clone(),
            )?)
        } else {
            None
        };
        let mut evidence = Self {
            operation: response.operation,
            body: response.body,
            request_receipt,
            response_receipt: response.receipt,
            provenance,
            state,
            source_digest,
            next_cursor,
            evidence_digest: Digest::pending(),
            redacted: true,
            connected: false,
            native: false,
            first_party: false,
        };
        evidence.evidence_digest = evidence.recomputed_digest()?;
        Ok(evidence)
    }

    pub fn recomputed_digest(&self) -> Result<Digest, ChargebeeModelError> {
        digest_serializable(&(
            &self.operation,
            &self.body,
            &self.request_receipt,
            &self.response_receipt,
            self.provenance,
            self.state,
            &self.source_digest,
            &self.next_cursor,
            self.redacted,
            self.connected,
            self.native,
            self.first_party,
        ))
    }

    pub fn validate(&self) -> Result<(), ChargebeeModelError> {
        let expected_state = if self.body.is_empty() {
            ChargebeeObservationState::Absent
        } else {
            ChargebeeObservationState::Complete
        };
        let normalized_body = self.body.clone().normalized()?;
        let expected_response_bytes = serde_json::to_vec(&normalized_body)
            .map_err(|error| ChargebeeModelError::Serialization(error.to_string()))?;
        let expected_response_digest = Digest::from_bytes(&expected_response_bytes);
        let expected_source_digest = Digest::from_fields([
            self.request_receipt.digest().as_str(),
            self.response_receipt.response_digest.as_str(),
            self.response_receipt.provider_revision.as_str(),
        ]);
        let cursor_digest = self
            .next_cursor
            .as_ref()
            .map_or_else(Digest::zero, |cursor| cursor.cursor_digest.clone());
        let cursor_state_valid = match (self.response_receipt.has_more, &self.next_cursor) {
            (true, Some(cursor)) => {
                cursor.validate_for(
                    &self.request_receipt.scope_digest,
                    &self.request_receipt.query_digest,
                    &cursor.registration_digest,
                )?;
                cursor.anchor_response_digest == self.response_receipt.response_digest
            }
            (false, None) => true,
            _ => false,
        };
        if self.redacted
            && !self.connected
            && !self.native
            && !self.first_party
            && self.operation == self.body.operation()
            && normalized_body == self.body
            && self.request_receipt.method == "GET"
            && self.response_receipt.status == 200
            && self.response_receipt.response_bytes <= MAX_RESPONSE_BYTES
            && self.response_receipt.response_bytes == expected_response_bytes.len()
            && self.response_receipt.response_digest == expected_response_digest
            && self.response_receipt.request_digest == self.request_receipt.request_digest
            && self.request_receipt.cursor_digest == cursor_digest
            && self.response_receipt.retry_after_seconds.is_none()
            && self.state == expected_state
            && cursor_state_valid
            && expected_source_digest == self.source_digest
            && validate_digest(&self.request_receipt.path_digest, "request path digest").is_ok()
            && validate_digest(&self.request_receipt.query_digest, "request query digest").is_ok()
            && validate_digest(&self.request_receipt.cursor_digest, "request cursor digest").is_ok()
            && validate_digest(&self.request_receipt.request_digest, "request digest").is_ok()
            && validate_digest(&self.response_receipt.response_digest, "response digest").is_ok()
            && self.evidence_digest == self.recomputed_digest()?
        {
            Ok(())
        } else {
            Err(ChargebeeModelError::Invalid {
                field: "read evidence",
            })
        }
    }
}

/// Per-operation state included in aggregate proposal evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeOperationStatus {
    pub operation: ChargebeeReadOperation,
    pub state: ChargebeeObservationState,
    pub retry_after_seconds: Option<u64>,
}

/// Redaction tripwire copied into every aggregate evidence object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeRedaction {
    pub raw_provider_payload: bool,
    pub raw_customer_pii: bool,
    pub raw_customer_email: bool,
    pub raw_customer_name: bool,
    pub payment_instruments: bool,
    pub invoice_line_items: bool,
    pub invoice_amounts: bool,
    pub plan_description: bool,
    pub entitlement_description: bool,
    pub raw_secret_reference: bool,
    pub raw_provider_error: bool,
    pub financial_advice: bool,
}

impl ChargebeeRedaction {
    pub const fn layer1() -> Self {
        Self {
            raw_provider_payload: false,
            raw_customer_pii: false,
            raw_customer_email: false,
            raw_customer_name: false,
            payment_instruments: false,
            invoice_line_items: false,
            invoice_amounts: false,
            plan_description: false,
            entitlement_description: false,
            raw_secret_reference: false,
            raw_provider_error: false,
            financial_advice: false,
        }
    }

    pub const fn is_safe(&self) -> bool {
        !self.raw_provider_payload
            && !self.raw_customer_pii
            && !self.raw_customer_email
            && !self.raw_customer_name
            && !self.payment_instruments
            && !self.invoice_line_items
            && !self.invoice_amounts
            && !self.plan_description
            && !self.entitlement_description
            && !self.raw_secret_reference
            && !self.raw_provider_error
            && !self.financial_advice
    }
}

/// Aggregate bounded subscription/entitlement/invoice/usage evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeEvidence {
    pub scope: ChargebeeSubscriptionScope,
    pub registration_digest: Digest,
    pub subscription: Option<SubscriptionObservation>,
    pub entitlements: Vec<EntitlementObservation>,
    pub invoices: Vec<InvoiceObservation>,
    pub usage: Option<UsageMetadata>,
    pub operation_statuses: Vec<ChargebeeOperationStatus>,
    pub read_receipts: Vec<ChargebeeResponseReceipt>,
    pub cursors: Vec<ChargebeeCursor>,
    pub result_digest: Digest,
    pub source_digest: Digest,
    pub overall_state: ChargebeeObservationState,
    pub partial: bool,
    pub redaction: ChargebeeRedaction,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub evidence_digest: Digest,
}

impl ChargebeeEvidence {
    pub fn from_reads(
        scope: ChargebeeSubscriptionScope,
        registration_digest: Digest,
        reads: impl IntoIterator<Item = ChargebeeReadEvidence>,
        operation_statuses: Vec<ChargebeeOperationStatus>,
    ) -> Result<Self, ChargebeeModelError> {
        let reads = reads.into_iter().collect::<Vec<_>>();
        if reads.len() > ChargebeeReadOperation::ALL.len() {
            return Err(ChargebeeModelError::TooManyRecords);
        }
        let mut subscription = None;
        let mut entitlements = Vec::new();
        let mut invoices = Vec::new();
        let mut usage = None;
        let mut read_receipts = Vec::new();
        let mut cursors = Vec::new();
        let mut sources = Vec::new();
        for read in &reads {
            read.validate()?;
            read_receipts.push(read.response_receipt.clone());
            sources.push(read.source_digest.clone());
            if let Some(cursor) = &read.next_cursor {
                cursors.push(cursor.clone());
            }
            match &read.body {
                ChargebeeResponseBody::Subscription(value) => subscription = Some(value.clone()),
                ChargebeeResponseBody::Entitlements(values) => entitlements.extend(values.clone()),
                ChargebeeResponseBody::Invoices(values) => invoices.extend(values.clone()),
                ChargebeeResponseBody::Usage(value) => usage = Some(value.clone()),
            }
        }
        entitlements.sort_by(|left, right| left.id.cmp(&right.id));
        invoices.sort_by(|left, right| left.id.cmp(&right.id));
        if entitlements.windows(2).any(|pair| pair[0].id == pair[1].id)
            || invoices.windows(2).any(|pair| pair[0].id == pair[1].id)
        {
            return Err(ChargebeeModelError::DuplicateIdentifier);
        }
        let partial = operation_statuses
            .iter()
            .any(|status| !status.state.is_complete())
            || operation_statuses.len() != ChargebeeReadOperation::ALL.len()
            || reads.iter().any(|read| read.response_receipt.has_more);
        let overall_state = aggregate_state(&operation_statuses, partial);
        let source_digest = Digest::from_fields(sources.iter().map(Digest::as_str));
        let mut evidence = Self {
            scope,
            registration_digest,
            subscription,
            entitlements,
            invoices,
            usage,
            operation_statuses,
            read_receipts,
            cursors,
            result_digest: Digest::pending(),
            source_digest,
            overall_state,
            partial,
            redaction: ChargebeeRedaction::layer1(),
            connected: false,
            native: false,
            first_party: false,
            evidence_digest: Digest::pending(),
        };
        evidence.scope.validate()?;
        evidence.result_digest = evidence.recomputed_result_digest()?;
        evidence.evidence_digest = evidence.recomputed_digest()?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn recomputed_result_digest(&self) -> Result<Digest, ChargebeeModelError> {
        digest_serializable(&(
            &self.scope.scope_digest,
            &self.subscription,
            &self.entitlements,
            &self.invoices,
            &self.usage,
            &self.operation_statuses,
            &self.read_receipts,
            &self.cursors,
            &self.source_digest,
            self.overall_state,
            self.partial,
        ))
    }

    pub fn recomputed_digest(&self) -> Result<Digest, ChargebeeModelError> {
        let redaction_digest = digest_serializable(&self.redaction)?;
        let state = format!("{:?}", self.overall_state);
        Ok(Digest::from_fields([
            self.scope.scope_digest.as_str(),
            self.registration_digest.as_str(),
            self.subscription
                .as_ref()
                .map_or("", |value| value.id.as_str()),
            &digest_serializable(&self.entitlements)?.to_string(),
            &digest_serializable(&self.invoices)?.to_string(),
            self.usage
                .as_ref()
                .map_or("", |value| value.metric_digest.as_str()),
            &digest_serializable(&self.operation_statuses)?.to_string(),
            &digest_serializable(&self.read_receipts)?.to_string(),
            &digest_serializable(&self.cursors)?.to_string(),
            self.result_digest.as_str(),
            self.source_digest.as_str(),
            state.as_str(),
            bool_marker(self.partial),
            redaction_digest.as_str(),
            bool_marker(self.connected),
            bool_marker(self.native),
            bool_marker(self.first_party),
        ]))
    }

    pub fn validate(&self) -> Result<(), ChargebeeModelError> {
        self.scope.validate()?;
        validate_digest(&self.registration_digest, "registration digest")?;
        validate_digest(&self.result_digest, "result digest")?;
        validate_digest(&self.source_digest, "source digest")?;
        validate_digest(&self.evidence_digest, "evidence digest")?;
        if self.entitlements.len() > MAX_RECORDS
            || self.invoices.len() > MAX_RECORDS
            || self.operation_statuses.len() > ChargebeeReadOperation::ALL.len()
            || self.read_receipts.len() > ChargebeeReadOperation::ALL.len()
            || self.cursors.len() > ChargebeeReadOperation::ALL.len()
        {
            return Err(ChargebeeModelError::TooManyRecords);
        }
        for receipt in &self.read_receipts {
            if receipt.status != 200
                || receipt.response_bytes > MAX_RESPONSE_BYTES
                || receipt.retry_after_seconds.is_some()
                || receipt.provider_revision.as_str() != PROVIDER_REVISION_TEXT
            {
                return Err(ChargebeeModelError::Invalid {
                    field: "response receipt",
                });
            }
            validate_digest(&receipt.response_digest, "response receipt digest")?;
            validate_digest(&receipt.request_digest, "request receipt digest")?;
        }
        for cursor in &self.cursors {
            cursor.validate_for(
                &self.scope.scope_digest,
                &cursor.query_digest,
                &self.registration_digest,
            )?;
        }
        let expected_partial = self
            .operation_statuses
            .iter()
            .any(|status| !status.state.is_complete())
            || self.operation_statuses.len() != ChargebeeReadOperation::ALL.len()
            || self.read_receipts.iter().any(|receipt| receipt.has_more);
        if self.partial != expected_partial
            || self.overall_state != aggregate_state(&self.operation_statuses, self.partial)
        {
            return Err(ChargebeeModelError::Invalid {
                field: "aggregate state",
            });
        }
        self.validate_observations()?;
        let mut operations = BTreeSet::new();
        if self
            .operation_statuses
            .iter()
            .any(|status| !operations.insert(status.operation))
        {
            return Err(ChargebeeModelError::DuplicateIdentifier);
        }
        if self.redaction.is_safe()
            && !self.connected
            && !self.native
            && !self.first_party
            && self.result_digest == self.recomputed_result_digest()?
            && self.evidence_digest == self.recomputed_digest()?
        {
            Ok(())
        } else {
            Err(ChargebeeModelError::Invalid {
                field: "aggregate evidence",
            })
        }
    }

    fn validate_observations(&self) -> Result<(), ChargebeeModelError> {
        if let Some(subscription) = &self.subscription
            && (subscription.id != self.scope.subscription_id
                || subscription.site_id != self.scope.site_id
                || subscription.customer_id != self.scope.customer_id
                || subscription.plan_id != self.scope.plan_id
                || subscription.revision != self.scope.subscription_revision)
        {
            return Err(ChargebeeModelError::ScopeMismatch);
        }
        for entitlement in &self.entitlements {
            if entitlement.id != self.scope.entitlement_id
                || entitlement.site_id != self.scope.site_id
                || entitlement.customer_id != self.scope.customer_id
                || entitlement.subscription_id != self.scope.subscription_id
                || entitlement.plan_id != self.scope.plan_id
                || entitlement.revision != self.scope.entitlement_revision
            {
                return Err(ChargebeeModelError::ScopeMismatch);
            }
        }
        for invoice in &self.invoices {
            if invoice.id != self.scope.invoice_id
                || invoice.site_id != self.scope.site_id
                || invoice.customer_id != self.scope.customer_id
                || invoice.subscription_id != self.scope.subscription_id
                || invoice.revision != self.scope.invoice_revision
            {
                return Err(ChargebeeModelError::ScopeMismatch);
            }
        }
        Ok(())
    }
}

fn aggregate_state(
    statuses: &[ChargebeeOperationStatus],
    partial: bool,
) -> ChargebeeObservationState {
    if let Some(status) = statuses
        .iter()
        .find(|status| matches!(status.state, ChargebeeObservationState::Tampered))
    {
        return status.state;
    }
    if statuses.iter().all(|status| status.state.is_complete()) && !partial {
        ChargebeeObservationState::Complete
    } else if let Some(first) = statuses.first()
        && (!partial || !first.state.is_complete())
        && statuses.iter().all(|status| status.state == first.state)
    {
        first.state
    } else {
        ChargebeeObservationState::Partial
    }
}

fn bool_marker(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// Digest-bound proposal emitted by the service and consumed by a Mission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeSubscriptionResultProposal {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub result_digest: Digest,
    pub evidence_digest: Digest,
    pub idempotency_keys: Vec<String>,
    pub evidence: ChargebeeEvidence,
    pub overall_state: ChargebeeObservationState,
    pub read_only: bool,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub subscription_mutation: bool,
    pub plan_mutation: bool,
    pub entitlement_mutation: bool,
    pub invoice_mutation: bool,
    pub refund: bool,
    pub payment_instruments: bool,
    pub raw_customer_pii: bool,
    pub financial_advice: bool,
    pub kernel_authority: bool,
    pub proposal_digest: Digest,
}

impl ChargebeeSubscriptionResultProposal {
    pub fn new(
        evidence: ChargebeeEvidence,
        idempotency_keys: Vec<String>,
    ) -> Result<Self, ChargebeeModelError> {
        evidence.validate()?;
        validate_idempotency_keys(&idempotency_keys)?;
        let mut proposal = Self {
            scope_digest: evidence.scope.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            result_digest: evidence.result_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            idempotency_keys,
            overall_state: evidence.overall_state,
            evidence,
            read_only: true,
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            subscription_mutation: false,
            plan_mutation: false,
            entitlement_mutation: false,
            invoice_mutation: false,
            refund: false,
            payment_instruments: false,
            raw_customer_pii: false,
            financial_advice: false,
            kernel_authority: false,
            proposal_digest: Digest::pending(),
        };
        proposal.proposal_digest = proposal.recomputed_digest()?;
        Ok(proposal)
    }

    pub fn recomputed_digest(&self) -> Result<Digest, ChargebeeModelError> {
        let idempotency_digest = digest_serializable(&self.idempotency_keys)?;
        let state = format!("{:?}", self.overall_state);
        Ok(Digest::from_fields([
            self.scope_digest.as_str(),
            self.registration_digest.as_str(),
            self.result_digest.as_str(),
            self.evidence_digest.as_str(),
            idempotency_digest.as_str(),
            state.as_str(),
            bool_marker(self.read_only),
            bool_marker(self.proposal_only),
            bool_marker(self.native),
            bool_marker(self.connected),
            bool_marker(self.first_party),
            bool_marker(self.subscription_mutation),
            bool_marker(self.plan_mutation),
            bool_marker(self.entitlement_mutation),
            bool_marker(self.invoice_mutation),
            bool_marker(self.refund),
            bool_marker(self.payment_instruments),
            bool_marker(self.raw_customer_pii),
            bool_marker(self.financial_advice),
            bool_marker(self.kernel_authority),
        ]))
    }

    pub fn validate(&self) -> Result<(), ChargebeeModelError> {
        self.evidence.validate()?;
        validate_idempotency_keys(&self.idempotency_keys)?;
        if self.scope_digest != self.evidence.scope.scope_digest
            || self.registration_digest != self.evidence.registration_digest
            || self.result_digest != self.evidence.result_digest
            || self.evidence_digest != self.evidence.evidence_digest
            || self.overall_state != self.evidence.overall_state
            || !self.read_only
            || !self.proposal_only
            || self.native
            || self.connected
            || self.first_party
            || self.subscription_mutation
            || self.plan_mutation
            || self.entitlement_mutation
            || self.invoice_mutation
            || self.refund
            || self.payment_instruments
            || self.raw_customer_pii
            || self.financial_advice
            || self.kernel_authority
            || self.proposal_digest != self.recomputed_digest()?
        {
            Err(ChargebeeModelError::Invalid { field: "proposal" })
        } else {
            Ok(())
        }
    }
}

/// Local record receipt; it is not a provider receipt or billing authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeRecordingReceipt {
    pub recorded: bool,
    pub idempotency_key: String,
    pub proposal_digest: Digest,
    pub result_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_mutated: bool,
    pub credential_material_retained: bool,
    pub durable_provider_receipt: bool,
    pub receipt_digest: Digest,
}

impl ChargebeeRecordingReceipt {
    pub fn new(
        proposal: &ChargebeeSubscriptionResultProposal,
    ) -> Result<Self, ChargebeeModelError> {
        let mut receipt = Self {
            recorded: true,
            idempotency_key: proposal
                .idempotency_keys
                .first()
                .cloned()
                .unwrap_or_default(),
            proposal_digest: proposal.proposal_digest.clone(),
            result_digest: proposal.result_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            provider_mutated: false,
            credential_material_retained: false,
            durable_provider_receipt: false,
            receipt_digest: Digest::pending(),
        };
        receipt.receipt_digest = digest_serializable(&(
            receipt.recorded,
            &receipt.idempotency_key,
            &receipt.proposal_digest,
            &receipt.result_digest,
            &receipt.evidence_digest,
            &receipt.registration_digest,
            receipt.provider_mutated,
            receipt.credential_material_retained,
            receipt.durable_provider_receipt,
        ))?;
        Ok(receipt)
    }
}

/// Local proposal verification receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeVerification {
    pub verified: bool,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub result_digest: Digest,
    pub registration_digest: Digest,
    pub provider_read_back_performed: bool,
    pub subscription_mutation_authority: bool,
    pub billing_authority: bool,
    pub consent_authority: bool,
    pub outcome_authority: bool,
    pub financial_advice: bool,
    pub verification_digest: Digest,
}

impl ChargebeeVerification {
    pub fn new(
        proposal: &ChargebeeSubscriptionResultProposal,
    ) -> Result<Self, ChargebeeModelError> {
        let mut value = Self {
            verified: true,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            result_digest: proposal.result_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            provider_read_back_performed: false,
            subscription_mutation_authority: false,
            billing_authority: false,
            consent_authority: false,
            outcome_authority: false,
            financial_advice: false,
            verification_digest: Digest::pending(),
        };
        value.verification_digest = digest_serializable(&(
            value.verified,
            &value.proposal_digest,
            &value.evidence_digest,
            &value.result_digest,
            &value.registration_digest,
            value.provider_read_back_performed,
            value.subscription_mutation_authority,
            value.billing_authority,
            value.consent_authority,
            value.outcome_authority,
            value.financial_advice,
        ))?;
        Ok(value)
    }
}

/// Independent read-back comparison receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeReadBackVerification {
    pub first_evidence_digest: Digest,
    pub read_back_evidence_digest: Digest,
    pub first_result_digest: Digest,
    pub read_back_result_digest: Digest,
    pub matched: bool,
    pub provider_read_back_performed: bool,
    pub verification_digest: Digest,
}

impl ChargebeeReadBackVerification {
    pub fn new(
        first: &ChargebeeEvidence,
        read_back: &ChargebeeEvidence,
    ) -> Result<Self, ChargebeeModelError> {
        first.validate()?;
        read_back.validate()?;
        let matched = first.scope.scope_digest == read_back.scope.scope_digest
            && first.registration_digest == read_back.registration_digest
            && first.result_digest == read_back.result_digest;
        let mut value = Self {
            first_evidence_digest: first.evidence_digest.clone(),
            read_back_evidence_digest: read_back.evidence_digest.clone(),
            first_result_digest: first.result_digest.clone(),
            read_back_result_digest: read_back.result_digest.clone(),
            matched,
            provider_read_back_performed: false,
            verification_digest: Digest::pending(),
        };
        value.verification_digest = digest_serializable(&(
            &value.first_evidence_digest,
            &value.read_back_evidence_digest,
            &value.first_result_digest,
            &value.read_back_result_digest,
            value.matched,
            value.provider_read_back_performed,
        ))?;
        Ok(value)
    }
}

/// Digest-bound reversible registration record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChargebeeRegistration {
    pub status: RegistrationStatus,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_implementation: String,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
}

/// Registration lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

impl RegistrationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

impl ChargebeeRegistration {
    pub fn new(
        scope: &ChargebeeSubscriptionScope,
        contract_digest: Digest,
        provider_digest: Digest,
        permission_digest: Digest,
        evidence_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            status: RegistrationStatus::Active,
            plugin_version: PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest,
            provider_id: PROVIDER_ID.to_owned(),
            provider_implementation: PROVIDER_IMPLEMENTATION.to_owned(),
            provider_version: PLUGIN_VERSION_TEXT.to_owned(),
            provider_revision: ProviderRevision::new(PROVIDER_REVISION_TEXT)
                .expect("static Chargebee provider revision is valid"),
            provider_digest,
            permission_digest,
            scope_digest: scope.scope_digest.clone(),
            evidence_digest,
            registration_digest: Digest::pending(),
        };
        registration.registration_digest = registration.recomputed_digest();
        registration
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn revoke(&mut self) -> Result<(), ChargebeeModelError> {
        if !self.is_active() {
            return Err(ChargebeeModelError::AlreadyRevoked);
        }
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_fields([
            self.status.as_str(),
            &self.plugin_version,
            &self.contract_version,
            self.contract_digest.as_str(),
            &self.provider_id,
            &self.provider_implementation,
            &self.provider_version,
            self.provider_revision.as_str(),
            self.provider_digest.as_str(),
            self.permission_digest.as_str(),
            self.scope_digest.as_str(),
            self.evidence_digest.as_str(),
        ])
    }

    pub fn validate(&self, scope: &ChargebeeSubscriptionScope) -> Result<(), ChargebeeModelError> {
        scope.validate()?;
        if self.scope_digest != *scope.scope_digest()
            || self.permission_digest != *scope.permission_digest()
            || self.registration_digest != self.recomputed_digest()
            || self.plugin_version != PLUGIN_VERSION_TEXT
            || self.contract_version != CONTRACT_VERSION
            || self.provider_id != PROVIDER_ID
            || self.provider_implementation != PROVIDER_IMPLEMENTATION
            || self.provider_version != PLUGIN_VERSION_TEXT
            || self.provider_revision.as_str() != PROVIDER_REVISION_TEXT
        {
            Err(ChargebeeModelError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

/// Build the deterministic idempotency key for a bounded read page.
pub fn deterministic_idempotency_key(
    scope_digest: &Digest,
    registration_digest: &Digest,
    query_digest: &Digest,
    cursor_digest: &Digest,
) -> String {
    let digest = Digest::from_fields([
        "hartevo.chargebee.subscription-result.idempotency/v1",
        scope_digest.as_str(),
        registration_digest.as_str(),
        query_digest.as_str(),
        cursor_digest.as_str(),
    ]);
    format!("chargebee-l1-{}", &digest.as_str()[..32])
}

fn validate_idempotency_keys(keys: &[String]) -> Result<(), ChargebeeModelError> {
    const PREFIX: &str = "chargebee-l1-";
    if keys.is_empty() || keys.len() > ChargebeeReadOperation::ALL.len() {
        return Err(ChargebeeModelError::Invalid {
            field: "idempotency keys",
        });
    }
    let mut unique = BTreeSet::new();
    for key in keys {
        let suffix = key
            .strip_prefix(PREFIX)
            .ok_or(ChargebeeModelError::Invalid {
                field: "idempotency key",
            })?;
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !unique.insert(key)
        {
            return Err(ChargebeeModelError::Invalid {
                field: "idempotency key",
            });
        }
    }
    Ok(())
}

/// Return the stable identity keys in a body as a set for pagination checks.
pub fn body_key_set(body: &ChargebeeResponseBody) -> Result<HashSet<String>, ChargebeeModelError> {
    let keys = body.keys();
    let set = keys.iter().cloned().collect::<HashSet<_>>();
    if set.len() != keys.len() {
        Err(ChargebeeModelError::DuplicateIdentifier)
    } else {
        Ok(set)
    }
}

/// Ensure a digest has the canonical lowercase shape.
pub fn validate_digest(value: &Digest, field: &'static str) -> Result<(), ChargebeeModelError> {
    if value.as_str().len() == 64
        && value
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ChargebeeModelError::InvalidDigest { field })
    }
}

/// Maximum page size used by the contract.
pub const fn max_page_size() -> u16 {
    MAX_PAGE_SIZE
}
