use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{BigCommerceOrderResultError, Result};
use crate::{MAX_FULFILLMENTS_PER_ORDER, MAX_IDENTIFIER_BYTES, MAX_TRANSACTIONS_PER_ORDER};

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    #[must_use]
    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for (name, value) in fields {
            append_field(&mut bytes, name);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    #[must_use]
    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(BigCommerceOrderResultError::InvalidDigest)
        }
    }

    pub fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(BigCommerceOrderResultError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
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

fn valid_identifier(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

macro_rules! identifier_type {
    ($name:ident, $domain:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(BigCommerceOrderResultError::InvalidIdentifier)
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if valid_identifier(&self.0) {
                    Ok(())
                } else {
                    Err(BigCommerceOrderResultError::InvalidIdentifier)
                }
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, &[("value", self.0.clone())])
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

identifier_type!(MissionId, "bigcommerce-mission-id/v1");
identifier_type!(ProjectId, "bigcommerce-project-id/v1");
identifier_type!(WorkProductId, "bigcommerce-work-product-id/v1");

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct StoreId(String);

impl StoreId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_identifier(&value) {
            Ok(Self(value))
        } else {
            Err(BigCommerceOrderResultError::InvalidIdentifier)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts("bigcommerce-store/v1", &[("store", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_identifier(&self.0) {
            Ok(())
        } else {
            Err(BigCommerceOrderResultError::InvalidIdentifier)
        }
    }
}

impl fmt::Debug for StoreId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("StoreId")
            .field(&self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OrderId(u64);

impl OrderId {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(BigCommerceOrderResultError::InvalidIdentifier)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub fn digest(self) -> Digest {
        Digest::from_parts("bigcommerce-order-id/v1", &[("order", self.0.to_string())])
    }

    pub(crate) const fn validate(self) -> Result<()> {
        if self.0 == 0 {
            Err(BigCommerceOrderResultError::InvalidIdentifier)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(BigCommerceOrderResultError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) const fn validate(self) -> Result<()> {
        if self.0 == 0 {
            Err(BigCommerceOrderResultError::InvalidRevision)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScope {
    id: MissionId,
    revision: Revision,
}

impl MissionScope {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }

    #[must_use]
    pub fn id(&self) -> &MissionId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "bigcommerce-mission-scope/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.revision.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectScope {
    id: ProjectId,
    revision: Revision,
}

impl ProjectScope {
    pub fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }

    #[must_use]
    pub fn id(&self) -> &ProjectId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "bigcommerce-project-scope/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.revision.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductScope {
    id: WorkProductId,
    revision: Revision,
}

impl WorkProductScope {
    pub fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }

    #[must_use]
    pub fn id(&self) -> &WorkProductId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "bigcommerce-work-product-scope/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.revision.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BigCommerceAuthKind {
    ApiToken,
    OAuth,
}

/// Opaque reference into a host-owned keyring or secret manager. The source
/// reference is digested immediately and is never retained, serialized, or
/// included in Debug output.
pub struct BigCommerceSecretReference {
    reference_digest: Digest,
    store_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: BigCommerceAuthKind,
    revoked: bool,
}

impl Clone for BigCommerceSecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            store_digest: self.store_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            auth_kind: self.auth_kind,
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for BigCommerceSecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BigCommerceSecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("store_digest", &self.store_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for BigCommerceSecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.store_digest == other.store_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.auth_kind == other.auth_kind
            && self.revoked == other.revoked
    }
}

impl Eq for BigCommerceSecretReference {}

impl BigCommerceSecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &BigCommerceOrderScope,
        credential_revision: Revision,
        auth_kind: BigCommerceAuthKind,
    ) -> Result<Self> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(BigCommerceOrderResultError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "bigcommerce-secret-reference/v1",
            &[
                ("reference", reference_id),
                ("store", scope.store.digest().as_str().to_owned()),
                ("scope", scope.scope_digest.as_str().to_owned()),
                ("revision", credential_revision.get().to_string()),
                ("auth", format!("{auth_kind:?}")),
            ],
        );
        Ok(Self {
            reference_digest,
            store_digest: scope.store.digest(),
            scope_digest: scope.scope_digest(),
            credential_revision,
            auth_kind,
            revoked: false,
        })
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn store_digest(&self) -> &Digest {
        &self.store_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    #[must_use]
    pub const fn auth_kind(&self) -> BigCommerceAuthKind {
        self.auth_kind
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn validate(&self, scope: &BigCommerceOrderScope) -> Result<()> {
        self.reference_digest.validate()?;
        self.store_digest.validate()?;
        self.scope_digest.validate()?;
        self.credential_revision.validate()?;
        if self.revoked {
            return Err(BigCommerceOrderResultError::SecretRevoked);
        }
        if self.store_digest != scope.store.digest() || self.scope_digest != scope.scope_digest() {
            Err(BigCommerceOrderResultError::InvalidSecretReference)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(BigCommerceOrderResultError::SecretRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Pending,
    AwaitingPayment,
    AwaitingFulfillment,
    AwaitingShipment,
    Shipped,
    Completed,
    Cancelled,
    Refunded,
    Disputed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Authorized,
    Captured,
    Settled,
    Voided,
    Refunded,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FulfillmentStatus {
    Pending,
    PartiallyFulfilled,
    Fulfilled,
    Cancelled,
    Unknown,
}

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ShipmentStatus {
    Pending,
    PartiallyShipped,
    Shipped,
    Delivered,
    Cancelled,
    #[default]
    Unknown,
}

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PaymentState {
    Pending,
    Authorized,
    Paid,
    PartiallyRefunded,
    Refunded,
    Failed,
    #[default]
    Unknown,
}

macro_rules! redacted_value {
    ($name:ident, $domain:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Digest);

        impl $name {
            #[must_use]
            pub fn from_value(value: impl AsRef<[u8]>) -> Self {
                Self(Digest::from_parts(
                    $domain,
                    &[(
                        "value",
                        String::from_utf8_lossy(value.as_ref()).into_owned(),
                    )],
                ))
            }

            pub fn from_digest(digest: Digest) -> Result<Self> {
                Digest::parse(digest.as_str().to_owned()).map(Self)
            }

            pub(crate) fn validate(&self) -> Result<()> {
                self.0.validate()
            }

            #[must_use]
            pub fn digest(&self) -> &Digest {
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

redacted_value!(OrderRevisionDigest, "bigcommerce-order-revision/v1");
redacted_value!(CustomerFingerprint, "bigcommerce-customer-fingerprint/v1");
redacted_value!(TransactionIdDigest, "bigcommerce-transaction-id/v1");
redacted_value!(FulfillmentIdDigest, "bigcommerce-fulfillment-id/v1");
redacted_value!(TrackingDigest, "bigcommerce-tracking/v1");
redacted_value!(AddressDigest, "bigcommerce-address/v1");
redacted_value!(EmailDigest, "bigcommerce-email/v1");
redacted_value!(LineItemDigest, "bigcommerce-line-items/v1");

pub type RevisionDigest = OrderRevisionDigest;

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AmountDigest {
    currency: String,
    amount_digest: Digest,
}

impl fmt::Debug for AmountDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AmountDigest")
            .field("currency", &self.currency)
            .field("amount_digest", &self.amount_digest)
            .finish()
    }
}

impl AmountDigest {
    pub fn from_decimal(currency: impl Into<String>, value: impl Into<String>) -> Result<Self> {
        let currency = currency.into().to_ascii_uppercase();
        let value =
            canonical_amount(&value.into()).ok_or(BigCommerceOrderResultError::InvalidAmount)?;
        if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(BigCommerceOrderResultError::InvalidAmount);
        }
        Ok(Self {
            amount_digest: Digest::from_parts(
                "bigcommerce-amount/v1",
                &[("currency", currency.clone()), ("value", value)],
            ),
            currency,
        })
    }

    pub fn from_digest(currency: impl Into<String>, amount_digest: Digest) -> Result<Self> {
        let currency = currency.into().to_ascii_uppercase();
        if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(BigCommerceOrderResultError::InvalidAmount);
        }
        amount_digest
            .validate()
            .map_err(|_| BigCommerceOrderResultError::InvalidAmount)?;
        Ok(Self {
            currency,
            amount_digest,
        })
    }

    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }

    #[must_use]
    pub fn amount_digest(&self) -> &Digest {
        &self.amount_digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.currency.len() == 3
            && self.currency.bytes().all(|byte| byte.is_ascii_uppercase())
            && is_digest(self.amount_digest.as_str())
        {
            Ok(())
        } else {
            Err(BigCommerceOrderResultError::InvalidAmount)
        }
    }
}

fn canonical_amount(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 64 || value.chars().any(char::is_whitespace) {
        return None;
    }
    let (negative, digits) = value
        .strip_prefix('-')
        .map_or((false, value), |rest| (true, rest));
    if digits.is_empty() || digits.matches('.').count() > 1 {
        return None;
    }
    let (whole, fraction) = digits.split_once('.').map_or((digits, ""), |parts| parts);
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 6
    {
        return None;
    }
    let whole = whole.trim_start_matches('0');
    let whole = if whole.is_empty() { "0" } else { whole };
    let fraction = fraction.trim_end_matches('0');
    let is_zero = whole == "0" && fraction.is_empty();
    let mut canonical = String::new();
    if negative && !is_zero {
        canonical.push('-');
    }
    canonical.push_str(whole);
    if !fraction.is_empty() {
        canonical.push('.');
        canonical.push_str(fraction);
    }
    Some(canonical)
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderDateFilter {
    pub min_created_at: Option<String>,
    pub max_created_at: Option<String>,
}

impl OrderDateFilter {
    pub fn new(min_created_at: Option<String>, max_created_at: Option<String>) -> Result<Self> {
        let filter = Self {
            min_created_at,
            max_created_at,
        };
        filter.validate()?;
        Ok(filter)
    }

    pub fn validate(&self) -> Result<()> {
        for value in [&self.min_created_at, &self.max_created_at]
            .into_iter()
            .flatten()
        {
            if value.is_empty()
                || value.len() > 64
                || value.trim() != value
                || value.chars().any(char::is_control)
            {
                return Err(BigCommerceOrderResultError::InvalidScope);
            }
        }
        if self
            .min_created_at
            .as_ref()
            .zip(self.max_created_at.as_ref())
            .is_some_and(|(min, max)| min > max)
        {
            return Err(BigCommerceOrderResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn from_strs(min_created_at: Option<&str>, max_created_at: Option<&str>) -> Result<Self> {
        Self::new(
            min_created_at.map(str::to_owned),
            max_created_at.map(str::to_owned),
        )
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "bigcommerce-order-date-filter/v1",
            &[
                (
                    "min_created_at",
                    self.min_created_at.clone().unwrap_or_default(),
                ),
                (
                    "max_created_at",
                    self.max_created_at.clone().unwrap_or_default(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderListFilter {
    pub statuses: BTreeSet<OrderStatus>,
    pub customer_fingerprints: BTreeSet<CustomerFingerprint>,
    pub date: Option<OrderDateFilter>,
}

impl OrderListFilter {
    pub fn new(
        statuses: impl IntoIterator<Item = OrderStatus>,
        customer_fingerprints: impl IntoIterator<Item = CustomerFingerprint>,
        date: Option<OrderDateFilter>,
    ) -> Self {
        Self {
            statuses: statuses.into_iter().collect(),
            customer_fingerprints: customer_fingerprints.into_iter().collect(),
            date,
        }
    }

    #[must_use]
    pub fn for_scope(scope: &BigCommerceOrderScope) -> Self {
        Self {
            statuses: scope.statuses.clone(),
            customer_fingerprints: scope.customer_fingerprints.clone(),
            date: None,
        }
    }

    pub fn validate_against(&self, scope: &BigCommerceOrderScope) -> Result<()> {
        if let Some(date) = &self.date {
            date.validate()?;
        }
        for customer in &self.customer_fingerprints {
            customer.validate()?;
        }
        if (!scope.statuses.is_empty() && !self.statuses.is_subset(&scope.statuses))
            || (!scope.customer_fingerprints.is_empty()
                && !self
                    .customer_fingerprints
                    .is_subset(&scope.customer_fingerprints))
        {
            Err(BigCommerceOrderResultError::ScopeMismatch)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "bigcommerce-order-list-filter/v1",
            &[
                (
                    "statuses",
                    self.statuses
                        .iter()
                        .map(|value| format!("{value:?}"))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "customers",
                    self.customer_fingerprints
                        .iter()
                        .map(|value| value.digest().as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "date",
                    self.date
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionEvidence {
    pub transaction_id_digest: TransactionIdDigest,
    pub status: TransactionStatus,
    pub amount: AmountDigest,
    pub revision_digest: OrderRevisionDigest,
    pub transaction_digest: Digest,
}

impl TransactionEvidence {
    pub fn new(
        transaction_id: impl AsRef<[u8]>,
        status: TransactionStatus,
        currency: impl Into<String>,
        amount: impl Into<String>,
        revision: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let transaction_id_digest = TransactionIdDigest::from_value(transaction_id);
        let amount = AmountDigest::from_decimal(currency, amount)?;
        let revision_digest = OrderRevisionDigest::from_value(revision);
        let transaction_digest =
            transaction_digest(&transaction_id_digest, status, &amount, &revision_digest);
        Ok(Self {
            transaction_id_digest,
            status,
            amount,
            revision_digest,
            transaction_digest,
        })
    }

    #[must_use]
    pub fn amount_digest(&self) -> &Digest {
        self.amount.amount_digest()
    }

    pub fn validate(&self) -> Result<()> {
        self.transaction_id_digest.validate()?;
        self.revision_digest.validate()?;
        self.amount.validate()?;
        if self.transaction_digest
            == transaction_digest(
                &self.transaction_id_digest,
                self.status,
                &self.amount,
                &self.revision_digest,
            )
        {
            Ok(())
        } else {
            Err(BigCommerceOrderResultError::DigestMismatch)
        }
    }
}

fn transaction_digest(
    transaction_id_digest: &TransactionIdDigest,
    status: TransactionStatus,
    amount: &AmountDigest,
    revision_digest: &OrderRevisionDigest,
) -> Digest {
    Digest::from_parts(
        "bigcommerce-transaction/v1",
        &[
            ("id", transaction_id_digest.digest().as_str().to_owned()),
            ("status", format!("{status:?}")),
            ("currency", amount.currency().to_owned()),
            ("amount", amount.amount_digest().as_str().to_owned()),
            ("revision", revision_digest.digest().as_str().to_owned()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FulfillmentEvidence {
    pub fulfillment_id_digest: FulfillmentIdDigest,
    pub status: FulfillmentStatus,
    pub quantity: u32,
    pub tracking_digest: Option<TrackingDigest>,
    pub revision_digest: OrderRevisionDigest,
    pub fulfillment_digest: Digest,
}

impl FulfillmentEvidence {
    pub fn new(
        fulfillment_id: impl AsRef<[u8]>,
        status: FulfillmentStatus,
        quantity: u32,
        tracking: Option<impl AsRef<[u8]>>,
        revision: impl AsRef<[u8]>,
    ) -> Result<Self> {
        if quantity == 0 {
            return Err(BigCommerceOrderResultError::InvalidEvidence);
        }
        let fulfillment_id_digest = FulfillmentIdDigest::from_value(fulfillment_id);
        let tracking_digest = tracking.map(TrackingDigest::from_value);
        let revision_digest = OrderRevisionDigest::from_value(revision);
        let fulfillment_digest = fulfillment_digest(
            &fulfillment_id_digest,
            status,
            quantity,
            tracking_digest.as_ref(),
            &revision_digest,
        );
        Ok(Self {
            fulfillment_id_digest,
            status,
            quantity,
            tracking_digest,
            revision_digest,
            fulfillment_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.fulfillment_id_digest.validate()?;
        if let Some(tracking) = &self.tracking_digest {
            tracking.validate()?;
        }
        self.revision_digest.validate()?;
        if self.quantity == 0
            || self.fulfillment_digest
                != fulfillment_digest(
                    &self.fulfillment_id_digest,
                    self.status,
                    self.quantity,
                    self.tracking_digest.as_ref(),
                    &self.revision_digest,
                )
        {
            Err(BigCommerceOrderResultError::DigestMismatch)
        } else {
            Ok(())
        }
    }
}

fn fulfillment_digest(
    fulfillment_id_digest: &FulfillmentIdDigest,
    status: FulfillmentStatus,
    quantity: u32,
    tracking_digest: Option<&TrackingDigest>,
    revision_digest: &OrderRevisionDigest,
) -> Digest {
    Digest::from_parts(
        "bigcommerce-fulfillment/v1",
        &[
            ("id", fulfillment_id_digest.digest().as_str().to_owned()),
            ("status", format!("{status:?}")),
            ("quantity", quantity.to_string()),
            (
                "tracking",
                tracking_digest
                    .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            ),
            ("revision", revision_digest.digest().as_str().to_owned()),
        ],
    )
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderRedactionMetadata {
    pub line_item_count: u32,
    pub shipment_status: ShipmentStatus,
    pub payment_state: PaymentState,
    pub shipping_address_digest: Option<AddressDigest>,
    pub billing_address_digest: Option<AddressDigest>,
    pub email_digest: Option<EmailDigest>,
    pub line_items_digest: Option<LineItemDigest>,
}

impl OrderRedactionMetadata {
    #[must_use]
    pub fn new(
        line_item_count: u32,
        shipment_status: ShipmentStatus,
        payment_state: PaymentState,
        shipping_address_digest: Option<AddressDigest>,
        billing_address_digest: Option<AddressDigest>,
        email_digest: Option<EmailDigest>,
        line_items_digest: Option<LineItemDigest>,
    ) -> Self {
        Self {
            line_item_count,
            shipment_status,
            payment_state,
            shipping_address_digest,
            billing_address_digest,
            email_digest,
            line_items_digest,
        }
    }

    #[must_use]
    pub fn from_values(
        line_item_count: u32,
        shipment_status: ShipmentStatus,
        payment_state: PaymentState,
        shipping_address: Option<&str>,
        billing_address: Option<&str>,
        email: Option<&str>,
        line_items: Option<&str>,
    ) -> Self {
        Self {
            line_item_count,
            shipment_status,
            payment_state,
            shipping_address_digest: shipping_address.map(AddressDigest::from_value),
            billing_address_digest: billing_address.map(AddressDigest::from_value),
            email_digest: email.map(EmailDigest::from_value),
            line_items_digest: line_items.map(LineItemDigest::from_value),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.line_item_count > 10_000 {
            return Err(BigCommerceOrderResultError::ResponseBoundExceeded);
        }
        if let Some(digest) = &self.shipping_address_digest {
            digest.validate()?;
        }
        if let Some(digest) = &self.billing_address_digest {
            digest.validate()?;
        }
        if let Some(digest) = &self.email_digest {
            digest.validate()?;
        }
        if let Some(digest) = &self.line_items_digest {
            digest.validate()?;
        }
        Ok(())
    }

    fn digest(&self) -> Digest {
        Digest::from_parts(
            "bigcommerce-order-redaction-metadata/v1",
            &[
                ("line_item_count", self.line_item_count.to_string()),
                ("shipment_status", format!("{:?}", self.shipment_status)),
                ("payment_state", format!("{:?}", self.payment_state)),
                (
                    "shipping_address",
                    self.shipping_address_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "billing_address",
                    self.billing_address_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "email",
                    self.email_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "line_items",
                    self.line_items_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BigCommerceOrderSnapshot {
    pub store: StoreId,
    pub order_id: OrderId,
    pub customer_fingerprint: CustomerFingerprint,
    pub status: OrderStatus,
    pub revision_digest: OrderRevisionDigest,
    pub total_amount: AmountDigest,
    pub transactions: Vec<TransactionEvidence>,
    pub fulfillments: Vec<FulfillmentEvidence>,
    pub line_item_count: u32,
    pub shipment_status: ShipmentStatus,
    pub payment_state: PaymentState,
    pub shipping_address_digest: Option<AddressDigest>,
    pub billing_address_digest: Option<AddressDigest>,
    pub email_digest: Option<EmailDigest>,
    pub line_items_digest: Option<LineItemDigest>,
    pub order_digest: Digest,
}

impl BigCommerceOrderSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: StoreId,
        order_id: OrderId,
        customer_value: impl AsRef<[u8]>,
        status: OrderStatus,
        revision: impl AsRef<[u8]>,
        total_currency: impl Into<String>,
        total_amount: impl Into<String>,
        transactions: Vec<TransactionEvidence>,
        fulfillments: Vec<FulfillmentEvidence>,
    ) -> Result<Self> {
        Self::from_redacted_with_metadata(
            store,
            order_id,
            CustomerFingerprint::from_value(customer_value),
            status,
            OrderRevisionDigest::from_value(revision),
            AmountDigest::from_decimal(total_currency, total_amount)?,
            transactions,
            fulfillments,
            OrderRedactionMetadata::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_redacted(
        store: StoreId,
        order_id: OrderId,
        customer_fingerprint: CustomerFingerprint,
        status: OrderStatus,
        revision_digest: OrderRevisionDigest,
        total_amount: AmountDigest,
        transactions: Vec<TransactionEvidence>,
        fulfillments: Vec<FulfillmentEvidence>,
    ) -> Result<Self> {
        Self::from_redacted_with_metadata(
            store,
            order_id,
            customer_fingerprint,
            status,
            revision_digest,
            total_amount,
            transactions,
            fulfillments,
            OrderRedactionMetadata::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_redacted_with_metadata(
        store: StoreId,
        order_id: OrderId,
        customer_fingerprint: CustomerFingerprint,
        status: OrderStatus,
        revision_digest: OrderRevisionDigest,
        total_amount: AmountDigest,
        transactions: Vec<TransactionEvidence>,
        fulfillments: Vec<FulfillmentEvidence>,
        metadata: OrderRedactionMetadata,
    ) -> Result<Self> {
        store.validate()?;
        order_id.validate()?;
        customer_fingerprint.validate()?;
        revision_digest.validate()?;
        if transactions.len() > MAX_TRANSACTIONS_PER_ORDER
            || fulfillments.len() > MAX_FULFILLMENTS_PER_ORDER
        {
            return Err(BigCommerceOrderResultError::ResponseBoundExceeded);
        }
        let mut transaction_ids = BTreeSet::new();
        for transaction in &transactions {
            transaction.validate()?;
            if transaction.amount.currency() != total_amount.currency() {
                return Err(BigCommerceOrderResultError::InvalidAmount);
            }
            if !transaction_ids.insert(transaction.transaction_id_digest.clone()) {
                return Err(BigCommerceOrderResultError::DuplicateEvidence);
            }
        }
        let mut fulfillment_ids = BTreeSet::new();
        for fulfillment in &fulfillments {
            fulfillment.validate()?;
            if !fulfillment_ids.insert(fulfillment.fulfillment_id_digest.clone()) {
                return Err(BigCommerceOrderResultError::DuplicateEvidence);
            }
        }
        total_amount.validate()?;
        metadata.validate()?;
        let order_digest = order_digest(
            &store,
            order_id,
            &customer_fingerprint,
            status,
            &revision_digest,
            &total_amount,
            &transactions,
            &fulfillments,
            &metadata,
        );
        Ok(Self {
            store,
            order_id,
            customer_fingerprint,
            status,
            revision_digest,
            total_amount,
            transactions,
            fulfillments,
            line_item_count: metadata.line_item_count,
            shipment_status: metadata.shipment_status,
            payment_state: metadata.payment_state,
            shipping_address_digest: metadata.shipping_address_digest,
            billing_address_digest: metadata.billing_address_digest,
            email_digest: metadata.email_digest,
            line_items_digest: metadata.line_items_digest,
            order_digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.order_digest
    }

    #[must_use]
    pub fn order_revision_digest(&self) -> &Digest {
        self.revision_digest.digest()
    }

    #[must_use]
    pub fn amount_digest(&self) -> &Digest {
        self.total_amount.amount_digest()
    }

    #[must_use]
    pub fn customer_fingerprint_digest(&self) -> &Digest {
        self.customer_fingerprint.digest()
    }

    #[must_use]
    pub fn redaction_metadata(&self) -> OrderRedactionMetadata {
        OrderRedactionMetadata {
            line_item_count: self.line_item_count,
            shipment_status: self.shipment_status,
            payment_state: self.payment_state,
            shipping_address_digest: self.shipping_address_digest.clone(),
            billing_address_digest: self.billing_address_digest.clone(),
            email_digest: self.email_digest.clone(),
            line_items_digest: self.line_items_digest.clone(),
        }
    }

    #[must_use]
    pub fn revision_digests(&self) -> Vec<Digest> {
        let mut digests = BTreeSet::from([self.revision_digest.digest().clone()]);
        digests.extend(
            self.transactions
                .iter()
                .map(|value| value.revision_digest.digest().clone()),
        );
        digests.extend(
            self.fulfillments
                .iter()
                .map(|value| value.revision_digest.digest().clone()),
        );
        digests.into_iter().collect()
    }

    #[must_use]
    pub fn amount_digests(&self) -> Vec<Digest> {
        let mut digests = BTreeSet::from([self.total_amount.amount_digest().clone()]);
        digests.extend(
            self.transactions
                .iter()
                .map(TransactionEvidence::amount_digest)
                .cloned(),
        );
        digests.into_iter().collect()
    }

    pub fn validate(&self) -> Result<()> {
        let rebuilt = Self::from_redacted_with_metadata(
            self.store.clone(),
            self.order_id,
            self.customer_fingerprint.clone(),
            self.status,
            self.revision_digest.clone(),
            self.total_amount.clone(),
            self.transactions.clone(),
            self.fulfillments.clone(),
            self.redaction_metadata(),
        )?;
        if rebuilt.order_digest == self.order_digest {
            Ok(())
        } else {
            Err(BigCommerceOrderResultError::DigestMismatch)
        }
    }
}

fn order_digest(
    store: &StoreId,
    order_id: OrderId,
    customer_fingerprint: &CustomerFingerprint,
    status: OrderStatus,
    revision_digest: &OrderRevisionDigest,
    total_amount: &AmountDigest,
    transactions: &[TransactionEvidence],
    fulfillments: &[FulfillmentEvidence],
    metadata: &OrderRedactionMetadata,
) -> Digest {
    let transaction_digests = transactions
        .iter()
        .map(|value| value.transaction_digest.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let fulfillment_digests = fulfillments
        .iter()
        .map(|value| value.fulfillment_digest.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Digest::from_parts(
        "bigcommerce-order-snapshot/v1",
        &[
            ("store", store.digest().as_str().to_owned()),
            ("order", order_id.get().to_string()),
            (
                "customer",
                customer_fingerprint.digest().as_str().to_owned(),
            ),
            ("status", format!("{status:?}")),
            ("revision", revision_digest.digest().as_str().to_owned()),
            ("currency", total_amount.currency().to_owned()),
            ("amount", total_amount.amount_digest().as_str().to_owned()),
            ("transactions", transaction_digests),
            ("fulfillments", fulfillment_digests),
            ("metadata", metadata.digest().as_str().to_owned()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BigCommerceOrderScope {
    pub(crate) store: StoreId,
    pub(crate) order_ids: BTreeSet<OrderId>,
    pub(crate) customer_fingerprints: BTreeSet<CustomerFingerprint>,
    pub(crate) statuses: BTreeSet<OrderStatus>,
    pub(crate) include_transactions: bool,
    pub(crate) include_fulfillments: bool,
    pub(crate) transaction_statuses: BTreeSet<TransactionStatus>,
    pub(crate) fulfillment_statuses: BTreeSet<FulfillmentStatus>,
    pub(crate) mission: MissionScope,
    pub(crate) project: ProjectScope,
    pub(crate) work_product: WorkProductScope,
    pub(crate) permission_digest: Digest,
    pub(crate) consent_digest: Digest,
    pub(crate) scope_digest: Digest,
}

impl BigCommerceOrderScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: StoreId,
        order_ids: impl IntoIterator<Item = OrderId>,
        customer_fingerprints: impl IntoIterator<Item = CustomerFingerprint>,
        statuses: impl IntoIterator<Item = OrderStatus>,
        include_transactions: bool,
        include_fulfillments: bool,
        mission: MissionScope,
        project: ProjectScope,
        work_product: WorkProductScope,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self> {
        let order_ids = order_ids.into_iter().collect::<BTreeSet<_>>();
        let customer_fingerprints = customer_fingerprints.into_iter().collect::<BTreeSet<_>>();
        let statuses = statuses.into_iter().collect::<BTreeSet<_>>();
        let transaction_statuses = BTreeSet::new();
        let fulfillment_statuses = BTreeSet::new();
        let scope_digest = scope_digest(
            &store,
            &order_ids,
            &customer_fingerprints,
            &statuses,
            include_transactions,
            include_fulfillments,
            &transaction_statuses,
            &fulfillment_statuses,
            &mission,
            &project,
            &work_product,
            &permission_digest,
            &consent_digest,
        );
        let scope = Self {
            store,
            order_ids,
            customer_fingerprints,
            statuses,
            include_transactions,
            include_fulfillments,
            transaction_statuses,
            fulfillment_statuses,
            mission,
            project,
            work_product,
            permission_digest,
            consent_digest,
            scope_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[must_use]
    pub fn store(&self) -> &StoreId {
        &self.store
    }

    #[must_use]
    pub fn order_ids(&self) -> &BTreeSet<OrderId> {
        &self.order_ids
    }

    #[must_use]
    pub fn customer_fingerprints(&self) -> &BTreeSet<CustomerFingerprint> {
        &self.customer_fingerprints
    }

    #[must_use]
    pub fn statuses(&self) -> &BTreeSet<OrderStatus> {
        &self.statuses
    }

    #[must_use]
    pub const fn include_transactions(&self) -> bool {
        self.include_transactions
    }

    #[must_use]
    pub const fn include_fulfillments(&self) -> bool {
        self.include_fulfillments
    }

    #[must_use]
    pub fn transaction_statuses(&self) -> &BTreeSet<TransactionStatus> {
        &self.transaction_statuses
    }

    #[must_use]
    pub fn fulfillment_statuses(&self) -> &BTreeSet<FulfillmentStatus> {
        &self.fulfillment_statuses
    }

    pub fn with_detail_statuses(
        mut self,
        transaction_statuses: impl IntoIterator<Item = TransactionStatus>,
        fulfillment_statuses: impl IntoIterator<Item = FulfillmentStatus>,
    ) -> Result<Self> {
        self.transaction_statuses = transaction_statuses.into_iter().collect();
        self.fulfillment_statuses = fulfillment_statuses.into_iter().collect();
        self.scope_digest = scope_digest(
            &self.store,
            &self.order_ids,
            &self.customer_fingerprints,
            &self.statuses,
            self.include_transactions,
            self.include_fulfillments,
            &self.transaction_statuses,
            &self.fulfillment_statuses,
            &self.mission,
            &self.project,
            &self.work_product,
            &self.permission_digest,
            &self.consent_digest,
        );
        self.validate()?;
        Ok(self)
    }

    #[must_use]
    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    #[must_use]
    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    #[must_use]
    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    #[must_use]
    pub fn fence(&self) -> PermissionFence {
        PermissionFence {
            scope_digest: self.scope_digest(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            work_product_revision: self.work_product.revision,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.store.validate()?;
        for order_id in &self.order_ids {
            order_id.validate()?;
        }
        for customer in &self.customer_fingerprints {
            customer.validate()?;
        }
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        self.permission_digest.validate()?;
        self.consent_digest.validate()?;
        if self.scope_digest
            != scope_digest(
                &self.store,
                &self.order_ids,
                &self.customer_fingerprints,
                &self.statuses,
                self.include_transactions,
                self.include_fulfillments,
                &self.transaction_statuses,
                &self.fulfillment_statuses,
                &self.mission,
                &self.project,
                &self.work_product,
                &self.permission_digest,
                &self.consent_digest,
            )
        {
            Err(BigCommerceOrderResultError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn allows(&self, order: &BigCommerceOrderSnapshot) -> Result<()> {
        if order.store != self.store
            || (!self.order_ids.is_empty() && !self.order_ids.contains(&order.order_id))
            || (!self.customer_fingerprints.is_empty()
                && !self
                    .customer_fingerprints
                    .contains(&order.customer_fingerprint))
            || (!self.statuses.is_empty() && !self.statuses.contains(&order.status))
            || (!self.include_transactions && !order.transactions.is_empty())
            || (!self.include_fulfillments && !order.fulfillments.is_empty())
            || (!self.transaction_statuses.is_empty()
                && order
                    .transactions
                    .iter()
                    .any(|value| !self.transaction_statuses.contains(&value.status)))
            || (!self.fulfillment_statuses.is_empty()
                && order
                    .fulfillments
                    .iter()
                    .any(|value| !self.fulfillment_statuses.contains(&value.status)))
        {
            Err(BigCommerceOrderResultError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

fn scope_digest(
    store: &StoreId,
    order_ids: &BTreeSet<OrderId>,
    customer_fingerprints: &BTreeSet<CustomerFingerprint>,
    statuses: &BTreeSet<OrderStatus>,
    include_transactions: bool,
    include_fulfillments: bool,
    transaction_statuses: &BTreeSet<TransactionStatus>,
    fulfillment_statuses: &BTreeSet<FulfillmentStatus>,
    mission: &MissionScope,
    project: &ProjectScope,
    work_product: &WorkProductScope,
    permission_digest: &Digest,
    consent_digest: &Digest,
) -> Digest {
    Digest::from_parts(
        "bigcommerce-order-scope/v1",
        &[
            ("store", store.digest().as_str().to_owned()),
            (
                "orders",
                order_ids
                    .iter()
                    .map(|value| value.get().to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "customers",
                customer_fingerprints
                    .iter()
                    .map(|value| value.digest().as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "statuses",
                statuses
                    .iter()
                    .map(|value| format!("{value:?}"))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("transactions", include_transactions.to_string()),
            ("fulfillments", include_fulfillments.to_string()),
            (
                "transaction_statuses",
                transaction_statuses
                    .iter()
                    .map(|value| format!("{value:?}"))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "fulfillment_statuses",
                fulfillment_statuses
                    .iter()
                    .map(|value| format!("{value:?}"))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("mission", mission.digest().as_str().to_owned()),
            ("project", project.digest().as_str().to_owned()),
            ("work_product", work_product.digest().as_str().to_owned()),
            ("permission", permission_digest.as_str().to_owned()),
            ("consent", consent_digest.as_str().to_owned()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub work_product_revision: Revision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}
