//! Bounded, redacted Shopify order-result model types.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    SHOPIFY_ADMIN_API_VERSION, SHOPIFY_ORDER_RESULT_CONTRACT_VERSION,
    SHOPIFY_ORDER_RESULT_PLUGIN_VERSION,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TIMESTAMP_BYTES: usize = 64;
pub const MAX_POLICY_REVISION_BYTES: usize = 128;
pub const MAX_AMOUNT_BYTES: usize = 64;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 25;
pub const MAX_FULFILLMENT_ORDERS: usize = 64;
pub const MAX_FULFILLMENTS: usize = 64;
pub const MAX_REFUNDS: usize = 64;
pub const MAX_TRANSACTIONS: usize = 128;
pub const MAX_RETRY_ATTEMPTS: u8 = 3;
pub const MAX_RETRY_AFTER_MILLISECONDS: u64 = 600_000;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a supported Shopify Admin API version")]
    InvalidApiVersion { field: &'static str },
    #[error("{field} must contain at least one permission")]
    EmptyPermissions { field: &'static str },
    #[error("{field} must contain read_orders")]
    MissingOrderPermission { field: &'static str },
    #[error("{field} has duplicate permissions")]
    DuplicatePermission { field: &'static str },
    #[error("{field} is not a bounded decimal amount")]
    InvalidAmount { field: &'static str },
}

fn validate_text(
    value: &str,
    field: &'static str,
    max: usize,
    allow_internal_whitespace: bool,
) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max || value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidText { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ModelError::InvalidDigest { field });
    }
    Ok(())
}

/// A deterministic SHA-256 digest used as a revision fence.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn sha256(bytes: impl AsRef<[u8]>) -> Self {
        let digest = Sha256::digest(bytes.as_ref());
        Self(hex_encode(digest))
    }

    pub fn from_text(value: impl AsRef<str>) -> Self {
        Self::sha256(value.as_ref().as_bytes())
    }

    pub fn from_fields(label: &str, fields: &[String]) -> Self {
        let mut material = Vec::new();
        material.extend_from_slice(label.as_bytes());
        material.push(0);
        for field in fields {
            material.extend_from_slice(field.as_bytes());
            material.push(0);
        }
        Self::sha256(material)
    }

    pub fn from_serializable<T: Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("Layer-1 digest material is serializable");
        Self::sha256(bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        validate_digest(&value, "digest")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_sha256(&self) -> bool {
        self.0.len() == 64 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit())
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

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

/// Positive revision used for Project, Mission, Work Product, policy, and
/// credential/permission leases.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $max:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, $max, false)?;
                Ok(Self(value))
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
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

bounded_identifier!(ShopifyId, "Shopify resource id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(ProjectId, "Project id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(MissionId, "Mission id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(WorkProductId, "Work Product id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(PolicyRevision, "policy revision", MAX_POLICY_REVISION_BYTES);
bounded_identifier!(ProviderRevision, "provider revision", MAX_IDENTIFIER_BYTES);

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ShopDomain(String);

impl ShopDomain {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        validate_text(&value, "shop domain", MAX_IDENTIFIER_BYTES, false)?;
        if value.contains('/')
            || value.contains(':')
            || value.contains('?')
            || value.contains('#')
            || !value.contains('.')
            || value.starts_with('.')
            || value.ends_with('.')
            || value.split('.').any(|label| {
                label.is_empty()
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err(ModelError::InvalidCharacters {
                field: "shop domain",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn admin_graphql_endpoint(&self) -> String {
        format!(
            "https://{}/admin/api/{}/graphql.json",
            self.as_str(),
            SHOPIFY_ADMIN_API_VERSION
        )
    }
}

impl fmt::Debug for ShopDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ShopDomain").field(&self.0).finish()
    }
}

impl fmt::Display for ShopDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ShopifyApiVersion(String);

impl ShopifyApiVersion {
    pub fn pinned() -> Self {
        Self(SHOPIFY_ADMIN_API_VERSION.to_owned())
    }

    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value != SHOPIFY_ADMIN_API_VERSION {
            return Err(ModelError::InvalidApiVersion {
                field: "Shopify Admin API version",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A host-owned handle to a Shopify Admin API token. The handle and token
/// material are never retained or serialized; only this digest crosses a
/// registration, proposal, or evidence boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    credential_revision: Revision,
}

impl SecretReference {
    pub fn new(
        opaque_reference: impl AsRef<str>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let opaque_reference = opaque_reference.as_ref();
        validate_text(
            opaque_reference,
            "opaque secret reference",
            MAX_IDENTIFIER_BYTES,
            false,
        )?;
        let credential_revision = Revision::new(credential_revision)?;
        let reference_digest = Digest::from_fields(
            "hartevo:shopify-secret-reference/v1",
            &[
                opaque_reference.to_owned(),
                credential_revision.get().to_string(),
            ],
        );
        Ok(Self {
            reference_digest,
            credential_revision,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("credential_revision", &self.credential_revision)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShopifyPermission {
    ReadOrders,
    ReadAllOrders,
    ReadMerchantManagedFulfillmentOrders,
    ReadAssignedFulfillmentOrders,
    ReadThirdPartyFulfillmentOrders,
}

impl ShopifyPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOrders => "read_orders",
            Self::ReadAllOrders => "read_all_orders",
            Self::ReadMerchantManagedFulfillmentOrders => {
                "read_merchant_managed_fulfillment_orders"
            }
            Self::ReadAssignedFulfillmentOrders => "read_assigned_fulfillment_orders",
            Self::ReadThirdPartyFulfillmentOrders => "read_third_party_fulfillment_orders",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionLease {
    permissions: Vec<ShopifyPermission>,
    revision: Revision,
    expires_at_epoch_seconds: Option<u64>,
}

impl PermissionLease {
    pub fn new(
        mut permissions: Vec<ShopifyPermission>,
        revision: u64,
        expires_at_epoch_seconds: Option<u64>,
    ) -> Result<Self, ModelError> {
        if permissions.is_empty() {
            return Err(ModelError::EmptyPermissions {
                field: "permission lease",
            });
        }
        if !permissions.contains(&ShopifyPermission::ReadOrders) {
            return Err(ModelError::MissingOrderPermission {
                field: "permission lease",
            });
        }
        let input_len = permissions.len();
        permissions.sort_unstable();
        permissions.dedup();
        if input_len != permissions.len() {
            return Err(ModelError::DuplicatePermission {
                field: "permission lease",
            });
        }
        if let Some(expires_at) = expires_at_epoch_seconds {
            validate_positive(expires_at, "permission expiry")?;
        }
        Ok(Self {
            permissions,
            revision: Revision::new(revision)?,
            expires_at_epoch_seconds,
        })
    }

    pub fn permissions(&self) -> &[ShopifyPermission] {
        &self.permissions
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn expires_at_epoch_seconds(&self) -> Option<u64> {
        self.expires_at_epoch_seconds
    }

    pub fn is_expired(&self, now_epoch_seconds: u64) -> bool {
        self.expires_at_epoch_seconds
            .is_some_and(|expires_at| now_epoch_seconds >= expires_at)
    }

    pub fn permission_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo:shopify-permission-lease/v1",
            &[
                self.permissions
                    .iter()
                    .map(|permission| permission.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                self.revision.get().to_string(),
                self.expires_at_epoch_seconds
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
            ],
        )
    }
}

macro_rules! revisioned_scope {
    ($name:ident, $field:literal, $id:ty) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            id: $id,
            revision: Revision,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
                Ok(Self {
                    id: <$id>::new(id)?,
                    revision: Revision::new(revision)?,
                })
            }

            pub fn id(&self) -> &$id {
                &self.id
            }

            pub const fn revision(&self) -> Revision {
                self.revision
            }

            fn digest_fields(&self) -> Vec<String> {
                vec![self.id.as_str().to_owned(), self.revision.get().to_string()]
            }
        }
    };
}

revisioned_scope!(ProjectScope, "project", ProjectId);
revisioned_scope!(MissionScope, "mission", MissionId);
revisioned_scope!(WorkProductScope, "work product", WorkProductId);

#[derive(Clone, Eq, PartialEq)]
pub struct ShopifyOrderResultScope {
    api_version: ShopifyApiVersion,
    shop: ShopDomain,
    order_id: ShopifyId,
    secret_reference: SecretReference,
    permission_lease: PermissionLease,
    project: ProjectScope,
    mission: MissionScope,
    work_product: WorkProductScope,
    policy_revision: PolicyRevision,
    scope_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShopifyOrderResultScopeInput {
    pub api_version: ShopifyApiVersion,
    pub shop: ShopDomain,
    pub order_id: ShopifyId,
    pub secret_reference: SecretReference,
    pub permission_lease: PermissionLease,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub policy_revision: PolicyRevision,
}

impl ShopifyOrderResultScope {
    pub fn new(input: ShopifyOrderResultScopeInput) -> Result<Self, ModelError> {
        let scope_digest = Digest::from_fields(
            "hartevo:shopify-order-result-scope/v1",
            &[
                SHOPIFY_ORDER_RESULT_PLUGIN_VERSION.to_owned(),
                SHOPIFY_ORDER_RESULT_CONTRACT_VERSION.to_owned(),
                input.api_version.as_str().to_owned(),
                input.shop.as_str().to_owned(),
                input.order_id.as_str().to_owned(),
                input
                    .secret_reference
                    .reference_digest()
                    .as_str()
                    .to_owned(),
                input
                    .permission_lease
                    .permission_digest()
                    .as_str()
                    .to_owned(),
                input.project.digest_fields().join("|"),
                input.mission.digest_fields().join("|"),
                input.work_product.digest_fields().join("|"),
                input.policy_revision.as_str().to_owned(),
            ],
        );
        Ok(Self {
            api_version: input.api_version,
            shop: input.shop,
            order_id: input.order_id,
            secret_reference: input.secret_reference,
            permission_lease: input.permission_lease,
            project: input.project,
            mission: input.mission,
            work_product: input.work_product,
            policy_revision: input.policy_revision,
            scope_digest,
        })
    }

    pub fn api_version(&self) -> &ShopifyApiVersion {
        &self.api_version
    }

    pub fn shop(&self) -> &ShopDomain {
        &self.shop
    }

    pub fn order_id(&self) -> &ShopifyId {
        &self.order_id
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn permission_lease(&self) -> &PermissionLease {
        &self.permission_lease
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission_lease.permission_digest()
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

    pub fn policy_revision(&self) -> &PolicyRevision {
        &self.policy_revision
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
}

impl fmt::Debug for ShopifyOrderResultScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShopifyOrderResultScope")
            .field("api_version", &self.api_version)
            .field("shop", &self.shop)
            .field("order_id", &self.order_id)
            .field("secret_reference", &self.secret_reference)
            .field("permission_lease", &self.permission_lease)
            .field("permission_digest", &self.permission_digest())
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .field("policy_revision", &self.policy_revision)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Money {
    amount: String,
    currency_code: String,
}

impl Money {
    pub fn new(
        amount: impl Into<String>,
        currency_code: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let amount = amount.into();
        let currency_code = currency_code.into().to_ascii_uppercase();
        validate_text(&amount, "money amount", MAX_AMOUNT_BYTES, false)?;
        if !is_decimal_amount(&amount) {
            return Err(ModelError::InvalidAmount {
                field: "money amount",
            });
        }
        if currency_code.len() != 3 || !currency_code.bytes().all(|byte| byte.is_ascii_uppercase())
        {
            return Err(ModelError::InvalidCharacters {
                field: "currency code",
            });
        }
        Ok(Self {
            amount,
            currency_code,
        })
    }

    pub fn amount(&self) -> &str {
        &self.amount
    }

    pub fn currency_code(&self) -> &str {
        &self.currency_code
    }
}

fn is_decimal_amount(value: &str) -> bool {
    let mut digits = 0;
    let mut decimal_points = 0;
    for (index, byte) in value.bytes().enumerate() {
        if byte.is_ascii_digit() {
            digits += 1;
        } else if byte == b'.' {
            decimal_points += 1;
            if decimal_points > 1 || index == 0 || index + 1 == value.len() {
                return false;
            }
        } else if byte == b'-' {
            if index != 0 {
                return false;
            }
        } else {
            return false;
        }
    }
    digits > 0
}

bounded_identifier!(RevisionStamp, "provider timestamp", MAX_TIMESTAMP_BYTES);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Pending,
    Authorized,
    Succeeded,
    Failed,
    PartiallyRefunded,
    Refunded,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FulfillmentState {
    Unfulfilled,
    Pending,
    InProgress,
    PartiallyFulfilled,
    Fulfilled,
    Cancelled,
    Unknown,
}

pub type PaymentState = TransactionState;
pub type RefundState = TransactionState;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FulfillmentOrderProjection {
    pub id: ShopifyId,
    pub status: String,
    pub request_status: String,
    pub created_at: Option<RevisionStamp>,
    pub updated_at: Option<RevisionStamp>,
    pub state: FulfillmentState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FulfillmentProjection {
    pub id: ShopifyId,
    pub status: String,
    pub created_at: Option<RevisionStamp>,
    pub updated_at: Option<RevisionStamp>,
    pub state: FulfillmentState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefundProjection {
    pub id: ShopifyId,
    pub created_at: Option<RevisionStamp>,
    pub processed_at: Option<RevisionStamp>,
    pub updated_at: Option<RevisionStamp>,
    pub total_refunded: Option<Money>,
    pub state: RefundState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransactionProjection {
    pub id: ShopifyId,
    pub kind: String,
    pub state: PaymentState,
    pub amount: Option<Money>,
    pub created_at: Option<RevisionStamp>,
    pub processed_at: Option<RevisionStamp>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    MorePages,
    CollectionBound,
    GraphqlErrors,
    MissingField,
    UnknownStatus,
    RevisionUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyOrderProjectionInput {
    pub order_id: ShopifyId,
    pub updated_at: RevisionStamp,
    pub created_at: Option<RevisionStamp>,
    pub currency_code: String,
    pub financial_state: TransactionState,
    pub fulfillment_state: FulfillmentState,
    pub current_total: Option<Money>,
    pub total_refunded: Option<Money>,
    pub fulfillment_orders: Vec<FulfillmentOrderProjection>,
    pub fulfillments: Vec<FulfillmentProjection>,
    pub refunds: Vec<RefundProjection>,
    pub transactions: Vec<TransactionProjection>,
    pub partial_reasons: Vec<PartialReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyOrderProjection {
    pub order_id: ShopifyId,
    pub order_revision_digest: Digest,
    pub updated_at: RevisionStamp,
    pub created_at: Option<RevisionStamp>,
    pub currency_code: String,
    pub financial_state: TransactionState,
    pub fulfillment_state: FulfillmentState,
    pub current_total: Option<Money>,
    pub total_refunded: Option<Money>,
    pub fulfillment_orders: Vec<FulfillmentOrderProjection>,
    pub fulfillments: Vec<FulfillmentProjection>,
    pub refunds: Vec<RefundProjection>,
    pub transactions: Vec<TransactionProjection>,
    pub partial_reasons: Vec<PartialReason>,
}

#[derive(Clone, Debug, Serialize)]
struct ProjectionFingerprint<'a> {
    order_id: &'a ShopifyId,
    updated_at: &'a RevisionStamp,
    created_at: &'a Option<RevisionStamp>,
    currency_code: &'a str,
    financial_state: TransactionState,
    fulfillment_state: FulfillmentState,
    current_total: &'a Option<Money>,
    total_refunded: &'a Option<Money>,
    fulfillment_orders: &'a [FulfillmentOrderProjection],
    fulfillments: &'a [FulfillmentProjection],
    refunds: &'a [RefundProjection],
    transactions: &'a [TransactionProjection],
    partial_reasons: &'a [PartialReason],
}

impl ShopifyOrderProjection {
    pub fn new(input: ShopifyOrderProjectionInput) -> Self {
        let order_revision_digest = Digest::from_serializable(&ProjectionFingerprint {
            order_id: &input.order_id,
            updated_at: &input.updated_at,
            created_at: &input.created_at,
            currency_code: &input.currency_code,
            financial_state: input.financial_state,
            fulfillment_state: input.fulfillment_state,
            current_total: &input.current_total,
            total_refunded: &input.total_refunded,
            fulfillment_orders: &input.fulfillment_orders,
            fulfillments: &input.fulfillments,
            refunds: &input.refunds,
            transactions: &input.transactions,
            partial_reasons: &input.partial_reasons,
        });
        Self {
            order_revision_digest,
            order_id: input.order_id,
            updated_at: input.updated_at,
            created_at: input.created_at,
            currency_code: input.currency_code,
            financial_state: input.financial_state,
            fulfillment_state: input.fulfillment_state,
            current_total: input.current_total,
            total_refunded: input.total_refunded,
            fulfillment_orders: input.fulfillment_orders,
            fulfillments: input.fulfillments,
            refunds: input.refunds,
            transactions: input.transactions,
            partial_reasons: input.partial_reasons,
        }
    }

    pub fn verify_revision_digest(&self) -> bool {
        let expected = Self::new(ShopifyOrderProjectionInput {
            order_id: self.order_id.clone(),
            updated_at: self.updated_at.clone(),
            created_at: self.created_at.clone(),
            currency_code: self.currency_code.clone(),
            financial_state: self.financial_state,
            fulfillment_state: self.fulfillment_state,
            current_total: self.current_total.clone(),
            total_refunded: self.total_refunded.clone(),
            fulfillment_orders: self.fulfillment_orders.clone(),
            fulfillments: self.fulfillments.clone(),
            refunds: self.refunds.clone(),
            transactions: self.transactions.clone(),
            partial_reasons: self.partial_reasons.clone(),
        });
        expected.order_revision_digest == self.order_revision_digest
    }

    pub fn is_partial(&self) -> bool {
        !self.partial_reasons.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionState {
    Complete,
    Partial,
    AccessLost,
    Deleted,
    Expired,
    Conflict,
    RateLimited,
    ProviderUnknown,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryEvidence {
    pub attempt: u8,
    pub retry_after_milliseconds: Option<u64>,
    pub backoff_milliseconds: u64,
}

pub(crate) fn provider_revision_digest(provider_revision: &ProviderRevision) -> Digest {
    Digest::from_fields(
        "hartevo:shopify-provider-revision/v1",
        &[
            provider_revision.as_str().to_owned(),
            SHOPIFY_ADMIN_API_VERSION.to_owned(),
        ],
    )
}
