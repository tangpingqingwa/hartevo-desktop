use std::{
    collections::BTreeSet,
    fmt,
    hash::{Hash, Hasher},
};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{AdyenPaymentResultError, Result};
use crate::{API_REVISION, CONTRACT_VERSION, MAX_IDENTIFIER_BYTES};

/// SHA-256 digest used for all safe payment evidence and authority fences.
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
            Err(AdyenPaymentResultError::InvalidDigest)
        }
    }

    pub fn pending() -> Self {
        Self::from_text("hartevo.adyen-payment.pending/v1")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AdyenPaymentResultError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl Hash for Digest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
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

fn valid_text(value: &str, max_bytes: usize, whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
}

macro_rules! identifier {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AdyenPaymentResultError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("hartevo-adyen-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AdyenPaymentResultError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&format!("{}:{}", $field, &self.digest().as_str()[..16]))
                    .finish()
            }
        }
    };
}

identifier!(MerchantAccount, "merchant-account", |value: &str| {
    (1..=MAX_IDENTIFIER_BYTES).contains(&value.len())
        && valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
identifier!(AccountId, "account-id", |value: &str| {
    (1..=MAX_IDENTIFIER_BYTES).contains(&value.len())
        && valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
identifier!(PaymentReference, "payment-reference", |value: &str| {
    (1..=MAX_IDENTIFIER_BYTES).contains(&value.len())
        && valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
identifier!(HartevoProjectId, "hartevo-project-id", |value: &str| {
    (1..=MAX_IDENTIFIER_BYTES).contains(&value.len())
        && valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
identifier!(MissionId, "mission-id", |value: &str| {
    (1..=MAX_IDENTIFIER_BYTES).contains(&value.len())
        && valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
identifier!(WorkProductId, "work-product-id", |value: &str| {
    (1..=MAX_IDENTIFIER_BYTES).contains(&value.len())
        && valid_identifier(value, MAX_IDENTIFIER_BYTES)
});

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CurrencyCode(String);

impl CurrencyCode {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase()) {
            Ok(Self(value))
        } else {
            Err(AdyenPaymentResultError::InvalidInput {
                field: "currency",
                reason: "must be an uppercase ISO 4217 three-letter code",
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("hartevo-adyen-currency/v1", &[("currency", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for CurrencyCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CurrencyCode")
            .field(&self.0)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Amount {
    pub value_minor_units: i64,
    pub currency: CurrencyCode,
}

impl Amount {
    pub fn new(value_minor_units: i64, currency: CurrencyCode) -> Result<Self> {
        let amount = Self {
            value_minor_units,
            currency,
        };
        amount.validate()?;
        Ok(amount)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.currency.validate()?;
        if self.value_minor_units < 0 {
            Err(AdyenPaymentResultError::InvalidInput {
                field: "amount.value_minor_units",
                reason: "must not be negative",
            })
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-adyen-amount/v1",
            &[
                ("value_minor_units", self.value_minor_units.to_string()),
                ("currency", self.currency.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CustomerFingerprint(Digest);

impl CustomerFingerprint {
    pub fn new(digest: Digest) -> Result<Self> {
        digest.validate()?;
        Ok(Self(digest))
    }

    /// Hash a host-provided customer identifier immediately. The identifier
    /// is not retained in this type, logs, receipts, or serialized evidence.
    pub fn from_identifier(value: impl AsRef<[u8]>) -> Self {
        Self(Digest::from_text(value))
    }

    pub fn digest(&self) -> &Digest {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.0.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Project {
    pub id: HartevoProjectId,
    pub revision: u64,
}

impl Project {
    pub fn new(id: HartevoProjectId, revision: u64) -> Result<Self> {
        let project = Self { id, revision };
        project.validate()?;
        Ok(project)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.revision == 0 {
            Err(AdyenPaymentResultError::InvalidInput {
                field: "Project revision",
                reason: "must be positive",
            })
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-adyen-project/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mission {
    pub id: MissionId,
    pub revision: u64,
}

impl Mission {
    pub fn new(id: MissionId, revision: u64) -> Result<Self> {
        let mission = Self { id, revision };
        mission.validate()?;
        Ok(mission)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.revision == 0 {
            Err(AdyenPaymentResultError::InvalidInput {
                field: "Mission revision",
                reason: "must be positive",
            })
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-adyen-mission/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProduct {
    pub id: WorkProductId,
    pub revision: u64,
}

impl WorkProduct {
    pub fn new(id: WorkProductId, revision: u64) -> Result<Self> {
        let work_product = Self { id, revision };
        work_product.validate()?;
        Ok(work_product)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.revision == 0 {
            Err(AdyenPaymentResultError::InvalidInput {
                field: "Work Product revision",
                reason: "must be positive",
            })
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-adyen-work-product/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }
}

pub type HartevoProject = Project;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdyenPaymentPermission {
    PaymentLinkRead,
    PaymentSessionStatusRead,
}

impl AdyenPaymentPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PaymentLinkRead => "payment_link_read",
            Self::PaymentSessionStatusRead => "payment_session_status_read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdyenPermissionSnapshot {
    pub permissions: BTreeSet<AdyenPaymentPermission>,
    pub revision: u64,
    pub snapshot_digest: Digest,
}

impl AdyenPermissionSnapshot {
    pub fn new(
        permissions: impl IntoIterator<Item = AdyenPaymentPermission>,
        revision: u64,
    ) -> Result<Self> {
        let snapshot = Self {
            permissions: permissions.into_iter().collect(),
            revision,
            snapshot_digest: Digest::pending(),
        };
        let snapshot = Self {
            snapshot_digest: snapshot.compute_digest(),
            ..snapshot
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn read_only_default(revision: impl Into<String>) -> Result<Self> {
        let revision = revision.into();
        let revision = revision
            .strip_prefix("permissions-r")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1);
        Self::new(
            [
                AdyenPaymentPermission::PaymentLinkRead,
                AdyenPaymentPermission::PaymentSessionStatusRead,
            ],
            revision,
        )
    }

    pub fn contains(&self, permission: AdyenPaymentPermission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn digest(&self) -> &Digest {
        &self.snapshot_digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision == 0
            || !self.contains(AdyenPaymentPermission::PaymentLinkRead)
            || !self.contains(AdyenPaymentPermission::PaymentSessionStatusRead)
            || self.snapshot_digest != self.compute_digest()
        {
            return Err(AdyenPaymentResultError::MissingPermission);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let permissions = self
            .permissions
            .iter()
            .map(|permission| permission.as_str())
            .collect::<Vec<_>>()
            .join(",");
        Digest::from_parts(
            "hartevo-adyen-permissions/v1",
            &[
                ("permissions", permissions),
                ("revision", self.revision.to_string()),
            ],
        )
    }
}

/// Opaque API-key identity. It intentionally has no serde implementation and
/// never stores the API-key bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_id: String,
    scope_digest: Digest,
    credential_revision: u64,
    revoked: bool,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest())
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope_digest: Digest,
        credential_revision: u64,
    ) -> Result<Self> {
        let reference = Self {
            reference_id: reference_id.into(),
            scope_digest,
            credential_revision,
            revoked: false,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn for_scope(
        reference_id: impl Into<String>,
        scope: &AdyenPaymentScope,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::new(reference_id, scope.digest(), credential_revision)
    }

    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-adyen-secret-reference/v1",
            &[
                ("reference_id", self.reference_id.clone()),
                ("scope_digest", self.scope_digest.as_str().to_owned()),
                ("credential_revision", self.credential_revision.to_string()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(AdyenPaymentResultError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    fn validate(&self) -> Result<()> {
        if !self.reference_id.starts_with("secret-ref-")
            || !valid_identifier(&self.reference_id, MAX_IDENTIFIER_BYTES)
        {
            return Err(AdyenPaymentResultError::InvalidIdentifier {
                field: "secret reference_id",
            });
        }
        self.scope_digest.validate()?;
        if self.credential_revision == 0 {
            return Err(AdyenPaymentResultError::InvalidInput {
                field: "credential revision",
                reason: "must be positive",
            });
        }
        Ok(())
    }
}

/// Exact payment and Hartevo identity binding for one Mission result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdyenPaymentScope {
    pub merchant_account: MerchantAccount,
    pub account_id: AccountId,
    pub payment_reference: PaymentReference,
    pub amount: Amount,
    pub customer_fingerprint: CustomerFingerprint,
    pub project: Project,
    pub mission: Mission,
    pub work_product: WorkProduct,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub permissions: AdyenPermissionSnapshot,
}

impl AdyenPaymentScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        merchant_account: MerchantAccount,
        account_id: AccountId,
        payment_reference: PaymentReference,
        amount: Amount,
        customer_fingerprint: CustomerFingerprint,
        project: Project,
        mission: Mission,
        work_product: WorkProduct,
        mission_revision: u64,
        work_product_revision: u64,
        permissions: AdyenPermissionSnapshot,
    ) -> Result<Self> {
        let scope = Self {
            merchant_account,
            account_id,
            payment_reference,
            amount,
            customer_fingerprint,
            project,
            mission,
            work_product,
            mission_revision,
            work_product_revision,
            permissions,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_ids(
        merchant_account: impl Into<String>,
        account_id: impl Into<String>,
        payment_reference: impl Into<String>,
        amount_minor_units: i64,
        currency: impl Into<String>,
        customer_fingerprint: Digest,
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        work_product_id: impl Into<String>,
        project_revision: u64,
        mission_revision: u64,
        work_product_revision: u64,
        permissions: AdyenPermissionSnapshot,
    ) -> Result<Self> {
        Self::new(
            MerchantAccount::new(merchant_account)?,
            AccountId::new(account_id)?,
            PaymentReference::new(payment_reference)?,
            Amount::new(amount_minor_units, CurrencyCode::new(currency)?)?,
            CustomerFingerprint::new(customer_fingerprint)?,
            Project::new(HartevoProjectId::new(project_id)?, project_revision)?,
            Mission::new(MissionId::new(mission_id)?, mission_revision)?,
            WorkProduct::new(WorkProductId::new(work_product_id)?, work_product_revision)?,
            mission_revision,
            work_product_revision,
            permissions,
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-adyen-payment-scope/v1",
            &[
                (
                    "merchant_account",
                    self.merchant_account.as_str().to_owned(),
                ),
                ("account_id", self.account_id.as_str().to_owned()),
                (
                    "payment_reference",
                    self.payment_reference.as_str().to_owned(),
                ),
                ("amount", self.amount.digest().as_str().to_owned()),
                (
                    "customer_fingerprint",
                    self.customer_fingerprint.digest().as_str().to_owned(),
                ),
                ("project", self.project.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                ("mission_revision", self.mission_revision.to_string()),
                (
                    "work_product_revision",
                    self.work_product_revision.to_string(),
                ),
                (
                    "permission_digest",
                    self.permissions.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.merchant_account.validate()?;
        self.account_id.validate()?;
        self.payment_reference.validate()?;
        self.amount.validate()?;
        self.customer_fingerprint.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        self.permissions.validate()?;
        if self.mission_revision == 0
            || self.work_product_revision == 0
            || self.mission_revision != self.mission.revision
            || self.work_product_revision != self.work_product.revision
        {
            return Err(AdyenPaymentResultError::InvalidInput {
                field: "Adyen payment scope",
                reason: "contains a stale or zero identity revision",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

impl RegistrationStatus {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Version-, API-, permission-, scope-, and evidence-schema-bound
/// registration. The secret reference is intentionally omitted from serde.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdyenPaymentRegistration {
    pub scope: AdyenPaymentScope,
    secret_reference: SecretReference,
    pub api_revision: String,
    pub api_digest: Digest,
    pub provider_version: PluginVersion,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub status: RegistrationStatus,
    pub revision: u64,
    pub revoked_at_ms: Option<u64>,
}

impl AdyenPaymentRegistration {
    pub fn new(scope: AdyenPaymentScope, secret_reference: SecretReference) -> Result<Self> {
        let registration = Self {
            permission_digest: scope.permissions.digest().clone(),
            scope_digest: scope.digest(),
            evidence_digest: crate::evidence_schema_digest(),
            api_revision: API_REVISION.to_owned(),
            api_digest: crate::api_digest(),
            provider_version: crate::PROVIDER_VERSION,
            provider_digest: crate::provider_digest(),
            contract_digest: crate::contract_digest(),
            registration_digest: Digest::pending(),
            status: RegistrationStatus::Active,
            revision: 1,
            revoked_at_ms: None,
            scope,
            secret_reference,
        };
        let registration = Self {
            registration_digest: registration.compute_digest(),
            ..registration
        };
        registration.validate()?;
        Ok(registration)
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn is_active(&self) -> bool {
        self.status.is_active()
            && !self.secret_reference.is_revoked()
            && self.revoked_at_ms.is_none()
    }

    pub fn revoke(&mut self, revoked_at_ms: u64) -> Result<RegistrationRevocation> {
        if !self.is_active() {
            return Err(AdyenPaymentResultError::AlreadyRevoked);
        }
        if revoked_at_ms == 0 {
            return Err(AdyenPaymentResultError::InvalidInput {
                field: "revoked_at_ms",
                reason: "must be positive",
            });
        }
        self.secret_reference.revoke()?;
        self.status = RegistrationStatus::Revoked;
        self.revoked_at_ms = Some(revoked_at_ms);
        self.revision = self.revision.saturating_add(1);
        self.registration_digest = self.compute_digest();
        self.validate()?;
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            revoked_at_ms,
            reversible: true,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.secret_reference.validate()?;
        if self.secret_reference.scope_digest() != &self.scope_digest
            || self.permission_digest != *self.scope.permissions.digest()
            || self.scope_digest != self.scope.digest()
            || self.api_revision != API_REVISION
            || self.api_digest != crate::api_digest()
            || self.provider_version != crate::PROVIDER_VERSION
            || self.provider_digest != crate::provider_digest()
            || self.contract_digest != crate::contract_digest()
            || self.evidence_digest != crate::evidence_schema_digest()
            || self.revision == 0
            || (self.status == RegistrationStatus::Active && self.revoked_at_ms.is_some())
            || (self.status == RegistrationStatus::Revoked && self.revoked_at_ms.is_none())
            || self.registration_digest != self.compute_digest()
        {
            return Err(AdyenPaymentResultError::RegistrationDigestMismatch);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-adyen-payment-registration/v1",
            &[
                ("contract", CONTRACT_VERSION.to_owned()),
                ("api_revision", self.api_revision.clone()),
                (
                    "provider_version",
                    self.provider_version.as_str().to_owned(),
                ),
                ("api_digest", self.api_digest.as_str().to_owned()),
                ("provider_digest", self.provider_digest.as_str().to_owned()),
                ("contract_digest", self.contract_digest.as_str().to_owned()),
                (
                    "secret_reference",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                (
                    "permission_digest",
                    self.permission_digest.as_str().to_owned(),
                ),
                ("scope_digest", self.scope_digest.as_str().to_owned()),
                ("evidence_digest", self.evidence_digest.as_str().to_owned()),
                ("status", format!("{:?}", self.status)),
                ("revision", self.revision.to_string()),
                (
                    "revoked_at_ms",
                    self.revoked_at_ms
                        .map_or_else(String::new, |v| v.to_string()),
                ),
            ],
        )
    }
}

impl Serialize for AdyenPaymentRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AdyenPaymentRegistration", 13)?;
        state.serialize_field("scope", &self.scope)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("providerVersion", &self.provider_version)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("revokedAtMs", &self.revoked_at_ms)?;
        state.end()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub revoked_at_ms: u64,
    pub reversible: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginVersion {
    V1,
}

impl PluginVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "1.0.0",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdyenPaymentStatus {
    Received,
    Pending,
    Authorised,
    Refused,
    Cancelled,
    Error,
    Expired,
    Unknown,
}

impl AdyenPaymentStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Pending => "pending",
            Self::Authorised => "authorised",
            Self::Refused => "refused",
            Self::Cancelled => "cancelled",
            Self::Error => "error",
            Self::Expired => "expired",
            Self::Unknown => "unknown",
        }
    }

    pub(crate) const fn rank(self) -> u8 {
        match self {
            Self::Received => 0,
            Self::Pending => 1,
            Self::Authorised | Self::Refused | Self::Cancelled | Self::Error | Self::Expired => 2,
            Self::Unknown => u8::MAX,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Authorised | Self::Refused | Self::Cancelled | Self::Error | Self::Expired
        )
    }

    pub(crate) fn from_api(status: Option<&str>, result_code: Option<&str>) -> Self {
        let value = status.or(result_code).map(str::to_ascii_lowercase);
        match value.as_deref() {
            Some("received" | "submitted") => Self::Received,
            Some("pending" | "paymentpending" | "redirectshopper" | "challenge") => Self::Pending,
            Some("authorised" | "authorized" | "completed" | "success") => Self::Authorised,
            Some("refused" | "failed" | "declined") => Self::Refused,
            Some("cancelled" | "canceled") => Self::Cancelled,
            Some("error") => Self::Error,
            Some("expired") => Self::Expired,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdyenPaymentResultState {
    DecisionReady,
    Pending,
    Refused,
    Cancelled,
    Error,
    Expired,
    ProviderUnknown,
    AccessLost,
}

impl AdyenPaymentResultState {
    pub const fn is_adoptable(self) -> bool {
        matches!(self, Self::DecisionReady)
    }
}

pub type PaymentOutcomeState = AdyenPaymentResultState;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    OfficialHttps,
    Recording,
    Fake,
    Fixture,
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

    pub const fn is_controlled(self) -> bool {
        !matches!(self, Self::OfficialHttps)
    }
}

/// Parsed, bounded Adyen metadata. It contains no payment method object,
/// shopper fields, URLs, response body, or API key.
#[derive(Clone, Eq, PartialEq)]
pub struct AdyenPaymentApiRecord {
    pub merchant_account: String,
    pub account_id: String,
    pub payment_reference: String,
    pub amount_minor_units: i64,
    pub currency: String,
    pub status: String,
    pub result_code: Option<String>,
    pub customer_fingerprint_digest: Option<Digest>,
    pub payment_method_digest: Option<Digest>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub reconciliation_reference: Option<String>,
}

impl fmt::Debug for AdyenPaymentApiRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdyenPaymentApiRecord")
            .field(
                "merchant_account_digest",
                &Digest::from_text(&self.merchant_account),
            )
            .field("account_id_digest", &Digest::from_text(&self.account_id))
            .field(
                "payment_reference_digest",
                &Digest::from_text(&self.payment_reference),
            )
            .field("amount_minor_units", &self.amount_minor_units)
            .field("currency", &self.currency)
            .field("status", &self.status)
            .field(
                "result_code",
                &self.result_code.as_deref().map(Digest::from_text),
            )
            .field(
                "customer_fingerprint_digest",
                &self.customer_fingerprint_digest,
            )
            .field("payment_method_digest", &self.payment_method_digest)
            .field(
                "created_at_digest",
                &self.created_at.as_deref().map(Digest::from_text),
            )
            .field(
                "updated_at_digest",
                &self.updated_at.as_deref().map(Digest::from_text),
            )
            .field(
                "reconciliation_reference_digest",
                &self
                    .reconciliation_reference
                    .as_deref()
                    .map(Digest::from_text),
            )
            .finish()
    }
}

impl AdyenPaymentApiRecord {
    pub fn new(
        merchant_account: impl Into<String>,
        account_id: impl Into<String>,
        payment_reference: impl Into<String>,
        amount_minor_units: i64,
        currency: impl Into<String>,
        status: impl Into<String>,
    ) -> Self {
        Self {
            merchant_account: merchant_account.into(),
            account_id: account_id.into(),
            payment_reference: payment_reference.into(),
            amount_minor_units,
            currency: currency.into(),
            status: status.into(),
            result_code: None,
            customer_fingerprint_digest: None,
            payment_method_digest: None,
            created_at: None,
            updated_at: None,
            reconciliation_reference: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdyenPaymentReadMode {
    PaymentLink,
    Session,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdyenPaymentProjection {
    pub merchant_account: MerchantAccount,
    pub account_id: AccountId,
    pub payment_reference: PaymentReference,
    pub amount: Amount,
    pub status: AdyenPaymentStatus,
    pub status_digest: Digest,
    pub customer_fingerprint: CustomerFingerprint,
    pub payment_method_digest: Option<Digest>,
    pub created_timestamp_digest: Option<Digest>,
    pub updated_timestamp_digest: Option<Digest>,
    pub reconciliation_digest: Digest,
    pub provenance: ProviderProvenance,
    pub native_connected: bool,
    pub provider_revision: u64,
    pub projection_digest: Digest,
}

impl AdyenPaymentProjection {
    pub(crate) fn from_api(
        api: &AdyenPaymentApiRecord,
        scope: &AdyenPaymentScope,
        provenance: ProviderProvenance,
        provider_revision: u64,
    ) -> Result<Self> {
        let merchant_account = MerchantAccount::new(api.merchant_account.clone())?;
        let account_id = AccountId::new(api.account_id.clone())?;
        let payment_reference = PaymentReference::new(api.payment_reference.clone())?;
        let currency = CurrencyCode::new(api.currency.clone())?;
        let stage_status =
            AdyenPaymentStatus::from_api(Some(api.status.as_str()), api.result_code.as_deref());
        let amount = Amount::new(api.amount_minor_units, currency)?;
        let customer_fingerprint = api
            .customer_fingerprint_digest
            .clone()
            .map(CustomerFingerprint::new)
            .transpose()?
            .unwrap_or_else(|| scope.customer_fingerprint.clone());
        let status_digest = Digest::from_parts(
            "hartevo-adyen-payment-status/v1",
            &[
                ("status", stage_status.as_str().to_owned()),
                ("result_code", api.result_code.clone().unwrap_or_default()),
            ],
        );
        let created_timestamp_digest = api.created_at.as_deref().map(Digest::from_text);
        let updated_timestamp_digest = api.updated_at.as_deref().map(Digest::from_text);
        let reconciliation_digest = Digest::from_parts(
            "hartevo-adyen-reconciliation/v1",
            &[
                ("merchant_account", merchant_account.as_str().to_owned()),
                ("account_id", account_id.as_str().to_owned()),
                ("payment_reference", payment_reference.as_str().to_owned()),
                ("amount", amount.digest().as_str().to_owned()),
                ("status", status_digest.as_str().to_owned()),
                (
                    "customer_fingerprint",
                    customer_fingerprint.digest().as_str().to_owned(),
                ),
                (
                    "payment_method",
                    api.payment_method_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "created_at",
                    created_timestamp_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "updated_at",
                    updated_timestamp_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "reconciliation_reference",
                    api.reconciliation_reference
                        .as_deref()
                        .map_or_else(String::new, |value| Digest::from_text(value).0),
                ),
            ],
        );
        let projection = Self {
            merchant_account,
            account_id,
            payment_reference,
            amount,
            status: stage_status,
            status_digest,
            customer_fingerprint,
            payment_method_digest: api.payment_method_digest.clone(),
            created_timestamp_digest,
            updated_timestamp_digest,
            reconciliation_digest,
            provenance,
            native_connected: false,
            provider_revision,
            projection_digest: Digest::pending(),
        };
        let projection = Self {
            projection_digest: projection.compute_digest(),
            ..projection
        };
        projection.validate(scope)?;
        Ok(projection)
    }

    pub fn digest(&self) -> &Digest {
        &self.projection_digest
    }

    pub(crate) fn validate(&self, scope: &AdyenPaymentScope) -> Result<()> {
        if self.merchant_account != scope.merchant_account {
            return Err(AdyenPaymentResultError::MerchantMismatch);
        }
        if self.account_id != scope.account_id {
            return Err(AdyenPaymentResultError::AccountMismatch);
        }
        if self.payment_reference != scope.payment_reference {
            return Err(AdyenPaymentResultError::PaymentReferenceMismatch);
        }
        if self.amount != scope.amount {
            if self.amount.currency != scope.amount.currency {
                return Err(AdyenPaymentResultError::CurrencyMismatch);
            }
            return Err(AdyenPaymentResultError::AmountMismatch);
        }
        if self.customer_fingerprint != scope.customer_fingerprint {
            return Err(AdyenPaymentResultError::CustomerFingerprintMismatch);
        }
        if self.native_connected {
            return Err(AdyenPaymentResultError::InvalidEvidence);
        }
        if self.projection_digest != self.compute_digest() {
            return Err(AdyenPaymentResultError::EvidenceDigestMismatch {
                field: "projection_digest",
            });
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-adyen-payment-projection/v1",
            &[
                (
                    "merchant_account",
                    self.merchant_account.as_str().to_owned(),
                ),
                ("account_id", self.account_id.as_str().to_owned()),
                (
                    "payment_reference",
                    self.payment_reference.as_str().to_owned(),
                ),
                ("amount", self.amount.digest().as_str().to_owned()),
                ("status", self.status_digest.as_str().to_owned()),
                (
                    "customer_fingerprint",
                    self.customer_fingerprint.digest().as_str().to_owned(),
                ),
                (
                    "payment_method",
                    self.payment_method_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "created_at",
                    self.created_timestamp_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "updated_at",
                    self.updated_timestamp_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "reconciliation",
                    self.reconciliation_digest.as_str().to_owned(),
                ),
                ("provenance", format!("{:?}", self.provenance)),
                ("native_connected", self.native_connected.to_string()),
                ("provider_revision", self.provider_revision.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdyenPaymentEvidence {
    pub scope: AdyenPaymentScope,
    pub payment: AdyenPaymentProjection,
    pub result_state: AdyenPaymentResultState,
    pub registration_digest: Digest,
    pub provider_revision: u64,
    pub idempotency_key: String,
    pub native_connected: bool,
    pub external_effect_performed: bool,
    pub financial_advice: bool,
    pub evidence_digest: Digest,
}

impl AdyenPaymentEvidence {
    pub(crate) fn new(
        scope: AdyenPaymentScope,
        payment: AdyenPaymentProjection,
        registration_digest: Digest,
        provider_revision: u64,
    ) -> Result<Self> {
        let result_state = result_state(payment.status);
        let idempotency_key = deterministic_idempotency_key(&scope, &payment);
        let evidence = Self {
            scope,
            payment,
            result_state,
            registration_digest,
            provider_revision,
            idempotency_key,
            native_connected: false,
            external_effect_performed: false,
            financial_advice: false,
            evidence_digest: Digest::pending(),
        };
        let evidence = Self {
            evidence_digest: evidence.compute_digest(),
            ..evidence
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn is_adoptable(&self) -> bool {
        self.result_state.is_adoptable()
            && self.payment.status == AdyenPaymentStatus::Authorised
            && !self.native_connected
            && !self.external_effect_performed
            && !self.financial_advice
    }

    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.payment.validate(&self.scope)?;
        if self.provider_revision == 0
            || self.registration_digest == Digest::pending()
            || self.idempotency_key != deterministic_idempotency_key(&self.scope, &self.payment)
            || self.native_connected
            || self.external_effect_performed
            || self.financial_advice
            || self.evidence_digest != self.compute_digest()
        {
            return Err(AdyenPaymentResultError::InvalidEvidence);
        }
        if self.result_state != result_state(self.payment.status) {
            return Err(AdyenPaymentResultError::EvidenceDigestMismatch {
                field: "result_state",
            });
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-adyen-payment-evidence/v1",
            &[
                ("scope", self.scope.digest().as_str().to_owned()),
                ("payment", self.payment.digest().as_str().to_owned()),
                ("result_state", format!("{:?}", self.result_state)),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("provider_revision", self.provider_revision.to_string()),
                ("idempotency_key", self.idempotency_key.clone()),
                ("native_connected", self.native_connected.to_string()),
                (
                    "external_effect_performed",
                    self.external_effect_performed.to_string(),
                ),
                ("financial_advice", self.financial_advice.to_string()),
                (
                    "schema_digest",
                    crate::evidence_schema_digest().as_str().to_owned(),
                ),
            ],
        )
    }
}

fn result_state(status: AdyenPaymentStatus) -> AdyenPaymentResultState {
    match status {
        AdyenPaymentStatus::Authorised => AdyenPaymentResultState::DecisionReady,
        AdyenPaymentStatus::Received | AdyenPaymentStatus::Pending => {
            AdyenPaymentResultState::Pending
        }
        AdyenPaymentStatus::Refused => AdyenPaymentResultState::Refused,
        AdyenPaymentStatus::Cancelled => AdyenPaymentResultState::Cancelled,
        AdyenPaymentStatus::Error => AdyenPaymentResultState::Error,
        AdyenPaymentStatus::Expired => AdyenPaymentResultState::Expired,
        AdyenPaymentStatus::Unknown => AdyenPaymentResultState::ProviderUnknown,
    }
}

pub fn deterministic_idempotency_key(
    scope: &AdyenPaymentScope,
    payment: &AdyenPaymentProjection,
) -> String {
    let digest = Digest::from_parts(
        "hartevo-adyen-payment-idempotency/v1",
        &[
            ("scope", scope.digest().as_str().to_owned()),
            ("payment", payment.digest().as_str().to_owned()),
            (
                "registration_schema",
                crate::evidence_schema_digest().as_str().to_owned(),
            ),
        ],
    );
    format!("hartevo-adyen-{}", &digest.as_str()[..32])
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdyenPaymentReceipt {
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub reconciliation_digest: Digest,
    pub idempotency_key: String,
    pub recorded_at_ms: u64,
    pub native_connected: bool,
    pub external_effect_performed: bool,
    pub receipt_digest: Digest,
}

impl AdyenPaymentReceipt {
    pub(crate) fn new(evidence: &AdyenPaymentEvidence, recorded_at_ms: u64) -> Result<Self> {
        if recorded_at_ms == 0 {
            return Err(AdyenPaymentResultError::InvalidInput {
                field: "recorded_at_ms",
                reason: "must be positive",
            });
        }
        let receipt = Self {
            registration_digest: evidence.registration_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            reconciliation_digest: evidence.payment.reconciliation_digest.clone(),
            idempotency_key: evidence.idempotency_key.clone(),
            recorded_at_ms,
            native_connected: false,
            external_effect_performed: false,
            receipt_digest: Digest::pending(),
        };
        let receipt = Self {
            receipt_digest: receipt.compute_digest(),
            ..receipt
        };
        receipt.validate(evidence)?;
        Ok(receipt)
    }

    pub fn validate(&self, evidence: &AdyenPaymentEvidence) -> Result<()> {
        if self.registration_digest != evidence.registration_digest
            || self.evidence_digest != evidence.evidence_digest
            || self.reconciliation_digest != evidence.payment.reconciliation_digest
            || self.idempotency_key != evidence.idempotency_key
            || self.recorded_at_ms == 0
            || self.native_connected
            || self.external_effect_performed
            || self.receipt_digest != self.compute_digest()
        {
            return Err(AdyenPaymentResultError::ReceiptDigestMismatch);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-adyen-payment-receipt/v1",
            &[
                ("registration", self.registration_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                (
                    "reconciliation",
                    self.reconciliation_digest.as_str().to_owned(),
                ),
                ("idempotency_key", self.idempotency_key.clone()),
                ("recorded_at_ms", self.recorded_at_ms.to_string()),
                ("native_connected", self.native_connected.to_string()),
                (
                    "external_effect_performed",
                    self.external_effect_performed.to_string(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AdyenPaymentResultProposal {
    pub scope: AdyenPaymentScope,
    pub payment: AdyenPaymentProjection,
    pub result_state: AdyenPaymentResultState,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub receipt_digest: Digest,
    pub idempotency_key: String,
    pub non_mutating: bool,
    pub external_effect_created: bool,
    pub durable_adoption: bool,
    pub kernel_authority: bool,
    pub financial_advice: bool,
    pub native_connected: bool,
    pub proposal_digest: Digest,
}

impl AdyenPaymentResultProposal {
    pub(crate) fn new(
        evidence: &AdyenPaymentEvidence,
        receipt: &AdyenPaymentReceipt,
    ) -> Result<Self> {
        evidence.validate()?;
        receipt.validate(evidence)?;
        if !evidence.is_adoptable() {
            return Err(AdyenPaymentResultError::InvalidEvidence);
        }
        let proposal = Self {
            scope: evidence.scope.clone(),
            payment: evidence.payment.clone(),
            result_state: evidence.result_state,
            registration_digest: evidence.registration_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            idempotency_key: evidence.idempotency_key.clone(),
            non_mutating: true,
            external_effect_created: false,
            durable_adoption: false,
            kernel_authority: false,
            financial_advice: false,
            native_connected: false,
            proposal_digest: Digest::pending(),
        };
        let proposal = Self {
            proposal_digest: proposal.compute_digest(),
            ..proposal
        };
        proposal.validate(evidence, receipt)?;
        Ok(proposal)
    }

    pub fn validate(
        &self,
        evidence: &AdyenPaymentEvidence,
        receipt: &AdyenPaymentReceipt,
    ) -> Result<()> {
        evidence.validate()?;
        receipt.validate(evidence)?;
        if self.scope != evidence.scope
            || self.payment != evidence.payment
            || self.result_state != evidence.result_state
            || self.registration_digest != evidence.registration_digest
            || self.evidence_digest != evidence.evidence_digest
            || self.receipt_digest != receipt.receipt_digest
            || self.idempotency_key != evidence.idempotency_key
            || !self.non_mutating
            || self.external_effect_created
            || self.durable_adoption
            || self.kernel_authority
            || self.financial_advice
            || self.native_connected
            || self.proposal_digest != self.compute_digest()
        {
            return Err(AdyenPaymentResultError::ProposalDigestMismatch);
        }
        Ok(())
    }

    pub(crate) fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-adyen-payment-proposal/v1",
            &[
                ("scope", self.scope.digest().as_str().to_owned()),
                ("payment", self.payment.digest().as_str().to_owned()),
                ("result_state", format!("{:?}", self.result_state)),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("receipt", self.receipt_digest.as_str().to_owned()),
                ("idempotency_key", self.idempotency_key.clone()),
                ("non_mutating", self.non_mutating.to_string()),
                (
                    "external_effect_created",
                    self.external_effect_created.to_string(),
                ),
                ("durable_adoption", self.durable_adoption.to_string()),
                ("kernel_authority", self.kernel_authority.to_string()),
                ("financial_advice", self.financial_advice.to_string()),
                ("native_connected", self.native_connected.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdyenReadBackVerification {
    pub first_evidence_digest: Digest,
    pub read_back_evidence_digest: Digest,
    pub reconciliation_digest: Digest,
    pub matched: bool,
    pub verification_digest: Digest,
}

impl AdyenReadBackVerification {
    pub(crate) fn new(
        first: &AdyenPaymentEvidence,
        read_back: &AdyenPaymentEvidence,
    ) -> Result<Self> {
        first.validate()?;
        read_back.validate()?;
        let matched = first.evidence_digest == read_back.evidence_digest
            && first.payment.reconciliation_digest == read_back.payment.reconciliation_digest;
        let verification = Self {
            first_evidence_digest: first.evidence_digest.clone(),
            read_back_evidence_digest: read_back.evidence_digest.clone(),
            reconciliation_digest: read_back.payment.reconciliation_digest.clone(),
            matched,
            verification_digest: Digest::pending(),
        };
        let verification = Self {
            verification_digest: verification.compute_digest(),
            ..verification
        };
        verification.validate()?;
        if !verification.matched {
            return Err(AdyenPaymentResultError::ReadBackMismatch);
        }
        Ok(verification)
    }

    pub fn validate(&self) -> Result<()> {
        if !self.matched || self.verification_digest != self.compute_digest() {
            return Err(AdyenPaymentResultError::ReadBackMismatch);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-adyen-payment-read-back/v1",
            &[
                (
                    "first_evidence",
                    self.first_evidence_digest.as_str().to_owned(),
                ),
                (
                    "read_back_evidence",
                    self.read_back_evidence_digest.as_str().to_owned(),
                ),
                (
                    "reconciliation",
                    self.reconciliation_digest.as_str().to_owned(),
                ),
                ("matched", self.matched.to_string()),
            ],
        )
    }
}
