//! Typed, bounded Xero Accounting projections and lifecycle fences.
//!
//! The model deliberately contains only normalized allowlisted fields. Xero
//! JSON, OAuth2 material, bank details, attachments, PDFs, arbitrary reports,
//! and provider error bodies are never part of the evidence model.

use std::{fmt, str::FromStr};

use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::{
    XERO_ACCOUNTING_API_REVISION, XERO_ACCOUNTING_RESULT_CONTRACT_VERSION,
    XERO_ACCOUNTING_RESULT_PLUGIN_VERSION, XERO_ACCOUNTING_RESULT_PROVIDER_ID,
    XERO_ACCOUNTING_RESULT_SCHEMA_VERSION, XERO_ACCOUNTING_RESULT_SERVICE_ID, XeroAccountingError,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_TEXT_BYTES: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RECORDS: usize = 100;
pub const MAX_DATE_RANGE_DAYS: i64 = 366;

pub const INVOICE_FIELDS: &[&str] = &[
    "InvoiceID",
    "InvoiceNumber",
    "Type",
    "Status",
    "Date",
    "DueDate",
    "Contact.ContactID",
    "Contact.Name",
    "Contact.ContactStatus",
    "CurrencyCode",
    "SubTotal",
    "TotalTax",
    "Total",
    "AmountDue",
    "AmountPaid",
    "AmountCredited",
    "UpdatedDateUTC",
];

pub const PAYMENT_FIELDS: &[&str] = &[
    "PaymentID",
    "Date",
    "Amount",
    "CurrencyRate",
    "CurrencyCode",
    "Status",
    "UpdatedDateUTC",
    "Invoice.InvoiceID",
    "Invoice.InvoiceNumber",
    "Account.AccountID",
    "Account.Code",
    "Account.Name",
    "Account.Type",
    "Account.Status",
];

pub const CONTACT_FIELDS: &[&str] = &["ContactID", "Name", "ContactStatus", "UpdatedDateUTC"];

fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
    allow_whitespace: bool,
) -> Result<(), XeroAccountingError> {
    if value.is_empty() || value.len() > max_bytes || value.trim() != value {
        return Err(XeroAccountingError::InvalidField {
            field,
            reason: "must be bounded and non-empty",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(XeroAccountingError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if !allow_whitespace && value.chars().any(char::is_whitespace) {
        return Err(XeroAccountingError::InvalidField {
            field,
            reason: "must not contain whitespace",
        });
    }
    Ok(())
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, XeroAccountingError> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES, false)?;
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
            type Err = XeroAccountingError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

bounded_identifier!(TenantId, "tenant_id");
bounded_identifier!(OrganisationId, "organisation_id");
bounded_identifier!(ContactId, "contact_id");
bounded_identifier!(InvoiceOrBillId, "invoice_or_bill_id");
bounded_identifier!(PaymentId, "payment_id");
bounded_identifier!(AccountId, "account_id");

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CurrencyCode(String);

impl CurrencyCode {
    pub fn new(value: impl Into<String>) -> Result<Self, XeroAccountingError> {
        let value = value.into().to_ascii_uppercase();
        if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(XeroAccountingError::InvalidField {
                field: "currency_code",
                reason: "must be a three-letter ISO currency code",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
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

impl fmt::Display for CurrencyCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for CurrencyCode {
    type Err = XeroAccountingError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// A provider revision is an opaque, checked-in adapter revision, not a
/// claim that a live Xero tenant has been connected.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProviderRevision(String);

impl ProviderRevision {
    pub fn new(value: impl Into<String>) -> Result<Self, XeroAccountingError> {
        let value = value.into();
        validate_text(&value, "provider_revision", MAX_TEXT_BYTES, false)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProviderRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProviderRevision")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ProviderRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// SHA-256 is used for all public binding and evidence digests.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("Xero canonical values serialize");
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, XeroAccountingError> {
        let value = value.into();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(XeroAccountingError::InvalidField {
                field: "digest",
                reason: "must be a SHA-256 hexadecimal digest",
            });
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, XeroAccountingError> {
        if value == 0 {
            return Err(XeroAccountingError::InvalidField {
                field: "revision",
                reason: "must be positive",
            });
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Xero's `UpdatedDateUTC` is treated as an opaque revision string. The
/// provider compares it byte-for-byte after bounded validation; it never
/// invents a local timestamp or claims monotonicity the API did not provide.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct UpdatedRevision(String);

impl UpdatedRevision {
    pub fn new(value: impl Into<String>) -> Result<Self, XeroAccountingError> {
        let value = value.into();
        validate_text(&value, "updated_revision", MAX_TEXT_BYTES, true)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

impl fmt::Debug for UpdatedRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("UpdatedRevision")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for UpdatedRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    id: String,
    revision: Revision,
}

impl ProjectScope {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self, XeroAccountingError> {
        let id = id.into();
        validate_text(&id, "project_id", MAX_IDENTIFIER_BYTES, false)?;
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    id: String,
    revision: Revision,
}

impl MissionScope {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self, XeroAccountingError> {
        let id = id.into();
        validate_text(&id, "mission_id", MAX_IDENTIFIER_BYTES, false)?;
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductScope {
    id: String,
    revision: Revision,
}

impl WorkProductScope {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self, XeroAccountingError> {
        let id = id.into();
        validate_text(&id, "work_product_id", MAX_IDENTIFIER_BYTES, false)?;
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct XeroApiHost(String);

impl XeroApiHost {
    pub fn new(value: impl Into<String>) -> Result<Self, XeroAccountingError> {
        let value = value.into().trim_end_matches('/').to_owned();
        let parsed = url::Url::parse(&value).map_err(|_| XeroAccountingError::InvalidField {
            field: "api_host",
            reason: "must be a valid HTTPS URL",
        })?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != ""
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(XeroAccountingError::InvalidField {
                field: "api_host",
                reason: "must be HTTPS without credentials, path, query, or fragment",
            });
        }
        Ok(Self(value))
    }

    pub fn xero() -> Self {
        Self(crate::XERO_ACCOUNTING_API_ORIGIN.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for XeroApiHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("XeroApiHost").field(&self.0).finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XeroPermission {
    AccountingTransactionsRead,
    AccountingContactsRead,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    transactions_read: bool,
    contacts_read: bool,
}

impl PermissionSnapshot {
    pub fn new(contacts_read: bool) -> Self {
        Self {
            transactions_read: true,
            contacts_read,
        }
    }

    pub const fn transactions_read(self) -> bool {
        self.transactions_read
    }

    pub const fn contacts_read(self) -> bool {
        self.contacts_read
    }

    pub fn permissions(self) -> Vec<XeroPermission> {
        let mut permissions = vec![XeroPermission::AccountingTransactionsRead];
        if self.contacts_read {
            permissions.push(XeroPermission::AccountingContactsRead);
        }
        permissions
    }

    pub fn digest(self) -> Digest {
        Digest::from_serializable(&self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceOrBillKind {
    Invoice,
    Bill,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvoiceOrBillScope {
    id: InvoiceOrBillId,
    kind: InvoiceOrBillKind,
}

impl InvoiceOrBillScope {
    pub fn new(id: InvoiceOrBillId, kind: InvoiceOrBillKind) -> Result<Self, XeroAccountingError> {
        Ok(Self { id, kind })
    }

    pub fn id(&self) -> &InvoiceOrBillId {
        &self.id
    }

    pub const fn kind(&self) -> InvoiceOrBillKind {
        self.kind
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XeroAccountingScope {
    api_host: XeroApiHost,
    tenant_id: TenantId,
    organisation_id: OrganisationId,
    contact_id: ContactId,
    invoice_or_bill: InvoiceOrBillScope,
    payment_id: PaymentId,
    account_id: AccountId,
    currency: CurrencyCode,
    updated_revision: UpdatedRevision,
    mission: MissionScope,
    project: ProjectScope,
    work_product: WorkProductScope,
    permissions: PermissionSnapshot,
}

impl XeroAccountingScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        api_host: XeroApiHost,
        tenant_id: TenantId,
        organisation_id: OrganisationId,
        contact_id: ContactId,
        invoice_or_bill: InvoiceOrBillScope,
        payment_id: PaymentId,
        account_id: AccountId,
        currency: CurrencyCode,
        updated_revision: UpdatedRevision,
        mission: MissionScope,
        project: ProjectScope,
        work_product: WorkProductScope,
        permissions: PermissionSnapshot,
    ) -> Result<Self, XeroAccountingError> {
        let scope = Self {
            api_host,
            tenant_id,
            organisation_id,
            contact_id,
            invoice_or_bill,
            payment_id,
            account_id,
            currency,
            updated_revision,
            mission,
            project,
            work_product,
            permissions,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), XeroAccountingError> {
        if self.api_host.as_str() != crate::XERO_ACCOUNTING_API_ORIGIN {
            return Err(XeroAccountingError::InvalidField {
                field: "api_host",
                reason: "Layer-1 is pinned to the official Xero Accounting API origin",
            });
        }
        if !self.permissions.transactions_read() {
            return Err(XeroAccountingError::InvalidField {
                field: "permissions",
                reason: "accounting transaction read permission is required",
            });
        }
        Ok(())
    }

    pub fn api_host(&self) -> &XeroApiHost {
        &self.api_host
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn organisation_id(&self) -> &OrganisationId {
        &self.organisation_id
    }

    pub fn contact_id(&self) -> &ContactId {
        &self.contact_id
    }

    pub fn invoice_or_bill(&self) -> &InvoiceOrBillScope {
        &self.invoice_or_bill
    }

    pub fn payment_id(&self) -> &PaymentId {
        &self.payment_id
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn currency(&self) -> &CurrencyCode {
        &self.currency
    }

    pub fn updated_revision(&self) -> &UpdatedRevision {
        &self.updated_revision
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    pub const fn permissions(&self) -> PermissionSnapshot {
        self.permissions
    }

    pub fn permission_digest(&self) -> Digest {
        self.permissions.digest()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(&ScopeDigestMaterial {
            api_host: &self.api_host,
            tenant_id: &self.tenant_id,
            organisation_id: &self.organisation_id,
            contact_id: &self.contact_id,
            invoice_or_bill: &self.invoice_or_bill,
            payment_id: &self.payment_id,
            account_id: &self.account_id,
            currency: &self.currency,
            updated_revision: &self.updated_revision,
            mission: &self.mission,
            project: &self.project,
            work_product: &self.work_product,
            permissions: self.permissions,
        })
    }

    pub fn revision_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.updated_revision,
            self.mission.revision(),
            self.project.revision(),
            self.work_product.revision(),
            XERO_ACCOUNTING_API_REVISION,
        ))
    }
}

#[derive(Serialize)]
struct ScopeDigestMaterial<'a> {
    api_host: &'a XeroApiHost,
    tenant_id: &'a TenantId,
    organisation_id: &'a OrganisationId,
    contact_id: &'a ContactId,
    invoice_or_bill: &'a InvoiceOrBillScope,
    payment_id: &'a PaymentId,
    account_id: &'a AccountId,
    currency: &'a CurrencyCode,
    updated_revision: &'a UpdatedRevision,
    mission: &'a MissionScope,
    project: &'a ProjectScope,
    work_product: &'a WorkProductScope,
    permissions: PermissionSnapshot,
}

/// The host passes only an opaque handle. The handle is immediately hashed and
/// is never retained, serialized, displayed, or returned from this crate.
#[derive(Clone, Eq, PartialEq)]
pub struct OAuth2SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
}

pub type SecretReference = OAuth2SecretReference;

impl OAuth2SecretReference {
    pub fn new(
        opaque_reference: impl AsRef<str>,
        scope_digest: Digest,
        credential_revision: Revision,
    ) -> Result<Self, XeroAccountingError> {
        let opaque_reference = opaque_reference.as_ref();
        validate_text(
            opaque_reference,
            "oauth2_secret_reference",
            MAX_IDENTIFIER_BYTES,
            false,
        )?;
        let reference_digest = Digest::from_serializable(&(
            "hartevo:xero-oauth2-secret-reference:v1",
            opaque_reference,
            &scope_digest,
            credential_revision,
        ));
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
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
}

impl fmt::Debug for OAuth2SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuth2SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XeroProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: ProviderRevision,
    pub api_digest: Digest,
    pub provider_digest: Digest,
}

impl XeroProviderDefinition {
    pub fn baseline() -> Self {
        let api_digest = crate::api_digest();
        let api_revision = ProviderRevision::new(XERO_ACCOUNTING_API_REVISION)
            .expect("checked-in Xero API revision");
        let provider_digest = Digest::from_serializable(&(
            XERO_ACCOUNTING_RESULT_PROVIDER_ID,
            XERO_ACCOUNTING_RESULT_PLUGIN_VERSION,
            &api_revision,
            &api_digest,
        ));
        Self {
            provider_id: XERO_ACCOUNTING_RESULT_PROVIDER_ID.to_owned(),
            provider_version: XERO_ACCOUNTING_RESULT_PLUGIN_VERSION.to_owned(),
            api_revision,
            api_digest,
            provider_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked { revision: Revision },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretState {
    Active,
    Revoked { revision: Revision },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    pub registration_digest: Digest,
    pub revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretRevocationReceipt {
    pub secret_reference_digest: Digest,
    pub revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XeroRegistration {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_digest: Digest,
    api_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    revision_digest: Digest,
    secret_reference_digest: Digest,
    registration_digest: Digest,
    state: RegistrationState,
    secret_state: SecretState,
}

impl XeroRegistration {
    pub fn new(
        scope: &XeroAccountingScope,
        secret_reference: &OAuth2SecretReference,
        provider: &XeroProviderDefinition,
    ) -> Result<Self, XeroAccountingError> {
        if secret_reference.scope_digest() != &scope.digest() {
            return Err(XeroAccountingError::ScopeMismatch(
                "OAuth2 SecretReference is bound to a different scope",
            ));
        }
        if provider.provider_id != XERO_ACCOUNTING_RESULT_PROVIDER_ID
            || provider.provider_version != XERO_ACCOUNTING_RESULT_PLUGIN_VERSION
            || provider.api_revision.as_str() != XERO_ACCOUNTING_API_REVISION
        {
            return Err(XeroAccountingError::ProviderRevisionDrift);
        }
        let contract_digest = crate::contract_digest();
        let permission_digest = scope.permission_digest();
        let scope_digest = scope.digest();
        let revision_digest = scope.revision_digest();
        let registration_digest = Digest::from_serializable(&RegistrationMaterial {
            plugin_version: XERO_ACCOUNTING_RESULT_PLUGIN_VERSION,
            contract_version: XERO_ACCOUNTING_RESULT_CONTRACT_VERSION,
            contract_digest: &contract_digest,
            provider_digest: &provider.provider_digest,
            api_digest: &provider.api_digest,
            permission_digest: &permission_digest,
            scope_digest: &scope_digest,
            revision_digest: &revision_digest,
            secret_reference_digest: secret_reference.reference_digest(),
        });
        Ok(Self {
            plugin_version: XERO_ACCOUNTING_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: XERO_ACCOUNTING_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest,
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest,
            scope_digest,
            revision_digest,
            secret_reference_digest: secret_reference.reference_digest().clone(),
            registration_digest,
            state: RegistrationState::Active,
            secret_state: SecretState::Active,
        })
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn state(&self) -> &RegistrationState {
        &self.state
    }

    pub fn secret_state(&self) -> &SecretState {
        &self.secret_state
    }

    pub fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
            && matches!(self.secret_state, SecretState::Active)
    }

    pub fn validate_active(
        &self,
        scope: &XeroAccountingScope,
        secret_reference: &OAuth2SecretReference,
        provider: &XeroProviderDefinition,
    ) -> Result<(), XeroAccountingError> {
        if !matches!(self.state, RegistrationState::Active) {
            return Err(XeroAccountingError::RegistrationRevoked);
        }
        if !matches!(self.secret_state, SecretState::Active) {
            return Err(XeroAccountingError::SecretRevoked);
        }
        let expected_scope_digest = scope.digest();
        if self.scope_digest != expected_scope_digest
            || secret_reference.scope_digest() != &expected_scope_digest
            || self.secret_reference_digest != *secret_reference.reference_digest()
        {
            return Err(XeroAccountingError::ScopeMismatch(
                "registration, scope, and SecretReference differ",
            ));
        }
        let expected_revision_digest = scope.revision_digest();
        if self.permission_digest != scope.permission_digest()
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.revision_digest != expected_revision_digest
            || self.contract_digest != crate::contract_digest()
            || self.plugin_version != XERO_ACCOUNTING_RESULT_PLUGIN_VERSION
            || self.contract_version != XERO_ACCOUNTING_RESULT_CONTRACT_VERSION
        {
            return Err(XeroAccountingError::RegistrationTampered);
        }
        let expected_registration_digest = Digest::from_serializable(&RegistrationMaterial {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            revision_digest: &self.revision_digest,
            secret_reference_digest: &self.secret_reference_digest,
        });
        if self.registration_digest != expected_registration_digest {
            return Err(XeroAccountingError::RegistrationTampered);
        }
        Ok(())
    }

    pub fn revoke(&mut self, revision: Revision) -> Result<RevocationReceipt, XeroAccountingError> {
        if !matches!(self.state, RegistrationState::Active) {
            return Err(XeroAccountingError::RegistrationRevoked);
        }
        self.state = RegistrationState::Revoked { revision };
        Ok(RevocationReceipt {
            registration_digest: self.registration_digest.clone(),
            revision,
        })
    }

    pub fn revoke_secret(
        &mut self,
        revision: Revision,
    ) -> Result<SecretRevocationReceipt, XeroAccountingError> {
        if !matches!(self.secret_state, SecretState::Active) {
            return Err(XeroAccountingError::SecretRevoked);
        }
        self.secret_state = SecretState::Revoked { revision };
        Ok(SecretRevocationReceipt {
            secret_reference_digest: self.secret_reference_digest.clone(),
            revision,
        })
    }
}

#[derive(Serialize)]
struct RegistrationMaterial<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    revision_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XeroEndpoint {
    Invoices,
    Payments,
    Contacts,
}

impl XeroEndpoint {
    pub const fn path(self) -> &'static str {
        match self {
            Self::Invoices => "/api.xro/2.0/Invoices",
            Self::Payments => "/api.xro/2.0/Payments",
            Self::Contacts => "/api.xro/2.0/Contacts",
        }
    }

    pub const fn allowlisted_fields(self) -> &'static [&'static str] {
        match self {
            Self::Invoices => INVOICE_FIELDS,
            Self::Payments => PAYMENT_FIELDS,
            Self::Contacts => CONTACT_FIELDS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DateBounds {
    from: String,
    to: String,
}

impl DateBounds {
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
    ) -> Result<Self, XeroAccountingError> {
        let from = from.into();
        let to = to.into();
        validate_text(&from, "date_from", 10, false)?;
        validate_text(&to, "date_to", 10, false)?;
        let bounds = Self { from, to };
        bounds.validate()?;
        Ok(bounds)
    }

    pub fn validate(&self) -> Result<(), XeroAccountingError> {
        let from_date = NaiveDate::parse_from_str(&self.from, "%Y-%m-%d").map_err(|_| {
            XeroAccountingError::InvalidField {
                field: "date_from",
                reason: "must be an ISO-8601 calendar date",
            }
        })?;
        let to_date = NaiveDate::parse_from_str(&self.to, "%Y-%m-%d").map_err(|_| {
            XeroAccountingError::InvalidField {
                field: "date_to",
                reason: "must be an ISO-8601 calendar date",
            }
        })?;
        let days = (to_date - from_date).num_days();
        if days <= 0 || days > MAX_DATE_RANGE_DAYS {
            return Err(XeroAccountingError::InvalidField {
                field: "date_bounds",
                reason: "must be a positive window within the Layer-1 maximum",
            });
        }
        Ok(())
    }

    pub fn from(&self) -> &str {
        &self.from
    }

    pub fn to(&self) -> &str {
        &self.to
    }
}

impl Default for DateBounds {
    fn default() -> Self {
        Self {
            from: "2026-01-01".to_owned(),
            to: "2026-12-31".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageBounds {
    page_size: u16,
    max_pages: u16,
}

impl PageBounds {
    pub fn new(page_size: u16, max_pages: u16) -> Result<Self, XeroAccountingError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(XeroAccountingError::InvalidField {
                field: "page_bounds",
                reason: "page size and page count exceed the Layer-1 limits",
            });
        }
        Ok(Self {
            page_size,
            max_pages,
        })
    }

    pub const fn page_size(self) -> u16 {
        self.page_size
    }

    pub const fn max_pages(self) -> u16 {
        self.max_pages
    }
}

impl Default for PageBounds {
    fn default() -> Self {
        Self {
            page_size: 50,
            max_pages: 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadBounds {
    pub max_response_bytes: usize,
    pub max_records: usize,
    pub pages: PageBounds,
}

impl ReadBounds {
    pub fn new(
        max_response_bytes: usize,
        max_records: usize,
        pages: PageBounds,
    ) -> Result<Self, XeroAccountingError> {
        let bounds = Self {
            max_response_bytes,
            max_records,
            pages,
        };
        bounds.validate()?;
        Ok(bounds)
    }

    pub fn validate(&self) -> Result<(), XeroAccountingError> {
        if self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_records == 0
            || self.max_records > MAX_RECORDS
            || self.pages.page_size() == 0
            || self.pages.page_size() > MAX_PAGE_SIZE
            || self.pages.max_pages() == 0
            || self.pages.max_pages() > MAX_PAGES
        {
            return Err(XeroAccountingError::InvalidField {
                field: "read_bounds",
                reason: "response, record, page size, or page count exceeds the Layer-1 maximum",
            });
        }
        Ok(())
    }
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_records: MAX_RECORDS,
            pages: PageBounds::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XeroReadRequest {
    include_contacts: bool,
    date_bounds: DateBounds,
    bounds: ReadBounds,
}

impl XeroReadRequest {
    pub fn new(
        include_contacts: bool,
        date_bounds: DateBounds,
        bounds: ReadBounds,
    ) -> Result<Self, XeroAccountingError> {
        date_bounds.validate()?;
        bounds.validate()?;
        Ok(Self {
            include_contacts,
            date_bounds,
            bounds,
        })
    }

    pub fn for_scope(scope: &XeroAccountingScope) -> Self {
        Self {
            include_contacts: scope.permissions.contacts_read(),
            date_bounds: DateBounds::default(),
            bounds: ReadBounds::default(),
        }
    }

    pub const fn include_contacts(&self) -> bool {
        self.include_contacts
    }

    pub fn date_bounds(&self) -> &DateBounds {
        &self.date_bounds
    }

    pub const fn bounds(&self) -> ReadBounds {
        self.bounds
    }

    pub fn endpoints(&self) -> Vec<XeroEndpoint> {
        let mut endpoints = vec![XeroEndpoint::Invoices, XeroEndpoint::Payments];
        if self.include_contacts {
            endpoints.push(XeroEndpoint::Contacts);
        }
        endpoints
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceStatus {
    Draft,
    Submitted,
    Authorised,
    Paid,
    Voided,
    Deleted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    Authorised,
    Deleted,
    Voided,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Money {
    currency: CurrencyCode,
    amount: Decimal,
}

impl Money {
    pub fn new(currency: CurrencyCode, amount: Decimal) -> Result<Self, XeroAccountingError> {
        if amount.is_sign_negative() || amount.scale() > 4 {
            return Err(XeroAccountingError::InvalidField {
                field: "amount",
                reason: "must be non-negative and have at most four decimal places",
            });
        }
        Ok(Self { currency, amount })
    }

    pub fn currency(&self) -> &CurrencyCode {
        &self.currency
    }

    pub const fn amount(&self) -> Decimal {
        self.amount
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XeroInvoiceRecord {
    pub id: InvoiceOrBillId,
    pub number: Option<String>,
    pub kind: InvoiceOrBillKind,
    pub status: InvoiceStatus,
    pub contact_id: ContactId,
    pub currency: CurrencyCode,
    pub subtotal: Money,
    pub total_tax: Money,
    pub total: Money,
    pub amount_due: Money,
    pub amount_paid: Money,
    pub amount_credited: Money,
    pub updated_revision: UpdatedRevision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XeroAccountRecord {
    pub id: AccountId,
    pub code: Option<String>,
    pub name: Option<String>,
    pub account_type: Option<String>,
    pub status: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XeroPaymentRecord {
    pub id: PaymentId,
    pub status: PaymentStatus,
    pub amount: Money,
    pub invoice_or_bill_id: InvoiceOrBillId,
    pub invoice_number: Option<String>,
    pub account: XeroAccountRecord,
    pub updated_revision: UpdatedRevision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XeroContactRecord {
    pub id: ContactId,
    pub name: Option<String>,
    pub status: Option<String>,
    pub updated_revision: UpdatedRevision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl EvidenceProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct EvidenceAuthority {
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub financial_advice: bool,
    pub durable_receipt: bool,
    pub independent_read_back: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl EvidenceAuthority {
    pub const fn layer1() -> Self {
        Self {
            read_only: true,
            connected: false,
            native: false,
            external_writes: false,
            financial_advice: false,
            durable_receipt: false,
            independent_read_back: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XeroAccountingEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub status: EvidenceStatus,
    pub provenance: EvidenceProvenance,
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub revision_digest: Digest,
    pub registration_digest: Digest,
    pub request_digest: Digest,
    pub redacted_response_digest: Digest,
    pub invoices: Vec<XeroInvoiceRecord>,
    pub payments: Vec<XeroPaymentRecord>,
    pub contacts: Vec<XeroContactRecord>,
    pub authority: EvidenceAuthority,
    pub evidence_digest: Digest,
}

impl XeroAccountingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn complete(
        provenance: EvidenceProvenance,
        scope: &XeroAccountingScope,
        registration: &XeroRegistration,
        request_digest: Digest,
        redacted_response_digest: Digest,
        invoices: Vec<XeroInvoiceRecord>,
        payments: Vec<XeroPaymentRecord>,
        contacts: Vec<XeroContactRecord>,
    ) -> Result<Self, XeroAccountingError> {
        let mut evidence = Self {
            contract_version: XERO_ACCOUNTING_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            status: EvidenceStatus::Complete,
            provenance,
            scope_digest: scope.digest(),
            provider_digest: registration.provider_digest().clone(),
            api_digest: registration.api_digest().clone(),
            permission_digest: registration.permission_digest().clone(),
            revision_digest: registration.revision_digest().clone(),
            registration_digest: registration.registration_digest().clone(),
            request_digest,
            redacted_response_digest,
            invoices,
            payments,
            contacts,
            authority: EvidenceAuthority::layer1(),
            evidence_digest: Digest::from_bytes(&[]),
        };
        evidence.validate_records(scope)?;
        evidence.evidence_digest = evidence.computed_digest();
        Ok(evidence)
    }

    pub(crate) fn blocked_env(
        scope: &XeroAccountingScope,
        registration: &XeroRegistration,
        request_digest: &Digest,
    ) -> Self {
        let mut evidence = Self {
            contract_version: XERO_ACCOUNTING_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            status: EvidenceStatus::BlockedEnv,
            provenance: EvidenceProvenance::BlockedEnv,
            scope_digest: scope.digest(),
            provider_digest: registration.provider_digest().clone(),
            api_digest: registration.api_digest().clone(),
            permission_digest: registration.permission_digest().clone(),
            revision_digest: registration.revision_digest().clone(),
            registration_digest: registration.registration_digest().clone(),
            request_digest: request_digest.clone(),
            redacted_response_digest: Digest::from_serializable(&(
                "BLOCKED_ENV",
                &request_digest,
                scope.digest(),
            )),
            invoices: Vec::new(),
            payments: Vec::new(),
            contacts: Vec::new(),
            authority: EvidenceAuthority::layer1(),
            evidence_digest: Digest::from_bytes(&[]),
        };
        evidence.evidence_digest = evidence.computed_digest();
        evidence
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serializable(&EvidenceMaterial {
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            status: self.status,
            provenance: self.provenance,
            scope_digest: &self.scope_digest,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            permission_digest: &self.permission_digest,
            revision_digest: &self.revision_digest,
            registration_digest: &self.registration_digest,
            request_digest: &self.request_digest,
            redacted_response_digest: &self.redacted_response_digest,
            invoices: &self.invoices,
            payments: &self.payments,
            contacts: &self.contacts,
            authority: self.authority,
        })
    }

    pub fn validate(
        &self,
        scope: &XeroAccountingScope,
        registration: &XeroRegistration,
    ) -> Result<(), XeroAccountingError> {
        if self.contract_version != XERO_ACCOUNTING_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.scope_digest != scope.digest()
            || self.provider_digest != *registration.provider_digest()
            || self.api_digest != *registration.api_digest()
            || self.permission_digest != *registration.permission_digest()
            || self.revision_digest != *registration.revision_digest()
            || self.registration_digest != *registration.registration_digest()
            || self.authority != EvidenceAuthority::layer1()
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.evidence_digest != self.computed_digest()
        {
            return Err(XeroAccountingError::EvidenceTampered);
        }
        match self.status {
            EvidenceStatus::BlockedEnv => {
                if self.provenance != EvidenceProvenance::BlockedEnv
                    || !self.invoices.is_empty()
                    || !self.payments.is_empty()
                    || !self.contacts.is_empty()
                {
                    return Err(XeroAccountingError::EvidenceTampered);
                }
            }
            EvidenceStatus::Complete => self.validate_records(scope)?,
        }
        Ok(())
    }

    pub fn validate_for_scope(
        &self,
        scope: &XeroAccountingScope,
    ) -> Result<(), XeroAccountingError> {
        if self.contract_version != XERO_ACCOUNTING_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.scope_digest != scope.digest()
            || self.authority != EvidenceAuthority::layer1()
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.evidence_digest != self.computed_digest()
        {
            return Err(XeroAccountingError::EvidenceTampered);
        }
        match self.status {
            EvidenceStatus::BlockedEnv => {
                if self.provenance != EvidenceProvenance::BlockedEnv
                    || !self.invoices.is_empty()
                    || !self.payments.is_empty()
                    || !self.contacts.is_empty()
                {
                    return Err(XeroAccountingError::EvidenceTampered);
                }
            }
            EvidenceStatus::Complete => self.validate_records(scope)?,
        }
        Ok(())
    }

    fn validate_records(&self, scope: &XeroAccountingScope) -> Result<(), XeroAccountingError> {
        if self.invoices.len() > MAX_RECORDS
            || self.payments.len() > MAX_RECORDS
            || self.contacts.len() > MAX_RECORDS
        {
            return Err(XeroAccountingError::RecordBoundExceeded);
        }
        if self.status == EvidenceStatus::Complete
            && (self.invoices.is_empty() || self.payments.is_empty())
        {
            return Err(XeroAccountingError::NotFound);
        }
        for invoice in &self.invoices {
            if invoice.id != *scope.invoice_or_bill().id()
                || invoice.kind != scope.invoice_or_bill().kind()
                || invoice.contact_id != *scope.contact_id()
                || invoice.currency != *scope.currency()
                || invoice.updated_revision != *scope.updated_revision()
            {
                return Err(XeroAccountingError::OutOfScopeRecord);
            }
            for money in [
                &invoice.subtotal,
                &invoice.total_tax,
                &invoice.total,
                &invoice.amount_due,
                &invoice.amount_paid,
                &invoice.amount_credited,
            ] {
                if money.currency() != scope.currency() {
                    return Err(XeroAccountingError::CurrencyMismatch {
                        field: "invoice_amount",
                    });
                }
            }
            if invoice.total.amount()
                != invoice.amount_due.amount()
                    + invoice.amount_paid.amount()
                    + invoice.amount_credited.amount()
            {
                return Err(XeroAccountingError::AmountMismatch {
                    field: "invoice_total",
                });
            }
            if invoice.status == InvoiceStatus::Paid && invoice.amount_due.amount() != Decimal::ZERO
            {
                return Err(XeroAccountingError::AmountMismatch {
                    field: "paid_invoice_amount_due",
                });
            }
        }
        for payment in &self.payments {
            if payment.id != *scope.payment_id()
                || payment.invoice_or_bill_id != *scope.invoice_or_bill().id()
                || payment.account.id != *scope.account_id()
                || payment.amount.currency() != scope.currency()
                || payment.updated_revision != *scope.updated_revision()
            {
                return Err(XeroAccountingError::OutOfScopeRecord);
            }
            if payment.amount.amount() <= Decimal::ZERO {
                return Err(XeroAccountingError::AmountMismatch {
                    field: "payment_amount",
                });
            }
        }
        for contact in &self.contacts {
            if contact.id != *scope.contact_id()
                || contact.updated_revision != *scope.updated_revision()
            {
                return Err(XeroAccountingError::OutOfScopeRecord);
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct EvidenceMaterial<'a> {
    contract_version: &'a str,
    contract_digest: &'a Digest,
    status: EvidenceStatus,
    provenance: EvidenceProvenance,
    scope_digest: &'a Digest,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    revision_digest: &'a Digest,
    registration_digest: &'a Digest,
    request_digest: &'a Digest,
    redacted_response_digest: &'a Digest,
    invoices: &'a [XeroInvoiceRecord],
    payments: &'a [XeroPaymentRecord],
    contacts: &'a [XeroContactRecord],
    authority: EvidenceAuthority,
}

pub const fn contract_schema_version() -> &'static str {
    XERO_ACCOUNTING_RESULT_SCHEMA_VERSION
}

pub const fn service_id() -> &'static str {
    XERO_ACCOUNTING_RESULT_SERVICE_ID
}
