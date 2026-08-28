//! Narrow Xero Accounting transport seams.
//!
//! The transport surface exposes exactly one operation: bounded `GET` for one
//! of the three checked-in endpoint paths. Recording, fixture, loopback, and
//! BLOCKED_ENV implementations are intentionally non-native evidence modes;
//! none can mint Connected/native authority.

use std::{collections::VecDeque, fmt};

use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    AccountId, ContactId, CurrencyCode, Digest, InvoiceOrBillId, InvoiceOrBillKind, InvoiceStatus,
    Money, PageBounds, PaymentId, PaymentStatus, ReadBounds, UpdatedRevision, XeroAccountRecord,
    XeroAccountingScope, XeroContactRecord, XeroEndpoint, XeroInvoiceRecord, XeroPaymentRecord,
};
use crate::{XERO_ACCOUNTING_API_REVISION, XeroAccountingError};
use crate::{model::EvidenceProvenance, provider::OAuth2CredentialLease};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum XeroTransportError {
    #[error("BLOCKED_ENV: native Xero transport is unavailable")]
    BlockedEnv,
    #[error("Xero transport request is invalid: {0}")]
    InvalidRequest(String),
    #[error("Xero transport response exceeded its bound")]
    ResponseTooLarge,
    #[error("Xero transport response could not be decoded: {0}")]
    Decode(String),
    #[error("Xero transport credential is unavailable")]
    CredentialUnavailable,
    #[error("Xero transport failed: {0}")]
    Transport(String),
}

impl From<XeroTransportError> for XeroAccountingError {
    fn from(error: XeroTransportError) -> Self {
        match error {
            XeroTransportError::BlockedEnv => Self::BlockedEnv,
            XeroTransportError::ResponseTooLarge => Self::ResponseTooLarge,
            XeroTransportError::InvalidRequest(message)
            | XeroTransportError::Decode(message)
            | XeroTransportError::Transport(message) => Self::Transport(message),
            XeroTransportError::CredentialUnavailable => {
                Self::Credential("credential lease is unavailable".to_owned())
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XeroHttpRequest {
    pub endpoint: XeroEndpoint,
    pub tenant_id: String,
    pub page: u16,
    pub page_size: u16,
    pub max_response_bytes: usize,
    pub scope_digest: Digest,
    query: Vec<(String, String)>,
}

impl XeroHttpRequest {
    pub fn new(
        endpoint: XeroEndpoint,
        scope: &XeroAccountingScope,
        date_bounds: &crate::DateBounds,
        bounds: ReadBounds,
        page: u16,
    ) -> Result<Self, XeroAccountingError> {
        if page == 0 || page > bounds.pages.max_pages() {
            return Err(XeroAccountingError::PageBoundExceeded);
        }
        let query = fixed_query(endpoint, scope, date_bounds, bounds.pages, page)?;
        Ok(Self {
            endpoint,
            tenant_id: scope.tenant_id().as_str().to_owned(),
            page,
            page_size: bounds.pages.page_size(),
            max_response_bytes: bounds.max_response_bytes,
            scope_digest: scope.digest(),
            query,
        })
    }

    pub fn method(&self) -> &'static str {
        "GET"
    }

    pub fn path_and_query(&self) -> String {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in &self.query {
            serializer.append_pair(key, value);
        }
        let query = serializer.finish();
        format!("{}?{query}", self.endpoint.path())
    }

    pub fn query(&self) -> &[(String, String)] {
        &self.query
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

fn fixed_query(
    endpoint: XeroEndpoint,
    scope: &XeroAccountingScope,
    date_bounds: &crate::DateBounds,
    pages: PageBounds,
    page: u16,
) -> Result<Vec<(String, String)>, XeroAccountingError> {
    let target_filter = match endpoint {
        XeroEndpoint::Invoices => format!(
            "InvoiceID==Guid(\"{}\")",
            scope.invoice_or_bill().id().as_str()
        ),
        XeroEndpoint::Payments => {
            format!("PaymentID==Guid(\"{}\")", scope.payment_id().as_str())
        }
        XeroEndpoint::Contacts => format!("ContactID==Guid(\"{}\")", scope.contact_id().as_str()),
    };
    let from = date_time_components(date_bounds.from())?;
    let to = date_time_components(date_bounds.to())?;
    let date_field = if endpoint == XeroEndpoint::Contacts {
        "UpdatedDateUTC"
    } else {
        "Date"
    };
    let bounded_filter = format!(
        "{target_filter} AND {date_field}>=DateTime({from}) AND {date_field}<DateTime({to})"
    );
    let mut query = vec![
        ("where".to_owned(), bounded_filter),
        ("page".to_owned(), page.to_string()),
        ("pageSize".to_owned(), pages.page_size().to_string()),
        ("order".to_owned(), "UpdatedDateUTC ASC".to_owned()),
    ];
    if endpoint == XeroEndpoint::Invoices {
        query.push(("unitdp".to_owned(), "4".to_owned()));
    }
    Ok(query)
}

fn date_time_components(value: &str) -> Result<String, XeroAccountingError> {
    let mut pieces = value.split('-');
    let year = pieces.next().ok_or(XeroAccountingError::InvalidField {
        field: "date_bounds",
        reason: "invalid date",
    })?;
    let month = pieces.next().ok_or(XeroAccountingError::InvalidField {
        field: "date_bounds",
        reason: "invalid date",
    })?;
    let day = pieces.next().ok_or(XeroAccountingError::InvalidField {
        field: "date_bounds",
        reason: "invalid date",
    })?;
    Ok(format!("{year}, {month}, {day}"))
}

/// A response retains the body only until the provider parses it. Its Debug
/// output never reveals body bytes, and no body is part of the evidence model.
#[derive(Clone, Eq, PartialEq)]
pub struct XeroHttpResponse {
    status: u16,
    body: Vec<u8>,
    api_revision: String,
    provider_revision: String,
    scope_digest: Option<Digest>,
    permission_digest: Option<Digest>,
}

impl fmt::Debug for XeroHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XeroHttpResponse")
            .field("status", &self.status)
            .field("response_size", &self.body.len())
            .field("api_revision", &self.api_revision)
            .field("provider_revision", &self.provider_revision)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .finish_non_exhaustive()
    }
}

impl XeroHttpResponse {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
            api_revision: XERO_ACCOUNTING_API_REVISION.to_owned(),
            provider_revision: XERO_ACCOUNTING_API_REVISION.to_owned(),
            scope_digest: None,
            permission_digest: None,
        }
    }

    pub fn json(status: u16, body: &str) -> Self {
        Self::new(status, body.as_bytes().to_vec())
    }

    #[must_use]
    pub fn with_fences(mut self, scope_digest: Digest, permission_digest: Digest) -> Self {
        self.scope_digest = Some(scope_digest);
        self.permission_digest = Some(permission_digest);
        self
    }

    #[must_use]
    pub fn with_api_revision(mut self, api_revision: impl Into<String>) -> Self {
        self.api_revision = api_revision.into();
        self
    }

    #[must_use]
    pub fn with_provider_revision(mut self, provider_revision: impl Into<String>) -> Self {
        self.provider_revision = provider_revision.into();
        self
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub fn response_size(&self) -> usize {
        self.body.len()
    }

    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn scope_digest(&self) -> Option<&Digest> {
        self.scope_digest.as_ref()
    }

    pub fn permission_digest(&self) -> Option<&Digest> {
        self.permission_digest.as_ref()
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
}

pub trait XeroTransport: fmt::Debug {
    fn get(
        &mut self,
        credential: &OAuth2CredentialLease,
        request: &XeroHttpRequest,
    ) -> Result<XeroHttpResponse, XeroTransportError>;

    fn provenance(&self) -> EvidenceProvenance;
}

/// A deterministic response queue used for recording evidence.
pub struct RecordingXeroTransport {
    provenance: EvidenceProvenance,
    responses: VecDeque<Result<XeroHttpResponse, XeroTransportError>>,
    requests: Vec<XeroHttpRequest>,
}

impl Default for RecordingXeroTransport {
    fn default() -> Self {
        Self::new([])
    }
}

impl fmt::Debug for RecordingXeroTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingXeroTransport")
            .field("provenance", &self.provenance)
            .field("queued_responses", &self.responses.len())
            .field("requests", &self.requests)
            .finish()
    }
}

impl RecordingXeroTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<XeroHttpResponse, XeroTransportError>>,
    ) -> Self {
        Self::with_provenance(EvidenceProvenance::Recording, responses)
    }

    pub fn with_provenance(
        provenance: EvidenceProvenance,
        responses: impl IntoIterator<Item = Result<XeroHttpResponse, XeroTransportError>>,
    ) -> Self {
        Self {
            provenance,
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(&mut self, response: Result<XeroHttpResponse, XeroTransportError>) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[XeroHttpRequest] {
        &self.requests
    }

    pub fn remaining_responses(&self) -> usize {
        self.responses.len()
    }
}

impl XeroTransport for RecordingXeroTransport {
    fn get(
        &mut self,
        credential: &OAuth2CredentialLease,
        request: &XeroHttpRequest,
    ) -> Result<XeroHttpResponse, XeroTransportError> {
        if !credential.is_usable() {
            return Err(XeroTransportError::CredentialUnavailable);
        }
        if request.method() != "GET" {
            return Err(XeroTransportError::InvalidRequest(
                "only GET is available in the Xero Layer-1 transport".to_owned(),
            ));
        }
        self.requests.push(request.clone());
        self.responses.pop_front().ok_or_else(|| {
            XeroTransportError::Transport("recording response queue exhausted".to_owned())
        })?
    }

    fn provenance(&self) -> EvidenceProvenance {
        self.provenance
    }
}

pub struct FixtureXeroTransport {
    inner: RecordingXeroTransport,
}

impl fmt::Debug for FixtureXeroTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureXeroTransport")
            .field("inner", &self.inner)
            .finish()
    }
}

impl FixtureXeroTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<XeroHttpResponse, XeroTransportError>>,
    ) -> Self {
        Self {
            inner: RecordingXeroTransport::with_provenance(EvidenceProvenance::Fixture, responses),
        }
    }

    pub fn requests(&self) -> &[XeroHttpRequest] {
        self.inner.requests()
    }
}

impl XeroTransport for FixtureXeroTransport {
    fn get(
        &mut self,
        credential: &OAuth2CredentialLease,
        request: &XeroHttpRequest,
    ) -> Result<XeroHttpResponse, XeroTransportError> {
        self.inner.get(credential, request)
    }

    fn provenance(&self) -> EvidenceProvenance {
        EvidenceProvenance::Fixture
    }
}

pub struct LoopbackXeroTransport {
    inner: RecordingXeroTransport,
}

impl fmt::Debug for LoopbackXeroTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackXeroTransport")
            .field("inner", &self.inner)
            .finish()
    }
}

impl LoopbackXeroTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<XeroHttpResponse, XeroTransportError>>,
    ) -> Self {
        Self {
            inner: RecordingXeroTransport::with_provenance(EvidenceProvenance::Loopback, responses),
        }
    }

    pub fn requests(&self) -> &[XeroHttpRequest] {
        self.inner.requests()
    }
}

impl XeroTransport for LoopbackXeroTransport {
    fn get(
        &mut self,
        credential: &OAuth2CredentialLease,
        request: &XeroHttpRequest,
    ) -> Result<XeroHttpResponse, XeroTransportError> {
        self.inner.get(credential, request)
    }

    fn provenance(&self) -> EvidenceProvenance {
        EvidenceProvenance::Loopback
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvXeroTransport;

impl XeroTransport for BlockedEnvXeroTransport {
    fn get(
        &mut self,
        _credential: &OAuth2CredentialLease,
        _request: &XeroHttpRequest,
    ) -> Result<XeroHttpResponse, XeroTransportError> {
        Err(XeroTransportError::BlockedEnv)
    }

    fn provenance(&self) -> EvidenceProvenance {
        EvidenceProvenance::BlockedEnv
    }
}

#[derive(Clone, Debug, Deserialize)]
struct InvoicesEnvelope {
    #[serde(rename = "Invoices", default)]
    invoices: Vec<RawInvoice>,
}

#[derive(Clone, Debug, Deserialize)]
struct PaymentsEnvelope {
    #[serde(rename = "Payments", default)]
    payments: Vec<RawPayment>,
}

#[derive(Clone, Debug, Deserialize)]
struct ContactsEnvelope {
    #[serde(rename = "Contacts", default)]
    contacts: Vec<RawContact>,
}

#[derive(Clone, Debug, Deserialize)]
struct RawInvoice {
    #[serde(rename = "InvoiceID")]
    invoice_id: Option<String>,
    #[serde(rename = "InvoiceNumber")]
    invoice_number: Option<String>,
    #[serde(rename = "Type")]
    kind: Option<String>,
    #[serde(rename = "Status")]
    status: Option<String>,
    #[serde(rename = "CurrencyCode")]
    currency_code: Option<String>,
    #[serde(rename = "SubTotal")]
    subtotal: Option<Value>,
    #[serde(rename = "TotalTax")]
    total_tax: Option<Value>,
    #[serde(rename = "Total")]
    total: Option<Value>,
    #[serde(rename = "AmountDue")]
    amount_due: Option<Value>,
    #[serde(rename = "AmountPaid")]
    amount_paid: Option<Value>,
    #[serde(rename = "AmountCredited")]
    amount_credited: Option<Value>,
    #[serde(rename = "UpdatedDateUTC")]
    updated_revision: Option<String>,
    #[serde(rename = "Contact")]
    contact: Option<RawContact>,
}

#[derive(Clone, Debug, Deserialize)]
struct RawPayment {
    #[serde(rename = "PaymentID")]
    payment_id: Option<String>,
    #[serde(rename = "Status")]
    status: Option<String>,
    #[serde(rename = "Amount")]
    amount: Option<Value>,
    #[serde(rename = "CurrencyCode")]
    currency_code: Option<String>,
    #[serde(rename = "UpdatedDateUTC")]
    updated_revision: Option<String>,
    #[serde(rename = "Invoice")]
    invoice: Option<RawPaymentInvoice>,
    #[serde(rename = "Account")]
    account: Option<RawAccount>,
}

#[derive(Clone, Debug, Deserialize)]
struct RawPaymentInvoice {
    #[serde(rename = "InvoiceID")]
    invoice_id: Option<String>,
    #[serde(rename = "InvoiceNumber")]
    invoice_number: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct RawAccount {
    #[serde(rename = "AccountID")]
    account_id: Option<String>,
    #[serde(rename = "Code")]
    code: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Type")]
    account_type: Option<String>,
    #[serde(rename = "Status")]
    status: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct RawContact {
    #[serde(rename = "ContactID")]
    contact_id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "ContactStatus")]
    status: Option<String>,
    #[serde(rename = "UpdatedDateUTC")]
    updated_revision: Option<String>,
}

#[derive(Clone, serde::Serialize)]
pub enum XeroResponsePayload {
    Invoices(Vec<XeroInvoiceRecord>),
    Payments(Vec<XeroPaymentRecord>),
    Contacts(Vec<XeroContactRecord>),
}

impl XeroResponsePayload {
    pub fn len(&self) -> usize {
        match self {
            Self::Invoices(records) => records.len(),
            Self::Payments(records) => records.len(),
            Self::Contacts(records) => records.len(),
        }
    }

    pub const fn is_empty(&self) -> bool {
        match self {
            Self::Invoices(records) => records.is_empty(),
            Self::Payments(records) => records.is_empty(),
            Self::Contacts(records) => records.is_empty(),
        }
    }

    pub fn redacted_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

impl fmt::Debug for XeroResponsePayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XeroResponsePayload")
            .field(
                "kind",
                &match self {
                    Self::Invoices(_) => "invoices",
                    Self::Payments(_) => "payments",
                    Self::Contacts(_) => "contacts",
                },
            )
            .field("record_count", &self.len())
            .finish()
    }
}

pub fn parse_payload(
    endpoint: XeroEndpoint,
    body: &[u8],
    fallback_currency: &CurrencyCode,
) -> Result<XeroResponsePayload, XeroAccountingError> {
    match endpoint {
        XeroEndpoint::Invoices => {
            let envelope = serde_json::from_slice::<InvoicesEnvelope>(body)
                .map_err(|error| XeroAccountingError::Decode(error.to_string()))?;
            envelope
                .invoices
                .into_iter()
                .map(parse_invoice)
                .collect::<Result<Vec<_>, _>>()
                .map(XeroResponsePayload::Invoices)
        }
        XeroEndpoint::Payments => {
            let envelope = serde_json::from_slice::<PaymentsEnvelope>(body)
                .map_err(|error| XeroAccountingError::Decode(error.to_string()))?;
            envelope
                .payments
                .into_iter()
                .map(|payment| parse_payment(payment, fallback_currency))
                .collect::<Result<Vec<_>, _>>()
                .map(XeroResponsePayload::Payments)
        }
        XeroEndpoint::Contacts => {
            let envelope = serde_json::from_slice::<ContactsEnvelope>(body)
                .map_err(|error| XeroAccountingError::Decode(error.to_string()))?;
            envelope
                .contacts
                .into_iter()
                .map(parse_contact)
                .collect::<Result<Vec<_>, _>>()
                .map(XeroResponsePayload::Contacts)
        }
    }
}

fn parse_invoice(raw: RawInvoice) -> Result<XeroInvoiceRecord, XeroAccountingError> {
    let id = InvoiceOrBillId::new(required_string(raw.invoice_id, "InvoiceID")?)?;
    let kind = match required_string(raw.kind, "Type")?
        .to_ascii_uppercase()
        .as_str()
    {
        "ACCREC" => InvoiceOrBillKind::Invoice,
        "ACCPAY" => InvoiceOrBillKind::Bill,
        _ => return Err(XeroAccountingError::UnsupportedOperation),
    };
    let status = parse_invoice_status(&required_string(raw.status, "Status")?)?;
    let currency = CurrencyCode::new(required_string(raw.currency_code, "CurrencyCode")?)?;
    let contact = raw.contact.ok_or(XeroAccountingError::Decode(
        "invoice contact is missing".to_owned(),
    ))?;
    let contact_id = ContactId::new(required_string(contact.contact_id, "Contact.ContactID")?)?;
    let updated_revision =
        UpdatedRevision::new(required_string(raw.updated_revision, "UpdatedDateUTC")?)?;
    let subtotal = money(&currency, raw.subtotal, "SubTotal")?;
    let total_tax = money(&currency, raw.total_tax, "TotalTax")?;
    let total = money(&currency, raw.total, "Total")?;
    let amount_due = money(&currency, raw.amount_due, "AmountDue")?;
    let amount_paid = money(&currency, raw.amount_paid, "AmountPaid")?;
    let amount_credited = match raw.amount_credited {
        Some(value) => money(&currency, Some(value), "AmountCredited")?,
        None => Money::new(currency.clone(), Decimal::ZERO)?,
    };
    Ok(XeroInvoiceRecord {
        id,
        number: optional_bounded_text(raw.invoice_number, "InvoiceNumber")?,
        kind,
        status,
        contact_id,
        currency,
        subtotal,
        total_tax,
        total,
        amount_due,
        amount_paid,
        amount_credited,
        updated_revision,
    })
}

fn parse_payment(
    raw: RawPayment,
    fallback_currency: &CurrencyCode,
) -> Result<XeroPaymentRecord, XeroAccountingError> {
    let id = PaymentId::new(required_string(raw.payment_id, "PaymentID")?)?;
    let status = parse_payment_status(&required_string(raw.status, "Status")?)?;
    let currency = match raw.currency_code {
        Some(value) => CurrencyCode::new(value)?,
        None => fallback_currency.clone(),
    };
    let amount = money(&currency, raw.amount, "Amount")?;
    let invoice = raw.invoice.ok_or(XeroAccountingError::Decode(
        "payment invoice is missing".to_owned(),
    ))?;
    let invoice_or_bill_id =
        InvoiceOrBillId::new(required_string(invoice.invoice_id, "Invoice.InvoiceID")?)?;
    let account = raw.account.ok_or(XeroAccountingError::Decode(
        "payment account is missing".to_owned(),
    ))?;
    let account = XeroAccountRecord {
        id: AccountId::new(required_string(account.account_id, "Account.AccountID")?)?,
        code: optional_bounded_text(account.code, "Account.Code")?,
        name: optional_bounded_text(account.name, "Account.Name")?,
        account_type: optional_bounded_text(account.account_type, "Account.Type")?,
        status: optional_bounded_text(account.status, "Account.Status")?,
    };
    Ok(XeroPaymentRecord {
        id,
        status,
        amount,
        invoice_or_bill_id,
        invoice_number: optional_bounded_text(invoice.invoice_number, "Invoice.InvoiceNumber")?,
        account,
        updated_revision: UpdatedRevision::new(required_string(
            raw.updated_revision,
            "UpdatedDateUTC",
        )?)?,
    })
}

fn parse_contact(raw: RawContact) -> Result<XeroContactRecord, XeroAccountingError> {
    Ok(XeroContactRecord {
        id: ContactId::new(required_string(raw.contact_id, "ContactID")?)?,
        name: optional_bounded_text(raw.name, "Name")?,
        status: optional_bounded_text(raw.status, "ContactStatus")?,
        updated_revision: UpdatedRevision::new(required_string(
            raw.updated_revision,
            "UpdatedDateUTC",
        )?)?,
    })
}

fn parse_invoice_status(value: &str) -> Result<InvoiceStatus, XeroAccountingError> {
    match value.to_ascii_uppercase().as_str() {
        "DRAFT" => Ok(InvoiceStatus::Draft),
        "SUBMITTED" => Ok(InvoiceStatus::Submitted),
        "AUTHORISED" | "AUTHORIZED" => Ok(InvoiceStatus::Authorised),
        "PAID" => Ok(InvoiceStatus::Paid),
        "VOIDED" => Ok(InvoiceStatus::Voided),
        "DELETED" => Ok(InvoiceStatus::Deleted),
        _ => Err(XeroAccountingError::UnsupportedStatus),
    }
}

fn parse_payment_status(value: &str) -> Result<PaymentStatus, XeroAccountingError> {
    match value.to_ascii_uppercase().as_str() {
        "AUTHORISED" | "AUTHORIZED" => Ok(PaymentStatus::Authorised),
        "DELETED" => Ok(PaymentStatus::Deleted),
        "VOIDED" => Ok(PaymentStatus::Voided),
        _ => Err(XeroAccountingError::UnsupportedStatus),
    }
}

fn required_string(
    value: Option<String>,
    field: &'static str,
) -> Result<String, XeroAccountingError> {
    let value = value.ok_or_else(|| XeroAccountingError::Decode(format!("{field} is missing")))?;
    if value.trim().is_empty() {
        return Err(XeroAccountingError::Decode(format!("{field} is empty")));
    }
    Ok(value)
}

fn optional_bounded_text(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<String>, XeroAccountingError> {
    if let Some(value) = &value
        && (value.len() > crate::model::MAX_TEXT_BYTES
            || value.chars().any(char::is_control)
            || value.trim() != value)
    {
        return Err(XeroAccountingError::InvalidField {
            field,
            reason: "must be a bounded display value",
        });
    }
    Ok(value)
}

fn money(
    currency: &CurrencyCode,
    value: Option<Value>,
    field: &'static str,
) -> Result<Money, XeroAccountingError> {
    let value = value.ok_or_else(|| XeroAccountingError::Decode(format!("{field} is missing")))?;
    let text = match value {
        Value::Number(number) => number.to_string(),
        Value::String(string) => string,
        _ => {
            return Err(XeroAccountingError::Decode(format!(
                "{field} is not a JSON number or decimal string"
            )));
        }
    };
    let amount = Decimal::from_str_exact(&text).map_err(|_| {
        XeroAccountingError::Decode(format!("{field} is not a valid decimal amount"))
    })?;
    Money::new(currency.clone(), amount)
}
