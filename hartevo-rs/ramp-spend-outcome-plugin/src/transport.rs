//! Official Ramp Developer API routes, bounded payload adapters, and
//! deterministic Layer-1 transports.

use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    BoundIdentifier, DateWindow, Digest, RampSpendScope, RefundState, TransportProvenance,
    canonical_digest, sha256_digest, validate_bounded_text, validate_cursor, validate_event_type,
    validate_high_water, validate_identifier, validate_page_size,
};
use crate::{
    MAX_AUDIT_EVENTS, MAX_CURSOR_BYTES, MAX_EVENT_TYPE_BYTES, MAX_IDENTIFIER_BYTES, MAX_MERCHANTS,
    MAX_PAGE_SIZE, MAX_PAGES, MAX_TRANSACTIONS,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RampTransportError {
    #[error("BLOCKED_ENV: native Ramp OAuth/client credential authority is unavailable")]
    BlockedEnv,
    #[error("Ramp returned HTTP 401")]
    Unauthorized401,
    #[error("Ramp returned HTTP 403")]
    Forbidden403,
    #[error("Ramp returned HTTP 404")]
    NotFound404,
    #[error("Ramp returned HTTP 409")]
    Conflict409,
    #[error("Ramp returned HTTP 429")]
    RateLimited429 { retry_after_seconds: Option<u64> },
    #[error("Ramp returned HTTP 504")]
    GatewayTimeout504,
    #[error("Ramp returned HTTP {status}")]
    Server5xx { status: u16 },
    #[error("Ramp request timed out")]
    Timeout,
    #[error("Ramp data was unavailable because retention was insufficient")]
    RetentionGap,
    #[error("Ramp access was lost while reading the bounded scope")]
    AccessLost,
    #[error("Ramp returned a partial response")]
    PartialResponse,
    #[error("Ramp response is provider-unknown")]
    ProviderUnknown,
    #[error("Ramp response is invalid or exceeds the bounded contract")]
    InvalidResponse,
    #[error("Ramp response fingerprint was tampered")]
    ResponseTampered,
}

impl RampTransportError {
    #[must_use]
    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited429 { .. }
                | Self::GatewayTimeout504
                | Self::Server5xx { .. }
                | Self::Timeout
        )
    }

    #[must_use]
    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized401 | Self::Forbidden403 | Self::AccessLost
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub initial_backoff_seconds: u64,
    pub max_backoff_seconds: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_seconds: 1,
            max_backoff_seconds: 32,
        }
    }
}

impl RetryPolicy {
    pub fn new(
        max_attempts: u8,
        initial_backoff_seconds: u64,
        max_backoff_seconds: u64,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        if !(1..=5).contains(&max_attempts)
            || initial_backoff_seconds == 0
            || initial_backoff_seconds > max_backoff_seconds
            || max_backoff_seconds > 300
        {
            return Err(crate::RampSpendOutcomeError::InvalidRetryPolicy);
        }
        Ok(Self {
            max_attempts,
            initial_backoff_seconds,
            max_backoff_seconds,
        })
    }

    #[must_use]
    pub fn delay_seconds(&self, failed_attempt: u8, error: &RampTransportError) -> u64 {
        if let RampTransportError::RateLimited429 {
            retry_after_seconds: Some(retry_after),
        } = error
        {
            return (*retry_after).min(self.max_backoff_seconds);
        }
        let exponent = u32::from(failed_attempt.saturating_sub(1)).min(8);
        self.initial_backoff_seconds
            .saturating_mul(2_u64.saturating_pow(exponent))
            .min(self.max_backoff_seconds)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RampEndpoint {
    Transactions,
    Merchants,
    AuditLogs,
}

impl RampEndpoint {
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Transactions => "/developer/v1/transactions",
            Self::Merchants => "/developer/v1/merchants",
            Self::AuditLogs => "/developer/v1/audit-logs/events",
        }
    }

    #[must_use]
    pub const fn required_scope(self) -> crate::RampReadScope {
        match self {
            Self::Transactions => crate::RampReadScope::TransactionsRead,
            Self::Merchants => crate::RampReadScope::MerchantsRead,
            Self::AuditLogs => crate::RampReadScope::AuditLogsRead,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReadOperation {
    ReadTransactions,
    ReadMerchants,
    ReadAuditLogs,
}

impl ReadOperation {
    #[must_use]
    pub const fn endpoint(self) -> RampEndpoint {
        match self {
            Self::ReadTransactions => RampEndpoint::Transactions,
            Self::ReadMerchants => RampEndpoint::Merchants,
            Self::ReadAuditLogs => RampEndpoint::AuditLogs,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RampReadRequest {
    pub operation: ReadOperation,
    pub endpoint: RampEndpoint,
    pub scope_digest: Digest,
    pub business_id: BoundIdentifier,
    pub entity_id: Option<BoundIdentifier>,
    pub spend_program_id: Option<BoundIdentifier>,
    pub card_id: Option<BoundIdentifier>,
    pub vendor_id: Option<BoundIdentifier>,
    pub transaction_id: Option<BoundIdentifier>,
    pub audit_event_id: Option<BoundIdentifier>,
    pub date_window: DateWindow,
    pub page_size: usize,
    pub cursor: Option<String>,
    pub high_water_mark: Option<String>,
    pub attempt: u8,
    pub backoff_seconds: u64,
    pub request_digest: Digest,
}

impl RampReadRequest {
    pub(crate) fn new(
        scope: &RampSpendScope,
        operation: ReadOperation,
        cursor: Option<String>,
        high_water_mark: Option<String>,
        attempt: u8,
        backoff_seconds: u64,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        validate_page_size(MAX_PAGE_SIZE)?;
        if attempt == 0 {
            return Err(crate::RampSpendOutcomeError::InvalidAttempt);
        }
        if let Some(cursor) = &cursor {
            validate_cursor(cursor)?;
        }
        if let Some(high_water_mark) = &high_water_mark {
            validate_high_water(high_water_mark)?;
        }
        let endpoint = operation.endpoint();
        let mut request = Self {
            operation,
            endpoint,
            scope_digest: scope.digest(),
            business_id: scope.business_id.clone(),
            entity_id: scope.entity_id.clone(),
            spend_program_id: scope.spend_program_id.clone(),
            card_id: scope.card_id.clone(),
            vendor_id: scope.vendor_id.clone(),
            transaction_id: scope.transaction_id.clone(),
            audit_event_id: scope.audit_event_id.clone(),
            date_window: scope.date_window.clone(),
            page_size: MAX_PAGE_SIZE,
            cursor,
            high_water_mark,
            attempt,
            backoff_seconds,
            request_digest: String::new(),
        };
        request.request_digest = canonical_digest(&RequestFingerprint::from(&request));
        Ok(request)
    }

    #[must_use]
    pub fn query_parameters(&self) -> Vec<(String, String)> {
        let mut query = vec![
            ("from".to_owned(), self.date_window.from.to_rfc3339()),
            ("to".to_owned(), self.date_window.to.to_rfc3339()),
            ("page_size".to_owned(), self.page_size.to_string()),
        ];
        if let Some(cursor) = &self.cursor {
            query.push(("page.next".to_owned(), cursor.clone()));
        }
        if let Some(high_water_mark) = &self.high_water_mark {
            query.push(("high_water_mark".to_owned(), high_water_mark.clone()));
        }
        if let Some(entity_id) = &self.entity_id {
            query.push(("entity_id".to_owned(), entity_id.raw().to_owned()));
        }
        if let Some(spend_program_id) = &self.spend_program_id {
            query.push((
                "spend_program_id".to_owned(),
                spend_program_id.raw().to_owned(),
            ));
        }
        if let Some(card_id) = &self.card_id {
            query.push(("card_id".to_owned(), card_id.raw().to_owned()));
        }
        if let Some(vendor_id) = &self.vendor_id {
            query.push(("vendor_id".to_owned(), vendor_id.raw().to_owned()));
        }
        if let Some(transaction_id) = &self.transaction_id {
            query.push(("transaction_id".to_owned(), transaction_id.raw().to_owned()));
        }
        if let Some(audit_event_id) = &self.audit_event_id {
            query.push(("audit_event_id".to_owned(), audit_event_id.raw().to_owned()));
        }
        query
    }

    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        if self.endpoint != self.operation.endpoint()
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.attempt == 0
        {
            return Err(crate::RampSpendOutcomeError::InvalidResponse);
        }
        let expected = canonical_digest(&RequestFingerprint::from(self));
        if expected != self.request_digest {
            return Err(crate::RampSpendOutcomeError::RequestTampered);
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestFingerprint<'a> {
    operation: ReadOperationFingerprint,
    endpoint: &'static str,
    scope_digest: &'a str,
    business_id_digest: Digest,
    entity_id_digest: Option<Digest>,
    spend_program_id_digest: Option<Digest>,
    card_id_digest: Option<Digest>,
    vendor_id_digest: Option<Digest>,
    transaction_id_digest: Option<Digest>,
    audit_event_id_digest: Option<Digest>,
    date_window: &'a DateWindow,
    page_size: usize,
    cursor: &'a Option<String>,
    high_water_mark: &'a Option<String>,
    attempt: u8,
    backoff_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ReadOperationFingerprint {
    Transactions,
    Merchants,
    AuditLogs,
}

impl<'a> From<&'a RampReadRequest> for RequestFingerprint<'a> {
    fn from(request: &'a RampReadRequest) -> Self {
        Self {
            operation: match request.operation {
                ReadOperation::ReadTransactions => ReadOperationFingerprint::Transactions,
                ReadOperation::ReadMerchants => ReadOperationFingerprint::Merchants,
                ReadOperation::ReadAuditLogs => ReadOperationFingerprint::AuditLogs,
            },
            endpoint: request.endpoint.path(),
            scope_digest: &request.scope_digest,
            business_id_digest: request.business_id.digest(),
            entity_id_digest: request.entity_id.as_ref().map(BoundIdentifier::digest),
            spend_program_id_digest: request
                .spend_program_id
                .as_ref()
                .map(BoundIdentifier::digest),
            card_id_digest: request.card_id.as_ref().map(BoundIdentifier::digest),
            vendor_id_digest: request.vendor_id.as_ref().map(BoundIdentifier::digest),
            transaction_id_digest: request.transaction_id.as_ref().map(BoundIdentifier::digest),
            audit_event_id_digest: request.audit_event_id.as_ref().map(BoundIdentifier::digest),
            date_window: &request.date_window,
            page_size: request.page_size,
            cursor: &request.cursor,
            high_water_mark: &request.high_water_mark,
            attempt: request.attempt,
            backoff_seconds: request.backoff_seconds,
        }
    }
}

#[derive(Clone)]
pub struct RampTransactionInputSpec {
    pub id: String,
    pub state: String,
    pub amount_minor: Option<i64>,
    pub currency_code: Option<String>,
    pub entity_id: Option<String>,
    pub spend_program_id: Option<String>,
    pub card_id: Option<String>,
    pub merchant_id: Option<String>,
    pub merchant_name: Option<String>,
    pub category_id: Option<String>,
    pub category_name: Option<String>,
    pub original_transaction_id: Option<String>,
    pub transaction_time: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub settlement_date: Option<DateTime<Utc>>,
    pub refund_state: Option<RefundState>,
}

impl fmt::Debug for RampTransactionInputSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RampTransactionInputSpec")
            .field("id", &"<redacted>")
            .field("state", &self.state)
            .field("amount_minor", &self.amount_minor.map(|_| "<redacted>"))
            .field("currency_code", &self.currency_code)
            .field(
                "merchant_id",
                &self.merchant_id.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "merchant_name",
                &self.merchant_name.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "category_id",
                &self.category_id.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "category_name",
                &self.category_name.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct RampTransactionInput {
    id: String,
    state: String,
    amount_minor: Option<i64>,
    currency_code: Option<String>,
    entity_id: Option<String>,
    spend_program_id: Option<String>,
    card_id: Option<String>,
    merchant_id: Option<String>,
    merchant_name: Option<String>,
    category_id: Option<String>,
    category_name: Option<String>,
    original_transaction_id: Option<String>,
    transaction_time: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
    settlement_date: Option<DateTime<Utc>>,
    refund_state: Option<RefundState>,
}

impl fmt::Debug for RampTransactionInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RampTransactionInput")
            .field("id", &"<redacted>")
            .field("state", &self.state)
            .field("amount_minor", &self.amount_minor.map(|_| "<redacted>"))
            .field("currency_code", &self.currency_code)
            .field(
                "merchant_id",
                &self.merchant_id.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "merchant_name",
                &self.merchant_name.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

impl RampTransactionInput {
    pub fn from_spec(spec: RampTransactionInputSpec) -> Result<Self, crate::RampSpendOutcomeError> {
        validate_identifier(&spec.id, "transaction id")?;
        validate_bounded_text(&spec.state, "transaction state", MAX_EVENT_TYPE_BYTES)?;
        validate_optional_identifier(spec.entity_id.as_deref(), "entity id")?;
        validate_optional_identifier(spec.spend_program_id.as_deref(), "spend program id")?;
        validate_optional_identifier(spec.card_id.as_deref(), "card id")?;
        validate_optional_identifier(spec.merchant_id.as_deref(), "merchant id")?;
        validate_optional_identifier(spec.category_id.as_deref(), "category id")?;
        validate_optional_identifier(
            spec.original_transaction_id.as_deref(),
            "original transaction id",
        )?;
        validate_optional_text(
            spec.merchant_name.as_deref(),
            "merchant name",
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_optional_text(
            spec.category_name.as_deref(),
            "category name",
            MAX_IDENTIFIER_BYTES,
        )?;
        if spec.transaction_time.is_none() {
            return Err(crate::RampSpendOutcomeError::InvalidResponse);
        }
        Ok(Self {
            id: spec.id,
            state: spec.state,
            amount_minor: spec.amount_minor,
            currency_code: spec.currency_code,
            entity_id: spec.entity_id,
            spend_program_id: spec.spend_program_id,
            card_id: spec.card_id,
            merchant_id: spec.merchant_id,
            merchant_name: spec.merchant_name,
            category_id: spec.category_id,
            category_name: spec.category_name,
            original_transaction_id: spec.original_transaction_id,
            transaction_time: spec.transaction_time,
            updated_at: spec.updated_at,
            settlement_date: spec.settlement_date,
            refund_state: spec.refund_state,
        })
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn state(&self) -> &str {
        &self.state
    }
    pub(crate) fn amount_minor(&self) -> Option<i64> {
        self.amount_minor
    }
    pub(crate) fn currency_code(&self) -> Option<&str> {
        self.currency_code.as_deref()
    }
    pub(crate) fn entity_id(&self) -> Option<&str> {
        self.entity_id.as_deref()
    }
    pub(crate) fn spend_program_id(&self) -> Option<&str> {
        self.spend_program_id.as_deref()
    }
    pub(crate) fn card_id(&self) -> Option<&str> {
        self.card_id.as_deref()
    }
    pub(crate) fn merchant_id(&self) -> Option<&str> {
        self.merchant_id.as_deref()
    }
    pub(crate) fn merchant_name(&self) -> Option<&str> {
        self.merchant_name.as_deref()
    }
    pub(crate) fn category_id(&self) -> Option<&str> {
        self.category_id.as_deref()
    }
    pub(crate) fn category_name(&self) -> Option<&str> {
        self.category_name.as_deref()
    }
    pub(crate) fn original_transaction_id(&self) -> Option<&str> {
        self.original_transaction_id.as_deref()
    }
    pub(crate) fn transaction_time(&self) -> DateTime<Utc> {
        self.transaction_time.expect("validated transaction time")
    }
    pub(crate) fn updated_at(&self) -> Option<DateTime<Utc>> {
        self.updated_at
    }
    pub(crate) fn settlement_date(&self) -> Option<DateTime<Utc>> {
        self.settlement_date
    }
    pub(crate) fn refund_state(&self) -> Option<RefundState> {
        self.refund_state
    }

    fn fingerprint_digest(&self) -> Digest {
        canonical_digest(&TransactionInputFingerprint {
            id_digest: sha256_digest(self.id.as_bytes()),
            state: &self.state,
            amount_minor: self.amount_minor,
            currency_code: &self.currency_code,
            entity_id_digest: self
                .entity_id
                .as_deref()
                .map(|value| sha256_digest(value.as_bytes())),
            spend_program_id_digest: self
                .spend_program_id
                .as_deref()
                .map(|value| sha256_digest(value.as_bytes())),
            card_id_digest: self
                .card_id
                .as_deref()
                .map(|value| sha256_digest(value.as_bytes())),
            merchant_id_digest: self
                .merchant_id
                .as_deref()
                .map(|value| sha256_digest(value.as_bytes())),
            merchant_name_digest: self
                .merchant_name
                .as_deref()
                .map(|value| sha256_digest(value.as_bytes())),
            category_id_digest: self
                .category_id
                .as_deref()
                .map(|value| sha256_digest(value.as_bytes())),
            category_name_digest: self
                .category_name
                .as_deref()
                .map(|value| sha256_digest(value.as_bytes())),
            original_transaction_id_digest: self
                .original_transaction_id
                .as_deref()
                .map(|value| sha256_digest(value.as_bytes())),
            transaction_time: self.transaction_time,
            updated_at: self.updated_at,
            settlement_date: self.settlement_date,
            refund_state: self.refund_state,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransactionInputFingerprint<'a> {
    id_digest: Digest,
    state: &'a str,
    amount_minor: Option<i64>,
    currency_code: &'a Option<String>,
    entity_id_digest: Option<Digest>,
    spend_program_id_digest: Option<Digest>,
    card_id_digest: Option<Digest>,
    merchant_id_digest: Option<Digest>,
    merchant_name_digest: Option<Digest>,
    category_id_digest: Option<Digest>,
    category_name_digest: Option<Digest>,
    original_transaction_id_digest: Option<Digest>,
    transaction_time: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
    settlement_date: Option<DateTime<Utc>>,
    refund_state: Option<RefundState>,
}

#[derive(Clone)]
pub struct RampMerchantInputSpec {
    pub id: String,
    pub merchant_name: String,
    pub category_name: Option<String>,
}

impl fmt::Debug for RampMerchantInputSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RampMerchantInputSpec")
            .field("id", &"<redacted>")
            .field("merchant_name", &"<redacted>")
            .field(
                "category_name",
                &self.category_name.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Clone)]
pub struct RampMerchantInput {
    id: String,
    merchant_name: String,
    category_name: Option<String>,
}

impl fmt::Debug for RampMerchantInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RampMerchantInput")
            .field("id", &"<redacted>")
            .field("merchant_name", &"<redacted>")
            .field(
                "category_name",
                &self.category_name.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl RampMerchantInput {
    pub fn from_spec(spec: RampMerchantInputSpec) -> Result<Self, crate::RampSpendOutcomeError> {
        validate_identifier(&spec.id, "merchant id")?;
        validate_bounded_text(&spec.merchant_name, "merchant name", MAX_IDENTIFIER_BYTES)?;
        validate_optional_text(
            spec.category_name.as_deref(),
            "merchant category",
            MAX_IDENTIFIER_BYTES,
        )?;
        Ok(Self {
            id: spec.id,
            merchant_name: spec.merchant_name,
            category_name: spec.category_name,
        })
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn merchant_name(&self) -> &str {
        &self.merchant_name
    }
    pub(crate) fn category_name(&self) -> Option<&str> {
        self.category_name.as_deref()
    }

    fn fingerprint_digest(&self) -> Digest {
        canonical_digest(&(
            sha256_digest(self.id.as_bytes()),
            sha256_digest(self.merchant_name.as_bytes()),
            self.category_name
                .as_deref()
                .map(|value| sha256_digest(value.as_bytes())),
        ))
    }
}

#[derive(Clone)]
pub struct RampAuditEventInputSpec {
    pub id: String,
    pub event_type: String,
    pub actor_type: String,
    pub resource_name: String,
    pub resource_id: Option<String>,
    pub event_time: DateTime<Utc>,
}

impl fmt::Debug for RampAuditEventInputSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RampAuditEventInputSpec")
            .field("id", &"<redacted>")
            .field("event_type", &self.event_type)
            .field("actor_type", &self.actor_type)
            .field("resource_name", &self.resource_name)
            .field(
                "resource_id",
                &self.resource_id.as_ref().map(|_| "<redacted>"),
            )
            .field("event_time", &self.event_time)
            .finish()
    }
}

#[derive(Clone)]
pub struct RampAuditEventInput {
    id: String,
    event_type: String,
    actor_type: String,
    resource_name: String,
    resource_id: Option<String>,
    event_time: DateTime<Utc>,
}

impl fmt::Debug for RampAuditEventInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RampAuditEventInput")
            .field("id", &"<redacted>")
            .field("event_type", &self.event_type)
            .field("actor_type", &self.actor_type)
            .field("resource_name", &self.resource_name)
            .field(
                "resource_id",
                &self.resource_id.as_ref().map(|_| "<redacted>"),
            )
            .field("event_time", &self.event_time)
            .finish()
    }
}

impl RampAuditEventInput {
    pub fn from_spec(spec: RampAuditEventInputSpec) -> Result<Self, crate::RampSpendOutcomeError> {
        validate_identifier(&spec.id, "audit event id")?;
        validate_event_type(&spec.event_type)?;
        validate_bounded_text(&spec.actor_type, "actor type", MAX_EVENT_TYPE_BYTES)?;
        validate_bounded_text(&spec.resource_name, "resource name", MAX_EVENT_TYPE_BYTES)?;
        validate_optional_identifier(spec.resource_id.as_deref(), "audit resource id")?;
        Ok(Self {
            id: spec.id,
            event_type: spec.event_type,
            actor_type: spec.actor_type,
            resource_name: spec.resource_name,
            resource_id: spec.resource_id,
            event_time: spec.event_time,
        })
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn event_type(&self) -> &str {
        &self.event_type
    }
    pub(crate) fn actor_type(&self) -> &str {
        &self.actor_type
    }
    pub(crate) fn resource_name(&self) -> &str {
        &self.resource_name
    }
    pub(crate) fn resource_id(&self) -> Option<&str> {
        self.resource_id.as_deref()
    }
    pub(crate) fn event_time(&self) -> DateTime<Utc> {
        self.event_time
    }

    fn fingerprint_digest(&self) -> Digest {
        canonical_digest(&(
            sha256_digest(self.id.as_bytes()),
            sha256_digest(self.event_type.as_bytes()),
            sha256_digest(self.actor_type.as_bytes()),
            sha256_digest(self.resource_name.as_bytes()),
            self.resource_id
                .as_deref()
                .map(|value| sha256_digest(value.as_bytes())),
            self.event_time,
        ))
    }
}

#[derive(Clone)]
pub struct RampApiPage {
    pub endpoint: RampEndpoint,
    pub business_id: BoundIdentifier,
    pub transactions: Vec<RampTransactionInput>,
    pub merchants: Vec<RampMerchantInput>,
    pub audit_events: Vec<RampAuditEventInput>,
    pub next_cursor: Option<String>,
    pub high_water_mark: String,
    pub response_digest: Digest,
}

impl fmt::Debug for RampApiPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RampApiPage")
            .field("endpoint", &self.endpoint)
            .field("business_id", &self.business_id)
            .field("transaction_count", &self.transactions.len())
            .field("merchant_count", &self.merchants.len())
            .field("audit_event_count", &self.audit_events.len())
            .field("next_cursor", &self.next_cursor)
            .field("high_water_mark", &"<redacted>")
            .field("response_digest", &self.response_digest)
            .finish()
    }
}

impl RampApiPage {
    pub fn new(
        endpoint: RampEndpoint,
        business_id: impl Into<String>,
        transactions: Vec<RampTransactionInput>,
        merchants: Vec<RampMerchantInput>,
        audit_events: Vec<RampAuditEventInput>,
        next_cursor: Option<String>,
        high_water_mark: impl Into<String>,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        let business_id = BoundIdentifier::new(business_id, "business id")?;
        if transactions.len() > MAX_PAGE_SIZE
            || merchants.len() > MAX_PAGE_SIZE
            || audit_events.len() > MAX_PAGE_SIZE
        {
            return Err(crate::RampSpendOutcomeError::BoundExceeded {
                field: "page records",
                maximum: MAX_PAGE_SIZE,
            });
        }
        if let Some(next_cursor) = &next_cursor {
            validate_cursor(next_cursor)?;
        }
        let high_water_mark = high_water_mark.into();
        validate_high_water(&high_water_mark)?;
        let mut page = Self {
            endpoint,
            business_id,
            transactions,
            merchants,
            audit_events,
            next_cursor,
            high_water_mark,
            response_digest: String::new(),
        };
        page.response_digest = page.computed_digest();
        page.validate()?;
        Ok(page)
    }

    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        if self.transactions.len() > MAX_PAGE_SIZE
            || self.merchants.len() > MAX_PAGE_SIZE
            || self.audit_events.len() > MAX_PAGE_SIZE
        {
            return Err(crate::RampSpendOutcomeError::BoundExceeded {
                field: "page records",
                maximum: MAX_PAGE_SIZE,
            });
        }
        validate_high_water(&self.high_water_mark)?;
        if let Some(cursor) = &self.next_cursor {
            validate_cursor(cursor)?;
        }
        if self.response_digest != self.computed_digest() {
            return Err(crate::RampSpendOutcomeError::ResponseTampered);
        }
        Ok(())
    }

    #[must_use]
    pub fn tampered(mut self) -> Self {
        self.response_digest = "0".repeat(64);
        self
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&PageFingerprint {
            endpoint: self.endpoint.path(),
            business_id_digest: self.business_id.digest(),
            transactions: self
                .transactions
                .iter()
                .map(RampTransactionInput::fingerprint_digest)
                .collect(),
            merchants: self
                .merchants
                .iter()
                .map(RampMerchantInput::fingerprint_digest)
                .collect(),
            audit_events: self
                .audit_events
                .iter()
                .map(RampAuditEventInput::fingerprint_digest)
                .collect(),
            next_cursor: &self.next_cursor,
            high_water_mark: &self.high_water_mark,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PageFingerprint<'a> {
    endpoint: &'static str,
    business_id_digest: Digest,
    transactions: Vec<Digest>,
    merchants: Vec<Digest>,
    audit_events: Vec<Digest>,
    next_cursor: &'a Option<String>,
    high_water_mark: &'a str,
}

pub trait RampTransport: fmt::Debug + Send + Sync {
    fn provenance(&self) -> TransportProvenance;

    fn read(&self, request: &RampReadRequest) -> Result<RampApiPage, RampTransportError>;
}

#[derive(Debug, Default)]
struct TransportBuffer {
    responses: VecDeque<Result<RampApiPage, RampTransportError>>,
    requests: Vec<RampReadRequest>,
}

impl TransportBuffer {
    fn from_pages(pages: Vec<RampApiPage>) -> Self {
        Self {
            responses: pages.into_iter().map(Ok).collect(),
            requests: Vec::new(),
        }
    }

    fn read(&mut self, request: &RampReadRequest) -> Result<RampApiPage, RampTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(RampTransportError::InvalidResponse))
    }
}

macro_rules! deterministic_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone)]
        pub struct $name {
            buffer: Arc<Mutex<TransportBuffer>>,
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("provenance", &$provenance)
                    .field("buffer", &"<bounded>")
                    .finish()
            }
        }

        impl $name {
            pub fn from_pages(pages: Vec<RampApiPage>) -> Self {
                Self {
                    buffer: Arc::new(Mutex::new(TransportBuffer::from_pages(pages))),
                }
            }

            pub fn from_page(page: RampApiPage) -> Self {
                Self::from_pages(vec![page])
            }

            pub fn push_page(&self, page: RampApiPage) -> Result<(), crate::RampSpendOutcomeError> {
                self.buffer
                    .lock()
                    .map_err(|_| crate::RampSpendOutcomeError::TransportPoisoned)
                    .map(|mut buffer| buffer.responses.push_back(Ok(page)))
            }

            pub fn push_error(
                &self,
                error: RampTransportError,
            ) -> Result<(), crate::RampSpendOutcomeError> {
                self.buffer
                    .lock()
                    .map_err(|_| crate::RampSpendOutcomeError::TransportPoisoned)
                    .map(|mut buffer| buffer.responses.push_back(Err(error)))
            }

            #[must_use]
            pub fn requests(&self) -> Vec<RampReadRequest> {
                self.buffer
                    .lock()
                    .map(|buffer| buffer.requests.clone())
                    .unwrap_or_default()
            }
        }

        impl RampTransport for $name {
            fn provenance(&self) -> TransportProvenance {
                $provenance
            }

            fn read(&self, request: &RampReadRequest) -> Result<RampApiPage, RampTransportError> {
                request
                    .validate()
                    .map_err(|_| RampTransportError::InvalidResponse)?;
                self.buffer
                    .lock()
                    .map_err(|_| RampTransportError::ProviderUnknown)?
                    .read(request)
            }
        }
    };
}

deterministic_transport!(RecordingRampTransport, TransportProvenance::Recording);
deterministic_transport!(FixtureRampTransport, TransportProvenance::Fixture);
deterministic_transport!(LoopbackRampTransport, TransportProvenance::Loopback);
deterministic_transport!(
    OfficialRampApiTransport,
    TransportProvenance::OfficialApiParser
);

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvRampTransport;

impl RampTransport for BlockedEnvRampTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read(&self, _request: &RampReadRequest) -> Result<RampApiPage, RampTransportError> {
        Err(RampTransportError::BlockedEnv)
    }
}

/// A transient official Ramp API response supplied by the host or a test
/// harness. Construction parses the response immediately; only the bounded
/// `RampApiPage` is retained by `OfficialRampApiTransport`.
#[derive(Clone)]
pub struct OfficialRampApiResponseSpec {
    endpoint: RampEndpoint,
    business_id: String,
    body: String,
    high_water_mark: String,
}

impl fmt::Debug for OfficialRampApiResponseSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfficialRampApiResponseSpec")
            .field("endpoint", &self.endpoint)
            .field("business_id", &"<redacted>")
            .field("body", &"<redacted>")
            .field("high_water_mark", &"<redacted>")
            .finish()
    }
}

impl OfficialRampApiResponseSpec {
    #[must_use]
    pub fn new(
        endpoint: RampEndpoint,
        business_id: impl Into<String>,
        body: impl Into<String>,
        high_water_mark: impl Into<String>,
    ) -> Self {
        Self {
            endpoint,
            business_id: business_id.into(),
            body: body.into(),
            high_water_mark: high_water_mark.into(),
        }
    }
}

impl OfficialRampApiTransport {
    /// Parse official Ramp response bodies before storing them in the
    /// deterministic transport buffer. This seam has no credential or
    /// network authority and therefore cannot claim native/Connected state.
    pub fn from_json_pages(
        specs: Vec<OfficialRampApiResponseSpec>,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        let pages = specs
            .into_iter()
            .map(|spec| {
                parse_official_json_page(
                    spec.endpoint,
                    spec.business_id,
                    &spec.body,
                    spec.high_water_mark,
                )
                .map_err(crate::RampSpendOutcomeError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::from_pages(pages))
    }
}

#[derive(Debug, Deserialize)]
struct PageWire {
    #[serde(default)]
    next: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TransactionsEnvelope {
    #[serde(default)]
    data: Vec<TransactionWire>,
    page: PageWire,
}

#[derive(Debug, Deserialize)]
struct TransactionWire {
    id: Option<String>,
    state: Option<String>,
    amount: Option<i64>,
    currency_code: Option<String>,
    entity_id: Option<String>,
    spend_program_id: Option<String>,
    card_id: Option<String>,
    merchant_id: Option<String>,
    merchant_name: Option<String>,
    sk_category_id: Option<i64>,
    sk_category_name: Option<String>,
    original_transaction_id: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    settlement_date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MerchantsEnvelope {
    #[serde(default)]
    data: Vec<MerchantWire>,
    page: PageWire,
}

#[derive(Debug, Deserialize)]
struct MerchantWire {
    id: String,
    merchant_name: String,
    sk_category_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuditEnvelope {
    #[serde(default)]
    data: Vec<AuditWire>,
    page: PageWire,
}

#[derive(Debug, Deserialize)]
struct AuditWire {
    id: String,
    event_type: String,
    actor_type: String,
    event_time: String,
    #[serde(default)]
    event_details: Option<AuditDetailsWire>,
}

#[derive(Debug, Deserialize)]
struct AuditDetailsWire {
    #[serde(default)]
    references: Vec<AuditReferenceWire>,
}

#[derive(Debug, Deserialize)]
struct AuditReferenceWire {
    resource_name: String,
}

/// Parse the allowlisted part of an official Ramp Developer API response.
/// Unknown provider fields are ignored and never retained; prohibited fields
/// such as card-holder objects, receipts, bank details, and memos have no
/// corresponding Rust field.
pub fn parse_official_json_page(
    endpoint: RampEndpoint,
    business_id: impl Into<String>,
    body: &str,
    high_water_mark: impl Into<String>,
) -> Result<RampApiPage, RampTransportError> {
    (match endpoint {
        RampEndpoint::Transactions => {
            let envelope: TransactionsEnvelope =
                serde_json::from_str(body).map_err(|_| RampTransportError::InvalidResponse)?;
            let transactions = envelope
                .data
                .into_iter()
                .map(|item| {
                    let category_id = item.sk_category_id.map(|value| value.to_string());
                    RampTransactionInput::from_spec(RampTransactionInputSpec {
                        id: item.id.ok_or(RampTransportError::InvalidResponse)?,
                        state: item.state.ok_or(RampTransportError::InvalidResponse)?,
                        amount_minor: item.amount,
                        currency_code: item.currency_code,
                        entity_id: item.entity_id,
                        spend_program_id: item.spend_program_id,
                        card_id: item.card_id,
                        merchant_id: item.merchant_id,
                        merchant_name: item.merchant_name,
                        category_id,
                        category_name: item.sk_category_name,
                        original_transaction_id: item.original_transaction_id,
                        transaction_time: Some(parse_timestamp(item.created_at.as_deref())?),
                        updated_at: parse_optional_timestamp(item.updated_at.as_deref())?,
                        settlement_date: parse_optional_timestamp(item.settlement_date.as_deref())?,
                        refund_state: None,
                    })
                    .map_err(|_| RampTransportError::InvalidResponse)
                })
                .collect::<Result<Vec<_>, _>>()?;
            RampApiPage::new(
                endpoint,
                business_id,
                transactions,
                Vec::new(),
                Vec::new(),
                envelope.page.next,
                high_water_mark,
            )
        }
        RampEndpoint::Merchants => {
            let envelope: MerchantsEnvelope =
                serde_json::from_str(body).map_err(|_| RampTransportError::InvalidResponse)?;
            let merchants = envelope
                .data
                .into_iter()
                .map(|item| {
                    RampMerchantInput::from_spec(RampMerchantInputSpec {
                        id: item.id,
                        merchant_name: item.merchant_name,
                        category_name: item.sk_category_name,
                    })
                    .map_err(|_| RampTransportError::InvalidResponse)
                })
                .collect::<Result<Vec<_>, _>>()?;
            RampApiPage::new(
                endpoint,
                business_id,
                Vec::new(),
                merchants,
                Vec::new(),
                envelope.page.next,
                high_water_mark,
            )
        }
        RampEndpoint::AuditLogs => {
            let envelope: AuditEnvelope =
                serde_json::from_str(body).map_err(|_| RampTransportError::InvalidResponse)?;
            let events = envelope
                .data
                .into_iter()
                .map(|item| {
                    let resource_name = item
                        .event_details
                        .and_then(|details| details.references.into_iter().next())
                        .map_or_else(
                            || "provider_unknown".to_owned(),
                            |reference| reference.resource_name,
                        );
                    RampAuditEventInput::from_spec(RampAuditEventInputSpec {
                        id: item.id,
                        event_type: item.event_type,
                        actor_type: item.actor_type,
                        resource_name,
                        resource_id: None,
                        event_time: parse_timestamp(Some(&item.event_time))?,
                    })
                    .map_err(|_| RampTransportError::InvalidResponse)
                })
                .collect::<Result<Vec<_>, _>>()?;
            RampApiPage::new(
                endpoint,
                business_id,
                Vec::new(),
                Vec::new(),
                events,
                envelope.page.next,
                high_water_mark,
            )
        }
    })
    .map_err(|_| RampTransportError::InvalidResponse)
}

fn parse_timestamp(value: Option<&str>) -> Result<DateTime<Utc>, RampTransportError> {
    value
        .ok_or(RampTransportError::InvalidResponse)
        .and_then(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(|timestamp| timestamp.with_timezone(&Utc))
                .map_err(|_| RampTransportError::InvalidResponse)
        })
}

fn parse_optional_timestamp(
    value: Option<&str>,
) -> Result<Option<DateTime<Utc>>, RampTransportError> {
    value.map(|value| parse_timestamp(Some(value))).transpose()
}

fn validate_optional_identifier(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), crate::RampSpendOutcomeError> {
    value.map_or(Ok(()), |value| validate_identifier(value, field))
}

fn validate_optional_text(
    value: Option<&str>,
    field: &'static str,
    maximum: usize,
) -> Result<(), crate::RampSpendOutcomeError> {
    value.map_or(Ok(()), |value| validate_bounded_text(value, field, maximum))
}

#[allow(dead_code)]
fn _bounded_constants_are_used() -> usize {
    MAX_CURSOR_BYTES
        + MAX_IDENTIFIER_BYTES
        + MAX_EVENT_TYPE_BYTES
        + MAX_PAGE_SIZE
        + MAX_PAGES
        + MAX_TRANSACTIONS
        + MAX_MERCHANTS
        + MAX_AUDIT_EVENTS
}
