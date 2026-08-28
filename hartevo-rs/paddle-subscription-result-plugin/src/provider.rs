use std::{fmt, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    PROVIDER_ID, PROVIDER_VERSION,
    error::{PaddleBillingProviderError, PaddleSubscriptionResultError, Result},
    model::{
        AccountId, AmountSummary, ApiBinding, BillingPeriod, CollectionMode, CursorKind, Digest,
        MAX_EVENTS_PER_PAGE, MAX_RESPONSE_BYTES, MAX_TRANSACTIONS_PER_PAGE, PaddleBillingScope,
        PaddleBillingScopeIdentity, PaddleCursor, PaddleEventListRequest, PaddleEventSummary,
        PaddlePaymentAttemptSummary, PaddleSubscriptionReadRequest, PaddleSubscriptionSummary,
        PaddleTransactionListRequest, PaddleTransactionReadRequest, PaddleTransactionSummary,
        PaymentAttemptStatus, ProviderProvenance, ScheduledChange, ScheduledChangeAction,
        SubscriptionId, SubscriptionStatus, TransactionId, TransactionStatus,
    },
    transport::{
        BlockedEnvPaddleBillingTransport, PaddleGetRequest, PaddleHttpResponse, PaddleTransport,
        PaddleTransportError,
    },
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderDefinitionIdentity {
    id: String,
    version: String,
    api_version: String,
    operations: Vec<String>,
    permissions: Vec<String>,
    native_status: crate::NativeStatus,
    connected: bool,
    native: bool,
    first_party: bool,
    external_writes: bool,
}

/// Provider metadata is a contract identity, not an account registry entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaddleBillingProviderDefinition {
    id: String,
    version: String,
    api_version: String,
    operations: Vec<String>,
    permissions: Vec<String>,
    native_status: crate::NativeStatus,
    connected: bool,
    native: bool,
    first_party: bool,
    external_writes: bool,
    digest: Digest,
}

impl PaddleBillingProviderDefinition {
    #[must_use]
    pub fn layer1() -> Self {
        let identity = ProviderDefinitionIdentity {
            id: String::from(PROVIDER_ID),
            version: String::from(PROVIDER_VERSION),
            api_version: String::from(crate::PADDLE_API_VERSION),
            operations: vec![
                String::from("GET /subscriptions/{subscription_id}"),
                String::from("GET /transactions/{transaction_id}"),
                String::from("GET /transactions?subscription_id={subscription_id}"),
                String::from("GET /events?event_type=subscription.*|transaction.*"),
            ],
            permissions: vec![
                String::from("subscription.read"),
                String::from("transaction.read"),
                String::from("notification.read"),
            ],
            native_status: crate::NativeStatus::BlockedEnv,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
        };
        Self {
            id: identity.id.clone(),
            version: identity.version.clone(),
            api_version: identity.api_version.clone(),
            operations: identity.operations.clone(),
            permissions: identity.permissions.clone(),
            native_status: identity.native_status,
            connected: identity.connected,
            native: identity.native,
            first_party: identity.first_party,
            external_writes: identity.external_writes,
            digest: Digest::from_serializable(&identity),
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    #[must_use]
    pub fn operations(&self) -> &[String] {
        &self.operations
    }

    #[must_use]
    pub fn permissions(&self) -> &[String] {
        &self.permissions
    }

    #[must_use]
    pub const fn native_status(&self) -> crate::NativeStatus {
        self.native_status
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        self.connected
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        self.native
    }

    #[must_use]
    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    #[must_use]
    pub const fn external_writes(&self) -> bool {
        self.external_writes
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<()> {
        if self != &Self::layer1() {
            Err(PaddleSubscriptionResultError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct PaddleSubscriptionResponse {
    pub subscription: PaddleSubscriptionSummary,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub observed_at: u64,
    pub snapshot_revision: crate::Revision,
}

#[derive(Clone, Debug)]
pub struct PaddleTransactionResponse {
    pub transaction: PaddleTransactionSummary,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub observed_at: u64,
    pub snapshot_revision: crate::Revision,
}

#[derive(Clone, Debug)]
pub struct PaddleTransactionListResponse {
    pub transactions: Vec<PaddleTransactionSummary>,
    pub next_cursor: Option<PaddleCursor>,
    pub has_more: bool,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub observed_at: u64,
    pub snapshot_revision: crate::Revision,
}

#[derive(Clone, Debug)]
pub struct PaddleEventListResponse {
    pub events: Vec<PaddleEventSummary>,
    pub next_cursor: Option<PaddleCursor>,
    pub has_more: bool,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub observed_at: u64,
    pub snapshot_revision: crate::Revision,
}

/// Typed Paddle provider. It owns only a host transport seam and a fixed
/// provider manifest; it does not resolve or store API-key bytes.
#[derive(Clone)]
pub struct PaddleBillingProvider {
    definition: PaddleBillingProviderDefinition,
    transport: Arc<dyn PaddleTransport>,
    provenance: ProviderProvenance,
}

impl fmt::Debug for PaddleBillingProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PaddleBillingProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.provenance)
            .field("transport", &self.transport)
            .finish()
    }
}

impl PaddleBillingProvider {
    pub fn new<T>(transport: T, provenance: ProviderProvenance) -> Result<Self>
    where
        T: PaddleTransport + 'static,
    {
        Self::with_transport(Arc::new(transport), provenance)
    }

    pub fn with_transport(
        transport: Arc<dyn PaddleTransport>,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        let definition = PaddleBillingProviderDefinition::layer1();
        definition.validate()?;
        Ok(Self {
            definition,
            transport,
            provenance,
        })
    }

    pub fn recording<T>(transport: T) -> Result<Self>
    where
        T: PaddleTransport + 'static,
    {
        Self::new(transport, ProviderProvenance::Recording)
    }

    pub fn fixture<T>(transport: T) -> Result<Self>
    where
        T: PaddleTransport + 'static,
    {
        Self::new(transport, ProviderProvenance::Fixture)
    }

    pub fn loopback<T>(transport: T) -> Result<Self>
    where
        T: PaddleTransport + 'static,
    {
        Self::new(transport, ProviderProvenance::Loopback)
    }

    pub fn blocked_env() -> Result<Self> {
        Self::new(
            BlockedEnvPaddleBillingTransport,
            ProviderProvenance::BlockedEnv,
        )
    }

    #[must_use]
    pub fn definition(&self) -> &PaddleBillingProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.digest().clone()
    }

    #[must_use]
    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    #[must_use]
    pub const fn native_status(&self) -> crate::NativeStatus {
        crate::NativeStatus::BlockedEnv
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(&self) -> bool {
        false
    }

    pub fn get_subscription(
        &self,
        scope: &PaddleBillingScope,
        request: &PaddleSubscriptionReadRequest,
    ) -> Result<PaddleSubscriptionResponse> {
        scope.validate()?;
        if request.subscription_id != scope.identity().subscription_id {
            return Err(PaddleSubscriptionResultError::SubscriptionMismatch);
        }
        let http_request = PaddleGetRequest::subscription(request.subscription_id.clone())?;
        let response = self.send_get(&http_request, scope)?;
        let response_bytes = response.body().len();
        let response_digest = Digest::from_bytes(response.body());
        let response = Self::ensure_success(response)?;
        let envelope: RawEnvelope<RawSubscription> = serde_json::from_slice(response.body())
            .map_err(|_| {
                PaddleSubscriptionResultError::Provider(
                    PaddleBillingProviderError::MalformedResponse("subscription JSON"),
                )
            })?;
        let subscription = project_subscription(envelope.data, scope)?;
        Ok(PaddleSubscriptionResponse {
            subscription,
            response_bytes,
            response_digest,
            observed_at: response.observed_at(),
            snapshot_revision: response.snapshot_revision(),
        })
    }

    pub fn get_transaction(
        &self,
        scope: &PaddleBillingScope,
        request: &PaddleTransactionReadRequest,
    ) -> Result<PaddleTransactionResponse> {
        scope.validate()?;
        if let Some(expected) = &scope.identity().transaction_id
            && request.transaction_id != *expected
        {
            return Err(PaddleSubscriptionResultError::TransactionMismatch);
        }
        let http_request = PaddleGetRequest::transaction(request.transaction_id.clone())?;
        let response = self.send_get(&http_request, scope)?;
        let response_bytes = response.body().len();
        let response_digest = Digest::from_bytes(response.body());
        let response = Self::ensure_success(response)?;
        let envelope: RawEnvelope<RawTransaction> = serde_json::from_slice(response.body())
            .map_err(|_| {
                PaddleSubscriptionResultError::Provider(
                    PaddleBillingProviderError::MalformedResponse("transaction JSON"),
                )
            })?;
        let transaction = project_transaction(envelope.data, scope)?;
        if transaction.transaction_id != request.transaction_id {
            return Err(PaddleSubscriptionResultError::Provider(
                PaddleBillingProviderError::ResponseTampered,
            ));
        }
        Ok(PaddleTransactionResponse {
            transaction,
            response_bytes,
            response_digest,
            observed_at: response.observed_at(),
            snapshot_revision: response.snapshot_revision(),
        })
    }

    pub fn list_transactions(
        &self,
        scope: &PaddleBillingScope,
        request: &PaddleTransactionListRequest,
    ) -> Result<PaddleTransactionListResponse> {
        scope.validate()?;
        if request.subscription_id != scope.identity().subscription_id {
            return Err(PaddleSubscriptionResultError::SubscriptionMismatch);
        }
        if let Some(cursor) = &request.cursor {
            cursor.validate_for(
                &scope.scope_digest(),
                CursorKind::Transactions,
                request.minimum_observed_at,
            )?;
        }
        let http_request = PaddleGetRequest::transactions(
            request.subscription_id.clone(),
            request.limit,
            request.cursor.as_ref(),
        )?;
        let response = self.send_get(&http_request, scope)?;
        let response_bytes = response.body().len();
        let response_digest = Digest::from_bytes(response.body());
        let response = Self::ensure_success(response)?;
        let envelope: RawList<RawTransaction> =
            serde_json::from_slice(response.body()).map_err(|_| {
                PaddleSubscriptionResultError::Provider(
                    PaddleBillingProviderError::MalformedResponse("transaction list JSON"),
                )
            })?;
        if envelope.data.len() > MAX_TRANSACTIONS_PER_PAGE {
            return Err(PaddleSubscriptionResultError::Provider(
                PaddleBillingProviderError::MalformedResponse("transaction page bound"),
            ));
        }
        let (has_more, after) = page_state(&envelope)?;
        let mut transactions = Vec::with_capacity(envelope.data.len());
        for raw in envelope.data {
            transactions.push(project_transaction(raw, scope)?);
        }
        let next_cursor = if has_more {
            Some(new_cursor(
                after.ok_or(PaddleSubscriptionResultError::Provider(
                    PaddleBillingProviderError::PartialResponse,
                ))?,
                CursorKind::Transactions,
                scope,
                &response_digest,
                response.observed_at(),
            )?)
        } else {
            None
        };
        Ok(PaddleTransactionListResponse {
            transactions,
            next_cursor,
            has_more,
            response_bytes,
            response_digest,
            observed_at: response.observed_at(),
            snapshot_revision: response.snapshot_revision(),
        })
    }

    pub fn list_events(
        &self,
        scope: &PaddleBillingScope,
        request: &PaddleEventListRequest,
    ) -> Result<PaddleEventListResponse> {
        scope.validate()?;
        if let Some(cursor) = &request.cursor {
            cursor.validate_for(
                &scope.scope_digest(),
                CursorKind::Events,
                request.minimum_observed_at,
            )?;
        }
        let http_request = PaddleGetRequest::events(request.limit, request.cursor.as_ref())?;
        let response = self.send_get(&http_request, scope)?;
        let response_bytes = response.body().len();
        let response_digest = Digest::from_bytes(response.body());
        let response = Self::ensure_success(response)?;
        let envelope: RawList<RawEvent> =
            serde_json::from_slice(response.body()).map_err(|_| {
                PaddleSubscriptionResultError::Provider(
                    PaddleBillingProviderError::MalformedResponse("event list JSON"),
                )
            })?;
        if envelope.data.len() > MAX_EVENTS_PER_PAGE {
            return Err(PaddleSubscriptionResultError::Provider(
                PaddleBillingProviderError::MalformedResponse("event page bound"),
            ));
        }
        let (has_more, after) = page_state(&envelope)?;
        let mut events = Vec::with_capacity(envelope.data.len());
        for raw in envelope.data {
            events.push(project_event(raw, scope)?);
        }
        let next_cursor = if has_more {
            Some(new_cursor(
                after.ok_or(PaddleSubscriptionResultError::Provider(
                    PaddleBillingProviderError::PartialResponse,
                ))?,
                CursorKind::Events,
                scope,
                &response_digest,
                response.observed_at(),
            )?)
        } else {
            None
        };
        Ok(PaddleEventListResponse {
            events,
            next_cursor,
            has_more,
            response_bytes,
            response_digest,
            observed_at: response.observed_at(),
            snapshot_revision: response.snapshot_revision(),
        })
    }

    fn send_get(
        &self,
        request: &PaddleGetRequest,
        scope: &PaddleBillingScope,
    ) -> Result<PaddleHttpResponse> {
        let allowed = request.path() == "/events"
            || request.path() == "/transactions"
            || request.path().starts_with("/transactions/")
            || request.path().starts_with("/subscriptions/");
        if request.method() != crate::PaddleHttpMethod::Get || !allowed {
            return Err(PaddleSubscriptionResultError::MutationForbidden(
                "non-GET or non-Billing request",
            ));
        }
        self.transport
            .get(request, scope.secret_reference())
            .map_err(map_transport_error)
    }

    fn ensure_success(response: PaddleHttpResponse) -> Result<PaddleHttpResponse> {
        if response.body().len() > MAX_RESPONSE_BYTES {
            return Err(PaddleSubscriptionResultError::ResponseTooLarge {
                actual: response.body().len(),
                maximum: MAX_RESPONSE_BYTES,
            });
        }
        match response.status() {
            200 => Ok(response),
            401 => Err(PaddleSubscriptionResultError::Provider(
                PaddleBillingProviderError::Unauthorized,
            )),
            403 => Err(PaddleSubscriptionResultError::Provider(
                PaddleBillingProviderError::Forbidden,
            )),
            404 => Err(PaddleSubscriptionResultError::Provider(
                PaddleBillingProviderError::NotFound,
            )),
            409 => Err(PaddleSubscriptionResultError::Provider(
                PaddleBillingProviderError::Conflict,
            )),
            429 => Err(PaddleSubscriptionResultError::Provider(
                PaddleBillingProviderError::RateLimited {
                    retry_after_seconds: None,
                },
            )),
            408 | 504 => Err(PaddleSubscriptionResultError::Provider(
                PaddleBillingProviderError::Timeout,
            )),
            500..=599 => Err(PaddleSubscriptionResultError::Provider(
                PaddleBillingProviderError::ServerError {
                    status: response.status(),
                },
            )),
            status => Err(PaddleSubscriptionResultError::UnsupportedStatus(status)),
        }
    }
}

fn map_transport_error(error: PaddleTransportError) -> PaddleSubscriptionResultError {
    PaddleSubscriptionResultError::Provider(match error {
        PaddleTransportError::BlockedEnv => PaddleBillingProviderError::BlockedEnv,
        PaddleTransportError::Timeout => PaddleBillingProviderError::Timeout,
        PaddleTransportError::TransportUnavailable => {
            PaddleBillingProviderError::TransportUnavailable
        }
        PaddleTransportError::AccessLoss => PaddleBillingProviderError::AccessLoss,
        PaddleTransportError::Unauthorized => PaddleBillingProviderError::Unauthorized,
        PaddleTransportError::Forbidden => PaddleBillingProviderError::Forbidden,
        PaddleTransportError::Conflict => PaddleBillingProviderError::Conflict,
        PaddleTransportError::RateLimited => PaddleBillingProviderError::RateLimited {
            retry_after_seconds: None,
        },
    })
}

#[derive(Debug, Deserialize)]
struct RawEnvelope<T> {
    data: T,
}

#[derive(Debug, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
struct RawList<T> {
    data: Vec<T>,
    #[serde(default)]
    meta: Option<RawMeta>,
    #[serde(default)]
    has_more: Option<bool>,
    #[serde(default)]
    next: Option<String>,
    #[serde(default)]
    last_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawMeta {
    #[serde(default)]
    pagination: Option<RawPagination>,
}

#[derive(Debug, Deserialize)]
struct RawPagination {
    #[serde(default)]
    next: Option<String>,
    #[serde(default)]
    has_more: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RawSubscription {
    id: String,
    status: String,
    #[serde(default)]
    seller_id: Option<String>,
    #[serde(default)]
    customer_id: Option<String>,
    #[serde(default)]
    customer: Option<Value>,
    #[serde(default)]
    currency_code: String,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    started_at: Option<String>,
    #[serde(default)]
    first_billed_at: Option<String>,
    #[serde(default)]
    next_billed_at: Option<String>,
    #[serde(default)]
    paused_at: Option<String>,
    #[serde(default)]
    canceled_at: Option<String>,
    #[serde(default)]
    current_billing_period: Option<RawBillingPeriod>,
    #[serde(default)]
    scheduled_change: Option<RawScheduledChange>,
    #[serde(default)]
    collection_mode: Option<String>,
    #[serde(default)]
    billing_cycle: Option<Value>,
    #[serde(default)]
    items: Vec<Value>,
    #[serde(default)]
    custom_data: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RawTransaction {
    id: String,
    status: String,
    #[serde(default)]
    seller_id: Option<String>,
    #[serde(default)]
    subscription_id: Option<String>,
    #[serde(default)]
    customer_id: Option<String>,
    #[serde(default)]
    customer: Option<Value>,
    #[serde(default)]
    currency_code: String,
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
    #[serde(default)]
    billed_at: Option<String>,
    #[serde(default)]
    completed_at: Option<String>,
    #[serde(default)]
    billing_period: Option<RawBillingPeriod>,
    #[serde(default)]
    details: Option<RawDetails>,
    #[serde(default)]
    items: Vec<Value>,
    #[serde(default)]
    payments: Vec<RawPaymentAttempt>,
    #[serde(default)]
    custom_data: Option<Value>,
    #[serde(default)]
    error_code: Option<Value>,
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RawDetails {
    #[serde(default)]
    totals: Option<RawTotals>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RawTotals {
    #[serde(default)]
    subtotal: Option<Value>,
    #[serde(default)]
    discount: Option<Value>,
    #[serde(default)]
    tax: Option<Value>,
    #[serde(default)]
    total: Option<Value>,
    #[serde(default)]
    earnings: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RawPaymentAttempt {
    #[serde(default)]
    payment_attempt_id: Option<String>,
    #[serde(default)]
    payment_method_id: Option<String>,
    #[serde(default)]
    amount: Option<Value>,
    status: String,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    error_code: Option<Value>,
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RawBillingPeriod {
    starts_at: String,
    ends_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RawScheduledChange {
    action: String,
    effective_at: String,
    #[serde(default)]
    resume_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawEvent {
    event_id: String,
    event_type: String,
    occurred_at: String,
    data: Value,
}

fn project_subscription(
    raw: RawSubscription,
    scope: &PaddleBillingScope,
) -> Result<PaddleSubscriptionSummary> {
    let source_digest = Digest::from_serializable(&raw);
    let account_id = account_from_optional(raw.seller_id.as_deref(), scope)?;
    let subscription_id = SubscriptionId::new(raw.id)?;
    let customer_digest = customer_digest(raw.customer_id.as_deref(), raw.customer.as_ref());
    let item_digest = (!raw.items.is_empty()).then(|| Digest::from_serializable(&raw.items));
    let metadata_digest = raw.custom_data.as_ref().map(Digest::from_serializable);
    let amount = raw
        .items
        .first()
        .and_then(|item| item.get("price"))
        .and_then(|price| price.get("unit_price"))
        .or_else(|| raw.items.first().and_then(|item| item.get("unit_price")))
        .map(|value| amount_summary(value, &raw.currency_code))
        .transpose()?;
    let current_billing_period = raw
        .current_billing_period
        .map(|period| BillingPeriod::new(period.starts_at, period.ends_at))
        .transpose()?;
    let scheduled_change = raw
        .scheduled_change
        .map(|change| -> Result<ScheduledChange> {
            let result = ScheduledChange {
                action: ScheduledChangeAction::parse(&change.action),
                effective_at: change.effective_at,
                resume_at: change.resume_at,
            };
            result.validate()?;
            Ok(result)
        })
        .transpose()?;
    let summary = PaddleSubscriptionSummary {
        account_id,
        subscription_id,
        customer_digest,
        status: SubscriptionStatus::parse(&raw.status),
        currency_code: raw.currency_code,
        created_at: raw.created_at,
        started_at: raw.started_at,
        first_billed_at: raw.first_billed_at,
        next_billed_at: raw.next_billed_at,
        paused_at: raw.paused_at,
        canceled_at: raw.canceled_at,
        current_billing_period,
        scheduled_change,
        collection_mode: raw.collection_mode.as_deref().map(CollectionMode::parse),
        billing_cycle_digest: raw.billing_cycle.as_ref().map(Digest::from_serializable),
        amount,
        item_count: raw.items.len().try_into().unwrap_or(u32::MAX),
        item_digest,
        metadata_digest,
        source_digest,
    };
    crate::model::validate_subscription_scope(&summary, scope)?;
    Ok(summary)
}

fn project_transaction(
    raw: RawTransaction,
    scope: &PaddleBillingScope,
) -> Result<PaddleTransactionSummary> {
    let source_digest = Digest::from_serializable(&raw);
    let account_id = account_from_optional(raw.seller_id.as_deref(), scope)?;
    let transaction_id = TransactionId::new(raw.id)?;
    let subscription_id = raw.subscription_id.map(SubscriptionId::new).transpose()?;
    let customer_digest = customer_digest(raw.customer_id.as_deref(), raw.customer.as_ref());
    let totals = raw
        .details
        .as_ref()
        .and_then(|details| details.totals.as_ref());
    let currency_code = raw.currency_code.clone();
    let subtotal = totals
        .and_then(|value| value.subtotal.as_ref())
        .map(|value| amount_summary(value, &currency_code))
        .transpose()?;
    let discount = totals
        .and_then(|value| value.discount.as_ref())
        .map(|value| amount_summary(value, &currency_code))
        .transpose()?;
    let tax = totals
        .and_then(|value| value.tax.as_ref())
        .map(|value| amount_summary(value, &currency_code))
        .transpose()?;
    let total = totals
        .and_then(|value| value.total.as_ref())
        .map(|value| amount_summary(value, &currency_code))
        .transpose()?;
    let earnings = totals
        .and_then(|value| value.earnings.as_ref())
        .map(|value| amount_summary(value, &currency_code))
        .transpose()?;
    let billing_period = raw
        .billing_period
        .map(|period| BillingPeriod::new(period.starts_at, period.ends_at))
        .transpose()?;
    let mut payment_attempts = Vec::with_capacity(raw.payments.len());
    for payment in &raw.payments {
        payment_attempts.push(project_payment(payment, &currency_code)?);
    }
    let item_digest = (!raw.items.is_empty()).then(|| Digest::from_serializable(&raw.items));
    let metadata_digest = raw.custom_data.as_ref().map(Digest::from_serializable);
    let error_digest = raw
        .error_code
        .as_ref()
        .or(raw.error.as_ref())
        .map(Digest::from_serializable);
    let summary = PaddleTransactionSummary {
        account_id,
        transaction_id,
        subscription_id,
        customer_digest,
        status: TransactionStatus::parse(&raw.status),
        origin: raw.origin,
        currency_code,
        subtotal,
        discount,
        tax,
        total,
        earnings,
        billing_period,
        created_at: raw.created_at,
        updated_at: raw.updated_at,
        billed_at: raw.billed_at,
        completed_at: raw.completed_at,
        payment_attempts,
        item_count: raw.items.len().try_into().unwrap_or(u32::MAX),
        item_digest,
        metadata_digest,
        error_digest,
        source_digest,
    };
    crate::model::validate_transaction_scope(&summary, scope)?;
    Ok(summary)
}

fn project_payment(
    raw: &RawPaymentAttempt,
    currency_code: &str,
) -> Result<PaddlePaymentAttemptSummary> {
    let amount = raw
        .amount
        .as_ref()
        .map(|value| amount_summary(value, currency_code))
        .transpose()?;
    let error_digest = raw
        .error_code
        .as_ref()
        .or(raw.error.as_ref())
        .map(Digest::from_serializable);
    let attempt_digest = Digest::from_serializable(raw);
    let result = PaddlePaymentAttemptSummary {
        attempt_digest,
        status: PaymentAttemptStatus::parse(&raw.status),
        amount,
        created_at: raw.created_at.clone(),
        error_digest,
    };
    result.validate()?;
    Ok(result)
}

fn project_event(raw: RawEvent, scope: &PaddleBillingScope) -> Result<PaddleEventSummary> {
    crate::model::validate_event_type(&raw.event_type)?;
    let data = raw
        .data
        .as_object()
        .ok_or(PaddleSubscriptionResultError::Provider(
            PaddleBillingProviderError::PartialResponse,
        ))?;
    let account_id = account_from_value(data.get("seller_id"), scope)?;
    let related_id =
        data.get("id")
            .and_then(Value::as_str)
            .ok_or(PaddleSubscriptionResultError::Provider(
                PaddleBillingProviderError::PartialResponse,
            ))?;
    let (subscription_id, transaction_id) = if raw.event_type.starts_with("subscription.") {
        (Some(SubscriptionId::new(related_id)?), None)
    } else {
        let transaction_id = TransactionId::new(related_id)?;
        let subscription_id = data
            .get("subscription_id")
            .and_then(Value::as_str)
            .map(SubscriptionId::new)
            .transpose()?;
        (subscription_id, Some(transaction_id))
    };
    let subscription_status = data
        .get("status")
        .and_then(Value::as_str)
        .filter(|_| raw.event_type.starts_with("subscription."))
        .map(SubscriptionStatus::parse);
    let transaction_status = data
        .get("status")
        .and_then(Value::as_str)
        .filter(|_| raw.event_type.starts_with("transaction."))
        .map(|status| {
            if raw.event_type == "transaction.payment_failed" {
                TransactionStatus::Failed
            } else {
                TransactionStatus::parse(status)
            }
        });
    let summary = PaddleEventSummary {
        account_id,
        event_id: crate::EventId::new(raw.event_id)?,
        event_type: raw.event_type,
        subscription_id,
        transaction_id,
        subscription_status,
        transaction_status,
        occurred_at: raw.occurred_at,
        customer_digest: customer_digest(
            data.get("customer_id").and_then(Value::as_str),
            data.get("customer"),
        ),
        item_digest: data.get("items").map(Digest::from_serializable),
        data_digest: Digest::from_serializable(&raw.data),
    };
    crate::model::validate_event_scope(&summary, scope)?;
    Ok(summary)
}

fn account_from_optional(seller_id: Option<&str>, scope: &PaddleBillingScope) -> Result<AccountId> {
    let account_id = seller_id
        .map(AccountId::new)
        .transpose()?
        .unwrap_or_else(|| scope.identity().account_id.clone());
    if account_id != scope.identity().account_id {
        Err(PaddleSubscriptionResultError::AccountMismatch)
    } else {
        Ok(account_id)
    }
}

fn account_from_value(value: Option<&Value>, scope: &PaddleBillingScope) -> Result<AccountId> {
    match value.and_then(Value::as_str) {
        Some(value) => account_from_optional(Some(value), scope),
        None => Ok(scope.identity().account_id.clone()),
    }
}

fn customer_digest(customer_id: Option<&str>, customer: Option<&Value>) -> Option<Digest> {
    if customer_id.is_none() && customer.is_none() {
        None
    } else {
        Some(Digest::from_serializable(&(customer_id, customer)))
    }
}

fn amount_summary(value: &Value, fallback_currency: &str) -> Result<AmountSummary> {
    let (currency, amount) = if let Some(object) = value.as_object() {
        let currency = object
            .get("currency_code")
            .and_then(Value::as_str)
            .unwrap_or(fallback_currency);
        let amount = object.get("amount").map(value_to_text).transpose()?.ok_or(
            PaddleSubscriptionResultError::Provider(PaddleBillingProviderError::MalformedResponse(
                "money amount",
            )),
        )?;
        (currency.to_owned(), amount)
    } else {
        (fallback_currency.to_owned(), value_to_text(value)?)
    };
    AmountSummary::new(currency, amount)
}

fn value_to_text(value: &Value) -> Result<String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        _ => Err(PaddleSubscriptionResultError::Provider(
            PaddleBillingProviderError::MalformedResponse("bounded scalar"),
        )),
    }
}

fn page_state<T>(page: &RawList<T>) -> Result<(bool, Option<String>)> {
    let pagination = page.meta.as_ref().and_then(|meta| meta.pagination.as_ref());
    let has_more = pagination
        .and_then(|value| value.has_more)
        .or(page.has_more)
        .unwrap_or(false);
    let next = pagination
        .and_then(|value| value.next.as_deref())
        .or(page.next.as_deref());
    let after = next
        .and_then(extract_after)
        .or_else(|| page.last_id.clone());
    if has_more && after.is_none() {
        Err(PaddleSubscriptionResultError::Provider(
            PaddleBillingProviderError::PartialResponse,
        ))
    } else {
        Ok((has_more, after))
    }
}

fn extract_after(next: &str) -> Option<String> {
    let marker = "after=";
    let start = next.find(marker)? + marker.len();
    let value = next[start..].split('&').next()?.to_owned();
    (!value.is_empty() && !value.chars().any(char::is_whitespace)).then_some(value)
}

fn new_cursor(
    token: String,
    kind: CursorKind,
    scope: &PaddleBillingScope,
    response_digest: &Digest,
    observed_at: u64,
) -> Result<PaddleCursor> {
    PaddleCursor::new(
        token,
        kind,
        scope.scope_digest(),
        response_digest.clone(),
        observed_at,
        observed_at.saturating_add(crate::EVENT_RETENTION_SECONDS),
    )
}

// These imports are part of the provider's typed surface and ensure the
// provider cannot silently accept a host/API binding it does not understand.
#[allow(dead_code)]
fn _binding_digest(scope: &PaddleBillingScopeIdentity) -> Digest {
    ApiBinding::official(scope.api.revision).digest()
}

#[allow(dead_code)]
fn _bounded_map_digest(map: &Map<String, Value>) -> Digest {
    Digest::from_serializable(map)
}
