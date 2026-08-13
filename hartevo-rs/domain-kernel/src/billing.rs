//! Typed Stripe Billing facts and request/verification contracts.
//!
//! This module deliberately stops at the provider boundary. A signed webhook or
//! a successful Stripe response is an immutable provider observation; it is not
//! by itself a Hartevo business settlement. Reconciliation observations are
//! append-only and are the only source that can independently settle a payment
//! or Connect payout.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::form_urlencoded::Serializer;

use crate::{CurrencyCode, Money, ProjectId, TenantId};

pub const STRIPE_BILLING_CONTRACT_VERSION: &str = "stripe-billing/v1";
pub const STRIPE_WEBHOOK_SIGNATURE_TOLERANCE_SECONDS: i64 = 300;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum StripeHttpMethod {
    Post,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StripeRequest {
    pub contract_version: String,
    pub method: StripeHttpMethod,
    pub path: String,
    pub form_body: String,
    pub idempotency_key: String,
    pub request_digest: String,
}

impl StripeRequest {
    fn new(
        path: impl Into<String>,
        form_body: String,
        idempotency_key: impl Into<String>,
    ) -> Result<Self, BillingLedgerError> {
        let path = path.into();
        let idempotency_key = idempotency_key.into();
        if !path.starts_with("/v1/")
            || path.contains('?')
            || form_body.trim().is_empty()
            || idempotency_key.trim().is_empty()
        {
            return Err(BillingLedgerError::InvalidStripeRequest);
        }
        let mut digest = Sha256::new();
        hash_field(&mut digest, STRIPE_BILLING_CONTRACT_VERSION);
        hash_field(&mut digest, "POST");
        hash_field(&mut digest, &path);
        hash_field(&mut digest, &form_body);
        hash_field(&mut digest, &idempotency_key);
        Ok(Self {
            contract_version: STRIPE_BILLING_CONTRACT_VERSION.into(),
            method: StripeHttpMethod::Post,
            path,
            form_body,
            idempotency_key,
            request_digest: format!("{:x}", digest.finalize()),
        })
    }
}

/// Real Stripe Billing sandbox-compatible form request builders. The
/// connector/Effect Broker owns credentials and dispatch; these builders only
/// produce a deterministic request contract and never contain a secret.
#[derive(Debug)]
pub struct StripeBillingRequest;

impl StripeBillingRequest {
    pub fn create_customer(
        tenant_id: &TenantId,
        project_id: &ProjectId,
        idempotency_key: impl Into<String>,
    ) -> Result<StripeRequest, BillingLedgerError> {
        let mut form = Serializer::new(String::new());
        add_scope_metadata(&mut form, tenant_id, project_id);
        StripeRequest::new("/v1/customers", form.finish(), idempotency_key)
    }

    pub fn create_subscription(
        tenant_id: &TenantId,
        project_id: &ProjectId,
        customer_id: &str,
        price_id: &str,
        quantity: u64,
        idempotency_key: impl Into<String>,
    ) -> Result<StripeRequest, BillingLedgerError> {
        validate_external_id(customer_id)?;
        validate_external_id(price_id)?;
        if quantity == 0 {
            return Err(BillingLedgerError::InvalidStripeRequest);
        }
        let mut form = Serializer::new(String::new());
        form.append_pair("customer", customer_id);
        form.append_pair("items[0][price]", price_id);
        form.append_pair("items[0][quantity]", &quantity.to_string());
        add_scope_metadata(&mut form, tenant_id, project_id);
        StripeRequest::new("/v1/subscriptions", form.finish(), idempotency_key)
    }

    /// Stripe customer balance transactions use a signed provider amount:
    /// negative credits increase the customer's credit balance and positive
    /// debits reduce it. The Hartevo contract exposes direction explicitly and
    /// emits the corresponding Stripe sign.
    pub fn create_credit_adjustment(
        tenant_id: &TenantId,
        project_id: &ProjectId,
        customer_id: &str,
        amount: &Money,
        direction: StripeCreditDirection,
        description: &str,
        idempotency_key: impl Into<String>,
    ) -> Result<StripeRequest, BillingLedgerError> {
        validate_external_id(customer_id)?;
        if !amount.is_positive() || description.trim().is_empty() {
            return Err(BillingLedgerError::InvalidStripeRequest);
        }
        let provider_amount = match direction {
            StripeCreditDirection::Grant => amount
                .amount_minor
                .checked_neg()
                .ok_or(BillingLedgerError::AmountOverflow)?,
            StripeCreditDirection::Debit => amount.amount_minor,
        };
        let mut form = Serializer::new(String::new());
        form.append_pair("amount", &provider_amount.to_string());
        form.append_pair("currency", &amount.currency.as_str().to_ascii_lowercase());
        form.append_pair("description", description.trim());
        add_scope_metadata(&mut form, tenant_id, project_id);
        StripeRequest::new(
            format!("/v1/customers/{customer_id}/balance_transactions"),
            form.finish(),
            idempotency_key,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeCreditDirection {
    Grant,
    Debit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeSubscriptionStatus {
    Incomplete,
    IncompleteExpired,
    Trialing,
    Active,
    PastDue,
    Canceled,
    Unpaid,
    Paused,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeInvoiceStatus {
    Draft,
    Open,
    Paid,
    Uncollectible,
    Void,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StripePaymentStatus {
    Processing,
    Succeeded,
    Failed,
    RequiresAction,
    RequiresPaymentMethod,
    Canceled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeCheckoutPaymentStatus {
    Paid,
    Unpaid,
    NoPaymentRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeRefundStatus {
    Pending,
    Succeeded,
    Failed,
    Canceled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeDisputeStatus {
    NeedsResponse,
    UnderReview,
    Won,
    Lost,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StripePayoutStatus {
    Pending,
    Paid,
    Failed,
    Canceled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeWebhookEventType {
    CustomerCreated,
    CustomerUpdated,
    CustomerDeleted,
    SubscriptionCreated,
    SubscriptionUpdated,
    SubscriptionDeleted,
    CheckoutSessionCompleted,
    InvoiceFinalized,
    InvoicePaid,
    InvoicePaymentFailed,
    InvoiceVoided,
    PaymentIntentProcessing,
    PaymentIntentSucceeded,
    PaymentIntentFailed,
    PaymentIntentCanceled,
    CreditTransactionCreated,
    CreditGrantCreated,
    CreditGrantUpdated,
    CreditGrantExpired,
    RefundCreated,
    RefundUpdated,
    ChargeRefunded,
    DisputeCreated,
    DisputeClosed,
    PayoutCreated,
    PayoutPaid,
    PayoutFailed,
    PayoutCanceled,
}

impl StripeWebhookEventType {
    fn parse(value: &str) -> Result<Self, BillingLedgerError> {
        match value {
            "customer.created" => Ok(Self::CustomerCreated),
            "customer.updated" => Ok(Self::CustomerUpdated),
            "customer.deleted" => Ok(Self::CustomerDeleted),
            "customer.subscription.created" => Ok(Self::SubscriptionCreated),
            "customer.subscription.updated" => Ok(Self::SubscriptionUpdated),
            "customer.subscription.deleted" => Ok(Self::SubscriptionDeleted),
            "checkout.session.completed" => Ok(Self::CheckoutSessionCompleted),
            "invoice.finalized" => Ok(Self::InvoiceFinalized),
            "invoice.paid" => Ok(Self::InvoicePaid),
            "invoice.payment_failed" => Ok(Self::InvoicePaymentFailed),
            "invoice.voided" => Ok(Self::InvoiceVoided),
            "payment_intent.processing" => Ok(Self::PaymentIntentProcessing),
            "payment_intent.succeeded" => Ok(Self::PaymentIntentSucceeded),
            "payment_intent.payment_failed" => Ok(Self::PaymentIntentFailed),
            "payment_intent.canceled" => Ok(Self::PaymentIntentCanceled),
            "customer.balance_transaction.created"
            | "customer_cash_balance_transaction.created" => Ok(Self::CreditTransactionCreated),
            "billing.credit_grant.created" => Ok(Self::CreditGrantCreated),
            "billing.credit_grant.updated" => Ok(Self::CreditGrantUpdated),
            "billing.credit_grant.expired" => Ok(Self::CreditGrantExpired),
            "refund.created" => Ok(Self::RefundCreated),
            "refund.updated" => Ok(Self::RefundUpdated),
            "charge.refunded" => Ok(Self::ChargeRefunded),
            "charge.dispute.created" => Ok(Self::DisputeCreated),
            "charge.dispute.closed" => Ok(Self::DisputeClosed),
            "payout.created" => Ok(Self::PayoutCreated),
            "payout.paid" => Ok(Self::PayoutPaid),
            "payout.failed" => Ok(Self::PayoutFailed),
            "payout.canceled" => Ok(Self::PayoutCanceled),
            other => Err(BillingLedgerError::UnsupportedWebhookEvent(other.into())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustomerCreated => "customer.created",
            Self::CustomerUpdated => "customer.updated",
            Self::CustomerDeleted => "customer.deleted",
            Self::SubscriptionCreated => "customer.subscription.created",
            Self::SubscriptionUpdated => "customer.subscription.updated",
            Self::SubscriptionDeleted => "customer.subscription.deleted",
            Self::CheckoutSessionCompleted => "checkout.session.completed",
            Self::InvoiceFinalized => "invoice.finalized",
            Self::InvoicePaid => "invoice.paid",
            Self::InvoicePaymentFailed => "invoice.payment_failed",
            Self::InvoiceVoided => "invoice.voided",
            Self::PaymentIntentProcessing => "payment_intent.processing",
            Self::PaymentIntentSucceeded => "payment_intent.succeeded",
            Self::PaymentIntentFailed => "payment_intent.payment_failed",
            Self::PaymentIntentCanceled => "payment_intent.canceled",
            Self::CreditTransactionCreated => "customer.balance_transaction.created",
            Self::CreditGrantCreated => "billing.credit_grant.created",
            Self::CreditGrantUpdated => "billing.credit_grant.updated",
            Self::CreditGrantExpired => "billing.credit_grant.expired",
            Self::RefundCreated => "refund.created",
            Self::RefundUpdated => "refund.updated",
            Self::ChargeRefunded => "charge.refunded",
            Self::DisputeCreated => "charge.dispute.created",
            Self::DisputeClosed => "charge.dispute.closed",
            Self::PayoutCreated => "payout.created",
            Self::PayoutPaid => "payout.paid",
            Self::PayoutFailed => "payout.failed",
            Self::PayoutCanceled => "payout.canceled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum StripeBillingFactPayload {
    Customer {
        customer_id: String,
        livemode: bool,
        deleted: bool,
    },
    Subscription {
        subscription_id: String,
        customer_id: String,
        status: StripeSubscriptionStatus,
        price_id: Option<String>,
        current_period_start: DateTime<Utc>,
        current_period_end: DateTime<Utc>,
        cancel_at_period_end: bool,
    },
    ProviderAccepted {
        session_id: String,
        customer_id: Option<String>,
        payment_status: Option<StripeCheckoutPaymentStatus>,
        amount: Option<Money>,
    },
    Invoice {
        invoice_id: String,
        customer_id: Option<String>,
        subscription_id: Option<String>,
        status: StripeInvoiceStatus,
        amount_due: Money,
        amount_paid: Money,
        payment_intent_id: Option<String>,
    },
    Payment {
        payment_intent_id: String,
        customer_id: Option<String>,
        invoice_id: Option<String>,
        amount: Money,
        status: StripePaymentStatus,
    },
    Credit {
        credit_id: String,
        customer_id: String,
        amount: Money,
        direction: StripeCreditDirection,
        expires_at: Option<DateTime<Utc>>,
    },
    Refund {
        refund_id: String,
        payment_intent_id: Option<String>,
        charge_id: Option<String>,
        amount: Money,
        status: StripeRefundStatus,
    },
    Dispute {
        dispute_id: String,
        charge_id: String,
        amount: Money,
        status: StripeDisputeStatus,
    },
    Payout {
        payout_id: String,
        connected_account_id: Option<String>,
        amount: Money,
        status: StripePayoutStatus,
        arrival_at: Option<DateTime<Utc>>,
    },
}

impl StripeBillingFactPayload {
    pub fn kind(&self) -> StripeBillingFactKind {
        match self {
            Self::Customer { .. } => StripeBillingFactKind::Customer,
            Self::Subscription { .. } => StripeBillingFactKind::Subscription,
            Self::ProviderAccepted { .. } => StripeBillingFactKind::ProviderAccepted,
            Self::Invoice { .. } => StripeBillingFactKind::Invoice,
            Self::Payment { .. } => StripeBillingFactKind::Payment,
            Self::Credit { .. } => StripeBillingFactKind::Credit,
            Self::Refund { .. } => StripeBillingFactKind::Refund,
            Self::Dispute { .. } => StripeBillingFactKind::Dispute,
            Self::Payout { .. } => StripeBillingFactKind::Payout,
        }
    }

    pub fn external_id(&self) -> &str {
        match self {
            Self::Customer { customer_id, .. } => customer_id,
            Self::Subscription {
                subscription_id, ..
            } => subscription_id,
            Self::ProviderAccepted { session_id, .. } => session_id,
            Self::Invoice { invoice_id, .. } => invoice_id,
            Self::Payment {
                payment_intent_id, ..
            } => payment_intent_id,
            Self::Credit { credit_id, .. } => credit_id,
            Self::Refund { refund_id, .. } => refund_id,
            Self::Dispute { dispute_id, .. } => dispute_id,
            Self::Payout { payout_id, .. } => payout_id,
        }
    }

    pub fn amount(&self) -> Option<&Money> {
        match self {
            Self::ProviderAccepted { amount, .. } => amount.as_ref(),
            Self::Invoice { amount_paid, .. } => Some(amount_paid),
            Self::Payment { amount, .. }
            | Self::Credit { amount, .. }
            | Self::Refund { amount, .. }
            | Self::Dispute { amount, .. }
            | Self::Payout { amount, .. } => Some(amount),
            Self::Customer { .. } | Self::Subscription { .. } => None,
        }
    }

    pub fn is_explicit_paid_or_settled(&self) -> bool {
        matches!(
            self,
            Self::Invoice {
                status: StripeInvoiceStatus::Paid,
                ..
            } | Self::Payment {
                status: StripePaymentStatus::Succeeded,
                ..
            } | Self::Payout {
                status: StripePayoutStatus::Paid,
                ..
            }
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeBillingFactKind {
    Customer,
    Subscription,
    ProviderAccepted,
    Invoice,
    Payment,
    Credit,
    Refund,
    Dispute,
    Payout,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum StripeFactSource {
    Webhook {
        event_id: String,
        signature_digest: String,
        received_at: DateTime<Utc>,
    },
    Reconciliation {
        request_id: String,
        readback_digest: String,
        observed_at: DateTime<Utc>,
    },
}

impl StripeFactSource {
    pub fn is_reconciliation(&self) -> bool {
        matches!(self, Self::Reconciliation { .. })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StripeBillingFact {
    pub fact_id: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub external_id: String,
    pub kind: StripeBillingFactKind,
    pub source: StripeFactSource,
    pub observed_at: DateTime<Utc>,
    pub payload: StripeBillingFactPayload,
    pub immutable_digest: String,
}

impl StripeBillingFact {
    pub fn new(
        fact_id: impl Into<String>,
        tenant_id: TenantId,
        project_id: ProjectId,
        source: StripeFactSource,
        observed_at: DateTime<Utc>,
        payload: StripeBillingFactPayload,
    ) -> Result<Self, BillingLedgerError> {
        let fact_id = fact_id.into();
        let external_id = payload.external_id().to_owned();
        let source_valid = match &source {
            StripeFactSource::Webhook {
                event_id,
                signature_digest,
                received_at,
            } => {
                !event_id.trim().is_empty()
                    && is_sha256(signature_digest)
                    && received_at.timestamp() >= 0
            }
            StripeFactSource::Reconciliation {
                request_id,
                readback_digest,
                observed_at,
            } => {
                !request_id.trim().is_empty()
                    && is_sha256(readback_digest)
                    && observed_at.timestamp() >= 0
            }
        };
        if fact_id.trim().is_empty()
            || tenant_id.as_str().trim().is_empty()
            || project_id.as_str().trim().is_empty()
            || external_id.trim().is_empty()
            || observed_at.timestamp() < 0
            || !source_valid
            || payload
                .amount()
                .is_some_and(|money| money.currency.as_str().len() != 3)
        {
            return Err(BillingLedgerError::InvalidFact);
        }
        let kind = payload.kind();
        let immutable_digest = fact_digest(
            &fact_id,
            &tenant_id,
            &project_id,
            &source,
            observed_at,
            &payload,
        )?;
        Ok(Self {
            fact_id,
            tenant_id,
            project_id,
            external_id,
            kind,
            source,
            observed_at,
            payload,
            immutable_digest,
        })
    }

    pub fn is_independently_settled(&self) -> bool {
        self.source.is_reconciliation() && self.payload.is_explicit_paid_or_settled()
    }

    pub fn credit_grant_amount(&self) -> Option<&Money> {
        match &self.payload {
            StripeBillingFactPayload::Credit {
                amount,
                direction: StripeCreditDirection::Grant,
                ..
            } => Some(amount),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StripeWebhookEvent {
    pub id: String,
    pub event_type: StripeWebhookEventType,
    pub created_at: DateTime<Utc>,
    pub livemode: bool,
    pub object_id: String,
    pub metadata: BTreeMap<String, String>,
    pub payload_digest: String,
    pub payload: StripeBillingFactPayload,
}

impl StripeWebhookEvent {
    pub fn parse(body: &str) -> Result<Self, BillingLedgerError> {
        let value: Value = serde_json::from_str(body)
            .map_err(|error| BillingLedgerError::InvalidWebhookPayload(error.to_string()))?;
        Self::parse_value(&value, body, None)
    }

    pub fn parse_at(body: &str, received_at: DateTime<Utc>) -> Result<Self, BillingLedgerError> {
        if received_at.timestamp() < 0 {
            return Err(BillingLedgerError::InvalidFact);
        }
        let value: Value = serde_json::from_str(body)
            .map_err(|error| BillingLedgerError::InvalidWebhookPayload(error.to_string()))?;
        Self::parse_value(&value, body, Some(received_at))
    }

    fn parse_value(
        value: &Value,
        body: &str,
        _received_at: Option<DateTime<Utc>>,
    ) -> Result<Self, BillingLedgerError> {
        let root = value.as_object().ok_or_else(|| {
            BillingLedgerError::InvalidWebhookPayload("root is not an object".into())
        })?;
        let id = required_string(root, "id")?;
        let raw_type = required_string(root, "type")?;
        let event_type = StripeWebhookEventType::parse(&raw_type)?;
        let created = required_i64(root, "created")?;
        let created_at = stripe_time(created)?;
        let livemode = root
            .get("livemode")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let data = root
            .get("data")
            .and_then(Value::as_object)
            .ok_or_else(|| BillingLedgerError::MissingWebhookField("data".into()))?;
        let object = data
            .get("object")
            .ok_or_else(|| BillingLedgerError::MissingWebhookField("data.object".into()))?;
        let object_map = object.as_object().ok_or_else(|| {
            BillingLedgerError::InvalidWebhookPayload("data.object is not an object".into())
        })?;
        let object_id = required_string(object_map, "id")?;
        let metadata = parse_metadata(object_map.get("metadata"))?;
        let payload = parse_payload(event_type, object_map, livemode)?;
        Ok(Self {
            id,
            event_type,
            created_at,
            livemode,
            object_id,
            metadata,
            payload_digest: sha256(body.as_bytes()),
            payload,
        })
    }

    pub fn bind_scope(
        self,
        tenant_id: TenantId,
        project_id: ProjectId,
    ) -> Result<ScopedStripeWebhook, BillingLedgerError> {
        let expected_tenant = self
            .metadata
            .get("hartevo_tenant_id")
            .or_else(|| self.metadata.get("tenant_id"))
            .ok_or(BillingLedgerError::WebhookScopeMissing)?;
        let expected_project = self
            .metadata
            .get("hartevo_project_id")
            .or_else(|| self.metadata.get("project_id"))
            .ok_or(BillingLedgerError::WebhookScopeMissing)?;
        if expected_tenant != tenant_id.as_str() || expected_project != project_id.as_str() {
            return Err(BillingLedgerError::WebhookScopeMismatch);
        }
        Ok(ScopedStripeWebhook {
            tenant_id,
            project_id,
            event: self,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopedStripeWebhook {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub event: StripeWebhookEvent,
}

impl ScopedStripeWebhook {
    pub fn fact(&self, source: StripeFactSource) -> Result<StripeBillingFact, BillingLedgerError> {
        StripeBillingFact::new(
            format!("stripe-event:{}", self.event.id),
            self.tenant_id.clone(),
            self.project_id.clone(),
            source,
            self.event.created_at,
            self.event.payload.clone(),
        )
    }

    pub fn event_id(&self) -> &str {
        &self.event.id
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedStripeWebhook {
    pub event: StripeWebhookEvent,
    pub signature: StripeSignature,
    pub signature_digest: String,
    pub received_at: DateTime<Utc>,
}

impl VerifiedStripeWebhook {
    pub fn bind_scope(
        self,
        tenant_id: TenantId,
        project_id: ProjectId,
    ) -> Result<ScopedVerifiedStripeWebhook, BillingLedgerError> {
        let scoped_event = self.event.clone().bind_scope(tenant_id, project_id)?;
        Ok(ScopedVerifiedStripeWebhook {
            webhook: self,
            scoped_event,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopedVerifiedStripeWebhook {
    pub webhook: VerifiedStripeWebhook,
    pub scoped_event: ScopedStripeWebhook,
}

impl ScopedVerifiedStripeWebhook {
    pub fn fact(&self) -> Result<StripeBillingFact, BillingLedgerError> {
        self.scoped_event.fact(StripeFactSource::Webhook {
            event_id: self.webhook.event.id.clone(),
            signature_digest: self.webhook.signature_digest.clone(),
            received_at: self.webhook.received_at,
        })
    }

    pub fn event_id(&self) -> &str {
        self.webhook.event.id.as_str()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StripeSignature {
    pub timestamp: i64,
    pub v1: Vec<String>,
}

impl StripeSignature {
    pub fn parse(header: &str) -> Result<Self, BillingLedgerError> {
        let mut timestamp = None;
        let mut signatures = Vec::new();
        for component in header.split(',') {
            let (key, value) = component
                .trim()
                .split_once('=')
                .ok_or(BillingLedgerError::InvalidStripeSignature)?;
            if value.trim().is_empty() {
                return Err(BillingLedgerError::InvalidStripeSignature);
            }
            match key {
                "t" if timestamp.is_none() => {
                    timestamp = Some(
                        value
                            .parse::<i64>()
                            .map_err(|_| BillingLedgerError::InvalidStripeSignature)?,
                    );
                }
                "v1" => {
                    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        return Err(BillingLedgerError::InvalidStripeSignature);
                    }
                    signatures.push(value.to_ascii_lowercase());
                }
                "t" | "v0" => {}
                _ => return Err(BillingLedgerError::InvalidStripeSignature),
            }
        }
        let timestamp = timestamp.ok_or(BillingLedgerError::InvalidStripeSignature)?;
        if signatures.is_empty() {
            return Err(BillingLedgerError::InvalidStripeSignature);
        }
        Ok(Self {
            timestamp,
            v1: signatures,
        })
    }

    pub fn verify(
        &self,
        body: &str,
        signing_secret: &str,
        now: DateTime<Utc>,
        tolerance: Duration,
    ) -> Result<(), BillingLedgerError> {
        if signing_secret.trim().is_empty() || tolerance < Duration::zero() {
            return Err(BillingLedgerError::InvalidStripeSignature);
        }
        let now_seconds = now.timestamp();
        let age = now_seconds
            .checked_sub(self.timestamp)
            .ok_or(BillingLedgerError::InvalidStripeSignature)?
            .unsigned_abs();
        let tolerance_seconds = u64::try_from(tolerance.num_seconds())
            .map_err(|_| BillingLedgerError::InvalidStripeSignature)?;
        if age > tolerance_seconds {
            return Err(BillingLedgerError::WebhookTimestampOutsideTolerance);
        }
        let signed_payload = format!("{}.{}", self.timestamp, body);
        let expected = hmac_sha256_hex(signing_secret.as_bytes(), signed_payload.as_bytes());
        if !self
            .v1
            .iter()
            .any(|candidate| constant_time_eq(candidate, &expected))
        {
            return Err(BillingLedgerError::InvalidStripeSignature);
        }
        Ok(())
    }
}

pub fn verify_stripe_webhook(
    body: &str,
    signature_header: &str,
    signing_secret: &str,
    now: DateTime<Utc>,
    tolerance: Duration,
) -> Result<VerifiedStripeWebhook, BillingLedgerError> {
    let signature = StripeSignature::parse(signature_header)?;
    signature.verify(body, signing_secret, now, tolerance)?;
    let event = StripeWebhookEvent::parse_at(body, now)?;
    Ok(VerifiedStripeWebhook {
        event,
        signature,
        signature_digest: sha256(signature_header.as_bytes()),
        received_at: now,
    })
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StripeBillingLedger {
    pub revision: u64,
    pub webhook_event_digests: BTreeMap<String, String>,
    pub facts: Vec<StripeBillingFact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BillingLedgerIngest {
    Applied { revision: u64, fact_digest: String },
    Replayed { revision: u64, fact_digest: String },
}

impl StripeBillingLedger {
    pub fn ingest_webhook(
        &mut self,
        webhook: &ScopedVerifiedStripeWebhook,
    ) -> Result<BillingLedgerIngest, BillingLedgerError> {
        let fact = webhook.fact()?;
        if let Some(existing) = self.webhook_event_digests.get(webhook.event_id()) {
            if existing == &webhook.webhook.event.payload_digest {
                let fact_digest = self
                    .facts
                    .iter()
                    .find(|candidate| candidate.fact_id == fact.fact_id)
                    .map(|candidate| candidate.immutable_digest.clone())
                    .unwrap_or(fact.immutable_digest);
                return Ok(BillingLedgerIngest::Replayed {
                    revision: self.revision,
                    fact_digest,
                });
            }
            return Err(BillingLedgerError::WebhookReplayConflict);
        }
        self.append_fact(fact.clone())?;
        self.webhook_event_digests.insert(
            webhook.event_id().into(),
            webhook.webhook.event.payload_digest.clone(),
        );
        Ok(BillingLedgerIngest::Applied {
            revision: self.revision,
            fact_digest: fact.immutable_digest,
        })
    }

    pub fn ingest_reconciliation(
        &mut self,
        fact: StripeBillingFact,
    ) -> Result<BillingLedgerIngest, BillingLedgerError> {
        if !fact.source.is_reconciliation() {
            return Err(BillingLedgerError::ReconciliationSourceRequired);
        }
        if let Some(existing) = self
            .facts
            .iter()
            .find(|candidate| candidate.immutable_digest == fact.immutable_digest)
        {
            return Ok(BillingLedgerIngest::Replayed {
                revision: self.revision,
                fact_digest: existing.immutable_digest.clone(),
            });
        }
        self.append_fact(fact.clone())?;
        Ok(BillingLedgerIngest::Applied {
            revision: self.revision,
            fact_digest: fact.immutable_digest,
        })
    }

    pub fn from_parts(
        revision: u64,
        webhook_event_digests: BTreeMap<String, String>,
        facts: Vec<StripeBillingFact>,
    ) -> Result<Self, BillingLedgerError> {
        if revision != u64::try_from(facts.len()).unwrap_or(u64::MAX) {
            return Err(BillingLedgerError::LedgerRevisionMismatch);
        }
        let mut ledger = Self {
            revision: 0,
            webhook_event_digests,
            facts: Vec::new(),
        };
        let mut seen_webhook_events = BTreeSet::new();
        for fact in facts {
            if let StripeFactSource::Webhook { event_id, .. } = &fact.source
                && (!ledger.webhook_event_digests.contains_key(event_id)
                    || !seen_webhook_events.insert(event_id.clone()))
            {
                return Err(BillingLedgerError::LedgerIntegrityFailure);
            }
            ledger.append_fact(fact)?;
        }
        if seen_webhook_events.len() != ledger.webhook_event_digests.len() {
            return Err(BillingLedgerError::LedgerIntegrityFailure);
        }
        Ok(ledger)
    }

    pub fn fact(&self, digest: &str) -> Option<&StripeBillingFact> {
        self.facts
            .iter()
            .find(|fact| fact.immutable_digest == digest)
    }

    fn append_fact(&mut self, fact: StripeBillingFact) -> Result<(), BillingLedgerError> {
        if self
            .facts
            .iter()
            .any(|existing| existing.immutable_digest == fact.immutable_digest)
        {
            return Err(BillingLedgerError::DuplicateFact);
        }
        if fact.tenant_id.as_str().trim().is_empty() || fact.project_id.as_str().trim().is_empty() {
            return Err(BillingLedgerError::InvalidFact);
        }
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(BillingLedgerError::LedgerRevisionOverflow)?;
        self.facts.push(fact);
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BillingLedgerError {
    #[error("Stripe webhook signature is missing, malformed, or invalid")]
    InvalidStripeSignature,
    #[error("Stripe webhook timestamp is outside the allowed tolerance")]
    WebhookTimestampOutsideTolerance,
    #[error("Stripe webhook payload is invalid: {0}")]
    InvalidWebhookPayload(String),
    #[error("Stripe webhook event type {0} is not supported by the Billing contract")]
    UnsupportedWebhookEvent(String),
    #[error("Stripe webhook is missing field {0}")]
    MissingWebhookField(String),
    #[error("Stripe webhook metadata does not contain a Hartevo scope")]
    WebhookScopeMissing,
    #[error("Stripe webhook metadata does not match the requested tenant/project scope")]
    WebhookScopeMismatch,
    #[error("Stripe webhook replay has the same event id but a different payload")]
    WebhookReplayConflict,
    #[error("a Billing fact is invalid")]
    InvalidFact,
    #[error("reconciliation facts must use a reconciliation source")]
    ReconciliationSourceRequired,
    #[error("the Billing fact ledger already contains this immutable fact")]
    DuplicateFact,
    #[error("Billing ledger revision overflowed")]
    LedgerRevisionOverflow,
    #[error("Billing ledger revision does not match its append-only facts")]
    LedgerRevisionMismatch,
    #[error("Billing ledger integrity validation failed")]
    LedgerIntegrityFailure,
    #[error("Stripe request contract is invalid")]
    InvalidStripeRequest,
    #[error("Stripe amount overflowed its minor-unit representation")]
    AmountOverflow,
    #[error("Stripe object id is missing or malformed")]
    InvalidExternalId,
    #[error("Stripe object state is unsupported: {0}")]
    InvalidStripeState(String),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum StripeWebhookError {
    #[error(transparent)]
    Billing(#[from] BillingLedgerError),
}

fn add_scope_metadata(
    serializer: &mut Serializer<String>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
) {
    serializer.append_pair("metadata[hartevo_tenant_id]", tenant_id.as_str());
    serializer.append_pair("metadata[hartevo_project_id]", project_id.as_str());
}

fn validate_external_id(value: &str) -> Result<(), BillingLedgerError> {
    if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
        Err(BillingLedgerError::InvalidExternalId)
    } else {
        Ok(())
    }
}

fn required_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<String, BillingLedgerError> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| BillingLedgerError::MissingWebhookField(field.into()))?;
    Ok(value.to_owned())
}

fn required_i64(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<i64, BillingLedgerError> {
    object
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| BillingLedgerError::MissingWebhookField(field.into()))
}

fn optional_i64(object: &serde_json::Map<String, Value>, field: &str) -> Option<i64> {
    object.get(field).and_then(Value::as_i64)
}

fn stripe_time(seconds: i64) -> Result<DateTime<Utc>, BillingLedgerError> {
    DateTime::from_timestamp(seconds, 0).ok_or(BillingLedgerError::InvalidFact)
}

fn parse_metadata(value: Option<&Value>) -> Result<BTreeMap<String, String>, BillingLedgerError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let object = value.as_object().ok_or_else(|| {
        BillingLedgerError::InvalidWebhookPayload("metadata is not an object".into())
    })?;
    let mut metadata = BTreeMap::new();
    for (key, value) in object {
        let value = value.as_str().ok_or_else(|| {
            BillingLedgerError::InvalidWebhookPayload("metadata value is not a string".into())
        })?;
        if key.trim().is_empty() || value.trim().is_empty() {
            return Err(BillingLedgerError::InvalidWebhookPayload(
                "metadata contains an empty value".into(),
            ));
        }
        metadata.insert(key.clone(), value.to_owned());
    }
    Ok(metadata)
}

#[allow(
    clippy::too_many_lines,
    reason = "the provider event matrix is kept in one auditable typed parser"
)]
fn parse_payload(
    event_type: StripeWebhookEventType,
    object: &serde_json::Map<String, Value>,
    livemode: bool,
) -> Result<StripeBillingFactPayload, BillingLedgerError> {
    match event_type {
        StripeWebhookEventType::CustomerCreated
        | StripeWebhookEventType::CustomerUpdated
        | StripeWebhookEventType::CustomerDeleted => Ok(StripeBillingFactPayload::Customer {
            customer_id: required_string(object, "id")?,
            livemode,
            deleted: object
                .get("deleted")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        StripeWebhookEventType::SubscriptionCreated
        | StripeWebhookEventType::SubscriptionUpdated
        | StripeWebhookEventType::SubscriptionDeleted => {
            let status = parse_subscription_status(
                object
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("canceled"),
            )?;
            Ok(StripeBillingFactPayload::Subscription {
                subscription_id: required_string(object, "id")?,
                customer_id: required_string(object, "customer")?,
                status,
                price_id: object
                    .get("items")
                    .and_then(Value::as_object)
                    .and_then(|items| items.get("data"))
                    .and_then(Value::as_array)
                    .and_then(|items| items.first())
                    .and_then(Value::as_object)
                    .and_then(|item| item.get("price"))
                    .and_then(Value::as_object)
                    .and_then(|price| price.get("id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                current_period_start: stripe_time(required_i64(object, "current_period_start")?)?,
                current_period_end: stripe_time(required_i64(object, "current_period_end")?)?,
                cancel_at_period_end: object
                    .get("cancel_at_period_end")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        }
        StripeWebhookEventType::CheckoutSessionCompleted => {
            let amount = parse_optional_money(object, "amount_total")?;
            Ok(StripeBillingFactPayload::ProviderAccepted {
                session_id: required_string(object, "id")?,
                customer_id: object
                    .get("customer")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                payment_status: object
                    .get("payment_status")
                    .and_then(Value::as_str)
                    .map(parse_checkout_payment_status)
                    .transpose()?,
                amount,
            })
        }
        StripeWebhookEventType::InvoiceFinalized
        | StripeWebhookEventType::InvoicePaid
        | StripeWebhookEventType::InvoicePaymentFailed
        | StripeWebhookEventType::InvoiceVoided => {
            let status = match event_type {
                StripeWebhookEventType::InvoicePaid => StripeInvoiceStatus::Paid,
                StripeWebhookEventType::InvoicePaymentFailed
                | StripeWebhookEventType::InvoiceFinalized => StripeInvoiceStatus::Open,
                StripeWebhookEventType::InvoiceVoided => StripeInvoiceStatus::Void,
                _ => unreachable!("event type already matched"),
            };
            let currency = required_currency(object, "currency")?;
            Ok(StripeBillingFactPayload::Invoice {
                invoice_id: required_string(object, "id")?,
                customer_id: object
                    .get("customer")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                subscription_id: object
                    .get("subscription")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                status,
                amount_due: Money::new(required_i64(object, "amount_due")?, currency.clone()),
                amount_paid: Money::new(required_i64(object, "amount_paid")?, currency),
                payment_intent_id: object
                    .get("payment_intent")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            })
        }
        StripeWebhookEventType::PaymentIntentProcessing
        | StripeWebhookEventType::PaymentIntentSucceeded
        | StripeWebhookEventType::PaymentIntentFailed
        | StripeWebhookEventType::PaymentIntentCanceled => {
            let status = match event_type {
                StripeWebhookEventType::PaymentIntentProcessing => StripePaymentStatus::Processing,
                StripeWebhookEventType::PaymentIntentSucceeded => StripePaymentStatus::Succeeded,
                StripeWebhookEventType::PaymentIntentFailed => StripePaymentStatus::Failed,
                StripeWebhookEventType::PaymentIntentCanceled => StripePaymentStatus::Canceled,
                _ => unreachable!("event type already matched"),
            };
            Ok(StripeBillingFactPayload::Payment {
                payment_intent_id: required_string(object, "id")?,
                customer_id: object
                    .get("customer")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                invoice_id: object
                    .get("invoice")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                amount: parse_money(object, "amount")?,
                status,
            })
        }
        StripeWebhookEventType::CreditTransactionCreated
        | StripeWebhookEventType::CreditGrantCreated
        | StripeWebhookEventType::CreditGrantUpdated
        | StripeWebhookEventType::CreditGrantExpired => {
            let raw_amount = required_i64(object, "amount")?;
            let direction = if raw_amount < 0 {
                StripeCreditDirection::Grant
            } else {
                StripeCreditDirection::Debit
            };
            let amount = Money::new(
                raw_amount
                    .checked_abs()
                    .ok_or(BillingLedgerError::AmountOverflow)?,
                required_currency(object, "currency")?,
            );
            Ok(StripeBillingFactPayload::Credit {
                credit_id: required_string(object, "id")?,
                customer_id: required_string(object, "customer")?,
                amount,
                direction,
                expires_at: optional_i64(object, "expires_at")
                    .map(stripe_time)
                    .transpose()?,
            })
        }
        StripeWebhookEventType::RefundCreated
        | StripeWebhookEventType::RefundUpdated
        | StripeWebhookEventType::ChargeRefunded => Ok(StripeBillingFactPayload::Refund {
            refund_id: required_string(object, "id")?,
            payment_intent_id: object
                .get("payment_intent")
                .and_then(Value::as_str)
                .map(str::to_owned),
            charge_id: object
                .get("charge")
                .and_then(Value::as_str)
                .map(str::to_owned),
            amount: parse_money(object, "amount")?,
            status: parse_refund_status(
                object
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("succeeded"),
            )?,
        }),
        StripeWebhookEventType::DisputeCreated | StripeWebhookEventType::DisputeClosed => {
            let status = if matches!(event_type, StripeWebhookEventType::DisputeCreated) {
                parse_dispute_status(
                    object
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("under_review"),
                )?
            } else {
                parse_dispute_status(
                    object
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("won"),
                )?
            };
            Ok(StripeBillingFactPayload::Dispute {
                dispute_id: required_string(object, "id")?,
                charge_id: required_string(object, "charge")?,
                amount: parse_money(object, "amount")?,
                status,
            })
        }
        StripeWebhookEventType::PayoutCreated
        | StripeWebhookEventType::PayoutPaid
        | StripeWebhookEventType::PayoutFailed
        | StripeWebhookEventType::PayoutCanceled => {
            let status = match event_type {
                StripeWebhookEventType::PayoutCreated => StripePayoutStatus::Pending,
                StripeWebhookEventType::PayoutPaid => StripePayoutStatus::Paid,
                StripeWebhookEventType::PayoutFailed => StripePayoutStatus::Failed,
                StripeWebhookEventType::PayoutCanceled => StripePayoutStatus::Canceled,
                _ => unreachable!("event type already matched"),
            };
            Ok(StripeBillingFactPayload::Payout {
                payout_id: required_string(object, "id")?,
                connected_account_id: object
                    .get("destination")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                amount: parse_money(object, "amount")?,
                status,
                arrival_at: optional_i64(object, "arrival_date")
                    .map(stripe_time)
                    .transpose()?,
            })
        }
    }
}

fn parse_money(
    object: &serde_json::Map<String, Value>,
    amount_field: &str,
) -> Result<Money, BillingLedgerError> {
    Ok(Money::new(
        required_i64(object, amount_field)?,
        required_currency(object, "currency")?,
    ))
}

fn parse_optional_money(
    object: &serde_json::Map<String, Value>,
    amount_field: &str,
) -> Result<Option<Money>, BillingLedgerError> {
    let Some(amount) = object.get(amount_field) else {
        return Ok(None);
    };
    let amount = amount.as_i64().ok_or_else(|| {
        BillingLedgerError::InvalidWebhookPayload(format!("{amount_field} is not an integer"))
    })?;
    let currency = object
        .get("currency")
        .and_then(Value::as_str)
        .map(parse_currency)
        .transpose()?;
    match currency {
        Some(currency) => Ok(Some(Money::new(amount, currency))),
        None if amount == 0 => Ok(None),
        None => Err(BillingLedgerError::MissingWebhookField("currency".into())),
    }
}

fn required_currency(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<CurrencyCode, BillingLedgerError> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| BillingLedgerError::MissingWebhookField(field.into()))?;
    parse_currency(value)
}

fn parse_currency(value: &str) -> Result<CurrencyCode, BillingLedgerError> {
    CurrencyCode::parse(value.to_ascii_uppercase()).map_err(|_| BillingLedgerError::InvalidFact)
}

fn parse_subscription_status(value: &str) -> Result<StripeSubscriptionStatus, BillingLedgerError> {
    match value {
        "incomplete" => Ok(StripeSubscriptionStatus::Incomplete),
        "incomplete_expired" => Ok(StripeSubscriptionStatus::IncompleteExpired),
        "trialing" => Ok(StripeSubscriptionStatus::Trialing),
        "active" => Ok(StripeSubscriptionStatus::Active),
        "past_due" => Ok(StripeSubscriptionStatus::PastDue),
        "canceled" => Ok(StripeSubscriptionStatus::Canceled),
        "unpaid" => Ok(StripeSubscriptionStatus::Unpaid),
        "paused" => Ok(StripeSubscriptionStatus::Paused),
        other => Err(BillingLedgerError::InvalidStripeState(other.into())),
    }
}

fn parse_checkout_payment_status(
    value: &str,
) -> Result<StripeCheckoutPaymentStatus, BillingLedgerError> {
    match value {
        "paid" => Ok(StripeCheckoutPaymentStatus::Paid),
        "unpaid" => Ok(StripeCheckoutPaymentStatus::Unpaid),
        "no_payment_required" => Ok(StripeCheckoutPaymentStatus::NoPaymentRequired),
        other => Err(BillingLedgerError::InvalidStripeState(other.into())),
    }
}

fn parse_refund_status(value: &str) -> Result<StripeRefundStatus, BillingLedgerError> {
    match value {
        "pending" => Ok(StripeRefundStatus::Pending),
        "succeeded" => Ok(StripeRefundStatus::Succeeded),
        "failed" => Ok(StripeRefundStatus::Failed),
        "canceled" => Ok(StripeRefundStatus::Canceled),
        other => Err(BillingLedgerError::InvalidStripeState(other.into())),
    }
}

fn parse_dispute_status(value: &str) -> Result<StripeDisputeStatus, BillingLedgerError> {
    match value {
        "needs_response" => Ok(StripeDisputeStatus::NeedsResponse),
        "under_review" => Ok(StripeDisputeStatus::UnderReview),
        "won" => Ok(StripeDisputeStatus::Won),
        "lost" => Ok(StripeDisputeStatus::Lost),
        other => Err(BillingLedgerError::InvalidStripeState(other.into())),
    }
}

fn fact_digest(
    fact_id: &str,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    source: &StripeFactSource,
    observed_at: DateTime<Utc>,
    payload: &StripeBillingFactPayload,
) -> Result<String, BillingLedgerError> {
    let payload =
        serde_json::to_vec(payload).map_err(|_| BillingLedgerError::LedgerIntegrityFailure)?;
    let source =
        serde_json::to_vec(source).map_err(|_| BillingLedgerError::LedgerIntegrityFailure)?;
    let mut digest = Sha256::new();
    hash_field(&mut digest, STRIPE_BILLING_CONTRACT_VERSION);
    hash_field(&mut digest, fact_id);
    hash_field(&mut digest, tenant_id.as_str());
    hash_field(&mut digest, project_id.as_str());
    hash_field(&mut digest, &String::from_utf8_lossy(&source));
    hash_field(&mut digest, &observed_at.to_rfc3339());
    digest.update(payload);
    Ok(format!("{:x}", digest.finalize()))
}

fn hash_field(digest: &mut Sha256, value: &str) {
    digest.update(value.len().to_be_bytes());
    digest.update(value.as_bytes());
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK_SIZE: usize = 64;
    let mut normalized_key = [0_u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        normalized_key[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK_SIZE];
    let mut outer_pad = [0x5c_u8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        inner_pad[index] ^= normalized_key[index];
        outer_pad[index] ^= normalized_key[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    format!("{:x}", outer.finalize())
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.bytes().zip(right.bytes()) {
        difference |= left ^ right;
    }
    difference == 0
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    const FIXTURE_SECRET: &str = "whsec_money01_fixture";
    const FIXTURE_BODY: &str = include_str!(
        "../../../contracts/providers/stripe-fixtures/checkout-session-completed.json"
    );

    fn fixture_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 2, 0, 0)
            .single()
            .expect("fixture time")
    }

    #[test]
    fn stripe_requests_are_real_deterministic_form_contracts() {
        let tenant = TenantId::from("tenant-money");
        let project = ProjectId::from("project-money");
        let request = StripeBillingRequest::create_subscription(
            &tenant,
            &project,
            "cus_money",
            "price_money",
            1,
            "money-subscription-1",
        )
        .expect("subscription request");
        assert_eq!(request.path, "/v1/subscriptions");
        assert!(request.form_body.contains("customer=cus_money"));
        assert!(
            request
                .form_body
                .contains("items%5B0%5D%5Bprice%5D=price_money")
        );
        assert!(
            request
                .form_body
                .contains("metadata%5Bhartevo_project_id%5D=project-money")
        );
        assert_eq!(request.request_digest.len(), 64);
        let customer = StripeBillingRequest::create_customer(&tenant, &project, "money-customer-1")
            .expect("customer request");
        assert_eq!(customer.path, "/v1/customers");
        let credit = StripeBillingRequest::create_credit_adjustment(
            &tenant,
            &project,
            "cus_money",
            &Money::new(400, CurrencyCode::parse("USD").expect("USD")),
            StripeCreditDirection::Grant,
            "Mission credits",
            "money-credit-1",
        )
        .expect("credit request");
        assert_eq!(credit.path, "/v1/customers/cus_money/balance_transactions");
        assert!(credit.form_body.contains("amount=-400"));
        assert!(credit.form_body.contains("currency=usd"));
    }

    #[test]
    fn signed_checkout_fixture_is_provider_acceptance_not_paid() {
        let now = fixture_now();
        let signature = format!(
            "t={},v1={}",
            now.timestamp(),
            hmac_sha256_hex(
                FIXTURE_SECRET.as_bytes(),
                format!("{}.{}", now.timestamp(), FIXTURE_BODY).as_bytes(),
            )
        );
        let verified = verify_stripe_webhook(
            FIXTURE_BODY,
            &signature,
            FIXTURE_SECRET,
            now,
            Duration::seconds(300),
        )
        .expect("signed fixture");
        let scoped = verified
            .bind_scope(
                TenantId::from("tenant-money"),
                ProjectId::from("project-money"),
            )
            .expect("scope");
        let fact = scoped.fact().expect("fact");
        assert_eq!(fact.kind, StripeBillingFactKind::ProviderAccepted);
        assert!(!fact.is_independently_settled());
        assert!(!fact.payload.is_explicit_paid_or_settled());
    }

    #[test]
    fn webhook_replay_is_idempotent_but_payload_swap_is_not() {
        let now = fixture_now();
        let signature = format!(
            "t={},v1={}",
            now.timestamp(),
            hmac_sha256_hex(
                FIXTURE_SECRET.as_bytes(),
                format!("{}.{}", now.timestamp(), FIXTURE_BODY).as_bytes(),
            )
        );
        let webhook = verify_stripe_webhook(
            FIXTURE_BODY,
            &signature,
            FIXTURE_SECRET,
            now,
            Duration::seconds(300),
        )
        .expect("signed fixture")
        .bind_scope(
            TenantId::from("tenant-money"),
            ProjectId::from("project-money"),
        )
        .expect("scope");
        let mut ledger = StripeBillingLedger::default();
        assert!(matches!(
            ledger.ingest_webhook(&webhook),
            Ok(BillingLedgerIngest::Applied { .. })
        ));
        assert!(matches!(
            ledger.ingest_webhook(&webhook),
            Ok(BillingLedgerIngest::Replayed { .. })
        ));
        assert_eq!(ledger.revision, 1);
    }

    #[test]
    fn payout_paid_requires_reconciliation_source_for_settlement() {
        let payload = StripeBillingFactPayload::Payout {
            payout_id: "po_money".into(),
            connected_account_id: Some("acct_creator".into()),
            amount: Money::new(10_000, CurrencyCode::parse("USD").expect("USD")),
            status: StripePayoutStatus::Paid,
            arrival_at: None,
        };
        let webhook_fact = StripeBillingFact::new(
            "stripe-event:payout",
            TenantId::from("tenant-money"),
            ProjectId::from("project-money"),
            StripeFactSource::Webhook {
                event_id: "evt_payout".into(),
                signature_digest: "a".repeat(64),
                received_at: fixture_now(),
            },
            fixture_now(),
            payload.clone(),
        )
        .expect("webhook fact");
        assert!(!webhook_fact.is_independently_settled());
        let reconciled = StripeBillingFact::new(
            "reconciliation:payout",
            TenantId::from("tenant-money"),
            ProjectId::from("project-money"),
            StripeFactSource::Reconciliation {
                request_id: "reconcile_payout".into(),
                readback_digest: "b".repeat(64),
                observed_at: fixture_now(),
            },
            fixture_now(),
            payload,
        )
        .expect("reconciliation fact");
        assert!(reconciled.is_independently_settled());
    }
}
