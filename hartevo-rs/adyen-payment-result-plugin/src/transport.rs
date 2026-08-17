use std::{
    fmt,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

use crate::error::AdyenPaymentTransportError;
use crate::model::{
    AdyenPaymentApiRecord, AdyenPaymentReadMode, AdyenPaymentScope, ProviderProvenance,
};
use crate::{MAX_RESPONSE_BYTES, MAX_RETRY_ATTEMPTS};

/// API-key bytes are available only for one provider call and are never
/// serializable or recoverable through Debug.
#[derive(Clone)]
pub struct SecretMaterial(Zeroizing<String>);

impl SecretMaterial {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMaterial(<redacted>)")
    }
}

/// The only provider capability surface: bounded GET-shaped metadata reads.
/// There are no methods for payment effects, webhooks, instruments, PII, or
/// raw response retrieval.
pub trait AdyenPaymentTransport: fmt::Debug + Send + Sync {
    fn provenance(&self) -> ProviderProvenance;

    fn retrieve_payment(
        &self,
        credential: &SecretMaterial,
        scope: &AdyenPaymentScope,
        mode: AdyenPaymentReadMode,
    ) -> Result<AdyenPaymentApiRecord, AdyenPaymentTransportError>;

    fn read_payment_status(
        &self,
        credential: &SecretMaterial,
        scope: &AdyenPaymentScope,
        mode: AdyenPaymentReadMode,
    ) -> Result<AdyenPaymentApiRecord, AdyenPaymentTransportError>;
}

pub type AdyenApiTransport = UreqAdyenTransport;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdyenTransportOperation {
    RetrievePayment,
    ReadPaymentStatus,
}

/// Deterministic recording, fixture, fake, loopback, and BLOCKED_ENV seam.
/// Every non-official provenance remains non-native and non-Connected.
#[derive(Clone)]
pub struct AdyenRecordingTransport {
    payment: Arc<Mutex<AdyenPaymentApiRecord>>,
    status: Arc<Mutex<AdyenPaymentApiRecord>>,
    provenance: ProviderProvenance,
    fault: Arc<Mutex<Option<AdyenPaymentTransportError>>>,
    operations: Arc<Mutex<Vec<AdyenTransportOperation>>>,
}

impl fmt::Debug for AdyenRecordingTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdyenRecordingTransport")
            .field("provenance", &self.provenance)
            .field("operations", &self.operations().len())
            .finish_non_exhaustive()
    }
}

impl AdyenRecordingTransport {
    pub fn new(
        payment: AdyenPaymentApiRecord,
        status: AdyenPaymentApiRecord,
        provenance: ProviderProvenance,
    ) -> Self {
        assert!(matches!(
            provenance,
            ProviderProvenance::Recording
                | ProviderProvenance::Fake
                | ProviderProvenance::Fixture
                | ProviderProvenance::Loopback
                | ProviderProvenance::BlockedEnv
        ));
        Self {
            payment: Arc::new(Mutex::new(payment)),
            status: Arc::new(Mutex::new(status)),
            provenance,
            fault: Arc::new(Mutex::new(None)),
            operations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn recording(payment: AdyenPaymentApiRecord) -> Self {
        Self::new(payment.clone(), payment, ProviderProvenance::Recording)
    }

    pub fn recording_with_status(
        payment: AdyenPaymentApiRecord,
        status: AdyenPaymentApiRecord,
    ) -> Self {
        Self::new(payment, status, ProviderProvenance::Recording)
    }

    pub fn fake(payment: AdyenPaymentApiRecord) -> Self {
        Self::new(payment.clone(), payment, ProviderProvenance::Fake)
    }

    pub fn fixture(payment: AdyenPaymentApiRecord) -> Self {
        Self::new(payment.clone(), payment, ProviderProvenance::Fixture)
    }

    pub fn loopback(payment: AdyenPaymentApiRecord) -> Self {
        Self::new(payment.clone(), payment, ProviderProvenance::Loopback)
    }

    pub fn blocked_env(payment: AdyenPaymentApiRecord) -> Self {
        Self::new(payment.clone(), payment, ProviderProvenance::BlockedEnv)
    }

    pub fn set_payment(&self, payment: AdyenPaymentApiRecord) {
        if let Ok(mut value) = self.payment.lock() {
            *value = payment;
        }
    }

    pub fn set_status(&self, status: AdyenPaymentApiRecord) {
        if let Ok(mut value) = self.status.lock() {
            *value = status;
        }
    }

    pub fn set_fault(&self, fault: AdyenPaymentTransportError) {
        if let Ok(mut value) = self.fault.lock() {
            *value = Some(fault);
        }
    }

    pub fn clear_fault(&self) {
        if let Ok(mut value) = self.fault.lock() {
            *value = None;
        }
    }

    pub fn operations(&self) -> Vec<AdyenTransportOperation> {
        self.operations
            .lock()
            .map_or_else(|_| Vec::new(), |operations| operations.clone())
    }

    fn before_call(
        &self,
        operation: AdyenTransportOperation,
        credential: &SecretMaterial,
    ) -> Result<(), AdyenPaymentTransportError> {
        self.operations
            .lock()
            .map_err(|_| AdyenPaymentTransportError::Network)?
            .push(operation);
        if credential.as_str().trim().is_empty()
            || credential.as_str().chars().any(char::is_control)
        {
            return Err(AdyenPaymentTransportError::Unauthorized);
        }
        self.fault
            .lock()
            .map_err(|_| AdyenPaymentTransportError::Network)?
            .clone()
            .map_or(Ok(()), Err)
    }
}

impl AdyenPaymentTransport for AdyenRecordingTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn retrieve_payment(
        &self,
        credential: &SecretMaterial,
        _scope: &AdyenPaymentScope,
        _mode: AdyenPaymentReadMode,
    ) -> Result<AdyenPaymentApiRecord, AdyenPaymentTransportError> {
        self.before_call(AdyenTransportOperation::RetrievePayment, credential)?;
        self.payment
            .lock()
            .map_err(|_| AdyenPaymentTransportError::Network)
            .map(|payment| payment.clone())
    }

    fn read_payment_status(
        &self,
        credential: &SecretMaterial,
        _scope: &AdyenPaymentScope,
        _mode: AdyenPaymentReadMode,
    ) -> Result<AdyenPaymentApiRecord, AdyenPaymentTransportError> {
        self.before_call(AdyenTransportOperation::ReadPaymentStatus, credential)?;
        self.status
            .lock()
            .map_err(|_| AdyenPaymentTransportError::Network)
            .map(|status| status.clone())
    }
}

pub type FakeAdyenTransport = AdyenRecordingTransport;
pub type LoopbackAdyenTransport = AdyenRecordingTransport;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub initial_backoff_ms: u64,
}

impl RetryPolicy {
    pub const fn bounded() -> Self {
        Self {
            max_attempts: MAX_RETRY_ATTEMPTS,
            initial_backoff_ms: 25,
        }
    }

    pub fn new(
        max_attempts: u8,
        initial_backoff_ms: u64,
    ) -> Result<Self, crate::AdyenPaymentResultError> {
        if max_attempts == 0 || max_attempts > MAX_RETRY_ATTEMPTS {
            return Err(crate::AdyenPaymentResultError::InvalidInput {
                field: "retry policy",
                reason: "attempts must be between one and three",
            });
        }
        Ok(Self {
            max_attempts,
            initial_backoff_ms,
        })
    }

    fn delay_for_attempt(self, attempt: u8) -> Duration {
        let exponent = u32::from(attempt.saturating_sub(1)).min(4);
        Duration::from_millis(self.initial_backoff_ms.saturating_mul(1_u64 << exponent))
    }
}

/// Official Adyen Checkout GET transport. It is a typed Layer-1 seam; the
/// default environment resolver remains BLOCKED_ENV and provenance never
/// upgrades evidence to Connected/native.
pub struct UreqAdyenTransport {
    base_url: String,
    agent: ureq::Agent,
    retry_policy: RetryPolicy,
    provenance: ProviderProvenance,
}

impl fmt::Debug for UreqAdyenTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UreqAdyenTransport")
            .field("base_url_digest", &crate::Digest::from_text(&self.base_url))
            .field("retry_policy", &self.retry_policy)
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

impl UreqAdyenTransport {
    pub fn new(base_url: impl Into<String>) -> Result<Self, crate::AdyenPaymentResultError> {
        Self::build(&base_url.into(), false)
    }

    pub fn new_loopback(
        base_url: impl Into<String>,
    ) -> Result<Self, crate::AdyenPaymentResultError> {
        Self::build(&base_url.into(), true)
    }

    #[must_use]
    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn build(base_url: &str, loopback: bool) -> Result<Self, crate::AdyenPaymentResultError> {
        let base_url = base_url.trim_end_matches('/').to_owned();
        let parsed =
            Url::parse(&base_url).map_err(|_| crate::AdyenPaymentResultError::InvalidInput {
                field: "Adyen API base URL",
                reason: "must be an exact HTTPS or loopback URL",
            })?;
        let host = parsed
            .host_str()
            .ok_or(crate::AdyenPaymentResultError::InvalidConfiguration)?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(crate::AdyenPaymentResultError::InvalidInput {
                field: "Adyen API base URL",
                reason: "must not contain credentials, query, or fragment",
            });
        }
        if loopback {
            if parsed.scheme() != "http" || !is_loopback_host(host) {
                return Err(crate::AdyenPaymentResultError::InvalidInput {
                    field: "Adyen loopback URL",
                    reason: "must be an HTTP loopback endpoint",
                });
            }
        } else if parsed.scheme() != "https" || !is_official_adyen_host(host) {
            return Err(crate::AdyenPaymentResultError::InvalidInput {
                field: "Adyen API base URL",
                reason: "must use HTTPS with an official Adyen host",
            });
        }
        let agent = ureq::Agent::config_builder()
            .user_agent("hartevo-adyen-payment-result/1")
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        Ok(Self {
            base_url,
            agent,
            retry_policy: RetryPolicy::bounded(),
            provenance: if loopback {
                ProviderProvenance::Loopback
            } else {
                ProviderProvenance::OfficialHttps
            },
        })
    }

    fn endpoint(&self, segments: &[&str]) -> Result<String, AdyenPaymentTransportError> {
        let mut url = Url::parse(&self.base_url)
            .map_err(|_| AdyenPaymentTransportError::InvalidConfiguration)?;
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| AdyenPaymentTransportError::InvalidConfiguration)?;
            for segment in segments {
                path.push(segment);
            }
        }
        Ok(url.to_string())
    }

    fn get_json(
        &self,
        credential: &SecretMaterial,
        url: &str,
    ) -> Result<Value, AdyenPaymentTransportError> {
        let mut attempt = 1;
        loop {
            let request = self
                .agent
                .get(url)
                .header("X-API-Key", credential.as_str())
                .header("Accept", "application/json")
                .header("X-Hartevo-Client", "hartevo-adyen-payment-result/1");
            match request.call() {
                Ok(mut response) => {
                    if response
                        .body()
                        .content_length()
                        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
                    {
                        return Err(AdyenPaymentTransportError::ResponseTooLarge);
                    }
                    let body = response
                        .body_mut()
                        .with_config()
                        .limit((MAX_RESPONSE_BYTES as u64).saturating_add(1))
                        .read_to_vec()
                        .map_err(|error| match error {
                            ureq::Error::BodyExceedsLimit(_) => {
                                AdyenPaymentTransportError::ResponseTooLarge
                            }
                            _ => AdyenPaymentTransportError::Network,
                        })?;
                    if body.len() > MAX_RESPONSE_BYTES {
                        return Err(AdyenPaymentTransportError::ResponseTooLarge);
                    }
                    return serde_json::from_slice(&body)
                        .map_err(|_| AdyenPaymentTransportError::Decode);
                }
                Err(error) => {
                    let classified = classify_http_error(&error);
                    if !is_retryable(&classified) || attempt >= self.retry_policy.max_attempts {
                        return Err(classified);
                    }
                    let delay = self.retry_policy.delay_for_attempt(attempt);
                    if !delay.is_zero() {
                        thread::sleep(delay);
                    }
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }
}

impl AdyenPaymentTransport for UreqAdyenTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn retrieve_payment(
        &self,
        credential: &SecretMaterial,
        scope: &AdyenPaymentScope,
        _mode: AdyenPaymentReadMode,
    ) -> Result<AdyenPaymentApiRecord, AdyenPaymentTransportError> {
        let url = self.endpoint(&["paymentLinks", scope.payment_reference.as_str()])?;
        let document = self.get_json(credential, &url)?;
        parse_payment_record(&document, scope)
    }

    fn read_payment_status(
        &self,
        credential: &SecretMaterial,
        scope: &AdyenPaymentScope,
        _mode: AdyenPaymentReadMode,
    ) -> Result<AdyenPaymentApiRecord, AdyenPaymentTransportError> {
        let url = self.endpoint(&["sessions", scope.payment_reference.as_str()])?;
        let document = self.get_json(credential, &url)?;
        parse_payment_record(&document, scope)
    }
}

fn parse_payment_record(
    value: &Value,
    scope: &AdyenPaymentScope,
) -> Result<AdyenPaymentApiRecord, AdyenPaymentTransportError> {
    let merchant_account = optional_string(value, "merchantAccount")
        .unwrap_or_else(|| scope.merchant_account.as_str().to_owned());
    let account_id = optional_string(value, "accountId")
        .or_else(|| optional_string(value, "balancePlatform"))
        .unwrap_or_else(|| scope.account_id.as_str().to_owned());
    let payment_reference = optional_string(value, "reference")
        .or_else(|| optional_string(value, "pspReference"))
        .or_else(|| optional_string(value, "id"))
        .unwrap_or_else(|| scope.payment_reference.as_str().to_owned());
    let (amount_minor_units, currency) = value
        .get("amount")
        .and_then(Value::as_object)
        .map(|amount| {
            (
                amount
                    .get("value")
                    .and_then(Value::as_i64)
                    .unwrap_or(scope.amount.value_minor_units),
                amount
                    .get("currency")
                    .and_then(Value::as_str)
                    .unwrap_or(scope.amount.currency.as_str())
                    .to_owned(),
            )
        })
        .unwrap_or((
            scope.amount.value_minor_units,
            scope.amount.currency.as_str().to_owned(),
        ));
    let status = optional_string(value, "status")
        .or_else(|| optional_string(value, "resultCode"))
        .unwrap_or_else(|| "unknown".to_owned());
    let result_code = optional_string(value, "resultCode");
    let customer_fingerprint_digest = value
        .get("shopperReference")
        .and_then(Value::as_str)
        .map(crate::Digest::from_text);
    let payment_method_digest = value
        .get("paymentMethod")
        .and_then(|method| method.get("type"))
        .and_then(Value::as_str)
        .map(crate::Digest::from_text);
    Ok(AdyenPaymentApiRecord {
        merchant_account,
        account_id,
        payment_reference,
        amount_minor_units,
        currency,
        status,
        result_code,
        customer_fingerprint_digest,
        payment_method_digest,
        created_at: optional_string(value, "createdAt"),
        updated_at: optional_string(value, "updatedAt")
            .or_else(|| optional_string(value, "expiresAt")),
        reconciliation_reference: optional_string(value, "pspReference"),
    })
}

fn optional_string(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn is_retryable(error: &AdyenPaymentTransportError) -> bool {
    matches!(
        error,
        AdyenPaymentTransportError::Conflict
            | AdyenPaymentTransportError::RateLimited { .. }
            | AdyenPaymentTransportError::Timeout
            | AdyenPaymentTransportError::ServerUnavailable
            | AdyenPaymentTransportError::Network
    )
}

fn classify_http_error(error: &ureq::Error) -> AdyenPaymentTransportError {
    match error {
        ureq::Error::StatusCode(status) => match *status {
            401 => AdyenPaymentTransportError::Unauthorized,
            403 => AdyenPaymentTransportError::Forbidden,
            404 => AdyenPaymentTransportError::NotFoundOrUnauthorized,
            409 => AdyenPaymentTransportError::Conflict,
            429 => AdyenPaymentTransportError::RateLimited {
                retry_after_seconds: None,
            },
            408 => AdyenPaymentTransportError::Timeout,
            500..=599 => AdyenPaymentTransportError::ServerUnavailable,
            _ => AdyenPaymentTransportError::Network,
        },
        _ => AdyenPaymentTransportError::Network,
    }
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn is_official_adyen_host(host: &str) -> bool {
    host == "checkout-test.adyen.com"
        || host == "checkout-live.adyen.com"
        || host.ends_with("-checkout-live.adyen.com")
}
