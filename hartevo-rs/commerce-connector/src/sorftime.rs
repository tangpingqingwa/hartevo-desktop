//! Sorftime estimate-only API and CLI transport seam.
//!
//! Sorftime is intentionally modeled as a distinct estimate type.  There is
//! no conversion from `SorftimeEstimateObservation` to a first-party record;
//! an Application service must keep the two provenance classes separate when
//! building a VM-07/VM-08 work product.

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::CurrencyCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::canonical::{
    Asin, CanonicalIdentityError, CanonicalMoney, CanonicalTime, MarketId, MarketIdentity,
};

pub const SORFTIME_PROVIDER_ID: &str = "sorftime";
pub const SORFTIME_API_HOST: &str = "open.sorftime.com";
pub const SORFTIME_ESTIMATE_AUTHORITY: &str = "estimate_only";
pub const SORFTIME_ESTIMATE_EVIDENCE_LEVEL: &str = "E1";
pub const SORFTIME_LIVE_VALIDATION_STATUS: &str = "BLOCKED_ENV";

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SorftimeAccountId(String);

impl SorftimeAccountId {
    pub fn parse(value: impl Into<String>) -> Result<Self, SorftimeError> {
        let value = value.into();
        validate_token(&value, "Sorftime account")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SorftimeCredentialReference(String);

impl SorftimeCredentialReference {
    /// Store only a vault/keychain reference; never put Sorftime secrets in the adapter model.
    pub fn parse(value: impl Into<String>) -> Result<Self, SorftimeError> {
        let value = value.into();
        validate_token(&value, "Sorftime credential reference")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SorftimeAuthStatus {
    Disconnected,
    BlockedEnv,
    CredentialReferenceOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SorftimeBlockedEnvReason {
    CredentialsUnavailable,
    NetworkUnavailable,
    ProviderUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SorftimeAuthState {
    Disconnected {
        observed_at: CanonicalTime,
    },
    BlockedEnv {
        observed_at: CanonicalTime,
        reason: SorftimeBlockedEnvReason,
    },
    CredentialReferenceOnly {
        observed_at: CanonicalTime,
        credential: SorftimeCredentialReference,
    },
}

impl SorftimeAuthState {
    pub fn disconnected(observed_at: DateTime<Utc>) -> Self {
        Self::Disconnected {
            observed_at: CanonicalTime::from_datetime(observed_at),
        }
    }

    pub fn no_credentials(observed_at: DateTime<Utc>) -> Self {
        Self::blocked_env(
            observed_at,
            SorftimeBlockedEnvReason::CredentialsUnavailable,
        )
    }

    pub fn blocked_env(observed_at: DateTime<Utc>, reason: SorftimeBlockedEnvReason) -> Self {
        Self::BlockedEnv {
            observed_at: CanonicalTime::from_datetime(observed_at),
            reason,
        }
    }

    pub fn credential_reference_only(
        observed_at: DateTime<Utc>,
        credential: SorftimeCredentialReference,
    ) -> Self {
        Self::CredentialReferenceOnly {
            observed_at: CanonicalTime::from_datetime(observed_at),
            credential,
        }
    }

    pub fn status(&self) -> SorftimeAuthStatus {
        match self {
            Self::Disconnected { .. } => SorftimeAuthStatus::Disconnected,
            Self::BlockedEnv { .. } => SorftimeAuthStatus::BlockedEnv,
            Self::CredentialReferenceOnly { .. } => SorftimeAuthStatus::CredentialReferenceOnly,
        }
    }

    pub fn observed_at(&self) -> &CanonicalTime {
        match self {
            Self::Disconnected { observed_at }
            | Self::BlockedEnv { observed_at, .. }
            | Self::CredentialReferenceOnly { observed_at, .. } => observed_at,
        }
    }

    pub fn credential(&self) -> Option<&SorftimeCredentialReference> {
        match self {
            Self::CredentialReferenceOnly { credential, .. } => Some(credential),
            Self::Disconnected { .. } | Self::BlockedEnv { .. } => None,
        }
    }

    /// A reference alone is not a live credential and cannot establish a connected state.
    pub const fn can_issue_live_read(&self) -> bool {
        false
    }

    pub const fn grants_connected_authority(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeMarket {
    pub market_id: MarketId,
    pub locale: String,
    pub currency: CurrencyCode,
}

impl SorftimeMarket {
    pub fn new(
        market_id: MarketId,
        locale: impl Into<String>,
        currency: CurrencyCode,
    ) -> Result<Self, SorftimeError> {
        let locale = locale.into();
        if locale.len() < 2
            || locale.len() > 16
            || locale.trim() != locale
            || !locale
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(SorftimeError::InvalidLocale(locale));
        }
        Ok(Self {
            market_id,
            locale,
            currency,
        })
    }

    pub fn as_market_identity(&self) -> Result<MarketIdentity, SorftimeError> {
        Ok(MarketIdentity::new(
            self.market_id.clone(),
            Some(self.locale.clone()),
        )?)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SorftimeDataset {
    Product,
    ProductTrend,
    ProductRealtime,
    CategoryMarket,
    Keyword,
    ProductReviews,
}

impl SorftimeDataset {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::Product => "ProductRequest",
            Self::ProductTrend => "ProductTrend",
            Self::ProductRealtime => "ProductRealtimeRequest",
            Self::CategoryMarket => "CategoryRequest",
            Self::Keyword => "KeywordRequest",
            Self::ProductReviews => "ProductReviewsQuery",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SorftimeTransportKind {
    Api,
    Cli,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeRequestCost {
    pub units: u64,
    pub currency: Option<CurrencyCode>,
    pub pricing_source: String,
    pub observed_at: CanonicalTime,
}

impl SorftimeRequestCost {
    pub fn new(
        units: u64,
        currency: Option<CurrencyCode>,
        pricing_source: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, SorftimeError> {
        let pricing_source = pricing_source.into();
        if units == 0 || pricing_source.trim().is_empty() {
            return Err(SorftimeError::InvalidCostProvenance);
        }
        Ok(Self {
            units,
            currency,
            pricing_source,
            observed_at: CanonicalTime::from_datetime(observed_at),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeRequestProvenance {
    pub provider_id: String,
    pub authority: SorftimeEvidenceAuthority,
    pub evidence_level: String,
    pub request_id: String,
    pub account: SorftimeAccountId,
    pub market: SorftimeMarket,
    pub dataset: SorftimeDataset,
    pub transport: SorftimeTransportKind,
    pub request_digest: String,
    pub request_cost: SorftimeRequestCost,
}

impl SorftimeRequestProvenance {
    pub fn new(
        request_id: String,
        account: SorftimeAccountId,
        market: SorftimeMarket,
        dataset: SorftimeDataset,
        transport: SorftimeTransportKind,
        request_digest: String,
        request_cost: SorftimeRequestCost,
    ) -> Result<Self, SorftimeError> {
        if request_id.trim().is_empty()
            || request_digest.len() != 64
            || !request_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(SorftimeError::InvalidRequestProvenance);
        }
        Ok(Self {
            provider_id: SORFTIME_PROVIDER_ID.into(),
            authority: SorftimeEvidenceAuthority::EstimateOnly,
            evidence_level: SORFTIME_ESTIMATE_EVIDENCE_LEVEL.into(),
            request_id,
            account,
            market,
            dataset,
            transport,
            request_digest,
            request_cost,
        })
    }

    pub fn validate(&self) -> Result<(), SorftimeError> {
        if self.provider_id != SORFTIME_PROVIDER_ID
            || !matches!(self.authority, SorftimeEvidenceAuthority::EstimateOnly)
            || self.evidence_level != SORFTIME_ESTIMATE_EVIDENCE_LEVEL
            || self.request_id.trim().is_empty()
            || self.request_digest.len() != 64
            || !self
                .request_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(SorftimeError::InvalidRequestProvenance);
        }
        if self.request_cost.units == 0 || self.request_cost.pricing_source.trim().is_empty() {
            return Err(SorftimeError::InvalidCostProvenance);
        }
        Ok(())
    }

    pub fn is_estimate_only(&self) -> bool {
        self.provider_id == SORFTIME_PROVIDER_ID
            && matches!(self.authority, SorftimeEvidenceAuthority::EstimateOnly)
            && self.evidence_level == SORFTIME_ESTIMATE_EVIDENCE_LEVEL
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeApiRequest {
    pub endpoint: String,
    pub account: SorftimeAccountId,
    pub market: SorftimeMarket,
    pub dataset: SorftimeDataset,
    pub request_id: String,
    pub payload: Value,
}

impl SorftimeApiRequest {
    pub fn new(
        endpoint: impl Into<String>,
        account: SorftimeAccountId,
        market: SorftimeMarket,
        dataset: SorftimeDataset,
        request_id: impl Into<String>,
        payload: Value,
    ) -> Result<Self, SorftimeError> {
        let endpoint_string = endpoint.into();
        let endpoint = Url::parse(&endpoint_string)
            .map_err(|_| SorftimeError::InvalidApiEndpoint(endpoint_string.clone()))?;
        if endpoint.scheme() != "https"
            || endpoint.host_str() != Some(SORFTIME_API_HOST)
            || endpoint.username() != ""
            || endpoint.password().is_some()
        {
            return Err(SorftimeError::InvalidApiEndpoint(endpoint_string));
        }
        let request_id = request_id.into();
        validate_token(&request_id, "Sorftime request id")?;
        Ok(Self {
            endpoint: endpoint.to_string(),
            account,
            market,
            dataset,
            request_id,
            payload,
        })
    }

    pub fn request_digest(&self) -> Result<String, SorftimeError> {
        digest_request(
            self.dataset,
            &self.account,
            &self.market,
            &self.request_id,
            &self.payload,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeCliRequest {
    pub program: String,
    pub args: Vec<String>,
    pub account: SorftimeAccountId,
    pub market: SorftimeMarket,
    pub dataset: SorftimeDataset,
    pub request_id: String,
    pub payload: Value,
}

impl SorftimeCliRequest {
    pub fn new(
        account: SorftimeAccountId,
        market: SorftimeMarket,
        dataset: SorftimeDataset,
        request_id: impl Into<String>,
        payload: Value,
    ) -> Result<Self, SorftimeError> {
        let request_id = request_id.into();
        validate_token(&request_id, "Sorftime request id")?;
        let args = vec![
            "--domain".into(),
            market.market_id.as_str().into(),
            "api".into(),
            dataset.api_name().into(),
            "--output".into(),
            "json".into(),
        ];
        Ok(Self {
            program: "sorftime".into(),
            args,
            account,
            market,
            dataset,
            request_id,
            payload,
        })
    }

    pub fn request_digest(&self) -> Result<String, SorftimeError> {
        digest_request(
            self.dataset,
            &self.account,
            &self.market,
            &self.request_id,
            &self.payload,
        )
    }
}

pub trait SorftimeTransport {
    fn execute_api(
        &mut self,
        request: SorftimeApiRequest,
    ) -> Result<SorftimeResponse, SorftimeTransportError>;

    fn execute_cli(
        &mut self,
        request: SorftimeCliRequest,
    ) -> Result<SorftimeResponse, SorftimeTransportError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeResponse {
    pub status: u16,
    pub request_id: String,
    pub body: Value,
    pub cost_units: u64,
    pub cost_currency: Option<CurrencyCode>,
    pub cost_source: String,
}

impl SorftimeResponse {
    fn validate_metadata(&self) -> Result<(), SorftimeError> {
        validate_token(&self.request_id, "Sorftime response request id")?;
        if self.cost_source.trim().is_empty() {
            return Err(SorftimeError::InvalidCostProvenance);
        }
        Ok(())
    }

    fn body_digest(&self) -> Result<String, SorftimeError> {
        digest_value(&self.body)
    }

    fn cost(&self, observed_at: DateTime<Utc>) -> Result<SorftimeRequestCost, SorftimeError> {
        if !(200..300).contains(&self.status) {
            return Err(SorftimeError::HttpStatus(self.status));
        }
        SorftimeRequestCost::new(
            self.cost_units,
            self.cost_currency.clone(),
            self.cost_source.clone(),
            observed_at,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SorftimeEvidenceAuthority {
    EstimateOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeEstimateObservation {
    pub authority: SorftimeEvidenceAuthority,
    pub target_asin: Option<Asin>,
    pub estimated_units: Option<u64>,
    pub estimated_revenue: Option<CanonicalMoney>,
    pub observed_at: CanonicalTime,
    pub response_digest: String,
    pub provenance: SorftimeRequestProvenance,
}

impl SorftimeEstimateObservation {
    pub fn is_estimate_only(&self) -> bool {
        matches!(self.authority, SorftimeEvidenceAuthority::EstimateOnly)
    }

    pub fn validate(&self) -> Result<(), SorftimeError> {
        if !self.is_estimate_only()
            || self.response_digest.len() != 64
            || !self
                .response_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.provenance.request_cost.observed_at != self.observed_at
        {
            return Err(SorftimeError::InvalidResponseProvenance);
        }
        self.provenance.validate()?;
        if self.provenance.authority != self.authority {
            return Err(SorftimeError::InvalidResponseProvenance);
        }
        Ok(())
    }

    pub const fn grants_first_party_authority(&self) -> bool {
        false
    }
}

pub fn query_estimate_api<T: SorftimeTransport>(
    transport: &mut T,
    request: SorftimeApiRequest,
    observed_at: DateTime<Utc>,
) -> Result<SorftimeEstimateObservation, SorftimeError> {
    let digest = request.request_digest()?;
    let response = transport
        .execute_api(request.clone())
        .map_err(|error| SorftimeError::Transport(error.to_string()))?;
    estimate_from_response(
        response,
        request.account,
        request.market,
        request.dataset,
        SorftimeTransportKind::Api,
        digest,
        observed_at,
    )
}

pub fn query_estimate_cli<T: SorftimeTransport>(
    transport: &mut T,
    request: SorftimeCliRequest,
    observed_at: DateTime<Utc>,
) -> Result<SorftimeEstimateObservation, SorftimeError> {
    if request.program != "sorftime" {
        return Err(SorftimeError::InvalidCliProgram(request.program));
    }
    let digest = request.request_digest()?;
    let response = transport
        .execute_cli(request.clone())
        .map_err(|error| SorftimeError::Transport(error.to_string()))?;
    estimate_from_response(
        response,
        request.account,
        request.market,
        request.dataset,
        SorftimeTransportKind::Cli,
        digest,
        observed_at,
    )
}

fn estimate_from_response(
    response: SorftimeResponse,
    account: SorftimeAccountId,
    market: SorftimeMarket,
    dataset: SorftimeDataset,
    transport: SorftimeTransportKind,
    request_digest: String,
    observed_at: DateTime<Utc>,
) -> Result<SorftimeEstimateObservation, SorftimeError> {
    response.validate_metadata()?;
    let response_digest = response.body_digest()?;
    let cost = response.cost(observed_at)?;
    let payload = serde_json::from_value::<EstimatePayload>(response.body)
        .map_err(|error| SorftimeError::MalformedResponse(error.to_string()))?;
    let target_asin = payload
        .asin
        .map(Asin::parse)
        .transpose()
        .map_err(SorftimeError::CanonicalIdentity)?;
    let estimated_revenue = match (payload.estimated_revenue_minor, payload.currency) {
        (Some(amount_minor), Some(currency)) => Some(CanonicalMoney::new(
            amount_minor,
            CurrencyCode::parse(currency)
                .map_err(|error| SorftimeError::InvalidCurrency(error.to_string()))?,
        )),
        (None, None) => None,
        _ => return Err(SorftimeError::IncompleteRevenue),
    };
    let provenance = SorftimeRequestProvenance::new(
        response.request_id,
        account,
        market,
        dataset,
        transport,
        request_digest,
        cost,
    )?;
    Ok(SorftimeEstimateObservation {
        authority: SorftimeEvidenceAuthority::EstimateOnly,
        target_asin,
        estimated_units: payload.estimated_units,
        estimated_revenue,
        observed_at: CanonicalTime::from_datetime(observed_at),
        response_digest,
        provenance,
    })
    .and_then(|observation| {
        observation.validate()?;
        Ok(observation)
    })
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SorftimeTransportError {
    #[error("Sorftime transport failed: {0}")]
    Failed(String),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SorftimeError {
    #[error("invalid {kind}: {value}")]
    InvalidToken { kind: &'static str, value: String },
    #[error("invalid Sorftime locale {0}")]
    InvalidLocale(String),
    #[error("invalid Sorftime API endpoint {0}")]
    InvalidApiEndpoint(String),
    #[error("invalid Sorftime CLI program {0}")]
    InvalidCliProgram(String),
    #[error("Sorftime HTTP status {0}")]
    HttpStatus(u16),
    #[error("Sorftime request cost provenance is missing or invalid")]
    InvalidCostProvenance,
    #[error("Sorftime request provenance is missing or invalid")]
    InvalidRequestProvenance,
    #[error("Sorftime response provenance is missing or invalid")]
    InvalidResponseProvenance,
    #[error("Sorftime transport failed: {0}")]
    Transport(String),
    #[error("malformed Sorftime response: {0}")]
    MalformedResponse(String),
    #[error("Sorftime estimate revenue requires both amount and currency")]
    IncompleteRevenue,
    #[error("invalid Sorftime currency: {0}")]
    InvalidCurrency(String),
    #[error("canonical identity error: {0}")]
    CanonicalIdentity(#[from] CanonicalIdentityError),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EstimatePayload {
    asin: Option<String>,
    estimated_units: Option<u64>,
    estimated_revenue_minor: Option<i64>,
    currency: Option<String>,
}

fn digest_request(
    dataset: SorftimeDataset,
    account: &SorftimeAccountId,
    market: &SorftimeMarket,
    request_id: &str,
    payload: &Value,
) -> Result<String, SorftimeError> {
    let value = serde_json::json!({
        "dataset": dataset,
        "account": account,
        "market": market,
        "requestId": request_id,
        "payload": payload,
    });
    let bytes = serde_json::to_vec(&value).map_err(|_| SorftimeError::InvalidRequestProvenance)?;
    let mut digest = Sha256::new();
    digest.update(bytes);
    Ok(format!("{:x}", digest.finalize()))
}

fn digest_value(value: &Value) -> Result<String, SorftimeError> {
    let bytes = serde_json::to_vec(value).map_err(|_| SorftimeError::InvalidResponseProvenance)?;
    let mut digest = Sha256::new();
    digest.update(bytes);
    Ok(format!("{:x}", digest.finalize()))
}

fn validate_token(value: &str, kind: &'static str) -> Result<(), SorftimeError> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(SorftimeError::InvalidToken {
            kind,
            value: value.into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_and_cli_requests_have_same_provenance_shape_but_distinct_transport() {
        let market = SorftimeMarket::new(
            MarketId::parse("ATVPDKIKX0DER").expect("market"),
            "en-US",
            CurrencyCode::parse("USD").expect("currency"),
        )
        .expect("market");
        let account = SorftimeAccountId::parse("sorftime-fixture-account").expect("account");
        let api = SorftimeApiRequest::new(
            "https://open.sorftime.com/api",
            account.clone(),
            market.clone(),
            SorftimeDataset::ProductTrend,
            "request-api-1",
            serde_json::json!({"asin":"B0C0MERC01"}),
        )
        .expect("api request");
        let cli = SorftimeCliRequest::new(
            account,
            market,
            SorftimeDataset::ProductTrend,
            "request-cli-1",
            serde_json::json!({"asin":"B0C0MERC01"}),
        )
        .expect("cli request");
        assert_eq!(api.endpoint, "https://open.sorftime.com/api");
        assert_eq!(cli.program, "sorftime");
        assert!(
            cli.args
                .windows(2)
                .any(|window| window == ["--output", "json"])
        );
        assert_ne!(
            api.request_digest().expect("digest"),
            cli.request_digest().expect("digest")
        );
    }

    #[test]
    fn estimate_carries_cost_and_can_never_become_first_party_in_this_module() {
        let observed_at = Utc::now();
        let cost =
            SorftimeRequestCost::new(3, None, "fixture-price-list/v1", observed_at).expect("cost");
        let provenance = SorftimeRequestProvenance::new(
            "request-1".into(),
            SorftimeAccountId::parse("account").expect("account"),
            SorftimeMarket::new(
                MarketId::parse("US").expect("market"),
                "en-US",
                CurrencyCode::parse("USD").expect("currency"),
            )
            .expect("market"),
            SorftimeDataset::Product,
            SorftimeTransportKind::Api,
            "a".repeat(64),
            cost,
        )
        .expect("provenance");
        let estimate = SorftimeEstimateObservation {
            authority: SorftimeEvidenceAuthority::EstimateOnly,
            target_asin: Some(Asin::parse("B0C0MERC01").expect("asin")),
            estimated_units: Some(10),
            estimated_revenue: None,
            observed_at: CanonicalTime::from_datetime(observed_at),
            response_digest: "b".repeat(64),
            provenance,
        };
        assert!(estimate.is_estimate_only());
        estimate.validate().expect("valid estimate");
        assert!(!estimate.grants_first_party_authority());
        assert_eq!(estimate.provenance.request_cost.units, 3);
    }
}
