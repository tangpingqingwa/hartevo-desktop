use std::fmt;

use chrono::{DateTime, NaiveDate, Utc};
use hartevo_domain_kernel::{ProjectId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum CommonValidationError {
    #[error("date range is invalid")]
    InvalidDateRange,
    #[error("market code is invalid")]
    InvalidMarket,
    #[error("language code is invalid")]
    InvalidLanguage,
    #[error("value is empty")]
    EmptyValue,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    FirstPartyAccount,
    ProviderEstimate,
}

impl EvidenceClassification {
    pub const fn is_first_party(self) -> bool {
        matches!(self, Self::FirstPartyAccount)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MarketCode(String);

impl MarketCode {
    pub fn new(value: &str) -> Result<Self, CommonValidationError> {
        let upper = value.trim().to_ascii_uppercase();
        if upper.len() != 2 || !upper.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(CommonValidationError::InvalidMarket);
        }
        Ok(Self(upper))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MarketCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct LanguageCode(String);

impl LanguageCode {
    pub fn new(value: &str) -> Result<Self, CommonValidationError> {
        let normalized = value.trim().to_ascii_lowercase();
        let valid = (2..=12).contains(&normalized.len())
            && normalized.split('-').all(|segment| {
                !segment.is_empty()
                    && segment.len() <= 8
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            });
        if !valid {
            return Err(CommonValidationError::InvalidLanguage);
        }
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LanguageCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarDateRange {
    start: NaiveDate,
    end: NaiveDate,
}

impl CalendarDateRange {
    pub fn new(start: NaiveDate, end: NaiveDate) -> Result<Self, CommonValidationError> {
        if end < start {
            return Err(CommonValidationError::InvalidDateRange);
        }
        Ok(Self { start, end })
    }

    pub const fn start(&self) -> NaiveDate {
        self.start
    }

    pub const fn end(&self) -> NaiveDate {
        self.end
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadScope {
    tenant_id: TenantId,
    project_id: ProjectId,
    market: MarketCode,
    language: LanguageCode,
    window: CalendarDateRange,
}

impl ReadScope {
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        market: MarketCode,
        language: LanguageCode,
        window: CalendarDateRange,
    ) -> Self {
        Self {
            tenant_id,
            project_id,
            market,
            language,
            window,
        }
    }

    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub const fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn market(&self) -> &MarketCode {
        &self.market
    }

    pub const fn language(&self) -> &LanguageCode {
        &self.language
    }

    pub const fn window(&self) -> CalendarDateRange {
        self.window
    }

    pub fn digest(&self) -> String {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Freshness {
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}

impl Freshness {
    pub fn new(
        observed_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, CommonValidationError> {
        if valid_until < observed_at {
            return Err(CommonValidationError::InvalidDateRange);
        }
        Ok(Self {
            observed_at,
            valid_until,
        })
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    pub fn is_fresh_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.observed_at && now < self.valid_until
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderReceiptReference {
    provider_id: String,
    operation: String,
    endpoint: String,
    request_digest: String,
    response_digest: String,
    provider_request_id: Option<String>,
    task_id: Option<String>,
}

impl ProviderReceiptReference {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_id: impl Into<String>,
        operation: impl Into<String>,
        endpoint: impl Into<String>,
        request_digest: impl Into<String>,
        response_digest: impl Into<String>,
        provider_request_id: Option<String>,
        task_id: Option<String>,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            operation: operation.into(),
            endpoint: endpoint.into(),
            request_digest: request_digest.into(),
            response_digest: response_digest.into(),
            provider_request_id,
            task_id,
        }
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub fn provider_request_id(&self) -> Option<&str> {
        self.provider_request_id.as_deref()
    }

    pub fn task_id(&self) -> Option<&str> {
        self.task_id.as_deref()
    }
}

pub fn canonical_digest<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("provider contract values serialize");
    format!("{:x}", Sha256::digest(bytes))
}

pub fn response_digest(value: &serde_json::Value) -> String {
    canonical_digest(value)
}

pub fn parse_date(value: &str) -> Result<NaiveDate, CommonValidationError> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|_| CommonValidationError::InvalidDateRange)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_digest_is_stable_and_market_language_are_canonical() {
        let scope = ReadScope::new(
            TenantId::from("tenant-growth"),
            ProjectId::from("project-growth"),
            MarketCode::new("de").expect("market"),
            LanguageCode::new("DE-de").expect("language"),
            CalendarDateRange::new(
                parse_date("2026-08-01").expect("date"),
                parse_date("2026-08-07").expect("date"),
            )
            .expect("window"),
        );
        assert_eq!(scope.market().as_str(), "DE");
        assert_eq!(scope.language().as_str(), "de-de");
        assert_eq!(
            serde_json::to_value(scope.market()).expect("market JSON"),
            "DE"
        );
        assert_eq!(scope.digest().len(), 64);
        assert_eq!(scope.digest(), scope.digest());
    }

    #[test]
    fn freshness_is_bounded() {
        let observed = DateTime::parse_from_rfc3339("2026-08-13T00:00:00Z")
            .expect("timestamp")
            .with_timezone(&Utc);
        let freshness =
            Freshness::new(observed, observed + chrono::Duration::hours(1)).expect("freshness");
        assert!(freshness.is_fresh_at(observed + chrono::Duration::minutes(1)));
        assert!(!freshness.is_fresh_at(observed + chrono::Duration::hours(1)));
    }
}
