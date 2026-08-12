use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CurrencyCode(String);

impl CurrencyCode {
    pub fn parse(value: impl Into<String>) -> Result<Self, MoneyError> {
        let value = value.into();
        if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(MoneyError::InvalidCurrency(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CurrencyCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for CurrencyCode {
    type Err = MoneyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Money {
    pub amount_minor: i64,
    pub currency: CurrencyCode,
}

impl Money {
    pub fn new(amount_minor: i64, currency: CurrencyCode) -> Self {
        Self {
            amount_minor,
            currency,
        }
    }

    pub fn zero(currency: CurrencyCode) -> Self {
        Self::new(0, currency)
    }

    pub fn checked_add(&self, other: &Self) -> Result<Self, MoneyError> {
        self.require_same_currency(other)?;
        let amount_minor = self
            .amount_minor
            .checked_add(other.amount_minor)
            .ok_or(MoneyError::Overflow)?;
        Ok(Self::new(amount_minor, self.currency.clone()))
    }

    pub fn checked_sub(&self, other: &Self) -> Result<Self, MoneyError> {
        self.require_same_currency(other)?;
        let amount_minor = self
            .amount_minor
            .checked_sub(other.amount_minor)
            .ok_or(MoneyError::Overflow)?;
        Ok(Self::new(amount_minor, self.currency.clone()))
    }

    pub fn is_positive(&self) -> bool {
        self.amount_minor > 0
    }

    fn require_same_currency(&self, other: &Self) -> Result<(), MoneyError> {
        if self.currency == other.currency {
            Ok(())
        } else {
            Err(MoneyError::CurrencyMismatch {
                left: self.currency.clone(),
                right: other.currency.clone(),
            })
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FxQuote {
    pub base: CurrencyCode,
    pub quote: CurrencyCode,
    pub rate: Decimal,
    pub source: String,
    pub observed_at: DateTime<Utc>,
}

impl FxQuote {
    pub fn new(
        base: CurrencyCode,
        quote: CurrencyCode,
        rate: Decimal,
        source: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, MoneyError> {
        let source = source.into();
        if rate <= Decimal::ZERO {
            return Err(MoneyError::InvalidFxRate);
        }
        if source.trim().is_empty() {
            return Err(MoneyError::MissingFxSource);
        }
        Ok(Self {
            base,
            quote,
            rate,
            source,
            observed_at,
        })
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MoneyError {
    #[error("invalid ISO currency code {0}; expected three uppercase ASCII letters")]
    InvalidCurrency(String),
    #[error("currency mismatch: {left} and {right}")]
    CurrencyMismatch {
        left: CurrencyCode,
        right: CurrencyCode,
    },
    #[error("money arithmetic overflow")]
    Overflow,
    #[error("FX rate must be positive")]
    InvalidFxRate,
    #[error("FX quote must record a source")]
    MissingFxSource,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn money_never_combines_different_currencies() {
        let usd = Money::new(1_000, CurrencyCode::parse("USD").expect("USD"));
        let eur = Money::new(1_000, CurrencyCode::parse("EUR").expect("EUR"));
        assert!(matches!(
            usd.checked_add(&eur),
            Err(MoneyError::CurrencyMismatch { .. })
        ));
    }

    #[test]
    fn fx_requires_positive_rate_and_provenance() {
        let observed_at = Utc
            .with_ymd_and_hms(2026, 8, 10, 8, 0, 0)
            .single()
            .expect("valid time");
        let result = FxQuote::new(
            CurrencyCode::parse("USD").expect("USD"),
            CurrencyCode::parse("EUR").expect("EUR"),
            Decimal::ZERO,
            "fixture-fx",
            observed_at,
        );
        assert_eq!(result, Err(MoneyError::InvalidFxRate));
    }
}
