use std::{env, fmt};

use chrono::NaiveDate;
use hartevo_connector_sdk::{ConnectorScope, SecretReference};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    GA4_PROVIDER_ID, GA4_READ_CAPABILITY, Ga4Error, Ga4OAuthCredentials, Ga4SearchRequest,
    Ga4TimeWindow, Ga4TimeoutRetryPolicy,
};

#[derive(Debug, Error, Eq, PartialEq)]
pub enum Ga4EnvError {
    #[error("BLOCKED_ENV: missing {0:?}")]
    BlockedEnv(Vec<String>),
    #[error("invalid Google Analytics 4 canary environment")]
    Invalid,
    #[error("Google Analytics 4 credential is invalid")]
    Credential(#[from] Ga4Error),
    #[error("Connector scope is invalid")]
    Scope,
}

pub struct Ga4EnvConfig {
    access_token: Zeroizing<String>,
    tenant_id: String,
    project_id: String,
    account_id: String,
    property_id: String,
    dimensions: Vec<String>,
    metrics: Vec<String>,
    window: Ga4TimeWindow,
    page_size: u32,
    secret_reference_id: String,
    credential_revision: u64,
}

impl fmt::Debug for Ga4EnvConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ga4EnvConfig")
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("account_id", &self.account_id)
            .field("property_id", &self.property_id)
            .field("dimensions", &self.dimensions)
            .field("metrics", &self.metrics)
            .field("page_size", &self.page_size)
            .field("secret_reference_id", &self.secret_reference_id)
            .field("credential_revision", &self.credential_revision)
            .finish_non_exhaustive()
    }
}

impl Ga4EnvConfig {
    pub fn from_env() -> Result<Self, Ga4EnvError> {
        let names = [
            "GA4_ACCESS_TOKEN",
            "GA4_TENANT_ID",
            "GA4_PROJECT_ID",
            "GA4_ACCOUNT_ID",
            "GA4_PROPERTY_ID",
            "GA4_WINDOW_START",
            "GA4_WINDOW_END",
        ];
        let mut missing = Vec::new();
        for name in names {
            if env::var(name).map_or(true, |value| value.trim().is_empty()) {
                missing.push(name.to_owned());
            }
        }
        if !missing.is_empty() {
            return Err(Ga4EnvError::BlockedEnv(missing));
        }
        let value = |name: &str| env::var(name).map_err(|_| Ga4EnvError::Invalid);
        let start = NaiveDate::parse_from_str(&value("GA4_WINDOW_START")?, "%Y-%m-%d")
            .map_err(|_| Ga4EnvError::Invalid)?;
        let end = NaiveDate::parse_from_str(&value("GA4_WINDOW_END")?, "%Y-%m-%d")
            .map_err(|_| Ga4EnvError::Invalid)?;
        let dimensions =
            csv_values(&env::var("GA4_DIMENSIONS").unwrap_or_else(|_| "date".to_owned()));
        let metrics =
            csv_values(&env::var("GA4_METRICS").unwrap_or_else(|_| "activeUsers".to_owned()));
        let page_size = env::var("GA4_PAGE_SIZE")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(100);
        Ok(Self {
            access_token: Zeroizing::new(value("GA4_ACCESS_TOKEN")?),
            tenant_id: value("GA4_TENANT_ID")?,
            project_id: value("GA4_PROJECT_ID")?,
            account_id: value("GA4_ACCOUNT_ID")?,
            property_id: value("GA4_PROPERTY_ID")?,
            dimensions,
            metrics,
            window: Ga4TimeWindow::new(start, end)?,
            page_size,
            secret_reference_id: env::var("GA4_SECRET_REFERENCE_ID")
                .unwrap_or_else(|_| "secret-ref-ga4-env".to_owned()),
            credential_revision: env::var("GA4_CREDENTIAL_REVISION")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(1),
        })
    }

    pub fn scope(&self) -> Result<ConnectorScope, Ga4EnvError> {
        ConnectorScope::new(
            self.tenant_id.clone(),
            self.project_id.clone(),
            GA4_PROVIDER_ID,
            self.account_id.clone(),
            [GA4_READ_CAPABILITY.to_owned()],
        )
        .map_err(|_| Ga4EnvError::Scope)
    }

    pub fn request(&self, scope: ConnectorScope) -> Result<Ga4SearchRequest, Ga4EnvError> {
        Ok(Ga4SearchRequest::new(
            scope,
            self.property_id.clone(),
            self.dimensions.clone(),
            self.metrics.clone(),
            self.window.clone(),
            self.page_size,
        )?)
    }

    pub fn credentials(&self) -> Result<Ga4OAuthCredentials, Ga4EnvError> {
        Ok(Ga4OAuthCredentials::new(self.access_token.as_str())?)
    }

    pub fn secret_reference(&self, scope: ConnectorScope) -> Result<SecretReference, Ga4EnvError> {
        SecretReference::new(
            self.secret_reference_id.clone(),
            scope,
            self.credential_revision,
        )
        .map_err(|_| Ga4EnvError::Invalid)
    }

    pub fn policy(&self) -> Ga4TimeoutRetryPolicy {
        Ga4TimeoutRetryPolicy::default()
    }
}

fn csv_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}
