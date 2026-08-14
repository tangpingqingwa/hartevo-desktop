use std::{env, fmt};

use chrono::NaiveDate;
use hartevo_connector_sdk::{ConnectorScope, SecretReference};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    GSC_PROVIDER_ID, GSC_READ_CAPABILITY, GscError, GscOAuthCredentials, GscSearchRequest,
    GscTimeWindow, GscTimeoutRetryPolicy,
};

#[derive(Debug, Error, Eq, PartialEq)]
pub enum GscEnvError {
    #[error("BLOCKED_ENV: missing {0:?}")]
    BlockedEnv(Vec<String>),
    #[error("invalid Google Search Console canary environment")]
    Invalid,
    #[error("Google Search Console credential is invalid")]
    Credential(#[from] GscError),
    #[error("Connector scope is invalid")]
    Scope,
}

pub struct GscEnvConfig {
    access_token: Zeroizing<String>,
    tenant_id: String,
    project_id: String,
    account_id: String,
    property: String,
    dimensions: Vec<String>,
    window: GscTimeWindow,
    row_limit: u32,
    secret_reference_id: String,
    credential_revision: u64,
}

impl fmt::Debug for GscEnvConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GscEnvConfig")
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("account_id", &self.account_id)
            .field("property", &self.property)
            .field("dimensions", &self.dimensions)
            .field("row_limit", &self.row_limit)
            .field("secret_reference_id", &self.secret_reference_id)
            .field("credential_revision", &self.credential_revision)
            .finish_non_exhaustive()
    }
}

impl GscEnvConfig {
    pub fn from_env() -> Result<Self, GscEnvError> {
        let names = [
            "GSC_ACCESS_TOKEN",
            "GSC_TENANT_ID",
            "GSC_PROJECT_ID",
            "GSC_ACCOUNT_ID",
            "GSC_PROPERTY",
            "GSC_WINDOW_START",
            "GSC_WINDOW_END",
        ];
        let mut missing = Vec::new();
        for name in names {
            if env::var(name).map_or(true, |value| value.trim().is_empty()) {
                missing.push(name.to_owned());
            }
        }
        if !missing.is_empty() {
            return Err(GscEnvError::BlockedEnv(missing));
        }
        let value = |name: &str| env::var(name).map_err(|_| GscEnvError::Invalid);
        let start = NaiveDate::parse_from_str(&value("GSC_WINDOW_START")?, "%Y-%m-%d")
            .map_err(|_| GscEnvError::Invalid)?;
        let end = NaiveDate::parse_from_str(&value("GSC_WINDOW_END")?, "%Y-%m-%d")
            .map_err(|_| GscEnvError::Invalid)?;
        let dimensions =
            csv_values(&env::var("GSC_DIMENSIONS").unwrap_or_else(|_| "query".to_owned()));
        let row_limit = env::var("GSC_ROW_LIMIT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(100);
        Ok(Self {
            access_token: Zeroizing::new(value("GSC_ACCESS_TOKEN")?),
            tenant_id: value("GSC_TENANT_ID")?,
            project_id: value("GSC_PROJECT_ID")?,
            account_id: value("GSC_ACCOUNT_ID")?,
            property: value("GSC_PROPERTY")?,
            dimensions,
            window: GscTimeWindow::new(start, end)?,
            row_limit,
            secret_reference_id: env::var("GSC_SECRET_REFERENCE_ID")
                .unwrap_or_else(|_| "secret-ref-gsc-env".to_owned()),
            credential_revision: env::var("GSC_CREDENTIAL_REVISION")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(1),
        })
    }

    pub fn scope(&self) -> Result<ConnectorScope, GscEnvError> {
        ConnectorScope::new(
            self.tenant_id.clone(),
            self.project_id.clone(),
            GSC_PROVIDER_ID,
            self.account_id.clone(),
            [GSC_READ_CAPABILITY.to_owned()],
        )
        .map_err(|_| GscEnvError::Scope)
    }

    pub fn request(&self, scope: ConnectorScope) -> Result<GscSearchRequest, GscEnvError> {
        Ok(GscSearchRequest::new(
            scope,
            self.property.clone(),
            self.dimensions.clone(),
            self.window.clone(),
            self.row_limit,
        )?)
    }

    pub fn credentials(&self) -> Result<GscOAuthCredentials, GscEnvError> {
        Ok(GscOAuthCredentials::new(self.access_token.as_str())?)
    }

    pub fn secret_reference(&self, scope: ConnectorScope) -> Result<SecretReference, GscEnvError> {
        SecretReference::new(
            self.secret_reference_id.clone(),
            scope,
            self.credential_revision,
        )
        .map_err(|_| GscEnvError::Invalid)
    }

    pub fn policy(&self) -> GscTimeoutRetryPolicy {
        GscTimeoutRetryPolicy::default()
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
