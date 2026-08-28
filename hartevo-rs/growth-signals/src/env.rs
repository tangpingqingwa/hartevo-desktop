use std::{env, fmt, str::FromStr};

use chrono::NaiveDate;
use hartevo_connector_sdk::{ConnectorScope, SecretReference};
use rust_decimal::Decimal;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    DATAFORSEO_LABS_READ_CAPABILITY, DATAFORSEO_PROVIDER_ID, DataForSeoCredentials,
    DataForSeoError, DataForSeoKeywordRequest, DataForSeoTimeWindow, DataForSeoTimeoutRetryPolicy,
};

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DataForSeoEnvError {
    #[error("BLOCKED_ENV: missing {0:?}")]
    BlockedEnv(Vec<String>),
    #[error("invalid DataForSEO canary environment")]
    Invalid,
    #[error("DataForSEO credential is invalid")]
    Credential(#[from] DataForSeoError),
    #[error("Connector scope is invalid")]
    Scope,
}

pub struct DataForSeoEnvConfig {
    login: Zeroizing<String>,
    password: Zeroizing<String>,
    tenant_id: String,
    project_id: String,
    account_id: String,
    target_domain: String,
    market: String,
    location_code: u32,
    language_code: String,
    window: DataForSeoTimeWindow,
    limit: u32,
    estimated_cost_usd: Decimal,
    max_cost_usd: Decimal,
    secret_reference_id: String,
    credential_revision: u64,
}

impl fmt::Debug for DataForSeoEnvConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataForSeoEnvConfig")
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("account_id", &self.account_id)
            .field("target_domain", &self.target_domain)
            .field("market", &self.market)
            .field("location_code", &self.location_code)
            .field("language_code", &self.language_code)
            .field("limit", &self.limit)
            .field("secret_reference_id", &self.secret_reference_id)
            .field("credential_revision", &self.credential_revision)
            .finish_non_exhaustive()
    }
}

impl DataForSeoEnvConfig {
    pub fn from_env() -> Result<Self, DataForSeoEnvError> {
        let names = [
            "DATAFORSEO_LOGIN",
            "DATAFORSEO_PASSWORD",
            "DATAFORSEO_TENANT_ID",
            "DATAFORSEO_PROJECT_ID",
            "DATAFORSEO_ACCOUNT_ID",
            "DATAFORSEO_TARGET_DOMAIN",
            "DATAFORSEO_MARKET",
            "DATAFORSEO_LOCATION_CODE",
            "DATAFORSEO_LANGUAGE_CODE",
            "DATAFORSEO_WINDOW_START",
            "DATAFORSEO_WINDOW_END",
            "DATAFORSEO_MAX_COST_USD",
        ];
        let mut missing = Vec::new();
        let mut values = Vec::new();
        for name in names {
            match env::var(name) {
                Ok(value) if !value.trim().is_empty() => values.push((name, value)),
                _ => missing.push(name.to_owned()),
            }
        }
        if !missing.is_empty() {
            return Err(DataForSeoEnvError::BlockedEnv(missing));
        }
        let value = |name: &str| {
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
                .ok_or(DataForSeoEnvError::Invalid)
        };
        let start = NaiveDate::parse_from_str(&value("DATAFORSEO_WINDOW_START")?, "%Y-%m-%d")
            .map_err(|_| DataForSeoEnvError::Invalid)?;
        let end = NaiveDate::parse_from_str(&value("DATAFORSEO_WINDOW_END")?, "%Y-%m-%d")
            .map_err(|_| DataForSeoEnvError::Invalid)?;
        let window = DataForSeoTimeWindow::new(start, end)?;
        let max_cost_usd = Decimal::from_str(&value("DATAFORSEO_MAX_COST_USD")?)
            .map_err(|_| DataForSeoEnvError::Invalid)?;
        let estimated_cost_usd = env::var("DATAFORSEO_ESTIMATED_COST_USD")
            .ok()
            .and_then(|value| Decimal::from_str(&value).ok())
            .unwrap_or(Decimal::new(1, 2));
        let limit = env::var("DATAFORSEO_LIMIT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(100);
        let credential_revision = env::var("DATAFORSEO_CREDENTIAL_REVISION")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1);
        let secret_reference_id = env::var("DATAFORSEO_SECRET_REFERENCE_ID")
            .unwrap_or_else(|_| "secret-ref-dataforseo-env".into());
        Ok(Self {
            login: Zeroizing::new(value("DATAFORSEO_LOGIN")?),
            password: Zeroizing::new(value("DATAFORSEO_PASSWORD")?),
            tenant_id: value("DATAFORSEO_TENANT_ID")?,
            project_id: value("DATAFORSEO_PROJECT_ID")?,
            account_id: value("DATAFORSEO_ACCOUNT_ID")?,
            target_domain: value("DATAFORSEO_TARGET_DOMAIN")?,
            market: value("DATAFORSEO_MARKET")?,
            location_code: value("DATAFORSEO_LOCATION_CODE")?
                .parse()
                .map_err(|_| DataForSeoEnvError::Invalid)?,
            language_code: value("DATAFORSEO_LANGUAGE_CODE")?,
            window,
            limit,
            estimated_cost_usd,
            max_cost_usd,
            secret_reference_id,
            credential_revision,
        })
    }

    pub fn scope(&self) -> Result<ConnectorScope, DataForSeoEnvError> {
        ConnectorScope::new(
            self.tenant_id.clone(),
            self.project_id.clone(),
            DATAFORSEO_PROVIDER_ID,
            self.account_id.clone(),
            [DATAFORSEO_LABS_READ_CAPABILITY.to_owned()],
        )
        .map_err(|_| DataForSeoEnvError::Scope)
    }

    pub fn request(
        &self,
        scope: ConnectorScope,
    ) -> Result<DataForSeoKeywordRequest, DataForSeoEnvError> {
        Ok(DataForSeoKeywordRequest::new(
            scope,
            self.target_domain.clone(),
            self.market.clone(),
            self.location_code,
            self.language_code.clone(),
            self.window.clone(),
            self.limit,
            false,
            false,
            self.estimated_cost_usd,
            self.max_cost_usd,
        )?)
    }

    pub fn credentials(&self) -> Result<DataForSeoCredentials, DataForSeoEnvError> {
        Ok(DataForSeoCredentials::new(
            self.login.as_str(),
            self.password.as_str(),
        )?)
    }

    pub fn secret_reference(
        &self,
        scope: ConnectorScope,
    ) -> Result<SecretReference, DataForSeoEnvError> {
        SecretReference::new(
            self.secret_reference_id.clone(),
            scope,
            self.credential_revision,
        )
        .map_err(|_| DataForSeoEnvError::Invalid)
    }

    pub fn policy(&self) -> DataForSeoTimeoutRetryPolicy {
        DataForSeoTimeoutRetryPolicy::default()
    }
}
