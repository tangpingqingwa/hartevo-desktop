use std::{env, fmt};

use hartevo_connector_sdk::{ConnectorScope, SecretReference};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    GOOGLE_ADS_PROVIDER_ID, GOOGLE_ADS_READ_CAPABILITY, GoogleAdsError, GoogleAdsGaqlRequest,
    GoogleAdsOAuthCredentials, GoogleAdsTimeoutRetryPolicy,
};

#[derive(Debug, Error, Eq, PartialEq)]
pub enum GoogleAdsEnvError {
    #[error("BLOCKED_ENV: missing {0:?}")]
    BlockedEnv(Vec<String>),
    #[error("invalid Google Ads canary environment")]
    Invalid,
    #[error("Google Ads credential or request is invalid")]
    Provider(#[from] GoogleAdsError),
    #[error("Connector scope is invalid")]
    Scope,
}

pub struct GoogleAdsEnvConfig {
    access_token: Zeroizing<String>,
    developer_token: Zeroizing<String>,
    tenant_id: String,
    project_id: String,
    customer_id: String,
    login_customer_id: String,
    query: String,
    max_pages: u32,
    max_quota_units: u64,
    secret_reference_id: String,
    credential_revision: u64,
}

impl fmt::Debug for GoogleAdsEnvConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleAdsEnvConfig")
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("customer_id", &self.customer_id)
            .field("login_customer_id", &self.login_customer_id)
            .field("max_pages", &self.max_pages)
            .field("max_quota_units", &self.max_quota_units)
            .field("secret_reference_id", &self.secret_reference_id)
            .field("credential_revision", &self.credential_revision)
            .finish_non_exhaustive()
    }
}

impl GoogleAdsEnvConfig {
    pub fn from_env() -> Result<Self, GoogleAdsEnvError> {
        let names = [
            "GOOGLE_ADS_OAUTH_ACCESS_TOKEN",
            "GOOGLE_ADS_DEVELOPER_TOKEN",
            "GOOGLE_ADS_TENANT_ID",
            "GOOGLE_ADS_PROJECT_ID",
            "GOOGLE_ADS_CUSTOMER_ID",
            "GOOGLE_ADS_LOGIN_CUSTOMER_ID",
            "GOOGLE_ADS_GAQL",
            "GOOGLE_ADS_MAX_QUOTA_UNITS",
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
            return Err(GoogleAdsEnvError::BlockedEnv(missing));
        }
        let value = |name: &str| {
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
                .ok_or(GoogleAdsEnvError::Invalid)
        };
        let max_pages = env::var("GOOGLE_ADS_MAX_PAGES")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(1);
        let max_quota_units = value("GOOGLE_ADS_MAX_QUOTA_UNITS")?
            .parse::<u64>()
            .map_err(|_| GoogleAdsEnvError::Invalid)?;
        let credential_revision = env::var("GOOGLE_ADS_CREDENTIAL_REVISION")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1);
        let secret_reference_id = env::var("GOOGLE_ADS_SECRET_REFERENCE_ID")
            .unwrap_or_else(|_| "secret-ref-google-ads-env".to_owned());
        Ok(Self {
            access_token: Zeroizing::new(value("GOOGLE_ADS_OAUTH_ACCESS_TOKEN")?),
            developer_token: Zeroizing::new(value("GOOGLE_ADS_DEVELOPER_TOKEN")?),
            tenant_id: value("GOOGLE_ADS_TENANT_ID")?,
            project_id: value("GOOGLE_ADS_PROJECT_ID")?,
            customer_id: value("GOOGLE_ADS_CUSTOMER_ID")?,
            login_customer_id: value("GOOGLE_ADS_LOGIN_CUSTOMER_ID")?,
            query: value("GOOGLE_ADS_GAQL")?,
            max_pages,
            max_quota_units,
            secret_reference_id,
            credential_revision,
        })
    }

    pub fn scope(&self) -> Result<ConnectorScope, GoogleAdsEnvError> {
        ConnectorScope::new(
            self.tenant_id.clone(),
            self.project_id.clone(),
            GOOGLE_ADS_PROVIDER_ID,
            self.customer_id.clone(),
            [GOOGLE_ADS_READ_CAPABILITY.to_owned()],
        )
        .map_err(|_| GoogleAdsEnvError::Scope)
    }

    pub fn request(
        &self,
        scope: ConnectorScope,
    ) -> Result<GoogleAdsGaqlRequest, GoogleAdsEnvError> {
        Ok(GoogleAdsGaqlRequest::new(
            scope,
            self.login_customer_id.clone(),
            self.query.clone(),
            self.max_pages,
            self.max_quota_units,
        )?)
    }

    pub fn credentials(&self) -> Result<GoogleAdsOAuthCredentials, GoogleAdsEnvError> {
        Ok(GoogleAdsOAuthCredentials::new(
            self.access_token.as_str(),
            self.developer_token.as_str(),
        )?)
    }

    pub fn secret_reference(
        &self,
        scope: ConnectorScope,
    ) -> Result<SecretReference, GoogleAdsEnvError> {
        SecretReference::new(
            self.secret_reference_id.clone(),
            scope,
            self.credential_revision,
        )
        .map_err(|_| GoogleAdsEnvError::Invalid)
    }

    pub fn policy(&self) -> GoogleAdsTimeoutRetryPolicy {
        GoogleAdsTimeoutRetryPolicy::default()
    }
}
