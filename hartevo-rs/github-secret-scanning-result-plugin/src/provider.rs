//! Typed, read-only provider boundary for GitHub secret-scanning alerts.
//!
//! The transport layer is deliberately script/fixture based. No implementation
//! in this crate resolves a credential or opens a live network connection.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AlertNumber, Digest, GithubSecretScanningAlert, GithubSecretScanningScope, MAX_ALERTS,
    MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, OpaqueCursor, PermissionSnapshot,
    RedactedRateReceipt, Revision, SecretScanningOperation, TransportProvenance,
};
use crate::{
    ALERT_ENDPOINT, ALERTS_ORG_ENDPOINT, ALERTS_REPOSITORY_ENDPOINT, PROVIDER_API_REVISION,
    PROVIDER_ID, PROVIDER_VERSION,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Unprocessable,
    RateLimited,
    ServiceUnavailable,
    Timeout,
    CursorLoop,
    Tampered,
    Partial,
    AccessLoss,
    BlockedEnv,
    InvalidRequest,
    ResponseTooLarge,
    ScriptExhausted,
}

impl ProviderErrorKind {
    pub const fn status(self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::Unprocessable => Some(422),
            Self::RateLimited => Some(429),
            Self::ServiceUnavailable => Some(503),
            _ => None,
        }
    }

    pub const fn is_access_loss(self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::NotFound | Self::AccessLoss
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[error("GitHub secret-scanning provider error: {kind:?}")]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
    pub status: Option<u16>,
    pub code_digest: Digest,
    pub response_digest: Option<Digest>,
    pub rate: RedactedRateReceipt,
    pub truncated: bool,
}

impl ProviderError {
    /// Hash a transport-local error label immediately; raw error text is not
    /// retained in a provider error or any evidence receipt.
    pub fn new(kind: ProviderErrorKind, code: impl AsRef<str>) -> Self {
        Self {
            status: kind.status(),
            kind,
            code_digest: Digest::from_parts(
                "github-secret-scanning-provider-error-code/v1",
                &[code.as_ref()],
            ),
            response_digest: None,
            rate: RedactedRateReceipt::empty(),
            truncated: false,
        }
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    pub fn with_response_digest(mut self, digest: Digest) -> Self {
        self.response_digest = Some(digest);
        self
    }

    pub fn with_rate(mut self, rate: RedactedRateReceipt) -> Self {
        self.rate = rate;
        self
    }

    pub fn truncated(mut self) -> Self {
        self.truncated = true;
        self
    }

    pub const fn is_access_loss(&self) -> bool {
        self.kind.is_access_loss()
    }

    pub const fn fail_closed(&self) -> bool {
        self.is_access_loss()
            || matches!(
                self.kind,
                ProviderErrorKind::Conflict
                    | ProviderErrorKind::Unprocessable
                    | ProviderErrorKind::RateLimited
                    | ProviderErrorKind::ServiceUnavailable
                    | ProviderErrorKind::Timeout
                    | ProviderErrorKind::CursorLoop
                    | ProviderErrorKind::Tampered
                    | ProviderErrorKind::Partial
                    | ProviderErrorKind::BlockedEnv
            )
    }
}

pub type GithubSecretScanningProviderError = ProviderError;
pub type TransportError = ProviderError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertTarget {
    Repository,
    Organization,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubSecretScanningRequest {
    pub operation: SecretScanningOperation,
    pub target: AlertTarget,
    pub organization: String,
    pub repository_owner: Option<String>,
    pub repository_name: Option<String>,
    pub alert_number: Option<AlertNumber>,
    pub page: u16,
    pub per_page: u16,
    pub cursor: Option<OpaqueCursor>,
    pub query_digest: Digest,
    pub hide_secret: bool,
    pub endpoint_digest: Digest,
    pub request_digest: Digest,
}

pub type GithubSecretScanningReadRequest = GithubSecretScanningRequest;

impl GithubSecretScanningRequest {
    pub fn list_repository(
        scope: &GithubSecretScanningScope,
        page: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ProviderError> {
        Self::list(scope, AlertTarget::Repository, page, cursor)
    }

    pub fn list_organization(
        scope: &GithubSecretScanningScope,
        page: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ProviderError> {
        Self::list(scope, AlertTarget::Organization, page, cursor)
    }

    fn list(
        scope: &GithubSecretScanningScope,
        target: AlertTarget,
        page: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ProviderError> {
        if !(1..=MAX_PAGES).contains(&page) {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "page_out_of_bounds",
            ));
        }
        let operation = match target {
            AlertTarget::Repository => SecretScanningOperation::ListRepositoryAlerts,
            AlertTarget::Organization => SecretScanningOperation::ListOrganizationAlerts,
        };
        Self::build(operation, target, scope, page, cursor, None)
    }

    pub fn get_repository(
        scope: &GithubSecretScanningScope,
        alert_number: AlertNumber,
    ) -> Result<Self, ProviderError> {
        Self::build(
            SecretScanningOperation::GetRepositoryAlert,
            AlertTarget::Repository,
            scope,
            1,
            None,
            Some(alert_number),
        )
    }

    fn build(
        operation: SecretScanningOperation,
        target: AlertTarget,
        scope: &GithubSecretScanningScope,
        page: u16,
        cursor: Option<OpaqueCursor>,
        alert_number: Option<AlertNumber>,
    ) -> Result<Self, ProviderError> {
        let (repository_owner, repository_name) = match target {
            AlertTarget::Repository => (
                Some(scope.repository.owner().to_owned()),
                Some(scope.repository.name().to_owned()),
            ),
            AlertTarget::Organization => (None, None),
        };
        let query_digest =
            scope
                .query
                .query_digest_for_request(page, MAX_PAGE_SIZE, cursor.as_ref());
        let endpoint = match target {
            AlertTarget::Repository => ALERTS_REPOSITORY_ENDPOINT,
            AlertTarget::Organization => ALERTS_ORG_ENDPOINT,
        };
        let endpoint_digest = Digest::from_parts(
            "github-secret-scanning-endpoint/v1",
            &[endpoint.to_owned(), scope.organization.as_str().to_owned()],
        );
        let request_digest = Digest::from_serialized(&(
            operation,
            target,
            &scope.installation_id,
            &scope.organization,
            &scope.repository,
            &scope.git_ref,
            &scope.commit_sha,
            alert_number,
            page,
            MAX_PAGE_SIZE,
            &cursor,
            &query_digest,
            true,
            &endpoint_digest,
        ));
        Ok(Self {
            operation,
            target,
            organization: scope.organization.as_str().to_owned(),
            repository_owner,
            repository_name,
            alert_number,
            page,
            per_page: MAX_PAGE_SIZE,
            cursor,
            query_digest,
            hide_secret: true,
            endpoint_digest,
            request_digest,
        })
    }

    pub const fn method(&self) -> &'static str {
        "GET"
    }

    pub fn path(&self) -> String {
        match self.target {
            AlertTarget::Repository => {
                let owner = self.repository_owner.as_deref().unwrap_or("_");
                let repository = self.repository_name.as_deref().unwrap_or("_");
                if let Some(alert_number) = self.alert_number {
                    format!(
                        "/repos/{owner}/{repository}{ALERT_ENDPOINT}/{}?hide_secret=true",
                        alert_number.get()
                    )
                } else {
                    format!(
                        "/repos/{owner}/{repository}{ALERTS_REPOSITORY_ENDPOINT}?{}",
                        self.query_string()
                    )
                }
            }
            AlertTarget::Organization => {
                format!(
                    "/orgs/{}{ALERTS_ORG_ENDPOINT}?{}",
                    self.organization,
                    self.query_string()
                )
            }
        }
    }

    pub fn query_string(&self) -> String {
        let mut values = vec![
            "hide_secret=true".to_owned(),
            format!("per_page={}", self.per_page),
        ];
        if self.alert_number.is_none() {
            values.push(format!("page={}", self.page));
            if let Some(cursor) = &self.cursor {
                values.push(format!("after={}", cursor.token_digest()));
            }
        }
        values.join("&")
    }

    pub fn path_and_query(&self) -> String {
        self.path()
    }

    pub fn validate(&self, scope: &GithubSecretScanningScope) -> Result<(), ProviderError> {
        if self.method() != "GET"
            || !self.hide_secret
            || self.per_page == 0
            || self.per_page > MAX_PAGE_SIZE
            || self
                .cursor
                .as_ref()
                .is_some_and(|cursor| cursor.validate().is_err())
            || self.query_digest
                != scope.query.query_digest_for_request(
                    self.page,
                    self.per_page,
                    self.cursor.as_ref(),
                )
        {
            return Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "request_binding_mismatch",
            ));
        }
        if let Some(number) = self.alert_number
            && number != scope.alert_number
        {
            return Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "alert_binding_mismatch",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubSecretScanningPage {
    pub operation: SecretScanningOperation,
    pub target: AlertTarget,
    pub page: u16,
    pub items: Vec<GithubSecretScanningAlert>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: u64,
    pub status: u16,
    pub rate: RedactedRateReceipt,
    pub query_digest: Digest,
    pub response_digest: Digest,
}

pub type AlertPage = GithubSecretScanningPage;

impl GithubSecretScanningPage {
    pub fn new(
        operation: SecretScanningOperation,
        target: AlertTarget,
        page: u16,
        items: Vec<GithubSecretScanningAlert>,
        next_cursor: Option<OpaqueCursor>,
        query_digest: Digest,
        rate: RedactedRateReceipt,
    ) -> Result<Self, ProviderError> {
        if page == 0 || items.len() > usize::from(MAX_PAGE_SIZE) || items.len() > MAX_ALERTS {
            return Err(ProviderError::new(
                ProviderErrorKind::ResponseTooLarge,
                "page_bound",
            ));
        }
        let response_bytes = serde_json::to_vec(&(&operation, &target, page, &items, &next_cursor))
            .map(|bytes| bytes.len() as u64)
            .map_err(|_| ProviderError::new(ProviderErrorKind::Tampered, "response_encoding"))?;
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::new(
                ProviderErrorKind::ResponseTooLarge,
                "response_bytes_bound",
            ));
        }
        query_digest
            .validate()
            .map_err(|_| ProviderError::new(ProviderErrorKind::Tampered, "query_digest"))?;
        let response_digest = Digest::from_serialized(&(
            &operation,
            &target,
            page,
            &items,
            &next_cursor,
            response_bytes,
            200_u16,
            &rate,
            &query_digest,
        ));
        Ok(Self {
            operation,
            target,
            page,
            items,
            next_cursor,
            response_bytes,
            status: 200,
            rate,
            query_digest,
            response_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.status != 200
            || self.page == 0
            || self.items.len() > usize::from(MAX_PAGE_SIZE)
            || self.items.len() > MAX_ALERTS
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self
                .next_cursor
                .as_ref()
                .is_some_and(|cursor| cursor.validate().is_err())
            || self.items.iter().any(|item| item.validate().is_err())
        {
            return Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "page_integrity",
            ));
        }
        self.query_digest
            .validate()
            .map_err(|_| ProviderError::new(ProviderErrorKind::Tampered, "query_digest"))?;
        let expected = Digest::from_serialized(&(
            &self.operation,
            &self.target,
            self.page,
            &self.items,
            &self.next_cursor,
            self.response_bytes,
            self.status,
            &self.rate,
            &self.query_digest,
        ));
        if expected != self.response_digest {
            Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "page_digest",
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubSecretScanningAlertResponse {
    pub operation: SecretScanningOperation,
    pub target: AlertTarget,
    pub alert: GithubSecretScanningAlert,
    pub response_bytes: u64,
    pub status: u16,
    pub rate: RedactedRateReceipt,
    pub query_digest: Digest,
    pub response_digest: Digest,
}

pub type AlertResponse = GithubSecretScanningAlertResponse;

impl GithubSecretScanningAlertResponse {
    pub fn new(
        operation: SecretScanningOperation,
        target: AlertTarget,
        alert: GithubSecretScanningAlert,
        query_digest: Digest,
        rate: RedactedRateReceipt,
    ) -> Result<Self, ProviderError> {
        let response_bytes = serde_json::to_vec(&(&operation, &target, &alert))
            .map(|bytes| bytes.len() as u64)
            .map_err(|_| ProviderError::new(ProviderErrorKind::Tampered, "response_encoding"))?;
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::new(
                ProviderErrorKind::ResponseTooLarge,
                "response_bytes_bound",
            ));
        }
        let response_digest = Digest::from_serialized(&(
            &operation,
            &target,
            &alert,
            response_bytes,
            200_u16,
            &rate,
            &query_digest,
        ));
        Ok(Self {
            operation,
            target,
            alert,
            response_bytes,
            status: 200,
            rate,
            query_digest,
            response_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.status != 200 || self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "alert_integrity",
            ));
        }
        self.alert
            .validate()
            .map_err(|_| ProviderError::new(ProviderErrorKind::Tampered, "alert_integrity"))?;
        let expected = Digest::from_serialized(&(
            &self.operation,
            &self.target,
            &self.alert,
            self.response_bytes,
            self.status,
            &self.rate,
            &self.query_digest,
        ));
        if expected != self.response_digest {
            Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "alert_digest",
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GithubSecretScanningResponse {
    Page(GithubSecretScanningPage),
    Alert(GithubSecretScanningAlertResponse),
}

pub type ProviderResponse = GithubSecretScanningResponse;

pub trait GithubSecretScanningTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;
    fn execute(
        &mut self,
        request: &GithubSecretScanningRequest,
    ) -> Result<GithubSecretScanningResponse, ProviderError>;
}

#[derive(Clone, Debug)]
pub struct GithubSecretScanningProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: Revision,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
}

pub type GithubProviderDefinition = GithubSecretScanningProviderDefinition;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ProviderDefinitionError {
    #[error("provider definition is invalid")]
    Invalid,
}

impl GithubSecretScanningProviderDefinition {
    pub fn layer1() -> Result<Self, ProviderDefinitionError> {
        Self::new(PermissionSnapshot::least_privilege())
    }

    pub fn new(permissions: PermissionSnapshot) -> Result<Self, ProviderDefinitionError> {
        permissions
            .validate()
            .map_err(|_| ProviderDefinitionError::Invalid)?;
        let api_revision = PROVIDER_API_REVISION.to_owned();
        let api_digest = Digest::from_parts(
            "github-secret-scanning-api/v1",
            &[
                PROVIDER_ID.to_owned(),
                api_revision.clone(),
                ALERTS_REPOSITORY_ENDPOINT.to_owned(),
                ALERTS_ORG_ENDPOINT.to_owned(),
                ALERT_ENDPOINT.to_owned(),
                "GET".to_owned(),
                "hide_secret=true".to_owned(),
            ],
        );
        let provider_digest = Digest::from_serialized(&(
            PROVIDER_ID,
            PROVIDER_VERSION,
            1_u64,
            &api_revision,
            &api_digest,
            permissions.digest(),
            [
                SecretScanningOperation::ListRepositoryAlerts,
                SecretScanningOperation::ListOrganizationAlerts,
                SecretScanningOperation::GetRepositoryAlert,
                SecretScanningOperation::GetOrganizationAlertFromBoundedList,
            ],
            false,
            false,
            false,
        ));
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PROVIDER_VERSION.to_owned(),
            provider_revision: Revision::new(1).map_err(|_| ProviderDefinitionError::Invalid)?,
            api_revision,
            provider_digest,
            api_digest,
            permission_digest: permissions.digest().clone(),
        })
    }

    pub fn validate(
        &self,
        permissions: &PermissionSnapshot,
    ) -> Result<(), ProviderDefinitionError> {
        if self.provider_id != PROVIDER_ID
            || self.provider_version != PROVIDER_VERSION
            || self.api_revision != PROVIDER_API_REVISION
            || self.provider_revision.get() == 0
            || self.permission_digest != *permissions.digest()
            || self.api_digest != Self::computed_api_digest(&self.api_revision)
            || self.provider_digest
                != Self::computed_provider_digest(
                    &self.api_revision,
                    &self.api_digest,
                    self.permission_digest.clone(),
                )
        {
            Err(ProviderDefinitionError::Invalid)
        } else {
            Ok(())
        }
    }

    fn computed_api_digest(api_revision: &str) -> Digest {
        Digest::from_parts(
            "github-secret-scanning-api/v1",
            &[
                PROVIDER_ID.to_owned(),
                api_revision.to_owned(),
                ALERTS_REPOSITORY_ENDPOINT.to_owned(),
                ALERTS_ORG_ENDPOINT.to_owned(),
                ALERT_ENDPOINT.to_owned(),
                "GET".to_owned(),
                "hide_secret=true".to_owned(),
            ],
        )
    }

    fn computed_provider_digest(
        api_revision: &str,
        api_digest: &Digest,
        permission_digest: Digest,
    ) -> Digest {
        Digest::from_serialized(&(
            PROVIDER_ID,
            PROVIDER_VERSION,
            1_u64,
            api_revision,
            api_digest,
            permission_digest,
            [
                SecretScanningOperation::ListRepositoryAlerts,
                SecretScanningOperation::ListOrganizationAlerts,
                SecretScanningOperation::GetRepositoryAlert,
                SecretScanningOperation::GetOrganizationAlertFromBoundedList,
            ],
            false,
            false,
            false,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct GithubSecretScanningProvider<T> {
    transport: T,
    definition: GithubSecretScanningProviderDefinition,
    provenance: TransportProvenance,
}

impl<T: GithubSecretScanningTransport> GithubSecretScanningProvider<T> {
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let definition = GithubSecretScanningProviderDefinition::layer1()?;
        let provenance = transport.provenance();
        if provenance.connected() || provenance.native() || provenance.first_party() {
            return Err(ProviderDefinitionError::Invalid);
        }
        Ok(Self {
            transport,
            definition,
            provenance,
        })
    }

    pub fn with_definition(
        transport: T,
        definition: GithubSecretScanningProviderDefinition,
    ) -> Result<Self, ProviderDefinitionError> {
        let provenance = transport.provenance();
        if provenance.connected() || provenance.native() || provenance.first_party() {
            return Err(ProviderDefinitionError::Invalid);
        }
        definition.validate(&PermissionSnapshot::least_privilege())?;
        Ok(Self {
            transport,
            definition,
            provenance,
        })
    }

    pub fn definition(&self) -> &GithubSecretScanningProviderDefinition {
        &self.definition
    }

    pub const fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn list_repository_alerts(
        &mut self,
        scope: &GithubSecretScanningScope,
        page: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<GithubSecretScanningPage, ProviderError> {
        let request = GithubSecretScanningRequest::list_repository(scope, page, cursor)?;
        self.execute_page(scope, request)
    }

    pub fn list_organization_alerts(
        &mut self,
        scope: &GithubSecretScanningScope,
        page: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<GithubSecretScanningPage, ProviderError> {
        let request = GithubSecretScanningRequest::list_organization(scope, page, cursor)?;
        self.execute_page(scope, request)
    }

    pub fn get_repository_alert(
        &mut self,
        scope: &GithubSecretScanningScope,
        alert_number: AlertNumber,
    ) -> Result<GithubSecretScanningAlertResponse, ProviderError> {
        let request = GithubSecretScanningRequest::get_repository(scope, alert_number)?;
        let response = self.execute(&request, scope)?;
        match response {
            GithubSecretScanningResponse::Alert(response) => Ok(response),
            GithubSecretScanningResponse::Page(_) => Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "expected_alert_response",
            )),
        }
    }

    fn execute_page(
        &mut self,
        scope: &GithubSecretScanningScope,
        request: GithubSecretScanningRequest,
    ) -> Result<GithubSecretScanningPage, ProviderError> {
        let response = self.execute(&request, scope)?;
        match response {
            GithubSecretScanningResponse::Page(page) => Ok(page),
            GithubSecretScanningResponse::Alert(_) => Err(ProviderError::new(
                ProviderErrorKind::Tampered,
                "expected_page_response",
            )),
        }
    }

    fn execute(
        &mut self,
        request: &GithubSecretScanningRequest,
        scope: &GithubSecretScanningScope,
    ) -> Result<GithubSecretScanningResponse, ProviderError> {
        scope
            .validate()
            .map_err(|_| ProviderError::new(ProviderErrorKind::Tampered, "scope_invalid"))?;
        request.validate(scope)?;
        let response = self.transport.execute(request)?;
        match &response {
            GithubSecretScanningResponse::Page(page) => {
                page.validate()?;
                if page.page != request.page
                    || page.operation != request.operation
                    || page.target != request.target
                    || page.query_digest != request.query_digest
                {
                    return Err(ProviderError::new(
                        ProviderErrorKind::Tampered,
                        "page_request_mismatch",
                    ));
                }
            }
            GithubSecretScanningResponse::Alert(alert) => {
                alert.validate()?;
                if alert.operation != request.operation
                    || alert.target != request.target
                    || alert.query_digest != request.query_digest
                    || alert.alert.number != request.alert_number.unwrap_or(scope.alert_number)
                {
                    return Err(ProviderError::new(
                        ProviderErrorKind::Tampered,
                        "alert_request_mismatch",
                    ));
                }
            }
        }
        Ok(response)
    }
}

impl GithubSecretScanningProvider<FixtureTransport> {
    pub fn fixture(
        responses: impl IntoIterator<Item = Result<GithubSecretScanningResponse, ProviderError>>,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new(FixtureTransport::fixture(responses))
    }
}

impl GithubSecretScanningProvider<RecordingTransport> {
    pub fn recording(
        responses: impl IntoIterator<Item = Result<GithubSecretScanningResponse, ProviderError>>,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new(RecordingTransport::fixture(responses))
    }
}

impl GithubSecretScanningProvider<LoopbackTransport> {
    pub fn loopback(
        responses: impl IntoIterator<Item = Result<GithubSecretScanningResponse, ProviderError>>,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new(LoopbackTransport::fixture(responses))
    }
}

impl GithubSecretScanningProvider<BlockedEnvTransport> {
    pub fn blocked_env() -> Result<Self, ProviderDefinitionError> {
        Self::new(BlockedEnvTransport)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    responses: VecDeque<Result<GithubSecretScanningResponse, ProviderError>>,
    requests: Vec<GithubSecretScanningRequest>,
}

impl FixtureTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<GithubSecretScanningResponse, ProviderError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn fixture(
        responses: impl IntoIterator<Item = Result<GithubSecretScanningResponse, ProviderError>>,
    ) -> Self {
        Self::new(responses)
    }

    pub fn requests(&self) -> &[GithubSecretScanningRequest] {
        &self.requests
    }
}

impl GithubSecretScanningTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        request: &GithubSecretScanningRequest,
    ) -> Result<GithubSecretScanningResponse, ProviderError> {
        self.requests.push(request.clone());
        self.responses.pop_front().unwrap_or_else(|| {
            Err(ProviderError::new(
                ProviderErrorKind::ScriptExhausted,
                "fixture_exhausted",
            ))
        })
    }
}

pub type FakeGithubSecretScanningTransport = FixtureTransport;
pub type FixtureGithubSecretScanningTransport = FixtureTransport;

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    responses: VecDeque<Result<GithubSecretScanningResponse, ProviderError>>,
    requests: Vec<GithubSecretScanningRequest>,
}

impl RecordingTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<GithubSecretScanningResponse, ProviderError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn fixture(
        responses: impl IntoIterator<Item = Result<GithubSecretScanningResponse, ProviderError>>,
    ) -> Self {
        Self::new(responses)
    }

    pub fn requests(&self) -> &[GithubSecretScanningRequest] {
        &self.requests
    }

    pub fn into_requests(self) -> Vec<GithubSecretScanningRequest> {
        self.requests
    }
}

impl GithubSecretScanningTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &GithubSecretScanningRequest,
    ) -> Result<GithubSecretScanningResponse, ProviderError> {
        self.requests.push(request.clone());
        self.responses.pop_front().unwrap_or_else(|| {
            Err(ProviderError::new(
                ProviderErrorKind::ScriptExhausted,
                "recording_exhausted",
            ))
        })
    }
}

pub type RecordingGithubSecretScanningTransport = RecordingTransport;

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    responses: VecDeque<Result<GithubSecretScanningResponse, ProviderError>>,
    requests: Vec<GithubSecretScanningRequest>,
}

impl LoopbackTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<GithubSecretScanningResponse, ProviderError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn fixture(
        responses: impl IntoIterator<Item = Result<GithubSecretScanningResponse, ProviderError>>,
    ) -> Self {
        Self::new(responses)
    }

    pub fn requests(&self) -> &[GithubSecretScanningRequest] {
        &self.requests
    }
}

impl GithubSecretScanningTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &GithubSecretScanningRequest,
    ) -> Result<GithubSecretScanningResponse, ProviderError> {
        self.requests.push(request.clone());
        self.responses.pop_front().unwrap_or_else(|| {
            Err(ProviderError::new(
                ProviderErrorKind::ScriptExhausted,
                "loopback_exhausted",
            ))
        })
    }
}

pub type LoopbackGithubSecretScanningTransport = LoopbackTransport;

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl GithubSecretScanningTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &GithubSecretScanningRequest,
    ) -> Result<GithubSecretScanningResponse, ProviderError> {
        Err(ProviderError::new(
            ProviderErrorKind::BlockedEnv,
            "BLOCKED_ENV",
        ))
    }
}

pub type BlockedEnvGithubSecretScanningTransport = BlockedEnvTransport;
