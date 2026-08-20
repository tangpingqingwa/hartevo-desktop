//! Typed AWS AppConfig provider seams.
//!
//! This module deliberately exposes no AWS SDK, SigV4 signer, credential
//! resolver, HTTP client, configuration-value read, or deployment mutation.

use std::{collections::VecDeque, fmt, fmt::Write as _};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::error::{AwsAppConfigDeploymentError, AwsAppConfigTransportError, Result};
use crate::model::{
    AppConfigDeploymentState, AwsAppConfigDeploymentScope, Cursor, DeploymentEvent,
    DeploymentEventClassification, DeploymentFilter, DeploymentMetadata, DeploymentMetadataInput,
    DeploymentStrategy, DeploymentStrategyId, Digest, TransportProvenance, validate_response_bytes,
};
use crate::service::AwsAppConfigDeploymentRegistration;
use crate::{CONTRACT_VERSION, LAYER1_PERMISSIONS, PROVIDER_API_REVISION, PROVIDER_ID};

pub const LIST_DEPLOYMENTS_OPERATION_PATH: &str =
    "/applications/{applicationId}/environments/{environmentId}/deployments";
pub const GET_DEPLOYMENT_OPERATION_PATH: &str =
    "/applications/{applicationId}/environments/{environmentId}/deployments/{deploymentId}";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsAppConfigOperation {
    ListDeployments,
    GetDeployment,
}

impl AwsAppConfigOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListDeployments => "ListDeployments",
            Self::GetDeployment => "GetDeployment",
        }
    }
}

/// The only provider transport trait exposed by Layer 1.
pub trait AwsAppConfigTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_deployments(
        &mut self,
        request: &ListDeploymentsRequest,
    ) -> std::result::Result<ListDeploymentsResponse, AwsAppConfigTransportError>;

    fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> std::result::Result<GetDeploymentResponse, AwsAppConfigTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsAppConfigOperation,
    pub scope_digest: Digest,
    pub filter_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListDeploymentsRequest {
    scope: AwsAppConfigDeploymentScope,
    filter: DeploymentFilter,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl ListDeploymentsRequest {
    pub fn new(
        scope: &AwsAppConfigDeploymentScope,
        filter: DeploymentFilter,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        scope.validate()?;
        filter.validate_against(scope)?;
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &filter)?;
        }
        let request_digest = Digest::from_parts(
            "aws-appconfig-list-deployments-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("filter", filter.digest().as_str().to_owned()),
                (
                    "cursor",
                    cursor.as_ref().map_or_else(String::new, |value| {
                        value.token_digest().as_str().to_owned()
                    }),
                ),
                (
                    "page",
                    cursor
                        .as_ref()
                        .map_or_else(|| "1".to_owned(), |value| value.page_number().to_string()),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            filter,
            cursor,
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsAppConfigDeploymentScope {
        &self.scope
    }

    pub fn filter(&self) -> &DeploymentFilter {
        &self.filter
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.cursor
            .as_ref()
            .map_or(1, |cursor| cursor.page_number())
    }

    /// The opaque provider token is never retained. Only its digest enters a
    /// path recording or request fence.
    pub fn path_and_query(&self) -> String {
        let mut query = vec![
            (
                "accountId".to_owned(),
                self.scope.account().as_str().to_owned(),
            ),
            ("region".to_owned(), self.scope.region().as_str().to_owned()),
            ("maxResults".to_owned(), self.filter.max_results.to_string()),
        ];
        if let Some(cursor) = &self.cursor {
            query.push((
                "nextToken".to_owned(),
                cursor.token_digest().as_str().to_owned(),
            ));
        }
        let query = query
            .into_iter()
            .map(|(name, value)| format!("{name}={}", percent_encode(&value)))
            .collect::<Vec<_>>()
            .join("&");
        format!(
            "/applications/{}/environments/{}/deployments?{query}",
            percent_encode(self.scope.application().as_str()),
            percent_encode(self.scope.environment().as_str()),
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsAppConfigOperation::ListDeployments,
            scope_digest: self.scope.digest(),
            filter_digest: Some(self.filter.digest()),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for ListDeploymentsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListDeploymentsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("filter", &self.filter)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetDeploymentRequest {
    scope: AwsAppConfigDeploymentScope,
    request_digest: Digest,
}

impl GetDeploymentRequest {
    pub fn for_scope(scope: &AwsAppConfigDeploymentScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-appconfig-get-deployment-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    (
                        "deployment",
                        scope.deployment().digest().as_str().to_owned(),
                    ),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &AwsAppConfigDeploymentScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/applications/{}/environments/{}/deployments/{}?accountId={}&region={}",
            percent_encode(self.scope.application().as_str()),
            percent_encode(self.scope.environment().as_str()),
            percent_encode(self.scope.deployment().as_str()),
            percent_encode(self.scope.account().as_str()),
            percent_encode(self.scope.region().as_str()),
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsAppConfigOperation::GetDeployment,
            scope_digest: self.scope.digest(),
            filter_digest: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for GetDeploymentRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetDeploymentRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDeploymentsResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub deployments: Vec<DeploymentMetadata>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl Eq for ListDeploymentsResponse {}

impl ListDeploymentsResponse {
    pub fn new(
        request: &ListDeploymentsRequest,
        deployments: Vec<DeploymentMetadata>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if deployments.len() > request.filter.max_results as usize {
            return Err(AwsAppConfigDeploymentError::PartialEvidence);
        }
        for deployment in &deployments {
            deployment.validate_list_item_against(request.scope())?;
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsAppConfigDeploymentError::CursorMismatch);
            }
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            deployments,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-appconfig-list-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &ListDeploymentsRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != request.filter().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.deployments.len() > request.filter.max_results as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsAppConfigDeploymentError::TamperedEvidence);
        }
        for deployment in &self.deployments {
            deployment.validate_list_item_against(request.scope())?;
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsAppConfigDeploymentError::CursorMismatch);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appconfig-list-deployments-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "deployments",
                    self.deployments
                        .iter()
                        .map(|deployment| deployment.digest().as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "next_cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
                        }),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDeploymentResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub deployment: DeploymentMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl Eq for GetDeploymentResponse {}

impl GetDeploymentResponse {
    pub fn new(
        request: &GetDeploymentRequest,
        deployment: DeploymentMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        deployment.validate_against(request.scope())?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            deployment,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-appconfig-get-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetDeploymentRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsAppConfigDeploymentError::TamperedEvidence);
        }
        self.deployment.validate_against(request.scope())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appconfig-get-deployment-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("deployment", self.deployment.digest().as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsAppConfigProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub release: String,
    pub contract_version: String,
    pub api_revision: String,
    pub provider_digest: Digest,
}

impl AwsAppConfigProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.trim().is_empty() {
            return Err(AwsAppConfigDeploymentError::ProviderDrift);
        }
        let mut definition = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            release,
            contract_version: CONTRACT_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            provider_digest: Digest::from_text("unsealed-aws-appconfig-provider"),
        };
        definition.provider_digest = definition.calculate_digest();
        Ok(definition)
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.release.trim().is_empty()
            || self.contract_version != CONTRACT_VERSION
            || self.api_revision != PROVIDER_API_REVISION
            || self.provider_digest != self.calculate_digest()
        {
            return Err(AwsAppConfigDeploymentError::ProviderDrift);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appconfig-provider-definition/v1",
            &[
                ("provider_id", self.provider_id.clone()),
                ("revision", self.provider_revision.to_string()),
                ("release", self.release.clone()),
                ("contract", self.contract_version.clone()),
                ("api", self.api_revision.clone()),
                ("permissions", LAYER1_PERMISSIONS.join("\n")),
            ],
        )
    }
}

#[derive(Debug)]
pub struct AwsAppConfigProvider<T> {
    transport: T,
    definition: AwsAppConfigProviderDefinition,
}

impl<T: AwsAppConfigTransport> AwsAppConfigProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording-1")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AwsAppConfigProviderDefinition::new(provider_revision, release)?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsAppConfigProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn list_deployments(
        &mut self,
        request: &ListDeploymentsRequest,
    ) -> std::result::Result<ListDeploymentsResponse, AwsAppConfigTransportError> {
        let response = self.transport.list_deployments(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsAppConfigTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsAppConfigTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> std::result::Result<GetDeploymentResponse, AwsAppConfigTransportError> {
        let response = self.transport.get_deployment(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsAppConfigTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsAppConfigTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl Default for AwsAppConfigProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("default provider definition")
    }
}

impl<T: AwsAppConfigTransport> AwsAppConfigProvider<T> {
    pub fn from_registration(
        registration: &AwsAppConfigDeploymentRegistration,
        transport: T,
    ) -> Result<Self> {
        registration.validate()?;
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(AwsAppConfigDeploymentError::ProviderDrift);
        }
        Ok(provider)
    }
}

#[derive(Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    list_responses:
        VecDeque<std::result::Result<ListDeploymentsResponse, AwsAppConfigTransportError>>,
    get_responses: VecDeque<std::result::Result<GetDeploymentResponse, AwsAppConfigTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            list_responses: VecDeque::new(),
            get_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListDeploymentsResponse, AwsAppConfigTransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_get_response(
        &mut self,
        response: std::result::Result<GetDeploymentResponse, AwsAppConfigTransportError>,
    ) {
        self.get_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl AwsAppConfigTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance.clone()
    }

    fn list_deployments(
        &mut self,
        request: &ListDeploymentsRequest,
    ) -> std::result::Result<ListDeploymentsResponse, AwsAppConfigTransportError> {
        self.requests.push(request.recorded_request());
        self.list_responses
            .pop_front()
            .unwrap_or(Err(AwsAppConfigTransportError::InvalidResponse))
    }

    fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> std::result::Result<GetDeploymentResponse, AwsAppConfigTransportError> {
        self.requests.push(request.recorded_request());
        self.get_responses
            .pop_front()
            .unwrap_or(Err(AwsAppConfigTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsAppConfigDeploymentScope,
    deployment: DeploymentMetadata,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsAppConfigDeploymentScope, observed_at: DateTime<Utc>) -> Self {
        let strategy = DeploymentStrategy::new(
            DeploymentStrategyId::new("linear-10-percent").expect("fixture strategy"),
            Some("fixture-linear".to_owned()),
        )
        .expect("fixture strategy projection");
        let events = vec![
            DeploymentEvent::new(
                1,
                DeploymentEventClassification::Started,
                observed_at - Duration::hours(1),
                "fixture deployment started",
            )
            .expect("fixture event"),
            DeploymentEvent::new(
                2,
                DeploymentEventClassification::Completed,
                observed_at - Duration::minutes(5),
                "fixture deployment completed",
            )
            .expect("fixture event"),
        ];
        let deployment = DeploymentMetadata::new(
            scope,
            DeploymentMetadataInput {
                deployment: scope.deployment().clone(),
                configuration_profile: scope.configuration_profile().clone(),
                configuration_version: scope.configuration_version().clone(),
                strategy,
                state: AppConfigDeploymentState::Complete,
                percentage_complete: 100.0,
                started_at: observed_at - Duration::hours(1),
                last_updated_at: observed_at,
                completed_at: Some(observed_at - Duration::minutes(5)),
                events,
                events_truncated: false,
            },
        )
        .expect("fixture deployment");
        Self {
            scope: scope.clone(),
            deployment,
        }
    }
}

impl AwsAppConfigTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_deployments(
        &mut self,
        request: &ListDeploymentsRequest,
    ) -> std::result::Result<ListDeploymentsResponse, AwsAppConfigTransportError> {
        if request.scope().digest() != self.scope.digest() {
            return Err(AwsAppConfigTransportError::InvalidResponse);
        }
        ListDeploymentsResponse::new(
            request,
            vec![self.deployment.clone()],
            None,
            1_024,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsAppConfigTransportError::InvalidResponse)
    }

    fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> std::result::Result<GetDeploymentResponse, AwsAppConfigTransportError> {
        if request.scope().digest() != self.scope.digest() {
            return Err(AwsAppConfigTransportError::InvalidResponse);
        }
        GetDeploymentResponse::new(
            request,
            self.deployment.clone(),
            1_024,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsAppConfigTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    scope: AwsAppConfigDeploymentScope,
    deployment: DeploymentMetadata,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsAppConfigDeploymentScope, observed_at: DateTime<Utc>) -> Self {
        let strategy = DeploymentStrategy::without_name(
            DeploymentStrategyId::new("canary-5-percent").expect("loopback strategy"),
        )
        .expect("loopback strategy projection");
        let event = DeploymentEvent::new(
            1,
            DeploymentEventClassification::Progressed,
            observed_at,
            "loopback deployment progress",
        )
        .expect("loopback event");
        let deployment = DeploymentMetadata::new(
            scope,
            DeploymentMetadataInput {
                deployment: scope.deployment().clone(),
                configuration_profile: scope.configuration_profile().clone(),
                configuration_version: scope.configuration_version().clone(),
                strategy,
                state: AppConfigDeploymentState::Deploying,
                percentage_complete: 42.5,
                started_at: observed_at - Duration::minutes(20),
                last_updated_at: observed_at,
                completed_at: None,
                events: vec![event],
                events_truncated: false,
            },
        )
        .expect("loopback deployment");
        Self {
            scope: scope.clone(),
            deployment,
        }
    }
}

impl AwsAppConfigTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_deployments(
        &mut self,
        request: &ListDeploymentsRequest,
    ) -> std::result::Result<ListDeploymentsResponse, AwsAppConfigTransportError> {
        if request.scope().digest() != self.scope.digest() {
            return Err(AwsAppConfigTransportError::InvalidResponse);
        }
        ListDeploymentsResponse::new(
            request,
            vec![self.deployment.clone()],
            None,
            1_024,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsAppConfigTransportError::InvalidResponse)
    }

    fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> std::result::Result<GetDeploymentResponse, AwsAppConfigTransportError> {
        if request.scope().digest() != self.scope.digest() {
            return Err(AwsAppConfigTransportError::InvalidResponse);
        }
        GetDeploymentResponse::new(
            request,
            self.deployment.clone(),
            1_024,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsAppConfigTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsAppConfigTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_deployments(
        &mut self,
        _request: &ListDeploymentsRequest,
    ) -> std::result::Result<ListDeploymentsResponse, AwsAppConfigTransportError> {
        Err(AwsAppConfigTransportError::BlockedEnv)
    }

    fn get_deployment(
        &mut self,
        _request: &GetDeploymentRequest,
    ) -> std::result::Result<GetDeploymentResponse, AwsAppConfigTransportError> {
        Err(AwsAppConfigTransportError::BlockedEnv)
    }
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}
