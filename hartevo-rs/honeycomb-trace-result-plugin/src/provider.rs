use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    HONEYCOMB_TRACE_RESULT_PROVIDER_ID, HONEYCOMB_TRACE_RESULT_PROVIDER_VERSION,
    model::{
        ApiVersion, DatasetId, Digest, EnvironmentId, HoneycombApiVersion, HoneycombPermission,
        HoneycombRegion, HoneycombTraceScope, ProviderErrorKind, QueryId, QueryResultId,
        QueryResultSnapshot, QueryResultState, TeamId,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty or malformed")]
    InvalidVersion,
    #[error("Honeycomb region is not supported by the Layer-1 contract")]
    UnsupportedRegion,
    #[error("Honeycomb API version is not the supported V1 query-data version")]
    ApiVersionMismatch,
    #[error("provider is missing the explicit Run Queries permission")]
    MissingRunQueriesPermission,
    #[error("provider is missing the explicit Manage Queries permission")]
    MissingManageQueriesPermission,
    #[error("Layer 1 cannot register a native or connected provider")]
    NativeProviderForbidden,
    #[error("provider definition digest or identity is tampered")]
    TamperedDefinition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HoneycombProviderDefinition {
    pub id: String,
    pub version: String,
    pub region: HoneycombRegion,
    pub api_version: HoneycombApiVersion,
    pub permissions: Vec<HoneycombPermission>,
    pub permission_digest: Digest,
    pub provenance: ProviderProvenance,
    pub native: bool,
    pub connected: bool,
    pub provider_digest: Digest,
}

impl HoneycombProviderDefinition {
    pub fn new(
        region: HoneycombRegion,
        api_version: HoneycombApiVersion,
        permissions: impl IntoIterator<Item = HoneycombPermission>,
        provenance: ProviderProvenance,
        version: impl Into<String>,
    ) -> Result<Self, ProviderDefinitionError> {
        let version = version.into();
        if version.is_empty()
            || version.len() > 64
            || !version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(ProviderDefinitionError::InvalidVersion);
        }
        if api_version != HoneycombApiVersion::V1 {
            return Err(ProviderDefinitionError::ApiVersionMismatch);
        }
        let permission_set = permissions
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        if !permission_set.contains(&HoneycombPermission::RunQueries) {
            return Err(ProviderDefinitionError::MissingRunQueriesPermission);
        }
        if !permission_set.contains(&HoneycombPermission::ManageQueries) {
            return Err(ProviderDefinitionError::MissingManageQueriesPermission);
        }
        let permissions = permission_set.into_iter().collect::<Vec<_>>();
        let permission_digest = Digest::from_fields(
            "honeycomb-permission-scope/v1",
            &permissions
                .iter()
                .map(|permission| permission.api_name().to_owned())
                .collect::<Vec<_>>(),
        );
        if provenance.is_native() || provenance.is_connected() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let provider_digest = Digest::from_fields(
            "honeycomb-provider-definition/v1",
            &[
                HONEYCOMB_TRACE_RESULT_PROVIDER_ID.to_owned(),
                version.clone(),
                region.as_str().to_owned(),
                api_version.as_str().to_owned(),
                permission_digest.as_str().to_owned(),
                format!("{provenance:?}"),
                "native=false".to_owned(),
                "connected=false".to_owned(),
            ],
        );
        Ok(Self {
            id: HONEYCOMB_TRACE_RESULT_PROVIDER_ID.to_owned(),
            version,
            region,
            api_version,
            permissions: permissions.clone(),
            permission_digest,
            provenance,
            native: false,
            connected: false,
            provider_digest,
        })
    }

    pub fn layer1(
        region: HoneycombRegion,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new(
            region,
            HoneycombApiVersion::V1,
            [
                HoneycombPermission::RunQueries,
                HoneycombPermission::ManageQueries,
            ],
            provenance,
            HONEYCOMB_TRACE_RESULT_PROVIDER_VERSION,
        )
    }

    pub fn validate_scope(
        &self,
        scope: &HoneycombTraceScope,
    ) -> Result<(), ProviderDefinitionError> {
        self.validate()?;
        if self.region != scope.region {
            return Err(ProviderDefinitionError::UnsupportedRegion);
        }
        if self.api_version != scope.api_version {
            return Err(ProviderDefinitionError::ApiVersionMismatch);
        }
        if self.permission_digest != *scope.permission_digest() {
            return Err(ProviderDefinitionError::MissingRunQueriesPermission);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.id != HONEYCOMB_TRACE_RESULT_PROVIDER_ID
            || self.api_version != HoneycombApiVersion::V1
            || self.native
            || self.connected
            || self.provenance.is_native()
            || self.provenance.is_connected()
        {
            return Err(ProviderDefinitionError::TamperedDefinition);
        }
        let required = [
            HoneycombPermission::RunQueries,
            HoneycombPermission::ManageQueries,
        ];
        if required
            .iter()
            .any(|permission| !self.permissions.contains(permission))
        {
            return Err(ProviderDefinitionError::TamperedDefinition);
        }
        let permission_digest = Digest::from_fields(
            "honeycomb-permission-scope/v1",
            &self
                .permissions
                .iter()
                .map(|permission| permission.api_name().to_owned())
                .collect::<Vec<_>>(),
        );
        let expected = Digest::from_fields(
            "honeycomb-provider-definition/v1",
            &[
                HONEYCOMB_TRACE_RESULT_PROVIDER_ID.to_owned(),
                self.version.clone(),
                self.region.as_str().to_owned(),
                self.api_version.as_str().to_owned(),
                permission_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
                "native=false".to_owned(),
                "connected=false".to_owned(),
            ],
        );
        if permission_digest != self.permission_digest || expected != self.provider_digest {
            Err(ProviderDefinitionError::TamperedDefinition)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.provider_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryCreateRequest {
    pub region: HoneycombRegion,
    pub api_version: HoneycombApiVersion,
    pub team: TeamId,
    pub environment: EnvironmentId,
    pub dataset: DatasetId,
    pub query: crate::HoneycombQuery,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub path: String,
    pub content_type: String,
    pub native_execution: bool,
}

impl QueryCreateRequest {
    pub fn from_scope(scope: &HoneycombTraceScope) -> Self {
        Self {
            region: scope.region,
            api_version: scope.api_version,
            team: scope.team.clone(),
            environment: scope.environment.clone(),
            dataset: scope.dataset.clone(),
            query: scope.query.clone(),
            query_digest: scope.query_digest().clone(),
            scope_digest: scope.digest().clone(),
            path: format!("/1/queries/{}", scope.dataset.as_str()),
            content_type: scope.api_version.content_type().to_owned(),
            native_execution: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryCreateResponse {
    pub query_id: QueryId,
    pub region: HoneycombRegion,
    pub api_version: HoneycombApiVersion,
    pub team: TeamId,
    pub environment: EnvironmentId,
    pub dataset: DatasetId,
    pub query_digest: Digest,
    pub response_digest: Digest,
}

impl QueryCreateResponse {
    pub fn recorded(
        request: &QueryCreateRequest,
        query_id: QueryId,
        response_digest: Digest,
    ) -> Self {
        Self {
            query_id,
            region: request.region,
            api_version: request.api_version,
            team: request.team.clone(),
            environment: request.environment.clone(),
            dataset: request.dataset.clone(),
            query_digest: request.query_digest.clone(),
            response_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryResultCreateRequest {
    pub region: HoneycombRegion,
    pub api_version: HoneycombApiVersion,
    pub team: TeamId,
    pub environment: EnvironmentId,
    pub dataset: DatasetId,
    pub query_id: QueryId,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub limit: u16,
    pub disable_series: bool,
    pub disable_total_by_aggregate: bool,
    pub disable_other_by_aggregate: bool,
    pub path: String,
    pub content_type: String,
    pub native_execution: bool,
}

impl QueryResultCreateRequest {
    pub fn from_scope(scope: &HoneycombTraceScope, query_id: QueryId) -> Self {
        Self {
            region: scope.region,
            api_version: scope.api_version,
            team: scope.team.clone(),
            environment: scope.environment.clone(),
            dataset: scope.dataset.clone(),
            query_id,
            query_digest: scope.query_digest().clone(),
            scope_digest: scope.digest().clone(),
            limit: scope.query.limit(),
            disable_series: false,
            disable_total_by_aggregate: true,
            disable_other_by_aggregate: true,
            path: format!("/1/query_results/{}", scope.dataset.as_str()),
            content_type: scope.api_version.content_type().to_owned(),
            native_execution: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryResultCreateResponse {
    pub query_id: QueryId,
    pub query_result_id: QueryResultId,
    pub region: HoneycombRegion,
    pub api_version: HoneycombApiVersion,
    pub team: TeamId,
    pub environment: EnvironmentId,
    pub dataset: DatasetId,
    pub query_digest: Digest,
    pub state: QueryResultState,
    pub response_digest: Digest,
}

impl QueryResultCreateResponse {
    pub fn recorded(
        request: &QueryResultCreateRequest,
        query_result_id: QueryResultId,
        state: QueryResultState,
        response_digest: Digest,
    ) -> Self {
        Self {
            query_id: request.query_id.clone(),
            query_result_id,
            region: request.region,
            api_version: request.api_version,
            team: request.team.clone(),
            environment: request.environment.clone(),
            dataset: request.dataset.clone(),
            query_digest: request.query_digest.clone(),
            state,
            response_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryResultGetRequest {
    pub region: HoneycombRegion,
    pub api_version: HoneycombApiVersion,
    pub team: TeamId,
    pub environment: EnvironmentId,
    pub dataset: DatasetId,
    pub query_id: QueryId,
    pub query_result_id: QueryResultId,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub path: String,
    pub native_readback: bool,
}

impl QueryResultGetRequest {
    pub fn from_scope(
        scope: &HoneycombTraceScope,
        query_id: QueryId,
        query_result_id: QueryResultId,
    ) -> Self {
        let path = format!(
            "/1/query_results/{}/{}",
            scope.dataset.as_str(),
            query_result_id.as_str()
        );
        Self {
            region: scope.region,
            api_version: scope.api_version,
            team: scope.team.clone(),
            environment: scope.environment.clone(),
            dataset: scope.dataset.clone(),
            query_id,
            query_result_id,
            query_digest: scope.query_digest().clone(),
            scope_digest: scope.digest().clone(),
            path,
            native_readback: false,
        }
    }
}

pub type QueryResultGetResponse = QueryResultSnapshot;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub retry_after_seconds: Option<u64>,
    pub diagnostic_digest: Digest,
}

impl TransportError {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        retry_after_seconds: Option<u64>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            kind,
            status_code,
            retryable: matches!(
                kind,
                ProviderErrorKind::RateLimited
                    | ProviderErrorKind::ServerFailure
                    | ProviderErrorKind::Timeout
            ),
            retry_after_seconds,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn from_status(status_code: u16, diagnostic: impl AsRef<[u8]>) -> Self {
        let kind = match status_code {
            400 => ProviderErrorKind::BadRequest,
            401 => ProviderErrorKind::Unauthenticated,
            403 => ProviderErrorKind::PermissionDenied,
            404 => ProviderErrorKind::NotFound,
            415 => ProviderErrorKind::UnsupportedMediaType,
            429 => ProviderErrorKind::RateLimited,
            500..=599 => ProviderErrorKind::ServerFailure,
            _ => ProviderErrorKind::Unknown,
        };
        Self::new(kind, Some(status_code), None, diagnostic)
    }
}

pub trait HoneycombQueryTransport: fmt::Debug {
    fn create_query(
        &mut self,
        request: &QueryCreateRequest,
    ) -> Result<QueryCreateResponse, TransportError>;

    fn create_query_result(
        &mut self,
        request: &QueryResultCreateRequest,
    ) -> Result<QueryResultCreateResponse, TransportError>;

    fn get_query_result(
        &mut self,
        request: &QueryResultGetRequest,
    ) -> Result<QueryResultSnapshot, TransportError>;
}

pub struct HoneycombQueryProvider<T> {
    transport: T,
    definition: HoneycombProviderDefinition,
}

impl<T: fmt::Debug> fmt::Debug for HoneycombQueryProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HoneycombQueryProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: HoneycombQueryTransport> HoneycombQueryProvider<T> {
    pub fn new(
        transport: T,
        region: HoneycombRegion,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let definition = HoneycombProviderDefinition::layer1(region, provenance)?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn with_definition(
        transport: T,
        definition: HoneycombProviderDefinition,
    ) -> Result<Self, ProviderDefinitionError> {
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &HoneycombProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.definition.provenance
    }

    pub fn provider_digest(&self) -> &Digest {
        self.definition.digest()
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    pub fn create_query(
        &mut self,
        request: &QueryCreateRequest,
    ) -> Result<QueryCreateResponse, TransportError> {
        self.validate_request(
            request.region,
            request.api_version,
            request.scope_digest.as_str(),
        )?;
        request.query.validate().map_err(|_| {
            TransportError::new(
                ProviderErrorKind::QueryDrift,
                None,
                None,
                "typed query AST digest or bounds are invalid",
            )
        })?;
        if request.native_execution {
            return Err(TransportError::new(
                ProviderErrorKind::BlockedEnv,
                None,
                None,
                "native query execution is a Layer-2 gap",
            ));
        }
        self.transport.create_query(request)
    }

    pub fn create_query_result(
        &mut self,
        request: &QueryResultCreateRequest,
    ) -> Result<QueryResultCreateResponse, TransportError> {
        self.validate_request(
            request.region,
            request.api_version,
            request.scope_digest.as_str(),
        )?;
        if !(1..=crate::MAX_LIMIT).contains(&request.limit) {
            return Err(TransportError::new(
                ProviderErrorKind::BadRequest,
                Some(400),
                None,
                "query-result limit exceeds the bounded Layer-1 ceiling",
            ));
        }
        if request.native_execution {
            return Err(TransportError::new(
                ProviderErrorKind::BlockedEnv,
                None,
                None,
                "native query-result execution is a Layer-2 gap",
            ));
        }
        self.transport.create_query_result(request)
    }

    pub fn get_query_result(
        &mut self,
        request: &QueryResultGetRequest,
    ) -> Result<QueryResultSnapshot, TransportError> {
        self.validate_request(
            request.region,
            request.api_version,
            request.scope_digest.as_str(),
        )?;
        if request.native_readback {
            return Err(TransportError::new(
                ProviderErrorKind::BlockedEnv,
                None,
                None,
                "native query-result readback is a Layer-2 gap",
            ));
        }
        self.transport.get_query_result(request)
    }

    fn validate_request(
        &self,
        region: HoneycombRegion,
        api_version: ApiVersion,
        scope_digest: &str,
    ) -> Result<(), TransportError> {
        if region != self.definition.region {
            return Err(TransportError::new(
                ProviderErrorKind::RegionMismatch,
                None,
                None,
                "provider region does not match the registered scope",
            ));
        }
        if api_version != self.definition.api_version {
            return Err(TransportError::new(
                ProviderErrorKind::ApiVersionMismatch,
                None,
                None,
                "provider API version does not match the registered scope",
            ));
        }
        if crate::model::Digest::parse(scope_digest.to_owned()).is_err() {
            return Err(TransportError::new(
                ProviderErrorKind::ScopeDrift,
                None,
                None,
                "scope digest is malformed",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum TransportCall {
    CreateQuery(String),
    CreateQueryResult(String),
    GetQueryResult(String),
}

#[derive(Clone, Debug, Default)]
pub struct RecordingHoneycombTransport {
    query_responses: VecDeque<Result<QueryCreateResponse, TransportError>>,
    query_result_responses: VecDeque<Result<QueryResultCreateResponse, TransportError>>,
    get_responses: VecDeque<Result<QueryResultSnapshot, TransportError>>,
    calls: Vec<TransportCall>,
}

impl RecordingHoneycombTransport {
    pub fn push_query_response(&mut self, response: Result<QueryCreateResponse, TransportError>) {
        self.query_responses.push_back(response);
    }

    pub fn push_query_result_response(
        &mut self,
        response: Result<QueryResultCreateResponse, TransportError>,
    ) {
        self.query_result_responses.push_back(response);
    }

    pub fn push_get_response(&mut self, response: Result<QueryResultSnapshot, TransportError>) {
        self.get_responses.push_back(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }
}

impl HoneycombQueryTransport for RecordingHoneycombTransport {
    fn create_query(
        &mut self,
        request: &QueryCreateRequest,
    ) -> Result<QueryCreateResponse, TransportError> {
        self.calls
            .push(TransportCall::CreateQuery(request.path.clone()));
        self.query_responses.pop_front().unwrap_or_else(|| {
            Err(TransportError::new(
                ProviderErrorKind::Unknown,
                None,
                None,
                "recording transport has no query response",
            ))
        })
    }

    fn create_query_result(
        &mut self,
        request: &QueryResultCreateRequest,
    ) -> Result<QueryResultCreateResponse, TransportError> {
        self.calls
            .push(TransportCall::CreateQueryResult(request.path.clone()));
        self.query_result_responses.pop_front().unwrap_or_else(|| {
            Err(TransportError::new(
                ProviderErrorKind::Unknown,
                None,
                None,
                "recording transport has no query-result response",
            ))
        })
    }

    fn get_query_result(
        &mut self,
        request: &QueryResultGetRequest,
    ) -> Result<QueryResultSnapshot, TransportError> {
        self.calls
            .push(TransportCall::GetQueryResult(request.path.clone()));
        self.get_responses.pop_front().unwrap_or_else(|| {
            Err(TransportError::new(
                ProviderErrorKind::Unknown,
                None,
                None,
                "recording transport has no GET response",
            ))
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureHoneycombTransport {
    inner: RecordingHoneycombTransport,
}

impl FixtureHoneycombTransport {
    pub fn push_query_response(&mut self, response: Result<QueryCreateResponse, TransportError>) {
        self.inner.push_query_response(response);
    }

    pub fn push_query_result_response(
        &mut self,
        response: Result<QueryResultCreateResponse, TransportError>,
    ) {
        self.inner.push_query_result_response(response);
    }

    pub fn push_get_response(&mut self, response: Result<QueryResultSnapshot, TransportError>) {
        self.inner.push_get_response(response);
    }
}

impl HoneycombQueryTransport for FixtureHoneycombTransport {
    fn create_query(
        &mut self,
        request: &QueryCreateRequest,
    ) -> Result<QueryCreateResponse, TransportError> {
        self.inner.create_query(request)
    }

    fn create_query_result(
        &mut self,
        request: &QueryResultCreateRequest,
    ) -> Result<QueryResultCreateResponse, TransportError> {
        self.inner.create_query_result(request)
    }

    fn get_query_result(
        &mut self,
        request: &QueryResultGetRequest,
    ) -> Result<QueryResultSnapshot, TransportError> {
        self.inner.get_query_result(request)
    }
}

pub type FakeHoneycombTransport = FixtureHoneycombTransport;

#[derive(Clone, Debug)]
pub struct LoopbackHoneycombTransport {
    query_id: QueryId,
    query_result_id: QueryResultId,
    snapshot: QueryResultSnapshot,
}

impl LoopbackHoneycombTransport {
    pub fn new(
        query_id: QueryId,
        query_result_id: QueryResultId,
        snapshot: QueryResultSnapshot,
    ) -> Self {
        Self {
            query_id,
            query_result_id,
            snapshot,
        }
    }
}

impl HoneycombQueryTransport for LoopbackHoneycombTransport {
    fn create_query(
        &mut self,
        request: &QueryCreateRequest,
    ) -> Result<QueryCreateResponse, TransportError> {
        Ok(QueryCreateResponse::recorded(
            request,
            self.query_id.clone(),
            Digest::from_text("loopback-query-response"),
        ))
    }

    fn create_query_result(
        &mut self,
        request: &QueryResultCreateRequest,
    ) -> Result<QueryResultCreateResponse, TransportError> {
        Ok(QueryResultCreateResponse::recorded(
            request,
            self.query_result_id.clone(),
            self.snapshot.state,
            Digest::from_text("loopback-query-result-response"),
        ))
    }

    fn get_query_result(
        &mut self,
        _request: &QueryResultGetRequest,
    ) -> Result<QueryResultSnapshot, TransportError> {
        Ok(self.snapshot.clone())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvHoneycombTransport;

impl HoneycombQueryTransport for BlockedEnvHoneycombTransport {
    fn create_query(
        &mut self,
        _request: &QueryCreateRequest,
    ) -> Result<QueryCreateResponse, TransportError> {
        Err(TransportError::new(
            ProviderErrorKind::BlockedEnv,
            None,
            None,
            "native Honeycomb credentials and network are unavailable in BLOCKED_ENV",
        ))
    }

    fn create_query_result(
        &mut self,
        _request: &QueryResultCreateRequest,
    ) -> Result<QueryResultCreateResponse, TransportError> {
        Err(TransportError::new(
            ProviderErrorKind::BlockedEnv,
            None,
            None,
            "native Honeycomb credentials and network are unavailable in BLOCKED_ENV",
        ))
    }

    fn get_query_result(
        &mut self,
        _request: &QueryResultGetRequest,
    ) -> Result<QueryResultSnapshot, TransportError> {
        Err(TransportError::new(
            ProviderErrorKind::BlockedEnv,
            None,
            None,
            "native Honeycomb credentials and network are unavailable in BLOCKED_ENV",
        ))
    }
}

pub type BlockedEnvTransport = BlockedEnvHoneycombTransport;
