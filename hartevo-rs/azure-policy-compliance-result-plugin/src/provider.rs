use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AZURE_POLICY_API_VERSION, AZURE_POLICY_COMPLIANCE_RESULT_SCHEMA_VERSION,
    AZURE_POLICY_INSIGHTS_PROVIDER_ID, AZURE_POLICY_INSIGHTS_PROVIDER_VERSION,
    model::{
        AzurePolicyRegistration, AzurePolicyScope, ComplianceState, Digest, ModelError,
        ODataFilter, OpaqueNextLink, PolicyStateRecord, ProviderErrorKind, ProviderProvenance,
        ResourceId, SecretReference,
    },
    query::AzurePolicyQuery,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("Layer 1 cannot register a native provider")]
    NativeProviderForbidden,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzurePolicyProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_version: String,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub query_results_resource: bool,
    pub query_results_resource_group: bool,
    pub query_results_subscription: bool,
    pub native: bool,
    pub https_transport: bool,
    pub live_execution: bool,
}

impl AzurePolicyProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provenance.is_native() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let capability_digest = Digest::from_fields(
            "azure-policy-provider-capability/v1",
            &[
                AZURE_POLICY_COMPLIANCE_RESULT_SCHEMA_VERSION.to_owned(),
                AZURE_POLICY_INSIGHTS_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                AZURE_POLICY_API_VERSION.to_owned(),
                format!("{provenance:?}"),
                "queryResults.resource=true".to_owned(),
                "queryResults.resourceGroup=true".to_owned(),
                "queryResults.subscription=true".to_owned(),
                "native=false".to_owned(),
                "https_transport=false".to_owned(),
                "live_execution=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: AZURE_POLICY_COMPLIANCE_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: AZURE_POLICY_INSIGHTS_PROVIDER_ID.to_owned(),
            provider_version,
            api_version: AZURE_POLICY_API_VERSION.to_owned(),
            capability_digest,
            provenance,
            query_results_resource: true,
            query_results_resource_group: true,
            query_results_subscription: true,
            native: false,
            https_transport: false,
            live_execution: false,
        })
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "azure-policy-provider-definition/v1",
            &[
                self.schema_version.clone(),
                self.provider_id.clone(),
                self.provider_version.clone(),
                self.api_version.clone(),
                self.capability_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
                self.query_results_resource.to_string(),
                self.query_results_resource_group.to_string(),
                self.query_results_subscription.to_string(),
                self.native.to_string(),
                self.https_transport.to_string(),
                self.live_execution.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("Azure Policy Insights transport returned {kind:?}")]
pub struct AzurePolicyTransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    diagnostic_digest: Digest,
}

impl AzurePolicyTransportError {
    #[must_use]
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        let retryable = matches!(
            kind,
            ProviderErrorKind::RateLimited
                | ProviderErrorKind::ServerFailure
                | ProviderErrorKind::Timeout
        );
        Self {
            kind,
            status_code,
            retryable,
            blocked_env: kind == ProviderErrorKind::BlockedEnv,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    #[must_use]
    pub fn timeout() -> Self {
        Self::new(ProviderErrorKind::Timeout, None, "timeout")
    }

    #[must_use]
    pub fn blocked_env() -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }

    #[must_use]
    pub fn http(status_code: u16) -> Self {
        Self::new(status_kind(status_code), Some(status_code), "http-status")
    }

    #[must_use]
    pub(crate) fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("Azure Policy provider returned {kind:?}")]
pub struct AzurePolicyProviderError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    pub error_digest: Digest,
}

impl AzurePolicyProviderError {
    #[must_use]
    pub(crate) fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        retryable: bool,
        blocked_env: bool,
        diagnostic_digest: &Digest,
    ) -> Self {
        let error_digest = Digest::from_fields(
            "azure-policy-provider-error/v1",
            &[
                format!("{kind:?}"),
                status_code.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                retryable.to_string(),
                blocked_env.to_string(),
                diagnostic_digest.as_str().to_owned(),
            ],
        );
        Self {
            kind,
            status_code,
            retryable,
            blocked_env,
            error_digest,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzurePolicyHttpRequest {
    pub method: String,
    pub path: String,
    pub api_version: String,
    pub filter: Option<String>,
    pub top: usize,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub next_link_digest: Option<Digest>,
}

impl fmt::Debug for AzurePolicyHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzurePolicyHttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("api_version", &self.api_version)
            .field("filter", &self.filter)
            .field("top", &self.top)
            .field("scope_digest", &self.scope_digest)
            .field("query_digest", &self.query_digest)
            .field("next_link_digest", &self.next_link_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AzurePolicyHttpResponse {
    status: u16,
    body: String,
}

impl fmt::Debug for AzurePolicyHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzurePolicyHttpResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl AzurePolicyHttpResponse {
    #[must_use]
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }

    #[must_use]
    pub fn ok(body: impl Into<String>) -> Self {
        Self::new(200, body)
    }

    #[must_use]
    pub fn partial(body: impl Into<String>) -> Self {
        Self::new(206, body)
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn response_bytes(&self) -> usize {
        self.body.len()
    }

    pub(crate) fn body(&self) -> &str {
        &self.body
    }
}

pub trait AzurePolicyTransport: fmt::Debug {
    fn post_query_results(
        &mut self,
        request: &AzurePolicyHttpRequest,
    ) -> Result<AzurePolicyHttpResponse, AzurePolicyTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzurePolicyPage {
    pub page_number: u8,
    pub records: Vec<PolicyStateRecord>,
    pub response_digest: Digest,
    pub page_digest: Digest,
    pub next_link_digest: Option<Digest>,
    #[serde(skip)]
    next_link: Option<OpaqueNextLink>,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub partial: bool,
    pub response_bytes: usize,
}

impl AzurePolicyPage {
    #[must_use]
    pub fn next_link_digest(&self) -> Option<&Digest> {
        self.next_link_digest.as_ref()
    }

    pub(crate) fn next_link(&self) -> Option<&OpaqueNextLink> {
        self.next_link.as_ref()
    }
}

#[derive(Clone, Debug)]
pub struct AzurePolicyInsightsProvider<T> {
    scope: AzurePolicyScope,
    secret_reference: SecretReference,
    definition: AzurePolicyProviderDefinition,
    registration: AzurePolicyRegistration,
    transport: T,
}

impl<T: AzurePolicyTransport> AzurePolicyInsightsProvider<T> {
    pub fn new(
        scope: AzurePolicyScope,
        secret_reference: SecretReference,
        transport: T,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        if secret_reference.scope_digest() != &scope.scope_digest() || secret_reference.is_revoked()
        {
            return Err(ProviderDefinitionError::Model(
                ModelError::InvalidSecretReference,
            ));
        }
        let definition =
            AzurePolicyProviderDefinition::new(AZURE_POLICY_INSIGHTS_PROVIDER_VERSION, provenance)?;
        let request = crate::AzurePolicyReadRequest::without_filter(&scope)
            .map_err(|_| ProviderDefinitionError::Model(ModelError::InvalidRegistration))?;
        let query = crate::AzurePolicyQuery::compile(&scope, &secret_reference, request)
            .map_err(|_| ProviderDefinitionError::Model(ModelError::InvalidRegistration))?;
        let registration = AzurePolicyRegistration::new(
            definition.provider_version.clone(),
            definition.provider_digest(),
            definition.api_version.clone(),
            crate::contract_digest(),
            scope.permission_digest().clone(),
            query.query_digest.clone(),
            scope.scope_digest(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            definition,
            registration,
            transport,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &AzurePolicyScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &AzurePolicyProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_definition(&self) -> &AzurePolicyProviderDefinition {
        self.definition()
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn registration(&self) -> &AzurePolicyRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub(crate) fn bind_query(&mut self, query: &AzurePolicyQuery) -> Result<(), ModelError> {
        self.registration.bind_query(query.query_digest.clone())
    }

    pub(crate) fn bind_evidence(&mut self, digest: Digest) -> Result<(), ModelError> {
        self.registration.bind_evidence(digest)
    }

    pub fn revoke_registration(&mut self) -> Result<crate::RegistrationRevocation, ModelError> {
        self.registration.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<(), ModelError> {
        self.registration.restore()
    }

    pub fn revoke_secret(&mut self) -> Result<(), ModelError> {
        self.secret_reference.revoke()
    }

    pub(crate) fn read_page(
        &mut self,
        query: &AzurePolicyQuery,
        next_link: Option<&OpaqueNextLink>,
        page_number: u8,
    ) -> Result<AzurePolicyPage, AzurePolicyProviderError> {
        self.registration
            .ensure_active()
            .map_err(|_| self.local_error(ProviderErrorKind::Revoked, None, "registration"))?;
        if self.secret_reference.is_revoked() {
            return Err(self.local_error(ProviderErrorKind::Revoked, None, "secret"));
        }
        if query.scope_digest() != &self.scope.scope_digest()
            || query.permission_digest() != self.scope.permission_digest()
        {
            return Err(self.local_error(ProviderErrorKind::ScopeMismatch, None, "scope"));
        }
        if let Some(next_link) = next_link {
            query
                .validate_next_link(&self.scope, next_link)
                .map_err(|_| {
                    self.local_error(ProviderErrorKind::NextLinkScopeMismatch, None, "next-link")
                })?;
        }
        let request = AzurePolicyHttpRequest {
            method: "POST".to_owned(),
            path: next_link.map_or_else(
                || query.endpoint_path(&self.scope),
                |value| value.as_str().to_owned(),
            ),
            api_version: AZURE_POLICY_API_VERSION.to_owned(),
            filter: query.filter_text(),
            top: query.bounds.max_records_per_page,
            scope_digest: query.scope_digest.clone(),
            query_digest: query.query_digest.clone(),
            next_link_digest: next_link.map(OpaqueNextLink::digest),
        };
        let response = self
            .transport
            .post_query_results(&request)
            .map_err(|error| {
                AzurePolicyProviderError::new(
                    error.kind,
                    error.status_code,
                    error.retryable,
                    error.blocked_env,
                    error.diagnostic_digest(),
                )
            })?;
        self.parse_response(query, response, page_number)
    }

    fn parse_response(
        &self,
        query: &AzurePolicyQuery,
        response: AzurePolicyHttpResponse,
        page_number: u8,
    ) -> Result<AzurePolicyPage, AzurePolicyProviderError> {
        let response_digest = Digest::from_text(response.body());
        if response.response_bytes() > query.bounds.max_response_bytes {
            return Err(self.provider_error(
                ProviderErrorKind::Truncated,
                Some(response.status()),
                "response-bytes",
            ));
        }
        if response.status() != 200 {
            return Err(self.provider_error(
                status_kind(response.status()),
                Some(response.status()),
                "http-status",
            ));
        }
        let wire = serde_json::from_str::<WireResponse>(response.body())
            .map_err(|_| self.provider_error(ProviderErrorKind::Unknown, Some(200), "decode"))?;
        if wire.partial.unwrap_or(false) {
            return Err(self.provider_error(ProviderErrorKind::PartialPage, Some(200), "partial"));
        }
        let values = wire.value.ok_or_else(|| {
            self.provider_error(ProviderErrorKind::PartialPage, Some(200), "missing-value")
        })?;
        if values.len() > query.bounds.max_records_per_page {
            return Err(self.provider_error(
                ProviderErrorKind::Truncated,
                Some(200),
                "page-record-bound",
            ));
        }
        let mut records = Vec::with_capacity(values.len());
        for value in values {
            records.push(self.parse_record(value, query)?);
        }
        let next_link = match wire.next_link {
            Some(value) => {
                let link = OpaqueNextLink::new(value).map_err(|_| {
                    self.provider_error(
                        ProviderErrorKind::NextLinkScopeMismatch,
                        Some(200),
                        "next-link",
                    )
                })?;
                query.validate_next_link(&self.scope, &link).map_err(|_| {
                    self.provider_error(
                        ProviderErrorKind::NextLinkScopeMismatch,
                        Some(200),
                        "next-link",
                    )
                })?;
                Some(link)
            }
            None => None,
        };
        let record_digests = records
            .iter()
            .map(PolicyStateRecord::digest)
            .map(|value| value.as_str().to_owned())
            .collect::<Vec<_>>();
        let next_link_digest = next_link.as_ref().map(OpaqueNextLink::digest);
        let page_digest = Digest::from_fields(
            "azure-policy-page/v1",
            &[
                page_number.to_string(),
                response_digest.as_str().to_owned(),
                record_digests.join(","),
                next_link_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                query.scope_digest().as_str().to_owned(),
                query.query_digest().as_str().to_owned(),
            ],
        );
        Ok(AzurePolicyPage {
            page_number,
            records,
            response_digest,
            page_digest,
            next_link_digest,
            next_link,
            scope_digest: query.scope_digest.clone(),
            query_digest: query.query_digest.clone(),
            partial: false,
            response_bytes: response.response_bytes(),
        })
    }

    fn parse_record(
        &self,
        value: WirePolicyState,
        query: &AzurePolicyQuery,
    ) -> Result<PolicyStateRecord, AzurePolicyProviderError> {
        let assignment = ResourceId::new(value.policy_assignment_id).map_err(|_| {
            self.provider_error(ProviderErrorKind::Unknown, Some(200), "assignment-id")
        })?;
        let definition = ResourceId::new(value.policy_definition_id).map_err(|_| {
            self.provider_error(ProviderErrorKind::Unknown, Some(200), "definition-id")
        })?;
        let set_definition = value
            .policy_set_definition_id
            .map(ResourceId::new)
            .transpose()
            .map_err(|_| self.provider_error(ProviderErrorKind::Unknown, Some(200), "set-id"))?;
        let resource = ResourceId::new(value.resource_id).map_err(|_| {
            self.provider_error(ProviderErrorKind::Unknown, Some(200), "resource-id")
        })?;
        let timestamp = value.timestamp.as_str();
        if !self.scope.matches_resource(resource.as_str())
            || timestamp < query_window_start(&self.scope)
            || timestamp > query_window_end(&self.scope)
        {
            return Err(self.provider_error(
                ProviderErrorKind::ScopeMismatch,
                Some(200),
                "record-scope",
            ));
        }
        let compliance_state = ComplianceState::parse(&value.compliance_state).map_err(|_| {
            self.provider_error(ProviderErrorKind::Unknown, Some(200), "compliance-state")
        })?;
        if !validate_fingerprint(&self.scope.policy_fingerprints().definition, &definition) {
            return Err(self.provider_error(
                ProviderErrorKind::ScopeMismatch,
                Some(200),
                "definition-fingerprint",
            ));
        }
        if !validate_fingerprint(&self.scope.policy_fingerprints().assignment, &assignment) {
            return Err(self.provider_error(
                ProviderErrorKind::ScopeMismatch,
                Some(200),
                "assignment-fingerprint",
            ));
        }
        if let Some(set_definition) = &set_definition {
            if !validate_fingerprint(
                &self.scope.policy_fingerprints().set_definition,
                set_definition,
            ) {
                return Err(self.provider_error(
                    ProviderErrorKind::ScopeMismatch,
                    Some(200),
                    "set-fingerprint",
                ));
            }
        } else if !self.scope.policy_fingerprints().set_definition.is_empty() {
            return Err(self.provider_error(
                ProviderErrorKind::ScopeMismatch,
                Some(200),
                "missing-set-fingerprint",
            ));
        }
        if let Some(filter) = &query.filter
            && !filter_matches(
                filter,
                &assignment,
                &definition,
                set_definition.as_ref(),
                compliance_state,
                timestamp,
            )
        {
            return Err(self.provider_error(ProviderErrorKind::QueryDrift, Some(200), "filter"));
        }
        let metadata_digest = Digest::from_fields(
            "azure-policy-metadata/v1",
            &[
                value.policy_definition_group_names.join(","),
                value.policy_definition_action.unwrap_or_default(),
                value.policy_assignment_scope.unwrap_or_default(),
                value.management_group_ids.join(","),
            ],
        );
        PolicyStateRecord::new(
            assignment,
            definition,
            set_definition,
            resource,
            compliance_state,
            crate::Timestamp::new(value.timestamp).map_err(|_| {
                self.provider_error(ProviderErrorKind::Unknown, Some(200), "timestamp")
            })?,
            value.resource_location,
            value.resource_type,
            metadata_digest,
        )
        .map_err(|_| self.provider_error(ProviderErrorKind::Unknown, Some(200), "record"))
    }

    fn local_error(
        &self,
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: &str,
    ) -> AzurePolicyProviderError {
        self.provider_error(kind, status_code, diagnostic)
    }

    #[allow(clippy::unused_self)]
    fn provider_error(
        &self,
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: &str,
    ) -> AzurePolicyProviderError {
        AzurePolicyProviderError::new(
            kind,
            status_code,
            matches!(
                kind,
                ProviderErrorKind::RateLimited
                    | ProviderErrorKind::ServerFailure
                    | ProviderErrorKind::Timeout
            ),
            kind == ProviderErrorKind::BlockedEnv,
            &Digest::from_text(diagnostic),
        )
    }
}

fn query_window_start(scope: &AzurePolicyScope) -> &str {
    scope.query_window().start.as_str()
}

fn query_window_end(scope: &AzurePolicyScope) -> &str {
    scope.query_window().end.as_str()
}

fn validate_fingerprint(
    allowlist: &std::collections::BTreeSet<Digest>,
    value: &ResourceId,
) -> bool {
    !(!allowlist.is_empty() && !allowlist.contains(&value.digest()))
}

fn filter_matches(
    filter: &ODataFilter,
    assignment: &ResourceId,
    definition: &ResourceId,
    set_definition: Option<&ResourceId>,
    state: ComplianceState,
    timestamp: &str,
) -> bool {
    match filter {
        ODataFilter::ComplianceState(expected) => *expected == state,
        ODataFilter::PolicyDefinitionId(expected) => expected == definition,
        ODataFilter::PolicyAssignmentId(expected) => expected == assignment,
        ODataFilter::PolicySetDefinitionId(expected) => Some(expected) == set_definition,
        ODataFilter::TimestampAfter(expected) => timestamp >= expected.as_str(),
        ODataFilter::TimestampBefore(expected) => timestamp <= expected.as_str(),
        ODataFilter::And(filters) => filters.iter().all(|value| {
            filter_matches(
                value,
                assignment,
                definition,
                set_definition,
                state,
                timestamp,
            )
        }),
    }
}

fn status_kind(status: u16) -> ProviderErrorKind {
    match status {
        400 => ProviderErrorKind::BadRequest,
        401 => ProviderErrorKind::Unauthenticated,
        403 => ProviderErrorKind::PermissionDenied,
        404 => ProviderErrorKind::NotFound,
        409 => ProviderErrorKind::Conflict,
        429 => ProviderErrorKind::RateLimited,
        206 => ProviderErrorKind::PartialPage,
        500..=599 => ProviderErrorKind::ServerFailure,
        _ => ProviderErrorKind::Unknown,
    }
}

#[derive(Debug, Deserialize)]
struct WireResponse {
    value: Option<Vec<WirePolicyState>>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
    partial: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WirePolicyState {
    policy_assignment_id: String,
    policy_definition_id: String,
    policy_set_definition_id: Option<String>,
    resource_id: String,
    compliance_state: String,
    timestamp: String,
    resource_location: Option<String>,
    resource_type: Option<String>,
    #[serde(default)]
    policy_definition_group_names: Vec<String>,
    policy_definition_action: Option<String>,
    policy_assignment_scope: Option<String>,
    #[serde(default)]
    management_group_ids: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct RecordingAzurePolicyTransport {
    responses: VecDeque<Result<AzurePolicyHttpResponse, AzurePolicyTransportError>>,
    requests: Vec<AzurePolicyHttpRequest>,
}

impl RecordingAzurePolicyTransport {
    #[must_use]
    pub fn new() -> Self {
        Self {
            responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(&mut self, response: AzurePolicyHttpResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: AzurePolicyTransportError) {
        self.responses.push_back(Err(error));
    }

    #[must_use]
    pub fn requests(&self) -> &[AzurePolicyHttpRequest] {
        &self.requests
    }

    #[must_use]
    pub fn call_count(&self) -> usize {
        self.requests.len()
    }
}

impl Default for RecordingAzurePolicyTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl AzurePolicyTransport for RecordingAzurePolicyTransport {
    fn post_query_results(
        &mut self,
        request: &AzurePolicyHttpRequest,
    ) -> Result<AzurePolicyHttpResponse, AzurePolicyTransportError> {
        self.requests.push(request.clone());
        self.responses.pop_front().unwrap_or_else(|| {
            Err(AzurePolicyTransportError::new(
                ProviderErrorKind::Unknown,
                None,
                "no-recorded-response",
            ))
        })
    }
}

#[derive(Clone, Debug)]
pub struct FixtureAzurePolicyTransport {
    response: AzurePolicyHttpResponse,
}

impl FixtureAzurePolicyTransport {
    #[must_use]
    pub fn new(body: impl Into<String>) -> Self {
        Self {
            response: AzurePolicyHttpResponse::ok(body),
        }
    }
}

impl AzurePolicyTransport for FixtureAzurePolicyTransport {
    fn post_query_results(
        &mut self,
        _request: &AzurePolicyHttpRequest,
    ) -> Result<AzurePolicyHttpResponse, AzurePolicyTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackAzurePolicyTransport {
    response: AzurePolicyHttpResponse,
    requests: Vec<AzurePolicyHttpRequest>,
}

impl LoopbackAzurePolicyTransport {
    #[must_use]
    pub fn new(body: impl Into<String>) -> Self {
        Self {
            response: AzurePolicyHttpResponse::ok(body),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[AzurePolicyHttpRequest] {
        &self.requests
    }
}

impl AzurePolicyTransport for LoopbackAzurePolicyTransport {
    fn post_query_results(
        &mut self,
        request: &AzurePolicyHttpRequest,
    ) -> Result<AzurePolicyHttpResponse, AzurePolicyTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAzurePolicyTransport;

impl AzurePolicyTransport for BlockedEnvAzurePolicyTransport {
    fn post_query_results(
        &mut self,
        _request: &AzurePolicyHttpRequest,
    ) -> Result<AzurePolicyHttpResponse, AzurePolicyTransportError> {
        Err(AzurePolicyTransportError::blocked_env())
    }
}

pub type FakeAzurePolicyTransport = RecordingAzurePolicyTransport;
