//! Deterministic Cloud Asset transport seams.
//!
//! There is intentionally no HTTP client and no native credential path in
//! this crate. Requests carry only digests and bounded limits. Fixture,
//! recording, loopback, and BLOCKED_ENV are all explicitly non-native.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::GCP_IAM_ANALYSIS_PROVIDER_REVISION;
use crate::model::{
    AccessAnalysisPage, AccessClassification, AnalysisExplanationCode, AnalysisNode,
    AnalysisNodeKind, Digest, GcpCloudAssetOperation, GcpIamModelError, GcpIamScope,
    MAX_ANALYSIS_EDGES, MAX_ANALYSIS_NODES, MAX_PAGE_SIZE, MAX_PAGES_PER_OPERATION,
    MAX_RESPONSE_BYTES, PageTokenDigest, PrincipalClass, PrincipalEvidence, ProviderProvenance,
    SearchAllIamPoliciesPage,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpTransportError {
    #[error("BLOCKED_ENV: native GCP OAuth/service-account authority is unavailable")]
    BlockedEnv,
    #[error("Cloud Asset returned HTTP 400")]
    BadRequest400,
    #[error("Cloud Asset returned HTTP 401")]
    Unauthorized401,
    #[error("Cloud Asset returned HTTP 403")]
    Forbidden403,
    #[error("Cloud Asset returned HTTP 404")]
    NotFound404,
    #[error("Cloud Asset returned HTTP 409")]
    Conflict409,
    #[error("Cloud Asset returned HTTP 429")]
    RateLimited429,
    #[error("Cloud Asset returned HTTP {status}")]
    Server5xx { status: u16 },
    #[error("Cloud Asset transport timed out")]
    Timeout,
    #[error("Cloud Asset response was too large")]
    ResponseTooLarge,
    #[error("Cloud Asset response could not be decoded")]
    Decode,
    #[error("Cloud Asset transport failed")]
    Transport,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpCloudAssetRequest {
    pub operation: GcpCloudAssetOperation,
    pub api_version: String,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub hierarchy_revision: Digest,
    pub policy_revision: Digest,
    pub principal_class: PrincipalClass,
    pub principal_digest: Digest,
    pub resource_digest: Digest,
    pub permission_digest: Digest,
    pub page_size: usize,
    pub page_number: usize,
    pub page_token: Option<PageTokenDigest>,
    pub request_digest: Digest,
}

impl GcpCloudAssetRequest {
    pub fn new(
        scope: &GcpIamScope,
        operation: GcpCloudAssetOperation,
        page_size: usize,
        page_number: usize,
        page_token: Option<PageTokenDigest>,
    ) -> Result<Self, GcpIamModelError> {
        if !(1..=MAX_PAGE_SIZE).contains(&page_size)
            || !(1..=MAX_PAGES_PER_OPERATION).contains(&page_number)
        {
            return Err(GcpIamModelError::BoundExceeded {
                field: "Cloud Asset pagination",
                maximum: MAX_PAGE_SIZE,
            });
        }
        if let Some(token) = &page_token {
            token.validate()?;
        }
        let mut request = Self {
            operation,
            api_version: String::from(crate::GCP_IAM_ANALYSIS_API_VERSION),
            scope_digest: scope.scope_digest(),
            query_digest: scope.query_digest.clone(),
            hierarchy_revision: scope.hierarchy_revision().clone(),
            policy_revision: scope.policy_revision.clone(),
            principal_class: scope.query.principal_class,
            principal_digest: scope.query.principal_digest.clone(),
            resource_digest: scope.resource_name.digest(),
            permission_digest: scope.permission_digest.clone(),
            page_size,
            page_number,
            page_token,
            request_digest: Digest::zero(),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    #[must_use]
    pub fn api_method(&self) -> &'static str {
        self.operation.api_method()
    }

    #[must_use]
    pub fn api_path(&self) -> String {
        format!("/v1/{{scope}}:{}", self.api_method())
    }

    fn compute_digest(&self) -> Digest {
        let mut request = self.clone();
        request.request_digest = Digest::zero();
        Digest::from_serialized(&request)
    }

    pub fn validate_for_scope(&self, scope: &GcpIamScope) -> Result<(), GcpIamModelError> {
        scope.validate()?;
        if self.api_version != crate::GCP_IAM_ANALYSIS_API_VERSION
            || self.scope_digest != scope.scope_digest
            || self.query_digest != scope.query_digest
            || self.hierarchy_revision != *scope.hierarchy_revision()
            || self.policy_revision != scope.policy_revision
            || self.principal_class != scope.query.principal_class
            || self.principal_digest != scope.query.principal_digest
            || self.resource_digest != scope.resource_name.digest()
            || self.permission_digest != scope.permission_digest
            || !(1..=MAX_PAGE_SIZE).contains(&self.page_size)
            || !(1..=MAX_PAGES_PER_OPERATION).contains(&self.page_number)
            || self.request_digest != self.compute_digest()
        {
            return Err(GcpIamModelError::DigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum GcpCloudAssetPayload {
    SearchAllIamPolicies(SearchAllIamPoliciesPage),
    AnalyzeIamPolicy(AccessAnalysisPage),
}

impl GcpCloudAssetPayload {
    #[must_use]
    pub const fn operation(&self) -> GcpCloudAssetOperation {
        match self {
            Self::SearchAllIamPolicies(_) => GcpCloudAssetOperation::SearchAllIamPolicies,
            Self::AnalyzeIamPolicy(_) => GcpCloudAssetOperation::AnalyzeIamPolicy,
        }
    }

    #[must_use]
    pub fn page_digest(&self) -> &Digest {
        match self {
            Self::SearchAllIamPolicies(page) => &page.page_digest,
            Self::AnalyzeIamPolicy(page) => &page.page_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpCloudAssetResponse {
    pub operation: GcpCloudAssetOperation,
    pub request_digest: Digest,
    pub status: u16,
    pub response_size: usize,
    pub provider_revision: String,
    pub payload: GcpCloudAssetPayload,
    pub response_digest: Digest,
}

impl GcpCloudAssetResponse {
    pub fn new(
        operation: GcpCloudAssetOperation,
        status: u16,
        response_size: usize,
        provider_revision: impl Into<String>,
        payload: GcpCloudAssetPayload,
    ) -> Result<Self, GcpTransportError> {
        if payload.operation() != operation || response_size > MAX_RESPONSE_BYTES {
            return Err(GcpTransportError::ResponseTooLarge);
        }
        let provider_revision = provider_revision.into();
        if provider_revision.is_empty() {
            return Err(GcpTransportError::Decode);
        }
        let response_digest = response_digest(
            operation,
            status,
            response_size,
            &provider_revision,
            &payload,
        );
        Ok(Self {
            operation,
            request_digest: Digest::zero(),
            status,
            response_size,
            provider_revision,
            payload,
            response_digest,
        })
    }

    pub fn for_request(
        request: &GcpCloudAssetRequest,
        status: u16,
        response_size: usize,
        provider_revision: impl Into<String>,
        payload: GcpCloudAssetPayload,
    ) -> Result<Self, GcpTransportError> {
        let mut response = Self::new(
            request.operation,
            status,
            response_size,
            provider_revision,
            payload,
        )?;
        response.request_digest = request.request_digest.clone();
        Ok(response)
    }

    pub fn verify_digest(&self) -> bool {
        self.response_digest
            == response_digest(
                self.operation,
                self.status,
                self.response_size,
                &self.provider_revision,
                &self.payload,
            )
    }
}

fn response_digest(
    operation: GcpCloudAssetOperation,
    status: u16,
    response_size: usize,
    provider_revision: &str,
    payload: &GcpCloudAssetPayload,
) -> Digest {
    Digest::from_serialized(&(operation, status, response_size, provider_revision, payload))
}

pub trait GcpCloudAssetTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn execute(
        &mut self,
        request: &GcpCloudAssetRequest,
    ) -> Result<GcpCloudAssetResponse, GcpTransportError>;
}

fn deterministic_fixture_response(
    request: &GcpCloudAssetRequest,
) -> Result<GcpCloudAssetResponse, GcpTransportError> {
    let payload = match request.operation {
        GcpCloudAssetOperation::SearchAllIamPolicies => GcpCloudAssetPayload::SearchAllIamPolicies(
            SearchAllIamPoliciesPage::new(
                request.scope_digest.clone(),
                request.query_digest.clone(),
                request.hierarchy_revision.clone(),
                request.policy_revision.clone(),
                Vec::new(),
                None,
                false,
                false,
            )
            .map_err(|_| GcpTransportError::Decode)?,
        ),
        GcpCloudAssetOperation::AnalyzeIamPolicy => {
            let principal =
                PrincipalEvidence::new(request.principal_class, request.principal_digest.clone())
                    .map_err(|_| GcpTransportError::Decode)?;
            let node = AnalysisNode::new(
                AnalysisNodeKind::Resource,
                request.resource_digest.clone(),
                0,
            )
            .map_err(|_| GcpTransportError::Decode)?;
            GcpCloudAssetPayload::AnalyzeIamPolicy(
                AccessAnalysisPage::new(
                    request.scope_digest.clone(),
                    request.query_digest.clone(),
                    request.hierarchy_revision.clone(),
                    request.policy_revision.clone(),
                    principal,
                    request.resource_digest.clone(),
                    request.permission_digest.clone(),
                    AccessClassification::NoMatch,
                    vec![AnalysisExplanationCode::MissingPermission],
                    vec![node],
                    Vec::new(),
                    None,
                    false,
                    false,
                )
                .map_err(|_| GcpTransportError::Decode)?,
            )
        }
    };
    GcpCloudAssetResponse::for_request(
        request,
        200,
        512,
        GCP_IAM_ANALYSIS_PROVIDER_REVISION,
        payload,
    )
}

macro_rules! scripted_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug, Default)]
        pub struct $name {
            scripted: VecDeque<Result<GcpCloudAssetResponse, GcpTransportError>>,
            requests: Vec<GcpCloudAssetRequest>,
        }

        impl $name {
            pub fn push_response(&mut self, response: GcpCloudAssetResponse) {
                self.scripted.push_back(Ok(response));
            }

            pub fn push_error(&mut self, error: GcpTransportError) {
                self.scripted.push_back(Err(error));
            }

            #[must_use]
            pub fn requests(&self) -> &[GcpCloudAssetRequest] {
                &self.requests
            }
        }

        impl GcpCloudAssetTransport for $name {
            fn provenance(&self) -> ProviderProvenance {
                $provenance
            }

            fn execute(
                &mut self,
                request: &GcpCloudAssetRequest,
            ) -> Result<GcpCloudAssetResponse, GcpTransportError> {
                self.requests.push(request.clone());
                match self.scripted.pop_front() {
                    Some(response) => response,
                    None => deterministic_fixture_response(request),
                }
            }
        }
    };
}

scripted_transport!(FixtureGcpCloudAssetTransport, ProviderProvenance::Fixture);
scripted_transport!(
    RecordingGcpCloudAssetTransport,
    ProviderProvenance::Recording
);
scripted_transport!(LoopbackGcpCloudAssetTransport, ProviderProvenance::Loopback);

pub type FakeGcpCloudAssetTransport = FixtureGcpCloudAssetTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvGcpCloudAssetTransport;

impl GcpCloudAssetTransport for BlockedEnvGcpCloudAssetTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &GcpCloudAssetRequest,
    ) -> Result<GcpCloudAssetResponse, GcpTransportError> {
        Err(GcpTransportError::BlockedEnv)
    }
}

pub type BlockedEnvTransport = BlockedEnvGcpCloudAssetTransport;

/// Retain these imports in this module's public API documentation and ensure
/// the transport seam stays tied to the declared graph limits.
#[allow(dead_code)]
const _DECLARED_LIMITS: (usize, usize, usize) =
    (MAX_ANALYSIS_NODES, MAX_ANALYSIS_EDGES, MAX_RESPONSE_BYTES);
