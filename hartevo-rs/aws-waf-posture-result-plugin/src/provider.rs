//! Bounded AWS WAF provider and transport seams.
//!
//! The provider accepts only typed, already-bounded pages. It does not own an
//! AWS SDK, SigV4 signer, credential resolver, HTTP client, or mutation path.

use std::{collections::VecDeque, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_WAF_API_VERSION, AWS_WAF_POSTURE_API_REVISION, AWS_WAF_POSTURE_PROVIDER_ID,
    AWS_WAF_POSTURE_PROVIDER_VERSION, MAX_PAGE_SIZE, MAX_PAGES, MAX_REQUESTS_PER_READ,
    MAX_RESPONSE_BYTES,
    model::{
        AwsWafPostureScope, Digest, ModelError, OpaquePageToken, ResourceAssociation,
        TransportProvenance, WafOperation, WebAclDetails, WebAclListItem, WebAclReference,
        digest_serializable,
    },
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListWebAclsRequest {
    pub scope_digest: Digest,
    pub scope_kind: crate::WafScopeKind,
    pub page_size: u16,
    pub cursor: Option<OpaquePageToken>,
    pub request_digest: Digest,
}

impl ListWebAclsRequest {
    pub fn new(
        scope: &AwsWafPostureScope,
        cursor: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if let Some(cursor) = &cursor {
            cursor.validate_for(scope, WafOperation::ListWebAcls, cursor.page_number)?;
        }
        let request_digest = Digest::from_parts(
            "aws-waf-list-web-acls-request/v1",
            &[
                scope.digest().to_string(),
                format!("{:?}", scope.scope_kind),
                MAX_PAGE_SIZE.to_string(),
                cursor
                    .as_ref()
                    .map_or_else(String::new, |cursor| cursor.token_digest.to_string()),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            scope_kind: scope.scope_kind,
            page_size: MAX_PAGE_SIZE,
            cursor,
            request_digest,
        })
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, |cursor| cursor.page_number)
    }

    pub fn recorded_call(&self) -> TransportCall {
        TransportCall {
            operation: WafOperation::ListWebAcls,
            scope_digest: self.scope_digest.clone(),
            target_digest: None,
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest.clone()),
            request_digest: self.request_digest.clone(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetWebAclRequest {
    pub scope_digest: Digest,
    pub web_acl_digest: Digest,
    pub request_digest: Digest,
    #[serde(skip)]
    web_acl: WebAclReference,
}

impl fmt::Debug for GetWebAclRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetWebAclRequest")
            .field("scope_digest", &self.scope_digest)
            .field("web_acl_digest", &self.web_acl_digest)
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

impl GetWebAclRequest {
    pub fn new(scope: &AwsWafPostureScope, web_acl: WebAclReference) -> Result<Self, ModelError> {
        scope.validate()?;
        if !scope.is_web_acl_allowed(&web_acl) {
            return Err(ModelError::ScopeMismatch {
                field: "web ACL allowlist",
            });
        }
        let web_acl_digest = web_acl.digest();
        let request_digest = Digest::from_parts(
            "aws-waf-get-web-acl-request/v1",
            &[scope.digest().to_string(), web_acl_digest.to_string()],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            web_acl_digest,
            request_digest,
            web_acl,
        })
    }

    pub fn web_acl(&self) -> &WebAclReference {
        &self.web_acl
    }

    pub fn recorded_call(&self) -> TransportCall {
        TransportCall {
            operation: WafOperation::GetWebAcl,
            scope_digest: self.scope_digest.clone(),
            target_digest: Some(self.web_acl_digest.clone()),
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResourcesForWebAclRequest {
    pub scope_digest: Digest,
    pub web_acl_digest: Digest,
    pub page_size: u16,
    pub cursor: Option<OpaquePageToken>,
    pub request_digest: Digest,
    #[serde(skip)]
    web_acl: WebAclReference,
}

impl fmt::Debug for ListResourcesForWebAclRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListResourcesForWebAclRequest")
            .field("scope_digest", &self.scope_digest)
            .field("web_acl_digest", &self.web_acl_digest)
            .field("page_size", &self.page_size)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

impl ListResourcesForWebAclRequest {
    pub fn new(
        scope: &AwsWafPostureScope,
        web_acl: WebAclReference,
        cursor: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if !scope.is_web_acl_allowed(&web_acl) {
            return Err(ModelError::ScopeMismatch {
                field: "web ACL allowlist",
            });
        }
        if let Some(cursor) = &cursor {
            cursor.validate_for(
                scope,
                WafOperation::ListResourcesForWebAcl,
                cursor.page_number,
            )?;
        }
        let web_acl_digest = web_acl.digest();
        let request_digest = Digest::from_parts(
            "aws-waf-list-resources-for-web-acl-request/v1",
            &[
                scope.digest().to_string(),
                web_acl_digest.to_string(),
                MAX_PAGE_SIZE.to_string(),
                cursor
                    .as_ref()
                    .map_or_else(String::new, |cursor| cursor.token_digest.to_string()),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            web_acl_digest,
            page_size: MAX_PAGE_SIZE,
            cursor,
            request_digest,
            web_acl,
        })
    }

    pub fn web_acl(&self) -> &WebAclReference {
        &self.web_acl
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, |cursor| cursor.page_number)
    }

    pub fn recorded_call(&self) -> TransportCall {
        TransportCall {
            operation: WafOperation::ListResourcesForWebAcl,
            scope_digest: self.scope_digest.clone(),
            target_digest: Some(self.web_acl_digest.clone()),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest.clone()),
            request_digest: self.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListWebAclsPage {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub items: Vec<WebAclListItem>,
    pub next_token: Option<OpaquePageToken>,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub partial: bool,
    pub page_digest: Digest,
}

impl ListWebAclsPage {
    pub fn new(
        request: &ListWebAclsRequest,
        items: Vec<WebAclListItem>,
        next_token: Option<OpaquePageToken>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        Self::with_partial(request, items, next_token, response_bytes, false)
    }

    pub fn with_partial(
        request: &ListWebAclsRequest,
        items: Vec<WebAclListItem>,
        next_token: Option<OpaquePageToken>,
        response_bytes: usize,
        partial: bool,
    ) -> Result<Self, ModelError> {
        validate_response(response_bytes)?;
        if items.len() > usize::from(request.page_size) {
            return Err(ModelError::TooMany {
                field: "ListWebACLs page items",
            });
        }
        if let Some(next_token) = &next_token {
            next_token.validate_for_digest(
                &request.scope_digest,
                WafOperation::ListWebAcls,
                request.page_number() + 1,
            )?;
        }
        let response_digest = list_web_acls_response_digest(
            request,
            &items,
            next_token.as_ref(),
            response_bytes,
            partial,
        );
        let page_digest = page_digest(
            "aws-waf-list-web-acls-page/v1",
            &request.scope_digest,
            &request.request_digest,
            &response_digest,
            next_token.as_ref(),
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            items,
            next_token,
            response_digest,
            response_bytes,
            partial,
            page_digest,
        })
    }

    pub fn validate_for(&self, request: &ListWebAclsRequest) -> Result<(), ModelError> {
        if let Some(token) = &self.next_token {
            token.validate_for_digest(
                &request.scope_digest,
                WafOperation::ListWebAcls,
                request.page_number() + 1,
            )?;
        }
        if self.scope_digest != request.scope_digest
            || self.request_digest != request.request_digest
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.response_digest
                != list_web_acls_response_digest(
                    request,
                    &self.items,
                    self.next_token.as_ref(),
                    self.response_bytes,
                    self.partial,
                )
            || self.page_digest
                != page_digest(
                    "aws-waf-list-web-acls-page/v1",
                    &self.scope_digest,
                    &self.request_digest,
                    &self.response_digest,
                    self.next_token.as_ref(),
                )
        {
            return Err(ModelError::ScopeMismatch {
                field: "ListWebACLs page fence",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetWebAclResponse {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub details: WebAclDetails,
    pub response_digest: Digest,
    pub response_bytes: usize,
}

impl GetWebAclResponse {
    pub fn new(
        request: &GetWebAclRequest,
        details: WebAclDetails,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        validate_response(response_bytes)?;
        if details.identity.id() != request.web_acl().id()
            || details.identity.arn() != request.web_acl().arn()
        {
            return Err(ModelError::ScopeMismatch {
                field: "GetWebACL identity",
            });
        }
        let response_digest = Digest::from_parts(
            "aws-waf-get-web-acl-response/v1",
            &[
                request.request_digest.to_string(),
                details.projection_digest().to_string(),
                details.revision_digest().to_string(),
                response_bytes.to_string(),
            ],
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            details,
            response_digest,
            response_bytes,
        })
    }

    pub fn validate_for(&self, request: &GetWebAclRequest) -> Result<(), ModelError> {
        if self.scope_digest != request.scope_digest
            || self.request_digest != request.request_digest
            || self.details.identity.id() != request.web_acl().id()
            || self.details.identity.arn() != request.web_acl().arn()
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.response_digest
                != Digest::from_parts(
                    "aws-waf-get-web-acl-response/v1",
                    &[
                        request.request_digest.to_string(),
                        self.details.projection_digest().to_string(),
                        self.details.revision_digest().to_string(),
                        self.response_bytes.to_string(),
                    ],
                )
        {
            return Err(ModelError::ScopeMismatch {
                field: "GetWebACL response fence",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResourcesForWebAclPage {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub associations: Vec<ResourceAssociation>,
    pub next_token: Option<OpaquePageToken>,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub partial: bool,
    pub page_digest: Digest,
}

impl ListResourcesForWebAclPage {
    pub fn new(
        request: &ListResourcesForWebAclRequest,
        associations: Vec<ResourceAssociation>,
        next_token: Option<OpaquePageToken>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        Self::with_partial(request, associations, next_token, response_bytes, false)
    }

    pub fn with_partial(
        request: &ListResourcesForWebAclRequest,
        associations: Vec<ResourceAssociation>,
        next_token: Option<OpaquePageToken>,
        response_bytes: usize,
        partial: bool,
    ) -> Result<Self, ModelError> {
        validate_response(response_bytes)?;
        if associations.len() > usize::from(request.page_size) {
            return Err(ModelError::TooMany {
                field: "ListResourcesForWebACL page items",
            });
        }
        if let Some(next_token) = &next_token {
            next_token.validate_for_digest(
                &request.scope_digest,
                WafOperation::ListResourcesForWebAcl,
                request.page_number() + 1,
            )?;
        }
        let response_digest = list_resources_response_digest(
            request,
            &associations,
            next_token.as_ref(),
            response_bytes,
            partial,
        );
        let page_digest = page_digest(
            "aws-waf-list-resources-for-web-acl-page/v1",
            &request.scope_digest,
            &request.request_digest,
            &response_digest,
            next_token.as_ref(),
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            associations,
            next_token,
            response_digest,
            response_bytes,
            partial,
            page_digest,
        })
    }

    pub fn validate_for(&self, request: &ListResourcesForWebAclRequest) -> Result<(), ModelError> {
        if let Some(token) = &self.next_token {
            token.validate_for_digest(
                &request.scope_digest,
                WafOperation::ListResourcesForWebAcl,
                request.page_number() + 1,
            )?;
        }
        if self.scope_digest != request.scope_digest
            || self.request_digest != request.request_digest
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.response_digest
                != list_resources_response_digest(
                    request,
                    &self.associations,
                    self.next_token.as_ref(),
                    self.response_bytes,
                    self.partial,
                )
            || self.page_digest
                != page_digest(
                    "aws-waf-list-resources-for-web-acl-page/v1",
                    &self.scope_digest,
                    &self.request_digest,
                    &self.response_digest,
                    self.next_token.as_ref(),
                )
        {
            return Err(ModelError::ScopeMismatch {
                field: "ListResourcesForWebACL page fence",
            });
        }
        Ok(())
    }
}

fn validate_response(response_bytes: usize) -> Result<(), ModelError> {
    if response_bytes > MAX_RESPONSE_BYTES {
        Err(ModelError::TooLong {
            field: "provider response",
        })
    } else {
        Ok(())
    }
}

fn list_web_acls_response_digest(
    request: &ListWebAclsRequest,
    items: &[WebAclListItem],
    next_token: Option<&OpaquePageToken>,
    response_bytes: usize,
    partial: bool,
) -> Digest {
    Digest::from_parts(
        "aws-waf-list-web-acls-response/v1",
        &[
            request.request_digest.to_string(),
            items
                .iter()
                .map(|item| item.identity.digest())
                .map(|digest| digest.to_string())
                .collect::<Vec<_>>()
                .join(","),
            next_token.map_or_else(String::new, |token| token.token_digest.to_string()),
            response_bytes.to_string(),
            partial.to_string(),
        ],
    )
}

fn list_resources_response_digest(
    request: &ListResourcesForWebAclRequest,
    associations: &[ResourceAssociation],
    next_token: Option<&OpaquePageToken>,
    response_bytes: usize,
    partial: bool,
) -> Digest {
    Digest::from_parts(
        "aws-waf-list-resources-for-web-acl-response/v1",
        &[
            request.request_digest.to_string(),
            associations
                .iter()
                .map(|association| association.resource.digest())
                .map(|digest| digest.to_string())
                .collect::<Vec<_>>()
                .join(","),
            next_token.map_or_else(String::new, |token| token.token_digest.to_string()),
            response_bytes.to_string(),
            partial.to_string(),
        ],
    )
}

fn page_digest(
    domain: &str,
    scope_digest: &Digest,
    request_digest: &Digest,
    response_digest: &Digest,
    next_token: Option<&OpaquePageToken>,
) -> Digest {
    Digest::from_parts(
        domain,
        &[
            scope_digest.to_string(),
            request_digest.to_string(),
            response_digest.to_string(),
            next_token.map_or_else(String::new, |token| token.token_digest.to_string()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportCall {
    pub operation: WafOperation,
    pub scope_digest: Digest,
    pub target_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("native AWS WAF transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("AWS WAF transport timed out")]
    Timeout,
    #[error("AWS WAF transport was throttled")]
    Throttled,
    #[error("AWS WAF provider returned an unknown transport failure")]
    ProviderUnknown,
    #[error("AWS WAF provider returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("AWS WAF provider response exceeded the Layer-1 bound")]
    ResponseTooLarge,
    #[error("AWS WAF provider response was malformed")]
    MalformedResponse,
}

/// The only transport interface available to Layer 1.
pub trait AwsWafTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_web_acls(
        &mut self,
        request: &ListWebAclsRequest,
    ) -> Result<ListWebAclsPage, TransportError>;

    fn get_web_acl(
        &mut self,
        request: &GetWebAclRequest,
    ) -> Result<GetWebAclResponse, TransportError>;

    fn list_resources_for_web_acl(
        &mut self,
        request: &ListResourcesForWebAclRequest,
    ) -> Result<ListResourcesForWebAclPage, TransportError>;
}

#[derive(Clone, Debug, Default)]
struct QueuedResponses {
    list_web_acls: VecDeque<Result<ListWebAclsPage, TransportError>>,
    get_web_acl: VecDeque<Result<GetWebAclResponse, TransportError>>,
    list_resources: VecDeque<Result<ListResourcesForWebAclPage, TransportError>>,
}

impl QueuedResponses {
    fn list_web_acls(
        &mut self,
        _request: &ListWebAclsRequest,
    ) -> Result<ListWebAclsPage, TransportError> {
        self.list_web_acls
            .pop_front()
            .unwrap_or(Err(TransportError::ProviderUnknown))
    }

    fn get_web_acl(
        &mut self,
        _request: &GetWebAclRequest,
    ) -> Result<GetWebAclResponse, TransportError> {
        self.get_web_acl
            .pop_front()
            .unwrap_or(Err(TransportError::ProviderUnknown))
    }

    fn list_resources(
        &mut self,
        _request: &ListResourcesForWebAclRequest,
    ) -> Result<ListResourcesForWebAclPage, TransportError> {
        self.list_resources
            .pop_front()
            .unwrap_or(Err(TransportError::ProviderUnknown))
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureAwsWafTransport {
    responses: QueuedResponses,
}

impl FixtureAwsWafTransport {
    pub fn fixture() -> Self {
        Self::default()
    }

    pub fn queue_list_web_acls(
        &mut self,
        response: Result<ListWebAclsPage, TransportError>,
    ) -> &mut Self {
        self.responses.list_web_acls.push_back(response);
        self
    }

    pub fn queue_get_web_acl(
        &mut self,
        response: Result<GetWebAclResponse, TransportError>,
    ) -> &mut Self {
        self.responses.get_web_acl.push_back(response);
        self
    }

    pub fn queue_list_resources_for_web_acl(
        &mut self,
        response: Result<ListResourcesForWebAclPage, TransportError>,
    ) -> &mut Self {
        self.responses.list_resources.push_back(response);
        self
    }
}

impl AwsWafTransport for FixtureAwsWafTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_web_acls(
        &mut self,
        request: &ListWebAclsRequest,
    ) -> Result<ListWebAclsPage, TransportError> {
        self.responses.list_web_acls(request)
    }

    fn get_web_acl(
        &mut self,
        request: &GetWebAclRequest,
    ) -> Result<GetWebAclResponse, TransportError> {
        self.responses.get_web_acl(request)
    }

    fn list_resources_for_web_acl(
        &mut self,
        request: &ListResourcesForWebAclRequest,
    ) -> Result<ListResourcesForWebAclPage, TransportError> {
        self.responses.list_resources(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingAwsWafTransport {
    responses: QueuedResponses,
    calls: Vec<TransportCall>,
}

impl RecordingAwsWafTransport {
    pub fn for_scope(scope: &AwsWafPostureScope) -> Result<Self, ModelError> {
        let fixture = FixtureAwsWafTransport::for_scope(scope)?;
        Ok(Self {
            responses: fixture.responses,
            calls: Vec::new(),
        })
    }

    pub fn queue_list_web_acls(
        &mut self,
        response: Result<ListWebAclsPage, TransportError>,
    ) -> &mut Self {
        self.responses.list_web_acls.push_back(response);
        self
    }

    pub fn queue_get_web_acl(
        &mut self,
        response: Result<GetWebAclResponse, TransportError>,
    ) -> &mut Self {
        self.responses.get_web_acl.push_back(response);
        self
    }

    pub fn queue_list_resources_for_web_acl(
        &mut self,
        response: Result<ListResourcesForWebAclPage, TransportError>,
    ) -> &mut Self {
        self.responses.list_resources.push_back(response);
        self
    }

    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }
}

impl AwsWafTransport for RecordingAwsWafTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn list_web_acls(
        &mut self,
        request: &ListWebAclsRequest,
    ) -> Result<ListWebAclsPage, TransportError> {
        self.calls.push(request.recorded_call());
        self.responses.list_web_acls(request)
    }

    fn get_web_acl(
        &mut self,
        request: &GetWebAclRequest,
    ) -> Result<GetWebAclResponse, TransportError> {
        self.calls.push(request.recorded_call());
        self.responses.get_web_acl(request)
    }

    fn list_resources_for_web_acl(
        &mut self,
        request: &ListResourcesForWebAclRequest,
    ) -> Result<ListResourcesForWebAclPage, TransportError> {
        self.calls.push(request.recorded_call());
        self.responses.list_resources(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackAwsWafTransport {
    responses: QueuedResponses,
    calls: Vec<TransportCall>,
}

impl LoopbackAwsWafTransport {
    pub fn queue_list_web_acls(
        &mut self,
        response: Result<ListWebAclsPage, TransportError>,
    ) -> &mut Self {
        self.responses.list_web_acls.push_back(response);
        self
    }

    pub fn queue_get_web_acl(
        &mut self,
        response: Result<GetWebAclResponse, TransportError>,
    ) -> &mut Self {
        self.responses.get_web_acl.push_back(response);
        self
    }

    pub fn queue_list_resources_for_web_acl(
        &mut self,
        response: Result<ListResourcesForWebAclPage, TransportError>,
    ) -> &mut Self {
        self.responses.list_resources.push_back(response);
        self
    }

    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }
}

impl AwsWafTransport for LoopbackAwsWafTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_web_acls(
        &mut self,
        request: &ListWebAclsRequest,
    ) -> Result<ListWebAclsPage, TransportError> {
        self.calls.push(request.recorded_call());
        self.responses.list_web_acls(request)
    }

    fn get_web_acl(
        &mut self,
        request: &GetWebAclRequest,
    ) -> Result<GetWebAclResponse, TransportError> {
        self.calls.push(request.recorded_call());
        self.responses.get_web_acl(request)
    }

    fn list_resources_for_web_acl(
        &mut self,
        request: &ListResourcesForWebAclRequest,
    ) -> Result<ListResourcesForWebAclPage, TransportError> {
        self.calls.push(request.recorded_call());
        self.responses.list_resources(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvAwsWafTransport;

impl AwsWafTransport for BlockedEnvAwsWafTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_web_acls(
        &mut self,
        _request: &ListWebAclsRequest,
    ) -> Result<ListWebAclsPage, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn get_web_acl(
        &mut self,
        _request: &GetWebAclRequest,
    ) -> Result<GetWebAclResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn list_resources_for_web_acl(
        &mut self,
        _request: &ListResourcesForWebAclRequest,
    ) -> Result<ListResourcesForWebAclPage, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

pub type BlockedEnvTransport = BlockedEnvAwsWafTransport;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsWafProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_version: String,
    pub api_revision: String,
    pub allowlisted_operations: [String; 3],
    pub capability_digest: Digest,
    pub provenance: TransportProvenance,
    pub max_pages: u16,
    pub max_page_size: u16,
    pub max_response_bytes: usize,
    pub max_requests_per_read: u16,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub external_writes: bool,
}

pub type ProviderDefinition = AwsWafProviderDefinition;

impl AwsWafProviderDefinition {
    pub fn layer1(provenance: TransportProvenance) -> Self {
        let allowlisted_operations = [
            WafOperation::ListWebAcls.as_str().to_owned(),
            WafOperation::GetWebAcl.as_str().to_owned(),
            WafOperation::ListResourcesForWebAcl.as_str().to_owned(),
        ];
        let capability_digest = Digest::from_parts(
            "aws-waf-provider-capabilities/v1",
            &[
                AWS_WAF_POSTURE_PROVIDER_ID.to_owned(),
                AWS_WAF_POSTURE_PROVIDER_VERSION.to_owned(),
                AWS_WAF_POSTURE_API_REVISION.to_owned(),
                allowlisted_operations.join(","),
            ],
        );
        Self {
            schema_version: crate::AWS_WAF_POSTURE_SCHEMA_VERSION.to_owned(),
            provider_id: AWS_WAF_POSTURE_PROVIDER_ID.to_owned(),
            provider_version: AWS_WAF_POSTURE_PROVIDER_VERSION.to_owned(),
            api_version: AWS_WAF_API_VERSION.to_owned(),
            api_revision: AWS_WAF_POSTURE_API_REVISION.to_owned(),
            allowlisted_operations,
            capability_digest,
            provenance,
            max_pages: MAX_PAGES,
            max_page_size: MAX_PAGE_SIZE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_requests_per_read: MAX_REQUESTS_PER_READ,
            read_only: true,
            live_execution: false,
            native: false,
            connected: false,
            first_party: false,
            external_writes: false,
        }
    }

    pub fn provider_digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsWafProviderError {
    #[error("AWS WAF provider registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("AWS WAF SecretReference is revoked")]
    SecretRevoked,
    #[error("AWS WAF request is outside the registered scope")]
    ScopeMismatch,
    #[error("AWS WAF provider response was too large")]
    ResponseTooLarge,
    #[error("AWS WAF provider response was malformed")]
    MalformedResponse,
    #[error("AWS WAF provider pagination cursor drifted")]
    PaginationDrift,
    #[error("AWS WAF provider lock token drifted")]
    LockTokenDrift,
    #[error("AWS WAF provider revision drifted")]
    RevisionDrift,
    #[error("AWS WAF transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("AWS WAF provider model error: {0}")]
    Model(#[from] ModelError),
}

pub struct AwsWafPostureProvider<T: AwsWafTransport> {
    scope: AwsWafPostureScope,
    secret_reference: crate::SecretReference,
    transport: T,
    definition: AwsWafProviderDefinition,
}

pub type AwsWafProvider<T> = AwsWafPostureProvider<T>;

impl<T: AwsWafTransport> fmt::Debug for AwsWafPostureProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsWafPostureProvider")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsWafTransport> AwsWafPostureProvider<T> {
    pub fn new(
        scope: AwsWafPostureScope,
        secret_reference: crate::SecretReference,
        transport: T,
    ) -> Result<Self, AwsWafProviderError> {
        scope.validate()?;
        if secret_reference.scope_digest() != &scope.digest()
            || secret_reference.region() != &scope.region
        {
            return Err(AwsWafProviderError::ScopeMismatch);
        }
        let definition = AwsWafProviderDefinition::layer1(transport.provenance());
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
        })
    }

    pub fn scope(&self) -> &AwsWafPostureScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &crate::SecretReference {
        &self.secret_reference
    }

    pub fn definition(&self) -> &AwsWafProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn revoke_secret(&mut self) -> Result<(), ModelError> {
        self.secret_reference.revoke()
    }

    pub fn restore_secret(&mut self) -> Result<(), ModelError> {
        self.secret_reference.restore()
    }

    pub fn list_web_acls(
        &mut self,
        request: &ListWebAclsRequest,
    ) -> Result<ListWebAclsPage, AwsWafProviderError> {
        self.ensure_scope(request.scope_digest.clone())?;
        let page = self.transport.list_web_acls(request)?;
        page.validate_for(request)
            .map_err(|_| AwsWafProviderError::PaginationDrift)?;
        Ok(page)
    }

    pub fn get_web_acl(
        &mut self,
        request: &GetWebAclRequest,
    ) -> Result<GetWebAclResponse, AwsWafProviderError> {
        self.ensure_scope(request.scope_digest.clone())?;
        if !self.scope.is_web_acl_allowed(request.web_acl()) {
            return Err(AwsWafProviderError::ScopeMismatch);
        }
        let response = self.transport.get_web_acl(request)?;
        response
            .validate_for(request)
            .map_err(|_| AwsWafProviderError::MalformedResponse)?;
        if response.details.revision != request.web_acl().revision() {
            return Err(AwsWafProviderError::RevisionDrift);
        }
        if let Some(expected) = request.web_acl().expected_lock_token_digest()
            && expected != &response.details.lock_token_digest()
        {
            return Err(AwsWafProviderError::LockTokenDrift);
        }
        Ok(response)
    }

    pub fn list_resources_for_web_acl(
        &mut self,
        request: &ListResourcesForWebAclRequest,
    ) -> Result<ListResourcesForWebAclPage, AwsWafProviderError> {
        self.ensure_scope(request.scope_digest.clone())?;
        if !self.scope.is_web_acl_allowed(request.web_acl()) {
            return Err(AwsWafProviderError::ScopeMismatch);
        }
        let page = self.transport.list_resources_for_web_acl(request)?;
        page.validate_for(request)
            .map_err(|_| AwsWafProviderError::PaginationDrift)?;
        for association in &page.associations {
            if self
                .scope
                .resource_for_arn(association.resource.arn())
                .is_some_and(|resource| resource.revision() != association.resource.revision())
            {
                return Err(AwsWafProviderError::RevisionDrift);
            }
        }
        Ok(page)
    }

    fn ensure_scope(&self, scope_digest: Digest) -> Result<(), AwsWafProviderError> {
        if self.secret_reference.is_revoked() {
            return Err(AwsWafProviderError::SecretRevoked);
        }
        if scope_digest != self.scope.digest() {
            return Err(AwsWafProviderError::ScopeMismatch);
        }
        Ok(())
    }
}

impl FixtureAwsWafTransport {
    /// Deterministic fixture for the first allowlisted ACL and resource.
    pub fn for_scope(scope: &AwsWafPostureScope) -> Result<Self, ModelError> {
        let acl = scope.web_acl().clone();
        let resource = scope.resource().clone();
        let list_request = ListWebAclsRequest::new(scope, None)?;
        let get_request = GetWebAclRequest::new(scope, acl.clone())?;
        let resources_request = ListResourcesForWebAclRequest::new(scope, acl.clone(), None)?;
        let details = WebAclDetails::new(
            acl.clone(),
            crate::ActionClass::Block,
            vec![crate::RuleActionSummary::new(crate::ActionClass::Block, 1)?],
            "fixture-lock-token",
            acl.revision(),
        )?;
        let mut transport = Self::default();
        transport.queue_list_web_acls(Ok(ListWebAclsPage::new(
            &list_request,
            vec![WebAclListItem::new(acl.clone())],
            None,
            512,
        )?));
        transport.queue_get_web_acl(Ok(GetWebAclResponse::new(&get_request, details, 768)?));
        transport.queue_list_resources_for_web_acl(Ok(ListResourcesForWebAclPage::new(
            &resources_request,
            vec![ResourceAssociation::new(resource, crate::Revision::new(1)?)],
            None,
            512,
        )?));
        Ok(transport)
    }
}

impl LoopbackAwsWafTransport {
    pub fn for_scope(scope: &AwsWafPostureScope) -> Result<Self, ModelError> {
        let fixture = FixtureAwsWafTransport::for_scope(scope)?;
        Ok(Self {
            responses: fixture.responses,
            calls: Vec::new(),
        })
    }
}
