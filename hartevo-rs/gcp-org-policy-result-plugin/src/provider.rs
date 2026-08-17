//! Provider and transport seams for bounded Organization Policy reads.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AvailableConstraintSummary, ConstraintId, Digest, GcpOrgPolicyScope, GcpResource,
    OpaquePageToken, PaginationEvidence, PolicySummary, ReadBounds, ReadOperation, Revision,
};
use crate::{API_VERSION, LAYER1_PERMISSIONS, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("provider returned HTTP 400 bad request")]
    BadRequest,
    #[error("provider returned HTTP 401 unauthorized")]
    Unauthorized,
    #[error("provider returned HTTP 403 forbidden")]
    Forbidden,
    #[error("provider returned HTTP 404 not found")]
    NotFound,
    #[error("provider returned HTTP 409 conflict")]
    Conflict,
    #[error("provider returned HTTP 429 throttled")]
    Throttled,
    #[error("provider returned a 5xx server failure")]
    ServerFailure,
    #[error("provider request timed out")]
    Timeout,
    #[error("provider response was malformed")]
    Malformed,
    #[error("live provider transport is unavailable in Layer 1: BLOCKED_ENV")]
    BlockedEnv,
}

pub type TransportFailure = TransportError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpOrgPolicyProviderDefinition {
    pub provider_id: String,
    pub api_version: String,
    pub api_revision: String,
    pub provider_revision: Revision,
    pub release: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub read_only: bool,
}

impl GcpOrgPolicyProviderDefinition {
    pub fn new(provider_revision: Revision, release: impl Into<String>) -> Self {
        let release = release.into();
        let capability_digest = Digest::from_parts(
            "gcp-org-policy-capabilities/v1",
            &[
                ("permissions", LAYER1_PERMISSIONS.to_vec().join(",")),
                ("operations", format!("{:?}", ReadOperation::ALL)),
            ],
        );
        let provider_digest = Digest::from_parts(
            "gcp-org-policy-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("api_version", API_VERSION.to_owned()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
                ("provider_revision", provider_revision.get().to_string()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
            ],
        );
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            api_version: API_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            provider_revision,
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
            read_only: true,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListPoliciesRequest {
    pub resource: GcpResource,
    pub constraint: Option<ConstraintId>,
    pub page_size: u16,
    pub page_token: Option<OpaquePageToken>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
}

impl fmt::Debug for ListPoliciesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListPoliciesRequest")
            .field("resource", &self.resource)
            .field("constraint", &self.constraint)
            .field("page_size", &self.page_size)
            .field("page_token", &self.page_token)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl ListPoliciesRequest {
    pub fn new(
        scope: &GcpOrgPolicyScope,
        bounds: ReadBounds,
        constraint: Option<ConstraintId>,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, crate::model::ModelError> {
        if let Some(constraint) = &constraint
            && !scope.contains_constraint(constraint)
        {
            return Err(crate::model::ModelError::Invalid {
                field: "constraint allowlist",
            });
        }
        let request_digest = request_digest(
            ReadOperation::ListPolicies,
            &scope.resource,
            constraint.as_ref(),
            bounds.page_size,
            page_token.as_ref(),
            scope.digest(),
            scope.permissions.digest(),
        );
        Ok(Self {
            resource: scope.resource.clone(),
            constraint,
            page_size: bounds.page_size,
            page_token,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permissions.permission_digest.clone(),
            request_digest,
        })
    }

    pub fn with_page_token(
        &self,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, crate::model::ModelError> {
        let request_digest = request_digest(
            ReadOperation::ListPolicies,
            &self.resource,
            self.constraint.as_ref(),
            self.page_size,
            page_token.as_ref(),
            &self.scope_digest,
            &self.permission_digest,
        );
        Ok(Self {
            resource: self.resource.clone(),
            constraint: self.constraint.clone(),
            page_size: self.page_size,
            page_token,
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            request_digest,
        })
    }

    pub fn page_token_digest(&self) -> Option<Digest> {
        self.page_token.as_ref().map(OpaquePageToken::digest)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetPolicyRequest {
    pub resource: GcpResource,
    pub constraint: ConstraintId,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
}

impl fmt::Debug for GetPolicyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetPolicyRequest")
            .field("resource", &self.resource)
            .field("constraint", &self.constraint)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl GetPolicyRequest {
    pub fn new(
        scope: &GcpOrgPolicyScope,
        constraint: ConstraintId,
    ) -> Result<Self, crate::model::ModelError> {
        if !scope.contains_constraint(&constraint) {
            return Err(crate::model::ModelError::Invalid {
                field: "constraint allowlist",
            });
        }
        let request_digest = request_digest(
            ReadOperation::GetPolicy,
            &scope.resource,
            Some(&constraint),
            0,
            None,
            scope.digest(),
            scope.permissions.digest(),
        );
        Ok(Self {
            resource: scope.resource.clone(),
            constraint,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permissions.permission_digest.clone(),
            request_digest,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetEffectivePolicyRequest {
    pub resource: GcpResource,
    pub constraint: ConstraintId,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
}

impl fmt::Debug for GetEffectivePolicyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetEffectivePolicyRequest")
            .field("resource", &self.resource)
            .field("constraint", &self.constraint)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl GetEffectivePolicyRequest {
    pub fn new(
        scope: &GcpOrgPolicyScope,
        constraint: ConstraintId,
    ) -> Result<Self, crate::model::ModelError> {
        if !scope.contains_constraint(&constraint) {
            return Err(crate::model::ModelError::Invalid {
                field: "constraint allowlist",
            });
        }
        let request_digest = request_digest(
            ReadOperation::GetEffectivePolicy,
            &scope.resource,
            Some(&constraint),
            0,
            None,
            scope.digest(),
            scope.permissions.digest(),
        );
        Ok(Self {
            resource: scope.resource.clone(),
            constraint,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permissions.permission_digest.clone(),
            request_digest,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListAvailableConstraintsRequest {
    pub resource: GcpResource,
    pub page_size: u16,
    pub page_token: Option<OpaquePageToken>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
}

pub type ListConstraintsRequest = ListAvailableConstraintsRequest;

impl fmt::Debug for ListAvailableConstraintsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListAvailableConstraintsRequest")
            .field("resource", &self.resource)
            .field("page_size", &self.page_size)
            .field("page_token", &self.page_token)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl ListAvailableConstraintsRequest {
    pub fn new(
        scope: &GcpOrgPolicyScope,
        bounds: ReadBounds,
        page_token: Option<OpaquePageToken>,
    ) -> Self {
        let request_digest = request_digest(
            ReadOperation::ListAvailableConstraints,
            &scope.resource,
            None,
            bounds.page_size,
            page_token.as_ref(),
            scope.digest(),
            scope.permissions.digest(),
        );
        Self {
            resource: scope.resource.clone(),
            page_size: bounds.page_size,
            page_token,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permissions.permission_digest.clone(),
            request_digest,
        }
    }

    #[must_use]
    pub fn with_page_token(&self, page_token: Option<OpaquePageToken>) -> Self {
        let request_digest = request_digest(
            ReadOperation::ListAvailableConstraints,
            &self.resource,
            None,
            self.page_size,
            page_token.as_ref(),
            &self.scope_digest,
            &self.permission_digest,
        );
        Self {
            resource: self.resource.clone(),
            page_size: self.page_size,
            page_token,
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            request_digest,
        }
    }

    pub fn page_token_digest(&self) -> Option<Digest> {
        self.page_token.as_ref().map(OpaquePageToken::digest)
    }
}

fn request_digest(
    operation: ReadOperation,
    resource: &GcpResource,
    constraint: Option<&ConstraintId>,
    page_size: u16,
    page_token: Option<&OpaquePageToken>,
    scope_digest: &Digest,
    permission_digest: &Digest,
) -> Digest {
    Digest::from_parts(
        "gcp-org-policy-request/v1",
        &[
            ("operation", format!("{operation:?}")),
            ("resource", resource.canonical_name()),
            (
                "constraint",
                constraint.map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            ("page_size", page_size.to_string()),
            (
                "page_token",
                page_token.map_or_else(String::new, |token| token.digest().as_str().to_owned()),
            ),
            ("scope", scope_digest.as_str().to_owned()),
            ("permission", permission_digest.as_str().to_owned()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPage {
    pub policies: Vec<PolicySummary>,
    pub next_page_token: Option<OpaquePageToken>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
    pub page_digest: Digest,
}

impl PolicyPage {
    pub fn new(
        policies: Vec<PolicySummary>,
        next_page_token: Option<OpaquePageToken>,
        scope_digest: Digest,
        permission_digest: Digest,
        request_digest: Digest,
    ) -> Self {
        let page_digest = Digest::from_parts(
            "gcp-org-policy-policy-page/v1",
            &[
                (
                    "policies",
                    policies
                        .iter()
                        .map(|policy| policy.policy_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    next_page_token
                        .as_ref()
                        .map_or_else(String::new, |token| token.digest().as_str().to_owned()),
                ),
                ("scope", scope_digest.as_str().to_owned()),
                ("permission", permission_digest.as_str().to_owned()),
                ("request", request_digest.as_str().to_owned()),
            ],
        );
        Self {
            policies,
            next_page_token,
            scope_digest,
            permission_digest,
            request_digest,
            page_digest,
        }
    }

    pub fn for_request(
        policies: Vec<PolicySummary>,
        next_page_token: Option<OpaquePageToken>,
        request: &ListPoliciesRequest,
    ) -> Self {
        Self::new(
            policies,
            next_page_token,
            request.scope_digest.clone(),
            request.permission_digest.clone(),
            request.request_digest.clone(),
        )
    }

    pub fn digest_matches(&self) -> bool {
        Self::new(
            self.policies.clone(),
            self.next_page_token.clone(),
            self.scope_digest.clone(),
            self.permission_digest.clone(),
            self.request_digest.clone(),
        )
        .page_digest
            == self.page_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstraintPage {
    pub constraints: Vec<AvailableConstraintSummary>,
    pub next_page_token: Option<OpaquePageToken>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
    pub page_digest: Digest,
}

pub type ListConstraintsPage = ConstraintPage;

impl ConstraintPage {
    pub fn new(
        constraints: Vec<AvailableConstraintSummary>,
        next_page_token: Option<OpaquePageToken>,
        scope_digest: Digest,
        permission_digest: Digest,
        request_digest: Digest,
    ) -> Self {
        let page_digest = Digest::from_parts(
            "gcp-org-policy-constraint-page/v1",
            &[
                (
                    "constraints",
                    constraints
                        .iter()
                        .map(|constraint| constraint.constraint.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    next_page_token
                        .as_ref()
                        .map_or_else(String::new, |token| token.digest().as_str().to_owned()),
                ),
                ("scope", scope_digest.as_str().to_owned()),
                ("permission", permission_digest.as_str().to_owned()),
                ("request", request_digest.as_str().to_owned()),
            ],
        );
        Self {
            constraints,
            next_page_token,
            scope_digest,
            permission_digest,
            request_digest,
            page_digest,
        }
    }

    pub fn for_request(
        constraints: Vec<AvailableConstraintSummary>,
        next_page_token: Option<OpaquePageToken>,
        request: &ListAvailableConstraintsRequest,
    ) -> Self {
        Self::new(
            constraints,
            next_page_token,
            request.scope_digest.clone(),
            request.permission_digest.clone(),
            request.request_digest.clone(),
        )
    }

    pub fn digest_matches(&self) -> bool {
        Self::new(
            self.constraints.clone(),
            self.next_page_token.clone(),
            self.scope_digest.clone(),
            self.permission_digest.clone(),
            self.request_digest.clone(),
        )
        .page_digest
            == self.page_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetPolicyResponse {
    pub policy: PolicySummary,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
}

impl GetPolicyResponse {
    pub fn new(
        policy: PolicySummary,
        scope_digest: Digest,
        permission_digest: Digest,
        request_digest: Digest,
    ) -> Self {
        let response_digest = Digest::from_parts(
            "gcp-org-policy-policy-response/v1",
            &[
                ("policy", policy.policy_digest.as_str().to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
                ("permission", permission_digest.as_str().to_owned()),
                ("request", request_digest.as_str().to_owned()),
            ],
        );
        Self {
            policy,
            scope_digest,
            permission_digest,
            request_digest,
            response_digest,
        }
    }

    pub fn for_request(policy: PolicySummary, request: &GetPolicyRequest) -> Self {
        Self::new(
            policy,
            request.scope_digest.clone(),
            request.permission_digest.clone(),
            request.request_digest.clone(),
        )
    }

    pub fn digest_matches(&self) -> bool {
        Self::new(
            self.policy.clone(),
            self.scope_digest.clone(),
            self.permission_digest.clone(),
            self.request_digest.clone(),
        )
        .response_digest
            == self.response_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpOrgPolicyReadRecord {
    pub operation: ReadOperation,
    pub resource: GcpResource,
    pub policies: Vec<PolicySummary>,
    pub available_constraints: Vec<AvailableConstraintSummary>,
    pub pagination: PaginationEvidence,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
    pub read_digest: Digest,
    pub provider_digest: Digest,
    pub provenance: TransportProvenance,
}

impl GcpOrgPolicyReadRecord {
    fn from_policies(
        operation: ReadOperation,
        request: &ListPoliciesRequest,
        policies: Vec<PolicySummary>,
        pagination: PaginationEvidence,
        provider_digest: Digest,
        provenance: TransportProvenance,
    ) -> Self {
        let read_digest = Digest::from_parts(
            "gcp-org-policy-read/v1",
            &[
                ("operation", format!("{operation:?}")),
                (
                    "items",
                    policies
                        .iter()
                        .map(|policy| policy.policy_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "pagination",
                    pagination.pagination_digest.as_str().to_owned(),
                ),
                ("scope", request.scope_digest.as_str().to_owned()),
                ("permission", request.permission_digest.as_str().to_owned()),
                ("provider", provider_digest.as_str().to_owned()),
            ],
        );
        Self {
            operation,
            resource: request.resource.clone(),
            policies,
            available_constraints: Vec::new(),
            pagination,
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            request_digest: request.request_digest.clone(),
            read_digest,
            provider_digest,
            provenance,
        }
    }

    fn from_constraints(
        request: &ListAvailableConstraintsRequest,
        available_constraints: Vec<AvailableConstraintSummary>,
        pagination: PaginationEvidence,
        provider_digest: Digest,
        provenance: TransportProvenance,
    ) -> Self {
        let read_digest = Digest::from_parts(
            "gcp-org-policy-read/v1",
            &[
                (
                    "operation",
                    format!("{:?}", ReadOperation::ListAvailableConstraints),
                ),
                (
                    "items",
                    available_constraints
                        .iter()
                        .map(|constraint| constraint.definition_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "pagination",
                    pagination.pagination_digest.as_str().to_owned(),
                ),
                ("scope", request.scope_digest.as_str().to_owned()),
                ("permission", request.permission_digest.as_str().to_owned()),
                ("provider", provider_digest.as_str().to_owned()),
            ],
        );
        Self {
            operation: ReadOperation::ListAvailableConstraints,
            resource: request.resource.clone(),
            policies: Vec::new(),
            available_constraints,
            pagination,
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            request_digest: request.request_digest.clone(),
            read_digest,
            provider_digest,
            provenance,
        }
    }

    fn from_single_policy(
        operation: ReadOperation,
        resource: GcpResource,
        request_digest: Digest,
        scope_digest: Digest,
        permission_digest: Digest,
        policy: PolicySummary,
        provider_digest: Digest,
        provenance: TransportProvenance,
    ) -> Self {
        let pagination =
            PaginationEvidence::new(1, 1, true, Vec::new(), None, vec![request_digest.clone()]);
        let read_digest = Digest::from_parts(
            "gcp-org-policy-read/v1",
            &[
                ("operation", format!("{operation:?}")),
                ("policy", policy.policy_digest.as_str().to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
                ("permission", permission_digest.as_str().to_owned()),
                ("provider", provider_digest.as_str().to_owned()),
            ],
        );
        Self {
            operation,
            resource,
            policies: vec![policy],
            available_constraints: Vec::new(),
            pagination,
            scope_digest,
            permission_digest,
            request_digest,
            read_digest,
            provider_digest,
            provenance,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    #[error("model validation failed: {0}")]
    Model(#[from] crate::model::ModelError),
    #[error("transport failed: {0}")]
    Transport(#[from] TransportError),
    #[error("provider definition drifted")]
    ProviderDrift,
    #[error("scope digest drifted")]
    ScopeDigestMismatch,
    #[error("permission digest drifted")]
    PermissionDigestMismatch,
    #[error("response request digest drifted")]
    RequestDigestMismatch,
    #[error("response page digest is invalid")]
    PageDigestMismatch,
    #[error("duplicate policy or constraint item")]
    DuplicateItem,
    #[error("opaque page token repeated or was not bound to the request")]
    PaginationTokenMismatch,
    #[error("bounded pagination did not complete")]
    PaginationIncomplete,
    #[error("response item bound exceeded")]
    ItemBoundExceeded,
    #[error("response item was malformed or outside scope")]
    MalformedResponse,
}

pub trait GcpOrgPolicyTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_policies(
        &mut self,
        request: &ListPoliciesRequest,
    ) -> Result<PolicyPage, TransportError>;

    fn get_policy(
        &mut self,
        request: &GetPolicyRequest,
    ) -> Result<GetPolicyResponse, TransportError>;

    fn get_effective_policy(
        &mut self,
        request: &GetEffectivePolicyRequest,
    ) -> Result<GetPolicyResponse, TransportError>;

    fn list_available_constraints(
        &mut self,
        request: &ListAvailableConstraintsRequest,
    ) -> Result<ConstraintPage, TransportError>;
}

pub struct GcpOrgPolicyProvider<T> {
    transport: T,
    bounds: ReadBounds,
    definition: GcpOrgPolicyProviderDefinition,
}

impl<T: GcpOrgPolicyTransport> fmt::Debug for GcpOrgPolicyProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpOrgPolicyProvider")
            .field("bounds", &self.bounds)
            .field("definition", &self.definition)
            .field("provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: GcpOrgPolicyTransport> GcpOrgPolicyProvider<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            bounds: ReadBounds::default(),
            definition: GcpOrgPolicyProviderDefinition::new(
                Revision::new(1).expect("constant provider revision"),
                PLUGIN_VERSION,
            ),
        }
    }

    pub fn with_bounds(transport: T, bounds: ReadBounds) -> Self {
        Self {
            transport,
            bounds,
            definition: GcpOrgPolicyProviderDefinition::new(
                Revision::new(1).expect("constant provider revision"),
                PLUGIN_VERSION,
            ),
        }
    }

    pub fn with_definition(
        transport: T,
        bounds: ReadBounds,
        definition: GcpOrgPolicyProviderDefinition,
    ) -> Self {
        Self {
            transport,
            bounds,
            definition,
        }
    }

    pub fn bounds(&self) -> ReadBounds {
        self.bounds
    }

    pub fn definition(&self) -> &GcpOrgPolicyProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn list_policies(
        &mut self,
        request: ListPoliciesRequest,
    ) -> Result<GcpOrgPolicyReadRecord, ProviderError> {
        let mut current_request = request.clone();
        let mut policy_items = Vec::new();
        let mut seen_policy_digests = BTreeSet::new();
        let mut seen_token_digests = BTreeSet::new();
        let mut page_token_digests = Vec::new();
        let mut request_digests = Vec::new();
        let mut pages_observed = 0;

        if let Some(token) = &current_request.page_token {
            let digest = token.digest();
            seen_token_digests.insert(digest.clone());
            page_token_digests.push(digest);
        }

        loop {
            if pages_observed >= self.bounds.max_pages {
                return Err(ProviderError::PaginationIncomplete);
            }
            let page = self.transport.list_policies(&current_request)?;
            if !page.digest_matches() {
                return Err(ProviderError::PageDigestMismatch);
            }
            Self::validate_page(
                page.scope_digest.clone(),
                page.permission_digest.clone(),
                page.request_digest.clone(),
                &current_request,
            )?;
            if page.policies.iter().any(|policy| {
                policy.validate().is_err()
                    || policy.resource != current_request.resource
                    || current_request
                        .constraint
                        .as_ref()
                        .is_some_and(|constraint| &policy.constraint != constraint)
            }) {
                return Err(ProviderError::MalformedResponse);
            }
            if page
                .policies
                .iter()
                .any(|policy| !seen_policy_digests.insert(policy.policy_digest.clone()))
            {
                return Err(ProviderError::DuplicateItem);
            }
            policy_items.extend(page.policies);
            if policy_items.len() > self.bounds.max_items {
                return Err(ProviderError::ItemBoundExceeded);
            }
            pages_observed += 1;
            request_digests.push(current_request.request_digest.clone());
            if let Some(token) = page.next_page_token {
                let digest = token.digest();
                if !seen_token_digests.insert(digest.clone()) {
                    return Err(ProviderError::PaginationTokenMismatch);
                }
                page_token_digests.push(digest);
                if pages_observed >= self.bounds.max_pages {
                    return Err(ProviderError::PaginationIncomplete);
                }
                current_request = current_request.with_page_token(Some(token))?;
            } else {
                break;
            }
        }

        let pagination = PaginationEvidence::new(
            pages_observed,
            policy_items.len(),
            true,
            page_token_digests,
            None,
            request_digests,
        );
        Ok(GcpOrgPolicyReadRecord::from_policies(
            ReadOperation::ListPolicies,
            &request,
            policy_items,
            pagination,
            self.definition.provider_digest.clone(),
            self.provenance(),
        ))
    }

    pub fn get_policy(
        &mut self,
        request: GetPolicyRequest,
    ) -> Result<GcpOrgPolicyReadRecord, ProviderError> {
        let response = self.transport.get_policy(&request)?;
        if !response.digest_matches() {
            return Err(ProviderError::PageDigestMismatch);
        }
        Self::validate_response(
            response.scope_digest.clone(),
            response.permission_digest.clone(),
            response.request_digest.clone(),
            &request.scope_digest,
            &request.permission_digest,
            &request.request_digest,
        )?;
        if response.policy.validate().is_err()
            || response.policy.resource != request.resource
            || response.policy.constraint != request.constraint
        {
            return Err(ProviderError::MalformedResponse);
        }
        Ok(GcpOrgPolicyReadRecord::from_single_policy(
            ReadOperation::GetPolicy,
            request.resource,
            request.request_digest,
            request.scope_digest,
            request.permission_digest,
            response.policy,
            self.definition.provider_digest.clone(),
            self.provenance(),
        ))
    }

    pub fn get_effective_policy(
        &mut self,
        request: GetEffectivePolicyRequest,
    ) -> Result<GcpOrgPolicyReadRecord, ProviderError> {
        let response = self.transport.get_effective_policy(&request)?;
        if !response.digest_matches() {
            return Err(ProviderError::PageDigestMismatch);
        }
        Self::validate_response(
            response.scope_digest.clone(),
            response.permission_digest.clone(),
            response.request_digest.clone(),
            &request.scope_digest,
            &request.permission_digest,
            &request.request_digest,
        )?;
        if response.policy.validate().is_err()
            || response.policy.resource != request.resource
            || response.policy.constraint != request.constraint
        {
            return Err(ProviderError::MalformedResponse);
        }
        Ok(GcpOrgPolicyReadRecord::from_single_policy(
            ReadOperation::GetEffectivePolicy,
            request.resource,
            request.request_digest,
            request.scope_digest,
            request.permission_digest,
            response.policy,
            self.definition.provider_digest.clone(),
            self.provenance(),
        ))
    }

    pub fn list_available_constraints(
        &mut self,
        request: ListAvailableConstraintsRequest,
    ) -> Result<GcpOrgPolicyReadRecord, ProviderError> {
        let mut current_request = request.clone();
        let mut constraints = Vec::new();
        let mut seen_constraints = BTreeSet::new();
        let mut seen_token_digests = BTreeSet::new();
        let mut page_token_digests = Vec::new();
        let mut request_digests = Vec::new();
        let mut pages_observed = 0;

        if let Some(token) = &current_request.page_token {
            let digest = token.digest();
            seen_token_digests.insert(digest.clone());
            page_token_digests.push(digest);
        }

        loop {
            if pages_observed >= self.bounds.max_pages {
                return Err(ProviderError::PaginationIncomplete);
            }
            let page = self
                .transport
                .list_available_constraints(&current_request)?;
            if !page.digest_matches() {
                return Err(ProviderError::PageDigestMismatch);
            }
            Self::validate_constraint_page(
                page.scope_digest.clone(),
                page.permission_digest.clone(),
                page.request_digest.clone(),
                &current_request,
            )?;
            if page.constraints.iter().any(|constraint| {
                constraint.validate().is_err()
                    || !seen_constraints.insert(constraint.constraint.clone())
            }) {
                return Err(ProviderError::DuplicateItem);
            }
            constraints.extend(page.constraints);
            if constraints.len() > self.bounds.max_items {
                return Err(ProviderError::ItemBoundExceeded);
            }
            pages_observed += 1;
            request_digests.push(current_request.request_digest.clone());
            if let Some(token) = page.next_page_token {
                let digest = token.digest();
                if !seen_token_digests.insert(digest.clone()) {
                    return Err(ProviderError::PaginationTokenMismatch);
                }
                page_token_digests.push(digest);
                if pages_observed >= self.bounds.max_pages {
                    return Err(ProviderError::PaginationIncomplete);
                }
                current_request = current_request.with_page_token(Some(token));
            } else {
                break;
            }
        }
        let pagination = PaginationEvidence::new(
            pages_observed,
            constraints.len(),
            true,
            page_token_digests,
            None,
            request_digests,
        );
        Ok(GcpOrgPolicyReadRecord::from_constraints(
            &request,
            constraints,
            pagination,
            self.definition.provider_digest.clone(),
            self.provenance(),
        ))
    }

    fn validate_page(
        scope_digest: Digest,
        permission_digest: Digest,
        response_request_digest: Digest,
        request: &ListPoliciesRequest,
    ) -> Result<(), ProviderError> {
        Self::validate_response(
            scope_digest,
            permission_digest,
            response_request_digest,
            &request.scope_digest,
            &request.permission_digest,
            &request.request_digest,
        )
    }

    fn validate_constraint_page(
        scope_digest: Digest,
        permission_digest: Digest,
        response_request_digest: Digest,
        request: &ListAvailableConstraintsRequest,
    ) -> Result<(), ProviderError> {
        Self::validate_response(
            scope_digest,
            permission_digest,
            response_request_digest,
            &request.scope_digest,
            &request.permission_digest,
            &request.request_digest,
        )
    }

    fn validate_response(
        scope_digest: Digest,
        permission_digest: Digest,
        response_request_digest: Digest,
        expected_scope_digest: &Digest,
        expected_permission_digest: &Digest,
        expected_request_digest: &Digest,
    ) -> Result<(), ProviderError> {
        if scope_digest != *expected_scope_digest {
            return Err(ProviderError::ScopeDigestMismatch);
        }
        if permission_digest != *expected_permission_digest {
            return Err(ProviderError::PermissionDigestMismatch);
        }
        if response_request_digest != *expected_request_digest {
            return Err(ProviderError::RequestDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportCall {
    pub operation: ReadOperation,
    pub request_digest: Digest,
    pub page_token_digest: Option<Digest>,
    pub provenance: TransportProvenance,
}

#[derive(Debug, Default)]
pub struct FixtureGcpOrgPolicyTransport {
    list_policies: VecDeque<Result<PolicyPage, TransportError>>,
    get_policies: VecDeque<Result<GetPolicyResponse, TransportError>>,
    get_effective_policies: VecDeque<Result<GetPolicyResponse, TransportError>>,
    list_constraints: VecDeque<Result<ConstraintPage, TransportError>>,
}

impl FixtureGcpOrgPolicyTransport {
    pub fn fixture() -> Self {
        Self::default()
    }

    pub fn queue_list_policies(&mut self, response: Result<PolicyPage, TransportError>) {
        self.list_policies.push_back(response);
    }

    pub fn queue_get_policy(&mut self, response: Result<GetPolicyResponse, TransportError>) {
        self.get_policies.push_back(response);
    }

    pub fn queue_get_effective_policy(
        &mut self,
        response: Result<GetPolicyResponse, TransportError>,
    ) {
        self.get_effective_policies.push_back(response);
    }

    pub fn queue_list_available_constraints(
        &mut self,
        response: Result<ConstraintPage, TransportError>,
    ) {
        self.list_constraints.push_back(response);
    }

    fn pop<T>(queue: &mut VecDeque<Result<T, TransportError>>) -> Result<T, TransportError> {
        queue.pop_front().unwrap_or(Err(TransportError::Malformed))
    }
}

impl GcpOrgPolicyTransport for FixtureGcpOrgPolicyTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_policies(
        &mut self,
        _request: &ListPoliciesRequest,
    ) -> Result<PolicyPage, TransportError> {
        Self::pop(&mut self.list_policies)
    }

    fn get_policy(
        &mut self,
        _request: &GetPolicyRequest,
    ) -> Result<GetPolicyResponse, TransportError> {
        Self::pop(&mut self.get_policies)
    }

    fn get_effective_policy(
        &mut self,
        _request: &GetEffectivePolicyRequest,
    ) -> Result<GetPolicyResponse, TransportError> {
        Self::pop(&mut self.get_effective_policies)
    }

    fn list_available_constraints(
        &mut self,
        _request: &ListAvailableConstraintsRequest,
    ) -> Result<ConstraintPage, TransportError> {
        Self::pop(&mut self.list_constraints)
    }
}

#[derive(Debug, Default)]
pub struct LoopbackGcpOrgPolicyTransport {
    inner: FixtureGcpOrgPolicyTransport,
}

impl LoopbackGcpOrgPolicyTransport {
    pub fn loopback() -> Self {
        Self::default()
    }

    pub fn queue_list_policies(&mut self, response: Result<PolicyPage, TransportError>) {
        self.inner.queue_list_policies(response);
    }

    pub fn queue_get_policy(&mut self, response: Result<GetPolicyResponse, TransportError>) {
        self.inner.queue_get_policy(response);
    }

    pub fn queue_get_effective_policy(
        &mut self,
        response: Result<GetPolicyResponse, TransportError>,
    ) {
        self.inner.queue_get_effective_policy(response);
    }

    pub fn queue_list_available_constraints(
        &mut self,
        response: Result<ConstraintPage, TransportError>,
    ) {
        self.inner.queue_list_available_constraints(response);
    }
}

impl GcpOrgPolicyTransport for LoopbackGcpOrgPolicyTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_policies(
        &mut self,
        request: &ListPoliciesRequest,
    ) -> Result<PolicyPage, TransportError> {
        self.inner.list_policies(request)
    }

    fn get_policy(
        &mut self,
        request: &GetPolicyRequest,
    ) -> Result<GetPolicyResponse, TransportError> {
        self.inner.get_policy(request)
    }

    fn get_effective_policy(
        &mut self,
        request: &GetEffectivePolicyRequest,
    ) -> Result<GetPolicyResponse, TransportError> {
        self.inner.get_effective_policy(request)
    }

    fn list_available_constraints(
        &mut self,
        request: &ListAvailableConstraintsRequest,
    ) -> Result<ConstraintPage, TransportError> {
        self.inner.list_available_constraints(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl GcpOrgPolicyTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_policies(
        &mut self,
        _request: &ListPoliciesRequest,
    ) -> Result<PolicyPage, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn get_policy(
        &mut self,
        _request: &GetPolicyRequest,
    ) -> Result<GetPolicyResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn get_effective_policy(
        &mut self,
        _request: &GetEffectivePolicyRequest,
    ) -> Result<GetPolicyResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn list_available_constraints(
        &mut self,
        _request: &ListAvailableConstraintsRequest,
    ) -> Result<ConstraintPage, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

pub struct RecordingGcpOrgPolicyTransport<T> {
    inner: T,
    calls: Vec<TransportCall>,
}

impl<T: GcpOrgPolicyTransport> fmt::Debug for RecordingGcpOrgPolicyTransport<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingGcpOrgPolicyTransport")
            .field("call_count", &self.calls.len())
            .field("inner", &std::any::type_name::<T>())
            .field("provenance", &TransportProvenance::Recording)
            .finish()
    }
}

impl<T: GcpOrgPolicyTransport> RecordingGcpOrgPolicyTransport<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            calls: Vec::new(),
        }
    }

    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    fn push(&mut self, operation: ReadOperation, request_digest: &Digest, token: Option<Digest>) {
        self.calls.push(TransportCall {
            operation,
            request_digest: request_digest.clone(),
            page_token_digest: token,
            provenance: TransportProvenance::Recording,
        });
    }
}

impl<T: GcpOrgPolicyTransport> GcpOrgPolicyTransport for RecordingGcpOrgPolicyTransport<T> {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn list_policies(
        &mut self,
        request: &ListPoliciesRequest,
    ) -> Result<PolicyPage, TransportError> {
        self.push(
            ReadOperation::ListPolicies,
            &request.request_digest,
            request.page_token_digest(),
        );
        self.inner.list_policies(request)
    }

    fn get_policy(
        &mut self,
        request: &GetPolicyRequest,
    ) -> Result<GetPolicyResponse, TransportError> {
        self.push(ReadOperation::GetPolicy, &request.request_digest, None);
        self.inner.get_policy(request)
    }

    fn get_effective_policy(
        &mut self,
        request: &GetEffectivePolicyRequest,
    ) -> Result<GetPolicyResponse, TransportError> {
        self.push(
            ReadOperation::GetEffectivePolicy,
            &request.request_digest,
            None,
        );
        self.inner.get_effective_policy(request)
    }

    fn list_available_constraints(
        &mut self,
        request: &ListAvailableConstraintsRequest,
    ) -> Result<ConstraintPage, TransportError> {
        self.push(
            ReadOperation::ListAvailableConstraints,
            &request.request_digest,
            request.page_token_digest(),
        );
        self.inner.list_available_constraints(request)
    }
}
