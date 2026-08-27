//! Provider and transport seams for bounded, read-only AWS Organizations calls.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_ORGANIZATIONS_API_VERSION, AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_JSON,
    AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_VERSION, AWS_ORGANIZATIONS_GOVERNANCE_PROVIDER_ID,
    AWS_ORGANIZATIONS_PROVIDER_VERSION,
    model::{
        Digest, OpaquePageToken, OrganizationId, PolicyIdentity, PolicyType, ReadBounds,
        ReadOperation, TargetReference, digest_serializable,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn native(self) -> bool {
        false
    }

    pub const fn connected(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportFailure {
    BadRequest,
    Unauthorized,
    AccessDenied,
    NotFound,
    Conflict,
    Throttled,
    Server,
    Timeout,
    BlockedEnv,
    Malformed,
}

impl TransportFailure {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::Throttled => Some(429),
            Self::Server => Some(500),
            Self::Timeout | Self::BlockedEnv | Self::Malformed => None,
        }
    }

    pub const fn from_status(status: u16) -> Self {
        match status {
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::AccessDenied,
            404 => Self::NotFound,
            409 => Self::Conflict,
            429 => Self::Throttled,
            500..=599 => Self::Server,
            _ => Self::Malformed,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[error("AWS Organizations transport failure: {failure:?}")]
#[serde(rename_all = "camelCase")]
pub struct TransportError {
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

impl TransportError {
    pub fn new(failure: TransportFailure) -> Self {
        Self {
            status_code: failure.status_code(),
            error_digest: Digest::from_text(match failure {
                TransportFailure::BadRequest => "400",
                TransportFailure::Unauthorized => "401",
                TransportFailure::AccessDenied => "403",
                TransportFailure::NotFound => "404",
                TransportFailure::Conflict => "409",
                TransportFailure::Throttled => "429",
                TransportFailure::Server => "5xx",
                TransportFailure::Timeout => "timeout",
                TransportFailure::BlockedEnv => "BLOCKED_ENV",
                TransportFailure::Malformed => "malformed",
            }),
            failure,
        }
    }

    pub fn from_status(status: u16) -> Self {
        Self::new(TransportFailure::from_status(status))
    }

    pub fn blocked_env() -> Self {
        Self::new(TransportFailure::BlockedEnv)
    }

    pub fn timeout() -> Self {
        Self::new(TransportFailure::Timeout)
    }

    pub fn malformed() -> Self {
        Self::new(TransportFailure::Malformed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListPoliciesRequest {
    pub organization_id: OrganizationId,
    pub policy_type: PolicyType,
    pub max_results: u8,
    pub next_token: Option<OpaquePageToken>,
    pub hierarchy_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
}

impl ListPoliciesRequest {
    pub fn new(
        organization_id: OrganizationId,
        policy_type: PolicyType,
        bounds: &ReadBounds,
        hierarchy_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
    ) -> Self {
        Self {
            organization_id,
            policy_type,
            max_results: bounds.max_results,
            next_token: None,
            hierarchy_digest,
            permission_digest,
            scope_digest,
        }
    }

    #[must_use]
    pub fn with_next_token(&self, next_token: Option<OpaquePageToken>) -> Self {
        let mut next = self.clone();
        next.next_token = next_token;
        next
    }

    pub fn request_digest(&self) -> Result<Digest, ProviderError> {
        digest_serializable(&(
            ReadOperation::ListPolicies,
            &self.organization_id,
            self.policy_type,
            self.max_results,
            self.next_token.as_ref().map(OpaquePageToken::digest),
            &self.hierarchy_digest,
            &self.permission_digest,
            &self.scope_digest,
        ))
        .map_err(ProviderError::Model)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListTargetsForPolicyRequest {
    pub organization_id: OrganizationId,
    pub policy: PolicyIdentity,
    pub max_results: u8,
    pub next_token: Option<OpaquePageToken>,
    pub hierarchy_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
}

impl ListTargetsForPolicyRequest {
    pub fn new(
        organization_id: OrganizationId,
        policy: PolicyIdentity,
        bounds: &ReadBounds,
        hierarchy_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
    ) -> Self {
        Self {
            organization_id,
            policy,
            max_results: bounds.max_results,
            next_token: None,
            hierarchy_digest,
            permission_digest,
            scope_digest,
        }
    }

    #[must_use]
    pub fn with_next_token(&self, next_token: Option<OpaquePageToken>) -> Self {
        let mut next = self.clone();
        next.next_token = next_token;
        next
    }

    pub fn request_digest(&self) -> Result<Digest, ProviderError> {
        digest_serializable(&(
            ReadOperation::ListTargetsForPolicy,
            &self.organization_id,
            &self.policy,
            self.max_results,
            self.next_token.as_ref().map(OpaquePageToken::digest),
            &self.hierarchy_digest,
            &self.permission_digest,
            &self.scope_digest,
        ))
        .map_err(ProviderError::Model)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListPoliciesForTargetRequest {
    pub organization_id: OrganizationId,
    pub target: TargetReference,
    pub policy_type: PolicyType,
    pub max_results: u8,
    pub next_token: Option<OpaquePageToken>,
    pub hierarchy_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
}

impl ListPoliciesForTargetRequest {
    pub fn new(
        organization_id: OrganizationId,
        target: TargetReference,
        policy_type: PolicyType,
        bounds: &ReadBounds,
        hierarchy_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
    ) -> Self {
        Self {
            organization_id,
            target,
            policy_type,
            max_results: bounds.max_results,
            next_token: None,
            hierarchy_digest,
            permission_digest,
            scope_digest,
        }
    }

    #[must_use]
    pub fn with_next_token(&self, next_token: Option<OpaquePageToken>) -> Self {
        let mut next = self.clone();
        next.next_token = next_token;
        next
    }

    pub fn request_digest(&self) -> Result<Digest, ProviderError> {
        digest_serializable(&(
            ReadOperation::ListPoliciesForTarget,
            &self.organization_id,
            &self.target,
            self.policy_type,
            self.max_results,
            self.next_token.as_ref().map(OpaquePageToken::digest),
            &self.hierarchy_digest,
            &self.permission_digest,
            &self.scope_digest,
        ))
        .map_err(ProviderError::Model)
    }
}

/// A normalized page. It intentionally has no policy name, description, JSON,
/// account contact data, raw organization metadata, or serializable cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListPoliciesPage {
    pub policies: Vec<PolicyIdentity>,
    pub next_token: Option<OpaquePageToken>,
    pub hierarchy_digest: Digest,
    pub permission_digest: Digest,
}

impl ListPoliciesPage {
    pub fn new(
        policies: Vec<PolicyIdentity>,
        next_token: Option<OpaquePageToken>,
        hierarchy_digest: Digest,
        permission_digest: Digest,
    ) -> Self {
        Self {
            policies,
            next_token,
            hierarchy_digest,
            permission_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListTargetsForPolicyPage {
    pub targets: Vec<TargetReference>,
    pub next_token: Option<OpaquePageToken>,
    pub hierarchy_digest: Digest,
    pub permission_digest: Digest,
}

impl ListTargetsForPolicyPage {
    pub fn new(
        targets: Vec<TargetReference>,
        next_token: Option<OpaquePageToken>,
        hierarchy_digest: Digest,
        permission_digest: Digest,
    ) -> Self {
        Self {
            targets,
            next_token,
            hierarchy_digest,
            permission_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListPoliciesForTargetPage {
    pub policies: Vec<PolicyIdentity>,
    pub next_token: Option<OpaquePageToken>,
    pub hierarchy_digest: Digest,
    pub permission_digest: Digest,
}

impl ListPoliciesForTargetPage {
    pub fn new(
        policies: Vec<PolicyIdentity>,
        next_token: Option<OpaquePageToken>,
        hierarchy_digest: Digest,
        permission_digest: Digest,
    ) -> Self {
        Self {
            policies,
            next_token,
            hierarchy_digest,
            permission_digest,
        }
    }
}

pub trait AwsOrganizationsTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn list_policies(
        &mut self,
        request: &ListPoliciesRequest,
    ) -> Result<ListPoliciesPage, TransportError>;

    fn list_targets_for_policy(
        &mut self,
        request: &ListTargetsForPolicyRequest,
    ) -> Result<ListTargetsForPolicyPage, TransportError>;

    fn list_policies_for_target(
        &mut self,
        request: &ListPoliciesForTargetRequest,
    ) -> Result<ListPoliciesForTargetPage, TransportError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsOrganizationsTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn list_policies(
        &mut self,
        _request: &ListPoliciesRequest,
    ) -> Result<ListPoliciesPage, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn list_targets_for_policy(
        &mut self,
        _request: &ListTargetsForPolicyRequest,
    ) -> Result<ListTargetsForPolicyPage, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn list_policies_for_target(
        &mut self,
        _request: &ListPoliciesForTargetRequest,
    ) -> Result<ListPoliciesForTargetPage, TransportError> {
        Err(TransportError::blocked_env())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportCall {
    pub operation: ReadOperation,
    pub request_digest: Digest,
    pub page_token_digest: Option<Digest>,
}

#[derive(Clone, Debug)]
pub struct RecordingAwsOrganizationsTransport {
    provenance: ProviderProvenance,
    list_policies: VecDeque<Result<ListPoliciesPage, TransportError>>,
    list_targets_for_policy: VecDeque<Result<ListTargetsForPolicyPage, TransportError>>,
    list_policies_for_target: VecDeque<Result<ListPoliciesForTargetPage, TransportError>>,
    calls: Vec<TransportCall>,
}

pub type FixtureAwsOrganizationsTransport = RecordingAwsOrganizationsTransport;
pub type LoopbackAwsOrganizationsTransport = RecordingAwsOrganizationsTransport;

impl Default for RecordingAwsOrganizationsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingAwsOrganizationsTransport {
    pub fn new() -> Self {
        Self {
            provenance: ProviderProvenance::Recording,
            list_policies: VecDeque::new(),
            list_targets_for_policy: VecDeque::new(),
            list_policies_for_target: VecDeque::new(),
            calls: Vec::new(),
        }
    }

    pub fn fixture() -> Self {
        Self {
            provenance: ProviderProvenance::Fixture,
            ..Self::new()
        }
    }

    pub fn loopback() -> Self {
        Self {
            provenance: ProviderProvenance::Loopback,
            ..Self::new()
        }
    }

    pub fn queue_list_policies(&mut self, response: Result<ListPoliciesPage, TransportError>) {
        self.list_policies.push_back(response);
    }

    pub fn queue_list_targets_for_policy(
        &mut self,
        response: Result<ListTargetsForPolicyPage, TransportError>,
    ) {
        self.list_targets_for_policy.push_back(response);
    }

    pub fn queue_list_policies_for_target(
        &mut self,
        response: Result<ListPoliciesForTargetPage, TransportError>,
    ) {
        self.list_policies_for_target.push_back(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }

    pub fn clear_calls(&mut self) {
        self.calls.clear();
    }

    fn record_call(
        &mut self,
        operation: ReadOperation,
        request_digest: Result<Digest, ProviderError>,
        token: Option<&OpaquePageToken>,
    ) -> Result<(), TransportError> {
        let request_digest = request_digest.map_err(|_| TransportError::malformed())?;
        self.calls.push(TransportCall {
            operation,
            request_digest,
            page_token_digest: token.map(OpaquePageToken::digest),
        });
        Ok(())
    }

    fn missing_response() -> TransportError {
        TransportError::malformed()
    }
}

impl AwsOrganizationsTransport for RecordingAwsOrganizationsTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn list_policies(
        &mut self,
        request: &ListPoliciesRequest,
    ) -> Result<ListPoliciesPage, TransportError> {
        self.record_call(
            ReadOperation::ListPolicies,
            request.request_digest(),
            request.next_token.as_ref(),
        )?;
        self.list_policies
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response()))
    }

    fn list_targets_for_policy(
        &mut self,
        request: &ListTargetsForPolicyRequest,
    ) -> Result<ListTargetsForPolicyPage, TransportError> {
        self.record_call(
            ReadOperation::ListTargetsForPolicy,
            request.request_digest(),
            request.next_token.as_ref(),
        )?;
        self.list_targets_for_policy
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response()))
    }

    fn list_policies_for_target(
        &mut self,
        request: &ListPoliciesForTargetRequest,
    ) -> Result<ListPoliciesForTargetPage, TransportError> {
        self.record_call(
            ReadOperation::ListPoliciesForTarget,
            request.request_digest(),
            request.next_token.as_ref(),
        )?;
        self.list_policies_for_target
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response()))
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderError {
    #[error(transparent)]
    Transport(TransportError),
    #[error(transparent)]
    Model(crate::model::ModelError),
    #[error("provider definition is invalid")]
    InvalidDefinition,
    #[error("provider request exceeds the bounded read shape")]
    BoundExceeded,
    #[error("provider returned an incomplete page sequence")]
    PaginationIncomplete,
    #[error("provider returned a repeated opaque page token")]
    PaginationLoop,
    #[error("provider returned duplicate normalized items")]
    DuplicateItem,
    #[error("provider response does not match the requested policy type")]
    FilterMismatch,
    #[error("provider response does not match the requested organization")]
    OrganizationMismatch,
    #[error("provider response does not match the requested target or policy")]
    TargetMismatch,
    #[error("provider hierarchy digest changed during the read")]
    HierarchyDrift,
    #[error("provider permission digest changed or the operation is not permitted")]
    PermissionLoss,
    #[error("record digest is stale or tampered")]
    RecordTampered,
}

impl From<TransportError> for ProviderError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<crate::model::ModelError> for ProviderError {
    fn from(value: crate::model::ModelError) -> Self {
        Self::Model(value)
    }
}

impl ProviderError {
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::Transport(error) => error.status_code,
            _ => None,
        }
    }

    pub fn transport_failure(&self) -> Option<TransportFailure> {
        match self {
            Self::Transport(error) => Some(error.failure),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsOrganizationsProviderDefinition {
    pub provider_id: String,
    pub api_version: String,
    pub provider_version: String,
    pub contract_version: String,
    pub read_only: bool,
    pub native: bool,
    pub first_party: bool,
    pub connected: bool,
    pub provider_digest: Digest,
    pub version_digest: Digest,
    pub contract_digest: Digest,
}

impl Default for AwsOrganizationsProviderDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsOrganizationsProviderDefinition {
    pub fn new() -> Self {
        let contract_digest = Digest::from_text(AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_JSON);
        let version_digest = Digest::from_text(&format!(
            "{AWS_ORGANIZATIONS_PROVIDER_VERSION}:{AWS_ORGANIZATIONS_API_VERSION}:{AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_VERSION}"
        ));
        let provider_digest = digest_serializable(&(
            AWS_ORGANIZATIONS_GOVERNANCE_PROVIDER_ID,
            AWS_ORGANIZATIONS_API_VERSION,
            AWS_ORGANIZATIONS_PROVIDER_VERSION,
            AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_VERSION,
            true,
            false,
            false,
            false,
        ))
        .expect("static provider definition digest");
        Self {
            provider_id: AWS_ORGANIZATIONS_GOVERNANCE_PROVIDER_ID.to_owned(),
            api_version: AWS_ORGANIZATIONS_API_VERSION.to_owned(),
            provider_version: AWS_ORGANIZATIONS_PROVIDER_VERSION.to_owned(),
            contract_version: AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_VERSION.to_owned(),
            read_only: true,
            native: false,
            first_party: false,
            connected: false,
            provider_digest,
            version_digest,
            contract_digest,
        }
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        let expected = Self::new();
        if self != &expected {
            Err(ProviderError::InvalidDefinition)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct AwsOrganizationsProvider<T = BlockedEnvTransport> {
    transport: T,
    definition: AwsOrganizationsProviderDefinition,
    bounds: ReadBounds,
}

impl Default for AwsOrganizationsProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport)
    }
}

impl<T: AwsOrganizationsTransport> AwsOrganizationsProvider<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            definition: AwsOrganizationsProviderDefinition::new(),
            bounds: ReadBounds::default(),
        }
    }

    pub fn with_bounds(transport: T, bounds: ReadBounds) -> Self {
        Self {
            transport,
            definition: AwsOrganizationsProviderDefinition::new(),
            bounds,
        }
    }

    pub fn definition(&self) -> &AwsOrganizationsProviderDefinition {
        &self.definition
    }

    pub fn bounds(&self) -> &ReadBounds {
        &self.bounds
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        self.definition.validate()?;
        if self.provenance().native()
            || self.provenance().connected()
            || self.provenance().first_party()
            || self.definition.native
            || self.definition.connected
            || self.definition.first_party
        {
            return Err(ProviderError::InvalidDefinition);
        }
        Ok(())
    }

    pub fn list_policies(
        &mut self,
        request: ListPoliciesRequest,
    ) -> Result<AwsOrganizationsReadRecord, ProviderError> {
        self.validate_request(
            ReadOperation::ListPolicies,
            request.max_results,
            &request.organization_id,
            &request.hierarchy_digest,
            &request.permission_digest,
            &request.scope_digest,
        )?;
        let request_digest = request.request_digest()?;
        let mut next_token = request.next_token.clone();
        let mut pages = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        let mut seen_policies = BTreeSet::new();
        let mut item_count = 0_usize;
        let mut complete = false;

        for page_number in 0..self.bounds.max_pages {
            let page_request = request.with_next_token(next_token.clone());
            let page = self
                .transport
                .list_policies(&page_request)
                .map_err(ProviderError::Transport)?;
            Self::validate_page_binding(&page.hierarchy_digest, &page.permission_digest, &request)?;
            if page.policies.len() > usize::from(request.max_results) {
                return Err(ProviderError::BoundExceeded);
            }
            item_count += page.policies.len();
            if item_count > self.bounds.max_items {
                return Err(ProviderError::BoundExceeded);
            }
            for policy in &page.policies {
                policy.verify()?;
                if policy.policy_type != request.policy_type {
                    return Err(ProviderError::FilterMismatch);
                }
                if policy
                    .policy_arn
                    .organization_id()
                    .is_some_and(|organization_id| {
                        organization_id != request.organization_id.as_str()
                    })
                {
                    return Err(ProviderError::OrganizationMismatch);
                }
                if !seen_policies.insert(policy.policy_id.clone()) {
                    return Err(ProviderError::DuplicateItem);
                }
            }
            pages.push(AwsOrganizationsRecordPage::Policies {
                policies: page.policies,
                next_token_digest: page.next_token.as_ref().map(OpaquePageToken::digest),
                hierarchy_digest: page.hierarchy_digest,
                permission_digest: page.permission_digest,
            });
            if let Some(token) = page.next_token {
                let token_digest = token.digest();
                if !seen_tokens.insert(token_digest) {
                    return Err(ProviderError::PaginationLoop);
                }
                next_token = Some(token);
                if page_number + 1 == self.bounds.max_pages {
                    return Err(ProviderError::PaginationIncomplete);
                }
            } else {
                complete = true;
                break;
            }
        }
        if !complete {
            return Err(ProviderError::PaginationIncomplete);
        }
        AwsOrganizationsReadRecord::new(
            ReadOperation::ListPolicies,
            request_digest,
            pages,
            item_count,
            complete,
            self.definition.provider_digest.clone(),
        )
        .map_err(ProviderError::Model)
    }

    pub fn list_targets_for_policy(
        &mut self,
        request: ListTargetsForPolicyRequest,
    ) -> Result<AwsOrganizationsReadRecord, ProviderError> {
        self.validate_request(
            ReadOperation::ListTargetsForPolicy,
            request.max_results,
            &request.organization_id,
            &request.hierarchy_digest,
            &request.permission_digest,
            &request.scope_digest,
        )?;
        if request
            .policy
            .policy_arn
            .organization_id()
            .is_some_and(|organization_id| organization_id != request.organization_id.as_str())
        {
            return Err(ProviderError::OrganizationMismatch);
        }
        let request_digest = request.request_digest()?;
        let mut next_token = request.next_token.clone();
        let mut pages = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        let mut seen_targets = BTreeSet::new();
        let mut item_count = 0_usize;
        let mut complete = false;

        for page_number in 0..self.bounds.max_pages {
            let page_request = request.with_next_token(next_token.clone());
            let page = self
                .transport
                .list_targets_for_policy(&page_request)
                .map_err(ProviderError::Transport)?;
            Self::validate_page_binding(&page.hierarchy_digest, &page.permission_digest, &request)?;
            if page.targets.len() > usize::from(request.max_results) {
                return Err(ProviderError::BoundExceeded);
            }
            item_count += page.targets.len();
            if item_count > self.bounds.max_items {
                return Err(ProviderError::BoundExceeded);
            }
            for target in &page.targets {
                target.verify()?;
                if target.organization_id != request.organization_id {
                    return Err(ProviderError::OrganizationMismatch);
                }
                if !seen_targets.insert(target.target_id.clone()) {
                    return Err(ProviderError::DuplicateItem);
                }
            }
            pages.push(AwsOrganizationsRecordPage::Targets {
                targets: page.targets,
                next_token_digest: page.next_token.as_ref().map(OpaquePageToken::digest),
                hierarchy_digest: page.hierarchy_digest,
                permission_digest: page.permission_digest,
            });
            if let Some(token) = page.next_token {
                let token_digest = token.digest();
                if !seen_tokens.insert(token_digest) {
                    return Err(ProviderError::PaginationLoop);
                }
                next_token = Some(token);
                if page_number + 1 == self.bounds.max_pages {
                    return Err(ProviderError::PaginationIncomplete);
                }
            } else {
                complete = true;
                break;
            }
        }
        if !complete {
            return Err(ProviderError::PaginationIncomplete);
        }
        AwsOrganizationsReadRecord::new(
            ReadOperation::ListTargetsForPolicy,
            request_digest,
            pages,
            item_count,
            complete,
            self.definition.provider_digest.clone(),
        )
        .map_err(ProviderError::Model)
    }

    pub fn list_policies_for_target(
        &mut self,
        request: ListPoliciesForTargetRequest,
    ) -> Result<AwsOrganizationsReadRecord, ProviderError> {
        self.validate_request(
            ReadOperation::ListPoliciesForTarget,
            request.max_results,
            &request.organization_id,
            &request.hierarchy_digest,
            &request.permission_digest,
            &request.scope_digest,
        )?;
        if request.target.organization_id != request.organization_id {
            return Err(ProviderError::OrganizationMismatch);
        }
        request.target.verify()?;
        let request_digest = request.request_digest()?;
        let mut next_token = request.next_token.clone();
        let mut pages = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        let mut seen_policies = BTreeSet::new();
        let mut item_count = 0_usize;
        let mut complete = false;

        for page_number in 0..self.bounds.max_pages {
            let page_request = request.with_next_token(next_token.clone());
            let page = self
                .transport
                .list_policies_for_target(&page_request)
                .map_err(ProviderError::Transport)?;
            Self::validate_page_binding(&page.hierarchy_digest, &page.permission_digest, &request)?;
            if page.policies.len() > usize::from(request.max_results) {
                return Err(ProviderError::BoundExceeded);
            }
            item_count += page.policies.len();
            if item_count > self.bounds.max_items {
                return Err(ProviderError::BoundExceeded);
            }
            for policy in &page.policies {
                policy.verify()?;
                if policy.policy_type != request.policy_type {
                    return Err(ProviderError::FilterMismatch);
                }
                if policy
                    .policy_arn
                    .organization_id()
                    .is_some_and(|organization_id| {
                        organization_id != request.organization_id.as_str()
                    })
                {
                    return Err(ProviderError::OrganizationMismatch);
                }
                if !seen_policies.insert(policy.policy_id.clone()) {
                    return Err(ProviderError::DuplicateItem);
                }
            }
            pages.push(AwsOrganizationsRecordPage::Policies {
                policies: page.policies,
                next_token_digest: page.next_token.as_ref().map(OpaquePageToken::digest),
                hierarchy_digest: page.hierarchy_digest,
                permission_digest: page.permission_digest,
            });
            if let Some(token) = page.next_token {
                let token_digest = token.digest();
                if !seen_tokens.insert(token_digest) {
                    return Err(ProviderError::PaginationLoop);
                }
                next_token = Some(token);
                if page_number + 1 == self.bounds.max_pages {
                    return Err(ProviderError::PaginationIncomplete);
                }
            } else {
                complete = true;
                break;
            }
        }
        if !complete {
            return Err(ProviderError::PaginationIncomplete);
        }
        AwsOrganizationsReadRecord::new(
            ReadOperation::ListPoliciesForTarget,
            request_digest,
            pages,
            item_count,
            complete,
            self.definition.provider_digest.clone(),
        )
        .map_err(ProviderError::Model)
    }

    fn validate_request(
        &self,
        _operation: ReadOperation,
        max_results: u8,
        organization_id: &OrganizationId,
        hierarchy_digest: &Digest,
        permission_digest: &Digest,
        scope_digest: &Digest,
    ) -> Result<(), ProviderError> {
        self.validate()?;
        if !(1..=20).contains(&max_results)
            || max_results > self.bounds.max_results
            || organization_id.as_str().is_empty()
            || hierarchy_digest.as_str().is_empty()
            || permission_digest.as_str().is_empty()
            || scope_digest.as_str().is_empty()
        {
            return Err(ProviderError::BoundExceeded);
        }
        Ok(())
    }

    fn validate_page_binding(
        hierarchy_digest: &Digest,
        permission_digest: &Digest,
        request: &impl RequestBinding,
    ) -> Result<(), ProviderError> {
        if hierarchy_digest != request.hierarchy_digest() {
            return Err(ProviderError::HierarchyDrift);
        }
        if permission_digest != request.permission_digest() {
            return Err(ProviderError::PermissionLoss);
        }
        Ok(())
    }
}

trait RequestBinding {
    fn hierarchy_digest(&self) -> &Digest;
    fn permission_digest(&self) -> &Digest;
}

impl RequestBinding for ListPoliciesRequest {
    fn hierarchy_digest(&self) -> &Digest {
        &self.hierarchy_digest
    }

    fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }
}

impl RequestBinding for ListTargetsForPolicyRequest {
    fn hierarchy_digest(&self) -> &Digest {
        &self.hierarchy_digest
    }

    fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }
}

impl RequestBinding for ListPoliciesForTargetRequest {
    fn hierarchy_digest(&self) -> &Digest {
        &self.hierarchy_digest
    }

    fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AwsOrganizationsRecordPage {
    Policies {
        policies: Vec<PolicyIdentity>,
        next_token_digest: Option<Digest>,
        hierarchy_digest: Digest,
        permission_digest: Digest,
    },
    Targets {
        targets: Vec<TargetReference>,
        next_token_digest: Option<Digest>,
        hierarchy_digest: Digest,
        permission_digest: Digest,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsOrganizationsReadRecord {
    pub operation: ReadOperation,
    pub request_digest: Digest,
    pub pages: Vec<AwsOrganizationsRecordPage>,
    pub item_count: usize,
    pub complete: bool,
    pub provider_digest: Digest,
    pub record_digest: Digest,
}

impl AwsOrganizationsReadRecord {
    fn new(
        operation: ReadOperation,
        request_digest: Digest,
        pages: Vec<AwsOrganizationsRecordPage>,
        item_count: usize,
        complete: bool,
        provider_digest: Digest,
    ) -> Result<Self, crate::model::ModelError> {
        let mut record = Self {
            operation,
            request_digest,
            pages,
            item_count,
            complete,
            provider_digest,
            record_digest: Digest::from_text("pending-record-digest"),
        };
        record.record_digest = record.compute_digest()?;
        Ok(record)
    }

    fn compute_digest(&self) -> Result<Digest, crate::model::ModelError> {
        digest_serializable(&(
            self.operation,
            &self.request_digest,
            &self.pages,
            self.item_count,
            self.complete,
            &self.provider_digest,
        ))
    }

    pub fn verify(&self) -> Result<(), ProviderError> {
        let observed_item_count = self
            .pages
            .iter()
            .map(|page| match page {
                AwsOrganizationsRecordPage::Policies { policies, .. } => policies.len(),
                AwsOrganizationsRecordPage::Targets { targets, .. } => targets.len(),
            })
            .sum::<usize>();
        if self.pages.is_empty()
            || !self.complete
            || observed_item_count != self.item_count
            || self.compute_digest()? != self.record_digest
        {
            return Err(ProviderError::RecordTampered);
        }
        Ok(())
    }

    pub fn policy_items(&self) -> impl Iterator<Item = &PolicyIdentity> {
        self.pages.iter().flat_map(|page| match page {
            AwsOrganizationsRecordPage::Policies { policies, .. } => policies.iter(),
            AwsOrganizationsRecordPage::Targets { .. } => [].iter(),
        })
    }

    pub fn target_items(&self) -> impl Iterator<Item = &TargetReference> {
        self.pages.iter().flat_map(|page| match page {
            AwsOrganizationsRecordPage::Policies { .. } => [].iter(),
            AwsOrganizationsRecordPage::Targets { targets, .. } => targets.iter(),
        })
    }

    pub fn page_token_digests(&self) -> Vec<Digest> {
        self.pages
            .iter()
            .filter_map(|page| match page {
                AwsOrganizationsRecordPage::Policies {
                    next_token_digest, ..
                }
                | AwsOrganizationsRecordPage::Targets {
                    next_token_digest, ..
                } => next_token_digest.clone(),
            })
            .collect()
    }
}
