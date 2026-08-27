//! Provider and transport seams for bounded AWS Network Firewall reads.
//!
//! No implementation in this module signs a request, resolves credentials,
//! opens a socket, or exposes a native AWS control-plane operation. The
//! transports are fixture, recording, loopback, and explicit BLOCKED_ENV
//! seams only.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_NETWORK_FIREWALL_API_REVISION, AWS_NETWORK_FIREWALL_API_VERSION,
    AWS_NETWORK_FIREWALL_CONTRACT_VERSION, AWS_NETWORK_FIREWALL_PROVIDER_ID,
    AWS_NETWORK_FIREWALL_PROVIDER_VERSION, MAX_ENDPOINTS, MAX_FIREWALLS, MAX_PAGE_SIZE,
    MAX_RESPONSE_BYTES, MAX_RULE_GROUP_REFERENCES,
    model::{
        ActionSummary, AwsNetworkFirewallScope, Digest, EndpointAttachmentPosture, FirewallAction,
        FirewallIdentity, FirewallPolicyBinding, FirewallPolicyIdentity, FirewallPostureProjection,
        FirewallStatus, OpaqueCursor, PolicyPostureProjection, PolicyRevision, PolicyStatus,
        ReadOperation, RuleGroupKind, RuleGroupReferenceProjection, SubnetId, VpcId,
        digest_serializable,
    },
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
    Partial,
    AccessLost,
    Malformed,
    BlockedEnv,
}

impl TransportFailure {
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

    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::Throttled => Some(429),
            Self::Server => Some(500),
            Self::Timeout
            | Self::Partial
            | Self::AccessLost
            | Self::Malformed
            | Self::BlockedEnv => None,
        }
    }

    pub const fn is_access_loss(self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::AccessDenied | Self::AccessLost
        )
    }

    pub const fn is_fail_closed(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize)]
#[error("AWS Network Firewall transport failure: {failure:?}")]
#[serde(rename_all = "camelCase")]
pub struct TransportError {
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

impl TransportError {
    pub fn new(failure: TransportFailure) -> Self {
        let label = match failure {
            TransportFailure::BadRequest => "400",
            TransportFailure::Unauthorized => "401",
            TransportFailure::AccessDenied => "403",
            TransportFailure::NotFound => "404",
            TransportFailure::Conflict => "409",
            TransportFailure::Throttled => "429",
            TransportFailure::Server => "5xx",
            TransportFailure::Timeout => "timeout",
            TransportFailure::Partial => "partial",
            TransportFailure::AccessLost => "access-loss",
            TransportFailure::Malformed => "malformed",
            TransportFailure::BlockedEnv => "BLOCKED_ENV",
        };
        Self {
            failure,
            status_code: failure.status_code(),
            error_digest: Digest::from_text(label),
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

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsNetworkFirewallProviderError {
    #[error("provider definition drifted")]
    ProviderDrift,
    #[error("request is invalid")]
    InvalidRequest,
    #[error("response is invalid")]
    InvalidResponse,
    #[error("response exceeds the bounded byte limit")]
    ResponseTooLarge,
    #[error("response contains a duplicate item")]
    DuplicateItem,
    #[error("response contains too many items")]
    BoundExceeded,
    #[error("response does not match its request")]
    RequestDrift,
    #[error("response contains a VPC outside the request scope")]
    VpcMismatch,
    #[error("response contains an endpoint outside the bounded scope")]
    EndpointMismatch,
    #[error("response contains too many rule-group references")]
    RuleGroupBoundExceeded,
    #[error("opaque cursor is invalid")]
    InvalidCursor,
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Model(#[from] crate::model::ModelError),
}

pub type ProviderError = AwsNetworkFirewallProviderError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsNetworkFirewallProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_version: String,
    pub api_revision: String,
    pub contract_version: String,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub api_digest: Digest,
    pub provider_digest: Digest,
}

impl AwsNetworkFirewallProviderDefinition {
    pub fn new() -> Self {
        let api_digest = Digest::from_parts(
            "aws-network-firewall-api/v1",
            &[
                ("version", AWS_NETWORK_FIREWALL_API_VERSION.to_owned()),
                ("revision", AWS_NETWORK_FIREWALL_API_REVISION.to_owned()),
                (
                    "operations",
                    "ListFirewalls,DescribeFirewall,DescribeFirewallPolicy".to_owned(),
                ),
            ],
        );
        let provider_digest = Digest::from_parts(
            "aws-network-firewall-provider-definition/v1",
            &[
                ("id", AWS_NETWORK_FIREWALL_PROVIDER_ID.to_owned()),
                ("version", AWS_NETWORK_FIREWALL_PROVIDER_VERSION.to_owned()),
                ("api", api_digest.as_str().to_owned()),
                ("contract", AWS_NETWORK_FIREWALL_CONTRACT_VERSION.to_owned()),
                ("read_only", "true".to_owned()),
                ("connected", "false".to_owned()),
                ("native", "false".to_owned()),
                ("first_party", "false".to_owned()),
            ],
        );
        Self {
            provider_id: AWS_NETWORK_FIREWALL_PROVIDER_ID.to_owned(),
            provider_version: AWS_NETWORK_FIREWALL_PROVIDER_VERSION.to_owned(),
            api_version: AWS_NETWORK_FIREWALL_API_VERSION.to_owned(),
            api_revision: AWS_NETWORK_FIREWALL_API_REVISION.to_owned(),
            contract_version: AWS_NETWORK_FIREWALL_CONTRACT_VERSION.to_owned(),
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            api_digest,
            provider_digest,
        }
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        let expected = Self::new();
        if self != &expected {
            Err(ProviderError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Default for AwsNetworkFirewallProviderDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListFirewallsRequest {
    pub account_id: AwsNetworkFirewallScopeAccount,
    pub region: AwsNetworkFirewallScopeRegion,
    pub vpc_id: VpcId,
    pub max_results: u16,
    pub next_token: Option<OpaqueCursor>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub policy_digest: Digest,
}

// These aliases keep request fields readable while preserving the public
// account/region types in the model module.
pub type AwsNetworkFirewallScopeAccount = crate::model::AwsAccountId;
pub type AwsNetworkFirewallScopeRegion = crate::model::AwsRegion;

impl ListFirewallsRequest {
    pub fn for_scope(scope: &AwsNetworkFirewallScope, next_token: Option<OpaqueCursor>) -> Self {
        Self {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            vpc_id: scope.vpc_id.clone(),
            max_results: MAX_PAGE_SIZE,
            next_token,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permissions.permission_digest.clone(),
            policy_digest: scope.policy_digest.clone(),
        }
    }

    #[must_use]
    pub fn with_next_token(&self, next_token: Option<OpaqueCursor>) -> Self {
        let mut next = self.clone();
        next.next_token = next_token;
        next
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-network-firewall-list-request/v1",
            &[
                ("account", self.account_id.as_str().to_owned()),
                ("region", self.region.as_str().to_owned()),
                ("vpc", self.vpc_id.as_str().to_owned()),
                ("max_results", self.max_results.to_string()),
                (
                    "next_token",
                    self.next_token
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.digest().as_str().to_owned()),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("policy", self.policy_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        self.account_id.validate()?;
        self.region.validate()?;
        self.vpc_id.validate()?;
        if self.max_results == 0 || self.max_results > MAX_PAGE_SIZE {
            return Err(ProviderError::InvalidRequest);
        }
        self.scope_digest.validate()?;
        self.permission_digest.validate()?;
        self.policy_digest.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeFirewallRequest {
    pub account_id: AwsNetworkFirewallScopeAccount,
    pub region: AwsNetworkFirewallScopeRegion,
    pub firewall: FirewallIdentity,
    pub vpc_id: VpcId,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub policy_digest: Digest,
}

impl DescribeFirewallRequest {
    pub fn for_scope(
        scope: &AwsNetworkFirewallScope,
        firewall: FirewallIdentity,
    ) -> Result<Self, ProviderError> {
        if scope.firewall(&firewall).is_none() {
            return Err(ProviderError::VpcMismatch);
        }
        Ok(Self {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            firewall,
            vpc_id: scope.vpc_id.clone(),
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permissions.permission_digest.clone(),
            policy_digest: scope.policy_digest.clone(),
        })
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-network-firewall-describe-request/v1",
            &[
                ("account", self.account_id.as_str().to_owned()),
                ("region", self.region.as_str().to_owned()),
                ("firewall", self.firewall.digest().as_str().to_owned()),
                ("vpc", self.vpc_id.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("policy", self.policy_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        self.account_id.validate()?;
        self.region.validate()?;
        self.firewall.arn.validate()?;
        self.firewall.name.validate()?;
        self.vpc_id.validate()?;
        self.scope_digest.validate()?;
        self.permission_digest.validate()?;
        self.policy_digest.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeFirewallPolicyRequest {
    pub account_id: AwsNetworkFirewallScopeAccount,
    pub region: AwsNetworkFirewallScopeRegion,
    pub policy: FirewallPolicyIdentity,
    pub expected_revision: PolicyRevision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub policy_digest: Digest,
}

impl DescribeFirewallPolicyRequest {
    pub fn for_scope(
        scope: &AwsNetworkFirewallScope,
        policy: FirewallPolicyIdentity,
    ) -> Result<Self, ProviderError> {
        let expected_revision = scope
            .policy_revision(&policy)
            .ok_or(ProviderError::RequestDrift)?
            .clone();
        Ok(Self {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            policy,
            expected_revision,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permissions.permission_digest.clone(),
            policy_digest: scope.policy_digest.clone(),
        })
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-network-firewall-policy-describe-request/v1",
            &[
                ("account", self.account_id.as_str().to_owned()),
                ("region", self.region.as_str().to_owned()),
                ("policy", self.policy.digest().as_str().to_owned()),
                (
                    "revision",
                    self.expected_revision.digest().as_str().to_owned(),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("policy_fence", self.policy_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        self.account_id.validate()?;
        self.region.validate()?;
        self.policy.arn.validate()?;
        self.policy.name.validate()?;
        self.expected_revision.update_token_digest.validate()?;
        self.scope_digest.validate()?;
        self.permission_digest.validate()?;
        self.policy_digest.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallListItem {
    pub identity: FirewallIdentity,
    pub vpc_id: VpcId,
    pub transit_gateway_attachment_digest: Option<Digest>,
}

impl FirewallListItem {
    pub fn new(
        identity: FirewallIdentity,
        vpc_id: VpcId,
        transit_gateway_attachment_id: Option<impl AsRef<str>>,
    ) -> Result<Self, ProviderError> {
        let transit_gateway_attachment_digest = transit_gateway_attachment_id.map(|value| {
            Digest::from_parts(
                "aws-network-firewall-transit-gateway-attachment/v1",
                &[("value", value.as_ref().to_owned())],
            )
        });
        Ok(Self {
            identity,
            vpc_id,
            transit_gateway_attachment_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListFirewallsPage {
    pub request_digest: Digest,
    pub page_number: u16,
    pub firewalls: Vec<FirewallListItem>,
    pub next_token: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub provider_digest: Digest,
}

impl ListFirewallsPage {
    pub fn new(
        request: &ListFirewallsRequest,
        page_number: u16,
        firewalls: Vec<FirewallListItem>,
        next_token: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self, ProviderError> {
        if page_number == 0 || firewalls.len() > MAX_PAGE_SIZE as usize {
            return Err(ProviderError::BoundExceeded);
        }
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge);
        }
        Ok(Self {
            request_digest: request.request_digest(),
            page_number,
            firewalls,
            next_token,
            response_bytes,
            provider_digest: AwsNetworkFirewallProviderDefinition::new().provider_digest,
        })
    }

    pub fn page_token_digest(&self) -> Option<Digest> {
        self.next_token.as_ref().map(|token| token.digest().clone())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallDescription {
    pub identity: FirewallIdentity,
    pub vpc_id: VpcId,
    pub firewall_policy: FirewallPolicyIdentity,
    pub status: FirewallStatus,
    pub endpoint_attachments: Vec<EndpointAttachmentPosture>,
    pub update_token_digest: Digest,
}

impl FirewallDescription {
    pub fn new(
        identity: FirewallIdentity,
        vpc_id: VpcId,
        firewall_policy: FirewallPolicyIdentity,
        provider_status: impl AsRef<str>,
        endpoint_attachments: Vec<EndpointAttachmentPosture>,
        update_token: impl AsRef<str>,
    ) -> Result<Self, ProviderError> {
        if endpoint_attachments.len() > MAX_ENDPOINTS {
            return Err(ProviderError::BoundExceeded);
        }
        let update_token = update_token.as_ref();
        if update_token.is_empty() || update_token.len() > 1_024 {
            return Err(ProviderError::InvalidResponse);
        }
        Ok(Self {
            identity,
            vpc_id,
            firewall_policy,
            status: FirewallStatus::from_provider(provider_status.as_ref()),
            endpoint_attachments,
            update_token_digest: Digest::from_parts(
                "aws-network-firewall-firewall-update-token/v1",
                &[("token", update_token.to_owned())],
            ),
        })
    }

    pub fn projection(&self) -> FirewallPostureProjection {
        FirewallPostureProjection {
            firewall_digest: self.identity.digest(),
            vpc_digest: self.vpc_id.digest(),
            policy_digest: self.firewall_policy.digest(),
            status: self.status,
            endpoint_attachments: self.endpoint_attachments.clone(),
            update_token_digest: self.update_token_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeFirewallResponse {
    pub request_digest: Digest,
    pub firewall: FirewallDescription,
    pub response_bytes: usize,
    pub provider_digest: Digest,
}

impl DescribeFirewallResponse {
    pub fn new(
        request: &DescribeFirewallRequest,
        firewall: FirewallDescription,
        response_bytes: usize,
    ) -> Result<Self, ProviderError> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge);
        }
        Ok(Self {
            request_digest: request.request_digest(),
            firewall,
            response_bytes,
            provider_digest: AwsNetworkFirewallProviderDefinition::new().provider_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallPolicyDescription {
    pub identity: FirewallPolicyIdentity,
    pub status: PolicyStatus,
    pub revision: PolicyRevision,
    pub stateful_default_actions: ActionSummary,
    pub stateless_default_actions: ActionSummary,
    pub stateful_rule_group_references: Vec<RuleGroupReferenceProjection>,
    pub stateless_rule_group_references: Vec<RuleGroupReferenceProjection>,
    pub tls_inspection_configuration_digest: Option<Digest>,
    pub number_of_associations: u32,
}

impl FirewallPolicyDescription {
    pub fn new(
        identity: FirewallPolicyIdentity,
        revision: PolicyRevision,
        provider_status: impl AsRef<str>,
        stateful_actions: Vec<String>,
        stateless_actions: Vec<String>,
        stateful_rule_group_references: Vec<RuleGroupReferenceProjection>,
        stateless_rule_group_references: Vec<RuleGroupReferenceProjection>,
        tls_inspection_configuration_arn: Option<impl AsRef<str>>,
        number_of_associations: u32,
    ) -> Result<Self, ProviderError> {
        if stateful_rule_group_references.len() + stateless_rule_group_references.len()
            > MAX_RULE_GROUP_REFERENCES
        {
            return Err(ProviderError::RuleGroupBoundExceeded);
        }
        let tls_inspection_configuration_digest = tls_inspection_configuration_arn.map(|value| {
            Digest::from_parts(
                "aws-network-firewall-tls-inspection-configuration/v1",
                &[("arn", value.as_ref().to_owned())],
            )
        });
        Ok(Self {
            identity,
            status: PolicyStatus::from_provider(provider_status.as_ref()),
            revision,
            stateful_default_actions: ActionSummary::from_provider(stateful_actions)?,
            stateless_default_actions: ActionSummary::from_provider(stateless_actions)?,
            stateful_rule_group_references,
            stateless_rule_group_references,
            tls_inspection_configuration_digest,
            number_of_associations,
        })
    }

    pub fn projection(&self) -> Result<PolicyPostureProjection, ProviderError> {
        let projection = PolicyPostureProjection {
            policy_digest: self.identity.digest(),
            status: self.status,
            revision: self.revision.clone(),
            stateful_default_actions: self.stateful_default_actions.clone(),
            stateless_default_actions: self.stateless_default_actions.clone(),
            stateful_rule_group_references: self.stateful_rule_group_references.clone(),
            stateless_rule_group_references: self.stateless_rule_group_references.clone(),
            tls_inspection_configuration_digest: self.tls_inspection_configuration_digest.clone(),
            number_of_associations: self.number_of_associations,
        };
        projection.validate()?;
        Ok(projection)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeFirewallPolicyResponse {
    pub request_digest: Digest,
    pub policy: FirewallPolicyDescription,
    pub response_bytes: usize,
    pub provider_digest: Digest,
}

impl DescribeFirewallPolicyResponse {
    pub fn new(
        request: &DescribeFirewallPolicyRequest,
        policy: FirewallPolicyDescription,
        response_bytes: usize,
    ) -> Result<Self, ProviderError> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge);
        }
        Ok(Self {
            request_digest: request.request_digest(),
            policy,
            response_bytes,
            provider_digest: AwsNetworkFirewallProviderDefinition::new().provider_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportCall {
    pub operation: ReadOperation,
    pub request_digest: Digest,
}

impl TransportCall {
    fn new(operation: ReadOperation, request_digest: Digest) -> Self {
        Self {
            operation,
            request_digest,
        }
    }
}

pub trait AwsNetworkFirewallTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;
    fn calls(&self) -> &[TransportCall];
    fn list_firewalls(
        &mut self,
        request: &ListFirewallsRequest,
    ) -> Result<ListFirewallsPage, TransportError>;
    fn describe_firewall(
        &mut self,
        request: &DescribeFirewallRequest,
    ) -> Result<DescribeFirewallResponse, TransportError>;
    fn describe_firewall_policy(
        &mut self,
        request: &DescribeFirewallPolicyRequest,
    ) -> Result<DescribeFirewallPolicyResponse, TransportError>;
}

#[derive(Clone, Debug, Default)]
pub struct RecordingAwsNetworkFirewallTransport {
    calls: Vec<TransportCall>,
    list_responses: VecDeque<Result<ListFirewallsPage, TransportError>>,
    firewall_responses: VecDeque<Result<DescribeFirewallResponse, TransportError>>,
    policy_responses: VecDeque<Result<DescribeFirewallPolicyResponse, TransportError>>,
}

pub type RecordingTransport = RecordingAwsNetworkFirewallTransport;

impl RecordingAwsNetworkFirewallTransport {
    pub fn push_list_response(&mut self, response: Result<ListFirewallsPage, TransportError>) {
        self.list_responses.push_back(response);
    }

    pub fn queue_list_firewalls(&mut self, response: Result<ListFirewallsPage, TransportError>) {
        self.push_list_response(response);
    }

    pub fn push_describe_firewall_response(
        &mut self,
        response: Result<DescribeFirewallResponse, TransportError>,
    ) {
        self.firewall_responses.push_back(response);
    }

    pub fn queue_describe_firewall(
        &mut self,
        response: Result<DescribeFirewallResponse, TransportError>,
    ) {
        self.push_describe_firewall_response(response);
    }

    pub fn push_describe_policy_response(
        &mut self,
        response: Result<DescribeFirewallPolicyResponse, TransportError>,
    ) {
        self.policy_responses.push_back(response);
    }

    pub fn queue_describe_firewall_policy(
        &mut self,
        response: Result<DescribeFirewallPolicyResponse, TransportError>,
    ) {
        self.push_describe_policy_response(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }
}

impl AwsNetworkFirewallTransport for RecordingAwsNetworkFirewallTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Recording
    }

    fn calls(&self) -> &[TransportCall] {
        &self.calls
    }

    fn list_firewalls(
        &mut self,
        request: &ListFirewallsRequest,
    ) -> Result<ListFirewallsPage, TransportError> {
        self.calls.push(TransportCall::new(
            ReadOperation::ListFirewalls,
            request.request_digest(),
        ));
        self.list_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::malformed()))
    }

    fn describe_firewall(
        &mut self,
        request: &DescribeFirewallRequest,
    ) -> Result<DescribeFirewallResponse, TransportError> {
        self.calls.push(TransportCall::new(
            ReadOperation::DescribeFirewall,
            request.request_digest(),
        ));
        self.firewall_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::malformed()))
    }

    fn describe_firewall_policy(
        &mut self,
        request: &DescribeFirewallPolicyRequest,
    ) -> Result<DescribeFirewallPolicyResponse, TransportError> {
        self.calls.push(TransportCall::new(
            ReadOperation::DescribeFirewallPolicy,
            request.request_digest(),
        ));
        self.policy_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::malformed()))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureAwsNetworkFirewallTransport {
    inner: RecordingAwsNetworkFirewallTransport,
}

pub type FixtureTransport = FixtureAwsNetworkFirewallTransport;

impl FixtureAwsNetworkFirewallTransport {
    pub fn for_scope(scope: &AwsNetworkFirewallScope) -> Result<Self, ProviderError> {
        let list_request = ListFirewallsRequest::for_scope(scope, None);
        let firewalls = scope
            .firewalls
            .iter()
            .cloned()
            .map(|identity| FirewallListItem::new(identity, scope.vpc_id.clone(), None::<&str>))
            .collect::<Result<Vec<_>, _>>()?;
        let mut inner = RecordingAwsNetworkFirewallTransport::default();
        inner.push_list_response(Ok(ListFirewallsPage::new(
            &list_request,
            1,
            firewalls,
            None,
            768,
        )?));

        let policy = scope
            .policies
            .first()
            .ok_or(ProviderError::InvalidRequest)?
            .clone();
        let attachments = scope
            .endpoints
            .iter()
            .map(|binding| {
                EndpointAttachmentPosture::new(
                    binding.endpoint_id.clone(),
                    binding.subnet_id.clone(),
                    crate::model::EndpointStatus::Ready,
                    Some("az-fixture"),
                    Some("IPV4".to_owned()),
                )
                .map_err(ProviderError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for firewall in &scope.firewalls {
            let request = DescribeFirewallRequest::for_scope(scope, firewall.clone())?;
            let description = FirewallDescription::new(
                firewall.clone(),
                scope.vpc_id.clone(),
                policy.identity.clone(),
                "READY",
                attachments.clone(),
                "fixture-firewall-update-token",
            )?;
            inner.push_describe_firewall_response(Ok(DescribeFirewallResponse::new(
                &request,
                description,
                1_024,
            )?));
        }
        for policy_binding in &scope.policies {
            let request =
                DescribeFirewallPolicyRequest::for_scope(scope, policy_binding.identity.clone())?;
            let description = FirewallPolicyDescription::new(
                policy_binding.identity.clone(),
                policy_binding.expected_revision.clone(),
                "ACTIVE",
                vec!["aws:drop_strict".to_owned()],
                vec!["aws:forward_to_sfe".to_owned()],
                vec![RuleGroupReferenceProjection {
                    reference_digest: Digest::from_text("fixture-stateful-rule-group"),
                    kind: RuleGroupKind::Stateful,
                    priority: None,
                    deep_threat_inspection: false,
                    override_action: Some(FirewallAction::Drop),
                }],
                vec![RuleGroupReferenceProjection {
                    reference_digest: Digest::from_text("fixture-stateless-rule-group"),
                    kind: RuleGroupKind::Stateless,
                    priority: Some(1),
                    deep_threat_inspection: false,
                    override_action: None,
                }],
                None::<&str>,
                scope.firewalls.len() as u32,
            )?;
            inner.push_describe_policy_response(Ok(DescribeFirewallPolicyResponse::new(
                &request,
                description,
                1_024,
            )?));
        }
        Ok(Self { inner })
    }

    pub fn fixture(scope: &AwsNetworkFirewallScope) -> Result<Self, ProviderError> {
        Self::for_scope(scope)
    }

    pub fn calls(&self) -> &[TransportCall] {
        self.inner.calls()
    }
}

impl AwsNetworkFirewallTransport for FixtureAwsNetworkFirewallTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn calls(&self) -> &[TransportCall] {
        self.inner.calls()
    }

    fn list_firewalls(
        &mut self,
        request: &ListFirewallsRequest,
    ) -> Result<ListFirewallsPage, TransportError> {
        self.inner.list_firewalls(request)
    }

    fn describe_firewall(
        &mut self,
        request: &DescribeFirewallRequest,
    ) -> Result<DescribeFirewallResponse, TransportError> {
        self.inner.describe_firewall(request)
    }

    fn describe_firewall_policy(
        &mut self,
        request: &DescribeFirewallPolicyRequest,
    ) -> Result<DescribeFirewallPolicyResponse, TransportError> {
        self.inner.describe_firewall_policy(request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackAwsNetworkFirewallTransport {
    inner: FixtureAwsNetworkFirewallTransport,
}

pub type LoopbackTransport = LoopbackAwsNetworkFirewallTransport;

impl LoopbackAwsNetworkFirewallTransport {
    pub fn for_scope(scope: &AwsNetworkFirewallScope) -> Result<Self, ProviderError> {
        Ok(Self {
            inner: FixtureAwsNetworkFirewallTransport::for_scope(scope)?,
        })
    }

    pub fn loopback(scope: &AwsNetworkFirewallScope) -> Result<Self, ProviderError> {
        Self::for_scope(scope)
    }

    pub fn calls(&self) -> &[TransportCall] {
        self.inner.calls()
    }
}

impl AwsNetworkFirewallTransport for LoopbackAwsNetworkFirewallTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn calls(&self) -> &[TransportCall] {
        self.inner.calls()
    }

    fn list_firewalls(
        &mut self,
        request: &ListFirewallsRequest,
    ) -> Result<ListFirewallsPage, TransportError> {
        self.inner.list_firewalls(request)
    }

    fn describe_firewall(
        &mut self,
        request: &DescribeFirewallRequest,
    ) -> Result<DescribeFirewallResponse, TransportError> {
        self.inner.describe_firewall(request)
    }

    fn describe_firewall_policy(
        &mut self,
        request: &DescribeFirewallPolicyRequest,
    ) -> Result<DescribeFirewallPolicyResponse, TransportError> {
        self.inner.describe_firewall_policy(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvAwsNetworkFirewallTransport {
    calls: Vec<TransportCall>,
}

pub type BlockedEnvTransport = BlockedEnvAwsNetworkFirewallTransport;

impl BlockedEnvAwsNetworkFirewallTransport {
    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }
}

impl AwsNetworkFirewallTransport for BlockedEnvAwsNetworkFirewallTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn calls(&self) -> &[TransportCall] {
        &self.calls
    }

    fn list_firewalls(
        &mut self,
        request: &ListFirewallsRequest,
    ) -> Result<ListFirewallsPage, TransportError> {
        self.calls.push(TransportCall::new(
            ReadOperation::ListFirewalls,
            request.request_digest(),
        ));
        Err(TransportError::blocked_env())
    }

    fn describe_firewall(
        &mut self,
        request: &DescribeFirewallRequest,
    ) -> Result<DescribeFirewallResponse, TransportError> {
        self.calls.push(TransportCall::new(
            ReadOperation::DescribeFirewall,
            request.request_digest(),
        ));
        Err(TransportError::blocked_env())
    }

    fn describe_firewall_policy(
        &mut self,
        request: &DescribeFirewallPolicyRequest,
    ) -> Result<DescribeFirewallPolicyResponse, TransportError> {
        self.calls.push(TransportCall::new(
            ReadOperation::DescribeFirewallPolicy,
            request.request_digest(),
        ));
        Err(TransportError::blocked_env())
    }
}

pub type BlockedEnvAwsConfigTransport = BlockedEnvAwsNetworkFirewallTransport;

/// Typed provider with a hard allowlist for the three Network Firewall reads.
pub struct AwsNetworkFirewallProvider<T: AwsNetworkFirewallTransport> {
    transport: T,
    definition: AwsNetworkFirewallProviderDefinition,
}

impl<T: AwsNetworkFirewallTransport> fmt::Debug for AwsNetworkFirewallProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsNetworkFirewallProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.transport.provenance())
            .field("call_count", &self.transport.calls().len())
            .finish()
    }
}

impl<T: AwsNetworkFirewallTransport> AwsNetworkFirewallProvider<T> {
    pub fn new(transport: T) -> Result<Self, ProviderError> {
        let provider = Self {
            transport,
            definition: AwsNetworkFirewallProviderDefinition::new(),
        };
        provider.definition.validate()?;
        Ok(provider)
    }

    pub fn definition(&self) -> &AwsNetworkFirewallProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub fn calls(&self) -> &[TransportCall] {
        self.transport.calls()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn list_firewalls(
        &mut self,
        request: &ListFirewallsRequest,
    ) -> Result<ListFirewallsPage, ProviderError> {
        request.validate()?;
        let page = self.transport.list_firewalls(request)?;
        self.validate_list_page(request, &page)?;
        Ok(page)
    }

    pub fn describe_firewall(
        &mut self,
        request: &DescribeFirewallRequest,
    ) -> Result<DescribeFirewallResponse, ProviderError> {
        request.validate()?;
        let response = self.transport.describe_firewall(request)?;
        if response.request_digest != request.request_digest()
            || response.provider_digest != self.definition.provider_digest
            || response.firewall.identity != request.firewall
            || response.firewall.vpc_id != request.vpc_id
        {
            return Err(ProviderError::RequestDrift);
        }
        if response.response_bytes > MAX_RESPONSE_BYTES
            || response.firewall.endpoint_attachments.len() > MAX_ENDPOINTS
        {
            return Err(ProviderError::BoundExceeded);
        }
        let mut endpoints = BTreeSet::new();
        for attachment in &response.firewall.endpoint_attachments {
            if !endpoints.insert(attachment.endpoint_digest.clone()) {
                return Err(ProviderError::DuplicateItem);
            }
        }
        Ok(response)
    }

    pub fn describe_firewall_policy(
        &mut self,
        request: &DescribeFirewallPolicyRequest,
    ) -> Result<DescribeFirewallPolicyResponse, ProviderError> {
        request.validate()?;
        let response = self.transport.describe_firewall_policy(request)?;
        if response.request_digest != request.request_digest()
            || response.provider_digest != self.definition.provider_digest
            || response.policy.identity != request.policy
        {
            return Err(ProviderError::RequestDrift);
        }
        if response.response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge);
        }
        let references = response.policy.stateful_rule_group_references.len()
            + response.policy.stateless_rule_group_references.len();
        if references > MAX_RULE_GROUP_REFERENCES {
            return Err(ProviderError::RuleGroupBoundExceeded);
        }
        response.policy.projection()?;
        Ok(response)
    }

    fn validate_list_page(
        &self,
        request: &ListFirewallsRequest,
        page: &ListFirewallsPage,
    ) -> Result<(), ProviderError> {
        if page.request_digest != request.request_digest()
            || page.provider_digest != self.definition.provider_digest
        {
            return Err(ProviderError::RequestDrift);
        }
        if page.page_number == 0
            || page.firewalls.len() > MAX_PAGE_SIZE as usize
            || page.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(ProviderError::BoundExceeded);
        }
        let mut identities = BTreeSet::new();
        for firewall in &page.firewalls {
            if firewall.vpc_id != request.vpc_id {
                return Err(ProviderError::VpcMismatch);
            }
            if !identities.insert(firewall.identity.digest()) {
                return Err(ProviderError::DuplicateItem);
            }
        }
        if page.firewalls.len() > MAX_FIREWALLS {
            return Err(ProviderError::BoundExceeded);
        }
        Ok(())
    }
}

impl Default for AwsNetworkFirewallProvider<BlockedEnvAwsNetworkFirewallTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvAwsNetworkFirewallTransport::default())
            .expect("static BLOCKED_ENV provider definition")
    }
}

// Kept private so accidental request serialization cannot bypass the opaque
// request digest APIs. It is also useful in tests to ensure all request fields
// have a stable digest without retaining provider payloads.
#[allow(dead_code)]
fn canonical_request_digest<T: serde::Serialize>(request: &T) -> Result<Digest, ProviderError> {
    digest_serializable(request).map_err(ProviderError::from)
}

#[allow(dead_code)]
fn _keep_types_linked(
    _: Option<FirewallPolicyBinding>,
    _: Option<SubnetId>,
    _: Option<FirewallAction>,
    _: Option<FirewallStatus>,
    _: Option<PolicyStatus>,
    _: Option<ActionSummary>,
    _: Option<FirewallPostureProjection>,
    _: Option<PolicyPostureProjection>,
    _: Option<RuleGroupKind>,
    _: Option<RuleGroupReferenceProjection>,
    _: Option<VpcId>,
    _: Option<EndpointAttachmentPosture>,
) {
}
