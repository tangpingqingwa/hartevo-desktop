//! Bounded, non-native AWS Firewall Manager provider and transport seams.
//!
//! No AWS SDK, HTTP client, SigV4 signer, credential resolver, policy
//! mutation, remediation API, or raw provider payload type is present here.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::{
    AWS_FIREWALL_MANAGER_API_REVISION, AWS_FIREWALL_MANAGER_API_VERSION,
    AWS_FIREWALL_MANAGER_PROVIDER_ID, AWS_FIREWALL_MANAGER_PROVIDER_VERSION,
    error::{AwsFirewallManagerError, Result, TransportError},
    model::{
        AwsFirewallManagerOperation, AwsFirewallManagerProviderIdentity, ComplianceDetailResponse,
        CompliancePage, GetComplianceDetailRequest, GetPolicyRequest, ListComplianceStatusRequest,
        ListPoliciesRequest, PolicyPage, PolicyResponse, ReadBounds, TransportProvenance,
        provider_digest,
    },
};

/// The only transport interface exposed by Layer 1.
pub trait AwsFirewallManagerTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_policies(
        &mut self,
        request: &ListPoliciesRequest,
    ) -> std::result::Result<PolicyPage, TransportError>;

    fn get_policy(
        &mut self,
        request: &GetPolicyRequest,
    ) -> std::result::Result<PolicyResponse, TransportError>;

    fn list_compliance_status(
        &mut self,
        request: &ListComplianceStatusRequest,
    ) -> std::result::Result<CompliancePage, TransportError>;

    fn get_compliance_detail(
        &mut self,
        request: &GetComplianceDetailRequest,
    ) -> std::result::Result<ComplianceDetailResponse, TransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsFirewallManagerOperation,
    pub scope_digest: crate::Digest,
    pub request_digest: crate::Digest,
    pub cursor_digest: Option<crate::Digest>,
    pub policy_digest: Option<crate::Digest>,
    pub response_digest: Option<crate::Digest>,
    pub path_digest: crate::Digest,
}

impl RecordedRequest {
    fn list_policies(request: &ListPoliciesRequest, response: Option<&PolicyPage>) -> Self {
        Self {
            operation: AwsFirewallManagerOperation::ListPolicies,
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest().clone(),
            cursor_digest: request
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            policy_digest: None,
            response_digest: response.map(|value| value.response_digest.clone()),
            path_digest: crate::Digest::from_parts(
                "aws-fms-list-policies-path/v1",
                &[
                    ("scope", request.scope_digest.to_string()),
                    ("request", request.request_digest().to_string()),
                ],
            ),
        }
    }

    fn get_policy(request: &GetPolicyRequest, response: Option<&PolicyResponse>) -> Self {
        Self {
            operation: AwsFirewallManagerOperation::GetPolicy,
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest().clone(),
            cursor_digest: None,
            policy_digest: Some(request.policy.digest()),
            response_digest: response.map(|value| value.response_digest.clone()),
            path_digest: crate::Digest::from_parts(
                "aws-fms-get-policy-path/v1",
                &[
                    ("scope", request.scope_digest.to_string()),
                    ("policy", request.policy.digest().to_string()),
                ],
            ),
        }
    }

    fn list_compliance_status(
        request: &ListComplianceStatusRequest,
        response: Option<&CompliancePage>,
    ) -> Self {
        Self {
            operation: AwsFirewallManagerOperation::ListComplianceStatus,
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest().clone(),
            cursor_digest: request
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            policy_digest: Some(request.policy.digest()),
            response_digest: response.map(|value| value.response_digest.clone()),
            path_digest: crate::Digest::from_parts(
                "aws-fms-list-compliance-status-path/v1",
                &[
                    ("scope", request.scope_digest.to_string()),
                    ("policy", request.policy.digest().to_string()),
                    ("request", request.request_digest().to_string()),
                ],
            ),
        }
    }

    fn get_compliance_detail(
        request: &GetComplianceDetailRequest,
        response: Option<&ComplianceDetailResponse>,
    ) -> Self {
        Self {
            operation: AwsFirewallManagerOperation::GetComplianceDetail,
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest().clone(),
            cursor_digest: None,
            policy_digest: Some(request.policy.digest()),
            response_digest: response.map(|value| value.response_digest.clone()),
            path_digest: crate::Digest::from_parts(
                "aws-fms-get-compliance-detail-path/v1",
                &[
                    ("scope", request.scope_digest.to_string()),
                    ("policy", request.policy.digest().to_string()),
                    ("account", request.member_account.digest().to_string()),
                    ("resource_type", request.resource_type.digest().to_string()),
                    ("resource", request.resource_id.digest().to_string()),
                ],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsFirewallManagerProviderDefinition {
    pub id: String,
    pub version: String,
    pub api_version: String,
    pub api_revision: String,
    pub operations: Vec<AwsFirewallManagerOperation>,
    pub bounds: ReadBounds,
    pub provider_digest: crate::Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsFirewallManagerProviderDefinition {
    pub fn new(bounds: ReadBounds) -> Result<Self> {
        bounds.validate()?;
        let definition = Self {
            id: AWS_FIREWALL_MANAGER_PROVIDER_ID.to_owned(),
            version: AWS_FIREWALL_MANAGER_PROVIDER_VERSION.to_owned(),
            api_version: AWS_FIREWALL_MANAGER_API_VERSION.to_owned(),
            api_revision: AWS_FIREWALL_MANAGER_API_REVISION.to_owned(),
            operations: vec![
                AwsFirewallManagerOperation::ListPolicies,
                AwsFirewallManagerOperation::GetPolicy,
                AwsFirewallManagerOperation::ListComplianceStatus,
                AwsFirewallManagerOperation::GetComplianceDetail,
            ],
            bounds,
            provider_digest: provider_digest(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn identity(&self) -> AwsFirewallManagerProviderIdentity {
        AwsFirewallManagerProviderIdentity {
            id: self.id.clone(),
            version: self.version.clone(),
            api_version: self.api_version.clone(),
            api_revision: self.api_revision.clone(),
            operations: self.operations.clone(),
            provider_digest: self.provider_digest.clone(),
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.id != AWS_FIREWALL_MANAGER_PROVIDER_ID
            || self.version != AWS_FIREWALL_MANAGER_PROVIDER_VERSION
            || self.api_version != AWS_FIREWALL_MANAGER_API_VERSION
            || self.api_revision != AWS_FIREWALL_MANAGER_API_REVISION
            || self.operations.len() != 4
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provider_digest != provider_digest()
        {
            return Err(AwsFirewallManagerError::InvalidProvider);
        }
        self.bounds.validate()
    }
}

impl Serialize for AwsFirewallManagerProviderDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsFirewallManagerProviderDefinition", 11)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("apiVersion", &self.api_version)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("operations", &self.operations)?;
        state.serialize_field("bounds", &self.bounds)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("connected", &self.connected)?;
        state.serialize_field("native", &self.native)?;
        state.serialize_field("firstParty", &self.first_party)?;
        state.serialize_field("providerReceipt", &self.provider_receipt)?;
        state.end()
    }
}

/// Typed provider wrapper. It enforces response/request digest fences and
/// rejects duplicate or out-of-bound page content before service code sees it.
pub struct AwsFirewallManagerProvider<T: AwsFirewallManagerTransport> {
    transport: T,
    definition: AwsFirewallManagerProviderDefinition,
    requests: Vec<RecordedRequest>,
}

impl<T: AwsFirewallManagerTransport> fmt::Debug for AwsFirewallManagerProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsFirewallManagerProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .field("request_count", &self.requests.len())
            .finish()
    }
}

impl<T: AwsFirewallManagerTransport> AwsFirewallManagerProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_bounds(transport, ReadBounds::default())
    }

    pub fn with_bounds(transport: T, bounds: ReadBounds) -> Result<Self> {
        let definition = AwsFirewallManagerProviderDefinition::new(bounds)?;
        if transport.provenance().connected()
            || transport.provenance().native()
            || transport.provenance().first_party()
        {
            return Err(AwsFirewallManagerError::InvalidProvider);
        }
        Ok(Self {
            transport,
            definition,
            requests: Vec::new(),
        })
    }

    pub fn definition(&self) -> &AwsFirewallManagerProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> &crate::Digest {
        &self.definition.provider_digest
    }

    pub fn bounds(&self) -> &ReadBounds {
        &self.definition.bounds
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn recorded_requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    pub fn list_policies(&mut self, request: &ListPoliciesRequest) -> Result<PolicyPage> {
        self.ensure_request_budget()?;
        let response = self.transport.list_policies(request)?;
        if response.provenance != self.provenance() {
            return Err(AwsFirewallManagerError::ProviderDrift);
        }
        response.validate_integrity(request)?;
        let mut policy_digests = BTreeSet::new();
        if response
            .policies
            .iter()
            .any(|policy| !policy_digests.insert(policy.policy_digest.clone()))
        {
            return Err(AwsFirewallManagerError::DuplicateItem);
        }
        self.requests
            .push(RecordedRequest::list_policies(request, Some(&response)));
        Ok(response)
    }

    pub fn get_policy(&mut self, request: &GetPolicyRequest) -> Result<PolicyResponse> {
        self.ensure_request_budget()?;
        let response = self.transport.get_policy(request)?;
        if response.provenance != self.provenance() {
            return Err(AwsFirewallManagerError::ProviderDrift);
        }
        response.validate_integrity(request)?;
        self.requests
            .push(RecordedRequest::get_policy(request, Some(&response)));
        Ok(response)
    }

    pub fn list_compliance_status(
        &mut self,
        request: &ListComplianceStatusRequest,
    ) -> Result<CompliancePage> {
        self.ensure_request_budget()?;
        let response = self.transport.list_compliance_status(request)?;
        if response.provenance != self.provenance() {
            return Err(AwsFirewallManagerError::ProviderDrift);
        }
        response.validate_integrity(request)?;
        let mut accounts = response
            .statuses
            .iter()
            .map(|status| status.member_account_digest.clone())
            .collect::<Vec<_>>();
        accounts.sort();
        if accounts.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(AwsFirewallManagerError::DuplicateItem);
        }
        self.requests.push(RecordedRequest::list_compliance_status(
            request,
            Some(&response),
        ));
        Ok(response)
    }

    pub fn get_compliance_detail(
        &mut self,
        request: &GetComplianceDetailRequest,
    ) -> Result<ComplianceDetailResponse> {
        self.ensure_request_budget()?;
        let response = self.transport.get_compliance_detail(request)?;
        if response.provenance != self.provenance() {
            return Err(AwsFirewallManagerError::ProviderDrift);
        }
        response.validate_integrity(request)?;
        self.requests.push(RecordedRequest::get_compliance_detail(
            request,
            Some(&response),
        ));
        Ok(response)
    }

    fn ensure_request_budget(&self) -> Result<()> {
        if self.requests.len() >= self.definition.bounds.max_requests as usize {
            Err(AwsFirewallManagerError::IncompletePagination)
        } else {
            Ok(())
        }
    }
}

impl Default for AwsFirewallManagerProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvAwsFirewallManagerTransport)
            .expect("blocked environment provider definition")
    }
}

macro_rules! queued_transport {
    ($name:ident, $alias:ident, $provenance:expr) => {
        #[derive(Debug)]
        pub struct $name {
            list_policies: VecDeque<std::result::Result<PolicyPage, TransportError>>,
            get_policy: VecDeque<std::result::Result<PolicyResponse, TransportError>>,
            list_compliance_status: VecDeque<std::result::Result<CompliancePage, TransportError>>,
            get_compliance_detail:
                VecDeque<std::result::Result<ComplianceDetailResponse, TransportError>>,
        }

        impl $name {
            pub fn new() -> Self {
                Self {
                    list_policies: VecDeque::new(),
                    get_policy: VecDeque::new(),
                    list_compliance_status: VecDeque::new(),
                    get_compliance_detail: VecDeque::new(),
                }
            }

            pub fn fixture() -> Self {
                Self::new()
            }

            pub fn queue_list_policies(
                &mut self,
                response: std::result::Result<PolicyPage, TransportError>,
            ) {
                self.list_policies.push_back(response);
            }

            pub fn queue_get_policy(
                &mut self,
                response: std::result::Result<PolicyResponse, TransportError>,
            ) {
                self.get_policy.push_back(response);
            }

            pub fn queue_list_compliance_status(
                &mut self,
                response: std::result::Result<CompliancePage, TransportError>,
            ) {
                self.list_compliance_status.push_back(response);
            }

            pub fn queue_get_compliance_detail(
                &mut self,
                response: std::result::Result<ComplianceDetailResponse, TransportError>,
            ) {
                self.get_compliance_detail.push_back(response);
            }

            fn unknown<T>() -> std::result::Result<T, TransportError> {
                Err(TransportError::unknown())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl AwsFirewallManagerTransport for $name {
            fn provenance(&self) -> TransportProvenance {
                $provenance
            }

            fn list_policies(
                &mut self,
                _request: &ListPoliciesRequest,
            ) -> std::result::Result<PolicyPage, TransportError> {
                self.list_policies.pop_front().unwrap_or_else(Self::unknown)
            }

            fn get_policy(
                &mut self,
                _request: &GetPolicyRequest,
            ) -> std::result::Result<PolicyResponse, TransportError> {
                self.get_policy.pop_front().unwrap_or_else(Self::unknown)
            }

            fn list_compliance_status(
                &mut self,
                _request: &ListComplianceStatusRequest,
            ) -> std::result::Result<CompliancePage, TransportError> {
                self.list_compliance_status
                    .pop_front()
                    .unwrap_or_else(Self::unknown)
            }

            fn get_compliance_detail(
                &mut self,
                _request: &GetComplianceDetailRequest,
            ) -> std::result::Result<ComplianceDetailResponse, TransportError> {
                self.get_compliance_detail
                    .pop_front()
                    .unwrap_or_else(Self::unknown)
            }
        }

        pub type $alias = $name;
    };
}

queued_transport!(
    RecordingAwsFirewallManagerTransport,
    RecordingTransport,
    TransportProvenance::Recording
);
queued_transport!(
    FixtureAwsFirewallManagerTransport,
    FixtureTransport,
    TransportProvenance::Fixture
);
queued_transport!(
    FakeAwsFirewallManagerTransport,
    FakeTransport,
    TransportProvenance::Fake
);
queued_transport!(
    LoopbackAwsFirewallManagerTransport,
    LoopbackTransport,
    TransportProvenance::Loopback
);

/// A blocked environment has no response queue and always fails closed.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsFirewallManagerTransport;

pub type BlockedEnvTransport = BlockedEnvAwsFirewallManagerTransport;

impl AwsFirewallManagerTransport for BlockedEnvAwsFirewallManagerTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_policies(
        &mut self,
        _request: &ListPoliciesRequest,
    ) -> std::result::Result<PolicyPage, TransportError> {
        Err(TransportError::new(crate::TransportFailure::BlockedEnv))
    }

    fn get_policy(
        &mut self,
        _request: &GetPolicyRequest,
    ) -> std::result::Result<PolicyResponse, TransportError> {
        Err(TransportError::new(crate::TransportFailure::BlockedEnv))
    }

    fn list_compliance_status(
        &mut self,
        _request: &ListComplianceStatusRequest,
    ) -> std::result::Result<CompliancePage, TransportError> {
        Err(TransportError::new(crate::TransportFailure::BlockedEnv))
    }

    fn get_compliance_detail(
        &mut self,
        _request: &GetComplianceDetailRequest,
    ) -> std::result::Result<ComplianceDetailResponse, TransportError> {
        Err(TransportError::new(crate::TransportFailure::BlockedEnv))
    }
}

pub type AwsFirewallManagerProviderError = AwsFirewallManagerError;

pub fn is_access_loss(error: &TransportError) -> bool {
    error.failure.is_access_loss()
}
