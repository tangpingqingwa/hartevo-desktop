//! Service, reversible registration, proposal/record/verify, and evidence.

use std::{collections::BTreeSet, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::consumer::MissionAwsNetworkFirewallConsumer;
use crate::model::{
    ActionSummary, AwsNetworkFirewallScope, Digest, EndpointStatus, FirewallIdentity,
    FirewallPolicyIdentity, FirewallPostureProjection, FirewallStatus, MissionBinding, ModelError,
    OpaqueCursor, PolicyPostureProjection, PolicyRevision, ProjectBinding, ReadOperation,
    SecretReference, WorkProductBinding, digest_serializable,
};
use crate::provider::{
    AwsNetworkFirewallProvider, AwsNetworkFirewallProviderDefinition,
    AwsNetworkFirewallProviderError, AwsNetworkFirewallTransport, DescribeFirewallPolicyRequest,
    DescribeFirewallRequest, DescribeFirewallResponse, FirewallDescription, FirewallListItem,
    ListFirewallsPage, ListFirewallsRequest, ProviderProvenance, TransportError,
};
use crate::{
    AWS_NETWORK_FIREWALL_API_REVISION, AWS_NETWORK_FIREWALL_API_VERSION,
    AWS_NETWORK_FIREWALL_CONTRACT_VERSION, AWS_NETWORK_FIREWALL_PLUGIN_VERSION,
    AWS_NETWORK_FIREWALL_PROVIDER_ID, AWS_NETWORK_FIREWALL_PROVIDER_VERSION,
    AWS_NETWORK_FIREWALL_SERVICE_ID, CONTRACT_DIGEST_INPUT, MAX_FIREWALLS, MAX_PAGES,
    MAX_REQUESTS_PER_READ, MAX_RESPONSE_BYTES, contract_digest,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Provider(#[from] AwsNetworkFirewallProviderError),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("service definition drifted")]
    ServiceDrift,
    #[error("contract definition drifted")]
    ContractDrift,
    #[error("provider or API definition drifted")]
    ProviderDrift,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration is not active")]
    RegistrationInactive,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("permission fence was lost")]
    PermissionLoss,
    #[error("scope fence was lost")]
    ScopeMismatch,
    #[error("policy revision drifted")]
    PolicyRevisionDrift,
    #[error("firewall or endpoint status is unknown")]
    ProviderUnknown,
    #[error("evidence is partial or pagination was truncated")]
    PartialEvidence,
    #[error("pagination cursor was replayed")]
    PaginationLoop,
    #[error("request or proposal digest drifted")]
    RequestDrift,
    #[error("evidence was tampered")]
    TamperedEvidence,
    #[error("operation is not supported by this Layer-1 provider")]
    UnsupportedOperation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceVersion {
    pub service_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub api_revision: String,
    pub version_digest: Digest,
    pub contract_digest: Digest,
}

impl ServiceVersion {
    pub fn new() -> Self {
        let version_digest = Digest::from_parts(
            "aws-network-firewall-service-version/v1",
            &[
                ("service", AWS_NETWORK_FIREWALL_SERVICE_ID.to_owned()),
                ("plugin", AWS_NETWORK_FIREWALL_PLUGIN_VERSION.to_owned()),
                ("contract", AWS_NETWORK_FIREWALL_CONTRACT_VERSION.to_owned()),
                ("api", AWS_NETWORK_FIREWALL_API_REVISION.to_owned()),
            ],
        );
        Self {
            service_id: AWS_NETWORK_FIREWALL_SERVICE_ID.to_owned(),
            plugin_version: AWS_NETWORK_FIREWALL_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_NETWORK_FIREWALL_CONTRACT_VERSION.to_owned(),
            api_revision: AWS_NETWORK_FIREWALL_API_REVISION.to_owned(),
            version_digest,
            contract_digest: contract_digest(),
        }
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        if self != &Self::new() {
            Err(ServiceError::ServiceDrift)
        } else {
            Ok(())
        }
    }
}

impl Default for ServiceVersion {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityBoundary {
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub durable_receipt: bool,
    pub effective_authorization: bool,
    pub policy_truth_authority: bool,
    pub external_writes: bool,
    pub firewall_mutation: bool,
    pub firewall_policy_mutation: bool,
    pub rule_group_mutation: bool,
    pub vpc_attachment_mutation: bool,
    pub packet_or_flow_log_read: bool,
    pub credential_resolution: bool,
    pub verification_authority: bool,
    pub kernel_outcome_adoption: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsNetworkFirewallCapabilities {
    pub service_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_version: String,
    pub api_revision: String,
    pub operations: Vec<ReadOperation>,
    pub max_pages: u16,
    pub max_page_size: u16,
    pub opaque_pagination: bool,
    pub read_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub authority: AuthorityBoundary,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransition {
    pub previous_state: RegistrationState,
    pub new_state: RegistrationState,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransition {
    fn new(
        previous_state: RegistrationState,
        new_state: RegistrationState,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "aws-network-firewall-registration-transition/v1",
            &[
                ("previous", format!("{previous_state:?}")),
                ("new", format!("{new_state:?}")),
                ("registration", registration_digest.as_str().to_owned()),
            ],
        );
        Self {
            previous_state,
            new_state,
            registration_digest,
            transition_digest,
        }
    }
}

/// Version/provider/permission/scope/policy/secret-bound reversible registration.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsNetworkFirewallPostureRegistration {
    id: String,
    service_version_digest: Digest,
    provider_id: String,
    provider_version: String,
    api_digest: Digest,
    provider_digest: Digest,
    contract_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    policy_digest: Digest,
    secret_reference_digest: Digest,
    registration_revision: u64,
    state: RegistrationState,
    registration_digest: Digest,
}

impl AwsNetworkFirewallPostureRegistration {
    pub fn new(
        id: impl Into<String>,
        scope: &AwsNetworkFirewallScope,
        secret_reference: &SecretReference,
        service_version: &ServiceVersion,
        provider: &AwsNetworkFirewallProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self, ServiceError> {
        let id = id.into();
        if id.is_empty() || id.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(ServiceError::Model(ModelError::Invalid {
                field: "registration id",
            }));
        }
        if registration_revision == 0 {
            return Err(ServiceError::Model(ModelError::MustBePositive {
                field: "registration revision",
            }));
        }
        let mut registration = Self {
            id,
            service_version_digest: service_version.version_digest.clone(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            api_digest: provider.api_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            contract_digest: service_version.contract_digest.clone(),
            permission_digest: scope.permissions.permission_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            policy_digest: scope.policy_digest.clone(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            registration_revision,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate(scope, secret_reference, service_version, provider)?;
        Ok(registration)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn service_version_digest(&self) -> &Digest {
        &self.service_version_digest
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn validate(
        &self,
        scope: &AwsNetworkFirewallScope,
        secret_reference: &SecretReference,
        service_version: &ServiceVersion,
        provider: &AwsNetworkFirewallProviderDefinition,
    ) -> Result<(), ServiceError> {
        scope.validate()?;
        service_version.validate()?;
        provider.validate()?;
        secret_reference
            .validate(scope)
            .map_err(|_| ServiceError::SecretRevoked)?;
        if self.id.is_empty()
            || self.service_version_digest != service_version.version_digest
            || self.provider_id != AWS_NETWORK_FIREWALL_PROVIDER_ID
            || self.provider_version != AWS_NETWORK_FIREWALL_PROVIDER_VERSION
            || self.api_digest != provider.api_digest
            || self.provider_digest != provider.provider_digest
            || self.contract_digest != contract_digest()
            || self.permission_digest != scope.permissions.permission_digest
            || self.scope_digest != scope.scope_digest
            || self.policy_digest != scope.policy_digest
            || self.secret_reference_digest != *secret_reference.reference_digest()
            || self.registration_revision == 0
            || self.registration_digest != self.calculate_digest()
        {
            return Err(ServiceError::RequestDrift);
        }
        Ok(())
    }

    pub fn revoke(
        &mut self,
        scope: &AwsNetworkFirewallScope,
        secret_reference: &SecretReference,
        service_version: &ServiceVersion,
        provider: &AwsNetworkFirewallProviderDefinition,
    ) -> Result<RegistrationTransition, ServiceError> {
        self.validate(scope, secret_reference, service_version, provider)?;
        if matches!(self.state, RegistrationState::Reversed) {
            return Err(ServiceError::RegistrationReversed);
        }
        let previous_state = self.state;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransition::new(
            previous_state,
            self.state,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(
        &mut self,
        scope: &AwsNetworkFirewallScope,
        secret_reference: &SecretReference,
        service_version: &ServiceVersion,
        provider: &AwsNetworkFirewallProviderDefinition,
    ) -> Result<RegistrationTransition, ServiceError> {
        self.validate(scope, secret_reference, service_version, provider)?;
        if matches!(self.state, RegistrationState::Reversed) {
            return Err(ServiceError::RegistrationReversed);
        }
        let previous_state = self.state;
        self.state = RegistrationState::Reversed;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransition::new(
            previous_state,
            self.state,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(
        &mut self,
        scope: &AwsNetworkFirewallScope,
        secret_reference: &SecretReference,
        service_version: &ServiceVersion,
        provider: &AwsNetworkFirewallProviderDefinition,
    ) -> Result<RegistrationTransition, ServiceError> {
        if matches!(self.state, RegistrationState::Reversed) {
            return Err(ServiceError::RegistrationReversed);
        }
        let previous_state = self.state;
        self.state = RegistrationState::Active;
        self.registration_digest = self.calculate_digest();
        self.validate(scope, secret_reference, service_version, provider)?;
        Ok(RegistrationTransition::new(
            previous_state,
            self.state,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-network-firewall-registration/v1",
            &[
                ("id", self.id.clone()),
                (
                    "service_version",
                    self.service_version_digest.as_str().to_owned(),
                ),
                ("provider_id", self.provider_id.clone()),
                ("provider_version", self.provider_version.clone()),
                ("api", self.api_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("policy", self.policy_digest.as_str().to_owned()),
                (
                    "secret_reference",
                    self.secret_reference_digest.as_str().to_owned(),
                ),
                ("revision", self.registration_revision.to_string()),
                ("state", format!("{:?}", self.state)),
            ],
        )
    }
}

impl fmt::Debug for AwsNetworkFirewallPostureRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsNetworkFirewallPostureRegistration")
            .field("id", &self.id)
            .field("service_version_digest", &self.service_version_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_version", &self.provider_version)
            .field("api_digest", &self.api_digest)
            .field("provider_digest", &self.provider_digest)
            .field("contract_digest", &self.contract_digest)
            .field("permission_digest", &self.permission_digest)
            .field("scope_digest", &self.scope_digest)
            .field("policy_digest", &self.policy_digest)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("registration_revision", &self.registration_revision)
            .field("state", &self.state)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for AwsNetworkFirewallPostureRegistration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsNetworkFirewallPostureRegistration", 14)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("serviceVersionDigest", &self.service_version_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerVersion", &self.provider_version)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("policyDigest", &self.policy_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("state", &self.state)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", content = "request", rename_all = "camelCase")]
pub enum AwsNetworkFirewallReadRequest {
    ListFirewalls(ListFirewallsRequest),
    DescribeFirewall(DescribeFirewallRequest),
    DescribeFirewallPolicy(DescribeFirewallPolicyRequest),
}

impl AwsNetworkFirewallReadRequest {
    pub const fn operation(&self) -> ReadOperation {
        match self {
            Self::ListFirewalls(_) => ReadOperation::ListFirewalls,
            Self::DescribeFirewall(_) => ReadOperation::DescribeFirewall,
            Self::DescribeFirewallPolicy(_) => ReadOperation::DescribeFirewallPolicy,
        }
    }

    pub fn request_digest(&self) -> Digest {
        match self {
            Self::ListFirewalls(request) => request.request_digest(),
            Self::DescribeFirewall(request) => request.request_digest(),
            Self::DescribeFirewallPolicy(request) => request.request_digest(),
        }
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        match self {
            Self::ListFirewalls(request) => request.validate().map_err(ServiceError::from),
            Self::DescribeFirewall(request) => request.validate().map_err(ServiceError::from),
            Self::DescribeFirewallPolicy(request) => request.validate().map_err(ServiceError::from),
        }
    }

    pub fn scope_digest(&self) -> &Digest {
        match self {
            Self::ListFirewalls(request) => &request.scope_digest,
            Self::DescribeFirewall(request) => &request.scope_digest,
            Self::DescribeFirewallPolicy(request) => &request.scope_digest,
        }
    }

    pub fn permission_digest(&self) -> &Digest {
        match self {
            Self::ListFirewalls(request) => &request.permission_digest,
            Self::DescribeFirewall(request) => &request.permission_digest,
            Self::DescribeFirewallPolicy(request) => &request.permission_digest,
        }
    }

    pub fn policy_digest(&self) -> &Digest {
        match self {
            Self::ListFirewalls(request) => &request.policy_digest,
            Self::DescribeFirewall(request) => &request.policy_digest,
            Self::DescribeFirewallPolicy(request) => &request.policy_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsNetworkFirewallPostureProposal {
    pub operation: ReadOperation,
    pub request: AwsNetworkFirewallReadRequest,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub registration_digest: Digest,
    pub version_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub policy_digest: Digest,
    pub proposal_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsNetworkFirewallPostureProposal {
    fn new(
        request: AwsNetworkFirewallReadRequest,
        scope: &AwsNetworkFirewallScope,
        version: &ServiceVersion,
        provider: &AwsNetworkFirewallProviderDefinition,
        registration: &AwsNetworkFirewallPostureRegistration,
    ) -> Result<Self, ServiceError> {
        let mut proposal = Self {
            operation: request.operation(),
            request,
            mission: scope.mission.clone(),
            project: scope.project.clone(),
            work_product: scope.work_product.clone(),
            registration_digest: registration.registration_digest.clone(),
            version_digest: version.version_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            contract_digest: version.contract_digest.clone(),
            permission_digest: scope.permissions.permission_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            policy_digest: scope.policy_digest.clone(),
            proposal_digest: Digest::zero(),
            read_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
        };
        proposal.proposal_digest = proposal.calculate_digest()?;
        Ok(proposal)
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        if self.operation != self.request.operation()
            || !self.read_only
            || self.live_execution
            || self.connected
            || self.native
            || self.first_party
            || self.proposal_digest != self.calculate_digest()?
        {
            return Err(ServiceError::TamperedEvidence);
        }
        self.request.validate()
    }

    fn calculate_digest(&self) -> Result<Digest, ServiceError> {
        Ok(Digest::from_parts(
            "aws-network-firewall-proposal/v1",
            &[
                ("operation", format!("{:?}", self.operation)),
                ("request", self.request.request_digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("version", self.version_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("policy", self.policy_digest.as_str().to_owned()),
                ("read_only", self.read_only.to_string()),
                ("live_execution", self.live_execution.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
            ],
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsNetworkFirewallListRecord {
    pub requests: Vec<ListFirewallsRequest>,
    pub pages: Vec<ListFirewallsPage>,
    pub complete: bool,
}

impl AwsNetworkFirewallListRecord {
    pub fn page_token_digests(&self) -> Vec<Digest> {
        self.pages
            .iter()
            .filter_map(ListFirewallsPage::page_token_digest)
            .collect()
    }

    pub fn item_count(&self) -> usize {
        self.pages.iter().map(|page| page.firewalls.len()).sum()
    }

    pub fn record_digest(&self) -> Result<Digest, ServiceError> {
        digest_serializable(self).map_err(ServiceError::from)
    }

    fn validate(&self, initial_request: &ListFirewallsRequest) -> Result<(), ServiceError> {
        if self.requests.is_empty()
            || self.requests.len() != self.pages.len()
            || self.pages.len() > MAX_PAGES as usize
            || self.item_count() > MAX_FIREWALLS
        {
            return Err(ServiceError::PartialEvidence);
        }
        let mut seen_cursors = BTreeSet::new();
        let mut request = initial_request.clone();
        for (index, (page_request, page)) in self.requests.iter().zip(&self.pages).enumerate() {
            if page_request.request_digest() != request.request_digest()
                || page.request_digest != page_request.request_digest()
                || page.page_number != (index as u16 + 1)
            {
                return Err(ServiceError::RequestDrift);
            }
            if let Some(cursor) = &page.next_token {
                if !seen_cursors.insert(cursor.digest().clone()) {
                    return Err(ServiceError::PaginationLoop);
                }
                request = request.with_next_token(Some(cursor.clone()));
            }
        }
        let ends = self.pages.last().and_then(|page| page.next_token.as_ref());
        if self.complete != ends.is_none() {
            return Err(ServiceError::PartialEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AwsNetworkFirewallReadRecord {
    ListFirewalls(AwsNetworkFirewallListRecord),
    DescribeFirewall(DescribeFirewallResponse),
    DescribeFirewallPolicy(crate::provider::DescribeFirewallPolicyResponse),
}

impl AwsNetworkFirewallReadRecord {
    pub const fn operation(&self) -> ReadOperation {
        match self {
            Self::ListFirewalls(_) => ReadOperation::ListFirewalls,
            Self::DescribeFirewall(_) => ReadOperation::DescribeFirewall,
            Self::DescribeFirewallPolicy(_) => ReadOperation::DescribeFirewallPolicy,
        }
    }

    pub fn record_digest(&self) -> Result<Digest, ServiceError> {
        digest_serializable(self).map_err(ServiceError::from)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    Partial,
    AccessLoss,
    ProviderUnknown,
    PolicyRevisionDrift,
    RegistrationRevoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationEvidence {
    pub pages_observed: u16,
    pub items_observed: usize,
    pub complete: bool,
    pub page_token_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionSummary {
    pub raw_identifiers_redacted: bool,
    pub raw_next_tokens_redacted: bool,
    pub raw_update_tokens_redacted: bool,
    pub raw_policy_objects_redacted: bool,
    pub raw_rule_text_redacted: bool,
    pub raw_rule_ips_redacted: bool,
    pub packet_payloads_retained: bool,
    pub flow_logs_retained: bool,
    pub secret_material_retained: bool,
    pub provider_error_messages_retained: bool,
}

impl Default for RedactionSummary {
    fn default() -> Self {
        Self {
            raw_identifiers_redacted: true,
            raw_next_tokens_redacted: true,
            raw_update_tokens_redacted: true,
            raw_policy_objects_redacted: true,
            raw_rule_text_redacted: true,
            raw_rule_ips_redacted: true,
            packet_payloads_retained: false,
            flow_logs_retained: false,
            secret_material_retained: false,
            provider_error_messages_retained: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub version_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub policy_digest: Digest,
    pub request_digest: Digest,
    pub record_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallListProjection {
    pub firewall_digest: Digest,
    pub vpc_digest: Digest,
    pub transit_gateway_attachment_digest: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceDigestMaterial<'a> {
    operation: ReadOperation,
    mission: &'a MissionBinding,
    project: &'a ProjectBinding,
    work_product: &'a WorkProductBinding,
    firewall_list: &'a [FirewallListProjection],
    firewall: &'a Option<FirewallPostureProjection>,
    policy: &'a Option<PolicyPostureProjection>,
    pagination: &'a PaginationEvidence,
    redaction: &'a RedactionSummary,
    authority: &'a AuthorityBoundary,
    status: EvidenceStatus,
    provenance: ProviderProvenance,
    registration_digest: &'a Digest,
    version_digest: &'a Digest,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    contract_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    policy_digest: &'a Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsNetworkFirewallPostureEvidence {
    pub operation: ReadOperation,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub firewall_list: Vec<FirewallListProjection>,
    pub firewall: Option<FirewallPostureProjection>,
    pub policy: Option<PolicyPostureProjection>,
    pub pagination: PaginationEvidence,
    pub redaction: RedactionSummary,
    pub status: EvidenceStatus,
    pub authority: AuthorityBoundary,
    pub provenance: ProviderProvenance,
    pub registration_digest: Digest,
    pub digests: EvidenceDigests,
}

impl AwsNetworkFirewallPostureEvidence {
    fn calculate_evidence_digest(&self) -> Result<Digest, ServiceError> {
        digest_serializable(&EvidenceDigestMaterial {
            operation: self.operation,
            mission: &self.mission,
            project: &self.project,
            work_product: &self.work_product,
            firewall_list: &self.firewall_list,
            firewall: &self.firewall,
            policy: &self.policy,
            pagination: &self.pagination,
            redaction: &self.redaction,
            authority: &self.authority,
            status: self.status,
            provenance: self.provenance,
            registration_digest: &self.registration_digest,
            version_digest: &self.digests.version_digest,
            provider_digest: &self.digests.provider_digest,
            api_digest: &self.digests.api_digest,
            contract_digest: &self.digests.contract_digest,
            permission_digest: &self.digests.permission_digest,
            scope_digest: &self.digests.scope_digest,
            policy_digest: &self.digests.policy_digest,
        })
        .map_err(ServiceError::from)
    }

    pub fn verify(&self) -> Result<(), ServiceError> {
        if self.digests.evidence_digest != self.calculate_evidence_digest()?
            || self.authority != AuthorityBoundary::default()
            || self.redaction.packet_payloads_retained
            || self.redaction.flow_logs_retained
            || self.redaction.secret_material_retained
            || self.redaction.provider_error_messages_retained
        {
            return Err(ServiceError::TamperedEvidence);
        }
        for digest in [
            &self.registration_digest,
            &self.digests.version_digest,
            &self.digests.provider_digest,
            &self.digests.api_digest,
            &self.digests.contract_digest,
            &self.digests.permission_digest,
            &self.digests.scope_digest,
            &self.digests.policy_digest,
            &self.digests.request_digest,
            &self.digests.record_digest,
            &self.digests.evidence_digest,
        ] {
            digest
                .validate()
                .map_err(|_| ServiceError::TamperedEvidence)?;
        }
        if let Some(policy) = &self.policy {
            policy.validate()?;
        }
        Ok(())
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

pub struct AwsNetworkFirewallPostureService<
    T: AwsNetworkFirewallTransport = crate::provider::BlockedEnvTransport,
> {
    scope: AwsNetworkFirewallScope,
    secret_reference: SecretReference,
    provider: AwsNetworkFirewallProvider<T>,
    version: ServiceVersion,
    registration: AwsNetworkFirewallPostureRegistration,
}

impl<T: AwsNetworkFirewallTransport> fmt::Debug for AwsNetworkFirewallPostureService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsNetworkFirewallPostureService")
            .field("scope_digest", &self.scope.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

impl<T: AwsNetworkFirewallTransport> AwsNetworkFirewallPostureService<T> {
    pub fn new(
        scope: AwsNetworkFirewallScope,
        secret_reference: SecretReference,
        provider: AwsNetworkFirewallProvider<T>,
    ) -> Result<Self, ServiceError> {
        scope.validate()?;
        secret_reference
            .validate(&scope)
            .map_err(|_| ServiceError::SecretRevoked)?;
        provider.definition().validate()?;
        let version = ServiceVersion::new();
        version.validate()?;
        let registration = AwsNetworkFirewallPostureRegistration::new(
            "aws-network-firewall-registration-1",
            &scope,
            &secret_reference,
            &version,
            provider.definition(),
            1,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            version,
            registration,
        })
    }

    pub fn describe_capabilities(&self) -> AwsNetworkFirewallCapabilities {
        AwsNetworkFirewallCapabilities {
            service_id: AWS_NETWORK_FIREWALL_SERVICE_ID.to_owned(),
            provider_id: AWS_NETWORK_FIREWALL_PROVIDER_ID.to_owned(),
            provider_version: AWS_NETWORK_FIREWALL_PROVIDER_VERSION.to_owned(),
            api_version: AWS_NETWORK_FIREWALL_API_VERSION.to_owned(),
            api_revision: AWS_NETWORK_FIREWALL_API_REVISION.to_owned(),
            operations: ReadOperation::ALL.to_vec(),
            max_pages: MAX_PAGES,
            max_page_size: crate::MAX_PAGE_SIZE,
            opaque_pagination: true,
            read_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            authority: AuthorityBoundary::default(),
        }
    }

    pub fn service_version(&self) -> &ServiceVersion {
        &self.version
    }

    pub fn scope(&self) -> &AwsNetworkFirewallScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsNetworkFirewallProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsNetworkFirewallProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsNetworkFirewallPostureRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsNetworkFirewallPostureRegistration {
        &mut self.registration
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransition, ServiceError> {
        let transition = self.registration.revoke(
            &self.scope,
            &self.secret_reference,
            &self.version,
            self.provider.definition(),
        )?;
        Ok(transition)
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransition, ServiceError> {
        self.registration.reverse(
            &self.scope,
            &self.secret_reference,
            &self.version,
            self.provider.definition(),
        )
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransition, ServiceError> {
        self.registration.restore(
            &self.scope,
            &self.secret_reference,
            &self.version,
            self.provider.definition(),
        )
    }

    pub fn revoke_secret_reference(&mut self) -> Result<(), ServiceError> {
        self.secret_reference
            .revoke()
            .map_err(|_| ServiceError::SecretRevoked)
    }

    pub fn consumer(&self) -> Result<MissionAwsNetworkFirewallConsumer, ServiceError> {
        MissionAwsNetworkFirewallConsumer::new(self.scope.clone(), self.registration.clone())
            .map_err(|error| {
                ServiceError::Model(ModelError::Invalid {
                    field: match error {
                        crate::consumer::ConsumerError::Revoked => "consumer registration",
                        _ => "consumer",
                    },
                })
            })
    }

    pub fn propose_list_firewalls(
        &self,
    ) -> Result<AwsNetworkFirewallPostureProposal, ServiceError> {
        self.propose(AwsNetworkFirewallReadRequest::ListFirewalls(
            ListFirewallsRequest::for_scope(&self.scope, None),
        ))
    }

    pub fn propose_describe_firewall(
        &self,
        firewall: FirewallIdentity,
    ) -> Result<AwsNetworkFirewallPostureProposal, ServiceError> {
        self.propose(AwsNetworkFirewallReadRequest::DescribeFirewall(
            DescribeFirewallRequest::for_scope(&self.scope, firewall)?,
        ))
    }

    pub fn propose_describe_firewall_policy(
        &self,
        policy: FirewallPolicyIdentity,
    ) -> Result<AwsNetworkFirewallPostureProposal, ServiceError> {
        self.propose(AwsNetworkFirewallReadRequest::DescribeFirewallPolicy(
            DescribeFirewallPolicyRequest::for_scope(&self.scope, policy)?,
        ))
    }

    pub fn propose(
        &self,
        request: AwsNetworkFirewallReadRequest,
    ) -> Result<AwsNetworkFirewallPostureProposal, ServiceError> {
        self.ensure_fences(request.operation())?;
        request.validate()?;
        if request.scope_digest() != &self.scope.scope_digest
            || request.permission_digest() != &self.scope.permissions.permission_digest
            || request.policy_digest() != &self.scope.policy_digest
        {
            return Err(ServiceError::ScopeMismatch);
        }
        let proposal = AwsNetworkFirewallPostureProposal::new(
            request,
            &self.scope,
            &self.version,
            self.provider.definition(),
            &self.registration,
        )?;
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &AwsNetworkFirewallPostureProposal,
    ) -> Result<AwsNetworkFirewallReadRecord, ServiceError> {
        self.ensure_proposal_fences(proposal)?;
        match &proposal.request {
            AwsNetworkFirewallReadRequest::ListFirewalls(initial_request) => {
                let mut requests = Vec::new();
                let mut pages = Vec::new();
                let mut request = initial_request.clone();
                let mut cursors = BTreeSet::new();
                let mut complete = false;
                for _ in 0..MAX_PAGES {
                    if requests.len() >= MAX_REQUESTS_PER_READ as usize {
                        break;
                    }
                    let page = self.provider.list_firewalls(&request)?;
                    requests.push(request.clone());
                    let next = page.next_token.clone();
                    pages.push(page);
                    match next {
                        None => {
                            complete = true;
                            break;
                        }
                        Some(cursor) => {
                            if !cursors.insert(cursor.digest().clone()) {
                                return Err(ServiceError::PaginationLoop);
                            }
                            request = request.with_next_token(Some(cursor));
                        }
                    }
                }
                Ok(AwsNetworkFirewallReadRecord::ListFirewalls(
                    AwsNetworkFirewallListRecord {
                        requests,
                        pages,
                        complete,
                    },
                ))
            }
            AwsNetworkFirewallReadRequest::DescribeFirewall(request) => {
                Ok(AwsNetworkFirewallReadRecord::DescribeFirewall(
                    self.provider.describe_firewall(request)?,
                ))
            }
            AwsNetworkFirewallReadRequest::DescribeFirewallPolicy(request) => {
                Ok(AwsNetworkFirewallReadRecord::DescribeFirewallPolicy(
                    self.provider.describe_firewall_policy(request)?,
                ))
            }
        }
    }

    pub fn verify(
        &self,
        proposal: &AwsNetworkFirewallPostureProposal,
        record: &AwsNetworkFirewallReadRecord,
    ) -> Result<AwsNetworkFirewallPostureEvidence, ServiceError> {
        self.ensure_proposal_fences(proposal)?;
        proposal.validate()?;
        if record.operation() != proposal.operation {
            return Err(ServiceError::RequestDrift);
        }
        let record_digest = record.record_digest()?;
        let evidence = match (&proposal.request, record) {
            (
                AwsNetworkFirewallReadRequest::ListFirewalls(request),
                AwsNetworkFirewallReadRecord::ListFirewalls(list),
            ) => self.verify_list(request, list, record_digest.clone(), proposal)?,
            (
                AwsNetworkFirewallReadRequest::DescribeFirewall(request),
                AwsNetworkFirewallReadRecord::DescribeFirewall(response),
            ) => self.verify_firewall(request, response, record_digest.clone(), proposal)?,
            (
                AwsNetworkFirewallReadRequest::DescribeFirewallPolicy(request),
                AwsNetworkFirewallReadRecord::DescribeFirewallPolicy(response),
            ) => self.verify_policy(request, response, record_digest.clone(), proposal)?,
            _ => return Err(ServiceError::RequestDrift),
        };
        evidence.verify()?;
        Ok(evidence)
    }

    pub fn read(
        &mut self,
        request: AwsNetworkFirewallReadRequest,
    ) -> Result<AwsNetworkFirewallReadResult, ServiceError> {
        let proposal = self.propose(request)?;
        let record = self.record(&proposal)?;
        let evidence = self.verify(&proposal, &record)?;
        Ok(AwsNetworkFirewallReadResult {
            proposal,
            record,
            evidence,
        })
    }

    pub fn read_list_firewalls(&mut self) -> Result<AwsNetworkFirewallReadResult, ServiceError> {
        self.read(AwsNetworkFirewallReadRequest::ListFirewalls(
            ListFirewallsRequest::for_scope(&self.scope, None),
        ))
    }

    pub fn read_describe_firewall(
        &mut self,
        firewall: FirewallIdentity,
    ) -> Result<AwsNetworkFirewallReadResult, ServiceError> {
        let request = DescribeFirewallRequest::for_scope(&self.scope, firewall)?;
        self.read(AwsNetworkFirewallReadRequest::DescribeFirewall(request))
    }

    pub fn read_describe_firewall_policy(
        &mut self,
        policy: FirewallPolicyIdentity,
    ) -> Result<AwsNetworkFirewallReadResult, ServiceError> {
        let request = DescribeFirewallPolicyRequest::for_scope(&self.scope, policy)?;
        self.read(AwsNetworkFirewallReadRequest::DescribeFirewallPolicy(
            request,
        ))
    }

    fn ensure_fences(&self, operation: ReadOperation) -> Result<(), ServiceError> {
        self.scope.validate()?;
        self.version.validate()?;
        self.provider.definition().validate()?;
        if !self.registration.is_active() {
            return match self.registration.state() {
                RegistrationState::Revoked => Err(ServiceError::RegistrationRevoked),
                RegistrationState::Reversed => Err(ServiceError::RegistrationReversed),
                RegistrationState::Active => Err(ServiceError::RegistrationInactive),
            };
        }
        self.registration.validate(
            &self.scope,
            &self.secret_reference,
            &self.version,
            self.provider.definition(),
        )?;
        self.secret_reference
            .validate(&self.scope)
            .map_err(|_| ServiceError::SecretRevoked)?;
        if !self.scope.permissions.permits(operation) {
            return Err(ServiceError::PermissionLoss);
        }
        Ok(())
    }

    fn ensure_proposal_fences(
        &self,
        proposal: &AwsNetworkFirewallPostureProposal,
    ) -> Result<(), ServiceError> {
        self.ensure_fences(proposal.operation)?;
        proposal.validate()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.version_digest != self.version.version_digest
            || proposal.provider_digest != self.provider.definition().provider_digest
            || proposal.api_digest != self.provider.definition().api_digest
            || proposal.contract_digest != self.version.contract_digest
            || proposal.permission_digest != self.scope.permissions.permission_digest
            || proposal.scope_digest != self.scope.scope_digest
            || proposal.policy_digest != self.scope.policy_digest
        {
            return Err(ServiceError::RequestDrift);
        }
        Ok(())
    }

    fn verify_list(
        &self,
        request: &ListFirewallsRequest,
        record: &AwsNetworkFirewallListRecord,
        record_digest: Digest,
        proposal: &AwsNetworkFirewallPostureProposal,
    ) -> Result<AwsNetworkFirewallPostureEvidence, ServiceError> {
        record.validate(request)?;
        if !record.complete {
            return Err(ServiceError::PartialEvidence);
        }
        let mut seen = BTreeSet::new();
        let mut firewall_list = Vec::new();
        for page in &record.pages {
            if page.provider_digest != self.provider.definition().provider_digest
                || page.response_bytes > MAX_RESPONSE_BYTES
            {
                return Err(ServiceError::TamperedEvidence);
            }
            for item in &page.firewalls {
                if self.scope.firewall(&item.identity).is_none()
                    || item.vpc_id != self.scope.vpc_id
                    || !seen.insert(item.identity.digest())
                {
                    return Err(ServiceError::ScopeMismatch);
                }
                firewall_list.push(FirewallListProjection {
                    firewall_digest: item.identity.digest(),
                    vpc_digest: item.vpc_id.digest(),
                    transit_gateway_attachment_digest: item
                        .transit_gateway_attachment_digest
                        .clone(),
                });
            }
        }
        self.build_evidence(
            proposal,
            record_digest,
            PaginationEvidence {
                pages_observed: record.pages.len() as u16,
                items_observed: record.item_count(),
                complete: true,
                page_token_digests: record.page_token_digests(),
            },
            firewall_list,
            None,
            None,
        )
    }

    fn verify_firewall(
        &self,
        request: &DescribeFirewallRequest,
        response: &DescribeFirewallResponse,
        record_digest: Digest,
        proposal: &AwsNetworkFirewallPostureProposal,
    ) -> Result<AwsNetworkFirewallPostureEvidence, ServiceError> {
        if response.request_digest != request.request_digest()
            || response.provider_digest != self.provider.definition().provider_digest
            || response.response_bytes > MAX_RESPONSE_BYTES
            || self.scope.firewall(&response.firewall.identity).is_none()
            || response.firewall.vpc_id != self.scope.vpc_id
            || self
                .scope
                .policy(&response.firewall.firewall_policy)
                .is_none()
        {
            return Err(ServiceError::ScopeMismatch);
        }
        response
            .firewall
            .update_token_digest
            .validate()
            .map_err(|_| ServiceError::TamperedEvidence)?;
        let mut endpoint_digests = BTreeSet::new();
        if response
            .firewall
            .endpoint_attachments
            .iter()
            .any(|attachment| !endpoint_digests.insert(attachment.endpoint_digest.clone()))
        {
            return Err(ServiceError::TamperedEvidence);
        }
        if response.firewall.status == FirewallStatus::Unknown
            || response
                .firewall
                .endpoint_attachments
                .iter()
                .any(|attachment| attachment.status == EndpointStatus::Unknown)
        {
            return Err(ServiceError::ProviderUnknown);
        }
        for attachment in &response.firewall.endpoint_attachments {
            let allowed = self.scope.endpoints.iter().any(|binding| {
                binding.endpoint_id.digest() == attachment.endpoint_digest
                    && binding.subnet_id.digest() == attachment.subnet_digest
            });
            if !allowed {
                return Err(ServiceError::ScopeMismatch);
            }
        }
        let firewall = response.firewall.projection();
        self.build_evidence(
            proposal,
            record_digest,
            PaginationEvidence {
                pages_observed: 1,
                items_observed: 1,
                complete: true,
                page_token_digests: Vec::new(),
            },
            Vec::new(),
            Some(firewall),
            None,
        )
    }

    fn verify_policy(
        &self,
        request: &DescribeFirewallPolicyRequest,
        response: &crate::provider::DescribeFirewallPolicyResponse,
        record_digest: Digest,
        proposal: &AwsNetworkFirewallPostureProposal,
    ) -> Result<AwsNetworkFirewallPostureEvidence, ServiceError> {
        let binding = self
            .scope
            .policy(&response.policy.identity)
            .ok_or(ServiceError::ScopeMismatch)?;
        if response.request_digest != request.request_digest()
            || response.provider_digest != self.provider.definition().provider_digest
            || response.response_bytes > MAX_RESPONSE_BYTES
            || response.policy.identity != request.policy
            || response.policy.revision != binding.expected_revision
        {
            return Err(ServiceError::PolicyRevisionDrift);
        }
        response.policy.projection()?;
        if response.policy.status == crate::model::PolicyStatus::Unknown {
            return Err(ServiceError::ProviderUnknown);
        }
        let policy = response.policy.projection()?;
        self.build_evidence(
            proposal,
            record_digest,
            PaginationEvidence {
                pages_observed: 1,
                items_observed: 1,
                complete: true,
                page_token_digests: Vec::new(),
            },
            Vec::new(),
            None,
            Some(policy),
        )
    }

    fn build_evidence(
        &self,
        proposal: &AwsNetworkFirewallPostureProposal,
        record_digest: Digest,
        pagination: PaginationEvidence,
        firewall_list: Vec<FirewallListProjection>,
        firewall: Option<FirewallPostureProjection>,
        policy: Option<PolicyPostureProjection>,
    ) -> Result<AwsNetworkFirewallPostureEvidence, ServiceError> {
        let redaction = RedactionSummary::default();
        let authority = AuthorityBoundary::default();
        let mut evidence = AwsNetworkFirewallPostureEvidence {
            operation: proposal.operation,
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            firewall_list,
            firewall,
            policy,
            pagination,
            redaction,
            status: EvidenceStatus::Complete,
            authority,
            provenance: self.provider.provenance(),
            registration_digest: proposal.registration_digest.clone(),
            digests: EvidenceDigests {
                version_digest: self.version.version_digest.clone(),
                provider_digest: self.provider.definition().provider_digest.clone(),
                api_digest: self.provider.definition().api_digest.clone(),
                contract_digest: self.version.contract_digest.clone(),
                permission_digest: self.scope.permissions.permission_digest.clone(),
                scope_digest: self.scope.scope_digest.clone(),
                policy_digest: self.scope.policy_digest.clone(),
                request_digest: proposal.request.request_digest(),
                record_digest,
                evidence_digest: Digest::zero(),
            },
        };
        evidence.digests.evidence_digest = evidence.calculate_evidence_digest()?;
        Ok(evidence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsNetworkFirewallReadResult {
    pub proposal: AwsNetworkFirewallPostureProposal,
    pub record: AwsNetworkFirewallReadRecord,
    pub evidence: AwsNetworkFirewallPostureEvidence,
}

// Compatibility aliases used by callers that shorten the service name.
pub type AwsNetworkFirewallPostureResult = AwsNetworkFirewallReadResult;
pub type AwsNetworkFirewallProviderErrorAlias = AwsNetworkFirewallProviderError;
pub type AwsNetworkFirewallPostureRegistrationState = RegistrationState;

#[allow(dead_code)]
fn _keep_service_types_linked(
    _: Option<OpaqueCursor>,
    _: Option<FirewallDescription>,
    _: Option<FirewallListItem>,
    _: Option<PolicyRevision>,
    _: Option<ActionSummary>,
    _: Option<ProviderProvenance>,
    _: Option<ContractDigestMarker>,
) {
}

struct ContractDigestMarker;

const _: &str = CONTRACT_DIGEST_INPUT;
