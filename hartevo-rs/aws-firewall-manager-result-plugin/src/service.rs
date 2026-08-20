//! Service, registration, proposal, recording, and verification seams.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::{
    AWS_FIREWALL_MANAGER_CONSUMER_ID, AWS_FIREWALL_MANAGER_CONTRACT_VERSION,
    AWS_FIREWALL_MANAGER_PLUGIN_VERSION, AWS_FIREWALL_MANAGER_SERVICE_ID, contract_digest,
    error::{AwsFirewallManagerError, Result, TransportError, TransportFailure},
    model::{
        AwsFirewallManagerOperation, AwsFirewallManagerScope, CapabilityDescription,
        ComplianceDetailProjection, CompliancePage, ComplianceSummary, Digest, EvidenceDigests,
        EvidenceState, FailureEvidence, GetComplianceDetailRequest, GetPolicyRequest,
        ListComplianceStatusRequest, ListPoliciesRequest, MissionBinding, PaginationEvidence,
        PolicyIdentity, PolicyPage, PolicyPosture, PolicyResponse, PolicySummary, ProjectBinding,
        RedactionSummary, ResourceId, ResourceType, SecretReference, TransportProvenance,
        WorkProductBinding,
    },
    provider::{AwsFirewallManagerProvider, AwsFirewallManagerTransport},
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

impl RegistrationState {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransition {
    pub previous_state: RegistrationState,
    pub new_state: RegistrationState,
    pub registration_revision: u64,
    pub registration_digest: Digest,
}

pub struct AwsFirewallManagerRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_version: String,
    api_version: String,
    api_revision: String,
    provider_digest: Digest,
    permission_digest: Digest,
    policy_allowlist_digest: Digest,
    scope_digest: Digest,
    evidence_binding_digest: Digest,
    secret_reference: SecretReference,
    consent_digest: Digest,
    registration_revision: u64,
    state: RegistrationState,
    registration_digest: Digest,
}

impl AwsFirewallManagerRegistration {
    pub fn new<T: AwsFirewallManagerTransport>(
        id: impl Into<String>,
        scope: &AwsFirewallManagerScope,
        secret_reference: SecretReference,
        provider: &AwsFirewallManagerProvider<T>,
        registration_revision: u64,
    ) -> Result<Self> {
        scope.validate()?;
        secret_reference.validate(scope)?;
        provider.definition().validate()?;
        if registration_revision == 0 {
            return Err(AwsFirewallManagerError::RegistrationMismatch);
        }
        let id = id.into();
        if id.trim().is_empty() || id.len() > 128 {
            return Err(AwsFirewallManagerError::RegistrationMismatch);
        }
        let evidence_binding_digest = Digest::from_parts(
            "aws-fms-registration-evidence-binding/v1",
            &[
                ("plugin", AWS_FIREWALL_MANAGER_PLUGIN_VERSION.to_owned()),
                ("provider", provider.provider_digest().to_string()),
                ("contract", contract_digest().to_string()),
                ("permission", scope.permissions().digest().to_string()),
                (
                    "policy_allowlist",
                    scope.policy_allowlist_digest().to_string(),
                ),
                ("scope", scope.scope_digest().to_string()),
                ("consent", scope.consent().digest().to_string()),
            ],
        );
        let mut registration = Self {
            id,
            plugin_version: AWS_FIREWALL_MANAGER_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_FIREWALL_MANAGER_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.definition().id.clone(),
            provider_version: provider.definition().version.clone(),
            api_version: provider.definition().api_version.clone(),
            api_revision: provider.definition().api_revision.clone(),
            provider_digest: provider.provider_digest().clone(),
            permission_digest: scope.permissions().digest().clone(),
            policy_allowlist_digest: scope.policy_allowlist_digest().clone(),
            scope_digest: scope.scope_digest().clone(),
            evidence_binding_digest,
            secret_reference,
            consent_digest: scope.consent().digest().clone(),
            registration_revision,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    pub fn id_digest(&self) -> Digest {
        Digest::from_text(&self.id)
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn policy_allowlist_digest(&self) -> &Digest {
        &self.policy_allowlist_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn evidence_binding_digest(&self) -> &Digest {
        &self.evidence_binding_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn is_active(&self) -> bool {
        self.state.is_active()
    }

    pub const fn is_reversible(&self) -> bool {
        !matches!(self.state, RegistrationState::Revoked)
    }

    pub const fn is_revocable(&self) -> bool {
        !matches!(self.state, RegistrationState::Revoked)
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn validate(&self) -> Result<()> {
        if self.plugin_version != AWS_FIREWALL_MANAGER_PLUGIN_VERSION
            || self.contract_version != AWS_FIREWALL_MANAGER_CONTRACT_VERSION
            || self.provider_id != crate::AWS_FIREWALL_MANAGER_PROVIDER_ID
            || self.provider_version != crate::AWS_FIREWALL_MANAGER_PROVIDER_VERSION
            || self.api_version != crate::AWS_FIREWALL_MANAGER_API_VERSION
            || self.api_revision != crate::AWS_FIREWALL_MANAGER_API_REVISION
            || self.registration_digest != self.compute_digest()
            || self.contract_digest != contract_digest()
            || self.state == RegistrationState::Active && self.secret_reference.is_revoked()
        {
            return Err(AwsFirewallManagerError::RegistrationMismatch);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition> {
        self.transition(RegistrationState::Revoked)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransition> {
        if self.state == RegistrationState::Revoked {
            return Err(AwsFirewallManagerError::InvalidRegistrationTransition);
        }
        self.transition(RegistrationState::Reversed)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransition> {
        if self.state != RegistrationState::Reversed {
            return Err(AwsFirewallManagerError::InvalidRegistrationTransition);
        }
        self.transition(RegistrationState::Active)
    }

    fn transition(&mut self, new_state: RegistrationState) -> Result<RegistrationTransition> {
        if self.state == RegistrationState::Revoked || self.state == new_state {
            return Err(AwsFirewallManagerError::InvalidRegistrationTransition);
        }
        let previous_state = self.state;
        self.state = new_state;
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(AwsFirewallManagerError::RegistrationMismatch)?;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationTransition {
            previous_state,
            new_state,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
        })
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-fms-registration/v1",
            &[
                ("id", self.id_digest().to_string()),
                ("plugin", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.to_string()),
                ("provider_id", self.provider_id.clone()),
                ("provider_version", self.provider_version.clone()),
                ("api", self.api_version.clone()),
                ("api_revision", self.api_revision.clone()),
                ("provider", self.provider_digest.to_string()),
                ("permission", self.permission_digest.to_string()),
                ("policy_allowlist", self.policy_allowlist_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                ("evidence", self.evidence_binding_digest.to_string()),
                (
                    "secret",
                    self.secret_reference.reference_digest().to_string(),
                ),
                ("consent", self.consent_digest.to_string()),
                ("revision", self.registration_revision.to_string()),
                ("state", format!("{:?}", self.state)),
            ],
        )
    }
}

impl fmt::Debug for AwsFirewallManagerRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsFirewallManagerRegistration")
            .field("id_digest", &self.id_digest())
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_version", &self.provider_version)
            .field("api_version", &self.api_version)
            .field("api_revision", &self.api_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest)
            .field("policy_allowlist_digest", &self.policy_allowlist_digest)
            .field("scope_digest", &self.scope_digest)
            .field("evidence_binding_digest", &self.evidence_binding_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("consent_digest", &self.consent_digest)
            .field("registration_revision", &self.registration_revision)
            .field("state", &self.state)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for AwsFirewallManagerRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsFirewallManagerRegistration", 17)?;
        state.serialize_field("idDigest", &self.id_digest())?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerVersion", &self.provider_version)?;
        state.serialize_field("apiVersion", &self.api_version)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("policyAllowlistDigest", &self.policy_allowlist_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("evidenceBindingDigest", &self.evidence_binding_digest)?;
        state.serialize_field(
            "secretReferenceDigest",
            self.secret_reference.reference_digest(),
        )?;
        state.serialize_field("consentDigest", &self.consent_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("state", &self.state)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum AwsFirewallManagerReadRequest {
    ListPolicies(ListPoliciesRequest),
    GetPolicy(GetPolicyRequest),
    ListComplianceStatus(ListComplianceStatusRequest),
    GetComplianceDetail(GetComplianceDetailRequest),
}

impl AwsFirewallManagerReadRequest {
    pub fn operation(&self) -> AwsFirewallManagerOperation {
        match self {
            Self::ListPolicies(_) => AwsFirewallManagerOperation::ListPolicies,
            Self::GetPolicy(_) => AwsFirewallManagerOperation::GetPolicy,
            Self::ListComplianceStatus(_) => AwsFirewallManagerOperation::ListComplianceStatus,
            Self::GetComplianceDetail(_) => AwsFirewallManagerOperation::GetComplianceDetail,
        }
    }

    pub fn scope_digest(&self) -> &Digest {
        match self {
            Self::ListPolicies(request) => &request.scope_digest,
            Self::GetPolicy(request) => &request.scope_digest,
            Self::ListComplianceStatus(request) => &request.scope_digest,
            Self::GetComplianceDetail(request) => &request.scope_digest,
        }
    }

    pub fn request_digest(&self) -> &Digest {
        match self {
            Self::ListPolicies(request) => request.request_digest(),
            Self::GetPolicy(request) => request.request_digest(),
            Self::ListComplianceStatus(request) => request.request_digest(),
            Self::GetComplianceDetail(request) => request.request_digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum AwsFirewallManagerReadResult {
    ListPolicies(PolicyPage),
    GetPolicy(PolicyResponse),
    ListComplianceStatus(CompliancePage),
    GetComplianceDetail(crate::ComplianceDetailResponse),
}

impl AwsFirewallManagerReadResult {
    pub fn operation(&self) -> AwsFirewallManagerOperation {
        match self {
            Self::ListPolicies(_) => AwsFirewallManagerOperation::ListPolicies,
            Self::GetPolicy(_) => AwsFirewallManagerOperation::GetPolicy,
            Self::ListComplianceStatus(_) => AwsFirewallManagerOperation::ListComplianceStatus,
            Self::GetComplianceDetail(_) => AwsFirewallManagerOperation::GetComplianceDetail,
        }
    }

    pub fn response_digest(&self) -> Digest {
        match self {
            Self::ListPolicies(page) => page.response_digest.clone(),
            Self::GetPolicy(response) => response.response_digest.clone(),
            Self::ListComplianceStatus(page) => page.response_digest.clone(),
            Self::GetComplianceDetail(response) => response.response_digest.clone(),
        }
    }

    pub fn provenance(&self) -> TransportProvenance {
        match self {
            Self::ListPolicies(page) => page.provenance,
            Self::GetPolicy(response) => response.provenance,
            Self::ListComplianceStatus(page) => page.provenance,
            Self::GetComplianceDetail(response) => response.provenance,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsFirewallManagerEvidence {
    pub service_id: String,
    pub consumer_id: String,
    pub operation: AwsFirewallManagerOperation,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub state: EvidenceState,
    pub policy_summaries: Vec<PolicySummary>,
    pub policy_posture: Option<PolicyPosture>,
    pub compliance_statuses: Vec<ComplianceSummary>,
    pub compliance_detail: Option<ComplianceDetailProjection>,
    pub pagination: PaginationEvidence,
    pub failure: Option<FailureEvidence>,
    pub redaction: RedactionSummary,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub remediation_authority: bool,
    pub effect_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl AwsFirewallManagerEvidence {
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-fms-evidence/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("operation", self.operation.as_str().to_owned()),
                ("registration", self.registration_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                (
                    "mission",
                    serde_json::to_string(&self.mission).unwrap_or_default(),
                ),
                (
                    "project",
                    serde_json::to_string(&self.project).unwrap_or_default(),
                ),
                (
                    "work_product",
                    serde_json::to_string(&self.work_product).unwrap_or_default(),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "policies",
                    serde_json::to_string(&self.policy_summaries).unwrap_or_default(),
                ),
                (
                    "posture",
                    serde_json::to_string(&self.policy_posture).unwrap_or_default(),
                ),
                (
                    "statuses",
                    serde_json::to_string(&self.compliance_statuses).unwrap_or_default(),
                ),
                (
                    "detail",
                    serde_json::to_string(&self.compliance_detail).unwrap_or_default(),
                ),
                (
                    "pagination",
                    serde_json::to_string(&self.pagination).unwrap_or_default(),
                ),
                (
                    "failure",
                    serde_json::to_string(&self.failure).unwrap_or_default(),
                ),
                (
                    "evidence",
                    serde_json::to_string(&self.evidence).unwrap_or_default(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("observed", self.observed_at.to_rfc3339()),
                ("expires", self.expires_at.to_rfc3339()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.plugin_version_digest.validate()?;
        self.evidence.provider_digest.validate()?;
        self.evidence.api_digest.validate()?;
        self.evidence.contract_digest.validate()?;
        self.evidence.permission_digest.validate()?;
        self.evidence.policy_allowlist_digest.validate()?;
        self.evidence.scope_digest.validate()?;
        self.evidence.request_digest.validate()?;
        self.evidence
            .cursor_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence
            .policy_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence
            .compliance_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence
            .violation_category_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        if self.service_id != AWS_FIREWALL_MANAGER_SERVICE_ID
            || self.consumer_id != AWS_FIREWALL_MANAGER_CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.remediation_authority
            || self.effect_authority
            || self.outcome_adopted
            || self.work_product_adopted
            || self.evidence.plugin_version_digest
                != Digest::from_text(AWS_FIREWALL_MANAGER_PLUGIN_VERSION)
            || self.evidence.api_digest != crate::model::api_digest()
            || self.evidence.contract_digest != contract_digest()
            || self.evidence.evidence_digest != self.evidence.compute_digest()
            || self.expires_at <= self.observed_at
        {
            return Err(AwsFirewallManagerError::TamperedEvidence);
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsFirewallManagerProposal {
    pub evidence: AwsFirewallManagerEvidence,
    pub proposal_digest: Digest,
}

impl AwsFirewallManagerProposal {
    pub fn new(evidence: AwsFirewallManagerEvidence) -> Self {
        let proposal_digest = Digest::from_parts(
            "aws-fms-proposal/v1",
            &[
                ("evidence", evidence.digest().to_string()),
                ("registration", evidence.registration_digest.to_string()),
                ("scope", evidence.scope_digest.to_string()),
            ],
        );
        Self {
            evidence,
            proposal_digest,
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate_integrity()?;
        let expected = Digest::from_parts(
            "aws-fms-proposal/v1",
            &[
                ("evidence", self.evidence.digest().to_string()),
                (
                    "registration",
                    self.evidence.registration_digest.to_string(),
                ),
                ("scope", self.evidence.scope_digest.to_string()),
            ],
        );
        if self.proposal_digest != expected {
            return Err(AwsFirewallManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsFirewallManagerRecord {
    pub record_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub recording_digest: Digest,
    pub replayed: bool,
    pub provider_receipt: bool,
    pub native: bool,
    pub connected: bool,
}

impl AwsFirewallManagerRecord {
    pub fn validate_integrity(&self) -> Result<()> {
        let expected = Digest::from_parts(
            "aws-fms-recording/v1",
            &[
                ("key", self.record_key_digest.to_string()),
                ("proposal", self.proposal_digest.to_string()),
                ("evidence", self.evidence_digest.to_string()),
                ("replayed", self.replayed.to_string()),
            ],
        );
        if self.recording_digest != expected
            || self.provider_receipt
            || self.native
            || self.connected
        {
            return Err(AwsFirewallManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

pub type AwsFirewallManagerRecordReceipt = AwsFirewallManagerRecord;
pub type AwsFirewallManagerVerifiedRecord = AwsFirewallManagerRecord;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationMismatch,
    ProviderDigestMismatch,
    ApiRevisionMismatch,
    PermissionDigestMismatch,
    PolicyAllowlistDigestMismatch,
    ScopeDigestMismatch,
    EvidenceDigestMismatch,
    ProposalDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    ExpiredEvidence,
    UnknownEvidence,
    AccessLoss,
    PaginationLoop,
    IncompletePagination,
    StaleMission,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn new(valid: bool, review_eligible: bool, failures: Vec<VerificationFailure>) -> Self {
        let verification_digest = Digest::from_parts(
            "aws-fms-verification/v1",
            &[
                ("valid", valid.to_string()),
                ("review_eligible", review_eligible.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|failure| format!("{failure:?}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Self {
            valid,
            review_eligible,
            failures,
            verification_digest,
        }
    }
}

pub struct AwsFirewallManagerService<T: AwsFirewallManagerTransport> {
    scope: AwsFirewallManagerScope,
    registration: AwsFirewallManagerRegistration,
    provider: AwsFirewallManagerProvider<T>,
    now: DateTime<Utc>,
    records: BTreeMap<Digest, AwsFirewallManagerRecord>,
}

impl<T: AwsFirewallManagerTransport> fmt::Debug for AwsFirewallManagerService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsFirewallManagerService")
            .field("scope", &self.scope)
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .field("now", &self.now)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T: AwsFirewallManagerTransport> AwsFirewallManagerService<T> {
    pub fn register(
        scope: AwsFirewallManagerScope,
        secret_reference: SecretReference,
        provider: AwsFirewallManagerProvider<T>,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(scope, secret_reference, provider, now)
    }

    pub fn new(
        scope: AwsFirewallManagerScope,
        secret_reference: SecretReference,
        provider: AwsFirewallManagerProvider<T>,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = AwsFirewallManagerRegistration::new(
            "aws-firewall-manager-registration",
            &scope,
            secret_reference,
            &provider,
            1,
        )?;
        Ok(Self {
            scope,
            registration,
            provider,
            now,
            records: BTreeMap::new(),
        })
    }

    pub fn with_registration(
        scope: AwsFirewallManagerScope,
        secret_reference: SecretReference,
        provider: AwsFirewallManagerProvider<T>,
        registration_id: impl Into<String>,
        registration_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = AwsFirewallManagerRegistration::new(
            registration_id,
            &scope,
            secret_reference,
            &provider,
            registration_revision,
        )?;
        Ok(Self {
            scope,
            registration,
            provider,
            now,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsFirewallManagerScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsFirewallManagerRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsFirewallManagerRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsFirewallManagerProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsFirewallManagerProvider<T> {
        &mut self.provider
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: AWS_FIREWALL_MANAGER_SERVICE_ID.to_owned(),
            provider_id: crate::AWS_FIREWALL_MANAGER_PROVIDER_ID.to_owned(),
            operations: self.provider.definition().operations.clone(),
            permissions: crate::model::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
        }
    }

    pub fn default_list_policies_request(&self) -> Result<ListPoliciesRequest> {
        ListPoliciesRequest::new(&self.scope, None, self.provider.bounds().page_size, None)
    }

    pub fn default_request(&self) -> Result<AwsFirewallManagerReadRequest> {
        self.default_list_policies_request()
            .map(AwsFirewallManagerReadRequest::ListPolicies)
    }

    pub fn default_get_policy_request(&self, policy: PolicyIdentity) -> Result<GetPolicyRequest> {
        GetPolicyRequest::new(&self.scope, policy)
    }

    pub fn default_list_compliance_status_request(
        &self,
        policy: PolicyIdentity,
    ) -> Result<ListComplianceStatusRequest> {
        ListComplianceStatusRequest::new(
            &self.scope,
            policy,
            self.provider.bounds().page_size,
            None,
        )
    }

    pub fn default_get_compliance_detail_request(
        &self,
        policy: PolicyIdentity,
        member_account: crate::MemberAccountId,
        resource_type: ResourceType,
        resource_id: ResourceId,
    ) -> Result<GetComplianceDetailRequest> {
        GetComplianceDetailRequest::new(
            &self.scope,
            policy,
            member_account,
            resource_type,
            resource_id,
        )
    }

    pub fn read_bounded(
        &mut self,
        request: AwsFirewallManagerReadRequest,
    ) -> Result<AwsFirewallManagerReadResult> {
        self.validate_request(&request)?;
        match request {
            AwsFirewallManagerReadRequest::ListPolicies(request) => self
                .provider
                .list_policies(&request)
                .map(AwsFirewallManagerReadResult::ListPolicies),
            AwsFirewallManagerReadRequest::GetPolicy(request) => self
                .provider
                .get_policy(&request)
                .map(AwsFirewallManagerReadResult::GetPolicy),
            AwsFirewallManagerReadRequest::ListComplianceStatus(request) => self
                .provider
                .list_compliance_status(&request)
                .map(AwsFirewallManagerReadResult::ListComplianceStatus),
            AwsFirewallManagerReadRequest::GetComplianceDetail(request) => self
                .provider
                .get_compliance_detail(&request)
                .map(AwsFirewallManagerReadResult::GetComplianceDetail),
        }
    }

    pub fn read(
        &mut self,
        request: AwsFirewallManagerReadRequest,
    ) -> Result<AwsFirewallManagerReadResult> {
        self.read_bounded(request)
    }

    pub fn read_list_policies(&mut self, request: ListPoliciesRequest) -> Result<PolicyPage> {
        match self.read_bounded(AwsFirewallManagerReadRequest::ListPolicies(request))? {
            AwsFirewallManagerReadResult::ListPolicies(page) => Ok(page),
            _ => Err(AwsFirewallManagerError::ProviderDrift),
        }
    }

    pub fn read_get_policy(&mut self, request: GetPolicyRequest) -> Result<PolicyResponse> {
        match self.read_bounded(AwsFirewallManagerReadRequest::GetPolicy(request))? {
            AwsFirewallManagerReadResult::GetPolicy(response) => Ok(response),
            _ => Err(AwsFirewallManagerError::ProviderDrift),
        }
    }

    pub fn read_list_compliance_status(
        &mut self,
        request: ListComplianceStatusRequest,
    ) -> Result<CompliancePage> {
        match self.read_bounded(AwsFirewallManagerReadRequest::ListComplianceStatus(request))? {
            AwsFirewallManagerReadResult::ListComplianceStatus(page) => Ok(page),
            _ => Err(AwsFirewallManagerError::ProviderDrift),
        }
    }

    pub fn read_get_compliance_detail(
        &mut self,
        request: GetComplianceDetailRequest,
    ) -> Result<crate::ComplianceDetailResponse> {
        match self.read_bounded(AwsFirewallManagerReadRequest::GetComplianceDetail(request))? {
            AwsFirewallManagerReadResult::GetComplianceDetail(response) => Ok(response),
            _ => Err(AwsFirewallManagerError::ProviderDrift),
        }
    }

    pub fn propose(
        &mut self,
        request: AwsFirewallManagerReadRequest,
    ) -> Result<AwsFirewallManagerProposal> {
        self.validate_request(&request)?;
        let observed_at = self.now;
        let expires_at = observed_at + Duration::hours(1);
        match self.propose_inner(request.clone(), observed_at, expires_at) {
            Ok(evidence) => Ok(AwsFirewallManagerProposal::new(evidence)),
            Err(AwsFirewallManagerError::Transport(error)) => Ok(AwsFirewallManagerProposal::new(
                self.failure_evidence(&request, observed_at, expires_at, error),
            )),
            Err(error) => Err(error),
        }
    }

    pub fn propose_at(
        &mut self,
        request: AwsFirewallManagerReadRequest,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<AwsFirewallManagerProposal> {
        if expires_at <= observed_at {
            return Err(AwsFirewallManagerError::ExpiredEvidence);
        }
        self.validate_request(&request)?;
        match self.propose_inner(request.clone(), observed_at, expires_at) {
            Ok(evidence) => Ok(AwsFirewallManagerProposal::new(evidence)),
            Err(AwsFirewallManagerError::Transport(error)) => Ok(AwsFirewallManagerProposal::new(
                self.failure_evidence(&request, observed_at, expires_at, error),
            )),
            Err(error) => Err(error),
        }
    }

    fn propose_inner(
        &mut self,
        request: AwsFirewallManagerReadRequest,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<AwsFirewallManagerEvidence> {
        match request {
            AwsFirewallManagerReadRequest::ListPolicies(request) => {
                let mut request = request;
                let mut policies = Vec::new();
                let mut token_digests = Vec::new();
                let mut pages: u16 = 0;
                let mut seen = BTreeSet::new();
                let mut response_digests = Vec::new();
                let mut complete = false;
                loop {
                    pages += 1;
                    let page = match self.read_list_policies(request.clone()) {
                        Ok(page) => page,
                        Err(AwsFirewallManagerError::Transport(error)) => {
                            if pages == 1 {
                                return Err(AwsFirewallManagerError::Transport(error));
                            }
                            let request =
                                AwsFirewallManagerReadRequest::ListPolicies(request.clone());
                            let mut evidence =
                                self.failure_evidence(&request, observed_at, expires_at, error);
                            evidence.state = EvidenceState::Partial;
                            evidence.pagination = PaginationEvidence {
                                pages_observed: pages.saturating_sub(1),
                                page_token_digests: token_digests,
                                complete: false,
                                loop_detected: false,
                            };
                            return Ok(evidence);
                        }
                        Err(error) => return Err(error),
                    };
                    if page.policies.iter().any(|summary| {
                        self.scope
                            .policy(&summary.policy_digest)
                            .is_none_or(|policy| {
                                policy.policy_type != summary.policy_type
                                    || policy.revision != summary.policy_revision
                                    || policy.arn.digest() != summary.policy_arn_digest
                            })
                    }) {
                        return Err(AwsFirewallManagerError::PolicyNotAllowed);
                    }
                    response_digests.push(page.response_digest.clone());
                    policies.extend(page.policies);
                    if policies.len() > self.provider.bounds().max_policies {
                        return Err(AwsFirewallManagerError::InvalidResponse);
                    }
                    if let Some(cursor) = page.next_cursor {
                        if !seen.insert(cursor.token_digest().clone()) {
                            return Err(AwsFirewallManagerError::Transport(TransportError::new(
                                TransportFailure::PaginationLoop,
                            )));
                        }
                        token_digests.push(cursor.token_digest().clone());
                        if pages >= self.provider.bounds().max_pages {
                            break;
                        }
                        request = request.with_cursor(Some(cursor))?;
                    } else {
                        complete = true;
                        break;
                    }
                }
                let state = if complete {
                    EvidenceState::Complete
                } else {
                    EvidenceState::Partial
                };
                let request_digest = request.request_digest().clone();
                let evidence = self.base_evidence(
                    AwsFirewallManagerOperation::ListPolicies,
                    state,
                    observed_at,
                    expires_at,
                    PaginationEvidence {
                        pages_observed: pages,
                        page_token_digests: token_digests,
                        complete,
                        loop_detected: false,
                    },
                    Some(request_digest.clone()),
                    None,
                    Some(Digest::from_parts(
                        "aws-fms-policy-pages/v1",
                        &[(
                            "pages",
                            response_digests
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join("\n"),
                        )],
                    )),
                    None,
                    policies,
                    None,
                    Vec::new(),
                    None,
                    None,
                );
                Ok(evidence)
            }
            AwsFirewallManagerReadRequest::GetPolicy(request) => {
                let response = self.read_get_policy(request.clone())?;
                if response
                    .policy
                    .resource_types
                    .iter()
                    .any(|resource_type| !self.scope.allows_resource_type(resource_type))
                {
                    return Err(AwsFirewallManagerError::ResourceTypeNotAllowed);
                }
                let policy_digest = response.policy.policy_digest.clone();
                Ok(self.base_evidence(
                    AwsFirewallManagerOperation::GetPolicy,
                    EvidenceState::Complete,
                    observed_at,
                    expires_at,
                    PaginationEvidence {
                        pages_observed: 1,
                        complete: true,
                        ..PaginationEvidence::default()
                    },
                    Some(request.request_digest().clone()),
                    Some(policy_digest.clone()),
                    Some(response.response_digest.clone()),
                    None,
                    Vec::new(),
                    Some(response.policy),
                    Vec::new(),
                    None,
                    None,
                ))
            }
            AwsFirewallManagerReadRequest::ListComplianceStatus(request) => {
                let mut request = request;
                let mut statuses = Vec::new();
                let mut token_digests = Vec::new();
                let mut response_digests = Vec::new();
                let mut seen = BTreeSet::new();
                let mut pages: u16 = 0;
                let mut complete = false;
                let policy_digest = request.policy.digest();
                loop {
                    pages += 1;
                    let page = match self.read_list_compliance_status(request.clone()) {
                        Ok(page) => page,
                        Err(AwsFirewallManagerError::Transport(error)) => {
                            if pages == 1 {
                                return Err(AwsFirewallManagerError::Transport(error));
                            }
                            let request = AwsFirewallManagerReadRequest::ListComplianceStatus(
                                request.clone(),
                            );
                            let mut evidence =
                                self.failure_evidence(&request, observed_at, expires_at, error);
                            evidence.state = EvidenceState::Partial;
                            evidence.pagination = PaginationEvidence {
                                pages_observed: pages.saturating_sub(1),
                                page_token_digests: token_digests,
                                complete: false,
                                loop_detected: false,
                            };
                            return Ok(evidence);
                        }
                        Err(error) => return Err(error),
                    };
                    if page.statuses.iter().any(|status| {
                        !self
                            .scope
                            .allows_member_account_digest(&status.member_account_digest)
                            || status
                                .resource_type_digests
                                .iter()
                                .any(|digest| !self.scope.allows_resource_type_digest(digest))
                    }) {
                        return Err(AwsFirewallManagerError::AccountNotAllowed);
                    }
                    response_digests.push(page.response_digest.clone());
                    statuses.extend(page.statuses);
                    if statuses.len() > self.provider.bounds().max_member_accounts {
                        return Err(AwsFirewallManagerError::InvalidResponse);
                    }
                    if let Some(cursor) = page.next_cursor {
                        if !seen.insert(cursor.token_digest().clone()) {
                            return Err(AwsFirewallManagerError::Transport(TransportError::new(
                                TransportFailure::PaginationLoop,
                            )));
                        }
                        token_digests.push(cursor.token_digest().clone());
                        if pages >= self.provider.bounds().max_pages {
                            break;
                        }
                        request = ListComplianceStatusRequest::new(
                            &self.scope,
                            request.policy.clone(),
                            request.max_results,
                            Some(cursor),
                        )?;
                    } else {
                        complete = true;
                        break;
                    }
                }
                let violation_digest = aggregate_violation_digest(&statuses);
                Ok(self.base_evidence(
                    AwsFirewallManagerOperation::ListComplianceStatus,
                    if complete {
                        EvidenceState::Complete
                    } else {
                        EvidenceState::Partial
                    },
                    observed_at,
                    expires_at,
                    PaginationEvidence {
                        pages_observed: pages,
                        page_token_digests: token_digests,
                        complete,
                        loop_detected: false,
                    },
                    Some(request.request_digest().clone()),
                    Some(policy_digest),
                    Some(Digest::from_parts(
                        "aws-fms-compliance-pages/v1",
                        &[(
                            "pages",
                            response_digests
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join("\n"),
                        )],
                    )),
                    Some(violation_digest),
                    Vec::new(),
                    None,
                    statuses,
                    None,
                    None,
                ))
            }
            AwsFirewallManagerReadRequest::GetComplianceDetail(request) => {
                let response = self.read_get_compliance_detail(request.clone())?;
                let detail_digest = response.detail.digest();
                let violation_digest = Digest::from_parts(
                    "aws-fms-violation-digests/v1",
                    &[(
                        "values",
                        response
                            .detail
                            .violation_category_digests
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join("\n"),
                    )],
                );
                Ok(self.base_evidence(
                    AwsFirewallManagerOperation::GetComplianceDetail,
                    EvidenceState::Complete,
                    observed_at,
                    expires_at,
                    PaginationEvidence {
                        pages_observed: 1,
                        complete: true,
                        ..PaginationEvidence::default()
                    },
                    Some(request.request_digest().clone()),
                    Some(request.policy.digest()),
                    Some(response.response_digest.clone()),
                    Some(violation_digest),
                    Vec::new(),
                    None,
                    Vec::new(),
                    Some(response.detail),
                    Some(detail_digest),
                ))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn base_evidence(
        &self,
        operation: AwsFirewallManagerOperation,
        state: EvidenceState,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        pagination: PaginationEvidence,
        request_digest: Option<Digest>,
        policy_digest: Option<Digest>,
        compliance_digest: Option<Digest>,
        violation_category_digest: Option<Digest>,
        policy_summaries: Vec<PolicySummary>,
        policy_posture: Option<PolicyPosture>,
        compliance_statuses: Vec<ComplianceSummary>,
        compliance_detail: Option<ComplianceDetailProjection>,
        _detail_digest: Option<Digest>,
    ) -> AwsFirewallManagerEvidence {
        let request_digest = request_digest.unwrap_or_else(|| Digest::from_text("no-request"));
        let evidence = EvidenceDigests::initial(
            self.provider.provider_digest().clone(),
            self.scope.permissions().digest().clone(),
            self.scope.policy_allowlist_digest().clone(),
            self.scope.scope_digest().clone(),
            request_digest,
            pagination.page_token_digests.first().cloned(),
            policy_digest,
            compliance_digest,
            violation_category_digest,
        );
        AwsFirewallManagerEvidence {
            service_id: AWS_FIREWALL_MANAGER_SERVICE_ID.to_owned(),
            consumer_id: AWS_FIREWALL_MANAGER_CONSUMER_ID.to_owned(),
            operation,
            registration_digest: self.registration.registration_digest().clone(),
            scope_digest: self.scope.scope_digest().clone(),
            mission: self.scope.mission().clone(),
            project: self.scope.project().clone(),
            work_product: self.scope.work_product().clone(),
            state,
            policy_summaries,
            policy_posture,
            compliance_statuses,
            compliance_detail,
            pagination,
            failure: None,
            redaction: RedactionSummary::default(),
            evidence,
            provenance: self.provider.provenance(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            remediation_authority: false,
            effect_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
            observed_at,
            expires_at,
        }
    }

    fn failure_evidence(
        &self,
        request: &AwsFirewallManagerReadRequest,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        error: TransportError,
    ) -> AwsFirewallManagerEvidence {
        let mut evidence = self.base_evidence(
            request.operation(),
            state_from_transport(&error),
            observed_at,
            expires_at,
            PaginationEvidence::default(),
            Some(request.request_digest().clone()),
            None,
            None,
            None,
            Vec::new(),
            None,
            Vec::new(),
            None,
            None,
        );
        evidence.failure = Some(FailureEvidence::from_transport(request.operation(), &error));
        evidence.evidence.evidence_digest = evidence.evidence.compute_digest();
        evidence
    }

    fn validate_request(&self, request: &AwsFirewallManagerReadRequest) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsFirewallManagerError::RegistrationInactive);
        }
        self.registration.secret_reference().validate(&self.scope)?;
        if !self.scope.is_active_at(self.now) {
            return Err(AwsFirewallManagerError::ExpiredEvidence);
        }
        if request.scope_digest() != self.scope.scope_digest()
            || request.scope_digest() != self.registration.scope_digest()
        {
            return Err(AwsFirewallManagerError::StaleMission);
        }
        Ok(())
    }

    pub fn verify(&self, proposal: &AwsFirewallManagerProposal) -> VerificationReport {
        self.verify_at(proposal, self.now)
    }

    pub fn verify_at(
        &self,
        proposal: &AwsFirewallManagerProposal,
        at: DateTime<Utc>,
    ) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if self.registration.validate().is_err()
            || proposal.evidence.registration_digest != *self.registration.registration_digest()
        {
            failures.push(VerificationFailure::RegistrationMismatch);
        }
        if proposal.evidence.evidence.provider_digest != *self.provider.provider_digest() {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.evidence.api_digest != crate::model::api_digest() {
            failures.push(VerificationFailure::ApiRevisionMismatch);
        }
        if proposal.evidence.evidence.permission_digest != *self.scope.permissions().digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.evidence.policy_allowlist_digest
            != *self.scope.policy_allowlist_digest()
        {
            failures.push(VerificationFailure::PolicyAllowlistDigestMismatch);
        }
        if proposal.evidence.scope_digest != *self.scope.scope_digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.evidence.evidence_digest != proposal.evidence.evidence.compute_digest()
        {
            failures.push(VerificationFailure::EvidenceDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        if at >= proposal.evidence.expires_at || at < proposal.evidence.observed_at {
            failures.push(VerificationFailure::ExpiredEvidence);
        }
        match proposal.evidence.state {
            EvidenceState::Partial => failures.push(VerificationFailure::PartialEvidence),
            EvidenceState::Unknown | EvidenceState::ProviderUnknown => {
                failures.push(VerificationFailure::UnknownEvidence);
            }
            EvidenceState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            EvidenceState::Stale => failures.push(VerificationFailure::StaleMission),
            EvidenceState::RegistrationRevoked => {
                failures.push(VerificationFailure::RegistrationInactive);
            }
            EvidenceState::Complete | EvidenceState::Expired => {}
        }
        if proposal.evidence.pagination.loop_detected {
            failures.push(VerificationFailure::PaginationLoop);
        }
        if !proposal.evidence.pagination.complete {
            failures.push(VerificationFailure::IncompletePagination);
        }
        failures.sort();
        failures.dedup();
        VerificationReport::new(
            failures.is_empty(),
            failures.is_empty() && proposal.evidence.state.is_adoptable(),
            failures,
        )
    }

    pub fn record(
        &mut self,
        proposal: &AwsFirewallManagerProposal,
        record_key: impl Into<String>,
    ) -> Result<AwsFirewallManagerRecordReceipt> {
        proposal.validate_integrity()?;
        let key = record_key.into();
        if key.trim().is_empty() || key.len() > 128 {
            return Err(AwsFirewallManagerError::RecordingConflict);
        }
        let key_digest = Digest::from_text(&key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != *proposal.digest() {
                return Err(AwsFirewallManagerError::ReplayMismatch);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = Digest::from_parts(
                "aws-fms-recording/v1",
                &[
                    ("key", replay.record_key_digest.to_string()),
                    ("proposal", replay.proposal_digest.to_string()),
                    ("evidence", replay.evidence_digest.to_string()),
                    ("replayed", "true".to_owned()),
                ],
            );
            return Ok(replay);
        }
        let mut record = AwsFirewallManagerRecord {
            record_key_digest: key_digest,
            proposal_digest: proposal.digest().clone(),
            evidence_digest: proposal.evidence.evidence.evidence_digest.clone(),
            recording_digest: Digest::zero(),
            replayed: false,
            provider_receipt: false,
            native: false,
            connected: false,
        };
        record.recording_digest = Digest::from_parts(
            "aws-fms-recording/v1",
            &[
                ("key", record.record_key_digest.to_string()),
                ("proposal", record.proposal_digest.to_string()),
                ("evidence", record.evidence_digest.to_string()),
                ("replayed", "false".to_owned()),
            ],
        );
        record.validate_integrity()?;
        self.records
            .insert(record.record_key_digest.clone(), record.clone());
        Ok(record)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransition> {
        self.registration.revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransition> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransition> {
        self.registration.restore()
    }
}

pub type AwsFirewallManagerServiceError = AwsFirewallManagerError;

fn state_from_transport(error: &TransportError) -> EvidenceState {
    match error.failure {
        TransportFailure::Unauthorized
        | TransportFailure::AccessDenied
        | TransportFailure::Forbidden
        | TransportFailure::AccessLoss => EvidenceState::AccessLoss,
        TransportFailure::Partial | TransportFailure::PaginationLoop => EvidenceState::Partial,
        TransportFailure::Stale => EvidenceState::Stale,
        TransportFailure::BlockedEnv
        | TransportFailure::BadRequest
        | TransportFailure::NotFound
        | TransportFailure::Throttled
        | TransportFailure::RateLimited
        | TransportFailure::Server
        | TransportFailure::ServerError
        | TransportFailure::Timeout
        | TransportFailure::Unknown => EvidenceState::Unknown,
    }
}

fn aggregate_violation_digest(statuses: &[ComplianceSummary]) -> Digest {
    let mut values = statuses
        .iter()
        .flat_map(|status| {
            status
                .violation_category_digests
                .iter()
                .map(ToString::to_string)
        })
        .collect::<Vec<_>>();
    values.sort();
    Digest::from_parts(
        "aws-fms-violation-digests/v1",
        &[("values", values.join("\n"))],
    )
}
