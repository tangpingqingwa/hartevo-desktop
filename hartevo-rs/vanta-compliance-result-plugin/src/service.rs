//! Typed Vanta service orchestration.

use std::{collections::BTreeMap, fmt};

use chrono::{DateTime, Utc};
use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginVersion, ProviderCardinality,
    ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};

use crate::model::{
    ComplianceObjective, Digest, VantaAuditRecord, VantaComplianceProjection,
    VantaComplianceResultProposal, VantaComplianceScope, VantaComplianceState, VantaControlRecord,
    VantaEvidenceBundle, VantaInformationRequestRecord, VantaIssueRecord, VantaReadEvidence,
    VantaReadFailure, VantaReadFailureKind, VantaReadRequest, VantaRecordingReceipt,
    VantaRegistration, VantaResponseBody, VantaTestRecord,
};
use crate::provider::VantaProvider;
use crate::transport::VantaTransport;
use crate::{
    VANTA_CONTRACT_VERSION, VANTA_MAX_PAGES, VANTA_PAGE_SIZE, VANTA_PLUGIN_VERSION_TEXT,
    VANTA_PROVIDER_ID, VANTA_SERVICE_ID, VANTA_SERVICE_NAME, VANTA_SERVICE_SCHEMA,
    VantaComplianceResultError, contract_digest, plugin_version,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VantaComplianceResultServiceOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ReadBoundedStatus,
    CompileReadinessProposal,
    RecordProposal,
}

impl VantaComplianceResultServiceOperation {
    pub const ALL: [Self; 6] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ReadBoundedStatus,
        Self::CompileReadinessProposal,
        Self::RecordProposal,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaCapability {
    pub capability_id: String,
    pub operation: VantaComplianceResultServiceOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VantaProposalRequest {
    pub objective: ComplianceObjective,
    pub page_size: u16,
    pub max_pages: u16,
    pub observed_at: DateTime<Utc>,
}

impl VantaProposalRequest {
    pub fn new(objective: ComplianceObjective, observed_at: DateTime<Utc>) -> Self {
        Self {
            objective,
            page_size: VANTA_PAGE_SIZE,
            max_pages: VANTA_MAX_PAGES,
            observed_at,
        }
    }

    pub fn with_bounds(mut self, page_size: u16, max_pages: u16) -> Self {
        self.page_size = page_size;
        self.max_pages = max_pages;
        self
    }
}

pub struct VantaComplianceResultService<T> {
    scope: VantaComplianceScope,
    secret_reference: crate::model::SecretReference,
    secret_revoked: bool,
    registration: VantaRegistration,
    provider: VantaProvider<T>,
}

impl<T: fmt::Debug> fmt::Debug for VantaComplianceResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VantaComplianceResultService")
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("secret_revoked", &self.secret_revoked)
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: VantaTransport> VantaComplianceResultService<T> {
    pub fn new(
        scope: VantaComplianceScope,
        secret_reference: crate::model::SecretReference,
        provider: VantaProvider<T>,
    ) -> Result<Self, VantaComplianceResultError> {
        scope.validate()?;
        crate::VantaComplianceResultContract::baseline()?;
        let registration = VantaRegistration::new(
            &scope,
            &secret_reference,
            provider.identity(),
            contract_digest(),
        )?;
        registration.validate(
            &scope,
            &secret_reference,
            provider.identity(),
            &contract_digest(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            secret_revoked: false,
            registration,
            provider,
        })
    }

    pub fn register(
        scope: VantaComplianceScope,
        secret_reference: crate::model::SecretReference,
        provider: VantaProvider<T>,
    ) -> Result<Self, VantaComplianceResultError> {
        Self::new(scope, secret_reference, provider)
    }

    pub fn scope(&self) -> &VantaComplianceScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &crate::model::SecretReference {
        &self.secret_reference
    }

    pub fn registration(&self) -> &VantaRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &VantaProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut VantaProvider<T> {
        &mut self.provider
    }

    pub const fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret_revoked
    }

    pub fn revoke_registration(&mut self) -> Result<(), VantaComplianceResultError> {
        self.registration
            .revoke()
            .map_err(|_| VantaComplianceResultError::RegistrationRevoked)
    }

    pub fn revoke_secret(&mut self) -> Result<(), VantaComplianceResultError> {
        if self.secret_revoked {
            return Err(VantaComplianceResultError::SecretRevoked);
        }
        self.secret_revoked = true;
        Ok(())
    }

    pub fn service_id(&self) -> &'static str {
        VANTA_SERVICE_ID
    }

    pub fn service_name(&self) -> &'static str {
        VANTA_SERVICE_NAME
    }

    pub const fn version(&self) -> PluginVersion {
        plugin_version()
    }

    pub const fn read_only(&self) -> bool {
        true
    }

    pub const fn native_connected(&self) -> bool {
        false
    }

    pub fn describe_capabilities(&self) -> Vec<VantaCapability> {
        [
            (
                "vanta.compliance-result.register",
                VantaComplianceResultServiceOperation::Register,
            ),
            (
                "vanta.compliance-result.revoke_registration",
                VantaComplianceResultServiceOperation::RevokeRegistration,
            ),
            (
                "vanta.compliance-result.read_bounded_status",
                VantaComplianceResultServiceOperation::ReadBoundedStatus,
            ),
            (
                "vanta.compliance-result.compile_readiness_proposal",
                VantaComplianceResultServiceOperation::CompileReadinessProposal,
            ),
            (
                "vanta.compliance-result.record_proposal",
                VantaComplianceResultServiceOperation::RecordProposal,
            ),
        ]
        .into_iter()
        .map(|(capability_id, operation)| VantaCapability {
            capability_id: capability_id.to_owned(),
            operation,
            read_only: true,
            mutates_provider: false,
            native: false,
        })
        .collect()
    }

    pub fn runtime_definition(&self) -> Result<ServiceDefinition, VantaComplianceResultError> {
        ServiceDefinition::read_only(
            ServiceId::new(VANTA_SERVICE_ID)?,
            plugin_version(),
            RuntimeDigest::from_text(VANTA_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(Into::into)
    }

    pub fn read(
        &mut self,
        endpoint: crate::model::VantaEndpoint,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<VantaReadEvidence, VantaComplianceResultError> {
        self.ensure_registration()?;
        self.ensure_endpoint(&endpoint)?;
        let request = VantaReadRequest::new(
            endpoint,
            self.scope.digest(),
            page_size,
            max_pages,
            observed_at,
        )?;
        let evidence = self.provider.read(&self.secret_reference, &request)?;
        evidence.validate_scope(&self.scope)?;
        Ok(evidence)
    }

    pub fn propose(
        &mut self,
        request: VantaProposalRequest,
    ) -> Result<VantaComplianceResultProposal, VantaComplianceResultError> {
        self.ensure_registration()?;
        if request.objective != self.scope.objective {
            return Err(VantaComplianceResultError::ScopeMismatch(
                "proposal objective does not match the registered Mission scope".to_owned(),
            ));
        }
        if request.page_size == 0
            || request.page_size > VANTA_PAGE_SIZE
            || request.max_pages == 0
            || request.max_pages > VANTA_MAX_PAGES
        {
            return Err(VantaComplianceResultError::InvalidInput(
                "Vanta proposal bounds exceed the Layer-1 contract".to_owned(),
            ));
        }
        let mut reads = Vec::new();
        let mut failures = Vec::new();
        for endpoint in self.scope.expected_endpoints() {
            match self.read(
                endpoint.clone(),
                request.page_size,
                request.max_pages,
                request.observed_at,
            ) {
                Ok(evidence) => reads.push(evidence),
                Err(error) => failures.push(classify_failure(endpoint, &error)),
            }
        }
        let bundle = VantaEvidenceBundle::new(
            &self.scope,
            self.registration.registration_digest.clone(),
            self.provider.identity(),
            reads,
            failures,
            self.provider.provenance(),
        )?;
        self.compile_proposal(request.objective, bundle)
    }

    pub fn compile_proposal(
        &self,
        objective: ComplianceObjective,
        bundle: VantaEvidenceBundle,
    ) -> Result<VantaComplianceResultProposal, VantaComplianceResultError> {
        self.ensure_registration()?;
        if objective != self.scope.objective {
            return Err(VantaComplianceResultError::ScopeMismatch(
                "proposal objective does not match the registered Mission scope".to_owned(),
            ));
        }
        bundle.validate(&self.scope)?;
        if bundle.registration_digest != self.registration.registration_digest
            || bundle.provider_digest != *self.provider.provider_digest()
            || bundle.provider_revision != *self.provider.provider_revision()
        {
            return Err(VantaComplianceResultError::StaleEvidence);
        }
        let projection = projection_from_bundle(&self.scope, &bundle)?;
        let mut proposal = VantaComplianceResultProposal {
            plugin_version: VANTA_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: VANTA_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: VANTA_PROVIDER_ID.to_owned(),
            provider_version: self.provider.identity().version.clone(),
            provider_revision: self.provider.provider_revision().clone(),
            provider_digest: self.provider.provider_digest().clone(),
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.registration_revision,
            audit_digest: self.scope.audit_digest(),
            audit_revision: self.scope.audit.revision,
            scope_digest: self.scope.digest(),
            permission_digest: self.scope.permission_digest.clone(),
            consent_digest: self.scope.consent.digest.clone(),
            mission_revision: self.scope.mission.revision,
            project_revision: self.scope.project.revision,
            objective,
            projection,
            provenance: bundle.provenance,
            evidence_digest: bundle.bundle_digest,
            read_only: true,
            proposal_only: true,
            native: false,
            connected: false,
            external_write_performed: false,
            certification_claim: false,
            adopted_outcome: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.recompute_digest()?;
        Ok(proposal)
    }

    pub fn record(
        &self,
        proposal: &VantaComplianceResultProposal,
    ) -> Result<VantaRecordingReceipt, VantaComplianceResultError> {
        self.ensure_registration()?;
        proposal.validate(&self.scope, &self.registration)?;
        Ok(VantaRecordingReceipt {
            contract_version: VANTA_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            registration_digest: self.registration.registration_digest.clone(),
            scope_digest: self.scope.digest(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            provenance: proposal.provenance,
            recorded: true,
            raw_provider_payload_retained: false,
            owners_redacted: true,
            evidence_urls_redacted: true,
            comments_redacted: true,
            document_bodies_redacted: true,
            native: false,
            connected: false,
            certification_claim: false,
        })
    }

    fn ensure_registration(&self) -> Result<(), VantaComplianceResultError> {
        if !self.registration.is_active() {
            return Err(VantaComplianceResultError::RegistrationRevoked);
        }
        if self.secret_revoked {
            return Err(VantaComplianceResultError::SecretRevoked);
        }
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                self.provider.identity(),
                &contract_digest(),
            )
            .map_err(|_| {
                VantaComplianceResultError::RegistrationDrift(
                    "registration digest or bound revision drifted".to_owned(),
                )
            })
    }

    fn ensure_endpoint(
        &self,
        endpoint: &crate::model::VantaEndpoint,
    ) -> Result<(), VantaComplianceResultError> {
        if endpoint.audit_id() != &self.scope.audit.id
            || !self.scope.api_family.allows(endpoint.family())
        {
            return Err(VantaComplianceResultError::ScopeMismatch(
                "Vanta endpoint is outside the tenant/audit/API-family scope".to_owned(),
            ));
        }
        Ok(())
    }
}

fn classify_failure(
    endpoint: crate::model::VantaEndpoint,
    error: &VantaComplianceResultError,
) -> VantaReadFailure {
    match error {
        VantaComplianceResultError::BlockedEnv => VantaReadFailure {
            endpoint,
            state: VantaComplianceState::ProviderUnknown,
            kind: VantaReadFailureKind::BlockedEnv,
        },
        VantaComplianceResultError::RateLimited { .. } => VantaReadFailure {
            endpoint,
            state: VantaComplianceState::Partial,
            kind: VantaReadFailureKind::RateLimited,
        },
        VantaComplianceResultError::Transport(
            crate::transport::VantaTransportError::Transport(_)
            | crate::transport::VantaTransportError::UnexpectedResponse,
        )
        | VantaComplianceResultError::ProviderMismatch => VantaReadFailure {
            endpoint,
            state: VantaComplianceState::ProviderUnknown,
            kind: VantaReadFailureKind::ProviderUnknown,
        },
        _ => VantaReadFailure {
            endpoint,
            state: VantaComplianceState::AccessLoss,
            kind: VantaReadFailureKind::AccessLost,
        },
    }
}

fn projection_from_bundle(
    scope: &VantaComplianceScope,
    bundle: &VantaEvidenceBundle,
) -> Result<VantaComplianceProjection, VantaComplianceResultError> {
    let mut audits = BTreeMap::<String, VantaAuditRecord>::new();
    let mut controls = BTreeMap::<String, VantaControlRecord>::new();
    let mut tests = BTreeMap::<String, VantaTestRecord>::new();
    let mut issues = BTreeMap::<String, VantaIssueRecord>::new();
    let mut information_requests = BTreeMap::<String, VantaInformationRequestRecord>::new();
    let mut state = VantaComplianceState::Complete;
    let mut page_limit_reached = false;

    for read in &bundle.reads {
        page_limit_reached |= read.page_limit_reached;
        for page in &read.pages {
            match page {
                VantaResponseBody::Audits(items) => {
                    for item in items {
                        insert_unique(&mut audits, item.audit_id.as_str(), item.clone())?;
                        state = worse_state(state, item.state);
                    }
                }
                VantaResponseBody::Controls(items) => {
                    for item in items {
                        insert_unique(&mut controls, item.control_id.as_str(), item.clone())?;
                        state = worse_state(state, item.state);
                    }
                }
                VantaResponseBody::Tests(items) => {
                    for item in items {
                        insert_unique(&mut tests, item.test_id.as_str(), item.clone())?;
                        state = worse_state(state, item.state);
                    }
                }
                VantaResponseBody::Issues(items) => {
                    for item in items {
                        insert_unique(&mut issues, item.issue_id.as_str(), item.clone())?;
                        state = worse_state(state, item.state);
                    }
                }
                VantaResponseBody::InformationRequests(items) => {
                    for item in items {
                        insert_unique(
                            &mut information_requests,
                            item.information_request_id.as_str(),
                            item.clone(),
                        )?;
                        state = worse_state(state, item.state);
                    }
                }
            }
        }
    }
    for failure in &bundle.failures {
        state = worse_state(state, failure.state);
    }
    let expected_read_count = u16::try_from(scope.expected_endpoints().len()).map_err(|_| {
        VantaComplianceResultError::InvalidInput("expected Vanta reads exceed bound".to_owned())
    })?;
    let observed_read_count =
        u16::try_from(bundle.reads.len() + bundle.failures.len()).map_err(|_| {
            VantaComplianceResultError::InvalidInput("observed Vanta reads exceed bound".to_owned())
        })?;
    if page_limit_reached
        || observed_read_count < expected_read_count
        || (audits.is_empty()
            && controls.is_empty()
            && tests.is_empty()
            && issues.is_empty()
            && information_requests.is_empty())
        || (issues.is_empty() && information_requests.is_empty())
    {
        state = worse_state(state, VantaComplianceState::Partial);
    }
    Ok(VantaComplianceProjection {
        state,
        audits: audits.into_values().collect(),
        controls: controls.into_values().collect(),
        tests: tests.into_values().collect(),
        issues: issues.into_values().collect(),
        information_requests: information_requests.into_values().collect(),
        observed_read_count,
        expected_read_count,
        page_limit_reached,
        no_issues_is_certification: false,
        certification_claim: false,
        native: false,
        connected: false,
        external_write_performed: false,
        outcome_authority: false,
    })
}

fn insert_unique<T: Clone + PartialEq>(
    map: &mut BTreeMap<String, T>,
    key: &str,
    value: T,
) -> Result<(), VantaComplianceResultError> {
    if let Some(existing) = map.get(key) {
        if existing != &value {
            return Err(VantaComplianceResultError::StaleEvidence);
        }
    } else {
        map.insert(key.to_owned(), value);
    }
    Ok(())
}

fn worse_state(left: VantaComplianceState, right: VantaComplianceState) -> VantaComplianceState {
    if state_rank(left) >= state_rank(right) {
        left
    } else {
        right
    }
}

fn state_rank(state: VantaComplianceState) -> u8 {
    match state {
        VantaComplianceState::Complete => 0,
        VantaComplianceState::Open => 1,
        VantaComplianceState::Overdue => 2,
        VantaComplianceState::Blocked => 3,
        VantaComplianceState::Partial => 4,
        VantaComplianceState::RetentionGap => 5,
        VantaComplianceState::AccessLoss => 6,
        VantaComplianceState::ProviderUnknown => 7,
    }
}
