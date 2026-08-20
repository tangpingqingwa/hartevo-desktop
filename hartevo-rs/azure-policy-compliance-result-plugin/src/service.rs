use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    model::{
        AzurePolicyRegistration, AzurePolicyScope, ComplianceState, Digest, EvidenceStatus,
        PermissionFenceReceipt, PolicyStateRecord, ProviderErrorEvidence, ProviderErrorKind,
        ProviderProvenance, RegistrationState,
    },
    provider::{AzurePolicyInsightsProvider, AzurePolicyProviderError, AzurePolicyTransport},
    query::{AzurePolicyQuery, AzurePolicyReadRequest, QueryError},
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AzurePolicyComplianceServiceError {
    #[error("Azure Policy registration is revoked")]
    RegistrationRevoked,
    #[error("Azure Policy SecretReference is revoked")]
    SecretRevoked,
    #[error("Azure Policy request is outside the registered scope")]
    RequestOutOfScope,
    #[error("Azure Policy evidence or proposal digest fence failed")]
    EvidenceMismatch,
    #[error("Azure Policy proposal replay was rejected")]
    ReplayDetected,
    #[error("Azure Policy contract is invalid: {0}")]
    Contract(String),
    #[error(transparent)]
    Query(#[from] QueryError),
    #[error(transparent)]
    Model(#[from] crate::ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzurePolicyComplianceServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub api_version: String,
    pub read_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub certification: bool,
    pub outcome_authority: bool,
}

impl Default for AzurePolicyComplianceServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: crate::AZURE_POLICY_COMPLIANCE_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: crate::AZURE_POLICY_COMPLIANCE_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: crate::AZURE_POLICY_COMPLIANCE_RESULT_SERVICE_ID.to_owned(),
            provider_id: crate::AZURE_POLICY_INSIGHTS_PROVIDER_ID.to_owned(),
            consumer_id: crate::MISSION_AZURE_POLICY_CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            api_version: crate::AZURE_POLICY_API_VERSION.to_owned(),
            read_only: true,
            live_execution: false,
            external_writes: false,
            certification: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceSummary {
    Compliant,
    NonCompliant,
    Exempt,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzurePolicyEvidence {
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub permission_fence: PermissionFenceReceipt,
    pub project_id: crate::ProjectId,
    pub mission_id: crate::MissionId,
    pub work_product_id: crate::WorkProductId,
    pub status: EvidenceStatus,
    pub summary: ComplianceSummary,
    pub records: Vec<PolicyStateRecord>,
    pub pages_observed: u8,
    pub response_bytes: usize,
    pub page_digests: Vec<Digest>,
    pub next_link_digests: Vec<Digest>,
    pub response_digest: Digest,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub provenance: ProviderProvenance,
    pub provider_reported_only: bool,
    pub certification: bool,
    pub outcome_authority: bool,
    pub evidence_digest: Digest,
}

impl AzurePolicyEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.evidence_digest.clone()
    }

    pub fn validate(
        &self,
        scope: &AzurePolicyScope,
        query: &AzurePolicyQuery,
    ) -> Result<(), AzurePolicyComplianceServiceError> {
        if self.scope_digest != scope.scope_digest()
            || self.query_digest != *query.query_digest()
            || self.permission_fence.scope_digest != scope.scope_digest()
            || self.permission_fence.permission_digest != *scope.permission_digest()
            || self.project_id != scope.project().id
            || self.mission_id != scope.mission().id
            || self.work_product_id != scope.work_product().id
            || self.records.len() > query.bounds.max_records
            || self.pages_observed > query.bounds.max_pages
            || !self.provider_reported_only
            || self.certification
            || self.outcome_authority
            || self.provenance.is_native()
        {
            return Err(AzurePolicyComplianceServiceError::EvidenceMismatch);
        }
        if self.records.iter().any(|record| {
            !scope.matches_resource(record.resource_id.as_str())
                || record.timestamp.as_str() < scope.query_window().start.as_str()
                || record.timestamp.as_str() > scope.query_window().end.as_str()
        }) {
            return Err(AzurePolicyComplianceServiceError::EvidenceMismatch);
        }
        if compute_evidence_digest(self) != self.evidence_digest {
            return Err(AzurePolicyComplianceServiceError::EvidenceMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzurePolicyComplianceProposal {
    pub query: AzurePolicyQuery,
    pub evidence: AzurePolicyEvidence,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub certification: bool,
    pub outcome_authority: bool,
    pub proposal_digest: Digest,
}

impl AzurePolicyComplianceProposal {
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.proposal_digest.clone()
    }

    #[must_use]
    pub fn status(&self) -> EvidenceStatus {
        self.evidence.status
    }

    #[must_use]
    pub fn summary(&self) -> &ComplianceSummary {
        &self.evidence.summary
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzurePolicyObservationReceipt {
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub provider_digest: Digest,
    pub provenance: ProviderProvenance,
    pub read_only: bool,
    pub durable_native_receipt: bool,
    pub independent_readback: bool,
    pub certification: bool,
    pub outcome_authority: bool,
}

pub struct AzurePolicyComplianceService<T> {
    provider: AzurePolicyInsightsProvider<T>,
    definition: AzurePolicyComplianceServiceDefinition,
    last_query: Option<AzurePolicyQuery>,
}

pub type AzurePolicyResultService<T> = AzurePolicyComplianceService<T>;

impl<T: AzurePolicyTransport> fmt::Debug for AzurePolicyComplianceService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzurePolicyComplianceService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .field("last_query", &self.last_query)
            .finish()
    }
}

impl<T: AzurePolicyTransport> AzurePolicyComplianceService<T> {
    pub fn new(
        provider: AzurePolicyInsightsProvider<T>,
    ) -> Result<Self, AzurePolicyComplianceServiceError> {
        if provider.definition().native
            || provider.definition().https_transport
            || provider.definition().live_execution
            || provider.registration().state != RegistrationState::Active
        {
            return Err(AzurePolicyComplianceServiceError::Contract(
                "Layer-1 provider definition is not read-only and non-native".to_owned(),
            ));
        }
        Ok(Self {
            provider,
            definition: AzurePolicyComplianceServiceDefinition::default(),
            last_query: None,
        })
    }

    #[must_use]
    pub fn from_provider(provider: AzurePolicyInsightsProvider<T>) -> Self {
        Self {
            provider,
            definition: AzurePolicyComplianceServiceDefinition::default(),
            last_query: None,
        }
    }

    #[must_use]
    pub fn provider(&self) -> &AzurePolicyInsightsProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut AzurePolicyInsightsProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &AzurePolicyScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &AzurePolicyRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &AzurePolicyComplianceServiceDefinition {
        &self.definition
    }

    pub fn read(
        &mut self,
        request: &AzurePolicyReadRequest,
    ) -> Result<AzurePolicyEvidence, AzurePolicyComplianceServiceError> {
        self.ensure_active()?;
        let query = AzurePolicyQuery::compile(
            self.scope(),
            self.provider.secret_reference(),
            request.clone(),
        )?;
        self.provider.bind_query(&query)?;
        self.last_query = Some(query.clone());
        let evidence = self.read_query(&query);
        self.provider
            .bind_evidence(evidence.evidence_digest.clone())?;
        Ok(evidence)
    }

    pub fn propose(
        &mut self,
        request: &AzurePolicyReadRequest,
    ) -> Result<AzurePolicyComplianceProposal, AzurePolicyComplianceServiceError> {
        let evidence = self.read(request)?;
        self.propose_from_evidence(evidence)
    }

    pub fn compile_proposal(
        &mut self,
        request: &AzurePolicyReadRequest,
    ) -> Result<AzurePolicyComplianceProposal, AzurePolicyComplianceServiceError> {
        self.propose(request)
    }

    pub fn propose_from_evidence(
        &self,
        evidence: AzurePolicyEvidence,
    ) -> Result<AzurePolicyComplianceProposal, AzurePolicyComplianceServiceError> {
        self.ensure_active()?;
        if evidence.scope_digest != self.scope().scope_digest()
            || evidence.query_digest != self.registration().query_digest
        {
            return Err(AzurePolicyComplianceServiceError::EvidenceMismatch);
        }
        let query = self
            .last_query
            .as_ref()
            .ok_or(AzurePolicyComplianceServiceError::EvidenceMismatch)?
            .clone();
        if evidence.query_digest != *query.query_digest() {
            return Err(AzurePolicyComplianceServiceError::EvidenceMismatch);
        }
        evidence.validate(self.scope(), &query)?;
        let mut proposal = AzurePolicyComplianceProposal {
            query,
            evidence,
            registration_digest: self.registration().registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            contract_digest: crate::contract_digest(),
            proposal_only: true,
            native: false,
            connected: false,
            certification: false,
            outcome_authority: false,
            proposal_digest: Digest::from_text("proposal-unbound"),
        };
        proposal.proposal_digest = compute_proposal_digest(&proposal);
        Ok(proposal)
    }

    pub fn verify(
        &self,
        proposal: &AzurePolicyComplianceProposal,
    ) -> Result<(), AzurePolicyComplianceServiceError> {
        self.verify_proposal(proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &AzurePolicyComplianceProposal,
    ) -> Result<(), AzurePolicyComplianceServiceError> {
        self.ensure_active()?;
        if !proposal.proposal_only
            || proposal.native
            || proposal.connected
            || proposal.certification
            || proposal.outcome_authority
            || proposal.registration_digest != self.registration().registration_digest
            || proposal.provider_digest != self.provider.provider_digest()
            || proposal.contract_digest != crate::contract_digest()
            || proposal.query.scope_digest() != &self.scope().scope_digest()
            || proposal.evidence.scope_digest != self.scope().scope_digest()
            || proposal.evidence.query_digest != *proposal.query.query_digest()
            || proposal.evidence.evidence_digest != self.registration().evidence_digest
            || proposal.query.query_digest != self.registration().query_digest
            || proposal.proposal_digest != compute_proposal_digest(proposal)
        {
            return Err(AzurePolicyComplianceServiceError::EvidenceMismatch);
        }
        proposal.evidence.validate(self.scope(), &proposal.query)
    }

    pub fn record(
        &self,
        proposal: &AzurePolicyComplianceProposal,
    ) -> Result<AzurePolicyObservationReceipt, AzurePolicyComplianceServiceError> {
        self.verify_proposal(proposal)?;
        Ok(AzurePolicyObservationReceipt {
            scope_digest: proposal.evidence.scope_digest.clone(),
            query_digest: proposal.evidence.query_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            provenance: self.provider.definition().provenance,
            read_only: true,
            durable_native_receipt: false,
            independent_readback: false,
            certification: false,
            outcome_authority: false,
        })
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<crate::RegistrationRevocation, AzurePolicyComplianceServiceError> {
        Ok(self.provider.revoke_registration()?)
    }

    pub fn restore_registration(&mut self) -> Result<(), AzurePolicyComplianceServiceError> {
        Ok(self.provider.restore_registration()?)
    }

    pub fn revoke_secret(&mut self) -> Result<(), AzurePolicyComplianceServiceError> {
        Ok(self.provider.revoke_secret()?)
    }

    fn ensure_active(&self) -> Result<(), AzurePolicyComplianceServiceError> {
        if self.registration().state != RegistrationState::Active {
            Err(AzurePolicyComplianceServiceError::RegistrationRevoked)
        } else if self.provider.secret_reference().is_revoked() {
            Err(AzurePolicyComplianceServiceError::SecretRevoked)
        } else {
            Ok(())
        }
    }

    fn read_query(&mut self, query: &AzurePolicyQuery) -> AzurePolicyEvidence {
        let fence = query.permission_fence(self.scope());
        let provenance = self.provider.definition().provenance;
        let mut records = Vec::new();
        let mut page_digests = Vec::new();
        let mut next_link_digests = Vec::new();
        let mut response_digests = Vec::new();
        let mut provider_errors = Vec::new();
        let mut response_bytes: usize = 0;
        let mut pages_observed: u8 = 0;
        let mut next_link = None;
        let mut visited_next_links = BTreeSet::new();

        for page_number in 1..=query.bounds.max_pages {
            let page = match self
                .provider
                .read_page(query, next_link.as_ref(), page_number)
            {
                Ok(page) => page,
                Err(error) => {
                    provider_errors.push(provider_error_evidence(&error));
                    break;
                }
            };
            if page.scope_digest != *query.scope_digest()
                || page.query_digest != *query.query_digest()
                || page.partial
            {
                provider_errors.push(ProviderErrorEvidence {
                    kind: if page.partial {
                        ProviderErrorKind::PartialPage
                    } else {
                        ProviderErrorKind::Tampered
                    },
                    status_code: Some(200),
                    retryable: false,
                    blocked_env: false,
                    error_digest: Digest::from_text("page-fence"),
                });
                break;
            }
            pages_observed = pages_observed.saturating_add(1);
            response_bytes = response_bytes.saturating_add(page.response_bytes);
            page_digests.push(page.page_digest.clone());
            response_digests.push(page.response_digest.clone());
            if let Some(next_link_digest) = page.next_link_digest() {
                next_link_digests.push(next_link_digest.clone());
            }
            if records.len().saturating_add(page.records.len()) > query.bounds.max_records {
                provider_errors.push(ProviderErrorEvidence {
                    kind: ProviderErrorKind::Truncated,
                    status_code: Some(200),
                    retryable: false,
                    blocked_env: false,
                    error_digest: Digest::from_text("record-bound"),
                });
                break;
            }
            next_link = page.next_link().cloned();
            records.extend(page.records);
            let Some(link) = next_link.as_ref() else {
                break;
            };
            if !visited_next_links.insert(link.digest()) {
                provider_errors.push(ProviderErrorEvidence {
                    kind: ProviderErrorKind::NextLinkReplay,
                    status_code: Some(200),
                    retryable: false,
                    blocked_env: false,
                    error_digest: Digest::from_text("next-link-replay"),
                });
                break;
            }
            if page_number == query.bounds.max_pages {
                provider_errors.push(ProviderErrorEvidence {
                    kind: ProviderErrorKind::Truncated,
                    status_code: Some(200),
                    retryable: false,
                    blocked_env: false,
                    error_digest: Digest::from_text("page-bound"),
                });
                break;
            }
        }
        let status = status_from_errors(&provider_errors);
        let summary = summary_for(&records);
        let response_digest = Digest::from_fields(
            "azure-policy-response-set/v1",
            &response_digests
                .iter()
                .map(|value| value.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        let mut evidence = AzurePolicyEvidence {
            scope_digest: fence.scope_digest.clone(),
            query_digest: query.query_digest.clone(),
            permission_fence: PermissionFenceReceipt::from(&fence),
            project_id: self.scope().project().id.clone(),
            mission_id: self.scope().mission().id.clone(),
            work_product_id: self.scope().work_product().id.clone(),
            status,
            summary,
            records,
            pages_observed,
            response_bytes,
            page_digests,
            next_link_digests,
            response_digest,
            provider_errors,
            provenance,
            provider_reported_only: true,
            certification: false,
            outcome_authority: false,
            evidence_digest: Digest::from_text("evidence-unbound"),
        };
        evidence.evidence_digest = compute_evidence_digest(&evidence);
        evidence
    }
}

fn provider_error_evidence(error: &AzurePolicyProviderError) -> ProviderErrorEvidence {
    ProviderErrorEvidence {
        kind: error.kind,
        status_code: error.status_code,
        retryable: error.retryable,
        blocked_env: error.blocked_env,
        error_digest: error.error_digest.clone(),
    }
}

fn status_from_errors(errors: &[ProviderErrorEvidence]) -> EvidenceStatus {
    let Some(error) = errors.first() else {
        return EvidenceStatus::Complete;
    };
    match error.kind {
        ProviderErrorKind::Unauthenticated | ProviderErrorKind::PermissionDenied => {
            EvidenceStatus::AccessLost
        }
        ProviderErrorKind::BadRequest
        | ProviderErrorKind::Conflict
        | ProviderErrorKind::ScopeMismatch
        | ProviderErrorKind::NextLinkScopeMismatch
        | ProviderErrorKind::NextLinkReplay
        | ProviderErrorKind::PartialPage
        | ProviderErrorKind::QueryDrift
        | ProviderErrorKind::Tampered
        | ProviderErrorKind::Truncated => EvidenceStatus::FinalError,
        ProviderErrorKind::NotFound
        | ProviderErrorKind::RateLimited
        | ProviderErrorKind::ServerFailure
        | ProviderErrorKind::Timeout
        | ProviderErrorKind::BlockedEnv
        | ProviderErrorKind::Revoked
        | ProviderErrorKind::Unknown => EvidenceStatus::ProviderUnknown,
    }
}

fn summary_for(records: &[PolicyStateRecord]) -> ComplianceSummary {
    if records.is_empty() {
        return ComplianceSummary::Unknown;
    }
    let states = records
        .iter()
        .map(|record| record.compliance_state)
        .collect::<BTreeSet<_>>();
    if states.contains(&ComplianceState::NonCompliant) {
        ComplianceSummary::NonCompliant
    } else if states.contains(&ComplianceState::Unknown) || states.len() > 1 {
        ComplianceSummary::Unknown
    } else if states.contains(&ComplianceState::Exempt) {
        ComplianceSummary::Exempt
    } else {
        ComplianceSummary::Compliant
    }
}

fn compute_evidence_digest(evidence: &AzurePolicyEvidence) -> Digest {
    let record_digests = evidence
        .records
        .iter()
        .map(PolicyStateRecord::digest)
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>();
    let page_digests = evidence
        .page_digests
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>();
    let next_link_digests = evidence
        .next_link_digests
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>();
    let error_digests = evidence
        .provider_errors
        .iter()
        .map(|value| value.error_digest.as_str().to_owned())
        .collect::<Vec<_>>();
    Digest::from_fields(
        "azure-policy-evidence/v1",
        &[
            evidence.scope_digest.as_str().to_owned(),
            evidence.query_digest.as_str().to_owned(),
            evidence
                .permission_fence
                .permission_digest
                .as_str()
                .to_owned(),
            evidence.project_id.as_str().to_owned(),
            evidence.mission_id.as_str().to_owned(),
            evidence.work_product_id.as_str().to_owned(),
            format!("{:?}", evidence.status),
            format!("{:?}", evidence.summary),
            record_digests.join(","),
            evidence.pages_observed.to_string(),
            evidence.response_bytes.to_string(),
            page_digests.join(","),
            next_link_digests.join(","),
            evidence.response_digest.as_str().to_owned(),
            error_digests.join(","),
            format!("{:?}", evidence.provenance),
            evidence.provider_reported_only.to_string(),
            evidence.certification.to_string(),
            evidence.outcome_authority.to_string(),
        ],
    )
}

fn compute_proposal_digest(proposal: &AzurePolicyComplianceProposal) -> Digest {
    Digest::from_fields(
        "azure-policy-proposal/v1",
        &[
            proposal.query.query_digest.as_str().to_owned(),
            proposal.evidence.evidence_digest.as_str().to_owned(),
            proposal.registration_digest.as_str().to_owned(),
            proposal.provider_digest.as_str().to_owned(),
            proposal.contract_digest.as_str().to_owned(),
            proposal.proposal_only.to_string(),
            proposal.native.to_string(),
            proposal.connected.to_string(),
            proposal.certification.to_string(),
            proposal.outcome_authority.to_string(),
        ],
    )
}
