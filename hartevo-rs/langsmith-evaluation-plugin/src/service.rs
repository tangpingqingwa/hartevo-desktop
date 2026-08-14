use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    Digest, canonical_digest,
    model::{
        EvaluationReceiptCandidate, EvaluationResultProposal, EvidenceStatus,
        LangSmithEvaluationError, LangSmithEvaluationEvidence, LangSmithEvaluationPage,
        LangSmithEvaluationPolicy, LangSmithEvaluationReadRequest, LangSmithEvaluationScope,
        LangSmithPluginRegistration, LangSmithProviderError, PluginVersion,
    },
    provider::{EvidenceSource, LangSmithProvider, LangSmithProviderManifest, NativeStatus},
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LangSmithEvaluationServiceConfig {
    pub policy: LangSmithEvaluationPolicy,
    pub default_as_of_ms: u64,
}

impl LangSmithEvaluationServiceConfig {
    #[must_use]
    pub fn fixture() -> Self {
        Self {
            policy: LangSmithEvaluationPolicy::fixture(),
            default_as_of_ms: 10_000,
        }
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        self.policy.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LangSmithCapabilities {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: PluginVersion,
    pub service_id: String,
    pub provider_id: String,
    pub source: EvidenceSource,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub arbitrary_trace_export: bool,
    pub tool_execution: bool,
    pub generic_telemetry: bool,
    pub model_registry: bool,
    pub operations: Vec<String>,
    pub secret_reference_required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LangSmithReadProposal {
    pub scope: LangSmithEvaluationScope,
    pub page_size: u16,
    pub as_of_ms: u64,
    pub registration_digest: Digest,
    pub provider_manifest_digest: Digest,
    pub external_write: bool,
    pub connected: bool,
    pub native: bool,
    pub request_digest: Digest,
}

impl LangSmithReadProposal {
    fn new(
        request: &LangSmithEvaluationReadRequest,
        registration: &LangSmithPluginRegistration,
        manifest: &LangSmithProviderManifest,
    ) -> Self {
        let mut proposal = Self {
            scope: request.scope.clone(),
            page_size: request.page_size,
            as_of_ms: request.as_of_ms,
            registration_digest: registration.registration_digest.clone(),
            provider_manifest_digest: manifest.manifest_digest.clone(),
            external_write: false,
            connected: false,
            native: false,
            request_digest: Digest::from_text("uninitialized-read-proposal"),
        };
        proposal.request_digest = canonical_digest(&ReadProposalIdentity {
            scope: proposal.scope.clone(),
            page_size: proposal.page_size,
            as_of_ms: proposal.as_of_ms,
            registration_digest: proposal.registration_digest.clone(),
            provider_manifest_digest: proposal.provider_manifest_digest.clone(),
            external_write: proposal.external_write,
            connected: proposal.connected,
            native: proposal.native,
        });
        proposal
    }

    pub fn validate(
        &self,
        registration: &LangSmithPluginRegistration,
        policy: &LangSmithEvaluationPolicy,
    ) -> Result<(), LangSmithEvaluationError> {
        registration.ensure_active()?;
        policy.validate()?;
        self.scope.validate()?;
        if self.scope.digest() != registration.scope.digest()
            || self.registration_digest != registration.registration_digest
            || self.external_write
            || self.connected
            || self.native
            || self.page_size == 0
            || self.page_size > policy.max_page_size
        {
            return Err(LangSmithEvaluationError::ProposalTampered);
        }
        self.provider_manifest_digest
            .validate("provider_manifest_digest")?;
        self.request_digest.validate("request_digest")?;
        let expected = canonical_digest(&ReadProposalIdentity {
            scope: self.scope.clone(),
            page_size: self.page_size,
            as_of_ms: self.as_of_ms,
            registration_digest: self.registration_digest.clone(),
            provider_manifest_digest: self.provider_manifest_digest.clone(),
            external_write: self.external_write,
            connected: self.connected,
            native: self.native,
        });
        if self.request_digest != expected {
            return Err(LangSmithEvaluationError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ReadProposalIdentity {
    scope: LangSmithEvaluationScope,
    page_size: u16,
    as_of_ms: u64,
    registration_digest: Digest,
    provider_manifest_digest: Digest,
    external_write: bool,
    connected: bool,
    native: bool,
}

/// The typed service that owns bounded read, pagination, proposal, and
/// verification orchestration. It never owns an external effect authority.
#[derive(Clone, Debug)]
pub struct LangSmithEvaluationService {
    provider: LangSmithProvider,
    config: LangSmithEvaluationServiceConfig,
}

impl LangSmithEvaluationService {
    pub fn new(provider: LangSmithProvider) -> Result<Self, LangSmithEvaluationError> {
        Self::with_config(provider, LangSmithEvaluationServiceConfig::fixture())
    }

    pub fn with_config(
        provider: LangSmithProvider,
        config: LangSmithEvaluationServiceConfig,
    ) -> Result<Self, LangSmithEvaluationError> {
        config.validate()?;
        let registration = provider.registration();
        registration.ensure_active()?;
        provider.provider_manifest().validate(&registration)?;
        Ok(Self { provider, config })
    }

    #[must_use]
    pub fn provider(&self) -> LangSmithProvider {
        self.provider.clone()
    }

    #[must_use]
    pub fn registration(&self) -> LangSmithPluginRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn policy(&self) -> &LangSmithEvaluationPolicy {
        &self.config.policy
    }

    pub fn describe_capabilities(&self) -> Result<LangSmithCapabilities, LangSmithEvaluationError> {
        let manifest = self.provider.describe_capabilities()?;
        let authentication = self.provider.authentication_plan()?;
        Ok(LangSmithCapabilities {
            schema_version: String::from(crate::LANGSMITH_EVALUATION_SCHEMA_VERSION),
            contract_version: String::from(crate::LANGSMITH_EVALUATION_CONTRACT_VERSION),
            plugin_version: PluginVersion::V1,
            service_id: String::from(crate::LANGSMITH_EVALUATION_SERVICE_ID),
            provider_id: manifest.provider_id,
            source: manifest.evidence_source,
            native_status: manifest.native_status,
            connected: false,
            native: false,
            external_writes: false,
            arbitrary_trace_export: false,
            tool_execution: false,
            generic_telemetry: false,
            model_registry: false,
            operations: vec![
                String::from("describe_capabilities"),
                String::from("compile_bounded_read_proposal"),
                String::from("read_run_summaries"),
                String::from("read_trace_summary"),
                String::from("read_dataset_revision"),
                String::from("read_evaluator_revision"),
                String::from("read_feedback_scores"),
                String::from("read_experiment_evidence"),
                String::from("paginate_bounded_evaluation"),
                String::from("compile_evaluation_result_proposal"),
                String::from("verify_evaluation_result_proposal"),
            ],
            secret_reference_required: authentication.required,
        })
    }

    pub fn compile_bounded_read_proposal(
        &self,
        scope: LangSmithEvaluationScope,
        page_size: u16,
        as_of_ms: Option<u64>,
    ) -> Result<LangSmithReadProposal, LangSmithEvaluationError> {
        let request = LangSmithEvaluationReadRequest::new(
            scope,
            page_size,
            as_of_ms.unwrap_or(self.config.default_as_of_ms),
        )?;
        request.validate(&self.config.policy)?;
        let registration = self.ensure_registration()?;
        if request.scope.digest() != registration.scope.digest() {
            return Err(LangSmithEvaluationError::ScopeMismatch);
        }
        let manifest = self.provider.provider_manifest();
        manifest.validate(&registration)?;
        let proposal = LangSmithReadProposal::new(&request, &registration, &manifest);
        proposal.validate(&registration, &self.config.policy)?;
        Ok(proposal)
    }

    pub fn read_page(
        &self,
        request: &LangSmithEvaluationReadRequest,
    ) -> Result<LangSmithEvaluationPage, LangSmithEvaluationError> {
        request.validate(&self.config.policy)?;
        let registration = self.ensure_registration()?;
        Self::ensure_request_binding(request, &registration)?;
        let page = self.provider.read_evaluation(request)?;
        page.validate(&self.config.policy)?;
        Self::ensure_page_binding(&page, &request.scope)?;
        if request.as_of_ms >= page.observed_at_ms
            && request.as_of_ms.saturating_sub(page.observed_at_ms) > self.config.policy.max_age_ms
        {
            return Err(LangSmithEvaluationError::StaleResult);
        }
        Ok(page)
    }

    pub fn read(
        &self,
        request: &LangSmithEvaluationReadRequest,
    ) -> Result<LangSmithEvaluationPage, LangSmithEvaluationError> {
        self.read_page(request)
    }

    pub fn paginate(
        &self,
        request: LangSmithEvaluationReadRequest,
    ) -> Result<LangSmithEvaluationEvidence, LangSmithEvaluationError> {
        request.validate(&self.config.policy)?;
        let mut pages = Vec::new();
        let mut current = request;
        let mut seen_cursors = BTreeSet::new();
        for _ in 0..self.config.policy.max_pages {
            let page = self.read_page(&current)?;
            let next_cursor = page.next_cursor.clone();
            pages.push(page);
            let Some(cursor) = next_cursor else {
                break;
            };
            if !seen_cursors.insert(cursor.cursor_digest.clone()) {
                return Err(LangSmithEvaluationError::CursorLoop);
            }
            current = current.next_page(cursor)?;
        }
        if pages
            .last()
            .and_then(|page| page.next_cursor.as_ref())
            .is_some()
        {
            return Err(LangSmithEvaluationError::BoundExceeded {
                field: "evaluation_pages",
                maximum: self.config.policy.max_pages as usize,
            });
        }
        let status = if pages
            .iter()
            .any(|page| page.status == EvidenceStatus::Partial)
        {
            EvidenceStatus::Partial
        } else if pages
            .iter()
            .all(|page| page.runs.is_empty() && page.traces.is_empty() && page.feedback.is_empty())
        {
            EvidenceStatus::Empty
        } else {
            EvidenceStatus::Present
        };
        let evidence =
            LangSmithEvaluationEvidence::from_pages(current.scope.clone(), &pages, status, false)?;
        evidence.validate(&self.config.policy)?;
        Ok(evidence)
    }

    pub fn propose_evaluation(
        &self,
        request: LangSmithEvaluationReadRequest,
    ) -> Result<EvaluationResultProposal, LangSmithEvaluationError> {
        let evidence = self.paginate(request)?;
        let registration = self.ensure_registration()?;
        let manifest = self.provider.provider_manifest();
        manifest.validate(&registration)?;
        let proposal = EvaluationResultProposal::new(
            &registration,
            manifest.manifest_digest.clone(),
            evidence,
            self.config.default_as_of_ms,
        );
        proposal.validate(&registration, &self.config.policy)?;
        Ok(proposal)
    }

    pub fn propose(
        &self,
        request: LangSmithEvaluationReadRequest,
    ) -> Result<EvaluationResultProposal, LangSmithEvaluationError> {
        self.propose_evaluation(request)
    }

    pub fn verify_proposal(
        &self,
        proposal: &EvaluationResultProposal,
    ) -> Result<(), LangSmithEvaluationError> {
        let registration = self.ensure_registration()?;
        let manifest = self.provider.provider_manifest();
        manifest.validate(&registration)?;
        if proposal.provider_manifest_digest != manifest.manifest_digest {
            return Err(LangSmithEvaluationError::ProviderManifestDrift);
        }
        proposal.validate(&registration, &self.config.policy)
    }

    pub fn receipt_candidate(
        &self,
        proposal: &EvaluationResultProposal,
    ) -> Result<EvaluationReceiptCandidate, LangSmithEvaluationError> {
        self.verify_proposal(proposal)?;
        Ok(EvaluationReceiptCandidate::from_proposal(proposal))
    }

    pub fn revoke(
        &self,
        reason: &str,
    ) -> Result<crate::RegistrationRevocation, LangSmithEvaluationError> {
        self.provider.revoke(reason)
    }

    fn ensure_registration(&self) -> Result<LangSmithPluginRegistration, LangSmithEvaluationError> {
        let registration = self.provider.registration();
        registration.ensure_active()?;
        self.provider.provider_manifest().validate(&registration)?;
        Ok(registration)
    }

    fn ensure_request_binding(
        request: &LangSmithEvaluationReadRequest,
        registration: &LangSmithPluginRegistration,
    ) -> Result<(), LangSmithEvaluationError> {
        if request.scope.digest() != registration.scope.digest() {
            return Err(LangSmithEvaluationError::ScopeMismatch);
        }
        if request.scope.permission_revision != registration.permission.revision {
            return Err(LangSmithEvaluationError::PermissionDrift);
        }
        Ok(())
    }

    fn ensure_page_binding(
        page: &LangSmithEvaluationPage,
        scope: &LangSmithEvaluationScope,
    ) -> Result<(), LangSmithEvaluationError> {
        if page.scope_digest != *scope.digest() {
            return Err(LangSmithEvaluationError::ScopeMismatch);
        }
        if page.dataset.dataset_id != scope.dataset {
            return Err(LangSmithEvaluationError::DatasetRevisionDrift);
        }
        if page.dataset.revision != scope.dataset_revision {
            return Err(LangSmithEvaluationError::DatasetRevisionDrift);
        }
        if page.evaluator.evaluator_id != scope.evaluator
            || page.evaluator.revision != scope.evaluator_revision
        {
            return Err(LangSmithEvaluationError::EvaluatorMismatch);
        }
        if page.experiment.experiment_id != scope.experiment
            || page.experiment.experiment_revision != scope.experiment_revision
        {
            return Err(LangSmithEvaluationError::ExperimentRevisionDrift);
        }
        if page.experiment.dataset_id != scope.dataset
            || page.experiment.dataset_revision != scope.dataset_revision
        {
            return Err(LangSmithEvaluationError::DatasetRevisionDrift);
        }
        if page.experiment.evaluator_id != scope.evaluator
            || page.experiment.evaluator_revision != scope.evaluator_revision
        {
            return Err(LangSmithEvaluationError::EvaluatorMismatch);
        }
        for run in &page.runs {
            if run.project_id != scope.project || run.project_revision != scope.project_revision {
                return Err(LangSmithEvaluationError::ProjectRevisionDrift);
            }
            if run.run_id != scope.run {
                return Err(LangSmithEvaluationError::RunMismatch);
            }
            if run.trace_id != scope.trace {
                return Err(LangSmithEvaluationError::TraceMismatch);
            }
        }
        for trace in &page.traces {
            if trace.project_id != scope.project || trace.project_revision != scope.project_revision
            {
                return Err(LangSmithEvaluationError::ProjectRevisionDrift);
            }
            if trace.trace_id != scope.trace {
                return Err(LangSmithEvaluationError::TraceMismatch);
            }
            if trace.root_run_id != scope.run {
                return Err(LangSmithEvaluationError::RunMismatch);
            }
        }
        for feedback in &page.feedback {
            if feedback.run_id != scope.run || feedback.trace_id != scope.trace {
                return Err(LangSmithEvaluationError::RunMismatch);
            }
            if feedback.evaluator_id != scope.evaluator
                || feedback.evaluator_revision != scope.evaluator_revision
            {
                return Err(LangSmithEvaluationError::EvaluatorMismatch);
            }
        }
        Ok(())
    }
}

impl From<LangSmithProviderError> for LangSmithEvaluationError {
    fn from(error: LangSmithProviderError) -> Self {
        match error {
            LangSmithProviderError::BlockedEnv => {
                Self::Provider(LangSmithProviderError::BlockedEnv)
            }
            LangSmithProviderError::RegistrationRevoked => Self::RegistrationRevoked,
            LangSmithProviderError::DatasetRevisionDrift => Self::DatasetRevisionDrift,
            LangSmithProviderError::EvaluatorRevisionDrift => Self::EvaluatorMismatch,
            LangSmithProviderError::ExperimentRevisionDrift => Self::ExperimentRevisionDrift,
            LangSmithProviderError::PermissionDrift => Self::PermissionDrift,
            LangSmithProviderError::ProjectRevisionDrift => Self::ProjectRevisionDrift,
            LangSmithProviderError::ScopeMismatch => Self::ScopeMismatch,
            LangSmithProviderError::StaleResult => Self::StaleResult,
            other => Self::Provider(other),
        }
    }
}
