use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::filter::MlflowFilter;
use crate::model::{
    AdoptionAvailability, DatasetDigest, Digest, EvidenceDigests, ExperimentId, ExperimentRecord,
    MAX_METRICS, MetricHistoryPoint, MetricKey, MlflowOperation, MlflowRegistration, MlflowScope,
    ModelError, OpaquePageToken, PartialReason, ProviderErrorEvidence, ProviderErrorKind,
    ProviderProvenance, RegistrationRevocation, ResultBounds, ResultStatus, RetryEvidence,
    Revision, RunId, RunRecord, ScopeRevisions, SecretReference,
};
use crate::provider::{
    MlflowProvider, MlflowProviderDefinition, MlflowResponsePage, TransportError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MlflowReadRequest {
    SearchExperiments {
        filter: MlflowFilter,
        bounds: ResultBounds,
        work_product_revision: Revision,
        page_token: Option<OpaquePageToken>,
    },
    GetExperiment {
        experiment_id: ExperimentId,
        bounds: ResultBounds,
        work_product_revision: Revision,
    },
    SearchRuns {
        experiment_ids: Vec<ExperimentId>,
        filter: MlflowFilter,
        bounds: ResultBounds,
        work_product_revision: Revision,
        page_token: Option<OpaquePageToken>,
    },
    GetRun {
        run_id: RunId,
        bounds: ResultBounds,
        work_product_revision: Revision,
    },
    MetricHistory {
        run_id: RunId,
        metric: MetricKey,
        bounds: ResultBounds,
        work_product_revision: Revision,
        page_token: Option<OpaquePageToken>,
    },
}

impl MlflowReadRequest {
    pub fn search_experiments(
        filter: MlflowFilter,
        bounds: ResultBounds,
        work_product_revision: Revision,
    ) -> Self {
        Self::SearchExperiments {
            filter,
            bounds,
            work_product_revision,
            page_token: None,
        }
    }

    pub fn get_experiment(
        experiment_id: ExperimentId,
        bounds: ResultBounds,
        work_product_revision: Revision,
    ) -> Self {
        Self::GetExperiment {
            experiment_id,
            bounds,
            work_product_revision,
        }
    }

    pub fn search_runs(
        experiment_ids: impl IntoIterator<Item = ExperimentId>,
        filter: MlflowFilter,
        bounds: ResultBounds,
        work_product_revision: Revision,
    ) -> Self {
        Self::SearchRuns {
            experiment_ids: experiment_ids.into_iter().collect(),
            filter,
            bounds,
            work_product_revision,
            page_token: None,
        }
    }

    pub fn get_run(run_id: RunId, bounds: ResultBounds, work_product_revision: Revision) -> Self {
        Self::GetRun {
            run_id,
            bounds,
            work_product_revision,
        }
    }

    pub fn metric_history(
        run_id: RunId,
        metric: MetricKey,
        bounds: ResultBounds,
        work_product_revision: Revision,
    ) -> Self {
        Self::MetricHistory {
            run_id,
            metric,
            bounds,
            work_product_revision,
            page_token: None,
        }
    }

    #[must_use]
    pub fn with_page_token(self, page_token: OpaquePageToken) -> Self {
        match self {
            Self::SearchExperiments {
                filter,
                bounds,
                work_product_revision,
                ..
            } => Self::SearchExperiments {
                filter,
                bounds,
                work_product_revision,
                page_token: Some(page_token),
            },
            Self::SearchRuns {
                experiment_ids,
                filter,
                bounds,
                work_product_revision,
                ..
            } => Self::SearchRuns {
                experiment_ids,
                filter,
                bounds,
                work_product_revision,
                page_token: Some(page_token),
            },
            Self::MetricHistory {
                run_id,
                metric,
                bounds,
                work_product_revision,
                ..
            } => Self::MetricHistory {
                run_id,
                metric,
                bounds,
                work_product_revision,
                page_token: Some(page_token),
            },
            request => request,
        }
    }

    pub fn operation(&self) -> MlflowOperation {
        match self {
            Self::SearchExperiments { .. } => MlflowOperation::SearchExperiments,
            Self::GetExperiment { .. } => MlflowOperation::GetExperiment,
            Self::SearchRuns { .. } => MlflowOperation::SearchRuns,
            Self::GetRun { .. } => MlflowOperation::GetRun,
            Self::MetricHistory { .. } => MlflowOperation::GetMetricHistory,
        }
    }

    pub fn bounds(&self) -> ResultBounds {
        match self {
            Self::SearchExperiments { bounds, .. }
            | Self::GetExperiment { bounds, .. }
            | Self::SearchRuns { bounds, .. }
            | Self::GetRun { bounds, .. }
            | Self::MetricHistory { bounds, .. } => *bounds,
        }
    }

    pub fn work_product_revision(&self) -> Revision {
        match self {
            Self::SearchExperiments {
                work_product_revision,
                ..
            }
            | Self::GetExperiment {
                work_product_revision,
                ..
            }
            | Self::SearchRuns {
                work_product_revision,
                ..
            }
            | Self::GetRun {
                work_product_revision,
                ..
            }
            | Self::MetricHistory {
                work_product_revision,
                ..
            } => *work_product_revision,
        }
    }

    fn initial_page_token(&self) -> Option<&OpaquePageToken> {
        match self {
            Self::SearchExperiments { page_token, .. }
            | Self::SearchRuns { page_token, .. }
            | Self::MetricHistory { page_token, .. } => page_token.as_ref(),
            Self::GetExperiment { .. } | Self::GetRun { .. } => None,
        }
    }

    fn filter(&self) -> Option<&MlflowFilter> {
        match self {
            Self::SearchExperiments { filter, .. } | Self::SearchRuns { filter, .. } => {
                Some(filter)
            }
            _ => None,
        }
    }

    fn digest_fields(&self) -> Vec<String> {
        let mut fields = vec![format!("{:?}", self.operation())];
        match self {
            Self::SearchExperiments {
                filter,
                bounds,
                work_product_revision,
                page_token,
            } => {
                fields.push(filter.digest().as_str().to_owned());
                fields.push(work_product_revision.get().to_string());
                fields.push(bounds_digest(*bounds));
                push_page_digest(&mut fields, page_token.as_ref());
            }
            Self::GetExperiment {
                experiment_id,
                bounds,
                work_product_revision,
            } => {
                fields.push(experiment_id.as_str().to_owned());
                fields.push(work_product_revision.get().to_string());
                fields.push(bounds_digest(*bounds));
            }
            Self::SearchRuns {
                experiment_ids,
                filter,
                bounds,
                work_product_revision,
                page_token,
            } => {
                fields.extend(experiment_ids.iter().map(|id| id.as_str().to_owned()));
                fields.push(filter.digest().as_str().to_owned());
                fields.push(work_product_revision.get().to_string());
                fields.push(bounds_digest(*bounds));
                push_page_digest(&mut fields, page_token.as_ref());
            }
            Self::GetRun {
                run_id,
                bounds,
                work_product_revision,
            } => {
                fields.push(run_id.as_str().to_owned());
                fields.push(work_product_revision.get().to_string());
                fields.push(bounds_digest(*bounds));
            }
            Self::MetricHistory {
                run_id,
                metric,
                bounds,
                work_product_revision,
                page_token,
            } => {
                fields.push(run_id.as_str().to_owned());
                fields.push(metric.as_str().to_owned());
                fields.push(work_product_revision.get().to_string());
                fields.push(bounds_digest(*bounds));
                push_page_digest(&mut fields, page_token.as_ref());
            }
        }
        fields
    }
}

fn push_page_digest(fields: &mut Vec<String>, page_token: Option<&OpaquePageToken>) {
    fields.push(page_token.map_or_else(
        || "none".to_owned(),
        |token| token.digest().as_str().to_owned(),
    ));
}

fn bounds_digest(bounds: ResultBounds) -> String {
    Digest::from_fields(
        "mlflow-bounds/v1",
        &[
            bounds.max_experiments().to_string(),
            bounds.max_runs().to_string(),
            bounds.max_metric_history().to_string(),
            bounds.max_pages().to_string(),
            bounds.page_size().to_string(),
            bounds.max_response_bytes().to_string(),
        ],
    )
    .as_str()
    .to_owned()
}

#[derive(Clone, Eq, PartialEq)]
pub struct MlflowReadProposal {
    request: MlflowReadRequest,
    operation: MlflowOperation,
    scope_digest: Digest,
    version_digest: Digest,
    provider_digest: Digest,
    contract_digest: Digest,
    query_digest: Digest,
    config_digest: Digest,
    permission_digest: Digest,
    consent_digest: Digest,
    revisions: ScopeRevisions,
    secret_reference_digest: Digest,
    credential_revision: Revision,
    provider_version: String,
    proposal_digest: Digest,
}

impl fmt::Debug for MlflowReadProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlflowReadProposal")
            .field("operation", &self.operation)
            .field("scope_digest", &self.scope_digest)
            .field("version_digest", &self.version_digest)
            .field("provider_digest", &self.provider_digest)
            .field("contract_digest", &self.contract_digest)
            .field("query_digest", &self.query_digest)
            .field("config_digest", &self.config_digest)
            .field("permission_digest", &self.permission_digest)
            .field("consent_digest", &self.consent_digest)
            .field("revisions", &self.revisions)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("credential_revision", &self.credential_revision)
            .field("provider_version", &self.provider_version)
            .field("proposal_digest", &self.proposal_digest)
            .finish_non_exhaustive()
    }
}

impl MlflowReadProposal {
    #[allow(clippy::too_many_arguments)]
    fn new(
        scope: &MlflowScope,
        secret: &SecretReference,
        provider: &MlflowProviderDefinition,
        request: MlflowReadRequest,
    ) -> Result<Self, ServiceError> {
        validate_request(scope, &request)?;
        if secret.scope_digest() != &scope.scope_digest() || secret.is_revoked() {
            return Err(ServiceError::SecretInvalid);
        }
        let operation = request.operation();
        let scope_digest = scope.scope_digest();
        let contract_digest = Digest::from_text(crate::MLFLOW_EVALUATION_RESULT_CONTRACT_JSON);
        let version_digest = Digest::from_fields(
            "mlflow-version/v1",
            &[
                crate::MLFLOW_EVALUATION_RESULT_SCHEMA_VERSION.to_owned(),
                crate::MLFLOW_EVALUATION_RESULT_CONTRACT_VERSION.to_owned(),
                crate::MLFLOW_EVALUATION_RESULT_SERVICE_VERSION.to_owned(),
                provider.provider_version.clone(),
            ],
        );
        let query_digest = Digest::from_fields("mlflow-query/v1", &request.digest_fields());
        let config_digest = Digest::from_fields(
            "mlflow-config/v1",
            &[
                operation_name(operation).to_owned(),
                scope.tracking_server_digest().as_str().to_owned(),
                provider.provider_version.clone(),
                provider.provenance.as_str().to_owned(),
                request.bounds().max_pages().to_string(),
                request.bounds().page_size().to_string(),
                request.bounds().max_response_bytes().to_string(),
            ],
        );
        let proposal_digest = Digest::from_fields(
            "mlflow-read-proposal/v1",
            &[
                scope_digest.as_str().to_owned(),
                version_digest.as_str().to_owned(),
                provider.provider_digest.as_str().to_owned(),
                contract_digest.as_str().to_owned(),
                query_digest.as_str().to_owned(),
                config_digest.as_str().to_owned(),
                scope.permission_digest().as_str().to_owned(),
                scope.consent_digest().as_str().to_owned(),
                secret.reference_digest().as_str().to_owned(),
                secret.credential_revision().get().to_string(),
                scope.revisions().experiment.get().to_string(),
                scope.revisions().run.get().to_string(),
                scope.revisions().dataset.get().to_string(),
                scope.revisions().mission.get().to_string(),
                scope.revisions().project.get().to_string(),
                scope.revisions().work_product.get().to_string(),
            ],
        );
        Ok(Self {
            request,
            operation,
            scope_digest,
            version_digest,
            provider_digest: provider.provider_digest.clone(),
            contract_digest,
            query_digest,
            config_digest,
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            revisions: scope.revisions(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            provider_version: provider.provider_version.clone(),
            proposal_digest,
        })
    }

    pub fn request(&self) -> &MlflowReadRequest {
        &self.request
    }

    pub const fn operation(&self) -> MlflowOperation {
        self.operation
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn version_digest(&self) -> &Digest {
        &self.version_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn config_digest(&self) -> &Digest {
        &self.config_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub const fn revisions(&self) -> ScopeRevisions {
        self.revisions
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn bounds(&self) -> ResultBounds {
        self.request.bounds()
    }

    fn initial_page_token(&self) -> Option<&OpaquePageToken> {
        self.request.initial_page_token()
    }
}

fn operation_name(operation: MlflowOperation) -> &'static str {
    match operation {
        MlflowOperation::SearchExperiments => "search_experiments",
        MlflowOperation::GetExperiment => "get_experiment",
        MlflowOperation::SearchRuns => "search_runs",
        MlflowOperation::GetRun => "get_run",
        MlflowOperation::GetMetricHistory => "get_metric_history",
    }
}

fn validate_request(scope: &MlflowScope, request: &MlflowReadRequest) -> Result<(), ServiceError> {
    if request.work_product_revision() != scope.revisions().work_product {
        return Err(ServiceError::RevisionMismatch);
    }
    if let Some(filter) = request.filter()
        && filter.scope_digest() != &scope.scope_digest()
    {
        return Err(ServiceError::ScopeMismatch);
    }
    match request {
        MlflowReadRequest::SearchExperiments { .. } => Ok(()),
        MlflowReadRequest::GetExperiment { experiment_id, .. } => {
            if scope.allows_experiment(experiment_id) {
                Ok(())
            } else {
                Err(ServiceError::ScopeMismatch)
            }
        }
        MlflowReadRequest::SearchRuns { experiment_ids, .. } => {
            if experiment_ids.iter().all(|id| scope.allows_experiment(id)) {
                Ok(())
            } else {
                Err(ServiceError::ScopeMismatch)
            }
        }
        MlflowReadRequest::GetRun { run_id, .. }
        | MlflowReadRequest::MetricHistory { run_id, .. } => {
            if scope.allows_run(run_id) {
                Ok(())
            } else {
                Err(ServiceError::ScopeMismatch)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error("MLflow registration is revoked")]
    RegistrationRevoked,
    #[error("MLflow SecretReference is invalid or revoked")]
    SecretInvalid,
    #[error("provider is not the governed MLflow provider")]
    ProviderMismatch,
    #[error("request is outside the governed MLflow scope")]
    ScopeMismatch,
    #[error("request revision does not match the Work Product scope")]
    RevisionMismatch,
    #[error("proposal does not match the active registration")]
    ProposalMismatch,
    #[error("provider page fence does not match the proposal")]
    FenceMismatch,
    #[error("provider page or evidence digest is invalid")]
    TamperedEvidence,
    #[error("provider page has an invalid shape for the requested operation")]
    InvalidResponseShape,
    #[error("provider page exceeds a governed bound")]
    BoundExceeded,
    #[error("provider returned a page with an invalid token")]
    InvalidPageToken,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RetryPolicy {
    pub max_attempts: u8,
}

impl RetryPolicy {
    pub fn new(max_attempts: u8) -> Result<Self, ServiceError> {
        if max_attempts == 0 || max_attempts > 5 {
            Err(ServiceError::BoundExceeded)
        } else {
            Ok(Self { max_attempts })
        }
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_attempts: 3 }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MlflowServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub service_version: String,
    pub evidence_level: String,
    pub read_only: bool,
    pub live_execution: bool,
}

impl Default for MlflowServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: crate::MLFLOW_EVALUATION_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: crate::MLFLOW_EVALUATION_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: crate::MLFLOW_EVALUATION_RESULT_SERVICE_ID.to_owned(),
            service_version: crate::MLFLOW_EVALUATION_RESULT_SERVICE_VERSION.to_owned(),
            evidence_level: crate::MLFLOW_EVALUATION_RESULT_EVIDENCE_LEVEL.to_owned(),
            read_only: true,
            live_execution: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MlflowEvidence {
    pub operation: MlflowOperation,
    pub status: ResultStatus,
    pub provider_provenance: ProviderProvenance,
    pub provider_version: String,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub revisions: ScopeRevisions,
    pub pages_observed: u8,
    pub response_bytes: u64,
    pub page_token_digests: Vec<Digest>,
    pub experiments: Vec<ExperimentRecord>,
    pub runs: Vec<RunRecord>,
    pub metric_history: Vec<MetricHistoryPoint>,
    pub dataset_digests: Vec<DatasetDigest>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub retries: Vec<RetryEvidence>,
    pub digests: EvidenceDigests,
}

impl MlflowEvidence {
    pub fn validate_digest(&self) -> Result<(), ServiceError> {
        for experiment in &self.experiments {
            experiment
                .validate_digest()
                .map_err(|_| ServiceError::TamperedEvidence)?;
        }
        for run in &self.runs {
            run.validate_digest()
                .map_err(|_| ServiceError::TamperedEvidence)?;
        }
        for point in &self.metric_history {
            point
                .validate_digest()
                .map_err(|_| ServiceError::TamperedEvidence)?;
        }
        let expected = EvidenceAccumulator::compute_digests(
            self.operation,
            self.status,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            self.revisions,
            &self.provider_version,
            &self.experiments,
            &self.runs,
            &self.metric_history,
            &self.dataset_digests,
            &self.provider_errors,
            &self.retries,
            &self.page_token_digests,
            self.pages_observed,
            self.response_bytes,
            &self.digests.query_digest,
            &self.digests.config_digest,
            &self.digests.version_digest,
            &self.digests.provider_digest,
            &self.digests.contract_digest,
            self.provider_provenance,
        );
        if expected != self.digests {
            Err(ServiceError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MlflowResultProposal {
    pub operation: MlflowOperation,
    pub status: ResultStatus,
    pub evidence: MlflowEvidence,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub proposal_digest: Digest,
    pub authority: crate::MlflowAuthority,
    pub adoption: AdoptionAvailability,
}

impl MlflowResultProposal {
    pub fn is_adopted(&self) -> bool {
        false
    }

    pub fn authority(&self) -> crate::MlflowAuthority {
        self.authority
    }
}

pub struct MlflowEvaluationResultService<P: MlflowProvider> {
    scope: MlflowScope,
    secret: SecretReference,
    provider: P,
    registration: MlflowRegistration,
    definition: MlflowServiceDefinition,
    retry_policy: RetryPolicy,
    active: bool,
}

impl<P: MlflowProvider> fmt::Debug for MlflowEvaluationResultService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlflowEvaluationResultService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret)
            .field("provider", self.provider.definition())
            .field("registration", &self.registration)
            .field("definition", &self.definition)
            .field("retry_policy", &self.retry_policy)
            .field("active", &self.active)
            .finish()
    }
}

impl<P: MlflowProvider> MlflowEvaluationResultService<P> {
    pub fn new(
        scope: MlflowScope,
        secret: SecretReference,
        provider: P,
        retry_policy: RetryPolicy,
    ) -> Result<Self, ServiceError> {
        if secret.scope_digest() != &scope.scope_digest() || secret.is_revoked() {
            return Err(ServiceError::SecretInvalid);
        }
        if provider.definition().provider_id.as_str() != crate::MLFLOW_EVALUATION_RESULT_PROVIDER_ID
        {
            return Err(ServiceError::ProviderMismatch);
        }
        let registration = MlflowRegistration::new(
            scope.scope_digest(),
            provider.definition().provider_id.clone(),
            provider.definition().provider_version.clone(),
            provider.definition().capability_digest.clone(),
        )?;
        Ok(Self {
            scope,
            secret,
            provider,
            registration,
            definition: MlflowServiceDefinition::default(),
            retry_policy,
            active: true,
        })
    }

    pub fn scope(&self) -> &MlflowScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn registration(&self) -> &MlflowRegistration {
        &self.registration
    }

    pub fn definition(&self) -> &MlflowServiceDefinition {
        &self.definition
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationRevocation, ServiceError> {
        self.active = false;
        self.registration.revoke().map_err(ServiceError::from)
    }

    pub fn revoke_secret(&mut self) -> Result<(), ServiceError> {
        self.secret.revoke().map_err(ServiceError::from)
    }

    pub fn propose(&self, request: MlflowReadRequest) -> Result<MlflowReadProposal, ServiceError> {
        self.ensure_active()?;
        MlflowReadProposal::new(
            &self.scope,
            &self.secret,
            self.provider.definition(),
            request,
        )
    }

    pub fn read(
        &mut self,
        request: MlflowReadRequest,
    ) -> Result<MlflowResultProposal, ServiceError> {
        let proposal = self.propose(request)?;
        self.record(proposal)
    }

    pub fn record(
        &mut self,
        proposal: MlflowReadProposal,
    ) -> Result<MlflowResultProposal, ServiceError> {
        self.ensure_active()?;
        self.validate_proposal(&proposal)?;
        let mut accumulator = EvidenceAccumulator::new(&proposal, self.provider.definition());
        let bounds = proposal.bounds();
        let mut page_token = proposal.initial_page_token().cloned();
        let mut seen_page_tokens = BTreeSet::new();
        let mut terminated = false;

        for page_index in 0..bounds.max_pages() {
            if let Some(token) = &page_token {
                if !seen_page_tokens.insert(token.digest()) {
                    accumulator.partial(PartialReason::PaginationLoop);
                    terminated = true;
                    break;
                }
                accumulator.record_page_token(token);
            }
            let mut response = None;
            for attempt in 1..=self.retry_policy.max_attempts {
                match self.provider.fetch(&proposal, page_token.as_ref()) {
                    Ok(page) => {
                        response = Some(page);
                        break;
                    }
                    Err(error) if error.retryable && attempt < self.retry_policy.max_attempts => {
                        accumulator.record_retry(proposal.operation(), attempt, &error);
                    }
                    Err(error) => {
                        accumulator.record_provider_error(&error, attempt);
                        accumulator.provider_failure(&error);
                        terminated = true;
                        break;
                    }
                }
            }
            let Some(page) = response else {
                break;
            };
            accumulator.add_page(&page, &self.scope, &proposal)?;
            let next_page_token = page.next_page_token.clone();
            if next_page_token.is_none() {
                if !page.complete {
                    accumulator.partial(PartialReason::MissingPage);
                }
                terminated = true;
                break;
            }
            page_token = next_page_token;
            if page_index + 1 == bounds.max_pages() {
                accumulator.partial(PartialReason::PageLimit);
                terminated = true;
                break;
            }
        }
        if !terminated {
            accumulator.partial(PartialReason::PageLimit);
        }
        let evidence = accumulator.finish();
        let result = MlflowResultProposal {
            operation: proposal.operation(),
            status: evidence.status,
            evidence,
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            proposal_digest: proposal.proposal_digest().clone(),
            authority: crate::MlflowAuthority,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        };
        self.verify(&proposal, &result)?;
        Ok(result)
    }

    pub fn verify(
        &self,
        proposal: &MlflowReadProposal,
        result: &MlflowResultProposal,
    ) -> Result<(), ServiceError> {
        self.ensure_active()?;
        self.validate_proposal(proposal)?;
        if result.registration_digest != self.registration.registration_digest
            || result.registration_revision != self.registration.revision
            || result.proposal_digest != *proposal.proposal_digest()
            || result.operation != proposal.operation()
        {
            return Err(ServiceError::ProposalMismatch);
        }
        if result.evidence.operation != proposal.operation()
            || result.evidence.scope_digest != *proposal.scope_digest()
            || result.evidence.permission_digest != *proposal.permission_digest()
            || result.evidence.consent_digest != *proposal.consent_digest()
            || result.evidence.revisions != proposal.revisions()
            || result.evidence.provider_version != proposal.provider_version()
            || result.evidence.digests.scope_digest != *proposal.scope_digest()
            || result.evidence.digests.version_digest != *proposal.version_digest()
            || result.evidence.digests.provider_digest != *proposal.provider_digest()
            || result.evidence.digests.contract_digest != *proposal.contract_digest()
            || result.evidence.digests.permission_digest != *proposal.permission_digest()
            || result.evidence.digests.consent_digest != *proposal.consent_digest()
            || result.evidence.digests.query_digest != *proposal.query_digest()
            || result.evidence.digests.config_digest != *proposal.config_digest()
        {
            return Err(ServiceError::FenceMismatch);
        }
        if result.status != result.evidence.status {
            return Err(ServiceError::TamperedEvidence);
        }
        result.evidence.validate_digest()
    }

    fn validate_proposal(&self, proposal: &MlflowReadProposal) -> Result<(), ServiceError> {
        if proposal.scope_digest() != &self.scope.scope_digest()
            || proposal.provider_version() != self.provider.definition().provider_version
            || proposal.provider_digest() != &self.provider.definition().provider_digest
            || proposal.secret_reference_digest() != self.secret.reference_digest()
            || proposal.credential_revision() != self.secret.credential_revision()
            || proposal.permission_digest() != self.scope.permission_digest()
            || proposal.consent_digest() != self.scope.consent_digest()
        {
            return Err(ServiceError::ProposalMismatch);
        }
        self.registration
            .ensure_active()
            .map_err(ServiceError::from)
    }

    fn ensure_active(&self) -> Result<(), ServiceError> {
        if self.active && !self.secret.is_revoked() {
            Ok(())
        } else {
            Err(if self.secret.is_revoked() {
                ServiceError::SecretInvalid
            } else {
                ServiceError::RegistrationRevoked
            })
        }
    }
}

struct EvidenceAccumulator {
    operation: MlflowOperation,
    provider_provenance: ProviderProvenance,
    provider_version: String,
    scope_digest: Digest,
    permission_digest: Digest,
    consent_digest: Digest,
    revisions: ScopeRevisions,
    bounds: ResultBounds,
    query_digest: Digest,
    config_digest: Digest,
    version_digest: Digest,
    provider_digest: Digest,
    contract_digest: Digest,
    pages_observed: u8,
    response_bytes: u64,
    page_token_digests: Vec<Digest>,
    experiments: Vec<ExperimentRecord>,
    runs: Vec<RunRecord>,
    metric_history: Vec<MetricHistoryPoint>,
    dataset_digests: BTreeSet<DatasetDigest>,
    provider_errors: Vec<ProviderErrorEvidence>,
    retries: Vec<RetryEvidence>,
    status: Option<ResultStatus>,
}

impl EvidenceAccumulator {
    fn new(proposal: &MlflowReadProposal, provider: &MlflowProviderDefinition) -> Self {
        Self {
            operation: proposal.operation(),
            provider_provenance: provider.provenance,
            provider_version: provider.provider_version.clone(),
            scope_digest: proposal.scope_digest().clone(),
            permission_digest: proposal.permission_digest().clone(),
            consent_digest: proposal.consent_digest().clone(),
            revisions: proposal.revisions(),
            bounds: proposal.bounds(),
            query_digest: proposal.query_digest().clone(),
            config_digest: proposal.config_digest().clone(),
            version_digest: proposal.version_digest().clone(),
            provider_digest: proposal.provider_digest().clone(),
            contract_digest: proposal.contract_digest().clone(),
            pages_observed: 0,
            response_bytes: 0,
            page_token_digests: Vec::new(),
            experiments: Vec::new(),
            runs: Vec::new(),
            metric_history: Vec::new(),
            dataset_digests: BTreeSet::new(),
            provider_errors: Vec::new(),
            retries: Vec::new(),
            status: None,
        }
    }

    fn record_page_token(&mut self, token: &OpaquePageToken) {
        self.page_token_digests.push(token.digest());
    }

    fn record_retry(&mut self, operation: MlflowOperation, attempt: u8, error: &TransportError) {
        self.retries.push(RetryEvidence {
            operation,
            attempt,
            kind: error.kind,
            status_code: error.status_code,
            error_digest: error.diagnostic_digest.clone(),
        });
    }

    fn record_provider_error(&mut self, error: &TransportError, attempt: u8) {
        self.provider_errors.push(error.evidence(attempt));
    }

    fn provider_failure(&mut self, error: &TransportError) {
        let has_progress = self.pages_observed > 0;
        self.status = Some(match error.kind {
            ProviderErrorKind::Unauthenticated | ProviderErrorKind::PermissionDenied => {
                if has_progress {
                    ResultStatus::Partial(PartialReason::AccessLossAfterProgress)
                } else {
                    ResultStatus::AccessLoss
                }
            }
            ProviderErrorKind::NotFound => {
                if has_progress {
                    ResultStatus::Partial(PartialReason::StaleAfterProgress)
                } else {
                    ResultStatus::Stale
                }
            }
            ProviderErrorKind::BadRequest | ProviderErrorKind::Tampered => ResultStatus::FinalError,
            ProviderErrorKind::Conflict
            | ProviderErrorKind::RateLimited
            | ProviderErrorKind::ServerFailure
            | ProviderErrorKind::Timeout
            | ProviderErrorKind::PaginationLoop
            | ProviderErrorKind::BlockedEnv
            | ProviderErrorKind::Unknown => ResultStatus::ProviderUnknown,
        });
    }

    fn partial(&mut self, reason: PartialReason) {
        if self.status.is_none_or(ResultStatus::is_complete) {
            self.status = Some(ResultStatus::Partial(reason));
        }
    }

    fn add_page(
        &mut self,
        page: &MlflowResponsePage,
        scope: &MlflowScope,
        proposal: &MlflowReadProposal,
    ) -> Result<(), ServiceError> {
        page.validate_digest()
            .map_err(|_| ServiceError::TamperedEvidence)?;
        if page.operation != self.operation
            || page.scope_digest != self.scope_digest
            || page.permission_digest != self.permission_digest
            || page.consent_digest != self.consent_digest
            || page.revisions != self.revisions
            || page.provider_version != self.provider_version
            || page.credential_revision != proposal.credential_revision()
        {
            return Err(ServiceError::FenceMismatch);
        }
        self.pages_observed = self.pages_observed.saturating_add(1);
        self.response_bytes = self.response_bytes.saturating_add(page.response_bytes);
        if self.response_bytes > self.bounds.max_response_bytes() {
            self.partial(PartialReason::ResponseBytesLimit);
        }
        if !page.experiments.is_empty()
            && !matches!(
                self.operation,
                MlflowOperation::SearchExperiments | MlflowOperation::GetExperiment
            )
        {
            return Err(ServiceError::InvalidResponseShape);
        }
        if !page.runs.is_empty()
            && !matches!(
                self.operation,
                MlflowOperation::SearchRuns | MlflowOperation::GetRun
            )
        {
            return Err(ServiceError::InvalidResponseShape);
        }
        if !page.metric_history.is_empty() && self.operation != MlflowOperation::GetMetricHistory {
            return Err(ServiceError::InvalidResponseShape);
        }
        let page_size = self.bounds.page_size() as usize;
        if page.experiments.len() > page_size {
            self.partial(PartialReason::ExperimentLimit);
        }
        if page.runs.len() > page_size {
            self.partial(PartialReason::RunLimit);
        }
        if page.metric_history.len() > page_size {
            self.partial(PartialReason::MetricHistoryLimit);
        }
        for experiment in page.experiments.iter().take(page_size) {
            if !scope.allows_experiment(&experiment.experiment_id)
                || experiment.revision != self.revisions.experiment
                || experiment.redacted_tags.iter().any(|tag| {
                    scope
                        .allowlisted_tags()
                        .iter()
                        .all(|allowed| allowed.as_str() != tag.key)
                })
            {
                return Err(ServiceError::FenceMismatch);
            }
            if self.experiments.len() >= self.bounds.max_experiments() as usize {
                self.partial(PartialReason::ExperimentLimit);
                break;
            }
            self.experiments.push(experiment.clone());
        }
        for run in page.runs.iter().take(page_size) {
            if run.metrics.len() > MAX_METRICS as usize {
                return Err(ServiceError::BoundExceeded);
            }
            if !scope.allows_run(&run.run_id)
                || !scope.allows_experiment(&run.experiment_id)
                || run.revision != self.revisions.run
                || run.metrics.iter().any(|metric| {
                    !scope.allows_metric(&metric.key)
                        || metric
                            .dataset_digest
                            .as_ref()
                            .is_some_and(|digest| !scope.allows_dataset_digest(digest))
                })
                || run.redacted_params.iter().any(|param| {
                    scope
                        .allowlisted_params()
                        .iter()
                        .all(|allowed| allowed.as_str() != param.key)
                })
                || run.redacted_tags.iter().any(|tag| {
                    scope
                        .allowlisted_tags()
                        .iter()
                        .all(|allowed| allowed.as_str() != tag.key)
                })
                || run.datasets.iter().any(|dataset| {
                    dataset.validate_digest().is_err()
                        || !scope.allows_dataset_digest(&dataset.digest)
                })
            {
                return Err(ServiceError::FenceMismatch);
            }
            if self.runs.len() >= self.bounds.max_runs() as usize {
                self.partial(PartialReason::RunLimit);
                break;
            }
            self.collect_datasets(run.datasets.iter().map(|dataset| &dataset.digest));
            self.collect_datasets(
                run.metrics
                    .iter()
                    .filter_map(|metric| metric.dataset_digest.as_ref()),
            );
            self.runs.push(run.clone());
        }
        for point in page.metric_history.iter().take(page_size) {
            if point.metric.key.as_str()
                != match &proposal.request() {
                    MlflowReadRequest::MetricHistory { metric, .. } => metric.as_str(),
                    _ => point.metric.key.as_str(),
                }
                || !scope.allows_metric(&point.metric.key)
                || point
                    .metric
                    .dataset_digest
                    .as_ref()
                    .is_some_and(|digest| !scope.allows_dataset_digest(digest))
            {
                return Err(ServiceError::FenceMismatch);
            }
            if self.metric_history.len() >= self.bounds.max_metric_history() as usize {
                self.partial(PartialReason::MetricHistoryLimit);
                break;
            }
            if let Some(dataset) = &point.metric.dataset_digest {
                self.dataset_digests.insert(dataset.clone());
            }
            self.metric_history.push(point.clone());
        }
        Ok(())
    }

    fn collect_datasets<'a>(&mut self, digests: impl IntoIterator<Item = &'a DatasetDigest>) {
        self.dataset_digests.extend(digests.into_iter().cloned());
    }

    fn finish(self) -> MlflowEvidence {
        let status = self.status.unwrap_or(ResultStatus::Complete);
        let dataset_digests = self.dataset_digests.into_iter().collect::<Vec<_>>();
        let digests = Self::compute_digests(
            self.operation,
            status,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            self.revisions,
            &self.provider_version,
            &self.experiments,
            &self.runs,
            &self.metric_history,
            &dataset_digests,
            &self.provider_errors,
            &self.retries,
            &self.page_token_digests,
            self.pages_observed,
            self.response_bytes,
            &self.query_digest,
            &self.config_digest,
            &self.version_digest,
            &self.provider_digest,
            &self.contract_digest,
            self.provider_provenance,
        );
        MlflowEvidence {
            operation: self.operation,
            status,
            provider_provenance: self.provider_provenance,
            provider_version: self.provider_version,
            scope_digest: self.scope_digest,
            permission_digest: self.permission_digest,
            consent_digest: self.consent_digest,
            revisions: self.revisions,
            pages_observed: self.pages_observed,
            response_bytes: self.response_bytes,
            page_token_digests: self.page_token_digests,
            experiments: self.experiments,
            runs: self.runs,
            metric_history: self.metric_history,
            dataset_digests,
            provider_errors: self.provider_errors,
            retries: self.retries,
            digests,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_digests(
        operation: MlflowOperation,
        status: ResultStatus,
        scope_digest: &Digest,
        permission_digest: &Digest,
        consent_digest: &Digest,
        revisions: ScopeRevisions,
        provider_version: &str,
        experiments: &[ExperimentRecord],
        runs: &[RunRecord],
        metric_history: &[MetricHistoryPoint],
        dataset_digests: &[DatasetDigest],
        provider_errors: &[ProviderErrorEvidence],
        retries: &[RetryEvidence],
        page_token_digests: &[Digest],
        pages_observed: u8,
        response_bytes: u64,
        query_digest: &Digest,
        config_digest: &Digest,
        version_digest: &Digest,
        provider_digest: &Digest,
        contract_digest: &Digest,
        provenance: ProviderProvenance,
    ) -> EvidenceDigests {
        let experiment_set_digest = Digest::from_fields(
            "mlflow-experiment-set/v1",
            &experiments
                .iter()
                .map(|experiment| experiment.record_digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        let run_set_digest = Digest::from_fields(
            "mlflow-run-set/v1",
            &runs
                .iter()
                .map(|run| run.record_digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        let metric_history_digest = Digest::from_fields(
            "mlflow-metric-history/v1",
            &metric_history
                .iter()
                .map(|point| point.point_digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        let dataset_set_digest = Digest::from_fields(
            "mlflow-dataset-set/v1",
            &dataset_digests
                .iter()
                .map(|digest| digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        let result_digest = Digest::from_fields(
            "mlflow-result/v1",
            &[
                operation_name(operation).to_owned(),
                format!("{status:?}"),
                experiment_set_digest.as_str().to_owned(),
                run_set_digest.as_str().to_owned(),
                metric_history_digest.as_str().to_owned(),
                dataset_set_digest.as_str().to_owned(),
            ],
        );
        let mut evidence_fields = vec![
            scope_digest.as_str().to_owned(),
            version_digest.as_str().to_owned(),
            provider_digest.as_str().to_owned(),
            contract_digest.as_str().to_owned(),
            permission_digest.as_str().to_owned(),
            consent_digest.as_str().to_owned(),
            query_digest.as_str().to_owned(),
            config_digest.as_str().to_owned(),
            experiment_set_digest.as_str().to_owned(),
            run_set_digest.as_str().to_owned(),
            metric_history_digest.as_str().to_owned(),
            dataset_set_digest.as_str().to_owned(),
            result_digest.as_str().to_owned(),
            format!("{provenance:?}"),
            provider_version.to_owned(),
            pages_observed.to_string(),
            response_bytes.to_string(),
        ];
        evidence_fields.extend(
            page_token_digests
                .iter()
                .map(|digest| digest.as_str().to_owned()),
        );
        evidence_fields.extend(
            provider_errors
                .iter()
                .map(|error| error.error_digest.as_str().to_owned()),
        );
        evidence_fields.extend(
            retries
                .iter()
                .map(|retry| retry.error_digest.as_str().to_owned()),
        );
        evidence_fields.extend([
            revisions.experiment.get().to_string(),
            revisions.run.get().to_string(),
            revisions.dataset.get().to_string(),
            revisions.mission.get().to_string(),
            revisions.project.get().to_string(),
            revisions.work_product.get().to_string(),
        ]);
        let evidence_digest = Digest::from_fields("mlflow-evidence/v1", &evidence_fields);
        EvidenceDigests {
            scope_digest: scope_digest.clone(),
            version_digest: version_digest.clone(),
            provider_digest: provider_digest.clone(),
            contract_digest: contract_digest.clone(),
            permission_digest: permission_digest.clone(),
            consent_digest: consent_digest.clone(),
            query_digest: query_digest.clone(),
            config_digest: config_digest.clone(),
            experiment_set_digest,
            run_set_digest,
            metric_history_digest,
            dataset_set_digest,
            result_digest,
            evidence_digest,
        }
    }
}
