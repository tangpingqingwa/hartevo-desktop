use std::{collections::VecDeque, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    Digest, ExperimentRecord, MlflowOperation, MlflowReadProposal, ModelError, OpaquePageToken,
    ProviderErrorKind, ProviderProvenance, Revision, RunRecord,
};

use crate::model::{MetricHistoryPoint, ProviderErrorEvidence};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MlflowProviderDefinition {
    pub provider_id: crate::ProviderId,
    pub provider_version: String,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub provider_digest: Digest,
}

impl MlflowProviderDefinition {
    pub fn new(
        provider_id: crate::ProviderId,
        provider_version: impl Into<String>,
        capability_digest: Digest,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        let provider_digest = Digest::from_fields(
            "mlflow-provider/v1",
            &[
                provider_id.as_str().to_owned(),
                provider_version.clone(),
                capability_digest.as_str().to_owned(),
                provenance.as_str().to_owned(),
            ],
        );
        Ok(Self {
            provider_id,
            provider_version,
            capability_digest,
            provenance,
            provider_digest,
        })
    }

    pub fn standard(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new(
            crate::ProviderId::new(crate::MLFLOW_EVALUATION_RESULT_PROVIDER_ID)?,
            provider_version,
            Digest::from_text(crate::MLFLOW_EVALUATION_RESULT_PROVIDER_ID),
            provenance,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderCall {
    pub operation: MlflowOperation,
    pub proposal_digest: Digest,
    pub page_token_digest: Option<Digest>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MlflowResponsePage {
    pub operation: MlflowOperation,
    pub experiments: Vec<ExperimentRecord>,
    pub runs: Vec<RunRecord>,
    pub metric_history: Vec<MetricHistoryPoint>,
    pub next_page_token: Option<OpaquePageToken>,
    pub complete: bool,
    pub response_bytes: u64,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub revisions: crate::ScopeRevisions,
    pub credential_revision: Revision,
    pub provider_version: String,
    pub response_digest: Digest,
}

impl MlflowResponsePage {
    #[allow(clippy::too_many_arguments)]
    pub fn for_proposal(
        proposal: &MlflowReadProposal,
        experiments: Vec<ExperimentRecord>,
        runs: Vec<RunRecord>,
        metric_history: Vec<MetricHistoryPoint>,
        next_page_token: Option<OpaquePageToken>,
        complete: bool,
        credential_revision: Revision,
        response_bytes: u64,
    ) -> Self {
        let response_digest = Self::compute_digest(
            proposal.operation(),
            &experiments,
            &runs,
            &metric_history,
            next_page_token.as_ref(),
            complete,
            response_bytes,
            proposal.scope_digest(),
            proposal.permission_digest(),
            proposal.consent_digest(),
            proposal.revisions(),
            credential_revision,
            proposal.provider_version(),
        );
        Self {
            operation: proposal.operation(),
            experiments,
            runs,
            metric_history,
            next_page_token,
            complete,
            response_bytes,
            scope_digest: proposal.scope_digest().clone(),
            permission_digest: proposal.permission_digest().clone(),
            consent_digest: proposal.consent_digest().clone(),
            revisions: proposal.revisions(),
            credential_revision,
            provider_version: proposal.provider_version().to_owned(),
            response_digest,
        }
    }

    pub fn empty(proposal: &MlflowReadProposal) -> Self {
        Self::for_proposal(
            proposal,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            true,
            proposal.credential_revision(),
            0,
        )
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        for experiment in &self.experiments {
            experiment.validate_digest()?;
        }
        for run in &self.runs {
            run.validate_digest()?;
        }
        for point in &self.metric_history {
            point.validate_digest()?;
        }
        let expected = Self::compute_digest(
            self.operation,
            &self.experiments,
            &self.runs,
            &self.metric_history,
            self.next_page_token.as_ref(),
            self.complete,
            self.response_bytes,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            self.revisions,
            self.credential_revision,
            &self.provider_version,
        );
        if expected == self.response_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_digest(
        operation: MlflowOperation,
        experiments: &[ExperimentRecord],
        runs: &[RunRecord],
        metric_history: &[MetricHistoryPoint],
        next_page_token: Option<&OpaquePageToken>,
        complete: bool,
        response_bytes: u64,
        scope_digest: &Digest,
        permission_digest: &Digest,
        consent_digest: &Digest,
        revisions: crate::ScopeRevisions,
        credential_revision: Revision,
        provider_version: &str,
    ) -> Digest {
        let mut fields = vec![
            format!("{operation:?}"),
            complete.to_string(),
            response_bytes.to_string(),
            scope_digest.as_str().to_owned(),
            permission_digest.as_str().to_owned(),
            consent_digest.as_str().to_owned(),
            revisions.experiment.get().to_string(),
            revisions.run.get().to_string(),
            revisions.dataset.get().to_string(),
            revisions.mission.get().to_string(),
            revisions.project.get().to_string(),
            revisions.work_product.get().to_string(),
            credential_revision.get().to_string(),
            provider_version.to_owned(),
            next_page_token.map_or_else(
                || "none".to_owned(),
                |token| token.digest().as_str().to_owned(),
            ),
        ];
        fields.extend(
            experiments
                .iter()
                .map(|experiment| experiment.record_digest.as_str().to_owned()),
        );
        fields.extend(runs.iter().map(|run| run.record_digest.as_str().to_owned()));
        fields.extend(
            metric_history
                .iter()
                .map(|point| point.point_digest.as_str().to_owned()),
        );
        Digest::from_fields("mlflow-response-page/v1", &fields)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("MLflow transport failed with {kind:?} ({status_code:?})")]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    pub diagnostic_digest: Digest,
}

impl TransportError {
    pub fn http(status_code: u16, diagnostic: impl AsRef<[u8]>) -> Self {
        let kind = match status_code {
            400 => ProviderErrorKind::BadRequest,
            401 => ProviderErrorKind::Unauthenticated,
            403 => ProviderErrorKind::PermissionDenied,
            404 => ProviderErrorKind::NotFound,
            409 => ProviderErrorKind::Conflict,
            429 => ProviderErrorKind::RateLimited,
            500..=599 => ProviderErrorKind::ServerFailure,
            _ => ProviderErrorKind::Unknown,
        };
        Self {
            kind,
            status_code: Some(status_code),
            retryable: matches!(status_code, 429 | 500..=599),
            blocked_env: false,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn timeout(diagnostic: impl AsRef<[u8]>) -> Self {
        Self {
            kind: ProviderErrorKind::Timeout,
            status_code: None,
            retryable: true,
            blocked_env: false,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn blocked_env() -> Self {
        Self {
            kind: ProviderErrorKind::BlockedEnv,
            status_code: None,
            retryable: false,
            blocked_env: true,
            diagnostic_digest: Digest::from_text(crate::MLFLOW_EVALUATION_RESULT_BLOCKED_ENV),
        }
    }

    pub fn tampered() -> Self {
        Self {
            kind: ProviderErrorKind::Tampered,
            status_code: None,
            retryable: false,
            blocked_env: false,
            diagnostic_digest: Digest::from_text("tampered-response"),
        }
    }

    pub fn provider_unknown(diagnostic: impl AsRef<[u8]>) -> Self {
        Self {
            kind: ProviderErrorKind::Unknown,
            status_code: None,
            retryable: false,
            blocked_env: false,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub(crate) fn evidence(&self, attempt: u8) -> ProviderErrorEvidence {
        let severity = match self.kind {
            ProviderErrorKind::RateLimited
            | ProviderErrorKind::ServerFailure
            | ProviderErrorKind::Timeout
            | ProviderErrorKind::BlockedEnv
            | ProviderErrorKind::Unknown => crate::ErrorSeverity::Warning,
            _ => crate::ErrorSeverity::Final,
        };
        ProviderErrorEvidence::new(
            self.kind,
            severity,
            self.status_code,
            self.retryable,
            attempt,
            self.blocked_env,
            &self.diagnostic_digest,
        )
    }
}

/// The Layer-1 provider seam. Implementations may be fixture, recording,
/// loopback, or blocked-environment providers; the service never assumes a
/// live MLflow connection.
pub trait MlflowProvider: fmt::Debug {
    fn definition(&self) -> &MlflowProviderDefinition;

    fn fetch(
        &mut self,
        proposal: &MlflowReadProposal,
        page_token: Option<&OpaquePageToken>,
    ) -> Result<MlflowResponsePage, TransportError>;
}

#[derive(Debug)]
pub struct RecordingMlflowProvider {
    definition: MlflowProviderDefinition,
    responses: VecDeque<Result<MlflowResponsePage, TransportError>>,
    calls: Vec<ProviderCall>,
}

impl RecordingMlflowProvider {
    pub fn new(provider_version: impl Into<String>) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            definition: MlflowProviderDefinition::standard(
                provider_version,
                ProviderProvenance::Recording,
            )?,
            responses: VecDeque::new(),
            calls: Vec::new(),
        })
    }

    pub fn with_responses(
        provider_version: impl Into<String>,
        responses: impl IntoIterator<Item = Result<MlflowResponsePage, TransportError>>,
    ) -> Result<Self, ProviderDefinitionError> {
        let mut provider = Self::new(provider_version)?;
        provider.responses.extend(responses);
        Ok(provider)
    }

    pub fn push_response(&mut self, response: Result<MlflowResponsePage, TransportError>) {
        self.responses.push_back(response);
    }

    pub fn calls(&self) -> &[ProviderCall] {
        &self.calls
    }
}

impl MlflowProvider for RecordingMlflowProvider {
    fn definition(&self) -> &MlflowProviderDefinition {
        &self.definition
    }

    fn fetch(
        &mut self,
        proposal: &MlflowReadProposal,
        page_token: Option<&OpaquePageToken>,
    ) -> Result<MlflowResponsePage, TransportError> {
        self.calls.push(ProviderCall {
            operation: proposal.operation(),
            proposal_digest: proposal.proposal_digest().clone(),
            page_token_digest: page_token.map(OpaquePageToken::digest),
        });
        self.responses.pop_front().unwrap_or_else(|| {
            Err(TransportError::provider_unknown(
                "recording-provider-exhausted",
            ))
        })
    }
}

#[derive(Debug)]
pub struct FixtureMlflowProvider {
    definition: MlflowProviderDefinition,
    responses: VecDeque<Result<MlflowResponsePage, TransportError>>,
}

impl FixtureMlflowProvider {
    pub fn new(provider_version: impl Into<String>) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            definition: MlflowProviderDefinition::standard(
                provider_version,
                ProviderProvenance::Fixture,
            )?,
            responses: VecDeque::new(),
        })
    }

    pub fn push_response(&mut self, response: Result<MlflowResponsePage, TransportError>) {
        self.responses.push_back(response);
    }
}

impl MlflowProvider for FixtureMlflowProvider {
    fn definition(&self) -> &MlflowProviderDefinition {
        &self.definition
    }

    fn fetch(
        &mut self,
        _proposal: &MlflowReadProposal,
        _page_token: Option<&OpaquePageToken>,
    ) -> Result<MlflowResponsePage, TransportError> {
        self.responses.pop_front().unwrap_or_else(|| {
            Err(TransportError::provider_unknown(
                "fixture-provider-exhausted",
            ))
        })
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackMlflowProvider {
    definition: MlflowProviderDefinition,
}

impl LoopbackMlflowProvider {
    pub fn new(provider_version: impl Into<String>) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            definition: MlflowProviderDefinition::standard(
                provider_version,
                ProviderProvenance::Loopback,
            )?,
        })
    }
}

impl MlflowProvider for LoopbackMlflowProvider {
    fn definition(&self) -> &MlflowProviderDefinition {
        &self.definition
    }

    fn fetch(
        &mut self,
        proposal: &MlflowReadProposal,
        _page_token: Option<&OpaquePageToken>,
    ) -> Result<MlflowResponsePage, TransportError> {
        Ok(MlflowResponsePage::empty(proposal))
    }
}

#[derive(Clone, Debug)]
pub struct BlockedEnvMlflowProvider {
    definition: MlflowProviderDefinition,
}

impl BlockedEnvMlflowProvider {
    pub fn new(provider_version: impl Into<String>) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            definition: MlflowProviderDefinition::standard(
                provider_version,
                ProviderProvenance::BlockedEnv,
            )?,
        })
    }
}

impl MlflowProvider for BlockedEnvMlflowProvider {
    fn definition(&self) -> &MlflowProviderDefinition {
        &self.definition
    }

    fn fetch(
        &mut self,
        _proposal: &MlflowReadProposal,
        _page_token: Option<&OpaquePageToken>,
    ) -> Result<MlflowResponsePage, TransportError> {
        Err(TransportError::blocked_env())
    }
}

pub type FakeMlflowProvider = RecordingMlflowProvider;
