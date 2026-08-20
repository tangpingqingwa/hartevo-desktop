use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::{
    GITHUB_ACTIONS_API_REVISION, GITHUB_ACTIONS_PROVIDER_ID, GITHUB_ACTIONS_PROVIDER_VERSION,
    GITHUB_ACTIONS_RESULT_CONTRACT_VERSION, GITHUB_ACTIONS_RESULT_PLUGIN_VERSION,
    GITHUB_ACTIONS_RESULT_SCHEMA_VERSION, GITHUB_ACTIONS_RESULT_SERVICE_ID, canonical_digest,
    contract_digest,
    model::{
        GithubActionsConclusion, GithubActionsRegistration, GithubActionsScope,
        GithubArtifactMetadata, GithubJobMetadata, GithubWorkflowRunMetadata, Layer1Authority,
        ModelError, RegistrationRevocationReceipt, TransportProvenance,
    },
    provider::{
        GithubActionsObservation, GithubActionsProvider, GithubActionsProviderDefinitionError,
        GithubActionsProviderError, GithubActionsProviderErrorKind, GithubActionsResponseReceipt,
        GithubActionsTransport,
    },
    version_digest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubActionsEvidenceState {
    Complete,
    Partial,
    RunInProgress,
    ArtifactExpired,
    AccessLost,
    RateLimited,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GithubActionsResultServiceError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("provider definition is invalid: {0}")]
    ProviderDefinition(GithubActionsProviderDefinitionError),
    #[error("GitHub Actions secret reference is revoked or scope-bound incorrectly")]
    SecretInvalid,
    #[error("GitHub Actions registration is revoked")]
    RegistrationRevoked,
    #[error("GitHub Actions registration is stale or tampered")]
    RegistrationDrift,
    #[error("GitHub Actions evidence or proposal digest mismatch")]
    EvidenceMismatch,
    #[error("GitHub Actions proposal is tampered")]
    ProposalTampered,
    #[error("GitHub Actions provider error: {0}")]
    Provider(#[from] GithubActionsProviderError),
}

impl From<GithubActionsProviderDefinitionError> for GithubActionsResultServiceError {
    fn from(error: GithubActionsProviderDefinitionError) -> Self {
        Self::ProviderDefinition(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubActionsProviderErrorEvidence {
    pub kind: GithubActionsProviderErrorKind,
    pub status_code: Option<u16>,
    pub diagnostic_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubActionsEvidence {
    pub schema_version: String,
    pub plugin_version: String,
    pub version_digest: String,
    pub contract_version: String,
    pub contract_digest: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub api_digest: String,
    pub provider_digest: String,
    pub installation_digest: String,
    pub permission_digest: String,
    pub scope_digest: String,
    pub workflow_digest: String,
    pub run_digest: String,
    pub job_digest: String,
    pub attempt_digest: String,
    pub commit_digest: String,
    pub response_digest: String,
    pub registration_digest: String,
    pub state: GithubActionsEvidenceState,
    pub provenance: TransportProvenance,
    pub run: Option<GithubWorkflowRunMetadata>,
    pub jobs: Vec<GithubJobMetadata>,
    pub artifacts: Vec<GithubArtifactMetadata>,
    pub response_receipts: Vec<GithubActionsResponseReceipt>,
    pub provider_error: Option<GithubActionsProviderErrorEvidence>,
    pub evidence_digest: String,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub durable_receipt: bool,
    pub adopts_outcome: bool,
    pub green_ci_claim: bool,
    pub authority: Layer1Authority,
}

impl GithubActionsEvidence {
    fn from_observation(
        scope: &GithubActionsScope,
        registration: &GithubActionsRegistration,
        provider: &GithubActionsProviderDefinitionView,
        observation: GithubActionsObservation,
    ) -> Self {
        let state = observation_state(&observation.run, &observation.jobs);
        let response_digest = canonical_digest(
            &observation
                .response_receipts
                .iter()
                .map(|receipt| receipt.response_digest.as_str())
                .collect::<Vec<_>>(),
        );
        Self::new(
            scope,
            registration,
            provider,
            state,
            observation.provenance,
            Some(observation.run),
            observation.jobs,
            observation.artifacts,
            observation.response_receipts,
            None,
            response_digest,
            observation.authority,
        )
    }

    fn from_provider_error(
        scope: &GithubActionsScope,
        registration: &GithubActionsRegistration,
        provider: &GithubActionsProviderDefinitionView,
        error: GithubActionsProviderError,
    ) -> Self {
        let state = error_state(error.kind);
        let response_digest = canonical_digest(
            &error
                .response_receipts
                .iter()
                .map(|receipt| receipt.response_digest.as_str())
                .collect::<Vec<_>>(),
        );
        let receipts = error.response_receipts;
        let provider_error = Some(GithubActionsProviderErrorEvidence {
            kind: error.kind,
            status_code: error.status_code,
            diagnostic_digest: error.diagnostic_digest,
        });
        Self::new(
            scope,
            registration,
            provider,
            state,
            provider.provenance,
            None,
            Vec::new(),
            Vec::new(),
            receipts,
            provider_error,
            response_digest,
            Layer1Authority::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        scope: &GithubActionsScope,
        registration: &GithubActionsRegistration,
        provider: &GithubActionsProviderDefinitionView,
        state: GithubActionsEvidenceState,
        provenance: TransportProvenance,
        run: Option<GithubWorkflowRunMetadata>,
        jobs: Vec<GithubJobMetadata>,
        artifacts: Vec<GithubArtifactMetadata>,
        response_receipts: Vec<GithubActionsResponseReceipt>,
        provider_error: Option<GithubActionsProviderErrorEvidence>,
        response_digest: String,
        authority: Layer1Authority,
    ) -> Self {
        let mut evidence = Self {
            schema_version: GITHUB_ACTIONS_RESULT_SCHEMA_VERSION.to_owned(),
            plugin_version: GITHUB_ACTIONS_RESULT_PLUGIN_VERSION.to_owned(),
            version_digest: version_digest(),
            contract_version: GITHUB_ACTIONS_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: GITHUB_ACTIONS_PROVIDER_ID.to_owned(),
            provider_version: GITHUB_ACTIONS_PROVIDER_VERSION.to_owned(),
            api_revision: GITHUB_ACTIONS_API_REVISION.to_owned(),
            api_digest: canonical_digest(&GITHUB_ACTIONS_API_REVISION),
            provider_digest: provider.provider_digest.clone(),
            installation_digest: scope.installation_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.digest().clone(),
            workflow_digest: scope.workflow_digest().clone(),
            run_digest: scope.run_digest().clone(),
            job_digest: scope.job_digest().clone(),
            attempt_digest: scope.attempt_digest().clone(),
            commit_digest: scope.commit_digest().clone(),
            response_digest,
            registration_digest: registration.registration_digest.clone(),
            state,
            provenance,
            run,
            jobs,
            artifacts,
            response_receipts,
            provider_error,
            evidence_digest: String::new(),
            proposal_only: true,
            native: false,
            connected: false,
            durable_receipt: false,
            adopts_outcome: false,
            green_ci_claim: false,
            authority,
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    fn compute_digest(&self) -> String {
        let mut value = self.clone();
        value.evidence_digest.clear();
        canonical_digest(&value)
    }

    #[must_use]
    pub fn digest(&self) -> &String {
        &self.evidence_digest
    }

    pub fn verify_digest(&self) -> Result<(), GithubActionsResultServiceError> {
        if self.evidence_digest != self.compute_digest() {
            Err(GithubActionsResultServiceError::EvidenceMismatch)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn conclusion(&self) -> Option<GithubActionsConclusion> {
        self.run.as_ref().and_then(|run| run.conclusion)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubActionsResultProposal {
    pub evidence: GithubActionsEvidence,
    pub source_evidence_digest: String,
    pub version_digest: String,
    pub contract_digest: String,
    pub provider_digest: String,
    pub permission_digest: String,
    pub scope_digest: String,
    pub registration_digest: String,
    pub registration_revision: crate::Revision,
    pub proposal_digest: String,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub adopts_outcome: bool,
    pub green_ci_claim: bool,
}

impl GithubActionsResultProposal {
    fn compute_digest(&self) -> String {
        let mut value = self.clone();
        value.proposal_digest.clear();
        canonical_digest(&value)
    }

    #[must_use]
    pub fn digest(&self) -> &String {
        &self.proposal_digest
    }

    pub fn verify_digest(&self) -> Result<(), GithubActionsResultServiceError> {
        if self.proposal_digest != self.compute_digest() {
            Err(GithubActionsResultServiceError::ProposalTampered)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubActionsObservationReceipt {
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub provenance: TransportProvenance,
    pub evidence_digest: String,
    pub proposal_digest: String,
    pub response_receipt_digests: Vec<String>,
    pub receipt_digest: String,
    pub durable_native_receipt: bool,
    pub native: bool,
    pub connected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GithubActionsResultServiceDefinition {
    pub service_id: String,
    pub version: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub external_writes: bool,
    pub native: bool,
    pub connected: bool,
}

impl Default for GithubActionsResultServiceDefinition {
    fn default() -> Self {
        Self {
            service_id: GITHUB_ACTIONS_RESULT_SERVICE_ID.to_owned(),
            version: "1.0.0".to_owned(),
            read_only: true,
            proposal_only: true,
            external_writes: false,
            native: false,
            connected: false,
        }
    }
}

/// A view avoids putting the generic provider type into evidence construction.
#[derive(Clone, Debug)]
struct GithubActionsProviderDefinitionView {
    provider_digest: String,
    provenance: TransportProvenance,
}

pub struct GithubActionsResultService<T: GithubActionsTransport> {
    provider: GithubActionsProvider<T>,
    definition: GithubActionsResultServiceDefinition,
}

impl<T: GithubActionsTransport> fmt::Debug for GithubActionsResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubActionsResultService")
            .field("scope_digest", self.scope().digest())
            .field(
                "registration_digest",
                &self.registration().registration_digest,
            )
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: GithubActionsTransport> GithubActionsResultService<T> {
    pub fn new(
        provider: GithubActionsProvider<T>,
    ) -> Result<Self, GithubActionsResultServiceError> {
        provider
            .definition()
            .validate(provider.scope())
            .map_err(GithubActionsResultServiceError::from)?;
        provider
            .validate_registration()
            .map_err(map_provider_error)?;
        Ok(Self {
            provider,
            definition: GithubActionsResultServiceDefinition::default(),
        })
    }

    #[must_use]
    pub fn definition(&self) -> &GithubActionsResultServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider(&self) -> &GithubActionsProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut GithubActionsProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &GithubActionsScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &GithubActionsRegistration {
        self.provider.registration()
    }

    fn provider_view(&self) -> GithubActionsProviderDefinitionView {
        GithubActionsProviderDefinitionView {
            provider_digest: self.provider.provider_digest().clone(),
            provenance: self.provider.provenance(),
        }
    }

    fn ensure_active(&self) -> Result<(), GithubActionsResultServiceError> {
        self.provider
            .validate_registration()
            .map_err(map_provider_error)
    }

    pub fn read(&mut self) -> Result<GithubActionsEvidence, GithubActionsResultServiceError> {
        self.ensure_active()?;
        let view = self.provider_view();
        let registration = self.registration().clone();
        match self.provider.read() {
            Ok(observation) => Ok(GithubActionsEvidence::from_observation(
                self.scope(),
                &registration,
                &view,
                observation,
            )),
            Err(error) if error.kind == GithubActionsProviderErrorKind::RegistrationRevoked => {
                Err(map_provider_error(error))
            }
            Err(error) => Ok(GithubActionsEvidence::from_provider_error(
                self.scope(),
                &registration,
                &view,
                error,
            )),
        }
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<GithubActionsResultProposal, GithubActionsResultServiceError> {
        let evidence = self.read()?;
        self.compile_proposal_from_evidence(evidence)
    }

    fn compile_proposal_from_evidence(
        &self,
        evidence: GithubActionsEvidence,
    ) -> Result<GithubActionsResultProposal, GithubActionsResultServiceError> {
        evidence.verify_digest()?;
        let mut proposal = GithubActionsResultProposal {
            source_evidence_digest: evidence.evidence_digest.clone(),
            version_digest: evidence.version_digest.clone(),
            contract_digest: evidence.contract_digest.clone(),
            provider_digest: evidence.provider_digest.clone(),
            permission_digest: evidence.permission_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: self.registration().registration_digest.clone(),
            registration_revision: self.registration().registration_revision,
            proposal_digest: String::new(),
            proposal_only: true,
            native: false,
            connected: false,
            adopts_outcome: false,
            green_ci_claim: false,
            evidence,
        };
        proposal.proposal_digest = proposal.compute_digest();
        Ok(proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &GithubActionsResultProposal,
    ) -> Result<(), GithubActionsResultServiceError> {
        self.ensure_active()?;
        if !proposal.proposal_only
            || proposal.native
            || proposal.connected
            || proposal.adopts_outcome
            || proposal.green_ci_claim
            || proposal.version_digest != version_digest()
            || proposal.contract_digest != contract_digest()
            || proposal.provider_digest != *self.provider.provider_digest()
            || proposal.permission_digest != *self.scope().permission_digest()
            || proposal.scope_digest != *self.scope().digest()
            || proposal.registration_digest != self.registration().registration_digest
            || proposal.registration_revision != self.registration().registration_revision
            || proposal.source_evidence_digest != proposal.evidence.evidence_digest
            || proposal.evidence.version_digest != version_digest()
            || proposal.evidence.contract_digest != contract_digest()
            || proposal.evidence.provider_digest != *self.provider.provider_digest()
            || proposal.evidence.permission_digest != *self.scope().permission_digest()
            || proposal.evidence.scope_digest != *self.scope().digest()
            || proposal.evidence.registration_digest != self.registration().registration_digest
        {
            return Err(GithubActionsResultServiceError::EvidenceMismatch);
        }
        proposal.evidence.verify_digest()?;
        proposal.verify_digest()?;
        Ok(())
    }

    pub fn verify(
        &self,
        proposal: &GithubActionsResultProposal,
    ) -> Result<(), GithubActionsResultServiceError> {
        self.verify_proposal(proposal)
    }

    pub fn record_observation(
        &self,
        proposal: &GithubActionsResultProposal,
    ) -> Result<GithubActionsObservationReceipt, GithubActionsResultServiceError> {
        self.verify_proposal(proposal)?;
        let response_receipt_digests = proposal
            .evidence
            .response_receipts
            .iter()
            .map(canonical_digest)
            .collect::<Vec<_>>();
        let receipt_digest = canonical_digest(&(
            "github-actions-observation-receipt/v1",
            &proposal.proposal_digest,
            &proposal.evidence.evidence_digest,
            &response_receipt_digests,
            self.provider.provenance(),
        ));
        Ok(GithubActionsObservationReceipt {
            provider_id: GITHUB_ACTIONS_PROVIDER_ID.to_owned(),
            provider_version: GITHUB_ACTIONS_PROVIDER_VERSION.to_owned(),
            api_revision: GITHUB_ACTIONS_API_REVISION.to_owned(),
            provenance: self.provider.provenance(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            response_receipt_digests,
            receipt_digest,
            durable_native_receipt: false,
            native: false,
            connected: false,
        })
    }

    pub fn record(
        &self,
        proposal: &GithubActionsResultProposal,
    ) -> Result<GithubActionsObservationReceipt, GithubActionsResultServiceError> {
        self.record_observation(proposal)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocationReceipt, GithubActionsResultServiceError> {
        self.provider
            .revoke()
            .map_err(GithubActionsResultServiceError::from)
    }

    pub fn restore_registration(&mut self) -> Result<(), GithubActionsResultServiceError> {
        self.provider
            .restore()
            .map_err(GithubActionsResultServiceError::from)
    }
}

fn observation_state(
    run: &GithubWorkflowRunMetadata,
    jobs: &[GithubJobMetadata],
) -> GithubActionsEvidenceState {
    if run.status != crate::GithubWorkflowRunStatus::Completed {
        return GithubActionsEvidenceState::RunInProgress;
    }
    if jobs.is_empty()
        || jobs
            .iter()
            .any(|job| job.status != crate::GithubJobStatus::Completed || job.conclusion.is_none())
    {
        GithubActionsEvidenceState::Partial
    } else {
        GithubActionsEvidenceState::Complete
    }
}

fn error_state(kind: GithubActionsProviderErrorKind) -> GithubActionsEvidenceState {
    match kind {
        GithubActionsProviderErrorKind::Unauthenticated
        | GithubActionsProviderErrorKind::PermissionDenied
        | GithubActionsProviderErrorKind::NotFound => GithubActionsEvidenceState::AccessLost,
        GithubActionsProviderErrorKind::RateLimited => GithubActionsEvidenceState::RateLimited,
        GithubActionsProviderErrorKind::PartialMetadata
        | GithubActionsProviderErrorKind::ScopeMismatch
        | GithubActionsProviderErrorKind::AttemptMismatch
        | GithubActionsProviderErrorKind::StaleHead => GithubActionsEvidenceState::Partial,
        GithubActionsProviderErrorKind::ArtifactExpired => {
            GithubActionsEvidenceState::ArtifactExpired
        }
        GithubActionsProviderErrorKind::RegistrationRevoked => {
            GithubActionsEvidenceState::ProviderUnknown
        }
        GithubActionsProviderErrorKind::BadRequest
        | GithubActionsProviderErrorKind::Conflict
        | GithubActionsProviderErrorKind::ServerFailure
        | GithubActionsProviderErrorKind::Timeout
        | GithubActionsProviderErrorKind::BlockedEnv
        | GithubActionsProviderErrorKind::ProviderUnknown
        | GithubActionsProviderErrorKind::MalformedResponse
        | GithubActionsProviderErrorKind::ResponseTooLarge
        | GithubActionsProviderErrorKind::PaginationMismatch
        | GithubActionsProviderErrorKind::EtagMismatch
        | GithubActionsProviderErrorKind::Tampered => GithubActionsEvidenceState::ProviderUnknown,
    }
}

fn map_provider_error(error: GithubActionsProviderError) -> GithubActionsResultServiceError {
    if error.kind == GithubActionsProviderErrorKind::RegistrationRevoked {
        GithubActionsResultServiceError::RegistrationRevoked
    } else if error.kind == GithubActionsProviderErrorKind::Tampered {
        GithubActionsResultServiceError::RegistrationDrift
    } else {
        GithubActionsResultServiceError::Provider(error)
    }
}
