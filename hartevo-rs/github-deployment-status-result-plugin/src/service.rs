use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::{
    Digest, GITHUB_DEPLOYMENT_STATUS_API_REVISION, GITHUB_DEPLOYMENT_STATUS_PROVIDER_ID,
    GITHUB_DEPLOYMENT_STATUS_PROVIDER_VERSION, GITHUB_DEPLOYMENT_STATUS_RESULT_CONTRACT_VERSION,
    GITHUB_DEPLOYMENT_STATUS_RESULT_PLUGIN_VERSION, GITHUB_DEPLOYMENT_STATUS_RESULT_SCHEMA_VERSION,
    GITHUB_DEPLOYMENT_STATUS_SERVICE_ID, GithubDeploymentMetadata, GithubDeploymentStatusMetadata,
    GithubDeploymentStatusProvider, GithubDeploymentStatusProviderDefinitionError,
    GithubDeploymentStatusProviderError, GithubDeploymentStatusProviderErrorKind,
    GithubDeploymentStatusRegistration, GithubDeploymentStatusScope, GithubDeploymentStatusState,
    GithubDeploymentStatusTransport, Layer1Authority, MAX_DIAGNOSTIC_BYTES,
    RegistrationRevocationReceipt, RegistrationState, Revision, TransportProvenance,
    canonical_digest, contract_digest, version_digest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubDeploymentStatusEvidenceState {
    Complete,
    Partial,
    HistoryTruncated,
    AccessLost,
    NotFound,
    RateLimited,
    StaleState,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDeploymentStatusProviderErrorEvidence {
    pub kind: GithubDeploymentStatusProviderErrorKind,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDeploymentStatusEvidence {
    pub schema_version: String,
    pub plugin_version: String,
    pub version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub api_digest: Digest,
    pub provider_digest: Digest,
    pub installation_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub repository_digest: Digest,
    pub deployment_scope_digest: Digest,
    pub ref_digest: Digest,
    pub commit_digest: Digest,
    pub environment_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provenance: TransportProvenance,
    pub deployment: Option<GithubDeploymentMetadata>,
    pub statuses: Vec<GithubDeploymentStatusMetadata>,
    pub latest_status: Option<GithubDeploymentStatusMetadata>,
    pub history_truncated: bool,
    pub pages_read: usize,
    pub request_receipt_digests: Vec<Digest>,
    pub response_receipt_digests: Vec<Digest>,
    pub provider_error: Option<GithubDeploymentStatusProviderErrorEvidence>,
    pub state: GithubDeploymentStatusEvidenceState,
    pub evidence_digest: Digest,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub durable_receipt: bool,
    pub adopts_outcome: bool,
    pub authority: Layer1Authority,
}

impl GithubDeploymentStatusEvidence {
    fn from_observation(
        scope: &GithubDeploymentStatusScope,
        registration: &GithubDeploymentStatusRegistration,
        provider: &GithubDeploymentStatusProviderView,
        observation: crate::GithubDeploymentStatusObservation,
    ) -> Self {
        let state = if observation.history_truncated {
            GithubDeploymentStatusEvidenceState::HistoryTruncated
        } else if observation.statuses.is_empty() {
            GithubDeploymentStatusEvidenceState::Partial
        } else {
            GithubDeploymentStatusEvidenceState::Complete
        };
        let latest_status = observation.statuses.first().cloned();
        let request_receipt_digests = observation
            .request_receipts
            .iter()
            .map(|receipt| receipt.request_digest.clone())
            .collect::<Vec<_>>();
        let response_receipt_digests = observation
            .response_receipts
            .iter()
            .map(|receipt| receipt.response_digest.clone())
            .collect::<Vec<_>>();
        Self::new(
            scope,
            registration,
            provider,
            state,
            observation.provenance,
            Some(observation.deployment),
            observation.statuses,
            latest_status,
            observation.history_truncated,
            observation.pages_read,
            request_receipt_digests,
            response_receipt_digests,
            None,
            observation.authority,
        )
    }

    fn from_provider_error(
        scope: &GithubDeploymentStatusScope,
        registration: &GithubDeploymentStatusRegistration,
        provider: &GithubDeploymentStatusProviderView,
        error: GithubDeploymentStatusProviderError,
    ) -> Self {
        let state = error_state(error.kind);
        let request_receipt_digests = error
            .request_receipts
            .iter()
            .map(|receipt| receipt.request_digest.clone())
            .collect::<Vec<_>>();
        let response_receipt_digests = error
            .response_receipts
            .iter()
            .map(|receipt| receipt.response_digest.clone())
            .collect::<Vec<_>>();
        let provider_error = Some(GithubDeploymentStatusProviderErrorEvidence {
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
            None,
            false,
            0,
            request_receipt_digests,
            response_receipt_digests,
            provider_error,
            Layer1Authority::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        scope: &GithubDeploymentStatusScope,
        registration: &GithubDeploymentStatusRegistration,
        provider: &GithubDeploymentStatusProviderView,
        state: GithubDeploymentStatusEvidenceState,
        provenance: TransportProvenance,
        deployment: Option<GithubDeploymentMetadata>,
        statuses: Vec<GithubDeploymentStatusMetadata>,
        latest_status: Option<GithubDeploymentStatusMetadata>,
        history_truncated: bool,
        pages_read: usize,
        request_receipt_digests: Vec<Digest>,
        response_receipt_digests: Vec<Digest>,
        provider_error: Option<GithubDeploymentStatusProviderErrorEvidence>,
        authority: Layer1Authority,
    ) -> Self {
        let mut evidence = Self {
            schema_version: GITHUB_DEPLOYMENT_STATUS_RESULT_SCHEMA_VERSION.to_owned(),
            plugin_version: GITHUB_DEPLOYMENT_STATUS_RESULT_PLUGIN_VERSION.to_owned(),
            version_digest: version_digest(),
            contract_version: GITHUB_DEPLOYMENT_STATUS_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: GITHUB_DEPLOYMENT_STATUS_PROVIDER_ID.to_owned(),
            provider_version: GITHUB_DEPLOYMENT_STATUS_PROVIDER_VERSION.to_owned(),
            api_revision: GITHUB_DEPLOYMENT_STATUS_API_REVISION.to_owned(),
            api_digest: provider.api_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            installation_digest: scope.installation_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.digest().clone(),
            repository_digest: scope.repository_digest().clone(),
            deployment_scope_digest: scope.deployment_digest().clone(),
            ref_digest: scope.ref_digest().clone(),
            commit_digest: scope.commit_digest().clone(),
            environment_digest: scope.environment_digest().clone(),
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            provenance,
            deployment,
            statuses,
            latest_status,
            history_truncated,
            pages_read,
            request_receipt_digests,
            response_receipt_digests,
            provider_error,
            state,
            evidence_digest: String::new(),
            proposal_only: true,
            native: false,
            connected: false,
            durable_receipt: false,
            adopts_outcome: false,
            authority,
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.evidence_digest.clear();
        canonical_digest(&value)
    }

    pub fn verify_integrity(&self) -> Result<(), GithubDeploymentStatusServiceError> {
        if self.evidence_digest != self.compute_digest() {
            return Err(GithubDeploymentStatusServiceError::EvidenceMismatch);
        }
        if self.native
            || self.connected
            || self.durable_receipt
            || self.adopts_outcome
            || !self.proposal_only
            || self.authority.native
            || self.authority.connected
            || self.authority.outcome_authority
        {
            return Err(GithubDeploymentStatusServiceError::EvidenceMismatch);
        }
        if let Some(deployment) = &self.deployment {
            deployment
                .validate_integrity()
                .map_err(|_| GithubDeploymentStatusServiceError::EvidenceMismatch)?;
        }
        for status in &self.statuses {
            status
                .validate_integrity()
                .map_err(|_| GithubDeploymentStatusServiceError::EvidenceMismatch)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn latest_state(&self) -> Option<GithubDeploymentStatusState> {
        self.latest_status
            .as_ref()
            .map(|status| status.state.clone())
    }

    #[must_use]
    pub fn is_review_only(&self) -> bool {
        self.proposal_only && !self.adopts_outcome
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDeploymentStatusResultProposal {
    pub evidence: GithubDeploymentStatusEvidence,
    pub source_evidence_digest: Digest,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub proposal_digest: Digest,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub adopts_outcome: bool,
}

impl GithubDeploymentStatusResultProposal {
    fn new(evidence: GithubDeploymentStatusEvidence) -> Self {
        let mut proposal = Self {
            source_evidence_digest: evidence.evidence_digest.clone(),
            version_digest: evidence.version_digest.clone(),
            contract_digest: evidence.contract_digest.clone(),
            provider_digest: evidence.provider_digest.clone(),
            permission_digest: evidence.permission_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            registration_revision: evidence.registration_revision,
            proposal_digest: String::new(),
            proposal_only: true,
            native: false,
            connected: false,
            adopts_outcome: false,
            evidence,
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.proposal_digest.clear();
        canonical_digest(&value)
    }

    pub fn verify_digest(&self) -> Result<(), GithubDeploymentStatusServiceError> {
        if self.proposal_digest != self.compute_digest() {
            Err(GithubDeploymentStatusServiceError::ProposalTampered)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub const fn is_review_only(&self) -> bool {
        self.proposal_only && !self.adopts_outcome
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDeploymentStatusObservationReceipt {
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub response_receipt_digests: Vec<Digest>,
    pub receipt_digest: Digest,
    pub durable_native_receipt: bool,
    pub native: bool,
    pub connected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GithubDeploymentStatusServiceDefinition {
    pub service_id: String,
    pub version: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub external_writes: bool,
    pub native: bool,
    pub connected: bool,
    pub durable_receipt: bool,
    pub kernel_authority: bool,
    pub outcome_authority: bool,
}

impl Default for GithubDeploymentStatusServiceDefinition {
    fn default() -> Self {
        Self {
            service_id: GITHUB_DEPLOYMENT_STATUS_SERVICE_ID.to_owned(),
            version: "1.0.0".to_owned(),
            read_only: true,
            proposal_only: true,
            external_writes: false,
            native: false,
            connected: false,
            durable_receipt: false,
            kernel_authority: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GithubDeploymentStatusServiceError {
    #[error("GitHub Deployment Status registration is revoked")]
    RegistrationRevoked,
    #[error("GitHub Deployment Status registration is stale or tampered")]
    RegistrationDrift,
    #[error("GitHub Deployment Status evidence or proposal digest mismatch")]
    EvidenceMismatch,
    #[error("GitHub Deployment Status proposal is tampered")]
    ProposalTampered,
    #[error("GitHub Deployment Status provider definition is invalid: {0}")]
    ProviderDefinition(#[from] GithubDeploymentStatusProviderDefinitionError),
    #[error("GitHub Deployment Status provider error: {0}")]
    Provider(#[from] GithubDeploymentStatusProviderError),
}

#[derive(Clone, Debug)]
struct GithubDeploymentStatusProviderView {
    provider_digest: Digest,
    api_digest: Digest,
    provenance: TransportProvenance,
}

pub struct GithubDeploymentStatusService<T: GithubDeploymentStatusTransport> {
    provider: GithubDeploymentStatusProvider<T>,
    definition: GithubDeploymentStatusServiceDefinition,
}

impl<T: GithubDeploymentStatusTransport> fmt::Debug for GithubDeploymentStatusService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeploymentStatusService")
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

impl<T: GithubDeploymentStatusTransport> GithubDeploymentStatusService<T> {
    pub fn new(
        provider: GithubDeploymentStatusProvider<T>,
    ) -> Result<Self, GithubDeploymentStatusServiceError> {
        provider
            .definition()
            .validate(provider.scope())
            .map_err(GithubDeploymentStatusServiceError::from)?;
        provider
            .validate_registration()
            .map_err(map_provider_error)?;
        Ok(Self {
            provider,
            definition: GithubDeploymentStatusServiceDefinition::default(),
        })
    }

    #[must_use]
    pub fn provider(&self) -> &GithubDeploymentStatusProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut GithubDeploymentStatusProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn definition(&self) -> &GithubDeploymentStatusServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn scope(&self) -> &GithubDeploymentStatusScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &GithubDeploymentStatusRegistration {
        self.provider.registration()
    }

    fn provider_view(&self) -> GithubDeploymentStatusProviderView {
        GithubDeploymentStatusProviderView {
            provider_digest: self.provider.provider_digest().clone(),
            api_digest: self.provider.definition().api_digest.clone(),
            provenance: self.provider.provenance(),
        }
    }

    pub fn read(
        &mut self,
    ) -> Result<GithubDeploymentStatusEvidence, GithubDeploymentStatusServiceError> {
        self.ensure_active()?;
        let view = self.provider_view();
        let registration = self.registration().clone();
        match self.provider.read() {
            Ok(observation) => Ok(GithubDeploymentStatusEvidence::from_observation(
                self.scope(),
                &registration,
                &view,
                observation,
            )),
            Err(error)
                if error.kind == GithubDeploymentStatusProviderErrorKind::RegistrationRevoked =>
            {
                Err(map_provider_error(error))
            }
            Err(error) => Ok(GithubDeploymentStatusEvidence::from_provider_error(
                self.scope(),
                &registration,
                &view,
                error,
            )),
        }
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<GithubDeploymentStatusResultProposal, GithubDeploymentStatusServiceError> {
        let evidence = self.read()?;
        Ok(GithubDeploymentStatusResultProposal::new(evidence))
    }

    pub fn verify_proposal(
        &self,
        proposal: &GithubDeploymentStatusResultProposal,
    ) -> Result<(), GithubDeploymentStatusServiceError> {
        self.ensure_active()?;
        if !proposal.proposal_only
            || proposal.native
            || proposal.connected
            || proposal.adopts_outcome
            || proposal.source_evidence_digest != proposal.evidence.evidence_digest
            || proposal.version_digest != version_digest()
            || proposal.contract_digest != contract_digest()
            || proposal.provider_digest != *self.provider.provider_digest()
            || proposal.permission_digest != *self.scope().permission_digest()
            || proposal.scope_digest != *self.scope().digest()
            || proposal.registration_digest != self.registration().registration_digest
            || proposal.registration_revision != self.registration().registration_revision
            || proposal.evidence.version_digest != version_digest()
            || proposal.evidence.contract_digest != contract_digest()
            || proposal.evidence.provider_digest != *self.provider.provider_digest()
            || proposal.evidence.permission_digest != *self.scope().permission_digest()
            || proposal.evidence.scope_digest != *self.scope().digest()
            || proposal.evidence.registration_digest != self.registration().registration_digest
            || proposal.evidence.registration_revision != self.registration().registration_revision
            || !proposal.evidence.proposal_only
            || proposal.evidence.native
            || proposal.evidence.connected
            || proposal.evidence.durable_receipt
            || proposal.evidence.adopts_outcome
        {
            return Err(GithubDeploymentStatusServiceError::EvidenceMismatch);
        }
        proposal.evidence.verify_integrity()?;
        proposal.verify_digest()?;
        Ok(())
    }

    pub fn verify(
        &self,
        proposal: &GithubDeploymentStatusResultProposal,
    ) -> Result<(), GithubDeploymentStatusServiceError> {
        self.verify_proposal(proposal)
    }

    pub fn record_observation(
        &self,
        proposal: &GithubDeploymentStatusResultProposal,
    ) -> Result<GithubDeploymentStatusObservationReceipt, GithubDeploymentStatusServiceError> {
        self.verify_proposal(proposal)?;
        let receipt_digest = canonical_digest(&(
            "github-deployment-status-observation-receipt/v1",
            &proposal.evidence.evidence_digest,
            &proposal.proposal_digest,
            &proposal.evidence.response_receipt_digests,
            self.provider.provenance(),
        ));
        Ok(GithubDeploymentStatusObservationReceipt {
            provider_id: GITHUB_DEPLOYMENT_STATUS_PROVIDER_ID.to_owned(),
            provider_version: GITHUB_DEPLOYMENT_STATUS_PROVIDER_VERSION.to_owned(),
            api_revision: GITHUB_DEPLOYMENT_STATUS_API_REVISION.to_owned(),
            provenance: self.provider.provenance(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            response_receipt_digests: proposal.evidence.response_receipt_digests.clone(),
            receipt_digest,
            durable_native_receipt: false,
            native: false,
            connected: false,
        })
    }

    pub fn record(
        &self,
        proposal: &GithubDeploymentStatusResultProposal,
    ) -> Result<GithubDeploymentStatusObservationReceipt, GithubDeploymentStatusServiceError> {
        self.record_observation(proposal)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocationReceipt, GithubDeploymentStatusServiceError> {
        self.provider
            .revoke()
            .map_err(|_| GithubDeploymentStatusServiceError::RegistrationDrift)
    }

    pub fn restore_registration(&mut self) -> Result<(), GithubDeploymentStatusServiceError> {
        self.provider
            .restore()
            .map_err(|_| GithubDeploymentStatusServiceError::RegistrationDrift)
    }

    fn ensure_active(&self) -> Result<(), GithubDeploymentStatusServiceError> {
        if self.registration().state == RegistrationState::Active
            && !self.provider.secret_reference().is_revoked()
        {
            Ok(())
        } else {
            Err(GithubDeploymentStatusServiceError::RegistrationRevoked)
        }
    }
}

fn error_state(
    kind: GithubDeploymentStatusProviderErrorKind,
) -> GithubDeploymentStatusEvidenceState {
    match kind {
        GithubDeploymentStatusProviderErrorKind::Unauthenticated
        | GithubDeploymentStatusProviderErrorKind::PermissionDenied => {
            GithubDeploymentStatusEvidenceState::AccessLost
        }
        GithubDeploymentStatusProviderErrorKind::NotFound => {
            GithubDeploymentStatusEvidenceState::NotFound
        }
        GithubDeploymentStatusProviderErrorKind::RateLimited => {
            GithubDeploymentStatusEvidenceState::RateLimited
        }
        GithubDeploymentStatusProviderErrorKind::ScopeMismatch
        | GithubDeploymentStatusProviderErrorKind::StaleState => {
            GithubDeploymentStatusEvidenceState::StaleState
        }
        GithubDeploymentStatusProviderErrorKind::RegistrationRevoked => {
            GithubDeploymentStatusEvidenceState::ProviderUnknown
        }
        GithubDeploymentStatusProviderErrorKind::BadRequest
        | GithubDeploymentStatusProviderErrorKind::Conflict
        | GithubDeploymentStatusProviderErrorKind::UnprocessableEntity
        | GithubDeploymentStatusProviderErrorKind::ServerFailure
        | GithubDeploymentStatusProviderErrorKind::Timeout
        | GithubDeploymentStatusProviderErrorKind::BlockedEnv
        | GithubDeploymentStatusProviderErrorKind::ProviderUnknown
        | GithubDeploymentStatusProviderErrorKind::MalformedResponse
        | GithubDeploymentStatusProviderErrorKind::ResponseTooLarge
        | GithubDeploymentStatusProviderErrorKind::PaginationMismatch
        | GithubDeploymentStatusProviderErrorKind::EtagMismatch
        | GithubDeploymentStatusProviderErrorKind::Tampered => {
            GithubDeploymentStatusEvidenceState::ProviderUnknown
        }
    }
}

fn map_provider_error(
    error: GithubDeploymentStatusProviderError,
) -> GithubDeploymentStatusServiceError {
    match error.kind {
        GithubDeploymentStatusProviderErrorKind::RegistrationRevoked => {
            GithubDeploymentStatusServiceError::RegistrationRevoked
        }
        GithubDeploymentStatusProviderErrorKind::Tampered => {
            GithubDeploymentStatusServiceError::RegistrationDrift
        }
        _ => GithubDeploymentStatusServiceError::Provider(error),
    }
}

#[allow(dead_code)]
fn _bound_diagnostic_size() -> usize {
    MAX_DIAGNOSTIC_BYTES
}
