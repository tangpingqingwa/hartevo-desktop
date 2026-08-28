//! Crowdin provider registration, bounded reads, and redacted recording.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::model::{
    CrowdinLocalizationResultProposal, CrowdinLocalizationScope, CrowdinReadReceipt, Digest,
    LocalizationObservation, LocalizationResultReceipt, ObservationWindow, ReadCursor,
    SecretReference, TransportProvenance,
};
use crate::service::CrowdinLocalizationResultService;
use crate::transport::{
    CrowdinNormalizedResponse, CrowdinReadRequest, CrowdinReadResponse, CrowdinReadTransport,
    CrowdinTransportError,
};
use crate::{
    CROWDIN_LOCALIZATION_RESULT_CONTRACT_VERSION, CROWDIN_LOCALIZATION_RESULT_PLUGIN_VERSION_TEXT,
    CROWDIN_PROVIDER_ID, CROWDIN_PROVIDER_REVISION, CrowdinError, contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrowdinRegistrationRequest {
    pub scope: CrowdinLocalizationScope,
    pub secret_reference: SecretReference,
    pub provider_revision: String,
    pub registration_revision: u64,
}

impl CrowdinRegistrationRequest {
    pub fn new(
        scope: CrowdinLocalizationScope,
        secret_reference: SecretReference,
    ) -> Result<Self, CrowdinError> {
        Self::with_revision(scope, secret_reference, CROWDIN_PROVIDER_REVISION, 1)
    }

    pub fn with_revision(
        scope: CrowdinLocalizationScope,
        secret_reference: SecretReference,
        provider_revision: impl Into<String>,
        registration_revision: u64,
    ) -> Result<Self, CrowdinError> {
        if registration_revision == 0 {
            return Err(CrowdinError::InvalidInput(
                "registration revision must be positive".to_owned(),
            ));
        }
        Ok(Self {
            scope,
            secret_reference,
            provider_revision: provider_revision.into(),
            registration_revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrowdinRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: String,
    pub scope: CrowdinLocalizationScope,
    pub scope_digest: Digest,
    pub secret_reference: SecretReference,
    pub secret_reference_digest: Digest,
    pub registration_revision: u64,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl CrowdinRegistration {
    pub fn new(request: CrowdinRegistrationRequest) -> Result<Self, CrowdinError> {
        crate::CrowdinLocalizationResultContract::baseline()?;
        if request.provider_revision != CROWDIN_PROVIDER_REVISION {
            return Err(CrowdinError::ProviderRevisionMismatch);
        }
        let scope_digest = request.scope.digest();
        let secret_reference_digest = request.secret_reference.reference_digest().clone();
        let mut registration = Self {
            plugin_version: CROWDIN_LOCALIZATION_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: CROWDIN_LOCALIZATION_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: CROWDIN_PROVIDER_ID.to_owned(),
            provider_revision: request.provider_revision,
            scope: request.scope,
            scope_digest,
            secret_reference: request.secret_reference,
            secret_reference_digest,
            registration_revision: request.registration_revision,
            state: RegistrationState::Active,
            registration_digest: Digest::from_bytes(b"uninitialized-crowdin-registration"),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "crowdin-registration/v1",
            &[
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.contract_digest.to_string(),
                self.provider_id.clone(),
                self.provider_revision.clone(),
                self.scope_digest.to_string(),
                self.secret_reference_digest.to_string(),
                self.registration_revision.to_string(),
                serde_json::to_string(&self.state).expect("registration state serializes"),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), CrowdinError> {
        if self.plugin_version != CROWDIN_LOCALIZATION_RESULT_PLUGIN_VERSION_TEXT
            || self.contract_version != CROWDIN_LOCALIZATION_RESULT_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != CROWDIN_PROVIDER_ID
            || self.provider_revision != CROWDIN_PROVIDER_REVISION
            || self.scope_digest != self.scope.digest()
            || self.secret_reference_digest != *self.secret_reference.reference_digest()
            || self.registration_revision == 0
            || self.registration_digest != self.compute_digest()
        {
            return Err(CrowdinError::RegistrationDrift(
                "version, provider, scope, secret, or digest fence changed".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), CrowdinError> {
        self.validate()?;
        if self.state == RegistrationState::Revoked {
            return Err(CrowdinError::RegistrationRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }
}

#[derive(Debug)]
pub struct CrowdinProvider<T> {
    transport: T,
    registration: CrowdinRegistration,
    service: CrowdinLocalizationResultService,
    seen_proposals: BTreeSet<Digest>,
    recorded_observations: BTreeSet<Digest>,
}

impl<T: CrowdinReadTransport> CrowdinProvider<T> {
    pub fn new(
        transport: T,
        scope: CrowdinLocalizationScope,
        secret_reference: SecretReference,
    ) -> Result<Self, CrowdinError> {
        let registration =
            CrowdinRegistration::new(CrowdinRegistrationRequest::new(scope, secret_reference)?)?;
        Self::from_registration(transport, registration)
    }

    pub fn from_registration(
        transport: T,
        registration: CrowdinRegistration,
    ) -> Result<Self, CrowdinError> {
        registration.validate()?;
        Ok(Self {
            transport,
            registration,
            service: CrowdinLocalizationResultService::new(),
            seen_proposals: BTreeSet::new(),
            recorded_observations: BTreeSet::new(),
        })
    }

    pub fn registration(&self) -> &CrowdinRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &CrowdinLocalizationScope {
        &self.registration.scope
    }

    pub fn service(&self) -> &CrowdinLocalizationResultService {
        &self.service
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub fn propose(
        &self,
        observation_window: ObservationWindow,
    ) -> Result<CrowdinLocalizationResultProposal, CrowdinError> {
        self.ensure_active()?;
        self.service.compile_proposal(
            &self.registration.scope,
            &self.registration.secret_reference,
            observation_window,
        )
    }

    pub fn compile_proposal(
        &self,
        observation_window: ObservationWindow,
    ) -> Result<CrowdinLocalizationResultProposal, CrowdinError> {
        self.propose(observation_window)
    }

    pub fn read(
        &mut self,
        proposal: &CrowdinLocalizationResultProposal,
    ) -> Result<LocalizationObservation, CrowdinError> {
        self.ensure_active()?;
        self.validate_proposal(proposal)?;
        if self.seen_proposals.contains(&proposal.proposal_digest) {
            return Err(CrowdinError::DuplicateEvidence);
        }
        let mut project_metadata = None;
        let mut language_coverage = None;
        let mut source_file = None;
        let mut translation_progress = None;
        let mut build_status = None;
        let mut receipts = Vec::new();
        for operation in &proposal.operations {
            let request = CrowdinReadRequest::new(
                &self.registration.scope,
                *operation,
                proposal.observation_window,
                proposal.bounds,
                ReadCursor::first(),
            )?;
            let (response, retries) = self.execute_bounded_get(&request)?;
            let receipt = CrowdinReadReceipt {
                operation: *operation,
                request_digest: request.request_digest.clone(),
                response_status: response.status,
                response_bytes: response.response_bytes,
                response_digest: response.response_digest.clone(),
                provider_revision: self.registration.provider_revision.clone(),
                retry_count: retries.saturating_add(response.retry_count),
                raw_body_retained: response.raw_body_retained,
                credential_material_retained: response.credential_material_retained,
            };
            receipts.push(receipt);
            match response.normalized {
                CrowdinNormalizedResponse::ProjectMetadata(value) => project_metadata = Some(value),
                CrowdinNormalizedResponse::LanguageCoverage(values) => {
                    language_coverage = values.into_iter().find(|value| {
                        value.project_id == self.scope().crowdin_project
                            && value.branch_id == self.scope().source_branch.id
                            && value.language == self.scope().target_language
                    });
                }
                CrowdinNormalizedResponse::SourceFileMetadata(value) => source_file = Some(value),
                CrowdinNormalizedResponse::TranslationProgress(values) => {
                    translation_progress = values.into_iter().find(|value| {
                        value.project_id == self.scope().crowdin_project
                            && value.branch_id == self.scope().source_branch.id
                            && value.file_id == self.scope().source_file.id
                            && value.language == self.scope().target_language
                    });
                }
                CrowdinNormalizedResponse::TranslationBuildStatus(values) => {
                    build_status = values.into_iter().find(|value| {
                        value.project_id == self.scope().crowdin_project
                            && value.branch_id == self.scope().source_branch.id
                            && value.file_id == self.scope().source_file.id
                            && value.language == self.scope().target_language
                    });
                }
            }
        }
        let observation = LocalizationObservation::new(
            proposal,
            project_metadata
                .ok_or_else(|| CrowdinError::IncompleteEvidence("project metadata".to_owned()))?,
            language_coverage.ok_or_else(|| {
                CrowdinError::IncompleteEvidence("target language coverage".to_owned())
            })?,
            source_file.ok_or_else(|| {
                CrowdinError::IncompleteEvidence("source file metadata".to_owned())
            })?,
            translation_progress.ok_or_else(|| {
                CrowdinError::IncompleteEvidence("target language translation progress".to_owned())
            })?,
            build_status.ok_or_else(|| {
                CrowdinError::IncompleteEvidence("target language build status".to_owned())
            })?,
            receipts,
            self.provenance(),
        )?;
        self.seen_proposals.insert(proposal.proposal_digest.clone());
        Ok(observation)
    }

    pub fn read_proposal(
        &mut self,
        proposal: &CrowdinLocalizationResultProposal,
    ) -> Result<LocalizationObservation, CrowdinError> {
        self.read(proposal)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn record(
        &mut self,
        observation: LocalizationObservation,
        recorded_at_epoch_seconds: u64,
    ) -> Result<LocalizationResultReceipt, CrowdinError> {
        self.ensure_active()?;
        self.registration.validate()?;
        observation.validate()?;
        if observation.scope_digest != self.registration.scope_digest
            || observation
                .receipts
                .iter()
                .any(|receipt| receipt.provider_revision != self.registration.provider_revision)
        {
            return Err(CrowdinError::ScopeMismatch(
                "recorded evidence does not match the active registration".to_owned(),
            ));
        }
        if !self
            .recorded_observations
            .insert(observation.observation_digest.clone())
        {
            return Err(CrowdinError::DuplicateEvidence);
        }
        Ok(LocalizationResultReceipt::new(
            &observation,
            self.registration.provider_revision.clone(),
            recorded_at_epoch_seconds,
        )?)
    }

    pub fn record_observation(
        &mut self,
        observation: LocalizationObservation,
        recorded_at_epoch_seconds: u64,
    ) -> Result<LocalizationResultReceipt, CrowdinError> {
        self.record(observation, recorded_at_epoch_seconds)
    }

    pub fn revoke_registration(&mut self) -> Result<(), CrowdinError> {
        self.registration.revoke()
    }

    fn ensure_active(&self) -> Result<(), CrowdinError> {
        self.registration.validate()?;
        if self.registration.state != RegistrationState::Active {
            return Err(CrowdinError::RegistrationRevoked);
        }
        Ok(())
    }

    fn validate_proposal(
        &self,
        proposal: &CrowdinLocalizationResultProposal,
    ) -> Result<(), CrowdinError> {
        proposal.validate()?;
        if proposal.contract_digest != self.registration.contract_digest {
            return Err(CrowdinError::ContractDigestMismatch);
        }
        if proposal.scope_digest != self.registration.scope_digest
            || proposal.secret_reference_digest != self.registration.secret_reference_digest
            || proposal.provider_revision != self.registration.provider_revision
        {
            return Err(CrowdinError::ScopeMismatch(
                "proposal is not bound to the active registration".to_owned(),
            ));
        }
        Ok(())
    }

    fn execute_bounded_get(
        &mut self,
        request: &CrowdinReadRequest,
    ) -> Result<(CrowdinReadResponse, u8), CrowdinError> {
        let mut retries = 0;
        loop {
            match self.transport.get(request) {
                Ok(response) => {
                    response.validate(request.bounds)?;
                    return Ok((response, retries));
                }
                Err(CrowdinTransportError::RateLimited { retry_after_ms }) => {
                    if retry_after_ms > request.bounds.max_backoff_ms {
                        return Err(CrowdinTransportError::BackoffOutOfBounds.into());
                    }
                    if retries >= request.bounds.max_retries {
                        return Err(CrowdinTransportError::RetryBudgetExceeded.into());
                    }
                    retries = retries.saturating_add(1);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl<T: CrowdinReadTransport> CrowdinProvider<T> {
    pub fn definition(&self) -> &'static str {
        CROWDIN_PROVIDER_ID
    }

    pub fn provider_revision(&self) -> &str {
        &self.registration.provider_revision
    }
}

impl<T: CrowdinReadTransport> fmt::Display for CrowdinProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CrowdinProvider({})",
            self.registration.provider_revision
        )
    }
}
