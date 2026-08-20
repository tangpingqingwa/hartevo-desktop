use std::fmt;

use thiserror::Error;

use crate::{
    ConsentScope, Digest, LokaliseEvidenceClassification, LokaliseEvidenceState,
    LokaliseLocalizationResultEvidence, LokaliseLocalizationResultProposal,
    LokaliseLocalizationResultRecommendation, LokaliseLocalizationScope, LokaliseProvider,
    LokaliseProviderError, LokaliseProviderRead, LokaliseRateLimitReceipt, LokaliseReadOperation,
    LokaliseReadReceipt, LokaliseRecommendationDisposition, LokaliseRegistration,
    LokaliseTransport, MAX_RESPONSE_BYTES, MISSION_LOKALISE_LOCALIZATION_CONSUMER_ID, ModelError,
    ObservationReceipt, TransportProvenance, canonical_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LokaliseLocalizationResultServiceError {
    #[error("Lokalise registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Lokalise SecretReference is revoked")]
    SecretRevoked,
    #[error("Lokalise permission set is missing")]
    MissingPermission,
    #[error("Lokalise scope does not match")]
    ScopeMismatch,
    #[error("Lokalise read consent is denied or stale")]
    ConsentMismatch,
    #[error("Lokalise cursor is invalid")]
    InvalidCursor,
    #[error("Lokalise evidence or proposal digest fence failed")]
    EvidenceMismatch,
    #[error("Lokalise proposal replay was rejected")]
    ReplayDetected,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LokaliseLocalizationResultServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub emits_outcome: bool,
    pub external_writes: bool,
}

impl Default for LokaliseLocalizationResultServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: crate::LOKALISE_LOCALIZATION_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: crate::LOKALISE_LOCALIZATION_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: crate::LOKALISE_LOCALIZATION_RESULT_SERVICE_ID.to_owned(),
            provider_id: crate::LOKALISE_PROVIDER_ID.to_owned(),
            consumer_id: MISSION_LOKALISE_LOCALIZATION_CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            read_only: true,
            live_execution: false,
            emits_outcome: false,
            external_writes: false,
        }
    }
}

/// Layer-1 typed service for bounded, redacted Lokalise localization result
/// evidence. It has no native network, credential, effect, receipt, or
/// adoption authority.
pub struct LokaliseLocalizationResultService<T: LokaliseTransport> {
    provider: LokaliseProvider<T>,
    definition: LokaliseLocalizationResultServiceDefinition,
}

impl<T: LokaliseTransport> fmt::Debug for LokaliseLocalizationResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LokaliseLocalizationResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: LokaliseTransport> LokaliseLocalizationResultService<T> {
    pub fn new(
        provider: LokaliseProvider<T>,
    ) -> Result<Self, LokaliseLocalizationResultServiceError> {
        provider
            .registration()
            .validate(
                provider.scope(),
                provider.secret_reference(),
                &provider.provider_digest(),
            )
            .map_err(|_| LokaliseLocalizationResultServiceError::RegistrationRevoked)?;
        Ok(Self {
            provider,
            definition: LokaliseLocalizationResultServiceDefinition::default(),
        })
    }

    #[must_use]
    pub fn from_provider(provider: LokaliseProvider<T>) -> Self {
        Self {
            provider,
            definition: LokaliseLocalizationResultServiceDefinition::default(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &LokaliseProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut LokaliseProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &LokaliseLocalizationScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &LokaliseRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &LokaliseLocalizationResultServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn issue_read_consent(&self) -> ConsentScope {
        self.scope().consent().clone()
    }

    pub fn read(
        &mut self,
    ) -> Result<LokaliseLocalizationResultEvidence, LokaliseLocalizationResultServiceError> {
        let consent = self.issue_read_consent();
        self.read_with_consent(&consent)
    }

    pub fn read_with_consent(
        &mut self,
        consent: &ConsentScope,
    ) -> Result<LokaliseLocalizationResultEvidence, LokaliseLocalizationResultServiceError> {
        self.validate_consent(consent)?;
        match self.provider.read() {
            Ok(read) => Ok(normalize_success(
                self.scope(),
                self.registration(),
                self.provider.provider_digest(),
                read,
            )),
            Err(error) => match map_hard_provider_error(&error) {
                Some(error) => Err(error),
                None => Ok(normalize_failure(
                    self.scope(),
                    self.registration(),
                    self.provider.provider_digest(),
                    self.provider.transport_provenance(),
                    &error,
                )),
            },
        }
    }

    pub fn read_from_cursor(
        &mut self,
        consent: &ConsentScope,
        cursor: Option<&str>,
    ) -> Result<LokaliseLocalizationResultEvidence, LokaliseLocalizationResultServiceError> {
        self.validate_consent(consent)?;
        match self.provider.read_from_cursor(cursor) {
            Ok(read) => Ok(normalize_success(
                self.scope(),
                self.registration(),
                self.provider.provider_digest(),
                read,
            )),
            Err(error) => match map_hard_provider_error(&error) {
                Some(error) => Err(error),
                None => Ok(normalize_failure(
                    self.scope(),
                    self.registration(),
                    self.provider.provider_digest(),
                    self.provider.transport_provenance(),
                    &error,
                )),
            },
        }
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<LokaliseLocalizationResultProposal, LokaliseLocalizationResultServiceError> {
        let evidence = self.read()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_localization_result_proposal(
        &mut self,
    ) -> Result<LokaliseLocalizationResultProposal, LokaliseLocalizationResultServiceError> {
        self.compile_proposal()
    }

    pub fn compile_proposal_with_consent(
        &mut self,
        consent: &ConsentScope,
    ) -> Result<LokaliseLocalizationResultProposal, LokaliseLocalizationResultServiceError> {
        let evidence = self.read_with_consent(consent)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: LokaliseLocalizationResultEvidence,
    ) -> Result<LokaliseLocalizationResultProposal, LokaliseLocalizationResultServiceError> {
        self.ensure_registration()?;
        self.verify_evidence(&evidence)?;
        let recommendation = recommendation_for(&evidence.state, &evidence);
        let source_evidence_digest = evidence.digest();
        let mut proposal = LokaliseLocalizationResultProposal {
            scope: self.scope().clone(),
            evidence,
            source_evidence_digest,
            registration_digest: self.registration().registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            contract_digest: crate::contract_digest(),
            permission_digest: self.scope().permission().digest(),
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            adopts_outcome: false,
            recommendation,
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.digest();
        Ok(proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &LokaliseLocalizationResultProposal,
    ) -> Result<(), LokaliseLocalizationResultServiceError> {
        self.ensure_registration()?;
        if !proposal.proposal_only
            || proposal.native
            || proposal.connected
            || proposal.first_party
            || proposal.adopts_outcome
            || proposal.scope != *self.scope()
            || proposal.registration_digest != self.registration().registration_digest
            || proposal.provider_digest != self.provider.provider_digest()
            || proposal.contract_digest != crate::contract_digest()
            || proposal.permission_digest != self.scope().permission().digest()
            || proposal.source_evidence_digest != proposal.evidence.digest()
            || proposal.proposal_digest != proposal.digest()
        {
            return Err(LokaliseLocalizationResultServiceError::EvidenceMismatch);
        }
        self.verify_evidence(&proposal.evidence)
    }

    pub fn record_observation(
        &self,
        proposal: &LokaliseLocalizationResultProposal,
    ) -> Result<ObservationReceipt, LokaliseLocalizationResultServiceError> {
        self.verify_proposal(proposal)?;
        Ok(ObservationReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            recorded: true,
            durable: false,
            native: false,
            connected: false,
            first_party: false,
        })
    }

    pub fn read_back(
        &self,
        proposal: &LokaliseLocalizationResultProposal,
    ) -> Result<crate::LokaliseReadbackReceipt, LokaliseLocalizationResultServiceError> {
        self.verify_proposal(proposal)?;
        Ok(crate::LokaliseReadbackReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            status: "verified_against_proposal_only".to_owned(),
            independent_native_readback: false,
            native: false,
            connected: false,
            first_party: false,
        })
    }

    pub fn revoke(
        &mut self,
    ) -> Result<crate::RegistrationRevocationReceipt, LokaliseLocalizationResultServiceError> {
        self.provider.revoke().map_err(map_provider_error)
    }

    pub fn restore(&mut self) -> Result<(), LokaliseLocalizationResultServiceError> {
        self.provider.restore().map_err(map_provider_error)
    }

    pub fn revoke_secret(&mut self) -> Result<(), LokaliseLocalizationResultServiceError> {
        self.provider.revoke_secret().map_err(map_provider_error)
    }

    fn validate_consent(
        &self,
        consent: &ConsentScope,
    ) -> Result<(), LokaliseLocalizationResultServiceError> {
        consent.validate()?;
        if consent == self.scope().consent() {
            Ok(())
        } else {
            Err(LokaliseLocalizationResultServiceError::ConsentMismatch)
        }
    }

    fn ensure_registration(&self) -> Result<(), LokaliseLocalizationResultServiceError> {
        self.registration()
            .validate(
                self.scope(),
                self.provider.secret_reference(),
                &self.provider.provider_digest(),
            )
            .map_err(|_| LokaliseLocalizationResultServiceError::RegistrationRevoked)
    }

    fn verify_evidence(
        &self,
        evidence: &LokaliseLocalizationResultEvidence,
    ) -> Result<(), LokaliseLocalizationResultServiceError> {
        let unique_operations = evidence
            .read_receipts
            .iter()
            .map(|receipt| receipt.operation)
            .collect::<std::collections::BTreeSet<_>>();
        if evidence.evidence_digest != evidence.digest()
            || evidence.scope != *self.scope()
            || evidence.provenance != self.provider.transport_provenance()
            || evidence.provenance.is_native()
            || evidence.provenance.is_connected()
            || evidence.provenance.is_first_party()
            || evidence.native
            || evidence.connected
            || evidence.first_party
            || !evidence.proposal_only
            || evidence.adopts_outcome
            || evidence.digests.contract_digest != crate::contract_digest()
            || evidence.digests.plugin_version_digest
                != canonical_digest(&crate::LOKALISE_LOCALIZATION_RESULT_PLUGIN_VERSION)
            || evidence.digests.provider_digest != self.provider.provider_digest()
            || evidence.digests.permission_digest != self.scope().permission().digest()
            || evidence.digests.scope_digest != *self.scope().scope_digest()
            || evidence.digests.revision_digest != *self.scope().revision_digest()
            || evidence.digests.privacy_digest != *self.scope().privacy_digest()
            || evidence.digests.registration_digest != self.registration().registration_digest
            || evidence.digests.team_digest != self.scope().team_id().digest()
            || evidence.digests.project_digest != self.scope().project_id().digest()
            || evidence.digests.branch_digest != self.scope().branch().digest()
            || evidence.digests.file_digest != self.scope().file_id().digest()
            || evidence.digests.language_digest != self.scope().language().digest()
            || evidence.read_receipts.len() != evidence.rate_limits.len()
            || evidence.read_receipts.is_empty()
            || unique_operations.len() != evidence.read_receipts.len()
            || evidence.aggregate.is_some() && evidence.read_receipts.len() != 6
            || evidence.aggregate.is_none() && evidence.read_receipts.len() != 1
            || !evidence.read_receipts.iter().all(|receipt| {
                receipt.method == crate::LokaliseHttpMethod::Get
                    && endpoint_matches_operation(receipt.operation, &receipt.endpoint)
                    && receipt.request_digest.len() == 64
                    && receipt.response_digest.len() == 64
                    && receipt.rate_limit_digest.len() == 64
                    && receipt.response_bytes <= MAX_RESPONSE_BYTES
                    && receipt
                        .next_cursor_digest
                        .as_ref()
                        .is_none_or(|digest| digest.len() == 64)
            })
            || evidence
                .read_receipts
                .iter()
                .zip(&evidence.rate_limits)
                .any(|(receipt, rate)| {
                    rate.validate().is_err() || receipt.rate_limit_digest != rate.digest()
                })
            || evidence.digests.request_digest
                != canonical_digest(
                    &evidence
                        .read_receipts
                        .iter()
                        .map(|receipt| &receipt.request_digest)
                        .collect::<Vec<_>>(),
                )
            || evidence.digests.response_digest != canonical_digest(&evidence.read_receipts)
            || evidence.aggregate.as_ref().is_some_and(|aggregate| {
                aggregate.state() != evidence.state
                    || evidence.classification != classification_for(&evidence.state)
                    || evidence.digests.content_digest != aggregate.content_digest
                    || evidence.digests.build_digest != aggregate.build_digest
            })
            || evidence.aggregate.is_none()
                && evidence.classification != classification_for(&evidence.state)
            || evidence.aggregate.is_none()
                && (evidence.digests.content_digest != canonical_digest(&"lokalise-no-content")
                    || evidence.digests.build_digest != canonical_digest(&"lokalise-no-build"))
        {
            return Err(LokaliseLocalizationResultServiceError::EvidenceMismatch);
        }
        Ok(())
    }
}

fn map_hard_provider_error(
    error: &LokaliseProviderError,
) -> Option<LokaliseLocalizationResultServiceError> {
    match error {
        LokaliseProviderError::RegistrationRevoked => {
            Some(LokaliseLocalizationResultServiceError::RegistrationRevoked)
        }
        LokaliseProviderError::SecretRevoked => {
            Some(LokaliseLocalizationResultServiceError::SecretRevoked)
        }
        LokaliseProviderError::MissingPermission => {
            Some(LokaliseLocalizationResultServiceError::MissingPermission)
        }
        LokaliseProviderError::ScopeMismatch => {
            Some(LokaliseLocalizationResultServiceError::ScopeMismatch)
        }
        LokaliseProviderError::InvalidCursor => {
            Some(LokaliseLocalizationResultServiceError::InvalidCursor)
        }
        LokaliseProviderError::Model(ModelError::InvalidScope(_)) => {
            Some(LokaliseLocalizationResultServiceError::ScopeMismatch)
        }
        LokaliseProviderError::Model(_) => None,
        LokaliseProviderError::RateLimited { .. }
        | LokaliseProviderError::HttpStatus { .. }
        | LokaliseProviderError::ResponseTooLarge { .. }
        | LokaliseProviderError::MalformedResponse { .. }
        | LokaliseProviderError::InvalidRateLimitReceipt { .. }
        | LokaliseProviderError::Transport { .. } => None,
    }
}

fn map_provider_error(error: LokaliseProviderError) -> LokaliseLocalizationResultServiceError {
    map_hard_provider_error(&error)
        .unwrap_or(LokaliseLocalizationResultServiceError::EvidenceMismatch)
}

fn normalize_success(
    scope: &LokaliseLocalizationScope,
    registration: &LokaliseRegistration,
    provider_digest: Digest,
    read: LokaliseProviderRead,
) -> LokaliseLocalizationResultEvidence {
    let state = read.aggregate.state();
    let classification = classification_for(&state);
    let digests = evidence_digests(
        scope,
        registration,
        provider_digest,
        read.aggregate.content_digest.clone(),
        read.aggregate.build_digest.clone(),
        canonical_digest(
            &read
                .receipts
                .iter()
                .map(|receipt| &receipt.request_digest)
                .collect::<Vec<_>>(),
        ),
        canonical_digest(&read.receipts),
    );
    let mut evidence = LokaliseLocalizationResultEvidence {
        state,
        classification,
        scope: scope.clone(),
        aggregate: Some(read.aggregate),
        read_receipts: read.receipts,
        rate_limits: read.rate_limits,
        digests,
        provenance: read.provenance,
        proposal_only: true,
        native: false,
        connected: false,
        first_party: false,
        adopts_outcome: false,
        evidence_digest: String::new(),
    };
    evidence.evidence_digest = evidence.digest();
    evidence
}

fn normalize_failure(
    scope: &LokaliseLocalizationScope,
    registration: &LokaliseRegistration,
    provider_digest: Digest,
    provenance: TransportProvenance,
    error: &LokaliseProviderError,
) -> LokaliseLocalizationResultEvidence {
    let request = error.request().cloned().unwrap_or_else(|| {
        // Hard scope/registration errors are returned before this seam. This
        // fallback is still bounded and contains no credential material.
        let mut request = crate::LokaliseRequest {
            operation: LokaliseReadOperation::TranslationItems,
            method: crate::LokaliseHttpMethod::Get,
            host: crate::LOKALISE_API_HOST.to_owned(),
            path: LokaliseReadOperation::TranslationItems
                .path_template()
                .to_owned(),
            team_id: scope.team_id().as_str().to_owned(),
            project_id: scope.project_id().as_str().to_owned(),
            branch: scope.branch().clone(),
            file_id: scope.file_id().as_str().to_owned(),
            language_id: scope.language().language_id().as_str().to_owned(),
            limit: crate::MAX_PAGE_SIZE,
            cursor_digest: None,
            scope_digest: scope.scope_digest().clone(),
            consent_digest: scope.consent().digest().clone(),
            secret_reference_digest: canonical_digest(&"secret-reference-unavailable"),
            request_digest: String::new(),
        };
        request.request_digest = request.digest();
        request
    });
    let (response_digest, response_bytes, rate_limit, status_code) = error.metadata().unwrap_or((
        canonical_digest(&("lokalise-provider-error", &request.request_digest)),
        0,
        LokaliseRateLimitReceipt::default(),
        None,
    ));
    let (state, classification) = failure_state(error, provenance);
    let read_receipt = LokaliseReadReceipt {
        operation: request.operation,
        method: request.method,
        endpoint: request.path,
        request_digest: request.request_digest,
        response_digest: response_digest.clone(),
        status_code,
        response_bytes,
        rate_limit_digest: rate_limit.digest(),
        next_cursor_digest: None,
    };
    let digests = evidence_digests(
        scope,
        registration,
        provider_digest,
        canonical_digest(&"lokalise-no-content"),
        canonical_digest(&"lokalise-no-build"),
        canonical_digest(&vec![&read_receipt.request_digest]),
        canonical_digest(std::slice::from_ref(&read_receipt)),
    );
    let mut evidence = LokaliseLocalizationResultEvidence {
        state,
        classification,
        scope: scope.clone(),
        aggregate: None,
        read_receipts: vec![read_receipt],
        rate_limits: vec![rate_limit],
        digests,
        provenance,
        proposal_only: true,
        native: false,
        connected: false,
        first_party: false,
        adopts_outcome: false,
        evidence_digest: String::new(),
    };
    evidence.evidence_digest = evidence.digest();
    evidence
}

fn failure_state(
    error: &LokaliseProviderError,
    provenance: TransportProvenance,
) -> (LokaliseEvidenceState, LokaliseEvidenceClassification) {
    if matches!(error, LokaliseProviderError::RateLimited { .. }) {
        return (
            LokaliseEvidenceState::RateLimited,
            LokaliseEvidenceClassification::RateLimited,
        );
    }
    if matches!(
        error,
        LokaliseProviderError::Transport {
            error: crate::LokaliseTransportError::BlockedEnv,
            ..
        }
    ) {
        return (
            LokaliseEvidenceState::AccessLost,
            LokaliseEvidenceClassification::BlockedEnv,
        );
    }
    if let LokaliseProviderError::HttpStatus { status_code, .. } = error {
        return match status_code {
            401 | 403 | 404 => (
                LokaliseEvidenceState::AccessLost,
                LokaliseEvidenceClassification::AccessLost,
            ),
            410 => (
                LokaliseEvidenceState::Expired,
                LokaliseEvidenceClassification::Expired,
            ),
            429 => (
                LokaliseEvidenceState::RateLimited,
                LokaliseEvidenceClassification::RateLimited,
            ),
            _ => (
                LokaliseEvidenceState::ProviderUnknown,
                LokaliseEvidenceClassification::ProviderUnknown,
            ),
        };
    }
    let classification = if provenance == TransportProvenance::BlockedEnv {
        LokaliseEvidenceClassification::BlockedEnv
    } else {
        LokaliseEvidenceClassification::ProviderUnknown
    };
    (LokaliseEvidenceState::ProviderUnknown, classification)
}

fn classification_for(state: &LokaliseEvidenceState) -> LokaliseEvidenceClassification {
    match state {
        LokaliseEvidenceState::Untranslated => LokaliseEvidenceClassification::Untranslated,
        LokaliseEvidenceState::Translated => LokaliseEvidenceClassification::Translated,
        LokaliseEvidenceState::Unverified => LokaliseEvidenceClassification::Unverified,
        LokaliseEvidenceState::Reviewed => LokaliseEvidenceClassification::Reviewed,
        LokaliseEvidenceState::QaIssue => LokaliseEvidenceClassification::QaIssue,
        LokaliseEvidenceState::Building => LokaliseEvidenceClassification::Building,
        LokaliseEvidenceState::Ready => LokaliseEvidenceClassification::Ready,
        LokaliseEvidenceState::Expired => LokaliseEvidenceClassification::Expired,
        LokaliseEvidenceState::Partial => LokaliseEvidenceClassification::Partial,
        LokaliseEvidenceState::RateLimited => LokaliseEvidenceClassification::RateLimited,
        LokaliseEvidenceState::AccessLost => LokaliseEvidenceClassification::AccessLost,
        LokaliseEvidenceState::ProviderUnknown => LokaliseEvidenceClassification::ProviderUnknown,
    }
}

fn recommendation_for(
    state: &LokaliseEvidenceState,
    evidence: &LokaliseLocalizationResultEvidence,
) -> LokaliseLocalizationResultRecommendation {
    let disposition = match state {
        LokaliseEvidenceState::Untranslated => {
            LokaliseRecommendationDisposition::ReviewUntranslated
        }
        LokaliseEvidenceState::Unverified => LokaliseRecommendationDisposition::ReviewUnverified,
        LokaliseEvidenceState::QaIssue => LokaliseRecommendationDisposition::ReviewQaIssues,
        LokaliseEvidenceState::Building => LokaliseRecommendationDisposition::ReviewBuildReadiness,
        LokaliseEvidenceState::Ready | LokaliseEvidenceState::Reviewed => {
            LokaliseRecommendationDisposition::ReviewLocalizedArtifact
        }
        LokaliseEvidenceState::Translated => {
            if evidence
                .aggregate
                .as_ref()
                .is_some_and(|aggregate| !aggregate.tasks.is_empty())
            {
                LokaliseRecommendationDisposition::ReviewTaskProgress
            } else {
                LokaliseRecommendationDisposition::ReviewLocalizedArtifact
            }
        }
        LokaliseEvidenceState::Partial => {
            LokaliseRecommendationDisposition::NoRecommendationPartial
        }
        LokaliseEvidenceState::RateLimited => {
            LokaliseRecommendationDisposition::NoRecommendationRateLimited
        }
        LokaliseEvidenceState::Expired => {
            LokaliseRecommendationDisposition::NoRecommendationExpired
        }
        LokaliseEvidenceState::AccessLost => {
            LokaliseRecommendationDisposition::NoRecommendationAccessLost
        }
        LokaliseEvidenceState::ProviderUnknown => {
            LokaliseRecommendationDisposition::NoRecommendationProviderUnknown
        }
    };
    LokaliseLocalizationResultRecommendation {
        disposition,
        provider_reported_only: true,
        non_mutating: true,
        claims_translation_quality: false,
        claims_publication: false,
        claims_approval: false,
        rationale_digest: canonical_digest(&(
            "lokalise-localization-recommendation/v1",
            state,
            &evidence.digests.content_digest,
            &evidence.digests.build_digest,
            &disposition,
        )),
    }
}

fn evidence_digests(
    scope: &LokaliseLocalizationScope,
    registration: &LokaliseRegistration,
    provider_digest: Digest,
    content_digest: Digest,
    build_digest: Digest,
    request_digest: Digest,
    response_digest: Digest,
) -> crate::LokaliseEvidenceDigests {
    crate::LokaliseEvidenceDigests {
        plugin_version_digest: canonical_digest(
            &crate::LOKALISE_LOCALIZATION_RESULT_PLUGIN_VERSION,
        ),
        contract_digest: crate::contract_digest(),
        provider_digest,
        permission_digest: scope.permission().digest(),
        scope_digest: scope.scope_digest().clone(),
        revision_digest: scope.revision_digest().clone(),
        privacy_digest: scope.privacy_digest().clone(),
        registration_digest: registration.registration_digest.clone(),
        team_digest: scope.team_id().digest(),
        project_digest: scope.project_id().digest(),
        branch_digest: scope.branch().digest(),
        file_digest: scope.file_id().digest(),
        language_digest: scope.language().digest(),
        content_digest,
        build_digest,
        request_digest,
        response_digest,
    }
}

fn endpoint_matches_operation(operation: LokaliseReadOperation, endpoint: &str) -> bool {
    if !endpoint.starts_with("/api2/projects/") {
        return false;
    }
    match operation {
        LokaliseReadOperation::ProjectMetadata => endpoint
            .strip_prefix("/api2/projects/")
            .is_some_and(|project| !project.is_empty() && !project.contains('/')),
        LokaliseReadOperation::LanguageMetadata => endpoint.ends_with("/languages"),
        LokaliseReadOperation::FileMetadata => endpoint.ends_with("/files"),
        LokaliseReadOperation::TranslationItems => endpoint.ends_with("/translations"),
        LokaliseReadOperation::TaskReviewStatus => endpoint.ends_with("/tasks"),
        LokaliseReadOperation::ExportBuildMetadata => endpoint.ends_with("/processes"),
    }
}

// Explicitly retain the provider version and response bound in this module so
// contract and lint checks cannot accidentally drop them from the service.
#[allow(dead_code)]
fn _bounds_are_bound() -> (usize, &'static str) {
    (MAX_RESPONSE_BYTES, crate::LOKALISE_PROVIDER_VERSION)
}

pub type LokaliseServiceError = LokaliseLocalizationResultServiceError;
pub type LokaliseLocalizationService<T> = LokaliseLocalizationResultService<T>;
