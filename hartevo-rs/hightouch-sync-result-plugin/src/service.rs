use std::fmt;

use thiserror::Error;

use crate::{
    ConsentScope, Digest, HightouchBackoffReceipt, HightouchEvidenceClassification,
    HightouchEvidenceState, HightouchFailureEvidence, HightouchObservationReceipt,
    HightouchPermissionSnapshot, HightouchProvider, HightouchProviderError, HightouchProviderRead,
    HightouchRateLimitReceipt, HightouchReadReceipt, HightouchRecommendation,
    HightouchRecommendationDisposition, HightouchRunProjection, HightouchRunStatus,
    HightouchSyncResultEvidence, HightouchSyncResultProposal, HightouchSyncScope,
    HightouchTransport, HightouchWorkspaceProjection, IdempotencyKey,
    RegistrationTransitionReceipt, TransportProvenance,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HightouchSyncResultServiceError {
    #[error("Hightouch registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Hightouch opaque API-key reference is revoked")]
    SecretRevoked,
    #[error("Hightouch scope or consent does not match")]
    ScopeMismatch,
    #[error("Hightouch read consent is denied or stale")]
    ConsentMismatch,
    #[error("Hightouch evidence or proposal digest fence failed")]
    EvidenceMismatch,
    #[error("Hightouch idempotency key conflicts with a different proposal")]
    IdempotencyConflict,
    #[error(transparent)]
    Model(#[from] crate::ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HightouchSyncResultServiceDefinition {
    pub service_id: String,
    pub version: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub operations: Vec<String>,
}

impl Default for HightouchSyncResultServiceDefinition {
    fn default() -> Self {
        Self {
            service_id: crate::HIGHTOUCH_SYNC_RESULT_SERVICE_ID.to_owned(),
            version: crate::HIGHTOUCH_SYNC_RESULT_PLUGIN_VERSION.to_owned(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            operations: vec![
                "read_workspace_metadata".to_owned(),
                "read_source_metadata".to_owned(),
                "read_model_metadata".to_owned(),
                "read_destination_metadata".to_owned(),
                "read_sync_metadata".to_owned(),
                "read_bounded_run_metadata".to_owned(),
                "compile_sync_result_proposal".to_owned(),
                "record_observation".to_owned(),
                "verify_proposal".to_owned(),
                "revoke_registration".to_owned(),
                "restore_registration".to_owned(),
            ],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HightouchCapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub provider_api_revision: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
}

pub struct HightouchSyncResultService<T: HightouchTransport> {
    provider: HightouchProvider<T>,
    registration: crate::HightouchRegistration,
    permissions: HightouchPermissionSnapshot,
    consent: ConsentScope,
    definition: HightouchSyncResultServiceDefinition,
}

impl<T: HightouchTransport> fmt::Debug for HightouchSyncResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HightouchSyncResultService")
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("permissions", &self.permissions.digest)
            .field("consent", &self.consent.digest())
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: HightouchTransport> HightouchSyncResultService<T> {
    pub fn new(provider: HightouchProvider<T>) -> Result<Self, HightouchSyncResultServiceError> {
        let permissions = HightouchPermissionSnapshot::metadata_read(1)?;
        let consent = ConsentScope::new("hightouch-sync-result.metadata-read", 1)?;
        Self::register(
            provider,
            "hightouch-sync-result-registration",
            permissions,
            consent,
            1,
        )
    }

    pub fn register(
        provider: HightouchProvider<T>,
        registration_id: impl AsRef<str>,
        permissions: HightouchPermissionSnapshot,
        consent: ConsentScope,
        registration_revision: u64,
    ) -> Result<Self, HightouchSyncResultServiceError> {
        let registration = crate::HightouchRegistration::new(
            registration_id,
            provider.scope(),
            provider.secret_reference(),
            &permissions,
            &consent,
            provider.provider_digest(),
            registration_revision,
        )?;
        Self::new_with_registration(provider, registration, permissions, consent)
    }

    pub fn new_with_registration(
        provider: HightouchProvider<T>,
        registration: crate::HightouchRegistration,
        permissions: HightouchPermissionSnapshot,
        consent: ConsentScope,
    ) -> Result<Self, HightouchSyncResultServiceError> {
        registration
            .validate(
                provider.scope(),
                provider.secret_reference(),
                &permissions,
                &consent,
                &provider.provider_digest(),
            )
            .map_err(|_| HightouchSyncResultServiceError::RegistrationRevoked)?;
        Ok(Self {
            provider,
            registration,
            permissions,
            consent,
            definition: HightouchSyncResultServiceDefinition::default(),
        })
    }

    #[must_use]
    pub fn provider(&self) -> &HightouchProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut HightouchProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &crate::HightouchRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut crate::HightouchRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &HightouchSyncScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn permissions(&self) -> &HightouchPermissionSnapshot {
        &self.permissions
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn service_definition(&self) -> &HightouchSyncResultServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> HightouchCapabilityDescription {
        HightouchCapabilityDescription {
            service_id: crate::HIGHTOUCH_SYNC_RESULT_SERVICE_ID.to_owned(),
            provider_id: crate::HIGHTOUCH_PROVIDER_ID.to_owned(),
            provider_api_revision: crate::HIGHTOUCH_PROVIDER_API_REVISION.to_owned(),
            operations: self.definition.operations.clone(),
            permissions: self
                .permissions
                .permissions
                .iter()
                .map(|permission| format!("{permission:?}"))
                .collect(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            connected: false,
            native: false,
        }
    }

    #[must_use]
    pub fn issue_read_consent(&self) -> ConsentScope {
        self.consent.clone()
    }

    pub fn read(&mut self) -> Result<HightouchSyncResultEvidence, HightouchSyncResultServiceError> {
        self.ensure_registration()?;
        match self.provider.read() {
            Ok(read) => Ok(success_evidence(
                self.scope(),
                &self.registration,
                &self.permissions,
                &self.consent,
                self.provider.provider_digest(),
                read,
            )),
            Err(HightouchProviderError::SecretRevoked) => {
                Err(HightouchSyncResultServiceError::SecretRevoked)
            }
            Err(HightouchProviderError::RegistrationRevoked) => {
                Err(HightouchSyncResultServiceError::RegistrationRevoked)
            }
            Err(error) => Ok(failure_evidence(
                self.scope(),
                &self.registration,
                &self.permissions,
                &self.consent,
                self.provider.provider_digest(),
                self.provider.transport_provenance(),
                &error,
            )),
        }
    }

    pub fn read_with_consent(
        &mut self,
        consent: &ConsentScope,
    ) -> Result<HightouchSyncResultEvidence, HightouchSyncResultServiceError> {
        consent.validate()?;
        if consent != &self.consent {
            return Err(HightouchSyncResultServiceError::ConsentMismatch);
        }
        self.read()
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<HightouchSyncResultProposal, HightouchSyncResultServiceError> {
        let evidence = self.read()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_sync_result_proposal(
        &mut self,
    ) -> Result<HightouchSyncResultProposal, HightouchSyncResultServiceError> {
        self.compile_proposal()
    }

    pub fn compile_proposal_with_consent(
        &mut self,
        consent: &ConsentScope,
    ) -> Result<HightouchSyncResultProposal, HightouchSyncResultServiceError> {
        let evidence = self.read_with_consent(consent)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: HightouchSyncResultEvidence,
    ) -> Result<HightouchSyncResultProposal, HightouchSyncResultServiceError> {
        self.ensure_registration()?;
        self.verify_evidence(&evidence)?;
        let recommendation = recommendation_for(&evidence.state, &evidence.classification);
        let idempotency_digest = evidence.digests.idempotency_digest.clone();
        Ok(HightouchSyncResultProposal {
            source_evidence_digest: evidence.evidence_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            permission_digest: self.permissions.digest.clone(),
            consent_digest: self.consent.digest().clone(),
            contract_digest: crate::contract_digest(),
            idempotency_digest,
            recommendation,
            proposal_only: true,
            connected: false,
            native: false,
            work_product_adopted: false,
            outcome_adopted: false,
            evidence,
            proposal_digest: Digest::pending(),
        }
        .seal())
    }

    pub fn verify_proposal(
        &self,
        proposal: &HightouchSyncResultProposal,
    ) -> Result<(), HightouchSyncResultServiceError> {
        self.ensure_registration()?;
        if proposal.provider_digest != self.provider.provider_digest()
            || proposal.permission_digest != self.permissions.digest
            || proposal.consent_digest != *self.consent.digest()
            || proposal.contract_digest != crate::contract_digest()
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope().digest()
            || proposal.evidence.registration_digest != self.registration.registration_digest
            || proposal.evidence.digests.provider_digest != self.provider.provider_digest()
            || proposal.evidence.digests.permission_digest != self.permissions.digest
            || proposal.evidence.digests.consent_digest != *self.consent.digest()
            || proposal.evidence.digests.contract_digest != crate::contract_digest()
            || proposal.evidence.digests.registration_digest
                != self.registration.registration_digest
            || proposal.evidence.digests.idempotency_digest != proposal.idempotency_digest
        {
            return Err(HightouchSyncResultServiceError::EvidenceMismatch);
        }
        proposal
            .validate_integrity()
            .map_err(|_| HightouchSyncResultServiceError::EvidenceMismatch)
    }

    pub fn verify_evidence(
        &self,
        evidence: &HightouchSyncResultEvidence,
    ) -> Result<(), HightouchSyncResultServiceError> {
        self.ensure_registration()?;
        if evidence.registration_digest != self.registration.registration_digest
            || evidence.registration_revision != self.registration.registration_revision
            || evidence.scope_digest != self.scope().digest()
            || evidence.permission_digest != self.permissions.digest
            || evidence.consent_digest != *self.consent.digest()
            || evidence.digests.plugin_version_digest
                != crate::canonical_digest(&crate::HIGHTOUCH_SYNC_RESULT_PLUGIN_VERSION)
            || evidence.digests.contract_digest != crate::contract_digest()
            || evidence.digests.provider_digest != self.provider.provider_digest()
            || evidence.digests.permission_digest != self.permissions.digest
            || evidence.digests.consent_digest != *self.consent.digest()
            || evidence.digests.scope_digest != self.scope().digest()
            || evidence.digests.commit_digest != *self.scope().commit_digest()
            || evidence.provenance != self.provider.transport_provenance()
        {
            return Err(HightouchSyncResultServiceError::EvidenceMismatch);
        }
        evidence
            .validate_integrity()
            .map_err(|_| HightouchSyncResultServiceError::EvidenceMismatch)
    }

    pub fn record_observation(
        &self,
        proposal: &HightouchSyncResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<HightouchObservationReceipt, HightouchSyncResultServiceError> {
        self.verify_proposal(proposal)?;
        let key = IdempotencyKey::new(idempotency_key)?;
        Ok(HightouchObservationReceipt::new(
            proposal, key.digest, false, false,
        ))
    }

    pub fn read_back(
        &self,
        proposal: &HightouchSyncResultProposal,
    ) -> Result<crate::HightouchReadbackReceipt, HightouchSyncResultServiceError> {
        self.verify_proposal(proposal)?;
        Ok(crate::HightouchReadbackReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            status: "verified_against_proposal_only".to_owned(),
            independent_native_readback: false,
            connected: false,
            native: false,
        })
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationTransitionReceipt, HightouchSyncResultServiceError> {
        self.registration
            .revoke()
            .map_err(HightouchSyncResultServiceError::Model)
    }

    pub fn revoke(
        &mut self,
    ) -> Result<RegistrationTransitionReceipt, HightouchSyncResultServiceError> {
        self.revoke_registration()
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<RegistrationTransitionReceipt, HightouchSyncResultServiceError> {
        self.registration
            .restore()
            .map_err(HightouchSyncResultServiceError::Model)
    }

    pub fn restore(
        &mut self,
    ) -> Result<RegistrationTransitionReceipt, HightouchSyncResultServiceError> {
        self.restore_registration()
    }

    pub fn revoke_secret(&mut self) -> Result<(), HightouchSyncResultServiceError> {
        self.provider.revoke_secret().map_err(|error| match error {
            HightouchProviderError::SecretRevoked => HightouchSyncResultServiceError::SecretRevoked,
            HightouchProviderError::Model(error) => HightouchSyncResultServiceError::Model(error),
            _ => HightouchSyncResultServiceError::SecretRevoked,
        })
    }

    fn ensure_registration(&self) -> Result<(), HightouchSyncResultServiceError> {
        if self.provider.secret_reference().is_revoked() {
            return Err(HightouchSyncResultServiceError::SecretRevoked);
        }
        self.registration
            .validate(
                self.scope(),
                self.provider.secret_reference(),
                &self.permissions,
                &self.consent,
                &self.provider.provider_digest(),
            )
            .map_err(|_| HightouchSyncResultServiceError::RegistrationRevoked)
    }
}

fn success_evidence(
    scope: &HightouchSyncScope,
    registration: &crate::HightouchRegistration,
    permissions: &HightouchPermissionSnapshot,
    consent: &ConsentScope,
    provider_digest: Digest,
    read: HightouchProviderRead,
) -> HightouchSyncResultEvidence {
    let target_run = read
        .runs
        .iter()
        .find(|run| run.id_digest == scope.run_id().digest())
        .cloned();
    let (state, classification) = match target_run.as_ref().map(|run| &run.status) {
        Some(HightouchRunStatus::Queued) => (
            HightouchEvidenceState::Queued,
            HightouchEvidenceClassification::Normalized,
        ),
        Some(HightouchRunStatus::Running) => (
            HightouchEvidenceState::Running,
            HightouchEvidenceClassification::Normalized,
        ),
        Some(HightouchRunStatus::Succeeded) if read.listing_complete => (
            HightouchEvidenceState::Succeeded,
            HightouchEvidenceClassification::Normalized,
        ),
        Some(HightouchRunStatus::Failed) => (
            HightouchEvidenceState::Failed,
            HightouchEvidenceClassification::Normalized,
        ),
        Some(HightouchRunStatus::Partial | HightouchRunStatus::Succeeded) => (
            HightouchEvidenceState::Partial,
            HightouchEvidenceClassification::Partial,
        ),
        Some(HightouchRunStatus::Unknown) | None => (
            HightouchEvidenceState::ProviderUnknown,
            HightouchEvidenceClassification::ProviderUnknown,
        ),
    };
    let run_digest = target_run
        .as_ref()
        .map_or_else(Digest::pending, HightouchRunProjection::digest);
    let idempotency_digest = Digest::from_parts(
        "hightouch-read-idempotency/v1",
        &[
            ("scope", scope.digest().as_str().to_owned()),
            (
                "receipts",
                crate::canonical_digest(&read.read_receipts)
                    .as_str()
                    .to_owned(),
            ),
        ],
    );
    let digests = crate::HightouchEvidenceDigests {
        plugin_version_digest: crate::canonical_digest(
            &crate::HIGHTOUCH_SYNC_RESULT_PLUGIN_VERSION,
        ),
        contract_digest: crate::contract_digest(),
        provider_digest,
        permission_digest: permissions.digest.clone(),
        consent_digest: consent.digest().clone(),
        scope_digest: scope.digest(),
        workspace_digest: read.workspace.digest(),
        source_digest: read.source.digest(),
        model_digest: read.model.digest(),
        sync_digest: read.sync.digest(),
        destination_digest: read.destination.digest(),
        run_digest,
        commit_digest: read.commit_digest.clone(),
        cursor_digests: read.cursor_digests.clone(),
        idempotency_digest,
        registration_digest: registration.registration_digest.clone(),
        evidence_digest: Digest::pending(),
    };
    HightouchSyncResultEvidence {
        registration_digest: registration.registration_digest.clone(),
        registration_revision: registration.registration_revision,
        scope_digest: scope.digest(),
        permission_digest: permissions.digest.clone(),
        consent_digest: consent.digest().clone(),
        project: crate::ProjectProjection::from(scope.project()),
        mission: crate::MissionProjection::from(scope.mission()),
        work_product: crate::WorkProductProjection::from(scope.work_product()),
        workspace: Some(read.workspace),
        source: Some(read.source),
        model: Some(read.model),
        sync: Some(read.sync),
        destination: Some(read.destination),
        run: target_run,
        runs: read.runs,
        commit_digest: read.commit_digest,
        state,
        classification,
        page_count: read.page_count,
        listing_complete: read.listing_complete,
        cursor_digests: read.cursor_digests,
        read_receipts: read.read_receipts,
        rate_limit: read.rate_limit,
        backoff: read.backoff,
        failure: None,
        provenance: read.provenance,
        proposal_only: true,
        connected: false,
        native: false,
        durable_provider_receipt: false,
        work_product_adopted: false,
        outcome_adopted: false,
        digests,
        evidence_digest: Digest::pending(),
    }
    .seal()
}

fn failure_evidence(
    scope: &HightouchSyncScope,
    registration: &crate::HightouchRegistration,
    permissions: &HightouchPermissionSnapshot,
    consent: &ConsentScope,
    provider_digest: Digest,
    provenance: TransportProvenance,
    error: &HightouchProviderError,
) -> HightouchSyncResultEvidence {
    let blocked = error.is_blocked_env() || provenance.is_blocked_env();
    let (state, classification, category) = if blocked {
        (
            HightouchEvidenceState::Denied,
            HightouchEvidenceClassification::BlockedEnv,
            "BLOCKED_ENV",
        )
    } else {
        match error {
            HightouchProviderError::Denied { .. } => (
                HightouchEvidenceState::Denied,
                HightouchEvidenceClassification::Denied,
                "denied",
            ),
            HightouchProviderError::RateLimited { .. } => (
                HightouchEvidenceState::RateLimited,
                HightouchEvidenceClassification::RateLimited,
                "rate_limited",
            ),
            HightouchProviderError::Tampered { .. }
            | HightouchProviderError::ResponseTooLarge
            | HightouchProviderError::ScopeMismatch
            | HightouchProviderError::CursorBindingMismatch => (
                HightouchEvidenceState::Tampered,
                HightouchEvidenceClassification::Tampered,
                "tampered",
            ),
            HightouchProviderError::PaginationBound | HightouchProviderError::PaginationLoop => (
                HightouchEvidenceState::Partial,
                HightouchEvidenceClassification::Partial,
                "pagination_bound",
            ),
            _ => (
                HightouchEvidenceState::ProviderUnknown,
                HightouchEvidenceClassification::ProviderUnknown,
                "provider_unknown",
            ),
        }
    };
    let retry_after_seconds = error.retry_after_seconds();
    let failure = HightouchFailureEvidence::new(
        category,
        error.status_code(),
        retry_after_seconds,
        format!("{error:?}"),
    );
    let request_digest = Digest::from_parts(
        "hightouch-failure-request/v1",
        &[
            ("scope", scope.digest().as_str().to_owned()),
            ("error", failure.failure_digest.as_str().to_owned()),
        ],
    );
    let read_receipt = HightouchReadReceipt {
        operation: crate::HightouchOperation::ListRuns,
        method: crate::HightouchHttpMethod::Get,
        request_digest,
        response_digest: failure.diagnostic_digest.clone(),
        status_code: error.status_code(),
        response_bytes: 0,
        page: 1,
        cursor_digest: None,
        rate_limit_digest: HightouchRateLimitReceipt::new(
            None,
            Some(u32::from(!matches!(
                state,
                HightouchEvidenceState::RateLimited
            ))),
            retry_after_seconds,
            matches!(state, HightouchEvidenceState::RateLimited),
        )
        .expect("bounded failure rate receipt")
        .digest(),
        provenance: provenance.clone(),
        connected: false,
        native: false,
    };
    let rate_limit = HightouchRateLimitReceipt::new(
        None,
        Some(u32::from(!matches!(
            state,
            HightouchEvidenceState::RateLimited
        ))),
        retry_after_seconds,
        matches!(state, HightouchEvidenceState::RateLimited),
    )
    .expect("bounded failure rate receipt");
    let backoff = retry_after_seconds.map(|retry| {
        HightouchBackoffReceipt::new(3, Some(retry), retry.min(crate::MAX_BACKOFF_SECONDS))
    });
    let digests = crate::HightouchEvidenceDigests {
        plugin_version_digest: crate::canonical_digest(
            &crate::HIGHTOUCH_SYNC_RESULT_PLUGIN_VERSION,
        ),
        contract_digest: crate::contract_digest(),
        provider_digest,
        permission_digest: permissions.digest.clone(),
        consent_digest: consent.digest().clone(),
        scope_digest: scope.digest(),
        workspace_digest: Digest::pending(),
        source_digest: Digest::pending(),
        model_digest: Digest::pending(),
        sync_digest: Digest::pending(),
        destination_digest: Digest::pending(),
        run_digest: Digest::pending(),
        commit_digest: scope.commit_digest().clone(),
        cursor_digests: Vec::new(),
        idempotency_digest: Digest::from_parts(
            "hightouch-failure-idempotency/v1",
            &[("failure", failure.failure_digest.as_str().to_owned())],
        ),
        registration_digest: registration.registration_digest.clone(),
        evidence_digest: Digest::pending(),
    };
    HightouchSyncResultEvidence {
        registration_digest: registration.registration_digest.clone(),
        registration_revision: registration.registration_revision,
        scope_digest: scope.digest(),
        permission_digest: permissions.digest.clone(),
        consent_digest: consent.digest().clone(),
        project: crate::ProjectProjection::from(scope.project()),
        mission: crate::MissionProjection::from(scope.mission()),
        work_product: crate::WorkProductProjection::from(scope.work_product()),
        workspace: None,
        source: None,
        model: None,
        sync: None,
        destination: None,
        run: None,
        runs: Vec::new(),
        commit_digest: scope.commit_digest().clone(),
        state,
        classification,
        page_count: 1,
        listing_complete: false,
        cursor_digests: Vec::new(),
        read_receipts: vec![read_receipt],
        rate_limit,
        backoff,
        failure: Some(failure),
        provenance,
        proposal_only: true,
        connected: false,
        native: false,
        durable_provider_receipt: false,
        work_product_adopted: false,
        outcome_adopted: false,
        digests,
        evidence_digest: Digest::pending(),
    }
    .seal()
}

fn recommendation_for(
    state: &HightouchEvidenceState,
    classification: &HightouchEvidenceClassification,
) -> HightouchRecommendation {
    let disposition = match state {
        HightouchEvidenceState::Succeeded => {
            HightouchRecommendationDisposition::ReviewSuccessfulDeliveryMetadata
        }
        HightouchEvidenceState::Queued => HightouchRecommendationDisposition::ReviewQueuedRun,
        HightouchEvidenceState::Running => HightouchRecommendationDisposition::ReviewRunningRun,
        HightouchEvidenceState::Failed => HightouchRecommendationDisposition::ReviewFailedRun,
        HightouchEvidenceState::Partial => HightouchRecommendationDisposition::ReviewPartialRun,
        HightouchEvidenceState::Denied => {
            HightouchRecommendationDisposition::NoRecommendationDenied
        }
        HightouchEvidenceState::RateLimited => {
            HightouchRecommendationDisposition::NoRecommendationRateLimited
        }
        HightouchEvidenceState::ProviderUnknown => {
            HightouchRecommendationDisposition::NoRecommendationProviderUnknown
        }
        HightouchEvidenceState::Tampered => {
            HightouchRecommendationDisposition::NoRecommendationTampered
        }
    };
    let rationale_digest = crate::canonical_digest(&(state, classification, &disposition));
    HightouchRecommendation {
        disposition,
        provider_reported_only: true,
        non_mutating: true,
        claims_delivery_truth: false,
        claims_source_truth: false,
        claims_business_success: false,
        rationale_digest,
    }
}

// Kept as a type-level assertion that the service does not accidentally
// acquire a native provider or receipt authority while the transport remains
// generic and recording-only.
#[allow(dead_code)]
fn _layer_one_types_are_bound<T: HightouchTransport>(
    service: &HightouchSyncResultService<T>,
    _workspace: &HightouchWorkspaceProjection,
) -> bool {
    !service.describe_capabilities().connected
}
