use std::fmt;

use thiserror::Error;

use crate::{
    ConsentScope, Digest, EvidenceClassification, EvidenceState, IncidentStatus,
    MAX_RESPONSE_BYTES, ModelError, ObservationReceipt, RecommendationDisposition,
    StatuspageEvidenceDigests, StatuspageIncidentResult, StatuspageIncidentResultEvidence,
    StatuspageIncidentResultProposal, StatuspageIncidentResultRecommendation,
    StatuspageIncidentResultScope, StatuspageProvider, StatuspageProviderError,
    StatuspageProviderRead, StatuspageRateLimitReceipt, StatuspageReadSeam,
    StatuspageReadbackReceipt, StatuspageRegistration, StatuspageRequest, StatuspageRequestReceipt,
    StatuspageTransport, TransportProvenance, canonical_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum StatuspageIncidentResultServiceError {
    #[error("Statuspage registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Statuspage SecretReference is revoked")]
    SecretRevoked,
    #[error("Statuspage permission is missing")]
    MissingPermission,
    #[error("Statuspage page or component scope does not match")]
    ScopeMismatch,
    #[error("Statuspage read consent is denied or stale")]
    ConsentMismatch,
    #[error("Statuspage evidence or proposal digest fence failed")]
    EvidenceMismatch,
    #[error("Statuspage proposal replay was rejected")]
    ReplayDetected,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatuspageIncidentResultServiceDefinition {
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

impl Default for StatuspageIncidentResultServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: crate::STATUSPAGE_INCIDENT_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: crate::STATUSPAGE_INCIDENT_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: crate::STATUSPAGE_INCIDENT_RESULT_SERVICE_ID.to_owned(),
            provider_id: crate::STATUSPAGE_PROVIDER_ID.to_owned(),
            consumer_id: crate::MISSION_STATUSPAGE_INCIDENT_CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            read_only: true,
            live_execution: false,
            emits_outcome: false,
            external_writes: false,
        }
    }
}

/// Typed Layer-1 service for bounded, read-only Statuspage incident evidence.
/// It does not resolve credentials, open HTTPS, or adopt kernel Outcome.
pub struct StatuspageIncidentResultService<T: StatuspageTransport> {
    provider: StatuspageProvider<T>,
    definition: StatuspageIncidentResultServiceDefinition,
}

impl<T: StatuspageTransport> fmt::Debug for StatuspageIncidentResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatuspageIncidentResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: StatuspageTransport> StatuspageIncidentResultService<T> {
    pub fn new(
        provider: StatuspageProvider<T>,
    ) -> Result<Self, StatuspageIncidentResultServiceError> {
        provider
            .registration()
            .validate(
                provider.scope(),
                provider.secret_reference(),
                &provider.provider_digest(),
            )
            .map_err(|_| StatuspageIncidentResultServiceError::RegistrationRevoked)?;
        Ok(Self {
            provider,
            definition: StatuspageIncidentResultServiceDefinition::default(),
        })
    }

    #[must_use]
    pub fn from_provider(provider: StatuspageProvider<T>) -> Self {
        Self {
            provider,
            definition: StatuspageIncidentResultServiceDefinition::default(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &StatuspageProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut StatuspageProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &StatuspageIncidentResultScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &StatuspageRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &StatuspageIncidentResultServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn issue_read_consent(&self) -> ConsentScope {
        self.scope().consent().clone()
    }

    pub fn read(
        &mut self,
    ) -> Result<StatuspageIncidentResultEvidence, StatuspageIncidentResultServiceError> {
        let consent = self.issue_read_consent();
        self.read_with_consent(&consent)
    }

    pub fn read_with_consent(
        &mut self,
        consent: &ConsentScope,
    ) -> Result<StatuspageIncidentResultEvidence, StatuspageIncidentResultServiceError> {
        self.validate_consent(consent)?;
        match self.provider.read() {
            Ok(read) => Ok(normalize_success(
                self.scope(),
                self.registration(),
                self.provider.provider_digest(),
                read,
            )),
            Err(StatuspageProviderError::RegistrationRevoked) => {
                Err(StatuspageIncidentResultServiceError::RegistrationRevoked)
            }
            Err(StatuspageProviderError::SecretRevoked) => {
                Err(StatuspageIncidentResultServiceError::SecretRevoked)
            }
            Err(StatuspageProviderError::MissingPermission { .. }) => {
                Err(StatuspageIncidentResultServiceError::MissingPermission)
            }
            Err(StatuspageProviderError::ScopeMismatch) => {
                Err(StatuspageIncidentResultServiceError::ScopeMismatch)
            }
            Err(error) => Ok(normalize_failure(
                self.scope(),
                self.registration(),
                self.provider.provider_digest(),
                self.provider.transport_provenance(),
                &error,
            )),
        }
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<StatuspageIncidentResultProposal, StatuspageIncidentResultServiceError> {
        let evidence = self.read()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_incident_result_proposal(
        &mut self,
    ) -> Result<StatuspageIncidentResultProposal, StatuspageIncidentResultServiceError> {
        self.compile_proposal()
    }

    pub fn compile_proposal_with_consent(
        &mut self,
        consent: &ConsentScope,
    ) -> Result<StatuspageIncidentResultProposal, StatuspageIncidentResultServiceError> {
        let evidence = self.read_with_consent(consent)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: StatuspageIncidentResultEvidence,
    ) -> Result<StatuspageIncidentResultProposal, StatuspageIncidentResultServiceError> {
        self.ensure_registration()?;
        self.verify_evidence(&evidence)?;
        let recommendation = recommendation_for(self.scope(), &evidence);
        let source_evidence_digest = evidence.digest();
        let mut proposal = StatuspageIncidentResultProposal {
            scope: self.scope().clone(),
            evidence,
            source_evidence_digest,
            registration_digest: self.registration().registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            contract_digest: crate::contract_digest(),
            permission_digest: self.scope().acl_digest(),
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
        proposal: &StatuspageIncidentResultProposal,
    ) -> Result<(), StatuspageIncidentResultServiceError> {
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
            || proposal.permission_digest != self.scope().acl_digest()
            || proposal.source_evidence_digest != proposal.evidence.digest()
            || proposal.proposal_digest != proposal.digest()
        {
            return Err(StatuspageIncidentResultServiceError::EvidenceMismatch);
        }
        self.verify_evidence(&proposal.evidence)
    }

    pub fn record_observation(
        &self,
        proposal: &StatuspageIncidentResultProposal,
    ) -> Result<ObservationReceipt, StatuspageIncidentResultServiceError> {
        self.verify_proposal(proposal)?;
        Ok(ObservationReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            recorded: true,
            durable: false,
            native: false,
            connected: false,
        })
    }

    pub fn read_back(
        &self,
        proposal: &StatuspageIncidentResultProposal,
    ) -> Result<StatuspageReadbackReceipt, StatuspageIncidentResultServiceError> {
        self.verify_proposal(proposal)?;
        Ok(StatuspageReadbackReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            status: "verified_against_proposal".to_owned(),
            independent_native_readback: false,
            native: false,
            connected: false,
        })
    }

    pub fn revoke(
        &mut self,
    ) -> Result<crate::RegistrationRevocationReceipt, StatuspageIncidentResultServiceError> {
        self.provider.revoke().map_err(map_provider_error)
    }

    pub fn restore(&mut self) -> Result<(), StatuspageIncidentResultServiceError> {
        self.provider.restore().map_err(map_provider_error)
    }

    pub fn revoke_secret(&mut self) -> Result<(), StatuspageIncidentResultServiceError> {
        self.provider.revoke_secret().map_err(map_provider_error)
    }

    pub fn restore_secret(&mut self) -> Result<(), StatuspageIncidentResultServiceError> {
        self.provider.restore_secret().map_err(map_provider_error)
    }

    fn validate_consent(
        &self,
        consent: &ConsentScope,
    ) -> Result<(), StatuspageIncidentResultServiceError> {
        consent.validate()?;
        if consent == self.scope().consent() {
            Ok(())
        } else {
            Err(StatuspageIncidentResultServiceError::ConsentMismatch)
        }
    }

    fn ensure_registration(&self) -> Result<(), StatuspageIncidentResultServiceError> {
        if self.registration().is_revoked() {
            return Err(StatuspageIncidentResultServiceError::RegistrationRevoked);
        }
        self.registration()
            .validate(
                self.scope(),
                self.provider.secret_reference(),
                &self.provider.provider_digest(),
            )
            .map_err(|_| StatuspageIncidentResultServiceError::RegistrationRevoked)
    }

    fn verify_evidence(
        &self,
        evidence: &StatuspageIncidentResultEvidence,
    ) -> Result<(), StatuspageIncidentResultServiceError> {
        if evidence.evidence_digest != evidence.digest()
            || evidence.scope != *self.scope()
            || evidence.provenance.is_native()
            || evidence.provenance.is_connected()
            || evidence.provenance.is_first_party()
            || evidence.native
            || evidence.connected
            || evidence.first_party
            || evidence.digests.contract_digest != crate::contract_digest()
            || evidence.digests.plugin_version_digest
                != canonical_digest(&crate::STATUSPAGE_INCIDENT_RESULT_PLUGIN_VERSION)
            || evidence.digests.provider_digest != self.provider.provider_digest()
            || evidence.digests.registration_digest != self.registration().registration_digest
            || evidence.digests.permission_digest != self.scope().acl_digest()
            || evidence.digests.scope_digest != *self.scope().scope_digest()
            || evidence.digests.revision_digest != *self.scope().revision_digest()
            || evidence.digests.time_window_digest != self.scope().time_window().digest()
            || evidence.digests.page_digest != self.scope().page().digest()
            || evidence.digests.request_digest
                != canonical_digest(
                    &evidence
                        .request_receipts
                        .iter()
                        .map(|receipt| receipt.request_digest.clone())
                        .collect::<Vec<_>>(),
                )
            || evidence.digests.response_digest
                != canonical_digest(
                    &evidence
                        .request_receipts
                        .iter()
                        .map(|receipt| receipt.response_digest.clone())
                        .collect::<Vec<_>>(),
                )
            || evidence.rate_limit.digest()
                != evidence.request_receipts.last().map_or_else(
                    || evidence.rate_limit.digest(),
                    |receipt| receipt.rate_limit_digest.clone(),
                )
            || evidence
                .result
                .as_ref()
                .is_some_and(|result| evidence.digests.result_digest != result.digest())
            || evidence.result.is_none()
                && evidence.digests.result_digest
                    != canonical_digest(&("no-result", &evidence.digests.response_digest))
            || !valid_receipts(&evidence.request_receipts, self.scope())
        {
            return Err(StatuspageIncidentResultServiceError::EvidenceMismatch);
        }
        Ok(())
    }
}

pub type StatuspageServiceError = StatuspageIncidentResultServiceError;

fn map_provider_error(error: StatuspageProviderError) -> StatuspageIncidentResultServiceError {
    match error {
        StatuspageProviderError::RegistrationRevoked => {
            StatuspageIncidentResultServiceError::RegistrationRevoked
        }
        StatuspageProviderError::SecretRevoked => {
            StatuspageIncidentResultServiceError::SecretRevoked
        }
        StatuspageProviderError::MissingPermission { .. } => {
            StatuspageIncidentResultServiceError::MissingPermission
        }
        StatuspageProviderError::ScopeMismatch => {
            StatuspageIncidentResultServiceError::ScopeMismatch
        }
        StatuspageProviderError::Model(error) => StatuspageIncidentResultServiceError::Model(error),
        StatuspageProviderError::RateLimited { .. }
        | StatuspageProviderError::HttpStatus { .. }
        | StatuspageProviderError::ResponseTooLarge { .. }
        | StatuspageProviderError::MalformedResponse { .. }
        | StatuspageProviderError::Transport { .. } => {
            StatuspageIncidentResultServiceError::EvidenceMismatch
        }
    }
}

fn normalize_success(
    scope: &StatuspageIncidentResultScope,
    registration: &StatuspageRegistration,
    provider_digest: Digest,
    read: StatuspageProviderRead,
) -> StatuspageIncidentResultEvidence {
    let state = if read.result.partial {
        EvidenceState::Partial
    } else if read.result.has_maintenance() {
        EvidenceState::Maintenance
    } else if read.result.is_empty() {
        EvidenceState::Empty
    } else {
        EvidenceState::Complete
    };
    let classification = match state {
        EvidenceState::Partial => EvidenceClassification::Partial,
        EvidenceState::Maintenance => EvidenceClassification::Maintenance,
        EvidenceState::Empty => EvidenceClassification::Empty,
        _ => EvidenceClassification::Normalized,
    };
    let digests = evidence_digests(
        scope,
        registration,
        provider_digest,
        &read.request_receipts,
        Some(&read.result),
    );
    evidence(
        state,
        classification,
        scope,
        Some(read.result),
        read.request_receipts,
        read.rate_limit,
        digests,
        read.provenance,
    )
}

fn normalize_failure(
    scope: &StatuspageIncidentResultScope,
    registration: &StatuspageRegistration,
    provider_digest: Digest,
    provenance: TransportProvenance,
    error: &StatuspageProviderError,
) -> StatuspageIncidentResultEvidence {
    let request = error
        .request()
        .cloned()
        .unwrap_or_else(|| synthetic_request(scope));
    let (response_digest, response_bytes, rate_limit, status_code) = error.metadata().unwrap_or((
        canonical_digest(&("statuspage-provider-error", request.request_digest.clone())),
        0,
        StatuspageRateLimitReceipt::default(),
        None,
    ));
    let (state, classification) = failure_state(error, provenance);
    let receipt = StatuspageRequestReceipt {
        method: request.method,
        seam: request.seam,
        endpoint: request.endpoint(),
        request_digest: request.request_digest,
        response_digest: response_digest.clone(),
        status_code,
        response_bytes,
        rate_limit_digest: rate_limit.digest(),
    };
    let digests = evidence_digests(
        scope,
        registration,
        provider_digest,
        std::slice::from_ref(&receipt),
        None,
    );
    evidence(
        state,
        classification,
        scope,
        None,
        vec![receipt],
        rate_limit,
        digests,
        provenance,
    )
}

fn failure_state(
    error: &StatuspageProviderError,
    provenance: TransportProvenance,
) -> (EvidenceState, EvidenceClassification) {
    if matches!(error, StatuspageProviderError::RateLimited { .. }) {
        return (
            EvidenceState::RateLimited,
            EvidenceClassification::RateLimited,
        );
    }
    if matches!(
        error,
        StatuspageProviderError::Transport {
            error: crate::StatuspageTransportError::BlockedEnv,
            ..
        }
    ) || provenance.is_blocked_env()
    {
        return (
            EvidenceState::AccessLost,
            EvidenceClassification::BlockedEnv,
        );
    }
    if let StatuspageProviderError::HttpStatus { status_code, .. } = error {
        return match status_code {
            401 | 403 | 404 => (
                EvidenceState::AccessLost,
                EvidenceClassification::AccessLost,
            ),
            420 | 429 => (
                EvidenceState::RateLimited,
                EvidenceClassification::RateLimited,
            ),
            _ => (
                EvidenceState::ProviderUnknown,
                EvidenceClassification::ProviderUnknown,
            ),
        };
    }
    (
        EvidenceState::ProviderUnknown,
        EvidenceClassification::ProviderUnknown,
    )
}

fn synthetic_request(scope: &StatuspageIncidentResultScope) -> StatuspageRequest {
    let mut request = StatuspageRequest {
        method: crate::StatuspageHttpMethod::Get,
        host: "https://api.statuspage.io".to_owned(),
        api_revision: "v1".to_owned(),
        seam: StatuspageReadSeam::PageProfile,
        path: StatuspageReadSeam::PageProfile
            .path_template()
            .replace("{page_id}", scope.page().id()),
        page_id: crate::PageId::new(scope.page().id()).expect("validated page binding"),
        page: 1,
        per_page: 100,
        scope_digest: scope.digest(),
        consent_digest: scope.consent_digest().clone(),
        secret_reference_digest: canonical_digest(&"secret-reference-unavailable"),
        request_digest: String::new(),
    };
    request.request_digest = request.digest();
    request
}

fn evidence_digests(
    scope: &StatuspageIncidentResultScope,
    registration: &StatuspageRegistration,
    provider_digest: Digest,
    receipts: &[StatuspageRequestReceipt],
    result: Option<&StatuspageIncidentResult>,
) -> StatuspageEvidenceDigests {
    let request_digest = canonical_digest(
        &receipts
            .iter()
            .map(|receipt| receipt.request_digest.clone())
            .collect::<Vec<_>>(),
    );
    let response_digest = canonical_digest(
        &receipts
            .iter()
            .map(|receipt| receipt.response_digest.clone())
            .collect::<Vec<_>>(),
    );
    let result_digest = result.map_or_else(
        || canonical_digest(&("no-result", &response_digest)),
        StatuspageIncidentResult::digest,
    );
    StatuspageEvidenceDigests {
        contract_digest: crate::contract_digest(),
        plugin_version_digest: canonical_digest(&crate::STATUSPAGE_INCIDENT_RESULT_PLUGIN_VERSION),
        provider_digest,
        registration_digest: registration.registration_digest.clone(),
        permission_digest: scope.acl_digest(),
        scope_digest: scope.digest(),
        revision_digest: scope.revision_digest().clone(),
        time_window_digest: scope.time_window().digest(),
        page_digest: scope.page().digest(),
        request_digest,
        response_digest,
        result_digest,
    }
}

fn evidence(
    state: EvidenceState,
    classification: EvidenceClassification,
    scope: &StatuspageIncidentResultScope,
    result: Option<StatuspageIncidentResult>,
    request_receipts: Vec<StatuspageRequestReceipt>,
    rate_limit: StatuspageRateLimitReceipt,
    digests: StatuspageEvidenceDigests,
    provenance: TransportProvenance,
) -> StatuspageIncidentResultEvidence {
    let mut evidence = StatuspageIncidentResultEvidence {
        scope: scope.clone(),
        state,
        classification,
        result,
        request_receipts,
        rate_limit,
        provenance,
        native: false,
        connected: false,
        first_party: false,
        digests,
        evidence_digest: String::new(),
    };
    evidence.evidence_digest = evidence.digest();
    evidence
}

fn valid_receipts(
    receipts: &[StatuspageRequestReceipt],
    scope: &StatuspageIncidentResultScope,
) -> bool {
    if receipts.is_empty()
        || receipts.iter().any(|receipt| {
            receipt.method != crate::StatuspageHttpMethod::Get
                || receipt.response_bytes > MAX_RESPONSE_BYTES
                || !receipt
                    .endpoint
                    .starts_with("https://api.statuspage.io/v1/pages/")
                || !valid_digest(&receipt.request_digest)
                || !valid_digest(&receipt.response_digest)
                || !valid_digest(&receipt.rate_limit_digest)
        })
    {
        return false;
    }
    if receipts.len() == 5 {
        let expected = [
            StatuspageReadSeam::PageProfile,
            StatuspageReadSeam::Components,
            StatuspageReadSeam::ComponentGroups,
            StatuspageReadSeam::Incidents,
            StatuspageReadSeam::ScheduledMaintenances,
        ];
        receipts.iter().zip(expected).all(|(receipt, seam)| {
            receipt.seam == seam
                && receipt
                    .endpoint
                    .ends_with(&seam.path_template().replace("{page_id}", scope.page().id()))
        })
    } else {
        receipts.len() == 1
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn recommendation_for(
    _scope: &StatuspageIncidentResultScope,
    evidence: &StatuspageIncidentResultEvidence,
) -> StatuspageIncidentResultRecommendation {
    let disposition = match evidence.state {
        EvidenceState::Complete => {
            if evidence
                .result
                .as_ref()
                .is_some_and(StatuspageIncidentResult::has_maintenance)
            {
                RecommendationDisposition::ReviewMaintenance
            } else if evidence.result.as_ref().is_some_and(|result| {
                result.incidents.iter().any(|incident| {
                    matches!(
                        incident.status,
                        IncidentStatus::Investigating
                            | IncidentStatus::Identified
                            | IncidentStatus::Monitoring
                    )
                })
            }) {
                RecommendationDisposition::ReviewIncidentEvidence
            } else {
                RecommendationDisposition::NoPublishedIncident
            }
        }
        EvidenceState::Maintenance => RecommendationDisposition::ReviewMaintenance,
        EvidenceState::Partial | EvidenceState::Empty => {
            RecommendationDisposition::NeedsMoreEvidence
        }
        EvidenceState::AccessLost => RecommendationDisposition::AccessLost,
        EvidenceState::RateLimited => RecommendationDisposition::RateLimited,
        EvidenceState::ProviderUnknown => RecommendationDisposition::ProviderUnknown,
    };
    StatuspageIncidentResultRecommendation {
        disposition,
        non_mutating: true,
        provider_reported_only: true,
        claims_customer_wide_uptime: false,
        claims_causality: false,
        claims_remediation: false,
        claims_business_outcome: false,
    }
}
