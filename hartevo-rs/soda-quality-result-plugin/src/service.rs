use std::{collections::BTreeMap, fmt};

use crate::consumer::MissionSodaQualityConsumer;
use crate::error::{Result, SodaQualityResultError, SodaTransportError};
use crate::model::{
    Digest, RegistrationStatus, Revision, SodaCheckProjection, SodaCostReceipt,
    SodaDatasetProjection, SodaEvidenceClassification, SodaEvidenceDigests, SodaEvidenceState,
    SodaFailureEvidence, SodaQualityEvidence, SodaQualityHealthProjection, SodaQualityRequest,
    SodaQualityResultProposal, SodaQualityScope, SodaQualityStatus, SodaRecommendation,
    SodaRegistration, SodaRequestReceipt, SodaScanProjection, TransportProvenance,
};
use crate::provider::{
    SodaCheckResponse, SodaDatasetResponse, SodaProvider, SodaProviderError,
    SodaQualityHealthResponse, SodaReadRequest, SodaScanResponse, SodaTransport,
};
use crate::{API_REVISION, CONTRACT_DIGEST, PLUGIN_VERSION};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SodaVerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    ContractDigestMismatch,
    ApiDigestMismatch,
    ScopeDigestMismatch,
    RevisionDigestMismatch,
    EvidenceIntegrity,
    TamperedEvidence,
    PartialEvidence,
    UnknownEvidence,
    DeniedEvidence,
    RateLimitedEvidence,
    ProviderUnknownEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaVerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<SodaVerificationFailure>,
    pub verification_digest: Digest,
}

impl SodaVerificationReport {
    fn new(valid: bool, review_eligible: bool, failures: Vec<SodaVerificationFailure>) -> Self {
        let verification_digest = Digest::from_parts(
            "soda-verification-report/v1",
            &[
                ("valid", valid.to_string()),
                ("review_eligible", review_eligible.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|failure| format!("{failure:?}"))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Self {
            valid,
            review_eligible,
            failures,
            verification_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SodaRecordedResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: SodaEvidenceState,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub registration_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl SodaRecordedResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &SodaQualityResultProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state(),
            provenance: proposal.evidence.provenance,
            replayed,
            registration_digest: proposal.registration_digest.clone(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-soda-recording"),
        };
        result.recording_digest = result.calculate_digest();
        result
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "soda-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        for digest in [
            &self.idempotency_key_digest,
            &self.proposal_digest,
            &self.registration_digest,
            &self.recording_digest,
        ] {
            digest.validate()?;
        }
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            return Err(SodaQualityResultError::TamperedEvidence);
        }
        Ok(())
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

pub struct SodaQualityResultService<T: SodaTransport> {
    scope: SodaQualityScope,
    registration: SodaRegistration,
    provider: SodaProvider<T>,
    proposals: BTreeMap<Digest, Digest>,
    records: BTreeMap<Digest, SodaRecordedResult>,
}

impl<T: SodaTransport> fmt::Debug for SodaQualityResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SodaQualityResultService")
            .field("scope_digest", &self.scope.digest())
            .field("registration_digest", &self.registration.digest())
            .field("provider", &self.provider)
            .field("proposal_count", &self.proposals.len())
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T: SodaTransport> SodaQualityResultService<T> {
    pub fn new(
        scope: SodaQualityScope,
        secret_reference: crate::SecretReference,
        transport: T,
    ) -> Result<Self> {
        let provider = SodaProvider::new(transport, &scope, secret_reference)
            .map_err(provider_error_to_result)?;
        let registration = SodaRegistration::bind(
            &scope,
            provider.secret_reference(),
            provider.definition().provider_digest.clone(),
        )?;
        Self::with_registration(scope, registration, provider)
    }

    pub fn with_registration(
        scope: SodaQualityScope,
        registration: SodaRegistration,
        provider: SodaProvider<T>,
    ) -> Result<Self> {
        registration.validate(
            &scope,
            provider.secret_reference(),
            &provider.definition().provider_digest,
        )?;
        Ok(Self {
            scope,
            registration,
            provider,
            proposals: BTreeMap::new(),
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &SodaQualityScope {
        &self.scope
    }

    #[must_use]
    pub fn registration(&self) -> &SodaRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut SodaRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn provider(&self) -> &SodaProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut SodaProvider<T> {
        &mut self.provider
    }

    pub fn request(
        &self,
        revision: u64,
        idempotency_key: impl Into<String>,
    ) -> Result<SodaQualityRequest> {
        SodaQualityRequest::new(&self.scope, revision, idempotency_key)
    }

    pub fn default_request(
        &self,
        idempotency_key: impl Into<String>,
    ) -> Result<SodaQualityRequest> {
        self.request(self.scope.mission().revision().get(), idempotency_key)
    }

    pub fn propose(&mut self, request: SodaQualityRequest) -> Result<SodaQualityResultProposal> {
        self.ensure_registration_active()?;
        self.validate_registration()?;
        request.validate(&self.scope)?;
        if request.revision != self.scope.mission().revision() {
            return Err(SodaQualityResultError::StaleRevision);
        }
        let previous = self.proposals.get(&request.idempotency_key_digest).cloned();
        let dataset_request = SodaReadRequest::for_dataset(&self.scope)?;
        let check_request = SodaReadRequest::for_check(&self.scope)?;
        let scan_request = SodaReadRequest::for_scan(&self.scope)?;
        let health_request = SodaReadRequest::for_quality_health(&self.scope)?;
        let mut request_receipts = Vec::new();
        let mut cost_receipts = Vec::new();

        let dataset = match self.provider.read_dataset(&dataset_request) {
            Ok(response) => {
                push_receipts(
                    &mut request_receipts,
                    &mut cost_receipts,
                    &dataset_request,
                    response.response_digest.clone(),
                    response.response_bytes,
                );
                Some(response)
            }
            Err(error) => {
                return self.finish_failed_proposal(
                    request,
                    previous,
                    request_receipts,
                    cost_receipts,
                    dataset_request,
                    error,
                );
            }
        };
        let check = match self.provider.read_check(&check_request) {
            Ok(response) => {
                push_receipts(
                    &mut request_receipts,
                    &mut cost_receipts,
                    &check_request,
                    response.response_digest.clone(),
                    response.response_bytes,
                );
                Some(response)
            }
            Err(error) => {
                return self.finish_failed_proposal(
                    request,
                    previous,
                    request_receipts,
                    cost_receipts,
                    check_request,
                    error,
                );
            }
        };
        let scan = match self.provider.read_scan(&scan_request) {
            Ok(response) => {
                push_receipts(
                    &mut request_receipts,
                    &mut cost_receipts,
                    &scan_request,
                    response.response_digest.clone(),
                    response.response_bytes,
                );
                Some(response)
            }
            Err(error) => {
                return self.finish_failed_proposal(
                    request,
                    previous,
                    request_receipts,
                    cost_receipts,
                    scan_request,
                    error,
                );
            }
        };
        let health = match self.provider.read_quality_health(&health_request) {
            Ok(response) => {
                push_receipts(
                    &mut request_receipts,
                    &mut cost_receipts,
                    &health_request,
                    response.response_digest.clone(),
                    response.response_bytes,
                );
                Some(response)
            }
            Err(error) => {
                return self.finish_failed_proposal(
                    request,
                    previous,
                    request_receipts,
                    cost_receipts,
                    health_request,
                    error,
                );
            }
        };

        let dataset = dataset.expect("dataset response is present");
        let check = check.expect("check response is present");
        let scan = scan.expect("scan response is present");
        let health = health.expect("health response is present");
        let state = aggregate_state([check.status, scan.status, health.status]);
        let evidence = self.build_evidence(
            state,
            SodaEvidenceClassification::ProviderReported,
            request,
            Some(dataset),
            Some(check),
            Some(scan),
            Some(health),
            None,
            request_receipts,
            cost_receipts,
        );
        self.finish_proposal(evidence, previous)
    }

    fn finish_failed_proposal(
        &mut self,
        request: SodaQualityRequest,
        previous: Option<Digest>,
        mut request_receipts: Vec<SodaRequestReceipt>,
        mut cost_receipts: Vec<SodaCostReceipt>,
        failed_request: SodaReadRequest,
        error: SodaProviderError,
    ) -> Result<SodaQualityResultProposal> {
        let (state, classification, failure) = provider_error_state(&error);
        let status_code = error
            .transport_error()
            .and_then(SodaTransportError::status_code);
        request_receipts.push(failed_request.receipt(None, 0, status_code));
        cost_receipts.push(SodaCostReceipt::new(failed_request.operation, 0));
        let evidence = self.build_evidence(
            state,
            classification,
            request,
            None,
            None,
            None,
            None,
            Some(failure),
            request_receipts,
            cost_receipts,
        );
        self.finish_proposal(evidence, previous)
    }

    fn build_evidence(
        &self,
        state: SodaEvidenceState,
        classification: SodaEvidenceClassification,
        request: SodaQualityRequest,
        dataset: Option<SodaDatasetResponse>,
        check: Option<SodaCheckResponse>,
        scan: Option<SodaScanResponse>,
        health: Option<SodaQualityHealthResponse>,
        failure: Option<SodaFailureEvidence>,
        request_receipts: Vec<SodaRequestReceipt>,
        cost_receipts: Vec<SodaCostReceipt>,
    ) -> SodaQualityEvidence {
        let dataset_projection = dataset.as_ref().map(|response| SodaDatasetProjection {
            dataset_digest: self.scope.dataset().digest(),
            revision_digest: self.scope.dataset().revision().into_digest(),
            row_count: response.row_count,
            partition_count: response.partition_count,
        });
        let check_projection = check.as_ref().map(|response| SodaCheckProjection {
            check_digest: self.scope.check().digest(),
            revision_digest: self.scope.check().revision().into_digest(),
            status: response.status,
            evaluated_rows: response.evaluated_rows,
            failed_rows: response.failed_rows,
            score_basis_points: response.score_basis_points,
        });
        let scan_projection = scan.as_ref().map(|response| SodaScanProjection {
            scan_digest: self.scope.scan().digest(),
            revision_digest: self.scope.scan().revision().into_digest(),
            status: response.status,
            check_count: response.check_count,
            completed_at_digest: response.completed_at_digest.clone(),
        });
        let health_projection = health.as_ref().map(|response| SodaQualityHealthProjection {
            metric_digest: self.scope.metric().digest(),
            revision_digest: self.scope.metric().revision().into_digest(),
            status: response.status,
            metric_value: response.metric_value,
            threshold: response.threshold,
            metric_count: response.metric_count,
        });
        let mut digests = SodaEvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned()).expect("contract digest"),
            provider_digest: self.provider.definition().provider_digest.clone(),
            api_digest: Digest::from_text(API_REVISION),
            permission_digest: crate::permission_digest(),
            scope_digest: self.scope.digest().clone(),
            revision_digest: self.scope.revision_digest().clone(),
            dataset_digest: self.scope.dataset().digest(),
            check_digest: self.scope.check().digest(),
            scan_digest: self.scope.scan().digest(),
            metric_digest: self.scope.metric().digest(),
            dataset_response_digest: dataset
                .as_ref()
                .map(|response| response.response_digest.clone()),
            check_response_digest: check
                .as_ref()
                .map(|response| response.response_digest.clone()),
            scan_response_digest: scan
                .as_ref()
                .map(|response| response.response_digest.clone()),
            health_response_digest: health
                .as_ref()
                .map(|response| response.response_digest.clone()),
            evidence_digest: Digest::from_text("unsealed-soda-evidence"),
        };
        let mut evidence = SodaQualityEvidence {
            state,
            classification,
            scope_digest: self.scope.digest().clone(),
            revision_digest: self.scope.revision_digest().clone(),
            dataset: dataset_projection,
            check: check_projection,
            scan: scan_projection,
            quality_health: health_projection,
            failure,
            request_receipts,
            cost_receipts,
            digests: digests.clone(),
            provenance: self.provider.transport_provenance(),
            idempotency_key_digest: request.idempotency_key_digest,
            revision: request.revision,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            raw_rows: false,
            data_correctness_claim: false,
            evidence_digest: Digest::from_text("unsealed-soda-evidence"),
        };
        let evidence_digest = evidence.calculate_digest();
        evidence.evidence_digest = evidence_digest.clone();
        digests.evidence_digest = evidence_digest;
        evidence.digests = digests;
        evidence
    }

    fn finish_proposal(
        &mut self,
        evidence: SodaQualityEvidence,
        previous: Option<Digest>,
    ) -> Result<SodaQualityResultProposal> {
        let recommendation = recommendation_for(evidence.state);
        let mut proposal = SodaQualityResultProposal {
            scope: self.scope.clone(),
            registration_digest: self.registration.digest().clone(),
            provider_digest: self.provider.definition().provider_digest.clone(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned()).expect("contract digest"),
            proposal_revision: evidence.revision,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            adopts_outcome: false,
            adopts_work_product: false,
            recommendation,
            evidence,
            proposal_digest: Digest::from_text("unsealed-soda-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        if let Some(previous) = previous
            && previous != proposal.proposal_digest
        {
            return Err(SodaQualityResultError::ReplayConflict);
        }
        proposal.validate_integrity()?;
        self.proposals.insert(
            proposal.evidence.idempotency_key_digest.clone(),
            proposal.proposal_digest.clone(),
        );
        Ok(proposal)
    }

    pub fn verify(&self, proposal: &SodaQualityResultProposal) -> SodaVerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(SodaVerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.digest() {
            failures.push(SodaVerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.provider_digest != self.provider.definition().provider_digest {
            failures.push(SodaVerificationFailure::ProviderDigestMismatch);
        }
        if proposal.contract_digest.as_str() != CONTRACT_DIGEST {
            failures.push(SodaVerificationFailure::ContractDigestMismatch);
        }
        if proposal.scope.digest() != self.scope.digest() {
            failures.push(SodaVerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.revision_digest != *self.scope.revision_digest() {
            failures.push(SodaVerificationFailure::RevisionDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(SodaVerificationFailure::EvidenceIntegrity);
        }
        match proposal.state() {
            SodaEvidenceState::Tampered => failures.push(SodaVerificationFailure::TamperedEvidence),
            SodaEvidenceState::Partial => failures.push(SodaVerificationFailure::PartialEvidence),
            SodaEvidenceState::Unknown => failures.push(SodaVerificationFailure::UnknownEvidence),
            SodaEvidenceState::Denied => failures.push(SodaVerificationFailure::DeniedEvidence),
            SodaEvidenceState::RateLimited => {
                failures.push(SodaVerificationFailure::RateLimitedEvidence);
            }
            SodaEvidenceState::ProviderUnknown => {
                failures.push(SodaVerificationFailure::ProviderUnknownEvidence);
            }
            SodaEvidenceState::Pass | SodaEvidenceState::Fail | SodaEvidenceState::Warn => {}
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        SodaVerificationReport::new(
            valid,
            valid && proposal.evidence.is_review_eligible(),
            failures,
        )
    }

    pub fn record(
        &mut self,
        proposal: &SodaQualityResultProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<SodaRecordedResult> {
        self.ensure_registration_active()?;
        let key = idempotency_digest(&self.scope, idempotency_key.into())?;
        if key != proposal.evidence.idempotency_key_digest {
            return Err(SodaQualityResultError::ScopeMismatch);
        }
        proposal.validate_integrity()?;
        if let Some(existing) = self.records.get(&key) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(SodaQualityResultError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.calculate_digest();
            return Ok(replay);
        }
        let recorded = SodaRecordedResult::new(key.clone(), proposal, false);
        recorded.validate_integrity()?;
        self.records.insert(key, recorded.clone());
        Ok(recorded)
    }

    pub fn revoke(&mut self) -> Result<crate::RegistrationTransitionReceipt> {
        self.registration.revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<crate::RegistrationTransitionReceipt> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<crate::RegistrationTransitionReceipt> {
        self.registration.restore()
    }

    pub fn revoke_secret(&mut self) -> Result<()> {
        self.provider.revoke_secret()
    }

    pub fn restore_secret(&mut self) -> Result<()> {
        self.provider.restore_secret()
    }

    pub fn consumer(&self) -> Result<MissionSodaQualityConsumer> {
        MissionSodaQualityConsumer::new(self.scope.clone(), self.registration.clone())
    }

    fn ensure_registration_active(&self) -> Result<()> {
        match self.registration.status() {
            RegistrationStatus::Active => Ok(()),
            RegistrationStatus::Revoked => Err(SodaQualityResultError::RegistrationRevoked),
            RegistrationStatus::Reversed => Err(SodaQualityResultError::RegistrationReversed),
        }
    }

    fn validate_registration(&self) -> Result<()> {
        if self.provider.secret_reference().is_revoked() {
            return Err(SodaQualityResultError::SecretRevoked);
        }
        self.registration.validate(
            &self.scope,
            self.provider.secret_reference(),
            &self.provider.definition().provider_digest,
        )
    }
}

fn push_receipts(
    request_receipts: &mut Vec<SodaRequestReceipt>,
    cost_receipts: &mut Vec<SodaCostReceipt>,
    request: &SodaReadRequest,
    response_digest: Digest,
    response_bytes: usize,
) {
    request_receipts.push(request.receipt(Some(response_digest), response_bytes, None));
    cost_receipts.push(SodaCostReceipt::new(request.operation, response_bytes));
}

fn aggregate_state(statuses: [SodaQualityStatus; 3]) -> SodaEvidenceState {
    if statuses.contains(&SodaQualityStatus::Fail) {
        SodaEvidenceState::Fail
    } else if statuses.contains(&SodaQualityStatus::Warn) {
        SodaEvidenceState::Warn
    } else if statuses.contains(&SodaQualityStatus::Unknown) {
        SodaEvidenceState::Unknown
    } else {
        SodaEvidenceState::Pass
    }
}

fn recommendation_for(state: SodaEvidenceState) -> SodaRecommendation {
    match state {
        SodaEvidenceState::Pass => SodaRecommendation::ReviewHealthy,
        SodaEvidenceState::Fail => SodaRecommendation::ReviewRemediation,
        SodaEvidenceState::Warn => SodaRecommendation::ReviewWarning,
        SodaEvidenceState::Unknown | SodaEvidenceState::Partial | SodaEvidenceState::Tampered => {
            SodaRecommendation::NeedMoreEvidence
        }
        SodaEvidenceState::Denied
        | SodaEvidenceState::RateLimited
        | SodaEvidenceState::ProviderUnknown => SodaRecommendation::NoDecisionProviderUnknown,
    }
}

fn provider_error_state(
    error: &SodaProviderError,
) -> (
    SodaEvidenceState,
    SodaEvidenceClassification,
    SodaFailureEvidence,
) {
    match error {
        SodaProviderError::Transport { error, .. } => {
            let state = match error {
                SodaTransportError::Denied => SodaEvidenceState::Denied,
                SodaTransportError::RateLimited { .. } => SodaEvidenceState::RateLimited,
                SodaTransportError::Partial => SodaEvidenceState::Partial,
                SodaTransportError::Tampered => SodaEvidenceState::Tampered,
                SodaTransportError::ProviderUnknown
                | SodaTransportError::BlockedEnv
                | SodaTransportError::InvalidResponse => SodaEvidenceState::ProviderUnknown,
                SodaTransportError::AccessLost | SodaTransportError::TimedOut => {
                    SodaEvidenceState::Unknown
                }
            };
            let classification = match state {
                SodaEvidenceState::Denied => SodaEvidenceClassification::Denied,
                SodaEvidenceState::RateLimited => SodaEvidenceClassification::RateLimit,
                SodaEvidenceState::Partial => SodaEvidenceClassification::Partial,
                SodaEvidenceState::Tampered => SodaEvidenceClassification::Tamper,
                SodaEvidenceState::ProviderUnknown
                | SodaEvidenceState::Unknown
                | SodaEvidenceState::Pass
                | SodaEvidenceState::Fail
                | SodaEvidenceState::Warn => SodaEvidenceClassification::ProviderUnknown,
            };
            (
                state,
                classification,
                SodaFailureEvidence::from_transport(error),
            )
        }
        SodaProviderError::PartialResponse | SodaProviderError::ResponseTooLarge => (
            SodaEvidenceState::Partial,
            SodaEvidenceClassification::Partial,
            SodaFailureEvidence::from_transport(&SodaTransportError::Partial),
        ),
        SodaProviderError::TamperedResponse => (
            SodaEvidenceState::Tampered,
            SodaEvidenceClassification::Tamper,
            SodaFailureEvidence::from_transport(&SodaTransportError::Tampered),
        ),
        SodaProviderError::ScopeMismatch
        | SodaProviderError::InvalidRequest
        | SodaProviderError::SecretRevoked => (
            SodaEvidenceState::ProviderUnknown,
            SodaEvidenceClassification::ProviderUnknown,
            SodaFailureEvidence::from_transport(&SodaTransportError::ProviderUnknown),
        ),
    }
}

fn provider_error_to_result(error: SodaProviderError) -> SodaQualityResultError {
    match error {
        SodaProviderError::Transport { error, .. } => SodaQualityResultError::Transport(error),
        SodaProviderError::ScopeMismatch => SodaQualityResultError::ScopeMismatch,
        SodaProviderError::SecretRevoked => SodaQualityResultError::SecretRevoked,
        SodaProviderError::ResponseTooLarge => SodaQualityResultError::ResponseTooLarge,
        SodaProviderError::TamperedResponse => SodaQualityResultError::TamperedEvidence,
        SodaProviderError::PartialResponse => SodaQualityResultError::PartialEvidence,
        SodaProviderError::InvalidRequest => SodaQualityResultError::InvalidRequest,
    }
}

fn idempotency_digest(scope: &SodaQualityScope, key: String) -> Result<Digest> {
    if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES || key.trim() != key {
        return Err(SodaQualityResultError::InvalidRequest);
    }
    Ok(Digest::from_parts(
        "soda-idempotency-key/v1",
        &[("key", key), ("scope", scope.digest().as_str().to_owned())],
    ))
}

trait RevisionDigestExt {
    fn into_digest(self) -> Digest;
}

impl RevisionDigestExt for Revision {
    fn into_digest(self) -> Digest {
        Digest::from_parts(
            "soda-resource-revision/v1",
            &[("revision", self.get().to_string())],
        )
    }
}

pub type SodaService<T> = SodaQualityResultService<T>;
pub type SodaQualityResultServiceError = SodaQualityResultError;
pub type VerificationFailure = SodaVerificationFailure;
pub type VerificationReport = SodaVerificationReport;
