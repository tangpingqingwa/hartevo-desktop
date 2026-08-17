use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::{
    model::{
        Digest, HoneycombRegistration, HoneycombTraceScope, Layer1Authority, ModelError,
        ProviderErrorKind, QueryId, QueryResultId, QueryResultSnapshot, QueryResultState,
        RegistrationRevocation, SecretReference,
    },
    provider::{
        HoneycombQueryProvider, HoneycombQueryTransport, ProviderDefinitionError,
        QueryCreateRequest, QueryCreateResponse, QueryResultCreateRequest,
        QueryResultCreateResponse, QueryResultGetRequest, TransportError,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub initial_backoff_seconds: u64,
    pub max_backoff_seconds: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_seconds: 1,
            max_backoff_seconds: 60,
        }
    }
}

impl RetryPolicy {
    pub fn new(
        max_attempts: u8,
        initial_backoff_seconds: u64,
        max_backoff_seconds: u64,
    ) -> Result<Self, HoneycombServiceError> {
        if max_attempts == 0
            || max_attempts > crate::MAX_RETRIES
            || initial_backoff_seconds == 0
            || max_backoff_seconds < initial_backoff_seconds
            || max_backoff_seconds > crate::MAX_BACKOFF_SECONDS
        {
            return Err(HoneycombServiceError::InvalidRetryPolicy);
        }
        Ok(Self {
            max_attempts,
            initial_backoff_seconds,
            max_backoff_seconds,
        })
    }

    pub fn delay_seconds(self, failed_attempt: u8, retry_after_seconds: Option<u64>) -> u64 {
        let exponential = self
            .initial_backoff_seconds
            .saturating_mul(2_u64.saturating_pow(u32::from(failed_attempt.saturating_sub(1))));
        retry_after_seconds
            .unwrap_or(exponential)
            .min(self.max_backoff_seconds)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HoneycombServiceError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("provider definition does not match the Honeycomb scope: {0}")]
    ProviderDefinition(ProviderDefinitionError),
    #[error("the opaque Honeycomb secret reference is revoked or scope-bound incorrectly")]
    SecretInvalid,
    #[error("the Honeycomb registration is revoked")]
    RegistrationRevoked,
    #[error("the Honeycomb registration is stale, tampered, or scope-bound incorrectly")]
    RegistrationDrift,
    #[error("the provider response is tampered or internally inconsistent")]
    TamperedEvidence,
    #[error("the provider response region or API version does not match the scope")]
    RegionOrApiVersionMismatch,
    #[error("the provider response team, environment, or dataset does not match the scope")]
    ScopeDimensionMismatch,
    #[error("the provider response query or query-result id does not match the proposal")]
    QueryResultMismatch,
    #[error("retry policy is outside the safe Layer-1 backoff bound")]
    InvalidRetryPolicy,
    #[error("provider transport failed with {kind:?} ({status_code:?})")]
    Provider {
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic_digest: Digest,
    },
}

impl From<ProviderDefinitionError> for HoneycombServiceError {
    fn from(error: ProviderDefinitionError) -> Self {
        Self::ProviderDefinition(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HoneycombQueryProposal {
    pub request: QueryCreateRequest,
    pub registration_digest: Digest,
    pub registration_revision: crate::Revision,
    pub provider_digest: Digest,
    pub proposal_digest: Digest,
    pub native_execution: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HoneycombQueryResultProposal {
    pub request: QueryResultCreateRequest,
    pub registration_digest: Digest,
    pub registration_revision: crate::Revision,
    pub provider_digest: Digest,
    pub proposal_digest: Digest,
    pub native_execution: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetryEvidence {
    pub operation: String,
    pub failed_attempt: u8,
    pub delay_seconds: u64,
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HoneycombResultEvidence {
    pub projection: QueryResultState,
    pub query_digest: Digest,
    pub query_result_digest: Digest,
    pub response_digest: Digest,
    pub aggregate_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub query_window_digest: Digest,
    pub deployment_marker_digest: Digest,
    pub mission_digest: Digest,
    pub project_digest: Digest,
    pub work_product_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub redaction_policy_digest: Digest,
    pub snapshot: QueryResultSnapshot,
    pub retries: Vec<RetryEvidence>,
    pub authority: Layer1Authority,
}

pub type ResultEvidence = HoneycombResultEvidence;

impl HoneycombResultEvidence {
    fn new(
        scope: &HoneycombTraceScope,
        registration: &HoneycombRegistration,
        provider_digest: &Digest,
        snapshot: QueryResultSnapshot,
        retries: Vec<RetryEvidence>,
    ) -> Self {
        let aggregate_digest = Digest::from_fields(
            "honeycomb-aggregate-evidence/v1",
            &snapshot
                .series
                .iter()
                .map(|series| series.series_digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        Self {
            projection: snapshot.state,
            query_digest: snapshot.query_digest.clone(),
            query_result_digest: snapshot.result_digest.clone(),
            response_digest: snapshot.response_digest.clone(),
            aggregate_digest,
            scope_digest: scope.digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            query_window_digest: scope.time_window.digest().clone(),
            deployment_marker_digest: scope.deployment_marker.digest().clone(),
            mission_digest: scope.mission.digest.clone(),
            project_digest: scope.project.digest.clone(),
            work_product_digest: scope.work_product.digest.clone(),
            provider_digest: provider_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            redaction_policy_digest: scope.redaction_policy.digest().clone(),
            snapshot,
            retries,
            authority: Layer1Authority,
        }
    }

    pub fn evidence_digest(&self) -> Digest {
        Digest::from_fields(
            "honeycomb-result-evidence/v1",
            &[
                format!("{:?}", self.projection),
                self.query_digest.as_str().to_owned(),
                self.query_result_digest.as_str().to_owned(),
                self.response_digest.as_str().to_owned(),
                self.aggregate_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.query_window_digest.as_str().to_owned(),
                self.deployment_marker_digest.as_str().to_owned(),
                self.mission_digest.as_str().to_owned(),
                self.project_digest.as_str().to_owned(),
                self.work_product_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.redaction_policy_digest.as_str().to_owned(),
                self.retries
                    .iter()
                    .map(|retry| {
                        format!(
                            "{}:{}:{}:{:?}:{}:{}",
                            retry.operation,
                            retry.failed_attempt,
                            retry.delay_seconds,
                            retry.kind,
                            retry.status_code.map_or(0, u16::from),
                            retry.diagnostic_digest.as_str()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HoneycombResultProposal {
    pub query_id: QueryId,
    pub query_result_id: QueryResultId,
    pub projection: QueryResultState,
    pub evidence: HoneycombResultEvidence,
    pub registration_digest: Digest,
    pub registration_revision: crate::Revision,
    pub provider_digest: Digest,
    pub proposal_digest: Digest,
    pub authority: Layer1Authority,
}

pub type ResultProposal = HoneycombResultProposal;

impl HoneycombResultProposal {
    pub fn validate_digest(&self) -> Result<(), HoneycombServiceError> {
        let expected = Digest::from_fields(
            "honeycomb-result-proposal/v1",
            &[
                self.registration_digest.as_str().to_owned(),
                self.registration_revision.get().to_string(),
                self.provider_digest.as_str().to_owned(),
                self.query_id.as_str().to_owned(),
                self.query_result_id.as_str().to_owned(),
                format!("{:?}", self.projection),
                self.evidence.evidence_digest().as_str().to_owned(),
            ],
        );
        if expected == self.proposal_digest {
            Ok(())
        } else {
            Err(HoneycombServiceError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HoneycombResultReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub receipt_digest: Digest,
    pub status: QueryResultState,
    pub observed_at: i64,
    pub durable: bool,
    pub connected: bool,
    pub native: bool,
    pub authority: Layer1Authority,
}

pub type ResultReceipt = HoneycombResultReceipt;

pub struct HoneycombTraceResultService<T> {
    scope: HoneycombTraceScope,
    secret: SecretReference,
    provider: HoneycombQueryProvider<T>,
    registration: HoneycombRegistration,
    retry_policy: RetryPolicy,
    active: bool,
}

impl<T: fmt::Debug> fmt::Debug for HoneycombTraceResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HoneycombTraceResultService")
            .field("scope", &self.scope)
            .field("secret", &self.secret)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("retry_policy", &self.retry_policy)
            .field("active", &self.active)
            .finish()
    }
}

pub type HoneycombService<T> = HoneycombTraceResultService<T>;

impl<T: HoneycombQueryTransport + fmt::Debug> HoneycombTraceResultService<T> {
    pub fn new(
        scope: HoneycombTraceScope,
        secret: SecretReference,
        provider: HoneycombQueryProvider<T>,
        retry_policy: RetryPolicy,
    ) -> Result<Self, HoneycombServiceError> {
        scope.validate()?;
        if !scope
            .consent
            .contains(crate::ConsentCapability::QueryDefinition)
            || !scope
                .consent
                .contains(crate::ConsentCapability::AggregateQueryResult)
        {
            return Err(HoneycombServiceError::Model(ModelError::InvalidConsent));
        }
        if secret.is_revoked() || secret.scope_digest() != scope.digest() {
            return Err(HoneycombServiceError::SecretInvalid);
        }
        provider.definition().validate_scope(&scope)?;
        let registration = HoneycombRegistration::new(&scope, provider.provider_digest().clone())?;
        Ok(Self {
            scope,
            secret,
            provider,
            registration,
            retry_policy,
            active: true,
        })
    }

    pub fn scope(&self) -> &HoneycombTraceScope {
        &self.scope
    }

    pub fn registration(&self) -> &HoneycombRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &HoneycombQueryProvider<T> {
        &self.provider
    }

    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry_policy
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationRevocation, HoneycombServiceError> {
        if !self.active {
            return Err(HoneycombServiceError::RegistrationRevoked);
        }
        self.active = false;
        self.registration
            .revoke()
            .map_err(HoneycombServiceError::from)
    }

    pub fn propose_query(&self) -> Result<HoneycombQueryProposal, HoneycombServiceError> {
        self.ensure_active()?;
        let request = QueryCreateRequest::from_scope(&self.scope);
        let proposal_digest = Digest::from_fields(
            "honeycomb-query-proposal/v1",
            &[
                self.registration.registration_digest.as_str().to_owned(),
                self.registration.revision.get().to_string(),
                self.provider.provider_digest().as_str().to_owned(),
                request.query_digest.as_str().to_owned(),
                request.scope_digest.as_str().to_owned(),
                request.path.clone(),
                request.native_execution.to_string(),
            ],
        );
        Ok(HoneycombQueryProposal {
            request,
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            provider_digest: self.provider.provider_digest().clone(),
            proposal_digest,
            native_execution: false,
        })
    }

    pub fn propose_query_result(
        &self,
        query_id: QueryId,
    ) -> Result<HoneycombQueryResultProposal, HoneycombServiceError> {
        self.ensure_active()?;
        let request = QueryResultCreateRequest::from_scope(&self.scope, query_id);
        let proposal_digest = Digest::from_fields(
            "honeycomb-query-result-create-proposal/v1",
            &[
                self.registration.registration_digest.as_str().to_owned(),
                self.registration.revision.get().to_string(),
                self.provider.provider_digest().as_str().to_owned(),
                request.query_id.as_str().to_owned(),
                request.query_digest.as_str().to_owned(),
                request.scope_digest.as_str().to_owned(),
                request.path.clone(),
                request.limit.to_string(),
                request.native_execution.to_string(),
            ],
        );
        Ok(HoneycombQueryResultProposal {
            request,
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            provider_digest: self.provider.provider_digest().clone(),
            proposal_digest,
            native_execution: false,
        })
    }

    pub fn create_query(&mut self) -> Result<QueryCreateResponse, HoneycombServiceError> {
        self.ensure_active()?;
        let proposal = self.propose_query()?;
        let response = self
            .provider
            .create_query(&proposal.request)
            .map_err(Self::provider_error)?;
        Self::validate_query_response(&proposal.request, &response)?;
        Ok(response)
    }

    pub fn create_query_result(
        &mut self,
        query_id: QueryId,
    ) -> Result<QueryResultCreateResponse, HoneycombServiceError> {
        self.ensure_active()?;
        let proposal = self.propose_query_result(query_id)?;
        let response = self
            .provider
            .create_query_result(&proposal.request)
            .map_err(Self::provider_error)?;
        Self::validate_query_result_create_response(&proposal.request, &response)?;
        Ok(response)
    }

    pub fn reconcile(
        &mut self,
        query_id: QueryId,
        query_result_id: QueryResultId,
    ) -> Result<HoneycombResultProposal, HoneycombServiceError> {
        self.ensure_active()?;
        let request = QueryResultGetRequest::from_scope(
            &self.scope,
            query_id.clone(),
            query_result_id.clone(),
        );
        let mut retries = Vec::new();
        for attempt in 1..=self.retry_policy.max_attempts {
            match self.provider.get_query_result(&request) {
                Ok(snapshot) => {
                    self.validate_snapshot(&request, &snapshot)?;
                    return Ok(self.finish_result_proposal(
                        query_id,
                        query_result_id,
                        snapshot,
                        retries,
                    ));
                }
                Err(error) if error.retryable && attempt < self.retry_policy.max_attempts => {
                    retries.push(RetryEvidence {
                        operation: "GET /1/query_results".to_owned(),
                        failed_attempt: attempt,
                        delay_seconds: self
                            .retry_policy
                            .delay_seconds(attempt, error.retry_after_seconds),
                        kind: error.kind,
                        status_code: error.status_code,
                        diagnostic_digest: error.diagnostic_digest,
                    });
                }
                Err(error) => {
                    let state = state_for_provider_error(error.kind);
                    let snapshot = QueryResultSnapshot::new(
                        &self.scope,
                        query_id.clone(),
                        query_result_id.clone(),
                        state,
                        Vec::new(),
                        Some(error.kind),
                        0,
                        error.diagnostic_digest,
                    )?;
                    return Ok(self.finish_result_proposal(
                        query_id,
                        query_result_id,
                        snapshot,
                        retries,
                    ));
                }
            }
        }
        unreachable!("bounded retry loop always returns")
    }

    pub fn record_receipt(
        &self,
        proposal: &HoneycombResultProposal,
    ) -> Result<HoneycombResultReceipt, HoneycombServiceError> {
        self.ensure_active()?;
        self.validate_result_proposal(proposal)?;
        let evidence_digest = proposal.evidence.evidence_digest();
        let receipt_digest = Digest::from_fields(
            "honeycomb-result-receipt/v1",
            &[
                proposal.proposal_digest.as_str().to_owned(),
                evidence_digest.as_str().to_owned(),
                format!("{:?}", proposal.projection),
                proposal.evidence.snapshot.observed_at.to_string(),
                "durable=false".to_owned(),
                "connected=false".to_owned(),
                "native=false".to_owned(),
            ],
        );
        Ok(HoneycombResultReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest,
            receipt_digest,
            status: proposal.projection,
            observed_at: proposal.evidence.snapshot.observed_at,
            durable: false,
            connected: false,
            native: false,
            authority: Layer1Authority,
        })
    }

    fn finish_result_proposal(
        &self,
        query_id: QueryId,
        query_result_id: QueryResultId,
        snapshot: QueryResultSnapshot,
        retries: Vec<RetryEvidence>,
    ) -> HoneycombResultProposal {
        let evidence = HoneycombResultEvidence::new(
            &self.scope,
            &self.registration,
            self.provider.provider_digest(),
            snapshot,
            retries,
        );
        let proposal_digest = Digest::from_fields(
            "honeycomb-result-proposal/v1",
            &[
                self.registration.registration_digest.as_str().to_owned(),
                self.registration.revision.get().to_string(),
                self.provider.provider_digest().as_str().to_owned(),
                query_id.as_str().to_owned(),
                query_result_id.as_str().to_owned(),
                format!("{:?}", evidence.projection),
                evidence.evidence_digest().as_str().to_owned(),
            ],
        );
        HoneycombResultProposal {
            query_id,
            query_result_id,
            projection: evidence.projection,
            evidence,
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            provider_digest: self.provider.provider_digest().clone(),
            proposal_digest,
            authority: Layer1Authority,
        }
    }

    fn validate_query_response(
        request: &QueryCreateRequest,
        response: &QueryCreateResponse,
    ) -> Result<(), HoneycombServiceError> {
        if request.native_execution
            || response.region != request.region
            || response.api_version != request.api_version
            || response.team != request.team
            || response.environment != request.environment
            || response.dataset != request.dataset
            || response.query_digest != request.query_digest
        {
            return Err(HoneycombServiceError::TamperedEvidence);
        }
        Ok(())
    }

    fn validate_query_result_create_response(
        request: &QueryResultCreateRequest,
        response: &QueryResultCreateResponse,
    ) -> Result<(), HoneycombServiceError> {
        if request.native_execution
            || response.query_id != request.query_id
            || response.region != request.region
            || response.api_version != request.api_version
            || response.team != request.team
            || response.environment != request.environment
            || response.dataset != request.dataset
            || response.query_digest != request.query_digest
        {
            return Err(HoneycombServiceError::TamperedEvidence);
        }
        Ok(())
    }

    fn validate_snapshot(
        &self,
        request: &QueryResultGetRequest,
        snapshot: &QueryResultSnapshot,
    ) -> Result<(), HoneycombServiceError> {
        snapshot
            .validate_digest()
            .map_err(|_| HoneycombServiceError::TamperedEvidence)?;
        if snapshot.region != request.region || snapshot.api_version != request.api_version {
            return Err(HoneycombServiceError::RegionOrApiVersionMismatch);
        }
        if snapshot.team != request.team
            || snapshot.environment != request.environment
            || snapshot.dataset != request.dataset
            || snapshot.scope_digest != request.scope_digest
        {
            return Err(HoneycombServiceError::ScopeDimensionMismatch);
        }
        if snapshot.query_id != request.query_id
            || snapshot.query_result_id != request.query_result_id
            || snapshot.query_digest != request.query_digest
        {
            return Err(HoneycombServiceError::QueryResultMismatch);
        }
        if snapshot.deployment_marker_digest != self.scope.deployment_marker.digest().clone()
            || snapshot.time_window_digest != self.scope.time_window.digest().clone()
            || snapshot.redaction_policy_digest != self.scope.redaction_policy.digest().clone()
        {
            return Err(HoneycombServiceError::TamperedEvidence);
        }
        Ok(())
    }

    fn validate_result_proposal(
        &self,
        proposal: &HoneycombResultProposal,
    ) -> Result<(), HoneycombServiceError> {
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
            || proposal.provider_digest != *self.provider.provider_digest()
            || proposal.query_id != proposal.evidence.snapshot.query_id
            || proposal.query_result_id != proposal.evidence.snapshot.query_result_id
            || proposal.projection != proposal.evidence.projection
            || proposal.evidence.scope_digest != *self.scope.digest()
            || proposal.evidence.permission_digest != *self.scope.permission_digest()
            || proposal.evidence.consent_digest != *self.scope.consent_digest()
            || proposal.evidence.query_digest != *self.scope.query_digest()
            || proposal.evidence.deployment_marker_digest != *self.scope.deployment_marker.digest()
            || proposal.evidence.query_window_digest != *self.scope.time_window.digest()
            || proposal.evidence.registration_digest != self.registration.registration_digest
        {
            return Err(HoneycombServiceError::RegistrationDrift);
        }
        proposal.validate_digest()?;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), HoneycombServiceError> {
        if self.active {
            Ok(())
        } else {
            Err(HoneycombServiceError::RegistrationRevoked)
        }
    }

    fn provider_error(error: TransportError) -> HoneycombServiceError {
        HoneycombServiceError::Provider {
            kind: error.kind,
            status_code: error.status_code,
            diagnostic_digest: error.diagnostic_digest,
        }
    }
}

fn state_for_provider_error(kind: ProviderErrorKind) -> QueryResultState {
    match kind {
        ProviderErrorKind::RateLimited => QueryResultState::RateLimited,
        ProviderErrorKind::Unauthenticated | ProviderErrorKind::PermissionDenied => {
            QueryResultState::AccessLost
        }
        _ => QueryResultState::ProviderUnknown,
    }
}
