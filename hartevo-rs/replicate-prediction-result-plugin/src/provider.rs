use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::Serialize;
use thiserror::Error;

use crate::model::{
    AccountId, ApiHost, Digest, MAX_PAGE_SIZE, MAX_RETRY_ATTEMPTS, ModelError, OpaquePageToken,
    PredictionId, PredictionStatus, ProviderErrorEvidence, ProviderErrorKind, ReplicateDigestSet,
    ReplicatePredictionRecord, ReplicateRegistration, ReplicateScope, RetryEvidence,
    SecretReference,
};

pub const MAX_LIST_PAGES: u8 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicateProviderState {
    Ready,
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
    Revoked,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("HTTP status {status_code} without retaining the provider body")]
    Http {
        status_code: u16,
        retry_after_millis: Option<u64>,
        error_digest: Digest,
    },
    #[error("the provider request timed out")]
    Timeout { error_digest: Digest },
    #[error("the provider response was malformed")]
    Malformed { error_digest: Digest },
    #[error("the provider response was partial")]
    Partial { error_digest: Digest },
    #[error("the live environment is blocked")]
    BlockedEnv,
    #[error("bounded prediction listing is not available on this transport")]
    ListingUnsupported,
}

impl TransportError {
    pub fn http(
        status_code: u16,
        retry_after_millis: Option<u64>,
        untrusted_message: impl AsRef<str>,
    ) -> Self {
        Self::Http {
            status_code,
            retry_after_millis,
            error_digest: Digest::from_text(untrusted_message.as_ref().as_bytes()),
        }
    }

    pub fn timeout(untrusted_message: impl AsRef<str>) -> Self {
        Self::Timeout {
            error_digest: Digest::from_text(untrusted_message.as_ref().as_bytes()),
        }
    }

    pub fn malformed(untrusted_message: impl AsRef<str>) -> Self {
        Self::Malformed {
            error_digest: Digest::from_text(untrusted_message.as_ref().as_bytes()),
        }
    }

    pub fn partial(untrusted_message: impl AsRef<str>) -> Self {
        Self::Partial {
            error_digest: Digest::from_text(untrusted_message.as_ref().as_bytes()),
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Http { status_code, .. } => Some(*status_code),
            Self::Timeout { .. }
            | Self::Malformed { .. }
            | Self::Partial { .. }
            | Self::BlockedEnv
            | Self::ListingUnsupported => None,
        }
    }

    pub fn error_digest(&self) -> Digest {
        match self {
            Self::Http { error_digest, .. }
            | Self::Timeout { error_digest }
            | Self::Malformed { error_digest }
            | Self::Partial { error_digest } => error_digest.clone(),
            Self::BlockedEnv => Digest::from_text("BLOCKED_ENV"),
            Self::ListingUnsupported => Digest::from_text("LISTING_UNSUPPORTED"),
        }
    }

    pub const fn retry_after_millis(&self) -> Option<u64> {
        match self {
            Self::Http {
                retry_after_millis, ..
            } => *retry_after_millis,
            _ => None,
        }
    }

    pub const fn retryable(&self) -> bool {
        match self {
            Self::Http { status_code, .. } => *status_code == 429 || *status_code >= 500,
            Self::Timeout { .. } => true,
            Self::Malformed { .. }
            | Self::Partial { .. }
            | Self::BlockedEnv
            | Self::ListingUnsupported => false,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("Replicate provider error: {evidence:?}")]
pub struct ReplicateProviderError {
    pub evidence: ProviderErrorEvidence,
    pub retries: Vec<RetryEvidence>,
}

impl ReplicateProviderError {
    pub fn kind(&self) -> ProviderErrorKind {
        self.evidence.kind
    }

    pub const fn status_code(&self) -> Option<u16> {
        self.evidence.status_code
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub base_backoff_millis: u64,
    pub max_backoff_millis: u64,
}

impl RetryPolicy {
    pub fn new(
        max_attempts: u8,
        base_backoff_millis: u64,
        max_backoff_millis: u64,
    ) -> Result<Self, ModelError> {
        if !(1..=MAX_RETRY_ATTEMPTS).contains(&max_attempts)
            || base_backoff_millis == 0
            || max_backoff_millis < base_backoff_millis
            || max_backoff_millis > 60_000
        {
            return Err(ModelError::InvalidBound);
        }
        Ok(Self {
            max_attempts,
            base_backoff_millis,
            max_backoff_millis,
        })
    }

    pub fn backoff_millis(self, attempt: u8, retry_after_millis: Option<u64>) -> u64 {
        let exponent = attempt.saturating_sub(1).min(6);
        let exponential = self.base_backoff_millis.saturating_mul(1_u64 << exponent);
        let bounded = exponential.min(self.max_backoff_millis);
        match retry_after_millis {
            Some(value) => value.min(self.max_backoff_millis).max(bounded),
            None => bounded,
        }
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_backoff_millis: 50,
            max_backoff_millis: 2_000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PredictionGetRequest {
    pub method: String,
    pub host: ApiHost,
    pub path: String,
    pub account_id: AccountId,
    pub prediction_id: PredictionId,
    pub secret_reference_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
}

impl PredictionGetRequest {
    pub fn new(scope: &ReplicateScope, secret: &SecretReference) -> Self {
        Self {
            method: "GET".to_owned(),
            host: scope.api_host().clone(),
            path: format!(
                "/v1/predictions/{}",
                scope.prediction().prediction_id().as_str()
            ),
            account_id: scope.account_id().clone(),
            prediction_id: scope.prediction().prediction_id().clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.scope_digest().clone(),
            revision_digest: scope.revision_digest().clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PredictionListRequest {
    pub method: String,
    pub host: ApiHost,
    pub path: String,
    pub account_id: AccountId,
    pub model_digest: Digest,
    pub version_or_deployment_digest: Digest,
    pub page_size: u16,
    pub page_number: u8,
    pub page_token_digest: Option<Digest>,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
}

impl PredictionListRequest {
    pub fn new(
        scope: &ReplicateScope,
        page_size: u16,
        page_number: u8,
        page_token: Option<&OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::InvalidBound);
        }
        Ok(Self {
            method: "GET".to_owned(),
            host: scope.api_host().clone(),
            path: "/v1/predictions".to_owned(),
            account_id: scope.account_id().clone(),
            model_digest: scope.model_digest().clone(),
            version_or_deployment_digest: scope.version_or_deployment_digest().clone(),
            page_size,
            page_number,
            page_token_digest: page_token.map(OpaquePageToken::digest),
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.scope_digest().clone(),
            revision_digest: scope.revision_digest().clone(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PredictionPage {
    pub records: Vec<ReplicatePredictionRecord>,
    pub next: Option<OpaquePageToken>,
    pub page_number: u8,
    pub partial: bool,
    pub page_digest: Digest,
}

impl PredictionPage {
    pub fn new(
        records: Vec<ReplicatePredictionRecord>,
        next: Option<OpaquePageToken>,
        page_number: u8,
        partial: bool,
    ) -> Result<Self, ModelError> {
        if records.len() > usize::from(MAX_PAGE_SIZE) || page_number == 0 {
            return Err(ModelError::InvalidBound);
        }
        let page_digest = Digest::from_fields(
            "replicate-prediction-page/v1",
            &[
                records
                    .iter()
                    .map(|record| record.response_digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                next.as_ref().map_or_else(
                    || "none".to_owned(),
                    |token| token.digest().as_str().to_owned(),
                ),
                page_number.to_string(),
                partial.to_string(),
            ],
        );
        Ok(Self {
            records,
            next,
            page_number,
            partial,
            page_digest,
        })
    }

    pub fn verify_digest(&self) -> bool {
        Self::new(
            self.records.clone(),
            self.next.clone(),
            self.page_number,
            self.partial,
        )
        .is_ok_and(|page| page.page_digest == self.page_digest)
    }
}

pub trait ReplicateTransport: fmt::Debug {
    fn get_prediction(
        &mut self,
        request: &PredictionGetRequest,
    ) -> Result<ReplicatePredictionRecord, TransportError>;

    fn list_predictions(
        &mut self,
        _request: &PredictionListRequest,
    ) -> Result<PredictionPage, TransportError> {
        Err(TransportError::ListingUnsupported)
    }

    fn provenance(&self) -> ProviderProvenance;
}

#[derive(Clone, Debug)]
pub struct RecordingReplicateTransport {
    provenance: ProviderProvenance,
    get_responses: VecDeque<Result<ReplicatePredictionRecord, TransportError>>,
    list_responses: VecDeque<Result<PredictionPage, TransportError>>,
    get_requests: Vec<PredictionGetRequest>,
    list_requests: Vec<PredictionListRequest>,
}

impl RecordingReplicateTransport {
    pub fn new(
        provenance: ProviderProvenance,
        get_responses: impl IntoIterator<Item = Result<ReplicatePredictionRecord, TransportError>>,
    ) -> Self {
        Self {
            provenance,
            get_responses: get_responses.into_iter().collect(),
            list_responses: VecDeque::new(),
            get_requests: Vec::new(),
            list_requests: Vec::new(),
        }
    }

    pub fn recording(
        get_responses: impl IntoIterator<Item = Result<ReplicatePredictionRecord, TransportError>>,
    ) -> Self {
        Self::new(ProviderProvenance::Recording, get_responses)
    }

    pub fn fixture(
        get_responses: impl IntoIterator<Item = Result<ReplicatePredictionRecord, TransportError>>,
    ) -> Self {
        Self::new(ProviderProvenance::Fixture, get_responses)
    }

    pub fn loopback(
        get_responses: impl IntoIterator<Item = Result<ReplicatePredictionRecord, TransportError>>,
    ) -> Self {
        Self::new(ProviderProvenance::Loopback, get_responses)
    }

    pub fn fake(
        get_responses: impl IntoIterator<Item = Result<ReplicatePredictionRecord, TransportError>>,
    ) -> Self {
        Self::fixture(get_responses)
    }

    pub fn blocked_env() -> Self {
        Self::new(
            ProviderProvenance::BlockedEnv,
            [Err(TransportError::BlockedEnv)],
        )
    }

    pub fn push_get_response(
        &mut self,
        response: Result<ReplicatePredictionRecord, TransportError>,
    ) {
        self.get_responses.push_back(response);
    }

    pub fn push_list_response(&mut self, response: Result<PredictionPage, TransportError>) {
        self.list_responses.push_back(response);
    }

    pub fn get_requests(&self) -> &[PredictionGetRequest] {
        &self.get_requests
    }

    pub fn list_requests(&self) -> &[PredictionListRequest] {
        &self.list_requests
    }
}

impl ReplicateTransport for RecordingReplicateTransport {
    fn get_prediction(
        &mut self,
        request: &PredictionGetRequest,
    ) -> Result<ReplicatePredictionRecord, TransportError> {
        self.get_requests.push(request.clone());
        self.get_responses
            .pop_front()
            .unwrap_or(Err(TransportError::BlockedEnv))
    }

    fn list_predictions(
        &mut self,
        request: &PredictionListRequest,
    ) -> Result<PredictionPage, TransportError> {
        self.list_requests.push(request.clone());
        self.list_responses
            .pop_front()
            .unwrap_or(Err(TransportError::ListingUnsupported))
    }

    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }
}

pub type FixtureReplicateTransport = RecordingReplicateTransport;
pub type LoopbackReplicateTransport = RecordingReplicateTransport;
pub type FakeReplicateTransport = RecordingReplicateTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl ReplicateTransport for BlockedEnvTransport {
    fn get_prediction(
        &mut self,
        _request: &PredictionGetRequest,
    ) -> Result<ReplicatePredictionRecord, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn list_predictions(
        &mut self,
        _request: &PredictionListRequest,
    ) -> Result<PredictionPage, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderObservation {
    pub record: ReplicatePredictionRecord,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub digests: ReplicateDigestSet,
    pub retries: Vec<RetryEvidence>,
    pub observation_digest: Digest,
}

impl ProviderObservation {
    pub fn status(&self) -> PredictionStatus {
        self.record.status()
    }

    pub fn verify_digest(&self) -> bool {
        let expected = Digest::from_fields(
            "replicate-provider-observation/v1",
            &[
                self.record.response_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
                self.digests.scope_digest.as_str().to_owned(),
                self.retries
                    .iter()
                    .map(|retry| retry.error_digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        );
        expected == self.observation_digest && !self.connected && !self.native
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderListObservation {
    pub records: Vec<ReplicatePredictionRecord>,
    pub pages_observed: u8,
    pub partial: bool,
    pub page_token_digests: Vec<Digest>,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub digests: ReplicateDigestSet,
    pub retries: Vec<RetryEvidence>,
    pub observation_digest: Digest,
}

pub struct ReplicateProvider<T: ReplicateTransport> {
    registration: ReplicateRegistration,
    secret_reference: SecretReference,
    transport: T,
    retry_policy: RetryPolicy,
    state: ReplicateProviderState,
    last_status: Option<PredictionStatus>,
    last_response_digest: Option<Digest>,
}

impl<T: ReplicateTransport> fmt::Debug for ReplicateProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicateProvider")
            .field("registration", &self.registration)
            .field("secret_reference", &self.secret_reference)
            .field("transport", &self.transport)
            .field("retry_policy", &self.retry_policy)
            .field("state", &self.state)
            .field("last_status", &self.last_status)
            .field("last_response_digest", &self.last_response_digest)
            .finish()
    }
}

impl<T: ReplicateTransport> ReplicateProvider<T> {
    pub fn new(
        registration: ReplicateRegistration,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, ModelError> {
        Self::with_retry_policy(
            registration,
            secret_reference,
            transport,
            RetryPolicy::default(),
        )
    }

    pub fn with_retry_policy(
        registration: ReplicateRegistration,
        secret_reference: SecretReference,
        transport: T,
        retry_policy: RetryPolicy,
    ) -> Result<Self, ModelError> {
        if !registration.is_active()
            || secret_reference.is_revoked()
            || secret_reference.scope_digest() != registration.scope().scope_digest()
            || registration.provider_definition().native
        {
            return Err(ModelError::InvalidRegistration);
        }
        Ok(Self {
            registration,
            secret_reference,
            state: match transport.provenance() {
                ProviderProvenance::Fixture => ReplicateProviderState::Fixture,
                ProviderProvenance::Recording => ReplicateProviderState::Recording,
                ProviderProvenance::Loopback => ReplicateProviderState::Loopback,
                ProviderProvenance::BlockedEnv => ReplicateProviderState::BlockedEnv,
            },
            transport,
            retry_policy,
            last_status: None,
            last_response_digest: None,
        })
    }

    pub fn registration(&self) -> &ReplicateRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &ReplicateScope {
        self.registration.scope()
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn definition(&self) -> &crate::model::ReplicateProviderDefinition {
        self.registration.provider_definition()
    }

    pub fn state(&self) -> ReplicateProviderState {
        if !self.registration.is_active() || self.secret_reference.is_revoked() {
            ReplicateProviderState::Revoked
        } else {
            self.state
        }
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub fn revoke(&self) -> Result<crate::model::RevocationReceipt, ModelError> {
        self.registration.revoke()
    }

    pub fn get_prediction(&mut self) -> Result<ProviderObservation, ReplicateProviderError> {
        self.read_prediction()
    }

    pub fn read_prediction(&mut self) -> Result<ProviderObservation, ReplicateProviderError> {
        self.ensure_active()?;
        let request = PredictionGetRequest::new(self.scope(), &self.secret_reference);
        let mut retries = Vec::new();
        for attempt in 1..=self.retry_policy.max_attempts {
            match self.transport.get_prediction(&request) {
                Ok(record) => {
                    if let Err(error) = self.validate_record(&record) {
                        return Err(with_retries(error, retries));
                    }
                    let provenance = self.transport.provenance();
                    let observation_digest = Digest::from_fields(
                        "replicate-provider-observation/v1",
                        &[
                            record.response_digest.as_str().to_owned(),
                            format!("{provenance:?}"),
                            self.registration.scope().scope_digest().as_str().to_owned(),
                            retries
                                .iter()
                                .map(|retry| retry.error_digest.as_str().to_owned())
                                .collect::<Vec<_>>()
                                .join(","),
                        ],
                    );
                    let observation = ProviderObservation {
                        record: record.clone(),
                        provenance,
                        connected: false,
                        native: false,
                        digests: self.registration.provider_definition().digests().clone(),
                        retries,
                        observation_digest,
                    };
                    self.last_status = Some(record.status());
                    self.last_response_digest = Some(record.response_digest.clone());
                    self.state = ReplicateProviderState::Ready;
                    return Ok(observation);
                }
                Err(error) if error.retryable() && attempt < self.retry_policy.max_attempts => {
                    let kind = transport_error_kind(&error);
                    let backoff = self
                        .retry_policy
                        .backoff_millis(attempt, error.retry_after_millis());
                    retries.push(RetryEvidence {
                        operation: "GET /v1/predictions/{prediction_id}".to_owned(),
                        attempt,
                        kind,
                        status_code: error.status_code(),
                        backoff_millis: backoff,
                        error_digest: error.error_digest(),
                    });
                }
                Err(error) => {
                    return Err(with_retries(
                        transport_error_to_provider_error(&error),
                        retries,
                    ));
                }
            }
        }
        Err(with_retries(
            ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::ProviderUnknown,
                None,
                None,
                "retry loop exhausted",
            )),
            retries,
        ))
    }

    pub fn record_prediction(
        &mut self,
        record: ReplicatePredictionRecord,
    ) -> Result<ProviderObservation, ReplicateProviderError> {
        self.ensure_active()?;
        self.validate_record(&record)?;
        let provenance = self.transport.provenance();
        let observation_digest = Digest::from_fields(
            "replicate-provider-observation/v1",
            &[
                record.response_digest.as_str().to_owned(),
                format!("{provenance:?}"),
                self.registration.scope().scope_digest().as_str().to_owned(),
                "recorded-directly".to_owned(),
            ],
        );
        self.last_status = Some(record.status());
        self.last_response_digest = Some(record.response_digest.clone());
        Ok(ProviderObservation {
            record,
            provenance,
            connected: false,
            native: false,
            digests: self.registration.provider_definition().digests().clone(),
            retries: Vec::new(),
            observation_digest,
        })
    }

    pub fn list_predictions(
        &mut self,
        page_size: u16,
    ) -> Result<ProviderListObservation, ReplicateProviderError> {
        self.ensure_active()?;
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::Malformed,
                None,
                None,
                "invalid page size",
            )));
        }
        let mut page_number = 1_u8;
        let mut page_token: Option<OpaquePageToken> = None;
        let mut seen_tokens = BTreeSet::new();
        let mut records = Vec::new();
        let mut page_token_digests = Vec::new();
        let mut retries = Vec::new();
        let mut partial = false;
        loop {
            let request = PredictionListRequest::new(
                self.scope(),
                page_size,
                page_number,
                page_token.as_ref(),
            )
            .map_err(|error| ProviderError::new(model_error_evidence(error)))?;
            let page = match self.transport.list_predictions(&request) {
                Ok(page) => page,
                Err(error)
                    if error.retryable()
                        && retries.len() < usize::from(self.retry_policy.max_attempts - 1) =>
                {
                    let attempt = u8::try_from(retries.len() + 1).unwrap_or(MAX_RETRY_ATTEMPTS);
                    retries.push(RetryEvidence {
                        operation: "GET /v1/predictions".to_owned(),
                        attempt,
                        kind: transport_error_kind(&error),
                        status_code: error.status_code(),
                        backoff_millis: self
                            .retry_policy
                            .backoff_millis(attempt, error.retry_after_millis()),
                        error_digest: error.error_digest(),
                    });
                    continue;
                }
                Err(error) => {
                    return Err(with_retries(
                        transport_error_to_provider_error(&error),
                        retries,
                    ));
                }
            };
            if !page.verify_digest() {
                return Err(with_retries(
                    ProviderError::new(ProviderErrorEvidence::redacted(
                        ProviderErrorKind::TamperedEvidence,
                        None,
                        None,
                        "prediction page digest mismatch",
                    )),
                    retries,
                ));
            }
            partial |= page.partial;
            for record in &page.records {
                self.validate_list_record(record)?;
            }
            records.extend(page.records);
            if let Some(next) = page.next {
                let next_digest = next.digest();
                if !seen_tokens.insert(next_digest.clone()) || page_number >= MAX_LIST_PAGES {
                    return Err(with_retries(
                        ProviderError::new(ProviderErrorEvidence::redacted(
                            ProviderErrorKind::Partial,
                            None,
                            None,
                            "bounded prediction pagination loop or cap",
                        )),
                        retries,
                    ));
                }
                page_token_digests.push(next_digest);
                page_token = Some(next);
                page_number += 1;
            } else {
                break;
            }
        }
        let provenance = self.transport.provenance();
        let observation_digest = Digest::from_fields(
            "replicate-provider-list-observation/v1",
            &[
                records
                    .iter()
                    .map(|record| record.response_digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                page_number.to_string(),
                partial.to_string(),
                page_token_digests
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        );
        Ok(ProviderListObservation {
            records,
            pages_observed: page_number,
            partial,
            page_token_digests,
            provenance,
            connected: false,
            native: false,
            digests: self.registration.provider_definition().digests().clone(),
            retries,
            observation_digest,
        })
    }

    fn ensure_active(&self) -> Result<(), ReplicateProviderError> {
        if !self.registration.is_active() {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::Revoked,
                None,
                None,
                "registration revoked",
            )));
        }
        if self.secret_reference.is_revoked() {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::Revoked,
                None,
                None,
                "secret reference revoked",
            )));
        }
        Ok(())
    }

    fn validate_list_record(
        &self,
        record: &ReplicatePredictionRecord,
    ) -> Result<(), ReplicateProviderError> {
        if !record.verify_digest() || record.partial {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                if record.partial {
                    ProviderErrorKind::Partial
                } else {
                    ProviderErrorKind::TamperedEvidence
                },
                None,
                None,
                "prediction list item is malformed or partial",
            )));
        }
        if record.account_id != *self.scope().account_id()
            || record.model.model_digest() != self.scope().model_digest()
            || record.model.version_or_deployment_digest()
                != self.scope().version_or_deployment_digest()
        {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::ScopeDrift,
                None,
                None,
                "prediction list item escaped exact account/model scope",
            )));
        }
        Ok(())
    }

    fn validate_record(
        &self,
        record: &ReplicatePredictionRecord,
    ) -> Result<(), ReplicateProviderError> {
        if !record.verify_digest() {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::TamperedEvidence,
                None,
                None,
                "prediction response digest mismatch",
            )));
        }
        if record.partial {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::Partial,
                None,
                None,
                "prediction response is partial",
            )));
        }
        if record.account_id != *self.scope().account_id() {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::AccountDrift,
                None,
                None,
                "prediction account drift",
            )));
        }
        if record.prediction_id != *self.scope().prediction().prediction_id() {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::PredictionDrift,
                None,
                None,
                "prediction id drift",
            )));
        }
        if record.model.model_digest() != self.scope().model_digest() {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::ModelDrift,
                None,
                None,
                "model digest drift",
            )));
        }
        if record.model.version_or_deployment_digest()
            != self.scope().version_or_deployment_digest()
        {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::VersionOrDeploymentDrift,
                None,
                None,
                "model version or deployment drift",
            )));
        }
        let status = record.status();
        if !self.scope().prediction().expected_status().accepts(status) {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::StatusDrift,
                None,
                None,
                "prediction status outside exact scope",
            )));
        }
        if self
            .scope()
            .prediction()
            .metric_scope()
            .max_predict_time_millis()
            .is_some_and(|limit| {
                record
                    .metrics
                    .predict_time_millis
                    .is_some_and(|v| v > limit)
            })
            || self
                .scope()
                .prediction()
                .metric_scope()
                .max_total_time_millis()
                .is_some_and(|limit| record.metrics.total_time_millis.is_some_and(|v| v > limit))
        {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::MetricDrift,
                None,
                None,
                "runtime metric exceeded exact scope",
            )));
        }
        let output_scope = self.scope().prediction().output_url_expiry();
        if !record.output.data_removed
            && output_scope.require_url_expiry()
            && (record.output.urls.is_empty()
                || record
                    .output
                    .urls
                    .iter()
                    .any(|url| url.expires_at.is_none()))
        {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::OutputUrlExpiryMismatch,
                None,
                None,
                "output URL expiry is missing",
            )));
        }
        if !record.output.data_removed
            && let Some(expected) = output_scope.expected_expires_at()
            && !record
                .output
                .urls
                .iter()
                .any(|url| url.expires_at == Some(expected))
        {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::OutputUrlExpiryMismatch,
                None,
                None,
                "output URL expiry drift",
            )));
        }
        if !record.output.data_removed
            && record.output.urls.iter().any(|url| {
                url.expires_at.is_some_and(|expiry| {
                    expiry
                        .seconds()
                        .saturating_sub(record.observed_at.seconds())
                        > output_scope.max_ttl_seconds()
                })
            })
        {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::OutputUrlExpiryMismatch,
                None,
                None,
                "output URL expiry exceeds bounded TTL",
            )));
        }
        if !record.output.data_removed
            && let Some(expected) = output_scope.expected_content_digest()
            && record.output.content_digest.as_ref() != Some(expected)
        {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::OutputContentDigestMismatch,
                None,
                None,
                "output content digest drift",
            )));
        }
        if let Some(previous) = self.last_status
            && !PredictionStatus::can_follow(previous, status)
        {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::StatusDrift,
                None,
                None,
                "prediction status regressed",
            )));
        }
        if let Some(previous_digest) = &self.last_response_digest
            && previous_digest != &record.response_digest
            && record.prediction_id == *self.scope().prediction().prediction_id()
            && self.last_status == Some(status)
            && status != PredictionStatus::DataRemoved
        {
            return Err(ProviderError::new(ProviderErrorEvidence::redacted(
                ProviderErrorKind::ReplayDetected,
                None,
                None,
                "same prediction status changed across replay",
            )));
        }
        Ok(())
    }
}

type ProviderError = ReplicateProviderError;

fn with_retries(mut error: ProviderError, retries: Vec<RetryEvidence>) -> ProviderError {
    error.retries = retries;
    error
}

fn transport_error_kind(error: &TransportError) -> ProviderErrorKind {
    match error {
        TransportError::Http { status_code, .. } => match status_code {
            401 => ProviderErrorKind::Unauthorized,
            403 => ProviderErrorKind::Forbidden,
            404 => ProviderErrorKind::NotFound,
            409 => ProviderErrorKind::Conflict,
            429 => ProviderErrorKind::RateLimited,
            500..=599 => ProviderErrorKind::ServerError,
            _ => ProviderErrorKind::ProviderUnknown,
        },
        TransportError::Timeout { .. } => ProviderErrorKind::Timeout,
        TransportError::Malformed { .. } => ProviderErrorKind::Malformed,
        TransportError::Partial { .. } => ProviderErrorKind::Partial,
        TransportError::BlockedEnv => ProviderErrorKind::BlockedEnv,
        TransportError::ListingUnsupported => ProviderErrorKind::ProviderUnknown,
    }
}

fn transport_error_to_provider_error(error: &TransportError) -> ProviderError {
    let kind = transport_error_kind(error);
    ProviderError::new(ProviderErrorEvidence::from_digest(
        kind,
        error.status_code(),
        error.retry_after_millis(),
        error.error_digest(),
    ))
}

fn model_error_evidence(error: ModelError) -> ProviderErrorEvidence {
    ProviderErrorEvidence::redacted(ProviderErrorKind::Malformed, None, None, error.to_string())
}

impl ReplicateProviderError {
    fn new(evidence: ProviderErrorEvidence) -> Self {
        Self {
            evidence,
            retries: Vec::new(),
        }
    }
}
