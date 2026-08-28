//! Typed Bitbucket provider registration and bounded read orchestration.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    BitbucketAccessToken, BitbucketDeliveryEvidence, BitbucketDeliveryScope, BitbucketReadRequest,
    BitbucketResponseBody, BitbucketResponseReceipt, BuildNumber, CommitHash,
    CommitStatusProjection, DeliveryResultState, DeploymentProjection, DeploymentUuid, Digest,
    ModelError, PartialReason, PipelineProjection, PipelineUuid, PullRequestId,
    PullRequestProjection, RepositoryProjection, RepositorySlug, RepositoryUuid, Revision,
    SecretReference, TransportProvenance, WorkspaceId, compute_evidence_digest,
    digest_serializable, validate_plugin_metadata,
};
use crate::transport::{
    BitbucketDeliveryTransport, BitbucketEndpoint, BitbucketHttpRequest, BitbucketHttpResponse,
    BitbucketTransportError, RequestBounds,
};
use crate::{
    BITBUCKET_API_REVISION, BITBUCKET_DELIVERY_RESULT_CONTRACT_VERSION,
    BITBUCKET_DELIVERY_RESULT_PLUGIN_VERSION, BITBUCKET_DELIVERY_RESULT_SERVICE_ID,
    BITBUCKET_PROVIDER_REVISION, MAX_DEPLOYMENTS, MAX_PAGES, MAX_REQUESTS_PER_MINUTE,
    MAX_RESPONSE_BYTES, MAX_RETRY_AFTER_SECONDS, MAX_STATUS_RECORDS, PAGE_SIZE, contract_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CredentialError {
    #[error("BLOCKED_ENV: native Bitbucket credential authority is unavailable")]
    BlockedEnv,
    #[error("Bitbucket credential reference is revoked")]
    Revoked,
    #[error("Bitbucket credential resolution failed: {0}")]
    Failed(String),
}

/// The host owns OAuth/API-token resolution.  Layer 1 can only borrow a
/// short-lived token for a bounded fixture/recording read.
pub trait BitbucketCredentialResolver: fmt::Debug {
    fn resolve(
        &mut self,
        reference: &SecretReference,
        at: DateTime<Utc>,
    ) -> Result<BitbucketAccessToken, CredentialError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl BitbucketCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &mut self,
        _reference: &SecretReference,
        _at: DateTime<Utc>,
    ) -> Result<BitbucketAccessToken, CredentialError> {
        Err(CredentialError::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeProbeStatus {
    BlockedEnv,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProbe {
    pub status: NativeProbeStatus,
    pub native_connected_claim: bool,
    pub native_provider_claim: bool,
    pub first_party_claim: bool,
}

impl NativeProbe {
    pub const fn blocked_env() -> Self {
        Self {
            status: NativeProbeStatus::BlockedEnv,
            native_connected_claim: false,
            native_provider_claim: false,
            first_party_claim: false,
        }
    }
}

pub fn native_probe_from_environment() -> NativeProbe {
    // Deliberately do not inspect an environment variable: Layer 1 must not
    // turn a token-shaped environment value into a Connected/native claim.
    NativeProbe::blocked_env()
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BitbucketDeliveryError {
    #[error("BLOCKED_ENV: native Bitbucket authority is unavailable")]
    BlockedEnv,
    #[error("Bitbucket delivery input is invalid: {0}")]
    InvalidInput(String),
    #[error("Bitbucket delivery contract is invalid: {0}")]
    Contract(String),
    #[error("Bitbucket delivery scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("Bitbucket delivery plugin metadata mismatch")]
    VersionMismatch,
    #[error("Bitbucket delivery contract digest mismatch")]
    ContractDigestMismatch,
    #[error("Bitbucket delivery registration is revoked")]
    RegistrationRevoked,
    #[error("Bitbucket delivery registration drifted: {0}")]
    RegistrationDrift(String),
    #[error("Bitbucket delivery credential is expired")]
    CredentialExpired,
    #[error("Bitbucket delivery credential failed: {0}")]
    Credential(String),
    #[error("Bitbucket API revision drifted: expected {expected}, observed {actual}")]
    ApiRevisionDrift { expected: String, actual: String },
    #[error("Bitbucket response was too large: {size} bytes")]
    ResponseTooLarge { size: usize },
    #[error("Bitbucket response could not be decoded: {0}")]
    Decode(String),
    #[error("Bitbucket transport failed: {0}")]
    Transport(String),
    #[error("Bitbucket repository identity did not match the registered scope")]
    RepositoryMismatch,
    #[error("Bitbucket repository UUID did not match the registered scope")]
    RepositoryUuidMismatch,
    #[error("Bitbucket pull request id did not match the registered scope")]
    PullRequestIdMismatch,
    #[error("Bitbucket pull request commit did not match the registered scope")]
    PullRequestCommitMismatch,
    #[error("Bitbucket pull request revision mismatch: expected {expected}, observed {observed}")]
    PullRequestRevisionMismatch { expected: String, observed: String },
    #[error("Bitbucket repository revision mismatch: expected {expected}, observed {observed}")]
    RepositoryRevisionMismatch { expected: String, observed: String },
    #[error("Bitbucket pipeline identity did not match the registered scope")]
    PipelineMismatch,
    #[error("Bitbucket pipeline build number did not match the registered scope")]
    BuildMismatch,
    #[error("Bitbucket pipeline commit did not match the registered scope")]
    PipelineCommitMismatch,
    #[error("Bitbucket pipeline revision mismatch: expected {expected}, observed {observed}")]
    PipelineRevisionMismatch { expected: String, observed: String },
    #[error("Bitbucket deployment identity did not match the registered scope")]
    DeploymentMismatch,
    #[error("Bitbucket deployment revision mismatch: expected {expected}, observed {observed}")]
    DeploymentRevisionMismatch { expected: String, observed: String },
    #[error("Bitbucket commit-status bound exceeded")]
    StatusBoundExceeded,
    #[error("Bitbucket deployment bound exceeded")]
    DeploymentBoundExceeded,
    #[error("Bitbucket pagination bound exceeded")]
    PaginationBoundExceeded,
    #[error("Bitbucket response receipt retained forbidden material")]
    ForbiddenPayloadRetention,
    #[error("Bitbucket evidence digest mismatch")]
    EvidenceDigestMismatch,
    #[error("Bitbucket evidence is stale or tampered")]
    StaleEvidence,
    #[error("Bitbucket evidence replay was rejected")]
    ReplayDetected,
    #[error("Bitbucket plugin runtime rejected the definition: {0}")]
    Plugin(#[from] hartevo_plugin_runtime::PluginError),
}

impl From<ModelError> for BitbucketDeliveryError {
    fn from(error: ModelError) -> Self {
        Self::InvalidInput(error.to_string())
    }
}

impl From<BitbucketTransportError> for BitbucketDeliveryError {
    fn from(error: BitbucketTransportError) -> Self {
        match error {
            BitbucketTransportError::BlockedEnv => Self::BlockedEnv,
            BitbucketTransportError::CredentialUnavailable => {
                Self::Credential("credential unavailable".to_owned())
            }
            BitbucketTransportError::InvalidRequest(detail)
            | BitbucketTransportError::Decode(detail) => Self::Decode(detail),
            BitbucketTransportError::UnexpectedBody => {
                Self::Decode("unexpected Bitbucket response body".to_owned())
            }
            BitbucketTransportError::Transport(detail) => Self::Transport(detail),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

pub struct BitbucketRegistrationRequest {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_revision: crate::model::ProviderRevision,
    pub scope: BitbucketDeliveryScope,
    pub secret_reference: SecretReference,
}

impl fmt::Debug for BitbucketRegistrationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitbucketRegistrationRequest")
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_revision", &self.provider_revision)
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .finish()
    }
}

impl BitbucketRegistrationRequest {
    pub fn baseline(scope: BitbucketDeliveryScope, secret_reference: SecretReference) -> Self {
        Self {
            plugin_version: BITBUCKET_DELIVERY_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: BITBUCKET_DELIVERY_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_revision: crate::model::ProviderRevision::parse(BITBUCKET_PROVIDER_REVISION)
                .expect("provider revision constant is valid"),
            scope,
            secret_reference,
        }
    }
}

pub struct BitbucketRegistration {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_revision: crate::model::ProviderRevision,
    scope: BitbucketDeliveryScope,
    secret_reference: SecretReference,
    secret_reference_digest: Digest,
    registration_digest: Digest,
    state: RegistrationState,
    revoked_at: Option<DateTime<Utc>>,
}

impl fmt::Debug for BitbucketRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitbucketRegistration")
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_revision", &self.provider_revision)
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("registration_digest", &self.registration_digest)
            .field("state", &self.state)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

impl BitbucketRegistration {
    pub fn new(request: BitbucketRegistrationRequest) -> Result<Self, BitbucketDeliveryError> {
        validate_plugin_metadata(&request.plugin_version, &request.contract_version)?;
        if request.contract_digest != contract_digest() {
            return Err(BitbucketDeliveryError::ContractDigestMismatch);
        }
        if request.provider_revision.as_str() != BITBUCKET_PROVIDER_REVISION {
            return Err(BitbucketDeliveryError::RegistrationDrift(
                "provider revision is not the checked-in Bitbucket REST adapter revision"
                    .to_owned(),
            ));
        }
        let secret_reference_digest = request.secret_reference.digest();
        let registration_digest = digest_serializable(&(
            &request.plugin_version,
            &request.contract_version,
            &request.contract_digest,
            &request.provider_revision,
            &request.scope,
            &secret_reference_digest,
        ))?;
        Ok(Self {
            plugin_version: request.plugin_version,
            contract_version: request.contract_version,
            contract_digest: request.contract_digest,
            provider_revision: request.provider_revision,
            scope: request.scope,
            secret_reference: request.secret_reference,
            secret_reference_digest,
            registration_digest,
            state: RegistrationState::Active,
            revoked_at: None,
        })
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_revision(&self) -> &crate::model::ProviderRevision {
        &self.provider_revision
    }

    pub fn scope(&self) -> &BitbucketDeliveryScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.revoked_at
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<(), BitbucketDeliveryError> {
        if self.state == RegistrationState::Revoked {
            return Err(BitbucketDeliveryError::RegistrationRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.revoked_at = Some(at);
        Ok(())
    }

    fn validate_active(
        &self,
        scope: &BitbucketDeliveryScope,
    ) -> Result<(), BitbucketDeliveryError> {
        if self.state == RegistrationState::Revoked {
            return Err(BitbucketDeliveryError::RegistrationRevoked);
        }
        if self.scope != *scope {
            return Err(BitbucketDeliveryError::ScopeMismatch(
                "provider registration scope differs from the requested scope".to_owned(),
            ));
        }
        Ok(())
    }
}

pub struct BitbucketProvider<T, R>
where
    T: BitbucketDeliveryTransport,
    R: BitbucketCredentialResolver,
{
    registration: BitbucketRegistration,
    transport: T,
    credential_resolver: R,
    bounds: RequestBounds,
    consumed_request_keys: BTreeSet<Digest>,
}

impl<T, R> fmt::Debug for BitbucketProvider<T, R>
where
    T: BitbucketDeliveryTransport,
    R: BitbucketCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitbucketProvider")
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("scope_digest", &self.registration.scope().digest())
            .field("transport_provenance", &self.transport.provenance())
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

impl<T, R> BitbucketProvider<T, R>
where
    T: BitbucketDeliveryTransport,
    R: BitbucketCredentialResolver,
{
    pub fn new(
        scope: BitbucketDeliveryScope,
        secret_reference: SecretReference,
        transport: T,
        credential_resolver: R,
    ) -> Result<Self, BitbucketDeliveryError> {
        Self::from_registration_request(
            BitbucketRegistrationRequest::baseline(scope, secret_reference),
            transport,
            credential_resolver,
            RequestBounds::default(),
        )
    }

    pub fn from_registration_request(
        request: BitbucketRegistrationRequest,
        transport: T,
        credential_resolver: R,
        bounds: RequestBounds,
    ) -> Result<Self, BitbucketDeliveryError> {
        let registration = BitbucketRegistration::new(request)?;
        Ok(Self {
            registration,
            transport,
            credential_resolver,
            bounds,
            consumed_request_keys: BTreeSet::new(),
        })
    }

    pub fn registration(&self) -> &BitbucketRegistration {
        &self.registration
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub const fn bounds(&self) -> RequestBounds {
        self.bounds
    }

    pub fn provider_revision(&self) -> &crate::model::ProviderRevision {
        self.registration.provider_revision()
    }

    pub fn is_connected(&self) -> bool {
        false
    }

    pub fn transport_provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<(), BitbucketDeliveryError> {
        self.registration.revoke(at)
    }

    pub fn read(
        &mut self,
        request: &BitbucketReadRequest,
        at: DateTime<Utc>,
    ) -> Result<BitbucketDeliveryEvidence, BitbucketDeliveryError> {
        self.read_internal(request, at)
    }

    /// A host can opt into one-shot request replay rejection.  The ordinary
    /// `read` remains repeatable for deterministic fixture comparison.
    pub fn read_once(
        &mut self,
        request: &BitbucketReadRequest,
        at: DateTime<Utc>,
    ) -> Result<BitbucketDeliveryEvidence, BitbucketDeliveryError> {
        let key = request.idempotency_key(self.registration.scope());
        if self.consumed_request_keys.contains(&key) {
            return Err(BitbucketDeliveryError::ReplayDetected);
        }
        let evidence = self.read_internal(request, at)?;
        self.consumed_request_keys.insert(key);
        Ok(evidence)
    }

    fn read_internal(
        &mut self,
        request: &BitbucketReadRequest,
        at: DateTime<Utc>,
    ) -> Result<BitbucketDeliveryEvidence, BitbucketDeliveryError> {
        self.registration
            .validate_active(self.registration.scope())?;
        request.validate()?;
        if request.page_size > self.bounds.page_size || request.max_pages > self.bounds.max_pages {
            return Err(BitbucketDeliveryError::InvalidInput(
                "requested pagination exceeds provider bounds".to_owned(),
            ));
        }
        let idempotency_key = request.idempotency_key(self.registration.scope());
        let token = self
            .credential_resolver
            .resolve(self.registration.secret_reference(), at)
            .map_err(|error| match error {
                CredentialError::BlockedEnv => BitbucketDeliveryError::BlockedEnv,
                CredentialError::Revoked => BitbucketDeliveryError::CredentialExpired,
                CredentialError::Failed(detail) => BitbucketDeliveryError::Credential(detail),
            })?;
        token
            .validate_at(at)
            .map_err(|_| BitbucketDeliveryError::CredentialExpired)?;

        let mut receipts = Vec::new();
        let repository_request = BitbucketHttpRequest::new(
            BitbucketEndpoint::Repository {
                workspace: self.registration.scope().workspace().to_owned(),
                repository: self.registration.scope().repository().to_owned(),
            },
            at,
            self.bounds.max_response_bytes,
        )?;
        let repository_response = self.execute(&token, &repository_request)?;
        receipts.push(repository_response.receipt().clone());
        if let Some(evidence) = self.short_circuit_evidence(
            &repository_response,
            &receipts,
            idempotency_key.clone(),
            at,
        )? {
            return Ok(evidence);
        }
        let repository = self.decode_repository(&repository_response, request)?;

        let pull_request_request = BitbucketHttpRequest::new(
            BitbucketEndpoint::PullRequest {
                workspace: self.registration.scope().workspace().to_owned(),
                repository: self.registration.scope().repository().to_owned(),
                pull_request_id: self.registration.scope().pull_request_id().get(),
            },
            at,
            self.bounds.max_response_bytes,
        )?;
        let pull_request_response = self.execute(&token, &pull_request_request)?;
        receipts.push(pull_request_response.receipt().clone());
        if let Some(evidence) = self.short_circuit_evidence(
            &pull_request_response,
            &receipts,
            idempotency_key.clone(),
            at,
        )? {
            return Ok(evidence);
        }
        let pull_request = self.decode_pull_request(&pull_request_response, request)?;

        let mut statuses = Vec::new();
        let mut partial_reasons = Vec::new();
        let mut page_token = None;
        let mut page_count = 0;
        let mut rate_limited = false;
        loop {
            if page_count >= request.max_pages {
                if page_token.is_some() {
                    partial_reasons.push(PartialReason::PaginationBoundExceeded);
                }
                break;
            }
            page_count += 1;
            let status_request = BitbucketHttpRequest::new(
                BitbucketEndpoint::CommitStatuses {
                    workspace: self.registration.scope().workspace().to_owned(),
                    repository: self.registration.scope().repository().to_owned(),
                    commit: self.registration.scope().commit().to_string(),
                    page_token: page_token.clone(),
                    page_size: request.page_size,
                },
                at,
                self.bounds.max_response_bytes,
            )?;
            let status_response = self.execute(&token, &status_request)?;
            receipts.push(status_response.receipt().clone());
            match status_response.receipt().response_status {
                200 => {
                    let BitbucketResponseBody::CommitStatuses(payload) = status_response.body()
                    else {
                        return Err(BitbucketDeliveryError::Decode(
                            "commit-status endpoint returned the wrong body".to_owned(),
                        ));
                    };
                    statuses.extend(
                        payload
                            .iter()
                            .map(status_projection)
                            .collect::<Result<Vec<_>, _>>()?,
                    );
                    if statuses.len() > MAX_STATUS_RECORDS {
                        return Err(BitbucketDeliveryError::StatusBoundExceeded);
                    }
                    page_token = status_response.next_page_token().cloned();
                    if page_token.is_none() {
                        break;
                    }
                }
                401 | 403 => {
                    partial_reasons.push(PartialReason::CommitStatusReadDenied);
                    partial_reasons.push(PartialReason::AccessLost);
                    break;
                }
                429 => {
                    rate_limited = true;
                    break;
                }
                _ => {
                    partial_reasons.push(PartialReason::ProviderRevisionDrift);
                    break;
                }
            }
        }

        let pipeline_request = BitbucketHttpRequest::new(
            BitbucketEndpoint::Pipeline {
                workspace: self.registration.scope().workspace().to_owned(),
                repository: self.registration.scope().repository().to_owned(),
                pipeline_uuid: self.registration.scope().pipeline_uuid().to_owned(),
            },
            at,
            self.bounds.max_response_bytes,
        )?;
        let pipeline_response = self.execute(&token, &pipeline_request)?;
        receipts.push(pipeline_response.receipt().clone());
        let pipeline = match pipeline_response.receipt().response_status {
            200 => Some(self.decode_pipeline(&pipeline_response, request)?),
            401 | 403 => {
                partial_reasons.push(PartialReason::PipelineReadDenied);
                partial_reasons.push(PartialReason::AccessLost);
                None
            }
            429 => {
                rate_limited = true;
                None
            }
            _ => {
                partial_reasons.push(PartialReason::ProviderRevisionDrift);
                None
            }
        };

        let deployment = if let Some(deployment_uuid) = self.registration.scope().deployment_uuid()
        {
            let deployment_request = BitbucketHttpRequest::new(
                BitbucketEndpoint::Deployment {
                    workspace: self.registration.scope().workspace().to_owned(),
                    repository: self.registration.scope().repository().to_owned(),
                    deployment_uuid: deployment_uuid.to_owned(),
                },
                at,
                self.bounds.max_response_bytes,
            )?;
            let deployment_response = self.execute(&token, &deployment_request)?;
            receipts.push(deployment_response.receipt().clone());
            match deployment_response.receipt().response_status {
                200 => Some(self.decode_deployment(&deployment_response, request)?),
                401 | 403 => {
                    partial_reasons.push(PartialReason::DeploymentReadDenied);
                    partial_reasons.push(PartialReason::AccessLost);
                    None
                }
                404 => {
                    partial_reasons.push(PartialReason::DeploymentNotFound);
                    None
                }
                429 => {
                    rate_limited = true;
                    None
                }
                _ => {
                    partial_reasons.push(PartialReason::ProviderRevisionDrift);
                    None
                }
            }
        } else {
            None
        };

        let state = delivery_state(
            &pull_request.state,
            statuses.iter().any(|status| is_failed_state(&status.state)),
            pipeline.as_ref(),
            !partial_reasons.is_empty(),
            rate_limited,
        );
        self.finish_evidence(
            state,
            Some(repository),
            Some(pull_request),
            statuses,
            pipeline,
            deployment,
            partial_reasons,
            page_count,
            receipts,
            idempotency_key,
        )
    }

    fn short_circuit_evidence(
        &self,
        response: &BitbucketHttpResponse,
        receipts: &[BitbucketResponseReceipt],
        idempotency_key: Digest,
        _at: DateTime<Utc>,
    ) -> Result<Option<BitbucketDeliveryEvidence>, BitbucketDeliveryError> {
        let state = match response.receipt().response_status {
            200 => return Ok(None),
            401 | 403 => DeliveryResultState::Denied,
            429 => DeliveryResultState::RateLimit,
            _ => DeliveryResultState::ProviderUnknown,
        };
        self.finish_evidence(
            state,
            None,
            None,
            Vec::new(),
            None,
            None,
            Vec::new(),
            1,
            receipts.to_vec(),
            idempotency_key,
        )
        .map(Some)
    }

    fn finish_evidence(
        &self,
        state: DeliveryResultState,
        repository: Option<RepositoryProjection>,
        pull_request: Option<PullRequestProjection>,
        commit_statuses: Vec<CommitStatusProjection>,
        pipeline: Option<PipelineProjection>,
        deployment: Option<DeploymentProjection>,
        partial_reasons: Vec<PartialReason>,
        page_count: u16,
        receipts: Vec<BitbucketResponseReceipt>,
        idempotency_key: Digest,
    ) -> Result<BitbucketDeliveryEvidence, BitbucketDeliveryError> {
        let mut evidence = BitbucketDeliveryEvidence {
            contract_version: BITBUCKET_DELIVERY_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            scope_digest: self.registration.scope().digest(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_revision: self.registration.provider_revision().clone(),
            idempotency_key,
            provenance: self.transport.provenance(),
            state,
            repository,
            pull_request,
            commit_statuses,
            pipeline,
            deployment,
            partial_reasons,
            page_count,
            receipts,
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            external_write_performed: false,
            generic_ci_authority: false,
            raw_diff_retained: false,
            raw_comments_retained: false,
            raw_artifact_bytes_retained: false,
            evidence_digest: Digest::parse("0".repeat(64))?,
        };
        evidence.evidence_digest = compute_evidence_digest(&evidence)?;
        evidence.validate()?;
        Ok(evidence)
    }

    fn execute(
        &mut self,
        token: &BitbucketAccessToken,
        request: &BitbucketHttpRequest,
    ) -> Result<BitbucketHttpResponse, BitbucketDeliveryError> {
        let response = self.transport.execute(token, request)?;
        self.validate_response(&response, request)?;
        Ok(response)
    }

    fn validate_response(
        &self,
        response: &BitbucketHttpResponse,
        request: &BitbucketHttpRequest,
    ) -> Result<(), BitbucketDeliveryError> {
        if response.receipt().api_revision != BITBUCKET_API_REVISION {
            return Err(BitbucketDeliveryError::ApiRevisionDrift {
                expected: BITBUCKET_API_REVISION.to_owned(),
                actual: response.receipt().api_revision.clone(),
            });
        }
        if response.receipt().provider_revision != *self.registration.provider_revision() {
            return Err(BitbucketDeliveryError::RegistrationDrift(
                "response provider revision differs from registration".to_owned(),
            ));
        }
        if response.receipt().request_digest != request.digest() {
            return Err(BitbucketDeliveryError::RegistrationDrift(
                "response receipt is not bound to the issued request".to_owned(),
            ));
        }
        if response.receipt().response_size > request.max_response_bytes {
            return Err(BitbucketDeliveryError::ResponseTooLarge {
                size: response.receipt().response_size,
            });
        }
        if response.receipt().raw_provider_payload_retained
            || response.receipt().raw_credential_material_retained
            || response.receipt().raw_pagination_token_retained
        {
            return Err(BitbucketDeliveryError::ForbiddenPayloadRetention);
        }
        Ok(())
    }

    fn decode_repository(
        &self,
        response: &BitbucketHttpResponse,
        request: &BitbucketReadRequest,
    ) -> Result<RepositoryProjection, BitbucketDeliveryError> {
        let BitbucketResponseBody::Repository(payload) = response.body() else {
            return Err(BitbucketDeliveryError::Decode(
                "repository endpoint returned the wrong body".to_owned(),
            ));
        };
        if payload.workspace != self.registration.scope().workspace()
            || payload.slug != self.registration.scope().repository()
        {
            return Err(BitbucketDeliveryError::RepositoryMismatch);
        }
        let uuid = RepositoryUuid::parse(payload.uuid.clone())?;
        if let Some(expected) = self.registration.scope().repository_uuid()
            && expected != uuid.as_str()
        {
            return Err(BitbucketDeliveryError::RepositoryUuidMismatch);
        }
        let revision = Revision::new(payload.revision.clone())?;
        if let Some(expected) = &request.expected_repository_revision
            && revision != *expected
        {
            return Err(BitbucketDeliveryError::RepositoryRevisionMismatch {
                expected: expected.to_string(),
                observed: revision.to_string(),
            });
        }
        Ok(RepositoryProjection {
            uuid,
            workspace: WorkspaceId::parse(payload.workspace.clone())?,
            slug: RepositorySlug::parse(payload.slug.clone())?,
            name: payload
                .name
                .as_ref()
                .map(|value| bounded_text(value, crate::model::MAX_TITLE_BYTES))
                .transpose()?,
            is_private: payload.is_private,
            revision,
        })
    }

    fn decode_pull_request(
        &self,
        response: &BitbucketHttpResponse,
        request: &BitbucketReadRequest,
    ) -> Result<PullRequestProjection, BitbucketDeliveryError> {
        let BitbucketResponseBody::PullRequest(payload) = response.body() else {
            return Err(BitbucketDeliveryError::Decode(
                "pull-request endpoint returned the wrong body".to_owned(),
            ));
        };
        if payload.id != self.registration.scope().pull_request_id().get() {
            return Err(BitbucketDeliveryError::PullRequestIdMismatch);
        }
        if let Some(expected_uuid) = self.registration.scope().repository_uuid()
            && payload.repository_uuid != expected_uuid
        {
            return Err(BitbucketDeliveryError::RepositoryUuidMismatch);
        }
        let source_commit = CommitHash::new(payload.source_commit.clone())?;
        if source_commit != *self.registration.scope().commit() {
            return Err(BitbucketDeliveryError::PullRequestCommitMismatch);
        }
        if let Some(expected) = &request.expected_commit
            && source_commit != *expected
        {
            return Err(BitbucketDeliveryError::PullRequestCommitMismatch);
        }
        let revision = Revision::new(payload.revision.clone())?;
        if let Some(expected) = &request.expected_pull_request_revision
            && revision != *expected
        {
            return Err(BitbucketDeliveryError::PullRequestRevisionMismatch {
                expected: expected.to_string(),
                observed: revision.to_string(),
            });
        }
        Ok(PullRequestProjection {
            id: PullRequestId::new(payload.id)?,
            repository_uuid: RepositoryUuid::parse(payload.repository_uuid.clone())?,
            state: bounded_status(&payload.state)?,
            title: payload
                .title
                .as_ref()
                .map(|value| bounded_text(value, crate::model::MAX_TITLE_BYTES))
                .transpose()?,
            source_commit,
            destination_commit: CommitHash::new(payload.destination_commit.clone())?,
            revision,
        })
    }

    fn decode_pipeline(
        &self,
        response: &BitbucketHttpResponse,
        request: &BitbucketReadRequest,
    ) -> Result<PipelineProjection, BitbucketDeliveryError> {
        let BitbucketResponseBody::Pipeline(payload) = response.body() else {
            return Err(BitbucketDeliveryError::Decode(
                "pipeline endpoint returned the wrong body".to_owned(),
            ));
        };
        let uuid = PipelineUuid::parse(payload.uuid.clone())?;
        if uuid.as_str() != self.registration.scope().pipeline_uuid() {
            return Err(BitbucketDeliveryError::PipelineMismatch);
        }
        if payload.build_number != self.registration.scope().build_number().get() {
            return Err(BitbucketDeliveryError::BuildMismatch);
        }
        let commit = CommitHash::new(payload.commit.clone())?;
        if commit != *self.registration.scope().commit() {
            return Err(BitbucketDeliveryError::PipelineCommitMismatch);
        }
        let revision = Revision::new(payload.revision.clone())?;
        if let Some(expected) = &request.expected_pipeline_revision
            && revision != *expected
        {
            return Err(BitbucketDeliveryError::PipelineRevisionMismatch {
                expected: expected.to_string(),
                observed: revision.to_string(),
            });
        }
        Ok(PipelineProjection {
            uuid,
            build_number: BuildNumber::new(payload.build_number)?,
            state: bounded_status(&payload.state)?,
            result: payload.result.as_deref().map(bounded_status).transpose()?,
            commit,
            target_ref: payload
                .target_ref
                .as_ref()
                .map(|value| bounded_text(value, crate::MAX_IDENTIFIER_BYTES))
                .transpose()?,
            revision,
        })
    }

    fn decode_deployment(
        &self,
        response: &BitbucketHttpResponse,
        request: &BitbucketReadRequest,
    ) -> Result<DeploymentProjection, BitbucketDeliveryError> {
        let BitbucketResponseBody::Deployment(payload) = response.body() else {
            return Err(BitbucketDeliveryError::Decode(
                "deployment endpoint returned the wrong body".to_owned(),
            ));
        };
        let uuid = DeploymentUuid::parse(payload.uuid.clone())?;
        if Some(uuid.as_str()) != self.registration.scope().deployment_uuid() {
            return Err(BitbucketDeliveryError::DeploymentMismatch);
        }
        let pipeline_uuid = PipelineUuid::parse(payload.pipeline_uuid.clone())?;
        if pipeline_uuid.as_str() != self.registration.scope().pipeline_uuid() {
            return Err(BitbucketDeliveryError::DeploymentMismatch);
        }
        let commit = CommitHash::new(payload.commit.clone())?;
        if commit != *self.registration.scope().commit() {
            return Err(BitbucketDeliveryError::PipelineCommitMismatch);
        }
        let revision = Revision::new(payload.revision.clone())?;
        if let Some(expected) = &request.expected_deployment_revision
            && revision != *expected
        {
            return Err(BitbucketDeliveryError::DeploymentRevisionMismatch {
                expected: expected.to_string(),
                observed: revision.to_string(),
            });
        }
        Ok(DeploymentProjection {
            uuid,
            pipeline_uuid,
            commit,
            state: bounded_status(&payload.state)?,
            environment: payload
                .environment
                .as_ref()
                .map(|value| bounded_text(value, crate::model::MAX_TITLE_BYTES))
                .transpose()?,
            revision,
        })
    }
}

fn status_projection(
    payload: &crate::model::CommitStatusPayload,
) -> Result<CommitStatusProjection, BitbucketDeliveryError> {
    Ok(CommitStatusProjection {
        key: bounded_status(&payload.key)?,
        name: payload
            .name
            .as_ref()
            .map(|value| bounded_text(value, crate::model::MAX_TITLE_BYTES))
            .transpose()?,
        state: bounded_status(&payload.state)?,
        revision: Revision::new(payload.revision.clone())?,
        target_url_digest: payload.target_url_digest.clone(),
    })
}

fn bounded_status(value: &str) -> Result<String, BitbucketDeliveryError> {
    bounded_text(value, crate::MAX_IDENTIFIER_BYTES)
}

fn bounded_text(value: &str, max_bytes: usize) -> Result<String, BitbucketDeliveryError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(BitbucketDeliveryError::InvalidInput(
            "Bitbucket provider status is unbounded or invalid".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn is_failed_state(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "failed" | "error" | "stopped" | "failure" | "halted"
    )
}

fn delivery_state(
    pull_request_state: &str,
    failed_status: bool,
    pipeline: Option<&PipelineProjection>,
    partial: bool,
    rate_limited: bool,
) -> DeliveryResultState {
    if rate_limited {
        return DeliveryResultState::RateLimit;
    }
    if partial {
        return DeliveryResultState::Partial;
    }
    if failed_status
        || pipeline.is_some_and(|value| {
            is_failed_state(&value.state) || value.result.as_deref().is_some_and(is_failed_state)
        })
    {
        return DeliveryResultState::Failed;
    }
    match pull_request_state.to_ascii_lowercase().as_str() {
        "open" => DeliveryResultState::Open,
        "merged" => DeliveryResultState::Merged,
        "declined" | "superseded" => DeliveryResultState::Declined,
        _ => DeliveryResultState::ProviderUnknown,
    }
}

pub use crate::model::BitbucketAccessToken as AccessToken;
pub type BitbucketCredentialResolverError = CredentialError;
pub type BitbucketCloudProvider<T, R> = BitbucketProvider<T, R>;

#[allow(dead_code)]
const _: (&str, usize, u16, u16, usize, u32, usize, &str) = (
    BITBUCKET_DELIVERY_RESULT_SERVICE_ID,
    MAX_REQUESTS_PER_MINUTE,
    MAX_PAGES,
    PAGE_SIZE,
    MAX_RESPONSE_BYTES,
    MAX_RETRY_AFTER_SECONDS,
    MAX_DEPLOYMENTS,
    BITBUCKET_PROVIDER_REVISION,
);
