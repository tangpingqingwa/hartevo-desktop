//! Production Sorftime estimate-only provider plugin.
//!
//! This layer is deliberately narrower than a general Sorftime client.  It
//! consumes an existing [`SorftimeCliRequest`], launches a pinned executable
//! directly, and emits a Mission-adoptable `EstimateOnly` result.  It never
//! reads a keyring or Store, never receives credential bytes, and has no
//! Effect authority.  The host supplies only the Connector SDK's opaque
//! [`SecretReference`] and [`CredentialLease`].
//!
//! The only raw-secret seam is [`SorftimeCredentialInjector`].  A host
//! implementation is responsible for using the SDK-owned credential boundary
//! to inject the secret into the already-cleared child environment.  The
//! plugin never places that value in arguments, logs, checkpoints, digests, or
//! result evidence.

use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration as StdDuration, Instant, UNIX_EPOCH};

use chrono::{DateTime, Duration, Utc};
use hartevo_connector_sdk::{
    ConnectorAuth, ConnectorScope, CredentialLease, ProviderProvenanceClass, SecretReference,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::sorftime::{
    SORFTIME_PROVIDER_ID, SorftimeCliRequest, SorftimeDataset, SorftimeEstimateObservation,
    SorftimeEvidenceAuthority, SorftimeMarket, SorftimeRequestCost, SorftimeResponse,
    SorftimeTransportKind, estimate_from_response,
};

pub const SORFTIME_ESTIMATE_CAPABILITY_ID: &str = "commerce.sorftime.estimate.read";
pub const SORFTIME_ESTIMATE_EVIDENCE_LEVEL: &str = "E1";
pub const SORFTIME_ESTIMATE_CLASSIFICATION: &str = "estimate_only_market_evidence";
pub const SORFTIME_ESTIMATE_LIVE_STATUS: &str = "LIVE_READ_E1";
pub const SORFTIME_ESTIMATE_BLOCKED_ENV_STATUS: &str = "BLOCKED_ENV";
pub const SORFTIME_ACCOUNT_SECRET_ENV: &str = "SORFTIME_ACCOUNT_SK";
pub const SORFTIME_ESTIMATE_CHECKPOINT_VERSION: &str = "sorftime-estimate-checkpoint/v1";
pub const SORFTIME_ESTIMATE_RESULT_VERSION: &str = "sorftime-estimate-result/v1";
pub const DEFAULT_SORFTIME_FRESHNESS_SECONDS: i64 = 900;
pub const MAX_SORFTIME_FRESHNESS_SECONDS: i64 = 86_400;
pub const DEFAULT_SORFTIME_TIMEOUT_SECONDS: u64 = 60;
pub const DEFAULT_SORFTIME_MAX_REQUEST_BYTES: usize = 256 * 1024;
pub const DEFAULT_SORFTIME_MAX_STDIN_BYTES: usize = 256 * 1024;
pub const DEFAULT_SORFTIME_MAX_STDOUT_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_SORFTIME_MAX_STDERR_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SorftimePluginError {
    #[error("Sorftime scope is not bound to the provider or request account")]
    ScopeMismatch,
    #[error("Sorftime credential lease is invalid, expired, or revoked")]
    CredentialChain,
    #[error("Sorftime adapter identity is invalid: {0}")]
    AdapterIdentity(String),
    #[error("Sorftime request is invalid: {0}")]
    Request(String),
    #[error("Sorftime durable checkpoint does not match this exact request")]
    CheckpointMismatch,
    #[error("Sorftime request has an unknown terminal state; replay is blocked")]
    UnknownTerminal,
    #[error("Sorftime checkpoint is already failed closed")]
    PreviouslyFailedClosed,
    #[error("Sorftime provider returned invalid estimate evidence: {0}")]
    InvalidEvidence(String),
    #[error("Sorftime provider failed: {0}")]
    Provider(String),
    #[error("Sorftime executable pin failed: {0}")]
    ExecutablePin(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SorftimeProviderError {
    #[error("credential injection was rejected")]
    CredentialInjectionRejected,
    #[error("Sorftime executable pin drifted: {0}")]
    ExecutableDrift(String),
    #[error("Sorftime request payload is too large")]
    RequestTooLarge,
    #[error("Sorftime command could not start")]
    CommandStart,
    #[error("Sorftime command timed out and was reaped")]
    CommandTimedOut,
    #[error("Sorftime command output exceeded its bound")]
    OutputLimit,
    #[error("Sorftime command output could not be read")]
    OutputRead,
    #[error("Sorftime command returned exit status {code} (stderr digest {stderr_digest})")]
    CommandFailed { code: i32, stderr_digest: String },
    #[error("Sorftime command output was not valid JSON")]
    MalformedJson,
    #[error("Sorftime response has no provider request id")]
    MissingProviderRequestId,
    #[error("Sorftime response has no exact quota field")]
    MissingQuota,
    #[error("Sorftime provider business code was non-zero: {0}")]
    BusinessFailure(i64),
    #[error("Sorftime response cost configuration is invalid")]
    InvalidCost,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SorftimePinError {
    #[error("Sorftime executable path is not a canonical regular executable")]
    InvalidPath,
    #[error("Sorftime executable metadata is unavailable")]
    Metadata,
    #[error("Sorftime executable digest could not be read")]
    DigestRead,
    #[error("Sorftime executable digest does not match the expected pin")]
    DigestMismatch,
    #[error("Sorftime executable version does not match the expected pin")]
    VersionMismatch,
    #[error("Sorftime executable version output is invalid")]
    VersionOutput,
    #[error("Sorftime version probe failed")]
    VersionProbe,
    #[error("Sorftime command limits are invalid")]
    InvalidLimits,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SorftimeReadFailureKind {
    #[error("provider execution reached an unknown terminal state")]
    UnknownTerminal,
    #[error("provider execution failed closed")]
    FailedClosed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SorftimeReadFailure {
    pub kind: SorftimeReadFailureKind,
    pub detail: SorftimePluginError,
    pub checkpoint: SorftimeDurableCheckpoint,
}

impl SorftimeReadFailure {
    pub fn checkpoint(&self) -> &SorftimeDurableCheckpoint {
        &self.checkpoint
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeFreshnessEvidence {
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub source: String,
}

impl SorftimeFreshnessEvidence {
    pub fn new(
        observed_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        source: impl Into<String>,
    ) -> Result<Self, SorftimePluginError> {
        let source = source.into();
        let age = valid_until - observed_at;
        if valid_until <= observed_at
            || age > Duration::seconds(MAX_SORFTIME_FRESHNESS_SECONDS)
            || source.trim().is_empty()
        {
            return Err(SorftimePluginError::InvalidEvidence(
                "invalid freshness window".into(),
            ));
        }
        Ok(Self {
            observed_at,
            valid_until,
            source,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeQuotaEvidence {
    pub request_left: u64,
    pub source: String,
    pub observed_at: DateTime<Utc>,
}

impl SorftimeQuotaEvidence {
    pub fn new(
        request_left: u64,
        source: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, SorftimePluginError> {
        let source = source.into();
        if source.trim().is_empty() {
            return Err(SorftimePluginError::InvalidEvidence(
                "quota source is empty".into(),
            ));
        }
        Ok(Self {
            request_left,
            source,
            observed_at,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeExecutableIdentity {
    pub canonical_path: String,
    pub file_identity: String,
    pub version: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeTransportIdentity {
    pub provider_id: String,
    pub transport: SorftimeTransportKind,
    pub executable: Option<SorftimeExecutableIdentity>,
}

impl SorftimeTransportIdentity {
    pub fn controlled(label: impl Into<String>) -> Result<Self, SorftimePluginError> {
        let label = label.into();
        if label.trim().is_empty() {
            return Err(SorftimePluginError::InvalidEvidence(
                "controlled transport label is empty".into(),
            ));
        }
        Ok(Self {
            provider_id: format!("{SORFTIME_PROVIDER_ID}:{label}"),
            transport: SorftimeTransportKind::Cli,
            executable: None,
        })
    }

    fn production(executable: SorftimeExecutableIdentity) -> Self {
        Self {
            provider_id: SORFTIME_PROVIDER_ID.into(),
            transport: SorftimeTransportKind::Cli,
            executable: Some(executable),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeEstimateResult {
    pub result_version: String,
    pub capability_id: String,
    pub classification: String,
    pub authority: SorftimeEvidenceAuthority,
    pub observation: SorftimeEstimateObservation,
    pub request_id: String,
    pub request_digest: String,
    pub response_digest: String,
    pub scope: ConnectorScope,
    pub scope_digest: String,
    pub secret_reference_id: String,
    pub credential_revision: u64,
    pub lease_id: String,
    pub lease_revision: u64,
    pub account: crate::sorftime::SorftimeAccountId,
    pub market: SorftimeMarket,
    pub dataset: SorftimeDataset,
    pub cost: SorftimeRequestCost,
    pub quota: SorftimeQuotaEvidence,
    pub freshness: SorftimeFreshnessEvidence,
    pub transport: SorftimeTransportIdentity,
    pub provenance_class: String,
    pub evidence_level: String,
    pub live_validation_status: String,
    pub connected: bool,
    pub first_party_amazon_fact: bool,
    pub replayed: bool,
    pub observed_at: DateTime<Utc>,
    pub result_digest: String,
}

impl SorftimeEstimateResult {
    pub fn is_estimate_only(&self) -> bool {
        matches!(self.authority, SorftimeEvidenceAuthority::EstimateOnly)
            && self.classification == SORFTIME_ESTIMATE_CLASSIFICATION
            && self.observation.is_estimate_only()
    }

    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    pub const fn is_first_party_amazon_fact(&self) -> bool {
        self.first_party_amazon_fact
    }

    pub fn is_mission_adoptable(&self) -> bool {
        self.is_estimate_only()
            && !self.connected
            && !self.first_party_amazon_fact
            && self.evidence_level == SORFTIME_ESTIMATE_EVIDENCE_LEVEL
    }

    /// Verifies the provider receipt's canonical digest before another layer
    /// is allowed to persist or adopt it.  The digest deliberately excludes
    /// the replay marker, so a replayed view cannot change the evidence
    /// identity while the durable committed receipt remains immutable.
    pub fn validate_integrity(&self) -> Result<(), SorftimePluginError> {
        if self.result_digest.is_empty() || self.digest()? != self.result_digest {
            return Err(SorftimePluginError::InvalidEvidence(
                "result digest mismatch".into(),
            ));
        }
        Ok(())
    }

    fn digest(&self) -> Result<String, SorftimePluginError> {
        let mut unsigned = self.clone();
        unsigned.result_digest.clear();
        unsigned.replayed = false;
        digest_json(&unsigned)
    }

    fn with_replayed(mut self) -> Self {
        self.replayed = true;
        self
    }
}

/// The committed provider result is the receipt consumed by the Mission
/// adoption layer.  This alias keeps the provider and adoption layers on one
/// typed receipt rather than introducing a second provider-result registry.
pub type SorftimeEstimateReceipt = SorftimeEstimateResult;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SorftimeCheckpointState {
    Empty,
    InFlight,
    Committed,
    FailedClosed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SorftimeDurableCheckpoint {
    pub checkpoint_version: String,
    pub state: SorftimeCheckpointState,
    pub scope_digest: Option<String>,
    pub account: Option<crate::sorftime::SorftimeAccountId>,
    pub market: Option<SorftimeMarket>,
    pub dataset: Option<SorftimeDataset>,
    pub request_id: Option<String>,
    pub request_digest: Option<String>,
    pub secret_reference_id: Option<String>,
    pub credential_revision: Option<u64>,
    pub lease_id: Option<String>,
    pub lease_revision: Option<u64>,
    pub started_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub result_digest: Option<String>,
    pub terminal_error_digest: Option<String>,
    pub result: Option<SorftimeEstimateResult>,
}

impl SorftimeDurableCheckpoint {
    pub fn empty() -> Self {
        Self {
            checkpoint_version: SORFTIME_ESTIMATE_CHECKPOINT_VERSION.into(),
            state: SorftimeCheckpointState::Empty,
            scope_digest: None,
            account: None,
            market: None,
            dataset: None,
            request_id: None,
            request_digest: None,
            secret_reference_id: None,
            credential_revision: None,
            lease_id: None,
            lease_revision: None,
            started_at: None,
            updated_at: None,
            result_digest: None,
            terminal_error_digest: None,
            result: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.state == SorftimeCheckpointState::Empty
    }

    /// Returns only a digest-verified committed receipt.  In-flight,
    /// failed-closed, empty, and malformed checkpoints cannot cross the
    /// provider-to-Mission boundary.
    pub fn committed_receipt(&self) -> Result<&SorftimeEstimateResult, SorftimePluginError> {
        if self.state != SorftimeCheckpointState::Committed {
            return Err(SorftimePluginError::InvalidEvidence(
                "checkpoint is not committed".into(),
            ));
        }
        let result = self
            .result
            .as_ref()
            .ok_or_else(|| SorftimePluginError::InvalidEvidence("missing result".into()))?;
        if self.result_digest.as_deref() != Some(result.result_digest.as_str()) {
            return Err(SorftimePluginError::InvalidEvidence(
                "checkpoint result digest mismatch".into(),
            ));
        }
        if self.scope_digest.as_deref() != Some(result.scope_digest.as_str())
            || self.account.as_ref() != Some(&result.account)
            || self.market.as_ref() != Some(&result.market)
            || self.dataset != Some(result.dataset)
            || self.request_id.as_deref() != Some(result.request_id.as_str())
            || self.request_digest.as_deref() != Some(result.request_digest.as_str())
            || self.secret_reference_id.as_deref() != Some(result.secret_reference_id.as_str())
            || self.credential_revision != Some(result.credential_revision)
            || self.lease_id.as_deref() != Some(result.lease_id.as_str())
            || self.lease_revision != Some(result.lease_revision)
        {
            return Err(SorftimePluginError::InvalidEvidence(
                "checkpoint binding does not match committed result".into(),
            ));
        }
        result.validate_integrity()?;
        Ok(result)
    }

    fn bind(
        &self,
        request: &SorftimeCliRequest,
        request_digest: &str,
        scope: &ConnectorScope,
        secret: &SecretReference,
        lease: &CredentialLease,
        now: DateTime<Utc>,
    ) -> Self {
        if !self.is_empty() {
            return self.clone();
        }
        Self {
            checkpoint_version: SORFTIME_ESTIMATE_CHECKPOINT_VERSION.into(),
            state: SorftimeCheckpointState::InFlight,
            scope_digest: Some(scope.digest()),
            account: Some(request.account.clone()),
            market: Some(request.market.clone()),
            dataset: Some(request.dataset),
            request_id: Some(request.request_id.clone()),
            request_digest: Some(request_digest.into()),
            secret_reference_id: Some(secret.reference_id().into()),
            credential_revision: Some(secret.credential_revision()),
            lease_id: Some(lease.lease_id().into()),
            lease_revision: Some(lease.lease_revision()),
            started_at: Some(now),
            updated_at: Some(now),
            result_digest: None,
            terminal_error_digest: None,
            result: None,
        }
    }

    fn matches_binding(
        &self,
        request: &SorftimeCliRequest,
        request_digest: &str,
        scope: &ConnectorScope,
        secret: &SecretReference,
        lease: &CredentialLease,
    ) -> bool {
        self.scope_digest.as_deref() == Some(scope.digest().as_str())
            && self.account.as_ref() == Some(&request.account)
            && self.market.as_ref() == Some(&request.market)
            && self.dataset == Some(request.dataset)
            && self.request_id.as_deref() == Some(request.request_id.as_str())
            && self.request_digest.as_deref() == Some(request_digest)
            && self.secret_reference_id.as_deref() == Some(secret.reference_id())
            && self.credential_revision == Some(secret.credential_revision())
            && self.lease_id.as_deref() == Some(lease.lease_id())
            && self.lease_revision == Some(lease.lease_revision())
    }

    fn committed(&self, result: SorftimeEstimateResult, now: DateTime<Utc>) -> Self {
        let mut checkpoint = self.clone();
        checkpoint.state = SorftimeCheckpointState::Committed;
        checkpoint.updated_at = Some(now);
        checkpoint.result_digest = Some(result.result_digest.clone());
        checkpoint.terminal_error_digest = None;
        checkpoint.result = Some(result);
        checkpoint
    }

    fn failed_closed(&self, error: &SorftimePluginError, now: DateTime<Utc>) -> Self {
        let mut checkpoint = self.clone();
        checkpoint.state = SorftimeCheckpointState::FailedClosed;
        checkpoint.updated_at = Some(now);
        checkpoint.terminal_error_digest = Some(digest_text(&error.to_string()));
        checkpoint.result = None;
        checkpoint.result_digest = None;
        checkpoint
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SorftimePreparedRead {
    request: SorftimeCliRequest,
    request_digest: String,
    checkpoint: SorftimeDurableCheckpoint,
}

impl SorftimePreparedRead {
    pub fn request(&self) -> &SorftimeCliRequest {
        &self.request
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn checkpoint(&self) -> &SorftimeDurableCheckpoint {
        &self.checkpoint
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SorftimeReadPlan {
    Execute(Box<SorftimePreparedRead>),
    Replay(Box<SorftimeEstimateResult>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SorftimeProviderResponse {
    pub response: SorftimeResponse,
    pub observed_at: DateTime<Utc>,
    pub quota: SorftimeQuotaEvidence,
    pub transport: SorftimeTransportIdentity,
}

pub trait SorftimeEstimateProvider {
    fn execute(
        &mut self,
        request: &SorftimeCliRequest,
        secret: &SecretReference,
        lease: &CredentialLease,
        scope: &ConnectorScope,
        now: DateTime<Utc>,
    ) -> Result<SorftimeProviderResponse, SorftimeProviderError>;

    fn provenance_class(&self) -> ProviderProvenanceClass;

    fn transport_identity(&self) -> SorftimeTransportIdentity;
}

pub struct SorftimeEstimateService<P> {
    provider: P,
    secret_reference: SecretReference,
    credential_lease: CredentialLease,
    scope: ConnectorScope,
    freshness_ttl: Duration,
    mounted: bool,
}

impl<P> fmt::Debug for SorftimeEstimateService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SorftimeEstimateService")
            .field("scope_digest", &self.scope.digest())
            .field(
                "credential_revision",
                &self.secret_reference.credential_revision(),
            )
            .field("lease_revision", &self.credential_lease.lease_revision())
            .field("freshness_ttl", &self.freshness_ttl)
            .field("mounted", &self.mounted)
            .finish_non_exhaustive()
    }
}

impl<P: SorftimeEstimateProvider> SorftimeEstimateService<P> {
    pub fn new(
        provider: P,
        secret_reference: SecretReference,
        credential_lease: CredentialLease,
        scope: ConnectorScope,
    ) -> Result<Self, SorftimePluginError> {
        Self::with_freshness(
            provider,
            secret_reference,
            credential_lease,
            scope,
            Duration::seconds(DEFAULT_SORFTIME_FRESHNESS_SECONDS),
        )
    }

    pub fn with_freshness(
        provider: P,
        secret_reference: SecretReference,
        credential_lease: CredentialLease,
        scope: ConnectorScope,
        freshness_ttl: Duration,
    ) -> Result<Self, SorftimePluginError> {
        let service = Self {
            provider,
            secret_reference,
            credential_lease,
            scope,
            freshness_ttl,
            mounted: true,
        };
        service.validate_bindings()?;
        if freshness_ttl <= Duration::zero()
            || freshness_ttl > Duration::seconds(MAX_SORFTIME_FRESHNESS_SECONDS)
        {
            return Err(SorftimePluginError::InvalidEvidence(
                "freshness TTL is outside the bounded contract".into(),
            ));
        }
        Ok(service)
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn credential_lease(&self) -> &CredentialLease {
        &self.credential_lease
    }

    pub fn provenance_class(&self) -> ProviderProvenanceClass {
        self.provider.provenance_class()
    }

    pub fn transport_identity(&self) -> SorftimeTransportIdentity {
        self.provider.transport_identity()
    }

    pub fn is_mounted(&self) -> bool {
        self.mounted
    }

    pub fn revoke(&mut self) {
        self.mounted = false;
    }

    pub fn unmount(&mut self) {
        self.mounted = false;
    }

    pub fn rotate_credentials(
        &mut self,
        secret_reference: SecretReference,
        credential_lease: CredentialLease,
    ) -> Result<(), SorftimePluginError> {
        self.validate_external_bindings(&secret_reference, &credential_lease)?;
        if secret_reference.credential_revision() <= self.secret_reference.credential_revision()
            && secret_reference.reference_id() == self.secret_reference.reference_id()
        {
            return Err(SorftimePluginError::CredentialChain);
        }
        self.secret_reference = secret_reference;
        self.credential_lease = credential_lease;
        self.mounted = true;
        Ok(())
    }

    pub fn prepare(
        &self,
        request: &SorftimeCliRequest,
        checkpoint: SorftimeDurableCheckpoint,
        now: DateTime<Utc>,
    ) -> Result<SorftimeReadPlan, SorftimePluginError> {
        if !self.mounted {
            return Err(SorftimePluginError::CredentialChain);
        }
        if checkpoint.checkpoint_version != SORFTIME_ESTIMATE_CHECKPOINT_VERSION {
            return Err(SorftimePluginError::InvalidEvidence(
                "unsupported checkpoint version".into(),
            ));
        }
        self.validate_bindings()?;
        self.validate_request(request)?;
        let request_digest = request
            .request_digest()
            .map_err(|error| SorftimePluginError::Request(error.to_string()))?;
        if !checkpoint.is_empty()
            && !checkpoint.matches_binding(
                request,
                &request_digest,
                &self.scope,
                &self.secret_reference,
                &self.credential_lease,
            )
        {
            return Err(SorftimePluginError::CheckpointMismatch);
        }
        match checkpoint.state {
            SorftimeCheckpointState::Empty => {
                Ok(SorftimeReadPlan::Execute(Box::new(SorftimePreparedRead {
                    request_digest: request_digest.clone(),
                    request: request.clone(),
                    checkpoint: checkpoint.bind(
                        request,
                        &request_digest,
                        &self.scope,
                        &self.secret_reference,
                        &self.credential_lease,
                        now,
                    ),
                })))
            }
            SorftimeCheckpointState::InFlight => Err(SorftimePluginError::UnknownTerminal),
            SorftimeCheckpointState::FailedClosed => {
                Err(SorftimePluginError::PreviouslyFailedClosed)
            }
            SorftimeCheckpointState::Committed => {
                let result = checkpoint
                    .result
                    .ok_or_else(|| SorftimePluginError::InvalidEvidence("missing result".into()))?;
                if checkpoint.result_digest.as_deref() != Some(result.result_digest.as_str())
                    || result.digest()? != result.result_digest
                    || !self.result_matches_binding(&result, request, &request_digest)
                {
                    return Err(SorftimePluginError::InvalidEvidence(
                        "committed result digest mismatch".into(),
                    ));
                }
                Ok(SorftimeReadPlan::Replay(Box::new(result.with_replayed())))
            }
        }
    }

    pub fn execute_prepared(
        &mut self,
        prepared: &SorftimePreparedRead,
        now: DateTime<Utc>,
    ) -> Result<(SorftimeEstimateResult, SorftimeDurableCheckpoint), Box<SorftimeReadFailure>> {
        if !self.mounted {
            return Err(Box::new(Self::fail(
                &prepared.checkpoint,
                &SorftimePluginError::CredentialChain,
                now,
            )));
        }
        if let Err(error) = self.validate_bindings() {
            return Err(Box::new(Self::fail(&prepared.checkpoint, &error, now)));
        }
        if prepared.checkpoint.state != SorftimeCheckpointState::InFlight
            || !prepared.checkpoint.matches_binding(
                &prepared.request,
                &prepared.request_digest,
                &self.scope,
                &self.secret_reference,
                &self.credential_lease,
            )
        {
            return Err(Box::new(Self::fail(
                &prepared.checkpoint,
                &SorftimePluginError::CheckpointMismatch,
                now,
            )));
        }
        if let Err(error) = self.validate_credential_chain(now) {
            return Err(Box::new(Self::fail(&prepared.checkpoint, &error, now)));
        }
        let response = match self.provider.execute(
            &prepared.request,
            &self.secret_reference,
            &self.credential_lease,
            &self.scope,
            now,
        ) {
            Ok(response) => response,
            Err(error) => {
                return Err(Box::new(Self::fail(
                    &prepared.checkpoint,
                    &SorftimePluginError::Provider(error.to_string()),
                    now,
                )));
            }
        };
        let result = match self.build_result(prepared, response) {
            Ok(result) => result,
            Err(error) => return Err(Box::new(Self::fail(&prepared.checkpoint, &error, now))),
        };
        let committed_checkpoint = prepared.checkpoint.committed(result.clone(), now);
        Ok((result, committed_checkpoint))
    }

    pub fn commit_checkpoint(
        &self,
        prepared: &SorftimePreparedRead,
        result: SorftimeEstimateResult,
        now: DateTime<Utc>,
    ) -> Result<SorftimeDurableCheckpoint, SorftimePluginError> {
        if result.digest()? != result.result_digest
            || !self.result_matches_binding(&result, &prepared.request, &prepared.request_digest)
            || !prepared.checkpoint.matches_binding(
                &prepared.request,
                &prepared.request_digest,
                &self.scope,
                &self.secret_reference,
                &self.credential_lease,
            )
        {
            return Err(SorftimePluginError::CheckpointMismatch);
        }
        Ok(prepared.checkpoint.committed(result, now))
    }

    fn result_matches_binding(
        &self,
        result: &SorftimeEstimateResult,
        request: &SorftimeCliRequest,
        request_digest: &str,
    ) -> bool {
        result.result_version == SORFTIME_ESTIMATE_RESULT_VERSION
            && result.capability_id == SORFTIME_ESTIMATE_CAPABILITY_ID
            && result.classification == SORFTIME_ESTIMATE_CLASSIFICATION
            && result.is_estimate_only()
            && result.request_id == request.request_id
            && result.request_digest == request_digest
            && result.scope == self.scope
            && result.scope_digest == self.scope.digest()
            && result.secret_reference_id == self.secret_reference.reference_id()
            && result.credential_revision == self.secret_reference.credential_revision()
            && result.lease_id == self.credential_lease.lease_id()
            && result.lease_revision == self.credential_lease.lease_revision()
            && result.account == request.account
            && result.market == request.market
            && result.dataset == request.dataset
    }

    fn build_result(
        &self,
        prepared: &SorftimePreparedRead,
        provider: SorftimeProviderResponse,
    ) -> Result<SorftimeEstimateResult, SorftimePluginError> {
        if provider.response.status < 200 || provider.response.status >= 300 {
            return Err(SorftimePluginError::InvalidEvidence(
                "provider response was not successful".into(),
            ));
        }
        let expected_transport = self.provider.transport_identity();
        if provider.transport != expected_transport {
            return Err(SorftimePluginError::InvalidEvidence(
                "transport identity changed during request".into(),
            ));
        }
        if provider.quota.observed_at != provider.observed_at {
            return Err(SorftimePluginError::InvalidEvidence(
                "quota timestamp is not bound to response".into(),
            ));
        }
        let normalized = normalize_estimate_body(provider.response.body.clone());
        let response = SorftimeResponse {
            body: normalized,
            ..provider.response.clone()
        };
        let observation = estimate_from_response(
            response,
            prepared.request.account.clone(),
            prepared.request.market.clone(),
            prepared.request.dataset,
            SorftimeTransportKind::Cli,
            prepared.request_digest.clone(),
            provider.observed_at,
        )
        .map_err(|error| SorftimePluginError::InvalidEvidence(error.to_string()))?;
        if !observation.is_estimate_only()
            || observation.provenance.account != prepared.request.account
            || observation.provenance.market != prepared.request.market
            || observation.provenance.dataset != prepared.request.dataset
            || observation.provenance.request_digest != prepared.request_digest
            || observation.provenance.provider_id != SORFTIME_PROVIDER_ID
        {
            return Err(SorftimePluginError::InvalidEvidence(
                "estimate provenance does not match the exact request".into(),
            ));
        }
        let freshness = SorftimeFreshnessEvidence::new(
            provider.observed_at,
            provider.observed_at + self.freshness_ttl,
            "sorftime-provider-response",
        )?;
        let response_digest = digest_json(&provider.response)
            .map_err(|error| SorftimePluginError::InvalidEvidence(error.to_string()))?;
        let provenance_class = provenance_name(self.provider.provenance_class()).into();
        let mut result = SorftimeEstimateResult {
            result_version: SORFTIME_ESTIMATE_RESULT_VERSION.into(),
            capability_id: SORFTIME_ESTIMATE_CAPABILITY_ID.into(),
            classification: SORFTIME_ESTIMATE_CLASSIFICATION.into(),
            authority: SorftimeEvidenceAuthority::EstimateOnly,
            observation: observation.clone(),
            request_id: prepared.request.request_id.clone(),
            request_digest: prepared.request_digest.clone(),
            response_digest,
            scope: self.scope.clone(),
            scope_digest: self.scope.digest(),
            secret_reference_id: self.secret_reference.reference_id().into(),
            credential_revision: self.secret_reference.credential_revision(),
            lease_id: self.credential_lease.lease_id().into(),
            lease_revision: self.credential_lease.lease_revision(),
            account: prepared.request.account.clone(),
            market: prepared.request.market.clone(),
            dataset: prepared.request.dataset,
            cost: observation.provenance.request_cost.clone(),
            quota: provider.quota,
            freshness,
            transport: provider.transport,
            provenance_class,
            evidence_level: SORFTIME_ESTIMATE_EVIDENCE_LEVEL.into(),
            live_validation_status: if self.provider.provenance_class()
                == ProviderProvenanceClass::ProductionProvider
            {
                SORFTIME_ESTIMATE_LIVE_STATUS.into()
            } else {
                SORFTIME_ESTIMATE_BLOCKED_ENV_STATUS.into()
            },
            connected: false,
            first_party_amazon_fact: false,
            replayed: false,
            observed_at: provider.observed_at,
            result_digest: String::new(),
        };
        result.result_digest = result.digest()?;
        Ok(result)
    }

    fn fail(
        checkpoint: &SorftimeDurableCheckpoint,
        error: &SorftimePluginError,
        now: DateTime<Utc>,
    ) -> SorftimeReadFailure {
        let kind = if matches!(error, SorftimePluginError::UnknownTerminal) {
            SorftimeReadFailureKind::UnknownTerminal
        } else {
            SorftimeReadFailureKind::FailedClosed
        };
        SorftimeReadFailure {
            kind,
            detail: error.clone(),
            checkpoint: checkpoint.failed_closed(error, now),
        }
    }

    fn validate_request(&self, request: &SorftimeCliRequest) -> Result<(), SorftimePluginError> {
        if request.program != "sorftime"
            || request.account.as_str() != self.scope.account_id()
            || request.request_id.trim().is_empty()
        {
            return Err(SorftimePluginError::ScopeMismatch);
        }
        Ok(())
    }

    fn validate_bindings(&self) -> Result<(), SorftimePluginError> {
        self.validate_external_bindings(&self.secret_reference, &self.credential_lease)
    }

    fn validate_external_bindings(
        &self,
        secret: &SecretReference,
        lease: &CredentialLease,
    ) -> Result<(), SorftimePluginError> {
        let adapter = crate::sorftime_adapter_identity()
            .map_err(|error| SorftimePluginError::AdapterIdentity(error.to_string()))?;
        if self.scope.provider_id() != SORFTIME_PROVIDER_ID
            || secret.scope() != &self.scope
            || lease.scope() != &self.scope
            || lease.adapter() != &adapter
            || secret.scope().account_id() != self.scope.account_id()
        {
            return Err(SorftimePluginError::ScopeMismatch);
        }
        Ok(())
    }

    fn validate_credential_chain(&self, now: DateTime<Utc>) -> Result<(), SorftimePluginError> {
        self.validate_bindings()?;
        let expires_at = std::cmp::min(
            self.credential_lease.expires_at(),
            now + Duration::seconds(1),
        );
        if expires_at <= now {
            return Err(SorftimePluginError::CredentialChain);
        }
        ConnectorAuth::begin_auth_session(
            &self.secret_reference,
            &self.credential_lease,
            "auth-session-sorftime-read",
            1,
            now,
            expires_at,
        )
        .map(|_| ())
        .map_err(|_| SorftimePluginError::CredentialChain)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SorftimeCommandLimits {
    pub timeout: StdDuration,
    pub max_request_bytes: usize,
    pub max_stdin_bytes: usize,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
}

impl SorftimeCommandLimits {
    pub fn new(
        timeout: StdDuration,
        max_request_bytes: usize,
        max_stdin_bytes: usize,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<Self, SorftimePinError> {
        let limits = Self {
            timeout,
            max_request_bytes,
            max_stdin_bytes,
            max_stdout_bytes,
            max_stderr_bytes,
        };
        if timeout.is_zero()
            || timeout > StdDuration::from_mins(5)
            || max_request_bytes == 0
            || max_stdin_bytes == 0
            || max_stdout_bytes == 0
            || max_stderr_bytes == 0
        {
            return Err(SorftimePinError::InvalidLimits);
        }
        Ok(limits)
    }
}

impl Default for SorftimeCommandLimits {
    fn default() -> Self {
        Self {
            timeout: StdDuration::from_secs(DEFAULT_SORFTIME_TIMEOUT_SECONDS),
            max_request_bytes: DEFAULT_SORFTIME_MAX_REQUEST_BYTES,
            max_stdin_bytes: DEFAULT_SORFTIME_MAX_STDIN_BYTES,
            max_stdout_bytes: DEFAULT_SORFTIME_MAX_STDOUT_BYTES,
            max_stderr_bytes: DEFAULT_SORFTIME_MAX_STDERR_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SorftimeCliCostPolicy {
    pub units: u64,
    pub currency: Option<hartevo_domain_kernel::CurrencyCode>,
    pub pricing_source: String,
}

impl SorftimeCliCostPolicy {
    pub fn new(
        units: u64,
        currency: Option<hartevo_domain_kernel::CurrencyCode>,
        pricing_source: impl Into<String>,
    ) -> Result<Self, SorftimePluginError> {
        let pricing_source = pricing_source.into();
        if units == 0 || pricing_source.trim().is_empty() {
            return Err(SorftimePluginError::InvalidEvidence(
                "cost policy is incomplete".into(),
            ));
        }
        Ok(Self {
            units,
            currency,
            pricing_source,
        })
    }
}

pub trait SorftimeCredentialInjector {
    fn inject_account_secret(
        &mut self,
        command: &mut Command,
        secret: &SecretReference,
        lease: &CredentialLease,
        now: DateTime<Utc>,
    ) -> Result<(), SorftimeProviderError>;
}

pub struct SorftimeCliTransport<I> {
    pin: SorftimeExecutablePin,
    injector: I,
    limits: SorftimeCommandLimits,
    cost: SorftimeCliCostPolicy,
}

impl<I> fmt::Debug for SorftimeCliTransport<I> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SorftimeCliTransport")
            .field("executable", &self.pin.identity())
            .field("limits", &self.limits)
            .field("cost", &self.cost)
            .finish_non_exhaustive()
    }
}

impl<I> SorftimeCliTransport<I> {
    pub fn new(
        pin: SorftimeExecutablePin,
        injector: I,
        limits: SorftimeCommandLimits,
        cost: SorftimeCliCostPolicy,
    ) -> Self {
        Self {
            pin,
            injector,
            limits,
            cost,
        }
    }

    pub fn executable(&self) -> &SorftimeExecutableIdentity {
        self.pin.identity()
    }

    pub fn into_injector(self) -> I {
        self.injector
    }
}

impl<I: SorftimeCredentialInjector> SorftimeEstimateProvider for SorftimeCliTransport<I> {
    fn execute(
        &mut self,
        request: &SorftimeCliRequest,
        secret: &SecretReference,
        lease: &CredentialLease,
        _scope: &ConnectorScope,
        now: DateTime<Utc>,
    ) -> Result<SorftimeProviderResponse, SorftimeProviderError> {
        if request.program != "sorftime" {
            return Err(SorftimeProviderError::CommandStart);
        }
        let executable = self
            .pin
            .verify(&self.limits)
            .map_err(|error| SorftimeProviderError::ExecutableDrift(error.to_string()))?;
        let payload = serde_json::to_string(&request.payload)
            .map_err(|_| SorftimeProviderError::RequestTooLarge)?;
        if payload.len() > self.limits.max_request_bytes {
            return Err(SorftimeProviderError::RequestTooLarge);
        }
        let mut command = Command::new(&executable.canonical_path);
        command.args([
            "api",
            request.dataset.api_name(),
            payload.as_str(),
            "--domain",
            request.market.market_id.as_str(),
            "--output",
            "json",
        ]);
        command.env_clear();
        command.env("LC_ALL", "C");
        command.env("LANG", "C");
        self.injector
            .inject_account_secret(&mut command, secret, lease, now)?;
        let output =
            run_bounded_command(command, None, &self.limits).map_err(|error| match error {
                ProcessError::Start => SorftimeProviderError::CommandStart,
                ProcessError::Timeout => SorftimeProviderError::CommandTimedOut,
                ProcessError::OutputLimit => SorftimeProviderError::OutputLimit,
                ProcessError::Read | ProcessError::Join => SorftimeProviderError::OutputRead,
            })?;
        if output.exit_code != 0 {
            return Err(SorftimeProviderError::CommandFailed {
                code: output.exit_code,
                stderr_digest: output.stderr_digest,
            });
        }
        let body = serde_json::from_slice::<Value>(&output.stdout)
            .map_err(|_| SorftimeProviderError::MalformedJson)?;
        if let Some(code) = response_business_code(&body)
            && code != 0
        {
            return Err(SorftimeProviderError::BusinessFailure(code));
        }
        let provider_request_id = response_string(&body, &["RequestId", "requestId", "request_id"])
            .ok_or(SorftimeProviderError::MissingProviderRequestId)?;
        let request_left = response_u64(&body, &["RequestLeft", "requestLeft", "request_left"])
            .ok_or(SorftimeProviderError::MissingQuota)?;
        let cost = SorftimeRequestCost::new(
            self.cost.units,
            self.cost.currency.clone(),
            self.cost.pricing_source.clone(),
            now,
        )
        .map_err(|_| SorftimeProviderError::InvalidCost)?;
        let response = SorftimeResponse {
            status: 200,
            request_id: provider_request_id,
            body,
            cost_units: cost.units,
            cost_currency: cost.currency,
            cost_source: cost.pricing_source,
        };
        let quota = SorftimeQuotaEvidence::new(request_left, "sorftime-cli-response", now)
            .map_err(|_| SorftimeProviderError::MissingQuota)?;
        Ok(SorftimeProviderResponse {
            response,
            observed_at: now,
            quota,
            transport: SorftimeTransportIdentity::production(executable),
        })
    }

    fn provenance_class(&self) -> ProviderProvenanceClass {
        ProviderProvenanceClass::ProductionProvider
    }

    fn transport_identity(&self) -> SorftimeTransportIdentity {
        SorftimeTransportIdentity::production(self.pin.identity().clone())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SorftimeExecutablePin {
    path: PathBuf,
    identity: SorftimeExecutableIdentity,
}

impl SorftimeExecutablePin {
    pub fn pin(
        path: impl AsRef<Path>,
        expected_version: impl Into<String>,
        expected_sha256: impl Into<String>,
        limits: &SorftimeCommandLimits,
    ) -> Result<Self, SorftimePinError> {
        let expected_version = expected_version.into();
        let expected_sha256 = expected_sha256.into().to_ascii_lowercase();
        validate_expected_pin(&expected_version, &expected_sha256)?;
        let canonical_path = canonical_executable_path(path.as_ref())?;
        let observed_digest = digest_file(&canonical_path)?;
        if observed_digest != expected_sha256 {
            return Err(SorftimePinError::DigestMismatch);
        }
        let identity = file_identity(&canonical_path)?;
        let observed_version = probe_version(&canonical_path, limits)?;
        if observed_version != expected_version {
            return Err(SorftimePinError::VersionMismatch);
        }
        Ok(Self {
            path: canonical_path.clone(),
            identity: SorftimeExecutableIdentity {
                canonical_path: canonical_path.to_string_lossy().into_owned(),
                file_identity: identity,
                version: observed_version,
                sha256: observed_digest,
            },
        })
    }

    pub fn identity(&self) -> &SorftimeExecutableIdentity {
        &self.identity
    }

    fn verify(
        &self,
        limits: &SorftimeCommandLimits,
    ) -> Result<SorftimeExecutableIdentity, SorftimePinError> {
        let canonical_path = canonical_executable_path(&self.path)?;
        if canonical_path.to_string_lossy() != self.identity.canonical_path {
            return Err(SorftimePinError::VersionMismatch);
        }
        let digest = digest_file(&canonical_path)?;
        let file_identity_value = file_identity(&canonical_path)?;
        if digest != self.identity.sha256 || file_identity_value != self.identity.file_identity {
            return Err(SorftimePinError::DigestMismatch);
        }
        let version = probe_version(&canonical_path, limits)?;
        if version != self.identity.version {
            return Err(SorftimePinError::VersionMismatch);
        }
        Ok(SorftimeExecutableIdentity {
            canonical_path: canonical_path.to_string_lossy().into_owned(),
            file_identity: file_identity_value,
            version,
            sha256: digest,
        })
    }
}

#[derive(Debug)]
struct ProcessOutput {
    stdout: Vec<u8>,
    #[allow(dead_code)]
    stderr_digest: String,
    exit_code: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessError {
    Start,
    Timeout,
    OutputLimit,
    Read,
    Join,
}

fn run_bounded_command(
    mut command: Command,
    input: Option<&[u8]>,
    limits: &SorftimeCommandLimits,
) -> Result<ProcessOutput, ProcessError> {
    if input.is_some_and(|bytes| bytes.len() > limits.max_stdin_bytes) {
        return Err(ProcessError::OutputLimit);
    }
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|_| ProcessError::Start)?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(ProcessError::Start);
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(ProcessError::Start);
    };
    let stdout_reader = spawn_bounded_reader(stdout, limits.max_stdout_bytes);
    let stderr_reader = spawn_bounded_reader(stderr, limits.max_stderr_bytes);
    let stdin_writer = input.map(|bytes| {
        let mut stdin = child.stdin.take().ok_or(ProcessError::Start)?;
        let bytes = bytes.to_vec();
        Ok(thread::spawn(move || stdin.write_all(&bytes)))
    });
    let stdin_writer = stdin_writer.transpose()?;
    let deadline = Instant::now() + limits.timeout;
    let mut terminal_error = None;
    let mut status = None;
    loop {
        match child.try_wait() {
            Ok(Some(exit_status)) => {
                status = Some(exit_status);
                break;
            }
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                terminal_error = Some(ProcessError::Timeout);
                break;
            }
            Ok(None) => thread::sleep(StdDuration::from_millis(10)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                terminal_error = Some(ProcessError::Read);
                break;
            }
        }
    }
    let stdin_error = stdin_writer.map(|writer| {
        writer
            .join()
            .map_err(|_| ProcessError::Join)
            .and_then(|result| result.map_err(|_| ProcessError::Read))
    });
    let stdout_result = stdout_reader.join().map_err(|_| ProcessError::Join);
    let stderr_result = stderr_reader.join().map_err(|_| ProcessError::Join);
    if let Some(error) = terminal_error {
        return Err(error);
    }
    if let Some(error) = stdin_error {
        error?;
    }
    let status = status.ok_or(ProcessError::Read)?;
    let stdout = stdout_result??;
    let stderr = stderr_result??;
    let exit_code = status.code().unwrap_or(-1);
    Ok(ProcessOutput {
        stdout,
        stderr_digest: digest_bytes(&stderr),
        exit_code,
    })
}

fn spawn_bounded_reader<R: Read + Send + 'static>(
    mut reader: R,
    maximum: usize,
) -> JoinHandle<Result<Vec<u8>, ProcessError>> {
    thread::spawn(move || {
        let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
        reader
            .by_ref()
            .take((maximum as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| ProcessError::Read)?;
        if bytes.len() > maximum {
            return Err(ProcessError::OutputLimit);
        }
        Ok(bytes)
    })
}

fn canonical_executable_path(path: &Path) -> Result<PathBuf, SorftimePinError> {
    let canonical = fs::canonicalize(path).map_err(|_| SorftimePinError::InvalidPath)?;
    let metadata = fs::metadata(&canonical).map_err(|_| SorftimePinError::Metadata)?;
    if !canonical.is_absolute() || !metadata.is_file() {
        return Err(SorftimePinError::InvalidPath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(SorftimePinError::InvalidPath);
        }
    }
    Ok(canonical)
}

fn validate_expected_pin(version: &str, sha256: &str) -> Result<(), SorftimePinError> {
    if version.trim().is_empty()
        || sha256.len() != 64
        || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(SorftimePinError::InvalidPath);
    }
    Ok(())
}

fn digest_file(path: &Path) -> Result<String, SorftimePinError> {
    let mut file = File::open(path).map_err(|_| SorftimePinError::DigestRead)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| SorftimePinError::DigestRead)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn file_identity(path: &Path) -> Result<String, SorftimePinError> {
    let metadata = fs::metadata(path).map_err(|_| SorftimePinError::Metadata)?;
    let modified = metadata
        .modified()
        .map_err(|_| SorftimePinError::Metadata)?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SorftimePinError::Metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(format!(
            "unix:{}:{}:{}:{}",
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            modified.as_nanos()
        ))
    }
    #[cfg(not(unix))]
    Ok(format!(
        "portable:{}:{}",
        metadata.len(),
        modified.as_nanos()
    ))
}

fn probe_version(path: &Path, limits: &SorftimeCommandLimits) -> Result<String, SorftimePinError> {
    let mut command = Command::new(path);
    command.arg("--version");
    command.env_clear();
    command.env("LC_ALL", "C");
    command.env("LANG", "C");
    let output = run_bounded_command(command, None, limits).map_err(|error| match error {
        ProcessError::OutputLimit => SorftimePinError::VersionOutput,
        _ => SorftimePinError::VersionProbe,
    })?;
    if output.exit_code != 0 {
        return Err(SorftimePinError::VersionProbe);
    }
    let version = String::from_utf8(output.stdout).map_err(|_| SorftimePinError::VersionOutput)?;
    let version = version.trim().to_owned();
    if version.is_empty() {
        return Err(SorftimePinError::VersionOutput);
    }
    Ok(version)
}

fn normalize_estimate_body(body: Value) -> Value {
    match body {
        Value::Object(mut object) => {
            for key in ["Data", "data"] {
                if let Some(data) = object.remove(key)
                    && data.is_object()
                {
                    return data;
                }
            }
            Value::Object(object)
        }
        other => other,
    }
}

fn response_value<'a>(body: &'a Value, names: &[&str]) -> Option<&'a Value> {
    let object = body.as_object()?;
    names.iter().find_map(|name| object.get(*name)).or_else(|| {
        ["Data", "data"].iter().find_map(|key| {
            object
                .get(*key)
                .and_then(Value::as_object)
                .and_then(|nested| names.iter().find_map(|name| nested.get(*name)))
        })
    })
}

fn response_string(body: &Value, names: &[&str]) -> Option<String> {
    response_value(body, names)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|value| !value.trim().is_empty())
}

fn response_u64(body: &Value, names: &[&str]) -> Option<u64> {
    let value = response_value(body, names)?;
    value
        .as_u64()
        .or_else(|| value.as_str()?.parse::<u64>().ok())
}

fn response_business_code(body: &Value) -> Option<i64> {
    let value = response_value(body, &["Code", "code"])?;
    value
        .as_i64()
        .or_else(|| value.as_str()?.parse::<i64>().ok())
}

fn provenance_name(provenance: ProviderProvenanceClass) -> &'static str {
    match provenance {
        ProviderProvenanceClass::Fixture => "fixture",
        ProviderProvenanceClass::ComponentHarness => "component_harness",
        ProviderProvenanceClass::ControlledProvider => "controlled_provider",
        ProviderProvenanceClass::ProductionProvider => "production_provider",
    }
}

fn digest_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn digest_text(value: &str) -> String {
    digest_bytes(value.as_bytes())
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, SorftimePluginError> {
    let bytes = serde_json::to_vec(value).map_err(|_| {
        SorftimePluginError::InvalidEvidence("cannot serialize digest input".into())
    })?;
    Ok(digest_text(&String::from_utf8_lossy(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_keep_sorftime_estimate_separate_from_amazon_facts() {
        assert_eq!(
            crate::sorftime::SORFTIME_ESTIMATE_AUTHORITY,
            "estimate_only"
        );
        assert_ne!(
            SORFTIME_ESTIMATE_CAPABILITY_ID,
            "commerce.amazon-sp-api.readonly"
        );
        assert_eq!(SORFTIME_ESTIMATE_BLOCKED_ENV_STATUS, "BLOCKED_ENV");
    }
}
