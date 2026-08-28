//! Typed OneTrust V4 and consent-API provider seam.

use std::{env, fmt};

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;

use crate::model::{
    Digest, OneTrustConsentObservation, OneTrustEndpoint, OneTrustHttpRequest,
    OneTrustProviderErrorEvidence, OneTrustProviderErrorKind, OneTrustReadEvidence,
    OneTrustReadRequest, OneTrustResponseReceipt, ProviderRevision, RegistrationState,
    SecretReference, TransportProvenance,
};
use crate::transport::{OneTrustTransport, OneTrustTransportError};
use crate::{
    ONETRUST_MAX_PAGES, ONETRUST_MAX_REQUESTS_PER_MINUTE, ONETRUST_PAGE_SIZE,
    ONETRUST_PLUGIN_VERSION_TEXT, ONETRUST_PROVIDER_ID, ONETRUST_PROVIDER_REVISION_TEXT,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OneTrustProviderDefinition {
    pub provider_id: String,
    pub implementation: String,
    pub version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub read_only: bool,
    pub external_writes: bool,
    pub native: bool,
    pub connected: bool,
}

impl OneTrustProviderDefinition {
    pub fn baseline() -> Self {
        let provider_revision = ProviderRevision::new(ONETRUST_PROVIDER_REVISION_TEXT)
            .expect("static OneTrust provider revision");
        let provider_digest = Digest::from_fields([
            ONETRUST_PROVIDER_ID,
            crate::ONETRUST_PROVIDER_NAME,
            ONETRUST_PLUGIN_VERSION_TEXT,
            provider_revision.as_str(),
            "/rest/api/consent/v4/datasubjects/details",
            "https://consent-api.onetrust.com/v2/preferences",
            "/api/consent/v2/transactions",
        ]);
        Self {
            provider_id: ONETRUST_PROVIDER_ID.to_owned(),
            implementation: crate::ONETRUST_PROVIDER_NAME.to_owned(),
            version: ONETRUST_PLUGIN_VERSION_TEXT.to_owned(),
            provider_revision,
            provider_digest,
            read_only: true,
            external_writes: false,
            native: false,
            connected: false,
        }
    }

    pub fn is_compatible(&self) -> bool {
        self.provider_id == ONETRUST_PROVIDER_ID
            && self.implementation == crate::ONETRUST_PROVIDER_NAME
            && self.version == ONETRUST_PLUGIN_VERSION_TEXT
            && self.read_only
            && !self.external_writes
            && !self.native
            && !self.connected
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OneTrustProviderError {
    #[error("OneTrust provider request bounds are invalid")]
    InvalidRequest,
    #[error("OneTrust provider rate limit exceeded")]
    RateLimited { retry_after_seconds: u64 },
    #[error("OneTrust provider returned HTTP {status_code}")]
    HttpStatus {
        status_code: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("OneTrust provider returned a repeated pagination cursor")]
    CursorLoop,
    #[error("OneTrust provider evidence was tampered or stale")]
    Tampered,
    #[error("OneTrust provider returned a stale policy revision")]
    StalePolicyRevision,
    #[error("OneTrust provider returned an invalid response: {0}")]
    InvalidResponse(String),
    #[error("OneTrust provider is unknown or unavailable")]
    ProviderUnknown,
    #[error("OneTrust provider is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("OneTrust provider transport error: {0}")]
    Transport(OneTrustTransportError),
    #[error("OneTrust provider model error: {0}")]
    Model(String),
}

impl From<OneTrustTransportError> for OneTrustProviderError {
    fn from(error: OneTrustTransportError) -> Self {
        match error {
            OneTrustTransportError::BlockedEnv => Self::BlockedEnv,
            OneTrustTransportError::Timeout => Self::Transport(OneTrustTransportError::Timeout),
            other => Self::Transport(other),
        }
    }
}

impl OneTrustProviderError {
    pub fn evidence(&self, endpoint: OneTrustEndpoint) -> OneTrustProviderErrorEvidence {
        let (kind, status_code, retry_after) = match self {
            Self::InvalidRequest | Self::InvalidResponse(_) | Self::Model(_) => {
                (OneTrustProviderErrorKind::InvalidResponse, None, None)
            }
            Self::RateLimited {
                retry_after_seconds,
            } => (
                OneTrustProviderErrorKind::RateLimited,
                Some(429),
                Some(*retry_after_seconds),
            ),
            Self::HttpStatus {
                status_code,
                retry_after_seconds,
            } => (
                status_kind(*status_code),
                Some(*status_code),
                *retry_after_seconds,
            ),
            Self::CursorLoop => (OneTrustProviderErrorKind::CursorLoop, None, None),
            Self::Tampered => (OneTrustProviderErrorKind::Tampered, None, None),
            Self::StalePolicyRevision => {
                (OneTrustProviderErrorKind::StalePolicyRevision, None, None)
            }
            Self::BlockedEnv => (OneTrustProviderErrorKind::BlockedEnv, None, None),
            Self::Transport(OneTrustTransportError::Timeout) => {
                (OneTrustProviderErrorKind::Timeout, None, None)
            }
            Self::ProviderUnknown | Self::Transport(_) => {
                (OneTrustProviderErrorKind::ProviderUnknown, None, None)
            }
        };
        OneTrustProviderErrorEvidence::new(
            endpoint.operation_name(),
            kind,
            status_code,
            self.to_string(),
            retry_after,
        )
    }
}

fn status_kind(status_code: u16) -> OneTrustProviderErrorKind {
    match status_code {
        401 => OneTrustProviderErrorKind::Unauthenticated,
        403 => OneTrustProviderErrorKind::PermissionDenied,
        404 => OneTrustProviderErrorKind::NotFound,
        409 => OneTrustProviderErrorKind::Conflict,
        429 => OneTrustProviderErrorKind::RateLimited,
        500..=599 => OneTrustProviderErrorKind::ServerFailure,
        _ => OneTrustProviderErrorKind::ProviderUnknown,
    }
}

/// A bounded provider that knows the official OneTrust read paths and HTTP
/// status classification, but delegates all network/auth authority to a host
/// transport. Layer 1 does not resolve a native access token.
pub struct OneTrustConsentProvider<T> {
    transport: T,
    definition: OneTrustProviderDefinition,
    request_times: Vec<DateTime<Utc>>,
}

impl<T: fmt::Debug> fmt::Debug for OneTrustConsentProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OneTrustConsentProvider")
            .field("transport", &self.transport)
            .field("definition", &self.definition)
            .field("request_count", &self.request_times.len())
            .finish()
    }
}

impl<T: OneTrustTransport> OneTrustConsentProvider<T> {
    pub fn new(transport: T) -> Result<Self, OneTrustProviderError> {
        let definition = OneTrustProviderDefinition::baseline();
        if !definition.is_compatible() {
            return Err(OneTrustProviderError::InvalidResponse(
                "static OneTrust provider definition is incompatible".to_owned(),
            ));
        }
        Ok(Self {
            transport,
            definition,
            request_times: Vec::new(),
        })
    }

    pub fn definition(&self) -> &OneTrustProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.definition.provider_digest
    }

    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.definition.provider_revision
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        request: &OneTrustReadRequest,
    ) -> Result<OneTrustReadEvidence, OneTrustProviderError> {
        if request.page_size == 0
            || request.page_size > ONETRUST_PAGE_SIZE
            || request.max_pages == 0
            || request.max_pages > ONETRUST_MAX_PAGES
        {
            return Err(OneTrustProviderError::InvalidRequest);
        }
        let mut cursor = request.cursor.clone();
        let mut seen_cursors = std::collections::BTreeSet::new();
        if let Some(cursor) = &cursor {
            seen_cursors.insert(cursor.digest());
        }
        let mut observations = Vec::new();
        let mut page_cursor_digests = Vec::new();
        let mut request_receipt_digests = Vec::new();
        let mut response_receipt_digests = Vec::new();
        let mut pages_observed = 0;
        let mut failures = Vec::new();

        loop {
            if pages_observed >= request.max_pages {
                failures.push(OneTrustProviderErrorEvidence::new(
                    request.endpoint.operation_name(),
                    OneTrustProviderErrorKind::Partial,
                    None,
                    "maximum page bound reached",
                    None,
                ));
                break;
            }
            self.check_budget(request.observed_at)?;
            let page_request = request.with_cursor(cursor.clone());
            let http_request = OneTrustHttpRequest::from_read(&page_request)
                .map_err(|error| OneTrustProviderError::Model(error.to_string()))?;
            let response = self
                .transport
                .send(&http_request)
                .map_err(OneTrustProviderError::from)?;
            if response.receipt.validate().is_err()
                || response.receipt.request_digest != http_request.request_digest
                || response.receipt.status_code != response.status_code
                || response.receipt.provider_revision != self.definition.provider_revision
            {
                return Err(OneTrustProviderError::Tampered);
            }
            if !(200..300).contains(&response.status_code) {
                return Err(OneTrustProviderError::HttpStatus {
                    status_code: response.status_code,
                    retry_after_seconds: (response.status_code == 429).then_some(60),
                });
            }
            for observation in &response.body.observations {
                validate_observation(observation, request)?;
                if observations.len() >= crate::ONETRUST_MAX_OBSERVATIONS {
                    failures.push(OneTrustProviderErrorEvidence::new(
                        request.endpoint.operation_name(),
                        OneTrustProviderErrorKind::Partial,
                        None,
                        "maximum observation bound reached",
                        None,
                    ));
                    break;
                }
                observations.push(observation.clone());
            }
            pages_observed += 1;
            let request_receipt = crate::OneTrustRequestReceipt::from_request(&http_request);
            if request_receipt.validate().is_err() {
                return Err(OneTrustProviderError::Tampered);
            }
            request_receipt_digests.push(request_receipt.digest());
            response_receipt_digests.push(response.receipt.digest());
            if let Some(next_cursor) = response.next_cursor {
                let next_digest = next_cursor.digest();
                page_cursor_digests.push(next_digest.clone());
                if !seen_cursors.insert(next_digest) {
                    return Err(OneTrustProviderError::CursorLoop);
                }
                cursor = Some(next_cursor);
            } else {
                break;
            }
        }

        OneTrustReadEvidence::new(
            request.endpoint,
            request.scope_digest.clone(),
            request.subject_reference.clone(),
            observations,
            pages_observed,
            page_cursor_digests,
            request_receipt_digests,
            response_receipt_digests,
            failures,
            self.provenance(),
        )
        .map_err(|error| OneTrustProviderError::Model(error.to_string()))
    }

    /// Provider-bound read seam that accepts only an opaque reference. The
    /// reference digest is checked without exposing secret material to the
    /// transport; native resolution remains a later host-owned layer.
    pub fn read_with_secret(
        &mut self,
        secret_reference: &SecretReference,
        request: &OneTrustReadRequest,
    ) -> Result<OneTrustReadEvidence, OneTrustProviderError> {
        if secret_reference.digest() == &Digest::zero() {
            return Err(OneTrustProviderError::InvalidRequest);
        }
        self.read(request)
    }

    fn check_budget(&mut self, observed_at: DateTime<Utc>) -> Result<(), OneTrustProviderError> {
        let cutoff = observed_at - Duration::minutes(1);
        self.request_times.retain(|timestamp| *timestamp > cutoff);
        if self.request_times.len() >= usize::from(ONETRUST_MAX_REQUESTS_PER_MINUTE) {
            return Err(OneTrustProviderError::RateLimited {
                retry_after_seconds: 60,
            });
        }
        self.request_times.push(observed_at);
        Ok(())
    }
}

fn validate_observation(
    observation: &OneTrustConsentObservation,
    request: &OneTrustReadRequest,
) -> Result<(), OneTrustProviderError> {
    if observation.purpose_id != request.purpose_id
        || observation.purpose_version != request.purpose_version
        || observation.collection_point != request.collection_point
        || observation.subject_reference != request.subject_reference
    {
        return Err(OneTrustProviderError::Tampered);
    }
    if observation.policy_revision != request.policy_revision {
        return Err(OneTrustProviderError::StalePolicyRevision);
    }
    observation
        .validate_against_window(&request.consent_window)
        .map_err(|error| OneTrustProviderError::Model(error.to_string()))?;
    let recomputed = crate::digest_serializable(&(
        &observation.purpose_id,
        &observation.purpose_version,
        observation.status,
        observation.consented_at,
        observation.withdrawn_at,
        observation.expires_at,
        &observation.collection_point,
        &observation.transaction_id_digest,
        &observation.policy_revision,
        &observation.subject_reference,
        &observation.source_digest,
    ))
    .map_err(|error| OneTrustProviderError::Model(error.to_string()))?;
    if recomputed != observation.result_digest {
        return Err(OneTrustProviderError::Tampered);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProbeStatus {
    BlockedEnv,
    GateNotEnabled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProbe {
    pub status: NativeProbeStatus,
    pub native: bool,
    pub connected: bool,
    pub reason: String,
}

pub fn native_probe_from_environment() -> NativeProbe {
    match env::var(crate::ONETRUST_NATIVE_PROBE_ENV).as_deref() {
        Ok("1") => NativeProbe {
            status: NativeProbeStatus::BlockedEnv,
            native: false,
            connected: false,
            reason: "native OneTrust credential and host authority are not supplied by Layer 1"
                .to_owned(),
        },
        _ => NativeProbe {
            status: NativeProbeStatus::GateNotEnabled,
            native: false,
            connected: false,
            reason: "native probe gate is not enabled; deterministic transports remain non-native"
                .to_owned(),
        },
    }
}

/// Keep the provider boundary explicit: this helper accepts only an opaque
/// reference digest and never a raw token or JWT.
pub fn provider_secret_reference_digest(secret_reference: &crate::SecretReference) -> Digest {
    secret_reference.digest().clone()
}

#[allow(dead_code)]
fn _receipt_is_bounded(receipt: &OneTrustResponseReceipt) -> bool {
    receipt.response_size_bytes <= crate::ONETRUST_MAX_RESPONSE_BYTES
}

#[allow(dead_code)]
fn _registration_is_active(registration: RegistrationState) -> bool {
    registration == RegistrationState::Active
}
