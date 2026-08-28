//! Typed Vanta provider and bounded rate handling.

use std::{collections::VecDeque, env, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, ProviderRevision, SecretReference, VantaReadEvidence, VantaReadRequest,
    VantaResponseReceipt,
};
use crate::transport::{VantaHttpRequest, VantaTransport};
use crate::{
    VANTA_CONTRACT_VERSION, VANTA_MAX_REQUESTS_PER_MINUTE, VANTA_NATIVE_PROBE_ENV,
    VANTA_NATIVE_PROBE_GATE, VANTA_PLUGIN_VERSION_TEXT, VANTA_PROVIDER_ID,
    VANTA_PROVIDER_REVISION_TEXT, VantaComplianceResultError,
};

pub use crate::model::VantaProviderIdentity;

const RATE_WINDOW_SECONDS: i64 = 60;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeProbeStatus {
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeProbe {
    pub status: NativeProbeStatus,
    pub native_credentials_resolved: bool,
    pub live_https_verified: bool,
    pub native_connected_claim: bool,
    pub reason: String,
}

impl NativeProbe {
    pub fn from_environment() -> Self {
        let enabled = env::var(VANTA_NATIVE_PROBE_ENV).ok().as_deref() == Some("1");
        let reason = if enabled {
            format!(
                "{VANTA_NATIVE_PROBE_GATE} is present, but Layer 1 has no native Vanta credential authority"
            )
        } else {
            format!("{VANTA_NATIVE_PROBE_GATE} is not enabled")
        };
        Self {
            status: NativeProbeStatus::BlockedEnv,
            native_credentials_resolved: false,
            live_https_verified: false,
            native_connected_claim: false,
            reason,
        }
    }
}

pub fn native_probe_from_environment() -> NativeProbe {
    NativeProbe::from_environment()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VantaRateLimit {
    max_requests: u8,
    window_seconds: i64,
    request_times: VecDeque<DateTime<Utc>>,
}

impl Default for VantaRateLimit {
    fn default() -> Self {
        Self {
            max_requests: VANTA_MAX_REQUESTS_PER_MINUTE,
            window_seconds: RATE_WINDOW_SECONDS,
            request_times: VecDeque::new(),
        }
    }
}

impl VantaRateLimit {
    pub fn new(max_requests: u8, window_seconds: i64) -> Result<Self, VantaComplianceResultError> {
        if max_requests == 0
            || max_requests > VANTA_MAX_REQUESTS_PER_MINUTE
            || window_seconds != RATE_WINDOW_SECONDS
        {
            return Err(VantaComplianceResultError::InvalidInput(
                "Vanta rate limit must be positive".to_owned(),
            ));
        }
        Ok(Self {
            max_requests,
            window_seconds,
            request_times: VecDeque::new(),
        })
    }

    fn admit(&mut self, at: DateTime<Utc>) -> Result<(), VantaComplianceResultError> {
        let cutoff = at - Duration::seconds(self.window_seconds);
        while self
            .request_times
            .front()
            .is_some_and(|time| *time <= cutoff)
        {
            self.request_times.pop_front();
        }
        if self.request_times.len() >= usize::from(self.max_requests) {
            let retry_after_seconds = u64::try_from(
                self.request_times
                    .front()
                    .map_or(1, |time| {
                        (*time + Duration::seconds(self.window_seconds) - at).num_seconds()
                    })
                    .max(1),
            )
            .unwrap_or(1);
            return Err(VantaComplianceResultError::RateLimited {
                retry_after_seconds,
            });
        }
        self.request_times.push_back(at);
        Ok(())
    }

    pub fn requests_in_window(&self) -> usize {
        self.request_times.len()
    }

    pub const fn max_requests(&self) -> u8 {
        self.max_requests
    }
}

/// Provider metadata is immutable and is included in every registration and
/// result fence. The transport is generic so fixture and recording tests do
/// not need a native HTTP client.
pub struct VantaProvider<T> {
    transport: T,
    identity: VantaProviderIdentity,
    rate_limit: VantaRateLimit,
}

impl<T: fmt::Debug> fmt::Debug for VantaProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VantaProvider")
            .field("identity", &self.identity)
            .field("transport", &self.transport)
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl<T: VantaTransport> VantaProvider<T> {
    pub fn new(transport: T) -> Result<Self, VantaComplianceResultError> {
        let revision = ProviderRevision::new(VANTA_PROVIDER_REVISION_TEXT)?;
        let digest = crate::model::digest_serializable(&(
            VANTA_PROVIDER_ID,
            VANTA_PLUGIN_VERSION_TEXT,
            VANTA_CONTRACT_VERSION,
            &revision,
            [
                "GET",
                "list_audits",
                "list_controls",
                "list_tests",
                "list_issues",
                "list_information_requests",
            ],
        ))?;
        Ok(Self {
            transport,
            identity: VantaProviderIdentity {
                id: VANTA_PROVIDER_ID.to_owned(),
                version: VANTA_PLUGIN_VERSION_TEXT.to_owned(),
                revision,
                digest,
            },
            rate_limit: VantaRateLimit::default(),
        })
    }

    pub fn with_rate_limit(
        transport: T,
        rate_limit: VantaRateLimit,
    ) -> Result<Self, VantaComplianceResultError> {
        let mut provider = Self::new(transport)?;
        provider.rate_limit = rate_limit;
        Ok(provider)
    }

    pub fn identity(&self) -> &VantaProviderIdentity {
        &self.identity
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.identity.digest
    }

    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.identity.revision
    }

    pub fn provenance(&self) -> crate::model::TransportProvenance {
        self.transport.provenance()
    }

    pub fn rate_limit(&self) -> &VantaRateLimit {
        &self.rate_limit
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        secret_reference: &SecretReference,
        request: &VantaReadRequest,
    ) -> Result<VantaReadEvidence, VantaComplianceResultError> {
        let mut cursor = None;
        let mut seen_cursors = Vec::new();
        let mut pages = Vec::new();
        let mut receipts: Vec<VantaResponseReceipt> = Vec::new();
        let mut page_limit_reached = false;

        for page_index in 0..request.max_pages {
            self.rate_limit.admit(request.observed_at)?;
            let http_request = VantaHttpRequest::new(request, cursor.clone())?;
            let response = self
                .transport
                .execute(secret_reference, &http_request)
                .map_err(|error| {
                    if matches!(error, crate::transport::VantaTransportError::BlockedEnv) {
                        VantaComplianceResultError::BlockedEnv
                    } else {
                        VantaComplianceResultError::Transport(error)
                    }
                })?;
            response.validate(&http_request)?;
            if response.receipt().provider_revision != self.identity.revision
                || response.receipt().endpoint != request.endpoint
            {
                return Err(VantaComplianceResultError::ProviderMismatch);
            }
            pages.push(response.body().clone());
            receipts.push(response.receipt().clone());
            let Some(next_cursor) = response.next_cursor().cloned() else {
                break;
            };
            if seen_cursors.contains(&next_cursor) || cursor.as_ref() == Some(&next_cursor) {
                return Err(VantaComplianceResultError::Transport(
                    crate::transport::VantaTransportError::Transport(
                        "Vanta pagination cursor loop".to_owned(),
                    ),
                ));
            }
            seen_cursors.push(next_cursor.clone());
            if page_index + 1 == request.max_pages {
                page_limit_reached = true;
                break;
            }
            cursor = Some(next_cursor);
        }

        VantaReadEvidence::new(
            request.endpoint.clone(),
            request.scope_digest.clone(),
            pages,
            receipts,
            page_limit_reached,
            self.transport.provenance(),
            self.identity.revision.clone(),
        )
        .map_err(VantaComplianceResultError::Model)
    }
}

// Keep this helper visible to tests without exposing credential material or a
// native resolver. It is intentionally a constant false for every transport.
pub fn provider_is_native<T: VantaTransport>(provider: &VantaProvider<T>) -> bool {
    provider.transport().is_native()
}
