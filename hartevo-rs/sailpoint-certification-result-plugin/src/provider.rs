//! Typed SailPoint provider definition, compatibility, and bounded read
//! policy. This provider owns no credential material and exposes GET only.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::{
    AccessType, Digest, PermissionSnapshot, ProviderRevision, SAILPOINT_API_VERSION,
    SAILPOINT_MAX_LIMIT, SAILPOINT_MAX_OFFSET, SAILPOINT_MAX_REQUESTS_PER_MINUTE,
    SAILPOINT_PLUGIN_VERSION_TEXT, SAILPOINT_PROVIDER_ID, SAILPOINT_PROVIDER_IMPLEMENTATION,
    SAILPOINT_PROVIDER_REVISION_TEXT, SailPointEndpoint, SailPointHttpResponse,
    SailPointModelError, SailPointReadEvidence, SailPointReadRequest, SailPointResponseBody,
    SailPointTransport, SailPointTransportError, SecretReference, TransportProvenance,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SailPointProviderError {
    #[error("SailPoint provider model error: {0}")]
    Model(#[from] SailPointModelError),
    #[error("SailPoint provider transport error: {0}")]
    Transport(SailPointTransportError),
    #[error("SailPoint provider is incompatible with the Layer-1 contract")]
    Incompatible,
    #[error("SailPoint provider permission snapshot is not exact read-only")]
    PermissionMismatch,
    #[error("SailPoint provider revision drifted")]
    ProviderRevisionMismatch,
    #[error("SailPoint provider response was tampered after receipt creation")]
    ResponseTampered,
    #[error("SailPoint provider response contained a duplicate immutable identifier")]
    DuplicateIdentifier,
    #[error("SailPoint provider pagination offset or deterministic ordering drifted")]
    PaginationDrift,
    #[error("SailPoint provider returned a stale campaign revision")]
    StaleCampaignRevision,
    #[error("SailPoint provider returned a stale entitlement revision")]
    StaleEntitlementRevision,
    #[error("SailPoint provider rate limit exceeded: retry after {retry_after_seconds} seconds")]
    RateLimited { retry_after_seconds: u64 },
    #[error("SailPoint provider access was lost")]
    AccessLost,
    #[error("SailPoint provider is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("SailPoint provider secret reference is revoked")]
    SecretRevoked,
}

impl SailPointProviderError {
    pub const fn is_access_lost(&self) -> bool {
        matches!(self, Self::AccessLost)
    }

    pub const fn is_provider_unknown(&self) -> bool {
        matches!(self, Self::BlockedEnv | Self::Transport(_))
    }
}

impl From<SailPointTransportError> for SailPointProviderError {
    fn from(error: SailPointTransportError) -> Self {
        match error {
            SailPointTransportError::AccessLost { .. } => Self::AccessLost,
            SailPointTransportError::RateLimited {
                retry_after_seconds,
            } => Self::RateLimited {
                retry_after_seconds,
            },
            SailPointTransportError::BlockedEnv => Self::BlockedEnv,
            other => Self::Transport(other),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SailPointProviderDefinition {
    pub id: String,
    pub implementation: String,
    pub version: String,
    pub api_version: String,
    pub revision: ProviderRevision,
    pub allowed_methods: Vec<String>,
    pub allowed_reads: Vec<String>,
    pub permissions: PermissionSnapshot,
    pub native: bool,
    pub connected: bool,
    pub external_writes: bool,
    pub decision_writes: bool,
    pub access_request_writes: bool,
    pub identity_mutation: bool,
    pub entitlement_mutation: bool,
}

impl SailPointProviderDefinition {
    pub fn baseline() -> Self {
        Self {
            id: SAILPOINT_PROVIDER_ID.to_owned(),
            implementation: SAILPOINT_PROVIDER_IMPLEMENTATION.to_owned(),
            version: SAILPOINT_PLUGIN_VERSION_TEXT.to_owned(),
            api_version: SAILPOINT_API_VERSION.to_owned(),
            revision: ProviderRevision::new(SAILPOINT_PROVIDER_REVISION_TEXT)
                .expect("static provider revision is valid"),
            allowed_methods: vec!["GET".to_owned()],
            allowed_reads: vec![
                "get_identity_certification".to_owned(),
                "get_identity_certifications".to_owned(),
                "get_identity_access_summaries".to_owned(),
            ],
            permissions: PermissionSnapshot::read_only(),
            native: false,
            connected: false,
            external_writes: false,
            decision_writes: false,
            access_request_writes: false,
            identity_mutation: false,
            entitlement_mutation: false,
        }
    }

    pub fn validate(&self) -> Result<(), SailPointProviderError> {
        if self.id != SAILPOINT_PROVIDER_ID
            || self.implementation != SAILPOINT_PROVIDER_IMPLEMENTATION
            || self.version != SAILPOINT_PLUGIN_VERSION_TEXT
            || self.api_version != SAILPOINT_API_VERSION
            || self.revision.as_str() != SAILPOINT_PROVIDER_REVISION_TEXT
            || self.allowed_methods != ["GET"]
            || self.allowed_reads
                != [
                    "get_identity_certification",
                    "get_identity_certifications",
                    "get_identity_access_summaries",
                ]
            || !self.permissions.is_exact_read_only()
            || self.native
            || self.connected
            || self.external_writes
            || self.decision_writes
            || self.access_request_writes
            || self.identity_mutation
            || self.entitlement_mutation
        {
            return Err(SailPointProviderError::Incompatible);
        }
        Ok(())
    }

    pub fn permission_digest(&self) -> &Digest {
        self.permissions.digest()
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields([
            self.id.as_str(),
            self.implementation.as_str(),
            self.version.as_str(),
            self.api_version.as_str(),
            self.revision.as_str(),
            self.allowed_methods.join(",").as_str(),
            self.allowed_reads.join(",").as_str(),
            self.permissions.digest().as_str(),
            "native=false",
            "connected=false",
            "external_writes=false",
            "decision_writes=false",
            "access_request_writes=false",
            "identity_mutation=false",
            "entitlement_mutation=false",
        ])
    }

    pub fn is_compatible(&self) -> bool {
        self.validate().is_ok()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PageState {
    last_offset: u32,
    last_key: Option<String>,
    keys: BTreeSet<String>,
    pages_seen: u16,
}

/// A bounded SailPoint V3 provider over a host-supplied typed transport.
pub struct SailPointProvider<T> {
    definition: SailPointProviderDefinition,
    transport: T,
    window_started: Option<DateTime<Utc>>,
    requests_in_window: u8,
    pages: BTreeMap<String, PageState>,
}

impl<T: fmt::Debug> fmt::Debug for SailPointProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SailPointProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .field("window_started", &self.window_started)
            .field("requests_in_window", &self.requests_in_window)
            .field("tracked_operations", &self.pages.len())
            .finish()
    }
}

impl<T: SailPointTransport> SailPointProvider<T> {
    pub fn new(transport: T) -> Result<Self, SailPointProviderError> {
        let definition = SailPointProviderDefinition::baseline();
        definition.validate()?;
        Ok(Self {
            definition,
            transport,
            window_started: None,
            requests_in_window: 0,
            pages: BTreeMap::new(),
        })
    }

    pub fn definition(&self) -> &SailPointProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.definition.revision
    }

    pub fn permission_digest(&self) -> &Digest {
        self.definition.permission_digest()
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
        request: &SailPointReadRequest,
    ) -> Result<SailPointReadEvidence, SailPointProviderError> {
        self.read_internal(request, None)
    }

    pub fn read_with_secret(
        &mut self,
        request: &SailPointReadRequest,
        secret: &SecretReference,
    ) -> Result<SailPointReadEvidence, SailPointProviderError> {
        if secret.is_revoked() {
            return Err(SailPointProviderError::SecretRevoked);
        }
        self.read_internal(request, Some(secret))
    }

    fn read_internal(
        &mut self,
        request: &SailPointReadRequest,
        _secret: Option<&SecretReference>,
    ) -> Result<SailPointReadEvidence, SailPointProviderError> {
        self.definition.validate()?;
        if request.limit == 0
            || request.limit > SAILPOINT_MAX_LIMIT
            || request.offset > SAILPOINT_MAX_OFFSET
        {
            return Err(SailPointProviderError::Incompatible);
        }
        self.check_budget(request.observed_at)?;
        let http_request = request.http_request();
        let response = self
            .transport
            .send(&http_request)
            .map_err(SailPointProviderError::from)?;
        self.validate_response(request, &http_request, &response)?;
        self.check_page_order(request, &response.body)?;
        SailPointReadEvidence::new(&http_request, response, self.provenance())
            .map_err(SailPointProviderError::from)
    }

    fn check_budget(&mut self, observed_at: DateTime<Utc>) -> Result<(), SailPointProviderError> {
        if let Some(started) = self.window_started {
            if observed_at < started || observed_at - started >= Duration::minutes(1) {
                self.window_started = Some(observed_at);
                self.requests_in_window = 0;
            }
        } else {
            self.window_started = Some(observed_at);
        }
        if self.requests_in_window >= SAILPOINT_MAX_REQUESTS_PER_MINUTE {
            return Err(SailPointProviderError::RateLimited {
                retry_after_seconds: 60,
            });
        }
        self.requests_in_window = self.requests_in_window.saturating_add(1);
        Ok(())
    }

    fn validate_response(
        &self,
        request: &SailPointReadRequest,
        http_request: &crate::SailPointHttpRequest,
        response: &SailPointHttpResponse,
    ) -> Result<(), SailPointProviderError> {
        if response.receipt.status != 200
            || response.receipt.request_digest != request.request_digest
            || response.endpoint != request.endpoint
            || !response.body.endpoint_matches(&request.endpoint)
        {
            return Err(SailPointProviderError::ResponseTampered);
        }
        if response.receipt.provider_revision != self.definition.revision {
            return Err(SailPointProviderError::ProviderRevisionMismatch);
        }
        let bytes = serde_json::to_vec(&response.body)
            .map_err(|_| SailPointProviderError::ResponseTampered)?;
        if bytes.len() > crate::SAILPOINT_MAX_RESPONSE_BYTES
            || response.receipt.response_bytes != bytes.len()
            || crate::sha256_digest(&bytes) != response.receipt.response_digest
        {
            return Err(SailPointProviderError::ResponseTampered);
        }
        if http_request.origin != request.api_base.origin()
            || http_request.path_and_query
                != request
                    .endpoint
                    .path_and_query(request.limit, request.offset)
            || http_request.scope_digest != request.scope_digest
            || http_request.expected_campaign_revision != request.expected_campaign_revision
            || http_request.expected_entitlement_revision != request.expected_entitlement_revision
            || http_request.observed_at != request.observed_at
            || http_request.method != "GET"
        {
            return Err(SailPointProviderError::ResponseTampered);
        }
        Self::validate_revisions(request, &response.body)
    }

    fn validate_revisions(
        request: &SailPointReadRequest,
        body: &SailPointResponseBody,
    ) -> Result<(), SailPointProviderError> {
        match body {
            SailPointResponseBody::Certification(record) => {
                if record.campaign.revision != request.expected_campaign_revision {
                    return Err(SailPointProviderError::StaleCampaignRevision);
                }
            }
            SailPointResponseBody::Campaigns(records) => {
                if records
                    .iter()
                    .any(|record| record.campaign.revision != request.expected_campaign_revision)
                {
                    return Err(SailPointProviderError::StaleCampaignRevision);
                }
            }
            SailPointResponseBody::AccessSummaries(records) => {
                if records
                    .iter()
                    .any(|summary| summary.campaign_revision != request.expected_campaign_revision)
                {
                    return Err(SailPointProviderError::StaleCampaignRevision);
                }
                for summary in records {
                    validate_access_revision(
                        request,
                        summary.campaign_revision,
                        summary.entitlement_revision,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn check_page_order(
        &mut self,
        request: &SailPointReadRequest,
        body: &SailPointResponseBody,
    ) -> Result<(), SailPointProviderError> {
        let operation = request.endpoint.operation_name().to_owned();
        let keys = response_keys(body);
        let page = self.pages.entry(operation.clone()).or_insert(PageState {
            last_offset: 0,
            last_key: None,
            keys: BTreeSet::new(),
            pages_seen: 0,
        });
        if page.pages_seen >= crate::SAILPOINT_MAX_PAGES {
            return Err(SailPointProviderError::PaginationDrift);
        }
        if request.offset < page.last_offset
            || request.offset == page.last_offset && page.last_key.is_some()
        {
            return Err(SailPointProviderError::PaginationDrift);
        }
        if keys.iter().any(|key| page.keys.contains(key)) {
            return Err(SailPointProviderError::DuplicateIdentifier);
        }
        if let (Some(previous), Some(first)) = (page.last_key.as_ref(), keys.first())
            && first <= previous
        {
            return Err(SailPointProviderError::PaginationDrift);
        }
        page.last_offset = request.offset;
        page.last_key = keys.last().cloned().or_else(|| page.last_key.clone());
        page.keys.extend(keys);
        page.pages_seen = page.pages_seen.saturating_add(1);
        Ok(())
    }
}

fn validate_access_revision(
    request: &SailPointReadRequest,
    _campaign_revision: crate::Revision,
    entitlement_revision: Option<crate::Revision>,
) -> Result<(), SailPointProviderError> {
    if let Some(expected) = request.expected_entitlement_revision
        && entitlement_revision != Some(expected)
    {
        return Err(SailPointProviderError::StaleEntitlementRevision);
    }
    Ok(())
}

fn response_keys(body: &SailPointResponseBody) -> Vec<String> {
    match body {
        SailPointResponseBody::Certification(record) => vec![record.id.as_str().to_owned()],
        SailPointResponseBody::Campaigns(records) => records
            .iter()
            .map(|record| record.id.as_str().to_owned())
            .collect(),
        SailPointResponseBody::AccessSummaries(records) => records
            .iter()
            .map(|record| {
                format!(
                    "{}:{}:{}",
                    record.access_type.as_str(),
                    record.id,
                    record.identity_id
                )
            })
            .collect(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProbeStatus {
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeProbe {
    pub status: NativeProbeStatus,
    pub native_connected_claim: bool,
    pub first_party_evidence_claim: bool,
}

pub fn native_probe_from_environment() -> NativeProbe {
    let _ = crate::SAILPOINT_NATIVE_PROBE_ENV;
    let _ = crate::SAILPOINT_NATIVE_PROBE_GATE;
    NativeProbe {
        status: NativeProbeStatus::BlockedEnv,
        native_connected_claim: false,
        first_party_evidence_claim: false,
    }
}

impl<T> SailPointProvider<T> {
    pub fn provider_identity(&self) -> (&str, &str, &str) {
        (
            self.definition.id.as_str(),
            self.definition.implementation.as_str(),
            self.definition.revision.as_str(),
        )
    }
}

impl<T: SailPointTransport> SailPointProvider<T> {
    pub fn expected_access_type(&self, endpoint: &SailPointEndpoint) -> Option<AccessType> {
        match endpoint {
            SailPointEndpoint::AccessSummaries { access_type, .. } => Some(*access_type),
            _ => None,
        }
    }
}
