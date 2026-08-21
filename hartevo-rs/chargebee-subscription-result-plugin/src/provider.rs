//! Typed Chargebee provider definition and bounded pagination policy.
//!
//! The provider accepts only typed GET-shaped requests over a caller-supplied
//! fixture/recording/fake/loopback transport. It owns no credential material,
//! has no mutation methods, and never reports connected/native evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::Serialize;
use thiserror::Error;

use crate::{
    ChargebeeHttpRequest, ChargebeeHttpResponse, ChargebeeModelError, ChargebeePermissionSnapshot,
    ChargebeeReadEvidence, ChargebeeReadOperation, ChargebeeReadRequest, ChargebeeResponseBody,
    ChargebeeScopeBindings, ChargebeeTransport, ChargebeeTransportError,
    ChargebeeTransportProvenance, Digest, EntitlementObservation, InvoiceObservation, MAX_PAGES,
    MAX_REQUESTS_PER_MINUTE, MAX_RESPONSE_BYTES, PLUGIN_VERSION_TEXT, PROVIDER_API_REVISION,
    PROVIDER_ID, PROVIDER_IMPLEMENTATION, PROVIDER_REVISION_TEXT, ProviderRevision,
    SecretReference, SubscriptionObservation, body_key_set,
};

/// Provider failures retain only typed status and digest metadata.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChargebeeProviderError {
    #[error("Chargebee provider model error: {0}")]
    Model(#[from] ChargebeeModelError),
    #[error("Chargebee provider transport error: {0}")]
    Transport(ChargebeeTransportError),
    #[error("Chargebee provider is incompatible with the Layer-1 contract")]
    Incompatible,
    #[error("Chargebee provider permission snapshot is not exact read-only")]
    PermissionMismatch,
    #[error("Chargebee provider revision drifted")]
    ProviderRevisionMismatch,
    #[error("Chargebee response was tampered after receipt creation")]
    ResponseTampered,
    #[error("Chargebee response scope does not match the exact request scope")]
    ScopeMismatch,
    #[error("Chargebee response contained a duplicate immutable identifier")]
    DuplicateIdentifier,
    #[error("Chargebee provider pagination or cursor binding drifted")]
    PaginationDrift,
    #[error("Chargebee provider returned a stale resource revision")]
    StaleRevision,
    #[error("Chargebee provider cursor is stale or tampered")]
    CursorMismatch,
    #[error("Chargebee provider rate limit exceeded; retry after {retry_after_seconds} seconds")]
    RateLimited { retry_after_seconds: u64 },
    #[error("Chargebee provider access was lost")]
    AccessLost,
    #[error("Chargebee provider denied the requested read")]
    Denied,
    #[error("Chargebee resource was absent")]
    Absent,
    #[error("Chargebee observation was expired")]
    Expired,
    #[error("Chargebee provider is unknown or unavailable")]
    ProviderUnknown,
    #[error("Chargebee provider is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("Chargebee provider secret reference is revoked")]
    SecretRevoked,
}

impl From<ChargebeeTransportError> for ChargebeeProviderError {
    fn from(error: ChargebeeTransportError) -> Self {
        match error {
            ChargebeeTransportError::AccessLost { .. } => Self::AccessLost,
            ChargebeeTransportError::Denied => Self::Denied,
            ChargebeeTransportError::Absent => Self::Absent,
            ChargebeeTransportError::Expired => Self::Expired,
            ChargebeeTransportError::RateLimited {
                retry_after_seconds,
            } => Self::RateLimited {
                retry_after_seconds,
            },
            ChargebeeTransportError::BlockedEnv => Self::BlockedEnv,
            ChargebeeTransportError::ProviderUnknown
            | ChargebeeTransportError::Timeout
            | ChargebeeTransportError::HttpStatus { .. } => Self::ProviderUnknown,
            other => Self::Transport(other),
        }
    }
}

impl ChargebeeProviderError {
    pub const fn is_projection_state(&self) -> bool {
        matches!(
            self,
            Self::AccessLost
                | Self::Denied
                | Self::Absent
                | Self::Expired
                | Self::ProviderUnknown
                | Self::BlockedEnv
                | Self::RateLimited { .. }
        )
    }
}

/// Immutable provider definition bound into registration and evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ChargebeeProviderDefinition {
    pub id: String,
    pub implementation: String,
    pub version: String,
    pub api_revision: String,
    pub revision: ProviderRevision,
    pub allowed_methods: Vec<String>,
    pub allowed_reads: Vec<String>,
    pub permissions: ChargebeePermissionSnapshot,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub subscription_writes: bool,
    pub plan_writes: bool,
    pub entitlement_writes: bool,
    pub invoice_writes: bool,
    pub refunds: bool,
    pub payment_instrument_access: bool,
    pub raw_customer_pii: bool,
}

impl ChargebeeProviderDefinition {
    pub fn baseline() -> Self {
        Self {
            id: PROVIDER_ID.to_owned(),
            implementation: PROVIDER_IMPLEMENTATION.to_owned(),
            version: PLUGIN_VERSION_TEXT.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            revision: ProviderRevision::new(PROVIDER_REVISION_TEXT)
                .expect("static Chargebee provider revision is valid"),
            allowed_methods: vec!["GET".to_owned()],
            allowed_reads: ChargebeeReadOperation::ALL
                .into_iter()
                .map(|operation| operation.as_str().to_owned())
                .collect(),
            permissions: ChargebeePermissionSnapshot::read_only(),
            native: false,
            connected: false,
            first_party: false,
            external_writes: false,
            subscription_writes: false,
            plan_writes: false,
            entitlement_writes: false,
            invoice_writes: false,
            refunds: false,
            payment_instrument_access: false,
            raw_customer_pii: false,
        }
    }

    pub fn validate(&self) -> Result<(), ChargebeeProviderError> {
        let expected_reads = ChargebeeReadOperation::ALL
            .into_iter()
            .map(|operation| operation.as_str().to_owned())
            .collect::<Vec<_>>();
        if self.id != PROVIDER_ID
            || self.implementation != PROVIDER_IMPLEMENTATION
            || self.version != PLUGIN_VERSION_TEXT
            || self.api_revision != PROVIDER_API_REVISION
            || self.revision.as_str() != PROVIDER_REVISION_TEXT
            || self.allowed_methods != ["GET"]
            || self.allowed_reads != expected_reads
            || !self.permissions.is_exact_read_only()
            || self.native
            || self.connected
            || self.first_party
            || self.external_writes
            || self.subscription_writes
            || self.plan_writes
            || self.entitlement_writes
            || self.invoice_writes
            || self.refunds
            || self.payment_instrument_access
            || self.raw_customer_pii
        {
            Err(ChargebeeProviderError::Incompatible)
        } else {
            Ok(())
        }
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permissions.digest
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields([
            self.id.as_str(),
            self.implementation.as_str(),
            self.version.as_str(),
            self.api_revision.as_str(),
            self.revision.as_str(),
            self.allowed_methods.join(",").as_str(),
            self.allowed_reads.join(",").as_str(),
            self.permissions.digest.as_str(),
            "native=false",
            "connected=false",
            "first_party=false",
            "external_writes=false",
            "subscription_writes=false",
            "plan_writes=false",
            "entitlement_writes=false",
            "invoice_writes=false",
            "refunds=false",
            "payment_instrument_access=false",
            "raw_customer_pii=false",
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PageState {
    pages_seen: u16,
    keys: BTreeSet<String>,
    last_key: Option<String>,
    last_key_digest: Option<Digest>,
}

/// Typed Chargebee provider over a host-supplied non-native transport.
pub struct ChargebeeProvider<T> {
    definition: ChargebeeProviderDefinition,
    transport: T,
    window_started_ms: Option<u64>,
    requests_in_window: u8,
    pages: BTreeMap<Digest, PageState>,
    cached_reads: BTreeMap<Digest, ChargebeeReadEvidence>,
}

impl<T: fmt::Debug> fmt::Debug for ChargebeeProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChargebeeProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .field("window_started_ms", &self.window_started_ms)
            .field("requests_in_window", &self.requests_in_window)
            .field("tracked_queries", &self.pages.len())
            .field("cached_reads", &self.cached_reads.len())
            .finish()
    }
}

impl<T: ChargebeeTransport> ChargebeeProvider<T> {
    pub fn new(transport: T) -> Result<Self, ChargebeeProviderError> {
        let definition = ChargebeeProviderDefinition::baseline();
        definition.validate()?;
        Ok(Self {
            definition,
            transport,
            window_started_ms: None,
            requests_in_window: 0,
            pages: BTreeMap::new(),
            cached_reads: BTreeMap::new(),
        })
    }

    pub fn definition(&self) -> &ChargebeeProviderDefinition {
        &self.definition
    }

    pub fn definition_mut(&mut self) -> &mut ChargebeeProviderDefinition {
        &mut self.definition
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

    pub fn provenance(&self) -> ChargebeeTransportProvenance {
        self.transport.provenance()
    }

    pub const fn native_connected(&self) -> bool {
        false
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        request: &ChargebeeReadRequest,
    ) -> Result<ChargebeeReadEvidence, ChargebeeProviderError> {
        self.read_internal(request, None)
    }

    pub fn read_with_secret(
        &mut self,
        request: &ChargebeeReadRequest,
        secret: &SecretReference,
    ) -> Result<ChargebeeReadEvidence, ChargebeeProviderError> {
        if secret.is_revoked() {
            return Err(ChargebeeProviderError::SecretRevoked);
        }
        if secret.scope_digest() != &request.bindings.scope_digest {
            return Err(ChargebeeProviderError::ScopeMismatch);
        }
        self.read_internal(request, Some(secret))
    }

    fn read_internal(
        &mut self,
        request: &ChargebeeReadRequest,
        _secret: Option<&SecretReference>,
    ) -> Result<ChargebeeReadEvidence, ChargebeeProviderError> {
        self.definition.validate()?;
        request.validate()?;
        if request.limit == 0 || request.limit > crate::MAX_PAGE_SIZE {
            return Err(ChargebeeProviderError::Incompatible);
        }
        if let Some(cached) = self.cached_reads.get(&request.request_digest) {
            return Ok(cached.clone());
        }
        self.check_budget(request.observed_at_ms)?;
        let http_request = request.http_request();
        let response = self
            .transport
            .send(&http_request)
            .map_err(ChargebeeProviderError::from)?;
        self.validate_response(request, &http_request, &response)?;
        let progress = self.check_page_order(request, &response.body, response.receipt.has_more)?;
        let evidence =
            ChargebeeReadEvidence::new(&http_request, response, self.provenance(), progress)?;
        self.cached_reads
            .insert(request.request_digest.clone(), evidence.clone());
        Ok(evidence)
    }

    fn check_budget(&mut self, observed_at_ms: u64) -> Result<(), ChargebeeProviderError> {
        if let Some(started) = self.window_started_ms {
            if observed_at_ms < started {
                return Err(ChargebeeProviderError::ProviderUnknown);
            }
            if observed_at_ms.saturating_sub(started) >= 60_000 {
                self.window_started_ms = Some(observed_at_ms);
                self.requests_in_window = 0;
            }
        } else {
            self.window_started_ms = Some(observed_at_ms);
        }
        if self.requests_in_window >= MAX_REQUESTS_PER_MINUTE {
            return Err(ChargebeeProviderError::RateLimited {
                retry_after_seconds: 60,
            });
        }
        self.requests_in_window = self.requests_in_window.saturating_add(1);
        Ok(())
    }

    fn validate_response(
        &self,
        request: &ChargebeeReadRequest,
        http_request: &ChargebeeHttpRequest,
        response: &ChargebeeHttpResponse,
    ) -> Result<(), ChargebeeProviderError> {
        if response.receipt.status != 200
            || response.receipt.request_digest != request.request_digest
            || response.operation != request.operation
            || response.body.operation() != request.operation
            || response.receipt.provider_revision != self.definition.revision
        {
            return Err(ChargebeeProviderError::ResponseTampered);
        }
        let body = response.body.clone().normalized()?;
        let bytes =
            serde_json::to_vec(&body).map_err(|_| ChargebeeProviderError::ResponseTampered)?;
        if bytes.len() > MAX_RESPONSE_BYTES
            || response.receipt.response_bytes != bytes.len()
            || crate::Digest::from_bytes(&bytes) != response.receipt.response_digest
        {
            return Err(ChargebeeProviderError::ResponseTampered);
        }
        let expected_http = request.http_request();
        if http_request != &expected_http
            || http_request.method != "GET"
            || http_request.query_digest != request.query.query_digest
        {
            return Err(ChargebeeProviderError::ResponseTampered);
        }
        Self::validate_body_bindings(request, &body)
    }

    fn validate_body_bindings(
        request: &ChargebeeReadRequest,
        body: &ChargebeeResponseBody,
    ) -> Result<(), ChargebeeProviderError> {
        match body {
            ChargebeeResponseBody::Subscription(value) => {
                validate_subscription(&request.bindings, value)?;
                if value.revision != request.bindings.subscription_revision {
                    return Err(ChargebeeProviderError::StaleRevision);
                }
                if value.plan_id.digest() != request.bindings.plan_digest {
                    return Err(ChargebeeProviderError::ScopeMismatch);
                }
            }
            ChargebeeResponseBody::Entitlements(values) => {
                for value in values {
                    validate_entitlement(&request.bindings, value)?;
                    if value.revision != request.bindings.entitlement_revision {
                        return Err(ChargebeeProviderError::StaleRevision);
                    }
                }
            }
            ChargebeeResponseBody::Invoices(values) => {
                for value in values {
                    validate_invoice(&request.bindings, value)?;
                    if value.revision != request.bindings.invoice_revision {
                        return Err(ChargebeeProviderError::StaleRevision);
                    }
                }
            }
            ChargebeeResponseBody::Usage(_) => {}
        }
        Ok(())
    }

    fn check_page_order(
        &mut self,
        request: &ChargebeeReadRequest,
        body: &ChargebeeResponseBody,
        has_more: bool,
    ) -> Result<crate::PageProgress, ChargebeeProviderError> {
        let keys = body_key_set(body).map_err(|error| match error {
            ChargebeeModelError::DuplicateIdentifier => ChargebeeProviderError::DuplicateIdentifier,
            other => ChargebeeProviderError::Model(other),
        })?;
        if matches!(
            request.operation,
            ChargebeeReadOperation::Subscription | ChargebeeReadOperation::Usage
        ) && has_more
        {
            return Err(ChargebeeProviderError::PaginationDrift);
        }
        let state = self
            .pages
            .entry(request.query.query_digest.clone())
            .or_insert(PageState {
                pages_seen: 0,
                keys: BTreeSet::new(),
                last_key: None,
                last_key_digest: None,
            });
        if state.pages_seen >= MAX_PAGES {
            return Err(ChargebeeProviderError::PaginationDrift);
        }
        if let Some(cursor) = &request.cursor {
            cursor
                .validate_for(
                    &request.bindings.scope_digest,
                    &request.query.query_digest,
                    &request.registration_digest,
                )
                .map_err(|_| ChargebeeProviderError::CursorMismatch)?;
            if cursor.page != state.pages_seen.saturating_add(1)
                || cursor.offset != request.offset
                || cursor.last_key_digest != state.last_key_digest
            {
                return Err(ChargebeeProviderError::PaginationDrift);
            }
        } else if request.offset != 0 || state.pages_seen != 0 {
            return Err(ChargebeeProviderError::PaginationDrift);
        }
        if keys.iter().any(|key| state.keys.contains(key)) {
            return Err(ChargebeeProviderError::DuplicateIdentifier);
        }
        let mut sorted_keys = keys.into_iter().collect::<Vec<_>>();
        sorted_keys.sort();
        if let (Some(previous), Some(first)) = (state.last_key.as_ref(), sorted_keys.first())
            && first <= previous
        {
            return Err(ChargebeeProviderError::PaginationDrift);
        }
        let last_key = sorted_keys.last().cloned();
        let last_key_digest = last_key.as_ref().map(Digest::from_text);
        let progress = crate::PageProgress {
            page: state.pages_seen,
            next_offset: request.offset.saturating_add(body.len() as u32),
            last_key_digest: last_key_digest.clone(),
        };
        state.pages_seen = state.pages_seen.saturating_add(1);
        state.keys.extend(sorted_keys);
        state.last_key = last_key;
        state.last_key_digest = last_key_digest;
        Ok(progress)
    }
}

fn validate_binding_prefix(
    bindings: &ChargebeeScopeBindings,
    site_id: &crate::SiteId,
    customer_id: &crate::CustomerId,
    subscription_id: &crate::SubscriptionId,
) -> Result<(), ChargebeeProviderError> {
    if site_id.digest() != bindings.site_digest
        || customer_id.digest() != &bindings.customer_digest
        || subscription_id.digest() != bindings.subscription_digest
    {
        Err(ChargebeeProviderError::ScopeMismatch)
    } else {
        Ok(())
    }
}

fn validate_subscription(
    bindings: &ChargebeeScopeBindings,
    value: &SubscriptionObservation,
) -> Result<(), ChargebeeProviderError> {
    validate_binding_prefix(bindings, &value.site_id, &value.customer_id, &value.id)?;
    Ok(())
}

fn validate_entitlement(
    bindings: &ChargebeeScopeBindings,
    value: &EntitlementObservation,
) -> Result<(), ChargebeeProviderError> {
    validate_binding_prefix(
        bindings,
        &value.site_id,
        &value.customer_id,
        &value.subscription_id,
    )?;
    if value.plan_id.digest() != bindings.plan_digest
        || value.id.digest() != bindings.entitlement_digest
    {
        return Err(ChargebeeProviderError::ScopeMismatch);
    }
    Ok(())
}

fn validate_invoice(
    bindings: &ChargebeeScopeBindings,
    value: &InvoiceObservation,
) -> Result<(), ChargebeeProviderError> {
    validate_binding_prefix(
        bindings,
        &value.site_id,
        &value.customer_id,
        &value.subscription_id,
    )?;
    if value.id.digest() != bindings.invoice_digest {
        return Err(ChargebeeProviderError::ScopeMismatch);
    }
    Ok(())
}

/// BLOCKED_ENV probe is always explicitly blocked and non-native.
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
    NativeProbe {
        status: NativeProbeStatus::BlockedEnv,
        native_connected_claim: false,
        first_party_evidence_claim: false,
    }
}

impl<T> ChargebeeProvider<T> {
    pub fn provider_identity(&self) -> (&str, &str, &str) {
        (
            self.definition.id.as_str(),
            self.definition.implementation.as_str(),
            self.definition.revision.as_str(),
        )
    }

    pub fn retry_after_seconds(&self, error: &ChargebeeProviderError) -> Option<u64> {
        match error {
            ChargebeeProviderError::RateLimited {
                retry_after_seconds,
            } => Some(*retry_after_seconds),
            ChargebeeProviderError::Transport(ChargebeeTransportError::RateLimited {
                retry_after_seconds,
            }) => Some(*retry_after_seconds),
            _ => None,
        }
    }
}

/// Marker showing all service methods are external-write-free.
pub const fn provider_has_mutation_authority() -> bool {
    false
}
