//! Controlled provider port for Calendly Layer-1 reads.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CalendlySchedulingResultError, Digest, MAX_RESPONSE_BYTES,
    model::{
        CalendlyPage, CalendlyScope, PageCursor, PermissionLease, ProviderLifecycle, ProviderMode,
        ProviderProvenance, ProviderState, SecretReference,
    },
    provider_digest,
};

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "details")]
pub enum ProviderError {
    #[error("provider is revoked")]
    ProviderRevoked,
    #[error("native Calendly access is blocked in Layer 1")]
    BlockedEnvironment,
    #[error("provider returned HTTP 401 unauthorized")]
    Unauthorized,
    #[error("provider returned HTTP 403 forbidden")]
    Forbidden,
    #[error("provider returned HTTP 404 not found")]
    NotFound,
    #[error("provider returned HTTP 409 conflict")]
    Conflict,
    #[error("provider returned HTTP 429 rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("provider returned HTTP {status}")]
    Server { status: u16 },
    #[error("provider request timed out")]
    Timeout,
    #[error("provider permission scope or lease was lost")]
    PermissionScopeLost,
    #[error("provider permission lease expired")]
    PermissionLeaseExpired,
    #[error("provider cursor expired")]
    CursorExpired,
    #[error("provider revision drifted")]
    ProviderRevisionDrift,
    #[error("provider response was malformed")]
    MalformedResponse,
}

impl ProviderError {
    pub const fn from_http_status(status: u16) -> Self {
        match status {
            401 => Self::Unauthorized,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            409 => Self::Conflict,
            429 => Self::RateLimited {
                retry_after_seconds: None,
            },
            500..=599 => Self::Server { status },
            _ => Self::MalformedResponse,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::Server { status } => Some(*status),
            Self::ProviderRevoked
            | Self::BlockedEnvironment
            | Self::Timeout
            | Self::PermissionScopeLost
            | Self::PermissionLeaseExpired
            | Self::CursorExpired
            | Self::ProviderRevisionDrift
            | Self::MalformedResponse => None,
        }
    }
}

/// A provider request contains only opaque references and bounded metadata
/// parameters. It has no access-token or raw HTTP-body field.
#[derive(Clone, Debug)]
pub struct ProviderRequest<'a> {
    scope: &'a CalendlyScope,
    secret_reference: &'a SecretReference,
    permission_lease: &'a PermissionLease,
    cursor: Option<&'a PageCursor>,
    page_size: u16,
    now_millis: u64,
}

impl<'a> ProviderRequest<'a> {
    pub fn new(
        scope: &'a CalendlyScope,
        secret_reference: &'a SecretReference,
        permission_lease: &'a PermissionLease,
        cursor: Option<&'a PageCursor>,
        page_size: u16,
        now_millis: u64,
    ) -> Result<Self, CalendlySchedulingResultError> {
        if page_size == 0 || now_millis == 0 {
            return Err(CalendlySchedulingResultError::InvalidScope);
        }
        Ok(Self {
            scope,
            secret_reference,
            permission_lease,
            cursor,
            page_size,
            now_millis,
        })
    }

    pub fn scope(&self) -> &CalendlyScope {
        self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        self.secret_reference
    }

    pub fn permission_lease(&self) -> &PermissionLease {
        self.permission_lease
    }

    pub fn cursor(&self) -> Option<&PageCursor> {
        self.cursor
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn now_millis(&self) -> u64 {
        self.now_millis
    }
}

/// Typed provider port used by `CalendlySchedulingResultService`.
pub trait CalendlyProviderPort: fmt::Debug {
    fn provider_revision(&self) -> u64;
    fn provider_digest(&self) -> &Digest;
    fn state(&self) -> ProviderState;
    fn read_page(&self, request: ProviderRequest<'_>) -> Result<CalendlyPage, ProviderError>;
    fn revoke(&mut self);
}

/// Controlled fixture/recording/loopback provider. There is intentionally no
/// HTTPS, OAuth, PAT, webhook-subscription, or booking implementation here.
#[derive(Clone, Debug)]
pub struct CalendlyProvider {
    state: ProviderState,
    provider_digest: Digest,
    pages: Vec<CalendlyPage>,
}

impl CalendlyProvider {
    pub fn new(
        mode: ProviderMode,
        pages: Vec<CalendlyPage>,
        provider_revision: u64,
    ) -> Result<Self, CalendlySchedulingResultError> {
        let provenance = match mode {
            ProviderMode::Fixture => ProviderProvenance::Fixture,
            ProviderMode::Recording => ProviderProvenance::ControlledRecording,
            ProviderMode::Loopback => ProviderProvenance::LoopbackRecording,
            ProviderMode::BlockedEnv => ProviderProvenance::BlockedEnvironment,
        };
        if mode != ProviderMode::BlockedEnv && pages.is_empty() {
            return Err(CalendlySchedulingResultError::InvalidScope);
        }
        if pages.len() > crate::MAX_PAGES as usize {
            return Err(CalendlySchedulingResultError::InvalidScope);
        }
        for page in &pages {
            if page.provider_revision() != provider_revision
                || page.response_size_bytes() > MAX_RESPONSE_BYTES
            {
                return Err(CalendlySchedulingResultError::MalformedProviderData);
            }
        }
        Ok(Self {
            state: ProviderState::new(mode, provenance, provider_revision)?,
            provider_digest: provider_digest()?,
            pages,
        })
    }

    pub fn fixture(
        pages: Vec<CalendlyPage>,
        provider_revision: u64,
    ) -> Result<Self, CalendlySchedulingResultError> {
        Self::new(ProviderMode::Fixture, pages, provider_revision)
    }

    pub fn recording(
        pages: Vec<CalendlyPage>,
        provider_revision: u64,
    ) -> Result<Self, CalendlySchedulingResultError> {
        Self::new(ProviderMode::Recording, pages, provider_revision)
    }

    pub fn loopback(
        pages: Vec<CalendlyPage>,
        provider_revision: u64,
    ) -> Result<Self, CalendlySchedulingResultError> {
        Self::new(ProviderMode::Loopback, pages, provider_revision)
    }

    pub fn blocked_env(provider_revision: u64) -> Result<Self, CalendlySchedulingResultError> {
        Self::new(ProviderMode::BlockedEnv, Vec::new(), provider_revision)
    }

    pub const fn mode(&self) -> ProviderMode {
        self.state.mode()
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.state.provenance()
    }

    pub const fn state(&self) -> ProviderState {
        self.state
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub const fn provider_revision(&self) -> u64 {
        self.state.provider_revision()
    }

    pub fn revoke(&mut self) {
        self.state.revoke();
    }
}

impl CalendlyProviderPort for CalendlyProvider {
    fn provider_revision(&self) -> u64 {
        self.provider_revision()
    }

    fn provider_digest(&self) -> &Digest {
        self.provider_digest()
    }

    fn state(&self) -> ProviderState {
        self.state()
    }

    fn read_page(&self, request: ProviderRequest<'_>) -> Result<CalendlyPage, ProviderError> {
        if self.state.lifecycle() == ProviderLifecycle::Revoked {
            return Err(ProviderError::ProviderRevoked);
        }
        if request.secret_reference().is_revoked()
            || request.secret_reference().scope_digest() != request.scope().scope_digest()
            || request.secret_reference().permission_digest()
                != request.permission_lease().permission_digest()
        {
            return Err(ProviderError::PermissionScopeLost);
        }
        if request
            .permission_lease()
            .is_expired_at(request.now_millis())
        {
            return Err(ProviderError::PermissionLeaseExpired);
        }
        if self.mode() == ProviderMode::BlockedEnv {
            return Err(ProviderError::BlockedEnvironment);
        }
        let page_index = match request.cursor() {
            None => 0,
            Some(cursor) => cursor
                .as_str()
                .strip_prefix("page-")
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or(ProviderError::CursorExpired)?,
        };
        let page = self
            .pages
            .get(page_index)
            .cloned()
            .ok_or(ProviderError::CursorExpired)?;
        if page.provider_revision() != self.provider_revision() {
            return Err(ProviderError::ProviderRevisionDrift);
        }
        if page.permission_digest() != request.permission_lease().permission_digest() {
            return Err(ProviderError::PermissionScopeLost);
        }
        Ok(page)
    }

    fn revoke(&mut self) {
        Self::revoke(self);
    }
}
