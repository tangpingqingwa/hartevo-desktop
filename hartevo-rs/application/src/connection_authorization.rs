use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    AccountId, Connection, ConnectionId, ConnectionStatus, ProjectId, TenantId,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

const CALLBACK_HOST: &str = "connection";
const CALLBACK_PATH: &str = "/callback";
const CALLBACK_SCHEME: &str = "hartevo";
const CANONICAL_REDIRECT_URI: &str = "hartevo://connection/callback";

/// Provider-neutral authorization input. State, nonce, and callback code are
/// short-lived handshake material and are never serialized into a projection
/// or included in Debug output.
#[derive(Eq, PartialEq)]
pub struct ConnectionAuthorizationRequest {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub provider: String,
    pub required_scopes: BTreeSet<String>,
    pub redirect_uri: String,
    state: Zeroizing<String>,
    nonce: Zeroizing<String>,
}

impl fmt::Debug for ConnectionAuthorizationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionAuthorizationRequest")
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("provider", &self.provider)
            .field("required_scopes", &self.required_scopes)
            .field("redirect_uri", &self.redirect_uri)
            .field("state", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}

impl ConnectionAuthorizationRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        provider: impl Into<String>,
        required_scopes: impl IntoIterator<Item = String>,
        redirect_uri: impl Into<String>,
        state: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Result<Self, ConnectionAuthorizationError> {
        let provider = provider.into().trim().to_owned();
        let redirect_uri = redirect_uri.into().trim().to_owned();
        let state = Zeroizing::new(state.into());
        let nonce = Zeroizing::new(nonce.into());
        let required_scopes = normalize_scopes(required_scopes);
        if tenant_id.as_str().trim().is_empty()
            || project_id.as_str().trim().is_empty()
            || !is_handshake_value(&provider)
            || required_scopes.is_empty()
            || !is_handshake_value(&state)
            || !is_handshake_value(&nonce)
        {
            return Err(ConnectionAuthorizationError::InvalidRequest);
        }
        if redirect_uri != CANONICAL_REDIRECT_URI {
            return Err(ConnectionAuthorizationError::InvalidRedirectUri);
        }
        Ok(Self {
            tenant_id,
            project_id,
            provider,
            required_scopes,
            redirect_uri,
            state,
            nonce,
        })
    }

    /// Explicit handoff for a Connector adapter. Callers must not persist or
    /// log this value; the request's Debug implementation remains redacted.
    pub fn state_for_connector(&self) -> &str {
        self.state.as_str()
    }

    /// Explicit handoff for a Connector adapter. Callers must not persist or
    /// log this value; the request's Debug implementation remains redacted.
    pub fn nonce_for_connector(&self) -> &str {
        self.nonce.as_str()
    }
}

/// A callback code may be handed to a Connector adapter, but it cannot be
/// rendered, logged, or persisted by this lifecycle type.
#[derive(Eq, PartialEq)]
pub struct ConnectionAuthorizationCode(Zeroizing<String>);

impl ConnectionAuthorizationCode {
    pub fn expose_for_connector(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for ConnectionAuthorizationCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionAuthorizationCode([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionAuthorizationErrorCode {
    InvalidRequest,
    InvalidRedirectUri,
    CallbackNotExpected,
    InvalidCallback,
    CrossProjectCallback,
    ProviderMismatch,
    StateMismatch,
    NonceMismatch,
    ProviderRejected,
    InvalidAccount,
    AccountMismatch,
    AuthorizationCodeUnavailable,
    Revoked,
    InvalidConnectionProjection,
    TimestampRegression,
    RevisionOverflow,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ConnectionAuthorizationError {
    #[error("connection authorization request is incomplete or invalid")]
    InvalidRequest,
    #[error("connection authorization redirect URI is not the canonical desktop callback")]
    InvalidRedirectUri,
    #[error("connection authorization callback is not expected in the current lifecycle state")]
    CallbackNotExpected,
    #[error("connection authorization callback is malformed")]
    InvalidCallback,
    #[error("connection authorization callback attempted to cross project scope")]
    CrossProjectCallback,
    #[error("connection authorization callback provider does not match the requested provider")]
    ProviderMismatch,
    #[error("connection authorization callback state does not match the pending request")]
    StateMismatch,
    #[error("connection authorization callback nonce does not match the pending request")]
    NonceMismatch,
    #[error("provider rejected the authorization request")]
    ProviderRejected,
    #[error("account selection is required before probing the connection")]
    InvalidAccount,
    #[error("selected account does not match the callback account hint")]
    AccountMismatch,
    #[error("the authorization code is no longer available to the Connector adapter")]
    AuthorizationCodeUnavailable,
    #[error("the connection authorization session was revoked")]
    Revoked,
    #[error("the Connection projection is not backed by a live Probe")]
    InvalidConnectionProjection,
    #[error("connection authorization lifecycle time moved backwards")]
    TimestampRegression,
    #[error("connection authorization lifecycle revision overflowed")]
    RevisionOverflow,
}

impl ConnectionAuthorizationError {
    pub const fn code(self) -> ConnectionAuthorizationErrorCode {
        match self {
            Self::InvalidRequest => ConnectionAuthorizationErrorCode::InvalidRequest,
            Self::InvalidRedirectUri => ConnectionAuthorizationErrorCode::InvalidRedirectUri,
            Self::CallbackNotExpected => ConnectionAuthorizationErrorCode::CallbackNotExpected,
            Self::InvalidCallback => ConnectionAuthorizationErrorCode::InvalidCallback,
            Self::CrossProjectCallback => ConnectionAuthorizationErrorCode::CrossProjectCallback,
            Self::ProviderMismatch => ConnectionAuthorizationErrorCode::ProviderMismatch,
            Self::StateMismatch => ConnectionAuthorizationErrorCode::StateMismatch,
            Self::NonceMismatch => ConnectionAuthorizationErrorCode::NonceMismatch,
            Self::ProviderRejected => ConnectionAuthorizationErrorCode::ProviderRejected,
            Self::InvalidAccount => ConnectionAuthorizationErrorCode::InvalidAccount,
            Self::AccountMismatch => ConnectionAuthorizationErrorCode::AccountMismatch,
            Self::AuthorizationCodeUnavailable => {
                ConnectionAuthorizationErrorCode::AuthorizationCodeUnavailable
            }
            Self::Revoked => ConnectionAuthorizationErrorCode::Revoked,
            Self::InvalidConnectionProjection => {
                ConnectionAuthorizationErrorCode::InvalidConnectionProjection
            }
            Self::TimestampRegression => ConnectionAuthorizationErrorCode::TimestampRegression,
            Self::RevisionOverflow => ConnectionAuthorizationErrorCode::RevisionOverflow,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionAuthorizationState {
    AwaitingCallback,
    AccountSelectionRequired {
        account_hint: Option<String>,
    },
    ProbeRequired {
        account_id: AccountId,
    },
    Verified {
        connection_id: ConnectionId,
        verified_at: DateTime<Utc>,
    },
    Error(ConnectionAuthorizationErrorCode),
    Revoked,
}

/// In-memory authorization/callback state. The domain Connection projection,
/// not this handshake state, remains the authority for Connected.
#[derive(Eq, PartialEq)]
pub struct ConnectionAuthorizationSession {
    tenant_id: TenantId,
    project_id: ProjectId,
    provider: String,
    required_scopes: BTreeSet<String>,
    redirect_uri: String,
    state_digest: String,
    nonce_digest: String,
    state: ConnectionAuthorizationState,
    account_hint: Option<String>,
    pending_code: Option<ConnectionAuthorizationCode>,
    revision: u64,
    started_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl fmt::Debug for ConnectionAuthorizationSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionAuthorizationSession")
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("provider", &self.provider)
            .field("required_scopes", &self.required_scopes)
            .field("redirect_uri", &self.redirect_uri)
            .field("state_digest", &"[REDACTED]")
            .field("nonce_digest", &"[REDACTED]")
            .field("state", &self.state)
            .field("account_hint", &self.account_hint)
            .field("has_pending_code", &self.pending_code.is_some())
            .field("revision", &self.revision)
            .field("started_at", &self.started_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl ConnectionAuthorizationSession {
    pub fn begin(
        request: ConnectionAuthorizationRequest,
        now: DateTime<Utc>,
    ) -> Result<Self, ConnectionAuthorizationError> {
        Ok(Self {
            tenant_id: request.tenant_id,
            project_id: request.project_id,
            provider: request.provider,
            required_scopes: request.required_scopes,
            redirect_uri: request.redirect_uri,
            state_digest: digest(request.state.as_bytes()),
            nonce_digest: digest(request.nonce.as_bytes()),
            state: ConnectionAuthorizationState::AwaitingCallback,
            account_hint: None,
            pending_code: None,
            revision: 1,
            started_at: now,
            updated_at: now,
        })
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn required_scopes(&self) -> &BTreeSet<String> {
        &self.required_scopes
    }

    pub fn state(&self) -> &ConnectionAuthorizationState {
        &self.state
    }

    pub fn account_hint(&self) -> Option<&str> {
        self.account_hint.as_deref()
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Consumes a canonical desktop callback without retaining its raw URL.
    /// The code remains only as zeroizing handshake memory until the Connector
    /// adapter takes it for token exchange.
    pub fn handle_deep_link(
        &mut self,
        raw_uri: &str,
        now: DateTime<Utc>,
    ) -> Result<(), ConnectionAuthorizationError> {
        if self.state == ConnectionAuthorizationState::Revoked {
            return Err(ConnectionAuthorizationError::Revoked);
        }
        if self.state != ConnectionAuthorizationState::AwaitingCallback {
            return Err(ConnectionAuthorizationError::CallbackNotExpected);
        }
        let callback = match parse_callback(raw_uri) {
            Ok(callback) => callback,
            Err(error) => return self.reject(error, now),
        };
        if callback.provider != self.provider {
            return self.reject(ConnectionAuthorizationError::ProviderMismatch, now);
        }
        if digest(callback.state.as_bytes()) != self.state_digest {
            return self.reject(ConnectionAuthorizationError::StateMismatch, now);
        }
        let Some(nonce) = callback.nonce.as_ref() else {
            return self.reject(ConnectionAuthorizationError::NonceMismatch, now);
        };
        if digest(nonce.as_bytes()) != self.nonce_digest {
            return self.reject(ConnectionAuthorizationError::NonceMismatch, now);
        }
        if callback.provider_error {
            return self.reject(ConnectionAuthorizationError::ProviderRejected, now);
        }
        let Some(code) = callback.code else {
            return self.reject(ConnectionAuthorizationError::InvalidCallback, now);
        };
        let next_revision = self.prepare_touch(now)?;
        self.account_hint = callback.account_hint;
        self.pending_code = Some(ConnectionAuthorizationCode(code));
        self.state = ConnectionAuthorizationState::AccountSelectionRequired {
            account_hint: self.account_hint.clone(),
        };
        self.commit_touch(next_revision, now);
        Ok(())
    }

    pub fn select_account(
        &mut self,
        account_id: AccountId,
        now: DateTime<Utc>,
    ) -> Result<(), ConnectionAuthorizationError> {
        if self.state == ConnectionAuthorizationState::Revoked {
            return Err(ConnectionAuthorizationError::Revoked);
        }
        if !matches!(
            self.state,
            ConnectionAuthorizationState::AccountSelectionRequired { .. }
        ) {
            return Err(ConnectionAuthorizationError::InvalidAccount);
        }
        if account_id.as_str().trim().is_empty() {
            return self.reject(ConnectionAuthorizationError::InvalidAccount, now);
        }
        if self
            .account_hint
            .as_deref()
            .is_some_and(|hint| hint != account_id.as_str())
        {
            return self.reject(ConnectionAuthorizationError::AccountMismatch, now);
        }
        let next_revision = self.prepare_touch(now)?;
        self.state = ConnectionAuthorizationState::ProbeRequired { account_id };
        self.commit_touch(next_revision, now);
        Ok(())
    }

    pub fn take_authorization_code(
        &mut self,
    ) -> Result<ConnectionAuthorizationCode, ConnectionAuthorizationError> {
        if !matches!(
            self.state,
            ConnectionAuthorizationState::ProbeRequired { .. }
        ) {
            return Err(ConnectionAuthorizationError::AuthorizationCodeUnavailable);
        }
        self.pending_code
            .take()
            .ok_or(ConnectionAuthorizationError::AuthorizationCodeUnavailable)
    }

    /// Applies an existing domain Connection to the handshake. A Connected
    /// result is accepted only when this reducer can verify the Probe's
    /// evidence, timestamps, account, project, provider, and scopes itself.
    pub fn observe_connection_projection(
        &mut self,
        connection: &Connection,
        now: DateTime<Utc>,
    ) -> Result<ConnectionAuthorizationState, ConnectionAuthorizationError> {
        if self.state == ConnectionAuthorizationState::Revoked {
            return Err(ConnectionAuthorizationError::Revoked);
        }
        let ConnectionAuthorizationState::ProbeRequired { account_id } = &self.state else {
            return Err(ConnectionAuthorizationError::CallbackNotExpected);
        };
        let status = connection.effective_status(now);
        let scope_matches = connection.tenant_id() == &self.tenant_id
            && connection.project_id() == &self.project_id
            && connection.provider() == self.provider
            && connection.account_id() == account_id;
        if !scope_matches
            || (status == ConnectionStatus::Connected
                && !connection.permits_scopes(&self.required_scopes, now))
        {
            return self
                .reject(
                    ConnectionAuthorizationError::InvalidConnectionProjection,
                    now,
                )
                .map(|()| self.state.clone());
        }
        let live_probe = status == ConnectionStatus::Connected
            && connection.last_probe().is_some_and(|probe| {
                probe.probed_at <= now
                    && probe.valid_until > now
                    && probe.credential_expires_at > now
                    && is_sha256_digest(&probe.evidence_digest)
            });
        if status == ConnectionStatus::Connected && !live_probe {
            return self
                .reject(
                    ConnectionAuthorizationError::InvalidConnectionProjection,
                    now,
                )
                .map(|()| self.state.clone());
        }
        if status == ConnectionStatus::Connected {
            let next_revision = self.prepare_touch(now)?;
            self.state = ConnectionAuthorizationState::Verified {
                connection_id: connection.id().clone(),
                verified_at: now,
            };
            self.commit_touch(next_revision, now);
        } else if status == ConnectionStatus::Revoked {
            let next_revision = self.prepare_touch(now)?;
            self.pending_code = None;
            self.state = ConnectionAuthorizationState::Revoked;
            self.commit_touch(next_revision, now);
        }
        Ok(self.state.clone())
    }

    pub fn revoke(&mut self, now: DateTime<Utc>) -> Result<(), ConnectionAuthorizationError> {
        if self.state == ConnectionAuthorizationState::Revoked {
            return Ok(());
        }
        let next_revision = self.prepare_touch(now)?;
        self.pending_code = None;
        self.account_hint = None;
        self.state = ConnectionAuthorizationState::Revoked;
        self.commit_touch(next_revision, now);
        Ok(())
    }

    /// A restart deliberately forgets callback material and returns to the
    /// callback boundary. Existing Connection projections are reloaded by the
    /// caller; this state machine never carries Connected across a restart.
    pub fn restart(&mut self, now: DateTime<Utc>) -> Result<(), ConnectionAuthorizationError> {
        let next_revision = self.prepare_touch(now)?;
        self.pending_code = None;
        self.account_hint = None;
        self.state = ConnectionAuthorizationState::AwaitingCallback;
        self.commit_touch(next_revision, now);
        Ok(())
    }

    fn reject(
        &mut self,
        error: ConnectionAuthorizationError,
        now: DateTime<Utc>,
    ) -> Result<(), ConnectionAuthorizationError> {
        let code = error.code();
        let next_revision = self.prepare_touch(now)?;
        self.pending_code = None;
        self.state = ConnectionAuthorizationState::Error(code);
        self.commit_touch(next_revision, now);
        Err(error)
    }

    fn prepare_touch(&self, now: DateTime<Utc>) -> Result<u64, ConnectionAuthorizationError> {
        if now < self.updated_at {
            return Err(ConnectionAuthorizationError::TimestampRegression);
        }
        self.revision
            .checked_add(1)
            .ok_or(ConnectionAuthorizationError::RevisionOverflow)
    }

    fn commit_touch(&mut self, revision: u64, now: DateTime<Utc>) {
        self.revision = revision;
        self.updated_at = now;
    }
}

struct ParsedCallback {
    provider: String,
    state: Zeroizing<String>,
    nonce: Option<Zeroizing<String>>,
    code: Option<Zeroizing<String>>,
    account_hint: Option<String>,
    provider_error: bool,
}

fn parse_callback(raw_uri: &str) -> Result<ParsedCallback, ConnectionAuthorizationError> {
    let parsed = Url::parse(raw_uri).map_err(|_| ConnectionAuthorizationError::InvalidCallback)?;
    if parsed.scheme() != CALLBACK_SCHEME
        || parsed.host_str() != Some(CALLBACK_HOST)
        || parsed.path() != CALLBACK_PATH
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConnectionAuthorizationError::InvalidCallback);
    }
    let mut provider = None;
    let mut state = None;
    let mut nonce = None;
    let mut code = None;
    let mut account_hint = None;
    let mut provider_error = false;
    let mut seen_singletons = BTreeSet::new();
    for (key, value) in parsed.query_pairs() {
        let key = key.into_owned();
        if matches!(
            key.as_str(),
            "provider" | "state" | "nonce" | "code" | "account" | "error"
        ) && !seen_singletons.insert(key.clone())
        {
            return Err(ConnectionAuthorizationError::InvalidCallback);
        }
        match key.as_str() {
            "provider" => provider = Some(value.into_owned()),
            "state" => state = Some(Zeroizing::new(value.into_owned())),
            "nonce" => nonce = Some(Zeroizing::new(value.into_owned())),
            "code" => code = Some(Zeroizing::new(value.into_owned())),
            "account" => account_hint = Some(value.into_owned()),
            "error" => provider_error = !value.trim().is_empty(),
            // Tenant and project are session-bound, never callback-selected.
            "tenant" | "project" | "connection_id" => {
                return Err(ConnectionAuthorizationError::CrossProjectCallback);
            }
            _ => {}
        }
    }
    let provider = provider
        .filter(|value| is_handshake_value(value))
        .ok_or(ConnectionAuthorizationError::InvalidCallback)?;
    let state = state
        .filter(|value| is_handshake_value(value))
        .ok_or(ConnectionAuthorizationError::InvalidCallback)?;
    if provider_error && code.is_some() {
        return Err(ConnectionAuthorizationError::InvalidCallback);
    }
    if !provider_error && code.as_ref().is_none_or(|value| !is_handshake_value(value)) {
        return Err(ConnectionAuthorizationError::InvalidCallback);
    }
    let account_hint = account_hint
        .map(|value| value.trim().to_owned())
        .map(|value| {
            if is_handshake_value(&value) {
                Ok(value)
            } else {
                Err(ConnectionAuthorizationError::InvalidCallback)
            }
        })
        .transpose()?;
    Ok(ParsedCallback {
        provider,
        state,
        nonce,
        code,
        account_hint,
        provider_error,
    })
}

fn normalize_scopes(values: impl IntoIterator<Item = String>) -> BTreeSet<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

fn is_handshake_value(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 512
        && !trimmed
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
}

fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 9, 0, 0)
            .single()
            .expect("valid test time")
    }

    fn request() -> ConnectionAuthorizationRequest {
        ConnectionAuthorizationRequest::new(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "provider-neutral",
            ["read.accounts".into(), "write.content".into()],
            CANONICAL_REDIRECT_URI,
            "state-secret",
            "nonce-secret",
        )
        .expect("request")
    }

    fn session() -> ConnectionAuthorizationSession {
        ConnectionAuthorizationSession::begin(request(), now()).expect("session")
    }

    fn callback(extra: &str) -> String {
        format!(
            "{CANONICAL_REDIRECT_URI}?provider=provider-neutral&state=state-secret&nonce=nonce-secret&code=authorization-code-secret&{extra}"
        )
    }

    fn connected_connection(project_id: &str, account_id: &str) -> Connection {
        let probe_at = now() + Duration::seconds(1);
        let mut connection = Connection::register(
            ConnectionId::from("connection-1"),
            TenantId::from("tenant-1"),
            ProjectId::from(project_id),
            "provider-neutral",
            AccountId::from(account_id),
            "external-account-1",
            ["read.accounts".into(), "write.content".into()],
            now(),
        )
        .expect("connection");
        connection.begin_probe(probe_at).expect("begin probe");
        connection
            .apply_probe(
                hartevo_domain_kernel::ConnectionProbe {
                    outcome: hartevo_domain_kernel::ProbeOutcome::Successful,
                    observed_external_account_id: "external-account-1".into(),
                    granted_scopes: BTreeSet::from([
                        "read.accounts".into(),
                        "write.content".into(),
                    ]),
                    probed_at: probe_at,
                    valid_until: probe_at + Duration::minutes(10),
                    credential_expires_at: probe_at + Duration::hours(1),
                    evidence_digest: "a".repeat(64),
                },
                probe_at + Duration::seconds(1),
            )
            .expect("apply probe");
        connection
    }

    #[test]
    fn callback_state_is_project_bound_and_debug_redacts_handshake_material() {
        let mut session = session();
        session
            .handle_deep_link(&callback("account=account-1"), now() + Duration::seconds(1))
            .expect("callback");
        let debug = format!("{session:?}");
        assert!(!debug.contains("state-secret"));
        assert!(!debug.contains("nonce-secret"));
        assert!(!debug.contains("authorization-code-secret"));
        assert!(debug.contains("has_pending_code: true"));
        assert_eq!(session.account_hint(), Some("account-1"));

        session
            .select_account(AccountId::from("account-1"), now() + Duration::seconds(2))
            .expect("account");
        let code = session.take_authorization_code().expect("connector code");
        assert_eq!(code.expose_for_connector(), "authorization-code-secret");
        assert!(!format!("{code:?}").contains("authorization-code-secret"));
    }

    #[test]
    fn project_override_and_state_mismatch_fail_closed_then_restart() {
        let mut session = session();
        let error = session
            .handle_deep_link(
                &format!(
                    "{CANONICAL_REDIRECT_URI}?provider=provider-neutral&state=state-secret&code=code&project=project-2"
                ),
                now() + Duration::seconds(1),
            )
            .expect_err("cross-project callback");
        assert_eq!(error, ConnectionAuthorizationError::CrossProjectCallback);
        assert_eq!(
            session.state(),
            &ConnectionAuthorizationState::Error(
                ConnectionAuthorizationErrorCode::CrossProjectCallback
            )
        );
        session
            .restart(now() + Duration::seconds(2))
            .expect("restart");
        assert_eq!(
            session.state(),
            &ConnectionAuthorizationState::AwaitingCallback
        );

        let error = session
            .handle_deep_link(
                &format!(
                    "{CANONICAL_REDIRECT_URI}?provider=provider-neutral&state=wrong-state&code=code"
                ),
                now() + Duration::seconds(3),
            )
            .expect_err("state mismatch");
        assert_eq!(error, ConnectionAuthorizationError::StateMismatch);
        assert_eq!(
            session.state(),
            &ConnectionAuthorizationState::Error(ConnectionAuthorizationErrorCode::StateMismatch)
        );
    }

    #[test]
    fn nonce_mismatch_and_duplicate_callback_fields_fail_closed() {
        let mut session = session();
        let error = session
            .handle_deep_link(
                &format!(
                    "{CANONICAL_REDIRECT_URI}?provider=provider-neutral&state=state-secret&nonce=wrong-nonce&code=code"
                ),
                now() + Duration::seconds(1),
            )
            .expect_err("nonce mismatch");
        assert_eq!(error, ConnectionAuthorizationError::NonceMismatch);

        session
            .restart(now() + Duration::seconds(2))
            .expect("restart");
        let error = session
            .handle_deep_link(
                &format!(
                    "{CANONICAL_REDIRECT_URI}?provider=provider-neutral&state=state-secret&code=code"
                ),
                now() + Duration::seconds(3),
            )
            .expect_err("missing nonce");
        assert_eq!(error, ConnectionAuthorizationError::NonceMismatch);

        session
            .restart(now() + Duration::seconds(4))
            .expect("restart after missing nonce");
        let error = session
            .handle_deep_link(
                &format!(
                    "{CANONICAL_REDIRECT_URI}?provider=provider-neutral&provider=provider-neutral&state=state-secret&code=code"
                ),
                now() + Duration::seconds(5),
            )
            .expect_err("duplicate provider");
        assert_eq!(error, ConnectionAuthorizationError::InvalidCallback);
    }

    #[test]
    fn provider_error_is_typed_without_retaining_error_description() {
        let mut session = session();
        let error = session
            .handle_deep_link(
                &format!(
                    "{CANONICAL_REDIRECT_URI}?provider=provider-neutral&state=state-secret&nonce=nonce-secret&error=access_denied&error_description=token-secret"
                ),
                now() + Duration::seconds(1),
            )
            .expect_err("provider rejection");
        assert_eq!(error, ConnectionAuthorizationError::ProviderRejected);
        assert_eq!(
            session.state(),
            &ConnectionAuthorizationState::Error(
                ConnectionAuthorizationErrorCode::ProviderRejected
            )
        );
        assert!(!format!("{session:?}").contains("token-secret"));
        assert!(!error.to_string().contains("token-secret"));
    }

    #[test]
    fn restart_and_revoke_clear_authorization_material() {
        let mut session = session();
        session
            .handle_deep_link(&callback("account=account-1"), now() + Duration::seconds(1))
            .expect("callback");
        session
            .revoke(now() + Duration::seconds(2))
            .expect("revoke");
        assert_eq!(session.state(), &ConnectionAuthorizationState::Revoked);
        assert_eq!(
            session.take_authorization_code(),
            Err(ConnectionAuthorizationError::AuthorizationCodeUnavailable)
        );
        assert_eq!(
            session.handle_deep_link(&callback("account=account-1"), now() + Duration::seconds(3)),
            Err(ConnectionAuthorizationError::Revoked)
        );

        session
            .restart(now() + Duration::seconds(4))
            .expect("explicit reauthorization restart");
        assert_eq!(
            session.state(),
            &ConnectionAuthorizationState::AwaitingCallback
        );
    }

    #[test]
    fn timestamp_regression_does_not_partially_mutate_the_session() {
        let mut session = session();
        session
            .handle_deep_link(&callback("account=account-1"), now() + Duration::seconds(1))
            .expect("callback");
        let error = session
            .select_account(AccountId::from("account-1"), now())
            .expect_err("timestamp regression");
        assert_eq!(error, ConnectionAuthorizationError::TimestampRegression);
        assert!(matches!(
            session.state(),
            ConnectionAuthorizationState::AccountSelectionRequired {
                account_hint: Some(hint)
            } if hint == "account-1"
        ));
        session
            .select_account(AccountId::from("account-1"), now() + Duration::seconds(2))
            .expect("retry after clock catches up");
    }

    #[test]
    fn verified_state_requires_a_live_probe() {
        let mut stale_session = session();
        stale_session
            .handle_deep_link(&callback("account=account-1"), now() + Duration::seconds(1))
            .expect("callback");
        stale_session
            .select_account(AccountId::from("account-1"), now() + Duration::seconds(2))
            .expect("account");
        let stale_state = stale_session
            .observe_connection_projection(
                &connected_connection("project-1", "account-1"),
                now() + Duration::hours(2),
            )
            .expect("expired probe remains unverified");
        assert!(matches!(
            stale_state,
            ConnectionAuthorizationState::ProbeRequired { .. }
        ));

        let mut session = session();
        session
            .handle_deep_link(&callback("account=account-1"), now() + Duration::seconds(5))
            .expect("callback again");
        session
            .select_account(AccountId::from("account-1"), now() + Duration::seconds(6))
            .expect("account again");
        let state = session
            .observe_connection_projection(
                &connected_connection("project-1", "account-1"),
                now() + Duration::seconds(7),
            )
            .expect("live probe");
        assert!(matches!(
            state,
            ConnectionAuthorizationState::Verified { .. }
        ));
    }

    #[test]
    fn verified_state_rejects_a_cross_project_or_account_projection() {
        let mut session = session();
        session
            .handle_deep_link(&callback("account=account-1"), now() + Duration::seconds(1))
            .expect("callback");
        session
            .select_account(AccountId::from("account-1"), now() + Duration::seconds(2))
            .expect("account");
        let error = session
            .observe_connection_projection(
                &connected_connection("project-2", "account-1"),
                now() + Duration::seconds(3),
            )
            .expect_err("cross-project projection");
        assert_eq!(
            error,
            ConnectionAuthorizationError::InvalidConnectionProjection
        );
        assert_eq!(
            session.state(),
            &ConnectionAuthorizationState::Error(
                ConnectionAuthorizationErrorCode::InvalidConnectionProjection
            )
        );
    }
}
