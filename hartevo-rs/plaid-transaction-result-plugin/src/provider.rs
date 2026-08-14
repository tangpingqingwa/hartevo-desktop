//! Plaid `/transactions/sync` transport, parsing, and non-native evidence modes.

use std::{collections::BTreeSet, fmt, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    PLAID_TRANSACTION_RESULT_PROVIDER_ID, digest_bytes, digest_serializable,
    model::{
        AmountBucket, BoundedTimestamp, CurrencyCode, Digest, EvidenceStatus, MAX_FAILURE_BYTES,
        MAX_PROVIDER_FIELD_BYTES, MAX_RESPONSE_BYTES, MAX_TRANSACTION_COUNT,
        PlaidTransactionResultError, PlaidTransactionsScope, SettlementState, TransactionState,
        TransactionSummary, TransactionSyncRequest, TransactionsUpdateStatus,
    },
};

pub const MAX_PAGINATION_MUTATION_RESTARTS: usize = 1;

/// Deterministic transport provenance. None of these modes are connected or
/// native; `BLOCKED_ENV` is an explicit environment capability result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedEnvCode {
    NativeCredentialResolution,
    LiveHttpsTransport,
    HostIntegration,
}

impl fmt::Display for BlockedEnvCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::NativeCredentialResolution => "native_credential_resolution",
            Self::LiveHttpsTransport => "live_https_transport",
            Self::HostIntegration => "host_integration",
        };
        formatter.write_str(value)
    }
}

/// Transport errors are classified without retaining a provider response body.
#[derive(Clone, Copy, Debug, Error, PartialEq)]
pub enum PlaidTransportError {
    #[error("transport timed out")]
    Timeout,
    #[error("transport unavailable")]
    Unavailable,
    #[error("BLOCKED_ENV: {code}")]
    BlockedEnv { code: BlockedEnvCode },
}

/// Redacted request record exposed by deterministic transports.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportRequestRecord {
    pub method: String,
    pub endpoint: String,
    pub api_version: String,
    pub cursor_digest: Digest,
    pub count: usize,
    pub account_filter_digest: Digest,
    pub body_digest: Digest,
    pub request_digest: Digest,
}

/// The official read-only transport request shape. Its cursor is kept only as
/// an ephemeral private field so a future native adapter could send it; all
/// observable accessors and Debug output are digest-only.
pub struct PlaidTransportRequest {
    method: &'static str,
    endpoint: &'static str,
    api_version: &'static str,
    cursor: crate::model::Cursor,
    count: usize,
    account_filter_digest: Digest,
    body_digest: Digest,
    request_digest: Digest,
}

impl PlaidTransportRequest {
    fn new(_scope: &PlaidTransactionsScope, request: &TransactionSyncRequest) -> Self {
        let account_filter_digest = request.account_filter().digest();
        let body_digest = digest_serializable(&(
            request.cursor_digest(),
            request.count(),
            &account_filter_digest,
        ));
        let request_digest = digest_serializable(&(
            PLAID_TRANSACTION_RESULT_PROVIDER_ID,
            PLAID_TRANSACTION_RESULT_API_VERSION,
            crate::model::DEFAULT_PLAID_SYNC_ENDPOINT,
            &body_digest,
        ));
        Self {
            method: "POST",
            endpoint: crate::model::DEFAULT_PLAID_SYNC_ENDPOINT,
            api_version: PLAID_TRANSACTION_RESULT_API_VERSION,
            cursor: request.cursor().clone(),
            count: request.count(),
            account_filter_digest,
            body_digest,
            request_digest,
        }
    }

    pub fn method(&self) -> &str {
        self.method
    }

    pub fn endpoint(&self) -> &str {
        self.endpoint
    }

    pub fn api_version(&self) -> &str {
        self.api_version
    }

    pub fn cursor_digest(&self) -> &Digest {
        self.cursor.digest()
    }

    pub const fn count(&self) -> usize {
        self.count
    }

    pub fn account_filter_digest(&self) -> &Digest {
        &self.account_filter_digest
    }

    pub fn body_digest(&self) -> &Digest {
        &self.body_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

impl fmt::Debug for PlaidTransportRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlaidTransportRequest")
            .field("method", &self.method)
            .field("endpoint", &self.endpoint)
            .field("api_version", &self.api_version)
            .field("cursor_digest", self.cursor.digest())
            .field("count", &self.count)
            .field("account_filter_digest", &self.account_filter_digest)
            .field("body_digest", &self.body_digest)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

/// Borrowed-host response frame. The body is consumed only long enough to
/// create redacted typed summaries and response digests.
#[derive(Clone)]
pub struct PlaidHttpResponse {
    status: u16,
    api_version: String,
    provider_id: String,
    body: Vec<u8>,
    request_digest: Option<Digest>,
    scope_digest: Option<Digest>,
}

impl PlaidHttpResponse {
    pub fn json(status: u16, body: impl AsRef<[u8]>) -> Self {
        Self {
            status,
            api_version: PLAID_TRANSACTION_RESULT_API_VERSION.to_owned(),
            provider_id: PLAID_TRANSACTION_RESULT_PROVIDER_ID.to_owned(),
            body: body.as_ref().to_vec(),
            request_digest: None,
            scope_digest: None,
        }
    }

    #[must_use]
    pub fn with_api_version(mut self, api_version: impl Into<String>) -> Self {
        self.api_version = api_version.into();
        self
    }

    #[must_use]
    pub fn with_provider_id(mut self, provider_id: impl Into<String>) -> Self {
        self.provider_id = provider_id.into();
        self
    }

    #[must_use]
    pub fn with_request_digest(mut self, request_digest: Digest) -> Self {
        self.request_digest = Some(request_digest);
        self
    }

    #[must_use]
    pub fn with_scope_digest(mut self, scope_digest: Digest) -> Self {
        self.scope_digest = Some(scope_digest);
        self
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    pub fn body_digest(&self) -> Digest {
        digest_bytes(&self.body)
    }

    pub fn request_digest(&self) -> Option<&Digest> {
        self.request_digest.as_ref()
    }

    pub fn scope_digest(&self) -> Option<&Digest> {
        self.scope_digest.as_ref()
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for PlaidHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlaidHttpResponse")
            .field("status", &self.status)
            .field("api_version", &self.api_version)
            .field("provider_id", &self.provider_id)
            .field("body_bytes", &self.body.len())
            .field("body_digest", &self.body_digest())
            .field("request_digest", &self.request_digest)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

/// Provider transport boundary. Layer 1 supplies deterministic transports;
/// native HTTPS and credential resolution are deliberately not implemented.
pub trait PlaidTransport: fmt::Debug + Send {
    fn mode(&self) -> TransportMode;

    fn send(
        &mut self,
        request: &PlaidTransportRequest,
    ) -> Result<PlaidHttpResponse, PlaidTransportError>;

    fn requests(&self) -> &[TransportRequestRecord] {
        &[]
    }
}

#[derive(Debug)]
struct QueuedPlaidTransport {
    mode: TransportMode,
    responses: std::collections::VecDeque<Result<PlaidHttpResponse, PlaidTransportError>>,
    requests: Vec<TransportRequestRecord>,
}

impl QueuedPlaidTransport {
    fn new<I>(mode: TransportMode, responses: I) -> Self
    where
        I: IntoIterator<Item = Result<PlaidHttpResponse, PlaidTransportError>>,
    {
        Self {
            mode,
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    fn send(
        &mut self,
        request: &PlaidTransportRequest,
    ) -> Result<PlaidHttpResponse, PlaidTransportError> {
        self.requests.push(TransportRequestRecord {
            method: request.method().to_owned(),
            endpoint: request.endpoint().to_owned(),
            api_version: request.api_version().to_owned(),
            cursor_digest: request.cursor_digest().clone(),
            count: request.count(),
            account_filter_digest: request.account_filter_digest().clone(),
            body_digest: request.body_digest().clone(),
            request_digest: request.request_digest().clone(),
        });
        self.responses
            .pop_front()
            .unwrap_or(Err(PlaidTransportError::Unavailable))
    }
}

macro_rules! queued_transport {
    ($name:ident, $mode:expr) => {
        #[derive(Debug)]
        pub struct $name {
            inner: QueuedPlaidTransport,
        }

        impl $name {
            pub fn new<I>(responses: I) -> Self
            where
                I: IntoIterator<Item = Result<PlaidHttpResponse, PlaidTransportError>>,
            {
                Self {
                    inner: QueuedPlaidTransport::new($mode, responses),
                }
            }

            pub fn push(&mut self, response: Result<PlaidHttpResponse, PlaidTransportError>) {
                self.inner.responses.push_back(response);
            }

            pub fn requests(&self) -> &[TransportRequestRecord] {
                &self.inner.requests
            }
        }

        impl PlaidTransport for $name {
            fn mode(&self) -> TransportMode {
                self.inner.mode
            }

            fn send(
                &mut self,
                request: &PlaidTransportRequest,
            ) -> Result<PlaidHttpResponse, PlaidTransportError> {
                self.inner.send(request)
            }

            fn requests(&self) -> &[TransportRequestRecord] {
                self.requests()
            }
        }
    };
}

queued_transport!(FixturePlaidTransport, TransportMode::Fixture);
queued_transport!(RecordingPlaidTransport, TransportMode::Recording);
queued_transport!(LoopbackPlaidTransport, TransportMode::Loopback);

#[derive(Debug, Default)]
pub struct BlockedEnvPlaidTransport;

impl PlaidTransport for BlockedEnvPlaidTransport {
    fn mode(&self) -> TransportMode {
        TransportMode::BlockedEnv
    }

    fn send(
        &mut self,
        _request: &PlaidTransportRequest,
    ) -> Result<PlaidHttpResponse, PlaidTransportError> {
        Err(PlaidTransportError::BlockedEnv {
            code: BlockedEnvCode::LiveHttpsTransport,
        })
    }
}

/// Credential resolution has an intentionally redacted output type. Native
/// keyring/store resolution is not present in this crate.
#[derive(Clone, Copy, Debug, Error, PartialEq)]
pub enum CredentialError {
    #[error("credential is unavailable")]
    Unavailable,
    #[error("credential resolution is BLOCKED_ENV")]
    BlockedEnv,
}

pub struct ResolvedSecret {
    bytes: Vec<u8>,
}

impl ResolvedSecret {
    fn new(value: impl AsRef<[u8]>) -> Result<Self, CredentialError> {
        let bytes = value.as_ref().to_vec();
        if bytes.is_empty() {
            return Err(CredentialError::Unavailable);
        }
        Ok(Self { bytes })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for ResolvedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSecret")
            .field("bytes", &"<redacted>")
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

impl Drop for ResolvedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

pub trait PlaidSecretResolver: fmt::Debug + Send {
    fn resolve(
        &mut self,
        reference: &crate::model::SecretReference,
    ) -> Result<ResolvedSecret, CredentialError>;
}

#[derive(Clone)]
pub struct FixtureSecretResolver {
    value: Arc<Vec<u8>>,
}

impl FixtureSecretResolver {
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self, PlaidTransactionResultError> {
        if value.as_ref().is_empty() {
            return Err(PlaidTransactionResultError::InvalidField {
                field: "fixture_secret",
                reason: "must not be empty",
            });
        }
        Ok(Self {
            value: Arc::new(value.as_ref().to_vec()),
        })
    }
}

impl fmt::Debug for FixtureSecretResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureSecretResolver")
            .field("value", &"<redacted>")
            .field("byte_len", &self.value.len())
            .finish()
    }
}

impl PlaidSecretResolver for FixtureSecretResolver {
    fn resolve(
        &mut self,
        _reference: &crate::model::SecretReference,
    ) -> Result<ResolvedSecret, CredentialError> {
        ResolvedSecret::new(self.value.as_slice())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvSecretResolver;

impl PlaidSecretResolver for BlockedEnvSecretResolver {
    fn resolve(
        &mut self,
        _reference: &crate::model::SecretReference,
    ) -> Result<ResolvedSecret, CredentialError> {
        Err(CredentialError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct PlaidProviderDescription {
    pub provider_id: String,
    pub api_version: String,
    pub endpoint: String,
    pub mode: TransportMode,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub link_token_creation: bool,
    pub refresh: bool,
    pub payments: bool,
    pub account_mutation: bool,
    pub financial_advice: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSyncRead {
    pub mode: TransportMode,
    pub status: EvidenceStatus,
    pub update_status: TransactionsUpdateStatus,
    pub transactions: Vec<TransactionSummary>,
    pub page_count: usize,
    pub restart_count: usize,
    pub has_more: bool,
    pub cursor_before_digest: Digest,
    pub cursor_after_digest: Digest,
    pub response_digest: Digest,
    pub failure_digest: Option<Digest>,
    pub request_id_digests: Vec<Digest>,
    pub request_digest: Digest,
}

impl ProviderSyncRead {
    fn blocked(mode: TransportMode, request: &TransactionSyncRequest) -> Self {
        let request_digest = request.digest();
        Self {
            mode,
            status: EvidenceStatus::BlockedEnv,
            update_status: TransactionsUpdateStatus::Unknown,
            transactions: Vec::new(),
            page_count: 0,
            restart_count: 0,
            has_more: false,
            cursor_before_digest: request.cursor_digest().clone(),
            cursor_after_digest: request.cursor_digest().clone(),
            response_digest: digest_serializable(&("blocked_env", &request_digest)),
            failure_digest: Some(digest_serializable(&("blocked_env", &request_digest))),
            request_id_digests: Vec::new(),
            request_digest,
        }
    }

    fn failure(
        mode: TransportMode,
        request: &TransactionSyncRequest,
        status: EvidenceStatus,
        response_digest: Digest,
        failure_digest: Digest,
    ) -> Self {
        let request_digest = request.digest();
        Self {
            mode,
            status,
            update_status: TransactionsUpdateStatus::Unknown,
            transactions: Vec::new(),
            page_count: 0,
            restart_count: 0,
            has_more: false,
            cursor_before_digest: request.cursor_digest().clone(),
            cursor_after_digest: request.cursor_digest().clone(),
            response_digest,
            failure_digest: Some(failure_digest),
            request_id_digests: Vec::new(),
            request_digest,
        }
    }
}

/// Plaid Transactions provider with typed parsing and bounded pagination.
pub struct PlaidTransactionsProvider {
    transport: Box<dyn PlaidTransport>,
    resolver: Box<dyn PlaidSecretResolver>,
}

impl PlaidTransactionsProvider {
    pub fn new<T, R>(transport: T, resolver: R) -> Self
    where
        T: PlaidTransport + 'static,
        R: PlaidSecretResolver + 'static,
    {
        Self {
            transport: Box::new(transport),
            resolver: Box::new(resolver),
        }
    }

    pub fn mode(&self) -> TransportMode {
        self.transport.mode()
    }

    pub fn description(&self) -> PlaidProviderDescription {
        PlaidProviderDescription {
            provider_id: PLAID_TRANSACTION_RESULT_PROVIDER_ID.to_owned(),
            api_version: PLAID_TRANSACTION_RESULT_API_VERSION.to_owned(),
            endpoint: crate::model::DEFAULT_PLAID_SYNC_ENDPOINT.to_owned(),
            mode: self.mode(),
            read_only: true,
            connected: false,
            native: false,
            link_token_creation: false,
            refresh: false,
            payments: false,
            account_mutation: false,
            financial_advice: false,
        }
    }

    pub fn transport(&self) -> &dyn PlaidTransport {
        self.transport.as_ref()
    }

    pub fn transport_mut(&mut self) -> &mut dyn PlaidTransport {
        self.transport.as_mut()
    }

    pub fn sync(
        &mut self,
        scope: &PlaidTransactionsScope,
        secret_reference: &crate::model::SecretReference,
        request: &TransactionSyncRequest,
    ) -> Result<ProviderSyncRead, PlaidTransactionResultError> {
        scope.validate()?;
        request.validate_against(scope)?;
        if request.account_filter() != scope.account_filter() {
            return Err(PlaidTransactionResultError::ScopeMismatch(
                "account filter drifted from the registration",
            ));
        }
        if secret_reference != scope.secret_reference() {
            return Err(PlaidTransactionResultError::ScopeMismatch(
                "secret reference is bound to a different permission scope",
            ));
        }

        if self.mode() == TransportMode::BlockedEnv {
            return Ok(ProviderSyncRead::blocked(self.mode(), request));
        }

        let resolved = match self.resolver.resolve(secret_reference) {
            Ok(resolved) => resolved,
            Err(CredentialError::BlockedEnv) => {
                return Ok(ProviderSyncRead::blocked(
                    TransportMode::BlockedEnv,
                    request,
                ));
            }
            Err(CredentialError::Unavailable) => {
                return Err(PlaidTransactionResultError::CredentialUnavailable);
            }
        };
        let _credential_digest = digest_bytes(resolved.as_bytes());
        drop(resolved);

        let initial_cursor = request.cursor().clone();
        let mut restart_count = 0;
        loop {
            match self.sync_attempt(scope, request, &initial_cursor) {
                Ok(read) => return Ok(read.with_restart_count(restart_count)),
                Err(AttemptError::PaginationMutation) => {
                    if restart_count >= MAX_PAGINATION_MUTATION_RESTARTS {
                        return Err(PlaidTransactionResultError::PaginationMutationRestartExceeded);
                    }
                    restart_count += 1;
                }
                Err(AttemptError::Fatal(error)) => return Err(error),
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn sync_attempt(
        &mut self,
        scope: &PlaidTransactionsScope,
        request: &TransactionSyncRequest,
        initial_cursor: &crate::model::Cursor,
    ) -> Result<ProviderSyncRead, AttemptError> {
        let mut cursor = initial_cursor.clone();
        let mut visited_cursors = BTreeSet::new();
        visited_cursors.insert(initial_cursor.digest().clone());
        let mut transactions = Vec::new();
        let mut page_count = 0;
        let mut update_status = TransactionsUpdateStatus::Complete;
        let mut response_digests = Vec::new();
        let mut request_id_digests = Vec::new();
        let mut last_cursor_digest = cursor.digest().clone();

        loop {
            if page_count >= request.max_pages() {
                return Ok(ProviderSyncRead {
                    mode: self.mode(),
                    status: EvidenceStatus::Partial,
                    update_status,
                    transactions,
                    page_count,
                    restart_count: 0,
                    has_more: true,
                    cursor_before_digest: initial_cursor.digest().clone(),
                    cursor_after_digest: last_cursor_digest,
                    response_digest: digest_serializable(&response_digests),
                    failure_digest: Some(digest_serializable(&("page_limit", page_count))),
                    request_id_digests,
                    request_digest: request.digest(),
                });
            }

            let cursor_request = request_for_cursor(request, cursor.clone());
            let transport_request = PlaidTransportRequest::new(scope, &cursor_request);
            let response = match self.transport.send(&transport_request) {
                Ok(response) => response,
                Err(PlaidTransportError::Timeout) => {
                    return Ok(ProviderSyncRead::failure(
                        self.mode(),
                        request,
                        EvidenceStatus::ProviderUnknown,
                        digest_serializable(&("timeout", &transport_request.request_digest())),
                        digest_serializable(&"timeout"),
                    ));
                }
                Err(PlaidTransportError::Unavailable) => {
                    return Ok(ProviderSyncRead::failure(
                        self.mode(),
                        request,
                        EvidenceStatus::ProviderUnknown,
                        digest_serializable(&("unavailable", &transport_request.request_digest())),
                        digest_serializable(&"unavailable"),
                    ));
                }
                Err(PlaidTransportError::BlockedEnv { .. }) => {
                    return Ok(ProviderSyncRead::blocked(
                        TransportMode::BlockedEnv,
                        request,
                    ));
                }
            };

            if response.body_len() > MAX_RESPONSE_BYTES {
                return Err(AttemptError::Fatal(
                    PlaidTransactionResultError::ResponseTooLarge,
                ));
            }
            if response.provider_id() != PLAID_TRANSACTION_RESULT_PROVIDER_ID {
                return Err(AttemptError::Fatal(
                    PlaidTransactionResultError::ProviderIdentityDrift,
                ));
            }
            if response.api_version() != scope.api_version() {
                return Err(AttemptError::Fatal(
                    PlaidTransactionResultError::ProviderApiVersionDrift,
                ));
            }
            if response
                .scope_digest()
                .is_some_and(|digest| digest != &scope.digest())
            {
                return Err(AttemptError::Fatal(
                    PlaidTransactionResultError::ProviderScopeDrift,
                ));
            }
            if response
                .request_digest()
                .is_some_and(|digest| digest != transport_request.request_digest())
            {
                return Err(AttemptError::Fatal(
                    PlaidTransactionResultError::ScopeMismatch(
                        "provider response is bound to a different request",
                    ),
                ));
            }

            let response_digest = response.body_digest();
            response_digests.push(response_digest);
            page_count += 1;

            if response.status() != 200 {
                if is_pagination_mutation(response.body()) {
                    return Err(AttemptError::PaginationMutation);
                }
                let status = status_for_http(response.status());
                let failure_digest = failure_digest(response.body(), response.status());
                return Ok(ProviderSyncRead::failure(
                    self.mode(),
                    request,
                    status,
                    digest_serializable(&response_digests),
                    failure_digest,
                ));
            }

            let page =
                parse_sync_page(response.body(), scope, request).map_err(AttemptError::Fatal)?;
            if let Some(request_id_digest) = page.request_id_digest {
                request_id_digests.push(request_id_digest);
            }
            update_status = merge_update_status(update_status, page.update_status);
            transactions.extend(page.transactions);
            if transactions.len() > request.max_transactions() {
                let transaction_count = transactions.len();
                return Ok(ProviderSyncRead {
                    mode: self.mode(),
                    status: EvidenceStatus::Partial,
                    update_status,
                    transactions,
                    page_count,
                    restart_count: 0,
                    has_more: true,
                    cursor_before_digest: initial_cursor.digest().clone(),
                    cursor_after_digest: last_cursor_digest,
                    response_digest: digest_serializable(&response_digests),
                    failure_digest: Some(digest_serializable(&(
                        "transaction_limit",
                        transaction_count,
                    ))),
                    request_id_digests,
                    request_digest: request.digest(),
                });
            }

            last_cursor_digest = page.next_cursor.digest().clone();
            if !page.has_more {
                let status = if update_status == TransactionsUpdateStatus::InProgress {
                    EvidenceStatus::NotReady
                } else if update_status == TransactionsUpdateStatus::Unknown {
                    EvidenceStatus::ProviderUnknown
                } else if transactions.is_empty() {
                    EvidenceStatus::Empty
                } else {
                    EvidenceStatus::Ready
                };
                return Ok(ProviderSyncRead {
                    mode: self.mode(),
                    status,
                    update_status,
                    transactions,
                    page_count,
                    restart_count: 0,
                    has_more: false,
                    cursor_before_digest: initial_cursor.digest().clone(),
                    cursor_after_digest: last_cursor_digest,
                    response_digest: digest_serializable(&response_digests),
                    failure_digest: None,
                    request_id_digests,
                    request_digest: request.digest(),
                });
            }

            if !visited_cursors.insert(page.next_cursor.digest().clone())
                || page.next_cursor.digest() == cursor.digest()
            {
                return Err(AttemptError::Fatal(PlaidTransactionResultError::CursorLoop));
            }
            cursor = page.next_cursor;
        }
    }
}

impl fmt::Debug for PlaidTransactionsProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlaidTransactionsProvider")
            .field("mode", &self.mode())
            .field("transport", &self.transport)
            .field("resolver", &self.resolver)
            .finish()
    }
}

impl ProviderSyncRead {
    fn with_restart_count(mut self, restart_count: usize) -> Self {
        self.restart_count = restart_count;
        self
    }
}

enum AttemptError {
    PaginationMutation,
    Fatal(PlaidTransactionResultError),
}

fn request_for_cursor(
    request: &TransactionSyncRequest,
    cursor: crate::model::Cursor,
) -> TransactionSyncRequest {
    request.with_provider_cursor(cursor)
}

fn parse_sync_page(
    body: &[u8],
    scope: &PlaidTransactionsScope,
    request: &TransactionSyncRequest,
) -> Result<ParsedSyncPage, PlaidTransactionResultError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| PlaidTransactionResultError::MalformedResponse("body is not valid JSON"))?;
    let object = value
        .as_object()
        .ok_or(PlaidTransactionResultError::MalformedResponse(
            "sync response must be an object",
        ))?;
    let added = parse_transaction_array(object, "added", TransactionState::Posted, scope, request)?;
    let modified = parse_transaction_array(
        object,
        "modified",
        TransactionState::Modified,
        scope,
        request,
    )?;
    let removed = parse_removed_array(object, scope, request)?;
    let has_more = object.get("has_more").and_then(Value::as_bool).ok_or(
        PlaidTransactionResultError::MalformedResponse("has_more must be a boolean"),
    )?;
    let next_cursor = object
        .get("next_cursor")
        .and_then(Value::as_str)
        .ok_or(PlaidTransactionResultError::MalformedResponse(
            "next_cursor must be a string",
        ))
        .and_then(|value| crate::model::Cursor::new(value.to_owned()))?;
    let update_status = parse_update_status(object.get("transactions_update_status"))?;
    let request_id_digest = object
        .get("request_id")
        .and_then(Value::as_str)
        .map(|value| digest_provider_field("request-id", value));
    let mut transactions = Vec::with_capacity(added.len() + modified.len() + removed.len());
    transactions.extend(added);
    transactions.extend(modified);
    transactions.extend(removed);
    Ok(ParsedSyncPage {
        transactions,
        has_more,
        next_cursor,
        update_status,
        request_id_digest,
    })
}

struct ParsedSyncPage {
    transactions: Vec<TransactionSummary>,
    has_more: bool,
    next_cursor: crate::model::Cursor,
    update_status: TransactionsUpdateStatus,
    request_id_digest: Option<Digest>,
}

fn parse_transaction_array(
    object: &Map<String, Value>,
    key: &str,
    state: TransactionState,
    scope: &PlaidTransactionsScope,
    request: &TransactionSyncRequest,
) -> Result<Vec<TransactionSummary>, PlaidTransactionResultError> {
    let entries = object.get(key).and_then(Value::as_array).ok_or(
        PlaidTransactionResultError::MalformedResponse("transaction update arrays are required"),
    )?;
    if entries.len() > MAX_TRANSACTION_COUNT {
        return Err(PlaidTransactionResultError::TransactionCountExceeded);
    }
    entries
        .iter()
        .map(|entry| parse_transaction(entry, state, scope, request))
        .collect()
}

fn parse_removed_array(
    object: &Map<String, Value>,
    scope: &PlaidTransactionsScope,
    request: &TransactionSyncRequest,
) -> Result<Vec<TransactionSummary>, PlaidTransactionResultError> {
    let entries = object.get("removed").and_then(Value::as_array).ok_or(
        PlaidTransactionResultError::MalformedResponse("removed transaction array is required"),
    )?;
    if entries.len() > MAX_TRANSACTION_COUNT {
        return Err(PlaidTransactionResultError::TransactionCountExceeded);
    }
    entries
        .iter()
        .map(|entry| parse_transaction(entry, TransactionState::Removed, scope, request))
        .collect()
}

fn parse_transaction(
    value: &Value,
    state: TransactionState,
    scope: &PlaidTransactionsScope,
    request: &TransactionSyncRequest,
) -> Result<TransactionSummary, PlaidTransactionResultError> {
    let object = value
        .as_object()
        .ok_or(PlaidTransactionResultError::MalformedResponse(
            "transaction entry must be an object",
        ))?;
    let transaction_id = required_string(object, "transaction_id", MAX_PROVIDER_FIELD_BYTES)?;
    let transaction_id_digest = digest_provider_field("transaction-id", transaction_id);
    let account_id_digest = object
        .get("account_id")
        .and_then(Value::as_str)
        .map(|value| digest_provider_field("account-id", value));
    if !matches!(state, TransactionState::Removed) && account_id_digest.is_none() {
        return Err(PlaidTransactionResultError::MalformedResponse(
            "account_id is required for added and modified transactions",
        ));
    }
    if let Some(account_id_digest) = account_id_digest.as_ref()
        && !request.account_filter().contains(account_id_digest)
    {
        return Err(PlaidTransactionResultError::ScopeMismatch(
            "transaction account is outside the registered filter",
        ));
    }
    if matches!(state, TransactionState::Removed) {
        return Ok(TransactionSummary {
            transaction_id_digest,
            account_id_digest,
            state,
            settlement_state: None,
            amount_bucket: AmountBucket::Unknown,
            amount_digest: None,
            currency: None,
            transaction_date: None,
            authorized_date: None,
            category_digest: None,
            entity_digest: None,
            pending_posted_linkage_digest: None,
            revision: scope.transaction_revision().number(),
        });
    }
    let pending = object.get("pending").and_then(Value::as_bool).ok_or(
        PlaidTransactionResultError::MalformedResponse("pending must be a boolean"),
    )?;
    let amount_value =
        object
            .get("amount")
            .ok_or(PlaidTransactionResultError::MalformedResponse(
                "amount is required",
            ))?;
    let amount_string = amount_string(amount_value)?;
    let amount_bucket = amount_bucket(&amount_string);
    let amount_digest = Some(digest_provider_field("amount", &amount_string));
    let currency = optional_string(object, "iso_currency_code")?
        .map(CurrencyCode::new)
        .transpose()?;
    let transaction_date = optional_string(object, "date")?
        .map(BoundedTimestamp::new)
        .transpose()?;
    let authorized_date = optional_string(object, "authorized_date")?
        .map(BoundedTimestamp::new)
        .transpose()?;
    let category_digest = category_digest(object.get("personal_finance_category"));
    let entity_digest = object
        .get("merchant_entity_id")
        .and_then(Value::as_str)
        .or_else(|| object.get("merchant_name").and_then(Value::as_str))
        .map(|value| digest_provider_field("entity", value));
    let pending_posted_linkage_digest = optional_string(object, "pending_transaction_id")?
        .map(|value| digest_provider_field("pending-posted-link", value));
    let settlement_state = if matches!(state, TransactionState::Modified) {
        Some(if pending {
            SettlementState::Pending
        } else {
            SettlementState::Posted
        })
    } else {
        None
    };
    let state = if matches!(state, TransactionState::Modified) {
        TransactionState::Modified
    } else if pending {
        TransactionState::Pending
    } else {
        TransactionState::Posted
    };
    Ok(TransactionSummary {
        transaction_id_digest,
        account_id_digest,
        state,
        settlement_state,
        amount_bucket,
        amount_digest,
        currency,
        transaction_date,
        authorized_date,
        category_digest,
        entity_digest,
        pending_posted_linkage_digest,
        revision: scope.transaction_revision().number(),
    })
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
    max_bytes: usize,
) -> Result<&'a str, PlaidTransactionResultError> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(PlaidTransactionResultError::MalformedResponse(field))?;
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(PlaidTransactionResultError::MalformedResponse(field));
    }
    Ok(value)
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<Option<&'a str>, PlaidTransactionResultError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            if value.len() > MAX_PROVIDER_FIELD_BYTES || value.chars().any(char::is_control) {
                Err(PlaidTransactionResultError::MalformedResponse(field))
            } else {
                Ok(Some(value.as_str()))
            }
        }
        Some(_) => Err(PlaidTransactionResultError::MalformedResponse(field)),
    }
}

fn amount_string(value: &Value) -> Result<String, PlaidTransactionResultError> {
    let value = match value {
        Value::Number(number) => number.to_string(),
        Value::String(value) => value.clone(),
        _ => {
            return Err(PlaidTransactionResultError::MalformedResponse("amount"));
        }
    };
    if value.is_empty()
        || value.len() > MAX_PROVIDER_FIELD_BYTES
        || value.chars().any(char::is_control)
        || value.parse::<f64>().is_err()
    {
        return Err(PlaidTransactionResultError::MalformedResponse("amount"));
    }
    Ok(value)
}

fn amount_bucket(value: &str) -> AmountBucket {
    let Ok(value) = value.parse::<f64>() else {
        return AmountBucket::Unknown;
    };
    let value = value.abs();
    if !value.is_finite() {
        AmountBucket::Unknown
    } else if value == 0.0 {
        AmountBucket::Zero
    } else if value < 10.0 {
        AmountBucket::UnderTen
    } else if value < 100.0 {
        AmountBucket::UnderHundred
    } else if value < 1_000.0 {
        AmountBucket::UnderThousand
    } else if value < 10_000.0 {
        AmountBucket::UnderTenThousand
    } else {
        AmountBucket::TenThousandOrMore
    }
}

fn category_digest(value: Option<&Value>) -> Option<Digest> {
    let object = value?.as_object()?;
    let primary = object.get("primary").and_then(Value::as_str);
    let detailed = object.get("detailed").and_then(Value::as_str);
    if primary.is_none() && detailed.is_none() {
        return None;
    }
    Some(digest_serializable(&(primary, detailed)))
}

fn digest_provider_field(namespace: &str, value: &str) -> Digest {
    let bounded = value
        .char_indices()
        .nth(MAX_PROVIDER_FIELD_BYTES)
        .map_or(value, |(index, _)| &value[..index]);
    let mut material = namespace.as_bytes().to_vec();
    material.extend_from_slice(b":v1:");
    material.extend_from_slice(bounded.as_bytes());
    digest_bytes(&material)
}

fn parse_update_status(
    value: Option<&Value>,
) -> Result<TransactionsUpdateStatus, PlaidTransactionResultError> {
    let Some(value) = value else {
        return Ok(TransactionsUpdateStatus::Complete);
    };
    let value = value
        .as_str()
        .ok_or(PlaidTransactionResultError::MalformedResponse(
            "transactions_update_status",
        ))?
        .to_ascii_lowercase();
    match value.as_str() {
        "complete" | "ready" => Ok(TransactionsUpdateStatus::Complete),
        "in_progress" | "in-progress" | "not_ready" | "not-ready" => {
            Ok(TransactionsUpdateStatus::InProgress)
        }
        "unknown" => Ok(TransactionsUpdateStatus::Unknown),
        _ => Err(PlaidTransactionResultError::MalformedResponse(
            "transactions_update_status",
        )),
    }
}

fn merge_update_status(
    left: TransactionsUpdateStatus,
    right: TransactionsUpdateStatus,
) -> TransactionsUpdateStatus {
    match (left, right) {
        (TransactionsUpdateStatus::Unknown, _) | (_, TransactionsUpdateStatus::Unknown) => {
            TransactionsUpdateStatus::Unknown
        }
        (TransactionsUpdateStatus::InProgress, _) | (_, TransactionsUpdateStatus::InProgress) => {
            TransactionsUpdateStatus::InProgress
        }
        _ => TransactionsUpdateStatus::Complete,
    }
}

fn is_pagination_mutation(body: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    object
        .get("pagination_mutation")
        .and_then(Value::as_bool)
        .is_some_and(|value| value)
        || object
            .get("error_code")
            .and_then(Value::as_str)
            .is_some_and(|value| {
                value == "TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION"
                    || value == "TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION_RETRY"
            })
}

fn failure_digest(body: &[u8], status: u16) -> Digest {
    let code = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error_code")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "provider_error".to_owned());
    let code = &code[..code.len().min(MAX_FAILURE_BYTES)];
    digest_serializable(&(status, code))
}

fn status_for_http(status: u16) -> EvidenceStatus {
    match status {
        401 | 403 | 404 => EvidenceStatus::AccessLost,
        409 => EvidenceStatus::Stale,
        _ => EvidenceStatus::ProviderUnknown,
    }
}

// Kept in this module so the public version constant cannot drift from the
// contract/API definition while the model remains the single source of truth.
pub(crate) const PLAID_TRANSACTION_RESULT_API_VERSION: &str =
    crate::model::DEFAULT_PLAID_API_VERSION;
