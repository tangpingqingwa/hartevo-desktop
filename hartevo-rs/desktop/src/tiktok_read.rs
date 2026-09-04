//! Desktop-owned native transport for Cordis-authorized TikTok reads.
//!
//! The channel adapter owns request and response semantics. This module owns
//! only the native OS-keyring and bounded HTTPS composition, keeping secret
//! bytes below the Desktop/Application boundary.

use std::{fmt, time::Duration};

use chrono::Utc;
use hartevo_channel_adapters::tiktok::{
    ProviderId as TiktokProviderId, USER_INFO_PATH, VIDEO_LIST_PATH, VIDEO_QUERY_PATH,
};
use hartevo_channel_adapters::transport::CredentialKind;
use hartevo_channel_adapters::{
    HttpMethod, OAuthCredential, ProviderKind, ProviderReadRequest, ProviderResponse,
    ReadOnlyTransport, ReadOperation, SecretReference as ChannelSecretReference, TiktokOAuthScope,
    TiktokReadScope, TransportError,
};
use hartevo_domain_kernel::{ProjectId, TenantId};
use hartevo_storage::{SecretReference as StorageSecretReference, SecretStore, SecretStoreError};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const TIKTOK_API_HOST: &str = "open.tiktokapis.com";
const TIKTOK_API_PATH_PREFIX: &str = "/v2";
const TIKTOK_USER_FIELDS: &str = "open_id,display_name";
const TIKTOK_VIDEO_FIELDS: &str = "id,create_time,title,video_description,share_url,like_count,comment_count,share_count,view_count";
const TIKTOK_ACCESS_TOKEN_PURPOSE: &str = "oauth-access-token";
const TIKTOK_MAX_REQUEST_BYTES: usize = 64 * 1024;
const TIKTOK_MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
const TIKTOK_MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const TIKTOK_GLOBAL_TIMEOUT_SECONDS: u64 = 20;

/// Derives the exact, generation-bound OS-keyring address used for one TikTok
/// access token. The account scope is hashed so provider identifiers do not
/// become keyring labels.
pub fn tiktok_access_token_reference(
    project_id: &ProjectId,
    scope: &TiktokReadScope,
    credential_generation: u64,
) -> Result<StorageSecretReference, SecretStoreError> {
    let scope_bytes = serde_json::to_vec(&(scope.business().as_str(), scope.account().as_str()))?;
    let reference = StorageSecretReference {
        tenant_id: TenantId::from(scope.tenant().as_str()),
        project_id: project_id.clone(),
        provider: "tiktok".into(),
        account_scope: format!("scope-sha256:{:x}", Sha256::digest(scope_bytes)),
        purpose: TIKTOK_ACCESS_TOKEN_PURPOSE.into(),
        version: credential_generation,
    };
    reference.credential_id()?;
    Ok(reference)
}

pub(crate) fn native_tiktok_read_transport<'a>(
    secret_store: &'a impl SecretStore,
    project_id: &ProjectId,
    scope: &TiktokReadScope,
    credential: &OAuthCredential,
) -> Result<impl ReadOnlyTransport + 'a, SecretStoreError> {
    TiktokReadTransport::new(
        secret_store,
        project_id,
        scope,
        credential,
        UreqTiktokHttpsExecutor::new(),
    )
}

trait TiktokHttpsExecutor {
    fn execute(
        &self,
        request: &ProviderReadRequest,
        access_token: &str,
    ) -> Result<ProviderResponse, TransportError>;
}

struct TiktokReadTransport<'a, S, H> {
    secret_store: &'a S,
    storage_reference: StorageSecretReference,
    channel_reference: ChannelSecretReference,
    executor: H,
}

impl<'a, S, H> TiktokReadTransport<'a, S, H>
where
    S: SecretStore,
{
    fn new(
        secret_store: &'a S,
        project_id: &ProjectId,
        scope: &TiktokReadScope,
        credential: &OAuthCredential,
        executor: H,
    ) -> Result<Self, SecretStoreError> {
        let channel_reference =
            ChannelSecretReference::new(format!("keychain://tiktok/{}", scope.account().as_str()))
                .map_err(|_| SecretStoreError::InvalidReference)?;
        if credential.scope() != scope || credential.secret_reference() != &channel_reference {
            return Err(SecretStoreError::InvalidReference);
        }
        Ok(Self {
            secret_store,
            storage_reference: tiktok_access_token_reference(
                project_id,
                scope,
                credential.generation(),
            )?,
            channel_reference,
            executor,
        })
    }
}

impl<S, H> fmt::Debug for TiktokReadTransport<'_, S, H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TiktokReadTransport")
            .field("storage_reference", &self.storage_reference)
            .field("channel_reference", &self.channel_reference)
            .field("secret_store", &"[REDACTED]")
            .field("executor", &"bounded_https")
            .finish()
    }
}

impl<S, H> ReadOnlyTransport for TiktokReadTransport<'_, S, H>
where
    S: SecretStore,
    H: TiktokHttpsExecutor,
{
    fn send(&mut self, request: &ProviderReadRequest) -> Result<ProviderResponse, TransportError> {
        if !valid_tiktok_request(request, &self.channel_reference) {
            return Err(TransportError::Unavailable);
        }
        let secret = self
            .secret_store
            .get(&self.storage_reference)
            .map_err(|_| TransportError::Unavailable)?;
        let access_token = std::str::from_utf8(secret.as_slice())
            .ok()
            .filter(|token| {
                !token.is_empty()
                    && token.len() <= 4_096
                    && token == &token.trim()
                    && !token.chars().any(char::is_control)
            })
            .ok_or(TransportError::Unavailable)?;
        self.executor.execute(request, access_token)
    }
}

fn valid_tiktok_request(
    request: &ProviderReadRequest,
    expected_credential: &ChannelSecretReference,
) -> bool {
    let Some((method, path, fields, required_scope, body_required)) = operation_policy(request)
    else {
        return false;
    };
    let url = request.url();
    let mut query = url.query_pairs();
    let exact_query = query
        .next()
        .is_some_and(|(name, value)| name == "fields" && value == fields)
        && query.next().is_none();
    let body_is_valid = match request.body() {
        Some(body) if body_required => {
            serde_json::to_vec(body).is_ok_and(|body| body.len() <= TIKTOK_MAX_REQUEST_BYTES)
        }
        None if !body_required => true,
        _ => false,
    };
    matches!(
        request.provider_kind(),
        ProviderKind::Tiktok(TiktokProviderId::Tiktok)
    ) && request.method() == method
        && url.scheme() == "https"
        && url.host_str() == Some(TIKTOK_API_HOST)
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url.path().strip_prefix(TIKTOK_API_PATH_PREFIX) == Some(path)
        && exact_query
        && request.required_scopes().len() == 1
        && request
            .required_scopes()
            .iter()
            .next()
            .is_some_and(|scope| scope.as_str() == required_scope.as_str())
        && matches!(
            request.credential(),
            CredentialKind::Tiktok(actual) if actual == expected_credential
        )
        && body_is_valid
}

fn operation_policy(
    request: &ProviderReadRequest,
) -> Option<(
    HttpMethod,
    &'static str,
    &'static str,
    TiktokOAuthScope,
    bool,
)> {
    match request.operation() {
        ReadOperation::TiktokUserInfo => Some((
            HttpMethod::Get,
            USER_INFO_PATH,
            TIKTOK_USER_FIELDS,
            TiktokOAuthScope::UserInfoBasic,
            false,
        )),
        ReadOperation::TiktokVideoList => Some((
            HttpMethod::Post,
            VIDEO_LIST_PATH,
            TIKTOK_VIDEO_FIELDS,
            TiktokOAuthScope::VideoList,
            true,
        )),
        ReadOperation::TiktokVideoQuery => Some((
            HttpMethod::Post,
            VIDEO_QUERY_PATH,
            TIKTOK_VIDEO_FIELDS,
            TiktokOAuthScope::VideoList,
            true,
        )),
        _ => None,
    }
}

struct UreqTiktokHttpsExecutor {
    agent: ureq::Agent,
}

impl UreqTiktokHttpsExecutor {
    fn new() -> Self {
        let agent = ureq::Agent::config_builder()
            .user_agent("hartevo-tiktok-read/1")
            .https_only(true)
            .max_redirects(0)
            .max_redirects_will_error(true)
            .http_status_as_error(false)
            .max_response_header_size(TIKTOK_MAX_RESPONSE_HEADER_BYTES)
            .timeout_connect(Some(Duration::from_secs(5)))
            .timeout_send_body(Some(Duration::from_secs(5)))
            .timeout_recv_body(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(TIKTOK_GLOBAL_TIMEOUT_SECONDS)))
            .build()
            .into();
        Self { agent }
    }
}

impl fmt::Debug for UreqTiktokHttpsExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UreqTiktokHttpsExecutor")
            .field("https_only", &true)
            .field("redirects", &0)
            .field("global_timeout_seconds", &TIKTOK_GLOBAL_TIMEOUT_SECONDS)
            .field("max_response_bytes", &TIKTOK_MAX_RESPONSE_BYTES)
            .finish()
    }
}

impl TiktokHttpsExecutor for UreqTiktokHttpsExecutor {
    fn execute(
        &self,
        request: &ProviderReadRequest,
        access_token: &str,
    ) -> Result<ProviderResponse, TransportError> {
        let authorization = Zeroizing::new(format!("Bearer {access_token}"));
        let mut response = match request.method() {
            HttpMethod::Get => self
                .agent
                .get(request.url().as_str())
                .header("Authorization", authorization.as_str())
                .header("Accept", "application/json")
                .call(),
            HttpMethod::Post => self
                .agent
                .post(request.url().as_str())
                .header("Authorization", authorization.as_str())
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .send_json(request.body().ok_or(TransportError::Unavailable)?),
        }
        .map_err(|error| classify_ureq_error(&error))?;
        let status = response.status().as_u16();
        let headers = [
            "content-type",
            "retry-after",
            "x-ratelimit-reset",
            "x-rate-limit-reset",
        ]
        .into_iter()
        .filter_map(|name| bounded_header(&response, name).map(|value| (name.into(), value)))
        .collect::<Vec<_>>();
        let body = response
            .body_mut()
            .with_config()
            .limit(TIKTOK_MAX_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|error| classify_ureq_error(&error))?;
        Ok(ProviderResponse::new(status, headers, body, Utc::now()))
    }
}

fn bounded_header(response: &ureq::http::Response<ureq::Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
        })
        .map(str::to_owned)
}

fn classify_ureq_error(error: &ureq::Error) -> TransportError {
    match error {
        ureq::Error::Timeout(_) => TransportError::TimedOut,
        _ => TransportError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use chrono::{DateTime, Duration as ChronoDuration};
    use hartevo_channel_adapters::tiktok::DISPLAY_API_BASE_URL;
    use hartevo_channel_adapters::transport::CredentialKind;
    use hartevo_channel_adapters::{
        BusinessId, CredentialReference, ProviderId as YoutubeProviderId, ScopeName,
        SecretReference as ChannelSecretReference, TenantId as ChannelTenantId, TiktokAccountId,
        TiktokAuthenticatedReadService, TiktokFreshnessPolicy, TiktokVideoListCursor,
    };
    use hartevo_storage::SecretBytes;
    use url::Url;

    use super::*;

    #[derive(Debug)]
    struct CountingSecretStore {
        secret: Option<Vec<u8>>,
        reads: AtomicUsize,
    }

    impl CountingSecretStore {
        fn new(secret: Option<&[u8]>) -> Self {
            Self {
                secret: secret.map(<[u8]>::to_vec),
                reads: AtomicUsize::new(0),
            }
        }
    }

    impl SecretStore for CountingSecretStore {
        fn put(
            &self,
            _reference: &StorageSecretReference,
            _secret: &SecretBytes,
        ) -> Result<(), SecretStoreError> {
            Err(SecretStoreError::BackendUnavailable)
        }

        fn get(
            &self,
            _reference: &StorageSecretReference,
        ) -> Result<SecretBytes, SecretStoreError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.secret
                .clone()
                .ok_or(SecretStoreError::SecretNotFound)
                .and_then(SecretBytes::new)
        }

        fn delete(&self, _reference: &StorageSecretReference) -> Result<(), SecretStoreError> {
            Err(SecretStoreError::BackendUnavailable)
        }
    }

    #[derive(Clone, Debug)]
    enum WireOutcome {
        Response(ProviderResponse),
        Error(TransportError),
    }

    #[derive(Debug)]
    struct RecordingExecutor {
        calls: Arc<AtomicUsize>,
        token_digest: Arc<Mutex<Option<String>>>,
        outcome: WireOutcome,
    }

    impl TiktokHttpsExecutor for RecordingExecutor {
        fn execute(
            &self,
            _request: &ProviderReadRequest,
            access_token: &str,
        ) -> Result<ProviderResponse, TransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.token_digest.lock().expect("token digest lock") =
                Some(format!("{:x}", Sha256::digest(access_token.as_bytes())));
            match &self.outcome {
                WireOutcome::Response(response) => Ok(response.clone()),
                WireOutcome::Error(error) => Err(error.clone()),
            }
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-09-04T10:00:00Z")
            .expect("valid time")
            .with_timezone(&Utc)
    }

    fn scope() -> TiktokReadScope {
        TiktokReadScope::new(
            ChannelTenantId::new("tenant-01").expect("tenant"),
            BusinessId::new("business-01").expect("business"),
            TiktokAccountId::new("open01").expect("account"),
        )
    }

    fn credential(scope: &TiktokReadScope) -> OAuthCredential {
        OAuthCredential::new(
            ChannelSecretReference::new("keychain://tiktok/open01").expect("reference"),
            scope.clone(),
            [TiktokOAuthScope::VideoList].into_iter().collect(),
            now() + ChronoDuration::hours(1),
            None,
            4,
        )
        .expect("credential")
    }

    fn video_list_request(
        url: &str,
        method: HttpMethod,
        reference: ChannelSecretReference,
        required_scope: TiktokOAuthScope,
        body: Option<serde_json::Value>,
    ) -> ProviderReadRequest {
        ProviderReadRequest::new(
            TiktokProviderId::Tiktok,
            ReadOperation::TiktokVideoList,
            method,
            Url::parse(url).expect("URL"),
            [ScopeName::new(required_scope.as_str()).expect("scope")],
            CredentialKind::Tiktok(reference),
            body,
        )
        .expect("request")
    }

    fn exact_request(reference: ChannelSecretReference) -> ProviderReadRequest {
        video_list_request(
            &format!("{DISPLAY_API_BASE_URL}{VIDEO_LIST_PATH}?fields={TIKTOK_VIDEO_FIELDS}"),
            HttpMethod::Post,
            reference,
            TiktokOAuthScope::VideoList,
            Some(serde_json::json!({"max_count": 20})),
        )
    }

    fn executor(
        outcome: WireOutcome,
    ) -> (
        RecordingExecutor,
        Arc<AtomicUsize>,
        Arc<Mutex<Option<String>>>,
    ) {
        let calls = Arc::new(AtomicUsize::new(0));
        let token_digest = Arc::new(Mutex::new(None));
        (
            RecordingExecutor {
                calls: Arc::clone(&calls),
                token_digest: Arc::clone(&token_digest),
                outcome,
            },
            calls,
            token_digest,
        )
    }

    #[test]
    fn actual_provider_request_reads_one_generation_bound_token_and_redacts_debug() {
        let scope = scope();
        let credential = credential(&scope);
        let store = CountingSecretStore::new(Some(b"token-123"));
        let response = ProviderResponse::new(
            200,
            [("content-type".into(), "application/json".into())],
            serde_json::json!({
                "data": {"videos": [], "cursor": 0, "has_more": false},
                "error": {"code": "ok"},
            })
            .to_string(),
            now(),
        );
        let (executor, calls, token_digest) = executor(WireOutcome::Response(response));
        let transport = TiktokReadTransport::new(
            &store,
            &ProjectId::from("project-01"),
            &scope,
            &credential,
            executor,
        )
        .expect("transport");
        let debug = format!("{transport:?}");
        let mut service =
            TiktokAuthenticatedReadService::controlled(transport, TiktokFreshnessPolicy::default());
        let mut cursor =
            TiktokVideoListCursor::new_with_page_size(scope.clone(), 20).expect("cursor");

        let page = service
            .list_videos(&credential, &mut cursor, now(), 20)
            .expect("native request accepted by the provider contract");

        assert!(!page.has_more());
        assert!(page.observations().is_empty());
        assert_eq!(store.reads.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let expected_token_digest = format!("{:x}", Sha256::digest(b"token-123"));
        assert_eq!(
            token_digest.lock().expect("token digest").as_deref(),
            Some(expected_token_digest.as_str())
        );
        assert!(!debug.contains("token-123"));
        assert!(!debug.contains("keychain://tiktok/open01"));
    }

    #[test]
    fn invalid_requests_fail_before_keychain_and_network() {
        let scope = scope();
        let credential = credential(&scope);
        let store = CountingSecretStore::new(Some(b"token-123"));
        let response = ProviderResponse::new(200, [], "{}", now());
        let (executor, calls, _) = executor(WireOutcome::Response(response));
        let mut transport = TiktokReadTransport::new(
            &store,
            &ProjectId::from("project-01"),
            &scope,
            &credential,
            executor,
        )
        .expect("transport");
        let expected = credential.secret_reference().clone();
        let invalid = [
            ProviderReadRequest::new(
                YoutubeProviderId::Youtube,
                ReadOperation::Content,
                HttpMethod::Get,
                Url::parse(&format!(
                    "{DISPLAY_API_BASE_URL}{VIDEO_LIST_PATH}?fields={TIKTOK_VIDEO_FIELDS}"
                ))
                .expect("URL"),
                [ScopeName::new(TiktokOAuthScope::VideoList.as_str()).expect("scope")],
                CredentialReference::new("keychain://youtube/channel-01").expect("reference"),
                None,
            )
            .expect("request"),
            video_list_request(
                &format!(
                    "https://example.com{TIKTOK_API_PATH_PREFIX}{VIDEO_LIST_PATH}?fields={TIKTOK_VIDEO_FIELDS}"
                ),
                HttpMethod::Post,
                expected.clone(),
                TiktokOAuthScope::VideoList,
                Some(serde_json::json!({"max_count": 20})),
            ),
            video_list_request(
                &format!("{DISPLAY_API_BASE_URL}/other/?fields={TIKTOK_VIDEO_FIELDS}"),
                HttpMethod::Post,
                expected.clone(),
                TiktokOAuthScope::VideoList,
                Some(serde_json::json!({"max_count": 20})),
            ),
            video_list_request(
                &format!("{DISPLAY_API_BASE_URL}{VIDEO_LIST_PATH}?fields={TIKTOK_VIDEO_FIELDS}"),
                HttpMethod::Get,
                expected.clone(),
                TiktokOAuthScope::VideoList,
                None,
            ),
            video_list_request(
                &format!("{DISPLAY_API_BASE_URL}{VIDEO_LIST_PATH}?fields={TIKTOK_VIDEO_FIELDS}"),
                HttpMethod::Post,
                ChannelSecretReference::new("keychain://tiktok/other").expect("reference"),
                TiktokOAuthScope::VideoList,
                Some(serde_json::json!({"max_count": 20})),
            ),
            video_list_request(
                &format!("{DISPLAY_API_BASE_URL}{VIDEO_LIST_PATH}?fields={TIKTOK_VIDEO_FIELDS}"),
                HttpMethod::Post,
                expected.clone(),
                TiktokOAuthScope::VideoList,
                Some(serde_json::json!({"payload": "x".repeat(TIKTOK_MAX_REQUEST_BYTES)})),
            ),
            video_list_request(
                &format!("{DISPLAY_API_BASE_URL}{VIDEO_LIST_PATH}?fields={TIKTOK_VIDEO_FIELDS}"),
                HttpMethod::Post,
                expected.clone(),
                TiktokOAuthScope::UserInfoBasic,
                Some(serde_json::json!({"max_count": 20})),
            ),
            video_list_request(
                &format!(
                    "{DISPLAY_API_BASE_URL}{VIDEO_LIST_PATH}?fields={TIKTOK_VIDEO_FIELDS}&extra=1"
                ),
                HttpMethod::Post,
                expected,
                TiktokOAuthScope::VideoList,
                Some(serde_json::json!({"max_count": 20})),
            ),
        ];

        for request in invalid {
            assert!(matches!(
                transport.send(&request),
                Err(TransportError::Unavailable)
            ));
        }
        assert_eq!(store.reads.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn missing_or_malformed_token_never_reaches_network() {
        for secret in [
            None,
            Some(b" bad-token".as_slice()),
            Some(b"bad\ntoken".as_slice()),
        ] {
            let scope = scope();
            let credential = credential(&scope);
            let store = CountingSecretStore::new(secret);
            let response = ProviderResponse::new(200, [], "{}", now());
            let (executor, calls, _) = executor(WireOutcome::Response(response));
            let mut transport = TiktokReadTransport::new(
                &store,
                &ProjectId::from("project-01"),
                &scope,
                &credential,
                executor,
            )
            .expect("transport");

            assert!(matches!(
                transport.send(&exact_request(credential.secret_reference().clone())),
                Err(TransportError::Unavailable)
            ));
            assert_eq!(store.reads.load(Ordering::SeqCst), 1);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn storage_reference_and_transport_failures_remain_bounded() {
        let scope = scope();
        let reference = tiktok_access_token_reference(&ProjectId::from("project-01"), &scope, 4)
            .expect("storage reference");
        assert_eq!(reference.tenant_id, TenantId::from("tenant-01"));
        assert_eq!(reference.project_id, ProjectId::from("project-01"));
        assert_eq!(reference.provider, "tiktok");
        assert!(reference.account_scope.starts_with("scope-sha256:"));
        assert!(!reference.account_scope.contains("business-01"));
        assert!(!reference.account_scope.contains("open01"));
        assert_eq!(reference.purpose, TIKTOK_ACCESS_TOKEN_PURPOSE);
        assert_eq!(reference.version, 4);
        assert!(tiktok_access_token_reference(&ProjectId::from("project-01"), &scope, 0).is_err());
        assert_eq!(
            classify_ureq_error(&ureq::Error::Timeout(ureq::Timeout::Global)),
            TransportError::TimedOut
        );
        assert_eq!(
            classify_ureq_error(&ureq::Error::BodyExceedsLimit(
                TIKTOK_MAX_RESPONSE_BYTES + 1
            )),
            TransportError::Unavailable
        );

        let credential = credential(&scope);
        let store = CountingSecretStore::new(Some(b"token-123"));
        let (executor, calls, _) = executor(WireOutcome::Error(TransportError::TimedOut));
        let mut transport = TiktokReadTransport::new(
            &store,
            &ProjectId::from("project-01"),
            &scope,
            &credential,
            executor,
        )
        .expect("transport");
        assert!(matches!(
            transport.send(&exact_request(credential.secret_reference().clone())),
            Err(TransportError::TimedOut)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
