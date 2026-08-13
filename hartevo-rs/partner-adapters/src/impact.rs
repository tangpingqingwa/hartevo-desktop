//! impact.com partner-network adapter.
//!
//! The HTTP implementation is deliberately behind [`ImpactApi`]. The adapter
//! accepts only an opaque secret reference, so an account SID or auth token can
//! never become a domain fact or be serialized by this crate.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::callback::{CallbackObservation, CallbackRequest, CallbackSignatureScheme};
use crate::contract::{
    AuthorizationGrant, AuthorizationObservation, BlockedEnvironmentReason, FixtureScenario,
    NetworkProbeObservation, NetworkProbeRequest, NetworkProvenance, NetworkProvider,
    NetworkReadData, NetworkReadObservation, NetworkReadRequest, NetworkResource, NetworkScope,
    OpaqueSecretReference, PartnerNetworkError, ProgramExpectation, ReadCursor, ReadPage,
    TypedPartnerNetworkAdapter,
};
use crate::fixture::{PartnerFixtureWorld, sign_body};
use crate::support::{
    ProviderAdapter, ProviderApiError, ProviderProbeResponse, ProviderReadResponse,
    ProviderTransport,
};

pub const IMPACT_PARTNER_API_BASE: &str = "https://api.impact.com";
pub const IMPACT_PROGRAM_RESOURCE: &str = "/Mediapartners/:AccountSID/Campaigns";
pub const IMPACT_CONTRACT_RESOURCE: &str =
    "/Mediapartners/:AccountSID/Campaigns/:CampaignId/Contracts/Active";
pub const IMPACT_LINK_RESOURCE: &str = "/Mediapartners/:AccountSID/Ads";
pub const IMPACT_ACTION_RESOURCE: &str = "/Mediapartners/:AccountSID/Actions";
pub const IMPACT_CONVERSION_RESOURCE: &str = "/Advertisers/:AccountSID/Conversions";
pub const IMPACT_AUTH_SCHEME: &str = "Basic <opaque-secret-reference>";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImpactApiError {
    AuthorizationRequired,
    BlockedEnv(BlockedEnvironmentReason),
    ScopeRevoked,
    RateLimited,
    Unavailable,
}

impl ImpactApiError {
    fn into_provider_error(self) -> ProviderApiError {
        match self {
            Self::AuthorizationRequired => ProviderApiError::AuthorizationRequired,
            Self::BlockedEnv(reason) => ProviderApiError::BlockedEnv(reason),
            Self::ScopeRevoked => ProviderApiError::ScopeRevoked,
            Self::RateLimited => ProviderApiError::RateLimited,
            Self::Unavailable => ProviderApiError::Unavailable,
        }
    }
}

/// Credentials resolved from the OS/project secret store for one opaque SDK
/// reference. The token has no `Debug` or serde representation and is only
/// handed to the HTTP executor while constructing the Basic authorization
/// header.
#[derive(Clone, Eq, PartialEq)]
pub struct ImpactCredentials {
    account_sid: String,
    auth_token: Zeroizing<String>,
}

impl fmt::Debug for ImpactCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImpactCredentials")
            .field("account_sid", &self.account_sid)
            .field("auth_token", &"<redacted>")
            .finish()
    }
}

impl ImpactCredentials {
    pub fn new(
        account_sid: impl Into<String>,
        auth_token: impl Into<String>,
    ) -> Result<Self, ImpactApiError> {
        let account_sid = account_sid.into();
        let auth_token = auth_token.into();
        if account_sid.trim().is_empty()
            || auth_token.trim().is_empty()
            || account_sid.chars().any(char::is_control)
            || auth_token.chars().any(char::is_control)
        {
            return Err(ImpactApiError::AuthorizationRequired);
        }
        Ok(Self {
            account_sid,
            auth_token: Zeroizing::new(auth_token),
        })
    }

    pub fn account_sid(&self) -> &str {
        &self.account_sid
    }

    fn auth_token(&self) -> &str {
        &self.auth_token
    }
}

/// Resolves an SDK opaque secret reference without exposing provider
/// credentials to the connector scope, Mission, or receipt.
pub trait ImpactCredentialResolver: Clone + Send + Sync + 'static {
    fn resolve(
        &self,
        authorization: &OpaqueSecretReference,
        account_id: &crate::NetworkAccountId,
    ) -> Result<ImpactCredentials, ImpactApiError>;
}

/// Explicit absence of commercial credentials. This is the safe default for
/// deployments that have not wired an OS/project secret store yet.
#[derive(Clone, Debug, Default)]
pub struct MissingImpactCredentialResolver;

impl ImpactCredentialResolver for MissingImpactCredentialResolver {
    fn resolve(
        &self,
        _authorization: &OpaqueSecretReference,
        _account_id: &crate::NetworkAccountId,
    ) -> Result<ImpactCredentials, ImpactApiError> {
        Err(ImpactApiError::BlockedEnv(
            BlockedEnvironmentReason::CommercialAuthorizationMissing,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImpactHttpResponse {
    pub status: u16,
    pub body: String,
    pub retry_after_seconds: Option<u64>,
}

/// Injectable HTTP seam used by the production Impact client and by contract
/// tests. The default executor below is the only implementation that performs
/// network I/O; tests never need to pretend that a fixture is production.
pub trait ImpactHttpExecutor: Clone + Send + Sync + 'static {
    fn get(
        &self,
        url: &str,
        credentials: &ImpactCredentials,
    ) -> Result<ImpactHttpResponse, ImpactApiError>;
}

#[derive(Clone, Debug, Default)]
pub struct UreqImpactHttpExecutor;

impl ImpactHttpExecutor for UreqImpactHttpExecutor {
    fn get(
        &self,
        url: &str,
        credentials: &ImpactCredentials,
    ) -> Result<ImpactHttpResponse, ImpactApiError> {
        let basic = BASE64.encode(format!(
            "{}:{}",
            credentials.account_sid(),
            credentials.auth_token()
        ));
        let response = ureq::get(url)
            .set("Accept", "application/json")
            .set("Authorization", &format!("Basic {basic}"))
            .call();
        match response {
            Ok(response) => {
                let status = response.status();
                let body = response
                    .into_string()
                    .map_err(|_| ImpactApiError::Unavailable)?;
                if !(200..300).contains(&status) {
                    return Err(http_status_error(status));
                }
                Ok(ImpactHttpResponse {
                    status,
                    body,
                    retry_after_seconds: None,
                })
            }
            Err(ureq::Error::Status(status, response)) => {
                let _retry_after_seconds = response
                    .header("retry-after")
                    .and_then(|value| value.parse::<u64>().ok());
                let _ = response.into_string();
                if status == 429 {
                    Err(ImpactApiError::RateLimited)
                } else {
                    Err(http_status_error(status))
                }
            }
            Err(_) => Err(ImpactApiError::Unavailable),
        }
    }
}

/// Production Impact partner API client. It currently implements the
/// account/program-scoped Campaigns read, which is the first authenticated
/// read vertical slice; other resources remain explicitly disabled rather than
/// being represented by fixture data.
#[derive(Clone, Debug)]
pub struct ImpactHttpApi<R, E = UreqImpactHttpExecutor> {
    resolver: R,
    executor: E,
}

impl<R: ImpactCredentialResolver> ImpactHttpApi<R, UreqImpactHttpExecutor> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            executor: UreqImpactHttpExecutor,
        }
    }
}

impl<R, E> ImpactHttpApi<R, E>
where
    R: ImpactCredentialResolver,
    E: ImpactHttpExecutor,
{
    pub fn with_executor(resolver: R, executor: E) -> Self {
        Self { resolver, executor }
    }

    fn credentials(
        &self,
        authorization: &OpaqueSecretReference,
        scope: &NetworkScope,
    ) -> Result<ImpactCredentials, ImpactApiError> {
        let credentials = self.resolver.resolve(authorization, &scope.account_id)?;
        if credentials.account_sid() != scope.account_id.as_str() {
            return Err(ImpactApiError::AuthorizationRequired);
        }
        Ok(credentials)
    }

    fn fetch_programs(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkReadRequest,
    ) -> Result<ImpactReadResponse, ImpactApiError> {
        let credentials = self.credentials(authorization, &request.scope)?;
        let page_number = match request.cursor.as_ref() {
            Some(cursor) => parse_page_cursor(cursor.as_str())?,
            None => 1,
        };
        let url = program_page_url(&request.scope.account_id, page_number, request.limit);
        let response = self.executor.get(&url, &credentials)?;
        if !(200..300).contains(&response.status) {
            return Err(http_status_error(response.status));
        }
        let payload = serde_json::from_str::<Value>(&response.body)
            .map_err(|_| ImpactApiError::Unavailable)?;
        let campaigns = campaign_values(&payload).ok_or(ImpactApiError::Unavailable)?;
        let records = campaigns
            .iter()
            .map(|campaign| {
                program_record(campaign, &request.scope.account_id, request.observed_at)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let data = NetworkReadData::Programs { records };
        let source_digest =
            crate::contract::canonical_digest(&data).map_err(|_| ImpactApiError::Unavailable)?;
        let total_pages = metadata_u64(&payload, "@numpages").unwrap_or(page_number);
        let has_explicit_next =
            metadata_string(&payload, "@nextpageuri").is_some_and(|value| !value.trim().is_empty());
        let has_more =
            page_number < total_pages || (total_pages == page_number && has_explicit_next);
        let next_cursor = has_more
            .then(|| ReadCursor::new(format!("page:{}", page_number.saturating_add(1))))
            .transpose()
            .map_err(|_| ImpactApiError::Unavailable)?;
        let item_count =
            u32::try_from(data.item_count()).map_err(|_| ImpactApiError::Unavailable)?;
        let (program_id, program_revision, program_terms_digest) = request
            .scope
            .program_id
            .as_ref()
            .and_then(|program_id| {
                data_program(&data, program_id).map(|record| {
                    (
                        Some(record.id.clone()),
                        Some(record.revision),
                        Some(record.terms_digest.clone()),
                    )
                })
            })
            .unwrap_or((None, None, None));
        Ok(ImpactReadResponse {
            data,
            page: ReadPage {
                cursor: request.cursor.clone(),
                next_cursor,
                has_more,
                item_count,
            },
            program_id,
            program_revision,
            program_terms_digest,
            observed_at: request.observed_at,
            source_digest,
            provenance: NetworkProvenance::ProductionProvider,
        })
    }
}

impl<R, E> ImpactApi for ImpactHttpApi<R, E>
where
    R: ImpactCredentialResolver,
    E: ImpactHttpExecutor,
{
    fn probe(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkProbeRequest,
    ) -> Result<ImpactProbeResponse, ImpactApiError> {
        let read = self.fetch_programs(
            authorization,
            &NetworkReadRequest::new(
                request.scope.clone(),
                NetworkResource::Programs,
                request.observed_at,
            ),
        )?;
        Ok(ImpactProbeResponse {
            account_id: request.scope.account_id.clone(),
            program_id: read.program_id,
            program_revision: read.program_revision,
            program_terms_digest: read.program_terms_digest,
            program_digest: Some(read.source_digest),
            observed_at: read.observed_at,
            provenance: NetworkProvenance::ProductionProvider,
        })
    }

    fn read(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkReadRequest,
    ) -> Result<ImpactReadResponse, ImpactApiError> {
        if request.resource != NetworkResource::Programs {
            return Err(ImpactApiError::BlockedEnv(
                BlockedEnvironmentReason::OfficialApiCapabilityNotEnabled,
            ));
        }
        self.fetch_programs(authorization, request)
    }
}

pub fn program_page_url(account_id: &crate::NetworkAccountId, page: u64, page_size: u16) -> String {
    format!(
        "{IMPACT_PARTNER_API_BASE}/Mediapartners/{}/Campaigns?Page={page}&PageSize={page_size}",
        encode_path_segment(account_id.as_str())
    )
}

fn http_status_error(status: u16) -> ImpactApiError {
    match status {
        401 | 403 => ImpactApiError::AuthorizationRequired,
        429 => ImpactApiError::RateLimited,
        _ => ImpactApiError::Unavailable,
    }
}

fn encode_path_segment(value: &str) -> String {
    value.bytes().fold(String::new(), |mut encoded, byte| {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
            encoded.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
        }
        encoded
    })
}

fn parse_page_cursor(value: &str) -> Result<u64, ImpactApiError> {
    value
        .strip_prefix("page:")
        .and_then(|page| page.parse::<u64>().ok())
        .filter(|page| *page > 0)
        .ok_or(ImpactApiError::Unavailable)
}

fn campaign_values(payload: &Value) -> Option<&[Value]> {
    payload.as_array().map(Vec::as_slice).or_else(|| {
        ["Campaigns", "campaigns", "Records", "records"]
            .iter()
            .find_map(|key| {
                payload
                    .get(*key)
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
            })
    })
}

fn metadata_string(payload: &Value, key: &str) -> Option<String> {
    payload.get(key).and_then(value_string)
}

fn metadata_u64(payload: &Value, key: &str) -> Option<u64> {
    metadata_string(payload, key).and_then(|value| value.parse::<u64>().ok())
}

fn value_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn field_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(value_string))
}

fn program_record(
    campaign: &Value,
    account_id: &crate::NetworkAccountId,
    observed_at: DateTime<Utc>,
) -> Result<crate::ProgramRecord, ImpactApiError> {
    let program_id = field_string(campaign, &["CampaignId", "campaignId", "Id", "id"])
        .ok_or(ImpactApiError::Unavailable)
        .and_then(|value| {
            crate::ProgramId::parse(value).map_err(|_| ImpactApiError::Unavailable)
        })?;
    let source_digest = serde_json::to_vec(campaign)
        .map(|bytes| crate::contract::digest_bytes(&bytes))
        .map_err(|_| ImpactApiError::Unavailable)?;
    let revision = u64::from_str_radix(&source_digest[..16], 16)
        .unwrap_or(1)
        .max(1);
    let state = match field_string(campaign, &["State", "state"])
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "active" | "approved" | "joined" => crate::ProgramState::Active,
        "paused" | "pending" | "inactive" => crate::ProgramState::Paused,
        "expired" | "ended" | "terminated" => crate::ProgramState::Expired,
        _ => crate::ProgramState::Unknown,
    };
    Ok(crate::ProgramRecord {
        account_id: account_id.clone(),
        id: program_id,
        revision,
        state,
        terms_digest: source_digest.clone(),
        observed_at,
        source_digest,
    })
}

fn data_program<'a>(
    data: &'a NetworkReadData,
    program_id: &crate::ProgramId,
) -> Option<&'a crate::ProgramRecord> {
    match data {
        NetworkReadData::Programs { records } => {
            records.iter().find(|record| &record.id == program_id)
        }
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct ImpactProbeResponse {
    pub account_id: crate::NetworkAccountId,
    pub program_id: Option<crate::ProgramId>,
    pub program_revision: Option<u64>,
    pub program_terms_digest: Option<String>,
    pub program_digest: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub provenance: NetworkProvenance,
}

#[derive(Clone, Debug)]
pub struct ImpactReadResponse {
    pub data: NetworkReadData,
    pub page: ReadPage,
    pub program_id: Option<crate::ProgramId>,
    pub program_revision: Option<u64>,
    pub program_terms_digest: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub source_digest: String,
    pub provenance: NetworkProvenance,
}

/// Provider-specific transport seam for the official impact.com API.
pub trait ImpactApi: Clone + Send + Sync + 'static {
    fn probe(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkProbeRequest,
    ) -> Result<ImpactProbeResponse, ImpactApiError>;

    fn read(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkReadRequest,
    ) -> Result<ImpactReadResponse, ImpactApiError>;
}

#[derive(Clone, Debug, Default)]
pub struct UnavailableImpactApi;

impl ImpactApi for UnavailableImpactApi {
    fn probe(
        &self,
        _authorization: &OpaqueSecretReference,
        _request: &NetworkProbeRequest,
    ) -> Result<ImpactProbeResponse, ImpactApiError> {
        Err(ImpactApiError::BlockedEnv(
            BlockedEnvironmentReason::TransportNotConfigured,
        ))
    }

    fn read(
        &self,
        _authorization: &OpaqueSecretReference,
        _request: &NetworkReadRequest,
    ) -> Result<ImpactReadResponse, ImpactApiError> {
        Err(ImpactApiError::BlockedEnv(
            BlockedEnvironmentReason::TransportNotConfigured,
        ))
    }
}

#[derive(Clone, Debug)]
struct ImpactTransport<T>(T);

impl<T: ImpactApi> ProviderTransport for ImpactTransport<T> {
    fn probe(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkProbeRequest,
    ) -> Result<ProviderProbeResponse, ProviderApiError> {
        ImpactApi::probe(&self.0, authorization, request)
            .map(|response| ProviderProbeResponse {
                account_id: response.account_id,
                program_id: response.program_id,
                program_revision: response.program_revision,
                program_terms_digest: response.program_terms_digest,
                program_digest: response.program_digest,
                observed_at: response.observed_at,
                provenance: response.provenance,
            })
            .map_err(ImpactApiError::into_provider_error)
    }

    fn read(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkReadRequest,
    ) -> Result<ProviderReadResponse, ProviderApiError> {
        ImpactApi::read(&self.0, authorization, request)
            .map(|response| ProviderReadResponse {
                data: response.data,
                page: response.page,
                program_id: response.program_id,
                program_revision: response.program_revision,
                program_terms_digest: response.program_terms_digest,
                observed_at: response.observed_at,
                source_digest: response.source_digest,
                provenance: response.provenance,
            })
            .map_err(ImpactApiError::into_provider_error)
    }
}

#[derive(Clone, Debug)]
pub struct ImpactFixtureWorld {
    inner: PartnerFixtureWorld,
}

impl ImpactFixtureWorld {
    pub fn new(scenario: FixtureScenario, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: PartnerFixtureWorld::new(NetworkProvider::Impact, scenario, observed_at),
        }
    }

    pub fn default_fixture(observed_at: DateTime<Utc>) -> Self {
        Self::new(FixtureScenario::HappyPath, observed_at)
    }

    pub fn scope(&self) -> NetworkScope {
        self.inner.program_scope()
    }

    pub fn account_scope(&self) -> NetworkScope {
        self.inner.account_scope()
    }

    pub fn current_program_expectation(&self) -> ProgramExpectation {
        self.inner.current_program_expectation()
    }

    pub fn original_program_expectation(&self) -> ProgramExpectation {
        self.inner.original_program_expectation()
    }

    pub fn authorization(&self) -> AuthorizationGrant {
        AuthorizationGrant::fixture(
            self.inner.account_scope(),
            crate::contract::default_fixture_expiry(self.inner.observed_at),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn callback_body(
        &self,
        event_id: &str,
        event_type: &str,
        occurred_at: DateTime<Utc>,
        conversion_id: Option<&str>,
        order_id: Option<&str>,
        action_id: Option<&str>,
        commission_id: Option<&str>,
        reversal_id: Option<&str>,
        payout_id: Option<&str>,
        amount_minor: Option<i64>,
    ) -> Vec<u8> {
        self.inner.callback_body(
            event_id,
            event_type,
            occurred_at,
            conversion_id,
            order_id,
            action_id,
            commission_id,
            reversal_id,
            payout_id,
            amount_minor,
        )
    }

    pub fn sign_callback(&self, scheme: CallbackSignatureScheme, body: &[u8]) -> String {
        sign_body(scheme, body)
    }

    pub fn callback_key() -> &'static [u8] {
        PartnerFixtureWorld::callback_key()
    }
}

impl ImpactApi for ImpactFixtureWorld {
    fn probe(
        &self,
        _authorization: &OpaqueSecretReference,
        request: &NetworkProbeRequest,
    ) -> Result<ImpactProbeResponse, ImpactApiError> {
        if self.inner.is_scope_revoked() {
            return Err(ImpactApiError::ScopeRevoked);
        }
        Ok(ImpactProbeResponse {
            account_id: self.inner.account_id.clone(),
            program_id: Some(self.inner.program_id.clone()),
            program_revision: Some(self.inner.current_program_revision),
            program_terms_digest: Some(self.inner.current_terms_digest.clone()),
            program_digest: Some(self.inner.source_digest(NetworkResource::Programs)),
            observed_at: request.observed_at,
            provenance: NetworkProvenance::Fixture,
        })
    }

    fn read(
        &self,
        _authorization: &OpaqueSecretReference,
        request: &NetworkReadRequest,
    ) -> Result<ImpactReadResponse, ImpactApiError> {
        if self.inner.is_scope_revoked() {
            return Err(ImpactApiError::ScopeRevoked);
        }
        let (data, page) = self
            .inner
            .read(request.resource)
            .map_err(|_| ImpactApiError::Unavailable)?;
        Ok(ImpactReadResponse {
            data,
            page,
            program_id: Some(self.inner.program_id.clone()),
            program_revision: Some(self.inner.current_program_revision),
            program_terms_digest: Some(self.inner.current_terms_digest.clone()),
            observed_at: request.observed_at,
            source_digest: self.inner.source_digest(request.resource),
            provenance: NetworkProvenance::Fixture,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ImpactAdapter<C> {
    inner: ProviderAdapter<ImpactTransport<C>>,
}

impl<C: ImpactApi> ImpactAdapter<C> {
    pub fn new(client: C) -> Self {
        Self {
            inner: ProviderAdapter::new(NetworkProvider::Impact, ImpactTransport(client)),
        }
    }

    pub fn callback_body_digest(body: &[u8]) -> String {
        crate::contract::digest_bytes(body)
    }
}

impl ImpactAdapter<UnavailableImpactApi> {
    pub fn without_authorization() -> Self {
        Self::new(UnavailableImpactApi)
    }
}

impl ImpactAdapter<ImpactFixtureWorld> {
    pub fn fixture(scenario: FixtureScenario, observed_at: DateTime<Utc>) -> Self {
        Self::new(ImpactFixtureWorld::new(scenario, observed_at))
    }
}

impl<C: ImpactApi> TypedPartnerNetworkAdapter for ImpactAdapter<C> {
    fn provider(&self) -> NetworkProvider {
        NetworkProvider::Impact
    }

    fn authorize(
        &mut self,
        grant: AuthorizationGrant,
        observed_at: DateTime<Utc>,
    ) -> Result<AuthorizationObservation, PartnerNetworkError> {
        self.inner.authorize(grant, observed_at)
    }

    fn probe(
        &self,
        request: NetworkProbeRequest,
    ) -> Result<NetworkProbeObservation, PartnerNetworkError> {
        self.inner.probe(request)
    }

    fn read(
        &self,
        request: NetworkReadRequest,
    ) -> Result<NetworkReadObservation, PartnerNetworkError> {
        self.inner.read(request)
    }

    fn handle_callback(
        &mut self,
        request: CallbackRequest<'_>,
    ) -> Result<CallbackObservation, PartnerNetworkError> {
        self.inner.handle_callback(
            &request,
            &[
                CallbackSignatureScheme::ImpactHookJwsDetached,
                CallbackSignatureScheme::ImpactHookHmacSha1,
                CallbackSignatureScheme::FixtureHmacSha256,
            ],
        )
    }

    fn revoke(
        &mut self,
        scope: &NetworkScope,
        observed_at: DateTime<Utc>,
    ) -> Result<AuthorizationObservation, PartnerNetworkError> {
        self.inner.revoke(scope, observed_at)
    }

    fn accepted_callbacks(&self) -> Vec<crate::CallbackEvent> {
        self.inner.accepted_callbacks()
    }
}
