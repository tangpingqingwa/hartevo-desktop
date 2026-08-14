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

#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub struct UreqImpactHttpExecutor {
    loopback_base_url: Option<String>,
}

#[cfg(not(test))]
#[derive(Clone, Debug, Default)]
pub struct UreqImpactHttpExecutor;

impl UreqImpactHttpExecutor {
    #[cfg(test)]
    fn loopback(base_url: impl Into<String>) -> Result<Self, ImpactApiError> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        if !base_url.starts_with("http://127.0.0.1:")
            || base_url.contains(['?', '#'])
            || base_url.ends_with(':')
        {
            return Err(ImpactApiError::Unavailable);
        }
        Ok(Self {
            loopback_base_url: Some(base_url),
        })
    }

    #[cfg(test)]
    fn request_url(&self, official_url: &str) -> Result<String, ImpactApiError> {
        let Some(base_url) = &self.loopback_base_url else {
            return Ok(official_url.to_owned());
        };
        let suffix = official_url
            .strip_prefix(IMPACT_PARTNER_API_BASE)
            .ok_or(ImpactApiError::Unavailable)?;
        Ok(format!("{base_url}{suffix}"))
    }
}

impl ImpactHttpExecutor for UreqImpactHttpExecutor {
    fn get(
        &self,
        url: &str,
        credentials: &ImpactCredentials,
    ) -> Result<ImpactHttpResponse, ImpactApiError> {
        #[cfg(test)]
        let request_url = self.request_url(url)?;
        #[cfg(not(test))]
        let request_url = url.to_owned();
        let basic = BASE64.encode(format!(
            "{}:{}",
            credentials.account_sid(),
            credentials.auth_token()
        ));
        let response = ureq::get(&request_url)
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
            #[cfg(test)]
            executor: UreqImpactHttpExecutor::default(),
            #[cfg(not(test))]
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};

    use chrono::{Duration, TimeZone};
    use hartevo_connector_sdk::{
        BeginAuthRequest, ConnectorAdapter, ConnectorAuth, ConnectorWorker, ProbeRequest,
        ProviderAdapterRegistry, ProviderProvenanceClass, SecretReference,
    };
    use hartevo_domain_kernel::{Mission, MissionContract, MissionId, ProjectId, TenantId};

    use super::*;
    use crate::{
        ConnectorAdapterBridge, DurablePartnerReadCursor, ImpactProgramReadRequest,
        ImpactProgramReadServiceDefinition, NetworkAccountId, NetworkResource, PartnerReadBudget,
        PartnerReadClassification, PartnerReadScope, ProgramId,
    };

    #[derive(Clone, Debug, Default)]
    struct LoopbackImpactCredentialResolver;

    impl ImpactCredentialResolver for LoopbackImpactCredentialResolver {
        fn resolve(
            &self,
            _authorization: &OpaqueSecretReference,
            _account_id: &NetworkAccountId,
        ) -> Result<ImpactCredentials, ImpactApiError> {
            ImpactCredentials::new("impact-account-1", "test-only-token")
        }
    }

    struct LoopbackServer {
        base_url: String,
        join: Option<JoinHandle<()>>,
    }

    impl LoopbackServer {
        fn start(expected_requests: usize) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
            let port = listener.local_addr().expect("loopback address").port();
            let join = thread::spawn(move || {
                for _ in 0..expected_requests {
                    let (mut stream, _) = listener.accept().expect("loopback request");
                    let request = read_http_request(&mut stream);
                    let body = loopback_response(&request);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream
                        .write_all(response.as_bytes())
                        .expect("loopback response");
                    stream.flush().expect("loopback flush");
                }
            });
            Self {
                base_url: format!("http://127.0.0.1:{port}"),
                join: Some(join),
            }
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn finish(mut self) {
            self.join
                .take()
                .expect("loopback join handle")
                .join()
                .expect("loopback server");
        }
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let count = stream.read(&mut buffer).expect("loopback request bytes");
            assert!(count > 0, "loopback request ended before headers");
            bytes.extend_from_slice(&buffer[..count]);
            assert!(
                bytes.len() <= 16 * 1024,
                "loopback request headers too large"
            );
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8(bytes).expect("loopback request utf8")
    }

    fn loopback_response(request: &str) -> String {
        let mut lines = request.split("\r\n");
        let request_line = lines.next().expect("loopback request line");
        let mut request_parts = request_line.split_whitespace();
        assert_eq!(request_parts.next(), Some("GET"));
        let target = request_parts.next().expect("loopback target");
        assert_eq!(request_parts.next(), Some("HTTP/1.1"));
        let (path, query) = target.split_once('?').expect("loopback query");
        assert_eq!(path, "/Mediapartners/impact-account-1/Campaigns");

        let headers = lines
            .take_while(|line| !line.is_empty())
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
            .collect::<BTreeMap<_, _>>();
        let expected_authorization = format!(
            "Basic {}",
            BASE64.encode("impact-account-1:test-only-token")
        );
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some(expected_authorization.as_str())
        );
        assert_eq!(
            headers.get("accept").map(String::as_str),
            Some("application/json")
        );

        let query = query
            .split('&')
            .filter_map(|part| part.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(query.get("PageSize").map(String::as_str), Some("100"));
        let page = query
            .get("Page")
            .expect("loopback page")
            .parse::<u64>()
            .expect("loopback page integer");
        assert!((1..=2).contains(&page));

        match page {
            1 => serde_json::json!({
                "@page": "1",
                "@numpages": "2",
                "@nextpageuri": "/Mediapartners/impact-account-1/Campaigns?Page=2&PageSize=100",
                "Campaigns": [{"CampaignId": "impact-program-1", "State": "ACTIVE"}]
            }),
            2 => serde_json::json!({
                "@page": "2",
                "@numpages": "2",
                "Campaigns": [{"CampaignId": "impact-program-1", "State": "ACTIVE"}]
            }),
            _ => unreachable!("loopback page is bounded above"),
        }
        .to_string()
    }

    fn observed_at() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc
            .with_ymd_and_hms(2026, 8, 14, 8, 0, 0)
            .single()
            .expect("valid loopback timestamp")
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn official_http_loopback_mission_pages_reconcile_exactly_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let at = observed_at();
        let server = LoopbackServer::start(5);
        let executor =
            UreqImpactHttpExecutor::loopback(server.base_url()).expect("valid loopback transport");
        let api = ImpactHttpApi::with_executor(LoopbackImpactCredentialResolver, executor);
        let account_id = NetworkAccountId::from_stable("impact-account-1");
        let program_id = ProgramId::from_stable("impact-program-1");
        let read_scope = PartnerReadScope::new(
            "tenant-impact-loopback",
            "project-impact-loopback",
            "mission-impact-loopback",
            account_id,
            Some(program_id),
        )?;
        let sdk_scope = read_scope.connector_scope()?;
        let bridge = ConnectorAdapterBridge::new(ImpactAdapter::new(api.clone()))?;
        let descriptor = bridge.descriptor().clone();
        let registry = ProviderAdapterRegistry::new(
            "partner-impact-loopback-read-1",
            descriptor.registrations().to_vec(),
        )?;
        let definition = ImpactProgramReadServiceDefinition::new(at)?;
        assert_eq!(
            definition.connection_state(&registry),
            crate::PartnerReadConnectionState::Registered
        );
        let mut worker = ConnectorWorker::new(
            "worker-impact-loopback-read",
            bridge,
            registry,
            sdk_scope.clone(),
            at,
            at + Duration::minutes(5),
        )?;
        let secret = SecretReference::new("secret-ref-impact-loopback", sdk_scope.clone(), 1)?;
        let lease = ConnectorAuth::issue_credential_lease(
            &secret,
            descriptor.identity().clone(),
            "credential-lease-impact-loopback",
            1,
            at,
            at + Duration::minutes(5),
        )?;
        let dispatch = worker.dispatch_fence();
        let session = worker.begin_auth(BeginAuthRequest {
            dispatch: dispatch.clone(),
            scope: sdk_scope.clone(),
            secret_reference: secret.clone(),
            credential_lease: lease.clone(),
            auth_revision: 1,
            issued_at: at,
            expires_at: at + Duration::minutes(5),
        })?;
        let probe = worker.probe(ProbeRequest {
            dispatch,
            scope: sdk_scope,
            secret_reference: secret,
            credential_lease: lease,
            session,
            probe_revision: 1,
            result_id: "probe-result-impact-loopback".to_owned(),
            at: at + Duration::seconds(1),
        })?;
        assert_eq!(
            probe.provenance_class(),
            ProviderProvenanceClass::ProductionProvider
        );

        let mission = Mission::compile(
            TenantId::from("tenant-impact-loopback"),
            MissionId::from("mission-impact-loopback"),
            ProjectId::from("project-impact-loopback"),
            "reconcile Impact loopback program pages",
            MissionContract::bootstrap(
                "read Impact partner programs",
                [crate::read::PARTNER_PROGRAM_READ_MISSION_CAPABILITY.to_owned()],
                at,
            ),
            at,
        )?;
        let budget = || PartnerReadBudget::new(3, at + Duration::minutes(1), 3, 3);
        let first_request =
            ImpactProgramReadRequest::new(read_scope.clone(), at + Duration::seconds(1))?
                .with_budget(budget()?);
        let first = definition.read_mission(&mut worker, &mission, &probe, &first_request)?;
        first.validate()?;
        assert_eq!(
            first.classification,
            PartnerReadClassification::ProductionAuthenticated
        );
        assert_eq!(first.scope.account_id.as_str(), "impact-account-1");
        assert_eq!(
            first.scope.program_id.as_ref().map(ProgramId::as_str),
            Some("impact-program-1")
        );
        assert!(first.source_uri.starts_with(IMPACT_PARTNER_API_BASE));
        let cursor = first.next_cursor.clone().expect("first page cursor");
        let persisted_cursor: DurablePartnerReadCursor =
            serde_json::from_slice(&serde_json::to_vec(&cursor)?)?;
        let request_digest = first.request_digest.clone();
        persisted_cursor.validate_for(&definition.service_id, &read_scope, &request_digest)?;

        let second_request = first_request
            .clone()
            .with_cursor(persisted_cursor.clone())
            .with_budget(budget()?);
        let second = definition.read_mission(&mut worker, &mission, &probe, &second_request)?;
        second.validate()?;
        assert_eq!(second.page_sequence, 2);
        assert!(second.next_cursor.is_none());

        let second_replay = definition.read_mission(
            &mut worker,
            &mission,
            &probe,
            &second_request.with_budget(budget()?),
        )?;
        second_replay.validate()?;
        let first_replay = definition.read_mission(
            &mut worker,
            &mission,
            &probe,
            &first_request.with_budget(budget()?),
        )?;
        first_replay.validate()?;
        assert_eq!(first_replay.receipt_digest, first.receipt_digest);
        assert_eq!(second_replay.receipt_digest, second.receipt_digest);

        let mut accepted = BTreeMap::new();
        for receipt in [second, first, second_replay, first_replay] {
            if let Some(previous_digest) =
                accepted.insert(receipt.page_sequence, receipt.receipt_digest.clone())
            {
                assert_eq!(previous_digest, receipt.receipt_digest);
            }
        }
        assert_eq!(accepted.keys().copied().collect::<Vec<_>>(), [1, 2]);

        let mut rolled_back = persisted_cursor;
        rolled_back.page = 1;
        assert_eq!(
            rolled_back.validate_for(&definition.service_id, &read_scope, &request_digest),
            Err(crate::PartnerReadError::InvalidCursor)
        );

        let authorization = OpaqueSecretReference::new("secret-ref-impact-loopback", 1)?;
        for resource in [
            NetworkResource::Actions,
            NetworkResource::Conversions,
            NetworkResource::Reports,
        ] {
            assert!(matches!(
                api.read(
                    &authorization,
                    &NetworkReadRequest::new(read_scope.network_scope()?, resource, at),
                ),
                Err(ImpactApiError::BlockedEnv(
                    BlockedEnvironmentReason::OfficialApiCapabilityNotEnabled
                ))
            ));
        }
        server.finish();
        Ok(())
    }
}
