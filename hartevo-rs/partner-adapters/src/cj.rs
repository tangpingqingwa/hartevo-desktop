//! Commission Junction (CJ) partner-network adapter skeleton.
//!
//! CJ REST APIs use a personal access token in the `Authorization: Bearer`
//! header. The token is represented only by an opaque reference here; a real
//! transport must still prove account and advertiser relationship scope.

use chrono::{DateTime, Utc};

use crate::callback::{CallbackObservation, CallbackRequest, CallbackSignatureScheme};
use crate::contract::{
    AuthorizationGrant, AuthorizationObservation, BlockedEnvironmentReason, FixtureScenario,
    NetworkProbeObservation, NetworkProbeRequest, NetworkProvenance, NetworkProvider,
    NetworkReadData, NetworkReadObservation, NetworkReadRequest, NetworkResource, NetworkScope,
    OpaqueSecretReference, PartnerNetworkAdapter, PartnerNetworkError, ProgramExpectation,
    ReadPage,
};
use crate::fixture::{PartnerFixtureWorld, sign_body};
use crate::support::{
    ProviderAdapter, ProviderApiError, ProviderProbeResponse, ProviderReadResponse,
    ProviderTransport,
};

pub const CJ_LINK_SEARCH_API: &str = "https://link-search.api.cj.com/v2/link-search";
pub const CJ_COMMISSION_DETAIL_API: &str = "https://commissions.api.cj.com/query";
pub const CJ_ADVERTISER_LOOKUP_API: &str =
    "https://advertiser-lookup.api.cj.com/v2/advertiser-lookup";
pub const CJ_AUTH_SCHEME: &str = "Bearer <opaque-secret-reference>";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CjApiError {
    AuthorizationRequired,
    BlockedEnv(BlockedEnvironmentReason),
    ScopeRevoked,
    Unavailable,
}

impl CjApiError {
    fn into_provider_error(self) -> ProviderApiError {
        match self {
            Self::AuthorizationRequired => ProviderApiError::AuthorizationRequired,
            Self::BlockedEnv(reason) => ProviderApiError::BlockedEnv(reason),
            Self::ScopeRevoked => ProviderApiError::ScopeRevoked,
            Self::Unavailable => ProviderApiError::Unavailable,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CjProbeResponse {
    pub account_id: crate::NetworkAccountId,
    pub program_id: Option<crate::ProgramId>,
    pub program_revision: Option<u64>,
    pub program_terms_digest: Option<String>,
    pub program_digest: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub provenance: NetworkProvenance,
}

#[derive(Clone, Debug)]
pub struct CjReadResponse {
    pub data: NetworkReadData,
    pub page: ReadPage,
    pub program_id: Option<crate::ProgramId>,
    pub program_revision: Option<u64>,
    pub program_terms_digest: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub source_digest: String,
    pub provenance: NetworkProvenance,
}

/// Provider-specific seam for CJ Link Search, advertiser lookup, and
/// commission-detail APIs.
pub trait CjApi: Clone + Send + Sync + 'static {
    fn probe(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkProbeRequest,
    ) -> Result<CjProbeResponse, CjApiError>;

    fn read(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkReadRequest,
    ) -> Result<CjReadResponse, CjApiError>;
}

#[derive(Clone, Debug, Default)]
pub struct UnavailableCjApi;

impl CjApi for UnavailableCjApi {
    fn probe(
        &self,
        _authorization: &OpaqueSecretReference,
        _request: &NetworkProbeRequest,
    ) -> Result<CjProbeResponse, CjApiError> {
        Err(CjApiError::BlockedEnv(
            BlockedEnvironmentReason::TransportNotConfigured,
        ))
    }

    fn read(
        &self,
        _authorization: &OpaqueSecretReference,
        _request: &NetworkReadRequest,
    ) -> Result<CjReadResponse, CjApiError> {
        Err(CjApiError::BlockedEnv(
            BlockedEnvironmentReason::TransportNotConfigured,
        ))
    }
}

#[derive(Clone, Debug)]
struct CjTransport<T>(T);

impl<T: CjApi> ProviderTransport for CjTransport<T> {
    fn probe(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkProbeRequest,
    ) -> Result<ProviderProbeResponse, ProviderApiError> {
        CjApi::probe(&self.0, authorization, request)
            .map(|response| ProviderProbeResponse {
                account_id: response.account_id,
                program_id: response.program_id,
                program_revision: response.program_revision,
                program_terms_digest: response.program_terms_digest,
                program_digest: response.program_digest,
                observed_at: response.observed_at,
                provenance: response.provenance,
            })
            .map_err(CjApiError::into_provider_error)
    }

    fn read(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkReadRequest,
    ) -> Result<ProviderReadResponse, ProviderApiError> {
        CjApi::read(&self.0, authorization, request)
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
            .map_err(CjApiError::into_provider_error)
    }
}

#[derive(Clone, Debug)]
pub struct CjFixtureWorld {
    inner: PartnerFixtureWorld,
}

impl CjFixtureWorld {
    pub fn new(scenario: FixtureScenario, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: PartnerFixtureWorld::new(NetworkProvider::Cj, scenario, observed_at),
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

impl CjApi for CjFixtureWorld {
    fn probe(
        &self,
        _authorization: &OpaqueSecretReference,
        request: &NetworkProbeRequest,
    ) -> Result<CjProbeResponse, CjApiError> {
        if self.inner.is_scope_revoked() {
            return Err(CjApiError::ScopeRevoked);
        }
        Ok(CjProbeResponse {
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
    ) -> Result<CjReadResponse, CjApiError> {
        if self.inner.is_scope_revoked() {
            return Err(CjApiError::ScopeRevoked);
        }
        let (data, page) = self
            .inner
            .read(request.resource)
            .map_err(|_| CjApiError::Unavailable)?;
        Ok(CjReadResponse {
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
pub struct CjAdapter<C> {
    inner: ProviderAdapter<CjTransport<C>>,
}

impl<C: CjApi> CjAdapter<C> {
    pub fn new(client: C) -> Self {
        Self {
            inner: ProviderAdapter::new(NetworkProvider::Cj, CjTransport(client)),
        }
    }
}

impl CjAdapter<UnavailableCjApi> {
    pub fn without_authorization() -> Self {
        Self::new(UnavailableCjApi)
    }
}

impl CjAdapter<CjFixtureWorld> {
    pub fn fixture(scenario: FixtureScenario, observed_at: DateTime<Utc>) -> Self {
        Self::new(CjFixtureWorld::new(scenario, observed_at))
    }
}

impl<C: CjApi> PartnerNetworkAdapter for CjAdapter<C> {
    fn provider(&self) -> NetworkProvider {
        NetworkProvider::Cj
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
        self.inner
            .handle_callback(&request, &[CallbackSignatureScheme::FixtureHmacSha256])
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
