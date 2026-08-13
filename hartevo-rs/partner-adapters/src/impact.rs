//! impact.com partner-network adapter.
//!
//! The HTTP implementation is deliberately behind [`ImpactApi`]. The adapter
//! accepts only an opaque secret reference, so an account SID or auth token can
//! never become a domain fact or be serialized by this crate.

use chrono::{DateTime, Utc};

use crate::callback::{CallbackObservation, CallbackRequest, CallbackSignatureScheme};
use crate::contract::{
    AuthorizationGrant, AuthorizationObservation, BlockedEnvironmentReason, FixtureScenario,
    NetworkProbeObservation, NetworkProbeRequest, NetworkProvenance, NetworkProvider,
    NetworkReadData, NetworkReadObservation, NetworkReadRequest, NetworkResource, NetworkScope,
    OpaqueSecretReference, PartnerNetworkError, ProgramExpectation, ReadPage,
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
    Unavailable,
}

impl ImpactApiError {
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
