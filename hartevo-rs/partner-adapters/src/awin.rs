//! Awin publisher/advertiser API adapter skeleton.
//!
//! Awin exposes user OAuth2 bearer access for most APIs and an `x-api-key`
//! path for the Create Transactions API. Both credentials stay behind the
//! opaque [`OpaqueSecretReference`]; this module does not infer access from a
//! configured string.

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

pub const AWIN_API_BASE: &str = "https://api.awin.com";
pub const AWIN_PUBLISHER_TRANSACTIONS_RESOURCE: &str = "/publishers/:PublisherId/transactions";
pub const AWIN_ADVERTISER_TRANSACTIONS_RESOURCE: &str = "/advertisers/:AdvertiserId/transactions";
pub const AWIN_CONVERSION_RESOURCE: &str = "/s2s/advertiser/:AdvertiserId/orders";
pub const AWIN_OAUTH_AUTH_SCHEME: &str = "Bearer <opaque-secret-reference>";
pub const AWIN_CREATE_TRANSACTIONS_AUTH_SCHEME: &str = "x-api-key: <opaque-secret-reference>";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwinApiError {
    AuthorizationRequired,
    BlockedEnv(BlockedEnvironmentReason),
    ScopeRevoked,
    Unavailable,
}

impl AwinApiError {
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
pub struct AwinProbeResponse {
    pub account_id: crate::NetworkAccountId,
    pub program_id: Option<crate::ProgramId>,
    pub program_revision: Option<u64>,
    pub program_terms_digest: Option<String>,
    pub program_digest: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub provenance: NetworkProvenance,
}

#[derive(Clone, Debug)]
pub struct AwinReadResponse {
    pub data: NetworkReadData,
    pub page: ReadPage,
    pub program_id: Option<crate::ProgramId>,
    pub program_revision: Option<u64>,
    pub program_terms_digest: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub source_digest: String,
    pub provenance: NetworkProvenance,
}

/// Provider-specific seam for the official Awin APIs.
pub trait AwinApi: Clone + Send + Sync + 'static {
    fn probe(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkProbeRequest,
    ) -> Result<AwinProbeResponse, AwinApiError>;

    fn read(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkReadRequest,
    ) -> Result<AwinReadResponse, AwinApiError>;
}

#[derive(Clone, Debug, Default)]
pub struct UnavailableAwinApi;

impl AwinApi for UnavailableAwinApi {
    fn probe(
        &self,
        _authorization: &OpaqueSecretReference,
        _request: &NetworkProbeRequest,
    ) -> Result<AwinProbeResponse, AwinApiError> {
        Err(AwinApiError::BlockedEnv(
            BlockedEnvironmentReason::TransportNotConfigured,
        ))
    }

    fn read(
        &self,
        _authorization: &OpaqueSecretReference,
        _request: &NetworkReadRequest,
    ) -> Result<AwinReadResponse, AwinApiError> {
        Err(AwinApiError::BlockedEnv(
            BlockedEnvironmentReason::TransportNotConfigured,
        ))
    }
}

#[derive(Clone, Debug)]
struct AwinTransport<T>(T);

impl<T: AwinApi> ProviderTransport for AwinTransport<T> {
    fn probe(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkProbeRequest,
    ) -> Result<ProviderProbeResponse, ProviderApiError> {
        AwinApi::probe(&self.0, authorization, request)
            .map(|response| ProviderProbeResponse {
                account_id: response.account_id,
                program_id: response.program_id,
                program_revision: response.program_revision,
                program_terms_digest: response.program_terms_digest,
                program_digest: response.program_digest,
                observed_at: response.observed_at,
                provenance: response.provenance,
            })
            .map_err(AwinApiError::into_provider_error)
    }

    fn read(
        &self,
        authorization: &OpaqueSecretReference,
        request: &NetworkReadRequest,
    ) -> Result<ProviderReadResponse, ProviderApiError> {
        AwinApi::read(&self.0, authorization, request)
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
            .map_err(AwinApiError::into_provider_error)
    }
}

#[derive(Clone, Debug)]
pub struct AwinFixtureWorld {
    inner: PartnerFixtureWorld,
}

impl AwinFixtureWorld {
    pub fn new(scenario: FixtureScenario, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: PartnerFixtureWorld::new(NetworkProvider::Awin, scenario, observed_at),
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

impl AwinApi for AwinFixtureWorld {
    fn probe(
        &self,
        _authorization: &OpaqueSecretReference,
        request: &NetworkProbeRequest,
    ) -> Result<AwinProbeResponse, AwinApiError> {
        if self.inner.is_scope_revoked() {
            return Err(AwinApiError::ScopeRevoked);
        }
        Ok(AwinProbeResponse {
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
    ) -> Result<AwinReadResponse, AwinApiError> {
        if self.inner.is_scope_revoked() {
            return Err(AwinApiError::ScopeRevoked);
        }
        let (data, page) = self
            .inner
            .read(request.resource)
            .map_err(|_| AwinApiError::Unavailable)?;
        Ok(AwinReadResponse {
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
pub struct AwinAdapter<C> {
    inner: ProviderAdapter<AwinTransport<C>>,
}

impl<C: AwinApi> AwinAdapter<C> {
    pub fn new(client: C) -> Self {
        Self {
            inner: ProviderAdapter::new(NetworkProvider::Awin, AwinTransport(client)),
        }
    }

    pub fn with_state_file(
        client: C,
        path: impl Into<std::path::PathBuf>,
    ) -> Result<Self, PartnerNetworkError> {
        Ok(Self {
            inner: ProviderAdapter::with_state_file(
                NetworkProvider::Awin,
                AwinTransport(client),
                path,
            )?,
        })
    }

    pub fn unmount(&mut self) -> Result<(), PartnerNetworkError> {
        self.inner.unmount()
    }

    pub fn durable_receipts(&self) -> Vec<crate::DurableReceipt> {
        self.inner.durable_receipts()
    }
}

impl AwinAdapter<UnavailableAwinApi> {
    pub fn without_authorization() -> Self {
        Self::new(UnavailableAwinApi)
    }
}

impl AwinAdapter<AwinFixtureWorld> {
    pub fn fixture(scenario: FixtureScenario, observed_at: DateTime<Utc>) -> Self {
        Self::new(AwinFixtureWorld::new(scenario, observed_at))
    }
}

impl<C: AwinApi> TypedPartnerNetworkAdapter for AwinAdapter<C> {
    fn provider(&self) -> NetworkProvider {
        NetworkProvider::Awin
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
