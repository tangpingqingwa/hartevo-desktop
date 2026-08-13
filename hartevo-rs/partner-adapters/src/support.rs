use chrono::{DateTime, Utc};

use crate::callback::{CallbackObservation, CallbackRequest, CallbackSignatureScheme};
use crate::contract::{
    AuthorizationGrant, AuthorizationObservation, BlockedEnvironmentReason, EvidenceLevel,
    NetworkCapability, NetworkProbeObservation, NetworkProbeRequest, NetworkProbeStatus,
    NetworkProvenance, NetworkProvider, NetworkReadData, NetworkReadObservation,
    NetworkReadRequest, NetworkScope, PartnerNetworkError, ReadPage, validate_scope_record_ids,
    verify_program_expectation,
};
use crate::state::AdapterState;

#[derive(Clone, Debug)]
pub(crate) struct ProviderProbeResponse {
    pub account_id: crate::NetworkAccountId,
    pub program_id: Option<crate::ProgramId>,
    pub program_revision: Option<u64>,
    pub program_terms_digest: Option<String>,
    pub program_digest: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub provenance: NetworkProvenance,
}

#[derive(Clone, Debug)]
pub(crate) struct ProviderReadResponse {
    pub data: NetworkReadData,
    pub page: ReadPage,
    pub program_id: Option<crate::ProgramId>,
    pub program_revision: Option<u64>,
    pub program_terms_digest: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub source_digest: String,
    pub provenance: NetworkProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProviderApiError {
    AuthorizationRequired,
    BlockedEnv(BlockedEnvironmentReason),
    ScopeRevoked,
    RateLimited,
    Unavailable,
}

pub(crate) trait ProviderTransport: Clone + Send + Sync + 'static {
    fn probe(
        &self,
        authorization: &crate::OpaqueSecretReference,
        request: &NetworkProbeRequest,
    ) -> Result<ProviderProbeResponse, ProviderApiError>;

    fn read(
        &self,
        authorization: &crate::OpaqueSecretReference,
        request: &NetworkReadRequest,
    ) -> Result<ProviderReadResponse, ProviderApiError>;
}

#[derive(Clone, Debug)]
pub(crate) struct ProviderAdapter<C> {
    provider: NetworkProvider,
    client: C,
    state: AdapterState,
}

impl<C: ProviderTransport> ProviderAdapter<C> {
    pub(crate) fn new(provider: NetworkProvider, client: C) -> Self {
        Self {
            provider,
            client,
            state: AdapterState::new(provider),
        }
    }

    pub(crate) fn authorize(
        &mut self,
        grant: AuthorizationGrant,
        observed_at: DateTime<Utc>,
    ) -> Result<AuthorizationObservation, PartnerNetworkError> {
        self.state.authorize(grant, observed_at)
    }

    pub(crate) fn probe(
        &self,
        request: NetworkProbeRequest,
    ) -> Result<NetworkProbeObservation, PartnerNetworkError> {
        request.validate()?;
        let authorization = match self.state.grant_for(
            &request.scope,
            NetworkCapability::Probe,
            request.observed_at,
        ) {
            Ok(grant) => grant,
            Err(
                PartnerNetworkError::AuthorizationRequired { .. }
                | PartnerNetworkError::AuthorizationExpired,
            ) => {
                return Ok(denied_probe(
                    self.provider,
                    request,
                    NetworkProbeStatus::AuthorizationRequired,
                ));
            }
            Err(PartnerNetworkError::ScopeRevoked) => {
                return Ok(denied_probe(
                    self.provider,
                    request,
                    NetworkProbeStatus::ScopeRevoked,
                ));
            }
            Err(error) => return Err(error),
        };
        let response = match self.client.probe(&authorization.secret_reference, &request) {
            Ok(response) => response,
            Err(ProviderApiError::AuthorizationRequired) => {
                return Ok(denied_probe(
                    self.provider,
                    request,
                    NetworkProbeStatus::AuthorizationRequired,
                ));
            }
            Err(ProviderApiError::ScopeRevoked) => {
                return Ok(denied_probe(
                    self.provider,
                    request,
                    NetworkProbeStatus::ScopeRevoked,
                ));
            }
            Err(ProviderApiError::BlockedEnv(_)) => {
                return Ok(denied_probe(
                    self.provider,
                    request,
                    NetworkProbeStatus::BlockedEnv,
                ));
            }
            Err(error) => return Err(error.into_network_error(self.provider, &request.scope)),
        };
        if response.account_id != request.scope.account_id {
            return Err(PartnerNetworkError::ScopeMismatch);
        }
        let status = if verify_program_expectation(
            &request.scope,
            request.expected_program.as_ref(),
            response.program_id.as_ref(),
            response.program_revision,
            response.program_terms_digest.as_deref(),
        )
        .is_err()
        {
            NetworkProbeStatus::ProgramDrift
        } else {
            NetworkProbeStatus::Reachable
        };
        let evidence_digest = crate::contract::canonical_digest(&(
            &request,
            &response.account_id,
            &response.program_id,
            &response.program_revision,
            &response.program_terms_digest,
            &status,
        ))?;
        Ok(NetworkProbeObservation {
            provider: self.provider,
            scope: request.scope,
            status,
            provenance: response.provenance,
            evidence_level: EvidenceLevel::E1,
            claim_authority: "connection_state_only",
            observed_account_id: response.account_id,
            observed_program_id: response.program_id,
            program_revision: response.program_revision,
            program_digest: response.program_digest,
            observed_at: response.observed_at,
            evidence_digest,
        })
    }

    pub(crate) fn read(
        &self,
        request: NetworkReadRequest,
    ) -> Result<NetworkReadObservation, PartnerNetworkError> {
        request.validate()?;
        let authorization = self.state.grant_for(
            &request.scope,
            NetworkCapability::PartnerRead,
            request.observed_at,
        )?;
        let response = self
            .client
            .read(&authorization.secret_reference, &request)
            .map_err(|error| error.into_network_error(self.provider, &request.scope))?;
        verify_program_expectation(
            &request.scope,
            request.expected_program.as_ref(),
            response.program_id.as_ref(),
            response.program_revision,
            response.program_terms_digest.as_deref(),
        )?;
        if response.data.resource() != request.resource {
            return Err(PartnerNetworkError::ReadScopeOrEvidenceMismatch);
        }
        response.data.validate_for(&request.scope)?;
        validate_scope_record_ids(&response.data)?;
        let observation = NetworkReadObservation {
            provider: self.provider,
            scope: request.scope,
            request: request.resource,
            data: response.data,
            page: response.page,
            provenance: response.provenance,
            evidence_level: EvidenceLevel::E1,
            observed_at: response.observed_at,
            source_digest: response.source_digest,
        };
        observation.validate()?;
        Ok(observation)
    }

    pub(crate) fn handle_callback(
        &mut self,
        request: &CallbackRequest<'_>,
        accepted_schemes: &[CallbackSignatureScheme],
    ) -> Result<CallbackObservation, PartnerNetworkError> {
        if !accepted_schemes.contains(&request.scheme) {
            return Err(PartnerNetworkError::UnsupportedCallbackSignature);
        }
        self.state.callback(request)
    }

    pub(crate) fn revoke(
        &mut self,
        scope: &NetworkScope,
        observed_at: DateTime<Utc>,
    ) -> Result<AuthorizationObservation, PartnerNetworkError> {
        self.state.revoke(scope, observed_at)
    }

    pub(crate) fn accepted_callbacks(&self) -> Vec<crate::CallbackEvent> {
        self.state.accepted_callbacks()
    }
}

impl ProviderApiError {
    fn into_network_error(
        self,
        provider: NetworkProvider,
        scope: &NetworkScope,
    ) -> PartnerNetworkError {
        match self {
            Self::AuthorizationRequired => PartnerNetworkError::AuthorizationRequired {
                provider,
                scope_digest: scope.digest(),
            },
            Self::BlockedEnv(reason) => PartnerNetworkError::BlockedEnv { provider, reason },
            Self::ScopeRevoked => PartnerNetworkError::ScopeRevoked,
            Self::RateLimited => PartnerNetworkError::ProviderRateLimited,
            Self::Unavailable => PartnerNetworkError::ProviderUnavailable,
        }
    }
}

fn denied_probe(
    provider: NetworkProvider,
    request: NetworkProbeRequest,
    status: NetworkProbeStatus,
) -> NetworkProbeObservation {
    let evidence_digest = crate::contract::canonical_digest(&(&request, &status))
        .expect("denied probe is serializable");
    NetworkProbeObservation {
        provider,
        scope: request.scope.clone(),
        status,
        provenance: NetworkProvenance::Fixture,
        evidence_level: EvidenceLevel::E1,
        claim_authority: "connection_state_only",
        observed_account_id: request.scope.account_id,
        observed_program_id: request.scope.program_id,
        program_revision: None,
        program_digest: None,
        observed_at: request.observed_at,
        evidence_digest,
    }
}
