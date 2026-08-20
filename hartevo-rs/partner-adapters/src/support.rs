use chrono::{DateTime, Utc};
use std::path::PathBuf;

use crate::callback::{CallbackObservation, CallbackRequest, CallbackSignatureScheme};
use crate::contract::{
    AuthorizationGrant, AuthorizationObservation, BlockedEnvironmentReason, EvidenceLevel,
    NetworkCapability, NetworkProbeObservation, NetworkProbeRequest, NetworkProbeStatus,
    NetworkProvenance, NetworkProvider, NetworkReadBudgetReceipt, NetworkReadData,
    NetworkReadObservation, NetworkReadRequest, NetworkScope, PartnerNetworkError, ReadCursor,
    ReadPage, is_sha256, read_observation_evidence_digest, validate_scope_record_ids,
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

    pub(crate) fn with_state_file(
        provider: NetworkProvider,
        client: C,
        path: impl Into<PathBuf>,
    ) -> Result<Self, PartnerNetworkError> {
        Ok(Self {
            provider,
            client,
            state: AdapterState::with_state_file(provider, path)?,
        })
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
        let provenance = seal_provenance(self.provider, response.provenance)?;
        if response
            .program_digest
            .as_deref()
            .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(PartnerNetworkError::ReadScopeOrEvidenceMismatch);
        }
        let evidence_digest = crate::contract::canonical_digest(&(
            &request,
            &response.account_id,
            &response.program_id,
            &response.program_revision,
            &response.program_terms_digest,
            &status,
            &provenance,
        ))?;
        Ok(NetworkProbeObservation {
            provider: self.provider,
            scope: request.scope,
            status,
            provenance,
            evidence_level: EvidenceLevel::E1,
            claim_authority: "unattested_provider_evidence",
            observed_account_id: response.account_id,
            observed_program_id: response.program_id,
            program_revision: response.program_revision,
            program_digest: response.program_digest,
            observed_at: response.observed_at,
            evidence_digest,
            native_canary_digest: None,
            native_canary_attested: false,
        })
    }

    pub(crate) fn read(
        &self,
        mut request: NetworkReadRequest,
    ) -> Result<NetworkReadObservation, PartnerNetworkError> {
        let authorization = self.state.grant_for(
            &request.scope,
            NetworkCapability::PartnerRead,
            request.observed_at,
        )?;
        let expected_generation = format!(
            "grant:{}:{}",
            authorization.secret_reference.reference_id(),
            authorization.secret_reference.revision()
        );
        if request
            .authorization_generation
            .as_deref()
            .is_some_and(|generation| {
                generation.starts_with("grant:") && generation != expected_generation
            })
        {
            return Err(PartnerNetworkError::CursorBindingMismatch);
        }
        if request.authorization_generation.is_none() {
            request.authorization_generation = Some(expected_generation);
        }
        request.validate()?;
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
        let provenance = seal_provenance(self.provider, response.provenance)?;
        if !is_sha256(&response.source_digest) {
            return Err(PartnerNetworkError::ReadScopeOrEvidenceMismatch);
        }
        let page = bind_page(response.page, &request)?;
        let generation = request
            .authorization_generation
            .clone()
            .ok_or(PartnerNetworkError::InvalidAuthorizationGrant)?;
        let cursor_digest = request.cursor_digest();
        let budget = NetworkReadBudgetReceipt::local(request.observed_at, request.limit);
        let mut observation = NetworkReadObservation {
            provider: self.provider,
            scope: request.scope,
            request: request.resource,
            data: response.data,
            page,
            expected_program: request.expected_program,
            window: request.window,
            observed_program_id: response.program_id,
            program_revision: response.program_revision,
            program_terms_digest: response.program_terms_digest,
            authorization_revision: authorization.secret_reference.revision(),
            authorization_generation: generation,
            cursor_digest,
            provenance,
            evidence_level: EvidenceLevel::E1,
            observed_at: response.observed_at,
            source_digest: response.source_digest,
            budget,
            native_canary_digest: None,
            native_canary_attested: false,
            evidence_digest: String::new(),
        };
        observation.evidence_digest = read_observation_evidence_digest(&observation)?;
        observation.validate()?;
        self.state.record_read_receipt(
            &observation.scope,
            observation.authorization_revision,
            observation.budget.evidence_digest.clone(),
            observation.observed_at,
            observation.evidence_digest.clone(),
        )?;
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

    pub(crate) fn durable_receipts(&self) -> Vec<crate::state::DurableReceipt> {
        self.state.durable_receipts()
    }

    pub(crate) fn unmount(&mut self) -> Result<(), PartnerNetworkError> {
        self.state.unmount()
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
        claim_authority: "unattested_provider_evidence",
        observed_account_id: request.scope.account_id,
        observed_program_id: request.scope.program_id,
        program_revision: None,
        program_digest: None,
        observed_at: request.observed_at,
        evidence_digest,
        native_canary_digest: None,
        native_canary_attested: false,
    }
}

fn seal_provenance(
    provider: NetworkProvider,
    provenance: NetworkProvenance,
) -> Result<NetworkProvenance, PartnerNetworkError> {
    if provenance == NetworkProvenance::ProductionProvider {
        return Err(PartnerNetworkError::BlockedEnv {
            provider,
            reason: BlockedEnvironmentReason::OfficialApiCapabilityNotEnabled,
        });
    }
    Ok(provenance)
}

fn bind_page(
    page: ReadPage,
    request: &NetworkReadRequest,
) -> Result<ReadPage, PartnerNetworkError> {
    let generation = request
        .authorization_generation
        .as_deref()
        .ok_or(PartnerNetworkError::InvalidAuthorizationGrant)?;
    let current_sequence = request
        .cursor
        .as_ref()
        .map_or(1, |cursor| cursor.sequence().saturating_add(1));
    let bind = |cursor: Option<ReadCursor>, sequence: u64| {
        cursor
            .map(|cursor| {
                ReadCursor::bound(
                    &request.scope,
                    request.resource,
                    request.expected_program.as_ref(),
                    request.window.as_ref(),
                    generation,
                    sequence,
                    cursor.as_str(),
                )
            })
            .transpose()
    };
    Ok(ReadPage {
        cursor: bind(page.cursor, current_sequence)?,
        next_cursor: bind(page.next_cursor, current_sequence.saturating_add(1))?,
        has_more: page.has_more,
        item_count: page.item_count,
    })
}
