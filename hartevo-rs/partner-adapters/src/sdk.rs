//! Bridge from provider-native partner records into the merged Connector SDK.
//!
//! The partner adapter contract remains useful for provider payloads and the
//! raw callback verification seam. The SDK owns the lifecycle fence,
//! credential chain, replay guard, registry binding, and dispatch budget.

use std::collections::BTreeSet;

use chrono::Duration;
use hartevo_connector_sdk::{
    AuthSession, BeginAuthRequest, ConnectorAdapter, ConnectorAuth, ConnectorDescriptor,
    ConnectorError, ConnectorScope, Cursor, ExecuteRequest, FreshnessWindow, PrepareEffectRequest,
    PreparedEffect, ProbeObservation, ProbeRequest, ProbeStatus, ProviderAdapterIdentity,
    ProviderAdapterOperation, ProviderCapabilityKey, ProviderCapabilitySupport,
    ProviderEvidenceClass, ProviderProvenanceClass, ReadObservation, ReadRequest, ReceiptCandidate,
    ReconcileRequest, ReconciliationObservation, RefreshAuthRequest, RevokeRequest,
    SecretReference, VerificationObservation, VerifyRequest, WebhookObservation, WebhookRequest,
};
use hartevo_effect_broker::ProviderEvidenceSupport;

use crate::contract::{
    AuthorizationGrant, NetworkCapability, NetworkProbeRequest, NetworkProbeStatus,
    NetworkProvenance, NetworkProvider, NetworkReadRequest, NetworkResource, NetworkScope,
    OpaqueSecretReference, PartnerNetworkError, ProgramExpectation, ReadCursor,
    TypedPartnerNetworkAdapter,
};

/// The only generic connector lifecycle implementation exposed by this crate.
/// `A` still owns provider-native typed records and transport behavior; all
/// generic auth/probe/read/webhook/revoke fencing is delegated to the SDK
/// worker that invokes this bridge.
#[derive(Clone, Debug)]
pub struct ConnectorAdapterBridge<A> {
    inner: A,
    descriptor: ConnectorDescriptor,
    expected_program: Option<ProgramExpectation>,
    read_sequence: u64,
}

impl<A: TypedPartnerNetworkAdapter + Send> ConnectorAdapterBridge<A> {
    pub fn new(inner: A) -> Result<Self, ConnectorError> {
        Self::with_expectation(inner, None)
    }

    pub fn with_program_expectation(
        inner: A,
        expectation: ProgramExpectation,
    ) -> Result<Self, ConnectorError> {
        Self::with_expectation(inner, Some(expectation))
    }

    fn with_expectation(
        inner: A,
        expected_program: Option<ProgramExpectation>,
    ) -> Result<Self, ConnectorError> {
        if let Some(expectation) = &expected_program {
            expectation
                .validate()
                .map_err(|error| map_network_error(&error))?;
        }
        let descriptor = descriptor_for(inner.provider())?;
        Ok(Self {
            inner,
            descriptor,
            expected_program,
            read_sequence: 0,
        })
    }

    pub fn inner(&self) -> &A {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut A {
        &mut self.inner
    }

    pub fn into_inner(self) -> A {
        self.inner
    }
}

impl<A: TypedPartnerNetworkAdapter + Send> ConnectorAdapter for ConnectorAdapterBridge<A> {
    fn descriptor(&self) -> &ConnectorDescriptor {
        &self.descriptor
    }

    fn begin_auth(&mut self, request: BeginAuthRequest) -> Result<AuthSession, ConnectorError> {
        ConnectorAuth::begin_auth_session(
            &request.secret_reference,
            &request.credential_lease,
            format!("auth-session-{}", request.auth_revision),
            request.auth_revision,
            request.issued_at,
            request.expires_at,
        )
    }

    fn refresh_auth(&mut self, request: RefreshAuthRequest) -> Result<AuthSession, ConnectorError> {
        ConnectorAuth::begin_auth_session(
            &request.secret_reference,
            &request.credential_lease,
            format!("auth-session-{}", request.auth_revision),
            request.auth_revision,
            request.issued_at,
            request.expires_at,
        )
    }

    fn probe(&mut self, request: ProbeRequest) -> Result<ProbeObservation, ConnectorError> {
        let scope = network_scope(&request.scope, self.inner.provider())?;
        let secret_reference = opaque_secret_reference(&request.secret_reference)?;
        let grant = AuthorizationGrant {
            scope: scope.clone(),
            secret_reference,
            capabilities: BTreeSet::from([
                NetworkCapability::Probe,
                NetworkCapability::PartnerRead,
                NetworkCapability::OutcomeIngest,
            ]),
            expires_at: request.session.expires_at(),
            provenance: NetworkProvenance::ControlledProvider,
        };
        self.inner
            .authorize(grant, request.at)
            .map_err(|error| map_network_error(&error))?;
        let probe_request = match &self.expected_program {
            Some(expectation) => {
                NetworkProbeRequest::for_program(scope, expectation.clone(), request.at)
            }
            None => NetworkProbeRequest::new(scope, request.at),
        };
        let observation = self
            .inner
            .probe(probe_request)
            .map_err(|error| map_network_error(&error))?;
        let expires_at = (request.at + Duration::seconds(60)).min(request.session.expires_at());
        ProbeObservation::new(
            probe_status(observation.status),
            provenance_class(observation.provenance),
            observation.observed_at,
            expires_at,
            observation.evidence_digest,
        )
    }

    fn read(&mut self, request: ReadRequest) -> Result<ReadObservation, ConnectorError> {
        let scope = network_scope(&request.scope, self.inner.provider())?;
        let resource = resource_for_capability(&request.capability)?;
        let mut network_request = match &self.expected_program {
            Some(expectation) => {
                NetworkReadRequest::for_program(scope, resource, expectation.clone(), request.at)
            }
            None => NetworkReadRequest::new(scope, resource, request.at),
        };
        network_request.limit =
            u16::try_from(request.page_size).map_err(|_| ConnectorError::InvalidPageSize)?;
        network_request.cursor = request
            .cursor
            .as_ref()
            // Impact's official pagination cursor is a page number. The SDK
            // deliberately persists only a token digest, so the sequence is
            // the durable bridge back to the provider page without keeping a
            // second cursor authority in this crate.
            .map(|cursor| ReadCursor::new(format!("page:{}", cursor.sequence().saturating_add(1))))
            .transpose()
            .map_err(|error| map_network_error(&error))?;
        let observation = self
            .inner
            .read(network_request)
            .map_err(|error| map_network_error(&error))?;
        let page_sequence = request
            .cursor
            .as_ref()
            .map_or(1, |cursor| cursor.sequence().saturating_add(1));
        let next_cursor = observation
            .page
            .next_cursor
            .as_ref()
            .map(|cursor| {
                Cursor::new(
                    &request.scope,
                    request.query_digest.clone(),
                    page_sequence,
                    crate::contract::digest_bytes(cursor.as_str().as_bytes()),
                )
            })
            .transpose()?;
        let content_digest = crate::contract::canonical_digest(&observation.data)
            .map_err(|error| map_network_error(&error))?;
        self.read_sequence = self.read_sequence.saturating_add(1);
        ReadObservation::new(
            format!("read-observation-{}", self.read_sequence),
            request.scope,
            request.capability,
            self.descriptor.identity().clone(),
            request.query_digest,
            observation.source_digest,
            content_digest,
            provenance_class(observation.provenance),
            FreshnessWindow::new(
                observation.observed_at,
                observation.observed_at + Duration::seconds(30),
                page_sequence,
            )?,
            page_sequence,
            observation.page.item_count,
            next_cursor,
        )
    }

    fn prepare_effect(
        &mut self,
        _request: PrepareEffectRequest,
    ) -> Result<PreparedEffect, ConnectorError> {
        Err(ConnectorError::ProviderRejected)
    }

    fn execute(&mut self, _request: ExecuteRequest) -> Result<ReceiptCandidate, ConnectorError> {
        Err(ConnectorError::ProviderRejected)
    }

    fn reconcile(
        &mut self,
        _request: ReconcileRequest,
    ) -> Result<ReconciliationObservation, ConnectorError> {
        Err(ConnectorError::ProviderRejected)
    }

    fn verify(
        &mut self,
        _request: VerifyRequest,
    ) -> Result<VerificationObservation, ConnectorError> {
        Err(ConnectorError::ProviderRejected)
    }

    fn handle_webhook(
        &mut self,
        request: WebhookRequest,
    ) -> Result<WebhookObservation, ConnectorError> {
        // ConnectorWorker has already verified the SDK envelope signature and
        // replay sequence. Provider-specific raw callback verification remains
        // available through TypedPartnerNetworkAdapter::handle_callback.
        WebhookObservation::from_envelope(&request.envelope, request.scope, request.at)
    }

    fn revoke(&mut self, request: RevokeRequest) -> Result<(), ConnectorError> {
        let scope = network_scope(&request.scope, self.inner.provider())?;
        self.inner
            .revoke(&scope, request.at)
            .map(|_| ())
            .map_err(|error| map_network_error(&error))
    }
}

fn descriptor_for(provider: NetworkProvider) -> Result<ConnectorDescriptor, ConnectorError> {
    let identity =
        ProviderAdapterIdentity::new(format!("partner.{}.network", provider.as_str()), 1)?;
    let mut registrations = Vec::new();
    registrations.push(registration(
        &identity,
        provider,
        "connection.probe",
        ProviderAdapterOperation::Probe,
        ProviderEvidenceClass::ProbeObservation,
    )?);
    registrations.push(registration(
        &identity,
        provider,
        "partner.read",
        ProviderAdapterOperation::Read,
        ProviderEvidenceClass::ReadObservation,
    )?);
    for capability in [
        "partner.program.read",
        "partner.partner.read",
        "partner.contract.read",
        "partner.link.read",
        "partner.click.read",
        "partner.conversion.read",
        "partner.action.read",
        "partner.commission.read",
        "partner.reversal.read",
        "partner.payout.read",
        "partner.report.read",
    ] {
        registrations.push(registration(
            &identity,
            provider,
            capability,
            ProviderAdapterOperation::Read,
            ProviderEvidenceClass::ReadObservation,
        )?);
    }
    registrations.push(registration(
        &identity,
        provider,
        "partner.outcome-ingest",
        ProviderAdapterOperation::HandleWebhook,
        ProviderEvidenceClass::WebhookObservation,
    )?);
    ConnectorDescriptor::new(identity, registrations)
}

fn registration(
    identity: &ProviderAdapterIdentity,
    provider: NetworkProvider,
    capability: &str,
    operation: ProviderAdapterOperation,
    evidence_class: ProviderEvidenceClass,
) -> Result<ProviderCapabilitySupport, ConnectorError> {
    let key = ProviderCapabilityKey::new(provider.as_str(), capability)?;
    let evidence_support = [
        ProviderProvenanceClass::Fixture,
        ProviderProvenanceClass::ControlledProvider,
        ProviderProvenanceClass::ProductionProvider,
    ]
    .into_iter()
    .map(|provenance| ProviderEvidenceSupport::new(operation, evidence_class, provenance))
    .collect::<Result<Vec<_>, _>>()?;
    Ok(ProviderCapabilitySupport::new(
        key,
        identity.clone(),
        evidence_support,
    )?)
}

fn network_scope(
    scope: &ConnectorScope,
    expected_provider: NetworkProvider,
) -> Result<NetworkScope, ConnectorError> {
    if scope.provider_id() != expected_provider.as_str() {
        return Err(ConnectorError::ScopeMismatch);
    }
    let account_id = crate::NetworkAccountId::parse(scope.account_id())
        .map_err(|_| ConnectorError::InvalidScope)?;
    let program_id = scope
        .scopes()
        .iter()
        .filter_map(|value| value.strip_prefix("program:"))
        .map(|value| crate::ProgramId::parse(value).map_err(|_| ConnectorError::InvalidScope))
        .collect::<Result<Vec<_>, _>>()?;
    if program_id.len() > 1 {
        return Err(ConnectorError::InvalidScope);
    }
    NetworkScope::new(
        scope.tenant_id(),
        scope.project_id(),
        account_id,
        program_id.into_iter().next(),
    )
    .map_err(|error| map_network_error(&error))
}

fn opaque_secret_reference(
    secret_reference: &SecretReference,
) -> Result<OpaqueSecretReference, ConnectorError> {
    OpaqueSecretReference::new(
        secret_reference.reference_id(),
        secret_reference.credential_revision(),
    )
    .map_err(|error| map_network_error(&error))
}

fn resource_for_capability(
    capability: &ProviderCapabilityKey,
) -> Result<NetworkResource, ConnectorError> {
    if capability.capability_id() == "partner.read" {
        return Ok(NetworkResource::Reports);
    }
    match capability.capability_id() {
        "partner.program.read" => Ok(NetworkResource::Programs),
        "partner.partner.read" => Ok(NetworkResource::Partners),
        "partner.contract.read" => Ok(NetworkResource::Contracts),
        "partner.link.read" => Ok(NetworkResource::Links),
        "partner.click.read" => Ok(NetworkResource::Clicks),
        "partner.conversion.read" => Ok(NetworkResource::Conversions),
        "partner.action.read" => Ok(NetworkResource::Actions),
        "partner.commission.read" => Ok(NetworkResource::Commissions),
        "partner.reversal.read" => Ok(NetworkResource::Reversals),
        "partner.payout.read" => Ok(NetworkResource::Payouts),
        "partner.report.read" => Ok(NetworkResource::Reports),
        _ => Err(ConnectorError::CapabilityNotRegistered),
    }
}

fn probe_status(status: NetworkProbeStatus) -> ProbeStatus {
    match status {
        NetworkProbeStatus::Reachable => ProbeStatus::Reachable,
        NetworkProbeStatus::AuthorizationRequired
        | NetworkProbeStatus::ScopeRevoked
        | NetworkProbeStatus::ProgramDrift
        | NetworkProbeStatus::BlockedEnv => ProbeStatus::Rejected,
    }
}

fn provenance_class(provenance: NetworkProvenance) -> ProviderProvenanceClass {
    match provenance {
        NetworkProvenance::Fixture => ProviderProvenanceClass::Fixture,
        NetworkProvenance::ControlledProvider => ProviderProvenanceClass::ControlledProvider,
        NetworkProvenance::ProductionProvider => ProviderProvenanceClass::ProductionProvider,
    }
}

fn map_network_error(error: &PartnerNetworkError) -> ConnectorError {
    match error {
        PartnerNetworkError::InvalidScope
        | PartnerNetworkError::InvalidAuthorizationReference
        | PartnerNetworkError::InvalidAuthorizationGrant
        | PartnerNetworkError::InvalidReadCursor
        | PartnerNetworkError::InvalidReadLimit
        | PartnerNetworkError::InvalidProgramExpectation
        | PartnerNetworkError::InvalidSettlementPeriod
        | PartnerNetworkError::MalformedCallback => ConnectorError::InvalidRequest,
        PartnerNetworkError::ScopeMismatch | PartnerNetworkError::CallbackScopeMismatch => {
            ConnectorError::ScopeMismatch
        }
        PartnerNetworkError::InvalidSignature => ConnectorError::InvalidWebhookSignature,
        PartnerNetworkError::InvalidReplayIdentity | PartnerNetworkError::ReplayWindowExpired => {
            ConnectorError::InvalidWebhook
        }
        PartnerNetworkError::DuplicateIdentity
        | PartnerNetworkError::ReadScopeOrEvidenceMismatch => ConnectorError::InvalidObservation,
        PartnerNetworkError::AuthorizationRequired { .. }
        | PartnerNetworkError::BlockedEnv { .. }
        | PartnerNetworkError::ScopeRevoked
        | PartnerNetworkError::ProgramDrift
        | PartnerNetworkError::AuthorizationExpired
        | PartnerNetworkError::ProviderUnavailable
        | PartnerNetworkError::UnsupportedCallbackSignature => ConnectorError::ProviderRejected,
        PartnerNetworkError::ProviderRateLimited => ConnectorError::RateLimited,
    }
}
