//! Azure Resource Graph provider and reversible Layer-1 registration.

use std::{collections::HashSet, env, fmt};

use thiserror::Error;
use zeroize::Zeroize;

use crate::model::{
    AzureResourceGraphEvidence, AzureResourceGraphEvidenceState, AzureResourceGraphProposal,
    AzureResourceGraphQueryAst, AzureResourceGraphResource, AzureResourceGraphResourcePayload,
    AzureResourceGraphResponseReceipt, AzureResourceGraphScope, AzureResourceGraphTarget, Digest,
    ProviderRevision, RegistrationState, ResourceGroupName, ResourceId, ResourceLocation,
    SubscriptionId, TransportProvenance, canonical_digest, compute_evidence_digest,
    compute_proposal_digest, digest_serializable,
};
use crate::transport::{
    AzureResourceGraphHttpRequest, AzureResourceGraphHttpResponse, AzureResourceGraphTransport,
    AzureResourceGraphTransportError, ContinuationToken, RequestBounds,
};
use crate::{
    AZURE_RESOURCE_GRAPH_API_VERSION, AZURE_RESOURCE_GRAPH_CONTRACT_VERSION,
    AZURE_RESOURCE_GRAPH_NATIVE_PROBE_ENV, AZURE_RESOURCE_GRAPH_NATIVE_PROBE_GATE,
    AZURE_RESOURCE_GRAPH_PLUGIN_ID, AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT,
    AZURE_RESOURCE_GRAPH_PROVIDER_ID, AZURE_RESOURCE_GRAPH_PROVIDER_REVISION,
    AzureResourceGraphError, contract_digest,
};

const FIXTURE_TOKEN: &str = "fixture-token";

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EntraCredentialError {
    #[error("BLOCKED_ENV: Microsoft Entra credential authority is unavailable")]
    BlockedEnv,
    #[error("Microsoft Entra credential reference is unavailable")]
    Unavailable,
    #[error("Microsoft Entra credential reference is revoked")]
    SecretRevoked,
}

/// A short-lived token borrowed by one transport request. It is never
/// serializable or printable as credential material.
pub struct EntraAccessToken {
    value: String,
}

impl fmt::Debug for EntraAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EntraAccessToken")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl EntraAccessToken {
    pub fn new(value: impl Into<String>) -> Result<Self, EntraCredentialError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(EntraCredentialError::Unavailable);
        }
        Ok(Self { value })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl Drop for EntraAccessToken {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

pub trait CredentialResolver: fmt::Debug {
    fn resolve(
        &mut self,
        reference: &crate::SecretReference,
    ) -> Result<EntraAccessToken, EntraCredentialError>;
}

pub use CredentialResolver as EntraCredentialResolver;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl CredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &mut self,
        _reference: &crate::SecretReference,
    ) -> Result<EntraAccessToken, EntraCredentialError> {
        Err(EntraCredentialError::BlockedEnv)
    }
}

/// Deterministic test-only credential seam. It supplies a local fixture token
/// and never upgrades evidence to native or Connected authority.
#[derive(Clone, Copy, Debug, Default)]
pub struct FixtureCredentialResolver;

impl CredentialResolver for FixtureCredentialResolver {
    fn resolve(
        &mut self,
        reference: &crate::SecretReference,
    ) -> Result<EntraAccessToken, EntraCredentialError> {
        if reference.is_revoked() {
            Err(EntraCredentialError::SecretRevoked)
        } else {
            EntraAccessToken::new(FIXTURE_TOKEN)
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EnvironmentCredentialResolver;

impl CredentialResolver for EnvironmentCredentialResolver {
    fn resolve(
        &mut self,
        reference: &crate::SecretReference,
    ) -> Result<EntraAccessToken, EntraCredentialError> {
        if reference.is_revoked() {
            return Err(EntraCredentialError::SecretRevoked);
        }
        if env::var(AZURE_RESOURCE_GRAPH_NATIVE_PROBE_ENV)
            .ok()
            .as_deref()
            != Some("1")
        {
            return Err(EntraCredentialError::BlockedEnv);
        }
        let value = env::var(crate::AZURE_RESOURCE_GRAPH_ACCESS_TOKEN_ENV)
            .map_err(|_| EntraCredentialError::BlockedEnv)?;
        EntraAccessToken::new(value)
    }
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeProbeStatus {
    BlockedEnv,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct NativeProbe {
    pub status: NativeProbeStatus,
    pub native_credentials_resolved: bool,
    pub live_https_verified: bool,
    pub native_connected_claim: bool,
    pub reason: String,
}

impl NativeProbe {
    #[must_use]
    pub fn from_environment() -> Self {
        let reason = if env::var(AZURE_RESOURCE_GRAPH_NATIVE_PROBE_ENV)
            .ok()
            .as_deref()
            == Some("1")
        {
            format!(
                "{AZURE_RESOURCE_GRAPH_NATIVE_PROBE_GATE} is present, but Layer 1 has no native Entra authority"
            )
        } else {
            format!("{AZURE_RESOURCE_GRAPH_NATIVE_PROBE_GATE} is not enabled")
        };
        Self {
            status: NativeProbeStatus::BlockedEnv,
            native_credentials_resolved: false,
            live_https_verified: false,
            native_connected_claim: false,
            reason,
        }
    }
}

#[must_use]
pub fn native_probe_from_environment() -> NativeProbe {
    NativeProbe::from_environment()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureResourceGraphRegistrationRequest {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_revision: ProviderRevision,
    pub scope: AzureResourceGraphScope,
    pub secret_reference: crate::SecretReference,
}

impl AzureResourceGraphRegistrationRequest {
    pub fn baseline(
        scope: AzureResourceGraphScope,
        secret_reference: crate::SecretReference,
    ) -> Result<Self, AzureResourceGraphError> {
        Ok(Self {
            plugin_version: AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: AZURE_RESOURCE_GRAPH_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            service_id: crate::AZURE_RESOURCE_GRAPH_SERVICE_ID.to_owned(),
            provider_id: AZURE_RESOURCE_GRAPH_PROVIDER_ID.to_owned(),
            provider_revision: ProviderRevision::parse(AZURE_RESOURCE_GRAPH_PROVIDER_REVISION)?,
            scope,
            secret_reference,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureResourceGraphRegistration {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    service_id: String,
    provider_id: String,
    provider_revision: ProviderRevision,
    scope: AzureResourceGraphScope,
    secret_reference: crate::SecretReference,
    registration_digest: Digest,
    state: RegistrationState,
}

impl AzureResourceGraphRegistration {
    pub fn new(
        request: AzureResourceGraphRegistrationRequest,
    ) -> Result<Self, AzureResourceGraphError> {
        if request.plugin_version != AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT
            || request.contract_version != AZURE_RESOURCE_GRAPH_CONTRACT_VERSION
        {
            return Err(AzureResourceGraphError::VersionMismatch);
        }
        if request.contract_digest != contract_digest()
            || request.service_id != crate::AZURE_RESOURCE_GRAPH_SERVICE_ID
        {
            return Err(AzureResourceGraphError::ContractDigestMismatch);
        }
        if request.provider_id != AZURE_RESOURCE_GRAPH_PROVIDER_ID {
            return Err(AzureResourceGraphError::ProviderIdentityMismatch);
        }
        if request.provider_revision.as_str() != AZURE_RESOURCE_GRAPH_PROVIDER_REVISION {
            return Err(AzureResourceGraphError::ProviderRevisionDrift);
        }
        request.scope.validate()?;
        if request.secret_reference.is_revoked() {
            return Err(AzureResourceGraphError::SecretRevoked);
        }
        let registration_digest = registration_digest(&request)?;
        Ok(Self {
            plugin_version: request.plugin_version,
            contract_version: request.contract_version,
            contract_digest: request.contract_digest,
            service_id: request.service_id,
            provider_id: request.provider_id,
            provider_revision: request.provider_revision,
            scope: request.scope,
            secret_reference: request.secret_reference,
            registration_digest,
            state: RegistrationState::Active,
        })
    }

    #[must_use]
    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    #[must_use]
    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    #[must_use]
    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    #[must_use]
    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.provider_revision
    }

    #[must_use]
    pub fn scope(&self) -> &AzureResourceGraphScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &crate::SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    #[must_use]
    pub const fn state(&self) -> &RegistrationState {
        &self.state
    }

    pub fn revoke(&mut self) -> Result<(), AzureResourceGraphError> {
        if self.state == RegistrationState::Revoked {
            Err(AzureResourceGraphError::RegistrationRevoked)
        } else {
            self.state = RegistrationState::Revoked;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<(), AzureResourceGraphError> {
        if self.state == RegistrationState::Active {
            Err(AzureResourceGraphError::RegistrationNotRevoked)
        } else if self.secret_reference.is_revoked() {
            Err(AzureResourceGraphError::SecretRevoked)
        } else {
            self.state = RegistrationState::Active;
            Ok(())
        }
    }

    pub fn revoke_secret(&mut self) -> Result<(), AzureResourceGraphError> {
        self.secret_reference.revoke()?;
        Ok(())
    }

    pub fn restore_secret(&mut self) -> Result<(), AzureResourceGraphError> {
        self.secret_reference.restore()?;
        Ok(())
    }

    fn validate_active(
        &self,
        scope: &AzureResourceGraphScope,
    ) -> Result<(), AzureResourceGraphError> {
        if self.state == RegistrationState::Revoked {
            return Err(AzureResourceGraphError::RegistrationRevoked);
        }
        if self.scope != *scope {
            return Err(AzureResourceGraphError::ScopeMismatch(
                "provider registration scope differs from the request scope".to_owned(),
            ));
        }
        if self.secret_reference.is_revoked() {
            return Err(AzureResourceGraphError::SecretRevoked);
        }
        Ok(())
    }
}

fn registration_digest(
    request: &AzureResourceGraphRegistrationRequest,
) -> Result<Digest, AzureResourceGraphError> {
    digest_serializable(&(
        &request.plugin_version,
        &request.contract_version,
        &request.contract_digest,
        &request.service_id,
        &request.provider_id,
        &request.provider_revision,
        &request.scope,
        request.secret_reference.digest(),
    ))
    .map_err(AzureResourceGraphError::from)
}

#[must_use]
pub fn continuation_binding_digest(
    registration_digest: &Digest,
    scope_digest: &Digest,
    query_digest: &Digest,
    page: u16,
) -> Digest {
    canonical_digest(&(
        AZURE_RESOURCE_GRAPH_PLUGIN_ID,
        AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT,
        AZURE_RESOURCE_GRAPH_CONTRACT_VERSION,
        AZURE_RESOURCE_GRAPH_PROVIDER_ID,
        AZURE_RESOURCE_GRAPH_PROVIDER_REVISION,
        registration_digest,
        scope_digest,
        query_digest,
        page,
    ))
}

pub struct AzureResourceGraphProvider<T, R>
where
    T: AzureResourceGraphTransport,
    R: CredentialResolver,
{
    service: crate::AzureResourceGraphService,
    registration: AzureResourceGraphRegistration,
    transport: T,
    credential_resolver: R,
    bounds: RequestBounds,
}

impl<T, R> fmt::Debug for AzureResourceGraphProvider<T, R>
where
    T: AzureResourceGraphTransport,
    R: CredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureResourceGraphProvider")
            .field("service", &self.service)
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("scope_digest", self.registration.scope.scope_digest())
            .field("transport_provenance", &self.transport.provenance())
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

impl<T, R> AzureResourceGraphProvider<T, R>
where
    T: AzureResourceGraphTransport,
    R: CredentialResolver,
{
    pub fn new(
        scope: AzureResourceGraphScope,
        secret_reference: crate::SecretReference,
        transport: T,
        credential_resolver: R,
    ) -> Result<Self, AzureResourceGraphError> {
        let request = AzureResourceGraphRegistrationRequest::baseline(scope, secret_reference)?;
        Self::from_registration_request(
            request,
            transport,
            credential_resolver,
            RequestBounds::default(),
        )
    }

    pub fn from_registration_request(
        request: AzureResourceGraphRegistrationRequest,
        transport: T,
        credential_resolver: R,
        bounds: RequestBounds,
    ) -> Result<Self, AzureResourceGraphError> {
        let registration = AzureResourceGraphRegistration::new(request)?;
        let service = crate::AzureResourceGraphService::new();
        service.validate()?;
        Ok(Self {
            service,
            registration,
            transport,
            credential_resolver,
            bounds,
        })
    }

    #[must_use]
    pub fn service(&self) -> &crate::AzureResourceGraphService {
        &self.service
    }

    #[must_use]
    pub fn registration(&self) -> &AzureResourceGraphRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub const fn bounds(&self) -> RequestBounds {
        self.bounds
    }

    #[must_use]
    pub fn is_connected(&self) -> bool {
        false
    }

    #[must_use]
    pub fn is_native(&self) -> bool {
        false
    }

    #[must_use]
    pub fn transport_provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn propose_query(&self) -> Result<AzureResourceGraphQueryAst, AzureResourceGraphError> {
        self.service.propose_query(self.registration.scope())
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        canonical_digest(&(
            AZURE_RESOURCE_GRAPH_PROVIDER_ID,
            AZURE_RESOURCE_GRAPH_PROVIDER_REVISION,
            AZURE_RESOURCE_GRAPH_API_VERSION,
            crate::AZURE_RESOURCE_GRAPH_API_PATH,
            false,
            false,
        ))
    }

    pub fn revoke_registration(&mut self) -> Result<(), AzureResourceGraphError> {
        self.registration.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<(), AzureResourceGraphError> {
        self.registration.restore()
    }

    pub fn revoke_secret(&mut self) -> Result<(), AzureResourceGraphError> {
        self.registration.revoke_secret()
    }

    pub fn restore_secret(&mut self) -> Result<(), AzureResourceGraphError> {
        self.registration.restore_secret()
    }

    #[allow(clippy::too_many_lines)]
    pub fn read(&mut self) -> Result<AzureResourceGraphEvidence, AzureResourceGraphError> {
        self.registration
            .validate_active(self.registration.scope())?;
        let token = match self
            .credential_resolver
            .resolve(self.registration.secret_reference())
        {
            Ok(token) => token,
            Err(EntraCredentialError::BlockedEnv) => {
                return Ok(self.failure_evidence(
                    AzureResourceGraphEvidenceState::BlockedEnv,
                    TransportProvenance::BlockedEnv,
                    Vec::new(),
                    1,
                    None,
                ));
            }
            Err(EntraCredentialError::SecretRevoked) => {
                return Err(AzureResourceGraphError::SecretRevoked);
            }
            Err(EntraCredentialError::Unavailable) => {
                return Err(AzureResourceGraphError::CredentialUnavailable);
            }
        };
        let query = self.registration.scope().query_ast();
        let provenance = self.transport.provenance();
        let mut page = 1;
        let mut continuation: Option<ContinuationToken> = None;
        let mut seen_continuations = HashSet::new();
        let mut resources = Vec::new();
        let mut receipts = Vec::new();

        loop {
            if page > self.bounds.max_pages {
                return Ok(self.failure_evidence(
                    AzureResourceGraphEvidenceState::Truncated,
                    provenance,
                    receipts,
                    page.saturating_sub(1),
                    None,
                ));
            }
            if let Some(cursor) = continuation.as_ref() {
                let expected = continuation_binding_digest(
                    self.registration.registration_digest(),
                    self.registration.scope().scope_digest(),
                    &query.digest(),
                    page,
                );
                if cursor.page() != page || cursor.binding_digest() != &expected {
                    return Err(AzureResourceGraphError::ContinuationRejected);
                }
                if !seen_continuations.insert(cursor.digest()) {
                    return Err(AzureResourceGraphError::ContinuationReplay);
                }
            }
            let request = AzureResourceGraphHttpRequest::new(
                self.registration.scope(),
                self.registration.registration_digest().clone(),
                &query,
                page,
                continuation.clone(),
                self.bounds,
            )?;
            let response = match self.transport.execute(&token, &request) {
                Ok(response) => response,
                Err(AzureResourceGraphTransportError::BlockedEnv) => {
                    return Ok(self.failure_evidence(
                        AzureResourceGraphEvidenceState::BlockedEnv,
                        TransportProvenance::BlockedEnv,
                        receipts,
                        page,
                        None,
                    ));
                }
                Err(AzureResourceGraphTransportError::Timeout(_)) => {
                    return Ok(self.failure_evidence(
                        AzureResourceGraphEvidenceState::Timeout,
                        provenance,
                        receipts,
                        page,
                        None,
                    ));
                }
                Err(AzureResourceGraphTransportError::ResponseTooLarge { size }) => {
                    return Err(AzureResourceGraphError::ResponseTooLarge { size });
                }
                Err(AzureResourceGraphTransportError::CredentialUnavailable) => {
                    return Err(AzureResourceGraphError::CredentialUnavailable);
                }
                Err(error) => return Err(AzureResourceGraphError::from(error)),
            };
            self.validate_response(&request, &response)?;
            let receipt = response.receipt().clone();
            receipts.push(receipt);
            if response.receipt().status != 200 {
                return Ok(self.failure_evidence(
                    status_state(response.receipt().status),
                    provenance,
                    receipts,
                    page,
                    response.continuation().map(ContinuationToken::digest),
                ));
            }
            if response.receipt().partial || response.receipt().truncated {
                return Ok(self.failure_evidence(
                    if response.receipt().truncated {
                        AzureResourceGraphEvidenceState::Truncated
                    } else {
                        AzureResourceGraphEvidenceState::Partial
                    },
                    provenance,
                    receipts,
                    page,
                    response.continuation().map(ContinuationToken::digest),
                ));
            }
            if resources.len() + response.body().resources.len() > self.bounds.max_resources {
                return Err(AzureResourceGraphError::ResultBoundExceeded);
            }
            for payload in &response.body().resources {
                resources.push(self.normalize_resource(payload, &query)?);
            }
            let Some(next) = response.continuation().cloned() else {
                break;
            };
            if page >= self.bounds.max_pages {
                return Ok(self.failure_evidence(
                    AzureResourceGraphEvidenceState::Truncated,
                    provenance,
                    receipts,
                    page,
                    Some(next.digest()),
                ));
            }
            let expected = continuation_binding_digest(
                self.registration.registration_digest(),
                self.registration.scope().scope_digest(),
                &query.digest(),
                page + 1,
            );
            if next.page() != page + 1 || next.binding_digest() != &expected {
                return Err(AzureResourceGraphError::ContinuationRejected);
            }
            continuation = Some(next);
            page += 1;
        }

        resources.sort_by(|left, right| left.resource_id.cmp(&right.resource_id));
        if resources
            .windows(2)
            .any(|pair| pair[0].resource_id == pair[1].resource_id)
        {
            return Err(AzureResourceGraphError::RegistrationDrift(
                "provider returned duplicate resource identities".to_owned(),
            ));
        }
        let state = if resources.is_empty() {
            AzureResourceGraphEvidenceState::Empty
        } else {
            AzureResourceGraphEvidenceState::Complete
        };
        self.make_evidence(
            state,
            provenance,
            resources,
            receipts,
            page,
            continuation.as_ref().map(ContinuationToken::digest),
        )
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<AzureResourceGraphProposal, AzureResourceGraphError> {
        let evidence = self.read()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: AzureResourceGraphEvidence,
    ) -> Result<AzureResourceGraphProposal, AzureResourceGraphError> {
        self.registration
            .validate_active(self.registration.scope())?;
        evidence.validate()?;
        if evidence.scope_digest != *self.registration.scope().scope_digest()
            || evidence.registration_digest != *self.registration.registration_digest()
            || evidence.contract_digest != contract_digest()
            || evidence.query_digest != self.registration.scope().query_digest()
            || evidence.permission_digest != self.registration.scope().permission().digest()
            || compute_evidence_digest(&evidence) != evidence.evidence_digest
        {
            return Err(AzureResourceGraphError::InvalidProposal);
        }
        let recommendation = recommendation_for(evidence.state);
        let mut proposal = AzureResourceGraphProposal {
            scope: self.registration.scope().clone(),
            source_evidence_digest: evidence.evidence_digest.clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_digest: self.provider_digest(),
            contract_digest: contract_digest(),
            query_digest: self.registration.scope().query_digest(),
            permission_digest: self.registration.scope().permission().digest(),
            proposal_only: true,
            native: false,
            connected: false,
            adopts_outcome: false,
            recommendation,
            evidence,
            proposal_digest: Digest::parse("0".repeat(64))?,
        };
        proposal.proposal_digest = compute_proposal_digest(&proposal);
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &AzureResourceGraphProposal,
    ) -> Result<(), AzureResourceGraphError> {
        self.registration
            .validate_active(self.registration.scope())?;
        proposal.validate()?;
        if proposal.scope != *self.registration.scope()
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.provider_digest != self.provider_digest()
            || proposal.contract_digest != contract_digest()
        {
            return Err(AzureResourceGraphError::InvalidProposal);
        }
        Ok(())
    }

    pub fn record_observation_receipt(
        &self,
        proposal: &AzureResourceGraphProposal,
    ) -> Result<crate::AzureResourceGraphObservationReceipt, AzureResourceGraphError> {
        self.verify_proposal(proposal)?;
        let mut receipt = crate::AzureResourceGraphObservationReceipt {
            contract_version: AZURE_RESOURCE_GRAPH_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            consumer_id: crate::MISSION_AZURE_RESOURCE_GRAPH_CONSUMER_ID.to_owned(),
            consumer_version: AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT.to_owned(),
            scope_digest: proposal.scope.scope_digest().clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            provenance: proposal.evidence.provenance,
            read_only: true,
            native: false,
            connected: false,
            durable_provider_receipt: false,
            observation_digest: Digest::parse("0".repeat(64))?,
        };
        receipt.observation_digest = canonical_digest(&(
            &receipt.contract_version,
            &receipt.contract_digest,
            &receipt.consumer_id,
            &receipt.consumer_version,
            &receipt.scope_digest,
            &receipt.evidence_digest,
            &receipt.proposal_digest,
            receipt.provenance,
            receipt.read_only,
            receipt.native,
            receipt.connected,
            receipt.durable_provider_receipt,
        ));
        Ok(receipt)
    }

    fn validate_response(
        &self,
        request: &AzureResourceGraphHttpRequest,
        response: &AzureResourceGraphHttpResponse,
    ) -> Result<(), AzureResourceGraphError> {
        let receipt = response.receipt();
        if receipt.request_digest != request.digest()
            || receipt.provider_revision != *self.registration.provider_revision()
            || receipt.response_size > request.max_response_bytes
            || receipt.raw_provider_payload
            || receipt.raw_properties
            || receipt.raw_tags
            || receipt.raw_secrets
            || receipt.page != request.page
            || receipt.continuation_digest != response.continuation().map(ContinuationToken::digest)
        {
            return Err(AzureResourceGraphError::InvalidResponseReceipt);
        }
        Ok(())
    }

    fn normalize_resource(
        &self,
        payload: &AzureResourceGraphResourcePayload,
        query: &AzureResourceGraphQueryAst,
    ) -> Result<AzureResourceGraphResource, AzureResourceGraphError> {
        let resource_type = crate::AzureResourceType::parse(&payload.resource_type)?;
        if !query.resource_types.contains(&resource_type) {
            return Err(AzureResourceGraphError::RegistrationDrift(
                "provider resource type is outside the registered allowlist".to_owned(),
            ));
        }
        let resource_id = ResourceId::new(payload.id.clone())?;
        let subscription_id = payload
            .subscription_id
            .as_deref()
            .map(SubscriptionId::new)
            .transpose()?;
        if let (AzureResourceGraphTarget::Subscriptions(_), Some(subscription)) =
            (self.registration.scope().target(), subscription_id.as_ref())
            && !self
                .registration
                .scope()
                .target()
                .contains_subscription(subscription)
        {
            return Err(AzureResourceGraphError::ScopeMismatch(
                "resource subscription is outside the registered subscription scope".to_owned(),
            ));
        }
        if matches!(
            self.registration.scope().target(),
            AzureResourceGraphTarget::Subscriptions(_)
        ) && subscription_id.is_none()
        {
            return Err(AzureResourceGraphError::ScopeMismatch(
                "subscription-scoped resource omitted its subscription ancestry".to_owned(),
            ));
        }
        let location = payload
            .location
            .as_deref()
            .map(ResourceLocation::new)
            .transpose()?;
        let resource_group = payload
            .resource_group
            .as_deref()
            .map(ResourceGroupName::new)
            .transpose()?;
        let mut property_digests = query
            .properties
            .iter()
            .filter_map(|property| {
                property.digest_value(payload).map(|value_digest| {
                    crate::AzureResourceGraphDigestProperty {
                        property: *property,
                        value_digest,
                    }
                })
            })
            .collect::<Vec<_>>();
        property_digests.sort_by_key(|property| property.property);
        Ok(AzureResourceGraphResource {
            resource_id,
            resource_type,
            location,
            subscription_id,
            resource_group,
            kind: payload.kind.clone(),
            property_digests,
        })
    }

    fn make_evidence(
        &self,
        state: AzureResourceGraphEvidenceState,
        provenance: TransportProvenance,
        resources: Vec<AzureResourceGraphResource>,
        response_receipts: Vec<AzureResourceGraphResponseReceipt>,
        page_count: u16,
        continuation_digest: Option<Digest>,
    ) -> Result<AzureResourceGraphEvidence, AzureResourceGraphError> {
        let mut evidence = AzureResourceGraphEvidence {
            contract_version: AZURE_RESOURCE_GRAPH_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            plugin_version: AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT.to_owned(),
            scope_digest: self.registration.scope().scope_digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_revision: self.registration.provider_revision().clone(),
            query_digest: self.registration.scope().query_digest(),
            permission_digest: self.registration.scope().permission().digest(),
            consent_digest: self.registration.scope().consent().digest(),
            provenance,
            state,
            page_count: page_count.max(1),
            resources,
            response_receipts,
            continuation_digest,
            usable: state.is_usable(),
            native: false,
            connected: false,
            external_writes: false,
            fleet_health_authority: false,
            deployment_authority: false,
            policy_authority: false,
            outcome_authority: false,
            evidence_digest: Digest::parse("0".repeat(64))?,
        };
        evidence.evidence_digest = compute_evidence_digest(&evidence);
        evidence.validate()?;
        Ok(evidence)
    }

    fn failure_evidence(
        &self,
        state: AzureResourceGraphEvidenceState,
        provenance: TransportProvenance,
        receipts: Vec<AzureResourceGraphResponseReceipt>,
        page_count: u16,
        continuation_digest: Option<Digest>,
    ) -> AzureResourceGraphEvidence {
        let mut evidence = AzureResourceGraphEvidence {
            contract_version: AZURE_RESOURCE_GRAPH_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            plugin_version: AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT.to_owned(),
            scope_digest: self.registration.scope().scope_digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_revision: self.registration.provider_revision().clone(),
            query_digest: self.registration.scope().query_digest(),
            permission_digest: self.registration.scope().permission().digest(),
            consent_digest: self.registration.scope().consent().digest(),
            provenance,
            state,
            page_count: page_count.max(1),
            resources: Vec::new(),
            response_receipts: receipts,
            continuation_digest,
            usable: false,
            native: false,
            connected: false,
            external_writes: false,
            fleet_health_authority: false,
            deployment_authority: false,
            policy_authority: false,
            outcome_authority: false,
            evidence_digest: Digest::parse("0".repeat(64)).expect("zero digest is valid"),
        };
        evidence.evidence_digest = compute_evidence_digest(&evidence);
        evidence
    }
}

fn status_state(status: u16) -> AzureResourceGraphEvidenceState {
    match status {
        400 => AzureResourceGraphEvidenceState::BadRequest,
        401 => AzureResourceGraphEvidenceState::Unauthorized,
        403 => AzureResourceGraphEvidenceState::Forbidden,
        404 => AzureResourceGraphEvidenceState::NotFound,
        408 => AzureResourceGraphEvidenceState::Timeout,
        409 => AzureResourceGraphEvidenceState::Conflict,
        429 => AzureResourceGraphEvidenceState::RateLimited,
        _ => AzureResourceGraphEvidenceState::ProviderUnavailable,
    }
}

fn recommendation_for(
    state: AzureResourceGraphEvidenceState,
) -> crate::AzureResourceGraphRecommendation {
    let disposition = match state {
        AzureResourceGraphEvidenceState::Complete => {
            crate::AzureResourceGraphRecommendationDisposition::ReviewInventory
        }
        AzureResourceGraphEvidenceState::Empty
        | AzureResourceGraphEvidenceState::Partial
        | AzureResourceGraphEvidenceState::Truncated => {
            crate::AzureResourceGraphRecommendationDisposition::NeedsMoreEvidence
        }
        AzureResourceGraphEvidenceState::Forbidden
        | AzureResourceGraphEvidenceState::Unauthorized
        | AzureResourceGraphEvidenceState::NotFound => {
            crate::AzureResourceGraphRecommendationDisposition::AccessLost
        }
        AzureResourceGraphEvidenceState::RateLimited => {
            crate::AzureResourceGraphRecommendationDisposition::RateLimited
        }
        AzureResourceGraphEvidenceState::BadRequest
        | AzureResourceGraphEvidenceState::Conflict
        | AzureResourceGraphEvidenceState::ProviderUnavailable
        | AzureResourceGraphEvidenceState::Timeout
        | AzureResourceGraphEvidenceState::BlockedEnv => {
            crate::AzureResourceGraphRecommendationDisposition::ProviderUnavailable
        }
    };
    crate::AzureResourceGraphRecommendation {
        disposition,
        non_mutating: true,
        provider_reported_only: true,
        claims_fleet_health: false,
        claims_deployability: false,
        claims_policy_compliance: false,
        adopts_outcome: false,
    }
}
