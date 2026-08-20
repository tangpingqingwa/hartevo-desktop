//! Bounded Azure Service Bus queue read, proposal, record, and local-integrity
//! verification service.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::{
    CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
    model::{
        AzureServiceBusQueueEvidence, AzureServiceBusReadOperation, AzureServiceBusReadRequest,
        AzureServiceBusScope, Digest, MAX_PAGES, MAX_REQUESTS_PER_READ, ModelError, PartialReason,
        PermissionAction, PermissionFence, ProviderErrorEvidence, ProviderId, ProviderRevision,
        QueuePostureProjection, QueuePostureState, SecretReference, TransportProvenance,
        validate_timestamp_order,
    },
    provider::{
        AzureServiceBusProvider, AzureServiceBusProviderError, AzureServiceBusProviderIdentity,
        AzureServiceBusTransport, is_access_loss,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AzureServiceBusRegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AzureServiceBusRegistrationError {
    #[error("Azure Service Bus registration model error: {0}")]
    Model(#[from] ModelError),
    #[error("Azure Service Bus registration is already revoked")]
    AlreadyRevoked,
    #[error("Azure Service Bus registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AzureServiceBusQueueResultServiceError {
    #[error("Azure Service Bus service model error: {0}")]
    Model(#[from] ModelError),
    #[error("Azure Service Bus provider error: {0}")]
    Provider(#[from] AzureServiceBusProviderError),
    #[error("Azure Service Bus registration is revoked")]
    RegistrationRevoked,
    #[error("Azure Service Bus Entra secret reference is revoked")]
    SecretRevoked,
    #[error("Azure Service Bus registration has drifted: {0}")]
    RegistrationDrift(String),
    #[error("Azure Service Bus scope or permission fence mismatch: {0}")]
    ScopeMismatch(String),
    #[error("Azure Service Bus evidence is stale or tampered")]
    EvidenceTampered,
    #[error("Azure Service Bus proposal is stale or tampered")]
    ProposalTampered,
    #[error("Azure Service Bus record is stale or tampered")]
    RecordTampered,
    #[error("Azure Service Bus registration lifecycle error: {0}")]
    Registration(#[from] AzureServiceBusRegistrationError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureServiceBusCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub operations: [&'static str; 8],
    pub allowlisted_api_operations: [&'static str; 2],
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub message_data_plane: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
}

impl AzureServiceBusCapabilities {
    pub const fn layer_one() -> Self {
        Self {
            service_id: SERVICE_ID,
            provider_id: PROVIDER_ID,
            operations: [
                "describe_capabilities",
                "register",
                "revoke_registration",
                "revoke_secret",
                "read_bounded",
                "propose",
                "record",
                "verify",
            ],
            allowlisted_api_operations: [
                "GET Microsoft.ServiceBus/namespaces/queues/read",
                "GET Microsoft.ServiceBus/namespaces/queues/list",
            ],
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            message_data_plane: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureServiceBusRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: crate::Revision,
    pub state: AzureServiceBusRegistrationState,
    pub registration_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationBody<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a ProviderId,
    provider_version: &'a str,
    provider_revision: &'a ProviderRevision,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    evidence_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: crate::Revision,
    state: AzureServiceBusRegistrationState,
}

impl AzureServiceBusRegistration {
    fn new(
        scope: &AzureServiceBusScope,
        secret_reference: &SecretReference,
        provider: &AzureServiceBusProviderIdentity,
    ) -> Result<Self, AzureServiceBusRegistrationError> {
        let evidence_digest = Digest::from_fields(
            "hartevo-azure-service-bus-evidence-policy/v1",
            &[
                ("contract", CONTRACT_VERSION.to_owned()),
                (
                    "max_response_bytes",
                    crate::model::MAX_RESPONSE_BYTES.to_string(),
                ),
                ("max_pages", MAX_PAGES.to_string()),
                ("page_size", crate::model::PAGE_SIZE.to_string()),
                ("max_count", crate::model::MAX_COUNT.to_string()),
                ("raw_payload", "excluded".to_owned()),
                ("data_plane", "excluded".to_owned()),
            ],
        );
        let mut registration = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.version.clone(),
            provider_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.digest(),
            evidence_digest,
            secret_reference_digest: secret_reference.digest().clone(),
            registration_revision: crate::Revision::new(1)?,
            state: AzureServiceBusRegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, AzureServiceBusRegistrationState::Active)
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&RegistrationBody {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_version: &self.provider_version,
            provider_revision: &self.provider_revision,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            evidence_digest: &self.evidence_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registration_revision: self.registration_revision,
            state: self.state,
        })
    }

    pub fn validate(
        &self,
        scope: &AzureServiceBusScope,
        secret_reference: &SecretReference,
        provider: &AzureServiceBusProviderIdentity,
    ) -> Result<(), AzureServiceBusRegistrationError> {
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.version
            || self.provider_revision != provider.api_revision
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.permission_digest != *scope.permission_digest()
            || self.scope_digest != scope.digest()
            || self.secret_reference_digest != *secret_reference.digest()
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(AzureServiceBusRegistrationError::Model(
                ModelError::ScopeMismatch {
                    field: "registration digest binding",
                },
            ));
        }
        Ok(())
    }

    fn revoke(&mut self) -> Result<(), AzureServiceBusRegistrationError> {
        if !self.is_active() {
            return Err(AzureServiceBusRegistrationError::AlreadyRevoked);
        }
        let next = self
            .registration_revision
            .get()
            .checked_add(1)
            .ok_or(AzureServiceBusRegistrationError::RevisionOverflow)?;
        self.registration_revision = crate::Revision::new(next)?;
        self.state = AzureServiceBusRegistrationState::Revoked;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureServiceBusReadResult {
    pub evidence: AzureServiceBusQueueEvidence,
    pub page_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureServiceBusQueueResultProposal {
    pub operation: AzureServiceBusReadOperation,
    pub state: QueuePostureState,
    pub evidence: AzureServiceBusQueueEvidence,
    pub proposed_at: DateTime<Utc>,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub queue_count_is_delivery_verification: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalBody<'a> {
    operation: AzureServiceBusReadOperation,
    state: QueuePostureState,
    evidence: &'a AzureServiceBusQueueEvidence,
    proposed_at: &'a DateTime<Utc>,
    registration_digest: &'a Digest,
    read_only: bool,
    proposal_only: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    truth_authority: bool,
    consent_authority: bool,
    effect_authority: bool,
    receipt_authority: bool,
    verification_authority: bool,
    outcome_authority: bool,
    queue_count_is_delivery_verification: bool,
}

impl AzureServiceBusQueueResultProposal {
    fn new(
        operation: AzureServiceBusReadOperation,
        evidence: AzureServiceBusQueueEvidence,
        proposed_at: DateTime<Utc>,
        registration_digest: Digest,
    ) -> Self {
        let mut proposal = Self {
            operation,
            state: evidence.state,
            evidence,
            proposed_at,
            registration_digest,
            proposal_digest: Digest::zero(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            queue_count_is_delivery_verification: false,
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&ProposalBody {
            operation: self.operation,
            state: self.state,
            evidence: &self.evidence,
            proposed_at: &self.proposed_at,
            registration_digest: &self.registration_digest,
            read_only: self.read_only,
            proposal_only: self.proposal_only,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            truth_authority: self.truth_authority,
            consent_authority: self.consent_authority,
            effect_authority: self.effect_authority,
            receipt_authority: self.receipt_authority,
            verification_authority: self.verification_authority,
            outcome_authority: self.outcome_authority,
            queue_count_is_delivery_verification: self.queue_count_is_delivery_verification,
        })
    }

    pub fn validate(
        &self,
        scope: &AzureServiceBusScope,
    ) -> Result<(), AzureServiceBusQueueResultServiceError> {
        self.evidence
            .validate(scope)
            .map_err(|_| AzureServiceBusQueueResultServiceError::EvidenceTampered)?;
        if self.state != self.evidence.state
            || self.registration_digest == Digest::zero()
            || !self.read_only
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_authority
            || self.queue_count_is_delivery_verification
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AzureServiceBusQueueResultServiceError::ProposalTampered);
        }
        Ok(())
    }

    pub fn tampered_state(scope: &AzureServiceBusScope, registration_digest: Digest) -> Self {
        let evidence = AzureServiceBusQueueEvidence::new(
            QueuePostureState::Tampered,
            None,
            None,
            0,
            0,
            0,
            true,
            Digest::from_parts(
                "hartevo-azure-service-bus-tampered-query/v1",
                &[scope.digest().to_string()],
            ),
            scope.digest(),
            scope.permission_digest().clone(),
            Digest::from_text("tampered-provider"),
            ProviderRevision::new("tampered-provider-revision").expect("bounded test revision"),
            Digest::from_text("tampered-api"),
            contract_digest(),
            Vec::new(),
            TransportProvenance::Recording,
        );
        Self::new(
            AzureServiceBusReadOperation::GetQueue,
            evidence,
            Utc::now(),
            registration_digest,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureServiceBusRecordReceipt {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub state: QueuePostureState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub retained_queue_projection: bool,
    pub raw_provider_payload_retained: bool,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub receipt_authority: bool,
    pub receipt_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordBody<'a> {
    recorded: bool,
    recorded_at: &'a DateTime<Utc>,
    state: QueuePostureState,
    proposal_digest: &'a Digest,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    retained_queue_projection: bool,
    raw_provider_payload_retained: bool,
    durable_receipt: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    receipt_authority: bool,
}

impl AzureServiceBusRecordReceipt {
    fn new(proposal: &AzureServiceBusQueueResultProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut receipt = Self {
            recorded: true,
            recorded_at,
            state: proposal.state,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            retained_queue_projection: proposal.evidence.queue.is_some(),
            raw_provider_payload_retained: false,
            durable_receipt: false,
            connected: false,
            native: false,
            first_party: false,
            receipt_authority: false,
            receipt_digest: Digest::zero(),
        };
        receipt.receipt_digest = receipt.recomputed_digest();
        receipt
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&RecordBody {
            recorded: self.recorded,
            recorded_at: &self.recorded_at,
            state: self.state,
            proposal_digest: &self.proposal_digest,
            evidence_digest: &self.evidence_digest,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            retained_queue_projection: self.retained_queue_projection,
            raw_provider_payload_retained: self.raw_provider_payload_retained,
            durable_receipt: self.durable_receipt,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            receipt_authority: self.receipt_authority,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureServiceBusVerifiedRecord {
    pub verified: bool,
    pub state: QueuePostureState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub verification_authority: bool,
    pub adopted_outcome: bool,
}

#[derive(Clone)]
pub struct AzureServiceBusQueueResultService<T>
where
    T: AzureServiceBusTransport,
{
    scope: AzureServiceBusScope,
    permission: PermissionFence,
    secret_reference: SecretReference,
    provider: AzureServiceBusProvider<T>,
    registration: AzureServiceBusRegistration,
}

impl<T> fmt::Debug for AzureServiceBusQueueResultService<T>
where
    T: AzureServiceBusTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureServiceBusQueueResultService")
            .field("scope_digest", &self.scope.digest())
            .field("permission_digest", &self.permission.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T> AzureServiceBusQueueResultService<T>
where
    T: AzureServiceBusTransport,
{
    pub fn register(
        scope: AzureServiceBusScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AzureServiceBusProvider<T>,
    ) -> Result<Self, AzureServiceBusQueueResultServiceError> {
        Self::new(scope, secret_reference, permission, provider)
    }

    pub fn new(
        scope: AzureServiceBusScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AzureServiceBusProvider<T>,
    ) -> Result<Self, AzureServiceBusQueueResultServiceError> {
        scope.validate()?;
        permission.validate()?;
        if scope.permission_digest() != &permission.digest() {
            return Err(AzureServiceBusQueueResultServiceError::ScopeMismatch(
                "permission digest".to_owned(),
            ));
        }
        if !permission.allows(PermissionAction::GetQueue)
            || !permission.allows(PermissionAction::ListQueues)
        {
            return Err(AzureServiceBusQueueResultServiceError::ScopeMismatch(
                "both ARM GET queue read permissions are required".to_owned(),
            ));
        }
        secret_reference
            .validate(&scope)
            .map_err(|error| match error {
                ModelError::SecretRevoked => AzureServiceBusQueueResultServiceError::SecretRevoked,
                other => AzureServiceBusQueueResultServiceError::Model(other),
            })?;
        if !provider.identity().is_layer_one() {
            return Err(AzureServiceBusQueueResultServiceError::ScopeMismatch(
                "provider must remain non-connected, non-native, and non-first-party".to_owned(),
            ));
        }
        let registration =
            AzureServiceBusRegistration::new(&scope, &secret_reference, provider.identity())?;
        Ok(Self {
            scope,
            permission,
            secret_reference,
            provider,
            registration,
        })
    }

    pub const fn describe_capabilities() -> AzureServiceBusCapabilities {
        AzureServiceBusCapabilities::layer_one()
    }

    pub fn scope(&self) -> &AzureServiceBusScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AzureServiceBusProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AzureServiceBusProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AzureServiceBusRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AzureServiceBusRegistration {
        &mut self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret_reference.is_revoked()
    }

    pub fn revoke_registration(&mut self) -> Result<(), AzureServiceBusQueueResultServiceError> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn revoke_secret(&mut self) -> Result<(), AzureServiceBusQueueResultServiceError> {
        self.secret_reference.revoke();
        Ok(())
    }

    pub fn read(
        &mut self,
        request: AzureServiceBusReadRequest,
    ) -> Result<AzureServiceBusReadResult, AzureServiceBusQueueResultServiceError> {
        self.ensure_active_and_bound()?;
        request.validate_against(&self.scope, &self.permission)?;
        let mut current_request = request.clone();
        let mut page_digests = Vec::new();
        let mut seen_continuations = BTreeSet::new();
        let mut provider_errors = Vec::new();
        let mut queue: Option<QueuePostureProjection> = None;
        let mut page_count = 0_u16;
        let mut request_count = 0_u16;
        let mut retry_count = 0_u8;
        let mut consecutive_retries = 0_u8;
        let mut response_bytes = 0_usize;
        let mut partial_reason = None;
        let mut terminal_state = None;

        loop {
            if request_count >= MAX_REQUESTS_PER_READ {
                partial_reason = Some(PartialReason::PageBudget);
                break;
            }
            request_count += 1;
            match self.provider.read(&current_request) {
                Ok(page) => {
                    if page.page_number != page_count + 1 {
                        return Err(AzureServiceBusQueueResultServiceError::Provider(
                            AzureServiceBusProviderError::PageBinding,
                        ));
                    }
                    response_bytes = response_bytes.saturating_add(page.response_bytes);
                    if response_bytes > request.max_response_bytes() {
                        partial_reason = Some(PartialReason::ResponseTooLarge);
                        break;
                    }
                    page_count += 1;
                    for projection in &page.queues {
                        projection.validate_for(&self.scope).map_err(|_| {
                            AzureServiceBusQueueResultServiceError::EvidenceTampered
                        })?;
                        if let Some(existing) = &queue {
                            if existing.posture_digest != projection.posture_digest {
                                partial_reason = Some(PartialReason::ProviderConflict);
                                break;
                            }
                        } else {
                            queue = Some(projection.clone());
                        }
                    }
                    if partial_reason.is_some() {
                        break;
                    }
                    page_digests.push(page.page_digest);
                    consecutive_retries = 0;
                    let Some(continuation) = page.next_continuation else {
                        break;
                    };
                    if !seen_continuations.insert(continuation.token_digest().clone()) {
                        partial_reason = Some(PartialReason::ContinuationReplay);
                        break;
                    }
                    if page_count >= request.max_pages() {
                        partial_reason = Some(PartialReason::PageBudget);
                        break;
                    }
                    current_request = current_request.with_continuation(Some(continuation))?;
                }
                Err(AzureServiceBusProviderError::Transport(error)) => {
                    provider_errors.push(error.evidence());
                    if error.retryable() && consecutive_retries < request.max_retries() {
                        consecutive_retries += 1;
                        retry_count += 1;
                        continue;
                    }
                    terminal_state = Some(if is_access_loss(&error) {
                        QueuePostureState::AccessLost
                    } else {
                        QueuePostureState::ProviderUnknown
                    });
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }

        let state = if let Some(terminal_state) = terminal_state {
            terminal_state
        } else if partial_reason.is_some() {
            QueuePostureState::Partial
        } else {
            let Some(projection) = &queue else {
                partial_reason = Some(PartialReason::MissingQueue);
                return Ok(self.finish_evidence(
                    request,
                    queue,
                    partial_reason,
                    page_count,
                    request_count,
                    retry_count,
                    response_bytes,
                    provider_errors,
                    page_digests,
                    QueuePostureState::Partial,
                    true,
                ));
            };
            if !projection.status.is_supported_state() {
                QueuePostureState::ProviderUnknown
            } else if !projection.complete {
                partial_reason = Some(PartialReason::MissingConfiguration);
                QueuePostureState::Partial
            } else {
                QueuePostureState::from_queue_status(projection.status)
            }
        };
        let truncated = partial_reason.is_some() || state.is_fail_closed();
        Ok(self.finish_evidence(
            request,
            queue,
            partial_reason,
            page_count,
            request_count,
            retry_count,
            response_bytes,
            provider_errors,
            page_digests,
            state,
            truncated,
        ))
    }

    fn finish_evidence(
        &self,
        request: AzureServiceBusReadRequest,
        queue: Option<QueuePostureProjection>,
        partial_reason: Option<PartialReason>,
        page_count: u16,
        request_count: u16,
        retry_count: u8,
        _response_bytes: usize,
        provider_errors: Vec<ProviderErrorEvidence>,
        page_digests: Vec<Digest>,
        state: QueuePostureState,
        truncated: bool,
    ) -> AzureServiceBusReadResult {
        let evidence = AzureServiceBusQueueEvidence::new(
            state,
            queue,
            partial_reason,
            page_count,
            request_count,
            retry_count,
            truncated,
            request.query_digest(),
            self.scope.digest(),
            self.permission.digest(),
            self.provider.identity().provider_digest.clone(),
            self.provider.identity().api_revision.clone(),
            self.provider.identity().api_digest.clone(),
            contract_digest(),
            provider_errors,
            self.provider.identity().provenance,
        );
        AzureServiceBusReadResult {
            evidence,
            page_digests,
        }
    }

    pub fn read_bounded(
        &mut self,
        request: AzureServiceBusReadRequest,
    ) -> Result<AzureServiceBusReadResult, AzureServiceBusQueueResultServiceError> {
        self.read(request)
    }

    pub fn propose(
        &mut self,
        request: AzureServiceBusReadRequest,
        proposed_at: DateTime<Utc>,
    ) -> Result<AzureServiceBusQueueResultProposal, AzureServiceBusQueueResultServiceError> {
        let operation = request.operation();
        let result = self.read(request)?;
        Ok(AzureServiceBusQueueResultProposal::new(
            operation,
            result.evidence,
            proposed_at,
            self.registration.registration_digest.clone(),
        ))
    }

    pub fn propose_now(
        &mut self,
        request: AzureServiceBusReadRequest,
    ) -> Result<AzureServiceBusQueueResultProposal, AzureServiceBusQueueResultServiceError> {
        self.propose(request, Utc::now())
    }

    pub fn record(
        &self,
        proposal: &AzureServiceBusQueueResultProposal,
    ) -> Result<AzureServiceBusRecordReceipt, AzureServiceBusQueueResultServiceError> {
        self.record_at(proposal, Utc::now())
    }

    pub fn record_at(
        &self,
        proposal: &AzureServiceBusQueueResultProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AzureServiceBusRecordReceipt, AzureServiceBusQueueResultServiceError> {
        self.ensure_active_and_bound()?;
        validate_timestamp_order(proposal.proposed_at, recorded_at)?;
        self.verify_proposal(proposal)?;
        Ok(AzureServiceBusRecordReceipt::new(proposal, recorded_at))
    }

    pub fn verify(
        &self,
        receipt: &AzureServiceBusRecordReceipt,
    ) -> Result<AzureServiceBusVerifiedRecord, AzureServiceBusQueueResultServiceError> {
        self.ensure_active_and_bound()?;
        if !receipt.recorded
            || receipt.registration_digest != self.registration.registration_digest
            || receipt.scope_digest != self.scope.digest()
            || receipt.proposal_digest == Digest::zero()
            || receipt.evidence_digest == Digest::zero()
            || receipt.registration_digest == Digest::zero()
            || receipt.connected
            || receipt.native
            || receipt.first_party
            || receipt.receipt_authority
            || receipt.durable_receipt
            || receipt.receipt_digest != receipt.recomputed_digest()
        {
            return Err(AzureServiceBusQueueResultServiceError::RecordTampered);
        }
        let verification_digest = Digest::from_fields(
            "hartevo-azure-service-bus-local-integrity-verification/v1",
            &[
                ("receipt", receipt.receipt_digest.to_string()),
                (
                    "registration",
                    self.registration.registration_digest.to_string(),
                ),
                ("scope", self.scope.digest().to_string()),
            ],
        );
        Ok(AzureServiceBusVerifiedRecord {
            verified: true,
            state: receipt.state,
            proposal_digest: receipt.proposal_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            verification_digest,
            connected: false,
            native: false,
            first_party: false,
            verification_authority: false,
            adopted_outcome: false,
        })
    }

    pub fn verify_proposal(
        &self,
        proposal: &AzureServiceBusQueueResultProposal,
    ) -> Result<(), AzureServiceBusQueueResultServiceError> {
        self.ensure_active_and_bound()?;
        proposal.validate(&self.scope)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.permission.digest()
            || proposal.evidence.provider_digest != self.provider.identity().provider_digest
            || proposal.evidence.provider_revision != self.provider.identity().api_revision
            || proposal.evidence.api_digest != self.provider.identity().api_digest
            || proposal.evidence.contract_digest != contract_digest()
            || proposal.evidence.query_digest == Digest::zero()
        {
            return Err(AzureServiceBusQueueResultServiceError::ProposalTampered);
        }
        Ok(())
    }

    fn ensure_active_and_bound(&self) -> Result<(), AzureServiceBusQueueResultServiceError> {
        if !self.registration.is_active() {
            return Err(AzureServiceBusQueueResultServiceError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(AzureServiceBusQueueResultServiceError::SecretRevoked);
        }
        self.secret_reference
            .validate(&self.scope)
            .map_err(AzureServiceBusQueueResultServiceError::Model)?;
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                self.provider.identity(),
            )
            .map_err(|error| {
                AzureServiceBusQueueResultServiceError::RegistrationDrift(error.to_string())
            })
    }
}

pub type AzureServiceBusService<T> = AzureServiceBusQueueResultService<T>;
pub type AzureServiceBusQueueResult<T> = AzureServiceBusQueueResultService<T>;
pub type AzureServiceBusProposal = AzureServiceBusQueueResultProposal;
pub type AzureServiceBusServiceError = AzureServiceBusQueueResultServiceError;
pub type AzureServiceBusRegistrationReceipt = AzureServiceBusRegistration;
pub type RegistrationState = AzureServiceBusRegistrationState;
pub type AzureServiceBusEvidence = AzureServiceBusQueueEvidence;
