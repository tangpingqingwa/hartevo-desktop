//! Bounded Slack history/replies read, proposal, recording, and verification.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::{
    SLACK_DECISION_CONTRACT_VERSION, SLACK_DECISION_PLUGIN_VERSION, SLACK_DECISION_PROVIDER_ID,
    SLACK_DECISION_SERVICE_ID, contract_digest,
    model::{
        Digest, MAX_MESSAGES, MAX_PAGES, MAX_REPLIES, MAX_REQUESTS_PER_READ, ModelError,
        ProviderErrorEvidence, ProviderErrorKind, RedactionState, RetentionState, Revision,
        SecretReference, SlackDecisionScope, SlackMessageProjection, SlackReadOperation,
        SlackReadRequest, TransportError, TransportProvenance, digest_serialized,
        evidence_policy_digest,
    },
    provider::{SlackProvider, SlackProviderError, SlackProviderIdentity, SlackTransport},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("Slack registration is already revoked")]
    AlreadyRevoked,
    #[error("Slack registration is tampered")]
    Tampered,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SlackDecisionServiceError {
    #[error("Slack decision model error: {0}")]
    Model(#[from] ModelError),
    #[error("Slack decision provider error: {0}")]
    Provider(#[from] SlackProviderError),
    #[error("Slack decision registration is revoked")]
    RegistrationRevoked,
    #[error("Slack decision secret reference is revoked")]
    SecretRevoked,
    #[error("Slack decision registration or provider binding drifted")]
    RegistrationDrift,
    #[error("Slack decision scope mismatch: {0}")]
    ScopeMismatch(&'static str),
    #[error("Slack decision cursor replay or loop detected")]
    CursorReplay,
    #[error("Slack decision retention fence failed")]
    RetentionLoss,
    #[error("Slack decision redaction fence failed")]
    RedactionLoss,
    #[error("Slack decision evidence is stale or tampered")]
    EvidenceTampered,
    #[error("Slack decision proposal is stale or tampered")]
    ProposalTampered,
    #[error("Slack decision record is stale or tampered")]
    RecordTampered,
    #[error("Slack decision registration lifecycle error: {0}")]
    Registration(#[from] RegistrationError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlackCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub operations: [&'static str; 7],
    pub allowlisted_api_operations: [&'static str; 2],
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub raw_message_export: bool,
    pub member_pii: bool,
    pub transcript_store: bool,
    pub kernel_authority: bool,
    pub work_product_adoption: bool,
}

impl SlackCapabilities {
    pub const fn layer_one() -> Self {
        Self {
            service_id: SLACK_DECISION_SERVICE_ID,
            provider_id: SLACK_DECISION_PROVIDER_ID,
            operations: [
                "describe_capabilities",
                "register",
                "revoke_registration",
                "read_bounded",
                "propose",
                "record",
                "verify",
            ],
            allowlisted_api_operations: ["conversations.history", "conversations.replies"],
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            raw_message_export: false,
            member_pii: false,
            transcript_store: false,
            kernel_authority: false,
            work_product_adoption: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlackRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: crate::model::ProviderId,
    pub provider_version: String,
    pub provider_revision: crate::model::ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub token_scope_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationBody<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a crate::model::ProviderId,
    provider_version: &'a str,
    provider_revision: &'a crate::model::ProviderRevision,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    token_scope_digest: &'a Digest,
    scope_digest: &'a Digest,
    evidence_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: Revision,
    state: RegistrationState,
}

impl SlackRegistration {
    pub fn new(
        scope: &SlackDecisionScope,
        secret_reference: &SecretReference,
        provider: &SlackProviderIdentity,
    ) -> Result<Self, RegistrationError> {
        if secret_reference.is_revoked() || secret_reference.scope_digest() != &scope.digest() {
            return Err(RegistrationError::Tampered);
        }
        let mut registration = Self {
            plugin_version: SLACK_DECISION_PLUGIN_VERSION.to_owned(),
            contract_version: SLACK_DECISION_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.version.clone(),
            provider_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            token_scope_digest: scope.token_scope.digest(),
            scope_digest: scope.digest(),
            evidence_digest: evidence_policy_digest(),
            secret_reference_digest: secret_reference.digest().clone(),
            registration_revision: Revision::new(1).map_err(|_| RegistrationError::Tampered)?,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&RegistrationBody {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_version: &self.provider_version,
            provider_revision: &self.provider_revision,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            token_scope_digest: &self.token_scope_digest,
            scope_digest: &self.scope_digest,
            evidence_digest: &self.evidence_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registration_revision: self.registration_revision,
            state: self.state,
        })
    }

    pub fn validate(
        &self,
        scope: &SlackDecisionScope,
        secret_reference: &SecretReference,
        provider: &SlackProviderIdentity,
    ) -> Result<(), RegistrationError> {
        if self.registration_digest != self.recomputed_digest()
            || self.plugin_version != SLACK_DECISION_PLUGIN_VERSION
            || self.contract_version != SLACK_DECISION_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.version
            || self.provider_revision != provider.api_revision
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.token_scope_digest != scope.token_scope.digest()
            || self.scope_digest != scope.digest()
            || self.evidence_digest != evidence_policy_digest()
            || self.secret_reference_digest != *secret_reference.digest()
        {
            return Err(RegistrationError::Tampered);
        }
        if secret_reference.is_revoked() {
            return Err(RegistrationError::Tampered);
        }
        Ok(())
    }

    fn revoke(&mut self) -> Result<(), RegistrationError> {
        if self.state == RegistrationState::Revoked {
            return Err(RegistrationError::AlreadyRevoked);
        }
        self.registration_revision = Revision::new(self.registration_revision.get() + 1)
            .map_err(|_| RegistrationError::Tampered)?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }

    fn restore(&mut self) -> Result<(), RegistrationError> {
        if self.state == RegistrationState::Active {
            return Err(RegistrationError::Tampered);
        }
        self.registration_revision = Revision::new(self.registration_revision.get() + 1)
            .map_err(|_| RegistrationError::Tampered)?;
        self.state = RegistrationState::Active;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlackEvidenceState {
    Complete,
    Empty,
    Partial,
    RetentionUnavailable,
    AccessLoss,
    RateLimited,
    Timeout,
    ProviderUnknown,
    CursorLoop,
    RedactionLoss,
    ScopeDrift,
    ReplayDetected,
    Revoked,
}

impl SlackEvidenceState {
    pub const fn requires_human_review(self) -> bool {
        true
    }

    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlackDecisionEvidence {
    pub operation: SlackReadOperation,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub provider_id: crate::model::ProviderId,
    pub provider_revision: crate::model::ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub token_scope_digest: Digest,
    pub contract_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub provenance: TransportProvenance,
    pub state: SlackEvidenceState,
    pub retention: RetentionState,
    pub redaction: RedactionState,
    pub page_count: u16,
    pub request_count: u16,
    pub retry_count: u8,
    pub participant_count: u16,
    pub message_count: u16,
    pub reply_count: u32,
    pub first_timestamp: Option<DateTime<Utc>>,
    pub last_timestamp: Option<DateTime<Utc>>,
    pub reaction_digest: Digest,
    pub decision_marker_digest: Digest,
    pub content_fingerprint_digest: Digest,
    pub page_digests: Vec<Digest>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub raw_message_export: bool,
    pub raw_attachment_export: bool,
    pub member_pii: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceDigestBody<'a> {
    operation: SlackReadOperation,
    scope_digest: &'a Digest,
    request_digest: &'a Digest,
    provider_id: &'a crate::model::ProviderId,
    provider_revision: &'a crate::model::ProviderRevision,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    token_scope_digest: &'a Digest,
    contract_digest: &'a Digest,
    evidence_policy_digest: &'a Digest,
    provenance: TransportProvenance,
    state: SlackEvidenceState,
    retention: RetentionState,
    redaction: RedactionState,
    page_count: u16,
    request_count: u16,
    retry_count: u8,
    participant_count: u16,
    message_count: u16,
    reply_count: u32,
    first_timestamp: Option<DateTime<Utc>>,
    last_timestamp: Option<DateTime<Utc>>,
    reaction_digest: &'a Digest,
    decision_marker_digest: &'a Digest,
    content_fingerprint_digest: &'a Digest,
    page_digests: &'a [Digest],
    provider_errors: &'a [ProviderErrorEvidence],
}

impl SlackDecisionEvidence {
    #[allow(clippy::too_many_arguments)]
    fn new(
        request: &SlackReadRequest,
        provider: &SlackProviderIdentity,
        state: SlackEvidenceState,
        retention: RetentionState,
        redaction: RedactionState,
        page_count: u16,
        request_count: u16,
        retry_count: u8,
        participant_count: u16,
        message_count: u16,
        reply_count: u32,
        first_timestamp: Option<DateTime<Utc>>,
        last_timestamp: Option<DateTime<Utc>>,
        reaction_digest: Digest,
        decision_marker_digest: Digest,
        content_fingerprint_digest: Digest,
        page_digests: Vec<Digest>,
        provider_errors: Vec<ProviderErrorEvidence>,
    ) -> Self {
        let mut evidence = Self {
            operation: request.operation,
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest.clone(),
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            token_scope_digest: Digest::zero(),
            contract_digest: contract_digest(),
            evidence_policy_digest: evidence_policy_digest(),
            provenance: provider.provenance,
            state,
            retention,
            redaction,
            page_count,
            request_count,
            retry_count,
            participant_count,
            message_count,
            reply_count,
            first_timestamp,
            last_timestamp,
            reaction_digest,
            decision_marker_digest,
            content_fingerprint_digest,
            page_digests,
            provider_errors,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            raw_message_export: false,
            raw_attachment_export: false,
            member_pii: false,
        };
        evidence.evidence_digest = evidence.recomputed_digest();
        evidence
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&EvidenceDigestBody {
            operation: self.operation,
            scope_digest: &self.scope_digest,
            request_digest: &self.request_digest,
            provider_id: &self.provider_id,
            provider_revision: &self.provider_revision,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            token_scope_digest: &self.token_scope_digest,
            contract_digest: &self.contract_digest,
            evidence_policy_digest: &self.evidence_policy_digest,
            provenance: self.provenance,
            state: self.state,
            retention: self.retention,
            redaction: self.redaction,
            page_count: self.page_count,
            request_count: self.request_count,
            retry_count: self.retry_count,
            participant_count: self.participant_count,
            message_count: self.message_count,
            reply_count: self.reply_count,
            first_timestamp: self.first_timestamp,
            last_timestamp: self.last_timestamp,
            reaction_digest: &self.reaction_digest,
            decision_marker_digest: &self.decision_marker_digest,
            content_fingerprint_digest: &self.content_fingerprint_digest,
            page_digests: &self.page_digests,
            provider_errors: &self.provider_errors,
        })
    }

    pub fn validate(&self) -> Result<(), SlackDecisionServiceError> {
        if self.evidence_digest != self.recomputed_digest()
            || self.contract_digest != contract_digest()
            || self.evidence_policy_digest != evidence_policy_digest()
            || self.scope_digest.is_zero()
            || self.request_digest.is_zero()
            || self.token_scope_digest.is_zero()
            || self.connected
            || self.native
            || self.first_party
            || self.raw_message_export
            || self.raw_attachment_export
            || self.member_pii
        {
            return Err(SlackDecisionServiceError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlackReadResult {
    pub evidence: SlackDecisionEvidence,
    pub page_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlackDecisionProposal {
    pub operation: SlackReadOperation,
    pub evidence: SlackDecisionEvidence,
    pub proposed_at: DateTime<Utc>,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub raw_message_export: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalDigestBody<'a> {
    operation: SlackReadOperation,
    evidence_digest: &'a Digest,
    proposed_at: DateTime<Utc>,
    registration_digest: &'a Digest,
    requires_human_review: bool,
    safe_to_promote: bool,
}

impl SlackDecisionProposal {
    fn new(
        evidence: SlackDecisionEvidence,
        proposed_at: DateTime<Utc>,
        registration_digest: Digest,
    ) -> Self {
        let mut proposal = Self {
            operation: evidence.operation,
            evidence,
            proposed_at,
            registration_digest,
            proposal_digest: Digest::zero(),
            requires_human_review: true,
            safe_to_promote: false,
            connected: false,
            native: false,
            first_party: false,
            raw_message_export: false,
            adopted_outcome: false,
            truth_authority: false,
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&ProposalDigestBody {
            operation: self.operation,
            evidence_digest: &self.evidence.evidence_digest,
            proposed_at: self.proposed_at,
            registration_digest: &self.registration_digest,
            requires_human_review: self.requires_human_review,
            safe_to_promote: self.safe_to_promote,
        })
    }

    pub fn validate(&self) -> Result<(), SlackDecisionServiceError> {
        self.evidence.validate()?;
        if self.operation != self.evidence.operation
            || self.proposal_digest != self.recomputed_digest()
            || !self.requires_human_review
            || self.safe_to_promote
            || self.connected
            || self.native
            || self.first_party
            || self.raw_message_export
            || self.adopted_outcome
            || self.truth_authority
        {
            return Err(SlackDecisionServiceError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlackDecisionRecord {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub state: SlackEvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub record_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub durable_native_receipt: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordDigestBody<'a> {
    recorded: bool,
    recorded_at: DateTime<Utc>,
    state: SlackEvidenceState,
    proposal_digest: &'a Digest,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
}

impl SlackDecisionRecord {
    fn new(proposal: &SlackDecisionProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut record = Self {
            recorded: true,
            recorded_at,
            state: proposal.evidence.state,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            record_digest: Digest::zero(),
            connected: false,
            native: false,
            durable_native_receipt: false,
        };
        record.record_digest = record.recomputed_digest();
        record
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&RecordDigestBody {
            recorded: self.recorded,
            recorded_at: self.recorded_at,
            state: self.state,
            proposal_digest: &self.proposal_digest,
            evidence_digest: &self.evidence_digest,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlackVerifiedDecision {
    pub verified: bool,
    pub state: SlackEvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub durable_native_receipt: bool,
    pub adopted_outcome: bool,
}

#[derive(Debug)]
pub struct SlackDecisionService<T> {
    scope: SlackDecisionScope,
    secret_reference: SecretReference,
    provider: SlackProvider<T>,
    registration: SlackRegistration,
}

impl<T> SlackDecisionService<T>
where
    T: SlackTransport,
{
    pub fn new(
        scope: SlackDecisionScope,
        secret_reference: SecretReference,
        provider: SlackProvider<T>,
    ) -> Result<Self, SlackDecisionServiceError> {
        scope.validate()?;
        if secret_reference.scope_digest() != &scope.digest() {
            return Err(SlackDecisionServiceError::ScopeMismatch("secret reference"));
        }
        let registration = SlackRegistration::new(&scope, &secret_reference, provider.identity())
            .map_err(SlackDecisionServiceError::Registration)?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
        })
    }

    pub fn register(
        scope: SlackDecisionScope,
        secret_reference: SecretReference,
        provider: SlackProvider<T>,
    ) -> Result<Self, SlackDecisionServiceError> {
        Self::new(scope, secret_reference, provider)
    }

    pub const fn capabilities() -> SlackCapabilities {
        SlackCapabilities::layer_one()
    }

    pub fn scope(&self) -> &SlackDecisionScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_mut(&mut self) -> &mut SecretReference {
        &mut self.secret_reference
    }

    pub fn revoke_secret_reference(&mut self) {
        self.secret_reference.revoke();
    }

    pub fn provider(&self) -> &SlackProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut SlackProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &SlackRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn revoke_registration(&mut self) -> Result<(), SlackDecisionServiceError> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn restore_registration(&mut self) -> Result<(), SlackDecisionServiceError> {
        self.registration.restore()?;
        self.ensure_active_and_bound()
    }

    pub fn read_bounded(
        &mut self,
        request: SlackReadRequest,
    ) -> Result<SlackReadResult, SlackDecisionServiceError> {
        self.read(request)
    }

    pub fn read(
        &mut self,
        request: SlackReadRequest,
    ) -> Result<SlackReadResult, SlackDecisionServiceError> {
        self.ensure_active_and_bound()?;
        self.validate_request(&request)?;

        let initial_request = request.clone();
        let mut current_request = request;
        let mut page_digests = Vec::new();
        let mut provider_errors = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        let mut page_count = 0_u16;
        let mut request_count = 0_u16;
        let mut retry_count = 0_u8;
        let mut consecutive_retries = 0_u8;
        let mut response_bytes = 0_usize;
        let mut participant_count = 0_u16;
        let mut message_count = 0_u16;
        let mut reply_count = 0_u32;
        let mut first_timestamp = None;
        let mut last_timestamp = None;
        let mut reaction_parts = Vec::new();
        let mut decision_marker_parts = Vec::new();
        let mut content_parts = Vec::new();
        let mut retention = RetentionState::WithinWindow;
        let mut redaction = RedactionState::Redacted;

        let state = loop {
            if request_count >= MAX_REQUESTS_PER_READ {
                break SlackEvidenceState::Partial;
            }
            request_count += 1;
            match self.provider.read_page(&current_request) {
                Ok(page) => {
                    if page.page_number != page_count + 1 {
                        return Err(SlackDecisionServiceError::Provider(
                            SlackProviderError::PageBinding,
                        ));
                    }
                    page.validate()
                        .map_err(|_| SlackDecisionServiceError::EvidenceTampered)?;
                    response_bytes = response_bytes.saturating_add(page.response_bytes);
                    if response_bytes > crate::model::MAX_RESPONSE_BYTES {
                        break SlackEvidenceState::Partial;
                    }
                    if !page.redaction.is_safe() {
                        redaction = page.redaction;
                        break SlackEvidenceState::RedactionLoss;
                    }
                    if !page.retention.is_safe() {
                        retention = page.retention;
                        break SlackEvidenceState::RetentionUnavailable;
                    }
                    page_count += 1;
                    page_digests.push(page.page_digest.clone());
                    if message_count + u16::try_from(page.messages.len()).unwrap_or(u16::MAX)
                        > MAX_MESSAGES as u16
                    {
                        break SlackEvidenceState::Partial;
                    }
                    let page_replies = page
                        .messages
                        .iter()
                        .map(|message| u32::from(message.reply_count))
                        .sum::<u32>();
                    if reply_count.saturating_add(page_replies) > MAX_REPLIES as u32 {
                        break SlackEvidenceState::Partial;
                    }
                    for message in &page.messages {
                        Self::accumulate_message(
                            message,
                            &mut participant_count,
                            &mut message_count,
                            &mut reply_count,
                            &mut first_timestamp,
                            &mut last_timestamp,
                            &mut reaction_parts,
                            &mut decision_marker_parts,
                            &mut content_parts,
                        );
                    }
                    consecutive_retries = 0;
                    let Some(cursor) = page.next_cursor else {
                        break if message_count == 0 {
                            SlackEvidenceState::Empty
                        } else {
                            SlackEvidenceState::Complete
                        };
                    };
                    if !seen_cursors.insert(cursor.token_digest().clone()) {
                        break SlackEvidenceState::CursorLoop;
                    }
                    if page_count >= current_request.max_pages {
                        break SlackEvidenceState::Partial;
                    }
                    current_request = current_request
                        .with_cursor(Some(cursor))
                        .map_err(|_| SlackDecisionServiceError::CursorReplay)?;
                }
                Err(SlackProviderError::Transport(error)) => {
                    provider_errors.push(ProviderErrorEvidence::new(&error));
                    if matches!(
                        error,
                        TransportError::Provider(
                            ProviderErrorKind::RateLimited | ProviderErrorKind::Timeout,
                        )
                    ) && consecutive_retries < 2
                    {
                        consecutive_retries += 1;
                        retry_count = retry_count.saturating_add(1);
                        continue;
                    }
                    break state_for_provider_error(&error);
                }
                Err(SlackProviderError::RedactionLoss) => {
                    redaction = RedactionState::Unredacted;
                    break SlackEvidenceState::RedactionLoss;
                }
                Err(SlackProviderError::RetentionLoss) => {
                    retention = RetentionState::Unavailable;
                    break SlackEvidenceState::RetentionUnavailable;
                }
                Err(error) => return Err(error.into()),
            }
        };

        let evidence = SlackDecisionEvidence::new(
            &initial_request,
            self.provider.identity(),
            state,
            retention,
            redaction,
            page_count,
            request_count,
            retry_count,
            participant_count,
            message_count,
            reply_count,
            first_timestamp,
            last_timestamp,
            Digest::from_parts("hartevo-slack-reaction-digest/v1", &reaction_parts),
            digest_or_zero(
                "hartevo-slack-decision-marker-digest/v1",
                &decision_marker_parts,
            ),
            Digest::from_parts("hartevo-slack-content-fingerprint/v1", &content_parts),
            page_digests.clone(),
            provider_errors,
        );
        let mut evidence = evidence;
        evidence.token_scope_digest = self.scope.token_scope.digest();
        evidence.evidence_digest = evidence.recomputed_digest();
        let evidence = evidence;
        Ok(SlackReadResult {
            evidence,
            page_digests,
        })
    }

    pub fn propose(
        &mut self,
        request: SlackReadRequest,
        proposed_at: DateTime<Utc>,
    ) -> Result<SlackDecisionProposal, SlackDecisionServiceError> {
        let result = self.read(request)?;
        Ok(SlackDecisionProposal::new(
            result.evidence,
            proposed_at,
            self.registration.registration_digest.clone(),
        ))
    }

    pub fn record(
        &self,
        proposal: &SlackDecisionProposal,
    ) -> Result<SlackDecisionRecord, SlackDecisionServiceError> {
        self.record_at(proposal, Utc::now())
    }

    pub fn record_at(
        &self,
        proposal: &SlackDecisionProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<SlackDecisionRecord, SlackDecisionServiceError> {
        self.ensure_active_and_bound()?;
        self.verify_proposal(proposal)?;
        Ok(SlackDecisionRecord::new(proposal, recorded_at))
    }

    pub fn verify(
        &self,
        record: &SlackDecisionRecord,
    ) -> Result<SlackVerifiedDecision, SlackDecisionServiceError> {
        self.ensure_active_and_bound()?;
        if !record.recorded
            || record.registration_digest != self.registration.registration_digest
            || record.scope_digest != self.scope.digest()
            || record.record_digest != record.recomputed_digest()
            || record.connected
            || record.native
            || record.durable_native_receipt
        {
            return Err(SlackDecisionServiceError::RecordTampered);
        }
        let verification_digest = Digest::from_parts(
            "hartevo-slack-verified-decision/v1",
            &[
                record.record_digest.to_string(),
                record.registration_digest.to_string(),
                record.scope_digest.to_string(),
            ],
        );
        Ok(SlackVerifiedDecision {
            verified: true,
            state: record.state,
            proposal_digest: record.proposal_digest.clone(),
            evidence_digest: record.evidence_digest.clone(),
            registration_digest: record.registration_digest.clone(),
            verification_digest,
            connected: false,
            native: false,
            durable_native_receipt: false,
            adopted_outcome: false,
        })
    }

    pub fn verify_proposal(
        &self,
        proposal: &SlackDecisionProposal,
    ) -> Result<(), SlackDecisionServiceError> {
        self.ensure_active_and_bound()?;
        proposal.validate()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.token_scope_digest != self.scope.token_scope.digest()
            || proposal.evidence.provider_id != self.provider.identity().provider_id
            || proposal.evidence.provider_revision != self.provider.identity().api_revision
            || proposal.evidence.provider_digest != self.provider.identity().provider_digest
            || proposal.evidence.api_digest != self.provider.identity().api_digest
            || proposal.evidence.contract_digest != contract_digest()
            || proposal.evidence.evidence_policy_digest != evidence_policy_digest()
        {
            return Err(SlackDecisionServiceError::ProposalTampered);
        }
        Ok(())
    }

    fn ensure_active_and_bound(&self) -> Result<(), SlackDecisionServiceError> {
        if !self.registration.is_active() {
            return Err(SlackDecisionServiceError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(SlackDecisionServiceError::SecretRevoked);
        }
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                self.provider.identity(),
            )
            .map_err(|_| SlackDecisionServiceError::RegistrationDrift)
    }

    fn validate_request(
        &self,
        request: &SlackReadRequest,
    ) -> Result<(), SlackDecisionServiceError> {
        if request.request_digest != request.recomputed_digest() {
            return Err(SlackDecisionServiceError::ScopeMismatch("request digest"));
        }
        if request.scope_digest != self.scope.digest()
            || request.channel != self.scope.channel
            || request.thread != self.scope.thread
            || request.time_window != self.scope.time_window
        {
            return Err(SlackDecisionServiceError::ScopeMismatch("read scope"));
        }
        if request.max_pages > MAX_PAGES || request.page_size == 0 {
            return Err(SlackDecisionServiceError::ScopeMismatch("read bounds"));
        }
        if let Some(cursor) = request.cursor.as_ref()
            && !cursor.is_bound_to(&request.binding_digest())
        {
            return Err(SlackDecisionServiceError::CursorReplay);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn accumulate_message(
        message: &SlackMessageProjection,
        participant_count: &mut u16,
        message_count: &mut u16,
        reply_count: &mut u32,
        first_timestamp: &mut Option<DateTime<Utc>>,
        last_timestamp: &mut Option<DateTime<Utc>>,
        reaction_parts: &mut Vec<String>,
        decision_marker_parts: &mut Vec<String>,
        content_parts: &mut Vec<String>,
    ) {
        *participant_count = participant_count.saturating_add(1);
        *message_count = message_count.saturating_add(1);
        *reply_count = reply_count.saturating_add(u32::from(message.reply_count));
        *first_timestamp = Some(
            first_timestamp.map_or(message.timestamp, |current| current.min(message.timestamp)),
        );
        *last_timestamp = Some(
            last_timestamp.map_or(message.timestamp, |current| current.max(message.timestamp)),
        );
        reaction_parts.push(message.reaction_digest.to_string());
        if let Some(marker) = &message.decision_marker_digest {
            decision_marker_parts.push(marker.to_string());
        }
        content_parts.push(message.content_fingerprint.to_string());
    }
}

fn state_for_provider_error(error: &TransportError) -> SlackEvidenceState {
    match error.kind() {
        ProviderErrorKind::PermissionDenied | ProviderErrorKind::Revoked => {
            SlackEvidenceState::AccessLoss
        }
        ProviderErrorKind::RetentionUnavailable => SlackEvidenceState::RetentionUnavailable,
        ProviderErrorKind::RateLimited => SlackEvidenceState::RateLimited,
        ProviderErrorKind::Timeout => SlackEvidenceState::Timeout,
        ProviderErrorKind::ScopeDrift => SlackEvidenceState::ScopeDrift,
        ProviderErrorKind::RedactionLoss => SlackEvidenceState::RedactionLoss,
        ProviderErrorKind::CursorReplay => SlackEvidenceState::ReplayDetected,
        ProviderErrorKind::CursorLoop => SlackEvidenceState::CursorLoop,
        ProviderErrorKind::ProviderUnknown => SlackEvidenceState::ProviderUnknown,
    }
}

fn digest_or_zero(domain: &str, parts: &[String]) -> Digest {
    if parts.is_empty() {
        Digest::zero()
    } else {
        Digest::from_parts(domain, parts)
    }
}
