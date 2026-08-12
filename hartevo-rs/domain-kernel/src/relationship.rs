use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    AccountId, ActorId, CampaignId, CompanyId, Connection, ConnectionId, ConnectionSnapshot,
    ConsentPurpose, ConsentRecord, ConsentRecordId, ConsentState, ConsentStatus, ContactChannel,
    ConversationIdentitySnapshot, Effect, EffectId, EffectStatus, MessageId, Mission, MissionId,
    Money, OpportunityId, PersonId, ProjectId, ReceiptId, TenantId, VerificationStatus,
};

const SEND_AUTHORIZATION_TTL_MINUTES: i64 = 10;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessagingGateway {
    Gmail,
    Outlook,
    Resend,
    Chatwoot,
    Social,
    Slack,
    Teams,
    Feishu,
}

impl MessagingGateway {
    pub fn supports_provider(&self, provider: &str) -> bool {
        match self {
            Self::Gmail => provider == "gmail",
            Self::Outlook => provider == "outlook",
            Self::Resend => provider == "resend",
            Self::Chatwoot => provider == "chatwoot",
            Self::Social => matches!(
                provider,
                "meta" | "tiktok" | "x" | "linkedin" | "reddit" | "youtube"
            ),
            Self::Slack => provider == "slack",
            Self::Teams => provider == "teams",
            Self::Feishu => provider == "feishu",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationState {
    Open,
    WaitingHuman,
    Resolved,
    Closed,
    DeadLetter,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum ConversationControl {
    Agent {
        generation: u64,
        resumed_at: DateTime<Utc>,
    },
    Human {
        generation: u64,
        actor_id: ActorId,
        acquired_at: DateTime<Utc>,
    },
    Paused {
        generation: u64,
        reason_digest: String,
        paused_at: DateTime<Utc>,
    },
}

impl ConversationControl {
    pub const fn generation(&self) -> u64 {
        match self {
            Self::Agent { generation, .. }
            | Self::Human { generation, .. }
            | Self::Paused { generation, .. } => *generation,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationContentRisk {
    Safe,
    PromptInjectionSuspected,
    MaliciousAttachment,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum MessageDelivery {
    Received,
    Draft,
    EffectPrepared {
        effect_id: EffectId,
    },
    Sent {
        effect_id: EffectId,
        receipt_id: ReceiptId,
    },
    Failed {
        effect_id: EffectId,
    },
    Uncertain {
        effect_id: EffectId,
        receipt_id: Option<ReceiptId>,
    },
    ReconciledNotSent {
        effect_id: EffectId,
    },
    ReconciliationDeadLetter {
        effect_id: EffectId,
    },
    CancelledByHandoff {
        effect_id: EffectId,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationMessage {
    pub id: MessageId,
    pub direction: MessageDirection,
    pub provider_event_digest: Option<String>,
    pub content_digest: String,
    /// Exact conversation/person/account/content/control scope prepared for an outbound effect.
    /// It is immutable once assigned and is re-read before provider execution.
    #[serde(default)]
    pub effect_scope_digest: Option<String>,
    /// Consent evidence or explicit not-required evidence used to derive the
    /// immutable outbound effect scope. It never contains message content.
    #[serde(default)]
    pub authorization_evidence_digest: Option<String>,
    pub attachment_digests: BTreeSet<String>,
    pub risk: ConversationContentRisk,
    pub classification_confidence: Option<Decimal>,
    pub delivery: MessageDelivery,
    pub control_generation: u64,
    pub occurred_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}

impl ConversationMessage {
    fn validate(&self) -> Result<(), RelationshipError> {
        let direction_matches = matches!(
            (&self.direction, &self.delivery),
            (MessageDirection::Inbound, MessageDelivery::Received)
                | (
                    MessageDirection::Outbound,
                    MessageDelivery::Draft
                        | MessageDelivery::EffectPrepared { .. }
                        | MessageDelivery::Sent { .. }
                        | MessageDelivery::Failed { .. }
                        | MessageDelivery::Uncertain { .. }
                        | MessageDelivery::ReconciledNotSent { .. }
                        | MessageDelivery::ReconciliationDeadLetter { .. }
                        | MessageDelivery::CancelledByHandoff { .. }
                )
        );
        let outbound_provider_acceptance = matches!(
            self.delivery,
            MessageDelivery::Sent { .. }
                | MessageDelivery::Uncertain {
                    receipt_id: Some(_),
                    ..
                }
        );
        if self.id.as_str().trim().is_empty()
            || !is_sha256(&self.content_digest)
            || self
                .provider_event_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || self
                .attachment_digests
                .iter()
                .any(|digest| !is_sha256(digest))
            || self
                .effect_scope_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || self
                .authorization_evidence_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || self.control_generation == 0
            || self.received_at < self.occurred_at - Duration::days(7)
            || self.delivered_at.is_some_and(|delivered| {
                self.direction != MessageDirection::Outbound || delivered < self.occurred_at
            })
            || self
                .classification_confidence
                .is_some_and(|confidence| confidence < Decimal::ZERO || confidence > Decimal::ONE)
            || message_effect_id(&self.delivery)
                .is_some_and(|effect_id| effect_id.as_str().trim().is_empty())
            || !direction_matches
            || (self.direction == MessageDirection::Inbound && self.provider_event_digest.is_none())
            || (self.direction == MessageDirection::Inbound && self.effect_scope_digest.is_some())
            || (self.direction == MessageDirection::Inbound
                && self.authorization_evidence_digest.is_some())
            || (matches!(
                self.delivery,
                MessageDelivery::EffectPrepared { .. }
                    | MessageDelivery::Sent { .. }
                    | MessageDelivery::Failed { .. }
                    | MessageDelivery::Uncertain { .. }
                    | MessageDelivery::ReconciledNotSent { .. }
                    | MessageDelivery::ReconciliationDeadLetter { .. }
                    | MessageDelivery::CancelledByHandoff { .. }
            ) && self.effect_scope_digest.is_none())
            || (matches!(self.delivery, MessageDelivery::Draft)
                && (self.effect_scope_digest.is_some()
                    || self.authorization_evidence_digest.is_some()))
            || (self.direction == MessageDirection::Outbound
                && (outbound_provider_acceptance != self.delivered_at.is_some()
                    || outbound_provider_acceptance != self.provider_event_digest.is_some()))
        {
            return Err(RelationshipError::InvalidConversationMessage);
        }
        Ok(())
    }
}

fn message_effect_id(delivery: &MessageDelivery) -> Option<&EffectId> {
    match delivery {
        MessageDelivery::EffectPrepared { effect_id }
        | MessageDelivery::Sent { effect_id, .. }
        | MessageDelivery::Failed { effect_id }
        | MessageDelivery::Uncertain { effect_id, .. }
        | MessageDelivery::ReconciledNotSent { effect_id }
        | MessageDelivery::ReconciliationDeadLetter { effect_id }
        | MessageDelivery::CancelledByHandoff { effect_id } => Some(effect_id),
        MessageDelivery::Received | MessageDelivery::Draft => None,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookAttestation {
    pub signature_verified: bool,
    pub route_digest: String,
    pub provider: String,
    pub connection_id: ConnectionId,
    pub account_id: AccountId,
    pub received_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundMessageInput {
    pub id: MessageId,
    pub provider_event_digest: String,
    pub content_digest: String,
    pub attachment_digests: BTreeSet<String>,
    pub risk: ConversationContentRisk,
    pub classification_confidence: Decimal,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundIngest {
    Inserted,
    Duplicate,
}

#[derive(Clone, Copy, Debug)]
pub enum AutomatedReplyAuthorization<'a> {
    Consent(&'a ConsentRecord),
    NotRequired { evidence_digest: &'a str },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedAutomaticReply {
    pub message_id: MessageId,
    pub effect_id: EffectId,
    pub control_generation: u64,
    pub scope_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Conversation {
    pub id: crate::ConversationId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: Option<MissionId>,
    pub person_id: PersonId,
    pub company_id: Option<CompanyId>,
    pub gateway: MessagingGateway,
    pub provider: String,
    pub connection_id: ConnectionId,
    pub account_id: AccountId,
    pub route_digest: String,
    pub contact_channel: ContactChannel,
    pub market: String,
    pub state: ConversationState,
    pub control: ConversationControl,
    pub messages: Vec<ConversationMessage>,
    pub last_resume_evidence_digest: Option<String>,
    /// Evidence for the latest explicit pause or terminal state transition.
    /// Legacy snapshots may omit it, but every new command records it.
    #[serde(default)]
    pub last_state_evidence_digest: Option<String>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Conversation {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        id: crate::ConversationId,
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: Option<MissionId>,
        person_id: PersonId,
        company_id: Option<CompanyId>,
        gateway: MessagingGateway,
        provider: impl Into<String>,
        connection_id: ConnectionId,
        account_id: AccountId,
        route_digest: impl Into<String>,
        contact_channel: ContactChannel,
        market: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, RelationshipError> {
        let provider = provider.into().trim().to_owned();
        let conversation = Self {
            id,
            tenant_id,
            project_id,
            mission_id,
            person_id,
            company_id,
            gateway,
            provider,
            connection_id,
            account_id,
            route_digest: route_digest.into(),
            contact_channel,
            market: market.into().trim().to_owned(),
            state: ConversationState::Open,
            control: ConversationControl::Agent {
                generation: 1,
                resumed_at: now,
            },
            messages: Vec::new(),
            last_resume_evidence_digest: None,
            last_state_evidence_digest: None,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        conversation.validate()?;
        Ok(conversation)
    }

    pub fn validate(&self) -> Result<(), RelationshipError> {
        let message_ids = self
            .messages
            .iter()
            .map(|message| message.id.clone())
            .collect::<BTreeSet<_>>();
        let provider_events = self
            .messages
            .iter()
            .filter_map(|message| message.provider_event_digest.clone())
            .collect::<BTreeSet<_>>();
        let active_prepared_effect = self
            .messages
            .iter()
            .any(|message| matches!(message.delivery, MessageDelivery::EffectPrepared { .. }));
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.person_id.as_str().trim().is_empty()
            || self.provider.trim().is_empty()
            || self.connection_id.as_str().trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || !self.gateway.supports_provider(&self.provider)
            || !is_sha256(&self.route_digest)
            || self.market.is_empty()
            || self.control.generation() == 0
            || self.revision == 0
            || self.created_at > self.updated_at
            || self
                .last_resume_evidence_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || self
                .last_state_evidence_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || self.messages.iter().any(|message| {
                message.validate().is_err()
                    || message.control_generation > self.control.generation()
            })
            || message_ids.len() != self.messages.len()
            || provider_events.len()
                != self
                    .messages
                    .iter()
                    .filter(|message| message.provider_event_digest.is_some())
                    .count()
            || (self.state != ConversationState::DeadLetter
                && self.messages.iter().any(|message| {
                    matches!(
                        message.delivery,
                        MessageDelivery::EffectPrepared { .. }
                            | MessageDelivery::Sent { .. }
                            | MessageDelivery::Failed { .. }
                            | MessageDelivery::Uncertain { .. }
                            | MessageDelivery::ReconciledNotSent { .. }
                            | MessageDelivery::ReconciliationDeadLetter { .. }
                            | MessageDelivery::CancelledByHandoff { .. }
                    ) && message.authorization_evidence_digest.is_none()
                }))
            || (matches!(
                self.control,
                ConversationControl::Human { .. } | ConversationControl::Paused { .. }
            ) && active_prepared_effect)
        {
            return Err(RelationshipError::InvalidConversation);
        }
        Ok(())
    }

    /// Validates a Conversation at a device/Cell trust boundary. The aggregate
    /// is accepted only when its identity, exact provider account, consent
    /// evidence, pending effects, receipts, and independent verification agree.
    pub fn validate_snapshot(
        &self,
        identity: &ConversationIdentitySnapshot,
        connection: &ConnectionSnapshot,
        mission: &Mission,
        consents: &[ConsentRecord],
        now: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        self.validate()?;
        identity
            .validate_for(
                &self.tenant_id,
                &self.project_id,
                &self.person_id,
                self.company_id.as_ref(),
            )
            .map_err(|_| RelationshipError::InvalidConversationSnapshot)?;
        Connection::restore(connection.clone())
            .map_err(|_| RelationshipError::InvalidConversationSnapshot)?;
        let mission_id = self
            .mission_id
            .as_ref()
            .ok_or(RelationshipError::InvalidConversationSnapshot)?;
        if mission.tenant_id != self.tenant_id
            || mission.project_id != self.project_id
            || mission.id != *mission_id
            || connection.tenant_id != self.tenant_id
            || connection.project_id != self.project_id
            || connection.id != self.connection_id
            || connection.provider != self.provider
            || connection.account_id != self.account_id
            || self.created_at > now
            || self.updated_at > now
            || self.provider == "legacy_unresolved"
        {
            return Err(RelationshipError::InvalidConversationSnapshot);
        }
        let mut consent_ids = BTreeSet::new();
        for consent in consents {
            if consent.tenant_id != self.tenant_id
                || consent.project_id != self.project_id
                || consent.person_id != self.person_id
                || !consent_ids.insert(consent.id.clone())
            {
                return Err(RelationshipError::InvalidConversationSnapshot);
            }
        }
        let mut referenced_consents = BTreeSet::new();
        for message in &self.messages {
            if let Some(effect_id) = message_effect_id(&message.delivery) {
                let effect = mission
                    .effects
                    .iter()
                    .find(|effect| effect.id == *effect_id)
                    .ok_or(RelationshipError::InvalidConversationSnapshot)?;
                if !effect
                    .required_scopes
                    .is_subset(&connection.required_scopes)
                {
                    return Err(RelationshipError::InvalidConversationSnapshot);
                }
            }
            if let Some(consent_id) =
                validate_conversation_message_effect(self, message, mission, consents)?
            {
                referenced_consents.insert(consent_id);
            }
        }
        if referenced_consents != consent_ids {
            return Err(RelationshipError::InvalidConversationSnapshot);
        }
        Ok(())
    }

    /// Proves that this snapshot is exactly one legal Conversation command
    /// after `previous`; arbitrary revision jumps and field replacement fail.
    pub fn follows(
        &self,
        previous: &Self,
        identity: &ConversationIdentitySnapshot,
        connection: &ConnectionSnapshot,
        mission: &Mission,
        consents: &[ConsentRecord],
        now: DateTime<Utc>,
    ) -> Result<bool, RelationshipError> {
        let previous_consent_ids = conversation_consent_ids(previous, mission);
        let previous_consents = consents
            .iter()
            .filter(|consent| previous_consent_ids.contains(&consent.id))
            .cloned()
            .collect::<Vec<_>>();
        previous.validate_snapshot(identity, connection, mission, &previous_consents, now)?;
        self.validate_snapshot(identity, connection, mission, consents, now)?;
        self.follows_command(previous)
    }

    /// Verifies the aggregate-only command transition. Storage uses this before
    /// writing any Conversation revision; sync additionally calls `follows` to
    /// bind the transition to identity, Connection, Consent, and Mission facts.
    pub fn follows_command(&self, previous: &Self) -> Result<bool, RelationshipError> {
        previous.validate()?;
        self.validate()?;
        if previous.revision.checked_add(1) != Some(self.revision)
            || !conversation_scope_is_immutable(previous, self)
        {
            return Ok(false);
        }
        Ok(replays_inbound(previous, self)
            || replays_prepared_reply(previous, self)
            || replays_delivery_transition(previous, self)
            || replays_control_transition(previous, self))
    }

    pub fn is_initial_snapshot(&self) -> Result<bool, RelationshipError> {
        self.validate()?;
        Ok(self.revision == 1
            && self.state == ConversationState::Open
            && matches!(
                self.control,
                ConversationControl::Agent {
                    generation: 1,
                    resumed_at,
                } if resumed_at == self.created_at
            )
            && self.messages.is_empty()
            && self.last_resume_evidence_digest.is_none()
            && self.last_state_evidence_digest.is_none()
            && self.updated_at == self.created_at)
    }

    pub fn ingest_inbound(
        &mut self,
        input: InboundMessageInput,
        attestation: &WebhookAttestation,
    ) -> Result<InboundIngest, RelationshipError> {
        if matches!(
            self.state,
            ConversationState::Resolved | ConversationState::Closed | ConversationState::DeadLetter
        ) {
            return Err(RelationshipError::InvalidConversationStateTransition);
        }
        if !attestation.signature_verified
            || attestation.route_digest != self.route_digest
            || attestation.provider != self.provider
            || attestation.connection_id != self.connection_id
            || attestation.account_id != self.account_id
        {
            return Err(RelationshipError::WebhookScopeOrSignatureInvalid);
        }
        if let Some(existing) = self.messages.iter().find(|message| {
            message.provider_event_digest.as_deref() == Some(&input.provider_event_digest)
        }) {
            if existing.content_digest == input.content_digest
                && existing.attachment_digests == input.attachment_digests
            {
                return Ok(InboundIngest::Duplicate);
            }
            return Err(RelationshipError::WebhookReplayConflict);
        }
        let message = ConversationMessage {
            id: input.id,
            direction: MessageDirection::Inbound,
            provider_event_digest: Some(input.provider_event_digest),
            content_digest: input.content_digest,
            effect_scope_digest: None,
            authorization_evidence_digest: None,
            attachment_digests: input.attachment_digests,
            risk: input.risk,
            classification_confidence: Some(input.classification_confidence),
            delivery: MessageDelivery::Received,
            control_generation: self.control.generation(),
            occurred_at: input.occurred_at,
            received_at: attestation.received_at,
            delivered_at: None,
        };
        message.validate()?;
        if self.messages.iter().any(|stored| stored.id == message.id) {
            return Err(RelationshipError::DuplicateMessageId);
        }
        let next_revision = self.prepare_bump(attestation.received_at)?;
        if message.risk != ConversationContentRisk::Safe
            || message
                .classification_confidence
                .is_none_or(|confidence| confidence < automatic_reply_confidence())
        {
            self.state = ConversationState::WaitingHuman;
        }
        self.messages.push(message);
        self.commit_bump(next_revision, attestation.received_at);
        Ok(InboundIngest::Inserted)
    }

    pub fn prepare_automatic_reply(
        &mut self,
        message_id: MessageId,
        content_digest: impl Into<String>,
        effect_id: EffectId,
        expected_generation: u64,
        authorization: AutomatedReplyAuthorization<'_>,
        now: DateTime<Utc>,
    ) -> Result<PreparedAutomaticReply, RelationshipError> {
        self.require_agent_generation(expected_generation)?;
        if self.state != ConversationState::Open
            || self.messages.iter().any(|message| {
                matches!(
                    message.delivery,
                    MessageDelivery::Uncertain { .. }
                        | MessageDelivery::ReconciliationDeadLetter { .. }
                )
            })
        {
            return Err(RelationshipError::AutomaticReplyNotAllowed);
        }
        let latest_inbound = self
            .messages
            .iter()
            .rev()
            .find(|message| message.direction == MessageDirection::Inbound)
            .ok_or(RelationshipError::AutomaticReplyNotAllowed)?;
        if latest_inbound.risk != ConversationContentRisk::Safe
            || latest_inbound
                .classification_confidence
                .is_none_or(|confidence| confidence < automatic_reply_confidence())
        {
            return Err(RelationshipError::AutomaticReplyNotAllowed);
        }
        let authorization_digest = match authorization {
            AutomatedReplyAuthorization::Consent(consent) => {
                if consent.tenant_id != self.tenant_id
                    || consent.project_id != self.project_id
                    || !consent.permits(
                        &self.person_id,
                        &ConsentPurpose::AutomatedReply,
                        &self.contact_channel,
                        &self.market,
                        now,
                    )
                {
                    return Err(RelationshipError::ConsentDoesNotAuthorizeReply);
                }
                consent.evidence_digest.clone()
            }
            AutomatedReplyAuthorization::NotRequired { evidence_digest } => {
                if !is_sha256(evidence_digest) {
                    return Err(RelationshipError::ConsentDoesNotAuthorizeReply);
                }
                evidence_digest.into()
            }
        };
        let content_digest = content_digest.into();
        if !is_sha256(&content_digest)
            || effect_id.as_str().trim().is_empty()
            || self.messages.iter().any(|message| message.id == message_id)
        {
            return Err(RelationshipError::InvalidConversationMessage);
        }
        let scope_digest = conversation_effect_scope_digest(
            self,
            &message_id,
            &content_digest,
            &effect_id,
            expected_generation,
            &authorization_digest,
        );
        let next_revision = self.prepare_bump(now)?;
        self.messages.push(ConversationMessage {
            id: message_id.clone(),
            direction: MessageDirection::Outbound,
            provider_event_digest: None,
            content_digest,
            effect_scope_digest: Some(scope_digest.clone()),
            authorization_evidence_digest: Some(authorization_digest),
            attachment_digests: BTreeSet::new(),
            risk: ConversationContentRisk::Safe,
            classification_confidence: None,
            delivery: MessageDelivery::EffectPrepared {
                effect_id: effect_id.clone(),
            },
            control_generation: expected_generation,
            occurred_at: now,
            received_at: now,
            delivered_at: None,
        });
        self.commit_bump(next_revision, now);
        Ok(PreparedAutomaticReply {
            message_id,
            effect_id,
            control_generation: expected_generation,
            scope_digest,
        })
    }

    pub fn take_human_control(
        &mut self,
        expected_generation: u64,
        actor_id: ActorId,
        now: DateTime<Utc>,
    ) -> Result<u64, RelationshipError> {
        if actor_id.as_str().trim().is_empty()
            || self.control.generation() != expected_generation
            || matches!(self.control, ConversationControl::Human { .. })
            || matches!(
                self.state,
                ConversationState::Closed | ConversationState::DeadLetter
            )
        {
            return Err(RelationshipError::ControlLeaseLost);
        }
        let generation = next_generation(expected_generation)?;
        let next_revision = self.prepare_bump(now)?;
        for message in &mut self.messages {
            if let MessageDelivery::EffectPrepared { effect_id } = &message.delivery {
                message.delivery = MessageDelivery::CancelledByHandoff {
                    effect_id: effect_id.clone(),
                };
            }
        }
        self.control = ConversationControl::Human {
            generation,
            actor_id,
            acquired_at: now,
        };
        self.state = ConversationState::WaitingHuman;
        self.last_state_evidence_digest = None;
        self.commit_bump(next_revision, now);
        Ok(generation)
    }

    pub fn pause_agent(
        &mut self,
        expected_generation: u64,
        reason_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<u64, RelationshipError> {
        let reason_digest = reason_digest.into();
        if self.control.generation() != expected_generation
            || !matches!(self.control, ConversationControl::Agent { .. })
            || matches!(
                self.state,
                ConversationState::Resolved
                    | ConversationState::Closed
                    | ConversationState::DeadLetter
            )
            || !is_sha256(&reason_digest)
        {
            return Err(RelationshipError::InvalidConversationStateTransition);
        }
        let generation = next_generation(expected_generation)?;
        let next_revision = self.prepare_bump(now)?;
        for message in &mut self.messages {
            if let MessageDelivery::EffectPrepared { effect_id } = &message.delivery {
                message.delivery = MessageDelivery::CancelledByHandoff {
                    effect_id: effect_id.clone(),
                };
            }
        }
        self.control = ConversationControl::Paused {
            generation,
            reason_digest: reason_digest.clone(),
            paused_at: now,
        };
        self.state = ConversationState::WaitingHuman;
        self.last_state_evidence_digest = Some(reason_digest);
        self.commit_bump(next_revision, now);
        Ok(generation)
    }

    pub fn resume_agent(
        &mut self,
        expected_generation: u64,
        resume_evidence_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<u64, RelationshipError> {
        let evidence = resume_evidence_digest.into();
        if self.control.generation() != expected_generation
            || !matches!(
                self.control,
                ConversationControl::Human { .. } | ConversationControl::Paused { .. }
            )
            || matches!(
                self.state,
                ConversationState::Resolved
                    | ConversationState::Closed
                    | ConversationState::DeadLetter
            )
            || !is_sha256(&evidence)
        {
            return Err(RelationshipError::ExplicitResumeRequired);
        }
        let generation = next_generation(expected_generation)?;
        let next_revision = self.prepare_bump(now)?;
        self.control = ConversationControl::Agent {
            generation,
            resumed_at: now,
        };
        self.state = ConversationState::Open;
        self.last_resume_evidence_digest = Some(evidence);
        self.last_state_evidence_digest = None;
        self.commit_bump(next_revision, now);
        Ok(generation)
    }

    pub fn resolve(
        &mut self,
        evidence_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        let evidence_digest = evidence_digest.into();
        if !matches!(
            self.state,
            ConversationState::Open | ConversationState::WaitingHuman
        ) || !is_sha256(&evidence_digest)
            || self.messages.iter().any(|message| {
                matches!(
                    message.delivery,
                    MessageDelivery::EffectPrepared { .. }
                        | MessageDelivery::Uncertain { .. }
                        | MessageDelivery::ReconciliationDeadLetter { .. }
                )
            })
        {
            return Err(RelationshipError::InvalidConversationStateTransition);
        }
        let generation = next_generation(self.control.generation())?;
        let next_revision = self.prepare_bump(now)?;
        self.control = ConversationControl::Paused {
            generation,
            reason_digest: evidence_digest.clone(),
            paused_at: now,
        };
        self.state = ConversationState::Resolved;
        self.last_state_evidence_digest = Some(evidence_digest);
        self.commit_bump(next_revision, now);
        Ok(())
    }

    pub fn close(
        &mut self,
        evidence_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        let evidence_digest = evidence_digest.into();
        if self.state != ConversationState::Resolved || !is_sha256(&evidence_digest) {
            return Err(RelationshipError::InvalidConversationStateTransition);
        }
        let generation = next_generation(self.control.generation())?;
        let next_revision = self.prepare_bump(now)?;
        self.control = ConversationControl::Paused {
            generation,
            reason_digest: evidence_digest.clone(),
            paused_at: now,
        };
        self.state = ConversationState::Closed;
        self.last_state_evidence_digest = Some(evidence_digest);
        self.commit_bump(next_revision, now);
        Ok(())
    }

    pub fn mark_dead_letter(
        &mut self,
        evidence_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        let evidence_digest = evidence_digest.into();
        if matches!(
            self.state,
            ConversationState::Closed | ConversationState::DeadLetter
        ) || !is_sha256(&evidence_digest)
            || self
                .messages
                .iter()
                .any(|message| matches!(message.delivery, MessageDelivery::EffectPrepared { .. }))
        {
            return Err(RelationshipError::InvalidConversationStateTransition);
        }
        let generation = next_generation(self.control.generation())?;
        let next_revision = self.prepare_bump(now)?;
        self.control = ConversationControl::Paused {
            generation,
            reason_digest: evidence_digest.clone(),
            paused_at: now,
        };
        self.state = ConversationState::DeadLetter;
        self.last_state_evidence_digest = Some(evidence_digest);
        self.commit_bump(next_revision, now);
        Ok(())
    }

    pub fn authorizes_agent_effect(&self, effect_id: &EffectId, generation: u64) -> bool {
        self.state == ConversationState::Open
            && matches!(
                self.control,
                ConversationControl::Agent {
                    generation: active_generation,
                    ..
                } if active_generation == generation
            )
            && self.messages.iter().any(|message| {
                message.control_generation == generation
                    && matches!(
                        &message.delivery,
                        MessageDelivery::EffectPrepared {
                            effect_id: pending
                        } if pending == effect_id
                    )
            })
    }

    pub fn authorizes_agent_effect_scope(
        &self,
        effect_id: &EffectId,
        generation: u64,
        scope_digest: &str,
    ) -> bool {
        is_sha256(scope_digest)
            && self.authorizes_agent_effect(effect_id, generation)
            && self.messages.iter().any(|message| {
                message.control_generation == generation
                    && message.effect_scope_digest.as_deref() == Some(scope_digest)
                    && message.authorization_evidence_digest.is_some()
                    && matches!(
                        &message.delivery,
                        MessageDelivery::EffectPrepared { effect_id: pending } if pending == effect_id
                    )
            })
    }

    pub fn records_sent_agent_effect_scope(
        &self,
        effect_id: &EffectId,
        generation: u64,
        scope_digest: &str,
        receipt_id: &ReceiptId,
    ) -> bool {
        is_sha256(scope_digest)
            && self.messages.iter().any(|message| {
                message.control_generation == generation
                    && message.effect_scope_digest.as_deref() == Some(scope_digest)
                    && message.authorization_evidence_digest.is_some()
                    && matches!(
                        &message.delivery,
                        MessageDelivery::Sent {
                            effect_id: stored_effect,
                            receipt_id: stored_receipt,
                        } if stored_effect == effect_id && stored_receipt == receipt_id
                    )
                    && message.provider_event_digest.is_some()
                    && message.delivered_at.is_some()
            })
    }

    pub fn record_agent_reply(
        &mut self,
        effect_id: &EffectId,
        receipt_id: ReceiptId,
        provider_event_digest: impl Into<String>,
        generation: u64,
        sent_at: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        if !self.authorizes_agent_effect(effect_id, generation)
            || receipt_id.as_str().trim().is_empty()
        {
            return Err(RelationshipError::ControlLeaseLost);
        }
        let provider_event_digest = provider_event_digest.into();
        if !is_sha256(&provider_event_digest) {
            return Err(RelationshipError::InvalidConversationMessage);
        }
        if self
            .messages
            .iter()
            .any(|message| message.provider_event_digest.as_deref() == Some(&provider_event_digest))
        {
            return Err(RelationshipError::WebhookReplayConflict);
        }
        let message_index = self.prepared_message_index(effect_id)?;
        let next_revision = self.prepare_bump(sent_at)?;
        let message = &mut self.messages[message_index];
        message.delivery = MessageDelivery::Sent {
            effect_id: effect_id.clone(),
            receipt_id,
        };
        message.provider_event_digest = Some(provider_event_digest);
        message.delivered_at = Some(sent_at);
        self.commit_bump(next_revision, sent_at);
        Ok(())
    }

    pub fn mark_agent_reply_failed(
        &mut self,
        effect_id: &EffectId,
        generation: u64,
        failed_at: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        if !self.authorizes_agent_effect(effect_id, generation) {
            return Err(RelationshipError::ControlLeaseLost);
        }
        let message_index = self.prepared_message_index(effect_id)?;
        let next_revision = self.prepare_bump(failed_at)?;
        let message = &mut self.messages[message_index];
        message.delivery = MessageDelivery::Failed {
            effect_id: effect_id.clone(),
        };
        self.commit_bump(next_revision, failed_at);
        Ok(())
    }

    pub fn mark_agent_reply_uncertain(
        &mut self,
        effect_id: &EffectId,
        generation: u64,
        receipt_id: Option<ReceiptId>,
        provider_event_digest: Option<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        if !self.authorizes_agent_effect(effect_id, generation)
            || receipt_id.is_some() != provider_event_digest.is_some()
            || provider_event_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(RelationshipError::ControlLeaseLost);
        }
        if provider_event_digest.as_ref().is_some_and(|digest| {
            self.messages
                .iter()
                .any(|message| message.provider_event_digest.as_ref() == Some(digest))
        }) {
            return Err(RelationshipError::WebhookReplayConflict);
        }
        let accepted = receipt_id.is_some();
        let message_index = self.prepared_message_index(effect_id)?;
        let next_revision = self.prepare_bump(observed_at)?;
        let message = &mut self.messages[message_index];
        message.delivery = MessageDelivery::Uncertain {
            effect_id: effect_id.clone(),
            receipt_id,
        };
        message.provider_event_digest = provider_event_digest;
        message.delivered_at = accepted.then_some(observed_at);
        self.commit_bump(next_revision, observed_at);
        Ok(())
    }

    /// Projects the outcome of a read-only Provider reconciliation. Unlike a
    /// fresh send, this may complete after human handoff because it cannot
    /// authorize another external action; it only resolves the exact earlier
    /// uncertain effect and original control generation.
    #[allow(clippy::too_many_arguments)]
    pub fn record_reconciled_agent_reply(
        &mut self,
        effect_id: &EffectId,
        receipt_id: ReceiptId,
        provider_event_digest: impl Into<String>,
        original_generation: u64,
        accepted_at: DateTime<Utc>,
        reconciled_at: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        let provider_event_digest = provider_event_digest.into();
        let (message_index, next_revision) = self.prepare_reconciled_receipt_projection(
            effect_id,
            &receipt_id,
            &provider_event_digest,
            original_generation,
            accepted_at,
            reconciled_at,
        )?;
        let message = &mut self.messages[message_index];
        message.delivery = MessageDelivery::Sent {
            effect_id: effect_id.clone(),
            receipt_id,
        };
        message.provider_event_digest = Some(provider_event_digest);
        message.delivered_at = Some(accepted_at);
        self.commit_bump(next_revision, reconciled_at);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_reconciled_agent_reply_uncertain_receipt(
        &mut self,
        effect_id: &EffectId,
        receipt_id: ReceiptId,
        provider_event_digest: impl Into<String>,
        original_generation: u64,
        accepted_at: DateTime<Utc>,
        reconciled_at: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        let provider_event_digest = provider_event_digest.into();
        let (message_index, next_revision) = self.prepare_reconciled_receipt_projection(
            effect_id,
            &receipt_id,
            &provider_event_digest,
            original_generation,
            accepted_at,
            reconciled_at,
        )?;
        let message = &mut self.messages[message_index];
        message.delivery = MessageDelivery::Uncertain {
            effect_id: effect_id.clone(),
            receipt_id: Some(receipt_id),
        };
        message.provider_event_digest = Some(provider_event_digest);
        message.delivered_at = Some(accepted_at);
        self.commit_bump(next_revision, reconciled_at);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_reconciled_receipt_projection(
        &self,
        effect_id: &EffectId,
        receipt_id: &ReceiptId,
        provider_event_digest: &str,
        original_generation: u64,
        accepted_at: DateTime<Utc>,
        reconciled_at: DateTime<Utc>,
    ) -> Result<(usize, u64), RelationshipError> {
        let message_index = self.reconciliation_message_index(effect_id, original_generation)?;
        let message = &self.messages[message_index];
        let MessageDelivery::Uncertain {
            receipt_id: previous_receipt,
            ..
        } = &message.delivery
        else {
            return Err(RelationshipError::AutomaticReplyNotAllowed);
        };
        if receipt_id.as_str().trim().is_empty()
            || !is_sha256(provider_event_digest)
            || accepted_at < message.occurred_at
            || accepted_at > reconciled_at
            || previous_receipt
                .as_ref()
                .is_some_and(|previous| previous != receipt_id)
            || message
                .provider_event_digest
                .as_deref()
                .is_some_and(|previous| previous != provider_event_digest)
            || message
                .delivered_at
                .is_some_and(|previous| previous != accepted_at)
            || self.messages.iter().enumerate().any(|(index, candidate)| {
                index != message_index
                    && candidate.provider_event_digest.as_deref() == Some(provider_event_digest)
            })
        {
            return Err(RelationshipError::InvalidConversationMessage);
        }
        Ok((message_index, self.prepare_bump(reconciled_at)?))
    }

    pub fn mark_agent_reply_reconciled_not_sent(
        &mut self,
        effect_id: &EffectId,
        original_generation: u64,
        reconciled_at: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        self.mark_agent_reply_reconciliation_terminal(
            effect_id,
            original_generation,
            MessageDelivery::ReconciledNotSent {
                effect_id: effect_id.clone(),
            },
            reconciled_at,
        )
    }

    pub fn mark_agent_reply_reconciled_failed(
        &mut self,
        effect_id: &EffectId,
        original_generation: u64,
        reconciled_at: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        self.mark_agent_reply_reconciliation_terminal(
            effect_id,
            original_generation,
            MessageDelivery::Failed {
                effect_id: effect_id.clone(),
            },
            reconciled_at,
        )
    }

    pub fn mark_agent_reply_reconciliation_dead_letter(
        &mut self,
        effect_id: &EffectId,
        original_generation: u64,
        reconciled_at: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        self.mark_agent_reply_reconciliation_terminal(
            effect_id,
            original_generation,
            MessageDelivery::ReconciliationDeadLetter {
                effect_id: effect_id.clone(),
            },
            reconciled_at,
        )
    }

    fn mark_agent_reply_reconciliation_terminal(
        &mut self,
        effect_id: &EffectId,
        original_generation: u64,
        delivery: MessageDelivery,
        reconciled_at: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        let message_index = self.reconciliation_message_index(effect_id, original_generation)?;
        let message = &self.messages[message_index];
        if !matches!(message.delivery, MessageDelivery::Uncertain { .. })
            || message.provider_event_digest.is_some()
            || message.delivered_at.is_some()
        {
            return Err(RelationshipError::InvalidConversationMessage);
        }
        let next_revision = self.prepare_bump(reconciled_at)?;
        self.messages[message_index].delivery = delivery;
        self.commit_bump(next_revision, reconciled_at);
        Ok(())
    }

    fn reconciliation_message_index(
        &self,
        effect_id: &EffectId,
        original_generation: u64,
    ) -> Result<usize, RelationshipError> {
        self.messages
            .iter()
            .position(|message| {
                message.control_generation == original_generation
                    && matches!(
                        &message.delivery,
                        MessageDelivery::Uncertain {
                            effect_id: pending,
                            ..
                        } if pending == effect_id
                    )
            })
            .ok_or(RelationshipError::AutomaticReplyNotAllowed)
    }

    fn prepared_message_index(&self, effect_id: &EffectId) -> Result<usize, RelationshipError> {
        self.messages
            .iter()
            .position(|message| {
                matches!(
                    &message.delivery,
                    MessageDelivery::EffectPrepared { effect_id: pending } if pending == effect_id
                )
            })
            .ok_or(RelationshipError::AutomaticReplyNotAllowed)
    }

    fn require_agent_generation(&self, expected_generation: u64) -> Result<(), RelationshipError> {
        if matches!(
            self.control,
            ConversationControl::Agent { generation, .. } if generation == expected_generation
        ) {
            Ok(())
        } else {
            Err(RelationshipError::ControlLeaseLost)
        }
    }

    fn prepare_bump(&self, now: DateTime<Utc>) -> Result<u64, RelationshipError> {
        prepare_aggregate_revision(self.revision, self.updated_at, now)
    }

    fn commit_bump(&mut self, next_revision: u64, now: DateTime<Utc>) {
        self.revision = next_revision;
        self.updated_at = now;
    }
}

fn conversation_scope_is_immutable(previous: &Conversation, next: &Conversation) -> bool {
    previous.id == next.id
        && previous.tenant_id == next.tenant_id
        && previous.project_id == next.project_id
        && previous.mission_id == next.mission_id
        && previous.person_id == next.person_id
        && previous.company_id == next.company_id
        && previous.gateway == next.gateway
        && previous.provider == next.provider
        && previous.connection_id == next.connection_id
        && previous.account_id == next.account_id
        && previous.route_digest == next.route_digest
        && previous.contact_channel == next.contact_channel
        && previous.market == next.market
        && previous.created_at == next.created_at
}

fn conversation_consent_ids(
    conversation: &Conversation,
    mission: &Mission,
) -> BTreeSet<ConsentRecordId> {
    conversation
        .messages
        .iter()
        .filter_map(|message| message_effect_id(&message.delivery))
        .filter_map(|effect_id| {
            mission
                .effects
                .iter()
                .find(|effect| effect.id == *effect_id)
        })
        .filter_map(|effect| effect.consent_record_id.clone())
        .collect()
}

fn validate_conversation_message_effect(
    conversation: &Conversation,
    message: &ConversationMessage,
    mission: &Mission,
    consents: &[ConsentRecord],
) -> Result<Option<ConsentRecordId>, RelationshipError> {
    if message.direction == MessageDirection::Inbound
        || matches!(message.delivery, MessageDelivery::Draft)
    {
        return Ok(None);
    }
    let effect_id = message_effect_id(&message.delivery)
        .ok_or(RelationshipError::InvalidConversationSnapshot)?;
    let effect = mission
        .effects
        .iter()
        .find(|effect| effect.id == *effect_id)
        .ok_or(RelationshipError::InvalidConversationSnapshot)?;
    validate_conversation_effect_scope(conversation, message, effect)?;
    let consent_id =
        validate_conversation_effect_authorization(conversation, message, effect, consents)?;
    if !delivery_matches_effect(message, effect) {
        return Err(RelationshipError::InvalidConversationSnapshot);
    }
    Ok(consent_id)
}

fn validate_conversation_effect_scope(
    conversation: &Conversation,
    message: &ConversationMessage,
    effect: &Effect,
) -> Result<(), RelationshipError> {
    let guard = effect
        .conversation_guard
        .as_ref()
        .ok_or(RelationshipError::InvalidConversationSnapshot)?;
    let authorization_digest = message
        .authorization_evidence_digest
        .as_deref()
        .ok_or(RelationshipError::InvalidConversationSnapshot)?;
    let expected_scope = conversation_effect_scope_digest(
        conversation,
        &message.id,
        &message.content_digest,
        &effect.id,
        message.control_generation,
        authorization_digest,
    );
    let expected_audience = format!(
        "{:x}",
        Sha256::digest(conversation.person_id.as_str().as_bytes())
    );
    if effect.tenant_id != conversation.tenant_id
        || effect.project_id != conversation.project_id
        || Some(&effect.mission_id) != conversation.mission_id.as_ref()
        || effect.capability != "conversation.reply"
        || effect.provider != conversation.provider
        || effect.connection_id.as_ref() != Some(&conversation.connection_id)
        || effect.account_id.as_ref() != Some(&conversation.account_id)
        || effect.target_resource != format!("conversation://{}", conversation.id)
        || effect.audience_digest.as_deref() != Some(expected_audience.as_str())
        || effect.payload_digest != message.content_digest
        || effect.amount.amount_minor != 0
        || effect.expires_at <= message.occurred_at
        || guard.conversation_id != conversation.id
        || guard.control_generation != message.control_generation
        || guard.scope_digest != expected_scope
        || message.effect_scope_digest.as_deref() != Some(expected_scope.as_str())
    {
        return Err(RelationshipError::InvalidConversationSnapshot);
    }
    Ok(())
}

fn validate_conversation_effect_authorization(
    conversation: &Conversation,
    message: &ConversationMessage,
    effect: &Effect,
    consents: &[ConsentRecord],
) -> Result<Option<ConsentRecordId>, RelationshipError> {
    match effect.consent {
        ConsentState::NotRequired
            if effect.consent_record_id.is_none() && effect.consent_requirement.is_none() =>
        {
            Ok(None)
        }
        ConsentState::Confirmed => {
            let record_id = effect
                .consent_record_id
                .as_ref()
                .ok_or(RelationshipError::InvalidConversationSnapshot)?;
            let requirement = effect
                .consent_requirement
                .as_ref()
                .ok_or(RelationshipError::InvalidConversationSnapshot)?;
            let record = consents
                .iter()
                .find(|record| record.id == *record_id)
                .ok_or(RelationshipError::InvalidConversationSnapshot)?;
            if requirement.person_id != conversation.person_id
                || requirement.purpose != ConsentPurpose::AutomatedReply
                || requirement.channel != conversation.contact_channel
                || !requirement
                    .market
                    .eq_ignore_ascii_case(&conversation.market)
                || message.authorization_evidence_digest.as_deref()
                    != Some(record.evidence_digest.as_str())
                || !consent_authorized_at(record, requirement, message.occurred_at)
            {
                return Err(RelationshipError::InvalidConversationSnapshot);
            }
            Ok(Some(record_id.clone()))
        }
        _ => Err(RelationshipError::InvalidConversationSnapshot),
    }
}

fn consent_authorized_at(
    record: &ConsentRecord,
    requirement: &crate::ConsentRequirement,
    at: DateTime<Utc>,
) -> bool {
    !record.tenant_id.as_str().trim().is_empty()
        && !record.project_id.as_str().trim().is_empty()
        && record.person_id == requirement.person_id
        && record.purpose == requirement.purpose
        && record.channel == requirement.channel
        && record.market.eq_ignore_ascii_case(&requirement.market)
        && is_sha256(&record.evidence_digest)
        && record.granted_at.is_some_and(|granted| granted <= at)
        && record.valid_until.is_none_or(|until| until > at)
        && record.withdrawn_at.is_none_or(|withdrawn| withdrawn > at)
        && matches!(
            record.status,
            ConsentStatus::Granted | ConsentStatus::Withdrawn
        )
}

fn delivery_matches_effect(message: &ConversationMessage, effect: &Effect) -> bool {
    match &message.delivery {
        MessageDelivery::EffectPrepared { effect_id } => effect_id == &effect.id,
        MessageDelivery::Sent {
            effect_id,
            receipt_id,
        } => {
            effect_id == &effect.id
                && effect.status == EffectStatus::Verified
                && effect.receipt.as_ref().is_some_and(|receipt| {
                    receipt.id == *receipt_id
                        && receipt.provider == effect.provider
                        && message.provider_event_digest.as_deref()
                            == Some(provider_receipt_event_digest(receipt).as_str())
                        && message.delivered_at == Some(receipt.accepted_at)
                })
                && effect.verification.as_ref().is_some_and(|verification| {
                    verification.status == VerificationStatus::Confirmed
                        && verification.independent
                        && verification.receipt_id == *receipt_id
                })
        }
        MessageDelivery::Failed { effect_id } => {
            effect_id == &effect.id
                && effect.status == EffectStatus::Failed
                && effect.receipt.is_none()
        }
        MessageDelivery::Uncertain {
            effect_id,
            receipt_id,
        } => {
            effect_id == &effect.id
                && matches!(
                    effect.status,
                    EffectStatus::VerificationRequired
                        | EffectStatus::Verified
                        | EffectStatus::Reconciled
                        | EffectStatus::DeadLetter
                        | EffectStatus::Failed
                )
                && uncertain_receipt_matches(message, effect, receipt_id.as_ref())
        }
        MessageDelivery::ReconciledNotSent { effect_id } => {
            effect_id == &effect.id
                && effect.status == EffectStatus::Reconciled
                && effect.receipt.is_none()
                && message.provider_event_digest.is_none()
                && message.delivered_at.is_none()
        }
        MessageDelivery::ReconciliationDeadLetter { effect_id } => {
            effect_id == &effect.id
                && effect.status == EffectStatus::DeadLetter
                && effect.receipt.is_none()
                && message.provider_event_digest.is_none()
                && message.delivered_at.is_none()
        }
        MessageDelivery::CancelledByHandoff { effect_id } => {
            effect_id == &effect.id && effect.status == EffectStatus::Cancelled
        }
        MessageDelivery::Received | MessageDelivery::Draft => false,
    }
}

fn uncertain_receipt_matches(
    message: &ConversationMessage,
    effect: &Effect,
    receipt_id: Option<&ReceiptId>,
) -> bool {
    match (receipt_id, effect.receipt.as_ref()) {
        (None, None) => message.provider_event_digest.is_none() && message.delivered_at.is_none(),
        (Some(expected_id), Some(receipt)) => {
            receipt.id == *expected_id
                && receipt.provider == effect.provider
                && message.provider_event_digest.as_deref()
                    == Some(provider_receipt_event_digest(receipt).as_str())
                && message.delivered_at == Some(receipt.accepted_at)
        }
        _ => false,
    }
}

fn provider_receipt_event_digest(receipt: &crate::Receipt) -> String {
    format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{}:{}:{}",
                receipt.provider, receipt.external_id, receipt.response_digest
            )
            .as_bytes()
        )
    )
}

fn conversation_effect_scope_digest(
    conversation: &Conversation,
    message_id: &MessageId,
    content_digest: &str,
    effect_id: &EffectId,
    generation: u64,
    authorization_evidence_digest: &str,
) -> String {
    canonical_digest(&serde_json::json!({
        "conversationId": conversation.id,
        "personId": conversation.person_id,
        "provider": conversation.provider,
        "connectionId": conversation.connection_id,
        "accountId": conversation.account_id,
        "messageId": message_id,
        "contentDigest": content_digest,
        "effectId": effect_id,
        "controlGeneration": generation,
        "authorizationEvidenceDigest": authorization_evidence_digest,
    }))
}

fn replays_inbound(previous: &Conversation, expected: &Conversation) -> bool {
    let Some(message) = appended_message(previous, expected) else {
        return false;
    };
    if message.direction != MessageDirection::Inbound {
        return false;
    }
    transition_matches(previous, expected, |candidate| {
        candidate.ingest_inbound(
            InboundMessageInput {
                id: message.id.clone(),
                provider_event_digest: message
                    .provider_event_digest
                    .clone()
                    .ok_or(RelationshipError::InvalidConversationSnapshot)?,
                content_digest: message.content_digest.clone(),
                attachment_digests: message.attachment_digests.clone(),
                risk: message.risk.clone(),
                classification_confidence: message
                    .classification_confidence
                    .ok_or(RelationshipError::InvalidConversationSnapshot)?,
                occurred_at: message.occurred_at,
            },
            &WebhookAttestation {
                signature_verified: true,
                route_digest: candidate.route_digest.clone(),
                provider: candidate.provider.clone(),
                connection_id: candidate.connection_id.clone(),
                account_id: candidate.account_id.clone(),
                received_at: message.received_at,
            },
        )?;
        Ok(())
    })
}

fn replays_prepared_reply(previous: &Conversation, expected: &Conversation) -> bool {
    let Some(message) = appended_message(previous, expected) else {
        return false;
    };
    let MessageDelivery::EffectPrepared { effect_id } = &message.delivery else {
        return false;
    };
    let Some(authorization_digest) = message.authorization_evidence_digest.as_deref() else {
        return false;
    };
    transition_matches(previous, expected, |candidate| {
        candidate.prepare_automatic_reply(
            message.id.clone(),
            message.content_digest.clone(),
            effect_id.clone(),
            message.control_generation,
            AutomatedReplyAuthorization::NotRequired {
                evidence_digest: authorization_digest,
            },
            message.occurred_at,
        )?;
        Ok(())
    })
}

fn replays_delivery_transition(previous: &Conversation, expected: &Conversation) -> bool {
    let Some(next_message) = changed_message(previous, expected) else {
        return false;
    };
    let Some(previous_message) = previous
        .messages
        .iter()
        .find(|message| message.id == next_message.id)
    else {
        return false;
    };
    transition_matches(previous, expected, |candidate| {
        match &next_message.delivery {
            MessageDelivery::Sent {
                effect_id,
                receipt_id,
            } => replay_sent_delivery(
                candidate,
                previous_message,
                next_message,
                effect_id,
                receipt_id,
                expected.updated_at,
            ),
            MessageDelivery::Failed { effect_id } => replay_failed_delivery(
                candidate,
                previous_message,
                effect_id,
                next_message.control_generation,
                expected.updated_at,
            ),
            MessageDelivery::Uncertain {
                effect_id,
                receipt_id,
            } => replay_uncertain_delivery(
                candidate,
                previous_message,
                next_message,
                effect_id,
                receipt_id.as_ref(),
                expected.updated_at,
            ),
            MessageDelivery::ReconciledNotSent { effect_id } => candidate
                .mark_agent_reply_reconciled_not_sent(
                    effect_id,
                    next_message.control_generation,
                    expected.updated_at,
                ),
            MessageDelivery::ReconciliationDeadLetter { effect_id } => candidate
                .mark_agent_reply_reconciliation_dead_letter(
                    effect_id,
                    next_message.control_generation,
                    expected.updated_at,
                ),
            _ => Err(RelationshipError::InvalidConversationSnapshot),
        }
    })
}

fn replay_sent_delivery(
    candidate: &mut Conversation,
    previous_message: &ConversationMessage,
    next_message: &ConversationMessage,
    effect_id: &EffectId,
    receipt_id: &ReceiptId,
    reconciled_at: DateTime<Utc>,
) -> Result<(), RelationshipError> {
    let provider_event_digest = next_message
        .provider_event_digest
        .clone()
        .ok_or(RelationshipError::InvalidConversationSnapshot)?;
    let delivered_at = next_message
        .delivered_at
        .ok_or(RelationshipError::InvalidConversationSnapshot)?;
    if matches!(previous_message.delivery, MessageDelivery::Uncertain { .. }) {
        candidate.record_reconciled_agent_reply(
            effect_id,
            receipt_id.clone(),
            provider_event_digest,
            next_message.control_generation,
            delivered_at,
            reconciled_at,
        )
    } else {
        candidate.record_agent_reply(
            effect_id,
            receipt_id.clone(),
            provider_event_digest,
            next_message.control_generation,
            delivered_at,
        )
    }
}

fn replay_failed_delivery(
    candidate: &mut Conversation,
    previous_message: &ConversationMessage,
    effect_id: &EffectId,
    generation: u64,
    reconciled_at: DateTime<Utc>,
) -> Result<(), RelationshipError> {
    if matches!(previous_message.delivery, MessageDelivery::Uncertain { .. }) {
        candidate.mark_agent_reply_reconciled_failed(effect_id, generation, reconciled_at)
    } else {
        candidate.mark_agent_reply_failed(effect_id, generation, reconciled_at)
    }
}

fn replay_uncertain_delivery(
    candidate: &mut Conversation,
    previous_message: &ConversationMessage,
    next_message: &ConversationMessage,
    effect_id: &EffectId,
    receipt_id: Option<&ReceiptId>,
    reconciled_at: DateTime<Utc>,
) -> Result<(), RelationshipError> {
    if matches!(previous_message.delivery, MessageDelivery::Uncertain { .. })
        && receipt_id.is_some()
    {
        return candidate.record_reconciled_agent_reply_uncertain_receipt(
            effect_id,
            receipt_id
                .cloned()
                .ok_or(RelationshipError::InvalidConversationSnapshot)?,
            next_message
                .provider_event_digest
                .clone()
                .ok_or(RelationshipError::InvalidConversationSnapshot)?,
            next_message.control_generation,
            next_message
                .delivered_at
                .ok_or(RelationshipError::InvalidConversationSnapshot)?,
            reconciled_at,
        );
    }
    candidate.mark_agent_reply_uncertain(
        effect_id,
        next_message.control_generation,
        receipt_id.cloned(),
        next_message.provider_event_digest.clone(),
        next_message.delivered_at.unwrap_or(reconciled_at),
    )
}

fn replays_control_transition(previous: &Conversation, expected: &Conversation) -> bool {
    match &expected.control {
        ConversationControl::Human {
            actor_id,
            acquired_at,
            ..
        } => transition_matches(previous, expected, |candidate| {
            candidate.take_human_control(
                previous.control.generation(),
                actor_id.clone(),
                *acquired_at,
            )?;
            Ok(())
        }),
        ConversationControl::Agent { resumed_at, .. } => {
            let Some(evidence) = expected.last_resume_evidence_digest.as_deref() else {
                return false;
            };
            transition_matches(previous, expected, |candidate| {
                candidate.resume_agent(previous.control.generation(), evidence, *resumed_at)?;
                Ok(())
            })
        }
        ConversationControl::Paused {
            reason_digest,
            paused_at,
            ..
        } => transition_matches(previous, expected, |candidate| match expected.state {
            ConversationState::WaitingHuman => {
                candidate.pause_agent(previous.control.generation(), reason_digest, *paused_at)?;
                Ok(())
            }
            ConversationState::Resolved => candidate.resolve(reason_digest, *paused_at),
            ConversationState::Closed => candidate.close(reason_digest, *paused_at),
            ConversationState::DeadLetter => candidate.mark_dead_letter(reason_digest, *paused_at),
            ConversationState::Open => Err(RelationshipError::InvalidConversationStateTransition),
        }),
    }
}

fn appended_message<'a>(
    previous: &Conversation,
    expected: &'a Conversation,
) -> Option<&'a ConversationMessage> {
    (expected.messages.len() == previous.messages.len() + 1
        && expected.messages[..previous.messages.len()] == previous.messages)
        .then(|| expected.messages.last())
        .flatten()
}

fn changed_message<'a>(
    previous: &Conversation,
    expected: &'a Conversation,
) -> Option<&'a ConversationMessage> {
    if previous.messages.len() != expected.messages.len() {
        return None;
    }
    let changed = previous
        .messages
        .iter()
        .zip(&expected.messages)
        .filter(|(before, after)| before != after)
        .collect::<Vec<_>>();
    (changed.len() == 1).then(|| changed[0].1)
}

fn transition_matches(
    previous: &Conversation,
    expected: &Conversation,
    transition: impl FnOnce(&mut Conversation) -> Result<(), RelationshipError>,
) -> bool {
    let mut candidate = previous.clone();
    transition(&mut candidate).is_ok() && candidate == *expected
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    Draft,
    Active,
    Paused,
    Completed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionReason {
    Unsubscribe,
    Complaint,
    HardBounce,
    ConsentWithdrawn,
    UserPaused,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum CampaignRecipientState {
    Active,
    Suppressed {
        reason: SuppressionReason,
        evidence_digest: String,
        suppressed_at: DateTime<Utc>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignRecipient {
    pub person_id: PersonId,
    pub consent_record_id: ConsentRecordId,
    pub state: CampaignRecipientState,
    pub sent_at: Vec<DateTime<Utc>>,
    pub receipt_ids: Vec<ReceiptId>,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignSendAuthorization {
    pub campaign_id: CampaignId,
    pub person_id: PersonId,
    pub consent_record_id: ConsentRecordId,
    pub consent_revision: u64,
    pub policy_version: u64,
    pub recipient_revision: u64,
    pub scope_digest: String,
    pub prepared_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Campaign {
    pub id: CampaignId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub channel: ContactChannel,
    pub purpose: ConsentPurpose,
    pub market: String,
    pub frequency_window_seconds: i64,
    pub max_messages_per_window: u32,
    pub status: CampaignStatus,
    pub policy_version: u64,
    pub recipients: Vec<CampaignRecipient>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Campaign {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        id: CampaignId,
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        channel: ContactChannel,
        purpose: ConsentPurpose,
        market: impl Into<String>,
        frequency_window: Duration,
        max_messages_per_window: u32,
        recipients: impl IntoIterator<Item = (PersonId, ConsentRecordId)>,
        now: DateTime<Utc>,
    ) -> Result<Self, RelationshipError> {
        let recipients = recipients
            .into_iter()
            .map(|(person_id, consent_record_id)| CampaignRecipient {
                person_id,
                consent_record_id,
                state: CampaignRecipientState::Active,
                sent_at: Vec::new(),
                receipt_ids: Vec::new(),
                revision: 1,
            })
            .collect::<Vec<_>>();
        let campaign = Self {
            id,
            tenant_id,
            project_id,
            mission_id,
            channel,
            purpose,
            market: market.into().trim().to_owned(),
            frequency_window_seconds: frequency_window.num_seconds(),
            max_messages_per_window,
            status: CampaignStatus::Draft,
            policy_version: 1,
            recipients,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        campaign.validate()?;
        Ok(campaign)
    }

    pub fn validate(&self) -> Result<(), RelationshipError> {
        let people = self
            .recipients
            .iter()
            .map(|recipient| recipient.person_id.clone())
            .collect::<BTreeSet<_>>();
        let receipt_count = self
            .recipients
            .iter()
            .map(|recipient| recipient.receipt_ids.len())
            .sum::<usize>();
        let receipts = self
            .recipients
            .iter()
            .flat_map(|recipient| recipient.receipt_ids.iter().cloned())
            .collect::<BTreeSet<_>>();
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.market.is_empty()
            || self.frequency_window_seconds <= 0
            || self.max_messages_per_window == 0
            || self.policy_version == 0
            || self.revision == 0
            || self.created_at > self.updated_at
            || self.recipients.is_empty()
            || people.len() != self.recipients.len()
            || receipts.len() != receipt_count
            || self.recipients.iter().any(invalid_campaign_recipient)
            || self.recipients.iter().any(|recipient| {
                recipient
                    .sent_at
                    .iter()
                    .any(|sent_at| *sent_at < self.created_at || *sent_at > self.updated_at)
                    || recipient
                        .sent_at
                        .windows(2)
                        .any(|window| window[0] > window[1])
                    || matches!(
                        recipient.state,
                        CampaignRecipientState::Suppressed { suppressed_at, .. }
                            if suppressed_at < self.created_at || suppressed_at > self.updated_at
                    )
            })
        {
            return Err(RelationshipError::InvalidCampaign);
        }
        Ok(())
    }

    pub fn is_initial_snapshot(&self) -> Result<bool, RelationshipError> {
        self.validate()?;
        Ok(self.status == CampaignStatus::Draft
            && self.policy_version == 1
            && self.revision == 1
            && self.created_at == self.updated_at
            && self.recipients.iter().all(|recipient| {
                matches!(recipient.state, CampaignRecipientState::Active)
                    && recipient.sent_at.is_empty()
                    && recipient.receipt_ids.is_empty()
                    && recipient.revision == 1
            }))
    }

    pub fn follows_command(&self, previous: &Self) -> Result<bool, RelationshipError> {
        self.validate()?;
        previous.validate()?;
        let immutable_scope_matches = self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.mission_id == previous.mission_id
            && self.channel == previous.channel
            && self.purpose == previous.purpose
            && self.market == previous.market
            && self.frequency_window_seconds == previous.frequency_window_seconds
            && self.max_messages_per_window == previous.max_messages_per_window
            && self.created_at == previous.created_at;
        if !immutable_scope_matches
            || previous.revision.checked_add(1) != Some(self.revision)
            || self.updated_at < previous.updated_at
        {
            return Ok(false);
        }

        let control_transition = match self.status {
            CampaignStatus::Active => campaign_transition_matches(previous, self, |candidate| {
                candidate.activate(self.updated_at)
            }),
            CampaignStatus::Paused => campaign_transition_matches(previous, self, |candidate| {
                candidate.pause(self.updated_at)
            }),
            CampaignStatus::Completed => campaign_transition_matches(previous, self, |candidate| {
                candidate.complete(self.updated_at)
            }),
            CampaignStatus::Cancelled => campaign_transition_matches(previous, self, |candidate| {
                candidate.cancel(self.updated_at)
            }),
            CampaignStatus::Draft => false,
        };
        if control_transition {
            return Ok(true);
        }

        let changed = previous
            .recipients
            .iter()
            .zip(&self.recipients)
            .filter(|(before, after)| before != after)
            .collect::<Vec<_>>();
        if previous.recipients.len() != self.recipients.len() || changed.len() != 1 {
            return Ok(false);
        }
        let (before_recipient, after_recipient) = changed[0];
        if let CampaignRecipientState::Suppressed {
            reason,
            evidence_digest,
            suppressed_at,
        } = &after_recipient.state
        {
            let mut candidate = previous.clone();
            if candidate
                .suppress_recipient(
                    &after_recipient.person_id,
                    *reason,
                    evidence_digest.clone(),
                    *suppressed_at,
                )
                .is_ok()
                && candidate == *self
            {
                return Ok(true);
            }
        }
        Ok(campaign_send_append_matches(
            previous,
            self,
            before_recipient,
            after_recipient,
        ))
    }

    pub fn activate(&mut self, now: DateTime<Utc>) -> Result<(), RelationshipError> {
        if !matches!(self.status, CampaignStatus::Draft | CampaignStatus::Paused) {
            return Err(RelationshipError::CampaignNotActive);
        }
        let next_policy_version = next_revision(self.policy_version)?;
        let next_revision = self.prepare_bump(now)?;
        self.status = CampaignStatus::Active;
        self.policy_version = next_policy_version;
        self.commit_bump(next_revision, now);
        Ok(())
    }

    pub fn pause(&mut self, now: DateTime<Utc>) -> Result<(), RelationshipError> {
        if self.status != CampaignStatus::Active {
            return Err(RelationshipError::CampaignNotActive);
        }
        let next_policy_version = next_revision(self.policy_version)?;
        let next_revision = self.prepare_bump(now)?;
        self.status = CampaignStatus::Paused;
        self.policy_version = next_policy_version;
        self.commit_bump(next_revision, now);
        Ok(())
    }

    pub fn complete(&mut self, now: DateTime<Utc>) -> Result<(), RelationshipError> {
        if !matches!(self.status, CampaignStatus::Active | CampaignStatus::Paused) {
            return Err(RelationshipError::CampaignNotActive);
        }
        self.transition_control(CampaignStatus::Completed, now)
    }

    pub fn cancel(&mut self, now: DateTime<Utc>) -> Result<(), RelationshipError> {
        if !matches!(
            self.status,
            CampaignStatus::Draft | CampaignStatus::Active | CampaignStatus::Paused
        ) {
            return Err(RelationshipError::CampaignNotActive);
        }
        self.transition_control(CampaignStatus::Cancelled, now)
    }

    pub fn authorize_send(
        &self,
        person_id: &PersonId,
        consent: &ConsentRecord,
        now: DateTime<Utc>,
    ) -> Result<CampaignSendAuthorization, RelationshipError> {
        if self.status != CampaignStatus::Active {
            return Err(RelationshipError::CampaignNotActive);
        }
        if now < self.updated_at {
            return Err(RelationshipError::TimestampRegression);
        }
        let recipient = self
            .recipients
            .iter()
            .find(|recipient| &recipient.person_id == person_id)
            .ok_or(RelationshipError::CampaignRecipientNotFound)?;
        if !matches!(recipient.state, CampaignRecipientState::Active)
            || recipient.consent_record_id != consent.id
            || consent.tenant_id != self.tenant_id
            || consent.project_id != self.project_id
            || !consent.permits(person_id, &self.purpose, &self.channel, &self.market, now)
        {
            return Err(RelationshipError::CampaignRecipientSuppressedOrUnconsented);
        }
        let window_start = now
            .checked_sub_signed(Duration::seconds(self.frequency_window_seconds))
            .ok_or(RelationshipError::RevisionOverflow)?;
        let recent_messages = recipient
            .sent_at
            .iter()
            .filter(|sent_at| **sent_at > window_start && **sent_at <= now)
            .count();
        if recent_messages >= self.max_messages_per_window as usize {
            return Err(RelationshipError::CampaignFrequencyCapReached);
        }
        let valid_until = now
            .checked_add_signed(Duration::minutes(SEND_AUTHORIZATION_TTL_MINUTES))
            .ok_or(RelationshipError::RevisionOverflow)?;
        let scope_digest =
            campaign_send_digest(self, recipient, consent, now, valid_until, recent_messages);
        Ok(CampaignSendAuthorization {
            campaign_id: self.id.clone(),
            person_id: person_id.clone(),
            consent_record_id: consent.id.clone(),
            consent_revision: consent.revision,
            policy_version: self.policy_version,
            recipient_revision: recipient.revision,
            scope_digest,
            prepared_at: now,
            valid_until,
        })
    }

    pub fn record_send(
        &mut self,
        authorization: &CampaignSendAuthorization,
        consent: &ConsentRecord,
        receipt_id: ReceiptId,
        now: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        if self.status != CampaignStatus::Active
            || authorization.campaign_id != self.id
            || authorization.policy_version != self.policy_version
            || authorization.consent_record_id != consent.id
            || authorization.consent_revision != consent.revision
            || now < authorization.prepared_at
            || now >= authorization.valid_until
            || receipt_id.as_str().trim().is_empty()
            || self
                .recipients
                .iter()
                .any(|recipient| recipient.receipt_ids.contains(&receipt_id))
        {
            return Err(RelationshipError::CampaignAuthorizationStale);
        }
        let recipient_index = self
            .recipients
            .iter()
            .position(|recipient| recipient.person_id == authorization.person_id)
            .ok_or(RelationshipError::CampaignRecipientNotFound)?;
        let recipient = &self.recipients[recipient_index];
        if recipient.revision != authorization.recipient_revision
            || !matches!(recipient.state, CampaignRecipientState::Active)
            || !consent.permits(
                &recipient.person_id,
                &self.purpose,
                &self.channel,
                &self.market,
                now,
            )
        {
            return Err(RelationshipError::CampaignAuthorizationStale);
        }
        let window_start = authorization
            .prepared_at
            .checked_sub_signed(Duration::seconds(self.frequency_window_seconds))
            .ok_or(RelationshipError::RevisionOverflow)?;
        let recent_messages = recipient
            .sent_at
            .iter()
            .filter(|sent_at| **sent_at > window_start && **sent_at <= authorization.prepared_at)
            .count();
        if campaign_send_digest(
            self,
            recipient,
            consent,
            authorization.prepared_at,
            authorization.valid_until,
            recent_messages,
        ) != authorization.scope_digest
        {
            return Err(RelationshipError::CampaignAuthorizationStale);
        }
        let next_recipient_revision = next_revision(recipient.revision)?;
        let next_campaign_revision = self.prepare_bump(now)?;
        let recipient = &mut self.recipients[recipient_index];
        recipient.sent_at.push(now);
        recipient.receipt_ids.push(receipt_id);
        recipient.revision = next_recipient_revision;
        self.commit_bump(next_campaign_revision, now);
        Ok(())
    }

    pub fn suppress_recipient(
        &mut self,
        person_id: &PersonId,
        reason: SuppressionReason,
        evidence_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        let evidence_digest = evidence_digest.into();
        if !is_sha256(&evidence_digest) {
            return Err(RelationshipError::InvalidCampaign);
        }
        let recipient_index = self
            .recipients
            .iter()
            .position(|recipient| &recipient.person_id == person_id)
            .ok_or(RelationshipError::CampaignRecipientNotFound)?;
        let recipient = &self.recipients[recipient_index];
        if !matches!(recipient.state, CampaignRecipientState::Active) {
            return Err(RelationshipError::CampaignRecipientSuppressedOrUnconsented);
        }
        let next_recipient_revision = next_revision(recipient.revision)?;
        let next_campaign_revision = self.prepare_bump(now)?;
        let recipient = &mut self.recipients[recipient_index];
        recipient.state = CampaignRecipientState::Suppressed {
            reason,
            evidence_digest,
            suppressed_at: now,
        };
        recipient.revision = next_recipient_revision;
        self.commit_bump(next_campaign_revision, now);
        Ok(())
    }

    fn prepare_bump(&self, now: DateTime<Utc>) -> Result<u64, RelationshipError> {
        prepare_aggregate_revision(self.revision, self.updated_at, now)
    }

    fn transition_control(
        &mut self,
        status: CampaignStatus,
        now: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        let next_policy_version = next_revision(self.policy_version)?;
        let next_revision = self.prepare_bump(now)?;
        self.status = status;
        self.policy_version = next_policy_version;
        self.commit_bump(next_revision, now);
        Ok(())
    }

    fn commit_bump(&mut self, next_revision: u64, now: DateTime<Utc>) {
        self.revision = next_revision;
        self.updated_at = now;
    }
}

fn campaign_transition_matches(
    previous: &Campaign,
    expected: &Campaign,
    transition: impl FnOnce(&mut Campaign) -> Result<(), RelationshipError>,
) -> bool {
    let mut candidate = previous.clone();
    transition(&mut candidate).is_ok() && candidate == *expected
}

fn campaign_send_append_matches(
    previous: &Campaign,
    expected: &Campaign,
    before: &CampaignRecipient,
    after: &CampaignRecipient,
) -> bool {
    previous.status == CampaignStatus::Active
        && expected.status == previous.status
        && expected.policy_version == previous.policy_version
        && before.person_id == after.person_id
        && before.consent_record_id == after.consent_record_id
        && before.state == after.state
        && before.revision.checked_add(1) == Some(after.revision)
        && after.sent_at.len() == before.sent_at.len() + 1
        && after.sent_at.starts_with(&before.sent_at)
        && after.sent_at.last() == Some(&expected.updated_at)
        && after.receipt_ids.len() == before.receipt_ids.len() + 1
        && after.receipt_ids.starts_with(&before.receipt_ids)
}

fn invalid_campaign_recipient(recipient: &CampaignRecipient) -> bool {
    recipient.person_id.as_str().trim().is_empty()
        || recipient.consent_record_id.as_str().trim().is_empty()
        || recipient.revision == 0
        || recipient.sent_at.len() != recipient.receipt_ids.len()
        || recipient
            .receipt_ids
            .iter()
            .any(|receipt_id| receipt_id.as_str().trim().is_empty())
        || matches!(
            &recipient.state,
            CampaignRecipientState::Suppressed {
                evidence_digest,
                ..
            } if !is_sha256(evidence_digest)
        )
}

fn campaign_send_digest(
    campaign: &Campaign,
    recipient: &CampaignRecipient,
    consent: &ConsentRecord,
    prepared_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    recent_messages: usize,
) -> String {
    canonical_digest(&serde_json::json!({
        "campaignId": campaign.id,
        "personId": recipient.person_id,
        "consentRecordId": consent.id,
        "consentRevision": consent.revision,
        "policyVersion": campaign.policy_version,
        "recipientRevision": recipient.revision,
        "channel": campaign.channel,
        "purpose": campaign.purpose,
        "market": campaign.market,
        "frequencyWindowSeconds": campaign.frequency_window_seconds,
        "maxMessagesPerWindow": campaign.max_messages_per_window,
        "recentMessages": recent_messages,
        "preparedAt": prepared_at,
        "validUntil": valid_until,
    }))
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuyingCommitteeRole {
    Champion,
    EconomicBuyer,
    TechnicalBuyer,
    SecurityReviewer,
    Procurement,
    EndUser,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuyingCommitteeMember {
    pub person_id: PersonId,
    pub role: BuyingCommitteeRole,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpportunityStage {
    Qualified,
    Discovery,
    Evaluation,
    SecurityReview,
    Procurement,
    ClosedWon,
    ClosedLost,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageTransition {
    pub from: OpportunityStage,
    pub to: OpportunityStage,
    pub evidence_digest: String,
    pub transitioned_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Opportunity {
    pub id: OpportunityId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub company_id: CompanyId,
    pub buying_committee: BTreeSet<BuyingCommitteeMember>,
    pub stage: OpportunityStage,
    /// Risk-weighted CRM forecast only. It is never recognized revenue.
    pub forecast_amount: Option<Money>,
    pub forecast_evidence_digest: Option<String>,
    pub evidence_gap_digests: BTreeSet<String>,
    pub objection_digests: BTreeSet<String>,
    pub deadline: Option<DateTime<Utc>>,
    pub stage_history: Vec<StageTransition>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Opportunity {
    pub fn create(
        id: OpportunityId,
        tenant_id: TenantId,
        project_id: ProjectId,
        company_id: CompanyId,
        buying_committee: impl IntoIterator<Item = BuyingCommitteeMember>,
        now: DateTime<Utc>,
    ) -> Result<Self, RelationshipError> {
        let opportunity = Self {
            id,
            tenant_id,
            project_id,
            company_id,
            buying_committee: buying_committee.into_iter().collect(),
            stage: OpportunityStage::Qualified,
            forecast_amount: None,
            forecast_evidence_digest: None,
            evidence_gap_digests: BTreeSet::new(),
            objection_digests: BTreeSet::new(),
            deadline: None,
            stage_history: Vec::new(),
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        opportunity.validate()?;
        Ok(opportunity)
    }

    pub fn validate(&self) -> Result<(), RelationshipError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.company_id.as_str().trim().is_empty()
            || self.buying_committee.is_empty()
            || self.buying_committee.iter().any(|member| {
                member.person_id.as_str().trim().is_empty() || !is_sha256(&member.evidence_digest)
            })
            || self
                .forecast_evidence_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || self
                .forecast_amount
                .as_ref()
                .is_some_and(|amount| amount.amount_minor < 0)
            || self.forecast_amount.is_some() != self.forecast_evidence_digest.is_some()
            || self
                .evidence_gap_digests
                .iter()
                .chain(self.objection_digests.iter())
                .any(|digest| !is_sha256(digest))
            || self.stage_history.iter().any(|transition| {
                !is_sha256(&transition.evidence_digest)
                    || transition.from == transition.to
                    || transition_not_allowed(&transition.from, &transition.to)
            })
            || !opportunity_stage_history_is_consistent(self)
            || self.revision == 0
            || self.created_at > self.updated_at
        {
            return Err(RelationshipError::InvalidOpportunity);
        }
        Ok(())
    }

    pub fn is_initial_snapshot(&self) -> Result<bool, RelationshipError> {
        self.validate()?;
        Ok(self.stage == OpportunityStage::Qualified
            && self.forecast_amount.is_none()
            && self.forecast_evidence_digest.is_none()
            && self.evidence_gap_digests.is_empty()
            && self.objection_digests.is_empty()
            && self.deadline.is_none()
            && self.stage_history.is_empty()
            && self.revision == 1
            && self.created_at == self.updated_at)
    }

    pub fn follows_command(&self, previous: &Self) -> Result<bool, RelationshipError> {
        self.validate()?;
        previous.validate()?;
        let immutable_scope_matches = self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.company_id == previous.company_id
            && self.created_at == previous.created_at;
        if !immutable_scope_matches
            || previous.revision.checked_add(1) != Some(self.revision)
            || self.updated_at < previous.updated_at
        {
            return Ok(false);
        }

        if let (Some(amount), Some(evidence_digest)) =
            (&self.forecast_amount, &self.forecast_evidence_digest)
        {
            let mut candidate = previous.clone();
            if candidate
                .set_forecast(amount.clone(), evidence_digest.clone(), self.updated_at)
                .is_ok()
                && candidate == *self
            {
                return Ok(true);
            }
        }
        if self.stage_history.len() == previous.stage_history.len() + 1
            && self.stage_history.starts_with(&previous.stage_history)
        {
            let transition = self.stage_history.last().expect("one appended transition");
            let mut candidate = previous.clone();
            if candidate
                .advance_stage(
                    transition.to.clone(),
                    transition.evidence_digest.clone(),
                    transition.transitioned_at,
                )
                .is_ok()
                && candidate == *self
            {
                return Ok(true);
            }
        }
        let added_members = self
            .buying_committee
            .difference(&previous.buying_committee)
            .cloned()
            .collect::<Vec<_>>();
        if added_members.len() == 1 && previous.buying_committee.is_subset(&self.buying_committee) {
            let mut candidate = previous.clone();
            if candidate
                .add_buying_committee_member(added_members[0].clone(), self.updated_at)
                .is_ok()
                && candidate == *self
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn set_forecast(
        &mut self,
        amount: Money,
        evidence_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        let evidence_digest = evidence_digest.into();
        if amount.amount_minor < 0 || !is_sha256(&evidence_digest) {
            return Err(RelationshipError::InvalidOpportunity);
        }
        let next_revision = self.prepare_bump(now)?;
        self.forecast_amount = Some(amount);
        self.forecast_evidence_digest = Some(evidence_digest);
        self.commit_bump(next_revision, now);
        Ok(())
    }

    pub fn advance_stage(
        &mut self,
        next: OpportunityStage,
        evidence_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        let evidence_digest = evidence_digest.into();
        if !is_sha256(&evidence_digest) || transition_not_allowed(&self.stage, &next) {
            return Err(RelationshipError::OpportunityStageTransitionNotAllowed);
        }
        let next_revision = self.prepare_bump(now)?;
        self.stage_history.push(StageTransition {
            from: self.stage.clone(),
            to: next.clone(),
            evidence_digest,
            transitioned_at: now,
        });
        self.stage = next;
        self.commit_bump(next_revision, now);
        Ok(())
    }

    pub fn add_buying_committee_member(
        &mut self,
        member: BuyingCommitteeMember,
        now: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        if member.person_id.as_str().trim().is_empty()
            || !is_sha256(&member.evidence_digest)
            || self
                .buying_committee
                .iter()
                .any(|stored| stored.person_id == member.person_id && stored.role == member.role)
        {
            return Err(RelationshipError::DuplicateBuyingCommitteeMember);
        }
        let next_revision = self.prepare_bump(now)?;
        self.buying_committee.insert(member);
        self.commit_bump(next_revision, now);
        Ok(())
    }

    fn prepare_bump(&self, now: DateTime<Utc>) -> Result<u64, RelationshipError> {
        prepare_aggregate_revision(self.revision, self.updated_at, now)
    }

    fn commit_bump(&mut self, next_revision: u64, now: DateTime<Utc>) {
        self.revision = next_revision;
        self.updated_at = now;
    }
}

fn opportunity_stage_history_is_consistent(opportunity: &Opportunity) -> bool {
    let mut stage = OpportunityStage::Qualified;
    let mut observed_at = opportunity.created_at;
    for transition in &opportunity.stage_history {
        if transition.from != stage
            || transition.transitioned_at < observed_at
            || transition.transitioned_at > opportunity.updated_at
        {
            return false;
        }
        stage = transition.to.clone();
        observed_at = transition.transitioned_at;
    }
    stage == opportunity.stage
}

fn transition_not_allowed(from: &OpportunityStage, to: &OpportunityStage) -> bool {
    if matches!(
        from,
        OpportunityStage::ClosedWon | OpportunityStage::ClosedLost
    ) {
        return true;
    }
    !matches!(
        (from, to),
        (
            OpportunityStage::Qualified,
            OpportunityStage::Discovery
                | OpportunityStage::Evaluation
                | OpportunityStage::ClosedWon
                | OpportunityStage::ClosedLost
        ) | (
            OpportunityStage::Discovery,
            OpportunityStage::Evaluation
                | OpportunityStage::SecurityReview
                | OpportunityStage::ClosedWon
                | OpportunityStage::ClosedLost
        ) | (
            OpportunityStage::Evaluation,
            OpportunityStage::SecurityReview
                | OpportunityStage::Procurement
                | OpportunityStage::ClosedWon
                | OpportunityStage::ClosedLost
        ) | (
            OpportunityStage::SecurityReview,
            OpportunityStage::Procurement
                | OpportunityStage::ClosedWon
                | OpportunityStage::ClosedLost
        ) | (
            OpportunityStage::Procurement,
            OpportunityStage::ClosedWon | OpportunityStage::ClosedLost
        )
    )
}

fn next_generation(current: u64) -> Result<u64, RelationshipError> {
    current
        .checked_add(1)
        .ok_or(RelationshipError::RevisionOverflow)
}

fn next_revision(current: u64) -> Result<u64, RelationshipError> {
    current
        .checked_add(1)
        .ok_or(RelationshipError::RevisionOverflow)
}

fn prepare_aggregate_revision(
    current: u64,
    updated_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<u64, RelationshipError> {
    if now < updated_at {
        return Err(RelationshipError::TimestampRegression);
    }
    next_revision(current)
}

fn automatic_reply_confidence() -> Decimal {
    Decimal::new(9, 1)
}

fn canonical_digest(value: &serde_json::Value) -> String {
    format!("{:x}", Sha256::digest(value.to_string().as_bytes()))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Error, PartialEq)]
pub enum RelationshipError {
    #[error("conversation aggregate is invalid")]
    InvalidConversation,
    #[error(
        "conversation snapshot identity, provider, consent, effect, or receipt chain is invalid"
    )]
    InvalidConversationSnapshot,
    #[error("conversation message, digest, timing, or delivery state is invalid")]
    InvalidConversationMessage,
    #[error("webhook signature, tenant route, or provider account does not match")]
    WebhookScopeOrSignatureInvalid,
    #[error("webhook event digest was replayed with different content")]
    WebhookReplayConflict,
    #[error("message id already exists")]
    DuplicateMessageId,
    #[error("automatic reply is unsafe, low confidence, blocked, or lacks an inbound message")]
    AutomaticReplyNotAllowed,
    #[error("consent or a not-required policy attestation does not authorize this reply")]
    ConsentDoesNotAuthorizeReply,
    #[error("conversation control owner or generation no longer matches")]
    ControlLeaseLost,
    #[error("only an explicit, evidenced human action may resume agent control")]
    ExplicitResumeRequired,
    #[error("conversation pause, resume, resolve, close, or dead-letter transition is invalid")]
    InvalidConversationStateTransition,
    #[error("campaign aggregate or recipient shape is invalid")]
    InvalidCampaign,
    #[error("campaign is not active")]
    CampaignNotActive,
    #[error("campaign recipient was not found")]
    CampaignRecipientNotFound,
    #[error("campaign recipient is suppressed or current consent does not authorize contact")]
    CampaignRecipientSuppressedOrUnconsented,
    #[error("campaign frequency cap was reached")]
    CampaignFrequencyCapReached,
    #[error(
        "campaign send authorization expired or no longer matches policy, consent, or recipient"
    )]
    CampaignAuthorizationStale,
    #[error("opportunity aggregate, forecast, or evidence shape is invalid")]
    InvalidOpportunity,
    #[error("opportunity stage transition is not allowed")]
    OpportunityStageTransitionNotAllowed,
    #[error("buying committee member and role already exist or are invalid")]
    DuplicateBuyingCommitteeMember,
    #[error("aggregate revision or control generation overflow")]
    RevisionOverflow,
    #[error("relationship aggregate timestamp cannot move backwards")]
    TimestampRegression,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use proptest::prelude::*;

    use super::*;
    use crate::{
        Approval, ApprovalDecision, ApprovalId, Company, ConnectionProbe, ConsentRequirement,
        CurrencyCode, EffectClass, EffectRisk, EffectSpec, LegalBasis, Person, ProbeOutcome,
        Receipt, Verification, VerificationId,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 19, 0, 0)
            .single()
            .expect("valid time")
    }

    fn conversation() -> Conversation {
        Conversation::open(
            crate::ConversationId::from("conversation-1"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            Some(MissionId::from("mission-10")),
            PersonId::from("person-1"),
            Some(CompanyId::from("company-1")),
            MessagingGateway::Gmail,
            "gmail",
            ConnectionId::from("connection-1"),
            AccountId::from("account-1"),
            "a".repeat(64),
            ContactChannel::Email,
            "DE",
            now(),
        )
        .expect("conversation")
    }

    fn attestation() -> WebhookAttestation {
        WebhookAttestation {
            signature_verified: true,
            route_digest: "a".repeat(64),
            provider: "gmail".into(),
            connection_id: ConnectionId::from("connection-1"),
            account_id: AccountId::from("account-1"),
            received_at: now(),
        }
    }

    fn inbound(id: &str, event_byte: char, risk: ConversationContentRisk) -> InboundMessageInput {
        InboundMessageInput {
            id: MessageId::from(id),
            provider_event_digest: event_byte.to_string().repeat(64),
            content_digest: "c".repeat(64),
            attachment_digests: BTreeSet::new(),
            risk,
            classification_confidence: Decimal::new(95, 2),
            occurred_at: now() - Duration::minutes(1),
        }
    }

    fn automated_reply_consent() -> ConsentRecord {
        ConsentRecord::grant(
            ConsentRecordId::from("consent-1"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            PersonId::from("person-1"),
            ConsentPurpose::AutomatedReply,
            ContactChannel::Email,
            "DE",
            LegalBasis::ExplicitConsent,
            "preference-center",
            "d".repeat(64),
            now() - Duration::days(1),
            None,
        )
        .expect("consent")
    }

    fn model_inbound(
        index: usize,
        risk: ConversationContentRisk,
        at: DateTime<Utc>,
    ) -> (InboundMessageInput, WebhookAttestation) {
        (
            InboundMessageInput {
                id: MessageId::from_stable(format!("message-model-{index}")),
                provider_event_digest: format!("{:064x}", index + 1),
                content_digest: format!("{:064x}", index + 10_000),
                attachment_digests: BTreeSet::new(),
                risk,
                classification_confidence: Decimal::new(95, 2),
                occurred_at: at - Duration::seconds(1),
            },
            WebhookAttestation {
                signature_verified: true,
                route_digest: "a".repeat(64),
                provider: "gmail".into(),
                connection_id: ConnectionId::from("connection-1"),
                account_id: AccountId::from("account-1"),
                received_at: at,
            },
        )
    }

    fn apply_conversation_model_action(
        conversation: &mut Conversation,
        action: u8,
        index: usize,
        at: DateTime<Utc>,
    ) -> Result<(), RelationshipError> {
        match action {
            0 | 1 => {
                let risk = if action == 0 {
                    ConversationContentRisk::Safe
                } else {
                    ConversationContentRisk::PromptInjectionSuspected
                };
                let (input, attestation) = model_inbound(index, risk, at);
                conversation.ingest_inbound(input, &attestation).map(|_| ())
            }
            2 => conversation
                .take_human_control(
                    conversation.control.generation(),
                    ActorId::from("human-model"),
                    at,
                )
                .map(|_| ()),
            3 => conversation
                .pause_agent(conversation.control.generation(), "1".repeat(64), at)
                .map(|_| ()),
            4 => conversation
                .resume_agent(conversation.control.generation(), "2".repeat(64), at)
                .map(|_| ()),
            5 => conversation.resolve("3".repeat(64), at),
            6 => conversation.close("4".repeat(64), at),
            _ => conversation.mark_dead_letter("5".repeat(64), at),
        }
    }

    #[test]
    fn webhook_is_signed_scoped_deduplicated_and_accepts_late_order() {
        let mut conversation = conversation();
        let mut forged = attestation();
        forged.signature_verified = false;
        assert_eq!(
            conversation.ingest_inbound(
                inbound("message-1", 'b', ConversationContentRisk::Safe),
                &forged
            ),
            Err(RelationshipError::WebhookScopeOrSignatureInvalid)
        );

        let first = inbound("message-1", 'b', ConversationContentRisk::Safe);
        assert_eq!(
            conversation
                .ingest_inbound(first.clone(), &attestation())
                .expect("insert"),
            InboundIngest::Inserted
        );
        assert_eq!(
            conversation
                .ingest_inbound(first, &attestation())
                .expect("dedupe"),
            InboundIngest::Duplicate
        );
        let mut late = inbound("message-2", 'e', ConversationContentRisk::Safe);
        late.occurred_at = now() - Duration::days(2);
        conversation
            .ingest_inbound(late, &attestation())
            .expect("late but valid event");
        assert_eq!(conversation.messages.len(), 2);
    }

    #[test]
    fn human_takeover_cancels_pending_effect_and_old_generation_cannot_send() {
        let mut conversation = conversation();
        conversation
            .ingest_inbound(
                inbound("message-1", 'b', ConversationContentRisk::Safe),
                &attestation(),
            )
            .expect("inbound");
        let effect_id = EffectId::from("reply-effect-1");
        conversation
            .prepare_automatic_reply(
                MessageId::from("reply-1"),
                "f".repeat(64),
                effect_id.clone(),
                1,
                AutomatedReplyAuthorization::Consent(&automated_reply_consent()),
                now(),
            )
            .expect("prepared reply");
        assert!(conversation.authorizes_agent_effect(&effect_id, 1));

        let human_generation = conversation
            .take_human_control(1, ActorId::from("human-1"), now())
            .expect("human takeover");
        assert!(!conversation.authorizes_agent_effect(&effect_id, 1));
        assert_eq!(
            conversation.record_agent_reply(
                &effect_id,
                ReceiptId::from("receipt-1"),
                "9".repeat(64),
                1,
                now(),
            ),
            Err(RelationshipError::ControlLeaseLost)
        );
        assert_eq!(
            conversation.resume_agent(human_generation, "bad", now()),
            Err(RelationshipError::ExplicitResumeRequired)
        );
        let resumed_generation = conversation
            .resume_agent(human_generation, "7".repeat(64), now())
            .expect("explicit resume");
        assert!(resumed_generation > human_generation);
        assert!(!conversation.authorizes_agent_effect(&effect_id, resumed_generation));
    }

    #[test]
    fn read_only_reconciliation_can_project_historical_send_after_human_handoff() {
        let mut conversation = conversation();
        conversation
            .ingest_inbound(
                inbound("message-reconcile", 'b', ConversationContentRisk::Safe),
                &attestation(),
            )
            .expect("inbound");
        let effect_id = EffectId::from("reply-effect-reconcile");
        conversation
            .prepare_automatic_reply(
                MessageId::from("reply-reconcile"),
                "f".repeat(64),
                effect_id.clone(),
                1,
                AutomatedReplyAuthorization::Consent(&automated_reply_consent()),
                now(),
            )
            .expect("prepared reply");
        conversation
            .mark_agent_reply_uncertain(&effect_id, 1, None, None, now() + Duration::seconds(1))
            .expect("uncertain result");
        conversation
            .take_human_control(
                1,
                ActorId::from("human-after-uncertain"),
                now() + Duration::seconds(2),
            )
            .expect("human takeover");
        let before_reconciliation = conversation.clone();
        assert_eq!(
            conversation.record_reconciled_agent_reply(
                &effect_id,
                ReceiptId::from("receipt-reconciled"),
                "9".repeat(64),
                2,
                now() + Duration::milliseconds(500),
                now() + Duration::seconds(3),
            ),
            Err(RelationshipError::AutomaticReplyNotAllowed)
        );
        conversation
            .record_reconciled_agent_reply(
                &effect_id,
                ReceiptId::from("receipt-reconciled"),
                "9".repeat(64),
                1,
                now() + Duration::milliseconds(500),
                now() + Duration::seconds(3),
            )
            .expect("read-only historical projection");
        assert!(matches!(
            conversation.control,
            ConversationControl::Human { generation: 2, .. }
        ));
        assert!(matches!(
            conversation
                .messages
                .iter()
                .find(|message| message.id == MessageId::from("reply-reconcile"))
                .expect("reply")
                .delivery,
            MessageDelivery::Sent { .. }
        ));
        assert!(
            conversation
                .follows_command(&before_reconciliation)
                .expect("replay reconciliation projection")
        );
    }

    #[test]
    fn pause_resume_resolve_close_and_dead_letter_are_exact_replayable_commands() {
        let initial = conversation();
        let mut paused = initial.clone();
        let paused_generation = paused
            .pause_agent(1, "1".repeat(64), now() + Duration::seconds(1))
            .expect("pause agent");
        assert_eq!(paused.state, ConversationState::WaitingHuman);
        assert!(matches!(paused.control, ConversationControl::Paused { .. }));
        assert!(paused.follows_command(&initial).expect("replay pause"));

        let mut forged_pause = paused.clone();
        forged_pause.last_state_evidence_digest = Some("2".repeat(64));
        assert!(
            !forged_pause
                .follows_command(&initial)
                .expect("reject forged pause evidence")
        );

        let mut resumed = paused.clone();
        resumed
            .resume_agent(
                paused_generation,
                "3".repeat(64),
                now() + Duration::seconds(2),
            )
            .expect("resume agent");
        assert_eq!(resumed.state, ConversationState::Open);
        assert!(resumed.follows_command(&paused).expect("replay resume"));

        let mut resolved = resumed.clone();
        resolved
            .resolve("4".repeat(64), now() + Duration::seconds(3))
            .expect("resolve");
        assert_eq!(resolved.state, ConversationState::Resolved);
        assert!(resolved.follows_command(&resumed).expect("replay resolve"));
        assert_eq!(
            resolved.resume_agent(
                resolved.control.generation(),
                "5".repeat(64),
                now() + Duration::seconds(4),
            ),
            Err(RelationshipError::ExplicitResumeRequired)
        );

        let mut closed = resolved.clone();
        closed
            .close("6".repeat(64), now() + Duration::seconds(4))
            .expect("close");
        assert_eq!(closed.state, ConversationState::Closed);
        assert!(closed.follows_command(&resolved).expect("replay close"));
        assert_eq!(
            closed.mark_dead_letter("7".repeat(64), now() + Duration::seconds(5)),
            Err(RelationshipError::InvalidConversationStateTransition)
        );

        let mut dead_lettered = initial.clone();
        dead_lettered
            .mark_dead_letter("8".repeat(64), now() + Duration::seconds(1))
            .expect("dead letter");
        assert_eq!(dead_lettered.state, ConversationState::DeadLetter);
        assert!(
            dead_lettered
                .follows_command(&initial)
                .expect("replay dead letter")
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the trust-boundary test keeps identity, Connection, Consent, Effect, Receipt, Verification, and forged variants in one auditable chain"
    )]
    fn conversation_snapshot_requires_exact_identity_effect_receipt_and_independent_verification() {
        let tenant_id = TenantId::from("tenant-1");
        let project_id = ProjectId::from("project-1");
        let company = Company::create(
            CompanyId::from("company-1"),
            tenant_id.clone(),
            project_id.clone(),
            "Verified customer",
            "DE",
        )
        .expect("company");
        let person = Person::create(
            PersonId::from("person-1"),
            tenant_id.clone(),
            project_id.clone(),
            "Verified person",
            Some(company.id.clone()),
            vec![],
        )
        .expect("person");
        let identity = ConversationIdentitySnapshot {
            person: person.clone(),
            company: Some(company),
        };
        let mut connection = Connection::register(
            ConnectionId::from("connection-1"),
            tenant_id.clone(),
            project_id.clone(),
            "gmail",
            AccountId::from("account-1"),
            "verified@example.invalid",
            ["messages.send".into()],
            now() - Duration::days(2),
        )
        .expect("connection");
        connection
            .begin_probe(now() - Duration::days(2) + Duration::seconds(1))
            .expect("begin probe");
        connection
            .apply_probe(
                ConnectionProbe {
                    outcome: ProbeOutcome::Successful,
                    observed_external_account_id: "verified@example.invalid".into(),
                    granted_scopes: BTreeSet::from(["messages.send".into()]),
                    probed_at: now() - Duration::days(2) + Duration::seconds(2),
                    valid_until: now() + Duration::days(1),
                    credential_expires_at: now() + Duration::days(1),
                    evidence_digest: "1".repeat(64),
                },
                now() - Duration::days(2) + Duration::seconds(2),
            )
            .expect("successful probe");
        let connection = connection.snapshot();
        let consent = automated_reply_consent();
        let mut mission = Mission::compile(
            tenant_id,
            MissionId::from("mission-10"),
            project_id,
            "Verified conversation reply",
            crate::MissionContract::bootstrap(
                "Reply only with exact Consent and readback",
                ["conversation.reply".into()],
                now() - Duration::hours(1),
            ),
            now() - Duration::hours(1),
        )
        .expect("mission");
        mission
            .start_research([], now() - Duration::hours(1))
            .expect("start mission");
        let mut received = conversation();
        received
            .ingest_inbound(
                inbound("message-exact", '2', ConversationContentRisk::Safe),
                &attestation(),
            )
            .expect("signed inbound");
        let mut prepared = received.clone();
        let effect_id = EffectId::from("effect-exact");
        let prepared_reply = prepared
            .prepare_automatic_reply(
                MessageId::from("reply-exact"),
                "3".repeat(64),
                effect_id.clone(),
                prepared.control.generation(),
                AutomatedReplyAuthorization::Consent(&consent),
                now() + Duration::seconds(1),
            )
            .expect("prepare exact reply");
        mission
            .propose_effect(
                EffectSpec {
                    id: effect_id.clone(),
                    actor_id: ActorId::from("agent-1"),
                    capability: "conversation.reply".into(),
                    provider: prepared.provider.clone(),
                    connection_id: Some(prepared.connection_id.clone()),
                    account_id: Some(prepared.account_id.clone()),
                    required_scopes: BTreeSet::from(["messages.send".into()]),
                    effect_class: EffectClass::Outreach,
                    description: "Send exact reply".into(),
                    target_resource: format!("conversation://{}", prepared.id),
                    audience_digest: Some(format!(
                        "{:x}",
                        Sha256::digest(prepared.person_id.as_str().as_bytes())
                    )),
                    payload_digest: "3".repeat(64),
                    asset_digests: BTreeSet::new(),
                    scheduled_for: None,
                    timezone: "Europe/Berlin".into(),
                    consent: ConsentState::Confirmed,
                    consent_record_id: Some(consent.id.clone()),
                    consent_requirement: Some(ConsentRequirement {
                        person_id: prepared.person_id.clone(),
                        purpose: ConsentPurpose::AutomatedReply,
                        channel: ContactChannel::Email,
                        market: "DE".into(),
                    }),
                    conversation_guard: Some(crate::ConversationEffectGuard {
                        conversation_id: prepared.id.clone(),
                        control_generation: prepared_reply.control_generation,
                        scope_digest: prepared_reply.scope_digest,
                    }),
                    creator_contact_guard: None,
                    policy_version: "conversation-exact-v1".into(),
                    risk: EffectRisk::High,
                    idempotency_key: "conversation-exact-v1".into(),
                    amount: Money::zero(CurrencyCode::parse("EUR").expect("EUR")),
                    expires_at: now() + Duration::hours(1),
                },
                now() + Duration::seconds(1),
            )
            .expect("propose exact Effect");
        let approval_digest = mission
            .effect(&effect_id)
            .expect("effect")
            .approval_digest();
        let approval_valid_until = mission
            .approval_valid_until(&effect_id, now() + Duration::seconds(2))
            .expect("approval validity");
        mission
            .approve_effect(
                &effect_id,
                Approval {
                    id: ApprovalId::from("approval-exact"),
                    decision: ApprovalDecision::Approved,
                    decided_by: ActorId::from("owner-1"),
                    decided_at: now() + Duration::seconds(2),
                    valid_until: approval_valid_until,
                    scope_digest: approval_digest,
                    permission_digest: "4".repeat(64),
                },
            )
            .expect("approve exact Effect");
        mission
            .begin_effect(&effect_id, now() + Duration::seconds(3))
            .expect("begin exact Effect");
        let receipt = Receipt {
            id: ReceiptId::from("receipt-exact"),
            provider: "gmail".into(),
            external_id: "gmail-message-exact".into(),
            accepted_at: now() + Duration::seconds(4),
            request_digest: mission
                .effect(&effect_id)
                .expect("effect")
                .approval_digest(),
            response_digest: "5".repeat(64),
        };
        let provider_event_digest = provider_receipt_event_digest(&receipt);
        mission
            .record_receipt(&effect_id, receipt.clone())
            .expect("record receipt");
        mission
            .record_verification(
                &effect_id,
                Verification {
                    id: VerificationId::from("verification-exact"),
                    status: VerificationStatus::Confirmed,
                    verifier: "gmail-readback".into(),
                    independent: true,
                    observed_at: now() + Duration::seconds(5),
                    evidence_digest: "6".repeat(64),
                    receipt_id: receipt.id.clone(),
                },
            )
            .expect("record independent verification");
        let mut sent = prepared.clone();
        sent.record_agent_reply(
            &effect_id,
            receipt.id,
            provider_event_digest,
            prepared_reply.control_generation,
            receipt.accepted_at,
        )
        .expect("record sent reply");

        sent.validate_snapshot(
            &identity,
            &connection,
            &mission,
            std::slice::from_ref(&consent),
            now() + Duration::minutes(1),
        )
        .expect("validate exact trust chain");
        assert!(
            sent.follows(
                &prepared,
                &identity,
                &connection,
                &mission,
                std::slice::from_ref(&consent),
                now() + Duration::minutes(1),
            )
            .expect("exact delivery transition")
        );

        let mut forged_receipt_readback = sent.clone();
        forged_receipt_readback
            .messages
            .last_mut()
            .expect("reply")
            .provider_event_digest = Some("7".repeat(64));
        assert_eq!(
            forged_receipt_readback.validate_snapshot(
                &identity,
                &connection,
                &mission,
                std::slice::from_ref(&consent),
                now() + Duration::minutes(1),
            ),
            Err(RelationshipError::InvalidConversationSnapshot)
        );
        let mut forged_verification = mission;
        forged_verification.effects[0]
            .verification
            .as_mut()
            .expect("verification")
            .independent = false;
        assert_eq!(
            sent.validate_snapshot(
                &identity,
                &connection,
                &forged_verification,
                std::slice::from_ref(&consent),
                now() + Duration::minutes(1),
            ),
            Err(RelationshipError::InvalidConversationSnapshot)
        );
    }

    #[test]
    fn poisoned_or_low_confidence_inbound_requires_human() {
        let mut conversation = conversation();
        conversation
            .ingest_inbound(
                inbound(
                    "message-1",
                    'b',
                    ConversationContentRisk::PromptInjectionSuspected,
                ),
                &attestation(),
            )
            .expect("inbound");
        assert_eq!(conversation.state, ConversationState::WaitingHuman);
        assert_eq!(
            conversation.prepare_automatic_reply(
                MessageId::from("reply-1"),
                "f".repeat(64),
                EffectId::from("effect-1"),
                1,
                AutomatedReplyAuthorization::Consent(&automated_reply_consent()),
                now(),
            ),
            Err(RelationshipError::AutomaticReplyNotAllowed)
        );
    }

    fn email_campaign() -> (Campaign, ConsentRecord) {
        let consent = ConsentRecord::grant(
            ConsentRecordId::from("campaign-consent-1"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            PersonId::from("person-1"),
            ConsentPurpose::EmailMarketing,
            ContactChannel::Email,
            "DE",
            LegalBasis::ExplicitConsent,
            "preference-center",
            "1".repeat(64),
            now() - Duration::days(2),
            None,
        )
        .expect("consent");
        let mut campaign = Campaign::create(
            CampaignId::from("campaign-1"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            MissionId::from("mission-5"),
            ContactChannel::Email,
            ConsentPurpose::EmailMarketing,
            "DE",
            Duration::days(7),
            1,
            [(PersonId::from("person-1"), consent.id.clone())],
            now(),
        )
        .expect("campaign");
        campaign.activate(now()).expect("activate");
        (campaign, consent)
    }

    #[test]
    fn campaign_rechecks_consent_frequency_and_suppression_at_send_time() {
        let (mut campaign, mut consent) = email_campaign();
        let authorization = campaign
            .authorize_send(&PersonId::from("person-1"), &consent, now())
            .expect("authorize");
        consent
            .withdraw(now() + Duration::minutes(1))
            .expect("withdraw");
        assert_eq!(
            campaign.record_send(
                &authorization,
                &consent,
                ReceiptId::from("receipt-1"),
                now() + Duration::minutes(1),
            ),
            Err(RelationshipError::CampaignAuthorizationStale)
        );

        let (mut campaign, consent) = email_campaign();
        let authorization = campaign
            .authorize_send(&PersonId::from("person-1"), &consent, now())
            .expect("authorize");
        campaign
            .record_send(
                &authorization,
                &consent,
                ReceiptId::from("receipt-1"),
                now() + Duration::minutes(1),
            )
            .expect("record send");
        assert_eq!(
            campaign.authorize_send(
                &PersonId::from("person-1"),
                &consent,
                now() + Duration::minutes(2)
            ),
            Err(RelationshipError::CampaignFrequencyCapReached)
        );
        campaign
            .suppress_recipient(
                &PersonId::from("person-1"),
                SuppressionReason::Complaint,
                "2".repeat(64),
                now() + Duration::minutes(2),
            )
            .expect("suppress");
        assert_eq!(
            campaign.authorize_send(
                &PersonId::from("person-1"),
                &consent,
                now() + Duration::days(8)
            ),
            Err(RelationshipError::CampaignRecipientSuppressedOrUnconsented)
        );
    }

    fn committee_member(id: &str, role: BuyingCommitteeRole) -> BuyingCommitteeMember {
        BuyingCommitteeMember {
            person_id: PersonId::from_stable(id),
            role,
            evidence_digest: "3".repeat(64),
        }
    }

    #[test]
    fn opportunity_forecast_and_closed_won_stage_are_never_revenue_events() {
        let mut opportunity = Opportunity::create(
            OpportunityId::from("opportunity-1"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            CompanyId::from("company-1"),
            [committee_member(
                "person-1",
                BuyingCommitteeRole::EconomicBuyer,
            )],
            now(),
        )
        .expect("opportunity");
        opportunity
            .set_forecast(
                Money::new(250_000, CurrencyCode::parse("EUR").expect("currency")),
                "4".repeat(64),
                now(),
            )
            .expect("forecast");
        opportunity
            .advance_stage(
                OpportunityStage::Discovery,
                "5".repeat(64),
                now() + Duration::minutes(1),
            )
            .expect("discovery");
        opportunity
            .advance_stage(
                OpportunityStage::ClosedWon,
                "6".repeat(64),
                now() + Duration::minutes(2),
            )
            .expect("closed won");

        let serialized = serde_json::to_value(&opportunity).expect("serialize");
        assert!(serialized.get("forecastAmount").is_some());
        assert!(serialized.get("revenue").is_none());
        assert_eq!(opportunity.stage, OpportunityStage::ClosedWon);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        #[test]
        fn arbitrary_conversation_control_sequences_are_atomic_generation_fenced_and_terminal(
            actions in prop::collection::vec((0_u8..10, 0_i64..4), 1..64),
        ) {
            let mut conversation = conversation();
            let initial = conversation.clone();
            let mut cursor = now();

            for (index, (action, advance_minutes)) in actions.into_iter().enumerate() {
                cursor += Duration::minutes(advance_minutes);
                let before = conversation.clone();
                let result = match action {
                    0..=7 => apply_conversation_model_action(
                        &mut conversation,
                        action,
                        index,
                        cursor,
                    ),
                    8 => {
                        let backwards = before.updated_at - Duration::seconds(1);
                        let backward_action = if before.state == ConversationState::Resolved {
                            6
                        } else if matches!(before.control, ConversationControl::Agent { .. }) {
                            3
                        } else {
                            4
                        };
                        apply_conversation_model_action(
                            &mut conversation,
                            backward_action,
                            index,
                            backwards,
                        )
                    }
                    _ => {
                        let mut overflow = conversation.clone();
                        overflow.revision = u64::MAX;
                        let overflow_before = overflow.clone();
                        let overflow_action = if overflow.state == ConversationState::Resolved {
                            6
                        } else if matches!(overflow.control, ConversationControl::Agent { .. }) {
                            3
                        } else {
                            4
                        };
                        let overflow_result = apply_conversation_model_action(
                            &mut overflow,
                            overflow_action,
                            index,
                            cursor,
                        );
                        prop_assert!(overflow_result.is_err());
                        prop_assert_eq!(overflow, overflow_before);
                        Ok(())
                    }
                };

                if result.is_ok() && action != 9 {
                    prop_assert_eq!(conversation.revision, before.revision + 1);
                    prop_assert!(conversation.updated_at >= before.updated_at);
                    prop_assert!(conversation.control.generation() >= before.control.generation());
                    prop_assert!(conversation.follows_command(&before).expect("command replay"));
                } else {
                    prop_assert_eq!(conversation.clone(), before);
                }
                prop_assert_eq!(conversation.id.clone(), initial.id.clone());
                prop_assert_eq!(conversation.tenant_id.clone(), initial.tenant_id.clone());
                prop_assert_eq!(conversation.project_id.clone(), initial.project_id.clone());
                prop_assert_eq!(conversation.connection_id.clone(), initial.connection_id.clone());
                prop_assert_eq!(conversation.account_id.clone(), initial.account_id.clone());
                prop_assert!(conversation.validate().is_ok());
                if matches!(
                    conversation.state,
                    ConversationState::Resolved
                        | ConversationState::Closed
                        | ConversationState::DeadLetter
                ) {
                    let (input, attestation) = model_inbound(
                        index + 100_000,
                        ConversationContentRisk::Safe,
                        cursor.max(conversation.updated_at),
                    );
                    let terminal_before = conversation.clone();
                    prop_assert!(conversation.ingest_inbound(input, &attestation).is_err());
                    prop_assert_eq!(conversation.clone(), terminal_before);
                }
            }
        }

        #[test]
        fn arbitrary_campaign_policy_send_and_suppression_sequences_are_atomic_and_deduplicated(
            actions in prop::collection::vec((0_u8..9, 0_i64..10), 1..64),
        ) {
            let (mut campaign, consent) = email_campaign();
            let initial = campaign.clone();
            let mut cursor = now();

            for (index, (action, advance_days)) in actions.into_iter().enumerate() {
                cursor += Duration::days(advance_days);
                let before = campaign.clone();
                let result = match action {
                    0 => campaign.activate(cursor),
                    1 => campaign.pause(cursor),
                    2 => campaign
                        .authorize_send(&PersonId::from("person-1"), &consent, cursor)
                        .and_then(|authorization| {
                            campaign.record_send(
                                &authorization,
                                &consent,
                                ReceiptId::from_stable(format!("receipt-model-{index}")),
                                cursor,
                            )
                        }),
                    3 => campaign.suppress_recipient(
                        &PersonId::from("person-1"),
                        SuppressionReason::UserPaused,
                        "6".repeat(64),
                        cursor,
                    ),
                    4 => {
                        let backwards = before.updated_at - Duration::seconds(1);
                        if before.status == CampaignStatus::Active {
                            campaign.pause(backwards)
                        } else {
                            campaign.activate(backwards)
                        }
                    }
                    5 => {
                        let mut overflow = campaign.clone();
                        overflow.revision = u64::MAX;
                        let overflow_before = overflow.clone();
                        let overflow_result = if overflow.status == CampaignStatus::Active {
                            overflow.pause(cursor)
                        } else {
                            overflow.activate(cursor)
                        };
                        prop_assert!(overflow_result.is_err());
                        prop_assert_eq!(overflow, overflow_before);
                        Ok(())
                    }
                    6 => campaign.record_send(
                        &CampaignSendAuthorization {
                            campaign_id: campaign.id.clone(),
                            person_id: PersonId::from("person-1"),
                            consent_record_id: consent.id.clone(),
                            consent_revision: consent.revision,
                            policy_version: campaign.policy_version,
                            recipient_revision: campaign.recipients[0].revision,
                            scope_digest: "0".repeat(64),
                            prepared_at: cursor,
                            valid_until: cursor + Duration::minutes(1),
                        },
                        &consent,
                        ReceiptId::from("forged-receipt"),
                        cursor,
                    ),
                    7 => campaign.complete(cursor),
                    _ => campaign.cancel(cursor),
                };

                if result.is_ok() && action != 5 {
                    prop_assert_eq!(campaign.revision, before.revision + 1);
                    prop_assert!(campaign.updated_at >= before.updated_at);
                    prop_assert!(campaign.follows_command(&before).expect("command replay"));
                } else {
                    prop_assert_eq!(campaign.clone(), before);
                }
                prop_assert_eq!(campaign.id.clone(), initial.id.clone());
                prop_assert_eq!(campaign.tenant_id.clone(), initial.tenant_id.clone());
                prop_assert_eq!(campaign.project_id.clone(), initial.project_id.clone());
                prop_assert!(campaign.validate().is_ok());
                let receipts = campaign
                    .recipients
                    .iter()
                    .flat_map(|recipient| recipient.receipt_ids.iter())
                    .collect::<BTreeSet<_>>();
                let receipt_count = campaign
                    .recipients
                    .iter()
                    .map(|recipient| recipient.receipt_ids.len())
                    .sum::<usize>();
                prop_assert_eq!(receipts.len(), receipt_count);
            }
        }

        #[test]
        fn arbitrary_opportunity_forecast_committee_and_stage_sequences_are_atomic_and_monotonic(
            actions in prop::collection::vec((0_u8..7, 0_i64..4, 0_i64..1_000_000), 1..64),
        ) {
            let mut opportunity = Opportunity::create(
                OpportunityId::from("opportunity-model"),
                TenantId::from("tenant-1"),
                ProjectId::from("project-1"),
                CompanyId::from("company-1"),
                [committee_member("person-initial", BuyingCommitteeRole::EconomicBuyer)],
                now(),
            ).expect("opportunity");
            let initial = opportunity.clone();
            let mut cursor = now();

            for (index, (action, advance_minutes, amount)) in actions.into_iter().enumerate() {
                cursor += Duration::minutes(advance_minutes);
                let before = opportunity.clone();
                let result = match action {
                    0 => opportunity.set_forecast(
                        Money::new(amount, CurrencyCode::parse("EUR").expect("EUR")),
                        "7".repeat(64),
                        cursor,
                    ),
                    1 => {
                        let next = match opportunity.stage {
                            OpportunityStage::Qualified => OpportunityStage::Discovery,
                            OpportunityStage::Discovery => OpportunityStage::Evaluation,
                            OpportunityStage::Evaluation => OpportunityStage::SecurityReview,
                            OpportunityStage::SecurityReview => OpportunityStage::Procurement,
                            OpportunityStage::Procurement => OpportunityStage::ClosedWon,
                            OpportunityStage::ClosedWon | OpportunityStage::ClosedLost => {
                                OpportunityStage::Discovery
                            }
                        };
                        opportunity.advance_stage(next, "8".repeat(64), cursor)
                    }
                    2 => opportunity.advance_stage(
                        OpportunityStage::Qualified,
                        "9".repeat(64),
                        cursor,
                    ),
                    3 => opportunity.add_buying_committee_member(
                        committee_member(
                            &format!("person-model-{index}"),
                            BuyingCommitteeRole::EndUser,
                        ),
                        cursor,
                    ),
                    4 => opportunity.set_forecast(
                        Money::new(amount, CurrencyCode::parse("EUR").expect("EUR")),
                        "a".repeat(64),
                        before.updated_at - Duration::seconds(1),
                    ),
                    5 => {
                        let mut overflow = opportunity.clone();
                        overflow.revision = u64::MAX;
                        let overflow_before = overflow.clone();
                        let overflow_result = overflow.set_forecast(
                            Money::new(amount, CurrencyCode::parse("EUR").expect("EUR")),
                            "b".repeat(64),
                            cursor,
                        );
                        prop_assert!(overflow_result.is_err());
                        prop_assert_eq!(overflow, overflow_before);
                        Ok(())
                    }
                    _ => opportunity.advance_stage(
                        OpportunityStage::ClosedLost,
                        "not-a-digest",
                        cursor,
                    ),
                };

                if result.is_ok() && action != 5 {
                    prop_assert_eq!(opportunity.revision, before.revision + 1);
                    prop_assert!(opportunity.updated_at >= before.updated_at);
                    prop_assert!(opportunity.follows_command(&before).expect("command replay"));
                } else {
                    prop_assert_eq!(opportunity.clone(), before);
                }
                prop_assert_eq!(opportunity.id.clone(), initial.id.clone());
                prop_assert_eq!(opportunity.tenant_id.clone(), initial.tenant_id.clone());
                prop_assert_eq!(opportunity.project_id.clone(), initial.project_id.clone());
                prop_assert!(opportunity.validate().is_ok());
                prop_assert!(opportunity_stage_history_is_consistent(&opportunity));
                let serialized = serde_json::to_value(&opportunity).expect("serialize");
                prop_assert!(serialized.get("revenue").is_none());
            }
        }
    }
}
