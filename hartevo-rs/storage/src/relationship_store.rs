use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    BuyingCommitteeMember, Campaign, CampaignId, CampaignRecipient, CampaignRecipientState,
    CompanyId, Conversation, ConversationId, ConversationMessage, MessageDelivery, Mission,
    Opportunity, OpportunityId, PersonId, ProjectId, StageTransition, TenantId,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::aggregate::{PendingEvent, append_events};
use crate::normalized::update_mission_normalized_cas;
use crate::{PersistedMutation, ProjectStore, StorageError};

impl ProjectStore {
    pub fn update_conversation_and_mission_atomic(
        &mut self,
        conversation: &Conversation,
        expected_conversation_revision: u64,
        mission: &Mission,
        expected_mission_revision: u64,
        conversation_events: &[PendingEvent],
        mission_events: &[PendingEvent],
    ) -> Result<(), StorageError> {
        validate_conversation(conversation)?;
        require_next(expected_conversation_revision, conversation.revision)?;
        validate_conversation_transition(self, conversation, expected_conversation_revision)?;
        if mission.revision <= expected_mission_revision {
            return Err(StorageError::UnexpectedNewerRevision {
                expected_revision: expected_mission_revision,
                actual: mission.revision,
            });
        }
        if conversation_events.is_empty() || mission_events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        if conversation.tenant_id != mission.tenant_id
            || conversation.project_id != mission.project_id
            || conversation.mission_id.as_ref() != Some(&mission.id)
        {
            return Err(StorageError::TenantScopeMismatch);
        }
        let transaction = self.connection.transaction()?;
        ensure_conversation_scope(&transaction, conversation)?;
        let updated =
            update_conversation_row(&transaction, conversation, expected_conversation_revision)?;
        require_updated(
            updated,
            "conversation",
            conversation.id.as_str(),
            expected_conversation_revision,
        )?;
        persist_conversation_messages(&transaction, conversation)?;
        update_mission_normalized_cas(&transaction, mission, expected_mission_revision)?;
        append_events(
            &transaction,
            conversation.tenant_id.as_str(),
            conversation.project_id.as_str(),
            conversation
                .mission_id
                .as_ref()
                .map(hartevo_domain_kernel::MissionId::as_str),
            "conversation",
            conversation.id.as_str(),
            conversation_events,
        )?;
        append_events(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            Some(mission.id.as_str()),
            "mission",
            mission.id.as_str(),
            mission_events,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn create_conversation(
        &mut self,
        conversation: &Conversation,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        validate_conversation(conversation)?;
        require_initial(conversation.revision)?;
        if !conversation
            .is_initial_snapshot()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?
        {
            return Err(StorageError::DomainDecode(
                "conversation must begin from its exact initial snapshot".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        ensure_conversation_scope(&transaction, conversation)?;
        insert_conversation(&transaction, conversation)?;
        persist_conversation_messages(&transaction, conversation)?;
        finish(
            transaction,
            &conversation.tenant_id,
            &conversation.project_id,
            conversation.mission_id.as_ref(),
            "conversation",
            conversation.id.as_str(),
            conversation.revision,
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn update_conversation(
        &mut self,
        conversation: &Conversation,
        expected_revision: u64,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        validate_conversation(conversation)?;
        require_next(expected_revision, conversation.revision)?;
        validate_conversation_transition(self, conversation, expected_revision)?;
        let transaction = self.connection.transaction()?;
        ensure_conversation_scope(&transaction, conversation)?;
        let updated = update_conversation_row(&transaction, conversation, expected_revision)?;
        require_updated(
            updated,
            "conversation",
            conversation.id.as_str(),
            expected_revision,
        )?;
        persist_conversation_messages(&transaction, conversation)?;
        finish(
            transaction,
            &conversation.tenant_id,
            &conversation.project_id,
            conversation.mission_id.as_ref(),
            "conversation",
            conversation.id.as_str(),
            conversation.revision,
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn load_conversation(
        &self,
        project_id: &ProjectId,
        conversation_id: &ConversationId,
    ) -> Result<Conversation, StorageError> {
        let record_json = load_record(
            &self.connection,
            "conversations",
            project_id,
            conversation_id.as_str(),
            "conversation",
        )?;
        let conversation: Conversation = decode_json(&record_json)?;
        let messages = load_json_children::<ConversationMessage>(
            &self.connection,
            "SELECT record_json FROM conversation_messages
             WHERE project_id = ?1 AND conversation_id = ?2 ORDER BY sequence ASC",
            project_id,
            conversation_id.as_str(),
        )?;
        if messages != conversation.messages {
            return Err(StorageError::DomainDecode(
                "conversation message projection differs from aggregate record".into(),
            ));
        }
        validate_conversation(&conversation)?;
        Ok(conversation)
    }

    pub fn create_campaign(
        &mut self,
        campaign: &Campaign,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        validate_campaign(campaign)?;
        require_initial(campaign.revision)?;
        if !campaign
            .is_initial_snapshot()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?
        {
            return Err(StorageError::DomainDecode(
                "campaign must begin from its exact initial snapshot".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        ensure_campaign_scope(&transaction, campaign)?;
        insert_campaign(&transaction, campaign)?;
        persist_campaign_recipients(&transaction, campaign)?;
        finish(
            transaction,
            &campaign.tenant_id,
            &campaign.project_id,
            Some(&campaign.mission_id),
            "campaign",
            campaign.id.as_str(),
            campaign.revision,
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn update_campaign(
        &mut self,
        campaign: &Campaign,
        expected_revision: u64,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        validate_campaign(campaign)?;
        require_next(expected_revision, campaign.revision)?;
        validate_campaign_transition(self, campaign, expected_revision)?;
        let transaction = self.connection.transaction()?;
        ensure_campaign_scope(&transaction, campaign)?;
        let updated = update_campaign_row(&transaction, campaign, expected_revision)?;
        require_updated(updated, "campaign", campaign.id.as_str(), expected_revision)?;
        persist_campaign_recipients(&transaction, campaign)?;
        finish(
            transaction,
            &campaign.tenant_id,
            &campaign.project_id,
            Some(&campaign.mission_id),
            "campaign",
            campaign.id.as_str(),
            campaign.revision,
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn load_campaign(
        &self,
        project_id: &ProjectId,
        campaign_id: &CampaignId,
    ) -> Result<Campaign, StorageError> {
        let record_json = load_record(
            &self.connection,
            "campaigns",
            project_id,
            campaign_id.as_str(),
            "campaign",
        )?;
        let campaign: Campaign = decode_json(&record_json)?;
        let recipients = load_json_children::<CampaignRecipient>(
            &self.connection,
            "SELECT record_json FROM campaign_recipients
             WHERE project_id = ?1 AND campaign_id = ?2 ORDER BY ordinal ASC",
            project_id,
            campaign_id.as_str(),
        )?;
        if recipients != campaign.recipients {
            return Err(StorageError::DomainDecode(
                "campaign recipient projection differs from aggregate record".into(),
            ));
        }
        validate_campaign(&campaign)?;
        Ok(campaign)
    }

    pub fn create_opportunity(
        &mut self,
        opportunity: &Opportunity,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        validate_opportunity(opportunity)?;
        require_initial(opportunity.revision)?;
        if !opportunity
            .is_initial_snapshot()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?
        {
            return Err(StorageError::DomainDecode(
                "opportunity must begin from its exact initial snapshot".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        ensure_opportunity_scope(&transaction, opportunity)?;
        insert_opportunity(&transaction, opportunity)?;
        persist_opportunity_children(&transaction, opportunity)?;
        finish(
            transaction,
            &opportunity.tenant_id,
            &opportunity.project_id,
            None,
            "opportunity",
            opportunity.id.as_str(),
            opportunity.revision,
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn update_opportunity(
        &mut self,
        opportunity: &Opportunity,
        expected_revision: u64,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        validate_opportunity(opportunity)?;
        require_next(expected_revision, opportunity.revision)?;
        validate_opportunity_transition(self, opportunity, expected_revision)?;
        let transaction = self.connection.transaction()?;
        ensure_opportunity_scope(&transaction, opportunity)?;
        let updated = update_opportunity_row(&transaction, opportunity, expected_revision)?;
        require_updated(
            updated,
            "opportunity",
            opportunity.id.as_str(),
            expected_revision,
        )?;
        persist_opportunity_children(&transaction, opportunity)?;
        finish(
            transaction,
            &opportunity.tenant_id,
            &opportunity.project_id,
            None,
            "opportunity",
            opportunity.id.as_str(),
            opportunity.revision,
            event_type,
            payload,
            recorded_at,
        )
    }

    pub fn load_opportunity(
        &self,
        project_id: &ProjectId,
        opportunity_id: &OpportunityId,
    ) -> Result<Opportunity, StorageError> {
        let record_json = load_record(
            &self.connection,
            "opportunities",
            project_id,
            opportunity_id.as_str(),
            "opportunity",
        )?;
        let opportunity: Opportunity = decode_json(&record_json)?;
        let stored_committee: std::collections::BTreeSet<_> =
            load_json_children::<BuyingCommitteeMember>(
                &self.connection,
                "SELECT record_json FROM opportunity_committee_members
             WHERE project_id = ?1 AND opportunity_id = ?2 ORDER BY person_id, role",
                project_id,
                opportunity_id.as_str(),
            )?
            .into_iter()
            .collect();
        let stored_history = load_json_children::<StageTransition>(
            &self.connection,
            "SELECT record_json FROM opportunity_stage_history
             WHERE project_id = ?1 AND opportunity_id = ?2 ORDER BY ordinal ASC",
            project_id,
            opportunity_id.as_str(),
        )?;
        if stored_committee != opportunity.buying_committee
            || stored_history != opportunity.stage_history
        {
            return Err(StorageError::DomainDecode(
                "opportunity child projection differs from aggregate record".into(),
            ));
        }
        validate_opportunity(&opportunity)?;
        Ok(opportunity)
    }
}

pub(crate) fn validate_conversation_transition(
    store: &ProjectStore,
    conversation: &Conversation,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let previous = store.load_conversation(&conversation.project_id, &conversation.id)?;
    if previous.revision != expected_revision {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("conversation:{}", conversation.id),
            expected_revision,
        });
    }
    if !conversation
        .follows_command(&previous)
        .map_err(|error| StorageError::DomainDecode(error.to_string()))?
    {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "conversation command transition",
            id: conversation.id.to_string(),
        });
    }
    Ok(())
}

fn validate_campaign_transition(
    store: &ProjectStore,
    campaign: &Campaign,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let previous = store.load_campaign(&campaign.project_id, &campaign.id)?;
    if previous.revision != expected_revision {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("campaign:{}", campaign.id),
            expected_revision,
        });
    }
    if !campaign
        .follows_command(&previous)
        .map_err(|error| StorageError::DomainDecode(error.to_string()))?
    {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "campaign command transition",
            id: campaign.id.to_string(),
        });
    }
    Ok(())
}

fn validate_opportunity_transition(
    store: &ProjectStore,
    opportunity: &Opportunity,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let previous = store.load_opportunity(&opportunity.project_id, &opportunity.id)?;
    if previous.revision != expected_revision {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("opportunity:{}", opportunity.id),
            expected_revision,
        });
    }
    if !opportunity
        .follows_command(&previous)
        .map_err(|error| StorageError::DomainDecode(error.to_string()))?
    {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "opportunity command transition",
            id: opportunity.id.to_string(),
        });
    }
    Ok(())
}

pub(crate) fn insert_conversation(
    transaction: &Transaction<'_>,
    conversation: &Conversation,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO conversations
           (id, tenant_id, project_id, mission_id, person_id, company_id, gateway,
            provider, connection_id, account_id, route_digest, contact_channel, market, state, control_json,
            control_generation, last_resume_evidence_digest, revision, created_at,
            updated_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                 ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        conversation_params(conversation)?,
    )?;
    Ok(())
}

pub(crate) fn update_conversation_row(
    transaction: &Transaction<'_>,
    conversation: &Conversation,
    expected_revision: u64,
) -> Result<usize, StorageError> {
    let values = conversation_values(conversation)?;
    Ok(transaction.execute(
        "UPDATE conversations SET
           tenant_id = ?2, mission_id = ?4, person_id = ?5, company_id = ?6,
           gateway = ?7, provider = ?8, connection_id = ?9, account_id = ?10,
           route_digest = ?11, contact_channel = ?12, market = ?13, state = ?14,
           control_json = ?15, control_generation = ?16,
           last_resume_evidence_digest = ?17, revision = ?18, created_at = ?19,
           updated_at = ?20, record_json = ?21
         WHERE id = ?1 AND project_id = ?3 AND revision = ?22",
        rusqlite::params_from_iter(values.into_iter().chain([rusqlite::types::Value::Integer(
            to_sql_u64(expected_revision)?,
        )])),
    )?)
}

fn conversation_params(
    conversation: &Conversation,
) -> Result<impl rusqlite::Params + use<>, StorageError> {
    Ok(rusqlite::params_from_iter(conversation_values(
        conversation,
    )?))
}

fn conversation_values(
    conversation: &Conversation,
) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    Ok(vec![
        conversation.id.to_string().into(),
        conversation.tenant_id.to_string().into(),
        conversation.project_id.to_string().into(),
        conversation
            .mission_id
            .as_ref()
            .map(ToString::to_string)
            .into(),
        conversation.person_id.to_string().into(),
        conversation
            .company_id
            .as_ref()
            .map(ToString::to_string)
            .into(),
        enum_name(&conversation.gateway)?.into(),
        conversation.provider.clone().into(),
        conversation.connection_id.to_string().into(),
        conversation.account_id.to_string().into(),
        conversation.route_digest.clone().into(),
        enum_name(&conversation.contact_channel)?.into(),
        conversation.market.clone().into(),
        enum_name(&conversation.state)?.into(),
        serde_json::to_string(&conversation.control)?.into(),
        to_sql_u64(conversation.control.generation())?.into(),
        conversation.last_resume_evidence_digest.clone().into(),
        to_sql_u64(conversation.revision)?.into(),
        conversation.created_at.to_rfc3339().into(),
        conversation.updated_at.to_rfc3339().into(),
        serde_json::to_string(conversation)?.into(),
    ])
}

pub(crate) fn persist_conversation_messages(
    transaction: &Transaction<'_>,
    conversation: &Conversation,
) -> Result<(), StorageError> {
    for message in &conversation.messages {
        let immutable_digest = conversation_message_immutable_digest(message)?;
        let existing = transaction
            .query_row(
                "SELECT immutable_digest, provider_event_digest, record_json
                 FROM conversation_messages
                 WHERE project_id = ?1 AND conversation_id = ?2 AND id = ?3",
                params![
                    conversation.project_id.as_str(),
                    conversation.id.as_str(),
                    message.id.as_str()
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        if let Some((stored_digest, stored_provider_event, stored_json)) = existing {
            let stored: ConversationMessage = decode_json(&stored_json)?;
            if stored_digest != immutable_digest
                || stored_provider_event
                    .as_ref()
                    .is_some_and(|digest| Some(digest) != message.provider_event_digest.as_ref())
                || !delivery_transition_allowed(&stored.delivery, &message.delivery)
            {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "conversation message",
                    id: message.id.to_string(),
                });
            }
            transaction.execute(
                "UPDATE conversation_messages SET provider_event_digest = ?4,
                   delivery_json = ?5, delivered_at = ?6, record_json = ?7
                 WHERE project_id = ?1 AND conversation_id = ?2 AND id = ?3",
                params![
                    conversation.project_id.as_str(),
                    conversation.id.as_str(),
                    message.id.as_str(),
                    message.provider_event_digest,
                    serde_json::to_string(&message.delivery)?,
                    message.delivered_at.map(|value| value.to_rfc3339()),
                    serde_json::to_string(message)?,
                ],
            )?;
        } else {
            transaction.execute(
                "INSERT INTO conversation_messages
                   (project_id, conversation_id, id, direction, provider_event_digest,
                    content_digest, effect_scope_digest, delivery_json, control_generation,
                    occurred_at, received_at, delivered_at, immutable_digest, record_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    conversation.project_id.as_str(),
                    conversation.id.as_str(),
                    message.id.as_str(),
                    enum_name(&message.direction)?,
                    message.provider_event_digest,
                    message.content_digest,
                    message.effect_scope_digest,
                    serde_json::to_string(&message.delivery)?,
                    to_sql_u64(message.control_generation)?,
                    message.occurred_at.to_rfc3339(),
                    message.received_at.to_rfc3339(),
                    message.delivered_at.map(|value| value.to_rfc3339()),
                    immutable_digest,
                    serde_json::to_string(message)?,
                ],
            )?;
        }
    }
    require_child_count(
        transaction,
        "conversation_messages",
        "conversation_id",
        &conversation.project_id,
        conversation.id.as_str(),
        conversation.messages.len(),
    )
}

fn conversation_message_immutable_digest(
    message: &ConversationMessage,
) -> Result<String, StorageError> {
    digest_json(&serde_json::json!({
        "id": message.id,
        "direction": message.direction,
        "contentDigest": message.content_digest,
        "effectScopeDigest": message.effect_scope_digest,
        "authorizationEvidenceDigest": message.authorization_evidence_digest,
        "attachmentDigests": message.attachment_digests,
        "risk": message.risk,
        "classificationConfidence": message.classification_confidence,
        "controlGeneration": message.control_generation,
        "occurredAt": message.occurred_at,
        "receivedAt": message.received_at,
    }))
}

fn delivery_transition_allowed(stored: &MessageDelivery, next: &MessageDelivery) -> bool {
    if stored == next {
        return true;
    }
    match (stored, next) {
        (MessageDelivery::Draft, MessageDelivery::EffectPrepared { .. }) => true,
        (
            MessageDelivery::EffectPrepared { effect_id: stored },
            MessageDelivery::Sent {
                effect_id: next, ..
            }
            | MessageDelivery::Failed { effect_id: next }
            | MessageDelivery::Uncertain {
                effect_id: next, ..
            }
            | MessageDelivery::CancelledByHandoff { effect_id: next },
        )
        | (
            MessageDelivery::Uncertain {
                effect_id: stored, ..
            },
            MessageDelivery::Sent {
                effect_id: next, ..
            }
            | MessageDelivery::Failed { effect_id: next },
        ) => stored == next,
        _ => false,
    }
}

pub(crate) fn insert_campaign(
    transaction: &Transaction<'_>,
    campaign: &Campaign,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO campaigns
           (id, tenant_id, project_id, mission_id, channel, purpose, market,
            frequency_window_seconds, max_messages_per_window, status, policy_version,
            revision, created_at, updated_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        campaign_params(campaign)?,
    )?;
    Ok(())
}

fn update_campaign_row(
    transaction: &Transaction<'_>,
    campaign: &Campaign,
    expected_revision: u64,
) -> Result<usize, StorageError> {
    Ok(transaction.execute(
        "UPDATE campaigns SET tenant_id = ?2, mission_id = ?4, channel = ?5,
           purpose = ?6, market = ?7, frequency_window_seconds = ?8,
           max_messages_per_window = ?9, status = ?10, policy_version = ?11,
           revision = ?12, created_at = ?13, updated_at = ?14, record_json = ?15
         WHERE id = ?1 AND project_id = ?3 AND revision = ?16",
        rusqlite::params_from_iter(campaign_values(campaign)?.into_iter().chain([
            rusqlite::types::Value::Integer(to_sql_u64(expected_revision)?),
        ])),
    )?)
}

fn campaign_params(campaign: &Campaign) -> Result<impl rusqlite::Params + use<>, StorageError> {
    Ok(rusqlite::params_from_iter(campaign_values(campaign)?))
}

fn campaign_values(campaign: &Campaign) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    Ok(vec![
        campaign.id.to_string().into(),
        campaign.tenant_id.to_string().into(),
        campaign.project_id.to_string().into(),
        campaign.mission_id.to_string().into(),
        enum_name(&campaign.channel)?.into(),
        enum_name(&campaign.purpose)?.into(),
        campaign.market.clone().into(),
        campaign.frequency_window_seconds.into(),
        i64::from(campaign.max_messages_per_window).into(),
        enum_name(&campaign.status)?.into(),
        to_sql_u64(campaign.policy_version)?.into(),
        to_sql_u64(campaign.revision)?.into(),
        campaign.created_at.to_rfc3339().into(),
        campaign.updated_at.to_rfc3339().into(),
        serde_json::to_string(campaign)?.into(),
    ])
}

pub(crate) fn persist_campaign_recipients(
    transaction: &Transaction<'_>,
    campaign: &Campaign,
) -> Result<(), StorageError> {
    for (ordinal, recipient) in campaign.recipients.iter().enumerate() {
        let ordinal = i64::try_from(ordinal)
            .map_err(|_| StorageError::DomainDecode("campaign ordinal overflow".into()))?;
        let existing = transaction
            .query_row(
                "SELECT ordinal, record_json FROM campaign_recipients
                 WHERE project_id = ?1 AND campaign_id = ?2 AND person_id = ?3",
                params![
                    campaign.project_id.as_str(),
                    campaign.id.as_str(),
                    recipient.person_id.as_str()
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        if let Some((stored_ordinal, stored_json)) = existing {
            let stored: CampaignRecipient = decode_json(&stored_json)?;
            if stored_ordinal != ordinal
                || !campaign_recipient_transition_allowed(&stored, recipient)
            {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "campaign recipient",
                    id: recipient.person_id.to_string(),
                });
            }
            transaction.execute(
                "UPDATE campaign_recipients SET state_json = ?4, revision = ?5,
                   record_json = ?6
                 WHERE project_id = ?1 AND campaign_id = ?2 AND person_id = ?3",
                params![
                    campaign.project_id.as_str(),
                    campaign.id.as_str(),
                    recipient.person_id.as_str(),
                    serde_json::to_string(&recipient.state)?,
                    to_sql_u64(recipient.revision)?,
                    serde_json::to_string(recipient)?,
                ],
            )?;
        } else {
            transaction.execute(
                "INSERT INTO campaign_recipients
                   (project_id, campaign_id, person_id, ordinal, consent_record_id,
                    state_json, revision, record_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    campaign.project_id.as_str(),
                    campaign.id.as_str(),
                    recipient.person_id.as_str(),
                    ordinal,
                    recipient.consent_record_id.as_str(),
                    serde_json::to_string(&recipient.state)?,
                    to_sql_u64(recipient.revision)?,
                    serde_json::to_string(recipient)?,
                ],
            )?;
        }
    }
    require_child_count(
        transaction,
        "campaign_recipients",
        "campaign_id",
        &campaign.project_id,
        campaign.id.as_str(),
        campaign.recipients.len(),
    )
}

fn campaign_recipient_transition_allowed(
    stored: &CampaignRecipient,
    next: &CampaignRecipient,
) -> bool {
    stored.person_id == next.person_id
        && stored.consent_record_id == next.consent_record_id
        && (stored == next
            || stored
                .revision
                .checked_add(1)
                .is_some_and(|revision| revision == next.revision))
        && next.sent_at.starts_with(&stored.sent_at)
        && next.receipt_ids.starts_with(&stored.receipt_ids)
        && match (&stored.state, &next.state) {
            (CampaignRecipientState::Active, _) => true,
            (stored @ CampaignRecipientState::Suppressed { .. }, next) => stored == next,
        }
}

pub(crate) fn insert_opportunity(
    transaction: &Transaction<'_>,
    opportunity: &Opportunity,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO opportunities
           (id, tenant_id, project_id, company_id, stage, forecast_amount_minor,
            forecast_currency, forecast_evidence_digest, revision, created_at, updated_at,
            record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        opportunity_params(opportunity)?,
    )?;
    Ok(())
}

fn update_opportunity_row(
    transaction: &Transaction<'_>,
    opportunity: &Opportunity,
    expected_revision: u64,
) -> Result<usize, StorageError> {
    Ok(transaction.execute(
        "UPDATE opportunities SET tenant_id = ?2, company_id = ?4, stage = ?5,
           forecast_amount_minor = ?6, forecast_currency = ?7,
           forecast_evidence_digest = ?8, revision = ?9, created_at = ?10,
           updated_at = ?11, record_json = ?12
         WHERE id = ?1 AND project_id = ?3 AND revision = ?13",
        rusqlite::params_from_iter(opportunity_values(opportunity)?.into_iter().chain([
            rusqlite::types::Value::Integer(to_sql_u64(expected_revision)?),
        ])),
    )?)
}

fn opportunity_params(
    opportunity: &Opportunity,
) -> Result<impl rusqlite::Params + use<>, StorageError> {
    Ok(rusqlite::params_from_iter(opportunity_values(opportunity)?))
}

fn opportunity_values(
    opportunity: &Opportunity,
) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    Ok(vec![
        opportunity.id.to_string().into(),
        opportunity.tenant_id.to_string().into(),
        opportunity.project_id.to_string().into(),
        opportunity.company_id.to_string().into(),
        enum_name(&opportunity.stage)?.into(),
        opportunity
            .forecast_amount
            .as_ref()
            .map(|money| money.amount_minor)
            .into(),
        opportunity
            .forecast_amount
            .as_ref()
            .map(|money| money.currency.to_string())
            .into(),
        opportunity.forecast_evidence_digest.clone().into(),
        to_sql_u64(opportunity.revision)?.into(),
        opportunity.created_at.to_rfc3339().into(),
        opportunity.updated_at.to_rfc3339().into(),
        serde_json::to_string(opportunity)?.into(),
    ])
}

pub(crate) fn persist_opportunity_children(
    transaction: &Transaction<'_>,
    opportunity: &Opportunity,
) -> Result<(), StorageError> {
    for member in &opportunity.buying_committee {
        let record_json = serde_json::to_string(member)?;
        let inserted = transaction.execute(
            "INSERT INTO opportunity_committee_members
               (project_id, opportunity_id, person_id, role, evidence_digest, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(project_id, opportunity_id, person_id, role) DO NOTHING",
            params![
                opportunity.project_id.as_str(),
                opportunity.id.as_str(),
                member.person_id.as_str(),
                enum_name(&member.role)?,
                member.evidence_digest,
                record_json,
            ],
        )?;
        if inserted == 0 {
            let stored: String = transaction.query_row(
                "SELECT record_json FROM opportunity_committee_members
                 WHERE project_id = ?1 AND opportunity_id = ?2 AND person_id = ?3 AND role = ?4",
                params![
                    opportunity.project_id.as_str(),
                    opportunity.id.as_str(),
                    member.person_id.as_str(),
                    enum_name(&member.role)?,
                ],
                |row| row.get(0),
            )?;
            if stored != serde_json::to_string(member)? {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "buying committee member",
                    id: member.person_id.to_string(),
                });
            }
        }
    }
    require_child_count(
        transaction,
        "opportunity_committee_members",
        "opportunity_id",
        &opportunity.project_id,
        opportunity.id.as_str(),
        opportunity.buying_committee.len(),
    )?;
    for (ordinal, transition) in opportunity.stage_history.iter().enumerate() {
        persist_stage_transition(transaction, opportunity, ordinal, transition)?;
    }
    require_child_count(
        transaction,
        "opportunity_stage_history",
        "opportunity_id",
        &opportunity.project_id,
        opportunity.id.as_str(),
        opportunity.stage_history.len(),
    )
}

fn persist_stage_transition(
    transaction: &Transaction<'_>,
    opportunity: &Opportunity,
    ordinal: usize,
    transition: &StageTransition,
) -> Result<(), StorageError> {
    let ordinal = i64::try_from(ordinal)
        .map_err(|_| StorageError::DomainDecode("stage history ordinal overflow".into()))?;
    let record_json = serde_json::to_string(transition)?;
    let immutable_digest = format!("{:x}", Sha256::digest(record_json.as_bytes()));
    let inserted = transaction.execute(
        "INSERT INTO opportunity_stage_history
           (project_id, opportunity_id, ordinal, immutable_digest, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(project_id, opportunity_id, ordinal) DO NOTHING",
        params![
            opportunity.project_id.as_str(),
            opportunity.id.as_str(),
            ordinal,
            immutable_digest,
            record_json,
        ],
    )?;
    if inserted == 0 {
        let stored_digest: String = transaction.query_row(
            "SELECT immutable_digest FROM opportunity_stage_history
             WHERE project_id = ?1 AND opportunity_id = ?2 AND ordinal = ?3",
            params![
                opportunity.project_id.as_str(),
                opportunity.id.as_str(),
                ordinal
            ],
            |row| row.get(0),
        )?;
        if stored_digest != immutable_digest {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "opportunity stage transition",
                id: ordinal.to_string(),
            });
        }
    }
    Ok(())
}

pub(crate) fn ensure_conversation_scope(
    transaction: &Transaction<'_>,
    conversation: &Conversation,
) -> Result<(), StorageError> {
    ensure_project(
        transaction,
        &conversation.tenant_id,
        &conversation.project_id,
    )?;
    if let Some(mission_id) = &conversation.mission_id {
        ensure_mission(transaction, &conversation.project_id, mission_id.as_str())?;
    }
    ensure_person(
        transaction,
        &conversation.project_id,
        &conversation.person_id,
    )?;
    if let Some(company_id) = &conversation.company_id {
        ensure_company(transaction, &conversation.project_id, company_id)?;
    }
    let binding = transaction
        .query_row(
            "SELECT tenant_id, provider, account_id FROM connections
             WHERE project_id = ?1 AND id = ?2",
            params![
                conversation.project_id.as_str(),
                conversation.connection_id.as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StorageError::ScopedRecordNotFound {
            kind: "conversation connection",
            project_id: conversation.project_id.clone(),
            id: conversation.connection_id.to_string(),
        })?;
    if binding.0 != conversation.tenant_id.as_str()
        || binding.1 != conversation.provider
        || binding.2 != conversation.account_id.as_str()
    {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

pub(crate) fn ensure_campaign_scope(
    transaction: &Transaction<'_>,
    campaign: &Campaign,
) -> Result<(), StorageError> {
    ensure_project(transaction, &campaign.tenant_id, &campaign.project_id)?;
    ensure_mission(
        transaction,
        &campaign.project_id,
        campaign.mission_id.as_str(),
    )?;
    for recipient in &campaign.recipients {
        ensure_person(transaction, &campaign.project_id, &recipient.person_id)?;
        let consent_person = transaction
            .query_row(
                "SELECT person_id FROM consent_records WHERE project_id = ?1 AND id = ?2",
                params![
                    campaign.project_id.as_str(),
                    recipient.consent_record_id.as_str()
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                missing(
                    "consent record",
                    &campaign.project_id,
                    recipient.consent_record_id.as_str(),
                )
            })?;
        if consent_person != recipient.person_id.as_str() {
            return Err(StorageError::TenantScopeMismatch);
        }
    }
    Ok(())
}

pub(crate) fn ensure_opportunity_scope(
    transaction: &Transaction<'_>,
    opportunity: &Opportunity,
) -> Result<(), StorageError> {
    ensure_project(transaction, &opportunity.tenant_id, &opportunity.project_id)?;
    ensure_company(
        transaction,
        &opportunity.project_id,
        &opportunity.company_id,
    )?;
    for member in &opportunity.buying_committee {
        ensure_person(transaction, &opportunity.project_id, &member.person_id)?;
    }
    Ok(())
}

fn ensure_project(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
) -> Result<(), StorageError> {
    let exists = transaction
        .query_row(
            "SELECT 1 FROM projects WHERE tenant_id = ?1 AND id = ?2",
            params![tenant_id.as_str(), project_id.as_str()],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(StorageError::ProjectNotFound(project_id.clone()))
    }
}

fn ensure_mission(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    mission_id: &str,
) -> Result<(), StorageError> {
    let exists = transaction
        .query_row(
            "SELECT 1 FROM missions WHERE project_id = ?1 AND id = ?2",
            params![project_id.as_str(), mission_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(StorageError::MissionNotFound {
            project_id: project_id.clone(),
            mission_id: hartevo_domain_kernel::MissionId::from_stable(mission_id),
        })
    }
}

fn ensure_person(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    person_id: &PersonId,
) -> Result<(), StorageError> {
    ensure_reference(
        transaction,
        "people",
        "person",
        project_id,
        person_id.as_str(),
    )
}

fn ensure_company(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    company_id: &CompanyId,
) -> Result<(), StorageError> {
    ensure_reference(
        transaction,
        "companies",
        "company",
        project_id,
        company_id.as_str(),
    )
}

fn ensure_reference(
    transaction: &Transaction<'_>,
    table: &'static str,
    kind: &'static str,
    project_id: &ProjectId,
    id: &str,
) -> Result<(), StorageError> {
    let query = format!("SELECT 1 FROM {table} WHERE project_id = ?1 AND id = ?2");
    let exists = transaction
        .query_row(&query, params![project_id.as_str(), id], |_| Ok(()))
        .optional()?
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(missing(kind, project_id, id))
    }
}

#[allow(clippy::too_many_arguments)]
fn finish(
    transaction: Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    mission_id: Option<&hartevo_domain_kernel::MissionId>,
    aggregate_type: &str,
    aggregate_id: &str,
    revision: u64,
    event_type: &str,
    payload: &Value,
    recorded_at: DateTime<Utc>,
) -> Result<PersistedMutation, StorageError> {
    if event_type.trim().is_empty() {
        return Err(StorageError::EmptyEventType);
    }
    let payload_json = serde_json::to_string(payload)?;
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            tenant_id.as_str(),
            project_id.as_str(),
            mission_id.map(hartevo_domain_kernel::MissionId::as_str),
            event_type,
            payload_json,
            recorded_at.to_rfc3339(),
        ],
    )?;
    let event_sequence = transaction.last_insert_rowid();
    transaction.execute(
        "INSERT INTO outbox_messages
           (tenant_id, project_id, mission_id, aggregate_type, aggregate_id, event_type,
            payload_json, available_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
        params![
            tenant_id.as_str(),
            project_id.as_str(),
            mission_id.map(hartevo_domain_kernel::MissionId::as_str),
            aggregate_type,
            aggregate_id,
            event_type,
            payload_json,
            recorded_at.to_rfc3339(),
        ],
    )?;
    let outbox_sequence = transaction.last_insert_rowid();
    transaction.commit()?;
    Ok(PersistedMutation {
        event_sequence,
        outbox_sequence,
        state_revision: revision,
    })
}

fn require_initial(revision: u64) -> Result<(), StorageError> {
    if revision == 1 {
        Ok(())
    } else {
        Err(StorageError::InvalidInitialRevision(revision))
    }
}

pub(crate) fn require_next(expected: u64, actual: u64) -> Result<(), StorageError> {
    let next = expected
        .checked_add(1)
        .ok_or(StorageError::RevisionOverflow(expected))?;
    if actual == next {
        Ok(())
    } else {
        Err(StorageError::UnexpectedNextRevision {
            expected: next,
            actual,
        })
    }
}

pub(crate) fn require_updated(
    updated: usize,
    kind: &str,
    id: &str,
    expected_revision: u64,
) -> Result<(), StorageError> {
    if updated == 1 {
        Ok(())
    } else {
        Err(StorageError::OptimisticConflict {
            aggregate: format!("{kind}:{id}"),
            expected_revision,
        })
    }
}

fn require_child_count(
    transaction: &Transaction<'_>,
    table: &str,
    parent_column: &str,
    project_id: &ProjectId,
    parent_id: &str,
    expected: usize,
) -> Result<(), StorageError> {
    let query =
        format!("SELECT COUNT(*) FROM {table} WHERE project_id = ?1 AND {parent_column} = ?2");
    let stored: i64 =
        transaction.query_row(&query, params![project_id.as_str(), parent_id], |row| {
            row.get(0)
        })?;
    if usize::try_from(stored).ok() == Some(expected) {
        Ok(())
    } else {
        Err(StorageError::ImmutableRecordMismatch {
            kind: "relationship child set",
            id: parent_id.into(),
        })
    }
}

fn load_record(
    connection: &rusqlite::Connection,
    table: &str,
    project_id: &ProjectId,
    id: &str,
    kind: &'static str,
) -> Result<String, StorageError> {
    let query = format!("SELECT record_json FROM {table} WHERE project_id = ?1 AND id = ?2");
    connection
        .query_row(&query, params![project_id.as_str(), id], |row| row.get(0))
        .optional()?
        .ok_or_else(|| missing(kind, project_id, id))
}

fn load_json_children<T: DeserializeOwned>(
    connection: &rusqlite::Connection,
    query: &str,
    project_id: &ProjectId,
    parent_id: &str,
) -> Result<Vec<T>, StorageError> {
    let mut statement = connection.prepare(query)?;
    let rows = statement.query_map(params![project_id.as_str(), parent_id], |row| {
        row.get::<_, String>(0)
    })?;
    rows.map(|row| decode_json(&row?)).collect()
}

pub(crate) fn validate_conversation(conversation: &Conversation) -> Result<(), StorageError> {
    conversation
        .validate()
        .map_err(|error| StorageError::DomainDecode(error.to_string()))
}

fn validate_campaign(campaign: &Campaign) -> Result<(), StorageError> {
    campaign
        .validate()
        .map_err(|error| StorageError::DomainDecode(error.to_string()))
}

fn validate_opportunity(opportunity: &Opportunity) -> Result<(), StorageError> {
    opportunity
        .validate()
        .map_err(|error| StorageError::DomainDecode(error.to_string()))
}

fn digest_json(value: &Value) -> Result<String, StorageError> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn enum_name(value: &impl Serialize) -> Result<String, StorageError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| StorageError::DomainDecode("enum did not serialize as a string".into()))
}

fn decode_json<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_str(value)?)
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn missing(kind: &'static str, project_id: &ProjectId, id: &str) -> StorageError {
    StorageError::ScopedRecordNotFound {
        kind,
        project_id: project_id.clone(),
        id: id.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, ActorId, AutomatedReplyAuthorization, BuyingCommitteeRole, Connection,
        ConnectionId, ConsentPurpose, ConsentRecord, ConsentRecordId, ConsentState, ContactChannel,
        ConversationContentRisk, ConversationEffectGuard, CurrencyCode, Effect, EffectClass,
        EffectId, EffectRisk, EffectSpec, InboundMessageInput, LegalBasis, MessageId, Mission,
        MissionContract, MissionId, Money, OpportunityStage, Person, PreparedAutomaticReply,
        Project, Receipt, ReceiptId, StorageMode, SuppressionReason, Verification, VerificationId,
        VerificationStatus, WebhookAttestation,
    };
    use hartevo_effect_broker::{
        BrokerError, EffectBroker, EffectExecutor, EffectPolicy, EffectRateLimit, EffectVerifier,
        PermissionFailure, ProviderFailure,
    };

    use crate::PendingEvent;

    use super::*;

    struct RelationshipFixture {
        store: ProjectStore,
        tenant_id: TenantId,
        project_id: ProjectId,
        company_id: CompanyId,
        person_id: PersonId,
        automated_reply_consent: ConsentRecord,
        marketing_consent: ConsentRecord,
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 20, 0, 0)
            .single()
            .expect("valid time")
    }

    fn setup() -> RelationshipFixture {
        let mut store = ProjectStore::in_memory().expect("store");
        let tenant_id = TenantId::from("tenant-relationship");
        let project_id = ProjectId::from("project-relationship");
        persist_project_and_missions(&mut store, &tenant_id, &project_id);
        let conversation_connection = Connection::register(
            ConnectionId::from("connection-relationship-gmail"),
            tenant_id.clone(),
            project_id.clone(),
            "gmail",
            AccountId::from("account-1"),
            "owner@example.invalid",
            ["conversation.reply".into()],
            now(),
        )
        .expect("conversation connection");
        store
            .create_connection(
                &conversation_connection,
                "connection.registered",
                &serde_json::json!({"connectionId": conversation_connection.id()}),
                now(),
            )
            .expect("persist conversation connection");
        let (company_id, person_id) =
            persist_company_and_person(&mut store, &tenant_id, &project_id);
        let automated_reply_consent = consent(
            "consent-reply",
            ConsentPurpose::AutomatedReply,
            &tenant_id,
            &project_id,
            &person_id,
        );
        let marketing_consent = consent(
            "consent-marketing",
            ConsentPurpose::EmailMarketing,
            &tenant_id,
            &project_id,
            &person_id,
        );
        for record in [&automated_reply_consent, &marketing_consent] {
            store
                .create_consent_record(
                    record,
                    "consent.granted",
                    &serde_json::json!({"consentRecordId": record.id}),
                    now(),
                )
                .expect("persist consent");
        }
        RelationshipFixture {
            store,
            tenant_id,
            project_id,
            company_id,
            person_id,
            automated_reply_consent,
            marketing_consent,
        }
    }

    fn persist_project_and_missions(
        store: &mut ProjectStore,
        tenant_id: &TenantId,
        project_id: &ProjectId,
    ) {
        let project = Project::create_local(
            tenant_id.clone(),
            project_id.clone(),
            "Relationship project",
            "",
            "/tmp/hartevo-relationship",
            StorageMode::LocalExisting,
        )
        .expect("project");
        store
            .create_project_atomic(
                &project,
                &[PendingEvent::new(
                    "project.created",
                    serde_json::json!({"projectId": project_id}),
                    now(),
                )],
            )
            .expect("persist project");
        for mission_id in ["mission-5", "mission-10"] {
            let mission = Mission::compile(
                tenant_id.clone(),
                MissionId::from_stable(mission_id),
                project_id.clone(),
                "Relationship mission",
                MissionContract::bootstrap(
                    "Preserve consent and human-control invariants",
                    ["conversation.reply".into()],
                    now(),
                ),
                now(),
            )
            .expect("mission");
            store
                .create_mission_atomic(
                    &mission,
                    &[PendingEvent::new(
                        "mission.compiled",
                        serde_json::json!({"missionId": mission_id}),
                        now(),
                    )],
                )
                .expect("persist mission");
        }
    }

    fn persist_company_and_person(
        store: &mut ProjectStore,
        tenant_id: &TenantId,
        project_id: &ProjectId,
    ) -> (CompanyId, PersonId) {
        let company_id = CompanyId::from("company-relationship");
        let company = hartevo_domain_kernel::Company::create(
            company_id.clone(),
            tenant_id.clone(),
            project_id.clone(),
            "Creator Studio",
            "DE",
        )
        .expect("company");
        store
            .create_company(
                &company,
                "company.created",
                &serde_json::json!({"companyId": company.id}),
                now(),
            )
            .expect("persist company");
        let person_id = PersonId::from("person-relationship");
        let person = Person::create(
            person_id.clone(),
            tenant_id.clone(),
            project_id.clone(),
            "Verified creator",
            Some(company_id.clone()),
            vec![],
        )
        .expect("person");
        store
            .create_person(
                &person,
                "person.created",
                &serde_json::json!({"personId": person.id}),
                now(),
            )
            .expect("persist person");
        (company_id, person_id)
    }

    fn consent(
        id: &str,
        purpose: ConsentPurpose,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        person_id: &PersonId,
    ) -> ConsentRecord {
        ConsentRecord::grant(
            ConsentRecordId::from_stable(id),
            tenant_id.clone(),
            project_id.clone(),
            person_id.clone(),
            purpose,
            ContactChannel::Email,
            "DE",
            LegalBasis::ExplicitConsent,
            "preference-center",
            "a".repeat(64),
            now() - Duration::days(1),
            None,
        )
        .expect("consent")
    }

    fn open_conversation(fixture: &RelationshipFixture) -> Conversation {
        Conversation::open(
            ConversationId::from("conversation-1"),
            fixture.tenant_id.clone(),
            fixture.project_id.clone(),
            Some(MissionId::from("mission-10")),
            fixture.person_id.clone(),
            Some(fixture.company_id.clone()),
            hartevo_domain_kernel::MessagingGateway::Gmail,
            "gmail",
            ConnectionId::from("connection-relationship-gmail"),
            AccountId::from("account-1"),
            "b".repeat(64),
            ContactChannel::Email,
            "DE",
            now(),
        )
        .expect("conversation")
    }

    fn inbound() -> InboundMessageInput {
        InboundMessageInput {
            id: MessageId::from("inbound-1"),
            provider_event_digest: "c".repeat(64),
            content_digest: "d".repeat(64),
            attachment_digests: BTreeSet::new(),
            risk: ConversationContentRisk::Safe,
            classification_confidence: "0.97".parse().expect("confidence"),
            occurred_at: now(),
        }
    }

    fn attestation() -> WebhookAttestation {
        WebhookAttestation {
            signature_verified: true,
            route_digest: "b".repeat(64),
            provider: "gmail".into(),
            connection_id: ConnectionId::from("connection-relationship-gmail"),
            account_id: AccountId::from("account-1"),
            received_at: now() + Duration::seconds(1),
        }
    }

    #[derive(Default)]
    struct CountingExecutor {
        calls: usize,
    }

    impl EffectExecutor for CountingExecutor {
        fn execute(&mut self, effect: &Effect) -> Result<Receipt, ProviderFailure> {
            self.calls += 1;
            Ok(Receipt {
                id: ReceiptId::from("reply-receipt-1"),
                provider: effect.provider.clone(),
                external_id: "provider-message-1".into(),
                accepted_at: now() + Duration::seconds(10),
                request_digest: effect.approval_digest(),
                response_digest: "6".repeat(64),
            })
        }
    }

    struct ConfirmingVerifier;

    impl EffectVerifier for ConfirmingVerifier {
        fn verify(&mut self, _effect: &Effect, receipt: &Receipt) -> Verification {
            Verification {
                id: VerificationId::from("reply-verification-1"),
                status: VerificationStatus::Confirmed,
                verifier: "provider-readback".into(),
                independent: true,
                observed_at: now() + Duration::seconds(11),
                evidence_digest: "7".repeat(64),
                receipt_id: receipt.id.clone(),
            }
        }
    }

    #[test]
    fn conversation_handoff_survives_restart_and_history_is_immutable() {
        let mut fixture = setup();
        let mut conversation = open_conversation(&fixture);
        fixture
            .store
            .create_conversation(
                &conversation,
                "conversation.opened",
                &serde_json::json!({"conversationId": conversation.id}),
                now(),
            )
            .expect("persist conversation");
        conversation
            .ingest_inbound(inbound(), &attestation())
            .expect("ingest");
        fixture
            .store
            .update_conversation(
                &conversation,
                1,
                "conversation.inbound_ingested",
                &serde_json::json!({"messageId": "inbound-1"}),
                now() + Duration::seconds(1),
            )
            .expect("persist inbound");
        let effect_id = EffectId::from("reply-effect-1");
        conversation
            .prepare_automatic_reply(
                MessageId::from("outbound-1"),
                "e".repeat(64),
                effect_id.clone(),
                1,
                AutomatedReplyAuthorization::Consent(&fixture.automated_reply_consent),
                now() + Duration::seconds(2),
            )
            .expect("prepare reply");
        fixture
            .store
            .update_conversation(
                &conversation,
                2,
                "conversation.reply_prepared",
                &serde_json::json!({"effectId": effect_id}),
                now() + Duration::seconds(2),
            )
            .expect("persist prepared reply");
        assert!(conversation.authorizes_agent_effect(&effect_id, 1));
        assert_effect_rebinding_rejected(&mut fixture, &conversation);
        let human_generation = conversation
            .take_human_control(1, ActorId::from("reviewer-1"), now() + Duration::seconds(3))
            .expect("take control");
        fixture
            .store
            .update_conversation(
                &conversation,
                3,
                "conversation.human_control_acquired",
                &serde_json::json!({"generation": human_generation}),
                now() + Duration::seconds(3),
            )
            .expect("persist handoff");

        let loaded = fixture
            .store
            .load_conversation(&fixture.project_id, &conversation.id)
            .expect("reload conversation");
        assert_eq!(loaded, conversation);
        assert!(!loaded.authorizes_agent_effect(&effect_id, 1));

        let mut tampered = loaded.clone();
        tampered.messages[0].content_digest = "f".repeat(64);
        tampered.revision += 1;
        tampered.updated_at += Duration::seconds(1);
        assert!(matches!(
            fixture.store.update_conversation(
                &tampered,
                loaded.revision,
                "conversation.tampered",
                &serde_json::json!({"messageId": "inbound-1"}),
                tampered.updated_at,
            ),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "conversation command transition",
                ..
            })
        ));
        assert_eq!(
            fixture
                .store
                .load_conversation(&fixture.project_id, &conversation.id)
                .expect("rollback preserved aggregate"),
            loaded
        );
    }

    fn assert_effect_rebinding_rejected(
        fixture: &mut RelationshipFixture,
        conversation: &Conversation,
    ) {
        let mut rebound = conversation.clone();
        rebound.messages[1].delivery = MessageDelivery::Sent {
            effect_id: EffectId::from("different-effect"),
            receipt_id: ReceiptId::from("forged-receipt"),
        };
        rebound.messages[1].provider_event_digest = Some("0".repeat(64));
        rebound.messages[1].delivered_at = Some(now() + Duration::milliseconds(2500));
        rebound.revision += 1;
        rebound.updated_at = now() + Duration::milliseconds(2500);
        assert!(matches!(
            fixture.store.update_conversation(
                &rebound,
                3,
                "conversation.effect_rebound",
                &serde_json::json!({"effectId": "different-effect"}),
                rebound.updated_at,
            ),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "conversation command transition",
                ..
            })
        ));
    }

    #[test]
    fn human_takeover_after_approval_blocks_provider_execution_before_claim() {
        let mut fixture = setup();
        let effect_id = EffectId::from("guarded-reply-effect-1");
        let (mut conversation, prepared) = persist_prepared_conversation(&mut fixture, &effect_id);
        let mut mission = guarded_reply_mission(&fixture, &conversation, prepared, &effect_id);
        let mut broker = relationship_broker();
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("approver-1"),
                &fixture.store,
                now() + Duration::seconds(3),
            )
            .expect("approve while agent owns generation");
        conversation
            .take_human_control(1, ActorId::from("human-1"), now() + Duration::seconds(4))
            .expect("human takeover");
        fixture
            .store
            .update_conversation(
                &conversation,
                3,
                "conversation.human_control_acquired",
                &serde_json::json!({"generation": 2}),
                now() + Duration::seconds(4),
            )
            .expect("persist takeover");
        let mut executor = CountingExecutor::default();
        let mut verifier = ConfirmingVerifier;
        let result = broker.execute_and_verify(
            &mut mission,
            &effect_id,
            &mut fixture.store,
            &mut executor,
            &mut verifier,
            now() + Duration::seconds(5),
        );

        assert_eq!(
            result,
            Err(BrokerError::Permission(
                PermissionFailure::ConversationControlLost
            ))
        );
        assert_eq!(executor.calls, 0);
    }

    fn persist_prepared_conversation(
        fixture: &mut RelationshipFixture,
        effect_id: &EffectId,
    ) -> (Conversation, PreparedAutomaticReply) {
        let mut conversation = open_conversation(fixture);
        fixture
            .store
            .create_conversation(
                &conversation,
                "conversation.opened",
                &serde_json::json!({"conversationId": conversation.id}),
                now(),
            )
            .expect("persist conversation");
        conversation
            .ingest_inbound(inbound(), &attestation())
            .expect("ingest");
        fixture
            .store
            .update_conversation(
                &conversation,
                1,
                "conversation.inbound_ingested",
                &serde_json::json!({"messageId": "inbound-1"}),
                now() + Duration::seconds(1),
            )
            .expect("persist inbound");
        let prepared = conversation
            .prepare_automatic_reply(
                MessageId::from("guarded-outbound-1"),
                "e".repeat(64),
                effect_id.clone(),
                1,
                AutomatedReplyAuthorization::Consent(&fixture.automated_reply_consent),
                now() + Duration::seconds(2),
            )
            .expect("prepare guarded reply");
        fixture
            .store
            .update_conversation(
                &conversation,
                2,
                "conversation.reply_prepared",
                &serde_json::json!({"effectId": effect_id}),
                now() + Duration::seconds(2),
            )
            .expect("persist prepared reply");
        (conversation, prepared)
    }

    fn guarded_reply_mission(
        fixture: &RelationshipFixture,
        conversation: &Conversation,
        prepared: PreparedAutomaticReply,
        effect_id: &EffectId,
    ) -> Mission {
        let mut mission = fixture
            .store
            .load_mission(&fixture.project_id, &MissionId::from("mission-10"))
            .expect("mission");
        mission.start_research([], now()).expect("start mission");
        mission
            .propose_effect(
                guarded_reply_effect(conversation, prepared, effect_id),
                now() + Duration::seconds(2),
            )
            .expect("propose effect");
        mission
    }

    fn guarded_reply_effect(
        conversation: &Conversation,
        prepared: PreparedAutomaticReply,
        effect_id: &EffectId,
    ) -> EffectSpec {
        EffectSpec {
            id: effect_id.clone(),
            actor_id: ActorId::from("agent-1"),
            capability: "conversation.reply".into(),
            provider: "fixture-gmail".into(),
            connection_id: None,
            account_id: None,
            required_scopes: BTreeSet::new(),
            effect_class: EffectClass::Outreach,
            description: "Send the exact prepared reply".into(),
            target_resource: "conversation://conversation-1".into(),
            audience_digest: Some("4".repeat(64)),
            payload_digest: "e".repeat(64),
            asset_digests: BTreeSet::new(),
            scheduled_for: None,
            timezone: "Europe/Berlin".into(),
            consent: ConsentState::NotRequired,
            consent_record_id: None,
            consent_requirement: None,
            conversation_guard: Some(ConversationEffectGuard {
                conversation_id: conversation.id.clone(),
                control_generation: prepared.control_generation,
                scope_digest: prepared.scope_digest,
            }),
            creator_contact_guard: None,
            policy_version: "relationship-policy-v1".into(),
            risk: EffectRisk::High,
            idempotency_key: "guarded-reply-effect-1:v1".into(),
            amount: Money::zero(CurrencyCode::parse("EUR").expect("EUR")),
            expires_at: now() + Duration::hours(1),
        }
    }

    fn relationship_broker() -> EffectBroker {
        EffectBroker::new(
            EffectPolicy {
                version: "relationship-policy-v1".into(),
                allowed_capabilities: BTreeSet::from(["conversation.reply".into()]),
                allowed_classes: BTreeSet::from([EffectClass::Outreach]),
                max_amounts_minor: [(CurrencyCode::parse("EUR").expect("EUR"), 0)]
                    .into_iter()
                    .collect(),
                rate_limits: vec![EffectRateLimit {
                    rule_id: "fixture-gmail-reply-per-minute".into(),
                    provider: "fixture-gmail".into(),
                    capability: "conversation.reply".into(),
                    max_executions: 60,
                    window_seconds: 60,
                }],
            },
            "relationship-worker",
        )
    }

    #[test]
    fn campaign_send_and_suppression_are_append_only() {
        let mut fixture = setup();
        let mut campaign = create_active_campaign(&mut fixture);
        let authorization = campaign
            .authorize_send(
                &fixture.person_id,
                &fixture.marketing_consent,
                now() + Duration::seconds(2),
            )
            .expect("authorize send");
        campaign
            .record_send(
                &authorization,
                &fixture.marketing_consent,
                ReceiptId::from("receipt-campaign-1"),
                now() + Duration::seconds(3),
            )
            .expect("record send");
        fixture
            .store
            .update_campaign(
                &campaign,
                2,
                "campaign.message_sent",
                &serde_json::json!({"receiptId": "receipt-campaign-1"}),
                now() + Duration::seconds(3),
            )
            .expect("persist send");
        campaign
            .suppress_recipient(
                &fixture.person_id,
                SuppressionReason::Complaint,
                "8".repeat(64),
                now() + Duration::seconds(4),
            )
            .expect("suppress");
        fixture
            .store
            .update_campaign(
                &campaign,
                3,
                "campaign.recipient_suppressed",
                &serde_json::json!({"personId": fixture.person_id}),
                now() + Duration::seconds(4),
            )
            .expect("persist suppression");
        let loaded = fixture
            .store
            .load_campaign(&fixture.project_id, &campaign.id)
            .expect("reload campaign");
        assert_eq!(loaded, campaign);

        let mut tampered = loaded.clone();
        tampered.recipients[0].receipt_ids[0] = ReceiptId::from("replacement-receipt");
        tampered.recipients[0].revision += 1;
        tampered.revision += 1;
        tampered.updated_at += Duration::seconds(1);
        assert!(matches!(
            fixture.store.update_campaign(
                &tampered,
                loaded.revision,
                "campaign.history_rewritten",
                &serde_json::json!({"campaignId": campaign.id}),
                tampered.updated_at,
            ),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "campaign command transition",
                ..
            })
        ));
    }

    fn create_active_campaign(fixture: &mut RelationshipFixture) -> Campaign {
        let mut campaign = Campaign::create(
            CampaignId::from("campaign-1"),
            fixture.tenant_id.clone(),
            fixture.project_id.clone(),
            MissionId::from("mission-5"),
            ContactChannel::Email,
            ConsentPurpose::EmailMarketing,
            "DE",
            Duration::days(7),
            1,
            [(
                fixture.person_id.clone(),
                fixture.marketing_consent.id.clone(),
            )],
            now(),
        )
        .expect("campaign");
        fixture
            .store
            .create_campaign(
                &campaign,
                "campaign.created",
                &serde_json::json!({"campaignId": campaign.id}),
                now(),
            )
            .expect("persist campaign");
        campaign
            .activate(now() + Duration::seconds(1))
            .expect("activate");
        fixture
            .store
            .update_campaign(
                &campaign,
                1,
                "campaign.activated",
                &serde_json::json!({"campaignId": campaign.id}),
                now() + Duration::seconds(1),
            )
            .expect("persist activation");
        campaign
    }

    #[test]
    fn opportunity_history_is_immutable_and_forecast_is_not_revenue() {
        let mut fixture = setup();
        let mut opportunity = Opportunity::create(
            OpportunityId::from("opportunity-1"),
            fixture.tenant_id.clone(),
            fixture.project_id.clone(),
            fixture.company_id.clone(),
            [BuyingCommitteeMember {
                person_id: fixture.person_id.clone(),
                role: BuyingCommitteeRole::EconomicBuyer,
                evidence_digest: "9".repeat(64),
            }],
            now(),
        )
        .expect("opportunity");
        fixture
            .store
            .create_opportunity(
                &opportunity,
                "opportunity.created",
                &serde_json::json!({"opportunityId": opportunity.id}),
                now(),
            )
            .expect("persist opportunity");
        opportunity
            .set_forecast(
                Money::new(250_000, CurrencyCode::parse("EUR").expect("EUR")),
                "1".repeat(64),
                now() + Duration::seconds(1),
            )
            .expect("forecast");
        fixture
            .store
            .update_opportunity(
                &opportunity,
                1,
                "opportunity.forecast_updated",
                &serde_json::json!({"forecastEvidenceDigest": "1".repeat(64)}),
                now() + Duration::seconds(1),
            )
            .expect("persist forecast");
        opportunity
            .advance_stage(
                OpportunityStage::Discovery,
                "2".repeat(64),
                now() + Duration::seconds(2),
            )
            .expect("advance stage");
        fixture
            .store
            .update_opportunity(
                &opportunity,
                2,
                "opportunity.stage_advanced",
                &serde_json::json!({"stage": "discovery"}),
                now() + Duration::seconds(2),
            )
            .expect("persist stage");
        let loaded = fixture
            .store
            .load_opportunity(&fixture.project_id, &opportunity.id)
            .expect("reload opportunity");
        assert_eq!(loaded, opportunity);
        let serialized = serde_json::to_value(&loaded).expect("serialize");
        assert!(serialized.get("forecastAmount").is_some());
        assert!(serialized.get("revenue").is_none());

        let mut tampered = loaded.clone();
        tampered.stage_history[0].evidence_digest = "3".repeat(64);
        tampered.revision += 1;
        tampered.updated_at += Duration::seconds(1);
        assert!(matches!(
            fixture.store.update_opportunity(
                &tampered,
                loaded.revision,
                "opportunity.history_rewritten",
                &serde_json::json!({"opportunityId": opportunity.id}),
                tampered.updated_at,
            ),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "opportunity command transition",
                ..
            })
        ));
    }
}
