use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    AccountId, CompanyId, Conversation, ConversationId, ConversationState, MessageDelivery,
    MessageDirection, PersonId, ProjectId, TenantId,
};

const SHA256_HEX_LENGTH: usize = 64;
const MAX_CURSOR_POSITION_LENGTH: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipSourceStream {
    People,
    Companies,
    Opportunities,
    Conversations,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationshipSourceKey {
    pub provider: String,
    pub account_id: AccountId,
    pub stream: RelationshipSourceStream,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationshipSourceRef {
    pub provider: String,
    pub account_id: AccountId,
    pub stream: RelationshipSourceStream,
    pub external_id: String,
}

impl RelationshipSourceRef {
    pub fn validate(&self) -> Result<(), RelationshipProjectionError> {
        if self.provider.trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || self.external_id.trim().is_empty()
        {
            return Err(RelationshipProjectionError::InvalidSourceReference);
        }
        Ok(())
    }

    pub fn key(&self) -> RelationshipSourceKey {
        RelationshipSourceKey {
            provider: self.provider.clone(),
            account_id: self.account_id.clone(),
            stream: self.stream,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationshipSourceCursor {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub provider: String,
    pub account_id: AccountId,
    pub stream: RelationshipSourceStream,
    pub scope_digest: String,
    pub position: Option<String>,
    pub source_revision: u64,
    pub revision: u64,
    pub observed_at: DateTime<Utc>,
}

impl RelationshipSourceCursor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        provider: impl Into<String>,
        account_id: AccountId,
        stream: RelationshipSourceStream,
        position: Option<String>,
        source_revision: u64,
        revision: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, RelationshipProjectionError> {
        let provider = provider.into().trim().to_owned();
        let cursor = Self {
            scope_digest: relationship_source_scope_digest(
                &tenant_id,
                &project_id,
                &provider,
                &account_id,
                stream,
            ),
            tenant_id,
            project_id,
            provider,
            account_id,
            stream,
            position,
            source_revision,
            revision,
            observed_at,
        };
        cursor.validate()?;
        Ok(cursor)
    }

    pub fn initial(
        tenant_id: TenantId,
        project_id: ProjectId,
        provider: impl Into<String>,
        account_id: AccountId,
        stream: RelationshipSourceStream,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, RelationshipProjectionError> {
        Self::new(
            tenant_id,
            project_id,
            provider,
            account_id,
            stream,
            None,
            0,
            1,
            observed_at,
        )
    }

    pub fn validate(&self) -> Result<(), RelationshipProjectionError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.provider.trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || self.revision == 0
            || !is_sha256(&self.scope_digest)
            || self.scope_digest
                != relationship_source_scope_digest(
                    &self.tenant_id,
                    &self.project_id,
                    &self.provider,
                    &self.account_id,
                    self.stream,
                )
            || self.position.as_deref().is_some_and(|position| {
                position.trim().is_empty() || position.len() > MAX_CURSOR_POSITION_LENGTH
            })
        {
            return Err(RelationshipProjectionError::InvalidSourceCursor);
        }
        Ok(())
    }

    pub fn key(&self) -> RelationshipSourceKey {
        RelationshipSourceKey {
            provider: self.provider.clone(),
            account_id: self.account_id.clone(),
            stream: self.stream,
        }
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, RelationshipProjectionError> {
        self.validate()?;
        previous.validate()?;
        if self.tenant_id != previous.tenant_id
            || self.project_id != previous.project_id
            || self.key() != previous.key()
            || self.scope_digest != previous.scope_digest
        {
            return Err(RelationshipProjectionError::ScopeMismatch);
        }
        if self.source_revision < previous.source_revision || self.revision <= previous.revision {
            return Err(RelationshipProjectionError::StaleSourceCursor);
        }
        if self.source_revision == previous.source_revision && self.position != previous.position {
            return Err(RelationshipProjectionError::CursorConflict);
        }
        if self.observed_at < previous.observed_at {
            return Err(RelationshipProjectionError::NonMonotonicObservation);
        }
        Ok(true)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalRelationshipRecord {
    pub canonical_id: String,
    pub source: RelationshipSourceRef,
    pub source_revision: String,
    pub display_name_digest: String,
    pub value_digests: BTreeSet<String>,
    #[serde(default)]
    pub deleted: bool,
    pub observed_at: DateTime<Utc>,
    pub revision: u64,
}

impl CanonicalRelationshipRecord {
    pub fn validate(&self) -> Result<(), RelationshipProjectionError> {
        self.source.validate()?;
        if self.canonical_id.trim().is_empty()
            || self.source_revision.trim().is_empty()
            || !is_sha256(&self.display_name_digest)
            || self.value_digests.iter().any(|digest| !is_sha256(digest))
            || self.revision == 0
        {
            return Err(RelationshipProjectionError::InvalidRelationshipRecord);
        }
        Ok(())
    }

    pub fn same_source_revision(&self, other: &Self) -> bool {
        self.source.key() == other.source.key()
            && self.source.external_id == other.source.external_id
            && self.source_revision == other.source_revision
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationSourceState {
    Open,
    Closed,
    Archived,
    Unknown,
}

/// Content-free provider conversation metadata. This is deliberately separate
/// from `InboxItemProjection`: provider observations cannot change the local
/// Conversation's draft, approval, or human-takeover state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationSourceProjection {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub conversation_id: ConversationId,
    pub person_id: Option<PersonId>,
    pub source: RelationshipSourceRef,
    pub source_revision: String,
    pub source_revision_digest: String,
    pub source_state: ConversationSourceState,
    pub archived: bool,
    #[serde(default)]
    pub deleted: bool,
    pub latest_activity_at: Option<DateTime<Utc>>,
    pub latest_received_at: Option<DateTime<Utc>>,
    pub latest_sent_at: Option<DateTime<Utc>>,
    pub observed_at: DateTime<Utc>,
    pub revision: u64,
}

impl ConversationSourceProjection {
    pub fn validate(&self) -> Result<(), RelationshipProjectionError> {
        self.source.validate()?;
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.conversation_id.as_str().trim().is_empty()
            || self.source.stream != RelationshipSourceStream::Conversations
            || self.source_revision.trim().is_empty()
            || !is_sha256(&self.source_revision_digest)
            || self.revision == 0
        {
            return Err(RelationshipProjectionError::InvalidConversationSource);
        }
        Ok(())
    }
}

/// Provider event identity used only for durable webhook deduplication. The
/// raw webhook body and property values never cross this domain boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationshipSourceEvent {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub source: RelationshipSourceRef,
    pub event_id: String,
    pub event_digest: String,
    pub occurred_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub revision: u64,
}

impl RelationshipSourceEvent {
    pub fn validate(&self) -> Result<(), RelationshipProjectionError> {
        self.source.validate()?;
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.event_id.trim().is_empty()
            || !is_sha256(&self.event_digest)
            || self.revision == 0
        {
            return Err(RelationshipProjectionError::InvalidSourceEvent);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxItemProjection {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub conversation_id: ConversationId,
    pub person_id: PersonId,
    pub company_id: Option<CompanyId>,
    pub provider: String,
    pub account_id: AccountId,
    pub state: ConversationState,
    pub control_generation: u64,
    pub latest_message_digest: Option<String>,
    pub latest_message_direction: Option<MessageDirection>,
    pub latest_message_delivery: Option<MessageDelivery>,
    pub latest_message_at: Option<DateTime<Utc>>,
    pub inbound_message_count: u64,
    pub conversation_revision: u64,
    pub updated_at: DateTime<Utc>,
}

impl InboxItemProjection {
    pub fn from_conversation(
        conversation: &Conversation,
    ) -> Result<Self, RelationshipProjectionError> {
        conversation
            .validate()
            .map_err(|error| RelationshipProjectionError::InvalidConversation(error.to_string()))?;
        let latest = conversation.messages.last();
        let inbound_message_count = conversation
            .messages
            .iter()
            .filter(|message| message.direction == MessageDirection::Inbound)
            .count();
        let inbound_message_count = u64::try_from(inbound_message_count)
            .map_err(|_| RelationshipProjectionError::RevisionOverflow)?;
        Ok(Self {
            tenant_id: conversation.tenant_id.clone(),
            project_id: conversation.project_id.clone(),
            conversation_id: conversation.id.clone(),
            person_id: conversation.person_id.clone(),
            company_id: conversation.company_id.clone(),
            provider: conversation.provider.clone(),
            account_id: conversation.account_id.clone(),
            state: conversation.state.clone(),
            control_generation: conversation.control.generation(),
            latest_message_digest: latest.map(|message| message.content_digest.clone()),
            latest_message_direction: latest.map(|message| message.direction.clone()),
            latest_message_delivery: latest.map(|message| message.delivery.clone()),
            latest_message_at: latest.map(|message| message.occurred_at),
            inbound_message_count,
            conversation_revision: conversation.revision,
            updated_at: conversation.updated_at,
        })
    }

    fn validate(&self) -> Result<(), RelationshipProjectionError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.conversation_id.as_str().trim().is_empty()
            || self.person_id.as_str().trim().is_empty()
            || self.provider.trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || self.control_generation == 0
            || self.conversation_revision == 0
            || self
                .latest_message_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(RelationshipProjectionError::InvalidInboxItem);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxProjection {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub revision: u64,
    pub items: Vec<InboxItemProjection>,
    pub relationships: Vec<CanonicalRelationshipRecord>,
    #[serde(default)]
    pub conversation_sources: Vec<ConversationSourceProjection>,
    pub source_cursors: Vec<RelationshipSourceCursor>,
    #[serde(default)]
    pub source_events: Vec<RelationshipSourceEvent>,
    pub updated_at: DateTime<Utc>,
}

impl InboxProjection {
    pub fn empty(tenant_id: TenantId, project_id: ProjectId, now: DateTime<Utc>) -> Self {
        Self {
            tenant_id,
            project_id,
            revision: 1,
            items: Vec::new(),
            relationships: Vec::new(),
            conversation_sources: Vec::new(),
            source_cursors: Vec::new(),
            source_events: Vec::new(),
            updated_at: now,
        }
    }

    pub fn validate(&self) -> Result<(), RelationshipProjectionError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.revision == 0
            || self.items.iter().any(|item| {
                item.validate().is_err()
                    || item.tenant_id != self.tenant_id
                    || item.project_id != self.project_id
            })
            || self.relationships.iter().any(|record| {
                record.validate().is_err()
                    || record.canonical_id
                        != canonical_relationship_id(
                            &self.tenant_id,
                            &self.project_id,
                            &record.source,
                        )
            })
            || self.conversation_sources.iter().any(|source| {
                source.validate().is_err()
                    || source.tenant_id != self.tenant_id
                    || source.project_id != self.project_id
                    || source.conversation_id.as_str()
                        != canonical_conversation_id(
                            &self.tenant_id,
                            &self.project_id,
                            &source.source,
                        )
            })
            || self.source_cursors.iter().any(|cursor| {
                cursor.validate().is_err()
                    || cursor.tenant_id != self.tenant_id
                    || cursor.project_id != self.project_id
            })
            || self.source_events.iter().any(|event| {
                event.validate().is_err()
                    || event.tenant_id != self.tenant_id
                    || event.project_id != self.project_id
            })
            || unique_conversation_count(&self.items) != self.items.len()
            || unique_relationship_count(&self.relationships) != self.relationships.len()
            || unique_conversation_source_count(&self.conversation_sources)
                != self.conversation_sources.len()
            || unique_cursor_count(&self.source_cursors) != self.source_cursors.len()
            || unique_source_event_count(&self.source_events) != self.source_events.len()
        {
            return Err(RelationshipProjectionError::InvalidInboxProjection);
        }
        Ok(())
    }

    pub fn upsert_conversation(
        &mut self,
        conversation: &Conversation,
    ) -> Result<bool, RelationshipProjectionError> {
        if conversation.tenant_id != self.tenant_id || conversation.project_id != self.project_id {
            return Err(RelationshipProjectionError::ScopeMismatch);
        }
        let item = InboxItemProjection::from_conversation(conversation)?;
        let changed = match self
            .items
            .iter()
            .position(|existing| existing.conversation_id == item.conversation_id)
        {
            Some(index) if self.items[index] == item => false,
            Some(index) => {
                self.items[index] = item;
                true
            }
            None => {
                self.items.push(item);
                self.items
                    .sort_by(|left, right| left.conversation_id.cmp(&right.conversation_id));
                true
            }
        };
        if changed {
            self.bump_revision(conversation.updated_at)?;
        }
        Ok(changed)
    }

    pub fn upsert_relationship(
        &mut self,
        record: CanonicalRelationshipRecord,
    ) -> Result<bool, RelationshipProjectionError> {
        record.validate()?;
        let key = (record.source.key(), record.source.external_id.clone());
        let changed = match self.relationships.iter().position(|existing| {
            (existing.source.key(), existing.source.external_id.clone()) == key
        }) {
            None => {
                self.relationships.push(record);
                self.relationships.sort_by(|left, right| {
                    (
                        left.source.provider.as_str(),
                        left.source.account_id.as_str(),
                        left.source.stream,
                        left.source.external_id.as_str(),
                    )
                        .cmp(&(
                            right.source.provider.as_str(),
                            right.source.account_id.as_str(),
                            right.source.stream,
                            right.source.external_id.as_str(),
                        ))
                });
                true
            }
            Some(index) => {
                let existing = &self.relationships[index];
                if existing.canonical_id != record.canonical_id {
                    return Err(RelationshipProjectionError::CanonicalIdentityConflict);
                }
                if existing.source_revision == record.source_revision {
                    if !same_relationship_observation(existing, &record) {
                        return Err(RelationshipProjectionError::SourceRevisionConflict);
                    }
                    false
                } else if source_revision_order(&record.source_revision)
                    .zip(source_revision_order(&existing.source_revision))
                    .is_some_and(|(incoming, stored)| incoming <= stored)
                {
                    return Err(RelationshipProjectionError::StaleSourceRevision);
                } else {
                    let mut record = record;
                    record.revision = existing
                        .revision
                        .checked_add(1)
                        .ok_or(RelationshipProjectionError::RevisionOverflow)?;
                    self.relationships[index] = record;
                    true
                }
            }
        };
        if changed {
            let now = self
                .relationships
                .iter()
                .map(|entry| entry.observed_at)
                .max()
                .ok_or(RelationshipProjectionError::InvalidInboxProjection)?;
            self.bump_revision(now)?;
        }
        Ok(changed)
    }

    pub fn upsert_conversation_source(
        &mut self,
        source: ConversationSourceProjection,
    ) -> Result<bool, RelationshipProjectionError> {
        source.validate()?;
        if source.tenant_id != self.tenant_id || source.project_id != self.project_id {
            return Err(RelationshipProjectionError::ScopeMismatch);
        }
        let key = (source.source.key(), source.source.external_id.clone());
        let changed = match self.conversation_sources.iter().position(|existing| {
            (existing.source.key(), existing.source.external_id.clone()) == key
        }) {
            None => {
                self.conversation_sources.push(source);
                self.conversation_sources.sort_by(|left, right| {
                    (
                        left.source.provider.as_str(),
                        left.source.account_id.as_str(),
                        left.source.external_id.as_str(),
                    )
                        .cmp(&(
                            right.source.provider.as_str(),
                            right.source.account_id.as_str(),
                            right.source.external_id.as_str(),
                        ))
                });
                true
            }
            Some(index) => {
                let existing = &self.conversation_sources[index];
                if existing.conversation_id != source.conversation_id {
                    return Err(RelationshipProjectionError::CanonicalIdentityConflict);
                }
                if existing.source_revision == source.source_revision {
                    if !same_conversation_source_observation(existing, &source) {
                        return Err(RelationshipProjectionError::SourceRevisionConflict);
                    }
                    false
                } else if source_revision_order(&source.source_revision)
                    .zip(source_revision_order(&existing.source_revision))
                    .is_some_and(|(incoming, stored)| incoming <= stored)
                {
                    return Err(RelationshipProjectionError::StaleSourceRevision);
                } else {
                    let mut source = source;
                    source.revision = existing
                        .revision
                        .checked_add(1)
                        .ok_or(RelationshipProjectionError::RevisionOverflow)?;
                    self.conversation_sources[index] = source;
                    true
                }
            }
        };
        if changed {
            let now = self
                .conversation_sources
                .iter()
                .map(|entry| entry.observed_at)
                .max()
                .ok_or(RelationshipProjectionError::InvalidInboxProjection)?;
            self.bump_revision(now)?;
        }
        Ok(changed)
    }

    pub fn upsert_source_event(
        &mut self,
        event: RelationshipSourceEvent,
    ) -> Result<bool, RelationshipProjectionError> {
        event.validate()?;
        if event.tenant_id != self.tenant_id || event.project_id != self.project_id {
            return Err(RelationshipProjectionError::ScopeMismatch);
        }
        let observed_at = event.observed_at;
        let key = (
            event.source.key(),
            event.source.external_id.clone(),
            event.event_id.clone(),
            event.event_digest.clone(),
        );
        let changed = match self.source_events.iter().position(|existing| {
            (
                existing.source.key(),
                existing.source.external_id.clone(),
                existing.event_id.clone(),
                existing.event_digest.clone(),
            ) == key
        }) {
            None => {
                self.source_events.push(event);
                self.source_events.sort_by(|left, right| {
                    (
                        left.source.provider.as_str(),
                        left.source.account_id.as_str(),
                        left.source.stream,
                        left.source.external_id.as_str(),
                        left.event_id.as_str(),
                        left.event_digest.as_str(),
                    )
                        .cmp(&(
                            right.source.provider.as_str(),
                            right.source.account_id.as_str(),
                            right.source.stream,
                            right.source.external_id.as_str(),
                            right.event_id.as_str(),
                            right.event_digest.as_str(),
                        ))
                });
                true
            }
            Some(_) => false,
        };
        if changed {
            self.bump_revision(observed_at)?;
        }
        Ok(changed)
    }

    pub fn conversation_source(
        &self,
        provider: &str,
        account_id: &AccountId,
        external_id: &str,
    ) -> Option<&ConversationSourceProjection> {
        self.conversation_sources.iter().find(|source| {
            source.source.provider == provider
                && source.source.account_id == *account_id
                && source.source.external_id == external_id
        })
    }

    pub fn source_event(
        &self,
        source: &RelationshipSourceRef,
        event_id: &str,
        event_digest: &str,
    ) -> Option<&RelationshipSourceEvent> {
        self.source_events.iter().find(|event| {
            event.source.key() == source.key()
                && event.source.external_id == source.external_id
                && event.event_id == event_id
                && event.event_digest == event_digest
        })
    }

    pub fn upsert_source_cursor(
        &mut self,
        cursor: &RelationshipSourceCursor,
    ) -> Result<bool, RelationshipProjectionError> {
        cursor.validate()?;
        if cursor.tenant_id != self.tenant_id || cursor.project_id != self.project_id {
            return Err(RelationshipProjectionError::ScopeMismatch);
        }
        let changed = match self
            .source_cursors
            .iter()
            .position(|existing| existing.key() == cursor.key())
        {
            None => {
                self.source_cursors.push((*cursor).clone());
                self.source_cursors
                    .sort_by_key(RelationshipSourceCursor::key);
                true
            }
            Some(index) => {
                let existing = &self.source_cursors[index];
                if existing == cursor {
                    false
                } else {
                    cursor.follows(existing)?;
                    self.source_cursors[index] = cursor.clone();
                    true
                }
            }
        };
        if changed {
            self.bump_revision(cursor.observed_at)?;
        }
        Ok(changed)
    }

    pub fn source_cursor(
        &self,
        provider: &str,
        account_id: &AccountId,
        stream: RelationshipSourceStream,
    ) -> Option<&RelationshipSourceCursor> {
        self.source_cursors.iter().find(|cursor| {
            cursor.provider == provider
                && cursor.account_id == *account_id
                && cursor.stream == stream
        })
    }

    pub fn replace_source_cursors(
        &mut self,
        cursors: Vec<RelationshipSourceCursor>,
    ) -> Result<(), RelationshipProjectionError> {
        self.source_cursors = cursors;
        self.validate()
    }

    fn bump_revision(&mut self, now: DateTime<Utc>) -> Result<(), RelationshipProjectionError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(RelationshipProjectionError::RevisionOverflow)?;
        if now < self.updated_at {
            return Err(RelationshipProjectionError::NonMonotonicObservation);
        }
        self.updated_at = now;
        Ok(())
    }
}

pub fn relationship_source_scope_digest(
    tenant_id: &TenantId,
    project_id: &ProjectId,
    provider: &str,
    account_id: &AccountId,
    stream: RelationshipSourceStream,
) -> String {
    let canonical = format!(
        "{}\u{0}{}\u{0}{}\u{0}{}\u{0}{:?}",
        tenant_id.as_str(),
        project_id.as_str(),
        provider.trim(),
        account_id.as_str(),
        stream,
    );
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

pub fn canonical_relationship_id(
    tenant_id: &TenantId,
    project_id: &ProjectId,
    source: &RelationshipSourceRef,
) -> String {
    let scope = format!(
        "{}\u{0}{}\u{0}{}\u{0}{}\u{0}{:?}\u{0}{}",
        tenant_id.as_str(),
        project_id.as_str(),
        source.provider,
        source.account_id.as_str(),
        source.stream,
        source.external_id,
    );
    format!("relationship:{:x}", Sha256::digest(scope.as_bytes()))
}

pub fn canonical_conversation_id(
    tenant_id: &TenantId,
    project_id: &ProjectId,
    source: &RelationshipSourceRef,
) -> String {
    let scope = format!(
        "{}\u{0}{}\u{0}{}\u{0}{}\u{0}{:?}\u{0}{}",
        tenant_id.as_str(),
        project_id.as_str(),
        source.provider,
        source.account_id.as_str(),
        source.stream,
        source.external_id,
    );
    format!("conversation:{:x}", Sha256::digest(scope.as_bytes()))
}

pub fn digest_relationship_value(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.trim().as_bytes()))
}

#[derive(Debug, Error)]
pub enum RelationshipProjectionError {
    #[error("relationship source reference is incomplete")]
    InvalidSourceReference,
    #[error("relationship source cursor is invalid")]
    InvalidSourceCursor,
    #[error("canonical relationship record is invalid")]
    InvalidRelationshipRecord,
    #[error("conversation source projection is invalid")]
    InvalidConversationSource,
    #[error("relationship source event is invalid")]
    InvalidSourceEvent,
    #[error("Inbox item projection is invalid")]
    InvalidInboxItem,
    #[error("Inbox projection is invalid")]
    InvalidInboxProjection,
    #[error("relationship projection is outside the requested tenant/project scope")]
    ScopeMismatch,
    #[error("relationship source cursor is stale")]
    StaleSourceCursor,
    #[error("relationship source cursor conflicts with the stored position")]
    CursorConflict,
    #[error("relationship source observation moved backwards in time")]
    NonMonotonicObservation,
    #[error("canonical relationship identity conflicts with an existing source mapping")]
    CanonicalIdentityConflict,
    #[error("source revision contains different relationship data")]
    SourceRevisionConflict,
    #[error("relationship source revision is stale")]
    StaleSourceRevision,
    #[error("conversation could not be projected: {0}")]
    InvalidConversation(String),
    #[error("relationship projection revision overflowed")]
    RevisionOverflow,
}

fn unique_conversation_count(items: &[InboxItemProjection]) -> usize {
    items
        .iter()
        .map(|item| item.conversation_id.clone())
        .collect::<BTreeSet<_>>()
        .len()
}

fn same_relationship_observation(
    left: &CanonicalRelationshipRecord,
    right: &CanonicalRelationshipRecord,
) -> bool {
    left.canonical_id == right.canonical_id
        && left.source == right.source
        && left.source_revision == right.source_revision
        && left.display_name_digest == right.display_name_digest
        && left.value_digests == right.value_digests
        && left.deleted == right.deleted
}

fn same_conversation_source_observation(
    left: &ConversationSourceProjection,
    right: &ConversationSourceProjection,
) -> bool {
    left.tenant_id == right.tenant_id
        && left.project_id == right.project_id
        && left.conversation_id == right.conversation_id
        && left.person_id == right.person_id
        && left.source == right.source
        && left.source_revision == right.source_revision
        && left.source_revision_digest == right.source_revision_digest
        && left.source_state == right.source_state
        && left.archived == right.archived
        && left.deleted == right.deleted
        && left.latest_activity_at == right.latest_activity_at
        && left.latest_received_at == right.latest_received_at
        && left.latest_sent_at == right.latest_sent_at
}

fn unique_relationship_count(records: &[CanonicalRelationshipRecord]) -> usize {
    records
        .iter()
        .map(|record| (record.source.key(), record.source.external_id.clone()))
        .collect::<BTreeSet<_>>()
        .len()
}

fn unique_conversation_source_count(sources: &[ConversationSourceProjection]) -> usize {
    sources
        .iter()
        .map(|source| (source.source.key(), source.source.external_id.clone()))
        .collect::<BTreeSet<_>>()
        .len()
}

fn unique_cursor_count(cursors: &[RelationshipSourceCursor]) -> usize {
    cursors
        .iter()
        .map(RelationshipSourceCursor::key)
        .collect::<BTreeSet<_>>()
        .len()
}

fn unique_source_event_count(events: &[RelationshipSourceEvent]) -> usize {
    events
        .iter()
        .map(|event| {
            (
                event.source.key(),
                event.source.external_id.clone(),
                event.event_id.clone(),
                event.event_digest.clone(),
            )
        })
        .collect::<BTreeSet<_>>()
        .len()
}

fn is_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_LENGTH && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn source_revision_order(value: &str) -> Option<i128> {
    if let Ok(time) = DateTime::parse_from_rfc3339(value) {
        return Some(i128::from(time.timestamp_millis()));
    }
    if let Ok(number) = value.parse::<i128>() {
        return Some(number);
    }
    let digits = value
        .rsplit_once(|character: char| !character.is_ascii_digit())
        .map_or(value, |(_, digits)| digits);
    (!digits.is_empty())
        .then(|| digits.parse::<i128>().ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(second: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_760_000_000 + second, 0).expect("valid test time")
    }

    #[test]
    fn source_scope_and_canonical_identity_are_deterministic_and_account_scoped() {
        let tenant = TenantId::from("tenant-rel");
        let project = ProjectId::from("project-rel");
        let account = AccountId::from("hubspot-account");
        let source = RelationshipSourceRef {
            provider: "hubspot".into(),
            account_id: account.clone(),
            stream: RelationshipSourceStream::People,
            external_id: "contact-42".into(),
        };
        assert_eq!(
            canonical_relationship_id(&tenant, &project, &source),
            canonical_relationship_id(&tenant, &project, &source)
        );
        let other_account = RelationshipSourceRef {
            account_id: AccountId::from("other-hubspot-account"),
            ..source.clone()
        };
        assert_ne!(
            canonical_relationship_id(&tenant, &project, &source),
            canonical_relationship_id(&tenant, &project, &other_account)
        );
        assert_ne!(
            relationship_source_scope_digest(
                &tenant,
                &project,
                "hubspot",
                &account,
                RelationshipSourceStream::People
            ),
            relationship_source_scope_digest(
                &tenant,
                &project,
                "hubspot",
                &AccountId::from("other-hubspot-account"),
                RelationshipSourceStream::People
            )
        );
    }

    #[test]
    fn stale_source_cursor_is_rejected_without_rewinding_the_position() {
        let tenant = TenantId::from("tenant-rel");
        let project = ProjectId::from("project-rel");
        let account = AccountId::from("hubspot-account");
        let first = RelationshipSourceCursor::new(
            tenant.clone(),
            project.clone(),
            "hubspot",
            account.clone(),
            RelationshipSourceStream::People,
            Some("20".into()),
            1,
            2,
            at(1),
        )
        .expect("first cursor");
        let stale = RelationshipSourceCursor::new(
            tenant,
            project,
            "hubspot",
            account,
            RelationshipSourceStream::People,
            Some("0".into()),
            0,
            3,
            at(2),
        )
        .expect("stale cursor shape");
        assert!(matches!(
            stale.follows(&first),
            Err(RelationshipProjectionError::StaleSourceCursor)
        ));
    }
}
