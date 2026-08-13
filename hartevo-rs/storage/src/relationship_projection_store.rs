use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    CanonicalRelationshipRecord, Conversation, ConversationSourceProjection, InboxProjection,
    ProjectId, RelationshipProjectionError, RelationshipSourceCursor, RelationshipSourceEvent,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::aggregate::{PendingEvent, append_events};
use crate::{ProjectStore, StorageError};

impl ProjectStore {
    /// Reads the durable, content-free Inbox/relationship projection. A
    /// missing row is an empty projection in the exact Project scope; it is
    /// not a connected-provider claim.
    pub fn load_inbox_projection(
        &self,
        project_id: &ProjectId,
    ) -> Result<InboxProjection, StorageError> {
        load_inbox_projection_from_connection(&self.connection, project_id)
    }

    /// Applies one provider read page and its source cursor in one local
    /// transaction. The provider adapter supplies candidate records only; it
    /// cannot mutate Mission, Connection, or Effect state through this method.
    pub fn apply_relationship_source_page(
        &mut self,
        tenant_id: &hartevo_domain_kernel::TenantId,
        project_id: &ProjectId,
        relationships: &[CanonicalRelationshipRecord],
        cursor: &RelationshipSourceCursor,
        recorded_at: DateTime<Utc>,
    ) -> Result<InboxProjection, StorageError> {
        self.apply_relationship_source_batch(
            tenant_id,
            project_id,
            relationships,
            &[],
            std::slice::from_ref(cursor),
            recorded_at,
        )
    }

    /// Applies one or more provider read pages atomically. Each stream has its
    /// own pagination cursor, while the resulting Inbox projection has one
    /// durable revision.
    pub fn apply_relationship_source_batch(
        &mut self,
        tenant_id: &hartevo_domain_kernel::TenantId,
        project_id: &ProjectId,
        relationships: &[CanonicalRelationshipRecord],
        conversation_sources: &[ConversationSourceProjection],
        cursors: &[RelationshipSourceCursor],
        recorded_at: DateTime<Utc>,
    ) -> Result<InboxProjection, StorageError> {
        for cursor in cursors {
            cursor
                .validate()
                .map_err(|error| projection_error(&error))?;
            if &cursor.tenant_id != tenant_id || &cursor.project_id != project_id {
                return Err(StorageError::TenantScopeMismatch);
            }
        }
        if relationships
            .iter()
            .any(|record| record.validate().is_err())
            || conversation_sources.iter().any(|source| {
                source.validate().is_err()
                    || &source.tenant_id != tenant_id
                    || &source.project_id != project_id
            })
        {
            return Err(StorageError::TenantScopeMismatch);
        }
        let initial_observed_at = cursors
            .iter()
            .map(|cursor| cursor.observed_at)
            .chain(conversation_sources.iter().map(|source| source.observed_at))
            .max()
            .unwrap_or(recorded_at);
        let transaction = self.connection.transaction()?;
        ensure_project_scope(&transaction, tenant_id.as_str(), project_id.as_str())?;
        let mut projection =
            load_inbox_projection_from_transaction(&transaction, project_id, initial_observed_at)?;
        let mut changed = false;
        for relationship in relationships {
            changed |= projection
                .upsert_relationship(relationship.clone())
                .map_err(|error| projection_error(&error))?;
        }
        for conversation_source in conversation_sources {
            changed |= projection
                .upsert_conversation_source(conversation_source.clone())
                .map_err(|error| projection_error(&error))?;
        }
        for cursor in cursors {
            changed |= projection
                .upsert_source_cursor(cursor)
                .map_err(|error| projection_error(&error))?;
        }
        if changed {
            persist_inbox_projection(&transaction, &projection)?;
            append_events(
                &transaction,
                tenant_id.as_str(),
                project_id.as_str(),
                None,
                "inbox_projection",
                project_id.as_str(),
                &[PendingEvent::new(
                    "relationship.source_page_applied",
                    json!({
                        "streams": cursors.iter().map(|cursor| json!({
                            "provider": cursor.provider,
                            "accountId": cursor.account_id,
                            "stream": cursor.stream,
                            "scopeDigest": cursor.scope_digest,
                            "sourceRevision": cursor.source_revision,
                            "recordCount": relationships.len(),
                        })).collect::<Vec<_>>(),
                        "relationshipRecordCount": relationships.len(),
                        "conversationSourceCount": conversation_sources.len(),
                    }),
                    recorded_at,
                )],
            )?;
        }
        transaction.commit()?;
        Ok(projection)
    }

    /// Applies a verified webhook event and its freshly fetched source
    /// observation. The event ledger is durable and idempotent; a retry with
    /// the same event identity never re-applies a source revision.
    pub fn apply_relationship_source_event(
        &mut self,
        tenant_id: &hartevo_domain_kernel::TenantId,
        project_id: &ProjectId,
        event: &RelationshipSourceEvent,
        relationship: Option<&CanonicalRelationshipRecord>,
        conversation_source: Option<&ConversationSourceProjection>,
        recorded_at: DateTime<Utc>,
    ) -> Result<InboxProjection, StorageError> {
        event.validate().map_err(|error| projection_error(&error))?;
        if &event.tenant_id != tenant_id || &event.project_id != project_id {
            return Err(StorageError::TenantScopeMismatch);
        }
        if relationship.is_some_and(|record| {
            record.source.key() != event.source.key()
                || record.source.external_id != event.source.external_id
        }) || conversation_source.is_some_and(|source| {
            source.tenant_id != *tenant_id
                || source.project_id != *project_id
                || source.source.key() != event.source.key()
                || source.source.external_id != event.source.external_id
        }) {
            return Err(StorageError::TenantScopeMismatch);
        }
        if relationship.is_some_and(|record| record.validate().is_err())
            || conversation_source.is_some_and(|source| source.validate().is_err())
        {
            return Err(StorageError::TenantScopeMismatch);
        }
        let transaction = self.connection.transaction()?;
        ensure_project_scope(&transaction, tenant_id.as_str(), project_id.as_str())?;
        let mut projection =
            load_inbox_projection_from_transaction(&transaction, project_id, event.observed_at)?;
        if projection
            .source_event(&event.source, &event.event_id, &event.event_digest)
            .is_some()
        {
            transaction.commit()?;
            return Ok(projection);
        }
        let mut changed = false;
        if let Some(record) = relationship {
            changed |= projection
                .upsert_relationship(record.clone())
                .map_err(|error| projection_error(&error))?;
        }
        if let Some(source) = conversation_source {
            changed |= projection
                .upsert_conversation_source(source.clone())
                .map_err(|error| projection_error(&error))?;
        }
        changed |= projection
            .upsert_source_event(event.clone())
            .map_err(|error| projection_error(&error))?;
        if changed {
            persist_inbox_projection(&transaction, &projection)?;
            append_events(
                &transaction,
                tenant_id.as_str(),
                project_id.as_str(),
                None,
                "inbox_projection",
                project_id.as_str(),
                &[PendingEvent::new(
                    "relationship.source_event_applied",
                    json!({
                        "provider": event.source.provider,
                        "accountId": event.source.account_id,
                        "stream": event.source.stream,
                        "sourceId": event.source.external_id,
                        "eventId": event.event_id,
                        "eventDigest": event.event_digest,
                        "occurredAt": event.occurred_at,
                    }),
                    recorded_at,
                )],
            )?;
        }
        transaction.commit()?;
        Ok(projection)
    }
}

/// Keeps the Inbox projection in the same transaction as a Conversation
/// aggregate write. This is intentionally crate-visible: only storage
/// aggregate commands may call it.
pub(crate) fn upsert_inbox_projection_for_conversation(
    transaction: &Transaction<'_>,
    conversation: &Conversation,
) -> Result<(), StorageError> {
    let mut projection = load_inbox_projection_from_transaction(
        transaction,
        &conversation.project_id,
        conversation.updated_at,
    )?;
    if projection
        .upsert_conversation(conversation)
        .map_err(|error| projection_error(&error))?
    {
        persist_inbox_projection(transaction, &projection)?;
    }
    Ok(())
}

fn load_inbox_projection_from_connection(
    connection: &rusqlite::Connection,
    project_id: &ProjectId,
) -> Result<InboxProjection, StorageError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, record_json
             FROM inbox_projections
             WHERE project_id = ?1",
            [project_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((tenant_id, record_json)) = row {
        let projection: InboxProjection = decode_json(&record_json)?;
        if projection.tenant_id.as_str() != tenant_id || projection.project_id != *project_id {
            return Err(StorageError::TenantScopeMismatch);
        }
        projection
            .validate()
            .map_err(|error| projection_error(&error))?;
        Ok(projection)
    } else {
        let tenant_id = connection
            .query_row(
                "SELECT tenant_id FROM projects WHERE id = ?1",
                [project_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::ProjectNotFound(project_id.clone()))?;
        Ok(InboxProjection::empty(
            hartevo_domain_kernel::TenantId::from_stable(tenant_id),
            project_id.clone(),
            Utc::now(),
        ))
    }
}

fn load_inbox_projection_from_transaction(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    initial_observed_at: DateTime<Utc>,
) -> Result<InboxProjection, StorageError> {
    let row = transaction
        .query_row(
            "SELECT tenant_id, record_json
             FROM inbox_projections
             WHERE project_id = ?1",
            [project_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let mut projection = if let Some((tenant_id, record_json)) = row {
        let projection: InboxProjection = decode_json(&record_json)?;
        if projection.tenant_id.as_str() != tenant_id || projection.project_id != *project_id {
            return Err(StorageError::TenantScopeMismatch);
        }
        projection
    } else {
        let tenant_id = transaction
            .query_row(
                "SELECT tenant_id FROM projects WHERE id = ?1",
                [project_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::ProjectNotFound(project_id.clone()))?;
        InboxProjection::empty(
            hartevo_domain_kernel::TenantId::from_stable(tenant_id),
            project_id.clone(),
            initial_observed_at,
        )
    };
    let mut statement = transaction.prepare(
        "SELECT record_json
         FROM relationship_source_cursors
         WHERE project_id = ?1
         ORDER BY provider, account_id, stream",
    )?;
    let rows = statement.query_map([project_id.as_str()], |row| row.get::<_, String>(0))?;
    let cursors = rows
        .map(|row| decode_json(&row?))
        .collect::<Result<Vec<RelationshipSourceCursor>, StorageError>>()?;
    if !cursors.is_empty() {
        projection
            .replace_source_cursors(cursors)
            .map_err(|error| projection_error(&error))?;
    }
    projection
        .validate()
        .map_err(|error| projection_error(&error))?;
    Ok(projection)
}

fn persist_inbox_projection(
    transaction: &Transaction<'_>,
    projection: &InboxProjection,
) -> Result<(), StorageError> {
    projection
        .validate()
        .map_err(|error| projection_error(&error))?;
    let record_json = serde_json::to_string(projection)?;
    let updated = transaction.execute(
        "UPDATE inbox_projections
         SET tenant_id = ?2, revision = ?3, updated_at = ?4, record_json = ?5
         WHERE project_id = ?1",
        params![
            projection.project_id.as_str(),
            projection.tenant_id.as_str(),
            to_sql_u64(projection.revision)?,
            projection.updated_at.to_rfc3339(),
            record_json,
        ],
    )?;
    if updated == 0 {
        transaction.execute(
            "INSERT INTO inbox_projections
               (project_id, tenant_id, revision, updated_at, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                projection.project_id.as_str(),
                projection.tenant_id.as_str(),
                to_sql_u64(projection.revision)?,
                projection.updated_at.to_rfc3339(),
                serde_json::to_string(projection)?,
            ],
        )?;
    }
    transaction.execute(
        "DELETE FROM relationship_source_cursors WHERE project_id = ?1",
        [projection.project_id.as_str()],
    )?;
    for cursor in &projection.source_cursors {
        transaction.execute(
            "INSERT INTO relationship_source_cursors
               (project_id, tenant_id, provider, account_id, stream, scope_digest,
                position, source_revision, revision, observed_at, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                projection.project_id.as_str(),
                cursor.tenant_id.as_str(),
                cursor.provider,
                cursor.account_id.as_str(),
                stream_name(cursor.stream),
                cursor.scope_digest,
                cursor.position,
                to_sql_u64(cursor.source_revision)?,
                to_sql_u64(cursor.revision)?,
                cursor.observed_at.to_rfc3339(),
                serde_json::to_string(cursor)?,
            ],
        )?;
    }
    Ok(())
}

fn ensure_project_scope(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    project_id: &str,
) -> Result<(), StorageError> {
    let stored_tenant = transaction
        .query_row(
            "SELECT tenant_id FROM projects WHERE id = ?1",
            [project_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| StorageError::ProjectNotFound(ProjectId::from_stable(project_id)))?;
    if stored_tenant != tenant_id {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

fn stream_name(stream: hartevo_domain_kernel::RelationshipSourceStream) -> &'static str {
    match stream {
        hartevo_domain_kernel::RelationshipSourceStream::People => "people",
        hartevo_domain_kernel::RelationshipSourceStream::Companies => "companies",
        hartevo_domain_kernel::RelationshipSourceStream::Opportunities => "opportunities",
        hartevo_domain_kernel::RelationshipSourceStream::Conversations => "conversations",
    }
}

fn decode_json<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_str(value)?)
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn projection_error(error: &RelationshipProjectionError) -> StorageError {
    StorageError::DomainDecode(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::DateTime;
    use hartevo_domain_kernel::{
        ConversationId, ConversationSourceProjection, ConversationSourceState, Project, ProjectId,
        RelationshipSourceEvent, RelationshipSourceRef, RelationshipSourceStream, StorageMode,
        TenantId, canonical_conversation_id, canonical_relationship_id, digest_relationship_value,
        relationship_source_scope_digest,
    };

    use super::*;

    fn observed_at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_760_000_000, 0).expect("valid test time")
    }

    #[test]
    fn source_page_and_cursor_survive_a_durable_projection_reload() {
        let tenant_id = TenantId::from("tenant-projection");
        let project_id = ProjectId::from("project-projection");
        let account_id = hartevo_domain_kernel::AccountId::from("hubspot-account");
        let project = Project::create_local(
            tenant_id.clone(),
            project_id.clone(),
            "Projection project",
            "",
            "/tmp/hartevo-projection",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project).expect("save project");
        let source = RelationshipSourceRef {
            provider: "hubspot".into(),
            account_id: account_id.clone(),
            stream: RelationshipSourceStream::People,
            external_id: "contact-42".into(),
        };
        let record = CanonicalRelationshipRecord {
            canonical_id: canonical_relationship_id(&tenant_id, &project_id, &source),
            source,
            source_revision: "2026-08-13T00:00:00Z".into(),
            display_name_digest: digest_relationship_value("Ada Lovelace"),
            value_digests: BTreeSet::from([digest_relationship_value("private@example.test")]),
            deleted: false,
            observed_at: observed_at(),
            revision: 1,
        };
        let cursor = RelationshipSourceCursor::new(
            tenant_id.clone(),
            project_id.clone(),
            "hubspot",
            account_id,
            RelationshipSourceStream::People,
            Some("20".into()),
            1,
            1,
            observed_at(),
        )
        .expect("cursor");
        let applied = store
            .apply_relationship_source_page(
                &tenant_id,
                &project_id,
                &[record],
                &cursor,
                observed_at(),
            )
            .expect("apply source page");
        assert_eq!(applied.relationships.len(), 1);
        assert_eq!(applied.source_cursors.len(), 1);
        assert_eq!(
            applied.source_cursors[0].scope_digest,
            relationship_source_scope_digest(
                &tenant_id,
                &project_id,
                "hubspot",
                &hartevo_domain_kernel::AccountId::from("hubspot-account"),
                RelationshipSourceStream::People
            )
        );
        let reloaded = store
            .load_inbox_projection(&project_id)
            .expect("reload projection");
        assert_eq!(reloaded, applied);
        let serialized = serde_json::to_string(&reloaded).expect("serialize projection");
        assert!(!serialized.contains("private@example.test"));
        let duplicate = store
            .apply_relationship_source_page(
                &tenant_id,
                &project_id,
                &reloaded.relationships,
                &reloaded.source_cursors[0],
                observed_at(),
            )
            .expect("idempotent source page");
        assert_eq!(duplicate, reloaded);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the test covers durable page, cursor, webhook event, reload, and retry boundaries in one transaction-focused fixture"
    )]
    fn conversation_source_and_webhook_event_are_durable_and_idempotent() {
        let tenant_id = TenantId::from("tenant-conversation");
        let project_id = ProjectId::from("project-conversation");
        let account_id = hartevo_domain_kernel::AccountId::from("hubspot-account");
        let project = Project::create_local(
            tenant_id.clone(),
            project_id.clone(),
            "Conversation projection",
            "",
            "/tmp/hartevo-conversation-projection",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project).expect("save project");
        let source = RelationshipSourceRef {
            provider: "hubspot".into(),
            account_id: account_id.clone(),
            stream: RelationshipSourceStream::Conversations,
            external_id: "thread-42".into(),
        };
        let source_projection = ConversationSourceProjection {
            tenant_id: tenant_id.clone(),
            project_id: project_id.clone(),
            conversation_id: ConversationId::from_stable(canonical_conversation_id(
                &tenant_id,
                &project_id,
                &source,
            )),
            person_id: None,
            source: source.clone(),
            source_revision: "2026-08-13T00:00:00Z".into(),
            source_revision_digest: digest_relationship_value("thread-42:open"),
            source_state: ConversationSourceState::Open,
            archived: false,
            deleted: false,
            latest_activity_at: Some(observed_at()),
            latest_received_at: Some(observed_at()),
            latest_sent_at: None,
            observed_at: observed_at(),
            revision: 1,
        };
        let cursor = RelationshipSourceCursor::new(
            tenant_id.clone(),
            project_id.clone(),
            "hubspot",
            account_id.clone(),
            RelationshipSourceStream::Conversations,
            Some("thread-page-2".into()),
            1,
            1,
            observed_at(),
        )
        .expect("conversation cursor");
        let applied = store
            .apply_relationship_source_batch(
                &tenant_id,
                &project_id,
                &[],
                &[source_projection],
                &[cursor],
                observed_at(),
            )
            .expect("apply conversation page");
        assert_eq!(applied.conversation_sources.len(), 1);
        assert_eq!(applied.source_cursors.len(), 1);
        let event = RelationshipSourceEvent {
            tenant_id: tenant_id.clone(),
            project_id: project_id.clone(),
            source: source.clone(),
            event_id: "event-42".into(),
            event_digest: digest_relationship_value("event-42"),
            occurred_at: observed_at(),
            observed_at: observed_at(),
            revision: 1,
        };
        let updated_source = ConversationSourceProjection {
            source_revision: "2026-08-13T00:00:01Z".into(),
            source_revision_digest: digest_relationship_value("thread-42:closed"),
            source_state: ConversationSourceState::Closed,
            ..applied.conversation_sources[0].clone()
        };
        let updated = store
            .apply_relationship_source_event(
                &tenant_id,
                &project_id,
                &event,
                None,
                Some(&updated_source),
                observed_at(),
            )
            .expect("apply webhook event");
        let duplicate = store
            .apply_relationship_source_event(
                &tenant_id,
                &project_id,
                &event,
                None,
                Some(&updated_source),
                observed_at(),
            )
            .expect("idempotent webhook event");
        assert_eq!(updated, duplicate);
        assert_eq!(duplicate.source_events.len(), 1);
        assert_eq!(
            duplicate.conversation_sources[0].source_state,
            ConversationSourceState::Closed
        );
    }
}
