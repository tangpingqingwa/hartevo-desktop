//! Durable Cordis Session checkpoints in the private SQLCipher database.
//!
//! Storage owns neutral rows and never depends on `hartevo-cordis`. Desktop
//! converts the live typed Session boundary to these records after SQLCipher
//! unlock. Writes extend an exact immutable prefix; they never replace one.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::{ProjectStore, StorageError};

const SESSION_HEADER_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS cordis_session_headers (
  id TEXT PRIMARY KEY CHECK (length(id) > 0),
  format_version INTEGER NOT NULL CHECK (
    format_version >= 0 AND format_version <= 4294967295
  ),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  parent_session_id TEXT CHECK (
    parent_session_id IS NULL OR length(parent_session_id) > 0
  ),
  seed_length INTEGER CHECK (seed_length IS NULL OR seed_length >= 0),
  event_count INTEGER NOT NULL CHECK (event_count >= 0),
  revision INTEGER NOT NULL CHECK (revision > 0),
  CHECK (seed_length IS NULL OR seed_length <= event_count)
)";

const SESSION_EVENT_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS cordis_session_events (
  session_id TEXT NOT NULL,
  seq INTEGER NOT NULL CHECK (seq >= 0),
  event_json TEXT NOT NULL CHECK (length(trim(event_json)) > 2),
  PRIMARY KEY (session_id, seq),
  FOREIGN KEY (session_id) REFERENCES cordis_session_headers(id) ON DELETE CASCADE
)";

pub(crate) fn install_cordis_session_schema(
    transaction: &Transaction<'_>,
) -> Result<(), StorageError> {
    transaction.execute_batch(SESSION_HEADER_TABLE_SQL)?;
    transaction.execute_batch(SESSION_EVENT_TABLE_SQL)?;
    Ok(())
}

pub(crate) fn verify_cordis_session_schema(connection: &Connection) -> Result<(), StorageError> {
    for (name, expected) in [
        ("cordis_session_headers", SESSION_HEADER_TABLE_SQL),
        ("cordis_session_events", SESSION_EVENT_TABLE_SQL),
    ] {
        let actual = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [name],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                StorageError::DomainDecode(format!("Cordis Session v49 table {name} is missing"))
            })?;
        if normalize_schema_sql(&actual) != normalize_schema_sql(expected) {
            return Err(StorageError::DomainDecode(format!(
                "Cordis Session v49 table {name} does not match"
            )));
        }
    }
    Ok(())
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("CREATE TABLE IF NOT EXISTS", "CREATE TABLE")
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistedSessionCancelCause {
    User,
    Parent,
    Hook,
    Disposed,
    Legacy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PersistedAgentInboxTarget {
    NextTurn,
    NextStep,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistedAgentInboxOutcome {
    Canceled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistedTurnEndReason {
    Completed,
    Aborted(PersistedSessionCancelCause),
    Blocked,
    Error,
    MaxTokens,
    Interrupted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersistedSessionToolError {
    pub name: String,
    pub code: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PersistedSessionEventKind {
    TurnStart {
        turn: u64,
    },
    TurnEnd {
        turn: u64,
        reason: PersistedTurnEndReason,
    },
    StepStart {
        turn: u64,
        step: u64,
    },
    StepEnd {
        turn: u64,
        step: u64,
    },
    AgentInboxSpliced {
        target: PersistedAgentInboxTarget,
        start: u64,
        #[serde(
            rename = "removedCount",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        removed_count: Option<u64>,
        inserted: Vec<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        outcome: Option<PersistedAgentInboxOutcome>,
    },
    UserMessage {
        message: serde_json::Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        surface: Option<serde_json::Value>,
    },
    AssistantChunk {
        turn: u64,
        step: u64,
        chunk: serde_json::Value,
    },
    RequestHeader {
        request: serde_json::Value,
    },
    RequestContext {
        context: serde_json::Value,
    },
    ToolCall {
        turn: u64,
        step: u64,
        #[serde(rename = "callId")]
        call_id: String,
        name: String,
        arguments: String,
    },
    AssistantMessage {
        turn: u64,
        step: u64,
        message: serde_json::Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        surface: Option<serde_json::Value>,
    },
    ToolResult {
        turn: u64,
        step: u64,
        message: serde_json::Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<PersistedSessionToolError>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        surface: Option<serde_json::Value>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersistedSessionEvent {
    pub seq: u64,
    pub time_ms: i64,
    pub kind: PersistedSessionEventKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedSessionHeader {
    pub version: u32,
    pub id: String,
    pub created_at_ms: i64,
    pub parent_session: Option<String>,
    pub seed_length: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedSessionCheckpoint {
    pub header: PersistedSessionHeader,
    pub events: Vec<PersistedSessionEvent>,
}

impl ProjectStore {
    /// Durably extend one exact Session prefix in a single SQLCipher transaction.
    ///
    /// Returns `true` when the durable prefix advanced or the header was first
    /// materialized, and `false` for an exact idempotent retry.
    pub fn persist_session_checkpoint(
        &mut self,
        checkpoint: &PersistedSessionCheckpoint,
    ) -> Result<bool, StorageError> {
        validate_checkpoint(checkpoint)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing_header = load_header(&transaction, &checkpoint.header.id)?;
        let (inserted_header, expected_stored_count) = if let Some((header, event_count)) =
            existing_header
        {
            if header != checkpoint.header {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "Cordis Session header",
                    id: checkpoint.header.id.clone(),
                });
            }
            let expected_count = usize::try_from(event_count).map_err(|_| {
                StorageError::DomainDecode("Cordis Session event count does not fit memory".into())
            })?;
            if expected_count > checkpoint.events.len() {
                return Err(StorageError::InvalidSessionCheckpoint(
                    "checkpoint is behind the durable prefix",
                ));
            }
            (false, expected_count)
        } else {
            insert_header(&transaction, checkpoint)?;
            (true, 0)
        };

        let stored_events = load_events(&transaction, &checkpoint.header.id)?;
        if stored_events.len() != expected_stored_count {
            return Err(StorageError::DomainDecode(format!(
                "Cordis Session {} event count does not match its rows",
                checkpoint.header.id
            )));
        }
        if !checkpoint.events.starts_with(&stored_events) {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "Cordis Session event prefix",
                id: checkpoint.header.id.clone(),
            });
        }
        if stored_events.len() == checkpoint.events.len() {
            transaction.commit()?;
            return Ok(inserted_header);
        }

        {
            let mut statement = transaction.prepare(
                "INSERT INTO cordis_session_events (session_id, seq, event_json)
                 VALUES (?1, ?2, ?3)",
            )?;
            for event in &checkpoint.events[stored_events.len()..] {
                statement.execute(params![
                    checkpoint.header.id,
                    sqlite_u64(event.seq, "event sequence")?,
                    serde_json::to_string(event)?,
                ])?;
            }
        }
        if !inserted_header {
            transaction.execute(
                "UPDATE cordis_session_headers
                 SET event_count = ?2, revision = revision + 1
                 WHERE id = ?1",
                params![
                    checkpoint.header.id,
                    sqlite_usize(checkpoint.events.len(), "event count")?
                ],
            )?;
        }
        transaction.commit()?;
        Ok(true)
    }

    /// Read every durable Session checkpoint without repairing or executing it.
    pub fn load_session_checkpoints(
        &self,
    ) -> Result<Vec<PersistedSessionCheckpoint>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT format_version, id, created_at_ms, parent_session_id,
                    seed_length, event_count
             FROM cordis_session_headers
             ORDER BY created_at_ms, id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;
        let mut checkpoints = Vec::new();
        for row in rows {
            let (version, id, created_at_ms, parent_session, seed_length, event_count) = row?;
            let header = decode_header(version, id, created_at_ms, parent_session, seed_length)?;
            let events = load_events(&self.connection, &header.id)?;
            let expected_count = usize::try_from(event_count).map_err(|_| {
                StorageError::DomainDecode("Cordis Session event count does not fit memory".into())
            })?;
            if events.len() != expected_count {
                return Err(StorageError::DomainDecode(format!(
                    "Cordis Session {} event count does not match its rows",
                    header.id
                )));
            }
            let checkpoint = PersistedSessionCheckpoint { header, events };
            validate_checkpoint(&checkpoint)?;
            checkpoints.push(checkpoint);
        }
        Ok(checkpoints)
    }
}

fn validate_checkpoint(checkpoint: &PersistedSessionCheckpoint) -> Result<(), StorageError> {
    if checkpoint.header.id.is_empty() {
        return Err(StorageError::InvalidSessionCheckpoint(
            "session id must not be empty",
        ));
    }
    if checkpoint.header.created_at_ms < 0 {
        return Err(StorageError::InvalidSessionCheckpoint(
            "created_at_ms must be non-negative",
        ));
    }
    if checkpoint
        .header
        .parent_session
        .as_ref()
        .is_some_and(String::is_empty)
    {
        return Err(StorageError::InvalidSessionCheckpoint(
            "parent session id must not be empty",
        ));
    }
    if checkpoint.header.seed_length.is_some_and(|seed_length| {
        usize::try_from(seed_length).map_or(true, |seed| seed > checkpoint.events.len())
    }) {
        return Err(StorageError::InvalidSessionCheckpoint(
            "seed length exceeds the event log",
        ));
    }
    for (expected, event) in checkpoint.events.iter().enumerate() {
        if event.seq
            != u64::try_from(expected).map_err(|_| {
                StorageError::InvalidSessionCheckpoint("event sequence does not fit u64")
            })?
        {
            return Err(StorageError::InvalidSessionCheckpoint(
                "event sequence is not contiguous",
            ));
        }
        if event.time_ms < 0 {
            return Err(StorageError::InvalidSessionCheckpoint(
                "event time must be non-negative",
            ));
        }
        let (turn, step) = validate_event_payload(&event.kind)?;
        if turn == Some(0) || step == Some(0) {
            return Err(StorageError::InvalidSessionCheckpoint(
                "turn and step numbers must be positive",
            ));
        }
        sqlite_u64(event.seq, "event sequence")?;
        if let Some(turn) = turn {
            sqlite_u64(turn, "turn")?;
        }
        if let Some(step) = step {
            sqlite_u64(step, "step")?;
        }
    }
    sqlite_usize(checkpoint.events.len(), "event count")?;
    Ok(())
}

fn validate_event_payload(
    kind: &PersistedSessionEventKind,
) -> Result<(Option<u64>, Option<u64>), StorageError> {
    Ok(match kind {
        PersistedSessionEventKind::TurnStart { turn }
        | PersistedSessionEventKind::TurnEnd { turn, .. } => (Some(*turn), None),
        PersistedSessionEventKind::StepStart { turn, step }
        | PersistedSessionEventKind::StepEnd { turn, step } => (Some(*turn), Some(*step)),
        PersistedSessionEventKind::AgentInboxSpliced {
            start,
            removed_count,
            inserted,
            outcome,
            ..
        } => {
            if *removed_count == Some(0) {
                return Err(StorageError::InvalidSessionCheckpoint(
                    "agent inbox zero removed count must be omitted",
                ));
            }
            if removed_count.is_none() && inserted.is_empty() {
                return Err(StorageError::InvalidSessionCheckpoint(
                    "agent inbox splice must insert or remove",
                ));
            }
            if outcome.is_some() && removed_count.is_none() {
                return Err(StorageError::InvalidSessionCheckpoint(
                    "agent inbox cancellation outcome requires a removal",
                ));
            }
            sqlite_u64(*start, "agent inbox splice start")?;
            if let Some(removed_count) = removed_count {
                sqlite_u64(*removed_count, "agent inbox removed count")?;
            }
            for message in inserted {
                validate_message_json(message)?;
            }
            (None, None)
        }
        PersistedSessionEventKind::UserMessage { message, surface } => {
            validate_message_json(message)?;
            validate_surface_json(surface.as_ref())?;
            (None, None)
        }
        PersistedSessionEventKind::AssistantChunk { turn, step, chunk } => {
            validate_chunk_json(chunk)?;
            (Some(*turn), Some(*step))
        }
        PersistedSessionEventKind::RequestHeader { request } => {
            validate_request_json(request, "request/header payload must be a JSON object")?;
            (None, None)
        }
        PersistedSessionEventKind::RequestContext { context } => {
            validate_request_json(context, "request/context payload must be a JSON object")?;
            (None, None)
        }
        PersistedSessionEventKind::ToolCall {
            turn,
            step,
            call_id,
            name,
            ..
        } => {
            if call_id.is_empty() || name.is_empty() {
                return Err(StorageError::InvalidSessionCheckpoint(
                    "tool/call id and name must not be empty",
                ));
            }
            (Some(*turn), Some(*step))
        }
        PersistedSessionEventKind::AssistantMessage {
            turn,
            step,
            message,
            surface,
        } => {
            validate_message_json(message)?;
            validate_surface_json(surface.as_ref())?;
            (Some(*turn), Some(*step))
        }
        PersistedSessionEventKind::ToolResult {
            turn,
            step,
            message,
            error,
            surface,
        } => {
            validate_message_json(message)?;
            if error
                .as_ref()
                .is_some_and(|error| error.name.is_empty() || error.code.is_empty())
            {
                return Err(StorageError::InvalidSessionCheckpoint(
                    "tool/result error name and code must not be empty",
                ));
            }
            validate_surface_json(surface.as_ref())?;
            (Some(*turn), Some(*step))
        }
    })
}

fn validate_message_json(message: &serde_json::Value) -> Result<(), StorageError> {
    if !message.is_object() {
        return Err(StorageError::InvalidSessionCheckpoint(
            "message payload must be a JSON object",
        ));
    }
    Ok(())
}

fn validate_chunk_json(chunk: &serde_json::Value) -> Result<(), StorageError> {
    if !chunk.is_object() {
        return Err(StorageError::InvalidSessionCheckpoint(
            "assistant chunk payload must be a JSON object",
        ));
    }
    Ok(())
}

fn validate_request_json(
    request: &serde_json::Value,
    expected: &'static str,
) -> Result<(), StorageError> {
    if !request.is_object() {
        return Err(StorageError::InvalidSessionCheckpoint(expected));
    }
    Ok(())
}

fn validate_surface_json(surface: Option<&serde_json::Value>) -> Result<(), StorageError> {
    if surface.is_some_and(|value| !value.is_object()) {
        return Err(StorageError::InvalidSessionCheckpoint(
            "surface metadata must be a JSON object",
        ));
    }
    Ok(())
}

fn insert_header(
    transaction: &Transaction<'_>,
    checkpoint: &PersistedSessionCheckpoint,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO cordis_session_headers (
           id, format_version, created_at_ms, parent_session_id,
           seed_length, event_count, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
        params![
            checkpoint.header.id,
            i64::from(checkpoint.header.version),
            checkpoint.header.created_at_ms,
            checkpoint.header.parent_session,
            checkpoint
                .header
                .seed_length
                .map(|length| sqlite_u64(length, "seed length"))
                .transpose()?,
            sqlite_usize(checkpoint.events.len(), "event count")?,
        ],
    )?;
    Ok(())
}

fn load_header(
    connection: &Connection,
    id: &str,
) -> Result<Option<(PersistedSessionHeader, i64)>, StorageError> {
    let row = connection
        .query_row(
            "SELECT format_version, id, created_at_ms, parent_session_id,
                    seed_length, event_count
             FROM cordis_session_headers WHERE id = ?1",
            [id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(version, id, created_at_ms, parent_session, seed_length, event_count)| {
            Ok((
                decode_header(version, id, created_at_ms, parent_session, seed_length)?,
                event_count,
            ))
        },
    )
    .transpose()
}

fn decode_header(
    version: i64,
    id: String,
    created_at_ms: i64,
    parent_session: Option<String>,
    seed_length: Option<i64>,
) -> Result<PersistedSessionHeader, StorageError> {
    Ok(PersistedSessionHeader {
        version: u32::try_from(version).map_err(|_| {
            StorageError::DomainDecode("Cordis Session format version is invalid".into())
        })?,
        id,
        created_at_ms,
        parent_session,
        seed_length: seed_length
            .map(|length| {
                u64::try_from(length).map_err(|_| {
                    StorageError::DomainDecode("Cordis Session seed length is invalid".into())
                })
            })
            .transpose()?,
    })
}

fn load_events(
    connection: &Connection,
    id: &str,
) -> Result<Vec<PersistedSessionEvent>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT seq, event_json
         FROM cordis_session_events
         WHERE session_id = ?1
         ORDER BY seq",
    )?;
    let rows = statement.query_map([id], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;
    rows.map(|row| {
        let (stored_seq, event_json) = row?;
        let stored_seq = u64::try_from(stored_seq).map_err(|_| {
            StorageError::DomainDecode("Cordis Session event sequence is invalid".into())
        })?;
        let event: PersistedSessionEvent = serde_json::from_str(&event_json)?;
        if event.seq != stored_seq {
            return Err(StorageError::DomainDecode(
                "Cordis Session event sequence does not match its row key".into(),
            ));
        }
        Ok(event)
    })
    .collect()
}

fn sqlite_u64(value: u64, field: &'static str) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::InvalidSessionCheckpoint(field))
}

fn sqlite_usize(value: usize, field: &'static str) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::InvalidSessionCheckpoint(field))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(events: Vec<PersistedSessionEvent>) -> PersistedSessionCheckpoint {
        PersistedSessionCheckpoint {
            header: PersistedSessionHeader {
                version: 0,
                id: "session-1".into(),
                created_at_ms: 1,
                parent_session: None,
                seed_length: None,
            },
            events,
        }
    }

    fn user_message() -> serde_json::Value {
        serde_json::json!({ "id": "user-1", "role": "user", "content": ["hello"] })
    }

    fn assistant_message() -> serde_json::Value {
        serde_json::json!({ "id": "assistant-1", "role": "assistant", "content": ["checking"] })
    }

    fn tool_result_message() -> serde_json::Value {
        serde_json::json!({ "id": "tool-1", "role": "user", "content": ["ok"] })
    }

    fn append_surface() -> serde_json::Value {
        serde_json::json!({ "surfaceOp": { "op": "append" } })
    }

    fn assistant_chunk() -> serde_json::Value {
        serde_json::json!({ "type": "text-delta", "index": 0, "text": "hello" })
    }

    fn request_header() -> serde_json::Value {
        serde_json::json!({
            "header": { "config": { "provider": "provider", "model": "model" } },
            "reason": "initial"
        })
    }

    fn request_context() -> serde_json::Value {
        serde_json::json!({
            "provider": "provider", "model": "model", "contextWindow": 32_768
        })
    }

    fn completed_turn() -> Vec<PersistedSessionEvent> {
        vec![
            PersistedSessionEvent {
                seq: 0,
                time_ms: 2,
                kind: PersistedSessionEventKind::TurnStart { turn: 1 },
            },
            PersistedSessionEvent {
                seq: 1,
                time_ms: 3,
                kind: PersistedSessionEventKind::UserMessage {
                    message: user_message(),
                    surface: Some(append_surface()),
                },
            },
            PersistedSessionEvent {
                seq: 2,
                time_ms: 4,
                kind: PersistedSessionEventKind::StepStart { turn: 1, step: 1 },
            },
            PersistedSessionEvent {
                seq: 3,
                time_ms: 5,
                kind: PersistedSessionEventKind::AssistantMessage {
                    turn: 1,
                    step: 1,
                    message: assistant_message(),
                    surface: Some(append_surface()),
                },
            },
            PersistedSessionEvent {
                seq: 4,
                time_ms: 6,
                kind: PersistedSessionEventKind::ToolCall {
                    turn: 1,
                    step: 1,
                    call_id: "call-1".into(),
                    name: "echo".into(),
                    arguments: "{}".into(),
                },
            },
            PersistedSessionEvent {
                seq: 5,
                time_ms: 7,
                kind: PersistedSessionEventKind::ToolResult {
                    turn: 1,
                    step: 1,
                    message: tool_result_message(),
                    error: None,
                    surface: Some(append_surface()),
                },
            },
            PersistedSessionEvent {
                seq: 6,
                time_ms: 8,
                kind: PersistedSessionEventKind::StepEnd { turn: 1, step: 1 },
            },
            PersistedSessionEvent {
                seq: 7,
                time_ms: 9,
                kind: PersistedSessionEventKind::TurnEnd {
                    turn: 1,
                    reason: PersistedTurnEndReason::Completed,
                },
            },
        ]
    }

    #[test]
    fn checkpoint_round_trips_and_extends_an_exact_prefix() {
        let mut store = ProjectStore::in_memory().unwrap();
        let empty = checkpoint(vec![]);
        assert!(store.persist_session_checkpoint(&empty).unwrap());
        assert!(!store.persist_session_checkpoint(&empty).unwrap());

        let complete = checkpoint(completed_turn());
        assert!(store.persist_session_checkpoint(&complete).unwrap());
        assert!(!store.persist_session_checkpoint(&complete).unwrap());
        assert_eq!(store.load_session_checkpoints().unwrap(), vec![complete]);
    }

    #[test]
    fn agent_inbox_splice_round_trips_with_exact_wire_fields() {
        let event = PersistedSessionEvent {
            seq: 0,
            time_ms: 1,
            kind: PersistedSessionEventKind::AgentInboxSpliced {
                target: PersistedAgentInboxTarget::NextTurn,
                start: 0,
                removed_count: None,
                inserted: vec![user_message()],
                outcome: None,
            },
        };
        let encoded = serde_json::to_value(&event).unwrap();
        let splice = &encoded["kind"]["agent_inbox_spliced"];
        assert_eq!(splice["target"], "next-turn");
        assert!(splice.get("removedCount").is_none());
        assert!(splice.get("removed_count").is_none());
        assert_eq!(
            serde_json::from_value::<PersistedSessionEvent>(encoded).unwrap(),
            event
        );

        let durable = checkpoint(vec![event]);
        let mut store = ProjectStore::in_memory().unwrap();
        assert!(store.persist_session_checkpoint(&durable).unwrap());
        assert_eq!(store.load_session_checkpoints().unwrap(), vec![durable]);
    }

    #[test]
    fn malformed_agent_inbox_splice_is_rejected_before_storage() {
        let cases = [
            (
                PersistedSessionEventKind::AgentInboxSpliced {
                    target: PersistedAgentInboxTarget::NextTurn,
                    start: 0,
                    removed_count: Some(0),
                    inserted: vec![user_message()],
                    outcome: None,
                },
                "agent inbox zero removed count must be omitted",
            ),
            (
                PersistedSessionEventKind::AgentInboxSpliced {
                    target: PersistedAgentInboxTarget::NextTurn,
                    start: 0,
                    removed_count: None,
                    inserted: vec![],
                    outcome: None,
                },
                "agent inbox splice must insert or remove",
            ),
            (
                PersistedSessionEventKind::AgentInboxSpliced {
                    target: PersistedAgentInboxTarget::NextTurn,
                    start: 0,
                    removed_count: None,
                    inserted: vec![user_message()],
                    outcome: Some(PersistedAgentInboxOutcome::Canceled),
                },
                "agent inbox cancellation outcome requires a removal",
            ),
            (
                PersistedSessionEventKind::AgentInboxSpliced {
                    target: PersistedAgentInboxTarget::NextTurn,
                    start: 0,
                    removed_count: None,
                    inserted: vec![serde_json::Value::Null],
                    outcome: None,
                },
                "message payload must be a JSON object",
            ),
        ];
        for (kind, expected) in cases {
            let mut store = ProjectStore::in_memory().unwrap();
            let invalid = checkpoint(vec![PersistedSessionEvent {
                seq: 0,
                time_ms: 1,
                kind,
            }]);
            assert!(matches!(
                store.persist_session_checkpoint(&invalid),
                Err(StorageError::InvalidSessionCheckpoint(actual)) if actual == expected
            ));
            assert!(store.load_session_checkpoints().unwrap().is_empty());
        }
    }

    #[test]
    fn divergent_prefix_is_rejected_without_mutation() {
        let mut store = ProjectStore::in_memory().unwrap();
        let complete = checkpoint(completed_turn());
        store.persist_session_checkpoint(&complete).unwrap();

        let mut divergent = complete.clone();
        divergent.events[7].kind = PersistedSessionEventKind::TurnEnd {
            turn: 1,
            reason: PersistedTurnEndReason::Error,
        };
        assert!(matches!(
            store.persist_session_checkpoint(&divergent),
            Err(StorageError::ImmutableRecordMismatch { .. })
        ));
        assert_eq!(store.load_session_checkpoints().unwrap(), vec![complete]);
    }

    #[test]
    fn malformed_message_checkpoint_is_rejected_before_storage() {
        let mut store = ProjectStore::in_memory().unwrap();
        let mut invalid = checkpoint(completed_turn());
        let PersistedSessionEventKind::ToolResult { message, .. } = &mut invalid.events[5].kind
        else {
            panic!("fixture must contain a tool result");
        };
        *message = serde_json::Value::Null;

        assert!(matches!(
            store.persist_session_checkpoint(&invalid),
            Err(StorageError::InvalidSessionCheckpoint(
                "message payload must be a JSON object"
            ))
        ));
        assert!(store.load_session_checkpoints().unwrap().is_empty());
    }

    #[test]
    fn tool_result_error_metadata_round_trips_and_legacy_rows_default_to_none() {
        let legacy = completed_turn()[5].clone();
        let legacy_json = serde_json::to_value(&legacy).unwrap();
        assert!(legacy_json["kind"]["tool_result"].get("error").is_none());
        assert_eq!(
            serde_json::from_value::<PersistedSessionEvent>(legacy_json).unwrap(),
            legacy
        );

        let mut complete = checkpoint(completed_turn());
        let PersistedSessionEventKind::ToolResult { error, .. } = &mut complete.events[5].kind
        else {
            panic!("fixture must contain a tool result");
        };
        *error = Some(PersistedSessionToolError {
            name: "ToolOutcomeUnknownError".into(),
            code: "TOOL_OUTCOME_UNKNOWN".into(),
        });
        let mut store = ProjectStore::in_memory().unwrap();
        assert!(store.persist_session_checkpoint(&complete).unwrap());
        assert_eq!(store.load_session_checkpoints().unwrap(), vec![complete]);

        for (name, code) in [("", "TOOL_OUTCOME_UNKNOWN"), ("ToolError", "")] {
            let mut invalid = checkpoint(completed_turn());
            let PersistedSessionEventKind::ToolResult { error, .. } = &mut invalid.events[5].kind
            else {
                panic!("fixture must contain a tool result");
            };
            *error = Some(PersistedSessionToolError {
                name: name.into(),
                code: code.into(),
            });
            let mut store = ProjectStore::in_memory().unwrap();
            assert!(matches!(
                store.persist_session_checkpoint(&invalid),
                Err(StorageError::InvalidSessionCheckpoint(
                    "tool/result error name and code must not be empty"
                ))
            ));
        }
    }

    #[test]
    fn malformed_tool_call_is_rejected_before_storage() {
        for (call_id, name) in [("", "echo"), ("call-1", "")] {
            let mut store = ProjectStore::in_memory().unwrap();
            let invalid = checkpoint(vec![PersistedSessionEvent {
                seq: 0,
                time_ms: 1,
                kind: PersistedSessionEventKind::ToolCall {
                    turn: 1,
                    step: 1,
                    call_id: call_id.into(),
                    name: name.into(),
                    arguments: "{raw".into(),
                },
            }]);
            assert!(matches!(
                store.persist_session_checkpoint(&invalid),
                Err(StorageError::InvalidSessionCheckpoint(
                    "tool/call id and name must not be empty"
                ))
            ));
            assert!(store.load_session_checkpoints().unwrap().is_empty());
        }
    }

    #[test]
    fn tool_call_uses_the_exact_external_call_id_shape() {
        let event = PersistedSessionEvent {
            seq: 0,
            time_ms: 1,
            kind: PersistedSessionEventKind::ToolCall {
                turn: 1,
                step: 1,
                call_id: "call-1".into(),
                name: "echo".into(),
                arguments: "{raw".into(),
            },
        };
        let encoded = serde_json::to_value(&event).unwrap();
        assert_eq!(encoded["kind"]["tool_call"]["callId"], "call-1");
        assert!(encoded["kind"]["tool_call"].get("call_id").is_none());
        assert_eq!(
            serde_json::from_value::<PersistedSessionEvent>(encoded).unwrap(),
            event
        );
    }

    #[test]
    fn assistant_chunk_round_trips_without_storage_interpretation() {
        let mut store = ProjectStore::in_memory().unwrap();
        let chunk = checkpoint(vec![PersistedSessionEvent {
            seq: 0,
            time_ms: 1,
            kind: PersistedSessionEventKind::AssistantChunk {
                turn: 1,
                step: 1,
                chunk: assistant_chunk(),
            },
        }]);

        assert!(store.persist_session_checkpoint(&chunk).unwrap());
        assert_eq!(store.load_session_checkpoints().unwrap(), vec![chunk]);
    }

    #[test]
    fn request_state_round_trips_without_storage_interpretation() {
        let mut store = ProjectStore::in_memory().unwrap();
        let request_state = checkpoint(vec![
            PersistedSessionEvent {
                seq: 0,
                time_ms: 1,
                kind: PersistedSessionEventKind::RequestHeader {
                    request: request_header(),
                },
            },
            PersistedSessionEvent {
                seq: 1,
                time_ms: 2,
                kind: PersistedSessionEventKind::RequestContext {
                    context: request_context(),
                },
            },
        ]);

        assert!(store.persist_session_checkpoint(&request_state).unwrap());
        assert_eq!(
            store.load_session_checkpoints().unwrap(),
            vec![request_state]
        );
    }

    #[test]
    fn malformed_request_state_is_rejected_before_storage() {
        for (kind, expected) in [
            (
                PersistedSessionEventKind::RequestHeader {
                    request: serde_json::Value::Null,
                },
                "request/header payload must be a JSON object",
            ),
            (
                PersistedSessionEventKind::RequestContext {
                    context: serde_json::json!([]),
                },
                "request/context payload must be a JSON object",
            ),
        ] {
            let mut store = ProjectStore::in_memory().unwrap();
            let invalid = checkpoint(vec![PersistedSessionEvent {
                seq: 0,
                time_ms: 1,
                kind,
            }]);
            assert!(matches!(
                store.persist_session_checkpoint(&invalid),
                Err(StorageError::InvalidSessionCheckpoint(actual)) if actual == expected
            ));
            assert!(store.load_session_checkpoints().unwrap().is_empty());
        }
    }

    #[test]
    fn malformed_assistant_chunk_is_rejected_before_storage() {
        let mut store = ProjectStore::in_memory().unwrap();
        let invalid = checkpoint(vec![PersistedSessionEvent {
            seq: 0,
            time_ms: 1,
            kind: PersistedSessionEventKind::AssistantChunk {
                turn: 1,
                step: 1,
                chunk: serde_json::Value::Null,
            },
        }]);

        assert!(matches!(
            store.persist_session_checkpoint(&invalid),
            Err(StorageError::InvalidSessionCheckpoint(
                "assistant chunk payload must be a JSON object"
            ))
        ));
        assert!(store.load_session_checkpoints().unwrap().is_empty());
    }

    #[test]
    fn malformed_surface_checkpoint_is_rejected_before_storage() {
        let mut store = ProjectStore::in_memory().unwrap();
        let mut invalid = checkpoint(completed_turn());
        let PersistedSessionEventKind::UserMessage { surface, .. } = &mut invalid.events[1].kind
        else {
            panic!("fixture must contain a user message");
        };
        *surface = Some(serde_json::Value::Null);

        assert!(matches!(
            store.persist_session_checkpoint(&invalid),
            Err(StorageError::InvalidSessionCheckpoint(
                "surface metadata must be a JSON object"
            ))
        ));
        assert!(store.load_session_checkpoints().unwrap().is_empty());
    }

    #[test]
    fn persisted_event_rejects_unknown_variant_fields() {
        let mut encoded = serde_json::to_value(&completed_turn()[1]).unwrap();
        encoded["kind"]["user_message"]["unknown"] = serde_json::Value::Bool(true);

        assert!(serde_json::from_value::<PersistedSessionEvent>(encoded).is_err());
    }

    #[test]
    fn migration_v49_installs_from_v48_and_rejects_schema_drift() {
        let mut store = ProjectStore::in_memory().unwrap();
        store
            .connection
            .execute_batch(
                "DROP TABLE cordis_session_events;
                 DROP TABLE cordis_session_headers;
                 DELETE FROM schema_migrations WHERE version >= 49;",
            )
            .unwrap();
        assert_eq!(store.schema_version().unwrap(), 48);

        store.migrate().unwrap();
        assert_eq!(
            store.schema_version().unwrap(),
            crate::STORAGE_SCHEMA_VERSION
        );
        verify_cordis_session_schema(&store.connection).unwrap();

        store
            .connection
            .execute_batch(
                "DROP TABLE cordis_session_events;
                 CREATE TABLE cordis_session_events (sentinel INTEGER NOT NULL);",
            )
            .unwrap();
        assert!(matches!(
            store.migrate(),
            Err(StorageError::DomainDecode(_))
        ));
    }
}
