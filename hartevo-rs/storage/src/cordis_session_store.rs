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
#[serde(rename_all = "snake_case")]
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
    UserMessage {
        message: serde_json::Value,
    },
    AssistantMessage {
        turn: u64,
        step: u64,
        message: serde_json::Value,
    },
    ToolResult {
        turn: u64,
        step: u64,
        message: serde_json::Value,
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
        let (turn, step) = match &event.kind {
            PersistedSessionEventKind::TurnStart { turn }
            | PersistedSessionEventKind::TurnEnd { turn, .. } => (Some(*turn), None),
            PersistedSessionEventKind::StepStart { turn, step }
            | PersistedSessionEventKind::StepEnd { turn, step } => (Some(*turn), Some(*step)),
            PersistedSessionEventKind::UserMessage { message } => {
                validate_message_json(message)?;
                (None, None)
            }
            PersistedSessionEventKind::AssistantMessage {
                turn,
                step,
                message,
            }
            | PersistedSessionEventKind::ToolResult {
                turn,
                step,
                message,
            } => {
                validate_message_json(message)?;
                (Some(*turn), Some(*step))
            }
        };
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

fn validate_message_json(message: &serde_json::Value) -> Result<(), StorageError> {
    if !message.is_object() {
        return Err(StorageError::InvalidSessionCheckpoint(
            "message payload must be a JSON object",
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
                },
            },
            PersistedSessionEvent {
                seq: 4,
                time_ms: 6,
                kind: PersistedSessionEventKind::ToolResult {
                    turn: 1,
                    step: 1,
                    message: tool_result_message(),
                },
            },
            PersistedSessionEvent {
                seq: 5,
                time_ms: 7,
                kind: PersistedSessionEventKind::StepEnd { turn: 1, step: 1 },
            },
            PersistedSessionEvent {
                seq: 6,
                time_ms: 8,
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
    fn divergent_prefix_is_rejected_without_mutation() {
        let mut store = ProjectStore::in_memory().unwrap();
        let complete = checkpoint(completed_turn());
        store.persist_session_checkpoint(&complete).unwrap();

        let mut divergent = complete.clone();
        divergent.events[6].kind = PersistedSessionEventKind::TurnEnd {
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
        let PersistedSessionEventKind::ToolResult { message, .. } = &mut invalid.events[4].kind
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
