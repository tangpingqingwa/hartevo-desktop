use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::mission_loop::{
    LoopCommand, LoopError, LoopMissionFacts, LoopPolicy, LoopReceipt, MissionLoop, loop_digest,
};
use hartevo_domain_kernel::{Mission, MissionConversationRole, MissionId, ProjectId};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::aggregate::append_events;
use crate::mission_conversation_store::load_mission_conversation_record;
use crate::normalized::load_mission_normalized;

#[cfg(test)]
#[path = "mission_loop_store_tests.rs"]
mod tests;
use crate::{PendingEvent, ProjectStore, StorageError};

const STATE_SQL: &str = "CREATE TABLE IF NOT EXISTS mission_loops (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    record_digest TEXT NOT NULL CHECK (length(record_digest) = 64),
    record_json TEXT NOT NULL CHECK (length(record_json) BETWEEN 2 AND 8388608),
    PRIMARY KEY (project_id, mission_id),
    FOREIGN KEY (mission_id, project_id) REFERENCES missions(id, project_id) ON DELETE CASCADE
)";

const OPERATIONS_SQL: &str = "CREATE TABLE IF NOT EXISTS mission_loop_operations (
    project_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    operation_digest TEXT NOT NULL CHECK (length(operation_digest) = 64),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
    receipt_digest TEXT NOT NULL CHECK (length(receipt_digest) = 64),
    receipt_json TEXT NOT NULL CHECK (length(receipt_json) BETWEEN 2 AND 1048576),
    revision INTEGER NOT NULL CHECK (revision > 1),
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (project_id, mission_id, operation_digest),
    UNIQUE (project_id, mission_id, revision),
    FOREIGN KEY (project_id, mission_id) REFERENCES mission_loops(project_id, mission_id) ON DELETE CASCADE
)";

pub(crate) fn install_schema(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch(STATE_SQL)?;
    connection.execute_batch(OPERATIONS_SQL)?;
    Ok(())
}

pub(crate) fn verify_schema(connection: &Connection) -> Result<(), StorageError> {
    for (name, expected) in [
        ("mission_loops", STATE_SQL),
        ("mission_loop_operations", OPERATIONS_SQL),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalize_sql) != Some(normalize_sql(expected)) {
            return Err(StorageError::DomainDecode(
                "Mission loop schema v52 is missing or changed".into(),
            ));
        }
    }
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("CREATE TABLE IF NOT EXISTS", "CREATE TABLE")
}

/// An internally consistent read of Mission, loop and the user-message fence.
/// Private titles, goals and questions must not enter Debug or public outbox.
#[derive(Clone)]
pub struct MissionLoopSnapshot {
    pub mission: Mission,
    pub state: MissionLoop,
    pub steering_digest: String,
}

impl fmt::Debug for MissionLoopSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MissionLoopSnapshot")
            .field("revision", &self.state.revision())
            .finish_non_exhaustive()
    }
}

impl MissionLoopSnapshot {
    pub fn facts(&self) -> LoopMissionFacts<'_> {
        LoopMissionFacts {
            mission: &self.mission,
            steering_digest: &self.steering_digest,
        }
    }
}

impl ProjectStore {
    pub fn mission_loop_accounting(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<Option<hartevo_domain_kernel::mission_loop::LoopAccounting>, StorageError> {
        let transaction = self.connection.unchecked_transaction()?;
        let mission = load_mission(&transaction, project_id, mission_id)?;
        let accounting = load_state(&transaction, &mission)?.map(|state| state.accounting());
        transaction.commit()?;
        Ok(accounting)
    }

    /// Opt-in initialization never overwrites an existing loop or quota ledger.
    pub fn create_mission_loop(
        &mut self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        policy: LoopPolicy,
        expected_mission_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<MissionLoop, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mission = load_mission(&transaction, project_id, mission_id)?;
        if let Some(existing) = load_state(&transaction, &mission)? {
            if existing.policy() != &policy {
                return Err(StorageError::MissionLoopReplayConflict);
            }
            return Ok(existing);
        }
        if mission.revision != expected_mission_revision {
            return Err(LoopError::RevisionConflict.into());
        }
        let state = MissionLoop::new(&mission, policy, now)?;
        let record_digest = loop_digest(&state)?;
        transaction.execute("INSERT INTO mission_loops (tenant_id, project_id, mission_id, revision, record_digest, record_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![mission.tenant_id.as_str(), project_id.as_str(), mission_id.as_str(), sql_revision(state.revision())?, record_digest, serde_json::to_string(&state)?])?;
        append_events(
            &transaction,
            mission.tenant_id.as_str(),
            project_id.as_str(),
            Some(mission_id.as_str()),
            "mission_loop",
            mission_id.as_str(),
            &[PendingEvent::new(
                "mission.loop.created",
                serde_json::json!({"revision": state.revision(), "stateDigest": record_digest}),
                now,
            )],
        )?;
        transaction.commit()?;
        Ok(state)
    }

    pub fn mission_loop_snapshot(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> Result<Option<MissionLoopSnapshot>, StorageError> {
        let transaction = self.connection.unchecked_transaction()?;
        let snapshot = load_snapshot(&transaction, project_id, mission_id, now)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    /// Claims, evidence acceptance, quota spend, compact history, operation
    /// receipt and public-safe Event/Outbox append share one SQLCipher commit.
    pub fn apply_mission_loop_command(
        &mut self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        command: &LoopCommand,
        now: DateTime<Utc>,
    ) -> Result<LoopReceipt, StorageError> {
        let request_digest = loop_digest(command)?;
        let operation_digest = loop_digest(&command.operation_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut snapshot = load_snapshot(&transaction, project_id, mission_id, now)?
            .ok_or_else(|| missing("mission_loop", project_id, mission_id))?;
        // Retry of a committed operation is read-only even if its original
        // revision/lease is now stale. Reuse with changed arguments is rejected.
        if let Some(receipt) = replay(
            &transaction,
            project_id,
            mission_id,
            &operation_digest,
            &request_digest,
        )? {
            return Ok(receipt);
        }
        let facts = LoopMissionFacts {
            mission: &snapshot.mission,
            steering_digest: &snapshot.steering_digest,
        };
        let receipt = snapshot.state.apply(facts, command, now)?;
        let state_digest = loop_digest(&snapshot.state)?;
        let receipt_digest = loop_digest(&receipt)?;
        let changed = transaction.execute("UPDATE mission_loops SET revision = ?1, record_digest = ?2, record_json = ?3 WHERE project_id = ?4 AND mission_id = ?5 AND revision = ?6",
            params![sql_revision(snapshot.state.revision())?, state_digest, serde_json::to_string(&snapshot.state)?, project_id.as_str(), mission_id.as_str(), sql_revision(command.expected_revision)?])?;
        if changed != 1 {
            return Err(LoopError::RevisionConflict.into());
        }
        transaction.execute("INSERT INTO mission_loop_operations (project_id, mission_id, operation_digest, request_digest, receipt_digest, receipt_json, revision, recorded_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![project_id.as_str(), mission_id.as_str(), operation_digest, request_digest, receipt_digest, serde_json::to_string(&receipt)?, sql_revision(receipt.revision)?, now.to_rfc3339()])?;
        let action = serde_json::to_value(&command.action)?;
        append_events(
            &transaction,
            snapshot.mission.tenant_id.as_str(),
            project_id.as_str(),
            Some(mission_id.as_str()),
            "mission_loop",
            mission_id.as_str(),
            &[PendingEvent::new(
                "mission.loop.changed",
                serde_json::json!({
                    "action": action.get("kind"), "revision": receipt.revision,
                    "operationDigest": operation_digest, "requestDigest": request_digest,
                    "stateDigest": state_digest, "receiptDigest": receipt_digest,
                    "spentSlots": snapshot.state.spent_slots()
                }),
                now,
            )],
        )?;
        transaction.commit()?;
        Ok(receipt)
    }
}

fn replay(
    connection: &Connection,
    project: &ProjectId,
    mission: &MissionId,
    operation: &str,
    request: &str,
) -> Result<Option<LoopReceipt>, StorageError> {
    let row = connection.query_row("SELECT request_digest, receipt_digest, receipt_json, revision FROM mission_loop_operations WHERE project_id = ?1 AND mission_id = ?2 AND operation_digest = ?3",
        params![project.as_str(), mission.as_str(), operation], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?))).optional()?;
    let Some((stored_request, stored_digest, json, revision)) = row else {
        return Ok(None);
    };
    if stored_request != request {
        return Err(StorageError::MissionLoopReplayConflict);
    }
    let mut receipt: LoopReceipt = serde_json::from_str(&json)?;
    if loop_digest(&receipt)? != stored_digest
        || sql_revision(receipt.revision)? != revision
        || receipt.replayed
    {
        return Err(LoopError::InvalidState.into());
    }
    receipt.replayed = true;
    Ok(Some(receipt))
}

fn load_snapshot(
    connection: &Connection,
    project: &ProjectId,
    mission: &MissionId,
    now: DateTime<Utc>,
) -> Result<Option<MissionLoopSnapshot>, StorageError> {
    let mission = load_mission(connection, project, mission)?;
    let Some(state) = load_state(connection, &mission)? else {
        return Ok(None);
    };
    let conversation = load_mission_conversation_record(connection, project, &mission.id)?;
    let steering_digest = if let Some(conversation) = conversation {
        conversation.validate_for(&mission, now)?;
        loop_digest(
            &conversation
                .messages
                .iter()
                .filter(|message| message.role == MissionConversationRole::User)
                .map(|message| (&message.id, message.sequence, &message.content_digest))
                .collect::<Vec<_>>(),
        )?
    } else if mission.definition.is_some() {
        return Err(LoopError::InvalidState.into());
    } else {
        loop_digest(&("legacy_mission_without_conversation", &mission.id))?
    };
    Ok(Some(MissionLoopSnapshot {
        mission,
        state,
        steering_digest,
    }))
}

fn load_state(
    connection: &Connection,
    mission: &Mission,
) -> Result<Option<MissionLoop>, StorageError> {
    let row = connection.query_row("SELECT tenant_id, revision, record_digest, record_json FROM mission_loops WHERE project_id = ?1 AND mission_id = ?2",
        params![mission.project_id.as_str(), mission.id.as_str()], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?))).optional()?;
    let Some((tenant, revision, stored_digest, json)) = row else {
        return Ok(None);
    };
    let state: MissionLoop = serde_json::from_str(&json)?;
    state.validate_for(mission)?;
    if tenant != mission.tenant_id.as_str()
        || sql_revision(state.revision())? != revision
        || loop_digest(&state)? != stored_digest
    {
        return Err(LoopError::InvalidState.into());
    }
    Ok(Some(state))
}

fn load_mission(
    connection: &Connection,
    project: &ProjectId,
    mission: &MissionId,
) -> Result<Mission, StorageError> {
    load_mission_normalized(connection, project, mission)?
        .ok_or_else(|| missing("mission", project, mission))
}

fn sql_revision(value: u64) -> Result<i64, LoopError> {
    i64::try_from(value).map_err(|_| LoopError::Overflow)
}

fn missing(kind: &'static str, project: &ProjectId, mission: &MissionId) -> StorageError {
    StorageError::ScopedRecordNotFound {
        kind,
        project_id: project.clone(),
        id: mission.to_string(),
    }
}
