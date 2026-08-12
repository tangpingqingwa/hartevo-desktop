use std::collections::BTreeSet;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    Effect, Evidence, EvidenceId, Mission, MissionCheckpoint, MissionCheckpointCompletionPolicy,
    MissionCheckpointExecutor, MissionCheckpointRoute, MissionDefinition, MissionId, OperatingMode,
    Outcome, Project, ProjectDataCell, ProjectId, Task, TaskId, TenantId, WorkProduct,
    WorkProductId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{ProjectStore, StorageError};

pub(crate) fn insert_project_normalized(
    transaction: &Transaction<'_>,
    project: &Project,
) -> Result<(), StorageError> {
    let data_cell = project.data_cell.as_ref().map(enum_name).transpose()?;
    transaction.execute(
        "INSERT INTO projects
           (id, name, snapshot_json, revision, tenant_id, description, storage_mode, data_cell)
         VALUES (?1, ?2, '{}', ?3, ?4, ?5, ?6, ?7)",
        params![
            project.id.as_str(),
            project.name,
            to_sql_u64(project.revision)?,
            project.tenant_id.as_str(),
            project.description,
            enum_name(&project.storage_mode)?,
            data_cell,
        ],
    )?;
    replace_project_roots(transaction, project)
}

pub(crate) fn upsert_project_normalized(
    transaction: &Transaction<'_>,
    project: &Project,
) -> Result<(), StorageError> {
    let data_cell = project.data_cell.as_ref().map(enum_name).transpose()?;
    transaction.execute(
        "INSERT INTO projects
           (id, name, snapshot_json, revision, tenant_id, description, storage_mode, data_cell)
         VALUES (?1, ?2, '{}', ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(id) DO UPDATE SET
           name = excluded.name, snapshot_json = '{}', revision = excluded.revision,
           tenant_id = excluded.tenant_id, description = excluded.description,
           storage_mode = excluded.storage_mode, data_cell = excluded.data_cell",
        params![
            project.id.as_str(),
            project.name,
            to_sql_u64(project.revision)?,
            project.tenant_id.as_str(),
            project.description,
            enum_name(&project.storage_mode)?,
            data_cell,
        ],
    )?;
    replace_project_roots(transaction, project)
}

pub(crate) fn update_project_normalized_cas(
    transaction: &Transaction<'_>,
    project: &Project,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let data_cell = project.data_cell.as_ref().map(enum_name).transpose()?;
    let updated = transaction.execute(
        "UPDATE projects SET name = ?2, snapshot_json = '{}', revision = ?3,
           tenant_id = ?4, description = ?5, storage_mode = ?6, data_cell = ?7
         WHERE id = ?1 AND tenant_id = ?4 AND revision = ?8",
        params![
            project.id.as_str(),
            project.name,
            to_sql_u64(project.revision)?,
            project.tenant_id.as_str(),
            project.description,
            enum_name(&project.storage_mode)?,
            data_cell,
            to_sql_u64(expected_revision)?,
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("project:{}", project.id),
            expected_revision,
        });
    }
    replace_project_roots(transaction, project)
}

pub(crate) fn load_project_normalized(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Option<Project>, StorageError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, id, name, description, storage_mode, data_cell, revision
             FROM projects WHERE id = ?1",
            [project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let mut statement = connection.prepare(
        "SELECT root_path FROM project_workspace_roots
         WHERE project_id = ?1 ORDER BY ordinal ASC",
    )?;
    let workspace_roots = statement
        .query_map([project_id.as_str()], |row| row.get::<_, String>(0))?
        .map(|row| row.map(PathBuf::from))
        .collect::<Result<Vec<_>, _>>()?;
    if workspace_roots.is_empty() {
        return Ok(None);
    }
    Ok(Some(Project {
        tenant_id: TenantId::from_stable(row.0),
        id: ProjectId::from_stable(row.1),
        name: row.2,
        description: row.3,
        storage_mode: decode_enum(&row.4)?,
        data_cell: row
            .5
            .map(|value| decode_enum::<ProjectDataCell>(&value))
            .transpose()?,
        workspace_roots,
        revision: from_sql_u64(row.6, "project revision")?,
    }))
}

pub(crate) fn insert_mission_normalized(
    transaction: &Transaction<'_>,
    mission: &Mission,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO missions
           (id, project_id, title, stage, snapshot_json, revision, tenant_id)
         VALUES (?1, ?2, ?3, ?4, '{}', ?5, ?6)",
        params![
            mission.id.as_str(),
            mission.project_id.as_str(),
            mission.title,
            enum_name(&mission.stage)?,
            to_sql_u64(mission.revision)?,
            mission.tenant_id.as_str(),
        ],
    )?;
    replace_mission_children(transaction, mission)
}

pub(crate) fn upsert_mission_normalized(
    transaction: &Transaction<'_>,
    mission: &Mission,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO missions
           (id, project_id, title, stage, snapshot_json, revision, tenant_id)
         VALUES (?1, ?2, ?3, ?4, '{}', ?5, ?6)
         ON CONFLICT(id, project_id) DO UPDATE SET
           title = excluded.title, stage = excluded.stage, snapshot_json = '{}',
           revision = excluded.revision, tenant_id = excluded.tenant_id",
        params![
            mission.id.as_str(),
            mission.project_id.as_str(),
            mission.title,
            enum_name(&mission.stage)?,
            to_sql_u64(mission.revision)?,
            mission.tenant_id.as_str(),
        ],
    )?;
    replace_mission_children(transaction, mission)
}

pub(crate) fn update_mission_normalized_cas(
    transaction: &Transaction<'_>,
    mission: &Mission,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let updated = transaction.execute(
        "UPDATE missions SET title = ?3, stage = ?4, snapshot_json = '{}',
           revision = ?5, tenant_id = ?6
         WHERE id = ?1 AND project_id = ?2 AND tenant_id = ?6 AND revision = ?7",
        params![
            mission.id.as_str(),
            mission.project_id.as_str(),
            mission.title,
            enum_name(&mission.stage)?,
            to_sql_u64(mission.revision)?,
            mission.tenant_id.as_str(),
            to_sql_u64(expected_revision)?,
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("mission:{}", mission.id),
            expected_revision,
        });
    }
    replace_mission_children(transaction, mission)
}

pub(crate) fn load_mission_normalized(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<Option<Mission>, StorageError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, id, project_id, title, stage, revision
             FROM missions WHERE project_id = ?1 AND id = ?2",
            params![project_id.as_str(), mission_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let contract_json = connection
        .query_row(
            "SELECT contract_json FROM mission_contracts
             WHERE project_id = ?1 AND mission_id = ?2",
            params![project_id.as_str(), mission_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(contract_json) = contract_json else {
        return Ok(None);
    };
    let lifecycle = connection.query_row(
        "SELECT created_at, updated_at, block_json FROM mission_lifecycle
         WHERE project_id = ?1 AND mission_id = ?2",
        params![project_id.as_str(), mission_id.as_str()],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        },
    )?;
    let outcome_history = load_outcomes(connection, project_id, mission_id)?;
    let definition = load_mission_definition(connection, project_id, mission_id)?;
    let mission = Mission {
        tenant_id: TenantId::from_stable(row.0),
        id: MissionId::from_stable(row.1),
        project_id: ProjectId::from_stable(row.2),
        title: row.3,
        contract: decode_json(&contract_json)?,
        definition,
        stage: decode_enum(&row.4)?,
        tasks: load_tasks(connection, project_id, mission_id)?,
        evidence: load_evidence(connection, project_id, mission_id)?,
        work_products: load_work_products(connection, project_id, mission_id)?,
        effects: load_effects(connection, project_id, mission_id)?,
        outcome: outcome_history.last().cloned(),
        outcome_history,
        block: lifecycle.2.as_deref().map(decode_json).transpose()?,
        created_at: parse_time(&lifecycle.0)?,
        updated_at: parse_time(&lifecycle.1)?,
        revision: from_sql_u64(row.5, "mission revision")?,
    };
    if let Some(definition) = &mission.definition {
        definition
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        if definition.operating_mode != mission.contract.mode
            || definition.capability_ids != mission.contract.enabled_capabilities
            || !definition
                .capability_ids
                .is_disjoint(&mission.contract.forbidden_capabilities)
        {
            return Err(StorageError::DomainDecode(
                "Mission definition does not match the persisted Operating Contract".into(),
            ));
        }
        mission
            .validate_checkpoint_evidence_scope()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
    }
    Ok(Some(mission))
}

fn load_mission_definition(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<Option<MissionDefinition>, StorageError> {
    let header = connection
        .query_row(
            "SELECT manifest_id, manifest_version, catalog_digest, operating_mode, cycle
             FROM mission_definitions WHERE project_id = ?1 AND mission_id = ?2",
            params![project_id.as_str(), mission_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some(header) = header else {
        return Ok(None);
    };
    let manifest_version = u32::try_from(header.1).map_err(|_| {
        StorageError::DomainDecode(format!("invalid Mission manifest version: {}", header.1))
    })?;
    let checkpoints = load_mission_checkpoints(connection, project_id, mission_id)?;
    let definition = MissionDefinition {
        manifest_id: header.0,
        manifest_version,
        catalog_digest: header.2,
        operating_mode: decode_enum::<OperatingMode>(&header.3)?,
        capability_ids: load_definition_values(
            connection,
            "mission_definition_capabilities",
            project_id,
            mission_id,
        )?,
        required_artifact_types: load_definition_values(
            connection,
            "mission_definition_artifacts",
            project_id,
            mission_id,
        )?,
        oracle_ids: load_definition_values(
            connection,
            "mission_definition_oracles",
            project_id,
            mission_id,
        )?,
        checkpoints,
        cycle: from_sql_u64(header.4, "Mission definition cycle")?,
    };
    definition
        .validate()
        .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
    Ok(Some(definition))
}

struct MissionCheckpointRow {
    id: String,
    depends_on_json: String,
    status: String,
    revision: i64,
    attempt: i64,
    started_at: Option<String>,
    block_json: Option<String>,
    completion_json: Option<String>,
    route_capability_id: Option<String>,
    route_executor: Option<String>,
    route_oracle_ids_json: Option<String>,
    route_completion_policy: Option<String>,
}

fn load_mission_checkpoints(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<Vec<MissionCheckpoint>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT id, depends_on_json, status, revision, attempt, started_at, block_json,
                completion_json, route_capability_id, route_executor,
                route_oracle_ids_json, route_completion_policy
         FROM mission_checkpoints
         WHERE project_id = ?1 AND mission_id = ?2 ORDER BY ordinal ASC",
    )?;
    statement
        .query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
            Ok(MissionCheckpointRow {
                id: row.get(0)?,
                depends_on_json: row.get(1)?,
                status: row.get(2)?,
                revision: row.get(3)?,
                attempt: row.get(4)?,
                started_at: row.get(5)?,
                block_json: row.get(6)?,
                completion_json: row.get(7)?,
                route_capability_id: row.get(8)?,
                route_executor: row.get(9)?,
                route_oracle_ids_json: row.get(10)?,
                route_completion_policy: row.get(11)?,
            })
        })?
        .map(|row| decode_mission_checkpoint(row?))
        .collect()
}

fn decode_mission_checkpoint(row: MissionCheckpointRow) -> Result<MissionCheckpoint, StorageError> {
    let route = match (
        row.route_capability_id,
        row.route_executor,
        row.route_oracle_ids_json,
        row.route_completion_policy,
    ) {
        (None, None, None, None) => None,
        (Some(capability_id), Some(executor), None, None) => Some(
            MissionCheckpointRoute::new(
                capability_id,
                decode_enum::<MissionCheckpointExecutor>(&executor)?,
            )
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?,
        ),
        (Some(capability_id), Some(executor), Some(oracle_ids_json), Some(policy)) => Some(
            MissionCheckpointRoute::contracted(
                capability_id,
                decode_enum::<MissionCheckpointExecutor>(&executor)?,
                decode_json::<BTreeSet<String>>(&oracle_ids_json)?,
                decode_enum::<MissionCheckpointCompletionPolicy>(&policy)?,
            )
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?,
        ),
        _ => {
            return Err(StorageError::DomainDecode(
                "Mission checkpoint route projection is incomplete".into(),
            ));
        }
    };
    Ok(MissionCheckpoint {
        id: row.id,
        depends_on: decode_json(&row.depends_on_json)?,
        route,
        status: decode_enum(&row.status)?,
        revision: from_sql_u64(row.revision, "Mission checkpoint revision")?,
        attempt: u32::try_from(row.attempt).map_err(|_| {
            StorageError::DomainDecode(format!(
                "invalid Mission checkpoint attempt: {}",
                row.attempt
            ))
        })?,
        started_at: row.started_at.as_deref().map(parse_time).transpose()?,
        block: row.block_json.as_deref().map(decode_json).transpose()?,
        completion: row
            .completion_json
            .as_deref()
            .map(decode_json)
            .transpose()?,
    })
}

fn load_definition_values(
    connection: &Connection,
    table: &str,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<std::collections::BTreeSet<String>, StorageError> {
    let mut statement = connection.prepare(&format!(
        "SELECT value FROM {table}
         WHERE project_id = ?1 AND mission_id = ?2 ORDER BY ordinal ASC"
    ))?;
    statement
        .query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<std::collections::BTreeSet<_>, _>>()
        .map_err(StorageError::from)
}

impl ProjectStore {
    pub(crate) fn backfill_normalized_state(&mut self) -> Result<(), StorageError> {
        let project_snapshots = {
            let mut statement = self.connection.prepare(
                "SELECT snapshot_json FROM projects
                 WHERE snapshot_json <> '{}' AND length(snapshot_json) > 2",
            )?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mission_snapshots = {
            let mut statement = self.connection.prepare(
                "SELECT snapshot_json FROM missions
                 WHERE snapshot_json <> '{}' AND length(snapshot_json) > 2",
            )?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        if project_snapshots.is_empty() && mission_snapshots.is_empty() {
            return Ok(());
        }
        let projects = project_snapshots
            .iter()
            .map(|snapshot| serde_json::from_str::<Project>(snapshot))
            .collect::<Result<Vec<_>, _>>()?;
        let missions = mission_snapshots
            .iter()
            .map(|snapshot| serde_json::from_str::<Mission>(snapshot))
            .collect::<Result<Vec<_>, _>>()?;
        let transaction = self.connection.transaction()?;
        for project in &projects {
            upsert_project_normalized(&transaction, project)?;
        }
        for mission in &missions {
            upsert_mission_normalized(&transaction, mission)?;
        }
        transaction.commit()?;
        Ok(())
    }
}

fn replace_project_roots(
    transaction: &Transaction<'_>,
    project: &Project,
) -> Result<(), StorageError> {
    transaction.execute(
        "DELETE FROM project_workspace_roots WHERE project_id = ?1",
        [project.id.as_str()],
    )?;
    for (ordinal, root) in project.workspace_roots.iter().enumerate() {
        let root = root
            .to_str()
            .ok_or_else(|| StorageError::DomainDecode("workspace root is not UTF-8".into()))?;
        transaction.execute(
            "INSERT INTO project_workspace_roots (project_id, ordinal, root_path)
             VALUES (?1, ?2, ?3)",
            params![project.id.as_str(), to_sql_usize(ordinal)?, root],
        )?;
    }
    Ok(())
}

fn replace_mission_children(
    transaction: &Transaction<'_>,
    mission: &Mission,
) -> Result<(), StorageError> {
    clear_mission_children(transaction, mission)?;
    insert_mission_metadata(transaction, mission)?;
    insert_mission_definition(transaction, mission)?;
    insert_mission_tasks(transaction, mission)?;
    insert_mission_evidence(transaction, mission)?;
    insert_mission_work_products(transaction, mission)?;
    insert_mission_effects(transaction, mission)?;
    insert_mission_outcomes(transaction, mission)
}

fn clear_mission_children(
    transaction: &Transaction<'_>,
    mission: &Mission,
) -> Result<(), StorageError> {
    for table in [
        "mission_checkpoints",
        "mission_definition_capabilities",
        "mission_definition_artifacts",
        "mission_definition_oracles",
        "mission_definitions",
        "mission_contracts",
        "mission_lifecycle",
        "mission_tasks",
        "mission_evidence",
        "mission_work_products",
        "mission_effects",
        "mission_outcomes",
    ] {
        transaction.execute(
            &format!("DELETE FROM {table} WHERE mission_id = ?1 AND project_id = ?2"),
            params![mission.id.as_str(), mission.project_id.as_str()],
        )?;
    }
    Ok(())
}

fn insert_mission_definition(
    transaction: &Transaction<'_>,
    mission: &Mission,
) -> Result<(), StorageError> {
    let Some(definition) = &mission.definition else {
        return Ok(());
    };
    definition
        .validate()
        .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
    if definition.operating_mode != mission.contract.mode
        || definition.capability_ids != mission.contract.enabled_capabilities
        || !definition
            .capability_ids
            .is_disjoint(&mission.contract.forbidden_capabilities)
    {
        return Err(StorageError::DomainDecode(
            "Mission definition does not match the Operating Contract".into(),
        ));
    }
    transaction.execute(
        "INSERT INTO mission_definitions
           (mission_id, project_id, manifest_id, manifest_version, catalog_digest,
            operating_mode, cycle)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            mission.id.as_str(),
            mission.project_id.as_str(),
            definition.manifest_id,
            i64::from(definition.manifest_version),
            definition.catalog_digest,
            enum_name(&definition.operating_mode)?,
            to_sql_u64(definition.cycle)?,
        ],
    )?;
    insert_definition_values(
        transaction,
        "mission_definition_capabilities",
        mission,
        definition.capability_ids.iter(),
    )?;
    insert_definition_values(
        transaction,
        "mission_definition_artifacts",
        mission,
        definition.required_artifact_types.iter(),
    )?;
    insert_definition_values(
        transaction,
        "mission_definition_oracles",
        mission,
        definition.oracle_ids.iter(),
    )?;
    for (ordinal, checkpoint) in definition.checkpoints.iter().enumerate() {
        insert_mission_checkpoint(transaction, mission, checkpoint, ordinal)?;
    }
    Ok(())
}

fn insert_mission_checkpoint(
    transaction: &Transaction<'_>,
    mission: &Mission,
    checkpoint: &MissionCheckpoint,
    ordinal: usize,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO mission_checkpoints
           (mission_id, project_id, id, ordinal, depends_on_json, status, revision,
            attempt, started_at, block_json, completion_json, route_capability_id,
            route_executor, route_oracle_ids_json, route_completion_policy)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            mission.id.as_str(),
            mission.project_id.as_str(),
            checkpoint.id,
            to_sql_usize(ordinal)?,
            serde_json::to_string(&checkpoint.depends_on)?,
            enum_name(&checkpoint.status)?,
            to_sql_u64(checkpoint.revision)?,
            i64::from(checkpoint.attempt),
            checkpoint.started_at.map(|value| value.to_rfc3339()),
            checkpoint
                .block
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
            checkpoint
                .completion
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
            checkpoint
                .route
                .as_ref()
                .map(|route| route.capability_id.as_str()),
            checkpoint
                .route
                .as_ref()
                .map(|route| enum_name(&route.executor))
                .transpose()?,
            checkpoint
                .route
                .as_ref()
                .filter(|route| route.is_contracted())
                .map(|route| serde_json::to_string(&route.oracle_ids))
                .transpose()?,
            checkpoint
                .route
                .as_ref()
                .and_then(|route| route.completion_policy.as_ref())
                .map(enum_name)
                .transpose()?,
        ],
    )?;
    Ok(())
}

fn insert_definition_values<'a>(
    transaction: &Transaction<'_>,
    table: &str,
    mission: &Mission,
    values: impl Iterator<Item = &'a String>,
) -> Result<(), StorageError> {
    for (ordinal, value) in values.enumerate() {
        transaction.execute(
            &format!(
                "INSERT INTO {table} (mission_id, project_id, ordinal, value)
                 VALUES (?1, ?2, ?3, ?4)"
            ),
            params![
                mission.id.as_str(),
                mission.project_id.as_str(),
                to_sql_usize(ordinal)?,
                value,
            ],
        )?;
    }
    Ok(())
}

fn insert_mission_metadata(
    transaction: &Transaction<'_>,
    mission: &Mission,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO mission_contracts (mission_id, project_id, contract_json)
         VALUES (?1, ?2, ?3)",
        params![
            mission.id.as_str(),
            mission.project_id.as_str(),
            serde_json::to_string(&mission.contract)?,
        ],
    )?;
    transaction.execute(
        "INSERT INTO mission_lifecycle
           (mission_id, project_id, created_at, updated_at, block_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            mission.id.as_str(),
            mission.project_id.as_str(),
            mission.created_at.to_rfc3339(),
            mission.updated_at.to_rfc3339(),
            mission
                .block
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
        ],
    )?;
    Ok(())
}

fn insert_mission_tasks(
    transaction: &Transaction<'_>,
    mission: &Mission,
) -> Result<(), StorageError> {
    for (ordinal, task) in mission.tasks.iter().enumerate() {
        transaction.execute(
            "INSERT INTO mission_tasks
               (mission_id, project_id, id, ordinal, title, status, capability)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                mission.id.as_str(),
                mission.project_id.as_str(),
                task.id.as_str(),
                to_sql_usize(ordinal)?,
                task.title,
                enum_name(&task.status)?,
                task.capability,
            ],
        )?;
    }
    Ok(())
}

fn insert_mission_evidence(
    transaction: &Transaction<'_>,
    mission: &Mission,
) -> Result<(), StorageError> {
    for (ordinal, evidence) in mission.evidence.iter().enumerate() {
        transaction.execute(
            "INSERT INTO mission_evidence
               (mission_id, project_id, id, ordinal, title, source_uri, observed_at,
                confidence, status, content_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                mission.id.as_str(),
                mission.project_id.as_str(),
                evidence.id.as_str(),
                to_sql_usize(ordinal)?,
                evidence.title,
                evidence.source_uri,
                evidence.observed_at.to_rfc3339(),
                evidence.confidence,
                enum_name(&evidence.status)?,
                evidence.content_digest,
            ],
        )?;
    }
    Ok(())
}

fn insert_mission_work_products(
    transaction: &Transaction<'_>,
    mission: &Mission,
) -> Result<(), StorageError> {
    for (ordinal, product) in mission.work_products.iter().enumerate() {
        transaction.execute(
            "INSERT INTO mission_work_products
               (mission_id, project_id, id, ordinal, title, body, evidence_ids_json,
                revision, status, content_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                mission.id.as_str(),
                mission.project_id.as_str(),
                product.id.as_str(),
                to_sql_usize(ordinal)?,
                product.title,
                product.body,
                serde_json::to_string(&product.evidence_ids)?,
                to_sql_u64(product.revision)?,
                enum_name(&product.status)?,
                product.content_digest,
            ],
        )?;
    }
    Ok(())
}

fn insert_mission_effects(
    transaction: &Transaction<'_>,
    mission: &Mission,
) -> Result<(), StorageError> {
    for (ordinal, effect) in mission.effects.iter().enumerate() {
        transaction.execute(
            "INSERT INTO mission_effects
               (mission_id, project_id, id, ordinal, capability, provider, connection_id,
                account_id, effect_class, status, idempotency_key, approval_digest, effect_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                mission.id.as_str(),
                mission.project_id.as_str(),
                effect.id.as_str(),
                to_sql_usize(ordinal)?,
                effect.capability,
                effect.provider,
                effect
                    .connection_id
                    .as_ref()
                    .map(hartevo_domain_kernel::ConnectionId::as_str),
                effect
                    .account_id
                    .as_ref()
                    .map(hartevo_domain_kernel::AccountId::as_str),
                enum_name(&effect.effect_class)?,
                enum_name(&effect.status)?,
                effect.idempotency_key,
                effect.approval_digest(),
                serde_json::to_string(effect)?,
            ],
        )?;
    }
    Ok(())
}

fn insert_mission_outcomes(
    transaction: &Transaction<'_>,
    mission: &Mission,
) -> Result<(), StorageError> {
    let outcomes = if mission.outcome_history.is_empty() {
        mission.outcome.iter().collect::<Vec<_>>()
    } else {
        mission.outcome_history.iter().collect::<Vec<_>>()
    };
    for (ordinal, outcome) in outcomes.into_iter().enumerate() {
        transaction.execute(
            "INSERT INTO mission_outcomes (mission_id, project_id, ordinal, outcome_json)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                mission.id.as_str(),
                mission.project_id.as_str(),
                to_sql_usize(ordinal)?,
                serde_json::to_string(outcome)?,
            ],
        )?;
    }
    Ok(())
}

fn load_tasks(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<Vec<Task>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT id, title, status, capability FROM mission_tasks
         WHERE project_id = ?1 AND mission_id = ?2 ORDER BY ordinal ASC",
    )?;
    statement
        .query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .map(|row| {
            let row = row?;
            Ok(Task {
                id: TaskId::from_stable(row.0),
                title: row.1,
                status: decode_enum(&row.2)?,
                capability: row.3,
            })
        })
        .collect()
}

fn load_evidence(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<Vec<Evidence>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT id, title, source_uri, observed_at, confidence, status, content_digest
         FROM mission_evidence WHERE project_id = ?1 AND mission_id = ?2 ORDER BY ordinal ASC",
    )?;
    statement
        .query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, f32>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .map(|row| {
            let row = row?;
            Ok(Evidence {
                id: EvidenceId::from_stable(row.0),
                title: row.1,
                source_uri: row.2,
                observed_at: parse_time(&row.3)?,
                confidence: row.4,
                status: decode_enum(&row.5)?,
                content_digest: row.6,
            })
        })
        .collect()
}

fn load_work_products(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<Vec<WorkProduct>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT id, title, body, evidence_ids_json, revision, status, content_digest
         FROM mission_work_products
         WHERE project_id = ?1 AND mission_id = ?2 ORDER BY ordinal ASC",
    )?;
    statement
        .query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .map(|row| {
            let row = row?;
            Ok(WorkProduct {
                id: WorkProductId::from_stable(row.0),
                title: row.1,
                body: row.2,
                evidence_ids: decode_json(&row.3)?,
                revision: from_sql_u64(row.4, "work product revision")?,
                status: decode_enum(&row.5)?,
                content_digest: row.6,
            })
        })
        .collect()
}

fn load_effects(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<Vec<Effect>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT id, capability, provider, connection_id, account_id, effect_class, status,
                idempotency_key, approval_digest, effect_json
         FROM mission_effects WHERE project_id = ?1 AND mission_id = ?2 ORDER BY ordinal ASC",
    )?;
    statement
        .query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        })?
        .map(|row| {
            let row = row?;
            let effect: Effect = decode_json(&row.9)?;
            if effect.id.as_str() != row.0
                || effect.capability != row.1
                || effect.provider != row.2
                || effect
                    .connection_id
                    .as_ref()
                    .map(hartevo_domain_kernel::ConnectionId::as_str)
                    != row.3.as_deref()
                || effect
                    .account_id
                    .as_ref()
                    .map(hartevo_domain_kernel::AccountId::as_str)
                    != row.4.as_deref()
                || enum_name(&effect.effect_class)? != row.5
                || enum_name(&effect.status)? != row.6
                || effect.idempotency_key != row.7
                || effect.approval_digest() != row.8
            {
                return Err(StorageError::DomainDecode(
                    "normalized effect index does not match effect payload".into(),
                ));
            }
            Ok(effect)
        })
        .collect()
}

fn load_outcomes(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<Vec<Outcome>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT outcome_json FROM mission_outcomes
         WHERE project_id = ?1 AND mission_id = ?2 ORDER BY ordinal ASC",
    )?;
    statement
        .query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
            row.get::<_, String>(0)
        })?
        .map(|row| decode_json(&row?))
        .collect()
}

pub(crate) fn enum_name(value: &impl Serialize) -> Result<String, StorageError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| StorageError::DomainDecode("enum did not serialize as a string".into()))
}

pub(crate) fn decode_enum<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_value(Value::String(value.to_owned()))?)
}

fn decode_json<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_str(value)?)
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, StorageError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn to_sql_usize(value: usize) -> Result<i64, StorageError> {
    i64::try_from(value)
        .map_err(|_| StorageError::DomainDecode("collection ordinal overflow".into()))
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("invalid {field}: {value}")))
}
