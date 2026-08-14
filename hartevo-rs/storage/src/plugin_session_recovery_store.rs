//! Durable Mission-scoped plugin session recovery over the existing event spine.
//!
//! Plugin session rows are deliberately not a second source of truth.  The
//! typed Context journal is serialized as one event per state transition in
//! `domain_events`; loading and mutation always rebuild and validate the full
//! journal before a consumer can resume or commit a side effect.

use chrono::{DateTime, Utc};
use hartevo_context_fabric::{
    PluginSessionConsumer, PluginSessionEvent, PluginSessionFence, PluginSessionProvider,
    PluginSessionReceipt, PluginSessionService,
};
use rusqlite::{Connection, params};

use crate::{ProjectStore, StorageError};

pub const PLUGIN_SESSION_EVENT_TYPE: &str = "context.plugin_session.recovery.v1";

impl ProjectStore {
    /// Records a durable preparation, or returns the existing replay receipt
    /// without appending another event for the same invocation and side
    /// effect digest.
    pub fn prepare_plugin_session_invocation(
        &mut self,
        fence: &PluginSessionFence,
        side_effect_digest: &str,
        recorded_at: &str,
    ) -> Result<PluginSessionReceipt, StorageError> {
        self.mutate_plugin_session(fence, |service| {
            service
                .prepare_invocation(fence, side_effect_digest, recorded_at)
                .map_err(StorageError::from)
        })
    }

    /// Commits the prepared invocation exactly once.  A stale cursor,
    /// generation, attachment epoch, or invocation fence is rejected before
    /// any event is written.
    pub fn commit_plugin_session_invocation(
        &mut self,
        fence: &PluginSessionFence,
        side_effect_digest: &str,
        next_cursor: u64,
        recorded_at: &str,
    ) -> Result<PluginSessionReceipt, StorageError> {
        self.mutate_plugin_session(fence, |service| {
            service
                .commit_invocation(fence, side_effect_digest, next_cursor, recorded_at)
                .map_err(StorageError::from)
        })
    }

    /// Rebuilds the journal after a process restart without writing rows or
    /// invoking a plugin.  The returned receipt is the only durable replay
    /// authority exposed to a consumer.
    pub fn resume_plugin_session_invocation(
        &self,
        fence: &PluginSessionFence,
    ) -> Result<Option<PluginSessionReceipt>, StorageError> {
        self.ensure_plugin_session_scope(fence)?;
        let events = load_plugin_session_events(&self.connection, fence)?;
        let service = PluginSessionService::from_events(fence.clone(), events)?;
        service.resume_invocation(fence).map_err(StorageError::from)
    }

    /// Revokes a mounted session and durably cancels every still-prepared
    /// invocation in one transaction.  Reopening the resulting history cannot
    /// resume a cancelled side effect.
    pub fn revoke_plugin_session(
        &mut self,
        fence: &PluginSessionFence,
        recorded_at: &str,
    ) -> Result<Vec<PluginSessionReceipt>, StorageError> {
        self.mutate_plugin_session(fence, |service| {
            service
                .revoke(fence, recorded_at)
                .map_err(StorageError::from)
        })
    }

    /// Unmounts a mounted session with the same durable cancellation fence as
    /// revocation.
    pub fn unmount_plugin_session(
        &mut self,
        fence: &PluginSessionFence,
        recorded_at: &str,
    ) -> Result<Vec<PluginSessionReceipt>, StorageError> {
        self.mutate_plugin_session(fence, |service| {
            service
                .unmount(fence, recorded_at)
                .map_err(StorageError::from)
        })
    }

    pub fn terminal_plugin_session(
        &mut self,
        fence: &PluginSessionFence,
        recorded_at: &str,
    ) -> Result<Vec<PluginSessionReceipt>, StorageError> {
        self.mutate_plugin_session(fence, |service| {
            service
                .terminal(fence, recorded_at)
                .map_err(StorageError::from)
        })
    }

    pub fn plugin_session_events(
        &self,
        fence: &PluginSessionFence,
    ) -> Result<Vec<PluginSessionEvent>, StorageError> {
        self.ensure_plugin_session_scope(fence)?;
        load_plugin_session_events(&self.connection, fence)
    }

    fn ensure_plugin_session_scope(&self, fence: &PluginSessionFence) -> Result<(), StorageError> {
        let project = self.load_project(fence.project_id())?;
        if project.tenant_id != *fence.tenant_id() {
            return Err(StorageError::TenantScopeMismatch);
        }
        self.load_mission(fence.project_id(), fence.mission_id())?;
        Ok(())
    }

    fn mutate_plugin_session<T, F>(
        &mut self,
        fence: &PluginSessionFence,
        mutator: F,
    ) -> Result<T, StorageError>
    where
        F: FnOnce(&mut PluginSessionService) -> Result<T, StorageError>,
    {
        self.ensure_plugin_session_scope(fence)?;
        let project = self.load_project(fence.project_id())?;
        let transaction = self.connection.transaction()?;
        let history = load_plugin_session_events(&transaction, fence)?;
        let mut service = PluginSessionService::from_events(fence.clone(), history)?;
        let previous_event_count = service.journal().event_count();
        let result = mutator(&mut service)?;
        let new_events = service
            .journal()
            .events_since(previous_event_count)
            .to_vec();
        if new_events.is_empty() {
            transaction.commit()?;
            return Ok(result);
        }

        for event in &new_events {
            let recorded_at =
                DateTime::parse_from_rfc3339(event.recorded_at())?.with_timezone(&Utc);
            transaction.execute(
                "INSERT INTO domain_events
                   (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    project.tenant_id.as_str(),
                    fence.project_id().as_str(),
                    fence.mission_id().as_str(),
                    PLUGIN_SESSION_EVENT_TYPE,
                    serde_json::to_string(event)?,
                    recorded_at.to_rfc3339(),
                ],
            )?;
        }
        transaction.commit()?;
        Ok(result)
    }
}

fn load_plugin_session_events(
    connection: &Connection,
    fence: &PluginSessionFence,
) -> Result<Vec<PluginSessionEvent>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT payload_json
         FROM domain_events
         WHERE tenant_id = ?1 AND project_id = ?2 AND mission_id = ?3 AND event_type = ?4
         ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map(
        params![
            fence.tenant_id().as_str(),
            fence.project_id().as_str(),
            fence.mission_id().as_str(),
            PLUGIN_SESSION_EVENT_TYPE,
        ],
        |row| row.get::<_, String>(0),
    )?;
    rows.map(|row| {
        let payload = row?;
        Ok(serde_json::from_str(&payload)?)
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use hartevo_context_fabric::{
        PluginSessionDescriptor, PluginSessionPosition, PluginSessionScope,
    };
    use hartevo_domain_kernel::{
        Mission, MissionContract, MissionId, Project, ProjectId, StorageMode, TenantId,
    };

    fn fence(invocation: &str, cursor: u64) -> PluginSessionFence {
        PluginSessionFence::new(
            PluginSessionScope::new(
                TenantId::from("tenant-plugin-test"),
                ProjectId::from("project-plugin-test"),
                MissionId::from("mission-plugin-test"),
            ),
            PluginSessionDescriptor::new(
                "plugin.browser",
                "2.4.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            PluginSessionPosition::new(invocation, cursor, 7, 11),
        )
    }

    fn seed_store() -> ProjectStore {
        let mut store = ProjectStore::in_memory().expect("in-memory store");
        let project = Project::create_local(
            TenantId::from("tenant-plugin-test"),
            ProjectId::from("project-plugin-test"),
            "plugin-test",
            "",
            "/tmp/plugin-test",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            TenantId::from("tenant-plugin-test"),
            MissionId::from("mission-plugin-test"),
            ProjectId::from("project-plugin-test"),
            "plugin recovery",
            MissionContract::bootstrap(
                "resume plugin",
                [],
                DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
                    .expect("valid contract time")
                    .with_timezone(&Utc),
            ),
            DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
                .expect("valid mission time")
                .with_timezone(&Utc),
        )
        .expect("mission");
        store.save_project(&project).expect("save project");
        store.save_mission(&mission).expect("save mission");
        store
    }

    #[test]
    fn durable_event_spine_reopens_prepared_invocation_without_duplicate_side_effect() {
        let mut store = seed_store();
        let fence = fence("invocation-1", 0);
        let digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let prepared = store
            .prepare_plugin_session_invocation(&fence, digest, "2026-08-14T00:00:01Z")
            .expect("prepare");
        assert!(matches!(prepared, PluginSessionReceipt::Prepared { .. }));
        assert_eq!(
            store.plugin_session_events(&fence).expect("events").len(),
            1
        );

        let replay = store
            .resume_plugin_session_invocation(&fence)
            .expect("resume")
            .expect("prepared receipt");
        assert!(matches!(
            replay,
            PluginSessionReceipt::ReplayRequired { .. }
        ));
        let idempotent = store
            .prepare_plugin_session_invocation(&fence, digest, "2026-08-14T00:00:02Z")
            .expect("idempotent prepare");
        assert!(matches!(
            idempotent,
            PluginSessionReceipt::ReplayRequired { .. }
        ));
        assert_eq!(
            store.plugin_session_events(&fence).expect("events").len(),
            1
        );

        let committed = store
            .commit_plugin_session_invocation(&fence, digest, 1, "2026-08-14T00:00:03Z")
            .expect("commit");
        assert!(matches!(
            committed,
            PluginSessionReceipt::AlreadyApplied {
                cursor_after: 1,
                ..
            }
        ));
        assert_eq!(
            store.plugin_session_events(&fence).expect("events").len(),
            2
        );
        let committed_replay = store
            .resume_plugin_session_invocation(&fence)
            .expect("reopen")
            .expect("committed receipt");
        assert!(matches!(
            committed_replay,
            PluginSessionReceipt::AlreadyApplied {
                cursor_after: 1,
                ..
            }
        ));
    }

    #[test]
    fn stale_scope_and_unmount_refuse_writes_after_reopen() {
        let mut store = seed_store();
        let fence = fence("invocation-1", 0);
        let digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        store
            .prepare_plugin_session_invocation(&fence, digest, "2026-08-14T00:00:01Z")
            .expect("prepare");
        let cancelled = store
            .unmount_plugin_session(&fence, "2026-08-14T00:00:02Z")
            .expect("unmount");
        assert_eq!(cancelled.len(), 1);
        assert!(matches!(
            store.prepare_plugin_session_invocation(&fence, digest, "2026-08-14T00:00:03Z"),
            Err(StorageError::PluginSession(
                hartevo_context_fabric::PluginSessionError::LifecycleUnavailable
            ))
        ));
        let drifted = fence.with_generation(8, 11);
        assert!(matches!(
            store.resume_plugin_session_invocation(&drifted),
            Err(StorageError::PluginSession(
                hartevo_context_fabric::PluginSessionError::StaleFence
            ))
        ));
        assert_eq!(
            store.plugin_session_events(&fence).expect("events").len(),
            2
        );
    }
}
