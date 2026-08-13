//! Durable consumer-side handshake for Mission-scoped plugin sessions.
//!
//! Resume receipts use the existing append-only `domain_events` spine.  The
//! session journal and the resume journal are loaded under one transaction,
//! validated against the exact cursor/recovery revision, and only then can a
//! lease-acquired or completion receipt be appended.

use chrono::{DateTime, Utc};
use hartevo_context_fabric::{
    PluginSessionEvent, PluginSessionFence, PluginSessionResumeEvent, PluginSessionResumeFence,
    PluginSessionResumeReceipt, PluginSessionResumeService, PluginSessionService,
};
use rusqlite::{Connection, params};

use crate::{PLUGIN_SESSION_EVENT_TYPE, ProjectStore, StorageError};

pub const PLUGIN_SESSION_RESUME_EVENT_TYPE: &str = "context.plugin_session.resume.v1";

impl ProjectStore {
    /// Reacquires the exact consumer lease once.  A durable prepared wake is
    /// returned as `ReplayRequired` after a crash, without appending another
    /// wake or dispatching the plugin again.
    pub fn prepare_plugin_session_resume(
        &mut self,
        fence: &PluginSessionResumeFence,
        now: DateTime<Utc>,
    ) -> Result<PluginSessionResumeReceipt, StorageError> {
        self.mutate_plugin_session_resume(fence, |service| {
            service.resume(now).map_err(StorageError::from)
        })
    }

    /// Commits one resumed invocation with the same lease and cursor fence.
    /// Repeating the exact outcome returns `AlreadyCompleted`; a different
    /// outcome or lease cannot advance the durable spine.
    pub fn complete_plugin_session_resume(
        &mut self,
        fence: &PluginSessionResumeFence,
        outcome_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<PluginSessionResumeReceipt, StorageError> {
        self.mutate_plugin_session_resume(fence, |service| {
            service
                .complete(outcome_digest, now)
                .map_err(StorageError::from)
        })
    }

    pub fn plugin_session_resume_events(
        &self,
        fence: &PluginSessionResumeFence,
    ) -> Result<Vec<PluginSessionResumeEvent>, StorageError> {
        self.ensure_resume_scope(fence)?;
        load_resume_events(&self.connection, fence)
    }

    fn ensure_resume_scope(&self, fence: &PluginSessionResumeFence) -> Result<(), StorageError> {
        let project = self.load_project(fence.session_fence().project_id())?;
        if project.tenant_id != *fence.session_fence().tenant_id()
            || fence.lease().tenant_id() != fence.session_fence().tenant_id()
            || fence.lease().project_id() != fence.session_fence().project_id()
            || fence.lease().mission_id() != fence.session_fence().mission_id()
        {
            return Err(StorageError::TenantScopeMismatch);
        }
        self.load_mission(
            fence.session_fence().project_id(),
            fence.session_fence().mission_id(),
        )?;
        Ok(())
    }

    fn load_resume_service(
        connection: &Connection,
        fence: &PluginSessionResumeFence,
    ) -> Result<PluginSessionResumeService, StorageError> {
        let session_events = load_session_events(connection, fence.session_fence())?;
        let session =
            PluginSessionService::from_events(fence.session_fence().clone(), session_events)
                .map_err(|error| match error {
                    hartevo_context_fabric::PluginSessionError::StaleFence => {
                        StorageError::PluginSessionResume(
                            hartevo_context_fabric::PluginSessionResumeError::CursorDrift,
                        )
                    }
                    other => StorageError::PluginSession(other),
                })?;
        if session.journal().event_count() as u64 != fence.session_event_sequence()
            || session.journal().fence() != fence.session_fence()
        {
            return Err(StorageError::PluginSessionResume(
                hartevo_context_fabric::PluginSessionResumeError::CursorDrift,
            ));
        }
        let events = load_resume_events(connection, fence)?;
        PluginSessionResumeService::from_events(
            fence.clone(),
            session.journal().lifecycle(),
            events,
        )
        .map_err(StorageError::from)
    }

    fn mutate_plugin_session_resume<T, F>(
        &mut self,
        fence: &PluginSessionResumeFence,
        mutator: F,
    ) -> Result<T, StorageError>
    where
        F: FnOnce(&mut PluginSessionResumeService) -> Result<T, StorageError>,
    {
        self.ensure_resume_scope(fence)?;
        let transaction = self.connection.transaction()?;
        let mut service = Self::load_resume_service(&transaction, fence)?;
        let previous_event_count = service.event_count();
        let result = mutator(&mut service)?;
        let new_events = service.events()[previous_event_count..].to_vec();
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
                    fence.session_fence().tenant_id().as_str(),
                    fence.session_fence().project_id().as_str(),
                    fence.session_fence().mission_id().as_str(),
                    PLUGIN_SESSION_RESUME_EVENT_TYPE,
                    serde_json::to_string(event)?,
                    recorded_at.to_rfc3339(),
                ],
            )?;
        }
        transaction.commit()?;
        Ok(result)
    }
}

fn load_session_events(
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
    rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
}

fn load_resume_events(
    connection: &Connection,
    fence: &PluginSessionResumeFence,
) -> Result<Vec<PluginSessionResumeEvent>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT payload_json
         FROM domain_events
         WHERE tenant_id = ?1 AND project_id = ?2 AND mission_id = ?3 AND event_type = ?4
         ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map(
        params![
            fence.session_fence().tenant_id().as_str(),
            fence.session_fence().project_id().as_str(),
            fence.session_fence().mission_id().as_str(),
            PLUGIN_SESSION_RESUME_EVENT_TYPE,
        ],
        |row| row.get::<_, String>(0),
    )?;
    rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use hartevo_context_fabric::{
        PluginSessionDescriptor, PluginSessionPosition, PluginSessionResumeError,
        PluginSessionResumeFence, PluginSessionResumeReceipt, PluginSessionRuntimeLease,
        PluginSessionRuntimeLeaseInput, PluginSessionScope, plugin_resume_digest,
    };
    use hartevo_domain_kernel::{
        Mission, MissionContract, MissionId, Project, ProjectId, StorageMode, TenantId,
    };

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
            .single()
            .expect("time")
    }

    fn base_fence() -> PluginSessionFence {
        PluginSessionFence::new(
            PluginSessionScope::new(
                TenantId::from("tenant-resume-store"),
                ProjectId::from("project-resume-store"),
                MissionId::from("mission-resume-store"),
            ),
            PluginSessionDescriptor::new(
                "plugin.browser",
                "2.4.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            PluginSessionPosition::new("invocation-1", 0, 4, 9),
        )
    }

    fn seed_store() -> ProjectStore {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = Project::create_local(
            TenantId::from("tenant-resume-store"),
            ProjectId::from("project-resume-store"),
            "resume-store",
            "",
            "/tmp/resume-store",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            TenantId::from("tenant-resume-store"),
            MissionId::from("mission-resume-store"),
            ProjectId::from("project-resume-store"),
            "resume plugin",
            MissionContract::bootstrap("resume plugin", [], now()),
            now(),
        )
        .expect("mission");
        store.save_project(&project).expect("project");
        store.save_mission(&mission).expect("mission");
        store
    }

    fn resume_fence(session: &PluginSessionFence, sequence: u64) -> PluginSessionResumeFence {
        let lease = PluginSessionRuntimeLease::new(PluginSessionRuntimeLeaseInput {
            tenant_id: session.tenant_id().clone(),
            project_id: session.project_id().clone(),
            mission_id: session.mission_id().clone(),
            lease_id: "lease-resume-store".into(),
            owner_digest: plugin_resume_digest("owner"),
            lease_token_digest: plugin_resume_digest("token"),
            generation: 8,
            revision: 1,
            issued_at: now(),
            expires_at: now() + Duration::minutes(10),
        })
        .expect("lease");
        PluginSessionResumeFence::new(session.clone(), sequence, 1, lease).expect("fence")
    }

    #[test]
    fn resume_reacquires_once_replays_after_crash_and_completes_once() {
        let mut store = seed_store();
        let session = base_fence();
        store
            .prepare_plugin_session_invocation(
                &session,
                &plugin_resume_digest("side-effect"),
                "2026-08-14T12:00:00Z",
            )
            .expect("prepare");
        let session = session.with_cursor(0);
        let fence = resume_fence(&session, 1);
        let acquired = store
            .prepare_plugin_session_resume(&fence, now())
            .expect("acquire");
        assert!(matches!(
            acquired,
            PluginSessionResumeReceipt::LeaseAcquired { cursor: 0, .. }
        ));
        let replay = store
            .prepare_plugin_session_resume(&fence, now())
            .expect("crash replay");
        assert!(matches!(
            replay,
            PluginSessionResumeReceipt::ReplayRequired { cursor: 0, .. }
        ));
        let outcome = plugin_resume_digest("resume-outcome");
        let completed = store
            .complete_plugin_session_resume(&fence, &outcome, now())
            .expect("complete");
        assert!(matches!(
            completed,
            PluginSessionResumeReceipt::Completed { .. }
        ));
        let duplicate = store
            .complete_plugin_session_resume(&fence, &outcome, now())
            .expect("duplicate completion");
        assert!(matches!(
            duplicate,
            PluginSessionResumeReceipt::AlreadyCompleted { .. }
        ));
        assert_eq!(
            store
                .plugin_session_resume_events(&fence)
                .expect("events")
                .len(),
            2
        );
    }

    #[test]
    fn cursor_drift_and_unmounted_session_refuse_resume_without_dispatch() {
        let mut store = seed_store();
        let session = base_fence();
        store
            .prepare_plugin_session_invocation(
                &session,
                &plugin_resume_digest("side-effect"),
                "2026-08-14T12:00:00Z",
            )
            .expect("prepare");
        let drifted = resume_fence(&session.with_cursor(1), 1);
        let drift_result = store.prepare_plugin_session_resume(&drifted, now());
        assert!(matches!(
            drift_result,
            Err(StorageError::PluginSessionResume(
                PluginSessionResumeError::CursorDrift
            ))
        ));
        let fence = resume_fence(&session, 1);
        assert!(matches!(
            store.prepare_plugin_session_resume(&fence, now()),
            Ok(PluginSessionResumeReceipt::LeaseAcquired { .. })
        ));
        let wrong_lease = PluginSessionRuntimeLease::new(PluginSessionRuntimeLeaseInput {
            tenant_id: session.tenant_id().clone(),
            project_id: session.project_id().clone(),
            mission_id: session.mission_id().clone(),
            lease_id: "lease-resume-store-other".into(),
            owner_digest: plugin_resume_digest("other-owner"),
            lease_token_digest: plugin_resume_digest("other-token"),
            generation: 8,
            revision: 1,
            issued_at: now(),
            expires_at: now() + Duration::minutes(10),
        })
        .expect("wrong lease shape");
        let wrong_fence = PluginSessionResumeFence::new(session.clone(), 1, 1, wrong_lease)
            .expect("wrong fence shape");
        assert!(matches!(
            store.prepare_plugin_session_resume(&wrong_fence, now()),
            Err(StorageError::PluginSessionResume(
                PluginSessionResumeError::InvalidHistory
            ))
        ));

        let mut unmounted_store = seed_store();
        let unmounted_session = base_fence();
        unmounted_store
            .prepare_plugin_session_invocation(
                &unmounted_session,
                &plugin_resume_digest("side-effect"),
                "2026-08-14T12:00:00Z",
            )
            .expect("prepare unmounted");
        unmounted_store
            .unmount_plugin_session(&unmounted_session, "2026-08-14T12:00:01Z")
            .expect("unmount");
        let unmounted_fence = resume_fence(&unmounted_session, 2);
        let cancelled = unmounted_store
            .prepare_plugin_session_resume(&unmounted_fence, now())
            .expect("cancelled");
        assert!(matches!(
            cancelled,
            PluginSessionResumeReceipt::Cancelled { .. }
        ));
        assert!(matches!(
            unmounted_store.complete_plugin_session_resume(
                &unmounted_fence,
                &plugin_resume_digest("outcome"),
                now(),
            ),
            Err(StorageError::PluginSessionResume(
                PluginSessionResumeError::LifecycleUnavailable
            ))
        ));
        assert_eq!(
            unmounted_store
                .plugin_session_resume_events(&unmounted_fence)
                .expect("events")
                .len(),
            1
        );
    }

    #[test]
    fn terminal_session_is_a_durable_cancelled_resume_outcome() {
        let mut store = seed_store();
        let session = base_fence();
        store
            .prepare_plugin_session_invocation(
                &session,
                &plugin_resume_digest("side-effect"),
                "2026-08-14T12:00:00Z",
            )
            .expect("prepare");
        store
            .terminal_plugin_session(&session, "2026-08-14T12:00:01Z")
            .expect("terminal");
        let fence = resume_fence(&session, 2);
        let cancelled = store
            .prepare_plugin_session_resume(&fence, now())
            .expect("terminal receipt");
        assert!(matches!(
            cancelled,
            PluginSessionResumeReceipt::Cancelled { .. }
        ));
    }
}
