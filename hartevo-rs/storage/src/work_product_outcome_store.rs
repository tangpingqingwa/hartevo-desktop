use hartevo_domain_kernel::{
    Mission, MissionId, ProjectId, WorkProductHandoffSnapshot, WorkProductId, WorkProductManifest,
};
use rusqlite::params;

use crate::{AtomicMutation, PendingEvent, ProjectStore, StorageError};

impl ProjectStore {
    pub fn create_work_product_outcome_atomic(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        manifest: &WorkProductManifest,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        self.create_work_product_manifest_atomic(
            mission,
            expected_mission_revision,
            manifest,
            events,
        )
    }

    pub fn revise_work_product_outcome_atomic(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        manifest: &WorkProductManifest,
        expected_manifest_version: u64,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        self.revise_work_product_manifest_atomic(
            mission,
            expected_mission_revision,
            manifest,
            expected_manifest_version,
            events,
        )
    }

    pub fn load_work_product_outcome_snapshot(
        &self,
        project_id: &ProjectId,
        work_product_id: &WorkProductId,
    ) -> Result<WorkProductHandoffSnapshot, StorageError> {
        let manifest = self.load_work_product_manifest(project_id, work_product_id)?;
        WorkProductHandoffSnapshot::from_preview(&manifest.preview)
            .map_err(|error| StorageError::DomainDecode(error.to_string()))
    }

    pub fn load_work_product_outcome_mission(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<Mission, StorageError> {
        self.load_mission(project_id, mission_id)
    }

    pub fn outbox_sequences_for_mission(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<Vec<i64>, StorageError> {
        self.load_mission(project_id, mission_id)?;
        let mut statement = self.connection.prepare(
            "SELECT sequence FROM outbox_messages
             WHERE project_id = ?1 AND mission_id = ?2
             ORDER BY sequence ASC",
        )?;
        let rows = statement
            .query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
                row.get::<_, i64>(0)
            })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }
}
