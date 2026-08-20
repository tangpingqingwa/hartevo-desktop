use std::collections::BTreeSet;

use serde::Serialize;
use thiserror::Error;

use crate::MISSION_AZURE_MONITOR_LOGS_CONSUMER_ID;
use crate::model::{AzureMonitorLogsScope, Digest, Layer1Authority, ResultStatus};
use crate::service::AzureMonitorLogsResult;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission Project/Mission/Work Product scope or revision is stale")]
    StaleMission,
    #[error("Mission consumer received tampered evidence")]
    Tampered,
    #[error("Mission consumer received revoked evidence")]
    Revoked,
    #[error("Mission consumer received a replayed result digest")]
    Replay,
    #[error("Mission consumer received forbidden authority claims")]
    ForbiddenAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionAzureMonitorLogsObservation {
    pub consumer_id: String,
    pub status: ResultStatus,
    pub scope_digest: Digest,
    pub project_id: crate::ProjectId,
    pub project_revision: crate::Revision,
    pub mission_id: crate::MissionId,
    pub mission_revision: crate::Revision,
    pub work_product_id: crate::WorkProductId,
    pub work_product_revision: crate::Revision,
    pub query_digest: Digest,
    pub parameter_digest: Digest,
    pub provider_digest: Digest,
    pub schema: Option<crate::AggregateSchema>,
    pub rows: Vec<crate::AggregateRow>,
    pub result_digest: Digest,
    pub decision_eligible: bool,
    pub adopted_outcome: bool,
    pub adopted_work_product: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub authority: Layer1Authority,
}

pub struct MissionAzureMonitorLogsConsumer {
    scope: AzureMonitorLogsScope,
    consumed_result_digests: BTreeSet<Digest>,
}

impl std::fmt::Debug for MissionAzureMonitorLogsConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionAzureMonitorLogsConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("consumed_result_count", &self.consumed_result_digests.len())
            .finish()
    }
}

impl MissionAzureMonitorLogsConsumer {
    pub fn new(scope: AzureMonitorLogsScope) -> Self {
        Self {
            scope,
            consumed_result_digests: BTreeSet::new(),
        }
    }

    pub fn consumer_id(&self) -> &'static str {
        MISSION_AZURE_MONITOR_LOGS_CONSUMER_ID
    }

    pub fn scope(&self) -> &AzureMonitorLogsScope {
        &self.scope
    }

    pub fn consumed_result_count(&self) -> usize {
        self.consumed_result_digests.len()
    }

    pub fn consume(
        &mut self,
        result: &AzureMonitorLogsResult,
    ) -> Result<MissionAzureMonitorLogsObservation, ConsumerError> {
        result
            .verify_digests()
            .map_err(|_| ConsumerError::Tampered)?;
        if result.authority != Layer1Authority::layer_one()
            || result.connected
            || result.native
            || result.first_party
        {
            return Err(ConsumerError::ForbiddenAuthority);
        }
        if result.status == ResultStatus::Revoked {
            return Err(ConsumerError::Revoked);
        }
        if result.status == ResultStatus::Tampered {
            return Err(ConsumerError::Tampered);
        }
        if result.scope_digest != self.scope.scope_digest()
            || result.project_id != self.scope.project_id
            || result.project_revision != self.scope.project_revision
            || result.mission_id != self.scope.mission_id
            || result.mission_revision != self.scope.mission_revision
            || result.work_product_id != self.scope.work_product_id
            || result.work_product_revision != self.scope.work_product_revision
        {
            return Err(ConsumerError::StaleMission);
        }
        if !self
            .consumed_result_digests
            .insert(result.result_digest.clone())
        {
            return Err(ConsumerError::Replay);
        }
        Ok(MissionAzureMonitorLogsObservation {
            consumer_id: self.consumer_id().to_owned(),
            status: result.status,
            scope_digest: result.scope_digest.clone(),
            project_id: result.project_id.clone(),
            project_revision: result.project_revision,
            mission_id: result.mission_id.clone(),
            mission_revision: result.mission_revision,
            work_product_id: result.work_product_id.clone(),
            work_product_revision: result.work_product_revision,
            query_digest: result.query_digest.clone(),
            parameter_digest: result.parameter_digest.clone(),
            provider_digest: result.provider_digest.clone(),
            schema: result.schema.clone(),
            rows: result.rows.clone(),
            result_digest: result.result_digest.clone(),
            decision_eligible: result.eligible_for_decision(),
            adopted_outcome: false,
            adopted_work_product: false,
            connected: false,
            native: false,
            first_party: false,
            authority: Layer1Authority::layer_one(),
        })
    }
}
