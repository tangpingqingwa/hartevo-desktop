//! Mission-scoped proposal and recording seam below Hartevo kernel authority.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{
    AirbyteScope, CatalogProjection, Digest, ProjectionCompleteness, SyncAttemptProjection,
    SyncAttemptStatus, TransportProvenance,
};
use crate::{
    AirbyteSyncResultError, CONSUMER_ID, CONTRACT_VERSION, Result, SERVICE_ID, validate_text,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    ReviewOnly,
    SchemaMismatch,
    IncompleteEvidence,
    ProviderUnknown,
}

/// A Mission/Project/Work Product-bound sync result proposal. It is a review
/// artifact only; it cannot be adopted as an Outcome or kernel fact.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirbyteSyncResultProposal {
    pub proposal_version: String,
    pub service_id: String,
    pub consumer_id: String,
    pub scope_digest: Digest,
    pub mission_id: String,
    pub project_id: String,
    pub work_product_id: String,
    pub catalog_digest: Digest,
    pub attempt_evidence_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub status: SyncAttemptStatus,
    pub disposition: ProposalDisposition,
    pub completeness: ProjectionCompleteness,
    pub schema_mismatch: bool,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub raw_records_retained: bool,
    pub outcome_adopted: bool,
    pub proposal_digest: Digest,
}

impl AirbyteSyncResultProposal {
    fn new(
        scope: &AirbyteScope,
        catalog: &CatalogProjection,
        attempt: &SyncAttemptProjection,
        idempotency_key: &str,
    ) -> Result<Self> {
        validate_text(idempotency_key, "idempotencyKey", 256)?;
        if catalog.scope_digest != scope.digest() || attempt.scope_digest != scope.digest() {
            return Err(AirbyteSyncResultError::ScopeMismatch);
        }
        catalog.validate_integrity()?;
        attempt.validate_integrity()?;
        let idempotency_key_digest = Digest::from_text(idempotency_key);
        let disposition = if attempt.schema_mismatch {
            ProposalDisposition::SchemaMismatch
        } else if attempt.status == SyncAttemptStatus::ProviderUnknown
            || attempt.completeness == ProjectionCompleteness::Unavailable
        {
            ProposalDisposition::ProviderUnknown
        } else if !catalog.is_complete() || !attempt.is_complete() {
            ProposalDisposition::IncompleteEvidence
        } else {
            ProposalDisposition::ReviewOnly
        };
        let mut proposal = Self {
            proposal_version: format!("{CONTRACT_VERSION}/proposal"),
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            scope_digest: scope.digest(),
            mission_id: scope.mission_id().as_str().to_owned(),
            project_id: scope.project_id().as_str().to_owned(),
            work_product_id: scope.work_product_id().as_str().to_owned(),
            catalog_digest: catalog.catalog_digest.clone(),
            attempt_evidence_digest: attempt.evidence_digest.clone(),
            idempotency_key_digest,
            status: attempt.status,
            disposition,
            completeness: attempt.completeness,
            schema_mismatch: attempt.schema_mismatch,
            provenance: attempt.provenance,
            connected: false,
            native: false,
            raw_records_retained: false,
            outcome_adopted: false,
            proposal_digest: Digest::from_text("unsealed-airbyte-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        Ok(proposal)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope_digest.validate()?;
        self.catalog_digest.validate()?;
        self.attempt_evidence_digest.validate()?;
        self.idempotency_key_digest.validate()?;
        if self.proposal_version != format!("{CONTRACT_VERSION}/proposal")
            || self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.raw_records_retained
            || self.outcome_adopted
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AirbyteSyncResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn is_review_only(&self) -> bool {
        true
    }

    pub fn computed_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.proposal_version,
            &self.service_id,
            &self.consumer_id,
            &self.scope_digest,
            &self.mission_id,
            &self.project_id,
            &self.work_product_id,
            &self.catalog_digest,
            &self.attempt_evidence_digest,
            &self.idempotency_key_digest,
            self.status,
            self.disposition,
            self.completeness,
            self.schema_mismatch,
            self.provenance,
        ))
    }
}

/// A safe durable recording result. It contains only digests and bounded
/// status metadata; it is not a Provider Receipt or Outcome.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedSyncResult {
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub status: SyncAttemptStatus,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedSyncResult {
    fn from_proposal(proposal: &AirbyteSyncResultProposal, replayed: bool) -> Self {
        let mut result = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            status: proposal.status,
            disposition: proposal.disposition,
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            provider_receipt: false,
            outcome_adopted: false,
            recording_digest: Digest::from_text("unsealed-airbyte-recording"),
        };
        result.recording_digest = Digest::from_serialized(&(
            &result.proposal_digest,
            &result.scope_digest,
            result.status,
            result.disposition,
            result.provenance,
        ));
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.proposal_digest.validate()?;
        self.scope_digest.validate()?;
        if self.connected || self.native || self.provider_receipt || self.outcome_adopted {
            return Err(AirbyteSyncResultError::TamperedEvidence);
        }
        let expected = Digest::from_serialized(&(
            &self.proposal_digest,
            &self.scope_digest,
            self.status,
            self.disposition,
            self.provenance,
        ));
        if self.recording_digest != expected {
            return Err(AirbyteSyncResultError::TamperedEvidence);
        }
        Ok(())
    }
}

/// In-memory deterministic recording seam. An integration host can persist
/// the returned safe record in its own bounded store, but this crate does not
/// own Hartevo storage.
#[derive(Clone, Debug, Default)]
pub struct SyncResultRecordingLog {
    records: BTreeMap<Digest, RecordedSyncResult>,
}

impl SyncResultRecordingLog {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, idempotency_key_digest: &Digest) -> Option<&RecordedSyncResult> {
        self.records.get(idempotency_key_digest)
    }
}

/// Mission consumer scoped to one exact Mission/Project/Work Product and
/// Airbyte object fence.
#[derive(Clone, Debug)]
pub struct MissionAirbyteSyncConsumer {
    scope: AirbyteScope,
}

impl MissionAirbyteSyncConsumer {
    pub fn new(scope: AirbyteScope) -> Self {
        Self { scope }
    }

    pub fn scope(&self) -> &AirbyteScope {
        &self.scope
    }

    pub fn compile_proposal(
        &self,
        catalog: &CatalogProjection,
        attempt: &SyncAttemptProjection,
        idempotency_key: &str,
    ) -> Result<AirbyteSyncResultProposal> {
        AirbyteSyncResultProposal::new(&self.scope, catalog, attempt, idempotency_key)
    }

    pub fn record(
        &self,
        log: &mut SyncResultRecordingLog,
        proposal: &AirbyteSyncResultProposal,
    ) -> Result<RecordedSyncResult> {
        proposal.validate_integrity()?;
        if proposal.scope_digest != self.scope.digest() {
            return Err(AirbyteSyncResultError::ScopeMismatch);
        }
        let existing = log.records.get(&proposal.idempotency_key_digest).cloned();
        match existing {
            Some(existing) if existing.proposal_digest == proposal.proposal_digest => {
                let replay = RecordedSyncResult::from_proposal(proposal, true);
                replay.validate_integrity()?;
                Ok(replay)
            }
            Some(_) => Err(AirbyteSyncResultError::ReplayConflict),
            None => {
                let recorded = RecordedSyncResult::from_proposal(proposal, false);
                recorded.validate_integrity()?;
                log.records
                    .insert(proposal.idempotency_key_digest.clone(), recorded.clone());
                Ok(recorded)
            }
        }
    }
}

#[cfg(test)]
mod consumer_tests {
    use super::*;
    use crate::model::{
        AirbyteScope, AttemptIdentity, CatalogProjection, JobIdentity, MissionId,
        PermissionSnapshot, ProjectId, ResourceIdentity, SecretReference, StreamIdentity,
        SyncAttemptProjection, WorkProductId, WorkspaceIdentity,
    };
    use crate::provider::{AirbyteCloudProvider, FakeTransport};
    use crate::service::{AirbyteRegistration, ProviderIdentity};

    fn scope() -> AirbyteScope {
        AirbyteScope::new(
            WorkspaceIdentity::new("workspace-1", "https://api.airbyte.com", 1).expect("workspace"),
            ResourceIdentity::new("source-1", 1).expect("source"),
            ResourceIdentity::new("destination-1", 1).expect("destination"),
            ResourceIdentity::new("connection-1", 1).expect("connection"),
            StreamIdentity::new("public", "users", 1, "b".repeat(64)).expect("stream"),
            JobIdentity::new("job-1", 1).expect("job"),
            AttemptIdentity::new("attempt-1", 1).expect("attempt"),
            MissionId::new("mission-1").expect("mission"),
            ProjectId::new("project-1").expect("project"),
            WorkProductId::new("work-product-1").expect("work product"),
        )
        .expect("scope")
    }

    fn read() -> (CatalogProjection, SyncAttemptProjection) {
        let scope = scope();
        let registration = AirbyteRegistration::new(
            crate::RegistrationId::new("registration-1").expect("registration"),
            scope.clone(),
            SecretReference::service_token("opaque-service-token", 1).expect("secret"),
            PermissionSnapshot::read_only(1).expect("permissions"),
            ProviderIdentity::new(1, "release-1").expect("provider"),
            1,
        )
        .expect("registration");
        let mut provider =
            AirbyteCloudProvider::new(registration, FakeTransport::from_scope(&scope))
                .expect("provider");
        (
            provider.read_catalog(100).expect("catalog"),
            provider.read_attempt("idempotency-1").expect("attempt"),
        )
    }

    #[test]
    fn proposal_and_recording_are_scope_bound_and_idempotent() {
        let (catalog, attempt) = read();
        let scope = scope();
        let consumer = MissionAirbyteSyncConsumer::new(scope);
        let proposal = consumer
            .compile_proposal(&catalog, &attempt, "idempotency-1")
            .expect("proposal");
        assert!(proposal.is_review_only());
        assert!(!proposal.can_be_adopted());
        assert!(!proposal.connected);
        let mut log = SyncResultRecordingLog::default();
        let first = consumer.record(&mut log, &proposal).expect("record");
        let replay = consumer.record(&mut log, &proposal).expect("replay");
        assert!(!first.replayed);
        assert!(replay.replayed);
        assert_eq!(log.len(), 1);
    }
}
