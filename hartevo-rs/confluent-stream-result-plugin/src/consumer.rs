//! Mission-scoped proposal and idempotent recording seam.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{
    ConfluentScope, ConnectorStatus, ConnectorStatusProjection, ConsumerGroupLagProjection,
    ConsumerGroupStatus, Digest, MetricProjection, ProjectionCompleteness,
};
use crate::{CONSUMER_ID, ConfluentStreamResultError, Result, validate_digest, validate_text};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    ReviewOnly,
}

/// A bounded, below-kernel Mission proposal. It contains statuses, digests,
/// timestamps, and completeness only; no records, metric values, or provider
/// receipt are carried.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfluentStreamResultProposal {
    pub consumer_id: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub connector_status: ConnectorStatus,
    pub consumer_group_status: ConsumerGroupStatus,
    pub connector_projection_digest: Digest,
    pub consumer_group_projection_digest: Digest,
    pub metric_projection_digest: Digest,
    pub lag_digest: Digest,
    pub throughput_digest: Option<Digest>,
    pub latency_digest: Option<Digest>,
    pub timestamps: Vec<i64>,
    pub completeness: ProjectionCompleteness,
    pub disposition: ProposalDisposition,
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
}

impl ConfluentStreamResultProposal {
    #[allow(clippy::too_many_arguments)]
    fn new(
        scope: &ConfluentScope,
        registration_digest: Digest,
        connector: &ConnectorStatusProjection,
        group: &ConsumerGroupLagProjection,
        metrics: &MetricProjection,
        idempotency_key: &str,
    ) -> Result<Self> {
        validate_digest(registration_digest.as_str(), "registrationDigest")?;
        validate_text(idempotency_key, "idempotencyKey", 256)?;
        let scope_digest = scope.digest();
        if connector.scope_digest != scope_digest {
            return Err(ConfluentStreamResultError::ScopeMismatch);
        }
        if group.scope_digest != scope_digest {
            return Err(ConfluentStreamResultError::ScopeMismatch);
        }
        if metrics.scope_digest != scope_digest {
            return Err(ConfluentStreamResultError::ScopeMismatch);
        }
        connector.validate_integrity()?;
        group.validate_integrity()?;
        metrics.validate_integrity()?;
        let completeness = connector
            .completeness
            .combine(group.completeness)
            .combine(metrics.completeness);
        let mut timestamps = group.timestamps.clone();
        timestamps.extend(metrics.timestamps.iter().copied());
        timestamps.push(connector.observed_at_epoch_seconds);
        timestamps.sort_unstable();
        timestamps.dedup();
        if timestamps.len() > crate::MAX_TIMESTAMP_COUNT {
            return Err(ConfluentStreamResultError::InvalidProjection);
        }
        let mut proposal = Self {
            consumer_id: CONSUMER_ID.to_owned(),
            scope_digest,
            registration_digest,
            connector_status: connector.status,
            consumer_group_status: group.status,
            connector_projection_digest: connector.projection_digest.clone(),
            consumer_group_projection_digest: group.projection_digest.clone(),
            metric_projection_digest: metrics.projection_digest.clone(),
            lag_digest: group.lag_digest.clone(),
            throughput_digest: metrics.throughput_digest.clone(),
            latency_digest: metrics.latency_digest.clone(),
            timestamps,
            completeness,
            disposition: ProposalDisposition::ReviewOnly,
            idempotency_key_digest: Digest::from_text(idempotency_key),
            proposal_digest: Digest::from_text("unsealed-confluent-proposal"),
            connected: false,
            native: false,
            provider_receipt: false,
            outcome_adopted: false,
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.validate_integrity()?;
        Ok(proposal)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.consumer_id != CONSUMER_ID
            || self.disposition != ProposalDisposition::ReviewOnly
            || self.connected
            || self.native
            || self.provider_receipt
            || self.outcome_adopted
            || self.timestamps.len() > crate::MAX_TIMESTAMP_COUNT
            || self.timestamps.iter().any(|timestamp| *timestamp <= 0)
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(ConfluentStreamResultError::InvalidProjection);
        }
        validate_digest(self.scope_digest.as_str(), "scopeDigest")?;
        validate_digest(self.registration_digest.as_str(), "registrationDigest")?;
        validate_digest(
            self.connector_projection_digest.as_str(),
            "connectorProjectionDigest",
        )?;
        validate_digest(
            self.consumer_group_projection_digest.as_str(),
            "consumerGroupProjectionDigest",
        )?;
        validate_digest(
            self.metric_projection_digest.as_str(),
            "metricProjectionDigest",
        )?;
        validate_digest(self.lag_digest.as_str(), "lagDigest")?;
        validate_digest(self.idempotency_key_digest.as_str(), "idempotencyKeyDigest")?;
        for digest in [&self.throughput_digest, &self.latency_digest]
            .into_iter()
            .flatten()
        {
            digest.validate()?;
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub fn computed_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "confluent-stream-result-proposal/v1",
            &[
                ("consumer_id", self.consumer_id.clone()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("connector_status", format!("{:?}", self.connector_status)),
                ("group_status", format!("{:?}", self.consumer_group_status)),
                (
                    "connector_projection",
                    self.connector_projection_digest.as_str().to_owned(),
                ),
                (
                    "group_projection",
                    self.consumer_group_projection_digest.as_str().to_owned(),
                ),
                (
                    "metric_projection",
                    self.metric_projection_digest.as_str().to_owned(),
                ),
                ("lag", self.lag_digest.as_str().to_owned()),
                (
                    "throughput",
                    self.throughput_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "latency",
                    self.latency_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "timestamps",
                    serde_json::to_string(&self.timestamps).expect("timestamps serialize"),
                ),
                ("completeness", format!("{:?}", self.completeness)),
                ("disposition", format!("{:?}", self.disposition)),
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("connected", "false".to_owned()),
                ("native", "false".to_owned()),
                ("provider_receipt", "false".to_owned()),
                ("outcome_adopted", "false".to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedStreamResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub recording_digest: Digest,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
}

impl RecordedStreamResult {
    fn from_proposal(proposal: &ConfluentStreamResultProposal, replayed: bool) -> Self {
        let mut recorded = Self {
            idempotency_key_digest: proposal.idempotency_key_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            recording_digest: Digest::from_text("unsealed-confluent-recording"),
            replayed,
            connected: false,
            native: false,
            provider_receipt: false,
            outcome_adopted: false,
        };
        recorded.recording_digest = Digest::from_serialized(&(
            &recorded.idempotency_key_digest,
            &recorded.proposal_digest,
            recorded.replayed,
            false,
            false,
            false,
            false,
        ));
        recorded
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.provider_receipt
            || self.outcome_adopted
            || self.recording_digest != self.calculate_digest()
        {
            return Err(ConfluentStreamResultError::TamperedEvidence);
        }
        validate_digest(self.idempotency_key_digest.as_str(), "idempotencyKeyDigest")?;
        validate_digest(self.proposal_digest.as_str(), "proposalDigest")?;
        validate_digest(self.recording_digest.as_str(), "recordingDigest")
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.idempotency_key_digest,
            &self.proposal_digest,
            self.replayed,
            false,
            false,
            false,
            false,
        ))
    }
}

#[derive(Clone, Debug, Default)]
pub struct StreamResultRecordingLog {
    records: BTreeMap<Digest, RecordedStreamResult>,
}

impl StreamResultRecordingLog {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, idempotency_key_digest: &Digest) -> Option<&RecordedStreamResult> {
        self.records.get(idempotency_key_digest)
    }
}

/// Mission consumer bound to one exact scope. It never adopts an Outcome or
/// claims a provider receipt.
#[derive(Clone, Debug)]
pub struct MissionConfluentStreamConsumer {
    scope: ConfluentScope,
}

impl MissionConfluentStreamConsumer {
    pub fn new(scope: ConfluentScope) -> Self {
        Self { scope }
    }

    pub fn scope(&self) -> &ConfluentScope {
        &self.scope
    }

    pub fn compile_proposal(
        &self,
        registration_digest: Digest,
        connector: &ConnectorStatusProjection,
        group: &ConsumerGroupLagProjection,
        metrics: &MetricProjection,
        idempotency_key: &str,
    ) -> Result<ConfluentStreamResultProposal> {
        self.compile_proposal_for_mission_revision(
            registration_digest,
            connector,
            group,
            metrics,
            idempotency_key,
            self.scope.mission.revision,
        )
    }

    pub fn compile_proposal_for_mission_revision(
        &self,
        registration_digest: Digest,
        connector: &ConnectorStatusProjection,
        group: &ConsumerGroupLagProjection,
        metrics: &MetricProjection,
        idempotency_key: &str,
        mission_revision: u64,
    ) -> Result<ConfluentStreamResultProposal> {
        self.scope.validate()?;
        if mission_revision != self.scope.mission.revision {
            return Err(ConfluentStreamResultError::StaleMissionRevision);
        }
        if connector.scope_digest != self.scope.digest()
            || group.scope_digest != self.scope.digest()
            || metrics.scope_digest != self.scope.digest()
        {
            return Err(self.classify_scope_mismatch(connector, group, metrics));
        }
        ConfluentStreamResultProposal::new(
            &self.scope,
            registration_digest,
            connector,
            group,
            metrics,
            idempotency_key,
        )
    }

    pub fn record(
        &self,
        log: &mut StreamResultRecordingLog,
        proposal: &ConfluentStreamResultProposal,
    ) -> Result<RecordedStreamResult> {
        proposal.validate_integrity()?;
        if proposal.scope_digest != self.scope.digest() {
            return Err(ConfluentStreamResultError::ScopeMismatch);
        }
        if let Some(existing) = log.records.get(&proposal.idempotency_key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ConfluentStreamResultError::ReplayConflict);
            }
            let replayed = RecordedStreamResult::from_proposal(proposal, true);
            replayed.validate_integrity()?;
            return Ok(replayed);
        }
        let recorded = RecordedStreamResult::from_proposal(proposal, false);
        recorded.validate_integrity()?;
        log.records
            .insert(proposal.idempotency_key_digest.clone(), recorded.clone());
        Ok(recorded)
    }

    fn classify_scope_mismatch(
        &self,
        connector: &ConnectorStatusProjection,
        group: &ConsumerGroupLagProjection,
        metrics: &MetricProjection,
    ) -> ConfluentStreamResultError {
        if connector.scope_digest != self.scope.digest() {
            return ConfluentStreamResultError::ScopeMismatch;
        }
        if group.scope_digest != self.scope.digest() {
            return ConfluentStreamResultError::StaleMissionRevision;
        }
        if metrics.scope_digest != self.scope.digest() {
            return ConfluentStreamResultError::MetricWindowMismatch;
        }
        ConfluentStreamResultError::ScopeMismatch
    }
}
