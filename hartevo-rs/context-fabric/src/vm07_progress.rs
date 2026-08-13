//! Content-free identity and cursor primitives for the VM-07 read-only plan.
//!
//! The Runtime Adapter owns request execution.  Context Fabric owns the
//! durable identity that lets the Application layer resume that execution
//! without persisting research text, provider payloads, or a heartbeat as
//! useful progress.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{MissionId, ProjectId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const VM07_MISSION_ID: &str = "VM-07";
pub const VM07_MISSION_VERSION: u32 = 3;
pub const VM07_PACK_CONTRACT_VERSION: &str = "vm07-market-evidence-pack/v1";
pub const VM07_PROGRESS_SCHEMA_VERSION: u32 = 1;
pub const VM07_PROGRESS_SCHEMA: &str = "hartevo.vm07-useful-progress/v1";

/// The only source classes that the Runtime may request for VM-07.
///
/// `decision.evaluate` and `outcome.review` are deliberately absent: they are
/// local Application/Human routes, not Runtime observations.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Vm07ObservationSourceClass {
    ResearchDiscovery,
    SearchMeasurement,
    GroundTruthMeasurement,
    MarketplaceRead,
}

impl Vm07ObservationSourceClass {
    pub const fn capability_id(self) -> &'static str {
        match self {
            Self::ResearchDiscovery => "research.discover",
            Self::SearchMeasurement => "search.measure",
            Self::GroundTruthMeasurement => "ground_truth.measure",
            Self::MarketplaceRead => "marketplace.read",
        }
    }

    pub const fn checkpoint_id(self) -> &'static str {
        match self {
            Self::ResearchDiscovery => "evidence_plan",
            Self::SearchMeasurement => "scoped_collection",
            Self::GroundTruthMeasurement => "confirmed_estimated_inferred_unknown_conflict",
            Self::MarketplaceRead => "scenarios_risks_counterevidence",
        }
    }

    pub const fn ordinal(self) -> u32 {
        match self {
            Self::ResearchDiscovery => 1,
            Self::SearchMeasurement => 2,
            Self::GroundTruthMeasurement => 3,
            Self::MarketplaceRead => 4,
        }
    }

    pub const fn all() -> [Self; 4] {
        [
            Self::ResearchDiscovery,
            Self::SearchMeasurement,
            Self::GroundTruthMeasurement,
            Self::MarketplaceRead,
        ]
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07ContractFence {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub contract_digest: String,
    pub mission_revision: u64,
    pub pack_revision: u64,
}

impl Vm07ContractFence {
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        contract_digest: impl Into<String>,
        mission_revision: u64,
        pack_revision: u64,
    ) -> Result<Self, Vm07ProgressIdentityError> {
        let fence = Self {
            tenant_id,
            project_id,
            mission_id,
            contract_digest: contract_digest.into(),
            mission_revision,
            pack_revision,
        };
        fence.validate()?;
        Ok(fence)
    }

    pub fn validate(&self) -> Result<(), Vm07ProgressIdentityError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || !is_sha256(&self.contract_digest)
            || self.mission_revision == 0
            || self.pack_revision == 0
        {
            return Err(Vm07ProgressIdentityError::InvalidFence);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, Vm07ProgressIdentityError> {
        self.validate()?;
        digest_json(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vm07ProgressCursor {
    /// One-based ordinal of the next VM-07 Runtime route.  The value is one
    /// greater than the final route after the plan is exhausted.
    pub next_step_ordinal: u32,
    /// One-based identity sequence for the next request.  A fresh plan starts
    /// at one and the value remains one greater than the last issued request.
    pub next_request_sequence: u32,
    pub requests_issued_in_step: u32,
    pub requests_issued: u32,
    pub requests_completed: u32,
    pub useful_observation_count: u32,
}

impl Vm07ProgressCursor {
    pub fn validate(&self) -> Result<(), Vm07ProgressIdentityError> {
        if self.next_step_ordinal == 0
            || self.next_request_sequence == 0
            || self.requests_completed > self.requests_issued
            || self.useful_observation_count > self.requests_completed
        {
            return Err(Vm07ProgressIdentityError::InvalidCursor);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Vm07UsefulProgressKind {
    /// The first concrete operation is ready for dispatch.  This is useful
    /// progress; it is not a heartbeat, loading state, or empty status tick.
    ObservationRequestIssued,
    ObservationRecorded,
    PlanCompleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DurableUsefulProgressIdentity {
    pub schema: String,
    pub schema_version: u32,
    pub scope: Vm07ContractFence,
    pub plan_id: String,
    pub plan_digest: String,
    pub request_id: String,
    pub request_sequence: u32,
    pub step_ordinal: u32,
    pub source_class: Option<Vm07ObservationSourceClass>,
    pub kind: Vm07UsefulProgressKind,
    pub observation_id: Option<String>,
    pub cursor: Vm07ProgressCursor,
    pub progress_digest: String,
    pub identity_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<DateTime<Utc>>,
}

impl DurableUsefulProgressIdentity {
    #[allow(clippy::too_many_arguments, reason = "identity binds every resume fence in one value")]
    pub fn issue_request(
        scope: Vm07ContractFence,
        plan_id: impl Into<String>,
        plan_digest: impl Into<String>,
        request_id: impl Into<String>,
        request_sequence: u32,
        step_ordinal: u32,
        source_class: Vm07ObservationSourceClass,
        cursor: Vm07ProgressCursor,
        recorded_at: DateTime<Utc>,
    ) -> Result<Self, Vm07ProgressIdentityError> {
        Self::seal(
            scope,
            plan_id,
            plan_digest,
            request_id,
            request_sequence,
            step_ordinal,
            Some(source_class),
            Vm07UsefulProgressKind::ObservationRequestIssued,
            None,
            cursor,
            Some(recorded_at),
        )
    }

    #[allow(clippy::too_many_arguments, reason = "identity binds every observation fence in one value")]
    pub fn record_observation(
        scope: Vm07ContractFence,
        plan_id: impl Into<String>,
        plan_digest: impl Into<String>,
        request_id: impl Into<String>,
        request_sequence: u32,
        step_ordinal: u32,
        source_class: Vm07ObservationSourceClass,
        observation_id: impl Into<String>,
        cursor: Vm07ProgressCursor,
        recorded_at: DateTime<Utc>,
    ) -> Result<Self, Vm07ProgressIdentityError> {
        Self::seal(
            scope,
            plan_id,
            plan_digest,
            request_id,
            request_sequence,
            step_ordinal,
            Some(source_class),
            Vm07UsefulProgressKind::ObservationRecorded,
            Some(observation_id.into()),
            cursor,
            Some(recorded_at),
        )
    }

    pub fn complete_plan(
        scope: Vm07ContractFence,
        plan_id: impl Into<String>,
        plan_digest: impl Into<String>,
        request_id: impl Into<String>,
        request_sequence: u32,
        step_ordinal: u32,
        cursor: Vm07ProgressCursor,
        recorded_at: DateTime<Utc>,
    ) -> Result<Self, Vm07ProgressIdentityError> {
        Self::seal(
            scope,
            plan_id,
            plan_digest,
            request_id,
            request_sequence,
            step_ordinal,
            None,
            Vm07UsefulProgressKind::PlanCompleted,
            None,
            cursor,
            Some(recorded_at),
        )
    }

    #[allow(clippy::too_many_arguments, reason = "one constructor keeps identity sealing uniform")]
    fn seal(
        scope: Vm07ContractFence,
        plan_id: impl Into<String>,
        plan_digest: impl Into<String>,
        request_id: impl Into<String>,
        request_sequence: u32,
        step_ordinal: u32,
        source_class: Option<Vm07ObservationSourceClass>,
        kind: Vm07UsefulProgressKind,
        observation_id: Option<String>,
        cursor: Vm07ProgressCursor,
        recorded_at: Option<DateTime<Utc>>,
    ) -> Result<Self, Vm07ProgressIdentityError> {
        let plan_id = plan_id.into();
        let plan_digest = plan_digest.into();
        let request_id = request_id.into();
        let mut identity = Self {
            schema: VM07_PROGRESS_SCHEMA.into(),
            schema_version: VM07_PROGRESS_SCHEMA_VERSION,
            scope,
            plan_id,
            plan_digest,
            request_id,
            request_sequence,
            step_ordinal,
            source_class,
            kind,
            observation_id,
            cursor,
            progress_digest: String::new(),
            identity_digest: String::new(),
            recorded_at,
        };
        identity.progress_digest = identity.calculate_progress_digest()?;
        identity.identity_digest = identity.calculate_identity_digest()?;
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), Vm07ProgressIdentityError> {
        self.scope.validate()?;
        if self.schema != VM07_PROGRESS_SCHEMA
            || self.schema_version != VM07_PROGRESS_SCHEMA_VERSION
            || !is_bounded_identifier(&self.plan_id)
            || !is_sha256(&self.plan_digest)
            || !is_bounded_identifier(&self.request_id)
            || !is_sha256(&self.progress_digest)
            || !is_sha256(&self.identity_digest)
            || self.request_sequence == 0
            || self.step_ordinal == 0
        {
            return Err(Vm07ProgressIdentityError::InvalidIdentity);
        }
        self.cursor.validate()?;
        match self.kind {
            Vm07UsefulProgressKind::ObservationRequestIssued => {
                if self.source_class.is_none() || self.observation_id.is_some() {
                    return Err(Vm07ProgressIdentityError::InvalidIdentity);
                }
            }
            Vm07UsefulProgressKind::ObservationRecorded => {
                if self.source_class.is_none()
                    || !self
                        .observation_id
                        .as_deref()
                        .is_some_and(is_bounded_identifier)
                {
                    return Err(Vm07ProgressIdentityError::InvalidIdentity);
                }
            }
            Vm07UsefulProgressKind::PlanCompleted => {
                if self.source_class.is_some() || self.observation_id.is_some() {
                    return Err(Vm07ProgressIdentityError::InvalidIdentity);
                }
            }
        }
        if self.progress_digest != self.calculate_progress_digest()?
            || self.identity_digest != self.calculate_identity_digest()?
        {
            return Err(Vm07ProgressIdentityError::DigestMismatch);
        }
        Ok(())
    }

    fn calculate_progress_digest(&self) -> Result<String, Vm07ProgressIdentityError> {
        let input = BTreeMap::from([
            ("kind", serde_json::to_value(self.kind)?),
            ("observationId", serde_json::to_value(&self.observation_id)?),
            ("planDigest", serde_json::to_value(&self.plan_digest)?),
            ("requestId", serde_json::to_value(&self.request_id)?),
            (
                "requestSequence",
                serde_json::to_value(self.request_sequence)?,
            ),
            ("sourceClass", serde_json::to_value(self.source_class)?),
            ("stepOrdinal", serde_json::to_value(self.step_ordinal)?),
        ]);
        digest_json(&input)
    }

    fn calculate_identity_digest(&self) -> Result<String, Vm07ProgressIdentityError> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or(Vm07ProgressIdentityError::InvalidIdentity)?
            .insert("identityDigest".into(), serde_json::Value::String(String::new()));
        digest_json(&value)
    }
}

#[derive(Debug, Error)]
pub enum Vm07ProgressIdentityError {
    #[error("VM-07 progress scope fence is invalid")]
    InvalidFence,
    #[error("VM-07 progress cursor is invalid")]
    InvalidCursor,
    #[error("VM-07 useful-progress identity is invalid")]
    InvalidIdentity,
    #[error("VM-07 useful-progress identity digest does not match its fields")]
    DigestMismatch,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn digest_json(value: &impl Serialize) -> Result<String, Vm07ProgressIdentityError> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0)
}
