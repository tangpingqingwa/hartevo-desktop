//! Runtime-side scheduler fencing without process or Application wiring.
//!
//! [`RuntimeSchedulerGate`] is the narrow seam between a scheduler dispatch
//! ticket and the existing [`super::StdioRuntime`] protocol methods. It binds
//! one schedule lease to one generation of [`super::RuntimeMapping`], accepts
//! only a turn dispatch for that exact mapping, and records terminal outcomes
//! by attempt digest. The gate never starts a process or retries a protocol
//! operation. Callers must record an uncertain protocol outcome explicitly;
//! uncertain attempts remain replay-suppressed across takeover.

use std::collections::BTreeMap;

use hartevo_mission_scheduler::os_lifecycle::{LeaseFence, ReplayDecision};
use thiserror::Error;

use super::{RuntimeMapping, RuntimeTurnDispatch};

const DIGEST_HEX_LENGTH: usize = 64;

/// The immutable schedule-to-runtime binding required before a Runtime turn
/// can be authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeScheduleBinding {
    schedule_id_digest: String,
    fence: LeaseFence,
    mapping: RuntimeMapping,
    mapping_digest: String,
}

impl RuntimeScheduleBinding {
    /// Creates a binding for a thread mapping that has not started a turn.
    pub fn new(
        schedule_id_digest: impl Into<String>,
        fence: LeaseFence,
        mapping: RuntimeMapping,
    ) -> Result<Self, RuntimeSchedulerError> {
        let schedule_id_digest = schedule_id_digest.into();
        validate_digest(&schedule_id_digest)
            .then_some(())
            .ok_or(RuntimeSchedulerError::InvalidScheduleId)?;
        validate_fence(&fence)?;
        validate_thread_mapping(&mapping)?;
        let mapping_digest = mapping
            .digest()
            .map_err(|_| RuntimeSchedulerError::InvalidRuntimeMapping)?;
        Ok(Self {
            schedule_id_digest,
            fence,
            mapping,
            mapping_digest,
        })
    }

    pub fn schedule_id_digest(&self) -> &str {
        &self.schedule_id_digest
    }

    pub const fn fence(&self) -> &LeaseFence {
        &self.fence
    }

    pub const fn mapping(&self) -> &RuntimeMapping {
        &self.mapping
    }

    pub fn mapping_digest(&self) -> &str {
        &self.mapping_digest
    }

    fn replace_after_takeover(
        &self,
        fence: LeaseFence,
        mapping: RuntimeMapping,
    ) -> Result<Self, RuntimeSchedulerError> {
        validate_fence(&fence)?;
        if fence.generation <= self.fence.generation {
            return Err(RuntimeSchedulerError::LeaseGenerationRegression);
        }
        if mapping.runtime_generation <= self.mapping.runtime_generation {
            return Err(RuntimeSchedulerError::RuntimeGenerationRegression);
        }
        if mapping.project_id != self.mapping.project_id
            || mapping.mission_id != self.mapping.mission_id
        {
            return Err(RuntimeSchedulerError::MappingScopeMismatch);
        }
        Self::new(self.schedule_id_digest.clone(), fence, mapping)
    }
}

/// A single-use authorization capability for one Runtime attempt.
///
/// The capability contains only digests and a generation fence. It is
/// invalidated when a failed attempt is re-authorized or when its lease is
/// taken over by a newer generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAttemptPermit {
    attempt_id_digest: String,
    schedule_id_digest: String,
    mapping_digest: String,
    fence: LeaseFence,
    sequence: u64,
}

impl RuntimeAttemptPermit {
    pub fn attempt_id_digest(&self) -> &str {
        &self.attempt_id_digest
    }

    pub fn schedule_id_digest(&self) -> &str {
        &self.schedule_id_digest
    }

    pub fn mapping_digest(&self) -> &str {
        &self.mapping_digest
    }

    pub const fn fence(&self) -> &LeaseFence {
        &self.fence
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAttemptStatus {
    Running,
    Failed,
    Completed,
    Uncertain,
}

impl RuntimeAttemptStatus {
    const fn replay_decision(self) -> ReplayDecision {
        match self {
            Self::Running | Self::Uncertain => ReplayDecision::SuppressedUncertain,
            Self::Failed => ReplayDecision::Allowed,
            Self::Completed => ReplayDecision::SuppressedCompleted,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAttemptView {
    pub attempt_id_digest: String,
    pub schedule_id_digest: String,
    pub status: RuntimeAttemptStatus,
    pub replay: ReplayDecision,
    pub lease_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDispatchReceipt {
    pub attempt_id_digest: String,
    pub schedule_id_digest: String,
    pub dispatch_mapping_digest: String,
    pub request_digest: String,
    pub response_digest: String,
}

impl RuntimeDispatchReceipt {
    fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeTakeoverReport {
    pub previous_lease_generation: u64,
    pub lease_generation: u64,
    pub fenced_running_attempts: usize,
}

#[derive(Debug)]
struct RuntimeAttemptRecord {
    permit: RuntimeAttemptPermit,
    status: RuntimeAttemptStatus,
    receipt: Option<RuntimeDispatchReceipt>,
}

/// A process-free Runtime dispatch gate.
///
/// The caller obtains a permit immediately before calling
/// `StdioRuntime::start_mapped_turn`. If the protocol write or its outcome is
/// ambiguous, the caller must call [`Self::record_uncertain`]. That state is
/// deliberately terminal for replay, including after a lease takeover.
#[derive(Debug)]
pub struct RuntimeSchedulerGate {
    binding: RuntimeScheduleBinding,
    attempts: BTreeMap<String, RuntimeAttemptRecord>,
    next_permit_sequence: u64,
}

impl RuntimeSchedulerGate {
    pub fn new(binding: RuntimeScheduleBinding) -> Self {
        Self {
            binding,
            attempts: BTreeMap::new(),
            next_permit_sequence: 0,
        }
    }

    pub const fn binding(&self) -> &RuntimeScheduleBinding {
        &self.binding
    }

    /// Authorizes a fresh Runtime turn for the exact bound thread mapping.
    pub fn authorize_turn(
        &mut self,
        attempt_id_digest: &str,
        mapping: &RuntimeMapping,
    ) -> Result<RuntimeAttemptPermit, RuntimeSchedulerError> {
        validate_attempt_id(attempt_id_digest)?;
        self.validate_current_mapping(mapping)?;
        let permit = self.make_permit(attempt_id_digest)?;
        if let Some(existing) = self.attempts.get_mut(attempt_id_digest) {
            return match existing.status {
                RuntimeAttemptStatus::Running => Err(RuntimeSchedulerError::AttemptRunning),
                RuntimeAttemptStatus::Uncertain => {
                    Err(RuntimeSchedulerError::UncertainReplaySuppressed)
                }
                RuntimeAttemptStatus::Completed => {
                    Err(RuntimeSchedulerError::CompletedReplaySuppressed)
                }
                RuntimeAttemptStatus::Failed => {
                    existing.permit = permit.clone();
                    existing.status = RuntimeAttemptStatus::Running;
                    existing.receipt = None;
                    Ok(permit)
                }
            };
        }
        self.attempts.insert(
            attempt_id_digest.into(),
            RuntimeAttemptRecord {
                permit: permit.clone(),
                status: RuntimeAttemptStatus::Running,
                receipt: None,
            },
        );
        Ok(permit)
    }

    /// Accepts the response of `start_mapped_turn` without marking business
    /// completion. A second exact observation is idempotent; a different
    /// response for the same attempt fails closed.
    pub fn accept_dispatch(
        &mut self,
        permit: &RuntimeAttemptPermit,
        dispatch: &RuntimeTurnDispatch,
    ) -> Result<RuntimeDispatchReceipt, RuntimeSchedulerError> {
        let receipt = self.validate_dispatch(permit, dispatch)?;
        let record = self.record_for_permit_mut(permit)?;
        match record.status {
            RuntimeAttemptStatus::Running => {
                if let Some(existing) = &record.receipt {
                    if !existing.matches(&receipt) {
                        return Err(RuntimeSchedulerError::DispatchConflict);
                    }
                    return Ok(existing.clone());
                }
                record.receipt = Some(receipt.clone());
                Ok(receipt)
            }
            RuntimeAttemptStatus::Failed => Err(RuntimeSchedulerError::AttemptTerminalConflict),
            RuntimeAttemptStatus::Completed => {
                if record
                    .receipt
                    .as_ref()
                    .is_some_and(|existing| existing.matches(&receipt))
                {
                    Ok(receipt)
                } else {
                    Err(RuntimeSchedulerError::DispatchConflict)
                }
            }
            RuntimeAttemptStatus::Uncertain => {
                Err(RuntimeSchedulerError::UncertainReplaySuppressed)
            }
        }
    }

    /// Records a successfully completed Runtime turn after its exact
    /// dispatch has been accepted.
    pub fn record_completed(
        &mut self,
        permit: &RuntimeAttemptPermit,
        dispatch: &RuntimeTurnDispatch,
    ) -> Result<RuntimeDispatchReceipt, RuntimeSchedulerError> {
        let receipt = self.accept_dispatch(permit, dispatch)?;
        let record = self.record_for_permit_mut(permit)?;
        match record.status {
            RuntimeAttemptStatus::Running => {
                record.status = RuntimeAttemptStatus::Completed;
                Ok(receipt)
            }
            RuntimeAttemptStatus::Completed => Ok(receipt),
            RuntimeAttemptStatus::Uncertain => {
                Err(RuntimeSchedulerError::UncertainReplaySuppressed)
            }
            RuntimeAttemptStatus::Failed => Err(RuntimeSchedulerError::AttemptTerminalConflict),
        }
    }

    /// Records an ambiguous protocol/process outcome. This is terminal and
    /// intentionally does not attempt to interrupt, inspect, or replay it.
    pub fn record_uncertain(
        &mut self,
        permit: &RuntimeAttemptPermit,
    ) -> Result<(), RuntimeSchedulerError> {
        let record = self.record_for_permit_mut(permit)?;
        match record.status {
            RuntimeAttemptStatus::Running => {
                record.status = RuntimeAttemptStatus::Uncertain;
                Ok(())
            }
            RuntimeAttemptStatus::Uncertain => Ok(()),
            RuntimeAttemptStatus::Failed | RuntimeAttemptStatus::Completed => {
                Err(RuntimeSchedulerError::AttemptTerminalConflict)
            }
        }
    }

    /// Records a definitive, retryable Runtime failure. A later call to
    /// `authorize_turn` may obtain a new permit for the same attempt digest.
    pub fn record_failed(
        &mut self,
        permit: &RuntimeAttemptPermit,
    ) -> Result<(), RuntimeSchedulerError> {
        let record = self.record_for_permit_mut(permit)?;
        match record.status {
            RuntimeAttemptStatus::Running | RuntimeAttemptStatus::Failed => {
                record.status = RuntimeAttemptStatus::Failed;
                Ok(())
            }
            RuntimeAttemptStatus::Uncertain => {
                Err(RuntimeSchedulerError::UncertainReplaySuppressed)
            }
            RuntimeAttemptStatus::Completed => Err(RuntimeSchedulerError::AttemptTerminalConflict),
        }
    }

    pub fn replay_decision(
        &self,
        attempt_id_digest: &str,
    ) -> Result<ReplayDecision, RuntimeSchedulerError> {
        validate_attempt_id(attempt_id_digest)?;
        self.attempts
            .get(attempt_id_digest)
            .map(|record| record.status.replay_decision())
            .ok_or(RuntimeSchedulerError::AttemptNotFound)
    }

    pub fn attempt(
        &self,
        attempt_id_digest: &str,
    ) -> Result<RuntimeAttemptView, RuntimeSchedulerError> {
        validate_attempt_id(attempt_id_digest)?;
        let record = self
            .attempts
            .get(attempt_id_digest)
            .ok_or(RuntimeSchedulerError::AttemptNotFound)?;
        Ok(RuntimeAttemptView {
            attempt_id_digest: attempt_id_digest.into(),
            schedule_id_digest: record.permit.schedule_id_digest.clone(),
            status: record.status,
            replay: record.status.replay_decision(),
            lease_generation: record.permit.fence.generation,
        })
    }

    /// Replaces the binding with a strictly newer lease and Runtime
    /// generation. Any Running attempt is fenced as Uncertain before the new
    /// binding becomes active, so takeover cannot replay a possibly accepted
    /// protocol request.
    pub fn take_over(
        &mut self,
        fence: LeaseFence,
        mapping: RuntimeMapping,
    ) -> Result<RuntimeTakeoverReport, RuntimeSchedulerError> {
        let next_binding = self.binding.replace_after_takeover(fence, mapping)?;
        let previous_lease_generation = self.binding.fence.generation;
        let lease_generation = next_binding.fence.generation;
        let mut fenced_running_attempts = 0;
        for record in self.attempts.values_mut() {
            if record.status == RuntimeAttemptStatus::Running {
                record.status = RuntimeAttemptStatus::Uncertain;
                fenced_running_attempts += 1;
            }
        }
        self.binding = next_binding;
        Ok(RuntimeTakeoverReport {
            previous_lease_generation,
            lease_generation,
            fenced_running_attempts,
        })
    }

    fn make_permit(
        &mut self,
        attempt_id_digest: &str,
    ) -> Result<RuntimeAttemptPermit, RuntimeSchedulerError> {
        self.next_permit_sequence = self
            .next_permit_sequence
            .checked_add(1)
            .ok_or(RuntimeSchedulerError::PermitSequenceExhausted)?;
        Ok(RuntimeAttemptPermit {
            attempt_id_digest: attempt_id_digest.into(),
            schedule_id_digest: self.binding.schedule_id_digest.clone(),
            mapping_digest: self.binding.mapping_digest.clone(),
            fence: self.binding.fence.clone(),
            sequence: self.next_permit_sequence,
        })
    }

    fn validate_current_mapping(
        &self,
        mapping: &RuntimeMapping,
    ) -> Result<(), RuntimeSchedulerError> {
        validate_thread_mapping(mapping)?;
        if mapping != &self.binding.mapping {
            return Err(RuntimeSchedulerError::MappingScopeMismatch);
        }
        Ok(())
    }

    fn validate_dispatch(
        &self,
        permit: &RuntimeAttemptPermit,
        dispatch: &RuntimeTurnDispatch,
    ) -> Result<RuntimeDispatchReceipt, RuntimeSchedulerError> {
        self.validate_permit_shape(permit)?;
        dispatch
            .mapping
            .validate()
            .map_err(|_| RuntimeSchedulerError::InvalidRuntimeMapping)?;
        if dispatch.mapping.runtime_turn_id.is_none() {
            return Err(RuntimeSchedulerError::DispatchMappingMissingTurn);
        }
        let mut thread_mapping = dispatch.mapping.clone();
        thread_mapping.runtime_turn_id = None;
        self.validate_current_mapping(&thread_mapping)?;
        validate_digest(&dispatch.request_digest)
            .then_some(())
            .ok_or(RuntimeSchedulerError::InvalidDispatchDigest)?;
        validate_digest(&dispatch.response_digest)
            .then_some(())
            .ok_or(RuntimeSchedulerError::InvalidDispatchDigest)?;
        let dispatch_mapping_digest = dispatch
            .mapping
            .digest()
            .map_err(|_| RuntimeSchedulerError::InvalidRuntimeMapping)?;
        Ok(RuntimeDispatchReceipt {
            attempt_id_digest: permit.attempt_id_digest.clone(),
            schedule_id_digest: permit.schedule_id_digest.clone(),
            dispatch_mapping_digest,
            request_digest: dispatch.request_digest.clone(),
            response_digest: dispatch.response_digest.clone(),
        })
    }

    fn validate_permit_shape(
        &self,
        permit: &RuntimeAttemptPermit,
    ) -> Result<(), RuntimeSchedulerError> {
        validate_attempt_id(&permit.attempt_id_digest)?;
        validate_fence(&permit.fence)?;
        if permit.sequence == 0 {
            return Err(RuntimeSchedulerError::InvalidPermit);
        }
        if permit.schedule_id_digest != self.binding.schedule_id_digest
            || permit.mapping_digest != self.binding.mapping_digest
            || permit.fence != self.binding.fence
        {
            return Err(RuntimeSchedulerError::LeaseFenceLost);
        }
        Ok(())
    }

    fn record_for_permit_mut(
        &mut self,
        permit: &RuntimeAttemptPermit,
    ) -> Result<&mut RuntimeAttemptRecord, RuntimeSchedulerError> {
        self.validate_permit_shape(permit)?;
        let record = self
            .attempts
            .get_mut(&permit.attempt_id_digest)
            .ok_or(RuntimeSchedulerError::AttemptNotFound)?;
        if record.permit != *permit {
            return Err(RuntimeSchedulerError::AttemptPermitLost);
        }
        Ok(record)
    }
}

fn validate_thread_mapping(mapping: &RuntimeMapping) -> Result<(), RuntimeSchedulerError> {
    mapping
        .validate()
        .map_err(|_| RuntimeSchedulerError::InvalidRuntimeMapping)?;
    if mapping.runtime_turn_id.is_some() {
        return Err(RuntimeSchedulerError::MappingHasActiveTurn);
    }
    Ok(())
}

fn validate_fence(fence: &LeaseFence) -> Result<(), RuntimeSchedulerError> {
    fence
        .validate()
        .map_err(|_| RuntimeSchedulerError::InvalidLeaseFence)
}

fn validate_attempt_id(attempt_id_digest: &str) -> Result<(), RuntimeSchedulerError> {
    validate_digest(attempt_id_digest)
        .then_some(())
        .ok_or(RuntimeSchedulerError::InvalidAttemptId)
}

fn validate_digest(value: &str) -> bool {
    value.len() == DIGEST_HEX_LENGTH && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RuntimeSchedulerError {
    #[error("runtime schedule identifier digest is invalid")]
    InvalidScheduleId,
    #[error("runtime lease owner/token/generation fence is invalid")]
    InvalidLeaseFence,
    #[error("runtime schedule lease fence is no longer current")]
    LeaseFenceLost,
    #[error("runtime lease generation must strictly increase on takeover")]
    LeaseGenerationRegression,
    #[error("runtime mapping is invalid for scheduler binding")]
    InvalidRuntimeMapping,
    #[error("runtime mapping already contains an active turn")]
    MappingHasActiveTurn,
    #[error("runtime mapping project or mission scope does not match the schedule")]
    MappingScopeMismatch,
    #[error("runtime generation must strictly increase on takeover")]
    RuntimeGenerationRegression,
    #[error("runtime attempt identifier digest is invalid")]
    InvalidAttemptId,
    #[error("runtime attempt is not registered")]
    AttemptNotFound,
    #[error("runtime attempt is already running")]
    AttemptRunning,
    #[error("uncertain Runtime outcome cannot be replayed")]
    UncertainReplaySuppressed,
    #[error("completed Runtime outcome cannot be replayed")]
    CompletedReplaySuppressed,
    #[error("runtime attempt permit no longer matches its record")]
    AttemptPermitLost,
    #[error("runtime attempt permit is invalid")]
    InvalidPermit,
    #[error("runtime attempt permit sequence is exhausted")]
    PermitSequenceExhausted,
    #[error("runtime dispatch mapping does not contain a turn")]
    DispatchMappingMissingTurn,
    #[error("runtime dispatch request or response digest is invalid")]
    InvalidDispatchDigest,
    #[error("runtime dispatch conflicts with the recorded dispatch")]
    DispatchConflict,
    #[error("runtime attempt has a conflicting terminal outcome")]
    AttemptTerminalConflict,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::digest_hex;

    fn digest(byte: u8) -> String {
        digest_hex(&[byte])
    }

    fn fence(owner: u8, token: u8, generation: u64) -> LeaseFence {
        LeaseFence {
            owner_digest: digest(owner),
            token_digest: digest(token),
            generation,
        }
    }

    fn mapping(generation: u64, instance: u8) -> RuntimeMapping {
        RuntimeMapping::new(
            "project-runtime-fence",
            "mission-runtime-fence",
            generation,
            digest(instance),
            "model",
            "provider",
            "thread-runtime-fence",
        )
        .expect("mapping")
    }

    fn binding() -> RuntimeScheduleBinding {
        RuntimeScheduleBinding::new(digest(b's'), fence(b'o', b't', 1), mapping(1, b'i'))
            .expect("binding")
    }

    fn authorize(
        gate: &mut RuntimeSchedulerGate,
        attempt_id_digest: &str,
    ) -> Result<RuntimeAttemptPermit, RuntimeSchedulerError> {
        let mapping = gate.binding().mapping().clone();
        gate.authorize_turn(attempt_id_digest, &mapping)
    }

    fn dispatch(
        mapping: &RuntimeMapping,
        turn: &str,
        request: u8,
        response: u8,
    ) -> RuntimeTurnDispatch {
        let mut mapping = mapping.clone();
        mapping.runtime_turn_id = Some(turn.into());
        RuntimeTurnDispatch {
            mapping,
            request_digest: digest(request),
            response_digest: digest(response),
            elapsed: Duration::from_millis(1),
        }
    }

    #[test]
    fn exact_mapping_is_required_and_completed_attempt_is_not_replayed() {
        let mut gate = RuntimeSchedulerGate::new(binding());
        let attempt = digest(b'a');
        let permit = authorize(&mut gate, &attempt).expect("permit");
        let dispatch = dispatch(gate.binding().mapping(), "turn-1", b'r', b's');
        let receipt = gate.record_completed(&permit, &dispatch).expect("complete");
        assert_eq!(receipt.request_digest, digest(b'r'));
        assert_eq!(
            gate.replay_decision(&attempt).expect("replay decision"),
            ReplayDecision::SuppressedCompleted
        );
        assert!(matches!(
            authorize(&mut gate, &attempt),
            Err(RuntimeSchedulerError::CompletedReplaySuppressed)
        ));
        let mut wrong_mapping = gate.binding().mapping().clone();
        wrong_mapping.runtime_thread_id = "other-thread".into();
        assert!(matches!(
            gate.authorize_turn(&digest(b'b'), &wrong_mapping),
            Err(RuntimeSchedulerError::MappingScopeMismatch)
        ));
    }

    #[test]
    fn uncertain_runtime_outcome_is_terminal_and_never_replayed() {
        let mut gate = RuntimeSchedulerGate::new(binding());
        let attempt = digest(b'u');
        let permit = authorize(&mut gate, &attempt).expect("permit");
        gate.record_uncertain(&permit).expect("uncertain");
        assert_eq!(
            gate.replay_decision(&attempt).expect("replay decision"),
            ReplayDecision::SuppressedUncertain
        );
        assert!(matches!(
            authorize(&mut gate, &attempt),
            Err(RuntimeSchedulerError::UncertainReplaySuppressed)
        ));
        let dispatch = dispatch(gate.binding().mapping(), "turn-uncertain", b'x', b'y');
        assert!(matches!(
            gate.record_completed(&permit, &dispatch),
            Err(RuntimeSchedulerError::UncertainReplaySuppressed)
        ));
    }

    #[test]
    fn failed_attempt_can_obtain_a_fresh_permit_without_reusing_the_old_one() {
        let mut gate = RuntimeSchedulerGate::new(binding());
        let attempt = digest(b'f');
        let old_permit = authorize(&mut gate, &attempt).expect("old permit");
        gate.record_failed(&old_permit).expect("failed");
        let new_permit = authorize(&mut gate, &attempt).expect("retry permit");
        assert_ne!(old_permit, new_permit);
        assert!(matches!(
            gate.record_uncertain(&old_permit),
            Err(RuntimeSchedulerError::AttemptPermitLost)
        ));
        assert_eq!(
            gate.replay_decision(&attempt).expect("replay decision"),
            ReplayDecision::SuppressedUncertain
        );
        gate.record_uncertain(&new_permit).expect("uncertain retry");
    }

    #[test]
    fn takeover_fences_running_attempt_and_requires_new_lease_and_runtime_generations() {
        let mut gate = RuntimeSchedulerGate::new(binding());
        let attempt = digest(b't');
        let old_permit = authorize(&mut gate, &attempt).expect("old permit");
        let report = gate
            .take_over(fence(b'n', b'm', 2), mapping(2, b'n'))
            .expect("takeover");
        assert_eq!(report.fenced_running_attempts, 1);
        assert_eq!(
            gate.replay_decision(&attempt).expect("replay decision"),
            ReplayDecision::SuppressedUncertain
        );
        let old_dispatch = dispatch(&mapping(1, b'i'), "turn-old", b'1', b'2');
        assert!(matches!(
            gate.record_completed(&old_permit, &old_dispatch),
            Err(RuntimeSchedulerError::LeaseFenceLost)
        ));
        assert!(matches!(
            gate.take_over(fence(b'x', b'y', 2), mapping(3, b'x')),
            Err(RuntimeSchedulerError::LeaseGenerationRegression)
        ));
        assert!(matches!(
            gate.take_over(fence(b'x', b'y', 3), mapping(2, b'x')),
            Err(RuntimeSchedulerError::RuntimeGenerationRegression)
        ));
        let next_attempt = digest(b'v');
        let next_permit = authorize(&mut gate, &next_attempt).expect("new generation permit");
        let next_dispatch = dispatch(gate.binding().mapping(), "turn-new", b'3', b'4');
        gate.record_completed(&next_permit, &next_dispatch)
            .expect("new generation complete");
    }

    #[test]
    fn dispatch_requires_exact_thread_mapping_and_turn_id() {
        let mut gate = RuntimeSchedulerGate::new(binding());
        let attempt = digest(b'd');
        let permit = authorize(&mut gate, &attempt).expect("permit");
        let mut no_turn = gate.binding().mapping().clone();
        assert!(matches!(
            gate.accept_dispatch(
                &permit,
                &RuntimeTurnDispatch {
                    mapping: no_turn.clone(),
                    request_digest: digest(b'1'),
                    response_digest: digest(b'2'),
                    elapsed: Duration::from_millis(1),
                }
            ),
            Err(RuntimeSchedulerError::DispatchMappingMissingTurn)
        ));
        no_turn.runtime_thread_id = "wrong-thread".into();
        no_turn.runtime_turn_id = Some("turn-wrong".into());
        assert!(matches!(
            gate.accept_dispatch(&permit, &dispatch(&no_turn, "turn-wrong", b'1', b'2')),
            Err(RuntimeSchedulerError::MappingScopeMismatch)
        ));
    }
}
