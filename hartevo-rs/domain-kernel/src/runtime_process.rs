use std::fmt;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ContextError, RuntimeRecoveryAttempt};

const MAX_CLEANUP_ATTEMPTS: usize = 16;
const RUNTIME_LAUNCH_TOKEN_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProcessClaimStatus {
    Prepared,
    Spawned,
    Terminated,
    Exited,
    Blocked,
}

impl RuntimeProcessClaimStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Terminated | Self::Exited)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProcessCleanupDisposition {
    Terminated,
    AlreadyExited,
    InspectionBlocked,
    TerminationFailed,
}

impl RuntimeProcessCleanupDisposition {
    fn resulting_status(self) -> RuntimeProcessClaimStatus {
        match self {
            Self::Terminated => RuntimeProcessClaimStatus::Terminated,
            Self::AlreadyExited => RuntimeProcessClaimStatus::Exited,
            Self::InspectionBlocked | Self::TerminationFailed => RuntimeProcessClaimStatus::Blocked,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeProcessIdentity {
    pub process_id: u32,
    pub started_at_epoch_seconds: u64,
    pub executable_path_digest: String,
    pub runtime_instance_digest: String,
}

impl RuntimeProcessIdentity {
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.process_id == 0
            || self.started_at_epoch_seconds == 0
            || !is_sha256(&self.executable_path_digest)
            || !is_sha256(&self.runtime_instance_digest)
        {
            return Err(ContextError::InvalidRuntimeRecovery);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeProcessCleanupEvidence {
    pub sequence: u32,
    pub disposition: RuntimeProcessCleanupDisposition,
    pub evidence_digest: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeProcessClaim {
    pub tenant_id: crate::TenantId,
    pub project_id: crate::ProjectId,
    pub mission_id: crate::MissionId,
    pub recovery_id: crate::RuntimeRecoveryAttemptId,
    pub workspace_id: crate::ContextWorkspaceId,
    pub worker_id: crate::WorkerId,
    pub worker_generation: u64,
    pub process_attempt: u32,
    pub runtime_config_digest: String,
    pub program_sha256: String,
    /// Private, random launch correlation. It stays inside SQLCipher and the child environment;
    /// events, Debug output, and UI projections use only `launch_token_digest`.
    pub launch_token: String,
    pub launch_token_digest: String,
    /// Private canonical launch path. Like the token, it never crosses the Domain event/UI
    /// boundary; only its digest is projected.
    pub launch_executable_path: String,
    pub launch_executable_path_digest: String,
    pub identity: Option<RuntimeProcessIdentity>,
    pub cleanup_attempts: Vec<RuntimeProcessCleanupEvidence>,
    pub status: RuntimeProcessClaimStatus,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for RuntimeProcessClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeProcessClaim")
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("recovery_id", &self.recovery_id)
            .field("workspace_id", &self.workspace_id)
            .field("worker_id", &self.worker_id)
            .field("worker_generation", &self.worker_generation)
            .field("process_attempt", &self.process_attempt)
            .field("runtime_config_digest", &self.runtime_config_digest)
            .field("program_sha256", &self.program_sha256)
            .field("launch_token_digest", &self.launch_token_digest)
            .field(
                "launch_executable_path_digest",
                &self.launch_executable_path_digest,
            )
            .field("identity", &self.identity)
            .field("cleanup_attempts", &self.cleanup_attempts)
            .field("status", &self.status)
            .field("revision", &self.revision)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

impl RuntimeProcessClaim {
    pub fn prepare(
        recovery: &RuntimeRecoveryAttempt,
        program_sha256: String,
        launch_token: String,
        launch_executable_path: String,
        launch_executable_path_digest: String,
        now: DateTime<Utc>,
    ) -> Result<Self, ContextError> {
        recovery.validate_record()?;
        if recovery.status != crate::RuntimeRecoveryStatus::Prepared
            || !is_sha256(&program_sha256)
            || !is_launch_token(&launch_token)
            || !is_runtime_launch_path(
                &launch_executable_path,
                &launch_executable_path_digest,
                &launch_token,
            )
            || now < recovery.updated_at
        {
            return Err(ContextError::InvalidRuntimeRecovery);
        }
        let value = Self {
            tenant_id: recovery.tenant_id.clone(),
            project_id: recovery.project_id.clone(),
            mission_id: recovery.mission_id.clone(),
            recovery_id: recovery.id.clone(),
            workspace_id: recovery.workspace_id.clone(),
            worker_id: recovery.worker_id.clone(),
            worker_generation: recovery.worker_generation,
            process_attempt: recovery.process_attempt,
            runtime_config_digest: recovery.runtime_config_digest.clone(),
            program_sha256,
            launch_token_digest: digest(launch_token.as_bytes()),
            launch_token,
            launch_executable_path,
            launch_executable_path_digest,
            identity: None,
            cleanup_attempts: Vec::new(),
            status: RuntimeProcessClaimStatus::Prepared,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        value.validate_record()?;
        Ok(value)
    }

    pub fn mark_spawned(
        &mut self,
        identity: RuntimeProcessIdentity,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        identity.validate()?;
        if self.status != RuntimeProcessClaimStatus::Prepared || now < self.updated_at {
            return Err(ContextError::InvalidRuntimeRecovery);
        }
        let previous = self.clone();
        self.identity = Some(identity);
        self.status = RuntimeProcessClaimStatus::Spawned;
        if let Err(error) = self.touch(now) {
            *self = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn record_cleanup(
        &mut self,
        disposition: RuntimeProcessCleanupDisposition,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.status.is_terminal()
            || !is_sha256(&evidence_digest)
            || now < self.updated_at
            || self.cleanup_attempts.len() >= MAX_CLEANUP_ATTEMPTS
        {
            return Err(ContextError::InvalidRuntimeRecovery);
        }
        let previous = self.clone();
        let sequence = u32::try_from(self.cleanup_attempts.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(ContextError::RevisionOverflow)?;
        self.cleanup_attempts.push(RuntimeProcessCleanupEvidence {
            sequence,
            disposition,
            evidence_digest,
            observed_at: now,
        });
        self.status = disposition.resulting_status();
        if let Err(error) = self.touch(now) {
            *self = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn validate_record(&self) -> Result<(), ContextError> {
        let identity_matches = match self.status {
            RuntimeProcessClaimStatus::Prepared => self.identity.is_none(),
            RuntimeProcessClaimStatus::Spawned => self.identity.is_some(),
            RuntimeProcessClaimStatus::Terminated
            | RuntimeProcessClaimStatus::Exited
            | RuntimeProcessClaimStatus::Blocked => true,
        };
        let cleanup_sequence_matches =
            self.cleanup_attempts
                .iter()
                .enumerate()
                .all(|(index, evidence)| {
                    evidence.sequence == u32::try_from(index).unwrap_or(u32::MAX) + 1
                        && is_sha256(&evidence.evidence_digest)
                        && evidence.observed_at >= self.created_at
                        && evidence.observed_at <= self.updated_at
                });
        let terminal_cleanup_matches = self
            .cleanup_attempts
            .last()
            .is_none_or(|evidence| evidence.disposition.resulting_status() == self.status);
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.recovery_id.as_str().trim().is_empty()
            || self.workspace_id.as_str().trim().is_empty()
            || self.worker_id.as_str().trim().is_empty()
            || self.worker_generation == 0
            || self.process_attempt == 0
            || !is_sha256(&self.runtime_config_digest)
            || !is_sha256(&self.program_sha256)
            || !is_launch_token(&self.launch_token)
            || self.launch_token_digest != digest(self.launch_token.as_bytes())
            || !is_runtime_launch_path(
                &self.launch_executable_path,
                &self.launch_executable_path_digest,
                &self.launch_token,
            )
            || self
                .identity
                .as_ref()
                .is_some_and(|identity| identity.validate().is_err())
            || !identity_matches
            || self.cleanup_attempts.len() > MAX_CLEANUP_ATTEMPTS
            || !cleanup_sequence_matches
            || !terminal_cleanup_matches
            || self.revision == 0
            || self.created_at > self.updated_at
        {
            return Err(ContextError::InvalidRuntimeRecovery);
        }
        Ok(())
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, ContextError> {
        self.validate_record()?;
        previous.validate_record()?;
        let immutable = self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.mission_id == previous.mission_id
            && self.recovery_id == previous.recovery_id
            && self.workspace_id == previous.workspace_id
            && self.worker_id == previous.worker_id
            && self.worker_generation == previous.worker_generation
            && self.process_attempt == previous.process_attempt
            && self.runtime_config_digest == previous.runtime_config_digest
            && self.program_sha256 == previous.program_sha256
            && self.launch_token == previous.launch_token
            && self.launch_token_digest == previous.launch_token_digest
            && self.launch_executable_path == previous.launch_executable_path
            && self.launch_executable_path_digest == previous.launch_executable_path_digest
            && self.created_at == previous.created_at;
        let spawned = previous.status == RuntimeProcessClaimStatus::Prepared
            && self.status == RuntimeProcessClaimStatus::Spawned
            && previous.identity.is_none()
            && self.identity.is_some()
            && self.cleanup_attempts == previous.cleanup_attempts;
        let cleaned = !previous.status.is_terminal()
            && self.cleanup_attempts.len() == previous.cleanup_attempts.len() + 1
            && self.cleanup_attempts[..previous.cleanup_attempts.len()]
                == previous.cleanup_attempts
            && self.identity == previous.identity
            && matches!(
                self.status,
                RuntimeProcessClaimStatus::Terminated
                    | RuntimeProcessClaimStatus::Exited
                    | RuntimeProcessClaimStatus::Blocked
            );
        Ok(immutable
            && (spawned || cleaned)
            && previous.revision.checked_add(1) == Some(self.revision)
            && self.updated_at >= previous.updated_at)
    }

    fn touch(&mut self, now: DateTime<Utc>) -> Result<(), ContextError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(ContextError::RevisionOverflow)?;
        self.updated_at = now;
        self.validate_record()
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_launch_token(value: &str) -> bool {
    value.len() == RUNTIME_LAUNCH_TOKEN_BYTES && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_runtime_launch_path(path: &str, path_digest: &str, launch_token: &str) -> bool {
    let path = Path::new(path);
    path.is_absolute()
        && path.as_os_str().len() <= 32 * 1024
        && !path.as_os_str().to_string_lossy().contains('\0')
        && is_sha256(path_digest)
        && path_digest == digest(path.to_string_lossy().as_bytes())
        && path
            .parent()
            .and_then(Path::file_name)
            .and_then(|value| value.to_str())
            == Some(digest(launch_token.as_bytes()).as_str())
}

fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ContextCheckpointId, ContextWorkspaceId, MissionId, ProjectId, RuntimeRecoveryAttemptId,
        RuntimeRecoveryStatus, RuntimeResumeStrategy, TenantId, WorkerId,
    };
    use chrono::Duration;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .expect("time")
            .with_timezone(&Utc)
    }

    fn recovery() -> RuntimeRecoveryAttempt {
        RuntimeRecoveryAttempt {
            id: RuntimeRecoveryAttemptId::from("recovery-runtime-process"),
            tenant_id: TenantId::from("tenant-runtime-process"),
            project_id: ProjectId::from("project-runtime-process"),
            mission_id: MissionId::from("mission-runtime-process"),
            workspace_id: ContextWorkspaceId::from("workspace-runtime-process"),
            worker_id: WorkerId::from("worker-runtime-process"),
            worker_generation: 1,
            source_attachment_epoch: 1,
            target_attachment_epoch: 2,
            source_mapping_digest: "1".repeat(64),
            checkpoint_id: ContextCheckpointId::from("checkpoint-runtime-process"),
            checkpoint_digest: "2".repeat(64),
            runtime_config_digest: "3".repeat(64),
            initial_strategy: RuntimeResumeStrategy::StartNew,
            requested_thread_id_digest: None,
            max_process_attempts: 3,
            process_attempt: 1,
            health_digest: None,
            runtime_instance_digest: None,
            runtime_thread_id: None,
            runtime_mapping_digest: None,
            failures: Vec::new(),
            status: RuntimeRecoveryStatus::Prepared,
            revision: 1,
            created_at: now(),
            updated_at: now(),
        }
    }

    #[test]
    fn process_claim_redacts_launch_token_and_allows_only_append_only_cleanup() {
        let recovery = recovery();
        let private_token = "a".repeat(64);
        let launch_directory = format!("/tmp/{}", digest(private_token.as_bytes()));
        let launch_path = format!("{launch_directory}/interpreter");
        let mut claim = RuntimeProcessClaim::prepare(
            &recovery,
            "3".repeat(64),
            private_token.clone(),
            launch_path.clone(),
            digest(launch_path.as_bytes()),
            now() + Duration::seconds(2),
        )
        .expect("claim");
        assert!(!format!("{claim:?}").contains(&private_token));
        let prepared = claim.clone();
        claim
            .mark_spawned(
                RuntimeProcessIdentity {
                    process_id: 42,
                    started_at_epoch_seconds: 1_786_492_800,
                    executable_path_digest: "4".repeat(64),
                    runtime_instance_digest: "5".repeat(64),
                },
                now() + Duration::seconds(3),
            )
            .expect("spawned");
        assert!(claim.follows(&prepared).expect("spawn follows"));
        let spawned = claim.clone();
        claim
            .record_cleanup(
                RuntimeProcessCleanupDisposition::InspectionBlocked,
                "6".repeat(64),
                now() + Duration::seconds(4),
            )
            .expect("blocked");
        assert!(claim.follows(&spawned).expect("cleanup follows"));
        let blocked = claim.clone();
        claim
            .record_cleanup(
                RuntimeProcessCleanupDisposition::Terminated,
                "7".repeat(64),
                now() + Duration::seconds(5),
            )
            .expect("terminated");
        assert!(claim.follows(&blocked).expect("retry follows"));
        assert_eq!(claim.status, RuntimeProcessClaimStatus::Terminated);
        assert!(
            claim
                .record_cleanup(
                    RuntimeProcessCleanupDisposition::AlreadyExited,
                    "8".repeat(64),
                    now() + Duration::seconds(6),
                )
                .is_err()
        );
    }
}
