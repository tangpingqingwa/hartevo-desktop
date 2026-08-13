//! Production-safe Unix process boundary for a separately pinned file scanner.
//!
//! This module authenticates and contains the scanner process. It does not ship
//! a malware engine and does not turn fixture verdicts into production malware
//! evidence.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use command_fds::{CommandFdExt, FdMapping};
use command_group::{CommandGroup, GroupChild, Signal, UnixChildExt};
use crossbeam_channel::{Sender, TryRecvError, bounded};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempfile::{Builder as TempBuilder, TempDir};
use zeroize::Zeroizing;

use crate::file_broker::{FileSafetyScanner, FileScanDecision, FileScanReport, FileScanRequest};
use crate::workspace::{digest, digest_json, is_bounded_identifier, is_sha256};
use crate::{BrowserError, BrowserFileType};

const SCANNER_PROTOCOL: &str = "hartevo-file-scanner-process/v3";
const VERSION_OPERATION: &str = "version-v3";
const SCAN_OPERATION: &str = "scan-v3";
const SCANNER_INPUT_FD: i32 = 3;
const MAX_PROCESS_TIMEOUT: Duration = Duration::from_mins(5);
const MIN_OUTPUT_BYTES: usize = 64;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(5);
const PROCESS_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const READER_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const EXECUTABLE_COPY_MODE: u32 = 0o500;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

/// Exact scanner release, executable, and policy accepted by the process boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct ScannerReleasePin {
    scanner_id: String,
    scanner_version: String,
    executable_sha256: String,
    policy_version: String,
    ruleset_sha256: String,
    config_sha256: String,
    policy_digest: String,
    release_digest: String,
}

impl ScannerReleasePin {
    pub fn new(
        scanner_id: impl Into<String>,
        scanner_version: impl Into<String>,
        executable_sha256: impl Into<String>,
        policy_version: impl Into<String>,
        ruleset_sha256: impl Into<String>,
        config_sha256: impl Into<String>,
    ) -> Result<Self, BrowserError> {
        let scanner_id = scanner_id.into();
        let scanner_version = scanner_version.into();
        let executable_sha256 = executable_sha256.into();
        let policy_version = policy_version.into();
        let ruleset_sha256 = ruleset_sha256.into();
        let config_sha256 = config_sha256.into();
        if !valid_release_identifier(&scanner_id)
            || !valid_release_identifier(&scanner_version)
            || !is_sha256(&executable_sha256)
            || !valid_release_identifier(&policy_version)
            || !is_sha256(&ruleset_sha256)
            || !is_sha256(&config_sha256)
        {
            return Err(BrowserError::FileScanUnavailable);
        }
        let policy_digest = digest_json(&serde_json::json!({
            "protocol": SCANNER_PROTOCOL,
            "policyVersion": policy_version,
            "rulesetSha256": ruleset_sha256,
            "configSha256": config_sha256,
        }))?;
        let release_digest = digest_json(&serde_json::json!({
            "protocol": SCANNER_PROTOCOL,
            "scannerId": scanner_id,
            "scannerVersion": scanner_version,
            "executableSha256": executable_sha256,
            "policyDigest": policy_digest,
        }))?;
        Ok(Self {
            scanner_id,
            scanner_version,
            executable_sha256,
            policy_version,
            ruleset_sha256,
            config_sha256,
            policy_digest,
            release_digest,
        })
    }

    pub fn scanner_id(&self) -> &str {
        &self.scanner_id
    }

    pub fn scanner_version(&self) -> &str {
        &self.scanner_version
    }

    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }

    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    pub fn ruleset_sha256(&self) -> &str {
        &self.ruleset_sha256
    }

    pub fn config_sha256(&self) -> &str {
        &self.config_sha256
    }

    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    pub fn release_digest(&self) -> &str {
        &self.release_digest
    }

    fn validate(&self) -> Result<(), BrowserError> {
        if Self::new(
            self.scanner_id.clone(),
            self.scanner_version.clone(),
            self.executable_sha256.clone(),
            self.policy_version.clone(),
            self.ruleset_sha256.clone(),
            self.config_sha256.clone(),
        )? != *self
        {
            return Err(BrowserError::FileScanUnavailable);
        }
        Ok(())
    }
}

impl fmt::Debug for ScannerReleasePin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScannerReleasePin")
            .field("scanner_id", &self.scanner_id)
            .field("scanner_version", &self.scanner_version)
            .field("executable_sha256", &self.executable_sha256)
            .field("policy_version", &self.policy_version)
            .field("ruleset_sha256", &self.ruleset_sha256)
            .field("config_sha256", &self.config_sha256)
            .field("policy_digest", &self.policy_digest)
            .field("release_digest", &self.release_digest)
            .finish()
    }
}

/// Hard wall-clock and output-retention limits for one scanner generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScannerProcessLimits {
    timeout: Duration,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
}

impl ScannerProcessLimits {
    pub fn new(
        timeout: Duration,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<Self, BrowserError> {
        let limits = Self {
            timeout,
            max_stdout_bytes,
            max_stderr_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn max_stdout_bytes(&self) -> usize {
        self.max_stdout_bytes
    }

    pub fn max_stderr_bytes(&self) -> usize {
        self.max_stderr_bytes
    }

    fn validate(&self) -> Result<(), BrowserError> {
        if self.timeout.is_zero()
            || self.timeout > MAX_PROCESS_TIMEOUT
            || !(MIN_OUTPUT_BYTES..=MAX_OUTPUT_BYTES).contains(&self.max_stdout_bytes)
            || !(MIN_OUTPUT_BYTES..=MAX_OUTPUT_BYTES).contains(&self.max_stderr_bytes)
        {
            return Err(BrowserError::FileScanUnavailable);
        }
        Ok(())
    }
}

/// A production-safe process boundary, not a bundled or certified malware engine.
pub struct ProductionFileScanner {
    runtime_directory: TempDir,
    canonical_runtime_directory: PathBuf,
    executable_path: PathBuf,
    executable_identity: ExactFileIdentity,
    release_pin: ScannerReleasePin,
    limits: ScannerProcessLimits,
    version_probe_evidence_digest: String,
    process_generation: u64,
    last_launch_digest: String,
    active_launch_digest: Option<String>,
    acceptance_generation: u64,
    pending_acceptance_digest: Option<String>,
    process_boundary_poisoned: bool,
}

impl ProductionFileScanner {
    pub fn new(
        executable_path: &Path,
        private_runtime_root: &Path,
        release_pin: ScannerReleasePin,
        limits: ScannerProcessLimits,
    ) -> Result<Self, BrowserError> {
        release_pin.validate()?;
        limits.validate()?;
        let canonical_root = validate_private_runtime_root(private_runtime_root)?;
        let mut source = open_executable_source(executable_path)?;
        let source_before = inspect_open_file(&mut source, FileRole::SourceExecutable)?;
        if source_before.content_digest != release_pin.executable_sha256 {
            return Err(BrowserError::InvalidExecutable);
        }

        let runtime_directory = TempBuilder::new()
            .prefix("production-file-scanner-")
            .tempdir_in(&canonical_root)?;
        set_private_directory(runtime_directory.path())?;
        let canonical_runtime_directory = fs::canonicalize(runtime_directory.path())?;
        if canonical_runtime_directory
            .parent()
            .is_none_or(|parent| parent != canonical_root)
        {
            return Err(BrowserError::FileScanUnavailable);
        }

        let (materialized_path, executable_identity) = materialize_executable(
            &mut source,
            &source_before,
            &canonical_runtime_directory,
            &release_pin.executable_sha256,
        )?;
        let source_after = inspect_open_file(&mut source, FileRole::SourceExecutable)?;
        if source_after != source_before {
            return Err(BrowserError::InvalidExecutable);
        }

        let executable_identity_digest = executable_identity.evidence_digest()?;
        let lifecycle_root_digest = digest_json(&serde_json::json!({
            "protocol": SCANNER_PROTOCOL,
            "lifecycle": "scanner-process-root",
            "releaseDigest": release_pin.release_digest,
            "policyDigest": release_pin.policy_digest,
            "executableIdentityDigest": executable_identity_digest,
        }))?;
        let mut scanner = Self {
            runtime_directory,
            canonical_runtime_directory,
            executable_path: materialized_path,
            executable_identity,
            release_pin,
            limits,
            version_probe_evidence_digest: digest(b"pending-scanner-version-probe"),
            process_generation: 0,
            last_launch_digest: lifecycle_root_digest,
            active_launch_digest: None,
            acceptance_generation: 0,
            pending_acceptance_digest: None,
            process_boundary_poisoned: false,
        };
        let probe = scanner.run_process(ProcessOperation::Version)?;
        probe.validate_result_candidate(scanner.limits)?;
        let version: VersionResponse = scanner.parse_process_response(&probe.stdout.retained)?;
        scanner.validate_response_identity(&probe.identity.launch, version.identity())?;
        scanner.version_probe_evidence_digest = digest_json(&serde_json::json!({
            "protocol": SCANNER_PROTOCOL,
            "operation": VERSION_OPERATION,
            "releaseDigest": scanner.release_pin.release_digest,
            "policyDigest": scanner.release_pin.policy_digest,
            "executableIdentityDigest": scanner.executable_identity.evidence_digest()?,
            "invocationContractDigest": probe.identity.launch.invocation_contract_digest,
            "launchIdentityDigest": probe.identity.launch.evidence_digest()?,
            "processObservationDigest": probe.evidence_digest()?,
            "response": {
                "schemaVersion": version.schema_version,
                "scannerId": version.scanner_id,
                "scannerVersion": version.scanner_version,
                "executableSha256": version.executable_sha256,
                "policyDigest": version.policy_digest,
                "invocationDigest": version.invocation_digest,
                "launchDigest": version.launch_digest,
            },
        }))?;
        Ok(scanner)
    }

    fn verify_runtime_boundary(&self) -> Result<ExactFileIdentity, BrowserError> {
        let canonical = validate_private_runtime_root(&self.canonical_runtime_directory)
            .map_err(|_| BrowserError::FileScanUnavailable)?;
        if canonical != self.canonical_runtime_directory
            || self.runtime_directory.path() != self.canonical_runtime_directory
        {
            return Err(BrowserError::FileScanUnavailable);
        }
        let identity = inspect_path(&self.executable_path, FileRole::MaterializedExecutable)
            .map_err(|_| BrowserError::FileScanUnavailable)?;
        if identity != self.executable_identity {
            return Err(BrowserError::FileScanUnavailable);
        }
        Ok(identity)
    }

    fn run_process(
        &mut self,
        operation: ProcessOperation<'_, '_>,
    ) -> Result<ProcessObservation, BrowserError> {
        if self.process_boundary_poisoned || self.active_launch_digest.is_some() {
            return Err(BrowserError::FileScanUnavailable);
        }
        let Ok(executable_before) = self.verify_runtime_boundary() else {
            self.poison_process_boundary();
            return Err(BrowserError::FileScanUnavailable);
        };
        let executable_identity_digest = executable_before.evidence_digest()?;
        let invocation = ScannerInvocationContract::new(
            &operation,
            &self.release_pin,
            &executable_identity_digest,
            self.limits,
        )?;
        let invocation_contract_digest = invocation.evidence_digest()?;
        let run_directory = TempBuilder::new()
            .prefix("run-")
            .tempdir_in(&self.canonical_runtime_directory)?;
        set_private_directory(run_directory.path())?;
        let home_directory = run_directory.path().join("home");
        let temp_directory = run_directory.path().join("tmp");
        fs::create_dir(&home_directory)?;
        fs::create_dir(&temp_directory)?;
        set_private_directory(&home_directory)?;
        set_private_directory(&temp_directory)?;
        let directories = ProcessDirectories {
            working: run_directory.path(),
            home: &home_directory,
            temporary: &temp_directory,
        };

        let operation_name = operation.name();
        let mut command = Command::new(&self.executable_path);

        let launch = self.begin_process_launch(
            operation_name,
            &executable_identity_digest,
            &invocation_contract_digest,
        )?;
        configure_clean_process(
            &mut command,
            directories.working,
            directories.home,
            directories.temporary,
            &self.release_pin,
            &launch,
            &invocation_contract_digest,
        );

        if configure_process_operation(&mut command, operation, &invocation).is_err() {
            let run_directory_removed = run_directory.close().is_ok();
            let launch_finished = self.finish_process_launch(&launch).is_ok();
            if !run_directory_removed || !launch_finished {
                self.poison_process_boundary();
            }
            return Err(BrowserError::FileScanUnavailable);
        }

        if validate_configured_process(
            &command,
            &self.executable_path,
            &directories,
            &self.release_pin,
            &launch,
            &invocation,
        )
        .is_err()
        {
            let _ = run_directory.close();
            let _ = self.finish_process_launch(&launch);
            self.poison_process_boundary();
            return Err(BrowserError::FileScanUnavailable);
        }

        let execution = execute_bounded_process(&mut command, self.limits, &launch);
        let invocation_after = validate_configured_process(
            &command,
            &self.executable_path,
            &directories,
            &self.release_pin,
            &launch,
            &invocation,
        );
        let run_directory_removed = run_directory.close().is_ok();
        let executable_after = self.verify_runtime_boundary();
        if execution.is_err()
            || invocation_after.is_err()
            || !run_directory_removed
            || !matches!(
                executable_after.as_ref(),
                Ok(identity) if identity == &executable_before
            )
        {
            self.poison_process_boundary();
            return Err(BrowserError::FileScanUnavailable);
        }
        let execution = execution.map_err(|_| BrowserError::FileScanUnavailable)?;
        self.finish_process_execution(execution, &launch)
    }

    fn finish_process_execution(
        &mut self,
        execution: ProcessExecution,
        launch: &ScannerProcessLaunch,
    ) -> Result<ProcessObservation, BrowserError> {
        match execution {
            ProcessExecution::Completed(observation) => {
                if !observation.identity.matches_launch(launch) {
                    self.poison_process_boundary();
                    return Err(BrowserError::FileScanUnavailable);
                }
                self.finish_process_launch(launch)?;
                Ok(*observation)
            }
            ProcessExecution::ContainedFailure => {
                self.finish_process_launch(launch)?;
                Err(BrowserError::FileScanUnavailable)
            }
        }
    }

    fn begin_process_launch(
        &mut self,
        operation: &'static str,
        executable_identity_digest: &str,
        invocation_contract_digest: &str,
    ) -> Result<ScannerProcessLaunch, BrowserError> {
        if self.process_boundary_poisoned || self.active_launch_digest.is_some() {
            return Err(BrowserError::FileScanUnavailable);
        }
        let generation = self
            .process_generation
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        let launch = ScannerProcessLaunch::new(
            generation,
            operation,
            &self.release_pin.release_digest,
            &self.release_pin.policy_digest,
            executable_identity_digest,
            invocation_contract_digest,
            &self.last_launch_digest,
        )?;
        self.process_generation = generation;
        self.last_launch_digest.clone_from(&launch.launch_digest);
        self.active_launch_digest = Some(launch.launch_digest.clone());
        Ok(launch)
    }

    fn finish_process_launch(&mut self, launch: &ScannerProcessLaunch) -> Result<(), BrowserError> {
        if self.active_launch_digest.as_deref() != Some(launch.launch_digest.as_str()) {
            self.poison_process_boundary();
            return Err(BrowserError::FileScanUnavailable);
        }
        self.active_launch_digest = None;
        Ok(())
    }

    fn parse_process_response<T: for<'de> Deserialize<'de>>(
        &mut self,
        bytes: &[u8],
    ) -> Result<T, BrowserError> {
        let Ok(response) = parse_exact_json(bytes) else {
            self.poison_process_boundary();
            return Err(BrowserError::FileScanUnavailable);
        };
        Ok(response)
    }

    fn validate_response_identity(
        &mut self,
        launch: &ScannerProcessLaunch,
        response: ScannerResponseIdentity<'_>,
    ) -> Result<(), BrowserError> {
        if response.schema_version != 3
            || response.scanner_id != self.release_pin.scanner_id
            || response.scanner_version != self.release_pin.scanner_version
            || response.executable_sha256 != self.release_pin.executable_sha256
            || response.policy_digest != self.release_pin.policy_digest
            || response.invocation_digest != launch.invocation_contract_digest
            || response.launch_digest != launch.launch_digest
        {
            self.poison_process_boundary();
            return Err(BrowserError::FileScanUnavailable);
        }
        Ok(())
    }

    fn poison_process_boundary(&mut self) {
        if self.pending_acceptance_digest.take().is_some() {
            self.acceptance_generation = self.acceptance_generation.saturating_add(1);
        }
        self.process_boundary_poisoned = true;
    }
}

impl fmt::Debug for ProductionFileScanner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionFileScanner")
            .field("release_pin", &self.release_pin)
            .field(
                "runtime_directory_digest",
                &digest(
                    self.canonical_runtime_directory
                        .as_os_str()
                        .as_encoded_bytes(),
                ),
            )
            .field(
                "executable_identity_digest",
                &self.executable_identity.evidence_digest().ok(),
            )
            .field("limits", &self.limits)
            .field(
                "version_probe_evidence_digest",
                &self.version_probe_evidence_digest,
            )
            .field("process_generation", &self.process_generation)
            .field("acceptance_generation", &self.acceptance_generation)
            .field(
                "scan_acceptance_pending",
                &self.pending_acceptance_digest.is_some(),
            )
            .field("process_boundary_poisoned", &self.process_boundary_poisoned)
            .field(
                "process_launch_active",
                &self.active_launch_digest.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl ProductionFileScanner {
    fn prepare_scan_verdict(
        &mut self,
        request: &ScannerInputRequest<'_>,
    ) -> Result<PreparedScanVerdict, BrowserError> {
        if self.process_boundary_poisoned || self.active_launch_digest.is_some() {
            return Err(BrowserError::FileScanUnavailable);
        }
        self.supersede_pending_acceptance()?;
        self.release_pin.validate()?;
        self.limits.validate()?;
        if !is_sha256(request.content_digest) || request.byte_count == 0 {
            return Err(BrowserError::FileChanged);
        }
        let (mut retained_input, dispatched_input) = inspect_staged_path(request.staged_path())?;
        if dispatched_input.file_identity.content_digest != request.content_digest
            || dispatched_input.file_identity.byte_count != request.byte_count
        {
            return Err(BrowserError::FileChanged);
        }
        retained_input.seek(SeekFrom::Start(0))?;
        let scanner_input = retained_input.try_clone()?;

        let process_result = self.run_process(ProcessOperation::Scan {
            request,
            input: scanner_input,
        });
        let retained_input_after = inspect_open_file(&mut retained_input, FileRole::StagedInput)?;
        let path_after = inspect_staged_path(request.staged_path())?.1;
        let input_revalidation =
            DispatchedInputRevalidation::new(dispatched_input, retained_input_after, path_after)?;
        let process = process_result?;
        process.validate_result_candidate(self.limits)?;
        let executable_identity_digest = self.executable_identity.evidence_digest()?;
        let Ok(result_envelope) = ScannerResultEnvelope::from_completed_process(
            &self.release_pin,
            &self.version_probe_evidence_digest,
            &executable_identity_digest,
            &process,
            self.limits,
            &input_revalidation,
        ) else {
            self.poison_process_boundary();
            return Err(BrowserError::FileScanUnavailable);
        };
        let decision = result_envelope.decision;
        let result_envelope_digest = result_envelope.evidence_digest()?;
        let verdict_evidence_digest = digest_json(&serde_json::json!({
            "protocol": SCANNER_PROTOCOL,
            "operation": SCAN_OPERATION,
            "releaseDigest": self.release_pin.release_digest,
            "policyDigest": self.release_pin.policy_digest,
            "versionProbeEvidenceDigest": self.version_probe_evidence_digest,
            "executableIdentityDigest": executable_identity_digest,
            "invocationContractDigest": process.identity.launch.invocation_contract_digest,
            "launchIdentityDigest": process.identity.launch.evidence_digest()?,
            "request": {
                "contentDigest": request.content_digest,
                "byteCount": request.byte_count,
                "detectedType": request.detected_type,
                "observedAt": request.observed_at,
            },
            "dispatchedInputIdentityDigest": input_revalidation.dispatched_evidence_digest()?,
            "retainedInputFdAfterDigest": input_revalidation.retained_fd_evidence_digest()?,
            "inputPathAfterDigest": input_revalidation.path_evidence_digest()?,
            "decision": decision,
            "scannerResultEnvelopeDigest": result_envelope_digest,
        }))?;
        if decision == FileScanDecision::Rejected {
            return Ok(PreparedScanVerdict::Rejected(self.scan_report(
                decision,
                verdict_evidence_digest,
                request,
            )));
        }
        let acceptance = self.issue_clean_acceptance(
            request,
            &input_revalidation,
            &process,
            &result_envelope,
            verdict_evidence_digest,
        )?;
        Ok(PreparedScanVerdict::Clean(Box::new(acceptance)))
    }
}

impl ProductionFileScanner {
    fn issue_clean_acceptance(
        &mut self,
        request: &ScannerInputRequest<'_>,
        input_revalidation: &DispatchedInputRevalidation,
        process: &ProcessObservation,
        result_envelope: &ScannerResultEnvelope,
        verdict_evidence_digest: String,
    ) -> Result<PendingScanAcceptance, BrowserError> {
        if result_envelope.decision != FileScanDecision::Clean
            || self.pending_acceptance_digest.is_some()
            || process.identity.launch.generation != self.process_generation
        {
            self.poison_process_boundary();
            return Err(BrowserError::FileScanUnavailable);
        }
        let acceptance_generation = self
            .acceptance_generation
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        let input_snapshot = input_revalidation.dispatched.clone();
        let request_digest = scan_request_digest(request, &input_snapshot)?;
        let mut acceptance = PendingScanAcceptance {
            state: ScanAcceptanceState::Pending,
            acceptance_generation,
            process_generation: process.identity.launch.generation,
            request_digest,
            input_snapshot,
            release_digest: self.release_pin.release_digest.clone(),
            executable_identity_digest: process.identity.launch.executable_identity_digest.clone(),
            policy_digest: self.release_pin.policy_digest.clone(),
            config_sha256: self.release_pin.config_sha256.clone(),
            invocation_contract_digest: process.identity.launch.invocation_contract_digest.clone(),
            result_envelope_digest: result_envelope.evidence_digest()?,
            launch_digest: process.identity.launch.launch_digest.clone(),
            launch_identity_digest: process.identity.launch.evidence_digest()?,
            verdict_evidence_digest,
            acceptance_digest: digest(b"pending-one-shot-scan-acceptance"),
            report: None,
        };
        let acceptance_digest = acceptance.evidence_digest()?;
        let report_evidence_digest =
            accepted_scan_report_evidence(&acceptance.verdict_evidence_digest, &acceptance_digest)?;
        acceptance.acceptance_digest.clone_from(&acceptance_digest);
        acceptance.report =
            Some(self.scan_report(FileScanDecision::Clean, report_evidence_digest, request));
        self.acceptance_generation = acceptance_generation;
        self.pending_acceptance_digest = Some(acceptance_digest);
        Ok(acceptance)
    }

    fn consume_scan_acceptance(
        &mut self,
        acceptance: &mut PendingScanAcceptance,
        request: &ScannerInputRequest<'_>,
    ) -> Result<FileScanReport, BrowserError> {
        if self.validate_scan_acceptance(acceptance, request).is_err() {
            self.reject_scan_acceptance(acceptance)?;
            return Err(BrowserError::FileScanUnavailable);
        }
        let report = acceptance
            .report
            .take()
            .ok_or(BrowserError::FileScanUnavailable)?;
        acceptance.state = ScanAcceptanceState::Consumed;
        self.pending_acceptance_digest = None;
        Ok(report)
    }

    fn validate_scan_acceptance(
        &self,
        acceptance: &PendingScanAcceptance,
        request: &ScannerInputRequest<'_>,
    ) -> Result<(), BrowserError> {
        if acceptance.state != ScanAcceptanceState::Pending
            || self.process_boundary_poisoned
            || self.active_launch_digest.is_some()
            || self.pending_acceptance_digest.as_deref()
                != Some(acceptance.acceptance_digest.as_str())
            || self.acceptance_generation != acceptance.acceptance_generation
            || self.process_generation != acceptance.process_generation
            || self.last_launch_digest != acceptance.launch_digest
        {
            return Err(BrowserError::FileScanUnavailable);
        }
        self.release_pin.validate()?;
        self.limits.validate()?;
        let executable_identity = self.verify_runtime_boundary()?;
        let executable_identity_digest = executable_identity.evidence_digest()?;
        let (_, current_input) = inspect_staged_path(request.staged_path())?;
        let request_digest = scan_request_digest(request, &current_input)?;
        let invocation_digest = ScannerInvocationContract::for_scan_request(
            request,
            &self.release_pin,
            &executable_identity_digest,
            self.limits,
        )?
        .evidence_digest()?;
        if current_input != acceptance.input_snapshot
            || request_digest != acceptance.request_digest
            || self.release_pin.release_digest != acceptance.release_digest
            || executable_identity_digest != acceptance.executable_identity_digest
            || self.release_pin.policy_digest != acceptance.policy_digest
            || self.release_pin.config_sha256 != acceptance.config_sha256
            || invocation_digest != acceptance.invocation_contract_digest
            || acceptance.evidence_digest()? != acceptance.acceptance_digest
        {
            return Err(BrowserError::FileScanUnavailable);
        }
        let report = acceptance
            .report
            .as_ref()
            .ok_or(BrowserError::FileScanUnavailable)?;
        let expected_report_evidence = accepted_scan_report_evidence(
            &acceptance.verdict_evidence_digest,
            &acceptance.acceptance_digest,
        )?;
        if report.scanner_id != self.release_pin.scanner_id
            || report.scanner_version != self.release_pin.scanner_version
            || report.decision != FileScanDecision::Clean
            || report.evidence_digest != expected_report_evidence
            || report.scanned_at != request.observed_at
        {
            return Err(BrowserError::FileScanUnavailable);
        }
        Ok(())
    }

    fn reject_scan_acceptance(
        &mut self,
        acceptance: &mut PendingScanAcceptance,
    ) -> Result<(), BrowserError> {
        if acceptance.state == ScanAcceptanceState::Pending {
            acceptance.state = ScanAcceptanceState::Cancelled;
            acceptance.report = None;
        }
        if self.pending_acceptance_digest.as_deref() == Some(acceptance.acceptance_digest.as_str())
        {
            self.pending_acceptance_digest = None;
            self.bump_acceptance_generation()?;
        }
        Ok(())
    }

    /// Invalidates a pending clean verdict after cancellation or lease loss.
    pub fn cancel_pending_acceptance(&mut self) -> Result<(), BrowserError> {
        if self.pending_acceptance_digest.take().is_some() {
            self.bump_acceptance_generation()?;
        }
        Ok(())
    }

    fn supersede_pending_acceptance(&mut self) -> Result<(), BrowserError> {
        self.cancel_pending_acceptance()
    }

    fn bump_acceptance_generation(&mut self) -> Result<(), BrowserError> {
        self.acceptance_generation = self
            .acceptance_generation
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        Ok(())
    }

    fn scan_report(
        &self,
        decision: FileScanDecision,
        evidence_digest: String,
        request: &ScannerInputRequest<'_>,
    ) -> FileScanReport {
        FileScanReport {
            scanner_id: self.release_pin.scanner_id.clone(),
            scanner_version: self.release_pin.scanner_version.clone(),
            decision,
            evidence_digest,
            scanned_at: request.observed_at,
        }
    }
}

impl FileSafetyScanner for ProductionFileScanner {
    fn scan(&mut self, request: &FileScanRequest<'_>) -> Result<FileScanReport, BrowserError> {
        let scanner_request = ScannerInputRequest::from_file_scan_request(request);
        match self.prepare_scan_verdict(&scanner_request)? {
            PreparedScanVerdict::Clean(mut acceptance) => {
                self.consume_scan_acceptance(&mut acceptance, &scanner_request)
            }
            PreparedScanVerdict::Rejected(report) => Ok(report),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ScannerInputRequest<'input> {
    staged_path: &'input Path,
    content_digest: &'input str,
    byte_count: u64,
    detected_type: BrowserFileType,
    observed_at: chrono::DateTime<chrono::Utc>,
}

impl<'input> ScannerInputRequest<'input> {
    fn from_file_scan_request(request: &'input FileScanRequest<'_>) -> Self {
        Self {
            staged_path: request.staged_path(),
            content_digest: request.content_digest,
            byte_count: request.byte_count,
            detected_type: request.detected_type,
            observed_at: request.observed_at,
        }
    }

    fn staged_path(self) -> &'input Path {
        self.staged_path
    }
}

enum ProcessOperation<'request, 'staged> {
    Version,
    Scan {
        request: &'request ScannerInputRequest<'staged>,
        input: File,
    },
}

impl ProcessOperation<'_, '_> {
    fn name(&self) -> &'static str {
        match self {
            Self::Version => VERSION_OPERATION,
            Self::Scan { .. } => SCAN_OPERATION,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScannerInvocationInput {
    content_digest: String,
    byte_count: u64,
    detected_type: &'static str,
    observed_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScannerInvocationContract {
    operation: &'static str,
    release_digest: String,
    policy_digest: String,
    executable_identity_digest: String,
    timeout_milliseconds: u64,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
    input: Option<ScannerInvocationInput>,
}

impl ScannerInvocationContract {
    fn new(
        operation: &ProcessOperation<'_, '_>,
        release_pin: &ScannerReleasePin,
        executable_identity_digest: &str,
        limits: ScannerProcessLimits,
    ) -> Result<Self, BrowserError> {
        match operation {
            ProcessOperation::Version => Self::from_input(
                VERSION_OPERATION,
                None,
                release_pin,
                executable_identity_digest,
                limits,
            ),
            ProcessOperation::Scan { request, .. } => {
                Self::for_scan_request(request, release_pin, executable_identity_digest, limits)
            }
        }
    }

    fn for_scan_request(
        request: &ScannerInputRequest<'_>,
        release_pin: &ScannerReleasePin,
        executable_identity_digest: &str,
        limits: ScannerProcessLimits,
    ) -> Result<Self, BrowserError> {
        if !is_sha256(request.content_digest) || request.byte_count == 0 {
            return Err(BrowserError::FileChanged);
        }
        Self::from_input(
            SCAN_OPERATION,
            Some(ScannerInvocationInput {
                content_digest: request.content_digest.to_owned(),
                byte_count: request.byte_count,
                detected_type: file_type_protocol_name(request.detected_type),
                observed_at: request.observed_at.to_rfc3339(),
            }),
            release_pin,
            executable_identity_digest,
            limits,
        )
    }

    fn from_input(
        operation: &'static str,
        input: Option<ScannerInvocationInput>,
        release_pin: &ScannerReleasePin,
        executable_identity_digest: &str,
        limits: ScannerProcessLimits,
    ) -> Result<Self, BrowserError> {
        release_pin.validate()?;
        limits.validate()?;
        if !is_sha256(executable_identity_digest) {
            return Err(BrowserError::FileScanUnavailable);
        }
        Ok(Self {
            operation,
            release_digest: release_pin.release_digest.clone(),
            policy_digest: release_pin.policy_digest.clone(),
            executable_identity_digest: executable_identity_digest.to_owned(),
            timeout_milliseconds: u64::try_from(limits.timeout.as_millis())
                .map_err(|_| BrowserError::FileScanUnavailable)?,
            max_stdout_bytes: limits.max_stdout_bytes,
            max_stderr_bytes: limits.max_stderr_bytes,
            input,
        })
    }

    fn evidence_digest(&self) -> Result<String, BrowserError> {
        let environment_keys = if self.input.is_some() {
            vec![
                "HARTEVO_SCANNER_BYTE_COUNT",
                "HARTEVO_SCANNER_CONFIG_SHA256",
                "HARTEVO_SCANNER_CONTENT_SHA256",
                "HARTEVO_SCANNER_DETECTED_TYPE",
                "HARTEVO_SCANNER_EXECUTABLE_SHA256",
                "HARTEVO_SCANNER_ID",
                "HARTEVO_SCANNER_INPUT_FD",
                "HARTEVO_SCANNER_INVOCATION_DIGEST",
                "HARTEVO_SCANNER_LAUNCH_DIGEST",
                "HARTEVO_SCANNER_OBSERVED_AT",
                "HARTEVO_SCANNER_OPERATION",
                "HARTEVO_SCANNER_POLICY_DIGEST",
                "HARTEVO_SCANNER_POLICY_VERSION",
                "HARTEVO_SCANNER_PROCESS_GENERATION",
                "HARTEVO_SCANNER_PROTOCOL",
                "HARTEVO_SCANNER_RELEASE_DIGEST",
                "HARTEVO_SCANNER_RULESET_SHA256",
                "HARTEVO_SCANNER_VERSION",
                "HOME",
                "LANG",
                "LC_ALL",
                "TMPDIR",
            ]
        } else {
            vec![
                "HARTEVO_SCANNER_CONFIG_SHA256",
                "HARTEVO_SCANNER_EXECUTABLE_SHA256",
                "HARTEVO_SCANNER_ID",
                "HARTEVO_SCANNER_INVOCATION_DIGEST",
                "HARTEVO_SCANNER_LAUNCH_DIGEST",
                "HARTEVO_SCANNER_OPERATION",
                "HARTEVO_SCANNER_POLICY_DIGEST",
                "HARTEVO_SCANNER_POLICY_VERSION",
                "HARTEVO_SCANNER_PROCESS_GENERATION",
                "HARTEVO_SCANNER_PROTOCOL",
                "HARTEVO_SCANNER_RELEASE_DIGEST",
                "HARTEVO_SCANNER_RULESET_SHA256",
                "HARTEVO_SCANNER_VERSION",
                "HOME",
                "LANG",
                "LC_ALL",
                "TMPDIR",
            ]
        };
        let input = self.input.as_ref().map(|input| {
            serde_json::json!({
                "fd": SCANNER_INPUT_FD,
                "contentDigest": input.content_digest,
                "byteCount": input.byte_count,
                "detectedType": input.detected_type,
                "observedAt": input.observed_at,
            })
        });
        digest_json(&serde_json::json!({
            "protocol": SCANNER_PROTOCOL,
            "operation": self.operation,
            "releaseDigest": self.release_digest,
            "policyDigest": self.policy_digest,
            "executableIdentityDigest": self.executable_identity_digest,
            "arguments": [],
            "workingDirectory": "private-per-launch",
            "homeDirectory": "private-per-launch",
            "temporaryDirectory": "private-per-launch",
            "stdin": "null",
            "stdout": {
                "mode": "bounded-pipe",
                "maximumBytes": self.max_stdout_bytes,
            },
            "stderr": {
                "mode": "bounded-pipe",
                "maximumBytes": self.max_stderr_bytes,
            },
            "timeoutMilliseconds": self.timeout_milliseconds,
            "environmentKeys": environment_keys,
            "input": input,
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScannerProcessLaunch {
    generation: u64,
    operation: &'static str,
    release_digest: String,
    policy_digest: String,
    executable_identity_digest: String,
    invocation_contract_digest: String,
    previous_launch_digest: String,
    launch_digest: String,
}

impl ScannerProcessLaunch {
    fn new(
        generation: u64,
        operation: &'static str,
        release_digest: &str,
        policy_digest: &str,
        executable_identity_digest: &str,
        invocation_contract_digest: &str,
        previous_launch_digest: &str,
    ) -> Result<Self, BrowserError> {
        if !is_sha256(release_digest)
            || !is_sha256(policy_digest)
            || !is_sha256(executable_identity_digest)
            || !is_sha256(invocation_contract_digest)
            || !is_sha256(previous_launch_digest)
        {
            return Err(BrowserError::FileScanUnavailable);
        }
        let launch_digest = digest_json(&serde_json::json!({
            "protocol": SCANNER_PROTOCOL,
            "generation": generation.to_string(),
            "operation": operation,
            "releaseDigest": release_digest,
            "policyDigest": policy_digest,
            "executableIdentityDigest": executable_identity_digest,
            "invocationContractDigest": invocation_contract_digest,
            "previousLaunchDigest": previous_launch_digest,
        }))?;
        Ok(Self {
            generation,
            operation,
            release_digest: release_digest.to_owned(),
            policy_digest: policy_digest.to_owned(),
            executable_identity_digest: executable_identity_digest.to_owned(),
            invocation_contract_digest: invocation_contract_digest.to_owned(),
            previous_launch_digest: previous_launch_digest.to_owned(),
            launch_digest,
        })
    }

    fn evidence_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "protocol": SCANNER_PROTOCOL,
            "generation": self.generation.to_string(),
            "operation": self.operation,
            "releaseDigest": self.release_digest,
            "policyDigest": self.policy_digest,
            "executableIdentityDigest": self.executable_identity_digest,
            "invocationContractDigest": self.invocation_contract_digest,
            "previousLaunchDigest": self.previous_launch_digest,
            "launchDigest": self.launch_digest,
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedScannerProcessIdentity {
    process_id: u32,
    launch: ScannerProcessLaunch,
}

impl ObservedScannerProcessIdentity {
    fn matches_launch(&self, launch: &ScannerProcessLaunch) -> bool {
        self.process_id != 0 && &self.launch == launch
    }

    fn evidence_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "processId": self.process_id.to_string(),
            "launchIdentityDigest": self.launch.evidence_digest()?,
        }))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VersionResponse {
    schema_version: u32,
    scanner_id: String,
    scanner_version: String,
    executable_sha256: String,
    policy_digest: String,
    invocation_digest: String,
    launch_digest: String,
}

#[derive(Clone, Copy)]
struct ScannerResponseIdentity<'response> {
    schema_version: u32,
    scanner_id: &'response str,
    scanner_version: &'response str,
    executable_sha256: &'response str,
    policy_digest: &'response str,
    invocation_digest: &'response str,
    launch_digest: &'response str,
}

impl VersionResponse {
    fn identity(&self) -> ScannerResponseIdentity<'_> {
        ScannerResponseIdentity {
            schema_version: self.schema_version,
            scanner_id: &self.scanner_id,
            scanner_version: &self.scanner_version,
            executable_sha256: &self.executable_sha256,
            policy_digest: &self.policy_digest,
            invocation_digest: &self.invocation_digest,
            launch_digest: &self.launch_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScannerDecision {
    Clean,
    Rejected,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScanResponse {
    schema_version: u32,
    scanner_id: String,
    scanner_version: String,
    executable_sha256: String,
    policy_digest: String,
    invocation_digest: String,
    launch_digest: String,
    decision: ScannerDecision,
}

impl ScanResponse {
    fn identity(&self) -> ScannerResponseIdentity<'_> {
        ScannerResponseIdentity {
            schema_version: self.schema_version,
            scanner_id: &self.scanner_id,
            scanner_version: &self.scanner_version,
            executable_sha256: &self.executable_sha256,
            policy_digest: &self.policy_digest,
            invocation_digest: &self.invocation_digest,
            launch_digest: &self.launch_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileRole {
    SourceExecutable,
    MaterializedExecutable,
    StagedInput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExactFileIdentity {
    device: u64,
    inode: u64,
    byte_count: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    change_seconds: i64,
    change_nanoseconds: i64,
    mode: u32,
    owner: u32,
    content_digest: String,
}

impl ExactFileIdentity {
    fn evidence_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "device": self.device.to_string(),
            "inode": self.inode.to_string(),
            "byteCount": self.byte_count,
            "modifiedSeconds": self.modified_seconds.to_string(),
            "modifiedNanoseconds": self.modified_nanoseconds.to_string(),
            "changeSeconds": self.change_seconds.to_string(),
            "changeNanoseconds": self.change_nanoseconds.to_string(),
            "mode": format!("{:o}", self.mode),
            "owner": self.owner.to_string(),
            "contentDigest": self.content_digest,
        }))
    }

    fn matches_metadata(&self, metadata: &fs::Metadata) -> bool {
        self.device == metadata.dev()
            && self.inode == metadata.ino()
            && self.byte_count == metadata.len()
            && self.modified_seconds == metadata.mtime()
            && self.modified_nanoseconds == metadata.mtime_nsec()
            && self.change_seconds == metadata.ctime()
            && self.change_nanoseconds == metadata.ctime_nsec()
            && self.mode == metadata.mode()
            && self.owner == metadata.uid()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct DispatchedInputSnapshot {
    canonical_path_digest: String,
    file_identity: ExactFileIdentity,
}

impl DispatchedInputSnapshot {
    fn evidence_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "canonicalPathDigest": self.canonical_path_digest,
            "fileIdentityDigest": self.file_identity.evidence_digest()?,
        }))
    }
}

impl fmt::Debug for DispatchedInputSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchedInputSnapshot")
            .field("canonical_path_digest", &self.canonical_path_digest)
            .field(
                "file_identity_digest",
                &self.file_identity.evidence_digest().ok(),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct DispatchedInputRevalidation {
    dispatched: DispatchedInputSnapshot,
    retained_fd_after: ExactFileIdentity,
    path_after: DispatchedInputSnapshot,
}

impl DispatchedInputRevalidation {
    fn new(
        dispatched: DispatchedInputSnapshot,
        retained_fd_after: ExactFileIdentity,
        path_after: DispatchedInputSnapshot,
    ) -> Result<Self, BrowserError> {
        let revalidation = Self {
            dispatched,
            retained_fd_after,
            path_after,
        };
        revalidation.validate()?;
        Ok(revalidation)
    }

    fn validate(&self) -> Result<(), BrowserError> {
        if self.retained_fd_after != self.dispatched.file_identity
            || self.path_after != self.dispatched
        {
            return Err(BrowserError::FileChanged);
        }
        Ok(())
    }

    fn dispatched_evidence_digest(&self) -> Result<String, BrowserError> {
        self.dispatched.evidence_digest()
    }

    fn retained_fd_evidence_digest(&self) -> Result<String, BrowserError> {
        self.retained_fd_after.evidence_digest()
    }

    fn path_evidence_digest(&self) -> Result<String, BrowserError> {
        self.path_after.evidence_digest()
    }
}

fn scan_request_digest(
    request: &ScannerInputRequest<'_>,
    input_snapshot: &DispatchedInputSnapshot,
) -> Result<String, BrowserError> {
    if !is_sha256(request.content_digest)
        || request.byte_count == 0
        || request.content_digest != input_snapshot.file_identity.content_digest
        || request.byte_count != input_snapshot.file_identity.byte_count
    {
        return Err(BrowserError::FileChanged);
    }
    digest_json(&serde_json::json!({
        "contentDigest": request.content_digest,
        "byteCount": request.byte_count,
        "detectedType": request.detected_type,
        "observedAt": request.observed_at,
        "inputIdentityDigest": input_snapshot.evidence_digest()?,
    }))
}

fn accepted_scan_report_evidence(
    verdict_evidence_digest: &str,
    acceptance_digest: &str,
) -> Result<String, BrowserError> {
    if !is_sha256(verdict_evidence_digest) || !is_sha256(acceptance_digest) {
        return Err(BrowserError::FileScanUnavailable);
    }
    digest_json(&serde_json::json!({
        "protocol": SCANNER_PROTOCOL,
        "report": "consumed-one-shot-clean-verdict",
        "verdictEvidenceDigest": verdict_evidence_digest,
        "acceptanceDigest": acceptance_digest,
    }))
}

fn valid_release_identifier(value: &str) -> bool {
    is_bounded_identifier(value) && value.len() <= 128
}

fn validate_private_runtime_root(path: &Path) -> Result<PathBuf, BrowserError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BrowserError::FileScanUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(BrowserError::FileScanUnavailable);
    }
    fs::canonicalize(path).map_err(BrowserError::Io)
}

fn set_private_directory(path: &Path) -> Result<(), BrowserError> {
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))?;
    Ok(())
}

fn open_executable_source(path: &Path) -> Result<File, BrowserError> {
    if !path.is_absolute() {
        return Err(BrowserError::InvalidExecutable);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| BrowserError::InvalidExecutable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BrowserError::InvalidExecutable);
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| BrowserError::InvalidExecutable)
}

fn open_read_only_no_follow(path: &Path) -> Result<File, BrowserError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(BrowserError::Io)
}

fn inspect_path(path: &Path, role: FileRole) -> Result<ExactFileIdentity, BrowserError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(role.error());
    }
    let mut file = open_read_only_no_follow(path)?;
    inspect_open_file(&mut file, role)
}

fn inspect_staged_path(path: &Path) -> Result<(File, DispatchedInputSnapshot), BrowserError> {
    let metadata_before = fs::symlink_metadata(path).map_err(|_| BrowserError::FileChanged)?;
    if metadata_before.file_type().is_symlink() || !metadata_before.is_file() {
        return Err(BrowserError::FileChanged);
    }
    validate_file_metadata(&metadata_before, FileRole::StagedInput)?;
    let canonical_before = fs::canonicalize(path).map_err(|_| BrowserError::FileChanged)?;
    let mut file = open_read_only_no_follow(path).map_err(|_| BrowserError::FileChanged)?;
    let identity = inspect_open_file(&mut file, FileRole::StagedInput)?;
    let metadata_after = fs::symlink_metadata(path).map_err(|_| BrowserError::FileChanged)?;
    validate_file_metadata(&metadata_after, FileRole::StagedInput)?;
    let canonical_after = fs::canonicalize(path).map_err(|_| BrowserError::FileChanged)?;
    if canonical_after != canonical_before
        || !same_metadata_identity(&metadata_before, &metadata_after)
        || !identity.matches_metadata(&metadata_after)
    {
        return Err(BrowserError::FileChanged);
    }
    Ok((
        file,
        DispatchedInputSnapshot {
            canonical_path_digest: digest(canonical_after.as_os_str().as_encoded_bytes()),
            file_identity: identity,
        },
    ))
}

impl FileRole {
    fn error(self) -> BrowserError {
        match self {
            Self::SourceExecutable => BrowserError::InvalidExecutable,
            Self::MaterializedExecutable => BrowserError::FileScanUnavailable,
            Self::StagedInput => BrowserError::FileChanged,
        }
    }
}

fn inspect_open_file(file: &mut File, role: FileRole) -> Result<ExactFileIdentity, BrowserError> {
    let before = file.metadata().map_err(|_| role.error())?;
    validate_file_metadata(&before, role)?;
    file.seek(SeekFrom::Start(0)).map_err(|_| role.error())?;
    let mut hasher = Sha256::new();
    let mut byte_count = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer).map_err(|_| role.error())?;
        if read == 0 {
            break;
        }
        byte_count = byte_count
            .checked_add(u64::try_from(read).map_err(|_| BrowserError::CounterOverflow)?)
            .ok_or(BrowserError::CounterOverflow)?;
        hasher.update(&buffer[..read]);
    }
    let after = file.metadata().map_err(|_| role.error())?;
    validate_file_metadata(&after, role)?;
    if !same_metadata_identity(&before, &after) || byte_count != after.len() || byte_count == 0 {
        return Err(role.error());
    }
    Ok(ExactFileIdentity {
        device: after.dev(),
        inode: after.ino(),
        byte_count,
        modified_seconds: after.mtime(),
        modified_nanoseconds: after.mtime_nsec(),
        change_seconds: after.ctime(),
        change_nanoseconds: after.ctime_nsec(),
        mode: after.mode(),
        owner: after.uid(),
        content_digest: hex::encode(hasher.finalize()),
    })
}

fn validate_file_metadata(metadata: &fs::Metadata, role: FileRole) -> Result<(), BrowserError> {
    if !metadata.is_file() {
        return Err(role.error());
    }
    let mode = metadata.mode();
    let valid_permissions = match role {
        FileRole::SourceExecutable => mode & 0o111 != 0 && mode & 0o022 == 0,
        FileRole::MaterializedExecutable => mode & 0o777 == EXECUTABLE_COPY_MODE,
        FileRole::StagedInput => mode & 0o222 == 0,
    };
    if !valid_permissions {
        return Err(role.error());
    }
    Ok(())
}

fn same_metadata_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
}

fn materialize_executable(
    source: &mut File,
    source_identity: &ExactFileIdentity,
    runtime_directory: &Path,
    expected_digest: &str,
) -> Result<(PathBuf, ExactFileIdentity), BrowserError> {
    source.seek(SeekFrom::Start(0))?;
    let pending_path = runtime_directory.join("scanner-install.pending");
    let final_path = runtime_directory.join(format!("scanner-{expected_digest}"));
    let mut pending = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pending_path)?;
    let install_result = (|| {
        let mut hasher = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            copied = copied
                .checked_add(u64::try_from(read).map_err(|_| BrowserError::CounterOverflow)?)
                .ok_or(BrowserError::CounterOverflow)?;
            hasher.update(&buffer[..read]);
            pending.write_all(&buffer[..read])?;
        }
        let copied_digest = hex::encode(hasher.finalize());
        if copied != source_identity.byte_count || copied_digest != expected_digest {
            return Err(BrowserError::InvalidExecutable);
        }
        pending.flush()?;
        pending.sync_all()?;
        fs::set_permissions(
            &pending_path,
            fs::Permissions::from_mode(EXECUTABLE_COPY_MODE),
        )?;
        pending.sync_all()?;
        drop(pending);
        fs::rename(&pending_path, &final_path)?;
        File::open(runtime_directory)?.sync_all()?;
        let installed = inspect_path(&final_path, FileRole::MaterializedExecutable)?;
        if installed.content_digest != expected_digest
            || installed.byte_count != source_identity.byte_count
        {
            return Err(BrowserError::InvalidExecutable);
        }
        Ok(installed)
    })();
    if install_result.is_err() {
        let _ = fs::remove_file(&pending_path);
        let _ = fs::remove_file(&final_path);
    }
    install_result.map(|identity| (final_path, identity))
}

fn file_type_protocol_name(file_type: BrowserFileType) -> &'static str {
    match file_type {
        BrowserFileType::Pdf => "pdf",
        BrowserFileType::Png => "png",
        BrowserFileType::Jpeg => "jpeg",
        BrowserFileType::Gif => "gif",
        BrowserFileType::WebP => "webp",
        BrowserFileType::Mp4 => "mp4",
        BrowserFileType::Json => "json",
        BrowserFileType::Utf8Text => "utf8_text",
    }
}

fn configure_clean_process(
    command: &mut Command,
    working_directory: &Path,
    home_directory: &Path,
    temp_directory: &Path,
    release_pin: &ScannerReleasePin,
    launch: &ScannerProcessLaunch,
    invocation_contract_digest: &str,
) {
    command
        .current_dir(working_directory)
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("HOME", home_directory)
        .env("TMPDIR", temp_directory)
        .env("HARTEVO_SCANNER_PROTOCOL", SCANNER_PROTOCOL)
        .env("HARTEVO_SCANNER_OPERATION", launch.operation)
        .env("HARTEVO_SCANNER_ID", &release_pin.scanner_id)
        .env("HARTEVO_SCANNER_VERSION", &release_pin.scanner_version)
        .env(
            "HARTEVO_SCANNER_EXECUTABLE_SHA256",
            &release_pin.executable_sha256,
        )
        .env(
            "HARTEVO_SCANNER_RELEASE_DIGEST",
            &release_pin.release_digest,
        )
        .env(
            "HARTEVO_SCANNER_POLICY_VERSION",
            &release_pin.policy_version,
        )
        .env(
            "HARTEVO_SCANNER_RULESET_SHA256",
            &release_pin.ruleset_sha256,
        )
        .env("HARTEVO_SCANNER_CONFIG_SHA256", &release_pin.config_sha256)
        .env("HARTEVO_SCANNER_POLICY_DIGEST", &release_pin.policy_digest)
        .env(
            "HARTEVO_SCANNER_PROCESS_GENERATION",
            launch.generation.to_string(),
        )
        .env("HARTEVO_SCANNER_LAUNCH_DIGEST", &launch.launch_digest)
        .env(
            "HARTEVO_SCANNER_INVOCATION_DIGEST",
            invocation_contract_digest,
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
}

fn configure_scan_input_environment(command: &mut Command, input: &ScannerInvocationInput) {
    command
        .env("HARTEVO_SCANNER_INPUT_FD", SCANNER_INPUT_FD.to_string())
        .env("HARTEVO_SCANNER_CONTENT_SHA256", &input.content_digest)
        .env("HARTEVO_SCANNER_BYTE_COUNT", input.byte_count.to_string())
        .env("HARTEVO_SCANNER_DETECTED_TYPE", input.detected_type)
        .env("HARTEVO_SCANNER_OBSERVED_AT", &input.observed_at);
}

fn configure_process_operation(
    command: &mut Command,
    operation: ProcessOperation<'_, '_>,
    invocation: &ScannerInvocationContract,
) -> Result<(), BrowserError> {
    match operation {
        ProcessOperation::Version if invocation.input.is_none() => Ok(()),
        ProcessOperation::Version => Err(BrowserError::FileScanUnavailable),
        ProcessOperation::Scan { input, .. } => {
            let input_contract = invocation
                .input
                .as_ref()
                .ok_or(BrowserError::FileScanUnavailable)?;
            configure_scan_input_environment(command, input_contract);
            command
                .fd_mappings(vec![FdMapping {
                    parent_fd: OwnedFd::from(input),
                    child_fd: SCANNER_INPUT_FD,
                }])
                .map(|_| ())
                .map_err(|_| BrowserError::FileScanUnavailable)
        }
    }
}

struct ProcessDirectories<'path> {
    working: &'path Path,
    home: &'path Path,
    temporary: &'path Path,
}

fn validate_configured_process(
    command: &Command,
    executable_path: &Path,
    directories: &ProcessDirectories<'_>,
    release_pin: &ScannerReleasePin,
    launch: &ScannerProcessLaunch,
    invocation: &ScannerInvocationContract,
) -> Result<(), BrowserError> {
    let invocation_contract_digest = invocation.evidence_digest()?;
    if invocation.operation != launch.operation
        || invocation.release_digest != release_pin.release_digest
        || invocation.policy_digest != release_pin.policy_digest
        || invocation.executable_identity_digest != launch.executable_identity_digest
        || invocation_contract_digest != launch.invocation_contract_digest
    {
        return Err(BrowserError::FileScanUnavailable);
    }

    let mut expected = Command::new(executable_path);
    configure_clean_process(
        &mut expected,
        directories.working,
        directories.home,
        directories.temporary,
        release_pin,
        launch,
        &invocation_contract_digest,
    );
    if let Some(input) = invocation.input.as_ref() {
        configure_scan_input_environment(&mut expected, input);
    }
    if command.get_program() != expected.get_program()
        || command.get_current_dir() != expected.get_current_dir()
        || !command.get_args().eq(expected.get_args())
        || command_environment(command) != command_environment(&expected)
    {
        return Err(BrowserError::FileScanUnavailable);
    }
    Ok(())
}

fn command_environment(command: &Command) -> BTreeMap<OsString, Option<OsString>> {
    command
        .get_envs()
        .map(|(key, value)| (key.to_os_string(), value.map(OsString::from)))
        .collect()
}

fn parse_exact_json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, BrowserError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer).map_err(|_| BrowserError::FileScanUnavailable)?;
    deserializer
        .end()
        .map_err(|_| BrowserError::FileScanUnavailable)?;
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReaderEvent {
    Overflow(OutputStream),
    Failed(OutputStream),
}

struct BoundedOutput {
    retained: Zeroizing<Vec<u8>>,
    byte_count: u64,
    content_digest: String,
    overflowed: bool,
}

impl BoundedOutput {
    fn validate_complete(&self, maximum: usize) -> Result<(), BrowserError> {
        let retained_byte_count =
            u64::try_from(self.retained.len()).map_err(|_| BrowserError::FileScanUnavailable)?;
        let maximum = u64::try_from(maximum).map_err(|_| BrowserError::FileScanUnavailable)?;
        if self.overflowed
            || self.byte_count > maximum
            || self.byte_count != retained_byte_count
            || !is_sha256(&self.content_digest)
            || digest(&self.retained) != self.content_digest
        {
            return Err(BrowserError::FileScanUnavailable);
        }
        Ok(())
    }

    fn evidence_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "byteCount": self.byte_count,
            "contentDigest": self.content_digest,
            "overflowed": self.overflowed,
        }))
    }
}

impl fmt::Debug for BoundedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedOutput")
            .field("byte_count", &self.byte_count)
            .field("content_digest", &self.content_digest)
            .field("overflowed", &self.overflowed)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExitObservation {
    code: Option<i32>,
    signal: Option<i32>,
    success: bool,
}

impl ExitObservation {
    fn from_status(status: ExitStatus) -> Self {
        Self {
            code: status.code(),
            signal: status.signal(),
            success: status.success(),
        }
    }

    fn success(self) -> bool {
        self.success && self.code == Some(0) && self.signal.is_none()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessCleanupOutcome {
    VerifiedNoResidualProcessGroup,
}

impl ProcessCleanupOutcome {
    fn protocol_name(self) -> &'static str {
        match self {
            Self::VerifiedNoResidualProcessGroup => "verified_no_residual_process_group",
        }
    }
}

struct ProcessObservation {
    identity: ObservedScannerProcessIdentity,
    status: ExitObservation,
    stdout: BoundedOutput,
    stderr: BoundedOutput,
    cleanup_outcome: ProcessCleanupOutcome,
}

impl ProcessObservation {
    fn validate_result_candidate(&self, limits: ScannerProcessLimits) -> Result<(), BrowserError> {
        if !self.status.success()
            || !self.identity.matches_launch(&self.identity.launch)
            || self.cleanup_outcome != ProcessCleanupOutcome::VerifiedNoResidualProcessGroup
        {
            return Err(BrowserError::FileScanUnavailable);
        }
        self.stdout.validate_complete(limits.max_stdout_bytes)?;
        self.stderr.validate_complete(limits.max_stderr_bytes)?;
        Ok(())
    }

    fn evidence_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "processIdentityDigest": self.identity.evidence_digest()?,
            "exit": {
                "code": self.status.code,
                "signal": self.status.signal,
                "success": self.status.success,
            },
            "stdoutDigest": self.stdout.evidence_digest()?,
            "stderrDigest": self.stderr.evidence_digest()?,
            "cleanupOutcome": self.cleanup_outcome.protocol_name(),
        }))
    }
}

impl fmt::Debug for ProcessObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessObservation")
            .field(
                "process_identity_digest",
                &self.identity.evidence_digest().ok(),
            )
            .field("status", &self.status)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("cleanup_outcome", &self.cleanup_outcome)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ScannerResultEnvelope {
    release_digest: String,
    version_probe_evidence_digest: String,
    scanner_id: String,
    scanner_version: String,
    executable_sha256: String,
    policy_version: String,
    ruleset_sha256: String,
    config_sha256: String,
    policy_digest: String,
    executable_identity_digest: String,
    invocation_contract_digest: String,
    process_identity_digest: String,
    launch_identity_digest: String,
    exit: ExitObservation,
    stdout_observation_digest: String,
    stderr_observation_digest: String,
    cleanup_outcome: ProcessCleanupOutcome,
    response_digest: String,
    dispatched_input_identity_digest: String,
    retained_input_fd_after_digest: String,
    input_path_after_digest: String,
    decision: FileScanDecision,
}

impl ScannerResultEnvelope {
    fn from_completed_process(
        release_pin: &ScannerReleasePin,
        version_probe_evidence_digest: &str,
        executable_identity_digest: &str,
        process: &ProcessObservation,
        limits: ScannerProcessLimits,
        input_revalidation: &DispatchedInputRevalidation,
    ) -> Result<Self, BrowserError> {
        release_pin.validate()?;
        process.validate_result_candidate(limits)?;
        input_revalidation.validate()?;
        if !is_sha256(version_probe_evidence_digest)
            || !is_sha256(executable_identity_digest)
            || process.identity.launch.operation != SCAN_OPERATION
            || process.identity.launch.release_digest != release_pin.release_digest
            || process.identity.launch.policy_digest != release_pin.policy_digest
            || process.identity.launch.executable_identity_digest != executable_identity_digest
            || !is_sha256(&process.identity.launch.invocation_contract_digest)
        {
            return Err(BrowserError::FileScanUnavailable);
        }

        let response: ScanResponse = parse_exact_json(&process.stdout.retained)?;
        let identity = response.identity();
        if identity.schema_version != 3
            || identity.scanner_id != release_pin.scanner_id
            || identity.scanner_version != release_pin.scanner_version
            || identity.executable_sha256 != release_pin.executable_sha256
            || identity.policy_digest != release_pin.policy_digest
            || identity.invocation_digest != process.identity.launch.invocation_contract_digest
            || identity.launch_digest != process.identity.launch.launch_digest
        {
            return Err(BrowserError::FileScanUnavailable);
        }
        let decision = match response.decision {
            ScannerDecision::Clean => FileScanDecision::Clean,
            ScannerDecision::Rejected => FileScanDecision::Rejected,
        };
        let response_digest = digest_json(&serde_json::json!({
            "schemaVersion": response.schema_version,
            "scannerId": response.scanner_id,
            "scannerVersion": response.scanner_version,
            "executableSha256": response.executable_sha256,
            "policyDigest": response.policy_digest,
            "invocationDigest": response.invocation_digest,
            "launchDigest": response.launch_digest,
            "decision": decision,
        }))?;
        Ok(Self {
            release_digest: release_pin.release_digest.clone(),
            version_probe_evidence_digest: version_probe_evidence_digest.to_owned(),
            scanner_id: release_pin.scanner_id.clone(),
            scanner_version: release_pin.scanner_version.clone(),
            executable_sha256: release_pin.executable_sha256.clone(),
            policy_version: release_pin.policy_version.clone(),
            ruleset_sha256: release_pin.ruleset_sha256.clone(),
            config_sha256: release_pin.config_sha256.clone(),
            policy_digest: release_pin.policy_digest.clone(),
            executable_identity_digest: executable_identity_digest.to_owned(),
            invocation_contract_digest: process.identity.launch.invocation_contract_digest.clone(),
            process_identity_digest: process.identity.evidence_digest()?,
            launch_identity_digest: process.identity.launch.evidence_digest()?,
            exit: process.status,
            stdout_observation_digest: process.stdout.evidence_digest()?,
            stderr_observation_digest: process.stderr.evidence_digest()?,
            cleanup_outcome: process.cleanup_outcome,
            response_digest,
            dispatched_input_identity_digest: input_revalidation.dispatched_evidence_digest()?,
            retained_input_fd_after_digest: input_revalidation.retained_fd_evidence_digest()?,
            input_path_after_digest: input_revalidation.path_evidence_digest()?,
            decision,
        })
    }

    fn evidence_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "protocol": SCANNER_PROTOCOL,
            "envelope": "scanner-result",
            "releaseDigest": self.release_digest,
            "versionProbeEvidenceDigest": self.version_probe_evidence_digest,
            "scannerId": self.scanner_id,
            "scannerVersion": self.scanner_version,
            "executableSha256": self.executable_sha256,
            "policyVersion": self.policy_version,
            "rulesetSha256": self.ruleset_sha256,
            "configSha256": self.config_sha256,
            "policyDigest": self.policy_digest,
            "executableIdentityDigest": self.executable_identity_digest,
            "invocationContractDigest": self.invocation_contract_digest,
            "processIdentityDigest": self.process_identity_digest,
            "launchIdentityDigest": self.launch_identity_digest,
            "exit": {
                "code": self.exit.code,
                "signal": self.exit.signal,
                "success": self.exit.success,
            },
            "stdoutObservationDigest": self.stdout_observation_digest,
            "stderrObservationDigest": self.stderr_observation_digest,
            "cleanupOutcome": self.cleanup_outcome.protocol_name(),
            "responseDigest": self.response_digest,
            "dispatchedInputIdentityDigest": self.dispatched_input_identity_digest,
            "retainedInputFdAfterDigest": self.retained_input_fd_after_digest,
            "inputPathAfterDigest": self.input_path_after_digest,
            "decision": self.decision,
        }))
    }
}

impl fmt::Debug for ScannerResultEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScannerResultEnvelope")
            .field("release_digest", &self.release_digest)
            .field(
                "version_probe_evidence_digest",
                &self.version_probe_evidence_digest,
            )
            .field("scanner_id", &self.scanner_id)
            .field("scanner_version", &self.scanner_version)
            .field("executable_sha256", &self.executable_sha256)
            .field("policy_version", &self.policy_version)
            .field("ruleset_sha256", &self.ruleset_sha256)
            .field("config_sha256", &self.config_sha256)
            .field("policy_digest", &self.policy_digest)
            .field(
                "executable_identity_digest",
                &self.executable_identity_digest,
            )
            .field(
                "invocation_contract_digest",
                &self.invocation_contract_digest,
            )
            .field("process_identity_digest", &self.process_identity_digest)
            .field("launch_identity_digest", &self.launch_identity_digest)
            .field("exit", &self.exit)
            .field("stdout_observation_digest", &self.stdout_observation_digest)
            .field("stderr_observation_digest", &self.stderr_observation_digest)
            .field("cleanup_outcome", &self.cleanup_outcome)
            .field("response_digest", &self.response_digest)
            .field(
                "dispatched_input_identity_digest",
                &self.dispatched_input_identity_digest,
            )
            .field(
                "retained_input_fd_after_digest",
                &self.retained_input_fd_after_digest,
            )
            .field("input_path_after_digest", &self.input_path_after_digest)
            .field("decision", &self.decision)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanAcceptanceState {
    Pending,
    Consumed,
    Cancelled,
}

struct PendingScanAcceptance {
    state: ScanAcceptanceState,
    acceptance_generation: u64,
    process_generation: u64,
    request_digest: String,
    input_snapshot: DispatchedInputSnapshot,
    release_digest: String,
    executable_identity_digest: String,
    policy_digest: String,
    config_sha256: String,
    invocation_contract_digest: String,
    result_envelope_digest: String,
    launch_digest: String,
    launch_identity_digest: String,
    verdict_evidence_digest: String,
    acceptance_digest: String,
    report: Option<FileScanReport>,
}

impl PendingScanAcceptance {
    fn evidence_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "protocol": SCANNER_PROTOCOL,
            "acceptance": "one-shot-clean-verdict",
            "acceptanceGeneration": self.acceptance_generation.to_string(),
            "processGeneration": self.process_generation.to_string(),
            "requestDigest": self.request_digest,
            "inputIdentityDigest": self.input_snapshot.evidence_digest()?,
            "releaseDigest": self.release_digest,
            "executableIdentityDigest": self.executable_identity_digest,
            "policyDigest": self.policy_digest,
            "configSha256": self.config_sha256,
            "invocationContractDigest": self.invocation_contract_digest,
            "resultEnvelopeDigest": self.result_envelope_digest,
            "launchDigest": self.launch_digest,
            "launchIdentityDigest": self.launch_identity_digest,
            "verdictEvidenceDigest": self.verdict_evidence_digest,
        }))
    }
}

impl fmt::Debug for PendingScanAcceptance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingScanAcceptance")
            .field("state", &self.state)
            .field("acceptance_generation", &self.acceptance_generation)
            .field("process_generation", &self.process_generation)
            .field("request_digest", &self.request_digest)
            .field(
                "input_identity_digest",
                &self.input_snapshot.evidence_digest().ok(),
            )
            .field("release_digest", &self.release_digest)
            .field(
                "executable_identity_digest",
                &self.executable_identity_digest,
            )
            .field("policy_digest", &self.policy_digest)
            .field("config_sha256", &self.config_sha256)
            .field(
                "invocation_contract_digest",
                &self.invocation_contract_digest,
            )
            .field("result_envelope_digest", &self.result_envelope_digest)
            .field("launch_digest", &self.launch_digest)
            .field("launch_identity_digest", &self.launch_identity_digest)
            .field("verdict_evidence_digest", &self.verdict_evidence_digest)
            .field("acceptance_digest", &self.acceptance_digest)
            .finish_non_exhaustive()
    }
}

enum PreparedScanVerdict {
    Clean(Box<PendingScanAcceptance>),
    Rejected(FileScanReport),
}

enum ProcessStop {
    Exited(ExitStatus),
    Timeout,
    OutputViolation,
    WaitFailure,
}

enum ProcessExecution {
    Completed(Box<ProcessObservation>),
    ContainedFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessBoundaryUncertain;

type OutputReader = JoinHandle<std::io::Result<BoundedOutput>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputReaderJoinFailure {
    Deadline,
    JoinedFailure,
}

fn execute_bounded_process(
    command: &mut Command,
    limits: ScannerProcessLimits,
    launch: &ScannerProcessLaunch,
) -> Result<ProcessExecution, ProcessBoundaryUncertain> {
    let Ok(mut child) = command.group_spawn() else {
        return Ok(ProcessExecution::ContainedFailure);
    };
    let identity = ObservedScannerProcessIdentity {
        process_id: child.id(),
        launch: launch.clone(),
    };
    let stdout = child.inner().stdout.take().ok_or(ProcessBoundaryUncertain);
    let stderr = child.inner().stderr.take().ok_or(ProcessBoundaryUncertain);
    let (Ok(stdout), Ok(stderr)) = (stdout, stderr) else {
        return contain_spawned_process(&mut child, []);
    };

    let (event_sender, event_receiver) = bounded(4);
    let stdout_reader = spawn_output_reader(
        stdout,
        OutputStream::Stdout,
        limits.max_stdout_bytes,
        event_sender.clone(),
    );
    let stderr_reader = spawn_output_reader(
        stderr,
        OutputStream::Stderr,
        limits.max_stderr_bytes,
        event_sender,
    );
    let (stdout_reader, stderr_reader) = match (stdout_reader, stderr_reader) {
        (Ok(stdout_reader), Ok(stderr_reader)) => (stdout_reader, stderr_reader),
        (stdout_reader, stderr_reader) => {
            let mut readers = Vec::with_capacity(2);
            if let Ok(reader) = stdout_reader {
                readers.push(reader);
            }
            if let Ok(reader) = stderr_reader {
                readers.push(reader);
            }
            return contain_spawned_process(&mut child, readers);
        }
    };

    let Some(deadline) = Instant::now().checked_add(limits.timeout) else {
        return contain_spawned_process(&mut child, [stdout_reader, stderr_reader]);
    };
    let stop = loop {
        match event_receiver.try_recv() {
            Ok(ReaderEvent::Overflow(stream) | ReaderEvent::Failed(stream)) => {
                let _ = stream;
                break ProcessStop::OutputViolation;
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
        }
        // Poll only the exact leader here. GroupChild::try_wait also reaps
        // descendants and can lose the leader status on a later call.
        match child.inner().try_wait() {
            Ok(Some(status)) => break ProcessStop::Exited(status),
            Ok(None) => {}
            Err(_) => break ProcessStop::WaitFailure,
        }
        if Instant::now() >= deadline {
            break ProcessStop::Timeout;
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    };

    let exited_status = match stop {
        ProcessStop::Exited(status) => Some(status),
        ProcessStop::Timeout | ProcessStop::OutputViolation | ProcessStop::WaitFailure => None,
    };
    let cleanup = terminate_process_group(&mut child, exited_status);
    let stdout = join_output_reader(stdout_reader);
    let stderr = join_output_reader(stderr_reader);
    if cleanup.is_err()
        || matches!(stdout, Err(OutputReaderJoinFailure::Deadline))
        || matches!(stderr, Err(OutputReaderJoinFailure::Deadline))
        || child.id() != identity.process_id
    {
        return Err(ProcessBoundaryUncertain);
    }
    let cleanup = cleanup.map_err(|_| ProcessBoundaryUncertain)?;
    let (Ok(stdout), Ok(stderr)) = (stdout, stderr) else {
        return Ok(ProcessExecution::ContainedFailure);
    };

    match stop {
        ProcessStop::Exited(_)
            if !cleanup.had_live_group_after_leader && !stdout.overflowed && !stderr.overflowed => {
        }
        ProcessStop::Exited(_)
        | ProcessStop::Timeout
        | ProcessStop::OutputViolation
        | ProcessStop::WaitFailure => return Ok(ProcessExecution::ContainedFailure),
    }
    Ok(ProcessExecution::Completed(Box::new(ProcessObservation {
        identity,
        status: ExitObservation::from_status(cleanup.status),
        stdout,
        stderr,
        cleanup_outcome: ProcessCleanupOutcome::VerifiedNoResidualProcessGroup,
    })))
}

fn contain_spawned_process(
    child: &mut GroupChild,
    readers: impl IntoIterator<Item = OutputReader>,
) -> Result<ProcessExecution, ProcessBoundaryUncertain> {
    let cleanup = terminate_process_group(child, None);
    let mut reader_cleanup_uncertain = false;
    for reader in readers {
        if matches!(
            join_output_reader(reader),
            Err(OutputReaderJoinFailure::Deadline)
        ) {
            reader_cleanup_uncertain = true;
        }
    }
    if cleanup.is_err() || reader_cleanup_uncertain {
        Err(ProcessBoundaryUncertain)
    } else {
        Ok(ProcessExecution::ContainedFailure)
    }
}

#[derive(Clone, Copy, Debug)]
struct ProcessCleanup {
    status: ExitStatus,
    had_live_group_after_leader: bool,
}

fn terminate_process_group(
    child: &mut GroupChild,
    leader_status: Option<ExitStatus>,
) -> Result<ProcessCleanup, BrowserError> {
    let deadline = Instant::now()
        .checked_add(PROCESS_CLEANUP_TIMEOUT)
        .ok_or(BrowserError::FileScanUnavailable)?;
    let soft_deadline = Instant::now()
        .checked_add(PROCESS_CLEANUP_TIMEOUT / 2)
        .ok_or(BrowserError::FileScanUnavailable)?;
    let leader_status_supplied = leader_status.is_some();
    let mut status = leader_status;
    let mut had_live_group_after_leader = false;
    let mut force_kill_sent = false;

    if leader_status.is_some() {
        // The exact leader was already reaped through std::process::Child.
        // Give remaining group members a bounded chance to terminate together
        // so a shell can reap its children before force termination.
        had_live_group_after_leader = signal_process_group(child, Signal::SIGTERM)?;
    }
    let mut group_absent = if leader_status.is_some() {
        !had_live_group_after_leader
    } else {
        !signal_process_group(child, Signal::SIGTERM)?
    };

    loop {
        // Preserve the leader's exact status independently of group teardown.
        // Once it is reaped, never wait again; only audit the process group.
        if status.is_none() {
            match child.inner().try_wait() {
                Ok(Some(observed)) => {
                    status = Some(observed);
                }
                Ok(None) => {}
                Err(_) => return Err(BrowserError::FileScanUnavailable),
            }
        }
        if !leader_status_supplied && status.is_some() && !group_absent {
            // The exact leader was reaped through std::process::Child above,
            // so the grouped wait can only reap descendants. Its return value
            // is not authoritative for the already-cached leader status.
            child
                .try_wait()
                .map_err(|_| BrowserError::FileScanUnavailable)?;
        }
        if status.is_some() && group_absent {
            break;
        }
        if !group_absent {
            if force_kill_sent || Instant::now() >= soft_deadline {
                force_kill_sent = true;
                group_absent = !kill_process_group(child)?;
            } else {
                // Re-signal during the bounded cooperative phase. On macOS,
                // EPERM can transiently mean a group whose final member is
                // exiting; only an absent-group error is conclusive.
                group_absent = !signal_process_group(child, Signal::SIGTERM)?;
            }
        }
        if Instant::now() >= deadline {
            return Err(BrowserError::FileScanUnavailable);
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
    let status = status.ok_or(BrowserError::FileScanUnavailable)?;
    Ok(ProcessCleanup {
        status,
        had_live_group_after_leader,
    })
}

fn kill_process_group(child: &mut GroupChild) -> Result<bool, BrowserError> {
    match child.kill() {
        Ok(()) => Ok(true),
        Err(error) if process_group_is_absent(&error) => Ok(false),
        Err(_) => Err(BrowserError::FileScanUnavailable),
    }
}

fn signal_process_group(child: &GroupChild, signal: Signal) -> Result<bool, BrowserError> {
    match child.signal(signal) {
        Ok(()) => Ok(true),
        Err(error) if process_group_is_absent(&error) => Ok(false),
        Err(error) if error.raw_os_error() == Some(libc::EPERM) => Ok(true),
        Err(_) => Err(BrowserError::FileScanUnavailable),
    }
}

fn process_group_is_absent(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::ESRCH) || error.kind() == std::io::ErrorKind::InvalidInput
}

fn spawn_output_reader<R: Read + Send + 'static>(
    reader: R,
    stream: OutputStream,
    maximum: usize,
    event_sender: Sender<ReaderEvent>,
) -> std::io::Result<JoinHandle<std::io::Result<BoundedOutput>>> {
    thread::Builder::new()
        .name(match stream {
            OutputStream::Stdout => "hartevo-scanner-stdout".to_owned(),
            OutputStream::Stderr => "hartevo-scanner-stderr".to_owned(),
        })
        .spawn(move || read_bounded_output(reader, stream, maximum, &event_sender))
}

fn read_bounded_output(
    mut reader: impl Read,
    stream: OutputStream,
    maximum: usize,
    event_sender: &Sender<ReaderEvent>,
) -> std::io::Result<BoundedOutput> {
    let mut retained = Zeroizing::new(Vec::with_capacity(maximum.min(8 * 1024)));
    let mut byte_count = 0_u64;
    let mut hasher = Sha256::new();
    let mut overflowed = false;
    let mut buffer = Zeroizing::new(vec![0_u8; 8 * 1024]);
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(error) => {
                let _ = event_sender.try_send(ReaderEvent::Failed(stream));
                return Err(error);
            }
        };
        if read == 0 {
            break;
        }
        byte_count = byte_count.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        hasher.update(&buffer[..read]);
        let remaining = maximum.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..read.min(remaining)]);
        if !overflowed && byte_count > u64::try_from(maximum).unwrap_or(u64::MAX) {
            overflowed = true;
            let _ = event_sender.try_send(ReaderEvent::Overflow(stream));
        }
    }
    Ok(BoundedOutput {
        retained,
        byte_count,
        content_digest: hex::encode(hasher.finalize()),
        overflowed,
    })
}

fn join_output_reader(reader: OutputReader) -> Result<BoundedOutput, OutputReaderJoinFailure> {
    let Some(deadline) = Instant::now().checked_add(READER_CLEANUP_TIMEOUT) else {
        return Err(OutputReaderJoinFailure::Deadline);
    };
    while !reader.is_finished() {
        if Instant::now() >= deadline {
            return Err(OutputReaderJoinFailure::Deadline);
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
    reader
        .join()
        .map_err(|_| OutputReaderJoinFailure::JoinedFailure)?
        .map_err(|_| OutputReaderJoinFailure::JoinedFailure)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{Mutex, MutexGuard, PoisonError};
    use std::time::Instant;

    use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
    use hartevo_domain_kernel::{
        AccountId, BrowserControlLeaseId, BrowserFileGrantId, BrowserProfileId, BrowserTabId,
        BrowserWorkspaceId, Mission, MissionContract, MissionId, Project, ProjectId, StorageMode,
        TenantId,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::{BrowserIdentity, BrowserProfile, BrowserWorkspace, FileBroker, FileScanDecision};

    const FIXTURE_SCANNER_ID: &str = "fixture-process-boundary";
    const FIXTURE_SCANNER_VERSION: &str = "fixture-v1";
    const FIXTURE_POLICY_VERSION: &str = "fixture-policy-v1";
    static SCANNER_PROCESS_TEST_LANE: Mutex<()> = Mutex::new(());

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 12, 14, 0, 0)
            .single()
            .expect("time")
    }

    struct ScannerFixture {
        temp: TempDir,
        project: Project,
        workspace: BrowserWorkspace,
        project_root: PathBuf,
        broker_root: PathBuf,
        scanner_root: PathBuf,
        _process_test_lane: MutexGuard<'static, ()>,
    }

    impl ScannerFixture {
        fn new() -> Self {
            // These tests intentionally exercise short wall-clock process
            // limits. Serializing their fresh fixture executables keeps host
            // exec/security-scan contention out of the timeout assertions.
            let process_test_lane = SCANNER_PROCESS_TEST_LANE
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let temp = TempDir::new().expect("temp dir");
            let project_root = temp.path().join("project");
            let broker_root = temp.path().join("broker");
            let scanner_root = temp.path().join("scanner-runtime");
            for directory in [&project_root, &broker_root, &scanner_root] {
                fs::create_dir(directory).expect("fixture directory");
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                    .expect("private fixture directory");
            }
            let project = Project::create_local(
                TenantId::from("tenant-production-scanner"),
                ProjectId::from("project-production-scanner"),
                "Production scanner boundary",
                "",
                &project_root,
                StorageMode::LocalExisting,
            )
            .expect("project");
            let mission = Mission::compile(
                project.tenant_id.clone(),
                MissionId::from("mission-production-scanner"),
                project.id.clone(),
                "Scan one upload",
                MissionContract::bootstrap(
                    "Scan an exact staged file",
                    ["deliverable.upload".into()],
                    now(),
                ),
                now(),
            )
            .expect("mission");
            let identity = BrowserIdentity::new(
                "fixture-provider",
                AccountId::from("account-production-scanner"),
                sha('1'),
                sha('2'),
                now(),
            )
            .expect("identity");
            let profile = BrowserProfile::create_managed(
                BrowserProfileId::from("profile-production-scanner"),
                &project,
                "keyring://browser/production-scanner",
                identity,
                now(),
            )
            .expect("profile");
            let workspace = BrowserWorkspace::create(
                BrowserWorkspaceId::from("workspace-production-scanner"),
                &project,
                &mission,
                &profile,
                BrowserTabId::from("tab-production-scanner"),
                BrowserControlLeaseId::from("lease-production-scanner"),
                now() + ChronoDuration::hours(1),
                sha('3'),
                now(),
            )
            .expect("workspace");
            Self {
                temp,
                project,
                workspace,
                project_root,
                broker_root,
                scanner_root,
                _process_test_lane: process_test_lane,
            }
        }

        fn broker(&self) -> FileBroker {
            FileBroker::new(&self.broker_root).expect("file broker")
        }

        fn source(&self, name: &str, content: &[u8]) -> PathBuf {
            let source = self.project_root.join(name);
            fs::write(&source, content).expect("source content");
            source
        }

        fn prepare(
            &self,
            broker: &mut FileBroker,
            scanner: &mut ProductionFileScanner,
            grant_id: &str,
            source: &Path,
        ) -> Result<crate::BrowserFileGrant, BrowserError> {
            broker.prepare_upload(
                BrowserFileGrantId::from(grant_id),
                &self.project,
                &self.workspace,
                &self.workspace.agent_lease_proof(now()).expect("proof"),
                source,
                BrowserFileType::Json,
                sha('4'),
                now() + ChronoDuration::minutes(10),
                now(),
                scanner,
            )
        }
    }

    fn write_scanner_fixture(root: &Path, scan_body: &str) -> (PathBuf, String) {
        let script = format!(
            r#"#!/bin/sh
set -eu
if [ "${{HARTEVO_SCANNER_PROTOCOL-}}" != "{SCANNER_PROTOCOL}" ]; then
  exit 80
fi
emit_version() {{
  printf '{{"schemaVersion":3,"scannerId":"%s","scannerVersion":"%s","executableSha256":"%s","policyDigest":"%s","invocationDigest":"%s","launchDigest":"%s"}}\n' \
    "{FIXTURE_SCANNER_ID}" "{FIXTURE_SCANNER_VERSION}" \
    "$HARTEVO_SCANNER_EXECUTABLE_SHA256" "$HARTEVO_SCANNER_POLICY_DIGEST" \
    "$HARTEVO_SCANNER_INVOCATION_DIGEST" "$HARTEVO_SCANNER_LAUNCH_DIGEST"
}}
emit_scan_with_identity() {{
  printf '{{"schemaVersion":3,"scannerId":"%s","scannerVersion":"%s","executableSha256":"%s","policyDigest":"%s","invocationDigest":"%s","launchDigest":"%s","decision":"%s"}}\n' \
    "$1" "$2" "$3" "$HARTEVO_SCANNER_POLICY_DIGEST" \
    "$HARTEVO_SCANNER_INVOCATION_DIGEST" "$4" "$5"
}}
emit_scan() {{
  emit_scan_with_identity "{FIXTURE_SCANNER_ID}" "{FIXTURE_SCANNER_VERSION}" \
    "$HARTEVO_SCANNER_EXECUTABLE_SHA256" "$HARTEVO_SCANNER_LAUNCH_DIGEST" "$1"
}}
emit_scan_with_launch() {{
  emit_scan_with_identity "{FIXTURE_SCANNER_ID}" "{FIXTURE_SCANNER_VERSION}" \
    "$HARTEVO_SCANNER_EXECUTABLE_SHA256" "$2" "$1"
}}
emit_scan_with_contract() {{
  printf '{{"schemaVersion":3,"scannerId":"%s","scannerVersion":"%s","executableSha256":"%s","policyDigest":"%s","invocationDigest":"%s","launchDigest":"%s","decision":"%s"}}\n' \
    "{FIXTURE_SCANNER_ID}" "{FIXTURE_SCANNER_VERSION}" \
    "$HARTEVO_SCANNER_EXECUTABLE_SHA256" "$1" "$2" \
    "$HARTEVO_SCANNER_LAUNCH_DIGEST" "$3"
}}
emit_scan_unknown() {{
  printf '{{"schemaVersion":3,"scannerId":"%s","scannerVersion":"%s","executableSha256":"%s","policyDigest":"%s","invocationDigest":"%s","launchDigest":"%s","decision":"%s","unknown":true}}\n' \
    "{FIXTURE_SCANNER_ID}" "{FIXTURE_SCANNER_VERSION}" \
    "$HARTEVO_SCANNER_EXECUTABLE_SHA256" "$HARTEVO_SCANNER_POLICY_DIGEST" \
    "$HARTEVO_SCANNER_INVOCATION_DIGEST" "$HARTEVO_SCANNER_LAUNCH_DIGEST" "$1"
}}
case "${{HARTEVO_SCANNER_OPERATION-}}" in
  {VERSION_OPERATION})
    emit_version
    ;;
  {SCAN_OPERATION})
{scan_body}
    ;;
  *)
    exit 81
    ;;
esac
"#
        );
        let path = root.join(format!("fixture-scanner-{}.sh", digest(script.as_bytes())));
        fs::write(&path, script.as_bytes()).expect("scanner fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("scanner fixture executable");
        let executable_digest = hex::encode(Sha256::digest(script.as_bytes()));
        (path, executable_digest)
    }

    fn scanner_with_limits(
        fixture: &ScannerFixture,
        scan_body: &str,
        limits: ScannerProcessLimits,
    ) -> (ProductionFileScanner, PathBuf) {
        let (path, executable_digest) = write_scanner_fixture(&fixture.scanner_root, scan_body);
        let pin = ScannerReleasePin::new(
            FIXTURE_SCANNER_ID,
            FIXTURE_SCANNER_VERSION,
            executable_digest,
            FIXTURE_POLICY_VERSION,
            sha('a'),
            sha('b'),
        )
        .expect("release pin");
        let scanner = ProductionFileScanner::new(&path, &fixture.scanner_root, pin, limits)
            .expect("production-safe scanner process boundary");
        (scanner, path)
    }

    fn default_limits() -> ScannerProcessLimits {
        ScannerProcessLimits::new(Duration::from_secs(2), 4096, 4096).expect("limits")
    }

    fn shell_quote(value: &Path) -> String {
        format!("'{}'", value.to_string_lossy().replace('\'', "'\\''"))
    }

    fn bounded_test_output(bytes: &[u8]) -> BoundedOutput {
        BoundedOutput {
            retained: Zeroizing::new(bytes.to_vec()),
            byte_count: u64::try_from(bytes.len()).expect("bounded fixture output"),
            content_digest: digest(bytes),
            overflowed: false,
        }
    }

    fn test_input_revalidation() -> DispatchedInputRevalidation {
        let file_identity = ExactFileIdentity {
            device: 11,
            inode: 12,
            byte_count: 2,
            modified_seconds: 13,
            modified_nanoseconds: 14,
            change_seconds: 15,
            change_nanoseconds: 16,
            mode: 0o100_400,
            owner: 17,
            content_digest: digest(b"{}"),
        };
        let dispatched = DispatchedInputSnapshot {
            canonical_path_digest: sha('e'),
            file_identity: file_identity.clone(),
        };
        DispatchedInputRevalidation::new(dispatched.clone(), file_identity, dispatched)
            .expect("input revalidation")
    }

    fn read_only_scan_source(
        fixture: &ScannerFixture,
        name: &str,
        content: &[u8],
    ) -> (PathBuf, String) {
        let source = fixture.source(name, content);
        fs::set_permissions(&source, fs::Permissions::from_mode(0o400))
            .expect("read-only direct scan source");
        (source, digest(content))
    }

    fn prepare_clean_acceptance(
        scanner: &mut ProductionFileScanner,
        request: &ScannerInputRequest<'_>,
    ) -> PendingScanAcceptance {
        match scanner
            .prepare_scan_verdict(request)
            .expect("prepared scanner verdict")
        {
            PreparedScanVerdict::Clean(acceptance) => *acceptance,
            PreparedScanVerdict::Rejected(_) => panic!("clean fixture rejected"),
        }
    }

    #[test]
    fn process_environment_is_an_exact_allowlist_without_path() {
        let fixture = ScannerFixture::new();
        let working = fixture.scanner_root.join("environment-run");
        let home = working.join("home");
        let temporary = working.join("tmp");
        for directory in [&working, &home, &temporary] {
            fs::create_dir(directory).expect("environment fixture directory");
        }
        let mut command = Command::new("/not/executed");
        command
            .env("PATH", "/ambient/path-must-not-survive")
            .env("HARTEVO_AMBIENT_SECRET", "must-not-survive");
        let release_pin = ScannerReleasePin::new(
            FIXTURE_SCANNER_ID,
            FIXTURE_SCANNER_VERSION,
            sha('5'),
            FIXTURE_POLICY_VERSION,
            sha('a'),
            sha('b'),
        )
        .expect("release pin");
        let executable_identity_digest = sha('6');
        let invocation = ScannerInvocationContract::new(
            &ProcessOperation::Version,
            &release_pin,
            &executable_identity_digest,
            default_limits(),
        )
        .expect("invocation contract");
        let invocation_digest = invocation.evidence_digest().expect("invocation digest");
        let launch = ScannerProcessLaunch::new(
            7,
            VERSION_OPERATION,
            release_pin.release_digest(),
            release_pin.policy_digest(),
            &executable_identity_digest,
            &invocation_digest,
            &sha('7'),
        )
        .expect("launch identity");
        configure_clean_process(
            &mut command,
            &working,
            &home,
            &temporary,
            &release_pin,
            &launch,
            &invocation_digest,
        );
        let environment = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            environment.keys().map(String::as_str).collect::<Vec<_>>(),
            vec![
                "HARTEVO_SCANNER_CONFIG_SHA256",
                "HARTEVO_SCANNER_EXECUTABLE_SHA256",
                "HARTEVO_SCANNER_ID",
                "HARTEVO_SCANNER_INVOCATION_DIGEST",
                "HARTEVO_SCANNER_LAUNCH_DIGEST",
                "HARTEVO_SCANNER_OPERATION",
                "HARTEVO_SCANNER_POLICY_DIGEST",
                "HARTEVO_SCANNER_POLICY_VERSION",
                "HARTEVO_SCANNER_PROCESS_GENERATION",
                "HARTEVO_SCANNER_PROTOCOL",
                "HARTEVO_SCANNER_RELEASE_DIGEST",
                "HARTEVO_SCANNER_RULESET_SHA256",
                "HARTEVO_SCANNER_VERSION",
                "HOME",
                "LANG",
                "LC_ALL",
                "TMPDIR",
            ]
        );
        assert_eq!(
            environment["HARTEVO_SCANNER_OPERATION"].as_deref(),
            Some(VERSION_OPERATION)
        );
        assert_eq!(
            environment["HARTEVO_SCANNER_PROTOCOL"].as_deref(),
            Some(SCANNER_PROTOCOL)
        );
        assert_eq!(
            environment["HARTEVO_SCANNER_LAUNCH_DIGEST"].as_deref(),
            Some(launch.launch_digest.as_str())
        );
        assert_eq!(
            environment["HARTEVO_SCANNER_PROCESS_GENERATION"].as_deref(),
            Some("7")
        );
        assert_eq!(command.get_current_dir(), Some(working.as_path()));
        assert!(!environment.contains_key("PATH"));
        assert!(!environment.contains_key("HARTEVO_AMBIENT_SECRET"));
    }

    #[test]
    fn invocation_argument_drift_is_rejected_before_spawn() {
        let fixture = ScannerFixture::new();
        let working = fixture.scanner_root.join("argument-drift-run");
        let home = working.join("home");
        let temporary = working.join("tmp");
        for directory in [&working, &home, &temporary] {
            fs::create_dir(directory).expect("invocation fixture directory");
        }
        let release_pin = ScannerReleasePin::new(
            FIXTURE_SCANNER_ID,
            FIXTURE_SCANNER_VERSION,
            sha('5'),
            FIXTURE_POLICY_VERSION,
            sha('a'),
            sha('b'),
        )
        .expect("release pin");
        let executable_identity_digest = sha('6');
        let invocation = ScannerInvocationContract::new(
            &ProcessOperation::Version,
            &release_pin,
            &executable_identity_digest,
            default_limits(),
        )
        .expect("invocation contract");
        let invocation_digest = invocation.evidence_digest().expect("invocation digest");
        let launch = ScannerProcessLaunch::new(
            7,
            VERSION_OPERATION,
            release_pin.release_digest(),
            release_pin.policy_digest(),
            &executable_identity_digest,
            &invocation_digest,
            &sha('7'),
        )
        .expect("launch identity");
        let mut command = Command::new("/not/executed");
        configure_clean_process(
            &mut command,
            &working,
            &home,
            &temporary,
            &release_pin,
            &launch,
            &invocation_digest,
        );
        let directories = ProcessDirectories {
            working: &working,
            home: &home,
            temporary: &temporary,
        };
        validate_configured_process(
            &command,
            Path::new("/not/executed"),
            &directories,
            &release_pin,
            &launch,
            &invocation,
        )
        .expect("exact configured invocation");
        command.arg("--unexpected-policy-override");
        assert!(matches!(
            validate_configured_process(
                &command,
                Path::new("/not/executed"),
                &directories,
                &release_pin,
                &launch,
                &invocation,
            ),
            Err(BrowserError::FileScanUnavailable)
        ));
    }

    #[test]
    fn clean_fixture_uses_exact_fd_clean_environment_and_content_free_receipt() {
        let fixture = ScannerFixture::new();
        let private_content = br#"{"customer":"private@example.com","status":"ready"}"#;
        let source = fixture.source("private-customer-deliverable.json", private_content);
        let clean_body = r#"    [ "${LC_ALL-}" = "C" ] || exit 91
    [ "${LANG-}" = "C" ] || exit 92
    [ -d "${HOME-}" ] || exit 93
    [ -d "${TMPDIR-}" ] || exit 94
    [ "${HARTEVO_SCANNER_INPUT_FD-}" = "3" ] || exit 95
    [ "${HARTEVO_SCANNER_DETECTED_TYPE-}" = "json" ] || exit 96
    content=''
    IFS= read -r content <&3 || true
    [ "$content" = '{"customer":"private@example.com","status":"ready"}' ] || exit 97
    printf '%s' 'private-scanner-diagnostic' >&2
    emit_scan clean"#;
        let (mut scanner, source_executable) =
            scanner_with_limits(&fixture, clean_body, default_limits());

        fs::write(
            &source_executable,
            b"#!/bin/sh\nprintf '%s\\n' '{\"schemaVersion\":1,\"decision\":\"rejected\"}'\n",
        )
        .expect("replace the no-longer-authoritative source path");
        fs::set_permissions(&source_executable, fs::Permissions::from_mode(0o700))
            .expect("replacement permissions");

        let mut broker = fixture.broker();
        let grant = fixture
            .prepare(
                &mut broker,
                &mut scanner,
                "grant-production-scanner-clean",
                &source,
            )
            .expect("clean grant from immutable private copy");
        assert_eq!(grant.scan_report.decision, FileScanDecision::Clean);
        assert_eq!(grant.scan_report.scanner_id, FIXTURE_SCANNER_ID);
        assert_eq!(grant.scan_report.scanner_version, FIXTURE_SCANNER_VERSION);
        let debug = format!("{scanner:?} {grant:?}");
        assert!(!debug.contains("private@example.com"));
        assert!(!debug.contains("private-scanner-diagnostic"));
        assert!(!debug.contains(source.to_string_lossy().as_ref()));
        assert!(!debug.contains("private-customer-deliverable.json"));
    }

    #[test]
    fn result_envelope_binds_identity_version_exit_streams_and_cleanup_without_raw_output() {
        let release_pin = ScannerReleasePin::new(
            FIXTURE_SCANNER_ID,
            FIXTURE_SCANNER_VERSION,
            sha('5'),
            FIXTURE_POLICY_VERSION,
            sha('a'),
            sha('b'),
        )
        .expect("release pin");
        let executable_identity_digest = sha('6');
        let invocation_digest = sha('8');
        let launch = ScannerProcessLaunch::new(
            9,
            SCAN_OPERATION,
            release_pin.release_digest(),
            release_pin.policy_digest(),
            &executable_identity_digest,
            &invocation_digest,
            &sha('7'),
        )
        .expect("launch");
        let stdout = format!(
            r#"{{"schemaVersion":3,"scannerId":"{FIXTURE_SCANNER_ID}","scannerVersion":"{FIXTURE_SCANNER_VERSION}","executableSha256":"{}","policyDigest":"{}","invocationDigest":"{}","launchDigest":"{}","decision":"clean"}}
"#,
            release_pin.executable_sha256(),
            release_pin.policy_digest(),
            invocation_digest,
            launch.launch_digest,
        );
        let process = ProcessObservation {
            identity: ObservedScannerProcessIdentity {
                process_id: 42,
                launch,
            },
            status: ExitObservation {
                code: Some(0),
                signal: None,
                success: true,
            },
            stdout: bounded_test_output(stdout.as_bytes()),
            stderr: bounded_test_output(b"private-result-envelope-stderr"),
            cleanup_outcome: ProcessCleanupOutcome::VerifiedNoResidualProcessGroup,
        };
        let input_revalidation = test_input_revalidation();
        let envelope = ScannerResultEnvelope::from_completed_process(
            &release_pin,
            &sha('4'),
            &executable_identity_digest,
            &process,
            default_limits(),
            &input_revalidation,
        )
        .expect("verified result envelope");
        let baseline = envelope.evidence_digest().expect("envelope evidence");
        assert_eq!(envelope.decision, FileScanDecision::Clean);
        assert_eq!(
            envelope.cleanup_outcome.protocol_name(),
            "verified_no_residual_process_group"
        );
        assert!(!format!("{envelope:?}").contains("private-result-envelope-stderr"));

        let mut variants = Vec::new();
        let mut changed = envelope.clone();
        changed.scanner_version = "fixture-v2".to_owned();
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.process_identity_digest = sha('9');
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.executable_sha256 = sha('a');
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.policy_digest = sha('c');
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.invocation_contract_digest = sha('d');
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.exit.code = Some(23);
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.exit.signal = Some(9);
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.stdout_observation_digest = sha('b');
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.stderr_observation_digest = sha('c');
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.response_digest = sha('d');
        variants.push(changed);
        let mut changed = envelope;
        changed.dispatched_input_identity_digest = sha('f');
        variants.push(changed);
        for changed in variants {
            assert_ne!(
                changed.evidence_digest().expect("changed evidence"),
                baseline
            );
        }
    }

    #[test]
    fn clean_acceptance_binds_full_verdict_context_and_is_consumed_exactly_once() {
        let fixture = ScannerFixture::new();
        let private_content = br#"{"private-one-shot":"customer@example.com"}"#;
        let (source, content_digest) =
            read_only_scan_source(&fixture, "private-one-shot.json", private_content);
        let request = ScannerInputRequest {
            staged_path: &source,
            content_digest: &content_digest,
            byte_count: u64::try_from(private_content.len()).expect("private content length"),
            detected_type: BrowserFileType::Json,
            observed_at: now(),
        };
        let (mut scanner, _) =
            scanner_with_limits(&fixture, "    emit_scan clean", default_limits());
        let mut acceptance = prepare_clean_acceptance(&mut scanner, &request);
        let baseline = acceptance.evidence_digest().expect("acceptance evidence");
        assert_eq!(acceptance.acceptance_digest, baseline);
        assert_eq!(acceptance.state, ScanAcceptanceState::Pending);
        assert_eq!(acceptance.process_generation, scanner.process_generation);
        assert_eq!(
            scanner.pending_acceptance_digest.as_deref(),
            Some(baseline.as_str())
        );

        let request_digest = acceptance.request_digest.clone();
        acceptance.request_digest = sha('0');
        assert_ne!(
            acceptance.evidence_digest().expect("request drift"),
            baseline
        );
        acceptance.request_digest = request_digest;
        let executable_identity_digest = acceptance.executable_identity_digest.clone();
        acceptance.executable_identity_digest = sha('1');
        assert_ne!(
            acceptance.evidence_digest().expect("executable drift"),
            baseline
        );
        acceptance.executable_identity_digest = executable_identity_digest;
        let policy_digest = acceptance.policy_digest.clone();
        acceptance.policy_digest = sha('2');
        assert_ne!(
            acceptance.evidence_digest().expect("policy drift"),
            baseline
        );
        acceptance.policy_digest = policy_digest;
        let config_sha256 = acceptance.config_sha256.clone();
        acceptance.config_sha256 = sha('3');
        assert_ne!(
            acceptance.evidence_digest().expect("config drift"),
            baseline
        );
        acceptance.config_sha256 = config_sha256;
        let invocation_digest = acceptance.invocation_contract_digest.clone();
        acceptance.invocation_contract_digest = sha('4');
        assert_ne!(
            acceptance.evidence_digest().expect("invocation drift"),
            baseline
        );
        acceptance.invocation_contract_digest = invocation_digest;
        let result_envelope_digest = acceptance.result_envelope_digest.clone();
        acceptance.result_envelope_digest = sha('5');
        assert_ne!(
            acceptance.evidence_digest().expect("result envelope drift"),
            baseline
        );
        acceptance.result_envelope_digest = result_envelope_digest;
        let process_generation = acceptance.process_generation;
        acceptance.process_generation = process_generation.checked_add(1).expect("next generation");
        assert_ne!(
            acceptance.evidence_digest().expect("lifecycle drift"),
            baseline
        );
        acceptance.process_generation = process_generation;
        assert_eq!(
            acceptance.evidence_digest().expect("restored token"),
            baseline
        );

        let debug = format!("{scanner:?} {acceptance:?}");
        assert!(!debug.contains("customer@example.com"));
        assert!(!debug.contains(source.to_string_lossy().as_ref()));
        let report = scanner
            .consume_scan_acceptance(&mut acceptance, &request)
            .expect("one-shot acceptance consumption");
        assert_eq!(report.decision, FileScanDecision::Clean);
        assert_eq!(acceptance.state, ScanAcceptanceState::Consumed);
        assert!(scanner.pending_acceptance_digest.is_none());
        assert!(matches!(
            scanner.consume_scan_acceptance(&mut acceptance, &request),
            Err(BrowserError::FileScanUnavailable)
        ));
        assert_eq!(acceptance.state, ScanAcceptanceState::Consumed);
        assert!(!format!("{scanner:?} {acceptance:?}").contains("customer@example.com"));
        assert_no_run_directory_residue(&scanner);
    }

    #[test]
    fn cancellation_cross_file_supersession_and_stale_generation_reject_acceptance() {
        let fixture = ScannerFixture::new();
        let private_content = br#"{"same-private-content":"lease-bound"}"#;
        let (first_source, content_digest) =
            read_only_scan_source(&fixture, "acceptance-first.json", private_content);
        let (second_source, second_content_digest) =
            read_only_scan_source(&fixture, "acceptance-second.json", private_content);
        let byte_count = u64::try_from(private_content.len()).expect("private content length");
        let first_request = ScannerInputRequest {
            staged_path: &first_source,
            content_digest: &content_digest,
            byte_count,
            detected_type: BrowserFileType::Json,
            observed_at: now(),
        };
        let second_request = ScannerInputRequest {
            staged_path: &second_source,
            content_digest: &second_content_digest,
            byte_count,
            detected_type: BrowserFileType::Json,
            observed_at: now(),
        };
        let (mut scanner, _) =
            scanner_with_limits(&fixture, "    emit_scan clean", default_limits());

        let mut cancelled = prepare_clean_acceptance(&mut scanner, &first_request);
        scanner
            .cancel_pending_acceptance()
            .expect("lease-loss cancellation");
        assert!(matches!(
            scanner.consume_scan_acceptance(&mut cancelled, &first_request),
            Err(BrowserError::FileScanUnavailable)
        ));
        assert_eq!(cancelled.state, ScanAcceptanceState::Cancelled);

        let mut cross_file = prepare_clean_acceptance(&mut scanner, &first_request);
        assert!(matches!(
            scanner.consume_scan_acceptance(&mut cross_file, &second_request),
            Err(BrowserError::FileScanUnavailable)
        ));
        assert_eq!(cross_file.state, ScanAcceptanceState::Cancelled);

        let mut superseded = prepare_clean_acceptance(&mut scanner, &first_request);
        let mut replacement = prepare_clean_acceptance(&mut scanner, &second_request);
        assert!(matches!(
            scanner.consume_scan_acceptance(&mut superseded, &first_request),
            Err(BrowserError::FileScanUnavailable)
        ));
        assert_eq!(superseded.state, ScanAcceptanceState::Cancelled);
        assert_eq!(
            scanner
                .consume_scan_acceptance(&mut replacement, &second_request)
                .expect("current superseding acceptance")
                .decision,
            FileScanDecision::Clean
        );

        let mut stale = prepare_clean_acceptance(&mut scanner, &first_request);
        let version_process = scanner
            .run_process(ProcessOperation::Version)
            .expect("new lifecycle generation");
        assert!(version_process.status.success());
        assert!(matches!(
            scanner.consume_scan_acceptance(&mut stale, &first_request),
            Err(BrowserError::FileScanUnavailable)
        ));
        assert_eq!(stale.state, ScanAcceptanceState::Cancelled);
        let debug = format!("{scanner:?} {cancelled:?} {cross_file:?} {superseded:?} {stale:?}");
        assert!(!debug.contains("lease-bound"));
        assert!(!debug.contains(first_source.to_string_lossy().as_ref()));
        assert!(!debug.contains(second_source.to_string_lossy().as_ref()));
        assert_no_run_directory_residue(&scanner);
    }

    #[test]
    fn partial_truncated_malformed_and_killed_generation_results_fail_closed_without_raw_output() {
        let cases = [
            (
                "truncated",
                r#"    printf '%s' '{"schemaVersion":3,"scannerId":"private-truncated-result'"#,
            ),
            (
                "malformed",
                r"    emit_scan clean
    printf '%s' 'private-malformed-trailing-result'",
            ),
            (
                "signaled",
                r"    emit_scan clean
    printf '%s' 'private-signaled-result' >&2
    kill -9 $$",
            ),
            (
                "killed-after-timeout",
                r"    emit_scan clean
    printf '%s' 'private-killed-buffered-result' >&2
    /bin/sleep 30",
            ),
        ];
        for (index, (name, body)) in cases.into_iter().enumerate() {
            let fixture = ScannerFixture::new();
            let source = fixture.source(&format!("invalid-result-{index}.json"), b"{}");
            let (mut scanner, _) = scanner_with_limits(&fixture, body, default_limits());
            let mut broker = fixture.broker();
            let grant_id_value = format!("grant-invalid-result-{index}");
            let grant_id = BrowserFileGrantId::from(grant_id_value.as_str());
            let result = fixture.prepare(&mut broker, &mut scanner, grant_id.as_str(), &source);
            assert!(
                matches!(result, Err(BrowserError::FileScanUnavailable)),
                "{name} result was not rejected"
            );
            assert!(broker.grant(&grant_id).is_none());
            let debug = format!("{result:?} {scanner:?} {broker:?}");
            assert!(!debug.contains("private-truncated-result"));
            assert!(!debug.contains("private-malformed-trailing-result"));
            assert!(!debug.contains("private-signaled-result"));
            assert!(!debug.contains("private-killed-buffered-result"));
            assert_no_run_directory_residue(&scanner);
        }
    }

    #[test]
    fn typed_rejected_verdict_creates_no_grant_or_staged_residue() {
        let fixture = ScannerFixture::new();
        let source = fixture.source("rejected.json", br#"{"status":"blocked"}"#);
        let (mut scanner, _) =
            scanner_with_limits(&fixture, "    emit_scan rejected", default_limits());
        let mut broker = fixture.broker();
        let grant_id = BrowserFileGrantId::from("grant-production-scanner-rejected");
        let result = fixture.prepare(&mut broker, &mut scanner, grant_id.as_str(), &source);
        assert!(matches!(result, Err(BrowserError::FileScanRejected)));
        assert!(broker.grant(&grant_id).is_none());
        let debug = format!("{broker:?}");
        assert!(debug.contains("grant_count: 0"));
        assert!(debug.contains("staged_file_count: 0"));
    }

    #[test]
    fn release_version_and_private_executable_drift_fail_closed() {
        let fixture = ScannerFixture::new();
        let body = "    emit_scan clean";
        let (path, executable_digest) = write_scanner_fixture(&fixture.scanner_root, body);
        let wrong_pin = ScannerReleasePin::new(
            FIXTURE_SCANNER_ID,
            FIXTURE_SCANNER_VERSION,
            sha('9'),
            FIXTURE_POLICY_VERSION,
            sha('a'),
            sha('b'),
        )
        .expect("shaped wrong pin");
        assert!(matches!(
            ProductionFileScanner::new(&path, &fixture.scanner_root, wrong_pin, default_limits()),
            Err(BrowserError::InvalidExecutable)
        ));

        let wrong_version = ScannerReleasePin::new(
            FIXTURE_SCANNER_ID,
            "fixture-v2",
            executable_digest.clone(),
            FIXTURE_POLICY_VERSION,
            sha('a'),
            sha('b'),
        )
        .expect("wrong version pin");
        assert!(matches!(
            ProductionFileScanner::new(
                &path,
                &fixture.scanner_root,
                wrong_version,
                default_limits()
            ),
            Err(BrowserError::FileScanUnavailable)
        ));

        let good_pin = ScannerReleasePin::new(
            FIXTURE_SCANNER_ID,
            FIXTURE_SCANNER_VERSION,
            executable_digest,
            FIXTURE_POLICY_VERSION,
            sha('a'),
            sha('b'),
        )
        .expect("good pin");
        let mut config_drift = good_pin.clone();
        config_drift.config_sha256 = sha('c');
        let mut ruleset_drift = good_pin.clone();
        ruleset_drift.ruleset_sha256 = sha('d');
        let mut policy_version_drift = good_pin.clone();
        policy_version_drift.policy_version = "fixture-policy-v2".to_owned();
        for drifted_policy in [config_drift, ruleset_drift, policy_version_drift] {
            assert!(matches!(
                ProductionFileScanner::new(
                    &path,
                    &fixture.scanner_root,
                    drifted_policy,
                    default_limits()
                ),
                Err(BrowserError::FileScanUnavailable)
            ));
        }
        let mut scanner =
            ProductionFileScanner::new(&path, &fixture.scanner_root, good_pin, default_limits())
                .expect("scanner");
        fs::set_permissions(&scanner.executable_path, fs::Permissions::from_mode(0o700))
            .expect("make private copy writable for tamper fixture");
        fs::write(&scanner.executable_path, b"tampered private executable")
            .expect("tamper private copy");
        let source = fixture.source("private-copy-drift.json", b"{}");
        let mut broker = fixture.broker();
        assert!(matches!(
            fixture.prepare(
                &mut broker,
                &mut scanner,
                "grant-private-copy-drift",
                &source
            ),
            Err(BrowserError::FileScanUnavailable)
        ));
    }

    #[test]
    fn malformed_unknown_nonzero_and_signaled_protocols_fail_closed() {
        let cases = [
            "    emit_scan_unknown clean",
            r"    printf '%s\n' '{'",
            "    emit_scan unavailable",
            "    exit 23",
            "    kill -9 $$",
        ];
        for (index, body) in cases.into_iter().enumerate() {
            let fixture = ScannerFixture::new();
            let source = fixture.source(&format!("protocol-{index}.json"), b"{}");
            let (mut scanner, _) = scanner_with_limits(&fixture, body, default_limits());
            let mut broker = fixture.broker();
            let result = fixture.prepare(
                &mut broker,
                &mut scanner,
                &format!("grant-protocol-{index}"),
                &source,
            );
            assert!(
                matches!(result, Err(BrowserError::FileScanUnavailable)),
                "case {index}: {result:?}"
            );
        }
    }

    #[test]
    fn stdout_and_stderr_overflow_are_bounded_and_fail_closed() {
        let cases = [
            r#"    count=0
    while [ "$count" -lt 4096 ]; do
      printf x
      count=$((count + 1))
    done"#,
            r#"    count=0
    while [ "$count" -lt 4096 ]; do
      printf x >&2
      count=$((count + 1))
    done
    emit_scan clean"#,
        ];
        for (index, body) in cases.into_iter().enumerate() {
            let fixture = ScannerFixture::new();
            let source = fixture.source(&format!("overflow-{index}.json"), b"{}");
            let limits = ScannerProcessLimits::new(Duration::from_secs(2), 512, 512)
                .expect("small bounded outputs");
            let (mut scanner, _) = scanner_with_limits(&fixture, body, limits);
            let mut broker = fixture.broker();
            let started = Instant::now();
            let result = fixture.prepare(
                &mut broker,
                &mut scanner,
                &format!("grant-overflow-{index}"),
                &source,
            );
            assert!(matches!(result, Err(BrowserError::FileScanUnavailable)));
            assert!(started.elapsed() < Duration::from_secs(4));
        }
    }

    #[test]
    fn timeout_kills_the_process_group_and_a_new_generation_can_scan() {
        let fixture = ScannerFixture::new();
        let first_marker = fixture.temp.path().join("first-scan.marker");
        let body = format!(
            r"    if [ ! -f {marker} ]; then
      printf first > {marker}
      printf '%s' 'private-partial-stdout'
      printf '%s' 'private-partial-stderr' >&2
      /bin/sleep 30 &
      wait
    fi
    emit_scan clean",
            marker = shell_quote(&first_marker),
        );
        let limits =
            ScannerProcessLimits::new(Duration::from_secs(2), 4096, 4096).expect("timeout limits");
        let (mut scanner, _) = scanner_with_limits(&fixture, &body, limits);
        let mut broker = fixture.broker();
        let first_source = fixture.source("timeout-first.json", b"{}");
        let started = Instant::now();
        let first = fixture.prepare(
            &mut broker,
            &mut scanner,
            "grant-timeout-first",
            &first_source,
        );
        assert!(matches!(first, Err(BrowserError::FileScanUnavailable)));
        assert!(started.elapsed() < Duration::from_secs(6));
        assert_eq!(scanner.process_generation, 2);
        assert!(!scanner.process_boundary_poisoned);
        assert!(scanner.active_launch_digest.is_none());
        assert!(!format!("{scanner:?}").contains("private-partial"));
        assert_no_run_directory_residue(&scanner);

        let second_source = fixture.source("timeout-second.json", b"{}");
        let second = fixture
            .prepare(
                &mut broker,
                &mut scanner,
                "grant-timeout-second",
                &second_source,
            )
            .expect("fresh scanner process after timeout");
        assert_eq!(second.scan_report.decision, FileScanDecision::Clean);
        assert_eq!(scanner.process_generation, 3);
        assert!(!scanner.process_boundary_poisoned);
        assert_no_run_directory_residue(&scanner);
    }

    #[test]
    fn every_result_revalidates_scanner_release_policy_and_invocation_before_restart() {
        let cases = [
            (
                "scanner-id",
                format!(
                    "    emit_scan_with_identity fixture-impostor {FIXTURE_SCANNER_VERSION} \"$HARTEVO_SCANNER_EXECUTABLE_SHA256\" \"$HARTEVO_SCANNER_LAUNCH_DIGEST\" clean"
                ),
            ),
            (
                "scanner-version",
                format!(
                    "    emit_scan_with_identity {FIXTURE_SCANNER_ID} fixture-v9 \"$HARTEVO_SCANNER_EXECUTABLE_SHA256\" \"$HARTEVO_SCANNER_LAUNCH_DIGEST\" clean"
                ),
            ),
            (
                "executable-digest",
                format!(
                    "    emit_scan_with_identity {FIXTURE_SCANNER_ID} {FIXTURE_SCANNER_VERSION} {} \"$HARTEVO_SCANNER_LAUNCH_DIGEST\" clean",
                    sha('9')
                ),
            ),
            (
                "policy-digest",
                format!(
                    "    emit_scan_with_contract {} \"$HARTEVO_SCANNER_INVOCATION_DIGEST\" clean",
                    sha('9')
                ),
            ),
            (
                "invocation-digest",
                format!(
                    "    emit_scan_with_contract \"$HARTEVO_SCANNER_POLICY_DIGEST\" {} clean",
                    sha('8')
                ),
            ),
        ];
        for (index, (name, response)) in cases.into_iter().enumerate() {
            let fixture = ScannerFixture::new();
            let launched = fixture.temp.path().join(format!("{name}.launched"));
            let body = format!(
                "    printf launched > {}\n{response}",
                shell_quote(&launched)
            );
            let (mut scanner, _) = scanner_with_limits(&fixture, &body, default_limits());
            let mut broker = fixture.broker();
            let first_source = fixture.source(&format!("identity-{index}-first.json"), b"{}");
            assert!(matches!(
                fixture.prepare(
                    &mut broker,
                    &mut scanner,
                    &format!("grant-identity-{index}-first"),
                    &first_source
                ),
                Err(BrowserError::FileScanUnavailable)
            ));
            assert!(launched.exists());
            assert_eq!(scanner.process_generation, 2);
            assert!(scanner.process_boundary_poisoned);
            assert!(scanner.active_launch_digest.is_none());
            fs::remove_file(&launched).expect("remove first launch marker");

            let second_source = fixture.source(&format!("identity-{index}-second.json"), b"{}");
            assert!(matches!(
                fixture.prepare(
                    &mut broker,
                    &mut scanner,
                    &format!("grant-identity-{index}-second"),
                    &second_source
                ),
                Err(BrowserError::FileScanUnavailable)
            ));
            assert!(!launched.exists(), "poisoned {name} boundary relaunched");
            assert_eq!(scanner.process_generation, 2);
            assert_no_run_directory_residue(&scanner);
        }
    }

    #[test]
    fn stale_launch_result_is_rejected_and_poisoned_generation_never_restarts() {
        let fixture = ScannerFixture::new();
        let count = fixture.temp.path().join("launch-count.marker");
        let first_launch = fixture.temp.path().join("first-launch-digest.marker");
        let body = format!(
            r#"    launch_count=0
    if [ -f {count} ]; then
      IFS= read -r launch_count < {count}
    fi
    launch_count=$((launch_count + 1))
    printf '%s\n' "$launch_count" > {count}
    if [ "$launch_count" -eq 1 ]; then
      printf '%s\n' "$HARTEVO_SCANNER_LAUNCH_DIGEST" > {first_launch}
      emit_scan clean
    else
      stale_launch=''
      IFS= read -r stale_launch < {first_launch}
      emit_scan_with_launch clean "$stale_launch"
    fi"#,
            count = shell_quote(&count),
            first_launch = shell_quote(&first_launch),
        );
        let (mut scanner, _) = scanner_with_limits(&fixture, &body, default_limits());
        let mut broker = fixture.broker();

        let first_source = fixture.source("fresh-launch.json", b"{}");
        let first = fixture
            .prepare(
                &mut broker,
                &mut scanner,
                "grant-fresh-launch",
                &first_source,
            )
            .expect("fresh launch response");
        assert_eq!(first.scan_report.decision, FileScanDecision::Clean);
        let accepted_launch_digest = scanner.last_launch_digest.clone();
        assert_eq!(scanner.process_generation, 2);

        let second_source = fixture.source("stale-launch.json", b"{}");
        assert!(matches!(
            fixture.prepare(
                &mut broker,
                &mut scanner,
                "grant-stale-launch",
                &second_source
            ),
            Err(BrowserError::FileScanUnavailable)
        ));
        assert_ne!(scanner.last_launch_digest, accepted_launch_digest);
        assert_eq!(scanner.process_generation, 3);
        assert!(scanner.process_boundary_poisoned);
        assert_eq!(fs::read_to_string(&count).expect("launch count"), "2\n");

        let third_source = fixture.source("poisoned-launch.json", b"{}");
        assert!(matches!(
            fixture.prepare(
                &mut broker,
                &mut scanner,
                "grant-poisoned-launch",
                &third_source
            ),
            Err(BrowserError::FileScanUnavailable)
        ));
        assert_eq!(
            fs::read_to_string(&count).expect("stable launch count"),
            "2\n"
        );
        assert_eq!(scanner.process_generation, 3);
        assert_no_run_directory_residue(&scanner);
    }

    #[test]
    fn overflowed_partial_output_is_drained_before_a_revalidated_restart() {
        let fixture = ScannerFixture::new();
        let first_marker = fixture.temp.path().join("overflow-first.marker");
        let body = format!(
            r#"    if [ ! -f {marker} ]; then
      printf first > {marker}
      count=0
      while [ "$count" -lt 4096 ]; do
        printf x
        count=$((count + 1))
      done
    else
      emit_scan clean
    fi"#,
            marker = shell_quote(&first_marker),
        );
        let limits = ScannerProcessLimits::new(Duration::from_secs(2), 512, 512)
            .expect("small bounded outputs");
        let (mut scanner, _) = scanner_with_limits(&fixture, &body, limits);
        let mut broker = fixture.broker();
        let first_source = fixture.source("overflow-restart-first.json", b"{}");
        assert!(matches!(
            fixture.prepare(
                &mut broker,
                &mut scanner,
                "grant-overflow-restart-first",
                &first_source
            ),
            Err(BrowserError::FileScanUnavailable)
        ));
        assert_eq!(scanner.process_generation, 2);
        assert!(!scanner.process_boundary_poisoned);
        assert_no_run_directory_residue(&scanner);

        let second_source = fixture.source("overflow-restart-second.json", b"{}");
        let second = fixture
            .prepare(
                &mut broker,
                &mut scanner,
                "grant-overflow-restart-second",
                &second_source,
            )
            .expect("restart after drained overflow");
        assert_eq!(second.scan_report.decision, FileScanDecision::Clean);
        assert_eq!(scanner.process_generation, 3);
        assert_no_run_directory_residue(&scanner);
    }

    #[test]
    fn a_clean_leader_with_a_live_descendant_is_rejected_and_contained() {
        let fixture = ScannerFixture::new();
        let source = fixture.source("descendant.json", b"{}");
        let body = r"    /bin/sleep 30 &
    emit_scan clean
    exit 0";
        let limits = ScannerProcessLimits::new(Duration::from_secs(5), 4096, 4096)
            .expect("descendant limits");
        let (mut scanner, _) = scanner_with_limits(&fixture, body, limits);
        let mut broker = fixture.broker();
        let started = Instant::now();
        let result = fixture.prepare(&mut broker, &mut scanner, "grant-live-descendant", &source);
        assert!(matches!(result, Err(BrowserError::FileScanUnavailable)));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn staged_replacement_symlink_identity_or_content_drift_after_dispatch_is_file_changed() {
        #[derive(Clone, Copy)]
        enum Tamper {
            ReplaceInode,
            ReplaceWithSymlink,
            RewriteContent,
        }

        for tamper_kind in [
            Tamper::ReplaceInode,
            Tamper::ReplaceWithSymlink,
            Tamper::RewriteContent,
        ] {
            let fixture = ScannerFixture::new();
            let marker = fixture.temp.path().join("scanner-dispatched.marker");
            let body = format!(
                r"    printf dispatched > {marker}
    /bin/sleep 1
    emit_scan clean",
                marker = shell_quote(&marker),
            );
            let (mut scanner, _) = scanner_with_limits(&fixture, &body, default_limits());
            let durable_root = fixture.temp.path().join("durable-broker");
            fs::create_dir(&durable_root).expect("durable root");
            fs::set_permissions(&durable_root, fs::Permissions::from_mode(0o700))
                .expect("private durable root");
            let (mut broker, reconciliation) = FileBroker::open_durable(
                &durable_root,
                &fixture.project.tenant_id,
                &fixture.project.id,
                [],
            )
            .expect("durable broker");
            assert!(reconciliation.is_healthy());
            let private_content = br#"{"same":"digest"}"#;
            let source = fixture.source("staged-tamper.json", private_content);
            let symlink_target = fixture.temp.path().join("private-symlink-target.json");
            fs::write(&symlink_target, private_content).expect("symlink target content");
            fs::set_permissions(&symlink_target, fs::Permissions::from_mode(0o400))
                .expect("read-only symlink target");
            let tamper_root = durable_root.clone();
            let tamper_marker = marker.clone();
            let tamper_content = private_content.to_vec();
            let tamper_symlink_target = symlink_target.clone();
            let tamper = thread::spawn(move || {
                wait_for_path(&tamper_marker);
                let blob = wait_for_managed_blob(&tamper_root);
                match tamper_kind {
                    Tamper::ReplaceInode => {
                        fs::remove_file(&blob).expect("remove original staged inode");
                        fs::write(&blob, tamper_content)
                            .expect("replace staged inode with same bytes");
                        fs::set_permissions(&blob, fs::Permissions::from_mode(0o400))
                            .expect("restore replacement read-only mode");
                    }
                    Tamper::ReplaceWithSymlink => {
                        fs::remove_file(&blob).expect("remove original staged inode");
                        std::os::unix::fs::symlink(&tamper_symlink_target, &blob)
                            .expect("replace staged inode with symlink");
                    }
                    Tamper::RewriteContent => {
                        fs::set_permissions(&blob, fs::Permissions::from_mode(0o600))
                            .expect("make staged inode writable for fixture");
                        fs::write(&blob, br#"{"changed":"digest"}"#)
                            .expect("change staged digest in place");
                        fs::set_permissions(&blob, fs::Permissions::from_mode(0o400))
                            .expect("restore rewritten read-only mode");
                    }
                }
            });
            let grant_id = match tamper_kind {
                Tamper::ReplaceInode => "grant-staged-inode-replacement",
                Tamper::ReplaceWithSymlink => "grant-staged-symlink-replacement",
                Tamper::RewriteContent => "grant-staged-digest-rewrite",
            };
            let result = fixture.prepare(&mut broker, &mut scanner, grant_id, &source);
            tamper.join().expect("tamper thread");
            assert!(matches!(result, Err(BrowserError::FileChanged)));
            assert!(broker.grant(&BrowserFileGrantId::from(grant_id)).is_none());
            let debug = format!("{result:?} {scanner:?} {broker:?}");
            assert!(!debug.contains(r#"{"same":"digest"}"#));
            assert!(!debug.contains(symlink_target.to_string_lossy().as_ref()));
            assert_no_run_directory_residue(&scanner);
        }
    }

    #[test]
    fn executable_mutation_during_scan_invalidates_an_apparent_clean_response() {
        let fixture = ScannerFixture::new();
        let source = fixture.source("self-mutating-scanner.json", b"{}");
        let body = r#"    /bin/chmod 700 "$0"
    printf '%s\n' '#!/bin/sh' > "$0"
    emit_scan clean"#;
        let (mut scanner, _) = scanner_with_limits(&fixture, body, default_limits());
        let mut broker = fixture.broker();
        assert!(matches!(
            fixture.prepare(
                &mut broker,
                &mut scanner,
                "grant-self-mutating-scanner",
                &source
            ),
            Err(BrowserError::FileScanUnavailable)
        ));
    }

    fn assert_no_run_directory_residue(scanner: &ProductionFileScanner) {
        for entry in
            fs::read_dir(&scanner.canonical_runtime_directory).expect("scanner runtime directory")
        {
            let entry = entry.expect("scanner runtime entry");
            assert!(
                !entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("run-")),
                "scanner run directory residue remained"
            );
        }
    }

    fn wait_for_path(path: &Path) {
        for _ in 0..1000 {
            if path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("path did not appear: {}", path.display());
    }

    fn wait_for_managed_blob(root: &Path) -> PathBuf {
        for _ in 0..1000 {
            if let Some(blob) = find_managed_blob(root) {
                return blob;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("managed staged blob did not appear");
    }

    fn find_managed_blob(root: &Path) -> Option<PathBuf> {
        for entry in fs::read_dir(root).ok()? {
            let entry = entry.ok()?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).ok()?;
            if metadata.is_dir() {
                if let Some(blob) = find_managed_blob(&path) {
                    return Some(blob);
                }
            } else if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("blob-"))
            {
                return Some(path);
            }
        }
        None
    }
}
