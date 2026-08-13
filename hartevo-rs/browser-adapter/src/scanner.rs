//! Production-safe Unix process boundary for a separately pinned file scanner.
//!
//! This module authenticates and contains the scanner process. It does not ship
//! a malware engine and does not turn fixture verdicts into production malware
//! evidence.

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
use command_group::{CommandGroup, GroupChild};
use crossbeam_channel::{Sender, TryRecvError, bounded};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempfile::{Builder as TempBuilder, TempDir};
use zeroize::Zeroizing;

use crate::file_broker::{FileSafetyScanner, FileScanDecision, FileScanReport, FileScanRequest};
use crate::workspace::{digest, digest_json, is_bounded_identifier, is_sha256};
use crate::{BrowserError, BrowserFileType};

const SCANNER_PROTOCOL: &str = "hartevo-file-scanner-process/v2";
const VERSION_OPERATION: &str = "version-v2";
const SCAN_OPERATION: &str = "scan-v2";
const SCANNER_INPUT_FD: i32 = 3;
const MAX_PROCESS_TIMEOUT: Duration = Duration::from_mins(5);
const MIN_OUTPUT_BYTES: usize = 64;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(5);
const PROCESS_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const READER_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const EXECUTABLE_COPY_MODE: u32 = 0o500;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

/// Exact scanner release and executable digest accepted by the process boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct ScannerReleasePin {
    scanner_id: String,
    scanner_version: String,
    executable_sha256: String,
    release_digest: String,
}

impl ScannerReleasePin {
    pub fn new(
        scanner_id: impl Into<String>,
        scanner_version: impl Into<String>,
        executable_sha256: impl Into<String>,
    ) -> Result<Self, BrowserError> {
        let scanner_id = scanner_id.into();
        let scanner_version = scanner_version.into();
        let executable_sha256 = executable_sha256.into();
        if !valid_release_identifier(&scanner_id)
            || !valid_release_identifier(&scanner_version)
            || !is_sha256(&executable_sha256)
        {
            return Err(BrowserError::FileScanUnavailable);
        }
        let release_digest = digest_json(&serde_json::json!({
            "protocol": SCANNER_PROTOCOL,
            "scannerId": scanner_id,
            "scannerVersion": scanner_version,
            "executableSha256": executable_sha256,
        }))?;
        Ok(Self {
            scanner_id,
            scanner_version,
            executable_sha256,
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

    pub fn release_digest(&self) -> &str {
        &self.release_digest
    }

    fn validate(&self) -> Result<(), BrowserError> {
        if Self::new(
            self.scanner_id.clone(),
            self.scanner_version.clone(),
            self.executable_sha256.clone(),
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
            "executableIdentityDigest": scanner.executable_identity.evidence_digest()?,
            "launchIdentityDigest": probe.identity.launch.evidence_digest()?,
            "processObservationDigest": probe.evidence_digest()?,
            "response": {
                "schemaVersion": version.schema_version,
                "scannerId": version.scanner_id,
                "scannerVersion": version.scanner_version,
                "executableSha256": version.executable_sha256,
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

        let operation_name = operation.name();
        let mut command = Command::new(&self.executable_path);

        let launch = self.begin_process_launch(operation_name)?;
        configure_clean_process(
            &mut command,
            run_directory.path(),
            &home_directory,
            &temp_directory,
            &self.release_pin,
            &launch,
        );

        if let ProcessOperation::Scan { request, input } = operation {
            command
                .env("HARTEVO_SCANNER_INPUT_FD", SCANNER_INPUT_FD.to_string())
                .env("HARTEVO_SCANNER_CONTENT_SHA256", request.content_digest)
                .env("HARTEVO_SCANNER_BYTE_COUNT", request.byte_count.to_string())
                .env(
                    "HARTEVO_SCANNER_DETECTED_TYPE",
                    file_type_protocol_name(request.detected_type),
                )
                .env(
                    "HARTEVO_SCANNER_OBSERVED_AT",
                    request.observed_at.to_rfc3339(),
                );
            if command
                .fd_mappings(vec![FdMapping {
                    parent_fd: OwnedFd::from(input),
                    child_fd: SCANNER_INPUT_FD,
                }])
                .is_err()
            {
                let run_directory_removed = run_directory.close().is_ok();
                let launch_finished = self.finish_process_launch(&launch).is_ok();
                if !run_directory_removed || !launch_finished {
                    self.poison_process_boundary();
                }
                return Err(BrowserError::FileScanUnavailable);
            }
        }

        let execution = execute_bounded_process(&mut command, self.limits, &launch);
        let run_directory_removed = run_directory.close().is_ok();
        let executable_after = self.verify_runtime_boundary();
        if execution.is_err()
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
        match execution {
            ProcessExecution::Completed(observation) => {
                if !observation.identity.matches_launch(&launch) {
                    self.poison_process_boundary();
                    return Err(BrowserError::FileScanUnavailable);
                }
                self.finish_process_launch(&launch)?;
                Ok(*observation)
            }
            ProcessExecution::ContainedFailure => {
                self.finish_process_launch(&launch)?;
                Err(BrowserError::FileScanUnavailable)
            }
        }
    }

    fn begin_process_launch(
        &mut self,
        operation: &'static str,
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
            &self.executable_identity.evidence_digest()?,
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
        if response.schema_version != 2
            || response.scanner_id != self.release_pin.scanner_id
            || response.scanner_version != self.release_pin.scanner_version
            || response.executable_sha256 != self.release_pin.executable_sha256
            || response.launch_digest != launch.launch_digest
        {
            self.poison_process_boundary();
            return Err(BrowserError::FileScanUnavailable);
        }
        Ok(())
    }

    fn poison_process_boundary(&mut self) {
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
            .field("process_boundary_poisoned", &self.process_boundary_poisoned)
            .field(
                "process_launch_active",
                &self.active_launch_digest.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl FileSafetyScanner for ProductionFileScanner {
    fn scan(&mut self, request: &FileScanRequest<'_>) -> Result<FileScanReport, BrowserError> {
        if self.process_boundary_poisoned || self.active_launch_digest.is_some() {
            return Err(BrowserError::FileScanUnavailable);
        }
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
        let evidence_digest = digest_json(&serde_json::json!({
            "protocol": SCANNER_PROTOCOL,
            "operation": SCAN_OPERATION,
            "releaseDigest": self.release_pin.release_digest,
            "versionProbeEvidenceDigest": self.version_probe_evidence_digest,
            "executableIdentityDigest": executable_identity_digest,
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
            "scannerResultEnvelopeDigest": result_envelope.evidence_digest()?,
        }))?;
        Ok(FileScanReport {
            scanner_id: self.release_pin.scanner_id.clone(),
            scanner_version: self.release_pin.scanner_version.clone(),
            decision,
            evidence_digest,
            scanned_at: request.observed_at,
        })
    }
}

enum ProcessOperation<'request, 'staged> {
    Version,
    Scan {
        request: &'request FileScanRequest<'staged>,
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
struct ScannerProcessLaunch {
    generation: u64,
    operation: &'static str,
    release_digest: String,
    executable_identity_digest: String,
    previous_launch_digest: String,
    launch_digest: String,
}

impl ScannerProcessLaunch {
    fn new(
        generation: u64,
        operation: &'static str,
        release_digest: &str,
        executable_identity_digest: &str,
        previous_launch_digest: &str,
    ) -> Result<Self, BrowserError> {
        let launch_digest = digest_json(&serde_json::json!({
            "protocol": SCANNER_PROTOCOL,
            "generation": generation.to_string(),
            "operation": operation,
            "releaseDigest": release_digest,
            "executableIdentityDigest": executable_identity_digest,
            "previousLaunchDigest": previous_launch_digest,
        }))?;
        Ok(Self {
            generation,
            operation,
            release_digest: release_digest.to_owned(),
            executable_identity_digest: executable_identity_digest.to_owned(),
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
            "executableIdentityDigest": self.executable_identity_digest,
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
    launch_digest: String,
}

#[derive(Clone, Copy)]
struct ScannerResponseIdentity<'response> {
    schema_version: u32,
    scanner_id: &'response str,
    scanner_version: &'response str,
    executable_sha256: &'response str,
    launch_digest: &'response str,
}

impl VersionResponse {
    fn identity(&self) -> ScannerResponseIdentity<'_> {
        ScannerResponseIdentity {
            schema_version: self.schema_version,
            scanner_id: &self.scanner_id,
            scanner_version: &self.scanner_version,
            executable_sha256: &self.executable_sha256,
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
            "HARTEVO_SCANNER_PROCESS_GENERATION",
            launch.generation.to_string(),
        )
        .env("HARTEVO_SCANNER_LAUNCH_DIGEST", &launch.launch_digest)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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
    executable_identity_digest: String,
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
            || process.identity.launch.executable_identity_digest != executable_identity_digest
        {
            return Err(BrowserError::FileScanUnavailable);
        }

        let response: ScanResponse = parse_exact_json(&process.stdout.retained)?;
        let identity = response.identity();
        if identity.schema_version != 2
            || identity.scanner_id != release_pin.scanner_id
            || identity.scanner_version != release_pin.scanner_version
            || identity.executable_sha256 != release_pin.executable_sha256
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
            "launchDigest": response.launch_digest,
            "decision": decision,
        }))?;
        Ok(Self {
            release_digest: release_pin.release_digest.clone(),
            version_probe_evidence_digest: version_probe_evidence_digest.to_owned(),
            scanner_id: release_pin.scanner_id.clone(),
            scanner_version: release_pin.scanner_version.clone(),
            executable_sha256: release_pin.executable_sha256.clone(),
            executable_identity_digest: executable_identity_digest.to_owned(),
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
            "executableIdentityDigest": self.executable_identity_digest,
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
            .field(
                "executable_identity_digest",
                &self.executable_identity_digest,
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
        // Keep the leader status in GroupChild's lifecycle cache while it
        // observes the Unix process group. Mixing a direct std::process::Child
        // reap with GroupChild::kill/try_wait leaves teardown racing its own
        // cached state on macOS.
        match child.try_wait() {
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
    let mut status = leader_status;
    let mut had_live_group_after_leader = false;

    if leader_status.is_some() {
        // The exact leader was already reaped and cached by GroupChild. A
        // successful group kill therefore proves that another group member
        // remained, and contains it without a PID-reuse or escape delay.
        had_live_group_after_leader = kill_process_group(child)?;
    }
    let mut group_absent = if leader_status.is_some() {
        !had_live_group_after_leader
    } else {
        !kill_process_group(child)?
    };

    loop {
        // Preserve the leader's exact status independently of group teardown;
        // GroupChild::try_wait returns its cached status after the first reap.
        match child.try_wait() {
            Ok(Some(observed)) => {
                status.get_or_insert(observed);
            }
            Ok(None) => {}
            Err(_) => return Err(BrowserError::FileScanUnavailable),
        }
        if status.is_some() && group_absent {
            break;
        }
        if !group_absent {
            group_absent = !kill_process_group(child)?;
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
  printf '{{"schemaVersion":2,"scannerId":"%s","scannerVersion":"%s","executableSha256":"%s","launchDigest":"%s"}}\n' \
    "{FIXTURE_SCANNER_ID}" "{FIXTURE_SCANNER_VERSION}" \
    "$HARTEVO_SCANNER_EXECUTABLE_SHA256" "$HARTEVO_SCANNER_LAUNCH_DIGEST"
}}
emit_scan_with_identity() {{
  printf '{{"schemaVersion":2,"scannerId":"%s","scannerVersion":"%s","executableSha256":"%s","launchDigest":"%s","decision":"%s"}}\n' \
    "$1" "$2" "$3" "$4" "$5"
}}
emit_scan() {{
  emit_scan_with_identity "{FIXTURE_SCANNER_ID}" "{FIXTURE_SCANNER_VERSION}" \
    "$HARTEVO_SCANNER_EXECUTABLE_SHA256" "$HARTEVO_SCANNER_LAUNCH_DIGEST" "$1"
}}
emit_scan_with_launch() {{
  emit_scan_with_identity "{FIXTURE_SCANNER_ID}" "{FIXTURE_SCANNER_VERSION}" \
    "$HARTEVO_SCANNER_EXECUTABLE_SHA256" "$2" "$1"
}}
emit_scan_unknown() {{
  printf '{{"schemaVersion":2,"scannerId":"%s","scannerVersion":"%s","executableSha256":"%s","launchDigest":"%s","decision":"%s","unknown":true}}\n' \
    "{FIXTURE_SCANNER_ID}" "{FIXTURE_SCANNER_VERSION}" \
    "$HARTEVO_SCANNER_EXECUTABLE_SHA256" "$HARTEVO_SCANNER_LAUNCH_DIGEST" "$1"
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
        let release_pin =
            ScannerReleasePin::new(FIXTURE_SCANNER_ID, FIXTURE_SCANNER_VERSION, sha('5'))
                .expect("release pin");
        let launch = ScannerProcessLaunch::new(
            7,
            SCAN_OPERATION,
            release_pin.release_digest(),
            &sha('6'),
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
                "HARTEVO_SCANNER_EXECUTABLE_SHA256",
                "HARTEVO_SCANNER_ID",
                "HARTEVO_SCANNER_LAUNCH_DIGEST",
                "HARTEVO_SCANNER_OPERATION",
                "HARTEVO_SCANNER_PROCESS_GENERATION",
                "HARTEVO_SCANNER_PROTOCOL",
                "HARTEVO_SCANNER_RELEASE_DIGEST",
                "HARTEVO_SCANNER_VERSION",
                "HOME",
                "LANG",
                "LC_ALL",
                "TMPDIR",
            ]
        );
        assert_eq!(
            environment["HARTEVO_SCANNER_OPERATION"].as_deref(),
            Some(SCAN_OPERATION)
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
        let release_pin =
            ScannerReleasePin::new(FIXTURE_SCANNER_ID, FIXTURE_SCANNER_VERSION, sha('5'))
                .expect("release pin");
        let executable_identity_digest = sha('6');
        let launch = ScannerProcessLaunch::new(
            9,
            SCAN_OPERATION,
            release_pin.release_digest(),
            &executable_identity_digest,
            &sha('7'),
        )
        .expect("launch");
        let stdout = format!(
            r#"{{"schemaVersion":2,"scannerId":"{FIXTURE_SCANNER_ID}","scannerVersion":"{FIXTURE_SCANNER_VERSION}","executableSha256":"{}","launchDigest":"{}","decision":"clean"}}
"#,
            release_pin.executable_sha256(),
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
            &sha('8'),
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
    fn partial_truncated_malformed_and_killed_generation_results_fail_closed_without_raw_output() {
        let cases = [
            (
                "truncated",
                r#"    printf '%s' '{"schemaVersion":2,"scannerId":"private-truncated-result'"#,
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
        let wrong_pin =
            ScannerReleasePin::new(FIXTURE_SCANNER_ID, FIXTURE_SCANNER_VERSION, sha('9'))
                .expect("shaped wrong pin");
        assert!(matches!(
            ProductionFileScanner::new(&path, &fixture.scanner_root, wrong_pin, default_limits()),
            Err(BrowserError::InvalidExecutable)
        ));

        let wrong_version =
            ScannerReleasePin::new(FIXTURE_SCANNER_ID, "fixture-v2", executable_digest.clone())
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
        )
        .expect("good pin");
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
    fn every_result_revalidates_scanner_identity_digest_and_version_before_restart() {
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

    fn assert_timeout_restart_cycle(cycle: usize) {
        let fixture = ScannerFixture::new();
        let first_marker = fixture.temp.path().join("timeout-first.marker");
        let body = format!(
            r"    if [ ! -f {marker} ]; then
      printf first > {marker}
      printf partial
      /bin/sleep 30 &
      wait
    fi
    emit_scan clean",
            marker = shell_quote(&first_marker),
        );
        let (mut scanner, _) = scanner_with_limits(&fixture, &body, default_limits());
        let mut broker = fixture.broker();
        let first_source = fixture.source(&format!("timeout-repeat-{cycle}-first.json"), b"{}");
        assert!(matches!(
            fixture.prepare(
                &mut broker,
                &mut scanner,
                &format!("grant-timeout-repeat-{cycle}-first"),
                &first_source,
            ),
            Err(BrowserError::FileScanUnavailable)
        ));
        assert_eq!(scanner.process_generation, 2);
        assert!(
            !scanner.process_boundary_poisoned,
            "timeout cycle {cycle} poisoned"
        );
        assert_no_run_directory_residue(&scanner);

        let second_source = fixture.source(&format!("timeout-repeat-{cycle}-second.json"), b"{}");
        let second = fixture
            .prepare(
                &mut broker,
                &mut scanner,
                &format!("grant-timeout-repeat-{cycle}-second"),
                &second_source,
            )
            .expect("timeout restart");
        assert_eq!(second.scan_report.decision, FileScanDecision::Clean);
        assert!(
            !scanner.process_boundary_poisoned,
            "timeout restart {cycle} poisoned"
        );
        assert_no_run_directory_residue(&scanner);
    }

    fn assert_overflow_restart_cycle(cycle: usize) {
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
        let limits = ScannerProcessLimits::new(Duration::from_secs(2), 512, 512).expect("limits");
        let (mut scanner, _) = scanner_with_limits(&fixture, &body, limits);
        let mut broker = fixture.broker();
        let first_source = fixture.source(&format!("overflow-repeat-{cycle}-first.json"), b"{}");
        assert!(matches!(
            fixture.prepare(
                &mut broker,
                &mut scanner,
                &format!("grant-overflow-repeat-{cycle}-first"),
                &first_source,
            ),
            Err(BrowserError::FileScanUnavailable)
        ));
        assert_eq!(scanner.process_generation, 2);
        assert!(
            !scanner.process_boundary_poisoned,
            "overflow cycle {cycle} poisoned"
        );
        assert_no_run_directory_residue(&scanner);

        let second_source = fixture.source(&format!("overflow-repeat-{cycle}-second.json"), b"{}");
        let second = fixture
            .prepare(
                &mut broker,
                &mut scanner,
                &format!("grant-overflow-repeat-{cycle}-second"),
                &second_source,
            )
            .expect("overflow restart");
        assert_eq!(second.scan_report.decision, FileScanDecision::Clean);
        assert!(
            !scanner.process_boundary_poisoned,
            "overflow restart {cycle} poisoned"
        );
        assert_no_run_directory_residue(&scanner);
    }

    #[test]
    fn repeated_timeout_and_overflow_restarts_keep_boundary_unpoisoned() {
        for cycle in 0..6 {
            assert_timeout_restart_cycle(cycle);
            assert_overflow_restart_cycle(cycle);
        }
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
