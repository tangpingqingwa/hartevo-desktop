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

const SCANNER_PROTOCOL: &str = "hartevo-file-scanner-process/v1";
const VERSION_OPERATION: &str = "version-v1";
const SCAN_OPERATION: &str = "scan-v1";
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

        let mut scanner = Self {
            runtime_directory,
            canonical_runtime_directory,
            executable_path: materialized_path,
            executable_identity,
            release_pin,
            limits,
            version_probe_evidence_digest: digest(b"pending-scanner-version-probe"),
        };
        let probe = scanner.run_process(ProcessOperation::Version)?;
        if !probe.status.success() {
            return Err(BrowserError::FileScanUnavailable);
        }
        let version: VersionResponse = parse_exact_json(&probe.stdout.retained)?;
        if version.schema_version != 1
            || version.scanner_id != scanner.release_pin.scanner_id
            || version.scanner_version != scanner.release_pin.scanner_version
        {
            return Err(BrowserError::FileScanUnavailable);
        }
        scanner.version_probe_evidence_digest = digest_json(&serde_json::json!({
            "protocol": SCANNER_PROTOCOL,
            "operation": VERSION_OPERATION,
            "releaseDigest": scanner.release_pin.release_digest,
            "executableIdentityDigest": scanner.executable_identity.evidence_digest()?,
            "processObservationDigest": probe.evidence_digest()?,
            "response": {
                "schemaVersion": version.schema_version,
                "scannerId": version.scanner_id,
                "scannerVersion": version.scanner_version,
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
        &self,
        operation: ProcessOperation<'_, '_>,
    ) -> Result<ProcessObservation, BrowserError> {
        let executable_before = self.verify_runtime_boundary()?;
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

        let mut command = Command::new(&self.executable_path);
        configure_clean_process(
            &mut command,
            run_directory.path(),
            &home_directory,
            &temp_directory,
            operation.name(),
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
            command
                .fd_mappings(vec![FdMapping {
                    parent_fd: OwnedFd::from(input),
                    child_fd: SCANNER_INPUT_FD,
                }])
                .map_err(|_| BrowserError::FileScanUnavailable)?;
        }

        let observation = execute_bounded_process(&mut command, self.limits);
        drop(run_directory);
        let executable_after = self.verify_runtime_boundary()?;
        if executable_after != executable_before {
            return Err(BrowserError::FileScanUnavailable);
        }
        observation
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
            .finish_non_exhaustive()
    }
}

impl FileSafetyScanner for ProductionFileScanner {
    fn scan(&mut self, request: &FileScanRequest<'_>) -> Result<FileScanReport, BrowserError> {
        self.release_pin.validate()?;
        self.limits.validate()?;
        if !is_sha256(request.content_digest) || request.byte_count == 0 {
            return Err(BrowserError::FileChanged);
        }
        let (mut staged_file, staged_before) = inspect_staged_path(request.staged_path())?;
        if staged_before.content_digest != request.content_digest
            || staged_before.byte_count != request.byte_count
        {
            return Err(BrowserError::FileChanged);
        }
        staged_file.seek(SeekFrom::Start(0))?;

        let process_result = self.run_process(ProcessOperation::Scan {
            request,
            input: staged_file,
        });
        let staged_after = inspect_staged_path(request.staged_path())?.1;
        if staged_after != staged_before {
            return Err(BrowserError::FileChanged);
        }
        let process = process_result?;
        if !process.status.success() {
            return Err(BrowserError::FileScanUnavailable);
        }
        let response: ScanResponse = parse_exact_json(&process.stdout.retained)?;
        if response.schema_version != 1 {
            return Err(BrowserError::FileScanUnavailable);
        }
        let decision = match response.decision {
            ScannerDecision::Clean => FileScanDecision::Clean,
            ScannerDecision::Rejected => FileScanDecision::Rejected,
        };
        let evidence_digest = digest_json(&serde_json::json!({
            "protocol": SCANNER_PROTOCOL,
            "operation": SCAN_OPERATION,
            "releaseDigest": self.release_pin.release_digest,
            "versionProbeEvidenceDigest": self.version_probe_evidence_digest,
            "executableIdentityDigest": self.executable_identity.evidence_digest()?,
            "request": {
                "contentDigest": request.content_digest,
                "byteCount": request.byte_count,
                "detectedType": request.detected_type,
                "observedAt": request.observed_at,
            },
            "stagedIdentityBeforeDigest": staged_before.evidence_digest()?,
            "stagedIdentityAfterDigest": staged_after.evidence_digest()?,
            "decision": decision,
            "processObservationDigest": process.evidence_digest()?,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VersionResponse {
    schema_version: u32,
    scanner_id: String,
    scanner_version: String,
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
    decision: ScannerDecision,
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

fn inspect_staged_path(path: &Path) -> Result<(File, ExactFileIdentity), BrowserError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BrowserError::FileChanged)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BrowserError::FileChanged);
    }
    let mut file = open_read_only_no_follow(path).map_err(|_| BrowserError::FileChanged)?;
    let identity = inspect_open_file(&mut file, FileRole::StagedInput)?;
    Ok((file, identity))
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
    operation: &str,
) {
    command
        .current_dir(working_directory)
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("HOME", home_directory)
        .env("TMPDIR", temp_directory)
        .env("HARTEVO_SCANNER_PROTOCOL", SCANNER_PROTOCOL)
        .env("HARTEVO_SCANNER_OPERATION", operation)
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

struct ProcessObservation {
    status: ExitObservation,
    stdout: BoundedOutput,
    stderr: BoundedOutput,
}

impl ProcessObservation {
    fn evidence_digest(&self) -> Result<String, BrowserError> {
        digest_json(&serde_json::json!({
            "exit": {
                "code": self.status.code,
                "signal": self.status.signal,
                "success": self.status.success,
            },
            "stdoutDigest": self.stdout.evidence_digest()?,
            "stderrDigest": self.stderr.evidence_digest()?,
        }))
    }
}

impl fmt::Debug for ProcessObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessObservation")
            .field("status", &self.status)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .finish()
    }
}

enum ProcessStop {
    Exited(ExitStatus),
    Timeout,
    OutputViolation,
    WaitFailure,
}

fn execute_bounded_process(
    command: &mut Command,
    limits: ScannerProcessLimits,
) -> Result<ProcessObservation, BrowserError> {
    let mut child = command
        .group_spawn()
        .map_err(|_| BrowserError::FileScanUnavailable)?;
    let stdout = child
        .inner()
        .stdout
        .take()
        .ok_or(BrowserError::FileScanUnavailable);
    let stderr = child
        .inner()
        .stderr
        .take()
        .ok_or(BrowserError::FileScanUnavailable);
    let (Ok(stdout), Ok(stderr)) = (stdout, stderr) else {
        terminate_process_group(&mut child, None)?;
        return Err(BrowserError::FileScanUnavailable);
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
            terminate_process_group(&mut child, None)?;
            if let Ok(reader) = stdout_reader {
                let _ = join_output_reader(reader);
            }
            if let Ok(reader) = stderr_reader {
                let _ = join_output_reader(reader);
            }
            return Err(BrowserError::FileScanUnavailable);
        }
    };

    let deadline = Instant::now()
        .checked_add(limits.timeout)
        .ok_or(BrowserError::FileScanUnavailable)?;
    let stop = loop {
        match event_receiver.try_recv() {
            Ok(ReaderEvent::Overflow(stream) | ReaderEvent::Failed(stream)) => {
                let _ = stream;
                break ProcessStop::OutputViolation;
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
        }
        // GroupChild::try_wait observes the Unix process group. Poll the exact
        // leader here, then audit and clear the group separately below.
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
    let cleanup = terminate_process_group(&mut child, exited_status)?;
    let stdout = join_output_reader(stdout_reader)?;
    let stderr = join_output_reader(stderr_reader)?;

    match stop {
        ProcessStop::Exited(_)
            if !cleanup.had_live_group_after_leader && !stdout.overflowed && !stderr.overflowed => {
        }
        ProcessStop::Exited(_)
        | ProcessStop::Timeout
        | ProcessStop::OutputViolation
        | ProcessStop::WaitFailure => return Err(BrowserError::FileScanUnavailable),
    }
    Ok(ProcessObservation {
        status: ExitObservation::from_status(cleanup.status),
        stdout,
        stderr,
    })
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
        // The exact leader was already reaped through std::process::Child.
        // A successful group kill therefore proves that another group member
        // remained, and contains it without a PID-reuse or escape delay.
        had_live_group_after_leader = kill_process_group(child)?;
    }
    let mut group_absent = if leader_status.is_some() {
        !had_live_group_after_leader
    } else {
        !kill_process_group(child)?
    };

    loop {
        // Preserve the leader's exact status independently of group teardown.
        match child.inner().try_wait() {
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
    let mut buffer = vec![0_u8; 8 * 1024].into_boxed_slice();
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

fn join_output_reader(
    reader: JoinHandle<std::io::Result<BoundedOutput>>,
) -> Result<BoundedOutput, BrowserError> {
    let deadline = Instant::now()
        .checked_add(READER_CLEANUP_TIMEOUT)
        .ok_or(BrowserError::FileScanUnavailable)?;
    while !reader.is_finished() {
        if Instant::now() >= deadline {
            return Err(BrowserError::FileScanUnavailable);
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
    reader
        .join()
        .map_err(|_| BrowserError::FileScanUnavailable)?
        .map_err(|_| BrowserError::FileScanUnavailable)
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
case "${{HARTEVO_SCANNER_OPERATION-}}" in
  {VERSION_OPERATION})
    printf '%s\n' '{{"schemaVersion":1,"scannerId":"{FIXTURE_SCANNER_ID}","scannerVersion":"{FIXTURE_SCANNER_VERSION}"}}'
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
        configure_clean_process(&mut command, &working, &home, &temporary, SCAN_OPERATION);
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
                "HARTEVO_SCANNER_OPERATION",
                "HARTEVO_SCANNER_PROTOCOL",
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
    printf '%s\n' '{"schemaVersion":1,"decision":"clean"}'"#;
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
    fn typed_rejected_verdict_creates_no_grant_or_staged_residue() {
        let fixture = ScannerFixture::new();
        let source = fixture.source("rejected.json", br#"{"status":"blocked"}"#);
        let (mut scanner, _) = scanner_with_limits(
            &fixture,
            r#"    printf '%s\n' '{"schemaVersion":1,"decision":"rejected"}'"#,
            default_limits(),
        );
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
        let body = r#"    printf '%s\n' '{"schemaVersion":1,"decision":"clean"}'"#;
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
            r#"    printf '%s\n' '{"schemaVersion":1,"decision":"clean","unknown":true}'"#,
            r"    printf '%s\n' '{'",
            r#"    printf '%s\n' '{"schemaVersion":1,"decision":"unavailable"}'"#,
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
    printf '%s\n' '{"schemaVersion":1,"decision":"clean"}'"#,
        ];
        for (index, body) in cases.into_iter().enumerate() {
            let fixture = ScannerFixture::new();
            let source = fixture.source(&format!("overflow-{index}.json"), b"{}");
            let limits = ScannerProcessLimits::new(Duration::from_secs(1), 256, 256)
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
            r#"    if [ ! -f {marker} ]; then
      printf first > {marker}
      /bin/sleep 30 &
      wait
    fi
    printf '%s\n' '{{"schemaVersion":1,"decision":"clean"}}'"#,
            marker = shell_quote(&first_marker),
        );
        let limits = ScannerProcessLimits::new(Duration::from_millis(500), 4096, 4096)
            .expect("timeout limits");
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
        assert!(started.elapsed() < Duration::from_secs(4));

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
    }

    #[test]
    fn a_clean_leader_with_a_live_descendant_is_rejected_and_contained() {
        let fixture = ScannerFixture::new();
        let source = fixture.source("descendant.json", b"{}");
        let body = r#"    /bin/sleep 30 &
    printf '%s\n' '{"schemaVersion":1,"decision":"clean"}'
    exit 0"#;
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
    fn staged_inode_or_digest_change_after_dispatch_is_file_changed() {
        for replace_inode_with_same_digest in [true, false] {
            let fixture = ScannerFixture::new();
            let marker = fixture.temp.path().join("scanner-dispatched.marker");
            let body = format!(
                r#"    printf dispatched > {marker}
    /bin/sleep 1
    printf '%s\n' '{{"schemaVersion":1,"decision":"clean"}}'"#,
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
            let tamper_root = durable_root.clone();
            let tamper_marker = marker.clone();
            let tamper_content = private_content.to_vec();
            let tamper = thread::spawn(move || {
                wait_for_path(&tamper_marker);
                let blob = wait_for_managed_blob(&tamper_root);
                if replace_inode_with_same_digest {
                    fs::remove_file(&blob).expect("remove original staged inode");
                    fs::write(&blob, tamper_content).expect("replace staged inode with same bytes");
                } else {
                    fs::set_permissions(&blob, fs::Permissions::from_mode(0o600))
                        .expect("make staged inode writable for fixture");
                    fs::write(&blob, br#"{"changed":"digest"}"#)
                        .expect("change staged digest in place");
                }
                fs::set_permissions(&blob, fs::Permissions::from_mode(0o400))
                    .expect("restore read-only staged mode");
            });
            let result = fixture.prepare(
                &mut broker,
                &mut scanner,
                if replace_inode_with_same_digest {
                    "grant-staged-inode-replacement"
                } else {
                    "grant-staged-digest-rewrite"
                },
                &source,
            );
            tamper.join().expect("tamper thread");
            assert!(matches!(result, Err(BrowserError::FileChanged)));
        }
    }

    #[test]
    fn executable_mutation_during_scan_invalidates_an_apparent_clean_response() {
        let fixture = ScannerFixture::new();
        let source = fixture.source("self-mutating-scanner.json", b"{}");
        let body = r#"    /bin/chmod 700 "$0"
    printf '%s\n' '#!/bin/sh' > "$0"
    printf '%s\n' '{"schemaVersion":1,"decision":"clean"}'"#;
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
