use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use hartevo_domain_kernel::BrowserProfileId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::workspace::{digest, digest_json};
use crate::{BrowserError, BrowserProfile, BrowserProfileSource, BrowserProfileStatus};

const PROFILE_BINDING_SCHEMA_VERSION: u32 = 1;
const PROFILE_OWNERSHIP_LOCK_SCHEMA_VERSION: u32 = 1;
const PROFILE_OWNERSHIP_LOCK_FILE: &str = "host.lock";
const PROFILE_OWNERSHIP_TOKEN_BYTES: u64 = 64;
const MAX_MARKER_BYTES: u64 = 64 * 1_024;

#[derive(Clone, Eq, PartialEq)]
pub struct BrowserExecutableIdentity {
    canonical_path: PathBuf,
    pub content_digest: String,
    pub byte_count: u64,
    pub modified_millis: u128,
    pub evidence_digest: String,
}

impl BrowserExecutableIdentity {
    pub fn inspect(path: &Path) -> Result<Self, BrowserError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| BrowserError::InvalidExecutable)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(BrowserError::InvalidExecutable);
        }
        validate_executable_permissions(&metadata)?;
        let canonical_path = fs::canonicalize(path).map_err(|_| BrowserError::InvalidExecutable)?;
        let canonical_metadata =
            fs::metadata(&canonical_path).map_err(|_| BrowserError::InvalidExecutable)?;
        if !canonical_metadata.is_file() {
            return Err(BrowserError::InvalidExecutable);
        }
        validate_executable_permissions(&canonical_metadata)?;

        let mut reader = BufReader::new(
            File::open(&canonical_path).map_err(|_| BrowserError::InvalidExecutable)?,
        );
        let mut hasher = Sha256::new();
        let mut byte_count = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            byte_count = byte_count
                .checked_add(u64::try_from(read).map_err(|_| BrowserError::CounterOverflow)?)
                .ok_or(BrowserError::CounterOverflow)?;
            hasher.update(&buffer[..read]);
        }
        if byte_count == 0 || byte_count != canonical_metadata.len() {
            return Err(BrowserError::InvalidExecutable);
        }
        let modified_millis = canonical_metadata
            .modified()
            .map_err(|_| BrowserError::InvalidExecutable)?
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BrowserError::InvalidExecutable)?
            .as_millis();
        let content_digest = hex::encode(hasher.finalize());
        let evidence_digest = digest_json(&serde_json::json!({
            "pathDigest": digest(canonical_path.as_os_str().as_encoded_bytes()),
            "contentDigest": content_digest,
            "byteCount": byte_count,
            "modifiedMillis": modified_millis.to_string(),
        }))?;
        Ok(Self {
            canonical_path,
            content_digest,
            byte_count,
            modified_millis,
            evidence_digest,
        })
    }

    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }
}

impl fmt::Debug for BrowserExecutableIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserExecutableIdentity")
            .field(
                "canonical_path_digest",
                &digest(self.canonical_path.as_os_str().as_encoded_bytes()),
            )
            .field("content_digest", &self.content_digest)
            .field("byte_count", &self.byte_count)
            .field("modified_millis", &self.modified_millis)
            .field("evidence_digest", &self.evidence_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileBindingMarker {
    schema_version: u32,
    profile_id: BrowserProfileId,
    profile_scope_digest: String,
    credential_reference_digest: String,
    identity_digest: String,
    executable_evidence_digest: String,
}

pub struct ManagedProfileDirectory {
    binding_directory: PathBuf,
    chrome_data_directory: PathBuf,
    private_home_directory: PathBuf,
    private_temp_directory: PathBuf,
    binding_digest: String,
    // The open file owns the kernel lock. Dropping it releases ownership even
    // when the process exits without running a custom cleanup path.
    _ownership_lock: File,
}

impl ManagedProfileDirectory {
    pub fn prepare(
        private_root: &Path,
        profile: &BrowserProfile,
        executable: &BrowserExecutableIdentity,
    ) -> Result<Self, BrowserError> {
        profile.validate()?;
        if BrowserExecutableIdentity::inspect(executable.canonical_path())? != *executable {
            return Err(BrowserError::InvalidExecutable);
        }
        if profile.source != BrowserProfileSource::Managed
            || profile.status != BrowserProfileStatus::Active
        {
            return Err(BrowserError::InvalidProfile);
        }
        let root_metadata = fs::symlink_metadata(private_root)
            .map_err(|_| BrowserError::InvalidProfileDirectory)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(BrowserError::InvalidProfileDirectory);
        }
        validate_private_directory_permissions(&root_metadata)?;
        let canonical_root =
            fs::canonicalize(private_root).map_err(|_| BrowserError::InvalidProfileDirectory)?;

        let profile_scope_digest = profile_scope_digest(profile)?;
        let directory_name = format!("profile-{}", &profile_scope_digest[..32]);
        let binding_directory = canonical_root.join(directory_name);
        create_or_validate_private_directory(&binding_directory, &canonical_root)?;

        let marker = ProfileBindingMarker {
            schema_version: PROFILE_BINDING_SCHEMA_VERSION,
            profile_id: profile.id.clone(),
            profile_scope_digest,
            credential_reference_digest: digest(profile.credential_reference.as_bytes()),
            identity_digest: profile.identity.identity_digest.clone(),
            executable_evidence_digest: executable.evidence_digest.clone(),
        };
        let binding_digest = digest_json(&marker)?;
        ensure_exact_marker(&binding_directory.join("binding-v1.json"), &marker)?;

        let chrome_data_directory = binding_directory.join("chrome-data");
        let private_home_directory = binding_directory.join("home");
        let private_temp_directory = binding_directory.join("tmp");
        for directory in [
            &chrome_data_directory,
            &private_home_directory,
            &private_temp_directory,
        ] {
            create_or_validate_private_directory(directory, &binding_directory)?;
        }

        let ownership_lock = acquire_profile_ownership_lock(
            &binding_directory.join(PROFILE_OWNERSHIP_LOCK_FILE),
            &binding_digest,
        )?;

        Ok(Self {
            binding_directory,
            chrome_data_directory,
            private_home_directory,
            private_temp_directory,
            binding_digest,
            _ownership_lock: ownership_lock,
        })
    }

    pub fn chrome_data_directory(&self) -> &Path {
        &self.chrome_data_directory
    }

    pub fn private_home_directory(&self) -> &Path {
        &self.private_home_directory
    }

    pub fn private_temp_directory(&self) -> &Path {
        &self.private_temp_directory
    }

    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }
}

impl fmt::Debug for ManagedProfileDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedProfileDirectory")
            .field(
                "binding_directory_digest",
                &digest(self.binding_directory.as_os_str().as_encoded_bytes()),
            )
            .field("binding_digest", &self.binding_digest)
            .finish_non_exhaustive()
    }
}

fn profile_scope_digest(profile: &BrowserProfile) -> Result<String, BrowserError> {
    digest_json(&serde_json::json!({
        "schemaVersion": PROFILE_BINDING_SCHEMA_VERSION,
        "profileId": profile.id,
        "tenantId": profile.tenant_id,
        "projectId": profile.project_id,
        "source": profile.source,
        "identityDigest": profile.identity.identity_digest,
    }))
}

fn acquire_profile_ownership_lock(path: &Path, binding_digest: &str) -> Result<File, BrowserError> {
    let existed_before_open = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(BrowserError::InvalidProfileDirectory);
            }
            validate_private_file_permissions(&metadata)?;
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(BrowserError::Io(error)),
    };

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(BrowserError::InvalidProfileDirectory);
    }
    if existed_before_open {
        validate_private_file_permissions(&opened_metadata)?;
    } else {
        set_private_open_file_permissions(&file)?;
    }

    file.try_lock().map_err(|_| BrowserError::ProfileInUse)?;

    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(BrowserError::InvalidProfileDirectory);
    }
    validate_private_file_permissions(&path_metadata)?;
    validate_same_file_identity(&opened_metadata, &path_metadata)?;

    let expected_token = profile_ownership_token(binding_digest)?;
    if file.metadata()?.len() == 0 {
        initialize_profile_ownership_token(&mut file, path, &expected_token)?;
    } else {
        validate_profile_ownership_token(&mut file, &expected_token)?;
    }
    Ok(file)
}

fn profile_ownership_token(binding_digest: &str) -> Result<String, BrowserError> {
    digest_json(&serde_json::json!({
        "schemaVersion": PROFILE_OWNERSHIP_LOCK_SCHEMA_VERSION,
        "domain": "hartevo-browser-profile-ownership-lock/v1",
        "bindingDigest": binding_digest,
    }))
}

fn initialize_profile_ownership_token(
    file: &mut File,
    path: &Path,
    expected_token: &str,
) -> Result<(), BrowserError> {
    if file.metadata()?.len() != 0 {
        return Err(BrowserError::ProfileBindingMismatch);
    }
    file.seek(SeekFrom::Start(0))?;
    file.write_all(expected_token.as_bytes())?;
    file.sync_all()?;
    validate_profile_ownership_token(file, expected_token)?;
    sync_parent_directory(path)
}

fn validate_profile_ownership_token(
    file: &mut File,
    expected_token: &str,
) -> Result<(), BrowserError> {
    if file.metadata()?.len() != PROFILE_OWNERSHIP_TOKEN_BYTES
        || expected_token.len()
            != usize::try_from(PROFILE_OWNERSHIP_TOKEN_BYTES)
                .map_err(|_| BrowserError::CounterOverflow)?
    {
        return Err(BrowserError::ProfileBindingMismatch);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut actual = String::new();
    file.read_to_string(&mut actual)
        .map_err(|_| BrowserError::ProfileBindingMismatch)?;
    if actual != expected_token {
        return Err(BrowserError::ProfileBindingMismatch);
    }
    Ok(())
}

fn ensure_exact_marker(path: &Path, expected: &ProfileBindingMarker) -> Result<(), BrowserError> {
    reject_symlink_if_present(path)?;
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            set_private_file_permissions(path)?;
            let encoded = serde_json::to_vec(expected)?;
            file.write_all(&encoded)?;
            file.sync_all()?;
            validate_private_file_permissions(&file.metadata()?)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let file = File::open(path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.len() > MAX_MARKER_BYTES {
                return Err(BrowserError::ProfileBindingMismatch);
            }
            validate_private_file_permissions(&metadata)?;
            let actual: ProfileBindingMarker =
                serde_json::from_reader(file).map_err(|_| BrowserError::ProfileBindingMismatch)?;
            if &actual != expected {
                return Err(BrowserError::ProfileBindingMismatch);
            }
            Ok(())
        }
        Err(error) => Err(BrowserError::Io(error)),
    }
}

fn create_or_validate_private_directory(path: &Path, parent: &Path) -> Result<(), BrowserError> {
    match fs::create_dir(path) {
        Ok(()) => set_private_directory_permissions(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(BrowserError::Io(error)),
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BrowserError::InvalidProfileDirectory);
    }
    validate_private_directory_permissions(&metadata)?;
    let canonical = fs::canonicalize(path)?;
    let canonical_parent = fs::canonicalize(parent)?;
    if !canonical.starts_with(&canonical_parent) || canonical == canonical_parent {
        return Err(BrowserError::InvalidProfileDirectory);
    }
    Ok(())
}

fn reject_symlink_if_present(path: &Path) -> Result<(), BrowserError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(BrowserError::InvalidProfileDirectory)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BrowserError::Io(error)),
    }
}

#[cfg(unix)]
fn validate_executable_permissions(metadata: &fs::Metadata) -> Result<(), BrowserError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode();
    if mode & 0o111 == 0 || mode & 0o022 != 0 {
        return Err(BrowserError::InvalidExecutable);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_executable_permissions(_metadata: &fs::Metadata) -> Result<(), BrowserError> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_directory_permissions(metadata: &fs::Metadata) -> Result<(), BrowserError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(BrowserError::InvalidProfileDirectory);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_directory_permissions(_metadata: &fs::Metadata) -> Result<(), BrowserError> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_file_permissions(metadata: &fs::Metadata) -> Result<(), BrowserError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(BrowserError::InvalidProfileDirectory);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file_permissions(_metadata: &fs::Metadata) -> Result<(), BrowserError> {
    Ok(())
}

#[cfg(unix)]
fn validate_same_file_identity(
    opened: &fs::Metadata,
    path: &fs::Metadata,
) -> Result<(), BrowserError> {
    use std::os::unix::fs::MetadataExt;

    if opened.dev() != path.dev() || opened.ino() != path.ino() {
        return Err(BrowserError::InvalidProfileDirectory);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_same_file_identity(
    _opened: &fs::Metadata,
    _path: &fs::Metadata,
) -> Result<(), BrowserError> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), BrowserError> {
    let parent = path.parent().ok_or(BrowserError::InvalidProfileDirectory)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), BrowserError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), BrowserError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), BrowserError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), BrowserError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
fn set_private_open_file_permissions(file: &File) -> Result<(), BrowserError> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_open_file_permissions(_file: &File) -> Result<(), BrowserError> {
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), BrowserError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::process::{Child, Command, ExitStatus, Stdio};
    #[cfg(unix)]
    use std::thread;
    #[cfg(unix)]
    use std::time::Duration;

    use chrono::{TimeZone, Utc};
    use hartevo_domain_kernel::{
        AccountId, BrowserProfileId, Project, ProjectId, StorageMode, TenantId,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::BrowserIdentity;

    #[cfg(unix)]
    const PROFILE_LOCK_HELPER_ROOT: &str = "HARTEVO_BROWSER_PROFILE_LOCK_HELPER_ROOT";
    #[cfg(unix)]
    const PROFILE_LOCK_HELPER_MODE: &str = "HARTEVO_BROWSER_PROFILE_LOCK_HELPER_MODE";

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn fixture(root: &Path) -> (BrowserProfile, BrowserExecutableIdentity, PathBuf) {
        let executable = root.join("managed-browser");
        if !executable.exists() {
            fs::write(&executable, b"managed browser test executable").expect("write executable");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
                .expect("make executable");
        }
        let project = Project::create_local(
            TenantId::from("tenant-browser-profile"),
            ProjectId::from("project-browser-profile"),
            "Browser profile",
            "",
            "/workspace/browser-profile",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let identity = BrowserIdentity::new(
            "github",
            AccountId::from("account-browser-profile"),
            sha('a'),
            sha('b'),
            Utc.with_ymd_and_hms(2026, 8, 11, 12, 0, 0)
                .single()
                .expect("time"),
        )
        .expect("identity");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-browser-managed"),
            &project,
            "keyring://browser/profile-browser-managed",
            identity,
            Utc.with_ymd_and_hms(2026, 8, 11, 12, 0, 0)
                .single()
                .expect("time"),
        )
        .expect("profile");
        let executable_identity =
            BrowserExecutableIdentity::inspect(&executable).expect("inspect executable");
        (profile, executable_identity, executable)
    }

    fn private_profiles_root(root: &Path) -> PathBuf {
        let profiles = root.join("profiles");
        match fs::create_dir(&profiles) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create profiles root: {error}"),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&profiles, fs::Permissions::from_mode(0o700))
                .expect("private profiles root");
        }
        profiles
    }

    #[cfg(unix)]
    struct ProfileLockChild {
        child: Option<Child>,
        ready_path: PathBuf,
        release_path: PathBuf,
    }

    #[cfg(unix)]
    impl ProfileLockChild {
        fn spawn(root: &Path, mode: &str) -> Self {
            let ready_path = root.join(format!("profile-lock-{mode}.ready"));
            let release_path = root.join(format!("profile-lock-{mode}.release"));
            let child = Command::new(std::env::current_exe().expect("current test executable"))
                .arg("profile_lock_process_fixture")
                .arg("--nocapture")
                .env(PROFILE_LOCK_HELPER_ROOT, root)
                .env(PROFILE_LOCK_HELPER_MODE, mode)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("spawn profile lock holder");
            Self {
                child: Some(child),
                ready_path,
                release_path,
            }
        }

        fn wait_until_ready(&mut self) {
            for _ in 0..1_000 {
                if self.ready_path.exists() {
                    return;
                }
                if let Some(status) = self
                    .child
                    .as_mut()
                    .expect("profile lock child")
                    .try_wait()
                    .expect("inspect profile lock child")
                {
                    panic!("profile lock child exited before ready: {status}");
                }
                thread::sleep(Duration::from_millis(10));
            }
            panic!("profile lock child did not become ready");
        }

        fn finish_gracefully(mut self) -> ExitStatus {
            fs::write(&self.release_path, b"release").expect("release profile lock child");
            let mut child = self.child.take().expect("profile lock child");
            child.wait().expect("wait for profile lock child")
        }

        fn kill_with_sigkill(mut self) -> ExitStatus {
            let mut child = self.child.take().expect("profile lock child");
            child.kill().expect("send SIGKILL to profile lock child");
            child.wait().expect("wait for killed profile lock child")
        }
    }

    #[cfg(unix)]
    impl Drop for ProfileLockChild {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                if child.try_wait().ok().flatten().is_none() {
                    let _ = child.kill();
                }
                let _ = child.wait();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn profile_lock_process_fixture() {
        let Some(root) = std::env::var_os(PROFILE_LOCK_HELPER_ROOT).map(PathBuf::from) else {
            return;
        };
        let mode = std::env::var(PROFILE_LOCK_HELPER_MODE).expect("profile lock helper mode");
        let (profile, executable, _) = fixture(&root);
        let profiles = private_profiles_root(&root);
        let _lease = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect("child acquires profile lock");
        let ready_path = root.join(format!("profile-lock-{mode}.ready"));
        let release_path = root.join(format!("profile-lock-{mode}.release"));
        fs::write(ready_path, b"ready").expect("publish profile lock readiness");
        match mode.as_str() {
            "graceful" => {
                for _ in 0..1_000 {
                    if release_path.exists() {
                        return;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                panic!("profile lock helper was not released");
            }
            "sigkill" => loop {
                thread::sleep(Duration::from_millis(100));
            },
            _ => panic!("unknown profile lock helper mode"),
        }
    }

    #[test]
    fn managed_profile_is_exact_private_locked_and_reusable_after_release() {
        let temp = TempDir::new().expect("temp dir");
        let (profile, executable, _) = fixture(temp.path());
        let profiles = private_profiles_root(temp.path());
        let first = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect("first profile lease");
        let error = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect_err("concurrent host must fail");
        assert!(matches!(error, BrowserError::ProfileInUse));
        let binding_digest = first.binding_digest().to_owned();
        let chrome_data = first.chrome_data_directory().to_path_buf();
        let ownership_lock = first.binding_directory.join(PROFILE_OWNERSHIP_LOCK_FILE);
        drop(first);
        assert!(
            ownership_lock.exists(),
            "ownership lock file must be durable"
        );
        let reopened = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect("reopen exact profile");
        assert_eq!(reopened.binding_digest(), binding_digest);
        assert_eq!(reopened.chrome_data_directory(), chrome_data);
        let debug = format!("{reopened:?}");
        assert!(!debug.contains(profiles.to_string_lossy().as_ref()));
        assert!(!debug.contains(&profile.credential_reference));
    }

    #[test]
    fn executable_swap_and_marker_tamper_fail_closed() {
        let temp = TempDir::new().expect("temp dir");
        let (profile, executable, executable_path) = fixture(temp.path());
        let profiles = private_profiles_root(temp.path());
        let prepared = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect("prepare profile");
        drop(prepared);

        fs::write(&executable_path, b"swapped executable").expect("swap executable");
        let _swapped = BrowserExecutableIdentity::inspect(&executable_path).expect("inspect swap");
        let error = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect_err("stale executable evidence must fail");
        assert!(matches!(error, BrowserError::InvalidExecutable));

        fs::write(&executable_path, b"managed browser test executable")
            .expect("restore executable");
        let restored =
            BrowserExecutableIdentity::inspect(&executable_path).expect("inspect restored");
        let error = ManagedProfileDirectory::prepare(&profiles, &profile, &restored)
            .expect_err("changed executable evidence must require reconciliation");
        assert!(matches!(error, BrowserError::ProfileBindingMismatch));

        let second = TempDir::new().expect("second temp dir");
        let (second_profile, second_executable, _) = fixture(second.path());
        let second_profiles = private_profiles_root(second.path());
        let second_prepared =
            ManagedProfileDirectory::prepare(&second_profiles, &second_profile, &second_executable)
                .expect("prepare second profile");
        let second_binding_directory = second_prepared.binding_directory.clone();
        drop(second_prepared);
        fs::write(second_binding_directory.join("binding-v1.json"), b"{}").expect("tamper marker");
        let error =
            ManagedProfileDirectory::prepare(&second_profiles, &second_profile, &second_executable)
                .expect_err("marker tamper must fail");
        assert!(matches!(error, BrowserError::ProfileBindingMismatch));
    }

    #[cfg(unix)]
    #[test]
    fn independent_process_lock_blocks_and_releases_after_normal_exit() {
        let temp = TempDir::new().expect("temp dir");
        let mut child = ProfileLockChild::spawn(temp.path(), "graceful");
        child.wait_until_ready();
        let (profile, executable, _) = fixture(temp.path());
        let profiles = private_profiles_root(temp.path());
        assert!(matches!(
            ManagedProfileDirectory::prepare(&profiles, &profile, &executable),
            Err(BrowserError::ProfileInUse)
        ));
        let status = child.finish_gracefully();
        assert!(status.success(), "profile lock child failed: {status}");
        let reopened = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect("kernel lock is released after normal process exit");
        drop(reopened);
    }

    #[cfg(unix)]
    #[test]
    fn independent_process_lock_releases_after_sigkill() {
        use std::os::unix::process::ExitStatusExt;

        let temp = TempDir::new().expect("temp dir");
        let mut child = ProfileLockChild::spawn(temp.path(), "sigkill");
        child.wait_until_ready();
        let (profile, executable, _) = fixture(temp.path());
        let profiles = private_profiles_root(temp.path());
        assert!(matches!(
            ManagedProfileDirectory::prepare(&profiles, &profile, &executable),
            Err(BrowserError::ProfileInUse)
        ));
        let status = child.kill_with_sigkill();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let reopened = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect("kernel lock is released after SIGKILL");
        drop(reopened);
    }

    #[cfg(unix)]
    #[test]
    fn zero_byte_ownership_lock_initialization_residue_is_recovered() {
        let temp = TempDir::new().expect("temp dir");
        let (profile, executable, _) = fixture(temp.path());
        let profiles = private_profiles_root(temp.path());
        let prepared = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect("prepare initialization fixture");
        let binding_digest = prepared.binding_digest().to_owned();
        let lock_path = prepared.binding_directory.join(PROFILE_OWNERSHIP_LOCK_FILE);
        drop(prepared);

        let residue = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&lock_path)
            .expect("truncate ownership token before simulated crash");
        residue.sync_all().expect("sync zero-byte residue");
        drop(residue);
        assert_eq!(fs::metadata(&lock_path).expect("lock metadata").len(), 0);

        let recovered = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect("recover zero-byte initialization residue under the kernel lock");
        assert_eq!(recovered.binding_digest(), binding_digest);
        drop(recovered);
        assert_eq!(
            fs::read_to_string(&lock_path).expect("recovered ownership token"),
            profile_ownership_token(&binding_digest).expect("expected ownership token")
        );
        let reopened = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect("reopen recovered ownership lock");
        drop(reopened);
    }

    #[cfg(unix)]
    #[test]
    fn ownership_token_symlink_and_permissions_tamper_fail_closed() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let token_temp = TempDir::new().expect("token temp dir");
        let (profile, executable, _) = fixture(token_temp.path());
        let profiles = private_profiles_root(token_temp.path());
        let prepared = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect("prepare token fixture");
        let lock_path = prepared.binding_directory.join(PROFILE_OWNERSHIP_LOCK_FILE);
        drop(prepared);
        fs::write(&lock_path, "f".repeat(64)).expect("tamper ownership token");
        assert!(matches!(
            ManagedProfileDirectory::prepare(&profiles, &profile, &executable),
            Err(BrowserError::ProfileBindingMismatch)
        ));

        let symlink_temp = TempDir::new().expect("symlink temp dir");
        let (profile, executable, _) = fixture(symlink_temp.path());
        let profiles = private_profiles_root(symlink_temp.path());
        let prepared = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect("prepare symlink fixture");
        let lock_path = prepared.binding_directory.join(PROFILE_OWNERSHIP_LOCK_FILE);
        drop(prepared);
        fs::remove_file(&lock_path).expect("remove ownership lock");
        let target = symlink_temp.path().join("malicious-lock-target");
        fs::write(&target, "0".repeat(64)).expect("write symlink target");
        symlink(target, &lock_path).expect("replace ownership lock with symlink");
        assert!(matches!(
            ManagedProfileDirectory::prepare(&profiles, &profile, &executable),
            Err(BrowserError::InvalidProfileDirectory)
        ));

        let permissions_temp = TempDir::new().expect("permissions temp dir");
        let (profile, executable, _) = fixture(permissions_temp.path());
        let profiles = private_profiles_root(permissions_temp.path());
        let prepared = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect("prepare permissions fixture");
        let lock_path = prepared.binding_directory.join(PROFILE_OWNERSHIP_LOCK_FILE);
        drop(prepared);
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644))
            .expect("weaken ownership lock permissions");
        assert!(matches!(
            ManagedProfileDirectory::prepare(&profiles, &profile, &executable),
            Err(BrowserError::InvalidProfileDirectory)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_or_shared_profile_root_and_world_writable_executable_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = TempDir::new().expect("temp dir");
        let (profile, _, executable_path) = fixture(temp.path());
        fs::set_permissions(&executable_path, fs::Permissions::from_mode(0o722))
            .expect("weaken executable");
        assert!(matches!(
            BrowserExecutableIdentity::inspect(&executable_path),
            Err(BrowserError::InvalidExecutable)
        ));

        fs::set_permissions(&executable_path, fs::Permissions::from_mode(0o700))
            .expect("restore executable");
        let executable =
            BrowserExecutableIdentity::inspect(&executable_path).expect("inspect executable");
        let shared = temp.path().join("shared");
        fs::create_dir(&shared).expect("shared root");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755))
            .expect("shared permissions");
        assert!(matches!(
            ManagedProfileDirectory::prepare(&shared, &profile, &executable),
            Err(BrowserError::InvalidProfileDirectory)
        ));

        let private = temp.path().join("private");
        fs::create_dir(&private).expect("private root");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let linked = temp.path().join("linked");
        symlink(&private, &linked).expect("profile symlink");
        assert!(matches!(
            ManagedProfileDirectory::prepare(&linked, &profile, &executable),
            Err(BrowserError::InvalidProfileDirectory)
        ));
    }
}
