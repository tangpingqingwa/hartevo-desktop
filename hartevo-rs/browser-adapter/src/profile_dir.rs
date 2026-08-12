use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use hartevo_domain_kernel::BrowserProfileId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::workspace::{digest, digest_json};
use crate::{BrowserError, BrowserProfile, BrowserProfileSource, BrowserProfileStatus};

const PROFILE_BINDING_SCHEMA_VERSION: u32 = 1;
const MAX_MARKER_BYTES: u64 = 64 * 1_024;
static PROFILE_LOCK_COUNTER: AtomicU64 = AtomicU64::new(1);

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
    lock_path: PathBuf,
    lock_digest: String,
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

        let lock_path = binding_directory.join("host.lock");
        reject_symlink_if_present(&lock_path)?;
        let lock_digest = new_lock_digest(&binding_digest)?;
        let mut lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    BrowserError::ProfileInUse
                } else {
                    BrowserError::Io(error)
                }
            })?;
        set_private_file_permissions(&lock_path)?;
        lock.write_all(lock_digest.as_bytes())?;
        lock.sync_all()?;

        Ok(Self {
            binding_directory,
            chrome_data_directory,
            private_home_directory,
            private_temp_directory,
            binding_digest,
            lock_path,
            lock_digest,
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

    fn release_lock(&self) {
        let current = fs::read_to_string(&self.lock_path).ok();
        if current.as_deref() == Some(self.lock_digest.as_str()) {
            let _ = fs::remove_file(&self.lock_path);
        }
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

impl Drop for ManagedProfileDirectory {
    fn drop(&mut self) {
        self.release_lock();
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

fn ensure_exact_marker(path: &Path, expected: &ProfileBindingMarker) -> Result<(), BrowserError> {
    reject_symlink_if_present(path)?;
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            set_private_file_permissions(path)?;
            let encoded = serde_json::to_vec(expected)?;
            file.write_all(&encoded)?;
            file.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let file = File::open(path)?;
            if file.metadata()?.len() > MAX_MARKER_BYTES {
                return Err(BrowserError::ProfileBindingMismatch);
            }
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

fn new_lock_digest(binding_digest: &str) -> Result<String, BrowserError> {
    let ordinal = PROFILE_LOCK_COUNTER.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BrowserError::InvalidProfileDirectory)?
        .as_nanos();
    digest_json(&serde_json::json!({
        "bindingDigest": binding_digest,
        "processId": std::process::id(),
        "ordinal": ordinal,
        "timestampNanos": timestamp.to_string(),
    }))
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

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), BrowserError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use chrono::{TimeZone, Utc};
    use hartevo_domain_kernel::{
        AccountId, BrowserProfileId, Project, ProjectId, StorageMode, TenantId,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::BrowserIdentity;

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn fixture(root: &Path) -> (BrowserProfile, BrowserExecutableIdentity, PathBuf) {
        let executable = root.join("managed-browser");
        fs::write(&executable, b"managed browser test executable").expect("write executable");
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

    #[test]
    fn managed_profile_is_exact_private_locked_and_reusable_after_release() {
        let temp = TempDir::new().expect("temp dir");
        let (profile, executable, _) = fixture(temp.path());
        let profiles = temp.path().join("profiles");
        fs::create_dir(&profiles).expect("profiles root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&profiles, fs::Permissions::from_mode(0o700))
                .expect("private root");
        }
        let first = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect("first profile lease");
        let error = ManagedProfileDirectory::prepare(&profiles, &profile, &executable)
            .expect_err("concurrent host must fail");
        assert!(matches!(error, BrowserError::ProfileInUse));
        let binding_digest = first.binding_digest().to_owned();
        let chrome_data = first.chrome_data_directory().to_path_buf();
        drop(first);
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
        let profiles = temp.path().join("profiles");
        fs::create_dir(&profiles).expect("profiles root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&profiles, fs::Permissions::from_mode(0o700))
                .expect("private root");
        }
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
        let second_profiles = second.path().join("profiles");
        fs::create_dir(&second_profiles).expect("second profiles root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&second_profiles, fs::Permissions::from_mode(0o700))
                .expect("second private root");
        }
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
