//! Process-lifetime single-writer ownership for SQLCipher Session logs.
//!
//! SQLite serializes commits, but cannot exclude two live agents between
//! commits. A separate kernel lock stays held for the owning store's lifetime.
//! Lock files contain no Session data and are never unlinked on release.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::StorageError;

#[derive(Debug, Default)]
pub(crate) struct SessionWriteOwnership {
    root: Option<PathBuf>,
    leases: BTreeMap<String, SessionWriteLease>,
}

impl SessionWriteOwnership {
    pub(crate) fn same_database(&self, other: &Self) -> bool {
        self.root.is_some() && self.root == other.root
    }

    pub(crate) fn for_database(path: &Path) -> Self {
        let mut name = path.as_os_str().to_owned();
        name.push(".cordis-session-locks");
        Self {
            root: Some(PathBuf::from(name)),
            leases: BTreeMap::new(),
        }
    }

    pub(crate) fn claim(&mut self, id: &str) -> Result<(), StorageError> {
        if id.is_empty() {
            return Err(StorageError::InvalidSessionCheckpoint(
                "session id must not be empty",
            ));
        }
        if let Some(lease) = self.leases.get_mut(id) {
            return lease.validate(id);
        }
        // An in-memory database belongs to exactly this non-cloneable store.
        let Some(root) = &self.root else {
            return Ok(());
        };
        let lease = SessionWriteLease::acquire(root, id)?;
        self.leases.insert(id.to_owned(), lease);
        Ok(())
    }

    /// Acquire a complete restore set, releasing newly taken claims on failure.
    pub(crate) fn claim_all(&mut self, ids: &[String]) -> Result<(), StorageError> {
        let mut acquired = Vec::new();
        for id in ids {
            let existing = self.leases.contains_key(id);
            if let Err(error) = self.claim(id) {
                for acquired_id in acquired {
                    self.leases.remove(&acquired_id);
                }
                return Err(error);
            }
            if !existing {
                acquired.push(id.clone());
            }
        }
        Ok(())
    }
}

struct SessionWriteLease {
    file: File,
    path: PathBuf,
    lost: bool,
}

impl std::fmt::Debug for SessionWriteLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionWriteLease")
            .field("lost", &self.lost)
            .finish_non_exhaustive()
    }
}

impl SessionWriteLease {
    fn acquire(root: &Path, id: &str) -> Result<Self, StorageError> {
        let directory = fs::DirBuilder::new();
        #[cfg(unix)]
        let directory = {
            use std::os::unix::fs::DirBuilderExt;
            let mut directory = directory;
            directory.mode(0o700);
            directory
        };
        match directory.create(root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(StorageError::InvalidSessionOwnershipPath);
        }
        require_private(&metadata)?;
        let path = root.join(format!(
            "{}.lock",
            hex::encode(Sha256::digest(id.as_bytes()))
        ));
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(StorageError::InvalidSessionOwnershipPath);
                }
                require_private(&metadata)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Allow other readers/contenders, but prohibit replacement while
            // any holder has this file open (no FILE_SHARE_DELETE).
            options.share_mode(0x1 | 0x2);
        }
        let file = options.open(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(StorageError::SessionAlreadyOwned(id.into()));
            }
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        let mut lease = Self {
            file,
            path,
            lost: false,
        };
        lease.validate(id)?;
        Ok(lease)
    }

    fn validate(&mut self, id: &str) -> Result<(), StorageError> {
        if self.lost || !self.same_file().unwrap_or(false) {
            // Never reacquire silently: this live agent's history may already
            // be stale after ownership was lost, even if the path reappears.
            self.lost = true;
            return Err(StorageError::SessionOwnershipLost(id.into()));
        }
        Ok(())
    }

    fn same_file(&self) -> Result<bool, StorageError> {
        let held = self.file.metadata()?;
        let current = fs::symlink_metadata(&self.path)?;
        if !held.is_file() || !current.is_file() || current.file_type().is_symlink() {
            return Ok(false);
        }
        require_private(&held)?;
        require_private(&current)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(held.dev() == current.dev() && held.ino() == current.ino())
        }
        #[cfg(not(unix))]
        {
            // Windows open sharing prohibits unlink/rename of the held file.
            Ok(true)
        }
    }
}

fn require_private(metadata: &fs::Metadata) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StorageError::InvalidSessionOwnershipPath);
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    Ok(())
}
