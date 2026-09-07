use super::*;
use crate::DatabaseKey;
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn checkpoint(id: &str) -> PersistedSessionCheckpoint {
    PersistedSessionCheckpoint {
        header: PersistedSessionHeader {
            version: 0,
            id: id.into(),
            created_at_ms: 1,
            parent_session: None,
            delegation_depth: 0,
            seed_length: None,
        },
        events: Vec::new(),
    }
}

fn open(path: &Path) -> ProjectStore {
    ProjectStore::open(path, &DatabaseKey::new([43; 32]).unwrap()).unwrap()
}

#[test]
fn session_writer_excludes_other_connections_but_allows_readers_and_other_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private.sqlite");
    let mut first = open(&path);
    let mut second = open(&path);
    let one = checkpoint("first-session");
    assert!(first.persist_session_checkpoint(&one).unwrap());
    assert_eq!(
        second.load_session_checkpoints().unwrap(),
        vec![one.clone()]
    );
    assert!(
        matches!(second.persist_session_checkpoint(&one), Err(StorageError::SessionAlreadyOwned(id)) if id == one.header.id)
    );
    assert!(
        second
            .persist_session_checkpoint(&checkpoint("other-session"))
            .unwrap()
    );
    assert!(!first.persist_session_checkpoint(&one).unwrap());
    drop(first);
    assert!(!second.persist_session_checkpoint(&one).unwrap());
}

#[test]
fn session_restore_claims_before_publication_and_rolls_back_a_partial_claim_set() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private.sqlite");
    let mut seed = open(&path);
    let first = checkpoint("a-session");
    let second = checkpoint("b-session");
    seed.persist_session_checkpoint(&first).unwrap();
    seed.persist_session_checkpoint(&second).unwrap();
    drop(seed);
    let mut owner = open(&path);
    owner.persist_session_checkpoint(&second).unwrap();
    let mut restore = open(&path);
    assert!(
        matches!(restore.load_owned_session_checkpoints(), Err(StorageError::SessionAlreadyOwned(id)) if id == second.header.id)
    );
    let mut contender = open(&path);
    assert!(
        !contender.persist_session_checkpoint(&first).unwrap(),
        "failed restore must release its newly claimed earlier session"
    );
    drop(owner);
    drop(contender);
    assert_eq!(
        restore.load_owned_session_checkpoints().unwrap(),
        vec![first.clone(), second]
    );
    let mut competitor = open(&path);
    assert!(matches!(
        competitor.persist_session_checkpoint(&first),
        Err(StorageError::SessionAlreadyOwned(_))
    ));
}

#[test]
fn session_future_format_is_refused_before_unknown_events_or_repair() {
    let mut store = ProjectStore::in_memory().unwrap();
    let mut future = checkpoint("future");
    future.header.version = 2;
    assert!(matches!(
        store.persist_session_checkpoint(&future),
        Err(StorageError::UnsupportedSessionFormat {
            actual: 2,
            supported: 0
        })
    ));
    assert!(store.load_session_checkpoints().unwrap().is_empty());
    future.header.version = 0;
    store.persist_session_checkpoint(&future).unwrap();
    store.connection.execute("UPDATE cordis_session_headers SET format_version = 2, event_count = 1 WHERE id = 'future'", []).unwrap();
    store
        .connection
        .execute(
            "INSERT INTO cordis_session_events VALUES ('future', 0, 'future-opaque-payload')",
            [],
        )
        .unwrap();
    assert!(matches!(
        store.load_owned_session_checkpoints(),
        Err(StorageError::UnsupportedSessionFormat {
            actual: 2,
            supported: 0
        })
    ));
    assert_eq!(
        store
            .connection
            .query_row(
                "SELECT event_json FROM cordis_session_events WHERE session_id = 'future'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "future-opaque-payload"
    );
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "subprocess fixture for the crash-release test"]
fn session_lease_child() {
    let Some(path) = std::env::var_os("HARTEVO_SESSION_LEASE_TEST_DATABASE") else {
        return;
    };
    let mut store = open(Path::new(&path));
    store
        .persist_session_checkpoint(&checkpoint("process-session"))
        .unwrap();
    println!("SESSION_WRITER_READY");
    std::io::stdout().flush().unwrap();
    // The parent kills this process, without running destructors/unlock.
    std::thread::sleep(Duration::from_secs(30));
    panic!("parent did not terminate the lease fixture");
}

#[test]
fn session_writer_kernel_lock_excludes_a_real_process_and_releases_after_crash() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private.sqlite");
    drop(open(&path));
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cordis_session_store::ownership_tests::session_lease_child",
                "--ignored",
                "--nocapture",
            ])
            .env("HARTEVO_SESSION_LEASE_TEST_DATABASE", &path)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let output = child.0.stdout.take().unwrap();
    let (sent, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let ready = std::io::BufReader::new(output)
            .lines()
            .any(|line| line.is_ok_and(|line| line == "SESSION_WRITER_READY"));
        let _ = sent.send(ready);
    });
    assert!(
        received.recv_timeout(Duration::from_secs(20)).unwrap(),
        "child failed before acquiring ownership"
    );
    let mut observer = open(&path);
    let stored = checkpoint("process-session");
    assert_eq!(
        observer.load_session_checkpoints().unwrap(),
        vec![stored.clone()]
    );
    assert!(matches!(
        observer.persist_session_checkpoint(&stored),
        Err(StorageError::SessionAlreadyOwned(_))
    ));
    child.0.kill().unwrap();
    assert!(!child.0.wait().unwrap().success());
    assert_eq!(
        observer.load_owned_session_checkpoints().unwrap(),
        vec![stored.clone()]
    );
    assert!(!observer.persist_session_checkpoint(&stored).unwrap());
}

#[cfg(unix)]
#[test]
fn session_writer_never_reacquires_after_its_lock_inode_is_replaced() {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::OpenOptionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private.sqlite");
    let mut store = open(&path);
    let stored = checkpoint("private-session");
    store.persist_session_checkpoint(&stored).unwrap();
    let root = dir.path().join("private.sqlite.cordis-session-locks");
    let lock = root.join(format!(
        "{}.lock",
        hex::encode(Sha256::digest(stored.header.id.as_bytes()))
    ));
    assert_eq!(std::fs::read(&lock).unwrap(), Vec::<u8>::new());
    let displaced = root.join("displaced");
    std::fs::rename(&lock, &displaced).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&lock)
        .unwrap();
    assert!(matches!(
        store.persist_session_checkpoint(&stored),
        Err(StorageError::SessionOwnershipLost(_))
    ));
    std::fs::remove_file(&lock).unwrap();
    std::fs::rename(&displaced, &lock).unwrap();
    assert!(
        matches!(
            store.persist_session_checkpoint(&stored),
            Err(StorageError::SessionOwnershipLost(_))
        ),
        "restoring the original inode must not resurrect a lost owner"
    );
    assert_eq!(store.load_session_checkpoints().unwrap(), vec![stored]);
}

#[cfg(unix)]
#[test]
fn session_writer_rejects_symlink_lock_roots_without_touching_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private.sqlite");
    let target = tempfile::tempdir().unwrap();
    let mut store = open(&path);
    std::os::unix::fs::symlink(
        target.path(),
        dir.path().join("private.sqlite.cordis-session-locks"),
    )
    .unwrap();
    assert!(matches!(
        store.persist_session_checkpoint(&checkpoint("session")),
        Err(StorageError::InvalidSessionOwnershipPath)
    ));
    assert!(std::fs::read_dir(target.path()).unwrap().next().is_none());
    assert!(store.load_session_checkpoints().unwrap().is_empty());
}
