use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, Utc};
use hartevo_context_fabric::{
    ContextAssemblyError, ContextMaterialReference, ContextMaterialResolver,
    ResolvedContextMaterial,
};
use hartevo_domain_kernel::{ProjectId, TenantId};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ContentCrypto, ContentEncryptionContext, EncryptedContent, KeyMaterial};

const MATERIAL_SCHEMA_VERSION: u32 = 1;
const MATERIAL_OBJECT_KIND: &str = "context_material.text";
const MAX_MATERIAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 2 * MAX_MATERIAL_BYTES as u64 + 32 * 1024;
const TEMP_NONCE_BYTES: usize = 16;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextMaterialDescriptor {
    pub storage_ref: String,
    pub content_digest: String,
    pub byte_len: u64,
    pub key_version: u64,
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextQuerySnapshot {
    pub provider: String,
    pub query_digest: String,
    pub schema_digest: String,
    pub observed_at: DateTime<Utc>,
    pub payload: Value,
}

impl ContextQuerySnapshot {
    fn validate(&self) -> Result<(), ContextMaterialStoreError> {
        if self.provider.trim().is_empty()
            || self.provider.len() > 128
            || !is_sha256(&self.query_digest)
            || !is_sha256(&self.schema_digest)
        {
            return Err(ContextMaterialStoreError::InvalidQuerySnapshot);
        }
        Ok(())
    }
}

impl fmt::Debug for ContextQuerySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextQuerySnapshot")
            .field("provider_digest", &sha256(self.provider.as_bytes()))
            .field("query_digest", &self.query_digest)
            .field("schema_digest", &self.schema_digest)
            .field("observed_at", &self.observed_at)
            .field(
                "payload_digest",
                &serde_json::to_vec(&self.payload)
                    .map_or_else(|_| "unavailable".into(), |payload| sha256(&payload)),
            )
            .finish()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredContextMaterial {
    schema_version: u32,
    tenant_id: TenantId,
    project_id: ProjectId,
    plaintext_digest: String,
    plaintext_byte_len: u64,
    key_version: u64,
    nonce_hex: String,
    ciphertext_hex: String,
    aad_digest: String,
    ciphertext_digest: String,
}

impl StoredContextMaterial {
    fn from_encrypted(
        tenant_id: TenantId,
        project_id: ProjectId,
        plaintext_digest: String,
        plaintext_byte_len: u64,
        key_version: u64,
        encrypted: EncryptedContent,
    ) -> Self {
        Self {
            schema_version: MATERIAL_SCHEMA_VERSION,
            tenant_id,
            project_id,
            plaintext_digest,
            plaintext_byte_len,
            key_version,
            nonce_hex: hex::encode(encrypted.nonce),
            ciphertext_hex: hex::encode(encrypted.ciphertext),
            aad_digest: encrypted.aad_digest,
            ciphertext_digest: encrypted.content_digest,
        }
    }

    fn encrypted(&self) -> Result<EncryptedContent, ContextMaterialStoreError> {
        Ok(EncryptedContent {
            nonce: hex::decode(&self.nonce_hex)
                .map_err(|_| ContextMaterialStoreError::CorruptRecord)?,
            ciphertext: hex::decode(&self.ciphertext_hex)
                .map_err(|_| ContextMaterialStoreError::CorruptRecord)?,
            aad_digest: self.aad_digest.clone(),
            content_digest: self.ciphertext_digest.clone(),
        })
    }
}

pub struct LocalEncryptedContextMaterialStore {
    tenant_id: TenantId,
    project_id: ProjectId,
    project_root: PathBuf,
    cas_root: PathBuf,
    active_key_version: u64,
    keys: BTreeMap<u64, KeyMaterial>,
}

impl LocalEncryptedContextMaterialStore {
    pub fn new(
        project_root: &Path,
        tenant_id: TenantId,
        project_id: ProjectId,
        active_key_version: u64,
        active_key: KeyMaterial,
    ) -> Result<Self, ContextMaterialStoreError> {
        if tenant_id.as_str().trim().is_empty()
            || project_id.as_str().trim().is_empty()
            || active_key_version == 0
        {
            return Err(ContextMaterialStoreError::InvalidScope);
        }
        let project_root = project_root
            .canonicalize()
            .map_err(|_| ContextMaterialStoreError::InvalidProjectRoot)?;
        if !project_root.is_dir() {
            return Err(ContextMaterialStoreError::InvalidProjectRoot);
        }
        let private_root = project_root.join(".hartevo");
        ensure_directory_without_symlink(&private_root)?;
        let requested_cas_root = private_root.join("context-material");
        ensure_directory_without_symlink(&requested_cas_root)?;
        let cas_root = requested_cas_root
            .canonicalize()
            .map_err(|_| ContextMaterialStoreError::InvalidProjectRoot)?;
        if !cas_root.starts_with(&project_root) {
            return Err(ContextMaterialStoreError::UnsafePath);
        }
        let keys = BTreeMap::from([(active_key_version, active_key)]);
        Ok(Self {
            tenant_id,
            project_id,
            project_root,
            cas_root,
            active_key_version,
            keys,
        })
    }

    pub fn add_decryption_key(
        &mut self,
        key_version: u64,
        key: KeyMaterial,
    ) -> Result<(), ContextMaterialStoreError> {
        if key_version == 0 || self.keys.contains_key(&key_version) {
            return Err(ContextMaterialStoreError::InvalidKeyVersion);
        }
        self.keys.insert(key_version, key);
        Ok(())
    }

    /// Returns the already-canonicalized project root to process-local
    /// orchestrators. Debug implementations must continue to redact it.
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    pub fn put_text(
        &self,
        text: &str,
    ) -> Result<ContextMaterialDescriptor, ContextMaterialStoreError> {
        if text.is_empty() {
            return Err(ContextMaterialStoreError::EmptyMaterial);
        }
        if text.len() > MAX_MATERIAL_BYTES {
            return Err(ContextMaterialStoreError::MaterialTooLarge);
        }
        let content_digest = sha256(text.as_bytes());
        let mut descriptor = ContextMaterialDescriptor {
            storage_ref: format!("cas://{content_digest}"),
            content_digest: content_digest.clone(),
            byte_len: u64::try_from(text.len())
                .map_err(|_| ContextMaterialStoreError::MaterialTooLarge)?,
            key_version: self.active_key_version,
        };
        let final_path = self.record_path(&content_digest)?;
        if final_path.exists() {
            descriptor.key_version = self.validate_existing(&descriptor)?;
            return Ok(descriptor);
        }
        let key = self
            .keys
            .get(&self.active_key_version)
            .ok_or(ContextMaterialStoreError::MissingKeyVersion)?;
        let encrypted = ContentCrypto::seal(
            text.as_bytes(),
            key,
            &self.encryption_context(&content_digest, self.active_key_version),
        )?;
        let record = StoredContextMaterial::from_encrypted(
            self.tenant_id.clone(),
            self.project_id.clone(),
            content_digest,
            descriptor.byte_len,
            self.active_key_version,
            encrypted,
        );
        let encoded = serde_json::to_vec(&record)?;
        if u64::try_from(encoded.len()).map_or(true, |length| length > MAX_RECORD_BYTES) {
            return Err(ContextMaterialStoreError::MaterialTooLarge);
        }
        Self::install_record(&final_path, &encoded)?;
        descriptor.key_version = self.validate_existing(&descriptor)?;
        Ok(descriptor)
    }

    pub fn snapshot_project_file(
        &self,
        relative_path: &Path,
    ) -> Result<ContextMaterialDescriptor, ContextMaterialStoreError> {
        let source_path = self.safe_project_file(relative_path)?;
        let bytes = read_bounded(&source_path, MAX_MATERIAL_BYTES)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ContextMaterialStoreError::MaterialIsNotUtf8)?;
        self.put_text(text)
    }

    pub fn snapshot_query(
        &self,
        snapshot: &ContextQuerySnapshot,
    ) -> Result<ContextMaterialDescriptor, ContextMaterialStoreError> {
        snapshot.validate()?;
        let encoded = serde_json::to_string(snapshot)?;
        self.put_text(&encoded)
    }

    pub fn load_text(
        &self,
        storage_ref: &str,
    ) -> Result<Option<ResolvedContextMaterial>, ContextMaterialStoreError> {
        let digest = parse_storage_ref(storage_ref)?;
        let path = self.record_path(digest)?;
        if !path.exists() {
            return Ok(None);
        }
        let record = Self::read_record(&path)?;
        self.validate_record(&record, digest)?;
        let key = self
            .keys
            .get(&record.key_version)
            .ok_or(ContextMaterialStoreError::MissingKeyVersion)?;
        let opened = ContentCrypto::open(
            &record.encrypted()?,
            key,
            &self.encryption_context(digest, record.key_version),
        )?;
        let plaintext = std::str::from_utf8(opened.as_slice())
            .map_err(|_| ContextMaterialStoreError::CorruptRecord)?;
        if plaintext.is_empty()
            || plaintext.len() != usize::try_from(record.plaintext_byte_len).unwrap_or(usize::MAX)
            || sha256(plaintext.as_bytes()) != digest
        {
            return Err(ContextMaterialStoreError::CorruptRecord);
        }
        Ok(Some(ResolvedContextMaterial::text(plaintext)))
    }

    fn encryption_context(&self, digest: &str, key_version: u64) -> ContentEncryptionContext {
        ContentEncryptionContext {
            cell: "local".into(),
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            object_id: digest.into(),
            object_kind: MATERIAL_OBJECT_KIND.into(),
            object_revision: 1,
            key_version,
            tombstone: false,
        }
    }

    fn record_path(&self, digest: &str) -> Result<PathBuf, ContextMaterialStoreError> {
        if !is_sha256(digest) {
            return Err(ContextMaterialStoreError::InvalidStorageReference);
        }
        let directory = self.cas_root.join(&digest[..2]);
        ensure_directory_without_symlink(&directory)?;
        let canonical_directory = directory
            .canonicalize()
            .map_err(|_| ContextMaterialStoreError::UnsafePath)?;
        if !canonical_directory.starts_with(&self.cas_root) {
            return Err(ContextMaterialStoreError::UnsafePath);
        }
        let path = canonical_directory.join(format!("{digest}.hctx"));
        if let Ok(metadata) = fs::symlink_metadata(&path)
            && (metadata.file_type().is_symlink() || !metadata.is_file())
        {
            return Err(ContextMaterialStoreError::UnsafePath);
        }
        Ok(path)
    }

    fn safe_project_file(
        &self,
        relative_path: &Path,
    ) -> Result<PathBuf, ContextMaterialStoreError> {
        if relative_path.as_os_str().is_empty() || relative_path.is_absolute() {
            return Err(ContextMaterialStoreError::UnsafePath);
        }
        let mut candidate = self.project_root.clone();
        for component in relative_path.components() {
            let Component::Normal(value) = component else {
                return Err(ContextMaterialStoreError::UnsafePath);
            };
            if value == ".hartevo" {
                return Err(ContextMaterialStoreError::UnsafePath);
            }
            candidate.push(value);
            let metadata = fs::symlink_metadata(&candidate)
                .map_err(|_| ContextMaterialStoreError::UnreadableMaterial)?;
            if metadata.file_type().is_symlink() {
                return Err(ContextMaterialStoreError::UnsafePath);
            }
        }
        let canonical = candidate
            .canonicalize()
            .map_err(|_| ContextMaterialStoreError::UnreadableMaterial)?;
        if !canonical.starts_with(&self.project_root) || !canonical.is_file() {
            return Err(ContextMaterialStoreError::UnsafePath);
        }
        Ok(canonical)
    }

    fn install_record(final_path: &Path, encoded: &[u8]) -> Result<(), ContextMaterialStoreError> {
        let parent = final_path
            .parent()
            .ok_or(ContextMaterialStoreError::UnsafePath)?;
        let mut nonce = [0_u8; TEMP_NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ContextMaterialStoreError::RandomnessUnavailable)?;
        let temporary_path = parent.join(format!(".{}.tmp", hex::encode(nonce)));
        let mut temporary = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary_path)
            .map_err(ContextMaterialStoreError::Io)?;
        let result = (|| {
            temporary
                .write_all(encoded)
                .map_err(ContextMaterialStoreError::Io)?;
            temporary
                .sync_all()
                .map_err(ContextMaterialStoreError::Io)?;
            match fs::hard_link(&temporary_path, final_path) {
                Ok(()) => sync_directory(parent)?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(ContextMaterialStoreError::Io(error)),
            }
            Ok(())
        })();
        drop(temporary);
        let cleanup_result = fs::remove_file(&temporary_path);
        if let Err(error) = cleanup_result
            && error.kind() != io::ErrorKind::NotFound
            && result.is_ok()
        {
            return Err(ContextMaterialStoreError::Io(error));
        }
        result
    }

    fn validate_existing(
        &self,
        descriptor: &ContextMaterialDescriptor,
    ) -> Result<u64, ContextMaterialStoreError> {
        let path = self.record_path(&descriptor.content_digest)?;
        let record = Self::read_record(&path)?;
        self.validate_record(&record, &descriptor.content_digest)?;
        if record.plaintext_byte_len != descriptor.byte_len {
            return Err(ContextMaterialStoreError::CorruptRecord);
        }
        let resolved = self
            .load_text(&descriptor.storage_ref)?
            .ok_or(ContextMaterialStoreError::CorruptRecord)?;
        if u64::try_from(resolved.as_str().len()).ok() != Some(descriptor.byte_len) {
            return Err(ContextMaterialStoreError::CorruptRecord);
        }
        Ok(record.key_version)
    }

    fn read_record(path: &Path) -> Result<StoredContextMaterial, ContextMaterialStoreError> {
        let metadata = fs::symlink_metadata(path).map_err(ContextMaterialStoreError::Io)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_RECORD_BYTES
        {
            return Err(ContextMaterialStoreError::CorruptRecord);
        }
        let bytes = read_bounded_u64(path, MAX_RECORD_BYTES)?;
        serde_json::from_slice(&bytes).map_err(|_| ContextMaterialStoreError::CorruptRecord)
    }

    fn validate_record(
        &self,
        record: &StoredContextMaterial,
        requested_digest: &str,
    ) -> Result<(), ContextMaterialStoreError> {
        if record.schema_version != MATERIAL_SCHEMA_VERSION
            || record.tenant_id != self.tenant_id
            || record.project_id != self.project_id
            || record.plaintext_digest != requested_digest
            || !is_sha256(&record.plaintext_digest)
            || record.plaintext_byte_len == 0
            || record.plaintext_byte_len
                > u64::try_from(MAX_MATERIAL_BYTES)
                    .map_err(|_| ContextMaterialStoreError::CorruptRecord)?
            || record.key_version == 0
            || !is_sha256(&record.aad_digest)
            || !is_sha256(&record.ciphertext_digest)
        {
            return Err(ContextMaterialStoreError::RecordScopeMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for LocalEncryptedContextMaterialStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalEncryptedContextMaterialStore")
            .field(
                "tenant_scope_digest",
                &sha256(self.tenant_id.as_str().as_bytes()),
            )
            .field(
                "project_scope_digest",
                &sha256(self.project_id.as_str().as_bytes()),
            )
            .field(
                "project_root_digest",
                &sha256(self.project_root.as_os_str().as_encoded_bytes()),
            )
            .field(
                "cas_root_digest",
                &sha256(self.cas_root.as_os_str().as_encoded_bytes()),
            )
            .field("active_key_version", &self.active_key_version)
            .field("available_key_versions", &self.keys.keys())
            .finish()
    }
}

impl ContextMaterialResolver for LocalEncryptedContextMaterialStore {
    fn resolve(
        &self,
        reference: &ContextMaterialReference,
    ) -> Result<Option<ResolvedContextMaterial>, ContextAssemblyError> {
        self.load_text(&reference.storage_ref)
            .map_err(|_| ContextAssemblyError::ResolverFailure)
    }
}

#[derive(Debug, Error)]
pub enum ContextMaterialStoreError {
    #[error("context material tenant, project, or key scope is invalid")]
    InvalidScope,
    #[error("context material project root is invalid")]
    InvalidProjectRoot,
    #[error("context material path escapes or aliases the project boundary")]
    UnsafePath,
    #[error("context material reference must be a lowercase SHA-256 CAS reference")]
    InvalidStorageReference,
    #[error("context material is empty")]
    EmptyMaterial,
    #[error("context material exceeds the local encrypted CAS limit")]
    MaterialTooLarge,
    #[error("context material cannot be read")]
    UnreadableMaterial,
    #[error("context material must be UTF-8 text")]
    MaterialIsNotUtf8,
    #[error("context query snapshot metadata is invalid")]
    InvalidQuerySnapshot,
    #[error("context material key version is invalid")]
    InvalidKeyVersion,
    #[error("context material decryption key is unavailable")]
    MissingKeyVersion,
    #[error("context material record is corrupt")]
    CorruptRecord,
    #[error("context material record does not match its tenant or project scope")]
    RecordScopeMismatch,
    #[error("context material randomness is unavailable")]
    RandomnessUnavailable,
    #[error("context material filesystem operation failed")]
    Io(#[source] io::Error),
    #[error("context material serialization failed")]
    Json(#[source] serde_json::Error),
    #[error("context material encryption failed")]
    Crypto(#[source] crate::SecretStoreError),
}

impl From<serde_json::Error> for ContextMaterialStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<crate::SecretStoreError> for ContextMaterialStoreError {
    fn from(error: crate::SecretStoreError) -> Self {
        Self::Crypto(error)
    }
}

fn parse_storage_ref(storage_ref: &str) -> Result<&str, ContextMaterialStoreError> {
    let digest = storage_ref
        .strip_prefix("cas://")
        .ok_or(ContextMaterialStoreError::InvalidStorageReference)?;
    if !is_sha256(digest) {
        return Err(ContextMaterialStoreError::InvalidStorageReference);
    }
    Ok(digest)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn ensure_directory_without_symlink(path: &Path) -> Result<(), ContextMaterialStoreError> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(ContextMaterialStoreError::UnsafePath);
    }
    fs::create_dir_all(path).map_err(ContextMaterialStoreError::Io)?;
    let metadata = fs::symlink_metadata(path).map_err(ContextMaterialStoreError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ContextMaterialStoreError::UnsafePath);
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, ContextMaterialStoreError> {
    read_bounded_u64(
        path,
        u64::try_from(maximum).map_err(|_| ContextMaterialStoreError::MaterialTooLarge)?,
    )
}

fn read_bounded_u64(path: &Path, maximum: u64) -> Result<Vec<u8>, ContextMaterialStoreError> {
    let file = File::open(path).map_err(ContextMaterialStoreError::Io)?;
    let metadata = file.metadata().map_err(ContextMaterialStoreError::Io)?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(ContextMaterialStoreError::MaterialTooLarge);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| ContextMaterialStoreError::MaterialTooLarge)?,
    );
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(ContextMaterialStoreError::Io)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        return Err(ContextMaterialStoreError::MaterialTooLarge);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ContextMaterialStoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(ContextMaterialStoreError::Io)
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), ContextMaterialStoreError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use chrono::TimeZone;
    use hartevo_context_fabric::{
        ContextFrameRequirement, ContextFrameSource, ContextMaterialResolver,
    };
    use hartevo_domain_kernel::ContextDataClass;
    use serde_json::json;

    use super::*;

    const PRIVATE_TEXT: &str =
        "PRIVATE-CONTEXT-MATERIAL::only the exact verified revision may be resolved";

    fn key(fill: u8) -> KeyMaterial {
        KeyMaterial::from_bytes([fill; 32]).expect("non-zero project key")
    }

    fn store(
        root: &Path,
        key_version: u64,
        project_key: KeyMaterial,
    ) -> LocalEncryptedContextMaterialStore {
        LocalEncryptedContextMaterialStore::new(
            root,
            TenantId::from("tenant-context-material"),
            ProjectId::from("project-context-material"),
            key_version,
            project_key,
        )
        .expect("encrypted context material store")
    }

    #[test]
    fn encrypted_cas_is_idempotent_resolvable_and_content_free_at_rest() {
        let project = tempfile::tempdir().expect("project root");
        let store = store(project.path(), 4, key(7));

        let first = store.put_text(PRIVATE_TEXT).expect("first CAS write");
        let replay = store.put_text(PRIVATE_TEXT).expect("idempotent CAS write");
        assert_eq!(first, replay);
        assert_eq!(first.content_digest, sha256(PRIVATE_TEXT.as_bytes()));
        assert_eq!(first.storage_ref, format!("cas://{}", first.content_digest));
        assert_eq!(first.key_version, 4);

        let resolved = store
            .load_text(&first.storage_ref)
            .expect("CAS read")
            .expect("material exists");
        assert_eq!(resolved.as_str(), PRIVATE_TEXT);

        let record_path = store
            .record_path(&first.content_digest)
            .expect("record path");
        let record_bytes = fs::read(record_path).expect("encrypted record");
        assert!(
            !record_bytes
                .windows(PRIVATE_TEXT.len())
                .any(|window| window == PRIVATE_TEXT.as_bytes())
        );
        let debug = format!("{store:?}");
        assert!(!debug.contains(PRIVATE_TEXT));
        assert!(!debug.contains(&project.path().display().to_string()));
        assert!(!debug.contains("07070707"));
    }

    #[test]
    fn project_file_query_snapshot_and_previous_key_resolve_through_one_cas() {
        let project = tempfile::tempdir().expect("project root");
        fs::create_dir_all(project.path().join("inputs")).expect("input directory");
        fs::write(project.path().join("inputs/brief.md"), PRIVATE_TEXT).expect("project file");

        let first_store = store(project.path(), 1, key(7));
        let file = first_store
            .snapshot_project_file(Path::new("inputs/brief.md"))
            .expect("file snapshot");
        assert_eq!(file.content_digest, sha256(PRIVATE_TEXT.as_bytes()));

        let query = ContextQuerySnapshot {
            provider: "provider-simulator".into(),
            query_digest: "1".repeat(64),
            schema_digest: "2".repeat(64),
            observed_at: Utc
                .with_ymd_and_hms(2026, 8, 11, 12, 0, 0)
                .single()
                .expect("timestamp"),
            payload: json!({
                "rows": [{"id": "row-1", "score": 7}],
                "nextCursor": null
            }),
        };
        let query_descriptor = first_store.snapshot_query(&query).expect("query snapshot");
        assert_ne!(query_descriptor.content_digest, file.content_digest);

        drop(first_store);
        let mut rotated = store(project.path(), 2, key(8));
        assert!(matches!(
            rotated.load_text(&file.storage_ref),
            Err(ContextMaterialStoreError::MissingKeyVersion)
        ));
        rotated
            .add_decryption_key(1, key(7))
            .expect("previous decryption key");
        let replay = rotated
            .put_text(PRIVATE_TEXT)
            .expect("content-addressed replay after rotation");
        assert_eq!(
            replay.key_version, 1,
            "an immutable v1 object must not be mislabeled as newly encrypted with v2"
        );
        assert_eq!(
            rotated
                .load_text(&file.storage_ref)
                .expect("old material read")
                .expect("old material exists")
                .as_str(),
            PRIVATE_TEXT
        );

        let query_text = rotated
            .load_text(&query_descriptor.storage_ref)
            .expect("query read")
            .expect("query exists");
        let loaded_query: ContextQuerySnapshot =
            serde_json::from_str(query_text.as_str()).expect("typed query snapshot");
        assert_eq!(loaded_query, query);

        let resolved = ContextMaterialResolver::resolve(
            &rotated,
            &ContextMaterialReference {
                source: ContextFrameSource::QuerySnapshot,
                source_id: "query-1".into(),
                storage_ref: query_descriptor.storage_ref,
                expected_digest: query_descriptor.content_digest,
                declared_max_bytes: Some(query_descriptor.byte_len),
                classification: ContextDataClass::Business,
                requirement: ContextFrameRequirement::Required,
                expired: false,
            },
        )
        .expect("context resolver")
        .expect("resolved query");
        assert_eq!(resolved.as_str(), query_text.as_str());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_scope_mismatch_and_ciphertext_tamper_fail_closed() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().expect("project root");
        let outside = tempfile::tempdir().expect("outside root");
        fs::write(outside.path().join("secret.txt"), "outside-secret").expect("outside file");
        symlink(outside.path(), project.path().join("escape")).expect("escape symlink");

        let store = store(project.path(), 1, key(7));
        assert!(matches!(
            store.snapshot_project_file(Path::new("escape/secret.txt")),
            Err(ContextMaterialStoreError::UnsafePath)
        ));
        assert!(matches!(
            store.snapshot_project_file(Path::new("../secret.txt")),
            Err(ContextMaterialStoreError::UnsafePath)
        ));

        let descriptor = store.put_text(PRIVATE_TEXT).expect("encrypted record");
        let wrong_scope = LocalEncryptedContextMaterialStore::new(
            project.path(),
            TenantId::from("tenant-context-material"),
            ProjectId::from("other-project"),
            1,
            key(7),
        )
        .expect("wrong-scope reader");
        assert!(matches!(
            wrong_scope.load_text(&descriptor.storage_ref),
            Err(ContextMaterialStoreError::RecordScopeMismatch)
        ));

        let path = store
            .record_path(&descriptor.content_digest)
            .expect("record path");
        let mut record: Value =
            serde_json::from_slice(&fs::read(&path).expect("record")).expect("record JSON");
        let ciphertext = record["ciphertextHex"]
            .as_str()
            .expect("ciphertext")
            .to_owned();
        let replacement = if ciphertext.starts_with('0') {
            '1'
        } else {
            '0'
        };
        record["ciphertextHex"] = format!("{replacement}{}", &ciphertext[1..]).into();
        fs::write(&path, serde_json::to_vec(&record).expect("tampered JSON"))
            .expect("tamper record");
        assert!(matches!(
            store.load_text(&descriptor.storage_ref),
            Err(ContextMaterialStoreError::Crypto(_) | ContextMaterialStoreError::CorruptRecord)
        ));

        assert!(matches!(
            ContextMaterialResolver::resolve(
                &store,
                &ContextMaterialReference {
                    source: ContextFrameSource::FileSnapshot,
                    source_id: "file-1".into(),
                    storage_ref: descriptor.storage_ref,
                    expected_digest: descriptor.content_digest,
                    declared_max_bytes: None,
                    classification: ContextDataClass::RedactedPersonal,
                    requirement: ContextFrameRequirement::Required,
                    expired: false,
                },
            ),
            Err(ContextAssemblyError::ResolverFailure)
        ));

        let symlink_project = tempfile::tempdir().expect("symlink project");
        symlink(outside.path(), symlink_project.path().join(".hartevo"))
            .expect("private root symlink");
        assert!(matches!(
            LocalEncryptedContextMaterialStore::new(
                symlink_project.path(),
                TenantId::from("tenant-context-material"),
                ProjectId::from("project-context-material"),
                1,
                key(7),
            ),
            Err(ContextMaterialStoreError::UnsafePath)
        ));
    }
}
