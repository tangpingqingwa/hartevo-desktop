//! SQLCipher event metadata plus private-record payload persistence for the
//! Mission memory plugin.  Candidate bodies never enter `domain_events`.

use std::sync::Arc;

use chrono::Utc;
use hartevo_domain_kernel::{MissionId, ProjectId, TenantId};
use hartevo_memory_runtime::{
    MemoryEventKind, MemoryLifecycleEvent, MemoryPayload, MemoryPersistence, MemoryPluginBinding,
    MemoryPolicy, MemoryRuntimeError,
};
use rusqlite::params;
use serde_json::Value;

use crate::{
    LocalEncryptedContextMaterialStore, ProjectStore, SecretBytes, SecretReference, SecretStore,
    SecretStoreError,
};

const MEMORY_EVENT_TYPE: &str = "memory.candidate.lifecycle.v1";
const MEMORY_PROVIDER: &str = "hartevo-memory-runtime";
const MEMORY_PURPOSE: &str = "candidate-payload";

/// A narrow adapter that keeps lifecycle metadata in the SQLCipher event
/// spine and candidate bodies behind the existing SecretStore boundary.
#[derive(Debug)]
pub struct SqlCipherMemoryPersistence<S> {
    project_store: ProjectStore,
    secret_store: S,
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
}

impl<S> SqlCipherMemoryPersistence<S>
where
    S: SecretStore,
{
    pub fn new(
        project_store: ProjectStore,
        secret_store: S,
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
    ) -> Self {
        Self {
            project_store,
            secret_store,
            tenant_id,
            project_id,
            mission_id,
        }
    }

    pub fn into_project_store(self) -> ProjectStore {
        self.project_store
    }

    fn secret_reference(
        &self,
        event: &MemoryLifecycleEvent,
    ) -> Result<SecretReference, MemoryRuntimeError> {
        if event.project_id().as_str() != self.project_id.as_str()
            || event.source_mission_id().as_str() != self.mission_id.as_str()
            || event.kind() != MemoryEventKind::Proposed
        {
            return Err(MemoryRuntimeError::ScopeMismatch);
        }
        Ok(SecretReference {
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            provider: MEMORY_PROVIDER.into(),
            account_scope: format!(
                "candidate:{}:{}",
                event.candidate_id().as_str(),
                event.content_digest().as_str()
            ),
            purpose: MEMORY_PURPOSE.into(),
            version: event.plugin().generation(),
        })
    }

    fn decode_metadata(payload: Value) -> Result<MemoryLifecycleEvent, MemoryRuntimeError> {
        serde_json::from_value(payload).map_err(|_| MemoryRuntimeError::PersistenceFailure)
    }

    fn existing_event(&self, candidate: &MemoryLifecycleEvent) -> Result<bool, MemoryRuntimeError> {
        let events = self
            .project_store
            .events_for_mission(&self.project_id, &self.mission_id)
            .map_err(|_| MemoryRuntimeError::PersistenceFailure)?;
        let expected = serde_json::to_value(candidate.redacted_for_persistence())
            .map_err(|_| MemoryRuntimeError::PersistenceFailure)?;
        Ok(events.iter().any(|event| {
            event.event_type == MEMORY_EVENT_TYPE
                && event
                    .payload
                    .as_object()
                    .and_then(|_| Self::decode_metadata(event.payload.clone()).ok())
                    .is_some_and(|stored| {
                        stored.sequence() == candidate.sequence()
                            && serde_json::to_value(stored).ok() == Some(expected.clone())
                    })
        }))
    }

    fn prepare_events(
        &self,
        binding: &MemoryPluginBinding,
        policy: &MemoryPolicy,
        events: &[MemoryLifecycleEvent],
    ) -> Result<Vec<(Value, Option<SecretReference>)>, MemoryRuntimeError> {
        let persisted_count = self
            .project_store
            .events_for_mission(&self.project_id, &self.mission_id)
            .map_err(|_| MemoryRuntimeError::PersistenceFailure)?
            .into_iter()
            .filter(|event| event.event_type == MEMORY_EVENT_TYPE)
            .count();
        let mut next_sequence = u64::try_from(persisted_count)
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or(MemoryRuntimeError::InvalidHistory)?;
        let mut pending = Vec::new();
        for event in events {
            event.validate_for_persistence()?;
            if event.project_id().as_str() != self.project_id.as_str()
                || event.source_mission_id().as_str() != self.mission_id.as_str()
                || event.plugin() != binding
                || event.policy() != policy
            {
                return Err(MemoryRuntimeError::PluginMismatch);
            }
            let metadata = event.redacted_for_persistence();
            let metadata_json = serde_json::to_value(&metadata)
                .map_err(|_| MemoryRuntimeError::PersistenceFailure)?;
            if self.existing_event(event)? {
                if event.kind() == MemoryEventKind::Proposed {
                    let payload = event.payload().ok_or(MemoryRuntimeError::InvalidHistory)?;
                    let reference = self.secret_reference(event)?;
                    let bytes = self
                        .secret_store
                        .get(&reference)
                        .map_err(|_| MemoryRuntimeError::PersistenceFailure)?;
                    let stored = std::str::from_utf8(bytes.as_slice())
                        .map_err(|_| MemoryRuntimeError::InvalidHistory)?;
                    if stored != payload.as_str() {
                        return Err(MemoryRuntimeError::InvalidHistory);
                    }
                }
                continue;
            }
            if event.sequence() != next_sequence {
                return Err(MemoryRuntimeError::InvalidHistory);
            }
            let reference = if event.kind() == MemoryEventKind::Proposed {
                let payload = event.payload().ok_or(MemoryRuntimeError::InvalidHistory)?;
                if payload.is_secret() {
                    return Err(MemoryRuntimeError::InvalidPayload);
                }
                let reference = self.secret_reference(event)?;
                let bytes = SecretBytes::new(payload.as_str().as_bytes().to_vec())
                    .map_err(|_| MemoryRuntimeError::PersistenceFailure)?;
                self.secret_store
                    .put(&reference, &bytes)
                    .map_err(|_| MemoryRuntimeError::PersistenceFailure)?;
                Some(reference)
            } else {
                None
            };
            pending.push((metadata_json, reference));
            next_sequence = next_sequence
                .checked_add(1)
                .ok_or(MemoryRuntimeError::InvalidHistory)?;
        }
        Ok(pending)
    }
}

/// File-backed private-record provider used by the production local boundary
/// and deterministic restart tests.  The existing encrypted CAS owns the
/// ciphertext; this adapter only binds a candidate SecretReference to its
/// authenticated content digest.
#[derive(Debug)]
pub struct FileMemoryPrivateRecordStore {
    store: LocalEncryptedContextMaterialStore,
}

impl FileMemoryPrivateRecordStore {
    pub fn new(store: LocalEncryptedContextMaterialStore) -> Self {
        Self { store }
    }

    fn digest(reference: &SecretReference) -> Result<&str, SecretStoreError> {
        reference
            .account_scope
            .rsplit_once(':')
            .map(|(_, digest)| digest)
            .filter(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .ok_or(SecretStoreError::InvalidReference)
    }
}

impl SecretStore for FileMemoryPrivateRecordStore {
    fn put(
        &self,
        reference: &SecretReference,
        secret: &SecretBytes,
    ) -> Result<(), SecretStoreError> {
        let digest = Self::digest(reference)?;
        let descriptor = self
            .store
            .put_text(
                std::str::from_utf8(secret.as_slice())
                    .map_err(|_| SecretStoreError::InvalidSecret)?,
            )
            .map_err(|_| SecretStoreError::BackendUnavailable)?;
        if descriptor.content_digest != digest {
            return Err(SecretStoreError::EnvelopeScopeMismatch);
        }
        Ok(())
    }

    fn get(&self, reference: &SecretReference) -> Result<SecretBytes, SecretStoreError> {
        let digest = Self::digest(reference)?;
        let material = self
            .store
            .load_text(&format!("cas://{digest}"))
            .map_err(|_| SecretStoreError::BackendUnavailable)?
            .ok_or(SecretStoreError::SecretNotFound)?;
        SecretBytes::new(material.as_str().as_bytes().to_vec())
    }

    fn delete(&self, _reference: &SecretReference) -> Result<(), SecretStoreError> {
        // Forget/revoke are represented by durable tombstones.  Keeping the
        // encrypted CAS is intentional: replay can authenticate the complete
        // history while lifecycle state prevents any query of the body.
        Ok(())
    }
}

impl<S> MemoryPersistence for SqlCipherMemoryPersistence<S>
where
    S: SecretStore,
{
    fn load_events(
        &self,
        _binding: &MemoryPluginBinding,
        _policy: &MemoryPolicy,
    ) -> Result<Vec<MemoryLifecycleEvent>, MemoryRuntimeError> {
        let rows = self
            .project_store
            .events_for_mission(&self.project_id, &self.mission_id)
            .map_err(|_| MemoryRuntimeError::PersistenceFailure)?;
        let mut events = Vec::new();
        for row in rows
            .into_iter()
            .filter(|row| row.event_type == MEMORY_EVENT_TYPE)
        {
            let event = Self::decode_metadata(row.payload)?;
            if event.project_id().as_str() != self.project_id.as_str()
                || event.source_mission_id().as_str() != self.mission_id.as_str()
            {
                return Err(MemoryRuntimeError::ScopeMismatch);
            }
            if event.kind() == MemoryEventKind::Proposed {
                if event.payload().is_some() {
                    return Err(MemoryRuntimeError::InvalidHistory);
                }
                let reference = self.secret_reference(&event)?;
                let bytes = self
                    .secret_store
                    .get(&reference)
                    .map_err(|_| MemoryRuntimeError::PersistenceFailure)?;
                let text = std::str::from_utf8(bytes.as_slice())
                    .map_err(|_| MemoryRuntimeError::InvalidHistory)?;
                let payload =
                    MemoryPayload::public(text).map_err(|_| MemoryRuntimeError::InvalidHistory)?;
                let event = event.with_persisted_payload(payload)?;
                events.push(event);
            } else {
                if event.payload().is_some() {
                    return Err(MemoryRuntimeError::InvalidHistory);
                }
                events.push(event);
            }
        }
        events.sort_by_key(MemoryLifecycleEvent::sequence);
        Ok(events)
    }

    fn append_events(
        &mut self,
        binding: &MemoryPluginBinding,
        policy: &MemoryPolicy,
        events: &[MemoryLifecycleEvent],
    ) -> Result<(), MemoryRuntimeError> {
        let pending = self.prepare_events(binding, policy, events)?;
        if pending.is_empty() {
            return Ok(());
        }

        let project = self
            .project_store
            .load_project(&self.project_id)
            .map_err(|_| MemoryRuntimeError::PersistenceFailure)?;
        self.project_store
            .load_mission(&self.project_id, &self.mission_id)
            .map_err(|_| MemoryRuntimeError::PersistenceFailure)?;
        let transaction = self
            .project_store
            .connection
            .transaction()
            .map_err(|_| MemoryRuntimeError::PersistenceFailure)?;
        let recorded_at = Utc::now().to_rfc3339();
        for (metadata_json, _) in &pending {
            let payload_json = serde_json::to_string(metadata_json)
                .map_err(|_| MemoryRuntimeError::PersistenceFailure)?;
            transaction
                .execute(
                    "INSERT INTO domain_events
                       (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        project.tenant_id.as_str(),
                        self.project_id.as_str(),
                        self.mission_id.as_str(),
                        MEMORY_EVENT_TYPE,
                        payload_json,
                        recorded_at,
                    ],
                )
                .map_err(|_| MemoryRuntimeError::PersistenceFailure)?;
        }
        transaction
            .commit()
            .map_err(|_| MemoryRuntimeError::PersistenceFailure)?;
        Ok(())
    }
}

impl<T> SecretStore for Arc<T>
where
    T: SecretStore + ?Sized,
{
    fn put(
        &self,
        reference: &SecretReference,
        secret: &SecretBytes,
    ) -> Result<(), crate::SecretStoreError> {
        (**self).put(reference, secret)
    }

    fn get(&self, reference: &SecretReference) -> Result<SecretBytes, crate::SecretStoreError> {
        (**self).get(reference)
    }

    fn delete(&self, reference: &SecretReference) -> Result<(), crate::SecretStoreError> {
        (**self).delete(reference)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use chrono::Utc;
    use hartevo_domain_kernel::{Mission, MissionContract, StorageMode};
    use hartevo_memory_runtime::{
        MemoryApplicability, MemoryCandidateClass, MemoryCandidateDraft, MemoryCandidateService,
        MemoryConsent, MemoryPluginBinding, MemoryPolicy, MemorySourceEvent, MemorySourceKind,
    };
    use hartevo_plugin_runtime::{
        Digest, MissionId as PluginMissionId, PluginRuntime, PluginScope, PluginVersion,
        ProjectId as PluginProjectId, sample::SampleReadOnlyPlugin,
    };
    use tempfile::tempdir;

    use super::*;
    use crate::{DatabaseKey, KeyMaterial, PendingEvent, ProjectStore};

    #[derive(Debug)]
    struct FailAfterPrivatePut {
        inner: FileMemoryPrivateRecordStore,
    }

    impl SecretStore for FailAfterPrivatePut {
        fn put(
            &self,
            reference: &SecretReference,
            secret: &SecretBytes,
        ) -> Result<(), SecretStoreError> {
            self.inner.put(reference, secret)?;
            Err(SecretStoreError::BackendUnavailable)
        }

        fn get(&self, reference: &SecretReference) -> Result<SecretBytes, SecretStoreError> {
            self.inner.get(reference)
        }

        fn delete(&self, reference: &SecretReference) -> Result<(), SecretStoreError> {
            self.inner.delete(reference)
        }
    }

    fn binding() -> (PluginScope, MemoryPluginBinding, MemoryPolicy) {
        binding_with_version(PluginVersion::new(1, 0, 0))
    }

    fn binding_with_version(
        version: PluginVersion,
    ) -> (PluginScope, MemoryPluginBinding, MemoryPolicy) {
        let scope = PluginScope::new(
            PluginProjectId::new("memory-project").expect("plugin project"),
            PluginMissionId::new("memory-mission").expect("plugin mission"),
            7,
        )
        .expect("plugin scope");
        let definition =
            SampleReadOnlyPlugin::definition(scope.clone(), version).expect("definition");
        let mut runtime = PluginRuntime::new();
        let handle = runtime.define(definition).expect("handle");
        let binding = MemoryPluginBinding::from_handle(&handle);
        let policy =
            MemoryPolicy::explicit_only(1, Digest::from_text("memory-policy")).expect("policy");
        (scope, binding, policy)
    }

    fn open_store(
        database: &Path,
        key: &DatabaseKey,
        project_root: &Path,
    ) -> (ProjectStore, LocalEncryptedContextMaterialStore) {
        let store = if database.exists() {
            ProjectStore::open(database, key).expect("reopen project store")
        } else {
            let mut store = ProjectStore::open(database, key).expect("project store");
            let project = hartevo_domain_kernel::Project::create_local(
                hartevo_domain_kernel::TenantId::from("memory-tenant"),
                hartevo_domain_kernel::ProjectId::from("memory-project"),
                "Memory project",
                "",
                project_root,
                StorageMode::LocalExisting,
            )
            .expect("project");
            store.save_project(&project).expect("save project");
            let now = Utc::now();
            let mission = Mission::compile(
                project.tenant_id.clone(),
                hartevo_domain_kernel::MissionId::from("memory-mission"),
                project.id.clone(),
                "Memory mission",
                MissionContract::bootstrap("Review memory", [], now),
                now,
            )
            .expect("mission");
            store
                .create_mission_atomic(
                    &mission,
                    &[PendingEvent::new(
                        "mission.created",
                        serde_json::json!({}),
                        now,
                    )],
                )
                .expect("save mission");
            store
        };
        let private = LocalEncryptedContextMaterialStore::new(
            project_root,
            hartevo_domain_kernel::TenantId::from("memory-tenant"),
            hartevo_domain_kernel::ProjectId::from("memory-project"),
            1,
            KeyMaterial::from_bytes([9; 32]).expect("key"),
        )
        .expect("private records");
        (store, private)
    }

    fn source_and_draft() -> (MemorySourceEvent, MemoryCandidateDraft) {
        (
            MemorySourceEvent::new(
                PluginProjectId::new("memory-project").expect("plugin project"),
                PluginMissionId::new("memory-mission").expect("plugin mission"),
                Digest::from_text("source-event"),
                4,
                MemorySourceKind::Conversation,
                Digest::from_text("source-content"),
                true,
            )
            .expect("source"),
            MemoryCandidateDraft::new(
                MemoryCandidateClass::Preference,
                hartevo_memory_runtime::MemoryPayload::public("keep summaries concise")
                    .expect("payload"),
                90,
                MemoryApplicability::Project,
            )
            .expect("draft"),
        )
    }

    #[test]
    fn sqlcipher_metadata_and_encrypted_private_record_survive_restart() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("memory.sqlite3");
        let key = DatabaseKey::new([3; 32]).expect("database key");
        let (store, private) = open_store(&database, &key, directory.path());
        let (scope, binding, policy) = binding();
        let adapter = SqlCipherMemoryPersistence::new(
            store,
            FileMemoryPrivateRecordStore::new(private),
            hartevo_domain_kernel::TenantId::from("memory-tenant"),
            hartevo_domain_kernel::ProjectId::from("memory-project"),
            hartevo_domain_kernel::MissionId::from("memory-mission"),
        );
        let mut service = MemoryCandidateService::from_persistence(
            scope.clone(),
            binding.clone(),
            policy.clone(),
            Box::new(adapter),
        )
        .expect("fresh persistent service");
        let (source, draft) = source_and_draft();
        let proposed = service.propose(&source, &draft).expect("propose");
        service
            .adopt(
                proposed.candidate_id(),
                source.revision(),
                MemoryConsent::Explicit,
            )
            .expect("adopt");
        let (receipt, recalls) = service
            .query(
                PluginProjectId::new("memory-project").expect("project"),
                PluginMissionId::new("memory-next").expect("mission"),
                7,
            )
            .expect("query")
            .recall()
            .expect("recall");
        assert_eq!(receipt.recalled_count(), 1);
        assert_eq!(recalls[0].payload().as_str(), "keep summaries concise");
        drop(service);

        let reopened_store = ProjectStore::open(&database, &key).expect("restart store");
        let private = LocalEncryptedContextMaterialStore::new(
            directory.path(),
            hartevo_domain_kernel::TenantId::from("memory-tenant"),
            hartevo_domain_kernel::ProjectId::from("memory-project"),
            1,
            KeyMaterial::from_bytes([9; 32]).expect("key"),
        )
        .expect("restart private records");
        let adapter = SqlCipherMemoryPersistence::new(
            reopened_store,
            FileMemoryPrivateRecordStore::new(private),
            hartevo_domain_kernel::TenantId::from("memory-tenant"),
            hartevo_domain_kernel::ProjectId::from("memory-project"),
            hartevo_domain_kernel::MissionId::from("memory-mission"),
        );
        let mut restarted =
            MemoryCandidateService::from_persistence(scope, binding, policy, Box::new(adapter))
                .expect("restart service");
        assert!(matches!(
            restarted.propose(&source, &draft),
            Err(MemoryRuntimeError::DuplicateEvent)
        ));
        let (_, recalls) = restarted
            .query(
                PluginProjectId::new("memory-project").expect("project"),
                PluginMissionId::new("memory-next").expect("mission"),
                7,
            )
            .expect("restart query")
            .recall()
            .expect("restart recall");
        assert_eq!(recalls.len(), 1);
        assert_eq!(recalls[0].payload().as_str(), "keep summaries concise");
        restarted
            .forget(recalls[0].candidate_id())
            .expect("forget tombstone");
        let persisted = ProjectStore::open(&database, &key)
            .expect("content-free inspection")
            .events_for_mission(
                &hartevo_domain_kernel::ProjectId::from("memory-project"),
                &hartevo_domain_kernel::MissionId::from("memory-mission"),
            )
            .expect("persisted memory events");
        assert!(
            persisted
                .iter()
                .filter(|event| event.event_type == MEMORY_EVENT_TYPE)
                .all(|event| event.payload.get("payload").is_some_and(Value::is_null))
        );
    }

    #[test]
    fn crash_after_private_record_before_event_is_not_queryable_after_restart() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("memory.sqlite3");
        let key = DatabaseKey::new([6; 32]).expect("database key");
        let (store, private) = open_store(&database, &key, directory.path());
        let (scope, binding, policy) = binding();
        let adapter = SqlCipherMemoryPersistence::new(
            store,
            FailAfterPrivatePut {
                inner: FileMemoryPrivateRecordStore::new(private),
            },
            hartevo_domain_kernel::TenantId::from("memory-tenant"),
            hartevo_domain_kernel::ProjectId::from("memory-project"),
            hartevo_domain_kernel::MissionId::from("memory-mission"),
        );
        let mut service = MemoryCandidateService::from_persistence(
            scope.clone(),
            binding.clone(),
            policy.clone(),
            Box::new(adapter),
        )
        .expect("service");
        let (source, draft) = source_and_draft();
        assert!(matches!(
            service.propose(&source, &draft),
            Err(MemoryRuntimeError::PersistenceFailure)
        ));
        assert!(service.events().is_empty());
        drop(service);

        let (store, private) = open_store(&database, &key, directory.path());
        let adapter = SqlCipherMemoryPersistence::new(
            store,
            FileMemoryPrivateRecordStore::new(private),
            hartevo_domain_kernel::TenantId::from("memory-tenant"),
            hartevo_domain_kernel::ProjectId::from("memory-project"),
            hartevo_domain_kernel::MissionId::from("memory-mission"),
        );
        let mut restarted =
            MemoryCandidateService::from_persistence(scope, binding, policy, Box::new(adapter))
                .expect("restart service");
        let (_, recalls) = restarted
            .query(
                PluginProjectId::new("memory-project").expect("project"),
                PluginMissionId::new("memory-next").expect("mission"),
                7,
            )
            .expect("query")
            .recall()
            .expect("recall");
        assert!(recalls.is_empty());
        let rows = ProjectStore::open(&database, &key)
            .expect("inspection store")
            .events_for_mission(
                &hartevo_domain_kernel::ProjectId::from("memory-project"),
                &hartevo_domain_kernel::MissionId::from("memory-mission"),
            )
            .expect("rows");
        assert!(!rows.iter().any(|row| row.event_type == MEMORY_EVENT_TYPE));
    }

    #[test]
    fn persisted_plugin_upgrade_and_missing_private_payload_fail_closed() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("memory.sqlite3");
        let key = DatabaseKey::new([4; 32]).expect("database key");
        let (store, private) = open_store(&database, &key, directory.path());
        let (scope, binding, policy) = binding();
        let adapter = SqlCipherMemoryPersistence::new(
            store,
            FileMemoryPrivateRecordStore::new(private),
            hartevo_domain_kernel::TenantId::from("memory-tenant"),
            hartevo_domain_kernel::ProjectId::from("memory-project"),
            hartevo_domain_kernel::MissionId::from("memory-mission"),
        );
        let mut service = MemoryCandidateService::from_persistence(
            scope,
            binding.clone(),
            policy.clone(),
            Box::new(adapter),
        )
        .expect("service");
        let (source, draft) = source_and_draft();
        let proposed = service.propose(&source, &draft).expect("propose");
        drop(service);
        let rows = ProjectStore::open(&database, &key)
            .expect("open")
            .events_for_mission(
                &hartevo_domain_kernel::ProjectId::from("memory-project"),
                &hartevo_domain_kernel::MissionId::from("memory-mission"),
            )
            .expect("rows");
        assert!(
            rows.iter()
                .filter(|row| row.event_type == MEMORY_EVENT_TYPE)
                .all(|row| { row.payload.get("payload").is_some_and(Value::is_null) })
        );

        let (scope_v2, binding_v2, policy_v2) = binding_with_version(PluginVersion::new(2, 0, 0));
        let reopened = ProjectStore::open(&database, &key).expect("upgrade store");
        let private = LocalEncryptedContextMaterialStore::new(
            directory.path(),
            hartevo_domain_kernel::TenantId::from("memory-tenant"),
            hartevo_domain_kernel::ProjectId::from("memory-project"),
            1,
            KeyMaterial::from_bytes([9; 32]).expect("key"),
        )
        .expect("upgrade private records");
        let upgrade = SqlCipherMemoryPersistence::new(
            reopened,
            FileMemoryPrivateRecordStore::new(private),
            hartevo_domain_kernel::TenantId::from("memory-tenant"),
            hartevo_domain_kernel::ProjectId::from("memory-project"),
            hartevo_domain_kernel::MissionId::from("memory-mission"),
        );
        assert!(matches!(
            MemoryCandidateService::from_persistence(
                scope_v2,
                binding_v2,
                policy_v2,
                Box::new(upgrade),
            ),
            Err(hartevo_memory_runtime::MemoryRuntimeError::PluginUpgradeRequiresMigration)
        ));

        let digest = draft.payload().digest().as_str().to_owned();
        let private_path = directory
            .path()
            .join(".hartevo/context-material")
            .join(&digest[..2])
            .join(format!("{digest}.hctx"));
        fs::remove_file(private_path).expect("remove private candidate record");
        let missing_store = ProjectStore::open(&database, &key).expect("missing store");
        let missing_private = LocalEncryptedContextMaterialStore::new(
            directory.path(),
            hartevo_domain_kernel::TenantId::from("memory-tenant"),
            hartevo_domain_kernel::ProjectId::from("memory-project"),
            1,
            KeyMaterial::from_bytes([9; 32]).expect("key"),
        )
        .expect("missing private records");
        let missing = SqlCipherMemoryPersistence::new(
            missing_store,
            FileMemoryPrivateRecordStore::new(missing_private),
            hartevo_domain_kernel::TenantId::from("memory-tenant"),
            hartevo_domain_kernel::ProjectId::from("memory-project"),
            hartevo_domain_kernel::MissionId::from("memory-mission"),
        );
        let (scope_missing, binding_missing, policy_missing) =
            binding_with_version(PluginVersion::new(1, 0, 0));
        assert!(matches!(
            MemoryCandidateService::from_persistence(
                scope_missing,
                binding_missing,
                policy_missing,
                Box::new(missing),
            ),
            Err(hartevo_memory_runtime::MemoryRuntimeError::PersistenceFailure)
        ));

        let _ = proposed;
    }

    #[test]
    fn persisted_revocation_reopens_as_inactive_without_queryable_memory() {
        let directory = tempdir().expect("directory");
        let database = directory.path().join("memory.sqlite3");
        let key = DatabaseKey::new([5; 32]).expect("database key");
        let (store, private) = open_store(&database, &key, directory.path());
        let (scope, binding, policy) = binding();
        let adapter = SqlCipherMemoryPersistence::new(
            store,
            FileMemoryPrivateRecordStore::new(private),
            hartevo_domain_kernel::TenantId::from("memory-tenant"),
            hartevo_domain_kernel::ProjectId::from("memory-project"),
            hartevo_domain_kernel::MissionId::from("memory-mission"),
        );
        let mut service = MemoryCandidateService::from_persistence(
            scope.clone(),
            binding.clone(),
            policy.clone(),
            Box::new(adapter),
        )
        .expect("service");
        let (source, draft) = source_and_draft();
        let proposed = service.propose(&source, &draft).expect("propose");
        service
            .adopt(
                proposed.candidate_id(),
                source.revision(),
                MemoryConsent::Explicit,
            )
            .expect("adopt");
        service
            .forget(proposed.candidate_id())
            .expect("forget tombstone");
        service.revoke_plugin().expect("revoke");
        drop(service);

        let (store, private) = open_store(&database, &key, directory.path());
        let adapter = SqlCipherMemoryPersistence::new(
            store,
            FileMemoryPrivateRecordStore::new(private),
            hartevo_domain_kernel::TenantId::from("memory-tenant"),
            hartevo_domain_kernel::ProjectId::from("memory-project"),
            hartevo_domain_kernel::MissionId::from("memory-mission"),
        );
        let mut restarted =
            MemoryCandidateService::from_persistence(scope, binding, policy, Box::new(adapter))
                .expect("reopen revoked service");
        assert!(matches!(
            restarted.query(
                PluginProjectId::new("memory-project").expect("project"),
                PluginMissionId::new("memory-next").expect("mission"),
                7,
            ),
            Err(hartevo_memory_runtime::MemoryRuntimeError::PluginRevoked)
        ));
    }
}
