//! Content-free persistence for deterministic Runtime context assembly evidence.
//!
//! Runtime envelopes contain resolved text and are deliberately never accepted
//! by this module. Only the digest/count manifest crosses the storage boundary.

use hartevo_context_fabric::{ContextAssemblyManifest, ContextAssemblyStatus};
use hartevo_domain_kernel::{
    ContextAssemblyId, ContextCapsuleStatus, ProjectId, WorkerLeaseStatus,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use crate::aggregate::{AtomicMutation, PendingEvent, append_events};
use crate::{ProjectStore, StorageError};

impl ProjectStore {
    pub fn record_context_assembly_manifest(
        &mut self,
        manifest: &ContextAssemblyManifest,
    ) -> Result<AtomicMutation, StorageError> {
        manifest.validate_dispatchable()?;
        match load_context_assembly_manifest_record(
            &self.connection,
            &manifest.project_id,
            &manifest.id,
        )? {
            Some(stored) if stored == *manifest => {
                return Ok(AtomicMutation {
                    event_sequences: vec![],
                    outbox_sequences: vec![],
                    state_revision: stored.revision,
                });
            }
            Some(_) => {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "context assembly manifest",
                    id: manifest.id.to_string(),
                });
            }
            None => {}
        }
        self.validate_context_assembly_scope(manifest)?;

        let manifest_digest = manifest.digest()?;
        let transaction = self.connection.transaction()?;
        insert_context_assembly_manifest(&transaction, manifest, &manifest_digest)?;
        insert_context_assembly_tokenizer_profile(&transaction, manifest)?;
        let event = context_assembly_event(manifest, &manifest_digest)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            manifest.tenant_id.as_str(),
            manifest.project_id.as_str(),
            Some(manifest.mission_id.as_str()),
            "context_assembly",
            manifest.id.as_str(),
            &[event],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: manifest.revision,
        })
    }

    pub fn load_context_assembly_manifest(
        &self,
        project_id: &ProjectId,
        id: &ContextAssemblyId,
    ) -> Result<ContextAssemblyManifest, StorageError> {
        load_context_assembly_manifest_record(&self.connection, project_id, id)?.ok_or_else(|| {
            StorageError::ScopedRecordNotFound {
                kind: "context assembly manifest",
                project_id: project_id.clone(),
                id: id.to_string(),
            }
        })
    }

    pub(crate) fn validate_context_assembly_scope(
        &self,
        manifest: &ContextAssemblyManifest,
    ) -> Result<(), StorageError> {
        let mission = self.load_mission(&manifest.project_id, &manifest.mission_id)?;
        let workspace =
            self.load_context_workspace(&manifest.project_id, &manifest.workspace_id)?;
        let capsule = self.load_context_capsule(&manifest.project_id, &manifest.capsule_id)?;
        let branch = self.load_context_branch(&manifest.project_id, &manifest.branch_id)?;
        let lease = self.load_worker_lease(&manifest.project_id, &manifest.worker_lease_id)?;
        let checkpoint =
            self.load_context_checkpoint(&manifest.project_id, &manifest.checkpoint_id)?;
        let latest_checkpoint = self
            .load_latest_context_checkpoint(&manifest.project_id, &manifest.workspace_id)?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "context checkpoint",
                project_id: manifest.project_id.clone(),
                id: manifest.workspace_id.to_string(),
            })?;
        manifest.policy.validate(&capsule)?;
        if mission.tenant_id != manifest.tenant_id
            || workspace.tenant_id != manifest.tenant_id
            || workspace.mission_id != manifest.mission_id
            || workspace.generation != manifest.worker_generation
            || capsule.tenant_id != manifest.tenant_id
            || capsule.mission_id != manifest.mission_id
            || capsule.workspace_id != manifest.workspace_id
            || capsule.branch_id != manifest.branch_id
            || capsule.revision != manifest.capsule_revision
            || capsule.worker_id != manifest.worker_id
            || capsule.worker_generation != manifest.worker_generation
            || capsule.worker_lease_id != manifest.worker_lease_id
            || capsule.authority_digest != manifest.capsule_authority_digest
            || capsule.status != ContextCapsuleStatus::Claimed
            || branch.workspace_id != manifest.workspace_id
            || branch.revision != manifest.branch_revision
            || branch.generation != manifest.worker_generation
            || lease.workspace_id != manifest.workspace_id
            || lease.branch_id != manifest.branch_id
            || lease.worker_id != manifest.worker_id
            || lease.generation != manifest.worker_generation
            || lease.revision != manifest.worker_lease_revision
            || lease.status != WorkerLeaseStatus::Active
            || checkpoint.mission_id != manifest.mission_id
            || checkpoint.workspace_id != manifest.workspace_id
            || checkpoint.generation != manifest.worker_generation
            || checkpoint.digest()? != manifest.checkpoint_digest
            || latest_checkpoint.id != checkpoint.id
            || manifest.created_at < checkpoint.created_at
            || manifest.created_at < capsule.updated_at
            || manifest.created_at > capsule.expires_at
            || manifest.created_at > lease.expires_at
        {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "context assembly authority closure",
                id: manifest.id.to_string(),
            });
        }
        Ok(())
    }
}

fn insert_context_assembly_manifest(
    transaction: &Transaction<'_>,
    manifest: &ContextAssemblyManifest,
    manifest_digest: &str,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO context_assembly_manifests
           (tenant_id, project_id, id, mission_id, workspace_id, capsule_id,
            capsule_revision, branch_id, branch_revision, worker_id, worker_generation,
            worker_lease_id, worker_lease_revision, foundation_sync_version,
            checkpoint_id, checkpoint_digest, capsule_authority_digest, policy_version,
            input_digest, manifest_digest, frame_count, gap_count, prompt_digest,
            prompt_byte_count, prompt_token_count, status, revision, created_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
                 ?27, ?28, ?29)",
        params![
            manifest.tenant_id.as_str(),
            manifest.project_id.as_str(),
            manifest.id.as_str(),
            manifest.mission_id.as_str(),
            manifest.workspace_id.as_str(),
            manifest.capsule_id.as_str(),
            to_sql_u64(manifest.capsule_revision)?,
            manifest.branch_id.as_str(),
            to_sql_u64(manifest.branch_revision)?,
            manifest.worker_id.as_str(),
            to_sql_u64(manifest.worker_generation)?,
            manifest.worker_lease_id.as_str(),
            to_sql_u64(manifest.worker_lease_revision)?,
            to_sql_u64(manifest.foundation_sync_version)?,
            manifest.checkpoint_id.as_str(),
            manifest.checkpoint_digest,
            manifest.capsule_authority_digest,
            to_sql_u64(u64::from(manifest.policy.version))?,
            manifest.input_digest,
            manifest_digest,
            to_sql_usize(manifest.frames.len())?,
            to_sql_usize(manifest.gaps.len())?,
            manifest.prompt_digest,
            to_sql_u64(manifest.prompt_byte_count)?,
            to_sql_u64(manifest.prompt_token_count)?,
            status_text(manifest.status),
            to_sql_u64(manifest.revision)?,
            manifest.created_at.to_rfc3339(),
            serde_json::to_string(manifest)?,
        ],
    )?;
    Ok(())
}

fn insert_context_assembly_tokenizer_profile(
    transaction: &Transaction<'_>,
    manifest: &ContextAssemblyManifest,
) -> Result<(), StorageError> {
    let Some(profile) = manifest.tokenizer_profile.as_ref() else {
        return Ok(());
    };
    profile.validate()?;
    transaction.execute(
        "INSERT INTO context_assembly_tokenizer_profiles
           (tenant_id, project_id, assembly_id, profile_schema_version, profile_digest,
            provider_digest, model_digest, model_revision_digest, artifact_digest,
            add_special_tokens, request_overhead_tokens, max_input_bytes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            manifest.tenant_id.as_str(),
            manifest.project_id.as_str(),
            manifest.id.as_str(),
            i64::from(profile.schema_version),
            profile.digest()?,
            digest_identity(&profile.provider),
            digest_identity(&profile.model),
            digest_identity(&profile.model_revision),
            profile.artifact_digest,
            i64::from(profile.add_special_tokens),
            to_sql_u64(profile.request_overhead_tokens)?,
            to_sql_u64(profile.max_input_bytes)?,
        ],
    )?;
    Ok(())
}

pub(crate) fn backfill_context_assembly_tokenizer_profiles(
    transaction: &Transaction<'_>,
) -> Result<(), StorageError> {
    let records = {
        let mut statement = transaction.prepare(
            "SELECT record_json FROM context_assembly_manifests ORDER BY project_id, id",
        )?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for record in records {
        let manifest: ContextAssemblyManifest = serde_json::from_str(&record)?;
        manifest.validate()?;
        if manifest.tokenizer_profile.is_some() {
            manifest.validate_dispatchable()?;
            insert_context_assembly_tokenizer_profile(transaction, &manifest)?;
        }
    }
    Ok(())
}

fn digest_identity(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn context_assembly_event(
    manifest: &ContextAssemblyManifest,
    manifest_digest: &str,
) -> Result<PendingEvent, StorageError> {
    let tokenizer_profile_digest = manifest.tokenizer_profile_digest()?;
    Ok(PendingEvent::new(
        "context.assembly_recorded",
        serde_json::json!({
            "assemblyId": manifest.id,
            "workspaceId": manifest.workspace_id,
            "capsuleId": manifest.capsule_id,
            "capsuleRevision": manifest.capsule_revision,
            "branchId": manifest.branch_id,
            "branchRevision": manifest.branch_revision,
            "workerId": manifest.worker_id,
            "workerGeneration": manifest.worker_generation,
            "workerLeaseRevision": manifest.worker_lease_revision,
            "checkpointId": manifest.checkpoint_id,
            "checkpointDigest": manifest.checkpoint_digest,
            "capsuleAuthorityDigest": manifest.capsule_authority_digest,
            "tokenizerProfileDigest": tokenizer_profile_digest,
            "inputDigest": manifest.input_digest,
            "manifestDigest": manifest_digest,
            "frameCount": manifest.frames.len(),
            "gapCount": manifest.gaps.len(),
            "promptDigest": manifest.prompt_digest,
            "promptByteCount": manifest.prompt_byte_count,
            "promptTokenCount": manifest.prompt_token_count,
            "status": manifest.status,
        }),
        manifest.created_at,
    ))
}

fn load_context_assembly_manifest_record(
    connection: &Connection,
    project_id: &ProjectId,
    id: &ContextAssemblyId,
) -> Result<Option<ContextAssemblyManifest>, StorageError> {
    let manifest = load_context_assembly_manifest_query(
        connection,
        "SELECT manifest_digest, record_json FROM context_assembly_manifests
         WHERE project_id = ?1 AND id = ?2",
        project_id.as_str(),
        id.as_str(),
    )?;
    if let Some(manifest) = manifest.as_ref() {
        validate_context_assembly_tokenizer_projection(connection, manifest)?;
    }
    Ok(manifest)
}

#[derive(Eq, PartialEq)]
struct ContextTokenizerProjection {
    tenant_id: String,
    profile_schema_version: i64,
    profile_digest: String,
    provider_digest: String,
    model_digest: String,
    model_revision_digest: String,
    artifact_digest: String,
    add_special_tokens: i64,
    request_overhead_tokens: i64,
    max_input_bytes: i64,
}

fn validate_context_assembly_tokenizer_projection(
    connection: &Connection,
    manifest: &ContextAssemblyManifest,
) -> Result<(), StorageError> {
    let stored = connection
        .query_row(
            "SELECT tenant_id, profile_schema_version, profile_digest, provider_digest,
                    model_digest, model_revision_digest, artifact_digest, add_special_tokens,
                    request_overhead_tokens, max_input_bytes
             FROM context_assembly_tokenizer_profiles
             WHERE project_id = ?1 AND assembly_id = ?2",
            params![manifest.project_id.as_str(), manifest.id.as_str()],
            |row| {
                Ok(ContextTokenizerProjection {
                    tenant_id: row.get(0)?,
                    profile_schema_version: row.get(1)?,
                    profile_digest: row.get(2)?,
                    provider_digest: row.get(3)?,
                    model_digest: row.get(4)?,
                    model_revision_digest: row.get(5)?,
                    artifact_digest: row.get(6)?,
                    add_special_tokens: row.get(7)?,
                    request_overhead_tokens: row.get(8)?,
                    max_input_bytes: row.get(9)?,
                })
            },
        )
        .optional()?;
    let expected = if let Some(profile) = manifest.tokenizer_profile.as_ref() {
        Some(ContextTokenizerProjection {
            tenant_id: manifest.tenant_id.to_string(),
            profile_schema_version: i64::from(profile.schema_version),
            profile_digest: profile.digest()?,
            provider_digest: digest_identity(&profile.provider),
            model_digest: digest_identity(&profile.model),
            model_revision_digest: digest_identity(&profile.model_revision),
            artifact_digest: profile.artifact_digest.clone(),
            add_special_tokens: i64::from(profile.add_special_tokens),
            request_overhead_tokens: to_sql_u64(profile.request_overhead_tokens)?,
            max_input_bytes: to_sql_u64(profile.max_input_bytes)?,
        })
    } else {
        None
    };
    if stored != expected {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "context assembly tokenizer profile",
            id: manifest.id.to_string(),
        });
    }
    Ok(())
}

fn load_context_assembly_manifest_query(
    connection: &Connection,
    sql: &str,
    first: &str,
    second: &str,
) -> Result<Option<ContextAssemblyManifest>, StorageError> {
    let row = connection
        .query_row(sql, params![first, second], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .optional()?;
    decode_manifest(row)
}

fn decode_manifest(
    row: Option<(String, String)>,
) -> Result<Option<ContextAssemblyManifest>, StorageError> {
    row.map(|(stored_digest, record)| {
        let manifest: ContextAssemblyManifest = serde_json::from_str(&record)?;
        if manifest.digest()? != stored_digest {
            return Err(StorageError::DomainDecode(
                "context assembly manifest digest mismatch".into(),
            ));
        }
        Ok(manifest)
    })
    .transpose()
}

fn status_text(status: ContextAssemblyStatus) -> &'static str {
    match status {
        ContextAssemblyStatus::Ready => "ready",
        ContextAssemblyStatus::BlockedMissingRequired => "blocked_missing_required",
        ContextAssemblyStatus::BlockedBudget => "blocked_budget",
    }
}

fn to_sql_usize(value: usize) -> Result<i64, StorageError> {
    to_sql_u64(u64::try_from(value).map_err(|_| StorageError::RevisionOverflow(u64::MAX))?)
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use chrono::{DateTime, Duration, TimeZone, Utc};
    use hartevo_context_fabric::{
        ContextAssembler, ContextAssemblyPolicy, ContextAssemblyRequest, ContextMaterialReference,
        ContextMaterialResolver, ContextTokenizer, ContextTokenizerProfile,
        ResolvedContextMaterial,
    };
    use hartevo_domain_kernel::{
        ApprovalPolicy, AutonomyLevel, Constraint, ContextAssemblyId, ContextBranch,
        ContextBranchId, ContextBudget, ContextCapsule, ContextCapsuleId, ContextCheckpoint,
        ContextCheckpointId, ContextCompactionRecord, ContextCompactionRecordId,
        ContextContinuationLedgerId, ContextDataPolicy, ContextInputRefs, ContextMergePolicy,
        ContextReturnContract, ContextWorkingSet, ContextWorkingSetId, ContextWorkspace,
        ContextWorkspaceId, ContinuationLedger, CurrencyCode, EffectClass, Mission,
        MissionContract, MissionId, Money, OperatingMode, Project, ProjectId, StorageMode, Task,
        TaskId, TaskStatus, TenantId, WorkerId, WorkerLease, WorkerLeaseId,
    };
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::context_store::{
        insert_context_branch, insert_context_capsule, insert_context_capsule_facts,
        insert_worker_lease,
    };

    const PRIVATE_SUMMARY: &str =
        "PRIVATE-STORAGE-SUMMARY::must never enter manifest, event, or outbox";

    pub(crate) fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    fn sha(value: &str) -> String {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    }

    struct SummaryResolver;

    impl ContextMaterialResolver for SummaryResolver {
        fn resolve(
            &self,
            reference: &ContextMaterialReference,
        ) -> Result<Option<ResolvedContextMaterial>, hartevo_context_fabric::ContextAssemblyError>
        {
            Ok((reference.storage_ref == "cas://storage-summary")
                .then(|| ResolvedContextMaterial::text(PRIVATE_SUMMARY)))
        }
    }

    struct ByteTokenizer;

    impl ContextTokenizer for ByteTokenizer {
        fn profile(
            &self,
        ) -> Result<ContextTokenizerProfile, hartevo_context_fabric::ContextAssemblyError> {
            ContextTokenizerProfile::new(
                "fixture-provider",
                "fixture-byte-model",
                "fixture-revision-v1",
                sha("fixture-byte-tokenizer"),
                false,
                0,
                16 * 1024 * 1024,
            )
        }

        fn count_tokens(
            &self,
            text: &str,
        ) -> Result<u64, hartevo_context_fabric::ContextAssemblyError> {
            u64::try_from(text.len())
                .map_err(|_| hartevo_context_fabric::ContextAssemblyError::TokenizerFailure)
        }
    }

    pub(crate) struct AssemblyStoreFixture {
        pub(crate) store: ProjectStore,
        pub(crate) project_id: ProjectId,
        pub(crate) mission_id: MissionId,
        pub(crate) manifest: ContextAssemblyManifest,
    }

    fn assert_exact_tokenizer_projection(
        store: &ProjectStore,
        project_id: &ProjectId,
        manifest: &ContextAssemblyManifest,
    ) {
        let profile = manifest
            .tokenizer_profile
            .as_ref()
            .expect("dispatchable tokenizer profile");
        let projection = store
            .connection
            .query_row(
                "SELECT profile_schema_version, profile_digest, provider_digest, model_digest,
                        model_revision_digest, artifact_digest, add_special_tokens,
                        request_overhead_tokens, max_input_bytes
                 FROM context_assembly_tokenizer_profiles
                 WHERE project_id = ?1 AND assembly_id = ?2",
                params![project_id.as_str(), manifest.id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                    ))
                },
            )
            .expect("normalized tokenizer profile");
        assert_eq!(projection.0, i64::from(profile.schema_version));
        assert_eq!(projection.1, profile.digest().expect("profile digest"));
        assert_eq!(projection.2, sha(&profile.provider));
        assert_eq!(projection.3, sha(&profile.model));
        assert_eq!(projection.4, sha(&profile.model_revision));
        assert_eq!(projection.5, profile.artifact_digest);
        assert_eq!(projection.6, i64::from(profile.add_special_tokens));
        assert_eq!(
            projection.7,
            i64::try_from(profile.request_overhead_tokens).expect("overhead")
        );
        assert_eq!(
            projection.8,
            i64::try_from(profile.max_input_bytes).expect("input bytes")
        );
        assert_ne!(projection.2, profile.provider);
        assert_ne!(projection.3, profile.model);
        assert_ne!(projection.4, profile.model_revision);
    }

    fn tokenizer_projection_count(
        store: &ProjectStore,
        project_id: &ProjectId,
        assembly_id: &ContextAssemblyId,
    ) -> i64 {
        store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM context_assembly_tokenizer_profiles
                 WHERE project_id = ?1 AND assembly_id = ?2",
                params![project_id.as_str(), assembly_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .expect("tokenizer projection count")
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture persists the complete Project-to-Checkpoint-to-claimed-Capsule foreign-key closure"
    )]
    pub(crate) fn fixture() -> AssemblyStoreFixture {
        let tenant_id = TenantId::from("tenant-context-assembly-store");
        let project_id = ProjectId::from("project-context-assembly-store");
        let mission_id = MissionId::from("mission-context-assembly-store");
        let project = Project::create_local(
            tenant_id.clone(),
            project_id.clone(),
            "Context assembly storage",
            "",
            PathBuf::from("/tmp/hartevo-context-assembly-store"),
            StorageMode::LocalExisting,
        )
        .expect("project");
        let contract = MissionContract {
            version: 1,
            mode: OperatingMode::BuildOnce,
            parent_mission_id: None,
            goal: "Return one typed finding".into(),
            non_goals: vec!["Never publish".into()],
            market: "DE".into(),
            language: "de".into(),
            audience: "owner".into(),
            kpis: BTreeMap::new(),
            budget: Money::new(20_000, CurrencyCode::parse("EUR").expect("EUR")),
            timezone: "Europe/Berlin".into(),
            cadence: None,
            autonomy_by_capability: BTreeMap::from([(
                "market.analyze".into(),
                AutonomyLevel::ApprovalRequired,
            )]),
            consent_requirements: BTreeSet::new(),
            approval_policy: ApprovalPolicy {
                required_effect_classes: BTreeSet::from([EffectClass::ExternalWrite]),
                validity_seconds: 3_600,
                exact_scope_required: true,
            },
            stop_conditions: vec!["user_cancelled".into()],
            completion_conditions: vec!["typed_result_returned".into()],
            valid_from: now(),
            valid_until: now() + Duration::days(1),
            constraints: vec![Constraint::Market { value: "DE".into() }],
            enabled_capabilities: BTreeSet::from(["market.analyze".into()]),
            forbidden_capabilities: BTreeSet::new(),
        };
        let mut mission = Mission::compile(
            tenant_id,
            mission_id.clone(),
            project_id.clone(),
            "Context assembly storage",
            contract,
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-context-assembly-store"),
                    title: "Analyze".into(),
                    status: TaskStatus::Ready,
                    capability: "market.analyze".into(),
                }],
                now(),
            )
            .expect("mission start");
        let workspace = ContextWorkspace::create(
            ContextWorkspaceId::from("workspace-context-assembly-store"),
            &mission,
            3,
            "context-policy/v1",
            BTreeSet::from(["market.analyze".into()]),
            ContextBudget {
                token_limit: 20_000,
                cost_limit: mission.contract.budget.clone(),
                deadline_at: now() + Duration::hours(6),
                max_depth: 2,
                max_concurrency: 1,
            },
            ContextDataPolicy::BusinessOnly,
            now(),
        )
        .expect("workspace");
        let working_set = ContextWorkingSet::create(
            ContextWorkingSetId::from("working-context-assembly-store"),
            &workspace,
            now(),
        )
        .expect("working set");
        let continuation = ContinuationLedger::create(
            ContextContinuationLedgerId::from("continuation-context-assembly-store"),
            &workspace,
            now(),
        )
        .expect("continuation");
        let compaction = ContextCompactionRecord::create(
            ContextCompactionRecordId::from("compaction-context-assembly-store"),
            &workspace,
            &mission,
            &[],
            None,
            1,
            10,
            "1".repeat(64),
            5_000,
            9,
            "cas://storage-summary".into(),
            sha(PRIVATE_SUMMARY),
            u64::try_from(PRIVATE_SUMMARY.len()).expect("summary length"),
            100,
            BTreeSet::new(),
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(64),
            now() + Duration::seconds(1),
        )
        .expect("compaction");
        let checkpoint = ContextCheckpoint::create(
            ContextCheckpointId::from("checkpoint-context-assembly-store"),
            &workspace,
            &mission,
            &[],
            &working_set,
            &continuation,
            &compaction,
            None,
            "5".repeat(64),
            "6".repeat(64),
            10,
            now() + Duration::seconds(2),
        )
        .expect("checkpoint");
        let branch = ContextBranch::create(
            ContextBranchId::from("branch-context-assembly-store"),
            &workspace,
            None,
            "one bounded turn",
            "7".repeat(64),
            ContextMergePolicy::TypedResultOnly,
            now() + Duration::seconds(2),
        )
        .expect("branch");
        let lease = WorkerLease::issue(
            WorkerLeaseId::from("lease-context-assembly-store"),
            &workspace,
            &branch,
            WorkerId::from("worker-context-assembly-store"),
            workspace.generation,
            "8".repeat(64),
            Some("9".repeat(64)),
            now() + Duration::hours(2),
            now() + Duration::seconds(2),
        )
        .expect("lease");
        let mut capsule = ContextCapsule::issue(
            ContextCapsuleId::from("capsule-context-assembly-store"),
            &workspace,
            &branch,
            &lease,
            &mission,
            "Return the typed result",
            TaskId::from("task-context-assembly-store"),
            BTreeSet::new(),
            &[],
            BTreeSet::from(["market.analyze".into()]),
            ContextBudget {
                token_limit: 10_000,
                cost_limit: Money::new(5_000, CurrencyCode::parse("EUR").expect("EUR")),
                deadline_at: now() + Duration::minutes(90),
                max_depth: 1,
                max_concurrency: 1,
            },
            ContextInputRefs::default(),
            ContextReturnContract {
                schema_id: "hartevo.context.storage-result".into(),
                schema_version: 1,
                required_fields: BTreeSet::from(["result".into()]),
                allowed_artifact_types: BTreeSet::new(),
                evidence_required: false,
                uncertainty_required: true,
                max_result_bytes: 4_096,
            },
            now() + Duration::hours(1),
            now() + Duration::seconds(2),
        )
        .expect("capsule");
        capsule
            .claim(workspace.generation, now() + Duration::seconds(3))
            .expect("claim");

        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project).expect("persist project");
        store.save_mission(&mission).expect("persist mission");
        store
            .create_context_workspace(
                &workspace,
                &working_set,
                &continuation,
                &[PendingEvent::new(
                    "context.workspace_created",
                    serde_json::json!({"workspaceId": workspace.id}),
                    now(),
                )],
                now(),
            )
            .expect("persist workspace");
        store
            .append_context_compaction_checkpoint(
                &compaction,
                &checkpoint,
                &[PendingEvent::new(
                    "context.checkpoint_recorded",
                    serde_json::json!({"checkpointId": checkpoint.id}),
                    checkpoint.created_at,
                )],
                checkpoint.created_at,
            )
            .expect("persist checkpoint");
        {
            let transaction = store.connection.transaction().expect("context transaction");
            insert_context_branch(&transaction, &branch).expect("persist branch");
            insert_worker_lease(&transaction, &lease).expect("persist lease");
            insert_context_capsule(&transaction, &capsule).expect("persist capsule");
            insert_context_capsule_facts(&transaction, &capsule).expect("persist grants");
            transaction.commit().expect("context commit");
        }
        let foundation = hartevo_domain_kernel::ContextFoundationSnapshot {
            sync_version: 1,
            workspace,
            working_set,
            continuation_ledger: continuation,
            compaction,
            checkpoint,
            truth_facts: vec![],
        };
        let request = ContextAssemblyRequest {
            id: ContextAssemblyId::from("assembly-context-assembly-store"),
            mission: &mission,
            foundation: &foundation,
            previous_compaction: None,
            previous_checkpoint: None,
            branch_lineage: std::slice::from_ref(&branch),
            worker_lease: &lease,
            capsule: &capsule,
            policy: ContextAssemblyPolicy {
                version: 1,
                max_prompt_tokens: 8_000,
                reserved_output_tokens: 1_000,
                max_prompt_bytes: 100_000,
                max_optional_frames: 8,
                max_gap_records: 16,
            },
            now: now() + Duration::seconds(4),
        };
        let manifest = ContextAssembler::assemble(&request, &SummaryResolver, &ByteTokenizer)
            .expect("assembly")
            .manifest;
        AssemblyStoreFixture {
            store,
            project_id,
            mission_id,
            manifest,
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the atomicity proof covers manifest, normalized tokenizer evidence, event/outbox redaction, immutable replay, and crash-gap rollback together"
    )]
    fn manifest_event_and_outbox_commit_atomically_without_context_content() {
        let AssemblyStoreFixture {
            mut store,
            project_id,
            mission_id,
            manifest,
        } = fixture();
        let mutation = store
            .record_context_assembly_manifest(&manifest)
            .expect("persist manifest");
        assert_eq!(mutation.event_sequences.len(), 1);
        assert_eq!(mutation.outbox_sequences.len(), 1);
        assert_eq!(
            store
                .load_context_assembly_manifest(&project_id, &manifest.id)
                .expect("roundtrip"),
            manifest
        );
        let replay = store
            .record_context_assembly_manifest(&manifest)
            .expect("idempotent replay");
        assert!(replay.event_sequences.is_empty());
        let record_json: String = store
            .connection
            .query_row(
                "SELECT record_json FROM context_assembly_manifests
                 WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), manifest.id.as_str()],
                |row| row.get(0),
            )
            .expect("record json");
        assert_exact_tokenizer_projection(&store, &project_id, &manifest);
        let events = store
            .events_for_mission(&project_id, &mission_id)
            .expect("events");
        let outbox_json: String = store
            .connection
            .query_row(
                "SELECT group_concat(payload_json, '') FROM outbox_messages
                 WHERE project_id = ?1",
                [project_id.as_str()],
                |row| row.get(0),
            )
            .expect("outbox json");
        assert!(!record_json.contains(PRIVATE_SUMMARY));
        assert!(
            !serde_json::to_string(&events)
                .expect("events json")
                .contains(PRIVATE_SUMMARY)
        );
        assert!(!outbox_json.contains(PRIVATE_SUMMARY));

        let mut conflicting = manifest.clone();
        conflicting.worker_lease_revision += 1;
        assert!(matches!(
            store.record_context_assembly_manifest(&conflicting),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "context assembly manifest",
                ..
            })
        ));

        let mut injected = manifest.clone();
        injected.id = ContextAssemblyId::from("assembly-context-assembly-injected");
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER inject_context_assembly_event_failure
                 BEFORE INSERT ON domain_events
                 WHEN NEW.event_type = 'context.assembly_recorded'
                 BEGIN SELECT RAISE(ABORT, 'injected context assembly event failure'); END;",
            )
            .expect("failure trigger");
        assert!(matches!(
            store.record_context_assembly_manifest(&injected),
            Err(StorageError::Sql(_))
        ));
        assert!(matches!(
            store.load_context_assembly_manifest(&project_id, &injected.id),
            Err(StorageError::ScopedRecordNotFound { .. })
        ));
        assert_eq!(
            tokenizer_projection_count(&store, &project_id, &injected.id),
            0
        );
        assert_eq!(
            store
                .events_for_mission(&project_id, &mission_id)
                .expect("events after rollback")
                .iter()
                .filter(|event| event.event_type == "context.assembly_recorded")
                .count(),
            1
        );
        store
            .connection
            .execute_batch("DROP TRIGGER inject_context_assembly_event_failure;")
            .expect("drop trigger");
        store
            .record_context_assembly_manifest(&injected)
            .expect("retry after rollback");
        assert_eq!(
            store
                .load_context_assembly_manifest(&project_id, &injected.id)
                .expect("injected retry"),
            injected
        );
    }

    #[test]
    fn tokenizer_projection_tamper_fails_closed_and_backfill_repairs_missing_projection() {
        let AssemblyStoreFixture {
            mut store,
            project_id,
            manifest,
            ..
        } = fixture();
        store
            .record_context_assembly_manifest(&manifest)
            .expect("persist manifest");
        store
            .connection
            .execute(
                "DELETE FROM context_assembly_tokenizer_profiles
                 WHERE project_id = ?1 AND assembly_id = ?2",
                params![project_id.as_str(), manifest.id.as_str()],
            )
            .expect("remove normalized projection");
        assert!(matches!(
            store.load_context_assembly_manifest(&project_id, &manifest.id),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "context assembly tokenizer profile",
                ..
            })
        ));
        {
            let transaction = store
                .connection
                .transaction()
                .expect("backfill transaction");
            backfill_context_assembly_tokenizer_profiles(&transaction).expect("backfill");
            transaction.commit().expect("commit backfill");
        }
        assert_eq!(
            store
                .load_context_assembly_manifest(&project_id, &manifest.id)
                .expect("repaired normalized projection"),
            manifest
        );
        store
            .connection
            .execute(
                "UPDATE context_assembly_tokenizer_profiles
                 SET provider_digest = ?3
                 WHERE project_id = ?1 AND assembly_id = ?2",
                params![project_id.as_str(), manifest.id.as_str(), "0".repeat(64)],
            )
            .expect("tamper projection");
        assert!(matches!(
            store.load_context_assembly_manifest(&project_id, &manifest.id),
            Err(StorageError::ImmutableRecordMismatch {
                kind: "context assembly tokenizer profile",
                ..
            })
        ));
    }

    #[test]
    fn legacy_unbound_manifest_is_audit_readable_but_cannot_be_written_or_dispatched() {
        let AssemblyStoreFixture {
            mut store,
            project_id,
            manifest,
            ..
        } = fixture();
        let mut legacy = manifest;
        legacy.id = ContextAssemblyId::from("assembly-context-assembly-legacy-v1");
        legacy.schema_version = 1;
        legacy.tokenizer_profile = None;
        let digest = legacy.digest().expect("legacy audit digest");
        {
            let transaction = store.connection.transaction().expect("legacy transaction");
            insert_context_assembly_manifest(&transaction, &legacy, &digest)
                .expect("persist historical legacy row");
            transaction.commit().expect("commit legacy fixture");
        }
        assert_eq!(
            store
                .load_context_assembly_manifest(&project_id, &legacy.id)
                .expect("legacy audit read"),
            legacy
        );
        assert!(matches!(
            store.record_context_assembly_manifest(&legacy),
            Err(StorageError::ContextAssembly(_))
        ));
        assert_eq!(
            tokenizer_projection_count(&store, &project_id, &legacy.id),
            0
        );
    }
}
