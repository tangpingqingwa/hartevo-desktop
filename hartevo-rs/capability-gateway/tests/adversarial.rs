use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use chrono::{Duration, Utc};
use hartevo_capability_gateway::{
    AdapterBinding, AdapterFailure, AdapterId, AdapterRegistry, ApprovalRequirement,
    BoundedPayload, BudgetAuthority, BudgetUse, CAPABILITY_EXECUTION_SCHEMA,
    CAPABILITY_MANIFEST_SCHEMA, CAPABILITY_REQUEST_SCHEMA, CAPABILITY_RESULT_SCHEMA,
    CapabilityAdapter, CapabilityClass, CapabilityGateway, CapabilityId, CapabilityManifest,
    CapabilityRequest, CapabilityResult, CostLimit, DataAuthority, DataClass, EffectAuthority,
    EffectId, EffectKind, ExternalEffectRequest, InvocationScope, LocalMutationOperation,
    LocalMutationRequest, ManifestIssuer, ManifestProvenance, MemoryInvocationLedger, MissionId,
    MissionScope, NetworkAuthority, ProjectId, ProjectScope, Provenance, ProvenanceSource,
    ReadCompleteness, ReadOperation, ReadRequest, RecoveryDisposition, RevocationBinding,
    RevocationStatus, SecretAuthority, SecretReference, SecretReferenceId,
    SignedCapabilityManifest, TaskId, TenantId, ToolSelfRecoveryPolicy, WorkerId, WorkerLeaseId,
};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

const NOW_OFFSET_SECONDS: i64 = 1;

#[derive(Clone)]
struct MockAdapter {
    binding: AdapterBinding,
    mode: MockMode,
    calls: Arc<AtomicUsize>,
}

#[derive(Clone)]
enum MockMode {
    Read,
    RetryRead { retried: Arc<AtomicUsize> },
    RetryReadForever { attempts: Arc<AtomicUsize> },
    RetryReadExpandsMax { attempts: Arc<AtomicUsize> },
    RetryLocalMutation,
    UncertainExternal,
}

impl CapabilityAdapter for MockAdapter {
    fn binding(&self) -> &AdapterBinding {
        &self.binding
    }

    fn invoke(&self, request: &CapabilityRequest) -> Result<CapabilityResult, AdapterFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.mode {
            MockMode::Read => Ok(read_result(request)),
            MockMode::RetryRead { retried } => {
                if retried.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(AdapterFailure::recovery(
                        RecoveryDisposition::retry_read(
                            request,
                            hartevo_capability_gateway::ReadRecoveryReason::TruncatedOutput,
                            0,
                            2,
                        )
                        .expect("valid read recovery"),
                    ))
                } else {
                    Ok(read_result(request))
                }
            }
            MockMode::RetryReadForever { attempts } => {
                let attempt = u32::try_from(attempts.fetch_add(1, Ordering::SeqCst))
                    .expect("bounded test attempts");
                Err(AdapterFailure::recovery(
                    RecoveryDisposition::retryable_read(request, attempt, 8)
                        .expect("valid bounded read recovery"),
                ))
            }
            MockMode::RetryReadExpandsMax { attempts } => {
                let attempt = u32::try_from(attempts.fetch_add(1, Ordering::SeqCst))
                    .expect("bounded test attempts");
                let max_attempts = if attempt == 0 { 2 } else { 8 };
                Err(AdapterFailure::recovery(
                    RecoveryDisposition::retryable_read(request, attempt, max_attempts)
                        .expect("valid bounded read recovery"),
                ))
            }
            MockMode::RetryLocalMutation => Err(AdapterFailure::recovery(
                RecoveryDisposition::stale_locator_or_path(request, 0, 1)
                    .expect("valid local recovery"),
            )),
            MockMode::UncertainExternal => Err(AdapterFailure::UncertainExternalEffect {
                effect_digest: request.digest(),
                reconciliation_digest: digest("reconcile-external-effect"),
            }),
        }
    }
}

fn digest(value: &str) -> hartevo_capability_gateway::Digest {
    hartevo_capability_gateway::Digest::from_text(value)
}

fn now() -> chrono::DateTime<Utc> {
    Utc::now()
}

fn adapter_binding() -> AdapterBinding {
    AdapterBinding {
        adapter_id: AdapterId::from_stable("mock.adapter"),
        implementation_id: "mock-typed-handler".into(),
        implementation_digest: digest("implementation-v1"),
        binary_digest: digest("binary-v1"),
        schema_digest: digest("capability-schema-v1"),
        version: "1.0.0".into(),
        revocation_epoch: 1,
    }
}

fn project_scope(project: &str) -> ProjectScope {
    ProjectScope {
        tenant_id: TenantId::from_stable("tenant-a"),
        project_id: ProjectId::from_stable(project),
        workspace_digest: digest("workspace-a"),
        resource_scope_digest: digest("resources-a"),
    }
}

fn mission_scope(project: &ProjectScope, generation: u64) -> MissionScope {
    MissionScope {
        tenant_id: project.tenant_id.clone(),
        project_id: project.project_id.clone(),
        mission_id: MissionId::from_stable("mission-a"),
        task_id: Some(TaskId::from_stable("task-a")),
        worker_id: Some(WorkerId::from_stable("worker-a")),
        worker_lease_id: Some(WorkerLeaseId::from_stable("lease-a")),
        context_workspace_id: None,
        context_capsule_id: None,
        context_branch_id: None,
        generation,
        contract_revision: 3,
        scope_digest: digest(&format!(
            "scope-{}-{generation}",
            project.project_id.as_str()
        )),
    }
}

fn budget() -> BudgetAuthority {
    BudgetAuthority {
        max_tokens: 10_000,
        max_cost: CostLimit {
            amount_minor: 1_000,
            currency: "USD".into(),
        },
        max_request_bytes: 4_096,
        max_result_bytes: 4_096,
        max_external_effects: 1,
        deadline_at: now() + Duration::hours(1),
    }
}

fn budget_use(external_effect_count: u32) -> BudgetUse {
    BudgetUse {
        request_bytes: 128,
        result_bytes: 128,
        estimated_tokens: 64,
        estimated_cost: CostLimit {
            amount_minor: 0,
            currency: "USD".into(),
        },
        external_effect_count,
    }
}

fn manifest_parts(
    class: CapabilityClass,
    capability_id: &str,
    network: NetworkAuthority,
    effect: EffectAuthority,
) -> (CapabilityManifest, AdapterRegistry) {
    let binding = adapter_binding();
    let mut registry = AdapterRegistry::new();
    let record_digest = registry
        .register(
            binding.clone(),
            BTreeSet::from([CapabilityId::from_stable(capability_id)]),
        )
        .expect("test adapter registration");
    let project = project_scope("project-a");
    let mission = mission_scope(&project, 7);
    let current = now();
    let manifest = CapabilityManifest {
        schema: CAPABILITY_MANIFEST_SCHEMA.into(),
        manifest_version: 1,
        schema_digest: binding.schema_digest.clone(),
        capability_id: CapabilityId::from_stable(capability_id),
        class,
        project,
        mission: mission.clone(),
        data: DataAuthority {
            maximum_class: DataClass::Restricted,
            allowed_resource_digests: BTreeSet::new(),
        },
        network,
        secrets: SecretAuthority {
            references: BTreeSet::from([SecretReference {
                id: SecretReferenceId::from_stable("mail-secret-ref"),
                provider: "mail".into(),
                purpose: "broker-auth".into(),
                scope_digest: digest("secret-scope"),
                version: 1,
            }]),
        },
        budget: budget(),
        effect,
        adapter: binding.clone(),
        revocation: RevocationBinding {
            registry_revision: 2,
            revocation_epoch: binding.revocation_epoch,
            status: RevocationStatus::Active,
            record_digest,
        },
        provenance: ManifestProvenance {
            issuer: ManifestIssuer::Application,
            source_digest: digest("mission-compiler"),
            parent_manifest_digest: None,
            issued_for_generation: mission.generation,
        },
        issued_at: current - Duration::seconds(NOW_OFFSET_SECONDS),
        expires_at: current + Duration::hours(1),
    };
    (manifest, registry)
}

fn signed(manifest: CapabilityManifest) -> SignedCapabilityManifest {
    let key_pair = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("test key");
    SignedCapabilityManifest::sign(manifest, "test-manifest-key", key_pair.as_ref())
        .expect("sign test manifest")
}

fn provenance(request: &CapabilityRequest, source: ProvenanceSource) -> Provenance {
    Provenance {
        source,
        manifest_digest: request.manifest_digest.clone(),
        authority_digest: request.provenance.authority_digest.clone(),
        parent_digest: None,
        input_digest: digest("typed-input"),
        generation: request.generation,
        observed_at: request.provenance.observed_at,
        links: Vec::new(),
    }
}

fn read_request(manifest: &CapabilityManifest, request_id: &str) -> CapabilityRequest {
    let manifest_digest = manifest.digest().expect("manifest digest");
    let authority_digest = manifest.authority_digest().expect("authority digest");
    CapabilityRequest {
        schema: CAPABILITY_REQUEST_SCHEMA.into(),
        request_id: hartevo_capability_gateway::RequestId::from_stable(request_id),
        capability_id: manifest.capability_id.clone(),
        class: CapabilityClass::Read,
        scope: InvocationScope::from_manifest(manifest),
        generation: manifest.mission.generation,
        idempotency_key: hartevo_capability_gateway::IdempotencyKey::from_stable("read-once"),
        manifest_digest: manifest_digest.clone(),
        provenance: Provenance {
            source: ProvenanceSource::Runtime,
            manifest_digest: manifest_digest.clone(),
            authority_digest,
            parent_digest: None,
            input_digest: digest("typed-input"),
            generation: manifest.mission.generation,
            observed_at: now(),
            links: Vec::new(),
        },
        budget_use: budget_use(0),
        payload: hartevo_capability_gateway::RequestPayload::Read(ReadRequest {
            operation: ReadOperation::ProjectSnapshot { revision: 1 },
            requested_class: DataClass::Business,
            secret_references: BTreeSet::new(),
        }),
    }
}

fn local_mutation_request(manifest: &CapabilityManifest, request_id: &str) -> CapabilityRequest {
    let manifest_digest = manifest.digest().expect("manifest digest");
    let authority_digest = manifest.authority_digest().expect("authority digest");
    CapabilityRequest {
        schema: CAPABILITY_REQUEST_SCHEMA.into(),
        request_id: hartevo_capability_gateway::RequestId::from_stable(request_id),
        capability_id: manifest.capability_id.clone(),
        class: CapabilityClass::LocalMutation,
        scope: InvocationScope::from_manifest(manifest),
        generation: manifest.mission.generation,
        idempotency_key: hartevo_capability_gateway::IdempotencyKey::from_stable(
            "local-mutation-once",
        ),
        manifest_digest: manifest_digest.clone(),
        provenance: Provenance {
            source: ProvenanceSource::Runtime,
            manifest_digest,
            authority_digest,
            parent_digest: None,
            input_digest: digest("typed-local-input"),
            generation: manifest.mission.generation,
            observed_at: now(),
            links: Vec::new(),
        },
        budget_use: budget_use(0),
        payload: hartevo_capability_gateway::RequestPayload::LocalMutation(LocalMutationRequest {
            operation: LocalMutationOperation::WorkspaceWrite {
                file_grant_digest: digest("file-grant-a"),
                content: BoundedPayload::try_new(
                    "hartevo.draft/v1",
                    DataClass::Business,
                    b"typed-local-material".to_vec(),
                    1024,
                )
                .expect("local payload"),
            },
            secret_references: BTreeSet::new(),
        }),
    }
}

fn read_result(request: &CapabilityRequest) -> CapabilityResult {
    CapabilityResult {
        schema: CAPABILITY_RESULT_SCHEMA.into(),
        request_id: request.request_id.clone(),
        capability_id: request.capability_id.clone(),
        class: CapabilityClass::Read,
        scope: request.scope.clone(),
        generation: request.generation,
        manifest_digest: request.manifest_digest.clone(),
        provenance: provenance(request, ProvenanceSource::Runtime),
        budget_use: budget_use(0),
        payload: hartevo_capability_gateway::ResultPayload::Read(
            hartevo_capability_gateway::ReadResult {
                payload: None,
                completeness: ReadCompleteness::Complete,
                continuation_digest: None,
            },
        ),
    }
}

#[test]
fn typed_read_is_scoped_idempotent_and_content_free() {
    let (manifest, registry) = manifest_parts(
        CapabilityClass::Read,
        "project.inventory",
        NetworkAuthority::None,
        EffectAuthority::proposal_only(digest("broker-policy")),
    );
    let signed_manifest = signed(manifest.clone());
    let gateway = CapabilityGateway::new(registry).expect("gateway");
    let adapter = MockAdapter {
        binding: manifest.adapter.clone(),
        mode: MockMode::Read,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let mut ledger = MemoryInvocationLedger::default();
    let request = read_request(&manifest, "request-a");
    let result = gateway
        .dispatch(&signed_manifest, &request, &adapter, &mut ledger, now())
        .expect("typed read");
    assert_eq!(result.class, CapabilityClass::Read);
    assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);

    let duplicate = gateway.dispatch(&signed_manifest, &request, &adapter, &mut ledger, now());
    assert!(matches!(
        duplicate,
        Err(hartevo_capability_gateway::GatewayError::Recovery(
            RecoveryDisposition::DuplicateRequest { .. }
        ))
    ));
    assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);

    let secret_payload = BoundedPayload::try_new(
        "text/plain",
        DataClass::Restricted,
        b"super-secret-looking-content".to_vec(),
        1024,
    )
    .expect("payload");
    let debug = format!("{secret_payload:?}");
    assert!(!debug.contains("super-secret-looking-content"));
    assert!(!format!("{signed_manifest:?}").contains("mail-secret-ref"));

    let mut tampered_manifest = signed_manifest.clone();
    tampered_manifest.manifest.expires_at += Duration::minutes(1);
    assert!(matches!(
        tampered_manifest.verify(now()),
        Err(hartevo_capability_gateway::GatewayError::SignatureVerificationFailed)
    ));
}

#[test]
fn read_recovery_is_typed_explicit_and_idempotent() {
    let (manifest, registry) = manifest_parts(
        CapabilityClass::Read,
        "project.inventory",
        NetworkAuthority::None,
        EffectAuthority::proposal_only(digest("broker-policy")),
    );
    let signed_manifest = signed(manifest.clone());
    let gateway = CapabilityGateway::new(registry).expect("gateway");
    let adapter = MockAdapter {
        binding: manifest.adapter.clone(),
        mode: MockMode::RetryRead {
            retried: Arc::new(AtomicUsize::new(0)),
        },
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let mut ledger = MemoryInvocationLedger::default();
    let request = read_request(&manifest, "request-recovery");

    let first = gateway.dispatch(&signed_manifest, &request, &adapter, &mut ledger, now());
    assert!(matches!(
        first,
        Err(hartevo_capability_gateway::GatewayError::Recovery(
            RecoveryDisposition::RetryRead { .. }
        ))
    ));
    let disposition = RecoveryDisposition::retry_read(
        &request,
        hartevo_capability_gateway::ReadRecoveryReason::EmptyResult,
        0,
        1,
    )
    .expect("recovery disposition");
    let envelope = disposition.envelope();
    let encoded = serde_json::to_value(&envelope).expect("recovery envelope");
    assert_eq!(encoded["schema"], "hartevo.capability-recovery/v1");
    assert_eq!(encoded["type"], "retry_read");

    let result = gateway
        .dispatch(&signed_manifest, &request, &adapter, &mut ledger, now())
        .expect("explicit read recovery");
    assert_eq!(result.class, CapabilityClass::Read);
    assert_eq!(adapter.calls.load(Ordering::SeqCst), 2);

    let duplicate = gateway.dispatch(&signed_manifest, &request, &adapter, &mut ledger, now());
    assert!(matches!(
        duplicate,
        Err(hartevo_capability_gateway::GatewayError::Recovery(
            RecoveryDisposition::DuplicateRequest { .. }
        ))
    ));
    assert_eq!(adapter.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn tool_self_recovery_executes_bounded_read_retry_and_duplicate_without_replay() {
    let (manifest, registry) = manifest_parts(
        CapabilityClass::Read,
        "project.inventory",
        NetworkAuthority::None,
        EffectAuthority::proposal_only(digest("broker-policy")),
    );
    let signed_manifest = signed(manifest.clone());
    let gateway = CapabilityGateway::new(registry).expect("gateway");
    let adapter = MockAdapter {
        binding: manifest.adapter.clone(),
        mode: MockMode::RetryRead {
            retried: Arc::new(AtomicUsize::new(0)),
        },
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let mut ledger = MemoryInvocationLedger::default();
    let request = read_request(&manifest, "request-auto-recovery");

    let execution = gateway
        .dispatch_with_recovery(
            &signed_manifest,
            &request,
            &adapter,
            &mut ledger,
            now(),
            ToolSelfRecoveryPolicy {
                max_read_retries: 1,
            },
        )
        .expect("bounded read recovery");
    assert_eq!(execution.schema, CAPABILITY_EXECUTION_SCHEMA);
    execution.validate().expect("execution envelope");
    let encoded = serde_json::to_value(&execution).expect("execution contract envelope");
    assert_eq!(encoded["schema"], CAPABILITY_EXECUTION_SCHEMA);
    assert_eq!(encoded["policy"]["maxReadRetries"], 1);
    assert_eq!(encoded["receipt"]["automaticReadRetries"], 1);
    assert_eq!(execution.result.class, CapabilityClass::Read);
    assert_eq!(execution.receipt.adapter_invocations, 2);
    assert_eq!(execution.receipt.automatic_read_retries, 1);
    assert_eq!(
        execution.receipt.cumulative_budget_use.estimated_tokens,
        128
    );
    assert_eq!(adapter.calls.load(Ordering::SeqCst), 2);

    let resumed_adapter = MockAdapter {
        binding: manifest.adapter.clone(),
        mode: MockMode::RetryRead {
            retried: Arc::new(AtomicUsize::new(0)),
        },
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let resumed_request = read_request(&manifest, "request-auto-recovery-resume");
    let mut resumed_ledger = MemoryInvocationLedger::default();
    assert!(matches!(
        gateway.dispatch(
            &signed_manifest,
            &resumed_request,
            &resumed_adapter,
            &mut resumed_ledger,
            now()
        ),
        Err(hartevo_capability_gateway::GatewayError::Recovery(
            RecoveryDisposition::RetryRead { .. }
        ))
    ));
    let resumed = gateway
        .dispatch_with_recovery(
            &signed_manifest,
            &resumed_request,
            &resumed_adapter,
            &mut resumed_ledger,
            now(),
            ToolSelfRecoveryPolicy::default(),
        )
        .expect("resumed read recovery");
    assert_eq!(resumed.receipt.adapter_invocations, 2);
    assert_eq!(resumed.receipt.automatic_read_retries, 1);
    assert_eq!(resumed_adapter.calls.load(Ordering::SeqCst), 2);

    let duplicate = gateway.dispatch_with_recovery(
        &signed_manifest,
        &request,
        &adapter,
        &mut ledger,
        now(),
        ToolSelfRecoveryPolicy::default(),
    );
    assert!(matches!(
        duplicate,
        Err(hartevo_capability_gateway::GatewayError::Recovery(
            RecoveryDisposition::DuplicateRequest { .. }
        ))
    ));
    assert_eq!(adapter.calls.load(Ordering::SeqCst), 2);
}

#[test]
#[allow(clippy::too_many_lines)]
fn tool_self_recovery_never_expands_retry_count_or_budget() {
    let (manifest, registry) = manifest_parts(
        CapabilityClass::Read,
        "project.inventory",
        NetworkAuthority::None,
        EffectAuthority::proposal_only(digest("broker-policy")),
    );
    let signed_manifest = signed(manifest.clone());
    let gateway = CapabilityGateway::new(registry).expect("gateway");
    let calls = Arc::new(AtomicUsize::new(0));
    let adapter = MockAdapter {
        binding: manifest.adapter.clone(),
        mode: MockMode::RetryReadForever {
            attempts: Arc::new(AtomicUsize::new(0)),
        },
        calls: calls.clone(),
    };
    let mut ledger = MemoryInvocationLedger::default();
    let request = read_request(&manifest, "request-retry-limit");
    let error = gateway
        .dispatch_with_recovery(
            &signed_manifest,
            &request,
            &adapter,
            &mut ledger,
            now(),
            ToolSelfRecoveryPolicy {
                max_read_retries: 1,
            },
        )
        .expect_err("retry count must be bounded");
    assert!(matches!(
        error,
        hartevo_capability_gateway::GatewayError::Recovery(RecoveryDisposition::FailClosed {
            code: hartevo_capability_gateway::FailClosedCode::RecoveryLimitExceeded
        })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let repeated = gateway.dispatch_with_recovery(
        &signed_manifest,
        &request,
        &adapter,
        &mut ledger,
        now(),
        ToolSelfRecoveryPolicy::default(),
    );
    assert!(matches!(
        repeated,
        Err(hartevo_capability_gateway::GatewayError::Recovery(
            RecoveryDisposition::FailClosed {
                code: hartevo_capability_gateway::FailClosedCode::RecoveryLimitExceeded
            }
        ))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let resumed_calls = Arc::new(AtomicUsize::new(0));
    let resumed_adapter = MockAdapter {
        binding: manifest.adapter.clone(),
        mode: MockMode::RetryReadForever {
            attempts: Arc::new(AtomicUsize::new(0)),
        },
        calls: resumed_calls.clone(),
    };
    let resumed_request = read_request(&manifest, "request-policy-resume-limit");
    let mut resumed_ledger = MemoryInvocationLedger::default();
    assert!(matches!(
        gateway.dispatch(
            &signed_manifest,
            &resumed_request,
            &resumed_adapter,
            &mut resumed_ledger,
            now()
        ),
        Err(hartevo_capability_gateway::GatewayError::Recovery(
            RecoveryDisposition::RetryRead { .. }
        ))
    ));
    let resumed_error = gateway
        .dispatch_with_recovery(
            &signed_manifest,
            &resumed_request,
            &resumed_adapter,
            &mut resumed_ledger,
            now(),
            ToolSelfRecoveryPolicy {
                max_read_retries: 0,
            },
        )
        .expect_err("a narrower resumed policy must not invoke the adapter");
    assert!(matches!(
        resumed_error,
        hartevo_capability_gateway::GatewayError::Recovery(RecoveryDisposition::FailClosed {
            code: hartevo_capability_gateway::FailClosedCode::RecoveryLimitExceeded
        })
    ));
    assert_eq!(resumed_calls.load(Ordering::SeqCst), 1);

    let expanding_calls = Arc::new(AtomicUsize::new(0));
    let expanding_adapter = MockAdapter {
        binding: manifest.adapter.clone(),
        mode: MockMode::RetryReadExpandsMax {
            attempts: Arc::new(AtomicUsize::new(0)),
        },
        calls: expanding_calls.clone(),
    };
    let expanding_request = read_request(&manifest, "request-adapter-retry-expansion");
    let mut expanding_ledger = MemoryInvocationLedger::default();
    let expanding_error = gateway
        .dispatch_with_recovery(
            &signed_manifest,
            &expanding_request,
            &expanding_adapter,
            &mut expanding_ledger,
            now(),
            ToolSelfRecoveryPolicy {
                max_read_retries: 3,
            },
        )
        .expect_err("an adapter cannot expand its recovery attempt contract");
    assert!(matches!(
        expanding_error,
        hartevo_capability_gateway::GatewayError::Recovery(RecoveryDisposition::FailClosed {
            code: hartevo_capability_gateway::FailClosedCode::UntrustedAdapter
        })
    ));
    assert_eq!(expanding_calls.load(Ordering::SeqCst), 2);

    let mut budget_limited_manifest = manifest;
    budget_limited_manifest.budget.max_tokens = 100;
    let signed_budget_limited_manifest = signed(budget_limited_manifest.clone());
    let budget_limited_request = read_request(&budget_limited_manifest, "request-budget-limit");
    let budget_calls = Arc::new(AtomicUsize::new(0));
    let budget_adapter = MockAdapter {
        binding: budget_limited_manifest.adapter.clone(),
        mode: MockMode::RetryReadForever {
            attempts: Arc::new(AtomicUsize::new(0)),
        },
        calls: budget_calls.clone(),
    };
    let mut budget_ledger = MemoryInvocationLedger::default();
    let error = gateway
        .dispatch_with_recovery(
            &signed_budget_limited_manifest,
            &budget_limited_request,
            &budget_adapter,
            &mut budget_ledger,
            now(),
            ToolSelfRecoveryPolicy {
                max_read_retries: 3,
            },
        )
        .expect_err("cumulative budget must be bounded");
    assert!(matches!(
        error,
        hartevo_capability_gateway::GatewayError::Recovery(RecoveryDisposition::FailClosed {
            code: hartevo_capability_gateway::FailClosedCode::BudgetExceeded
        })
    ));
    assert_eq!(budget_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn tool_self_recovery_keeps_stale_locator_explicit_and_external_write_uncertain() {
    let (manifest, registry) = manifest_parts(
        CapabilityClass::LocalMutation,
        "project.draft",
        NetworkAuthority::None,
        EffectAuthority::proposal_only(digest("broker-policy")),
    );
    let signed_manifest = signed(manifest.clone());
    let gateway = CapabilityGateway::new(registry).expect("gateway");
    let calls = Arc::new(AtomicUsize::new(0));
    let adapter = MockAdapter {
        binding: manifest.adapter.clone(),
        mode: MockMode::RetryLocalMutation,
        calls: calls.clone(),
    };
    let request = local_mutation_request(&manifest, "request-stale-locator");
    let mut ledger = MemoryInvocationLedger::default();
    let error = gateway
        .dispatch_with_recovery(
            &signed_manifest,
            &request,
            &adapter,
            &mut ledger,
            now(),
            ToolSelfRecoveryPolicy::default(),
        )
        .expect_err("stale locator must require explicit handling");
    assert!(matches!(
        error,
        hartevo_capability_gateway::GatewayError::Recovery(
            RecoveryDisposition::RetryLocalMutation { .. }
        )
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn cross_project_scope_and_payload_tamper_fail_closed() {
    let (manifest, registry) = manifest_parts(
        CapabilityClass::Read,
        "project.inventory",
        NetworkAuthority::None,
        EffectAuthority::proposal_only(digest("broker-policy")),
    );
    let signed_manifest = signed(manifest.clone());
    let gateway = CapabilityGateway::new(registry).expect("gateway");
    let adapter = MockAdapter {
        binding: manifest.adapter.clone(),
        mode: MockMode::Read,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let mut ledger = MemoryInvocationLedger::default();
    let mut request = read_request(&manifest, "request-cross-project");
    request.scope.project_id = ProjectId::from_stable("project-b");
    let error = gateway
        .dispatch(&signed_manifest, &request, &adapter, &mut ledger, now())
        .expect_err("cross-project request must fail");
    assert!(matches!(
        error,
        hartevo_capability_gateway::GatewayError::ScopeMismatch
    ));
    assert!(ledger.is_empty());

    let mut tampered_request = read_request(&manifest, "request-tamper");
    tampered_request.payload =
        hartevo_capability_gateway::RequestPayload::LocalMutation(LocalMutationRequest {
            operation: LocalMutationOperation::WorkspaceWrite {
                file_grant_digest: digest("grant-a"),
                content: BoundedPayload::try_new(
                    "text/plain",
                    DataClass::Business,
                    b"safe-content".to_vec(),
                    1024,
                )
                .expect("payload"),
            },
            secret_references: BTreeSet::new(),
        });
    let error = gateway
        .dispatch(
            &signed_manifest,
            &tampered_request,
            &adapter,
            &mut ledger,
            now(),
        )
        .expect_err("classification tamper must fail");
    assert!(matches!(
        error,
        hartevo_capability_gateway::GatewayError::ScopeMismatch
    ));
    assert!(ledger.is_empty());
}

#[test]
fn bounded_payload_byte_tamper_and_registry_tamper_fail_closed() {
    let (manifest, registry) = manifest_parts(
        CapabilityClass::LocalMutation,
        "project.draft",
        NetworkAuthority::None,
        EffectAuthority::proposal_only(digest("broker-policy")),
    );
    let signed_manifest = signed(manifest.clone());
    let gateway = CapabilityGateway::new(registry.clone()).expect("gateway");
    let adapter = MockAdapter {
        binding: manifest.adapter.clone(),
        mode: MockMode::Read,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let mut ledger = MemoryInvocationLedger::default();
    let mut request = read_request(&manifest, "request-byte-tamper");
    request.class = CapabilityClass::LocalMutation;
    let mut content = BoundedPayload::try_new(
        "text/plain",
        DataClass::Business,
        b"safe-content".to_vec(),
        1024,
    )
    .expect("payload");
    content.bytes[0] ^= 1;
    request.payload =
        hartevo_capability_gateway::RequestPayload::LocalMutation(LocalMutationRequest {
            operation: LocalMutationOperation::WorkspaceWrite {
                file_grant_digest: digest("grant-a"),
                content,
            },
            secret_references: BTreeSet::new(),
        });
    let error = gateway
        .dispatch(&signed_manifest, &request, &adapter, &mut ledger, now())
        .expect_err("byte tamper must fail");
    assert!(matches!(
        error,
        hartevo_capability_gateway::GatewayError::PayloadTampered
    ));
    assert!(ledger.is_empty());
    assert_eq!(adapter.calls.load(Ordering::SeqCst), 0);

    let adapter_id = manifest.adapter.adapter_id.clone();
    let original_record_digest = registry
        .registrations
        .get(&adapter_id)
        .expect("registration")
        .record_digest
        .clone();
    let mut tampered_registry = registry;
    tampered_registry
        .registrations
        .get_mut(&adapter_id)
        .expect("registration")
        .record_digest = digest("tampered-record");
    assert_ne!(
        original_record_digest,
        tampered_registry
            .registrations
            .get(&adapter_id)
            .expect("registration")
            .record_digest
    );
    assert!(matches!(
        CapabilityGateway::new(tampered_registry),
        Err(hartevo_capability_gateway::GatewayError::InvalidAdapterRegistry)
    ));
}

#[test]
fn uncertain_external_effect_is_reconcile_only_and_never_retried() {
    let (manifest, registry) = manifest_parts(
        CapabilityClass::ExternalEffect,
        "message.send",
        NetworkAuthority::EffectBroker {
            providers: BTreeSet::from(["mail".into()]),
        },
        EffectAuthority {
            allowed_kinds: BTreeSet::from([EffectKind::Outreach]),
            allowed_providers: BTreeSet::from(["mail".into()]),
            approval: ApprovalRequirement::Required,
            uncertain_policy: hartevo_capability_gateway::UncertainEffectPolicy::ReconcileOnly,
            max_cost: None,
            broker_policy_digest: digest("broker-policy"),
        },
    );
    let signed_manifest = signed(manifest.clone());
    let gateway = CapabilityGateway::new(registry).expect("gateway");
    let calls = Arc::new(AtomicUsize::new(0));
    let adapter = MockAdapter {
        binding: manifest.adapter.clone(),
        mode: MockMode::UncertainExternal,
        calls: calls.clone(),
    };
    let mut ledger = MemoryInvocationLedger::default();
    let manifest_digest = manifest.digest().expect("manifest digest");
    let authority_digest = manifest.authority_digest().expect("authority digest");
    let request = CapabilityRequest {
        schema: CAPABILITY_REQUEST_SCHEMA.into(),
        request_id: hartevo_capability_gateway::RequestId::from_stable("effect-request"),
        capability_id: manifest.capability_id.clone(),
        class: CapabilityClass::ExternalEffect,
        scope: InvocationScope::from_manifest(&manifest),
        generation: manifest.mission.generation,
        idempotency_key: hartevo_capability_gateway::IdempotencyKey::from_stable("send-once"),
        manifest_digest: manifest_digest.clone(),
        provenance: Provenance {
            source: ProvenanceSource::Runtime,
            manifest_digest,
            authority_digest,
            parent_digest: None,
            input_digest: digest("typed-effect-input"),
            generation: manifest.mission.generation,
            observed_at: now(),
            links: Vec::new(),
        },
        budget_use: budget_use(1),
        payload: hartevo_capability_gateway::RequestPayload::ExternalEffect(
            ExternalEffectRequest {
                effect_id: EffectId::from_stable("effect-a"),
                kind: EffectKind::Outreach,
                provider: "mail".into(),
                target_origin: hartevo_capability_gateway::Origin::parse("https://mail.example")
                    .expect("origin"),
                target_digest: digest("recipient-a"),
                payload: BoundedPayload::try_new(
                    "hartevo.message/v1",
                    DataClass::Business,
                    b"opaque-message-material".to_vec(),
                    1024,
                )
                .expect("effect payload"),
                audience_digest: Some(digest("audience-a")),
                amount: None,
                approval_required: ApprovalRequirement::Required,
                secret_references: BTreeSet::from([SecretReferenceId::from_stable(
                    "mail-secret-ref",
                )]),
            },
        ),
    };
    let first = gateway.dispatch_with_recovery(
        &signed_manifest,
        &request,
        &adapter,
        &mut ledger,
        now(),
        ToolSelfRecoveryPolicy::default(),
    );
    assert!(matches!(
        first,
        Err(hartevo_capability_gateway::GatewayError::Recovery(
            RecoveryDisposition::UncertainExternalEffect { .. }
        ))
    ));
    let second = gateway.dispatch_with_recovery(
        &signed_manifest,
        &request,
        &adapter,
        &mut ledger,
        now(),
        ToolSelfRecoveryPolicy::default(),
    );
    assert!(matches!(
        second,
        Err(hartevo_capability_gateway::GatewayError::Recovery(
            RecoveryDisposition::UncertainExternalEffect { .. }
        ))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn adapter_revocation_and_recovery_scope_are_fail_closed() {
    let (manifest, mut registry) = manifest_parts(
        CapabilityClass::Read,
        "project.inventory",
        NetworkAuthority::None,
        EffectAuthority::proposal_only(digest("broker-policy")),
    );
    let adapter_id = manifest.adapter.adapter_id.clone();
    registry.revoke(&adapter_id).expect("revoke");
    let gateway = CapabilityGateway::new(registry).expect("gateway");
    let request = read_request(&manifest, "request-revoked");
    let adapter = MockAdapter {
        binding: manifest.adapter.clone(),
        mode: MockMode::Read,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let mut ledger = MemoryInvocationLedger::default();
    let error = gateway
        .dispatch(
            &signed(manifest.clone()),
            &request,
            &adapter,
            &mut ledger,
            now(),
        )
        .expect_err("revoked adapter");
    assert!(matches!(
        error,
        hartevo_capability_gateway::GatewayError::AdapterRevoked
    ));

    let external_request = CapabilityRequest {
        class: CapabilityClass::ExternalEffect,
        ..request
    };
    assert!(matches!(
        RecoveryDisposition::retry_read(
            &external_request,
            hartevo_capability_gateway::ReadRecoveryReason::EmptyResult,
            0,
            1
        ),
        Err(hartevo_capability_gateway::GatewayError::RecoveryScopeViolation)
    ));
}

#[test]
fn authority_can_only_narrow_data_budget_and_effect_scope() {
    let (parent, _) = manifest_parts(
        CapabilityClass::Read,
        "project.inventory",
        NetworkAuthority::ReadOnly {
            origins: BTreeSet::from([hartevo_capability_gateway::Origin::parse(
                "https://research.example",
            )
            .expect("origin")]),
        },
        EffectAuthority::proposal_only(digest("broker-policy")),
    );
    let mut child = parent.clone();
    child.data.maximum_class = DataClass::Business;
    child.budget.max_tokens = 100;
    child.budget.max_request_bytes = 512;
    child.budget.max_result_bytes = 512;
    assert!(child.is_authority_subset_of(&parent).expect("subset"));
    child.budget.max_tokens = parent.budget.max_tokens + 1;
    assert!(!child.is_authority_subset_of(&parent).expect("not subset"));

    child = parent.clone();
    child.mission.task_id = None;
    assert!(
        !child
            .is_authority_subset_of(&parent)
            .expect("scope is not subset")
    );
}
