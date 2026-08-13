use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_domain_kernel::{ProjectId, TenantId};
use ring::signature::{Ed25519KeyPair, KeyPair};

use super::{
    AUTHORITY_SNAPSHOT_SCHEMA_VERSION, AuthorityKeyPurpose, AuthorityLifecycleState,
    AuthorityMutationKind, AuthorityOperation, AuthoritySignatureBundle,
    BrowserRecipeAuthorityError, BrowserRecipeAuthorityMutation, BrowserRecipeAuthoritySnapshot,
    ExistingKeyTarget, HumanOperationAuthorityReference, LEAF_POSSESSION_DOMAIN,
    LifecycleAuthorityBinding, LifecycleAuthorityKind, LifecycleDecision, NewLeafTarget,
    NewRootTarget, ROOT_POSSESSION_DOMAIN, ReplayedAuthoritySnapshot, RootRotationTargets,
    TrustedBrowserRecipeKey, canonical_public_key_digest,
};
use crate::{BrowserRecipeKeyPurpose, BrowserRecipeTrustStore};

const TENANT_ID: &str = "tenant-recipe-negative-lifecycle";
const PROJECT_ID: &str = "project-recipe-negative-lifecycle";
const CANDIDATE_KEY_ID: &str = "candidate-1";
const RELEASE_KEY_ID: &str = "release-1";

#[test]
#[ignore = "requires macOS, HARTEVO_TEST_CHROME_BINARY, mock Keychain, and loopback; explicit missing prerequisites panic BLOCKED_ENV"]
fn real_chromium_recipe_negative_lifecycle_smoke() {
    let keys = RootSigningKeys::new();
    assert_root_rotation_and_revocation(&keys);

    #[cfg(target_os = "macos")]
    macos::run(&keys);

    #[cfg(not(target_os = "macos"))]
    panic!("BLOCKED_ENV: reason=macos_required");
}

struct RootSigningKeys {
    root_one: Ed25519KeyPair,
    root_two: Ed25519KeyPair,
    candidate: Ed25519KeyPair,
    release: Ed25519KeyPair,
}

impl RootSigningKeys {
    fn new() -> Self {
        Self {
            root_one: must(
                Ed25519KeyPair::from_seed_unchecked(&[11; 32]),
                "root_one_signing_key",
            ),
            root_two: must(
                Ed25519KeyPair::from_seed_unchecked(&[13; 32]),
                "root_two_signing_key",
            ),
            candidate: must(
                Ed25519KeyPair::from_seed_unchecked(&[17; 32]),
                "candidate_signing_key",
            ),
            release: must(
                Ed25519KeyPair::from_seed_unchecked(&[29; 32]),
                "release_signing_key",
            ),
        }
    }
}

fn authority_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 13, 8, 0, 0)
        .single()
        .unwrap_or_else(|| fail("fixed_time_invalid"))
}

fn tenant_id() -> TenantId {
    TenantId::from(TENANT_ID)
}

fn project_id() -> ProjectId {
    ProjectId::from(PROJECT_ID)
}

fn public_key_hex(key: &Ed25519KeyPair) -> String {
    hex::encode(key.public_key().as_ref())
}

fn synthetic_human_reference() -> HumanOperationAuthorityReference {
    HumanOperationAuthorityReference {
        schema_version: "hartevo-human-operation-authority-contract/test-only-v1".into(),
        contract_version: "test-only-recipe-root-lifecycle/v1".into(),
        contract_digest: sha('b'),
        operation_kinds: vec!["recipe_root_lifecycle".into()],
    }
}

fn mutation(
    sequence: u64,
    recorded_at: DateTime<Utc>,
    operation: AuthorityOperation,
    signatures: impl FnOnce(&str) -> AuthoritySignatureBundle,
) -> BrowserRecipeAuthorityMutation {
    let kind = operation.kind();
    let target = operation.target();
    let mut mutation = BrowserRecipeAuthorityMutation {
        schema_version: AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
        tenant_id: tenant_id(),
        project_id: project_id(),
        mutation_id: format!("recipe-negative-lifecycle-{sequence}"),
        sequence,
        recorded_at,
        operation,
        lifecycle_authority: LifecycleAuthorityBinding {
            human_operation_authority: synthetic_human_reference(),
            authority_kind: LifecycleAuthorityKind::RecipeRootLifecycle,
            decision: LifecycleDecision::Approve,
            operation_kind: kind,
            tenant_id: tenant_id(),
            project_id: project_id(),
            target,
            issued_at: recorded_at - Duration::minutes(1),
            valid_until: recorded_at + Duration::minutes(5),
            operation_digest: String::new(),
            capability_digest: sha('c'),
            authority_digest: String::new(),
        },
        signatures: AuthoritySignatureBundle::RecordCompromise {},
    };
    let operation_digest = must(mutation.operation_digest(), "root_operation_digest");
    mutation.lifecycle_authority.operation_digest = operation_digest.clone();
    mutation.lifecycle_authority.authority_digest = must(
        mutation.lifecycle_authority.canonical_digest(),
        "root_authority_binding_digest",
    );
    mutation.signatures = signatures(&operation_digest);
    mutation
}

fn authorization_signature(
    key: &Ed25519KeyPair,
    kind: AuthorityMutationKind,
    operation_digest: &str,
) -> String {
    let payload = must(
        serde_json::to_vec(&(kind.domain(), tenant_id(), project_id(), operation_digest)),
        "root_authorization_payload",
    );
    hex::encode(key.sign(&payload).as_ref())
}

#[allow(clippy::too_many_arguments)]
fn possession_signature(
    key: &Ed25519KeyPair,
    domain: &'static str,
    operation_digest: &str,
    key_id: &str,
    purpose: AuthorityKeyPurpose,
    public_key_digest: &str,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
) -> String {
    let payload = must(
        serde_json::to_vec(&(
            domain,
            tenant_id(),
            project_id(),
            operation_digest,
            key_id,
            purpose,
            public_key_digest,
            valid_from,
            valid_until,
        )),
        "root_possession_payload",
    );
    hex::encode(key.sign(&payload).as_ref())
}

fn provision_root(
    sequence: u64,
    at: DateTime<Utc>,
    key_id: &str,
    generation: u64,
    key: &Ed25519KeyPair,
) -> BrowserRecipeAuthorityMutation {
    let valid_from = at - Duration::minutes(1);
    let valid_until = at + Duration::days(30);
    let public_key_hex = public_key_hex(key);
    let public_key_digest = must(
        canonical_public_key_digest(&public_key_hex),
        "root_public_key_digest",
    );
    mutation(
        sequence,
        at,
        AuthorityOperation::ProvisionRoot {
            target: NewRootTarget {
                root_key_id: key_id.into(),
                expected_absent: true,
            },
            generation,
            public_key_hex,
            valid_from,
            valid_until,
        },
        |operation_digest| AuthoritySignatureBundle::ProvisionRoot {
            root_self_possession_hex: possession_signature(
                key,
                ROOT_POSSESSION_DOMAIN,
                operation_digest,
                key_id,
                AuthorityKeyPurpose::RootAuthority,
                &public_key_digest,
                valid_from,
                valid_until,
            ),
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn authorize_leaf(
    sequence: u64,
    at: DateTime<Utc>,
    root_id: &str,
    root_revision: u64,
    root: &Ed25519KeyPair,
    leaf_id: &str,
    purpose: AuthorityKeyPurpose,
    leaf: &Ed25519KeyPair,
) -> BrowserRecipeAuthorityMutation {
    let valid_from = at;
    let valid_until = at + Duration::days(20);
    let leaf_public_key_hex = public_key_hex(leaf);
    let leaf_digest = must(
        canonical_public_key_digest(&leaf_public_key_hex),
        "leaf_public_key_digest",
    );
    mutation(
        sequence,
        at,
        AuthorityOperation::AuthorizeLeaf {
            authorizing_root: ExistingKeyTarget {
                key_id: root_id.into(),
                expected_revision: root_revision,
            },
            target: NewLeafTarget {
                leaf_key_id: leaf_id.into(),
                purpose,
                expected_absent: true,
            },
            public_key_hex: leaf_public_key_hex,
            valid_from,
            valid_until,
        },
        |operation_digest| AuthoritySignatureBundle::AuthorizeLeaf {
            current_root_authorization_hex: authorization_signature(
                root,
                AuthorityMutationKind::AuthorizeLeaf,
                operation_digest,
            ),
            new_leaf_possession_hex: possession_signature(
                leaf,
                LEAF_POSSESSION_DOMAIN,
                operation_digest,
                leaf_id,
                purpose,
                &leaf_digest,
                valid_from,
                valid_until,
            ),
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn rotate_root(
    sequence: u64,
    at: DateTime<Utc>,
    predecessor_id: &str,
    predecessor_revision: u64,
    predecessor: &Ed25519KeyPair,
    successor_id: &str,
    successor_generation: u64,
    successor: &Ed25519KeyPair,
) -> BrowserRecipeAuthorityMutation {
    let valid_from = at;
    let valid_until = at + Duration::days(30);
    let successor_public_key_hex = public_key_hex(successor);
    let successor_digest = must(
        canonical_public_key_digest(&successor_public_key_hex),
        "successor_public_key_digest",
    );
    mutation(
        sequence,
        at,
        AuthorityOperation::RotateRoot {
            target: RootRotationTargets {
                predecessor: ExistingKeyTarget {
                    key_id: predecessor_id.into(),
                    expected_revision: predecessor_revision,
                },
                successor: NewRootTarget {
                    root_key_id: successor_id.into(),
                    expected_absent: true,
                },
            },
            successor_generation,
            successor_public_key_hex,
            successor_valid_from: valid_from,
            successor_valid_until: valid_until,
        },
        |operation_digest| AuthoritySignatureBundle::RotateRoot {
            predecessor_root_authorization_hex: authorization_signature(
                predecessor,
                AuthorityMutationKind::RotateRoot,
                operation_digest,
            ),
            successor_root_possession_hex: possession_signature(
                successor,
                ROOT_POSSESSION_DOMAIN,
                operation_digest,
                successor_id,
                AuthorityKeyPurpose::RootAuthority,
                &successor_digest,
                valid_from,
                valid_until,
            ),
        },
    )
}

fn revoke_key(
    sequence: u64,
    at: DateTime<Utc>,
    root_id: &str,
    root_revision: u64,
    root: &Ed25519KeyPair,
    target_id: &str,
    target_revision: u64,
) -> BrowserRecipeAuthorityMutation {
    mutation(
        sequence,
        at,
        AuthorityOperation::RevokeKey {
            authorizing_root: ExistingKeyTarget {
                key_id: root_id.into(),
                expected_revision: root_revision,
            },
            target: ExistingKeyTarget {
                key_id: target_id.into(),
                expected_revision: target_revision,
            },
        },
        |operation_digest| AuthoritySignatureBundle::RevokeKey {
            current_root_authorization_hex: authorization_signature(
                root,
                AuthorityMutationKind::RevokeKey,
                operation_digest,
            ),
        },
    )
}

fn authority_snapshot(
    mutations: Vec<BrowserRecipeAuthorityMutation>,
    snapshot_as_of: DateTime<Utc>,
) -> BrowserRecipeAuthoritySnapshot {
    BrowserRecipeAuthoritySnapshot {
        schema_version: AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
        tenant_id: tenant_id(),
        project_id: project_id(),
        snapshot_revision: u64::try_from(mutations.len())
            .unwrap_or_else(|_| fail("root_snapshot_revision")),
        snapshot_as_of,
        mutations,
    }
}

fn replay_snapshot(
    snapshot: &BrowserRecipeAuthoritySnapshot,
    validation_at: DateTime<Utc>,
) -> Result<ReplayedAuthoritySnapshot, BrowserRecipeAuthorityError> {
    let expectation = must(snapshot.expectation(), "root_snapshot_expectation");
    ReplayedAuthoritySnapshot::replay(snapshot, validation_at, &expectation)
}

fn legacy_leaf(
    key_id: &str,
    purpose: BrowserRecipeKeyPurpose,
    key: &Ed25519KeyPair,
    valid_from: DateTime<Utc>,
) -> TrustedBrowserRecipeKey {
    must(
        TrustedBrowserRecipeKey::new(
            key_id,
            purpose,
            key.public_key().as_ref(),
            valid_from,
            valid_from + Duration::days(20),
        ),
        "legacy_leaf_contract",
    )
}

fn base_root_mutations(keys: &RootSigningKeys) -> Vec<BrowserRecipeAuthorityMutation> {
    let at = authority_time();
    vec![
        provision_root(1, at, "root-1", 1, &keys.root_one),
        authorize_leaf(
            2,
            at + Duration::minutes(1),
            "root-1",
            1,
            &keys.root_one,
            CANDIDATE_KEY_ID,
            AuthorityKeyPurpose::CandidatePublisher,
            &keys.candidate,
        ),
        authorize_leaf(
            3,
            at + Duration::minutes(2),
            "root-1",
            1,
            &keys.root_one,
            RELEASE_KEY_ID,
            AuthorityKeyPurpose::ProductionRelease,
            &keys.release,
        ),
        rotate_root(
            4,
            at + Duration::minutes(3),
            "root-1",
            1,
            &keys.root_one,
            "root-2",
            2,
            &keys.root_two,
        ),
    ]
}

fn assert_root_rotation_and_revocation(keys: &RootSigningKeys) {
    let at = authority_time();
    let rotated_mutations = base_root_mutations(keys);
    let rotated_snapshot = authority_snapshot(rotated_mutations.clone(), at + Duration::minutes(4));
    assert_rotated_root_snapshot(keys, &rotated_snapshot, at);
    assert_stale_root_rejected(keys, &rotated_mutations, at);
    assert_revoked_root_blocks_ancestry(keys, rotated_mutations, at);
}

fn assert_rotated_root_snapshot(
    keys: &RootSigningKeys,
    rotated_snapshot: &BrowserRecipeAuthoritySnapshot,
    at: DateTime<Utc>,
) {
    let rotated = must(
        replay_snapshot(rotated_snapshot, at + Duration::minutes(4)),
        "rotated_root_snapshot_replay",
    );
    if rotated.active_root_key_id.as_deref() != Some("root-2")
        || rotated.keys["root-1"].state != AuthorityLifecycleState::Retired
    {
        fail("rotated_root_state");
    }
    must(
        rotated.validate_legacy_leaf(
            &legacy_leaf(
                CANDIDATE_KEY_ID,
                BrowserRecipeKeyPurpose::CandidatePublisher,
                &keys.candidate,
                at + Duration::minutes(1),
            ),
            at + Duration::minutes(1),
        ),
        "rotated_candidate_ancestry",
    );
    must(
        rotated.validate_legacy_leaf(
            &legacy_leaf(
                RELEASE_KEY_ID,
                BrowserRecipeKeyPurpose::ProductionRelease,
                &keys.release,
                at + Duration::minutes(2),
            ),
            at + Duration::minutes(2),
        ),
        "rotated_release_ancestry",
    );
    assert_public_root_snapshot_fails_closed(
        rotated_snapshot,
        at + Duration::minutes(4),
        "rotated_public_boundary",
    );
}

fn assert_stale_root_rejected(
    keys: &RootSigningKeys,
    rotated_mutations: &[BrowserRecipeAuthorityMutation],
    at: DateTime<Utc>,
) {
    let stale_mutation = authorize_leaf(
        5,
        at + Duration::minutes(5),
        "root-1",
        2,
        &keys.root_one,
        "stale-release",
        AuthorityKeyPurpose::ProductionRelease,
        &keys.release,
    );
    let stale_snapshot = authority_snapshot(
        rotated_mutations
            .iter()
            .cloned()
            .chain([stale_mutation])
            .collect(),
        at + Duration::minutes(5),
    );
    assert_authority_error(
        replay_snapshot(&stale_snapshot, at + Duration::minutes(5)),
        &BrowserRecipeAuthorityError::InvalidRootHead,
        "stale_root_mutation_not_rejected",
    );
}

fn assert_revoked_root_blocks_ancestry(
    keys: &RootSigningKeys,
    rotated_mutations: Vec<BrowserRecipeAuthorityMutation>,
    at: DateTime<Utc>,
) {
    let revoked_snapshot = authority_snapshot(
        rotated_mutations
            .into_iter()
            .chain([revoke_key(
                5,
                at + Duration::minutes(5),
                "root-2",
                1,
                &keys.root_two,
                "root-1",
                2,
            )])
            .collect(),
        at + Duration::minutes(6),
    );
    let revoked = must(
        replay_snapshot(&revoked_snapshot, at + Duration::minutes(6)),
        "revoked_root_snapshot_replay",
    );
    if revoked.keys["root-1"].state != AuthorityLifecycleState::Revoked {
        fail("revoked_root_state");
    }
    assert_authority_error(
        revoked.validate_legacy_leaf(
            &legacy_leaf(
                CANDIDATE_KEY_ID,
                BrowserRecipeKeyPurpose::CandidatePublisher,
                &keys.candidate,
                at + Duration::minutes(1),
            ),
            at + Duration::minutes(1),
        ),
        &BrowserRecipeAuthorityError::ObservedKeyBlocked,
        "revoked_candidate_ancestry_not_blocked",
    );
    assert_authority_error(
        revoked.validate_legacy_leaf(
            &legacy_leaf(
                RELEASE_KEY_ID,
                BrowserRecipeKeyPurpose::ProductionRelease,
                &keys.release,
                at + Duration::minutes(2),
            ),
            at + Duration::minutes(2),
        ),
        &BrowserRecipeAuthorityError::ObservedKeyBlocked,
        "revoked_release_ancestry_not_blocked",
    );
    assert_public_root_snapshot_fails_closed(
        &revoked_snapshot,
        at + Duration::minutes(6),
        "revoked_public_boundary",
    );
}

fn assert_public_root_snapshot_fails_closed(
    snapshot: &BrowserRecipeAuthoritySnapshot,
    validation_at: DateTime<Utc>,
    label: &'static str,
) {
    let expectation = must(snapshot.expectation(), "public_root_snapshot_expectation");
    let snapshot_json = must(
        serde_json::to_string(snapshot),
        "public_root_snapshot_serialization",
    );
    assert_browser_error(
        BrowserRecipeTrustStore::validate_supplied_root_authority_snapshot(
            &snapshot_json,
            &expectation.tenant_id,
            &expectation.project_id,
            expectation.snapshot_revision,
            expectation.snapshot_as_of,
            &expectation.snapshot_digest,
            validation_at,
        ),
        "BROWSER_INVALID_RECIPE_KEY",
        label,
    );
}

fn assert_authority_error<T>(
    result: Result<T, BrowserRecipeAuthorityError>,
    expected: &BrowserRecipeAuthorityError,
    label: &'static str,
) {
    match result {
        Err(error) if &error == expected => {}
        Err(_) | Ok(_) => fail(label),
    }
}

fn assert_browser_error<T>(
    result: Result<T, crate::BrowserError>,
    expected_code: &'static str,
    label: &'static str,
) {
    match result {
        Err(error) if error.code() == expected_code => {}
        Err(_) | Ok(_) => fail(label),
    }
}

fn sha(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn must<T, E>(result: Result<T, E>, label: &'static str) -> T {
    result.unwrap_or_else(|_| fail(label))
}

#[track_caller]
fn fail(label: &'static str) -> ! {
    panic!("RECIPE_SMOKE_02_FAIL: step={label}")
}

#[cfg(target_os = "macos")]
mod macos {
    use std::collections::BTreeSet;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration as StdDuration, Instant};

    use chrono::{DateTime, Duration, Utc};
    use hartevo_domain_kernel::{
        AccountId, ActorId, Approval, ApprovalDecision, ApprovalId, BrowserActionBatchId,
        BrowserControlLeaseId, BrowserProfileId, BrowserRecipeId, BrowserSnapshotId, BrowserTabId,
        BrowserWorkspaceId, ConsentState, CurrencyCode, Effect, EffectClass, EffectId, EffectRisk,
        EffectStatus, Mission, MissionContract, MissionId, Money, Project, StorageMode, TenantId,
    };
    use ring::signature::KeyPair;
    use tempfile::TempDir;

    use super::{
        CANDIDATE_KEY_ID, PROJECT_ID, RELEASE_KEY_ID, RootSigningKeys, TENANT_ID,
        assert_browser_error, authority_time, fail, must, sha,
    };
    use crate::{
        BrowserAction, BrowserActionBatch, BrowserActionKind, BrowserActionRisk,
        BrowserActionSurface, BrowserIdentity, BrowserLeaseProof, BrowserLocatorResolution,
        BrowserNavigationPolicy, BrowserProfile, BrowserRecipeCandidate,
        BrowserRecipeEvaluationEvidence, BrowserRecipeExecutionAuthorization,
        BrowserRecipeKeyPurpose, BrowserRecipeManifest, BrowserRecipePreparedPlan,
        BrowserRecipePromotion, BrowserRecipeRegistry, BrowserRecipeRelease,
        BrowserRecipeResolvedAction, BrowserRecipeStep, BrowserRecipeTrustStore,
        BrowserStableLocator, BrowserWorkspace, ChromiumCredentialStoreMode, ChromiumLaunchConfig,
        ManagedChromiumClickExecutor, ManagedChromiumHost, TrustedBrowserRecipeKey,
    };

    const CHROME_ENV: &str = "HARTEVO_TEST_CHROME_BINARY";
    const RECIPE_ID: &str = "real-chromium-negative-lifecycle";
    const CLICK_CAPABILITY: &str = "browser.semantic_click";
    const WAIT_LIMIT: StdDuration = StdDuration::from_secs(5);
    const QUIET_LIMIT: StdDuration = StdDuration::from_millis(75);

    pub(super) fn run(keys: &RootSigningKeys) {
        let prerequisites = ExternalPrerequisites::acquire();
        let mut resources = SmokeResources::new(prerequisites);
        let body_result = catch_unwind(AssertUnwindSafe(|| run_smoke(&mut resources, keys)));
        let cleanup_result = resources.cleanup();

        match (body_result, cleanup_result) {
            (Ok(()), Ok(())) => {}
            (Err(payload), Ok(())) => resume_unwind(payload),
            (body, Err(step)) => panic!(
                "RECIPE_SMOKE_02_CLEANUP_FAILED: step={step} has_prior_failure={}",
                body.is_err()
            ),
        }
    }

    struct ExternalPrerequisites {
        executable: PathBuf,
        temp: TempDir,
        listener: TcpListener,
    }

    impl ExternalPrerequisites {
        fn acquire() -> Self {
            let executable = std::env::var_os(CHROME_ENV).map_or_else(
                || panic!("BLOCKED_ENV: reason=chrome_env_missing"),
                PathBuf::from,
            );
            let executable_exists = executable
                .try_exists()
                .unwrap_or_else(|_| panic!("BLOCKED_ENV: reason=chrome_path_unavailable"));
            assert!(executable_exists, "BLOCKED_ENV: reason=chrome_path_missing");
            let temp = TempDir::new()
                .unwrap_or_else(|_| panic!("BLOCKED_ENV: reason=private_temp_root_unavailable"));
            let listener = TcpListener::bind(("127.0.0.1", 0))
                .unwrap_or_else(|_| panic!("BLOCKED_ENV: reason=loopback_bind_unavailable"));
            Self {
                executable,
                temp,
                listener,
            }
        }
    }

    struct SmokeResources {
        executable: PathBuf,
        temp: Option<TempDir>,
        listener: Option<TcpListener>,
        server: Option<FixtureServer>,
        host: Option<ManagedChromiumHost>,
    }

    impl SmokeResources {
        fn new(prerequisites: ExternalPrerequisites) -> Self {
            Self {
                executable: prerequisites.executable,
                temp: Some(prerequisites.temp),
                listener: Some(prerequisites.listener),
                server: None,
                host: None,
            }
        }

        fn start_server(&mut self) {
            let listener = self
                .listener
                .take()
                .unwrap_or_else(|| fail("fixture_listener_missing"));
            self.server = Some(must(FixtureServer::start(listener), "fixture_thread_spawn"));
        }

        fn temp_root(&self) -> &Path {
            self.temp
                .as_ref()
                .map_or_else(|| fail("temp_root_missing"), TempDir::path)
        }

        fn server(&self) -> &FixtureServer {
            self.server
                .as_ref()
                .unwrap_or_else(|| fail("fixture_server_missing"))
        }

        fn host_mut(&mut self) -> &mut ManagedChromiumHost {
            self.host
                .as_mut()
                .unwrap_or_else(|| fail("chromium_host_missing"))
        }

        fn spawn_host(&mut self, domain: &BrowserDomain) {
            if self.host.is_some() {
                fail("chromium_host_already_running");
            }
            let config = must(
                ChromiumLaunchConfig::new(&self.executable, self.temp_root().to_path_buf(), true),
                "launch_config_contract",
            );
            let config = must(
                config.with_macos_mock_keychain_for_test(),
                "mock_keychain_contract",
            );
            self.host = Some(must(
                ManagedChromiumHost::spawn(
                    domain.profile.clone(),
                    domain.workspace.clone(),
                    &config,
                ),
                "chromium_host_spawn",
            ));
            assert_host_health(self.host_mut());
            must(
                self.host_mut().attach_about_blank_tab(
                    &domain.tab_id,
                    &domain.proof,
                    runtime_time(),
                ),
                "attach_about_blank_tab",
            );
        }

        fn stop_host(&mut self) {
            let mut host = self
                .host
                .take()
                .unwrap_or_else(|| fail("chromium_host_missing_for_stop"));
            match host.shutdown() {
                Ok(shutdown) if shutdown.success => {}
                Ok(_) | Err(_) => fail("chromium_host_shutdown"),
            }
        }

        fn cleanup(&mut self) -> Result<(), &'static str> {
            let mut first_failure = None;
            if let Some(mut host) = self.host.take() {
                match host.shutdown() {
                    Ok(shutdown) if shutdown.success => {}
                    Ok(_) | Err(_) => first_failure = Some("chromium_host_shutdown"),
                }
            }
            if let Some(mut server) = self.server.take()
                && server.shutdown().is_err()
                && first_failure.is_none()
            {
                first_failure = Some("fixture_server_shutdown");
            }
            self.listener.take();
            if let Some(temp) = self.temp.take()
                && temp.close().is_err()
                && first_failure.is_none()
            {
                first_failure = Some("private_temp_root_release");
            }
            first_failure.map_or(Ok(()), Err)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ClickCounts {
        root: usize,
        iframe: usize,
    }

    struct FixtureState {
        root_clicks: AtomicUsize,
        iframe_clicks: AtomicUsize,
        iframe_loads: AtomicUsize,
        signal: Mutex<()>,
        changed: Condvar,
    }

    impl FixtureState {
        fn new() -> Self {
            Self {
                root_clicks: AtomicUsize::new(0),
                iframe_clicks: AtomicUsize::new(0),
                iframe_loads: AtomicUsize::new(0),
                signal: Mutex::new(()),
                changed: Condvar::new(),
            }
        }

        fn counts(&self) -> ClickCounts {
            ClickCounts {
                root: self.root_clicks.load(Ordering::Acquire),
                iframe: self.iframe_clicks.load(Ordering::Acquire),
            }
        }

        fn iframe_loads(&self) -> usize {
            self.iframe_loads.load(Ordering::Acquire)
        }

        fn record(&self, route: FixtureRoute) {
            match route {
                FixtureRoute::RootClicked => {
                    self.root_clicks.fetch_add(1, Ordering::AcqRel);
                }
                FixtureRoute::IframeClicked => {
                    self.iframe_clicks.fetch_add(1, Ordering::AcqRel);
                }
                FixtureRoute::IframeChild => {
                    self.iframe_loads.fetch_add(1, Ordering::AcqRel);
                }
                FixtureRoute::Page | FixtureRoute::Other => {}
            }
            self.changed.notify_all();
        }

        fn wait_until(&self, label: &'static str, predicate: impl Fn() -> bool) {
            let deadline = Instant::now() + WAIT_LIMIT;
            let mut guard = self
                .signal
                .lock()
                .unwrap_or_else(|_| fail("fixture_barrier_poisoned"));
            while !predicate() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    fail(label);
                }
                let (next_guard, timeout) = self
                    .changed
                    .wait_timeout(guard, remaining)
                    .unwrap_or_else(|_| fail("fixture_barrier_poisoned"));
                guard = next_guard;
                if timeout.timed_out() && !predicate() {
                    fail(label);
                }
            }
        }

        fn assert_counts_stable(&self, expected: ClickCounts, label: &'static str) {
            let deadline = Instant::now() + QUIET_LIMIT;
            let mut guard = self
                .signal
                .lock()
                .unwrap_or_else(|_| fail("fixture_barrier_poisoned"));
            loop {
                if self.counts() != expected {
                    fail(label);
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return;
                }
                let (next_guard, _) = self
                    .changed
                    .wait_timeout(guard, remaining)
                    .unwrap_or_else(|_| fail("fixture_barrier_poisoned"));
                guard = next_guard;
            }
        }
    }

    struct ServerControl {
        stop: AtomicBool,
        signal: Mutex<()>,
        changed: Condvar,
        worker_failed: AtomicBool,
    }

    impl ServerControl {
        fn new() -> Self {
            Self {
                stop: AtomicBool::new(false),
                signal: Mutex::new(()),
                changed: Condvar::new(),
                worker_failed: AtomicBool::new(false),
            }
        }

        fn request_stop(&self) {
            self.stop.store(true, Ordering::Release);
            self.changed.notify_all();
        }
    }

    struct FixtureServer {
        address: std::net::SocketAddr,
        state: Arc<FixtureState>,
        control: Arc<ServerControl>,
        finished: Receiver<()>,
        thread: Option<JoinHandle<()>>,
    }

    impl FixtureServer {
        fn start(listener: TcpListener) -> std::io::Result<Self> {
            listener.set_nonblocking(true)?;
            let address = listener.local_addr()?;
            let state = Arc::new(FixtureState::new());
            let control = Arc::new(ServerControl::new());
            let worker_state = Arc::clone(&state);
            let worker_control = Arc::clone(&control);
            let (finished_tx, finished) = sync_channel(1);
            let thread = thread::Builder::new()
                .name("hartevo-recipe-negative-loopback".into())
                .spawn(move || {
                    serve(&listener, &worker_state, &worker_control);
                    let _ = finished_tx.send(());
                })?;
            Ok(Self {
                address,
                state,
                control,
                finished,
                thread: Some(thread),
            })
        }

        fn origin(&self) -> String {
            format!("http://{}", self.address)
        }

        fn url(&self, path: &str) -> String {
            format!("{}{path}", self.origin())
        }

        fn counts(&self) -> ClickCounts {
            self.state.counts()
        }

        fn iframe_loads(&self) -> usize {
            self.state.iframe_loads()
        }

        fn wait_for_iframe_after(&self, before: usize) {
            self.state
                .wait_until("iframe_load_timeout", || self.state.iframe_loads() > before);
        }

        fn assert_counts_stable(&self, expected: ClickCounts, label: &'static str) {
            self.state.assert_counts_stable(expected, label);
        }

        fn shutdown(&mut self) -> Result<(), ()> {
            self.control.request_stop();
            let completed = match self.finished.recv_timeout(StdDuration::from_secs(3)) {
                Ok(()) => true,
                Err(RecvTimeoutError::Disconnected) => false,
                Err(RecvTimeoutError::Timeout) => return Err(()),
            };
            let joined = self
                .thread
                .take()
                .is_some_and(|thread| thread.join().is_ok());
            if completed && joined && !self.control.worker_failed.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    impl Drop for FixtureServer {
        fn drop(&mut self) {
            self.control.request_stop();
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    #[derive(Clone, Copy)]
    enum FixtureRoute {
        Page,
        IframeChild,
        RootClicked,
        IframeClicked,
        Other,
    }

    fn serve(listener: &TcpListener, state: &FixtureState, control: &ServerControl) {
        while !control.stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => handle_connection(stream, state, control),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let guard = control
                        .signal
                        .lock()
                        .unwrap_or_else(|_| fail("fixture_control_poisoned"));
                    drop(
                        control
                            .changed
                            .wait_timeout(guard, StdDuration::from_millis(10)),
                    );
                }
                Err(_) => {
                    control.worker_failed.store(true, Ordering::Release);
                    return;
                }
            }
        }
    }

    fn handle_connection(mut stream: TcpStream, state: &FixtureState, control: &ServerControl) {
        if stream.set_nonblocking(true).is_err() {
            return;
        }
        let Some(path) = read_request_path(&mut stream, control) else {
            return;
        };
        let route = route_for(&path);
        state.record(route);
        write_bounded(&mut stream, &fixture_response(route), control);
    }

    fn read_request_path(stream: &mut TcpStream, control: &ServerControl) -> Option<String> {
        const REQUEST_LIMIT: usize = 8 * 1_024;
        let deadline = Instant::now() + StdDuration::from_secs(2);
        let mut request = Vec::with_capacity(512);
        let mut buffer = [0_u8; 512];
        loop {
            if control.stop.load(Ordering::Acquire) || Instant::now() >= deadline {
                return None;
            }
            match stream.read(&mut buffer) {
                Ok(0) => return None,
                Ok(read) => {
                    if request.len().saturating_add(read) > REQUEST_LIMIT {
                        return None;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if request.contains(&b'\n') {
                        let line_end = request.iter().position(|byte| *byte == b'\n')?;
                        let line = std::str::from_utf8(&request[..line_end]).ok()?;
                        return line.split_whitespace().nth(1).map(str::to_owned);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(StdDuration::from_millis(2));
                }
                Err(_) => return None,
            }
        }
    }

    fn write_bounded(stream: &mut TcpStream, response: &[u8], control: &ServerControl) {
        let deadline = Instant::now() + StdDuration::from_secs(2);
        let mut written = 0;
        while written < response.len()
            && !control.stop.load(Ordering::Acquire)
            && Instant::now() < deadline
        {
            match stream.write(&response[written..]) {
                Ok(0) => return,
                Ok(count) => written += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(StdDuration::from_millis(2));
                }
                Err(_) => return,
            }
        }
        let _ = stream.flush();
    }

    fn route_for(path: &str) -> FixtureRoute {
        match path.split('?').next().unwrap_or(path) {
            "/page" => FixtureRoute::Page,
            "/iframe-child" => FixtureRoute::IframeChild,
            "/clicked" => FixtureRoute::RootClicked,
            "/iframe-clicked" => FixtureRoute::IframeClicked,
            _ => FixtureRoute::Other,
        }
    }

    fn fixture_response(route: FixtureRoute) -> Vec<u8> {
        let (status, body) = match route {
            FixtureRoute::Page => (
                "200 OK",
                "<html><body><form action=\"/clicked\" method=\"get\"><button type=\"submit\" style=\"width:200px;height:60px\">Review</button></form><iframe src=\"/iframe-child\" title=\"Embedded review\"></iframe></body></html>",
            ),
            FixtureRoute::IframeChild => (
                "200 OK",
                "<html><body><form action=\"/iframe-clicked\" method=\"get\"><button type=\"submit\">Review</button></form></body></html>",
            ),
            FixtureRoute::RootClicked => (
                "200 OK",
                "<html><body><h1>Unexpected root input</h1></body></html>",
            ),
            FixtureRoute::IframeClicked => (
                "200 OK",
                "<html><body><h1>Unexpected iframe input</h1></body></html>",
            ),
            FixtureRoute::Other => ("404 Not Found", "not found"),
        };
        http_response(status, body)
    }

    fn http_response(status: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[derive(Clone)]
    struct BrowserDomain {
        project: Project,
        mission: Mission,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        proof: BrowserLeaseProof,
        tab_id: BrowserTabId,
    }

    struct LiveScope {
        domain: BrowserDomain,
        policy: BrowserNavigationPolicy,
        locator: BrowserStableLocator,
    }

    fn run_smoke(resources: &mut SmokeResources, keys: &RootSigningKeys) {
        resources.start_server();
        let domain = initial_domain(resources.temp_root(), runtime_time());
        let initial = start_live_scope(resources, domain, "negative-lifecycle-initial");
        let expected = ClickCounts { root: 0, iframe: 0 };
        if resources.server().counts() != expected {
            fail("fixture_initial_input_count");
        }

        reject_recipe_digest_drift(resources, &initial, keys);
        let reauthenticated = reject_profile_reauthentication(resources, &initial, keys);
        reject_restart_after_promotion_revocation(resources, &reauthenticated, keys);

        resources
            .server()
            .assert_counts_stable(expected, "negative_lifecycle_dispatched_input");
    }

    fn runtime_time() -> DateTime<Utc> {
        authority_time() + Duration::minutes(10)
    }

    fn initial_domain(private_root: &Path, now: DateTime<Utc>) -> BrowserDomain {
        let project = must(
            Project::create_local(
                TenantId::from(TENANT_ID),
                hartevo_domain_kernel::ProjectId::from(PROJECT_ID),
                "Signed Recipe Negative Lifecycle",
                "",
                private_root,
                StorageMode::LocalExisting,
            ),
            "project_scope",
        );
        let mission = must(
            Mission::compile(
                project.tenant_id.clone(),
                MissionId::from("mission-recipe-negative-lifecycle"),
                project.id.clone(),
                "Signed recipe negative lifecycle real Chromium smoke",
                MissionContract::bootstrap(
                    "Reject invalidated signed browser recipe lifecycle state",
                    [CLICK_CAPABILITY.into()],
                    now,
                ),
                now,
            ),
            "mission_scope",
        );
        make_domain(
            project,
            mission,
            BrowserProfileId::from("profile-recipe-negative-initial"),
            BrowserWorkspaceId::from("workspace-recipe-negative-initial"),
            BrowserTabId::from("tab-recipe-negative-initial"),
            BrowserControlLeaseId::from("lease-recipe-negative-initial"),
            sha('1'),
            sha('2'),
            sha('3'),
            now,
        )
    }

    fn reauthenticated_domain(previous: &BrowserDomain, now: DateTime<Utc>) -> BrowserDomain {
        make_domain(
            previous.project.clone(),
            previous.mission.clone(),
            BrowserProfileId::from("profile-recipe-negative-reauthenticated"),
            BrowserWorkspaceId::from("workspace-recipe-negative-reauthenticated"),
            BrowserTabId::from("tab-recipe-negative-reauthenticated"),
            BrowserControlLeaseId::from("lease-recipe-negative-reauthenticated"),
            sha('4'),
            sha('5'),
            sha('6'),
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn make_domain(
        project: Project,
        mission: Mission,
        profile_id: BrowserProfileId,
        workspace_id: BrowserWorkspaceId,
        tab_id: BrowserTabId,
        lease_id: BrowserControlLeaseId,
        identity_digest: String,
        probe_digest: String,
        lease_evidence_digest: String,
        now: DateTime<Utc>,
    ) -> BrowserDomain {
        let identity = must(
            BrowserIdentity::new(
                "real-chromium-recipe-negative",
                AccountId::from("account-recipe-negative"),
                identity_digest,
                probe_digest,
                now,
            ),
            "browser_identity",
        );
        let profile = must(
            BrowserProfile::create_managed(
                profile_id,
                &project,
                "keyring://browser/real-recipe-negative",
                identity,
                now,
            ),
            "browser_profile",
        );
        let workspace = must(
            BrowserWorkspace::create(
                workspace_id,
                &project,
                &mission,
                &profile,
                tab_id.clone(),
                lease_id,
                now + Duration::hours(1),
                lease_evidence_digest,
                now,
            ),
            "browser_workspace",
        );
        let proof = must(workspace.agent_lease_proof(now), "browser_lease_proof");
        BrowserDomain {
            project,
            mission,
            profile,
            workspace,
            proof,
            tab_id,
        }
    }

    fn start_live_scope(
        resources: &mut SmokeResources,
        domain: BrowserDomain,
        observation_id: &'static str,
    ) -> LiveScope {
        resources.spawn_host(&domain);
        let origin = resources.server().origin();
        let policy = must(
            BrowserNavigationPolicy::with_loopback_http_for_test([origin.as_str()]),
            "loopback_navigation_policy",
        );
        let navigation = navigate_page(resources, &domain, &policy);
        let snapshot = must(
            resources.host_mut().observe_ax(
                &domain.tab_id,
                &domain.proof,
                BrowserSnapshotId::from(observation_id),
                runtime_time(),
            ),
            "production_observation",
        );
        if snapshot.document_generation != navigation.document_generation {
            fail("observation_document_generation");
        }
        let locator = must(
            BrowserStableLocator::exact_accessible_name(
                &domain.workspace,
                domain.tab_id.clone(),
                &policy,
                navigation.final_origin_digest,
                "button",
                "Review",
                runtime_time(),
            ),
            "review_locator_contract",
        );
        LiveScope {
            domain,
            policy,
            locator,
        }
    }

    fn restart_live_scope(resources: &mut SmokeResources, scope: &LiveScope) {
        resources.spawn_host(&scope.domain);
        let navigation = navigate_page(resources, &scope.domain, &scope.policy);
        let snapshot = must(
            resources.host_mut().observe_ax(
                &scope.domain.tab_id,
                &scope.domain.proof,
                BrowserSnapshotId::from("negative-lifecycle-restarted"),
                runtime_time(),
            ),
            "restart_production_observation",
        );
        if snapshot.document_generation != navigation.document_generation {
            fail("restart_observation_document_generation");
        }
    }

    fn assert_host_health(host: &mut ManagedChromiumHost) {
        let health = must(host.health(), "chromium_health");
        if !health.product.contains("Chrome") && !health.product.contains("Chromium") {
            fail("chromium_product_contract");
        }
        if health.credential_store_mode != ChromiumCredentialStoreMode::MacOsMockForTest {
            fail("mock_keychain_mode");
        }
    }

    fn navigate_page(
        resources: &mut SmokeResources,
        domain: &BrowserDomain,
        policy: &BrowserNavigationPolicy,
    ) -> crate::BrowserNavigationReceipt {
        let iframe_before = resources.server().iframe_loads();
        let page_url = resources.server().url("/page");
        let target = must(policy.authorize(page_url), "page_navigation_target");
        let receipt = must(
            resources.host_mut().navigate_allowlisted(
                &domain.tab_id,
                &domain.proof,
                policy,
                &target,
                runtime_time(),
            ),
            "page_navigation",
        );
        if !receipt.script_execution_disabled {
            fail("page_script_execution_not_disabled");
        }
        resources.server().wait_for_iframe_after(iframe_before);
        receipt
    }

    fn resolve_case(
        resources: &mut SmokeResources,
        scope: &LiveScope,
        snapshot_id: &'static str,
    ) -> BrowserLocatorResolution {
        must(
            resources.host_mut().resolve_stable_locator(
                &scope.domain.tab_id,
                &scope.domain.proof,
                &scope.locator,
                BrowserSnapshotId::from(snapshot_id),
                runtime_time(),
            ),
            "production_locator_resolution",
        )
    }

    struct RecipeAuthority {
        trust: BrowserRecipeTrustStore,
        registry: BrowserRecipeRegistry,
        recipe_id: BrowserRecipeId,
    }

    impl RecipeAuthority {
        fn fresh(
            keys: &RootSigningKeys,
            profile: &BrowserProfile,
            origin_digest: &str,
            selector_digest: &str,
            now: DateTime<Utc>,
        ) -> Self {
            let trust = trust_store(keys);
            let recipe_id = BrowserRecipeId::from(RECIPE_ID);
            let release = signed_release(keys, profile, origin_digest, selector_digest, now);
            let mut registry = BrowserRecipeRegistry::default();
            must(
                registry.register_candidate(release.candidate.clone(), &trust, now),
                "candidate_registry_insert",
            );
            must(
                registry.register_release(release, &trust, now),
                "release_registry_insert",
            );
            must(
                registry.activate_release(&recipe_id, 1, None, &sha('d'), &trust, now),
                "recipe_activation",
            );
            Self {
                trust,
                registry,
                recipe_id,
            }
        }
    }

    fn trust_store(keys: &RootSigningKeys) -> BrowserRecipeTrustStore {
        // D-01A intentionally exposes snapshot validation without production
        // dispatch. The real-host cases therefore use the existing public trust
        // store with the exact same rooted leaf material proven above; this test
        // does not claim that root-snapshot admission is enabled.
        let at = authority_time();
        let mut trust = BrowserRecipeTrustStore::default();
        must(
            trust.insert(must(
                TrustedBrowserRecipeKey::new(
                    CANDIDATE_KEY_ID,
                    BrowserRecipeKeyPurpose::CandidatePublisher,
                    keys.candidate.public_key().as_ref(),
                    at + Duration::minutes(1),
                    at + Duration::minutes(1) + Duration::days(20),
                ),
                "candidate_trust_contract",
            )),
            "candidate_trust_insert",
        );
        must(
            trust.insert(must(
                TrustedBrowserRecipeKey::new(
                    RELEASE_KEY_ID,
                    BrowserRecipeKeyPurpose::ProductionRelease,
                    keys.release.public_key().as_ref(),
                    at + Duration::minutes(2),
                    at + Duration::minutes(2) + Duration::days(20),
                ),
                "release_trust_contract",
            )),
            "release_trust_insert",
        );
        trust
    }

    fn signed_release(
        keys: &RootSigningKeys,
        profile: &BrowserProfile,
        origin_digest: &str,
        selector_digest: &str,
        now: DateTime<Utc>,
    ) -> BrowserRecipeRelease {
        // `1` is the checked-in wire value. The public validation and signature
        // APIs below, not a copied private constant, enforce this contract.
        let manifest = BrowserRecipeManifest {
            schema_version: 1,
            id: BrowserRecipeId::from(RECIPE_ID),
            version: 1,
            provider: profile.identity.provider.clone(),
            origin_digest: origin_digest.to_owned(),
            capability: CLICK_CAPABILITY.into(),
            effect_class: EffectClass::ExternalWrite,
            steps: vec![BrowserRecipeStep {
                sequence: 1,
                kind: BrowserActionKind::Click,
                surface: BrowserActionSurface::Semantic,
                risk: BrowserActionRisk::PotentialExternalWrite,
                selector_digest: selector_digest.to_owned(),
            }],
            publisher_key_id: CANDIDATE_KEY_ID.into(),
            created_at: now - Duration::minutes(5),
            expires_at: now + Duration::days(15),
        };
        must(manifest.validate(), "recipe_manifest_public_validation");
        let candidate_payload = must(
            BrowserRecipeCandidate::signing_payload(&manifest),
            "candidate_signing_payload",
        );
        let candidate = must(
            BrowserRecipeCandidate::new(
                manifest,
                hex::encode(keys.candidate.sign(&candidate_payload).as_ref()),
            ),
            "candidate_constructor",
        );
        let evidence = evaluation_evidence();
        let candidate_digest = must(candidate.digest(), "candidate_digest");
        let promoted_at = now - Duration::minutes(2);
        let expires_at = now + Duration::days(14);
        let promotion_payload = must(
            BrowserRecipePromotion::signing_payload(
                &candidate_digest,
                &evidence,
                RELEASE_KEY_ID,
                promoted_at,
                expires_at,
            ),
            "promotion_signing_payload",
        );
        let release = BrowserRecipeRelease {
            candidate,
            promotion: BrowserRecipePromotion {
                // This checked-in wire value is enforced by public release verification.
                schema_version: 1,
                candidate_digest,
                evidence,
                release_key_id: RELEASE_KEY_ID.into(),
                promoted_at,
                expires_at,
                signature_hex: hex::encode(keys.release.sign(&promotion_payload).as_ref()),
            },
        };
        let verification_trust = trust_store(keys);
        must(
            release.candidate.verify(&verification_trust, now),
            "candidate_public_verification",
        );
        must(
            release.verify(&verification_trust, now),
            "release_public_verification",
        );
        release
    }

    fn evaluation_evidence() -> BrowserRecipeEvaluationEvidence {
        BrowserRecipeEvaluationEvidence {
            v1_dataset_revision: "recipe-negative-v1-holdout".into(),
            v1_result_digest: sha('7'),
            v1_passed: 9,
            v1_total: 10,
            v2_dataset_revision: "recipe-negative-v2-shadow".into(),
            v2_result_digest: sha('8'),
            v2_passed: 4,
            v2_total: 5,
            safety_suite_digest: sha('9'),
            contamination_audit_digest: sha('a'),
            rollback_strategy_digest: sha('b'),
            promotion_approval_digest: sha('c'),
        }
    }

    struct PreparedExecution {
        plan: BrowserRecipePreparedPlan,
        batch: BrowserActionBatch,
        resolution: BrowserLocatorResolution,
    }

    fn prepare_execution(
        authority: &RecipeAuthority,
        scope: &LiveScope,
        resolution: BrowserLocatorResolution,
        case_id: &'static str,
    ) -> PreparedExecution {
        let now = resolution.resolved_at;
        let action = must(
            BrowserAction::semantic_click(1, &resolution),
            "semantic_click_action",
        );
        let actions = vec![action];
        let plan = must(
            authority.registry.prepare_active_plan(
                &authority.recipe_id,
                &authority.trust,
                &scope.domain.profile,
                &scope.domain.workspace,
                scope.policy.evidence_digest().to_owned(),
                &[BrowserRecipeResolvedAction {
                    action: &actions[0],
                    resolution: &resolution,
                }],
                now,
                now + Duration::minutes(5),
            ),
            "active_recipe_plan_prepare",
        );
        let effect = approved_effect(scope, &plan, case_id, now);
        let batch = must(
            BrowserActionBatch::for_recipe_effect(
                BrowserActionBatchId::from_stable(format!("batch-{case_id}")),
                &scope.domain.profile,
                &scope.domain.workspace,
                scope.domain.proof.clone(),
                scope.policy.evidence_digest().to_owned(),
                actions,
                &plan,
                &authority.registry,
                &authority.trust,
                &effect,
                now,
                now + Duration::minutes(5),
            ),
            "recipe_effect_batch",
        );
        validate_prepared_contract(authority, &plan, &batch, &effect, now);
        PreparedExecution {
            plan,
            batch,
            resolution,
        }
    }

    fn approved_effect(
        scope: &LiveScope,
        plan: &BrowserRecipePreparedPlan,
        case_id: &'static str,
        now: DateTime<Utc>,
    ) -> Effect {
        let mut effect = Effect {
            id: EffectId::from_stable(format!("effect-{case_id}")),
            tenant_id: scope.domain.workspace.tenant_id.clone(),
            project_id: scope.domain.workspace.project_id.clone(),
            mission_id: scope.domain.workspace.mission_id.clone(),
            actor_id: ActorId::from("actor-recipe-negative"),
            capability: plan.capability.clone(),
            provider: plan.provider.clone(),
            connection_id: None,
            account_id: Some(scope.domain.profile.identity.account_id.clone()),
            required_scopes: BTreeSet::from(["browser.click".into()]),
            effect_class: plan.effect_class.clone(),
            description: "Reject invalidated synthetic Review control".into(),
            target_resource: "synthetic-review-control".into(),
            audience_digest: None,
            payload_digest: plan.effect_payload_digest.clone(),
            asset_digests: BTreeSet::new(),
            scheduled_for: None,
            timezone: "UTC".into(),
            consent: ConsentState::NotRequired,
            consent_record_id: None,
            consent_requirement: None,
            conversation_guard: None,
            creator_contact_guard: None,
            policy_version: "recipe-negative-policy-v1".into(),
            risk: EffectRisk::Medium,
            idempotency_key: format!("recipe-negative:{case_id}"),
            amount: Money::zero(must(CurrencyCode::parse("USD"), "currency_contract")),
            expires_at: now + Duration::minutes(10),
            status: EffectStatus::Approved,
            approval: None,
            receipt: None,
            verification: None,
        };
        let scope_digest = effect.approval_digest();
        effect.approval = Some(Approval {
            id: ApprovalId::from_stable(format!("approval-{case_id}")),
            decision: ApprovalDecision::Approved,
            decided_by: ActorId::from("approver-recipe-negative"),
            decided_at: now,
            valid_until: now + Duration::minutes(10),
            scope_digest,
            permission_digest: sha('e'),
        });
        effect
    }

    fn validate_prepared_contract(
        authority: &RecipeAuthority,
        plan: &BrowserRecipePreparedPlan,
        batch: &BrowserActionBatch,
        effect: &Effect,
        now: DateTime<Utc>,
    ) {
        let authorization = must(
            BrowserRecipeExecutionAuthorization::new(
                plan.clone(),
                &authority.registry,
                &authority.trust,
                batch,
                now,
            ),
            "recipe_authorization_constructor",
        );
        must(
            authorization.validate_batch(batch, now),
            "recipe_authorization_validate_batch",
        );
        must(
            authorization.validate_effect(batch, effect, now),
            "recipe_authorization_validate_effect",
        );
        must(batch.validate_effect(effect, now), "batch_validate_effect");
        assert_named_digest(
            "batch_plan_vs_prepared_effect_payload",
            &batch.plan_digest,
            &plan.effect_payload_digest,
        );
        assert_named_digest(
            "prepared_effect_payload_vs_effect_payload",
            &plan.effect_payload_digest,
            &effect.payload_digest,
        );
    }

    fn assert_named_digest(label: &'static str, left: &str, right: &str) {
        if left != right {
            fail(label);
        }
    }

    fn reject_recipe_digest_drift(
        resources: &mut SmokeResources,
        scope: &LiveScope,
        keys: &RootSigningKeys,
    ) {
        let before = resources.server().counts();
        let resolution = resolve_case(resources, scope, "negative-recipe-digest-drift");
        let now = resolution.resolved_at;
        let authority = RecipeAuthority::fresh(
            keys,
            &scope.domain.profile,
            &resolution.origin_digest,
            &resolution.selector_digest,
            now,
        );
        let prepared = prepare_execution(&authority, scope, resolution, "recipe-digest-drift");
        let mut drifted_plan = prepared.plan.clone();
        drifted_plan.release_digest = sha('0');
        assert_browser_error(
            drifted_plan.validate_for(
                &scope.domain.profile,
                &scope.domain.workspace,
                &prepared.batch.actions,
                now,
            ),
            "BROWSER_RECIPE_SCOPE_MISMATCH",
            "recipe_digest_drift_plan_not_rejected",
        );
        assert_constructor_rejected(
            resources.host_mut(),
            prepared.batch,
            prepared.resolution,
            drifted_plan,
            &authority.registry,
            &authority.trust,
            "BROWSER_RECIPE_SCOPE_MISMATCH",
            "recipe_digest_drift_constructor_not_rejected",
        );
        resources
            .server()
            .assert_counts_stable(before, "recipe_digest_drift_dispatched_input");
    }

    fn reject_profile_reauthentication(
        resources: &mut SmokeResources,
        initial: &LiveScope,
        keys: &RootSigningKeys,
    ) -> LiveScope {
        let before = resources.server().counts();
        let resolution = resolve_case(resources, initial, "negative-profile-reauth");
        let now = resolution.resolved_at;
        let authority = RecipeAuthority::fresh(
            keys,
            &initial.domain.profile,
            &resolution.origin_digest,
            &resolution.selector_digest,
            now,
        );
        let prepared = prepare_execution(&authority, initial, resolution, "profile-reauth");

        resources.stop_host();
        let reauthenticated_domain = reauthenticated_domain(&initial.domain, now);
        let reauthenticated = start_live_scope(
            resources,
            reauthenticated_domain,
            "negative-lifecycle-reauthenticated",
        );
        assert_browser_error(
            prepared.plan.validate_for(
                &reauthenticated.domain.profile,
                &reauthenticated.domain.workspace,
                &prepared.batch.actions,
                now,
            ),
            "BROWSER_RECIPE_SCOPE_MISMATCH",
            "profile_reauth_plan_not_rejected",
        );
        assert_constructor_rejected(
            resources.host_mut(),
            prepared.batch,
            prepared.resolution,
            prepared.plan,
            &authority.registry,
            &authority.trust,
            "BROWSER_INVALID_BATCH",
            "profile_reauth_constructor_not_rejected",
        );
        resources
            .server()
            .assert_counts_stable(before, "profile_reauth_dispatched_input");
        reauthenticated
    }

    fn reject_restart_after_promotion_revocation(
        resources: &mut SmokeResources,
        scope: &LiveScope,
        keys: &RootSigningKeys,
    ) {
        let before = resources.server().counts();
        let resolution = resolve_case(resources, scope, "negative-restart-promotion");
        let now = resolution.resolved_at;
        let mut authority = RecipeAuthority::fresh(
            keys,
            &scope.domain.profile,
            &resolution.origin_digest,
            &resolution.selector_digest,
            now,
        );
        let prepared = prepare_execution(&authority, scope, resolution, "restart-promotion");
        let registry_snapshot = must(authority.registry.snapshot(), "restart_registry_snapshot");
        must(
            authority.trust.revoke(RELEASE_KEY_ID, 1, now),
            "restart_release_key_revoke",
        );
        let trust_snapshot = authority.trust.snapshot();

        resources.stop_host();
        restart_live_scope(resources, scope);
        let restored_trust = must(
            BrowserRecipeTrustStore::restore(trust_snapshot),
            "restart_trust_restore",
        );
        let restored_registry = must(
            BrowserRecipeRegistry::restore(registry_snapshot, &restored_trust),
            "restart_registry_restore",
        );
        assert_constructor_rejected(
            resources.host_mut(),
            prepared.batch,
            prepared.resolution,
            prepared.plan,
            &restored_registry,
            &restored_trust,
            "BROWSER_RECIPE_KEY_REVOKED",
            "restart_promotion_not_invalidated",
        );
        resources
            .server()
            .assert_counts_stable(before, "restart_promotion_dispatched_input");
    }

    #[allow(clippy::too_many_arguments)]
    fn assert_constructor_rejected(
        host: &mut ManagedChromiumHost,
        batch: BrowserActionBatch,
        resolution: BrowserLocatorResolution,
        plan: BrowserRecipePreparedPlan,
        registry: &BrowserRecipeRegistry,
        trust: &BrowserRecipeTrustStore,
        expected_code: &'static str,
        label: &'static str,
    ) {
        match ManagedChromiumClickExecutor::new_for_recipe(
            host,
            batch,
            resolution,
            plan,
            registry,
            trust,
            runtime_time(),
        ) {
            Err(error) if error.code() == expected_code => {}
            Err(_) | Ok(_) => fail(label),
        }
    }
}
