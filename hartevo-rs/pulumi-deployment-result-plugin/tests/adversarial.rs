use std::collections::{BTreeMap, BTreeSet};

use hartevo_pulumi_deployment_result_plugin::*;

fn digest(seed: u8) -> String {
    format!("sha256:{seed:064x}")
}

fn scope() -> PulumiDeploymentScope {
    PulumiDeploymentScope::new(
        default_pulumi_cloud_endpoint().expect("endpoint"),
        "acme",
        3,
        "platform",
        5,
        "production",
        9,
        "deployment-17",
        PulumiSourceScope::new(
            "https://github.com/acme/platform",
            Some("main".into()),
            Some("infra".into()),
            "commit-abc123",
        )
        .expect("source"),
        PulumiUpdateScope::new("update-17", 7).expect("update"),
        PulumiPolicyScope::new(digest(9), 4).expect("policy"),
        "hartevo-project",
        "mission-17",
        "work-product-17",
        11,
        13,
        17,
        PermissionSnapshot::read_only_default("permissions-r3").expect("permissions"),
    )
    .expect("scope")
}

fn secret(scope: &PulumiDeploymentScope) -> SecretReference {
    SecretReference::for_scope("pulumi-secret-reference", 2, scope.digest().as_str())
        .expect("opaque scoped secret reference")
}

fn policy(scope: &PulumiDeploymentScope) -> PulumiPolicyEvidence {
    PulumiPolicyEvidence {
        policy_digest: scope.policy.policy_digest.clone(),
        policy_revision: scope.policy.policy_revision,
        status: PulumiPolicyStatus::Passed,
        policy_pack_count: 2,
        violation_count: 0,
        findings_digest: Some(Digest::from_text("policy-findings")),
        evaluated_at: 119,
        redacted: true,
    }
}

fn update(scope: &PulumiDeploymentScope, status: PulumiUpdateStatus) -> PulumiUpdateEvidence {
    PulumiUpdateEvidence {
        update_id: scope.update.update_id.clone(),
        version: scope.update.version,
        status,
        started_at: Some(105),
        finished_at: Some(118),
        resource_change_counts: BTreeMap::from([(String::from("update"), 2)]),
        result_digest: Some(Digest::from_text("update-result")),
    }
}

fn audit() -> PulumiAuditEvidence {
    PulumiAuditEvidence {
        audit_id: "audit-17".into(),
        event: "deployment.read".into(),
        occurred_at: 119,
        actor_digest: Digest::from_text("actor-17"),
        provider_request_id: Some("request-audit-17".into()),
        details_digest: Some(Digest::from_text("audit-details")),
        redacted: true,
    }
}

fn api_status(status: PulumiDeploymentStatus) -> PulumiDeploymentApiRecord {
    let scope = scope();
    let mut transitions = Vec::new();
    if status != PulumiDeploymentStatus::NotStarted {
        transitions.push(StatusTransition {
            from: PulumiDeploymentStatus::NotStarted,
            to: status,
            occurred_at: 105,
        });
    }
    PulumiDeploymentApiRecord {
        provider_request_id: "request-deployment-17".into(),
        deployment_id: scope.deployment_id.clone(),
        organization: scope.organization.clone(),
        pulumi_project: scope.pulumi_project.clone(),
        stack: scope.stack.clone(),
        status,
        operation: PulumiOperation::Update,
        created_at: 100,
        modified_at: 120,
        version: scope.update.version,
        latest_version: scope.update.version,
        source: scope.source.clone(),
        update: scope.update.clone(),
        jobs: vec![PulumiJobEvidence {
            job_id: "job-17".into(),
            status,
            started_at: Some(106),
            last_updated_at: 118,
            steps: vec![PulumiStepEvidence {
                step_id: "step-17".into(),
                name: "pulumi-update".into(),
                status: PulumiStepStatus::Succeeded,
                started_at: Some(107),
                last_updated_at: 117,
                message_digest: Some(Digest::from_text("redacted-step-message")),
                redacted: true,
            }],
        }],
        status_transitions: transitions,
        redacted_fields: BTreeSet::from([String::from("logs"), String::from("requestedBy.email")]),
        truncated: false,
    }
}

fn stack_record(scope: &PulumiDeploymentScope) -> PulumiStackApiRecord {
    PulumiStackApiRecord {
        organization: scope.organization.clone(),
        organization_revision: scope.organization_revision,
        pulumi_project: scope.pulumi_project.clone(),
        pulumi_project_revision: scope.pulumi_project_revision,
        stack: scope.stack.clone(),
        stack_revision: scope.stack_revision,
        deployment_settings_revision: Some(3),
        permissions: scope.permissions.clone(),
        provider_request_id: Some("request-stack-17".into()),
    }
}

fn service_with_status(
    status: PulumiDeploymentStatus,
) -> PulumiDeploymentResultService<RecordingPulumiCloudTransport, StaticPulumiCredentialResolver> {
    service_with_provenance(status, EvidenceProvenance::Recording)
}

fn service_with_provenance(
    status: PulumiDeploymentStatus,
    provenance: EvidenceProvenance,
) -> PulumiDeploymentResultService<RecordingPulumiCloudTransport, StaticPulumiCredentialResolver> {
    let scope = scope();
    let secret = secret(&scope);
    let registration = PulumiDeploymentResultRegistration::new(&scope, &secret, "adapter-r1", 1)
        .expect("registration");
    let mut transport = RecordingPulumiCloudTransport::new(provenance);
    transport.set_description(Ok(stack_record(&scope)));
    transport.set_deployment(Ok(api_status(status)));
    transport.push_update_page(Ok(PulumiUpdatePage {
        items: vec![update(
            &scope,
            if status == PulumiDeploymentStatus::Succeeded {
                PulumiUpdateStatus::Succeeded
            } else {
                PulumiUpdateStatus::Running
            },
        )],
        next_cursor: None,
    }));
    transport.set_policy(Ok(policy(&scope)));
    transport.push_audit_page(Ok(PulumiAuditPage {
        items: vec![audit()],
        next_cursor: None,
    }));
    let provider = PulumiCloudProvider::new(
        registration,
        secret,
        transport,
        StaticPulumiCredentialResolver::new("super-secret-pulumi-token"),
    )
    .expect("provider");
    PulumiDeploymentResultService::new(provider).expect("service")
}

#[test]
fn contract_registration_and_authority_are_layer_one_only() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(contract["properties"]["layer"]["const"], 1);
    assert_eq!(
        contract["properties"]["service"]["properties"]["externalWrites"]["const"],
        false
    );
    assert_eq!(
        contract["properties"]["service"]["properties"]["outcomeAdoption"]["const"],
        false
    );
    assert_eq!(
        contract["properties"]["provider"]["properties"]["connectedEvidence"]["const"],
        false
    );
    assert_eq!(
        contract["properties"]["nativeGap"]["properties"]["status"]["const"],
        "BLOCKED_ENV"
    );
    assert!(!ReadOnlyAuthority::store());
    assert!(!ReadOnlyAuthority::keyring());
    assert!(!ReadOnlyAuthority::external_writes());
    assert!(!ReadOnlyAuthority::raw_logs());
    assert!(!ReadOnlyAuthority::raw_state());
    assert!(!ReadOnlyAuthority::raw_secrets());
    assert!(!ReadOnlyAuthority::outcome_adoption());

    let scope = scope();
    let secret = secret(&scope);
    let registration = PulumiDeploymentResultRegistration::new(&scope, &secret, "adapter-r1", 1)
        .expect("registration");
    assert_eq!(registration.scope, scope);
    assert_eq!(
        registration.permission_snapshot_digest,
        *scope.permissions.digest()
    );
    assert_eq!(registration.auth_kind, AuthKind::AccessToken);
    assert!(registration.is_active());
}

#[test]
fn recording_path_reads_exact_evidence_and_consumes_a_non_outcome_proposal() {
    let mut service = service_with_status(PulumiDeploymentStatus::Succeeded);
    let description = service.describe_stack().expect("stack description");
    assert_eq!(description.scope.stack, "production");
    assert!(!description.connected);
    assert!(!description.native);

    let evidence = service
        .read_deployment_evidence()
        .expect("deployment evidence");
    evidence.validate().expect("evidence validates");
    assert_eq!(evidence.status, PulumiDeploymentStatus::Succeeded);
    assert_eq!(evidence.updates.len(), 1);
    assert_eq!(evidence.audit.len(), 1);
    assert_eq!(evidence.pages_read, 3);
    assert_eq!(evidence.provenance, EvidenceProvenance::Recording);
    assert!(!evidence.connected);
    assert!(!evidence.native);

    let receipt = service
        .record_deployment_receipt(&evidence)
        .expect("record receipt");
    receipt.validate().expect("receipt validates");
    assert!(!receipt.write_receipt);
    assert!(!receipt.durable_readback);
    assert!(!receipt.native_connected);

    let proposal = service
        .verify_deployment_result(&evidence, &receipt)
        .expect("verified proposal");
    proposal.validate().expect("proposal validates");
    assert_eq!(
        proposal.verification_status,
        ResultVerificationStatus::Verified
    );
    assert!(!proposal.outcome_adoption);
    assert_eq!(proposal.authority, "mission_result_proposal");

    let consumer = MissionPulumiDeploymentConsumer::from_registration(service.registration())
        .expect("consumer");
    let result = consumer
        .consume_result(&proposal)
        .expect("Mission proposal");
    result.validate().expect("Mission result validates");
    assert_eq!(result.mission_id, "mission-17");
    assert!(!result.kernel_authority);
    assert!(!result.outcome_adoption);

    let debug = format!(
        "{service:?} {:?} {:?}",
        service.provider(),
        service.provider().secret_reference()
    );
    assert!(!debug.contains("super-secret-pulumi-token"));
    assert!(!debug.contains("pulumi-secret-reference"));
}

#[test]
fn fake_and_loopback_transports_remain_non_native_and_permission_drift_is_blocked() {
    for provenance in [EvidenceProvenance::Fixture, EvidenceProvenance::Loopback] {
        let mut service = service_with_provenance(PulumiDeploymentStatus::Succeeded, provenance);
        let evidence = service
            .read_deployment_evidence()
            .expect("bounded fixture evidence");
        assert_eq!(evidence.provenance, provenance);
        assert!(!evidence.provenance.is_connected());
        assert!(!evidence.provenance.is_native());
        let receipt = service
            .record_deployment_receipt(&evidence)
            .expect("recording");
        let proposal = service
            .verify_deployment_result(&evidence, &receipt)
            .expect("proposal");
        assert!(!proposal.connected);
        assert!(!proposal.native);
    }
    assert_eq!(
        PulumiCloudFakeTransport::fake().provenance(),
        EvidenceProvenance::Fixture
    );
    assert_eq!(
        PulumiCloudLoopbackTransport::loopback().provenance(),
        EvidenceProvenance::Loopback
    );

    let mut service = service_with_status(PulumiDeploymentStatus::Succeeded);
    let mut record = stack_record(service.scope());
    record.permissions =
        PermissionSnapshot::read_only_default("permissions-drifted").expect("permission snapshot");
    service
        .provider_mut()
        .transport_mut()
        .set_description(Ok(record));
    assert!(matches!(
        service.describe_stack(),
        Err(PulumiDeploymentResultError::PermissionDrift)
    ));
}

#[test]
fn every_provider_status_is_typed_without_becoming_connected() {
    for status in [
        PulumiDeploymentStatus::NotStarted,
        PulumiDeploymentStatus::Accepted,
        PulumiDeploymentStatus::Running,
        PulumiDeploymentStatus::Succeeded,
        PulumiDeploymentStatus::Failed,
        PulumiDeploymentStatus::Skipped,
        PulumiDeploymentStatus::Cancelled,
        PulumiDeploymentStatus::Drift,
        PulumiDeploymentStatus::Partial,
    ] {
        let mut service = service_with_status(status);
        let evidence = service.read_deployment_evidence().expect("typed status");
        assert_eq!(evidence.status, status);
        assert!(!evidence.provenance.is_connected());
        let receipt = service
            .record_deployment_receipt(&evidence)
            .expect("receipt");
        let proposal = service
            .verify_deployment_result(&evidence, &receipt)
            .expect("proposal");
        assert_eq!(proposal.status, status);
        assert!(!proposal.native);
        assert!(!proposal.connected);
        match status {
            PulumiDeploymentStatus::NotStarted
            | PulumiDeploymentStatus::Accepted
            | PulumiDeploymentStatus::Running => {
                assert_eq!(
                    proposal.verification_status,
                    ResultVerificationStatus::Pending
                );
            }
            PulumiDeploymentStatus::Succeeded => {
                assert_eq!(
                    proposal.verification_status,
                    ResultVerificationStatus::Verified
                );
            }
            _ => assert_eq!(
                proposal.verification_status,
                ResultVerificationStatus::Failed
            ),
        }
    }

    let mut unknown = service_with_status(PulumiDeploymentStatus::ProviderUnknown);
    let evidence = unknown
        .read_deployment_evidence()
        .expect("unknown status remains typed evidence");
    let receipt = unknown
        .record_deployment_receipt(&evidence)
        .expect("unknown receipt");
    let proposal = unknown
        .verify_deployment_result(&evidence, &receipt)
        .expect("unknown proposal");
    assert_eq!(
        proposal.verification_status,
        ResultVerificationStatus::ProviderUnknown
    );
}

#[test]
fn source_stack_update_and_policy_revision_fences_fail_closed() {
    let mut service = service_with_status(PulumiDeploymentStatus::Succeeded);
    let mut record = api_status(PulumiDeploymentStatus::Succeeded);
    record.source.commit_sha = "different-commit".into();
    service
        .provider_mut()
        .transport_mut()
        .set_deployment(Ok(record));
    assert!(matches!(
        service.read_deployment_evidence(),
        Err(PulumiDeploymentResultError::CommitMismatch)
    ));

    let mut service = service_with_status(PulumiDeploymentStatus::Succeeded);
    let mut record = api_status(PulumiDeploymentStatus::Succeeded);
    record.stack = "staging".into();
    service
        .provider_mut()
        .transport_mut()
        .set_deployment(Ok(record));
    assert!(matches!(
        service.read_deployment_evidence(),
        Err(PulumiDeploymentResultError::StackMismatch)
    ));

    let mut service = service_with_status(PulumiDeploymentStatus::Succeeded);
    let mut record = api_status(PulumiDeploymentStatus::Succeeded);
    record.update.version += 1;
    service
        .provider_mut()
        .transport_mut()
        .set_deployment(Ok(record));
    assert!(matches!(
        service.read_deployment_evidence(),
        Err(PulumiDeploymentResultError::UpdateMismatch)
    ));

    let mut service = service_with_status(PulumiDeploymentStatus::Succeeded);
    let current_policy = policy(service.scope());
    service
        .provider_mut()
        .transport_mut()
        .set_policy(Ok(PulumiPolicyEvidence {
            policy_digest: Digest::from_text("drifted-policy"),
            policy_revision: 5,
            ..current_policy
        }));
    assert!(matches!(
        service.read_deployment_evidence(),
        Err(PulumiDeploymentResultError::PolicyDrift)
    ));
}

#[test]
fn pagination_is_bounded_and_cursor_replay_is_rejected() {
    let mut service = service_with_status(PulumiDeploymentStatus::Succeeded);
    let scope = service.scope().clone();
    service.provider_mut().transport_mut().set_update_pages([
        Ok(PulumiUpdatePage {
            items: vec![update(&scope, PulumiUpdateStatus::Running)],
            next_cursor: Some("cursor-1".into()),
        }),
        Ok(PulumiUpdatePage {
            items: vec![update(&scope, PulumiUpdateStatus::Succeeded)],
            next_cursor: None,
        }),
    ]);
    service.provider_mut().transport_mut().set_audit_pages([
        Ok(PulumiAuditPage {
            items: Vec::new(),
            next_cursor: Some("audit-1".into()),
        }),
        Ok(PulumiAuditPage {
            items: vec![audit()],
            next_cursor: None,
        }),
    ]);
    let evidence = service.read_deployment_evidence().expect("bounded pages");
    assert_eq!(evidence.pages_read, 5);
    let requests = service.provider().transport().requests();
    assert!(requests.iter().any(|request| {
        request.operation == PulumiCloudTransportOperation::ReadUpdates
            && request.cursor.as_deref() == Some("cursor-1")
    }));
    assert!(requests.iter().any(|request| {
        request.operation == PulumiCloudTransportOperation::ReadAudit
            && request.cursor.as_deref() == Some("audit-1")
    }));

    let mut looped = service_with_status(PulumiDeploymentStatus::Succeeded);
    let scope = looped.scope().clone();
    looped.provider_mut().transport_mut().set_update_pages([
        Ok(PulumiUpdatePage {
            items: vec![update(&scope, PulumiUpdateStatus::Running)],
            next_cursor: Some("same".into()),
        }),
        Ok(PulumiUpdatePage {
            items: vec![update(&scope, PulumiUpdateStatus::Running)],
            next_cursor: Some("same".into()),
        }),
    ]);
    assert!(matches!(
        looped.read_deployment_evidence(),
        Err(PulumiDeploymentResultError::Transport(
            PulumiCloudTransportError::PaginationLoop
        ))
    ));
}

#[test]
fn duplicate_replay_tamper_and_truncation_do_not_upgrade_authority() {
    let mut service = service_with_status(PulumiDeploymentStatus::Succeeded);
    let evidence = service.read_deployment_evidence().expect("evidence");
    let receipt = service
        .record_deployment_receipt(&evidence)
        .expect("receipt");
    let replay = service
        .record_deployment_receipt(&evidence)
        .expect("idempotent replay");
    assert_eq!(replay, receipt);

    let mut tampered = evidence.clone();
    tampered.modified_at += 1;
    assert!(matches!(
        tampered.validate(),
        Err(PulumiDeploymentResultError::InvalidEvidence)
    ));

    let mut conflicting = service_with_status(PulumiDeploymentStatus::Succeeded);
    conflicting.provider_mut().transport_mut().set_deployment({
        let mut record = api_status(PulumiDeploymentStatus::Succeeded);
        record.provider_request_id = "request-replayed-differently".into();
        Ok(record)
    });
    // Reconfigure the pages consumed by the second read.
    let scope = conflicting.scope().clone();
    conflicting
        .provider_mut()
        .transport_mut()
        .push_update_page(Ok(PulumiUpdatePage {
            items: vec![update(&scope, PulumiUpdateStatus::Succeeded)],
            next_cursor: None,
        }));
    conflicting
        .provider_mut()
        .transport_mut()
        .push_audit_page(Ok(PulumiAuditPage {
            items: vec![audit()],
            next_cursor: None,
        }));
    let first = conflicting
        .read_deployment_evidence()
        .expect("first evidence");
    let _ = conflicting
        .record_deployment_receipt(&first)
        .expect("first receipt");
    conflicting.provider_mut().transport_mut().set_deployment({
        let mut record = api_status(PulumiDeploymentStatus::Succeeded);
        record.provider_request_id = "request-replayed-again".into();
        Ok(record)
    });
    conflicting
        .provider_mut()
        .transport_mut()
        .push_update_page(Ok(PulumiUpdatePage {
            items: vec![update(&scope, PulumiUpdateStatus::Succeeded)],
            next_cursor: None,
        }));
    conflicting
        .provider_mut()
        .transport_mut()
        .push_audit_page(Ok(PulumiAuditPage {
            items: vec![audit()],
            next_cursor: None,
        }));
    let second = conflicting
        .read_deployment_evidence()
        .expect("second evidence");
    assert!(matches!(
        conflicting.record_deployment_receipt(&second),
        Err(PulumiDeploymentResultError::DuplicateDeployment)
    ));

    let mut truncated = service_with_status(PulumiDeploymentStatus::Succeeded);
    truncated.provider_mut().transport_mut().set_deployment({
        let mut record = api_status(PulumiDeploymentStatus::Succeeded);
        record.truncated = true;
        Ok(record)
    });
    let scope = truncated.scope().clone();
    truncated
        .provider_mut()
        .transport_mut()
        .push_update_page(Ok(PulumiUpdatePage {
            items: vec![update(&scope, PulumiUpdateStatus::Succeeded)],
            next_cursor: None,
        }));
    truncated
        .provider_mut()
        .transport_mut()
        .push_audit_page(Ok(PulumiAuditPage {
            items: vec![audit()],
            next_cursor: None,
        }));
    let evidence = truncated
        .read_deployment_evidence()
        .expect("truncated metadata");
    let receipt = truncated
        .record_deployment_receipt(&evidence)
        .expect("truncated receipt");
    assert!(matches!(
        truncated.verify_deployment_result(&evidence, &receipt),
        Err(PulumiDeploymentResultError::IncompleteEvidence)
    ));
}

#[test]
fn authorization_faults_access_loss_rate_limit_conflict_timeout_and_5xx_are_typed() {
    let cases = [
        (
            PulumiCloudTransportError::HttpStatus {
                status: 401,
                request_id: "unauthorized".into(),
            },
            PulumiCloudProviderState::AccessLost,
        ),
        (
            PulumiCloudTransportError::HttpStatus {
                status: 403,
                request_id: "forbidden".into(),
            },
            PulumiCloudProviderState::AccessLost,
        ),
        (
            PulumiCloudTransportError::HttpStatus {
                status: 404,
                request_id: "obscured".into(),
            },
            PulumiCloudProviderState::AuthorizationObscured404,
        ),
        (
            PulumiCloudTransportError::HttpStatus {
                status: 409,
                request_id: "conflict".into(),
            },
            PulumiCloudProviderState::Conflict,
        ),
        (
            PulumiCloudTransportError::HttpStatus {
                status: 429,
                request_id: "rate-limit".into(),
            },
            PulumiCloudProviderState::RateLimited,
        ),
        (
            PulumiCloudTransportError::Timeout,
            PulumiCloudProviderState::Timeout,
        ),
        (
            PulumiCloudTransportError::HttpStatus {
                status: 503,
                request_id: "server".into(),
            },
            PulumiCloudProviderState::Unavailable,
        ),
    ];
    for (fault, expected_state) in cases {
        let mut service = service_with_status(PulumiDeploymentStatus::Succeeded);
        service
            .provider_mut()
            .transport_mut()
            .set_deployment(Err(fault.clone()));
        let error = service
            .read_deployment_evidence()
            .expect_err("fault must fail");
        assert_eq!(service.provider().state(), expected_state);
        assert_eq!(error.status_code(), fault.status_code());
        assert_eq!(error.retryable(), fault.retryable());
        assert!(!service.provider().native_connected());
    }
}

#[test]
fn blocked_environment_opaque_auth_and_reversible_registration_are_honest() {
    let scope = scope();
    let mut secret_ref = secret(&scope);
    let debug = format!("{secret_ref:?}");
    assert!(!debug.contains("pulumi-secret-reference"));
    secret_ref.revoke();
    assert!(matches!(
        PulumiDeploymentResultRegistration::new(&scope, &secret_ref, "adapter-r1", 1),
        Err(PulumiDeploymentResultError::CredentialRevoked)
    ));

    let fresh_secret = secret(&scope);
    let mut registration =
        PulumiDeploymentResultRegistration::new(&scope, &fresh_secret, "adapter-r1", 1)
            .expect("registration");
    let before = registration.registration_digest.clone();
    let revocation = registration.revoke("test-revocation").expect("revoke");
    assert!(revocation.reversible);
    assert_ne!(before, registration.registration_digest);
    assert!(!registration.is_active());
    let reissued = registration
        .reissue(&scope, &fresh_secret, "adapter-r2", 3)
        .expect("reissue");
    assert!(reissued.is_active());
    assert_ne!(
        reissued.registration_digest,
        registration.registration_digest
    );
    assert_eq!(reissued.scope_digest, scope.digest());

    let blocked =
        PulumiCloudProvider::blocked_env(reissued, fresh_secret).expect("blocked provider");
    let mut service = PulumiDeploymentResultService::new(blocked).expect("blocked service");
    assert!(matches!(
        service.read_deployment_evidence(),
        Err(PulumiDeploymentResultError::Transport(
            PulumiCloudTransportError::BlockedEnv
        ))
    ));
    assert_eq!(
        service.provider().state(),
        PulumiCloudProviderState::BlockedEnv
    );
    for operation in [
        "deployment_create",
        "deployment_cancel",
        "deployment_resume",
        "stack_mutation",
        "config_mutation",
        "policy_mutation",
        "resource_mutation",
        "raw_logs",
        "raw_state",
        "raw_secrets",
    ] {
        assert!(matches!(
            service.reject_mutation(operation),
            Err(PulumiDeploymentResultError::MutationForbidden { .. })
        ));
    }
}
