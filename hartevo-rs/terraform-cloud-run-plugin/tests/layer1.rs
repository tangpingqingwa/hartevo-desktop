use hartevo_terraform_cloud_run_plugin::{
    ApplyProposalRequest, BlockedEnvCredentialResolver, ConfigurationProposalRequest,
    ConfigurationSource, ConfigurationVersionFence, ConsentBinding, CostAvailability, CostEvidence,
    Digest, HcpTerraformHostname, MissionTerraformRunConsumer, PlanEvidence, PlanId, PlanStatus,
    PolicyEvidence, PolicyResult, PolicySetId, ProviderProvenance,
    RecordingTerraformCloudTransport, RunEvidence, RunId, RunMode, RunProposalRequest,
    SecretReference, StaticTerraformCloudCredentialResolver, StatusTransition,
    TerraformCloudRunError, TerraformCloudRunProvider, TerraformCloudRunProviderState,
    TerraformCloudRunRegistration, TerraformCloudRunService, TerraformCloudRunTransport,
    TerraformCloudScope, TerraformCloudTransportError, TerraformCloudTransportOperation,
    TerraformCloudWorkspaceApiRecord, TerraformResourceFence, TerraformRunStatus,
    UreqTerraformCloudTransport,
};

const TOKEN: &str = "sensitive-team-user-token";
const OBSERVED_AT: &str = "2026-08-14T00:00:00Z";

fn scope() -> TerraformCloudScope {
    TerraformCloudScope::new(
        "HTTPS://App.Terraform.io",
        "org-fixture",
        "terraform-project-fixture",
        "workspace-fixture",
        "workspace-revision-1",
        "lock-identity-1",
        "hartevo-project-1",
        "mission-1",
        "work-product-1",
    )
    .expect("scope")
    .with_resources(TerraformResourceFence {
        configuration_version: Some(
            hartevo_terraform_cloud_run_plugin::ConfigurationVersionId::new("cv-1")
                .expect("configuration version"),
        ),
        run: Some(RunId::new("run-1").expect("run")),
        plan: Some(PlanId::new("plan-1").expect("plan")),
        apply: None,
        policy_evaluation: Some(
            hartevo_terraform_cloud_run_plugin::PolicyEvaluationId::new("policy-eval-1")
                .expect("policy evaluation"),
        ),
        policy_set: Some(PolicySetId::new("policy-set-1").expect("policy set")),
    })
    .expect("resource fence")
}

fn configuration(scope: &TerraformCloudScope) -> ConfigurationVersionFence {
    ConfigurationVersionFence::new(
        scope
            .resources
            .configuration_version
            .as_ref()
            .expect("configuration id")
            .as_str(),
        ConfigurationSource::VersionControl,
        "repo-main",
        Some("commit-sha-1".to_owned()),
        Digest::from_bytes(b"configuration-archive-not-retained"),
    )
    .expect("configuration fence")
}

fn evidence(scope: &TerraformCloudScope, mode: RunMode, has_changes: Option<bool>) -> RunEvidence {
    let config = configuration(scope);
    let plan = PlanEvidence::new(
        scope.resources.plan.clone().expect("plan id"),
        PlanStatus::Finished,
        has_changes,
        Digest::from_bytes(b"bounded-plan-summary"),
        OBSERVED_AT,
    )
    .expect("plan evidence");
    let policy = PolicyEvidence::new(
        scope
            .resources
            .policy_evaluation
            .clone()
            .expect("policy id"),
        scope.resources.policy_set.clone(),
        if mode == RunMode::Speculative {
            PolicyResult::NotEvaluated
        } else {
            PolicyResult::Passed
        },
        Digest::from_bytes(b"bounded-policy-summary"),
        OBSERVED_AT,
    )
    .expect("policy evidence");
    let cost = CostEvidence::new(
        Some("cost-estimate-1".to_owned()),
        if mode == RunMode::Speculative {
            CostAvailability::Unavailable
        } else {
            CostAvailability::Available
        },
        (mode == RunMode::Normal).then(|| Digest::from_bytes(b"bounded-cost-summary")),
        OBSERVED_AT,
    )
    .expect("cost evidence");
    RunEvidence::new(
        scope.clone(),
        config,
        scope.resources.run.clone().expect("run id"),
        TerraformRunStatus::Planned,
        mode,
        has_changes,
        false,
        Some("provider-request-1".to_owned()),
        vec![
            StatusTransition::new(None, TerraformRunStatus::Planned, OBSERVED_AT)
                .expect("transition"),
        ],
        Some(plan),
        None,
        Some(policy),
        Some(cost),
        OBSERVED_AT,
    )
    .expect("run evidence")
}

fn workspace(scope: &TerraformCloudScope) -> TerraformCloudWorkspaceApiRecord {
    TerraformCloudWorkspaceApiRecord {
        workspace_id: scope.workspace.clone(),
        workspace_revision: scope.workspace_revision.clone(),
        lock_identity: scope.lock_identity.clone(),
        locked: false,
        execution_mode: "remote".to_owned(),
        terraform_version: Some("1.9.0".to_owned()),
        configuration_version: scope.resources.configuration_version.clone(),
        current_run: scope.resources.run.clone(),
    }
}

fn registration(scope: &TerraformCloudScope) -> TerraformCloudRunRegistration {
    let secret =
        SecretReference::new("secret-ref-tfc-fixture", scope, 1).expect("secret reference");
    TerraformCloudRunRegistration::new(scope.clone(), secret).expect("registration")
}

fn provider() -> (
    TerraformCloudRunProvider<
        RecordingTerraformCloudTransport,
        StaticTerraformCloudCredentialResolver,
    >,
    RecordingTerraformCloudTransport,
    TerraformCloudScope,
    RunEvidence,
) {
    let scope = scope();
    let evidence = evidence(&scope, RunMode::Normal, Some(true));
    let transport = RecordingTerraformCloudTransport::fixture(workspace(&scope), evidence.clone());
    let provider = TerraformCloudRunProvider::new(
        registration(&scope),
        transport.clone(),
        StaticTerraformCloudCredentialResolver::new(TOKEN),
    )
    .expect("provider");
    (provider, transport, scope, evidence)
}

fn service() -> (
    TerraformCloudRunService<
        RecordingTerraformCloudTransport,
        StaticTerraformCloudCredentialResolver,
    >,
    RecordingTerraformCloudTransport,
    TerraformCloudScope,
    RunEvidence,
) {
    let (provider, transport, scope, evidence) = provider();
    (
        TerraformCloudRunService::new(provider).expect("service"),
        transport,
        scope,
        evidence,
    )
}

fn configuration_proposal(
    service: &TerraformCloudRunService<
        RecordingTerraformCloudTransport,
        StaticTerraformCloudCredentialResolver,
    >,
    scope: &TerraformCloudScope,
    consent: ConsentBinding,
) -> hartevo_terraform_cloud_run_plugin::ConfigurationProposal {
    service
        .compile_configuration_proposal(
            ConfigurationProposalRequest::new(scope.clone(), configuration(scope), 7, 3, consent)
                .expect("configuration request"),
        )
        .expect("configuration proposal")
}

#[test]
fn fixture_reads_are_bounded_and_never_native_or_connected() {
    let (mut service, transport, scope, _evidence) = service();
    let description = service.describe_workspace().expect("workspace description");
    assert_eq!(description.provenance, ProviderProvenance::Fixture);
    assert!(!description.native_transport);
    assert!(!description.native_connected);
    assert!(!description.provenance.is_native());
    assert!(!description.provenance.is_connected());
    assert!(description.proposal_capable);
    let observed = service.read_run_evidence().expect("run evidence");
    assert_eq!(
        observed.outcome(),
        hartevo_terraform_cloud_run_plugin::RunOutcome::Applyable
    );
    assert_eq!(
        transport.operations(),
        vec![
            TerraformCloudTransportOperation::DescribeWorkspace,
            TerraformCloudTransportOperation::ReadRunEvidence,
        ]
    );
    assert!(!service.provider().native_connected());
    assert_eq!(
        service.provider().native_status(),
        hartevo_terraform_cloud_run_plugin::NativeStatus::BlockedEnv
    );
    assert_eq!(observed.scope, scope);
}

#[test]
fn service_provider_and_mission_consumer_seal_a_proposal_only_result() {
    let (mut service, _transport, scope, evidence) = service();
    let consent = ConsentBinding::granted(11, 4);
    let config = configuration_proposal(&service, &scope, consent);
    let run = service
        .compile_run_proposal(
            RunProposalRequest::new(
                config,
                Some(RunId::new("run-1").expect("run id")),
                RunMode::Normal,
                false,
                consent,
            )
            .expect("run request"),
        )
        .expect("run proposal");
    let receipt = service.record_run_receipt(&evidence).expect("receipt");
    assert!(receipt.independent);
    assert!(!receipt.truncated);
    let result = service
        .verify_run_result(&run, &evidence, &receipt)
        .expect("verified result proposal");
    assert_eq!(
        result.outcome,
        hartevo_terraform_cloud_run_plugin::RunOutcome::Applyable
    );
    assert_eq!(
        result.verification_status,
        hartevo_terraform_cloud_run_plugin::ResultVerificationStatus::ProviderFingerprintMatch
    );
    assert!(!result.native_connected);
    assert!(!result.external_effect_performed);
    assert!(!result.durable_adoption);
    assert!(!result.kernel_authority);
    let consumer =
        MissionTerraformRunConsumer::from_registration(service.provider().registration())
            .expect("consumer");
    let consumed_proposal = consumer.consume(&result).expect("consumer proposal");
    assert_eq!(consumed_proposal, result);
    let mission_result = consumer.consume_result(&result).expect("mission result");
    mission_result.validate().expect("valid mission result");
    assert!(!mission_result.durable_adoption);
    assert!(!mission_result.kernel_authority);
}

#[test]
fn apply_proposal_requires_consent_policy_and_complete_cost_evidence() {
    let (service, transport, scope, evidence) = service();
    let pending = ConsentBinding::pending(11, 4);
    let pending_config = configuration_proposal(&service, &scope, pending);
    let pending_run = service
        .compile_run_proposal(
            RunProposalRequest::new(
                pending_config,
                Some(RunId::new("run-1").expect("run id")),
                RunMode::Normal,
                false,
                pending,
            )
            .expect("pending run request"),
        )
        .expect("pending run proposal");
    assert_eq!(
        ApplyProposalRequest::new(pending_run, evidence.clone(), pending)
            .expect_err("apply before consent"),
        TerraformCloudRunError::ConsentRequired
    );

    let granted = ConsentBinding::granted(11, 4);
    let granted_config = configuration_proposal(&service, &scope, granted);
    let granted_run = service
        .compile_run_proposal(
            RunProposalRequest::new(
                granted_config,
                Some(RunId::new("run-1").expect("run id")),
                RunMode::Normal,
                false,
                granted,
            )
            .expect("granted run request"),
        )
        .expect("granted run proposal");
    let apply = service
        .compile_apply_proposal(
            ApplyProposalRequest::new(granted_run.clone(), evidence.clone(), granted)
                .expect("apply request"),
        )
        .expect("apply proposal");
    assert!(!apply.apply_performed);
    assert!(!apply.external_effect_created);
    assert!(!apply.kernel_authority);

    let mut policy_blocked = evidence.clone();
    policy_blocked.policy = Some(
        PolicyEvidence::new(
            scope
                .resources
                .policy_evaluation
                .clone()
                .expect("policy id"),
            scope.resources.policy_set.clone(),
            PolicyResult::OverrideRequired,
            Digest::from_bytes(b"override-required"),
            OBSERVED_AT,
        )
        .expect("policy evidence"),
    );
    policy_blocked.evidence_digest = policy_blocked.computed_digest();
    assert_eq!(
        ApplyProposalRequest::new(granted_run.clone(), policy_blocked, granted)
            .expect_err("policy override must not be inferred"),
        TerraformCloudRunError::PolicyBlocked
    );

    let mut partial_cost = evidence;
    partial_cost.cost = Some(
        CostEvidence::new(
            Some("cost-estimate-1".to_owned()),
            CostAvailability::Partial,
            Some(Digest::from_bytes(b"partial-cost")),
            OBSERVED_AT,
        )
        .expect("partial cost"),
    );
    partial_cost.evidence_digest = partial_cost.computed_digest();
    assert_eq!(
        ApplyProposalRequest::new(granted_run, partial_cost, granted)
            .expect_err("partial cost cannot authorize apply"),
        TerraformCloudRunError::CostPartial
    );
    transport.clear_fault();
}

#[test]
fn speculative_no_change_and_unknown_states_remain_typed_and_non_mutating() {
    let (mut service, transport, scope, _normal) = service();
    let speculative = evidence(&scope, RunMode::Speculative, Some(false));
    transport.set_evidence(speculative.clone());
    let observed = service.read_run_evidence().expect("speculative read");
    assert_eq!(
        observed.outcome(),
        hartevo_terraform_cloud_run_plugin::RunOutcome::SpeculativeNoChanges
    );
    let config = configuration_proposal(&service, &scope, ConsentBinding::pending(12, 5));
    let run = service
        .compile_run_proposal(
            RunProposalRequest::new(
                config,
                Some(RunId::new("run-1").expect("run")),
                RunMode::Speculative,
                false,
                ConsentBinding::pending(12, 5),
            )
            .expect("speculative request"),
        )
        .expect("speculative proposal");
    let receipt = service
        .record_run_receipt(&observed)
        .expect("speculative receipt");
    let result = service
        .verify_run_result(&run, &observed, &receipt)
        .expect("speculative result");
    assert_eq!(
        result.outcome,
        hartevo_terraform_cloud_run_plugin::RunOutcome::SpeculativeNoChanges
    );
    assert_eq!(
        ApplyProposalRequest::new(run, observed, ConsentBinding::granted(12, 5))
            .expect_err("speculative apply"),
        TerraformCloudRunError::SpeculativeApply
    );

    let mut unknown = evidence(&scope, RunMode::Normal, Some(true));
    unknown.status = TerraformRunStatus::ProviderUnknown;
    unknown.evidence_digest = unknown.computed_digest();
    transport.set_evidence(unknown);
    let unknown_observed = service.read_run_evidence().expect("unknown is typed");
    assert_eq!(
        unknown_observed.outcome(),
        hartevo_terraform_cloud_run_plugin::RunOutcome::ProviderUnknown
    );
    assert_eq!(
        service.provider().state(),
        TerraformCloudRunProviderState::ProviderUnknown
    );
}

#[test]
fn authorization_obscured_404_401_rate_limit_and_revocation_fail_closed() {
    let (mut provider, transport, _scope, _evidence) = provider();
    transport.set_fault(TerraformCloudTransportError::NotFoundOrUnauthorized);
    assert_eq!(
        provider
            .read_run_evidence()
            .expect_err("404 must be preserved"),
        TerraformCloudRunError::NotFoundOrUnauthorized
    );
    assert_eq!(
        provider.state(),
        TerraformCloudRunProviderState::AuthorizationObscured404
    );
    transport.set_fault(TerraformCloudTransportError::Unauthorized);
    assert_eq!(
        provider.read_run_evidence().expect_err("401"),
        TerraformCloudRunError::Unauthorized
    );
    transport.set_fault(TerraformCloudTransportError::RateLimited {
        retry_after_seconds: Some(7),
    });
    assert_eq!(
        provider.read_run_evidence().expect_err("rate limit"),
        TerraformCloudRunError::RateLimited {
            retry_after_seconds: Some(7)
        }
    );
    transport.clear_fault();
    let revocation = provider.revoke().expect("revoke");
    assert!(revocation.reversible);
    assert_eq!(provider.state(), TerraformCloudRunProviderState::Revoked);
    assert_eq!(
        provider.read_run_evidence().expect_err("revoked provider"),
        TerraformCloudRunError::RegistrationRevoked
    );
}

#[test]
fn duplicate_and_tampered_receipts_are_rejected_without_raw_plan_or_state() {
    let (mut service, _transport, scope, evidence) = service();
    let first = service.record_run_receipt(&evidence).expect("receipt");
    let replay = service
        .record_run_receipt(&evidence)
        .expect("idempotent receipt");
    assert_eq!(first, replay);
    let mut altered = evidence.clone();
    altered.status = TerraformRunStatus::Applying;
    altered.evidence_digest = altered.computed_digest();
    assert_eq!(
        service
            .record_run_receipt(&altered)
            .expect_err("same run changed fingerprint"),
        TerraformCloudRunError::DuplicateFingerprint
    );
    let config = configuration_proposal(&service, &scope, ConsentBinding::granted(11, 4));
    let run = service
        .compile_run_proposal(
            RunProposalRequest::new(
                config,
                Some(RunId::new("run-1").expect("run")),
                RunMode::Normal,
                false,
                ConsentBinding::granted(11, 4),
            )
            .expect("run request"),
        )
        .expect("run proposal");
    let mut tampered = first.clone();
    tampered.has_changes = Some(false);
    assert_eq!(
        service
            .verify_run_result(&run, &evidence, &tampered)
            .expect_err("tampered receipt"),
        TerraformCloudRunError::ReceiptMismatch
    );
    let serialized = serde_json::to_string(&first).expect("receipt JSON");
    assert!(!serialized.contains(TOKEN));
    assert!(!serialized.contains("rawState"));
    assert!(!serialized.contains("rawPlan"));
    let debug = format!("{:?} {:?}", first, service.provider());
    assert!(!debug.contains(TOKEN));
    assert!(!debug.contains("configuration-archive-not-retained"));
}

#[test]
fn blocked_env_scope_drift_and_hostname_fences_are_explicit() {
    let (_provider, _transport, scope, _evidence) = provider();
    let secret = SecretReference::new("secret-ref-tfc-blocked", &scope, 1).expect("secret");
    let transport = RecordingTerraformCloudTransport::blocked_env(
        workspace(&scope),
        evidence(&scope, RunMode::Normal, Some(true)),
    );
    let mut blocked = TerraformCloudRunProvider::new(
        registration(&scope),
        transport,
        BlockedEnvCredentialResolver,
    )
    .expect("blocked provider");
    assert_eq!(
        blocked
            .read_run_evidence()
            .expect_err("missing credentials"),
        TerraformCloudRunError::BlockedEnv
    );
    assert_eq!(blocked.state(), TerraformCloudRunProviderState::BlockedEnv);
    let drifted_scope = TerraformCloudScope::new(
        scope.hostname.to_string(),
        scope.organization.to_string(),
        scope.terraform_project.to_string(),
        scope.workspace.to_string(),
        "workspace-revision-drift",
        scope.lock_identity.to_string(),
        scope.hartevo_project.to_string(),
        scope.mission.to_string(),
        scope.work_product.to_string(),
    )
    .expect("drifted scope")
    .with_resources(scope.resources.clone())
    .expect("drifted resources");
    assert_ne!(scope.digest(), drifted_scope.digest());
    assert!(matches!(
        HcpTerraformHostname::parse("http://app.terraform.io"),
        Err(TerraformCloudRunError::InvalidHostname)
    ));
    assert!(matches!(
        HcpTerraformHostname::parse("https://app.terraform.io/api/v2"),
        Err(TerraformCloudRunError::InvalidHostname)
    ));
    let loopback =
        UreqTerraformCloudTransport::new_loopback("http://127.0.0.1:1").expect("loopback seam");
    assert_eq!(loopback.provenance(), ProviderProvenance::Loopback);
    assert!(!loopback.provenance().is_native());
    assert!(UreqTerraformCloudTransport::new("http://example.invalid").is_err());
    let _ = (secret, drifted_scope);
}

#[test]
fn transport_and_secret_debug_surfaces_are_redacted() {
    let (_provider, transport, scope, evidence) = provider();
    let secret = SecretReference::new("secret-ref-redaction", &scope, 1).expect("secret");
    assert!(!format!("{secret:?}").contains(TOKEN));
    assert!(!format!("{transport:?}").contains(TOKEN));
    assert!(!format!("{evidence:?}").contains(TOKEN));
    assert!(
        !serde_json::to_string(&secret)
            .expect("secret reference JSON")
            .contains(TOKEN)
    );
}

#[test]
fn transient_http_conflict_timeout_422_server_and_truncation_are_typed() {
    let (mut provider, transport, _scope, _evidence) = provider();
    for (fault, expected) in [
        (
            TerraformCloudTransportError::Conflict,
            TerraformCloudRunError::Conflict,
        ),
        (
            TerraformCloudTransportError::UnprocessableEntity,
            TerraformCloudRunError::UnprocessableEntity,
        ),
        (
            TerraformCloudTransportError::Timeout,
            TerraformCloudRunError::Timeout,
        ),
        (
            TerraformCloudTransportError::ResponseTooLarge,
            TerraformCloudRunError::ResponseTooLarge,
        ),
        (
            TerraformCloudTransportError::ServerUnavailable,
            TerraformCloudRunError::RetryExhausted,
        ),
    ] {
        transport.set_fault(fault);
        assert_eq!(
            provider
                .read_run_evidence()
                .expect_err("typed transport fault"),
            expected
        );
        transport.clear_fault();
    }
}

#[test]
fn stale_resource_and_workspace_lock_fences_fail_closed() {
    let (mut provider, transport, scope, baseline) = provider();
    let mut stale_configuration = baseline.clone();
    stale_configuration.configuration = ConfigurationVersionFence::new(
        "cv-stale",
        ConfigurationSource::VersionControl,
        "repo-main",
        Some("commit-sha-stale".to_owned()),
        Digest::from_bytes(b"stale-archive"),
    )
    .expect("stale configuration");
    stale_configuration.evidence_digest = stale_configuration.computed_digest();
    assert_eq!(
        stale_configuration
            .validate()
            .expect_err("stale configuration"),
        TerraformCloudRunError::StaleConfiguration
    );
    let mut stale_run = baseline;
    stale_run.run_id = RunId::new("run-stale").expect("stale run");
    stale_run.evidence_digest = stale_run.computed_digest();
    assert_eq!(
        stale_run.validate().expect_err("stale run"),
        TerraformCloudRunError::StaleRun
    );

    let mut locked_workspace = workspace(&scope);
    locked_workspace.locked = true;
    transport.set_workspace(locked_workspace);
    let description = provider
        .describe_workspace()
        .expect("locked workspace is readable");
    assert!(!description.proposal_capable);
    let request = ConfigurationProposalRequest::new(
        scope.clone(),
        configuration(&scope),
        7,
        3,
        ConsentBinding::pending(1, 1),
    )
    .expect("proposal request");
    assert_eq!(
        provider
            .compile_configuration_proposal(request)
            .expect_err("locked workspace proposal"),
        TerraformCloudRunError::StaleWorkspace
    );
}

#[test]
fn policy_fail_cost_unavailable_and_all_mutations_are_rejected() {
    let (service, _transport, scope, evidence) = service();
    let consent = ConsentBinding::granted(15, 2);
    let config = configuration_proposal(&service, &scope, consent);
    let run = service
        .compile_run_proposal(
            RunProposalRequest::new(
                config,
                Some(RunId::new("run-1").expect("run")),
                RunMode::Normal,
                false,
                consent,
            )
            .expect("run request"),
        )
        .expect("run proposal");
    let mut policy_fail = evidence.clone();
    policy_fail.policy = Some(
        PolicyEvidence::new(
            scope.resources.policy_evaluation.clone().expect("policy"),
            scope.resources.policy_set.clone(),
            PolicyResult::Failed,
            Digest::from_bytes(b"policy-failed"),
            OBSERVED_AT,
        )
        .expect("policy failure"),
    );
    policy_fail.evidence_digest = policy_fail.computed_digest();
    assert_eq!(
        ApplyProposalRequest::new(run.clone(), policy_fail, consent).expect_err("failed policy"),
        TerraformCloudRunError::PolicyBlocked
    );
    let mut cost_unavailable = evidence;
    cost_unavailable.cost = Some(
        CostEvidence::new(
            Some("cost-estimate-1".to_owned()),
            CostAvailability::Unavailable,
            None,
            OBSERVED_AT,
        )
        .expect("unavailable cost"),
    );
    cost_unavailable.evidence_digest = cost_unavailable.computed_digest();
    assert_eq!(
        ApplyProposalRequest::new(run, cost_unavailable, consent).expect_err("unavailable cost"),
        TerraformCloudRunError::CostUnavailable
    );
    for operation in [
        "configuration upload",
        "run create",
        "run cancel",
        "run discard",
        "apply",
        "policy override",
        "workspace mutation",
        "variable mutation",
        "state mutation",
        "ambiguous create",
    ] {
        assert_eq!(
            service.reject_write(operation),
            Err(TerraformCloudRunError::MutationForbidden { operation })
        );
    }
}

#[test]
fn receipt_truncation_and_scope_registration_drift_never_verify() {
    let (mut service, _transport, scope, evidence) = service();
    let receipt = service.record_run_receipt(&evidence).expect("receipt");
    let mut truncated = receipt.clone();
    truncated.truncated = true;
    assert_eq!(
        truncated
            .validate_against(
                &evidence,
                &service.provider().registration().registration_digest,
            )
            .expect_err("truncated receipt"),
        TerraformCloudRunError::ReceiptMismatch
    );
    let drifted = TerraformCloudScope::new(
        scope.hostname.to_string(),
        scope.organization.to_string(),
        scope.terraform_project.to_string(),
        scope.workspace.to_string(),
        scope.workspace_revision.to_string(),
        scope.lock_identity.to_string(),
        scope.hartevo_project.to_string(),
        "mission-drift",
        scope.work_product.to_string(),
    )
    .expect("drifted scope")
    .with_resources(scope.resources.clone())
    .expect("drifted resource fence");
    assert_eq!(
        service
            .compile_configuration_proposal(
                ConfigurationProposalRequest::new(
                    drifted,
                    configuration(&scope),
                    7,
                    3,
                    ConsentBinding::pending(1, 1),
                )
                .expect("drifted request"),
            )
            .expect_err("cross mission scope"),
        TerraformCloudRunError::ScopeMismatch
    );
}
