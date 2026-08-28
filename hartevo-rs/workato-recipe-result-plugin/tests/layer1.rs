use hartevo_workato_recipe_result_plugin::{
    BlockedEnvTransport, ConsentScope, Digest, FixtureTransport, FolderId, JobHandle, JobIdentity,
    JobPageRequest, JobStatusFilter, Layer1Authority, LoopbackTransport, MissionId, MissionScope,
    MissionWorkatoRecipeConsumer, MissionWorkatoRecipeState, ModelError, PermissionScope,
    ProjectId, ProviderErrorKind, ProviderProvenance, RawJob, RawRecipe, RawRecipeVersion, RawStep,
    RecipeId, RecipeVersionBinding, RecipeVersionId, RecordingTransport, Revision, SecretKind,
    SecretReference, StepId, StepScope, StepStatus, TransportError, WorkProductId, WorkatoContract,
    WorkatoOperation, WorkatoProjectId, WorkatoRecipeResultService, WorkatoResponse,
    WorkatoResponseBody, WorkatoResultStatus, WorkatoScope, WorkatoTransport, WorkspaceId,
};

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("revision")
}

fn scope() -> WorkatoScope {
    let consent = ConsentScope::read_only(revision(5));
    let mission = MissionScope::new(
        ProjectId::new("hartevo-project").expect("project"),
        revision(7),
        MissionId::new("mission-443").expect("mission"),
        revision(9),
        WorkProductId::new("work-product-443").expect("work product"),
        revision(11),
        Digest::from_text("recipe-job-objective"),
        consent,
    )
    .expect("mission scope");
    let recipe_version = RecipeVersionBinding::new(
        RecipeVersionId::new("version-17").expect("version id"),
        17,
        revision(3),
    )
    .expect("recipe version");
    let job_handle = JobHandle::new("j-root-443").expect("job");
    let job = JobIdentity::new(
        job_handle.clone(),
        hartevo_workato_recipe_result_plugin::RetryIdentity::initial(job_handle),
    )
    .expect("job identity");
    WorkatoScope::new(
        WorkspaceId::new("workspace-443").expect("workspace"),
        WorkatoProjectId::new("project-443").expect("Workato project"),
        FolderId::new("folder-443").expect("folder"),
        RecipeId::new("recipe-443").expect("recipe"),
        recipe_version,
        job,
        StepScope::only(
            [
                StepId::new("step-trigger").expect("step"),
                StepId::new("step-action").expect("step"),
            ],
            revision(4),
        )
        .expect("step scope"),
        mission,
        PermissionScope::read_only(revision(6)),
    )
    .expect("Workato scope")
}

fn response(body: WorkatoResponseBody, marker: &str) -> WorkatoResponse {
    WorkatoResponse {
        status_code: 200,
        response_bytes: 512,
        response_digest: Digest::from_text(marker),
        body,
    }
}

fn recipe_response() -> WorkatoResponse {
    response(
        WorkatoResponseBody::Recipe(RawRecipe {
            workspace_id: "workspace-443".to_owned(),
            project_id: "project-443".to_owned(),
            folder_id: "folder-443".to_owned(),
            recipe_id: "recipe-443".to_owned(),
            name: "Sensitive recipe name is digested".to_owned(),
            status: "running".to_owned(),
            revision: 12,
            provider_revision: 91,
        }),
        "recipe-response",
    )
}

fn version_response() -> WorkatoResponse {
    response(
        WorkatoResponseBody::RecipeVersion(RawRecipeVersion {
            recipe_id: "recipe-443".to_owned(),
            version_id: "version-17".to_owned(),
            version_number: 17,
            revision: 18,
            comment: "Version comment with private detail".to_owned(),
            author: "private-author@example.test".to_owned(),
            created_at: "2026-08-14T00:00:00Z".to_owned(),
            updated_at: "2026-08-14T00:01:00Z".to_owned(),
            provider_revision: 92,
        }),
        "version-response",
    )
}

fn job_response(status: &str) -> WorkatoResponse {
    response(
        WorkatoResponseBody::Job(RawJob {
            workspace_id: "workspace-443".to_owned(),
            project_id: "project-443".to_owned(),
            folder_id: "folder-443".to_owned(),
            recipe_id: "recipe-443".to_owned(),
            job_handle: "j-root-443".to_owned(),
            recipe_version_id: "version-17".to_owned(),
            recipe_version_number: 17,
            status: status.to_owned(),
            retry_number: 0,
            root_job_handle: "j-root-443".to_owned(),
            parent_job_handle: None,
            started_at: Some("2026-08-14T00:02:00Z".to_owned()),
            completed_at: Some("2026-08-14T00:02:03Z".to_owned()),
            duration_ms: Some(3_000),
            tasks_used: Some(4),
            steps: vec![
                RawStep {
                    step_id: "step-trigger".to_owned(),
                    ordinal: 1,
                    kind: "trigger".to_owned(),
                    status: "completed".to_owned(),
                    error: None,
                    duration_ms: Some(100),
                    retry_number: 0,
                    input_payload: Some("SECRET_TRIGGER_INPUT".to_owned()),
                    output_payload: Some("SECRET_TRIGGER_OUTPUT".to_owned()),
                    runtime_datapills: vec!["SECRET_DATAPILL".to_owned()],
                },
                RawStep {
                    step_id: "step-action".to_owned(),
                    ordinal: 2,
                    kind: "action".to_owned(),
                    status: "completed".to_owned(),
                    error: None,
                    duration_ms: Some(2_900),
                    retry_number: 0,
                    input_payload: Some("SECRET_ACTION_INPUT".to_owned()),
                    output_payload: Some("SECRET_ACTION_OUTPUT".to_owned()),
                    runtime_datapills: vec!["SECRET_ACTION_DATAPILL".to_owned()],
                },
            ],
            retention_gap: false,
            provider_revision: 93,
        }),
        "job-response",
    )
}

fn service_with<T: WorkatoTransport>(transport: T) -> WorkatoRecipeResultService<T> {
    let scope = scope();
    let secret = SecretReference::new(
        "host-keyring-workato-reference",
        &scope,
        revision(2),
        SecretKind::ApiToken,
    )
    .expect("opaque secret reference");
    WorkatoRecipeResultService::new(scope, secret, transport).expect("service")
}

#[test]
fn fixture_compiles_redacted_proposal_and_mission_consumption() {
    let transport = FixtureTransport::from_responses([
        recipe_response(),
        version_response(),
        job_response("completed"),
    ]);
    let mut service = service_with(transport);
    let evidence = service.read_result().expect("fixture evidence");
    assert_eq!(evidence.status, WorkatoResultStatus::Completed);
    assert_eq!(evidence.provenance, ProviderProvenance::Fixture);
    assert_eq!(evidence.steps.len(), 2);
    assert!(
        evidence
            .steps
            .iter()
            .all(|step| { step.runtime_data_redacted && step.status == StepStatus::Completed })
    );
    assert!(evidence.is_non_native());
    let serialized = serde_json::to_string(&evidence).expect("evidence json");
    for forbidden in [
        "SECRET_TRIGGER_INPUT",
        "SECRET_TRIGGER_OUTPUT",
        "SECRET_DATAPILL",
        "SECRET_ACTION_INPUT",
        "SECRET_ACTION_OUTPUT",
        "SECRET_ACTION_DATAPILL",
        "private-author@example.test",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "retained forbidden value: {forbidden}"
        );
    }
    let proposal = service
        .compile_result_proposal(&evidence)
        .expect("proposal");
    assert!(proposal.is_non_native());
    let mut consumer =
        MissionWorkatoRecipeConsumer::new(service.scope().clone(), service.registration())
            .expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert_eq!(result.state, MissionWorkatoRecipeState::PendingDecision);
    assert!(!result.adopted_outcome);
    let replay = consumer.consume(&proposal).expect("replay");
    assert_eq!(replay.proposal_digest, result.proposal_digest);
}

#[test]
fn recording_transport_is_get_only_and_retries_rate_limits_once() {
    let transport = RecordingTransport::new([
        Err(TransportError::rate_limited()),
        Ok(recipe_response()),
        Ok(version_response()),
        Ok(job_response("failed")),
    ]);
    let mut service = service_with(transport);
    let evidence = service.read_result().expect("recording evidence");
    assert_eq!(evidence.status, WorkatoResultStatus::Failed);
    assert_eq!(evidence.provenance, ProviderProvenance::Recording);
    assert_eq!(evidence.retries.len(), 1);
    assert_eq!(evidence.retries[0].kind, ProviderErrorKind::RateLimited);
    assert!(evidence.receipts.iter().all(|receipt| {
        receipt.method == "GET"
            && receipt.redacted_request
            && receipt.redacted_result
            && !receipt.connected
            && !receipt.native
    }));
    let requests = service.provider().transport().recorded_requests();
    assert_eq!(requests.len(), 4);
    assert!(requests.iter().all(|request| request.method() == "GET"));
    assert!(requests.iter().all(|request| {
        matches!(
            request.operation(),
            WorkatoOperation::GetRecipe
                | WorkatoOperation::GetRecipeVersion
                | WorkatoOperation::GetJob
        )
    }));
}

#[test]
fn loopback_and_blocked_env_never_claim_native_or_connected() {
    let mut loopback = service_with(LoopbackTransport::from_responses([
        recipe_response(),
        version_response(),
        job_response("processing"),
    ]));
    let processing = loopback.read_result().expect("loopback evidence");
    assert_eq!(processing.status, WorkatoResultStatus::Processing);
    assert!(!processing.connected);
    assert!(!processing.native);
    assert_eq!(
        loopback.provider().provenance(),
        ProviderProvenance::Loopback
    );

    let mut blocked = service_with(BlockedEnvTransport::default());
    let evidence = blocked.read_result().expect("blocked evidence projection");
    assert_eq!(evidence.status, WorkatoResultStatus::ProviderUnknown);
    assert_eq!(
        evidence.provider_errors[0].kind,
        ProviderErrorKind::BlockedEnv
    );
    assert!(evidence.provider_errors[0].blocked_env);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(evidence.receipts[0].redacted_request);
    assert_eq!(
        blocked.provider().provenance(),
        ProviderProvenance::BlockedEnv
    );
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native());

    let mut access_lost = service_with(RecordingTransport::new([Err(
        TransportError::unauthorized(),
    )]));
    let evidence = access_lost.read_result().expect("access-lost evidence");
    assert_eq!(evidence.status, WorkatoResultStatus::AccessLost);
    assert_eq!(
        evidence.provider_errors[0].kind,
        ProviderErrorKind::Unauthorized
    );
}

#[test]
fn normalized_statuses_include_pause_abort_retry_and_retention_gap() {
    for (raw, expected) in [
        ("paused", WorkatoResultStatus::Paused),
        ("aborted", WorkatoResultStatus::Aborted),
        ("retried", WorkatoResultStatus::Retried),
        ("partial", WorkatoResultStatus::Partial),
    ] {
        let mut service = service_with(FixtureTransport::from_responses([
            recipe_response(),
            version_response(),
            job_response(raw),
        ]));
        assert_eq!(
            service.read_result().expect("status evidence").status,
            expected
        );
    }

    let mut retention = service_with(FixtureTransport::from_responses([
        recipe_response(),
        version_response(),
        response(
            WorkatoResponseBody::Job(RawJob {
                workspace_id: "workspace-443".to_owned(),
                project_id: "project-443".to_owned(),
                folder_id: "folder-443".to_owned(),
                recipe_id: "recipe-443".to_owned(),
                job_handle: "j-root-443".to_owned(),
                recipe_version_id: "version-17".to_owned(),
                recipe_version_number: 17,
                status: "completed".to_owned(),
                retry_number: 0,
                root_job_handle: "j-root-443".to_owned(),
                parent_job_handle: None,
                started_at: None,
                completed_at: None,
                duration_ms: None,
                tasks_used: None,
                steps: Vec::new(),
                retention_gap: true,
                provider_revision: 94,
            }),
            "retention-gap-response",
        ),
    ]));
    assert_eq!(
        retention.read_result().expect("retention evidence").status,
        WorkatoResultStatus::RetentionGap
    );
}

#[test]
fn registration_recording_is_replay_safe_and_revocable() {
    let mut service = service_with(FixtureTransport::from_responses([
        recipe_response(),
        version_response(),
        job_response("completed"),
        recipe_response(),
        version_response(),
        job_response("failed"),
    ]));
    let evidence = service.read_result().expect("evidence");
    let first = service
        .record_redacted_receipt(&evidence)
        .expect("recording");
    let replay = service
        .record_redacted_receipt(&evidence)
        .expect("replay recording");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert!(!first.durable_native);

    let different = service
        .read_result()
        .expect("different valid rerun evidence");
    assert!(matches!(
        service.record_redacted_receipt(&different),
        Err(hartevo_workato_recipe_result_plugin::WorkatoServiceError::DuplicateRerun)
    ));

    service.unmount().expect("unmount");
    assert!(matches!(
        service.read_result(),
        Err(hartevo_workato_recipe_result_plugin::WorkatoServiceError::RegistrationInactive)
    ));
    service.remount().expect("remount");
    service.revoke().expect("revoke");
    assert!(matches!(
        service.read_result(),
        Err(hartevo_workato_recipe_result_plugin::WorkatoServiceError::SecretRevoked)
    ));
}

#[test]
fn scope_and_request_bounds_fail_closed() {
    assert!(matches!(
        JobPageRequest::new(17, 1, None, false, Some(JobStatusFilter::Pending)),
        Err(ModelError::InvalidBounds)
    ));
    let bad_transport = FixtureTransport::from_responses([
        recipe_response(),
        version_response(),
        response(
            WorkatoResponseBody::Job(RawJob {
                workspace_id: "workspace-443".to_owned(),
                project_id: "project-443".to_owned(),
                folder_id: "folder-443".to_owned(),
                recipe_id: "recipe-443".to_owned(),
                job_handle: "j-other".to_owned(),
                recipe_version_id: "version-17".to_owned(),
                recipe_version_number: 17,
                status: "completed".to_owned(),
                retry_number: 0,
                root_job_handle: "j-other".to_owned(),
                parent_job_handle: None,
                started_at: None,
                completed_at: None,
                duration_ms: None,
                tasks_used: None,
                steps: Vec::new(),
                retention_gap: false,
                provider_revision: 95,
            }),
            "bad-job",
        ),
    ]);
    let mut service = service_with(bad_transport);
    assert!(matches!(
        service.read_result(),
        Err(hartevo_workato_recipe_result_plugin::WorkatoServiceError::Provider(error))
            if error.kind() == ProviderErrorKind::RetryMismatch
    ));
}

#[test]
fn consent_effect_receipt_and_readback_seams_are_explicitly_layer_two() {
    let service = service_with(BlockedEnvTransport::default());
    assert!(service.consent().read_proposal());
    assert!(!service.consent().external_effects());
    assert!(matches!(
        service.propose_effect(hartevo_workato_recipe_result_plugin::WorkatoEffectKind::ForceRun),
        Err(hartevo_workato_recipe_result_plugin::WorkatoServiceError::EffectAuthorityUnavailable)
    ));
    assert!(matches!(
        service.read_back(
            hartevo_workato_recipe_result_plugin::WorkatoReadBackRequest {
                scope_digest: service.scope().scope_digest(),
                job_digest: service.scope().job().digest(),
                source_proposal_digest: Digest::from_text("proposal"),
            }
        ),
        Err(hartevo_workato_recipe_result_plugin::WorkatoServiceError::ReadBackUnavailable)
    ));
    let definition = service.definition();
    assert!(!definition.scheduler_authority);
    assert!(!definition.effect_authority);
    assert!(!definition.receipt_authority);
    assert!(!definition.verification_authority);
}

#[test]
fn contract_validation_and_secret_debug_are_honest() {
    WorkatoContract::baseline().expect("contract");
    let scope = scope();
    let secret = SecretReference::new(
        "never-print-this-raw-reference",
        &scope,
        revision(1),
        SecretKind::OAuthClient,
    )
    .expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("never-print-this-raw-reference"));
    assert_eq!(secret.kind(), SecretKind::OAuthClient);
}
