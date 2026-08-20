use hartevo_launchdarkly_release_plugin::*;
use serde_json::{json, to_string, to_value};

fn digest(label: &str) -> Digest {
    Digest::from_text(label)
}

fn scope_for(account_id: &str, base_url: &str) -> FeatureReleaseScope {
    let policy = ApprovalPolicySnapshot::required("release-policy", 7).expect("policy");
    FeatureReleaseScope::new(
        account_id,
        base_url,
        "project-fixture",
        "production",
        "checkout-banner",
        42,
        ["/variations/0".to_owned(), "/variations/1".to_owned()],
        ["/targeting/rules".to_owned()],
        policy,
        "mission-release-01",
        "project-hartevo-01",
        "work-product-release-01",
        11,
        7,
    )
    .expect("scope")
}

fn scope() -> FeatureReleaseScope {
    scope_for("account-fixture", "https://app.launchdarkly.com")
}

fn flag(scope: &FeatureReleaseScope, version: u64, suffix: &str) -> FlagSnapshot {
    FlagSnapshot::for_scope(
        scope,
        version,
        digest(&format!("variation-{suffix}")),
        digest(&format!("targeting-{suffix}")),
        digest(&format!("semantic-{suffix}")),
        1_000 + version,
    )
    .expect("flag")
}

fn approved(scope: &FeatureReleaseScope, id: &str, status: ApprovalStatus) -> ApprovalEvidence {
    ApprovalEvidence::for_scope(
        scope,
        id,
        status,
        scope.flag_version,
        scope.policy_revision,
        b"private reviewer email reviewer@example.invalid",
        1_100,
    )
    .expect("approval")
}

fn audit(
    scope: &FeatureReleaseScope,
    id: &str,
    version: u64,
    kind: AuditEventKind,
    approval_id: Option<String>,
) -> AuditEvidence {
    AuditEvidence::for_scope(
        scope,
        id,
        kind,
        version,
        b"actor@example.invalid",
        b"raw targeting context user=customer@example.invalid",
        approval_id,
        None,
        2_000,
    )
    .expect("audit")
}

fn patch(scope: &FeatureReleaseScope, base: &FlagSnapshot) -> SemanticPatch {
    SemanticPatch::new(
        scope.flag_version,
        base.variation_digest.clone(),
        base.targeting_digest.clone(),
        digest("target-variation"),
        digest("target-targeting"),
        vec![SemanticPatchOperation::replace(
            "/variations/0",
            PatchValue::VariationIndex(1),
        )],
    )
    .expect("patch")
}

fn secret(scope: &FeatureReleaseScope) -> SecretReference {
    secret_with_id(scope, "secret-ref-launchdarkly-read")
}

fn secret_with_id(scope: &FeatureReleaseScope, reference_id: &str) -> SecretReference {
    SecretReference::for_scope(reference_id, scope, 1).expect("secret reference")
}

fn reseal_proposal(proposal: &mut FeatureReleaseResultProposal) {
    let mut semantic = to_value(&*proposal).expect("proposal json");
    let object = semantic.as_object_mut().expect("proposal object");
    object.remove("proposalDigest");
    object.remove("semanticFenceDigest");
    proposal.semantic_fence_digest = Digest::from_serialized(&semantic);

    let mut full = to_value(&*proposal).expect("proposal json");
    full.as_object_mut()
        .expect("proposal object")
        .remove("proposalDigest");
    proposal.proposal_digest = Digest::from_serialized(&full);
}

fn reseal_read_evidence(evidence: &mut ReleaseReadEvidence) {
    for approval in &mut evidence.approvals {
        let mut value = to_value(&*approval).expect("approval json");
        value
            .as_object_mut()
            .expect("approval object")
            .remove("evidenceDigest");
        approval.evidence_digest = Digest::from_serialized(&value);
    }
    for audit in &mut evidence.audit_entries {
        let mut value = to_value(&*audit).expect("audit json");
        value
            .as_object_mut()
            .expect("audit object")
            .remove("evidenceDigest");
        audit.evidence_digest = Digest::from_serialized(&value);
    }
    let without_digest = (
        &evidence.availability,
        &evidence.scope_digest,
        &evidence.registration_digest,
        &evidence.flag,
        &evidence.approvals,
        &evidence.audit_entries,
        &evidence.audit_limit,
        &evidence.provider_code_digest,
        &evidence.provenance,
        &evidence.retry_summary,
        &evidence.claims,
    );
    evidence.evidence_digest = Digest::from_serialized(&without_digest);
}

#[test]
#[allow(clippy::too_many_lines)]
fn typed_service_compiles_but_recording_never_becomes_adoptable() {
    let scope = scope();
    let before = flag(&scope, 42, "before");
    let approval = approved(&scope, "approval-01", ApprovalStatus::Approved);
    let transport = RecordingTransport::new(before.clone(), vec![approval], Vec::new());
    let provider =
        LaunchDarklyReleaseProvider::with_defaults(transport, scope.clone(), secret(&scope))
            .expect("provider");
    let mut service = FeatureReleaseService::new(provider);

    let description = service.describe_release();
    assert_eq!(description.service_definition.service_id, SERVICE_ID);
    assert_eq!(description.availability, EvidenceAvailability::Complete);
    assert_eq!(description.claims, EvidenceClaims::layer_one());

    let evidence = service.read_flag_evidence().expect("read evidence");
    assert_eq!(evidence.retry_summary.flag_attempts, 1);
    let patch = patch(&scope, &before);
    let dry_run = DryRunEvidence::local_valid(&scope, &before, &patch).expect("dry run");
    let request = FeatureReleaseProposalRequest::for_scope(&scope, patch, false).expect("request");
    let proposal = service
        .compile_release_proposal(&request, &evidence, &dry_run)
        .expect("proposal");
    assert_eq!(proposal.status, ReleaseStatus::Approved);
    assert!(!proposal.recordable);
    assert!(!proposal.dry_run);
    assert_eq!(proposal.claims, EvidenceClaims::layer_one());
    let mission_proposal = MissionFeatureReleaseConsumer::for_request_with_evidence(
        &scope,
        service
            .provider()
            .registration_receipt()
            .registration_digest
            .clone(),
        request.clone(),
        &evidence,
    )
    .expect("mission consumer")
    .consume(&proposal)
    .expect("mission proposal");
    assert_eq!(mission_proposal.status, ReleaseStatus::Approved);
    assert!(!mission_proposal.adoptable);
    assert_eq!(
        mission_proposal.authority_boundary,
        AuthorityBoundary::layer_one()
    );
    assert_eq!(
        MissionFeatureReleaseConsumer::for_request(
            &scope,
            service
                .provider()
                .registration_receipt()
                .registration_digest
                .clone(),
            request.clone(),
        )
        .expect("legacy request consumer")
        .consume(&proposal),
        Err(FeatureReleaseError::ProposalSemanticMismatch)
    );
    assert_eq!(
        MissionFeatureReleaseConsumer::for_scope(
            &scope,
            service
                .provider()
                .registration_receipt()
                .registration_digest
                .clone(),
        )
        .consume(&proposal),
        Err(FeatureReleaseError::ProposalSemanticMismatch)
    );

    let loopback_provider = LaunchDarklyReleaseProvider::with_defaults(
        LoopbackTransport::new(
            before.clone(),
            vec![approved(
                &scope,
                "approval-loopback",
                ApprovalStatus::Approved,
            )],
            Vec::new(),
        ),
        scope.clone(),
        secret(&scope),
    )
    .expect("loopback provider");
    let mut loopback_service = FeatureReleaseService::new(loopback_provider);
    let loopback_evidence = loopback_service
        .read_flag_evidence()
        .expect("loopback evidence");
    let loopback_proposal = loopback_service
        .compile_release_proposal(&request, &loopback_evidence, &dry_run)
        .expect("loopback proposal");
    assert_eq!(loopback_proposal.status, ReleaseStatus::Approved);
    assert!(!loopback_proposal.recordable);
    let loopback_mission = MissionFeatureReleaseConsumer::for_request_with_evidence(
        &scope,
        loopback_service
            .provider()
            .registration_receipt()
            .registration_digest
            .clone(),
        request.clone(),
        &loopback_evidence,
    )
    .expect("loopback mission consumer")
    .consume(&loopback_proposal)
    .expect("loopback mission proposal");
    assert!(!loopback_mission.adoptable);

    let after = flag(&scope, 43, "after");
    let applied_audit = AuditEvidence::for_scope_with_bindings(
        &scope,
        "audit-01",
        AuditEventKind::ChangeApplied,
        43,
        b"actor@example.invalid",
        b"raw targeting context user=customer@example.invalid",
        Some("approval-01".into()),
        Some(
            proposal
                .approval
                .as_ref()
                .expect("approval evidence")
                .evidence_digest
                .clone(),
        ),
        Some(proposal.proposal_digest.clone()),
        2_000,
    )
    .expect("audit");
    let readback = ReleaseReadBack::new(
        &scope,
        service
            .provider()
            .registration_receipt()
            .registration_digest
            .clone(),
        after,
        vec![applied_audit],
        TransportProvenance::Recording,
    )
    .expect("read back");
    assert_eq!(
        service.record_release_receipt(&proposal, &readback),
        Err(FeatureReleaseError::ApprovalNotApproved)
    );

    let encoded = to_string(&(&description, &evidence, &proposal)).expect("json");
    assert!(!encoded.contains("reviewer@example.invalid"));
    assert!(!encoded.contains("customer@example.invalid"));
    assert!(!encoded.contains("targeting context"));
    assert!(!encoded.contains("token-value"));
    let payload = FeatureReleaseContractPayload::from_evidence(
        &scope,
        service.provider().registration_receipt(),
        &evidence,
    )
    .expect("contract payload");
    let mut tampered_payload = to_value(&payload).expect("payload json");
    tampered_payload["evidence"]["flag"]["unexpected"] = json!(true);
    assert_eq!(
        validate_contract_json(&tampered_payload),
        Err(FeatureReleaseError::SchemaValidation)
    );
}

#[test]
fn dry_run_is_validation_only_and_redacted_types_have_no_secret_or_context_fields() {
    let scope = scope();
    let before = flag(&scope, 42, "before");
    let transport = RecordingTransport::new(
        before.clone(),
        vec![approved(&scope, "approval-01", ApprovalStatus::Approved)],
        Vec::new(),
    );
    let provider =
        LaunchDarklyReleaseProvider::with_defaults(transport, scope.clone(), secret(&scope))
            .expect("provider");
    let mut service = FeatureReleaseService::new(provider);
    let evidence = service.read_flag_evidence().expect("evidence");
    let patch = patch(&scope, &before);
    let dry_run = DryRunEvidence::local_valid(&scope, &before, &patch).expect("dry run");
    let request = FeatureReleaseProposalRequest::for_scope(&scope, patch, true).expect("request");
    let proposal = service
        .compile_release_proposal(&request, &evidence, &dry_run)
        .expect("proposal");
    assert!(!proposal.recordable);
    let readback = ReleaseReadBack::new(
        &scope,
        service
            .provider()
            .registration_receipt()
            .registration_digest
            .clone(),
        flag(&scope, 43, "after"),
        vec![audit(
            &scope,
            "audit-01",
            43,
            AuditEventKind::ChangeScheduled,
            None,
        )],
        TransportProvenance::Loopback,
    )
    .expect("readback");
    assert_eq!(
        service.record_release_receipt(&proposal, &readback),
        Err(FeatureReleaseError::DryRunReceiptForbidden)
    );
    let encoded = to_string(&proposal).expect("proposal json");
    assert!(!encoded.contains("connected\":true"));
    assert!(!encoded.contains("native\":true"));
    assert!(!encoded.contains("firstParty\":true"));
}

#[test]
fn adversarial_digest_version_conflict_and_redaction_fences_fail_closed() {
    let scope = scope();
    let before = flag(&scope, 42, "before");
    let patch = patch(&scope, &before);
    let dry_run = DryRunEvidence::local_valid(&scope, &before, &patch).expect("dry run");

    let drifted_transport = RecordingTransport::new(
        flag(&scope, 41, "older"),
        vec![approved(&scope, "approval-01", ApprovalStatus::Approved)],
        Vec::new(),
    );
    let drifted_provider = LaunchDarklyReleaseProvider::with_defaults(
        drifted_transport,
        scope.clone(),
        secret(&scope),
    )
    .expect("provider");
    let mut drifted = FeatureReleaseService::new(drifted_provider);
    assert!(matches!(
        drifted.read_flag_evidence(),
        Err(FeatureReleaseError::VersionDrift { .. })
    ));
    let request =
        FeatureReleaseProposalRequest::for_scope(&scope, patch.clone(), false).expect("request");

    let conflict_transport = RecordingTransport::new(
        before.clone(),
        vec![
            approved(&scope, "approval-01", ApprovalStatus::Approved),
            approved(&scope, "approval-02", ApprovalStatus::Approved),
        ],
        Vec::new(),
    );
    let conflict_provider = LaunchDarklyReleaseProvider::with_defaults(
        conflict_transport,
        scope.clone(),
        secret(&scope),
    )
    .expect("provider");
    let mut conflict = FeatureReleaseService::new(conflict_provider);
    let conflict_evidence = conflict.read_flag_evidence().expect("conflict evidence");
    let proposal = conflict
        .compile_release_proposal(&request, &conflict_evidence, &dry_run)
        .expect("conflict proposal");
    assert_eq!(proposal.status, ReleaseStatus::Conflicted);
    assert!(!proposal.recordable);

    let mut tampered_patch = patch.clone();
    tampered_patch.patch_digest = digest("tampered");
    assert!(matches!(
        tampered_patch.validate_against(&scope, &before),
        Err(FeatureReleaseError::InvalidDigest)
    ));
    assert_eq!(
        ReleaseReadBack::new(
            &scope,
            conflict
                .provider()
                .registration_receipt()
                .registration_digest
                .clone(),
            flag(&scope, 43, "after"),
            Vec::new(),
            TransportProvenance::Recording,
        ),
        Err(FeatureReleaseError::AuditMissing)
    );
    let long_description = vec![b'x'; MAX_AUDIT_DESCRIPTION_BYTES + 1];
    assert_eq!(
        AuditEvidence::for_scope(
            &scope,
            "audit-long",
            AuditEventKind::ChangeApplied,
            43,
            b"actor",
            long_description,
            None,
            None,
            2_000,
        ),
        Err(FeatureReleaseError::AuditUnbounded)
    );
}

#[test]
fn exact_provider_mission_and_audit_fences_reject_replay() {
    let scope = scope();
    let other_scope = scope_for("other-account", "https://other.launchdarkly.com");
    let before = flag(&scope, 42, "before");
    let patch = patch(&scope, &before);
    let dry_run = DryRunEvidence::local_valid(&scope, &before, &patch).expect("dry run");
    let request = FeatureReleaseProposalRequest::for_scope(&scope, patch, false).expect("request");
    let provider = LaunchDarklyReleaseProvider::with_defaults(
        RecordingTransport::new(
            before,
            vec![approved(&scope, "approval-01", ApprovalStatus::Approved)],
            Vec::new(),
        ),
        scope.clone(),
        secret(&scope),
    )
    .expect("provider");
    let mut service = FeatureReleaseService::new(provider);
    let evidence = service.read_flag_evidence().expect("evidence");
    let proposal = service
        .compile_release_proposal(&request, &evidence, &dry_run)
        .expect("proposal");
    let registration_digest = service
        .provider()
        .registration_receipt()
        .registration_digest
        .clone();

    let wrong_registration =
        MissionFeatureReleaseConsumer::for_scope(&scope, digest("different-registration"));
    assert_eq!(
        wrong_registration.consume(&proposal),
        Err(FeatureReleaseError::ProposalSemanticMismatch)
    );
    let wrong_account = MissionFeatureReleaseConsumer::for_scope(&other_scope, registration_digest);
    assert_eq!(
        wrong_account.consume(&proposal),
        Err(FeatureReleaseError::ProposalSemanticMismatch)
    );

    let cross_scope_audit = audit(
        &other_scope,
        "audit-cross-account",
        43,
        AuditEventKind::ChangeScheduled,
        None,
    );
    assert_eq!(
        cross_scope_audit.validate_for_scope(&scope),
        Err(FeatureReleaseError::ScopeMismatch)
    );
    assert!(matches!(
        AuditEvidence::for_scope_with_bindings(
            &scope,
            "audit-missing-bindings",
            AuditEventKind::ChangeApplied,
            43,
            b"actor",
            b"description",
            Some("approval-01".into()),
            None,
            Some(proposal.proposal_digest.clone()),
            2_000,
        ),
        Err(FeatureReleaseError::InvalidInput(_))
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn approval_and_audit_versions_bind_complete_contract_and_mission() {
    let scope = scope();
    let before = flag(&scope, 42, "version-fence");
    let wrong_approval = ApprovalEvidence::for_scope(
        &scope,
        "approval-wrong-version",
        ApprovalStatus::Approved,
        41,
        scope.policy_revision,
        b"decision",
        1_100,
    )
    .expect("wrong-version approval remains structurally valid");
    assert!(matches!(
        wrong_approval.validate_for_scope(&scope),
        Err(FeatureReleaseError::VersionDrift { .. })
    ));
    let wrong_audit = AuditEvidence::for_scope(
        &scope,
        "audit-wrong-version",
        AuditEventKind::ChangeScheduled,
        41,
        b"actor",
        b"description",
        None,
        None,
        2_000,
    )
    .expect("wrong-version audit remains structurally valid");
    assert!(matches!(
        wrong_audit.validate_for_scope(&scope),
        Err(FeatureReleaseError::VersionDrift { .. })
    ));

    let approval_provider = LaunchDarklyReleaseProvider::with_defaults(
        RecordingTransport::new(before.clone(), vec![wrong_approval.clone()], Vec::new()),
        scope.clone(),
        secret_with_id(&scope, "secret-ref-approval-version-complete"),
    )
    .expect("approval-version provider");
    let mut approval_service = FeatureReleaseService::new(approval_provider);
    assert!(matches!(
        approval_service.read_flag_evidence(),
        Err(FeatureReleaseError::VersionDrift { .. })
    ));

    let audit_provider = LaunchDarklyReleaseProvider::with_defaults(
        RecordingTransport::new(
            before.clone(),
            vec![approved(
                &scope,
                "approval-audit-version",
                ApprovalStatus::Approved,
            )],
            vec![wrong_audit.clone()],
        ),
        scope.clone(),
        secret_with_id(&scope, "secret-ref-audit-version-complete"),
    )
    .expect("audit-version provider");
    let mut audit_service = FeatureReleaseService::new(audit_provider);
    assert!(matches!(
        audit_service.read_flag_evidence(),
        Err(FeatureReleaseError::VersionDrift { .. })
    ));

    let exact_audit = audit(
        &scope,
        "audit-version-binding",
        42,
        AuditEventKind::ChangeScheduled,
        None,
    );
    let provider = LaunchDarklyReleaseProvider::with_defaults(
        RecordingTransport::new(
            before.clone(),
            vec![approved(
                &scope,
                "approval-version-binding",
                ApprovalStatus::Approved,
            )],
            vec![exact_audit],
        ),
        scope.clone(),
        secret_with_id(&scope, "secret-ref-version-contract"),
    )
    .expect("contract provider");
    let mut service = FeatureReleaseService::new(provider);
    let evidence = service.read_flag_evidence().expect("exact evidence");
    let registration = service.provider().registration_receipt().clone();

    let mut wrong_approval_evidence = evidence.clone();
    wrong_approval_evidence.approvals[0].flag_version = 41;
    reseal_read_evidence(&mut wrong_approval_evidence);
    assert!(matches!(
        FeatureReleaseContractPayload::from_evidence(
            &scope,
            &registration,
            &wrong_approval_evidence,
        ),
        Err(FeatureReleaseError::VersionDrift { .. })
    ));

    let mut wrong_audit_evidence = evidence.clone();
    wrong_audit_evidence.audit_entries[0].flag_version = 41;
    reseal_read_evidence(&mut wrong_audit_evidence);
    assert!(matches!(
        FeatureReleaseContractPayload::from_evidence(&scope, &registration, &wrong_audit_evidence,),
        Err(FeatureReleaseError::VersionDrift { .. })
    ));

    let patch = patch(&scope, &before);
    let request = FeatureReleaseProposalRequest::for_scope(&scope, patch, false).expect("request");
    let dry_run = DryRunEvidence::local_valid(&scope, &before, &request.patch).expect("dry run");
    let proposal = service
        .compile_release_proposal(&request, &evidence, &dry_run)
        .expect("scheduled proposal");
    let consumer = MissionFeatureReleaseConsumer::for_request_with_evidence(
        &scope,
        registration.registration_digest.clone(),
        request.clone(),
        &evidence,
    )
    .expect("evidence-bound mission consumer");
    consumer.consume(&proposal).expect("trusted proposal");

    let mut substituted_approval = proposal.clone();
    substituted_approval.approval = Some(
        ApprovalEvidence::for_scope(
            &scope,
            "approval-fabricated",
            ApprovalStatus::Approved,
            scope.flag_version,
            scope.policy_revision,
            b"fabricated decision",
            1_101,
        )
        .expect("fabricated approval remains structurally valid"),
    );
    substituted_approval.approval_status = Some(ApprovalStatus::Approved);
    reseal_proposal(&mut substituted_approval);
    assert_eq!(
        consumer.consume(&substituted_approval),
        Err(FeatureReleaseError::ProposalSemanticMismatch)
    );

    let mut fabricated = proposal.clone();
    fabricated.audit_fence.entry_kinds[0] = AuditEventKind::ChangeApplied;
    fabricated.audit_fence.entry_digests[0] = digest("fabricated-audit");
    fabricated.status = ReleaseStatus::Applied;
    reseal_proposal(&mut fabricated);
    assert_eq!(
        consumer.consume(&fabricated),
        Err(FeatureReleaseError::ProposalSemanticMismatch)
    );
    let unbound_consumer = MissionFeatureReleaseConsumer::for_request(
        &scope,
        registration.registration_digest,
        request,
    )
    .expect("unbound consumer");
    assert_eq!(
        unbound_consumer.consume(&proposal),
        Err(FeatureReleaseError::ProposalSemanticMismatch)
    );
}

#[test]
fn plugin_version_unknown_fields_fail_schema_and_serde() {
    let scope = scope();
    let provider = LaunchDarklyReleaseProvider::with_defaults(
        RecordingTransport::new(
            flag(&scope, 42, "plugin-version"),
            vec![approved(
                &scope,
                "approval-plugin-version",
                ApprovalStatus::Approved,
            )],
            Vec::new(),
        ),
        scope.clone(),
        secret_with_id(&scope, "secret-ref-plugin-version"),
    )
    .expect("provider");
    let mut service = FeatureReleaseService::new(provider);
    let evidence = service.read_flag_evidence().expect("evidence");
    let payload = FeatureReleaseContractPayload::from_evidence(
        &scope,
        service.provider().registration_receipt(),
        &evidence,
    )
    .expect("payload");
    let mut encoded = to_value(&payload).expect("payload json");
    encoded["registration"]["pluginVersion"]["extra"] = json!(true);
    assert_eq!(
        validate_contract_json(&encoded),
        Err(FeatureReleaseError::SchemaValidation)
    );
    assert!(serde_json::from_value::<FeatureReleaseContractPayload>(encoded).is_err());
}

#[test]
fn legacy_mission_consumers_fail_closed_for_empty_audit_statuses() {
    let scope = scope();
    let before = flag(&scope, 42, "legacy-mission");
    let patch = patch(&scope, &before);
    let dry_run = DryRunEvidence::local_valid(&scope, &before, &patch).expect("dry run");
    let request = FeatureReleaseProposalRequest::for_scope(&scope, patch, false).expect("request");
    let cases = vec![
        (
            vec![approved(
                &scope,
                "approval-legacy-approved",
                ApprovalStatus::Approved,
            )],
            ReleaseStatus::Approved,
            "approved",
        ),
        (Vec::new(), ReleaseStatus::Pending, "pending"),
    ];
    for (approvals, expected_status, case_id) in cases {
        let provider = LaunchDarklyReleaseProvider::with_defaults(
            RecordingTransport::new(before.clone(), approvals, Vec::new()),
            scope.clone(),
            secret_with_id(&scope, &format!("secret-ref-legacy-{case_id}")),
        )
        .expect("provider");
        let mut service = FeatureReleaseService::new(provider);
        let evidence = service.read_flag_evidence().expect("evidence");
        let proposal = service
            .compile_release_proposal(&request, &evidence, &dry_run)
            .expect("proposal");
        assert_eq!(proposal.status, expected_status);
        assert!(proposal.audit_fence.entry_ids.is_empty());
        let registration_digest = service
            .provider()
            .registration_receipt()
            .registration_digest
            .clone();
        assert_eq!(
            MissionFeatureReleaseConsumer::for_request(
                &scope,
                registration_digest.clone(),
                request.clone(),
            )
            .expect("legacy request consumer")
            .consume(&proposal),
            Err(FeatureReleaseError::ProposalSemanticMismatch)
        );
        assert_eq!(
            MissionFeatureReleaseConsumer::for_scope(&scope, registration_digest)
                .consume(&proposal),
            Err(FeatureReleaseError::ProposalSemanticMismatch)
        );
    }
}

#[test]
fn mission_denies_recomputed_cross_semantic_proposal() {
    let scope = scope();
    let before = flag(&scope, 42, "before");
    let original_patch = patch(&scope, &before);
    let dry_run = DryRunEvidence::local_valid(&scope, &before, &original_patch).expect("dry run");
    let request = FeatureReleaseProposalRequest::for_scope(&scope, original_patch.clone(), false)
        .expect("request");
    let provider = LaunchDarklyReleaseProvider::with_defaults(
        RecordingTransport::new(
            before.clone(),
            vec![approved(&scope, "approval-01", ApprovalStatus::Approved)],
            Vec::new(),
        ),
        scope.clone(),
        secret(&scope),
    )
    .expect("provider");
    let mut service = FeatureReleaseService::new(provider);
    let evidence = service.read_flag_evidence().expect("evidence");
    let proposal = service
        .compile_release_proposal(&request, &evidence, &dry_run)
        .expect("proposal");
    let registration_digest = service
        .provider()
        .registration_receipt()
        .registration_digest
        .clone();
    let consumer = MissionFeatureReleaseConsumer::for_request_with_evidence(
        &scope,
        registration_digest,
        request,
        &evidence,
    )
    .expect("consumer");

    let replacement_patch = SemanticPatch::new(
        original_patch.base_flag_version,
        original_patch.base_variation_digest.clone(),
        original_patch.base_targeting_digest.clone(),
        digest("different-target-variation"),
        original_patch.target_targeting_digest.clone(),
        original_patch.operations.clone(),
    )
    .expect("replacement patch");
    let mut tampered_patch = proposal.clone();
    tampered_patch.patch = replacement_patch;
    reseal_proposal(&mut tampered_patch);
    assert_eq!(
        consumer.consume(&tampered_patch),
        Err(FeatureReleaseError::ProposalSemanticMismatch)
    );

    let mut tampered_approval = proposal;
    tampered_approval.approval_status = Some(ApprovalStatus::Declined);
    reseal_proposal(&mut tampered_approval);
    assert_eq!(
        consumer.consume(&tampered_approval),
        Err(FeatureReleaseError::ProposalSemanticMismatch)
    );
}

#[test]
fn secret_tamper_revoke_and_retry_bounds_fail_closed() {
    let scope = scope();
    let before = flag(&scope, 42, "before");
    let original_secret = secret_with_id(&scope, "secret-ref-revocation-regression");
    let original_secret_json = to_value(&original_secret).expect("secret json");
    let mut tampered_secret = original_secret_json.clone();
    tampered_secret["metadataDigest"] = json!(digest("tampered").to_string());
    let tampered_secret: SecretReference =
        serde_json::from_value(tampered_secret).expect("secret reference json");
    assert_eq!(
        tampered_secret.validate(),
        Err(FeatureReleaseError::SecretReferenceTampered)
    );

    let mut registration = FeatureReleaseRegistration::new(
        &scope,
        &original_secret,
        PluginVersion::new(1, 0, 0),
        DEFAULT_ADAPTER_REVISION,
        DEFAULT_API_REVISION,
        PermissionSnapshot::read_only(&scope),
    )
    .expect("registration");
    let mut revoked_secret = original_secret.clone();
    revoked_secret.revoke().expect("revoke secret");
    assert_ne!(
        original_secret.reference_digest(),
        revoked_secret.reference_digest()
    );
    registration
        .record_secret_revocation(&scope, &revoked_secret)
        .expect("persist revocation tombstone");
    let rolled_back: SecretReference =
        serde_json::from_value(original_secret_json).expect("old secret snapshot");
    rolled_back
        .validate()
        .expect("old snapshot remains well formed");
    assert!(matches!(
        FeatureReleaseRegistration::new(
            &scope,
            &rolled_back,
            PluginVersion::new(1, 0, 0),
            DEFAULT_ADAPTER_REVISION,
            DEFAULT_API_REVISION,
            PermissionSnapshot::read_only(&scope),
        ),
        Err(FeatureReleaseError::SecretReferenceRevoked)
    ));
    assert_eq!(
        registration.reregister(&scope, &rolled_back),
        Err(FeatureReleaseError::SecretReferenceRevoked)
    );

    let mut provider = LaunchDarklyReleaseProvider::with_defaults(
        RecordingTransport::new(before, Vec::new(), Vec::new()),
        scope.clone(),
        secret_with_id(&scope, "secret-ref-revocation-provider"),
    )
    .expect("provider");
    provider.revoke_secret_reference().expect("secret revoke");
    assert!(provider.secret_reference().is_revoked());
    assert_eq!(
        provider.read_flag_evidence(),
        Err(FeatureReleaseError::SecretReferenceRevoked)
    );
    provider.revoke_registration().expect("registration revoke");
    assert_eq!(
        provider.reregister(),
        Err(FeatureReleaseError::SecretReferenceRevoked)
    );

    let unbounded: RetryPolicy = serde_json::from_value(json!({
        "maxAttempts": 255,
        "maxBackoffSeconds": 60
    }))
    .expect("retry policy json");
    assert!(matches!(
        unbounded.validate(),
        Err(FeatureReleaseError::InvalidInput(_))
    ));
    assert!(matches!(
        LaunchDarklyReleaseProvider::new(
            RecordingTransport::new(flag(&scope, 42, "retry"), Vec::new(), Vec::new()),
            scope.clone(),
            secret(&scope),
            PluginVersion::new(1, 0, 0),
            DEFAULT_ADAPTER_REVISION,
            DEFAULT_API_REVISION,
            unbounded,
        ),
        Err(FeatureReleaseError::InvalidInput(_))
    ));
}

#[test]
fn blocked_env_is_not_contract_or_mission_evidence() {
    let scope = scope();
    let provider = LaunchDarklyReleaseProvider::with_defaults(
        BlockedEnvTransport::new("missing-launchdarkly-token"),
        scope.clone(),
        secret(&scope),
    )
    .expect("provider");
    let service = FeatureReleaseService::new(provider);
    let registration = service.provider().registration_receipt().clone();
    let before = flag(&scope, 42, "before");
    let patch = patch(&scope, &before);
    let request =
        FeatureReleaseProposalRequest::for_scope(&scope, patch.clone(), false).expect("request");
    let blocked = ReleaseReadEvidence::blocked_env_for_registration(
        &scope,
        registration.registration_digest.clone(),
        b"environment blocked",
    );
    assert_eq!(
        FeatureReleaseContractPayload::from_evidence(&scope, &registration, &blocked),
        Err(FeatureReleaseError::RegistrationFenceMismatch)
    );
    let proposal = service
        .compile_release_proposal(
            &request,
            &blocked,
            &DryRunEvidence::rejected(&scope, &patch, b"blocked"),
        )
        .expect("blocked proposal");
    assert_eq!(proposal.status, ReleaseStatus::BlockedEnv);
    assert!(!proposal.recordable);
    assert_eq!(
        MissionFeatureReleaseConsumer::for_scope(&scope, registration.registration_digest.clone(),)
            .consume(&proposal),
        Err(FeatureReleaseError::ProposalSemanticMismatch)
    );
}

#[test]
fn bounded_429_retries_and_405_400_401_403_404_409_statuses_are_transparent() {
    let scope = scope();
    let before = flag(&scope, 42, "before");
    let retried_transport = RecordingTransport::from_results(
        vec![
            Err(TransportError::http(429, b"retry body")),
            Ok(before.clone()),
        ],
        vec![Ok(vec![])],
        vec![Ok(vec![])],
        TransportProvenance::Recording,
    );
    let provider = LaunchDarklyReleaseProvider::with_defaults(
        retried_transport,
        scope.clone(),
        secret(&scope),
    )
    .expect("provider");
    let mut service = FeatureReleaseService::new(provider);
    let evidence = service.read_flag_evidence().expect("bounded retry");
    assert_eq!(evidence.retry_summary.flag_attempts, 2);
    assert_eq!(evidence.provenance, TransportProvenance::Recording);
    assert!(!EvidenceClaims::layer_one().connected);

    let fixture_provider = LaunchDarklyReleaseProvider::with_defaults(
        FixtureTransport::new(before.clone(), Vec::new(), Vec::new()),
        scope.clone(),
        secret(&scope),
    )
    .expect("fixture provider");
    let mut fixture_service = FeatureReleaseService::new(fixture_provider);
    assert_eq!(
        fixture_service.describe_release().availability,
        EvidenceAvailability::BlockedEnv
    );
    assert_eq!(
        fixture_service.read_flag_evidence(),
        Err(FeatureReleaseError::ProvenanceForbidden)
    );

    for status in [400, 401, 403, 404, 409] {
        let transport = RecordingTransport::from_results(
            vec![Err(TransportError::http(status, b"opaque response"))],
            vec![Ok(vec![])],
            vec![Ok(vec![])],
            TransportProvenance::Recording,
        );
        let provider =
            LaunchDarklyReleaseProvider::with_defaults(transport, scope.clone(), secret(&scope))
                .expect("provider");
        let mut service = FeatureReleaseService::new(provider);
        let error = service.read_flag_evidence().expect_err("http error");
        assert_eq!(
            match error {
                FeatureReleaseError::Transport(transport) => transport.status(),
                other => panic!("unexpected error: {other:?}"),
            },
            Some(status)
        );
    }

    let approval_405 = RecordingTransport::from_results(
        vec![Ok(before)],
        vec![Err(TransportError::http(405, b"approval required"))],
        vec![Ok(vec![])],
        TransportProvenance::Recording,
    );
    let provider =
        LaunchDarklyReleaseProvider::with_defaults(approval_405, scope.clone(), secret(&scope))
            .expect("provider");
    let mut service = FeatureReleaseService::new(provider);
    let error = service.read_flag_evidence().expect_err("approval 405");
    assert_eq!(
        match error {
            FeatureReleaseError::Transport(transport) => transport.status(),
            other => panic!("unexpected error: {other:?}"),
        },
        Some(405)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn scheduled_declined_stale_unknown_blocked_env_and_revocation_never_become_native() {
    let scope = scope();
    let before = flag(&scope, 42, "before");
    let patch = patch(&scope, &before);
    let dry_run = DryRunEvidence::local_valid(&scope, &before, &patch).expect("dry run");
    let request = FeatureReleaseProposalRequest::for_scope(&scope, patch, false).expect("request");

    let scheduled_transport = RecordingTransport::new(
        before.clone(),
        vec![approved(&scope, "approval-01", ApprovalStatus::Approved)],
        vec![audit(
            &scope,
            "audit-scheduled",
            42,
            AuditEventKind::ChangeScheduled,
            None,
        )],
    );
    let provider = LaunchDarklyReleaseProvider::with_defaults(
        scheduled_transport,
        scope.clone(),
        secret(&scope),
    )
    .expect("provider");
    let mut service = FeatureReleaseService::new(provider);
    let evidence = service.read_flag_evidence().expect("scheduled evidence");
    assert_eq!(
        service
            .compile_release_proposal(&request, &evidence, &dry_run)
            .expect("scheduled proposal")
            .status,
        ReleaseStatus::Scheduled
    );

    for (approval_status, expected) in [
        (ApprovalStatus::Declined, ReleaseStatus::Declined),
        (ApprovalStatus::Pending, ReleaseStatus::Pending),
        (ApprovalStatus::Unknown, ReleaseStatus::ProviderUnknown),
    ] {
        let transport = RecordingTransport::new(
            before.clone(),
            vec![approved(&scope, "approval-01", approval_status)],
            Vec::new(),
        );
        let provider =
            LaunchDarklyReleaseProvider::with_defaults(transport, scope.clone(), secret(&scope))
                .expect("provider");
        let mut service = FeatureReleaseService::new(provider);
        let evidence = service.read_flag_evidence().expect("approval evidence");
        assert_eq!(
            service
                .compile_release_proposal(&request, &evidence, &dry_run)
                .expect("approval proposal")
                .status,
            expected
        );
    }

    let stale = ApprovalEvidence::for_scope(
        &scope,
        "approval-stale",
        ApprovalStatus::Approved,
        scope.flag_version,
        scope.policy_revision - 1,
        b"old policy",
        1_100,
    )
    .expect("stale approval");
    let provider = LaunchDarklyReleaseProvider::with_defaults(
        RecordingTransport::new(before.clone(), vec![stale], Vec::new()),
        scope.clone(),
        secret(&scope),
    )
    .expect("provider");
    let mut service = FeatureReleaseService::new(provider);
    let evidence = service.read_flag_evidence().expect("stale evidence");
    assert_eq!(
        service
            .compile_release_proposal(&request, &evidence, &dry_run)
            .expect("stale proposal")
            .status,
        ReleaseStatus::Stale
    );

    let provider = LaunchDarklyReleaseProvider::with_defaults(
        BlockedEnvTransport::new("missing-launchdarkly-token"),
        scope.clone(),
        secret(&scope),
    )
    .expect("blocked provider");
    let mut service = FeatureReleaseService::new(provider);
    assert_eq!(
        service.describe_release().availability,
        EvidenceAvailability::BlockedEnv
    );
    assert!(matches!(
        service.read_flag_evidence(),
        Err(FeatureReleaseError::Transport(
            TransportError::BlockedEnv { .. }
        ))
    ));

    let provider = LaunchDarklyReleaseProvider::with_defaults(
        RecordingTransport::new(before, vec![], vec![]),
        scope.clone(),
        secret(&scope),
    )
    .expect("revocable provider");
    let mut service = FeatureReleaseService::new(provider);
    let old_registration = service
        .provider()
        .registration_receipt()
        .registration_digest
        .clone();
    service
        .provider_mut()
        .revoke_registration()
        .expect("revoke");
    assert_eq!(
        service.read_flag_evidence(),
        Err(FeatureReleaseError::RegistrationRevoked)
    );
    service.provider_mut().reregister().expect("reregister");
    assert_ne!(
        old_registration,
        service
            .provider()
            .registration_receipt()
            .registration_digest
    );

    let unknown = ReleaseReadEvidence::provider_unknown_for_registration(
        &scope,
        service
            .provider()
            .registration_receipt()
            .registration_digest
            .clone(),
        b"provider state was not bounded",
    );
    let proposal = service
        .compile_release_proposal(
            &request,
            &unknown,
            &DryRunEvidence::rejected(&scope, &request.patch, b"unknown"),
        )
        .expect("unknown proposal");
    assert_eq!(proposal.status, ReleaseStatus::ProviderUnknown);
    assert!(!proposal.claims.native);
}
