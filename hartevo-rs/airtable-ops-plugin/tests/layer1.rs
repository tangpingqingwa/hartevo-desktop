use std::collections::BTreeMap;

use hartevo_airtable_ops_plugin::{
    AIRTABLE_MAX_BATCH_SIZE, AirtableBaseId, AirtableError, AirtableFieldAllowlist,
    AirtableFieldBinding, AirtableFieldDefinition, AirtableFieldId, AirtableFieldType,
    AirtableMissionConsumer, AirtableOffset, AirtableOpsProvider, AirtableOpsService,
    AirtableProviderError, AirtableProviderProvenance, AirtableRecordId, AirtableRecordPage,
    AirtableRecordSnapshot, AirtableScope, AirtableTableId, AirtableTableSchema, AirtableViewId,
    BlockedEnvAirtableProvider, FakeAirtableProvider, ListRecordsRequest, MissionId, MissionOutput,
    MissionOutputKind, MissionRecordProposalRequest, OutcomeCandidate, OutcomeCandidateId,
    ProjectId, ReadbackMismatchField, RecordReadback, RecordReceipt, RecordValue, SecretReference,
    StableRecordField, WorkProduct, WorkProductId,
};

fn scope() -> AirtableScope {
    AirtableScope::new(
        AirtableBaseId::new("app-layer1").expect("base ID"),
        AirtableTableId::new("tbl-outcomes").expect("table ID"),
        Some(AirtableViewId::new("viw-ops").expect("view ID")),
    )
}

fn schema(scope: &AirtableScope) -> AirtableTableSchema {
    let fields = [
        (
            "fld-mission",
            "Mission ID",
            AirtableFieldType::SingleLineText,
        ),
        (
            "fld-project",
            "Project ID",
            AirtableFieldType::SingleLineText,
        ),
        (
            "fld-work-product",
            "WorkProduct ID",
            AirtableFieldType::SingleLineText,
        ),
        (
            "fld-outcome-candidate",
            "OutcomeCandidate ID",
            AirtableFieldType::SingleLineText,
        ),
        ("fld-kind", "Output Kind", AirtableFieldType::SingleSelect),
        ("fld-revision", "Revision", AirtableFieldType::Number),
        ("fld-title", "Title", AirtableFieldType::SingleLineText),
        ("fld-summary", "Summary", AirtableFieldType::MultilineText),
        (
            "fld-content-fingerprint",
            "Content Fingerprint",
            AirtableFieldType::SingleLineText,
        ),
        (
            "fld-idempotency",
            "Idempotency Key",
            AirtableFieldType::SingleLineText,
        ),
    ]
    .into_iter()
    .map(|(id, name, field_type)| {
        AirtableFieldDefinition::new(
            AirtableFieldId::new(id).expect("field ID"),
            name,
            field_type,
            true,
        )
        .expect("field definition")
    })
    .collect();
    AirtableTableSchema::new(scope.clone(), "schema-rev-1", fields).expect("schema")
}

fn binding(
    stable_field: StableRecordField,
    id: &str,
    name: &str,
    field_type: AirtableFieldType,
) -> AirtableFieldBinding {
    AirtableFieldBinding::new(
        stable_field,
        AirtableFieldId::new(id).expect("field ID"),
        name,
        field_type,
    )
    .expect("binding")
}

fn work_product_allowlist() -> AirtableFieldAllowlist {
    AirtableFieldAllowlist::new([
        binding(
            StableRecordField::MissionId,
            "fld-mission",
            "Mission ID",
            AirtableFieldType::SingleLineText,
        ),
        binding(
            StableRecordField::ProjectId,
            "fld-project",
            "Project ID",
            AirtableFieldType::SingleLineText,
        ),
        binding(
            StableRecordField::WorkProductId,
            "fld-work-product",
            "WorkProduct ID",
            AirtableFieldType::SingleLineText,
        ),
        binding(
            StableRecordField::OutputKind,
            "fld-kind",
            "Output Kind",
            AirtableFieldType::SingleSelect,
        ),
        binding(
            StableRecordField::Revision,
            "fld-revision",
            "Revision",
            AirtableFieldType::Number,
        ),
        binding(
            StableRecordField::Title,
            "fld-title",
            "Title",
            AirtableFieldType::SingleLineText,
        ),
        binding(
            StableRecordField::Summary,
            "fld-summary",
            "Summary",
            AirtableFieldType::MultilineText,
        ),
        binding(
            StableRecordField::ContentFingerprint,
            "fld-content-fingerprint",
            "Content Fingerprint",
            AirtableFieldType::SingleLineText,
        ),
        binding(
            StableRecordField::IdempotencyKey,
            "fld-idempotency",
            "Idempotency Key",
            AirtableFieldType::SingleLineText,
        ),
    ])
    .expect("work product allowlist")
}

fn outcome_allowlist() -> AirtableFieldAllowlist {
    let mut bindings = work_product_allowlist()
        .bindings
        .into_values()
        .collect::<Vec<_>>();
    bindings.retain(|binding| binding.stable_field != StableRecordField::WorkProductId);
    bindings.push(binding(
        StableRecordField::OutcomeCandidateId,
        "fld-outcome-candidate",
        "OutcomeCandidate ID",
        AirtableFieldType::SingleLineText,
    ));
    AirtableFieldAllowlist::new(bindings).expect("outcome allowlist")
}

fn work_product() -> MissionOutput {
    MissionOutput::WorkProduct(
        WorkProduct::new(
            MissionId::new("mission-42").expect("mission ID"),
            ProjectId::new("project-7").expect("project ID"),
            WorkProductId::new("work-product-9").expect("work product ID"),
            3,
            "Structured outcome",
            "A stable summary",
            "Sensitive source content is fingerprinted, not copied to the receipt",
        )
        .expect("work product"),
    )
}

fn outcome_candidate() -> MissionOutput {
    MissionOutput::OutcomeCandidate(
        OutcomeCandidate::new(
            MissionId::new("mission-42").expect("mission ID"),
            ProjectId::new("project-7").expect("project ID"),
            OutcomeCandidateId::new("candidate-9").expect("candidate ID"),
            4,
            "Candidate outcome",
            "A candidate summary",
            "Candidate source content",
        )
        .expect("outcome candidate"),
    )
}

fn request(
    scope: &AirtableScope,
    schema: &AirtableTableSchema,
    allowlist: AirtableFieldAllowlist,
    output: MissionOutput,
) -> MissionRecordProposalRequest {
    MissionRecordProposalRequest::new(scope.clone(), schema.clone(), allowlist, output)
        .expect("proposal request")
}

fn proposal() -> hartevo_airtable_ops_plugin::RecordProposal {
    let scope = scope();
    let schema = schema(&scope);
    AirtableOpsService::new()
        .compile_record_proposal(request(
            &scope,
            &schema,
            work_product_allowlist(),
            work_product(),
        ))
        .expect("record proposal")
}

fn snapshot(
    scope: &AirtableScope,
    record_id: &str,
    field_fingerprint: &str,
    content_digest: &str,
) -> AirtableRecordSnapshot {
    AirtableRecordSnapshot {
        record_id: AirtableRecordId::new(record_id).expect("record ID"),
        scope: scope.clone(),
        field_fingerprint: field_fingerprint.to_owned(),
        revision: 1,
        content_digest: content_digest.to_owned(),
        fields: BTreeMap::new(),
    }
}

#[test]
fn work_product_proposal_is_deterministic_scoped_and_allowlisted() {
    let scope = scope();
    let schema = schema(&scope);
    let service = AirtableOpsService::new();
    let first = service
        .compile_record_proposal(request(
            &scope,
            &schema,
            work_product_allowlist(),
            work_product(),
        ))
        .expect("first proposal");
    let second = service
        .compile_record_proposal(request(
            &scope,
            &schema,
            work_product_allowlist(),
            work_product(),
        ))
        .expect("second proposal");

    assert_eq!(first, second);
    assert_eq!(first.scope, scope);
    assert_eq!(first.output_kind, MissionOutputKind::WorkProduct);
    assert_eq!(first.output_id, "work-product-9");
    assert_eq!(first.revision, 3);
    assert_eq!(first.fields.len(), 9);
    assert!(!first.content_fingerprint.is_empty());
    assert!(!first.idempotency_key.is_empty());
    assert!(
        first
            .field_names()
            .iter()
            .all(|name| name != "Unapproved secret field")
    );
    assert!(
        !serde_json::to_string(&first)
            .expect("proposal JSON")
            .contains("Sensitive source content")
    );
}

#[test]
fn outcome_candidate_uses_its_own_stable_identity_field() {
    let scope = scope();
    let schema = schema(&scope);
    let proposal = AirtableOpsService::new()
        .compile_record_proposal(request(
            &scope,
            &schema,
            outcome_allowlist(),
            outcome_candidate(),
        ))
        .expect("outcome proposal");

    assert_eq!(proposal.output_kind, MissionOutputKind::OutcomeCandidate);
    assert_eq!(proposal.output_id, "candidate-9");
    assert!(
        proposal
            .fields
            .iter()
            .any(|field| field.stable_field == StableRecordField::OutcomeCandidateId)
    );
    assert!(
        !proposal
            .fields
            .iter()
            .any(|field| field.stable_field == StableRecordField::WorkProductId)
    );
}

#[test]
fn typed_mission_consumer_constructs_the_same_deterministic_proposal() {
    let scope = scope();
    let schema = schema(&scope);
    let service_proposal = proposal();
    let consumer_proposal = AirtableMissionConsumer::new()
        .compile_output(scope, schema, work_product_allowlist(), work_product())
        .expect("consumer proposal");
    assert_eq!(
        AirtableMissionConsumer::consumer_id(),
        "mission.external.record.airtable"
    );
    assert_eq!(consumer_proposal, service_proposal);
}

#[test]
fn schema_drift_and_manifest_drift_fail_closed() {
    let scope = scope();
    let mut drifted_schema = schema(&scope);
    drifted_schema.revision = "schema-rev-2".to_owned();
    let schema_error = AirtableOpsService::new()
        .compile_record_proposal(request(
            &scope,
            &drifted_schema,
            work_product_allowlist(),
            work_product(),
        ))
        .expect_err("stale schema fingerprint must fail closed");
    assert!(matches!(schema_error, AirtableError::SchemaDrift { .. }));

    let valid_schema = schema(&scope);
    let mut provider = FakeAirtableProvider::new(scope.clone(), valid_schema).expect("provider");
    provider.manifest_mut().contract_digest = "stale-digest".to_owned();
    let secret = SecretReference::from_environment("HARTEVO_AIRTABLE_PAT").expect("secret ref");
    let manifest_error = AirtableOpsService::new()
        .describe_schema(&mut provider, &scope, &secret)
        .expect_err("manifest drift must fail closed");
    assert!(matches!(
        manifest_error,
        AirtableError::ContractDrift { .. }
    ));
}

#[test]
fn field_allowlist_rejects_schema_name_and_type_drift() {
    let scope = scope();
    let schema = schema(&scope);
    let mut bindings = work_product_allowlist()
        .bindings
        .into_values()
        .collect::<Vec<_>>();
    let title = bindings
        .iter_mut()
        .find(|binding| binding.stable_field == StableRecordField::Title)
        .expect("title binding");
    title.field_name = "Renamed by an attacker".to_owned();
    let name_error = AirtableOpsService::new()
        .compile_record_proposal(request(
            &scope,
            &schema,
            AirtableFieldAllowlist::new(bindings).expect("allowlist"),
            work_product(),
        ))
        .expect_err("name drift must fail closed");
    assert!(matches!(name_error, AirtableError::FieldAllowlist { .. }));

    let mut bindings = work_product_allowlist()
        .bindings
        .into_values()
        .collect::<Vec<_>>();
    let revision = bindings
        .iter_mut()
        .find(|binding| binding.stable_field == StableRecordField::Revision)
        .expect("revision binding");
    revision.field_type = AirtableFieldType::SingleLineText;
    let type_error = AirtableOpsService::new()
        .compile_record_proposal(request(
            &scope,
            &schema,
            AirtableFieldAllowlist::new(bindings).expect("allowlist"),
            work_product(),
        ))
        .expect_err("type drift must fail closed");
    assert!(matches!(type_error, AirtableError::FieldAllowlist { .. }));
}

#[test]
fn pagination_uses_offsets_and_rejects_repeated_or_overfull_pages() {
    let scope = scope();
    let table_schema = schema(&scope);
    let mut provider = FakeAirtableProvider::new(scope.clone(), table_schema).expect("provider");
    let first_offset = AirtableOffset::new("offset-1").expect("offset");
    provider
        .set_page(
            None,
            AirtableRecordPage::new(
                vec![snapshot(&scope, "rec-1", "fields-1", "digest-1")],
                Some(first_offset.clone()),
            )
            .expect("first page"),
        )
        .expect("set first page");
    provider
        .set_page(
            Some(first_offset.clone()),
            AirtableRecordPage::new(
                vec![snapshot(&scope, "rec-2", "fields-1", "digest-2")],
                None,
            )
            .expect("second page"),
        )
        .expect("set second page");
    let secret = SecretReference::bearer_pat("pat-reference-only").expect("secret ref");
    let result = AirtableOpsService::new()
        .read_records(&mut provider, &scope, &secret, 1, None)
        .expect("paginated read");
    assert_eq!(result.records.len(), 2);
    assert_eq!(result.pagination.pages, 2);
    assert_eq!(result.pagination.offsets, vec!["offset-1"]);
    assert_eq!(provider.requests().len(), 2);
    assert!(provider.requests()[0].secret_reference_digest != "pat-reference-only");

    let mut repeated = FakeAirtableProvider::new(scope.clone(), schema(&scope)).expect("provider");
    repeated
        .set_page(
            None,
            AirtableRecordPage::new(vec![], Some(first_offset.clone())).expect("page"),
        )
        .expect("set page");
    repeated
        .set_page(
            Some(first_offset.clone()),
            AirtableRecordPage::new(vec![], Some(first_offset)).expect("page"),
        )
        .expect("set page");
    let repeated_error = AirtableOpsService::new()
        .read_records(&mut repeated, &scope, &secret, 10, None)
        .expect_err("repeated offset must fail closed");
    assert!(matches!(repeated_error, AirtableError::Pagination { .. }));

    let mut overfull = FakeAirtableProvider::new(scope.clone(), schema(&scope)).expect("provider");
    overfull
        .set_page(
            None,
            AirtableRecordPage::new(
                vec![
                    snapshot(&scope, "rec-1", "fields-1", "digest-1"),
                    snapshot(&scope, "rec-2", "fields-1", "digest-2"),
                ],
                None,
            )
            .expect("page"),
        )
        .expect("set page");
    let overfull_error = AirtableOpsService::new()
        .read_records(&mut overfull, &scope, &secret, 1, None)
        .expect_err("page larger than request must fail closed");
    assert!(matches!(overfull_error, AirtableError::Pagination { .. }));
}

#[test]
fn batches_never_cross_airtable_ten_record_boundary() {
    let proposal = proposal();
    let batches = AirtableOpsService::new().batch_proposals(vec![proposal; 21]);
    assert_eq!(batches.len(), 3);
    assert_eq!(batches[0].proposals().len(), AIRTABLE_MAX_BATCH_SIZE);
    assert_eq!(batches[1].proposals().len(), AIRTABLE_MAX_BATCH_SIZE);
    assert_eq!(batches[2].proposals().len(), 1);
    assert!(AirtableRecordPage::new(Vec::new(), None).is_ok());
}

#[test]
fn rate_limit_and_retry_classification_preserve_only_safe_metadata() {
    let rate_limited = AirtableProviderError::from_http(429, "rate limited", None);
    assert_eq!(
        rate_limited.retry_classification(),
        hartevo_airtable_ops_plugin::RetryClassification::RetryAfter
    );
    assert_eq!(
        rate_limited.retry_after_seconds(),
        Some(AirtableProviderError::DEFAULT_RATE_LIMIT_RETRY_AFTER_SECONDS)
    );
    assert_eq!(
        AirtableProviderError::from_http(503, "temporary", None).retry_classification(),
        hartevo_airtable_ops_plugin::RetryClassification::RetryWithBackoff
    );
    assert_eq!(
        AirtableProviderError::from_http(401, "do not log token", None).retry_classification(),
        hartevo_airtable_ops_plugin::RetryClassification::DoNotRetry
    );

    let scope = scope();
    let mut provider = FakeAirtableProvider::new(scope.clone(), schema(&scope)).expect("provider");
    provider.push_error(rate_limited);
    let secret = SecretReference::from_environment("HARTEVO_AIRTABLE_PAT").expect("secret ref");
    let error = AirtableOpsService::new()
        .read_records(&mut provider, &scope, &secret, 10, None)
        .expect_err("fixture rate limit");
    assert_eq!(
        error.retry_classification(),
        hartevo_airtable_ops_plugin::RetryClassification::RetryAfter
    );
    assert!(!error.to_string().contains("do not log token"));
}

#[test]
fn record_receipt_and_readback_verify_all_stable_identity_fields() {
    let scope = scope();
    let schema = schema(&scope);
    let service = AirtableOpsService::new();
    let proposal = service
        .compile_record_proposal(request(
            &scope,
            &schema,
            work_product_allowlist(),
            work_product(),
        ))
        .expect("proposal");
    let mut provider = FakeAirtableProvider::new(scope.clone(), schema).expect("provider");
    let receipt = service
        .recording_receipt(
            &provider,
            &proposal,
            AirtableRecordId::new("rec-verified").expect("record ID"),
        )
        .expect("receipt");
    assert!(!receipt.write_executed);
    assert_eq!(receipt.scope, scope);
    assert_eq!(receipt.field_fingerprint, proposal.field_fingerprint);
    assert_eq!(receipt.content_digest, proposal.content_fingerprint);
    assert!(
        !serde_json::to_string(&receipt)
            .expect("receipt JSON")
            .contains("Sensitive source content")
    );

    provider
        .set_readback(RecordReadback::from_receipt(&receipt))
        .expect("readback");
    let verified = service
        .readback_and_verify(
            &mut provider,
            &proposal,
            &receipt,
            &SecretReference::from_environment("HARTEVO_AIRTABLE_PAT").expect("secret ref"),
        )
        .expect("verified readback");
    assert!(verified.verified);
    assert_eq!(verified.record_id, receipt.record_id);

    let mut bad_content = RecordReadback::from_receipt(&receipt);
    bad_content.content_digest = "different-content-digest".to_owned();
    let error = service
        .verify_record_readback(&proposal, &receipt, &bad_content)
        .expect_err("content mismatch");
    assert!(matches!(
        error,
        AirtableError::ReadbackMismatch(ref mismatch)
            if mismatch.field == ReadbackMismatchField::ContentDigest
    ));

    let mut bad_record_id = RecordReadback::from_receipt(&receipt);
    bad_record_id.record_id = AirtableRecordId::new("rec-other").expect("record ID");
    let error = service
        .verify_record_readback(&proposal, &receipt, &bad_record_id)
        .expect_err("record ID mismatch");
    assert!(matches!(
        error,
        AirtableError::ReadbackMismatch(ref mismatch)
            if mismatch.field == ReadbackMismatchField::RecordId
    ));

    let mut bad_field_fingerprint = RecordReadback::from_receipt(&receipt);
    bad_field_fingerprint.field_fingerprint = "different-field-fingerprint".to_owned();
    let error = service
        .verify_record_readback(&proposal, &receipt, &bad_field_fingerprint)
        .expect_err("field fingerprint mismatch");
    assert!(matches!(
        error,
        AirtableError::ReadbackMismatch(ref mismatch)
            if mismatch.field == ReadbackMismatchField::FieldFingerprint
    ));
}

#[test]
fn secrets_are_boundary_only_and_native_journey_is_blocked_env() {
    let secret = SecretReference::bearer_pat("pat_super_secret_value").expect("secret ref");
    assert!(!format!("{secret:?}").contains("pat_super_secret_value"));
    let serialized = serde_json::to_string(&secret).expect("secret reference JSON");
    assert!(serialized.contains("pat_super_secret_value"));

    let scope = scope();
    let mut provider = BlockedEnvAirtableProvider::new(scope.clone());
    assert_eq!(
        provider.manifest().provenance,
        AirtableProviderProvenance::BlockedEnv
    );
    assert!(!provider.manifest().provenance.is_connected());
    let error = AirtableOpsService::new()
        .describe_schema(&mut provider, &scope, &secret)
        .expect_err("native credential environment is blocked");
    assert!(error.is_blocked_env());
    assert_eq!(
        hartevo_airtable_ops_plugin::native_provider_from_environment()
            .expect_err("native provider blocked")
            .to_string(),
        "Airtable native environment is blocked: missing HARTEVO_AIRTABLE_PAT"
    );
}

#[test]
fn webhook_signal_is_not_truth_and_recording_is_not_connected() {
    let signal = hartevo_airtable_ops_plugin::AirtableChangeSignal {
        scope: scope(),
        record_id: Some(AirtableRecordId::new("rec-signal").expect("record ID")),
        changed_at: "2026-08-14T00:00:00Z".to_owned(),
        delivery_id: "delivery-1".to_owned(),
    };
    assert!(!signal.is_truth());
    assert!(signal.requires_readback());
    let proposal = proposal();
    assert_eq!(proposal.provenance, AirtableProviderProvenance::Recording);
    assert!(!proposal.provenance.is_connected());
}

#[test]
fn list_request_rejects_page_size_above_airtable_limit() {
    let error = ListRecordsRequest::new(101).expect_err("Airtable max page size");
    assert!(matches!(error, AirtableError::InvalidInput { .. }));
    let value = RecordValue::Integer(3);
    assert!(AirtableFieldType::Number.accepts(&value));
    assert!(!AirtableFieldType::Checkbox.accepts(&value));
}

#[test]
fn receipts_do_not_claim_native_write_even_when_fixture_is_used() {
    let scope = scope();
    let mut provider =
        FakeAirtableProvider::fixture(scope.clone(), schema(&scope)).expect("provider");
    let service = AirtableOpsService::new();
    let proposal = proposal();
    let receipt = service
        .recording_receipt(
            &provider,
            &proposal,
            AirtableRecordId::new("rec-fixture").expect("record ID"),
        )
        .expect("fixture receipt");
    assert_eq!(
        receipt.kind,
        hartevo_airtable_ops_plugin::ReceiptKind::Fixture
    );
    assert_eq!(receipt.provenance, AirtableProviderProvenance::Fixture);
    assert!(!receipt.write_executed);
    provider
        .set_readback(RecordReadback::from_receipt(&receipt))
        .expect("readback");
    assert!(
        service
            .readback_and_verify(
                &mut provider,
                &proposal,
                &receipt,
                &SecretReference::from_environment("HARTEVO_AIRTABLE_PAT").expect("secret ref"),
            )
            .expect("fixture readback")
            .verified
    );
}

#[test]
fn proposal_request_rejects_schema_scope_mismatch() {
    let scope = scope();
    let other_scope = AirtableScope::new(
        AirtableBaseId::new("app-other").expect("base ID"),
        AirtableTableId::new("tbl-other").expect("table ID"),
        None,
    );
    let error = MissionRecordProposalRequest::new(
        scope,
        schema(&other_scope),
        work_product_allowlist(),
        work_product(),
    )
    .expect_err("scope mismatch");
    assert!(matches!(error, AirtableError::ScopeMismatch { .. }));
}

#[test]
fn record_receipt_constructor_rejects_native_provenance() {
    let proposal = proposal();
    let error = RecordReceipt::from_proposal(
        &proposal,
        AirtableRecordId::new("rec-native").expect("record ID"),
        AirtableProviderProvenance::NativeHttps,
        hartevo_airtable_ops_plugin::ReceiptKind::Fixture,
    )
    .expect_err("Layer 1 cannot emit native receipt");
    assert!(matches!(error, AirtableError::ContractDrift { .. }));
}
