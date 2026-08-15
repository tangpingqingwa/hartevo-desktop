use std::collections::BTreeMap;

use hartevo_bamboohr_directory_result_plugin::*;
use serde_json::Value;

const RAW_COMPANY_DOMAIN: &str = "acme-people";
const RAW_SECRET_HANDLE: &str = "secret_ref_bamboohr_701";
const RAW_EMPLOYEE_ID: &str = "123";
const RAW_DISPLAY_NAME: &str = "Alice Example";
const RAW_EMAIL: &str = "alice@example.test";
const RAW_WORK_PRODUCT: &str = "work-product_bamboohr_directory";

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("positive revision")
}

fn scope() -> BambooHrDirectoryScope {
    BambooHrDirectoryScope::read_only_with_work_product(
        CompanyDomain::new(RAW_COMPANY_DOMAIN).expect("company domain"),
        true,
        Project::new("project_bamboohr_701", revision(2)).expect("project"),
        Mission::new("mission_bamboohr_701", revision(3)).expect("mission"),
        WorkProduct::new(RAW_WORK_PRODUCT, revision(5)).expect("work product"),
        Consent::new("consent_bamboohr_directory", revision(4)).expect("consent"),
    )
    .expect("scope")
}

fn snapshot() -> BambooHrDirectorySnapshot {
    let fields = vec![
        DirectoryFieldProjection::from_provider_fields("displayName", "text", "Display Name")
            .expect("display field"),
        DirectoryFieldProjection::from_provider_fields("workEmail", "text", "Work Email")
            .expect("email field"),
        DirectoryFieldProjection::from_provider_fields("department", "text", "Department")
            .expect("department field"),
    ];
    let employee = DirectoryEmployeeProjection::from_provider_fields(
        RAW_EMPLOYEE_ID,
        vec![
            ("displayName".to_owned(), RAW_DISPLAY_NAME.to_owned()),
            ("workEmail".to_owned(), RAW_EMAIL.to_owned()),
            ("jobTitleName".to_owned(), "Engineer".to_owned()),
            ("department".to_owned(), "People".to_owned()),
            ("supervisor".to_owned(), "manager-7".to_owned()),
            ("status".to_owned(), "active".to_owned()),
        ],
    )
    .expect("employee");
    BambooHrDirectorySnapshot::new(fields, vec![employee]).expect("snapshot")
}

fn response(
    scope: &BambooHrDirectoryScope,
    provenance: TransportProvenance,
) -> BambooHrDirectoryResponse {
    let request = BambooHrDirectoryRequest::new(scope).expect("request");
    BambooHrDirectoryResponse::new(
        &request,
        snapshot(),
        1_024,
        ProviderRevision::new(BAMBOOHR_DIRECTORY_API_REVISION).expect("provider revision"),
        provenance,
    )
    .expect("response")
}

fn fixture_service() -> BambooHrDirectoryResultService {
    let current_scope = scope();
    let provider =
        BambooHrProvider::fixture(response(&current_scope, TransportProvenance::Fixture));
    let secret = SecretReference::oauth(RAW_SECRET_HANDLE, &current_scope, 1)
        .expect("opaque secret reference");
    BambooHrDirectoryResultService::register(
        provider,
        "registration_bamboohr_701",
        current_scope,
        secret,
    )
    .expect("service")
}

#[test]
fn contract_registration_and_debug_are_digest_bound_and_redacted() {
    let document: Value = serde_json::from_str(BAMBOOHR_DIRECTORY_CONTRACT_JSON).expect("contract");
    assert_eq!(
        document["schemaVersion"],
        BAMBOOHR_DIRECTORY_RESULT_SCHEMA_VERSION
    );
    assert_eq!(
        document["contractVersion"],
        BAMBOOHR_DIRECTORY_RESULT_CONTRACT_VERSION
    );
    assert_eq!(document["pluginId"], BAMBOOHR_DIRECTORY_RESULT_PLUGIN_ID);
    assert_eq!(document["contractDigest"], contract_digest().as_str());
    assert_eq!(
        document["provider"]["type"],
        BAMBOOHR_DIRECTORY_PROVIDER_IMPLEMENTATION
    );
    assert_eq!(
        document["consumer"]["type"],
        BAMBOOHR_DIRECTORY_CONSUMER_IMPLEMENTATION
    );

    let service = fixture_service();
    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    let registration_debug = format!("{:?}", service.registration());
    for raw in [RAW_SECRET_HANDLE, RAW_COMPANY_DOMAIN] {
        assert!(
            !registration_json.contains(raw),
            "registration leaked {raw}"
        );
        assert!(
            !registration_debug.contains(raw),
            "registration debug leaked {raw}"
        );
    }
    assert!(registration_json.contains("secretReferenceDigest"));
    assert!(service.registration().validate(service.provider()).is_ok());
    assert!(service.registration().scope.validate().is_ok());
    assert_eq!(service.describe_capabilities().operations.len(), 11);
    assert_eq!(
        service.describe_capabilities().service_id,
        BAMBOOHR_DIRECTORY_SERVICE_ID
    );
    assert!(!service.is_connected());
    assert!(!service.is_native());
    assert!(!service.is_first_party());
}

#[test]
fn fixture_directory_is_bounded_digest_only_and_recordable() {
    let mut service = fixture_service();
    let evidence = service
        .read_directory_evidence(ReadBounds::default())
        .expect("directory evidence");
    assert_eq!(evidence.status, EvidenceStatus::Ready);
    assert_eq!(evidence.fields.len(), 3);
    assert_eq!(evidence.employees.len(), 1);
    assert!(evidence.employees[0].role_digest.is_some());
    assert!(evidence.employees[0].department_digest.is_some());
    assert!(evidence.employees[0].supervisor_digest.is_some());
    assert_eq!(evidence.employees[0].status, EmployeeStatus::Active);
    assert!(evidence.employees[0].redacted_field_count >= 2);
    assert_eq!(evidence.response_bytes, 1_024);
    assert_eq!(evidence.request_receipts.len(), 1);
    assert_eq!(evidence.cost_receipts.len(), 1);
    assert!(evidence.request_receipts[0].redacted);
    assert!(evidence.cost_receipts[0].redacted);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);
    assert!(!evidence.provider_receipt);
    assert!(!evidence.raw_employee_ids_retained);
    assert!(!evidence.raw_field_values_retained);
    assert!(!evidence.raw_response_retained);
    assert!(evidence.verify_integrity());

    let evidence_json = serde_json::to_string(&evidence).expect("evidence JSON");
    for raw in [
        RAW_COMPANY_DOMAIN,
        RAW_SECRET_HANDLE,
        RAW_EMPLOYEE_ID,
        RAW_DISPLAY_NAME,
        RAW_EMAIL,
    ] {
        assert!(!evidence_json.contains(raw), "evidence leaked {raw}");
    }

    let proposal = service
        .compile_evidence_proposal(evidence.clone())
        .expect("proposal");
    assert!(proposal.verify_integrity());
    assert!(proposal.review_only);
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    service.verify_proposal(&proposal).expect("proposal fence");

    let record = service.record_proposal(&proposal).expect("record");
    assert!(record.verify_integrity());
    let read_back = service.read_back_record(&record).expect("read back");
    assert!(read_back.verified);
    assert!(!read_back.independent_provider_reread);
    assert!(!read_back.connected && !read_back.native && !read_back.first_party);
    assert_eq!(
        service.record_proposal(&proposal),
        Err(BambooHrDirectoryResultError::StaleRecord)
    );
}

#[test]
fn employee_metadata_list_is_cursor_bounded_change_fenced_and_redacted() {
    let current_scope = scope();
    let bounds = BambooHrEmployeeListBounds::default();
    let provider_revision =
        ProviderRevision::new(BAMBOOHR_DIRECTORY_API_REVISION).expect("provider revision");
    let first_request =
        BambooHrEmployeeListRequest::new(&current_scope, &bounds).expect("first request");
    let cursor = PageCursor::after(
        "opaque-bamboohr-cursor-1",
        &current_scope,
        &current_scope.employee_fields,
        1,
        bounds.now_epoch_seconds,
        bounds.cursor_ttl_seconds,
    )
    .expect("opaque cursor");
    let second_request =
        BambooHrEmployeeListRequest::with_cursor(&current_scope, &bounds, cursor.clone())
            .expect("second request");
    let first_employee = DirectoryEmployeeProjection::from_provider_metadata(
        "123",
        vec![
            ("jobTitleName".to_owned(), "Engineer".to_owned()),
            ("department".to_owned(), "People".to_owned()),
            ("status".to_owned(), "active".to_owned()),
            ("workEmail".to_owned(), RAW_EMAIL.to_owned()),
        ],
        EmployeeStatus::Active,
        provider_revision.clone(),
    )
    .expect("first employee");
    let second_employee = DirectoryEmployeeProjection::from_provider_metadata(
        "124",
        vec![
            ("jobTitleName".to_owned(), "Former Engineer".to_owned()),
            ("department".to_owned(), "People".to_owned()),
            ("status".to_owned(), "inactive".to_owned()),
        ],
        EmployeeStatus::Unknown,
        provider_revision.clone(),
    )
    .expect("second employee");
    let change_fence = Digest::from_text("bamboohr-directory-change-fence-1");
    let first_page = BambooHrEmployeeListPage::new(
        &first_request,
        vec![first_employee],
        2,
        Some(cursor.clone()),
        None,
        512,
        provider_revision.clone(),
        change_fence.clone(),
        TransportProvenance::Fixture,
        false,
    )
    .expect("first page");
    let second_page = BambooHrEmployeeListPage::new(
        &second_request,
        vec![second_employee],
        2,
        None,
        Some(cursor),
        512,
        provider_revision,
        change_fence,
        TransportProvenance::Fixture,
        true,
    )
    .expect("second page");
    let page_json = serde_json::to_string(&first_page).expect("page JSON");
    assert!(!page_json.contains("opaque-bamboohr-cursor-1"));

    let fixture = BambooHrDirectoryFixture::with_employee_pages(
        Vec::<std::result::Result<BambooHrDirectoryResponse, ProviderError>>::new(),
        [Ok(first_page), Ok(second_page)],
    );
    let secret =
        SecretReference::oauth("secret_ref_employee_list", &current_scope, 1).expect("secret");
    let service = BambooHrDirectoryResultService::register(
        BambooHrProvider::fixture(fixture),
        "registration_bamboohr_employee_list",
        current_scope,
        secret,
    )
    .expect("service");
    let evidence = service
        .read_employee_metadata(bounds)
        .expect("employee metadata evidence");
    assert_eq!(evidence.status, EvidenceStatus::Inactive);
    assert_eq!(evidence.total, 2);
    assert_eq!(evidence.employees.len(), 2);
    assert_eq!(evidence.page_count, 2);
    assert_eq!(evidence.cursor_digests.len(), 1);
    assert_eq!(evidence.request_receipts.len(), 2);
    assert!(
        evidence
            .request_receipts
            .iter()
            .all(|receipt| receipt.redacted)
    );
    assert_eq!(evidence.response_bytes, 1_024);
    assert!(evidence.verify_integrity());
    let evidence_json = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!evidence_json.contains("opaque-bamboohr-cursor-1"));
    assert!(!evidence_json.contains(RAW_EMAIL));
    let proposal = service
        .compile_employee_metadata_proposal(evidence)
        .expect("metadata proposal");
    assert!(proposal.verify_integrity());
    assert!(!proposal.can_be_adopted());
    service
        .verify_employee_metadata_proposal(&proposal)
        .expect("metadata proposal fence");
}

#[test]
fn employee_metadata_stale_cursor_and_tampered_page_fail_closed() {
    let current_scope = scope();
    let stale_cursor = PageCursor::after(
        "opaque-stale-cursor",
        &current_scope,
        &current_scope.employee_fields,
        1,
        1,
        1,
    )
    .expect("stale cursor fixture");
    let stale_bounds = BambooHrEmployeeListBounds::default().with_initial_cursor(stale_cursor);
    let stale_service = BambooHrDirectoryResultService::register(
        BambooHrProvider::fixture(BambooHrDirectoryFixture::employee_pages(Vec::<
            std::result::Result<BambooHrEmployeeListPage, ProviderError>,
        >::new())),
        "registration_bamboohr_stale_cursor",
        current_scope.clone(),
        SecretReference::oauth("secret_ref_stale_cursor", &current_scope, 1).expect("secret"),
    )
    .expect("service");
    assert_eq!(
        stale_service.read_employee_metadata(stale_bounds),
        Err(BambooHrDirectoryResultError::Model(
            ModelError::InvalidResponse
        ))
    );

    let bounds = BambooHrEmployeeListBounds::default();
    let request = BambooHrEmployeeListRequest::new(&current_scope, &bounds).expect("request");
    let employee = DirectoryEmployeeProjection::from_provider_metadata(
        "125",
        [("department".to_owned(), "People".to_owned())],
        EmployeeStatus::Active,
        ProviderRevision::new(BAMBOOHR_DIRECTORY_API_REVISION).expect("revision"),
    )
    .expect("employee");
    let page = BambooHrEmployeeListPage::new(
        &request,
        vec![employee],
        1,
        None,
        None,
        256,
        ProviderRevision::new(BAMBOOHR_DIRECTORY_API_REVISION).expect("revision"),
        Digest::from_text("bamboohr-directory-change-fence-tamper"),
        TransportProvenance::Fixture,
        true,
    )
    .expect("page");
    let mut tampered_page = page;
    tampered_page.response_bytes += 1;
    let tampered_service = BambooHrDirectoryResultService::register(
        BambooHrProvider::fixture(BambooHrDirectoryFixture::employee_pages([Ok(
            tampered_page,
        )])),
        "registration_bamboohr_tampered_page",
        current_scope.clone(),
        SecretReference::oauth("secret_ref_tampered_page", &current_scope, 1).expect("secret"),
    )
    .expect("service");
    assert_eq!(
        tampered_service.read_employee_metadata(bounds),
        Err(BambooHrDirectoryResultError::Provider(
            ProviderError::TamperedResponse
        ))
    );
}

#[test]
fn mission_consumer_is_exactly_scoped_and_never_adopts_kernel_authority() {
    let service = fixture_service();
    let current_scope = service.scope().clone();
    let context = MissionBambooHrDirectoryContext::new_with_work_product(
        current_scope.project.clone(),
        current_scope.mission.clone(),
        current_scope.work_product.clone(),
        current_scope.consent.clone(),
    );
    let consumer = MissionBambooHrDirectoryConsumer::new(service);
    let evidence = consumer
        .inspect(&context, ReadBounds::default())
        .expect("mission evidence");
    let adoption = consumer
        .consume(&context, evidence)
        .expect("review proposal");
    assert!(adoption.review_only);
    assert!(!adoption.adopted);
    assert!(!adoption.can_be_adopted());
    assert!(!adoption.mutates_identity);
    assert!(!adoption.creates_access_grant);
    assert!(!adoption.kernel_truth_authority);
    assert!(!adoption.kernel_consent_authority);
    assert!(!adoption.effect_authority);
    assert!(!adoption.receipt_authority);
    assert!(!adoption.verification_authority);
    assert!(!adoption.outcome_authority);
    assert!(!adoption.connected && !adoption.native && !adoption.first_party);

    let stale_context = MissionBambooHrDirectoryContext::new_with_work_product(
        context.project,
        Mission::new("mission_bamboohr_701", revision(99)).expect("stale mission"),
        context.work_product,
        context.consent,
    );
    assert_eq!(
        consumer.inspect(&stale_context, ReadBounds::default()),
        Err(BambooHrDirectoryResultError::ScopeMismatch)
    );
}

#[test]
fn partial_and_tampered_responses_fail_closed_before_proposal() {
    let current_scope = scope();
    let request = BambooHrDirectoryRequest::new(&current_scope).expect("request");
    let partial = BambooHrDirectoryResponse::partial(
        &request,
        snapshot(),
        1_024,
        ProviderRevision::new(BAMBOOHR_DIRECTORY_API_REVISION).expect("revision"),
        TransportProvenance::Fixture,
    )
    .expect("partial response");
    let partial_service = BambooHrDirectoryResultService::register(
        BambooHrProvider::fixture(partial),
        "registration_bamboohr_partial",
        current_scope.clone(),
        SecretReference::basic("secret_ref_partial", &current_scope, 1).expect("secret"),
    )
    .expect("service");
    assert!(matches!(
        partial_service.read_directory_evidence(ReadBounds::default()),
        Err(BambooHrDirectoryResultError::Provider(
            ProviderError::Partial { .. }
        ))
    ));

    let mut tampered = response(&current_scope, TransportProvenance::Fixture);
    tampered.response_bytes += 1;
    let tampered_service = BambooHrDirectoryResultService::register(
        BambooHrProvider::fixture(tampered),
        "registration_bamboohr_tampered",
        current_scope.clone(),
        SecretReference::oauth("secret_ref_tampered", &current_scope, 1).expect("secret"),
    )
    .expect("service");
    assert_eq!(
        tampered_service.read_directory_evidence(ReadBounds::default()),
        Err(BambooHrDirectoryResultError::Provider(
            ProviderError::TamperedResponse,
        ))
    );
}

#[test]
fn scope_drift_rate_limit_bounds_and_secret_revocation_are_typed() {
    let current_scope = scope();
    let other_scope = BambooHrDirectoryScope::read_only_with_work_product(
        CompanyDomain::new("other-company").expect("domain"),
        false,
        current_scope.project.clone(),
        current_scope.mission.clone(),
        current_scope.work_product.clone(),
        current_scope.consent.clone(),
    )
    .expect("other scope");
    let mismatch_service = BambooHrDirectoryResultService::register(
        BambooHrProvider::fixture(response(&other_scope, TransportProvenance::Fixture)),
        "registration_bamboohr_scope_mismatch",
        current_scope.clone(),
        SecretReference::oauth("secret_ref_scope_mismatch", &current_scope, 1).expect("secret"),
    )
    .expect("service");
    assert!(matches!(
        mismatch_service.read_directory_evidence(ReadBounds::default()),
        Err(BambooHrDirectoryResultError::Provider(
            ProviderError::TamperedResponse
        ))
    ));

    let rate_service = BambooHrDirectoryResultService::register(
        BambooHrProvider::fixture(BambooHrDirectoryFixture::error(
            ProviderError::rate_limited(Some(9)),
        )),
        "registration_bamboohr_rate",
        current_scope.clone(),
        SecretReference::oauth("secret_ref_rate", &current_scope, 1).expect("secret"),
    )
    .expect("service");
    match rate_service.read_directory_evidence(ReadBounds::default()) {
        Err(BambooHrDirectoryResultError::Provider(error)) => {
            assert_eq!(error.status_code(), Some(429));
            assert_eq!(error.retry_after_seconds(), Some(9));
            assert!(error.is_retryable());
            assert_eq!(error.class(), ProviderFailureClass::RateLimited);
        }
        other => panic!("unexpected rate-limit result: {other:?}"),
    }

    let bounded_service = BambooHrDirectoryResultService::register(
        BambooHrProvider::fixture(response(&current_scope, TransportProvenance::Fixture)),
        "registration_bamboohr_bounds",
        current_scope.clone(),
        SecretReference::oauth("secret_ref_bounds", &current_scope, 1).expect("secret"),
    )
    .expect("service");
    assert_eq!(
        bounded_service.read_directory_evidence(ReadBounds {
            max_records: 1,
            max_fields: 1,
            max_response_bytes: 1_024,
        }),
        Err(BambooHrDirectoryResultError::PartialResponse)
    );

    let mut revoked_service = fixture_service();
    revoked_service
        .revoke_secret_reference()
        .expect("revoke secret");
    assert_eq!(
        revoked_service.read_directory_evidence(ReadBounds::default()),
        Err(BambooHrDirectoryResultError::SecretReferenceRevoked)
    );
    revoked_service
        .restore_secret_reference()
        .expect("restore secret");
    revoked_service.reverse_registration().expect("reverse");
    assert_eq!(
        revoked_service.read_directory(),
        Err(BambooHrDirectoryResultError::RegistrationInactive)
    );
    revoked_service.restore_registration().expect("restore");
    assert!(revoked_service.read_directory().is_ok());
    revoked_service
        .revoke_registration()
        .expect("revoke registration");
    assert_eq!(
        revoked_service.read_directory(),
        Err(BambooHrDirectoryResultError::RegistrationRevoked)
    );
}

#[test]
fn all_test_transports_are_explicitly_non_native_and_blocked_env_is_fail_closed() {
    let current_scope = scope();
    let recording =
        BambooHrProvider::recording(response(&current_scope, TransportProvenance::Recording));
    let loopback =
        BambooHrProvider::loopback(response(&current_scope, TransportProvenance::Loopback));
    for provider in [&recording, &loopback] {
        assert_eq!(provider.provenance(), provider.definition().provenance);
        assert!(!provider.is_connected());
        assert!(!provider.is_native());
        assert!(!provider.is_first_party());
        assert!(!provider.definition().connected);
        assert!(!provider.definition().native);
        assert!(!provider.definition().first_party);
    }

    let blocked = BambooHrProvider::blocked_env();
    assert_eq!(blocked.provenance(), TransportProvenance::BlockedEnv);
    assert!(!blocked.is_connected());
    assert!(!blocked.is_native());
    assert!(!blocked.is_first_party());
    let blocked_service = BambooHrDirectoryResultService::register(
        blocked,
        "registration_bamboohr_blocked",
        current_scope.clone(),
        SecretReference::oauth("secret_ref_blocked", &current_scope, 1).expect("secret"),
    )
    .expect("service");
    assert_eq!(
        blocked_service.read_directory(),
        Err(BambooHrDirectoryResultError::Provider(
            ProviderError::BlockedEnv
        ))
    );
}

#[test]
fn opaque_employee_projection_hashes_dynamic_fields_deterministically() {
    let first = DirectoryEmployeeProjection::from_provider_fields(
        RAW_EMPLOYEE_ID,
        vec![
            ("workEmail".to_owned(), RAW_EMAIL.to_owned()),
            ("displayName".to_owned(), RAW_DISPLAY_NAME.to_owned()),
        ],
    )
    .expect("first projection");
    let second = DirectoryEmployeeProjection::from_provider_fields(
        RAW_EMPLOYEE_ID,
        vec![
            ("displayName".to_owned(), RAW_DISPLAY_NAME.to_owned()),
            ("workEmail".to_owned(), RAW_EMAIL.to_owned()),
        ],
    )
    .expect("second projection");
    assert_eq!(first, second);
    assert!(first.verify_integrity());
    let json = serde_json::to_string(&first).expect("projection JSON");
    assert!(!json.contains(RAW_EMPLOYEE_ID));
    assert!(!json.contains(RAW_DISPLAY_NAME));
    assert!(!json.contains(RAW_EMAIL));

    let mut nullable = BTreeMap::new();
    nullable.insert("workPhone".to_owned(), None);
    nullable.insert("workEmail".to_owned(), Some(RAW_EMAIL.to_owned()));
    let nullable_projection =
        DirectoryEmployeeProjection::from_provider_values("124", nullable).expect("nullable");
    assert!(nullable_projection.verify_integrity());
}
