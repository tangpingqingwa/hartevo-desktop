use std::collections::{BTreeMap, BTreeSet};

use hartevo_salesforce_crm_result_plugin::{
    ApprovalFixture, ApprovalStatus, Digest, HistoryFixture, MissionSalesforceCrmConsumer,
    QuerySeam, RecordingSalesforceTransport, SalesforceCrmResultContract, SalesforceCrmResultError,
    SalesforceCrmResultService, SalesforceField, SalesforceHttpRequest, SalesforceHttpResponse,
    SalesforceObject, SalesforceReadRequest, SalesforceRecordFixture, SalesforceResultStatus,
    SalesforceScope, SalesforceScopeInput, SalesforceTransportError, SecretReference,
    TransportProvenance,
};

const RECORD_ID: &str = "006000000000001";
const RECORD_REVISION_TEXT: &str = "2026-08-15T00:00:00.000Z";

fn record_revision() -> Digest {
    Digest::from_text(RECORD_REVISION_TEXT)
}

fn scope() -> SalesforceScope {
    SalesforceScope::new(SalesforceScopeInput {
        organization: "org-504".to_owned(),
        instance: "acme.my.salesforce.com".to_owned(),
        api_version: "v66.0".to_owned(),
        allowlisted_objects: BTreeSet::from([SalesforceObject::Opportunity]),
        allowlisted_fields: BTreeMap::from([(
            SalesforceObject::Opportunity,
            BTreeSet::from([
                SalesforceField::OpportunityId,
                SalesforceField::OpportunityName,
                SalesforceField::OpportunityStage,
                SalesforceField::OpportunityCloseDate,
                SalesforceField::OpportunityAmount,
                SalesforceField::OpportunityProbability,
                SalesforceField::OpportunityForecastCategory,
                SalesforceField::OpportunityIsClosed,
                SalesforceField::OpportunityIsWon,
                SalesforceField::OpportunityAccountId,
            ]),
        )]),
        record_id: RECORD_ID.to_owned(),
        record_revision: record_revision(),
        mission_id: "mission-504".to_owned(),
        mission_revision: 3,
        project_id: "project-504".to_owned(),
        project_revision: 4,
        work_product_id: "work-product-504".to_owned(),
        work_product_revision: 5,
        permission_digest: Digest::from_text("salesforce-read-permission"),
        consent_digest: Digest::from_text("mission-consent"),
    })
    .expect("scope")
}

fn request(seam: QuerySeam, max_pages: u8) -> SalesforceReadRequest {
    SalesforceReadRequest::new(
        SalesforceObject::Opportunity,
        RECORD_ID,
        [
            SalesforceField::OpportunityId,
            SalesforceField::OpportunityName,
            SalesforceField::OpportunityStage,
            SalesforceField::OpportunityCloseDate,
            SalesforceField::OpportunityAmount,
            SalesforceField::OpportunityProbability,
            SalesforceField::OpportunityForecastCategory,
            SalesforceField::OpportunityIsClosed,
            SalesforceField::OpportunityIsWon,
            SalesforceField::OpportunityAccountId,
        ],
        seam,
        true,
        true,
        max_pages,
    )
    .expect("request")
}

fn fixture() -> SalesforceRecordFixture {
    SalesforceRecordFixture::new(SalesforceObject::Opportunity, RECORD_ID, record_revision())
        .expect("fixture")
        .with_field(
            SalesforceField::OpportunityId,
            hartevo_salesforce_crm_result_plugin::SalesforceFixtureValue::Text(
                RECORD_ID.to_owned(),
            ),
        )
        .with_field(
            SalesforceField::OpportunityName,
            hartevo_salesforce_crm_result_plugin::SalesforceFixtureValue::Text(
                "Acme expansion".to_owned(),
            ),
        )
        .with_field(
            SalesforceField::OpportunityStage,
            hartevo_salesforce_crm_result_plugin::SalesforceFixtureValue::Text(
                "Proposal".to_owned(),
            ),
        )
        .with_field(
            SalesforceField::OpportunityCloseDate,
            hartevo_salesforce_crm_result_plugin::SalesforceFixtureValue::Text(
                "2026-12-31".to_owned(),
            ),
        )
        .with_field(
            SalesforceField::OpportunityAmount,
            hartevo_salesforce_crm_result_plugin::SalesforceFixtureValue::Decimal(
                "125000".to_owned(),
            ),
        )
        .with_field(
            SalesforceField::OpportunityProbability,
            hartevo_salesforce_crm_result_plugin::SalesforceFixtureValue::Integer(70),
        )
        .with_field(
            SalesforceField::OpportunityForecastCategory,
            hartevo_salesforce_crm_result_plugin::SalesforceFixtureValue::Text(
                "BestCase".to_owned(),
            ),
        )
        .with_field(
            SalesforceField::OpportunityIsClosed,
            hartevo_salesforce_crm_result_plugin::SalesforceFixtureValue::Boolean(false),
        )
        .with_field(
            SalesforceField::OpportunityIsWon,
            hartevo_salesforce_crm_result_plugin::SalesforceFixtureValue::Boolean(false),
        )
        .with_field(
            SalesforceField::OpportunityAccountId,
            hartevo_salesforce_crm_result_plugin::SalesforceFixtureValue::Text(
                "001000000000001".to_owned(),
            ),
        )
        .with_approval(
            ApprovalFixture::new(ApprovalStatus::Pending)
                .with_process_reference("process-504")
                .with_times(Some(1_787_000_000), None)
                .with_steps(2, Some(ApprovalStatus::Pending)),
        )
        .with_history(
            HistoryFixture::new(2)
                .with_latest_at(Some(1_787_000_100))
                .with_change("StageName", "Qualification", "Proposal"),
        )
}

#[test]
fn contract_registration_and_native_boundary_are_explicit() {
    let contract = SalesforceCrmResultContract::baseline().expect("contract");
    assert_eq!(contract.layer, 1);
    assert!(!contract.authority.connected);
    assert!(!contract.authority.approval_mutation);
    assert!(!contract.native_claims.blocked_environment_is_native);

    let scope = scope();
    let secret = SecretReference::oauth("opaque-salesforce-ref", &scope, 1).expect("secret");
    assert!(!format!("{secret:?}").contains("opaque-salesforce-ref"));
    assert_eq!(
        secret.auth_kind(),
        hartevo_salesforce_crm_result_plugin::AuthKind::OAuth
    );
}

#[test]
fn rest_and_graphql_proposals_are_typed_allowlisted_and_read_only() {
    let scope = scope();
    let rest = SalesforceHttpRequest::new(&scope, &request(QuerySeam::RestSoql, 1)).expect("REST");
    assert!(rest.path.ends_with("/services/data/v66.0/query/"));
    assert!(rest.query_text.starts_with("SELECT "));
    assert!(
        rest.approval_query_text
            .as_deref()
            .is_some_and(|query| query.contains("ProcessInstance"))
    );
    assert!(
        rest.history_query_text
            .as_deref()
            .is_some_and(|query| query.contains("OpportunityHistory"))
    );
    assert!(rest.is_read_only());
    assert!(!rest.path_and_query().contains("%27DELETE"));

    let graphql =
        SalesforceHttpRequest::new(&scope, &request(QuerySeam::GraphQl, 1)).expect("GraphQL");
    assert!(graphql.path.ends_with("/services/data/v66.0/graphql"));
    assert!(graphql.query_text.starts_with("query "));
    assert!(
        graphql
            .approval_query_text
            .as_deref()
            .is_some_and(|query| query.contains("SalesforceApprovalMetadata"))
    );
    assert!(
        graphql
            .history_query_text
            .as_deref()
            .is_some_and(|query| query.contains("SalesforceHistoryMetadata"))
    );
    assert!(!graphql.query_text.to_ascii_lowercase().contains("mutation"));
    assert!(graphql.is_read_only());

    let injected = SalesforceReadRequest::new(
        SalesforceObject::Opportunity,
        "006000000000001' OR Id != 'x",
        [SalesforceField::OpportunityId],
        QuerySeam::RestSoql,
        false,
        false,
        1,
    );
    assert!(injected.is_err());
}

#[test]
fn fixture_recording_and_mission_consumer_redact_payloads_and_bind_revisions() {
    let scope = scope();
    let read_request = request(QuerySeam::RestSoql, 1);
    let http_request = SalesforceHttpRequest::new(&scope, &read_request).expect("HTTP request");
    let page = hartevo_salesforce_crm_result_plugin::SalesforcePage::from_fixture(
        &http_request,
        fixture(),
        None,
        true,
    )
    .expect("page");
    let response = SalesforceHttpResponse::ok(page, "fixture-response-504");
    let mut service = SalesforceCrmResultService::new(
        scope.clone(),
        SecretReference::oauth("oauth-reference-504", &scope, 1).expect("secret"),
        RecordingSalesforceTransport::fixture([Ok(response)]),
    )
    .expect("service");
    let result = service.read(read_request).expect("read");
    assert_eq!(result.evidence.status, SalesforceResultStatus::Complete);
    assert_eq!(result.evidence.records.len(), 1);
    assert!(
        result.evidence.records[0]
            .field(SalesforceField::OpportunityName)
            .is_some_and(|value| matches!(
                value,
                hartevo_salesforce_crm_result_plugin::SalesforceProjectedValue::Digest(_)
            ))
    );
    assert_eq!(
        result.evidence.records[0].approval.status,
        ApprovalStatus::Pending
    );
    assert_eq!(result.evidence.records[0].history.entry_count, 2);
    assert!(!result.evidence.raw_payload_retained);
    assert!(!result.evidence.pii_retained);
    assert!(!result.evidence.native_evidence);
    assert!(!result.verification.independent_readback);

    let consumer = MissionSalesforceCrmConsumer::from_service(&service).expect("consumer");
    let mission_result = consumer.consume(result.clone()).expect("Mission result");
    assert_eq!(
        mission_result.state,
        hartevo_salesforce_crm_result_plugin::MissionSalesforceResultState::PendingDecision
    );
    let serialized = serde_json::to_string(&mission_result).expect("JSON");
    assert!(!serialized.contains("oauth-reference-504"));
    assert!(!serialized.contains("Acme expansion"));
    assert!(!serialized.contains("contact@example.com"));
    assert!(!format!("{mission_result:?}").contains("Acme expansion"));

    let tampered = {
        let mut value = result.evidence.clone();
        value.records[0].record_revision = Digest::from_text("different-revision");
        value
    };
    assert!(service.verify(&result.proposal, &tampered).is_err());
}

#[test]
fn raw_json_is_projected_without_retaining_names_emails_addresses_notes_or_payload() {
    let scope = scope();
    let read_request = SalesforceReadRequest::new(
        SalesforceObject::Opportunity,
        RECORD_ID,
        [
            SalesforceField::OpportunityId,
            SalesforceField::OpportunityName,
            SalesforceField::OpportunityStage,
        ],
        QuerySeam::RestSoql,
        false,
        false,
        1,
    )
    .expect("request");
    let http_request = SalesforceHttpRequest::new(&scope, &read_request).expect("HTTP request");
    let raw = r#"{
        "totalSize": 1,
        "done": true,
        "records": [{
            "Id": "006000000000001",
            "Name": "Alice contact@example.com 18 Main Street",
            "StageName": "Proposal",
            "Email": "contact@example.com",
            "Notes": "do not retain this note",
            "LastModifiedDate": "2026-08-15T00:00:00.000Z"
        }]
    }"#;
    let response = SalesforceHttpResponse::from_json(&http_request, 200, raw).expect("decode");
    let mut service = SalesforceCrmResultService::new(
        scope.clone(),
        SecretReference::oauth("oauth-reference-504", &scope, 1).expect("secret"),
        RecordingSalesforceTransport::recording([Ok(response)]),
    )
    .expect("service");
    let result = service.read(read_request).expect("read");
    let serialized = serde_json::to_string(&result).expect("JSON");
    assert!(!serialized.contains("contact@example.com"));
    assert!(!serialized.contains("18 Main Street"));
    assert!(!serialized.contains("do not retain this note"));
    assert!(serialized.contains("recordDigest"));
}

#[test]
fn pagination_is_bounded_and_next_records_urls_are_digest_only() {
    let scope = scope();
    let read_request = request(QuerySeam::RestSoql, 1);
    let http_request = SalesforceHttpRequest::new(&scope, &read_request).expect("HTTP request");
    let page = hartevo_salesforce_crm_result_plugin::SalesforcePage::from_fixture(
        &http_request,
        fixture(),
        Some("/services/data/v66.0/query/nextRecordsUrl?email=secret@example.com"),
        false,
    )
    .expect("page");
    let mut service = SalesforceCrmResultService::new(
        scope.clone(),
        SecretReference::oauth("oauth-reference-504", &scope, 1).expect("secret"),
        RecordingSalesforceTransport::loopback([Ok(SalesforceHttpResponse::ok(page, "page-one"))]),
    )
    .expect("service");
    let result = service.read(read_request).expect("read");
    assert_eq!(result.evidence.status, SalesforceResultStatus::Partial);
    assert!(result.evidence.pagination.truncated);
    assert_eq!(result.evidence.pagination.pages, 1);
    assert!(
        !serde_json::to_string(&result)
            .expect("JSON")
            .contains("secret@example.com")
    );
    assert_eq!(
        service.provider().provenance(),
        TransportProvenance::Loopback
    );
}

#[test]
fn http_faults_timeout_and_blocked_env_are_typed_without_native_claims() {
    let cases = [
        (400, SalesforceResultStatus::FinalError),
        (401, SalesforceResultStatus::AccessLost),
        (403, SalesforceResultStatus::AccessLost),
        (404, SalesforceResultStatus::NotFound),
        (409, SalesforceResultStatus::FinalError),
        (429, SalesforceResultStatus::ProviderUnknown),
        (500, SalesforceResultStatus::ProviderUnknown),
    ];
    for (status, expected) in cases {
        let scope = scope();
        let request = request(QuerySeam::RestSoql, 1);
        let http_request = SalesforceHttpRequest::new(&scope, &request).expect("HTTP request");
        let mut service = SalesforceCrmResultService::new(
            scope.clone(),
            SecretReference::oauth("oauth-reference-504", &scope, 1).expect("secret"),
            RecordingSalesforceTransport::fake([Ok(SalesforceHttpResponse::status(
                status,
                "diagnostic-payload",
            ))]),
        )
        .expect("service");
        let result = service.read(request).expect("typed status");
        assert_eq!(result.evidence.status, expected);
        assert_eq!(result.evidence.provider_errors[0].status_code, Some(status));
        assert!(!result.evidence.native_evidence);
        assert!(http_request.validate_integrity().is_ok());
    }

    let blocked_scope = scope();
    let mut blocked = SalesforceCrmResultService::new(
        blocked_scope.clone(),
        SecretReference::oauth("oauth-reference-504", &blocked_scope, 1).expect("secret"),
        hartevo_salesforce_crm_result_plugin::BlockedEnvTransport,
    )
    .expect("blocked service");
    let result = blocked
        .read(request(QuerySeam::GraphQl, 1))
        .expect("blocked result");
    assert_eq!(
        result.evidence.status,
        SalesforceResultStatus::ProviderUnknown
    );
    assert!(result.evidence.provider_errors[0].blocked_env);
    assert_eq!(
        blocked.provider().provenance(),
        TransportProvenance::BlockedEnv
    );

    let timeout_scope = scope();
    let request = request(QuerySeam::RestSoql, 1);
    let mut timeout = SalesforceCrmResultService::new(
        timeout_scope.clone(),
        SecretReference::oauth("oauth-reference-504", &timeout_scope, 1).expect("secret"),
        RecordingSalesforceTransport::recording([Err(SalesforceTransportError::timeout(
            "network-timeout",
        ))]),
    )
    .expect("timeout service");
    let result = timeout.read(request).expect("timeout result");
    assert_eq!(
        result.evidence.status,
        SalesforceResultStatus::ProviderUnknown
    );
    assert_eq!(
        result.evidence.provider_errors[0].kind,
        hartevo_salesforce_crm_result_plugin::ProviderErrorKind::Timeout
    );
}

#[test]
fn registration_and_secret_reversal_are_fail_closed_and_reversible() {
    let scope = scope();
    let mut service = SalesforceCrmResultService::new(
        scope.clone(),
        SecretReference::oauth("oauth-reference-504", &scope, 1).expect("secret"),
        RecordingSalesforceTransport::recording([]),
    )
    .expect("service");
    service.revoke_registration().expect("revoke");
    assert!(matches!(
        service.propose(request(QuerySeam::RestSoql, 1)),
        Err(SalesforceCrmResultError::RegistrationRevoked)
    ));
    service.restore_registration().expect("restore");
    service.revoke_secret().expect("secret revoke");
    assert!(matches!(
        service.propose(request(QuerySeam::RestSoql, 1)),
        Err(SalesforceCrmResultError::SecretRevoked)
    ));
    service.restore_secret().expect("secret restore");
    assert!(service.propose(request(QuerySeam::RestSoql, 1)).is_ok());
}
