use std::collections::BTreeMap;

use hartevo_sap_sales_order_result_plugin::{
    BlockState, Digest, FixtureSapODataTransport, FulfillmentState, MissionSapSalesOrderConsumer,
    MissionSapSalesOrderConsumerError, OpaqueDocumentId, RecordingSapODataTransport, RevisionFence,
    SapEntitySet, SapODataPage, SapODataRequest, SapODataResponse, SapObservationState,
    SapProviderError, SapProviderErrorKind, SapQueryBounds, SapSalesOrderResultService,
    SapSalesOrderScope, SapTransportError, SapTransportProvenance, SecretReference,
};

fn fields(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn scope() -> SapSalesOrderScope {
    SapSalesOrderScope::new(
        "tenant-a",
        "s4hana-prod",
        "5000001234",
        "project-a",
        4,
        "mission-a",
        9,
        "work-product-a",
        12,
    )
    .expect("scope")
}

fn header_page(
    status: &str,
    delivery_status: &str,
    billing_status: &str,
    delivery_block: &str,
    billing_block: &str,
    etag: &str,
    source_revision: u64,
    next_skip: Option<u32>,
) -> SapODataPage {
    SapODataPage::new(
        SapEntitySet::SalesOrder,
        vec![fields(&[
            ("SalesOrder", "5000001234"),
            ("SalesOrderType", "OR"),
            ("CreationDate", "2026-08-14"),
            ("LastChangeDate", "2026-08-14T10:00:00Z"),
            ("TransactionCurrency", "EUR"),
            ("TotalNetAmount", "1250.50"),
            ("OverallSDProcessStatus", status),
            ("OverallDeliveryStatus", delivery_status),
            ("OverallBillingStatus", billing_status),
            ("DeliveryBlockReason", delivery_block),
            ("BillingBlockReason", billing_block),
            ("CustomerName", "Alice Customer"),
            ("SoldToParty", "PARTNER-PRIVATE"),
            ("LongText", "private customer text"),
        ])],
        next_skip,
        Some(etag),
        source_revision,
    )
    .expect("header page")
}

fn item_page(source_revision: u64) -> SapODataPage {
    SapODataPage::new(
        SapEntitySet::SalesOrderItem,
        vec![fields(&[
            ("SalesOrder", "5000001234"),
            ("SalesOrderItem", "000010"),
            ("Material", "MAT-100"),
            ("RequestedQuantity", "2"),
            ("RequestedQuantityUnit", "EA"),
            ("NetAmount", "1250.50"),
            ("TransactionCurrency", "EUR"),
            ("DeliveryStatus", "B"),
            ("BillingStatus", "A"),
            ("ETag", "etag-1"),
        ])],
        None,
        Some("etag-1"),
        source_revision,
    )
    .expect("item page")
}

fn flow_page(source_revision: u64) -> SapODataPage {
    SapODataPage::new(
        SapEntitySet::SalesOrderDocumentFlow,
        vec![fields(&[
            ("SalesOrder", "5000001234"),
            ("PrecedingDocument", "4500000001"),
            ("SubsequentDocument", "8000000001"),
            ("DeliveryDocument", "8000000001"),
            ("BillingDocument", "9000000001"),
            ("DocumentCategory", "J"),
            ("DocumentFlowStatus", "in_process"),
            ("CreationDate", "2026-08-14"),
        ])],
        None,
        Some("etag-1"),
        source_revision,
    )
    .expect("flow page")
}

fn fixture_provider()
-> hartevo_sap_sales_order_result_plugin::SapS4HanaProvider<FixtureSapODataTransport> {
    let scope = scope();
    let secret = SecretReference::oauth("opaque-sap-secret-ref", &scope, 3).expect("secret");
    hartevo_sap_sales_order_result_plugin::SapS4HanaProvider::new(
        scope,
        secret,
        FixtureSapODataTransport::new(vec![
            header_page("A", "B", "A", "", "", "etag-1", 7, None),
            item_page(7),
            flow_page(7),
        ]),
    )
    .expect("provider")
}

#[test]
fn happy_path_is_redacted_bounded_and_below_kernel_authority() {
    let mut provider = fixture_provider();
    let service = SapSalesOrderResultService::new();
    let run = service.run(&mut provider).expect("run");

    assert_eq!(run.observation.state, SapObservationState::Available);
    assert_eq!(
        run.observation
            .evidence
            .as_ref()
            .expect("evidence")
            .items
            .len(),
        1
    );
    assert_eq!(
        run.observation
            .evidence
            .as_ref()
            .expect("evidence")
            .fulfillment_state,
        FulfillmentState::InProgress
    );
    assert!(
        run.observation
            .evidence
            .as_ref()
            .expect("evidence")
            .redaction
            .count()
            >= 3
    );
    let rendered = serde_json::to_string(&run).expect("safe JSON");
    assert!(!rendered.contains("Alice Customer"));
    assert!(!rendered.contains("PARTNER-PRIVATE"));
    assert!(!rendered.contains("private customer text"));
    assert!(!rendered.contains("opaque-sap-secret-ref"));
    assert!(!run.adoption_proposal.connected);
    assert!(!run.adoption_proposal.native);
    assert!(!run.adoption_proposal.first_party);
    assert!(!run.adoption_proposal.kernel_outcome_adoption);
    assert!(!run.recording.contains_raw_partner_data);
    assert!(run.recording.redacted_field_count >= 3);

    let mut consumer = MissionSapSalesOrderConsumer::new(scope());
    let result = consumer
        .consume_run(&run, &scope().revision_fence())
        .expect("consumer result");
    assert!(result.verified_for_review);
    assert!(!result.adopted_outcome);
    assert!(!result.truth_authority);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    assert_eq!(result.scope_digest, *scope().scope_digest());
    assert!(consumer.has_consumed(&run.adoption_proposal.proposal_digest));
}

#[test]
fn document_ids_etags_and_secrets_are_opaque() {
    let scope = scope();
    let secret =
        SecretReference::client_certificate("raw-client-cert-ref", &scope, 1).expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("raw-client-cert-ref"));
    assert!(!format!("{secret:?}").contains("PRIVATE"));
    let order_id = OpaqueDocumentId::new("5000001234").expect("opaque id");
    assert_ne!(order_id.as_str(), "5000001234");
    assert_eq!(
        order_id,
        OpaqueDocumentId::new("5000001234").expect("same digest")
    );
}

#[test]
fn allowlist_rejects_mutation_shaped_projections_and_raw_filters() {
    let scope = scope();
    let request = SapODataRequest::for_scope(&scope, SapEntitySet::SalesOrder, 0).expect("request");
    assert!(request.is_read_only());
    assert!(!request.has_external_write());
    assert!(!request.render_query().contains("5000001234"));
    assert!(
        request
            .clone()
            .with_select(vec!["CreatedByUser".to_owned()])
            .is_err()
    );
    assert!(
        request
            .clone()
            .with_select(vec!["SalesOrder".to_owned(), "TotalNetAmount".to_owned()])
            .is_ok()
    );
    assert!(SapQueryBounds::new(101, 1, 1, 1, 1).is_err());
    assert!(SapQueryBounds::new(1, 1, 1, 1, 1).is_ok());
}

#[test]
fn bounded_pagination_returns_partial_without_unbounded_follow_up() {
    let bounded_scope = scope()
        .with_bounds(SapQueryBounds::new(1, 1, 1, 1, 1).expect("bounds"))
        .expect("scoped bounds");
    let secret = SecretReference::api_key("opaque-api-key-ref", &bounded_scope, 1).expect("secret");
    let transport = FixtureSapODataTransport::new(vec![
        header_page("A", "A", "A", "", "", "etag-1", 7, None),
        SapODataPage::new(
            SapEntitySet::SalesOrderItem,
            vec![fields(&[
                ("SalesOrder", "5000001234"),
                ("SalesOrderItem", "000010"),
                ("RequestedQuantity", "1"),
                ("TransactionCurrency", "EUR"),
                ("NetAmount", "10"),
            ])],
            Some(1),
            Some("etag-1"),
            7,
        )
        .expect("partial item page"),
        flow_page(7),
    ]);
    let mut provider = hartevo_sap_sales_order_result_plugin::SapS4HanaProvider::new(
        bounded_scope,
        secret,
        transport,
    )
    .expect("provider");
    let evidence = SapSalesOrderResultService::new()
        .read(&mut provider)
        .expect("partial evidence");
    assert!(evidence.partial);
    assert_eq!(provider.transport().requests().len(), 3);
}

#[test]
fn etag_and_source_revision_drift_fail_closed() {
    let scope = scope();
    let secret = SecretReference::oauth("opaque-ref", &scope, 1).expect("secret");
    let mut transport = RecordingSapODataTransport::new();
    transport.push_page(header_page("A", "A", "A", "", "", "etag-1", 7, Some(1)));
    transport.push_page(header_page("A", "A", "A", "", "", "etag-2", 7, None));
    let mut provider = hartevo_sap_sales_order_result_plugin::SapS4HanaProvider::new(
        scope.clone(),
        secret,
        transport,
    )
    .expect("provider");
    assert!(matches!(
        provider.read_sales_order(),
        Err(SapProviderError::EtagDrift)
    ));

    let secret = SecretReference::oauth("opaque-ref-2", &scope, 1).expect("secret");
    let mut transport = RecordingSapODataTransport::new();
    transport.push_page(header_page("A", "A", "A", "", "", "etag-1", 7, None));
    transport.push_page(item_page(8));
    let mut provider =
        hartevo_sap_sales_order_result_plugin::SapS4HanaProvider::new(scope, secret, transport)
            .expect("provider");
    assert!(matches!(
        provider.read_sales_order(),
        Err(SapProviderError::RevisionDrift)
    ));
}

#[test]
fn http_statuses_and_timeout_are_explicit_non_native_states() {
    for (status, expected_kind, expected_state) in [
        (
            401,
            SapProviderErrorKind::Unauthorized,
            SapObservationState::AccessLost,
        ),
        (
            403,
            SapProviderErrorKind::Forbidden,
            SapObservationState::AccessLost,
        ),
        (
            404,
            SapProviderErrorKind::NotFound,
            SapObservationState::Deleted,
        ),
        (
            409,
            SapProviderErrorKind::Conflict,
            SapObservationState::RevisionConflict,
        ),
        (
            429,
            SapProviderErrorKind::RateLimited,
            SapObservationState::ProviderUnknown,
        ),
        (
            503,
            SapProviderErrorKind::ServerFailure,
            SapObservationState::ProviderUnknown,
        ),
    ] {
        let current_scope = scope();
        let secret = SecretReference::oauth("opaque-ref", &current_scope, 1).expect("secret");
        let request = SapODataRequest::for_scope(&current_scope, SapEntitySet::SalesOrder, 0)
            .expect("request");
        let mut transport = RecordingSapODataTransport::new();
        transport.push_response(SapODataResponse::http_error(&request, status, Some(3)));
        let mut provider = hartevo_sap_sales_order_result_plugin::SapS4HanaProvider::new(
            current_scope,
            secret,
            transport,
        )
        .expect("provider");
        let observation = provider.read_observation();
        assert_eq!(observation.state, expected_state);
        assert_eq!(
            observation.error.as_ref().expect("error").kind,
            expected_kind
        );
        assert_eq!(
            observation.error.as_ref().expect("error").http_status,
            Some(status)
        );
        assert!(!observation.connected());
        assert!(!observation.native());
        assert!(!observation.first_party());
    }

    let current_scope = scope();
    let secret = SecretReference::oauth("opaque-timeout-ref", &current_scope, 1).expect("secret");
    let mut transport = RecordingSapODataTransport::new();
    transport.push_error(SapTransportError::Timeout);
    let mut provider = hartevo_sap_sales_order_result_plugin::SapS4HanaProvider::new(
        current_scope,
        secret,
        transport,
    )
    .expect("provider");
    let observation = provider.read_observation();
    assert_eq!(observation.state, SapObservationState::ProviderUnknown);
    assert_eq!(
        observation.error.as_ref().expect("error").kind,
        SapProviderErrorKind::Timeout
    );
}

#[test]
fn revocation_revision_fence_and_duplicate_proposals_are_reversible_and_fail_closed() {
    let current_scope = scope();
    let secret = SecretReference::oauth("opaque-revocable-ref", &current_scope, 1).expect("secret");
    let transport = FixtureSapODataTransport::new(vec![
        header_page("A", "A", "A", "", "", "etag-1", 7, None),
        item_page(7),
        flow_page(7),
    ]);
    let mut provider = hartevo_sap_sales_order_result_plugin::SapS4HanaProvider::new(
        current_scope.clone(),
        secret,
        transport,
    )
    .expect("provider");
    assert!(provider.is_registered());
    provider.revoke().expect("revoke");
    assert!(!provider.is_registered());
    assert!(matches!(
        provider.read_sales_order(),
        Err(SapProviderError::RegistrationRevoked)
    ));
    assert!(provider.revoke().is_err());

    let mut provider = fixture_provider();
    let service = SapSalesOrderResultService::new();
    let run = service.run(&mut provider).expect("run");
    let mut consumer = MissionSapSalesOrderConsumer::new(scope());
    let expected = scope().revision_fence();
    consumer
        .consume_run(&run, &expected)
        .expect("first consume");
    assert!(matches!(
        consumer.consume_run(&run, &expected),
        Err(MissionSapSalesOrderConsumerError::DuplicateProposal)
    ));

    let stale_scope = SapSalesOrderScope::new(
        "tenant-a",
        "s4hana-prod",
        "5000001234",
        "project-a",
        4,
        "mission-a",
        10,
        "work-product-a",
        12,
    )
    .expect("stale scope");
    let stale_fence = stale_scope.revision_fence();
    assert!(matches!(
        consumer.consume(&run.adoption_proposal, &run.recording, &stale_fence),
        Err(MissionSapSalesOrderConsumerError::RevisionFenceChanged)
    ));
    let mut new_consumer = MissionSapSalesOrderConsumer::new(scope());
    assert!(matches!(
        new_consumer.consume(&run.adoption_proposal, &run.recording, &stale_fence),
        Err(MissionSapSalesOrderConsumerError::RevisionFenceChanged)
    ));
}

#[test]
fn all_evidence_provenance_modes_are_never_connected_native_or_first_party() {
    assert!(!SapTransportProvenance::Fixture.is_connected());
    assert!(!SapTransportProvenance::Fixture.is_native());
    assert!(!SapTransportProvenance::Fixture.is_first_party());
    assert!(!SapTransportProvenance::Recording.is_connected());
    assert!(!SapTransportProvenance::Loopback.is_native());
    assert!(!SapTransportProvenance::BlockedEnv.is_first_party());

    let current_scope = scope();
    let blocked = hartevo_sap_sales_order_result_plugin::SapS4HanaProvider::blocked(current_scope)
        .expect("blocked provider");
    assert!(!blocked.connected());
    assert!(!blocked.native());
    assert!(!blocked.first_party());
}

#[test]
fn tampered_response_digest_is_rejected() {
    let current_scope = scope();
    let secret = SecretReference::oauth("opaque-tamper-ref", &current_scope, 1).expect("secret");
    let request =
        SapODataRequest::for_scope(&current_scope, SapEntitySet::SalesOrder, 0).expect("request");
    let mut transport = RecordingSapODataTransport::new();
    transport.push_response(SapODataResponse::tampered_request_digest(
        Digest::from_text("tampered"),
        200,
    ));
    let mut provider = hartevo_sap_sales_order_result_plugin::SapS4HanaProvider::new(
        current_scope,
        secret,
        transport,
    )
    .expect("provider");
    assert_eq!(provider.transport().requests().len(), 0);
    assert!(matches!(
        provider.read_sales_order(),
        Err(SapProviderError::InvalidResponse)
    ));
    assert_eq!(request.entity_set, SapEntitySet::SalesOrder);
}

#[test]
fn block_state_is_projected_without_mutation_authority() {
    let current_scope = scope();
    let secret = SecretReference::oauth("opaque-block-ref", &current_scope, 1).expect("secret");
    let transport = FixtureSapODataTransport::new(vec![
        header_page("B", "B", "B", "10", "20", "etag-1", 7, None),
        item_page(7),
        flow_page(7),
    ]);
    let mut provider = hartevo_sap_sales_order_result_plugin::SapS4HanaProvider::new(
        current_scope,
        secret,
        transport,
    )
    .expect("provider");
    let evidence = provider.read_sales_order().expect("evidence");
    assert_eq!(evidence.block_state, BlockState::DeliveryAndBilling);
    assert_eq!(evidence.fulfillment_state, FulfillmentState::Blocked);
    assert!(!evidence.connected());
    assert!(!evidence.native());
}

#[test]
fn revision_fence_exposes_project_mission_and_work_product_bindings() {
    let fence: RevisionFence = scope().revision_fence();
    assert_eq!(fence.project().id(), "project-a");
    assert_eq!(fence.project().revision().get(), 4);
    assert_eq!(fence.mission().id(), "mission-a");
    assert_eq!(fence.mission().revision().get(), 9);
    assert_eq!(fence.work_product().id(), "work-product-a");
    assert_eq!(fence.work_product().revision().get(), 12);
}
