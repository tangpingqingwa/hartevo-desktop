use hartevo_chargebee_subscription_result_plugin::{
    ChargebeeEvidenceProposalRequest, ChargebeeHttpResponse, ChargebeeObservationState,
    ChargebeePermissionSnapshot, ChargebeeProvider, ChargebeeReadOperation, ChargebeeReadRequest,
    ChargebeeSubscriptionResultError, ChargebeeSubscriptionResultService,
    ChargebeeSubscriptionScope, ChargebeeSubscriptionScopeInput, ChargebeeTransportError,
    CustomerId, EntitlementId, EntitlementObservation, EntitlementStatus,
    FixtureChargebeeTransport, InvoiceId, InvoiceObservation, InvoiceStatus,
    MissionChargebeeSubscriptionConsumer, PlanId, Revision, SecretReference, SiteId,
    SubscriptionId, SubscriptionObservation, SubscriptionStatus, UsageMetadata,
    deterministic_idempotency_key,
};

const OBSERVED_AT_MS: u64 = 1_800_000_000_000;

struct Fixtures {
    scope: ChargebeeSubscriptionScope,
    site_id: SiteId,
    customer_id: CustomerId,
    subscription_id: SubscriptionId,
    plan_id: PlanId,
    invoice_id: InvoiceId,
}

impl Fixtures {
    fn new() -> Self {
        let scope = ChargebeeSubscriptionScope::new(ChargebeeSubscriptionScopeInput {
            site_id: "site-l1".to_owned(),
            customer_id: "cust-private-email@example.invalid".to_owned(),
            subscription_id: "sub-l1".to_owned(),
            plan_id: "plan-l1".to_owned(),
            invoice_id: "inv-l1".to_owned(),
            entitlement_id: "ent-l1".to_owned(),
            site_revision: 1,
            customer_revision: 2,
            subscription_revision: 3,
            plan_revision: 4,
            invoice_revision: 5,
            entitlement_revision: 6,
            project_id: "project-l1".to_owned(),
            project_revision: 7,
            mission_id: "mission-l1".to_owned(),
            mission_revision: 8,
            work_product_id: "work-product-l1".to_owned(),
            work_product_revision: 9,
            consent_id: "consent-l1".to_owned(),
            consent_revision: 10,
            permissions: ChargebeePermissionSnapshot::read_only(),
        })
        .expect("exact scope");
        Self {
            site_id: scope.site_id.clone(),
            customer_id: scope.customer_id.clone(),
            subscription_id: scope.subscription_id.clone(),
            plan_id: scope.plan_id.clone(),
            invoice_id: scope.invoice_id.clone(),
            scope,
        }
    }

    fn subscription(&self) -> SubscriptionObservation {
        SubscriptionObservation {
            id: self.subscription_id.clone(),
            site_id: self.site_id.clone(),
            customer_id: self.customer_id.clone(),
            plan_id: self.plan_id.clone(),
            revision: Revision::new(3, "subscription revision").unwrap(),
            status: SubscriptionStatus::Active,
            quantity: 3,
            current_term_start: Some("2026-08-01T00:00:00Z".to_owned()),
            current_term_end: Some("2026-09-01T00:00:00Z".to_owned()),
            cancel_at_end: false,
            usage: Some(
                UsageMetadata::new(
                    "api_calls",
                    12,
                    Some("2026-08-01".to_owned()),
                    Some("2026-09-01".to_owned()),
                )
                .unwrap(),
            ),
        }
    }

    fn entitlement(&self, id: &str) -> EntitlementObservation {
        EntitlementObservation {
            id: EntitlementId::new(id).unwrap(),
            site_id: self.site_id.clone(),
            customer_id: self.customer_id.clone(),
            subscription_id: self.subscription_id.clone(),
            plan_id: self.plan_id.clone(),
            revision: Revision::new(6, "entitlement revision").unwrap(),
            status: EntitlementStatus::Active,
            feature_digest: hartevo_chargebee_subscription_result_plugin::Digest::from_text(
                format!("feature-{id}"),
            ),
        }
    }

    fn invoice(&self) -> InvoiceObservation {
        InvoiceObservation {
            id: self.invoice_id.clone(),
            site_id: self.site_id.clone(),
            customer_id: self.customer_id.clone(),
            subscription_id: self.subscription_id.clone(),
            revision: Revision::new(5, "invoice revision").unwrap(),
            status: InvoiceStatus::Paid,
            due_at: Some("2026-08-10".to_owned()),
            paid_at: Some("2026-08-10".to_owned()),
        }
    }

    fn service(&self) -> ChargebeeSubscriptionResultService<FixtureChargebeeTransport> {
        let provider = ChargebeeProvider::new(FixtureChargebeeTransport::fixture()).unwrap();
        let secret =
            SecretReference::for_scope("chargebee-api-key-do-not-retain", &self.scope, 1).unwrap();
        ChargebeeSubscriptionResultService::new(self.scope.clone(), secret, provider).unwrap()
    }

    fn queue_body(
        &self,
        service: &mut ChargebeeSubscriptionResultService<FixtureChargebeeTransport>,
        operation: ChargebeeReadOperation,
        limit: u16,
        body: hartevo_chargebee_subscription_result_plugin::ChargebeeResponseBody,
        has_more: bool,
        observed_at_ms: u64,
    ) {
        let request = ChargebeeReadRequest::new(
            &self.scope,
            &service.registration().registration_digest,
            operation,
            limit,
            None,
            observed_at_ms,
        )
        .unwrap();
        let response = ChargebeeHttpResponse::from_body(
            &request.http_request(),
            body,
            service.provider().provider_revision().clone(),
            has_more,
        )
        .unwrap();
        service.provider_mut().transport_mut().queue_ok(response);
    }

    fn queue_complete_proposal(
        &self,
        service: &mut ChargebeeSubscriptionResultService<FixtureChargebeeTransport>,
        observed_at_ms: u64,
    ) {
        self.queue_body(
            service,
            ChargebeeReadOperation::Subscription,
            1,
            hartevo_chargebee_subscription_result_plugin::ChargebeeResponseBody::Subscription(
                self.subscription(),
            ),
            false,
            observed_at_ms,
        );
        self.queue_body(
            service,
            ChargebeeReadOperation::Entitlements,
            50,
            hartevo_chargebee_subscription_result_plugin::ChargebeeResponseBody::Entitlements(
                vec![self.entitlement("ent-l1")],
            ),
            false,
            observed_at_ms,
        );
        self.queue_body(
            service,
            ChargebeeReadOperation::Invoices,
            50,
            hartevo_chargebee_subscription_result_plugin::ChargebeeResponseBody::Invoices(vec![
                self.invoice(),
            ]),
            false,
            observed_at_ms,
        );
        self.queue_body(
            service,
            ChargebeeReadOperation::Usage,
            1,
            hartevo_chargebee_subscription_result_plugin::ChargebeeResponseBody::Usage(
                UsageMetadata::new(
                    "api_calls",
                    12,
                    Some("2026-08-01".to_owned()),
                    Some("2026-09-01".to_owned()),
                )
                .unwrap(),
            ),
            false,
            observed_at_ms,
        );
    }
}

#[test]
fn exact_scope_registration_and_contract_are_digest_bound() {
    let fixtures = Fixtures::new();
    assert!(hartevo_chargebee_subscription_result_plugin::contract_bounds_tripwire());
    assert_eq!(
        fixtures.scope.scope_digest(),
        &fixtures.scope.recomputed_digest()
    );
    assert_eq!(
        fixtures.scope.permission_digest(),
        &fixtures.scope.permissions.digest
    );

    let service = fixtures.service();
    assert!(service.registration().is_active());
    assert_eq!(
        service.registration().registration_digest,
        service.registration().recomputed_digest()
    );
    assert!(!service.native_connected());
    assert!(!service.provider().definition().connected);
    assert!(!service.provider().definition().native);
    assert!(!service.provider().definition().first_party);
}

#[test]
fn customer_and_secret_reference_are_redacted() {
    let fixtures = Fixtures::new();
    let service = fixtures.service();
    let secret_debug = format!("{:?}", service.secret_reference());
    assert!(!secret_debug.contains("chargebee-api-key-do-not-retain"));
    let scope_json = serde_json::to_string(service.scope()).unwrap();
    assert!(!scope_json.contains("cust-private-email@example.invalid"));
    assert!(scope_json.contains("opaque"));
    let customer_json = serde_json::to_string(&fixtures.customer_id).unwrap();
    assert!(!customer_json.contains("cust-private-email@example.invalid"));
    assert!(
        serde_json::to_string(&service.provider().definition())
            .unwrap()
            .contains("payment_instrument_access")
    );
}

#[test]
fn complete_proposal_is_bounded_and_consumable_without_authority() {
    let fixtures = Fixtures::new();
    let mut service = fixtures.service();
    fixtures.queue_complete_proposal(&mut service, OBSERVED_AT_MS);
    let proposal = service
        .propose(ChargebeeEvidenceProposalRequest::new(OBSERVED_AT_MS))
        .unwrap();
    assert_eq!(proposal.overall_state, ChargebeeObservationState::Complete);
    assert_eq!(proposal.evidence.entitlements.len(), 1);
    assert_eq!(proposal.evidence.invoices.len(), 1);
    assert_eq!(
        proposal.evidence.scope.scope_digest,
        *fixtures.scope.scope_digest()
    );
    assert!(proposal.evidence.redaction.is_safe());
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert!(!proposal.first_party);
    assert!(!proposal.subscription_mutation);
    assert!(!proposal.plan_mutation);
    assert!(!proposal.entitlement_mutation);
    assert!(!proposal.invoice_mutation);
    assert!(!proposal.refund);
    assert!(!proposal.payment_instruments);
    assert!(!proposal.raw_customer_pii);
    assert!(!proposal.financial_advice);

    let consumer =
        MissionChargebeeSubscriptionConsumer::new(fixtures.scope.clone(), service.registration())
            .unwrap();
    let result = consumer.consume(&proposal).unwrap();
    assert!(result.accepted);
    assert!(!result.adopted_outcome);
    assert!(!result.truth_authority);
    assert!(!result.consent_authority);
    assert!(!result.effect_authority);
    assert!(!result.financial_advice);
}

#[test]
fn recording_is_idempotent_and_registration_is_reversible() {
    let fixtures = Fixtures::new();
    let mut service = fixtures.service();
    fixtures.queue_complete_proposal(&mut service, OBSERVED_AT_MS);
    let proposal = service
        .propose(ChargebeeEvidenceProposalRequest::new(OBSERVED_AT_MS))
        .unwrap();
    let first = service.record(&proposal).unwrap();
    let second = service.record(&proposal).unwrap();
    assert_eq!(first, second);
    assert!(!first.provider_mutated);
    assert!(!first.credential_material_retained);
    assert!(!first.durable_provider_receipt);

    service.revoke_registration().unwrap();
    assert!(matches!(
        service.read_subscription(OBSERVED_AT_MS + 1),
        Err(ChargebeeSubscriptionResultError::RegistrationRevoked)
    ));
}

#[test]
fn pagination_cursor_is_bound_and_duplicate_pages_fail_closed() {
    let fixtures = Fixtures::new();
    let mut service = fixtures.service();
    let first_request = ChargebeeReadRequest::new(
        &fixtures.scope,
        &service.registration().registration_digest,
        ChargebeeReadOperation::Entitlements,
        1,
        None,
        OBSERVED_AT_MS,
    )
    .unwrap();
    let first_response = ChargebeeHttpResponse::from_body(
        &first_request.http_request(),
        hartevo_chargebee_subscription_result_plugin::ChargebeeResponseBody::Entitlements(vec![
            fixtures.entitlement("ent-l1"),
        ]),
        service.provider().provider_revision().clone(),
        true,
    )
    .unwrap();
    service
        .provider_mut()
        .transport_mut()
        .queue_ok(first_response);
    let first = service.read_entitlements(1, None, OBSERVED_AT_MS).unwrap();
    let cursor = first.next_cursor.clone().unwrap();
    assert_eq!(cursor.scope_digest, *fixtures.scope.scope_digest());
    assert_eq!(cursor.query_digest, first.request_receipt.query_digest);

    let mut tampered = cursor.clone();
    tampered.offset = tampered.offset.saturating_add(1);
    assert!(
        ChargebeeReadRequest::new(
            &fixtures.scope,
            &service.registration().registration_digest,
            ChargebeeReadOperation::Entitlements,
            1,
            Some(tampered),
            OBSERVED_AT_MS + 1,
        )
        .is_err()
    );

    let second_request = ChargebeeReadRequest::new(
        &fixtures.scope,
        &service.registration().registration_digest,
        ChargebeeReadOperation::Entitlements,
        1,
        Some(cursor.clone()),
        OBSERVED_AT_MS + 1,
    )
    .unwrap();
    let second_response = ChargebeeHttpResponse::from_body(
        &second_request.http_request(),
        hartevo_chargebee_subscription_result_plugin::ChargebeeResponseBody::Entitlements(vec![
            fixtures.entitlement("ent-l1"),
        ]),
        service.provider().provider_revision().clone(),
        false,
    )
    .unwrap();
    service
        .provider_mut()
        .transport_mut()
        .queue_ok(second_response);
    assert!(matches!(
        service.read_entitlements(1, Some(cursor), OBSERVED_AT_MS + 1),
        Err(ChargebeeSubscriptionResultError::PaginationDrift
            | ChargebeeSubscriptionResultError::DuplicateIdentifier,)
    ));
}

#[test]
fn typed_availability_states_project_without_claiming_success() {
    let fixtures = Fixtures::new();
    for (error, expected) in [
        (
            ChargebeeTransportError::Denied,
            ChargebeeObservationState::Denied,
        ),
        (
            ChargebeeTransportError::Absent,
            ChargebeeObservationState::Absent,
        ),
        (
            ChargebeeTransportError::Expired,
            ChargebeeObservationState::Expired,
        ),
        (
            ChargebeeTransportError::AccessLost { status: 401 },
            ChargebeeObservationState::AccessLost,
        ),
        (
            ChargebeeTransportError::ProviderUnknown,
            ChargebeeObservationState::ProviderUnknown,
        ),
        (
            ChargebeeTransportError::RateLimited {
                retry_after_seconds: 17,
            },
            ChargebeeObservationState::RateLimited,
        ),
    ] {
        let mut service = fixtures.service();
        service.provider_mut().transport_mut().queue_error(error);
        service
            .provider_mut()
            .transport_mut()
            .queue_error(ChargebeeTransportError::Denied);
        service
            .provider_mut()
            .transport_mut()
            .queue_error(ChargebeeTransportError::Denied);
        service
            .provider_mut()
            .transport_mut()
            .queue_error(ChargebeeTransportError::Denied);
        let proposal = service
            .propose(ChargebeeEvidenceProposalRequest::new(OBSERVED_AT_MS))
            .unwrap();
        assert_eq!(proposal.evidence.operation_statuses[0].state, expected);
        assert!(!proposal.connected);
        assert!(!proposal.native);
        assert!(!proposal.financial_advice);
    }
}

#[test]
fn rate_limit_exposes_bounded_backoff_and_never_retries_mutation() {
    let fixtures = Fixtures::new();
    let mut service = fixtures.service();
    for limit in 1..=5 {
        fixtures.queue_body(
            &mut service,
            ChargebeeReadOperation::Entitlements,
            limit,
            hartevo_chargebee_subscription_result_plugin::ChargebeeResponseBody::Entitlements(
                Vec::new(),
            ),
            false,
            OBSERVED_AT_MS,
        );
        let result = service.read_entitlements(limit, None, OBSERVED_AT_MS);
        assert!(result.is_ok());
    }
    let error = service.read_usage(OBSERVED_AT_MS).unwrap_err();
    assert_eq!(
        error,
        ChargebeeSubscriptionResultError::RateLimited {
            retry_after_seconds: 60
        }
    );
    assert!(!service.provider().definition().external_writes);
}

#[test]
fn proposal_and_readback_verification_fail_closed_on_tamper() {
    let fixtures = Fixtures::new();
    let mut service = fixtures.service();
    fixtures.queue_complete_proposal(&mut service, OBSERVED_AT_MS);
    let proposal = service
        .propose(ChargebeeEvidenceProposalRequest::new(OBSERVED_AT_MS))
        .unwrap();
    let mut tampered = proposal.clone();
    tampered.financial_advice = true;
    assert!(matches!(
        service.verify(&tampered),
        Err(ChargebeeSubscriptionResultError::ProposalTampered)
    ));

    let first = proposal.evidence.clone();
    let mut read_back = first.clone();
    read_back.invoices[0].status = InvoiceStatus::NotPaid;
    assert!(service.verify_read_back(&first, &read_back).is_err());

    let consumer =
        MissionChargebeeSubscriptionConsumer::new(fixtures.scope.clone(), service.registration())
            .unwrap();
    assert!(consumer.consume(&tampered).is_err());
}

#[test]
fn json_parser_discards_raw_payload_and_keeps_only_allowlisted_fields() {
    let fixtures = Fixtures::new();
    let mut service = fixtures.service();
    let request = ChargebeeReadRequest::new(
        &fixtures.scope,
        &service.registration().registration_digest,
        ChargebeeReadOperation::Subscription,
        1,
        None,
        OBSERVED_AT_MS,
    )
    .unwrap();
    let raw = br#"{
      "id":"sub-l1",
      "site_id":"site-l1",
      "customer_id":"cust-private-email@example.invalid",
      "plan_id":"plan-l1",
      "revision":3,
      "status":"active",
      "quantity":2,
      "payment_method":{"card_number":"4111111111111111"},
      "customer":{"email":"private@example.invalid","name":"Private"},
      "usage":{"metric":"api_calls","quantity":9}
    }"#;
    let response = hartevo_chargebee_subscription_result_plugin::response_from_json(
        &request,
        200,
        raw,
        service.provider().provider_revision().clone(),
        false,
        None,
    )
    .unwrap();
    assert!(
        !serde_json::to_string(&response)
            .unwrap()
            .contains("4111111111111111")
    );
    assert!(
        !serde_json::to_string(&response)
            .unwrap()
            .contains("private@example.invalid")
    );
    service.provider_mut().transport_mut().queue_ok(response);
    let read = service.read_subscription(OBSERVED_AT_MS).unwrap();
    assert_eq!(read.state, ChargebeeObservationState::Complete);
}

#[test]
fn deterministic_idempotency_key_is_cursor_and_registration_bound() {
    let fixtures = Fixtures::new();
    let service = fixtures.service();
    let request = ChargebeeReadRequest::new(
        &fixtures.scope,
        &service.registration().registration_digest,
        ChargebeeReadOperation::Invoices,
        10,
        None,
        OBSERVED_AT_MS,
    )
    .unwrap();
    let expected = deterministic_idempotency_key(
        fixtures.scope.scope_digest(),
        &service.registration().registration_digest,
        &request.query.query_digest,
        &hartevo_chargebee_subscription_result_plugin::Digest::zero(),
    );
    assert_eq!(request.idempotency_key, expected);
    assert_ne!(
        request.idempotency_key,
        deterministic_idempotency_key(
            fixtures.scope.scope_digest(),
            &service.registration().registration_digest,
            &request.query.query_digest,
            &hartevo_chargebee_subscription_result_plugin::Digest::from_text("foreign-cursor"),
        )
    );
}

#[test]
fn registration_drift_and_secret_revoke_fail_closed() {
    let fixtures = Fixtures::new();
    let mut service = fixtures.service();
    service.provider_mut().definition_mut().connected = true;
    assert!(matches!(
        service.read_subscription(OBSERVED_AT_MS),
        Err(ChargebeeSubscriptionResultError::Provider(_)
            | ChargebeeSubscriptionResultError::RegistrationDrift(_),)
    ));

    let mut service = fixtures.service();
    service.revoke_secret().unwrap();
    assert!(matches!(
        service.read_subscription(OBSERVED_AT_MS),
        Err(ChargebeeSubscriptionResultError::SecretRevoked)
    ));
}
