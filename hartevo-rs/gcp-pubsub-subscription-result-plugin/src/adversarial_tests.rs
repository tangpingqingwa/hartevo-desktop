use super::*;

#[derive(Clone)]
struct Fixture {
    scope: GcpPubsubSubscriptionScope,
    secret: SecretReference,
    topic: TopicConfiguration,
    subscription: SubscriptionConfiguration,
}

fn digest(label: &str) -> Digest {
    Digest::from_text(label)
}

fn fixture() -> Fixture {
    let project = ProjectId::new("project-1").expect("project");
    let topic = TopicResource::new(project.clone(), TopicId::new("topic-1").expect("topic"));
    let subscription = SubscriptionResource::new(
        project.clone(),
        SubscriptionId::new("subscription-1").expect("subscription"),
    );
    let schema_resource =
        SchemaResource::new(project.clone(), SchemaId::new("schema-1").expect("schema"));
    let dead_letter_topic = TopicResource::new(
        project.clone(),
        TopicId::new("dead-letter-1").expect("dead letter topic"),
    );
    let scope = GcpPubsubSubscriptionScope::new(
        project.clone(),
        topic.clone(),
        subscription.clone(),
        Some(schema_resource.clone()),
        Some(dead_letter_topic.clone()),
        MissionId::new("mission-1").expect("mission"),
        WorkProductId::new("work-product-1").expect("work product"),
        Revision::new(7).expect("revision"),
        digest("permission-revision-1"),
        digest("consent-revision-1"),
    )
    .expect("scope");
    let secret =
        SecretReference::new("gcp-secret-ref", &scope, 3, GoogleAuthKind::OAuth).expect("secret");
    let schema = SchemaSettings::new(
        schema_resource,
        SchemaEncoding::Json,
        Some("revision-1"),
        Some("revision-3"),
    )
    .expect("schema settings");
    let topic_configuration = TopicConfiguration::new(
        topic.clone(),
        Some(schema),
        Some(86_400),
        TopicState::Active,
    )
    .expect("topic configuration");
    let filter = FilterExpression::new("attributes.environment = \"prod\"").expect("filter");
    let push = PushConfiguration::new(
        Some("https://hooks.example.test/pubsub/opaque"),
        Some("publisher@example.iam.gserviceaccount.com"),
        Some("https://consumer.example.test"),
        PushWrapper::Pubsub,
    )
    .expect("push configuration");
    let dead_letter = DeadLetterPolicy::new(dead_letter_topic, 10).expect("dead letter");
    let retry = RetryPolicy::new(10, 600).expect("retry");
    let expiration = ExpirationPolicy::new(Some(31 * 24 * 60 * 60), false).expect("expiration");
    let subscription_configuration = SubscriptionConfiguration::new(
        subscription,
        topic,
        SubscriptionState::Active,
        false,
        30,
        false,
        Some(86_400),
        Some(600),
        expiration,
        Some(filter),
        Some(dead_letter),
        Some(retry),
        Some(push),
        true,
        true,
    )
    .expect("subscription configuration");
    Fixture {
        scope,
        secret,
        topic: topic_configuration,
        subscription: subscription_configuration,
    }
}

fn queued_service(
    fixture: &Fixture,
    provenance: ProviderProvenance,
    topic_response: Result<TopicConfigurationResponse, TransportError>,
    subscription_response: Result<SubscriptionConfigurationResponse, TransportError>,
    list_response: Result<ListSubscriptionsResponse, TransportError>,
) -> GcpPubsubSubscriptionResultService<GcpPubsubProvider<RecordingGcpPubsubTransport>> {
    let list_request = ListSubscriptionsRequest::new(&fixture.scope, &fixture.secret, 50, None)
        .expect("list request");
    let mut transport = RecordingGcpPubsubTransport::new(provenance);
    transport.push_topic_response(topic_response);
    transport.push_subscription_response(subscription_response);
    transport.push_list_response(list_response);
    let provider = GcpPubsubProvider::new(transport, "1.0.0", provenance).expect("provider");
    let _ = list_request;
    GcpPubsubSubscriptionResultService::new(fixture.scope.clone(), fixture.secret.clone(), provider)
        .expect("service")
}

fn complete_responses(
    fixture: &Fixture,
) -> (
    TopicConfigurationResponse,
    SubscriptionConfigurationResponse,
    ListSubscriptionsResponse,
) {
    let fence = fixture.scope.fence();
    let topic_response = TopicConfigurationResponse::new(
        fixture.topic.clone(),
        fence.clone(),
        fixture.secret.credential_revision(),
    );
    let subscription_response = SubscriptionConfigurationResponse::new(
        fixture.subscription.clone(),
        fence.clone(),
        fixture.secret.credential_revision(),
    );
    let list_request = ListSubscriptionsRequest::new(&fixture.scope, &fixture.secret, 50, None)
        .expect("list request");
    let list_response = ListSubscriptionsResponse::new(
        [fixture.scope.subscription().clone()],
        None,
        1,
        fence,
        fixture.secret.credential_revision(),
        list_request.list_digest(),
    )
    .expect("list response");
    (topic_response, subscription_response, list_response)
}

#[test]
fn complete_recording_is_bounded_and_offline() {
    let fixture = fixture();
    let (topic, subscription, list) = complete_responses(&fixture);
    let mut service = queued_service(
        &fixture,
        ProviderProvenance::Recording,
        Ok(topic),
        Ok(subscription),
        Ok(list),
    );
    let proposal = service.inspect().expect("proposal");
    assert_eq!(proposal.status(), SubscriptionPosture::Active);
    assert_eq!(proposal.evidence.provenance, ProviderProvenance::Recording);
    assert!(!proposal.evidence.authority.connected);
    assert!(!proposal.evidence.authority.native_provider);
    assert!(!proposal.evidence.authority.first_party);
    assert!(!proposal.evidence.authority.truth_authority);
    assert!(!proposal.evidence.configuration_is_delivery_completion);
    assert_eq!(proposal.evidence.page_token_digests.len(), 0);
    assert!(proposal.evidence.topic.is_some());
    assert!(proposal.evidence.subscription.is_some());

    let serialized = serde_json::to_string(&proposal).expect("bounded JSON");
    for forbidden in [
        "projects/project-1/topics/topic-1",
        "projects/project-1/subscriptions/subscription-1",
        "hooks.example.test/pubsub/opaque",
        "publisher@example.iam.gserviceaccount.com",
        "attributes.environment",
        "message_body",
        "ack_ids",
        "orderingKey",
    ] {
        assert!(!serialized.contains(forbidden), "leaked {forbidden}");
    }
    assert!(!format!("{:?}", fixture.secret).contains("gcp-secret-ref"));
    assert_eq!(service.provider().transport().requests().len(), 3);
}

#[test]
fn fixture_loopback_and_blocked_environment_never_claim_native_authority() {
    for provenance in [
        ProviderProvenance::Fixture,
        ProviderProvenance::Recording,
        ProviderProvenance::Loopback,
        ProviderProvenance::BlockedEnv,
    ] {
        let definition = GcpPubsubProviderDefinition::new("1.0.0", provenance).expect("definition");
        assert!(!definition.native);
        assert!(!definition.first_party);
        assert!(!definition.live_execution);
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
    let fixture = fixture();
    let provider =
        GcpPubsubProvider::new(BlockedEnvTransport, "1.0.0", ProviderProvenance::BlockedEnv)
            .expect("blocked provider");
    let mut service = GcpPubsubSubscriptionResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
    )
    .expect("blocked service");
    let result = service.inspect().expect("blocked result");
    assert_eq!(result.status(), SubscriptionPosture::ProviderUnknown);
    assert!(!result.evidence.authority.connected);
    assert!(!result.evidence.authority.native_provider);
    assert!(!result.evidence.authority.first_party);
}

#[test]
fn posture_states_fail_closed_for_detached_expired_misconfigured_and_partial() {
    let base = fixture();
    let (topic, _, list) = complete_responses(&base);
    let detached = SubscriptionConfiguration::new(
        base.subscription.name().clone(),
        base.subscription.topic().clone(),
        SubscriptionState::Active,
        true,
        30,
        false,
        Some(86_400),
        Some(600),
        ExpirationPolicy::new(Some(31 * 24 * 60 * 60), false).expect("expiration"),
        None::<FilterExpression>,
        Some(
            DeadLetterPolicy::new(
                TopicResource::new(
                    base.scope.project().clone(),
                    TopicId::new("dead-letter-1").expect("dead letter"),
                ),
                10,
            )
            .expect("dead letter"),
        ),
        Some(RetryPolicy::new(10, 600).expect("retry")),
        None::<PushConfiguration>,
        true,
        true,
    )
    .expect("detached");
    let detached_response = SubscriptionConfigurationResponse::new(
        detached,
        base.scope.fence(),
        base.secret.credential_revision(),
    );
    let mut service = queued_service(
        &base,
        ProviderProvenance::Fixture,
        Ok(topic.clone()),
        Ok(detached_response),
        Ok(list.clone()),
    );
    assert_eq!(
        service.inspect().expect("detached").status(),
        SubscriptionPosture::Detached
    );

    let expired = SubscriptionConfiguration::new(
        base.subscription.name().clone(),
        base.subscription.topic().clone(),
        SubscriptionState::Active,
        false,
        30,
        false,
        Some(86_400),
        Some(600),
        ExpirationPolicy::new(Some(31 * 24 * 60 * 60), true).expect("expiration"),
        None::<FilterExpression>,
        Some(
            DeadLetterPolicy::new(
                TopicResource::new(
                    base.scope.project().clone(),
                    TopicId::new("dead-letter-1").expect("dead letter"),
                ),
                10,
            )
            .expect("dead letter"),
        ),
        Some(RetryPolicy::new(10, 600).expect("retry")),
        None::<PushConfiguration>,
        true,
        true,
    )
    .expect("expired");
    let mut service = queued_service(
        &base,
        ProviderProvenance::Recording,
        Ok(topic.clone()),
        Ok(SubscriptionConfigurationResponse::new(
            expired,
            base.scope.fence(),
            base.secret.credential_revision(),
        )),
        Ok(list.clone()),
    );
    assert_eq!(
        service.inspect().expect("expired").status(),
        SubscriptionPosture::Expired
    );

    let misconfigured = SubscriptionConfiguration::new(
        base.subscription.name().clone(),
        base.subscription.topic().clone(),
        SubscriptionState::ResourceError,
        false,
        30,
        false,
        Some(86_400),
        Some(600),
        ExpirationPolicy::new(Some(31 * 24 * 60 * 60), false).expect("expiration"),
        None::<FilterExpression>,
        Some(
            DeadLetterPolicy::new(
                TopicResource::new(
                    base.scope.project().clone(),
                    TopicId::new("dead-letter-1").expect("dead letter"),
                ),
                10,
            )
            .expect("dead letter"),
        ),
        Some(RetryPolicy::new(10, 600).expect("retry")),
        None::<PushConfiguration>,
        true,
        true,
    )
    .expect("misconfigured");
    let mut service = queued_service(
        &base,
        ProviderProvenance::Recording,
        Ok(topic.clone()),
        Ok(SubscriptionConfigurationResponse::new(
            misconfigured,
            base.scope.fence(),
            base.secret.credential_revision(),
        )),
        Ok(list.clone()),
    );
    assert_eq!(
        service.inspect().expect("misconfigured").status(),
        SubscriptionPosture::Misconfigured
    );

    let list_request =
        ListSubscriptionsRequest::new(&base.scope, &base.secret, 50, None).expect("list request");
    let empty_list = ListSubscriptionsResponse::new(
        [],
        None,
        1,
        base.scope.fence(),
        base.secret.credential_revision(),
        list_request.list_digest(),
    )
    .expect("empty list");
    let mut service = queued_service(
        &base,
        ProviderProvenance::Recording,
        Ok(topic),
        Ok(SubscriptionConfigurationResponse::new(
            base.subscription.clone(),
            base.scope.fence(),
            base.secret.credential_revision(),
        )),
        Ok(empty_list),
    );
    assert_eq!(
        service.inspect().expect("partial").status(),
        SubscriptionPosture::Partial
    );
}

#[test]
fn access_loss_http_failure_and_tamper_are_distinct() {
    let fixture = fixture();
    let (_, subscription, list) = complete_responses(&fixture);
    let mut access_service = queued_service(
        &fixture,
        ProviderProvenance::Recording,
        Err(TransportError::permission_denied()),
        Ok(subscription.clone()),
        Ok(list.clone()),
    );
    assert_eq!(
        access_service.inspect().expect("access result").status(),
        SubscriptionPosture::AccessLost
    );

    let wrong_topic = TopicConfiguration::new(
        TopicResource::new(
            fixture.scope.project().clone(),
            TopicId::new("different-topic").expect("topic"),
        ),
        None,
        Some(86_400),
        TopicState::Active,
    )
    .expect("wrong topic");
    let mut tampered_service = queued_service(
        &fixture,
        ProviderProvenance::Recording,
        Ok(TopicConfigurationResponse::new(
            wrong_topic,
            fixture.scope.fence(),
            fixture.secret.credential_revision(),
        )),
        Ok(subscription),
        Ok(list),
    );
    assert_eq!(
        tampered_service
            .inspect()
            .expect("tampered result")
            .status(),
        SubscriptionPosture::Tampered
    );
}

#[test]
fn opaque_page_tokens_are_scope_bound_and_repeated_tokens_fail_closed() {
    let fixture = fixture();
    let (topic, subscription, _) = complete_responses(&fixture);
    let first_request = ListSubscriptionsRequest::new(&fixture.scope, &fixture.secret, 50, None)
        .expect("first request");
    let token = OpaquePageToken::bound(
        "provider-page-token",
        &fixture.scope.scope_digest(),
        first_request.list_digest(),
        2,
    )
    .expect("bound token");
    let first_page = ListSubscriptionsResponse::new(
        [],
        Some(token.clone()),
        1,
        fixture.scope.fence(),
        fixture.secret.credential_revision(),
        first_request.list_digest(),
    )
    .expect("first page");
    let second_request =
        ListSubscriptionsRequest::new(&fixture.scope, &fixture.secret, 50, Some(token.clone()))
            .expect("second request");
    let second_page = ListSubscriptionsResponse::new(
        [fixture.scope.subscription().clone()],
        Some(token),
        2,
        fixture.scope.fence(),
        fixture.secret.credential_revision(),
        second_request.list_digest(),
    )
    .expect("second page");
    let mut service = queued_service(
        &fixture,
        ProviderProvenance::Recording,
        Ok(topic),
        Ok(subscription),
        Ok(first_page),
    );
    service
        .provider_mut()
        .transport_mut()
        .push_list_response(Ok(second_page));
    assert_eq!(
        service
            .propose(InspectionRequest::new(3, 50).expect("bounds"))
            .expect("loop result")
            .status(),
        SubscriptionPosture::Tampered
    );

    let other_scope = {
        let mut altered = fixture.scope.clone();
        let _ = &mut altered;
        GcpPubsubSubscriptionScope::new(
            fixture.scope.project().clone(),
            fixture.scope.topic().clone(),
            fixture.scope.subscription().clone(),
            fixture.scope.schema().cloned(),
            fixture.scope.dead_letter_topic().cloned(),
            fixture.scope.mission().clone(),
            fixture.scope.work_product().clone(),
            fixture.scope.work_product_revision(),
            digest("different-permission"),
            fixture.scope.consent_digest().clone(),
        )
        .expect("other scope")
    };
    let other_request = ListSubscriptionsRequest::new(&other_scope, &fixture.secret, 50, None);
    assert!(other_request.is_err());
}

#[test]
fn registration_and_secret_revocation_are_reversible_and_visible() {
    let fixture = fixture();
    let (topic, subscription, list) = complete_responses(&fixture);
    let mut service = queued_service(
        &fixture,
        ProviderProvenance::Recording,
        Ok(topic),
        Ok(subscription),
        Ok(list),
    );
    let transition = service.revoke_registration().expect("revoke");
    assert_eq!(transition.new_status, RegistrationStatus::Revoked);
    assert_eq!(
        service.inspect().expect("revoked result").status(),
        SubscriptionPosture::Revoked
    );
    let reverse = service.reverse_registration().expect("reverse");
    assert_eq!(reverse.new_status, RegistrationStatus::Reversed);
    assert_eq!(
        service.inspect().expect("reversed result").status(),
        SubscriptionPosture::Revoked
    );
}

#[test]
fn bounded_configuration_limits_reject_adversarial_values() {
    let project = ProjectId::new("project-1").expect("project");
    let topic = TopicResource::new(project.clone(), TopicId::new("topic-1").expect("topic"));
    let other_project = ProjectId::new("project-2").expect("other project");
    let other_topic = TopicResource::new(
        other_project.clone(),
        TopicId::new("topic-1").expect("other topic"),
    );
    let subscription = SubscriptionResource::new(
        project.clone(),
        SubscriptionId::new("subscription-1").expect("subscription"),
    );
    assert!(
        GcpPubsubSubscriptionScope::new(
            project.clone(),
            other_topic,
            subscription.clone(),
            None,
            None,
            MissionId::new("mission-1").expect("mission"),
            WorkProductId::new("work-product-1").expect("work product"),
            Revision::new(1).expect("revision"),
            digest("permission"),
            digest("consent"),
        )
        .is_err()
    );
    assert!(DeadLetterPolicy::new(topic.clone(), 4).is_err());
    assert!(RetryPolicy::new(601, 601).is_err());
    assert!(ExpirationPolicy::new(Some(60), false).is_err());
    assert!(TopicConfiguration::new(topic.clone(), None, Some(599), TopicState::Active).is_err());
    assert!(FilterExpression::new("\n").is_err());
    assert!(
        PushConfiguration::new(
            Some("not-a-url"),
            None::<&str>,
            None::<&str>,
            PushWrapper::Pubsub,
        )
        .is_err()
    );
    assert!(OpaquePageToken::new(" ").is_err());
    assert!(InspectionRequest::new(17, 1).is_err());
    assert!(InspectionRequest::new(1, 101).is_err());
}

#[test]
fn mission_consumer_rejects_stale_scope_and_preserves_layer_two_boundary() {
    let fixture = fixture();
    let (topic, subscription, list) = complete_responses(&fixture);
    let mut service = queued_service(
        &fixture,
        ProviderProvenance::Recording,
        Ok(topic),
        Ok(subscription),
        Ok(list),
    );
    let proposal = service.inspect().expect("proposal");
    let consumer = MissionGcpPubsubConsumer::new(fixture.scope.clone(), service.registration())
        .expect("consumer");
    let result = consumer.consume(proposal.clone()).expect("Mission result");
    assert_eq!(result.posture, SubscriptionPosture::Active);
    assert!(result.review_only);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    assert!(!result.truth_authority);
    assert!(!result.consent_authority);
    assert!(!result.effect_authority);
    assert!(!result.receipt_authority);
    assert!(!result.verification_authority);
    assert!(!result.outcome_authority);
    assert!(!result.delivery_completion);
    assert!(!result.work_product_adopted);
    assert_eq!(result.project.digest, fixture.scope.project().digest());

    let stale_scope = GcpPubsubSubscriptionScope::new(
        fixture.scope.project().clone(),
        fixture.scope.topic().clone(),
        fixture.scope.subscription().clone(),
        fixture.scope.schema().cloned(),
        fixture.scope.dead_letter_topic().cloned(),
        MissionId::new("stale-mission").expect("stale mission"),
        fixture.scope.work_product().clone(),
        fixture.scope.work_product_revision(),
        fixture.scope.permission_digest().clone(),
        fixture.scope.consent_digest().clone(),
    )
    .expect("stale scope");
    assert!(MissionGcpPubsubConsumer::new(stale_scope, service.registration()).is_err());
}

#[test]
fn http_failure_classes_map_to_fail_closed_postures() {
    let fixture = fixture();
    for (error, expected) in [
        (
            TransportError::bad_request(),
            SubscriptionPosture::Misconfigured,
        ),
        (
            TransportError::not_found(),
            SubscriptionPosture::Misconfigured,
        ),
        (
            TransportError::unauthenticated(),
            SubscriptionPosture::AccessLost,
        ),
        (
            TransportError::rate_limited(),
            SubscriptionPosture::ProviderUnknown,
        ),
        (
            TransportError::server_failure(),
            SubscriptionPosture::ProviderUnknown,
        ),
        (
            TransportError::timeout(),
            SubscriptionPosture::ProviderUnknown,
        ),
    ] {
        let mut transport = RecordingGcpPubsubTransport::default();
        transport.push_topic_response(Err(error));
        let provider = GcpPubsubProvider::new(transport, "1.0.0", ProviderProvenance::Recording)
            .expect("provider");
        let mut service = GcpPubsubSubscriptionResultService::new(
            fixture.scope.clone(),
            fixture.secret.clone(),
            provider,
        )
        .expect("service");
        assert_eq!(
            service.inspect().expect("failure result").status(),
            expected
        );
    }
}
