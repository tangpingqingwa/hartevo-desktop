use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_plugin_runtime::{
    MissionId as RuntimeMissionId, PluginRuntime, PluginScope, ProjectId as RuntimeProjectId,
};
use serde_json::json;

use hartevo_sailpoint_certification_result_plugin::{
    AccessSummary, AccessType, BlockedEnvSailPointTransport, CampaignId, CampaignSnapshot,
    CampaignState, CertificationId, CertificationRecord, DecisionCounts, DecisionState, Digest,
    EntitlementId, IdentityId, MissionSailPointCertificationConsumer, PermissionSnapshot,
    ProviderRevision, RecordingSailPointTransport, ReviewerId, SailPointCertificationContract,
    SailPointCertificationResultError, SailPointCertificationScope,
    SailPointCertificationScopeInput, SailPointEndpoint, SailPointEvidenceProposalRequest,
    SailPointHttpResponse, SailPointProvider, SailPointReadRequest, SailPointResponseBody,
    SailPointTransportError, SecretReference, TransportProvenance, contract_bounds_tripwire,
    contract_digest, native_probe_from_environment, plugin_definition, response_from_json,
};

const NOW_SECONDS: i64 = 1_800_000_000;

fn at() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid test timestamp")
}

fn provider_revision() -> ProviderRevision {
    ProviderRevision::new("sailpoint-isc-v3-r1").expect("provider revision")
}

fn role_scope() -> SailPointCertificationScope {
    SailPointCertificationScope::new(SailPointCertificationScopeInput {
        tenant: "acme".to_owned(),
        api_base: "https://acme.api.identitynow.com/v3".to_owned(),
        certification_id: "cert-1".to_owned(),
        campaign_id: "campaign-1".to_owned(),
        access_type: AccessType::Role,
        reviewer_id: "reviewer-1".to_owned(),
        identity_id: "identity-1".to_owned(),
        entitlement_id: None,
        campaign_revision: 7,
        entitlement_revision: None,
        mission_id: "mission-1".to_owned(),
        mission_revision: 3,
        project_id: "project-1".to_owned(),
        project_revision: 4,
        consent_id: "consent-1".to_owned(),
        consent_revision: 5,
        permission_digest: PermissionSnapshot::read_only().digest().clone(),
    })
    .expect("role scope")
}

fn entitlement_scope() -> SailPointCertificationScope {
    SailPointCertificationScope::new(SailPointCertificationScopeInput {
        tenant: "acme".to_owned(),
        api_base: "https://acme.api.identitynow.com".to_owned(),
        certification_id: "cert-1".to_owned(),
        campaign_id: "campaign-1".to_owned(),
        access_type: AccessType::Entitlement,
        reviewer_id: "reviewer-1".to_owned(),
        identity_id: "identity-1".to_owned(),
        entitlement_id: Some("entitlement-1".to_owned()),
        campaign_revision: 7,
        entitlement_revision: Some(9),
        mission_id: "mission-1".to_owned(),
        mission_revision: 3,
        project_id: "project-1".to_owned(),
        project_revision: 4,
        consent_id: "consent-1".to_owned(),
        consent_revision: 5,
        permission_digest: PermissionSnapshot::read_only().digest().clone(),
    })
    .expect("entitlement scope")
}

fn counts(decision: DecisionState) -> DecisionCounts {
    let mut counts = DecisionCounts::default();
    counts.add_decision(decision);
    counts
}

fn certification(
    scope: &SailPointCertificationScope,
    state: CampaignState,
    decision: DecisionState,
    id: &str,
    reviewer_id: &str,
) -> CertificationRecord {
    let decision_counts = counts(decision);
    CertificationRecord {
        id: CertificationId::new(id).expect("certification id"),
        campaign: CampaignSnapshot {
            id: CampaignId::new(scope.campaign_id().as_str()).expect("campaign id"),
            revision: scope.campaign_revision(),
            state,
            identities_completed: u32::from(!matches!(state, CampaignState::Active)),
            identities_total: 1,
            decision_counts: decision_counts.clone(),
            created_at: Some(at() - Duration::hours(1)),
            modified_at: Some(at()),
            due_at: Some(at() + Duration::hours(1)),
        },
        reviewer_id: ReviewerId::new(reviewer_id).expect("reviewer id"),
        identity_id: IdentityId::new(scope.identity_id().as_str()).expect("identity id"),
        decision_state: decision,
        decision_counts,
        created_at: Some(at() - Duration::hours(1)),
        modified_at: Some(at()),
        due_at: Some(at() + Duration::hours(1)),
    }
}

fn access_summary(
    scope: &SailPointCertificationScope,
    decision: DecisionState,
    id: &str,
    reviewer_id: &str,
) -> AccessSummary {
    AccessSummary {
        id: EntitlementId::new(id).expect("access id"),
        access_type: scope.access_type(),
        reviewer_id: ReviewerId::new(reviewer_id).expect("reviewer id"),
        identity_id: IdentityId::new(scope.identity_id().as_str()).expect("identity id"),
        entitlement_id: scope.entitlement_id().cloned(),
        campaign_revision: scope.campaign_revision(),
        entitlement_revision: scope.entitlement_revision(),
        decision_state: decision,
        privileged: true,
        decision_at: Some(at()),
    }
}

fn response(
    scope: &SailPointCertificationScope,
    endpoint: SailPointEndpoint,
    body: SailPointResponseBody,
    total_count: Option<u32>,
) -> Result<SailPointHttpResponse, SailPointTransportError> {
    let limit = if matches!(endpoint, SailPointEndpoint::Certification { .. }) {
        1
    } else {
        50
    };
    let request = SailPointReadRequest::new(endpoint, scope, limit, 0, at())
        .expect("bounded request")
        .http_request();
    SailPointHttpResponse::from_body(&request, body, provider_revision(), total_count)
        .map_err(SailPointTransportError::from)
}

fn service(
    scope: SailPointCertificationScope,
    state: CampaignState,
    decision: DecisionState,
) -> hartevo_sailpoint_certification_result_plugin::SailPointCertificationService<
    RecordingSailPointTransport,
> {
    let cert_endpoint = SailPointEndpoint::Certification {
        certification_id: scope.certification_id().clone(),
    };
    let campaign_endpoint = SailPointEndpoint::Campaigns;
    let access_endpoint = SailPointEndpoint::AccessSummaries {
        certification_id: scope.certification_id().clone(),
        access_type: scope.access_type(),
    };
    let cert_request = SailPointReadRequest::new(cert_endpoint.clone(), &scope, 1, 0, at())
        .expect("cert request")
        .http_request();
    let campaign_request =
        SailPointReadRequest::new(campaign_endpoint.clone(), &scope, 50, 0, at())
            .expect("campaign request")
            .http_request();
    let access_request = SailPointReadRequest::new(access_endpoint.clone(), &scope, 50, 0, at())
        .expect("access request")
        .http_request();
    let responses = [
        SailPointHttpResponse::from_body(
            &cert_request,
            SailPointResponseBody::Certification(certification(
                &scope,
                state,
                decision,
                "cert-1",
                "reviewer-1",
            )),
            provider_revision(),
            Some(1),
        ),
        SailPointHttpResponse::from_body(
            &campaign_request,
            SailPointResponseBody::campaigns(vec![certification(
                &scope,
                state,
                decision,
                "cert-1",
                "reviewer-1",
            )])
            .expect("campaign body"),
            provider_revision(),
            Some(1),
        ),
        SailPointHttpResponse::from_body(
            &access_request,
            SailPointResponseBody::access_summaries(vec![access_summary(
                &scope,
                decision,
                "role-1",
                "reviewer-1",
            )])
            .expect("access body"),
            provider_revision(),
            Some(1),
        ),
    ];
    let transport = RecordingSailPointTransport::fixture(
        responses.map(|response| response.map_err(SailPointTransportError::from)),
    );
    let provider = SailPointProvider::new(transport).expect("provider");
    hartevo_sailpoint_certification_result_plugin::SailPointCertificationService::new(
        scope,
        SecretReference::oauth("host-owned-sailpoint-reference").expect("secret"),
        provider,
    )
    .expect("service")
}

#[test]
fn contract_registration_plugin_and_secret_are_fail_closed() {
    let contract = SailPointCertificationContract::baseline().expect("contract");
    assert_eq!(contract.digest(), contract_digest());
    assert!(contract_bounds_tripwire());

    let scope = role_scope();
    let secret = SecretReference::pat("pat-live-material-must-not-escape").expect("secret");
    let service = service(
        scope.clone(),
        CampaignState::Active,
        DecisionState::Approved,
    );
    assert!(service.registration().is_active());
    assert_eq!(service.registration().scope_digest, *scope.scope_digest());
    assert_ne!(service.registration().provider_digest, Digest::zero());
    assert_ne!(service.registration().evidence_digest, Digest::zero());
    assert!(service.is_active());
    let encoded = serde_json::to_string(&secret).expect("opaque secret JSON");
    let debug = format!("{secret:?}");
    assert!(!encoded.contains("pat-live-material"));
    assert!(!debug.contains("pat-live-material"));
    assert!(encoded.contains("opaque"));

    let runtime_scope = PluginScope::new(
        RuntimeProjectId::new("project-1").expect("runtime project"),
        RuntimeMissionId::new("mission-1").expect("runtime mission"),
        1,
    )
    .expect("runtime scope");
    let definition = plugin_definition(runtime_scope.clone()).expect("definition");
    let mut runtime = PluginRuntime::new();
    let handle = runtime.define(definition).expect("define");
    let receipt = runtime.mount(&handle).expect("mount");
    assert_eq!(receipt.generation(), 1);
    runtime.revoke(&handle).expect("revoke");
    assert_eq!(
        native_probe_from_environment().status,
        hartevo_sailpoint_certification_result_plugin::NativeProbeStatus::BlockedEnv
    );
}

#[test]
fn proposal_consumer_record_and_verify_are_non_mutating() {
    let scope = role_scope();
    let mut service = service(
        scope.clone(),
        CampaignState::Active,
        DecisionState::Approved,
    );
    let proposal = service
        .propose(SailPointEvidenceProposalRequest::new(at()))
        .expect("proposal");
    assert_eq!(proposal.campaign_state(), CampaignState::Active);
    assert_eq!(proposal.decision_state(), DecisionState::Approved);
    assert!(!proposal.projection.partial);
    assert!(proposal.read_only);
    assert!(proposal.proposal_only);
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert!(!proposal.certification_approved);
    assert!(!proposal.certification_revoked);
    assert!(!proposal.certification_finalized);
    assert!(!proposal.access_request_submitted);
    assert!(!proposal.projection.access_safety_claim);
    assert!(!proposal.evidence.raw_identity_payload_retained);

    let consumer = MissionSailPointCertificationConsumer::new(scope, service.registration())
        .expect("consumer");
    let adoption = consumer.consume(&proposal).expect("consumer proposal");
    assert!(!adoption.adopted);
    assert!(!adoption.mutates_consent);
    assert!(!adoption.creates_effect);
    assert!(!adoption.access_safety_authority);
    assert!(!adoption.kernel_consent_authority);
    assert!(!adoption.kernel_outcome_authority);

    let verification = service.verify(&proposal).expect("verification");
    assert!(verification.verified);
    assert!(!verification.provider_readback_performed);
    let receipt = service.record(&proposal).expect("record");
    assert!(receipt.recorded);
    assert!(!receipt.provider_mutated);
    assert!(service.record(&proposal).is_err());
}

#[test]
fn official_paths_scope_types_and_reviewer_filtering_are_exact() {
    let scope = entitlement_scope();
    let certification_request = SailPointReadRequest::new(
        SailPointEndpoint::Certification {
            certification_id: scope.certification_id().clone(),
        },
        &scope,
        1,
        0,
        at(),
    )
    .expect("certification request");
    let certification_http = certification_request.http_request();
    assert_eq!(certification_http.method, "GET");
    assert_eq!(
        certification_http.origin,
        "https://acme.api.identitynow.com"
    );
    assert_eq!(
        certification_http.path_and_query,
        "/v3/certifications/cert-1"
    );
    let access = SailPointReadRequest::new(
        SailPointEndpoint::AccessSummaries {
            certification_id: scope.certification_id().clone(),
            access_type: AccessType::Entitlement,
        },
        &scope,
        125,
        250,
        at(),
    )
    .expect("access request");
    assert_eq!(
        access.http_request().path_and_query,
        "/v3/certifications/cert-1/access-summaries/ENTITLEMENT?limit=125&offset=250&count=false&sorters=access.name"
    );
    assert!(
        SailPointReadRequest::new(
            SailPointEndpoint::AccessSummaries {
                certification_id: scope.certification_id().clone(),
                access_type: AccessType::Role,
            },
            &scope,
            10,
            0,
            at(),
        )
        .is_err()
    );

    let other = certification(
        &scope,
        CampaignState::Active,
        DecisionState::Pending,
        "cert-other",
        "reviewer-other",
    );
    let target = certification(
        &scope,
        CampaignState::Active,
        DecisionState::Approved,
        "cert-1",
        "reviewer-1",
    );
    assert_ne!(other.id, target.id);
    let json_body = serde_json::to_string(&target).expect("sanitized target");
    assert!(!json_body.contains("reviewer-other"));
}

#[test]
fn json_redaction_drops_names_emails_descriptions_comments_and_tokens() {
    let scope = entitlement_scope();
    let request = SailPointReadRequest::new(
        SailPointEndpoint::AccessSummaries {
            certification_id: scope.certification_id().clone(),
            access_type: AccessType::Entitlement,
        },
        &scope,
        50,
        0,
        at(),
    )
    .expect("request");
    let raw = serde_json::to_vec(&json!([{
        "id": "access-1",
        "type": "ENTITLEMENT",
        "name": "Raw entitlement name",
        "description": "Raw access description",
        "comment": "Reviewer raw comment",
        "decision": "APPROVED",
        "completed": true,
        "campaignRevision": 7,
        "entitlementRevision": 9,
        "privileged": true,
        "reviewer": {
            "id": "reviewer-1",
            "name": "Reviewer Name",
            "email": "reviewer@example.com"
        },
        "identity": {
            "id": "identity-1",
            "name": "Identity Name",
            "email": "identity@example.com"
        },
        "entitlement": {
            "id": "entitlement-1",
            "name": "Nested entitlement name",
            "description": "Nested description"
        },
        "pat": "pat-raw-material",
        "oauth": "oauth-raw-material"
    }]))
    .expect("raw fixture");
    let response = response_from_json(&request, 200, &raw, provider_revision(), Some(1), None)
        .expect("sanitized response");
    let encoded = serde_json::to_string(&response).expect("response JSON");
    for forbidden in [
        "Raw entitlement name",
        "Raw access description",
        "Reviewer raw comment",
        "Reviewer Name",
        "reviewer@example.com",
        "Identity Name",
        "identity@example.com",
        "Nested description",
        "pat-raw-material",
        "oauth-raw-material",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "raw value survived: {forbidden}"
        );
    }
    assert!(encoded.contains("entitlement-1"));
    assert!(encoded.contains("privileged"));
}

#[test]
fn campaign_and_decision_states_are_distinct_and_fail_closed() {
    assert_eq!(
        CampaignState::from_wire(Some("ACTIVE"), false, false, None, at()),
        CampaignState::Active
    );
    assert_eq!(
        CampaignState::from_wire(Some("COMPLETED"), true, false, None, at()),
        CampaignState::Completed
    );
    assert_eq!(
        CampaignState::from_wire(Some("REMEDIATION"), false, true, None, at()),
        CampaignState::Remediation
    );
    assert_eq!(
        CampaignState::from_wire(None, false, false, Some(at() - Duration::seconds(1)), at()),
        CampaignState::Expired
    );
    assert_eq!(
        CampaignState::from_wire(Some("unmodeled"), false, false, None, at()),
        CampaignState::Unknown
    );
    assert_eq!(
        DecisionState::from_wire(Some("APPROVED"), true),
        DecisionState::Approved
    );
    assert_eq!(
        DecisionState::from_wire(Some("REVOKED"), true),
        DecisionState::Revoked
    );
    assert_eq!(
        DecisionState::from_wire(None, false),
        DecisionState::Pending
    );
    assert_eq!(
        DecisionState::from_wire(Some("MIXED"), true),
        DecisionState::Partial
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn stale_duplicate_tamper_pagination_and_budget_fences_fail_closed() {
    let scope = role_scope();
    let cert_endpoint = SailPointEndpoint::Certification {
        certification_id: scope.certification_id().clone(),
    };
    let request = SailPointReadRequest::new(cert_endpoint.clone(), &scope, 1, 0, at())
        .expect("request")
        .http_request();
    let stale_record = {
        let mut record = certification(
            &scope,
            CampaignState::Active,
            DecisionState::Pending,
            "cert-1",
            "reviewer-1",
        );
        record.campaign.revision =
            hartevo_sailpoint_certification_result_plugin::Revision::new(8).expect("revision");
        record
    };
    let stale_response = SailPointHttpResponse::from_body(
        &request,
        SailPointResponseBody::Certification(stale_record),
        provider_revision(),
        Some(1),
    )
    .expect("stale response");
    let mut stale_service =
        hartevo_sailpoint_certification_result_plugin::SailPointCertificationService::new(
            scope.clone(),
            SecretReference::new("secret").expect("secret"),
            SailPointProvider::new(RecordingSailPointTransport::new([Ok(stale_response)]))
                .expect("provider"),
        )
        .expect("service");
    assert!(matches!(
        stale_service.read_certification(at()),
        Err(SailPointCertificationResultError::StaleCampaignRevision)
    ));

    let mut tampered_response = response(
        &scope,
        cert_endpoint.clone(),
        SailPointResponseBody::Certification(certification(
            &scope,
            CampaignState::Active,
            DecisionState::Pending,
            "cert-1",
            "reviewer-1",
        )),
        Some(1),
    )
    .expect("response");
    if let SailPointResponseBody::Certification(record) = &mut tampered_response.body {
        record.decision_state = DecisionState::Approved;
    }
    let mut tampered_service =
        hartevo_sailpoint_certification_result_plugin::SailPointCertificationService::new(
            scope.clone(),
            SecretReference::new("secret").expect("secret"),
            SailPointProvider::new(RecordingSailPointTransport::new([Ok(tampered_response)]))
                .expect("provider"),
        )
        .expect("service");
    assert!(matches!(
        tampered_service.read_certification(at()),
        Err(SailPointCertificationResultError::ResponseTampered)
    ));

    let page_one = response(
        &scope,
        SailPointEndpoint::Campaigns,
        SailPointResponseBody::campaigns(vec![certification(
            &scope,
            CampaignState::Active,
            DecisionState::Pending,
            "cert-1",
            "reviewer-1",
        )])
        .expect("page one"),
        Some(2),
    )
    .expect("page one response");
    let page_two_request =
        SailPointReadRequest::new(SailPointEndpoint::Campaigns, &scope, 50, 50, at())
            .expect("page two request")
            .http_request();
    let page_two = SailPointHttpResponse::from_body(
        &page_two_request,
        SailPointResponseBody::campaigns(vec![certification(
            &scope,
            CampaignState::Active,
            DecisionState::Pending,
            "cert-1",
            "reviewer-1",
        )])
        .expect("page two"),
        provider_revision(),
        Some(2),
    )
    .expect("page two response");
    let mut pagination_provider = SailPointProvider::new(RecordingSailPointTransport::new([
        Ok(page_one),
        Ok(page_two),
    ]))
    .expect("provider");
    let page_one_request =
        SailPointReadRequest::new(SailPointEndpoint::Campaigns, &scope, 50, 0, at())
            .expect("page one request");
    assert!(pagination_provider.read(&page_one_request).is_ok());
    let page_two_request =
        SailPointReadRequest::new(SailPointEndpoint::Campaigns, &scope, 50, 50, at())
            .expect("page two request");
    assert!(matches!(
        pagination_provider.read(&page_two_request),
        Err(hartevo_sailpoint_certification_result_plugin::SailPointProviderError::DuplicateIdentifier)
    ));

    let blocked_provider = SailPointProvider::new(BlockedEnvSailPointTransport).expect("provider");
    let mut blocked_service =
        hartevo_sailpoint_certification_result_plugin::SailPointCertificationService::new(
            scope.clone(),
            SecretReference::new("secret").expect("secret"),
            blocked_provider,
        )
        .expect("service");
    let unknown = blocked_service
        .propose(SailPointEvidenceProposalRequest::new(at()))
        .expect("provider unknown proposal");
    assert_eq!(unknown.campaign_state(), CampaignState::Unknown);
    assert!(unknown.projection.provider_unknown);
    for _ in 0..4 {
        assert!(matches!(
            blocked_service.read_campaign(50, 0, at()),
            Err(SailPointCertificationResultError::BlockedEnv)
        ));
    }
    assert!(matches!(
        blocked_service.read_campaign(50, 0, at()),
        Err(SailPointCertificationResultError::RateLimited { .. })
    ));
}

#[test]
fn status_errors_are_redacted_and_registration_revocation_is_reversible() {
    let scope = entitlement_scope();
    let request = SailPointReadRequest::new(
        SailPointEndpoint::AccessSummaries {
            certification_id: scope.certification_id().clone(),
            access_type: scope.access_type(),
        },
        &scope,
        50,
        0,
        at(),
    )
    .expect("request");
    let raw = b"{\"message\":\"reviewer@example.com raw provider error\"}";
    for status in [401, 403, 404, 409, 500] {
        let error = response_from_json(&request, status, raw, provider_revision(), None, None)
            .expect_err("status should fail closed");
        let rendered = format!("{error:?}");
        assert!(!rendered.contains("reviewer@example.com"));
    }
    assert!(matches!(
        response_from_json(&request, 429, raw, provider_revision(), None, Some(11),),
        Err(SailPointTransportError::RateLimited {
            retry_after_seconds: 11
        })
    ));

    let mut service = service(scope, CampaignState::Completed, DecisionState::Revoked);
    service.revoke_registration().expect("revoke registration");
    assert!(!service.is_active());
    assert!(matches!(
        service.read_access_summary(50, 0, at()),
        Err(SailPointCertificationResultError::RegistrationRevoked)
    ));
    assert!(service.revoke_registration().is_err());
}

#[test]
fn scope_and_consent_fences_reject_mismatched_consumers() {
    let role = role_scope();
    let entitlement = entitlement_scope();
    assert!(
        SailPointCertificationScope::new(SailPointCertificationScopeInput {
            entitlement_id: Some("entitlement-1".to_owned()),
            access_type: AccessType::Role,
            ..scope_input(&role)
        })
        .is_err()
    );
    assert!(
        SailPointCertificationScope::new(SailPointCertificationScopeInput {
            entitlement_id: None,
            access_type: AccessType::Entitlement,
            ..scope_input(&entitlement)
        })
        .is_err()
    );

    let mut first = service(role.clone(), CampaignState::Active, DecisionState::Pending);
    let proposal = first
        .propose(SailPointEvidenceProposalRequest::new(at()))
        .expect("proposal");
    let other_service = service(
        entitlement.clone(),
        CampaignState::Active,
        DecisionState::Pending,
    );
    let consumer =
        MissionSailPointCertificationConsumer::new(role, first.registration()).expect("consumer");
    assert!(consumer.consume(&proposal).is_ok());
    let other_proposal = other_service.registration().registration_digest.clone();
    assert_ne!(other_proposal, proposal.registration_digest);
}

fn scope_input(scope: &SailPointCertificationScope) -> SailPointCertificationScopeInput {
    SailPointCertificationScopeInput {
        tenant: scope.tenant().as_str().to_owned(),
        api_base: scope.api_base().v3_base(),
        certification_id: scope.certification_id().as_str().to_owned(),
        campaign_id: scope.campaign_id().as_str().to_owned(),
        access_type: scope.access_type(),
        reviewer_id: scope.reviewer_id().as_str().to_owned(),
        identity_id: scope.identity_id().as_str().to_owned(),
        entitlement_id: scope.entitlement_id().map(|id| id.as_str().to_owned()),
        campaign_revision: scope.campaign_revision().get(),
        entitlement_revision: scope
            .entitlement_revision()
            .map(hartevo_sailpoint_certification_result_plugin::Revision::get),
        mission_id: scope.mission_id().as_str().to_owned(),
        mission_revision: scope.mission_revision().get(),
        project_id: scope.project_id().as_str().to_owned(),
        project_revision: scope.project_revision().get(),
        consent_id: scope.consent_id().as_str().to_owned(),
        consent_revision: scope.consent_revision().get(),
        permission_digest: scope.permission_digest().clone(),
    }
}

#[test]
fn loopback_and_fixture_provenance_never_claim_native_or_connected() {
    let scope = role_scope();
    let body = SailPointResponseBody::Certification(certification(
        &scope,
        CampaignState::Completed,
        DecisionState::Partial,
        "cert-1",
        "reviewer-1",
    ));
    let response = response(
        &scope,
        SailPointEndpoint::Certification {
            certification_id: scope.certification_id().clone(),
        },
        body,
        Some(1),
    )
    .expect("response");
    for transport in [
        RecordingSailPointTransport::fixture([Ok(response.clone())]),
        RecordingSailPointTransport::new([Ok(response.clone())]),
        RecordingSailPointTransport::loopback([Ok(response)]),
    ] {
        let provider = SailPointProvider::new(transport).expect("provider");
        assert!(!provider.definition().native);
        assert!(!provider.definition().connected);
        assert!(!provider.provenance().is_native());
        assert!(!provider.provenance().is_connected());
    }
    assert!(!TransportProvenance::BlockedEnv.is_native());
}
