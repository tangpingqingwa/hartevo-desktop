use std::collections::{BTreeMap, BTreeSet};

use chrono::{TimeZone, Utc};
use hartevo_contentful_entry_result_plugin::{
    BlockedEnvContentfulProvider, CONTENTFUL_ENTRY_RESULT_CONTRACT_JSON, CONTENTFUL_MAX_PAGE_SIZE,
    CONTENTFUL_MAX_PAGES, CONTENTFUL_MAX_REFERENCE_DEPTH, CONTENTFUL_MAX_REFERENCES, ContentfulApi,
    ContentfulEntryResultContract, ContentfulEntryResultService, ContentfulEntrySnapshot,
    ContentfulModelError, ContentfulPagination, ContentfulProjection, ContentfulProvider,
    ContentfulProviderError, ContentfulReadRequest, ContentfulReferenceMetadata,
    ContentfulResultError, ContentfulScope, ContentfulScopeInput, ContentfulVersion, Digest,
    EntryId, EvidenceSource, FixtureContentfulProvider, LocaleCode, LoopbackContentfulProvider,
    MissionContentfulResultConsumer, NativeStatus, PublishedCounter, RecordingContentfulProvider,
    SecretReference, contract_digest,
};

const NOW_SECONDS: i64 = 1_750_000_000;

fn now() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("fixed timestamp")
}

fn scope() -> ContentfulScope {
    ContentfulScope::new(ContentfulScopeInput {
        organization: "org-1".to_owned(),
        space: "space-1".to_owned(),
        environment: "staging".to_owned(),
        content_type: "article".to_owned(),
        entry: "entry-1".to_owned(),
        locale: "en-US".to_owned(),
        version: 3,
        published_counter: 2,
        project_id: "project-1".to_owned(),
        project_revision: 4,
        mission_id: "mission-1".to_owned(),
        mission_revision: 5,
        work_product_id: "work-product-1".to_owned(),
        work_product_revision: 6,
    })
    .expect("scope")
}

fn secret() -> SecretReference {
    SecretReference::new("vault/contentful-cma-cda", 7).expect("secret reference")
}

fn snapshot(
    scope: &ContentfulScope,
    projection: ContentfulProjection,
    version: u64,
    published_counter: u64,
) -> ContentfulEntrySnapshot {
    ContentfulEntrySnapshot::new(
        scope,
        projection,
        ContentfulVersion::new(version).expect("version"),
        PublishedCounter::new(published_counter),
        now(),
        BTreeSet::from([
            LocaleCode::new("en-US").expect("locale"),
            LocaleCode::new("de-DE").expect("locale"),
        ]),
        BTreeMap::from([
            ("title".to_owned(), Digest::from_text("localized-title")),
            ("summary".to_owned(), Digest::from_text("localized-summary")),
        ]),
        Some(Digest::from_text("reference-set")),
    )
    .expect("snapshot")
}

fn fixture_service() -> ContentfulEntryResultService<FixtureContentfulProvider> {
    ContentfulEntryResultService::new_at(
        FixtureContentfulProvider::new(scope()).expect("fixture"),
        now(),
    )
    .expect("service")
}

#[test]
fn contract_is_json_valid_and_exactly_layer_one() {
    let contract = ContentfulEntryResultContract::baseline().expect("contract");
    contract.validate().expect("contract validates");
    assert_eq!(contract.digest(), contract_digest());
    assert!(
        serde_json::from_str::<serde_json::Value>(CONTENTFUL_ENTRY_RESULT_CONTRACT_JSON).is_ok()
    );
    assert_eq!(contract.document()["layer"], 1);
    assert_eq!(contract.document()["native"]["status"], "BLOCKED_ENV");
    assert_eq!(contract.document()["api"]["arbitraryGraphql"], false);
    assert_eq!(
        contract.document()["typedHttpStatuses"],
        serde_json::json!([401, 403, 404, 409, 422, 429, 500, 502, 503, 504])
    );
}

#[test]
fn fixture_reads_draft_published_and_references_without_raw_content() {
    let service = fixture_service();
    let request = ContentfulReadRequest::new(scope(), ContentfulApi::Cma);
    let mut consumer = MissionContentfulResultConsumer::new(service);
    let evidence = consumer.read_result(&request).expect("result evidence");
    evidence.validate().expect("valid evidence");
    assert_eq!(evidence.draft.entry.projection, ContentfulProjection::Draft);
    assert_eq!(
        evidence
            .published
            .as_ref()
            .expect("published projection")
            .entry
            .projection,
        ContentfulProjection::Published
    );
    assert_eq!(evidence.references.references.len(), 1);
    assert_eq!(evidence.draft.entry.locale_coverage.len(), 2);
    assert_eq!(evidence.draft.entry.field_digests.len(), 2);
    assert_eq!(evidence.draft.receipt.response_status, 200);
    assert_eq!(evidence.draft.receipt.api, ContentfulApi::Cma);
    assert_eq!(
        evidence.draft.receipt.evidence_source,
        EvidenceSource::Fixture
    );
    assert!(!evidence.draft.receipt.native_connected_claim);
    assert!(!evidence.draft.receipt.raw_localized_body_retained);
    assert!(!evidence.draft.receipt.raw_provider_payload_retained);
    assert!(!evidence.draft.receipt.secret_material_retained);
    assert!(!evidence.native_connected_claim);
    assert!(!evidence.kernel_authority);
    let serialized = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!serialized.contains("localized-title"));
    assert!(!serialized.contains("localized-summary"));
    assert!(!serialized.contains("vault/contentful-cma-cda"));
    assert!(!serialized.contains("Authorization"));
    assert_eq!(consumer.service().provider().calls().len(), 3);

    let observation = consumer
        .compile_work_product_observation(&evidence)
        .expect("work product observation");
    assert_eq!(observation.mission_id.as_str(), "mission-1");
    assert_eq!(observation.work_product_revision, 6);
    assert!(!observation.effect_authority);
    assert!(!observation.outcome_authority);
    assert!(!observation.adopted);
}

#[test]
fn fixture_recording_loopback_and_blocked_env_never_claim_native() {
    let fixture = FixtureContentfulProvider::new(scope()).expect("fixture");
    let recording = RecordingContentfulProvider::new(scope()).expect("recording");
    let loopback = LoopbackContentfulProvider::new(scope()).expect("loopback");
    let blocked = BlockedEnvContentfulProvider::new(scope()).expect("blocked env");
    for manifest in [
        fixture.manifest(),
        recording.manifest(),
        loopback.manifest(),
        blocked.manifest(),
    ] {
        assert_eq!(manifest.native_status, NativeStatus::BlockedEnv);
        assert!(!manifest.native_connected_claim);
        assert!(!manifest.evidence_source.is_native());
    }
    assert!(!format!("{:?}", secret()).contains("vault/contentful-cma-cda"));
    assert!(
        !serde_json::to_string(&secret())
            .expect("secret JSON")
            .contains("vault/contentful-cma-cda")
    );
}

#[test]
fn blocked_env_provider_fails_closed_before_any_read() {
    let mut service = ContentfulEntryResultService::new(
        BlockedEnvContentfulProvider::new(scope()).expect("blocked provider"),
    )
    .expect("service registration remains local");
    let error = service
        .read_entry(&ContentfulReadRequest::new(scope(), ContentfulApi::Cma))
        .expect_err("native credential gap");
    assert_eq!(
        error,
        ContentfulResultError::Provider(ContentfulProviderError::BlockedEnv)
    );
}

#[test]
fn exact_scope_and_stale_mission_fences_are_typed() {
    let mut service = fixture_service();
    let mut stale = scope();
    stale.mission_revision = 99;
    let error = service
        .read_entry(&ContentfulReadRequest::new(stale, ContentfulApi::Cma))
        .expect_err("stale mission");
    assert_eq!(
        error,
        ContentfulResultError::StaleMission {
            expected: 5,
            actual: 99
        }
    );

    let mut drifted = scope();
    drifted.space =
        hartevo_contentful_entry_result_plugin::SpaceId::new("other-space").expect("space");
    let error = service
        .read_entry(&ContentfulReadRequest::new(drifted, ContentfulApi::Cma))
        .expect_err("space drift");
    assert!(matches!(error, ContentfulResultError::ScopeDrift { .. }));
}

#[test]
fn version_and_published_counter_drift_and_regression_fail_closed() {
    let bound_scope = scope();
    let mut provider = FixtureContentfulProvider::from_responses(
        bound_scope.clone(),
        secret(),
        Ok(snapshot(&bound_scope, ContentfulProjection::Draft, 4, 2)),
        Ok(snapshot(
            &bound_scope,
            ContentfulProjection::Published,
            4,
            2,
        )),
        Ok(Vec::new()),
    );
    let mut service = ContentfulEntryResultService::new(provider.clone()).expect("service");
    let error = service
        .read_entry(&ContentfulReadRequest::new(
            bound_scope.clone(),
            ContentfulApi::Cma,
        ))
        .expect_err("version drift");
    assert_eq!(
        error,
        ContentfulResultError::VersionDrift {
            expected: 3,
            observed: 4
        }
    );

    let mut request = ContentfulReadRequest::new(bound_scope.clone(), ContentfulApi::Cma);
    request.expected_version = None;
    request.expected_published_counter = None;
    provider.set_entry_response(Ok(snapshot(
        &bound_scope,
        ContentfulProjection::Draft,
        3,
        2,
    )));
    let mut service = ContentfulEntryResultService::new(provider).expect("service");
    service.read_entry(&request).expect("first revision");
    service.provider_mut().set_entry_response(Ok(snapshot(
        &bound_scope,
        ContentfulProjection::Draft,
        2,
        1,
    )));
    let error = service.read_entry(&request).expect_err("regression");
    assert!(matches!(
        error,
        ContentfulResultError::VersionRegression { .. }
    ));
}

#[test]
fn pagination_and_reference_caps_are_enforced_before_provider_use() {
    assert!(matches!(
        ContentfulPagination::new(CONTENTFUL_MAX_PAGES + 1, CONTENTFUL_MAX_PAGE_SIZE, None),
        Err(ContentfulModelError::InvalidPagination)
    ));
    assert!(matches!(
        ContentfulPagination::new(1, CONTENTFUL_MAX_PAGE_SIZE + 1, None),
        Err(ContentfulModelError::InvalidPagination)
    ));
    assert!(matches!(
        hartevo_contentful_entry_result_plugin::ContentfulReferenceRequest::new(
            scope(),
            ContentfulApi::Cma,
            CONTENTFUL_MAX_REFERENCE_DEPTH + 1
        ),
        Err(ContentfulModelError::InvalidReferenceDepth)
    ));

    let bound_scope = scope();
    let references = (0..=CONTENTFUL_MAX_REFERENCES)
        .map(|index| {
            ContentfulReferenceMetadata::new(
                EntryId::new(format!("ref-{index}"))?,
                bound_scope.content_type.clone(),
                ContentfulProjection::Published,
                bound_scope.version,
                bound_scope.published_counter,
                BTreeSet::from([bound_scope.locale.clone()]),
            )
        })
        .collect::<Result<Vec<_>, ContentfulModelError>>()
        .expect("bounded metadata values");
    let provider = FixtureContentfulProvider::from_responses(
        bound_scope.clone(),
        secret(),
        Ok(snapshot(&bound_scope, ContentfulProjection::Draft, 3, 2)),
        Ok(snapshot(
            &bound_scope,
            ContentfulProjection::Published,
            3,
            2,
        )),
        Ok(references),
    );
    let mut service = ContentfulEntryResultService::new(provider).expect("service");
    let request = hartevo_contentful_entry_result_plugin::ContentfulReferenceRequest::new(
        bound_scope,
        ContentfulApi::Cma,
        10,
    )
    .expect("reference request");
    assert_eq!(
        service.read_entry_references(&request),
        Err(ContentfulResultError::BoundExceeded {
            kind: "references",
            maximum: CONTENTFUL_MAX_REFERENCES
        })
    );
}

#[test]
fn typed_http_failures_cover_requested_status_and_shape_classes() {
    let statuses = [
        ContentfulProviderError::Unauthorized,
        ContentfulProviderError::Forbidden,
        ContentfulProviderError::NotFound,
        ContentfulProviderError::Conflict,
        ContentfulProviderError::UnprocessableEntity,
        ContentfulProviderError::RateLimited {
            retry_after_seconds: Some(1),
        },
        ContentfulProviderError::ServerFailure { status: 500 },
        ContentfulProviderError::ServerFailure { status: 503 },
        ContentfulProviderError::Timeout,
        ContentfulProviderError::Malformed,
        ContentfulProviderError::Partial,
    ];
    assert_eq!(
        ContentfulProviderError::Unauthorized.status_code(),
        Some(401)
    );
    assert_eq!(ContentfulProviderError::Forbidden.status_code(), Some(403));
    assert_eq!(ContentfulProviderError::NotFound.status_code(), Some(404));
    assert_eq!(ContentfulProviderError::Conflict.status_code(), Some(409));
    assert_eq!(
        ContentfulProviderError::UnprocessableEntity.status_code(),
        Some(422)
    );
    assert_eq!(
        ContentfulProviderError::RateLimited {
            retry_after_seconds: None
        }
        .status_code(),
        Some(429)
    );
    assert_eq!(
        ContentfulProviderError::ServerFailure { status: 502 }.status_code(),
        Some(502)
    );
    assert_eq!(
        ContentfulProviderError::ServerFailure { status: 504 }.status_code(),
        Some(504)
    );
    assert_eq!(ContentfulProviderError::Timeout.status_code(), None);
    assert_eq!(ContentfulProviderError::Malformed.status_code(), None);
    assert_eq!(ContentfulProviderError::Partial.status_code(), None);

    for error in statuses {
        let bound_scope = scope();
        let provider = FixtureContentfulProvider::from_responses(
            bound_scope.clone(),
            secret(),
            Err(error.clone()),
            Ok(snapshot(
                &bound_scope,
                ContentfulProjection::Published,
                3,
                2,
            )),
            Ok(Vec::new()),
        );
        let mut service = ContentfulEntryResultService::new(provider).expect("service");
        let observed = service
            .read_entry(&ContentfulReadRequest::new(bound_scope, ContentfulApi::Cma))
            .expect_err("typed provider failure");
        assert_eq!(observed, ContentfulResultError::Provider(error));
    }
}

#[test]
fn replay_tamper_and_revocation_are_detected_without_native_authority() {
    let mut service = fixture_service();
    let request = ContentfulReadRequest::new(scope(), ContentfulApi::Cda);
    let evidence = service.read_result(&request).expect("evidence");
    let mut tampered = evidence.clone();
    tampered.result_digest = Digest::from_text("tampered-result");
    assert_eq!(
        tampered.validate(),
        Err(ContentfulResultError::ReplayOrTamper {
            kind: "result_digest"
        })
    );
    let mut tampered_scope = evidence;
    tampered_scope.scope_digest = Digest::from_text("tampered-scope");
    assert_eq!(
        tampered_scope.validate(),
        Err(ContentfulResultError::ReplayOrTamper {
            kind: "scope_digest"
        })
    );

    let revocation = service.revoke_at(now()).expect("revocation");
    assert!(!revocation.native_connected_claim);
    assert_eq!(
        service.registration().state,
        hartevo_contentful_entry_result_plugin::RegistrationState::Revoked
    );
    assert_eq!(
        service
            .read_entry(&request)
            .expect_err("revoked registration"),
        ContentfulResultError::RegistrationRevoked
    );
}

#[test]
fn secret_reference_is_opaque_and_scope_digests_are_present_in_receipts() {
    let service = fixture_service();
    let registration = service.registration();
    assert_eq!(registration.contract_digest, contract_digest());
    assert_eq!(registration.scope_digest, scope().digest());
    assert_ne!(
        registration.secret_reference_digest,
        Digest::from_text("raw-token")
    );
    let debug = format!("{registration:?}");
    assert!(!debug.contains("raw-token"));
}
