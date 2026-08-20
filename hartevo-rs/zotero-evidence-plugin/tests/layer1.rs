use hartevo_zotero_evidence_plugin::{
    ClaimId, FixtureZoteroProvider, MissionClaimResultBinding, MissionId,
    MissionResearchEvidenceConsumer, MissionResearchEvidenceRequest, NativeStatus,
    ReadOnlyAuthority, RecordingZoteroProvider, ResultId, SecretReference, ZoteroAccessLoss,
    ZoteroApiTransport, ZoteroAuthenticationMode, ZoteroBackoff, ZoteroCapabilityProbeRequest,
    ZoteroCitationFormat, ZoteroCitationLocale, ZoteroCitationRequest, ZoteroCitationStyle,
    ZoteroCollectionKey, ZoteroConditionalRequest, ZoteroEvidenceError, ZoteroEvidenceProvider,
    ZoteroEvidenceScope, ZoteroGroupId, ZoteroItemEvidence, ZoteroLibraryId, ZoteroObjectIdentity,
    ZoteroObjectLifecycle, ZoteroOfficialLocalApiV3Transport, ZoteroPage,
    ZoteroPreconditionFailure, ZoteroPreconditionKind, ZoteroProviderCall, ZoteroProviderError,
    ZoteroProviderManifest, ZoteroReadRequest, ZoteroReadResponse, ZoteroReadStatus,
    ZoteroReadTarget, ZoteroSinceCursor, ZoteroTransportKind, ZoteroTransportOperation,
    ZoteroUserId, ZoteroVersion, ZoteroWebApiV3Transport, canonical_digest,
};
use serde_json::Value;

fn item_scope(mission: &str) -> ZoteroEvidenceScope {
    ZoteroEvidenceScope::item(
        ZoteroLibraryId::user(ZoteroUserId::new(42).expect("user ID")),
        Some(ZoteroCollectionKey::new("COLLECTION1").expect("collection key")),
        hartevo_zotero_evidence_plugin::ZoteroItemKey::new("ITEM0001").expect("item key"),
        MissionId::new(mission).expect("mission ID"),
    )
    .expect("item scope")
}

fn read_request(scope: &ZoteroEvidenceScope) -> ZoteroReadRequest {
    ZoteroReadRequest::new(
        scope.clone(),
        ZoteroReadTarget::Item {
            item_key: scope.item_key.clone().expect("item scope"),
        },
        ZoteroPage::first(),
        None,
        None,
    )
    .expect("read request")
}

fn citation_request(scope: &ZoteroEvidenceScope, style: &str) -> ZoteroCitationRequest {
    ZoteroCitationRequest::new(
        scope.clone(),
        ZoteroCitationStyle::new(style).expect("style"),
        ZoteroCitationLocale::new("en-US").expect("locale"),
        ZoteroCitationFormat::Citation,
    )
    .expect("citation request")
}

fn binding(scope: &ZoteroEvidenceScope) -> MissionClaimResultBinding {
    MissionClaimResultBinding::new(
        scope.mission_id.clone(),
        ClaimId::new("claim-1").expect("claim ID"),
        3,
        ResultId::new("result-1").expect("result ID"),
        7,
    )
    .expect("binding")
}

fn fixture_consumer(
    scope: &ZoteroEvidenceScope,
) -> (
    MissionResearchEvidenceConsumer<FixtureZoteroProvider>,
    FixtureZoteroProvider,
) {
    let provider = FixtureZoteroProvider::fixture(scope.clone()).expect("fixture provider");
    let handle = provider.clone();
    let service =
        hartevo_zotero_evidence_plugin::ZoteroEvidenceService::new(provider).expect("service");
    (MissionResearchEvidenceConsumer::new(service), handle)
}

#[test]
fn contract_and_authority_are_layer_one_honest() {
    let contract: Value =
        serde_json::from_str(hartevo_zotero_evidence_plugin::ZOTERO_EVIDENCE_CONTRACT_JSON)
            .expect("contract JSON");
    assert_eq!(contract["contractVersion"], "EXT-ZOTERO-01-L1/v1");
    assert_eq!(contract["api"]["web"]["version"], 3);
    assert_eq!(
        contract["api"]["local"]["provenance"],
        "official_local_api_v3"
    );
    assert_eq!(
        contract["responses"]["success"],
        serde_json::json!([200, 304])
    );
    assert_eq!(
        contract["responses"]["typedErrors"],
        serde_json::json!([403, 404, 409, 412, 428, 429])
    );
    assert_eq!(contract["native"]["status"], "BLOCKED_ENV");
    assert!(!ReadOnlyAuthority::external_write());
    assert!(!ReadOnlyAuthority::connected());
    assert!(!ReadOnlyAuthority::native());
}

#[test]
fn mission_consumer_binds_exact_versions_and_digest_only_proposal() {
    let scope = item_scope("mission-1");
    let (consumer, provider) = fixture_consumer(&scope);
    let probe = consumer
        .probe(&ZoteroCapabilityProbeRequest::new(scope.clone()).expect("probe request"))
        .expect("probe");
    assert_eq!(probe.native_status, NativeStatus::BlockedEnv);
    assert_eq!(
        probe.provenance,
        hartevo_zotero_evidence_plugin::ZoteroProvenance::Fixture
    );

    let read = consumer.read(&read_request(&scope)).expect("read");
    assert_eq!(read.status, ZoteroReadStatus::Ok200);
    assert_eq!(read.library_version, Some(ZoteroVersion::new(17)));
    assert_eq!(read.last_modified_version, Some(ZoteroVersion::new(11)));
    assert_eq!(
        read.since_cursor.as_ref().expect("cursor").version,
        ZoteroVersion::new(17)
    );

    let citation = consumer
        .citation(&citation_request(&scope, "apa"))
        .expect("citation");
    assert!(citation.formatted_only);
    let mission_request = MissionResearchEvidenceRequest::new(
        binding(&scope),
        scope.clone(),
        ZoteroCitationStyle::new("apa").expect("style"),
        ZoteroCitationLocale::new("en-US").expect("locale"),
    )
    .expect("mission request");
    let proposal = consumer
        .propose_research_evidence(&mission_request, &read, &citation)
        .expect("proposal");
    proposal.validate().expect("proposal digest");
    assert_eq!(proposal.library_version, ZoteroVersion::new(17));
    assert_eq!(proposal.item_version, ZoteroVersion::new(11));
    assert_eq!(proposal.last_modified_version, ZoteroVersion::new(11));
    assert!(!proposal.can_claim_verified_source());
    assert_eq!(
        proposal.disposition,
        hartevo_zotero_evidence_plugin::ZoteroEvidenceDisposition::ProposalOnly
    );
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized.contains("Lovelace, Ada"));
    assert!(!serialized.contains("A bounded research source"));
    assert!(
        provider
            .calls()
            .iter()
            .any(|call| matches!(call, ZoteroProviderCall::Read { .. }))
    );
}

#[test]
fn web_and_local_plans_are_distinct_and_conditional() {
    let scope = item_scope("mission-plan");
    let cursor = ZoteroSinceCursor::new(
        scope.library.clone(),
        ZoteroVersion::new(17),
        &scope,
        hartevo_zotero_evidence_plugin::ZoteroProvenance::WebApiV3,
    )
    .expect("cursor");
    let conditional =
        ZoteroConditionalRequest::new(ZoteroVersion::new(17), &scope).expect("conditional");
    let request = ZoteroReadRequest::new(
        scope.clone(),
        ZoteroReadTarget::Item {
            item_key: scope.item_key.clone().expect("item key"),
        },
        ZoteroPage::first(),
        Some(cursor),
        Some(conditional),
    )
    .expect("read request");
    let operation = ZoteroTransportOperation::Read(request);
    let web = ZoteroWebApiV3Transport
        .plan(&operation, ZoteroAuthenticationMode::SecretReference)
        .expect("Web plan");
    let local = ZoteroOfficialLocalApiV3Transport
        .plan(
            &operation,
            ZoteroAuthenticationMode::LocalReadNoAuthentication,
        )
        .expect("local plan");
    assert_eq!(web.transport, ZoteroTransportKind::WebApiV3);
    assert_eq!(local.transport, ZoteroTransportKind::OfficialLocalApiV3);
    assert!(web.endpoint.starts_with("https://api.zotero.org/users/42"));
    assert!(
        local
            .endpoint
            .starts_with("http://localhost:23119/api/users/42")
    );
    assert_eq!(web.headers["If-Modified-Since-Version"], "17");
    assert_eq!(web.query["since"], "17");
    assert!(web.secret_reference_required);
    assert!(!local.secret_reference_required);
    assert!(
        !web.headers
            .values()
            .any(|value| value.contains("raw-secret"))
    );
}

#[test]
fn conditional_304_is_explicitly_not_source_evidence() {
    let scope = item_scope("mission-304");
    let (consumer, _) = fixture_consumer(&scope);
    let conditional =
        ZoteroConditionalRequest::new(ZoteroVersion::new(17), &scope).expect("conditional");
    let request = ZoteroReadRequest::new(
        scope.clone(),
        ZoteroReadTarget::Item {
            item_key: scope.item_key.clone().expect("item key"),
        },
        ZoteroPage::first(),
        None,
        Some(conditional),
    )
    .expect("read request");
    let read = consumer.read(&request).expect("304");
    assert_eq!(read.status, ZoteroReadStatus::NotModified304);
    assert!(!read.is_source_evidence());
    let citation = consumer
        .citation(&citation_request(&scope, "apa"))
        .expect("citation");
    let mission_request = MissionResearchEvidenceRequest::new(
        binding(&scope),
        scope,
        ZoteroCitationStyle::new("apa").expect("style"),
        ZoteroCitationLocale::new("en-US").expect("locale"),
    )
    .expect("mission request");
    let error = consumer
        .propose_research_evidence(&mission_request, &read, &citation)
        .expect_err("304 cannot verify source evidence");
    assert_eq!(error, ZoteroEvidenceError::NotModifiedIsNotEvidence);
}

#[test]
fn private_access_requires_opaque_secret_reference_and_stays_redacted() {
    let scope = item_scope("mission-private");
    let manifest = ZoteroProviderManifest::private_layer1(scope.clone()).expect("manifest");
    let missing = RecordingZoteroProvider::new(manifest.clone());
    let service =
        hartevo_zotero_evidence_plugin::ZoteroEvidenceService::new(missing).expect("service");
    let error = service
        .probe(&ZoteroCapabilityProbeRequest::new(scope.clone()).expect("probe"))
        .expect_err("private probe requires reference");
    assert_eq!(
        error,
        ZoteroEvidenceError::Provider(ZoteroProviderError::SecretReferenceRequired)
    );

    let secret = SecretReference::new("raw-secret-must-not-escape").expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("raw-secret-must-not-escape"));
    let provider = RecordingZoteroProvider::new(manifest).with_secret_reference(secret);
    let service = hartevo_zotero_evidence_plugin::ZoteroEvidenceService::new(provider)
        .expect("private service");
    let probe = service
        .probe(&ZoteroCapabilityProbeRequest::new(scope).expect("probe"))
        .expect("private probe");
    assert_eq!(
        probe.authentication,
        ZoteroAuthenticationMode::SecretReference
    );
}

#[test]
fn cursor_regression_and_tamper_fail_closed() {
    let scope = item_scope("mission-adversarial");
    let provider = RecordingZoteroProvider::fixture(scope.clone()).expect("fixture");
    let cursor = ZoteroSinceCursor::new(
        scope.library.clone(),
        ZoteroVersion::new(18),
        &scope,
        hartevo_zotero_evidence_plugin::ZoteroProvenance::Fixture,
    )
    .expect("cursor");
    let request = ZoteroReadRequest::new(
        scope.clone(),
        ZoteroReadTarget::Item {
            item_key: scope.item_key.clone().expect("item key"),
        },
        ZoteroPage::first(),
        Some(cursor),
        None,
    )
    .expect("request");
    let service = hartevo_zotero_evidence_plugin::ZoteroEvidenceService::new(provider.clone())
        .expect("service");
    let error = service.read(&request).expect_err("cursor regression");
    assert!(matches!(error, ZoteroEvidenceError::CursorRegressed { .. }));

    let clean = provider.read(&read_request(&scope)).expect("recorded read");
    let mut tampered = clean;
    tampered.evidence_digest = canonical_digest("tampered");
    provider.set_read_response(Ok(tampered));
    let error = service
        .read(&read_request(&scope))
        .expect_err("tampered read");
    assert_eq!(error, ZoteroEvidenceError::InvalidProviderResponse);
}

#[test]
fn all_required_http_statuses_are_typed_without_response_bodies() {
    assert_eq!(
        ZoteroProviderError::from_status(403).status_code(),
        Some(403)
    );
    assert_eq!(
        ZoteroProviderError::from_status(404).status_code(),
        Some(404)
    );
    assert_eq!(
        ZoteroProviderError::from_status(409).status_code(),
        Some(409)
    );
    assert_eq!(
        ZoteroProviderError::from_status(412).status_code(),
        Some(412)
    );
    assert_eq!(
        ZoteroProviderError::from_status(428).status_code(),
        Some(428)
    );
    assert_eq!(
        ZoteroProviderError::from_status(429).status_code(),
        Some(429)
    );
    let errors = [
        ZoteroProviderError::Forbidden403 {
            access: ZoteroAccessLoss::ScopeRevoked,
        },
        ZoteroProviderError::NotFound404 {
            object: ZoteroObjectIdentity::Unknown,
            deleted: true,
        },
        ZoteroProviderError::Conflict409 {
            reason: hartevo_zotero_evidence_plugin::ZoteroConflictReason::AmbiguousObject,
        },
        ZoteroProviderError::PreconditionFailed412 {
            expected: Some(ZoteroVersion::new(4)),
            actual: Some(ZoteroVersion::new(5)),
            reason: ZoteroPreconditionFailure::VersionDrift,
        },
        ZoteroProviderError::PreconditionRequired428 {
            required: ZoteroPreconditionKind::IfUnmodifiedSinceVersion,
        },
        ZoteroProviderError::RateLimited429 {
            retry_after_seconds: Some(3),
            backoff_seconds: Some(5),
        },
    ];
    assert!(errors.iter().all(|error| error.status_code().is_some()));
    assert!(!format!("{:?}", errors[0]).contains("raw-secret"));
}

#[test]
fn fixture_recording_and_loopback_are_never_connected_or_native() {
    let scope = item_scope("mission-provenance");
    let providers = [
        FixtureZoteroProvider::fixture(scope.clone()).expect("fixture"),
        RecordingZoteroProvider::recording(scope.clone()).expect("recording"),
        RecordingZoteroProvider::loopback(scope.clone()).expect("loopback"),
    ];
    for provider in providers {
        let manifest = provider.current_manifest();
        assert_eq!(manifest.native_status, NativeStatus::BlockedEnv);
        assert!(!ReadOnlyAuthority::connected());
        assert!(!provider.external_write_available());
    }
}

#[test]
fn registration_is_versioned_scope_bound_and_reversible() {
    let scope = item_scope("mission-registration");
    let manifest = ZoteroProviderManifest::layer1(scope.clone()).expect("manifest");
    manifest.validate().expect("manifest validates");
    let registration = &manifest.registration;
    registration
        .validate(&scope)
        .expect("registration validates");
    assert!(registration.reversible);
    assert!(registration.enabled);
    let revoked = manifest.revoked().expect("revoke");
    assert!(!revoked.registration.enabled);
    assert_ne!(revoked.manifest_digest, manifest.manifest_digest);
    assert!(revoked.validate().is_err());
    let reactivated = revoked.reactivated().expect("reactivate");
    assert!(reactivated.registration.enabled);
    reactivated.validate().expect("reactivated manifest");
}

#[test]
fn deletion_and_access_loss_are_not_cache_hits() {
    let scope = item_scope("mission-deletion");
    let provider = RecordingZoteroProvider::fixture(scope.clone()).expect("fixture");
    let manifest = provider.current_manifest();
    let request = read_request(&scope);
    let clean = provider.read(&request).expect("clean read");
    let mut deleted_item: ZoteroItemEvidence = clean.items[0].clone();
    deleted_item.lifecycle = ZoteroObjectLifecycle::Deleted;
    deleted_item.item_digest = deleted_item.calculate_digest();
    let deleted_response = ZoteroReadResponse::new_200(
        &request,
        &manifest,
        ZoteroVersion::new(17),
        ZoteroVersion::new(11),
        vec![deleted_item],
        None,
    )
    .expect("deleted response");
    provider.set_read_response(Ok(deleted_response));
    let service =
        hartevo_zotero_evidence_plugin::ZoteroEvidenceService::new(provider).expect("service");
    let read = service.read(&request).expect("typed deleted observation");
    assert_eq!(
        read.exact_item().expect_err("deleted item").to_string(),
        ZoteroEvidenceError::DeletedOrAccessLost.to_string()
    );

    let access_provider = RecordingZoteroProvider::fixture(scope.clone())
        .expect("fixture")
        .with_fault(ZoteroProviderError::Forbidden403 {
            access: ZoteroAccessLoss::ScopeRevoked,
        });
    let access_service =
        hartevo_zotero_evidence_plugin::ZoteroEvidenceService::new(access_provider)
            .expect("service");
    let error = access_service.read(&request).expect_err("access loss");
    assert_eq!(
        error,
        ZoteroEvidenceError::Provider(ZoteroProviderError::Forbidden403 {
            access: ZoteroAccessLoss::ScopeRevoked,
        })
    );
}

#[test]
fn citation_style_and_locale_drift_cannot_enter_a_proposal() {
    let scope = item_scope("mission-citation-drift");
    let provider = RecordingZoteroProvider::fixture(scope.clone()).expect("fixture");
    let service = hartevo_zotero_evidence_plugin::ZoteroEvidenceService::new(provider.clone())
        .expect("service");
    let read = service.read(&read_request(&scope)).expect("read");
    let expected_request = citation_request(&scope, "apa");
    let drifted_request = citation_request(&scope, "chicago");
    let drifted = provider
        .citation(&drifted_request)
        .expect("drifted citation");
    provider.set_citation_response(Ok(drifted));
    let citation = service
        .citation(&expected_request)
        .expect("typed citation response");
    let mission_request = MissionResearchEvidenceRequest::new(
        binding(&scope),
        scope.clone(),
        ZoteroCitationStyle::new("apa").expect("style"),
        ZoteroCitationLocale::new("en-US").expect("locale"),
    )
    .expect("mission request");
    let error = service
        .propose_research_evidence(&mission_request, &read, &citation)
        .expect_err("style drift");
    assert_eq!(error, ZoteroEvidenceError::CitationPresentationMismatch);

    let provider = RecordingZoteroProvider::fixture(scope.clone()).expect("fixture");
    let service = hartevo_zotero_evidence_plugin::ZoteroEvidenceService::new(provider.clone())
        .expect("service");
    let read = service.read(&read_request(&scope)).expect("read");
    let expected_request = citation_request(&scope, "apa");
    let mut locale_request = expected_request.clone();
    locale_request.locale = ZoteroCitationLocale::new("fr-FR").expect("locale");
    let drifted = provider.citation(&locale_request).expect("drifted locale");
    provider.set_citation_response(Ok(drifted));
    let citation = service
        .citation(&expected_request)
        .expect("typed citation response");
    let mission_request = MissionResearchEvidenceRequest::new(
        binding(&scope),
        scope,
        ZoteroCitationStyle::new("apa").expect("style"),
        ZoteroCitationLocale::new("en-US").expect("locale"),
    )
    .expect("mission request");
    let error = service
        .propose_research_evidence(&mission_request, &read, &citation)
        .expect_err("locale drift");
    assert_eq!(error, ZoteroEvidenceError::CitationPresentationMismatch);
}

#[test]
fn group_library_scope_and_backoff_are_typed() {
    let group_scope = ZoteroEvidenceScope::library(
        ZoteroLibraryId::group(ZoteroGroupId::new(7).expect("group ID")),
        MissionId::new("mission-group").expect("mission ID"),
    )
    .expect("group scope");
    assert_eq!(group_scope.library.user_id(), None);
    assert_eq!(group_scope.library.group_id().expect("group").get(), 7);
    let manifest = ZoteroProviderManifest::local_layer1(group_scope).expect("local manifest");
    assert_eq!(manifest.transport, ZoteroTransportKind::OfficialLocalApiV3);
    assert_eq!(
        manifest.authentication,
        ZoteroAuthenticationMode::LocalReadNoAuthentication
    );
    assert_eq!(ZoteroBackoff::new(5).expect("backoff").seconds, 5);
    assert!(ZoteroBackoff::new(0).is_err());
}
