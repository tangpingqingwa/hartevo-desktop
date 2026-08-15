use std::collections::BTreeMap;

use hartevo_aws_entity_resolution_result_plugin::{
    AwsAccountId, AwsEntityResolutionProvider, AwsEntityResolutionResultService,
    AwsEntityResolutionScope, AwsEntityResolutionTransportError, AwsRegion, BlockedEnvTransport,
    Digest, FixtureTransport, GetMatchIdRequest, GetMatchIdResponse, ListIdNamespacesRequest,
    ListIdNamespacesResponse, LoopbackTransport, MatchStatus, PermissionSnapshot,
    RecordingTransport, ResourceIdentity, ResourceName, SchemaAttributeMetadata,
    SchemaAttributeType, SchemaMappingMetadata, SecretReference, SourceRecordFingerprint,
    TransportProvenance,
};
use proptest::prelude::*;

const RAW_NAME: &str = "Ada Lovelace";
const RAW_EMAIL: &str = "ada@example.test";
const RAW_PHONE: &str = "+1 555 0100";
const RAW_SECRET: &str = "opaque-sigv4-handle-never-serialized";

fn scope() -> AwsEntityResolutionScope {
    let mut record = BTreeMap::new();
    record.insert("name".to_owned(), RAW_NAME.to_owned());
    record.insert("email".to_owned(), RAW_EMAIL.to_owned());
    record.insert("phone".to_owned(), RAW_PHONE.to_owned());
    let fingerprint = SourceRecordFingerprint::from_record(&record, true).expect("fingerprint");
    AwsEntityResolutionScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        ResourceIdentity::new(
            ResourceName::new("customer-schema").expect("schema name"),
            Some("arn:aws:entityresolution:us-east-1:123456789012:schemamapping/customer-schema"),
        )
        .expect("schema"),
        ResourceIdentity::new(
            ResourceName::new("customer-namespace").expect("namespace name"),
            Some("arn:aws:entityresolution:us-east-1:123456789012:idnamespace/customer-namespace"),
        )
        .expect("namespace"),
        ResourceIdentity::new(
            ResourceName::new("customer-workflow").expect("workflow name"),
            Some("arn:aws:entityresolution:us-east-1:123456789012:matchingworkflow/customer-workflow"),
        )
        .expect("workflow"),
        fingerprint,
        hartevo_aws_entity_resolution_result_plugin::ProjectScope::new("project-810", 2)
            .expect("project"),
        hartevo_aws_entity_resolution_result_plugin::MissionScope::new("mission-810", 4)
            .expect("mission"),
        hartevo_aws_entity_resolution_result_plugin::WorkProductScope::new("work-product-810", 1)
            .expect("work product"),
    )
    .expect("scope")
}

fn secret(scope: &AwsEntityResolutionScope) -> SecretReference {
    SecretReference::sigv4(RAW_SECRET, scope, 1).expect("secret reference")
}

fn fixture_service() -> AwsEntityResolutionResultService<FixtureTransport> {
    let scope = scope();
    let provider = AwsEntityResolutionProvider::new(
        FixtureTransport::for_scope(&scope).expect("fixture transport"),
    )
    .expect("provider");
    AwsEntityResolutionResultService::new(scope.clone(), secret(&scope), provider, 1)
        .expect("service")
}

#[test]
fn fixture_match_is_a_redacted_review_only_proposal() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");
    assert_eq!(proposal.status, MatchStatus::Matched);
    assert_eq!(proposal.provenance, TransportProvenance::Fixture);
    assert!(proposal.namespace_complete);
    assert!(proposal.namespace_metadata.is_some());
    assert!(proposal.workflow_metadata.is_some());
    assert!(proposal.schema_metadata.is_some());
    assert!(proposal.evidence.match_group_digest.is_some());
    assert!(proposal.evidence.match_rule_digest.is_some());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.identity_certainty);
    assert!(!proposal.identity_map_retained);
    assert!(!proposal.s3_output_retained);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.is_review_only());
    assert!(service.verify(&proposal).review_eligible);

    let json = serde_json::to_string(&proposal).expect("proposal JSON");
    let debug = format!("{proposal:?}");
    for raw in [RAW_NAME, RAW_EMAIL, RAW_PHONE, RAW_SECRET] {
        assert!(!json.contains(raw), "raw value leaked in JSON: {raw}");
        assert!(!debug.contains(raw), "raw value leaked in Debug: {raw}");
    }
    assert!(!json.contains("matchId"));
    assert!(json.contains("matchGroupDigest"));
    assert!(json.contains("matchRuleDigest"));

    let mut consumer = service.consumer().expect("consumer");
    let mission_result = consumer.consume(&proposal).expect("mission result");
    assert_eq!(mission_result.status, MatchStatus::Matched);
    assert!(!mission_result.can_be_adopted());
    let first = consumer.record(&proposal, "recording-key").expect("record");
    let replay = consumer.record(&proposal, "recording-key").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert!(first.validate_integrity().is_ok());
}

#[test]
fn source_record_fingerprint_normalizes_without_retaining_values() {
    let mut first = BTreeMap::new();
    first.insert("Email".to_owned(), " Ada   Example@TEST ".to_owned());
    first.insert("Phone".to_owned(), " +1 555 0100 ".to_owned());
    let mut second = BTreeMap::new();
    second.insert("email".to_owned(), "ada example@test".to_owned());
    second.insert("phone".to_owned(), "+1 555 0100".to_owned());
    let first_fingerprint = SourceRecordFingerprint::from_record(&first, true).expect("first");
    let second_fingerprint = SourceRecordFingerprint::from_record(&second, true).expect("second");
    assert_eq!(
        first_fingerprint.fingerprint_digest(),
        second_fingerprint.fingerprint_digest()
    );
    let unnormalized = SourceRecordFingerprint::from_record(&first, false).expect("raw mode");
    assert_ne!(
        first_fingerprint.fingerprint_digest(),
        unnormalized.fingerprint_digest()
    );
    let json = serde_json::to_string(&first_fingerprint).expect("fingerprint JSON");
    let debug = format!("{first_fingerprint:?}");
    for raw in ["Ada", "Example", "555"] {
        assert!(!json.contains(raw));
        assert!(!debug.contains(raw));
    }
}

#[test]
fn fixture_loopback_and_blocked_env_never_claim_connected_or_native() {
    let scope = scope();
    let mut loopback = AwsEntityResolutionResultService::new(
        scope.clone(),
        secret(&scope),
        AwsEntityResolutionProvider::new(LoopbackTransport::for_scope(&scope).expect("loopback"))
            .expect("provider"),
        1,
    )
    .expect("service");
    let loopback_proposal = loopback
        .propose(loopback.default_request().expect("request"))
        .expect("loopback proposal");
    assert_eq!(loopback_proposal.provenance, TransportProvenance::Loopback);
    assert!(!loopback_proposal.connected);
    assert!(!loopback_proposal.native);
    assert!(!loopback_proposal.first_party);

    let mut blocked = AwsEntityResolutionResultService::new(
        scope.clone(),
        secret(&scope),
        AwsEntityResolutionProvider::new(BlockedEnvTransport).expect("provider"),
        1,
    )
    .expect("service");
    let blocked_proposal = blocked
        .propose(blocked.default_request().expect("request"))
        .expect("blocked proposal");
    assert_eq!(blocked_proposal.status, MatchStatus::ProviderUnknown);
    assert_eq!(blocked_proposal.provenance, TransportProvenance::BlockedEnv);
    assert_eq!(
        blocked_proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!blocked_proposal.connected);
    assert!(!blocked_proposal.native);
    assert!(blocked.verify(&blocked_proposal).valid);
}

#[test]
fn access_loss_and_tampered_responses_fail_closed() {
    let scope = scope();
    let list_request = ListIdNamespacesRequest::new(&scope, 25, 1, None).expect("list request");
    let mut access_loss = RecordingTransport::default();
    access_loss.push_list_response(Err(AwsEntityResolutionTransportError::Forbidden));
    let mut service = AwsEntityResolutionResultService::new(
        scope.clone(),
        secret(&scope),
        AwsEntityResolutionProvider::new(access_loss).expect("provider"),
        1,
    )
    .expect("service");
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("access-loss proposal");
    assert_eq!(proposal.status, MatchStatus::AccessLost);
    assert!(!service.verify(&proposal).review_eligible);

    let mut tampered = RecordingTransport::default();
    let response = ListIdNamespacesResponse::new(
        &list_request,
        Vec::new(),
        None,
        128,
        TransportProvenance::Recording,
    )
    .expect("response")
    .with_declared_digest(Digest::from_text("tampered"));
    tampered.push_list_response(Ok(response));
    let mut service = AwsEntityResolutionResultService::new(
        scope.clone(),
        secret(&scope),
        AwsEntityResolutionProvider::new(tampered).expect("provider"),
        1,
    )
    .expect("service");
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("tampered proposal");
    assert_eq!(proposal.status, MatchStatus::Tampered);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn registration_reversal_and_scope_replay_fences_are_reversible() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");
    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    let registration_debug = format!("{:?}", service.registration());
    assert!(registration_json.contains("secretReferenceDigest"));
    assert!(!registration_json.contains(RAW_SECRET));
    assert!(!registration_debug.contains(RAW_SECRET));

    service.revoke().expect("revoke");
    assert!(
        service
            .propose(service.default_request().expect("request"))
            .is_err()
    );
    service.restore_registration().expect("restore");
    let restored = service
        .propose(service.default_request().expect("request"))
        .expect("restored proposal");
    assert_eq!(restored.status, MatchStatus::Matched);
    service.reverse().expect("reverse");
    assert!(service.restore_registration().is_err());

    let mut consumer = AwsEntityResolutionResultService::new(
        scope(),
        secret(&scope()),
        AwsEntityResolutionProvider::new(FixtureTransport::for_scope(&scope()).expect("fixture"))
            .expect("provider"),
        1,
    )
    .expect("service")
    .consumer()
    .expect("consumer");
    let mut tampered_proposal = proposal.clone();
    tampered_proposal.proposal_digest = Digest::from_text("tampered-proposal");
    assert!(consumer.record(&tampered_proposal, "same-key").is_err());
}

#[test]
fn provider_permissions_metadata_and_response_bounds_are_explicit() {
    let permissions = PermissionSnapshot::for_layer_one(1).expect("permissions");
    assert_eq!(permissions.permissions.len(), 6);
    assert!(
        PermissionSnapshot::new(
            vec!["entityresolution:CreateMatchingWorkflow".to_owned()],
            1
        )
        .is_err()
    );
    assert!(
        SchemaAttributeMetadata::from_field(
            "record_key",
            SchemaAttributeType::UniqueId,
            true,
            true
        )
        .is_ok()
    );
    assert!(
        SchemaMappingMetadata::new("schema", None::<&str>, &[], false, false, None, None).is_err()
    );
    let provider = AwsEntityResolutionProvider::new(BlockedEnvTransport).expect("provider");
    assert!(provider.definition().validate().is_ok());
    assert!(!provider.definition().connected_evidence);
    assert!(!provider.definition().native_evidence);
}

#[test]
fn response_types_only_expose_redacted_match_digests() {
    let scope = scope();
    let request = GetMatchIdRequest::for_scope(&scope, true).expect("request");
    let response = GetMatchIdResponse::matched(
        &request,
        "raw-match-id-should-not-survive",
        "raw-rule-name-should-not-survive",
        TransportProvenance::Fixture,
    )
    .expect("response");
    let json = serde_json::to_string(&response).expect("response JSON");
    let debug = format!("{response:?}");
    assert!(json.contains("matchGroupDigest"));
    assert!(json.contains("matchRuleDigest"));
    assert!(!json.contains("raw-match-id"));
    assert!(!json.contains("raw-rule-name"));
    assert!(!debug.contains("raw-match-id"));
    assert!(!debug.contains("raw-rule-name"));
    response.validate_integrity(&request).expect("integrity");
}

proptest! {
    #[test]
    fn normalized_fingerprints_are_deterministic(
        value in "[A-Za-z]{1,24}( [A-Za-z]{1,24})?"
    ) {
        let mut first = BTreeMap::new();
        first.insert("field".to_owned(), value.clone());
        let mut second = BTreeMap::new();
        second.insert("field".to_owned(), format!("  {}  ", value.to_lowercase()));
        let left = SourceRecordFingerprint::from_record(&first, true).expect("left");
        let right = SourceRecordFingerprint::from_record(&second, true).expect("right");
        prop_assert_eq!(left.fingerprint_digest(), right.fingerprint_digest());
    }
}
