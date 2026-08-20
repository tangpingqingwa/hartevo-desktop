use std::collections::BTreeSet;

use hartevo_notion_result_plugin::{
    FakeNotionProvider, MissionId, MissionNotionResultConsumer, MissionWorkProduct, NativeStatus,
    NotionCapability, NotionDataSourceId, NotionDescribeRequest, NotionPageId, NotionProviderError,
    NotionPublishDestination, NotionPublishOperation, NotionReadRequest, NotionReadbackField,
    NotionResultError, NotionResultProvider, NotionResultService, NotionScope, ProjectId,
    ReadOnlyAuthority, RecordingNotionProvider, SecretReference, TenantId, WorkProductId,
    canonical_digest,
};
use serde_json::Value;

fn capabilities() -> BTreeSet<NotionCapability> {
    BTreeSet::from([
        NotionCapability::ReadContent,
        NotionCapability::InsertContent,
        NotionCapability::UpdateContent,
    ])
}

fn page_scope() -> NotionScope {
    NotionScope::page(
        NotionPageId::new("parent-page").expect("page ID"),
        "consent-page",
        capabilities(),
    )
    .expect("page scope")
}

fn data_source_scope() -> NotionScope {
    NotionScope::data_source(
        NotionDataSourceId::new("source-1").expect("data source ID"),
        "consent-source",
        capabilities(),
    )
    .expect("data source scope")
}

fn work_product(revision: u64) -> MissionWorkProduct {
    MissionWorkProduct::new(
        TenantId::new("tenant-1").expect("tenant ID"),
        ProjectId::new("project-1").expect("project ID"),
        MissionId::new("mission-1").expect("mission ID"),
        WorkProductId::new("work-product-1").expect("work product ID"),
        revision,
        canonical_digest(&format!("artifact-{revision}")),
        canonical_digest(&format!("manifest-{revision}")),
        "Mission result",
        "A deterministic Notion result body.",
    )
    .expect("work product")
}

fn consumer(
    scope: &NotionScope,
) -> (
    MissionNotionResultConsumer<FakeNotionProvider>,
    FakeNotionProvider,
) {
    let manifest = hartevo_notion_result_plugin::NotionProviderManifest::layer1(scope.clone())
        .expect("manifest");
    let provider = FakeNotionProvider::new(manifest);
    let handle = provider.clone();
    let service = NotionResultService::new(provider).expect("service");
    (MissionNotionResultConsumer::new(service), handle)
}

#[test]
fn standalone_contract_is_typed_and_honest_about_native_gap() {
    let contract: Value =
        serde_json::from_str(hartevo_notion_result_plugin::NOTION_RESULT_CONTRACT_JSON)
            .expect("contract JSON");
    assert_eq!(contract["contractVersion"], "EXT-NOTION-01-L1/v1");
    assert_eq!(contract["api"]["version"], "2026-03-11");
    assert_eq!(contract["api"]["databaseAndDataSourceDistinct"], true);
    assert_eq!(
        contract["errors"]["typedHttpStatuses"],
        serde_json::json!([403, 404, 409, 429])
    );
    assert_eq!(contract["native"]["write"], "BLOCKED_ENV");
    assert!(!ReadOnlyAuthority::external_write());
    assert!(!ReadOnlyAuthority::store());
    assert!(!ReadOnlyAuthority::keyring());
    assert!(!ReadOnlyAuthority::browser_profile());
    assert!(!ReadOnlyAuthority::effect());
}

#[test]
fn mission_consumer_compiles_deterministic_scope_bound_proposal_and_records_only() {
    let scope = page_scope();
    let (consumer, provider) = consumer(&scope);
    let destination =
        NotionPublishDestination::new(scope.clone(), NotionPublishOperation::CreatePage, None)
            .expect("destination");
    let proposal = consumer
        .compile_publish_proposal(work_product(3), destination.clone())
        .expect("proposal");
    let proposal_again = consumer
        .compile_publish_proposal(work_product(3), destination)
        .expect("same proposal");
    assert_eq!(proposal.idempotency_key, proposal_again.idempotency_key);
    assert_eq!(proposal.proposal_digest, proposal_again.proposal_digest);
    assert_eq!(proposal.work_product.mission_id.as_str(), "mission-1");
    assert_eq!(proposal.work_product.work_product_revision, 3);
    assert_eq!(
        proposal.effect,
        hartevo_notion_result_plugin::NotionProposalEffect::ProposalOnly
    );
    assert_eq!(proposal.native_status, NativeStatus::BlockedEnv);
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized.contains("access-token"));

    let receipt = consumer
        .record_publish_proposal(&proposal)
        .expect("recorded receipt");
    assert_eq!(
        receipt.evidence,
        hartevo_notion_result_plugin::NotionEvidenceSource::Recording
    );
    assert_eq!(receipt.native_status, NativeStatus::BlockedEnv);
    assert!(
        !serde_json::to_string(&receipt)
            .expect("receipt JSON")
            .contains("A deterministic Notion result body")
    );
    let read_request = NotionReadRequest::new(
        receipt.page_id.clone(),
        scope.clone(),
        hartevo_notion_result_plugin::NotionPaginationTemplate::layer1(),
        None,
    )
    .expect("read request");
    let readback = consumer.read(&read_request).expect("recorded read-back");
    let verified = consumer
        .consume_readback(&proposal, &receipt, &readback)
        .expect("verified read-back");
    assert!(verified.verified);
    assert_eq!(verified.page_id, receipt.page_id);
    assert!(verified.page_url.as_str().starts_with("https://"));
    assert_eq!(verified.revision, receipt.revision);
    assert_eq!(verified.content_fingerprint, proposal.content_fingerprint);

    let calls = provider.calls();
    assert_eq!(calls.len(), 2);
    assert!(
        calls
            .iter()
            .all(|call| !format!("{call:?}").contains("A deterministic"))
    );
    assert!(calls.iter().any(|call| matches!(
        call,
        hartevo_notion_result_plugin::NotionProviderCall::RecordProposal { .. }
    )));
}

#[test]
fn data_source_parent_requires_explicit_title_property_and_is_not_a_database_alias() {
    let scope = data_source_scope();
    let (consumer, _) = consumer(&scope);
    assert!(
        NotionPublishDestination::new(scope.clone(), NotionPublishOperation::CreatePage, None,)
            .is_err()
    );
    let destination = NotionPublishDestination::new(
        scope,
        NotionPublishOperation::CreatePage,
        Some(
            hartevo_notion_result_plugin::NotionPropertyKey::new("Result title")
                .expect("property key"),
        ),
    )
    .expect("data source destination");
    let proposal = consumer
        .compile_publish_proposal(work_product(1), destination)
        .expect("data source proposal");
    assert!(matches!(
        proposal.scope.parent,
        hartevo_notion_result_plugin::NotionParent::DataSource { .. }
    ));
    assert!(
        proposal
            .payload
            .properties
            .keys()
            .any(|key| key.as_str() == "Result title")
    );
}

#[test]
fn consent_scope_and_provider_manifest_drift_fail_closed() {
    let scope = page_scope();
    let (consumer, provider) = consumer(&scope);
    let no_insert_scope = NotionScope::page(
        NotionPageId::new("parent-page").expect("page ID"),
        "consent-read-only",
        BTreeSet::from([NotionCapability::ReadContent]),
    )
    .expect("read-only scope");
    let destination =
        NotionPublishDestination::new(no_insert_scope, NotionPublishOperation::CreatePage, None)
            .expect("destination can be described");
    let error = consumer
        .compile_publish_proposal(work_product(1), destination)
        .expect_err("missing insert consent must fail");
    assert!(matches!(error, NotionResultError::ScopeMismatch));

    let mut drifted = provider.manifest();
    drifted.scope.consent.consent_id = String::from("drifted-consent");
    drifted.manifest_digest = drifted.calculate_digest();
    provider.set_manifest(drifted);
    let error = consumer
        .compile_publish_proposal(
            work_product(1),
            NotionPublishDestination::new(scope, NotionPublishOperation::CreatePage, None)
                .expect("destination"),
        )
        .expect_err("manifest drift must fail");
    assert!(matches!(
        error,
        NotionResultError::ProviderManifestDrift { .. }
    ));
}

#[test]
fn missing_or_invalid_provider_manifest_fields_fail_closed_at_service_creation() {
    let scope = page_scope();
    let base = hartevo_notion_result_plugin::NotionProviderManifest::layer1(scope.clone())
        .expect("manifest");

    let mut missing_digest = base.clone();
    missing_digest.manifest_digest.clear();
    let error = NotionResultService::new(FakeNotionProvider::new(missing_digest))
        .expect_err("missing manifest digest");
    assert!(matches!(error, NotionResultError::InvalidProviderManifest));

    let mut wrong_version = base.clone();
    wrong_version.version.minor = 1;
    wrong_version.manifest_digest = wrong_version.calculate_digest();
    let error = NotionResultService::new(FakeNotionProvider::new(wrong_version))
        .expect_err("provider version drift");
    assert!(matches!(error, NotionResultError::InvalidProviderManifest));

    let mut missing_consent = base;
    missing_consent.scope.consent.consent_id.clear();
    missing_consent.manifest_digest = missing_consent.calculate_digest();
    let error = NotionResultService::new(FakeNotionProvider::new(missing_consent))
        .expect_err("missing consent scope");
    assert!(matches!(
        error,
        NotionResultError::InvalidInput { .. } | NotionResultError::InvalidScope
    ));
}

#[test]
fn readback_page_url_revision_and_fingerprint_mismatches_are_typed() {
    let scope = page_scope();
    let (consumer, provider) = consumer(&scope);
    let proposal = consumer
        .compile_publish_proposal(
            work_product(2),
            NotionPublishDestination::new(scope.clone(), NotionPublishOperation::CreatePage, None)
                .expect("destination"),
        )
        .expect("proposal");
    let receipt = consumer
        .record_publish_proposal(&proposal)
        .expect("receipt");
    let mut readback = provider.last_readback().expect("readback");
    readback.page_url =
        hartevo_notion_result_plugin::NotionPageUrl::new("https://www.notion.so/another-page")
            .expect("URL");
    let error = consumer
        .consume_readback(&proposal, &receipt, &readback)
        .expect_err("URL mismatch");
    assert!(matches!(
        error,
        NotionResultError::ReadbackMismatch {
            field: NotionReadbackField::PageUrl,
            ..
        }
    ));

    let mut readback = provider.last_readback().expect("readback");
    readback.revision =
        hartevo_notion_result_plugin::NotionRevision::new("recorded-other").expect("revision");
    let error = consumer
        .consume_readback(&proposal, &receipt, &readback)
        .expect_err("revision mismatch");
    assert!(matches!(
        error,
        NotionResultError::ReadbackMismatch {
            field: NotionReadbackField::Revision,
            ..
        }
    ));

    let mut readback = provider.last_readback().expect("readback");
    readback.content_fingerprint = canonical_digest("tampered");
    let error = consumer
        .consume_readback(&proposal, &receipt, &readback)
        .expect_err("fingerprint mismatch");
    assert!(matches!(
        error,
        NotionResultError::ReadbackMismatch {
            field: NotionReadbackField::ContentFingerprint,
            ..
        }
    ));
}

#[test]
fn provider_status_classes_are_explicit_and_secret_debug_is_redacted() {
    assert_eq!(
        NotionProviderError::from_status(403).status_code(),
        Some(403)
    );
    assert_eq!(
        NotionProviderError::from_status(404).status_code(),
        Some(404)
    );
    assert_eq!(
        NotionProviderError::from_status(409).status_code(),
        Some(409)
    );
    assert_eq!(
        NotionProviderError::from_status(429).status_code(),
        Some(429)
    );
    let secret = SecretReference::new("raw-token-must-not-escape").expect("secret reference");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("raw-token-must-not-escape"));
    let manifest = hartevo_notion_result_plugin::NotionProviderManifest::layer1(page_scope())
        .expect("manifest");
    let provider = RecordingNotionProvider::new(manifest).with_secret_reference(secret);
    let service = NotionResultService::new(provider).expect("service");
    assert!(!service.provider().external_write_available());
}

#[test]
fn missing_native_environment_is_explicitly_blocked() {
    let manifest = hartevo_notion_result_plugin::NotionProviderManifest::layer1(page_scope())
        .expect("manifest");
    assert_eq!(manifest.native_status, NativeStatus::BlockedEnv);
    assert_eq!(
        hartevo_notion_result_plugin::NOTION_ACCESS_TOKEN_ENV,
        "HARTEVO_NOTION_ACCESS_TOKEN"
    );
}

#[test]
fn describe_and_read_requests_use_bounded_pagination_metadata() {
    let scope = page_scope();
    let (consumer, provider) = consumer(&scope);
    let description = consumer
        .describe(
            &NotionDescribeRequest::new(
                scope.clone(),
                hartevo_notion_result_plugin::NotionPaginationTemplate::layer1(),
            )
            .expect("describe request"),
        )
        .expect("description");
    assert_eq!(description.pagination.pages_read, 1);
    assert_eq!(
        description.resource_kind,
        hartevo_notion_result_plugin::NotionResourceKind::Page
    );
    let error = consumer
        .read(
            &NotionReadRequest::new(
                NotionPageId::new("missing-page").expect("page ID"),
                scope,
                hartevo_notion_result_plugin::NotionPaginationTemplate::layer1(),
                None,
            )
            .expect("read request"),
        )
        .expect_err("missing fake page");
    assert!(matches!(
        error,
        NotionResultError::Provider(NotionProviderError::NoRecordedPage)
    ));
    assert_eq!(provider.calls().len(), 2);
}
