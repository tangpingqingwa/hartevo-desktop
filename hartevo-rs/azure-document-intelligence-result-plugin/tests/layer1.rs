use hartevo_azure_document_intelligence_result_plugin::{
    AnalyzeResultProjection, AzureDocumentIntelligenceContract, AzureDocumentIntelligenceError,
    AzureDocumentIntelligenceProvider, AzureDocumentIntelligenceScope,
    AzureDocumentIntelligenceScopeInput, AzureDocumentIntelligenceService, ConsentScope,
    DocumentIntelligenceDisposition, DocumentIntelligencePermission, DocumentModel,
    MissionDocumentIntelligenceConsumer, MissionScope, PageRange, ProjectScope, ProviderMode,
    RecordedProviderResponse, RedactionPolicy, RevocationReason, SecretReference, WorkProductScope,
    contract_digest, sha256_digest,
};

const PROVIDER_REVISION: &str = "azure-document-intelligence-rest-2024-11-30-r1";

fn scope(model: DocumentModel) -> AzureDocumentIntelligenceScope {
    AzureDocumentIntelligenceScope::new(AzureDocumentIntelligenceScopeInput {
        tenant_id: "tenant-1".to_owned(),
        resource_name: "resource-1".to_owned(),
        region: "eastus".to_owned(),
        model,
        document_id: "document-1".to_owned(),
        source_digest: sha256_digest(b"document-source"),
        page_range: PageRange::new(1, 2).expect("page range"),
        project: ProjectScope::new("project-1", 3).expect("Project scope"),
        mission: MissionScope::new("mission-1", 5).expect("Mission scope"),
        work_product: WorkProductScope::new("work-product-1", 7).expect("Work Product scope"),
        consent: ConsentScope::with_purpose("consent-1", 9, "document_processing")
            .expect("Consent scope"),
        permission: DocumentIntelligencePermission::AnalyzeRead,
    })
    .expect("exact scope")
}

fn secret() -> SecretReference {
    SecretReference::new("vault/azure-document-intelligence", "tenant-1", 4)
        .expect("opaque secret reference")
}

fn response_body(model: DocumentModel) -> Vec<u8> {
    serde_json::json!({
        "status": "succeeded",
        "analyzeResult": {
            "modelId": model.as_str(),
            "content": "Alice confidential document text",
            "pages": [{
                "pageNumber": 1,
                "lines": [{"content": "Alice confidential document text", "polygon": [0, 0, 10, 0, 10, 10, 0, 10]}],
                "words": [{"content": "Alice", "confidence": 0.97, "polygon": [0, 0, 5, 0, 5, 5, 0, 5]}]
            }],
            "paragraphs": [{"content": "Alice confidential document text", "role": "body", "boundingRegions": [{"pageNumber": 1, "polygon": [0, 0, 10, 0, 10, 10, 0, 10]}]}],
            "tables": if model.supports_tables() {
                serde_json::json!([{"rowCount": 1, "columnCount": 1, "cells": [{"rowIndex": 0, "columnIndex": 0, "kind": "content", "content": "Alice", "confidence": 0.91, "boundingRegions": [{"pageNumber": 1, "polygon": [0, 0, 4, 0, 4, 4, 0, 4]}]}]}])
            } else {
                serde_json::json!([])
            },
            "documents": [{"docType": "custom", "fields": {"AccountName": {"type": "string", "valueString": "Alice", "confidence": 0.88, "boundingRegions": [{"pageNumber": 1, "polygon": [0, 0, 3, 0, 3, 3, 0, 3]}]}}}]
        }
    })
    .to_string()
    .into_bytes()
}

#[test]
fn contract_registration_and_service_descriptor_are_exact_layer_one() {
    let contract = AzureDocumentIntelligenceContract::baseline().expect("contract");
    assert_eq!(contract.digest(), contract_digest());
    assert_eq!(
        contract.allowlisted_models,
        ["prebuilt-read", "prebuilt-layout"]
    );
    assert!(!contract.authority.connected);
    assert!(!contract.authority.native);
    assert!(!contract.authority.kernel_receipt);
    assert_eq!(contract.layer, "Layer-1");

    let provider =
        AzureDocumentIntelligenceProvider::fixture(scope(DocumentModel::PrebuiltRead), secret())
            .expect("provider");
    let service =
        AzureDocumentIntelligenceService::new(provider.scope().clone(), provider).expect("service");
    service.validate().expect("service descriptor");
    assert!(service.read_only());
    assert!(!service.native_connected());
    assert!(service.registration().plugin_version_digest().is_sha256());
    assert!(service.registration().contract_digest().is_sha256());
    assert!(service.registration().provider_digest().is_sha256());
    assert!(service.registration().permission_digest().is_sha256());
    assert!(service.registration().scope_digest().is_sha256());
    assert!(service.registration().source_digest().is_sha256());
    assert!(service.registration().registration_digest().is_sha256());
    assert_eq!(
        service
            .registration()
            .secret_reference()
            .credential_revision(),
        4
    );
    assert_eq!(
        format!("{:?}", service.registration().secret_reference()),
        "SecretReference { reference_id: \"<opaque>\", tenant_id: \"<opaque>\", credential_revision: 4 }"
    );
}

#[test]
fn recording_projects_bounded_text_tables_fields_and_geometry_without_pii() {
    let scope = scope(DocumentModel::PrebuiltLayout);
    let provider =
        AzureDocumentIntelligenceProvider::recording(scope.clone(), secret()).expect("provider");
    let mut service =
        AzureDocumentIntelligenceService::new(scope.clone(), provider).expect("service");
    let request = service
        .compile_analysis_request(RedactionPolicy::bounded_prefix(5).expect("redaction"))
        .expect("request");
    let response = RecordedProviderResponse::from_json(
        &request,
        "https://resource-1.cognitiveservices.azure.com/documentintelligence/operations/op-1",
        200,
        PROVIDER_REVISION,
        &response_body(DocumentModel::PrebuiltLayout),
    )
    .expect("recorded response");
    service.provider_mut().push_response(response);

    let consumer = MissionDocumentIntelligenceConsumer::new(scope);
    let result = consumer
        .read(
            &mut service,
            RedactionPolicy::bounded_prefix(5).expect("redaction"),
        )
        .expect("mission projection");
    result.validate(consumer.scope()).expect("result binding");
    assert_eq!(
        result.observation.disposition,
        DocumentIntelligenceDisposition::Projected
    );
    assert!(result.proposal_only());
    assert!(!result.connected());
    assert!(!result.native());
    assert!(!result.adopted());
    assert_eq!(
        result
            .evidence
            .result
            .as_ref()
            .expect("result")
            .tables()
            .len(),
        1
    );
    assert_eq!(
        result
            .evidence
            .result
            .as_ref()
            .expect("result")
            .fields()
            .len(),
        1
    );
    let text = result
        .evidence
        .result
        .as_ref()
        .expect("result")
        .content()
        .expect("content");
    assert_eq!(text.preview(), Some("Alice"));
    assert!(
        !serde_json::to_string(&result)
            .expect("safe evidence JSON")
            .contains("confidential document text")
    );
    assert!(
        !serde_json::to_string(&result)
            .expect("safe evidence JSON")
            .contains("cognitiveservices.azure.com")
    );
    assert!(
        result
            .evidence
            .operation
            .operation_location()
            .expect("location")
            .digest()
            .is_sha256()
    );
    assert_eq!(
        result.evidence.operation.response_bytes(),
        response_body(DocumentModel::PrebuiltLayout).len()
    );
}

#[test]
fn fixture_and_loopback_are_explicitly_non_native_and_blocked_env_is_honest() {
    let fixture_scope = scope(DocumentModel::PrebuiltRead);
    let fixture = AzureDocumentIntelligenceProvider::fixture(fixture_scope.clone(), secret())
        .expect("fixture provider");
    assert_eq!(fixture.mode(), ProviderMode::Fixture);
    assert!(!fixture.is_connected());
    assert!(!fixture.is_native());
    assert!(!fixture.native_connected_claim());

    let loopback = AzureDocumentIntelligenceProvider::loopback(fixture_scope.clone(), secret())
        .expect("loopback provider");
    assert_eq!(loopback.provenance(), ProviderMode::Loopback);
    assert!(!loopback.provenance().is_native());

    let blocked_provider =
        AzureDocumentIntelligenceProvider::blocked_env(fixture_scope.clone(), secret())
            .expect("blocked provider");
    let mut blocked_service =
        AzureDocumentIntelligenceService::new(fixture_scope.clone(), blocked_provider)
            .expect("blocked service");
    let blocked_consumer = MissionDocumentIntelligenceConsumer::new(fixture_scope);
    let result = blocked_consumer
        .read_digest_only(&mut blocked_service)
        .expect("blocked evidence");
    assert_eq!(
        result.observation.disposition,
        DocumentIntelligenceDisposition::BlockedEnv
    );
    assert_eq!(result.evidence.provenance, ProviderMode::BlockedEnv);
    assert!(!result.connected());
    assert!(!result.native());
    assert!(result.evidence.result.is_none());
}

#[test]
fn scope_revision_model_page_and_registration_lifecycle_fail_closed() {
    let original_scope = scope(DocumentModel::PrebuiltRead);
    let wrong_secret = SecretReference::new("vault/azure-document-intelligence", "other-tenant", 4)
        .expect("wrong tenant secret");
    assert!(matches!(
        AzureDocumentIntelligenceProvider::fixture(original_scope.clone(), wrong_secret),
        Err(AzureDocumentIntelligenceError::ScopeMismatch(_))
    ));

    let provider = AzureDocumentIntelligenceProvider::fixture(original_scope.clone(), secret())
        .expect("provider");
    let mut service =
        AzureDocumentIntelligenceService::new(original_scope.clone(), provider).expect("service");
    service
        .revoke(RevocationReason::UserRequested)
        .expect("revoke");
    assert!(matches!(
        service.compile_request(),
        Err(AzureDocumentIntelligenceError::RegistrationRevoked)
    ));
    service.restore().expect("restore");
    assert!(service.registration().is_active());

    let request = service.compile_request().expect("request");
    let wrong_model_result = AnalyzeResultProjection::fixture(
        DocumentModel::PrebuiltLayout,
        request.source_digest(),
        request.page_range(),
        RedactionPolicy::digest_only(),
    );
    assert!(wrong_model_result.is_ok());
    assert_ne!(
        wrong_model_result.expect("layout fixture").model(),
        original_scope.model()
    );
}
