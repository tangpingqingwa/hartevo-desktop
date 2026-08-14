use std::collections::{BTreeMap, BTreeSet, VecDeque};

use hartevo_servicenow_change_plugin::{
    AclProbe, ApprovalFieldMapping, ApprovalProposalOperation, ApprovalProposalRequest,
    AuditFieldMapping, ChangeFieldMapping, ChangeProposalRequest, ChangeRecordIdentity,
    ChangeResultRequest, ConnectorScope, ConsentReference, DomainIdentity, EvidenceProvenance,
    FieldName, InstanceIdentity, MissionId, MissionScope, MissionServiceNowChangeConsumer,
    ProbeStatus, ProjectId, ProposalOperation, ProviderIdentity, ProviderPage, ProviderPageRequest,
    ProviderProbeResponse, ProviderRevision, RawFieldValue, RawRecord, RegistrationId,
    SchemaMapping, SchemaProbe, SecretReference, ServiceNowChangeError, ServiceNowChangeProvider,
    ServiceNowChangeService, ServiceNowScope, ServiceNowTransport, StateMappingEntry, SysId,
    TableName, TenantId, TransportError, WorkProductId,
};
use sha2::{Digest, Sha256};

const ORIGIN: &str = "https://snow.example.com";
const INSTANCE_ID: &str = "snow-prod";
const RELEASE: &str = "custom-release-7";
const DOMAIN_ID: &str = "global";
const CHANGE_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const APPROVAL_ID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const AUDIT_ID: &str = "cccccccccccccccccccccccccccccccc";

#[derive(Debug)]
struct ScriptedTransport {
    provenance: EvidenceProvenance,
    probe: std::result::Result<ProviderProbeResponse, TransportError>,
    pages: VecDeque<ProviderPage>,
    requests: Vec<ProviderPageRequest>,
}

impl ServiceNowTransport for ScriptedTransport {
    fn provenance(&self) -> EvidenceProvenance {
        self.provenance
    }

    fn probe(
        &mut self,
        _scope: &ServiceNowScope,
        _mapping: &SchemaMapping,
    ) -> std::result::Result<ProviderProbeResponse, TransportError> {
        self.probe.clone()
    }

    fn page(
        &mut self,
        request: &ProviderPageRequest,
    ) -> std::result::Result<ProviderPage, TransportError> {
        self.requests.push(request.clone());
        self.pages.pop_front().ok_or(TransportError::Malformed)
    }
}

struct Fixture {
    scope: ServiceNowScope,
    mapping: SchemaMapping,
    registration_id: RegistrationId,
}

fn digest(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn field(value: &str) -> FieldName {
    FieldName::new(value).expect("field")
}

fn table(value: &str) -> TableName {
    TableName::new(value).expect("table")
}

fn sys_id(value: &str) -> SysId {
    SysId::new(value).expect("sys_id")
}

fn mapping() -> SchemaMapping {
    let change_fields = ChangeFieldMapping {
        sys_id: field("sys_id"),
        number: field("number"),
        state: field("state"),
        provider_revision: field("sys_updated_on"),
        domain: field("sys_domain"),
        correlation: Some(field("u_hartevo_correlation")),
        proposal_fields: BTreeSet::from([field("short_description")]),
    };
    let approval_fields = ApprovalFieldMapping {
        sys_id: field("sys_id"),
        change_sys_id: field("change_sys_id"),
        state: field("state"),
        provider_revision: field("sys_updated_on"),
    };
    let audit_fields = AuditFieldMapping {
        sys_id: field("sys_id"),
        change_sys_id: field("document_id"),
        field_name: field("field_name"),
        value_digest: field("value_digest"),
        provider_revision: field("sys_updated_on"),
        changed_at: field("changed_at"),
    };
    let states = BTreeMap::from([(
        "scheduled".to_owned(),
        StateMappingEntry::new("custom_scheduled", false).expect("state"),
    )]);
    SchemaMapping::new(
        table("u_change_request"),
        table("u_change_approval"),
        table("u_change_audit"),
        change_fields,
        approval_fields,
        audit_fields,
        states,
        digest("schema-fingerprint-v1"),
    )
    .expect("mapping")
}

fn scope() -> ServiceNowScope {
    let project_id = ProjectId::from("project-1");
    let mission_id = MissionId::from("mission-1");
    let work_product_id = WorkProductId::from("work-product-1");
    let consent = ConsentReference::new(
        hartevo_servicenow_change_plugin::ConsentRecordId::from("consent-1"),
        3,
        project_id.clone(),
        mission_id.clone(),
        work_product_id.clone(),
    )
    .expect("consent reference");
    let mission = MissionScope::new(
        TenantId::from("tenant-1"),
        project_id,
        11,
        mission_id,
        17,
        work_product_id,
        5,
        consent,
    )
    .expect("mission scope");
    let instance = InstanceIdentity::new(ORIGIN, INSTANCE_ID, RELEASE).expect("instance");
    let domain = DomainIdentity::new(DOMAIN_ID, "/global").expect("domain");
    let connector_scope = ConnectorScope::new(
        "tenant-1",
        "project-1",
        hartevo_servicenow_change_plugin::PROVIDER_ID,
        INSTANCE_ID,
        [
            "servicenow.change.read".to_owned(),
            "servicenow.approval.read".to_owned(),
        ],
    )
    .expect("connector scope");
    let secret = SecretReference::new("secret-ref-snow-1", connector_scope, 9).expect("secret");
    ServiceNowScope::new(
        mission,
        instance,
        domain,
        Some(ChangeRecordIdentity::new(CHANGE_ID, "CHG0001").expect("change identity")),
        [sys_id(APPROVAL_ID)],
        secret,
    )
    .expect("ServiceNow scope")
}

fn probe_response(
    provenance: EvidenceProvenance,
    mapping: &SchemaMapping,
) -> ProviderProbeResponse {
    let mut fields = mapping.required_fields();
    fields.insert(field("u_hartevo_correlation"));
    fields.insert(field("short_description"));
    ProviderProbeResponse::new(
        provenance,
        format!("{ORIGIN}/"),
        Vec::new(),
        INSTANCE_ID,
        RELEASE,
        DOMAIN_ID,
        AclProbe::explicit(fields.clone()),
        SchemaProbe::explicit(digest("schema-fingerprint-v1"), fields),
    )
    .with_domain_path("/global")
}

fn raw(fields: &[(&str, RawFieldValue)], tag: &str) -> RawRecord {
    RawRecord::new(
        fields
            .iter()
            .map(|(name, value)| (field(name), value.clone()))
            .collect::<Vec<_>>(),
        digest(tag),
    )
    .expect("raw record")
}

fn change_record(number: &str) -> RawRecord {
    raw(
        &[
            ("sys_id", RawFieldValue::text(CHANGE_ID)),
            ("number", RawFieldValue::text(number)),
            ("state", RawFieldValue::text("custom_scheduled")),
            ("sys_updated_on", RawFieldValue::text("change-rev-1")),
            ("sys_domain", RawFieldValue::text(DOMAIN_ID)),
        ],
        "change-response",
    )
}

fn approval_record() -> RawRecord {
    raw(
        &[
            ("sys_id", RawFieldValue::text(APPROVAL_ID)),
            ("change_sys_id", RawFieldValue::text(CHANGE_ID)),
            ("state", RawFieldValue::text("custom_scheduled")),
            ("sys_updated_on", RawFieldValue::text("approval-rev-1")),
        ],
        "approval-response",
    )
}

fn audit_record() -> RawRecord {
    raw(
        &[
            ("sys_id", RawFieldValue::text(AUDIT_ID)),
            ("document_id", RawFieldValue::text(CHANGE_ID)),
            ("field_name", RawFieldValue::text("short_description")),
            ("value_digest", RawFieldValue::text(digest("before"))),
            ("sys_updated_on", RawFieldValue::text("audit-rev-1")),
            ("changed_at", RawFieldValue::text("2026-08-14T08:00:00Z")),
        ],
        "audit-response",
    )
}

fn make_fixture(
    provenance: EvidenceProvenance,
    probe: std::result::Result<ProviderProbeResponse, TransportError>,
    pages: Vec<ProviderPage>,
    bounds: hartevo_servicenow_change_plugin::QueryBounds,
) -> (ServiceNowChangeService<ScriptedTransport>, Fixture) {
    let scope = scope();
    let mapping = mapping();
    let registration_id =
        RegistrationId::new("servicenow-registration-test-1").expect("registration id");
    let transport = ScriptedTransport {
        provenance,
        probe,
        pages: pages.into(),
        requests: Vec::new(),
    };
    let provider = ServiceNowChangeProvider::new(transport, bounds).expect("provider");
    let mut service = ServiceNowChangeService::new(provider);
    service
        .register(
            registration_id.clone(),
            scope.clone(),
            mapping.clone(),
            ProviderIdentity::new(1, RELEASE).expect("provider identity"),
        )
        .expect("registration");
    (
        service,
        Fixture {
            scope,
            mapping,
            registration_id,
        },
    )
}

fn page(records: Vec<RawRecord>) -> ProviderPage {
    ProviderPage::new(records, None, 512)
}

#[test]
fn recording_provider_projects_exact_scope_and_compiles_non_mutating_proposals() {
    let mapping = mapping();
    let response = probe_response(EvidenceProvenance::Recording, &mapping);
    let (mut service, fixture) = make_fixture(
        EvidenceProvenance::Recording,
        Ok(response),
        vec![
            page(vec![change_record("CHG0001")]),
            page(vec![approval_record()]),
            page(vec![audit_record()]),
        ],
        hartevo_servicenow_change_plugin::QueryBounds::layer_one(),
    );
    let probe = service
        .probe_registration(&fixture.registration_id)
        .expect("recording probe");
    assert_eq!(probe.status, ProbeStatus::Ready);
    assert!(!probe.connected);
    assert!(!probe.native);

    let change = service
        .read_change(&fixture.registration_id)
        .expect("change projection");
    assert_eq!(change.sys_id, sys_id(CHANGE_ID));
    assert_eq!(change.number, "CHG0001");
    assert_eq!(change.canonical_state, "scheduled");
    assert!(!change.evidence.connected);

    let approvals = service
        .read_approvals(&fixture.registration_id)
        .expect("approval projection");
    assert_eq!(approvals.len(), 1);
    let audit = service
        .read_audit(&fixture.registration_id)
        .expect("audit projection");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].field_name, field("short_description"));

    let consumer = MissionServiceNowChangeConsumer;
    let mut request = ChangeProposalRequest::new(ProposalOperation::Update);
    request
        .field_digests
        .insert(field("short_description"), digest("new description"));
    request.expected_provider_revision = Some(ProviderRevision::new("change-rev-1").unwrap());
    request.target_change_sys_id = Some(sys_id(CHANGE_ID));
    request.correlation = Some(
        hartevo_servicenow_change_plugin::CorrelationBinding::new(
            field("u_hartevo_correlation"),
            digest("correlation-1"),
            true,
        )
        .unwrap(),
    );
    let proposal = consumer
        .compile_change_proposal(
            service.registration(&fixture.registration_id).unwrap(),
            request.clone(),
        )
        .expect("change proposal");
    assert!(proposal.non_mutating);
    assert!(proposal.ensure_future_write_safe().is_ok());
    assert!(!proposal.connected);
    assert!(!proposal.native);

    let mut missing_correlation = request.clone();
    missing_correlation.correlation = None;
    let missing_correlation = consumer
        .compile_change_proposal(
            service.registration(&fixture.registration_id).unwrap(),
            missing_correlation,
        )
        .expect("proposal without correlation remains a proposal");
    assert_eq!(
        missing_correlation.ensure_future_write_safe(),
        Err(ServiceNowChangeError::MissingCorrelation)
    );

    let mut ambiguous = request.clone();
    ambiguous.correlation = Some(
        hartevo_servicenow_change_plugin::CorrelationBinding::new(
            field("u_hartevo_correlation"),
            digest("correlation-1"),
            false,
        )
        .unwrap(),
    );
    let ambiguous = consumer
        .compile_change_proposal(
            service.registration(&fixture.registration_id).unwrap(),
            ambiguous,
        )
        .expect("ambiguous write remains a proposal");
    assert_eq!(
        ambiguous.ensure_future_write_safe(),
        Err(ServiceNowChangeError::ExactReadbackRequired)
    );

    let approval_request = ApprovalProposalRequest {
        operation: ApprovalProposalOperation::Observe,
        expected_provider_revisions: BTreeMap::from([(
            sys_id(APPROVAL_ID),
            ProviderRevision::new("approval-rev-1").unwrap(),
        )]),
    };
    let approval_proposal = consumer
        .compile_approval_proposal(
            service.registration(&fixture.registration_id).unwrap(),
            &proposal,
            &approvals,
            approval_request,
        )
        .expect("approval proposal");
    assert!(approval_proposal.non_mutating);

    let result = consumer
        .compile_change_result_proposal(
            service.registration(&fixture.registration_id).unwrap(),
            &change,
            &approvals,
            ChangeResultRequest {
                expected_change_revision: ProviderRevision::new("change-rev-1").unwrap(),
                expected_approval_revisions: BTreeMap::from([(
                    sys_id(APPROVAL_ID),
                    ProviderRevision::new("approval-rev-1").unwrap(),
                )]),
                expected_canonical_state: Some("scheduled".into()),
            },
        )
        .expect("result proposal");
    assert!(result.candidate_only);
    assert!(!result.adopted_outcome);
    let serialized = serde_json::to_string(&result).expect("result serialization");
    assert!(!serialized.contains("oauth-token"));
    assert!(!serialized.contains("journal"));

    let _ = fixture.scope;
    let _ = fixture.mapping;
}

#[test]
fn fake_provenance_never_claims_connected_native_or_first_party() {
    let mapping = mapping();
    let (mut service, fixture) = make_fixture(
        EvidenceProvenance::Fake,
        Ok(probe_response(EvidenceProvenance::Fake, &mapping)),
        vec![page(vec![change_record("CHG0001")])],
        hartevo_servicenow_change_plugin::QueryBounds::layer_one(),
    );
    let probe = service
        .probe_registration(&fixture.registration_id)
        .expect("fake probe");
    assert_eq!(probe.provenance, EvidenceProvenance::Fake);
    let change = service
        .read_change(&fixture.registration_id)
        .expect("fake read");
    assert_eq!(change.evidence.provenance, EvidenceProvenance::Fake);
    assert!(!change.evidence.connected);
    assert!(!change.evidence.native);
    assert!(!change.evidence.first_party);
}

#[test]
fn blocked_env_is_explicit_and_never_read_as_connected() {
    let mapping = mapping();
    let (mut service, fixture) = make_fixture(
        EvidenceProvenance::BlockedEnv,
        Err(TransportError::BlockedEnv),
        Vec::new(),
        hartevo_servicenow_change_plugin::QueryBounds::layer_one(),
    );
    let probe = service
        .probe_registration(&fixture.registration_id)
        .expect("blocked probe");
    assert_eq!(probe.status, ProbeStatus::BlockedEnv);
    assert_eq!(probe.provenance, EvidenceProvenance::BlockedEnv);
    assert!(!probe.connected);
    assert_eq!(
        service.read_change(&fixture.registration_id),
        Err(ServiceNowChangeError::BlockedEnvironment)
    );
    let _ = mapping;
}

#[test]
fn probe_rejects_redirects_acl_omission_and_schema_drift() {
    let mapping = mapping();
    let mut redirected = probe_response(EvidenceProvenance::Recording, &mapping);
    redirected.redirects = vec!["https://other-instance.example.com".into()];
    let (mut service, fixture) = make_fixture(
        EvidenceProvenance::Recording,
        Ok(redirected),
        Vec::new(),
        hartevo_servicenow_change_plugin::QueryBounds::layer_one(),
    );
    assert!(matches!(
        service.probe_registration(&fixture.registration_id),
        Err(ServiceNowChangeError::InstanceMismatch(_))
    ));

    let mut acl_omitted = probe_response(EvidenceProvenance::Recording, &mapping);
    acl_omitted.acl = AclProbe::omitted();
    let (mut service, fixture) = make_fixture(
        EvidenceProvenance::Recording,
        Ok(acl_omitted),
        Vec::new(),
        hartevo_servicenow_change_plugin::QueryBounds::layer_one(),
    );
    assert!(matches!(
        service.probe_registration(&fixture.registration_id),
        Err(ServiceNowChangeError::AclNotVisible { .. })
    ));

    let mut drift = probe_response(EvidenceProvenance::Recording, &mapping);
    drift.schema = SchemaProbe::explicit(digest("drifted-schema"), mapping.required_fields());
    let (mut service, fixture) = make_fixture(
        EvidenceProvenance::Recording,
        Ok(drift),
        Vec::new(),
        hartevo_servicenow_change_plugin::QueryBounds::layer_one(),
    );
    assert!(matches!(
        service.probe_registration(&fixture.registration_id),
        Err(ServiceNowChangeError::SchemaDrift(_))
    ));
}

#[test]
fn projection_rejects_display_number_confusion_and_omitted_or_null_fields() {
    let mapping = mapping();
    let (mut service, fixture) = make_fixture(
        EvidenceProvenance::Recording,
        Ok(probe_response(EvidenceProvenance::Recording, &mapping)),
        vec![page(vec![change_record("CHG9999")])],
        hartevo_servicenow_change_plugin::QueryBounds::layer_one(),
    );
    service
        .probe_registration(&fixture.registration_id)
        .unwrap();
    assert_eq!(
        service.read_change(&fixture.registration_id),
        Err(ServiceNowChangeError::RecordIdentityMismatch)
    );

    let omitted = raw(
        &[("sys_id", RawFieldValue::text(CHANGE_ID))],
        "omitted-change",
    );
    let (mut service, fixture) = make_fixture(
        EvidenceProvenance::Recording,
        Ok(probe_response(EvidenceProvenance::Recording, &mapping)),
        vec![page(vec![omitted])],
        hartevo_servicenow_change_plugin::QueryBounds::layer_one(),
    );
    service
        .probe_registration(&fixture.registration_id)
        .unwrap();
    assert!(matches!(
        service.read_change(&fixture.registration_id),
        Err(ServiceNowChangeError::FieldNotVisible(_))
    ));

    let null_state = raw(
        &[
            ("sys_id", RawFieldValue::text(CHANGE_ID)),
            ("number", RawFieldValue::text("CHG0001")),
            ("state", RawFieldValue::null()),
            ("sys_updated_on", RawFieldValue::text("change-rev-1")),
            ("sys_domain", RawFieldValue::text(DOMAIN_ID)),
        ],
        "null-state",
    );
    let (mut service, fixture) = make_fixture(
        EvidenceProvenance::Recording,
        Ok(probe_response(EvidenceProvenance::Recording, &mapping)),
        vec![page(vec![null_state])],
        hartevo_servicenow_change_plugin::QueryBounds::layer_one(),
    );
    service
        .probe_registration(&fixture.registration_id)
        .unwrap();
    assert!(matches!(
        service.read_change(&fixture.registration_id),
        Err(ServiceNowChangeError::FieldNotVisible(field)) if field == "state"
    ));
}

#[test]
fn approval_projection_requires_the_exact_scoped_set() {
    let mapping = mapping();
    let (mut service, fixture) = make_fixture(
        EvidenceProvenance::Recording,
        Ok(probe_response(EvidenceProvenance::Recording, &mapping)),
        vec![page(vec![approval_record(), approval_record()])],
        hartevo_servicenow_change_plugin::QueryBounds::layer_one(),
    );
    service
        .probe_registration(&fixture.registration_id)
        .expect("probe");
    assert_eq!(
        service.read_approvals(&fixture.registration_id),
        Err(ServiceNowChangeError::ApprovalSetMismatch)
    );

    let (mut service, fixture) = make_fixture(
        EvidenceProvenance::Recording,
        Ok(probe_response(EvidenceProvenance::Recording, &mapping)),
        vec![page(Vec::new())],
        hartevo_servicenow_change_plugin::QueryBounds::layer_one(),
    );
    service
        .probe_registration(&fixture.registration_id)
        .expect("probe");
    assert_eq!(
        service.read_approvals(&fixture.registration_id),
        Err(ServiceNowChangeError::ApprovalSetMismatch)
    );
}

#[test]
fn pagination_loops_and_bounds_fail_closed_and_queries_are_digest_bound() {
    let mapping = mapping();
    let looping_first =
        ProviderPage::new(vec![change_record("CHG0001")], Some("cursor-1".into()), 512);
    let looping_second =
        ProviderPage::new(vec![change_record("CHG0001")], Some("cursor-1".into()), 512);
    let (mut service, fixture) = make_fixture(
        EvidenceProvenance::Recording,
        Ok(probe_response(EvidenceProvenance::Recording, &mapping)),
        vec![looping_first, looping_second],
        hartevo_servicenow_change_plugin::QueryBounds::layer_one(),
    );
    service
        .probe_registration(&fixture.registration_id)
        .unwrap();
    assert_eq!(
        service.read_change(&fixture.registration_id),
        Err(ServiceNowChangeError::PaginationLoop)
    );

    let bounded_first =
        ProviderPage::new(vec![change_record("CHG0001")], Some("cursor-1".into()), 512);
    let bounds = hartevo_servicenow_change_plugin::QueryBounds {
        max_page_size: 100,
        max_pages: 1,
        max_items: 256,
        max_response_bytes: 1024 * 1024,
    };
    let (mut service, fixture) = make_fixture(
        EvidenceProvenance::Recording,
        Ok(probe_response(EvidenceProvenance::Recording, &mapping)),
        vec![bounded_first],
        bounds,
    );
    service
        .probe_registration(&fixture.registration_id)
        .unwrap();
    assert_eq!(
        service.read_change(&fixture.registration_id),
        Err(ServiceNowChangeError::PaginationBound)
    );

    let (mut service, fixture) = make_fixture(
        EvidenceProvenance::Recording,
        Ok(probe_response(EvidenceProvenance::Recording, &mapping)),
        Vec::new(),
        hartevo_servicenow_change_plugin::QueryBounds::layer_one(),
    );
    service
        .probe_registration(&fixture.registration_id)
        .unwrap();
    let mut query = service
        .compile_query(
            &fixture.registration_id,
            hartevo_servicenow_change_plugin::QueryKind::Change,
        )
        .unwrap();
    query.encoded_query = "javascript:gs.getSession().getProperty('secret')".into();
    assert_eq!(
        query.validate(),
        Err(ServiceNowChangeError::QueryBindingMismatch)
    );
}

#[test]
fn registration_is_reversible_but_probe_and_digests_remain_fenced() {
    let mapping = mapping();
    let (mut service, fixture) = make_fixture(
        EvidenceProvenance::Recording,
        Ok(probe_response(EvidenceProvenance::Recording, &mapping)),
        vec![page(vec![change_record("CHG0001")])],
        hartevo_servicenow_change_plugin::QueryBounds::layer_one(),
    );
    service
        .probe_registration(&fixture.registration_id)
        .unwrap();
    service
        .revoke_registration(&fixture.registration_id)
        .unwrap();
    assert_eq!(
        service.read_change(&fixture.registration_id),
        Err(ServiceNowChangeError::RegistrationNotActive)
    );
    service
        .restore_registration(&fixture.registration_id)
        .unwrap();
    assert_eq!(
        service.read_change(&fixture.registration_id),
        Err(ServiceNowChangeError::ProbeRequired)
    );

    let mut tampered_mapping = mapping.clone();
    tampered_mapping.schema_fingerprint = digest("tampered");
    assert_eq!(
        tampered_mapping.validate(),
        Err(ServiceNowChangeError::SchemaMappingDigestMismatch)
    );
}
