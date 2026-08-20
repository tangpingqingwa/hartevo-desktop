use std::{cell::Cell, rc::Rc};

use chrono::{TimeZone, Utc};
use hartevo_connector_sdk::SecretReference;
use hartevo_domain_kernel::{MissionId, ProjectId, TenantId};
use hartevo_plugin_runtime::PluginRuntime;
use serde_json::Value;

use hartevo_docusign_signature_plugin::{
    BaseUri, BlockedEnvDocuSignTransport, DOCUSIGN_PLUGIN_VERSION, DOCUSIGN_PROVIDER_ID, Digest,
    DocuSignAccountId, DocuSignPluginRegistration, DocuSignScope, DocuSignSignatureProvider,
    DocuSignSignatureService, DocuSignTransport, DocuSignTransportError, DocumentContentType,
    DocumentId, DocumentReference, EnvelopeContent, EnvelopeId, EnvelopeProposal,
    EnvelopeProposalRequest, EnvelopeStatus, FixtureDocuSignTransport, LoopbackDocuSignTransport,
    NativeOperation, NativeOptInDocuSignTransport, NonConnectedEvidence, PollPlan, ProviderError,
    ProviderProvenance, RecipientId, RecipientRole, RecipientSpec, RecipientStatus,
    RecipientStatusProjection, RecordedEnvelopeObservation, RedactionSummary, RevisionFence,
    RoutingOrder, RoutingPlan, RoutingStep, ServiceError, SignedResultSource,
};

fn fixture_scope() -> DocuSignScope {
    DocuSignScope::new(
        TenantId::from("tenant-docusign-layer1"),
        ProjectId::from("project-docusign-layer1"),
        MissionId::from("mission-signature-01"),
        DocuSignAccountId::new("account-fixture-01").expect("account"),
        BaseUri::new("https://demo.docusign.net/restapi").expect("base URI"),
    )
    .expect("scope")
}

fn fixture_revision() -> RevisionFence {
    RevisionFence::new(4, 9, 12).expect("revision")
}

fn registration(scope: &DocuSignScope, revision: RevisionFence) -> DocuSignPluginRegistration {
    DocuSignPluginRegistration::new(
        scope.clone(),
        revision,
        Digest::from_text("docusign-signature-implementation/v1"),
    )
    .expect("registration")
}

fn secret(scope: &DocuSignScope) -> SecretReference {
    SecretReference::new(
        "secret-ref-docusign-fixture",
        scope.connector_scope().expect("connector scope"),
        1,
    )
    .expect("secret reference")
}

fn recipients() -> (Vec<RecipientSpec>, RoutingPlan) {
    let first_id = RecipientId::new("recipient-alice").expect("first recipient");
    let second_id = RecipientId::new("recipient-bob").expect("second recipient");
    let first_order = RoutingOrder::new(1).expect("first order");
    let second_order = RoutingOrder::new(2).expect("second order");
    let first = RecipientSpec::new(
        first_id.clone(),
        RecipientRole::Signer,
        Digest::from_text("alice@example.com"),
        Digest::from_text("Alice Example"),
        first_order,
    );
    let second = RecipientSpec::new(
        second_id.clone(),
        RecipientRole::Signer,
        Digest::from_text("bob@example.com"),
        Digest::from_text("Bob Example"),
        second_order,
    );
    let routing = RoutingPlan::new([
        RoutingStep::new(first_order, [first_id]).expect("first routing step"),
        RoutingStep::new(second_order, [second_id]).expect("second routing step"),
    ])
    .expect("routing plan");
    (vec![first, second], routing)
}

fn proposal_request(
    scope: &DocuSignScope,
    revision: RevisionFence,
    source_suffix: &str,
) -> EnvelopeProposalRequest {
    let (recipients, routing) = recipients();
    let created_at = Utc
        .with_ymd_and_hms(2026, 8, 14, 1, 2, 3)
        .single()
        .expect("created time");
    let expires_at = Utc
        .with_ymd_and_hms(2026, 8, 20, 1, 2, 3)
        .single()
        .expect("expiry time");
    EnvelopeProposalRequest::new(
        scope.clone(),
        revision,
        Digest::from_text(format!("source-result-{source_suffix}")),
        Digest::from_text(format!("source-file-{source_suffix}")),
        EnvelopeContent::Documents(vec![DocumentReference::new(
            DocumentId::new(format!("document-{source_suffix}")).expect("document"),
            Digest::from_text(format!("document-bytes-{source_suffix}")),
            DocumentContentType::Pdf,
        )]),
        recipients,
        routing,
        created_at,
        expires_at,
    )
    .expect("proposal request")
}

fn observation(
    proposal: &EnvelopeProposal,
    status: EnvelopeStatus,
    provenance: ProviderProvenance,
) -> RecordedEnvelopeObservation {
    let statuses = proposal
        .recipients()
        .iter()
        .map(|recipient| {
            let status = match status {
                EnvelopeStatus::ProviderUnknown => RecipientStatus::ProviderUnknown {
                    status_digest: Digest::from_text("provider-unknown-status"),
                },
                EnvelopeStatus::Created => RecipientStatus::Created,
                EnvelopeStatus::Sent => RecipientStatus::Sent,
                EnvelopeStatus::Delivered => RecipientStatus::Delivered,
                EnvelopeStatus::Completed => RecipientStatus::Completed,
                EnvelopeStatus::Declined => RecipientStatus::Declined,
                EnvelopeStatus::Voided => RecipientStatus::Voided,
            };
            RecipientStatusProjection::new(
                recipient.recipient_id().clone(),
                recipient.role(),
                recipient.routing_order(),
                status,
            )
        })
        .collect::<Vec<_>>();
    let completion_evidence = status
        .is_completed()
        .then(|| Digest::from_text("fixture-completion-attestation"));
    RecordedEnvelopeObservation::new(
        proposal.scope().clone(),
        EnvelopeId::new(format!("envelope-{status:?}")).expect("envelope"),
        proposal.fingerprint().clone(),
        proposal.revision_fence(),
        status,
        statuses,
        proposal.created_at(),
        Digest::from_text(format!("provider-response-{status:?}")),
        completion_evidence,
        DOCUSIGN_PLUGIN_VERSION,
        proposal.registration_digest().clone(),
        provenance,
    )
    .expect("observation")
}

fn fixture_service(
    scope: &DocuSignScope,
    revision: RevisionFence,
) -> DocuSignSignatureService<DocuSignSignatureProvider<FixtureDocuSignTransport>> {
    let registration = registration(scope, revision);
    let provider = DocuSignSignatureProvider::from_registration(
        &registration,
        secret(scope),
        FixtureDocuSignTransport,
    )
    .expect("provider");
    DocuSignSignatureService::new(provider, revision).expect("service")
}

#[test]
fn completed_fixture_projection_is_revision_fenced_and_adoptable_as_a_proposal() {
    let scope = fixture_scope();
    let revision = fixture_revision();
    let mut service = fixture_service(&scope, revision);
    let proposal = service
        .propose_envelope(proposal_request(&scope, revision, "completed"))
        .expect("proposal");
    let receipt = service
        .project_receipt(
            &proposal,
            &observation(
                &proposal,
                EnvelopeStatus::Completed,
                ProviderProvenance::Fixture,
            ),
        )
        .expect("receipt");

    assert!(receipt.validate_integrity().is_ok());
    assert!(receipt.is_verified_completed());
    assert_eq!(
        service
            .project_envelope_status(&receipt)
            .expect("status projection")
            .status(),
        EnvelopeStatus::Completed
    );
    assert_eq!(
        service
            .project_recipient_statuses(&receipt)
            .expect("recipient projection")
            .len(),
        2
    );
    assert_eq!(
        service
            .project_recipient_statuses(&receipt)
            .expect("recipient projection")[0]
            .routing_order()
            .value(),
        1
    );
    assert_eq!(
        service
            .project_recipient_statuses(&receipt)
            .expect("recipient projection")[1]
            .routing_order()
            .value(),
        2
    );

    let source = SignedResultSource::new(
        scope.project_id().clone(),
        scope.mission_id().clone(),
        proposal.source_result_digest().clone(),
        proposal.source_file_digest().clone(),
        proposal
            .recipients()
            .iter()
            .map(|recipient| recipient.recipient_id().clone()),
        revision,
    )
    .expect("signed-result source");
    let adoption = service
        .propose_signed_result_adoption(&receipt, &source)
        .expect("adoption proposal");
    assert_eq!(adoption.mission_id(), scope.mission_id());
    assert_eq!(adoption.recipient_ids().len(), 2);
    assert_eq!(adoption.provider_version(), DOCUSIGN_PLUGIN_VERSION);
    assert_eq!(
        adoption.registration_digest(),
        proposal.registration_digest()
    );
    assert!(!adoption.claims_connected());
    assert!(!adoption.claims_native());
}

#[test]
fn all_envelope_states_are_distinct_and_projected_without_native_claims() {
    let states = [
        (EnvelopeStatus::Created, "created"),
        (EnvelopeStatus::Sent, "sent"),
        (EnvelopeStatus::Delivered, "delivered"),
        (EnvelopeStatus::Completed, "completed"),
        (EnvelopeStatus::Declined, "declined"),
        (EnvelopeStatus::Voided, "voided"),
        (EnvelopeStatus::ProviderUnknown, "provider_unknown"),
    ];
    for (status, serialized) in states {
        assert_eq!(
            serde_json::to_string(&status).expect("status JSON"),
            format!("\"{serialized}\"")
        );
        let scope = fixture_scope();
        let revision = fixture_revision();
        let mut service = fixture_service(&scope, revision);
        let proposal = service
            .propose_envelope(proposal_request(&scope, revision, serialized))
            .expect("proposal");
        let receipt = service
            .project_receipt(
                &proposal,
                &observation(&proposal, status, ProviderProvenance::Fixture),
            )
            .expect("receipt");
        let projection = service
            .project_envelope_status(&receipt)
            .expect("status projection");
        assert_eq!(projection.status(), status);
        assert!(!projection.claims_connected());
        assert!(!projection.claims_native());
    }
}

#[test]
fn only_verified_completed_envelopes_can_advance_and_stale_sources_are_rejected() {
    let scope = fixture_scope();
    let revision = fixture_revision();
    let mut service = fixture_service(&scope, revision);
    let proposal = service
        .propose_envelope(proposal_request(&scope, revision, "stale"))
        .expect("proposal");
    let receipt = service
        .project_receipt(
            &proposal,
            &observation(&proposal, EnvelopeStatus::Sent, ProviderProvenance::Fixture),
        )
        .expect("sent receipt");
    let source = SignedResultSource::new(
        scope.project_id().clone(),
        scope.mission_id().clone(),
        proposal.source_result_digest().clone(),
        proposal.source_file_digest().clone(),
        proposal
            .recipients()
            .iter()
            .map(|recipient| recipient.recipient_id().clone()),
        revision,
    )
    .expect("source");
    assert!(matches!(
        service.propose_signed_result_adoption(&receipt, &source),
        Err(ServiceError::Consumer(
            hartevo_docusign_signature_plugin::ConsumerError::NotCompleted
        ))
    ));

    let stale_revision = RevisionFence::new(4, 10, 12).expect("stale revision");
    let stale_source = SignedResultSource::new(
        scope.project_id().clone(),
        scope.mission_id().clone(),
        proposal.source_result_digest().clone(),
        proposal.source_file_digest().clone(),
        proposal
            .recipients()
            .iter()
            .map(|recipient| recipient.recipient_id().clone()),
        stale_revision,
    )
    .expect("stale source");
    assert!(matches!(
        service.propose_signed_result_adoption(&receipt, &stale_source),
        Err(ServiceError::Consumer(
            hartevo_docusign_signature_plugin::ConsumerError::StaleRevision
        ))
    ));
}

#[test]
fn tampered_receipts_and_duplicate_fingerprints_fail_closed() {
    let scope = fixture_scope();
    let revision = fixture_revision();
    let mut service = fixture_service(&scope, revision);
    let proposal = service
        .propose_envelope(proposal_request(&scope, revision, "tamper"))
        .expect("proposal");
    let observation = observation(
        &proposal,
        EnvelopeStatus::Completed,
        ProviderProvenance::Fixture,
    );
    let receipt = service
        .project_receipt(&proposal, &observation)
        .expect("receipt");

    let mut tampered = serde_json::to_value(&receipt).expect("receipt JSON");
    tampered["status"] = Value::String("declined".to_owned());
    let tampered = serde_json::from_value(tampered).expect("tampered receipt");
    let source = SignedResultSource::new(
        scope.project_id().clone(),
        scope.mission_id().clone(),
        proposal.source_result_digest().clone(),
        proposal.source_file_digest().clone(),
        proposal
            .recipients()
            .iter()
            .map(|recipient| recipient.recipient_id().clone()),
        revision,
    )
    .expect("source");
    assert!(matches!(
        service.propose_signed_result_adoption(&tampered, &source),
        Err(ServiceError::Consumer(
            hartevo_docusign_signature_plugin::ConsumerError::TamperedReceipt
        ))
    ));

    assert!(matches!(
        service.project_receipt(&proposal, &observation),
        Err(ServiceError::Provider(ProviderError::DuplicateFingerprint))
    ));
}

#[test]
fn receipts_are_redacted_and_never_serialize_signer_pii_or_oauth_material() {
    let scope = fixture_scope();
    let revision = fixture_revision();
    let mut service = fixture_service(&scope, revision);
    let proposal = service
        .propose_envelope(proposal_request(&scope, revision, "redaction"))
        .expect("proposal");
    let receipt = service
        .project_receipt(
            &proposal,
            &observation(
                &proposal,
                EnvelopeStatus::Completed,
                ProviderProvenance::Fixture,
            ),
        )
        .expect("receipt");
    let serialized = serde_json::to_string(&receipt).expect("receipt JSON");
    let debug = format!("{receipt:?}");
    for forbidden in [
        "alice@example.com",
        "bob@example.com",
        "Alice Example",
        "access_token",
        "refresh_token",
        "connect-payload-secret",
    ] {
        assert!(!serialized.contains(forbidden), "found {forbidden} in JSON");
        assert!(!debug.contains(forbidden), "found {forbidden} in Debug");
    }
    assert!(serialized.contains("\"rawConnectPayload\":\"omitted\""));
    assert_eq!(receipt.redaction(), &RedactionSummary::layer1());
}

#[test]
fn registration_is_version_digest_scope_bound_and_reversible() {
    let scope = fixture_scope();
    let revision = fixture_revision();
    let registration = registration(&scope, revision);
    let mut runtime = PluginRuntime::new();
    let receipt = registration.register(&mut runtime).expect("mount");
    assert_eq!(receipt.version(), DOCUSIGN_PLUGIN_VERSION);
    assert_eq!(receipt.scope_digest(), &scope.digest());
    assert_eq!(
        receipt.registration_digest(),
        registration.registration_digest()
    );
    assert_eq!(
        runtime
            .inspect(registration.definition().scope())
            .plugins
            .len(),
        1
    );
    registration
        .unregister(&mut runtime, &receipt)
        .expect("unmount");
    assert!(
        runtime
            .inspect(registration.definition().scope())
            .plugins
            .is_empty()
    );

    let mut runtime = PluginRuntime::new();
    let receipt = registration.register(&mut runtime).expect("remount");
    registration.revoke(&mut runtime, &receipt).expect("revoke");
    assert!(
        runtime
            .inspect(registration.definition().scope())
            .plugins
            .is_empty()
    );
}

#[test]
fn fixture_loopback_blocked_env_and_native_opt_in_are_never_connected_or_native() {
    let scope = fixture_scope();
    let revision = fixture_revision();
    let registration = registration(&scope, revision);
    let secret = secret(&scope);

    let fixture = DocuSignSignatureProvider::from_registration(
        &registration,
        secret.clone(),
        FixtureDocuSignTransport,
    )
    .expect("fixture provider");
    assert_eq!(
        fixture.availability().provenance(),
        &ProviderProvenance::Fixture
    );
    assert_eq!(
        fixture.availability().evidence(),
        NonConnectedEvidence::Fixture
    );
    assert!(!fixture.availability().claims_connected());
    assert!(!fixture.availability().claims_native());

    let loopback = DocuSignSignatureProvider::from_registration(
        &registration,
        secret.clone(),
        LoopbackDocuSignTransport,
    )
    .expect("loopback provider");
    assert_eq!(
        loopback.availability().provenance(),
        &ProviderProvenance::Loopback
    );
    assert!(!loopback.availability().claims_connected());
    assert!(!loopback.availability().claims_native());

    let blocked = DocuSignSignatureProvider::from_registration(
        &registration,
        secret.clone(),
        BlockedEnvDocuSignTransport::new("BLOCKED_ENV"),
    )
    .expect("blocked provider");
    assert_eq!(
        blocked.availability().provenance(),
        &ProviderProvenance::BlockedEnv
    );
    assert_eq!(
        blocked.availability().evidence(),
        NonConnectedEvidence::BlockedEnv
    );
    assert!(!blocked.availability().claims_connected());
    assert!(!blocked.availability().claims_native());

    let native_gap = DocuSignSignatureProvider::from_registration(
        &registration,
        secret,
        NativeOptInDocuSignTransport::new("HARTEVO_DOCUSIGN_NATIVE_LAYER2", true),
    )
    .expect("native-gap provider");
    assert!(matches!(
        native_gap.availability().provenance(),
        ProviderProvenance::NativeLayer2Gap {
            operation: NativeOperation::EnvelopeCreate
        }
    ));
    assert!(!native_gap.availability().claims_connected());
    assert!(!native_gap.availability().claims_native());
}

#[test]
fn bounded_poll_plan_and_explicit_non_connected_failures_are_deterministic() {
    let plan = PollPlan::default();
    assert_eq!(plan.max_attempts(), 5);
    assert_eq!(plan.delays(), vec![2, 4, 8, 16, 32]);
    let capped = PollPlan::new(4, 5, 10).expect("bounded plan");
    assert_eq!(capped.delays(), vec![5, 10, 10, 10]);
    assert!(PollPlan::new(13, 1, 1).is_err());
    assert!(!NonConnectedEvidence::MissingCredentials.claims_connected());
    assert!(!NonConnectedEvidence::AccountMismatch.claims_native());
    assert!(!NonConnectedEvidence::UnsupportedStatus.claims_connected());
    assert!(
        !NonConnectedEvidence::RateLimited {
            retry_after_seconds: 30
        }
        .claims_native()
    );
    assert!(!NonConnectedEvidence::Timeout.claims_connected());
    assert!(
        !NonConnectedEvidence::EventualConsistency {
            retry_after_seconds: 5
        }
        .claims_native()
    );
    assert_eq!(
        DocuSignTransportError::MissingCredentials.non_connected_evidence(),
        NonConnectedEvidence::MissingCredentials
    );
    assert_eq!(
        DocuSignTransportError::AccountMismatch.non_connected_evidence(),
        NonConnectedEvidence::AccountMismatch
    );
    assert_eq!(
        DocuSignTransportError::UnsupportedStatus.non_connected_evidence(),
        NonConnectedEvidence::UnsupportedStatus
    );
    assert_eq!(
        DocuSignTransportError::RateLimited.non_connected_evidence(),
        NonConnectedEvidence::RateLimited {
            retry_after_seconds: 0
        }
    );
    assert_eq!(
        DocuSignTransportError::Timeout.non_connected_evidence(),
        NonConnectedEvidence::Timeout
    );
    assert_eq!(
        DocuSignTransportError::EventualConsistency.non_connected_evidence(),
        NonConnectedEvidence::EventualConsistency {
            retry_after_seconds: 0
        }
    );
}

#[derive(Debug)]
struct CountingTransport {
    calls: Rc<Cell<u32>>,
}

impl DocuSignTransport for CountingTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn execute(
        &mut self,
        request: &hartevo_docusign_signature_plugin::DocuSignHttpRequest,
        _secret_reference: &SecretReference,
    ) -> Result<hartevo_docusign_signature_plugin::DocuSignHttpResponse, DocuSignTransportError>
    {
        self.calls.set(self.calls.get() + 1);
        Err(DocuSignTransportError::Layer2Gap(request.operation()))
    }
}

#[test]
fn layer2_request_seam_fails_closed_without_invoking_transport() {
    let scope = fixture_scope();
    let revision = fixture_revision();
    let registration = registration(&scope, revision);
    let calls = Rc::new(Cell::new(0));
    let mut provider = DocuSignSignatureProvider::from_registration(
        &registration,
        secret(&scope),
        CountingTransport {
            calls: calls.clone(),
        },
    )
    .expect("provider");
    let request = provider.prepare_layer2_request(
        NativeOperation::EnvelopeCreate,
        Digest::from_text("envelope-create-request"),
    );
    assert_eq!(
        provider.execute_layer2(&request),
        Err(ProviderError::Layer2Gap(NativeOperation::EnvelopeCreate))
    );
    assert_eq!(calls.get(), 0);
}

#[test]
fn secret_reference_scope_is_exactly_account_project_and_provider_bound() {
    let scope = fixture_scope();
    let revision = fixture_revision();
    let registration = registration(&scope, revision);
    let mismatched_scope = hartevo_connector_sdk::ConnectorScope::new(
        scope.tenant_id().as_str(),
        scope.project_id().as_str(),
        DOCUSIGN_PROVIDER_ID,
        "account-other",
        ["signature.read".to_owned(), "signature.proposal".to_owned()],
    )
    .expect("mismatched connector scope");
    let mismatched_secret = SecretReference::new("secret-ref-docusign-other", mismatched_scope, 1)
        .expect("mismatched secret");
    assert!(matches!(
        DocuSignSignatureProvider::from_registration(
            &registration,
            mismatched_secret,
            FixtureDocuSignTransport,
        ),
        Err(ProviderError::SecretScopeMismatch)
    ));
}
