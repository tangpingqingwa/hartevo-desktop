use super::*;

fn scope() -> SemanticScholarScope {
    SemanticScholarScope::new(SemanticScholarScopeInput {
        api_host: ApiHost::SemanticScholar,
        api_version: ApiVersion::V1,
        api_key_permission: ApiKeyPermission::AcademicGraphReadKey,
        project_id: ProjectId::new("project-1").expect("project"),
        project_revision: Revision::new(2).expect("project revision"),
        mission_id: MissionId::new("mission-1").expect("mission"),
        mission_revision: Revision::new(3).expect("mission revision"),
        work_product_id: WorkProductId::new("work-product-1").expect("work product"),
        work_product_revision: Revision::new(4).expect("work product revision"),
        consent: ConsentScope::new(
            Digest::from_text("consent-v1"),
            Revision::new(1).expect("consent revision"),
            [
                ConsentDataClass::PaperMetadata,
                ConsentDataClass::AuthorMetadata,
                ConsentDataClass::VenueMetadata,
                ConsentDataClass::CitationMetadata,
            ],
        )
        .expect("consent"),
        paper_ids: [PaperId::new("paper-1").expect("paper")]
            .into_iter()
            .collect(),
        author_ids: [AuthorId::new("author-1").expect("author")]
            .into_iter()
            .collect(),
        venue_ids: [VenueId::new("venue-1").expect("venue")]
            .into_iter()
            .collect(),
        permission_digest: Digest::from_text("permission-v1"),
    })
    .expect("scope")
}

fn secret(scope: &SemanticScholarScope) -> SecretReference {
    SecretReference::new(
        "keyring/semantic-scholar/api-key",
        scope,
        7,
        ApiKeyPermission::AcademicGraphReadKey,
    )
    .expect("secret reference")
}

fn query() -> ResearchQuery {
    ResearchQuery::PaperSearch {
        query: QueryText::new("bounded scientific graph").expect("query"),
        page: PageRequest::first(1).expect("page"),
        fields: FieldSelection::paper_metadata(),
    }
}

fn paper(abstract_state: AbstractState) -> PaperMetadata {
    PaperMetadata::new(PaperMetadataInput {
        paper_id: PaperId::new("paper-1").expect("paper"),
        corpus_id: Some(42),
        title: Some(String::from("A bounded scholarly result")),
        year: Some(2026),
        publication_date: Some(String::from("2026-08-14")),
        venue: Some(VenueMetadataInput {
            venue_id: Some(VenueId::new("venue-1").expect("venue")),
            name: Some(String::from("Safe Venue")),
            kind: VenueKind::Conference,
        }),
        authors: vec![AuthorMetadataInput {
            author_id: AuthorId::new("author-1").expect("author"),
            name: Some(String::from("Indexed Author")),
        }],
        citation_count: Some(12),
        reference_count: Some(8),
        influential_citation_count: Some(2),
        abstract_state,
        retraction_state: RetractionState::NotReported,
    })
    .expect("paper metadata")
}

fn paper_with_id(paper_id: &str, abstract_state: AbstractState) -> PaperMetadata {
    PaperMetadata::new(PaperMetadataInput {
        paper_id: PaperId::new(paper_id).expect("paper"),
        corpus_id: Some(42),
        title: Some(String::from("A bounded scholarly result")),
        year: Some(2026),
        publication_date: Some(String::from("2026-08-14")),
        venue: Some(VenueMetadataInput {
            venue_id: Some(VenueId::new("venue-1").expect("venue")),
            name: Some(String::from("Safe Venue")),
            kind: VenueKind::Conference,
        }),
        authors: vec![AuthorMetadataInput {
            author_id: AuthorId::new("author-1").expect("author"),
            name: Some(String::from("Indexed Author")),
        }],
        citation_count: Some(12),
        reference_count: Some(8),
        influential_citation_count: Some(2),
        abstract_state,
        retraction_state: RetractionState::NotReported,
    })
    .expect("paper metadata")
}

fn paper_response(
    scope: &SemanticScholarScope,
    secret: &SecretReference,
    registration: &SemanticScholarRegistration,
    query: &ResearchQuery,
    records: Vec<PaperMetadata>,
    next_cursor: Option<OpaqueCursor>,
    complete: bool,
) -> SemanticScholarResponse {
    let request = ApiGetRequest::from_query(
        query,
        scope,
        registration.registration_digest.clone(),
        secret.credential_revision(),
    )
    .expect("request");
    SemanticScholarResponse::Paper(
        PaperPage::from_request(&request, records, next_cursor, complete, 512).expect("paper page"),
    )
}

fn service_with_recording() -> (
    SemanticScholarResearchResultService<RecordingSemanticScholarTransport>,
    ResearchQuery,
    SemanticScholarRegistration,
) {
    let scope = scope();
    let secret = secret(&scope);
    let provider =
        SemanticScholarProvider::new(RecordingSemanticScholarTransport::default(), "1.0.0")
            .expect("provider");
    let mut service =
        SemanticScholarResearchResultService::new(scope, secret, provider).expect("service");
    let query = query();
    let registration = service
        .register(query.clone())
        .expect("registration")
        .clone();
    (service, query, registration)
}

#[test]
fn recorded_result_is_redacted_fenced_and_not_native() {
    let (mut service, query, registration) = service_with_recording();
    let response = paper_response(
        service.scope(),
        service.secret_reference(),
        &registration,
        &query,
        vec![paper(AbstractState::Present {
            digest: Digest::from_text("abstract-text-never-retained"),
        })],
        None,
        true,
    );
    service
        .provider_mut()
        .transport_mut()
        .push_response(response);
    let request = SemanticScholarResearchProposalRequest::new(query, &registration);
    let proposal = service.propose(request).expect("proposal");

    assert_eq!(proposal.evidence.status, ResearchResultStatus::Indexed);
    assert_eq!(proposal.evidence.papers.len(), 1);
    assert_eq!(proposal.evidence.retry.attempts, 1);
    assert!(!proposal.connected());
    assert!(!proposal.native());
    assert!(!proposal.truth_authority());
    assert!(!proposal.adopted());
    assert!(!format!("{:?}", service.secret_reference()).contains("keyring/semantic-scholar"));
    let encoded = serde_json::to_string(&proposal.evidence).expect("redacted evidence JSON");
    assert!(!encoded.contains("abstract-text-never-retained"));
    assert!(!encoded.contains("openAccessPdf"));
    assert!(!encoded.contains("rawGraphBody"));

    let consumer =
        MissionSemanticScholarResearchConsumer::new(service.scope().clone(), &registration)
            .expect("consumer");
    let result = consumer.consume(proposal).expect("Mission result");
    assert_eq!(result.state, MissionResearchResultState::PendingDecision);
    assert_eq!(result.adoption, AdoptionAvailability::NotAdoptedLayer2);
    assert!(!result.authority.truth());
}

#[test]
fn no_abstract_and_retraction_states_are_explicit() {
    let (mut service, query, registration) = service_with_recording();
    let result = paper_with_retraction(AbstractState::NoAbstract, RetractionState::Unknown);
    let scope_snapshot = service.scope().clone();
    let secret_snapshot = service.secret_reference().clone();
    let response = paper_response(
        &scope_snapshot,
        &secret_snapshot,
        &registration,
        &query,
        vec![result],
        None,
        true,
    );
    service
        .provider_mut()
        .transport_mut()
        .push_response(response);
    let proposal = service
        .propose(SemanticScholarResearchProposalRequest::new(
            query,
            &registration,
        ))
        .expect("proposal");
    assert_eq!(
        proposal.evidence.status,
        ResearchResultStatus::RetractedOrUnknown
    );
}

fn paper_with_retraction(
    abstract_state: AbstractState,
    retraction_state: RetractionState,
) -> PaperMetadata {
    let input = PaperMetadataInput {
        paper_id: PaperId::new("paper-1").expect("paper"),
        corpus_id: Some(42),
        title: Some(String::from("A bounded scholarly result")),
        year: Some(2026),
        publication_date: Some(String::from("2026-08-14")),
        venue: Some(VenueMetadataInput {
            venue_id: Some(VenueId::new("venue-1").expect("venue")),
            name: Some(String::from("Safe Venue")),
            kind: VenueKind::Conference,
        }),
        authors: vec![AuthorMetadataInput {
            author_id: AuthorId::new("author-1").expect("author"),
            name: Some(String::from("Indexed Author")),
        }],
        citation_count: Some(12),
        reference_count: Some(8),
        influential_citation_count: Some(2),
        abstract_state,
        retraction_state,
    };
    PaperMetadata::new(input).expect("paper metadata")
}

#[test]
fn scope_drift_and_response_tamper_fail_closed() {
    let (mut service, query, registration) = service_with_recording();
    let out_of_scope = paper_with_id("paper-2", AbstractState::NoAbstract);
    let scope_snapshot = service.scope().clone();
    let secret_snapshot = service.secret_reference().clone();
    let response = paper_response(
        &scope_snapshot,
        &secret_snapshot,
        &registration,
        &query,
        vec![out_of_scope],
        None,
        true,
    );
    service
        .provider_mut()
        .transport_mut()
        .push_response(response);
    let error = service
        .propose(SemanticScholarResearchProposalRequest::new(
            query.clone(),
            &registration,
        ))
        .expect_err("scope drift");
    assert_eq!(error, ServiceError::ScopeMismatch);

    let (mut service, query, registration) = service_with_recording();
    let mut response = paper_response(
        service.scope(),
        service.secret_reference(),
        &registration,
        &query,
        vec![paper(AbstractState::NoAbstract)],
        None,
        true,
    );
    if let SemanticScholarResponse::Paper(page) = &mut response {
        page.response_digest = Digest::from_text("tampered-response");
    }
    service
        .provider_mut()
        .transport_mut()
        .push_response(response);
    assert!(matches!(
        service.propose(SemanticScholarResearchProposalRequest::new(
            query,
            &registration
        )),
        Err(ServiceError::Provider(ProviderError::ResponseTampered))
    ));
}

#[test]
fn bounded_rate_retry_and_cursor_loop_are_visible_or_rejected() {
    let (mut service, query, registration) = service_with_recording();
    let response = paper_response(
        service.scope(),
        service.secret_reference(),
        &registration,
        &query,
        vec![paper(AbstractState::NoAbstract)],
        None,
        true,
    );
    service
        .provider_mut()
        .transport_mut()
        .push_error(TransportError::RateLimited {
            retry_after_seconds: Some(2),
        });
    service
        .provider_mut()
        .transport_mut()
        .push_response(response);
    let proposal = service
        .propose(SemanticScholarResearchProposalRequest::new(
            query.clone(),
            &registration,
        ))
        .expect("bounded retry");
    assert_eq!(proposal.evidence.status, ResearchResultStatus::NoAbstract);
    assert_eq!(proposal.evidence.retry.attempts, 2);
    assert_eq!(proposal.evidence.retry.retry_after_seconds, Some(2));

    let (mut service, query, registration) = service_with_recording();
    let cursor = OpaqueCursor::new("cursor-1").expect("cursor");
    let first = paper_response(
        service.scope(),
        service.secret_reference(),
        &registration,
        &query,
        vec![paper(AbstractState::NoAbstract)],
        Some(cursor.clone()),
        false,
    );
    let second_query = match query.clone() {
        ResearchQuery::PaperSearch {
            query,
            page,
            fields,
        } => ResearchQuery::PaperSearch {
            query,
            page: PageRequest::new(page.limit(), 0, Some(cursor.clone())).expect("page"),
            fields,
        },
        _ => unreachable!("fixture query is paper search"),
    };
    let second = paper_response(
        service.scope(),
        service.secret_reference(),
        &registration,
        &second_query,
        Vec::new(),
        Some(cursor),
        false,
    );
    service.provider_mut().transport_mut().push_response(first);
    service.provider_mut().transport_mut().push_response(second);
    assert_eq!(
        service
            .propose(SemanticScholarResearchProposalRequest::new(
                query,
                &registration
            ))
            .expect_err("cursor loop")
            .to_string(),
        "the bounded cursor repeated before the provider marked the response complete"
    );
}

#[test]
fn blocked_environment_never_claims_connected_or_native() {
    let scope = scope();
    let secret = secret(&scope);
    let provider = SemanticScholarProvider::new(BlockedEnvTransport, "1.0.0").expect("provider");
    assert!(!provider.connected());
    assert!(!provider.native());
    let mut service =
        SemanticScholarResearchResultService::new(scope, secret, provider).expect("service");
    let query = query();
    let registration = service
        .register(query.clone())
        .expect("registration")
        .clone();
    let proposal = service
        .propose(SemanticScholarResearchProposalRequest::new(
            query,
            &registration,
        ))
        .expect("blocked proposal");
    assert_eq!(
        proposal.evidence.status,
        ResearchResultStatus::ProviderUnknown
    );
    assert_eq!(
        proposal
            .evidence
            .provider_error
            .as_ref()
            .expect("blocked error")
            .code,
        "BLOCKED_ENV"
    );
    assert!(!proposal.connected());
    assert!(!proposal.native());
}
