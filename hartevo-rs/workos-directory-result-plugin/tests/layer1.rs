use hartevo_workos_directory_result_plugin::*;

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("positive revision")
}

fn scope(filter: MembershipFilter) -> WorkOsDirectoryScope {
    WorkOsDirectoryScope::new(
        OrganizationId::new("org_01HXYZ123456789ABCDEFGHIJ").expect("organization id"),
        DirectoryId::new("directory_01HXYZ123456789ABCDEFGHIJ").expect("directory id"),
        ConnectionId::new("conn_01HXYZ123456789ABCDEFGHIJ").expect("connection id"),
        filter,
        Project::new("project_workos", revision(2)).expect("project"),
        Mission::new("mission_directory", revision(3)).expect("mission"),
        Consent::new("consent_directory_read", revision(4)).expect("consent"),
        Digest::from_text("directory.read.filtered"),
    )
    .expect("scope")
}

fn provider_revision() -> ProviderRevision {
    ProviderRevision::new("workos-directory-sync-api-v1").expect("provider revision")
}

fn connection(scope: &WorkOsDirectoryScope) -> ConnectionRecord {
    ConnectionRecord::new(
        scope.organization_id.clone(),
        scope.connection_id.clone(),
        ConnectionState::Active,
        Digest::from_text("OktaSAML"),
        Some(Digest::from_text("Example Directory")),
        Some(Digest::from_text("example.com")),
        provider_revision(),
    )
    .expect("connection")
}

fn directory(scope: &WorkOsDirectoryScope, state: DirectoryState) -> DirectoryRecord {
    DirectoryRecord::new(
        scope.organization_id.clone(),
        scope.directory_id.clone(),
        state,
        Digest::from_text("okta_directory"),
        Some(Digest::from_text("external-key")),
        Some(3),
        Some(1),
        Some(2),
        provider_revision(),
    )
    .expect("directory")
}

fn user(scope: &WorkOsDirectoryScope, id: &str, state: UserState) -> DirectoryUserRecord {
    DirectoryUserRecord::from_provider_fields(
        scope.organization_id.clone(),
        scope.directory_id.clone(),
        DirectoryUserId::new(id).expect("user id"),
        state,
        "idp-2836",
        Some("jane@example.com"),
        Some("Jane Doe"),
        Some("department=Engineering"),
        provider_revision(),
    )
    .expect("user")
}

fn group(scope: &WorkOsDirectoryScope, id: &str, state: GroupState) -> DirectoryGroupRecord {
    DirectoryGroupRecord::from_provider_fields(
        scope.organization_id.clone(),
        scope.directory_id.clone(),
        DirectoryGroupId::new(id).expect("group id"),
        state,
        "idp-group-1",
        Some("Engineering"),
        Some("sensitivity=internal"),
        provider_revision(),
    )
    .expect("group")
}

fn service_for_group_filter() -> (WorkOsDirectoryResultService, WorkOsDirectoryScope) {
    let group_id = DirectoryGroupId::new("directory_group_01HXYZ123456789ABCDEFGHIJ")
        .expect("group filter id");
    let scope = scope(MembershipFilter::ByGroup(group_id.clone()));
    let first_user = user(
        &scope,
        "directory_user_01HXYZ123456789ABCDEFGH1",
        UserState::Active,
    );
    let second_user = user(
        &scope,
        "directory_user_01HXYZ123456789ABCDEFGH2",
        UserState::Inactive,
    );
    let operation = PageOperation::UsersByGroup(group_id);
    let cursor = PageCursor::after("opaque-after-page-1", &scope, operation.clone(), 1_000, 300)
        .expect("cursor");
    let first_page = WorkOsDirectoryPage::new(
        operation.clone(),
        vec![first_user],
        vec![],
        None,
        Some(cursor),
        provider_revision(),
        180,
        false,
    )
    .expect("first page");
    let second_page = WorkOsDirectoryPage::new(
        operation,
        vec![second_user],
        vec![],
        None,
        None,
        provider_revision(),
        180,
        true,
    )
    .expect("second page");
    let provider = WorkOsDirectoryProvider::fixture(WorkOsDirectoryFixture::with_pages(
        provider_revision(),
        connection(&scope),
        directory(&scope, DirectoryState::Linked),
        [first_page, second_page],
    ));
    let secret = SecretReference::new_api_key(
        "secret_ref_workos_1",
        revision(1),
        scope.scope_digest().clone(),
    )
    .expect("opaque API-key reference");
    let service = WorkOsDirectoryResultService::register(
        provider,
        "registration_workos_1",
        scope.clone(),
        secret,
    )
    .expect("service registration");
    (service, scope)
}

#[test]
fn bounded_filtered_evidence_is_redacted_and_recorded() {
    let (mut service, scope) = service_for_group_filter();
    assert!(!service.is_connected());
    assert!(!service.is_native());
    assert_eq!(service.provider().provenance(), ProviderProvenance::Fixture);
    assert!(!service.provider().is_connected());
    assert!(!service.provider().is_native());

    let evidence = service
        .read_directory_evidence(ReadBounds {
            now_epoch_seconds: 1_050,
            ..ReadBounds::default()
        })
        .expect("bounded evidence");
    assert_eq!(evidence.status, EvidenceStatus::UserDeactivated);
    assert_eq!(evidence.membership.pages_observed, 2);
    assert_eq!(evidence.membership.users.len(), 2);
    assert_eq!(evidence.membership.memberships.len(), 2);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.raw_idp_attributes_retained);
    assert!(!evidence.raw_email_retained);
    assert!(!evidence.raw_name_retained);
    assert!(evidence.verify_integrity().is_ok());

    let json = serde_json::to_string(&evidence).expect("safe evidence serializes");
    assert!(!json.contains("jane@example.com"));
    assert!(!json.contains("Jane Doe"));
    assert!(!json.contains("Engineering"));
    assert!(!json.contains("opaque-after-page-1"));

    let proposal = service
        .compile_evidence_proposal(evidence)
        .expect("proposal");
    service.verify_proposal(&proposal).expect("proposal fences");
    let record = service.record_proposal(&proposal).expect("record");
    let read_back = service.read_back_record(&record).expect("read back");
    assert!(read_back.verified);
    assert!(!read_back.independent_provider_reread);
    assert!(!read_back.connected);
    assert!(!read_back.native);
    assert_eq!(read_back.scope_digest, *scope.scope_digest());
    assert!(service.record_proposal(&proposal).is_err());
}

#[test]
fn user_filtered_groups_are_scoped_and_consumer_rejects_stale_mission() {
    let user_id =
        DirectoryUserId::new("directory_user_01HXYZ123456789ABCDEFGHIJ").expect("user filter id");
    let scope = scope(MembershipFilter::ByUser(user_id.clone()));
    let operation = PageOperation::GroupsByUser(user_id);
    let page = WorkOsDirectoryPage::new(
        operation,
        vec![],
        vec![group(
            &scope,
            "directory_group_01HXYZ123456789ABCDEFGH1",
            GroupState::Active,
        )],
        None,
        None,
        provider_revision(),
        220,
        true,
    )
    .expect("group page");
    let provider = WorkOsDirectoryProvider::recording(WorkOsDirectoryFixture::with_pages(
        provider_revision(),
        connection(&scope),
        directory(&scope, DirectoryState::Linked),
        [page],
    ));
    let secret = SecretReference::new(
        "secret_ref_workos_2",
        revision(1),
        scope.scope_digest().clone(),
    )
    .expect("secret reference");
    let service = WorkOsDirectoryResultService::register(
        provider,
        "registration_workos_2",
        scope.clone(),
        secret,
    )
    .expect("service");
    let consumer = MissionWorkOsDirectoryConsumer::new(service);
    let context = MissionWorkOsDirectoryContext::new(
        scope.project.clone(),
        scope.mission.clone(),
        scope.consent.clone(),
    );
    let evidence = consumer
        .inspect(&context, ReadBounds::default())
        .expect("mission evidence");
    assert_eq!(evidence.status, EvidenceStatus::Complete);
    assert_eq!(evidence.membership.groups.len(), 1);
    let adoption = consumer
        .consume(&context, evidence.clone())
        .expect("consumer proposal");
    assert!(!adoption.adopted);
    assert!(!adoption.kernel_identity_authority);
    assert!(!adoption.kernel_consent_authority);
    assert!(!adoption.effect_authority);
    assert!(!adoption.connected);
    assert!(!adoption.native);

    let stale = MissionWorkOsDirectoryContext::new(
        scope.project,
        Mission::new("mission_directory", revision(99)).expect("stale mission"),
        scope.consent,
    );
    assert_eq!(
        consumer.inspect(&stale, ReadBounds::default()),
        Err(WorkOsDirectoryResultError::ScopeMismatch)
    );
}

#[test]
fn cursor_replay_and_expiry_fail_closed() {
    let group_id =
        DirectoryGroupId::new("directory_group_01HXYZ123456789ABCDEFGHIJ").expect("group id");
    let scope = scope(MembershipFilter::ByGroup(group_id.clone()));
    let operation = PageOperation::UsersByGroup(group_id);
    let replay_cursor =
        PageCursor::after("same-cursor", &scope, operation.clone(), 1_735_689_500, 300)
            .expect("replay cursor");
    let first_page = WorkOsDirectoryPage::new(
        operation.clone(),
        vec![user(
            &scope,
            "directory_user_01HXYZ123456789ABCDEFGH1",
            UserState::Active,
        )],
        vec![],
        None,
        Some(replay_cursor.clone()),
        provider_revision(),
        100,
        false,
    )
    .expect("first replay page");
    let second_page = WorkOsDirectoryPage::new(
        operation.clone(),
        vec![user(
            &scope,
            "directory_user_01HXYZ123456789ABCDEFGH2",
            UserState::Active,
        )],
        vec![],
        None,
        Some(replay_cursor),
        provider_revision(),
        100,
        false,
    )
    .expect("second replay page");
    let provider = WorkOsDirectoryProvider::loopback(WorkOsDirectoryFixture::with_pages(
        provider_revision(),
        connection(&scope),
        directory(&scope, DirectoryState::Linked),
        [first_page, second_page],
    ));
    let secret = SecretReference::new_api_key(
        "secret_ref_workos_3",
        revision(1),
        scope.scope_digest().clone(),
    )
    .expect("secret reference");
    let service = WorkOsDirectoryResultService::register(
        provider,
        "registration_workos_3",
        scope.clone(),
        secret,
    )
    .expect("service");
    assert_eq!(
        service.read_filtered_memberships(ReadBounds::default()),
        Err(WorkOsDirectoryResultError::CursorReplay)
    );

    let expired_cursor =
        PageCursor::after("expired-cursor", &scope, operation, 10, 1).expect("expired cursor");
    let empty_provider = WorkOsDirectoryProvider::fixture(WorkOsDirectoryFixture::with_pages(
        provider_revision(),
        connection(&scope),
        directory(&scope, DirectoryState::Linked),
        std::iter::empty::<WorkOsDirectoryPage>(),
    ));
    let expired_service = WorkOsDirectoryResultService::register(
        empty_provider,
        "registration_workos_4",
        scope,
        SecretReference::new_api_key(
            "secret_ref_workos_4",
            revision(1),
            expired_cursor.scope_digest().clone(),
        )
        .expect("expired secret reference"),
    )
    .expect("expired service");
    let expired_bounds = ReadBounds {
        now_epoch_seconds: 12,
        ..ReadBounds::default().with_initial_cursor(expired_cursor)
    };
    assert_eq!(
        expired_service.read_filtered_memberships(expired_bounds),
        Err(WorkOsDirectoryResultError::CursorExpired)
    );
}

#[test]
fn status_errors_deactivation_tamper_and_reversal_are_explicit() {
    let group_id =
        DirectoryGroupId::new("directory_group_01HXYZ123456789ABCDEFGHIJ").expect("group id");
    let scope = scope(MembershipFilter::ByGroup(group_id.clone()));
    let page = WorkOsDirectoryPage::new(
        PageOperation::UsersByGroup(group_id),
        vec![],
        vec![],
        None,
        None,
        provider_revision(),
        100,
        true,
    )
    .expect("empty page");
    let provider = WorkOsDirectoryProvider::fixture(WorkOsDirectoryFixture::new(
        provider_revision(),
        connection(&scope),
        directory(&scope, DirectoryState::Deleting),
        [Err(ProviderError::http_status(401)), Ok(page)],
    ));
    let secret = SecretReference::new_api_key(
        "secret_ref_workos_5",
        revision(1),
        scope.scope_digest().clone(),
    )
    .expect("secret reference");
    let mut service =
        WorkOsDirectoryResultService::register(provider, "registration_workos_5", scope, secret)
            .expect("service");
    let first_error = service
        .read_directory_evidence(ReadBounds::default())
        .expect_err("401 must not become evidence");
    assert!(matches!(
        first_error,
        WorkOsDirectoryResultError::Provider(ProviderError::Unauthorized { status: 401, .. })
    ));

    service.reverse_registration().expect("reverse");
    assert_eq!(
        service.read_directory(),
        Err(WorkOsDirectoryResultError::RegistrationInactive)
    );
    service.restore_registration().expect("restore");
    service.revoke_secret_reference();
    assert_eq!(
        service.read_directory(),
        Err(WorkOsDirectoryResultError::SecretReferenceRevoked)
    );
}

#[test]
fn blocked_environment_never_reports_native_or_connected() {
    let group_id =
        DirectoryGroupId::new("directory_group_01HXYZ123456789ABCDEFGHIJ").expect("group id");
    let scope = scope(MembershipFilter::ByGroup(group_id));
    let provider = WorkOsDirectoryProvider::blocked_env();
    assert_eq!(provider.provenance(), ProviderProvenance::BlockedEnv);
    assert!(!provider.is_connected());
    assert!(!provider.is_native());
    let service = WorkOsDirectoryResultService::register(
        provider,
        "registration_workos_blocked",
        scope.clone(),
        SecretReference::new_api_key(
            "secret_ref_workos_blocked",
            revision(1),
            scope.scope_digest().clone(),
        )
        .expect("secret reference"),
    )
    .expect("blocked service registration");
    assert!(!service.is_connected());
    assert!(!service.is_native());
    assert!(matches!(
        service.read_directory(),
        Err(WorkOsDirectoryResultError::Provider(
            ProviderError::BlockedEnv
        ))
    ));
}

#[test]
fn provider_auth_conflict_rate_limit_server_and_timeout_states_stay_typed() {
    let errors = [
        ProviderError::http_status(403),
        ProviderError::http_status(404),
        ProviderError::http_status(409),
        ProviderError::http_status(429),
        ProviderError::http_status(500),
        ProviderError::timeout(),
    ];
    for (index, expected) in errors.into_iter().enumerate() {
        let group_id =
            DirectoryGroupId::new(format!("directory_group_01HXYZ123456789ABCDEFG{index:02}"))
                .expect("group id");
        let scope = scope(MembershipFilter::ByGroup(group_id));
        let provider = WorkOsDirectoryProvider::fixture(WorkOsDirectoryFixture::new(
            provider_revision(),
            connection(&scope),
            directory(&scope, DirectoryState::Linked),
            [Err(expected.clone())],
        ));
        let service = WorkOsDirectoryResultService::register(
            provider,
            format!("registration_error_{index}"),
            scope.clone(),
            SecretReference::new_api_key(
                format!("secret_ref_error_{index}"),
                revision(1),
                scope.scope_digest().clone(),
            )
            .expect("secret reference"),
        )
        .expect("service");
        let actual = service
            .read_filtered_memberships(ReadBounds::default())
            .expect_err("typed provider error");
        match actual {
            WorkOsDirectoryResultError::Provider(actual) => {
                assert_eq!(actual.status_code(), expected.status_code());
                assert_eq!(actual.is_retryable(), expected.is_retryable());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
