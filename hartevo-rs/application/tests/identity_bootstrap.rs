use std::collections::BTreeSet;
use std::sync::Mutex;

use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_application::{
    ApplicationError, ApplicationService, BeginOidcAuthorization, CompleteIdentityBootstrap,
};
use hartevo_domain_kernel::{
    DeviceId, IdentityAccessMode, IdentityAccount, IdentityBootstrapSnapshot, IdentityMembership,
    IdentityProject, IdentityProviderError, IdentitySessionError, IdentitySessionStatus,
    IdentityTeam, KEYCLOAK_PROVIDER_ID, OidcAuthorizationCallback, OidcIdentityProvider,
    OidcProviderConfiguration, OidcTokenSet, PkceCodeVerifier, ProjectEncryptionMode, ProjectId,
    StorageMode, TeamId, TenantId,
};
use hartevo_storage::{
    DatabaseKey, MemorySecretStore, OsSecretStore, ProjectStore, SecretBytes, SecretReference,
    SecretStore,
};
use sha2::{Digest, Sha256};

const ISSUER: &str = "https://sso.example.test/realms/hartevo";
const TENANT_ID: &str = "tenant-id-01";
const ACCOUNT_ID: &str = "account-id-01";
const TEAM_ID: &str = "team-id-01";
const MEMBER_ID: &str = "member-id-01";
const PROJECT_ID: &str = "project-id-01";
const DEVICE_ID: &str = "device-id-01";

#[derive(Debug)]
struct FakeIdp {
    configuration: OidcProviderConfiguration,
    snapshot: IdentityBootstrapSnapshot,
    initial_tokens: OidcTokenSet,
    refreshed_tokens: OidcTokenSet,
    expected_code_challenge: Mutex<Option<String>>,
    revoked_refresh_tokens: Mutex<Vec<String>>,
}

impl FakeIdp {
    fn new(now: DateTime<Utc>) -> Self {
        let subject_digest = digest("fake-subject");
        let account = IdentityAccount::new(
            ACCOUNT_ID.into(),
            TENANT_ID.into(),
            ISSUER,
            subject_digest.clone(),
            "Founder",
            Some(digest("founder@example.test")),
        )
        .expect("account");
        let team = IdentityTeam::new(TEAM_ID.into(), TENANT_ID.into(), "Growth").expect("team");
        let membership = IdentityMembership::new(
            MEMBER_ID.into(),
            TENANT_ID.into(),
            TEAM_ID.into(),
            ACCOUNT_ID.into(),
            "owner",
        )
        .expect("membership");
        let project = IdentityProject::new(
            PROJECT_ID.into(),
            TENANT_ID.into(),
            TEAM_ID.into(),
            "Launch",
            "Launch project",
        )
        .expect("project");
        let snapshot = IdentityBootstrapSnapshot::new(
            ISSUER,
            subject_digest,
            account,
            vec![team],
            vec![membership],
            vec![project],
        )
        .expect("snapshot");
        let configuration =
            OidcProviderConfiguration::keycloak(ISSUER, "hartevo-desktop-test").expect("config");
        let initial_tokens = OidcTokenSet::new(
            "fake-access-token-1",
            "fake-refresh-token-1",
            now + Duration::hours(1),
            now + Duration::hours(2),
        )
        .expect("initial tokens");
        let refreshed_tokens = OidcTokenSet::new(
            "fake-access-token-2",
            "fake-refresh-token-2",
            now + Duration::hours(3),
            now + Duration::hours(6),
        )
        .expect("refreshed tokens");
        Self {
            configuration,
            snapshot,
            initial_tokens,
            refreshed_tokens,
            expected_code_challenge: Mutex::new(None),
            revoked_refresh_tokens: Mutex::new(Vec::new()),
        }
    }

    fn set_expected_code_challenge(&self, challenge: String) {
        *self.expected_code_challenge.lock().expect("challenge lock") = Some(challenge);
    }

    fn revoked_refresh_tokens(&self) -> Vec<String> {
        self.revoked_refresh_tokens
            .lock()
            .expect("revocation lock")
            .clone()
    }
}

impl OidcIdentityProvider for FakeIdp {
    fn configuration(&self) -> &OidcProviderConfiguration {
        &self.configuration
    }

    fn exchange_code(
        &self,
        callback: &OidcAuthorizationCallback,
        code_verifier: &PkceCodeVerifier,
    ) -> Result<OidcTokenSet, IdentityProviderError> {
        let expected_challenge = self
            .expected_code_challenge
            .lock()
            .map_err(|_| IdentityProviderError::AuthorizationCodeRejected)?
            .clone();
        if callback.code != "fake-authorization-code"
            || callback.issuer_url != self.configuration.issuer_url
            || expected_challenge.as_deref() != Some(code_verifier.challenge().as_str())
        {
            return Err(IdentityProviderError::AuthorizationCodeRejected);
        }
        Ok(self.initial_tokens.clone())
    }

    fn bootstrap(
        &self,
        tokens: &OidcTokenSet,
    ) -> Result<IdentityBootstrapSnapshot, IdentityProviderError> {
        if tokens.access_token() != self.initial_tokens.access_token()
            && tokens.access_token() != self.refreshed_tokens.access_token()
        {
            return Err(IdentityProviderError::BootstrapUnavailable);
        }
        Ok(self.snapshot.clone())
    }

    fn refresh(&self, refresh_token: &str) -> Result<OidcTokenSet, IdentityProviderError> {
        if refresh_token != self.initial_tokens.refresh_token() {
            return Err(IdentityProviderError::RefreshFailed);
        }
        Ok(self.refreshed_tokens.clone())
    }

    fn revoke(&self, refresh_token: &str) -> Result<(), IdentityProviderError> {
        self.revoked_refresh_tokens
            .lock()
            .map_err(|_| IdentityProviderError::RevocationFailed)?
            .push(refresh_token.to_owned());
        Ok(())
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the scoped E2E intentionally keeps bootstrap, restart, offline, expiry, and revocation assertions in one product journey"
)]
fn fake_idp_bootstrap_restart_refresh_offline_expiry_and_revoke_are_fenced() {
    let now = Utc
        .with_ymd_and_hms(2026, 8, 13, 9, 0, 0)
        .single()
        .expect("fixed test time");
    let fixture_root = tempfile::tempdir().expect("fixture root");
    let database_path = fixture_root.path().join("identity.sqlite3");
    let database_key = DatabaseKey::new([7; 32]).expect("database key");
    let secret_store = MemorySecretStore::default();
    let provider = FakeIdp::new(now);

    let (project_id, session_id, initial_scope) = {
        let store = ProjectStore::open(&database_path, &database_key).expect("fresh store");
        let mut service = ApplicationService::new(store);
        let attempt = service
            .begin_oidc_authorization(BeginOidcAuthorization {
                provider: provider.configuration.clone(),
                redirect_uri: "https://desktop.example.test/callback".into(),
                scopes: BTreeSet::new(),
            })
            .expect("authorization attempt");
        assert!(
            attempt
                .request()
                .authorization_url()
                .expect("authorization URL")
                .contains("code_challenge_method=S256")
        );
        provider.set_expected_code_challenge(attempt.request().code_challenge().to_owned());
        let callback = OidcAuthorizationCallback {
            code: "fake-authorization-code".into(),
            state: attempt.request().state().into(),
            issuer_url: ISSUER.into(),
            nonce: attempt.request().nonce().into(),
        };
        let result = service
            .complete_oidc_identity_bootstrap(
                &secret_store,
                &provider,
                &attempt,
                &callback,
                CompleteIdentityBootstrap {
                    selected_team_id: TeamId::from(TEAM_ID),
                    selected_project_id: ProjectId::from(PROJECT_ID),
                    workspace_root: fixture_root.path().join("workspace"),
                    storage_mode: StorageMode::LocalExisting,
                    device_id: DeviceId::from(DEVICE_ID),
                    encryption_mode: ProjectEncryptionMode::TeamEnvelope,
                    recovery_recipient_id: None,
                    user_recovery_secret: None,
                    recovery_confirmed: false,
                },
                now,
            )
            .expect("identity bootstrap");
        let callback_debug = format!("{callback:?}");
        assert!(!callback_debug.contains("fake-authorization-code"));
        assert_eq!(
            result.identity.session.status,
            IdentitySessionStatus::Online
        );
        assert_eq!(
            result.identity.session.scope.tenant_id,
            TenantId::from(TENANT_ID)
        );
        assert_eq!(result.identity.session.scope.team_id, TeamId::from(TEAM_ID));
        assert_eq!(
            result.identity.session.scope.project_id,
            ProjectId::from(PROJECT_ID)
        );
        assert_eq!(
            result.identity.session.scope.device_id,
            DeviceId::from(DEVICE_ID)
        );
        assert_eq!(secret_store.entry_count().expect("secret count"), 4);
        let debug = format!("{provider:?}");
        assert!(!debug.contains("fake-access-token-1"));
        assert!(!debug.contains("fake-refresh-token-1"));
        (
            result.project.id,
            result.identity.session.id,
            result.identity.session.scope,
        )
    };

    let mut service = ApplicationService::new(
        ProjectStore::open(&database_path, &database_key).expect("restart store"),
    );
    let refreshed = service
        .refresh_identity_session(
            &secret_store,
            &provider,
            &project_id,
            &session_id,
            now + Duration::minutes(5),
        )
        .expect("refresh session");
    assert_eq!(refreshed.status, IdentitySessionStatus::Online);
    assert_eq!(refreshed.revision, 2);
    assert_eq!(secret_store.entry_count().expect("rotated secret count"), 4);
    drop(service);

    let mut service = ApplicationService::new(
        ProjectStore::open(&database_path, &database_key).expect("offline restart store"),
    );
    let offline = service
        .reopen_identity_session_offline(
            &secret_store,
            &project_id,
            &session_id,
            now + Duration::minutes(10),
        )
        .expect("offline reopen");
    assert_eq!(offline.session.status, IdentitySessionStatus::Offline);
    assert_eq!(offline.session.revision, 3);
    let local = service
        .authorize_local_identity_scope(
            &secret_store,
            &project_id,
            &session_id,
            &offline.session.scope,
            now + Duration::minutes(10),
        )
        .expect("offline local authorization");
    assert_eq!(local.mode, IdentityAccessMode::Offline);
    let missing_binding_store = MemorySecretStore::default();
    let binding_error = service
        .authorize_local_identity_scope(
            &missing_binding_store,
            &project_id,
            &session_id,
            &offline.session.scope,
            now + Duration::minutes(10),
        )
        .expect_err("missing device binding must block local authorization");
    assert!(matches!(
        binding_error,
        ApplicationError::IdentityDeviceBindingUnavailable
    ));
    let cloud_error = service
        .authorize_cloud_identity_scope(
            &secret_store,
            &project_id,
            &session_id,
            &offline.session.scope,
            now + Duration::minutes(10),
        )
        .expect_err("offline cloud authorization must be blocked");
    assert!(matches!(
        cloud_error,
        ApplicationError::IdentitySession(IdentitySessionError::OfflineCloudUnavailable)
    ));
    let mut other_tenant_scope = initial_scope.clone();
    other_tenant_scope.tenant_id = TenantId::from("tenant-other");
    let scope_error = service
        .authorize_local_identity_scope(
            &secret_store,
            &project_id,
            &session_id,
            &other_tenant_scope,
            now + Duration::minutes(10),
        )
        .expect_err("cross-tenant scope must be blocked");
    assert!(matches!(
        scope_error,
        ApplicationError::IdentitySession(IdentitySessionError::ScopeMismatch)
    ));
    drop(service);

    let mut service = ApplicationService::new(
        ProjectStore::open(&database_path, &database_key).expect("expiry restart store"),
    );
    let expiry_error = service
        .reopen_identity_session_offline(
            &secret_store,
            &project_id,
            &session_id,
            now + Duration::hours(7),
        )
        .expect_err("expired offline reopen must fail closed");
    assert!(matches!(
        expiry_error,
        ApplicationError::IdentitySession(IdentitySessionError::Expired)
    ));
    let revoked = service
        .revoke_identity_session(
            &secret_store,
            &provider,
            &project_id,
            &session_id,
            now + Duration::hours(7),
        )
        .expect("durable revoke");
    assert_eq!(revoked.session.status, IdentitySessionStatus::Revoked);
    assert_eq!(revoked.session.revision, 5);
    assert!(!revoked.remote_revocation_pending);
    assert_eq!(
        provider.revoked_refresh_tokens(),
        vec!["fake-refresh-token-2".to_owned()]
    );
    assert_eq!(secret_store.entry_count().expect("revoked secret count"), 2);
    let revoked_error = service
        .authorize_local_identity_scope(
            &secret_store,
            &project_id,
            &session_id,
            &offline.session.scope,
            now + Duration::hours(7),
        )
        .expect_err("revoked identity must not authorize local work");
    assert!(matches!(
        revoked_error,
        ApplicationError::IdentitySession(IdentitySessionError::Revoked)
    ));
    drop(service);

    let reopened = ProjectStore::open(&database_path, &database_key).expect("event store");
    let events = reopened
        .events_for_project(&project_id)
        .expect("identity events");
    let event_text = serde_json::to_string(&events).expect("event JSON");
    assert!(event_text.contains("identity_session.authorized"));
    assert!(event_text.contains("identity_session.refreshed"));
    assert!(event_text.contains("identity_session.offline_reopened"));
    assert!(event_text.contains("identity_session.expired"));
    assert!(event_text.contains("identity_session.revoked"));
    assert!(!event_text.contains("fake-access-token-1"));
    assert!(!event_text.contains("fake-access-token-2"));
    assert!(!event_text.contains("fake-refresh-token-1"));
    assert!(!event_text.contains("fake-refresh-token-2"));
}

#[test]
#[ignore = "requires HARTEVO_IDENTITY_NATIVE_PROBE=1 and an available native OS secret store"]
fn native_os_secret_store_probe_is_explicitly_env_gated() {
    assert_eq!(
        std::env::var("HARTEVO_IDENTITY_NATIVE_PROBE").as_deref(),
        Ok("1"),
        "BLOCKED_ENV: set HARTEVO_IDENTITY_NATIVE_PROBE=1 to run the native vault probe"
    );
    let store = OsSecretStore::new("hartevo-id01-native-probe").expect("native secret store");
    let reference = SecretReference {
        tenant_id: TenantId::from("native-probe-tenant"),
        project_id: ProjectId::from("native-probe-project"),
        provider: KEYCLOAK_PROVIDER_ID.into(),
        account_scope: "identity:native-probe".into(),
        purpose: hartevo_domain_kernel::OIDC_REFRESH_TOKEN_PURPOSE.into(),
        version: 1,
    };
    let secret = SecretBytes::new(b"native-probe-secret".to_vec()).expect("secret");
    store.put(&reference, &secret).expect("native put");
    assert_eq!(
        store.get(&reference).expect("native get").as_slice(),
        secret.as_slice()
    );
    store.delete(&reference).expect("native delete");
}

fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
