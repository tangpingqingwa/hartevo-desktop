use std::collections::HashMap;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    IdentityPluginError, IdentityPluginHandle, IdentityPluginMountRequest, IdentityPluginProvider,
    IdentityPluginScope, IdentityPluginService, IdentityPluginSessionFacts, IdentitySessionError,
};

use crate::{ProjectStore, StorageError};

#[derive(Clone, Debug)]
struct MountedIdentityHandle {
    consumer_id: String,
    scope: IdentityPluginScope,
}

/// Host-owned Project/Mission identity seam for plugin consumers.
///
/// The service owns the mutable `ProjectStore` borrow and never exposes it, a
/// `SecretStore`, or token bytes through its provider trait. Handles are process
/// local: dropping this service drops every mounted capability, which provides
/// crash cleanup when the host tears down a plugin runtime.
#[derive(Debug)]
pub struct ProjectIdentityPluginService<'a> {
    store: &'a mut ProjectStore,
    mounted: HashMap<IdentityPluginHandle, MountedIdentityHandle>,
}

impl ProjectStore {
    /// Borrows the project store into the host-owned plugin identity seam.
    pub fn identity_plugin_service(&mut self) -> ProjectIdentityPluginService<'_> {
        ProjectIdentityPluginService::new(self)
    }
}

impl<'a> ProjectIdentityPluginService<'a> {
    pub fn new(store: &'a mut ProjectStore) -> Self {
        Self {
            store,
            mounted: HashMap::new(),
        }
    }

    pub fn active_handle_count(&self) -> usize {
        self.mounted.len()
    }

    pub fn mount_identity(
        &mut self,
        request: &IdentityPluginMountRequest,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginHandle, IdentityPluginError> {
        let expected_scope = request.scope();
        let state = self
            .store
            .load_identity_bootstrap_state(expected_scope.project_id(), expected_scope.session_id())
            .map_err(|error| storage_error(&error))?;
        let actual_scope = IdentityPluginScope::from_bootstrap_state(
            &state,
            expected_scope.mission_id().clone(),
            expected_scope.mission_revision(),
        )?;
        if actual_scope != *expected_scope {
            return Err(IdentityPluginError::ScopeMismatch);
        }
        self.validate_mission_scope(&actual_scope)?;
        state
            .session
            .assert_local_access(&state.session.scope, now)
            .map_err(identity_session_error)?;

        let handle = IdentityPluginHandle::new();
        self.mounted.insert(
            handle.clone(),
            MountedIdentityHandle {
                consumer_id: request.consumer_id().to_owned(),
                scope: actual_scope,
            },
        );
        Ok(handle)
    }

    pub fn provide_identity_facts(
        &mut self,
        handle: &IdentityPluginHandle,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginSessionFacts, IdentityPluginError> {
        let mounted = self
            .mounted
            .get(handle)
            .cloned()
            .ok_or(IdentityPluginError::HandleNotMounted)?;
        let state = match self
            .store
            .load_identity_bootstrap_state(mounted.scope.project_id(), mounted.scope.session_id())
        {
            Ok(state) => state,
            Err(error) => {
                self.mounted.remove(handle);
                return Err(storage_error(&error));
            }
        };
        let actual_scope = match IdentityPluginScope::from_bootstrap_state(
            &state,
            mounted.scope.mission_id().clone(),
            mounted.scope.mission_revision(),
        ) {
            Ok(scope) => scope,
            Err(error) => {
                self.mounted.remove(handle);
                return Err(error);
            }
        };
        if actual_scope != mounted.scope {
            self.mounted.remove(handle);
            return Err(IdentityPluginError::ScopeMismatch);
        }
        if let Err(error) = self.validate_mission_scope(&actual_scope) {
            self.mounted.remove(handle);
            return Err(error);
        }
        if let Err(error) = state
            .session
            .assert_local_access(&state.session.scope, now)
            .map_err(identity_session_error)
        {
            if matches!(
                error,
                IdentityPluginError::Revoked
                    | IdentityPluginError::Expired
                    | IdentityPluginError::SessionUnavailable
            ) {
                self.mounted.remove(handle);
            }
            return Err(error);
        }
        IdentityPluginSessionFacts::from_bootstrap_state(
            &state,
            mounted.scope.mission_id().clone(),
            mounted.scope.mission_revision(),
        )
    }

    pub fn unmount_identity(
        &mut self,
        handle: &IdentityPluginHandle,
    ) -> Result<(), IdentityPluginError> {
        self.mounted
            .remove(handle)
            .map(|_| ())
            .ok_or(IdentityPluginError::HandleNotMounted)
    }

    pub fn revoke_identity_handle(
        &mut self,
        handle: &IdentityPluginHandle,
    ) -> Result<(), IdentityPluginError> {
        self.mounted
            .remove(handle)
            .map(|_| ())
            .ok_or(IdentityPluginError::HandleNotMounted)
    }

    pub fn reclaim_crashed_consumer(&mut self, consumer_id: &str) -> usize {
        let reclaimed = self
            .mounted
            .values()
            .filter(|mounted| mounted.consumer_id == consumer_id)
            .count();
        self.mounted
            .retain(|_, mounted| mounted.consumer_id != consumer_id);
        reclaimed
    }

    fn validate_mission_scope(
        &self,
        scope: &IdentityPluginScope,
    ) -> Result<(), IdentityPluginError> {
        let mission = self
            .store
            .load_mission(scope.project_id(), scope.mission_id())
            .map_err(|error| storage_error(&error))?;
        scope.validate_against_mission(&mission)
    }
}

impl Drop for ProjectIdentityPluginService<'_> {
    fn drop(&mut self) {
        self.mounted.clear();
    }
}

impl IdentityPluginProvider for ProjectIdentityPluginService<'_> {
    fn provide_identity_facts(
        &mut self,
        handle: &IdentityPluginHandle,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginSessionFacts, IdentityPluginError> {
        self.provide_identity_facts(handle, now)
    }
}

impl IdentityPluginService for ProjectIdentityPluginService<'_> {
    fn mount_identity(
        &mut self,
        request: &IdentityPluginMountRequest,
        now: DateTime<Utc>,
    ) -> Result<IdentityPluginHandle, IdentityPluginError> {
        self.mount_identity(request, now)
    }

    fn unmount_identity(
        &mut self,
        handle: &IdentityPluginHandle,
    ) -> Result<(), IdentityPluginError> {
        self.unmount_identity(handle)
    }

    fn revoke_identity_handle(
        &mut self,
        handle: &IdentityPluginHandle,
    ) -> Result<(), IdentityPluginError> {
        self.revoke_identity_handle(handle)
    }

    fn reclaim_crashed_consumer(&mut self, consumer_id: &str) -> usize {
        self.reclaim_crashed_consumer(consumer_id)
    }
}

fn storage_error(error: &StorageError) -> IdentityPluginError {
    IdentityPluginError::Persistence(error.to_string())
}

fn identity_session_error(error: IdentitySessionError) -> IdentityPluginError {
    error.into()
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        IdentityAccessMode, IdentityAccount, IdentityBootstrapSelection, IdentityBootstrapSnapshot,
        IdentityDevice, IdentityPluginConsumer, IdentityPluginError, IdentityPluginMountRequest,
        IdentityPluginProvider, IdentityPluginScope, IdentityProject, IdentitySession,
        IdentitySessionId, IdentitySessionStatus, IdentityTeam, KEYCLOAK_PROVIDER_ID, Mission,
        MissionContract, MissionId, Project, ProjectId, StorageMode, TeamId, TenantId,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{IdentitySessionSecretReferences, SecretReference};

    const TENANT_ID: &str = "tenant-plugin-01";
    const ISSUER: &str = "https://sso.example.test/realms/hartevo";

    #[derive(Clone)]
    struct SeededIdentity {
        state: hartevo_domain_kernel::IdentityBootstrapState,
        references: IdentitySessionSecretReferences,
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 9, 0, 0)
            .single()
            .expect("fixed test time")
    }

    fn digest(value: &str) -> String {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture keeps the complete persisted identity projection together"
    )]
    fn seed_identity(store: &mut ProjectStore, suffix: &str) -> SeededIdentity {
        let tenant_id = TenantId::from(TENANT_ID);
        let account_id =
            hartevo_domain_kernel::AccountId::from_stable(format!("account-plugin-{suffix}"));
        let team_id = TeamId::from_stable(format!("team-plugin-{suffix}"));
        let member_id =
            hartevo_domain_kernel::MemberId::from_stable(format!("member-plugin-{suffix}"));
        let project_id = ProjectId::from_stable(format!("project-plugin-{suffix}"));
        let device_id =
            hartevo_domain_kernel::DeviceId::from_stable(format!("device-plugin-{suffix}"));
        let account_subject = digest(&format!("subject-{suffix}"));
        let account = IdentityAccount::new(
            account_id,
            tenant_id.clone(),
            ISSUER,
            account_subject.clone(),
            format!("Plugin User {suffix}"),
            None,
        )
        .expect("account");
        let team = IdentityTeam::new(team_id.clone(), tenant_id.clone(), "Growth").expect("team");
        let membership = hartevo_domain_kernel::IdentityMembership::new(
            member_id,
            tenant_id.clone(),
            team_id.clone(),
            account.id.clone(),
            "owner",
        )
        .expect("membership");
        let project_identity = IdentityProject::new(
            project_id.clone(),
            tenant_id.clone(),
            team_id.clone(),
            format!("Project {suffix}"),
            "Plugin identity test project",
        )
        .expect("identity project");
        let snapshot = IdentityBootstrapSnapshot::new(
            ISSUER,
            account_subject,
            account.clone(),
            vec![team.clone()],
            vec![membership.clone()],
            vec![project_identity.clone()],
        )
        .expect("snapshot");
        let selection = IdentityBootstrapSelection {
            account: account.clone(),
            team,
            membership,
            project: project_identity,
        };
        let access_token = SecretReference::oidc_access_token(
            tenant_id.clone(),
            project_id.clone(),
            KEYCLOAK_PROVIDER_ID,
            account.id.as_str(),
            1,
        )
        .expect("access reference");
        let refresh_token = SecretReference::oidc_refresh_token(
            tenant_id.clone(),
            project_id.clone(),
            KEYCLOAK_PROVIDER_ID,
            account.id.as_str(),
            1,
        )
        .expect("refresh reference");
        let device_binding = SecretReference::identity_device_binding(
            tenant_id.clone(),
            project_id.clone(),
            device_id.as_str(),
            1,
        )
        .expect("device reference");
        let device = IdentityDevice::bind(
            device_id,
            tenant_id,
            account.id.clone(),
            project_id.clone(),
            device_binding.credential_id().expect("device digest"),
        )
        .expect("device");
        let references = IdentitySessionSecretReferences {
            access_token,
            refresh_token,
            device_binding,
        };
        let session = IdentitySession::create(
            IdentitySessionId::from_stable(format!("session-plugin-{suffix}")),
            KEYCLOAK_PROVIDER_ID,
            ISSUER,
            snapshot.subject_digest.clone(),
            &selection,
            &device,
            references
                .access_token
                .credential_id()
                .expect("access digest"),
            references
                .refresh_token
                .credential_id()
                .expect("refresh digest"),
            now(),
            now() + Duration::minutes(5),
            now() + Duration::hours(1),
        )
        .expect("session");
        let project = Project::create_local(
            TenantId::from(TENANT_ID),
            project_id,
            format!("Project {suffix}"),
            "Plugin identity test project",
            format!("/tmp/hartevo-identity-plugin-{suffix}"),
            StorageMode::LocalExisting,
        )
        .expect("local project");
        store.save_project(&project).expect("project persisted");
        let mission = Mission::compile(
            TenantId::from(TENANT_ID),
            MissionId::from_stable(format!("mission-{suffix}")),
            project.id.clone(),
            format!("Mission {suffix}"),
            MissionContract::bootstrap(
                "Consume project-scoped identity facts",
                ["identity.read".into()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        store.save_mission(&mission).expect("mission persisted");
        store
            .save_identity_bootstrap_atomic(
                &snapshot,
                &selection.team.id,
                &selection.project.id,
                &device,
                &session,
                &references,
                "identity_plugin_test_bootstrap",
                &json!({"suffix": suffix}),
                now(),
            )
            .expect("identity bootstrap persisted");
        SeededIdentity {
            state: hartevo_domain_kernel::IdentityBootstrapState {
                account,
                team: selection.team,
                membership: selection.membership,
                project: selection.project,
                device,
                session,
            },
            references,
        }
    }

    #[derive(Default)]
    struct TestPluginConsumer {
        handle: Option<IdentityPluginHandle>,
        facts: Option<IdentityPluginSessionFacts>,
    }

    impl IdentityPluginConsumer for TestPluginConsumer {
        fn mount_identity(
            &mut self,
            provider: &mut dyn IdentityPluginProvider,
            handle: IdentityPluginHandle,
            now: DateTime<Utc>,
        ) -> Result<(), IdentityPluginError> {
            self.facts = Some(provider.provide_identity_facts(&handle, now)?);
            self.handle = Some(handle);
            Ok(())
        }

        fn unmount_identity(&mut self, handle: &IdentityPluginHandle) {
            if self.handle.as_ref() == Some(handle) {
                self.handle = None;
                self.facts = None;
            }
        }
    }

    fn request_for(
        state: &hartevo_domain_kernel::IdentityBootstrapState,
        mission_id: &str,
        consumer_id: &str,
    ) -> IdentityPluginMountRequest {
        IdentityPluginMountRequest::new(
            consumer_id,
            IdentityPluginScope::from_bootstrap_state(state, MissionId::from(mission_id), 1)
                .expect("plugin scope"),
        )
        .expect("mount request")
    }

    #[test]
    fn offline_reopen_releases_only_scoped_non_secret_facts_to_consumer() {
        let mut store = ProjectStore::in_memory().expect("store");
        let mut seeded = seed_identity(&mut store, "offline");
        let offline = seeded
            .state
            .session
            .reopen_offline(now() + Duration::minutes(1))
            .expect("offline reopen");
        store
            .update_identity_session_atomic(
                &offline,
                &seeded.references,
                seeded.state.session.revision,
                "identity_plugin_test_offline_reopen",
                &json!({"status": "offline"}),
                now() + Duration::minutes(1),
            )
            .expect("offline update");
        seeded.state.session = offline;
        let request = request_for(&seeded.state, "mission-offline", "consumer-offline");
        let mut service = store.identity_plugin_service();
        let handle = service
            .mount_identity(&request, now() + Duration::minutes(1))
            .expect("mount");
        let mut consumer = TestPluginConsumer::default();
        consumer
            .mount_identity(&mut service, handle.clone(), now() + Duration::minutes(1))
            .expect("consumer mount");
        let facts = consumer.facts.as_ref().expect("facts");
        assert_eq!(facts.access_mode(), IdentityAccessMode::Offline);
        assert_eq!(facts.project_id(), request.scope().project_id());
        assert_eq!(facts.mission_id(), request.scope().mission_id());
        assert_eq!(facts.team_id(), request.scope().team_id());
        assert_eq!(facts.issuer_url(), ISSUER);
        assert_eq!(facts.subject_digest(), seeded.state.account.subject_digest);
        assert_eq!(facts.provider_id(), KEYCLOAK_PROVIDER_ID);
        assert_eq!(facts.status(), IdentitySessionStatus::Offline);
        assert_eq!(facts.scope().mission_revision(), 1);
        assert_eq!(facts.scope().session_revision(), 2);
        assert_eq!(facts.scope().fence().account_revision, 1);
        assert_eq!(facts.scope().fence().team_revision, 1);
        assert_eq!(facts.scope().fence().membership_revision, 1);
        assert_eq!(facts.scope().fence().project_revision, 1);
        assert_eq!(facts.scope().fence().device_revision, 1);
        let rendered = format!("{facts:?}");
        assert!(!rendered.contains("access-token"));
        assert!(!rendered.contains("refresh-token"));
        assert_eq!(format!("{handle:?}"), "IdentityPluginHandle([REDACTED])");
        consumer.unmount_identity(&handle);
        service.unmount_identity(&handle).expect("host unmount");
        assert_eq!(
            service.provide_identity_facts(&handle, now() + Duration::minutes(1)),
            Err(IdentityPluginError::HandleNotMounted)
        );
    }

    #[test]
    fn revocation_and_crash_reclaim_remove_handles_before_facts_can_escape() {
        let mut store = ProjectStore::in_memory().expect("store");
        let mut seeded = seed_identity(&mut store, "revoke");
        let request = request_for(&seeded.state, "mission-revoke", "consumer-revoke");
        let handle = {
            let mut service = store.identity_plugin_service();
            let handle = service.mount_identity(&request, now()).expect("mount");
            assert_eq!(service.active_handle_count(), 1);
            service
                .revoke_identity_handle(&handle)
                .expect("handle revoke");
            assert_eq!(
                service.provide_identity_facts(&handle, now()),
                Err(IdentityPluginError::HandleNotMounted)
            );
            handle
        };
        let mut service = store.identity_plugin_service();
        assert_eq!(
            service.provide_identity_facts(&handle, now()),
            Err(IdentityPluginError::HandleNotMounted)
        );
        let second = service
            .mount_identity(&request, now())
            .expect("second mount");
        assert_eq!(service.reclaim_crashed_consumer("consumer-revoke"), 1);
        assert_eq!(
            service.provide_identity_facts(&second, now()),
            Err(IdentityPluginError::HandleNotMounted)
        );
        let expired = service
            .mount_identity(&request, now())
            .expect("expiry mount");
        assert_eq!(
            service.provide_identity_facts(&expired, now() + Duration::hours(2)),
            Err(IdentityPluginError::Expired)
        );
        assert_eq!(service.active_handle_count(), 0);
        drop(service);

        let revoked = seeded
            .state
            .session
            .revoked(now() + Duration::minutes(2))
            .expect("revoked session");
        store
            .update_identity_session_atomic(
                &revoked,
                &seeded.references,
                seeded.state.session.revision,
                "identity_plugin_test_revoke",
                &json!({"status": "revoked"}),
                now() + Duration::minutes(2),
            )
            .expect("revocation persisted");
        seeded.state.session = revoked;
        let revoked_request = request_for(&seeded.state, "mission-revoke", "consumer-revoke");
        let mut service = store.identity_plugin_service();
        assert_eq!(
            service.mount_identity(&request, now() + Duration::minutes(2)),
            Err(IdentityPluginError::ScopeMismatch)
        );
        assert_eq!(
            service.mount_identity(&revoked_request, now() + Duration::minutes(2)),
            Err(IdentityPluginError::Revoked)
        );
    }

    #[test]
    fn cross_project_and_revision_tampering_is_rejected_without_fact_leak() {
        let mut store = ProjectStore::in_memory().expect("store");
        let first = seed_identity(&mut store, "first");
        let second = seed_identity(&mut store, "second");
        let first_request = request_for(&first.state, "mission-first", "consumer-first");
        let second_scope = IdentityPluginScope::from_bootstrap_state(
            &second.state,
            MissionId::from("mission-second"),
            1,
        )
        .expect("second scope");
        let mut forged = serde_json::to_value(first_request.scope()).expect("scope json");
        forged["projectId"] = json!(second_scope.project_id().as_str());
        forged["sessionId"] = json!(second_scope.session_id().as_str());
        forged["deviceId"] = json!(second_scope.device_id().as_str());
        forged["fence"]["projectId"] = json!(second_scope.fence().project_id.as_str());
        forged["fence"]["deviceId"] = json!(second_scope.fence().device_id.as_str());
        let forged_scope: IdentityPluginScope =
            serde_json::from_value(forged).expect("forged scope shape");
        let forged_request = IdentityPluginMountRequest::new("consumer-forged", forged_scope)
            .expect("forged request");
        let mut service = store.identity_plugin_service();
        assert_eq!(
            service.mount_identity(&forged_request, now()),
            Err(IdentityPluginError::ScopeMismatch)
        );
        let first_handle = service
            .mount_identity(&first_request, now())
            .expect("first mount");
        let facts = service
            .provide_identity_facts(&first_handle, now())
            .expect("first facts");
        assert_eq!(facts.project_id(), first_request.scope().project_id());
        assert_ne!(facts.project_id(), second_scope.project_id());
        assert_eq!(facts.scope().fence().project_revision, 1);
        assert_eq!(facts.scope().fence().device_revision, 1);
        assert_eq!(facts.scope().session_revision(), 1);
    }
}
