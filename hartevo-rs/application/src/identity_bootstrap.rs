use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    IdentityAccessMode, IdentityBootstrapError, IdentityBootstrapSelection, IdentityBootstrapState,
    IdentityDevice, IdentityProviderError, IdentityScopeFence, IdentitySession,
    IdentitySessionError, IdentitySessionId, KeyRecipient, OidcAuthorizationAttempt,
    OidcAuthorizationCallback, OidcIdentityProvider, OidcProviderConfiguration,
    ProjectEncryptionMode, ProjectId, StorageMode, TeamId,
};
use hartevo_storage::{
    IdentitySessionSecretReferences, KeyMaterial, SecretBytes, SecretReference, SecretStore,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;

use super::{ApplicationError, ApplicationService, ProvisionProjectEncryption};

#[derive(Clone, Debug)]
pub struct BeginOidcAuthorization {
    pub provider: OidcProviderConfiguration,
    pub redirect_uri: String,
    pub scopes: BTreeSet<String>,
}

#[derive(Debug)]
pub struct CompleteIdentityBootstrap {
    pub selected_team_id: TeamId,
    pub selected_project_id: ProjectId,
    pub workspace_root: PathBuf,
    pub storage_mode: StorageMode,
    pub device_id: hartevo_domain_kernel::DeviceId,
    pub encryption_mode: ProjectEncryptionMode,
    pub recovery_recipient_id: Option<String>,
    pub user_recovery_secret: Option<SecretBytes>,
    pub recovery_confirmed: bool,
}

#[derive(Debug)]
pub struct IdentityBootstrapResult {
    pub project: hartevo_domain_kernel::Project,
    pub encryption: super::ProvisionedProjectEncryption,
    pub identity: IdentityBootstrapState,
    pub secret_references: IdentitySessionSecretReferences,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityScopeAuthorization {
    pub mode: IdentityAccessMode,
    pub scope: IdentityScopeFence,
    pub session_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentitySessionRevocationResult {
    pub session: IdentitySession,
    pub remote_revocation_pending: bool,
}

impl ApplicationService {
    pub fn begin_oidc_authorization(
        &self,
        command: BeginOidcAuthorization,
    ) -> Result<OidcAuthorizationAttempt, ApplicationError> {
        command.provider.validate()?;
        let random = SystemRandom::new();
        let state = random_hex(&random, 32)?;
        let nonce = random_hex(&random, 32)?;
        let verifier = hartevo_domain_kernel::PkceCodeVerifier::new(random_hex(&random, 48)?)?;
        let scopes = if command.scopes.is_empty() {
            command.provider.default_scopes.clone()
        } else {
            command.scopes
        };
        Ok(command.provider.authorization_attempt(
            command.redirect_uri,
            state,
            nonce,
            verifier,
            scopes,
        )?)
    }

    #[allow(clippy::too_many_lines)]
    pub fn complete_oidc_identity_bootstrap(
        &mut self,
        secret_store: &impl SecretStore,
        provider: &impl OidcIdentityProvider,
        attempt: &OidcAuthorizationAttempt,
        callback: &OidcAuthorizationCallback,
        command: CompleteIdentityBootstrap,
        now: DateTime<Utc>,
    ) -> Result<IdentityBootstrapResult, ApplicationError> {
        let configuration = provider.configuration();
        configuration.validate()?;
        if attempt.request().provider_id != configuration.provider_id
            || attempt.request().issuer_url != configuration.issuer_url
        {
            return Err(IdentityBootstrapError::AuthorizationIssuerMismatch.into());
        }
        attempt.validate_callback(callback)?;
        let tokens = provider.exchange_code(callback, attempt.code_verifier())?;
        tokens.validate()?;
        if tokens.access_expires_at <= now || tokens.refresh_expires_at <= now {
            return Err(hartevo_domain_kernel::IdentityProviderError::InvalidTokenSet.into());
        }
        let snapshot = provider.bootstrap(&tokens)?;
        snapshot.validate()?;
        if snapshot.issuer_url != configuration.issuer_url {
            return Err(IdentityBootstrapError::IdentityAssertionMismatch.into());
        }
        let selection = snapshot.select(&command.selected_team_id, &command.selected_project_id)?;
        if selection.project.id != command.selected_project_id {
            return Err(IdentityBootstrapError::ProjectSelectionNotFound.into());
        }
        validate_encryption_command(&command)?;

        let project = hartevo_domain_kernel::Project::create_local(
            selection.account.tenant_id.clone(),
            selection.project.id.clone(),
            selection.project.name.clone(),
            selection.project.description.clone(),
            command.workspace_root,
            command.storage_mode,
        )?;
        self.store.create_project_atomic(
            &project,
            &[hartevo_storage::PendingEvent::new(
                "identity_project.bootstrapped",
                json!({
                    "provider": configuration.provider_id,
                    "accountId": selection.account.id,
                    "teamId": selection.team.id,
                    "projectId": selection.project.id,
                    "tenantId": selection.account.tenant_id,
                    "projectRevision": selection.project.revision,
                }),
                now,
            )],
        )?;

        let primary_recipient = KeyRecipient::Device(command.device_id.clone());
        let encryption_command = ProvisionProjectEncryption {
            project_id: project.id.clone(),
            mode: command.encryption_mode.clone(),
            primary_recipient,
            recovery_recipient_id: command.recovery_recipient_id.clone(),
        };
        let encryption = match command.user_recovery_secret {
            Some(secret) => self.provision_project_encryption_with_user_recovery(
                secret_store,
                encryption_command,
                &secret,
                now,
            )?,
            None => self.provision_project_encryption(secret_store, encryption_command, now)?,
        };

        let access_reference = SecretReference::oidc_access_token(
            selection.account.tenant_id.clone(),
            project.id.clone(),
            configuration.provider_id.clone(),
            selection.account.id.as_str(),
            1,
        )?;
        let refresh_reference = SecretReference::oidc_refresh_token(
            selection.account.tenant_id.clone(),
            project.id.clone(),
            configuration.provider_id.clone(),
            selection.account.id.as_str(),
            1,
        )?;
        let device_reference = SecretReference::identity_device_binding(
            selection.account.tenant_id.clone(),
            project.id.clone(),
            command.device_id.as_str(),
            1,
        )?;
        let device = IdentityDevice::bind(
            command.device_id.clone(),
            selection.account.tenant_id.clone(),
            selection.account.id.clone(),
            project.id.clone(),
            device_reference.credential_id()?,
        )?;
        let session = IdentitySession::create(
            IdentitySessionId::new(),
            configuration.provider_id.clone(),
            configuration.issuer_url.clone(),
            snapshot.subject_digest.clone(),
            &selection,
            &device,
            access_reference.credential_id()?,
            refresh_reference.credential_id()?,
            now,
            tokens.access_expires_at,
            tokens.refresh_expires_at,
        )?;
        let references = IdentitySessionSecretReferences {
            access_token: access_reference,
            refresh_token: refresh_reference,
            device_binding: device_reference,
        };
        let access_secret = SecretBytes::new(tokens.access_token().as_bytes().to_vec())?;
        let refresh_secret = SecretBytes::new(tokens.refresh_token().as_bytes().to_vec())?;
        let binding_secret = KeyMaterial::generate()?.to_secret();
        put_identity_secrets(
            secret_store,
            &references,
            &access_secret,
            &refresh_secret,
            &binding_secret,
        )?;
        if let Err(error) = self.store.save_identity_bootstrap_atomic(
            &snapshot,
            &command.selected_team_id,
            &command.selected_project_id,
            &device,
            &session,
            &references,
            "identity_session.authorized",
            &json!({
                "provider": configuration.provider_id,
                "accountId": selection.account.id,
                "teamId": selection.team.id,
                "memberId": selection.membership.id,
                "projectId": selection.project.id,
                "deviceId": device.id,
                "tenantId": selection.account.tenant_id,
                "scope": session.scope,
                "status": session.status,
            }),
            now,
        ) {
            cleanup_identity_secrets(secret_store, &references)?;
            return Err(error.into());
        }
        let identity = self
            .store
            .load_identity_bootstrap_state(&project.id, &session.id)?;
        Ok(IdentityBootstrapResult {
            project,
            encryption,
            identity,
            secret_references: references,
        })
    }

    pub fn reopen_identity_session_offline(
        &mut self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        session_id: &IdentitySessionId,
        now: DateTime<Utc>,
    ) -> Result<IdentityBootstrapState, ApplicationError> {
        let mut state = self
            .store
            .load_identity_bootstrap_state(project_id, session_id)?;
        let references = self
            .store
            .load_identity_session_secret_references(project_id, session_id)?;
        secret_store
            .get(&references.device_binding)
            .map_err(|_| ApplicationError::IdentityDeviceBindingUnavailable)?;
        if now >= state.session.expires_at
            && state.session.status != hartevo_domain_kernel::IdentitySessionStatus::Revoked
            && state.session.status != hartevo_domain_kernel::IdentitySessionStatus::Expired
        {
            let expired = state.session.expired(now)?;
            self.store.update_identity_session_atomic(
                &expired,
                &references,
                state.session.revision,
                "identity_session.expired",
                &json!({
                    "sessionId": expired.id,
                    "projectId": expired.project_id,
                    "tenantId": expired.scope.tenant_id,
                    "status": expired.status,
                }),
                now,
            )?;
            return Err(IdentitySessionError::Expired.into());
        }
        let offline = state.session.reopen_offline(now)?;
        if offline.revision != state.session.revision {
            self.store.update_identity_session_atomic(
                &offline,
                &references,
                state.session.revision,
                "identity_session.offline_reopened",
                &json!({
                    "sessionId": offline.id,
                    "projectId": offline.project_id,
                    "tenantId": offline.scope.tenant_id,
                    "status": offline.status,
                }),
                now,
            )?;
            state.session = offline;
        }
        Ok(state)
    }

    pub fn authorize_local_identity_scope(
        &self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        session_id: &IdentitySessionId,
        expected_scope: &IdentityScopeFence,
        now: DateTime<Utc>,
    ) -> Result<IdentityScopeAuthorization, ApplicationError> {
        let state = self
            .store
            .load_identity_bootstrap_state(project_id, session_id)?;
        let mode = state.session.assert_local_access(expected_scope, now)?;
        let references = self
            .store
            .load_identity_session_secret_references(project_id, session_id)?;
        secret_store
            .get(&references.device_binding)
            .map_err(|_| ApplicationError::IdentityDeviceBindingUnavailable)?;
        Ok(IdentityScopeAuthorization {
            mode,
            scope: state.session.scope,
            session_revision: state.session.revision,
        })
    }

    pub fn authorize_cloud_identity_scope(
        &self,
        secret_store: &impl SecretStore,
        project_id: &ProjectId,
        session_id: &IdentitySessionId,
        expected_scope: &IdentityScopeFence,
        now: DateTime<Utc>,
    ) -> Result<IdentityScopeAuthorization, ApplicationError> {
        let state = self
            .store
            .load_identity_bootstrap_state(project_id, session_id)?;
        state.session.assert_cloud_access(expected_scope, now)?;
        let references = self
            .store
            .load_identity_session_secret_references(project_id, session_id)?;
        secret_store
            .get(&references.device_binding)
            .map_err(|_| ApplicationError::IdentityDeviceBindingUnavailable)?;
        secret_store
            .get(&references.access_token)
            .map_err(|_| ApplicationError::IdentityAccessSecretUnavailable)?;
        Ok(IdentityScopeAuthorization {
            mode: IdentityAccessMode::Online,
            scope: state.session.scope,
            session_revision: state.session.revision,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "refresh keeps token retrieval, identity re-bootstrap, secret rotation, and durable session CAS in one fail-closed boundary"
    )]
    pub fn refresh_identity_session(
        &mut self,
        secret_store: &impl SecretStore,
        provider: &impl OidcIdentityProvider,
        project_id: &ProjectId,
        session_id: &IdentitySessionId,
        now: DateTime<Utc>,
    ) -> Result<IdentitySession, ApplicationError> {
        let state = self
            .store
            .load_identity_bootstrap_state(project_id, session_id)?;
        if provider.configuration().provider_id != state.session.provider_id
            || provider.configuration().issuer_url != state.session.issuer_url
        {
            return Err(IdentityBootstrapError::AuthorizationIssuerMismatch.into());
        }
        provider.configuration().validate()?;
        state
            .session
            .assert_local_access(&state.session.scope, now)?;
        let references = self
            .store
            .load_identity_session_secret_references(project_id, session_id)?;
        let refresh_secret = secret_store
            .get(&references.refresh_token)
            .map_err(|_| ApplicationError::IdentityRefreshSecretUnavailable)?;
        let refresh_token = std::str::from_utf8(refresh_secret.as_slice())
            .map_err(|_| ApplicationError::IdentityRefreshSecretUnavailable)?;
        let tokens = provider.refresh(refresh_token)?;
        tokens.validate()?;
        if tokens.access_expires_at <= now || tokens.refresh_expires_at <= now {
            return Err(IdentityProviderError::InvalidTokenSet.into());
        }
        let refreshed_snapshot = provider.bootstrap(&tokens)?;
        let refreshed_selection =
            refreshed_snapshot.select(&state.session.team_id, &state.session.project_id)?;
        if !selection_matches_state(&refreshed_selection, &state)
            || refreshed_snapshot.issuer_url != state.session.issuer_url
            || refreshed_snapshot.subject_digest != state.session.subject_digest
        {
            return Err(IdentityBootstrapError::IdentityAssertionMismatch.into());
        }
        let access_version = references
            .access_token
            .version
            .checked_add(1)
            .ok_or(IdentitySessionError::RevisionOverflow)?;
        let refresh_version = references
            .refresh_token
            .version
            .checked_add(1)
            .ok_or(IdentitySessionError::RevisionOverflow)?;
        let next_access_reference = SecretReference::oidc_access_token(
            state.session.scope.tenant_id.clone(),
            project_id.clone(),
            state.session.provider_id.clone(),
            state.session.account_id.as_str(),
            access_version,
        )?;
        let next_refresh_reference = SecretReference::oidc_refresh_token(
            state.session.scope.tenant_id.clone(),
            project_id.clone(),
            state.session.provider_id.clone(),
            state.session.account_id.as_str(),
            refresh_version,
        )?;
        let next_references = IdentitySessionSecretReferences {
            access_token: next_access_reference,
            refresh_token: next_refresh_reference,
            device_binding: references.device_binding.clone(),
        };
        let next_session = state.session.refreshed(
            next_references.access_token.credential_id()?,
            next_references.refresh_token.credential_id()?,
            tokens.access_expires_at,
            tokens.refresh_expires_at,
            now,
        )?;
        let access_secret = SecretBytes::new(tokens.access_token().as_bytes().to_vec())?;
        let refresh_secret = SecretBytes::new(tokens.refresh_token().as_bytes().to_vec())?;
        if let Err(error) = secret_store.put(&next_references.access_token, &access_secret) {
            return Err(error.into());
        }
        if let Err(error) = secret_store.put(&next_references.refresh_token, &refresh_secret) {
            let _ = secret_store.delete(&next_references.access_token);
            return Err(error.into());
        }
        if let Err(error) = self.store.update_identity_session_atomic(
            &next_session,
            &next_references,
            state.session.revision,
            "identity_session.refreshed",
            &json!({
                "sessionId": next_session.id,
                "projectId": next_session.project_id,
                "tenantId": next_session.scope.tenant_id,
                "status": next_session.status,
                "accessExpiresAt": next_session.access_expires_at,
                "sessionExpiresAt": next_session.expires_at,
            }),
            now,
        ) {
            let _ = secret_store.delete(&next_references.access_token);
            let _ = secret_store.delete(&next_references.refresh_token);
            return Err(error.into());
        }
        let _ = secret_store.delete(&references.access_token);
        let _ = secret_store.delete(&references.refresh_token);
        Ok(next_session)
    }

    pub fn revoke_identity_session(
        &mut self,
        secret_store: &impl SecretStore,
        provider: &impl OidcIdentityProvider,
        project_id: &ProjectId,
        session_id: &IdentitySessionId,
        now: DateTime<Utc>,
    ) -> Result<IdentitySessionRevocationResult, ApplicationError> {
        let state = self
            .store
            .load_identity_bootstrap_state(project_id, session_id)?;
        provider.configuration().validate()?;
        if provider.configuration().provider_id != state.session.provider_id
            || provider.configuration().issuer_url != state.session.issuer_url
        {
            return Err(IdentityBootstrapError::AuthorizationIssuerMismatch.into());
        }
        let references = self
            .store
            .load_identity_session_secret_references(project_id, session_id)?;
        let revoked =
            if state.session.status == hartevo_domain_kernel::IdentitySessionStatus::Revoked {
                state.session
            } else {
                let revoked = state.session.revoked(now)?;
                self.store.update_identity_session_atomic(
                    &revoked,
                    &references,
                    state.session.revision,
                    "identity_session.revoked",
                    &json!({
                        "sessionId": revoked.id,
                        "projectId": revoked.project_id,
                        "tenantId": revoked.scope.tenant_id,
                        "status": revoked.status,
                    }),
                    now,
                )?;
                revoked
            };
        let mut remote_revocation_pending = false;
        match secret_store.get(&references.refresh_token) {
            Ok(secret) => match std::str::from_utf8(secret.as_slice()) {
                Ok(refresh_token) => {
                    if provider.revoke(refresh_token).is_err() {
                        remote_revocation_pending = true;
                    }
                }
                Err(_) => remote_revocation_pending = true,
            },
            Err(_) => remote_revocation_pending = true,
        }
        if secret_store.delete(&references.access_token).is_err() {
            remote_revocation_pending = true;
        }
        if secret_store.delete(&references.refresh_token).is_err() {
            remote_revocation_pending = true;
        }
        Ok(IdentitySessionRevocationResult {
            session: revoked,
            remote_revocation_pending,
        })
    }
}

fn validate_encryption_command(
    command: &CompleteIdentityBootstrap,
) -> Result<(), ApplicationError> {
    match command.encryption_mode {
        ProjectEncryptionMode::PersonalE2ee => {
            if command.recovery_recipient_id.is_none()
                || command.user_recovery_secret.is_none()
                || !command.recovery_confirmed
            {
                return Err(ApplicationError::InvalidEncryptionProvisioning);
            }
        }
        ProjectEncryptionMode::TeamEnvelope => {
            if command.user_recovery_secret.is_some() || command.recovery_confirmed {
                return Err(ApplicationError::InvalidEncryptionProvisioning);
            }
        }
    }
    Ok(())
}

fn selection_matches_state(
    selection: &IdentityBootstrapSelection,
    state: &IdentityBootstrapState,
) -> bool {
    selection.account == state.account
        && selection.team == state.team
        && selection.membership == state.membership
        && selection.project == state.project
}

fn random_hex(random: &SystemRandom, byte_count: usize) -> Result<String, ApplicationError> {
    let mut bytes = vec![0_u8; byte_count];
    random
        .fill(&mut bytes)
        .map_err(|_| ApplicationError::IdentityRandomnessUnavailable)?;
    Ok(hex::encode(bytes))
}

fn put_identity_secrets(
    secret_store: &impl SecretStore,
    references: &IdentitySessionSecretReferences,
    access_secret: &SecretBytes,
    refresh_secret: &SecretBytes,
    binding_secret: &SecretBytes,
) -> Result<(), ApplicationError> {
    secret_store.put(&references.access_token, access_secret)?;
    if let Err(error) = secret_store.put(&references.refresh_token, refresh_secret) {
        let _ = secret_store.delete(&references.access_token);
        return Err(error.into());
    }
    if let Err(error) = secret_store.put(&references.device_binding, binding_secret) {
        let _ = secret_store.delete(&references.access_token);
        let _ = secret_store.delete(&references.refresh_token);
        return Err(error.into());
    }
    Ok(())
}

fn cleanup_identity_secrets(
    secret_store: &impl SecretStore,
    references: &IdentitySessionSecretReferences,
) -> Result<(), ApplicationError> {
    let access = secret_store.delete(&references.access_token);
    let refresh = secret_store.delete(&references.refresh_token);
    let binding = secret_store.delete(&references.device_binding);
    if access.is_err() || refresh.is_err() || binding.is_err() {
        return Err(ApplicationError::IdentitySecretCompensationFailed);
    }
    Ok(())
}

impl fmt::Display for IdentityScopeAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "identity scope authorized ({:?})", self.mode)
    }
}
