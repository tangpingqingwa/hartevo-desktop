use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{AccountId, DeviceId, IdentitySessionId, MemberId, ProjectId, TeamId, TenantId};

pub const KEYCLOAK_PROVIDER_ID: &str = "keycloak";
pub const OIDC_ACCESS_TOKEN_PURPOSE: &str = "oidc_access_token";
pub const OIDC_REFRESH_TOKEN_PURPOSE: &str = "oidc_refresh_token";
pub const IDENTITY_DEVICE_BINDING_PURPOSE: &str = "identity_device_binding";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityProviderKind {
    Keycloak,
    GenericOidc,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcProviderConfiguration {
    pub provider_id: String,
    pub kind: IdentityProviderKind,
    pub issuer_url: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: Option<String>,
    pub client_id: String,
    pub default_scopes: BTreeSet<String>,
}

impl OidcProviderConfiguration {
    pub fn keycloak(
        issuer_url: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Result<Self, IdentityBootstrapError> {
        let issuer_url = issuer_url.into();
        let issuer_url = normalize_issuer(&issuer_url)?;
        let configuration = Self {
            provider_id: KEYCLOAK_PROVIDER_ID.into(),
            kind: IdentityProviderKind::Keycloak,
            authorization_endpoint: format!("{issuer_url}/protocol/openid-connect/auth"),
            token_endpoint: format!("{issuer_url}/protocol/openid-connect/token"),
            revocation_endpoint: Some(format!("{issuer_url}/protocol/openid-connect/revoke")),
            issuer_url,
            client_id: client_id.into(),
            default_scopes: default_oidc_scopes(),
        };
        configuration.validate()?;
        Ok(configuration)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn generic_oidc(
        provider_id: impl Into<String>,
        issuer_url: impl Into<String>,
        authorization_endpoint: impl Into<String>,
        token_endpoint: impl Into<String>,
        revocation_endpoint: Option<String>,
        client_id: impl Into<String>,
        default_scopes: BTreeSet<String>,
    ) -> Result<Self, IdentityBootstrapError> {
        let issuer_url = issuer_url.into();
        let configuration = Self {
            provider_id: provider_id.into(),
            kind: IdentityProviderKind::GenericOidc,
            issuer_url: normalize_issuer(&issuer_url)?,
            authorization_endpoint: authorization_endpoint.into(),
            token_endpoint: token_endpoint.into(),
            revocation_endpoint,
            client_id: client_id.into(),
            default_scopes,
        };
        configuration.validate()?;
        Ok(configuration)
    }

    pub fn validate(&self) -> Result<(), IdentityBootstrapError> {
        if self.provider_id.trim().is_empty()
            || self.issuer_url.trim().is_empty()
            || self.client_id.trim().is_empty()
            || !is_https_url(&self.issuer_url)
            || !is_https_url(&self.authorization_endpoint)
            || !is_https_url(&self.token_endpoint)
            || self
                .revocation_endpoint
                .as_ref()
                .is_some_and(|endpoint| !is_https_url(endpoint))
            || !self.default_scopes.contains("openid")
            || self
                .default_scopes
                .iter()
                .any(|scope| scope.trim().is_empty() || scope.chars().any(char::is_control))
        {
            return Err(IdentityBootstrapError::InvalidProviderConfiguration);
        }
        if self.kind == IdentityProviderKind::Keycloak && self.provider_id != KEYCLOAK_PROVIDER_ID {
            return Err(IdentityBootstrapError::InvalidProviderConfiguration);
        }
        Ok(())
    }

    pub fn authorization_attempt(
        &self,
        redirect_uri: impl Into<String>,
        state: impl Into<String>,
        nonce: impl Into<String>,
        code_verifier: PkceCodeVerifier,
        scopes: BTreeSet<String>,
    ) -> Result<OidcAuthorizationAttempt, IdentityBootstrapError> {
        self.validate()?;
        let redirect_uri = redirect_uri.into();
        let state = state.into();
        let nonce = nonce.into();
        if redirect_uri.trim().is_empty()
            || !is_https_url(&redirect_uri)
            || state.trim().is_empty()
            || nonce.trim().is_empty()
            || scopes.is_empty()
            || !scopes.contains("openid")
            || scopes.iter().any(|scope| scope.trim().is_empty())
        {
            return Err(IdentityBootstrapError::InvalidAuthorizationRequest);
        }
        let request = OidcAuthorizationRequest {
            provider_id: self.provider_id.clone(),
            issuer_url: self.issuer_url.clone(),
            authorization_endpoint: self.authorization_endpoint.clone(),
            client_id: self.client_id.clone(),
            redirect_uri,
            scopes,
            state,
            nonce,
            code_challenge: code_verifier.challenge(),
        };
        Ok(OidcAuthorizationAttempt {
            request,
            code_verifier,
        })
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcAuthorizationRequest {
    pub provider_id: String,
    pub issuer_url: String,
    pub authorization_endpoint: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: BTreeSet<String>,
    #[serde(skip)]
    pub state: String,
    #[serde(skip)]
    pub nonce: String,
    pub code_challenge: String,
}

impl OidcAuthorizationRequest {
    pub fn authorization_url(&self) -> Result<String, IdentityBootstrapError> {
        if self.provider_id.trim().is_empty()
            || self.issuer_url.trim().is_empty()
            || self.authorization_endpoint.trim().is_empty()
            || self.client_id.trim().is_empty()
            || self.redirect_uri.trim().is_empty()
            || self.scopes.is_empty()
            || self.state.trim().is_empty()
            || self.nonce.trim().is_empty()
            || self.code_challenge.trim().is_empty()
        {
            return Err(IdentityBootstrapError::InvalidAuthorizationRequest);
        }
        let scope = self.scopes.iter().cloned().collect::<Vec<_>>().join(" ");
        Ok(format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            self.authorization_endpoint,
            percent_encode(&self.client_id),
            percent_encode(&self.redirect_uri),
            percent_encode(&scope),
            percent_encode(&self.state),
            percent_encode(&self.nonce),
            percent_encode(&self.code_challenge),
        ))
    }

    pub fn state(&self) -> &str {
        &self.state
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn code_challenge(&self) -> &str {
        &self.code_challenge
    }
}

impl fmt::Debug for OidcAuthorizationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcAuthorizationRequest")
            .field("provider_id", &self.provider_id)
            .field("issuer_url", &self.issuer_url)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .field("state", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("code_challenge", &self.code_challenge)
            .finish()
    }
}

#[derive(Clone)]
pub struct OidcAuthorizationAttempt {
    request: OidcAuthorizationRequest,
    code_verifier: PkceCodeVerifier,
}

impl OidcAuthorizationAttempt {
    pub fn request(&self) -> &OidcAuthorizationRequest {
        &self.request
    }

    pub fn code_verifier(&self) -> &PkceCodeVerifier {
        &self.code_verifier
    }

    pub fn validate_callback(
        &self,
        callback: &OidcAuthorizationCallback,
    ) -> Result<(), IdentityBootstrapError> {
        if callback.state != self.request.state {
            return Err(IdentityBootstrapError::AuthorizationStateMismatch);
        }
        if callback.issuer_url != self.request.issuer_url {
            return Err(IdentityBootstrapError::AuthorizationIssuerMismatch);
        }
        if callback.nonce != self.request.nonce {
            return Err(IdentityBootstrapError::AuthorizationNonceMismatch);
        }
        if callback.code.trim().is_empty() {
            return Err(IdentityBootstrapError::InvalidAuthorizationCallback);
        }
        Ok(())
    }
}

impl fmt::Debug for OidcAuthorizationAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcAuthorizationAttempt")
            .field("request", &self.request)
            .field("code_verifier", &self.code_verifier)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcAuthorizationCallback {
    pub code: String,
    pub state: String,
    pub issuer_url: String,
    pub nonce: String,
}

impl fmt::Debug for OidcAuthorizationCallback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcAuthorizationCallback")
            .field("code", &"[REDACTED]")
            .field("state", &"[REDACTED]")
            .field("issuer_url", &self.issuer_url)
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PkceCodeVerifier(String);

impl PkceCodeVerifier {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityBootstrapError> {
        let value = value.into();
        if !(43..=128).contains(&value.len())
            || value
                .bytes()
                .any(|byte| !matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b'~'))
        {
            return Err(IdentityBootstrapError::InvalidPkceVerifier);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn challenge(&self) -> String {
        base64_url_no_padding(&Sha256::digest(self.0.as_bytes()))
    }
}

impl fmt::Debug for PkceCodeVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PkceCodeVerifier([REDACTED])")
    }
}

#[derive(Clone)]
pub struct OidcTokenSet {
    access_token: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
}

impl OidcTokenSet {
    pub fn new(
        access_token: impl Into<String>,
        refresh_token: impl Into<String>,
        access_expires_at: DateTime<Utc>,
        refresh_expires_at: DateTime<Utc>,
    ) -> Result<Self, IdentityProviderError> {
        let token_set = Self {
            access_token: Zeroizing::new(access_token.into()),
            refresh_token: Zeroizing::new(refresh_token.into()),
            access_expires_at,
            refresh_expires_at,
        };
        token_set.validate()?;
        Ok(token_set)
    }

    pub fn validate(&self) -> Result<(), IdentityProviderError> {
        if self.access_token.trim().is_empty()
            || self.refresh_token.trim().is_empty()
            || self.refresh_expires_at <= self.access_expires_at
        {
            return Err(IdentityProviderError::InvalidTokenSet);
        }
        Ok(())
    }

    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }
}

impl fmt::Debug for OidcTokenSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcTokenSet")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish()
    }
}

pub trait OidcIdentityProvider: fmt::Debug {
    fn configuration(&self) -> &OidcProviderConfiguration;

    fn exchange_code(
        &self,
        callback: &OidcAuthorizationCallback,
        code_verifier: &PkceCodeVerifier,
    ) -> Result<OidcTokenSet, IdentityProviderError>;

    fn bootstrap(
        &self,
        tokens: &OidcTokenSet,
    ) -> Result<IdentityBootstrapSnapshot, IdentityProviderError>;

    fn refresh(&self, refresh_token: &str) -> Result<OidcTokenSet, IdentityProviderError>;

    fn revoke(&self, refresh_token: &str) -> Result<(), IdentityProviderError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityAccountStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityAccount {
    pub id: AccountId,
    pub tenant_id: TenantId,
    pub issuer_url: String,
    pub subject_digest: String,
    pub display_name: String,
    pub email_digest: Option<String>,
    pub status: IdentityAccountStatus,
    pub revision: u64,
}

impl IdentityAccount {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: AccountId,
        tenant_id: TenantId,
        issuer_url: impl Into<String>,
        subject_digest: impl Into<String>,
        display_name: impl Into<String>,
        email_digest: Option<String>,
    ) -> Result<Self, IdentityBootstrapError> {
        let account = Self {
            id,
            tenant_id,
            issuer_url: issuer_url.into(),
            subject_digest: subject_digest.into(),
            display_name: display_name.into().trim().to_owned(),
            email_digest,
            status: IdentityAccountStatus::Active,
            revision: 1,
        };
        account.validate()?;
        Ok(account)
    }

    pub fn validate(&self) -> Result<(), IdentityBootstrapError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || !is_https_url(&self.issuer_url)
            || !is_sha256(&self.subject_digest)
            || self.display_name.is_empty()
            || self
                .email_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256(digest))
            || self.revision == 0
        {
            return Err(IdentityBootstrapError::InvalidAccount);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityTeam {
    pub id: TeamId,
    pub tenant_id: TenantId,
    pub display_name: String,
    pub revision: u64,
}

impl IdentityTeam {
    pub fn new(
        id: TeamId,
        tenant_id: TenantId,
        display_name: impl Into<String>,
    ) -> Result<Self, IdentityBootstrapError> {
        let team = Self {
            id,
            tenant_id,
            display_name: display_name.into().trim().to_owned(),
            revision: 1,
        };
        team.validate()?;
        Ok(team)
    }

    pub fn validate(&self) -> Result<(), IdentityBootstrapError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.display_name.is_empty()
            || self.revision == 0
        {
            return Err(IdentityBootstrapError::InvalidTeam);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMembershipStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityMembership {
    pub id: MemberId,
    pub tenant_id: TenantId,
    pub team_id: TeamId,
    pub account_id: AccountId,
    pub role: String,
    pub status: IdentityMembershipStatus,
    pub revision: u64,
}

impl IdentityMembership {
    pub fn new(
        id: MemberId,
        tenant_id: TenantId,
        team_id: TeamId,
        account_id: AccountId,
        role: impl Into<String>,
    ) -> Result<Self, IdentityBootstrapError> {
        let membership = Self {
            id,
            tenant_id,
            team_id,
            account_id,
            role: role.into().trim().to_owned(),
            status: IdentityMembershipStatus::Active,
            revision: 1,
        };
        membership.validate()?;
        Ok(membership)
    }

    pub fn validate(&self) -> Result<(), IdentityBootstrapError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.team_id.as_str().trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || self.role.is_empty()
            || self.revision == 0
        {
            return Err(IdentityBootstrapError::InvalidMembership);
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.status == IdentityMembershipStatus::Active
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityProject {
    pub id: ProjectId,
    pub tenant_id: TenantId,
    pub team_id: TeamId,
    pub name: String,
    pub description: String,
    pub revision: u64,
}

impl IdentityProject {
    pub fn new(
        id: ProjectId,
        tenant_id: TenantId,
        team_id: TeamId,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Result<Self, IdentityBootstrapError> {
        let project = Self {
            id,
            tenant_id,
            team_id,
            name: name.into().trim().to_owned(),
            description: description.into(),
            revision: 1,
        };
        project.validate()?;
        Ok(project)
    }

    pub fn validate(&self) -> Result<(), IdentityBootstrapError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.team_id.as_str().trim().is_empty()
            || self.name.is_empty()
            || self.revision == 0
        {
            return Err(IdentityBootstrapError::InvalidProject);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityDeviceStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityDevice {
    pub id: DeviceId,
    pub tenant_id: TenantId,
    pub account_id: AccountId,
    pub project_id: ProjectId,
    pub binding_secret_reference_digest: String,
    pub status: IdentityDeviceStatus,
    pub revision: u64,
}

impl IdentityDevice {
    pub fn bind(
        id: DeviceId,
        tenant_id: TenantId,
        account_id: AccountId,
        project_id: ProjectId,
        binding_secret_reference_digest: impl Into<String>,
    ) -> Result<Self, IdentityBootstrapError> {
        let device = Self {
            id,
            tenant_id,
            account_id,
            project_id,
            binding_secret_reference_digest: binding_secret_reference_digest.into(),
            status: IdentityDeviceStatus::Active,
            revision: 1,
        };
        device.validate()?;
        Ok(device)
    }

    pub fn validate(&self) -> Result<(), IdentityBootstrapError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || !is_sha256(&self.binding_secret_reference_digest)
            || self.revision == 0
        {
            return Err(IdentityBootstrapError::InvalidDevice);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityBootstrapSnapshot {
    pub issuer_url: String,
    pub subject_digest: String,
    pub account: IdentityAccount,
    pub teams: Vec<IdentityTeam>,
    pub memberships: Vec<IdentityMembership>,
    pub projects: Vec<IdentityProject>,
}

impl IdentityBootstrapSnapshot {
    pub fn new(
        issuer_url: impl Into<String>,
        subject_digest: impl Into<String>,
        account: IdentityAccount,
        teams: Vec<IdentityTeam>,
        memberships: Vec<IdentityMembership>,
        projects: Vec<IdentityProject>,
    ) -> Result<Self, IdentityBootstrapError> {
        let snapshot = Self {
            issuer_url: issuer_url.into(),
            subject_digest: subject_digest.into(),
            account,
            teams,
            memberships,
            projects,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), IdentityBootstrapError> {
        self.account.validate()?;
        if self.issuer_url != self.account.issuer_url
            || self.subject_digest != self.account.subject_digest
            || !is_https_url(&self.issuer_url)
            || !is_sha256(&self.subject_digest)
        {
            return Err(IdentityBootstrapError::IdentityAssertionMismatch);
        }
        let mut team_ids = BTreeSet::new();
        for team in &self.teams {
            team.validate()?;
            if team.tenant_id != self.account.tenant_id || !team_ids.insert(team.id.clone()) {
                return Err(IdentityBootstrapError::InvalidTeam);
            }
        }
        let mut membership_ids = BTreeSet::new();
        for membership in &self.memberships {
            membership.validate()?;
            if membership.tenant_id != self.account.tenant_id
                || membership.account_id != self.account.id
                || !team_ids.contains(&membership.team_id)
                || !membership_ids.insert(membership.id.clone())
            {
                return Err(IdentityBootstrapError::InvalidMembership);
            }
        }
        let mut project_ids = BTreeSet::new();
        for project in &self.projects {
            project.validate()?;
            if project.tenant_id != self.account.tenant_id
                || !team_ids.contains(&project.team_id)
                || !project_ids.insert(project.id.clone())
            {
                return Err(IdentityBootstrapError::InvalidProject);
            }
        }
        Ok(())
    }

    pub fn select(
        &self,
        team_id: &TeamId,
        project_id: &ProjectId,
    ) -> Result<IdentityBootstrapSelection, IdentityBootstrapError> {
        self.validate()?;
        if self.account.status != IdentityAccountStatus::Active {
            return Err(IdentityBootstrapError::AccountUnavailable);
        }
        let team = self
            .teams
            .iter()
            .find(|team| &team.id == team_id)
            .cloned()
            .ok_or(IdentityBootstrapError::TeamMembershipNotFound)?;
        let membership = self
            .memberships
            .iter()
            .find(|membership| membership.team_id == *team_id && membership.is_active())
            .cloned()
            .ok_or(IdentityBootstrapError::TeamMembershipNotFound)?;
        let project = self
            .projects
            .iter()
            .find(|project| &project.id == project_id && project.team_id == *team_id)
            .cloned()
            .ok_or(IdentityBootstrapError::ProjectSelectionNotFound)?;
        Ok(IdentityBootstrapSelection {
            account: self.account.clone(),
            team,
            membership,
            project,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityBootstrapSelection {
    pub account: IdentityAccount,
    pub team: IdentityTeam,
    pub membership: IdentityMembership,
    pub project: IdentityProject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityScopeFence {
    pub tenant_id: TenantId,
    pub team_id: TeamId,
    pub project_id: ProjectId,
    pub device_id: DeviceId,
    pub account_revision: u64,
    pub team_revision: u64,
    pub membership_revision: u64,
    pub project_revision: u64,
    pub device_revision: u64,
}

impl IdentityScopeFence {
    pub fn from_selection(
        selection: &IdentityBootstrapSelection,
        device: &IdentityDevice,
    ) -> Result<Self, IdentityBootstrapError> {
        let fence = Self {
            tenant_id: selection.account.tenant_id.clone(),
            team_id: selection.team.id.clone(),
            project_id: selection.project.id.clone(),
            device_id: device.id.clone(),
            account_revision: selection.account.revision,
            team_revision: selection.team.revision,
            membership_revision: selection.membership.revision,
            project_revision: selection.project.revision,
            device_revision: device.revision,
        };
        fence.validate()?;
        Ok(fence)
    }

    pub fn validate(&self) -> Result<(), IdentityBootstrapError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.team_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.device_id.as_str().trim().is_empty()
            || self.account_revision == 0
            || self.team_revision == 0
            || self.membership_revision == 0
            || self.project_revision == 0
            || self.device_revision == 0
        {
            return Err(IdentityBootstrapError::InvalidScopeFence);
        }
        Ok(())
    }

    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySessionStatus {
    Online,
    Offline,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityAccessMode {
    Online,
    Offline,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentitySession {
    pub id: IdentitySessionId,
    pub provider_id: String,
    pub issuer_url: String,
    pub subject_digest: String,
    pub account_id: AccountId,
    pub team_id: TeamId,
    pub member_id: MemberId,
    pub project_id: ProjectId,
    pub device_id: DeviceId,
    pub scope: IdentityScopeFence,
    pub access_secret_reference_digest: String,
    pub refresh_secret_reference_digest: String,
    pub issued_at: DateTime<Utc>,
    pub access_expires_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: IdentitySessionStatus,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revision: u64,
}

impl IdentitySession {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        id: IdentitySessionId,
        provider_id: impl Into<String>,
        issuer_url: impl Into<String>,
        subject_digest: impl Into<String>,
        selection: &IdentityBootstrapSelection,
        device: &IdentityDevice,
        access_secret_reference_digest: impl Into<String>,
        refresh_secret_reference_digest: impl Into<String>,
        issued_at: DateTime<Utc>,
        access_expires_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, IdentityBootstrapError> {
        let session = Self {
            id,
            provider_id: provider_id.into(),
            issuer_url: issuer_url.into(),
            subject_digest: subject_digest.into(),
            account_id: selection.account.id.clone(),
            team_id: selection.team.id.clone(),
            member_id: selection.membership.id.clone(),
            project_id: selection.project.id.clone(),
            device_id: device.id.clone(),
            scope: IdentityScopeFence::from_selection(selection, device)?,
            access_secret_reference_digest: access_secret_reference_digest.into(),
            refresh_secret_reference_digest: refresh_secret_reference_digest.into(),
            issued_at,
            access_expires_at,
            expires_at,
            status: IdentitySessionStatus::Online,
            revoked_at: None,
            revision: 1,
        };
        session.validate()?;
        Ok(session)
    }

    pub fn validate(&self) -> Result<(), IdentityBootstrapError> {
        self.scope.validate()?;
        if self.id.as_str().trim().is_empty()
            || self.provider_id.trim().is_empty()
            || !is_https_url(&self.issuer_url)
            || !is_sha256(&self.subject_digest)
            || self.account_id.as_str().trim().is_empty()
            || self.member_id.as_str().trim().is_empty()
            || self.team_id != self.scope.team_id
            || self.project_id != self.scope.project_id
            || self.device_id != self.scope.device_id
            || !is_sha256(&self.access_secret_reference_digest)
            || !is_sha256(&self.refresh_secret_reference_digest)
            || self.issued_at >= self.access_expires_at
            || self.access_expires_at > self.expires_at
            || self.revision == 0
            || self
                .revoked_at
                .is_some_and(|revoked_at| revoked_at < self.issued_at)
        {
            return Err(IdentityBootstrapError::InvalidSession);
        }
        if self.status == IdentitySessionStatus::Revoked && self.revoked_at.is_none() {
            return Err(IdentityBootstrapError::InvalidSession);
        }
        if self.status != IdentitySessionStatus::Revoked && self.revoked_at.is_some() {
            return Err(IdentityBootstrapError::InvalidSession);
        }
        Ok(())
    }

    pub fn assert_local_access(
        &self,
        expected_scope: &IdentityScopeFence,
        now: DateTime<Utc>,
    ) -> Result<IdentityAccessMode, IdentitySessionError> {
        self.validate()
            .map_err(|_| IdentitySessionError::InvalidSession)?;
        expected_scope
            .validate()
            .map_err(|_| IdentitySessionError::ScopeMismatch)?;
        if !self.scope.matches(expected_scope) {
            return Err(IdentitySessionError::ScopeMismatch);
        }
        if self.status == IdentitySessionStatus::Revoked || self.revoked_at.is_some() {
            return Err(IdentitySessionError::Revoked);
        }
        if self.status == IdentitySessionStatus::Expired || now >= self.expires_at {
            return Err(IdentitySessionError::Expired);
        }
        Ok(match self.status {
            IdentitySessionStatus::Online => IdentityAccessMode::Online,
            IdentitySessionStatus::Offline => IdentityAccessMode::Offline,
            IdentitySessionStatus::Expired | IdentitySessionStatus::Revoked => {
                return Err(IdentitySessionError::Expired);
            }
        })
    }

    pub fn assert_cloud_access(
        &self,
        expected_scope: &IdentityScopeFence,
        now: DateTime<Utc>,
    ) -> Result<(), IdentitySessionError> {
        let mode = self.assert_local_access(expected_scope, now)?;
        if mode == IdentityAccessMode::Offline {
            return Err(IdentitySessionError::OfflineCloudUnavailable);
        }
        if now >= self.access_expires_at {
            return Err(IdentitySessionError::AccessTokenExpired);
        }
        Ok(())
    }

    pub fn reopen_offline(&self, now: DateTime<Utc>) -> Result<Self, IdentitySessionError> {
        self.assert_local_access(&self.scope, now)?;
        if self.status == IdentitySessionStatus::Offline {
            return Ok(self.clone());
        }
        let mut next = self.clone();
        next.status = IdentitySessionStatus::Offline;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(IdentitySessionError::RevisionOverflow)?;
        next.validate()
            .map_err(|_| IdentitySessionError::InvalidSession)?;
        Ok(next)
    }

    pub fn refreshed(
        &self,
        access_secret_reference_digest: impl Into<String>,
        refresh_secret_reference_digest: impl Into<String>,
        access_expires_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Self, IdentitySessionError> {
        self.assert_local_access(&self.scope, now)?;
        if access_expires_at <= now || expires_at <= access_expires_at || expires_at <= now {
            return Err(IdentitySessionError::InvalidRefreshExpiry);
        }
        let mut next = self.clone();
        next.access_secret_reference_digest = access_secret_reference_digest.into();
        next.refresh_secret_reference_digest = refresh_secret_reference_digest.into();
        next.access_expires_at = access_expires_at;
        next.expires_at = expires_at;
        next.status = IdentitySessionStatus::Online;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(IdentitySessionError::RevisionOverflow)?;
        next.validate()
            .map_err(|_| IdentitySessionError::InvalidSession)?;
        Ok(next)
    }

    pub fn revoked(&self, now: DateTime<Utc>) -> Result<Self, IdentitySessionError> {
        self.validate()
            .map_err(|_| IdentitySessionError::InvalidSession)?;
        if self.status == IdentitySessionStatus::Revoked {
            return Ok(self.clone());
        }
        if now < self.issued_at {
            return Err(IdentitySessionError::TimestampRegression);
        }
        let mut next = self.clone();
        next.status = IdentitySessionStatus::Revoked;
        next.revoked_at = Some(now);
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(IdentitySessionError::RevisionOverflow)?;
        next.validate()
            .map_err(|_| IdentitySessionError::InvalidSession)?;
        Ok(next)
    }

    pub fn expired(&self, now: DateTime<Utc>) -> Result<Self, IdentitySessionError> {
        self.validate()
            .map_err(|_| IdentitySessionError::InvalidSession)?;
        if now < self.expires_at {
            return Err(IdentitySessionError::SessionStillValid);
        }
        if self.status == IdentitySessionStatus::Expired {
            return Ok(self.clone());
        }
        if self.status == IdentitySessionStatus::Revoked {
            return Ok(self.clone());
        }
        let mut next = self.clone();
        next.status = IdentitySessionStatus::Expired;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(IdentitySessionError::RevisionOverflow)?;
        next.validate()
            .map_err(|_| IdentitySessionError::InvalidSession)?;
        Ok(next)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityBootstrapState {
    pub account: IdentityAccount,
    pub team: IdentityTeam,
    pub membership: IdentityMembership,
    pub project: IdentityProject,
    pub device: IdentityDevice,
    pub session: IdentitySession,
}

impl IdentityBootstrapState {
    pub fn validate(&self) -> Result<(), IdentityBootstrapError> {
        self.account.validate()?;
        self.team.validate()?;
        self.membership.validate()?;
        self.project.validate()?;
        self.device.validate()?;
        if self.account.status != IdentityAccountStatus::Active {
            return Err(IdentityBootstrapError::AccountUnavailable);
        }
        if !self.membership.is_active() {
            return Err(IdentityBootstrapError::TeamMembershipNotFound);
        }
        if self.device.status != IdentityDeviceStatus::Active {
            return Err(IdentityBootstrapError::DeviceUnavailable);
        }
        if self.team.tenant_id != self.account.tenant_id
            || self.membership.tenant_id != self.account.tenant_id
            || self.membership.team_id != self.team.id
            || self.membership.account_id != self.account.id
            || self.project.tenant_id != self.account.tenant_id
            || self.project.team_id != self.team.id
            || self.device.tenant_id != self.account.tenant_id
            || self.device.account_id != self.account.id
            || self.device.project_id != self.project.id
            || self.session.issuer_url != self.account.issuer_url
            || self.session.subject_digest != self.account.subject_digest
            || self.session.account_id != self.account.id
            || self.session.team_id != self.team.id
            || self.session.member_id != self.membership.id
            || self.session.project_id != self.project.id
            || self.session.device_id != self.device.id
        {
            return Err(IdentityBootstrapError::IdentityAssertionMismatch);
        }
        let selection = IdentityBootstrapSelection {
            account: self.account.clone(),
            team: self.team.clone(),
            membership: self.membership.clone(),
            project: self.project.clone(),
        };
        let expected_scope = IdentityScopeFence::from_selection(&selection, &self.device)?;
        if self.session.scope != expected_scope {
            return Err(IdentityBootstrapError::InvalidScopeFence);
        }
        self.session.validate()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum IdentityBootstrapError {
    #[error("OIDC provider configuration is invalid")]
    InvalidProviderConfiguration,
    #[error("OIDC authorization request is invalid")]
    InvalidAuthorizationRequest,
    #[error("OIDC authorization callback is invalid")]
    InvalidAuthorizationCallback,
    #[error("OIDC authorization state does not match the pending attempt")]
    AuthorizationStateMismatch,
    #[error("OIDC authorization issuer does not match the pending provider")]
    AuthorizationIssuerMismatch,
    #[error("OIDC authorization nonce does not match the pending attempt")]
    AuthorizationNonceMismatch,
    #[error("PKCE verifier is malformed")]
    InvalidPkceVerifier,
    #[error("OIDC identity assertion does not match the configured account")]
    IdentityAssertionMismatch,
    #[error("identity account is suspended or revoked")]
    AccountUnavailable,
    #[error("identity account projection is invalid")]
    InvalidAccount,
    #[error("identity team projection is invalid")]
    InvalidTeam,
    #[error("identity membership projection is invalid")]
    InvalidMembership,
    #[error("identity project projection is invalid")]
    InvalidProject,
    #[error("identity device binding is invalid")]
    InvalidDevice,
    #[error("identity device is revoked")]
    DeviceUnavailable,
    #[error("identity bootstrap selection does not contain an active team membership")]
    TeamMembershipNotFound,
    #[error("identity bootstrap selection does not contain the requested project")]
    ProjectSelectionNotFound,
    #[error("identity scope fence is invalid")]
    InvalidScopeFence,
    #[error("identity session projection is invalid")]
    InvalidSession,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum IdentityProviderError {
    #[error("OIDC provider rejected the authorization code")]
    AuthorizationCodeRejected,
    #[error("OIDC provider returned an invalid token set")]
    InvalidTokenSet,
    #[error("OIDC provider could not produce a bootstrap snapshot")]
    BootstrapUnavailable,
    #[error("OIDC provider refresh failed")]
    RefreshFailed,
    #[error("OIDC provider revocation failed")]
    RevocationFailed,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum IdentitySessionError {
    #[error("identity session projection is invalid")]
    InvalidSession,
    #[error("identity session scope does not match the requested tenant, team, project, or device")]
    ScopeMismatch,
    #[error("identity session has been revoked")]
    Revoked,
    #[error("identity session has expired")]
    Expired,
    #[error("offline identity session cannot authorize cloud-only work")]
    OfflineCloudUnavailable,
    #[error("identity access token has expired")]
    AccessTokenExpired,
    #[error("identity refresh expiry is invalid")]
    InvalidRefreshExpiry,
    #[error("identity session timestamp moved backwards")]
    TimestampRegression,
    #[error("identity session is still valid")]
    SessionStillValid,
    #[error("identity session revision overflowed")]
    RevisionOverflow,
}

fn default_oidc_scopes() -> BTreeSet<String> {
    ["openid", "profile", "email"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn normalize_issuer(issuer: &str) -> Result<String, IdentityBootstrapError> {
    let issuer = issuer.trim().trim_end_matches('/').to_owned();
    if !is_https_url(&issuer) || issuer.contains(char::is_control) {
        return Err(IdentityBootstrapError::InvalidProviderConfiguration);
    }
    Ok(issuer)
}

fn is_https_url(value: &str) -> bool {
    value.starts_with("https://")
        && value.len() > "https://".len()
        && !value.chars().any(char::is_whitespace)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            byte => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn base64_url_no_padding(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut index = 0;
    while index < bytes.len() {
        let first = bytes[index];
        let second = bytes.get(index + 1).copied();
        let third = bytes.get(index + 2).copied();
        result.push(ALPHABET[(first >> 2) as usize] as char);
        result.push(ALPHABET[((first & 0x03) << 4 | second.unwrap_or(0) >> 4) as usize] as char);
        if second.is_some() {
            result.push(
                ALPHABET[((second.unwrap_or(0) & 0x0f) << 2 | third.unwrap_or(0) >> 6) as usize]
                    as char,
            );
        }
        if third.is_some() {
            result.push(ALPHABET[(third.unwrap_or(0) & 0x3f) as usize] as char);
        }
        index += 3;
    }
    result
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 9, 0, 0)
            .single()
            .expect("valid time")
    }

    fn digest(value: &str) -> String {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    }

    fn snapshot() -> (
        IdentityBootstrapSnapshot,
        IdentityBootstrapSelection,
        IdentityDevice,
    ) {
        let account = IdentityAccount::new(
            AccountId::from("account-1"),
            TenantId::from("tenant-1"),
            "https://sso.example.test/realms/hartevo",
            digest("subject-1"),
            "Founder",
            Some(digest("founder@example.test")),
        )
        .expect("account");
        let team = IdentityTeam::new(TeamId::from("team-1"), TenantId::from("tenant-1"), "Growth")
            .expect("team");
        let membership = IdentityMembership::new(
            MemberId::from("member-1"),
            TenantId::from("tenant-1"),
            TeamId::from("team-1"),
            AccountId::from("account-1"),
            "owner",
        )
        .expect("membership");
        let project = IdentityProject::new(
            ProjectId::from("project-1"),
            TenantId::from("tenant-1"),
            TeamId::from("team-1"),
            "Launch",
            "Launch project",
        )
        .expect("project");
        let snapshot = IdentityBootstrapSnapshot::new(
            "https://sso.example.test/realms/hartevo",
            digest("subject-1"),
            account,
            vec![team],
            vec![membership],
            vec![project],
        )
        .expect("snapshot");
        let selection = snapshot
            .select(&TeamId::from("team-1"), &ProjectId::from("project-1"))
            .expect("selection");
        let device = IdentityDevice::bind(
            DeviceId::from("device-1"),
            TenantId::from("tenant-1"),
            AccountId::from("account-1"),
            ProjectId::from("project-1"),
            digest("device-reference"),
        )
        .expect("device");
        (snapshot, selection, device)
    }

    #[test]
    fn keycloak_authorization_request_uses_s256_pkce_and_redacted_debug() {
        let provider = OidcProviderConfiguration::keycloak(
            "https://sso.example.test/realms/hartevo",
            "desktop-client",
        )
        .expect("provider");
        let verifier = PkceCodeVerifier::new("a".repeat(64)).expect("verifier");
        let attempt = provider
            .authorization_attempt(
                "https://desktop.example.test/callback",
                "state-1",
                "nonce-1",
                verifier,
                provider.default_scopes.clone(),
            )
            .expect("attempt");
        let url = attempt.request().authorization_url().expect("url");
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains(attempt.request().code_challenge()));
        assert!(!format!("{attempt:?}").contains("state-1"));
        assert!(!format!("{attempt:?}").contains(&"a".repeat(64)));
    }

    #[test]
    fn session_offline_reopen_and_revocation_are_fenced() {
        let (snapshot, selection, device) = snapshot();
        let session = IdentitySession::create(
            IdentitySessionId::from("session-1"),
            KEYCLOAK_PROVIDER_ID,
            snapshot.issuer_url,
            snapshot.subject_digest,
            &selection,
            &device,
            digest("access-reference"),
            digest("refresh-reference"),
            now(),
            now() + Duration::minutes(5),
            now() + Duration::hours(1),
        )
        .expect("session");
        let offline = session
            .reopen_offline(now() + Duration::minutes(1))
            .expect("offline");
        assert_eq!(
            offline.assert_local_access(&offline.scope, now() + Duration::minutes(1)),
            Ok(IdentityAccessMode::Offline)
        );
        assert_eq!(
            offline.assert_cloud_access(&offline.scope, now() + Duration::minutes(1)),
            Err(IdentitySessionError::OfflineCloudUnavailable)
        );
        let revoked = offline
            .revoked(now() + Duration::minutes(2))
            .expect("revoked");
        assert_eq!(
            revoked.assert_local_access(&revoked.scope, now() + Duration::minutes(2)),
            Err(IdentitySessionError::Revoked)
        );
    }
}
