use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hartevo_connector_sdk::authenticated_probe::SecretMaterial;
use hartevo_connector_sdk::{
    AuthSession, ConnectorAuth, ConnectorScope, CredentialLease, ProbeObservation, ProbeStatus,
    ProviderAdapterIdentity, ProviderAdapterOperation, ProviderAdapterRegistry,
    ProviderCapabilityKey, ProviderCapabilitySupport, ProviderEvidenceClass,
    ProviderProvenanceClass, SecretReference,
};
use hartevo_domain_kernel::MissionId;
use hartevo_effect_broker::ProviderEvidenceSupport;
use serde::{Deserialize, Serialize};

use crate::model::{
    GithubCheckRunPayload, GithubCheckRunProjection, GithubEndpoint, GithubHttpRequest,
    GithubHttpResponse, GithubHttpResponseBody, GithubHttpResponseReceipt,
    GithubInstallationPayload, GithubIssuePayload, GithubIssueProjection, GithubPageReceipt,
    GithubPermissionReceipt, GithubPullRequestPayload, GithubPullRequestProjection,
    GithubRepositoryPayload, GithubRepositoryProjection, GithubWorkReadProjection,
    GithubWorkReadRequest, GithubWorkResultMetadata,
};
use crate::transport::{GithubTransportError, GithubWorkHttpTransport, UreqGithubAppTransport};
use crate::{
    GITHUB_API_VERSION, GITHUB_WORK_CAPABILITY_ID, GITHUB_WORK_CREDENTIAL_ENV,
    GITHUB_WORK_MAX_PAGE_SIZE, GITHUB_WORK_MAX_PAGES, GITHUB_WORK_NATIVE_PROBE_ENV,
    GITHUB_WORK_PLUGIN_VERSION_TEXT, GITHUB_WORK_PROPOSAL_CAPABILITY_ID, GithubWorkError,
    digest_json, github_work_plugin_digest, required_permissions, required_scopes, sha256_bytes,
    validate_identifier, validate_text,
};

pub const GITHUB_PROVIDER_ID: &str = "github";
pub const GITHUB_WORK_ADAPTER_ID: &str = "github.app-work";
pub const GITHUB_WORK_ADAPTER_VERSION: u32 = 1;
pub const GITHUB_WORK_PROVIDER_REGISTRY_VERSION: &str = "github-work-provider/v1";

/// Resolves exactly one opaque Connector SDK secret reference for one request.
/// Implementations must not retain or serialize the returned material.
pub trait GithubAppCredentialResolver: Send {
    fn resolve(
        &mut self,
        reference: &SecretReference,
        at: DateTime<Utc>,
    ) -> Result<SecretMaterial, GithubWorkError>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl GithubAppCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &mut self,
        _reference: &SecretReference,
        _at: DateTime<Utc>,
    ) -> Result<SecretMaterial, GithubWorkError> {
        Err(GithubWorkError::BlockedEnv)
    }
}

#[derive(Clone, Debug)]
pub struct EnvironmentGithubAppCredentialResolver {
    credential_env: String,
}

impl EnvironmentGithubAppCredentialResolver {
    pub fn new() -> Result<Self, GithubWorkError> {
        Self::with_env(GITHUB_WORK_CREDENTIAL_ENV)
    }

    pub fn with_env(credential_env: impl Into<String>) -> Result<Self, GithubWorkError> {
        let credential_env = credential_env.into();
        if credential_env.is_empty()
            || credential_env.len() > 128
            || !credential_env.is_ascii()
            || credential_env.contains('=')
            || credential_env.chars().any(char::is_control)
        {
            return Err(GithubWorkError::InvalidInput(
                "GitHub credential environment variable name is invalid".to_owned(),
            ));
        }
        Ok(Self { credential_env })
    }

    pub fn credential_env(&self) -> &str {
        &self.credential_env
    }
}

impl GithubAppCredentialResolver for EnvironmentGithubAppCredentialResolver {
    fn resolve(
        &mut self,
        reference: &SecretReference,
        _at: DateTime<Utc>,
    ) -> Result<SecretMaterial, GithubWorkError> {
        if reference.scope().provider_id() != GITHUB_PROVIDER_ID {
            return Err(GithubWorkError::ScopeMismatch(
                "GitHub credential reference is bound to another provider".to_owned(),
            ));
        }
        let token = std::env::var(&self.credential_env).map_err(|_| GithubWorkError::BlockedEnv)?;
        if token.trim().is_empty() || token.trim() != token || token.chars().any(char::is_control) {
            return Err(GithubWorkError::BlockedEnv);
        }
        SecretMaterial::new(token.as_bytes()).map_err(|_| GithubWorkError::BlockedEnv)
    }
}

/// The installation and repository binding carried by a mounted provider.
/// Secret bytes never enter this value.
#[derive(Clone, Debug)]
pub struct GithubAppWorkConnection {
    scope: ConnectorScope,
    mission_id: MissionId,
    secret_reference: SecretReference,
    credential_lease: CredentialLease,
    auth_session: AuthSession,
    installation_id: u64,
    owner: String,
    repository: String,
    registration_digest: String,
    revoked_at: Option<DateTime<Utc>>,
}

impl GithubAppWorkConnection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ConnectorScope,
        mission_id: MissionId,
        secret_reference: SecretReference,
        credential_lease: CredentialLease,
        auth_session: AuthSession,
        installation_id: u64,
        owner: impl Into<String>,
        repository: impl Into<String>,
    ) -> Result<Self, GithubWorkError> {
        let owner = owner.into();
        let repository = repository.into();
        let adapter = github_work_adapter_identity()?;
        let required = required_scopes();
        if scope.provider_id() != GITHUB_PROVIDER_ID
            || installation_id == 0
            || !required.is_subset(scope.scopes())
            || scope != *secret_reference.scope()
            || scope != *credential_lease.scope()
            || scope != *auth_session.scope()
            || credential_lease.adapter() != &adapter
            || auth_session.adapter() != &adapter
            || mission_id.as_str().trim().is_empty()
        {
            return Err(GithubWorkError::ScopeMismatch(
                "GitHub App connection is not bound to the exact Mission scope and adapter"
                    .to_owned(),
            ));
        }
        validate_identifier(&owner, "owner")?;
        validate_identifier(&repository, "repository")?;
        if owner.contains('/') || repository.contains('/') {
            return Err(GithubWorkError::InvalidInput(
                "GitHub repository binding must contain one owner and one repository segment"
                    .to_owned(),
            ));
        }
        let registry = github_work_provider_registry()?;
        let registration_digest = digest_json(&registry)?;
        let connection = Self {
            scope,
            mission_id,
            secret_reference,
            credential_lease,
            auth_session,
            installation_id,
            owner,
            repository,
            registration_digest,
            revoked_at: None,
        };
        connection.validate_shape()?;
        Ok(connection)
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn credential_lease(&self) -> &CredentialLease {
        &self.credential_lease
    }

    pub fn auth_session(&self) -> &AuthSession {
        &self.auth_session
    }

    pub const fn installation_id(&self) -> u64 {
        self.installation_id
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.repository)
    }

    pub fn registration_digest(&self) -> &str {
        &self.registration_digest
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<(), GithubWorkError> {
        if let Some(existing) = self.revoked_at {
            if existing == at {
                return Ok(());
            }
            return Err(GithubWorkError::Revoked);
        }
        self.secret_reference
            .revoke(at)
            .map_err(GithubWorkError::from)?;
        self.revoked_at = Some(at);
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), GithubWorkError> {
        if !valid_digest(&self.registration_digest)
            || self.scope.provider_id() != GITHUB_PROVIDER_ID
            || self.installation_id == 0
        {
            return Err(GithubWorkError::InvalidInput(
                "GitHub App connection registration binding is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_at(&self, now: DateTime<Utc>) -> Result<(), GithubWorkError> {
        if self.revoked_at.is_some_and(|revoked_at| revoked_at <= now) {
            return Err(GithubWorkError::Revoked);
        }
        let valid_until = self
            .auth_session
            .expires_at()
            .min(now + Duration::seconds(120));
        if valid_until <= now {
            return Err(GithubWorkError::AuthExpired);
        }
        let observation = ProbeObservation::new(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ControlledProvider,
            now,
            valid_until,
            sha256_bytes(self.registration_digest.as_bytes()),
        )
        .map_err(GithubWorkError::from)?;
        ConnectorAuth::record_probe(
            &self.secret_reference,
            &self.credential_lease,
            &self.auth_session,
            "probe-result-github-work",
            1,
            observation,
        )
        .map(|_| ())
        .map_err(GithubWorkError::from)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubInstallationProjection {
    pub id: u64,
    pub account_login: String,
    pub permissions: std::collections::BTreeMap<String, String>,
    pub suspended_at: Option<DateTime<Utc>>,
}

impl GithubInstallationProjection {
    fn from_payload(payload: GithubInstallationPayload) -> Result<Self, GithubWorkError> {
        let account_login = payload
            .account
            .and_then(|account| account.login)
            .ok_or_else(|| {
                GithubWorkError::Decode(
                    "GitHub installation response has no account login".to_owned(),
                )
            })?;
        validate_identifier(&account_login, "installation account")?;
        if payload.id == 0 {
            return Err(GithubWorkError::Decode(
                "GitHub installation response has no positive id".to_owned(),
            ));
        }
        Ok(Self {
            id: payload.id,
            account_login,
            permissions: payload.permissions,
            suspended_at: payload.suspended_at,
        })
    }

    fn validate(&self) -> Result<(), GithubWorkError> {
        if self.id == 0 || self.suspended_at.is_some() {
            return Err(GithubWorkError::InstallationRevoked);
        }
        validate_identifier(&self.account_login, "installation account")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubAppProbeReceipt {
    pub installation: GithubInstallationProjection,
    pub repository: GithubRepositoryProjection,
    pub permission: GithubPermissionReceipt,
    pub installation_response: GithubHttpResponseReceipt,
    pub repository_response: GithubHttpResponseReceipt,
    pub scope_digest: String,
    pub registration_digest: String,
    pub provider_revision: u64,
    pub plugin_version: String,
    pub plugin_digest: String,
    pub provenance_class: ProviderProvenanceClass,
    pub native_transport: bool,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub connected: bool,
    pub probe_digest: String,
}

impl GithubAppProbeReceipt {
    #[allow(clippy::too_many_arguments)]
    fn seal(
        installation: GithubInstallationProjection,
        repository: GithubRepositoryProjection,
        permission: GithubPermissionReceipt,
        installation_response: GithubHttpResponseReceipt,
        repository_response: GithubHttpResponseReceipt,
        scope_digest: String,
        registration_digest: String,
        provider_revision: u64,
        provenance_class: ProviderProvenanceClass,
        native_transport: bool,
        observed_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, GithubWorkError> {
        let connected =
            native_transport && provenance_class == ProviderProvenanceClass::ProductionProvider;
        let mut receipt = Self {
            installation,
            repository,
            permission,
            installation_response,
            repository_response,
            scope_digest,
            registration_digest,
            provider_revision,
            plugin_version: GITHUB_WORK_PLUGIN_VERSION_TEXT.to_owned(),
            plugin_digest: github_work_plugin_digest(),
            provenance_class,
            native_transport,
            observed_at,
            valid_until,
            connected,
            probe_digest: String::new(),
        };
        receipt.probe_digest = receipt.calculate_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), GithubWorkError> {
        self.installation.validate()?;
        self.permission.validate()?;
        if !valid_digest(&self.scope_digest)
            || !valid_digest(&self.registration_digest)
            || !valid_digest(&self.plugin_digest)
            || !valid_digest(&self.probe_digest)
            || self.plugin_version != GITHUB_WORK_PLUGIN_VERSION_TEXT
            || self.provider_revision == 0
            || self.valid_until <= self.observed_at
            || self.valid_until - self.observed_at > Duration::seconds(120)
            || self.observed_at.timestamp() <= 0
            || (self.native_transport
                && self.provenance_class != ProviderProvenanceClass::ProductionProvider)
            || self.connected
                != (self.native_transport
                    && self.provenance_class == ProviderProvenanceClass::ProductionProvider)
            || self.installation_response.status / 100 != 2
            || self.repository_response.status / 100 != 2
            || self.installation_response.api_version != GITHUB_API_VERSION
            || self.repository_response.api_version != GITHUB_API_VERSION
        {
            return Err(GithubWorkError::InvalidInput(
                "GitHub App probe receipt is not canonical".to_owned(),
            ));
        }
        if self.calculate_digest()? != self.probe_digest {
            return Err(GithubWorkError::InvalidInput(
                "GitHub App probe digest does not match its evidence".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn probe_digest(&self) -> &str {
        &self.probe_digest
    }

    fn calculate_digest(&self) -> Result<String, GithubWorkError> {
        digest_json(&GithubAppProbeDigest {
            installation: &self.installation,
            repository: &self.repository,
            permission: &self.permission,
            installation_response: &self.installation_response,
            repository_response: &self.repository_response,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            provider_revision: self.provider_revision,
            plugin_version: &self.plugin_version,
            plugin_digest: &self.plugin_digest,
            provenance_class: self.provenance_class,
            native_transport: self.native_transport,
            observed_at: self.observed_at,
            valid_until: self.valid_until,
            connected: self.connected,
        })
    }
}

#[derive(Serialize)]
struct GithubAppProbeDigest<'a> {
    installation: &'a GithubInstallationProjection,
    repository: &'a GithubRepositoryProjection,
    permission: &'a GithubPermissionReceipt,
    installation_response: &'a GithubHttpResponseReceipt,
    repository_response: &'a GithubHttpResponseReceipt,
    scope_digest: &'a String,
    registration_digest: &'a String,
    provider_revision: u64,
    plugin_version: &'a String,
    plugin_digest: &'a String,
    provenance_class: ProviderProvenanceClass,
    native_transport: bool,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    connected: bool,
}

pub type GithubWorkProviderRevision = u64;

/// Provider registry metadata is built from the existing Effect Broker
/// contract types.  It grants no execution authority; it binds probe/read
/// evidence to this adapter and its provenance class.
pub fn github_work_provider_registry() -> Result<ProviderAdapterRegistry, GithubWorkError> {
    let adapter = github_work_adapter_identity()?;
    let probe_support = [
        ProviderEvidenceSupport::new(
            ProviderAdapterOperation::Probe,
            ProviderEvidenceClass::ProbeObservation,
            ProviderProvenanceClass::ControlledProvider,
        ),
        ProviderEvidenceSupport::new(
            ProviderAdapterOperation::Probe,
            ProviderEvidenceClass::ProbeObservation,
            ProviderProvenanceClass::ProductionProvider,
        ),
    ]
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(|error| GithubWorkError::Contract(error.to_string()))?;
    let read_support = [
        ProviderEvidenceSupport::new(
            ProviderAdapterOperation::Read,
            ProviderEvidenceClass::ReadObservation,
            ProviderProvenanceClass::ControlledProvider,
        ),
        ProviderEvidenceSupport::new(
            ProviderAdapterOperation::Read,
            ProviderEvidenceClass::ReadObservation,
            ProviderProvenanceClass::ProductionProvider,
        ),
    ]
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(|error| GithubWorkError::Contract(error.to_string()))?;
    let probe = ProviderCapabilitySupport::new(
        ProviderCapabilityKey::new(GITHUB_PROVIDER_ID, "connection.probe")
            .map_err(|error| GithubWorkError::Contract(error.to_string()))?,
        adapter.clone(),
        probe_support,
    )
    .map_err(|error| GithubWorkError::Contract(error.to_string()))?;
    let read = ProviderCapabilitySupport::new(
        ProviderCapabilityKey::new(GITHUB_PROVIDER_ID, GITHUB_WORK_CAPABILITY_ID)
            .map_err(|error| GithubWorkError::Contract(error.to_string()))?,
        adapter.clone(),
        read_support.clone(),
    )
    .map_err(|error| GithubWorkError::Contract(error.to_string()))?;
    let proposal = ProviderCapabilitySupport::new(
        ProviderCapabilityKey::new(GITHUB_PROVIDER_ID, GITHUB_WORK_PROPOSAL_CAPABILITY_ID)
            .map_err(|error| GithubWorkError::Contract(error.to_string()))?,
        adapter,
        read_support,
    )
    .map_err(|error| GithubWorkError::Contract(error.to_string()))?;
    ProviderAdapterRegistry::new(
        GITHUB_WORK_PROVIDER_REGISTRY_VERSION,
        [probe, read, proposal],
    )
    .map_err(|error| GithubWorkError::Contract(error.to_string()))
}

fn github_work_adapter_identity() -> Result<ProviderAdapterIdentity, GithubWorkError> {
    ProviderAdapterIdentity::new(GITHUB_WORK_ADAPTER_ID, GITHUB_WORK_ADAPTER_VERSION)
        .map_err(|error| GithubWorkError::Contract(error.to_string()))
}

pub struct GithubAppWorkProvider<T, R>
where
    T: GithubWorkHttpTransport,
    R: GithubAppCredentialResolver,
{
    connection: GithubAppWorkConnection,
    transport: T,
    resolver: R,
    provider_revision: GithubWorkProviderRevision,
    last_probe: Option<GithubAppProbeReceipt>,
}

impl<T, R> fmt::Debug for GithubAppWorkProvider<T, R>
where
    T: GithubWorkHttpTransport,
    R: GithubAppCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubAppWorkProvider")
            .field("connection", &self.connection)
            .field("provider_revision", &self.provider_revision)
            .field(
                "last_probe",
                &self
                    .last_probe
                    .as_ref()
                    .map(GithubAppProbeReceipt::probe_digest),
            )
            .field("transport", &"<opaque>")
            .field("resolver", &"<opaque>")
            .finish()
    }
}

impl<T, R> GithubAppWorkProvider<T, R>
where
    T: GithubWorkHttpTransport,
    R: GithubAppCredentialResolver,
{
    pub fn new(
        connection: GithubAppWorkConnection,
        transport: T,
        resolver: R,
        now: DateTime<Utc>,
    ) -> Result<Self, GithubWorkError> {
        connection.validate_at(now)?;
        github_work_provider_registry()?;
        Ok(Self {
            connection,
            transport,
            resolver,
            provider_revision: 0,
            last_probe: None,
        })
    }

    pub fn connection(&self) -> &GithubAppWorkConnection {
        &self.connection
    }

    pub fn last_probe(&self) -> Option<&GithubAppProbeReceipt> {
        self.last_probe.as_ref()
    }

    pub fn is_connected(&self) -> bool {
        self.last_probe
            .as_ref()
            .is_some_and(GithubAppProbeReceipt::is_connected)
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<(), GithubWorkError> {
        self.connection.revoke(at)
    }

    pub fn probe(&mut self, now: DateTime<Utc>) -> Result<GithubAppProbeReceipt, GithubWorkError> {
        self.connection.validate_at(now)?;
        let token = self.resolve_token(now)?;
        self.probe_with_token(&token, now)
    }

    pub fn read(
        &mut self,
        request: &GithubWorkReadRequest,
        now: DateTime<Utc>,
    ) -> Result<GithubWorkReadProjection, GithubWorkError> {
        request.validate()?;
        self.connection.validate_at(now)?;
        let token = self.resolve_token(now)?;
        let probe = self.probe_with_token(&token, now)?;
        let mut page_receipts = Vec::new();
        let issue = request
            .issue_number
            .map(|number| self.collect_issue(&token, request, number, now, &mut page_receipts))
            .transpose()?;
        let pull_request = request
            .pull_request_number
            .map(|number| {
                self.collect_pull_request(&token, request, number, now, &mut page_receipts)
            })
            .transpose()?;
        if let (Some(check_ref), Some(pull_request)) = (&request.check_ref, pull_request.as_ref())
            && valid_sha(check_ref)
            && pull_request.head_sha != *check_ref
        {
            return Err(GithubWorkError::StaleHead);
        }
        let check_runs = request
            .check_ref
            .as_deref()
            .map(|reference| {
                self.collect_check_runs(&token, request, reference, now, &mut page_receipts)
            })
            .transpose()?
            .unwrap_or_default();
        if let Some(check_ref) = &request.check_ref
            && valid_sha(check_ref)
            && check_runs.iter().any(|run| run.head_sha != *check_ref)
        {
            return Err(GithubWorkError::StaleHead);
        }
        let metadata = GithubWorkResultMetadata {
            scope_digest: self.connection.scope().digest(),
            registration_digest: self.connection.registration_digest().to_owned(),
            probe_digest: probe.probe_digest().to_owned(),
            provider_revision: probe.provider_revision,
            plugin_version: GITHUB_WORK_PLUGIN_VERSION_TEXT.to_owned(),
            plugin_digest: github_work_plugin_digest(),
            provenance_class: probe.provenance_class,
            native_transport: probe.native_transport,
            observed_at: now,
        };
        GithubWorkReadProjection::seal(
            metadata,
            probe.repository.clone(),
            issue,
            pull_request,
            check_runs,
            page_receipts,
        )
    }

    fn resolve_token(&mut self, now: DateTime<Utc>) -> Result<String, GithubWorkError> {
        let material = self
            .resolver
            .resolve(self.connection.secret_reference(), now)?;
        let token = std::str::from_utf8(material.as_bytes())
            .map_err(|_| GithubWorkError::BlockedEnv)?
            .to_owned();
        if token.trim().is_empty() || token.trim() != token || token.chars().any(char::is_control) {
            return Err(GithubWorkError::BlockedEnv);
        }
        Ok(token)
    }

    #[allow(clippy::too_many_lines)]
    fn probe_with_token(
        &mut self,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<GithubAppProbeReceipt, GithubWorkError> {
        let installation_request = GithubHttpRequest::new(
            GithubEndpoint::Installation {
                installation_id: self.connection.installation_id(),
            },
            None,
            now,
        )?;
        let installation_response =
            self.execute(token, &installation_request, ProbeTarget::Installation)?;
        ensure_success(&installation_response)?;
        let installation_receipt = installation_response.receipt.clone();
        let Some(GithubHttpResponseBody::Installation(installation_payload)) =
            installation_response.body
        else {
            return Err(GithubWorkError::Decode(
                "GitHub installation response body has the wrong shape".to_owned(),
            ));
        };
        let installation = GithubInstallationProjection::from_payload(installation_payload)?;
        if installation.id != self.connection.installation_id()
            || installation.account_login != self.connection.owner()
        {
            return Err(GithubWorkError::InstallationRevoked);
        }
        installation.validate()?;
        let permission = GithubPermissionReceipt::seal(
            installation.id,
            installation.permissions.clone(),
            required_permissions(),
            now,
            installation_receipt.clone(),
        )?;
        permission.validate()?;

        let repository_request = GithubHttpRequest::new(
            GithubEndpoint::Repository {
                owner: self.connection.owner().to_owned(),
                repository: self.connection.repository().to_owned(),
            },
            None,
            now,
        )?;
        let repository_response =
            self.execute(token, &repository_request, ProbeTarget::Repository)?;
        ensure_success(&repository_response)?;
        let repository_receipt = repository_response.receipt.clone();
        let Some(GithubHttpResponseBody::Repository(repository_payload)) = repository_response.body
        else {
            return Err(GithubWorkError::Decode(
                "GitHub repository response body has the wrong shape".to_owned(),
            ));
        };
        let repository = repository_projection(repository_payload)?;
        if repository.full_name != self.connection.full_name()
            || repository.owner != self.connection.owner()
            || repository.name != self.connection.repository()
            || !repository.permissions.get("pull").copied().unwrap_or(false)
        {
            return Err(GithubWorkError::RepositoryRevoked);
        }
        if let Some(previous) = &self.last_probe {
            if previous.installation.id != installation.id
                || previous.installation.account_login != installation.account_login
            {
                return Err(GithubWorkError::InstallationRevoked);
            }
            if previous.repository.id != repository.id
                || previous.repository.full_name != repository.full_name
            {
                return Err(GithubWorkError::RepositoryRevoked);
            }
            if previous.permission.permissions != permission.permissions {
                return Err(GithubWorkError::PermissionDrift);
            }
        }
        self.provider_revision = self.provider_revision.checked_add(1).ok_or_else(|| {
            GithubWorkError::InvalidInput("provider revision overflow".to_owned())
        })?;
        let valid_until = self
            .connection
            .auth_session()
            .expires_at()
            .min(now + Duration::seconds(120));
        let receipt = GithubAppProbeReceipt::seal(
            installation,
            repository,
            permission,
            installation_receipt,
            repository_receipt,
            self.connection.scope().digest(),
            self.connection.registration_digest().to_owned(),
            self.provider_revision,
            self.transport.provenance_class(),
            self.transport.is_native(),
            now,
            valid_until,
        )?;
        self.last_probe = Some(receipt.clone());
        Ok(receipt)
    }

    fn execute(
        &self,
        token: &str,
        request: &GithubHttpRequest,
        target: ProbeTarget,
    ) -> Result<GithubHttpResponse, GithubWorkError> {
        self.transport
            .execute(token, request)
            .map_err(|error| map_transport_error(error, target))
    }

    fn collect_issue(
        &self,
        token: &str,
        request: &GithubWorkReadRequest,
        number: u64,
        now: DateTime<Utc>,
        page_receipts: &mut Vec<GithubPageReceipt>,
    ) -> Result<GithubIssueProjection, GithubWorkError> {
        let mut page = 1;
        loop {
            if page > GITHUB_WORK_MAX_PAGES {
                return Err(GithubWorkError::Pagination(
                    "issue pagination exceeded the bounded page count".to_owned(),
                ));
            }
            let page_size = request.page_size.min(GITHUB_WORK_MAX_PAGE_SIZE);
            let endpoint = GithubEndpoint::Issues {
                owner: self.connection.owner().to_owned(),
                repository: self.connection.repository().to_owned(),
                page,
                per_page: page_size,
            };
            let etag = (page == 1)
                .then(|| request.etag_for(crate::model::RESOURCE_ISSUES))
                .flatten();
            let http_request = GithubHttpRequest::new(endpoint, etag, now)?;
            let response = self.execute(token, &http_request, ProbeTarget::Read)?;
            if response.receipt.status == 304 {
                return Err(GithubWorkError::NotModified);
            }
            ensure_success(&response)?;
            let next = next_page(page, response.receipt.next_page)?;
            page_receipts.push(GithubPageReceipt::from_response(&http_request, &response)?);
            let Some(GithubHttpResponseBody::Issues(items)) = response.body else {
                return Err(GithubWorkError::Decode(
                    "GitHub issue response body has the wrong shape".to_owned(),
                ));
            };
            if let Some(item) = items.into_iter().find(|item| item.number == number) {
                return issue_projection(item);
            }
            let Some(next) = next else {
                return Err(GithubWorkError::ItemNotFound);
            };
            page = next;
        }
    }

    fn collect_pull_request(
        &self,
        token: &str,
        request: &GithubWorkReadRequest,
        number: u64,
        now: DateTime<Utc>,
        page_receipts: &mut Vec<GithubPageReceipt>,
    ) -> Result<GithubPullRequestProjection, GithubWorkError> {
        let mut page = 1;
        loop {
            if page > GITHUB_WORK_MAX_PAGES {
                return Err(GithubWorkError::Pagination(
                    "pull request pagination exceeded the bounded page count".to_owned(),
                ));
            }
            let page_size = request.page_size.min(GITHUB_WORK_MAX_PAGE_SIZE);
            let endpoint = GithubEndpoint::PullRequests {
                owner: self.connection.owner().to_owned(),
                repository: self.connection.repository().to_owned(),
                page,
                per_page: page_size,
            };
            let etag = (page == 1)
                .then(|| request.etag_for(crate::model::RESOURCE_PULL_REQUESTS))
                .flatten();
            let http_request = GithubHttpRequest::new(endpoint, etag, now)?;
            let response = self.execute(token, &http_request, ProbeTarget::Read)?;
            if response.receipt.status == 304 {
                return Err(GithubWorkError::NotModified);
            }
            ensure_success(&response)?;
            let next = next_page(page, response.receipt.next_page)?;
            page_receipts.push(GithubPageReceipt::from_response(&http_request, &response)?);
            let Some(GithubHttpResponseBody::PullRequests(items)) = response.body else {
                return Err(GithubWorkError::Decode(
                    "GitHub pull request response body has the wrong shape".to_owned(),
                ));
            };
            if let Some(item) = items.into_iter().find(|item| item.number == number) {
                return pull_request_projection(item);
            }
            let Some(next) = next else {
                return Err(GithubWorkError::ItemNotFound);
            };
            page = next;
        }
    }

    fn collect_check_runs(
        &self,
        token: &str,
        request: &GithubWorkReadRequest,
        reference: &str,
        now: DateTime<Utc>,
        page_receipts: &mut Vec<GithubPageReceipt>,
    ) -> Result<Vec<GithubCheckRunProjection>, GithubWorkError> {
        let mut page = 1;
        let mut projections = Vec::new();
        loop {
            if page > GITHUB_WORK_MAX_PAGES {
                return Err(GithubWorkError::Pagination(
                    "check run pagination exceeded the bounded page count".to_owned(),
                ));
            }
            let page_size = request.page_size.min(GITHUB_WORK_MAX_PAGE_SIZE);
            let endpoint = GithubEndpoint::CheckRuns {
                owner: self.connection.owner().to_owned(),
                repository: self.connection.repository().to_owned(),
                reference: reference.to_owned(),
                page,
                per_page: page_size,
            };
            let etag = (page == 1)
                .then(|| request.etag_for(crate::model::RESOURCE_CHECK_RUNS))
                .flatten();
            let http_request = GithubHttpRequest::new(endpoint, etag, now)?;
            let response = self.execute(token, &http_request, ProbeTarget::Read)?;
            if response.receipt.status == 304 {
                return Err(GithubWorkError::NotModified);
            }
            ensure_success(&response)?;
            let next = next_page(page, response.receipt.next_page)?;
            page_receipts.push(GithubPageReceipt::from_response(&http_request, &response)?);
            let Some(GithubHttpResponseBody::CheckRuns(items)) = response.body else {
                return Err(GithubWorkError::Decode(
                    "GitHub check run response body has the wrong shape".to_owned(),
                ));
            };
            for item in items {
                let projection = check_run_projection(item)?;
                if valid_sha(reference) && projection.head_sha != reference {
                    return Err(GithubWorkError::StaleHead);
                }
                projections.push(projection);
            }
            let Some(next) = next else {
                return Ok(projections);
            };
            page = next;
        }
    }
}

#[derive(Clone, Copy)]
enum ProbeTarget {
    Installation,
    Repository,
    Read,
}

fn map_transport_error(error: GithubTransportError, target: ProbeTarget) -> GithubWorkError {
    match (target, error) {
        (
            ProbeTarget::Installation,
            GithubTransportError::NotFound
            | GithubTransportError::Unauthorized
            | GithubTransportError::Forbidden,
        ) => GithubWorkError::InstallationRevoked,
        (ProbeTarget::Repository, GithubTransportError::NotFound) => {
            GithubWorkError::RepositoryRevoked
        }
        (
            ProbeTarget::Repository,
            GithubTransportError::Unauthorized | GithubTransportError::Forbidden,
        ) => GithubWorkError::PermissionDrift,
        (_, other) => GithubWorkError::from(other),
    }
}

fn ensure_success(response: &GithubHttpResponse) -> Result<(), GithubWorkError> {
    if (200..=299).contains(&response.receipt.status) {
        Ok(())
    } else if response.receipt.status == 304 {
        Err(GithubWorkError::NotModified)
    } else {
        Err(GithubWorkError::Transport(format!(
            "unexpected GitHub response status {}",
            response.receipt.status
        )))
    }
}

fn next_page(current: u32, next: Option<u32>) -> Result<Option<u32>, GithubWorkError> {
    if let Some(next) = next {
        if next <= current || next > GITHUB_WORK_MAX_PAGES {
            return Err(GithubWorkError::Pagination(
                "GitHub next-page receipt is outside the bounded sequence".to_owned(),
            ));
        }
        Ok(Some(next))
    } else {
        Ok(None)
    }
}

fn valid_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn repository_projection(
    payload: GithubRepositoryPayload,
) -> Result<GithubRepositoryProjection, GithubWorkError> {
    let owner = payload.owner.login.ok_or_else(|| {
        GithubWorkError::Decode("GitHub repository response has no owner login".to_owned())
    })?;
    validate_identifier(&owner, "repository owner")?;
    validate_identifier(&payload.name, "repository name")?;
    validate_identifier(&payload.full_name, "full_name")?;
    validate_text(&payload.default_branch, "default branch", 256)?;
    if payload.id == 0 || payload.full_name != format!("{owner}/{}", payload.name) {
        return Err(GithubWorkError::RepositoryRevoked);
    }
    Ok(GithubRepositoryProjection {
        id: payload.id,
        owner,
        name: payload.name,
        full_name: payload.full_name,
        default_branch: payload.default_branch,
        permissions: payload.permissions,
    })
}

fn issue_projection(payload: GithubIssuePayload) -> Result<GithubIssueProjection, GithubWorkError> {
    if payload.number == 0 {
        return Err(GithubWorkError::Decode(
            "GitHub issue number is zero".to_owned(),
        ));
    }
    validate_text(&payload.title, "issue title", 4_096)?;
    validate_text(&payload.state, "issue state", 64)?;
    if let Some(body) = &payload.body
        && (body.len() > 64 * 1024 || body.chars().any(char::is_control))
    {
        return Err(GithubWorkError::Decode(
            "GitHub issue body is invalid".to_owned(),
        ));
    }
    Ok(GithubIssueProjection {
        number: payload.number,
        title: payload.title,
        state: payload.state,
        body: payload.body,
        html_url: payload.html_url,
    })
}

fn pull_request_projection(
    payload: GithubPullRequestPayload,
) -> Result<GithubPullRequestProjection, GithubWorkError> {
    if payload.number == 0 {
        return Err(GithubWorkError::Decode(
            "GitHub pull request number is zero".to_owned(),
        ));
    }
    validate_text(&payload.title, "pull request title", 4_096)?;
    validate_text(&payload.state, "pull request state", 64)?;
    validate_text(&payload.base.ref_name, "pull request base ref", 512)?;
    validate_text(&payload.head.ref_name, "pull request head ref", 512)?;
    if !valid_sha(&payload.base.sha) || !valid_sha(&payload.head.sha) {
        return Err(GithubWorkError::StaleHead);
    }
    Ok(GithubPullRequestProjection {
        number: payload.number,
        title: payload.title,
        state: payload.state,
        base_ref: payload.base.ref_name,
        base_sha: payload.base.sha,
        head_ref: payload.head.ref_name,
        head_sha: payload.head.sha,
        body: payload.body,
        draft: payload.draft,
        merged: payload.merged,
        html_url: payload.html_url,
    })
}

fn check_run_projection(
    payload: GithubCheckRunPayload,
) -> Result<GithubCheckRunProjection, GithubWorkError> {
    if payload.id == 0
        || payload.name.trim().is_empty()
        || payload.status.trim().is_empty()
        || !valid_sha(&payload.head_sha)
    {
        return Err(GithubWorkError::Decode(
            "GitHub check run projection is invalid".to_owned(),
        ));
    }
    Ok(GithubCheckRunProjection {
        id: payload.id,
        name: payload.name,
        status: payload.status,
        conclusion: payload.conclusion,
        head_sha: payload.head_sha,
        html_url: payload.html_url,
    })
}

/// The native path is intentionally disabled unless the explicit environment
/// gate is set.  A loopback or fixture transport is never used here.
pub fn native_probe_from_environment(
    connection: GithubAppWorkConnection,
    now: DateTime<Utc>,
) -> Result<GithubAppProbeReceipt, GithubWorkError> {
    if std::env::var(GITHUB_WORK_NATIVE_PROBE_ENV).ok().as_deref() != Some("1") {
        return Err(GithubWorkError::BlockedEnv);
    }
    let transport = UreqGithubAppTransport::github_api()?;
    let resolver = EnvironmentGithubAppCredentialResolver::new()?;
    let mut provider = GithubAppWorkProvider::new(connection, transport, resolver, now)?;
    provider.probe(now)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
