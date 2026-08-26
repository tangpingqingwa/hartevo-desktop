//! Azure DevOps Services provider for bounded Layer-1 read evidence.

use std::{collections::BTreeSet, env, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::model::{
    ArtifactProjection, AzureDevOpsReadRequest, AzureDevOpsResponseBody,
    AzureDevOpsResponseReceipt, AzureDevOpsScope, AzureDevOpsWorkEvidence,
    AzureReposPullRequestLink, BuildEvidence, BuildId, BuildPayload, BuildProjection, CommitSha,
    Digest, EntraSecretReference, ProviderRevision, PullRequestId, PullRequestProjection,
    RepositoryId, TimelineRecordPayload, TimelineRecordProjection, WorkItemId, WorkItemProjection,
    digest_serializable, validate_plugin_metadata,
};
use crate::transport::{
    AzureDevOpsEndpoint, AzureDevOpsHttpRequest, AzureDevOpsHttpResponse, AzureDevOpsWorkTransport,
    RequestBounds,
};
use crate::{
    AZURE_DEVOPS_ACCESS_TOKEN_ENV, AZURE_DEVOPS_API_VERSION, AZURE_DEVOPS_NATIVE_PROBE_ENV,
    AZURE_DEVOPS_NATIVE_PROBE_GATE, AZURE_DEVOPS_WORK_CONTRACT_VERSION,
    AZURE_DEVOPS_WORK_PLUGIN_VERSION_TEXT, AZURE_DEVOPS_WORK_PROVIDER_REVISION,
    AzureDevOpsWorkError, contract_digest,
};

const MAX_CREDENTIAL_LEASE_SECONDS: i64 = 900;
const MAX_ACCESS_TOKEN_SECONDS: i64 = 600;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EntraCredentialError {
    #[error("BLOCKED_ENV: Microsoft Entra credential authority is unavailable")]
    BlockedEnv,
    #[error("Microsoft Entra credential reference is unavailable")]
    Unavailable,
    #[error("Microsoft Entra access token is invalid or expired")]
    Invalid,
}

impl From<EntraCredentialError> for AzureDevOpsWorkError {
    fn from(error: EntraCredentialError) -> Self {
        match error {
            EntraCredentialError::BlockedEnv => Self::BlockedEnv,
            EntraCredentialError::Unavailable | EntraCredentialError::Invalid => {
                Self::Credential(error.to_string())
            }
        }
    }
}

/// A short-lived token borrowed by one transport request.  It is deliberately
/// not `Clone`, `Serialize`, or printable as a string through `Debug`.
pub struct EntraAccessToken {
    value: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl fmt::Debug for EntraAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EntraAccessToken")
            .field("value", &"<redacted>")
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl EntraAccessToken {
    pub fn new(
        value: impl Into<String>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, EntraCredentialError> {
        let value = value.into();
        if value.trim().is_empty()
            || value.chars().any(char::is_control)
            || expires_at <= issued_at
            || expires_at - issued_at > Duration::seconds(MAX_ACCESS_TOKEN_SECONDS)
        {
            return Err(EntraCredentialError::Invalid);
        }
        Ok(Self {
            value,
            issued_at,
            expires_at,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn validate_at(&self, at: DateTime<Utc>) -> Result<(), EntraCredentialError> {
        if at < self.issued_at || at >= self.expires_at {
            Err(EntraCredentialError::Invalid)
        } else {
            Ok(())
        }
    }
}

impl Drop for EntraAccessToken {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

pub trait EntraCredentialResolver: fmt::Debug {
    fn resolve(
        &mut self,
        reference: &EntraSecretReference,
        at: DateTime<Utc>,
    ) -> Result<EntraAccessToken, EntraCredentialError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl EntraCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &mut self,
        _reference: &EntraSecretReference,
        _at: DateTime<Utc>,
    ) -> Result<EntraAccessToken, EntraCredentialError> {
        Err(EntraCredentialError::BlockedEnv)
    }
}

/// Optional host seam for local tests or a later host integration.  It is not
/// a Connected implementation: the native probe remains `BLOCKED_ENV`, and
/// this resolver is never used to mint Hartevo Connected authority.
#[derive(Clone, Debug)]
pub struct EnvironmentEntraCredentialResolver {
    gate_env: String,
    token_env: String,
}

impl Default for EnvironmentEntraCredentialResolver {
    fn default() -> Self {
        Self {
            gate_env: AZURE_DEVOPS_NATIVE_PROBE_ENV.to_owned(),
            token_env: AZURE_DEVOPS_ACCESS_TOKEN_ENV.to_owned(),
        }
    }
}

impl EnvironmentEntraCredentialResolver {
    pub fn new(gate_env: impl Into<String>, token_env: impl Into<String>) -> Self {
        Self {
            gate_env: gate_env.into(),
            token_env: token_env.into(),
        }
    }
}

impl EntraCredentialResolver for EnvironmentEntraCredentialResolver {
    fn resolve(
        &mut self,
        _reference: &EntraSecretReference,
        at: DateTime<Utc>,
    ) -> Result<EntraAccessToken, EntraCredentialError> {
        if env::var(&self.gate_env).ok().as_deref() != Some("1") {
            return Err(EntraCredentialError::BlockedEnv);
        }
        let token = env::var(&self.token_env).map_err(|_| EntraCredentialError::BlockedEnv)?;
        EntraAccessToken::new(token, at - Duration::seconds(1), at + Duration::minutes(5))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeProbeStatus {
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeProbe {
    pub status: NativeProbeStatus,
    pub native_credentials_resolved: bool,
    pub live_https_verified: bool,
    pub native_connected_claim: bool,
    pub reason: String,
}

impl NativeProbe {
    pub fn from_environment() -> Self {
        let gate_present = env::var(AZURE_DEVOPS_NATIVE_PROBE_ENV).ok().as_deref() == Some("1");
        let reason = if gate_present {
            format!(
                "{AZURE_DEVOPS_NATIVE_PROBE_GATE} is present, but Layer 1 has no native Entra authority"
            )
        } else {
            format!("{AZURE_DEVOPS_NATIVE_PROBE_GATE} is not enabled")
        };
        Self {
            status: NativeProbeStatus::BlockedEnv,
            native_credentials_resolved: false,
            live_https_verified: false,
            native_connected_claim: false,
            reason,
        }
    }
}

pub fn native_probe_from_environment() -> NativeProbe {
    NativeProbe::from_environment()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialLease {
    lease_id: String,
    secret_reference: EntraSecretReference,
    lease_revision: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl CredentialLease {
    pub fn new(
        lease_id: impl Into<String>,
        secret_reference: EntraSecretReference,
        lease_revision: u64,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, AzureDevOpsWorkError> {
        let lease_id = lease_id.into();
        if lease_id.trim().is_empty()
            || lease_id.chars().any(char::is_control)
            || lease_revision == 0
            || expires_at <= issued_at
            || expires_at - issued_at > Duration::seconds(MAX_CREDENTIAL_LEASE_SECONDS)
        {
            return Err(AzureDevOpsWorkError::InvalidInput(
                "credential lease is invalid or exceeds the 15 minute bound".to_owned(),
            ));
        }
        Ok(Self {
            lease_id,
            secret_reference,
            lease_revision,
            issued_at,
            expires_at,
            revoked_at: None,
        })
    }

    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    pub fn secret_reference(&self) -> &EntraSecretReference {
        &self.secret_reference
    }

    pub const fn lease_revision(&self) -> u64 {
        self.lease_revision
    }

    pub const fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<(), AzureDevOpsWorkError> {
        if at < self.issued_at {
            return Err(AzureDevOpsWorkError::InvalidInput(
                "credential lease revocation precedes issuance".to_owned(),
            ));
        }
        if self.revoked_at.is_some() {
            return Err(AzureDevOpsWorkError::CredentialExpired);
        }
        self.revoked_at = Some(at);
        Ok(())
    }

    fn validate_at(
        &self,
        reference: &EntraSecretReference,
        at: DateTime<Utc>,
    ) -> Result<(), AzureDevOpsWorkError> {
        if self.secret_reference != *reference
            || at < self.issued_at
            || at >= self.expires_at
            || self.revoked_at.is_some_and(|revoked_at| revoked_at <= at)
        {
            return Err(AzureDevOpsWorkError::CredentialExpired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureDevOpsRegistrationRequest {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub scope: AzureDevOpsScope,
    pub secret_reference: EntraSecretReference,
    pub credential_lease: CredentialLease,
    pub provider_revision: ProviderRevision,
}

impl AzureDevOpsRegistrationRequest {
    pub fn baseline(
        scope: AzureDevOpsScope,
        secret_reference: EntraSecretReference,
        at: DateTime<Utc>,
    ) -> Result<Self, AzureDevOpsWorkError> {
        let credential_lease = CredentialLease::new(
            "azure-devops-work-lease-1",
            secret_reference.clone(),
            1,
            at - Duration::seconds(1),
            at + Duration::seconds(300),
        )?;
        Ok(Self {
            plugin_version: AZURE_DEVOPS_WORK_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: AZURE_DEVOPS_WORK_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            scope,
            secret_reference,
            credential_lease,
            provider_revision: ProviderRevision::parse(AZURE_DEVOPS_WORK_PROVIDER_REVISION)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureDevOpsRegistration {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    scope: AzureDevOpsScope,
    secret_reference: EntraSecretReference,
    credential_lease: CredentialLease,
    provider_revision: ProviderRevision,
    registration_digest: Digest,
    state: RegistrationState,
    revoked_at: Option<DateTime<Utc>>,
}

impl AzureDevOpsRegistration {
    pub fn new(request: AzureDevOpsRegistrationRequest) -> Result<Self, AzureDevOpsWorkError> {
        validate_plugin_metadata(&request.plugin_version, &request.contract_version)?;
        if request.contract_digest != contract_digest() {
            return Err(AzureDevOpsWorkError::ContractDigestMismatch);
        }
        if request.credential_lease.secret_reference() != &request.secret_reference {
            return Err(AzureDevOpsWorkError::RegistrationDrift(
                "credential lease and Entra secret reference differ".to_owned(),
            ));
        }
        if request.provider_revision.as_str() != AZURE_DEVOPS_WORK_PROVIDER_REVISION {
            return Err(AzureDevOpsWorkError::RegistrationDrift(
                "provider revision is not the checked-in Azure DevOps REST adapter revision"
                    .to_owned(),
            ));
        }
        let registration_digest = registration_digest(&request)?;
        Ok(Self {
            plugin_version: request.plugin_version,
            contract_version: request.contract_version,
            contract_digest: request.contract_digest,
            scope: request.scope,
            secret_reference: request.secret_reference,
            credential_lease: request.credential_lease,
            provider_revision: request.provider_revision,
            registration_digest,
            state: RegistrationState::Active,
            revoked_at: None,
        })
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn scope(&self) -> &AzureDevOpsScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &EntraSecretReference {
        &self.secret_reference
    }

    pub fn credential_lease(&self) -> &CredentialLease {
        &self.credential_lease
    }

    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.provider_revision
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn state(&self) -> &RegistrationState {
        &self.state
    }

    pub fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.revoked_at
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<(), AzureDevOpsWorkError> {
        if self.state == RegistrationState::Revoked {
            return Err(AzureDevOpsWorkError::RegistrationRevoked);
        }
        if at < self.credential_lease.issued_at() {
            return Err(AzureDevOpsWorkError::InvalidInput(
                "registration revocation precedes registration issuance".to_owned(),
            ));
        }
        self.state = RegistrationState::Revoked;
        self.revoked_at = Some(at);
        Ok(())
    }

    fn validate_active(
        &self,
        scope: &AzureDevOpsScope,
        at: DateTime<Utc>,
    ) -> Result<(), AzureDevOpsWorkError> {
        if self.state == RegistrationState::Revoked {
            return Err(AzureDevOpsWorkError::RegistrationRevoked);
        }
        if self.scope != *scope {
            return Err(AzureDevOpsWorkError::ScopeMismatch(
                "provider registration scope differs from consumer scope".to_owned(),
            ));
        }
        self.credential_lease
            .validate_at(&self.secret_reference, at)
    }
}

fn registration_digest(
    request: &AzureDevOpsRegistrationRequest,
) -> Result<Digest, AzureDevOpsWorkError> {
    let canonical = (
        &request.plugin_version,
        &request.contract_version,
        &request.contract_digest,
        &request.scope,
        &request.secret_reference,
        request.credential_lease.lease_id(),
        request.credential_lease.lease_revision(),
        &request.provider_revision,
    );
    digest_serializable(&canonical).map_err(AzureDevOpsWorkError::from)
}

pub struct AzureDevOpsServicesProvider<T, R>
where
    T: AzureDevOpsWorkTransport,
    R: EntraCredentialResolver,
{
    service: crate::AzureDevOpsWorkService,
    registration: AzureDevOpsRegistration,
    transport: T,
    credential_resolver: R,
    bounds: RequestBounds,
}

impl<T, R> fmt::Debug for AzureDevOpsServicesProvider<T, R>
where
    T: AzureDevOpsWorkTransport,
    R: EntraCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureDevOpsServicesProvider")
            .field("service", &self.service)
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("scope_digest", &self.registration.scope().digest())
            .field("transport_provenance", &self.transport.provenance())
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

impl<T, R> AzureDevOpsServicesProvider<T, R>
where
    T: AzureDevOpsWorkTransport,
    R: EntraCredentialResolver,
{
    pub fn new(
        scope: AzureDevOpsScope,
        secret_reference: EntraSecretReference,
        transport: T,
        credential_resolver: R,
        at: DateTime<Utc>,
    ) -> Result<Self, AzureDevOpsWorkError> {
        let request = AzureDevOpsRegistrationRequest::baseline(scope, secret_reference, at)?;
        Self::from_registration_request(
            request,
            transport,
            credential_resolver,
            RequestBounds::default(),
        )
    }

    pub fn from_registration_request(
        request: AzureDevOpsRegistrationRequest,
        transport: T,
        credential_resolver: R,
        bounds: RequestBounds,
    ) -> Result<Self, AzureDevOpsWorkError> {
        let registration = AzureDevOpsRegistration::new(request)?;
        let service = crate::AzureDevOpsWorkService::new();
        service.validate()?;
        Ok(Self {
            service,
            registration,
            transport,
            credential_resolver,
            bounds,
        })
    }

    pub fn service(&self) -> &crate::AzureDevOpsWorkService {
        &self.service
    }

    pub fn registration(&self) -> &AzureDevOpsRegistration {
        &self.registration
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub const fn bounds(&self) -> RequestBounds {
        self.bounds
    }

    pub fn is_connected(&self) -> bool {
        false
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<(), AzureDevOpsWorkError> {
        self.registration.revoke(at)
    }

    pub fn read(
        &mut self,
        request: &AzureDevOpsReadRequest,
        at: DateTime<Utc>,
    ) -> Result<AzureDevOpsWorkEvidence, AzureDevOpsWorkError> {
        self.registration
            .validate_active(self.registration.scope(), at)?;
        let token = self
            .credential_resolver
            .resolve(self.registration.secret_reference(), at)
            .map_err(AzureDevOpsWorkError::from)?;
        token.validate_at(at).map_err(AzureDevOpsWorkError::from)?;
        let mut receipts = Vec::new();

        let work_item_request = AzureDevOpsHttpRequest::new(
            AzureDevOpsEndpoint::WorkItem {
                organization: self.registration.scope().organization().to_owned(),
                project: self.registration.scope().project().to_owned(),
                work_item_id: self.registration.scope().work_item_id().get(),
            },
            at,
            self.bounds.max_response_bytes,
        )?;
        let work_item_response = self.execute(&token, &work_item_request)?;
        receipts.push(work_item_response.receipt().clone());
        let work_item = self.decode_work_item(&work_item_response, request)?;
        let pull_request_link = work_item
            .pull_request_links
            .iter()
            .find(|link| link.repository_id.as_str() == self.registration.scope().repository_id())
            .cloned()
            .ok_or_else(|| AzureDevOpsWorkError::PullRequestRelationMissing {
                repository: self.registration.scope().repository_id().to_owned(),
            })?;
        if let Some(expected) = request.expected_pull_request_id
            && expected != pull_request_link.pull_request_id
        {
            return Err(AzureDevOpsWorkError::PullRequestIdMismatch);
        }

        let pull_request_request = AzureDevOpsHttpRequest::new(
            AzureDevOpsEndpoint::PullRequest {
                organization: self.registration.scope().organization().to_owned(),
                project: self.registration.scope().project().to_owned(),
                repository_id: self.registration.scope().repository_id().to_owned(),
                pull_request_id: pull_request_link.pull_request_id.get(),
            },
            at,
            self.bounds.max_response_bytes,
        )?;
        let pull_request_response = self.execute(&token, &pull_request_request)?;
        receipts.push(pull_request_response.receipt().clone());
        let pull_request = self.decode_pull_request(&pull_request_response, &pull_request_link)?;

        let builds = self.read_build_evidence(
            &token,
            pull_request_link.pull_request_id,
            &pull_request,
            work_item.rev,
            at,
            &mut receipts,
        )?;
        let provenance = self.transport.provenance();
        let mut evidence = AzureDevOpsWorkEvidence {
            contract_version: AZURE_DEVOPS_WORK_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            scope_digest: self.registration.scope().digest(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_revision: self.registration.provider_revision().clone(),
            provenance,
            native_evidence: false,
            external_write_performed: false,
            outcome_authority: false,
            work_item,
            pull_request,
            builds,
            receipts,
            evidence_digest: Digest::parse(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )?,
        };
        evidence.evidence_digest = crate::model::compute_evidence_digest(&evidence)?;
        evidence.validate()?;
        Ok(evidence)
    }

    fn execute(
        &mut self,
        token: &EntraAccessToken,
        request: &AzureDevOpsHttpRequest,
    ) -> Result<AzureDevOpsHttpResponse, AzureDevOpsWorkError> {
        let response = self.transport.execute(token, request)?;
        self.validate_response(&response, request)?;
        Ok(response)
    }

    fn validate_response(
        &self,
        response: &AzureDevOpsHttpResponse,
        request: &AzureDevOpsHttpRequest,
    ) -> Result<(), AzureDevOpsWorkError> {
        if response.receipt().status != 200 {
            return Err(AzureDevOpsWorkError::UnexpectedStatus {
                status: response.receipt().status,
            });
        }
        if response.receipt().api_version != AZURE_DEVOPS_API_VERSION {
            return Err(AzureDevOpsWorkError::ApiVersionDrift {
                expected: AZURE_DEVOPS_API_VERSION.to_owned(),
                actual: response.receipt().api_version.clone(),
            });
        }
        if response.receipt().response_size > request.max_response_bytes {
            return Err(AzureDevOpsWorkError::ResponseTooLarge {
                size: response.receipt().response_size,
            });
        }
        if response.receipt().request_digest != request.digest()? {
            return Err(AzureDevOpsWorkError::RegistrationDrift(
                "response receipt is not bound to the issued request".to_owned(),
            ));
        }
        if response.receipt().provider_revision != *self.registration.provider_revision() {
            return Err(AzureDevOpsWorkError::RegistrationDrift(
                "provider revision receipt differs from registration".to_owned(),
            ));
        }
        if response.receipt().raw_payload_retained
            || response.receipt().raw_logs_retained
            || response.receipt().raw_artifacts_retained
            || response.receipt().credential_material_retained
        {
            return Err(AzureDevOpsWorkError::ForbiddenPayloadRetention);
        }
        Ok(())
    }

    fn decode_work_item(
        &self,
        response: &AzureDevOpsHttpResponse,
        request: &AzureDevOpsReadRequest,
    ) -> Result<WorkItemProjection, AzureDevOpsWorkError> {
        let AzureDevOpsResponseBody::WorkItem(payload) = response.body() else {
            return Err(AzureDevOpsWorkError::Decode(
                "work item endpoint returned a non-work-item body".to_owned(),
            ));
        };
        if payload.relations.len() > self.bounds.max_work_item_relations {
            return Err(AzureDevOpsWorkError::InvalidInput(
                "work item relation bound exceeded".to_owned(),
            ));
        }
        let expected_id = self.registration.scope().work_item_id().get();
        if payload.id != expected_id {
            return Err(AzureDevOpsWorkError::WorkItemNotFound {
                expected: expected_id,
            });
        }
        if let Some(expected) = request.expected_work_item_rev
            && payload.rev != expected
        {
            return Err(AzureDevOpsWorkError::WorkItemRevisionMismatch {
                expected,
                observed: payload.rev,
            });
        }
        if payload.rev == 0 {
            return Err(AzureDevOpsWorkError::InvalidInput(
                "work item revision must be positive".to_owned(),
            ));
        }
        let pull_request_links = payload
            .relations
            .iter()
            .filter(|relation| {
                relation.relation_type.eq_ignore_ascii_case("artifactlink")
                    || relation.url.to_ascii_lowercase().contains("pullrequest")
            })
            .filter_map(|relation| {
                AzureReposPullRequestLink::parse_relation_url(&relation.url).ok()
            })
            .collect::<Vec<_>>();
        Ok(WorkItemProjection {
            id: WorkItemId::new(payload.id)?,
            rev: payload.rev,
            title: payload.title.clone(),
            state: payload.state.clone(),
            work_item_type: payload.work_item_type.clone(),
            pull_request_links,
        })
    }

    fn decode_pull_request(
        &self,
        response: &AzureDevOpsHttpResponse,
        link: &AzureReposPullRequestLink,
    ) -> Result<PullRequestProjection, AzureDevOpsWorkError> {
        let AzureDevOpsResponseBody::PullRequest(payload) = response.body() else {
            return Err(AzureDevOpsWorkError::Decode(
                "pull request endpoint returned a non-pull-request body".to_owned(),
            ));
        };
        if payload.pull_request_id != link.pull_request_id.get() {
            return Err(AzureDevOpsWorkError::PullRequestIdMismatch);
        }
        if payload.repository_id != self.registration.scope().repository_id() {
            return Err(AzureDevOpsWorkError::PullRequestRepositoryMismatch);
        }
        let source_commit = parse_optional_commit(payload.source_commit.as_deref())?;
        let target_commit = parse_optional_commit(payload.target_commit.as_deref())?;
        let last_merge_source_commit =
            parse_optional_commit(payload.last_merge_source_commit.as_deref())?;
        let last_merge_target_commit =
            parse_optional_commit(payload.last_merge_target_commit.as_deref())?;
        if source_commit.is_none() && last_merge_source_commit.is_none() {
            return Err(AzureDevOpsWorkError::PullRequestCommitInvalid);
        }
        Ok(PullRequestProjection {
            id: PullRequestId::new(payload.pull_request_id)?,
            repository_id: RepositoryId::parse(payload.repository_id.clone())?,
            status: payload.status.clone(),
            title: payload.title.clone(),
            source_ref_name: payload.source_ref_name.clone(),
            target_ref_name: payload.target_ref_name.clone(),
            source_commit,
            target_commit,
            last_merge_source_commit,
            last_merge_target_commit,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn read_build_evidence(
        &mut self,
        token: &EntraAccessToken,
        pull_request_id: PullRequestId,
        pull_request: &PullRequestProjection,
        work_item_rev: u64,
        at: DateTime<Utc>,
        receipts: &mut Vec<AzureDevOpsResponseReceipt>,
    ) -> Result<Vec<BuildEvidence>, AzureDevOpsWorkError> {
        let mut builds = Vec::new();
        let mut page = 1;
        let mut continuation_token = None;
        let mut seen_tokens = BTreeSet::new();
        loop {
            let request = AzureDevOpsHttpRequest::new(
                AzureDevOpsEndpoint::Builds {
                    organization: self.registration.scope().organization().to_owned(),
                    project: self.registration.scope().project().to_owned(),
                    repository_id: self.registration.scope().repository_id().to_owned(),
                    pull_request_id: pull_request_id.get(),
                    page,
                    top: self.bounds.page_size,
                    continuation_token: continuation_token.clone(),
                },
                at,
                self.bounds.max_response_bytes,
            )?;
            let response = self.execute(token, &request)?;
            receipts.push(response.receipt().clone());
            let AzureDevOpsResponseBody::Builds(page_builds) = response.body() else {
                return Err(AzureDevOpsWorkError::Decode(
                    "build endpoint returned a non-build body".to_owned(),
                ));
            };
            for payload in page_builds {
                if builds.len() >= self.bounds.max_builds {
                    return Err(AzureDevOpsWorkError::InvalidInput(
                        "build bound exceeded".to_owned(),
                    ));
                }
                let build =
                    self.decode_build(payload, pull_request_id, pull_request, work_item_rev)?;
                let timeline = self.read_timeline(
                    token,
                    build.id,
                    pull_request_id,
                    work_item_rev,
                    at,
                    receipts,
                )?;
                let artifacts = self.read_artifacts(
                    token,
                    build.id,
                    pull_request_id,
                    work_item_rev,
                    at,
                    receipts,
                )?;
                builds.push(BuildEvidence {
                    build,
                    timeline,
                    artifacts,
                });
            }
            let Some(next) = response.continuation_token().map(str::to_owned) else {
                break;
            };
            if page >= self.bounds.max_pages || !seen_tokens.insert(next.clone()) {
                return Err(AzureDevOpsWorkError::Pagination(
                    "build continuation exceeded its bound or repeated".to_owned(),
                ));
            }
            continuation_token = Some(next);
            page += 1;
        }
        if builds.is_empty() {
            return Err(AzureDevOpsWorkError::BuildNotFound);
        }
        Ok(builds)
    }

    fn decode_build(
        &self,
        payload: &BuildPayload,
        pull_request_id: PullRequestId,
        pull_request: &PullRequestProjection,
        work_item_rev: u64,
    ) -> Result<BuildProjection, AzureDevOpsWorkError> {
        let source_version = CommitSha::parse(payload.source_version.clone())?;
        let expected_branch = format!("refs/pull/{}/merge", pull_request_id.get());
        if payload.source_branch != expected_branch {
            return Err(AzureDevOpsWorkError::BuildBranchMismatch);
        }
        let expected_commit = pull_request
            .last_merge_source_commit
            .as_ref()
            .or(pull_request.source_commit.as_ref())
            .ok_or(AzureDevOpsWorkError::PullRequestCommitInvalid)?;
        if &source_version != expected_commit {
            return Err(AzureDevOpsWorkError::BuildSourceMismatch);
        }
        let repository_id = payload
            .repository_id
            .as_ref()
            .map(|value| RepositoryId::parse(value.clone()))
            .transpose()?;
        if repository_id.as_ref().is_some_and(|repository| {
            repository.as_str() != self.registration.scope().repository_id()
        }) {
            return Err(AzureDevOpsWorkError::PullRequestRepositoryMismatch);
        }
        Ok(BuildProjection {
            id: BuildId::new(payload.id)?,
            build_number: payload.build_number.clone(),
            status: payload.status.clone(),
            result: payload.result.clone(),
            source_version,
            source_branch: payload.source_branch.clone(),
            repository_id,
            queue_time: payload.queue_time,
            start_time: payload.start_time,
            finish_time: payload.finish_time,
            definition_name: payload.definition_name.clone(),
            work_item_rev,
            pull_request_id,
        })
    }

    fn read_timeline(
        &mut self,
        token: &EntraAccessToken,
        build_id: BuildId,
        pull_request_id: PullRequestId,
        _work_item_rev: u64,
        at: DateTime<Utc>,
        receipts: &mut Vec<AzureDevOpsResponseReceipt>,
    ) -> Result<Vec<TimelineRecordProjection>, AzureDevOpsWorkError> {
        let mut records = Vec::new();
        let mut page = 1;
        let mut continuation_token = None;
        let mut seen_tokens = BTreeSet::new();
        loop {
            let request = AzureDevOpsHttpRequest::new(
                AzureDevOpsEndpoint::Timeline {
                    organization: self.registration.scope().organization().to_owned(),
                    project: self.registration.scope().project().to_owned(),
                    build_id: build_id.get(),
                    page,
                    top: self.bounds.page_size,
                    continuation_token: continuation_token.clone(),
                },
                at,
                self.bounds.max_response_bytes,
            )?;
            let response = self.execute(token, &request)?;
            receipts.push(response.receipt().clone());
            let AzureDevOpsResponseBody::Timeline(page_records) = response.body() else {
                return Err(AzureDevOpsWorkError::Decode(
                    "timeline endpoint returned a non-timeline body".to_owned(),
                ));
            };
            for payload in page_records {
                if records.len() >= self.bounds.max_timeline_records {
                    return Err(AzureDevOpsWorkError::TimelineBoundExceeded);
                }
                records.push(decode_timeline_record(payload)?);
            }
            let Some(next) = response.continuation_token().map(str::to_owned) else {
                break;
            };
            if page >= self.bounds.max_pages || !seen_tokens.insert(next.clone()) {
                return Err(AzureDevOpsWorkError::Pagination(
                    "timeline continuation exceeded its bound or repeated".to_owned(),
                ));
            }
            continuation_token = Some(next);
            page += 1;
        }
        let _ = pull_request_id;
        Ok(records)
    }

    fn read_artifacts(
        &mut self,
        token: &EntraAccessToken,
        build_id: BuildId,
        pull_request_id: PullRequestId,
        work_item_rev: u64,
        at: DateTime<Utc>,
        receipts: &mut Vec<AzureDevOpsResponseReceipt>,
    ) -> Result<Vec<ArtifactProjection>, AzureDevOpsWorkError> {
        let mut artifacts = Vec::new();
        let mut page = 1;
        let mut continuation_token = None;
        let mut seen_tokens = BTreeSet::new();
        loop {
            let request = AzureDevOpsHttpRequest::new(
                AzureDevOpsEndpoint::Artifacts {
                    organization: self.registration.scope().organization().to_owned(),
                    project: self.registration.scope().project().to_owned(),
                    build_id: build_id.get(),
                    page,
                    top: self.bounds.page_size,
                    continuation_token: continuation_token.clone(),
                },
                at,
                self.bounds.max_response_bytes,
            )?;
            let response = self.execute(token, &request)?;
            receipts.push(response.receipt().clone());
            let AzureDevOpsResponseBody::Artifacts(page_artifacts) = response.body() else {
                return Err(AzureDevOpsWorkError::Decode(
                    "artifact endpoint returned a non-artifact body".to_owned(),
                ));
            };
            for payload in page_artifacts {
                if artifacts.len() >= self.bounds.max_artifacts {
                    return Err(AzureDevOpsWorkError::ArtifactBoundExceeded);
                }
                artifacts.push(ArtifactProjection {
                    id: payload.id.clone(),
                    name: payload.name.clone(),
                    artifact_type: payload.artifact_type.clone(),
                    build_id,
                    work_item_rev,
                    pull_request_id,
                });
            }
            let Some(next) = response.continuation_token().map(str::to_owned) else {
                break;
            };
            if page >= self.bounds.max_pages || !seen_tokens.insert(next.clone()) {
                return Err(AzureDevOpsWorkError::Pagination(
                    "artifact continuation exceeded its bound or repeated".to_owned(),
                ));
            }
            continuation_token = Some(next);
            page += 1;
        }
        Ok(artifacts)
    }
}

fn parse_optional_commit(value: Option<&str>) -> Result<Option<CommitSha>, AzureDevOpsWorkError> {
    value
        .map(|value| CommitSha::parse(value.to_owned()))
        .transpose()
        .map_err(AzureDevOpsWorkError::from)
}

fn decode_timeline_record(
    payload: &TimelineRecordPayload,
) -> Result<TimelineRecordProjection, AzureDevOpsWorkError> {
    if payload.log_reference_present {
        return Err(AzureDevOpsWorkError::ForbiddenPayloadRetention);
    }
    Ok(TimelineRecordProjection {
        id: payload.id.clone(),
        record_type: payload.record_type.clone(),
        name: payload.name.clone(),
        state: payload.state.clone(),
        result: payload.result.clone(),
        order: payload.order,
        start_time: payload.start_time,
        finish_time: payload.finish_time,
        error_count: payload.error_count,
        warning_count: payload.warning_count,
        log_reference_present: false,
    })
}
