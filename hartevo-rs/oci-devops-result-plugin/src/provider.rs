//! Bounded OCI DevOps provider with reversible registration and read fences.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::model::{
    BuildRunId, CompartmentId, DeploymentId, Digest, OciBuildRunPayload, OciBuildRunProjection,
    OciDeploymentPayload, OciDeploymentProjection, OciDevopsEvidence, OciDevopsReadRequest,
    OciDevopsScope, OciResponseBody, OciStageFence, OciStagePayload, OciStageProjection,
    OciWorkRequestPayload, OciWorkRequestProjection, Ocid, OpaquePageToken, ProviderRevision,
    ResourceId, StateValue, WorkRequestId, compute_evidence_digest, digest_serializable,
    validate_artifact_bounds, validate_plugin_metadata, validate_stage_bounds,
};
use crate::transport::{
    OciDevopsEndpoint, OciDevopsHttpRequest, OciDevopsHttpResponse, OciDevopsTransport,
    OciTransportError,
};
use crate::{
    OCI_DEVOPS_API_VERSION, OCI_DEVOPS_MAX_BUILD_RUNS, OCI_DEVOPS_MAX_DEPLOYMENTS,
    OCI_DEVOPS_MAX_PAGES, OCI_DEVOPS_MAX_STAGES, OCI_DEVOPS_MAX_WORK_REQUESTS,
    OCI_DEVOPS_NATIVE_PROBE_ENV, OCI_DEVOPS_NATIVE_PROBE_GATE, OCI_DEVOPS_PROVIDER_REVISION,
    OCI_DEVOPS_RESULT_CONTRACT_VERSION, OCI_DEVOPS_RESULT_PLUGIN_VERSION_TEXT, OciDevopsError,
    contract_digest, evidence_policy_digest,
};

const MAX_CREDENTIAL_LEASE_SECONDS: i64 = 900;
const MAX_SIGNING_CREDENTIAL_SECONDS: i64 = 600;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OciCredentialError {
    #[error("BLOCKED_ENV: OCI signing-key authority is unavailable")]
    BlockedEnv,
    #[error("OCI signing-key reference is unavailable")]
    Unavailable,
    #[error("OCI signing credential is invalid or expired")]
    Invalid,
}

impl From<OciCredentialError> for OciDevopsError {
    fn from(error: OciCredentialError) -> Self {
        match error {
            OciCredentialError::BlockedEnv => Self::BlockedEnv,
            OciCredentialError::Unavailable | OciCredentialError::Invalid => {
                Self::Credential(error.to_string())
            }
        }
    }
}

/// Short-lived signing material borrowed by one request. It is never cloned,
/// serialized, or printed, and zeroizes when dropped.
pub struct OciAccessCredential {
    value: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl fmt::Debug for OciAccessCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OciAccessCredential")
            .field("value", &"<redacted>")
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl OciAccessCredential {
    pub fn new(
        value: impl Into<String>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, OciCredentialError> {
        let value = value.into();
        if value.trim().is_empty()
            || value.chars().any(char::is_control)
            || expires_at <= issued_at
            || expires_at - issued_at > Duration::seconds(MAX_SIGNING_CREDENTIAL_SECONDS)
        {
            return Err(OciCredentialError::Invalid);
        }
        Ok(Self {
            value,
            issued_at,
            expires_at,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.value.trim().is_empty()
    }

    pub fn validate_at(&self, at: DateTime<Utc>) -> Result<(), OciCredentialError> {
        if at < self.issued_at || at >= self.expires_at {
            Err(OciCredentialError::Invalid)
        } else {
            Ok(())
        }
    }

    pub(crate) fn authorization_header(&self) -> String {
        format!("Signature {value}", value = self.value)
    }
}

impl Drop for OciAccessCredential {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

pub trait OciSigningKeyResolver: fmt::Debug {
    fn resolve(
        &mut self,
        reference: &crate::model::SecretReference,
        at: DateTime<Utc>,
    ) -> Result<OciAccessCredential, OciCredentialError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvSigningKeyResolver;

impl OciSigningKeyResolver for BlockedEnvSigningKeyResolver {
    fn resolve(
        &mut self,
        _reference: &crate::model::SecretReference,
        _at: DateTime<Utc>,
    ) -> Result<OciAccessCredential, OciCredentialError> {
        Err(OciCredentialError::BlockedEnv)
    }
}

/// A gated local test seam. Even when used, the provider and probe remain
/// non-native/non-Connected until a later host authority exists.
#[derive(Clone, Debug)]
pub struct EnvironmentSigningKeyResolver {
    gate_env: String,
    key_env: String,
}

impl Default for EnvironmentSigningKeyResolver {
    fn default() -> Self {
        Self {
            gate_env: OCI_DEVOPS_NATIVE_PROBE_ENV.to_owned(),
            key_env: crate::OCI_DEVOPS_SIGNING_KEY_ENV.to_owned(),
        }
    }
}

impl EnvironmentSigningKeyResolver {
    pub fn new(gate_env: impl Into<String>, key_env: impl Into<String>) -> Self {
        Self {
            gate_env: gate_env.into(),
            key_env: key_env.into(),
        }
    }
}

impl OciSigningKeyResolver for EnvironmentSigningKeyResolver {
    fn resolve(
        &mut self,
        _reference: &crate::model::SecretReference,
        at: DateTime<Utc>,
    ) -> Result<OciAccessCredential, OciCredentialError> {
        if env::var(&self.gate_env).ok().as_deref() != Some("1") {
            return Err(OciCredentialError::BlockedEnv);
        }
        let key = env::var(&self.key_env).map_err(|_| OciCredentialError::BlockedEnv)?;
        OciAccessCredential::new(key, at - Duration::seconds(1), at + Duration::minutes(5))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OciNativeProbeStatus {
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciNativeProbe {
    pub status: OciNativeProbeStatus,
    pub native_credentials_resolved: bool,
    pub live_https_verified: bool,
    pub native_connected_claim: bool,
    pub reason: String,
}

impl OciNativeProbe {
    pub fn from_environment() -> Self {
        let gate_present = env::var(OCI_DEVOPS_NATIVE_PROBE_ENV).ok().as_deref() == Some("1");
        let reason = if gate_present {
            format!(
                "{OCI_DEVOPS_NATIVE_PROBE_GATE} is present, but Layer 1 has no native OCI signing authority"
            )
        } else {
            format!("{OCI_DEVOPS_NATIVE_PROBE_GATE} is not enabled")
        };
        Self {
            status: OciNativeProbeStatus::BlockedEnv,
            native_credentials_resolved: false,
            live_https_verified: false,
            native_connected_claim: false,
            reason,
        }
    }
}

pub fn native_probe_from_environment() -> OciNativeProbe {
    OciNativeProbe::from_environment()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialLease {
    lease_id: String,
    secret_reference: crate::model::SecretReference,
    lease_revision: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl CredentialLease {
    pub fn new(
        lease_id: impl Into<String>,
        secret_reference: crate::model::SecretReference,
        lease_revision: u64,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, OciDevopsError> {
        let lease_id = lease_id.into();
        if lease_id.trim().is_empty()
            || lease_id.chars().any(char::is_control)
            || lease_revision == 0
            || expires_at <= issued_at
            || expires_at - issued_at > Duration::seconds(MAX_CREDENTIAL_LEASE_SECONDS)
        {
            return Err(OciDevopsError::InvalidInput(
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

    pub fn secret_reference(&self) -> &crate::model::SecretReference {
        &self.secret_reference
    }

    pub const fn lease_revision(&self) -> u64 {
        self.lease_revision
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<(), OciDevopsError> {
        if at < self.issued_at || self.revoked_at.is_some() {
            return Err(OciDevopsError::CredentialExpired);
        }
        self.revoked_at = Some(at);
        Ok(())
    }

    fn validate_at(
        &self,
        reference: &crate::model::SecretReference,
        at: DateTime<Utc>,
    ) -> Result<(), OciDevopsError> {
        if self.secret_reference != *reference
            || reference.is_revoked()
            || at < self.issued_at
            || at >= self.expires_at
            || self.revoked_at.is_some_and(|revoked_at| revoked_at <= at)
        {
            return Err(OciDevopsError::CredentialExpired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OciRegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciRegistrationRequest {
    pub plugin_version: String,
    pub provider_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub evidence_digest: Digest,
    pub scope: OciDevopsScope,
    pub secret_reference: crate::model::SecretReference,
    pub credential_lease: CredentialLease,
    pub provider_revision: ProviderRevision,
}

impl OciRegistrationRequest {
    pub fn baseline(
        scope: OciDevopsScope,
        secret_reference: crate::model::SecretReference,
        at: DateTime<Utc>,
    ) -> Result<Self, OciDevopsError> {
        let credential_lease = CredentialLease::new(
            "oci-devops-result-lease-1",
            secret_reference.clone(),
            1,
            at - Duration::seconds(1),
            at + Duration::seconds(300),
        )?;
        Ok(Self {
            plugin_version: OCI_DEVOPS_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            provider_version: OCI_DEVOPS_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: OCI_DEVOPS_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            permission_digest: scope.permission_digest().clone(),
            evidence_digest: evidence_policy_digest(),
            scope,
            secret_reference,
            credential_lease,
            provider_revision: ProviderRevision::parse(OCI_DEVOPS_PROVIDER_REVISION)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciRegistration {
    plugin_version: String,
    provider_version: String,
    contract_version: String,
    contract_digest: Digest,
    permission_digest: Digest,
    evidence_digest: Digest,
    scope: OciDevopsScope,
    secret_reference: crate::model::SecretReference,
    credential_lease: CredentialLease,
    provider_revision: ProviderRevision,
    registration_digest: Digest,
    state: OciRegistrationState,
    registered_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl OciRegistration {
    pub fn new(request: OciRegistrationRequest) -> Result<Self, OciDevopsError> {
        validate_plugin_metadata(
            &request.plugin_version,
            &request.provider_version,
            &request.contract_version,
            &request.contract_digest,
            &request.provider_revision,
        )?;
        if request.permission_digest != *request.scope.permission_digest() {
            return Err(OciDevopsError::PermissionDigestMismatch);
        }
        if request.evidence_digest != evidence_policy_digest() {
            return Err(OciDevopsError::RegistrationDrift(
                "evidence policy digest differs from the Layer-1 baseline".to_owned(),
            ));
        }
        if request.secret_reference.scope_digest() != &request.scope.digest()
            || request.credential_lease.secret_reference() != &request.secret_reference
        {
            return Err(OciDevopsError::RegistrationDrift(
                "signing-key reference is not bound to the exact scope and lease".to_owned(),
            ));
        }
        let registration_digest = digest_serializable(&(
            &request.plugin_version,
            &request.provider_version,
            &request.contract_version,
            &request.contract_digest,
            &request.permission_digest,
            &request.evidence_digest,
            &request.scope.digest(),
            request.secret_reference.reference_digest(),
            request.secret_reference.credential_revision(),
            &request.provider_revision,
        ))?;
        let registered_at = request.credential_lease.issued_at;
        Ok(Self {
            plugin_version: request.plugin_version,
            provider_version: request.provider_version,
            contract_version: request.contract_version,
            contract_digest: request.contract_digest,
            permission_digest: request.permission_digest,
            evidence_digest: request.evidence_digest,
            scope: request.scope,
            secret_reference: request.secret_reference,
            credential_lease: request.credential_lease,
            provider_revision: request.provider_revision,
            registration_digest,
            state: OciRegistrationState::Active,
            registered_at,
            revoked_at: None,
        })
    }

    pub fn scope(&self) -> &OciDevopsScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.provider_revision
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn secret_reference(&self) -> &crate::model::SecretReference {
        &self.secret_reference
    }

    pub fn state(&self) -> &OciRegistrationState {
        &self.state
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<(), OciDevopsError> {
        if self.state == OciRegistrationState::Revoked || at < self.registered_at {
            return Err(OciDevopsError::RegistrationRevoked);
        }
        self.state = OciRegistrationState::Revoked;
        self.revoked_at = Some(at);
        Ok(())
    }

    fn validate_at(&self, at: DateTime<Utc>) -> Result<(), OciDevopsError> {
        if self.state == OciRegistrationState::Revoked
            || self.revoked_at.is_some_and(|revoked_at| revoked_at <= at)
        {
            return Err(OciDevopsError::RegistrationRevoked);
        }
        self.credential_lease
            .validate_at(&self.secret_reference, at)
    }
}

pub struct OciDevopsProvider<T, R>
where
    T: OciDevopsTransport,
    R: OciSigningKeyResolver,
{
    registration: OciRegistration,
    transport: T,
    resolver: R,
    bounds: crate::transport::RequestBounds,
}

impl<T, R> fmt::Debug for OciDevopsProvider<T, R>
where
    T: OciDevopsTransport,
    R: OciSigningKeyResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OciDevopsProvider")
            .field("registration", &self.registration)
            .field("transport_provenance", &self.transport.provenance())
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

impl<T, R> OciDevopsProvider<T, R>
where
    T: OciDevopsTransport,
    R: OciSigningKeyResolver,
{
    pub fn new(
        scope: OciDevopsScope,
        secret_reference: crate::model::SecretReference,
        transport: T,
        resolver: R,
        at: DateTime<Utc>,
    ) -> Result<Self, OciDevopsError> {
        let request = OciRegistrationRequest::baseline(scope, secret_reference, at)?;
        Self::from_registration(OciRegistration::new(request)?, transport, resolver)
    }

    pub fn from_registration(
        registration: OciRegistration,
        transport: T,
        resolver: R,
    ) -> Result<Self, OciDevopsError> {
        if transport.is_native() || transport.provenance().is_native() {
            return Err(OciDevopsError::RegistrationDrift(
                "Layer 1 transport cannot claim native authority".to_owned(),
            ));
        }
        Ok(Self {
            registration,
            transport,
            resolver,
            bounds: crate::transport::RequestBounds::default(),
        })
    }

    pub fn registration(&self) -> &OciRegistration {
        &self.registration
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn is_connected(&self) -> bool {
        false
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<(), OciDevopsError> {
        self.registration.revoke(at)
    }

    pub fn read(
        &mut self,
        request: &OciDevopsReadRequest,
        at: DateTime<Utc>,
    ) -> Result<OciDevopsEvidence, OciDevopsError> {
        self.registration.validate_at(at)?;
        crate::model::validate_page_bounds(request.max_results, request.max_pages)?;
        let credential = self
            .resolver
            .resolve(self.registration.secret_reference(), at)?;
        credential.validate_at(at)?;
        let mut receipts = Vec::new();
        let mut next_page_tokens = BTreeMap::new();
        let mut pages_read = 0u16;

        let deployment = self.fetch_deployment(
            &credential,
            request,
            at,
            &mut receipts,
            &mut next_page_tokens,
            &mut pages_read,
        )?;
        let build_run = self.fetch_build_run(
            &credential,
            request,
            at,
            &mut receipts,
            &mut next_page_tokens,
            &mut pages_read,
        )?;
        let work_request = self.fetch_work_request(
            &credential,
            request,
            at,
            &mut receipts,
            &mut next_page_tokens,
            &mut pages_read,
        )?;
        let mut evidence = OciDevopsEvidence {
            contract_version: OCI_DEVOPS_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            scope_digest: self.registration.scope().digest(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_revision: self.registration.provider_revision().clone(),
            provenance: self.transport.provenance(),
            native_evidence: false,
            external_write_performed: false,
            outcome_authority: false,
            pages_read: 0,
            deployment,
            build_run,
            work_request,
            next_page_tokens,
            receipts,
            evidence_digest: Digest::zero(),
        };
        evidence.pages_read = pages_read.clamp(1, OCI_DEVOPS_MAX_PAGES);
        evidence.evidence_digest = compute_evidence_digest(&evidence)?;
        evidence.validate()?;
        Ok(evidence)
    }

    fn execute(
        &mut self,
        credential: &OciAccessCredential,
        request: &OciDevopsHttpRequest,
    ) -> Result<OciDevopsHttpResponse, OciDevopsError> {
        let response =
            self.transport
                .execute(credential, request)
                .map_err(|error| match error {
                    OciTransportError::BlockedEnv => OciDevopsError::BlockedEnv,
                    OciTransportError::Status(status) => {
                        OciDevopsError::UnexpectedStatus { status }
                    }
                    OciTransportError::Timeout => OciDevopsError::Transport("timeout".to_owned()),
                    other => OciDevopsError::Transport(other.to_string()),
                })?;
        self.validate_response(&response, request)?;
        Ok(response)
    }

    fn validate_response(
        &self,
        response: &OciDevopsHttpResponse,
        request: &OciDevopsHttpRequest,
    ) -> Result<(), OciDevopsError> {
        if response.receipt().status != 200 {
            return Err(OciDevopsError::UnexpectedStatus {
                status: response.receipt().status,
            });
        }
        if response.receipt().api_version != OCI_DEVOPS_API_VERSION {
            return Err(OciDevopsError::ApiVersionDrift {
                expected: OCI_DEVOPS_API_VERSION.to_owned(),
                actual: response.receipt().api_version.clone(),
            });
        }
        if response.receipt().response_size > request.max_response_bytes {
            return Err(OciDevopsError::ResponseTooLarge {
                size: response.receipt().response_size,
            });
        }
        if response.receipt().request_digest != request.digest()? {
            return Err(OciDevopsError::RegistrationDrift(
                "response receipt is not bound to the issued request".to_owned(),
            ));
        }
        if response.receipt().provider_revision != *self.registration.provider_revision() {
            return Err(OciDevopsError::RegistrationDrift(
                "provider revision differs from registration".to_owned(),
            ));
        }
        if response.receipt().raw_provider_payload_retained
            || response.receipt().raw_logs_retained
            || response.receipt().raw_artifacts_retained
            || response.receipt().credential_material_retained
        {
            return Err(OciDevopsError::ForbiddenPayloadRetention);
        }
        Ok(())
    }

    fn fetch_deployment(
        &mut self,
        credential: &OciAccessCredential,
        request: &OciDevopsReadRequest,
        at: DateTime<Utc>,
        receipts: &mut Vec<crate::model::OciResponseReceipt>,
        next_page_tokens: &mut BTreeMap<String, OpaquePageToken>,
        pages_read: &mut u16,
    ) -> Result<OciDeploymentProjection, OciDevopsError> {
        let fetched = self.list_deployments(
            credential,
            request,
            at,
            receipts,
            next_page_tokens,
            pages_read,
        )?;
        let listed = fetched
            .into_iter()
            .filter(|payload| payload.id == self.registration.scope().deployment_id())
            .collect::<Vec<_>>();
        if listed.len() > 1 {
            return Err(OciDevopsError::DuplicateResource);
        }
        if listed.is_empty() {
            return Err(OciDevopsError::DeploymentNotFound);
        }
        let get_request = OciDevopsHttpRequest::new(
            OciDevopsEndpoint::GetDeployment {
                deployment_id: self.registration.scope().deployment_id().to_owned(),
            },
            at,
            self.bounds.max_response_bytes,
        )?;
        let response = self.execute(credential, &get_request)?;
        receipts.push(response.receipt().clone());
        let OciResponseBody::Deployment(payload) = response.body() else {
            return Err(OciDevopsError::Decode(
                "deployment endpoint returned a non-deployment body".to_owned(),
            ));
        };
        self.decode_deployment(
            payload,
            request.expected_deployment_revision,
            request,
            &get_request,
        )
    }

    fn fetch_build_run(
        &mut self,
        credential: &OciAccessCredential,
        request: &OciDevopsReadRequest,
        at: DateTime<Utc>,
        receipts: &mut Vec<crate::model::OciResponseReceipt>,
        next_page_tokens: &mut BTreeMap<String, OpaquePageToken>,
        pages_read: &mut u16,
    ) -> Result<OciBuildRunProjection, OciDevopsError> {
        let listed = self.list_build_runs(
            credential,
            request,
            at,
            receipts,
            next_page_tokens,
            pages_read,
        )?;
        let matches = listed
            .into_iter()
            .filter(|payload| payload.id == self.registration.scope().build_id())
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(OciDevopsError::DuplicateResource);
        }
        if matches.is_empty() {
            return Err(OciDevopsError::BuildRunNotFound);
        }
        let get_request = OciDevopsHttpRequest::new(
            OciDevopsEndpoint::GetBuildRun {
                build_run_id: self.registration.scope().build_id().to_owned(),
            },
            at,
            self.bounds.max_response_bytes,
        )?;
        let response = self.execute(credential, &get_request)?;
        receipts.push(response.receipt().clone());
        let OciResponseBody::BuildRun(payload) = response.body() else {
            return Err(OciDevopsError::Decode(
                "build endpoint returned a non-build body".to_owned(),
            ));
        };
        self.decode_build_run(
            payload,
            request.expected_build_revision,
            request,
            &get_request,
        )
    }

    fn fetch_work_request(
        &mut self,
        credential: &OciAccessCredential,
        request: &OciDevopsReadRequest,
        at: DateTime<Utc>,
        receipts: &mut Vec<crate::model::OciResponseReceipt>,
        next_page_tokens: &mut BTreeMap<String, OpaquePageToken>,
        pages_read: &mut u16,
    ) -> Result<OciWorkRequestProjection, OciDevopsError> {
        let listed = self.list_work_requests(
            credential,
            request,
            at,
            receipts,
            next_page_tokens,
            pages_read,
        )?;
        let matches = listed
            .into_iter()
            .filter(|payload| payload.id == self.registration.scope().work_request_id())
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(OciDevopsError::WorkRequestAmbiguous);
        }
        let Some(_) = matches.first() else {
            return Err(OciDevopsError::WorkRequestNotFound);
        };
        let get_request = OciDevopsHttpRequest::new(
            OciDevopsEndpoint::GetWorkRequest {
                work_request_id: self.registration.scope().work_request_id().to_owned(),
            },
            at,
            self.bounds.max_response_bytes,
        )?;
        let response = self.execute(credential, &get_request)?;
        receipts.push(response.receipt().clone());
        let OciResponseBody::WorkRequest(payload) = response.body() else {
            return Err(OciDevopsError::Decode(
                "work request endpoint returned a non-work-request body".to_owned(),
            ));
        };
        self.decode_work_request(
            payload,
            request.expected_work_request_revision,
            request,
            &get_request,
        )
    }

    fn list_deployments(
        &mut self,
        credential: &OciAccessCredential,
        request: &OciDevopsReadRequest,
        at: DateTime<Utc>,
        receipts: &mut Vec<crate::model::OciResponseReceipt>,
        next_page_tokens: &mut BTreeMap<String, OpaquePageToken>,
        pages_read: &mut u16,
    ) -> Result<Vec<OciDeploymentPayload>, OciDevopsError> {
        let mut values = Vec::new();
        let mut token = request
            .next_page_tokens
            .get("deployments")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .map_err(OciDevopsError::from)
            })
            .transpose()?;
        let mut seen = BTreeSet::new();
        let mut seen_tokens = BTreeSet::new();
        for page in 1..=request.max_pages {
            let http_request = OciDevopsHttpRequest::new(
                OciDevopsEndpoint::ListDeployments {
                    compartment_id: self.registration.scope().compartment_id().to_owned(),
                    project_id: self.registration.scope().oci_project_id().to_owned(),
                    pipeline_id: self.registration.scope().pipeline_id().to_owned(),
                    limit: request.max_results,
                    page_token: token.clone(),
                },
                at,
                self.bounds.max_response_bytes,
            )?;
            let response = self.execute(credential, &http_request)?;
            receipts.push(response.receipt().clone());
            let OciResponseBody::Deployments(page_values) = response.body() else {
                return Err(OciDevopsError::Decode(
                    "deployment list returned a non-list body".to_owned(),
                ));
            };
            if values.len() + page_values.len() > OCI_DEVOPS_MAX_DEPLOYMENTS {
                return Err(OciDevopsError::Pagination(
                    "deployment bound exceeded".to_owned(),
                ));
            }
            for value in page_values {
                if !seen.insert(value.id.clone()) {
                    return Err(OciDevopsError::DuplicateResource);
                }
                values.push(value.clone());
            }
            *pages_read = pages_read.saturating_add(1);
            let Some(next) = response.next_page_token() else {
                return Ok(values);
            };
            if !seen_tokens.insert(next.to_owned()) {
                return Err(OciDevopsError::Pagination(
                    "repeated deployment page token".to_owned(),
                ));
            }
            if page == request.max_pages {
                return Err(OciDevopsError::Pagination(
                    "deployment page bound exceeded".to_owned(),
                ));
            }
            let opaque = OpaquePageToken::new(next)?;
            next_page_tokens.insert("deployments".to_owned(), opaque);
            token = Some(next.to_owned());
        }
        Ok(values)
    }

    fn list_build_runs(
        &mut self,
        credential: &OciAccessCredential,
        request: &OciDevopsReadRequest,
        at: DateTime<Utc>,
        receipts: &mut Vec<crate::model::OciResponseReceipt>,
        next_page_tokens: &mut BTreeMap<String, OpaquePageToken>,
        pages_read: &mut u16,
    ) -> Result<Vec<OciBuildRunPayload>, OciDevopsError> {
        let mut values = Vec::new();
        let mut token = request
            .next_page_tokens
            .get("buildRuns")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .map_err(OciDevopsError::from)
            })
            .transpose()?;
        let mut seen = BTreeSet::new();
        let mut seen_tokens = BTreeSet::new();
        for page in 1..=request.max_pages {
            let http_request = OciDevopsHttpRequest::new(
                OciDevopsEndpoint::ListBuildRuns {
                    compartment_id: self.registration.scope().compartment_id().to_owned(),
                    project_id: self.registration.scope().oci_project_id().to_owned(),
                    pipeline_id: self.registration.scope().pipeline_id().to_owned(),
                    limit: request.max_results,
                    page_token: token.clone(),
                },
                at,
                self.bounds.max_response_bytes,
            )?;
            let response = self.execute(credential, &http_request)?;
            receipts.push(response.receipt().clone());
            let OciResponseBody::BuildRuns(page_values) = response.body() else {
                return Err(OciDevopsError::Decode(
                    "build list returned a non-list body".to_owned(),
                ));
            };
            if values.len() + page_values.len() > OCI_DEVOPS_MAX_BUILD_RUNS {
                return Err(OciDevopsError::Pagination(
                    "build bound exceeded".to_owned(),
                ));
            }
            for value in page_values {
                if !seen.insert(value.id.clone()) {
                    return Err(OciDevopsError::DuplicateResource);
                }
                values.push(value.clone());
            }
            *pages_read = pages_read.saturating_add(1);
            let Some(next) = response.next_page_token() else {
                return Ok(values);
            };
            if page == request.max_pages {
                return Err(OciDevopsError::Pagination(
                    "build page bound exceeded".to_owned(),
                ));
            }
            if !seen_tokens.insert(next.to_owned()) {
                return Err(OciDevopsError::Pagination(
                    "repeated build page token".to_owned(),
                ));
            }
            let opaque = OpaquePageToken::new(next)?;
            next_page_tokens.insert("buildRuns".to_owned(), opaque);
            token = Some(next.to_owned());
        }
        Ok(values)
    }

    fn list_work_requests(
        &mut self,
        credential: &OciAccessCredential,
        request: &OciDevopsReadRequest,
        at: DateTime<Utc>,
        receipts: &mut Vec<crate::model::OciResponseReceipt>,
        next_page_tokens: &mut BTreeMap<String, OpaquePageToken>,
        pages_read: &mut u16,
    ) -> Result<Vec<OciWorkRequestPayload>, OciDevopsError> {
        let mut values = Vec::new();
        let mut token = request
            .next_page_tokens
            .get("workRequests")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .map_err(OciDevopsError::from)
            })
            .transpose()?;
        let mut seen = BTreeSet::new();
        let mut seen_tokens = BTreeSet::new();
        for page in 1..=request.max_pages {
            let http_request = OciDevopsHttpRequest::new(
                OciDevopsEndpoint::ListWorkRequests {
                    compartment_id: self.registration.scope().compartment_id().to_owned(),
                    project_id: self.registration.scope().oci_project_id().to_owned(),
                    limit: request.max_results,
                    page_token: token.clone(),
                },
                at,
                self.bounds.max_response_bytes,
            )?;
            let response = self.execute(credential, &http_request)?;
            receipts.push(response.receipt().clone());
            let OciResponseBody::WorkRequests(page_values) = response.body() else {
                return Err(OciDevopsError::Decode(
                    "work request list returned a non-list body".to_owned(),
                ));
            };
            if values.len() + page_values.len() > OCI_DEVOPS_MAX_WORK_REQUESTS {
                return Err(OciDevopsError::Pagination(
                    "work request bound exceeded".to_owned(),
                ));
            }
            for value in page_values {
                if !seen.insert(value.id.clone())
                    && value.id != self.registration.scope().work_request_id()
                {
                    return Err(OciDevopsError::DuplicateResource);
                }
                values.push(value.clone());
            }
            *pages_read = pages_read.saturating_add(1);
            let Some(next) = response.next_page_token() else {
                return Ok(values);
            };
            if page == request.max_pages {
                return Err(OciDevopsError::Pagination(
                    "work request page bound exceeded".to_owned(),
                ));
            }
            if !seen_tokens.insert(next.to_owned()) {
                return Err(OciDevopsError::Pagination(
                    "repeated work request page token".to_owned(),
                ));
            }
            let opaque = OpaquePageToken::new(next)?;
            next_page_tokens.insert("workRequests".to_owned(), opaque);
            token = Some(next.to_owned());
        }
        Ok(values)
    }

    fn decode_deployment(
        &self,
        payload: &OciDeploymentPayload,
        expected_revision: Option<u64>,
        read_request: &OciDevopsReadRequest,
        _request: &OciDevopsHttpRequest,
    ) -> Result<OciDeploymentProjection, OciDevopsError> {
        let scope = self.registration.scope();
        if payload.id != scope.deployment_id() {
            return Err(OciDevopsError::ResourceIdMismatch);
        }
        if payload.compartment_id != scope.compartment_id()
            || payload.project_id != scope.oci_project_id()
        {
            return Err(OciDevopsError::CompartmentProjectMismatch);
        }
        if payload.pipeline_id != scope.pipeline_id() {
            return Err(OciDevopsError::PipelineMismatch);
        }
        if payload.build_run_id.as_deref() != Some(scope.build_id()) {
            return Err(OciDevopsError::ResourceIdMismatch);
        }
        if let Some(expected) = expected_revision
            && payload.revision != expected
        {
            return Err(OciDevopsError::RevisionMismatch {
                resource: "deployment".to_owned(),
                expected,
                observed: payload.revision,
            });
        }
        Self::reconcile_revision(
            &Ocid::parse(payload.id.clone())?,
            payload.revision,
            &read_request.reconcile_resource_revisions,
        )?;
        let stages = Self::decode_stages(&payload.stages)?;
        Self::validate_stage_fences(&stages, &read_request.stage_fences)?;
        validate_artifact_bounds(payload.artifact_count)?;
        Ok(OciDeploymentProjection {
            id: DeploymentId::parse(payload.id.clone())?,
            compartment_id: CompartmentId::parse(payload.compartment_id.clone())?,
            project_id: Ocid::parse(payload.project_id.clone())?,
            pipeline_id: Ocid::parse(payload.pipeline_id.clone())?,
            build_run_id: payload
                .build_run_id
                .clone()
                .map(BuildRunId::parse)
                .transpose()?,
            lifecycle_state: StateValue::parse(payload.lifecycle_state.clone())?,
            revision: payload.revision,
            time_created: payload.time_created,
            time_started: payload.time_started,
            time_finished: payload.time_finished,
            stages,
            artifact_count: payload.artifact_count,
            artifact_metadata_fingerprint: payload.artifact_metadata_fingerprint.clone(),
            log_metadata_fingerprint: payload.log_metadata_fingerprint.clone(),
        })
    }

    fn decode_build_run(
        &self,
        payload: &OciBuildRunPayload,
        expected_revision: Option<u64>,
        read_request: &OciDevopsReadRequest,
        _request: &OciDevopsHttpRequest,
    ) -> Result<OciBuildRunProjection, OciDevopsError> {
        let scope = self.registration.scope();
        if payload.id != scope.build_id() {
            return Err(OciDevopsError::ResourceIdMismatch);
        }
        if payload.compartment_id != scope.compartment_id()
            || payload.project_id != scope.oci_project_id()
        {
            return Err(OciDevopsError::CompartmentProjectMismatch);
        }
        if payload.pipeline_id != scope.pipeline_id() {
            return Err(OciDevopsError::PipelineMismatch);
        }
        if let Some(expected) = expected_revision
            && payload.revision != expected
        {
            return Err(OciDevopsError::RevisionMismatch {
                resource: "build".to_owned(),
                expected,
                observed: payload.revision,
            });
        }
        Self::reconcile_revision(
            &Ocid::parse(payload.id.clone())?,
            payload.revision,
            &read_request.reconcile_resource_revisions,
        )?;
        let stages = Self::decode_stages(&payload.stages)?;
        Self::validate_stage_fences(&stages, &read_request.stage_fences)?;
        validate_artifact_bounds(payload.artifact_count)?;
        Ok(OciBuildRunProjection {
            id: BuildRunId::parse(payload.id.clone())?,
            compartment_id: CompartmentId::parse(payload.compartment_id.clone())?,
            project_id: Ocid::parse(payload.project_id.clone())?,
            pipeline_id: Ocid::parse(payload.pipeline_id.clone())?,
            lifecycle_state: StateValue::parse(payload.lifecycle_state.clone())?,
            revision: payload.revision,
            time_created: payload.time_created,
            time_started: payload.time_started,
            time_finished: payload.time_finished,
            stages,
            artifact_count: payload.artifact_count,
            artifact_metadata_fingerprint: payload.artifact_metadata_fingerprint.clone(),
            log_metadata_fingerprint: payload.log_metadata_fingerprint.clone(),
        })
    }

    fn decode_work_request(
        &self,
        payload: &OciWorkRequestPayload,
        expected_revision: Option<u64>,
        read_request: &OciDevopsReadRequest,
        _request: &OciDevopsHttpRequest,
    ) -> Result<OciWorkRequestProjection, OciDevopsError> {
        let scope = self.registration.scope();
        if payload.id != scope.work_request_id() {
            return Err(OciDevopsError::ResourceIdMismatch);
        }
        if payload.compartment_id != scope.compartment_id()
            || payload.project_id != scope.oci_project_id()
        {
            return Err(OciDevopsError::CompartmentProjectMismatch);
        }
        if let Some(resource_id) = payload.resource_id.as_deref()
            && resource_id != scope.deployment_id()
            && resource_id != scope.build_id()
            && resource_id != scope.pipeline_id()
        {
            return Err(OciDevopsError::ResourceIdMismatch);
        }
        if let Some(expected) = expected_revision
            && payload.revision != expected
        {
            return Err(OciDevopsError::RevisionMismatch {
                resource: "work request".to_owned(),
                expected,
                observed: payload.revision,
            });
        }
        Self::reconcile_revision(
            &Ocid::parse(payload.id.clone())?,
            payload.revision,
            &read_request.reconcile_resource_revisions,
        )?;
        Ok(OciWorkRequestProjection {
            id: WorkRequestId::parse(payload.id.clone())?,
            compartment_id: CompartmentId::parse(payload.compartment_id.clone())?,
            project_id: Ocid::parse(payload.project_id.clone())?,
            resource_id: payload
                .resource_id
                .clone()
                .map(ResourceId::parse)
                .transpose()?,
            operation_type: payload.operation_type.clone(),
            status: StateValue::parse(payload.status.clone())?,
            percent_complete: payload.percent_complete,
            revision: payload.revision,
            time_accepted: payload.time_accepted,
            time_started: payload.time_started,
            time_finished: payload.time_finished,
        })
    }

    fn decode_stages(
        stages: &[OciStagePayload],
    ) -> Result<Vec<OciStageProjection>, OciDevopsError> {
        validate_stage_bounds(stages.len())?;
        let mut seen = BTreeSet::new();
        stages
            .iter()
            .map(|stage| {
                if !seen.insert(stage.id.clone()) {
                    return Err(OciDevopsError::DuplicateResource);
                }
                Ok(OciStageProjection {
                    id: Ocid::parse(stage.id.clone())?,
                    state: StateValue::parse(stage.state.clone())?,
                    revision: stage.revision,
                })
            })
            .collect()
    }

    fn validate_stage_fences(
        stages: &[OciStageProjection],
        fences: &[OciStageFence],
    ) -> Result<(), OciDevopsError> {
        if stages.len() > OCI_DEVOPS_MAX_STAGES {
            return Err(OciDevopsError::StageStateMismatch);
        }
        for fence in fences {
            let Some(stage) = stages.iter().find(|stage| stage.id == fence.stage_id) else {
                return Err(OciDevopsError::StageStateMismatch);
            };
            if stage.state != fence.expected_state || stage.revision != fence.expected_revision {
                return Err(OciDevopsError::StageStateMismatch);
            }
        }
        Ok(())
    }

    fn reconcile_revision(
        id: &Ocid,
        revision: u64,
        fences: &BTreeMap<Ocid, u64>,
    ) -> Result<(), OciDevopsError> {
        if fences.get(id).is_some_and(|expected| *expected != revision) {
            return Err(OciDevopsError::RevisionMismatch {
                resource: id.to_string(),
                expected: *fences.get(id).expect("checked fence presence"),
                observed: revision,
            });
        }
        Ok(())
    }
}
