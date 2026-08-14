use std::{collections::VecDeque, env, fmt};

use zeroize::Zeroizing;

use crate::{
    EvidenceProvenance, PulumiAuditPage, PulumiCloudEndpoint, PulumiCloudTransportError,
    PulumiDeploymentApiRecord, PulumiDeploymentResultError, PulumiDeploymentScope,
    PulumiPolicyEvidence, PulumiStackApiRecord, PulumiUpdatePage, SecretReference,
    valid_identifier,
};

pub const PULUMI_ACCESS_TOKEN_ENVIRONMENT_VARIABLE: &str = "HARTEVO_PULUMI_ACCESS_TOKEN";
pub const PULUMI_OIDC_TOKEN_ENVIRONMENT_VARIABLE: &str = "HARTEVO_PULUMI_OIDC_TOKEN";
pub const PULUMI_NATIVE_GATE_ENVIRONMENT_VARIABLE: &str = "HARTEVO_PULUMI_NATIVE";

/// Credential bytes are held only at the resolver/transport boundary and are
/// never serializable, debuggable, or included in a request record.
pub struct SecretMaterial(Zeroizing<String>);

impl SecretMaterial {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Clone for SecretMaterial {
    fn clone(&self) -> Self {
        Self::new(self.as_str())
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMaterial(<redacted>)")
    }
}

/// Host-owned credential resolution. The provider receives only an opaque
/// `SecretReference`; the resolver is the sole boundary where secret material
/// may be obtained.
pub trait PulumiCredentialResolver: fmt::Debug + Send + Sync {
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<SecretMaterial, PulumiDeploymentResultError>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl PulumiCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<SecretMaterial, PulumiDeploymentResultError> {
        Err(PulumiCloudTransportError::BlockedEnv.into())
    }
}

#[derive(Clone, Debug, Default)]
pub struct EnvironmentPulumiCredentialResolver;

impl PulumiCredentialResolver for EnvironmentPulumiCredentialResolver {
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<SecretMaterial, PulumiDeploymentResultError> {
        if env::var(PULUMI_NATIVE_GATE_ENVIRONMENT_VARIABLE)
            .ok()
            .as_deref()
            != Some("1")
        {
            return Err(PulumiCloudTransportError::BlockedEnv.into());
        }
        let variable = match reference.kind() {
            crate::AuthKind::AccessToken => PULUMI_ACCESS_TOKEN_ENVIRONMENT_VARIABLE,
            crate::AuthKind::Oidc => PULUMI_OIDC_TOKEN_ENVIRONMENT_VARIABLE,
        };
        let value = env::var(variable).map_err(|_| {
            PulumiDeploymentResultError::Transport(PulumiCloudTransportError::BlockedEnv)
        })?;
        if value.trim().is_empty() || !valid_identifier(&value, 16 * 1024) {
            return Err(PulumiCloudTransportError::BlockedEnv.into());
        }
        Ok(SecretMaterial::new(value))
    }
}

#[derive(Clone)]
pub struct StaticPulumiCredentialResolver {
    material: SecretMaterial,
}

impl fmt::Debug for StaticPulumiCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticPulumiCredentialResolver(<redacted>)")
    }
}

impl StaticPulumiCredentialResolver {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            material: SecretMaterial::new(value),
        }
    }
}

impl PulumiCredentialResolver for StaticPulumiCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<SecretMaterial, PulumiDeploymentResultError> {
        if self.material.as_str().trim().is_empty() {
            Err(PulumiCloudTransportError::BlockedEnv.into())
        } else {
            Ok(self.material.clone())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PulumiCloudTransportOperation {
    DescribeStack,
    ReadDeployment,
    ReadUpdates,
    ReadPolicy,
    ReadAudit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedRequest {
    pub operation: PulumiCloudTransportOperation,
    pub cursor: Option<String>,
}

/// The only provider API surface exposed by Layer 1. Every method is a read;
/// there is intentionally no create, cancel, resume, mutation, log, state, or
/// secret-export method.
pub trait PulumiCloudTransport: fmt::Debug + Send + Sync {
    fn provenance(&self) -> EvidenceProvenance;

    fn describe_stack(
        &mut self,
        credential: &SecretMaterial,
        scope: &PulumiDeploymentScope,
    ) -> Result<PulumiStackApiRecord, PulumiCloudTransportError>;

    fn read_deployment(
        &mut self,
        credential: &SecretMaterial,
        scope: &PulumiDeploymentScope,
    ) -> Result<PulumiDeploymentApiRecord, PulumiCloudTransportError>;

    fn read_updates(
        &mut self,
        credential: &SecretMaterial,
        scope: &PulumiDeploymentScope,
        cursor: Option<&str>,
    ) -> Result<PulumiUpdatePage, PulumiCloudTransportError>;

    fn read_policy(
        &mut self,
        credential: &SecretMaterial,
        scope: &PulumiDeploymentScope,
    ) -> Result<PulumiPolicyEvidence, PulumiCloudTransportError>;

    fn read_audit(
        &mut self,
        credential: &SecretMaterial,
        scope: &PulumiDeploymentScope,
        cursor: Option<&str>,
    ) -> Result<PulumiAuditPage, PulumiCloudTransportError>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl PulumiCloudTransport for BlockedEnvTransport {
    fn provenance(&self) -> EvidenceProvenance {
        EvidenceProvenance::BlockedEnv
    }

    fn describe_stack(
        &mut self,
        _credential: &SecretMaterial,
        _scope: &PulumiDeploymentScope,
    ) -> Result<PulumiStackApiRecord, PulumiCloudTransportError> {
        Err(PulumiCloudTransportError::BlockedEnv)
    }

    fn read_deployment(
        &mut self,
        _credential: &SecretMaterial,
        _scope: &PulumiDeploymentScope,
    ) -> Result<PulumiDeploymentApiRecord, PulumiCloudTransportError> {
        Err(PulumiCloudTransportError::BlockedEnv)
    }

    fn read_updates(
        &mut self,
        _credential: &SecretMaterial,
        _scope: &PulumiDeploymentScope,
        _cursor: Option<&str>,
    ) -> Result<PulumiUpdatePage, PulumiCloudTransportError> {
        Err(PulumiCloudTransportError::BlockedEnv)
    }

    fn read_policy(
        &mut self,
        _credential: &SecretMaterial,
        _scope: &PulumiDeploymentScope,
    ) -> Result<PulumiPolicyEvidence, PulumiCloudTransportError> {
        Err(PulumiCloudTransportError::BlockedEnv)
    }

    fn read_audit(
        &mut self,
        _credential: &SecretMaterial,
        _scope: &PulumiDeploymentScope,
        _cursor: Option<&str>,
    ) -> Result<PulumiAuditPage, PulumiCloudTransportError> {
        Err(PulumiCloudTransportError::BlockedEnv)
    }
}

/// Deterministic recording, fixture, and loopback transport. It stores only
/// typed bounded records and faults, never a token or raw provider payload.
pub struct RecordingPulumiCloudTransport {
    provenance: EvidenceProvenance,
    description: Option<Result<PulumiStackApiRecord, PulumiCloudTransportError>>,
    deployment: Option<Result<PulumiDeploymentApiRecord, PulumiCloudTransportError>>,
    policy: Option<Result<PulumiPolicyEvidence, PulumiCloudTransportError>>,
    updates: VecDeque<Result<PulumiUpdatePage, PulumiCloudTransportError>>,
    audits: VecDeque<Result<PulumiAuditPage, PulumiCloudTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl fmt::Debug for RecordingPulumiCloudTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingPulumiCloudTransport")
            .field("provenance", &self.provenance)
            .field("description_configured", &self.description.is_some())
            .field("deployment_configured", &self.deployment.is_some())
            .field("policy_configured", &self.policy.is_some())
            .field("queued_update_pages", &self.updates.len())
            .field("queued_audit_pages", &self.audits.len())
            .field("request_count", &self.requests.len())
            .finish()
    }
}

impl RecordingPulumiCloudTransport {
    pub fn new(provenance: EvidenceProvenance) -> Self {
        Self {
            provenance,
            description: None,
            deployment: None,
            policy: None,
            updates: VecDeque::new(),
            audits: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn recording() -> Self {
        Self::new(EvidenceProvenance::Recording)
    }

    pub fn fixture() -> Self {
        Self::new(EvidenceProvenance::Fixture)
    }

    pub fn fake() -> Self {
        Self::fixture()
    }

    pub fn loopback() -> Self {
        Self::new(EvidenceProvenance::Loopback)
    }

    pub fn blocked_env() -> Self {
        Self::new(EvidenceProvenance::BlockedEnv)
    }

    pub fn set_description(
        &mut self,
        result: Result<PulumiStackApiRecord, PulumiCloudTransportError>,
    ) {
        self.description = Some(result);
    }

    pub fn set_deployment(
        &mut self,
        result: Result<PulumiDeploymentApiRecord, PulumiCloudTransportError>,
    ) {
        self.deployment = Some(result);
    }

    pub fn set_policy(&mut self, result: Result<PulumiPolicyEvidence, PulumiCloudTransportError>) {
        self.policy = Some(result);
    }

    pub fn push_update_page(
        &mut self,
        result: Result<PulumiUpdatePage, PulumiCloudTransportError>,
    ) {
        self.updates.push_back(result);
    }

    pub fn push_audit_page(&mut self, result: Result<PulumiAuditPage, PulumiCloudTransportError>) {
        self.audits.push_back(result);
    }

    pub fn set_update_pages(
        &mut self,
        pages: impl IntoIterator<Item = Result<PulumiUpdatePage, PulumiCloudTransportError>>,
    ) {
        self.updates = pages.into_iter().collect();
    }

    pub fn set_audit_pages(
        &mut self,
        pages: impl IntoIterator<Item = Result<PulumiAuditPage, PulumiCloudTransportError>>,
    ) {
        self.audits = pages.into_iter().collect();
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    fn record(&mut self, operation: PulumiCloudTransportOperation, cursor: Option<&str>) {
        self.requests.push(RecordedRequest {
            operation,
            cursor: cursor.map(str::to_owned),
        });
    }

    fn configured<T>(
        result: Option<&Result<T, PulumiCloudTransportError>>,
    ) -> Result<T, PulumiCloudTransportError>
    where
        T: Clone,
    {
        result
            .cloned()
            .unwrap_or(Err(PulumiCloudTransportError::FixtureMissing))
    }

    fn next_page<T>(
        pages: &mut VecDeque<Result<T, PulumiCloudTransportError>>,
    ) -> Result<T, PulumiCloudTransportError> {
        pages
            .pop_front()
            .unwrap_or(Err(PulumiCloudTransportError::FixtureMissing))
    }
}

impl PulumiCloudTransport for RecordingPulumiCloudTransport {
    fn provenance(&self) -> EvidenceProvenance {
        self.provenance
    }

    fn describe_stack(
        &mut self,
        _credential: &SecretMaterial,
        _scope: &PulumiDeploymentScope,
    ) -> Result<PulumiStackApiRecord, PulumiCloudTransportError> {
        self.record(PulumiCloudTransportOperation::DescribeStack, None);
        Self::configured(self.description.as_ref())
    }

    fn read_deployment(
        &mut self,
        _credential: &SecretMaterial,
        _scope: &PulumiDeploymentScope,
    ) -> Result<PulumiDeploymentApiRecord, PulumiCloudTransportError> {
        self.record(PulumiCloudTransportOperation::ReadDeployment, None);
        Self::configured(self.deployment.as_ref())
    }

    fn read_updates(
        &mut self,
        _credential: &SecretMaterial,
        _scope: &PulumiDeploymentScope,
        cursor: Option<&str>,
    ) -> Result<PulumiUpdatePage, PulumiCloudTransportError> {
        self.record(PulumiCloudTransportOperation::ReadUpdates, cursor);
        Self::next_page(&mut self.updates)
    }

    fn read_policy(
        &mut self,
        _credential: &SecretMaterial,
        _scope: &PulumiDeploymentScope,
    ) -> Result<PulumiPolicyEvidence, PulumiCloudTransportError> {
        self.record(PulumiCloudTransportOperation::ReadPolicy, None);
        Self::configured(self.policy.as_ref())
    }

    fn read_audit(
        &mut self,
        _credential: &SecretMaterial,
        _scope: &PulumiDeploymentScope,
        cursor: Option<&str>,
    ) -> Result<PulumiAuditPage, PulumiCloudTransportError> {
        self.record(PulumiCloudTransportOperation::ReadAudit, cursor);
        Self::next_page(&mut self.audits)
    }
}

pub type PulumiCloudRecordingTransport = RecordingPulumiCloudTransport;
pub type PulumiCloudFakeTransport = RecordingPulumiCloudTransport;
pub type PulumiCloudLoopbackTransport = RecordingPulumiCloudTransport;

/// A small endpoint value used by callers constructing an eventual native
/// transport. Layer 1 only carries the endpoint as a validated scope value;
/// it does not ship a live HTTP implementation or claim native connectivity.
pub fn default_pulumi_cloud_endpoint() -> Result<PulumiCloudEndpoint, PulumiDeploymentResultError> {
    PulumiCloudEndpoint::new(crate::PULUMI_CLOUD_API_BASE_URL)
}
