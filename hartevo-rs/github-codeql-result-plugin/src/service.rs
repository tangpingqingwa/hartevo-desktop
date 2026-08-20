//! Typed service definition, reversible registration, bounded reads, and
//! below-kernel proposal/record/verify seams.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CONSUMER_ID, CONTRACT_SCHEMA, CONTRACT_VERSION, PLUGIN_VERSION, SERVICE_ID,
    model::{
        CodeScanningTool, CommitSha, Digest, GithubCodeqlScope, ModelError, RegistrationId,
        RegistrationState, Revision, SecretReference, Version,
    },
    provider::{
        AlertRecord, AnalysisSummary, CodeqlReadRequest, GetAlertRequest,
        GithubCodeScanningProvider, GithubCodeScanningProviderDefinition,
        GithubCodeScanningTransport, ListAlertsRequest, ProviderDefinitionError, ProviderError,
        ProviderProvenance, TransportError,
    },
};

pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error("model validation failed: {0}")]
    Model(#[from] ModelError),
    #[error("provider definition validation failed: {0}")]
    ProviderDefinition(#[from] ProviderDefinitionError),
    #[error("provider evidence validation failed: {0}")]
    ProviderEvidence(ProviderError),
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is not active")]
    RegistrationInactive,
    #[error("opaque SecretReference is revoked")]
    SecretRevoked,
    #[error("provider permission digest does not match the exact scope")]
    PermissionMismatch,
    #[error("repository identity drifted")]
    RepositoryDrift,
    #[error("ref drifted")]
    RefDrift,
    #[error("commit drifted")]
    CommitDrift,
    #[error("analysis identity or tool drifted")]
    AnalysisDrift,
    #[error("alert identity or rule drifted")]
    AlertDrift,
    #[error("alert state is stale")]
    StaleAlertState,
    #[error("provider tool or rule is outside the exact allowlist")]
    RuleNotAllowlisted,
    #[error("provider pagination did not follow the exact bounded sequence")]
    PaginationMismatch,
    #[error("provider pagination token repeated")]
    PageLoop,
    #[error("provider returned a duplicate alert or analysis")]
    DuplicateEvidence,
    #[error("provider response exceeded the byte bound")]
    ResponseTooLarge,
    #[error("provider response was marked truncated")]
    TruncatedEvidence,
    #[error("proposal integrity did not verify")]
    ProposalTampered,
    #[error("recording integrity did not verify")]
    RecordingTampered,
    #[error("recording or proposal registration fence is stale")]
    RegistrationDrift,
    #[error("idempotency key is empty or too long")]
    InvalidIdempotencyKey,
    #[error("consumer registration or scope fence is stale")]
    ConsumerFenceMismatch,
}

pub type Result<T> = std::result::Result<T, ServiceError>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionState {
    AlertEvidence,
    NoAlertEvidence,
    AnalysisNotFound,
    AnalysisIncomplete,
    Partial,
    AccessLoss,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    AlertEvidence,
    NoAlertEvidence,
    AnalysisNotFound,
    AnalysisIncomplete,
    Partial,
    AccessLoss,
    ProviderUnknown,
}

impl From<ProjectionState> for ProposalDisposition {
    fn from(value: ProjectionState) -> Self {
        match value {
            ProjectionState::AlertEvidence => Self::AlertEvidence,
            ProjectionState::NoAlertEvidence => Self::NoAlertEvidence,
            ProjectionState::AnalysisNotFound => Self::AnalysisNotFound,
            ProjectionState::AnalysisIncomplete => Self::AnalysisIncomplete,
            ProjectionState::Partial => Self::Partial,
            ProjectionState::AccessLoss => Self::AccessLoss,
            ProjectionState::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadLimits {
    pub max_alert_pages: u32,
    pub max_analysis_pages: u32,
    pub page_size: u32,
    pub max_alerts: usize,
    pub max_locations: usize,
    pub max_response_bytes: u32,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_alert_pages: crate::model::MAX_ALERT_PAGES,
            max_analysis_pages: crate::model::MAX_ANALYSIS_PAGES,
            page_size: crate::model::MAX_PAGE_SIZE,
            max_alerts: crate::model::MAX_ALERTS,
            max_locations: crate::model::MAX_LOCATIONS,
            max_response_bytes: crate::model::MAX_RESPONSE_BYTES,
        }
    }
}

impl ReadLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_alert_pages == 0
            || self.max_alert_pages > crate::model::MAX_ALERT_PAGES
            || self.max_analysis_pages == 0
            || self.max_analysis_pages > crate::model::MAX_ANALYSIS_PAGES
            || self.page_size == 0
            || self.page_size > crate::model::MAX_PAGE_SIZE
            || self.max_alerts == 0
            || self.max_alerts > crate::model::MAX_ALERTS
            || self.max_locations == 0
            || self.max_locations > crate::model::MAX_LOCATIONS
            || self.max_response_bytes == 0
            || self.max_response_bytes > crate::model::MAX_RESPONSE_BYTES
        {
            Err(ServiceError::ResponseTooLarge)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubCodeqlCapabilityDescription {
    pub service_id: String,
    pub operations: Vec<String>,
    pub endpoints: Vec<String>,
    pub read_only: bool,
    pub proposals_below_kernel: bool,
    pub local_recording_only: bool,
    pub can_dismiss_alert: bool,
    pub can_fix_alert: bool,
    pub can_upload_sarif: bool,
    pub can_trigger_analysis: bool,
    pub can_mutate_branch: bool,
    pub can_mutate_pull_request: bool,
    pub can_resolve_secret: bool,
    pub can_adopt_outcome: bool,
    pub capability_digest: Digest,
}

impl GithubCodeqlCapabilityDescription {
    pub fn layer1() -> Self {
        let mut value = Self {
            service_id: SERVICE_ID.to_owned(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "read_code_scanning_alerts".to_owned(),
                "read_code_scanning_analyses".to_owned(),
                "compile_codeql_result_proposal".to_owned(),
                "record_codeql_result".to_owned(),
                "verify_codeql_recording".to_owned(),
            ],
            endpoints: vec![
                crate::ALERTS_ENDPOINT.to_owned(),
                crate::ALERT_ENDPOINT.to_owned(),
                crate::ANALYSES_ENDPOINT.to_owned(),
            ],
            read_only: true,
            proposals_below_kernel: true,
            local_recording_only: true,
            can_dismiss_alert: false,
            can_fix_alert: false,
            can_upload_sarif: false,
            can_trigger_analysis: false,
            can_mutate_branch: false,
            can_mutate_pull_request: false,
            can_resolve_secret: false,
            can_adopt_outcome: false,
            capability_digest: Digest::from_text("unsealed-github-codeql-capability"),
        };
        value.capability_digest = value.computed_digest();
        value
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.service_id,
            &self.operations,
            &self.endpoints,
            self.read_only,
            self.proposals_below_kernel,
            self.local_recording_only,
            self.can_dismiss_alert,
            self.can_fix_alert,
            self.can_upload_sarif,
            self.can_trigger_analysis,
            self.can_mutate_branch,
            self.can_mutate_pull_request,
            self.can_resolve_secret,
            self.can_adopt_outcome,
        ))
    }

    pub fn validate(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.capability_digest != self.computed_digest()
            || !self.read_only
            || !self.proposals_below_kernel
            || !self.local_recording_only
            || self.can_dismiss_alert
            || self.can_fix_alert
            || self.can_upload_sarif
            || self.can_trigger_analysis
            || self.can_mutate_branch
            || self.can_mutate_pull_request
            || self.can_resolve_secret
            || self.can_adopt_outcome
        {
            Err(ServiceError::InvalidRegistration)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubCodeqlResultServiceDefinition {
    pub plugin_id: String,
    pub plugin_version: Version,
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub capability: GithubCodeqlCapabilityDescription,
    pub contract_digest: Digest,
}

pub type GithubCodeqlServiceDefinition = GithubCodeqlResultServiceDefinition;

impl GithubCodeqlResultServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            plugin_id: crate::PLUGIN_ID.to_owned(),
            plugin_version: Version::new(0, 1, 0),
            schema_version: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            capability: GithubCodeqlCapabilityDescription::layer1(),
            contract_digest: crate::contract_digest(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.capability.validate()?;
        let expected_capability = Self::layer1().capability;
        if self.plugin_id != crate::PLUGIN_ID
            || self.plugin_version.to_string() != PLUGIN_VERSION
            || self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.service_id != SERVICE_ID
            || self.capability != expected_capability
            || self.contract_digest != crate::contract_digest()
        {
            Err(ServiceError::InvalidRegistration)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubCodeqlRegistration {
    pub registration_id: RegistrationId,
    pub plugin_version: Version,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: Version,
    pub provider_digest: Digest,
    pub api_revision: String,
    pub api_digest: Digest,
    pub installation_digest: Digest,
    pub repository_digest: Digest,
    pub ref_digest: Digest,
    pub commit_digest: Digest,
    pub analysis_digest: Digest,
    pub tool_digest: Digest,
    pub rule_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub alert_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl GithubCodeqlRegistration {
    pub fn new(
        scope: &GithubCodeqlScope,
        secret: &SecretReference,
        provider: &GithubCodeScanningProviderDefinition,
        registration_revision: Revision,
    ) -> Result<Self> {
        let mut registration = Self {
            registration_id: RegistrationId::new("github-codeql-result")?,
            plugin_version: Version::new(0, 1, 0),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version,
            provider_digest: provider.provider_digest.clone(),
            api_revision: provider.api_revision.as_str().to_owned(),
            api_digest: provider.api_digest.clone(),
            installation_digest: scope.installation_digest(),
            repository_digest: scope.repository_digest(),
            ref_digest: scope.ref_digest(),
            commit_digest: scope.commit_digest(),
            analysis_digest: scope.analysis_digest(),
            tool_digest: scope.tool_digest(),
            rule_digest: scope.rule_digest(),
            permission_digest: scope.permissions.digest().clone(),
            scope_digest: scope.digest().clone(),
            alert_digest: scope.alert_digest(),
            evidence_policy_digest: scope.evidence_policy_digest.clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            registration_revision,
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("unsealed-github-codeql-registration"),
        };
        registration.registration_digest = registration.computed_digest();
        registration.validate(scope, secret, provider)?;
        Ok(registration)
    }

    pub fn validate(
        &self,
        scope: &GithubCodeqlScope,
        secret: &SecretReference,
        provider: &GithubCodeScanningProviderDefinition,
    ) -> Result<()> {
        scope.validate()?;
        provider.validate()?;
        secret.validate_for_scope(scope)?;
        if self.registration_id.as_str() != "github-codeql-result"
            || self.plugin_version.to_string() != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.provider_version
            || self.provider_digest != provider.provider_digest
            || self.api_revision != provider.api_revision.as_str()
            || self.api_digest != provider.api_digest
            || self.installation_digest != scope.installation_digest()
            || self.repository_digest != scope.repository_digest()
            || self.ref_digest != scope.ref_digest()
            || self.commit_digest != scope.commit_digest()
            || self.analysis_digest != scope.analysis_digest()
            || self.tool_digest != scope.tool_digest()
            || self.rule_digest != scope.rule_digest()
            || self.permission_digest != *scope.permissions.digest()
            || self.scope_digest != *scope.digest()
            || self.alert_digest != scope.alert_digest()
            || self.evidence_policy_digest != scope.evidence_policy_digest
            || self.secret_reference_digest != *secret.reference_digest()
            || self.registration_revision.get() == 0
            || self.registration_digest != self.computed_digest()
        {
            Err(ServiceError::InvalidRegistration)
        } else {
            Ok(())
        }
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_fields(
            "github-codeql-registration/v1",
            &[
                self.registration_id.as_str().to_owned(),
                self.plugin_version.to_string(),
                self.contract_version.clone(),
                self.contract_digest.as_str().to_owned(),
                self.provider_id.clone(),
                self.provider_version.to_string(),
                self.provider_digest.as_str().to_owned(),
                self.api_revision.clone(),
                self.api_digest.as_str().to_owned(),
                self.installation_digest.as_str().to_owned(),
                self.repository_digest.as_str().to_owned(),
                self.ref_digest.as_str().to_owned(),
                self.commit_digest.as_str().to_owned(),
                self.analysis_digest.as_str().to_owned(),
                self.tool_digest.as_str().to_owned(),
                self.rule_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.alert_digest.as_str().to_owned(),
                self.evidence_policy_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                self.registration_revision.get().to_string(),
                format!("{:?}", self.state),
            ],
        )
    }

    pub fn unmount(&mut self) -> Result<()> {
        if self.state == RegistrationState::Revoked {
            Err(ServiceError::RegistrationInactive)
        } else {
            self.state = RegistrationState::Unmounted;
            self.registration_digest = self.computed_digest();
            Ok(())
        }
    }

    pub fn remount(&mut self) -> Result<()> {
        if self.state == RegistrationState::Revoked {
            Err(ServiceError::RegistrationInactive)
        } else {
            self.state = RegistrationState::Active;
            self.registration_digest = self.computed_digest();
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.state == RegistrationState::Revoked {
            Err(ServiceError::RegistrationInactive)
        } else {
            self.state = RegistrationState::Revoked;
            self.registration_digest = self.computed_digest();
            Ok(())
        }
    }

    pub const fn is_active(&self) -> bool {
        self.state.is_active()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeqlResultEvidence {
    pub scope_digest: Digest,
    pub installation_digest: Digest,
    pub repository_digest: Digest,
    pub ref_digest: Digest,
    pub commit_sha: CommitSha,
    pub analysis: Option<AnalysisSummary>,
    pub alert: Option<AlertRecord>,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub response_digests: Vec<Digest>,
    pub provider_errors: Vec<TransportError>,
    pub provenance: ProviderProvenance,
    pub partial: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub evidence_digest: Digest,
}

impl CodeqlResultEvidence {
    fn new(
        scope: &GithubCodeqlScope,
        analysis: Option<AnalysisSummary>,
        alert: Option<AlertRecord>,
        response_digests: Vec<Digest>,
        provider_errors: Vec<TransportError>,
        provenance: ProviderProvenance,
        partial: bool,
        secret_reference_digest: &Digest,
    ) -> Result<Self> {
        let mut evidence = Self {
            scope_digest: scope.digest().clone(),
            installation_digest: scope.installation_digest(),
            repository_digest: scope.repository_digest(),
            ref_digest: scope.ref_digest(),
            commit_sha: scope.commit_sha.clone(),
            analysis,
            alert,
            permission_digest: scope.permissions.digest().clone(),
            secret_reference_digest: secret_reference_digest.clone(),
            response_digests,
            provider_errors,
            provenance,
            partial,
            connected: false,
            native: false,
            first_party: false,
            evidence_digest: Digest::from_text("unsealed-github-codeql-evidence"),
        };
        evidence.evidence_digest = evidence.computed_digest();
        evidence.validate(scope)?;
        Ok(evidence)
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope_digest,
            &self.installation_digest,
            &self.repository_digest,
            &self.ref_digest,
            &self.commit_sha,
            &self.analysis,
            &self.alert,
            &self.permission_digest,
            &self.secret_reference_digest,
            &self.response_digests,
            &self.provider_errors,
            self.provenance,
            self.partial,
            self.connected,
            self.native,
            self.first_party,
        ))
    }

    pub fn validate(&self, scope: &GithubCodeqlScope) -> Result<()> {
        if self.scope_digest != *scope.digest()
            || self.installation_digest != scope.installation_digest()
            || self.repository_digest != scope.repository_digest()
            || self.ref_digest != scope.ref_digest()
            || self.commit_sha != scope.commit_sha
            || self.permission_digest != *scope.permissions.digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self
                .response_digests
                .iter()
                .any(|digest| digest.validate().is_err())
            || self.evidence_digest != self.computed_digest()
        {
            return Err(ServiceError::ProviderEvidence(
                ProviderError::TamperedEvidence,
            ));
        }
        if let Some(analysis) = &self.analysis {
            analysis
                .validate_digest()
                .map_err(ServiceError::ProviderEvidence)?;
            validate_analysis(scope, analysis)?;
        }
        if let Some(alert) = &self.alert {
            alert
                .validate_digest()
                .map_err(ServiceError::ProviderEvidence)?;
            validate_alert(scope, alert)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubCodeqlResultProjection {
    pub scope_digest: Digest,
    pub state: ProjectionState,
    pub evidence: Option<CodeqlResultEvidence>,
    pub response_digests: Vec<Digest>,
    pub provider_errors: Vec<TransportError>,
    pub provenance: ProviderProvenance,
    pub partial: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub projection_digest: Digest,
}

impl GithubCodeqlResultProjection {
    fn new(
        scope: &GithubCodeqlScope,
        state: ProjectionState,
        evidence: Option<CodeqlResultEvidence>,
        response_digests: Vec<Digest>,
        provider_errors: Vec<TransportError>,
        provenance: ProviderProvenance,
        partial: bool,
    ) -> Result<Self> {
        let mut projection = Self {
            scope_digest: scope.digest().clone(),
            state,
            evidence,
            response_digests,
            provider_errors,
            provenance,
            partial,
            connected: false,
            native: false,
            first_party: false,
            projection_digest: Digest::from_text("unsealed-github-codeql-projection"),
        };
        projection.projection_digest = projection.computed_digest();
        projection.validate(scope)?;
        Ok(projection)
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope_digest,
            self.state,
            &self.evidence,
            &self.response_digests,
            &self.provider_errors,
            self.provenance,
            self.partial,
            self.connected,
            self.native,
            self.first_party,
        ))
    }

    pub fn validate(&self, scope: &GithubCodeqlScope) -> Result<()> {
        if self.scope_digest != *scope.digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.projection_digest != self.computed_digest()
        {
            return Err(ServiceError::ProviderEvidence(
                ProviderError::TamperedEvidence,
            ));
        }
        if let Some(evidence) = &self.evidence {
            evidence.validate(scope)?;
        }
        Ok(())
    }

    pub const fn is_conclusion_free(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeqlResultProposal {
    pub proposal_version: String,
    pub service_id: String,
    pub consumer_id: String,
    pub registration_id: RegistrationId,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub installation_digest: Digest,
    pub repository_digest: Digest,
    pub ref_digest: Digest,
    pub commit_digest: Digest,
    pub analysis_digest: Digest,
    pub tool_digest: Digest,
    pub rule_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub alert_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub secret_reference_digest: Digest,
    pub scope: GithubCodeqlScope,
    pub projection: GithubCodeqlResultProjection,
    pub disposition: ProposalDisposition,
    pub idempotency_key_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub proposal_digest: Digest,
}

impl CodeqlResultProposal {
    fn from_projection(
        scope: &GithubCodeqlScope,
        registration: &GithubCodeqlRegistration,
        projection: GithubCodeqlResultProjection,
        idempotency_key: &str,
    ) -> Self {
        let secret_reference_digest = projection.evidence.as_ref().map_or_else(
            || registration.secret_reference_digest.clone(),
            |evidence| evidence.secret_reference_digest.clone(),
        );
        let mut proposal = Self {
            proposal_version: format!("{CONTRACT_VERSION}/codeql-result-proposal"),
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_id: registration.registration_id.clone(),
            registration_revision: registration.registration_revision,
            registration_digest: registration.registration_digest.clone(),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: registration.provider_digest.clone(),
            api_digest: registration.api_digest.clone(),
            installation_digest: registration.installation_digest.clone(),
            repository_digest: registration.repository_digest.clone(),
            ref_digest: registration.ref_digest.clone(),
            commit_digest: registration.commit_digest.clone(),
            analysis_digest: registration.analysis_digest.clone(),
            tool_digest: registration.tool_digest.clone(),
            rule_digest: registration.rule_digest.clone(),
            permission_digest: registration.permission_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            alert_digest: registration.alert_digest.clone(),
            evidence_policy_digest: registration.evidence_policy_digest.clone(),
            secret_reference_digest,
            scope: scope.clone(),
            disposition: projection.state.into(),
            projection,
            idempotency_key_digest: Digest::from_text(idempotency_key),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            proposal_digest: Digest::from_text("unsealed-github-codeql-proposal"),
        };
        proposal.proposal_digest = proposal.computed_digest();
        proposal
    }

    pub fn computed_digest(&self) -> Digest {
        let fields = vec![
            self.proposal_version.clone(),
            self.service_id.clone(),
            self.consumer_id.clone(),
            self.registration_id.as_str().to_owned(),
            self.registration_revision.get().to_string(),
            self.registration_digest.as_str().to_owned(),
            self.contract_digest.as_str().to_owned(),
            self.provider_digest.as_str().to_owned(),
            self.api_digest.as_str().to_owned(),
            self.installation_digest.as_str().to_owned(),
            self.repository_digest.as_str().to_owned(),
            self.ref_digest.as_str().to_owned(),
            self.commit_digest.as_str().to_owned(),
            self.analysis_digest.as_str().to_owned(),
            self.tool_digest.as_str().to_owned(),
            self.rule_digest.as_str().to_owned(),
            self.permission_digest.as_str().to_owned(),
            self.scope_digest.as_str().to_owned(),
            self.alert_digest.as_str().to_owned(),
            self.evidence_policy_digest.as_str().to_owned(),
            self.secret_reference_digest.as_str().to_owned(),
            serde_json::to_string(&self.scope).expect("scope serializes"),
            serde_json::to_string(&self.projection).expect("projection serializes"),
            format!("{:?}", self.disposition),
            self.idempotency_key_digest.as_str().to_owned(),
            self.connected.to_string(),
            self.native.to_string(),
            self.first_party.to_string(),
            self.provider_receipt.to_string(),
            self.outcome_adopted.to_string(),
        ];
        Digest::from_fields("github-codeql-proposal/v1", &fields)
    }

    pub fn validate_integrity(
        &self,
        scope: &GithubCodeqlScope,
        registration: &GithubCodeqlRegistration,
    ) -> Result<()> {
        self.projection.validate(scope)?;
        if self.proposal_version != format!("{CONTRACT_VERSION}/codeql-result-proposal")
            || self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.registration_id != registration.registration_id
            || self.registration_revision != registration.registration_revision
            || self.registration_digest != registration.registration_digest
            || self.contract_digest != registration.contract_digest
            || self.provider_digest != registration.provider_digest
            || self.api_digest != registration.api_digest
            || self.installation_digest != registration.installation_digest
            || self.repository_digest != registration.repository_digest
            || self.ref_digest != registration.ref_digest
            || self.commit_digest != registration.commit_digest
            || self.analysis_digest != registration.analysis_digest
            || self.tool_digest != registration.tool_digest
            || self.rule_digest != registration.rule_digest
            || self.permission_digest != registration.permission_digest
            || self.scope_digest != registration.scope_digest
            || self.alert_digest != registration.alert_digest
            || self.evidence_policy_digest != registration.evidence_policy_digest
            || self.secret_reference_digest != registration.secret_reference_digest
            || self.scope != *scope
            || self.projection.scope_digest != self.scope_digest
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.projection.provenance.connected()
            || self.projection.provenance.native()
            || self.projection.provenance.first_party()
            || self.proposal_digest != self.computed_digest()
        {
            Err(ServiceError::ProposalTampered)
        } else {
            Ok(())
        }
    }

    pub const fn can_adopt_outcome(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeqlResultRecording {
    pub recording_version: String,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub proposal_digest: Digest,
    pub evidence_digest: Option<Digest>,
    pub provenance: ProviderProvenance,
    pub durable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adopted: bool,
    pub recording_digest: Digest,
}

impl CodeqlResultRecording {
    fn from_proposal(proposal: &CodeqlResultProposal) -> Self {
        let mut recording = Self {
            recording_version: format!("{CONTRACT_VERSION}/codeql-result-recording"),
            registration_digest: proposal.registration_digest.clone(),
            registration_revision: proposal.registration_revision,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal
                .projection
                .evidence
                .as_ref()
                .map(|evidence| evidence.evidence_digest.clone()),
            provenance: proposal.projection.provenance,
            durable: false,
            connected: false,
            native: false,
            first_party: false,
            outcome_adopted: false,
            recording_digest: Digest::from_text("unsealed-github-codeql-recording"),
        };
        recording.recording_digest = recording.computed_digest();
        recording
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.recording_version,
            &self.registration_digest,
            self.registration_revision,
            &self.proposal_digest,
            &self.evidence_digest,
            self.provenance,
            self.durable,
            self.connected,
            self.native,
            self.first_party,
            self.outcome_adopted,
        ))
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.recording_version != format!("{CONTRACT_VERSION}/codeql-result-recording")
            || self.durable
            || self.connected
            || self.native
            || self.first_party
            || self.outcome_adopted
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.recording_digest != self.computed_digest()
        {
            Err(ServiceError::RecordingTampered)
        } else {
            Ok(())
        }
    }
}

pub struct GithubCodeqlResultService<T> {
    scope: GithubCodeqlScope,
    secret: SecretReference,
    provider: GithubCodeScanningProvider<T>,
    definition: GithubCodeqlResultServiceDefinition,
    registration: GithubCodeqlRegistration,
    limits: ReadLimits,
}

impl<T: fmt::Debug> fmt::Debug for GithubCodeqlResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubCodeqlResultService")
            .field("scope", &self.scope)
            .field("secret", &self.secret)
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("limits", &self.limits)
            .finish()
    }
}

impl<T: GithubCodeScanningTransport + fmt::Debug> GithubCodeqlResultService<T> {
    pub fn new(
        scope: GithubCodeqlScope,
        secret: SecretReference,
        provider: GithubCodeScanningProvider<T>,
        limits: ReadLimits,
    ) -> Result<Self> {
        scope.validate()?;
        secret.validate_for_scope(&scope)?;
        if secret.is_revoked() {
            return Err(ServiceError::SecretRevoked);
        }
        limits.validate()?;
        provider.definition().validate()?;
        if provider.definition().permissions != scope.permissions {
            return Err(ServiceError::PermissionMismatch);
        }
        let definition = GithubCodeqlResultServiceDefinition::layer1();
        definition.validate()?;
        let registration = GithubCodeqlRegistration::new(
            &scope,
            &secret,
            provider.definition(),
            Revision::new(1)?,
        )?;
        Ok(Self {
            scope,
            secret,
            provider,
            definition,
            registration,
            limits,
        })
    }

    pub fn scope(&self) -> &GithubCodeqlScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn provider(&self) -> &GithubCodeScanningProvider<T> {
        &self.provider
    }

    pub fn provider_definition(&self) -> &GithubCodeScanningProviderDefinition {
        self.provider.definition()
    }

    pub fn definition(&self) -> &GithubCodeqlResultServiceDefinition {
        &self.definition
    }

    pub fn capabilities(&self) -> &GithubCodeqlCapabilityDescription {
        &self.definition.capability
    }

    pub fn registration(&self) -> &GithubCodeqlRegistration {
        &self.registration
    }

    pub const fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret.is_revoked()
    }

    pub fn unmount(&mut self) -> Result<()> {
        self.registration.unmount()
    }

    pub fn remount(&mut self) -> Result<()> {
        if self.secret.is_revoked() {
            return Err(ServiceError::SecretRevoked);
        }
        self.registration.remount()
    }

    pub fn revoke_registration(&mut self) -> Result<()> {
        self.secret.revoke().map_err(ServiceError::Model)?;
        self.registration.revoke()
    }

    pub fn read_alert_evidence(&mut self) -> Result<GithubCodeqlResultProjection> {
        self.read_evidence()
    }

    pub fn read_evidence(&mut self) -> Result<GithubCodeqlResultProjection> {
        self.ensure_active()?;
        self.registration
            .validate(&self.scope, &self.secret, self.provider.definition())?;

        let mut response_digests = Vec::new();
        let mut provider_errors = Vec::new();
        let mut partial = false;
        let analysis = match self.read_analysis_pages(
            &mut response_digests,
            &mut provider_errors,
            &mut partial,
        )? {
            PageResult::Projection(state) => {
                return self.make_projection(
                    state,
                    None::<CodeqlResultEvidence>,
                    response_digests,
                    provider_errors,
                    partial,
                );
            }
            PageResult::Found(analysis) => analysis,
            PageResult::NotFound => {
                return self.make_projection(
                    ProjectionState::AnalysisNotFound,
                    None::<CodeqlResultEvidence>,
                    response_digests,
                    provider_errors,
                    partial,
                );
            }
        };

        if !analysis.status.is_complete() {
            return self.make_projection(
                ProjectionState::AnalysisIncomplete,
                Some(analysis),
                response_digests,
                provider_errors,
                partial,
            );
        }

        let alert = match self.read_alert_pages(
            &mut response_digests,
            &mut provider_errors,
            &mut partial,
        )? {
            PageResult::Projection(state) => {
                return self.make_projection(
                    state,
                    Some(analysis),
                    response_digests,
                    provider_errors,
                    partial,
                );
            }
            PageResult::Found(alert) => alert,
            PageResult::NotFound => {
                return self.make_projection(
                    ProjectionState::NoAlertEvidence,
                    Some(analysis),
                    response_digests,
                    provider_errors,
                    partial,
                );
            }
        };

        let evidence = CodeqlResultEvidence::new(
            &self.scope,
            Some(analysis),
            Some(alert),
            response_digests.clone(),
            provider_errors.clone(),
            self.provider.provenance(),
            partial,
            self.secret.reference_digest(),
        )?;
        self.make_projection(
            ProjectionState::AlertEvidence,
            Some(evidence),
            response_digests,
            provider_errors,
            partial,
        )
    }

    pub fn compile_proposal(
        &mut self,
        idempotency_key: impl AsRef<str>,
    ) -> Result<CodeqlResultProposal> {
        self.compile_result_proposal(idempotency_key)
    }

    pub fn compile_result_proposal(
        &mut self,
        idempotency_key: impl AsRef<str>,
    ) -> Result<CodeqlResultProposal> {
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(ServiceError::InvalidIdempotencyKey);
        }
        let projection = self.read_evidence()?;
        Ok(CodeqlResultProposal::from_projection(
            &self.scope,
            &self.registration,
            projection,
            idempotency_key,
        ))
    }

    pub fn record_proposal(
        &self,
        proposal: &CodeqlResultProposal,
    ) -> Result<CodeqlResultRecording> {
        self.record_result(proposal)
    }

    pub fn record_result(&self, proposal: &CodeqlResultProposal) -> Result<CodeqlResultRecording> {
        self.ensure_active()?;
        proposal.validate_integrity(&self.scope, &self.registration)?;
        Ok(CodeqlResultRecording::from_proposal(proposal))
    }

    pub fn verify_recording(&self, recording: &CodeqlResultRecording) -> Result<()> {
        self.ensure_active()?;
        recording.validate_integrity()?;
        if recording.registration_digest != self.registration.registration_digest
            || recording.registration_revision != self.registration.registration_revision
        {
            Err(ServiceError::RegistrationDrift)
        } else {
            Ok(())
        }
    }

    pub fn limits(&self) -> ReadLimits {
        self.limits
    }

    fn ensure_active(&self) -> Result<()> {
        if self.secret.is_revoked() {
            Err(ServiceError::SecretRevoked)
        } else if !self.registration.is_active() {
            Err(ServiceError::RegistrationInactive)
        } else {
            Ok(())
        }
    }

    fn make_projection(
        &self,
        state: ProjectionState,
        value: Option<impl IntoEvidence>,
        response_digests: Vec<Digest>,
        provider_errors: Vec<TransportError>,
        partial: bool,
    ) -> Result<GithubCodeqlResultProjection> {
        let evidence = value
            .map(|value| {
                value.into_evidence(
                    &self.scope,
                    &self.secret,
                    &response_digests,
                    &provider_errors,
                    self.provider.provenance(),
                    partial,
                )
            })
            .transpose()?;
        GithubCodeqlResultProjection::new(
            &self.scope,
            state,
            evidence,
            response_digests,
            provider_errors,
            self.provider.provenance(),
            partial,
        )
    }

    fn read_analysis_pages(
        &mut self,
        response_digests: &mut Vec<Digest>,
        provider_errors: &mut Vec<TransportError>,
        partial: &mut bool,
    ) -> Result<PageResult<AnalysisSummary>> {
        let mut page_number = 1;
        let mut page_token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut found = None;
        let mut seen_analyses = BTreeSet::new();
        loop {
            if page_number > self.limits.max_analysis_pages {
                return Err(ServiceError::PaginationMismatch);
            }
            let request = CodeqlReadRequest::from_scope(
                &self.scope,
                self.limits.page_size,
                page_token.clone(),
            );
            let page = match self.provider.list_analyses(&request) {
                Ok(page) => page,
                Err(error) => {
                    provider_errors.push(error.clone());
                    *partial |= error.truncated;
                    return Ok(PageResult::Projection(provider_error_state(&error)));
                }
            };
            page.validate_digest()
                .map_err(ServiceError::ProviderEvidence)?;
            if page.page != page_number {
                return Err(ServiceError::PaginationMismatch);
            }
            if page.response_bytes > self.limits.max_response_bytes {
                return Err(ServiceError::ResponseTooLarge);
            }
            let page_size = usize::try_from(self.limits.page_size)
                .expect("u32 fits in the supported usize targets");
            if page.items.len() > page_size {
                return Err(ServiceError::ResponseTooLarge);
            }
            if page.truncated {
                *partial = true;
                return Ok(PageResult::Projection(ProjectionState::Partial));
            }
            response_digests.push(page.response_digest.clone());
            for item in page.items {
                if !seen_analyses.insert(item.analysis_id.clone()) {
                    return Err(ServiceError::DuplicateEvidence);
                }
                if seen_analyses.len() > self.limits.max_alerts {
                    return Err(ServiceError::ResponseTooLarge);
                }
                item.validate_digest()
                    .map_err(ServiceError::ProviderEvidence)?;
                if item.tool != self.scope.tool
                    || item.repository_digest != self.scope.repository_digest()
                    || item.ref_digest != self.scope.ref_digest()
                    || item.commit_sha != self.scope.commit_sha
                {
                    if item.analysis_id == self.scope.analysis_id {
                        return Err(ServiceError::AnalysisDrift);
                    }
                    continue;
                }
                if item.analysis_id == self.scope.analysis_id {
                    found = Some(item);
                }
            }
            match page.next_page_token {
                Some(next) => {
                    if !seen_tokens.insert(next.digest().clone()) {
                        return Err(ServiceError::PageLoop);
                    }
                    page_token = Some(next);
                    page_number += 1;
                }
                None => break,
            }
        }
        Ok(found.map_or(PageResult::NotFound, PageResult::Found))
    }

    fn read_alert_pages(
        &mut self,
        response_digests: &mut Vec<Digest>,
        provider_errors: &mut Vec<TransportError>,
        partial: &mut bool,
    ) -> Result<PageResult<AlertRecord>> {
        let mut page_number = 1;
        let mut page_token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut seen_alerts = BTreeSet::new();
        let mut target = None;
        loop {
            if page_number > self.limits.max_alert_pages {
                return Err(ServiceError::PaginationMismatch);
            }
            let request = ListAlertsRequest::from_scope(
                &self.scope,
                self.limits.page_size,
                page_token.clone(),
            );
            let page = match self.provider.list_alerts(&request) {
                Ok(page) => page,
                Err(error) => {
                    provider_errors.push(error.clone());
                    *partial |= error.truncated;
                    return Ok(PageResult::Projection(provider_error_state(&error)));
                }
            };
            page.validate_digest()
                .map_err(ServiceError::ProviderEvidence)?;
            if page.page != page_number {
                return Err(ServiceError::PaginationMismatch);
            }
            if page.response_bytes > self.limits.max_response_bytes {
                return Err(ServiceError::ResponseTooLarge);
            }
            let page_size = usize::try_from(self.limits.page_size)
                .expect("u32 fits in the supported usize targets");
            if page.items.len() > page_size {
                return Err(ServiceError::ResponseTooLarge);
            }
            if page.truncated {
                *partial = true;
                return Ok(PageResult::Projection(ProjectionState::Partial));
            }
            response_digests.push(page.response_digest.clone());
            for item in page.items {
                if !seen_alerts.insert(item.alert_number) {
                    return Err(ServiceError::DuplicateEvidence);
                }
                if seen_alerts.len() > self.limits.max_alerts {
                    return Err(ServiceError::ResponseTooLarge);
                }
                item.validate_digest()
                    .map_err(ServiceError::ProviderEvidence)?;
                if item.tool != CodeScanningTool::CodeQL
                    || !self.scope.rule_allowlist.contains(&item.rule_id)
                {
                    return Err(ServiceError::RuleNotAllowlisted);
                }
                if item.alert_number == self.scope.alert_number {
                    if item.fingerprint != self.scope.alert_fingerprint {
                        return Err(ServiceError::AlertDrift);
                    }
                    if item.state != self.scope.expected_alert_state {
                        return Err(ServiceError::StaleAlertState);
                    }
                    if item.rule_id != self.scope.rule_id
                        || item.analysis_id != self.scope.analysis_id
                        || item.repository_digest != self.scope.repository_digest()
                        || item.ref_digest != self.scope.ref_digest()
                        || item.commit_sha != self.scope.commit_sha
                    {
                        return Err(ServiceError::AlertDrift);
                    }
                    target = Some(item);
                }
            }
            match page.next_page_token {
                Some(next) => {
                    if !seen_tokens.insert(next.digest().clone()) {
                        return Err(ServiceError::PageLoop);
                    }
                    page_token = Some(next);
                    page_number += 1;
                }
                None => break,
            }
        }
        let Some(summary) = target else {
            return Ok(PageResult::NotFound);
        };
        let request = GetAlertRequest {
            read: CodeqlReadRequest::from_scope(&self.scope, self.limits.page_size, None),
            alert_number: summary.alert_number,
            fingerprint: summary.fingerprint,
        };
        let record = match self.provider.get_alert(&request) {
            Ok(record) => record,
            Err(error) => {
                provider_errors.push(error.clone());
                *partial |= error.truncated;
                return Ok(PageResult::Projection(provider_error_state(&error)));
            }
        };
        record
            .validate_digest()
            .map_err(ServiceError::ProviderEvidence)?;
        if record.locations.len() > self.limits.max_locations {
            return Err(ServiceError::ResponseTooLarge);
        }
        validate_alert(&self.scope, &record)?;
        Ok(PageResult::Found(record))
    }
}

enum PageResult<T> {
    Found(T),
    NotFound,
    Projection(ProjectionState),
}

trait IntoEvidence {
    fn into_evidence(
        self,
        scope: &GithubCodeqlScope,
        secret: &SecretReference,
        response_digests: &[Digest],
        provider_errors: &[TransportError],
        provenance: ProviderProvenance,
        partial: bool,
    ) -> Result<CodeqlResultEvidence>;
}

impl IntoEvidence for AnalysisSummary {
    fn into_evidence(
        self,
        scope: &GithubCodeqlScope,
        secret: &SecretReference,
        response_digests: &[Digest],
        provider_errors: &[TransportError],
        provenance: ProviderProvenance,
        partial: bool,
    ) -> Result<CodeqlResultEvidence> {
        CodeqlResultEvidence::new(
            scope,
            Some(self),
            None,
            response_digests.to_vec(),
            provider_errors.to_vec(),
            provenance,
            partial,
            secret.reference_digest(),
        )
    }
}

impl IntoEvidence for AlertRecord {
    fn into_evidence(
        self,
        scope: &GithubCodeqlScope,
        secret: &SecretReference,
        response_digests: &[Digest],
        provider_errors: &[TransportError],
        provenance: ProviderProvenance,
        partial: bool,
    ) -> Result<CodeqlResultEvidence> {
        CodeqlResultEvidence::new(
            scope,
            None,
            Some(self),
            response_digests.to_vec(),
            provider_errors.to_vec(),
            provenance,
            partial,
            secret.reference_digest(),
        )
    }
}

impl IntoEvidence for CodeqlResultEvidence {
    fn into_evidence(
        self,
        _scope: &GithubCodeqlScope,
        _secret: &SecretReference,
        _response_digests: &[Digest],
        _provider_errors: &[TransportError],
        _provenance: ProviderProvenance,
        _partial: bool,
    ) -> Result<CodeqlResultEvidence> {
        Ok(self)
    }
}

fn provider_error_state(error: &TransportError) -> ProjectionState {
    if error.is_access_loss() {
        ProjectionState::AccessLoss
    } else if error.truncated {
        ProjectionState::Partial
    } else {
        ProjectionState::ProviderUnknown
    }
}

fn validate_analysis(scope: &GithubCodeqlScope, analysis: &AnalysisSummary) -> Result<()> {
    if analysis.analysis_id != scope.analysis_id {
        return Err(ServiceError::AnalysisDrift);
    }
    if analysis.tool != scope.tool
        || analysis.repository_digest != scope.repository_digest()
        || analysis.ref_digest != scope.ref_digest()
        || analysis.commit_sha != scope.commit_sha
    {
        Err(ServiceError::AnalysisDrift)
    } else {
        Ok(())
    }
}

fn validate_alert(scope: &GithubCodeqlScope, alert: &AlertRecord) -> Result<()> {
    if alert.alert_number != scope.alert_number || alert.fingerprint != scope.alert_fingerprint {
        return Err(ServiceError::AlertDrift);
    }
    if alert.state != scope.expected_alert_state {
        return Err(ServiceError::StaleAlertState);
    }
    if alert.tool != scope.tool
        || alert.rule_id != scope.rule_id
        || !scope.rule_allowlist.contains(&alert.rule_id)
        || alert.analysis_id != scope.analysis_id
        || alert.repository_digest != scope.repository_digest()
        || alert.ref_digest != scope.ref_digest()
        || alert.commit_sha != scope.commit_sha
        || alert
            .locations
            .iter()
            .any(|location| location.validate().is_err())
    {
        Err(ServiceError::AlertDrift)
    } else {
        Ok(())
    }
}
