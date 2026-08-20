//! Mission-scoped Jenkins build-result service and reversible registration.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

use crate::model::{
    Digest, JenkinsBuildProjection, JenkinsBuildResultEvidence, JenkinsBuildResultScope,
    JenkinsBuildResultStatus, JenkinsCursor, JenkinsEndpoint, JenkinsFailureCode,
    JenkinsModelError, JenkinsPermissionSnapshot, JenkinsReadFailure, JenkinsReadOperation,
    JenkinsRegistrationSnapshot, MAX_OPERATIONS, RegistrationState, SecretReference,
    digest_serializable,
};
use crate::provider::{
    JenkinsPayload, JenkinsProvider, JenkinsProviderDefinition, JenkinsProviderError,
    JenkinsProviderRead, JenkinsReadRequest, JenkinsTransport,
};
use crate::{
    JENKINS_BUILD_RESULT_CONTRACT_VERSION, JENKINS_BUILD_RESULT_PLUGIN_VERSION,
    JENKINS_BUILD_RESULT_SCHEMA_VERSION, JENKINS_BUILD_RESULT_SERVICE_ID,
    JENKINS_BUILD_RESULT_SERVICE_NAME, JENKINS_EVIDENCE_POLICY_SCHEMA, contract_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum JenkinsBuildResultServiceError {
    #[error("Jenkins build-result model error: {0}")]
    Model(#[from] JenkinsModelError),
    #[error("Jenkins build-result provider error: {0}")]
    Provider(#[from] JenkinsProviderError),
    #[error("Jenkins build-result contract is invalid: {0}")]
    Contract(String),
    #[error("Jenkins build-result registration is revoked")]
    RegistrationRevoked,
    #[error("Jenkins build-result registration drifted")]
    RegistrationDrift,
    #[error("Jenkins build-result request is outside the exact scope")]
    ScopeMismatch,
    #[error("Jenkins build-result proposal is tampered or stale")]
    ProposalTampered,
    #[error("Jenkins build-result proposal was already consumed")]
    ReplayDetected,
    #[error("Jenkins build-result request must contain between one and eight unique reads")]
    InvalidRequest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JenkinsBuildResultOperation {
    DescribeCapabilities,
    ReadController,
    ReadFolder,
    ReadJob,
    ReadBranch,
    ReadBuild,
    ReadCommit,
    ReadTestSummary,
    ReadArtifactMetadata,
    CompileProposal,
    VerifyProposal,
    RevokeRegistration,
    RestoreRegistration,
    ConsumeObservation,
}

impl JenkinsBuildResultOperation {
    pub const ALL: [Self; 14] = [
        Self::DescribeCapabilities,
        Self::ReadController,
        Self::ReadFolder,
        Self::ReadJob,
        Self::ReadBuild,
        Self::ReadBranch,
        Self::ReadCommit,
        Self::ReadTestSummary,
        Self::ReadArtifactMetadata,
        Self::CompileProposal,
        Self::VerifyProposal,
        Self::RevokeRegistration,
        Self::RestoreRegistration,
        Self::ConsumeObservation,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsBuildResultCapability {
    pub capability_id: String,
    pub operation: JenkinsBuildResultOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
    pub kernel_authority: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JenkinsBuildResultServiceDefinition {
    id: String,
    name: String,
    version: String,
    read_only: bool,
    native: bool,
    connected: bool,
    capabilities: Vec<JenkinsBuildResultCapability>,
}

impl Default for JenkinsBuildResultServiceDefinition {
    fn default() -> Self {
        Self::baseline()
    }
}

impl JenkinsBuildResultServiceDefinition {
    pub fn baseline() -> Self {
        let capabilities = JenkinsBuildResultOperation::ALL
            .into_iter()
            .map(|operation| JenkinsBuildResultCapability {
                capability_id: format!(
                    "{JENKINS_BUILD_RESULT_SERVICE_ID}.{}",
                    operation_name(operation)
                ),
                operation,
                read_only: true,
                mutates_provider: false,
                native_evidence: false,
                kernel_authority: false,
            })
            .collect();
        Self {
            id: JENKINS_BUILD_RESULT_SERVICE_ID.to_owned(),
            name: JENKINS_BUILD_RESULT_SERVICE_NAME.to_owned(),
            version: "1.0.0".to_owned(),
            read_only: true,
            native: false,
            connected: false,
            capabilities,
        }
    }

    pub fn validate(&self) -> Result<(), JenkinsBuildResultServiceError> {
        if self.id != JENKINS_BUILD_RESULT_SERVICE_ID
            || self.name != JENKINS_BUILD_RESULT_SERVICE_NAME
            || self.version != "1.0.0"
            || !self.read_only
            || self.native
            || self.connected
            || self.capabilities.len() != JenkinsBuildResultOperation::ALL.len()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only
                    || capability.mutates_provider
                    || capability.native_evidence
                    || capability.kernel_authority
            })
        {
            return Err(JenkinsBuildResultServiceError::Contract(
                "Jenkins service descriptor drifted".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub const fn native(&self) -> bool {
        self.native
    }

    pub const fn connected(&self) -> bool {
        self.connected
    }

    pub fn capabilities(&self) -> &[JenkinsBuildResultCapability] {
        &self.capabilities
    }
}

fn operation_name(operation: JenkinsBuildResultOperation) -> &'static str {
    match operation {
        JenkinsBuildResultOperation::DescribeCapabilities => "describe_capabilities",
        JenkinsBuildResultOperation::ReadController => "read_controller",
        JenkinsBuildResultOperation::ReadFolder => "read_folder",
        JenkinsBuildResultOperation::ReadJob => "read_job",
        JenkinsBuildResultOperation::ReadBranch => "read_branch",
        JenkinsBuildResultOperation::ReadBuild => "read_build",
        JenkinsBuildResultOperation::ReadCommit => "read_commit",
        JenkinsBuildResultOperation::ReadTestSummary => "read_test_summary",
        JenkinsBuildResultOperation::ReadArtifactMetadata => "read_artifact_metadata",
        JenkinsBuildResultOperation::CompileProposal => "compile_proposal",
        JenkinsBuildResultOperation::VerifyProposal => "verify_proposal",
        JenkinsBuildResultOperation::RevokeRegistration => "revoke_registration",
        JenkinsBuildResultOperation::RestoreRegistration => "restore_registration",
        JenkinsBuildResultOperation::ConsumeObservation => "consume_observation",
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsRegistrationTransition {
    pub previous_state: RegistrationState,
    pub new_state: RegistrationState,
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub revision: u64,
    pub reversible: bool,
}

/// A reversible registration that serializes only digests and lifecycle
/// fields. The opaque SecretReference is kept in memory but cannot serialize.
pub struct JenkinsRegistration {
    snapshot: JenkinsRegistrationSnapshot,
    secret_reference: SecretReference,
}

impl fmt::Debug for JenkinsRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JenkinsRegistration")
            .field("snapshot", &self.snapshot)
            .field("secret_reference", &self.secret_reference)
            .finish()
    }
}

impl Serialize for JenkinsRegistration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.snapshot.serialize(serializer)
    }
}

impl JenkinsRegistration {
    pub fn new(
        scope: &JenkinsBuildResultScope,
        secret_reference: SecretReference,
        provider_digest: Digest,
        permission_digest: JenkinsPermissionSnapshot,
    ) -> Result<Self, JenkinsBuildResultServiceError> {
        scope.validate()?;
        secret_reference.validate_for_scope(scope)?;
        permission_digest.validate_exact()?;
        let mut registration = Self {
            snapshot: JenkinsRegistrationSnapshot {
                state: RegistrationState::Active,
                version_digest: Digest::from_text(JENKINS_BUILD_RESULT_PLUGIN_VERSION),
                contract_digest: contract_digest(),
                provider_digest,
                permission_digest: permission_digest.digest.clone(),
                scope_digest: scope.digest().clone(),
                evidence_digest: Digest::from_text(JENKINS_EVIDENCE_POLICY_SCHEMA),
                secret_reference_digest: secret_reference.reference_digest().clone(),
                revision: 1,
                registration_digest: Digest::zero(),
            },
            secret_reference,
        };
        registration.snapshot.registration_digest = registration.snapshot.recompute_digest();
        Ok(registration)
    }

    pub fn snapshot(&self) -> &JenkinsRegistrationSnapshot {
        &self.snapshot
    }

    pub fn state(&self) -> RegistrationState {
        self.snapshot.state.clone()
    }

    pub fn is_active(&self) -> bool {
        matches!(self.snapshot.state, RegistrationState::Active)
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.snapshot.registration_digest
    }

    pub fn version_digest(&self) -> &Digest {
        &self.snapshot.version_digest
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.snapshot.contract_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.snapshot.provider_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.snapshot.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.snapshot.scope_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.snapshot.evidence_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.snapshot.secret_reference_digest
    }

    pub const fn revision(&self) -> u64 {
        self.snapshot.revision
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_mut(&mut self) -> &mut SecretReference {
        &mut self.secret_reference
    }

    pub fn validate(
        &self,
        scope: &JenkinsBuildResultScope,
        provider: &JenkinsProviderDefinition,
    ) -> Result<(), JenkinsBuildResultServiceError> {
        scope.validate()?;
        self.secret_reference.validate_for_scope(scope)?;
        if self.snapshot.scope_digest != *scope.digest()
            || self.snapshot.provider_digest != provider.provider_digest
            || self.snapshot.permission_digest != *provider.permission_digest()
            || self.snapshot.contract_digest != contract_digest()
            || self.snapshot.version_digest
                != Digest::from_text(JENKINS_BUILD_RESULT_PLUGIN_VERSION)
            || self.snapshot.evidence_digest != Digest::from_text(JENKINS_EVIDENCE_POLICY_SCHEMA)
            || self.snapshot.secret_reference_digest != *self.secret_reference.reference_digest()
            || self.snapshot.registration_digest != self.snapshot.recompute_digest()
        {
            return Err(JenkinsBuildResultServiceError::RegistrationDrift);
        }
        Ok(())
    }

    pub fn revoke(
        &mut self,
    ) -> Result<JenkinsRegistrationTransition, JenkinsBuildResultServiceError> {
        if !self.is_active() {
            return Err(JenkinsBuildResultServiceError::RegistrationRevoked);
        }
        let previous_state = self.state();
        let previous_registration_digest = self.registration_digest().clone();
        self.snapshot.state = RegistrationState::Revoked;
        self.snapshot.revision = self.snapshot.revision.saturating_add(1);
        self.snapshot.registration_digest = self.snapshot.recompute_digest();
        Ok(JenkinsRegistrationTransition {
            previous_state,
            new_state: self.state(),
            previous_registration_digest,
            registration_digest: self.registration_digest().clone(),
            revision: self.revision(),
            reversible: true,
        })
    }

    pub fn restore(
        &mut self,
    ) -> Result<JenkinsRegistrationTransition, JenkinsBuildResultServiceError> {
        if self.is_active() {
            return Err(JenkinsBuildResultServiceError::Contract(
                "Jenkins registration is already active".to_owned(),
            ));
        }
        let previous_state = self.state();
        let previous_registration_digest = self.registration_digest().clone();
        self.snapshot.state = RegistrationState::Active;
        self.snapshot.revision = self.snapshot.revision.saturating_add(1);
        self.snapshot.registration_digest = self.snapshot.recompute_digest();
        Ok(JenkinsRegistrationTransition {
            previous_state,
            new_state: self.state(),
            previous_registration_digest,
            registration_digest: self.registration_digest().clone(),
            revision: self.revision(),
            reversible: true,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsBuildResultRequest {
    pub scope_digest: Digest,
    pub operations: Vec<JenkinsReadOperation>,
    pub cursor: Option<JenkinsCursor>,
}

impl JenkinsBuildResultRequest {
    pub fn new(
        scope: &JenkinsBuildResultScope,
        operations: Vec<JenkinsReadOperation>,
        cursor: Option<JenkinsCursor>,
    ) -> Result<Self, JenkinsBuildResultServiceError> {
        if operations.is_empty() || operations.len() > MAX_OPERATIONS {
            return Err(JenkinsBuildResultServiceError::InvalidRequest);
        }
        let unique = operations.iter().copied().collect::<BTreeSet<_>>();
        if unique.len() != operations.len() {
            return Err(JenkinsBuildResultServiceError::InvalidRequest);
        }
        if let Some(cursor) = cursor.as_ref() {
            cursor.validate(scope)?;
        }
        Ok(Self {
            scope_digest: scope.digest().clone(),
            operations,
            cursor,
        })
    }

    pub fn all(scope: &JenkinsBuildResultScope) -> Self {
        Self {
            scope_digest: scope.digest().clone(),
            operations: JenkinsReadOperation::ALL.to_vec(),
            cursor: None,
        }
    }
}

pub type JenkinsBuildResultReadRequest = JenkinsBuildResultRequest;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsBuildResultProposal {
    pub evidence: JenkinsBuildResultEvidence,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub project: crate::ProjectBinding,
    pub mission: crate::MissionBinding,
    pub work_product: crate::WorkProductBinding,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

impl JenkinsBuildResultProposal {
    pub fn recompute_digest(&self) -> Result<Digest, JenkinsModelError> {
        digest_serializable(&(
            &self.evidence,
            &self.scope_digest,
            &self.registration_digest,
            &self.project,
            &self.mission,
            &self.work_product,
            self.proposal_only,
            self.native,
            self.connected,
            self.adopts_outcome,
            self.adopts_work_product,
        ))
    }

    pub fn validate_integrity(&self) -> Result<(), JenkinsModelError> {
        if self.proposal_digest != self.recompute_digest()?
            || self.scope_digest != self.evidence.scope_digest
            || self.registration_digest != self.evidence.registration_digest
            || !self.proposal_only
            || self.native
            || self.connected
            || self.adopts_outcome
            || self.adopts_work_product
        {
            return Err(JenkinsModelError::Invalid {
                field: "proposal integrity",
            });
        }
        self.evidence.validate_integrity()
    }

    pub fn status(&self) -> JenkinsBuildResultStatus {
        self.evidence.status
    }
}

pub type JenkinsProposal = JenkinsBuildResultProposal;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JenkinsVerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ScopeDigestMismatch,
    ProviderDigestMismatch,
    PermissionDigestMismatch,
    ContractDigestMismatch,
    EvidenceDigestMismatch,
    ProposalDigestMismatch,
    AuthorityViolation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsVerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<JenkinsVerificationFailure>,
}

pub struct JenkinsBuildResultService<T: JenkinsTransport> {
    scope: JenkinsBuildResultScope,
    provider: JenkinsProvider<T>,
    registration: JenkinsRegistration,
}

impl<T: JenkinsTransport> fmt::Debug for JenkinsBuildResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JenkinsBuildResultService")
            .field("scope", &self.scope)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T: JenkinsTransport> JenkinsBuildResultService<T> {
    pub fn new(provider: JenkinsProvider<T>) -> Result<Self, JenkinsBuildResultServiceError> {
        let scope = provider.scope().clone();
        let registration = JenkinsRegistration::new(
            &scope,
            provider.secret_reference().clone(),
            provider.provider_digest().clone(),
            provider.definition().permissions.clone(),
        )?;
        Ok(Self {
            scope,
            provider,
            registration,
        })
    }

    pub fn from_parts(
        scope: JenkinsBuildResultScope,
        secret_reference: SecretReference,
        provider: JenkinsProvider<T>,
    ) -> Result<Self, JenkinsBuildResultServiceError> {
        if provider.scope() != &scope || provider.secret_reference() != &secret_reference {
            return Err(JenkinsBuildResultServiceError::ScopeMismatch);
        }
        Self::new(provider)
    }

    pub fn service_definition() -> JenkinsBuildResultServiceDefinition {
        JenkinsBuildResultServiceDefinition::baseline()
    }

    pub fn scope(&self) -> &JenkinsBuildResultScope {
        &self.scope
    }

    pub fn provider(&self) -> &JenkinsProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut JenkinsProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &JenkinsRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut JenkinsRegistration {
        &mut self.registration
    }

    pub fn describe_capabilities(&self) -> JenkinsBuildResultServiceDefinition {
        Self::service_definition()
    }

    pub fn default_request(&self) -> JenkinsBuildResultRequest {
        JenkinsBuildResultRequest::all(&self.scope)
    }

    pub fn read_default(
        &mut self,
    ) -> Result<JenkinsBuildResultEvidence, JenkinsBuildResultServiceError> {
        let request = self.default_request();
        self.read(&request)
    }

    pub fn read_operation(
        &mut self,
        operation: JenkinsReadOperation,
    ) -> Result<JenkinsBuildResultEvidence, JenkinsBuildResultServiceError> {
        let request = JenkinsBuildResultRequest::new(&self.scope, vec![operation], None)?;
        self.read(&request)
    }

    pub fn read_controller(
        &mut self,
    ) -> Result<JenkinsBuildResultEvidence, JenkinsBuildResultServiceError> {
        self.read_operation(JenkinsReadOperation::ReadController)
    }

    pub fn read_folder(
        &mut self,
    ) -> Result<JenkinsBuildResultEvidence, JenkinsBuildResultServiceError> {
        self.read_operation(JenkinsReadOperation::ReadFolder)
    }

    pub fn read_job(
        &mut self,
    ) -> Result<JenkinsBuildResultEvidence, JenkinsBuildResultServiceError> {
        self.read_operation(JenkinsReadOperation::ReadJob)
    }

    pub fn read_branch(
        &mut self,
    ) -> Result<JenkinsBuildResultEvidence, JenkinsBuildResultServiceError> {
        self.read_operation(JenkinsReadOperation::ReadBranch)
    }

    pub fn read_build(
        &mut self,
    ) -> Result<JenkinsBuildResultEvidence, JenkinsBuildResultServiceError> {
        self.read_operation(JenkinsReadOperation::ReadBuild)
    }

    pub fn read_commit(
        &mut self,
    ) -> Result<JenkinsBuildResultEvidence, JenkinsBuildResultServiceError> {
        self.read_operation(JenkinsReadOperation::ReadCommit)
    }

    pub fn read_test_summary(
        &mut self,
    ) -> Result<JenkinsBuildResultEvidence, JenkinsBuildResultServiceError> {
        self.read_operation(JenkinsReadOperation::ReadTestSummary)
    }

    pub fn read_artifact_metadata(
        &mut self,
    ) -> Result<JenkinsBuildResultEvidence, JenkinsBuildResultServiceError> {
        self.read_operation(JenkinsReadOperation::ReadArtifactMetadata)
    }

    pub fn read(
        &mut self,
        request: &JenkinsBuildResultRequest,
    ) -> Result<JenkinsBuildResultEvidence, JenkinsBuildResultServiceError> {
        self.ensure_active()?;
        self.registration
            .validate(&self.scope, self.provider.definition())?;
        if request.scope_digest != *self.scope.digest()
            || request.operations.is_empty()
            || request.operations.len() > MAX_OPERATIONS
            || request
                .operations
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != request.operations.len()
        {
            return Err(JenkinsBuildResultServiceError::InvalidRequest);
        }
        if request
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.validate(&self.scope).is_err())
        {
            return Err(JenkinsBuildResultServiceError::ScopeMismatch);
        }
        let mut reads = Vec::new();
        let mut failures = Vec::new();
        for operation in &request.operations {
            let endpoint = match operation {
                JenkinsReadOperation::ReadController => JenkinsEndpoint::Controller,
                JenkinsReadOperation::ReadFolder => JenkinsEndpoint::Folder,
                JenkinsReadOperation::ReadJob => JenkinsEndpoint::Job,
                JenkinsReadOperation::ReadBranch => JenkinsEndpoint::Branch,
                JenkinsReadOperation::ReadBuild => JenkinsEndpoint::Build,
                JenkinsReadOperation::ReadCommit => JenkinsEndpoint::Commit,
                JenkinsReadOperation::ReadTestSummary => JenkinsEndpoint::TestSummary,
                JenkinsReadOperation::ReadArtifactMetadata => JenkinsEndpoint::ArtifactMetadata,
            };
            let read_request =
                JenkinsReadRequest::new(&self.scope, endpoint, request.cursor.clone());
            let result = read_request.and_then(|request| self.provider.read(&request));
            match result {
                Ok(read) => reads.push(read),
                Err(error) => failures.push(JenkinsReadFailure {
                    operation: *operation,
                    code: error.failure_code(),
                }),
            }
        }
        self.build_evidence(reads, failures, request.cursor.as_ref())
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<JenkinsBuildResultProposal, JenkinsBuildResultServiceError> {
        let evidence = self.read_default()?;
        self.proposal_from_evidence(evidence)
    }

    pub fn propose(
        &mut self,
    ) -> Result<JenkinsBuildResultProposal, JenkinsBuildResultServiceError> {
        self.compile_proposal()
    }

    pub fn compile_proposal_for(
        &mut self,
        request: &JenkinsBuildResultRequest,
    ) -> Result<JenkinsBuildResultProposal, JenkinsBuildResultServiceError> {
        let evidence = self.read(request)?;
        self.proposal_from_evidence(evidence)
    }

    pub fn verify_proposal(
        &self,
        proposal: &JenkinsBuildResultProposal,
    ) -> Result<(), JenkinsBuildResultServiceError> {
        let report = self.verify(proposal);
        if report.valid {
            Ok(())
        } else {
            Err(JenkinsBuildResultServiceError::ProposalTampered)
        }
    }

    pub fn verify(&self, proposal: &JenkinsBuildResultProposal) -> JenkinsVerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(JenkinsVerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(JenkinsVerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.scope_digest != *self.scope.digest() {
            failures.push(JenkinsVerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.provider_digest != *self.provider.provider_digest() {
            failures.push(JenkinsVerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.permission_digest != *self.provider.permission_digest() {
            failures.push(JenkinsVerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.contract_version != JENKINS_BUILD_RESULT_CONTRACT_VERSION {
            failures.push(JenkinsVerificationFailure::ContractDigestMismatch);
        }
        if proposal.evidence.registration_digest != *self.registration.registration_digest() {
            failures.push(JenkinsVerificationFailure::RegistrationDigestMismatch);
        }
        if proposal
            .recompute_digest()
            .map_or(true, |digest| digest != proposal.proposal_digest)
        {
            failures.push(JenkinsVerificationFailure::ProposalDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(JenkinsVerificationFailure::EvidenceDigestMismatch);
        }
        if proposal.project != *self.scope.project()
            || proposal.mission != *self.scope.mission()
            || proposal.work_product != *self.scope.work_product()
            || !proposal.proposal_only
            || proposal.native
            || proposal.connected
            || proposal.adopts_outcome
            || proposal.adopts_work_product
        {
            failures.push(JenkinsVerificationFailure::AuthorityViolation);
        }
        failures.sort_unstable();
        failures.dedup();
        JenkinsVerificationReport {
            valid: failures.is_empty(),
            review_eligible: failures.is_empty()
                && proposal.status() != JenkinsBuildResultStatus::Tampered
                && proposal.status() != JenkinsBuildResultStatus::Revoked
                && proposal.status() != JenkinsBuildResultStatus::ProviderUnknown
                && proposal.status() != JenkinsBuildResultStatus::AccessLost,
            failures,
        }
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<JenkinsRegistrationTransition, JenkinsBuildResultServiceError> {
        self.registration.revoke()
    }

    pub fn revoke(
        &mut self,
    ) -> Result<JenkinsRegistrationTransition, JenkinsBuildResultServiceError> {
        self.revoke_registration()
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<JenkinsRegistrationTransition, JenkinsBuildResultServiceError> {
        self.registration.restore()
    }

    pub fn restore(
        &mut self,
    ) -> Result<JenkinsRegistrationTransition, JenkinsBuildResultServiceError> {
        self.restore_registration()
    }

    pub fn revoke_secret(&mut self) -> Result<(), JenkinsBuildResultServiceError> {
        self.registration.secret_reference_mut().revoke()?;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), JenkinsBuildResultServiceError> {
        if self.registration.is_active() {
            if self.registration.secret_reference().is_revoked() {
                Err(JenkinsBuildResultServiceError::RegistrationRevoked)
            } else {
                Ok(())
            }
        } else {
            Err(JenkinsBuildResultServiceError::RegistrationRevoked)
        }
    }

    fn build_evidence(
        &self,
        reads: Vec<JenkinsProviderRead>,
        failures: Vec<JenkinsReadFailure>,
        cursor: Option<&JenkinsCursor>,
    ) -> Result<JenkinsBuildResultEvidence, JenkinsBuildResultServiceError> {
        let mut controller = None;
        let mut folder = None;
        let mut job = None;
        let mut branch = None;
        let mut build = None;
        let mut commit = None;
        let mut test_summary = None;
        let mut artifact_metadata = None;
        let mut receipts = Vec::with_capacity(reads.len());
        for read in reads {
            receipts.push(read.receipt.clone());
            match read.payload {
                JenkinsPayload::Controller(value) => controller = Some(value),
                JenkinsPayload::Folder(value) => folder = Some(value),
                JenkinsPayload::Job(value) => job = Some(value),
                JenkinsPayload::Branch(value) => branch = Some(value),
                JenkinsPayload::Build(value) => build = Some(value),
                JenkinsPayload::Commit(value) => commit = Some(value),
                JenkinsPayload::TestSummary(value) => test_summary = Some(value),
                JenkinsPayload::ArtifactMetadata(value) => artifact_metadata = Some(value),
            }
        }
        if let Some(build) = build.as_mut() {
            if let Some(summary) = test_summary.as_ref() {
                build.test_summary_digest = Some(summary.summary_digest.clone());
            }
            if let Some(metadata) = artifact_metadata.as_ref() {
                build.artifact_metadata_digest = Some(metadata.metadata_digest.clone());
            }
            build.metadata_digest = digest_serializable(&(
                build.build_number,
                build.status,
                build.timestamp_millis,
                build.duration_millis,
                &build.branch_digest,
                &build.commit_digest,
                &build.test_summary_digest,
                &build.artifact_metadata_digest,
            ))?;
        }
        let source_digest = Digest::from_fields(
            receipts
                .iter()
                .map(|receipt| receipt.response_digest.as_str().to_owned()),
        );
        let status = evidence_status(build.as_ref(), &failures, receipts.len());
        let provenance = self.provider.provenance();
        let mut evidence = JenkinsBuildResultEvidence {
            schema_version: JENKINS_BUILD_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: JENKINS_BUILD_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: JENKINS_BUILD_RESULT_PLUGIN_VERSION.to_owned(),
            scope_digest: self.scope.digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_digest: self.provider.provider_digest().clone(),
            permission_digest: self.provider.permission_digest().clone(),
            source_digest,
            evidence_digest: Digest::zero(),
            status,
            provenance,
            controller,
            folder,
            job,
            branch,
            build,
            commit,
            test_summary,
            artifact_metadata,
            receipts,
            failures,
            cursor_digest: cursor.map(|value| value.cursor_digest().clone()),
            read_only: true,
            proposal_only: true,
            native: false,
            connected: false,
            external_writes: false,
            raw_response_retained: false,
            raw_console_logs_retained: false,
            raw_artifacts_retained: false,
            raw_source_retained: false,
            raw_scripts_retained: false,
        };
        evidence.evidence_digest = evidence.recompute_digest()?;
        Ok(evidence)
    }

    fn proposal_from_evidence(
        &self,
        evidence: JenkinsBuildResultEvidence,
    ) -> Result<JenkinsBuildResultProposal, JenkinsBuildResultServiceError> {
        evidence.validate_integrity()?;
        let mut proposal = JenkinsBuildResultProposal {
            scope_digest: self.scope.digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            proposal_digest: Digest::zero(),
            project: self.scope.project().clone(),
            mission: self.scope.mission().clone(),
            work_product: self.scope.work_product().clone(),
            evidence,
            proposal_only: true,
            native: false,
            connected: false,
            adopts_outcome: false,
            adopts_work_product: false,
        };
        proposal.proposal_digest = proposal.recompute_digest()?;
        Ok(proposal)
    }
}

fn evidence_status(
    build: Option<&JenkinsBuildProjection>,
    failures: &[JenkinsReadFailure],
    successful_reads: usize,
) -> JenkinsBuildResultStatus {
    if failures
        .iter()
        .any(|failure| failure.code == JenkinsFailureCode::ResponseTampered)
    {
        return JenkinsBuildResultStatus::Tampered;
    }
    if failures
        .iter()
        .any(|failure| failure.code == JenkinsFailureCode::RegistrationRevoked)
    {
        return JenkinsBuildResultStatus::Revoked;
    }
    if successful_reads > 0 && !failures.is_empty() {
        return JenkinsBuildResultStatus::Partial;
    }
    if let Some(build) = build {
        return build.status;
    }
    if failures
        .iter()
        .any(|failure| failure.code == JenkinsFailureCode::AccessLost)
    {
        return JenkinsBuildResultStatus::AccessLost;
    }
    if failures.iter().any(|failure| {
        matches!(
            failure.code,
            JenkinsFailureCode::BlockedEnv | JenkinsFailureCode::ProviderUnknown
        )
    }) {
        return JenkinsBuildResultStatus::ProviderUnknown;
    }
    JenkinsBuildResultStatus::Partial
}

pub type JenkinsBuildResultRegistration = JenkinsRegistration;
pub type JenkinsService<T> = JenkinsBuildResultService<T>;
