use std::{collections::BTreeMap, env, fmt};

use serde::{Deserialize, Serialize};

use crate::error::{TerraformCloudRunError, TerraformCloudTransportError};
use crate::model::{
    ApplyProposal, ApplyProposalRequest, ConfigurationProposal, ConfigurationProposalRequest,
    Digest, MAX_IDENTIFIER_BYTES, NativeStatus, ProviderProvenance, RegistrationRevocation,
    RegistrationStatus, RunEvidence, RunProposal, RunProposalRequest, RunReceipt,
    TerraformCloudRunRegistration, TerraformCloudScope, TerraformRunResultProposal,
    TerraformRunStatus, WorkspaceDescription,
};
use crate::transport::{SecretMaterial, TerraformCloudRunTransport};

pub const TERRAFORM_CLOUD_TOKEN_ENVIRONMENT_VARIABLE: &str = "HARTEVO_TERRAFORM_CLOUD_RUN_TOKEN";
pub const TERRAFORM_CLOUD_NATIVE_GATE_ENVIRONMENT_VARIABLE: &str =
    "HARTEVO_TERRAFORM_CLOUD_RUN_NATIVE";

/// The host resolves a SecretReference; the provider never receives Store,
/// keyring, browser-profile, or kernel authority.
pub trait TerraformCloudCredentialResolver: fmt::Debug + Send + Sync {
    fn resolve(
        &self,
        reference: &crate::SecretReference,
    ) -> Result<SecretMaterial, TerraformCloudRunError>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl TerraformCloudCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &self,
        _reference: &crate::SecretReference,
    ) -> Result<SecretMaterial, TerraformCloudRunError> {
        Err(TerraformCloudRunError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Default)]
pub struct EnvironmentTerraformCloudCredentialResolver;

impl TerraformCloudCredentialResolver for EnvironmentTerraformCloudCredentialResolver {
    fn resolve(
        &self,
        _reference: &crate::SecretReference,
    ) -> Result<SecretMaterial, TerraformCloudRunError> {
        if env::var(TERRAFORM_CLOUD_NATIVE_GATE_ENVIRONMENT_VARIABLE)
            .ok()
            .as_deref()
            != Some("1")
        {
            return Err(TerraformCloudRunError::BlockedEnv);
        }
        let token = env::var(TERRAFORM_CLOUD_TOKEN_ENVIRONMENT_VARIABLE)
            .map_err(|_| TerraformCloudRunError::BlockedEnv)?;
        if token.trim().is_empty() || token.len() > MAX_IDENTIFIER_BYTES * 8 {
            return Err(TerraformCloudRunError::BlockedEnv);
        }
        Ok(SecretMaterial::new(token))
    }
}

#[derive(Clone)]
pub struct StaticTerraformCloudCredentialResolver {
    material: SecretMaterial,
}

impl fmt::Debug for StaticTerraformCloudCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticTerraformCloudCredentialResolver(<redacted>)")
    }
}

impl StaticTerraformCloudCredentialResolver {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            material: SecretMaterial::new(value),
        }
    }
}

impl TerraformCloudCredentialResolver for StaticTerraformCloudCredentialResolver {
    fn resolve(
        &self,
        _reference: &crate::SecretReference,
    ) -> Result<SecretMaterial, TerraformCloudRunError> {
        if self.material.as_str().trim().is_empty() {
            Err(TerraformCloudRunError::BlockedEnv)
        } else {
            Ok(self.material.clone())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerraformCloudRunProviderState {
    Disconnected,
    ReadOnlyAvailable,
    Recording,
    Fixture,
    Loopback,
    AuthorizationObscured404,
    RateLimited,
    BlockedEnv,
    Revoked,
    ProviderUnknown,
}

#[derive(Debug)]
pub struct TerraformCloudRunProvider<T, R>
where
    T: TerraformCloudRunTransport,
    R: TerraformCloudCredentialResolver,
{
    registration: TerraformCloudRunRegistration,
    transport: T,
    credentials: R,
    state: TerraformCloudRunProviderState,
    last_workspace: Option<WorkspaceDescription>,
    receipts: BTreeMap<Digest, RunReceipt>,
    run_fingerprints: BTreeMap<(Digest, crate::RunId), Digest>,
}

impl<T, R> TerraformCloudRunProvider<T, R>
where
    T: TerraformCloudRunTransport,
    R: TerraformCloudCredentialResolver,
{
    pub fn new(
        registration: TerraformCloudRunRegistration,
        transport: T,
        credentials: R,
    ) -> Result<Self, TerraformCloudRunError> {
        registration.validate()?;
        if registration.status != RegistrationStatus::Active {
            return Err(TerraformCloudRunError::RegistrationRevoked);
        }
        Ok(Self {
            registration,
            transport,
            credentials,
            state: TerraformCloudRunProviderState::Disconnected,
            last_workspace: None,
            receipts: BTreeMap::new(),
            run_fingerprints: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &TerraformCloudRunRegistration {
        &self.registration
    }

    pub fn state(&self) -> TerraformCloudRunProviderState {
        self.state
    }

    pub fn provenance(&self) -> ProviderProvenance {
        match self.state {
            TerraformCloudRunProviderState::BlockedEnv
            | TerraformCloudRunProviderState::Revoked => ProviderProvenance::BlockedEnv,
            TerraformCloudRunProviderState::Recording => ProviderProvenance::Recording,
            TerraformCloudRunProviderState::Fixture => ProviderProvenance::Fixture,
            TerraformCloudRunProviderState::Loopback => ProviderProvenance::Loopback,
            _ => self.transport.provenance(),
        }
    }

    pub fn native_status(&self) -> NativeStatus {
        NativeStatus::BlockedEnv
    }

    pub fn native_transport(&self) -> bool {
        self.provenance().is_native()
    }

    pub const fn native_connected(&self) -> bool {
        false
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn receipts(&self) -> &BTreeMap<Digest, RunReceipt> {
        &self.receipts
    }

    pub fn last_workspace(&self) -> Option<&WorkspaceDescription> {
        self.last_workspace.as_ref()
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, TerraformCloudRunError> {
        let revocation = self.registration.revoke()?;
        self.state = TerraformCloudRunProviderState::Revoked;
        Ok(revocation)
    }

    pub fn describe_workspace(&mut self) -> Result<WorkspaceDescription, TerraformCloudRunError> {
        self.ensure_active()?;
        let token = self.authenticate()?;
        let record = self
            .transport
            .describe_workspace(&token, &self.registration.scope)
            .map_err(|error| self.map_transport_error(error))?;
        if record.workspace_id != self.registration.scope.workspace
            || record.workspace_revision != self.registration.scope.workspace_revision
            || record.lock_identity != self.registration.scope.lock_identity
        {
            self.state = TerraformCloudRunProviderState::ProviderUnknown;
            return Err(TerraformCloudRunError::StaleWorkspace);
        }
        self.mark_available();
        let provenance = self.provenance();
        let native_transport = self.native_transport();
        let read_digest = crate::canonical_digest(&(
            &self.registration.scope,
            &record,
            provenance,
            native_transport,
        ));
        let description = WorkspaceDescription {
            scope: self.registration.scope.clone(),
            workspace_id: record.workspace_id,
            workspace_revision: record.workspace_revision,
            lock_identity: record.lock_identity,
            locked: record.locked,
            execution_mode: record.execution_mode,
            terraform_version: record.terraform_version,
            configuration_version: record.configuration_version,
            current_run: record.current_run,
            proposal_capable: !record.locked,
            provenance,
            native_transport,
            native_connected: false,
            read_digest,
        };
        description.validate()?;
        self.last_workspace = Some(description.clone());
        Ok(description)
    }

    pub fn read_run_evidence(&mut self) -> Result<RunEvidence, TerraformCloudRunError> {
        self.ensure_active()?;
        let token = self.authenticate()?;
        let evidence = self
            .transport
            .read_run_evidence(&token, &self.registration.scope)
            .map_err(|error| self.map_transport_error(error))?;
        self.ensure_scope(&evidence.scope)?;
        evidence.validate()?;
        if evidence.status == TerraformRunStatus::ProviderUnknown {
            self.state = TerraformCloudRunProviderState::ProviderUnknown;
        } else {
            self.mark_available();
        }
        Ok(evidence)
    }

    pub fn compile_configuration_proposal(
        &self,
        request: ConfigurationProposalRequest,
    ) -> Result<ConfigurationProposal, TerraformCloudRunError> {
        self.ensure_proposal_capable()?;
        self.ensure_scope(&request.scope)?;
        ConfigurationProposal::from_request(request)
    }

    pub fn compile_run_proposal(
        &self,
        request: RunProposalRequest,
    ) -> Result<RunProposal, TerraformCloudRunError> {
        self.ensure_proposal_capable()?;
        self.ensure_scope(&request.configuration_proposal.scope)?;
        RunProposal::from_request(request)
    }

    pub fn compile_apply_proposal(
        &self,
        request: ApplyProposalRequest,
    ) -> Result<ApplyProposal, TerraformCloudRunError> {
        self.ensure_proposal_capable()?;
        self.ensure_scope(&request.run_proposal.scope)?;
        ApplyProposal::from_request(request)
    }

    pub fn record_run_receipt(
        &mut self,
        evidence: &RunEvidence,
    ) -> Result<RunReceipt, TerraformCloudRunError> {
        self.ensure_active()?;
        self.ensure_scope(&evidence.scope)?;
        evidence.validate()?;
        if evidence.status == TerraformRunStatus::ProviderUnknown {
            self.state = TerraformCloudRunProviderState::ProviderUnknown;
        }
        let key = (evidence.scope.digest(), evidence.run_id.clone());
        if let Some(existing_fingerprint) = self.run_fingerprints.get(&key)
            && existing_fingerprint != &evidence.evidence_digest
        {
            return Err(TerraformCloudRunError::DuplicateFingerprint);
        }
        if let Some(receipt) = self.receipts.get(&evidence.evidence_digest) {
            receipt.validate_against(evidence, &self.registration.registration_digest)?;
            return Ok(receipt.clone());
        }
        let receipt =
            RunReceipt::from_evidence(evidence, self.registration.registration_digest.clone())?;
        self.run_fingerprints
            .insert(key, evidence.evidence_digest.clone());
        self.receipts
            .insert(evidence.evidence_digest.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn verify_run_result(
        &self,
        run_proposal: &RunProposal,
        evidence: &RunEvidence,
        receipt: &RunReceipt,
    ) -> Result<TerraformRunResultProposal, TerraformCloudRunError> {
        self.ensure_active()?;
        self.ensure_scope(&run_proposal.scope)?;
        run_proposal.validate()?;
        evidence.validate()?;
        self.ensure_scope(&evidence.scope)?;
        if run_proposal.scope != evidence.scope
            || run_proposal.configuration != evidence.configuration
            || run_proposal.mode != evidence.mode
            || run_proposal.auto_apply != evidence.auto_apply
            || run_proposal
                .run_id
                .as_ref()
                .is_some_and(|run| run != &evidence.run_id)
        {
            return Err(TerraformCloudRunError::StaleRun);
        }
        if evidence.status == TerraformRunStatus::ProviderUnknown {
            return Err(TerraformCloudRunError::ProviderUnknown);
        }
        let stored = self
            .receipts
            .get(&evidence.evidence_digest)
            .ok_or(TerraformCloudRunError::ReceiptNotRecorded)?;
        if stored != receipt {
            return Err(TerraformCloudRunError::ReceiptMismatch);
        }
        receipt.validate_against(evidence, &self.registration.registration_digest)?;
        TerraformRunResultProposal::from_receipt(
            run_proposal,
            receipt,
            self.provenance(),
            self.native_transport(),
        )
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<(), TerraformCloudRunError> {
        Err(TerraformCloudRunError::MutationForbidden { operation })
    }

    fn ensure_active(&self) -> Result<(), TerraformCloudRunError> {
        if self.registration.status != RegistrationStatus::Active
            || self.state == TerraformCloudRunProviderState::Revoked
        {
            Err(TerraformCloudRunError::RegistrationRevoked)
        } else {
            Ok(())
        }
    }

    fn ensure_proposal_capable(&self) -> Result<(), TerraformCloudRunError> {
        self.ensure_active()?;
        if self.state == TerraformCloudRunProviderState::ProviderUnknown {
            return Err(TerraformCloudRunError::ProviderUnknown);
        }
        if self
            .last_workspace
            .as_ref()
            .is_some_and(|workspace| !workspace.proposal_capable)
        {
            return Err(TerraformCloudRunError::StaleWorkspace);
        }
        Ok(())
    }

    fn authenticate(&mut self) -> Result<SecretMaterial, TerraformCloudRunError> {
        let token = self
            .credentials
            .resolve(&self.registration.secret_reference)
            .inspect_err(|_error| {
                self.state = TerraformCloudRunProviderState::BlockedEnv;
            })?;
        if token.as_str().trim().is_empty() {
            self.state = TerraformCloudRunProviderState::BlockedEnv;
            return Err(TerraformCloudRunError::BlockedEnv);
        }
        Ok(token)
    }

    fn mark_available(&mut self) {
        self.state = match self.transport.provenance() {
            ProviderProvenance::Recording => TerraformCloudRunProviderState::Recording,
            ProviderProvenance::Fixture => TerraformCloudRunProviderState::Fixture,
            ProviderProvenance::Loopback => TerraformCloudRunProviderState::Loopback,
            ProviderProvenance::BlockedEnv => TerraformCloudRunProviderState::BlockedEnv,
            ProviderProvenance::OfficialHttps => TerraformCloudRunProviderState::ReadOnlyAvailable,
        };
    }

    fn map_transport_error(
        &mut self,
        error: TerraformCloudTransportError,
    ) -> TerraformCloudRunError {
        self.state = match error {
            TerraformCloudTransportError::NotFoundOrUnauthorized => {
                TerraformCloudRunProviderState::AuthorizationObscured404
            }
            TerraformCloudTransportError::RateLimited { .. } => {
                TerraformCloudRunProviderState::RateLimited
            }
            TerraformCloudTransportError::ServerUnavailable
            | TerraformCloudTransportError::Timeout
            | TerraformCloudTransportError::Network
            | TerraformCloudTransportError::Decode
            | TerraformCloudTransportError::ResponseTooLarge
            | TerraformCloudTransportError::Unauthorized
            | TerraformCloudTransportError::Conflict
            | TerraformCloudTransportError::UnprocessableEntity
            | TerraformCloudTransportError::InvalidConfiguration => self.state,
        };
        error.into()
    }

    fn ensure_scope(&self, scope: &TerraformCloudScope) -> Result<(), TerraformCloudRunError> {
        let registered = &self.registration.scope;
        if registered.hostname != scope.hostname
            || registered.organization != scope.organization
            || registered.terraform_project != scope.terraform_project
            || registered.workspace != scope.workspace
            || registered.workspace_revision != scope.workspace_revision
            || registered.lock_identity != scope.lock_identity
            || registered.hartevo_project != scope.hartevo_project
            || registered.mission != scope.mission
            || registered.work_product != scope.work_product
            || !resource_fence_matches(&registered.resources, &scope.resources)
        {
            return Err(TerraformCloudRunError::ScopeMismatch);
        }
        Ok(())
    }
}

fn resource_fence_matches(
    registered: &crate::TerraformResourceFence,
    candidate: &crate::TerraformResourceFence,
) -> bool {
    registered
        .configuration_version
        .as_ref()
        .is_none_or(|id| candidate.configuration_version.as_ref() == Some(id))
        && registered
            .run
            .as_ref()
            .is_none_or(|id| candidate.run.as_ref() == Some(id))
        && registered
            .plan
            .as_ref()
            .is_none_or(|id| candidate.plan.as_ref() == Some(id))
        && registered
            .apply
            .as_ref()
            .is_none_or(|id| candidate.apply.as_ref() == Some(id))
        && registered
            .policy_evaluation
            .as_ref()
            .is_none_or(|id| candidate.policy_evaluation.as_ref() == Some(id))
        && registered
            .policy_set
            .as_ref()
            .is_none_or(|id| candidate.policy_set.as_ref() == Some(id))
}

pub type TerraformCloudRunRecordingProvider = crate::TerraformCloudRunProvider<
    crate::RecordingTerraformCloudTransport,
    StaticTerraformCloudCredentialResolver,
>;
