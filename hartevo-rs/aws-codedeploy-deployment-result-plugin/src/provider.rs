use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use crate::{
    API_REVISION, CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, PROVIDER_VERSION,
    SERVICE_ID, canonical_digest,
    error::{AwsCodeDeployDeploymentResultError, AwsCodeDeployTransportError},
    model::{
        CodeDeployDeploymentEvidence, CodeDeployDeploymentPage, CodeDeployDeploymentReceipt,
        CodeDeployDeploymentResultProposal, CodeDeployDeploymentStatus, CodeDeployReadRequest,
        CodeDeployRegistration, CodeDeployResultState, CodeDeployScope, CodeDeployTargetPage,
        CodeDeployTargetRecord, CodeDeployTargetStatus, Digest, MAX_DEPLOYMENTS, MAX_PAGES,
        MAX_RESPONSE_BYTES, MAX_TARGETS, ProviderProvenance, RegistrationRevocation,
        RegistrationStatus, ResultVerificationStatus, SecretReference,
    },
    transport::{
        CodeDeployGetDeploymentRequest, CodeDeployListDeploymentTargetsRequest,
        CodeDeployListDeploymentsRequest, CodeDeployTransport,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeDeployProviderIdentity {
    pub provider_id: String,
    pub version: crate::PluginVersion,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
}

impl CodeDeployProviderIdentity {
    pub fn for_provenance(provenance: ProviderProvenance) -> Self {
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            version: PROVIDER_VERSION,
            api_revision: API_REVISION.to_owned(),
            provider_digest: crate::provider_digest(),
            api_digest: crate::api_digest(),
            provenance,
            connected: false,
            native: false,
        }
    }

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        if self.provider_id != PROVIDER_ID
            || self.version != PROVIDER_VERSION
            || self.api_revision != API_REVISION
            || self.provider_digest != crate::provider_digest()
            || self.api_digest != crate::api_digest()
            || self.connected
            || self.native
            || self.provenance.is_connected()
            || self.provenance.is_native()
        {
            return Err(AwsCodeDeployDeploymentResultError::ProviderDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodeDeployProviderState {
    Disconnected,
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
    Revoked,
    Created,
    Queued,
    InProgress,
    Baking,
    Ready,
    Succeeded,
    Failed,
    Stopped,
    Partial,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    NotFound,
}

/// Layer-1 CodeDeploy provider. The transport is deliberately generic and
/// contains no native credential or deployment-effect capability.
pub struct CodeDeployProvider<T>
where
    T: CodeDeployTransport,
{
    registration: CodeDeployRegistration,
    transport: T,
    state: CodeDeployProviderState,
    evidence_sequence: u64,
    receipts: BTreeMap<Digest, CodeDeployDeploymentReceipt>,
    evidence_fingerprints: BTreeMap<(Digest, Digest), Digest>,
    last_deployment_digest: Option<Digest>,
}

impl<T> fmt::Debug for CodeDeployProvider<T>
where
    T: CodeDeployTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodeDeployProvider")
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("state", &self.state)
            .field("evidence_sequence", &self.evidence_sequence)
            .field("receipt_count", &self.receipts.len())
            .field("last_deployment_digest", &self.last_deployment_digest)
            .finish_non_exhaustive()
    }
}

impl<T> CodeDeployProvider<T>
where
    T: CodeDeployTransport,
{
    pub fn new(
        registration: CodeDeployRegistration,
        transport: T,
    ) -> Result<Self, AwsCodeDeployDeploymentResultError> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsCodeDeployDeploymentResultError::RegistrationRevoked);
        }
        CodeDeployProviderIdentity::for_provenance(transport.provenance()).validate()?;
        Ok(Self {
            registration,
            transport,
            state: CodeDeployProviderState::Disconnected,
            evidence_sequence: 0,
            receipts: BTreeMap::new(),
            evidence_fingerprints: BTreeMap::new(),
            last_deployment_digest: None,
        })
    }

    pub fn registration(&self) -> &CodeDeployRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut CodeDeployRegistration {
        &mut self.registration
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn provider_identity(&self) -> CodeDeployProviderIdentity {
        CodeDeployProviderIdentity::for_provenance(self.transport.provenance())
    }

    pub fn provider_id(&self) -> &str {
        PROVIDER_ID
    }

    pub fn api_revision(&self) -> &str {
        API_REVISION
    }

    pub fn state(&self) -> CodeDeployProviderState {
        self.state
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub const fn native_transport(&self) -> bool {
        false
    }

    pub const fn native_connected(&self) -> bool {
        false
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.registration.secret_reference
    }

    pub fn receipts(&self) -> &BTreeMap<Digest, CodeDeployDeploymentReceipt> {
        &self.receipts
    }

    pub fn last_deployment_digest(&self) -> Option<&Digest> {
        self.last_deployment_digest.as_ref()
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, AwsCodeDeployDeploymentResultError> {
        let revocation = self.registration.revoke()?;
        self.state = CodeDeployProviderState::Revoked;
        Ok(revocation)
    }

    pub fn read_evidence(
        &mut self,
    ) -> Result<CodeDeployDeploymentEvidence, AwsCodeDeployDeploymentResultError> {
        let request = CodeDeployReadRequest::new(self.registration.scope.clone())?;
        self.read_deployment_evidence(&request)
    }

    #[allow(clippy::too_many_lines)]
    pub fn read_deployment_evidence(
        &mut self,
        request: &CodeDeployReadRequest,
    ) -> Result<CodeDeployDeploymentEvidence, AwsCodeDeployDeploymentResultError> {
        self.ensure_active()?;
        request.validate()?;
        self.ensure_scope(&request.scope)?;
        if request.scope.permissions.digest() != self.registration.scope.permissions.digest() {
            return Err(AwsCodeDeployDeploymentResultError::PermissionDrift);
        }

        let expected_scope_digest = self.registration.scope.digest();
        let expected_filter_digest = request.filter.filter_digest.clone();
        let mut deployment_cursor = None;
        let mut seen_deployment_cursors = BTreeSet::new();
        let mut deployment_ids = BTreeSet::new();
        let mut deployment_page_digests = Vec::new();
        let mut deployment_page_count = 0;
        let mut truncated = false;

        loop {
            if deployment_page_count >= request.max_pages {
                return Err(AwsCodeDeployDeploymentResultError::PageLimitExceeded);
            }
            let transport_request = CodeDeployListDeploymentsRequest::for_scope(
                &self.registration.scope,
                request.filter.clone(),
                deployment_cursor.clone(),
            );
            let page = self
                .transport
                .list_deployments(&transport_request)
                .map_err(|error| self.map_transport_error(error))?;
            Self::validate_deployment_page(&page, &expected_scope_digest, &expected_filter_digest)?;
            deployment_page_count += 1;
            truncated |= page.truncated;
            deployment_page_digests.push(page.page_digest.clone());
            for deployment in page.deployments {
                if !deployment_ids.insert(deployment.clone()) {
                    return Err(AwsCodeDeployDeploymentResultError::ReplayConflict);
                }
                if deployment != self.registration.scope.deployment {
                    return Err(AwsCodeDeployDeploymentResultError::ScopeMismatch);
                }
                if deployment_ids.len() > request.max_deployments {
                    return Err(AwsCodeDeployDeploymentResultError::ItemLimitExceeded);
                }
            }
            let Some(next_cursor) = page.next_cursor else {
                break;
            };
            if !seen_deployment_cursors.insert(next_cursor.digest().clone()) {
                return Err(AwsCodeDeployDeploymentResultError::PaginationLoop);
            }
            deployment_cursor = Some(next_cursor);
        }

        if !deployment_ids.contains(&self.registration.scope.deployment) {
            self.state = CodeDeployProviderState::NotFound;
            return Err(AwsCodeDeployDeploymentResultError::DeploymentNotFound);
        }

        let deployment_request =
            CodeDeployGetDeploymentRequest::for_scope(&self.registration.scope);
        let deployment = self
            .transport
            .get_deployment(&deployment_request)
            .map_err(|error| self.map_transport_error(error))?;
        deployment.validate_for(&self.registration.scope)?;
        let deployment_digest = deployment.digest();
        self.last_deployment_digest = Some(deployment_digest.clone());

        let mut target_cursor = None;
        let mut seen_target_cursors = BTreeSet::new();
        let mut target_ids = BTreeSet::new();
        let mut targets = Vec::new();
        let mut target_page_digests = Vec::new();
        let mut target_page_count = 0;
        loop {
            if target_page_count >= request.max_pages {
                return Err(AwsCodeDeployDeploymentResultError::PageLimitExceeded);
            }
            let transport_request = CodeDeployListDeploymentTargetsRequest::for_scope(
                &self.registration.scope,
                target_cursor.clone(),
            );
            let page = self
                .transport
                .list_deployment_targets(&transport_request)
                .map_err(|error| self.map_transport_error(error))?;
            self.validate_target_page(&page, &expected_scope_digest, &deployment_digest)?;
            target_page_count += 1;
            truncated |= page.truncated;
            target_page_digests.push(page.page_digest.clone());
            for target in page.targets {
                if !target_ids.insert(target.target.clone()) {
                    return Err(AwsCodeDeployDeploymentResultError::ReplayConflict);
                }
                if targets.len() >= request.max_targets {
                    return Err(AwsCodeDeployDeploymentResultError::ItemLimitExceeded);
                }
                targets.push(target);
            }
            let Some(next_cursor) = page.next_cursor else {
                break;
            };
            if !seen_target_cursors.insert(next_cursor.digest().clone()) {
                return Err(AwsCodeDeployDeploymentResultError::PaginationLoop);
            }
            target_cursor = Some(next_cursor);
        }

        self.evidence_sequence = self
            .evidence_sequence
            .checked_add(1)
            .ok_or(AwsCodeDeployDeploymentResultError::EvidenceTampered)?;
        let state = result_state(deployment.status, &targets);
        let mut evidence = CodeDeployDeploymentEvidence {
            scope: self.registration.scope.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            plugin_version_digest: Digest::from_serializable(&PLUGIN_VERSION),
            contract_digest: crate::contract_digest(),
            provider_digest: crate::provider_digest(),
            permission_digest: self.registration.permission_digest.clone(),
            scope_digest: expected_scope_digest,
            deployment,
            targets,
            deployment_page_count,
            target_page_count,
            deployment_page_digests,
            target_page_digests,
            state,
            provenance: self.provenance(),
            native_transport: false,
            native_connected: false,
            truncated,
            observed_sequence: self.evidence_sequence,
            evidence_digest: Digest::pending(),
        };
        evidence.evidence_digest = evidence.computed_digest();
        evidence.validate()?;
        self.set_state(state);
        Ok(evidence)
    }

    pub fn compile_deployment_result_proposal(
        &self,
        evidence: &CodeDeployDeploymentEvidence,
    ) -> Result<CodeDeployDeploymentResultProposal, AwsCodeDeployDeploymentResultError> {
        self.ensure_active()?;
        evidence.validate()?;
        if evidence.registration_digest != self.registration.registration_digest {
            return Err(AwsCodeDeployDeploymentResultError::ReceiptMismatch);
        }
        CodeDeployDeploymentResultProposal::from_evidence(
            evidence,
            self.registration.registration_digest.clone(),
        )
    }

    pub fn record_deployment_receipt(
        &mut self,
        evidence: &CodeDeployDeploymentEvidence,
    ) -> Result<CodeDeployDeploymentReceipt, AwsCodeDeployDeploymentResultError> {
        self.ensure_active()?;
        evidence.validate()?;
        if evidence.registration_digest != self.registration.registration_digest {
            return Err(AwsCodeDeployDeploymentResultError::ReceiptMismatch);
        }
        if evidence.truncated {
            return Err(AwsCodeDeployDeploymentResultError::IncompleteEvidence);
        }
        let fingerprint_key = (evidence.scope.digest(), evidence.deployment.digest());
        if let Some(previous) = self.evidence_fingerprints.get(&fingerprint_key)
            && previous != &evidence.evidence_digest
        {
            return Err(AwsCodeDeployDeploymentResultError::DuplicateEvidence);
        }
        if let Some(previous) = self.receipts.get(&evidence.evidence_digest) {
            previous.validate_against(evidence, &self.registration.registration_digest)?;
            return Ok(previous.clone());
        }
        let receipt = CodeDeployDeploymentReceipt::from_evidence(
            evidence,
            self.registration.registration_digest.clone(),
        )?;
        self.evidence_fingerprints
            .insert(fingerprint_key, evidence.evidence_digest.clone());
        self.receipts
            .insert(evidence.evidence_digest.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn verify_deployment_result(
        &self,
        proposal: &CodeDeployDeploymentResultProposal,
        evidence: &CodeDeployDeploymentEvidence,
        receipt: &CodeDeployDeploymentReceipt,
    ) -> Result<CodeDeployDeploymentResultProposal, AwsCodeDeployDeploymentResultError> {
        self.ensure_active()?;
        evidence.validate()?;
        proposal.validate_for_registration(&self.registration.registration_digest)?;
        receipt.validate_against(evidence, &self.registration.registration_digest)?;
        if proposal.scope != evidence.scope
            || proposal.evidence_digest != evidence.evidence_digest
            || proposal.result_digest != proposal.computed_digest()
        {
            return Err(AwsCodeDeployDeploymentResultError::ReceiptMismatch);
        }
        if !self.receipts.contains_key(&evidence.evidence_digest) {
            return Err(AwsCodeDeployDeploymentResultError::ReceiptNotRecorded);
        }
        Ok(proposal.clone())
    }

    pub fn verify(
        &self,
        proposal: &CodeDeployDeploymentResultProposal,
        evidence: &CodeDeployDeploymentEvidence,
        receipt: &CodeDeployDeploymentReceipt,
    ) -> Result<CodeDeployDeploymentResultProposal, AwsCodeDeployDeploymentResultError> {
        self.verify_deployment_result(proposal, evidence, receipt)
    }

    pub fn reject_write(
        &self,
        operation: &'static str,
    ) -> Result<(), AwsCodeDeployDeploymentResultError> {
        Err(AwsCodeDeployDeploymentResultError::MutationForbidden { operation })
    }

    fn ensure_active(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        if self.registration.status != RegistrationStatus::Active {
            return Err(AwsCodeDeployDeploymentResultError::RegistrationRevoked);
        }
        self.registration.validate()
    }

    fn ensure_scope(
        &self,
        scope: &CodeDeployScope,
    ) -> Result<(), AwsCodeDeployDeploymentResultError> {
        if scope != &self.registration.scope {
            Err(AwsCodeDeployDeploymentResultError::ScopeMismatch)
        } else {
            Ok(())
        }
    }

    fn validate_deployment_page(
        page: &CodeDeployDeploymentPage,
        expected_scope_digest: &Digest,
        expected_filter_digest: &Digest,
    ) -> Result<(), AwsCodeDeployDeploymentResultError> {
        page.validate()?;
        if &page.scope_digest != expected_scope_digest {
            return Err(AwsCodeDeployDeploymentResultError::ScopeMismatch);
        }
        if &page.filter_digest != expected_filter_digest {
            return Err(AwsCodeDeployDeploymentResultError::EvidenceTampered);
        }
        if page.response_bytes > MAX_RESPONSE_BYTES || page.deployments.len() > MAX_DEPLOYMENTS {
            return Err(AwsCodeDeployDeploymentResultError::ItemLimitExceeded);
        }
        Ok(())
    }

    fn validate_target_page(
        &self,
        page: &CodeDeployTargetPage,
        expected_scope_digest: &Digest,
        expected_deployment_digest: &Digest,
    ) -> Result<(), AwsCodeDeployDeploymentResultError> {
        page.validate()?;
        if &page.scope_digest != expected_scope_digest {
            return Err(AwsCodeDeployDeploymentResultError::ScopeMismatch);
        }
        if &page.deployment_digest != expected_deployment_digest {
            return Err(AwsCodeDeployDeploymentResultError::ReplayConflict);
        }
        if page.response_bytes > MAX_RESPONSE_BYTES || page.targets.len() > MAX_TARGETS {
            return Err(AwsCodeDeployDeploymentResultError::ItemLimitExceeded);
        }
        for target in &page.targets {
            target.validate_for(&self.registration.scope)?;
        }
        Ok(())
    }

    fn map_transport_error(
        &mut self,
        error: AwsCodeDeployTransportError,
    ) -> AwsCodeDeployDeploymentResultError {
        self.state = match error {
            AwsCodeDeployTransportError::BlockedEnv => CodeDeployProviderState::BlockedEnv,
            AwsCodeDeployTransportError::AccessLoss => CodeDeployProviderState::AccessLoss,
            AwsCodeDeployTransportError::NotFound => CodeDeployProviderState::NotFound,
            AwsCodeDeployTransportError::Throttled => CodeDeployProviderState::Throttled,
            AwsCodeDeployTransportError::PaginationLoop => CodeDeployProviderState::ProviderUnknown,
            AwsCodeDeployTransportError::Conflict
            | AwsCodeDeployTransportError::Malformed(_)
            | AwsCodeDeployTransportError::ResponseTooLarge
            | AwsCodeDeployTransportError::NetworkUnavailable
            | AwsCodeDeployTransportError::Timeout
            | AwsCodeDeployTransportError::UnexpectedOperation => self.state,
        };
        error.into()
    }

    fn set_state(&mut self, state: CodeDeployResultState) {
        self.state = match state {
            CodeDeployResultState::Created => CodeDeployProviderState::Created,
            CodeDeployResultState::Queued => CodeDeployProviderState::Queued,
            CodeDeployResultState::InProgress => CodeDeployProviderState::InProgress,
            CodeDeployResultState::Baking => CodeDeployProviderState::Baking,
            CodeDeployResultState::Ready => CodeDeployProviderState::Ready,
            CodeDeployResultState::Succeeded => CodeDeployProviderState::Succeeded,
            CodeDeployResultState::Failed => CodeDeployProviderState::Failed,
            CodeDeployResultState::Stopped => CodeDeployProviderState::Stopped,
            CodeDeployResultState::Partial => CodeDeployProviderState::Partial,
            CodeDeployResultState::NotFound => CodeDeployProviderState::NotFound,
            CodeDeployResultState::AccessLoss => CodeDeployProviderState::AccessLoss,
            CodeDeployResultState::Throttled => CodeDeployProviderState::Throttled,
            CodeDeployResultState::ProviderUnknown | CodeDeployResultState::RegistrationRevoked => {
                CodeDeployProviderState::ProviderUnknown
            }
        };
    }
}

fn result_state(
    status: CodeDeployDeploymentStatus,
    targets: &[CodeDeployTargetRecord],
) -> CodeDeployResultState {
    if targets
        .iter()
        .any(|target| target.status == CodeDeployTargetStatus::Failed)
    {
        return CodeDeployResultState::Failed;
    }
    if status == CodeDeployDeploymentStatus::Succeeded
        && !targets.is_empty()
        && targets.iter().all(|target| target.status.is_terminal())
        && targets
            .iter()
            .all(|target| target.status == CodeDeployTargetStatus::Succeeded)
    {
        return CodeDeployResultState::Succeeded;
    }
    match status {
        CodeDeployDeploymentStatus::Created => CodeDeployResultState::Created,
        CodeDeployDeploymentStatus::Queued => CodeDeployResultState::Queued,
        CodeDeployDeploymentStatus::InProgress => CodeDeployResultState::InProgress,
        CodeDeployDeploymentStatus::Baking => CodeDeployResultState::Baking,
        CodeDeployDeploymentStatus::Ready => CodeDeployResultState::Ready,
        CodeDeployDeploymentStatus::Succeeded => CodeDeployResultState::Partial,
        CodeDeployDeploymentStatus::Failed => CodeDeployResultState::Failed,
        CodeDeployDeploymentStatus::Stopped => CodeDeployResultState::Stopped,
        CodeDeployDeploymentStatus::Unknown => CodeDeployResultState::ProviderUnknown,
    }
}

pub type AwsCodeDeployProvider<T> = CodeDeployProvider<T>;
pub type AwsCodeDeployDeploymentResultProvider<T> = CodeDeployProvider<T>;
pub type ProviderProvenanceType = ProviderProvenance;
pub type VerificationStatus = ResultVerificationStatus;

const _: (&str, &str, &str, &str) = (PLUGIN_ID, CONTRACT_VERSION, SERVICE_ID, PROVIDER_ID);
const _: usize = MAX_PAGES + MAX_DEPLOYMENTS + MAX_TARGETS;
const _: fn(&CodeDeployDeploymentResultProposal) -> Digest = canonical_digest;
