use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use crate::{
    BLOCKED_ENV, BlockedEnvCredentialResolver, BlockedEnvTransport, Digest, EvidenceProvenance,
    MAX_PAGES, PulumiAuditEvidence, PulumiCloudTransport, PulumiCloudTransportError,
    PulumiCredentialResolver, PulumiDeploymentApiRecord, PulumiDeploymentEvidence,
    PulumiDeploymentReceipt, PulumiDeploymentResultError, PulumiDeploymentResultProposal,
    PulumiDeploymentResultRegistration, PulumiDeploymentScope, PulumiDeploymentStatus,
    PulumiStackApiRecord, PulumiStackDescription, PulumiUpdateEvidence, ReadOnlyAuthority,
    RegistrationRevocation, RegistrationState, ResultVerificationStatus, SecretMaterial,
    SecretReference,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PulumiCloudProviderState {
    Disconnected,
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
    AccessLost,
    AuthorizationObscured404,
    Conflict,
    RateLimited,
    Timeout,
    Unavailable,
    ProviderUnknown,
    Revoked,
}

use serde::{Deserialize, Serialize};

/// Typed Pulumi Cloud provider seam. It can only read bounded metadata through
/// `PulumiCloudTransport`; mutation and native authority are intentionally not
/// represented by this type.
pub struct PulumiCloudProvider<T = BlockedEnvTransport, R = BlockedEnvCredentialResolver>
where
    T: PulumiCloudTransport,
    R: PulumiCredentialResolver,
{
    registration: PulumiDeploymentResultRegistration,
    secret_reference: SecretReference,
    scope: PulumiDeploymentScope,
    transport: T,
    credentials: R,
    state: PulumiCloudProviderState,
    last_stack: Option<PulumiStackDescription>,
    receipts: BTreeMap<Digest, PulumiDeploymentReceipt>,
    deployment_fingerprints: BTreeMap<(Digest, String), Digest>,
}

impl<T, R> fmt::Debug for PulumiCloudProvider<T, R>
where
    T: PulumiCloudTransport,
    R: PulumiCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PulumiCloudProvider")
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("scope_digest", &self.registration.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("transport", &self.transport)
            .field("state", &self.state)
            .field("receipt_count", &self.receipts.len())
            .finish_non_exhaustive()
    }
}

impl<T, R> PulumiCloudProvider<T, R>
where
    T: PulumiCloudTransport,
    R: PulumiCredentialResolver,
{
    pub fn new(
        registration: PulumiDeploymentResultRegistration,
        secret_reference: SecretReference,
        transport: T,
        credentials: R,
    ) -> Result<Self, PulumiDeploymentResultError> {
        if registration.state != RegistrationState::Active {
            return Err(PulumiDeploymentResultError::RegistrationRevoked);
        }
        let scope = registration.scope.clone();
        registration.validate(&scope, &secret_reference)?;
        let scope_digest = registration.scope_digest.clone();
        if secret_reference.is_revoked()
            || secret_reference.scope_digest() != Some(&scope_digest)
            || secret_reference.reference_digest() != &registration.secret_reference_digest
            || secret_reference.credential_revision() != registration.credential_revision
        {
            return Err(PulumiDeploymentResultError::AuthScopeMismatch);
        }
        Ok(Self {
            registration,
            secret_reference,
            transport,
            credentials,
            scope,
            state: PulumiCloudProviderState::Disconnected,
            last_stack: None,
            receipts: BTreeMap::new(),
            deployment_fingerprints: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &PulumiDeploymentResultRegistration {
        &self.registration
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn scope(&self) -> &PulumiDeploymentScope {
        &self.scope
    }

    pub fn state(&self) -> PulumiCloudProviderState {
        self.state
    }

    pub fn provenance(&self) -> EvidenceProvenance {
        match self.state {
            PulumiCloudProviderState::BlockedEnv | PulumiCloudProviderState::Revoked => {
                EvidenceProvenance::BlockedEnv
            }
            PulumiCloudProviderState::Recording => EvidenceProvenance::Recording,
            PulumiCloudProviderState::Fixture => EvidenceProvenance::Fixture,
            PulumiCloudProviderState::Loopback => EvidenceProvenance::Loopback,
            PulumiCloudProviderState::AccessLost
            | PulumiCloudProviderState::AuthorizationObscured404
            | PulumiCloudProviderState::Conflict
            | PulumiCloudProviderState::RateLimited
            | PulumiCloudProviderState::Timeout
            | PulumiCloudProviderState::Unavailable
            | PulumiCloudProviderState::ProviderUnknown
            | PulumiCloudProviderState::Disconnected => self.transport.provenance(),
        }
    }

    pub const fn native_status(&self) -> &'static str {
        BLOCKED_ENV
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

    pub fn last_stack(&self) -> Option<&PulumiStackDescription> {
        self.last_stack.as_ref()
    }

    pub fn receipts(&self) -> &BTreeMap<Digest, PulumiDeploymentReceipt> {
        &self.receipts
    }

    pub fn describe_stack(
        &mut self,
    ) -> Result<PulumiStackDescription, PulumiDeploymentResultError> {
        self.ensure_active()?;
        let credential = self.authenticate()?;
        let result = self
            .transport
            .describe_stack(&credential, &self.scope_from_registration());
        let record = result.map_err(|error| self.map_transport_error(error))?;
        self.validate_stack_record(&record)?;
        let description = PulumiStackDescription::from_record(
            self.scope_from_registration(),
            record,
            self.transport.provenance(),
        )?;
        self.mark_available();
        self.last_stack = Some(description.clone());
        Ok(description)
    }

    pub fn read_deployment_evidence(
        &mut self,
    ) -> Result<PulumiDeploymentEvidence, PulumiDeploymentResultError> {
        self.ensure_active()?;
        let scope = self.scope_from_registration();
        let credential = self.authenticate()?;
        let result = self.transport.read_deployment(&credential, &scope);
        let record = result.map_err(|error| self.map_transport_error(error))?;
        Self::validate_deployment_identity(&record, &scope)?;

        let (updates, update_pages) = self.read_updates(&credential, &scope)?;
        let policy = self
            .transport
            .read_policy(&credential, &scope)
            .map_err(|error| self.map_transport_error(error))?;
        policy.validate()?;
        if policy.policy_digest != scope.policy.policy_digest
            || policy.policy_revision != scope.policy.policy_revision
        {
            return Err(PulumiDeploymentResultError::PolicyDrift);
        }
        let (audit, audit_pages) = self.read_audit(&credential, &scope)?;
        let pages_read = update_pages
            .checked_add(audit_pages)
            .and_then(|pages| pages.checked_add(1))
            .ok_or(PulumiDeploymentResultError::InvalidEvidence)?;
        let provenance = self.transport.provenance();
        let evidence = PulumiDeploymentEvidence::from_parts(
            scope, record, updates, policy, audit, pages_read, provenance,
        )?;
        if evidence.status == PulumiDeploymentStatus::ProviderUnknown
            || evidence.operation == crate::PulumiOperation::ProviderUnknown
            || evidence.policy.status == crate::PulumiPolicyStatus::ProviderUnknown
        {
            self.state = PulumiCloudProviderState::ProviderUnknown;
        } else {
            self.mark_available();
        }
        Ok(evidence)
    }

    pub fn read_deployment(
        &mut self,
    ) -> Result<PulumiDeploymentEvidence, PulumiDeploymentResultError> {
        self.read_deployment_evidence()
    }

    pub fn record_deployment_receipt(
        &mut self,
        evidence: &PulumiDeploymentEvidence,
    ) -> Result<PulumiDeploymentReceipt, PulumiDeploymentResultError> {
        self.ensure_active()?;
        let scope = self.scope_from_registration();
        evidence.validate_against_scope(&scope)?;
        let key = (scope.digest(), evidence.deployment_id.clone());
        if let Some(existing) = self.deployment_fingerprints.get(&key)
            && existing != &evidence.evidence_digest
        {
            return Err(PulumiDeploymentResultError::DuplicateDeployment);
        }
        if let Some(receipt) = self.receipts.get(&evidence.evidence_digest) {
            receipt.validate()?;
            return Ok(receipt.clone());
        }
        let receipt = PulumiDeploymentReceipt::from_evidence(
            evidence,
            self.registration.registration_digest.clone(),
        )?;
        self.deployment_fingerprints
            .insert(key, evidence.evidence_digest.clone());
        self.receipts
            .insert(evidence.evidence_digest.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn verify_deployment_result(
        &self,
        evidence: &PulumiDeploymentEvidence,
        receipt: &PulumiDeploymentReceipt,
    ) -> Result<PulumiDeploymentResultProposal, PulumiDeploymentResultError> {
        self.ensure_active()?;
        let scope = self.scope_from_registration();
        evidence.validate_against_scope(&scope)?;
        receipt.validate()?;
        if receipt.scope_digest != scope.digest()
            || receipt.deployment_id != evidence.deployment_id
            || receipt.evidence_digest != evidence.evidence_digest
            || receipt.registration_digest != self.registration.registration_digest
            || self.receipts.get(&receipt.evidence_digest) != Some(receipt)
        {
            return Err(PulumiDeploymentResultError::ReceiptMismatch);
        }
        if evidence.truncated {
            return Err(PulumiDeploymentResultError::IncompleteEvidence);
        }
        let verification_status = match evidence.status {
            PulumiDeploymentStatus::ProviderUnknown
            | PulumiDeploymentStatus::NotStarted
            | PulumiDeploymentStatus::Accepted
            | PulumiDeploymentStatus::Running => {
                if evidence.status == PulumiDeploymentStatus::ProviderUnknown
                    || evidence.policy.status == crate::PulumiPolicyStatus::ProviderUnknown
                {
                    ResultVerificationStatus::ProviderUnknown
                } else {
                    ResultVerificationStatus::Pending
                }
            }
            PulumiDeploymentStatus::Succeeded => {
                if evidence.policy.passed() {
                    ResultVerificationStatus::Verified
                } else {
                    ResultVerificationStatus::Failed
                }
            }
            PulumiDeploymentStatus::Failed
            | PulumiDeploymentStatus::Skipped
            | PulumiDeploymentStatus::Cancelled
            | PulumiDeploymentStatus::Drift
            | PulumiDeploymentStatus::Partial => ResultVerificationStatus::Failed,
        };
        PulumiDeploymentResultProposal::from_verified(evidence, receipt, verification_status)
    }

    pub fn compile_deployment_result_proposal(
        &self,
        evidence: &PulumiDeploymentEvidence,
        receipt: &PulumiDeploymentReceipt,
    ) -> Result<PulumiDeploymentResultProposal, PulumiDeploymentResultError> {
        self.verify_deployment_result(evidence, receipt)
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, PulumiDeploymentResultError> {
        self.ensure_active()?;
        let revocation = self.registration.revoke("operator-requested-revocation")?;
        self.state = PulumiCloudProviderState::Revoked;
        Ok(revocation)
    }

    pub fn reject_mutation(
        &self,
        operation: &'static str,
    ) -> Result<(), PulumiDeploymentResultError> {
        let _ = ReadOnlyAuthority;
        Err(PulumiDeploymentResultError::MutationForbidden { operation })
    }

    fn ensure_active(&self) -> Result<(), PulumiDeploymentResultError> {
        if !self.registration.is_active() || self.state == PulumiCloudProviderState::Revoked {
            Err(PulumiDeploymentResultError::RegistrationRevoked)
        } else {
            self.registration
                .validate(&self.scope, &self.secret_reference)?;
            if self.secret_reference.is_revoked() {
                Err(PulumiDeploymentResultError::CredentialRevoked)
            } else {
                Ok(())
            }
        }
    }

    fn scope_from_registration(&self) -> PulumiDeploymentScope {
        // The provider's registration digest is intentionally opaque, so the
        // scope is retained by the service/provider boundary through the
        // validated stack description. For normal construction this value is
        // recovered from the registration binding below.
        self.scope.clone()
    }

    fn authenticate(&mut self) -> Result<SecretMaterial, PulumiDeploymentResultError> {
        let credential = self
            .credentials
            .resolve(&self.secret_reference)
            .map_err(|error| {
                if matches!(
                    error,
                    PulumiDeploymentResultError::Transport(PulumiCloudTransportError::BlockedEnv)
                ) {
                    self.state = PulumiCloudProviderState::BlockedEnv;
                }
                error
            })?;
        if credential.as_str().trim().is_empty() {
            self.state = PulumiCloudProviderState::BlockedEnv;
            return Err(PulumiCloudTransportError::BlockedEnv.into());
        }
        Ok(credential)
    }

    fn validate_stack_record(
        &self,
        record: &PulumiStackApiRecord,
    ) -> Result<(), PulumiDeploymentResultError> {
        record.validate()?;
        let scope = self.scope_from_registration();
        if record.organization != scope.organization {
            return Err(PulumiDeploymentResultError::OrganizationMismatch);
        }
        if record.organization_revision != scope.organization_revision {
            return Err(PulumiDeploymentResultError::StaleStackRevision);
        }
        if record.pulumi_project != scope.pulumi_project {
            return Err(PulumiDeploymentResultError::ProjectMismatch);
        }
        if record.pulumi_project_revision != scope.pulumi_project_revision {
            return Err(PulumiDeploymentResultError::StaleStackRevision);
        }
        if record.stack != scope.stack {
            return Err(PulumiDeploymentResultError::StackMismatch);
        }
        if record.stack_revision != scope.stack_revision {
            return Err(PulumiDeploymentResultError::StaleStackRevision);
        }
        if record.permissions != scope.permissions {
            return Err(PulumiDeploymentResultError::PermissionDrift);
        }
        Ok(())
    }

    fn validate_deployment_identity(
        record: &PulumiDeploymentApiRecord,
        scope: &PulumiDeploymentScope,
    ) -> Result<(), PulumiDeploymentResultError> {
        record.validate()?;
        if record.organization != scope.organization {
            return Err(PulumiDeploymentResultError::OrganizationMismatch);
        }
        if record.pulumi_project != scope.pulumi_project {
            return Err(PulumiDeploymentResultError::ProjectMismatch);
        }
        if record.stack != scope.stack {
            return Err(PulumiDeploymentResultError::StackMismatch);
        }
        if record.deployment_id != scope.deployment_id {
            return Err(PulumiDeploymentResultError::DeploymentMismatch);
        }
        if record.source != scope.source {
            if record.source.commit_sha != scope.source.commit_sha {
                return Err(PulumiDeploymentResultError::CommitMismatch);
            }
            return Err(PulumiDeploymentResultError::SourceMismatch);
        }
        if record.update != scope.update {
            return Err(PulumiDeploymentResultError::UpdateMismatch);
        }
        Ok(())
    }

    fn read_updates(
        &mut self,
        credential: &SecretMaterial,
        scope: &PulumiDeploymentScope,
    ) -> Result<(Vec<PulumiUpdateEvidence>, u8), PulumiDeploymentResultError> {
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen = BTreeSet::new();
        let mut pages: u8 = 0;
        loop {
            if usize::from(pages) >= MAX_PAGES {
                return Err(PulumiCloudTransportError::PaginationExceeded.into());
            }
            pages = pages.saturating_add(1);
            let result = self
                .transport
                .read_updates(credential, scope, cursor.as_deref());
            let page = result.map_err(|error| self.map_transport_error(error))?;
            page.validate()?;
            if items.len().saturating_add(page.items.len()) > crate::MAX_UPDATES {
                return Err(PulumiDeploymentResultError::InvalidPage);
            }
            items.extend(page.items);
            match page.next_cursor {
                Some(next) => {
                    if !seen.insert(next.clone()) {
                        return Err(PulumiCloudTransportError::PaginationLoop.into());
                    }
                    cursor = Some(next);
                }
                None => break,
            }
        }
        Ok((items, pages))
    }

    fn read_audit(
        &mut self,
        credential: &SecretMaterial,
        scope: &PulumiDeploymentScope,
    ) -> Result<(Vec<PulumiAuditEvidence>, u8), PulumiDeploymentResultError> {
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen = BTreeSet::new();
        let mut pages: u8 = 0;
        loop {
            if usize::from(pages) >= MAX_PAGES {
                return Err(PulumiCloudTransportError::PaginationExceeded.into());
            }
            pages = pages.saturating_add(1);
            let result = self
                .transport
                .read_audit(credential, scope, cursor.as_deref());
            let page = result.map_err(|error| self.map_transport_error(error))?;
            page.validate()?;
            if items.len().saturating_add(page.items.len()) > crate::MAX_AUDIT_ENTRIES {
                return Err(PulumiDeploymentResultError::InvalidPage);
            }
            items.extend(page.items);
            match page.next_cursor {
                Some(next) => {
                    if !seen.insert(next.clone()) {
                        return Err(PulumiCloudTransportError::PaginationLoop.into());
                    }
                    cursor = Some(next);
                }
                None => break,
            }
        }
        Ok((items, pages))
    }

    fn mark_available(&mut self) {
        self.state = match self.transport.provenance() {
            EvidenceProvenance::Recording => PulumiCloudProviderState::Recording,
            EvidenceProvenance::Fixture => PulumiCloudProviderState::Fixture,
            EvidenceProvenance::Loopback => PulumiCloudProviderState::Loopback,
            EvidenceProvenance::BlockedEnv => PulumiCloudProviderState::BlockedEnv,
        };
    }

    fn map_transport_error(
        &mut self,
        error: PulumiCloudTransportError,
    ) -> PulumiDeploymentResultError {
        self.state = match &error {
            PulumiCloudTransportError::BlockedEnv => PulumiCloudProviderState::BlockedEnv,
            PulumiCloudTransportError::Conflict => PulumiCloudProviderState::Conflict,
            PulumiCloudTransportError::RateLimited { .. } => PulumiCloudProviderState::RateLimited,
            PulumiCloudTransportError::Timeout => PulumiCloudProviderState::Timeout,
            PulumiCloudTransportError::ServerUnavailable
            | PulumiCloudTransportError::Network
            | PulumiCloudTransportError::Decode
            | PulumiCloudTransportError::ResponseTooLarge
            | PulumiCloudTransportError::HttpStatus {
                status: 500..=599, ..
            } => PulumiCloudProviderState::Unavailable,
            PulumiCloudTransportError::HttpStatus {
                status: 401 | 403, ..
            }
            | PulumiCloudTransportError::Unauthorized
            | PulumiCloudTransportError::Forbidden => PulumiCloudProviderState::AccessLost,
            PulumiCloudTransportError::HttpStatus { status: 404, .. }
            | PulumiCloudTransportError::NotFoundOrUnauthorized => {
                PulumiCloudProviderState::AuthorizationObscured404
            }
            PulumiCloudTransportError::HttpStatus { status: 409, .. } => {
                PulumiCloudProviderState::Conflict
            }
            PulumiCloudTransportError::HttpStatus { status: 429, .. } => {
                PulumiCloudProviderState::RateLimited
            }
            PulumiCloudTransportError::FixtureMissing
            | PulumiCloudTransportError::PaginationLoop
            | PulumiCloudTransportError::PaginationExceeded
            | PulumiCloudTransportError::HttpStatus { .. } => self.state,
        };
        error.into()
    }
}

impl PulumiCloudProvider<BlockedEnvTransport, BlockedEnvCredentialResolver> {
    pub fn blocked_env(
        registration: PulumiDeploymentResultRegistration,
        secret_reference: SecretReference,
    ) -> Result<Self, PulumiDeploymentResultError> {
        Self::new(
            registration,
            secret_reference,
            BlockedEnvTransport,
            BlockedEnvCredentialResolver,
        )
    }
}
