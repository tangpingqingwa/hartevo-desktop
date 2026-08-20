//! Read-only Security Command Center provider and reversible registration.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use hartevo_plugin_runtime::PluginError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::transport::{
    FindingsGroupResponse, FindingsListResponse, GcpSecurityCenterTransport,
    SecurityCenterHttpRequest, TransportError,
};
use crate::{
    Digest, EvidenceAuthority, EvidenceDigests, EvidenceOperation, EvidenceProjection,
    FindingRecord, FindingsGroupEvidence, FindingsGroupReceipt, FindingsGroupRequest,
    FindingsGroupVerification, FindingsListEvidence, FindingsListReceipt, FindingsListRequest,
    FindingsListVerification, GcpSecurityCenterPermission, GcpSecurityCenterScope, ModelError,
    PluginVersion, ProviderErrorEvidence, ProviderErrorKind, ProviderRevision, SecretReference,
    TransportProvenance, contract_digest, digest_serializable, plugin_version,
};

const REDACTED_FIELDS: [&str; 4] = [
    "sourceProperties",
    "securityMarks",
    "PII",
    "rawProviderPayload",
];

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpSecurityCenterError {
    #[error("invalid GCP Security Command Center input: {0}")]
    Model(#[from] ModelError),
    #[error("GCP Security Command Center transport failed: {0}")]
    Transport(#[from] TransportError),
    #[error("plugin runtime rejected the contribution: {0}")]
    Plugin(#[from] PluginError),
    #[error("the GCP Security Command Center registration is revoked")]
    RegistrationRevoked,
    #[error("the registration does not match the provider or proposal")]
    RegistrationMismatch,
    #[error("the Project/Mission/Work Product scope does not match")]
    ScopeMismatch,
    #[error("the permission snapshot does not match")]
    PermissionMismatch,
    #[error("the provider revision does not match")]
    ProviderRevisionMismatch,
    #[error("the proposal digest or binding was tampered")]
    ProposalTampered,
    #[error("the provider response was tampered or outside the safe projection")]
    ResponseTampered,
    #[error("the evidence digest or binding was tampered")]
    EvidenceTampered,
    #[error("the recorded receipt digest or binding was tampered")]
    ReceiptTampered,
    #[error("findings.group requires the optional group permission")]
    GroupPermissionMissing,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpSecurityCenterRegistrationRequest {
    pub provider_revision: ProviderRevision,
    pub registration_revision: u64,
    pub permission_digest: Digest,
}

impl GcpSecurityCenterRegistrationRequest {
    pub fn new(
        provider_revision: ProviderRevision,
        registration_revision: u64,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        if registration_revision == 0 {
            return Err(ModelError::MustBePositive {
                field: "registration revision",
            });
        }
        Ok(Self {
            provider_revision,
            registration_revision,
            permission_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct GcpSecurityCenterRegistration {
    pub plugin_version: PluginVersion,
    pub contract_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: u64,
    pub registration_digest: Digest,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
}

impl GcpSecurityCenterRegistration {
    pub fn new(
        scope: &GcpSecurityCenterScope,
        secret: &SecretReference,
        provider_revision: ProviderRevision,
        registration_revision: u64,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if registration_revision == 0 {
            return Err(ModelError::MustBePositive {
                field: "registration revision",
            });
        }
        let mut registration = Self {
            plugin_version: plugin_version(),
            contract_digest: contract_digest(),
            provider_revision,
            permission_digest: scope.permissions().digest.clone(),
            scope_digest: scope.scope_digest().clone(),
            secret_reference_digest: secret.digest(),
            registration_revision,
            registration_digest: Digest::from_text("pending-registration-digest"),
            state: RegistrationState::Active,
            reversible: true,
            revocable: true,
        };
        registration.registration_digest = registration.calculate_digest();
        Ok(registration)
    }

    pub fn calculate_digest(&self) -> Digest {
        digest_serializable(&RegistrationDigestView {
            plugin_version: self.plugin_version,
            contract_digest: &self.contract_digest,
            provider_revision: &self.provider_revision,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registration_revision: self.registration_revision,
            reversible: self.reversible,
            revocable: self.revocable,
        })
    }

    pub fn validate(&self, scope: &GcpSecurityCenterScope) -> Result<(), GcpSecurityCenterError> {
        scope.validate()?;
        if self.plugin_version != plugin_version()
            || self.contract_digest != contract_digest()
            || self.permission_digest != *scope.permissions().digest()
            || self.scope_digest != *scope.scope_digest()
            || !self.reversible
            || !self.revocable
            || self.registration_revision == 0
            || self.registration_digest != self.calculate_digest()
        {
            return Err(GcpSecurityCenterError::RegistrationMismatch);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), GcpSecurityCenterError> {
        if self.state == RegistrationState::Revoked {
            return Err(GcpSecurityCenterError::RegistrationRevoked);
        }
        self.state = RegistrationState::Revoked;
        Ok(())
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }
}

#[derive(Serialize)]
struct RegistrationDigestView<'a> {
    plugin_version: PluginVersion,
    contract_digest: &'a Digest,
    provider_revision: &'a ProviderRevision,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: u64,
    reversible: bool,
    revocable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingsListProposal {
    pub request: FindingsListRequest,
    pub registration_digest: Digest,
    pub registration_revision: u64,
    pub provider_revision: ProviderRevision,
    pub proposal_digest: Digest,
}

impl FindingsListProposal {
    fn new(request: FindingsListRequest, registration: &GcpSecurityCenterRegistration) -> Self {
        let proposal_digest = digest_serializable(&ProposalDigestView {
            operation: EvidenceOperation::FindingsList,
            request_digest: request.request_digest(),
            registration_digest: &registration.registration_digest,
            registration_revision: registration.registration_revision,
            provider_revision: &registration.provider_revision,
        });
        Self {
            request,
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            provider_revision: registration.provider_revision.clone(),
            proposal_digest,
        }
    }

    fn calculate_digest(&self) -> Digest {
        digest_serializable(&ProposalDigestView {
            operation: EvidenceOperation::FindingsList,
            request_digest: self.request.request_digest(),
            registration_digest: &self.registration_digest,
            registration_revision: self.registration_revision,
            provider_revision: &self.provider_revision,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingsGroupProposal {
    pub request: FindingsGroupRequest,
    pub registration_digest: Digest,
    pub registration_revision: u64,
    pub provider_revision: ProviderRevision,
    pub proposal_digest: Digest,
}

impl FindingsGroupProposal {
    fn new(request: FindingsGroupRequest, registration: &GcpSecurityCenterRegistration) -> Self {
        let proposal_digest = digest_serializable(&ProposalDigestView {
            operation: EvidenceOperation::FindingsGroup,
            request_digest: request.request_digest(),
            registration_digest: &registration.registration_digest,
            registration_revision: registration.registration_revision,
            provider_revision: &registration.provider_revision,
        });
        Self {
            request,
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            provider_revision: registration.provider_revision.clone(),
            proposal_digest,
        }
    }

    fn calculate_digest(&self) -> Digest {
        digest_serializable(&ProposalDigestView {
            operation: EvidenceOperation::FindingsGroup,
            request_digest: self.request.request_digest(),
            registration_digest: &self.registration_digest,
            registration_revision: self.registration_revision,
            provider_revision: &self.provider_revision,
        })
    }
}

#[derive(Serialize)]
struct ProposalDigestView<'a> {
    operation: EvidenceOperation,
    request_digest: &'a Digest,
    registration_digest: &'a Digest,
    registration_revision: u64,
    provider_revision: &'a ProviderRevision,
}

pub struct GcpSecurityCenterProvider<T> {
    scope: GcpSecurityCenterScope,
    secret: SecretReference,
    registration: GcpSecurityCenterRegistration,
    transport: T,
}

impl<T: fmt::Debug> fmt::Debug for GcpSecurityCenterProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpSecurityCenterProvider")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("secret", &self.secret)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: GcpSecurityCenterTransport> GcpSecurityCenterProvider<T> {
    pub fn new(
        scope: GcpSecurityCenterScope,
        secret: SecretReference,
        transport: T,
        provider_revision: impl Into<String>,
        registration_revision: u64,
    ) -> Result<Self, GcpSecurityCenterError> {
        let provider_revision = ProviderRevision::new(provider_revision)?;
        let registration = GcpSecurityCenterRegistration::new(
            &scope,
            &secret,
            provider_revision,
            registration_revision,
        )?;
        Ok(Self {
            scope,
            secret,
            registration,
            transport,
        })
    }

    pub fn new_with_registration_request(
        scope: GcpSecurityCenterScope,
        secret: SecretReference,
        transport: T,
        request: GcpSecurityCenterRegistrationRequest,
    ) -> Result<Self, GcpSecurityCenterError> {
        if request.permission_digest != *scope.permissions().digest() {
            return Err(GcpSecurityCenterError::PermissionMismatch);
        }
        Self::new(
            scope,
            secret,
            transport,
            request.provider_revision.as_str(),
            request.registration_revision,
        )
    }

    pub fn scope(&self) -> &GcpSecurityCenterScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn registration(&self) -> &GcpSecurityCenterRegistration {
        &self.registration
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub fn revoke(&mut self) -> Result<(), GcpSecurityCenterError> {
        self.registration.revoke()
    }

    pub fn propose_findings_list(
        &self,
        request: FindingsListRequest,
    ) -> Result<FindingsListProposal, GcpSecurityCenterError> {
        self.ensure_active()?;
        self.ensure_request_scope(request.scope_digest())?;
        Ok(FindingsListProposal::new(request, &self.registration))
    }

    pub fn propose_findings_group(
        &self,
        request: FindingsGroupRequest,
    ) -> Result<FindingsGroupProposal, GcpSecurityCenterError> {
        self.ensure_active()?;
        if !self
            .scope
            .permissions()
            .contains(GcpSecurityCenterPermission::FindingsGroup)
        {
            return Err(GcpSecurityCenterError::GroupPermissionMissing);
        }
        self.ensure_request_scope(request.scope_digest())?;
        Ok(FindingsGroupProposal::new(request, &self.registration))
    }

    pub fn read_findings_list(
        &mut self,
        proposal: &FindingsListProposal,
        requested_at: DateTime<Utc>,
    ) -> Result<FindingsListEvidence, GcpSecurityCenterError> {
        self.validate_list_proposal(proposal)?;
        let request =
            SecurityCenterHttpRequest::for_findings_list(&proposal.request, requested_at)?;
        match self.transport.list_findings(&request) {
            Ok(response) => self.project_list_response(proposal, response),
            Err(TransportError::ResponseTampered) => Err(GcpSecurityCenterError::ResponseTampered),
            Err(error) => Ok(self.error_list_evidence(proposal, &error)),
        }
    }

    pub fn read_findings_group(
        &mut self,
        proposal: &FindingsGroupProposal,
        requested_at: DateTime<Utc>,
    ) -> Result<FindingsGroupEvidence, GcpSecurityCenterError> {
        self.validate_group_proposal(proposal)?;
        let request =
            SecurityCenterHttpRequest::for_findings_group(&proposal.request, requested_at)?;
        match self.transport.group_findings(&request) {
            Ok(response) => self.project_group_response(proposal, response),
            Err(TransportError::ResponseTampered) => Err(GcpSecurityCenterError::ResponseTampered),
            Err(error) => Ok(self.error_group_evidence(proposal, &error)),
        }
    }

    pub fn record_findings_list(
        &self,
        evidence: &FindingsListEvidence,
    ) -> Result<FindingsListReceipt, GcpSecurityCenterError> {
        self.ensure_active()?;
        self.validate_list_evidence(evidence)?;
        FindingsListReceipt::new(evidence.clone())
            .map_err(|_| GcpSecurityCenterError::EvidenceTampered)
    }

    pub fn record_findings_group(
        &self,
        evidence: &FindingsGroupEvidence,
    ) -> Result<FindingsGroupReceipt, GcpSecurityCenterError> {
        self.ensure_active()?;
        self.validate_group_evidence(evidence)?;
        FindingsGroupReceipt::new(evidence.clone())
            .map_err(|_| GcpSecurityCenterError::EvidenceTampered)
    }

    pub fn verify_findings_list(
        &self,
        receipt: &FindingsListReceipt,
    ) -> Result<FindingsListVerification, GcpSecurityCenterError> {
        self.ensure_active()?;
        receipt
            .validate_integrity()
            .map_err(|_| GcpSecurityCenterError::ReceiptTampered)?;
        self.validate_list_evidence(&receipt.evidence)?;
        FindingsListVerification::from_receipt(receipt)
            .map_err(|_| GcpSecurityCenterError::ReceiptTampered)
    }

    pub fn verify_findings_group(
        &self,
        receipt: &FindingsGroupReceipt,
    ) -> Result<FindingsGroupVerification, GcpSecurityCenterError> {
        self.ensure_active()?;
        receipt
            .validate_integrity()
            .map_err(|_| GcpSecurityCenterError::ReceiptTampered)?;
        self.validate_group_evidence(&receipt.evidence)?;
        FindingsGroupVerification::from_receipt(receipt)
            .map_err(|_| GcpSecurityCenterError::ReceiptTampered)
    }

    fn ensure_active(&self) -> Result<(), GcpSecurityCenterError> {
        if !self.registration.is_active() {
            return Err(GcpSecurityCenterError::RegistrationRevoked);
        }
        self.registration.validate(&self.scope)
    }

    fn ensure_request_scope(
        &self,
        request_scope_digest: &Digest,
    ) -> Result<(), GcpSecurityCenterError> {
        if request_scope_digest != self.scope.scope_digest() {
            return Err(GcpSecurityCenterError::ScopeMismatch);
        }
        Ok(())
    }

    fn validate_list_proposal(
        &self,
        proposal: &FindingsListProposal,
    ) -> Result<(), GcpSecurityCenterError> {
        self.ensure_active()?;
        self.ensure_request_scope(proposal.request.scope_digest())?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.registration_revision
            || proposal.provider_revision != self.registration.provider_revision
            || proposal.proposal_digest != proposal.calculate_digest()
        {
            return Err(GcpSecurityCenterError::ProposalTampered);
        }
        Ok(())
    }

    fn validate_group_proposal(
        &self,
        proposal: &FindingsGroupProposal,
    ) -> Result<(), GcpSecurityCenterError> {
        self.ensure_active()?;
        if !self
            .scope
            .permissions()
            .contains(GcpSecurityCenterPermission::FindingsGroup)
        {
            return Err(GcpSecurityCenterError::GroupPermissionMissing);
        }
        self.ensure_request_scope(proposal.request.scope_digest())?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.registration_revision
            || proposal.provider_revision != self.registration.provider_revision
            || proposal.proposal_digest != proposal.calculate_digest()
        {
            return Err(GcpSecurityCenterError::ProposalTampered);
        }
        Ok(())
    }

    fn project_list_response(
        &self,
        proposal: &FindingsListProposal,
        response: FindingsListResponse,
    ) -> Result<FindingsListEvidence, GcpSecurityCenterError> {
        response
            .validate()
            .map_err(|_| GcpSecurityCenterError::ResponseTampered)?;
        if response.provider_revision != self.registration.provider_revision {
            return Err(GcpSecurityCenterError::ProviderRevisionMismatch);
        }
        let mut ids = BTreeSet::new();
        for finding in &response.findings {
            finding
                .validate_against(&self.scope, proposal.request.filter())
                .map_err(|_| GcpSecurityCenterError::ResponseTampered)?;
            if !ids.insert(finding.finding_id.clone()) {
                return Err(GcpSecurityCenterError::ResponseTampered);
            }
        }
        let mut errors = Vec::new();
        let has_next_page = response.next_page_token().is_some();
        let response_partial = response.partial;
        let warning_count = response.warning_count;
        let response_digest = response.response_digest.clone();
        let mut findings = response.findings;
        let mut projection = if response_partial {
            EvidenceProjection::Partial(crate::PartialReason::ProviderReportedPartial)
        } else if has_next_page {
            EvidenceProjection::Partial(crate::PartialReason::NextPage)
        } else if warning_count > 0 {
            EvidenceProjection::Partial(crate::PartialReason::ProviderWarning)
        } else {
            EvidenceProjection::Complete
        };
        if findings.len() > proposal.request.bounds().max_findings {
            findings.truncate(proposal.request.bounds().max_findings);
            projection = EvidenceProjection::Partial(crate::PartialReason::BoundExceeded);
            errors.push(ProviderErrorEvidence::new(
                ProviderErrorKind::BoundExceeded,
                false,
                false,
                false,
            ));
        }
        if warning_count > 0 {
            errors.push(ProviderErrorEvidence::new(
                ProviderErrorKind::InvalidResponse,
                false,
                false,
                false,
            ));
        }
        Ok(self.finish_list_evidence(
            proposal,
            projection,
            findings,
            errors,
            response_digest,
            has_next_page,
        ))
    }

    fn project_group_response(
        &self,
        proposal: &FindingsGroupProposal,
        response: FindingsGroupResponse,
    ) -> Result<FindingsGroupEvidence, GcpSecurityCenterError> {
        response
            .validate()
            .map_err(|_| GcpSecurityCenterError::ResponseTampered)?;
        if response.provider_revision != self.registration.provider_revision {
            return Err(GcpSecurityCenterError::ProviderRevisionMismatch);
        }
        let mut keys = BTreeSet::new();
        for group in &response.groups {
            group
                .validate()
                .map_err(|_| GcpSecurityCenterError::ResponseTampered)?;
            if group.group_by != proposal.request.group_by()
                || !keys.insert(digest_serializable(&group.key))
            {
                return Err(GcpSecurityCenterError::ResponseTampered);
            }
        }
        let mut errors = Vec::new();
        let has_next_page = response.next_page_token().is_some();
        let response_partial = response.partial;
        let warning_count = response.warning_count;
        let response_digest = response.response_digest.clone();
        let mut groups = response.groups;
        let mut projection = if response_partial {
            EvidenceProjection::Partial(crate::PartialReason::ProviderReportedPartial)
        } else if has_next_page {
            EvidenceProjection::Partial(crate::PartialReason::NextPage)
        } else if warning_count > 0 {
            EvidenceProjection::Partial(crate::PartialReason::ProviderWarning)
        } else {
            EvidenceProjection::Complete
        };
        if groups.len() > proposal.request.bounds().max_groups {
            groups.truncate(proposal.request.bounds().max_groups);
            projection = EvidenceProjection::Partial(crate::PartialReason::BoundExceeded);
            errors.push(ProviderErrorEvidence::new(
                ProviderErrorKind::BoundExceeded,
                false,
                false,
                false,
            ));
        }
        if warning_count > 0 {
            errors.push(ProviderErrorEvidence::new(
                ProviderErrorKind::InvalidResponse,
                false,
                false,
                false,
            ));
        }
        Ok(self.finish_group_evidence(
            proposal,
            projection,
            groups,
            errors,
            response_digest,
            has_next_page,
        ))
    }

    fn error_list_evidence(
        &self,
        proposal: &FindingsListProposal,
        error: &TransportError,
    ) -> FindingsListEvidence {
        let (projection, kind, access_lost, blocked_env, retryable) =
            classify_transport_error(error);
        self.finish_list_evidence(
            proposal,
            projection,
            Vec::new(),
            vec![ProviderErrorEvidence::new(
                kind,
                retryable,
                access_lost,
                blocked_env,
            )],
            digest_serializable(&format!("transport-error:{error}")),
            false,
        )
    }

    fn error_group_evidence(
        &self,
        proposal: &FindingsGroupProposal,
        error: &TransportError,
    ) -> FindingsGroupEvidence {
        let (projection, kind, access_lost, blocked_env, retryable) =
            classify_transport_error(error);
        self.finish_group_evidence(
            proposal,
            projection,
            Vec::new(),
            vec![ProviderErrorEvidence::new(
                kind,
                retryable,
                access_lost,
                blocked_env,
            )],
            digest_serializable(&format!("transport-error:{error}")),
            false,
        )
    }

    fn finish_list_evidence(
        &self,
        proposal: &FindingsListProposal,
        projection: EvidenceProjection,
        findings: Vec<FindingRecord>,
        errors: Vec<ProviderErrorEvidence>,
        response_digest: Digest,
        has_next_page: bool,
    ) -> FindingsListEvidence {
        let permission_digest = self.scope.permissions().digest.clone();
        let scope_digest = self.scope.scope_digest().clone();
        let request_digest = proposal.request.request_digest().clone();
        let provider_revision = self.registration.provider_revision.clone();
        let digests = EvidenceDigests {
            plugin_version_digest: plugin_version().digest(),
            contract_digest: contract_digest(),
            provider_revision_digest: provider_revision.digest(),
            permission_digest: permission_digest.clone(),
            scope_digest: scope_digest.clone(),
            request_digest: request_digest.clone(),
            response_digest: response_digest.clone(),
            evidence_digest: Digest::from_text("pending-evidence-digest"),
        };
        let mut evidence = FindingsListEvidence {
            operation: EvidenceOperation::FindingsList,
            projection,
            classification: self.provenance(),
            findings,
            errors,
            redacted_fields: REDACTED_FIELDS.iter().map(ToString::to_string).collect(),
            has_next_page,
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.registration_revision,
            provider_revision,
            filter_digest: proposal.request.filter().digest(),
            page_digest: proposal.request.page().digest().clone(),
            request_digest,
            response_digest,
            scope_digest,
            permission_digest,
            digests,
            evidence_digest: Digest::from_text("pending-evidence-digest"),
            authority: EvidenceAuthority::layer1(),
        };
        evidence.evidence_digest = evidence.calculate_evidence_digest();
        evidence.digests.evidence_digest = evidence.evidence_digest.clone();
        evidence
    }

    fn finish_group_evidence(
        &self,
        proposal: &FindingsGroupProposal,
        projection: EvidenceProjection,
        groups: Vec<crate::GroupFindingBucket>,
        errors: Vec<ProviderErrorEvidence>,
        response_digest: Digest,
        has_next_page: bool,
    ) -> FindingsGroupEvidence {
        let permission_digest = self.scope.permissions().digest.clone();
        let scope_digest = self.scope.scope_digest().clone();
        let request_digest = proposal.request.request_digest().clone();
        let provider_revision = self.registration.provider_revision.clone();
        let digests = EvidenceDigests {
            plugin_version_digest: plugin_version().digest(),
            contract_digest: contract_digest(),
            provider_revision_digest: provider_revision.digest(),
            permission_digest: permission_digest.clone(),
            scope_digest: scope_digest.clone(),
            request_digest: request_digest.clone(),
            response_digest: response_digest.clone(),
            evidence_digest: Digest::from_text("pending-evidence-digest"),
        };
        let mut evidence = FindingsGroupEvidence {
            operation: EvidenceOperation::FindingsGroup,
            projection,
            classification: self.provenance(),
            groups,
            errors,
            redacted_fields: REDACTED_FIELDS.iter().map(ToString::to_string).collect(),
            has_next_page,
            group_by: proposal.request.group_by(),
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.registration_revision,
            provider_revision,
            filter_digest: proposal.request.filter().digest(),
            page_digest: proposal.request.page().digest().clone(),
            request_digest,
            response_digest,
            scope_digest,
            permission_digest,
            digests,
            evidence_digest: Digest::from_text("pending-evidence-digest"),
            authority: EvidenceAuthority::layer1(),
        };
        evidence.evidence_digest = evidence.calculate_evidence_digest();
        evidence.digests.evidence_digest = evidence.evidence_digest.clone();
        evidence
    }

    fn validate_list_evidence(
        &self,
        evidence: &FindingsListEvidence,
    ) -> Result<(), GcpSecurityCenterError> {
        evidence
            .validate_integrity()
            .map_err(|_| GcpSecurityCenterError::EvidenceTampered)?;
        if evidence.registration_digest != self.registration.registration_digest
            || evidence.registration_revision != self.registration.registration_revision
            || evidence.scope_digest != *self.scope.scope_digest()
            || evidence.permission_digest != *self.scope.permissions().digest()
            || evidence.provider_revision != self.registration.provider_revision
            || evidence.authority != EvidenceAuthority::layer1()
            || evidence.classification.is_native()
            || evidence.classification.is_connected()
        {
            return Err(GcpSecurityCenterError::RegistrationMismatch);
        }
        Ok(())
    }

    fn validate_group_evidence(
        &self,
        evidence: &FindingsGroupEvidence,
    ) -> Result<(), GcpSecurityCenterError> {
        evidence
            .validate_integrity()
            .map_err(|_| GcpSecurityCenterError::EvidenceTampered)?;
        if evidence.registration_digest != self.registration.registration_digest
            || evidence.registration_revision != self.registration.registration_revision
            || evidence.scope_digest != *self.scope.scope_digest()
            || evidence.permission_digest != *self.scope.permissions().digest()
            || evidence.provider_revision != self.registration.provider_revision
            || evidence.authority != EvidenceAuthority::layer1()
            || evidence.classification.is_native()
            || evidence.classification.is_connected()
        {
            return Err(GcpSecurityCenterError::RegistrationMismatch);
        }
        Ok(())
    }
}

fn classify_transport_error(
    error: &TransportError,
) -> (EvidenceProjection, ProviderErrorKind, bool, bool, bool) {
    match error {
        TransportError::Unauthorized | TransportError::Forbidden | TransportError::NotFound => (
            EvidenceProjection::AccessLost,
            match error {
                TransportError::Unauthorized => ProviderErrorKind::Unauthorized,
                TransportError::Forbidden => ProviderErrorKind::Forbidden,
                _ => ProviderErrorKind::NotFound,
            },
            true,
            false,
            false,
        ),
        TransportError::BlockedEnv => (
            EvidenceProjection::ProviderUnknown,
            ProviderErrorKind::BlockedEnv,
            false,
            true,
            false,
        ),
        TransportError::RateLimited => (
            EvidenceProjection::ProviderUnknown,
            ProviderErrorKind::RateLimited,
            false,
            false,
            true,
        ),
        TransportError::Timeout => (
            EvidenceProjection::ProviderUnknown,
            ProviderErrorKind::Timeout,
            false,
            false,
            true,
        ),
        TransportError::Server => (
            EvidenceProjection::ProviderUnknown,
            ProviderErrorKind::Server,
            false,
            false,
            true,
        ),
        TransportError::NoFixtureResponse => (
            EvidenceProjection::ProviderUnknown,
            ProviderErrorKind::NoFixtureResponse,
            false,
            false,
            false,
        ),
        TransportError::ResponseTooLarge => (
            EvidenceProjection::Partial(crate::PartialReason::BoundExceeded),
            ProviderErrorKind::BoundExceeded,
            false,
            false,
            false,
        ),
        TransportError::GroupUnsupported => (
            EvidenceProjection::ProviderUnknown,
            ProviderErrorKind::InvalidResponse,
            false,
            false,
            false,
        ),
        TransportError::ResponseTampered | TransportError::InvalidResponse => (
            EvidenceProjection::ProviderUnknown,
            ProviderErrorKind::InvalidResponse,
            false,
            false,
            false,
        ),
    }
}
