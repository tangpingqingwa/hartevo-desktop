use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::model::{
    ApprovalProjection, ChangeProjection, ProviderRevision, ServiceNowScopeReceipt, SysId,
};
use crate::service::{RegistrationId, RegistrationStatus, ServiceNowRegistration};
use crate::{FieldName, Result, ServiceNowChangeError, canonical_json_digest, is_sha256};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalOperation {
    Create,
    Update,
    SubmitForApproval,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CorrelationBinding {
    pub field: FieldName,
    pub value_digest: String,
    pub exact_readback: bool,
}

impl CorrelationBinding {
    pub fn new(
        field: FieldName,
        value_digest: impl Into<String>,
        exact_readback: bool,
    ) -> Result<Self> {
        let binding = Self {
            field,
            value_digest: value_digest.into(),
            exact_readback,
        };
        if !is_sha256(&binding.value_digest) {
            return Err(ServiceNowChangeError::InvalidProposal(
                "correlation value must be a SHA-256 digest".into(),
            ));
        }
        Ok(binding)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FutureWriteGate {
    pub configured_correlation: bool,
    pub exact_readback: bool,
    pub ambiguous_response_fails_closed: bool,
    pub reason: Option<String>,
}

impl FutureWriteGate {
    pub fn from(
        mapping_correlation: Option<&FieldName>,
        requested: Option<&CorrelationBinding>,
    ) -> Self {
        match (mapping_correlation, requested) {
            (Some(expected), Some(binding)) if expected == &binding.field => Self {
                configured_correlation: true,
                exact_readback: binding.exact_readback,
                ambiguous_response_fails_closed: true,
                reason: if binding.exact_readback {
                    None
                } else {
                    Some("exact readback is required".into())
                },
            },
            (None, _) => Self {
                configured_correlation: false,
                exact_readback: false,
                ambiguous_response_fails_closed: true,
                reason: Some("mapping has no configured correlation field".into()),
            },
            (Some(_), None) => Self {
                configured_correlation: false,
                exact_readback: false,
                ambiguous_response_fails_closed: true,
                reason: Some("proposal omitted the configured correlation binding".into()),
            },
            (Some(_), Some(_)) => Self {
                configured_correlation: false,
                exact_readback: false,
                ambiguous_response_fails_closed: true,
                reason: Some("proposal correlation field differs from the mapping".into()),
            },
        }
    }

    pub fn is_safe_for_future_write(&self) -> bool {
        self.configured_correlation && self.exact_readback && self.ambiguous_response_fails_closed
    }

    pub fn ensure_safe(&self) -> Result<()> {
        if !self.configured_correlation {
            return Err(ServiceNowChangeError::MissingCorrelation);
        }
        if !self.exact_readback {
            return Err(ServiceNowChangeError::ExactReadbackRequired);
        }
        if !self.ambiguous_response_fails_closed {
            return Err(ServiceNowChangeError::AmbiguousWrite);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeProposalRequest {
    pub operation: ProposalOperation,
    pub field_digests: BTreeMap<FieldName, String>,
    pub expected_provider_revision: Option<ProviderRevision>,
    pub correlation: Option<CorrelationBinding>,
    pub target_change_sys_id: Option<SysId>,
}

impl ChangeProposalRequest {
    pub fn new(operation: ProposalOperation) -> Self {
        Self {
            operation,
            field_digests: BTreeMap::new(),
            expected_provider_revision: None,
            correlation: None,
            target_change_sys_id: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeProposal {
    pub proposal_version: String,
    pub operation: ProposalOperation,
    pub registration_id: RegistrationId,
    pub scope: ServiceNowScopeReceipt,
    pub mapping_digest: String,
    pub schema_fingerprint: String,
    pub mission_scope_digest: String,
    pub target_change_sys_id: Option<SysId>,
    pub field_digests: BTreeMap<FieldName, String>,
    pub expected_provider_revision: Option<ProviderRevision>,
    pub correlation: Option<CorrelationBinding>,
    pub future_write_gate: FutureWriteGate,
    pub non_mutating: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub proposal_digest: String,
}

impl ChangeProposal {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        if self.proposal_version != "servicenow-change-proposal/v1"
            || !is_sha256(&self.mapping_digest)
            || !is_sha256(&self.schema_fingerprint)
            || !is_sha256(&self.mission_scope_digest)
            || self.mission_scope_digest != self.scope.mission.digest()
            || self.field_digests.values().any(|digest| !is_sha256(digest))
            || !self.non_mutating
            || self.connected
            || self.native
            || self.first_party
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(ServiceNowChangeError::InvalidProposal(
                "change proposal binding is invalid".into(),
            ));
        }
        if matches!(
            self.operation,
            ProposalOperation::Update | ProposalOperation::SubmitForApproval
        ) && self.target_change_sys_id.is_none()
        {
            return Err(ServiceNowChangeError::InvalidProposal(
                "update/submit proposal has no exact change sys_id".into(),
            ));
        }
        if self.operation == ProposalOperation::Create && self.target_change_sys_id.is_some() {
            return Err(ServiceNowChangeError::InvalidProposal(
                "create proposal cannot bind an existing sys_id".into(),
            ));
        }
        Ok(())
    }

    pub fn future_write_gate(&self) -> &FutureWriteGate {
        &self.future_write_gate
    }

    pub fn ensure_future_write_safe(&self) -> Result<()> {
        self.future_write_gate.ensure_safe()
    }

    fn calculate_digest(&self) -> String {
        let mut clone = self.clone();
        clone.proposal_digest.clear();
        canonical_json_digest(&clone).expect("change proposal serializable")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalProposalOperation {
    Observe,
    PrepareSubmission,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalProposalRequest {
    pub operation: ApprovalProposalOperation,
    pub expected_provider_revisions: BTreeMap<SysId, ProviderRevision>,
}

impl ApprovalProposalRequest {
    pub fn observe() -> Self {
        Self {
            operation: ApprovalProposalOperation::Observe,
            expected_provider_revisions: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalProposal {
    pub proposal_version: String,
    pub operation: ApprovalProposalOperation,
    pub registration_id: RegistrationId,
    pub scope: ServiceNowScopeReceipt,
    pub mapping_digest: String,
    pub schema_fingerprint: String,
    pub change_proposal_digest: String,
    pub approval_sys_ids: BTreeSet<SysId>,
    pub expected_provider_revisions: BTreeMap<SysId, ProviderRevision>,
    pub future_write_gate: FutureWriteGate,
    pub non_mutating: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub proposal_digest: String,
}

impl ApprovalProposal {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        if self.proposal_version != "servicenow-approval-proposal/v1"
            || !is_sha256(&self.mapping_digest)
            || !is_sha256(&self.schema_fingerprint)
            || !is_sha256(&self.change_proposal_digest)
            || self
                .expected_provider_revisions
                .keys()
                .any(|id| !self.approval_sys_ids.contains(id))
            || !self.non_mutating
            || self.connected
            || self.native
            || self.first_party
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(ServiceNowChangeError::InvalidProposal(
                "approval proposal binding is invalid".into(),
            ));
        }
        Ok(())
    }

    pub fn ensure_future_write_safe(&self) -> Result<()> {
        self.future_write_gate.ensure_safe()
    }

    fn calculate_digest(&self) -> String {
        let mut clone = self.clone();
        clone.proposal_digest.clear();
        canonical_json_digest(&clone).expect("approval proposal serializable")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeResultRequest {
    pub expected_change_revision: ProviderRevision,
    pub expected_approval_revisions: BTreeMap<SysId, ProviderRevision>,
    pub expected_canonical_state: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeResultProposal {
    pub proposal_version: String,
    pub registration_id: RegistrationId,
    pub scope: ServiceNowScopeReceipt,
    pub mapping_digest: String,
    pub schema_fingerprint: String,
    pub change_projection_digest: String,
    pub approval_projection_digests: BTreeMap<SysId, String>,
    pub change_provider_revision: ProviderRevision,
    pub approval_provider_revisions: BTreeMap<SysId, ProviderRevision>,
    pub canonical_state: String,
    pub candidate_only: bool,
    pub adopted_outcome: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub result_digest: String,
}

impl ChangeResultProposal {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        if self.proposal_version != "servicenow-change-result-proposal/v1"
            || !is_sha256(&self.mapping_digest)
            || !is_sha256(&self.schema_fingerprint)
            || !is_sha256(&self.change_projection_digest)
            || self
                .approval_projection_digests
                .values()
                .any(|digest| !is_sha256(digest))
            || !self.candidate_only
            || self.adopted_outcome
            || self.connected
            || self.native
            || self.first_party
            || self.result_digest != self.calculate_digest()
        {
            return Err(ServiceNowChangeError::InvalidProposal(
                "change result proposal binding is invalid".into(),
            ));
        }
        Ok(())
    }

    fn calculate_digest(&self) -> String {
        let mut clone = self.clone();
        clone.result_digest.clear();
        canonical_json_digest(&clone).expect("result proposal serializable")
    }
}

/// The Mission consumer is a proposal compiler only.  It does not own Mission
/// identity, consent, effects, receipts, verification, outcome, or provider
/// mutation authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MissionServiceNowChangeConsumer;

impl MissionServiceNowChangeConsumer {
    pub fn compile_change_proposal(
        &self,
        registration: &ServiceNowRegistration,
        request: ChangeProposalRequest,
    ) -> Result<ChangeProposal> {
        validate_active_registration(registration)?;
        let target = registration.scope.change.as_ref();
        match request.operation {
            ProposalOperation::Create if request.target_change_sys_id.is_some() => {
                return Err(ServiceNowChangeError::InvalidProposal(
                    "create proposal cannot bind an existing sys_id".into(),
                ));
            }
            ProposalOperation::Update | ProposalOperation::SubmitForApproval => {
                let target_id = request
                    .target_change_sys_id
                    .as_ref()
                    .or_else(|| target.map(|record| &record.sys_id));
                if target_id != target.map(|record| &record.sys_id) {
                    return Err(ServiceNowChangeError::RecordIdentityMismatch);
                }
            }
            ProposalOperation::Create => {}
        }
        if request.field_digests.is_empty() {
            return Err(ServiceNowChangeError::InvalidProposal(
                "proposal has no allowlisted field digests".into(),
            ));
        }
        if request.field_digests.iter().any(|(field, digest)| {
            !registration.mapping.proposal_field_allowed(field) || !is_sha256(digest)
        }) {
            return Err(ServiceNowChangeError::InvalidProposal(
                "proposal field is outside the digest-bound allowlist".into(),
            ));
        }
        if matches!(
            request.operation,
            ProposalOperation::Update | ProposalOperation::SubmitForApproval
        ) && request.expected_provider_revision.is_none()
        {
            return Err(ServiceNowChangeError::StaleProviderRevision);
        }
        if let Some(correlation) = &request.correlation
            && !registration
                .mapping
                .proposal_field_allowed(&correlation.field)
            && registration.mapping.change_fields.correlation.as_ref() != Some(&correlation.field)
        {
            return Err(ServiceNowChangeError::InvalidProposal(
                "correlation field is outside the mapping".into(),
            ));
        }
        let future_write_gate = FutureWriteGate::from(
            registration.mapping.change_fields.correlation.as_ref(),
            request.correlation.as_ref(),
        );
        let mut proposal = ChangeProposal {
            proposal_version: "servicenow-change-proposal/v1".into(),
            operation: request.operation,
            registration_id: registration.id.clone(),
            scope: registration.scope.receipt(),
            mapping_digest: registration.mapping.mapping_digest.clone(),
            schema_fingerprint: registration.mapping.schema_fingerprint.clone(),
            mission_scope_digest: registration.scope.mission.digest(),
            target_change_sys_id: match request.operation {
                ProposalOperation::Create => None,
                ProposalOperation::Update | ProposalOperation::SubmitForApproval => request
                    .target_change_sys_id
                    .or_else(|| target.map(|record| record.sys_id.clone())),
            },
            field_digests: request.field_digests,
            expected_provider_revision: request.expected_provider_revision,
            correlation: request.correlation,
            future_write_gate,
            non_mutating: true,
            connected: false,
            native: false,
            first_party: false,
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn compile_approval_proposal(
        &self,
        registration: &ServiceNowRegistration,
        change_proposal: &ChangeProposal,
        approvals: &[ApprovalProjection],
        request: ApprovalProposalRequest,
    ) -> Result<ApprovalProposal> {
        validate_active_registration(registration)?;
        change_proposal.validate()?;
        if change_proposal.registration_id != registration.id
            || change_proposal.mapping_digest != registration.mapping.mapping_digest
            || change_proposal.scope != registration.scope.receipt()
            || change_proposal.mission_scope_digest != registration.scope.mission.digest()
        {
            return Err(ServiceNowChangeError::ScopeMismatch);
        }
        let mut seen = BTreeSet::new();
        let mut revisions = BTreeMap::new();
        for approval in approvals {
            approval.validate()?;
            if approval.scope_digest() != registration.scope.digest()
                || approval.mapping_digest != registration.mapping.mapping_digest
                || !seen.insert(approval.sys_id.clone())
            {
                return Err(ServiceNowChangeError::ApprovalSetMismatch);
            }
            revisions.insert(approval.sys_id.clone(), approval.provider_revision.clone());
        }
        if seen != registration.scope.approval_sys_ids
            || (!request.expected_provider_revisions.is_empty()
                && request.expected_provider_revisions != revisions)
        {
            return Err(ServiceNowChangeError::ApprovalSetMismatch);
        }
        let mut proposal = ApprovalProposal {
            proposal_version: "servicenow-approval-proposal/v1".into(),
            operation: request.operation,
            registration_id: registration.id.clone(),
            scope: registration.scope.receipt(),
            mapping_digest: registration.mapping.mapping_digest.clone(),
            schema_fingerprint: registration.mapping.schema_fingerprint.clone(),
            change_proposal_digest: change_proposal.proposal_digest.clone(),
            approval_sys_ids: seen,
            expected_provider_revisions: revisions,
            future_write_gate: change_proposal.future_write_gate.clone(),
            non_mutating: true,
            connected: false,
            native: false,
            first_party: false,
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn compile_change_result_proposal(
        &self,
        registration: &ServiceNowRegistration,
        change: &ChangeProjection,
        approvals: &[ApprovalProjection],
        request: ChangeResultRequest,
    ) -> Result<ChangeResultProposal> {
        validate_active_registration(registration)?;
        change.validate()?;
        if change.scope_digest() != registration.scope.digest()
            || change.mapping_digest != registration.mapping.mapping_digest
            || change.schema_fingerprint != registration.mapping.schema_fingerprint
            || change.provider_revision != request.expected_change_revision
        {
            return Err(ServiceNowChangeError::StaleProviderRevision);
        }
        if request
            .expected_canonical_state
            .as_deref()
            .is_some_and(|expected| expected != change.canonical_state)
        {
            return Err(ServiceNowChangeError::StateMappingDrift);
        }
        let mut approval_digests = BTreeMap::new();
        let mut approval_revisions = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for approval in approvals {
            approval.validate()?;
            if approval.scope_digest() != registration.scope.digest()
                || approval.mapping_digest != registration.mapping.mapping_digest
                || !seen.insert(approval.sys_id.clone())
            {
                return Err(ServiceNowChangeError::ApprovalSetMismatch);
            }
            if request.expected_approval_revisions.get(&approval.sys_id)
                != Some(&approval.provider_revision)
            {
                return Err(ServiceNowChangeError::StaleProviderRevision);
            }
            approval_digests.insert(approval.sys_id.clone(), approval.digest());
            approval_revisions.insert(approval.sys_id.clone(), approval.provider_revision.clone());
        }
        if seen != registration.scope.approval_sys_ids
            || approval_revisions != request.expected_approval_revisions
        {
            return Err(ServiceNowChangeError::ApprovalSetMismatch);
        }
        let mut proposal = ChangeResultProposal {
            proposal_version: "servicenow-change-result-proposal/v1".into(),
            registration_id: registration.id.clone(),
            scope: registration.scope.receipt(),
            mapping_digest: registration.mapping.mapping_digest.clone(),
            schema_fingerprint: registration.mapping.schema_fingerprint.clone(),
            change_projection_digest: change.digest(),
            approval_projection_digests: approval_digests,
            change_provider_revision: change.provider_revision.clone(),
            approval_provider_revisions: approval_revisions,
            canonical_state: change.canonical_state.clone(),
            candidate_only: true,
            adopted_outcome: false,
            connected: false,
            native: false,
            first_party: false,
            result_digest: String::new(),
        };
        proposal.result_digest = proposal.calculate_digest();
        proposal.validate()?;
        Ok(proposal)
    }
}

fn validate_active_registration(registration: &ServiceNowRegistration) -> Result<()> {
    registration.validate()?;
    if registration.status != RegistrationStatus::Active {
        return Err(ServiceNowChangeError::RegistrationNotActive);
    }
    Ok(())
}

trait ProjectionBindingExt {
    fn scope_digest(&self) -> &str;
}

impl ProjectionBindingExt for ApprovalProjection {
    fn scope_digest(&self) -> &str {
        &self.scope_digest
    }
}

impl ProjectionBindingExt for ChangeProjection {
    fn scope_digest(&self) -> &str {
        &self.scope_digest
    }
}
