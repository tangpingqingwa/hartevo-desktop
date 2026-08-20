//! Bounded AWS Config read, proposal, recording, and verification service.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_CONFIG_CONTRACT_VERSION, AWS_CONFIG_PLUGIN_VERSION, contract_digest,
    model::{
        AwsConfigComplianceEvidence, AwsConfigReadOperation, AwsConfigReadRequest, AwsConfigScope,
        ComplianceEvaluation, ComplianceState, ConfigRuleName, Digest, EvaluationRevision,
        ModelError, PartialReason, PermissionFence, ProviderErrorEvidence, ProviderId,
        ProviderRevision, ResourceKey, Revision, SecretReference, TransportError,
        TransportProvenance, latest_evaluations, sort_evaluations,
    },
    provider::{
        AwsConfigProvider, AwsConfigProviderError, AwsConfigProviderIdentity, AwsConfigTransport,
        is_access_loss,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("AWS Config registration is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("AWS Config registration is already revoked")]
    AlreadyRevoked,
    #[error("AWS Config registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsConfigComplianceServiceError {
    #[error("AWS Config service model error: {0}")]
    Model(#[from] ModelError),
    #[error("AWS Config provider error: {0}")]
    Provider(#[from] AwsConfigProviderError),
    #[error("AWS Config registration is revoked")]
    RegistrationRevoked,
    #[error("AWS Config registration has drifted: {0}")]
    RegistrationDrift(String),
    #[error("AWS Config scope or permission fence mismatch: {0}")]
    ScopeMismatch(String),
    #[error("AWS Config evidence is stale or tampered")]
    EvidenceTampered,
    #[error("AWS Config proposal is stale or tampered")]
    ProposalTampered,
    #[error("AWS Config record is stale or tampered")]
    RecordTampered,
    #[error("AWS Config registration lifecycle error: {0}")]
    Registration(#[from] RegistrationError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvaluationFenceError {
    Scope(&'static str),
    StaleRuleRevision,
    StaleResourceRevision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsConfigCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub operations: [&'static str; 7],
    pub allowlisted_api_operations: [&'static str; 2],
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub raw_configuration_items: bool,
    pub certification_authority: bool,
    pub outcome_authority: bool,
}

impl AwsConfigCapabilities {
    pub const fn layer_one() -> Self {
        Self {
            service_id: crate::AWS_CONFIG_SERVICE_ID,
            provider_id: crate::AWS_CONFIG_PROVIDER_ID,
            operations: [
                "describe_capabilities",
                "register",
                "revoke_registration",
                "read_bounded",
                "propose",
                "record",
                "verify",
            ],
            allowlisted_api_operations: [
                "GetComplianceDetailsByConfigRule",
                "DescribeComplianceByResource",
            ],
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            external_writes: false,
            raw_configuration_items: false,
            certification_authority: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsConfigRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationBody<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a ProviderId,
    provider_version: &'a str,
    provider_revision: &'a ProviderRevision,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    evidence_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: Revision,
    state: RegistrationState,
}

impl AwsConfigRegistration {
    fn new(
        scope: &AwsConfigScope,
        secret_reference: &SecretReference,
        provider: &AwsConfigProviderIdentity,
    ) -> Result<Self, RegistrationError> {
        let evidence_digest = Digest::from_parts(
            "hartevo-aws-config-evidence-policy/v1",
            &[
                crate::AWS_CONFIG_CONTRACT_VERSION.to_owned(),
                crate::model::MAX_RESPONSE_BYTES.to_string(),
                crate::model::MAX_PAGES.to_string(),
                crate::model::PAGE_SIZE.to_string(),
                crate::model::MAX_EVALUATIONS.to_string(),
                "raw-configuration-items-excluded".to_owned(),
            ],
        );
        let mut registration = Self {
            plugin_version: AWS_CONFIG_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_CONFIG_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.version.clone(),
            provider_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: scope.permission_digest.clone(),
            scope_digest: scope.digest(),
            evidence_digest,
            secret_reference_digest: secret_reference.digest().clone(),
            registration_revision: Revision::new(1)?,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&RegistrationBody {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_version: &self.provider_version,
            provider_revision: &self.provider_revision,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            evidence_digest: &self.evidence_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registration_revision: self.registration_revision,
            state: self.state,
        })
    }

    pub fn validate(
        &self,
        scope: &AwsConfigScope,
        secret_reference: &SecretReference,
        provider: &AwsConfigProviderIdentity,
    ) -> Result<(), RegistrationError> {
        if self.plugin_version != AWS_CONFIG_PLUGIN_VERSION
            || self.contract_version != AWS_CONFIG_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.version
            || self.provider_revision != provider.api_revision
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.permission_digest != scope.permission_digest
            || self.scope_digest != scope.digest()
            || self.secret_reference_digest != *secret_reference.digest()
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(RegistrationError::Model(ModelError::ScopeMismatch {
                field: "registration digest binding",
            }));
        }
        Ok(())
    }

    fn revoke(&mut self) -> Result<(), RegistrationError> {
        if self.state == RegistrationState::Revoked {
            return Err(RegistrationError::AlreadyRevoked);
        }
        let next = self
            .registration_revision
            .get()
            .checked_add(1)
            .ok_or(RegistrationError::RevisionOverflow)?;
        self.registration_revision = Revision::new(next)?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsConfigReadResult {
    pub evidence: AwsConfigComplianceEvidence,
    pub page_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsConfigComplianceProposal {
    pub operation: AwsConfigReadOperation,
    pub state: ComplianceState,
    pub evidence: AwsConfigComplianceEvidence,
    pub proposed_at: DateTime<Utc>,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub certification_claim: bool,
    pub adopted_outcome: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalBody<'a> {
    operation: AwsConfigReadOperation,
    state: ComplianceState,
    evidence: &'a AwsConfigComplianceEvidence,
    proposed_at: &'a DateTime<Utc>,
    registration_digest: &'a Digest,
    read_only: bool,
    live_execution: bool,
    connected: bool,
    native: bool,
    certification_claim: bool,
    adopted_outcome: bool,
}

impl AwsConfigComplianceProposal {
    fn new(
        operation: AwsConfigReadOperation,
        evidence: AwsConfigComplianceEvidence,
        proposed_at: DateTime<Utc>,
        registration_digest: Digest,
    ) -> Self {
        let mut proposal = Self {
            operation,
            state: evidence.state,
            evidence,
            proposed_at,
            registration_digest,
            proposal_digest: Digest::zero(),
            read_only: true,
            live_execution: false,
            connected: false,
            native: false,
            certification_claim: false,
            adopted_outcome: false,
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&ProposalBody {
            operation: self.operation,
            state: self.state,
            evidence: &self.evidence,
            proposed_at: &self.proposed_at,
            registration_digest: &self.registration_digest,
            read_only: self.read_only,
            live_execution: self.live_execution,
            connected: self.connected,
            native: self.native,
            certification_claim: self.certification_claim,
            adopted_outcome: self.adopted_outcome,
        })
    }

    pub fn validate(&self) -> Result<(), AwsConfigComplianceServiceError> {
        self.evidence
            .validate()
            .map_err(|_| AwsConfigComplianceServiceError::EvidenceTampered)?;
        if self.state != self.evidence.state
            || !self.read_only
            || self.live_execution
            || self.connected
            || self.native
            || self.certification_claim
            || self.adopted_outcome
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsConfigComplianceServiceError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsConfigRecordReceipt {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub state: ComplianceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub retained_evaluation_count: usize,
    pub raw_provider_payload_retained: bool,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub receipt_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordBody<'a> {
    recorded: bool,
    recorded_at: &'a DateTime<Utc>,
    state: ComplianceState,
    proposal_digest: &'a Digest,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    retained_evaluation_count: usize,
    raw_provider_payload_retained: bool,
    durable_receipt: bool,
    connected: bool,
    native: bool,
}

impl AwsConfigRecordReceipt {
    fn new(proposal: &AwsConfigComplianceProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut receipt = Self {
            recorded: true,
            recorded_at,
            state: proposal.state,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            retained_evaluation_count: proposal.evidence.evaluations.len(),
            raw_provider_payload_retained: false,
            durable_receipt: false,
            connected: false,
            native: false,
            receipt_digest: Digest::zero(),
        };
        receipt.receipt_digest = receipt.recomputed_digest();
        receipt
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&RecordBody {
            recorded: self.recorded,
            recorded_at: &self.recorded_at,
            state: self.state,
            proposal_digest: &self.proposal_digest,
            evidence_digest: &self.evidence_digest,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            retained_evaluation_count: self.retained_evaluation_count,
            raw_provider_payload_retained: self.raw_provider_payload_retained,
            durable_receipt: self.durable_receipt,
            connected: self.connected,
            native: self.native,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsConfigVerifiedRecord {
    pub verified: bool,
    pub state: ComplianceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
}

#[derive(Clone)]
pub struct AwsConfigComplianceService<T>
where
    T: AwsConfigTransport,
{
    scope: AwsConfigScope,
    permission: PermissionFence,
    secret_reference: SecretReference,
    provider: AwsConfigProvider<T>,
    registration: AwsConfigRegistration,
}

impl<T> fmt::Debug for AwsConfigComplianceService<T>
where
    T: AwsConfigTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsConfigComplianceService")
            .field("scope_digest", &self.scope.digest())
            .field("permission_digest", &self.permission.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T> AwsConfigComplianceService<T>
where
    T: AwsConfigTransport,
{
    pub fn register(
        scope: AwsConfigScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsConfigProvider<T>,
    ) -> Result<Self, AwsConfigComplianceServiceError> {
        Self::new(scope, secret_reference, permission, provider)
    }

    pub fn new(
        scope: AwsConfigScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsConfigProvider<T>,
    ) -> Result<Self, AwsConfigComplianceServiceError> {
        scope.validate()?;
        if scope.permission_digest != permission.digest() {
            return Err(AwsConfigComplianceServiceError::ScopeMismatch(
                "permission digest".to_owned(),
            ));
        }
        if !permission.allows(crate::model::PermissionAction::GetComplianceDetailsByConfigRule)
            || !permission.allows(crate::model::PermissionAction::DescribeComplianceByResource)
        {
            return Err(AwsConfigComplianceServiceError::ScopeMismatch(
                "both AWS Config read permissions are required".to_owned(),
            ));
        }
        if secret_reference.signing_region() != scope.target.region() {
            return Err(AwsConfigComplianceServiceError::ScopeMismatch(
                "SigV4 secret reference region".to_owned(),
            ));
        }
        let registration =
            AwsConfigRegistration::new(&scope, &secret_reference, provider.identity())?;
        Ok(Self {
            scope,
            permission,
            secret_reference,
            provider,
            registration,
        })
    }

    pub const fn describe_capabilities() -> AwsConfigCapabilities {
        AwsConfigCapabilities::layer_one()
    }

    pub fn scope(&self) -> &AwsConfigScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsConfigProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsConfigProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsConfigRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn revoke_registration(&mut self) -> Result<(), AwsConfigComplianceServiceError> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn read(
        &mut self,
        request: AwsConfigReadRequest,
    ) -> Result<AwsConfigReadResult, AwsConfigComplianceServiceError> {
        self.ensure_active_and_bound()?;
        request.validate_against(&self.scope, &self.permission)?;

        let mut current_request = request.clone();
        let mut evaluations = Vec::new();
        let mut page_digests = Vec::new();
        let mut provider_errors = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        let mut page_count = 0_u16;
        let mut request_count = 0_u16;
        let mut retry_count = 0_u8;
        let mut consecutive_retries = 0_u8;
        let mut response_bytes = 0_usize;
        let mut partial_reason = None;
        let mut truncated = false;
        let mut terminal_state = None;

        loop {
            if request_count >= crate::model::MAX_REQUESTS_PER_READ {
                partial_reason = Some(PartialReason::PageBudget);
                truncated = true;
                break;
            }
            request_count += 1;
            match self.provider.read(&current_request) {
                Ok(page) => {
                    if page.page_number != page_count + 1 {
                        return Err(AwsConfigComplianceServiceError::Provider(
                            AwsConfigProviderError::PageBinding,
                        ));
                    }
                    response_bytes = response_bytes.saturating_add(page.response_bytes);
                    if response_bytes > current_request.max_response_bytes {
                        partial_reason = Some(PartialReason::ResponseTooLarge);
                        truncated = true;
                        break;
                    }
                    page_count += 1;
                    let mut stale_page = None;
                    for evaluation in &page.evaluations {
                        match self.validate_evaluation(&current_request, evaluation) {
                            Ok(()) => {}
                            Err(EvaluationFenceError::StaleRuleRevision) => {
                                stale_page = Some(PartialReason::StaleRuleRevision);
                                break;
                            }
                            Err(EvaluationFenceError::StaleResourceRevision) => {
                                stale_page = Some(PartialReason::StaleResourceRevision);
                                break;
                            }
                            Err(EvaluationFenceError::Scope(field)) => {
                                return Err(AwsConfigComplianceServiceError::ScopeMismatch(
                                    field.to_owned(),
                                ));
                            }
                        }
                    }
                    if stale_page.is_some() {
                        partial_reason = stale_page;
                        truncated = true;
                        break;
                    }
                    if evaluations.len() + page.evaluations.len()
                        > usize::from(current_request.max_evaluations)
                    {
                        let remaining = usize::from(current_request.max_evaluations)
                            .saturating_sub(evaluations.len());
                        evaluations.extend(page.evaluations.into_iter().take(remaining));
                        partial_reason = Some(PartialReason::EvaluationBudget);
                        truncated = true;
                        page_digests.push(page.page_digest);
                        break;
                    }
                    evaluations.extend(page.evaluations);
                    page_digests.push(page.page_digest);
                    consecutive_retries = 0;
                    let Some(cursor) = page.next_cursor else {
                        break;
                    };
                    if !seen_cursors.insert(cursor.token_digest().clone()) {
                        partial_reason = Some(PartialReason::CursorReplay);
                        truncated = true;
                        break;
                    }
                    if page_count >= current_request.max_pages {
                        partial_reason = Some(PartialReason::PageBudget);
                        truncated = true;
                        break;
                    }
                    current_request = current_request.with_cursor(Some(cursor))?;
                }
                Err(AwsConfigProviderError::Transport(error)) => {
                    provider_errors.push(error.evidence());
                    if error.retryable() && consecutive_retries < current_request.max_retries {
                        consecutive_retries += 1;
                        retry_count += 1;
                        continue;
                    }
                    if is_access_loss(&error) {
                        terminal_state = Some(ComplianceState::AccessLoss);
                    } else if matches!(error, TransportError::Conflict) {
                        terminal_state = Some(ComplianceState::Partial);
                        partial_reason = Some(PartialReason::ProviderConflict);
                    } else {
                        terminal_state = Some(ComplianceState::ProviderUnknown);
                    }
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }

        sort_evaluations(&mut evaluations);
        if partial_reason.is_none() && !ordering_is_consistent(&evaluations) {
            partial_reason = Some(PartialReason::EvaluationOrdering);
            truncated = true;
        }
        let expected = current_request.expected_resources(&self.scope);
        let latest = latest_evaluations(&evaluations);
        if terminal_state.is_none() && partial_reason.is_none() && latest.len() < expected.len() {
            if evaluations.is_empty() {
                terminal_state = Some(ComplianceState::InsufficientData);
            } else {
                partial_reason = Some(PartialReason::MissingEvaluation);
                truncated = true;
            }
        }
        let state = terminal_state.unwrap_or_else(|| {
            aggregate_state(
                &latest,
                &expected,
                partial_reason,
                provider_errors.is_empty(),
            )
        });
        let evidence = AwsConfigComplianceEvidence::new(
            state,
            evaluations,
            partial_reason,
            page_count,
            request_count,
            retry_count,
            truncated,
            request.query_digest(),
            self.scope.digest(),
            self.permission.digest(),
            self.provider.identity().provider_digest.clone(),
            self.provider.identity().api_revision.clone(),
            self.provider.identity().api_digest.clone(),
            contract_digest(),
            provider_errors,
            self.provider.identity().provenance,
        );
        Ok(AwsConfigReadResult {
            evidence,
            page_digests,
        })
    }

    pub fn propose(
        &mut self,
        request: AwsConfigReadRequest,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsConfigComplianceProposal, AwsConfigComplianceServiceError> {
        let operation = request.operation;
        let result = self.read(request)?;
        Ok(AwsConfigComplianceProposal::new(
            operation,
            result.evidence,
            proposed_at,
            self.registration.registration_digest.clone(),
        ))
    }

    pub fn record(
        &self,
        proposal: &AwsConfigComplianceProposal,
    ) -> Result<AwsConfigRecordReceipt, AwsConfigComplianceServiceError> {
        self.record_at(proposal, Utc::now())
    }

    pub fn record_at(
        &self,
        proposal: &AwsConfigComplianceProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsConfigRecordReceipt, AwsConfigComplianceServiceError> {
        self.ensure_active_and_bound()?;
        self.verify_proposal(proposal)?;
        Ok(AwsConfigRecordReceipt::new(proposal, recorded_at))
    }

    pub fn verify(
        &self,
        receipt: &AwsConfigRecordReceipt,
    ) -> Result<AwsConfigVerifiedRecord, AwsConfigComplianceServiceError> {
        self.ensure_active_and_bound()?;
        if !receipt.recorded
            || receipt.registration_digest != self.registration.registration_digest
            || receipt.scope_digest != self.scope.digest()
            || receipt.receipt_digest != receipt.recomputed_digest()
        {
            return Err(AwsConfigComplianceServiceError::RecordTampered);
        }
        let verification_digest = Digest::from_parts(
            "hartevo-aws-config-verified-record/v1",
            &[
                receipt.receipt_digest.to_string(),
                self.registration.registration_digest.to_string(),
                self.scope.digest().to_string(),
            ],
        );
        Ok(AwsConfigVerifiedRecord {
            verified: true,
            state: receipt.state,
            proposal_digest: receipt.proposal_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            verification_digest,
            connected: false,
            native: false,
            adopted_outcome: false,
        })
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsConfigComplianceProposal,
    ) -> Result<(), AwsConfigComplianceServiceError> {
        self.ensure_active_and_bound()?;
        proposal.validate()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.permission.digest()
            || proposal.evidence.provider_digest != self.provider.identity().provider_digest
            || proposal.evidence.provider_revision != self.provider.identity().api_revision
            || proposal.evidence.api_digest != self.provider.identity().api_digest
            || proposal.evidence.contract_digest != contract_digest()
            || proposal.evidence.query_digest == Digest::zero()
        {
            return Err(AwsConfigComplianceServiceError::ProposalTampered);
        }
        Ok(())
    }

    fn ensure_active_and_bound(&self) -> Result<(), AwsConfigComplianceServiceError> {
        if !self.registration.is_active() {
            return Err(AwsConfigComplianceServiceError::RegistrationRevoked);
        }
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                self.provider.identity(),
            )
            .map_err(|error| AwsConfigComplianceServiceError::RegistrationDrift(error.to_string()))
    }

    fn validate_evaluation(
        &self,
        request: &AwsConfigReadRequest,
        evaluation: &ComplianceEvaluation,
    ) -> Result<(), EvaluationFenceError> {
        if evaluation.config_rule_name != self.scope.config_rule.name
            || evaluation.config_rule_name != request.config_rule_name
        {
            return Err(EvaluationFenceError::Scope("Config rule allowlist"));
        }
        if !request
            .compliance_filter
            .allows(evaluation.compliance_state)
        {
            return Err(EvaluationFenceError::Scope("compliance filter"));
        }
        let key = evaluation.resource_key();
        let Some(expected_revision) = self.scope.resource_revision(&key) else {
            return Err(EvaluationFenceError::Scope("resource allowlist"));
        };
        if evaluation.rule_revision != self.scope.config_rule.revision {
            return Err(EvaluationFenceError::StaleRuleRevision);
        }
        if evaluation.resource_revision != expected_revision {
            return Err(EvaluationFenceError::StaleResourceRevision);
        }
        if matches!(
            request.operation,
            AwsConfigReadOperation::DescribeComplianceByResource
        ) && request.resource.as_ref() != Some(&key)
        {
            return Err(EvaluationFenceError::Scope("resource operation binding"));
        }
        Ok(())
    }
}

fn ordering_is_consistent(evaluations: &[ComplianceEvaluation]) -> bool {
    let mut by_resource: BTreeMap<ResourceKey, Vec<&ComplianceEvaluation>> = BTreeMap::new();
    for evaluation in evaluations {
        by_resource
            .entry(evaluation.resource_key())
            .or_default()
            .push(evaluation);
    }
    for values in by_resource.values_mut() {
        values.sort_by_key(|evaluation| evaluation.evaluation_revision);
        for pair in values.windows(2) {
            let previous = pair[0];
            let current = pair[1];
            if current.evaluation_revision == previous.evaluation_revision
                && current.evaluation_digest != previous.evaluation_digest
            {
                return false;
            }
            if current.evaluation_revision > previous.evaluation_revision
                && current.ordering_timestamp < previous.ordering_timestamp
            {
                return false;
            }
        }
    }
    true
}

fn aggregate_state(
    latest: &BTreeMap<ResourceKey, ComplianceEvaluation>,
    expected: &[ResourceKey],
    partial_reason: Option<PartialReason>,
    no_provider_errors: bool,
) -> ComplianceState {
    if partial_reason.is_some() || !no_provider_errors {
        return ComplianceState::Partial;
    }
    if latest.is_empty() {
        return ComplianceState::InsufficientData;
    }
    if latest.len() < expected.len() {
        return ComplianceState::Partial;
    }
    let states = latest
        .values()
        .map(|evaluation| evaluation.compliance_state)
        .collect::<BTreeSet<_>>();
    if states.len() == 1 {
        return states
            .into_iter()
            .next()
            .unwrap_or(ComplianceState::InsufficientData);
    }
    if states.contains(&ComplianceState::InsufficientData) {
        return ComplianceState::Partial;
    }
    if states.contains(&ComplianceState::NonCompliant) {
        return ComplianceState::NonCompliant;
    }
    if states.contains(&ComplianceState::NotApplicable) {
        return ComplianceState::Partial;
    }
    ComplianceState::Partial
}

pub type AwsConfigService<T> = AwsConfigComplianceService<T>;
pub type AwsConfigComplianceResultService<T> = AwsConfigComplianceService<T>;
pub type AwsConfigProposal = AwsConfigComplianceProposal;
pub type AwsConfigServiceError = AwsConfigComplianceServiceError;
pub type AwsConfigRegistrationReceipt = AwsConfigRegistration;
pub type AwsConfigEvaluationRevision = EvaluationRevision;
pub type AwsConfigRule = ConfigRuleName;
pub type AwsConfigTransportProvenance = TransportProvenance;
pub type AwsConfigProviderErrorEvidence = ProviderErrorEvidence;
pub type AwsConfigProviderRevision = ProviderRevision;
pub type AwsConfigResourceKey = ResourceKey;
