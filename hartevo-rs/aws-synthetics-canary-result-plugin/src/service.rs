//! Bounded AWS Synthetics read, proposal, recording, and verification service.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_SYNTHETICS_CONTRACT_VERSION, AWS_SYNTHETICS_PLUGIN_VERSION, AWS_SYNTHETICS_PROVIDER_ID,
    AWS_SYNTHETICS_SERVICE_ID, contract_digest,
    model::{
        AwsSyntheticsScope, CanaryEvidence, CanaryReadOperation,
        CanaryReadRequest as AwsSyntheticsReadRequest, CanaryRun, Digest, EvidenceState,
        MAX_REQUESTS_PER_READ, MAX_RUNS, ModelError, PartialReason, PermissionAction,
        PermissionFence, ProviderErrorEvidence, ProviderErrorKind, ProviderRevision,
        SecretReference, sort_runs,
    },
    provider::{
        AwsSyntheticsProvider, AwsSyntheticsProviderError, AwsSyntheticsProviderIdentity,
        AwsSyntheticsTransport,
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
    #[error("AWS Synthetics registration model error: {0}")]
    Model(#[from] ModelError),
    #[error("AWS Synthetics registration is already revoked")]
    AlreadyRevoked,
    #[error("AWS Synthetics registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsSyntheticsCanaryServiceError {
    #[error("AWS Synthetics service model error: {0}")]
    Model(#[from] ModelError),
    #[error("AWS Synthetics provider error: {0}")]
    Provider(#[from] AwsSyntheticsProviderError),
    #[error("AWS Synthetics registration is revoked")]
    RegistrationRevoked,
    #[error("AWS Synthetics registration has drifted: {0}")]
    RegistrationDrift(String),
    #[error("AWS Synthetics scope or permission fence mismatch: {0}")]
    ScopeMismatch(String),
    #[error("AWS Synthetics evidence is stale or tampered")]
    EvidenceTampered,
    #[error("AWS Synthetics proposal is stale or tampered")]
    ProposalTampered,
    #[error("AWS Synthetics record is stale or tampered")]
    RecordTampered,
    #[error("AWS Synthetics registration lifecycle error: {0}")]
    Registration(#[from] RegistrationError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSyntheticsCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub operations: [&'static str; 7],
    pub allowlisted_api_operations: [&'static str; 1],
    pub allowlisted_method: &'static str,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub raw_provider_payloads: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
}

impl AwsSyntheticsCapabilities {
    pub const fn layer_one() -> Self {
        Self {
            service_id: AWS_SYNTHETICS_SERVICE_ID,
            provider_id: AWS_SYNTHETICS_PROVIDER_ID,
            operations: [
                "describe_capabilities",
                "register",
                "revoke_registration",
                "read_bounded",
                "propose",
                "record",
                "verify",
            ],
            allowlisted_api_operations: ["GetCanaryRuns"],
            allowlisted_method: "POST",
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            raw_provider_payloads: false,
            verification_authority: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSyntheticsRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: crate::model::ProviderId,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: crate::model::Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationBody<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a crate::model::ProviderId,
    provider_version: &'a str,
    provider_revision: &'a ProviderRevision,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    evidence_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: crate::model::Revision,
    state: RegistrationState,
}

impl AwsSyntheticsRegistration {
    fn new(
        scope: &AwsSyntheticsScope,
        secret_reference: &SecretReference,
        provider: &AwsSyntheticsProviderIdentity,
    ) -> Result<Self, RegistrationError> {
        let evidence_digest = Digest::from_parts(
            "hartevo-aws-synthetics-evidence-policy/v1",
            &[
                AWS_SYNTHETICS_CONTRACT_VERSION.to_owned(),
                crate::model::MAX_RESPONSE_BYTES.to_string(),
                crate::model::MAX_PAGES.to_string(),
                crate::model::PAGE_SIZE.to_string(),
                crate::model::MAX_RUNS.to_string(),
                "raw-provider-payloads-excluded".to_owned(),
                "endpoint-url-excluded".to_owned(),
            ],
        );
        let mut registration = Self {
            plugin_version: AWS_SYNTHETICS_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_SYNTHETICS_CONTRACT_VERSION.to_owned(),
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
            registration_revision: crate::model::Revision::new(1)?,
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
        scope: &AwsSyntheticsScope,
        secret_reference: &SecretReference,
        provider: &AwsSyntheticsProviderIdentity,
    ) -> Result<(), RegistrationError> {
        if self.plugin_version != AWS_SYNTHETICS_PLUGIN_VERSION
            || self.contract_version != AWS_SYNTHETICS_CONTRACT_VERSION
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
                field: "registration version, digest, scope, permission, or secret binding",
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
        self.registration_revision = crate::model::Revision::new(next)?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSyntheticsReadResult {
    pub evidence: CanaryEvidence,
    pub page_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSyntheticsCanaryProposal {
    pub operation: CanaryReadOperation,
    pub state: EvidenceState,
    pub evidence: CanaryEvidence,
    pub proposed_at: DateTime<Utc>,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub verification_authority: bool,
    pub certification_claim: bool,
    pub adopted_outcome: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalBody<'a> {
    operation: CanaryReadOperation,
    state: EvidenceState,
    evidence: &'a CanaryEvidence,
    proposed_at: &'a DateTime<Utc>,
    registration_digest: &'a Digest,
    read_only: bool,
    live_execution: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    verification_authority: bool,
    certification_claim: bool,
    adopted_outcome: bool,
}

impl AwsSyntheticsCanaryProposal {
    fn new(
        operation: CanaryReadOperation,
        evidence: CanaryEvidence,
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
            first_party: false,
            verification_authority: false,
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
            first_party: self.first_party,
            verification_authority: self.verification_authority,
            certification_claim: self.certification_claim,
            adopted_outcome: self.adopted_outcome,
        })
    }

    pub fn validate(&self) -> Result<(), AwsSyntheticsCanaryServiceError> {
        self.evidence
            .validate()
            .map_err(|_| AwsSyntheticsCanaryServiceError::EvidenceTampered)?;
        if self.state != self.evidence.state
            || !self.read_only
            || self.live_execution
            || self.connected
            || self.native
            || self.first_party
            || self.verification_authority
            || self.certification_claim
            || self.adopted_outcome
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsSyntheticsCanaryServiceError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSyntheticsRecordReceipt {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub state: EvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub retained_run_count: usize,
    pub raw_provider_payload_retained: bool,
    pub endpoint_url_retained: bool,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub receipt_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordBody<'a> {
    recorded: bool,
    recorded_at: &'a DateTime<Utc>,
    state: EvidenceState,
    proposal_digest: &'a Digest,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    retained_run_count: usize,
    raw_provider_payload_retained: bool,
    endpoint_url_retained: bool,
    durable_receipt: bool,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl AwsSyntheticsRecordReceipt {
    fn new(proposal: &AwsSyntheticsCanaryProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut receipt = Self {
            recorded: true,
            recorded_at,
            state: proposal.state,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            retained_run_count: proposal.evidence.runs.len(),
            raw_provider_payload_retained: false,
            endpoint_url_retained: false,
            durable_receipt: false,
            connected: false,
            native: false,
            first_party: false,
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
            retained_run_count: self.retained_run_count,
            raw_provider_payload_retained: self.raw_provider_payload_retained,
            endpoint_url_retained: self.endpoint_url_retained,
            durable_receipt: self.durable_receipt,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSyntheticsVerifiedRecord {
    pub verified: bool,
    pub state: EvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub verification_authority: bool,
    pub adopted_outcome: bool,
}

#[derive(Clone)]
pub struct AwsSyntheticsService<T>
where
    T: AwsSyntheticsTransport,
{
    scope: AwsSyntheticsScope,
    permission: PermissionFence,
    secret_reference: SecretReference,
    provider: AwsSyntheticsProvider<T>,
    registration: AwsSyntheticsRegistration,
}

impl<T> fmt::Debug for AwsSyntheticsService<T>
where
    T: AwsSyntheticsTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSyntheticsService")
            .field("scope_digest", &self.scope.digest())
            .field("permission_digest", &self.permission.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T> AwsSyntheticsService<T>
where
    T: AwsSyntheticsTransport,
{
    pub fn register(
        scope: AwsSyntheticsScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsSyntheticsProvider<T>,
    ) -> Result<Self, AwsSyntheticsCanaryServiceError> {
        Self::new(scope, secret_reference, permission, provider)
    }

    pub fn new(
        scope: AwsSyntheticsScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsSyntheticsProvider<T>,
    ) -> Result<Self, AwsSyntheticsCanaryServiceError> {
        scope.validate()?;
        if scope.permission_digest != permission.digest()
            || !permission.allows(PermissionAction::GetCanaryRuns)
        {
            return Err(AwsSyntheticsCanaryServiceError::ScopeMismatch(
                "GetCanaryRuns permission digest or action".to_owned(),
            ));
        }
        if secret_reference.signing_service() != "synthetics"
            || secret_reference.signing_region() != &scope.target.region
        {
            return Err(AwsSyntheticsCanaryServiceError::ScopeMismatch(
                "SigV4 secret reference service or region".to_owned(),
            ));
        }
        let registration =
            AwsSyntheticsRegistration::new(&scope, &secret_reference, provider.identity())?;
        Ok(Self {
            scope,
            permission,
            secret_reference,
            provider,
            registration,
        })
    }

    pub const fn describe_capabilities() -> AwsSyntheticsCapabilities {
        AwsSyntheticsCapabilities::layer_one()
    }

    pub fn scope(&self) -> &AwsSyntheticsScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsSyntheticsProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsSyntheticsProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsSyntheticsRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsSyntheticsRegistration {
        &mut self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn revoke_registration(&mut self) -> Result<(), AwsSyntheticsCanaryServiceError> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn read(
        &mut self,
        request: AwsSyntheticsReadRequest,
    ) -> Result<AwsSyntheticsReadResult, AwsSyntheticsCanaryServiceError> {
        self.ensure_active_and_bound()?;
        request.validate_against(&self.scope, &self.permission)?;

        let mut current_request = request.clone();
        let mut runs = Vec::new();
        let mut page_digests = Vec::new();
        let mut provider_errors = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        let mut seen_run_ids = BTreeSet::new();
        let mut page_count = 0_u16;
        let mut request_count = 0_u16;
        let mut retry_count = 0_u8;
        let mut consecutive_retries = 0_u8;
        let mut response_bytes = 0_usize;
        let mut partial_reason = None;
        let mut truncated = false;

        loop {
            if request_count >= MAX_REQUESTS_PER_READ {
                partial_reason = Some(PartialReason::PageBudget);
                truncated = true;
                break;
            }
            request_count += 1;
            match self.provider.read(&current_request) {
                Ok(page) => {
                    if page.page_number != page_count + 1 {
                        partial_reason = Some(PartialReason::MalformedPage);
                        truncated = true;
                        break;
                    }
                    response_bytes = response_bytes.saturating_add(page.response_bytes);
                    page_digests.push(page.page_digest.clone());
                    if response_bytes > current_request.max_response_bytes {
                        partial_reason = Some(PartialReason::ResponseBudget);
                        truncated = true;
                        break;
                    }
                    page_count += 1;

                    let mut page_invalid = None;
                    for run in &page.runs {
                        if let Some(reason) = self.validate_run(&current_request, run) {
                            page_invalid = Some(reason);
                            break;
                        }
                        if !seen_run_ids.insert(run.run_id.clone()) {
                            page_invalid = Some(PartialReason::CursorReplay);
                            break;
                        }
                    }
                    if let Some(reason) = page_invalid {
                        partial_reason = Some(reason);
                        truncated = true;
                        break;
                    }
                    if runs.len() + page.runs.len() > MAX_RUNS {
                        let remaining = MAX_RUNS.saturating_sub(runs.len());
                        runs.extend(page.runs.into_iter().take(remaining));
                        partial_reason = Some(PartialReason::RunBudget);
                        truncated = true;
                        break;
                    }
                    runs.extend(page.runs);
                    consecutive_retries = 0;
                    let Some(cursor) = page.next_cursor else {
                        break;
                    };
                    if page_count >= current_request.max_pages {
                        partial_reason = Some(PartialReason::PageBudget);
                        truncated = true;
                        break;
                    }
                    if !seen_cursors.insert(cursor.token_digest().clone()) {
                        partial_reason = Some(PartialReason::PaginationLoop);
                        truncated = true;
                        break;
                    }
                    if cursor
                        .binding_digest()
                        .is_some_and(|binding| binding != current_request.query_digest())
                    {
                        partial_reason = Some(PartialReason::ScopeMismatch);
                        truncated = true;
                        break;
                    }
                    if let Ok(next_request) = current_request.with_cursor(Some(cursor)) {
                        current_request = next_request;
                    } else {
                        partial_reason = Some(PartialReason::ScopeMismatch);
                        truncated = true;
                        break;
                    }
                }
                Err(AwsSyntheticsProviderError::Transport(error)) => {
                    provider_errors.push(error.evidence(
                        self.provider.provenance(),
                        self.provider.identity().api_revision.clone(),
                    ));
                    if error.retryable() && consecutive_retries < current_request.max_retries {
                        consecutive_retries += 1;
                        retry_count += 1;
                        continue;
                    }
                    partial_reason = Some(match error.kind() {
                        ProviderErrorKind::AccessDenied | ProviderErrorKind::NotFound => {
                            PartialReason::AccessLoss
                        }
                        ProviderErrorKind::Throttled => PartialReason::Throttled,
                        ProviderErrorKind::Timeout => PartialReason::Timeout,
                        ProviderErrorKind::BlockedEnv => PartialReason::BlockedEnv,
                        _ => PartialReason::ProviderError,
                    });
                    truncated = true;
                    break;
                }
                Err(AwsSyntheticsProviderError::RevisionMismatch) => {
                    provider_errors.push(ProviderErrorEvidence::new(
                        ProviderErrorKind::RevisionMismatch,
                        self.provider.provenance(),
                        self.provider.identity().api_revision.clone(),
                    ));
                    partial_reason = Some(PartialReason::StaleRevision);
                    truncated = true;
                    break;
                }
                Err(AwsSyntheticsProviderError::MalformedPage) => {
                    provider_errors.push(ProviderErrorEvidence::new(
                        ProviderErrorKind::Malformed,
                        self.provider.provenance(),
                        self.provider.identity().api_revision.clone(),
                    ));
                    partial_reason = Some(PartialReason::MalformedPage);
                    truncated = true;
                    break;
                }
                Err(AwsSyntheticsProviderError::UnsupportedOperation) => {
                    return Err(AwsSyntheticsCanaryServiceError::Provider(
                        AwsSyntheticsProviderError::UnsupportedOperation,
                    ));
                }
            }
        }

        if runs.is_empty() && provider_errors.is_empty() && partial_reason.is_none() {
            partial_reason = Some(PartialReason::MissingRuns);
            truncated = true;
        }
        sort_runs(&mut runs);
        let evidence = CanaryEvidence::new(
            request.operation,
            request.query_digest.clone(),
            self.scope.digest(),
            self.permission.digest(),
            self.provider.identity().provider_digest.clone(),
            self.provider.identity().api_revision.clone(),
            self.provider.identity().api_digest.clone(),
            contract_digest(),
            self.provider.provenance(),
            runs,
            page_digests.clone(),
            page_count,
            request_count,
            retry_count,
            truncated,
            partial_reason,
            provider_errors,
        )?;
        Ok(AwsSyntheticsReadResult {
            evidence,
            page_digests,
        })
    }

    pub fn propose(
        &mut self,
        request: AwsSyntheticsReadRequest,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsSyntheticsCanaryProposal, AwsSyntheticsCanaryServiceError> {
        let operation = request.operation;
        let result = self.read(request)?;
        Ok(AwsSyntheticsCanaryProposal::new(
            operation,
            result.evidence,
            proposed_at,
            self.registration.registration_digest.clone(),
        ))
    }

    pub fn record(
        &self,
        proposal: &AwsSyntheticsCanaryProposal,
    ) -> Result<AwsSyntheticsRecordReceipt, AwsSyntheticsCanaryServiceError> {
        self.record_at(proposal, Utc::now())
    }

    pub fn record_at(
        &self,
        proposal: &AwsSyntheticsCanaryProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsSyntheticsRecordReceipt, AwsSyntheticsCanaryServiceError> {
        self.ensure_active_and_bound()?;
        self.verify_proposal(proposal)?;
        Ok(AwsSyntheticsRecordReceipt::new(proposal, recorded_at))
    }

    pub fn verify(
        &self,
        receipt: &AwsSyntheticsRecordReceipt,
    ) -> Result<AwsSyntheticsVerifiedRecord, AwsSyntheticsCanaryServiceError> {
        self.ensure_active_and_bound()?;
        if !receipt.recorded
            || receipt.registration_digest != self.registration.registration_digest
            || receipt.scope_digest != self.scope.digest()
            || receipt.raw_provider_payload_retained
            || receipt.endpoint_url_retained
            || receipt.durable_receipt
            || receipt.connected
            || receipt.native
            || receipt.first_party
            || receipt.receipt_digest != receipt.recomputed_digest()
        {
            return Err(AwsSyntheticsCanaryServiceError::RecordTampered);
        }
        let verification_digest = Digest::from_parts(
            "hartevo-mission-aws-synthetics-verified-record/v1",
            &[
                receipt.receipt_digest.to_string(),
                self.registration.registration_digest.to_string(),
                self.scope.digest().to_string(),
            ],
        );
        Ok(AwsSyntheticsVerifiedRecord {
            verified: true,
            state: receipt.state,
            proposal_digest: receipt.proposal_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            verification_digest,
            connected: false,
            native: false,
            first_party: false,
            verification_authority: false,
            adopted_outcome: false,
        })
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsSyntheticsCanaryProposal,
    ) -> Result<(), AwsSyntheticsCanaryServiceError> {
        self.ensure_active_and_bound()?;
        proposal.validate()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.permission.digest()
            || proposal.evidence.provider_digest != self.provider.identity().provider_digest
            || proposal.evidence.provider_revision != self.provider.identity().api_revision
            || proposal.evidence.api_digest != self.provider.identity().api_digest
            || proposal.evidence.contract_digest != contract_digest()
            || proposal.evidence.provenance != self.provider.provenance()
            || proposal.evidence.query_digest == Digest::zero()
        {
            return Err(AwsSyntheticsCanaryServiceError::ProposalTampered);
        }
        if proposal
            .evidence
            .runs
            .iter()
            .any(|run| self.validate_run_scope(run).is_some())
        {
            return Err(AwsSyntheticsCanaryServiceError::ProposalTampered);
        }
        Ok(())
    }

    fn ensure_active_and_bound(&self) -> Result<(), AwsSyntheticsCanaryServiceError> {
        if !self.registration.is_active() {
            return Err(AwsSyntheticsCanaryServiceError::RegistrationRevoked);
        }
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                self.provider.identity(),
            )
            .map_err(|error| AwsSyntheticsCanaryServiceError::RegistrationDrift(error.to_string()))
    }

    fn validate_run(
        &self,
        request: &AwsSyntheticsReadRequest,
        run: &CanaryRun,
    ) -> Option<PartialReason> {
        if let Some(reason) = self.validate_run_scope(run) {
            return Some(reason);
        }
        if run.canary_revision != self.scope.target.canary_revision
            || run.canary_revision != request.canary_revision
        {
            return Some(PartialReason::StaleRevision);
        }
        None
    }

    fn validate_run_scope(&self, run: &CanaryRun) -> Option<PartialReason> {
        if run.canary_name != self.scope.target.canary_name
            || run.endpoint_digest != self.scope.target.endpoint_digest
        {
            Some(PartialReason::ScopeMismatch)
        } else if run.canary_revision != self.scope.target.canary_revision {
            Some(PartialReason::StaleRevision)
        } else {
            None
        }
    }
}

pub type AwsSyntheticsCanaryService<T> = AwsSyntheticsService<T>;
pub type AwsSyntheticsServiceError = AwsSyntheticsCanaryServiceError;
pub type AwsSyntheticsRegistrationReceipt = AwsSyntheticsRegistration;
pub type AwsSyntheticsCanaryProposalType = AwsSyntheticsCanaryProposal;
pub type AwsSyntheticsCanaryProviderRevision = ProviderRevision;
