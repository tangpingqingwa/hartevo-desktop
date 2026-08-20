//! Bounded GitHub Dependabot read, proposal, recording, and verification.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::{
    GITHUB_DEPENDABOT_CONTRACT_VERSION, GITHUB_DEPENDABOT_PLUGIN_VERSION, contract_digest,
    model::{
        AlertNumber, AlertState, DependabotAlert, DependabotEvidenceState, Digest,
        GithubDependabotEvidence, GithubDependabotReadOperation, GithubDependabotReadRequest,
        GithubDependabotScope, MAX_ALERTS, MAX_PROVIDER_ERRORS, MAX_REQUESTS_PER_READ, ModelError,
        PartialReason, PermissionAction, PermissionFence, ProviderErrorEvidence, ProviderRevision,
        Revision, SecretReference, TransportError, TransportProvenance,
    },
    provider::{
        GithubDependabotProvider, GithubDependabotProviderError, GithubDependabotProviderIdentity,
        GithubDependabotTransport, is_access_loss,
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
    #[error("GitHub Dependabot registration model error: {0}")]
    Model(#[from] ModelError),
    #[error("GitHub Dependabot registration is already revoked")]
    AlreadyRevoked,
    #[error("GitHub Dependabot registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GithubDependabotServiceError {
    #[error("GitHub Dependabot service model error: {0}")]
    Model(#[from] ModelError),
    #[error("GitHub Dependabot provider error: {0}")]
    Provider(#[from] GithubDependabotProviderError),
    #[error("GitHub Dependabot registration is revoked")]
    RegistrationRevoked,
    #[error("GitHub Dependabot registration has drifted: {0}")]
    RegistrationDrift(String),
    #[error("GitHub Dependabot scope or permission fence mismatch: {0}")]
    ScopeMismatch(String),
    #[error("GitHub Dependabot evidence is stale or tampered")]
    EvidenceTampered,
    #[error("GitHub Dependabot proposal is stale or tampered")]
    ProposalTampered,
    #[error("GitHub Dependabot record is stale or tampered")]
    RecordTampered,
    #[error("GitHub Dependabot registration lifecycle error: {0}")]
    Registration(#[from] RegistrationError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDependabotResultServiceDefinition {
    pub id: &'static str,
    pub implementation: &'static str,
    pub version: &'static str,
    pub operations: [&'static str; 7],
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub outcome_authority: bool,
}

impl GithubDependabotResultServiceDefinition {
    pub const fn layer_one() -> Self {
        Self {
            id: crate::GITHUB_DEPENDABOT_SERVICE_ID,
            implementation: "GithubDependabotResultService",
            version: GITHUB_DEPENDABOT_PLUGIN_VERSION,
            operations: [
                "describe_capabilities",
                "register",
                "revoke_registration",
                "read_bounded",
                "propose",
                "record",
                "verify",
            ],
            read_only: true,
            proposal_only: true,
            live_execution: false,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
            truth_authority: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDependabotRegistration {
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
    provider_id: &'a crate::model::ProviderId,
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

impl GithubDependabotRegistration {
    fn new(
        scope: &GithubDependabotScope,
        secret_reference: &SecretReference,
        provider: &GithubDependabotProviderIdentity,
    ) -> Result<Self, RegistrationError> {
        let evidence_digest = Digest::from_parts(
            "hartevo-github-dependabot-evidence-policy/v1",
            &[
                GITHUB_DEPENDABOT_CONTRACT_VERSION.to_owned(),
                crate::model::MAX_RESPONSE_BYTES.to_string(),
                crate::model::MAX_PAGES.to_string(),
                crate::model::PAGE_SIZE.to_string(),
                MAX_ALERTS.to_string(),
                "raw-descriptions-manifests-packages-excluded".to_owned(),
            ],
        );
        let mut registration = Self {
            plugin_version: GITHUB_DEPENDABOT_PLUGIN_VERSION.to_owned(),
            contract_version: GITHUB_DEPENDABOT_CONTRACT_VERSION.to_owned(),
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
        scope: &GithubDependabotScope,
        secret_reference: &SecretReference,
        provider: &GithubDependabotProviderIdentity,
    ) -> Result<(), RegistrationError> {
        if self.plugin_version != GITHUB_DEPENDABOT_PLUGIN_VERSION
            || self.contract_version != GITHUB_DEPENDABOT_CONTRACT_VERSION
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
                field: "registration version or digest",
            }));
        }
        Ok(())
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn revoke(&mut self) -> Result<(), RegistrationError> {
        if !self.is_active() {
            return Err(RegistrationError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(RegistrationError::RevisionOverflow)?,
        )?;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDependabotReadResult {
    pub evidence: GithubDependabotEvidence,
    pub page_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDependabotProposal {
    pub operation: GithubDependabotReadOperation,
    pub evidence: GithubDependabotEvidence,
    pub proposed_at: DateTime<Utc>,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalBody<'a> {
    operation: GithubDependabotReadOperation,
    evidence_digest: &'a Digest,
    proposed_at: &'a DateTime<Utc>,
    registration_digest: &'a Digest,
}

impl GithubDependabotProposal {
    fn new(
        operation: GithubDependabotReadOperation,
        evidence: GithubDependabotEvidence,
        proposed_at: DateTime<Utc>,
        registration_digest: Digest,
    ) -> Self {
        let mut proposal = Self {
            operation,
            evidence,
            proposed_at,
            registration_digest,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&ProposalBody {
            operation: self.operation,
            evidence_digest: &self.evidence.evidence_digest,
            proposed_at: &self.proposed_at,
            registration_digest: &self.registration_digest,
        })
    }

    pub fn validate(&self) -> Result<(), GithubDependabotServiceError> {
        self.evidence
            .validate()
            .map_err(|_| GithubDependabotServiceError::EvidenceTampered)?;
        if self.registration_digest == Digest::zero()
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(GithubDependabotServiceError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDependabotRecordReceipt {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub state: DependabotEvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub retained_alert_count: usize,
    pub raw_provider_payload_retained: bool,
    pub remediation_instructions_retained: bool,
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
    state: DependabotEvidenceState,
    proposal_digest: &'a Digest,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    retained_alert_count: usize,
    raw_provider_payload_retained: bool,
    remediation_instructions_retained: bool,
    durable_receipt: bool,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl GithubDependabotRecordReceipt {
    fn new(proposal: &GithubDependabotProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut receipt = Self {
            recorded: true,
            recorded_at,
            state: proposal.evidence.state,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            retained_alert_count: proposal.evidence.alerts.len(),
            raw_provider_payload_retained: false,
            remediation_instructions_retained: false,
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
            retained_alert_count: self.retained_alert_count,
            raw_provider_payload_retained: self.raw_provider_payload_retained,
            remediation_instructions_retained: self.remediation_instructions_retained,
            durable_receipt: self.durable_receipt,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDependabotVerifiedRecord {
    pub verified: bool,
    pub state: DependabotEvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopted_outcome: bool,
}

#[derive(Clone)]
pub struct GithubDependabotResultService<T>
where
    T: GithubDependabotTransport,
{
    scope: GithubDependabotScope,
    permission: PermissionFence,
    secret_reference: SecretReference,
    provider: GithubDependabotProvider<T>,
    registration: GithubDependabotRegistration,
}

impl<T> fmt::Debug for GithubDependabotResultService<T>
where
    T: GithubDependabotTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDependabotResultService")
            .field("scope_digest", &self.scope.digest())
            .field("permission_digest", &self.permission.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T> GithubDependabotResultService<T>
where
    T: GithubDependabotTransport,
{
    pub fn register(
        scope: GithubDependabotScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: GithubDependabotProvider<T>,
    ) -> Result<Self, GithubDependabotServiceError> {
        Self::new(scope, secret_reference, permission, provider)
    }

    pub fn new(
        scope: GithubDependabotScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: GithubDependabotProvider<T>,
    ) -> Result<Self, GithubDependabotServiceError> {
        scope.validate()?;
        if scope.permission_digest != permission.digest() {
            return Err(GithubDependabotServiceError::ScopeMismatch(
                "permission digest".to_owned(),
            ));
        }
        if secret_reference
            .scope_digest()
            .is_some_and(|digest| digest != &scope.digest())
        {
            return Err(GithubDependabotServiceError::ScopeMismatch(
                "secret reference scope digest".to_owned(),
            ));
        }
        if !permission.allows(PermissionAction::ListDependabotAlerts)
            || !permission.allows(PermissionAction::GetDependabotAlert)
        {
            return Err(GithubDependabotServiceError::ScopeMismatch(
                "both Dependabot read permissions are required".to_owned(),
            ));
        }
        if provider.identity().provider_id.as_str() != crate::GITHUB_DEPENDABOT_PROVIDER_ID
            || provider.identity().api_revision.as_str() != crate::GITHUB_DEPENDABOT_API_REVISION
            || provider.identity().provenance.connected()
            || provider.identity().provenance.native()
            || provider.identity().provenance.first_party()
        {
            return Err(GithubDependabotServiceError::ScopeMismatch(
                "Layer-1 provider provenance".to_owned(),
            ));
        }
        let registration =
            GithubDependabotRegistration::new(&scope, &secret_reference, provider.identity())?;
        Ok(Self {
            scope,
            permission,
            secret_reference,
            provider,
            registration,
        })
    }

    pub const fn describe_capabilities() -> GithubDependabotResultServiceDefinition {
        GithubDependabotResultServiceDefinition::layer_one()
    }

    pub fn scope(&self) -> &GithubDependabotScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &GithubDependabotProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut GithubDependabotProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &GithubDependabotRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn revoke_registration(&mut self) -> Result<(), GithubDependabotServiceError> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn read(
        &mut self,
        request: GithubDependabotReadRequest,
    ) -> Result<GithubDependabotReadResult, GithubDependabotServiceError> {
        self.ensure_active_and_bound()?;
        request
            .validate_against(&self.scope, &self.permission)
            .map_err(|error| GithubDependabotServiceError::ScopeMismatch(error.to_string()))?;

        let mut current_request = request.clone();
        let mut alerts = Vec::new();
        let mut alert_digests = BTreeMap::<AlertNumber, Digest>::new();
        let mut page_digests = Vec::new();
        let mut provider_errors = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        if let Some(cursor) = &current_request.cursor {
            seen_cursors.insert(cursor.token_digest().clone());
        }
        let mut page_count = 0_u16;
        let mut request_count = 0_u16;
        let mut retry_count = 0_u8;
        let mut consecutive_retries = 0_u8;
        let mut response_bytes = 0_usize;
        let mut partial_reason = None;
        let mut truncated = false;
        let mut terminal_state = None;
        let mut not_modified = false;
        let mut etag_digest = current_request.etag_digest.clone();

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
                        return Err(GithubDependabotServiceError::Provider(
                            GithubDependabotProviderError::PageBinding,
                        ));
                    }
                    response_bytes = response_bytes.saturating_add(page.response_bytes);
                    if response_bytes > current_request.max_response_bytes {
                        partial_reason = Some(PartialReason::ResponseTooLarge);
                        truncated = true;
                        break;
                    }
                    page_count += 1;
                    page_digests.push(page.page_digest.clone());
                    etag_digest = page.etag_digest.clone().or(etag_digest);
                    if page.not_modified {
                        not_modified = true;
                        partial_reason = Some(PartialReason::NotModified);
                        break;
                    }

                    for alert in &page.alerts {
                        match self.validate_alert(&current_request, alert) {
                            Ok(()) => {}
                            Err(AlertFenceError::StaleRevision) => {
                                partial_reason = Some(PartialReason::StaleAlertRevision);
                                truncated = true;
                                break;
                            }
                            Err(AlertFenceError::Scope(field)) => {
                                return Err(GithubDependabotServiceError::ScopeMismatch(
                                    field.to_owned(),
                                ));
                            }
                        }
                        if partial_reason.is_some() {
                            break;
                        }
                        if let Some(existing) = alert_digests.get(&alert.alert_number) {
                            if existing != &alert.alert_digest {
                                partial_reason = Some(PartialReason::AlertReplay);
                                truncated = true;
                                break;
                            }
                            continue;
                        }
                        if alerts.len() >= usize::from(current_request.max_alerts) {
                            partial_reason = Some(PartialReason::AlertBudget);
                            truncated = true;
                            break;
                        }
                        alert_digests.insert(alert.alert_number, alert.alert_digest.clone());
                        alerts.push(alert.clone());
                    }
                    if partial_reason.is_some() {
                        break;
                    }
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
                Err(GithubDependabotProviderError::Transport(error)) => {
                    if provider_errors.len() < MAX_PROVIDER_ERRORS {
                        provider_errors.push(error.evidence());
                    }
                    if error.retryable() && consecutive_retries < current_request.max_retries {
                        consecutive_retries += 1;
                        retry_count += 1;
                        continue;
                    }
                    if is_access_loss(&error) {
                        terminal_state = Some(DependabotEvidenceState::AccessLoss);
                    } else if matches!(error, TransportError::NotModified) {
                        terminal_state = Some(DependabotEvidenceState::NotModified);
                        partial_reason = Some(PartialReason::NotModified);
                        not_modified = true;
                    } else if matches!(error, TransportError::Conflict) {
                        terminal_state = Some(DependabotEvidenceState::Partial);
                        partial_reason = Some(PartialReason::ProviderConflict);
                    } else if matches!(error, TransportError::UnprocessableEntity) {
                        terminal_state = Some(DependabotEvidenceState::Partial);
                        partial_reason = Some(PartialReason::UnprocessableProviderResponse);
                    } else {
                        terminal_state = Some(DependabotEvidenceState::ProviderUnknown);
                    }
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }

        alerts.sort_by_key(|alert| (alert.alert_number, alert.alert_revision));
        let expected = self.scope.expected_alerts(&request);
        if terminal_state.is_none() && partial_reason.is_none() {
            let present = alerts
                .iter()
                .map(|alert| alert.alert_number)
                .collect::<BTreeSet<_>>();
            let missing_expected = expected.iter().any(|number| !present.contains(number));
            if missing_expected
                && (matches!(request.operation, GithubDependabotReadOperation::GetAlert)
                    || !alerts.is_empty())
            {
                partial_reason = Some(PartialReason::MissingAlert);
                truncated = true;
            }
        }
        let state = terminal_state.unwrap_or_else(|| {
            aggregate_state(
                &alerts,
                partial_reason,
                provider_errors.is_empty(),
                not_modified,
            )
        });
        let evidence = GithubDependabotEvidence::new(
            state,
            alerts,
            partial_reason,
            page_count,
            request_count,
            retry_count,
            truncated,
            not_modified,
            request.query_digest(),
            self.scope.digest(),
            self.permission.digest(),
            self.scope.repository.digest(),
            self.scope.ref_name.digest(),
            self.scope.commit_sha.digest(),
            self.provider.identity().provider_digest.clone(),
            self.provider.identity().api_revision.clone(),
            self.provider.identity().api_digest.clone(),
            contract_digest(),
            provider_errors,
            etag_digest,
            self.provider.identity().provenance,
        )?;
        Ok(GithubDependabotReadResult {
            evidence,
            page_digests,
        })
    }

    pub fn read_bounded(
        &mut self,
        request: GithubDependabotReadRequest,
    ) -> Result<GithubDependabotReadResult, GithubDependabotServiceError> {
        self.read(request)
    }

    pub fn propose(
        &mut self,
        request: GithubDependabotReadRequest,
        proposed_at: DateTime<Utc>,
    ) -> Result<GithubDependabotProposal, GithubDependabotServiceError> {
        let operation = request.operation;
        let result = self.read(request)?;
        Ok(GithubDependabotProposal::new(
            operation,
            result.evidence,
            proposed_at,
            self.registration.registration_digest.clone(),
        ))
    }

    pub fn propose_now(
        &mut self,
        request: GithubDependabotReadRequest,
    ) -> Result<GithubDependabotProposal, GithubDependabotServiceError> {
        self.propose(request, Utc::now())
    }

    pub fn record(
        &self,
        proposal: &GithubDependabotProposal,
    ) -> Result<GithubDependabotRecordReceipt, GithubDependabotServiceError> {
        self.record_at(proposal, Utc::now())
    }

    pub fn record_at(
        &self,
        proposal: &GithubDependabotProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<GithubDependabotRecordReceipt, GithubDependabotServiceError> {
        self.ensure_active_and_bound()?;
        self.verify_proposal(proposal)?;
        Ok(GithubDependabotRecordReceipt::new(proposal, recorded_at))
    }

    pub fn verify(
        &self,
        receipt: &GithubDependabotRecordReceipt,
    ) -> Result<GithubDependabotVerifiedRecord, GithubDependabotServiceError> {
        self.ensure_active_and_bound()?;
        if !receipt.recorded
            || receipt.registration_digest != self.registration.registration_digest
            || receipt.scope_digest != self.scope.digest()
            || receipt.receipt_digest != receipt.recomputed_digest()
            || receipt.raw_provider_payload_retained
            || receipt.remediation_instructions_retained
            || receipt.durable_receipt
            || receipt.connected
            || receipt.native
            || receipt.first_party
        {
            return Err(GithubDependabotServiceError::RecordTampered);
        }
        let verification_digest = Digest::from_parts(
            "hartevo-github-dependabot-verified-record/v1",
            &[
                receipt.receipt_digest.to_string(),
                self.registration.registration_digest.to_string(),
                self.scope.digest().to_string(),
            ],
        );
        Ok(GithubDependabotVerifiedRecord {
            verified: true,
            state: receipt.state,
            proposal_digest: receipt.proposal_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            verification_digest,
            connected: false,
            native: false,
            first_party: false,
            adopted_outcome: false,
        })
    }

    pub fn verify_proposal(
        &self,
        proposal: &GithubDependabotProposal,
    ) -> Result<(), GithubDependabotServiceError> {
        self.ensure_active_and_bound()?;
        proposal.validate()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.permission.digest()
            || proposal.evidence.repository_digest != self.scope.repository.digest()
            || proposal.evidence.ref_digest != self.scope.ref_name.digest()
            || proposal.evidence.commit_digest != self.scope.commit_sha.digest()
            || proposal.evidence.provider_digest != self.provider.identity().provider_digest
            || proposal.evidence.provider_revision != self.provider.identity().api_revision
            || proposal.evidence.api_digest != self.provider.identity().api_digest
            || proposal.evidence.contract_digest != contract_digest()
            || proposal.evidence.query_digest == Digest::zero()
            || proposal.operation == GithubDependabotReadOperation::GetAlert
                && proposal.evidence.alerts.len() > 1
        {
            return Err(GithubDependabotServiceError::ProposalTampered);
        }
        Ok(())
    }

    fn ensure_active_and_bound(&self) -> Result<(), GithubDependabotServiceError> {
        if !self.registration.is_active() {
            return Err(GithubDependabotServiceError::RegistrationRevoked);
        }
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                self.provider.identity(),
            )
            .map_err(|error| GithubDependabotServiceError::RegistrationDrift(error.to_string()))
    }

    fn validate_alert(
        &self,
        request: &GithubDependabotReadRequest,
        alert: &DependabotAlert,
    ) -> Result<(), AlertFenceError> {
        let Some(binding) = self.scope.alert_binding(alert.alert_number) else {
            return Err(AlertFenceError::Scope("Dependabot alert allowlist"));
        };
        if request
            .alert_number
            .is_some_and(|number| number != alert.alert_number)
        {
            return Err(AlertFenceError::Scope("get alert number binding"));
        }
        if alert.alert_revision != binding.revision {
            return Err(AlertFenceError::StaleRevision);
        }
        if alert.package_ecosystem != binding.package_ecosystem
            || alert.dependency_digest != binding.dependency_digest
            || alert.package_digest != binding.package_digest
            || alert.manifest_digest != binding.manifest_digest
        {
            return Err(AlertFenceError::Scope("package or manifest digest binding"));
        }
        if !alert.matches_filter(&request.filter) {
            return Err(AlertFenceError::Scope("provider filter binding"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AlertFenceError {
    Scope(&'static str),
    StaleRevision,
}

fn aggregate_state(
    alerts: &[DependabotAlert],
    partial_reason: Option<PartialReason>,
    no_provider_errors: bool,
    not_modified: bool,
) -> DependabotEvidenceState {
    if not_modified {
        return DependabotEvidenceState::NotModified;
    }
    if partial_reason.is_some() {
        return DependabotEvidenceState::Partial;
    }
    if !no_provider_errors {
        return DependabotEvidenceState::ProviderUnknown;
    }
    if alerts.is_empty() {
        return DependabotEvidenceState::InsufficientData;
    }
    let states = alerts
        .iter()
        .map(|alert| alert.state)
        .collect::<BTreeSet<_>>();
    if states.len() == 1 {
        return match states.iter().next().copied() {
            Some(AlertState::Open) => DependabotEvidenceState::Open,
            Some(AlertState::Fixed) => DependabotEvidenceState::Fixed,
            Some(AlertState::Dismissed) => DependabotEvidenceState::Dismissed,
            Some(AlertState::AutoDismissed) => DependabotEvidenceState::AutoDismissed,
            None => DependabotEvidenceState::InsufficientData,
        };
    }
    if states.contains(&AlertState::Open) {
        DependabotEvidenceState::Open
    } else {
        DependabotEvidenceState::Partial
    }
}

pub type GithubDependabotService<T> = GithubDependabotResultService<T>;
pub type GithubDependabotServiceDefinition = GithubDependabotResultServiceDefinition;
pub type GithubDependabotResultProposal = GithubDependabotProposal;
pub type GithubDependabotServiceErrorAlias = GithubDependabotServiceError;
pub type GithubDependabotRegistrationReceipt = GithubDependabotRegistration;
pub type GithubDependabotProviderErrorEvidence = ProviderErrorEvidence;
pub type GithubDependabotTransportProvenance = TransportProvenance;
