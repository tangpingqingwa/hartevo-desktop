//! Bounded AWS ECS deployment read, proposal, recording and verification service.

use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_ECS_CONTRACT_VERSION, AWS_ECS_PLUGIN_VERSION, AWS_ECS_SERVICE_ID, contract_digest,
    model::{
        DescribeServicesPage, DescribeServicesRequest, DescribeTaskDefinitionPage,
        DescribeTaskDefinitionRequest, DescribeTasksPage, DescribeTasksRequest, Digest,
        EcsDeploymentEvidence, EcsDeploymentScope, EcsReadRequest, EvidenceState, ListTasksPage,
        ListTasksRequest, ModelError, PaginationEvidence, PartialReason, ProviderRevision,
        ReadOperation, SecretReference, mission_projection, project_projection,
        work_product_projection,
    },
    provider::{
        EcsProvider, EcsProviderError, EcsProviderIdentity, EcsTransport, TransportFailure,
        is_access_loss,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("ECS registration model error: {0}")]
    Model(#[from] ModelError),
    #[error("ECS registration is already terminal")]
    Terminal,
    #[error("ECS registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EcsDeploymentServiceError {
    #[error("ECS service model error: {0}")]
    Model(#[from] ModelError),
    #[error("ECS provider error: {0}")]
    Provider(#[from] EcsProviderError),
    #[error("ECS registration is not active")]
    RegistrationRevoked,
    #[error("ECS registration is reversed")]
    RegistrationReversed,
    #[error("ECS registration has drifted: {0}")]
    RegistrationDrift(&'static str),
    #[error("ECS scope or permission fence mismatch: {0}")]
    ScopeMismatch(&'static str),
    #[error("ECS deployment generation is stale")]
    StaleDeploymentGeneration,
    #[error("ECS task-definition revision is stale")]
    StaleTaskDefinitionRevision,
    #[error("ECS evidence is stale or tampered")]
    EvidenceTampered,
    #[error("ECS proposal is stale or tampered")]
    ProposalTampered,
    #[error("ECS record is stale or tampered")]
    RecordTampered,
    #[error("ECS registration lifecycle error: {0}")]
    Registration(#[from] RegistrationError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub operations: [&'static str; 7],
    pub allowlisted_api_operations: [&'static str; 4],
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub task_mutation: bool,
    pub exec: bool,
    pub logs: bool,
    pub environment_export: bool,
    pub secret_export: bool,
    pub image_content_download: bool,
    pub outcome_authority: bool,
}

impl EcsCapabilities {
    pub const fn layer_one() -> Self {
        Self {
            service_id: AWS_ECS_SERVICE_ID,
            provider_id: crate::AWS_ECS_PROVIDER_ID,
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
                "DescribeServices",
                "DescribeTasks",
                "DescribeTaskDefinition",
                "ListTasks",
            ],
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            external_writes: false,
            task_mutation: false,
            exec: false,
            logs: false,
            environment_export: false,
            secret_export: false,
            image_content_download: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsDeploymentRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: crate::Revision,
    pub state: RegistrationState,
    pub reversible: bool,
    pub registration_digest: Digest,
}

pub type Registration = EcsDeploymentRegistration;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationBody<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a str,
    provider_version: &'a str,
    provider_revision: &'a ProviderRevision,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    consent_digest: &'a Digest,
    scope_digest: &'a Digest,
    evidence_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: crate::Revision,
    state: RegistrationState,
    reversible: bool,
}

impl EcsDeploymentRegistration {
    pub fn new(
        scope: &EcsDeploymentScope,
        secret: &SecretReference,
        provider: &EcsProviderIdentity,
    ) -> Result<Self, RegistrationError> {
        let evidence_digest = Digest::from_parts(
            "aws-ecs-evidence-policy/v1",
            &[
                AWS_ECS_CONTRACT_VERSION.to_owned(),
                crate::MAX_RESPONSE_BYTES.to_string(),
                crate::MAX_PAGES.to_string(),
                crate::PAGE_SIZE.to_string(),
                "stopped-reasons-digest-only".to_owned(),
                "no-container-definitions".to_owned(),
            ],
        );
        let mut value = Self {
            plugin_version: AWS_ECS_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_ECS_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: scope.permission.permission_digest.clone(),
            consent_digest: scope.consent.consent_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            evidence_digest,
            secret_reference_digest: secret.reference_digest(),
            registration_revision: crate::Revision::new(1)?,
            state: RegistrationState::Active,
            reversible: true,
            registration_digest: Digest::zero(),
        };
        value.registration_digest = value.recomputed_digest();
        Ok(value)
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub const fn is_revoked(&self) -> bool {
        matches!(self.state, RegistrationState::Revoked)
    }

    pub const fn is_reversed(&self) -> bool {
        matches!(self.state, RegistrationState::Reversed)
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::digest_serialized(&RegistrationBody {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_version: &self.provider_version,
            provider_revision: &self.provider_revision,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            permission_digest: &self.permission_digest,
            consent_digest: &self.consent_digest,
            scope_digest: &self.scope_digest,
            evidence_digest: &self.evidence_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registration_revision: self.registration_revision,
            state: self.state,
            reversible: self.reversible,
        })
    }

    pub fn validate(
        &self,
        scope: &EcsDeploymentScope,
        secret: &SecretReference,
        provider: &EcsProviderIdentity,
    ) -> Result<(), RegistrationError> {
        if self.plugin_version != AWS_ECS_PLUGIN_VERSION
            || self.contract_version != AWS_ECS_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.provider_version
            || self.provider_revision != provider.api_revision
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.permission_digest != scope.permission.permission_digest
            || self.consent_digest != scope.consent.consent_digest
            || self.scope_digest != scope.scope_digest
            || self.secret_reference_digest != secret.reference_digest()
            || !self.reversible
            || self.registration_revision.get() == 0
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(RegistrationError::Model(ModelError::ScopeMismatch {
                field: "registration digest binding",
            }));
        }
        Ok(())
    }

    fn transition(&mut self, state: RegistrationState) -> Result<(), RegistrationError> {
        if self.is_reversed() || (self.is_revoked() && state != RegistrationState::Active) {
            return Err(RegistrationError::Terminal);
        }
        let next = self
            .registration_revision
            .get()
            .checked_add(1)
            .ok_or(RegistrationError::RevisionOverflow)?;
        self.registration_revision = crate::Revision::new(next)?;
        self.state = state;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), RegistrationError> {
        if self.is_revoked() {
            return Err(RegistrationError::Terminal);
        }
        self.transition(RegistrationState::Revoked)
    }

    pub fn reverse(&mut self) -> Result<(), RegistrationError> {
        self.transition(RegistrationState::Reversed)
    }

    pub fn restore(&mut self) -> Result<(), RegistrationError> {
        if self.is_reversed() {
            return Err(RegistrationError::Terminal);
        }
        self.transition(RegistrationState::Active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsDeploymentReadResult {
    pub evidence: EcsDeploymentEvidence,
    pub page_digests: Vec<Digest>,
    pub read_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsDeploymentProposal {
    pub operation: ReadOperation,
    pub state: EvidenceState,
    pub evidence: EcsDeploymentEvidence,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub mission: crate::MissionProjection,
    pub project: crate::ProjectProjection,
    pub work_product: crate::WorkProductProjection,
    pub read_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
    pub proposal_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalBody<'a> {
    operation: ReadOperation,
    state: EvidenceState,
    evidence: &'a EcsDeploymentEvidence,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    mission: &'a crate::MissionProjection,
    project: &'a crate::ProjectProjection,
    work_product: &'a crate::WorkProductProjection,
    read_only: bool,
    live_execution: bool,
    connected: bool,
    native: bool,
    adopted_outcome: bool,
}

impl EcsDeploymentProposal {
    fn new(
        evidence: EcsDeploymentEvidence,
        registration_digest: Digest,
        scope: &EcsDeploymentScope,
    ) -> Self {
        let mut value = Self {
            operation: evidence.operation,
            state: evidence.state,
            evidence,
            registration_digest,
            scope_digest: scope.scope_digest.clone(),
            mission: mission_projection(&scope.mission),
            project: project_projection(&scope.project),
            work_product: work_product_projection(&scope.work_product),
            read_only: true,
            live_execution: false,
            connected: false,
            native: false,
            adopted_outcome: false,
            proposal_digest: Digest::zero(),
        };
        value.proposal_digest = value.recomputed_digest();
        value
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::digest_serialized(&ProposalBody {
            operation: self.operation,
            state: self.state,
            evidence: &self.evidence,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            mission: &self.mission,
            project: &self.project,
            work_product: &self.work_product,
            read_only: self.read_only,
            live_execution: self.live_execution,
            connected: self.connected,
            native: self.native,
            adopted_outcome: self.adopted_outcome,
        })
    }

    pub fn validate(&self) -> Result<(), EcsDeploymentServiceError> {
        self.evidence
            .validate()
            .map_err(|_| EcsDeploymentServiceError::EvidenceTampered)?;
        if self.operation != self.evidence.operation
            || self.state != self.evidence.state
            || !self.read_only
            || self.live_execution
            || self.connected
            || self.native
            || self.adopted_outcome
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(EcsDeploymentServiceError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsDeploymentRecord {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub state: EvidenceState,
    pub replayed: bool,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
    pub recording_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordBody<'a> {
    idempotency_key_digest: &'a Digest,
    proposal_digest: &'a Digest,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    state: EvidenceState,
    replayed: bool,
    durable_receipt: bool,
    connected: bool,
    native: bool,
    adopted_outcome: bool,
}

impl EcsDeploymentRecord {
    fn new(proposal: &EcsDeploymentProposal, key: &str, replayed: bool) -> Self {
        let mut value = Self {
            idempotency_key_digest: Digest::from_text(key),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digests.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            replayed,
            durable_receipt: false,
            connected: false,
            native: false,
            adopted_outcome: false,
            recording_digest: Digest::zero(),
        };
        value.recording_digest = value.recomputed_digest();
        value
    }

    pub(crate) fn new_for_consumer(proposal: &EcsDeploymentProposal, key: &str) -> Self {
        Self::new(proposal, key, false)
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::digest_serialized(&RecordBody {
            idempotency_key_digest: &self.idempotency_key_digest,
            proposal_digest: &self.proposal_digest,
            evidence_digest: &self.evidence_digest,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            state: self.state,
            replayed: self.replayed,
            durable_receipt: self.durable_receipt,
            connected: self.connected,
            native: self.native,
            adopted_outcome: self.adopted_outcome,
        })
    }

    pub fn validate(&self) -> Result<(), EcsDeploymentServiceError> {
        if self.durable_receipt
            || self.connected
            || self.native
            || self.adopted_outcome
            || self.recording_digest != self.recomputed_digest()
        {
            return Err(EcsDeploymentServiceError::RecordTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsDeploymentVerifiedRecord {
    pub verified: bool,
    pub state: EvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub recording_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
    pub verification_digest: Digest,
}

#[derive(Clone)]
pub struct EcsDeploymentResultService<T: EcsTransport> {
    scope: EcsDeploymentScope,
    secret_reference: SecretReference,
    provider: EcsProvider<T>,
    registration: EcsDeploymentRegistration,
}

pub type EcsDeploymentService<T> = EcsDeploymentResultService<T>;

impl<T: EcsTransport> fmt::Debug for EcsDeploymentResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EcsDeploymentResultService")
            .field("scope_digest", &self.scope.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T: EcsTransport> EcsDeploymentResultService<T> {
    pub fn new(
        scope: EcsDeploymentScope,
        secret_reference: SecretReference,
        provider: EcsProvider<T>,
    ) -> Result<Self, EcsDeploymentServiceError> {
        scope.validate()?;
        if secret_reference.scope_digest() != &scope.scope_digest
            || secret_reference.signing_region() != &scope.region.id
        {
            return Err(EcsDeploymentServiceError::ScopeMismatch(
                "secret reference scope or region",
            ));
        }
        let registration =
            EcsDeploymentRegistration::new(&scope, &secret_reference, provider.identity())?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
        })
    }

    pub fn register(
        scope: EcsDeploymentScope,
        secret_reference: SecretReference,
        provider: EcsProvider<T>,
    ) -> Result<Self, EcsDeploymentServiceError> {
        Self::new(scope, secret_reference, provider)
    }

    pub const fn describe_capabilities() -> EcsCapabilities {
        EcsCapabilities::layer_one()
    }

    pub fn scope(&self) -> &EcsDeploymentScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &EcsProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut EcsProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &EcsDeploymentRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret_reference.is_revoked()
    }

    pub fn revoke_registration(&mut self) -> Result<(), EcsDeploymentServiceError> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn reverse_registration(&mut self) -> Result<(), EcsDeploymentServiceError> {
        self.registration.reverse()?;
        Ok(())
    }

    pub fn restore_registration(&mut self) -> Result<(), EcsDeploymentServiceError> {
        self.registration.restore()?;
        Ok(())
    }

    pub fn revoke_secret_reference(&mut self) -> Result<(), EcsDeploymentServiceError> {
        self.secret_reference.revoke()?;
        Ok(())
    }

    fn ensure_active_and_bound(&self) -> Result<(), EcsDeploymentServiceError> {
        if self.registration.is_reversed() {
            return Err(EcsDeploymentServiceError::RegistrationReversed);
        }
        if !self.registration.is_active() {
            return Err(EcsDeploymentServiceError::RegistrationRevoked);
        }
        self.secret_reference.ensure_active()?;
        self.scope.validate()?;
        if self
            .registration
            .validate(
                &self.scope,
                &self.secret_reference,
                self.provider.identity(),
            )
            .is_err()
        {
            return Err(EcsDeploymentServiceError::RegistrationDrift(
                "registration/version/provider/scope/secret binding",
            ));
        }
        Ok(())
    }

    pub fn read(
        &mut self,
        request: impl Into<EcsReadRequest>,
    ) -> Result<EcsDeploymentReadResult, EcsDeploymentServiceError> {
        self.ensure_active_and_bound()?;
        let request = request.into();
        request.validate_against(&self.scope)?;
        let operation = request.operation();
        let mut current = request.clone();
        let mut services = Vec::new();
        let mut tasks = Vec::new();
        let mut task_definition = None;
        let mut page_digests = Vec::new();
        let mut cursor_digests = Vec::new();
        let mut seen_items = BTreeSet::new();
        let mut seen_cursors = BTreeSet::new();
        let mut pages_observed = 0_u16;
        let mut requests_observed = 0_u16;
        let mut retry_count = 0_u8;
        let mut response_bytes = 0_usize;
        let mut partial_reason = None;
        let mut provider_errors = Vec::new();
        let mut terminal_state = None;
        let mut next_cursor = None;

        loop {
            let max_requests = request_max_requests(&current);
            if requests_observed >= max_requests {
                partial_reason = Some(PartialReason::RequestBudget);
                break;
            }
            requests_observed += 1;
            let page_result = match &current {
                EcsReadRequest::DescribeServices(value) => self
                    .provider
                    .describe_services(value)
                    .map(EcsPage::Services),
                EcsReadRequest::DescribeTasks(value) => {
                    self.provider.describe_tasks(value).map(EcsPage::Tasks)
                }
                EcsReadRequest::DescribeTaskDefinition(value) => self
                    .provider
                    .describe_task_definition(value)
                    .map(EcsPage::TaskDefinition),
                EcsReadRequest::ListTasks(value) => {
                    self.provider.list_tasks(value).map(EcsPage::ListTasks)
                }
            };
            retry_count = retry_count.saturating_add(self.provider.last_retry_count());
            match page_result {
                Ok(page) => {
                    let (page_number, page_bytes, page_digest, page_cursor) = page.metadata();
                    if page_number != pages_observed + 1 {
                        return Err(EcsDeploymentServiceError::Provider(
                            EcsProviderError::PageBinding,
                        ));
                    }
                    pages_observed += 1;
                    response_bytes = response_bytes.saturating_add(page_bytes);
                    if response_bytes > request_max_response_bytes(&current) {
                        partial_reason = Some(PartialReason::ResponseTooLarge);
                        break;
                    }
                    page_digests.push(page_digest);
                    match page {
                        EcsPage::Services(page) => {
                            for service in page.services {
                                service
                                    .validate_against(&self.scope)
                                    .map_err(map_observation_error)?;
                                if service.status == crate::ServiceStatus::Unknown
                                    || service.deployment_status
                                        == crate::DeploymentRolloutState::Unknown
                                {
                                    partial_reason = Some(PartialReason::UnknownLifecycleState);
                                }
                                if !seen_items.insert(service.observation_digest.clone()) {
                                    return Err(EcsDeploymentServiceError::Provider(
                                        EcsProviderError::DuplicateItem,
                                    ));
                                }
                                services.push(service);
                            }
                        }
                        EcsPage::Tasks(page) => {
                            for task in page.tasks {
                                task.validate_against(&self.scope)
                                    .map_err(map_observation_error)?;
                                if task.last_status == crate::TaskLastStatus::Unknown {
                                    partial_reason = Some(PartialReason::UnknownLifecycleState);
                                }
                                if !seen_items.insert(task.observation_digest.clone()) {
                                    return Err(EcsDeploymentServiceError::Provider(
                                        EcsProviderError::DuplicateItem,
                                    ));
                                }
                                tasks.push(task);
                            }
                        }
                        EcsPage::TaskDefinition(page) => {
                            page.task_definition
                                .validate_against(&self.scope)
                                .map_err(map_observation_error)?;
                            task_definition = Some(page.task_definition);
                        }
                        EcsPage::ListTasks(page) => {
                            for task in page.tasks {
                                task.validate_against(&self.scope)
                                    .map_err(map_observation_error)?;
                                if task.last_status == crate::TaskLastStatus::Unknown {
                                    partial_reason = Some(PartialReason::UnknownLifecycleState);
                                }
                                if !seen_items.insert(task.observation_digest.clone()) {
                                    return Err(EcsDeploymentServiceError::Provider(
                                        EcsProviderError::DuplicateItem,
                                    ));
                                }
                                tasks.push(task);
                            }
                        }
                    }
                    let item_count =
                        services.len() + tasks.len() + usize::from(task_definition.is_some());
                    if item_count > request_max_items(&current) {
                        partial_reason = Some(PartialReason::ItemBudget);
                        match operation {
                            ReadOperation::DescribeServices => {
                                services.truncate(request_max_items(&current));
                            }
                            _ => tasks.truncate(request_max_items(&current)),
                        }
                        break;
                    }
                    retry_count = retry_count.saturating_add(0);
                    let Some(cursor) = page_cursor else {
                        break;
                    };
                    cursor_digests.push(cursor.token_digest().clone());
                    if !seen_cursors.insert(cursor.token_digest().clone()) {
                        partial_reason = Some(PartialReason::CursorReplay);
                        break;
                    }
                    if pages_observed >= request_max_pages(&current) {
                        partial_reason = Some(PartialReason::PageBudget);
                        next_cursor = Some(cursor);
                        break;
                    }
                    next_cursor = Some(cursor.clone());
                    current = next_request_with_cursor(current, cursor)?;
                }
                Err(EcsProviderError::Transport(error)) => {
                    provider_errors.push(error.evidence());
                    terminal_state = Some(if is_access_loss(&error) {
                        EvidenceState::AccessLoss
                    } else {
                        match error.failure {
                            TransportFailure::NotFound => EvidenceState::NotFound,
                            TransportFailure::Throttled => EvidenceState::Throttled,
                            _ => EvidenceState::ProviderUnknown,
                        }
                    });
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }

        let state = terminal_state.unwrap_or_else(|| {
            if partial_reason.is_some() {
                EvidenceState::Partial
            } else {
                EvidenceState::Complete
            }
        });
        let filter_digest = request_filter_digest(&request);
        let cursor_digest = match &request {
            EcsReadRequest::ListTasks(value) => {
                value.cursor.as_ref().map(crate::OpaqueCursor::digest)
            }
            _ => None,
        };
        let pagination = PaginationEvidence {
            pages_observed,
            requests_observed,
            items_observed: services.len() + tasks.len() + usize::from(task_definition.is_some()),
            complete: matches!(state, EvidenceState::Complete) && partial_reason.is_none(),
            truncated: partial_reason.is_some(),
            cursor_digests,
            filter_digest: filter_digest.clone(),
        };
        let evidence = EcsDeploymentEvidence::new(
            operation,
            state,
            services,
            tasks,
            task_definition,
            pagination,
            provider_errors,
            Digest::from_text(AWS_ECS_PLUGIN_VERSION),
            contract_digest(),
            self.provider.identity().provider_digest.clone(),
            self.provider.identity().api_digest.clone(),
            self.provider.identity().api_revision.clone(),
            self.scope.permission.permission_digest.clone(),
            self.scope.consent.consent_digest.clone(),
            self.scope.scope_digest.clone(),
            filter_digest,
            cursor_digest,
            page_digests.clone(),
        );
        let read_digest = Digest::from_parts(
            "aws-ecs-read/v1",
            &[
                evidence.digests.evidence_digest.as_str().to_owned(),
                retry_count.to_string(),
                response_bytes.to_string(),
                next_cursor
                    .as_ref()
                    .map_or_else(String::new, |cursor| cursor.digest().as_str().to_owned()),
            ],
        );
        Ok(EcsDeploymentReadResult {
            evidence,
            page_digests,
            read_digest,
        })
    }

    pub fn read_describe_services(
        &mut self,
    ) -> Result<EcsDeploymentReadResult, EcsDeploymentServiceError> {
        self.read(DescribeServicesRequest::for_scope(
            &self.scope,
            crate::ReadBounds::default(),
        )?)
    }

    pub fn read_describe_tasks(
        &mut self,
    ) -> Result<EcsDeploymentReadResult, EcsDeploymentServiceError> {
        self.read(DescribeTasksRequest::for_scope(
            &self.scope,
            crate::ReadBounds::default(),
        )?)
    }

    pub fn read_describe_task_definition(
        &mut self,
    ) -> Result<EcsDeploymentReadResult, EcsDeploymentServiceError> {
        self.read(DescribeTaskDefinitionRequest::for_scope(
            &self.scope,
            crate::ReadBounds::default(),
        )?)
    }

    pub fn read_list_tasks(
        &mut self,
        filter: crate::TaskFilter,
    ) -> Result<EcsDeploymentReadResult, EcsDeploymentServiceError> {
        self.read(ListTasksRequest::for_scope(
            &self.scope,
            filter,
            crate::ReadBounds::default(),
        )?)
    }

    pub fn propose(
        &mut self,
        request: impl Into<EcsReadRequest>,
    ) -> Result<EcsDeploymentProposal, EcsDeploymentServiceError> {
        let result = self.read(request)?;
        Ok(EcsDeploymentProposal::new(
            result.evidence,
            self.registration.registration_digest.clone(),
            &self.scope,
        ))
    }

    pub fn record(
        &self,
        proposal: &EcsDeploymentProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<EcsDeploymentRecord, EcsDeploymentServiceError> {
        self.ensure_active_and_bound()?;
        if idempotency_key.as_ref().is_empty()
            || idempotency_key.as_ref().len() > crate::MAX_IDENTIFIER_BYTES
        {
            return Err(EcsDeploymentServiceError::Model(ModelError::Invalid {
                field: "idempotency key",
            }));
        }
        self.verify_proposal(proposal)?;
        Ok(EcsDeploymentRecord::new(
            proposal,
            idempotency_key.as_ref(),
            false,
        ))
    }

    pub fn verify(
        &self,
        proposal: &EcsDeploymentProposal,
        record: &EcsDeploymentRecord,
    ) -> Result<EcsDeploymentVerifiedRecord, EcsDeploymentServiceError> {
        self.ensure_active_and_bound()?;
        self.verify_proposal(proposal)?;
        record.validate()?;
        if record.proposal_digest != proposal.proposal_digest
            || record.registration_digest != self.registration.registration_digest
            || record.scope_digest != self.scope.scope_digest
        {
            return Err(EcsDeploymentServiceError::RecordTampered);
        }
        let verification_digest = Digest::from_parts(
            "aws-ecs-verification/v1",
            &[
                proposal.proposal_digest.as_str().to_owned(),
                record.recording_digest.as_str().to_owned(),
            ],
        );
        Ok(EcsDeploymentVerifiedRecord {
            verified: true,
            state: proposal.state,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digests.evidence_digest.clone(),
            recording_digest: record.recording_digest.clone(),
            connected: false,
            native: false,
            adopted_outcome: false,
            verification_digest,
        })
    }

    fn verify_proposal(
        &self,
        proposal: &EcsDeploymentProposal,
    ) -> Result<(), EcsDeploymentServiceError> {
        proposal.validate()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.scope_digest != self.scope.scope_digest
            || proposal.mission != mission_projection(&self.scope.mission)
            || proposal.project != project_projection(&self.scope.project)
            || proposal.work_product != work_product_projection(&self.scope.work_product)
            || proposal.evidence.digests.permission_digest
                != self.scope.permission.permission_digest
            || proposal.evidence.digests.consent_digest != self.scope.consent.consent_digest
        {
            return Err(EcsDeploymentServiceError::ScopeMismatch(
                "proposal registration, Mission or scope fence",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum EcsPage {
    Services(DescribeServicesPage),
    Tasks(DescribeTasksPage),
    TaskDefinition(DescribeTaskDefinitionPage),
    ListTasks(ListTasksPage),
}

impl EcsPage {
    fn metadata(&self) -> (u16, usize, Digest, Option<crate::OpaqueCursor>) {
        match self {
            Self::Services(page) => (
                page.page_number,
                page.response_bytes,
                page.page_digest.clone(),
                page.next_cursor.clone(),
            ),
            Self::Tasks(page) => (
                page.page_number,
                page.response_bytes,
                page.page_digest.clone(),
                None,
            ),
            Self::TaskDefinition(page) => (
                page.page_number,
                page.response_bytes,
                page.page_digest.clone(),
                None,
            ),
            Self::ListTasks(page) => (
                page.page_number,
                page.response_bytes,
                page.page_digest.clone(),
                page.next_cursor.clone(),
            ),
        }
    }
}

fn request_max_pages(request: &EcsReadRequest) -> u16 {
    match request {
        EcsReadRequest::DescribeServices(value) => value.bounds.max_pages,
        EcsReadRequest::DescribeTasks(value) => value.bounds.max_pages,
        EcsReadRequest::DescribeTaskDefinition(value) => value.bounds.max_pages,
        EcsReadRequest::ListTasks(value) => value.max_pages,
    }
}

fn request_max_requests(request: &EcsReadRequest) -> u16 {
    match request {
        EcsReadRequest::DescribeServices(value) => value.bounds.max_requests,
        EcsReadRequest::DescribeTasks(value) => value.bounds.max_requests,
        EcsReadRequest::DescribeTaskDefinition(value) => value.bounds.max_requests,
        EcsReadRequest::ListTasks(value) => value.max_requests,
    }
}

fn request_max_items(request: &EcsReadRequest) -> usize {
    match request {
        EcsReadRequest::DescribeServices(value) => value.bounds.max_items,
        EcsReadRequest::DescribeTasks(value) => value.bounds.max_items,
        EcsReadRequest::DescribeTaskDefinition(_) => 1,
        EcsReadRequest::ListTasks(value) => value.max_items,
    }
}

fn request_max_response_bytes(request: &EcsReadRequest) -> usize {
    match request {
        EcsReadRequest::DescribeServices(value) => value.bounds.max_response_bytes,
        EcsReadRequest::DescribeTasks(value) => value.bounds.max_response_bytes,
        EcsReadRequest::DescribeTaskDefinition(value) => value.bounds.max_response_bytes,
        EcsReadRequest::ListTasks(value) => value.max_response_bytes,
    }
}

fn request_filter_digest(request: &EcsReadRequest) -> Digest {
    match request {
        EcsReadRequest::ListTasks(value) => value.filter.digest(),
        _ => Digest::from_parts(
            "aws-ecs-filter/v1",
            &[request.request_digest().as_str().to_owned()],
        ),
    }
}

fn next_request_with_cursor(
    request: EcsReadRequest,
    cursor: crate::OpaqueCursor,
) -> Result<EcsReadRequest, EcsDeploymentServiceError> {
    match request {
        EcsReadRequest::ListTasks(value) => {
            Ok(EcsReadRequest::ListTasks(value.with_cursor(Some(cursor))?))
        }
        EcsReadRequest::DescribeServices(_) => {
            Err(EcsDeploymentServiceError::Model(ModelError::Invalid {
                field: "DescribeServices pagination",
            }))
        }
        EcsReadRequest::DescribeTasks(_) | EcsReadRequest::DescribeTaskDefinition(_) => {
            Err(EcsDeploymentServiceError::Model(ModelError::Invalid {
                field: "non-paginated ECS operation cursor",
            }))
        }
    }
}

fn map_observation_error(error: ModelError) -> EcsDeploymentServiceError {
    match error {
        ModelError::ScopeMismatch {
            field: "service deployment or task-definition revision",
        } => EcsDeploymentServiceError::StaleDeploymentGeneration,
        ModelError::ScopeMismatch {
            field: "task or task-definition revision" | "task-definition family or revision",
        } => EcsDeploymentServiceError::StaleTaskDefinitionRevision,
        ModelError::InvalidDigest { .. } => EcsDeploymentServiceError::EvidenceTampered,
        _ => EcsDeploymentServiceError::ScopeMismatch("normalized ECS observation"),
    }
}

pub type AwsEcsDeploymentResultService<T> = EcsDeploymentResultService<T>;
pub type AwsEcsDeploymentServiceError = EcsDeploymentServiceError;
