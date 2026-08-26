use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use hartevo_connector_sdk::SecretReference;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BLOCKED_ENV_STATUS,
    types::{
        ConnectionEvidence, DescribeExecutionFixture, DescribeExecutionRequest, Digest,
        ExecutionMode, ExecutionReceipt, FailureEvidence, ObservationConsistency, OutputEvidence,
        ProviderAvailability, ProviderIdentity, ProviderProvenance, RegistrationBinding,
        SecretReferenceBinding, StartExecutionOutcome, StartExecutionProposal,
        StartExecutionReceipt, StepFunctionsMissionScope, TaskTokenCallback, TaskTokenReceipt,
        ValidationError,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepFunctionsAction {
    StartExecution,
    DescribeExecution,
    SendTaskSuccess,
    SendTaskFailure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer2Operation {
    LiveStartExecution,
    LiveDescribeExecution,
    SendTaskSuccess,
    SendTaskFailure,
    IndependentOutputReadback,
    AmbiguousStartRecovery,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedEnvironmentReason {
    MissingAwsCredentials,
    SigV4Failure,
    Throttled,
    Timeout,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SigV4HttpRequest {
    action: StepFunctionsAction,
    region: crate::AwsRegion,
    scope_digest: Digest,
    body_digest: Digest,
    authentication: SecretReferenceBinding,
}

impl SigV4HttpRequest {
    fn new(
        action: StepFunctionsAction,
        scope: &StepFunctionsMissionScope,
        body_digest: Digest,
        authentication: SecretReferenceBinding,
    ) -> Self {
        Self {
            action,
            region: scope.region().clone(),
            scope_digest: scope.binding_digest(),
            body_digest,
            authentication,
        }
    }

    pub const fn action(&self) -> StepFunctionsAction {
        self.action
    }

    pub fn region(&self) -> &crate::AwsRegion {
        &self.region
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn body_digest(&self) -> &Digest {
        &self.body_digest
    }

    pub fn authentication(&self) -> &SecretReferenceBinding {
        &self.authentication
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SigV4HttpResponse {
    status_code: u16,
    body_digest: Digest,
}

impl SigV4HttpResponse {
    pub fn new(status_code: u16, body_digest: Digest) -> Self {
        Self {
            status_code,
            body_digest,
        }
    }

    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    pub fn body_digest(&self) -> &Digest {
        &self.body_digest
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("HTTPS transport is unavailable in Layer 1")]
    Unavailable,
    #[error("SigV4 signing failed")]
    SigV4Rejected,
    #[error("AWS transport was throttled")]
    Throttled,
    #[error("AWS transport timed out")]
    Timeout,
    #[error("AWS transport returned HTTP status {0}")]
    HttpStatus(u16),
}

/// Layer-2 owns the actual HTTPS request and SigV4 signing implementation.
/// Layer 1 only creates [`SigV4HttpRequest`] values and never calls this seam.
pub trait HttpsSigV4Transport: fmt::Debug {
    fn send(&mut self, request: SigV4HttpRequest) -> Result<SigV4HttpResponse, TransportError>;
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderError {
    #[error("provider registration is revoked")]
    RegistrationRevoked,
    #[error("provider registration does not match the request")]
    RegistrationMismatch,
    #[error("provider request does not match the exact Mission scope")]
    ScopeMismatch,
    #[error("SecretReference is not scoped to the AWS account/provider")]
    AuthenticationScopeMismatch,
    #[error("{status}: {reason:?} for {operation:?}")]
    BlockedEnvironment {
        status: &'static str,
        reason: BlockedEnvironmentReason,
        operation: Layer2Operation,
    },
    #[error("native Step Functions operation remains a Layer-2 gap: {0:?}")]
    NativeGap(Layer2Operation),
    #[error("STANDARD execution name already exists with different input")]
    ExecutionAlreadyExistsDifferentInput,
    #[error("STANDARD execution name belongs to a closed execution")]
    ExecutionAlreadyExistsClosed,
    #[error("EXPRESS DescribeExecution is not supported by the AWS API")]
    ExpressDescribeUnsupported,
    #[error("fixture response was not supplied")]
    FixtureExhausted,
    #[error("fixture response violated the typed contract: {0}")]
    InvalidFixture(ValidationError),
    #[error("the provider observed eventual consistency; retry is required")]
    EventuallyConsistent,
    #[error("task-token callback is tampered or was never issued for this execution")]
    TaskTokenTampered,
    #[error("task-token callback was replayed")]
    TaskTokenReplay,
    #[error("task-token callback does not match the exact Mission scope")]
    TaskTokenScopeMismatch,
    #[error("task-token callback payload digest is missing")]
    TaskTokenPayloadMissing,
}

pub trait StepFunctionsProvider: fmt::Debug {
    fn registration(&self) -> &RegistrationBinding;

    fn provider_identity(&self) -> &ProviderIdentity {
        self.registration().provider()
    }

    fn provenance(&self) -> ProviderProvenance;

    fn availability(&self) -> ProviderAvailability;

    fn connection_evidence(&self) -> ConnectionEvidence {
        ConnectionEvidence::new(self.availability(), self.provenance(), self.registration())
    }

    fn prepare_start_execution(
        &self,
        proposal: &StartExecutionProposal,
    ) -> Result<SigV4HttpRequest, ProviderError>;

    fn prepare_describe_execution(
        &self,
        request: &DescribeExecutionRequest,
    ) -> Result<SigV4HttpRequest, ProviderError>;

    fn start_execution(
        &mut self,
        proposal: &StartExecutionProposal,
    ) -> Result<StartExecutionReceipt, ProviderError>;

    fn describe_execution(
        &mut self,
        request: &DescribeExecutionRequest,
    ) -> Result<crate::ExecutionStatusProjection, ProviderError>;

    fn project_task_token_callback(
        &mut self,
        callback: TaskTokenCallback,
    ) -> Result<TaskTokenReceipt, ProviderError>;
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RecordedProviderCall {
    StartExecution {
        mode: ExecutionMode,
        name: crate::ExecutionName,
        input_digest: Digest,
        idempotency_key: Digest,
    },
    DescribeExecution {
        execution_arn: crate::ExecutionArn,
    },
    TaskTokenCallback {
        execution_arn: crate::ExecutionArn,
        token_digest: Digest,
        kind: crate::TaskTokenCallbackKind,
    },
}

#[derive(Debug)]
pub struct RecordingStepFunctionsProvider {
    registration: RegistrationBinding,
    authentication: SecretReferenceBinding,
    provenance: ProviderProvenance,
    availability: ProviderAvailability,
    standard_by_name: BTreeMap<String, ExecutionReceipt>,
    closed_standard_executions: BTreeSet<crate::ExecutionArn>,
    describe_fixtures:
        BTreeMap<crate::ExecutionArn, VecDeque<Result<DescribeExecutionFixture, ProviderError>>>,
    task_tokens: BTreeMap<crate::ExecutionArn, BTreeMap<Digest, bool>>,
    calls: Vec<RecordedProviderCall>,
    next_fixture_ordinal: u64,
}

impl RecordingStepFunctionsProvider {
    pub fn new(
        registration: RegistrationBinding,
        secret: &SecretReference,
    ) -> Result<Self, ProviderError> {
        Self::new_with_provenance(
            registration,
            secret,
            ProviderProvenance::Fixture,
            ProviderAvailability::Fixture,
        )
    }

    pub fn loopback(
        registration: RegistrationBinding,
        secret: &SecretReference,
    ) -> Result<Self, ProviderError> {
        Self::new_with_provenance(
            registration,
            secret,
            ProviderProvenance::Loopback,
            ProviderAvailability::Loopback,
        )
    }

    fn new_with_provenance(
        registration: RegistrationBinding,
        secret: &SecretReference,
        provenance: ProviderProvenance,
        availability: ProviderAvailability,
    ) -> Result<Self, ProviderError> {
        registration
            .require_active()
            .map_err(|_| ProviderError::RegistrationRevoked)?;
        let authentication = SecretReferenceBinding::from_secret(secret, registration.scope())?;
        Ok(Self {
            registration,
            authentication,
            provenance,
            availability,
            standard_by_name: BTreeMap::new(),
            closed_standard_executions: BTreeSet::new(),
            describe_fixtures: BTreeMap::new(),
            task_tokens: BTreeMap::new(),
            calls: Vec::new(),
            next_fixture_ordinal: 0,
        })
    }

    pub fn push_describe_fixture(
        &mut self,
        execution: &ExecutionReceipt,
        fixture: Result<DescribeExecutionFixture, ProviderError>,
    ) {
        self.describe_fixtures
            .entry(execution.execution_arn().clone())
            .or_default()
            .push_back(fixture);
    }

    pub fn register_task_token(
        &mut self,
        execution: &ExecutionReceipt,
        token: &crate::TaskToken,
    ) -> Result<(), ProviderError> {
        self.ensure_execution_scope(execution)?;
        self.task_tokens
            .entry(execution.execution_arn().clone())
            .or_default()
            .insert(token.digest(), false);
        Ok(())
    }

    pub fn calls(&self) -> &[RecordedProviderCall] {
        &self.calls
    }

    pub fn mark_execution_closed(
        &mut self,
        execution: &ExecutionReceipt,
    ) -> Result<(), ProviderError> {
        self.ensure_execution_scope(execution)?;
        if execution.identity().mode() == ExecutionMode::Standard {
            self.closed_standard_executions
                .insert(execution.execution_arn().clone());
        }
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), ProviderError> {
        self.registration
            .require_active()
            .map_err(|_| ProviderError::RegistrationRevoked)
    }

    fn ensure_proposal(&self, proposal: &StartExecutionProposal) -> Result<(), ProviderError> {
        self.ensure_active()?;
        if proposal.registration_digest() != self.registration.registration_digest()
            || proposal.scope() != self.registration.scope()
        {
            return Err(ProviderError::RegistrationMismatch);
        }
        Ok(())
    }

    fn ensure_execution_scope(&self, execution: &ExecutionReceipt) -> Result<(), ProviderError> {
        self.ensure_active()?;
        if execution.registration_digest() != self.registration.registration_digest()
            || execution.scope() != self.registration.scope()
            || execution.provider() != self.registration.provider()
        {
            return Err(ProviderError::RegistrationMismatch);
        }
        Ok(())
    }

    fn start_key(proposal: &StartExecutionProposal) -> String {
        format!(
            "{}:{}",
            proposal.scope().binding_digest(),
            proposal.identity().name().as_str()
        )
    }

    fn body_digest_for_start(proposal: &StartExecutionProposal) -> Digest {
        Digest::from_parts(&[
            StepFunctionsAction::StartExecution.as_str(),
            proposal.scope().state_machine_arn().as_str(),
            proposal.identity().name().as_str(),
            proposal.identity().input_digest().as_str(),
        ])
    }

    fn body_digest_for_describe(request: &DescribeExecutionRequest) -> Digest {
        Digest::from_parts(&[
            StepFunctionsAction::DescribeExecution.as_str(),
            request.execution().execution_arn().as_str(),
        ])
    }
}

impl StepFunctionsProvider for RecordingStepFunctionsProvider {
    fn registration(&self) -> &RegistrationBinding {
        &self.registration
    }

    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn availability(&self) -> ProviderAvailability {
        self.availability
    }

    fn prepare_start_execution(
        &self,
        proposal: &StartExecutionProposal,
    ) -> Result<SigV4HttpRequest, ProviderError> {
        self.ensure_proposal(proposal)?;
        Ok(SigV4HttpRequest::new(
            StepFunctionsAction::StartExecution,
            proposal.scope(),
            Self::body_digest_for_start(proposal),
            self.authentication.clone(),
        ))
    }

    fn prepare_describe_execution(
        &self,
        request: &DescribeExecutionRequest,
    ) -> Result<SigV4HttpRequest, ProviderError> {
        self.ensure_execution_scope(request.execution())?;
        Ok(SigV4HttpRequest::new(
            StepFunctionsAction::DescribeExecution,
            request.execution().scope(),
            Self::body_digest_for_describe(request),
            self.authentication.clone(),
        ))
    }

    fn start_execution(
        &mut self,
        proposal: &StartExecutionProposal,
    ) -> Result<StartExecutionReceipt, ProviderError> {
        self.ensure_proposal(proposal)?;
        let identity = proposal.identity();
        self.calls.push(RecordedProviderCall::StartExecution {
            mode: identity.mode(),
            name: identity.name().clone(),
            input_digest: identity.input_digest().clone(),
            idempotency_key: identity.idempotency_key().clone(),
        });

        let key = Self::start_key(proposal);
        if identity.mode() == ExecutionMode::Standard
            && let Some(existing) = self.standard_by_name.get(&key)
        {
            if self
                .closed_standard_executions
                .contains(existing.execution_arn())
            {
                return Err(ProviderError::ExecutionAlreadyExistsClosed);
            }
            if existing.identity().input_digest() == identity.input_digest() {
                return Ok(StartExecutionReceipt::new(
                    StartExecutionOutcome::DuplicateSameInput,
                    existing.clone(),
                ));
            }
            return Err(ProviderError::ExecutionAlreadyExistsDifferentInput);
        }

        self.next_fixture_ordinal = self.next_fixture_ordinal.saturating_add(1);
        let execution_arn =
            crate::ExecutionArn::for_fixture(proposal.scope(), identity, self.next_fixture_ordinal)
                .map_err(ProviderError::InvalidFixture)?;
        let execution = ExecutionReceipt::new(
            proposal.scope().clone(),
            execution_arn,
            identity.clone(),
            &self.registration,
            self.provenance,
        )
        .map_err(ProviderError::InvalidFixture)?;
        if identity.mode() == ExecutionMode::Standard {
            self.standard_by_name.insert(key, execution.clone());
        }
        let outcome = if identity.mode() == ExecutionMode::Express {
            StartExecutionOutcome::ExpressNonIdempotent
        } else {
            StartExecutionOutcome::Started
        };
        Ok(StartExecutionReceipt::new(outcome, execution))
    }

    fn describe_execution(
        &mut self,
        request: &DescribeExecutionRequest,
    ) -> Result<crate::ExecutionStatusProjection, ProviderError> {
        self.ensure_execution_scope(request.execution())?;
        if request.execution().identity().mode() == ExecutionMode::Express {
            return Err(ProviderError::ExpressDescribeUnsupported);
        }
        self.calls.push(RecordedProviderCall::DescribeExecution {
            execution_arn: request.execution().execution_arn().clone(),
        });
        let fixture = self
            .describe_fixtures
            .get_mut(request.execution().execution_arn())
            .and_then(VecDeque::pop_front)
            .ok_or(ProviderError::FixtureExhausted)??;
        let projection = crate::ExecutionStatusProjection::from_fixture(
            request,
            fixture,
            &self.registration,
            self.provenance,
        )
        .map_err(ProviderError::InvalidFixture)?;
        if projection.status().is_terminal() {
            self.mark_execution_closed(request.execution())?;
        }
        Ok(projection)
    }

    fn project_task_token_callback(
        &mut self,
        callback: TaskTokenCallback,
    ) -> Result<TaskTokenReceipt, ProviderError> {
        self.ensure_active()?;
        if callback.scope() != self.registration.scope() {
            return Err(ProviderError::TaskTokenScopeMismatch);
        }
        let token_digest = callback.token_digest();
        self.calls.push(RecordedProviderCall::TaskTokenCallback {
            execution_arn: callback.execution_arn().clone(),
            token_digest: token_digest.clone(),
            kind: callback.kind(),
        });
        let tokens = self
            .task_tokens
            .get_mut(callback.execution_arn())
            .ok_or(ProviderError::TaskTokenTampered)?;
        let consumed = tokens
            .get_mut(&token_digest)
            .ok_or(ProviderError::TaskTokenTampered)?;
        if *consumed {
            return Err(ProviderError::TaskTokenReplay);
        }
        if callback.payload_digest().is_none() {
            return Err(ProviderError::TaskTokenPayloadMissing);
        }
        *consumed = true;
        Ok(TaskTokenReceipt::from_callback(
            &callback,
            &self.registration,
            self.provenance,
        ))
    }
}

pub type FixtureStepFunctionsProvider = RecordingStepFunctionsProvider;
pub type LoopbackStepFunctionsProvider = RecordingStepFunctionsProvider;

#[derive(Debug)]
pub struct NativeStepFunctionsProvider<T> {
    registration: RegistrationBinding,
    authentication: Option<SecretReferenceBinding>,
    transport: T,
}

impl<T> NativeStepFunctionsProvider<T>
where
    T: HttpsSigV4Transport,
{
    pub fn new(
        registration: RegistrationBinding,
        secret: &SecretReference,
        transport: T,
    ) -> Result<Self, ProviderError> {
        registration
            .require_active()
            .map_err(|_| ProviderError::RegistrationRevoked)?;
        let authentication = SecretReferenceBinding::from_secret(secret, registration.scope())?;
        Ok(Self {
            registration,
            authentication: Some(authentication),
            transport,
        })
    }

    pub fn without_credentials(registration: RegistrationBinding, transport: T) -> Self {
        Self {
            registration,
            authentication: None,
            transport,
        }
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    fn blocked_or_native(&self, operation: Layer2Operation) -> ProviderError {
        match self.authentication {
            Some(_) => ProviderError::NativeGap(operation),
            None => ProviderError::BlockedEnvironment {
                status: BLOCKED_ENV_STATUS,
                reason: BlockedEnvironmentReason::MissingAwsCredentials,
                operation,
            },
        }
    }

    fn ensure_active(&self) -> Result<(), ProviderError> {
        self.registration
            .require_active()
            .map_err(|_| ProviderError::RegistrationRevoked)
    }

    fn ensure_proposal(&self, proposal: &StartExecutionProposal) -> Result<(), ProviderError> {
        self.ensure_active()?;
        if proposal.registration_digest() != self.registration.registration_digest()
            || proposal.scope() != self.registration.scope()
        {
            return Err(ProviderError::RegistrationMismatch);
        }
        Ok(())
    }

    fn ensure_execution(&self, execution: &ExecutionReceipt) -> Result<(), ProviderError> {
        self.ensure_active()?;
        if execution.registration_digest() != self.registration.registration_digest()
            || execution.scope() != self.registration.scope()
        {
            return Err(ProviderError::RegistrationMismatch);
        }
        Ok(())
    }

    fn auth(&self) -> Result<SecretReferenceBinding, ProviderError> {
        self.authentication
            .clone()
            .ok_or_else(|| self.blocked_or_native(Layer2Operation::LiveStartExecution))
    }
}

impl<T> StepFunctionsProvider for NativeStepFunctionsProvider<T>
where
    T: HttpsSigV4Transport,
{
    fn registration(&self) -> &RegistrationBinding {
        &self.registration
    }

    fn provenance(&self) -> ProviderProvenance {
        if self.authentication.is_some() {
            ProviderProvenance::NativeLayer2Gap
        } else {
            ProviderProvenance::BlockedEnv
        }
    }

    fn availability(&self) -> ProviderAvailability {
        if self.authentication.is_some() {
            ProviderAvailability::NativeLayer2Gap
        } else {
            ProviderAvailability::BlockedEnv
        }
    }

    fn prepare_start_execution(
        &self,
        proposal: &StartExecutionProposal,
    ) -> Result<SigV4HttpRequest, ProviderError> {
        self.ensure_proposal(proposal)?;
        Ok(SigV4HttpRequest::new(
            StepFunctionsAction::StartExecution,
            proposal.scope(),
            Digest::from_parts(&[
                StepFunctionsAction::StartExecution.as_str(),
                proposal.scope().state_machine_arn().as_str(),
                proposal.identity().name().as_str(),
                proposal.identity().input_digest().as_str(),
            ]),
            self.auth()?,
        ))
    }

    fn prepare_describe_execution(
        &self,
        request: &DescribeExecutionRequest,
    ) -> Result<SigV4HttpRequest, ProviderError> {
        self.ensure_execution(request.execution())?;
        Ok(SigV4HttpRequest::new(
            StepFunctionsAction::DescribeExecution,
            request.execution().scope(),
            Digest::from_parts(&[
                StepFunctionsAction::DescribeExecution.as_str(),
                request.execution().execution_arn().as_str(),
            ]),
            self.authentication
                .clone()
                .ok_or_else(|| self.blocked_or_native(Layer2Operation::LiveDescribeExecution))?,
        ))
    }

    fn start_execution(
        &mut self,
        _proposal: &StartExecutionProposal,
    ) -> Result<StartExecutionReceipt, ProviderError> {
        Err(self.blocked_or_native(Layer2Operation::LiveStartExecution))
    }

    fn describe_execution(
        &mut self,
        _request: &DescribeExecutionRequest,
    ) -> Result<crate::ExecutionStatusProjection, ProviderError> {
        Err(self.blocked_or_native(Layer2Operation::LiveDescribeExecution))
    }

    fn project_task_token_callback(
        &mut self,
        _callback: TaskTokenCallback,
    ) -> Result<TaskTokenReceipt, ProviderError> {
        Err(self.blocked_or_native(Layer2Operation::SendTaskSuccess))
    }
}

#[derive(Clone, Debug)]
pub struct BlockedEnvStepFunctionsProvider {
    registration: RegistrationBinding,
    reason: BlockedEnvironmentReason,
}

impl BlockedEnvStepFunctionsProvider {
    pub fn new(registration: RegistrationBinding, reason: BlockedEnvironmentReason) -> Self {
        Self {
            registration,
            reason,
        }
    }

    fn error(&self, operation: Layer2Operation) -> ProviderError {
        ProviderError::BlockedEnvironment {
            status: BLOCKED_ENV_STATUS,
            reason: self.reason,
            operation,
        }
    }

    fn ensure_active(&self) -> Result<(), ProviderError> {
        self.registration
            .require_active()
            .map_err(|_| ProviderError::RegistrationRevoked)
    }
}

impl StepFunctionsProvider for BlockedEnvStepFunctionsProvider {
    fn registration(&self) -> &RegistrationBinding {
        &self.registration
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn availability(&self) -> ProviderAvailability {
        ProviderAvailability::BlockedEnv
    }

    fn prepare_start_execution(
        &self,
        _proposal: &StartExecutionProposal,
    ) -> Result<SigV4HttpRequest, ProviderError> {
        self.ensure_active()?;
        Err(self.error(Layer2Operation::LiveStartExecution))
    }

    fn prepare_describe_execution(
        &self,
        _request: &DescribeExecutionRequest,
    ) -> Result<SigV4HttpRequest, ProviderError> {
        self.ensure_active()?;
        Err(self.error(Layer2Operation::LiveDescribeExecution))
    }

    fn start_execution(
        &mut self,
        _proposal: &StartExecutionProposal,
    ) -> Result<StartExecutionReceipt, ProviderError> {
        self.ensure_active()?;
        Err(self.error(Layer2Operation::LiveStartExecution))
    }

    fn describe_execution(
        &mut self,
        _request: &DescribeExecutionRequest,
    ) -> Result<crate::ExecutionStatusProjection, ProviderError> {
        self.ensure_active()?;
        Err(self.error(Layer2Operation::LiveDescribeExecution))
    }

    fn project_task_token_callback(
        &mut self,
        _callback: TaskTokenCallback,
    ) -> Result<TaskTokenReceipt, ProviderError> {
        self.ensure_active()?;
        Err(self.error(Layer2Operation::SendTaskSuccess))
    }
}

impl StepFunctionsAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StartExecution => "StartExecution",
            Self::DescribeExecution => "DescribeExecution",
            Self::SendTaskSuccess => "SendTaskSuccess",
            Self::SendTaskFailure => "SendTaskFailure",
        }
    }
}

#[allow(dead_code)]
fn _keep_typed_evidence_imports(
    output: OutputEvidence,
    failure: FailureEvidence,
) -> (OutputEvidence, FailureEvidence, ObservationConsistency) {
    (output, failure, ObservationConsistency::Fresh)
}
