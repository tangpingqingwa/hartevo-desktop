use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::error::{AwsSsmAutomationError, AwsSsmAutomationTransportError};
use crate::model::{
    AutomationExecutionMetadata, AutomationStepMetadata, AutomationStepName, AwsSsmAutomationScope,
    DescribeAutomationExecutionsRequest, DescribeAutomationExecutionsResponse,
    DescribeAutomationStepExecutionsRequest, DescribeAutomationStepExecutionsResponse, Digest,
    GetAutomationExecutionRequest, GetAutomationExecutionResponse, ProviderErrorEvidence,
    TransportProvenance,
};
use crate::{PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID};

pub type ProviderResult<T> = std::result::Result<T, AwsSsmAutomationProviderError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsSsmAutomationProviderError {
    #[error("AWS SSM Automation provider definition is invalid")]
    InvalidDefinition,
    #[error("AWS SSM Automation provider request is invalid: {0}")]
    Request(#[from] AwsSsmAutomationError),
    #[error("AWS SSM Automation transport failed: {0}")]
    Transport(#[from] AwsSsmAutomationTransportError),
    #[error("AWS SSM Automation provider response is invalid")]
    InvalidResponse,
}

impl AwsSsmAutomationProviderError {
    pub fn evidence(&self) -> ProviderErrorEvidence {
        match self {
            Self::Transport(error) => ProviderErrorEvidence::from_transport(error),
            Self::Request(error) => ProviderErrorEvidence {
                kind: crate::model::ProviderErrorKind::InvalidResponse,
                status_code: None,
                error_digest: Digest::from_parts(
                    "hartevo-aws-ssm-automation-provider-request-error/v1",
                    &[("error", error.to_string())],
                ),
            },
            Self::InvalidDefinition => ProviderErrorEvidence {
                kind: crate::model::ProviderErrorKind::InvalidResponse,
                status_code: None,
                error_digest: Digest::from_text("InvalidProviderDefinition"),
            },
            Self::InvalidResponse => ProviderErrorEvidence {
                kind: crate::model::ProviderErrorKind::InvalidResponse,
                status_code: None,
                error_digest: Digest::from_text("InvalidProviderResponse"),
            },
        }
    }

    pub fn transport_error(&self) -> Option<&AwsSsmAutomationTransportError> {
        match self {
            Self::Transport(error) => Some(error),
            Self::InvalidDefinition | Self::Request(_) | Self::InvalidResponse => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSsmAutomationProviderDefinition {
    pub provider_id: String,
    pub version: String,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub allowlisted_operations: [&'static str; 3],
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
}

impl AwsSsmAutomationProviderDefinition {
    pub fn baseline() -> Self {
        let allowlisted_operations = [
            "DescribeAutomationExecutions",
            "GetAutomationExecution",
            "DescribeAutomationStepExecutions",
        ];
        let provider_digest = Digest::from_parts(
            "hartevo-aws-ssm-automation-provider/v1",
            &[
                ("id", PROVIDER_ID.to_owned()),
                ("version", PLUGIN_VERSION.to_owned()),
                ("revision", PROVIDER_API_REVISION.to_owned()),
            ],
        );
        let api_digest = Digest::from_parts(
            "hartevo-aws-ssm-automation-api/v1",
            &[
                ("operation0", allowlisted_operations[0].to_owned()),
                ("operation1", allowlisted_operations[1].to_owned()),
                ("operation2", allowlisted_operations[2].to_owned()),
            ],
        );
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            version: PLUGIN_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            provider_digest,
            api_digest,
            allowlisted_operations,
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
        }
    }

    pub fn validate(&self) -> ProviderResult<()> {
        let baseline = Self::baseline();
        if self != &baseline {
            Err(AwsSsmAutomationProviderError::InvalidDefinition)
        } else {
            Ok(())
        }
    }
}

/// Layer-1 transports are deliberately limited to deterministic fixture,
/// recording, loopback, and `BLOCKED_ENV` seams.
pub trait AwsSsmAutomationTransport {
    fn provenance(&self) -> TransportProvenance;

    fn describe_automation_executions(
        &mut self,
        request: &DescribeAutomationExecutionsRequest,
    ) -> ProviderResult<DescribeAutomationExecutionsResponse>;

    fn get_automation_execution(
        &mut self,
        request: &GetAutomationExecutionRequest,
    ) -> ProviderResult<GetAutomationExecutionResponse>;

    fn describe_automation_step_executions(
        &mut self,
        request: &DescribeAutomationStepExecutionsRequest,
    ) -> ProviderResult<DescribeAutomationStepExecutionsResponse>;
}

pub struct AwsSsmAutomationProvider<T>
where
    T: AwsSsmAutomationTransport,
{
    transport: T,
    definition: AwsSsmAutomationProviderDefinition,
}

impl<T> fmt::Debug for AwsSsmAutomationProvider<T>
where
    T: AwsSsmAutomationTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSsmAutomationProvider")
            .field("provenance", &self.transport.provenance())
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T> AwsSsmAutomationProvider<T>
where
    T: AwsSsmAutomationTransport,
{
    pub fn new(transport: T) -> ProviderResult<Self> {
        let definition = AwsSsmAutomationProviderDefinition::baseline();
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsSsmAutomationProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn describe_automation_executions(
        &mut self,
        request: &DescribeAutomationExecutionsRequest,
    ) -> ProviderResult<DescribeAutomationExecutionsResponse> {
        let response = self.transport.describe_automation_executions(request)?;
        self.validate_provenance(response.provenance)?;
        response
            .validate_for(request)
            .map_err(|_| AwsSsmAutomationProviderError::InvalidResponse)?;
        Ok(response)
    }

    pub fn get_automation_execution(
        &mut self,
        request: &GetAutomationExecutionRequest,
    ) -> ProviderResult<GetAutomationExecutionResponse> {
        let response = self.transport.get_automation_execution(request)?;
        self.validate_provenance(response.provenance)?;
        response
            .validate_for(request)
            .map_err(|_| AwsSsmAutomationProviderError::InvalidResponse)?;
        Ok(response)
    }

    pub fn describe_automation_step_executions(
        &mut self,
        request: &DescribeAutomationStepExecutionsRequest,
    ) -> ProviderResult<DescribeAutomationStepExecutionsResponse> {
        let response = self
            .transport
            .describe_automation_step_executions(request)?;
        self.validate_provenance(response.provenance)?;
        response
            .validate_for(request)
            .map_err(|_| AwsSsmAutomationProviderError::InvalidResponse)?;
        Ok(response)
    }

    fn validate_provenance(&self, provenance: TransportProvenance) -> ProviderResult<()> {
        if provenance != self.transport.provenance()
            || provenance.connected()
            || provenance.native()
            || provenance.first_party()
            || provenance.provider_receipt()
        {
            return Err(AwsSsmAutomationProviderError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct RecordingAwsSsmAutomationTransport {
    executions: VecDeque<ProviderResult<DescribeAutomationExecutionsResponse>>,
    gets: VecDeque<ProviderResult<GetAutomationExecutionResponse>>,
    steps: VecDeque<ProviderResult<DescribeAutomationStepExecutionsResponse>>,
}

impl RecordingAwsSsmAutomationTransport {
    pub fn push_describe_automation_executions(
        &mut self,
        response: ProviderResult<DescribeAutomationExecutionsResponse>,
    ) {
        self.executions.push_back(response);
    }

    pub fn push_get_automation_execution(
        &mut self,
        response: ProviderResult<GetAutomationExecutionResponse>,
    ) {
        self.gets.push_back(response);
    }

    pub fn push_describe_automation_step_executions(
        &mut self,
        response: ProviderResult<DescribeAutomationStepExecutionsResponse>,
    ) {
        self.steps.push_back(response);
    }

    pub fn push_execution_error(&mut self, error: AwsSsmAutomationTransportError) {
        self.executions
            .push_back(Err(AwsSsmAutomationProviderError::Transport(error)));
    }

    pub fn push_get_error(&mut self, error: AwsSsmAutomationTransportError) {
        self.gets
            .push_back(Err(AwsSsmAutomationProviderError::Transport(error)));
    }

    pub fn push_step_error(&mut self, error: AwsSsmAutomationTransportError) {
        self.steps
            .push_back(Err(AwsSsmAutomationProviderError::Transport(error)));
    }
}

impl AwsSsmAutomationTransport for RecordingAwsSsmAutomationTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn describe_automation_executions(
        &mut self,
        _request: &DescribeAutomationExecutionsRequest,
    ) -> ProviderResult<DescribeAutomationExecutionsResponse> {
        self.executions
            .pop_front()
            .unwrap_or(Err(AwsSsmAutomationProviderError::Transport(
                AwsSsmAutomationTransportError::Unknown,
            )))
    }

    fn get_automation_execution(
        &mut self,
        _request: &GetAutomationExecutionRequest,
    ) -> ProviderResult<GetAutomationExecutionResponse> {
        self.gets
            .pop_front()
            .unwrap_or(Err(AwsSsmAutomationProviderError::Transport(
                AwsSsmAutomationTransportError::Unknown,
            )))
    }

    fn describe_automation_step_executions(
        &mut self,
        _request: &DescribeAutomationStepExecutionsRequest,
    ) -> ProviderResult<DescribeAutomationStepExecutionsResponse> {
        self.steps
            .pop_front()
            .unwrap_or(Err(AwsSsmAutomationProviderError::Transport(
                AwsSsmAutomationTransportError::Unknown,
            )))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureAwsSsmAutomationTransport {
    scope: AwsSsmAutomationScope,
    observed_at: DateTime<Utc>,
}

impl FixtureAwsSsmAutomationTransport {
    pub fn for_scope(scope: &AwsSsmAutomationScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn execution(&self) -> ProviderResult<AutomationExecutionMetadata> {
        AutomationExecutionMetadata::new(
            self.scope.execution_id.clone(),
            self.scope.document_name.clone(),
            self.scope.document_version.clone(),
            1,
            self.scope.target.clone(),
            crate::model::AutomationExecutionStatus::Success,
            self.observed_at - Duration::minutes(2),
            self.observed_at,
            Some("fixture-output-not-retained"),
            None,
        )
        .map_err(AwsSsmAutomationProviderError::Request)
    }

    fn step(&self) -> ProviderResult<AutomationStepMetadata> {
        AutomationStepMetadata::new(
            self.scope
                .step_name
                .clone()
                .unwrap_or(AutomationStepName::new("main").expect("fixture step")),
            1,
            crate::model::AutomationExecutionStatus::Success,
            self.scope.target.clone(),
            self.observed_at - Duration::minutes(1),
            self.observed_at,
            Some("fixture-step-output-not-retained"),
            None,
        )
        .map_err(AwsSsmAutomationProviderError::Request)
    }
}

impl AwsSsmAutomationTransport for FixtureAwsSsmAutomationTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn describe_automation_executions(
        &mut self,
        request: &DescribeAutomationExecutionsRequest,
    ) -> ProviderResult<DescribeAutomationExecutionsResponse> {
        let execution = self.execution()?;
        DescribeAutomationExecutionsResponse::new(
            request,
            [execution],
            None,
            true,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(AwsSsmAutomationProviderError::Request)
    }

    fn get_automation_execution(
        &mut self,
        request: &GetAutomationExecutionRequest,
    ) -> ProviderResult<GetAutomationExecutionResponse> {
        let execution = self.execution()?;
        Ok(GetAutomationExecutionResponse::new(
            request,
            execution,
            512,
            TransportProvenance::Fixture,
        ))
    }

    fn describe_automation_step_executions(
        &mut self,
        request: &DescribeAutomationStepExecutionsRequest,
    ) -> ProviderResult<DescribeAutomationStepExecutionsResponse> {
        let step = self.step()?;
        DescribeAutomationStepExecutionsResponse::new(
            request,
            [step],
            None,
            true,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(AwsSsmAutomationProviderError::Request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackAwsSsmAutomationTransport {
    fixture: FixtureAwsSsmAutomationTransport,
}

impl LoopbackAwsSsmAutomationTransport {
    pub fn for_scope(scope: &AwsSsmAutomationScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            fixture: FixtureAwsSsmAutomationTransport::for_scope(scope, observed_at),
        }
    }
}

impl AwsSsmAutomationTransport for LoopbackAwsSsmAutomationTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn describe_automation_executions(
        &mut self,
        request: &DescribeAutomationExecutionsRequest,
    ) -> ProviderResult<DescribeAutomationExecutionsResponse> {
        let execution = self.fixture.execution()?;
        DescribeAutomationExecutionsResponse::new(
            request,
            [execution],
            None,
            true,
            512,
            TransportProvenance::Loopback,
        )
        .map_err(AwsSsmAutomationProviderError::Request)
    }

    fn get_automation_execution(
        &mut self,
        request: &GetAutomationExecutionRequest,
    ) -> ProviderResult<GetAutomationExecutionResponse> {
        let execution = self.fixture.execution()?;
        Ok(GetAutomationExecutionResponse::new(
            request,
            execution,
            512,
            TransportProvenance::Loopback,
        ))
    }

    fn describe_automation_step_executions(
        &mut self,
        request: &DescribeAutomationStepExecutionsRequest,
    ) -> ProviderResult<DescribeAutomationStepExecutionsResponse> {
        let step = self.fixture.step()?;
        DescribeAutomationStepExecutionsResponse::new(
            request,
            [step],
            None,
            true,
            512,
            TransportProvenance::Loopback,
        )
        .map_err(AwsSsmAutomationProviderError::Request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsSsmAutomationTransport;

impl AwsSsmAutomationTransport for BlockedEnvAwsSsmAutomationTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn describe_automation_executions(
        &mut self,
        _request: &DescribeAutomationExecutionsRequest,
    ) -> ProviderResult<DescribeAutomationExecutionsResponse> {
        Err(AwsSsmAutomationProviderError::Transport(
            AwsSsmAutomationTransportError::BlockedEnv,
        ))
    }

    fn get_automation_execution(
        &mut self,
        _request: &GetAutomationExecutionRequest,
    ) -> ProviderResult<GetAutomationExecutionResponse> {
        Err(AwsSsmAutomationProviderError::Transport(
            AwsSsmAutomationTransportError::BlockedEnv,
        ))
    }

    fn describe_automation_step_executions(
        &mut self,
        _request: &DescribeAutomationStepExecutionsRequest,
    ) -> ProviderResult<DescribeAutomationStepExecutionsResponse> {
        Err(AwsSsmAutomationProviderError::Transport(
            AwsSsmAutomationTransportError::BlockedEnv,
        ))
    }
}

pub type RecordingTransport = RecordingAwsSsmAutomationTransport;
pub type FixtureTransport = FixtureAwsSsmAutomationTransport;
pub type LoopbackTransport = LoopbackAwsSsmAutomationTransport;
pub type BlockedEnvTransport = BlockedEnvAwsSsmAutomationTransport;
