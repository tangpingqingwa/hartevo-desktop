//! Read-only CodePipeline provider and fixture/recording/loopback seams.

use std::{collections::BTreeSet, collections::VecDeque, fmt};

use serde::Serialize;

use crate::model::{
    ActionExecutionFilter, ActionExecutionRecord, AwsCodePipelineScope, Cursor, Digest,
    PipelineExecutionFilter, PipelineExecutionRecord, PipelineStateRecord, ReadOperation,
    TransportProvenance,
};
use crate::service::AwsCodePipelineRegistration;
use crate::{
    AwsCodePipelineReleaseError, AwsCodePipelineTransportError, MAX_ACTION_EXECUTIONS,
    MAX_CURSOR_BYTES, MAX_PAGE_SIZE, MAX_PAGES, MAX_PIPELINE_EXECUTIONS, MAX_RESPONSE_BYTES,
    Result,
};

pub type AwsCodePipelineProviderError = AwsCodePipelineReleaseError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPipelineStateRequest {
    pub scope_digest: Digest,
    pub request_digest: Digest,
}

impl GetPipelineStateRequest {
    pub fn new(scope: &AwsCodePipelineScope) -> Self {
        let scope_digest = scope.digest().clone();
        let request_digest = Digest::from_parts(
            "aws-codepipeline-get-pipeline-state-request/v1",
            &[("scope", scope_digest.as_str().to_owned())],
        );
        Self {
            scope_digest,
            request_digest,
        }
    }

    pub fn validate(&self, scope: &AwsCodePipelineScope) -> Result<()> {
        let expected = Self::new(scope);
        if self.scope_digest == expected.scope_digest
            && self.request_digest == expected.request_digest
        {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::RequestBindingMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPipelineExecutionRequest {
    pub scope_digest: Digest,
    pub request_digest: Digest,
}

impl GetPipelineExecutionRequest {
    pub fn new(scope: &AwsCodePipelineScope) -> Self {
        let scope_digest = scope.digest().clone();
        let request_digest = Digest::from_parts(
            "aws-codepipeline-get-pipeline-execution-request/v1",
            &[("scope", scope_digest.as_str().to_owned())],
        );
        Self {
            scope_digest,
            request_digest,
        }
    }

    pub fn validate(&self, scope: &AwsCodePipelineScope) -> Result<()> {
        let expected = Self::new(scope);
        if self.scope_digest == expected.scope_digest
            && self.request_digest == expected.request_digest
        {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::RequestBindingMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListPipelineExecutionsRequest {
    pub scope_digest: Digest,
    pub filter: PipelineExecutionFilter,
    pub page_size: usize,
    pub cursor: Option<Cursor>,
    pub request_digest: Digest,
}

impl ListPipelineExecutionsRequest {
    pub fn new(
        scope: &AwsCodePipelineScope,
        filter: PipelineExecutionFilter,
        page_size: usize,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        filter.validate_against(scope)?;
        validate_page_size(page_size)?;
        if let Some(cursor) = &cursor {
            cursor.validate_for(filter.digest())?;
        }
        let scope_digest = scope.digest().clone();
        let request_digest = Digest::from_parts(
            "aws-codepipeline-list-pipeline-executions-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("filter", filter.digest().as_str().to_owned()),
                ("page_size", page_size.to_string()),
                (
                    "cursor",
                    cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.token_digest.as_str().to_owned()),
                ),
            ],
        );
        Ok(Self {
            scope_digest,
            filter,
            page_size,
            cursor,
            request_digest,
        })
    }

    pub fn validate(&self, scope: &AwsCodePipelineScope) -> Result<()> {
        let expected = Self::new(
            scope,
            self.filter.clone(),
            self.page_size,
            self.cursor.clone(),
        )?;
        if self.scope_digest == expected.scope_digest
            && self.request_digest == expected.request_digest
        {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::RequestBindingMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListActionExecutionsRequest {
    pub scope_digest: Digest,
    pub filter: ActionExecutionFilter,
    pub page_size: usize,
    pub cursor: Option<Cursor>,
    pub request_digest: Digest,
}

impl ListActionExecutionsRequest {
    pub fn new(
        scope: &AwsCodePipelineScope,
        filter: ActionExecutionFilter,
        page_size: usize,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        filter.validate_against(scope)?;
        validate_page_size(page_size)?;
        if let Some(cursor) = &cursor {
            cursor.validate_for(filter.digest())?;
        }
        let scope_digest = scope.digest().clone();
        let request_digest = Digest::from_parts(
            "aws-codepipeline-list-action-executions-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("filter", filter.digest().as_str().to_owned()),
                ("page_size", page_size.to_string()),
                (
                    "cursor",
                    cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.token_digest.as_str().to_owned()),
                ),
            ],
        );
        Ok(Self {
            scope_digest,
            filter,
            page_size,
            cursor,
            request_digest,
        })
    }

    pub fn validate(&self, scope: &AwsCodePipelineScope) -> Result<()> {
        let expected = Self::new(
            scope,
            self.filter.clone(),
            self.page_size,
            self.cursor.clone(),
        )?;
        if self.scope_digest == expected.scope_digest
            && self.request_digest == expected.request_digest
        {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::RequestBindingMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineStateResponse {
    pub state: PipelineStateRecord,
    pub response_bytes: usize,
    pub request_digest: Option<Digest>,
    pub response_digest: Digest,
}

pub type PipelineExecutionResponse = PipelineStateResponse;

impl PipelineStateResponse {
    pub fn new(state: PipelineStateRecord, response_bytes: usize) -> Result<Self> {
        state.validate_integrity()?;
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsCodePipelineReleaseError::ResponseTooLarge);
        }
        let mut response = Self {
            state,
            response_bytes,
            request_digest: None,
            response_digest: Digest::from_text("unsealed-aws-codepipeline-state-response"),
        };
        response.response_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn for_scope(scope: &AwsCodePipelineScope) -> Self {
        Self::new(PipelineStateRecord::for_scope(scope), 512)
            .expect("bounded state response fixture")
    }

    pub fn bind_request(&mut self, request: &GetPipelineStateRequest) {
        self.request_digest = Some(request.request_digest.clone());
        self.response_digest = self.calculate_digest();
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.state.validate_integrity()?;
        if self.response_bytes <= MAX_RESPONSE_BYTES
            && self
                .request_digest
                .as_ref()
                .is_none_or(|value| value.validate().is_ok())
            && self.response_digest == self.calculate_digest()
        {
            Ok(())
        } else {
            Err(AwsCodePipelineReleaseError::PageTampered)
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-state-response/v1",
            &[
                ("state", self.state.record_digest.as_str().to_owned()),
                ("bytes", self.response_bytes.to_string()),
                (
                    "request",
                    self.request_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineExecutionPage {
    pub page_number: usize,
    pub executions: Vec<PipelineExecutionRecord>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: usize,
    pub request_digest: Option<Digest>,
    pub page_digest: Digest,
}

impl PipelineExecutionPage {
    pub fn new(
        page_number: usize,
        executions: Vec<PipelineExecutionRecord>,
        next_cursor: Option<Cursor>,
        response_bytes: usize,
    ) -> Result<Self> {
        if page_number == 0
            || executions.len() > MAX_PIPELINE_EXECUTIONS
            || response_bytes > MAX_RESPONSE_BYTES
            || next_cursor
                .as_ref()
                .is_some_and(|value| value.token_digest.as_str().len() > MAX_CURSOR_BYTES)
        {
            return Err(AwsCodePipelineReleaseError::PageTampered);
        }
        for execution in &executions {
            execution.validate_integrity()?;
        }
        let mut page = Self {
            page_number,
            executions,
            next_cursor,
            response_bytes,
            request_digest: None,
            page_digest: Digest::from_text("unsealed-aws-codepipeline-execution-page"),
        };
        page.page_digest = page.calculate_digest();
        Ok(page)
    }

    pub fn for_scope(scope: &AwsCodePipelineScope) -> Self {
        Self::new(
            1,
            vec![PipelineExecutionRecord::for_scope(scope)],
            None,
            512,
        )
        .expect("bounded execution page fixture")
    }

    pub fn bind_request(&mut self, request: &ListPipelineExecutionsRequest) {
        self.request_digest = Some(request.request_digest.clone());
        self.page_digest = self.calculate_digest();
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.page_number == 0
            || self.executions.len() > MAX_PIPELINE_EXECUTIONS
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self
                .request_digest
                .as_ref()
                .is_some_and(|value| value.validate().is_err())
            || self
                .next_cursor
                .as_ref()
                .is_some_and(|value| value.token_digest.validate().is_err())
            || self.page_digest != self.calculate_digest()
        {
            return Err(AwsCodePipelineReleaseError::PageTampered);
        }
        for execution in &self.executions {
            execution.validate_integrity()?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-execution-page/v1",
            &[
                ("page", self.page_number.to_string()),
                (
                    "executions",
                    self.executions
                        .iter()
                        .map(|value| value.record_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.token_digest.as_str().to_owned()),
                ),
                ("bytes", self.response_bytes.to_string()),
                (
                    "request",
                    self.request_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionExecutionPage {
    pub page_number: usize,
    pub actions: Vec<ActionExecutionRecord>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: usize,
    pub request_digest: Option<Digest>,
    pub page_digest: Digest,
}

impl ActionExecutionPage {
    pub fn new(
        page_number: usize,
        actions: Vec<ActionExecutionRecord>,
        next_cursor: Option<Cursor>,
        response_bytes: usize,
    ) -> Result<Self> {
        if page_number == 0
            || actions.len() > MAX_ACTION_EXECUTIONS
            || response_bytes > MAX_RESPONSE_BYTES
            || next_cursor
                .as_ref()
                .is_some_and(|value| value.token_digest.as_str().len() > MAX_CURSOR_BYTES)
        {
            return Err(AwsCodePipelineReleaseError::PageTampered);
        }
        for action in &actions {
            action.validate_integrity()?;
        }
        let mut page = Self {
            page_number,
            actions,
            next_cursor,
            response_bytes,
            request_digest: None,
            page_digest: Digest::from_text("unsealed-aws-codepipeline-action-page"),
        };
        page.page_digest = page.calculate_digest();
        Ok(page)
    }

    pub fn for_scope(scope: &AwsCodePipelineScope) -> Self {
        Self::new(1, vec![ActionExecutionRecord::for_scope(scope)], None, 512)
            .expect("bounded action page fixture")
    }

    pub fn bind_request(&mut self, request: &ListActionExecutionsRequest) {
        self.request_digest = Some(request.request_digest.clone());
        self.page_digest = self.calculate_digest();
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.page_number == 0
            || self.actions.len() > MAX_ACTION_EXECUTIONS
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self
                .request_digest
                .as_ref()
                .is_some_and(|value| value.validate().is_err())
            || self
                .next_cursor
                .as_ref()
                .is_some_and(|value| value.token_digest.validate().is_err())
            || self.page_digest != self.calculate_digest()
        {
            return Err(AwsCodePipelineReleaseError::PageTampered);
        }
        for action in &self.actions {
            action.validate_integrity()?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-action-page/v1",
            &[
                ("page", self.page_number.to_string()),
                (
                    "actions",
                    self.actions
                        .iter()
                        .map(|value| value.record_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.token_digest.as_str().to_owned()),
                ),
                ("bytes", self.response_bytes.to_string()),
                (
                    "request",
                    self.request_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }
}

/// Request provenance is kept with the exact operation and request digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: ReadOperation,
    pub request_digest: Digest,
    pub filter_digest: Option<Digest>,
}

/// The only provider API exposed by this Layer-1 crate.
pub trait AwsCodePipelineTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get_pipeline_state(
        &mut self,
        request: &GetPipelineStateRequest,
    ) -> std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError>;

    fn get_pipeline_execution(
        &mut self,
        request: &GetPipelineExecutionRequest,
    ) -> std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError>;

    fn list_pipeline_executions(
        &mut self,
        request: &ListPipelineExecutionsRequest,
    ) -> std::result::Result<PipelineExecutionPage, AwsCodePipelineTransportError>;

    fn list_action_executions(
        &mut self,
        request: &ListActionExecutionsRequest,
    ) -> std::result::Result<ActionExecutionPage, AwsCodePipelineTransportError>;
}

#[derive(Clone, Debug)]
struct ScriptedTransport {
    states: VecDeque<std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError>>,
    executions: VecDeque<std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError>>,
    pipeline_pages:
        VecDeque<std::result::Result<PipelineExecutionPage, AwsCodePipelineTransportError>>,
    action_pages: VecDeque<std::result::Result<ActionExecutionPage, AwsCodePipelineTransportError>>,
    requests: Vec<RecordedRequest>,
    provenance: TransportProvenance,
}

impl ScriptedTransport {
    fn new(
        states: impl IntoIterator<
            Item = std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError>,
        >,
        executions: impl IntoIterator<
            Item = std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError>,
        >,
        pipeline_pages: impl IntoIterator<
            Item = std::result::Result<PipelineExecutionPage, AwsCodePipelineTransportError>,
        >,
        action_pages: impl IntoIterator<
            Item = std::result::Result<ActionExecutionPage, AwsCodePipelineTransportError>,
        >,
        provenance: TransportProvenance,
    ) -> Self {
        Self {
            states: states.into_iter().collect(),
            executions: executions.into_iter().collect(),
            pipeline_pages: pipeline_pages.into_iter().collect(),
            action_pages: action_pages.into_iter().collect(),
            requests: Vec::new(),
            provenance,
        }
    }

    fn from_scope(scope: &AwsCodePipelineScope, provenance: TransportProvenance) -> Self {
        Self::new(
            [Ok(PipelineStateResponse::for_scope(scope))],
            [Ok(PipelineStateResponse::new(
                PipelineStateRecord::for_scope(scope),
                512,
            )
            .expect("bounded execution response"))],
            [Ok(PipelineExecutionPage::for_scope(scope))],
            [Ok(ActionExecutionPage::for_scope(scope))],
            provenance,
        )
    }

    fn record(
        &mut self,
        operation: ReadOperation,
        request_digest: &Digest,
        filter: Option<&Digest>,
    ) {
        self.requests.push(RecordedRequest {
            operation,
            request_digest: request_digest.clone(),
            filter_digest: filter.cloned(),
        });
    }

    fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    fn remaining_pages(&self) -> usize {
        self.states.len()
            + self.executions.len()
            + self.pipeline_pages.len()
            + self.action_pages.len()
    }
}

#[derive(Clone, Debug)]
pub struct RecordingAwsCodePipelineTransport {
    inner: ScriptedTransport,
}

impl RecordingAwsCodePipelineTransport {
    pub fn new(
        states: impl IntoIterator<
            Item = std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError>,
        >,
        executions: impl IntoIterator<
            Item = std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError>,
        >,
        pipeline_pages: impl IntoIterator<
            Item = std::result::Result<PipelineExecutionPage, AwsCodePipelineTransportError>,
        >,
        action_pages: impl IntoIterator<
            Item = std::result::Result<ActionExecutionPage, AwsCodePipelineTransportError>,
        >,
    ) -> Self {
        Self {
            inner: ScriptedTransport::new(
                states,
                executions,
                pipeline_pages,
                action_pages,
                TransportProvenance::Recording,
            ),
        }
    }

    pub fn from_scope(scope: &AwsCodePipelineScope) -> Self {
        Self {
            inner: ScriptedTransport::from_scope(scope, TransportProvenance::Recording),
        }
    }

    pub fn push_state(
        &mut self,
        value: std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError>,
    ) {
        self.inner.states.push_back(value);
    }

    pub fn push_execution(
        &mut self,
        value: std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError>,
    ) {
        self.inner.executions.push_back(value);
    }

    pub fn push_pipeline_page(
        &mut self,
        value: std::result::Result<PipelineExecutionPage, AwsCodePipelineTransportError>,
    ) {
        self.inner.pipeline_pages.push_back(value);
    }

    pub fn push_action_page(
        &mut self,
        value: std::result::Result<ActionExecutionPage, AwsCodePipelineTransportError>,
    ) {
        self.inner.action_pages.push_back(value);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        self.inner.requests()
    }

    pub fn remaining_pages(&self) -> usize {
        self.inner.remaining_pages()
    }
}

impl AwsCodePipelineTransport for RecordingAwsCodePipelineTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance
    }

    fn get_pipeline_state(
        &mut self,
        request: &GetPipelineStateRequest,
    ) -> std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError> {
        self.inner.record(
            ReadOperation::GetPipelineState,
            &request.request_digest,
            None,
        );
        self.inner
            .states
            .pop_front()
            .unwrap_or(Err(AwsCodePipelineTransportError::Unavailable))
    }

    fn get_pipeline_execution(
        &mut self,
        request: &GetPipelineExecutionRequest,
    ) -> std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError> {
        self.inner.record(
            ReadOperation::GetPipelineExecution,
            &request.request_digest,
            None,
        );
        self.inner
            .executions
            .pop_front()
            .unwrap_or(Err(AwsCodePipelineTransportError::Unavailable))
    }

    fn list_pipeline_executions(
        &mut self,
        request: &ListPipelineExecutionsRequest,
    ) -> std::result::Result<PipelineExecutionPage, AwsCodePipelineTransportError> {
        self.inner.record(
            ReadOperation::ListPipelineExecutions,
            &request.request_digest,
            Some(request.filter.digest()),
        );
        self.inner
            .pipeline_pages
            .pop_front()
            .unwrap_or(Err(AwsCodePipelineTransportError::Unavailable))
    }

    fn list_action_executions(
        &mut self,
        request: &ListActionExecutionsRequest,
    ) -> std::result::Result<ActionExecutionPage, AwsCodePipelineTransportError> {
        self.inner.record(
            ReadOperation::ListActionExecutions,
            &request.request_digest,
            Some(request.filter.digest()),
        );
        self.inner
            .action_pages
            .pop_front()
            .unwrap_or(Err(AwsCodePipelineTransportError::Unavailable))
    }
}

pub type RecordingTransport = RecordingAwsCodePipelineTransport;

#[derive(Clone, Debug)]
pub struct FixtureAwsCodePipelineTransport {
    inner: ScriptedTransport,
}

impl FixtureAwsCodePipelineTransport {
    pub fn new(
        states: impl IntoIterator<
            Item = std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError>,
        >,
        executions: impl IntoIterator<
            Item = std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError>,
        >,
        pipeline_pages: impl IntoIterator<
            Item = std::result::Result<PipelineExecutionPage, AwsCodePipelineTransportError>,
        >,
        action_pages: impl IntoIterator<
            Item = std::result::Result<ActionExecutionPage, AwsCodePipelineTransportError>,
        >,
    ) -> Self {
        Self {
            inner: ScriptedTransport::new(
                states,
                executions,
                pipeline_pages,
                action_pages,
                TransportProvenance::Fixture,
            ),
        }
    }

    pub fn from_scope(scope: &AwsCodePipelineScope) -> Self {
        Self {
            inner: ScriptedTransport::from_scope(scope, TransportProvenance::Fixture),
        }
    }
}

pub type FakeAwsCodePipelineTransport = FixtureAwsCodePipelineTransport;
pub type FakeTransport = FixtureAwsCodePipelineTransport;

macro_rules! impl_scripted_wrapper_transport {
    ($type:ty) => {
        impl AwsCodePipelineTransport for $type {
            fn provenance(&self) -> TransportProvenance {
                self.inner.provenance
            }

            fn get_pipeline_state(
                &mut self,
                request: &GetPipelineStateRequest,
            ) -> std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError> {
                self.inner.record(
                    ReadOperation::GetPipelineState,
                    &request.request_digest,
                    None,
                );
                self.inner
                    .states
                    .pop_front()
                    .unwrap_or(Err(AwsCodePipelineTransportError::Unavailable))
            }

            fn get_pipeline_execution(
                &mut self,
                request: &GetPipelineExecutionRequest,
            ) -> std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError> {
                self.inner.record(
                    ReadOperation::GetPipelineExecution,
                    &request.request_digest,
                    None,
                );
                self.inner
                    .executions
                    .pop_front()
                    .unwrap_or(Err(AwsCodePipelineTransportError::Unavailable))
            }

            fn list_pipeline_executions(
                &mut self,
                request: &ListPipelineExecutionsRequest,
            ) -> std::result::Result<PipelineExecutionPage, AwsCodePipelineTransportError> {
                self.inner.record(
                    ReadOperation::ListPipelineExecutions,
                    &request.request_digest,
                    Some(request.filter.digest()),
                );
                self.inner
                    .pipeline_pages
                    .pop_front()
                    .unwrap_or(Err(AwsCodePipelineTransportError::Unavailable))
            }

            fn list_action_executions(
                &mut self,
                request: &ListActionExecutionsRequest,
            ) -> std::result::Result<ActionExecutionPage, AwsCodePipelineTransportError> {
                self.inner.record(
                    ReadOperation::ListActionExecutions,
                    &request.request_digest,
                    Some(request.filter.digest()),
                );
                self.inner
                    .action_pages
                    .pop_front()
                    .unwrap_or(Err(AwsCodePipelineTransportError::Unavailable))
            }
        }
    };
}

impl_scripted_wrapper_transport!(FixtureAwsCodePipelineTransport);

#[derive(Clone, Debug)]
pub struct LoopbackAwsCodePipelineTransport {
    inner: ScriptedTransport,
}

impl LoopbackAwsCodePipelineTransport {
    pub fn new(
        states: impl IntoIterator<
            Item = std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError>,
        >,
        executions: impl IntoIterator<
            Item = std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError>,
        >,
        pipeline_pages: impl IntoIterator<
            Item = std::result::Result<PipelineExecutionPage, AwsCodePipelineTransportError>,
        >,
        action_pages: impl IntoIterator<
            Item = std::result::Result<ActionExecutionPage, AwsCodePipelineTransportError>,
        >,
    ) -> Self {
        Self {
            inner: ScriptedTransport::new(
                states,
                executions,
                pipeline_pages,
                action_pages,
                TransportProvenance::Loopback,
            ),
        }
    }

    pub fn from_scope(scope: &AwsCodePipelineScope) -> Self {
        Self {
            inner: ScriptedTransport::from_scope(scope, TransportProvenance::Loopback),
        }
    }
}

impl_scripted_wrapper_transport!(LoopbackAwsCodePipelineTransport);
pub type LoopbackTransport = LoopbackAwsCodePipelineTransport;

#[derive(Clone, Debug)]
pub struct BlockedEnvAwsCodePipelineTransport;

impl AwsCodePipelineTransport for BlockedEnvAwsCodePipelineTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get_pipeline_state(
        &mut self,
        _request: &GetPipelineStateRequest,
    ) -> std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError> {
        Err(AwsCodePipelineTransportError::BlockedEnv)
    }

    fn get_pipeline_execution(
        &mut self,
        _request: &GetPipelineExecutionRequest,
    ) -> std::result::Result<PipelineStateResponse, AwsCodePipelineTransportError> {
        Err(AwsCodePipelineTransportError::BlockedEnv)
    }

    fn list_pipeline_executions(
        &mut self,
        _request: &ListPipelineExecutionsRequest,
    ) -> std::result::Result<PipelineExecutionPage, AwsCodePipelineTransportError> {
        Err(AwsCodePipelineTransportError::BlockedEnv)
    }

    fn list_action_executions(
        &mut self,
        _request: &ListActionExecutionsRequest,
    ) -> std::result::Result<ActionExecutionPage, AwsCodePipelineTransportError> {
        Err(AwsCodePipelineTransportError::BlockedEnv)
    }
}

pub type BlockedEnvTransport = BlockedEnvAwsCodePipelineTransport;

#[derive(Debug)]
pub struct AwsCodePipelineProvider<T: AwsCodePipelineTransport> {
    registration: AwsCodePipelineRegistration,
    transport: T,
}

impl<T: AwsCodePipelineTransport> AwsCodePipelineProvider<T> {
    pub fn new(registration: AwsCodePipelineRegistration, transport: T) -> Result<Self> {
        registration.validate()?;
        Ok(Self {
            registration,
            transport,
        })
    }

    pub fn registration(&self) -> &AwsCodePipelineRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsCodePipelineRegistration {
        &mut self.registration
    }

    pub fn scope(&self) -> &AwsCodePipelineScope {
        self.registration.scope()
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub fn provider_identity(&self) -> &crate::model::ProviderIdentity {
        self.registration.provider_identity()
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    fn ensure_ready(&self) -> Result<()> {
        self.registration.validate()?;
        if self.registration.secret_reference().is_revoked() {
            return Err(AwsCodePipelineReleaseError::SecretRevoked);
        }
        match self.registration.status() {
            crate::service::RegistrationStatus::Active => Ok(()),
            crate::service::RegistrationStatus::Revoked => {
                Err(AwsCodePipelineReleaseError::RegistrationRevoked)
            }
            crate::service::RegistrationStatus::Reversed => {
                Err(AwsCodePipelineReleaseError::RegistrationReversed)
            }
        }
    }

    pub fn get_pipeline_state(&mut self) -> Result<PipelineStateResponse> {
        let request = GetPipelineStateRequest::new(self.scope());
        self.get_pipeline_state_with_request(&request)
    }

    pub fn get_pipeline_state_with_request(
        &mut self,
        request: &GetPipelineStateRequest,
    ) -> Result<PipelineStateResponse> {
        self.ensure_ready()?;
        request.validate(self.scope())?;
        let response = self.transport.get_pipeline_state(request)?;
        self.validate_state_response(response, request.request_digest.clone(), true)
    }

    pub fn get_pipeline_execution(&mut self) -> Result<PipelineStateResponse> {
        let request = GetPipelineExecutionRequest::new(self.scope());
        self.get_pipeline_execution_with_request(&request)
    }

    pub fn get_pipeline_execution_with_request(
        &mut self,
        request: &GetPipelineExecutionRequest,
    ) -> Result<PipelineStateResponse> {
        self.ensure_ready()?;
        request.validate(self.scope())?;
        let response = self.transport.get_pipeline_execution(request)?;
        self.validate_state_response(response, request.request_digest.clone(), true)
    }

    fn validate_state_response(
        &self,
        response: PipelineStateResponse,
        request_digest: Digest,
        require_execution: bool,
    ) -> Result<PipelineStateResponse> {
        response.validate_integrity()?;
        if response
            .request_digest
            .as_ref()
            .is_some_and(|value| value != &request_digest)
        {
            return Err(AwsCodePipelineReleaseError::RequestBindingMismatch);
        }
        let state = &response.state;
        if state.pipeline != self.scope().pipeline {
            return Err(AwsCodePipelineReleaseError::OutOfScope);
        }
        if require_execution && state.execution != self.scope().execution {
            if state.execution.value == self.scope().execution.value {
                return Err(AwsCodePipelineReleaseError::ExecutionReplaced);
            }
            return Err(AwsCodePipelineReleaseError::OutOfScope);
        }
        if state.stage != self.scope().stage || state.action != self.scope().action {
            if state.stage.value == self.scope().stage.value
                || state.action.value == self.scope().action.value
            {
                return Err(AwsCodePipelineReleaseError::StageActionReplaced);
            }
            return Err(AwsCodePipelineReleaseError::OutOfScope);
        }
        Ok(response)
    }

    pub fn list_pipeline_executions_page(
        &mut self,
        filter: PipelineExecutionFilter,
        page_size: usize,
        cursor: Option<Cursor>,
    ) -> Result<PipelineExecutionPage> {
        self.ensure_ready()?;
        let request = ListPipelineExecutionsRequest::new(self.scope(), filter, page_size, cursor)?;
        request.validate(self.scope())?;
        let response = self.transport.list_pipeline_executions(&request)?;
        self.validate_execution_page(response, &request)
    }

    pub fn list_action_executions_page(
        &mut self,
        filter: ActionExecutionFilter,
        page_size: usize,
        cursor: Option<Cursor>,
    ) -> Result<ActionExecutionPage> {
        self.ensure_ready()?;
        let request = ListActionExecutionsRequest::new(self.scope(), filter, page_size, cursor)?;
        request.validate(self.scope())?;
        let response = self.transport.list_action_executions(&request)?;
        self.validate_action_page(response, &request)
    }

    pub fn list_pipeline_executions(
        &mut self,
        filter: PipelineExecutionFilter,
        page_size: usize,
        max_pages: usize,
    ) -> Result<crate::model::PipelineExecutionsProjection> {
        self.ensure_ready()?;
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(AwsCodePipelineReleaseError::PaginationLimit);
        }
        let mut cursor = None;
        let mut seen = BTreeSet::new();
        let mut executions = Vec::new();
        let mut pages_read = 0_u16;
        let mut response_bytes = 0_usize;
        let mut complete = false;
        loop {
            if pages_read as usize >= max_pages {
                break;
            }
            let page =
                self.list_pipeline_executions_page(filter.clone(), page_size, cursor.clone())?;
            pages_read = pages_read.saturating_add(1);
            if page.page_number != pages_read as usize {
                return Err(AwsCodePipelineReleaseError::PageTampered);
            }
            response_bytes = response_bytes.saturating_add(page.response_bytes);
            if response_bytes > MAX_RESPONSE_BYTES {
                return Err(AwsCodePipelineReleaseError::ResponseTooLarge);
            }
            executions.extend(page.executions);
            if executions.len() > MAX_PIPELINE_EXECUTIONS {
                return Err(AwsCodePipelineReleaseError::PaginationLimit);
            }
            if let Some(next) = page.next_cursor {
                next.validate_for(filter.digest())?;
                if !seen.insert(next.token_digest.clone()) {
                    return Err(AwsCodePipelineReleaseError::PaginationLoop);
                }
                cursor = Some(next);
            } else {
                complete = true;
                cursor = None;
                break;
            }
        }
        crate::model::PipelineExecutionsProjection::new(
            executions,
            pages_read,
            complete,
            !complete,
            cursor.map(|value| value.token_digest),
        )
    }

    pub fn list_action_executions(
        &mut self,
        filter: ActionExecutionFilter,
        page_size: usize,
        max_pages: usize,
    ) -> Result<crate::model::ActionExecutionsProjection> {
        self.ensure_ready()?;
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(AwsCodePipelineReleaseError::PaginationLimit);
        }
        let mut cursor = None;
        let mut seen = BTreeSet::new();
        let mut actions = Vec::new();
        let mut pages_read = 0_u16;
        let mut response_bytes = 0_usize;
        let mut complete = false;
        loop {
            if pages_read as usize >= max_pages {
                break;
            }
            let page =
                self.list_action_executions_page(filter.clone(), page_size, cursor.clone())?;
            pages_read = pages_read.saturating_add(1);
            if page.page_number != pages_read as usize {
                return Err(AwsCodePipelineReleaseError::PageTampered);
            }
            response_bytes = response_bytes.saturating_add(page.response_bytes);
            if response_bytes > MAX_RESPONSE_BYTES {
                return Err(AwsCodePipelineReleaseError::ResponseTooLarge);
            }
            actions.extend(page.actions);
            if actions.len() > MAX_ACTION_EXECUTIONS {
                return Err(AwsCodePipelineReleaseError::PaginationLimit);
            }
            if let Some(next) = page.next_cursor {
                next.validate_for(filter.digest())?;
                if !seen.insert(next.token_digest.clone()) {
                    return Err(AwsCodePipelineReleaseError::PaginationLoop);
                }
                cursor = Some(next);
            } else {
                complete = true;
                cursor = None;
                break;
            }
        }
        crate::model::ActionExecutionsProjection::new(
            actions,
            pages_read,
            complete,
            !complete,
            cursor.map(|value| value.token_digest),
        )
    }

    fn validate_execution_page(
        &self,
        page: PipelineExecutionPage,
        request: &ListPipelineExecutionsRequest,
    ) -> Result<PipelineExecutionPage> {
        page.validate_integrity()?;
        if page
            .request_digest
            .as_ref()
            .is_some_and(|value| value != &request.request_digest)
        {
            return Err(AwsCodePipelineReleaseError::RequestBindingMismatch);
        }
        if page
            .next_cursor
            .as_ref()
            .is_some_and(|value| value.validate_for(request.filter.digest()).is_err())
        {
            return Err(AwsCodePipelineReleaseError::CursorMismatch);
        }
        for execution in &page.executions {
            if !execution.matches_pipeline(self.scope()) {
                return Err(AwsCodePipelineReleaseError::OutOfScope);
            }
            if request
                .filter
                .target_execution_digest
                .as_ref()
                .is_some_and(|target| execution.execution.digest() == *target)
            {
                continue;
            }
            if request
                .filter
                .target_execution_digest
                .as_ref()
                .is_some_and(|target| {
                    execution.execution.value == self.scope().execution.value
                        && execution.execution.digest() != *target
                })
            {
                return Err(AwsCodePipelineReleaseError::ExecutionReplaced);
            }
        }
        Ok(page)
    }

    fn validate_action_page(
        &self,
        page: ActionExecutionPage,
        request: &ListActionExecutionsRequest,
    ) -> Result<ActionExecutionPage> {
        page.validate_integrity()?;
        if page
            .request_digest
            .as_ref()
            .is_some_and(|value| value != &request.request_digest)
        {
            return Err(AwsCodePipelineReleaseError::RequestBindingMismatch);
        }
        if page
            .next_cursor
            .as_ref()
            .is_some_and(|value| value.validate_for(request.filter.digest()).is_err())
        {
            return Err(AwsCodePipelineReleaseError::CursorMismatch);
        }
        for action in &page.actions {
            if action.pipeline != self.scope().pipeline {
                return Err(AwsCodePipelineReleaseError::OutOfScope);
            }
            if action.execution != self.scope().execution {
                if action.execution.value == self.scope().execution.value {
                    return Err(AwsCodePipelineReleaseError::ExecutionReplaced);
                }
                return Err(AwsCodePipelineReleaseError::OutOfScope);
            }
            if action.stage != self.scope().stage || action.action != self.scope().action {
                if action.stage.value == self.scope().stage.value
                    || action.action.value == self.scope().action.value
                {
                    return Err(AwsCodePipelineReleaseError::StageActionReplaced);
                }
                return Err(AwsCodePipelineReleaseError::OutOfScope);
            }
        }
        Ok(page)
    }
}

fn validate_page_size(page_size: usize) -> Result<()> {
    if page_size == 0 || page_size > MAX_PAGE_SIZE {
        Err(AwsCodePipelineReleaseError::PaginationLimit)
    } else {
        Ok(())
    }
}
