use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    error::{AwsCodeDeployDeploymentResultError, AwsCodeDeployTransportError},
    model::{
        ApplicationName, AwsRegion, CodeDeployDeploymentPage, CodeDeployDeploymentRecord,
        CodeDeployDeploymentStatus, CodeDeployScope, CodeDeployTargetPage, DeploymentGroupName,
        DeploymentId, DeploymentListFilter, Digest, OpaqueCursor, ProviderProvenance,
    },
};

/// Typed request for the allowlisted CodeDeploy ListDeployments operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeDeployListDeploymentsRequest {
    pub scope_digest: Digest,
    pub account: crate::AccountId,
    pub region: AwsRegion,
    pub application: ApplicationName,
    pub deployment_group: DeploymentGroupName,
    pub filter: DeploymentListFilter,
    pub cursor: Option<OpaqueCursor>,
}

impl CodeDeployListDeploymentsRequest {
    pub fn for_scope(
        scope: &CodeDeployScope,
        filter: DeploymentListFilter,
        cursor: Option<OpaqueCursor>,
    ) -> Self {
        Self {
            scope_digest: scope.digest(),
            account: scope.account.clone(),
            region: scope.region.clone(),
            application: scope.application.clone(),
            deployment_group: scope.deployment_group.clone(),
            filter,
            cursor,
        }
    }
}

/// Typed request for the allowlisted CodeDeploy GetDeployment operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeDeployGetDeploymentRequest {
    pub scope_digest: Digest,
    pub account: crate::AccountId,
    pub region: AwsRegion,
    pub application: ApplicationName,
    pub deployment_group: DeploymentGroupName,
    pub deployment: DeploymentId,
}

impl CodeDeployGetDeploymentRequest {
    pub fn for_scope(scope: &CodeDeployScope) -> Self {
        Self {
            scope_digest: scope.digest(),
            account: scope.account.clone(),
            region: scope.region.clone(),
            application: scope.application.clone(),
            deployment_group: scope.deployment_group.clone(),
            deployment: scope.deployment.clone(),
        }
    }
}

/// Typed request for the allowlisted CodeDeploy ListDeploymentTargets operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeDeployListDeploymentTargetsRequest {
    pub scope_digest: Digest,
    pub account: crate::AccountId,
    pub region: AwsRegion,
    pub application: ApplicationName,
    pub deployment_group: DeploymentGroupName,
    pub deployment: DeploymentId,
    pub cursor: Option<OpaqueCursor>,
}

impl CodeDeployListDeploymentTargetsRequest {
    pub fn for_scope(scope: &CodeDeployScope, cursor: Option<OpaqueCursor>) -> Self {
        Self {
            scope_digest: scope.digest(),
            account: scope.account.clone(),
            region: scope.region.clone(),
            application: scope.application.clone(),
            deployment_group: scope.deployment_group.clone(),
            deployment: scope.deployment.clone(),
            cursor,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodeDeployTransportOperation {
    ListDeployments {
        cursor_digest: Option<Digest>,
        filter_digest: Digest,
    },
    GetDeployment {
        deployment_digest: Digest,
    },
    ListDeploymentTargets {
        cursor_digest: Option<Digest>,
        deployment_digest: Digest,
    },
}

/// A provider transport seam with exactly three read operations. Native HTTP
/// and credential resolution remain outside this Layer-1 crate.
pub trait CodeDeployTransport: fmt::Debug + Send {
    fn provenance(&self) -> ProviderProvenance;

    fn list_deployments(
        &mut self,
        request: &CodeDeployListDeploymentsRequest,
    ) -> Result<CodeDeployDeploymentPage, AwsCodeDeployTransportError>;

    fn get_deployment(
        &mut self,
        request: &CodeDeployGetDeploymentRequest,
    ) -> Result<CodeDeployDeploymentRecord, AwsCodeDeployTransportError>;

    fn list_deployment_targets(
        &mut self,
        request: &CodeDeployListDeploymentTargetsRequest,
    ) -> Result<CodeDeployTargetPage, AwsCodeDeployTransportError>;
}

/// In-memory recording/fixture/loopback transport. It records typed request
/// shapes and returns only caller-supplied redacted records.
pub struct RecordingCodeDeployTransport {
    provenance: ProviderProvenance,
    deployment_pages: VecDeque<Result<CodeDeployDeploymentPage, AwsCodeDeployTransportError>>,
    deployment_page_fallback: Option<Result<CodeDeployDeploymentPage, AwsCodeDeployTransportError>>,
    deployment: Option<Result<CodeDeployDeploymentRecord, AwsCodeDeployTransportError>>,
    target_pages: VecDeque<Result<CodeDeployTargetPage, AwsCodeDeployTransportError>>,
    target_page_fallback: Option<Result<CodeDeployTargetPage, AwsCodeDeployTransportError>>,
    operations: Vec<CodeDeployTransportOperation>,
    fault: Option<AwsCodeDeployTransportError>,
}

impl fmt::Debug for RecordingCodeDeployTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingCodeDeployTransport")
            .field("provenance", &self.provenance)
            .field("queued_deployment_pages", &self.deployment_pages.len())
            .field("has_deployment", &self.deployment.is_some())
            .field("queued_target_pages", &self.target_pages.len())
            .field("operation_count", &self.operations.len())
            .field("fault", &self.fault)
            .finish_non_exhaustive()
    }
}

impl RecordingCodeDeployTransport {
    pub fn new(provenance: ProviderProvenance) -> Self {
        Self {
            provenance,
            deployment_pages: VecDeque::new(),
            deployment_page_fallback: None,
            deployment: None,
            target_pages: VecDeque::new(),
            target_page_fallback: None,
            operations: Vec::new(),
            fault: None,
        }
    }

    pub fn recording() -> Self {
        Self::new(ProviderProvenance::Recording)
    }

    pub fn fake() -> Self {
        Self::new(ProviderProvenance::Fixture)
    }

    pub fn fixture() -> Self {
        Self::new(ProviderProvenance::Fixture)
    }

    pub fn loopback() -> Self {
        Self::new(ProviderProvenance::Loopback)
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderProvenance::BlockedEnv)
    }

    pub fn push_deployment_page(
        &mut self,
        page: Result<CodeDeployDeploymentPage, AwsCodeDeployTransportError>,
    ) {
        self.deployment_pages.push_back(page);
    }

    pub fn clear_queued_deployment_pages(&mut self) {
        self.deployment_pages.clear();
    }

    pub fn set_deployment_page(&mut self, page: CodeDeployDeploymentPage) {
        self.deployment_page_fallback = Some(Ok(page));
    }

    pub fn set_deployment_page_result(
        &mut self,
        page: Result<CodeDeployDeploymentPage, AwsCodeDeployTransportError>,
    ) {
        self.deployment_page_fallback = Some(page);
    }

    pub fn set_deployment(&mut self, deployment: CodeDeployDeploymentRecord) {
        self.deployment = Some(Ok(deployment));
    }

    pub fn set_deployment_result(
        &mut self,
        deployment: Result<CodeDeployDeploymentRecord, AwsCodeDeployTransportError>,
    ) {
        self.deployment = Some(deployment);
    }

    pub fn push_target_page(
        &mut self,
        page: Result<CodeDeployTargetPage, AwsCodeDeployTransportError>,
    ) {
        self.target_pages.push_back(page);
    }

    pub fn clear_queued_target_pages(&mut self) {
        self.target_pages.clear();
    }

    pub fn set_target_page(&mut self, page: CodeDeployTargetPage) {
        self.target_page_fallback = Some(Ok(page));
    }

    pub fn set_target_page_result(
        &mut self,
        page: Result<CodeDeployTargetPage, AwsCodeDeployTransportError>,
    ) {
        self.target_page_fallback = Some(page);
    }

    pub fn set_fault(&mut self, fault: AwsCodeDeployTransportError) {
        self.fault = Some(fault);
    }

    pub fn clear_fault(&mut self) {
        self.fault = None;
    }

    pub fn requests(&self) -> &[CodeDeployTransportOperation] {
        &self.operations
    }

    pub fn operations(&self) -> &[CodeDeployTransportOperation] {
        self.requests()
    }

    fn before_call(&self) -> Result<(), AwsCodeDeployTransportError> {
        if let Some(fault) = &self.fault {
            Err(fault.clone())
        } else if self.provenance == ProviderProvenance::BlockedEnv {
            Err(AwsCodeDeployTransportError::BlockedEnv)
        } else {
            Ok(())
        }
    }

    fn pop_page<T>(
        queue: &mut VecDeque<Result<T, AwsCodeDeployTransportError>>,
        fallback: Option<&Result<T, AwsCodeDeployTransportError>>,
    ) -> Result<T, AwsCodeDeployTransportError>
    where
        T: Clone,
    {
        queue.pop_front().or_else(|| fallback.cloned()).ok_or(
            AwsCodeDeployTransportError::Malformed("fixture response missing"),
        )?
    }
}

impl CodeDeployTransport for RecordingCodeDeployTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn list_deployments(
        &mut self,
        request: &CodeDeployListDeploymentsRequest,
    ) -> Result<CodeDeployDeploymentPage, AwsCodeDeployTransportError> {
        self.operations
            .push(CodeDeployTransportOperation::ListDeployments {
                cursor_digest: request
                    .cursor
                    .as_ref()
                    .map(|cursor| cursor.digest().clone()),
                filter_digest: request.filter.filter_digest.clone(),
            });
        self.before_call()?;
        Self::pop_page(
            &mut self.deployment_pages,
            self.deployment_page_fallback.as_ref(),
        )
    }

    fn get_deployment(
        &mut self,
        request: &CodeDeployGetDeploymentRequest,
    ) -> Result<CodeDeployDeploymentRecord, AwsCodeDeployTransportError> {
        self.operations
            .push(CodeDeployTransportOperation::GetDeployment {
                deployment_digest: Digest::from_serializable(&request.deployment),
            });
        self.before_call()?;
        self.deployment
            .clone()
            .ok_or(AwsCodeDeployTransportError::Malformed(
                "deployment response missing",
            ))?
    }

    fn list_deployment_targets(
        &mut self,
        request: &CodeDeployListDeploymentTargetsRequest,
    ) -> Result<CodeDeployTargetPage, AwsCodeDeployTransportError> {
        self.operations
            .push(CodeDeployTransportOperation::ListDeploymentTargets {
                cursor_digest: request
                    .cursor
                    .as_ref()
                    .map(|cursor| cursor.digest().clone()),
                deployment_digest: Digest::from_serializable(&request.deployment),
            });
        self.before_call()?;
        Self::pop_page(&mut self.target_pages, self.target_page_fallback.as_ref())
    }
}

/// A transport with an explicit no-native-evidence boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvCodeDeployTransport;

impl CodeDeployTransport for BlockedEnvCodeDeployTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn list_deployments(
        &mut self,
        _request: &CodeDeployListDeploymentsRequest,
    ) -> Result<CodeDeployDeploymentPage, AwsCodeDeployTransportError> {
        Err(AwsCodeDeployTransportError::BlockedEnv)
    }

    fn get_deployment(
        &mut self,
        _request: &CodeDeployGetDeploymentRequest,
    ) -> Result<CodeDeployDeploymentRecord, AwsCodeDeployTransportError> {
        Err(AwsCodeDeployTransportError::BlockedEnv)
    }

    fn list_deployment_targets(
        &mut self,
        _request: &CodeDeployListDeploymentTargetsRequest,
    ) -> Result<CodeDeployTargetPage, AwsCodeDeployTransportError> {
        Err(AwsCodeDeployTransportError::BlockedEnv)
    }
}

pub type FakeCodeDeployTransport = RecordingCodeDeployTransport;
pub type FixtureCodeDeployTransport = RecordingCodeDeployTransport;
pub type LoopbackCodeDeployTransport = RecordingCodeDeployTransport;
pub type CodeDeployRecordingTransport = RecordingCodeDeployTransport;
pub type BlockedEnvTransport = BlockedEnvCodeDeployTransport;
pub type CodeDeployApiTransport = RecordingCodeDeployTransport;
pub type FakeAwsCodeDeployTransport = RecordingCodeDeployTransport;
pub type FixtureAwsCodeDeployTransport = RecordingCodeDeployTransport;
pub type LoopbackAwsCodeDeployTransport = RecordingCodeDeployTransport;
pub type RecordingAwsCodeDeployTransport = RecordingCodeDeployTransport;
pub type BlockedEnvAwsCodeDeployTransport = BlockedEnvCodeDeployTransport;

/// Helper for small deterministic fixtures.
pub fn default_deployment_page(
    scope: &CodeDeployScope,
) -> Result<CodeDeployDeploymentPage, AwsCodeDeployDeploymentResultError> {
    CodeDeployDeploymentPage::new(
        scope.digest(),
        DeploymentListFilter::exact(crate::MAX_PAGE_SIZE)?.filter_digest,
        vec![scope.deployment.clone()],
        None,
        128,
        false,
    )
}

pub fn status_name(status: CodeDeployDeploymentStatus) -> &'static str {
    match status {
        CodeDeployDeploymentStatus::Created => "Created",
        CodeDeployDeploymentStatus::Queued => "Queued",
        CodeDeployDeploymentStatus::InProgress => "InProgress",
        CodeDeployDeploymentStatus::Baking => "Baking",
        CodeDeployDeploymentStatus::Ready => "Ready",
        CodeDeployDeploymentStatus::Succeeded => "Succeeded",
        CodeDeployDeploymentStatus::Failed => "Failed",
        CodeDeployDeploymentStatus::Stopped => "Stopped",
        CodeDeployDeploymentStatus::Unknown => "Unknown",
    }
}
