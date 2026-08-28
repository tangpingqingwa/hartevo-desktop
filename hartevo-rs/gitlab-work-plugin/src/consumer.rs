//! Mission-scoped consumer boundary for the typed GitLab provider.

use crate::model::{GitLabScope, IssueProjection, PipelineResultProposal, WorkProposal};
use crate::provider::{
    GitLabWorkError, GitLabWorkProvider, MergeRequestRead, PaginationBounds, PipelineResultRead,
    ProviderRead,
};
use crate::transport::GitLabWorkTransport;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionGitLabWorkConsumer {
    scope: GitLabScope,
}

impl MissionGitLabWorkConsumer {
    pub fn new(scope: GitLabScope) -> Self {
        Self { scope }
    }

    pub fn scope(&self) -> &GitLabScope {
        &self.scope
    }

    pub fn read_issue_graph<T: GitLabWorkTransport>(
        &self,
        provider: &mut GitLabWorkProvider<T>,
        bounds: PaginationBounds,
    ) -> Result<ProviderRead<IssueProjection>, GitLabWorkError> {
        provider.read_issue_graph(&self.scope, bounds)
    }

    pub fn read_merge_request<T: GitLabWorkTransport>(
        &self,
        provider: &mut GitLabWorkProvider<T>,
        bounds: PaginationBounds,
    ) -> Result<MergeRequestRead, GitLabWorkError> {
        provider.read_merge_request(&self.scope, bounds)
    }

    pub fn read_pipeline_result<T: GitLabWorkTransport>(
        &self,
        provider: &mut GitLabWorkProvider<T>,
        bounds: PaginationBounds,
    ) -> Result<PipelineResultRead, GitLabWorkError> {
        provider.read_pipeline_result(&self.scope, bounds)
    }

    pub fn compile_issue_proposal<T: GitLabWorkTransport>(
        &self,
        provider: &GitLabWorkProvider<T>,
        projection: &IssueProjection,
    ) -> Result<WorkProposal, GitLabWorkError> {
        if projection.scope.fence() != self.scope.fence() {
            return Err(GitLabWorkError::ScopeMismatch);
        }
        provider.compile_issue_proposal(projection)
    }

    pub fn compile_merge_request_proposal<T: GitLabWorkTransport>(
        &self,
        provider: &GitLabWorkProvider<T>,
        read: &MergeRequestRead,
    ) -> Result<WorkProposal, GitLabWorkError> {
        if read.merge_request.scope.fence() != self.scope.fence() {
            return Err(GitLabWorkError::ScopeMismatch);
        }
        provider.compile_merge_request_proposal(read)
    }

    pub fn compile_pipeline_result_proposal<T: GitLabWorkTransport>(
        &self,
        provider: &GitLabWorkProvider<T>,
        read: &PipelineResultRead,
    ) -> Result<PipelineResultProposal, GitLabWorkError> {
        if read.pipeline.scope.fence() != self.scope.fence() {
            return Err(GitLabWorkError::ScopeMismatch);
        }
        provider.compile_pipeline_result_proposal(read)
    }
}
