use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::{
    AZURE_POLICY_API_VERSION,
    model::{
        AzurePolicyScope, Digest, ModelError, ODataFilter, OpaqueNextLink, PermissionFence,
        PolicyQueryScope, QueryBounds, SecretReference,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum QueryError {
    #[error("query request scope digest does not match the registered scope")]
    ScopeMismatch,
    #[error("query request project, Mission, or Work Product revision is stale")]
    RevisionMismatch,
    #[error("query filter is not allowlisted")]
    InvalidFilter,
    #[error("query secret reference is revoked or belongs to another scope")]
    InvalidSecret,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzurePolicyReadRequest {
    pub scope_digest: Digest,
    pub project_revision: crate::Revision,
    pub mission_revision: crate::Revision,
    pub work_product_revision: crate::Revision,
    pub filter: Option<ODataFilter>,
}

impl AzurePolicyReadRequest {
    pub fn new(scope: &AzurePolicyScope, filter: Option<ODataFilter>) -> Result<Self, QueryError> {
        if let Some(filter) = &filter {
            filter.validate().map_err(|_| QueryError::InvalidFilter)?;
        }
        Ok(Self {
            scope_digest: scope.scope_digest(),
            project_revision: scope.project().revision,
            mission_revision: scope.mission().revision,
            work_product_revision: scope.work_product().revision,
            filter,
        })
    }

    pub fn with_filter(scope: &AzurePolicyScope, filter: ODataFilter) -> Result<Self, QueryError> {
        Self::new(scope, Some(filter))
    }

    pub fn without_filter(scope: &AzurePolicyScope) -> Result<Self, QueryError> {
        Self::new(scope, None)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzurePolicyQuery {
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub filter: Option<ODataFilter>,
    pub filter_digest: Option<Digest>,
    pub policy_state_view: crate::PolicyStateView,
    pub bounds: QueryBounds,
    pub permission_digest: Digest,
    pub project_revision: crate::Revision,
    pub mission_revision: crate::Revision,
    pub work_product_revision: crate::Revision,
    pub secret_reference_digest: Digest,
    pub credential_revision: crate::Revision,
}

impl fmt::Debug for AzurePolicyQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzurePolicyQuery")
            .field("scope_digest", &self.scope_digest)
            .field("query_digest", &self.query_digest)
            .field("filter", &self.filter)
            .field("filter_digest", &self.filter_digest)
            .field("policy_state_view", &self.policy_state_view)
            .field("bounds", &self.bounds)
            .field("permission_digest", &self.permission_digest)
            .field("project_revision", &self.project_revision)
            .field("mission_revision", &self.mission_revision)
            .field("work_product_revision", &self.work_product_revision)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("credential_revision", &self.credential_revision)
            .finish()
    }
}

pub type AzurePolicyQueryProposal = AzurePolicyQuery;

impl AzurePolicyQuery {
    pub(crate) fn compile(
        scope: &AzurePolicyScope,
        secret: &SecretReference,
        request: AzurePolicyReadRequest,
    ) -> Result<Self, QueryError> {
        if request.scope_digest != scope.scope_digest() {
            return Err(QueryError::ScopeMismatch);
        }
        if request.project_revision != scope.project().revision
            || request.mission_revision != scope.mission().revision
            || request.work_product_revision != scope.work_product().revision
        {
            return Err(QueryError::RevisionMismatch);
        }
        if secret.is_revoked() || secret.scope_digest() != &request.scope_digest {
            return Err(QueryError::InvalidSecret);
        }
        if let Some(filter) = &request.filter {
            filter.validate().map_err(|_| QueryError::InvalidFilter)?;
        }
        let filter_digest = request.filter.as_ref().map(ODataFilter::digest);
        let query_digest = Digest::from_fields(
            "azure-policy-query/v1",
            &[
                request.scope_digest.as_str().to_owned(),
                filter_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                format!("{:?}", scope.query_window().state_view),
                scope.query_window().start.as_str().to_owned(),
                scope.query_window().end.as_str().to_owned(),
                scope.query_window().bounds.max_pages.to_string(),
                scope.query_window().bounds.max_records.to_string(),
                scope.query_window().bounds.max_records_per_page.to_string(),
                scope.query_window().bounds.max_response_bytes.to_string(),
                scope.permission_digest().as_str().to_owned(),
                scope.project().revision.get().to_string(),
                scope.mission().revision.get().to_string(),
                scope.work_product().revision.get().to_string(),
                secret.reference_digest().as_str().to_owned(),
                secret.credential_revision().get().to_string(),
                AZURE_POLICY_API_VERSION.to_owned(),
            ],
        );
        Ok(Self {
            scope_digest: request.scope_digest,
            query_digest,
            filter: request.filter,
            filter_digest,
            policy_state_view: scope.query_window().state_view,
            bounds: scope.query_window().bounds.clone(),
            permission_digest: scope.permission_digest().clone(),
            project_revision: scope.project().revision,
            mission_revision: scope.mission().revision,
            work_product_revision: scope.work_product().revision,
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
        })
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    #[must_use]
    pub fn filter_text(&self) -> Option<String> {
        self.filter.as_ref().map(ODataFilter::render)
    }

    #[must_use]
    pub fn endpoint_path(&self, scope: &AzurePolicyScope) -> String {
        let view = match self.policy_state_view {
            crate::PolicyStateView::Latest => "latest",
            crate::PolicyStateView::Default => "default",
        };
        match scope.kind() {
            PolicyQueryScope::Resource => format!(
                "{}/providers/Microsoft.PolicyInsights/policyStates/{view}/queryResults",
                scope
                    .resource_id()
                    .expect("resource scope has resource id")
                    .as_str()
            ),
            PolicyQueryScope::ResourceGroup => format!(
                "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.PolicyInsights/policyStates/{view}/queryResults",
                scope.subscription_id().as_str(),
                scope
                    .resource_group()
                    .expect("resource-group scope has group")
                    .as_str()
            ),
            PolicyQueryScope::Subscription => format!(
                "/subscriptions/{}/providers/Microsoft.PolicyInsights/policyStates/{view}/queryResults",
                scope.subscription_id().as_str()
            ),
        }
    }

    #[must_use]
    pub(crate) fn permission_fence(&self, scope: &AzurePolicyScope) -> PermissionFence {
        PermissionFence {
            scope_digest: scope.scope_digest(),
            permission_digest: self.permission_digest.clone(),
            project_revision: self.project_revision,
            mission_revision: self.mission_revision,
            work_product_revision: self.work_product_revision,
        }
    }

    pub(crate) fn validate_next_link(
        &self,
        scope: &AzurePolicyScope,
        link: &OpaqueNextLink,
    ) -> Result<(), QueryError> {
        let raw = link.as_str();
        let expected = self.endpoint_path(scope);
        let path = if let Some((_, rest)) = raw.split_once("://") {
            let Some((host, _)) = rest.split_once('/') else {
                return Err(QueryError::ScopeMismatch);
            };
            if host != "management.azure.com" {
                return Err(QueryError::ScopeMismatch);
            }
            rest.find('/').map_or("/", |index| &rest[index..])
        } else {
            raw
        };
        let path_without_query = path.split('?').next().unwrap_or(path);
        if path_without_query != expected || !raw.contains("api-version=2024-10-01") {
            return Err(QueryError::ScopeMismatch);
        }
        if raw.contains("$filter") || raw.contains("%24filter") {
            return Err(QueryError::ScopeMismatch);
        }
        Ok(())
    }
}
