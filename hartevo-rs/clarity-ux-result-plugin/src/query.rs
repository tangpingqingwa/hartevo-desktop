use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::model::{ClarityUxScope, Digest, ModelError, Revision, Timestamp};
use crate::{CLARITY_DATA_EXPORT_ORIGIN, CLARITY_DATA_EXPORT_PATH};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClarityUxResultRequest {
    pub scope_digest: Digest,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub requested_at: Timestamp,
}

impl ClarityUxResultRequest {
    pub fn new(scope: &ClarityUxScope, requested_at: Timestamp) -> Self {
        Self {
            scope_digest: scope.digest(),
            mission_revision: scope.mission().revision(),
            work_product_revision: scope.work_product().revision(),
            requested_at,
        }
    }

    #[must_use]
    pub fn with_mission_revision(mut self, revision: Revision) -> Self {
        self.mission_revision = revision;
        self
    }

    #[must_use]
    pub fn with_work_product_revision(mut self, revision: Revision) -> Self {
        self.work_product_revision = revision;
        self
    }

    pub fn validate_against(&self, scope: &ClarityUxScope) -> Result<(), ModelError> {
        if self.scope_digest != scope.digest()
            || self.mission_revision != scope.mission().revision()
            || self.work_product_revision != scope.work_product().revision()
        {
            Err(ModelError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum QueryError {
    #[error("query is outside the registered Clarity scope")]
    ScopeMismatch,
    #[error("Clarity Data Export API URL could not be constructed")]
    InvalidEndpoint,
    #[error("query contains a non-allowlisted metric or dimension")]
    NotAllowlisted,
    #[error("query digest does not match its immutable fields")]
    DigestMismatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClarityDataExportGetRequest {
    project_id: crate::model::ProjectId,
    time_window: crate::model::TimeWindow,
    metrics: crate::model::MetricSet,
    dimensions: crate::model::DimensionSet,
    scope_digest: Digest,
    requested_at: Timestamp,
    query_digest: Digest,
}

impl ClarityDataExportGetRequest {
    pub fn new(scope: &ClarityUxScope, requested_at: Timestamp) -> Result<Self, QueryError> {
        scope.validate().map_err(|_| QueryError::NotAllowlisted)?;
        requested_at
            .validate()
            .map_err(|_| QueryError::NotAllowlisted)?;
        let scope_digest = scope.digest();
        let project_id = scope.project().project_id().clone();
        let time_window = scope.time_window();
        let metrics = scope.metrics().clone();
        let dimensions = scope.dimensions().clone();
        let query_digest = compute_query_digest(
            &project_id,
            time_window,
            &metrics,
            &dimensions,
            &scope_digest,
            requested_at,
        );
        Ok(Self {
            project_id,
            time_window,
            metrics,
            dimensions,
            scope_digest,
            requested_at,
            query_digest,
        })
    }

    pub fn validate(&self) -> Result<(), QueryError> {
        self.time_window
            .validate()
            .map_err(|_| QueryError::NotAllowlisted)?;
        self.metrics
            .validate()
            .map_err(|_| QueryError::NotAllowlisted)?;
        self.dimensions
            .validate()
            .map_err(|_| QueryError::NotAllowlisted)?;
        self.requested_at
            .validate()
            .map_err(|_| QueryError::NotAllowlisted)?;
        if compute_query_digest(
            &self.project_id,
            self.time_window,
            &self.metrics,
            &self.dimensions,
            &self.scope_digest,
            self.requested_at,
        ) != self.query_digest
        {
            Err(QueryError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn project_id(&self) -> &crate::model::ProjectId {
        &self.project_id
    }

    pub const fn time_window(&self) -> crate::model::TimeWindow {
        self.time_window
    }

    pub fn metrics(&self) -> &crate::model::MetricSet {
        &self.metrics
    }

    pub fn dimensions(&self) -> &crate::model::DimensionSet {
        &self.dimensions
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn requested_at(&self) -> Timestamp {
        self.requested_at
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn path_and_query(&self) -> Result<String, QueryError> {
        let mut url =
            Url::parse(CLARITY_DATA_EXPORT_ORIGIN).map_err(|_| QueryError::InvalidEndpoint)?;
        url.set_path(CLARITY_DATA_EXPORT_PATH);
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("numOfDays", &self.time_window.days().to_string());
            for (index, dimension) in self.dimensions.iter().enumerate() {
                let parameter = format!("dimension{}", index + 1);
                query.append_pair(&parameter, dimension.api_name());
            }
        }
        Ok(url.to_string())
    }
}

fn compute_query_digest(
    project_id: &crate::model::ProjectId,
    time_window: crate::model::TimeWindow,
    metrics: &crate::model::MetricSet,
    dimensions: &crate::model::DimensionSet,
    scope_digest: &Digest,
    requested_at: Timestamp,
) -> Digest {
    Digest::from_fields(
        "clarity-data-export-query/v1",
        &[
            project_id.as_str().to_owned(),
            time_window.days().to_string(),
            metrics.digest().as_str().to_owned(),
            dimensions.digest().as_str().to_owned(),
            scope_digest.as_str().to_owned(),
            requested_at.seconds().to_string(),
        ],
    )
}
