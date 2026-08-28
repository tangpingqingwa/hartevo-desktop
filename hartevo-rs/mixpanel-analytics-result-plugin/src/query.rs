use std::fmt::Write;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    DateWindow, Digest, EventSelector, MixpanelAnalyticsScope, ModelError, ProjectId, ReportId,
    Revision, Timestamp, WorkspaceId,
};
use crate::{MIXPANEL_INSIGHTS_METHOD, MIXPANEL_INSIGHTS_ORIGIN, MIXPANEL_INSIGHTS_PATH};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct IdempotencyKey(Digest);

impl IdempotencyKey {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > 128
            || value.trim() != value
            || value.chars().any(char::is_control)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(ModelError::InvalidIdempotencyKey);
        }
        Ok(Self(Digest::from_fields(
            "mixpanel-idempotency-key/v1",
            &[value.to_owned()],
        )))
    }

    pub fn digest(&self) -> &Digest {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MixpanelAnalyticsResultRequest {
    scope_digest: Digest,
    project_id: ProjectId,
    workspace_id: Option<WorkspaceId>,
    report_id: ReportId,
    date_window: DateWindow,
    event_selector: EventSelector,
    mission_revision: Revision,
    work_product_revision: Revision,
    requested_at: Timestamp,
    idempotency_key_digest: Digest,
    request_digest: Digest,
}

impl MixpanelAnalyticsResultRequest {
    pub fn new(
        scope: &MixpanelAnalyticsScope,
        requested_at: Timestamp,
        idempotency_key: IdempotencyKey,
    ) -> Self {
        let mut request = Self {
            scope_digest: scope.digest(),
            project_id: scope.project().project_id(),
            workspace_id: scope.workspace_id(),
            report_id: scope.report_id(),
            date_window: scope.date_window().clone(),
            event_selector: scope.event_selector().clone(),
            mission_revision: scope.mission().revision(),
            work_product_revision: scope.work_product().revision(),
            requested_at,
            idempotency_key_digest: idempotency_key.digest().clone(),
            request_digest: Digest::from_text("placeholder"),
        };
        request.request_digest = request.compute_digest();
        request
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "mixpanel-analytics-request/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.project_id.get().to_string(),
                self.workspace_id
                    .map_or_else(|| "none".to_owned(), |id| id.get().to_string()),
                self.report_id.get().to_string(),
                self.date_window.digest().as_str().to_owned(),
                self.event_selector.digest().as_str().to_owned(),
                self.mission_revision.get().to_string(),
                self.work_product_revision.get().to_string(),
                self.requested_at.seconds().to_string(),
                self.idempotency_key_digest.as_str().to_owned(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), QueryError> {
        self.date_window.validate().map_err(QueryError::Model)?;
        if self.event_selector.is_empty() {
            return Err(QueryError::Model(ModelError::EmptyEventSelector));
        }
        if self.requested_at.seconds() < 0 {
            return Err(QueryError::Model(ModelError::InvalidTimestamp));
        }
        if self.request_digest != self.compute_digest() {
            Err(QueryError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn validate_against(&self, scope: &MixpanelAnalyticsScope) -> Result<(), QueryError> {
        self.validate()?;
        if self.scope_digest != scope.digest()
            || self.project_id != scope.project().project_id()
            || self.workspace_id != scope.workspace_id()
            || self.report_id != scope.report_id()
            || self.date_window != *scope.date_window()
            || self.event_selector != *scope.event_selector()
            || self.mission_revision != scope.mission().revision()
            || self.work_product_revision != scope.work_product().revision()
        {
            Err(QueryError::ScopeMismatch)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn with_scope_digest(mut self, scope_digest: Digest) -> Self {
        self.scope_digest = scope_digest;
        self
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

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    pub const fn workspace_id(&self) -> Option<WorkspaceId> {
        self.workspace_id
    }

    pub const fn report_id(&self) -> ReportId {
        self.report_id
    }

    pub fn date_window(&self) -> &DateWindow {
        &self.date_window
    }

    pub fn event_selector(&self) -> &EventSelector {
        &self.event_selector
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub const fn requested_at(&self) -> Timestamp {
        self.requested_at
    }

    pub fn idempotency_key_digest(&self) -> &Digest {
        &self.idempotency_key_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> Result<String, QueryError> {
        self.validate()?;
        let mut path = format!(
            "{MIXPANEL_INSIGHTS_ORIGIN}{MIXPANEL_INSIGHTS_PATH}?project_id={}",
            self.project_id.get()
        );
        if let Some(workspace_id) = self.workspace_id {
            let _ = write!(path, "&workspace_id={}", workspace_id.get());
        }
        let _ = write!(path, "&bookmark_id={}", self.report_id.get());
        Ok(path)
    }

    pub const fn method() -> &'static str {
        MIXPANEL_INSIGHTS_METHOD
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum QueryError {
    #[error("Mixpanel request is outside the registered scope")]
    ScopeMismatch,
    #[error("Mixpanel request digest does not match its immutable fields")]
    DigestMismatch,
    #[error("Mixpanel request model is invalid: {0}")]
    Model(ModelError),
}
