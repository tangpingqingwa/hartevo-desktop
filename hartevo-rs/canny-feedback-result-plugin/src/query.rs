use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{CannyFeedbackScope, Digest, ModelError, Revision, Timestamp};

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct IdempotencyKey(Digest);

impl IdempotencyKey {
    pub fn new(value: impl AsRef<str>) -> Result<Self, QueryError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > MAX_IDEMPOTENCY_KEY_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(QueryError::InvalidIdempotencyKey);
        }
        Ok(Self(Digest::from_fields(
            "canny-idempotency-key/v1",
            &[value.to_owned()],
        )))
    }

    pub fn from_digest(digest: Digest) -> Result<Self, QueryError> {
        Digest::parse(digest.as_str().to_owned()).map_err(|_| QueryError::InvalidIdempotencyKey)?;
        Ok(Self(digest))
    }

    pub fn digest(&self) -> &Digest {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CannyFeedbackReadOperations {
    pub board: bool,
    pub post: bool,
    pub comment: bool,
    pub aggregate_vote: bool,
    pub status: bool,
    pub category: bool,
    pub roadmap: bool,
}

impl CannyFeedbackReadOperations {
    pub const fn all() -> Self {
        Self {
            board: true,
            post: true,
            comment: true,
            aggregate_vote: true,
            status: true,
            category: true,
            roadmap: true,
        }
    }

    pub fn validate(&self) -> Result<(), QueryError> {
        if self.board
            || self.post
            || self.comment
            || self.aggregate_vote
            || self.status
            || self.category
            || self.roadmap
        {
            Ok(())
        } else {
            Err(QueryError::NoAllowlistedRead)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CannyFeedbackResultRequest {
    pub scope: CannyFeedbackScope,
    pub scope_digest: Digest,
    pub requested_at: Timestamp,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub operations: CannyFeedbackReadOperations,
    pub idempotency_key_digest: Digest,
    pub request_digest: Digest,
}

pub type CannyFeedbackRequest = CannyFeedbackResultRequest;

impl CannyFeedbackResultRequest {
    pub fn new(
        scope: &CannyFeedbackScope,
        requested_at: Timestamp,
        idempotency_key: IdempotencyKey,
    ) -> Result<Self, QueryError> {
        Self::new_with_operations(
            scope,
            requested_at,
            idempotency_key,
            CannyFeedbackReadOperations::all(),
        )
    }

    pub fn new_with_operations(
        scope: &CannyFeedbackScope,
        requested_at: Timestamp,
        idempotency_key: IdempotencyKey,
        operations: CannyFeedbackReadOperations,
    ) -> Result<Self, QueryError> {
        scope.validate().map_err(QueryError::Model)?;
        operations.validate()?;
        let mission_revision = scope.mission.revision;
        let work_product_revision = scope.work_product.revision;
        let scope_digest = scope.digest();
        let mut request = Self {
            scope: scope.clone(),
            scope_digest,
            requested_at,
            mission_revision,
            work_product_revision,
            operations,
            idempotency_key_digest: idempotency_key.digest().clone(),
            request_digest: Digest::zero(),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn idempotency_key_digest(&self) -> &Digest {
        &self.idempotency_key_digest
    }

    pub fn scope(&self) -> &CannyFeedbackScope {
        &self.scope
    }

    pub const fn requested_at(&self) -> Timestamp {
        self.requested_at
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub fn with_scope_digest(mut self, scope_digest: Digest) -> Self {
        self.scope_digest = scope_digest;
        self
    }

    pub fn with_mission_revision(mut self, revision: Revision) -> Self {
        self.mission_revision = revision;
        self
    }

    pub fn with_work_product_revision(mut self, revision: Revision) -> Self {
        self.work_product_revision = revision;
        self
    }

    pub fn with_operations(mut self, operations: CannyFeedbackReadOperations) -> Self {
        self.operations = operations;
        self
    }

    pub fn validate(&self) -> Result<(), QueryError> {
        self.scope.validate().map_err(QueryError::Model)?;
        self.operations.validate()?;
        if self.scope_digest != self.scope.digest() {
            return Err(QueryError::ScopeMismatch);
        }
        Revision::new(self.mission_revision.get()).map_err(QueryError::Model)?;
        Revision::new(self.work_product_revision.get()).map_err(QueryError::Model)?;
        Timestamp::new(self.requested_at.seconds()).map_err(QueryError::Model)?;
        Digest::parse(self.idempotency_key_digest.as_str().to_owned())
            .map_err(QueryError::Model)?;
        if self.request_digest != self.compute_digest() {
            return Err(QueryError::DigestMismatch);
        }
        Ok(())
    }

    pub fn validate_against(&self, scope: &CannyFeedbackScope) -> Result<(), QueryError> {
        if self.scope_digest != scope.digest()
            || self.mission_revision != scope.mission.revision
            || self.work_product_revision != scope.work_product.revision
        {
            return Err(QueryError::ScopeMismatch);
        }
        self.validate()
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "canny-feedback-request/v1",
            &[
                self.scope_digest.to_string(),
                self.requested_at.seconds().to_string(),
                self.mission_revision.get().to_string(),
                self.work_product_revision.get().to_string(),
                serde_json::to_string(&self.operations).expect("read operations serialize"),
                self.idempotency_key_digest.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum QueryError {
    #[error("Canny model is invalid: {0}")]
    Model(ModelError),
    #[error("idempotency key is empty, malformed, or too long")]
    InvalidIdempotencyKey,
    #[error("request is outside the registered Canny scope")]
    ScopeMismatch,
    #[error("no allowlisted Canny read operation was requested")]
    NoAllowlistedRead,
    #[error("request digest does not match immutable fields")]
    DigestMismatch,
}

impl From<ModelError> for QueryError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}
