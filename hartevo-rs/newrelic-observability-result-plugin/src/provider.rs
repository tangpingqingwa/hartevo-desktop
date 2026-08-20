use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    API_REVISION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
    error::ModelError,
    model::{
        ALL_READ_OPERATIONS, AccountId, ConditionId, ConditionType, Digest, EntityGuid, EntityType,
        IssueEventType, IssueId, IssueState, MAX_IDENTIFIER_BYTES, MAX_ITEMS_PER_PAGE,
        MAX_PAGE_SIZE, MAX_RESPONSE_BYTES, MAX_RETRY_ATTEMPTS, MAX_RETRY_DELAY_MILLIS,
        ObservabilityScope, OpaqueCursor, PolicyId, ReadOperation, Severity, TransportProvenance,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportFailure {
    Unauthorized,
    AccessDenied,
    NotFound,
    Throttled,
    Server,
    Timeout,
    BlockedEnv,
    Malformed,
}

impl TransportFailure {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::Throttled => Some(429),
            Self::Server => Some(500),
            Self::Timeout | Self::BlockedEnv | Self::Malformed => None,
        }
    }

    pub const fn retryable(self) -> bool {
        matches!(self, Self::Throttled | Self::Server | Self::Timeout)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[error("New Relic transport failure: {failure:?}")]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportError {
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub retry_after_millis: Option<u32>,
    pub diagnostic_digest: Digest,
}

impl TransportError {
    pub fn new(failure: TransportFailure, retry_after_millis: Option<u32>) -> Self {
        Self {
            status_code: failure.status_code(),
            retry_after_millis,
            diagnostic_digest: Digest::from_parts(
                "newrelic-transport-error/v1",
                &[
                    ("failure", format!("{failure:?}")),
                    (
                        "retry_after",
                        retry_after_millis.map_or_else(String::new, |value| value.to_string()),
                    ),
                ],
            ),
            failure,
        }
    }

    pub fn blocked_env() -> Self {
        Self::new(TransportFailure::BlockedEnv, None)
    }

    pub fn throttled(retry_after_millis: Option<u32>) -> Self {
        Self::new(TransportFailure::Throttled, retry_after_millis)
    }

    pub fn unauthorized() -> Self {
        Self::new(TransportFailure::Unauthorized, None)
    }

    pub fn malformed() -> Self {
        Self::new(TransportFailure::Malformed, None)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    #[error("invalid New Relic read request: {0}")]
    InvalidRequest(#[from] ModelError),
    #[error("New Relic transport failed after bounded retries: {error}")]
    Transport {
        error: TransportError,
        retries: Vec<RetryEvidence>,
    },
    #[error("New Relic response did not match the allowlisted operation")]
    UnexpectedResponse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub base_delay_millis: u32,
    pub max_delay_millis: u32,
}

impl RetryPolicy {
    pub fn bounded_default() -> Result<Self, ModelError> {
        Self::new(3, 250, MAX_RETRY_DELAY_MILLIS)
    }

    pub fn new(
        max_attempts: u8,
        base_delay_millis: u32,
        max_delay_millis: u32,
    ) -> Result<Self, ModelError> {
        if max_attempts == 0
            || max_attempts > MAX_RETRY_ATTEMPTS
            || base_delay_millis == 0
            || max_delay_millis < base_delay_millis
            || max_delay_millis > MAX_RETRY_DELAY_MILLIS
        {
            return Err(ModelError::InvalidBound {
                field: "retry policy",
            });
        }
        Ok(Self {
            max_attempts,
            base_delay_millis,
            max_delay_millis,
        })
    }

    pub fn delay_millis(&self, failed_attempt: u8, retry_after_millis: Option<u32>) -> u32 {
        let shift = u32::from(failed_attempt.saturating_sub(1)).min(16);
        let exponential = self
            .base_delay_millis
            .saturating_mul(1_u32.checked_shl(shift).unwrap_or(u32::MAX));
        exponential.min(self.max_delay_millis).max(
            retry_after_millis
                .unwrap_or_default()
                .min(self.max_delay_millis),
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(
            self.max_attempts,
            self.base_delay_millis,
            self.max_delay_millis,
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryEvidence {
    pub operation: ReadOperation,
    pub failed_attempt: u8,
    pub delay_millis: u32,
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewRelicReadRequest {
    pub operation: ReadOperation,
    pub account: AccountId,
    pub entity_digest: Digest,
    pub workload_digest: Digest,
    pub policy_digest: Digest,
    pub condition_digest: Digest,
    pub time_window_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub cursor: Option<OpaqueCursor>,
    pub page_size: u16,
    pub max_response_bytes: usize,
    pub allowlisted: bool,
    pub arbitrary_query: bool,
    pub redacted: bool,
    pub path_digest: Digest,
    pub request_digest: Digest,
}

impl NewRelicReadRequest {
    pub fn first(scope: &ObservabilityScope, operation: ReadOperation) -> Result<Self, ModelError> {
        Self::new(scope, operation, None)
    }

    pub fn with_cursor(
        &self,
        scope: &ObservabilityScope,
        cursor: OpaqueCursor,
    ) -> Result<Self, ModelError> {
        if cursor.query_digest() != &self.query_digest {
            return Err(ModelError::InvalidCursor);
        }
        Self::new(scope, self.operation, Some(cursor))
    }

    fn new(
        scope: &ObservabilityScope,
        operation: ReadOperation,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if !scope.query_policy().allows(operation)
            || !scope.permissions().allows(operation.permission())
        {
            return Err(ModelError::InvalidScope);
        }
        if let Some(cursor) = &cursor {
            cursor.validate_for(&Self::query_digest(scope, operation))?;
        }
        let query_digest = Self::query_digest(scope, operation);
        let path_digest = Digest::from_parts(
            "newrelic-nerdgraph-path/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("account", scope.account().digest().as_str().to_owned()),
                (
                    "cursor",
                    cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
            ],
        );
        let mut request = Self {
            operation,
            account: scope.account(),
            entity_digest: scope.entity().digest().clone(),
            workload_digest: scope.workload().digest().clone(),
            policy_digest: scope.policy().digest().clone(),
            condition_digest: scope.condition().digest().clone(),
            time_window_digest: scope.time_window().digest.clone(),
            scope_digest: scope.digest().clone(),
            query_digest,
            cursor,
            page_size: scope.query_policy().page_size,
            max_response_bytes: scope.query_policy().max_response_bytes,
            allowlisted: true,
            arbitrary_query: false,
            redacted: true,
            path_digest,
            request_digest: Digest::from_text("pending-newrelic-request"),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    fn query_digest(scope: &ObservabilityScope, operation: ReadOperation) -> Digest {
        Digest::from_parts(
            "newrelic-allowlisted-query/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("account", scope.account().digest().as_str().to_owned()),
                ("entity", scope.entity().digest().as_str().to_owned()),
                ("workload", scope.workload().digest().as_str().to_owned()),
                ("policy", scope.policy().digest().as_str().to_owned()),
                ("condition", scope.condition().digest().as_str().to_owned()),
                ("window", scope.time_window().digest.as_str().to_owned()),
                ("fields", field_allowlist(operation)),
            ],
        )
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "newrelic-read-request/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                ("account", self.account.digest().as_str().to_owned()),
                ("entity", self.entity_digest.as_str().to_owned()),
                ("workload", self.workload_digest.as_str().to_owned()),
                ("policy", self.policy_digest.as_str().to_owned()),
                ("condition", self.condition_digest.as_str().to_owned()),
                ("window", self.time_window_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("query", self.query_digest.as_str().to_owned()),
                (
                    "cursor",
                    self.cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("page_size", self.page_size.to_string()),
                ("max_bytes", self.max_response_bytes.to_string()),
                ("path", self.path_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate(&self, scope: &ObservabilityScope) -> Result<(), ModelError> {
        scope.validate()?;
        for digest in [
            &self.entity_digest,
            &self.workload_digest,
            &self.policy_digest,
            &self.condition_digest,
            &self.time_window_digest,
            &self.scope_digest,
            &self.query_digest,
            &self.path_digest,
            &self.request_digest,
        ] {
            digest.validate()?;
        }
        if self.account != scope.account()
            || self.scope_digest != *scope.digest()
            || self.entity_digest != *scope.entity().digest()
            || self.workload_digest != *scope.workload().digest()
            || self.policy_digest != *scope.policy().digest()
            || self.condition_digest != *scope.condition().digest()
            || self.time_window_digest != scope.time_window().digest
            || self.query_digest != Self::query_digest(scope, self.operation)
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || !self.allowlisted
            || self.arbitrary_query
            || !self.redacted
            || self.compute_digest() != self.request_digest
        {
            return Err(ModelError::InvalidScope);
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate_for(&self.query_digest)?;
        }
        Ok(())
    }

    pub fn recorded(&self) -> RecordedRequest {
        RecordedRequest {
            operation: self.operation,
            account_digest: self.account.digest(),
            scope_digest: self.scope_digest.clone(),
            query_digest: self.query_digest.clone(),
            cursor_digest: self.cursor.as_ref().map(|value| value.digest().clone()),
            path_digest: self.path_digest.clone(),
            request_digest: self.request_digest.clone(),
            redacted: self.redacted,
            raw_query: false,
        }
    }
}

fn field_allowlist(operation: ReadOperation) -> String {
    match operation {
        ReadOperation::SearchEntities => {
            "guid,entityType,domainType,accountId,reporting,alertSeverity".to_owned()
        }
        ReadOperation::ReadEntitySummary => "guid,entityType,reporting,alertSeverity".to_owned(),
        ReadOperation::ReadAlertPolicies => "id,name,enabled,revisionDigest".to_owned(),
        ReadOperation::ReadNrqlConditions => {
            "id,policyId,type,enabled,revisionDigest,definitionDigest".to_owned()
        }
        ReadOperation::ReadIssues => {
            "issueId,priority,state,entityGuids,entityTypes,updatedAt".to_owned()
        }
        ReadOperation::ReadIssueEvents => "issueId,priority,state,eventType,timestamp".to_owned(),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedRequest {
    pub operation: ReadOperation,
    pub account_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub path_digest: Digest,
    pub request_digest: Digest,
    pub redacted: bool,
    pub raw_query: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityRecord {
    pub guid: EntityGuid,
    pub entity_type: EntityType,
    pub reporting: Option<bool>,
    pub alert_severity: Option<Severity>,
    pub observed_at_millis: Option<i64>,
}

impl EntityRecord {
    pub fn new(
        guid: EntityGuid,
        entity_type: EntityType,
        reporting: Option<bool>,
        alert_severity: Option<Severity>,
        observed_at_millis: Option<i64>,
    ) -> Result<Self, ModelError> {
        guid.validate()?;
        entity_type.validate()?;
        if observed_at_millis.is_some_and(|value| value < 0) {
            return Err(ModelError::InvalidBound {
                field: "entity observation timestamp",
            });
        }
        Ok(Self {
            guid,
            entity_type,
            reporting,
            alert_severity,
            observed_at_millis,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "newrelic-entity-record/v1",
            &[
                ("guid", self.guid.digest().as_str().to_owned()),
                ("type", self.entity_type.digest().as_str().to_owned()),
                (
                    "reporting",
                    self.reporting
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "severity",
                    self.alert_severity
                        .map_or_else(String::new, |value| format!("{value:?}")),
                ),
                (
                    "observed_at",
                    self.observed_at_millis
                        .map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRecord {
    pub id: PolicyId,
    pub enabled: Option<bool>,
    pub condition_count: u16,
    pub revision_digest: Digest,
}

impl PolicyRecord {
    pub fn new(
        id: PolicyId,
        enabled: Option<bool>,
        condition_count: u16,
        revision_digest: Digest,
    ) -> Result<Self, ModelError> {
        id.validate()?;
        revision_digest.validate()?;
        if usize::from(condition_count) > MAX_ITEMS_PER_PAGE {
            return Err(ModelError::InvalidBound {
                field: "policy condition count",
            });
        }
        Ok(Self {
            id,
            enabled,
            condition_count,
            revision_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "newrelic-policy-record/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                (
                    "enabled",
                    self.enabled
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                ("conditions", self.condition_count.to_string()),
                ("revision", self.revision_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionRecord {
    pub id: ConditionId,
    pub policy_id: PolicyId,
    pub condition_type: ConditionType,
    pub enabled: Option<bool>,
    pub revision_digest: Digest,
    pub definition_digest: Digest,
    pub observed_at_millis: Option<i64>,
}

impl ConditionRecord {
    pub fn new(
        id: ConditionId,
        policy_id: PolicyId,
        condition_type: ConditionType,
        enabled: Option<bool>,
        revision_digest: Digest,
        definition_digest: Digest,
        observed_at_millis: Option<i64>,
    ) -> Result<Self, ModelError> {
        id.validate()?;
        policy_id.validate()?;
        revision_digest.validate()?;
        definition_digest.validate()?;
        if observed_at_millis.is_some_and(|value| value < 0) {
            return Err(ModelError::InvalidBound {
                field: "condition observation timestamp",
            });
        }
        Ok(Self {
            id,
            policy_id,
            condition_type,
            enabled,
            revision_digest,
            definition_digest,
            observed_at_millis,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "newrelic-condition-record/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("policy", self.policy_id.digest().as_str().to_owned()),
                ("type", format!("{:?}", self.condition_type)),
                (
                    "enabled",
                    self.enabled
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                ("revision", self.revision_digest.as_str().to_owned()),
                ("definition", self.definition_digest.as_str().to_owned()),
                (
                    "observed_at",
                    self.observed_at_millis
                        .map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueRecord {
    pub id: IssueId,
    pub priority: Severity,
    pub state: IssueState,
    pub entity_guid_digests: Vec<Digest>,
    pub entity_type_digests: Vec<Digest>,
    pub title_digest: Digest,
    pub updated_at_millis: Option<i64>,
}

impl IssueRecord {
    pub fn new(
        id: IssueId,
        priority: Severity,
        state: IssueState,
        entity_guids: Vec<EntityGuid>,
        entity_types: Vec<EntityType>,
        title: impl AsRef<str>,
        updated_at_millis: Option<i64>,
    ) -> Result<Self, ModelError> {
        id.validate()?;
        if entity_guids.len() > MAX_ITEMS_PER_PAGE || entity_types.len() > MAX_ITEMS_PER_PAGE {
            return Err(ModelError::InvalidBound {
                field: "issue entity references",
            });
        }
        if updated_at_millis.is_some_and(|value| value < 0) {
            return Err(ModelError::InvalidBound {
                field: "issue timestamp",
            });
        }
        let title = title.as_ref();
        if !title.is_empty() && title.len() > MAX_IDENTIFIER_BYTES {
            return Err(ModelError::InvalidBound {
                field: "issue title",
            });
        }
        let entity_guid_digests = entity_guids
            .into_iter()
            .map(|value| value.digest())
            .collect::<Vec<_>>();
        let entity_type_digests = entity_types
            .into_iter()
            .map(|value| value.digest())
            .collect::<Vec<_>>();
        let title_digest =
            Digest::from_parts("newrelic-issue-title/v1", &[("value", title.to_owned())]);
        Ok(Self {
            id,
            priority,
            state,
            entity_guid_digests,
            entity_type_digests,
            title_digest,
            updated_at_millis,
        })
    }

    pub fn digest(&self) -> Result<Digest, ModelError> {
        crate::model::digest_serializable(&(
            self.id.digest(),
            self.priority,
            self.state,
            &self.entity_guid_digests,
            &self.entity_type_digests,
            &self.title_digest,
            self.updated_at_millis,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueEventRecord {
    pub issue_id: IssueId,
    pub priority: Severity,
    pub state: IssueState,
    pub event_type: IssueEventType,
    pub title_digest: Digest,
    pub timestamp_millis: Option<i64>,
}

impl IssueEventRecord {
    pub fn new(
        issue_id: IssueId,
        priority: Severity,
        state: IssueState,
        event_type: IssueEventType,
        title: impl AsRef<str>,
        timestamp_millis: Option<i64>,
    ) -> Result<Self, ModelError> {
        issue_id.validate()?;
        let title = title.as_ref();
        if !title.is_empty() && title.len() > MAX_IDENTIFIER_BYTES {
            return Err(ModelError::InvalidBound {
                field: "issue event title",
            });
        }
        if timestamp_millis.is_some_and(|value| value < 0) {
            return Err(ModelError::InvalidBound {
                field: "issue event timestamp",
            });
        }
        Ok(Self {
            issue_id,
            priority,
            state,
            event_type,
            title_digest: Digest::from_parts(
                "newrelic-issue-event-title/v1",
                &[("value", title.to_owned())],
            ),
            timestamp_millis,
        })
    }

    pub fn digest(&self) -> Result<Digest, ModelError> {
        crate::model::digest_serializable(&(
            self.issue_id.digest(),
            self.priority,
            self.state,
            self.event_type,
            &self.title_digest,
            self.timestamp_millis,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityPage {
    pub entities: Vec<EntityRecord>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub redacted: bool,
}

impl EntityPage {
    pub fn new(
        entities: Vec<EntityRecord>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        validate_page(&entities, response_bytes)?;
        let response_digest = page_digest(
            "newrelic-entity-page/v1",
            entities.iter().map(EntityRecord::digest),
            next_cursor.as_ref(),
        );
        Ok(Self {
            entities,
            next_cursor,
            response_digest,
            response_bytes,
            redacted: true,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPage {
    pub policies: Vec<PolicyRecord>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub redacted: bool,
}

impl PolicyPage {
    pub fn new(
        policies: Vec<PolicyRecord>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        validate_page(&policies, response_bytes)?;
        let response_digest = page_digest(
            "newrelic-policy-page/v1",
            policies.iter().map(PolicyRecord::digest),
            next_cursor.as_ref(),
        );
        Ok(Self {
            policies,
            next_cursor,
            response_digest,
            response_bytes,
            redacted: true,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionPage {
    pub conditions: Vec<ConditionRecord>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub redacted: bool,
}

impl ConditionPage {
    pub fn new(
        conditions: Vec<ConditionRecord>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        validate_page(&conditions, response_bytes)?;
        let response_digest = page_digest(
            "newrelic-condition-page/v1",
            conditions.iter().map(ConditionRecord::digest),
            next_cursor.as_ref(),
        );
        Ok(Self {
            conditions,
            next_cursor,
            response_digest,
            response_bytes,
            redacted: true,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuePage {
    pub issues: Vec<IssueRecord>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub redacted: bool,
}

impl IssuePage {
    pub fn new(
        issues: Vec<IssueRecord>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        validate_page(&issues, response_bytes)?;
        let mut digests = Vec::with_capacity(issues.len());
        for issue in &issues {
            digests.push(issue.digest()?);
        }
        let response_digest = page_digest(
            "newrelic-issue-page/v1",
            digests.into_iter(),
            next_cursor.as_ref(),
        );
        Ok(Self {
            issues,
            next_cursor,
            response_digest,
            response_bytes,
            redacted: true,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueEventPage {
    pub events: Vec<IssueEventRecord>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub redacted: bool,
}

impl IssueEventPage {
    pub fn new(
        events: Vec<IssueEventRecord>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        validate_page(&events, response_bytes)?;
        let mut digests = Vec::with_capacity(events.len());
        for event in &events {
            digests.push(event.digest()?);
        }
        let response_digest = page_digest(
            "newrelic-issue-event-page/v1",
            digests.into_iter(),
            next_cursor.as_ref(),
        );
        Ok(Self {
            events,
            next_cursor,
            response_digest,
            response_bytes,
            redacted: true,
        })
    }
}

fn validate_page<T>(items: &[T], response_bytes: usize) -> Result<(), ModelError> {
    if items.len() > MAX_ITEMS_PER_PAGE
        || response_bytes == 0
        || response_bytes > MAX_RESPONSE_BYTES
    {
        Err(ModelError::InvalidBound {
            field: "provider response page",
        })
    } else {
        Ok(())
    }
}

fn page_digest(
    domain: &str,
    item_digests: impl Iterator<Item = Digest>,
    next_cursor: Option<&OpaqueCursor>,
) -> Digest {
    let mut fields = item_digests
        .enumerate()
        .map(|(index, digest)| (format!("item_{index}"), digest.as_str().to_owned()))
        .collect::<Vec<_>>();
    fields.push((
        "next_cursor".to_owned(),
        next_cursor.map_or_else(String::new, |value| value.digest().as_str().to_owned()),
    ));
    let fields = fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.clone()))
        .collect::<Vec<_>>();
    Digest::from_parts(domain, &fields)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderResponse {
    Entities(EntityPage),
    EntitySummary(EntityPage),
    Policies(PolicyPage),
    Conditions(ConditionPage),
    Issues(IssuePage),
    IssueEvents(IssueEventPage),
}

impl ProviderResponse {
    pub const fn operation(&self) -> ReadOperation {
        match self {
            Self::Entities(_) => ReadOperation::SearchEntities,
            Self::EntitySummary(_) => ReadOperation::ReadEntitySummary,
            Self::Policies(_) => ReadOperation::ReadAlertPolicies,
            Self::Conditions(_) => ReadOperation::ReadNrqlConditions,
            Self::Issues(_) => ReadOperation::ReadIssues,
            Self::IssueEvents(_) => ReadOperation::ReadIssueEvents,
        }
    }

    pub fn response_digest(&self) -> &Digest {
        match self {
            Self::Entities(page) | Self::EntitySummary(page) => &page.response_digest,
            Self::Policies(page) => &page.response_digest,
            Self::Conditions(page) => &page.response_digest,
            Self::Issues(page) => &page.response_digest,
            Self::IssueEvents(page) => &page.response_digest,
        }
    }

    pub fn next_cursor(&self) -> Option<&OpaqueCursor> {
        match self {
            Self::Entities(page) | Self::EntitySummary(page) => page.next_cursor.as_ref(),
            Self::Policies(page) => page.next_cursor.as_ref(),
            Self::Conditions(page) => page.next_cursor.as_ref(),
            Self::Issues(page) => page.next_cursor.as_ref(),
            Self::IssueEvents(page) => page.next_cursor.as_ref(),
        }
    }

    pub fn item_count(&self) -> usize {
        match self {
            Self::Entities(page) | Self::EntitySummary(page) => page.entities.len(),
            Self::Policies(page) => page.policies.len(),
            Self::Conditions(page) => page.conditions.len(),
            Self::Issues(page) => page.issues.len(),
            Self::IssueEvents(page) => page.events.len(),
        }
    }

    pub fn response_bytes(&self) -> usize {
        match self {
            Self::Entities(page) | Self::EntitySummary(page) => page.response_bytes,
            Self::Policies(page) => page.response_bytes,
            Self::Conditions(page) => page.response_bytes,
            Self::Issues(page) => page.response_bytes,
            Self::IssueEvents(page) => page.response_bytes,
        }
    }

    pub fn redacted(&self) -> bool {
        match self {
            Self::Entities(page) | Self::EntitySummary(page) => page.redacted,
            Self::Policies(page) => page.redacted,
            Self::Conditions(page) => page.redacted,
            Self::Issues(page) => page.redacted,
            Self::IssueEvents(page) => page.redacted,
        }
    }

    pub fn validate_for(&self, request: &NewRelicReadRequest) -> Result<(), ProviderError> {
        if self.operation() != request.operation
            || !self.redacted()
            || self.response_bytes() > request.max_response_bytes
            || self.response_bytes() == 0
            || self.item_count() > usize::from(request.page_size)
        {
            return Err(ProviderError::UnexpectedResponse);
        }
        if let Some(cursor) = self.next_cursor() {
            cursor
                .validate_for(&request.query_digest)
                .map_err(|_| ProviderError::UnexpectedResponse)?;
            if cursor.page() <= request.cursor.as_ref().map_or(1, OpaqueCursor::page) {
                return Err(ProviderError::UnexpectedResponse);
            }
        }
        let expected = match self {
            Self::Entities(page) | Self::EntitySummary(page) => page_digest(
                "newrelic-entity-page/v1",
                page.entities.iter().map(EntityRecord::digest),
                page.next_cursor.as_ref(),
            ),
            Self::Policies(page) => page_digest(
                "newrelic-policy-page/v1",
                page.policies.iter().map(PolicyRecord::digest),
                page.next_cursor.as_ref(),
            ),
            Self::Conditions(page) => page_digest(
                "newrelic-condition-page/v1",
                page.conditions.iter().map(ConditionRecord::digest),
                page.next_cursor.as_ref(),
            ),
            Self::Issues(page) => {
                let mut digests = Vec::with_capacity(page.issues.len());
                for issue in &page.issues {
                    digests.push(
                        issue
                            .digest()
                            .map_err(|_| ProviderError::UnexpectedResponse)?,
                    );
                }
                page_digest(
                    "newrelic-issue-page/v1",
                    digests.into_iter(),
                    page.next_cursor.as_ref(),
                )
            }
            Self::IssueEvents(page) => {
                let mut digests = Vec::with_capacity(page.events.len());
                for event in &page.events {
                    digests.push(
                        event
                            .digest()
                            .map_err(|_| ProviderError::UnexpectedResponse)?,
                    );
                }
                page_digest(
                    "newrelic-issue-event-page/v1",
                    digests.into_iter(),
                    page.next_cursor.as_ref(),
                )
            }
        };
        if expected == *self.response_digest() {
            Ok(())
        } else {
            Err(ProviderError::UnexpectedResponse)
        }
    }
}

pub trait NewRelicTransport: fmt::Debug {
    fn send(&mut self, request: &NewRelicReadRequest) -> Result<ProviderResponse, TransportError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderDefinition {
    pub id: String,
    pub service_id: String,
    pub version: String,
    pub api_revision: String,
    pub provenance: TransportProvenance,
    pub operations: Vec<ReadOperation>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub digest: Digest,
}

impl ProviderDefinition {
    fn new(provenance: TransportProvenance) -> Self {
        let operations = ALL_READ_OPERATIONS.to_vec();
        let digest = Digest::from_parts(
            "newrelic-provider-definition/v1",
            &[
                ("id", PROVIDER_ID.to_owned()),
                ("service", SERVICE_ID.to_owned()),
                ("version", PLUGIN_VERSION.to_owned()),
                ("api", API_REVISION.to_owned()),
                ("provenance", format!("{provenance:?}")),
                (
                    "operations",
                    operations
                        .iter()
                        .map(|value| value.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Self {
            id: PROVIDER_ID.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            version: PLUGIN_VERSION.to_owned(),
            api_revision: API_REVISION.to_owned(),
            provenance,
            operations,
            connected: false,
            native: false,
            first_party: false,
            digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.connected || self.native || self.first_party {
            return Err(ModelError::InvalidScope);
        }
        if self.operations != ALL_READ_OPERATIONS {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ProviderRead {
    pub response: ProviderResponse,
    pub retries: Vec<RetryEvidence>,
}

pub struct NewRelicProvider<T> {
    transport: T,
    definition: ProviderDefinition,
    retry_policy: RetryPolicy,
}

impl<T: fmt::Debug> fmt::Debug for NewRelicProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewRelicProvider")
            .field("transport", &self.transport)
            .field("definition", &self.definition)
            .field("retry_policy", &self.retry_policy)
            .finish()
    }
}

impl<T: NewRelicTransport> NewRelicProvider<T> {
    pub fn new(
        transport: T,
        provenance: TransportProvenance,
        retry_policy: RetryPolicy,
    ) -> Result<Self, ModelError> {
        retry_policy.validate()?;
        let definition = ProviderDefinition::new(provenance);
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
            retry_policy,
        })
    }

    pub fn recording(transport: T) -> Result<Self, ModelError> {
        Self::new(
            transport,
            TransportProvenance::Recording,
            RetryPolicy::bounded_default()?,
        )
    }

    pub fn fixture(transport: T) -> Result<Self, ModelError> {
        Self::new(
            transport,
            TransportProvenance::Fixture,
            RetryPolicy::bounded_default()?,
        )
    }

    pub fn loopback(transport: T) -> Result<Self, ModelError> {
        Self::new(
            transport,
            TransportProvenance::Loopback,
            RetryPolicy::bounded_default()?,
        )
    }

    pub fn blocked_env(transport: T) -> Result<Self, ModelError> {
        Self::new(
            transport,
            TransportProvenance::BlockedEnv,
            RetryPolicy::bounded_default()?,
        )
    }

    pub fn definition(&self) -> &ProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.definition.digest
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry_policy
    }

    pub fn read(
        &mut self,
        request: &NewRelicReadRequest,
        scope: &ObservabilityScope,
    ) -> Result<ProviderRead, ProviderError> {
        request.validate(scope)?;
        if !self.definition.operations.contains(&request.operation) {
            return Err(ProviderError::UnexpectedResponse);
        }
        let mut retries = Vec::new();
        for attempt in 1..=self.retry_policy.max_attempts {
            match self.transport.send(request) {
                Ok(response) => {
                    response.validate_for(request)?;
                    return Ok(ProviderRead { response, retries });
                }
                Err(error)
                    if error.failure.retryable() && attempt < self.retry_policy.max_attempts =>
                {
                    retries.push(RetryEvidence {
                        operation: request.operation,
                        failed_attempt: attempt,
                        delay_millis: self
                            .retry_policy
                            .delay_millis(attempt, error.retry_after_millis),
                        failure: error.failure,
                        status_code: error.status_code,
                        diagnostic_digest: error.diagnostic_digest,
                    });
                }
                Err(error) => {
                    return Err(ProviderError::Transport { error, retries });
                }
            }
        }
        Err(ProviderError::UnexpectedResponse)
    }
}

#[derive(Debug, Default)]
pub struct BlockedEnvTransport;

impl NewRelicTransport for BlockedEnvTransport {
    fn send(&mut self, _request: &NewRelicReadRequest) -> Result<ProviderResponse, TransportError> {
        Err(TransportError::blocked_env())
    }
}

macro_rules! scripted_transport {
    ($name:ident) => {
        #[derive(Debug, Default)]
        pub struct $name {
            responses: VecDeque<Result<ProviderResponse, TransportError>>,
        }

        impl $name {
            pub fn new(responses: Vec<Result<ProviderResponse, TransportError>>) -> Self {
                Self {
                    responses: responses.into_iter().collect(),
                }
            }

            pub fn push(&mut self, response: Result<ProviderResponse, TransportError>) {
                self.responses.push_back(response);
            }
        }

        impl NewRelicTransport for $name {
            fn send(
                &mut self,
                _request: &NewRelicReadRequest,
            ) -> Result<ProviderResponse, TransportError> {
                self.responses
                    .pop_front()
                    .unwrap_or_else(|| Err(TransportError::malformed()))
            }
        }
    };
}

scripted_transport!(RecordingTransport);
scripted_transport!(FixtureTransport);
scripted_transport!(LoopbackTransport);
