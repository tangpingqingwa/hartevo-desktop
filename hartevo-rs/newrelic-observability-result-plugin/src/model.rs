use std::{fmt, time::Duration};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::ModelError;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 512;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u8 = 4;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_ITEMS_PER_PAGE: usize = 100;
pub const MAX_TIME_WINDOW_MILLIS: i64 = 31 * 24 * 60 * 60 * 1_000;
pub const MAX_RETRY_ATTEMPTS: u8 = 4;
pub const MAX_RETRY_DELAY_MILLIS: u32 = 30_000;

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(&Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for (name, value) in fields {
            append_field(&mut bytes, name);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(ModelError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::Serialization)?;
    Ok(Digest::from_bytes(&bytes))
}

fn valid_text(value: &str, max_bytes: usize, allow_internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str) -> bool {
    valid_text(value, MAX_IDENTIFIER_BYTES, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'+' | b'=' | b'|')
        })
}

macro_rules! identifier_type {
    ($name:ident, $field:literal, $domain:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, &[("value", self.0.clone())])
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub fn validate(&self) -> Result<(), ModelError> {
                if valid_identifier(&self.0) {
                    Ok(())
                } else {
                    Err(ModelError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.redacted())
                    .finish()
            }
        }
    };
}

identifier_type!(EntityGuid, "entity-guid", "newrelic-entity-guid/v1");
identifier_type!(EntityType, "entity-type", "newrelic-entity-type/v1");
identifier_type!(WorkloadId, "workload", "newrelic-workload/v1");
identifier_type!(PolicyId, "policy", "newrelic-policy/v1");
identifier_type!(ConditionId, "condition", "newrelic-condition/v1");
identifier_type!(IssueId, "issue", "newrelic-issue/v1");
identifier_type!(ProjectId, "project", "hartevo-project/v1");
identifier_type!(MissionId, "mission", "hartevo-mission/v1");
identifier_type!(WorkProductId, "work-product", "hartevo-work-product/v1");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AccountId(u64);

impl AccountId {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidIdentifier { field: "account" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn digest(self) -> Digest {
        Digest::from_parts("newrelic-account/v1", &[("value", self.0.to_string())])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimeWindow {
    pub start_millis: i64,
    pub end_millis: i64,
    pub digest: Digest,
}

impl TimeWindow {
    pub fn new(start_millis: i64, end_millis: i64) -> Result<Self, ModelError> {
        if start_millis < 0
            || end_millis <= start_millis
            || end_millis - start_millis > MAX_TIME_WINDOW_MILLIS
        {
            return Err(ModelError::InvalidTimeWindow);
        }
        let digest = Digest::from_parts(
            "newrelic-time-window/v1",
            &[
                ("start", start_millis.to_string()),
                ("end", end_millis.to_string()),
            ],
        );
        Ok(Self {
            start_millis,
            end_millis,
            digest,
        })
    }

    pub fn duration(&self) -> Duration {
        Duration::from_millis((self.end_millis - self.start_millis).cast_unsigned())
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::new(self.start_millis, self.end_millis)?;
        if expected.digest == self.digest {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    EntitySearchRead,
    EntitySummaryRead,
    AlertPolicyRead,
    NrqlConditionRead,
    IssuesRead,
    IssueEventsRead,
}

impl Permission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EntitySearchRead => "entity_search.read",
            Self::EntitySummaryRead => "entity_summary.read",
            Self::AlertPolicyRead => "alert_policy.read",
            Self::NrqlConditionRead => "nrql_condition.read",
            Self::IssuesRead => "issues.read",
            Self::IssueEventsRead => "issue_events.read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub permissions: Vec<Permission>,
    pub revision: u64,
    pub digest: Digest,
}

impl PermissionSnapshot {
    pub fn new(mut permissions: Vec<Permission>, revision: u64) -> Result<Self, ModelError> {
        if permissions.is_empty() || revision == 0 {
            return Err(ModelError::InvalidBound {
                field: "permission snapshot",
            });
        }
        permissions.sort_unstable();
        permissions.dedup();
        let digest = digest_serializable(&(permissions.clone(), revision))?;
        Ok(Self {
            permissions,
            revision,
            digest,
        })
    }

    pub fn allows(&self, permission: Permission) -> bool {
        self.permissions.binary_search(&permission).is_ok()
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::new(self.permissions.clone(), self.revision)?;
        if expected.digest == self.digest {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadOperation {
    SearchEntities,
    ReadEntitySummary,
    ReadAlertPolicies,
    ReadNrqlConditions,
    ReadIssues,
    ReadIssueEvents,
}

impl ReadOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SearchEntities => "search_entities",
            Self::ReadEntitySummary => "read_entity_summary",
            Self::ReadAlertPolicies => "read_alert_policies",
            Self::ReadNrqlConditions => "read_nrql_conditions",
            Self::ReadIssues => "read_issues",
            Self::ReadIssueEvents => "read_issue_events",
        }
    }

    pub const fn permission(self) -> Permission {
        match self {
            Self::SearchEntities => Permission::EntitySearchRead,
            Self::ReadEntitySummary => Permission::EntitySummaryRead,
            Self::ReadAlertPolicies => Permission::AlertPolicyRead,
            Self::ReadNrqlConditions => Permission::NrqlConditionRead,
            Self::ReadIssues => Permission::IssuesRead,
            Self::ReadIssueEvents => Permission::IssueEventsRead,
        }
    }
}

pub const ALL_READ_OPERATIONS: [ReadOperation; 6] = [
    ReadOperation::SearchEntities,
    ReadOperation::ReadEntitySummary,
    ReadOperation::ReadAlertPolicies,
    ReadOperation::ReadNrqlConditions,
    ReadOperation::ReadIssues,
    ReadOperation::ReadIssueEvents,
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryPolicy {
    pub operations: Vec<ReadOperation>,
    pub max_pages: u8,
    pub page_size: u16,
    pub max_response_bytes: usize,
    pub arbitrary_query: bool,
    pub digest: Digest,
}

impl QueryPolicy {
    pub fn bounded_default() -> Result<Self, ModelError> {
        Self::new(
            ALL_READ_OPERATIONS.to_vec(),
            MAX_PAGES,
            MAX_PAGE_SIZE,
            MAX_RESPONSE_BYTES,
        )
    }

    pub fn new(
        mut operations: Vec<ReadOperation>,
        max_pages: u8,
        page_size: u16,
        max_response_bytes: usize,
    ) -> Result<Self, ModelError> {
        if operations.is_empty()
            || max_pages == 0
            || max_pages > MAX_PAGES
            || page_size == 0
            || page_size > MAX_PAGE_SIZE
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(ModelError::InvalidBound {
                field: "query policy",
            });
        }
        operations.sort_unstable();
        operations.dedup();
        let digest =
            digest_serializable(&(operations.clone(), max_pages, page_size, max_response_bytes))?;
        Ok(Self {
            operations,
            max_pages,
            page_size,
            max_response_bytes,
            arbitrary_query: false,
            digest,
        })
    }

    pub fn allows(&self, operation: ReadOperation) -> bool {
        self.operations.binary_search(&operation).is_ok()
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.arbitrary_query {
            return Err(ModelError::InvalidScope);
        }
        let expected = Self::new(
            self.operations.clone(),
            self.max_pages,
            self.page_size,
            self.max_response_bytes,
        )?;
        if expected.digest == self.digest {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: u64,
    pub digest: Digest,
}

impl ProjectBinding {
    pub fn new(id: ProjectId, revision: u64) -> Result<Self, ModelError> {
        if revision == 0 {
            return Err(ModelError::InvalidBound {
                field: "project revision",
            });
        }
        let digest = Digest::from_parts(
            "hartevo-project-binding/v1",
            &[
                ("id", id.digest().as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(Self {
            id,
            revision,
            digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.id.validate()?;
        let expected = Self::new(self.id.clone(), self.revision)?;
        if expected.digest == self.digest {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: u64,
    pub digest: Digest,
}

impl WorkProductBinding {
    pub fn new(id: WorkProductId, revision: u64) -> Result<Self, ModelError> {
        if revision == 0 {
            return Err(ModelError::InvalidBound {
                field: "work product revision",
            });
        }
        let digest = Digest::from_parts(
            "hartevo-work-product-binding/v1",
            &[
                ("id", id.digest().as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(Self {
            id,
            revision,
            digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.id.validate()?;
        let expected = Self::new(self.id.clone(), self.revision)?;
        if expected.digest == self.digest {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentBinding {
    pub digest: Digest,
    pub read_only: bool,
}

impl ConsentBinding {
    pub fn read_only(digest: Digest) -> Result<Self, ModelError> {
        digest.validate()?;
        Ok(Self {
            digest,
            read_only: true,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.digest.validate()?;
        if self.read_only {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: u64,
    pub project_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub digest: Digest,
}

impl MissionBinding {
    pub fn new(
        id: MissionId,
        revision: u64,
        project: &ProjectBinding,
        work_product: &WorkProductBinding,
        consent: &ConsentBinding,
    ) -> Result<Self, ModelError> {
        if revision == 0 {
            return Err(ModelError::InvalidBound {
                field: "mission revision",
            });
        }
        project.validate()?;
        work_product.validate()?;
        consent.validate()?;
        let project_digest = project.digest.clone();
        let work_product_digest = work_product.digest.clone();
        let consent_digest = consent.digest.clone();
        let digest = Digest::from_parts(
            "hartevo-mission-binding/v1",
            &[
                ("id", id.digest().as_str().to_owned()),
                ("revision", revision.to_string()),
                ("project", project_digest.as_str().to_owned()),
                ("work_product", work_product_digest.as_str().to_owned()),
                ("consent", consent_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            id,
            revision,
            project_digest,
            work_product_digest,
            consent_digest,
            digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.id.validate()?;
        for digest in [
            &self.project_digest,
            &self.work_product_digest,
            &self.consent_digest,
        ] {
            digest.validate()?;
        }
        let expected = Digest::from_parts(
            "hartevo-mission-binding/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
                ("project", self.project_digest.as_str().to_owned()),
                ("work_product", self.work_product_digest.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
            ],
        );
        if expected == self.digest {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadReference {
    pub id: WorkloadId,
    name_digest: Digest,
    entity_type: EntityType,
    digest: Digest,
}

impl WorkloadReference {
    pub fn new(
        id: WorkloadId,
        display_name: impl Into<String>,
        entity_type: EntityType,
    ) -> Result<Self, ModelError> {
        let display_name = display_name.into();
        if !valid_text(&display_name, MAX_IDENTIFIER_BYTES, true) {
            return Err(ModelError::InvalidIdentifier {
                field: "workload name",
            });
        }
        let name_digest =
            Digest::from_parts("newrelic-workload-name/v1", &[("value", display_name)]);
        let digest = Digest::from_parts(
            "newrelic-workload-reference/v1",
            &[
                ("id", id.digest().as_str().to_owned()),
                ("name", name_digest.as_str().to_owned()),
                ("type", entity_type.digest().as_str().to_owned()),
            ],
        );
        Ok(Self {
            id,
            name_digest,
            entity_type,
            digest,
        })
    }

    pub fn name_digest(&self) -> &Digest {
        &self.name_digest
    }

    pub fn entity_type(&self) -> &EntityType {
        &self.entity_type
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.id.validate()?;
        self.entity_type.validate()?;
        self.name_digest.validate()?;
        let expected = Digest::from_parts(
            "newrelic-workload-reference/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("name", self.name_digest.as_str().to_owned()),
                ("type", self.entity_type.digest().as_str().to_owned()),
            ],
        );
        if expected == self.digest {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityReference {
    pub guid: EntityGuid,
    pub entity_type: EntityType,
    digest: Digest,
}

impl EntityReference {
    pub fn new(guid: EntityGuid, entity_type: EntityType) -> Result<Self, ModelError> {
        let digest = Digest::from_parts(
            "newrelic-entity-reference/v1",
            &[
                ("guid", guid.digest().as_str().to_owned()),
                ("type", entity_type.digest().as_str().to_owned()),
            ],
        );
        Ok(Self {
            guid,
            entity_type,
            digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.guid.validate()?;
        self.entity_type.validate()?;
        let expected = Digest::from_parts(
            "newrelic-entity-reference/v1",
            &[
                ("guid", self.guid.digest().as_str().to_owned()),
                ("type", self.entity_type.digest().as_str().to_owned()),
            ],
        );
        if expected == self.digest {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyReference {
    pub id: PolicyId,
    pub revision_digest: Digest,
    digest: Digest,
}

impl PolicyReference {
    pub fn new(id: PolicyId, revision: impl AsRef<str>) -> Result<Self, ModelError> {
        let revision = revision.as_ref();
        if !valid_text(revision, MAX_IDENTIFIER_BYTES, true) {
            return Err(ModelError::InvalidIdentifier {
                field: "policy revision",
            });
        }
        let revision_digest = Digest::from_parts(
            "newrelic-policy-revision/v1",
            &[("value", revision.to_owned())],
        );
        let digest = Digest::from_parts(
            "newrelic-policy-reference/v1",
            &[
                ("id", id.digest().as_str().to_owned()),
                ("revision", revision_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            id,
            revision_digest,
            digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.id.validate()?;
        self.revision_digest.validate()?;
        let expected = Digest::from_parts(
            "newrelic-policy-reference/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision_digest.as_str().to_owned()),
            ],
        );
        if expected == self.digest {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionReference {
    pub id: ConditionId,
    pub policy_digest: Digest,
    pub revision_digest: Digest,
    digest: Digest,
}

impl ConditionReference {
    pub fn new(
        id: ConditionId,
        policy: &PolicyReference,
        revision: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        let revision = revision.as_ref();
        if !valid_text(revision, MAX_IDENTIFIER_BYTES, true) {
            return Err(ModelError::InvalidIdentifier {
                field: "condition revision",
            });
        }
        let revision_digest = Digest::from_parts(
            "newrelic-condition-revision/v1",
            &[("value", revision.to_owned())],
        );
        let policy_digest = policy.digest.clone();
        let digest = Digest::from_parts(
            "newrelic-condition-reference/v1",
            &[
                ("id", id.digest().as_str().to_owned()),
                ("policy", policy_digest.as_str().to_owned()),
                ("revision", revision_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            id,
            policy_digest,
            revision_digest,
            digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.id.validate()?;
        self.policy_digest.validate()?;
        self.revision_digest.validate()?;
        let expected = Digest::from_parts(
            "newrelic-condition-reference/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("policy", self.policy_digest.as_str().to_owned()),
                ("revision", self.revision_digest.as_str().to_owned()),
            ],
        );
        if expected == self.digest {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservabilityScope {
    account: AccountId,
    entity: EntityReference,
    workload: WorkloadReference,
    policy: PolicyReference,
    condition: ConditionReference,
    time_window: TimeWindow,
    mission: MissionBinding,
    project: ProjectBinding,
    work_product: WorkProductBinding,
    consent: ConsentBinding,
    permissions: PermissionSnapshot,
    query_policy: QueryPolicy,
    scope_digest: Digest,
}

impl ObservabilityScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AccountId,
        entity: EntityReference,
        workload: WorkloadReference,
        policy: PolicyReference,
        condition: ConditionReference,
        time_window: TimeWindow,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        consent: ConsentBinding,
        permissions: PermissionSnapshot,
        query_policy: QueryPolicy,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            account,
            entity,
            workload,
            policy,
            condition,
            time_window,
            mission,
            project,
            work_product,
            consent,
            permissions,
            query_policy,
            scope_digest: Digest::from_text("pending-newrelic-observability-scope"),
        };
        scope.validate_fields()?;
        let scope_digest = scope.compute_digest();
        Ok(Self {
            scope_digest,
            ..scope
        })
    }

    fn validate_fields(&self) -> Result<(), ModelError> {
        if self.account.get() == 0 {
            return Err(ModelError::InvalidScope);
        }
        self.entity.validate()?;
        self.workload.validate()?;
        self.policy.validate()?;
        self.condition.validate()?;
        self.time_window.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        self.consent.validate()?;
        self.permissions.validate()?;
        self.query_policy.validate()?;
        if self.condition.policy_digest != *self.policy.digest() {
            return Err(ModelError::InvalidScope);
        }
        if self.mission.project_digest != self.project.digest
            || self.mission.work_product_digest != self.work_product.digest
            || self.mission.consent_digest != self.consent.digest
        {
            return Err(ModelError::InvalidScope);
        }
        for operation in ALL_READ_OPERATIONS {
            if !self.query_policy.allows(operation)
                || !self.permissions.allows(operation.permission())
            {
                return Err(ModelError::InvalidScope);
            }
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "newrelic-observability-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("entity", self.entity.digest.as_str().to_owned()),
                ("workload", self.workload.digest.as_str().to_owned()),
                ("policy", self.policy.digest.as_str().to_owned()),
                ("condition", self.condition.digest.as_str().to_owned()),
                ("window", self.time_window.digest.as_str().to_owned()),
                ("mission", self.mission.digest.as_str().to_owned()),
                ("project", self.project.digest.as_str().to_owned()),
                ("work_product", self.work_product.digest.as_str().to_owned()),
                ("consent", self.consent.digest.as_str().to_owned()),
                ("permissions", self.permissions.digest.as_str().to_owned()),
                ("query", self.query_policy.digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.validate_fields()?;
        if self.compute_digest() == self.scope_digest {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }

    pub fn account(&self) -> AccountId {
        self.account
    }

    pub fn entity(&self) -> &EntityReference {
        &self.entity
    }

    pub fn workload(&self) -> &WorkloadReference {
        &self.workload
    }

    pub fn policy(&self) -> &PolicyReference {
        &self.policy
    }

    pub fn condition(&self) -> &ConditionReference {
        &self.condition
    }

    pub fn time_window(&self) -> &TimeWindow {
        &self.time_window
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    pub fn consent(&self) -> &ConsentBinding {
        &self.consent
    }

    pub fn permissions(&self) -> &PermissionSnapshot {
        &self.permissions
    }

    pub fn query_policy(&self) -> &QueryPolicy {
        &self.query_policy
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    secret_digest: Digest,
    scope_digest: Digest,
    revoked: bool,
}

impl SecretReference {
    pub fn from_opaque_handle(
        handle: impl AsRef<str>,
        scope_digest: &Digest,
    ) -> Result<Self, ModelError> {
        let handle = handle.as_ref();
        if !valid_text(handle, MAX_SECRET_REFERENCE_BYTES, false) {
            return Err(ModelError::InvalidSecretReference);
        }
        scope_digest.validate()?;
        Ok(Self {
            secret_digest: Digest::from_parts(
                "newrelic-secret-reference/v1",
                &[("opaque_handle", handle.to_owned())],
            ),
            scope_digest: scope_digest.clone(),
            revoked: false,
        })
    }

    pub fn secret_digest(&self) -> &Digest {
        &self.secret_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::InvalidSecretReference);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn validate_for(&self, scope: &ObservabilityScope) -> Result<(), ModelError> {
        if self.revoked || self.scope_digest != *scope.digest() {
            Err(ModelError::InvalidSecretReference)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("secret_digest", &self.secret_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IssueState {
    Created,
    Activated,
    Deactivated,
    Closed,
}

impl IssueState {
    pub const fn is_closed(self) -> bool {
        matches!(self, Self::Closed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ConditionType {
    Static,
    Baseline,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IssueEventType {
    IncidentAdded,
    AttributesUpdated,
    Closed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationState {
    Reporting,
    Healthy,
    Degraded,
    Alerting,
    Closed,
    NoTelemetry,
    Partial,
    Stale,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    Partial,
    AccessLost,
    ProviderUnknown,
    Stale,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AuthorityBoundary {
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub raw_telemetry: bool,
    pub external_writes: bool,
    pub adopts_outcome: bool,
}

impl AuthorityBoundary {
    pub const fn layer1() -> Self {
        Self {
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
            raw_telemetry: false,
            external_writes: false,
            adopts_outcome: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaqueCursor {
    digest: Digest,
    query_digest: Digest,
    page: u8,
}

impl OpaqueCursor {
    pub fn new(
        provider_cursor: impl AsRef<str>,
        query_digest: &Digest,
        page: u8,
    ) -> Result<Self, ModelError> {
        let provider_cursor = provider_cursor.as_ref();
        if !valid_text(provider_cursor, MAX_IDENTIFIER_BYTES, false) || page < 2 {
            return Err(ModelError::InvalidCursor);
        }
        query_digest.validate()?;
        Ok(Self {
            digest: Digest::from_parts(
                "newrelic-opaque-cursor/v1",
                &[
                    ("cursor", provider_cursor.to_owned()),
                    ("query", query_digest.as_str().to_owned()),
                    ("page", page.to_string()),
                ],
            ),
            query_digest: query_digest.clone(),
            page,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub const fn page(&self) -> u8 {
        self.page
    }

    pub fn validate_for(&self, query_digest: &Digest) -> Result<(), ModelError> {
        self.digest.validate()?;
        if self.query_digest == *query_digest && self.page >= 2 {
            Ok(())
        } else {
            Err(ModelError::InvalidCursor)
        }
    }
}
