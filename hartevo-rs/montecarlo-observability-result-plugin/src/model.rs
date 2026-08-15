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
pub const MAX_LINEAGE_EDGES: usize = 100;
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

identifier_type!(OrganizationId, "organization", "montecarlo-organization/v1");
identifier_type!(
    MonteCarloProjectId,
    "Monte Carlo project",
    "montecarlo-project/v1"
);
identifier_type!(WarehouseId, "warehouse", "montecarlo-warehouse/v1");
identifier_type!(TableId, "table", "montecarlo-table/v1");
identifier_type!(IncidentId, "incident", "montecarlo-incident/v1");
identifier_type!(LineageId, "lineage", "montecarlo-lineage/v1");
identifier_type!(MonitorId, "monitor", "montecarlo-monitor/v1");
identifier_type!(ProjectId, "project", "hartevo-project/v1");
identifier_type!(MissionId, "mission", "hartevo-mission/v1");
identifier_type!(WorkProductId, "work product", "hartevo-work-product/v1");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidBound { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
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
            "montecarlo-time-window/v1",
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
    IncidentRead,
    FreshnessRead,
    LineageRead,
    MonitorRead,
}

impl Permission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IncidentRead => "incident.read",
            Self::FreshnessRead => "freshness.read",
            Self::LineageRead => "lineage.read",
            Self::MonitorRead => "monitor.read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub permissions: Vec<Permission>,
    pub revision: Revision,
    pub digest: Digest,
}

impl PermissionSnapshot {
    pub fn new(mut permissions: Vec<Permission>, revision: Revision) -> Result<Self, ModelError> {
        if permissions.is_empty() {
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
    ReadIncidents,
    ReadFreshness,
    ReadLineage,
    ReadMonitors,
}

impl ReadOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadIncidents => "read_incidents",
            Self::ReadFreshness => "read_freshness",
            Self::ReadLineage => "read_lineage",
            Self::ReadMonitors => "read_monitors",
        }
    }

    pub const fn permission(self) -> Permission {
        match self {
            Self::ReadIncidents => Permission::IncidentRead,
            Self::ReadFreshness => Permission::FreshnessRead,
            Self::ReadLineage => Permission::LineageRead,
            Self::ReadMonitors => Permission::MonitorRead,
        }
    }
}

pub const ALL_READ_OPERATIONS: [ReadOperation; 4] = [
    ReadOperation::ReadIncidents,
    ReadOperation::ReadFreshness,
    ReadOperation::ReadLineage,
    ReadOperation::ReadMonitors,
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
    pub revision: Revision,
    pub digest: Digest,
}

impl ProjectBinding {
    pub fn new(id: ProjectId, revision: Revision) -> Result<Self, ModelError> {
        let digest = Digest::from_parts(
            "hartevo-project-binding/v1",
            &[
                ("id", id.digest().as_str().to_owned()),
                ("revision", revision.get().to_string()),
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
    pub revision: Revision,
    pub digest: Digest,
}

impl WorkProductBinding {
    pub fn new(id: WorkProductId, revision: Revision) -> Result<Self, ModelError> {
        let digest = Digest::from_parts(
            "hartevo-work-product-binding/v1",
            &[
                ("id", id.digest().as_str().to_owned()),
                ("revision", revision.get().to_string()),
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
    pub revision: Revision,
    pub project_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub digest: Digest,
}

impl MissionBinding {
    pub fn new(
        id: MissionId,
        revision: Revision,
        project: &ProjectBinding,
        work_product: &WorkProductBinding,
        consent: &ConsentBinding,
    ) -> Result<Self, ModelError> {
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
                ("revision", revision.get().to_string()),
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
                ("revision", self.revision.get().to_string()),
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

macro_rules! named_reference {
    ($name:ident, $id:ident, $field:literal, $domain:literal) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            pub id: $id,
            pub name_digest: Digest,
            digest: Digest,
        }

        impl $name {
            pub fn new(id: $id, name: impl AsRef<str>) -> Result<Self, ModelError> {
                let name = name.as_ref();
                if !valid_text(name, MAX_IDENTIFIER_BYTES, true) {
                    return Err(ModelError::InvalidIdentifier { field: $field });
                }
                let name_digest =
                    Digest::from_parts(concat!($domain, "-name/v1"), &[("value", name.to_owned())]);
                let digest = Digest::from_parts(
                    concat!($domain, "-reference/v1"),
                    &[
                        ("id", id.digest().as_str().to_owned()),
                        ("name", name_digest.as_str().to_owned()),
                    ],
                );
                Ok(Self {
                    id,
                    name_digest,
                    digest,
                })
            }

            pub fn digest(&self) -> &Digest {
                &self.digest
            }

            pub fn validate(&self) -> Result<(), ModelError> {
                self.id.validate()?;
                self.name_digest.validate()?;
                let expected = Digest::from_parts(
                    concat!($domain, "-reference/v1"),
                    &[
                        ("id", self.id.digest().as_str().to_owned()),
                        ("name", self.name_digest.as_str().to_owned()),
                    ],
                );
                if expected == self.digest {
                    Ok(())
                } else {
                    Err(ModelError::InvalidScope)
                }
            }
        }
    };
}

named_reference!(
    MonteCarloProjectReference,
    MonteCarloProjectId,
    "project name",
    "montecarlo-project"
);
named_reference!(
    WarehouseReference,
    WarehouseId,
    "warehouse name",
    "montecarlo-warehouse"
);
named_reference!(TableReference, TableId, "table name", "montecarlo-table");

macro_rules! revision_reference {
    ($name:ident, $id:ident, $field:literal, $domain:literal) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            pub id: $id,
            pub revision_digest: Digest,
            digest: Digest,
        }

        impl $name {
            pub fn new(id: $id, revision: impl AsRef<str>) -> Result<Self, ModelError> {
                let revision = revision.as_ref();
                if !valid_text(revision, MAX_IDENTIFIER_BYTES, true) {
                    return Err(ModelError::InvalidIdentifier { field: $field });
                }
                let revision_digest = Digest::from_parts(
                    concat!($domain, "-revision/v1"),
                    &[("value", revision.to_owned())],
                );
                let digest = Digest::from_parts(
                    concat!($domain, "-reference/v1"),
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
                    concat!($domain, "-reference/v1"),
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
    };
}

revision_reference!(
    IncidentReference,
    IncidentId,
    "incident revision",
    "montecarlo-incident"
);
revision_reference!(
    LineageReference,
    LineageId,
    "lineage revision",
    "montecarlo-lineage"
);
revision_reference!(
    MonitorReference,
    MonitorId,
    "monitor revision",
    "montecarlo-monitor"
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonteCarloObservabilityScope {
    organization: OrganizationId,
    project: MonteCarloProjectReference,
    warehouse: WarehouseReference,
    table: TableReference,
    incident: IncidentReference,
    lineage: LineageReference,
    monitor: MonitorReference,
    time_window: TimeWindow,
    mission: MissionBinding,
    project_binding: ProjectBinding,
    work_product: WorkProductBinding,
    consent: ConsentBinding,
    permissions: PermissionSnapshot,
    query_policy: QueryPolicy,
    scope_digest: Digest,
}

impl MonteCarloObservabilityScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization: OrganizationId,
        project: MonteCarloProjectReference,
        warehouse: WarehouseReference,
        table: TableReference,
        incident: IncidentReference,
        lineage: LineageReference,
        monitor: MonitorReference,
        time_window: TimeWindow,
        mission: MissionBinding,
        project_binding: ProjectBinding,
        work_product: WorkProductBinding,
        consent: ConsentBinding,
        permissions: PermissionSnapshot,
        query_policy: QueryPolicy,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            organization,
            project,
            warehouse,
            table,
            incident,
            lineage,
            monitor,
            time_window,
            mission,
            project_binding,
            work_product,
            consent,
            permissions,
            query_policy,
            scope_digest: Digest::from_text("pending-montecarlo-scope"),
        };
        scope.validate_fields()?;
        let scope_digest = scope.compute_digest();
        Ok(Self {
            scope_digest,
            ..scope
        })
    }

    fn validate_fields(&self) -> Result<(), ModelError> {
        self.organization.validate()?;
        self.project.validate()?;
        self.warehouse.validate()?;
        self.table.validate()?;
        self.incident.validate()?;
        self.lineage.validate()?;
        self.monitor.validate()?;
        self.time_window.validate()?;
        self.mission.validate()?;
        self.project_binding.validate()?;
        self.work_product.validate()?;
        self.consent.validate()?;
        self.permissions.validate()?;
        self.query_policy.validate()?;
        if self.mission.project_digest != self.project_binding.digest
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
            "montecarlo-observability-scope/v1",
            &[
                (
                    "organization",
                    self.organization.digest().as_str().to_owned(),
                ),
                ("project", self.project.digest().as_str().to_owned()),
                ("warehouse", self.warehouse.digest().as_str().to_owned()),
                ("table", self.table.digest().as_str().to_owned()),
                ("incident", self.incident.digest().as_str().to_owned()),
                ("lineage", self.lineage.digest().as_str().to_owned()),
                ("monitor", self.monitor.digest().as_str().to_owned()),
                ("window", self.time_window.digest.as_str().to_owned()),
                ("mission", self.mission.digest.as_str().to_owned()),
                (
                    "project_binding",
                    self.project_binding.digest.as_str().to_owned(),
                ),
                ("work_product", self.work_product.digest.as_str().to_owned()),
                ("consent", self.consent.digest.as_str().to_owned()),
                ("permission", self.permissions.digest.as_str().to_owned()),
                ("query", self.query_policy.digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.validate_fields()?;
        if self.scope_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(ModelError::InvalidScope)
        }
    }

    pub fn organization(&self) -> &OrganizationId {
        &self.organization
    }

    pub fn monte_carlo_project(&self) -> &MonteCarloProjectReference {
        &self.project
    }

    pub fn warehouse(&self) -> &WarehouseReference {
        &self.warehouse
    }

    pub fn table(&self) -> &TableReference {
        &self.table
    }

    pub fn incident(&self) -> &IncidentReference {
        &self.incident
    }

    pub fn lineage(&self) -> &LineageReference {
        &self.lineage
    }

    pub fn monitor(&self) -> &MonitorReference {
        &self.monitor
    }

    pub fn time_window(&self) -> &TimeWindow {
        &self.time_window
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    pub fn project_binding(&self) -> &ProjectBinding {
        &self.project_binding
    }

    pub fn project(&self) -> &ProjectBinding {
        &self.project_binding
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
                "montecarlo-secret-reference/v1",
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

    pub fn validate_for(&self, scope: &MonteCarloObservabilityScope) -> Result<(), ModelError> {
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
    Fake,
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

    pub const fn contract_name(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentState {
    Open,
    Resolved,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessState {
    Fresh,
    Stale,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorState {
    Healthy,
    Firing,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    Partial,
    AccessLost,
    Denied,
    RateLimited,
    ProviderUnknown,
    Tampered,
}

impl EvidenceStatus {
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub const fn adoptable(self) -> bool {
        self.is_complete()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationState {
    Open,
    Resolved,
    Unknown,
    Partial,
    AccessLost,
    Denied,
    RateLimited,
    ProviderUnknown,
    Tampered,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Verified,
    Tampered,
    RegistrationRevoked,
    ScopeDrift,
    ReplayConflict,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityBoundary {
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub truth_authority: bool,
    pub effect_authority: bool,
    pub outcome_authority: bool,
    pub raw_rows: bool,
    pub raw_lineage: bool,
    pub monitor_mutation: bool,
}

impl AuthorityBoundary {
    pub fn layer1() -> Self {
        Self {
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            truth_authority: false,
            effect_authority: false,
            outcome_authority: false,
            raw_rows: false,
            raw_lineage: false,
            monitor_mutation: false,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaqueCursor {
    query_digest: Digest,
    cursor_digest: Digest,
    page: u8,
}

impl OpaqueCursor {
    pub fn new(
        opaque_cursor: impl AsRef<str>,
        query_digest: &Digest,
        page: u8,
    ) -> Result<Self, ModelError> {
        if !valid_text(opaque_cursor.as_ref(), MAX_IDENTIFIER_BYTES, false)
            || page == 0
            || page > MAX_PAGES
        {
            return Err(ModelError::InvalidCursor);
        }
        query_digest.validate()?;
        Ok(Self {
            query_digest: query_digest.clone(),
            cursor_digest: Digest::from_parts(
                "montecarlo-opaque-cursor/v1",
                &[("value", opaque_cursor.as_ref().to_owned())],
            ),
            page,
        })
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn digest(&self) -> &Digest {
        &self.cursor_digest
    }

    pub const fn page(&self) -> u8 {
        self.page
    }

    pub fn validate_for(&self, query_digest: &Digest) -> Result<(), ModelError> {
        if self.page == 0 || self.page > MAX_PAGES || self.query_digest != *query_digest {
            Err(ModelError::InvalidCursor)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("query_digest", &self.query_digest)
            .field("cursor_digest", &self.cursor_digest)
            .field("page", &self.page)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncidentRecord {
    pub incident_digest: Digest,
    pub state: IncidentState,
    pub severity: Severity,
    pub affected_table_digest: Digest,
    pub title_digest: Digest,
    pub updated_at_millis: Option<i64>,
}

impl IncidentRecord {
    pub fn new(
        incident: &IncidentId,
        state: IncidentState,
        severity: Severity,
        affected_table: &TableId,
        title: impl AsRef<str>,
        updated_at_millis: Option<i64>,
    ) -> Result<Self, ModelError> {
        incident.validate()?;
        affected_table.validate()?;
        let title = title.as_ref();
        if !title.is_empty() && !valid_text(title, MAX_IDENTIFIER_BYTES, true) {
            return Err(ModelError::InvalidBound {
                field: "incident title",
            });
        }
        if updated_at_millis.is_some_and(|value| value < 0) {
            return Err(ModelError::InvalidBound {
                field: "incident timestamp",
            });
        }
        Ok(Self {
            incident_digest: incident.digest(),
            state,
            severity,
            affected_table_digest: affected_table.digest(),
            title_digest: Digest::from_parts(
                "montecarlo-incident-title/v1",
                &[("value", title.to_owned())],
            ),
            updated_at_millis,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "montecarlo-incident-record/v1",
            &[
                ("incident", self.incident_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("severity", format!("{:?}", self.severity)),
                ("table", self.affected_table_digest.as_str().to_owned()),
                ("title", self.title_digest.as_str().to_owned()),
                (
                    "updated_at",
                    self.updated_at_millis
                        .map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshnessRecord {
    pub table_digest: Digest,
    pub state: FreshnessState,
    pub lag_seconds: Option<u64>,
    pub observed_at_millis: Option<i64>,
}

impl FreshnessRecord {
    pub fn new(
        table: &TableId,
        state: FreshnessState,
        lag_seconds: Option<u64>,
        observed_at_millis: Option<i64>,
    ) -> Result<Self, ModelError> {
        table.validate()?;
        if lag_seconds.is_some_and(|value| value > (MAX_TIME_WINDOW_MILLIS as u64 / 1_000))
            || observed_at_millis.is_some_and(|value| value < 0)
        {
            return Err(ModelError::InvalidBound {
                field: "freshness observation",
            });
        }
        Ok(Self {
            table_digest: table.digest(),
            state,
            lag_seconds,
            observed_at_millis,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "montecarlo-freshness-record/v1",
            &[
                ("table", self.table_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                (
                    "lag",
                    self.lag_seconds
                        .map_or_else(String::new, |value| value.to_string()),
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
pub struct LineageRecord {
    pub lineage_digest: Digest,
    pub table_digest: Digest,
    pub upstream_count: u16,
    pub downstream_count: u16,
    pub graph_digest: Digest,
    pub observed_at_millis: Option<i64>,
}

impl LineageRecord {
    pub fn new(
        lineage: &LineageId,
        table: &TableId,
        upstream_count: u16,
        downstream_count: u16,
        graph_digest: Digest,
        observed_at_millis: Option<i64>,
    ) -> Result<Self, ModelError> {
        lineage.validate()?;
        table.validate()?;
        graph_digest.validate()?;
        if usize::from(upstream_count) > MAX_LINEAGE_EDGES
            || usize::from(downstream_count) > MAX_LINEAGE_EDGES
            || observed_at_millis.is_some_and(|value| value < 0)
        {
            return Err(ModelError::InvalidBound {
                field: "lineage evidence",
            });
        }
        Ok(Self {
            lineage_digest: lineage.digest(),
            table_digest: table.digest(),
            upstream_count,
            downstream_count,
            graph_digest,
            observed_at_millis,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "montecarlo-lineage-record/v1",
            &[
                ("lineage", self.lineage_digest.as_str().to_owned()),
                ("table", self.table_digest.as_str().to_owned()),
                ("upstream", self.upstream_count.to_string()),
                ("downstream", self.downstream_count.to_string()),
                ("graph", self.graph_digest.as_str().to_owned()),
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
pub struct MonitorRecord {
    pub monitor_digest: Digest,
    pub state: MonitorState,
    pub enabled: Option<bool>,
    pub revision_digest: Digest,
    pub observed_at_millis: Option<i64>,
}

impl MonitorRecord {
    pub fn new(
        monitor: &MonitorId,
        state: MonitorState,
        enabled: Option<bool>,
        revision_digest: Digest,
        observed_at_millis: Option<i64>,
    ) -> Result<Self, ModelError> {
        monitor.validate()?;
        revision_digest.validate()?;
        if observed_at_millis.is_some_and(|value| value < 0) {
            return Err(ModelError::InvalidBound {
                field: "monitor timestamp",
            });
        }
        Ok(Self {
            monitor_digest: monitor.digest(),
            state,
            enabled,
            revision_digest,
            observed_at_millis,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "montecarlo-monitor-record/v1",
            &[
                ("monitor", self.monitor_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                (
                    "enabled",
                    self.enabled
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                ("revision", self.revision_digest.as_str().to_owned()),
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
pub struct IncidentPage {
    pub incidents: Vec<IncidentRecord>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub redacted: bool,
}

impl IncidentPage {
    pub fn new(
        incidents: Vec<IncidentRecord>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        validate_page(incidents.len(), response_bytes)?;
        let response_digest = page_digest(
            "montecarlo-incident-page/v1",
            incidents.iter().map(IncidentRecord::digest),
            next_cursor.as_ref(),
        );
        Ok(Self {
            incidents,
            next_cursor,
            response_digest,
            response_bytes,
            redacted: true,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshnessPage {
    pub freshness: Vec<FreshnessRecord>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub redacted: bool,
}

impl FreshnessPage {
    pub fn new(
        freshness: Vec<FreshnessRecord>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        validate_page(freshness.len(), response_bytes)?;
        let response_digest = page_digest(
            "montecarlo-freshness-page/v1",
            freshness.iter().map(FreshnessRecord::digest),
            next_cursor.as_ref(),
        );
        Ok(Self {
            freshness,
            next_cursor,
            response_digest,
            response_bytes,
            redacted: true,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineagePage {
    pub lineage: Vec<LineageRecord>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub redacted: bool,
}

impl LineagePage {
    pub fn new(
        lineage: Vec<LineageRecord>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        validate_page(lineage.len(), response_bytes)?;
        let response_digest = page_digest(
            "montecarlo-lineage-page/v1",
            lineage.iter().map(LineageRecord::digest),
            next_cursor.as_ref(),
        );
        Ok(Self {
            lineage,
            next_cursor,
            response_digest,
            response_bytes,
            redacted: true,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonitorPage {
    pub monitors: Vec<MonitorRecord>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub redacted: bool,
}

impl MonitorPage {
    pub fn new(
        monitors: Vec<MonitorRecord>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        validate_page(monitors.len(), response_bytes)?;
        let response_digest = page_digest(
            "montecarlo-monitor-page/v1",
            monitors.iter().map(MonitorRecord::digest),
            next_cursor.as_ref(),
        );
        Ok(Self {
            monitors,
            next_cursor,
            response_digest,
            response_bytes,
            redacted: true,
        })
    }
}

fn validate_page(item_count: usize, response_bytes: usize) -> Result<(), ModelError> {
    if item_count > MAX_ITEMS_PER_PAGE || response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES
    {
        Err(ModelError::InvalidBound {
            field: "provider response page",
        })
    } else {
        Ok(())
    }
}

pub(crate) fn page_digest(
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
