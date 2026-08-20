//! Typed, bounded, serializable-safe Application Signals model values.

use std::{collections::BTreeSet, fmt, hash::Hash};

use chrono::{DateTime, Duration, TimeZone, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub const MAX_IDENTIFIER_LENGTH: usize = 256;
pub const MAX_REGION_LENGTH: usize = 64;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGE_COUNT: u16 = 100;
pub const MAX_ITEM_COUNT: usize = 5_000;
pub const MAX_TIME_WINDOW_SECONDS: i64 = 7_776_000;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} is not a valid AWS account id")]
    InvalidAccountId { field: &'static str },
    #[error("{field} is not a valid AWS region")]
    InvalidRegion { field: &'static str },
    #[error("{field} is not a valid SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} contains a duplicate")]
    Duplicate { field: &'static str },
    #[error("{field} exceeds its bound")]
    BoundExceeded { field: &'static str },
    #[error("read page size is outside its bound")]
    InvalidPageSize,
    #[error("read page count is outside its bound")]
    InvalidPageCount,
    #[error("read item count is outside its bound")]
    InvalidItemCount,
    #[error("the time window must be closed, positive, rounded, and bounded")]
    InvalidTimeWindow,
    #[error("the permission scope is invalid")]
    InvalidPermissionScope,
    #[error("the Application Signals scope is invalid")]
    InvalidScope,
    #[error("the SLO status or transition is invalid")]
    InvalidSloStatus,
    #[error("the error-budget summary is invalid")]
    InvalidErrorBudget,
    #[error("the opaque page token is invalid")]
    InvalidPageToken,
    #[error("the opaque page token is bound to a different request")]
    CursorBindingMismatch,
    #[error("the registration is already revoked")]
    AlreadyRevoked,
    #[error("the registration or secret reference is revoked")]
    Revoked,
}

fn validate_text(value: &str, field: &'static str, maximum: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > maximum {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_text(value, field, MAX_IDENTIFIER_LENGTH)?;
    if value.chars().any(char::is_whitespace)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/@+-".contains(&byte))
    {
        return Err(ModelError::Invalid { field });
    }
    Ok(())
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                Self::new(value)
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ModelError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 12 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ModelError::InvalidAccountId {
                field: "account id",
            });
        }
        Ok(Self(value))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl TryFrom<&str> for AccountId {
    type Error = ModelError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Region(String);

impl Region {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "region", MAX_REGION_LENGTH)?;
        if value.chars().any(char::is_whitespace)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !value.contains('-')
        {
            return Err(ModelError::InvalidRegion { field: "region" });
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Region {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl TryFrom<&str> for Region {
    type Error = ModelError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

pub type AwsAccountId = AccountId;
pub type AwsRegion = Region;

bounded_identifier!(ServiceName, "service name");
bounded_identifier!(SloId, "SLO id");
bounded_identifier!(DeploymentId, "deployment id");
bounded_identifier!(ReleaseId, "release id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(RevisionId, "revision id");
pub type ServiceId = ServiceName;
pub type OperationId = OperationName;

/// AWS Application Signals operation names may contain an internal space, for
/// example `GET /checkout`; surrounding whitespace remains forbidden.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OperationName(String);

impl OperationName {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "operation name", MAX_IDENTIFIER_LENGTH)?;
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/@+- ".contains(&byte))
        {
            return Err(ModelError::Invalid {
                field: "operation name",
            });
        }
        Ok(Self(value))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OperationName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl TryFrom<&str> for OperationName {
    type Error = ModelError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A lower-case SHA-256 digest used as a binding or evidence handle.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: &str) -> Self {
        Self::from_bytes(value.as_bytes())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::Invalid {
        field: "canonical digest input",
    })?;
    Ok(Digest::from_bytes(&bytes))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum ReadOperation {
    ListServices,
    GetService,
    ListServiceLevelObjectives,
    GetServiceLevelObjective,
}

impl ReadOperation {
    pub const ALL: [Self; 4] = [
        Self::ListServices,
        Self::GetService,
        Self::ListServiceLevelObjectives,
        Self::GetServiceLevelObjective,
    ];
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub mission_revision: RevisionId,
    pub consent_digest: Digest,
}

impl MissionBinding {
    #[must_use]
    pub const fn new(
        mission_id: MissionId,
        project_id: ProjectId,
        mission_revision: RevisionId,
        consent_digest: Digest,
    ) -> Self {
        Self {
            mission_id,
            project_id,
            mission_revision,
            consent_digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.consent_digest.as_str().len() != 64 {
            return Err(ModelError::InvalidDigest {
                field: "Mission consent digest",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest, ModelError> {
        self.validate()?;
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentBinding {
    pub deployment_id: DeploymentId,
    pub deployment_revision: u64,
}

impl DeploymentBinding {
    pub fn new(
        deployment_id: impl Into<String>,
        deployment_revision: u64,
    ) -> Result<Self, ModelError> {
        let binding = Self {
            deployment_id: DeploymentId::new(deployment_id)?,
            deployment_revision,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.deployment_revision == 0 {
            return Err(ModelError::Invalid {
                field: "deployment revision",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseBinding {
    pub release_id: ReleaseId,
    pub release_revision: u64,
}

impl ReleaseBinding {
    pub fn new(release_id: impl Into<String>, release_revision: u64) -> Result<Self, ModelError> {
        let binding = Self {
            release_id: ReleaseId::new(release_id)?,
            release_revision,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.release_revision == 0 {
            return Err(ModelError::Invalid {
                field: "release revision",
            });
        }
        Ok(())
    }
}

/// A closed UTC window normalized to whole seconds before it is hashed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimeWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl TimeWindow {
    pub fn closed(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self, ModelError> {
        let start_seconds = start.timestamp();
        let end_seconds = end.timestamp() + i64::from(end.timestamp_subsec_nanos() > 0);
        let start = Utc
            .timestamp_opt(start_seconds, 0)
            .single()
            .ok_or(ModelError::InvalidTimeWindow)?;
        let end = Utc
            .timestamp_opt(end_seconds, 0)
            .single()
            .ok_or(ModelError::InvalidTimeWindow)?;
        let window = Self { start, end };
        window.validate()?;
        Ok(window)
    }

    pub fn closed_seconds(start: i64, end: i64) -> Result<Self, ModelError> {
        let start = Utc
            .timestamp_opt(start, 0)
            .single()
            .ok_or(ModelError::InvalidTimeWindow)?;
        let end = Utc
            .timestamp_opt(end, 0)
            .single()
            .ok_or(ModelError::InvalidTimeWindow)?;
        Self::closed(start, end)
    }

    pub fn exact(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self, ModelError> {
        if start.timestamp_subsec_nanos() != 0 || end.timestamp_subsec_nanos() != 0 {
            return Err(ModelError::InvalidTimeWindow);
        }
        Self::closed(start, end)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.start.timestamp_subsec_nanos() != 0
            || self.end.timestamp_subsec_nanos() != 0
            || self.start >= self.end
            || (self.end - self.start) > Duration::seconds(MAX_TIME_WINDOW_SECONDS)
        {
            return Err(ModelError::InvalidTimeWindow);
        }
        Ok(())
    }

    #[must_use]
    pub fn start_seconds(&self) -> i64 {
        self.start.timestamp()
    }

    #[must_use]
    pub fn end_seconds(&self) -> i64 {
        self.end.timestamp()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(&format!(
            "aws-application-signals-window|{}|{}",
            self.start_seconds(),
            self.end_seconds()
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadBounds {
    pub max_results: u16,
    pub max_pages: u16,
    pub max_items: usize,
}

impl ReadBounds {
    pub fn new(max_results: u16, max_pages: u16, max_items: usize) -> Result<Self, ModelError> {
        let bounds = Self {
            max_results,
            max_pages,
            max_items,
        };
        bounds.validate()?;
        Ok(bounds)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.max_results == 0 || self.max_results > MAX_PAGE_SIZE {
            return Err(ModelError::InvalidPageSize);
        }
        if self.max_pages == 0 || self.max_pages > MAX_PAGE_COUNT {
            return Err(ModelError::InvalidPageCount);
        }
        if self.max_items == 0 || self.max_items > MAX_ITEM_COUNT {
            return Err(ModelError::InvalidItemCount);
        }
        Ok(())
    }
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            max_results: 20,
            max_pages: 20,
            max_items: 500,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionScope {
    pub account_id: AccountId,
    pub region: Region,
    pub allowed_operations: BTreeSet<ReadOperation>,
    pub permission_revision: RevisionId,
    pub permission_digest: Digest,
}

impl PermissionScope {
    pub fn new(
        account_id: AccountId,
        region: Region,
        allowed_operations: BTreeSet<ReadOperation>,
        permission_revision: RevisionId,
    ) -> Result<Self, ModelError> {
        if allowed_operations.is_empty()
            || allowed_operations
                .iter()
                .any(|operation| !ReadOperation::ALL.contains(operation))
        {
            return Err(ModelError::InvalidPermissionScope);
        }
        let mut permission = Self {
            account_id,
            region,
            allowed_operations,
            permission_revision,
            permission_digest: Digest::from_text("pending-permission-digest"),
        };
        permission.validate()?;
        permission.permission_digest = permission.compute_digest()?;
        Ok(permission)
    }

    pub fn least_privilege(
        account_id: AccountId,
        region: Region,
        allowed_operations: BTreeSet<ReadOperation>,
        permission_revision: RevisionId,
    ) -> Result<Self, ModelError> {
        Self::new(account_id, region, allowed_operations, permission_revision)
    }

    pub fn all(
        account_id: AccountId,
        region: Region,
        permission_revision: RevisionId,
    ) -> Result<Self, ModelError> {
        Self::new(
            account_id,
            region,
            ReadOperation::ALL.into_iter().collect(),
            permission_revision,
        )
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.account_id,
            &self.region,
            &self.allowed_operations,
            &self.permission_revision,
        ))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.permission_revision.as_str().is_empty() || self.allowed_operations.is_empty() {
            return Err(ModelError::InvalidPermissionScope);
        }
        if self.compute_digest()? != self.permission_digest
            && self.permission_digest.as_str()
                != Digest::from_text("pending-permission-digest").as_str()
        {
            return Err(ModelError::InvalidPermissionScope);
        }
        Ok(())
    }

    #[must_use]
    pub fn permits(&self, operation: ReadOperation) -> bool {
        self.allowed_operations.contains(&operation)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsApplicationSignalsScope {
    pub account_id: AccountId,
    pub region: Region,
    pub service_name: Option<ServiceName>,
    pub slo_id: Option<SloId>,
    pub operation_name: Option<OperationName>,
    pub time_window: TimeWindow,
    pub deployment: DeploymentBinding,
    pub release: ReleaseBinding,
    pub mission: MissionBinding,
    pub permissions: PermissionScope,
    pub window_digest: Digest,
    pub scope_digest: Digest,
}

impl AwsApplicationSignalsScope {
    pub fn new(
        account_id: AccountId,
        region: Region,
        service_name: Option<ServiceName>,
        slo_id: Option<SloId>,
        operation_name: Option<OperationName>,
        time_window: TimeWindow,
        deployment: DeploymentBinding,
        release: ReleaseBinding,
        mission: MissionBinding,
        permissions: PermissionScope,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            account_id,
            region,
            service_name,
            slo_id,
            operation_name,
            window_digest: time_window.digest(),
            time_window,
            deployment,
            release,
            mission,
            permissions,
            scope_digest: Digest::from_text("pending-scope-digest"),
        };
        scope.validate_shape()?;
        let mut scope = scope;
        scope.scope_digest = scope.compute_digest()?;
        Ok(scope)
    }

    pub fn for_service_slo(
        account_id: AccountId,
        region: Region,
        service_name: ServiceName,
        slo_id: SloId,
        operation_name: OperationName,
        time_window: TimeWindow,
        deployment: DeploymentBinding,
        release: ReleaseBinding,
        mission: MissionBinding,
        permissions: PermissionScope,
    ) -> Result<Self, ModelError> {
        Self::new(
            account_id,
            region,
            Some(service_name),
            Some(slo_id),
            Some(operation_name),
            time_window,
            deployment,
            release,
            mission,
            permissions,
        )
    }

    fn validate_shape(&self) -> Result<(), ModelError> {
        self.time_window.validate()?;
        self.deployment.validate()?;
        self.release.validate()?;
        self.mission.validate()?;
        self.permissions.validate()?;
        if self.permissions.account_id != self.account_id
            || self.permissions.region != self.region
            || self.slo_id.is_some() && self.service_name.is_none()
            || self.operation_name.is_some() && self.slo_id.is_none()
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.account_id,
            &self.region,
            &self.service_name,
            &self.slo_id,
            &self.operation_name,
            &self.window_digest,
            &self.deployment,
            &self.release,
            &self.mission,
            &self.permissions.permission_digest,
        ))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.validate_shape()?;
        if self.window_digest != self.time_window.digest()
            || self.scope_digest != self.compute_digest()?
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn project_id(&self) -> &ProjectId {
        &self.mission.project_id
    }

    #[must_use]
    pub fn contains_service(&self, service: &ServiceName) -> bool {
        self.service_name
            .as_ref()
            .is_none_or(|expected| expected == service)
    }

    #[must_use]
    pub fn contains_slo(&self, service: &ServiceName, slo: &SloId) -> bool {
        self.contains_service(service)
            && self.slo_id.as_ref().is_none_or(|expected| expected == slo)
    }

    #[must_use]
    pub fn contains_operation(&self, operation: &OperationName) -> bool {
        self.operation_name
            .as_ref()
            .is_none_or(|expected| expected == operation)
    }
}

/// Opaque host/provider cursor. The raw cursor never implements `Display`,
/// never appears in `Debug`, and serializes only as its digest handle.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    token: String,
    binding_digest: Option<Digest>,
    serialized_digest: Option<Digest>,
}

impl OpaquePageToken {
    pub fn new(token: impl Into<String>) -> Result<Self, ModelError> {
        let token = token.into();
        validate_text(&token, "page token", 100_000)?;
        Ok(Self {
            token,
            binding_digest: None,
            serialized_digest: None,
        })
    }

    pub fn for_request(
        token: impl Into<String>,
        binding_digest: Digest,
    ) -> Result<Self, ModelError> {
        let mut page_token = Self::new(token)?;
        if binding_digest.as_str().len() != 64 {
            return Err(ModelError::InvalidDigest {
                field: "cursor binding digest",
            });
        }
        page_token.binding_digest = Some(binding_digest);
        Ok(page_token)
    }

    #[must_use]
    pub fn bind(&self, binding_digest: Digest) -> Self {
        Self {
            token: self.token.clone(),
            binding_digest: Some(binding_digest),
            serialized_digest: self.serialized_digest.clone(),
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.serialized_digest.clone().unwrap_or_else(|| {
            Digest::from_text(&format!("aws-application-signals-cursor|{}", self.token))
        })
    }

    #[must_use]
    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }

    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.binding_digest.is_some()
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest())
            .field("binding_digest", &self.binding_digest)
            .field("token", &"<redacted>")
            .field("serialized_digest", &self.serialized_digest)
            .finish()
    }
}

impl<'de> Deserialize<'de> for OpaquePageToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let digest = String::deserialize(deserializer)?;
        let digest = Digest::parse(digest).map_err(D::Error::custom)?;
        Ok(Self {
            token: String::new(),
            binding_digest: None,
            serialized_digest: Some(digest),
        })
    }
}

impl Serialize for OpaquePageToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

impl Drop for OpaquePageToken {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    NoData,
    Partial,
    Expired,
    AccessLost,
    ProviderUnknown,
}

impl EvidenceStatus {
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SloStatus {
    Healthy,
    Warning,
    Breached,
    NoData,
    Partial,
    Expired,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SloTransition {
    pub from: Option<SloStatus>,
    pub to: SloStatus,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SloStatusSummary {
    pub current: SloStatus,
    pub previous: Option<SloStatus>,
    pub transition: Option<SloTransition>,
    pub observed_at: DateTime<Utc>,
}

impl SloStatusSummary {
    pub fn new(
        current: SloStatus,
        previous: Option<SloStatus>,
        transition: Option<SloTransition>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        if transition.as_ref().is_some_and(|transition| {
            transition.to != current || transition.observed_at != observed_at
        }) {
            return Err(ModelError::InvalidSloStatus);
        }
        if transition.is_some() && previous == Some(current) {
            return Err(ModelError::InvalidSloStatus);
        }
        Ok(Self {
            current,
            previous,
            transition,
            observed_at,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(
            self.current,
            self.previous,
            self.transition.clone(),
            self.observed_at,
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorBudgetSummary {
    pub target_percentage: f64,
    pub achieved_percentage: Option<f64>,
    pub remaining_percentage: Option<f64>,
    pub consumed_percentage: Option<f64>,
    pub remaining_seconds: Option<i64>,
}

impl ErrorBudgetSummary {
    pub fn new(
        target_percentage: f64,
        achieved_percentage: Option<f64>,
        remaining_percentage: Option<f64>,
        consumed_percentage: Option<f64>,
        remaining_seconds: Option<i64>,
    ) -> Result<Self, ModelError> {
        let summary = Self {
            target_percentage,
            achieved_percentage,
            remaining_percentage,
            consumed_percentage,
            remaining_seconds,
        };
        summary.validate()?;
        Ok(summary)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let values = [
            (self.target_percentage, "target percentage"),
            (
                self.achieved_percentage.unwrap_or(0.0),
                "achieved percentage",
            ),
            (
                self.remaining_percentage.unwrap_or(0.0),
                "remaining percentage",
            ),
            (
                self.consumed_percentage.unwrap_or(0.0),
                "consumed percentage",
            ),
        ];
        if values
            .iter()
            .any(|(value, _)| !value.is_finite() || !(0.0..=100.0).contains(value))
        {
            return Err(ModelError::InvalidErrorBudget);
        }
        if self.remaining_seconds.is_some_and(|seconds| seconds < 0) {
            return Err(ModelError::InvalidErrorBudget);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceSummary {
    pub account_id: AccountId,
    pub region: Region,
    pub service_name: ServiceName,
    pub environment: Option<String>,
}

impl ServiceSummary {
    pub fn new(
        account_id: AccountId,
        region: Region,
        service_name: ServiceName,
        environment: Option<String>,
    ) -> Result<Self, ModelError> {
        if let Some(environment) = &environment {
            validate_text(environment, "environment", MAX_IDENTIFIER_LENGTH)?;
        }
        Ok(Self {
            account_id,
            region,
            service_name,
            environment,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(
            self.account_id.clone(),
            self.region.clone(),
            self.service_name.clone(),
            self.environment.clone(),
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceDetail {
    pub summary: ServiceSummary,
    pub operations: Vec<OperationName>,
}

impl ServiceDetail {
    pub fn new(
        summary: ServiceSummary,
        operations: Vec<OperationName>,
    ) -> Result<Self, ModelError> {
        if operations.len() > MAX_PAGE_SIZE as usize {
            return Err(ModelError::BoundExceeded {
                field: "operations",
            });
        }
        let mut seen = BTreeSet::new();
        for operation in &operations {
            if !seen.insert(operation) {
                return Err(ModelError::Duplicate {
                    field: "operations",
                });
            }
        }
        summary.validate()?;
        Ok(Self {
            summary,
            operations,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(self.summary.clone(), self.operations.clone()).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SloSummary {
    pub account_id: AccountId,
    pub region: Region,
    pub service_name: ServiceName,
    pub slo_id: SloId,
    pub operation_name: OperationName,
    pub target_percentage: f64,
    pub status: SloStatus,
}

impl SloSummary {
    pub fn new(
        account_id: AccountId,
        region: Region,
        service_name: ServiceName,
        slo_id: SloId,
        operation_name: OperationName,
        target_percentage: f64,
        status: SloStatus,
    ) -> Result<Self, ModelError> {
        if !target_percentage.is_finite() || !(0.0..=100.0).contains(&target_percentage) {
            return Err(ModelError::InvalidErrorBudget);
        }
        Ok(Self {
            account_id,
            region,
            service_name,
            slo_id,
            operation_name,
            target_percentage,
            status,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(
            self.account_id.clone(),
            self.region.clone(),
            self.service_name.clone(),
            self.slo_id.clone(),
            self.operation_name.clone(),
            self.target_percentage,
            self.status,
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SloDetail {
    pub summary: SloSummary,
    pub window: TimeWindow,
    pub status_summary: SloStatusSummary,
    pub error_budget: ErrorBudgetSummary,
}

impl SloDetail {
    pub fn new(
        summary: SloSummary,
        window: TimeWindow,
        status_summary: SloStatusSummary,
        error_budget: ErrorBudgetSummary,
    ) -> Result<Self, ModelError> {
        window.validate()?;
        summary.validate()?;
        status_summary.validate()?;
        error_budget.validate()?;
        if summary.status != status_summary.current {
            return Err(ModelError::InvalidSloStatus);
        }
        Ok(Self {
            summary,
            window,
            status_summary,
            error_budget,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(
            self.summary.clone(),
            self.window.clone(),
            self.status_summary.clone(),
            self.error_budget.clone(),
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub raw_provider_payload_retained: bool,
    pub raw_secret_material_retained: bool,
    pub raw_cursor_retained: bool,
    pub raw_metric_retained: bool,
    pub raw_trace_retained: bool,
    pub raw_log_retained: bool,
}

impl RedactionSummary {
    #[must_use]
    pub const fn layer1() -> Self {
        Self {
            raw_provider_payload_retained: false,
            raw_secret_material_retained: false,
            raw_cursor_retained: false,
            raw_metric_retained: false,
            raw_trace_retained: false,
            raw_log_retained: false,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.raw_provider_payload_retained
            || self.raw_secret_material_retained
            || self.raw_cursor_retained
            || self.raw_metric_retained
            || self.raw_trace_retained
            || self.raw_log_retained
        {
            return Err(ModelError::Invalid {
                field: "Layer-1 redaction summary",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub version_digest: Digest,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub window_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Registration {
    pub state: RegistrationState,
    pub registration_revision: u64,
    pub version_digest: Digest,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub window_digest: Digest,
    pub registration_digest: Digest,
}

impl Registration {
    pub fn new(
        registration_revision: u64,
        version_digest: Digest,
        api_digest: Digest,
        contract_digest: Digest,
        provider_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
        window_digest: Digest,
    ) -> Result<Self, ModelError> {
        if registration_revision == 0 {
            return Err(ModelError::Invalid {
                field: "registration revision",
            });
        }
        let mut registration = Self {
            state: RegistrationState::Active,
            registration_revision,
            version_digest,
            api_digest,
            contract_digest,
            provider_digest,
            permission_digest,
            scope_digest,
            window_digest,
            registration_digest: Digest::from_text("pending-registration-digest"),
        };
        registration.registration_digest = registration.compute_digest()?;
        Ok(registration)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            self.state,
            self.registration_revision,
            &self.version_digest,
            &self.api_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.window_digest,
        ))
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        if self.registration_digest != self.compute_digest()? {
            return Err(ModelError::InvalidDigest {
                field: "registration digest",
            });
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<Digest, ModelError> {
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest()?;
        Ok(self.registration_digest.clone())
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }
}

/// Opaque, host-owned SigV4 material reference. It intentionally has no
/// `Serialize`, `Deserialize`, or `Display` implementation.
#[derive(Clone, Eq, PartialEq)]
pub struct SigV4SecretReference {
    opaque_reference: String,
    account_id: AccountId,
    region: Region,
    scope_digest: Digest,
    credential_revision: u64,
    revoked: bool,
}

pub type SecretReference = SigV4SecretReference;

impl SigV4SecretReference {
    pub fn new(
        opaque_reference: impl Into<String>,
        scope: &AwsApplicationSignalsScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::from_parts(
            opaque_reference,
            scope.account_id.clone(),
            scope.region.clone(),
            scope.scope_digest.clone(),
            credential_revision,
        )
    }

    pub fn from_parts(
        opaque_reference: impl Into<String>,
        account_id: AccountId,
        region: Region,
        scope_digest: Digest,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let opaque_reference = opaque_reference.into();
        validate_text(
            &opaque_reference,
            "SigV4 secret reference",
            MAX_IDENTIFIER_LENGTH,
        )?;
        if credential_revision == 0 || scope_digest.as_str().len() != 64 {
            return Err(ModelError::Invalid {
                field: "SigV4 secret reference",
            });
        }
        Ok(Self {
            opaque_reference,
            account_id,
            region,
            scope_digest,
            credential_revision,
            revoked: false,
        })
    }

    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    #[must_use]
    pub fn region(&self) -> &Region {
        &self.region
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    #[must_use]
    pub fn reference_digest(&self) -> Digest {
        Digest::from_text(&format!(
            "aws-application-signals-sigv4-reference|{}|{}|{}|{}",
            self.account_id, self.region, self.scope_digest, self.credential_revision
        ))
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }
}

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("reference_digest", &self.reference_digest())
            .field("account_id", &self.account_id)
            .field("region", &self.region)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .field("opaque_reference", &"<redacted>")
            .finish()
    }
}

impl Drop for SigV4SecretReference {
    fn drop(&mut self) {
        self.opaque_reference.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialOrd, Ord, PartialEq, Serialize)]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// Keep this import visible to the compiler when model values are expanded by
// downstream crates; it also documents that all set-based fences are ordered.
#[allow(dead_code)]
fn _ordered_set_type_is_hashable<T: Hash>() {}
