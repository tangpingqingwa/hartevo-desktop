use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{AwsSsmAutomationError, AwsSsmAutomationTransportError, Result};
use crate::{MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES};

pub const MAX_CURSOR_BYTES: usize = 2_048;
pub const MAX_STEP_COUNT: usize = 256;

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

fn identifier(value: impl Into<String>, field: &'static str, max_bytes: usize) -> Result<String> {
    let value = value.into();
    if valid_text(&value, max_bytes) {
        Ok(value)
    } else {
        Err(AwsSsmAutomationError::InvalidIdentifier { field })
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

use serde::Deserialize;

impl Digest {
    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
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

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AwsSsmAutomationError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self == &Self::zero()
    }

    pub fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsSsmAutomationError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
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

pub(crate) fn digest_serialized<T: Serialize>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).expect("contract types serialize"))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(AwsSsmAutomationError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn next(self) -> Result<Self> {
        Self::new(
            self.0
                .checked_add(1)
                .ok_or(AwsSsmAutomationError::InvalidRevision)?,
        )
    }
}

macro_rules! identifier_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                Ok(Self(identifier(value, $field, MAX_IDENTIFIER_BYTES)?))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

identifier_type!(AutomationDocumentName, "automation document name");
identifier_type!(AutomationDocumentVersion, "automation document version");
identifier_type!(AutomationExecutionId, "automation execution id");
identifier_type!(AutomationStepName, "automation step name");
identifier_type!(MissionId, "mission id");
identifier_type!(ProjectId, "project id");
identifier_type!(WorkProductId, "work product id");

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_text(&value, 64)
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            Ok(Self(value))
        } else {
            Err(AwsSsmAutomationError::InvalidIdentifier {
                field: "AWS region",
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(Self(value))
        } else {
            Err(AwsSsmAutomationError::InvalidIdentifier {
                field: "AWS account id",
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionIdentity {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: MissionId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectIdentity {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: ProjectId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductIdentity {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TargetKey(String);

impl TargetKey {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        Ok(Self(identifier(value, "automation target key", 128)?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Target values are reduced to a digest at the boundary. The raw selector
/// value is never stored, serialized, or printed.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetSelector {
    pub key: TargetKey,
    pub value_digest: Digest,
}

impl TargetSelector {
    pub fn new(key: impl Into<String>, value: impl AsRef<str>) -> Result<Self> {
        let key = TargetKey::new(key)?;
        let value = value.as_ref();
        if !valid_text(value, MAX_IDENTIFIER_BYTES) {
            return Err(AwsSsmAutomationError::InvalidIdentifier {
                field: "automation target value",
            });
        }
        Ok(Self {
            value_digest: Digest::from_parts(
                "hartevo-aws-ssm-automation-target/v1",
                &[
                    ("key", key.as_str().to_owned()),
                    ("value", value.to_owned()),
                ],
            ),
            key,
        })
    }

    pub fn from_digest(key: TargetKey, value_digest: Digest) -> Result<Self> {
        value_digest.validate()?;
        Ok(Self { key, value_digest })
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSsmAutomationScope {
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub document_name: AutomationDocumentName,
    pub document_version: AutomationDocumentVersion,
    pub execution_id: AutomationExecutionId,
    pub step_name: Option<AutomationStepName>,
    pub target: Option<TargetSelector>,
    pub mission: MissionIdentity,
    pub project: ProjectIdentity,
    pub work_product: WorkProductIdentity,
    pub permission_digest: Digest,
}

impl AwsSsmAutomationScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AwsAccountId,
        region: AwsRegion,
        document_name: AutomationDocumentName,
        document_version: AutomationDocumentVersion,
        execution_id: AutomationExecutionId,
        step_name: Option<AutomationStepName>,
        target: Option<TargetSelector>,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
        permission_digest: Digest,
    ) -> Result<Self> {
        let scope = Self {
            account_id,
            region,
            document_name,
            document_version,
            execution_id,
            step_name,
            target,
            mission,
            project,
            work_product,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        self.permission_digest.validate()?;
        if self.permission_digest.is_zero() {
            return Err(AwsSsmAutomationError::InvalidScope);
        }
        if let Some(target) = &self.target {
            target.value_digest.validate()?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn target_matches(&self, target: Option<&TargetSelector>) -> bool {
        match (&self.target, target) {
            (None, _) => true,
            (Some(expected), Some(actual)) => expected == actual,
            (Some(_), None) => false,
        }
    }

    pub fn step_matches(&self, step: &AutomationStepName) -> bool {
        self.step_name
            .as_ref()
            .is_none_or(|expected| expected == step)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    digest: Digest,
    region: AwsRegion,
}

impl SecretReference {
    pub fn for_ssm(reference: impl AsRef<str>, scope: &AwsSsmAutomationScope) -> Result<Self> {
        let value = reference.as_ref();
        if !valid_text(value, MAX_IDENTIFIER_BYTES) {
            return Err(AwsSsmAutomationError::InvalidSecretReference);
        }
        Ok(Self {
            digest: Digest::from_parts(
                "hartevo-aws-ssm-automation-sigv4-secret/v1",
                &[
                    ("service", "ssm".to_owned()),
                    ("region", scope.region.as_str().to_owned()),
                    ("reference", value.to_owned()),
                ],
            ),
            region: scope.region.clone(),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn signing_service(&self) -> &'static str {
        "ssm"
    }

    pub fn signing_region(&self) -> &AwsRegion {
        &self.region
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("value", &"<opaque>")
            .field("signing_service", &"ssm")
            .field("signing_region", &self.region)
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("SecretReference", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum PermissionAction {
    DescribeAutomationExecutions,
    GetAutomationExecution,
    DescribeAutomationStepExecutions,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub id: String,
    pub revision: Revision,
    pub allowed_actions: BTreeSet<PermissionAction>,
}

impl PermissionSnapshot {
    pub fn readonly(id: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(
            id,
            revision,
            [
                PermissionAction::DescribeAutomationExecutions,
                PermissionAction::GetAutomationExecution,
                PermissionAction::DescribeAutomationStepExecutions,
            ],
        )
    }

    pub fn new(
        id: impl Into<String>,
        revision: u64,
        allowed_actions: impl IntoIterator<Item = PermissionAction>,
    ) -> Result<Self> {
        let id = id.into();
        if !valid_text(&id, MAX_IDENTIFIER_BYTES) {
            return Err(AwsSsmAutomationError::InvalidPermissionFence);
        }
        let allowed_actions = allowed_actions.into_iter().collect::<BTreeSet<_>>();
        if allowed_actions.is_empty() {
            return Err(AwsSsmAutomationError::InvalidPermissionFence);
        }
        Ok(Self {
            id,
            revision: Revision::new(revision)?,
            allowed_actions,
        })
    }

    pub fn allows(&self, action: PermissionAction) -> bool {
        self.allowed_actions.contains(&action)
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationExecutionStatus {
    Pending,
    InProgress,
    Waiting,
    Success,
    Failed,
    TimedOut,
    Cancelling,
    Cancelled,
    Exiting,
    Unknown,
}

impl AutomationExecutionStatus {
    pub fn parse_api(value: &str) -> Self {
        match value {
            "Pending" => Self::Pending,
            "InProgress" => Self::InProgress,
            "Waiting" => Self::Waiting,
            "Success" => Self::Success,
            "Failed" => Self::Failed,
            "TimedOut" => Self::TimedOut,
            "Cancelling" => Self::Cancelling,
            "Cancelled" => Self::Cancelled,
            "Exiting" => Self::Exiting,
            _ => Self::Unknown,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Success | Self::Failed | Self::TimedOut | Self::Cancelled | Self::Unknown
        )
    }

    fn rank(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::InProgress => 1,
            Self::Waiting => 1,
            Self::Cancelling => 2,
            Self::Exiting => 2,
            Self::Success | Self::Failed | Self::TimedOut | Self::Cancelled => 3,
            Self::Unknown => 4,
        }
    }

    pub const fn evidence_state(self) -> AutomationEvidenceState {
        match self {
            Self::Pending => AutomationEvidenceState::Pending,
            Self::InProgress => AutomationEvidenceState::InProgress,
            Self::Waiting => AutomationEvidenceState::Waiting,
            Self::Success => AutomationEvidenceState::Success,
            Self::Failed => AutomationEvidenceState::Failed,
            Self::TimedOut => AutomationEvidenceState::TimedOut,
            Self::Cancelling => AutomationEvidenceState::Cancelling,
            Self::Cancelled => AutomationEvidenceState::Cancelled,
            Self::Exiting => AutomationEvidenceState::InProgress,
            Self::Unknown => AutomationEvidenceState::ProviderUnknown,
        }
    }

    pub fn permits_transition_from(self, previous: Self) -> bool {
        previous == self || (!previous.is_terminal() && self.rank() >= previous.rank())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationEvidenceState {
    Pending,
    InProgress,
    Waiting,
    Success,
    Failed,
    TimedOut,
    Cancelling,
    Cancelled,
    Partial,
    ProviderUnknown,
    AccessLoss,
    InvalidFilter,
    InvalidNextToken,
    Throttled,
    Truncated,
    ExecutionReplaced,
    RegistrationRevoked,
}

impl AutomationEvidenceState {
    pub const fn can_be_adopted(self) -> bool {
        false
    }

    pub const fn is_non_adoptable_failure(self) -> bool {
        matches!(
            self,
            Self::Partial
                | Self::ProviderUnknown
                | Self::AccessLoss
                | Self::InvalidFilter
                | Self::InvalidNextToken
                | Self::Throttled
                | Self::Truncated
                | Self::ExecutionReplaced
                | Self::RegistrationRevoked
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BlockedEnv,
    InvalidFilter,
    InvalidNextToken,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    ServerError,
    Timeout,
    AccessLoss,
    Partial,
    Truncated,
    Unknown,
    InvalidResponse,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

impl ProviderErrorEvidence {
    pub fn from_transport(error: &AwsSsmAutomationTransportError) -> Self {
        let kind = match error {
            AwsSsmAutomationTransportError::BlockedEnv => ProviderErrorKind::BlockedEnv,
            AwsSsmAutomationTransportError::InvalidFilter => ProviderErrorKind::InvalidFilter,
            AwsSsmAutomationTransportError::InvalidNextToken => ProviderErrorKind::InvalidNextToken,
            AwsSsmAutomationTransportError::BadRequest => ProviderErrorKind::BadRequest,
            AwsSsmAutomationTransportError::Unauthorized => ProviderErrorKind::Unauthorized,
            AwsSsmAutomationTransportError::Forbidden => ProviderErrorKind::Forbidden,
            AwsSsmAutomationTransportError::NotFound => ProviderErrorKind::NotFound,
            AwsSsmAutomationTransportError::Conflict => ProviderErrorKind::Conflict,
            AwsSsmAutomationTransportError::Throttled { .. } => ProviderErrorKind::Throttled,
            AwsSsmAutomationTransportError::ServerError { .. } => ProviderErrorKind::ServerError,
            AwsSsmAutomationTransportError::Timeout => ProviderErrorKind::Timeout,
            AwsSsmAutomationTransportError::AccessLoss => ProviderErrorKind::AccessLoss,
            AwsSsmAutomationTransportError::Partial => ProviderErrorKind::Partial,
            AwsSsmAutomationTransportError::Truncated => ProviderErrorKind::Truncated,
            AwsSsmAutomationTransportError::Unknown => ProviderErrorKind::Unknown,
            AwsSsmAutomationTransportError::InvalidResponse => ProviderErrorKind::InvalidResponse,
        };
        Self {
            kind,
            status_code: error.status_code(),
            error_digest: Digest::from_parts(
                "hartevo-aws-ssm-automation-provider-error/v1",
                &[("code", error.stable_code().to_owned())],
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
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

    pub const fn provider_receipt(self) -> bool {
        false
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Option<Digest>,
}

impl OpaqueCursor {
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let value = value.as_ref();
        if !valid_text(value, MAX_CURSOR_BYTES) {
            return Err(AwsSsmAutomationError::InvalidNextToken);
        }
        Ok(Self {
            token_digest: Digest::from_parts(
                "hartevo-aws-ssm-automation-next-token/v1",
                &[("token", value.to_owned())],
            ),
            binding_digest: None,
        })
    }

    pub fn bind(&self, binding_digest: &Digest) -> Self {
        Self {
            token_digest: self.token_digest.clone(),
            binding_digest: Some(binding_digest.clone()),
        }
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("OpaqueCursor", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

impl<'de> Deserialize<'de> for OpaqueCursor {
    fn deserialize<D>(_deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom(
            "opaque cursor cannot be deserialized without its bound provider token",
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutomationExecutionFilter {
    pub document_name: AutomationDocumentName,
    pub document_version: AutomationDocumentVersion,
    pub execution_id: AutomationExecutionId,
    pub status: Option<AutomationExecutionStatus>,
    pub step_name: Option<AutomationStepName>,
    pub target_digest: Option<Digest>,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_response_bytes: usize,
    pub cursor: Option<OpaqueCursor>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

impl AutomationExecutionFilter {
    pub fn for_scope(scope: &AwsSsmAutomationScope) -> Result<Self> {
        let filter = Self {
            document_name: scope.document_name.clone(),
            document_version: scope.document_version.clone(),
            execution_id: scope.execution_id.clone(),
            status: None,
            step_name: scope.step_name.clone(),
            target_digest: scope.target.as_ref().map(TargetSelector::digest),
            page_size: MAX_PAGE_SIZE,
            max_pages: MAX_PAGES,
            max_response_bytes: MAX_RESPONSE_BYTES,
            cursor: None,
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest.clone(),
        };
        filter.validate(scope)?;
        Ok(filter)
    }

    pub fn with_status(&self, status: AutomationExecutionStatus) -> Result<Self> {
        let mut filter = self.clone();
        filter.status = Some(status);
        filter.cursor = None;
        Ok(filter)
    }

    pub fn with_cursor(&self, cursor: Option<OpaqueCursor>) -> Result<Self> {
        let mut filter = self.clone();
        filter.cursor = match cursor {
            None => None,
            Some(cursor) => {
                let binding = self.query_digest();
                if let Some(existing) = cursor.binding_digest()
                    && existing != &binding
                {
                    return Err(AwsSsmAutomationError::CursorMismatch);
                }
                Some(cursor.bind(&binding))
            }
        };
        Ok(filter)
    }

    pub fn query_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct Binding<'a> {
            document_name: &'a AutomationDocumentName,
            document_version: &'a AutomationDocumentVersion,
            execution_id: &'a AutomationExecutionId,
            status: &'a Option<AutomationExecutionStatus>,
            step_name: &'a Option<AutomationStepName>,
            target_digest: &'a Option<Digest>,
            page_size: u16,
            max_pages: u16,
            max_response_bytes: usize,
            scope_digest: &'a Digest,
            permission_digest: &'a Digest,
        }
        digest_serialized(&Binding {
            document_name: &self.document_name,
            document_version: &self.document_version,
            execution_id: &self.execution_id,
            status: &self.status,
            step_name: &self.step_name,
            target_digest: &self.target_digest,
            page_size: self.page_size,
            max_pages: self.max_pages,
            max_response_bytes: self.max_response_bytes,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
        })
    }

    pub fn filter_digest(&self) -> Digest {
        self.query_digest()
    }

    pub fn validate(&self, scope: &AwsSsmAutomationScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.permission_digest != scope.permission_digest
            || self.document_name != scope.document_name
            || self.document_version != scope.document_version
            || self.execution_id != scope.execution_id
            || self.step_name != scope.step_name
            || self.target_digest != scope.target.as_ref().map(TargetSelector::digest)
        {
            return Err(AwsSsmAutomationError::FilterMismatch);
        }
        if self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsSsmAutomationError::InvalidFilter);
        }
        if let Some(cursor) = &self.cursor
            && cursor.binding_digest() != Some(&self.query_digest())
        {
            return Err(AwsSsmAutomationError::CursorMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSsmAutomationReadRequest {
    pub filter: AutomationExecutionFilter,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

impl AwsSsmAutomationReadRequest {
    pub fn for_scope(scope: &AwsSsmAutomationScope) -> Result<Self> {
        let filter = AutomationExecutionFilter::for_scope(scope)?;
        Ok(Self {
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest.clone(),
            filter,
        })
    }

    pub fn with_status(&self, status: AutomationExecutionStatus) -> Result<Self> {
        Ok(Self {
            filter: self.filter.with_status(status)?,
            ..self.clone()
        })
    }

    pub fn with_cursor(&self, cursor: Option<OpaqueCursor>) -> Result<Self> {
        Ok(Self {
            filter: self.filter.with_cursor(cursor)?,
            ..self.clone()
        })
    }

    pub fn validate(&self, scope: &AwsSsmAutomationScope) -> Result<()> {
        if self.scope_digest != scope.digest() || self.permission_digest != scope.permission_digest
        {
            return Err(AwsSsmAutomationError::ScopeMismatch {
                field: "read request binding",
            });
        }
        self.filter.validate(scope)
    }

    pub fn request_digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn describe_request(&self) -> DescribeAutomationExecutionsRequest {
        DescribeAutomationExecutionsRequest {
            filter: self.filter.clone(),
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
        }
    }

    pub fn get_request(&self) -> GetAutomationExecutionRequest {
        GetAutomationExecutionRequest {
            execution_id: self.filter.execution_id.clone(),
            document_name: self.filter.document_name.clone(),
            document_version: self.filter.document_version.clone(),
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
        }
    }

    pub fn steps_request(&self) -> DescribeAutomationStepExecutionsRequest {
        DescribeAutomationStepExecutionsRequest {
            execution_id: self.filter.execution_id.clone(),
            document_name: self.filter.document_name.clone(),
            document_version: self.filter.document_version.clone(),
            step_name: self.filter.step_name.clone(),
            target_digest: self.filter.target_digest.clone(),
            cursor: None,
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeAutomationExecutionsRequest {
    pub filter: AutomationExecutionFilter,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

impl DescribeAutomationExecutionsRequest {
    pub fn request_digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "Action=DescribeAutomationExecutions&DocumentName={}&DocumentVersion={}&ExecutionId={}&FilterDigest={}&NextTokenDigest={}",
            self.filter.document_name,
            self.filter.document_version,
            self.filter.execution_id,
            self.filter.filter_digest(),
            self.filter
                .cursor
                .as_ref()
                .map_or("none", |cursor| cursor.token_digest().as_str())
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAutomationExecutionRequest {
    pub execution_id: AutomationExecutionId,
    pub document_name: AutomationDocumentName,
    pub document_version: AutomationDocumentVersion,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

impl GetAutomationExecutionRequest {
    pub fn request_digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeAutomationStepExecutionsRequest {
    pub execution_id: AutomationExecutionId,
    pub document_name: AutomationDocumentName,
    pub document_version: AutomationDocumentVersion,
    pub step_name: Option<AutomationStepName>,
    pub target_digest: Option<Digest>,
    pub cursor: Option<OpaqueCursor>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

impl DescribeAutomationStepExecutionsRequest {
    pub fn query_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct Binding<'a> {
            execution_id: &'a AutomationExecutionId,
            document_name: &'a AutomationDocumentName,
            document_version: &'a AutomationDocumentVersion,
            step_name: &'a Option<AutomationStepName>,
            target_digest: &'a Option<Digest>,
            scope_digest: &'a Digest,
            permission_digest: &'a Digest,
        }
        digest_serialized(&Binding {
            execution_id: &self.execution_id,
            document_name: &self.document_name,
            document_version: &self.document_version,
            step_name: &self.step_name,
            target_digest: &self.target_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
        })
    }

    pub fn with_cursor(&self, cursor: Option<OpaqueCursor>) -> Result<Self> {
        let mut request = self.clone();
        request.cursor = match cursor {
            None => None,
            Some(cursor) => {
                let binding = self.query_digest();
                if let Some(existing) = cursor.binding_digest()
                    && existing != &binding
                {
                    return Err(AwsSsmAutomationError::CursorMismatch);
                }
                Some(cursor.bind(&binding))
            }
        };
        Ok(request)
    }

    pub fn request_digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutomationExecutionMetadata {
    pub execution_id: AutomationExecutionId,
    pub document_name: AutomationDocumentName,
    pub document_version: AutomationDocumentVersion,
    pub execution_revision: Revision,
    pub target: Option<TargetSelector>,
    pub status: AutomationExecutionStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub output_digest: Option<Digest>,
    pub error_digest: Option<Digest>,
}

impl AutomationExecutionMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution_id: AutomationExecutionId,
        document_name: AutomationDocumentName,
        document_version: AutomationDocumentVersion,
        execution_revision: u64,
        target: Option<TargetSelector>,
        status: AutomationExecutionStatus,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        output: Option<&str>,
        error: Option<&str>,
    ) -> Result<Self> {
        if let Some(value) = output
            && !valid_text(value, MAX_RESPONSE_BYTES)
        {
            return Err(AwsSsmAutomationError::InvalidText {
                field: "automation output",
            });
        }
        if let Some(value) = error
            && !valid_text(value, MAX_RESPONSE_BYTES)
        {
            return Err(AwsSsmAutomationError::InvalidText {
                field: "automation error",
            });
        }
        Ok(Self {
            execution_id,
            document_name,
            document_version,
            execution_revision: Revision::new(execution_revision)?,
            target,
            status,
            created_at,
            updated_at,
            output_digest: output.map(|value| {
                Digest::from_parts(
                    "hartevo-aws-ssm-automation-output/v1",
                    &[("output", value.to_owned())],
                )
            }),
            error_digest: error.map(|value| {
                Digest::from_parts(
                    "hartevo-aws-ssm-automation-error/v1",
                    &[("error", value.to_owned())],
                )
            }),
        })
    }

    pub fn fingerprint_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-ssm-automation-execution-fingerprint/v1",
            &[
                ("execution", self.execution_id.as_str().to_owned()),
                ("document", self.document_name.as_str().to_owned()),
                ("version", self.document_version.as_str().to_owned()),
                ("revision", self.execution_revision.get().to_string()),
                ("createdAt", self.created_at.to_rfc3339()),
            ],
        )
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutomationStepMetadata {
    pub step_name: AutomationStepName,
    pub step_revision: Revision,
    pub status: AutomationExecutionStatus,
    pub target: Option<TargetSelector>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub output_digest: Option<Digest>,
    pub error_digest: Option<Digest>,
}

impl AutomationStepMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        step_name: AutomationStepName,
        step_revision: u64,
        status: AutomationExecutionStatus,
        target: Option<TargetSelector>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        output: Option<&str>,
        error: Option<&str>,
    ) -> Result<Self> {
        let execution = AutomationExecutionMetadata::new(
            AutomationExecutionId::new("step-placeholder")?,
            AutomationDocumentName::new("step-placeholder")?,
            AutomationDocumentVersion::new("step-placeholder")?,
            step_revision,
            target.clone(),
            status,
            created_at,
            updated_at,
            output,
            error,
        )?;
        Ok(Self {
            step_name,
            step_revision: execution.execution_revision,
            status: execution.status,
            target,
            created_at,
            updated_at,
            output_digest: execution.output_digest,
            error_digest: execution.error_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeAutomationExecutionsResponse {
    pub executions: Vec<AutomationExecutionMetadata>,
    pub next_cursor: Option<OpaqueCursor>,
    pub complete: bool,
    pub response_bytes: usize,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl DescribeAutomationExecutionsResponse {
    pub fn new(
        request: &DescribeAutomationExecutionsRequest,
        executions: impl IntoIterator<Item = AutomationExecutionMetadata>,
        next_token: Option<&str>,
        complete: bool,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let executions = executions.into_iter().collect::<Vec<_>>();
        let next_cursor = next_token
            .map(OpaqueCursor::new)
            .transpose()?
            .map(|cursor| cursor.bind(&request.filter.query_digest()));
        let mut response = Self {
            executions,
            next_cursor,
            complete,
            response_bytes,
            provenance,
            response_digest: Digest::zero(),
        };
        response.response_digest = response.recomputed_digest(request);
        Ok(response)
    }

    pub fn recomputed_digest(&self, request: &DescribeAutomationExecutionsRequest) -> Digest {
        let execution_digest = digest_serialized(&self.executions);
        let step_digest = Digest::zero();
        let request_digest = request.request_digest();
        digest_serialized(&ResponseBinding {
            operation: "DescribeAutomationExecutions",
            scope_digest: &request.scope_digest,
            request_digest: &request_digest,
            execution_digest: &execution_digest,
            step_digest: &step_digest,
            complete: self.complete,
            response_bytes: self.response_bytes,
            provenance: self.provenance,
        })
    }

    pub fn validate_for(&self, request: &DescribeAutomationExecutionsRequest) -> Result<()> {
        if self
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.binding_digest() != Some(&request.filter.query_digest()))
            || self.response_digest != self.recomputed_digest(request)
        {
            return Err(AwsSsmAutomationError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAutomationExecutionResponse {
    pub execution: AutomationExecutionMetadata,
    pub response_bytes: usize,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl GetAutomationExecutionResponse {
    pub fn new(
        request: &GetAutomationExecutionRequest,
        execution: AutomationExecutionMetadata,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Self {
        let mut response = Self {
            execution,
            response_bytes,
            provenance,
            response_digest: Digest::zero(),
        };
        response.response_digest = response.recomputed_digest(request);
        response
    }

    pub fn recomputed_digest(&self, request: &GetAutomationExecutionRequest) -> Digest {
        let execution_digest = self.execution.digest();
        let step_digest = Digest::zero();
        let request_digest = request.request_digest();
        digest_serialized(&ResponseBinding {
            operation: "GetAutomationExecution",
            scope_digest: &request.scope_digest,
            request_digest: &request_digest,
            execution_digest: &execution_digest,
            step_digest: &step_digest,
            complete: true,
            response_bytes: self.response_bytes,
            provenance: self.provenance,
        })
    }

    pub fn validate_for(&self, request: &GetAutomationExecutionRequest) -> Result<()> {
        if self.execution.execution_id != request.execution_id
            || self.execution.document_name != request.document_name
            || self.execution.document_version != request.document_version
            || self.response_digest != self.recomputed_digest(request)
        {
            return Err(AwsSsmAutomationError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeAutomationStepExecutionsResponse {
    pub steps: Vec<AutomationStepMetadata>,
    pub next_cursor: Option<OpaqueCursor>,
    pub complete: bool,
    pub response_bytes: usize,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl DescribeAutomationStepExecutionsResponse {
    pub fn new(
        request: &DescribeAutomationStepExecutionsRequest,
        steps: impl IntoIterator<Item = AutomationStepMetadata>,
        next_token: Option<&str>,
        complete: bool,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let steps = steps.into_iter().collect::<Vec<_>>();
        let next_cursor = next_token
            .map(OpaqueCursor::new)
            .transpose()?
            .map(|cursor| cursor.bind(&request.query_digest()));
        let mut response = Self {
            steps,
            next_cursor,
            complete,
            response_bytes,
            provenance,
            response_digest: Digest::zero(),
        };
        response.response_digest = response.recomputed_digest(request);
        Ok(response)
    }

    pub fn recomputed_digest(&self, request: &DescribeAutomationStepExecutionsRequest) -> Digest {
        let execution_digest = Digest::zero();
        let step_digest = digest_serialized(&self.steps);
        let request_digest = request.request_digest();
        digest_serialized(&ResponseBinding {
            operation: "DescribeAutomationStepExecutions",
            scope_digest: &request.scope_digest,
            request_digest: &request_digest,
            execution_digest: &execution_digest,
            step_digest: &step_digest,
            complete: self.complete,
            response_bytes: self.response_bytes,
            provenance: self.provenance,
        })
    }

    pub fn validate_for(&self, request: &DescribeAutomationStepExecutionsRequest) -> Result<()> {
        if self
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.binding_digest() != Some(&request.query_digest()))
            || self.response_digest != self.recomputed_digest(request)
        {
            return Err(AwsSsmAutomationError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseBinding<'a> {
    operation: &'static str,
    scope_digest: &'a Digest,
    request_digest: &'a Digest,
    execution_digest: &'a Digest,
    step_digest: &'a Digest,
    complete: bool,
    response_bytes: usize,
    provenance: TransportProvenance,
}
