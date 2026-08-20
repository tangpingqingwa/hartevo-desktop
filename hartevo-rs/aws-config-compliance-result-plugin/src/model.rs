//! Typed, bounded AWS Config scope and evidence models.
//!
//! The model intentionally has no type for a configuration item, rule code,
//! tag, environment value, annotation, credential, or raw provider payload.
//! Those values cannot accidentally cross the Layer-1 boundary because they
//! are not representable in the public evidence types.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_RESOURCES: usize = 128;
pub const MAX_EVALUATIONS_PER_PAGE: usize = 64;
pub const MAX_EVALUATIONS: usize = 256;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 50;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 6;
pub const MAX_RETRIES: u8 = 2;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a bounded opaque cursor")]
    InvalidCursor { field: &'static str },
    #[error("{field} contains too many entries")]
    TooMany { field: &'static str },
    #[error("{field} is not allowed for this operation")]
    Unsupported { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("registration is already revoked")]
    AlreadyRevoked,
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    if value
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || "-_.:/+=@*".contains(character)))
    {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(
            Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &Digest::from_text(self.as_str()))
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

bounded_identifier!(DeploymentId, "deployment id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(ConfigRuleName, "Config rule name");
bounded_identifier!(ResourceType, "resource type");
bounded_identifier!(ResourceId, "resource id");
bounded_identifier!(AggregatorId, "configuration aggregator id");
bounded_identifier!(PermissionId, "permission id");
bounded_identifier!(ProviderId, "provider id");
bounded_identifier!(ProviderRevision, "provider revision");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 12 || value.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(ModelError::Invalid {
                field: "AWS account id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountId")
            .field("digest", &Digest::from_text(self.as_str()))
            .finish()
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "AWS region", 63)?;
        if value.starts_with('-') || value.ends_with('-') {
            return Err(ModelError::Invalid {
                field: "AWS region",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRegion")
            .field("value", &self.0)
            .finish()
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub type Region = AwsRegion;

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

pub type EvaluationRevision = Revision;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(Sha256::digest(bytes).as_slice()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(tag: &str, parts: &[String]) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(tag.as_bytes());
        for part in parts {
            bytes.push(0);
            bytes.extend_from_slice(part.as_bytes());
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(ModelError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value))
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentBinding {
    pub id: DeploymentId,
    pub revision: Revision,
}

impl DeploymentBinding {
    pub const fn new(id: DeploymentId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub const fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub const fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub const fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum AwsConfigTarget {
    AccountRegion {
        account_id: AccountId,
        region: AwsRegion,
    },
    ApprovedAggregator {
        aggregator_id: AggregatorId,
        region: AwsRegion,
        approval_digest: Digest,
    },
}

impl AwsConfigTarget {
    pub fn account_region(account_id: AccountId, region: AwsRegion) -> Result<Self, ModelError> {
        Ok(Self::AccountRegion { account_id, region })
    }

    pub fn approved_aggregator(
        aggregator_id: AggregatorId,
        region: AwsRegion,
        approval_digest: Digest,
    ) -> Result<Self, ModelError> {
        if approval_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "aggregator approval digest",
            });
        }
        Ok(Self::ApprovedAggregator {
            aggregator_id,
            region,
            approval_digest,
        })
    }

    pub fn region(&self) -> &AwsRegion {
        match self {
            Self::AccountRegion { region, .. } | Self::ApprovedAggregator { region, .. } => region,
        }
    }

    pub fn account_id(&self) -> Option<&AccountId> {
        match self {
            Self::AccountRegion { account_id, .. } => Some(account_id),
            Self::ApprovedAggregator { .. } => None,
        }
    }

    pub const fn is_approved_aggregator(&self) -> bool {
        matches!(self, Self::ApprovedAggregator { .. })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        match self {
            Self::AccountRegion { .. } => Ok(()),
            Self::ApprovedAggregator {
                approval_digest, ..
            } if *approval_digest != Digest::zero() => Ok(()),
            Self::ApprovedAggregator { .. } => Err(ModelError::Invalid {
                field: "aggregator approval digest",
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceKey {
    pub resource_type: ResourceType,
    pub resource_id: ResourceId,
}

impl ResourceKey {
    pub const fn new(resource_type: ResourceType, resource_id: ResourceId) -> Self {
        Self {
            resource_type,
            resource_id,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceBinding {
    pub key: ResourceKey,
    pub revision: Revision,
}

impl ResourceBinding {
    pub const fn new(key: ResourceKey, revision: Revision) -> Self {
        Self { key, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigRuleBinding {
    pub name: ConfigRuleName,
    pub revision: Revision,
    pub resources: Vec<ResourceBinding>,
}

impl ConfigRuleBinding {
    pub fn new(
        name: ConfigRuleName,
        revision: Revision,
        resources: impl IntoIterator<Item = ResourceBinding>,
    ) -> Result<Self, ModelError> {
        let mut resources = resources.into_iter().collect::<Vec<_>>();
        if resources.is_empty() {
            return Err(ModelError::Empty {
                field: "Config rule resource allowlist",
            });
        }
        if resources.len() > MAX_RESOURCES {
            return Err(ModelError::TooMany {
                field: "Config rule resources",
            });
        }
        let mut keys = BTreeSet::new();
        for resource in &resources {
            if !keys.insert(resource.key.clone()) {
                return Err(ModelError::Duplicate {
                    field: "Config rule resource allowlist",
                });
            }
        }
        resources.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(Self {
            name,
            revision,
            resources,
        })
    }

    pub fn resource_revision(&self, key: &ResourceKey) -> Option<Revision> {
        self.resources
            .iter()
            .find(|resource| resource.key == *key)
            .map(|resource| resource.revision)
    }

    pub fn allows(&self, key: &ResourceKey) -> bool {
        self.resource_revision(key).is_some()
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionAction {
    GetComplianceDetailsByConfigRule,
    DescribeComplianceByResource,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub id: PermissionId,
    pub revision: Revision,
    pub allowed_actions: BTreeSet<PermissionAction>,
}

impl PermissionFence {
    pub fn readonly(id: PermissionId, revision: Revision) -> Result<Self, ModelError> {
        Ok(Self {
            id,
            revision,
            allowed_actions: [
                PermissionAction::GetComplianceDetailsByConfigRule,
                PermissionAction::DescribeComplianceByResource,
            ]
            .into_iter()
            .collect(),
        })
    }

    pub fn new(
        id: PermissionId,
        revision: Revision,
        allowed_actions: impl IntoIterator<Item = PermissionAction>,
    ) -> Result<Self, ModelError> {
        let allowed_actions = allowed_actions.into_iter().collect::<BTreeSet<_>>();
        if allowed_actions.is_empty() {
            return Err(ModelError::Empty {
                field: "permission allowlist",
            });
        }
        Ok(Self {
            id,
            revision,
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsConfigScope {
    pub deployment: DeploymentBinding,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub target: AwsConfigTarget,
    pub config_rule: ConfigRuleBinding,
    pub permission_digest: Digest,
}

impl AwsConfigScope {
    pub fn new(
        deployment: DeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        target: AwsConfigTarget,
        config_rule: ConfigRuleBinding,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            deployment,
            mission,
            project,
            work_product,
            target,
            config_rule,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.target.validate()?;
        if self.config_rule.resources.is_empty() {
            return Err(ModelError::Empty {
                field: "Config rule resource allowlist",
            });
        }
        if self.permission_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "permission digest",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn resource_revision(&self, key: &ResourceKey) -> Option<Revision> {
        self.config_rule.resource_revision(key)
    }
}

/// A SigV4 reference is reduced to a digest before it enters the service.
/// Neither the supplied reference nor signing material is retained.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    digest: Digest,
    region: AwsRegion,
}

impl SecretReference {
    pub fn for_config(
        reference: impl AsRef<str>,
        target: &AwsConfigTarget,
    ) -> Result<Self, ModelError> {
        let value = reference.as_ref();
        validate_text(value, "SigV4 secret reference", MAX_IDENTIFIER_BYTES)?;
        let region = target.region().clone();
        let digest = Digest::from_parts(
            "hartevo-aws-config-sigv4-secret/v1",
            &[
                "config".to_owned(),
                region.as_str().to_owned(),
                value.to_owned(),
            ],
        );
        Ok(Self { digest, region })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn signing_service(&self) -> &'static str {
        "config"
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
            .field("signing_service", &"config")
            .field("signing_region", &self.region)
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("SecretReference", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Option<Digest>,
}

impl OpaqueCursor {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidCursor {
                field: "next token",
            });
        }
        Ok(Self {
            token_digest: Digest::from_parts(
                "hartevo-aws-config-next-token/v1",
                &[value.to_owned()],
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
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("OpaqueCursor", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComplianceState {
    Compliant,
    NonCompliant,
    NotApplicable,
    InsufficientData,
    #[serde(rename = "partial")]
    Partial,
    #[serde(rename = "access_loss")]
    AccessLoss,
    #[serde(rename = "provider_unknown")]
    ProviderUnknown,
}

pub type AwsConfigComplianceState = ComplianceState;

impl ComplianceState {
    pub fn parse_api(value: &str) -> Result<Self, ModelError> {
        match value {
            "COMPLIANT" => Ok(Self::Compliant),
            "NON_COMPLIANT" => Ok(Self::NonCompliant),
            "NOT_APPLICABLE" => Ok(Self::NotApplicable),
            "INSUFFICIENT_DATA" => Ok(Self::InsufficientData),
            _ => Err(ModelError::Invalid {
                field: "AWS Config compliance state",
            }),
        }
    }

    pub const fn is_api_state(self) -> bool {
        matches!(
            self,
            Self::Compliant | Self::NonCompliant | Self::NotApplicable | Self::InsufficientData
        )
    }

    pub const fn is_fail_closed(self) -> bool {
        !matches!(self, Self::Compliant | Self::NotApplicable)
    }

    pub const fn api_name(self) -> Option<&'static str> {
        match self {
            Self::Compliant => Some("COMPLIANT"),
            Self::NonCompliant => Some("NON_COMPLIANT"),
            Self::NotApplicable => Some("NOT_APPLICABLE"),
            Self::InsufficientData => Some("INSUFFICIENT_DATA"),
            Self::Partial | Self::AccessLoss | Self::ProviderUnknown => None,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceFilter {
    pub states: BTreeSet<ComplianceState>,
}

impl ComplianceFilter {
    pub fn new(states: impl IntoIterator<Item = ComplianceState>) -> Result<Self, ModelError> {
        let states = states.into_iter().collect::<BTreeSet<_>>();
        if states.is_empty() {
            return Err(ModelError::Empty {
                field: "compliance filter",
            });
        }
        if states.len() > 4 || states.iter().any(|state| !state.is_api_state()) {
            return Err(ModelError::Unsupported {
                field: "aggregate compliance state in provider filter",
            });
        }
        Ok(Self { states })
    }

    pub fn all() -> Self {
        Self {
            states: [
                ComplianceState::Compliant,
                ComplianceState::NonCompliant,
                ComplianceState::NotApplicable,
                ComplianceState::InsufficientData,
            ]
            .into_iter()
            .collect(),
        }
    }

    pub fn allows(&self, state: ComplianceState) -> bool {
        self.states.contains(&state)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsConfigReadOperation {
    GetComplianceDetailsByConfigRule,
    DescribeComplianceByResource,
}

impl AwsConfigReadOperation {
    pub const fn permission(self) -> PermissionAction {
        match self {
            Self::GetComplianceDetailsByConfigRule => {
                PermissionAction::GetComplianceDetailsByConfigRule
            }
            Self::DescribeComplianceByResource => PermissionAction::DescribeComplianceByResource,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsConfigReadRequest {
    pub operation: AwsConfigReadOperation,
    pub target: AwsConfigTarget,
    pub config_rule_name: ConfigRuleName,
    pub resource: Option<ResourceKey>,
    pub compliance_filter: ComplianceFilter,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_evaluations: u16,
    pub max_response_bytes: usize,
    pub max_retries: u8,
    pub cursor: Option<OpaqueCursor>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadBinding<'a> {
    operation: AwsConfigReadOperation,
    target: &'a AwsConfigTarget,
    config_rule_name: &'a ConfigRuleName,
    resource: &'a Option<ResourceKey>,
    compliance_filter: &'a ComplianceFilter,
    page_size: u16,
    max_pages: u16,
    max_evaluations: u16,
    max_response_bytes: usize,
    max_retries: u8,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
}

impl AwsConfigReadRequest {
    pub fn by_config_rule(
        scope: &AwsConfigScope,
        filter: ComplianceFilter,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        Self::new(
            AwsConfigReadOperation::GetComplianceDetailsByConfigRule,
            scope,
            None,
            filter,
            page_size,
            max_pages,
            cursor,
        )
    }

    pub fn by_resource(
        scope: &AwsConfigScope,
        resource: ResourceKey,
        filter: ComplianceFilter,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        Self::new(
            AwsConfigReadOperation::DescribeComplianceByResource,
            scope,
            Some(resource),
            filter,
            page_size,
            max_pages,
            cursor,
        )
    }

    fn new(
        operation: AwsConfigReadOperation,
        scope: &AwsConfigScope,
        resource: Option<ResourceKey>,
        compliance_filter: ComplianceFilter,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > PAGE_SIZE {
            return Err(ModelError::Invalid { field: "page size" });
        }
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::Invalid {
                field: "page budget",
            });
        }
        let request = Self {
            operation,
            target: scope.target.clone(),
            config_rule_name: scope.config_rule.name.clone(),
            resource,
            compliance_filter,
            page_size,
            max_pages,
            max_evaluations: MAX_EVALUATIONS as u16,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_retries: MAX_RETRIES,
            cursor: None,
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest.clone(),
        };
        let mut request = request;
        request.cursor = request.bind_cursor(cursor)?;
        if let Some(resource) = &request.resource
            && !scope.config_rule.allows(resource)
        {
            return Err(ModelError::ScopeMismatch {
                field: "resource allowlist",
            });
        }
        Ok(request)
    }

    fn bind_cursor(
        &self,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Option<OpaqueCursor>, ModelError> {
        let Some(cursor) = cursor else {
            return Ok(None);
        };
        let binding = self.query_digest();
        if let Some(existing) = cursor.binding_digest()
            && existing != &binding
        {
            return Err(ModelError::ScopeMismatch {
                field: "cursor query binding",
            });
        }
        Ok(Some(cursor.bind(&binding)))
    }

    pub fn with_cursor(&self, cursor: Option<OpaqueCursor>) -> Result<Self, ModelError> {
        let mut request = self.clone();
        request.cursor = request.bind_cursor(cursor)?;
        Ok(request)
    }

    pub fn with_bounds(
        &self,
        max_evaluations: u16,
        max_response_bytes: usize,
        max_retries: u8,
    ) -> Result<Self, ModelError> {
        if self.cursor.is_some()
            || max_evaluations == 0
            || usize::from(max_evaluations) > MAX_EVALUATIONS
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
            || max_retries > MAX_RETRIES
        {
            return Err(ModelError::Invalid {
                field: "read bounds",
            });
        }
        let mut request = self.clone();
        request.max_evaluations = max_evaluations;
        request.max_response_bytes = max_response_bytes;
        request.max_retries = max_retries;
        Ok(request)
    }

    pub fn query_digest(&self) -> Digest {
        digest_serialized(&ReadBinding {
            operation: self.operation,
            target: &self.target,
            config_rule_name: &self.config_rule_name,
            resource: &self.resource,
            compliance_filter: &self.compliance_filter,
            page_size: self.page_size,
            max_pages: self.max_pages,
            max_evaluations: self.max_evaluations,
            max_response_bytes: self.max_response_bytes,
            max_retries: self.max_retries,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
        })
    }

    pub fn request_digest(&self) -> Digest {
        let cursor_digest = self
            .cursor
            .as_ref()
            .map_or_else(Digest::zero, |cursor| cursor.token_digest().clone());
        Digest::from_parts(
            "hartevo-aws-config-read-request/v1",
            &[self.query_digest().to_string(), cursor_digest.to_string()],
        )
    }

    pub fn validate_against(
        &self,
        scope: &AwsConfigScope,
        permission: &PermissionFence,
    ) -> Result<(), ModelError> {
        if self.scope_digest != scope.digest() {
            return Err(ModelError::ScopeMismatch {
                field: "scope digest",
            });
        }
        if self.permission_digest != permission.digest()
            || self.permission_digest != scope.permission_digest
        {
            return Err(ModelError::ScopeMismatch {
                field: "permission digest",
            });
        }
        if self.target != scope.target || self.config_rule_name != scope.config_rule.name {
            return Err(ModelError::ScopeMismatch {
                field: "AWS Config target or rule",
            });
        }
        if matches!(
            self.operation,
            AwsConfigReadOperation::DescribeComplianceByResource
        ) && self.resource.is_none()
        {
            return Err(ModelError::Invalid {
                field: "resource selector",
            });
        }
        if let Some(resource) = &self.resource
            && !scope.config_rule.allows(resource)
        {
            return Err(ModelError::ScopeMismatch {
                field: "resource allowlist",
            });
        }
        if !permission.allows(self.operation.permission()) {
            return Err(ModelError::ScopeMismatch {
                field: "permission action",
            });
        }
        if self.page_size == 0
            || self.page_size > PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_evaluations == 0
            || usize::from(self.max_evaluations) > MAX_EVALUATIONS
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_retries > MAX_RETRIES
        {
            return Err(ModelError::Invalid {
                field: "read bounds",
            });
        }
        if let Some(cursor) = &self.cursor
            && cursor.binding_digest() != Some(&self.query_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "cursor query binding",
            });
        }
        Ok(())
    }

    pub fn expected_resources(&self, scope: &AwsConfigScope) -> Vec<ResourceKey> {
        self.resource.clone().map_or_else(
            || {
                scope
                    .config_rule
                    .resources
                    .iter()
                    .map(|resource| resource.key.clone())
                    .collect()
            },
            |resource| vec![resource],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageBudget,
    EvaluationBudget,
    ResponseTooLarge,
    CursorReplay,
    CursorBindingMismatch,
    MissingEvaluation,
    StaleRuleRevision,
    StaleResourceRevision,
    EvaluationOrdering,
    ProviderConflict,
    Truncated,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    BlockedEnvironment,
    MalformedResponse,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("AWS Config provider returned HTTP 400")]
    InvalidRequest,
    #[error("AWS Config provider rejected the request")]
    Unauthorized,
    #[error("AWS Config provider denied the request")]
    Forbidden,
    #[error("AWS Config scope was not found")]
    NotFound,
    #[error("AWS Config provider returned a conflict")]
    Conflict,
    #[error("AWS Config provider rate limited the request")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS Config provider returned a server failure")]
    ServerFailure { status_code: Option<u16> },
    #[error("AWS Config provider timed out")]
    Timeout,
    #[error("AWS Config native transport is unavailable in BLOCKED_ENV")]
    BlockedEnvironment,
    #[error("AWS Config provider response was malformed")]
    MalformedResponse,
    #[error("AWS Config provider returned an unknown error")]
    Unknown,
}

impl TransportError {
    pub const fn kind(&self) -> ProviderErrorKind {
        match self {
            Self::InvalidRequest => ProviderErrorKind::InvalidRequest,
            Self::Unauthorized => ProviderErrorKind::Unauthorized,
            Self::Forbidden => ProviderErrorKind::Forbidden,
            Self::NotFound => ProviderErrorKind::NotFound,
            Self::Conflict => ProviderErrorKind::Conflict,
            Self::RateLimited { .. } => ProviderErrorKind::RateLimited,
            Self::ServerFailure { .. } => ProviderErrorKind::ServerFailure,
            Self::Timeout => ProviderErrorKind::Timeout,
            Self::BlockedEnvironment => ProviderErrorKind::BlockedEnvironment,
            Self::MalformedResponse => ProviderErrorKind::MalformedResponse,
            Self::Unknown => ProviderErrorKind::Unknown,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::InvalidRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerFailure { status_code } => *status_code,
            Self::Timeout | Self::BlockedEnvironment | Self::MalformedResponse | Self::Unknown => {
                None
            }
        }
    }

    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerFailure { .. } | Self::Timeout
        )
    }

    pub const fn evidence(&self) -> ProviderErrorEvidence {
        ProviderErrorEvidence {
            kind: self.kind(),
            status_code: self.status_code(),
            retry_after_seconds: self.retry_after_seconds(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceEvaluation {
    pub config_rule_name: ConfigRuleName,
    pub rule_revision: Revision,
    pub resource_type: ResourceType,
    pub resource_id: ResourceId,
    pub resource_revision: Revision,
    pub evaluation_revision: EvaluationRevision,
    pub compliance_state: ComplianceState,
    pub ordering_timestamp: DateTime<Utc>,
    pub result_recorded_timestamp: DateTime<Utc>,
    pub evaluation_digest: Digest,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EvaluationBody<'a> {
    config_rule_name: &'a ConfigRuleName,
    rule_revision: Revision,
    resource_type: &'a ResourceType,
    resource_id: &'a ResourceId,
    resource_revision: Revision,
    evaluation_revision: EvaluationRevision,
    compliance_state: ComplianceState,
    ordering_timestamp: &'a DateTime<Utc>,
    result_recorded_timestamp: &'a DateTime<Utc>,
}

impl ComplianceEvaluation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config_rule_name: ConfigRuleName,
        rule_revision: Revision,
        resource_type: ResourceType,
        resource_id: ResourceId,
        resource_revision: Revision,
        evaluation_revision: EvaluationRevision,
        compliance_state: ComplianceState,
        ordering_timestamp: DateTime<Utc>,
        result_recorded_timestamp: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        if !compliance_state.is_api_state() {
            return Err(ModelError::Unsupported {
                field: "aggregate compliance state in evaluation",
            });
        }
        if result_recorded_timestamp < ordering_timestamp {
            return Err(ModelError::Invalid {
                field: "evaluation timestamp ordering",
            });
        }
        let mut evaluation = Self {
            config_rule_name,
            rule_revision,
            resource_type,
            resource_id,
            resource_revision,
            evaluation_revision,
            compliance_state,
            ordering_timestamp,
            result_recorded_timestamp,
            evaluation_digest: Digest::zero(),
        };
        evaluation.evaluation_digest = evaluation.recomputed_digest();
        Ok(evaluation)
    }

    pub fn resource_key(&self) -> ResourceKey {
        ResourceKey::new(self.resource_type.clone(), self.resource_id.clone())
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&EvaluationBody {
            config_rule_name: &self.config_rule_name,
            rule_revision: self.rule_revision,
            resource_type: &self.resource_type,
            resource_id: &self.resource_id,
            resource_revision: self.resource_revision,
            evaluation_revision: self.evaluation_revision,
            compliance_state: self.compliance_state,
            ordering_timestamp: &self.ordering_timestamp,
            result_recorded_timestamp: &self.result_recorded_timestamp,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.compliance_state.is_api_state()
            || self.result_recorded_timestamp < self.ordering_timestamp
            || self.evaluation_digest != self.recomputed_digest()
        {
            return Err(ModelError::Invalid {
                field: "evaluation digest or state",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsConfigReadPage {
    pub operation: AwsConfigReadOperation,
    pub query_digest: Digest,
    pub page_number: u16,
    pub evaluations: Vec<ComplianceEvaluation>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    pub provider_revision: ProviderRevision,
    pub page_digest: Digest,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadPageBody<'a> {
    operation: AwsConfigReadOperation,
    query_digest: &'a Digest,
    page_number: u16,
    evaluations: &'a [ComplianceEvaluation],
    next_cursor: &'a Option<OpaqueCursor>,
    response_bytes: usize,
    provider_revision: &'a ProviderRevision,
}

impl AwsConfigReadPage {
    pub fn new(
        request: &AwsConfigReadRequest,
        page_number: u16,
        evaluations: Vec<ComplianceEvaluation>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, ModelError> {
        if page_number == 0 {
            return Err(ModelError::Invalid {
                field: "page number",
            });
        }
        if evaluations.len() > MAX_EVALUATIONS_PER_PAGE {
            return Err(ModelError::TooMany {
                field: "evaluations per page",
            });
        }
        if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::Invalid {
                field: "provider response bytes",
            });
        }
        for evaluation in &evaluations {
            evaluation.validate()?;
        }
        let query_digest = request.query_digest();
        let next_cursor = next_cursor
            .map(|cursor| {
                if let Some(existing) = cursor.binding_digest()
                    && existing != &query_digest
                {
                    return Err(ModelError::ScopeMismatch {
                        field: "next cursor query binding",
                    });
                }
                Ok(cursor.bind(&query_digest))
            })
            .transpose()?;
        let mut page = Self {
            operation: request.operation,
            query_digest,
            page_number,
            evaluations,
            next_cursor,
            response_bytes,
            provider_revision,
            page_digest: Digest::zero(),
        };
        page.page_digest = page.recomputed_digest();
        Ok(page)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&ReadPageBody {
            operation: self.operation,
            query_digest: &self.query_digest,
            page_number: self.page_number,
            evaluations: &self.evaluations,
            next_cursor: &self.next_cursor,
            response_bytes: self.response_bytes,
            provider_revision: &self.provider_revision,
        })
    }

    pub fn validate_for(&self, request: &AwsConfigReadRequest) -> Result<(), ModelError> {
        if self.operation != request.operation
            || self.query_digest != request.query_digest()
            || self.page_digest != self.recomputed_digest()
            || self.page_number == 0
            || self.evaluations.len() > MAX_EVALUATIONS_PER_PAGE
            || self.response_bytes == 0
            || self.response_bytes > request.max_response_bytes
        {
            return Err(ModelError::Invalid {
                field: "AWS Config page binding",
            });
        }
        if let Some(cursor) = &self.next_cursor
            && cursor.binding_digest() != Some(&request.query_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "next cursor query binding",
            });
        }
        for evaluation in &self.evaluations {
            evaluation.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsConfigComplianceEvidence {
    pub state: ComplianceState,
    pub evaluations: Vec<ComplianceEvaluation>,
    pub partial_reason: Option<PartialReason>,
    pub page_count: u16,
    pub request_count: u16,
    pub retry_count: u8,
    pub truncated: bool,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub evaluation_order_digest: Digest,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceBody<'a> {
    state: ComplianceState,
    evaluations: &'a [ComplianceEvaluation],
    partial_reason: Option<PartialReason>,
    page_count: u16,
    request_count: u16,
    retry_count: u8,
    truncated: bool,
    query_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    provider_digest: &'a Digest,
    provider_revision: &'a ProviderRevision,
    api_digest: &'a Digest,
    contract_digest: &'a Digest,
    evaluation_order_digest: &'a Digest,
    provider_errors: &'a [ProviderErrorEvidence],
    provenance: TransportProvenance,
}

impl AwsConfigComplianceEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: ComplianceState,
        evaluations: Vec<ComplianceEvaluation>,
        partial_reason: Option<PartialReason>,
        page_count: u16,
        request_count: u16,
        retry_count: u8,
        truncated: bool,
        query_digest: Digest,
        scope_digest: Digest,
        permission_digest: Digest,
        provider_digest: Digest,
        provider_revision: ProviderRevision,
        api_digest: Digest,
        contract_digest: Digest,
        provider_errors: Vec<ProviderErrorEvidence>,
        provenance: TransportProvenance,
    ) -> Self {
        let evaluation_order_digest = digest_serialized(&evaluations);
        let mut evidence = Self {
            state,
            evaluations,
            partial_reason,
            page_count,
            request_count,
            retry_count,
            truncated,
            query_digest,
            scope_digest,
            permission_digest,
            provider_digest,
            provider_revision,
            api_digest,
            contract_digest,
            evaluation_order_digest,
            provider_errors,
            provenance,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.recomputed_digest();
        evidence
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&EvidenceBody {
            state: self.state,
            evaluations: &self.evaluations,
            partial_reason: self.partial_reason,
            page_count: self.page_count,
            request_count: self.request_count,
            retry_count: self.retry_count,
            truncated: self.truncated,
            query_digest: &self.query_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            provider_digest: &self.provider_digest,
            provider_revision: &self.provider_revision,
            api_digest: &self.api_digest,
            contract_digest: &self.contract_digest,
            evaluation_order_digest: &self.evaluation_order_digest,
            provider_errors: &self.provider_errors,
            provenance: self.provenance,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.evaluations.len() > MAX_EVALUATIONS
            || self.evidence_digest != self.recomputed_digest()
        {
            return Err(ModelError::Invalid {
                field: "evidence digest or bound",
            });
        }
        for evaluation in &self.evaluations {
            evaluation.validate()?;
        }
        Ok(())
    }
}

pub fn digest_serialized<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("bounded AWS Config values serialize");
    Digest::from_bytes(&bytes)
}

pub fn sort_evaluations(evaluations: &mut [ComplianceEvaluation]) {
    evaluations.sort_by(|left, right| {
        left.resource_key()
            .cmp(&right.resource_key())
            .then_with(|| right.evaluation_revision.cmp(&left.evaluation_revision))
            .then_with(|| right.ordering_timestamp.cmp(&left.ordering_timestamp))
            .then_with(|| {
                right
                    .result_recorded_timestamp
                    .cmp(&left.result_recorded_timestamp)
            })
            .then_with(|| left.evaluation_digest.cmp(&right.evaluation_digest))
    });
}

pub fn latest_evaluations(
    evaluations: &[ComplianceEvaluation],
) -> BTreeMap<ResourceKey, ComplianceEvaluation> {
    let mut latest = BTreeMap::new();
    for evaluation in evaluations {
        let key = evaluation.resource_key();
        let replace = latest
            .get(&key)
            .is_none_or(|existing: &ComplianceEvaluation| {
                (
                    evaluation.evaluation_revision,
                    evaluation.ordering_timestamp,
                ) > (existing.evaluation_revision, existing.ordering_timestamp)
            });
        if replace {
            latest.insert(key, evaluation.clone());
        }
    }
    latest
}
