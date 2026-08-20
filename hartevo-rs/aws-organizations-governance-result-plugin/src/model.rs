//! Safe normalized model types for AWS Organizations hierarchy/policy evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub const MAX_IDENTIFIER_LENGTH: usize = 256;
pub const MAX_ARN_LENGTH: usize = 2_048;
pub const MAX_PAGE_TOKEN_LENGTH: usize = 100_000;
pub const MAX_HIERARCHY_NODES: usize = 4_096;
pub const MAX_SCOPE_TARGETS: usize = 128;

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
    #[error("{field} is not a valid digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a valid AWS Organizations identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is not a valid AWS Organizations ARN")]
    InvalidArn { field: &'static str },
    #[error("{field} has an invalid policy type")]
    InvalidPolicyType { field: &'static str },
    #[error("{field} has an invalid parent/child relationship")]
    InvalidRelationship { field: &'static str },
    #[error("{field} contains a duplicate")]
    Duplicate { field: &'static str },
    #[error("{field} exceeds its bound")]
    BoundExceeded { field: &'static str },
    #[error("read page size must be between one and twenty")]
    InvalidPageSize,
    #[error("read page count must be positive and bounded")]
    InvalidPageCount,
    #[error("read item count must be positive and bounded")]
    InvalidItemCount,
    #[error("opaque page token is invalid")]
    InvalidPageToken,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration or secret reference is revoked")]
    Revoked,
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
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_text(value, field, MAX_IDENTIFIER_LENGTH)?;
    if value.chars().any(char::is_whitespace) {
        return Err(ModelError::InvalidIdentifier { field });
    }
    Ok(())
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(RevisionId, "revision id");

/// A lower-case SHA-256 digest used as a fence or evidence handle.
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

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn from_text(value: &str) -> Self {
        Self::from_bytes(value.as_bytes())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::Invalid {
        field: "canonical digest input",
    })?;
    Ok(Digest::from_bytes(&bytes))
}

/// API operation names are also the permission fence keys.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum ReadOperation {
    ListPolicies,
    ListTargetsForPolicy,
    ListPoliciesForTarget,
}

impl ReadOperation {
    pub const ALL: [Self; 3] = [
        Self::ListPolicies,
        Self::ListTargetsForPolicy,
        Self::ListPoliciesForTarget,
    ];
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityKind {
    ManagementAccount,
    DelegatedAdministrator,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernanceTargetKind {
    Root,
    OrganizationalUnit,
    Account,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub enum TargetId {
    Root(RootId),
    OrganizationalUnit(OrganizationalUnitId),
    Account(AccountId),
}

impl TargetId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.starts_with("r-") {
            return Ok(Self::Root(RootId::parse(value)?));
        }
        if value.starts_with("ou-") {
            return Ok(Self::OrganizationalUnit(OrganizationalUnitId::parse(
                value,
            )?));
        }
        if value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Ok(Self::Account(AccountId::parse(value)?));
        }
        Err(ModelError::InvalidIdentifier { field: "target id" })
    }

    pub fn kind(&self) -> GovernanceTargetKind {
        match self {
            Self::Root(_) => GovernanceTargetKind::Root,
            Self::OrganizationalUnit(_) => GovernanceTargetKind::OrganizationalUnit,
            Self::Account(_) => GovernanceTargetKind::Account,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Root(value) => value.as_str(),
            Self::OrganizationalUnit(value) => value.as_str(),
            Self::Account(value) => value.as_str(),
        }
    }
}

impl fmt::Display for TargetId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OrganizationId(String);

impl OrganizationId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "organization id")?;
        let suffix = value
            .strip_prefix("o-")
            .ok_or(ModelError::InvalidIdentifier {
                field: "organization id",
            })?;
        if !(10..=32).contains(&suffix.len())
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(ModelError::InvalidIdentifier {
                field: "organization id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OrganizationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "account id")?;
        if value.len() != 12 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ModelError::InvalidIdentifier {
                field: "account id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RootId(String);

impl RootId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "root id")?;
        let suffix = value
            .strip_prefix("r-")
            .ok_or(ModelError::InvalidIdentifier { field: "root id" })?;
        if !(4..=32).contains(&suffix.len())
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(ModelError::InvalidIdentifier { field: "root id" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RootId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OrganizationalUnitId(String);

impl OrganizationalUnitId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "organizational unit id")?;
        let mut parts = value.split('-');
        let prefix = parts.next();
        let root = parts.next();
        let unit = parts.next();
        if prefix != Some("ou")
            || root.is_none_or(|value| !(4..=32).contains(&value.len()))
            || unit.is_none_or(|value| !(8..=32).contains(&value.len()))
            || parts.next().is_some()
            || !root
                .unwrap_or_default()
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || !unit
                .unwrap_or_default()
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(ModelError::InvalidIdentifier {
                field: "organizational unit id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OrganizationalUnitId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PolicyId(String);

impl PolicyId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "policy id")?;
        let suffix = value
            .strip_prefix("p-")
            .ok_or(ModelError::InvalidIdentifier { field: "policy id" })?;
        if !(8..=128).contains(&suffix.len())
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(ModelError::InvalidIdentifier { field: "policy id" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PolicyArn(String);

impl PolicyArn {
    pub fn parse(value: impl Into<String>, policy_id: &PolicyId) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "policy ARN", MAX_ARN_LENGTH)?;
        let arn_parts = value.split(':').collect::<Vec<_>>();
        let valid_service = arn_parts.len() >= 6
            && arn_parts[0] == "arn"
            && arn_parts[2] == "organizations"
            && arn_parts[5].starts_with("policy/");
        if !valid_service || !arn_parts[5].ends_with(policy_id.as_str()) {
            return Err(ModelError::InvalidArn {
                field: "policy ARN",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn organization_id(&self) -> Option<&str> {
        let resource = self.0.split(':').nth(5)?;
        let mut parts = resource.split('/');
        if parts.next() != Some("policy") {
            return None;
        }
        let organization_id = parts.next()?;
        organization_id.starts_with("o-").then_some(organization_id)
    }
}

impl fmt::Display for PolicyArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyType {
    ServiceControlPolicy,
    ResourceControlPolicy,
    TagPolicy,
    BackupPolicy,
    AiServicesOptOutPolicy,
    ChatbotPolicy,
    DeclarativePolicyEc2,
    SecurityHubPolicy,
    InspectorPolicy,
    UpgradeRolloutPolicy,
    BedrockPolicy,
    S3Policy,
    NetworkSecurityDirectorPolicy,
}

impl PolicyType {
    pub const ALL: [Self; 13] = [
        Self::ServiceControlPolicy,
        Self::ResourceControlPolicy,
        Self::TagPolicy,
        Self::BackupPolicy,
        Self::AiServicesOptOutPolicy,
        Self::ChatbotPolicy,
        Self::DeclarativePolicyEc2,
        Self::SecurityHubPolicy,
        Self::InspectorPolicy,
        Self::UpgradeRolloutPolicy,
        Self::BedrockPolicy,
        Self::S3Policy,
        Self::NetworkSecurityDirectorPolicy,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceControlPolicy => "SERVICE_CONTROL_POLICY",
            Self::ResourceControlPolicy => "RESOURCE_CONTROL_POLICY",
            Self::TagPolicy => "TAG_POLICY",
            Self::BackupPolicy => "BACKUP_POLICY",
            Self::AiServicesOptOutPolicy => "AISERVICES_OPT_OUT_POLICY",
            Self::ChatbotPolicy => "CHATBOT_POLICY",
            Self::DeclarativePolicyEc2 => "DECLARATIVE_POLICY_EC2",
            Self::SecurityHubPolicy => "SECURITYHUB_POLICY",
            Self::InspectorPolicy => "INSPECTOR_POLICY",
            Self::UpgradeRolloutPolicy => "UPGRADE_ROLLOUT_POLICY",
            Self::BedrockPolicy => "BEDROCK_POLICY",
            Self::S3Policy => "S3_POLICY",
            Self::NetworkSecurityDirectorPolicy => "NETWORK_SECURITY_DIRECTOR_POLICY",
        }
    }
}

impl FromStr for PolicyType {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|item| item.as_str() == value)
            .ok_or(ModelError::InvalidPolicyType {
                field: "policy type",
            })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyIdentity {
    pub policy_type: PolicyType,
    pub policy_id: PolicyId,
    pub policy_arn: PolicyArn,
    /// A digest of the safe policy summary, not a policy document/version body.
    pub policy_revision: PolicyRevision,
}

pub type PolicySummary = PolicyIdentity;
pub type PolicyRevision = Digest;

impl PolicyIdentity {
    pub fn new(
        policy_type: PolicyType,
        policy_id: PolicyId,
        policy_arn: PolicyArn,
    ) -> Result<Self, ModelError> {
        let revision_material = (&policy_type, &policy_id, &policy_arn);
        let policy_revision = digest_serializable(&revision_material)?;
        Ok(Self {
            policy_type,
            policy_id,
            policy_arn,
            policy_revision,
        })
    }

    pub fn from_values(
        policy_type: PolicyType,
        policy_id: impl Into<String>,
        policy_arn: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let policy_id = PolicyId::parse(policy_id)?;
        let policy_arn = PolicyArn::parse(policy_arn, &policy_id)?;
        Self::new(policy_type, policy_id, policy_arn)
    }

    pub fn policy_revision_digest(&self) -> &Digest {
        &self.policy_revision
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            self.policy_type,
            self.policy_id.clone(),
            self.policy_arn.clone(),
        )?;
        if rebuilt.policy_revision != self.policy_revision {
            return Err(ModelError::InvalidDigest {
                field: "policy revision digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetReference {
    pub organization_id: OrganizationId,
    pub target_id: TargetId,
    pub arn: String,
}

impl TargetReference {
    pub fn new(
        organization_id: OrganizationId,
        target_id: TargetId,
        arn: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let arn = arn.into();
        validate_text(&arn, "target ARN", MAX_ARN_LENGTH)?;
        let parts = arn.split(':').collect::<Vec<_>>();
        let valid_service = parts.len() >= 6
            && parts[0] == "arn"
            && parts[2] == "organizations"
            && parts[5].contains('/')
            && arn.contains(&format!("/{}/", organization_id.as_str()))
            && arn.ends_with(target_id.as_str());
        let resource_kind_matches = match target_id.kind() {
            GovernanceTargetKind::Root => parts[5].starts_with("root/"),
            GovernanceTargetKind::OrganizationalUnit => parts[5].starts_with("ou/"),
            GovernanceTargetKind::Account => parts[5].starts_with("account/"),
        };
        if !valid_service || !resource_kind_matches {
            return Err(ModelError::InvalidArn {
                field: "target ARN",
            });
        }
        Ok(Self {
            organization_id,
            target_id,
            arn,
        })
    }

    pub fn kind(&self) -> GovernanceTargetKind {
        self.target_id.kind()
    }

    pub fn contains_in(&self, hierarchy: &OrganizationHierarchy) -> bool {
        hierarchy.contains_target(&self.target_id)
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            self.organization_id.clone(),
            self.target_id.clone(),
            self.arn.clone(),
        )?;
        if rebuilt != *self {
            return Err(ModelError::InvalidDigest {
                field: "target identity",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HierarchyNode {
    pub target: TargetReference,
    pub parent_target_id: Option<TargetId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrganizationHierarchy {
    pub organization_id: OrganizationId,
    pub nodes: Vec<HierarchyNode>,
    pub hierarchy_digest: Digest,
}

impl OrganizationHierarchy {
    pub fn new(
        organization_id: OrganizationId,
        mut nodes: Vec<HierarchyNode>,
    ) -> Result<Self, ModelError> {
        if nodes.is_empty() {
            return Err(ModelError::Empty {
                field: "organization hierarchy",
            });
        }
        if nodes.len() > MAX_HIERARCHY_NODES {
            return Err(ModelError::BoundExceeded {
                field: "organization hierarchy",
            });
        }
        for node in &nodes {
            node.target.verify()?;
            if node.target.organization_id != organization_id {
                return Err(ModelError::InvalidRelationship {
                    field: "hierarchy organization",
                });
            }
            if let Some(parent) = &node.parent_target_id {
                if parent == &node.target.target_id {
                    return Err(ModelError::InvalidRelationship {
                        field: "self parent",
                    });
                }
                if matches!(parent, TargetId::Account(_)) {
                    return Err(ModelError::InvalidRelationship {
                        field: "account parent",
                    });
                }
            }
            match (node.target.kind(), node.parent_target_id.is_some()) {
                (GovernanceTargetKind::Root, true)
                | (
                    GovernanceTargetKind::OrganizationalUnit | GovernanceTargetKind::Account,
                    false,
                ) => {
                    return Err(ModelError::InvalidRelationship {
                        field: "target parent cardinality",
                    });
                }
                _ => {}
            }
        }
        nodes.sort_by(|left, right| left.target.target_id.cmp(&right.target.target_id));
        let mut ids = BTreeSet::new();
        let parents = nodes
            .iter()
            .map(|node| (node.target.target_id.clone(), node.parent_target_id.clone()))
            .collect::<BTreeMap<_, _>>();
        for node in &nodes {
            if !ids.insert(node.target.target_id.clone()) {
                return Err(ModelError::Duplicate {
                    field: "hierarchy target",
                });
            }
            if let Some(parent) = &node.parent_target_id
                && !parents.contains_key(parent)
            {
                return Err(ModelError::InvalidRelationship {
                    field: "missing parent",
                });
            }
        }
        for node in &nodes {
            let mut visited = BTreeSet::new();
            let mut cursor = Some(node.target.target_id.clone());
            while let Some(current) = cursor {
                if !visited.insert(current.clone()) {
                    return Err(ModelError::InvalidRelationship {
                        field: "hierarchy cycle",
                    });
                }
                cursor = parents.get(&current).cloned().flatten();
            }
        }
        let material = (&organization_id, &nodes);
        let hierarchy_digest = digest_serializable(&material)?;
        Ok(Self {
            organization_id,
            nodes,
            hierarchy_digest,
        })
    }

    pub fn contains_target(&self, target_id: &TargetId) -> bool {
        self.nodes
            .iter()
            .any(|node| &node.target.target_id == target_id)
    }

    pub fn target(&self, target_id: &TargetId) -> Option<&TargetReference> {
        self.nodes
            .iter()
            .find(|node| &node.target.target_id == target_id)
            .map(|node| &node.target)
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(self.organization_id.clone(), self.nodes.clone())?;
        if rebuilt.hierarchy_digest != self.hierarchy_digest {
            return Err(ModelError::InvalidDigest {
                field: "hierarchy digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub work_product_id: WorkProductId,
    pub mission_revision: RevisionId,
    pub consent_digest: Digest,
}

impl MissionBinding {
    pub fn new(
        mission_id: MissionId,
        project_id: ProjectId,
        work_product_id: WorkProductId,
        mission_revision: RevisionId,
        consent_digest: Digest,
    ) -> Self {
        Self {
            mission_id,
            project_id,
            work_product_id,
            mission_revision,
            consent_digest,
        }
    }

    pub fn digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentBinding {
    pub consent_digest: Digest,
    pub consent_revision: RevisionId,
}

impl ConsentBinding {
    pub fn new(consent_digest: Digest, consent_revision: RevisionId) -> Self {
        Self {
            consent_digest,
            consent_revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PermissionDigestMaterial<'a> {
    organization_id: &'a OrganizationId,
    caller_account_id: &'a AccountId,
    authority: AuthorityKind,
    allowed_operations: &'a BTreeSet<ReadOperation>,
    permission_revision: &'a RevisionId,
    consent: &'a ConsentBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionScope {
    pub organization_id: OrganizationId,
    pub caller_account_id: AccountId,
    pub authority: AuthorityKind,
    pub allowed_operations: BTreeSet<ReadOperation>,
    pub permission_revision: RevisionId,
    pub consent: ConsentBinding,
    pub permission_digest: Digest,
}

impl PermissionScope {
    pub fn new(
        organization_id: OrganizationId,
        caller_account_id: AccountId,
        authority: AuthorityKind,
        allowed_operations: BTreeSet<ReadOperation>,
        permission_revision: RevisionId,
        consent: ConsentBinding,
    ) -> Result<Self, ModelError> {
        if allowed_operations.is_empty() {
            return Err(ModelError::Empty {
                field: "allowed Organizations operations",
            });
        }
        let material = PermissionDigestMaterial {
            organization_id: &organization_id,
            caller_account_id: &caller_account_id,
            authority,
            allowed_operations: &allowed_operations,
            permission_revision: &permission_revision,
            consent: &consent,
        };
        let permission_digest = digest_serializable(&material)?;
        Ok(Self {
            organization_id,
            caller_account_id,
            authority,
            allowed_operations,
            permission_revision,
            consent,
            permission_digest,
        })
    }

    pub fn all(
        organization_id: OrganizationId,
        caller_account_id: AccountId,
        authority: AuthorityKind,
        permission_revision: RevisionId,
        consent: ConsentBinding,
    ) -> Result<Self, ModelError> {
        Self::new(
            organization_id,
            caller_account_id,
            authority,
            ReadOperation::ALL.into_iter().collect(),
            permission_revision,
            consent,
        )
    }

    pub fn permits(&self, operation: ReadOperation) -> bool {
        self.allowed_operations.contains(&operation)
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(
            self.organization_id.clone(),
            self.caller_account_id.clone(),
            self.authority,
            self.allowed_operations.clone(),
            self.permission_revision.clone(),
            self.consent.clone(),
        )?;
        if rebuilt.permission_digest != self.permission_digest {
            return Err(ModelError::InvalidDigest {
                field: "permission digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopeDigestMaterial<'a> {
    organization_id: &'a OrganizationId,
    hierarchy: &'a OrganizationHierarchy,
    target_scope: &'a [TargetReference],
    policy_type: PolicyType,
    mission: &'a MissionBinding,
    permission_digest: &'a Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsOrganizationsScope {
    pub organization_id: OrganizationId,
    pub hierarchy: OrganizationHierarchy,
    pub target_scope: Vec<TargetReference>,
    pub policy_type: PolicyType,
    pub mission: MissionBinding,
    pub permissions: PermissionScope,
    pub hierarchy_digest: Digest,
    pub scope_digest: Digest,
}

impl AwsOrganizationsScope {
    pub fn new(
        organization_id: OrganizationId,
        hierarchy: OrganizationHierarchy,
        mut target_scope: Vec<TargetReference>,
        policy_type: PolicyType,
        mission: MissionBinding,
        permissions: PermissionScope,
    ) -> Result<Self, ModelError> {
        if hierarchy.organization_id != organization_id
            || permissions.organization_id != organization_id
        {
            return Err(ModelError::InvalidRelationship {
                field: "scope organization",
            });
        }
        if target_scope.is_empty() {
            return Err(ModelError::Empty {
                field: "scope targets",
            });
        }
        if target_scope.len() > MAX_SCOPE_TARGETS {
            return Err(ModelError::BoundExceeded {
                field: "scope targets",
            });
        }
        if permissions.consent.consent_digest != mission.consent_digest {
            return Err(ModelError::InvalidRelationship {
                field: "mission consent scope",
            });
        }
        for target in &target_scope {
            target.verify()?;
            if target.organization_id != organization_id || !target.contains_in(&hierarchy) {
                return Err(ModelError::InvalidRelationship {
                    field: "scope target hierarchy",
                });
            }
        }
        target_scope.sort_by(|left, right| left.target_id.cmp(&right.target_id));
        for pair in target_scope.windows(2) {
            if pair[0].target_id == pair[1].target_id {
                return Err(ModelError::Duplicate {
                    field: "scope target",
                });
            }
        }
        let hierarchy_digest = hierarchy.hierarchy_digest.clone();
        let material = ScopeDigestMaterial {
            organization_id: &organization_id,
            hierarchy: &hierarchy,
            target_scope: &target_scope,
            policy_type,
            mission: &mission,
            permission_digest: &permissions.permission_digest,
        };
        let scope_digest = digest_serializable(&material)?;
        Ok(Self {
            organization_id,
            hierarchy,
            target_scope,
            policy_type,
            mission,
            permissions,
            hierarchy_digest,
            scope_digest,
        })
    }

    pub fn contains_target(&self, target: &TargetReference) -> bool {
        self.target_scope
            .iter()
            .any(|candidate| candidate.target_id == target.target_id)
    }

    pub fn target(&self, target_id: &TargetId) -> Option<&TargetReference> {
        self.target_scope
            .iter()
            .find(|target| &target.target_id == target_id)
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        self.hierarchy.verify()?;
        self.permissions.verify()?;
        let rebuilt = Self::new(
            self.organization_id.clone(),
            self.hierarchy.clone(),
            self.target_scope.clone(),
            self.policy_type,
            self.mission.clone(),
            self.permissions.clone(),
        )?;
        if rebuilt.hierarchy_digest != self.hierarchy_digest {
            return Err(ModelError::InvalidDigest {
                field: "scope hierarchy digest",
            });
        }
        if rebuilt.scope_digest != self.scope_digest {
            return Err(ModelError::InvalidDigest {
                field: "scope digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SigV4SecretReference {
    reference_id: String,
    region: String,
    scope_digest: Digest,
    revision: RevisionId,
    revoked: bool,
}

pub type SecretReference = SigV4SecretReference;

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("reference_id", &"<opaque>")
            .field("region", &self.region)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SigV4SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        region: impl Into<String>,
        scope_digest: Digest,
        revision: RevisionId,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        let region = region.into();
        validate_text(
            &reference_id,
            "SigV4 secret reference",
            MAX_IDENTIFIER_LENGTH,
        )?;
        validate_text(&region, "AWS region", MAX_IDENTIFIER_LENGTH)?;
        if reference_id.chars().any(char::is_whitespace) || region.chars().any(char::is_whitespace)
        {
            return Err(ModelError::Invalid {
                field: "SigV4 secret reference",
            });
        }
        Ok(Self {
            reference_id,
            region,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn revision(&self) -> &RevisionId {
        &self.revision
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_text(&format!(
            "{}:{}:{}:{}",
            self.reference_id,
            self.region,
            self.scope_digest.as_str(),
            self.revision.as_str()
        ))
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::Revoked)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }
}

impl Drop for SigV4SecretReference {
    fn drop(&mut self) {
        self.reference_id.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Registration {
    pub state: RegistrationState,
    pub reversible: bool,
    pub version_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub hierarchy_digest: Digest,
    pub registration_revision: RevisionId,
    pub registration_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub prior_registration_digest: Digest,
    pub revocation_digest: Digest,
}

impl Registration {
    pub fn new(
        version_digest: Digest,
        provider_digest: Digest,
        contract_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
        hierarchy_digest: Digest,
        registration_revision: RevisionId,
    ) -> Result<Self, ModelError> {
        let mut registration = Self {
            state: RegistrationState::Active,
            reversible: true,
            version_digest,
            provider_digest,
            contract_digest,
            permission_digest,
            scope_digest,
            hierarchy_digest,
            registration_revision,
            registration_digest: Digest::from_text("pending-registration-digest"),
        };
        registration.registration_digest = registration.compute_digest()?;
        Ok(registration)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.state,
            self.reversible,
            &self.version_digest,
            &self.provider_digest,
            &self.contract_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.hierarchy_digest,
            &self.registration_revision,
        ))
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.state == RegistrationState::Active {
            Ok(())
        } else {
            Err(ModelError::Revoked)
        }
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        if !self.reversible || self.compute_digest()? != self.registration_digest {
            return Err(ModelError::InvalidDigest {
                field: "registration digest",
            });
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        self.ensure_active()?;
        let prior_registration_digest = self.registration_digest.clone();
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest()?;
        Ok(RegistrationRevocation {
            prior_registration_digest,
            revocation_digest: self.registration_digest.clone(),
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    token: String,
}

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PAGE_TOKEN_LENGTH
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidPageToken);
        }
        Ok(Self { token: value })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_bytes(self.token.as_bytes())
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest())
            .finish()
    }
}

impl Drop for OpaquePageToken {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentDirection {
    None,
    PolicyToTarget,
    TargetToPolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentState {
    Attached,
    NotAttached,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttachmentObservation {
    pub policy: PolicyIdentity,
    pub target: TargetReference,
    pub direction: AttachmentDirection,
    pub state: AttachmentState,
    pub relationship_digest: Digest,
}

impl AttachmentObservation {
    pub fn new(
        policy: PolicyIdentity,
        target: TargetReference,
        direction: AttachmentDirection,
        state: AttachmentState,
    ) -> Result<Self, ModelError> {
        policy.verify()?;
        target.verify()?;
        if direction == AttachmentDirection::None {
            return Err(ModelError::Invalid {
                field: "attachment direction",
            });
        }
        let relationship_digest = digest_serializable(&(
            &policy.policy_type,
            &policy.policy_id,
            &policy.policy_arn,
            &target.organization_id,
            &target.target_id,
            direction,
            state,
        ))?;
        Ok(Self {
            policy,
            target,
            direction,
            state,
            relationship_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadBounds {
    pub max_pages: u16,
    pub max_items: usize,
    pub max_results: u8,
}

impl ReadBounds {
    pub fn new(max_pages: u16, max_items: usize, max_results: u8) -> Result<Self, ModelError> {
        if !(1..=64).contains(&max_pages) {
            return Err(ModelError::InvalidPageCount);
        }
        if !(1..=4_096).contains(&max_items) {
            return Err(ModelError::InvalidItemCount);
        }
        if !(1..=20).contains(&max_results) {
            return Err(ModelError::InvalidPageSize);
        }
        Ok(Self {
            max_pages,
            max_items,
            max_results,
        })
    }
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            max_pages: 16,
            max_items: 512,
            max_results: 20,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub version_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub hierarchy_digest: Digest,
    pub evidence_digest: Digest,
}
