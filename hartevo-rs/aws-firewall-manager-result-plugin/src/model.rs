//! Typed and redacted AWS Firewall Manager scope, request, and response models.
//!
//! The model deliberately has no type for a policy document, managed rule
//! group body, raw violation metadata, account PII, or a provider cursor. AWS
//! identifiers are accepted only at construction time and are represented in
//! public serialization by digests.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::{
    AWS_FIREWALL_MANAGER_API_VERSION, AWS_FIREWALL_MANAGER_CONTRACT_VERSION,
    AWS_FIREWALL_MANAGER_PLUGIN_VERSION, AWS_FIREWALL_MANAGER_PROVIDER_ID,
    AWS_FIREWALL_MANAGER_PROVIDER_VERSION,
    error::{AwsFirewallManagerError, ModelError, Result},
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_POLICIES: usize = 64;
pub const MAX_MEMBER_ACCOUNTS: usize = 128;
pub const MAX_RESOURCE_TYPES: usize = 32;
pub const MAX_COMPLIANCE_DETAILS: usize = 256;
pub const MAX_VIOLATION_CATEGORIES: usize = 32;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 50;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 12;
pub const MAX_RETRIES: u8 = 2;

pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "fms:ListPolicies",
    "fms:GetPolicy",
    "fms:ListComplianceStatus",
    "fms:GetComplianceDetail",
    "mission.scope",
];

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<()> {
    if value.is_empty() {
        return Err(ModelError::Empty { field }.into());
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field }.into());
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field }.into());
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str, max: usize) -> Result<()> {
    validate_text(value, field, max)?;
    if value
        .bytes()
        .any(|byte| !(byte.is_ascii_alphanumeric() || b"-_.:/+=@*".contains(&byte)))
    {
        return Err(ModelError::InvalidCharacters { field }.into());
    }
    Ok(())
}

fn validate_digest(value: &Digest, field: &'static str) -> Result<()> {
    if value.as_str().len() == 64
        && value
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ModelError::InvalidDigest { field }.into())
    }
}

fn validate_positive(value: u64, field: &'static str) -> Result<()> {
    if value == 0 {
        Err(ModelError::MustBePositive { field }.into())
    } else {
        Ok(())
    }
}

fn digest_lines(domain: &str, values: impl IntoIterator<Item = String>) -> Digest {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(domain.as_bytes());
    for value in values {
        bytes.push(0);
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    Digest::from_bytes(&bytes)
}

/// A SHA-256 digest used for every redacted identifier, request, and evidence
/// fence.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(Sha256::digest(bytes).as_slice()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(domain: &str, values: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(domain.as_bytes());
        for (name, value) in values {
            bytes.push(0);
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let digest = Self(value);
        validate_digest(&digest, "digest")?;
        Ok(digest)
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_digest(self, "digest")
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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[usize::from(byte >> 4)] as char);
        result.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    result
}

macro_rules! redacted_identifier {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if !($validator)(&value) {
                    return Err(ModelError::Invalid { field: $field }.into());
                }
                Ok(Self(value))
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-fms-redacted-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(ModelError::Invalid { field: $field }.into())
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

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(self.digest().as_str())
            }
        }
    };
}

redacted_identifier!(OrganizationId, "organization", |value: &str| {
    validate_identifier(value, "organization", MAX_IDENTIFIER_BYTES).is_ok()
        && value.starts_with("o-")
});
redacted_identifier!(AccountId, "account", |value: &str| {
    value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
});
redacted_identifier!(AwsRegion, "region", |value: &str| {
    validate_identifier(value, "region", 63).is_ok()
        && value.len() >= 3
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
});
redacted_identifier!(PolicyId, "policy", |value: &str| {
    validate_identifier(value, "policy", MAX_IDENTIFIER_BYTES).is_ok()
});
redacted_identifier!(PolicyArn, "policy-arn", |value: &str| {
    validate_text(value, "policy arn", 2_048).is_ok() && value.starts_with("arn:")
});
redacted_identifier!(MissionId, "mission", |value: &str| {
    validate_identifier(value, "mission", MAX_IDENTIFIER_BYTES).is_ok()
});
redacted_identifier!(ProjectId, "project", |value: &str| {
    validate_identifier(value, "project", MAX_IDENTIFIER_BYTES).is_ok()
});
redacted_identifier!(WorkProductId, "work-product", |value: &str| {
    validate_identifier(value, "work product", MAX_IDENTIFIER_BYTES).is_ok()
});

pub type AdminAccountId = AccountId;
pub type MemberAccountId = AccountId;

/// Resource identifiers are immediately reduced to a digest; the raw value
/// is never retained by the model.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ResourceId(Digest);

impl ResourceId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let mut value = value.into();
        validate_text(&value, "resource id", 2_048)?;
        let digest = Digest::from_parts("aws-fms-resource-id/v1", &[("value", value.clone())]);
        value.zeroize();
        Ok(Self(digest))
    }

    pub fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Debug for ResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ResourceId").field(&self.0).finish()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceType(String);

impl ResourceType {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_identifier(&value, "resource type", 128)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("aws-fms-resource-type/v1", &[("value", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_identifier(&self.0, "resource type", 128)
    }
}

impl fmt::Debug for ResourceType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ResourceType")
            .field(&self.0)
            .finish()
    }
}

impl Serialize for ResourceType {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyType {
    Waf,
    NetworkFirewall,
    ShieldAdvanced,
    DnsFirewall,
    ThirdParty,
    Other,
}

impl PolicyType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Waf => "waf",
            Self::NetworkFirewall => "network_firewall",
            Self::ShieldAdvanced => "shield_advanced",
            Self::DnsFirewall => "dns_firewall",
            Self::ThirdParty => "third_party",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

pub type PolicyRevision = Revision;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub const fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-fms-mission/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub const fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-fms-project/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub const fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-fms-work-product/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScope {
    pub revision: Revision,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    consent_digest: Digest,
}

impl ConsentScope {
    pub fn new(
        consent_id: impl Into<String>,
        revision: Revision,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let consent_id = consent_id.into();
        validate_identifier(&consent_id, "consent", MAX_IDENTIFIER_BYTES)?;
        let consent_digest = Digest::from_parts(
            "aws-fms-consent/v1",
            &[
                ("id", Digest::from_text(&consent_id).as_str().to_owned()),
                ("revision", revision.get().to_string()),
                ("expires", expires_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            revision,
            expires_at,
            revoked: false,
            consent_digest,
        })
    }

    pub fn for_layer_one(
        consent_id: impl Into<String>,
        revision: Revision,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(consent_id, revision, expires_at)
    }

    pub fn digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn is_active_at(&self, at: DateTime<Utc>) -> bool {
        !self.revoked && at < self.expires_at
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: Revision,
    pub authority: String,
    pub permissions: BTreeSet<String>,
    permission_digest: Digest,
}

impl PermissionSnapshot {
    pub fn new<I, S>(
        revision: Revision,
        authority: impl Into<String>,
        permissions: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let permissions = permissions
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        let authority = authority.into();
        let expected_permissions = LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<BTreeSet<_>>();
        if permissions != expected_permissions {
            return Err(ModelError::Invalid {
                field: "permission snapshot",
            }
            .into());
        }
        validate_identifier(&authority, "permission authority", MAX_IDENTIFIER_BYTES)?;
        let permission_digest = digest_lines(
            "aws-fms-permissions/v1",
            [
                revision.get().to_string(),
                authority.clone(),
                permissions.iter().cloned().collect::<Vec<_>>().join("\n"),
            ],
        );
        Ok(Self {
            revision,
            authority,
            permissions,
            permission_digest,
        })
    }

    pub fn for_layer_one(revision: Revision) -> Self {
        Self::new(
            revision,
            "management_or_delegated_administrator",
            LAYER1_PERMISSIONS,
        )
        .expect("Layer-1 permission set is valid")
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn validate(&self) -> Result<()> {
        let expected_permissions = LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<BTreeSet<_>>();
        if self.permissions != expected_permissions {
            return Err(ModelError::Invalid {
                field: "permission snapshot",
            }
            .into());
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PolicyIdentity {
    pub policy_type: PolicyType,
    pub id: PolicyId,
    pub arn: PolicyArn,
    pub revision: Revision,
}

impl PolicyIdentity {
    pub fn new(policy_type: PolicyType, id: PolicyId, arn: PolicyArn, revision: Revision) -> Self {
        Self {
            policy_type,
            id,
            arn,
            revision,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-fms-policy-identity/v1",
            &[
                ("type", self.policy_type.as_str().to_owned()),
                ("id", self.id.digest().as_str().to_owned()),
                ("arn", self.arn.digest().as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    pub fn id_digest(&self) -> Digest {
        self.id.digest()
    }

    pub fn arn_digest(&self) -> Digest {
        self.arn.digest()
    }

    pub fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.arn.validate()?;
        validate_positive(self.revision.get(), "policy revision")
    }
}

impl fmt::Debug for PolicyIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyIdentity")
            .field("policy_type", &self.policy_type)
            .field("policy_digest", &self.digest())
            .finish()
    }
}

impl Serialize for PolicyIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("PolicyIdentity", 3)?;
        state.serialize_field("policyType", &self.policy_type)?;
        state.serialize_field("policyDigest", &self.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsFirewallManagerScope {
    organization: OrganizationId,
    admin_account: AdminAccountId,
    region: AwsRegion,
    policies: Vec<PolicyIdentity>,
    member_accounts: Vec<MemberAccountId>,
    resource_types: Vec<ResourceType>,
    mission: MissionBinding,
    project: ProjectBinding,
    work_product: WorkProductBinding,
    permissions: PermissionSnapshot,
    consent: ConsentScope,
    policy_allowlist_digest: Digest,
    member_account_allowlist_digest: Digest,
    resource_type_allowlist_digest: Digest,
    scope_digest: Digest,
}

impl AwsFirewallManagerScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization: OrganizationId,
        admin_account: AdminAccountId,
        region: AwsRegion,
        policies: Vec<PolicyIdentity>,
        member_accounts: Vec<MemberAccountId>,
        resource_types: Vec<ResourceType>,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        permissions: PermissionSnapshot,
        consent: ConsentScope,
    ) -> Result<Self> {
        if policies.is_empty() || policies.len() > MAX_POLICIES {
            return Err(ModelError::TooMany { field: "policies" }.into());
        }
        if member_accounts.is_empty() || member_accounts.len() > MAX_MEMBER_ACCOUNTS {
            return Err(ModelError::TooMany {
                field: "member accounts",
            }
            .into());
        }
        if resource_types.is_empty() || resource_types.len() > MAX_RESOURCE_TYPES {
            return Err(ModelError::TooMany {
                field: "resource types",
            }
            .into());
        }
        organization.validate()?;
        admin_account.validate()?;
        region.validate()?;
        mission.id.validate()?;
        project.id.validate()?;
        work_product.id.validate()?;
        permissions.validate()?;
        if member_accounts
            .iter()
            .any(|account| account == &admin_account)
        {
            return Err(ModelError::Invalid {
                field: "member account allowlist",
            }
            .into());
        }
        let mut policy_digests = policies
            .iter()
            .map(PolicyIdentity::digest)
            .collect::<Vec<_>>();
        policy_digests.sort();
        if policy_digests.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ModelError::Duplicate {
                field: "policy allowlist",
            }
            .into());
        }
        if policies.iter().any(|policy| policy.validate().is_err()) {
            return Err(ModelError::Invalid {
                field: "policy allowlist",
            }
            .into());
        }
        let mut account_digests = member_accounts
            .iter()
            .map(AccountId::digest)
            .collect::<Vec<_>>();
        account_digests.sort();
        if account_digests.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ModelError::Duplicate {
                field: "member account allowlist",
            }
            .into());
        }
        let mut type_digests = resource_types
            .iter()
            .map(ResourceType::digest)
            .collect::<Vec<_>>();
        type_digests.sort();
        if type_digests.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ModelError::Duplicate {
                field: "resource type allowlist",
            }
            .into());
        }
        let policy_allowlist_digest = digest_lines(
            "aws-fms-policy-allowlist/v1",
            policy_digests.into_iter().map(|digest| digest.to_string()),
        );
        let member_account_allowlist_digest = digest_lines(
            "aws-fms-member-account-allowlist/v1",
            account_digests.into_iter().map(|digest| digest.to_string()),
        );
        let resource_type_allowlist_digest = digest_lines(
            "aws-fms-resource-type-allowlist/v1",
            type_digests.into_iter().map(|digest| digest.to_string()),
        );
        let scope_digest = Digest::from_parts(
            "aws-fms-scope/v1",
            &[
                ("organization", organization.digest().to_string()),
                ("admin_account", admin_account.digest().to_string()),
                ("region", region.digest().to_string()),
                ("policies", policy_allowlist_digest.to_string()),
                (
                    "member_accounts",
                    member_account_allowlist_digest.to_string(),
                ),
                ("resource_types", resource_type_allowlist_digest.to_string()),
                ("mission", mission.digest().to_string()),
                ("project", project.digest().to_string()),
                ("work_product", work_product.digest().to_string()),
                ("permission", permissions.digest().to_string()),
                ("consent", consent.digest().to_string()),
            ],
        );
        Ok(Self {
            organization,
            admin_account,
            region,
            policies,
            member_accounts,
            resource_types,
            mission,
            project,
            work_product,
            permissions,
            consent,
            policy_allowlist_digest,
            member_account_allowlist_digest,
            resource_type_allowlist_digest,
            scope_digest,
        })
    }

    pub fn organization(&self) -> &OrganizationId {
        &self.organization
    }

    pub fn admin_account(&self) -> &AdminAccountId {
        &self.admin_account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn policies(&self) -> &[PolicyIdentity] {
        &self.policies
    }

    pub fn member_accounts(&self) -> &[MemberAccountId] {
        &self.member_accounts
    }

    pub fn resource_types(&self) -> &[ResourceType] {
        &self.resource_types
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

    pub fn permissions(&self) -> &PermissionSnapshot {
        &self.permissions
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn policy_allowlist_digest(&self) -> &Digest {
        &self.policy_allowlist_digest
    }

    pub fn member_account_allowlist_digest(&self) -> &Digest {
        &self.member_account_allowlist_digest
    }

    pub fn resource_type_allowlist_digest(&self) -> &Digest {
        &self.resource_type_allowlist_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn allows_policy(&self, policy: &PolicyIdentity) -> bool {
        self.policies
            .iter()
            .any(|allowed| allowed.digest() == policy.digest())
    }

    pub fn policy(&self, digest: &Digest) -> Option<&PolicyIdentity> {
        self.policies
            .iter()
            .find(|policy| policy.digest() == *digest)
    }

    pub fn allows_member_account(&self, account: &MemberAccountId) -> bool {
        self.member_accounts
            .iter()
            .any(|allowed| allowed == account)
    }

    pub fn allows_member_account_digest(&self, digest: &Digest) -> bool {
        self.member_accounts
            .iter()
            .any(|account| account.digest() == *digest)
    }

    pub fn allows_resource_type(&self, resource_type: &ResourceType) -> bool {
        self.resource_types
            .iter()
            .any(|allowed| allowed == resource_type)
    }

    pub fn allows_resource_type_digest(&self, digest: &Digest) -> bool {
        self.resource_types
            .iter()
            .any(|resource_type| resource_type.digest() == *digest)
    }

    pub fn is_active_at(&self, at: DateTime<Utc>) -> bool {
        self.consent.is_active_at(at)
    }

    pub fn validate(&self) -> Result<()> {
        if self.policies.is_empty()
            || self.member_accounts.is_empty()
            || self.resource_types.is_empty()
            || self.scope_digest
                != Self::new(
                    self.organization.clone(),
                    self.admin_account.clone(),
                    self.region.clone(),
                    self.policies.clone(),
                    self.member_accounts.clone(),
                    self.resource_types.clone(),
                    self.mission.clone(),
                    self.project.clone(),
                    self.work_product.clone(),
                    self.permissions.clone(),
                    self.consent.clone(),
                )?
                .scope_digest
        {
            return Err(ModelError::ScopeMismatch {
                field: "scope digest",
            }
            .into());
        }
        Ok(())
    }
}

impl fmt::Debug for AwsFirewallManagerScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsFirewallManagerScope")
            .field("organization", &self.organization)
            .field("admin_account", &self.admin_account)
            .field("region", &self.region)
            .field("policy_allowlist_digest", &self.policy_allowlist_digest)
            .field(
                "member_account_allowlist_digest",
                &self.member_account_allowlist_digest,
            )
            .field(
                "resource_type_allowlist_digest",
                &self.resource_type_allowlist_digest,
            )
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

impl Serialize for AwsFirewallManagerScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsFirewallManagerScope", 10)?;
        state.serialize_field("organizationDigest", &self.organization.digest())?;
        state.serialize_field("adminAccountDigest", &self.admin_account.digest())?;
        state.serialize_field("regionDigest", &self.region.digest())?;
        state.serialize_field("policyAllowlistDigest", &self.policy_allowlist_digest)?;
        state.serialize_field(
            "memberAccountAllowlistDigest",
            &self.member_account_allowlist_digest,
        )?;
        state.serialize_field(
            "resourceTypeAllowlistDigest",
            &self.resource_type_allowlist_digest,
        )?;
        state.serialize_field("mission", &self.mission)?;
        state.serialize_field("project", &self.project)?;
        state.serialize_field("workProduct", &self.work_product)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.end()
    }
}

/// A non-serializing, non-displayable SigV4 reference. The opaque host handle
/// is used only to derive a digest and is zeroized before this value returns.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    region_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl Into<String>,
        region: &AwsRegion,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self> {
        let mut handle = opaque_handle.into();
        validate_text(&handle, "opaque SigV4 reference", MAX_IDENTIFIER_BYTES)?;
        let reference_digest = Digest::from_parts(
            "aws-fms-opaque-sigv4-reference/v1",
            &[
                ("handle", handle.clone()),
                ("region", region.digest().to_string()),
                ("scope", scope_digest.to_string()),
                ("revision", revision.get().to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            reference_digest,
            scope_digest,
            region_digest: region.digest(),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsFirewallManagerScope,
        revision: Revision,
    ) -> Result<Self> {
        Self::new(
            opaque_handle,
            scope.region(),
            scope.scope_digest().clone(),
            revision,
        )
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn region_digest(&self) -> &Digest {
        &self.region_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn validate(&self, scope: &AwsFirewallManagerScope) -> Result<()> {
        if self.revoked
            || self.scope_digest != *scope.scope_digest()
            || self.region_digest != scope.region().digest()
        {
            return Err(AwsFirewallManagerError::InvalidSecretReference);
        }
        self.reference_digest.validate()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("region_digest", &self.region_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

pub type SigV4SecretReference = SecretReference;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Fake,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Fake => "fake",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadBounds {
    pub max_pages: u16,
    pub page_size: u16,
    pub max_response_bytes: u64,
    pub max_requests: u16,
    pub max_policies: usize,
    pub max_member_accounts: usize,
    pub max_compliance_details: usize,
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            page_size: PAGE_SIZE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_requests: MAX_REQUESTS_PER_READ,
            max_policies: MAX_POLICIES,
            max_member_accounts: MAX_MEMBER_ACCOUNTS,
            max_compliance_details: MAX_COMPLIANCE_DETAILS,
        }
    }
}

impl ReadBounds {
    pub fn new(
        max_pages: u16,
        page_size: u16,
        max_response_bytes: u64,
        max_requests: u16,
    ) -> Result<Self> {
        let bounds = Self {
            max_pages,
            page_size,
            max_response_bytes,
            max_requests,
            ..Self::default()
        };
        bounds.validate()?;
        Ok(bounds)
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.page_size == 0
            || self.page_size > PAGE_SIZE
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_requests == 0
            || self.max_requests > MAX_REQUESTS_PER_READ
        {
            return Err(ModelError::Invalid {
                field: "read bounds",
            }
            .into());
        }
        Ok(())
    }
}

/// Opaque pagination state. Neither the provider's raw token nor its bytes
/// are retained; only a request-bound digest is carried forward.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    token_digest: Digest,
    request_digest: Digest,
    scope_digest: Digest,
    page_number: u16,
}

impl OpaquePageToken {
    pub fn new(
        raw_token: impl Into<String>,
        request_digest: &Digest,
        scope_digest: &Digest,
        page_number: u16,
    ) -> Result<Self> {
        let mut raw_token = raw_token.into();
        validate_text(&raw_token, "pagination token", MAX_CURSOR_BYTES)?;
        if page_number == 0 || page_number > MAX_PAGES {
            raw_token.zeroize();
            return Err(ModelError::InvalidCursor {
                field: "pagination token",
            }
            .into());
        }
        let token_digest = Digest::from_parts(
            "aws-fms-opaque-cursor/v1",
            &[
                ("token", raw_token.clone()),
                ("request", request_digest.to_string()),
                ("scope", scope_digest.to_string()),
                ("page", page_number.to_string()),
            ],
        );
        raw_token.zeroize();
        Ok(Self {
            token_digest,
            request_digest: request_digest.clone(),
            scope_digest: scope_digest.clone(),
            page_number,
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn validate_against(
        &self,
        request_digest: &Digest,
        scope_digest: &Digest,
        expected_page: u16,
    ) -> Result<()> {
        if self.request_digest != *request_digest
            || self.scope_digest != *scope_digest
            || self.page_number != expected_page
        {
            return Err(AwsFirewallManagerError::CursorMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("token_digest", &self.token_digest)
            .field("request_digest", &self.request_digest)
            .field("scope_digest", &self.scope_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for OpaquePageToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("OpaquePageToken", 4)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

pub type OpaqueCursor = OpaquePageToken;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsFirewallManagerOperation {
    ListPolicies,
    GetPolicy,
    ListComplianceStatus,
    GetComplianceDetail,
}

impl AwsFirewallManagerOperation {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ListPolicies => "ListPolicies",
            Self::GetPolicy => "GetPolicy",
            Self::ListComplianceStatus => "ListComplianceStatus",
            Self::GetComplianceDetail => "GetComplianceDetail",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListPoliciesRequest {
    pub scope_digest: Digest,
    pub policy_type: Option<PolicyType>,
    pub max_results: u16,
    pub cursor: Option<OpaquePageToken>,
    request_digest: Digest,
}

impl ListPoliciesRequest {
    pub fn new(
        scope: &AwsFirewallManagerScope,
        policy_type: Option<PolicyType>,
        max_results: u16,
        cursor: Option<OpaquePageToken>,
    ) -> Result<Self> {
        if max_results == 0 || max_results > PAGE_SIZE {
            return Err(ModelError::Invalid {
                field: "ListPolicies max results",
            }
            .into());
        }
        let request_digest = request_digest(
            AwsFirewallManagerOperation::ListPolicies,
            scope.scope_digest(),
            &[
                (
                    "policy_type",
                    policy_type.map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("max_results", max_results.to_string()),
                ("allowlist", scope.policy_allowlist_digest().to_string()),
            ],
        );
        if let Some(cursor) = &cursor {
            cursor.validate_against(&request_digest, scope.scope_digest(), cursor.page_number())?;
        }
        Ok(Self {
            scope_digest: scope.scope_digest().clone(),
            policy_type,
            max_results,
            cursor,
            request_digest,
        })
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, OpaquePageToken::page_number)
    }

    pub fn with_cursor(&self, cursor: Option<OpaquePageToken>) -> Result<Self> {
        if let Some(cursor) = &cursor {
            cursor.validate_against(
                &self.request_digest,
                &self.scope_digest,
                cursor.page_number(),
            )?;
        }
        Ok(Self {
            scope_digest: self.scope_digest.clone(),
            policy_type: self.policy_type,
            max_results: self.max_results,
            cursor,
            request_digest: self.request_digest.clone(),
        })
    }

    pub fn with_next_token(&self, cursor: Option<OpaquePageToken>) -> Result<Self> {
        self.with_cursor(cursor)
    }
}

impl fmt::Debug for ListPoliciesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListPoliciesRequest")
            .field("scope_digest", &self.scope_digest)
            .field("policy_type", &self.policy_type)
            .field("max_results", &self.max_results)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for ListPoliciesRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ListPoliciesRequest", 5)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("policyType", &self.policy_type)?;
        state.serialize_field("maxResults", &self.max_results)?;
        state.serialize_field("cursor", &self.cursor)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetPolicyRequest {
    pub scope_digest: Digest,
    pub policy: PolicyIdentity,
    request_digest: Digest,
}

impl GetPolicyRequest {
    pub fn new(scope: &AwsFirewallManagerScope, policy: PolicyIdentity) -> Result<Self> {
        if !scope.allows_policy(&policy) {
            return Err(AwsFirewallManagerError::PolicyNotAllowed);
        }
        let request_digest = request_digest(
            AwsFirewallManagerOperation::GetPolicy,
            scope.scope_digest(),
            &[
                ("policy", policy.digest().to_string()),
                ("revision", policy.revision.get().to_string()),
                ("allowlist", scope.policy_allowlist_digest().to_string()),
            ],
        );
        Ok(Self {
            scope_digest: scope.scope_digest().clone(),
            policy,
            request_digest,
        })
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

impl fmt::Debug for GetPolicyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetPolicyRequest")
            .field("scope_digest", &self.scope_digest)
            .field("policy_digest", &self.policy.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for GetPolicyRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("GetPolicyRequest", 3)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("policy", &self.policy)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListComplianceStatusRequest {
    pub scope_digest: Digest,
    pub policy: PolicyIdentity,
    pub max_results: u16,
    pub cursor: Option<OpaquePageToken>,
    request_digest: Digest,
}

impl ListComplianceStatusRequest {
    pub fn new(
        scope: &AwsFirewallManagerScope,
        policy: PolicyIdentity,
        max_results: u16,
        cursor: Option<OpaquePageToken>,
    ) -> Result<Self> {
        if !scope.allows_policy(&policy) {
            return Err(AwsFirewallManagerError::PolicyNotAllowed);
        }
        if max_results == 0 || max_results > PAGE_SIZE {
            return Err(ModelError::Invalid {
                field: "ListComplianceStatus max results",
            }
            .into());
        }
        let request_digest = request_digest(
            AwsFirewallManagerOperation::ListComplianceStatus,
            scope.scope_digest(),
            &[
                ("policy", policy.digest().to_string()),
                ("max_results", max_results.to_string()),
                (
                    "accounts",
                    scope.member_account_allowlist_digest().to_string(),
                ),
            ],
        );
        if let Some(cursor) = &cursor {
            cursor.validate_against(&request_digest, scope.scope_digest(), cursor.page_number())?;
        }
        Ok(Self {
            scope_digest: scope.scope_digest().clone(),
            policy,
            max_results,
            cursor,
            request_digest,
        })
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, OpaquePageToken::page_number)
    }

    pub fn with_cursor(&self, cursor: Option<OpaquePageToken>) -> Result<Self> {
        if let Some(cursor) = &cursor {
            cursor.validate_against(
                &self.request_digest,
                &self.scope_digest,
                cursor.page_number(),
            )?;
        }
        Ok(Self {
            scope_digest: self.scope_digest.clone(),
            policy: self.policy.clone(),
            max_results: self.max_results,
            cursor,
            request_digest: self.request_digest.clone(),
        })
    }

    pub fn with_next_token(&self, cursor: Option<OpaquePageToken>) -> Result<Self> {
        self.with_cursor(cursor)
    }
}

impl fmt::Debug for ListComplianceStatusRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListComplianceStatusRequest")
            .field("scope_digest", &self.scope_digest)
            .field("policy_digest", &self.policy.digest())
            .field("max_results", &self.max_results)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for ListComplianceStatusRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ListComplianceStatusRequest", 5)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("policy", &self.policy)?;
        state.serialize_field("maxResults", &self.max_results)?;
        state.serialize_field("cursor", &self.cursor)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetComplianceDetailRequest {
    pub scope_digest: Digest,
    pub policy: PolicyIdentity,
    pub member_account: MemberAccountId,
    pub resource_type: ResourceType,
    pub resource_id: ResourceId,
    request_digest: Digest,
}

impl GetComplianceDetailRequest {
    pub fn new(
        scope: &AwsFirewallManagerScope,
        policy: PolicyIdentity,
        member_account: MemberAccountId,
        resource_type: ResourceType,
        resource_id: ResourceId,
    ) -> Result<Self> {
        if !scope.allows_policy(&policy) {
            return Err(AwsFirewallManagerError::PolicyNotAllowed);
        }
        if !scope.allows_member_account(&member_account) {
            return Err(AwsFirewallManagerError::AccountNotAllowed);
        }
        if !scope.allows_resource_type(&resource_type) {
            return Err(AwsFirewallManagerError::ResourceTypeNotAllowed);
        }
        let request_digest = request_digest(
            AwsFirewallManagerOperation::GetComplianceDetail,
            scope.scope_digest(),
            &[
                ("policy", policy.digest().to_string()),
                ("account", member_account.digest().to_string()),
                ("resource_type", resource_type.digest().to_string()),
                ("resource", resource_id.digest().to_string()),
            ],
        );
        Ok(Self {
            scope_digest: scope.scope_digest().clone(),
            policy,
            member_account,
            resource_type,
            resource_id,
            request_digest,
        })
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

impl fmt::Debug for GetComplianceDetailRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetComplianceDetailRequest")
            .field("scope_digest", &self.scope_digest)
            .field("policy_digest", &self.policy.digest())
            .field("member_account_digest", &self.member_account.digest())
            .field("resource_type", &self.resource_type)
            .field("resource_id_digest", &self.resource_id.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for GetComplianceDetailRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("GetComplianceDetailRequest", 6)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("policy", &self.policy)?;
        state.serialize_field("memberAccountDigest", &self.member_account.digest())?;
        state.serialize_field("resourceType", &self.resource_type)?;
        state.serialize_field("resourceIdDigest", self.resource_id.digest())?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.end()
    }
}

pub fn request_digest(
    operation: AwsFirewallManagerOperation,
    scope_digest: &Digest,
    fields: &[(&str, String)],
) -> Digest {
    let mut values = vec![
        ("operation", operation.as_str().to_owned()),
        ("scope", scope_digest.to_string()),
        ("api", AWS_FIREWALL_MANAGER_API_VERSION.to_owned()),
    ];
    values.extend(fields.iter().cloned());
    Digest::from_parts("aws-fms-request/v1", &values)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySummary {
    pub policy_digest: Digest,
    pub policy_type: PolicyType,
    pub policy_revision: Revision,
    pub policy_arn_digest: Digest,
}

impl PolicySummary {
    pub fn from_identity(policy: &PolicyIdentity) -> Self {
        Self {
            policy_digest: policy.digest(),
            policy_type: policy.policy_type,
            policy_revision: policy.revision,
            policy_arn_digest: policy.arn.digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyPosture {
    pub policy_digest: Digest,
    pub policy_type: PolicyType,
    pub policy_revision: Revision,
    pub resource_types: Vec<ResourceType>,
    pub resource_scope_digest: Digest,
    pub remediation_enabled: bool,
    pub managed_service_digest: Option<Digest>,
}

impl PolicyPosture {
    pub fn new(
        policy: &PolicyIdentity,
        resource_types: Vec<ResourceType>,
        resource_scope_digest: Digest,
        remediation_enabled: bool,
        managed_service: Option<String>,
    ) -> Result<Self> {
        if resource_types.is_empty() || resource_types.len() > MAX_RESOURCE_TYPES {
            return Err(ModelError::TooMany {
                field: "policy resource types",
            }
            .into());
        }
        for resource_type in &resource_types {
            resource_type.validate()?;
        }
        resource_scope_digest.validate()?;
        Ok(Self {
            policy_digest: policy.digest(),
            policy_type: policy.policy_type,
            policy_revision: policy.revision,
            resource_types,
            resource_scope_digest,
            remediation_enabled,
            managed_service_digest: managed_service
                .map(|value| Digest::from_parts("aws-fms-managed-service/v1", &[("value", value)])),
        })
    }

    pub fn validate_against(&self, policy: &PolicyIdentity) -> Result<()> {
        if self.policy_digest != policy.digest()
            || self.policy_type != policy.policy_type
            || self.policy_revision != policy.revision
        {
            return Err(AwsFirewallManagerError::ProviderDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceState {
    Compliant,
    NonCompliant,
    NotApplicable,
    InsufficientData,
    Unknown,
}

impl ComplianceState {
    pub const fn is_adoptable(self) -> bool {
        matches!(self, Self::Compliant | Self::NonCompliant)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ComplianceSummary {
    pub member_account_digest: Digest,
    pub policy_digest: Digest,
    pub state: ComplianceState,
    pub compliant_resource_count: u32,
    pub non_compliant_resource_count: u32,
    pub resource_type_digests: Vec<Digest>,
    pub violation_category_digests: Vec<Digest>,
    pub evaluation_revision: Revision,
    pub observed_at: DateTime<Utc>,
}

impl ComplianceSummary {
    pub fn new(
        policy: &PolicyIdentity,
        member_account: &MemberAccountId,
        state: ComplianceState,
        compliant_resource_count: u32,
        non_compliant_resource_count: u32,
        resource_types: Vec<ResourceType>,
        violation_categories: Vec<String>,
        evaluation_revision: Revision,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if resource_types.len() > MAX_RESOURCE_TYPES
            || violation_categories.len() > MAX_VIOLATION_CATEGORIES
        {
            return Err(ModelError::TooMany {
                field: "compliance categories",
            }
            .into());
        }
        let resource_type_digests = resource_types
            .iter()
            .map(ResourceType::digest)
            .collect::<Vec<_>>();
        let violation_category_digests = violation_categories
            .into_iter()
            .map(|category| {
                Digest::from_parts("aws-fms-violation-category/v1", &[("category", category)])
            })
            .collect::<Vec<_>>();
        Ok(Self {
            member_account_digest: member_account.digest(),
            policy_digest: policy.digest(),
            state,
            compliant_resource_count,
            non_compliant_resource_count,
            resource_type_digests,
            violation_category_digests,
            evaluation_revision,
            observed_at,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-fms-compliance-summary/v1",
            &[
                ("account", self.member_account_digest.to_string()),
                ("policy", self.policy_digest.to_string()),
                ("state", format!("{:?}", self.state)),
                ("compliant", self.compliant_resource_count.to_string()),
                (
                    "non_compliant",
                    self.non_compliant_resource_count.to_string(),
                ),
                (
                    "types",
                    self.resource_type_digests
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "violations",
                    self.violation_category_digests
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("revision", self.evaluation_revision.get().to_string()),
                ("observed", self.observed_at.to_rfc3339()),
            ],
        )
    }
}

impl fmt::Debug for ComplianceSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComplianceSummary")
            .field("member_account_digest", &self.member_account_digest)
            .field("policy_digest", &self.policy_digest)
            .field("state", &self.state)
            .field("compliant_resource_count", &self.compliant_resource_count)
            .field(
                "non_compliant_resource_count",
                &self.non_compliant_resource_count,
            )
            .field("resource_type_digests", &self.resource_type_digests)
            .field(
                "violation_category_digests",
                &self.violation_category_digests,
            )
            .field("evaluation_revision", &self.evaluation_revision)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

impl Serialize for ComplianceSummary {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ComplianceSummary", 9)?;
        state.serialize_field("memberAccountDigest", &self.member_account_digest)?;
        state.serialize_field("policyDigest", &self.policy_digest)?;
        state.serialize_field("state", &self.state)?;
        state.serialize_field("compliantResourceCount", &self.compliant_resource_count)?;
        state.serialize_field(
            "nonCompliantResourceCount",
            &self.non_compliant_resource_count,
        )?;
        state.serialize_field("resourceTypeDigests", &self.resource_type_digests)?;
        state.serialize_field("violationCategoryDigests", &self.violation_category_digests)?;
        state.serialize_field("evaluationRevision", &self.evaluation_revision)?;
        state.serialize_field("observedAt", &self.observed_at)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ComplianceDetailProjection {
    pub member_account_digest: Digest,
    pub policy_digest: Digest,
    pub resource_type: ResourceType,
    pub resource_id_digest: Digest,
    pub state: ComplianceState,
    pub violation_category_digests: Vec<Digest>,
    pub evaluation_revision: Revision,
    pub observed_at: DateTime<Utc>,
}

impl ComplianceDetailProjection {
    pub fn new(
        request: &GetComplianceDetailRequest,
        state: ComplianceState,
        violation_categories: Vec<String>,
        evaluation_revision: Revision,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if violation_categories.len() > MAX_VIOLATION_CATEGORIES {
            return Err(ModelError::TooMany {
                field: "violation categories",
            }
            .into());
        }
        Ok(Self {
            member_account_digest: request.member_account.digest(),
            policy_digest: request.policy.digest(),
            resource_type: request.resource_type.clone(),
            resource_id_digest: request.resource_id.digest().clone(),
            state,
            violation_category_digests: violation_categories
                .into_iter()
                .map(|category| {
                    Digest::from_parts("aws-fms-violation-category/v1", &[("category", category)])
                })
                .collect(),
            evaluation_revision,
            observed_at,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-fms-compliance-detail/v1",
            &[
                ("account", self.member_account_digest.to_string()),
                ("policy", self.policy_digest.to_string()),
                ("resource_type", self.resource_type.digest().to_string()),
                ("resource", self.resource_id_digest.to_string()),
                ("state", format!("{:?}", self.state)),
                (
                    "violations",
                    self.violation_category_digests
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("revision", self.evaluation_revision.get().to_string()),
                ("observed", self.observed_at.to_rfc3339()),
            ],
        )
    }
}

impl fmt::Debug for ComplianceDetailProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComplianceDetailProjection")
            .field("member_account_digest", &self.member_account_digest)
            .field("policy_digest", &self.policy_digest)
            .field("resource_type", &self.resource_type)
            .field("resource_id_digest", &self.resource_id_digest)
            .field("state", &self.state)
            .field(
                "violation_category_digests",
                &self.violation_category_digests,
            )
            .field("evaluation_revision", &self.evaluation_revision)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

impl Serialize for ComplianceDetailProjection {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ComplianceDetailProjection", 8)?;
        state.serialize_field("memberAccountDigest", &self.member_account_digest)?;
        state.serialize_field("policyDigest", &self.policy_digest)?;
        state.serialize_field("resourceType", &self.resource_type)?;
        state.serialize_field("resourceIdDigest", &self.resource_id_digest)?;
        state.serialize_field("state", &self.state)?;
        state.serialize_field("violationCategoryDigests", &self.violation_category_digests)?;
        state.serialize_field("evaluationRevision", &self.evaluation_revision)?;
        state.serialize_field("observedAt", &self.observed_at)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionSummary {
    pub raw_resource_ids_redacted: bool,
    pub raw_policy_identifiers_redacted: bool,
    pub policy_json_redacted: bool,
    pub managed_rule_groups_redacted: bool,
    pub account_pii_redacted: bool,
    pub violation_metadata_redacted: bool,
    pub raw_next_tokens_redacted: bool,
    pub secret_material_redacted: bool,
}

impl Default for RedactionSummary {
    fn default() -> Self {
        Self {
            raw_resource_ids_redacted: true,
            raw_policy_identifiers_redacted: true,
            policy_json_redacted: true,
            managed_rule_groups_redacted: true,
            account_pii_redacted: true,
            violation_metadata_redacted: true,
            raw_next_tokens_redacted: true,
            secret_material_redacted: true,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationEvidence {
    pub pages_observed: u16,
    pub page_token_digests: Vec<Digest>,
    pub complete: bool,
    pub loop_detected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: AwsFirewallManagerOperation,
    pub category: String,
    pub status_code: Option<u16>,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    pub fn from_transport(
        operation: AwsFirewallManagerOperation,
        error: &crate::TransportError,
    ) -> Self {
        let category = match error.failure {
            crate::TransportFailure::BadRequest => "bad_request",
            crate::TransportFailure::Unauthorized => "unauthorized",
            crate::TransportFailure::AccessDenied | crate::TransportFailure::Forbidden => {
                "access_loss"
            }
            crate::TransportFailure::NotFound => "not_found",
            crate::TransportFailure::Throttled | crate::TransportFailure::RateLimited => {
                "throttled"
            }
            crate::TransportFailure::Server | crate::TransportFailure::ServerError => {
                "server_error"
            }
            crate::TransportFailure::Timeout => "timeout",
            crate::TransportFailure::AccessLoss => "access_loss",
            crate::TransportFailure::Partial => "partial",
            crate::TransportFailure::Unknown => "provider_unknown",
            crate::TransportFailure::BlockedEnv => "blocked_env",
            crate::TransportFailure::PaginationLoop => "pagination_loop",
            crate::TransportFailure::Stale => "stale",
        }
        .to_owned();
        Self {
            operation: operation.clone(),
            status_code: error.status_code,
            failure_digest: Digest::from_parts(
                "aws-fms-failure/v1",
                &[
                    ("operation", operation.as_str().to_owned()),
                    ("category", category.clone()),
                    (
                        "status",
                        error
                            .status_code
                            .map_or_else(String::new, |value| value.to_string()),
                    ),
                ],
            ),
            category,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Partial,
    Expired,
    Unknown,
    ProviderUnknown,
    AccessLoss,
    Stale,
    RegistrationRevoked,
}

impl EvidenceState {
    pub const fn is_adoptable(self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub policy_allowlist_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub policy_digest: Option<Digest>,
    pub compliance_digest: Option<Digest>,
    pub violation_category_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub fn initial(
        provider_digest: Digest,
        permission_digest: Digest,
        policy_allowlist_digest: Digest,
        scope_digest: Digest,
        request_digest: Digest,
        cursor_digest: Option<Digest>,
        policy_digest: Option<Digest>,
        compliance_digest: Option<Digest>,
        violation_category_digest: Option<Digest>,
    ) -> Self {
        let mut value = Self {
            plugin_version_digest: Digest::from_text(AWS_FIREWALL_MANAGER_PLUGIN_VERSION),
            provider_digest,
            api_digest: crate::model::api_digest(),
            contract_digest: crate::contract_digest(),
            permission_digest,
            policy_allowlist_digest,
            scope_digest,
            request_digest,
            cursor_digest,
            policy_digest,
            compliance_digest,
            violation_category_digest,
            evidence_digest: Digest::zero(),
        };
        value.evidence_digest = value.compute_digest();
        value
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-fms-evidence-digests/v1",
            &[
                ("plugin", self.plugin_version_digest.to_string()),
                ("provider", self.provider_digest.to_string()),
                ("api", self.api_digest.to_string()),
                ("contract", self.contract_digest.to_string()),
                ("permission", self.permission_digest.to_string()),
                ("policy_allowlist", self.policy_allowlist_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                ("request", self.request_digest.to_string()),
                (
                    "cursor",
                    self.cursor_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                (
                    "policy",
                    self.policy_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                (
                    "compliance",
                    self.compliance_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                (
                    "violation",
                    self.violation_category_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderFlags {
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyPage {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub page_number: u16,
    pub policies: Vec<PolicySummary>,
    pub next_cursor: Option<OpaquePageToken>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub flags: ProviderFlags,
}

impl PolicyPage {
    pub fn new(
        request: &ListPoliciesRequest,
        policies: Vec<PolicySummary>,
        next_cursor: Option<OpaquePageToken>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if policies.len() > request.max_results as usize {
            return Err(AwsFirewallManagerError::InvalidResponse);
        }
        validate_next_cursor(
            request.request_digest(),
            &request.scope_digest,
            request.page_number(),
            next_cursor.as_ref(),
        )?;
        let mut page = Self {
            request_digest: request.request_digest().clone(),
            scope_digest: request.scope_digest.clone(),
            page_number: request.page_number(),
            policies,
            next_cursor,
            response_bytes,
            provenance,
            response_digest: Digest::zero(),
            flags: ProviderFlags::default(),
        };
        page.response_digest = page.compute_digest();
        Ok(page)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-fms-list-policies-page/v1",
            &[
                ("request", self.request_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                ("page", self.page_number.to_string()),
                (
                    "policies",
                    serde_json::to_string(&self.policies).unwrap_or_default(),
                ),
                (
                    "next",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.token_digest().to_string()),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &ListPoliciesRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.request_digest != *request.request_digest()
            || self.scope_digest != request.scope_digest
            || self.page_number != request.page_number()
            || self.policies.len() > request.max_results as usize
            || self.flags != ProviderFlags::default()
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.response_digest != self.compute_digest()
        {
            return Err(AwsFirewallManagerError::TamperedEvidence);
        }
        validate_next_cursor(
            request.request_digest(),
            &request.scope_digest,
            request.page_number(),
            self.next_cursor.as_ref(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyResponse {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub policy: PolicyPosture,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub flags: ProviderFlags,
}

impl PolicyResponse {
    pub fn new(
        request: &GetPolicyRequest,
        policy: PolicyPosture,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        policy.validate_against(&request.policy)?;
        let mut response = Self {
            request_digest: request.request_digest().clone(),
            scope_digest: request.scope_digest.clone(),
            policy,
            response_bytes,
            provenance,
            response_digest: Digest::zero(),
            flags: ProviderFlags::default(),
        };
        response.response_digest = response.compute_digest();
        Ok(response)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-fms-get-policy-response/v1",
            &[
                ("request", self.request_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                (
                    "policy",
                    serde_json::to_string(&self.policy).unwrap_or_default(),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_integrity(&self, request: &GetPolicyRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.request_digest != *request.request_digest()
            || self.scope_digest != request.scope_digest
            || self.flags != ProviderFlags::default()
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.policy.validate_against(&request.policy).is_err()
            || self.response_digest != self.compute_digest()
        {
            return Err(AwsFirewallManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompliancePage {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub policy_digest: Digest,
    pub page_number: u16,
    pub statuses: Vec<ComplianceSummary>,
    pub next_cursor: Option<OpaquePageToken>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub flags: ProviderFlags,
}

impl CompliancePage {
    pub fn new(
        request: &ListComplianceStatusRequest,
        statuses: Vec<ComplianceSummary>,
        next_cursor: Option<OpaquePageToken>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if statuses.len() > request.max_results as usize {
            return Err(AwsFirewallManagerError::InvalidResponse);
        }
        for status in &statuses {
            if status.policy_digest != request.policy.digest() {
                return Err(AwsFirewallManagerError::ProviderDrift);
            }
        }
        validate_next_cursor(
            request.request_digest(),
            &request.scope_digest,
            request.page_number(),
            next_cursor.as_ref(),
        )?;
        let mut page = Self {
            request_digest: request.request_digest().clone(),
            scope_digest: request.scope_digest.clone(),
            policy_digest: request.policy.digest(),
            page_number: request.page_number(),
            statuses,
            next_cursor,
            response_bytes,
            provenance,
            response_digest: Digest::zero(),
            flags: ProviderFlags::default(),
        };
        page.response_digest = page.compute_digest();
        Ok(page)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-fms-list-compliance-status-page/v1",
            &[
                ("request", self.request_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                ("policy", self.policy_digest.to_string()),
                ("page", self.page_number.to_string()),
                (
                    "statuses",
                    serde_json::to_string(&self.statuses).unwrap_or_default(),
                ),
                (
                    "next",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.token_digest().to_string()),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &ListComplianceStatusRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.request_digest != *request.request_digest()
            || self.scope_digest != request.scope_digest
            || self.policy_digest != request.policy.digest()
            || self.page_number != request.page_number()
            || self.statuses.len() > request.max_results as usize
            || self
                .statuses
                .iter()
                .any(|status| status.policy_digest != request.policy.digest())
            || self.flags != ProviderFlags::default()
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.response_digest != self.compute_digest()
        {
            return Err(AwsFirewallManagerError::TamperedEvidence);
        }
        validate_next_cursor(
            request.request_digest(),
            &request.scope_digest,
            request.page_number(),
            self.next_cursor.as_ref(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceDetailResponse {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub detail: ComplianceDetailProjection,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub flags: ProviderFlags,
}

impl ComplianceDetailResponse {
    pub fn new(
        request: &GetComplianceDetailRequest,
        detail: ComplianceDetailProjection,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if detail.policy_digest != request.policy.digest()
            || detail.member_account_digest != request.member_account.digest()
            || detail.resource_type != request.resource_type
            || detail.resource_id_digest != *request.resource_id.digest()
        {
            return Err(AwsFirewallManagerError::ProviderDrift);
        }
        let mut response = Self {
            request_digest: request.request_digest().clone(),
            scope_digest: request.scope_digest.clone(),
            detail,
            response_bytes,
            provenance,
            response_digest: Digest::zero(),
            flags: ProviderFlags::default(),
        };
        response.response_digest = response.compute_digest();
        Ok(response)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-fms-get-compliance-detail-response/v1",
            &[
                ("request", self.request_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                ("detail", self.detail.digest().to_string()),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_integrity(&self, request: &GetComplianceDetailRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.request_digest != *request.request_digest()
            || self.scope_digest != request.scope_digest
            || self.flags != ProviderFlags::default()
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.detail.policy_digest != request.policy.digest()
            || self.detail.member_account_digest != request.member_account.digest()
            || self.detail.resource_type != request.resource_type
            || self.detail.resource_id_digest != *request.resource_id.digest()
            || self.response_digest != self.compute_digest()
        {
            return Err(AwsFirewallManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

fn validate_next_cursor(
    request_digest: &Digest,
    scope_digest: &Digest,
    current_page: u16,
    next_cursor: Option<&OpaquePageToken>,
) -> Result<()> {
    if let Some(cursor) = next_cursor {
        if current_page >= MAX_PAGES {
            return Err(AwsFirewallManagerError::IncompletePagination);
        }
        cursor.validate_against(request_digest, scope_digest, current_page + 1)?;
    }
    Ok(())
}

pub fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
        Err(AwsFirewallManagerError::InvalidResponse)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsFirewallManagerProviderIdentity {
    pub id: String,
    pub version: String,
    pub api_version: String,
    pub api_revision: String,
    pub operations: Vec<AwsFirewallManagerOperation>,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsFirewallManagerProviderIdentity {
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-fms-provider/v1",
            &[
                ("id", self.id.clone()),
                ("version", self.version.clone()),
                ("api", self.api_version.clone()),
                ("revision", self.api_revision.clone()),
                (
                    "operations",
                    self.operations
                        .iter()
                        .map(AwsFirewallManagerOperation::as_str)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub operations: Vec<AwsFirewallManagerOperation>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadDigestRecord {
    pub operation: AwsFirewallManagerOperation,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub response_digest: Digest,
    pub provenance: TransportProvenance,
}

pub fn api_digest() -> Digest {
    Digest::from_text(format!("aws-fms-api/{AWS_FIREWALL_MANAGER_API_VERSION}"))
}

pub fn provider_digest() -> Digest {
    Digest::from_text(format!(
        "{AWS_FIREWALL_MANAGER_PROVIDER_ID}|{AWS_FIREWALL_MANAGER_PROVIDER_VERSION}|{AWS_FIREWALL_MANAGER_API_VERSION}"
    ))
}

pub fn contract_digest_from_version() -> Digest {
    Digest::from_text(AWS_FIREWALL_MANAGER_CONTRACT_VERSION)
}

pub type EvidenceMap = BTreeMap<Digest, Digest>;
