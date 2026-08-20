//! Bounded, redacted data types for the AWS Network Firewall Layer-1 seam.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    MAX_CURSOR_BYTES, MAX_ENDPOINTS, MAX_FIREWALLS, MAX_IDENTIFIER_BYTES, MAX_RULE_GROUP_REFERENCES,
};

pub const MAX_ARN_BYTES: usize = 2_048;
pub const MAX_FIREWALL_NAME_BYTES: usize = 128;
pub const MAX_POLICY_NAME_BYTES: usize = 128;
pub const MAX_PERMISSION_COUNT: usize = 16;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} is not a valid SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a valid opaque cursor")]
    InvalidCursor { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} contains a duplicate")]
    Duplicate { field: &'static str },
    #[error("{field} exceeds its bound")]
    BoundExceeded { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("{field} is unsupported")]
    Unsupported { field: &'static str },
    #[error("secret reference is revoked")]
    SecretRevoked,
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

fn validate_ascii_token(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
    validate_text(value, field, max)?;
    if value
        .bytes()
        .any(|byte| !(byte.is_ascii_alphanumeric() || b"-_.:/+=@".contains(&byte)))
    {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn valid_account(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_region(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-'))
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn valid_prefixed_hex(value: &str, prefix: &str) -> bool {
    value.len() > prefix.len()
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn valid_arn(value: &str) -> bool {
    value.len() <= MAX_ARN_BYTES
        && value.starts_with("arn:aws:")
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
}

fn valid_name(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

macro_rules! opaque_identifier {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::Invalid { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-network-firewall-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub fn validate(&self) -> Result<(), ModelError> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(ModelError::Invalid { field: $field })
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
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&format!("sha256:{}", self.digest().as_str()))
            }
        }
    };
}

opaque_identifier!(AwsAccountId, "account", valid_account);
opaque_identifier!(AwsRegion, "region", valid_region);
opaque_identifier!(VpcId, "vpc", |value: &str| valid_prefixed_hex(
    value, "vpc-"
));
opaque_identifier!(FirewallArn, "firewall-arn", valid_arn);
opaque_identifier!(FirewallName, "firewall-name", |value: &str| valid_name(
    value,
    MAX_FIREWALL_NAME_BYTES
));
opaque_identifier!(FirewallId, "firewall-id", |value: &str| valid_prefixed_hex(
    value,
    "firewall-"
));
opaque_identifier!(FirewallPolicyArn, "firewall-policy-arn", valid_arn);
opaque_identifier!(FirewallPolicyName, "firewall-policy-name", |value: &str| {
    valid_name(value, MAX_POLICY_NAME_BYTES)
});
opaque_identifier!(FirewallPolicyId, "firewall-policy-id", |value: &str| {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
});
opaque_identifier!(SubnetId, "subnet", |value: &str| valid_prefixed_hex(
    value, "subnet-"
));
opaque_identifier!(EndpointId, "endpoint", |value: &str| valid_prefixed_hex(
    value, "vpce-"
));
opaque_identifier!(RuleGroupArn, "rule-group-arn", valid_arn);
opaque_identifier!(MissionId, "mission", |value: &str| {
    validate_ascii_token(value, "mission", MAX_IDENTIFIER_BYTES).is_ok()
});
opaque_identifier!(ProjectId, "project", |value: &str| {
    validate_ascii_token(value, "project", MAX_IDENTIFIER_BYTES).is_ok()
});
opaque_identifier!(WorkProductId, "work-product", |value: &str| {
    validate_ascii_token(value, "work-product", MAX_IDENTIFIER_BYTES).is_ok()
});

/// A lowercase SHA-256 digest used for all Layer-1 fences and projections.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
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

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            })
        }
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            })
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
        self.0.fmt(formatter)
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

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    serde_json::to_vec(value)
        .map(|bytes| Digest::from_bytes(&bytes))
        .map_err(|_| ModelError::Invalid {
            field: "canonical digest input",
        })
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::MustBePositive { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-network-firewall-mission-binding/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-network-firewall-project-binding/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-network-firewall-work-product-binding/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum ReadOperation {
    ListFirewalls,
    DescribeFirewall,
    DescribeFirewallPolicy,
}

impl ReadOperation {
    pub const ALL: [Self; 3] = [
        Self::ListFirewalls,
        Self::DescribeFirewall,
        Self::DescribeFirewallPolicy,
    ];

    pub const fn permission(self) -> &'static str {
        match self {
            Self::ListFirewalls => "network-firewall:ListFirewalls",
            Self::DescribeFirewall => "network-firewall:DescribeFirewall",
            Self::DescribeFirewallPolicy => "network-firewall:DescribeFirewallPolicy",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionScope {
    pub revision: Revision,
    pub permissions: BTreeSet<String>,
    pub permission_digest: Digest,
}

impl PermissionScope {
    pub fn new<I, S>(revision: Revision, permissions: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let permissions = permissions
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        if permissions.is_empty() || permissions.len() > crate::MAX_REQUESTS_PER_READ as usize * 2 {
            return Err(ModelError::BoundExceeded {
                field: "permission scope",
            });
        }
        if permissions.iter().any(|permission| {
            validate_ascii_token(permission, "permission", MAX_IDENTIFIER_BYTES).is_err()
        }) {
            return Err(ModelError::InvalidCharacters {
                field: "permission",
            });
        }
        let permission_digest = Digest::from_parts(
            "aws-network-firewall-permissions/v1",
            &[
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join(","),
                ),
                ("revision", revision.get().to_string()),
            ],
        );
        Ok(Self {
            revision,
            permissions,
            permission_digest,
        })
    }

    pub fn read_only(revision: Revision) -> Result<Self, ModelError> {
        Self::new(
            revision,
            [
                "network-firewall:ListFirewalls",
                "network-firewall:DescribeFirewall",
                "network-firewall:DescribeFirewallPolicy",
                "mission.scope",
            ],
        )
    }

    pub fn permits(&self, operation: ReadOperation) -> bool {
        self.permissions.contains(operation.permission())
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(self.revision, self.permissions.clone())?;
        if rebuilt.permission_digest != self.permission_digest {
            return Err(ModelError::ScopeMismatch {
                field: "permission digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallIdentity {
    pub arn: FirewallArn,
    pub name: FirewallName,
}

impl FirewallIdentity {
    pub fn new(arn: FirewallArn, name: FirewallName) -> Result<Self, ModelError> {
        arn.validate()?;
        name.validate()?;
        Ok(Self { arn, name })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-network-firewall-identity/v1",
            &[
                ("arn", self.arn.as_str().to_owned()),
                ("name", self.name.as_str().to_owned()),
            ],
        )
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.arn == other.arn && self.name == other.name
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallPolicyIdentity {
    pub arn: FirewallPolicyArn,
    pub name: FirewallPolicyName,
}

impl FirewallPolicyIdentity {
    pub fn new(arn: FirewallPolicyArn, name: FirewallPolicyName) -> Result<Self, ModelError> {
        arn.validate()?;
        name.validate()?;
        Ok(Self { arn, name })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-network-firewall-policy-identity/v1",
            &[
                ("arn", self.arn.as_str().to_owned()),
                ("name", self.name.as_str().to_owned()),
            ],
        )
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.arn == other.arn && self.name == other.name
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRevision {
    pub revision: Revision,
    pub update_token_digest: Digest,
}

impl PolicyRevision {
    pub fn new(revision: Revision, update_token: impl AsRef<str>) -> Result<Self, ModelError> {
        let update_token = update_token.as_ref();
        validate_ascii_token(update_token, "update token", 1_024)?;
        Ok(Self {
            revision,
            update_token_digest: Digest::from_parts(
                "aws-network-firewall-update-token/v1",
                &[("token", update_token.to_owned())],
            ),
        })
    }

    pub fn from_digest(
        revision: Revision,
        update_token_digest: Digest,
    ) -> Result<Self, ModelError> {
        update_token_digest.validate()?;
        Ok(Self {
            revision,
            update_token_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-network-firewall-policy-revision/v1",
            &[
                ("revision", self.revision.get().to_string()),
                ("update_token", self.update_token_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallPolicyBinding {
    pub identity: FirewallPolicyIdentity,
    pub expected_revision: PolicyRevision,
    pub policy_digest: Digest,
}

impl FirewallPolicyBinding {
    pub fn new(
        identity: FirewallPolicyIdentity,
        expected_revision: PolicyRevision,
    ) -> Result<Self, ModelError> {
        let policy_digest = Digest::from_parts(
            "aws-network-firewall-policy-fence/v1",
            &[
                ("identity", identity.digest().as_str().to_owned()),
                ("revision", expected_revision.digest().as_str().to_owned()),
            ],
        );
        Ok(Self {
            identity,
            expected_revision,
            policy_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(self.identity.clone(), self.expected_revision.clone())?;
        if rebuilt.policy_digest != self.policy_digest {
            return Err(ModelError::ScopeMismatch {
                field: "policy digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointBinding {
    pub endpoint_id: EndpointId,
    pub subnet_id: SubnetId,
}

impl EndpointBinding {
    pub fn new(endpoint_id: EndpointId, subnet_id: SubnetId) -> Self {
        Self {
            endpoint_id,
            subnet_id,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-network-firewall-endpoint-binding/v1",
            &[
                ("endpoint", self.endpoint_id.as_str().to_owned()),
                ("subnet", self.subnet_id.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsNetworkFirewallScope {
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub vpc_id: VpcId,
    pub firewalls: Vec<FirewallIdentity>,
    pub policies: Vec<FirewallPolicyBinding>,
    pub endpoints: Vec<EndpointBinding>,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub permissions: PermissionScope,
    pub scope_digest: Digest,
    pub policy_digest: Digest,
}

impl AwsNetworkFirewallScope {
    pub fn new(
        account_id: AwsAccountId,
        region: AwsRegion,
        vpc_id: VpcId,
        firewalls: Vec<FirewallIdentity>,
        policies: Vec<FirewallPolicyBinding>,
        endpoints: Vec<EndpointBinding>,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        permissions: PermissionScope,
    ) -> Result<Self, ModelError> {
        if firewalls.is_empty() || firewalls.len() > MAX_FIREWALLS {
            return Err(ModelError::BoundExceeded { field: "firewalls" });
        }
        if policies.is_empty() || policies.len() > MAX_FIREWALLS {
            return Err(ModelError::BoundExceeded { field: "policies" });
        }
        if endpoints.len() > MAX_ENDPOINTS {
            return Err(ModelError::BoundExceeded { field: "endpoints" });
        }
        let firewall_digests = firewalls
            .iter()
            .map(FirewallIdentity::digest)
            .collect::<BTreeSet<_>>();
        if firewall_digests.len() != firewalls.len() {
            return Err(ModelError::Duplicate { field: "firewalls" });
        }
        let policy_digests = policies
            .iter()
            .map(|policy| policy.identity.digest())
            .collect::<BTreeSet<_>>();
        if policy_digests.len() != policies.len() {
            return Err(ModelError::Duplicate { field: "policies" });
        }
        let endpoint_digests = endpoints
            .iter()
            .map(EndpointBinding::digest)
            .collect::<BTreeSet<_>>();
        if endpoint_digests.len() != endpoints.len() {
            return Err(ModelError::Duplicate { field: "endpoints" });
        }
        for policy in &policies {
            policy.validate()?;
        }
        permissions.validate()?;
        let policy_digest = Digest::from_parts(
            "aws-network-firewall-policy-scope/v1",
            &policy_digests
                .iter()
                .enumerate()
                .map(|(index, digest)| ("policy", format!("{index}:{}", digest.as_str())))
                .collect::<Vec<_>>(),
        );
        let mut scope = Self {
            account_id,
            region,
            vpc_id,
            firewalls,
            policies,
            endpoints,
            mission,
            project,
            work_product,
            permissions,
            scope_digest: Digest::zero(),
            policy_digest,
        };
        scope.scope_digest = scope.calculate_scope_digest();
        Ok(scope)
    }

    pub fn calculate_scope_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-network-firewall-scope/v1",
            &[
                ("account", self.account_id.as_str().to_owned()),
                ("region", self.region.as_str().to_owned()),
                ("vpc", self.vpc_id.as_str().to_owned()),
                (
                    "firewalls",
                    self.firewalls
                        .iter()
                        .map(|firewall| firewall.digest().as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "policies",
                    self.policies
                        .iter()
                        .map(|policy| policy.policy_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "endpoints",
                    self.endpoints
                        .iter()
                        .map(|endpoint| endpoint.digest().as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                (
                    "permission",
                    self.permissions.permission_digest.as_str().to_owned(),
                ),
            ],
        )
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permissions.permission_digest
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.account_id.validate()?;
        self.region.validate()?;
        self.vpc_id.validate()?;
        if self.firewalls.is_empty() || self.firewalls.len() > MAX_FIREWALLS {
            return Err(ModelError::BoundExceeded { field: "firewalls" });
        }
        if self.policies.is_empty() || self.policies.len() > MAX_FIREWALLS {
            return Err(ModelError::BoundExceeded { field: "policies" });
        }
        for firewall in &self.firewalls {
            firewall.arn.validate()?;
            firewall.name.validate()?;
        }
        for policy in &self.policies {
            policy.validate()?;
        }
        for endpoint in &self.endpoints {
            endpoint.endpoint_id.validate()?;
            endpoint.subnet_id.validate()?;
        }
        self.permissions.validate()?;
        let expected_policy_digest = Digest::from_parts(
            "aws-network-firewall-policy-scope/v1",
            &self
                .policies
                .iter()
                .enumerate()
                .map(|(index, policy)| {
                    (
                        "policy",
                        format!("{index}:{}", policy.identity.digest().as_str()),
                    )
                })
                .collect::<Vec<_>>(),
        );
        if expected_policy_digest != self.policy_digest
            || self.calculate_scope_digest() != self.scope_digest
        {
            return Err(ModelError::ScopeMismatch {
                field: "scope or policy digest",
            });
        }
        Ok(())
    }

    pub fn policy(&self, identity: &FirewallPolicyIdentity) -> Option<&FirewallPolicyBinding> {
        self.policies
            .iter()
            .find(|policy| policy.identity.matches(identity))
    }

    pub fn firewall(&self, identity: &FirewallIdentity) -> Option<&FirewallIdentity> {
        self.firewalls
            .iter()
            .find(|firewall| firewall.matches(identity))
    }

    pub fn endpoint(&self, endpoint_id: &EndpointId) -> Option<&EndpointBinding> {
        self.endpoints
            .iter()
            .find(|endpoint| &endpoint.endpoint_id == endpoint_id)
    }

    pub fn policy_revision(&self, identity: &FirewallPolicyIdentity) -> Option<&PolicyRevision> {
        self.policy(identity)
            .map(|binding| &binding.expected_revision)
    }
}

/// An opaque page cursor. Its provider value never serializes or appears in Debug.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    digest: Digest,
}

impl OpaqueCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_ascii_token(&value, "opaque cursor", MAX_CURSOR_BYTES)?;
        Ok(Self {
            digest: Digest::from_parts(
                "aws-network-firewall-cursor/v1",
                &[("value", value.clone())],
            ),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OpaqueCursor", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

/// Opaque, revocable, non-serializing SigV4 reference. The handle is zeroized
/// on drop and is never exposed through Serialize, Debug, Display, or evidence.
pub struct SigV4SecretReference {
    handle: Zeroizing<String>,
    scope_digest: Digest,
    generation: Revision,
    reference_digest: Digest,
    revoked: bool,
}

pub type SecretReference = SigV4SecretReference;

impl SigV4SecretReference {
    pub fn sigv4(
        handle: impl Into<String>,
        scope: &AwsNetworkFirewallScope,
        generation: Revision,
    ) -> Result<Self, ModelError> {
        Self::new(handle, scope, generation)
    }

    pub fn new(
        handle: impl Into<String>,
        scope: &AwsNetworkFirewallScope,
        generation: Revision,
    ) -> Result<Self, ModelError> {
        let handle = handle.into();
        validate_ascii_token(&handle, "SigV4 secret reference", MAX_IDENTIFIER_BYTES)?;
        let reference_digest = Digest::from_parts(
            "aws-network-firewall-sigv4-secret-reference/v1",
            &[
                ("handle", handle.clone()),
                ("scope", scope.scope_digest.as_str().to_owned()),
                ("generation", generation.get().to_string()),
            ],
        );
        Ok(Self {
            handle: Zeroizing::new(handle),
            scope_digest: scope.scope_digest.clone(),
            generation,
            reference_digest,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn generation(&self) -> Revision {
        self.generation
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::SecretRevoked)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::SecretRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub(crate) fn validate(&self, scope: &AwsNetworkFirewallScope) -> Result<(), ModelError> {
        self.ensure_active()?;
        if self.scope_digest != scope.scope_digest || self.reference_digest.as_str().is_empty() {
            return Err(ModelError::ScopeMismatch {
                field: "secret reference scope",
            });
        }
        Ok(())
    }
}

impl Clone for SigV4SecretReference {
    fn clone(&self) -> Self {
        Self {
            handle: Zeroizing::new(self.handle.as_str().to_owned()),
            scope_digest: self.scope_digest.clone(),
            generation: self.generation,
            reference_digest: self.reference_digest.clone(),
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SigV4SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.scope_digest == other.scope_digest
            && self.generation == other.generation
            && self.reference_digest == other.reference_digest
            && self.revoked == other.revoked
    }
}

impl Eq for SigV4SecretReference {}

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("generation", &self.generation)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

impl Serialize for SigV4SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SigV4SecretReference", 2)?;
        state.serialize_field("opaque", &true)?;
        state.serialize_field("referenceDigest", &self.reference_digest)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FirewallStatus {
    Ready,
    Degraded,
    Provisioning,
    Deleting,
    Error,
    Unknown,
}

impl FirewallStatus {
    pub fn from_provider(value: &str) -> Self {
        match value {
            "READY" => Self::Ready,
            "DELETING" => Self::Deleting,
            "ERROR" => Self::Error,
            "PROVISIONING" | "PENDING" => Self::Provisioning,
            "DEGRADED" => Self::Degraded,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EndpointStatus {
    Ready,
    NotReady,
    Syncing,
    Error,
    Unknown,
}

impl EndpointStatus {
    pub fn from_provider(value: &str) -> Self {
        match value {
            "READY" | "ATTACHED" | "UP" => Self::Ready,
            "NOT_READY" | "DOWN" | "DETACHED" => Self::NotReady,
            "SYNCING" | "PENDING" => Self::Syncing,
            "ERROR" => Self::Error,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyStatus {
    Active,
    Deleting,
    Error,
    Unknown,
}

impl PolicyStatus {
    pub fn from_provider(value: &str) -> Self {
        match value {
            "ACTIVE" => Self::Active,
            "DELETING" => Self::Deleting,
            "ERROR" => Self::Error,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleGroupKind {
    Stateful,
    Stateless,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FirewallAction {
    Pass,
    Drop,
    ForwardToStateful,
    Alert,
    Custom,
    Unknown,
}

impl FirewallAction {
    pub fn from_provider(value: &str) -> Self {
        match value {
            "aws:pass" => Self::Pass,
            "aws:drop" | "aws:drop_strict" | "aws:drop_established" => Self::Drop,
            "aws:forward_to_sfe" => Self::ForwardToStateful,
            value if value.starts_with("aws:alert") => Self::Alert,
            value if !value.is_empty() => Self::Custom,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionSummary {
    pub actions: Vec<FirewallAction>,
    pub custom_action_count: u16,
    pub unknown_action_count: u16,
}

impl ActionSummary {
    pub fn from_provider<I, S>(values: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut actions = Vec::new();
        let mut custom_action_count = 0;
        let mut unknown_action_count = 0;
        for value in values {
            if actions.len() >= 32 {
                return Err(ModelError::BoundExceeded {
                    field: "policy action summary",
                });
            }
            let action = FirewallAction::from_provider(value.as_ref());
            custom_action_count += u16::from(action == FirewallAction::Custom);
            unknown_action_count += u16::from(action == FirewallAction::Unknown);
            actions.push(action);
        }
        Ok(Self {
            actions,
            custom_action_count,
            unknown_action_count,
        })
    }

    pub fn empty() -> Self {
        Self {
            actions: Vec::new(),
            custom_action_count: 0,
            unknown_action_count: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleGroupReferenceProjection {
    pub reference_digest: Digest,
    pub kind: RuleGroupKind,
    pub priority: Option<u32>,
    pub deep_threat_inspection: bool,
    pub override_action: Option<FirewallAction>,
}

impl RuleGroupReferenceProjection {
    pub fn new(
        arn: RuleGroupArn,
        kind: RuleGroupKind,
        priority: Option<u32>,
        deep_threat_inspection: bool,
        override_action: Option<FirewallAction>,
    ) -> Self {
        Self {
            reference_digest: arn.digest(),
            kind,
            priority,
            deep_threat_inspection,
            override_action,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointAttachmentPosture {
    pub endpoint_digest: Digest,
    pub subnet_digest: Digest,
    pub status: EndpointStatus,
    pub availability_zone_digest: Option<Digest>,
    pub ip_address_type: Option<String>,
}

impl EndpointAttachmentPosture {
    pub fn new(
        endpoint: EndpointId,
        subnet: SubnetId,
        status: EndpointStatus,
        availability_zone: Option<impl AsRef<str>>,
        ip_address_type: Option<impl Into<String>>,
    ) -> Result<Self, ModelError> {
        let ip_address_type = ip_address_type.map(Into::into);
        if let Some(value) = &ip_address_type {
            validate_ascii_token(value, "IP address type", 32)?;
        }
        let availability_zone_digest = availability_zone.map(|value| {
            Digest::from_parts(
                "aws-network-firewall-availability-zone/v1",
                &[("value", value.as_ref().to_owned())],
            )
        });
        Ok(Self {
            endpoint_digest: endpoint.digest(),
            subnet_digest: subnet.digest(),
            status,
            availability_zone_digest,
            ip_address_type,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallPostureProjection {
    pub firewall_digest: Digest,
    pub vpc_digest: Digest,
    pub policy_digest: Digest,
    pub status: FirewallStatus,
    pub endpoint_attachments: Vec<EndpointAttachmentPosture>,
    pub update_token_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyPostureProjection {
    pub policy_digest: Digest,
    pub status: PolicyStatus,
    pub revision: PolicyRevision,
    pub stateful_default_actions: ActionSummary,
    pub stateless_default_actions: ActionSummary,
    pub stateful_rule_group_references: Vec<RuleGroupReferenceProjection>,
    pub stateless_rule_group_references: Vec<RuleGroupReferenceProjection>,
    pub tls_inspection_configuration_digest: Option<Digest>,
    pub number_of_associations: u32,
}

impl PolicyPostureProjection {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.stateful_rule_group_references.len() + self.stateless_rule_group_references.len()
            > MAX_RULE_GROUP_REFERENCES
        {
            return Err(ModelError::BoundExceeded {
                field: "rule group references",
            });
        }
        self.revision.update_token_digest.validate()
    }
}

/// Redacted policy field helper for callers that need a stable map of posture facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyActionCounts {
    pub stateful_actions: BTreeMap<String, u16>,
    pub stateless_actions: BTreeMap<String, u16>,
}

impl PolicyActionCounts {
    pub fn from_summaries(stateful: &ActionSummary, stateless: &ActionSummary) -> Self {
        fn counts(summary: &ActionSummary) -> BTreeMap<String, u16> {
            let mut result = BTreeMap::new();
            for action in &summary.actions {
                let key = format!("{action:?}");
                *result.entry(key).or_insert(0) += 1;
            }
            result
        }
        Self {
            stateful_actions: counts(stateful),
            stateless_actions: counts(stateless),
        }
    }
}

impl Drop for SigV4SecretReference {
    fn drop(&mut self) {
        self.handle.zeroize();
    }
}
