//! Typed scope, digest, redaction, and bounded evidence inputs for AWS WAF.
//!
//! Raw WAF rule statements, IP sets, request bodies, sampled requests, logs,
//! provider payloads, and secret material are intentionally not represented by
//! the public Layer-1 evidence types.

use std::{collections::BTreeSet, fmt};

use serde::{Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    MAX_ARN_BYTES, MAX_CURSOR_BYTES, MAX_IDENTIFIER_BYTES, MAX_RESOURCES, MAX_RULE_SUMMARIES,
    MAX_WEB_ACLS,
};

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
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("{field} does not match the required revision fence")]
    RevisionMismatch { field: &'static str },
    #[error("{field} is missing a required permission")]
    MissingPermission { field: &'static str },
    #[error("registration or secret reference is already revoked")]
    AlreadyRevoked,
    #[error("registration or secret reference is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
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
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if value.bytes().any(|byte| {
        !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@'))
    }) {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_arn(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_text(value, field, MAX_ARN_BYTES)?;
    if !value.starts_with("arn:") {
        return Err(ModelError::Invalid { field });
    }
    Ok(())
}

fn validate_revision(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_part(concat!("aws-waf-", $field, "/v1"), &self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &self.digest())
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

bounded_identifier!(MissionId, "mission-id");
bounded_identifier!(ProjectId, "project-id");
bounded_identifier!(WorkProductId, "work-product-id");
bounded_identifier!(WebAclId, "web-acl-id");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AccountId(String);

pub type AwsAccountId = AccountId;

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

    pub fn digest(&self) -> Digest {
        Digest::from_part("aws-waf-account/v1", &self.0)
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountId")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "AWS region")?;
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

    pub fn digest(&self) -> Digest {
        Digest::from_part("aws-waf-region/v1", &self.0)
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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_revision(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn next(self) -> Result<Self, ModelError> {
        Self::new(self.0.checked_add(1).ok_or(ModelError::RevisionOverflow)?)
    }
}

pub type RevisionId = Revision;

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

    pub fn from_part(domain: &str, part: &str) -> Self {
        Self::from_parts(domain, &[part.to_owned()])
    }

    pub fn from_parts(domain: &str, parts: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_len_prefixed(&mut bytes, domain);
        for part in parts {
            append_len_prefixed(&mut bytes, part);
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

fn append_len_prefixed(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
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

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).expect("bounded Layer-1 value serializes"))
}

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
        digest_serializable(self)
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
        digest_serializable(self)
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
        digest_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum WafOperation {
    ListWebAcls,
    GetWebAcl,
    ListResourcesForWebAcl,
}

impl WafOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListWebAcls => "ListWebACLs",
            Self::GetWebAcl => "GetWebACL",
            Self::ListResourcesForWebAcl => "ListResourcesForWebACL",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WafScopeKind {
    CloudFront,
    Regional,
}

pub type AwsWafScopeKind = WafScopeKind;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    Allow,
    Block,
    Count,
    Captcha,
    Challenge,
    Override,
    Other,
}

impl ActionClass {
    pub const fn is_protective(self) -> bool {
        matches!(self, Self::Block | Self::Captcha | Self::Challenge)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleActionSummary {
    pub action_class: ActionClass,
    pub rule_count: u16,
}

impl RuleActionSummary {
    pub fn new(action_class: ActionClass, rule_count: u16) -> Result<Self, ModelError> {
        if rule_count == 0 {
            return Err(ModelError::MustBePositive {
                field: "rule count",
            });
        }
        Ok(Self {
            action_class,
            rule_count,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentBinding {
    pub digest: Digest,
    pub revision: Revision,
}

impl ConsentBinding {
    pub fn new(digest: Digest, revision: Revision) -> Result<Self, ModelError> {
        Ok(Self { digest, revision })
    }

    pub fn from_text(value: impl AsRef<[u8]>, revision: Revision) -> Self {
        Self {
            digest: Digest::from_text(value),
            revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionScope {
    pub account: AccountId,
    pub revision: Revision,
    pub operations: BTreeSet<WafOperation>,
    pub consent_digest: Digest,
    pub consent_revision: Revision,
    pub permission_digest: Digest,
}

impl PermissionScope {
    pub fn new(
        account: AccountId,
        revision: Revision,
        operations: BTreeSet<WafOperation>,
        consent: ConsentBinding,
    ) -> Result<Self, ModelError> {
        if operations.len() != 3 {
            return Err(ModelError::MissingPermission {
                field: "all three read-only WAF operations",
            });
        }
        for operation in [
            WafOperation::ListWebAcls,
            WafOperation::GetWebAcl,
            WafOperation::ListResourcesForWebAcl,
        ] {
            if !operations.contains(&operation) {
                return Err(ModelError::MissingPermission {
                    field: operation.as_str(),
                });
            }
        }
        let permission_digest = Digest::from_parts(
            "aws-waf-permission/v1",
            &[
                account.digest().to_string(),
                revision.get().to_string(),
                operations
                    .iter()
                    .map(|operation| operation.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                consent.digest.to_string(),
                consent.revision.get().to_string(),
            ],
        );
        Ok(Self {
            account,
            revision,
            operations,
            consent_digest: consent.digest,
            consent_revision: consent.revision,
            permission_digest,
        })
    }

    pub fn read_only(account: AccountId, revision: Revision, consent: ConsentBinding) -> Self {
        let operations = [
            WafOperation::ListWebAcls,
            WafOperation::GetWebAcl,
            WafOperation::ListResourcesForWebAcl,
        ]
        .into_iter()
        .collect();
        Self::new(account, revision, operations, consent).expect("complete WAF read permission")
    }

    pub fn all(account: AccountId, revision: Revision, consent: ConsentBinding) -> Self {
        Self::read_only(account, revision, consent)
    }

    pub fn digest(&self) -> Digest {
        self.permission_digest.clone()
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-waf-permission/v1",
            &[
                self.account.digest().to_string(),
                self.revision.get().to_string(),
                self.operations
                    .iter()
                    .map(|operation| operation.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                self.consent_digest.to_string(),
                self.consent_revision.get().to_string(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.permission_digest != self.recomputed_digest() {
            return Err(ModelError::ScopeMismatch {
                field: "permission digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WebAclArn(String);

pub type AwsWebAclArn = WebAclArn;

impl WebAclArn {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_arn(&value, "web ACL ARN")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_part("aws-waf-web-acl-arn/v1", &self.0)
    }
}

impl fmt::Debug for WebAclArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAclArn")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for WebAclArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for WebAclArn {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.digest().as_str())
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceArn(String);

impl ResourceArn {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_arn(&value, "resource ARN")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_part("aws-waf-resource-arn/v1", &self.0)
    }
}

impl fmt::Debug for ResourceArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceArn")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for ResourceArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for ResourceArn {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.digest().as_str())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct WebAclReference {
    id: WebAclId,
    arn: WebAclArn,
    revision: Revision,
    expected_lock_token_digest: Option<Digest>,
}

pub type WebAclIdentity = WebAclReference;

impl WebAclReference {
    pub fn new(
        id: WebAclId,
        arn: WebAclArn,
        revision: Revision,
        expected_lock_token_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if let Some(digest) = &expected_lock_token_digest {
            Digest::parse(digest.as_str().to_owned())?;
        }
        Ok(Self {
            id,
            arn,
            revision,
            expected_lock_token_digest,
        })
    }

    pub fn without_lock_fence(id: WebAclId, arn: WebAclArn, revision: Revision) -> Self {
        Self {
            id,
            arn,
            revision,
            expected_lock_token_digest: None,
        }
    }

    pub fn id(&self) -> &WebAclId {
        &self.id
    }

    pub fn arn(&self) -> &WebAclArn {
        &self.arn
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn expected_lock_token_digest(&self) -> Option<&Digest> {
        self.expected_lock_token_digest.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-waf-web-acl-reference/v1",
            &[
                self.id.digest().to_string(),
                self.arn.digest().to_string(),
                self.revision.get().to_string(),
                self.expected_lock_token_digest
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string),
            ],
        )
    }
}

impl fmt::Debug for WebAclReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAclReference")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl Serialize for WebAclReference {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Redacted<'a> {
            id_digest: Digest,
            arn_digest: Digest,
            revision: Revision,
            expected_lock_token_digest: Option<&'a Digest>,
        }
        Redacted {
            id_digest: self.id.digest(),
            arn_digest: self.arn.digest(),
            revision: self.revision,
            expected_lock_token_digest: self.expected_lock_token_digest.as_ref(),
        }
        .serialize(serializer)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ResourceReference {
    arn: ResourceArn,
    revision: Revision,
}

pub type ResourceIdentity = ResourceReference;

impl ResourceReference {
    pub fn new(arn: ResourceArn, revision: Revision) -> Self {
        Self { arn, revision }
    }

    pub fn arn(&self) -> &ResourceArn {
        &self.arn
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-waf-resource-reference/v1",
            &[
                self.arn.digest().to_string(),
                self.revision.get().to_string(),
            ],
        )
    }
}

impl From<ResourceArn> for ResourceReference {
    fn from(arn: ResourceArn) -> Self {
        Self {
            arn,
            revision: Revision(1),
        }
    }
}

impl fmt::Debug for ResourceReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceReference")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl Serialize for ResourceReference {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Redacted {
            arn_digest: Digest,
            revision: Revision,
        }
        Redacted {
            arn_digest: self.arn.digest(),
            revision: self.revision,
        }
        .serialize(serializer)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsWafPostureScope {
    pub account: AccountId,
    pub region: AwsRegion,
    pub scope_kind: WafScopeKind,
    pub web_acl_allowlist: Vec<WebAclReference>,
    pub resource_allowlist: Vec<ResourceReference>,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub permission: PermissionScope,
    pub scope_revision: Revision,
    pub scope_digest: Digest,
}

impl AwsWafPostureScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AccountId,
        region: AwsRegion,
        scope_kind: WafScopeKind,
        web_acl_allowlist: Vec<WebAclReference>,
        resource_allowlist: Vec<ResourceReference>,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        permission: PermissionScope,
    ) -> Result<Self, ModelError> {
        Self::with_revision(
            account,
            region,
            scope_kind,
            web_acl_allowlist,
            resource_allowlist,
            mission,
            project,
            work_product,
            permission,
            Revision::new(1)?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_revision(
        account: AccountId,
        region: AwsRegion,
        scope_kind: WafScopeKind,
        mut web_acl_allowlist: Vec<WebAclReference>,
        mut resource_allowlist: Vec<ResourceReference>,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        permission: PermissionScope,
        scope_revision: Revision,
    ) -> Result<Self, ModelError> {
        if web_acl_allowlist.is_empty() {
            return Err(ModelError::Empty {
                field: "web ACL allowlist",
            });
        }
        if web_acl_allowlist.len() > MAX_WEB_ACLS {
            return Err(ModelError::TooMany {
                field: "web ACL allowlist",
            });
        }
        if resource_allowlist.is_empty() {
            return Err(ModelError::Empty {
                field: "resource allowlist",
            });
        }
        if resource_allowlist.len() > MAX_RESOURCES {
            return Err(ModelError::TooMany {
                field: "resource allowlist",
            });
        }
        web_acl_allowlist.sort_by_key(WebAclReference::digest);
        resource_allowlist.sort_by_key(ResourceReference::digest);
        if web_acl_allowlist
            .windows(2)
            .any(|window| window[0].digest() == window[1].digest())
        {
            return Err(ModelError::Duplicate {
                field: "web ACL allowlist",
            });
        }
        if resource_allowlist
            .windows(2)
            .any(|window| window[0].digest() == window[1].digest())
        {
            return Err(ModelError::Duplicate {
                field: "resource allowlist",
            });
        }
        if permission.account != account {
            return Err(ModelError::ScopeMismatch {
                field: "permission account",
            });
        }
        permission.validate()?;
        let scope_digest = Self::compute_digest(
            &account,
            &region,
            scope_kind,
            &web_acl_allowlist,
            &resource_allowlist,
            &mission,
            &project,
            &work_product,
            &permission,
            scope_revision,
        );
        Ok(Self {
            account,
            region,
            scope_kind,
            web_acl_allowlist,
            resource_allowlist,
            mission,
            project,
            work_product,
            permission,
            scope_revision,
            scope_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_digest(
        account: &AccountId,
        region: &AwsRegion,
        scope_kind: WafScopeKind,
        web_acl_allowlist: &[WebAclReference],
        resource_allowlist: &[ResourceReference],
        mission: &MissionBinding,
        project: &ProjectBinding,
        work_product: &WorkProductBinding,
        permission: &PermissionScope,
        scope_revision: Revision,
    ) -> Digest {
        Digest::from_parts(
            "aws-waf-posture-scope/v1",
            &[
                account.digest().to_string(),
                region.digest().to_string(),
                format!("{scope_kind:?}"),
                web_acl_allowlist
                    .iter()
                    .map(WebAclReference::digest)
                    .map(|digest| digest.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                resource_allowlist
                    .iter()
                    .map(ResourceReference::digest)
                    .map(|digest| digest.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                mission.digest().to_string(),
                project.digest().to_string(),
                work_product.digest().to_string(),
                permission.digest().to_string(),
                scope_revision.get().to_string(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.permission.account != self.account
            || self.permission.permission_digest != self.permission.recomputed_digest()
            || self.scope_digest
                != Self::compute_digest(
                    &self.account,
                    &self.region,
                    self.scope_kind,
                    &self.web_acl_allowlist,
                    &self.resource_allowlist,
                    &self.mission,
                    &self.project,
                    &self.work_product,
                    &self.permission,
                    self.scope_revision,
                )
        {
            return Err(ModelError::ScopeMismatch {
                field: "scope digest",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission.permission_digest
    }

    pub fn web_acl(&self) -> &WebAclReference {
        &self.web_acl_allowlist[0]
    }

    pub fn is_web_acl_allowed(&self, identity: &WebAclReference) -> bool {
        self.web_acl_allowlist
            .iter()
            .any(|allowed| allowed.id == identity.id && allowed.arn == identity.arn)
    }

    pub fn resource(&self) -> &ResourceReference {
        &self.resource_allowlist[0]
    }

    pub fn resource_for_arn(&self, arn: &ResourceArn) -> Option<&ResourceReference> {
        self.resource_allowlist
            .iter()
            .find(|resource| resource.arn == *arn)
    }
}

pub type AwsWafScope = AwsWafPostureScope;
pub type WafPostureScope = AwsWafPostureScope;

/// A host-owned opaque handle for SigV4 credentials. The handle is never
/// serialised or printed; Layer 1 only binds its digest and revision.
pub struct SecretReference {
    opaque_handle: Zeroizing<String>,
    region: AwsRegion,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

pub type SigV4SecretReference = SecretReference;

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            opaque_handle: Zeroizing::new(self.opaque_handle.as_str().to_owned()),
            region: self.region.clone(),
            scope_digest: self.scope_digest.clone(),
            revision: self.revision,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.digest() == other.digest() && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("opaque_handle", &"<redacted>")
            .field("region", &self.region)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        opaque_handle: impl Into<String>,
        region: AwsRegion,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let opaque_handle = opaque_handle.into();
        validate_text(
            &opaque_handle,
            "opaque secret reference",
            MAX_IDENTIFIER_BYTES,
        )?;
        Ok(Self {
            opaque_handle: Zeroizing::new(opaque_handle),
            region,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        region: AwsRegion,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::new(opaque_handle, region, scope_digest, revision)
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-waf-secret-reference/v1",
            &[
                self.opaque_handle.as_str().to_owned(),
                self.region.digest().to_string(),
                self.scope_digest.to_string(),
                self.revision.get().to_string(),
            ],
        )
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if !self.revoked {
            Err(ModelError::NotRevoked)
        } else {
            self.revoked = false;
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

pub type ProviderProvenance = TransportProvenance;

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
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
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    NoMatchingAcl,
    Partial,
    AccessLoss,
    Throttled,
    Timeout,
    ProviderUnknown,
    ScopeDrift,
    RevisionDrift,
    RegistrationRevoked,
}

pub type WafEvidenceState = EvidenceState;

impl EvidenceState {
    pub const fn review_eligible(self) -> bool {
        matches!(self, Self::Complete | Self::NoMatchingAcl)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WafDecisionState {
    Protected,
    NotProtected,
    InsufficientData,
    AccessLoss,
    Throttled,
    Timeout,
    ProviderUnknown,
    RevisionDrift,
    ScopeDrift,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WafDeploymentDecision {
    Block,
    Review,
    InsufficientEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaquePageToken {
    pub token_digest: Digest,
    pub scope_digest: Digest,
    pub operation: WafOperation,
    pub page_number: u16,
}

impl OpaquePageToken {
    pub fn new(
        raw_token: impl AsRef<str>,
        scope: &AwsWafPostureScope,
        operation: WafOperation,
        page_number: u16,
    ) -> Result<Self, ModelError> {
        let raw_token = raw_token.as_ref();
        validate_text(raw_token, "provider next token", MAX_CURSOR_BYTES)?;
        if page_number == 0 {
            return Err(ModelError::MustBePositive {
                field: "page number",
            });
        }
        Ok(Self {
            token_digest: Digest::from_parts(
                "aws-waf-opaque-page-token/v1",
                &[
                    raw_token.to_owned(),
                    scope.digest().to_string(),
                    operation.as_str().to_owned(),
                    page_number.to_string(),
                ],
            ),
            scope_digest: scope.digest(),
            operation,
            page_number,
        })
    }

    pub fn from_digest(
        token_digest: Digest,
        scope: &AwsWafPostureScope,
        operation: WafOperation,
        page_number: u16,
    ) -> Result<Self, ModelError> {
        if page_number == 0 {
            return Err(ModelError::MustBePositive {
                field: "page number",
            });
        }
        Ok(Self {
            token_digest,
            scope_digest: scope.digest(),
            operation,
            page_number,
        })
    }

    pub fn validate_for(
        &self,
        scope: &AwsWafPostureScope,
        operation: WafOperation,
        expected_page: u16,
    ) -> Result<(), ModelError> {
        self.validate_for_digest(&scope.digest(), operation, expected_page)
    }

    pub fn validate_for_digest(
        &self,
        scope_digest: &Digest,
        operation: WafOperation,
        expected_page: u16,
    ) -> Result<(), ModelError> {
        if &self.scope_digest != scope_digest
            || self.operation != operation
            || self.page_number != expected_page
        {
            return Err(ModelError::ScopeMismatch {
                field: "opaque page token",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebAclListItem {
    pub identity: WebAclReference,
}

impl WebAclListItem {
    pub fn new(identity: WebAclReference) -> Self {
        Self { identity }
    }
}

impl Serialize for WebAclListItem {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Redacted {
            web_acl_digest: Digest,
        }
        Redacted {
            web_acl_digest: self.identity.digest(),
        }
        .serialize(serializer)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct WebAclDetails {
    pub identity: WebAclReference,
    pub default_action: ActionClass,
    pub rules: Vec<RuleActionSummary>,
    lock_token: Zeroizing<String>,
    pub revision: Revision,
}

impl fmt::Debug for WebAclDetails {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAclDetails")
            .field("identity", &self.identity)
            .field("default_action", &self.default_action)
            .field("rules", &self.rules)
            .field("lock_token_digest", &self.lock_token_digest())
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl WebAclDetails {
    pub fn new(
        identity: WebAclReference,
        default_action: ActionClass,
        rules: Vec<RuleActionSummary>,
        lock_token: impl Into<String>,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        if rules.len() > MAX_RULE_SUMMARIES {
            return Err(ModelError::TooMany {
                field: "WAF rule summaries",
            });
        }
        let lock_token = lock_token.into();
        validate_text(&lock_token, "WAF lock token", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            identity,
            default_action,
            rules,
            lock_token: Zeroizing::new(lock_token),
            revision,
        })
    }

    pub fn lock_token_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-waf-lock-token/v1",
            &[self.lock_token.as_str().to_owned()],
        )
    }

    pub fn revision_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-waf-acl-revision/v1",
            &[
                self.identity.digest().to_string(),
                self.revision.get().to_string(),
                self.lock_token_digest().to_string(),
            ],
        )
    }

    pub fn projection_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-waf-acl-projection/v1",
            &[
                self.identity.digest().to_string(),
                format!("{:?}", self.default_action),
                self.rules
                    .iter()
                    .map(|rule| format!("{:?}:{}", rule.action_class, rule.rule_count))
                    .collect::<Vec<_>>()
                    .join(","),
                self.lock_token_digest().to_string(),
                self.revision.get().to_string(),
            ],
        )
    }
}

impl Serialize for WebAclDetails {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Redacted<'a> {
            web_acl_digest: Digest,
            default_action: ActionClass,
            rules: &'a [RuleActionSummary],
            lock_token_digest: Digest,
            revision: Revision,
        }
        Redacted {
            web_acl_digest: self.identity.digest(),
            default_action: self.default_action,
            rules: &self.rules,
            lock_token_digest: self.lock_token_digest(),
            revision: self.revision,
        }
        .serialize(serializer)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceAssociation {
    pub resource: ResourceReference,
    pub association_revision: Revision,
}

impl ResourceAssociation {
    pub const fn new(resource: ResourceReference, association_revision: Revision) -> Self {
        Self {
            resource,
            association_revision,
        }
    }

    pub fn digest(&self, web_acl: &WebAclReference) -> Digest {
        Digest::from_parts(
            "aws-waf-association/v1",
            &[
                web_acl.digest().to_string(),
                self.resource.digest().to_string(),
                self.association_revision.get().to_string(),
            ],
        )
    }
}

impl Serialize for ResourceAssociation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Redacted {
            resource_digest: Digest,
            revision: Revision,
            association_revision: Revision,
        }
        Redacted {
            resource_digest: self.resource.digest(),
            revision: self.resource.revision(),
            association_revision: self.association_revision,
        }
        .serialize(serializer)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleActionEvidence {
    pub action_class: ActionClass,
    pub rule_count: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAclPostureProjection {
    pub web_acl_digest: Digest,
    pub default_action: ActionClass,
    pub rules: Vec<RuleActionEvidence>,
    pub lock_token_digest: Digest,
    pub revision_digest: Digest,
    pub associated_resource_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssociationProjection {
    pub web_acl_digest: Digest,
    pub resource_digest: Digest,
    pub association_identity_digest: Digest,
    pub resource_revision_digest: Digest,
    pub associated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionSummary {
    pub rule_statements_redacted: bool,
    pub ip_sets_redacted: bool,
    pub request_bodies_redacted: bool,
    pub sampled_requests_redacted: bool,
    pub raw_provider_payload_redacted: bool,
    pub raw_next_token_redacted: bool,
    pub secret_material_redacted: bool,
    pub unbounded_logs_redacted: bool,
}

impl RedactionSummary {
    pub const fn layer_one() -> Self {
        Self {
            rule_statements_redacted: true,
            ip_sets_redacted: true,
            request_bodies_redacted: true,
            sampled_requests_redacted: true,
            raw_provider_payload_redacted: true,
            raw_next_token_redacted: true,
            secret_material_redacted: true,
            unbounded_logs_redacted: true,
        }
    }
}
