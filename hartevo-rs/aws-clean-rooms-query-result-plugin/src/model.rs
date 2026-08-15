use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsCleanRoomsQueryResultError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, MAX_METADATA_TEXT_BYTES, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_RESPONSE_BYTES,
};

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AwsCleanRoomsQueryResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsCleanRoomsQueryResultError::InvalidDigest)
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

fn valid_text(value: &str, max_bytes: usize, allow_internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_reference(value: &str, max_bytes: usize) -> bool {
    valid_identifier(value, max_bytes) || valid_arn(value)
}

fn valid_arn(value: &str) -> bool {
    valid_text(value, 2_048, false) && value.starts_with("arn:")
}

fn valid_sensitive_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_METADATA_TEXT_BYTES
        && !value.bytes().any(|byte| byte == 0)
}

macro_rules! redacted_text {
    ($name:ident, $field:literal, $domain:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsCleanRoomsQueryResultError::InvalidIdentifier { field: $field })
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

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsCleanRoomsQueryResultError::InvalidIdentifier { field: $field })
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

redacted_text!(
    AwsAccountId,
    "account",
    "aws-clean-rooms-account/v1",
    |value: &str| value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
);
redacted_text!(
    AwsRegion,
    "region",
    "aws-clean-rooms-region/v1",
    |value: &str| valid_identifier(value, 64)
);
redacted_text!(
    CollaborationId,
    "collaboration",
    "aws-clean-rooms-collaboration/v1",
    |value: &str| valid_reference(value, MAX_IDENTIFIER_BYTES)
);
redacted_text!(
    MembershipId,
    "membership",
    "aws-clean-rooms-membership/v1",
    |value: &str| valid_reference(value, MAX_IDENTIFIER_BYTES)
);
redacted_text!(
    AnalysisTemplateArn,
    "analysis-template",
    "aws-clean-rooms-analysis-template/v1",
    |value: &str| valid_reference(value, MAX_IDENTIFIER_BYTES)
);
redacted_text!(
    ProtectedQueryId,
    "protected-query",
    "aws-clean-rooms-protected-query/v1",
    |value: &str| valid_reference(value, MAX_IDENTIFIER_BYTES)
);
redacted_text!(
    PrivacyBudgetId,
    "privacy-budget",
    "aws-clean-rooms-privacy-budget/v1",
    |value: &str| valid_reference(value, MAX_IDENTIFIER_BYTES)
);

#[derive(Clone, Eq, PartialEq)]
pub struct CollaborationIdentity {
    id: CollaborationId,
    arn_digest: Option<Digest>,
}

impl CollaborationIdentity {
    pub fn new(id: CollaborationId) -> Result<Self> {
        Self::with_optional_arn(id, None::<String>)
    }

    pub fn with_arn(id: CollaborationId, arn: impl Into<String>) -> Result<Self> {
        Self::with_optional_arn(id, Some(arn.into()))
    }

    fn with_optional_arn(id: CollaborationId, arn: Option<String>) -> Result<Self> {
        let arn_digest = arn
            .map(|value| {
                if valid_arn(&value) {
                    Ok(Digest::from_parts(
                        "aws-clean-rooms-collaboration-arn/v1",
                        &[("arn", value)],
                    ))
                } else {
                    Err(AwsCleanRoomsQueryResultError::InvalidIdentifier {
                        field: "collaboration-arn",
                    })
                }
            })
            .transpose()?;
        Ok(Self { id, arn_digest })
    }

    pub fn id(&self) -> &CollaborationId {
        &self.id
    }

    pub fn arn_digest(&self) -> Option<&Digest> {
        self.arn_digest.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-clean-rooms-collaboration-identity/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                (
                    "arn",
                    self.arn_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.arn_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

impl fmt::Debug for CollaborationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollaborationIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MembershipIdentity {
    id: MembershipId,
    arn_digest: Option<Digest>,
}

impl MembershipIdentity {
    pub fn new(id: MembershipId) -> Result<Self> {
        Self::with_optional_arn(id, None::<String>)
    }

    pub fn with_arn(id: MembershipId, arn: impl Into<String>) -> Result<Self> {
        Self::with_optional_arn(id, Some(arn.into()))
    }

    fn with_optional_arn(id: MembershipId, arn: Option<String>) -> Result<Self> {
        let arn_digest = arn
            .map(|value| {
                if valid_arn(&value) {
                    Ok(Digest::from_parts(
                        "aws-clean-rooms-membership-arn/v1",
                        &[("arn", value)],
                    ))
                } else {
                    Err(AwsCleanRoomsQueryResultError::InvalidIdentifier {
                        field: "membership-arn",
                    })
                }
            })
            .transpose()?;
        Ok(Self { id, arn_digest })
    }

    pub fn id(&self) -> &MembershipId {
        &self.id
    }

    pub fn arn_digest(&self) -> Option<&Digest> {
        self.arn_digest.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-clean-rooms-membership-identity/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                (
                    "arn",
                    self.arn_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.arn_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

impl fmt::Debug for MembershipIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MembershipIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AnalysisTemplateIdentity {
    arn: AnalysisTemplateArn,
    revision_digest: Option<Digest>,
}

impl AnalysisTemplateIdentity {
    pub fn new(arn: AnalysisTemplateArn) -> Result<Self> {
        Self::with_optional_revision(arn, None::<String>)
    }

    pub fn with_revision(arn: AnalysisTemplateArn, revision: impl AsRef<str>) -> Result<Self> {
        Self::with_optional_revision(arn, Some(revision.as_ref().to_owned()))
    }

    fn with_optional_revision(arn: AnalysisTemplateArn, revision: Option<String>) -> Result<Self> {
        let revision_digest = revision
            .map(|value| {
                if valid_text(&value, MAX_IDENTIFIER_BYTES, true) {
                    Ok(Digest::from_parts(
                        "aws-clean-rooms-analysis-template-revision/v1",
                        &[("revision", value)],
                    ))
                } else {
                    Err(AwsCleanRoomsQueryResultError::InvalidIdentifier {
                        field: "analysis-template-revision",
                    })
                }
            })
            .transpose()?;
        Ok(Self {
            arn,
            revision_digest,
        })
    }

    pub fn arn(&self) -> &AnalysisTemplateArn {
        &self.arn
    }

    pub fn revision_digest(&self) -> Option<&Digest> {
        self.revision_digest.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-clean-rooms-analysis-template-identity/v1",
            &[
                ("arn", self.arn.digest().as_str().to_owned()),
                (
                    "revision",
                    self.revision_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.arn.validate()?;
        self.revision_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

impl fmt::Debug for AnalysisTemplateIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnalysisTemplateIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedQueryIdentity {
    id: ProtectedQueryId,
    arn_digest: Option<Digest>,
}

impl ProtectedQueryIdentity {
    pub fn new(id: ProtectedQueryId) -> Result<Self> {
        Self::with_optional_arn(id, None::<String>)
    }

    pub fn with_arn(id: ProtectedQueryId, arn: impl Into<String>) -> Result<Self> {
        Self::with_optional_arn(id, Some(arn.into()))
    }

    fn with_optional_arn(id: ProtectedQueryId, arn: Option<String>) -> Result<Self> {
        let arn_digest = arn
            .map(|value| {
                if valid_arn(&value) {
                    Ok(Digest::from_parts(
                        "aws-clean-rooms-protected-query-arn/v1",
                        &[("arn", value)],
                    ))
                } else {
                    Err(AwsCleanRoomsQueryResultError::InvalidIdentifier {
                        field: "protected-query-arn",
                    })
                }
            })
            .transpose()?;
        Ok(Self { id, arn_digest })
    }

    pub fn id(&self) -> &ProtectedQueryId {
        &self.id
    }

    pub fn arn_digest(&self) -> Option<&Digest> {
        self.arn_digest.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-clean-rooms-protected-query-identity/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                (
                    "arn",
                    self.arn_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.arn_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

impl fmt::Debug for ProtectedQueryIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedQueryIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PrivacyBudgetIdentity {
    id: PrivacyBudgetId,
    revision_digest: Option<Digest>,
}

impl PrivacyBudgetIdentity {
    pub fn new(id: PrivacyBudgetId) -> Result<Self> {
        Self::with_optional_revision(id, None::<String>)
    }

    pub fn with_revision(id: PrivacyBudgetId, revision: impl AsRef<str>) -> Result<Self> {
        Self::with_optional_revision(id, Some(revision.as_ref().to_owned()))
    }

    fn with_optional_revision(id: PrivacyBudgetId, revision: Option<String>) -> Result<Self> {
        let revision_digest = revision
            .map(|value| {
                if valid_text(&value, MAX_IDENTIFIER_BYTES, true) {
                    Ok(Digest::from_parts(
                        "aws-clean-rooms-privacy-budget-revision/v1",
                        &[("revision", value)],
                    ))
                } else {
                    Err(AwsCleanRoomsQueryResultError::InvalidIdentifier {
                        field: "privacy-budget-revision",
                    })
                }
            })
            .transpose()?;
        Ok(Self {
            id,
            revision_digest,
        })
    }

    pub fn id(&self) -> &PrivacyBudgetId {
        &self.id
    }

    pub fn revision_digest(&self) -> Option<&Digest> {
        self.revision_digest.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-clean-rooms-privacy-budget-identity/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                (
                    "revision",
                    self.revision_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.revision_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

impl fmt::Debug for PrivacyBudgetIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivacyBudgetIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

macro_rules! revision_identity {
    ($name:ident, $field:literal, $domain:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            id: String,
            revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                let id = id.into();
                if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
                    return Err(AwsCleanRoomsQueryResultError::InvalidScope);
                }
                Ok(Self { id, revision })
            }

            pub fn id(&self) -> &str {
                &self.id
            }

            pub const fn revision(&self) -> u64 {
                self.revision
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        ("id", self.id.clone()),
                        ("revision", self.revision.to_string()),
                    ],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
                    Ok(())
                } else {
                    Err(AwsCleanRoomsQueryResultError::InvalidScope)
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &self.digest())
                    .field("revision", &self.revision)
                    .finish()
            }
        }
    };
}

revision_identity!(MissionIdentity, "mission", "aws-clean-rooms-mission/v1");
revision_identity!(ProjectIdentity, "project", "aws-clean-rooms-project/v1");
revision_identity!(
    WorkProductIdentity,
    "work-product",
    "aws-clean-rooms-work-product/v1"
);

#[derive(Clone, Eq, PartialEq)]
pub struct AwsCleanRoomsQueryResultScope {
    account: AwsAccountId,
    region: AwsRegion,
    collaboration: CollaborationIdentity,
    membership: MembershipIdentity,
    analysis_template: AnalysisTemplateIdentity,
    protected_query: ProtectedQueryIdentity,
    privacy_budget: PrivacyBudgetIdentity,
    project: ProjectIdentity,
    mission: MissionIdentity,
    work_product: WorkProductIdentity,
}

impl AwsCleanRoomsQueryResultScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        collaboration: CollaborationIdentity,
        membership: MembershipIdentity,
        analysis_template: AnalysisTemplateIdentity,
        protected_query: ProtectedQueryIdentity,
        privacy_budget: PrivacyBudgetIdentity,
        project: ProjectIdentity,
        mission: MissionIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            collaboration,
            membership,
            analysis_template,
            protected_query,
            privacy_budget,
            project,
            mission,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn collaboration(&self) -> &CollaborationIdentity {
        &self.collaboration
    }

    pub fn membership(&self) -> &MembershipIdentity {
        &self.membership
    }

    pub fn analysis_template(&self) -> &AnalysisTemplateIdentity {
        &self.analysis_template
    }

    pub fn protected_query(&self) -> &ProtectedQueryIdentity {
        &self.protected_query
    }

    pub fn privacy_budget(&self) -> &PrivacyBudgetIdentity {
        &self.privacy_budget
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-clean-rooms-query-result-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                (
                    "collaboration",
                    self.collaboration.digest().as_str().to_owned(),
                ),
                ("membership", self.membership.digest().as_str().to_owned()),
                (
                    "analysis_template",
                    self.analysis_template.digest().as_str().to_owned(),
                ),
                (
                    "protected_query",
                    self.protected_query.digest().as_str().to_owned(),
                ),
                (
                    "privacy_budget",
                    self.privacy_budget.digest().as_str().to_owned(),
                ),
                ("project", self.project.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.collaboration.validate()?;
        self.membership.validate()?;
        self.analysis_template.validate()?;
        self.protected_query.validate()?;
        self.privacy_budget.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()
    }
}

impl fmt::Debug for AwsCleanRoomsQueryResultScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCleanRoomsQueryResultScope")
            .field("digest", &self.digest())
            .field("account", &self.account)
            .field("region", &self.region)
            .field("collaboration", &self.collaboration)
            .field("membership", &self.membership)
            .field("analysis_template", &self.analysis_template)
            .field("protected_query", &self.protected_query)
            .field("privacy_budget", &self.privacy_budget)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// Opaque SigV4 reference. The caller-supplied handle is hashed and dropped;
/// it is never serializable, displayable, or present in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        let mut handle = opaque_handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            handle.zeroize();
            return Err(AwsCleanRoomsQueryResultError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-clean-rooms-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("handle", handle.clone()),
                ("revision", revision.to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            kind: SecretKind::Sigv4Credential,
            reference_digest,
            scope_digest: Digest::from_text("unbound-aws-clean-rooms-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsCleanRoomsQueryResultScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-clean-rooms-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("reference", reference.reference_digest.as_str().to_owned()),
                ("scope", reference.scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(reference)
    }

    pub fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self, scope: &AwsCleanRoomsQueryResultScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::Sigv4Credential)
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsCleanRoomsQueryResultError::InvalidSecretReference);
        }
        self.reference_digest.validate()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn is_native(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let snapshot = Self {
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn for_layer_one(revision: u64) -> Self {
        Self {
            revision,
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-clean-rooms-permissions/v1",
            &[
                ("revision", self.revision.to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision == 0
            || self.permissions.len() != LAYER1_PERMISSIONS.len()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            Err(AwsCleanRoomsQueryResultError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConsentScope {
    id: String,
    revision: u64,
    permissions: BTreeSet<String>,
    expires_at: DateTime<Utc>,
    revoked: bool,
}

impl ConsentScope {
    pub fn new<I, S>(
        id: impl Into<String>,
        revision: u64,
        permissions: I,
        expires_at: DateTime<Utc>,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let consent = Self {
            id: id.into(),
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
            expires_at,
            revoked: false,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn for_layer_one(
        id: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(id, revision, LAYER1_PERMISSIONS, expires_at)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-clean-rooms-consent/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("expires_at", self.expires_at.to_rfc3339()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub fn is_active_at(&self, at: DateTime<Utc>) -> bool {
        !self.revoked && at < self.expires_at
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    fn validate(&self) -> Result<()> {
        if !valid_identifier(&self.id, MAX_IDENTIFIER_BYTES)
            || self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            Err(AwsCleanRoomsQueryResultError::InvalidConsent)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for ConsentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsentScope")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectedQueryStatus {
    Submitted,
    Started,
    Cancelling,
    Success,
    Failed,
    Cancelled,
    TimedOut,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

pub type ProtectedQueryEvidenceState = ProtectedQueryStatus;
pub type QueryEvidenceState = ProtectedQueryStatus;

impl ProtectedQueryStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "SUBMITTED",
            Self::Started => "STARTED",
            Self::Cancelling => "CANCELLING",
            Self::Success => "SUCCESS",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::TimedOut => "TIMED_OUT",
            Self::Partial => "PARTIAL",
            Self::AccessLost => "ACCESS_LOST",
            Self::ProviderUnknown => "PROVIDER_UNKNOWN",
            Self::Tampered => "TAMPERED",
            Self::Revoked => "REVOKED",
        }
    }

    pub fn from_provider_status(status: &str) -> Self {
        match status {
            "SUBMITTED" => Self::Submitted,
            "STARTED" => Self::Started,
            "CANCELLING" => Self::Cancelling,
            "SUCCESS" => Self::Success,
            "FAILED" => Self::Failed,
            "CANCELLED" => Self::Cancelled,
            "TIMED_OUT" => Self::TimedOut,
            _ => Self::ProviderUnknown,
        }
    }

    pub const fn is_review_complete(self) -> bool {
        matches!(self, Self::Success)
    }

    pub const fn is_non_adoptable(self) -> bool {
        !self.is_review_complete()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedQueryMetadataInput {
    pub status: ProtectedQueryStatus,
    pub created_at: DateTime<Utc>,
    pub last_updated_at: Option<DateTime<Utc>>,
    pub duration_millis: Option<u64>,
    pub billed_units: Option<u64>,
    pub sql_text: Option<String>,
    pub member_ids: Vec<String>,
    pub output_reference: Option<String>,
    pub provider_error: Option<String>,
    pub query_compute_payer_account_id: Option<String>,
}

impl fmt::Debug for ProtectedQueryMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedQueryMetadataInput")
            .field("status", &self.status)
            .field("created_at", &self.created_at)
            .field("last_updated_at", &self.last_updated_at)
            .field("duration_present", &self.duration_millis.is_some())
            .field("billed_units_present", &self.billed_units.is_some())
            .field("sql_present", &self.sql_text.is_some())
            .field("member_count", &self.member_ids.len())
            .field("output_present", &self.output_reference.is_some())
            .field("provider_error_present", &self.provider_error.is_some())
            .field(
                "payer_account_present",
                &self.query_compute_payer_account_id.is_some(),
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedQueryMetadata {
    protected_query: ProtectedQueryIdentity,
    membership: MembershipIdentity,
    collaboration: CollaborationIdentity,
    analysis_template: AnalysisTemplateIdentity,
    privacy_budget: PrivacyBudgetIdentity,
    status: ProtectedQueryStatus,
    created_at: DateTime<Utc>,
    last_updated_at: Option<DateTime<Utc>>,
    status_digest: Digest,
    duration_digest: Option<Digest>,
    billed_units_digest: Option<Digest>,
    sql_digest: Option<Digest>,
    member_set_digest: Option<Digest>,
    output_digest: Option<Digest>,
    provider_error_digest: Option<Digest>,
    payer_account_digest: Option<Digest>,
}

impl ProtectedQueryMetadata {
    pub fn new(
        scope: &AwsCleanRoomsQueryResultScope,
        input: ProtectedQueryMetadataInput,
    ) -> Result<Self> {
        Self::for_query(scope, scope.protected_query.clone(), input)
    }

    pub fn for_query(
        scope: &AwsCleanRoomsQueryResultScope,
        protected_query: ProtectedQueryIdentity,
        input: ProtectedQueryMetadataInput,
    ) -> Result<Self> {
        scope.validate()?;
        protected_query.validate()?;
        if input
            .sql_text
            .as_ref()
            .is_some_and(|value| !valid_sensitive_text(value))
            || input
                .output_reference
                .as_ref()
                .is_some_and(|value| !valid_sensitive_text(value))
            || input
                .provider_error
                .as_ref()
                .is_some_and(|value| !valid_sensitive_text(value))
        {
            return Err(AwsCleanRoomsQueryResultError::InvalidMetadata);
        }
        if let Some(last_updated_at) = input.last_updated_at {
            if last_updated_at < input.created_at {
                return Err(AwsCleanRoomsQueryResultError::InvalidMetadata);
            }
        }
        let status_digest = Digest::from_parts(
            "aws-clean-rooms-protected-query-status/v1",
            &[("status", input.status.as_str().to_owned())],
        );
        let duration_digest = input.duration_millis.map(|duration| {
            Digest::from_parts(
                "aws-clean-rooms-protected-query-duration/v1",
                &[("milliseconds", duration.to_string())],
            )
        });
        let billed_units_digest = input.billed_units.map(|units| {
            Digest::from_parts(
                "aws-clean-rooms-protected-query-billed-units/v1",
                &[("units", units.to_string())],
            )
        });
        let sql_digest = input.sql_text.map(|sql| {
            Digest::from_parts("aws-clean-rooms-protected-query-sql/v1", &[("sql", sql)])
        });
        let member_set_digest = if input.member_ids.is_empty() {
            None
        } else {
            let mut member_digests = Vec::with_capacity(input.member_ids.len());
            for member_id in input.member_ids {
                if !valid_identifier(&member_id, MAX_IDENTIFIER_BYTES) {
                    return Err(AwsCleanRoomsQueryResultError::InvalidIdentifier {
                        field: "member-id",
                    });
                }
                member_digests.push(Digest::from_parts(
                    "aws-clean-rooms-member-id/v1",
                    &[("member", member_id)],
                ));
            }
            member_digests.sort_unstable();
            member_digests.dedup();
            Some(Digest::from_parts(
                "aws-clean-rooms-member-set/v1",
                &[(
                    "members",
                    member_digests
                        .iter()
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                )],
            ))
        };
        let output_digest = input.output_reference.map(|output| {
            Digest::from_parts("aws-clean-rooms-output-reference/v1", &[("output", output)])
        });
        let provider_error_digest = input.provider_error.map(|error| {
            Digest::from_parts("aws-clean-rooms-provider-error/v1", &[("error", error)])
        });
        let payer_account_digest = input.query_compute_payer_account_id.map(|account| {
            Digest::from_parts(
                "aws-clean-rooms-query-payer-account/v1",
                &[("account", account)],
            )
        });
        let metadata = Self {
            protected_query,
            membership: scope.membership.clone(),
            collaboration: scope.collaboration.clone(),
            analysis_template: scope.analysis_template.clone(),
            privacy_budget: scope.privacy_budget.clone(),
            status: input.status,
            created_at: input.created_at,
            last_updated_at: input.last_updated_at,
            status_digest,
            duration_digest,
            billed_units_digest,
            sql_digest,
            member_set_digest,
            output_digest,
            provider_error_digest,
            payer_account_digest,
        };
        metadata.validate_list_item_against(scope)?;
        Ok(metadata)
    }

    pub fn protected_query(&self) -> &ProtectedQueryIdentity {
        &self.protected_query
    }

    pub fn membership(&self) -> &MembershipIdentity {
        &self.membership
    }

    pub fn collaboration(&self) -> &CollaborationIdentity {
        &self.collaboration
    }

    pub fn analysis_template(&self) -> &AnalysisTemplateIdentity {
        &self.analysis_template
    }

    pub fn privacy_budget(&self) -> &PrivacyBudgetIdentity {
        &self.privacy_budget
    }

    pub const fn status(&self) -> ProtectedQueryStatus {
        self.status
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn last_updated_at(&self) -> Option<DateTime<Utc>> {
        self.last_updated_at
    }

    pub fn status_digest(&self) -> &Digest {
        &self.status_digest
    }

    pub fn duration_digest(&self) -> Option<&Digest> {
        self.duration_digest.as_ref()
    }

    pub fn billed_units_digest(&self) -> Option<&Digest> {
        self.billed_units_digest.as_ref()
    }

    pub fn sql_digest(&self) -> Option<&Digest> {
        self.sql_digest.as_ref()
    }

    pub fn member_set_digest(&self) -> Option<&Digest> {
        self.member_set_digest.as_ref()
    }

    pub fn output_digest(&self) -> Option<&Digest> {
        self.output_digest.as_ref()
    }

    pub fn provider_error_digest(&self) -> Option<&Digest> {
        self.provider_error_digest.as_ref()
    }

    pub fn payer_account_digest(&self) -> Option<&Digest> {
        self.payer_account_digest.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-clean-rooms-protected-query-metadata/v1",
            &[
                ("query", self.protected_query.digest().as_str().to_owned()),
                ("membership", self.membership.digest().as_str().to_owned()),
                (
                    "collaboration",
                    self.collaboration.digest().as_str().to_owned(),
                ),
                (
                    "analysis_template",
                    self.analysis_template.digest().as_str().to_owned(),
                ),
                (
                    "privacy_budget",
                    self.privacy_budget.digest().as_str().to_owned(),
                ),
                ("status", self.status.as_str().to_owned()),
                ("created_at", self.created_at.to_rfc3339()),
                (
                    "last_updated_at",
                    self.last_updated_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                ("status_digest", self.status_digest.as_str().to_owned()),
                (
                    "duration_digest",
                    self.duration_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "billed_units_digest",
                    self.billed_units_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "sql_digest",
                    self.sql_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "member_set_digest",
                    self.member_set_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "output_digest",
                    self.output_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "provider_error_digest",
                    self.provider_error_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "payer_account_digest",
                    self.payer_account_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsCleanRoomsQueryResultScope) -> Result<()> {
        self.validate_list_item_against(scope)?;
        if self.protected_query != scope.protected_query {
            return Err(AwsCleanRoomsQueryResultError::ScopeMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_list_item_against(
        &self,
        scope: &AwsCleanRoomsQueryResultScope,
    ) -> Result<()> {
        if self.membership != scope.membership
            || self.collaboration != scope.collaboration
            || self.analysis_template != scope.analysis_template
            || self.privacy_budget != scope.privacy_budget
            || self
                .last_updated_at
                .is_some_and(|updated| updated < self.created_at)
        {
            return Err(AwsCleanRoomsQueryResultError::ScopeMismatch);
        }
        self.protected_query.validate()?;
        self.membership.validate()?;
        self.collaboration.validate()?;
        self.analysis_template.validate()?;
        self.privacy_budget.validate()?;
        self.status_digest.validate()?;
        for digest in [
            self.duration_digest.as_ref(),
            self.billed_units_digest.as_ref(),
            self.sql_digest.as_ref(),
            self.member_set_digest.as_ref(),
            self.output_digest.as_ref(),
            self.provider_error_digest.as_ref(),
            self.payer_account_digest.as_ref(),
        ] {
            digest.map(Digest::validate).transpose()?;
        }
        Ok(())
    }
}

impl fmt::Debug for ProtectedQueryMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedQueryMetadata")
            .field("digest", &self.digest())
            .field("protected_query", &self.protected_query)
            .field("status", &self.status)
            .field("created_at", &self.created_at)
            .field("last_updated_at", &self.last_updated_at)
            .field("duration_digest", &self.duration_digest)
            .field("billed_units_digest", &self.billed_units_digest)
            .field("sql_digest", &self.sql_digest)
            .field("member_set_digest", &self.member_set_digest)
            .field("output_digest", &self.output_digest)
            .field("provider_error_digest", &self.provider_error_digest)
            .finish()
    }
}

impl Serialize for ProtectedQueryMetadata {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ProtectedQueryMetadata", 16)?;
        state.serialize_field("protectedQueryDigest", &self.protected_query.digest())?;
        state.serialize_field("membershipDigest", &self.membership.digest())?;
        state.serialize_field("collaborationDigest", &self.collaboration.digest())?;
        state.serialize_field("analysisTemplateDigest", &self.analysis_template.digest())?;
        state.serialize_field("privacyBudgetDigest", &self.privacy_budget.digest())?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("statusDigest", &self.status_digest)?;
        state.serialize_field("createdAt", &self.created_at)?;
        state.serialize_field("lastUpdatedAt", &self.last_updated_at)?;
        state.serialize_field("durationDigest", &self.duration_digest)?;
        state.serialize_field("billedUnitsDigest", &self.billed_units_digest)?;
        state.serialize_field("sqlDigest", &self.sql_digest)?;
        state.serialize_field("memberSetDigest", &self.member_set_digest)?;
        state.serialize_field("outputDigest", &self.output_digest)?;
        state.serialize_field("providerErrorDigest", &self.provider_error_digest)?;
        state.serialize_field("payerAccountDigest", &self.payer_account_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectedQueryProjection {
    pub protected_query_digest: Digest,
    pub membership_digest: Digest,
    pub collaboration_digest: Digest,
    pub analysis_template_digest: Digest,
    pub privacy_budget_digest: Digest,
    pub status: ProtectedQueryStatus,
    pub status_digest: Digest,
    pub created_at: DateTime<Utc>,
    pub last_updated_at: Option<DateTime<Utc>>,
    pub duration_digest: Option<Digest>,
    pub billed_units_digest: Option<Digest>,
    pub sql_digest: Option<Digest>,
    pub member_set_digest: Option<Digest>,
    pub output_digest: Option<Digest>,
    pub provider_error_digest: Option<Digest>,
    pub payer_account_digest: Option<Digest>,
}

impl ProtectedQueryProjection {
    pub fn from_metadata(metadata: &ProtectedQueryMetadata) -> Self {
        Self {
            protected_query_digest: metadata.protected_query.digest(),
            membership_digest: metadata.membership.digest(),
            collaboration_digest: metadata.collaboration.digest(),
            analysis_template_digest: metadata.analysis_template.digest(),
            privacy_budget_digest: metadata.privacy_budget.digest(),
            status: metadata.status,
            status_digest: metadata.status_digest.clone(),
            created_at: metadata.created_at,
            last_updated_at: metadata.last_updated_at,
            duration_digest: metadata.duration_digest.clone(),
            billed_units_digest: metadata.billed_units_digest.clone(),
            sql_digest: metadata.sql_digest.clone(),
            member_set_digest: metadata.member_set_digest.clone(),
            output_digest: metadata.output_digest.clone(),
            provider_error_digest: metadata.provider_error_digest.clone(),
            payer_account_digest: metadata.payer_account_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub list_digest: Option<Digest>,
    pub get_digest: Option<Digest>,
    pub status_digest: Option<Digest>,
    pub duration_digest: Option<Digest>,
    pub billed_units_digest: Option<Digest>,
    pub sql_digest: Option<Digest>,
    pub member_set_digest: Option<Digest>,
    pub output_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

pub(crate) fn mission_projection(mission: &MissionIdentity) -> MissionProjection {
    MissionProjection {
        id_digest: mission.digest(),
        revision: mission.revision,
    }
}

pub(crate) fn project_projection(project: &ProjectIdentity) -> ProjectProjection {
    ProjectProjection {
        id_digest: project.digest(),
        revision: project.revision,
    }
}

pub(crate) fn work_product_projection(work_product: &WorkProductIdentity) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: work_product.digest(),
        revision: work_product.revision,
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedQueryFilter {
    scope_digest: Digest,
    status: Option<ProtectedQueryStatus>,
    max_results: u16,
}

impl ProtectedQueryFilter {
    pub fn for_scope(
        scope: &AwsCleanRoomsQueryResultScope,
        max_results: u16,
        status: Option<ProtectedQueryStatus>,
    ) -> Result<Self> {
        if max_results == 0 || max_results > MAX_PAGE_SIZE {
            return Err(AwsCleanRoomsQueryResultError::InvalidRequest);
        }
        let filter = Self {
            scope_digest: scope.digest(),
            status,
            max_results,
        };
        filter.validate_against(scope)?;
        Ok(filter)
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn status(&self) -> Option<ProtectedQueryStatus> {
        self.status
    }

    pub const fn max_results(&self) -> u16 {
        self.max_results
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-clean-rooms-protected-query-filter/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "status",
                    self.status
                        .map_or_else(String::new, |status| status.as_str().to_owned()),
                ),
                ("max_results", self.max_results.to_string()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsCleanRoomsQueryResultScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.max_results == 0
            || self.max_results > MAX_PAGE_SIZE
            || matches!(
                self.status,
                Some(ProtectedQueryStatus::Tampered | ProtectedQueryStatus::Revoked)
            )
        {
            return Err(AwsCleanRoomsQueryResultError::FilterMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for ProtectedQueryFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedQueryFilter")
            .field("digest", &self.digest())
            .field("status", &self.status)
            .field("max_results", &self.max_results)
            .finish()
    }
}

impl Serialize for ProtectedQueryFilter {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ProtectedQueryFilter", 3)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("maxResults", &self.max_results)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Cursor {
    scope_digest: Digest,
    filter_digest: Digest,
    token_digest: Digest,
    page_number: u16,
}

impl Cursor {
    pub fn new(
        opaque_token: impl Into<String>,
        scope: &AwsCleanRoomsQueryResultScope,
        filter: &ProtectedQueryFilter,
        page_number: u16,
    ) -> Result<Self> {
        let token = opaque_token.into();
        if !valid_text(&token, MAX_IDENTIFIER_BYTES, true)
            || page_number == 0
            || page_number > MAX_PAGES
        {
            return Err(AwsCleanRoomsQueryResultError::InvalidRequest);
        }
        filter.validate_against(scope)?;
        Ok(Self {
            scope_digest: scope.digest(),
            filter_digest: filter.digest(),
            token_digest: Digest::from_parts("aws-clean-rooms-next-token/v1", &[("token", token)]),
            page_number,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn validate_against(
        &self,
        scope: &AwsCleanRoomsQueryResultScope,
        filter: &ProtectedQueryFilter,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.filter_digest != filter.digest()
            || self.page_number == 0
            || self.page_number > MAX_PAGES
        {
            return Err(AwsCleanRoomsQueryResultError::CursorMismatch);
        }
        self.token_digest.validate()
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("scope_digest", &self.scope_digest)
            .field("filter_digest", &self.filter_digest)
            .field("token_digest", &self.token_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for Cursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Cursor", 4)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("filterDigest", &self.filter_digest)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

pub(crate) fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes > MAX_RESPONSE_BYTES {
        Err(AwsCleanRoomsQueryResultError::PartialEvidence)
    } else {
        Ok(())
    }
}
