//! Redacted, digest-bound model types for the AWS Resilience Hub Layer-1 seam.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsResilienceHubError, Result};
use crate::{LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES};

pub const MAX_ARN_BYTES: usize = 2_048;
pub const MAX_RISK_CATEGORIES: usize = 16;
pub const MAX_RISK_COUNT: u16 = 10_000;
pub const MAX_ASSESSMENT_AGE_SECONDS: i64 = 24 * 60 * 60;

/// A lowercase SHA-256 digest used as the only stable evidence identifier.
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
            Err(AwsResilienceHubError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsResilienceHubError::InvalidDigest)
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

fn valid_arn(value: &str) -> bool {
    valid_text(value, MAX_ARN_BYTES, false) && value.starts_with("arn:")
}

macro_rules! redacted_text {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsResilienceHubError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-resilience-hub-", $field, "/v1"),
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
                    Err(AwsResilienceHubError::InvalidIdentifier { field: $field })
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

redacted_text!(AwsAccountId, "account", |value: &str| value.len() == 12
    && value.bytes().all(|byte| byte.is_ascii_digit()));
redacted_text!(AwsRegion, "region", |value: &str| valid_identifier(
    value, 63
));
redacted_text!(ApplicationArn, "application-arn", valid_arn);
redacted_text!(AssessmentArn, "assessment-arn", valid_arn);
redacted_text!(ResiliencyPolicyArn, "resiliency-policy-arn", valid_arn);
redacted_text!(ApplicationVersion, "application-version", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});

macro_rules! mission_identity {
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
                    return Err(AwsResilienceHubError::InvalidScope);
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
                    Err(AwsResilienceHubError::InvalidScope)
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("id_digest", &Digest::from_text(&self.id))
                    .field("revision", &self.revision)
                    .finish()
            }
        }
    };
}

mission_identity!(MissionIdentity, "Mission", "aws-resilience-hub-mission/v1");
mission_identity!(ProjectIdentity, "Project", "aws-resilience-hub-project/v1");
mission_identity!(
    WorkProductIdentity,
    "Work Product",
    "aws-resilience-hub-work-product/v1"
);

/// The typed application identity is never serialized by this crate.
#[derive(Clone, Eq, PartialEq)]
pub struct ApplicationIdentity {
    arn: ApplicationArn,
}

impl ApplicationIdentity {
    pub fn new(arn: ApplicationArn) -> Self {
        Self { arn }
    }

    pub fn arn(&self) -> &ApplicationArn {
        &self.arn
    }

    pub fn digest(&self) -> Digest {
        self.arn.digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.arn.validate()
    }
}

impl fmt::Debug for ApplicationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

/// A version is kept as a typed value in the request scope and as a digest in
/// all evidence and projections.
#[derive(Clone, Eq, PartialEq)]
pub struct ApplicationVersionIdentity {
    value: ApplicationVersion,
}

impl ApplicationVersionIdentity {
    pub fn new(value: ApplicationVersion) -> Self {
        Self { value }
    }

    pub fn value(&self) -> &ApplicationVersion {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        self.value.digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.value.validate()
    }
}

impl fmt::Debug for ApplicationVersionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationVersionIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AssessmentIdentity {
    arn: AssessmentArn,
}

impl AssessmentIdentity {
    pub fn new(arn: AssessmentArn) -> Self {
        Self { arn }
    }

    pub fn arn(&self) -> &AssessmentArn {
        &self.arn
    }

    pub fn digest(&self) -> Digest {
        self.arn.digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.arn.validate()
    }
}

impl fmt::Debug for AssessmentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssessmentIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ResiliencyPolicyIdentity {
    arn: ResiliencyPolicyArn,
}

impl ResiliencyPolicyIdentity {
    pub fn new(arn: ResiliencyPolicyArn) -> Self {
        Self { arn }
    }

    pub fn arn(&self) -> &ResiliencyPolicyArn {
        &self.arn
    }

    pub fn digest(&self) -> Digest {
        self.arn.digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.arn.validate()
    }
}

impl fmt::Debug for ResiliencyPolicyIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResiliencyPolicyIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationAllowlist {
    application_digests: BTreeSet<Digest>,
}

impl ApplicationAllowlist {
    pub fn new(applications: impl IntoIterator<Item = ApplicationIdentity>) -> Result<Self> {
        let application_digests = applications
            .into_iter()
            .map(|application| {
                application.validate()?;
                Ok(application.digest())
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if application_digests.is_empty() {
            return Err(AwsResilienceHubError::InvalidAllowlist {
                field: "application",
            });
        }
        Ok(Self {
            application_digests,
        })
    }

    pub fn exact(application: &ApplicationIdentity) -> Self {
        Self {
            application_digests: [application.digest()].into_iter().collect(),
        }
    }

    pub fn allows(&self, application: &ApplicationIdentity) -> bool {
        self.application_digests.contains(&application.digest())
    }

    pub fn allows_digest(&self, application_digest: &Digest) -> bool {
        self.application_digests.contains(application_digest)
    }

    pub fn digests(&self) -> &BTreeSet<Digest> {
        &self.application_digests
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-application-allowlist/v1",
            &[(
                "applications",
                self.application_digests
                    .iter()
                    .map(|digest| digest.as_str())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.application_digests.is_empty() {
            return Err(AwsResilienceHubError::InvalidAllowlist {
                field: "application",
            });
        }
        for digest in &self.application_digests {
            digest.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssessmentAllowlist {
    assessment_digests: BTreeSet<Digest>,
}

impl AssessmentAllowlist {
    pub fn new(assessments: impl IntoIterator<Item = AssessmentIdentity>) -> Result<Self> {
        let assessment_digests = assessments
            .into_iter()
            .map(|assessment| {
                assessment.validate()?;
                Ok(assessment.digest())
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if assessment_digests.is_empty() {
            return Err(AwsResilienceHubError::InvalidAllowlist {
                field: "assessment",
            });
        }
        Ok(Self { assessment_digests })
    }

    pub fn exact(assessment: &AssessmentIdentity) -> Self {
        Self {
            assessment_digests: [assessment.digest()].into_iter().collect(),
        }
    }

    pub fn allows(&self, assessment: &AssessmentIdentity) -> bool {
        self.assessment_digests.contains(&assessment.digest())
    }

    pub fn allows_digest(&self, assessment_digest: &Digest) -> bool {
        self.assessment_digests.contains(assessment_digest)
    }

    pub fn digests(&self) -> &BTreeSet<Digest> {
        &self.assessment_digests
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-assessment-allowlist/v1",
            &[(
                "assessments",
                self.assessment_digests
                    .iter()
                    .map(|digest| digest.as_str())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.assessment_digests.is_empty() {
            return Err(AwsResilienceHubError::InvalidAllowlist {
                field: "assessment",
            });
        }
        for digest in &self.assessment_digests {
            digest.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsResilienceHubScope {
    account: AwsAccountId,
    region: AwsRegion,
    application: ApplicationIdentity,
    application_version: ApplicationVersionIdentity,
    assessment: AssessmentIdentity,
    resiliency_policy: ResiliencyPolicyIdentity,
    application_allowlist: ApplicationAllowlist,
    assessment_allowlist: AssessmentAllowlist,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsResilienceHubScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        application: ApplicationIdentity,
        application_version: ApplicationVersionIdentity,
        assessment: AssessmentIdentity,
        resiliency_policy: ResiliencyPolicyIdentity,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        Self::with_allowlists(
            account,
            region,
            application.clone(),
            application_version,
            assessment.clone(),
            resiliency_policy,
            ApplicationAllowlist::exact(&application),
            AssessmentAllowlist::exact(&assessment),
            mission,
            project,
            work_product,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_allowlists(
        account: AwsAccountId,
        region: AwsRegion,
        application: ApplicationIdentity,
        application_version: ApplicationVersionIdentity,
        assessment: AssessmentIdentity,
        resiliency_policy: ResiliencyPolicyIdentity,
        application_allowlist: ApplicationAllowlist,
        assessment_allowlist: AssessmentAllowlist,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            application,
            application_version,
            assessment,
            resiliency_policy,
            application_allowlist,
            assessment_allowlist,
            mission,
            project,
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

    pub fn application(&self) -> &ApplicationIdentity {
        &self.application
    }

    pub fn application_version(&self) -> &ApplicationVersionIdentity {
        &self.application_version
    }

    pub fn assessment(&self) -> &AssessmentIdentity {
        &self.assessment
    }

    pub fn resiliency_policy(&self) -> &ResiliencyPolicyIdentity {
        &self.resiliency_policy
    }

    pub fn application_allowlist(&self) -> &ApplicationAllowlist {
        &self.application_allowlist
    }

    pub fn assessment_allowlist(&self) -> &AssessmentAllowlist {
        &self.assessment_allowlist
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("application", self.application.digest().as_str().to_owned()),
                (
                    "application_version",
                    self.application_version.digest().as_str().to_owned(),
                ),
                ("assessment", self.assessment.digest().as_str().to_owned()),
                (
                    "resiliency_policy",
                    self.resiliency_policy.digest().as_str().to_owned(),
                ),
                (
                    "application_allowlist",
                    self.application_allowlist.digest().as_str().to_owned(),
                ),
                (
                    "assessment_allowlist",
                    self.assessment_allowlist.digest().as_str().to_owned(),
                ),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
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
        self.application.validate()?;
        self.application_version.validate()?;
        self.assessment.validate()?;
        self.resiliency_policy.validate()?;
        self.application_allowlist.validate()?;
        self.assessment_allowlist.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        if !self.application_allowlist.allows(&self.application)
            || !self.assessment_allowlist.allows(&self.assessment)
        {
            return Err(AwsResilienceHubError::InvalidAllowlist {
                field: "scope target",
            });
        }
        Ok(())
    }
}

impl fmt::Debug for AwsResilienceHubScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsResilienceHubScope")
            .field("digest", &self.digest())
            .field(
                "application_allowlist",
                &self.application_allowlist.digest(),
            )
            .field("assessment_allowlist", &self.assessment_allowlist.digest())
            .finish()
    }
}

/// Compatibility alias for callers that name the scope after the application.
pub type ResilienceHubApplicationScope = AwsResilienceHubScope;
pub type AwsResilienceHubApplicationIdentity = ApplicationIdentity;
pub type AwsResilienceHubApplicationVersionIdentity = ApplicationVersionIdentity;
pub type AwsResilienceHubAssessmentIdentity = AssessmentIdentity;
pub type AwsResilienceHubResiliencyPolicyIdentity = ResiliencyPolicyIdentity;
pub type ResilienceHubApplicationIdentity = ApplicationIdentity;
pub type ResilienceHubApplicationVersionIdentity = ApplicationVersionIdentity;
pub type ResilienceHubAssessmentIdentity = AssessmentIdentity;
pub type ResilienceHubResiliencyPolicyIdentity = ResiliencyPolicyIdentity;
pub type AwsResilienceHubApplicationAllowlist = ApplicationAllowlist;
pub type AwsResilienceHubAssessmentAllowlist = AssessmentAllowlist;

/// The reference is reduced to a digest immediately; the supplied handle is
/// zeroized and the raw value is never retained, formatted, or serialized.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    region: AwsRegion,
    revision: u64,
}

impl SecretReference {
    pub fn sigv4(
        reference: impl AsRef<str>,
        scope: &AwsResilienceHubScope,
        revision: u64,
    ) -> Result<Self> {
        let mut value = reference.as_ref().to_owned();
        if !valid_text(&value, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            value.zeroize();
            return Err(AwsResilienceHubError::InvalidSecretReference);
        }
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "hartevo-aws-resilience-hub-sigv4-secret/v1",
            &[
                ("service", "resiliencehub".to_owned()),
                ("region", scope.region().as_str().to_owned()),
                ("account", scope.account().digest().as_str().to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
                ("reference", value.clone()),
            ],
        );
        value.zeroize();
        Ok(Self {
            reference_digest,
            scope_digest,
            region: scope.region().clone(),
            revision,
        })
    }

    pub fn for_scope(
        reference: impl AsRef<str>,
        scope: &AwsResilienceHubScope,
        revision: u64,
    ) -> Result<Self> {
        Self::sigv4(reference, scope, revision)
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn digest(&self) -> &Digest {
        self.reference_digest()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn signing_service(&self) -> &'static str {
        "resiliencehub"
    }

    pub fn signing_region(&self) -> &AwsRegion {
        &self.region
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub(crate) fn validate(&self, scope: &AwsResilienceHubScope) -> Result<()> {
        if self.revision == 0
            || self.region != *scope.region()
            || self.scope_digest != scope.digest()
        {
            return Err(AwsResilienceHubError::InvalidSecretReference);
        }
        self.scope_digest.validate()?;
        self.reference_digest.validate()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("value", &"<opaque>")
            .field("signing_service", &self.signing_service())
            .field("signing_region", &self.region)
            .field("revision", &self.revision)
            .field("scope_digest", &self.scope_digest)
            .field("digest", &self.reference_digest)
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
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
            "aws-resilience-hub-permission-snapshot/v1",
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

    pub fn validate(&self) -> Result<()> {
        let expected_permissions = LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<BTreeSet<_>>();
        if self.revision == 0
            || self.permissions.is_empty()
            || self.permissions != expected_permissions
            || self
                .permissions
                .iter()
                .any(|permission| !valid_text(permission, MAX_IDENTIFIER_BYTES, false))
        {
            Err(AwsResilienceHubError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScope {
    id: Digest,
    revision: u64,
    expires_at: DateTime<Utc>,
    permissions: BTreeSet<String>,
    revoked: bool,
}

impl ConsentScope {
    pub fn for_layer_one(
        id: impl AsRef<str>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let id = id.as_ref();
        if !valid_identifier(id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(AwsResilienceHubError::InvalidConsent);
        }
        Ok(Self {
            id: Digest::from_parts("aws-resilience-hub-consent-id/v1", &[("id", id.to_owned())]),
            revision,
            expires_at,
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            revoked: false,
        })
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        !self.revoked && now < self.expires_at
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-consent/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.to_string()),
                ("expires_at", self.expires_at.to_rfc3339()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        let expected_permissions = LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<BTreeSet<_>>();
        if self.revision == 0
            || self.permissions.is_empty()
            || self.permissions != expected_permissions
            || self.id.validate().is_err()
        {
            return Err(AwsResilienceHubError::InvalidConsent);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Digest,
    page_number: u16,
}

impl OpaqueCursor {
    pub fn new(
        token: impl AsRef<str>,
        scope: &AwsResilienceHubScope,
        operation: &str,
        query_digest: &Digest,
        page_number: u16,
    ) -> Result<Self> {
        let token = token.as_ref();
        if !valid_text(token, MAX_IDENTIFIER_BYTES * 2, true)
            || page_number == 0
            || page_number > MAX_PAGES
        {
            return Err(AwsResilienceHubError::InvalidCursor);
        }
        let token_digest = Digest::from_parts(
            "aws-resilience-hub-cursor-token/v1",
            &[("token", token.to_owned())],
        );
        let binding_digest = cursor_binding(scope, operation, query_digest, page_number);
        Ok(Self {
            token_digest,
            binding_digest,
            page_number,
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub(crate) fn validate_against(
        &self,
        scope: &AwsResilienceHubScope,
        operation: &str,
        query_digest: &Digest,
        expected_page: u16,
    ) -> Result<()> {
        if self.page_number != expected_page
            || self.binding_digest != cursor_binding(scope, operation, query_digest, expected_page)
        {
            return Err(AwsResilienceHubError::CursorMismatch);
        }
        self.token_digest.validate()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OpaqueCursor", 3)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

fn cursor_binding(
    scope: &AwsResilienceHubScope,
    operation: &str,
    query_digest: &Digest,
    page_number: u16,
) -> Digest {
    Digest::from_parts(
        "aws-resilience-hub-cursor-binding/v1",
        &[
            ("scope", scope.digest().as_str().to_owned()),
            ("operation", operation.to_owned()),
            ("query", query_digest.as_str().to_owned()),
            ("page", page_number.to_string()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialOrd, Ord, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }

    pub const fn is_native(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentStatus {
    Pending,
    InProgress,
    Succeeded,
    Failed,
    Expired,
    Unknown,
}

impl AssessmentStatus {
    pub fn from_api(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "PENDING" => Self::Pending,
            "IN_PROGRESS" | "RUNNING" => Self::InProgress,
            "SUCCEEDED" | "COMPLETED" => Self::Succeeded,
            "FAILED" => Self::Failed,
            "EXPIRED" => Self::Expired,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureStatus {
    Met,
    AtRisk,
    NotMet,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RpoRtoPosture {
    pub rpo: PostureStatus,
    pub rto: PostureStatus,
    pub rpo_minutes: Option<u32>,
    pub rto_minutes: Option<u32>,
}

impl RpoRtoPosture {
    #[allow(clippy::similar_names)]
    pub fn new(
        rpo: PostureStatus,
        rto: PostureStatus,
        rpo_minutes: Option<u32>,
        rto_minutes: Option<u32>,
    ) -> Result<Self> {
        if rpo_minutes.is_some_and(|minutes| minutes == 0)
            || rto_minutes.is_some_and(|minutes| minutes == 0)
        {
            return Err(AwsResilienceHubError::InvalidAssessmentMetadata);
        }
        Ok(Self {
            rpo,
            rto,
            rpo_minutes,
            rto_minutes,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-rpo-rto/v1",
            &[
                ("rpo", format!("{:?}", self.rpo)),
                ("rto", format!("{:?}", self.rto)),
                (
                    "rpo_minutes",
                    self.rpo_minutes.map_or_else(String::new, |v| v.to_string()),
                ),
                (
                    "rto_minutes",
                    self.rto_minutes.map_or_else(String::new, |v| v.to_string()),
                ),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftStatus {
    NotDetected,
    Detected,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    Availability,
    Durability,
    RecoveryPoint,
    RecoveryTime,
    ConfigurationDrift,
    Policy,
    Dependency,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskEvidence {
    pub category: RiskCategory,
    pub count: u16,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: Digest,
}

impl RiskEvidence {
    pub fn new(category: RiskCategory, count: u16, observed_at: DateTime<Utc>) -> Result<Self> {
        if count > MAX_RISK_COUNT {
            return Err(AwsResilienceHubError::InvalidAssessmentMetadata);
        }
        let evidence_digest = Digest::from_parts(
            "aws-resilience-hub-risk/v1",
            &[
                ("category", format!("{category:?}")),
                ("count", count.to_string()),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            category,
            count,
            observed_at,
            evidence_digest,
        })
    }
}

#[derive(Clone)]
pub struct ApplicationMetadataInput {
    pub application_version: ApplicationVersionIdentity,
    pub resiliency_policy: ResiliencyPolicyIdentity,
    pub drift: DriftStatus,
    pub observed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status_message: Option<String>,
    pub resource_arns: Vec<String>,
    pub tags: Vec<String>,
}

impl fmt::Debug for ApplicationMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationMetadataInput")
            .field("application_version", &self.application_version.digest())
            .field("resiliency_policy", &self.resiliency_policy.digest())
            .field("drift", &self.drift)
            .field("observed_at", &self.observed_at)
            .field("expires_at", &self.expires_at)
            .field("redacted_fields", &self.redaction_digest())
            .finish()
    }
}

impl ApplicationMetadataInput {
    fn redaction_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-application-redaction/v1",
            &[
                (
                    "status_message",
                    self.status_message.clone().unwrap_or_default(),
                ),
                ("resource_arns", self.resource_arns.join("\n")),
                ("tags", self.tags.join("\n")),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationMetadata {
    application_digest: Digest,
    application_version_digest: Digest,
    resiliency_policy_digest: Digest,
    drift: DriftStatus,
    observed_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    redaction_digest: Digest,
    evidence_digest: Digest,
}

impl ApplicationMetadata {
    pub fn new(scope: &AwsResilienceHubScope, input: ApplicationMetadataInput) -> Result<Self> {
        let application_version = input.application_version.clone();
        let resiliency_policy = input.resiliency_policy.clone();
        Self::for_application(
            scope.application(),
            &application_version,
            &resiliency_policy,
            input,
        )
    }

    pub fn for_application(
        application: &ApplicationIdentity,
        application_version: &ApplicationVersionIdentity,
        resiliency_policy: &ResiliencyPolicyIdentity,
        input: ApplicationMetadataInput,
    ) -> Result<Self> {
        application.validate()?;
        application_version.validate()?;
        resiliency_policy.validate()?;
        let redaction_digest = input.redaction_digest();
        let mut metadata = Self {
            application_digest: application.digest(),
            application_version_digest: application_version.digest(),
            resiliency_policy_digest: resiliency_policy.digest(),
            drift: input.drift,
            observed_at: input.observed_at,
            expires_at: input.expires_at,
            redaction_digest,
            evidence_digest: Digest::from_text("unsealed-aws-resilience-hub-application"),
        };
        metadata.evidence_digest = metadata.calculate_digest();
        Ok(metadata)
    }

    pub fn application_digest(&self) -> &Digest {
        &self.application_digest
    }

    pub fn application_version_digest(&self) -> &Digest {
        &self.application_version_digest
    }

    pub fn resiliency_policy_digest(&self) -> &Digest {
        &self.resiliency_policy_digest
    }

    pub const fn drift(&self) -> DriftStatus {
        self.drift
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    pub fn redaction_digest(&self) -> &Digest {
        &self.redaction_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }

    pub(crate) fn validate_against(&self, scope: &AwsResilienceHubScope) -> Result<()> {
        if self.application_digest != scope.application().digest()
            || self.application_version_digest != scope.application_version().digest()
            || self.resiliency_policy_digest != scope.resiliency_policy().digest()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsResilienceHubError::ApplicationDrift);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-application-metadata/v1",
            &[
                ("application", self.application_digest.as_str().to_owned()),
                (
                    "application_version",
                    self.application_version_digest.as_str().to_owned(),
                ),
                (
                    "resiliency_policy",
                    self.resiliency_policy_digest.as_str().to_owned(),
                ),
                ("drift", format!("{:?}", self.drift)),
                ("observed_at", self.observed_at.to_rfc3339()),
                (
                    "expires_at",
                    self.expires_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                ("redaction", self.redaction_digest.as_str().to_owned()),
            ],
        )
    }
}

impl Serialize for ApplicationMetadata {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ApplicationMetadata", 9)?;
        state.serialize_field("applicationDigest", &self.application_digest)?;
        state.serialize_field("applicationVersionDigest", &self.application_version_digest)?;
        state.serialize_field("resiliencyPolicyDigest", &self.resiliency_policy_digest)?;
        state.serialize_field("drift", &self.drift)?;
        state.serialize_field("observedAt", &self.observed_at)?;
        state.serialize_field("expiresAt", &self.expires_at)?;
        state.serialize_field("redactionDigest", &self.redaction_digest)?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.end()
    }
}

#[derive(Clone)]
pub struct AssessmentMetadataInput {
    pub status: AssessmentStatus,
    pub compliance_status: ComplianceStatus,
    pub resiliency_score: Option<u8>,
    pub rpo_rto: RpoRtoPosture,
    pub drift: DriftStatus,
    pub risk_categories: Vec<(RiskCategory, u16, DateTime<Utc>)>,
    pub observed_at: DateTime<Utc>,
    pub assessed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status_message: Option<String>,
    pub recommendation_text: Option<String>,
    pub resource_arns: Vec<String>,
    pub tags: Vec<String>,
}

impl fmt::Debug for AssessmentMetadataInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssessmentMetadataInput")
            .field("status", &self.status)
            .field("compliance_status", &self.compliance_status)
            .field("resiliency_score", &self.resiliency_score)
            .field("rpo_rto", &self.rpo_rto)
            .field("drift", &self.drift)
            .field("risk_count", &self.risk_categories.len())
            .field("observed_at", &self.observed_at)
            .field("assessed_at", &self.assessed_at)
            .field("expires_at", &self.expires_at)
            .field("redacted_fields", &self.redaction_digest())
            .finish()
    }
}

impl AssessmentMetadataInput {
    fn redaction_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-assessment-redaction/v1",
            &[
                (
                    "status_message",
                    self.status_message.clone().unwrap_or_default(),
                ),
                (
                    "recommendation_text",
                    self.recommendation_text.clone().unwrap_or_default(),
                ),
                ("resource_arns", self.resource_arns.join("\n")),
                ("tags", self.tags.join("\n")),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssessmentMetadata {
    application_digest: Digest,
    application_version_digest: Digest,
    assessment_digest: Digest,
    resiliency_policy_digest: Digest,
    status: AssessmentStatus,
    compliance_status: ComplianceStatus,
    resiliency_score: Option<u8>,
    rpo_rto: RpoRtoPosture,
    drift: DriftStatus,
    risk_categories: Vec<RiskEvidence>,
    observed_at: DateTime<Utc>,
    assessed_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    redaction_digest: Digest,
    evidence_digest: Digest,
}

impl AssessmentMetadata {
    pub fn new(scope: &AwsResilienceHubScope, input: AssessmentMetadataInput) -> Result<Self> {
        Self::for_assessment(
            scope.application(),
            scope.application_version(),
            scope.assessment(),
            scope.resiliency_policy(),
            input,
        )
    }

    pub fn for_assessment(
        application: &ApplicationIdentity,
        application_version: &ApplicationVersionIdentity,
        assessment: &AssessmentIdentity,
        resiliency_policy: &ResiliencyPolicyIdentity,
        input: AssessmentMetadataInput,
    ) -> Result<Self> {
        application.validate()?;
        application_version.validate()?;
        assessment.validate()?;
        resiliency_policy.validate()?;
        if input.resiliency_score.is_some_and(|score| score > 100)
            || input.risk_categories.len() > MAX_RISK_CATEGORIES
        {
            return Err(AwsResilienceHubError::InvalidAssessmentMetadata);
        }
        let risk_categories = input
            .risk_categories
            .iter()
            .map(|(category, count, observed_at)| {
                RiskEvidence::new(*category, *count, *observed_at)
            })
            .collect::<Result<Vec<_>>>()?;
        let redaction_digest = input.redaction_digest();
        let mut metadata = Self {
            application_digest: application.digest(),
            application_version_digest: application_version.digest(),
            assessment_digest: assessment.digest(),
            resiliency_policy_digest: resiliency_policy.digest(),
            status: input.status,
            compliance_status: input.compliance_status,
            resiliency_score: input.resiliency_score,
            rpo_rto: input.rpo_rto,
            drift: input.drift,
            risk_categories,
            observed_at: input.observed_at,
            assessed_at: input.assessed_at,
            expires_at: input.expires_at,
            redaction_digest,
            evidence_digest: Digest::from_text("unsealed-aws-resilience-hub-assessment"),
        };
        metadata.evidence_digest = metadata.calculate_digest();
        Ok(metadata)
    }

    pub fn application_digest(&self) -> &Digest {
        &self.application_digest
    }

    pub fn application_version_digest(&self) -> &Digest {
        &self.application_version_digest
    }

    pub fn assessment_digest(&self) -> &Digest {
        &self.assessment_digest
    }

    pub fn resiliency_policy_digest(&self) -> &Digest {
        &self.resiliency_policy_digest
    }

    pub const fn status(&self) -> AssessmentStatus {
        self.status
    }

    pub const fn compliance_status(&self) -> ComplianceStatus {
        self.compliance_status
    }

    pub const fn resiliency_score(&self) -> Option<u8> {
        self.resiliency_score
    }

    pub fn rpo_rto(&self) -> &RpoRtoPosture {
        &self.rpo_rto
    }

    pub const fn drift(&self) -> DriftStatus {
        self.drift
    }

    pub fn risk_categories(&self) -> &[RiskEvidence] {
        &self.risk_categories
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn assessed_at(&self) -> Option<DateTime<Utc>> {
        self.assessed_at
    }

    pub const fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    pub fn redaction_digest(&self) -> &Digest {
        &self.redaction_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
            || matches!(self.status, AssessmentStatus::Expired)
    }

    pub fn is_stale_at(&self, now: DateTime<Utc>) -> bool {
        self.assessed_at
            .or(Some(self.observed_at))
            .is_some_and(|assessed_at| {
                now.signed_duration_since(assessed_at)
                    > chrono::Duration::seconds(MAX_ASSESSMENT_AGE_SECONDS)
            })
    }

    pub(crate) fn validate_against(&self, scope: &AwsResilienceHubScope) -> Result<()> {
        if self.application_digest != scope.application().digest()
            || self.application_version_digest != scope.application_version().digest()
            || self.assessment_digest != scope.assessment().digest()
            || self.resiliency_policy_digest != scope.resiliency_policy().digest()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsResilienceHubError::AssessmentDrift);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-assessment-metadata/v1",
            &[
                ("application", self.application_digest.as_str().to_owned()),
                (
                    "application_version",
                    self.application_version_digest.as_str().to_owned(),
                ),
                ("assessment", self.assessment_digest.as_str().to_owned()),
                (
                    "resiliency_policy",
                    self.resiliency_policy_digest.as_str().to_owned(),
                ),
                ("status", format!("{:?}", self.status)),
                ("compliance", format!("{:?}", self.compliance_status)),
                (
                    "score",
                    self.resiliency_score
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                ("rpo_rto", self.rpo_rto.digest().as_str().to_owned()),
                ("drift", format!("{:?}", self.drift)),
                (
                    "risks",
                    self.risk_categories
                        .iter()
                        .map(|risk| risk.evidence_digest.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("observed_at", self.observed_at.to_rfc3339()),
                (
                    "assessed_at",
                    self.assessed_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "expires_at",
                    self.expires_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                ("redaction", self.redaction_digest.as_str().to_owned()),
            ],
        )
    }
}

impl Serialize for AssessmentMetadata {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AssessmentMetadata", 16)?;
        state.serialize_field("applicationDigest", &self.application_digest)?;
        state.serialize_field("applicationVersionDigest", &self.application_version_digest)?;
        state.serialize_field("assessmentDigest", &self.assessment_digest)?;
        state.serialize_field("resiliencyPolicyDigest", &self.resiliency_policy_digest)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("complianceStatus", &self.compliance_status)?;
        state.serialize_field("resiliencyScore", &self.resiliency_score)?;
        state.serialize_field("rpoRto", &self.rpo_rto)?;
        state.serialize_field("drift", &self.drift)?;
        state.serialize_field("riskCategories", &self.risk_categories)?;
        state.serialize_field("observedAt", &self.observed_at)?;
        state.serialize_field("assessedAt", &self.assessed_at)?;
        state.serialize_field("expiresAt", &self.expires_at)?;
        state.serialize_field("redactionDigest", &self.redaction_digest)?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.end()
    }
}

pub type ApplicationProjection = ApplicationMetadata;
pub type AssessmentProjection = AssessmentMetadata;
pub type AwsResilienceHubApplicationMetadata = ApplicationMetadata;
pub type AwsResilienceHubAssessmentMetadata = AssessmentMetadata;
pub type AwsResilienceHubApplicationMetadataInput = ApplicationMetadataInput;
pub type AwsResilienceHubAssessmentMetadataInput = AssessmentMetadataInput;
pub type Cursor = OpaqueCursor;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

impl From<&MissionIdentity> for MissionProjection {
    fn from(value: &MissionIdentity) -> Self {
        Self {
            id_digest: Digest::from_text(value.id()),
            revision: value.revision(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

impl From<&ProjectIdentity> for ProjectProjection {
    fn from(value: &ProjectIdentity) -> Self {
        Self {
            id_digest: Digest::from_text(value.id()),
            revision: value.revision(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

impl From<&WorkProductIdentity> for WorkProductProjection {
    fn from(value: &WorkProductIdentity) -> Self {
        Self {
            id_digest: Digest::from_text(value.id()),
            revision: value.revision(),
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
    pub application_allowlist_digest: Digest,
    pub assessment_allowlist_digest: Digest,
    pub list_apps_digest: Option<Digest>,
    pub describe_app_digest: Option<Digest>,
    pub list_app_assessments_digest: Option<Digest>,
    pub describe_app_assessment_digest: Option<Digest>,
    pub pagination_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub fn validate(&self) -> Result<()> {
        self.plugin_version_digest.validate()?;
        self.contract_digest.validate()?;
        self.provider_digest.validate()?;
        self.permission_digest.validate()?;
        self.consent_digest.validate()?;
        self.scope_digest.validate()?;
        self.application_allowlist_digest.validate()?;
        self.assessment_allowlist_digest.validate()?;
        self.evidence_digest.validate()?;
        for digest in [
            self.list_apps_digest.as_ref(),
            self.describe_app_digest.as_ref(),
            self.list_app_assessments_digest.as_ref(),
            self.describe_app_assessment_digest.as_ref(),
            self.pagination_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        Ok(())
    }
}

pub fn digest_failure(category: &str, detail: &str) -> Digest {
    Digest::from_parts(
        "aws-resilience-hub-failure/v1",
        &[
            ("category", category.to_owned()),
            ("detail", detail.to_owned()),
        ],
    )
}

pub fn digest_pages(digests: &[Digest]) -> Option<Digest> {
    (!digests.is_empty()).then(|| {
        Digest::from_parts(
            "aws-resilience-hub-pages/v1",
            &[(
                "pages",
                digests
                    .iter()
                    .map(|digest| digest.as_str())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        )
    })
}

pub fn bounded_page_size(value: u16) -> Result<()> {
    if value == 0 || value > MAX_PAGE_SIZE {
        Err(AwsResilienceHubError::InvalidRequest)
    } else {
        Ok(())
    }
}

pub fn bounded_page_count(value: u16) -> Result<()> {
    if value == 0 || value > MAX_PAGES {
        Err(AwsResilienceHubError::InvalidRequest)
    } else {
        Ok(())
    }
}
