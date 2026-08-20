use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsSecurityLakeError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_ACCOUNTS, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES, MAX_REGIONS,
    MAX_RESPONSE_BYTES, MAX_SOURCES, MAX_TOKEN_BYTES, MAX_TOKEN_TTL_HOURS,
};

pub const MAX_ARN_BYTES: usize = 1_024;
pub const MAX_EXCEPTION_CATEGORY_BYTES: usize = 128;

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
            Err(AwsSecurityLakeError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsSecurityLakeError::InvalidDigest)
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

fn digest_values<I, S>(domain: &str, values: I) -> Digest
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    Digest::from_parts(
        domain,
        &values
            .into_iter()
            .enumerate()
            .map(|(index, value)| ("value", format!("{index}:{}", value.as_ref())))
            .collect::<Vec<_>>(),
    )
}

macro_rules! identifier_type {
    ($name:ident, $field:literal, $domain:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsSecurityLakeError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, &[("value", self.0.clone())])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsSecurityLakeError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&format!("{}:{}", $field, &self.digest().as_str()[..16]))
                    .finish()
            }
        }
    };
}

identifier_type!(
    OrganizationId,
    "organization",
    "aws-security-lake-organization/v1",
    |value: &str| { valid_identifier(value, MAX_IDENTIFIER_BYTES) }
);
identifier_type!(
    AwsAccountId,
    "account",
    "aws-security-lake-account/v1",
    |value: &str| { value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) }
);
identifier_type!(
    AwsRegion,
    "region",
    "aws-security-lake-region/v1",
    |value: &str| { valid_identifier(value, 64) && value.contains('-') }
);
identifier_type!(
    DataLakeArn,
    "data-lake-arn",
    "aws-security-lake-lake-arn/v1",
    |value: &str| { valid_arn(value) && value.contains(":securitylake:") }
);
identifier_type!(
    SourceName,
    "source",
    "aws-security-lake-source/v1",
    |value: &str| {
        valid_text(value, MAX_IDENTIFIER_BYTES, false)
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
            })
    }
);

#[derive(Clone, Eq, PartialEq)]
pub struct DeploymentIdentity {
    id: String,
    revision: u64,
}

impl DeploymentIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(AwsSecurityLakeError::InvalidScope);
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
            "aws-security-lake-deployment/v1",
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
            Err(AwsSecurityLakeError::InvalidScope)
        }
    }
}

impl fmt::Debug for DeploymentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeploymentIdentity")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

macro_rules! mission_identity {
    ($name:ident, $domain:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            id: String,
            revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                let id = id.into();
                if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
                    return Err(AwsSecurityLakeError::InvalidScope);
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
                    Err(AwsSecurityLakeError::InvalidScope)
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

mission_identity!(MissionIdentity, "aws-security-lake-mission/v1");
mission_identity!(ProjectIdentity, "aws-security-lake-project/v1");
mission_identity!(WorkProductIdentity, "aws-security-lake-work-product/v1");

#[derive(Clone, Eq, PartialEq)]
pub struct DataLakeIdentity {
    region: AwsRegion,
    arn: Option<DataLakeArn>,
}

impl DataLakeIdentity {
    pub fn new(region: AwsRegion, arn: Option<DataLakeArn>) -> Result<Self> {
        region.validate()?;
        Ok(Self { region, arn })
    }

    pub fn for_region(region: AwsRegion) -> Result<Self> {
        Self::new(region, None)
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn arn(&self) -> Option<&DataLakeArn> {
        self.arn.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-data-lake/v1",
            &[
                ("region", self.region.digest().as_str().to_owned()),
                (
                    "arn",
                    self.arn
                        .as_ref()
                        .map_or_else(String::new, |arn| arn.digest().as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.region.validate()?;
        if let Some(arn) = &self.arn {
            arn.validate()?;
        }
        Ok(())
    }
}

impl fmt::Debug for DataLakeIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataLakeIdentity")
            .field("digest", &self.digest())
            .field("region", &self.region)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LakeStatus {
    Completed,
    InProgress,
    Failed,
    Unknown,
}

impl LakeStatus {
    pub fn from_label(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_uppercase().as_str() {
            "COMPLETED" | "COMPLETE" | "ENABLED" => Self::Completed,
            "IN_PROGRESS" | "INPROGRESS" | "PENDING" => Self::InProgress,
            "FAILED" | "ERROR" => Self::Failed,
            _ => Self::Unknown,
        }
    }

    pub fn digest(self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-lake-status/v1",
            &[("status", format!("{self:?}"))],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceState {
    Enabled,
    Disabled,
    Failed,
    Unknown,
}

impl SourceState {
    pub fn from_label(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_uppercase().as_str() {
            "ENABLED" | "ACTIVE" | "HEALTHY" => Self::Enabled,
            "DISABLED" | "INACTIVE" => Self::Disabled,
            "FAILED" | "ERROR" => Self::Failed,
            _ => Self::Unknown,
        }
    }

    pub fn digest(self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-source-state/v1",
            &[("state", format!("{self:?}"))],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionFence {
    pub as_of: DateTime<Utc>,
    pub window_days: u16,
    pub expires_at: DateTime<Utc>,
    pub digest: Digest,
}

impl RetentionFence {
    pub fn new(as_of: DateTime<Utc>, window_days: u16) -> Result<Self> {
        if !(1..=14).contains(&window_days) {
            return Err(AwsSecurityLakeError::InvalidScope);
        }
        let expires_at = as_of + Duration::days(i64::from(window_days));
        let digest = Digest::from_parts(
            "aws-security-lake-retention-fence/v1",
            &[
                ("as_of", as_of.to_rfc3339()),
                ("window_days", window_days.to_string()),
                ("expires_at", expires_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            as_of,
            window_days,
            expires_at,
            digest,
        })
    }

    pub fn accepts(&self, observed_at: DateTime<Utc>) -> bool {
        observed_at <= self.as_of
            && observed_at >= self.as_of - Duration::days(i64::from(self.window_days))
    }

    pub(crate) fn validate_integrity(&self) -> Result<()> {
        let expected = Digest::from_parts(
            "aws-security-lake-retention-fence/v1",
            &[
                ("as_of", self.as_of.to_rfc3339()),
                ("window_days", self.window_days.to_string()),
                ("expires_at", self.expires_at.to_rfc3339()),
            ],
        );
        if !(1..=14).contains(&self.window_days)
            || self.expires_at != self.as_of + Duration::days(i64::from(self.window_days))
            || self.digest != expected
        {
            return Err(AwsSecurityLakeError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsSecurityLakeScope {
    organization: OrganizationId,
    account: AwsAccountId,
    accounts: Vec<AwsAccountId>,
    regions: Vec<AwsRegion>,
    lakes: Vec<DataLakeIdentity>,
    expected_lake_status: Option<LakeStatus>,
    sources: Vec<SourceName>,
    exception_window_days: u16,
    deployment: DeploymentIdentity,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsSecurityLakeScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization: OrganizationId,
        account: AwsAccountId,
        regions: Vec<AwsRegion>,
        lakes: Vec<DataLakeIdentity>,
        sources: Vec<SourceName>,
        exception_window_days: u16,
        deployment: DeploymentIdentity,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            organization,
            account: account.clone(),
            accounts: vec![account],
            regions,
            lakes,
            expected_lake_status: None,
            sources,
            exception_window_days,
            deployment,
            mission,
            project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn with_accounts(mut self, accounts: Vec<AwsAccountId>) -> Result<Self> {
        self.accounts = accounts;
        self.validate()?;
        Ok(self)
    }

    #[must_use]
    pub fn with_expected_lake_status(mut self, status: LakeStatus) -> Self {
        self.expected_lake_status = Some(status);
        self
    }

    pub fn organization(&self) -> &OrganizationId {
        &self.organization
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn accounts(&self) -> &[AwsAccountId] {
        &self.accounts
    }

    pub fn regions(&self) -> &[AwsRegion] {
        &self.regions
    }

    pub fn lakes(&self) -> &[DataLakeIdentity] {
        &self.lakes
    }

    pub const fn expected_lake_status(&self) -> Option<LakeStatus> {
        self.expected_lake_status
    }

    pub fn sources(&self) -> &[SourceName] {
        &self.sources
    }

    pub const fn exception_window_days(&self) -> u16 {
        self.exception_window_days
    }

    pub fn deployment(&self) -> &DeploymentIdentity {
        &self.deployment
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

    pub fn lake_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-lake-allowlist/v1",
            &self
                .lakes
                .iter()
                .map(|lake| ("lake", lake.digest().as_str().to_owned()))
                .collect::<Vec<_>>(),
        )
    }

    pub fn source_digest(&self) -> Digest {
        digest_values(
            "aws-security-lake-source-allowlist/v1",
            self.sources.iter().map(SourceName::as_str),
        )
    }

    pub fn region_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-region-allowlist/v1",
            &self
                .regions
                .iter()
                .map(|region| ("region", region.digest().as_str().to_owned()))
                .collect::<Vec<_>>(),
        )
    }

    pub fn account_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-account-allowlist/v1",
            &self
                .accounts
                .iter()
                .map(|account| ("account", account.digest().as_str().to_owned()))
                .collect::<Vec<_>>(),
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-scope/v1",
            &[
                (
                    "organization",
                    self.organization.digest().as_str().to_owned(),
                ),
                ("account", self.account.digest().as_str().to_owned()),
                ("accounts", self.account_digest().as_str().to_owned()),
                ("regions", self.region_digest().as_str().to_owned()),
                ("lakes", self.lake_digest().as_str().to_owned()),
                (
                    "expected_lake_status",
                    self.expected_lake_status
                        .map_or_else(String::new, |status| format!("{status:?}")),
                ),
                ("sources", self.source_digest().as_str().to_owned()),
                (
                    "exception_window_days",
                    self.exception_window_days.to_string(),
                ),
                ("deployment", self.deployment.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub fn evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-evidence-policy/v1",
            &[
                ("scope", self.digest().as_str().to_owned()),
                ("lake", self.lake_digest().as_str().to_owned()),
                ("sources", self.source_digest().as_str().to_owned()),
                ("retention", self.exception_window_days.to_string()),
            ],
        )
    }

    pub fn retention_fence(&self, as_of: DateTime<Utc>) -> Result<RetentionFence> {
        RetentionFence::new(as_of, self.exception_window_days)
    }

    pub(crate) fn allows_lake(&self, lake_digest: &Digest, region_digest: &Digest) -> bool {
        self.lakes.iter().any(|lake| {
            lake.digest() == *lake_digest
                || (lake.arn().is_none() && lake.region().digest() == *region_digest)
        })
    }

    pub(crate) fn allows_account(&self, account_digest: &Digest) -> bool {
        self.accounts
            .iter()
            .any(|account| account.digest() == *account_digest)
    }

    pub(crate) fn allows_region(&self, region_digest: &Digest) -> bool {
        self.regions
            .iter()
            .any(|region| region.digest() == *region_digest)
    }

    pub(crate) fn allows_source(&self, source_digest: &Digest) -> bool {
        self.sources
            .iter()
            .any(|source| source.digest() == *source_digest)
    }

    pub(crate) fn expected_log_source_digest(
        account_digest: &Digest,
        region_digest: &Digest,
        source_digest: &Digest,
    ) -> Digest {
        Digest::from_parts(
            "aws-security-lake-log-source-projection/v1",
            &[
                ("account", account_digest.as_str().to_owned()),
                ("region", region_digest.as_str().to_owned()),
                ("source", source_digest.as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn allows_log_source(
        &self,
        account_digest: &Digest,
        region_digest: &Digest,
        projection_source_digest: &Digest,
    ) -> bool {
        self.allows_account(account_digest)
            && self.allows_region(region_digest)
            && self.sources.iter().any(|source| {
                Self::expected_log_source_digest(account_digest, region_digest, &source.digest())
                    == *projection_source_digest
            })
    }

    pub(crate) fn allows_data_lake_source(
        &self,
        lake_digest: &Digest,
        account_digest: &Digest,
        source_digest: &Digest,
        region_digest: &Digest,
    ) -> bool {
        self.allows_lake(lake_digest, region_digest)
            && self.allows_account(account_digest)
            && self.allows_region(region_digest)
            && self.allows_source(source_digest)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.organization.validate()?;
        self.account.validate()?;
        if self.accounts.is_empty() || self.accounts.len() > MAX_ACCOUNTS {
            return Err(AwsSecurityLakeError::InvalidScope);
        }
        if self
            .accounts
            .iter()
            .any(|account| account.validate().is_err())
        {
            return Err(AwsSecurityLakeError::InvalidScope);
        }
        if !self.accounts.contains(&self.account)
            || self.regions.is_empty()
            || self.regions.len() > MAX_REGIONS
            || self.lakes.is_empty()
            || self.lakes.len() > MAX_REGIONS
            || self.sources.is_empty()
            || self.sources.len() > MAX_SOURCES
            || !(1..=14).contains(&self.exception_window_days)
        {
            return Err(AwsSecurityLakeError::InvalidScope);
        }
        for region in &self.regions {
            region.validate()?;
        }
        for lake in &self.lakes {
            lake.validate()?;
            if !self.regions.contains(lake.region()) {
                return Err(AwsSecurityLakeError::InvalidScope);
            }
        }
        for source in &self.sources {
            source.validate()?;
        }
        self.deployment.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }
}

impl fmt::Debug for AwsSecurityLakeScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSecurityLakeScope")
            .field("digest", &self.digest())
            .field("organization", &self.organization)
            .field("account", &self.account)
            .field("region_count", &self.regions.len())
            .field("lake_digest", &self.lake_digest())
            .field("source_digest", &self.source_digest())
            .field("exception_window_days", &self.exception_window_days)
            .field("deployment", &self.deployment)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

impl Serialize for AwsSecurityLakeScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsSecurityLakeScope", 10)?;
        state.serialize_field("organizationDigest", &self.organization.digest())?;
        state.serialize_field("accountDigest", &self.account.digest())?;
        state.serialize_field("accountAllowlistDigest", &self.account_digest())?;
        state.serialize_field("regionAllowlistDigest", &self.region_digest())?;
        state.serialize_field("lakeDigest", &self.lake_digest())?;
        state.serialize_field("expectedLakeStatus", &self.expected_lake_status)?;
        state.serialize_field("sourceAllowlistDigest", &self.source_digest())?;
        state.serialize_field("exceptionWindowDays", &self.exception_window_days)?;
        state.serialize_field("deploymentDigest", &self.deployment.digest())?;
        state.serialize_field("missionDigest", &self.mission.digest())?;
        state.serialize_field("projectDigest", &self.project.digest())?;
        state.serialize_field("workProductDigest", &self.work_product.digest())?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4,
}

/// An opaque SigV4 handle. The supplied handle is hashed and zeroized before
/// this value is returned; neither signing material nor the handle is stored.
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
            return Err(AwsSecurityLakeError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-security-lake-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4".to_owned()),
                ("handle", handle.clone()),
                ("revision", revision.to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            kind: SecretKind::Sigv4,
            reference_digest,
            scope_digest: Digest::from_text("unbound-aws-security-lake-secret"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsSecurityLakeScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-security-lake-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4".to_owned()),
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

    pub(crate) fn validate(&self, scope: &AwsSecurityLakeScope) -> Result<()> {
        if self.kind != SecretKind::Sigv4
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsSecurityLakeError::InvalidSecretReference);
        }
        self.reference_digest.validate()
    }
}

pub type SigV4SecretReference = SecretReference;

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("opaque", &true)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SecretReference", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
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
            "aws-security-lake-permissions/v1",
            &[
                ("revision", self.revision.to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let expected = LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<BTreeSet<_>>();
        if self.revision == 0 || self.permissions != expected {
            Err(AwsSecurityLakeError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConsentScope {
    consent_digest: Digest,
    revision: u64,
    expires_at: DateTime<Utc>,
}

impl ConsentScope {
    pub fn for_layer_one(
        opaque_consent: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let mut consent = opaque_consent.into();
        if !valid_text(&consent, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            consent.zeroize();
            return Err(AwsSecurityLakeError::InvalidConsent);
        }
        let consent_digest = Digest::from_parts(
            "aws-security-lake-consent/v1",
            &[
                ("consent", consent.clone()),
                ("revision", revision.to_string()),
                ("expires_at", expires_at.to_rfc3339()),
            ],
        );
        consent.zeroize();
        Ok(Self {
            consent_digest,
            revision,
            expires_at,
        })
    }

    pub fn digest(&self) -> Digest {
        self.consent_digest.clone()
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision == 0 {
            return Err(AwsSecurityLakeError::InvalidConsent);
        }
        self.consent_digest.validate()
    }
}

impl fmt::Debug for ConsentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsentScope")
            .field("consent_digest", &self.consent_digest)
            .field("revision", &self.revision)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsSecurityLakeOperation {
    ListDataLakes,
    ListLogSources,
    GetDataLakeSources,
    ListDataLakeExceptions,
}

impl AwsSecurityLakeOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListDataLakes => "ListDataLakes",
            Self::ListLogSources => "ListLogSources",
            Self::GetDataLakeSources => "GetDataLakeSources",
            Self::ListDataLakeExceptions => "ListDataLakeExceptions",
        }
    }

    pub const fn path(self) -> &'static str {
        match self {
            Self::ListDataLakes => "/v1/datalakes",
            Self::ListLogSources => "/v1/datalake/logsources/list",
            Self::GetDataLakeSources => "/v1/datalake/sources",
            Self::ListDataLakeExceptions => "/v1/datalake/exceptions",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    token_digest: Digest,
    operation: Option<AwsSecurityLakeOperation>,
    scope_digest: Option<Digest>,
    filter_digest: Option<Digest>,
    page_number: u16,
    issued_at: DateTime<Utc>,
}

impl OpaquePageToken {
    pub fn new(raw_token: impl Into<String>) -> Result<Self> {
        Self::new_at(raw_token, Utc::now())
    }

    pub fn new_at(raw_token: impl Into<String>, issued_at: DateTime<Utc>) -> Result<Self> {
        let mut token = raw_token.into();
        if !valid_text(&token, MAX_TOKEN_BYTES, true) {
            token.zeroize();
            return Err(AwsSecurityLakeError::InvalidIdentifier {
                field: "pagination-token",
            });
        }
        let token_digest = Digest::from_parts(
            "aws-security-lake-pagination-token/v1",
            &[("token", token.clone())],
        );
        token.zeroize();
        Ok(Self {
            token_digest,
            operation: None,
            scope_digest: None,
            filter_digest: None,
            page_number: 0,
            issued_at,
        })
    }

    pub fn bind(
        &self,
        operation: AwsSecurityLakeOperation,
        scope_digest: Digest,
        filter_digest: Digest,
        page_number: u16,
    ) -> Result<Self> {
        if page_number == 0 || page_number > MAX_PAGES.saturating_add(1) {
            return Err(AwsSecurityLakeError::PaginationPartial);
        }
        let mut bound = self.clone();
        bound.operation = Some(operation);
        bound.scope_digest = Some(scope_digest);
        bound.filter_digest = Some(filter_digest);
        bound.page_number = page_number;
        Ok(bound)
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    pub fn binding_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-pagination-binding/v1",
            &[
                (
                    "operation",
                    self.operation
                        .map_or_else(String::new, |operation| operation.as_str().to_owned()),
                ),
                (
                    "scope",
                    self.scope_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "filter",
                    self.filter_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("page", self.page_number.to_string()),
            ],
        )
    }

    pub fn validate_for(
        &self,
        operation: AwsSecurityLakeOperation,
        scope_digest: &Digest,
        filter_digest: &Digest,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if now > self.issued_at + Duration::hours(MAX_TOKEN_TTL_HOURS) || self.page_number == 0 {
            return Err(AwsSecurityLakeError::PaginationExpired);
        }
        if self.operation != Some(operation)
            || self.scope_digest.as_ref() != Some(scope_digest)
            || self.filter_digest.as_ref() != Some(filter_digest)
        {
            return Err(AwsSecurityLakeError::PaginationDrift);
        }
        Ok(())
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest())
            .field("page_number", &self.page_number)
            .field("issued_at", &self.issued_at)
            .finish()
    }
}

impl Serialize for OpaquePageToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("OpaquePageToken", 4)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest())?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.serialize_field("issuedAt", &self.issued_at)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListDataLakesFilter {
    regions: Vec<AwsRegion>,
}

impl ListDataLakesFilter {
    pub fn new(regions: Vec<AwsRegion>) -> Result<Self> {
        let filter = Self { regions };
        filter.validate()?;
        Ok(filter)
    }

    pub fn regions(&self) -> &[AwsRegion] {
        &self.regions
    }

    pub fn digest(&self) -> Digest {
        digest_values(
            "aws-security-lake-list-lakes-filter/v1",
            self.regions.iter().map(AwsRegion::as_str),
        )
    }

    fn validate(&self) -> Result<()> {
        if self.regions.is_empty() || self.regions.len() > MAX_REGIONS {
            return Err(AwsSecurityLakeError::RequestOutsideAllowlist);
        }
        for region in &self.regions {
            region.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListLogSourcesFilter {
    accounts: Vec<AwsAccountId>,
    regions: Vec<AwsRegion>,
    sources: Vec<SourceName>,
}

impl ListLogSourcesFilter {
    pub fn new(
        accounts: Vec<AwsAccountId>,
        regions: Vec<AwsRegion>,
        sources: Vec<SourceName>,
    ) -> Result<Self> {
        let filter = Self {
            accounts,
            regions,
            sources,
        };
        filter.validate()?;
        Ok(filter)
    }

    pub fn accounts(&self) -> &[AwsAccountId] {
        &self.accounts
    }

    pub fn regions(&self) -> &[AwsRegion] {
        &self.regions
    }

    pub fn sources(&self) -> &[SourceName] {
        &self.sources
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-list-sources-filter/v1",
            &[
                (
                    "accounts",
                    self.accounts
                        .iter()
                        .map(AwsAccountId::as_str)
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
                (
                    "regions",
                    self.regions
                        .iter()
                        .map(AwsRegion::as_str)
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
                (
                    "sources",
                    self.sources
                        .iter()
                        .map(SourceName::as_str)
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        if self.accounts.is_empty()
            || self.accounts.len() > MAX_ACCOUNTS
            || self.regions.is_empty()
            || self.regions.len() > MAX_REGIONS
            || self.sources.is_empty()
            || self.sources.len() > MAX_SOURCES
        {
            return Err(AwsSecurityLakeError::RequestOutsideAllowlist);
        }
        for account in &self.accounts {
            account.validate()?;
        }
        for region in &self.regions {
            region.validate()?;
        }
        for source in &self.sources {
            source.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetDataLakeSourcesFilter {
    accounts: Vec<AwsAccountId>,
}

impl GetDataLakeSourcesFilter {
    pub fn new(accounts: Vec<AwsAccountId>) -> Result<Self> {
        let filter = Self { accounts };
        filter.validate()?;
        Ok(filter)
    }

    pub fn accounts(&self) -> &[AwsAccountId] {
        &self.accounts
    }

    pub fn digest(&self) -> Digest {
        digest_values(
            "aws-security-lake-get-sources-filter/v1",
            self.accounts.iter().map(AwsAccountId::as_str),
        )
    }

    fn validate(&self) -> Result<()> {
        if self.accounts.is_empty() || self.accounts.len() > MAX_ACCOUNTS {
            return Err(AwsSecurityLakeError::RequestOutsideAllowlist);
        }
        for account in &self.accounts {
            account.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListDataLakeExceptionsFilter {
    regions: Vec<AwsRegion>,
}

impl ListDataLakeExceptionsFilter {
    pub fn new(regions: Vec<AwsRegion>) -> Result<Self> {
        let filter = Self { regions };
        filter.validate()?;
        Ok(filter)
    }

    pub fn regions(&self) -> &[AwsRegion] {
        &self.regions
    }

    pub fn digest(&self) -> Digest {
        digest_values(
            "aws-security-lake-list-exceptions-filter/v1",
            self.regions.iter().map(AwsRegion::as_str),
        )
    }

    fn validate(&self) -> Result<()> {
        if self.regions.is_empty() || self.regions.len() > MAX_REGIONS {
            return Err(AwsSecurityLakeError::RequestOutsideAllowlist);
        }
        for region in &self.regions {
            region.validate()?;
        }
        Ok(())
    }
}

macro_rules! request_type {
    ($name:ident, $filter:ty, $operation:expr) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            scope: AwsSecurityLakeScope,
            filter: $filter,
            cursor: Option<OpaquePageToken>,
            request_digest: Digest,
        }

        impl $name {
            pub fn new(
                scope: &AwsSecurityLakeScope,
                filter: $filter,
                cursor: Option<OpaquePageToken>,
            ) -> Result<Self> {
                scope.validate()?;
                let filter_digest = filter.digest();
                if let Some(cursor) = &cursor {
                    if cursor.page_number() > MAX_PAGES {
                        return Err(AwsSecurityLakeError::PaginationPartial);
                    }
                    cursor.validate_for($operation, &scope.digest(), &filter_digest, Utc::now())?;
                }
                let request_digest = Digest::from_parts(
                    concat!("aws-security-lake-", stringify!($name), "/v1"),
                    &[
                        ("scope", scope.digest().as_str().to_owned()),
                        ("filter", filter_digest.as_str().to_owned()),
                        (
                            "cursor",
                            cursor.as_ref().map_or_else(String::new, |cursor| {
                                cursor.token_digest().as_str().to_owned()
                            }),
                        ),
                        (
                            "page",
                            cursor.as_ref().map_or_else(
                                || "1".to_owned(),
                                |cursor| cursor.page_number().to_string(),
                            ),
                        ),
                    ],
                );
                Ok(Self {
                    scope: scope.clone(),
                    filter,
                    cursor,
                    request_digest,
                })
            }

            pub fn scope(&self) -> &AwsSecurityLakeScope {
                &self.scope
            }

            pub fn filter(&self) -> &$filter {
                &self.filter
            }

            pub fn cursor(&self) -> Option<&OpaquePageToken> {
                self.cursor.as_ref()
            }

            pub fn request_digest(&self) -> &Digest {
                &self.request_digest
            }

            pub fn filter_digest(&self) -> Digest {
                self.filter.digest()
            }

            pub fn page_number(&self) -> u16 {
                self.cursor.as_ref().map_or(1, OpaquePageToken::page_number)
            }

            pub fn path_and_query(&self) -> String {
                let cursor = self.cursor.as_ref().map_or_else(String::new, |cursor| {
                    cursor.token_digest().as_str().to_owned()
                });
                format!(
                    "{}?scopeDigest={}&filterDigest={}&nextTokenDigest={}",
                    $operation.path(),
                    self.scope.digest(),
                    self.filter.digest(),
                    cursor
                )
            }

            pub fn operation(&self) -> AwsSecurityLakeOperation {
                $operation
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("scope_digest", &self.scope.digest())
                    .field("filter_digest", &self.filter.digest())
                    .field("cursor", &self.cursor)
                    .field("request_digest", &self.request_digest)
                    .finish()
            }
        }
    };
}

request_type!(
    ListDataLakesRequest,
    ListDataLakesFilter,
    AwsSecurityLakeOperation::ListDataLakes
);
request_type!(
    ListLogSourcesRequest,
    ListLogSourcesFilter,
    AwsSecurityLakeOperation::ListLogSources
);
request_type!(
    GetDataLakeSourcesRequest,
    GetDataLakeSourcesFilter,
    AwsSecurityLakeOperation::GetDataLakeSources
);
request_type!(
    ListDataLakeExceptionsRequest,
    ListDataLakeExceptionsFilter,
    AwsSecurityLakeOperation::ListDataLakeExceptions
);

impl ListDataLakesRequest {
    pub fn for_scope(scope: &AwsSecurityLakeScope) -> Result<Self> {
        Self::new(
            scope,
            ListDataLakesFilter::new(scope.regions().to_vec())?,
            None,
        )
    }
}

impl ListLogSourcesRequest {
    pub fn for_scope(scope: &AwsSecurityLakeScope) -> Result<Self> {
        Self::new(
            scope,
            ListLogSourcesFilter::new(
                scope.accounts().to_vec(),
                scope.regions().to_vec(),
                scope.sources().to_vec(),
            )?,
            None,
        )
    }
}

impl GetDataLakeSourcesRequest {
    pub fn for_scope(scope: &AwsSecurityLakeScope) -> Result<Self> {
        Self::new(
            scope,
            GetDataLakeSourcesFilter::new(scope.accounts().to_vec())?,
            None,
        )
    }
}

impl ListDataLakeExceptionsRequest {
    pub fn for_scope(scope: &AwsSecurityLakeScope) -> Result<Self> {
        Self::new(
            scope,
            ListDataLakeExceptionsFilter::new(scope.regions().to_vec())?,
            None,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataLakeProjection {
    pub lake_digest: Digest,
    pub region_digest: Digest,
    pub status: LakeStatus,
    pub status_digest: Digest,
    pub encryption_posture_digest: Digest,
    pub retention_posture_digest: Digest,
    pub update_status_digest: Digest,
}

impl DataLakeProjection {
    pub fn new(
        region: AwsRegion,
        lake_arn: DataLakeArn,
        status: LakeStatus,
        encryption_reference: Option<impl AsRef<str>>,
        retention_days: Option<u32>,
        update_status: Option<LakeStatus>,
    ) -> Result<Self> {
        region.validate()?;
        lake_arn.validate()?;
        let lake_digest = DataLakeIdentity::new(region.clone(), Some(lake_arn))?.digest();
        let encryption_posture_digest = Digest::from_parts(
            "aws-security-lake-encryption-posture/v1",
            &[(
                "reference",
                encryption_reference.map_or_else(String::new, |value| value.as_ref().to_owned()),
            )],
        );
        let retention_posture_digest = Digest::from_parts(
            "aws-security-lake-retention-posture/v1",
            &[(
                "days",
                retention_days.map_or_else(String::new, |days| days.to_string()),
            )],
        );
        let update_status_digest =
            update_status.map_or_else(|| Digest::from_text("no-update-status"), LakeStatus::digest);
        Ok(Self {
            lake_digest,
            region_digest: region.digest(),
            status,
            status_digest: status.digest(),
            encryption_posture_digest,
            retention_posture_digest,
            update_status_digest,
        })
    }

    pub fn fixture(region: AwsRegion, lake_arn: DataLakeArn, status: LakeStatus) -> Result<Self> {
        Self::new(region, lake_arn, status, None::<String>, None, None)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-lake-projection-record/v1",
            &[
                ("lake", self.lake_digest.as_str().to_owned()),
                ("region", self.region_digest.as_str().to_owned()),
                ("status", self.status_digest.as_str().to_owned()),
                (
                    "encryption",
                    self.encryption_posture_digest.as_str().to_owned(),
                ),
                (
                    "retention",
                    self.retention_posture_digest.as_str().to_owned(),
                ),
                ("update", self.update_status_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogSourceProjection {
    pub source_digest: Digest,
    pub account_digest: Digest,
    pub region_digest: Digest,
    pub source_type_digest: Digest,
    pub state: SourceState,
    pub state_digest: Digest,
    pub last_observed_revision: u64,
    pub event_class_digest: Digest,
}

impl LogSourceProjection {
    pub fn new<I, S>(
        account: AwsAccountId,
        region: AwsRegion,
        source: SourceName,
        source_type: impl AsRef<str>,
        state: SourceState,
        last_observed_revision: u64,
        event_classes: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        account.validate()?;
        region.validate()?;
        source.validate()?;
        let source_digest = Digest::from_parts(
            "aws-security-lake-log-source-projection/v1",
            &[
                ("account", account.digest().as_str().to_owned()),
                ("region", region.digest().as_str().to_owned()),
                ("source", source.digest().as_str().to_owned()),
            ],
        );
        let source_type_digest = Digest::from_text(source_type.as_ref());
        let event_class_digest =
            digest_values("aws-security-lake-event-class-metadata/v1", event_classes);
        Ok(Self {
            source_digest,
            account_digest: account.digest(),
            region_digest: region.digest(),
            source_type_digest,
            state,
            state_digest: state.digest(),
            last_observed_revision,
            event_class_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-log-source-projection-record/v1",
            &[
                ("source", self.source_digest.as_str().to_owned()),
                ("account", self.account_digest.as_str().to_owned()),
                ("region", self.region_digest.as_str().to_owned()),
                ("type", self.source_type_digest.as_str().to_owned()),
                ("state", self.state_digest.as_str().to_owned()),
                ("revision", self.last_observed_revision.to_string()),
                ("classes", self.event_class_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataLakeSourceProjection {
    pub lake_digest: Digest,
    pub account_digest: Digest,
    pub source_digest: Digest,
    pub region_digest: Digest,
    pub event_class_digest: Digest,
    pub state: SourceState,
    pub state_digest: Digest,
    pub source_status_digest: Digest,
}

impl DataLakeSourceProjection {
    pub fn new<I, S>(
        lake: DataLakeIdentity,
        account: AwsAccountId,
        source: SourceName,
        event_classes: I,
        state: SourceState,
        resource_status: impl AsRef<str>,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        lake.validate()?;
        account.validate()?;
        source.validate()?;
        Ok(Self {
            lake_digest: lake.digest(),
            account_digest: account.digest(),
            source_digest: source.digest(),
            region_digest: lake.region().digest(),
            event_class_digest: digest_values(
                "aws-security-lake-data-lake-event-class-metadata/v1",
                event_classes,
            ),
            state,
            state_digest: state.digest(),
            source_status_digest: Digest::from_text(resource_status.as_ref()),
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-data-lake-source-projection-record/v1",
            &[
                ("lake", self.lake_digest.as_str().to_owned()),
                ("account", self.account_digest.as_str().to_owned()),
                ("source", self.source_digest.as_str().to_owned()),
                ("region", self.region_digest.as_str().to_owned()),
                ("classes", self.event_class_digest.as_str().to_owned()),
                ("state_value", format!("{:?}", self.state)),
                ("state", self.state_digest.as_str().to_owned()),
                ("status", self.source_status_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataLakeExceptionProjection {
    pub exception_digest: Digest,
    pub region_digest: Digest,
    pub category_digest: Digest,
    pub remediation_digest: Digest,
    pub observed_at: DateTime<Utc>,
    pub retention_expires_at: DateTime<Utc>,
}

impl DataLakeExceptionProjection {
    pub fn new(
        region: AwsRegion,
        category: impl AsRef<str>,
        remediation: impl AsRef<str>,
        observed_at: DateTime<Utc>,
        retention: &RetentionFence,
    ) -> Result<Self> {
        region.validate()?;
        if !valid_text(category.as_ref(), MAX_EXCEPTION_CATEGORY_BYTES, true)
            || !valid_text(remediation.as_ref(), MAX_IDENTIFIER_BYTES * 2, true)
        {
            return Err(AwsSecurityLakeError::InvalidIdentifier {
                field: "exception-category",
            });
        }
        let category_digest = Digest::from_text(category.as_ref());
        let remediation_digest = Digest::from_text(remediation.as_ref());
        let exception_digest = Digest::from_parts(
            "aws-security-lake-exception-projection/v1",
            &[
                ("region", region.digest().as_str().to_owned()),
                ("category", category_digest.as_str().to_owned()),
                ("remediation", remediation_digest.as_str().to_owned()),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            exception_digest,
            region_digest: region.digest(),
            category_digest,
            remediation_digest,
            observed_at,
            retention_expires_at: observed_at + Duration::days(i64::from(retention.window_days)),
        })
    }

    pub fn validate_retention(&self, retention: &RetentionFence) -> Result<()> {
        if retention.accepts(self.observed_at) {
            Ok(())
        } else {
            Err(AwsSecurityLakeError::RetentionGap)
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-exception-projection-record/v1",
            &[
                ("exception", self.exception_digest.as_str().to_owned()),
                ("region", self.region_digest.as_str().to_owned()),
                ("category", self.category_digest.as_str().to_owned()),
                ("remediation", self.remediation_digest.as_str().to_owned()),
                ("observed_at", self.observed_at.to_rfc3339()),
                ("expires_at", self.retention_expires_at.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Partial,
    PaginationLoop,
    RetentionGap,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    Expired,
    RegistrationRevoked,
    Tampered,
}

impl EvidenceState {
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

pub(crate) fn validate_page_size<T>(items: &[T], response_bytes: u64) -> Result<()> {
    if items.len() > usize::from(MAX_PAGE_SIZE) {
        return Err(AwsSecurityLakeError::RequestOutsideAllowlist);
    }
    if response_bytes > MAX_RESPONSE_BYTES {
        return Err(AwsSecurityLakeError::Transport(
            crate::error::AwsSecurityLakeTransportError::ResponseTooLarge,
        ));
    }
    Ok(())
}

fn bind_next_token(
    token: Option<OpaquePageToken>,
    operation: AwsSecurityLakeOperation,
    scope: &AwsSecurityLakeScope,
    filter: &Digest,
    page_number: u16,
) -> Result<Option<OpaquePageToken>> {
    token
        .map(|token| token.bind(operation, scope.digest(), filter.clone(), page_number))
        .transpose()
}

macro_rules! response_type {
    ($name:ident, $request:ty, $items:ident, $item:ty, $operation:expr) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            pub $items: Vec<$item>,
            pub next_token: Option<OpaquePageToken>,
            pub scope_digest: Digest,
            pub filter_digest: Digest,
            pub request_digest: Digest,
            pub page_digest: Digest,
            pub response_bytes: u64,
            pub provenance: TransportProvenance,
        }

        impl $name {
            pub fn new(
                request: &$request,
                $items: Vec<$item>,
                next_token: Option<OpaquePageToken>,
                response_bytes: u64,
                provenance: TransportProvenance,
            ) -> Result<Self> {
                validate_page_size(&$items, response_bytes)?;
                let filter_digest = request.filter_digest();
                let page_number = request.page_number().saturating_add(1);
                let next_token = bind_next_token(
                    next_token,
                    $operation,
                    request.scope(),
                    &filter_digest,
                    page_number,
                )?;
                let page_digest = Digest::from_parts(
                    concat!("aws-security-lake-", stringify!($name), "/v1"),
                    &[
                        ("request", request.request_digest().as_str().to_owned()),
                        (
                            "items",
                            $items
                                .iter()
                                .map(|item| item.digest().as_str().to_owned())
                                .collect::<Vec<_>>()
                                .join("\u{1f}"),
                        ),
                        (
                            "next",
                            next_token.as_ref().map_or_else(String::new, |token| {
                                token.token_digest().as_str().to_owned()
                            }),
                        ),
                        ("bytes", response_bytes.to_string()),
                        ("provenance", provenance.as_str().to_owned()),
                    ],
                );
                Ok(Self {
                    $items,
                    next_token,
                    scope_digest: request.scope().digest(),
                    filter_digest,
                    request_digest: request.request_digest().clone(),
                    page_digest,
                    response_bytes,
                    provenance,
                })
            }

            pub fn validate_integrity(&self, request: &$request, now: DateTime<Utc>) -> Result<()> {
                validate_page_size(&self.$items, self.response_bytes)?;
                if self.scope_digest != request.scope().digest()
                    || self.filter_digest != request.filter_digest()
                    || self.request_digest != *request.request_digest()
                    || self.provenance.native()
                    || self.provenance.connected()
                    || self.provenance.first_party()
                {
                    return Err(AwsSecurityLakeError::TamperedEvidence);
                }
                if let Some(token) = &self.next_token {
                    token.validate_for($operation, &self.scope_digest, &self.filter_digest, now)?;
                    if token.page_number() != request.page_number().saturating_add(1) {
                        return Err(AwsSecurityLakeError::PaginationDrift);
                    }
                }
                let expected = Digest::from_parts(
                    concat!("aws-security-lake-", stringify!($name), "/v1"),
                    &[
                        ("request", request.request_digest().as_str().to_owned()),
                        (
                            "items",
                            self.$items
                                .iter()
                                .map(|item| item.digest().as_str().to_owned())
                                .collect::<Vec<_>>()
                                .join("\u{1f}"),
                        ),
                        (
                            "next",
                            self.next_token.as_ref().map_or_else(String::new, |token| {
                                token.token_digest().as_str().to_owned()
                            }),
                        ),
                        ("bytes", self.response_bytes.to_string()),
                        ("provenance", self.provenance.as_str().to_owned()),
                    ],
                );
                if expected != self.page_digest {
                    return Err(AwsSecurityLakeError::TamperedEvidence);
                }
                Ok(())
            }

            pub fn next_token(&self) -> Option<&OpaquePageToken> {
                self.next_token.as_ref()
            }
        }
    };
}

response_type!(
    ListDataLakesResponse,
    ListDataLakesRequest,
    data_lakes,
    DataLakeProjection,
    AwsSecurityLakeOperation::ListDataLakes
);
response_type!(
    ListLogSourcesResponse,
    ListLogSourcesRequest,
    sources,
    LogSourceProjection,
    AwsSecurityLakeOperation::ListLogSources
);
response_type!(
    GetDataLakeSourcesResponse,
    GetDataLakeSourcesRequest,
    data_lake_sources,
    DataLakeSourceProjection,
    AwsSecurityLakeOperation::GetDataLakeSources
);
response_type!(
    ListDataLakeExceptionsResponse,
    ListDataLakeExceptionsRequest,
    exceptions,
    DataLakeExceptionProjection,
    AwsSecurityLakeOperation::ListDataLakeExceptions
);

pub type ListDataLakesPage = ListDataLakesResponse;
pub type ListLogSourcesPage = ListLogSourcesResponse;
pub type GetDataLakeSourcesPage = GetDataLakeSourcesResponse;
pub type ListDataLakeExceptionsPage = ListDataLakeExceptionsResponse;
