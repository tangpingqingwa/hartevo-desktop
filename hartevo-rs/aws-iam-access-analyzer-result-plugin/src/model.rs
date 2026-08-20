//! Exact AWS IAM Access Analyzer scope, bounded request models, and redacted
//! finding evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use serde_json::Value;

use crate::AwsIamAccessAnalyzerError;
use crate::error::Result;
use crate::{
    CONTRACT_DIGEST_INPUT, MAX_BACKOFF_MILLIS, MAX_CRITERION_VALUES, MAX_CURSOR_BYTES, MAX_FILTERS,
    MAX_FINDING_ID_BYTES, MAX_FINDINGS, MAX_PAGE_SIZE, MAX_PAGES, MAX_POLICY_BYTES,
    MAX_RETRY_ATTEMPTS, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, digest_serialized,
    sha256_hex, valid_digest, valid_identifier, valid_text,
};

/// A lower-case SHA-256 digest. It carries no raw policy, principal, finding,
/// or credential material.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_hex(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if valid_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AwsIamAccessAnalyzerError::InvalidInput("digest"))
        }
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self(sha256_hex(value.as_ref()))
    }

    pub fn from_bytes(value: impl AsRef<[u8]>) -> Self {
        Self::from_text(value)
    }

    pub fn from_serialized<T: Serialize>(value: &T) -> Self {
        digest_serialized(value)
    }

    pub fn from_parts(label: &str, values: &[(&str, String)]) -> Self {
        let mut canonical = Vec::with_capacity(64 + values.len() * 32);
        append_part(&mut canonical, label);
        for (name, value) in values {
            append_part(&mut canonical, name);
            append_part(&mut canonical, value);
        }
        Self::from_bytes(canonical)
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
        formatter.write_str(&self.0)
    }
}

fn append_part(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

macro_rules! identifier_type {
    ($name:ident, $max:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if valid_identifier(&value, $max) {
                    Ok(Self(value))
                } else {
                    Err(AwsIamAccessAnalyzerError::InvalidInput(stringify!($name)))
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }
    };
}

identifier_type!(ProjectId, 256);
identifier_type!(MissionId, 256);
identifier_type!(ConsentId, 256);

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationId {
    id: String,
    revision: Revision,
}

impl RegistrationId {
    pub fn new(value: impl Into<String>, revision: u64) -> Result<Self> {
        let id = value.into();
        if !valid_identifier(&id, 256) {
            return Err(AwsIamAccessAnalyzerError::InvalidInput("registration id"));
        }
        Ok(Self {
            id,
            revision: Revision::new(revision)?,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

impl fmt::Debug for RegistrationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistrationId")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(Self(value))
        } else {
            Err(AwsIamAccessAnalyzerError::InvalidInput("aws account id"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AwsAccountId")
            .field(&self.0)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into().to_ascii_lowercase();
        if valid_text(&value, 128, false)
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            Ok(Self(value))
        } else {
            Err(AwsIamAccessAnalyzerError::InvalidInput("aws region"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AwsRegion").field(&self.0).finish()
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AnalyzerArn(String);

impl AnalyzerArn {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let parts = value.split(':').collect::<Vec<_>>();
        let valid = parts.len() == 6
            && parts[0] == "arn"
            && parts[1] == "aws"
            && parts[2] == "access-analyzer"
            && !parts[3].is_empty()
            && parts[4].len() == 12
            && parts[4].bytes().all(|byte| byte.is_ascii_digit())
            && parts[5].strip_prefix("analyzer/").is_some_and(|name| {
                !name.is_empty() && name.len() <= 255 && !name.chars().any(char::is_whitespace)
            });
        if valid {
            Ok(Self(value))
        } else {
            Err(AwsIamAccessAnalyzerError::InvalidInput("analyzer arn"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn region(&self) -> Result<AwsRegion> {
        AwsRegion::new(self.0.split(':').nth(3).unwrap_or_default())
    }

    pub fn account_id(&self) -> Result<AwsAccountId> {
        AwsAccountId::new(self.0.split(':').nth(4).unwrap_or_default())
    }
}

impl fmt::Debug for AnalyzerArn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AnalyzerArn").field(&self.0).finish()
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ResourceArn(String);

impl ResourceArn {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.starts_with("arn:") && valid_text(&value, 1024, false) {
            Ok(Self(value))
        } else {
            Err(AwsIamAccessAnalyzerError::InvalidInput("resource arn"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(AwsIamAccessAnalyzerError::InvalidInput("revision"))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Timestamp(u64);

impl Timestamp {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(AwsIamAccessAnalyzerError::InvalidInput("timestamp"))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn millis(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionIdentity {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionIdentity {
    pub fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectIdentity {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectIdentity {
    pub fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentIdentity {
    pub id: ConsentId,
    pub revision: Revision,
    pub digest: Digest,
}

impl ConsentIdentity {
    pub fn new(id: ConsentId, revision: Revision, digest: Digest) -> Result<Self> {
        Ok(Self {
            id,
            revision,
            digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AnalyzerType {
    External,
    Internal,
    Unused,
}

impl AnalyzerType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::External => "EXTERNAL",
            Self::Internal => "INTERNAL",
            Self::Unused => "UNUSED",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyType {
    IdentityPolicy,
    ResourcePolicy,
    ServiceControlPolicy,
    ResourceControlPolicy,
}

impl PolicyType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentityPolicy => "IDENTITY_POLICY",
            Self::ResourcePolicy => "RESOURCE_POLICY",
            Self::ServiceControlPolicy => "SERVICE_CONTROL_POLICY",
            Self::ResourceControlPolicy => "RESOURCE_CONTROL_POLICY",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyResourceType {
    S3Bucket,
    S3AccessPoint,
    S3MultiRegionAccessPoint,
    S3ObjectLambdaAccessPoint,
    IamAssumeRolePolicyDocument,
    DynamoDbTable,
}

impl PolicyResourceType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::S3Bucket => "AWS::S3::Bucket",
            Self::S3AccessPoint => "AWS::S3::AccessPoint",
            Self::S3MultiRegionAccessPoint => "AWS::S3::MultiRegionAccessPoint",
            Self::S3ObjectLambdaAccessPoint => "AWS::S3ObjectLambda::AccessPoint",
            Self::IamAssumeRolePolicyDocument => "AWS::IAM::AssumeRolePolicyDocument",
            Self::DynamoDbTable => "AWS::DynamoDB::Table",
        }
    }

    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        match value.as_ref() {
            "AWS::S3::Bucket" => Ok(Self::S3Bucket),
            "AWS::S3::AccessPoint" => Ok(Self::S3AccessPoint),
            "AWS::S3::MultiRegionAccessPoint" => Ok(Self::S3MultiRegionAccessPoint),
            "AWS::S3ObjectLambda::AccessPoint" => Ok(Self::S3ObjectLambdaAccessPoint),
            "AWS::IAM::AssumeRolePolicyDocument" => Ok(Self::IamAssumeRolePolicyDocument),
            "AWS::DynamoDB::Table" => Ok(Self::DynamoDbTable),
            _ => Err(AwsIamAccessAnalyzerError::InvalidInput(
                "policy resource type",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceType {
    S3Bucket,
    IamRole,
    SqsQueue,
    LambdaFunction,
    LambdaLayerVersion,
    KmsKey,
    SecretsManagerSecret,
    EfsFileSystem,
    Ec2Snapshot,
    EcrRepository,
    RdsDbSnapshot,
    RdsDbClusterSnapshot,
    SnsTopic,
    S3ExpressDirectoryBucket,
    DynamoDbTable,
    DynamoDbStream,
    IamUser,
}

impl ResourceType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::S3Bucket => "AWS::S3::Bucket",
            Self::IamRole => "AWS::IAM::Role",
            Self::SqsQueue => "AWS::SQS::Queue",
            Self::LambdaFunction => "AWS::Lambda::Function",
            Self::LambdaLayerVersion => "AWS::Lambda::LayerVersion",
            Self::KmsKey => "AWS::KMS::Key",
            Self::SecretsManagerSecret => "AWS::SecretsManager::Secret",
            Self::EfsFileSystem => "AWS::EFS::FileSystem",
            Self::Ec2Snapshot => "AWS::EC2::Snapshot",
            Self::EcrRepository => "AWS::ECR::Repository",
            Self::RdsDbSnapshot => "AWS::RDS::DBSnapshot",
            Self::RdsDbClusterSnapshot => "AWS::RDS::DBClusterSnapshot",
            Self::SnsTopic => "AWS::SNS::Topic",
            Self::S3ExpressDirectoryBucket => "AWS::S3Express::DirectoryBucket",
            Self::DynamoDbTable => "AWS::DynamoDB::Table",
            Self::DynamoDbStream => "AWS::DynamoDB::Stream",
            Self::IamUser => "AWS::IAM::User",
        }
    }

    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let value = value.as_ref();
        let all = [
            Self::S3Bucket,
            Self::IamRole,
            Self::SqsQueue,
            Self::LambdaFunction,
            Self::LambdaLayerVersion,
            Self::KmsKey,
            Self::SecretsManagerSecret,
            Self::EfsFileSystem,
            Self::Ec2Snapshot,
            Self::EcrRepository,
            Self::RdsDbSnapshot,
            Self::RdsDbClusterSnapshot,
            Self::SnsTopic,
            Self::S3ExpressDirectoryBucket,
            Self::DynamoDbTable,
            Self::DynamoDbStream,
            Self::IamUser,
        ];
        all.into_iter()
            .find(|candidate| candidate.as_str() == value)
            .ok_or(AwsIamAccessAnalyzerError::InvalidInput("resource type"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceScope {
    pub arn: ResourceArn,
    pub resource_type: ResourceType,
    pub owner_account: AwsAccountId,
    pub revision: Revision,
    pub resource_digest: Digest,
}

impl ResourceScope {
    pub fn new(
        arn: ResourceArn,
        resource_type: ResourceType,
        owner_account: AwsAccountId,
        revision: Revision,
    ) -> Self {
        let resource_digest = arn.digest();
        Self {
            arn,
            resource_type,
            owner_account,
            revision,
            resource_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsIamAccessAnalyzerScope {
    pub account: AwsAccountId,
    pub region: AwsRegion,
    pub analyzer: AnalyzerArn,
    pub analyzer_type: AnalyzerType,
    pub policy_type: PolicyType,
    pub policy_resource_type: Option<PolicyResourceType>,
    pub policy_revision: Revision,
    pub resource: ResourceScope,
    pub mission: MissionIdentity,
    pub project: ProjectIdentity,
    pub consent: ConsentIdentity,
    scope_digest: Digest,
}

pub type AwsIamScope = AwsIamAccessAnalyzerScope;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsIamAccessAnalyzerScopeInput {
    pub account: AwsAccountId,
    pub region: AwsRegion,
    pub analyzer: AnalyzerArn,
    pub analyzer_type: AnalyzerType,
    pub policy_type: PolicyType,
    pub policy_resource_type: Option<PolicyResourceType>,
    pub policy_revision: Revision,
    pub resource: ResourceScope,
    pub mission: MissionIdentity,
    pub project: ProjectIdentity,
    pub consent: ConsentIdentity,
}

impl AwsIamAccessAnalyzerScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        analyzer: AnalyzerArn,
        analyzer_type: AnalyzerType,
        policy_type: PolicyType,
        policy_resource_type: Option<PolicyResourceType>,
        policy_revision: Revision,
        resource: ResourceScope,
        mission: MissionIdentity,
        project: ProjectIdentity,
        consent: ConsentIdentity,
    ) -> Result<Self> {
        Self::from_input(AwsIamAccessAnalyzerScopeInput {
            account,
            region,
            analyzer,
            analyzer_type,
            policy_type,
            policy_resource_type,
            policy_revision,
            resource,
            mission,
            project,
            consent,
        })
    }

    pub fn from_input(input: AwsIamAccessAnalyzerScopeInput) -> Result<Self> {
        if input.analyzer.account_id()? != input.account || input.analyzer.region()? != input.region
        {
            return Err(AwsIamAccessAnalyzerError::ScopeMismatch);
        }
        if matches!(input.policy_type, PolicyType::ResourcePolicy)
            != input.policy_resource_type.is_some()
        {
            return Err(AwsIamAccessAnalyzerError::InvalidInput(
                "resource policy type binding",
            ));
        }
        let scope_digest = Digest::from_parts(
            "aws-iam-access-analyzer-scope/v1",
            &[
                ("account", input.account.as_str().to_owned()),
                ("region", input.region.as_str().to_owned()),
                ("analyzer", input.analyzer.as_str().to_owned()),
                ("analyzer_type", input.analyzer_type.as_str().to_owned()),
                ("policy_type", input.policy_type.as_str().to_owned()),
                (
                    "policy_resource_type",
                    input
                        .policy_resource_type
                        .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                ),
                ("policy_revision", input.policy_revision.get().to_string()),
                (
                    "resource",
                    input.resource.resource_digest.as_str().to_owned(),
                ),
                (
                    "resource_type",
                    input.resource.resource_type.as_str().to_owned(),
                ),
                (
                    "resource_owner",
                    input.resource.owner_account.as_str().to_owned(),
                ),
                (
                    "resource_revision",
                    input.resource.revision.get().to_string(),
                ),
                ("mission", input.mission.id.as_str().to_owned()),
                ("mission_revision", input.mission.revision.get().to_string()),
                ("project", input.project.id.as_str().to_owned()),
                ("project_revision", input.project.revision.get().to_string()),
                ("consent", input.consent.id.as_str().to_owned()),
                ("consent_revision", input.consent.revision.get().to_string()),
                ("consent_digest", input.consent.digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            account: input.account,
            region: input.region,
            analyzer: input.analyzer,
            analyzer_type: input.analyzer_type,
            policy_type: input.policy_type,
            policy_resource_type: input.policy_resource_type,
            policy_revision: input.policy_revision,
            resource: input.resource,
            mission: input.mission,
            project: input.project,
            consent: input.consent,
            scope_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: Revision,
    pub permissions: BTreeSet<String>,
    pub digest: Digest,
}

impl PermissionSnapshot {
    pub fn new(revision: Revision, permissions: impl IntoIterator<Item = String>) -> Result<Self> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if permissions.is_empty()
            || permissions.iter().any(|permission| {
                !matches!(
                    permission.as_str(),
                    "access-analyzer:ListFindings"
                        | "access-analyzer:ValidatePolicy"
                        | "mission.scope"
                        | "consent.scope"
                )
            })
        {
            return Err(AwsIamAccessAnalyzerError::InvalidInput(
                "permission snapshot",
            ));
        }
        let digest = Digest::from_parts(
            "aws-iam-access-analyzer-permissions/v1",
            &[
                ("revision", revision.get().to_string()),
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join(","),
                ),
            ],
        );
        Ok(Self {
            revision,
            permissions,
            digest,
        })
    }

    pub fn for_layer_one(revision: u64) -> Result<Self> {
        Self::new(
            Revision::new(revision)?,
            [
                "access-analyzer:ListFindings".to_owned(),
                "access-analyzer:ValidatePolicy".to_owned(),
                "mission.scope".to_owned(),
                "consent.scope".to_owned(),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.revision, self.permissions.clone())?;
        if expected.digest == self.digest {
            Ok(())
        } else {
            Err(AwsIamAccessAnalyzerError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Iam,
}

/// Opaque host-keyring reference. It intentionally does not implement
/// `Serialize`; the original reference ID is consumed into a digest and is
/// never retained or printed.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    kind: SecretKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revision: self.revision,
            kind: self.kind,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.revision == other.revision
            && self.kind == other.kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("kind", &self.kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl AsRef<str>,
        scope: &AwsIamAccessAnalyzerScope,
        revision: u64,
    ) -> Result<Self> {
        let reference_id = reference_id.as_ref();
        if !valid_text(reference_id, 512, false) {
            return Err(AwsIamAccessAnalyzerError::InvalidInput("secret reference"));
        }
        let revision = Revision::new(revision)?;
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "aws-iam-access-analyzer-sigv4-reference/v1",
            &[
                ("reference", reference_id.to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
                ("revision", revision.get().to_string()),
                ("kind", "sigv4_iam".to_owned()),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            revision,
            kind: SecretKind::Sigv4Iam,
            revoked: false,
        })
    }

    pub fn for_scope(
        reference_id: impl AsRef<str>,
        scope: &AwsIamAccessAnalyzerScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new(reference_id, scope, revision)
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision.get()
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(AwsIamAccessAnalyzerError::RegistrationRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderIdentity {
    pub id: String,
    pub revision: Revision,
    pub api_revision: String,
    pub digest: Digest,
}

impl ProviderIdentity {
    pub fn new(revision: u64, id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, 256) {
            return Err(AwsIamAccessAnalyzerError::InvalidInput("provider id"));
        }
        let revision = Revision::new(revision)?;
        let api_revision = PROVIDER_API_REVISION.to_owned();
        let digest = Digest::from_parts(
            "aws-iam-access-analyzer-provider/v1",
            &[
                ("id", id.clone()),
                ("revision", revision.get().to_string()),
                ("api", api_revision.clone()),
            ],
        );
        Ok(Self {
            id,
            revision,
            api_revision,
            digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.revision.get(), self.id.clone())?;
        if expected == *self && self.api_revision == PROVIDER_API_REVISION {
            Ok(())
        } else {
            Err(AwsIamAccessAnalyzerError::InvalidRegistration)
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    #[default]
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

pub type ProviderProvenance = TransportProvenance;

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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum FindingType {
    ExternalAccess,
    InternalAccess,
    UnusedIamRole,
    UnusedIamUserAccessKey,
    UnusedIamUserPassword,
    UnusedPermission,
}

impl FindingType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExternalAccess => "ExternalAccess",
            Self::InternalAccess => "InternalAccess",
            Self::UnusedIamRole => "UnusedIAMRole",
            Self::UnusedIamUserAccessKey => "UnusedIAMUserAccessKey",
            Self::UnusedIamUserPassword => "UnusedIAMUserPassword",
            Self::UnusedPermission => "UnusedPermission",
        }
    }

    pub const fn analyzer_type(self) -> AnalyzerType {
        match self {
            Self::ExternalAccess => AnalyzerType::External,
            Self::InternalAccess => AnalyzerType::Internal,
            Self::UnusedIamRole
            | Self::UnusedIamUserAccessKey
            | Self::UnusedIamUserPassword
            | Self::UnusedPermission => AnalyzerType::Unused,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FindingStatus {
    Active,
    Archived,
    Resolved,
}

impl FindingStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Archived => "ARCHIVED",
            Self::Resolved => "RESOLVED",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessExposure {
    Public,
    CrossAccount,
    Internal,
    Unused,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicyFindingType {
    Error,
    SecurityWarning,
    Warning,
    Suggestion,
}

impl PolicyFindingType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::SecurityWarning => "SECURITY_WARNING",
            Self::Warning => "WARNING",
            Self::Suggestion => "SUGGESTION",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerError,
    Timeout,
    MalformedResponse,
    MissingFixture,
    BlockedEnv,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "reason")]
pub enum AnalysisState {
    Complete,
    EmptyNotProof,
    Partial(PartialReason),
    ProviderUnknown(ProviderUnknownReason),
    BlockedEnv,
}

impl AnalysisState {
    pub const fn is_certifying(self) -> bool {
        false
    }

    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete | Self::EmptyNotProof)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageBudgetExhausted,
    FindingBudgetExhausted,
    RetentionGap,
    MalformedFinding,
    RetryBudgetExhausted,
    CursorEndedUnexpectedly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderUnknownReason {
    ServerError,
    Timeout,
    ProviderUnknown,
    MissingFixture,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingFilterKey {
    FindingType,
    Status,
    ResourceType,
    Resource,
    ResourceOwnerAccount,
    IsPublic,
}

impl FindingFilterKey {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FindingType => "findingType",
            Self::Status => "status",
            Self::ResourceType => "resourceType",
            Self::Resource => "resource",
            Self::ResourceOwnerAccount => "resourceOwnerAccount",
            Self::IsPublic => "isPublic",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterCriterion {
    pub contains: Vec<String>,
    pub eq: Vec<String>,
    pub neq: Vec<String>,
    pub exists: Option<bool>,
}

impl FilterCriterion {
    pub fn new(
        contains: impl IntoIterator<Item = String>,
        eq: impl IntoIterator<Item = String>,
        neq: impl IntoIterator<Item = String>,
        exists: Option<bool>,
    ) -> Result<Self> {
        let criterion = Self {
            contains: contains.into_iter().collect(),
            eq: eq.into_iter().collect(),
            neq: neq.into_iter().collect(),
            exists,
        };
        criterion.validate()?;
        Ok(criterion)
    }

    pub fn equals(value: impl Into<String>) -> Result<Self> {
        Self::new([], [value.into()], [], None)
    }

    pub fn contains_value(value: impl Into<String>) -> Result<Self> {
        Self::new([value.into()], [], [], None)
    }

    pub fn not_equals(value: impl Into<String>) -> Result<Self> {
        Self::new([], [], [value.into()], None)
    }

    pub fn exists(value: bool) -> Result<Self> {
        Self::new([], [], [], Some(value))
    }

    pub fn validate(&self) -> Result<()> {
        let total = self.contains.len() + self.eq.len() + self.neq.len();
        if total == 0 || total > MAX_CRITERION_VALUES {
            return Err(AwsIamAccessAnalyzerError::InvalidInput("filter criterion"));
        }
        if self
            .contains
            .iter()
            .chain(self.eq.iter())
            .chain(self.neq.iter())
            .any(|value| !valid_text(value, 512, true))
        {
            return Err(AwsIamAccessAnalyzerError::InvalidInput("filter value"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingFilter {
    pub key: FindingFilterKey,
    pub criterion: FilterCriterion,
}

impl FindingFilter {
    pub fn new(key: FindingFilterKey, criterion: FilterCriterion) -> Result<Self> {
        criterion.validate()?;
        if matches!(key, FindingFilterKey::IsPublic)
            && criterion
                .contains
                .iter()
                .chain(criterion.eq.iter())
                .chain(criterion.neq.iter())
                .any(|value| !matches!(value.as_str(), "true" | "false"))
        {
            return Err(AwsIamAccessAnalyzerError::InvalidInput("isPublic filter"));
        }
        Ok(Self { key, criterion })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FindingFilters(Vec<FindingFilter>);

impl FindingFilters {
    pub fn new(filters: impl IntoIterator<Item = FindingFilter>) -> Result<Self> {
        let filters = filters.into_iter().collect::<Vec<_>>();
        if filters.len() > MAX_FILTERS {
            return Err(AwsIamAccessAnalyzerError::InvalidInput("finding filters"));
        }
        let mut keys = BTreeSet::new();
        for filter in &filters {
            filter.criterion.validate()?;
            if !keys.insert(filter.key.as_str()) {
                return Err(AwsIamAccessAnalyzerError::InvalidInput(
                    "duplicate filter key",
                ));
            }
        }
        Ok(Self(filters))
    }

    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn as_slice(&self) -> &[FindingFilter] {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

impl Default for FindingFilters {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SortAttribute {
    CreatedAt,
    UpdatedAt,
    FindingType,
    Status,
    ResourceType,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SortOrder {
    Asc,
    Desc,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SortCriteria {
    pub attribute_name: SortAttribute,
    pub order_by: SortOrder,
}

impl SortCriteria {
    pub const fn new(attribute_name: SortAttribute, order_by: SortOrder) -> Self {
        Self {
            attribute_name,
            order_by,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageBounds {
    pub max_pages: u16,
    pub max_findings: usize,
    pub page_size: u32,
}

impl PageBounds {
    pub fn new(max_pages: u16, max_findings: usize, page_size: u32) -> Result<Self> {
        if max_pages == 0
            || max_pages > MAX_PAGES
            || max_findings == 0
            || max_findings > MAX_FINDINGS
            || page_size == 0
            || page_size > MAX_PAGE_SIZE
        {
            return Err(AwsIamAccessAnalyzerError::InvalidInput("page bounds"));
        }
        Ok(Self {
            max_pages,
            max_findings,
            page_size,
        })
    }
}

impl Default for PageBounds {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            max_findings: MAX_FINDINGS,
            page_size: MAX_PAGE_SIZE,
        }
    }
}

/// A provider cursor whose raw token is retained only inside the provider
/// boundary. Serialization and Debug expose its digest and binding only.
pub struct OpaqueCursor {
    token: String,
    digest: Digest,
    binding_digest: Digest,
}

impl Clone for OpaqueCursor {
    fn clone(&self) -> Self {
        Self {
            token: self.token.clone(),
            digest: self.digest.clone(),
            binding_digest: self.binding_digest.clone(),
        }
    }
}

impl PartialEq for OpaqueCursor {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest && self.binding_digest == other.binding_digest
    }
}

impl Eq for OpaqueCursor {}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("digest", &self.digest)
            .field("binding_digest", &self.binding_digest)
            .finish_non_exhaustive()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OpaqueCursor", 2)?;
        state.serialize_field("digest", &self.digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.end()
    }
}

impl OpaqueCursor {
    pub fn new(token: impl Into<String>, binding_digest: Digest) -> Result<Self> {
        let token = token.into();
        if !valid_text(&token, MAX_CURSOR_BYTES, false) {
            return Err(AwsIamAccessAnalyzerError::InvalidInput("cursor"));
        }
        let digest = Digest::from_text(&token);
        Ok(Self {
            token,
            digest,
            binding_digest,
        })
    }

    pub fn fixture(token: impl Into<String>, binding_digest: Digest) -> Result<Self> {
        Self::new(token, binding_digest)
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub(crate) fn matches(&self, binding_digest: &Digest) -> bool {
        &self.binding_digest == binding_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListFindingsV2Request {
    pub scope_digest: Digest,
    pub analyzer_arn: AnalyzerArn,
    pub filter: FindingFilters,
    pub sort: Option<SortCriteria>,
    pub max_results: u32,
    pub max_pages: u16,
    pub max_findings: usize,
    pub next_cursor: Option<OpaqueCursor>,
    pub permission_digest: Digest,
    pub mission_revision: Revision,
    pub binding_digest: Digest,
    pub request_digest: Digest,
}

impl ListFindingsV2Request {
    pub fn new(
        scope: &AwsIamAccessAnalyzerScope,
        filter: FindingFilters,
        sort: Option<SortCriteria>,
        bounds: PageBounds,
        next_cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        let binding_digest = Digest::from_parts(
            "aws-iam-list-findings-binding/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("analyzer", scope.analyzer.as_str().to_owned()),
                ("filter", filter.digest().as_str().to_owned()),
                (
                    "sort",
                    sort.as_ref().map_or_else(
                        || "none".to_owned(),
                        |value| value.digest().as_str().to_owned(),
                    ),
                ),
                ("page_size", bounds.page_size.to_string()),
                ("max_pages", bounds.max_pages.to_string()),
                ("max_findings", bounds.max_findings.to_string()),
            ],
        );
        if next_cursor
            .as_ref()
            .is_some_and(|cursor| !cursor.matches(&binding_digest))
        {
            return Err(AwsIamAccessAnalyzerError::CursorBindingMismatch);
        }
        let request_digest = Digest::from_parts(
            "aws-iam-list-findings-request/v1",
            &[
                ("binding", binding_digest.as_str().to_owned()),
                (
                    "cursor",
                    next_cursor.as_ref().map_or_else(
                        || "none".to_owned(),
                        |cursor| cursor.digest().as_str().to_owned(),
                    ),
                ),
                ("permission", scope.digest().as_str().to_owned()),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            analyzer_arn: scope.analyzer.clone(),
            filter,
            sort,
            max_results: bounds.page_size,
            max_pages: bounds.max_pages,
            max_findings: bounds.max_findings,
            next_cursor,
            permission_digest: Digest::from_text("permission-fence-placeholder"),
            mission_revision: scope.mission.revision,
            binding_digest,
            request_digest,
        })
    }

    pub fn with_permission_digest(mut self, permission_digest: Digest) -> Self {
        self.permission_digest = permission_digest;
        self.request_digest = Digest::from_parts(
            "aws-iam-list-findings-request/v1",
            &[
                ("binding", self.binding_digest.as_str().to_owned()),
                (
                    "cursor",
                    self.next_cursor.as_ref().map_or_else(
                        || "none".to_owned(),
                        |cursor| cursor.digest().as_str().to_owned(),
                    ),
                ),
                ("permission", self.permission_digest.as_str().to_owned()),
            ],
        );
        self
    }

    pub fn cursor_binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn next_page(&self, cursor: OpaqueCursor) -> Result<Self> {
        if !cursor.matches(&self.binding_digest) {
            return Err(AwsIamAccessAnalyzerError::CursorBindingMismatch);
        }
        let mut next = self.clone();
        next.next_cursor = Some(cursor);
        next.request_digest = Digest::from_parts(
            "aws-iam-list-findings-request/v1",
            &[
                ("binding", next.binding_digest.as_str().to_owned()),
                (
                    "cursor",
                    next.next_cursor.as_ref().map_or_else(
                        || "none".to_owned(),
                        |value| value.digest().as_str().to_owned(),
                    ),
                ),
                ("permission", next.permission_digest.as_str().to_owned()),
            ],
        );
        Ok(next)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Locale {
    De,
    En,
    Es,
    Fr,
    It,
    Ja,
    Ko,
    PtBr,
    ZhCn,
    ZhTw,
}

impl Locale {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::De => "DE",
            Self::En => "EN",
            Self::Es => "ES",
            Self::Fr => "FR",
            Self::It => "IT",
            Self::Ja => "JA",
            Self::Ko => "KO",
            Self::PtBr => "PT_BR",
            Self::ZhCn => "ZH_CN",
            Self::ZhTw => "ZH_TW",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatePolicyRequest {
    pub scope_digest: Digest,
    pub policy_type: PolicyType,
    pub policy_resource_type: Option<PolicyResourceType>,
    pub policy_revision: Revision,
    pub policy_digest: Digest,
    pub policy_bytes: usize,
    pub locale: Locale,
    pub max_results: u32,
    pub max_pages: u16,
    pub max_findings: usize,
    pub next_cursor: Option<OpaqueCursor>,
    pub permission_digest: Digest,
    pub binding_digest: Digest,
    pub request_digest: Digest,
}

impl ValidatePolicyRequest {
    pub fn new(
        scope: &AwsIamAccessAnalyzerScope,
        policy_document: impl AsRef<str>,
        locale: Locale,
        bounds: PageBounds,
        next_cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        let policy_document = policy_document.as_ref();
        if policy_document.len() > MAX_POLICY_BYTES {
            return Err(AwsIamAccessAnalyzerError::InvalidInput("policy bytes"));
        }
        let value = serde_json::from_str::<Value>(policy_document)
            .map_err(|_| AwsIamAccessAnalyzerError::InvalidPolicyDocument)?;
        if !value.is_object() {
            return Err(AwsIamAccessAnalyzerError::InvalidPolicyDocument);
        }
        let policy_digest = Digest::from_text(policy_document);
        let binding_digest = Digest::from_parts(
            "aws-iam-validate-policy-binding/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("policy", policy_digest.as_str().to_owned()),
                ("policy_type", scope.policy_type.as_str().to_owned()),
                (
                    "resource_type",
                    scope
                        .policy_resource_type
                        .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                ),
                ("locale", locale.as_str().to_owned()),
                ("page_size", bounds.page_size.to_string()),
                ("max_pages", bounds.max_pages.to_string()),
                ("max_findings", bounds.max_findings.to_string()),
            ],
        );
        if next_cursor
            .as_ref()
            .is_some_and(|cursor| !cursor.matches(&binding_digest))
        {
            return Err(AwsIamAccessAnalyzerError::CursorBindingMismatch);
        }
        let request_digest = Digest::from_parts(
            "aws-iam-validate-policy-request/v1",
            &[
                ("binding", binding_digest.as_str().to_owned()),
                (
                    "cursor",
                    next_cursor.as_ref().map_or_else(
                        || "none".to_owned(),
                        |cursor| cursor.digest().as_str().to_owned(),
                    ),
                ),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            policy_type: scope.policy_type,
            policy_resource_type: scope.policy_resource_type,
            policy_revision: scope.policy_revision,
            policy_digest,
            policy_bytes: policy_document.len(),
            locale,
            max_results: bounds.page_size,
            max_pages: bounds.max_pages,
            max_findings: bounds.max_findings,
            next_cursor,
            permission_digest: Digest::from_text("permission-fence-placeholder"),
            binding_digest,
            request_digest,
        })
    }

    pub fn with_permission_digest(mut self, permission_digest: Digest) -> Self {
        self.permission_digest = permission_digest;
        self.request_digest = Digest::from_parts(
            "aws-iam-validate-policy-request/v1",
            &[
                ("binding", self.binding_digest.as_str().to_owned()),
                (
                    "cursor",
                    self.next_cursor.as_ref().map_or_else(
                        || "none".to_owned(),
                        |cursor| cursor.digest().as_str().to_owned(),
                    ),
                ),
                ("permission", self.permission_digest.as_str().to_owned()),
            ],
        );
        self
    }

    pub fn cursor_binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn next_page(&self, cursor: OpaqueCursor) -> Result<Self> {
        if !cursor.matches(&self.binding_digest) {
            return Err(AwsIamAccessAnalyzerError::CursorBindingMismatch);
        }
        let mut next = self.clone();
        next.next_cursor = Some(cursor);
        next.request_digest = Digest::from_parts(
            "aws-iam-validate-policy-request/v1",
            &[
                ("binding", next.binding_digest.as_str().to_owned()),
                (
                    "cursor",
                    next.next_cursor.as_ref().map_or_else(
                        || "none".to_owned(),
                        |value| value.digest().as_str().to_owned(),
                    ),
                ),
                ("permission", next.permission_digest.as_str().to_owned()),
            ],
        );
        Ok(next)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingSummaryV2 {
    pub id: String,
    pub finding_type: FindingType,
    pub status: FindingStatus,
    pub resource_type: ResourceType,
    pub resource_owner_account: AwsAccountId,
    pub resource_digest: Option<Digest>,
    pub analyzed_at: Timestamp,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub action_count: u16,
    pub action_digest: Option<Digest>,
    pub error_digest: Option<Digest>,
    pub exposure: AccessExposure,
    pub finding_digest: Digest,
}

impl FindingSummaryV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        finding_type: FindingType,
        status: FindingStatus,
        resource_type: ResourceType,
        resource_owner_account: AwsAccountId,
        resource_digest: Option<Digest>,
        analyzed_at: Timestamp,
        created_at: Timestamp,
        updated_at: Timestamp,
        action_count: u16,
        action_digest: Option<Digest>,
        error_digest: Option<Digest>,
        exposure: AccessExposure,
    ) -> Result<Self> {
        let id = id.into();
        if !valid_text(&id, MAX_FINDING_ID_BYTES, false) {
            return Err(AwsIamAccessAnalyzerError::InvalidFinding);
        }
        if action_count == 0 && action_digest.is_some() {
            return Err(AwsIamAccessAnalyzerError::InvalidFinding);
        }
        if action_count > 0 && action_digest.is_none() {
            return Err(AwsIamAccessAnalyzerError::InvalidFinding);
        }
        if !exposure_matches(finding_type, exposure) {
            return Err(AwsIamAccessAnalyzerError::InvalidFinding);
        }
        let finding_digest = Digest::from_parts(
            "aws-iam-finding-summary-v2/v1",
            &[
                ("id", id.clone()),
                ("finding_type", finding_type.as_str().to_owned()),
                ("status", status.as_str().to_owned()),
                ("resource_type", resource_type.as_str().to_owned()),
                ("owner", resource_owner_account.as_str().to_owned()),
                (
                    "resource",
                    resource_digest
                        .as_ref()
                        .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                ),
                ("analyzed", analyzed_at.millis().to_string()),
                ("created", created_at.millis().to_string()),
                ("updated", updated_at.millis().to_string()),
                ("action_count", action_count.to_string()),
                (
                    "action_digest",
                    action_digest
                        .as_ref()
                        .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                ),
                (
                    "error_digest",
                    error_digest
                        .as_ref()
                        .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                ),
                ("exposure", format!("{exposure:?}")),
            ],
        );
        Ok(Self {
            id,
            finding_type,
            status,
            resource_type,
            resource_owner_account,
            resource_digest,
            analyzed_at,
            created_at,
            updated_at,
            action_count,
            action_digest,
            error_digest,
            exposure,
            finding_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(
            self.id.clone(),
            self.finding_type,
            self.status,
            self.resource_type,
            self.resource_owner_account.clone(),
            self.resource_digest.clone(),
            self.analyzed_at,
            self.created_at,
            self.updated_at,
            self.action_count,
            self.action_digest.clone(),
            self.error_digest.clone(),
            self.exposure,
        )?;
        if expected.finding_digest == self.finding_digest {
            Ok(())
        } else {
            Err(AwsIamAccessAnalyzerError::TamperedEvidence)
        }
    }

    pub fn is_public(&self) -> bool {
        self.exposure == AccessExposure::Public
    }
}

fn exposure_matches(finding_type: FindingType, exposure: AccessExposure) -> bool {
    match finding_type {
        FindingType::ExternalAccess => {
            matches!(
                exposure,
                AccessExposure::Public | AccessExposure::CrossAccount
            )
        }
        FindingType::InternalAccess => exposure == AccessExposure::Internal,
        FindingType::UnusedIamRole
        | FindingType::UnusedIamUserAccessKey
        | FindingType::UnusedIamUserPassword
        | FindingType::UnusedPermission => exposure == AccessExposure::Unused,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyLocation {
    pub path_digest: Digest,
    pub start_line: u32,
    pub start_column: u32,
    pub start_offset: u32,
    pub end_line: u32,
    pub end_column: u32,
    pub end_offset: u32,
}

impl PolicyLocation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: impl AsRef<str>,
        start_line: u32,
        start_column: u32,
        start_offset: u32,
        end_line: u32,
        end_column: u32,
        end_offset: u32,
    ) -> Result<Self> {
        let path = path.as_ref();
        if !valid_text(path, 1024, false)
            || start_line == 0
            || start_column == 0
            || end_line < start_line
            || (end_line == start_line && end_column < start_column)
        {
            return Err(AwsIamAccessAnalyzerError::InvalidPolicyFinding);
        }
        Ok(Self {
            path_digest: Digest::from_text(path),
            start_line,
            start_column,
            start_offset,
            end_line,
            end_column,
            end_offset,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatePolicyFinding {
    pub finding_type: PolicyFindingType,
    pub issue_code: String,
    pub finding_details_digest: Digest,
    pub learn_more_digest: Digest,
    pub locations: Vec<PolicyLocation>,
    pub finding_digest: Digest,
}

pub type PolicyValidationFinding = ValidatePolicyFinding;
pub type FindingSummary = FindingSummaryV2;

impl ValidatePolicyFinding {
    pub fn new(
        finding_type: PolicyFindingType,
        issue_code: impl Into<String>,
        finding_details: impl AsRef<str>,
        learn_more_link: impl AsRef<str>,
        locations: Vec<PolicyLocation>,
    ) -> Result<Self> {
        let issue_code = issue_code.into();
        if !valid_identifier(&issue_code, 256) || locations.len() > 32 {
            return Err(AwsIamAccessAnalyzerError::InvalidPolicyFinding);
        }
        let finding_details_digest = Digest::from_text(finding_details.as_ref());
        let learn_more_digest = Digest::from_text(learn_more_link.as_ref());
        let finding_digest = Digest::from_parts(
            "aws-iam-validate-policy-finding/v1",
            &[
                ("type", finding_type.as_str().to_owned()),
                ("issue", issue_code.clone()),
                ("details", finding_details_digest.as_str().to_owned()),
                ("learn_more", learn_more_digest.as_str().to_owned()),
                (
                    "locations",
                    Digest::from_serialized(&locations).as_str().to_owned(),
                ),
            ],
        );
        Ok(Self {
            finding_type,
            issue_code,
            finding_details_digest,
            learn_more_digest,
            locations,
            finding_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Digest::from_parts(
            "aws-iam-validate-policy-finding/v1",
            &[
                ("type", self.finding_type.as_str().to_owned()),
                ("issue", self.issue_code.clone()),
                ("details", self.finding_details_digest.as_str().to_owned()),
                ("learn_more", self.learn_more_digest.as_str().to_owned()),
                (
                    "locations",
                    Digest::from_serialized(&self.locations).as_str().to_owned(),
                ),
            ],
        );
        if expected == self.finding_digest {
            Ok(())
        } else {
            Err(AwsIamAccessAnalyzerError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub max_backoff_millis: u64,
}

impl RetryPolicy {
    pub fn new(max_attempts: u8, max_backoff_millis: u64) -> Result<Self> {
        if max_attempts == 0
            || max_attempts > MAX_RETRY_ATTEMPTS
            || max_backoff_millis > MAX_BACKOFF_MILLIS
        {
            return Err(AwsIamAccessAnalyzerError::InvalidInput("retry policy"));
        }
        Ok(Self {
            max_attempts,
            max_backoff_millis,
        })
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            max_backoff_millis: 1_000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryEvidence {
    pub attempts: u8,
    pub retried: bool,
    pub errors: Vec<ProviderErrorKind>,
    pub backoff_millis: u64,
}

impl RetryEvidence {
    pub fn new(attempts: u8, errors: Vec<ProviderErrorKind>) -> Result<Self> {
        if attempts == 0 || attempts > MAX_RETRY_ATTEMPTS || errors.len() > usize::from(attempts) {
            return Err(AwsIamAccessAnalyzerError::InvalidInput("retry evidence"));
        }
        Ok(Self {
            attempts,
            retried: attempts > 1,
            errors,
            backoff_millis: 0,
        })
    }

    pub fn with_backoff_millis(mut self, backoff_millis: u64) -> Result<Self> {
        if backoff_millis > crate::MAX_BACKOFF_MILLIS {
            return Err(AwsIamAccessAnalyzerError::InvalidInput("retry backoff"));
        }
        self.backoff_millis = backoff_millis;
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityClaim {
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adoption: bool,
    pub least_privilege_certified: bool,
}

impl CapabilityClaim {
    pub const fn layer_one() -> Self {
        Self {
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adoption: false,
            least_privilege_certified: false,
        }
    }
}

/// Useful in tests and examples; it is intentionally all digest-only.
pub fn fixture_scope() -> AwsIamAccessAnalyzerScope {
    let account = AwsAccountId::new("123456789012").expect("fixture account");
    let region = AwsRegion::new("us-east-1").expect("fixture region");
    let analyzer = AnalyzerArn::new(
        "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/fixture-analyzer",
    )
    .expect("fixture analyzer");
    let resource = ResourceScope::new(
        ResourceArn::new("arn:aws:s3:::fixture-resource").expect("fixture resource"),
        ResourceType::S3Bucket,
        account.clone(),
        Revision::new(1).expect("resource revision"),
    );
    AwsIamAccessAnalyzerScope::new(
        account,
        region,
        analyzer,
        AnalyzerType::External,
        PolicyType::ResourcePolicy,
        Some(PolicyResourceType::S3Bucket),
        Revision::new(7).expect("policy revision"),
        resource,
        MissionIdentity::new(
            MissionId::new("mission-1").expect("mission"),
            Revision::new(3).expect("mission revision"),
        ),
        ProjectIdentity::new(
            ProjectId::new("project-1").expect("project"),
            Revision::new(4).expect("project revision"),
        ),
        ConsentIdentity::new(
            ConsentId::new("consent-1").expect("consent"),
            Revision::new(5).expect("consent revision"),
            Digest::from_text("consent-1"),
        )
        .expect("consent identity"),
    )
    .expect("fixture scope")
}

pub fn contract_input_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

pub fn version_digest() -> Digest {
    Digest::from_text(PLUGIN_VERSION)
}

pub fn provider_id_digest() -> Digest {
    Digest::from_text(PROVIDER_ID)
}

pub fn policy_digest_from_text(policy: &str) -> Digest {
    Digest::from_text(policy)
}

pub fn serialized_digest<T: Serialize>(value: &T) -> Digest {
    Digest::from_serialized(value)
}

pub fn empty_map_digest() -> Digest {
    Digest::from_serialized(&BTreeMap::<String, String>::new())
}
