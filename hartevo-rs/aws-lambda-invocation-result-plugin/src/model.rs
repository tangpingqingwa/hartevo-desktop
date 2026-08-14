//! Exact AWS Lambda scope, bounded invocation evidence, and digest models.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::{
    AwsLambdaInvocationResultError, MAX_ALIAS_BYTES, MAX_ASYNCHRONOUS_INPUT_BYTES,
    MAX_BACKOFF_MILLIS, MAX_FUNCTION_NAME_BYTES, MAX_FUNCTION_TIMEOUT_MILLIS, MAX_IDENTIFIER_BYTES,
    MAX_REGION_BYTES, MAX_RESPONSE_BYTES, MAX_RETRY_ATTEMPTS, MAX_SYNCHRONOUS_INPUT_BYTES,
    MAX_VERSION_BYTES, digest_serialized, sha256_hex, validate_digest, validate_identifier,
    validate_text,
};

/// A lower-case SHA-256 digest. It carries no raw payload or secret material.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_hex(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_digest(&value, "digest")?;
        Ok(Self(value))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self(sha256_hex(value.as_ref()))
    }

    pub fn from_bytes(value: impl AsRef<[u8]>) -> Self {
        Self::from_text(value)
    }

    pub fn from_serialized<T: Serialize>(value: &T) -> Self {
        Self(digest_serialized(value))
    }

    pub fn from_parts(label: &str, values: &[(&str, String)]) -> Self {
        let mut canonical = String::with_capacity(64 + values.len() * 24);
        canonical.push_str(label);
        for (name, value) in values {
            canonical.push('|');
            canonical.push_str(name);
            canonical.push(':');
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(value);
        }
        Self::from_text(canonical)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        validate_digest(&self.0, "digest")
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

macro_rules! define_revision_identity {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub id: String,
            pub revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                let id = id.into();
                validate_identifier(&id, $field)?;
                if revision == 0 {
                    return Err(AwsLambdaInvocationResultError::InvalidScope);
                }
                Ok(Self { id, revision })
            }

            pub fn validate(&self) -> Result<()> {
                Self::new(&self.id, self.revision).map(|_| ())
            }

            pub fn as_str(&self) -> &str {
                &self.id
            }

            pub fn digest(&self) -> Digest {
                Digest::from_serialized(self)
            }
        }
    };
}

define_revision_identity!(InputId, "inputId");
define_revision_identity!(ConfigId, "configId");
define_revision_identity!(MissionIdentity, "missionId");
define_revision_identity!(ProjectIdentity, "projectId");
define_revision_identity!(WorkProductIdentity, "workProductId");
define_revision_identity!(RegistrationId, "registrationId");

/// Semantic version for the plugin registration binding.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

/// An AWS account identifier. It is deliberately not a credential.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 12 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(AwsLambdaInvocationResultError::InvalidAwsIdentity);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// An AWS region identifier bound to the Lambda endpoint and ARN.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_REGION_BYTES
            || value.trim() != value
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(AwsLambdaInvocationResultError::InvalidAwsIdentity);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// The unqualified function ARN. Version and alias are separate immutable
/// scope fields so a qualified-ARN mismatch cannot be hidden in a string.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FunctionArn {
    pub arn: String,
    pub partition: String,
    pub region: AwsRegion,
    pub account: AwsAccountId,
    pub function_name: String,
}

impl FunctionArn {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let arn = value.into();
        let parts = arn.split(':').collect::<Vec<_>>();
        if parts.len() != 7
            || parts[0] != "arn"
            || !matches!(
                parts[1],
                "aws" | "aws-us-gov" | "aws-cn" | "aws-iso" | "aws-iso-b"
            )
            || parts[2] != "lambda"
            || parts[5] != "function"
            || parts[6].is_empty()
            || parts[6].contains(':')
        {
            return Err(AwsLambdaInvocationResultError::InvalidAwsIdentity);
        }
        if arn.len() > MAX_IDENTIFIER_BYTES
            || !parts[6]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(AwsLambdaInvocationResultError::InvalidAwsIdentity);
        }
        let region = AwsRegion::new(parts[3])?;
        let account = AwsAccountId::new(parts[4])?;
        if parts[6].len() > MAX_FUNCTION_NAME_BYTES {
            return Err(AwsLambdaInvocationResultError::InvalidAwsIdentity);
        }
        let partition = parts[1].to_owned();
        let function_name = parts[6].to_owned();
        Ok(Self {
            arn,
            partition,
            region,
            account,
            function_name,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.arn
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// A published, immutable Lambda version. `$LATEST` is intentionally refused.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PublishedVersion(String);

impl PublishedVersion {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_VERSION_BYTES
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || value == "0"
        {
            return Err(AwsLambdaInvocationResultError::InvalidAwsIdentity);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// A Lambda alias bound alongside the immutable published version.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct FunctionAlias(String);

impl FunctionAlias {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_ALIAS_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(AwsLambdaInvocationResultError::InvalidAwsIdentity);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// Exact function ARN/version/alias/code SHA/revision fence.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FunctionTarget {
    pub function_arn: FunctionArn,
    pub version: PublishedVersion,
    pub alias: Option<FunctionAlias>,
    pub code_sha256: Digest,
    pub revision: u64,
}

impl FunctionTarget {
    pub fn new(
        function_arn: FunctionArn,
        version: PublishedVersion,
        alias: Option<FunctionAlias>,
        code_sha256: Digest,
        revision: u64,
    ) -> Result<Self> {
        code_sha256.validate()?;
        if revision == 0 {
            return Err(AwsLambdaInvocationResultError::InvalidScope);
        }
        if function_arn.account.as_str().is_empty() || function_arn.region.as_str().is_empty() {
            return Err(AwsLambdaInvocationResultError::InvalidAwsIdentity);
        }
        Ok(Self {
            function_arn,
            version,
            alias,
            code_sha256,
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(
            self.function_arn.clone(),
            self.version.clone(),
            self.alias.clone(),
            self.code_sha256.clone(),
            self.revision,
        )
        .map(|_| ())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum InvocationType {
    RequestResponse,
    Event,
}

impl InvocationType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestResponse => "RequestResponse",
            Self::Event => "Event",
        }
    }

    pub const fn max_input_bytes(self) -> u64 {
        match self {
            Self::RequestResponse => MAX_SYNCHRONOUS_INPUT_BYTES,
            Self::Event => MAX_ASYNCHRONOUS_INPUT_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum LogType {
    None,
    Tail,
}

/// Invocation configuration is metadata only. Tail logs are refused because
/// Layer 1 never retains or projects raw execution logs.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvocationConfig {
    pub id: ConfigId,
    pub revision: u64,
    pub timeout_millis: u64,
    pub max_response_bytes: u64,
    pub log_type: LogType,
}

impl InvocationConfig {
    pub fn new(
        id: ConfigId,
        revision: u64,
        timeout_millis: u64,
        max_response_bytes: u64,
        log_type: LogType,
    ) -> Result<Self> {
        if revision == 0
            || timeout_millis == 0
            || timeout_millis > MAX_FUNCTION_TIMEOUT_MILLIS
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
            || matches!(log_type, LogType::Tail)
        {
            return Err(AwsLambdaInvocationResultError::InvalidInvocationConfiguration);
        }
        id.validate()?;
        Ok(Self {
            id,
            revision,
            timeout_millis,
            max_response_bytes,
            log_type,
        })
    }

    pub fn default_for_revision(id: ConfigId, revision: u64) -> Result<Self> {
        Self::new(id, revision, 30_000, MAX_RESPONSE_BYTES, LogType::None)
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(
            self.id.clone(),
            self.revision,
            self.timeout_millis,
            self.max_response_bytes,
            self.log_type,
        )
        .map(|_| ())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// Retry/timeout identity bound to one exact Mission invocation proposal.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryPolicy {
    pub revision: u64,
    pub max_attempts: u8,
    pub timeout_millis: u64,
    pub backoff_base_millis: u64,
    pub backoff_max_millis: u64,
}

impl RetryPolicy {
    pub fn new(
        revision: u64,
        max_attempts: u8,
        timeout_millis: u64,
        backoff_base_millis: u64,
        backoff_max_millis: u64,
    ) -> Result<Self> {
        if revision == 0
            || max_attempts == 0
            || max_attempts > MAX_RETRY_ATTEMPTS
            || timeout_millis == 0
            || timeout_millis > MAX_FUNCTION_TIMEOUT_MILLIS
            || backoff_base_millis == 0
            || backoff_base_millis > backoff_max_millis
            || backoff_max_millis > MAX_BACKOFF_MILLIS
        {
            return Err(AwsLambdaInvocationResultError::InvalidScope);
        }
        Ok(Self {
            revision,
            max_attempts,
            timeout_millis,
            backoff_base_millis,
            backoff_max_millis,
        })
    }

    pub fn default_for_revision(revision: u64) -> Result<Self> {
        Self::new(revision, 3, 30_000, 250, 8_000)
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(
            self.revision,
            self.max_attempts,
            self.timeout_millis,
            self.backoff_base_millis,
            self.backoff_max_millis,
        )
        .map(|_| ())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn backoff_millis(&self, attempt_number: u8) -> u64 {
        let mut delay = self.backoff_base_millis;
        for _ in 1..attempt_number.min(32) {
            delay = delay.saturating_mul(2).min(self.backoff_max_millis);
        }
        delay.min(self.backoff_max_millis)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            revision: 1,
            max_attempts: 3,
            timeout_millis: 30_000,
            backoff_base_millis: 250,
            backoff_max_millis: 8_000,
        }
    }
}

/// Only the serialized digest and size are retained; input bytes are accepted
/// transiently by `from_bounded_bytes` and are not stored.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputIdentity {
    pub id: InputId,
    pub revision: u64,
    pub input_digest: Digest,
    pub serialized_bytes: u64,
}

impl InputIdentity {
    pub fn new(
        id: InputId,
        revision: u64,
        input_digest: Digest,
        serialized_bytes: u64,
    ) -> Result<Self> {
        id.validate()?;
        input_digest.validate()?;
        if revision == 0 || serialized_bytes == 0 || serialized_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsLambdaInvocationResultError::InvalidScope);
        }
        Ok(Self {
            id,
            revision,
            input_digest,
            serialized_bytes,
        })
    }

    pub fn from_bounded_bytes(id: InputId, revision: u64, bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let serialized_bytes = u64::try_from(bytes.len())
            .map_err(|_| AwsLambdaInvocationResultError::InputTooLarge)?;
        Self::new(id, revision, Digest::from_bytes(bytes), serialized_bytes)
    }

    pub fn serialized_digest(&self) -> &Digest {
        &self.input_digest
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(
            self.id.clone(),
            self.revision,
            self.input_digest.clone(),
            self.serialized_bytes,
        )
        .map(|_| ())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// Exact account/region/function/version/alias/input/config/retry/Mission/
/// Project/Work Product scope for one deployment-verification objective.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsLambdaScope {
    pub account: AwsAccountId,
    pub region: AwsRegion,
    pub function: FunctionTarget,
    pub invocation_type: InvocationType,
    pub input: InputIdentity,
    pub config: InvocationConfig,
    pub retry: RetryPolicy,
    pub mission: MissionIdentity,
    pub project: ProjectIdentity,
    pub work_product: WorkProductIdentity,
}

impl AwsLambdaScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        function: FunctionTarget,
        invocation_type: InvocationType,
        input: InputIdentity,
        config: InvocationConfig,
        retry: RetryPolicy,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            function,
            invocation_type,
            input,
            config,
            retry,
            mission,
            project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        self.function.validate()?;
        self.input.validate()?;
        self.config.validate()?;
        self.retry.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        if self.function.function_arn.account != self.account
            || self.function.function_arn.region != self.region
            || self.input.serialized_bytes > self.invocation_type.max_input_bytes()
            || self.config.max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsLambdaInvocationResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn max_input_bytes(&self) -> u64 {
        self.invocation_type.max_input_bytes()
    }

    pub fn matches_provider_identities(
        &self,
        function: &FunctionTarget,
        input: &InputIdentity,
        config: &InvocationConfig,
        retry: &RetryPolicy,
    ) -> Result<()> {
        if self.function.function_arn != function.function_arn {
            return Err(AwsLambdaInvocationResultError::FunctionArnDrift);
        }
        if self.function.version != function.version {
            return Err(AwsLambdaInvocationResultError::FunctionVersionDrift);
        }
        if self.function.alias != function.alias {
            return Err(AwsLambdaInvocationResultError::FunctionAliasDrift);
        }
        if self.function.code_sha256 != function.code_sha256 {
            return Err(AwsLambdaInvocationResultError::FunctionCodeShaDrift);
        }
        if self.function.revision != function.revision {
            return Err(AwsLambdaInvocationResultError::FunctionRevisionDrift);
        }
        if self.input != *input {
            return Err(AwsLambdaInvocationResultError::InputDrift);
        }
        if self.config != *config {
            return Err(AwsLambdaInvocationResultError::ConfigDrift);
        }
        if self.retry != *retry {
            return Err(AwsLambdaInvocationResultError::RetryDrift);
        }
        Ok(())
    }

    pub fn matches_mission_scope(
        &self,
        mission: &MissionIdentity,
        project: &ProjectIdentity,
        work_product: &WorkProductIdentity,
    ) -> Result<()> {
        if self.mission != *mission {
            return Err(AwsLambdaInvocationResultError::MissionDrift);
        }
        if self.project != *project {
            return Err(AwsLambdaInvocationResultError::ProjectDrift);
        }
        if self.work_product != *work_product {
            return Err(AwsLambdaInvocationResultError::WorkProductDrift);
        }
        Ok(())
    }
}

impl fmt::Debug for AwsLambdaScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsLambdaScope")
            .field("scope_digest", &self.digest())
            .field("account", &self.account)
            .field("region", &self.region)
            .field("function", &self.function)
            .field("invocation_type", &self.invocation_type)
            .field("input", &self.input)
            .field("config", &self.config)
            .field("retry", &self.retry)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "function.read",
    "invocation.proposal",
    "invocation.result.read",
    "usage.read",
    "mission.scope",
];

/// Closed read/proposal/result permission snapshot. It is metadata and does
/// not call or mutate AWS IAM.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
        let permissions = permissions.into_iter().map(Into::into).collect();
        let snapshot = Self {
            revision,
            permissions,
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

    pub fn validate(&self) -> Result<()> {
        if self.revision == 0
            || self.permissions.is_empty()
            || self.permissions.iter().any(|permission| {
                !LAYER1_PERMISSIONS.contains(&permission.as_str())
                    || permission.contains("write")
                    || permission.contains("iam")
                    || permission.contains("logs")
            })
        {
            return Err(AwsLambdaInvocationResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// Opaque SigV4 credential reference. The supplied handle is hashed and
/// dropped; it is never serializable, displayable, or present in Debug.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Option<Digest>,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new_with_scope(opaque_handle, None, revision)
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        account: &AwsAccountId,
        region: &AwsRegion,
        revision: u64,
    ) -> Result<Self> {
        let scope_digest = Digest::from_parts(
            "aws-lambda-sigv4-scope/v1",
            &[
                ("account", account.as_str().to_owned()),
                ("region", region.as_str().to_owned()),
            ],
        );
        Self::new_with_scope(opaque_handle, Some(scope_digest), revision)
    }

    pub fn for_scope(
        opaque_handle: impl Into<String>,
        scope: &AwsLambdaScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new_with_scope(opaque_handle, Some(scope.digest()), revision)
    }

    fn new_with_scope(
        opaque_handle: impl Into<String>,
        scope_digest: Option<Digest>,
        revision: u64,
    ) -> Result<Self> {
        let opaque_handle = opaque_handle.into();
        validate_text(
            &opaque_handle,
            "secretReference",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        if revision == 0 {
            return Err(AwsLambdaInvocationResultError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-lambda-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("opaque_handle", opaque_handle),
                (
                    "scope",
                    scope_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("revision", revision.to_string()),
            ],
        );
        Ok(Self {
            kind: SecretKind::Sigv4Credential,
            reference_digest,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> Option<&Digest> {
        self.scope_digest.as_ref()
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

    pub fn validate(&self) -> Result<()> {
        self.reference_digest.validate()?;
        if self.revision == 0 || !matches!(self.kind, SecretKind::Sigv4Credential) {
            return Err(AwsLambdaInvocationResultError::InvalidSecretReference);
        }
        if let Some(scope_digest) = &self.scope_digest {
            scope_digest.validate()?;
        }
        Ok(())
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

/// Layer-1 transport provenance. No variant is allowed to claim live/native
/// connectivity or first-party evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fake,
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

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationStatus {
    Accepted,
    Queued,
    Running,
    Succeeded,
    FunctionError,
    Throttled,
    Timeout,
    Partial,
    ProviderUnknown,
}

impl InvocationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::FunctionError => "function_error",
            Self::Throttled => "throttled",
            Self::Timeout => "timeout",
            Self::Partial => "partial",
            Self::ProviderUnknown => "provider_unknown",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::FunctionError
                | Self::Throttled
                | Self::Timeout
                | Self::Partial
                | Self::ProviderUnknown
        )
    }

    pub const fn is_non_adoptable(self) -> bool {
        !matches!(self, Self::Succeeded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionCompleteness {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerError,
    Timeout,
    AccessLost,
    MalformedResponse,
    ResponseTooLarge,
    RequestDigestMismatch,
    OutputDigestMismatch,
    ErrorDigestMismatch,
    ProviderUnknown,
}

/// Bounded usage metadata. It never contains cost, logs, or raw payload data.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageEvidence {
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub duration_millis: Option<u64>,
    pub retry_count: u8,
    pub attempt_number: u8,
}

impl UsageEvidence {
    pub fn new(
        input_bytes: u64,
        output_bytes: u64,
        duration_millis: Option<u64>,
        retry_count: u8,
        attempt_number: u8,
    ) -> Result<Self> {
        if input_bytes == 0
            || input_bytes > MAX_RESPONSE_BYTES
            || output_bytes > MAX_RESPONSE_BYTES
            || duration_millis.is_some_and(|duration| duration > MAX_FUNCTION_TIMEOUT_MILLIS)
            || attempt_number == 0
            || retry_count.checked_add(1) != Some(attempt_number)
        {
            return Err(AwsLambdaInvocationResultError::InvalidScope);
        }
        Ok(Self {
            input_bytes,
            output_bytes,
            duration_millis,
            retry_count,
            attempt_number,
        })
    }

    pub fn for_input(input: &InputIdentity) -> Result<Self> {
        Self::new(input.serialized_bytes, 0, None, 0, 1)
    }

    pub fn validate_against(&self, scope: &AwsLambdaScope) -> Result<()> {
        if self.input_bytes != scope.input.serialized_bytes
            || self.output_bytes > scope.config.max_response_bytes
            || self.retry_count >= scope.retry.max_attempts
            || self.attempt_number > scope.retry.max_attempts
            || self.retry_count.checked_add(1) != Some(self.attempt_number)
        {
            return Err(AwsLambdaInvocationResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// Bounded typed invocation proposal. Payload bytes are intentionally absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvocationProposal {
    pub registration_id: RegistrationId,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub function: FunctionTarget,
    pub invocation_type: InvocationType,
    pub input: InputIdentity,
    pub config: InvocationConfig,
    pub retry: RetryPolicy,
    pub mission: MissionIdentity,
    pub project: ProjectIdentity,
    pub work_product: WorkProductIdentity,
    pub request_digest: Digest,
    pub proposal_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl InvocationProposal {
    pub fn new(
        registration_id: RegistrationId,
        registration_digest: Digest,
        scope: &AwsLambdaScope,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        scope.validate()?;
        registration_id.validate()?;
        registration_digest.validate()?;
        let request_digest = Self::calculate_request_digest(scope);
        let mut proposal = Self {
            registration_id,
            registration_digest,
            scope_digest: scope.digest(),
            function: scope.function.clone(),
            invocation_type: scope.invocation_type,
            input: scope.input.clone(),
            config: scope.config.clone(),
            retry: scope.retry.clone(),
            mission: scope.mission.clone(),
            project: scope.project.clone(),
            work_product: scope.work_product.clone(),
            request_digest,
            proposal_digest: Digest::from_text("unsealed-aws-lambda-invocation-proposal"),
            provenance,
            connected: false,
            native: false,
            first_party: false,
        };
        proposal.proposal_digest = proposal.calculate_digest();
        Ok(proposal)
    }

    fn calculate_request_digest(scope: &AwsLambdaScope) -> Digest {
        Digest::from_parts(
            "aws-lambda-invocation-request/v1",
            &[
                ("account", scope.account.as_str().to_owned()),
                ("region", scope.region.as_str().to_owned()),
                ("function", scope.function.function_arn.as_str().to_owned()),
                ("version", scope.function.version.as_str().to_owned()),
                (
                    "alias",
                    scope
                        .function
                        .alias
                        .as_ref()
                        .map_or_else(String::new, |alias| alias.as_str().to_owned()),
                ),
                (
                    "code_sha256",
                    scope.function.code_sha256.as_str().to_owned(),
                ),
                ("invocation_type", scope.invocation_type.as_str().to_owned()),
                ("input", scope.input.input_digest.as_str().to_owned()),
                ("input_revision", scope.input.revision.to_string()),
                ("config", scope.config.digest().as_str().to_owned()),
                ("retry", scope.retry.digest().as_str().to_owned()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.registration_id.validate()?;
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        self.function.validate()?;
        self.input.validate()?;
        self.config.validate()?;
        self.retry.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        if self.connected
            || self.native
            || self.first_party
            || self.request_digest
                != Self::calculate_request_digest(&AwsLambdaScope::new(
                    self.function.function_arn.account.clone(),
                    self.function.function_arn.region.clone(),
                    self.function.clone(),
                    self.invocation_type,
                    self.input.clone(),
                    self.config.clone(),
                    self.retry.clone(),
                    self.mission.clone(),
                    self.project.clone(),
                    self.work_product.clone(),
                )?)
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AwsLambdaInvocationResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    /// Payload bytes are never part of the canonical proposal representation.
    pub const fn canonical_contains_raw_payload(&self) -> bool {
        false
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-lambda-invocation-proposal/v1",
            &[
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("function", self.function.digest().as_str().to_owned()),
                ("invocation_type", self.invocation_type.as_str().to_owned()),
                ("input", self.input.digest().as_str().to_owned()),
                ("config", self.config.digest().as_str().to_owned()),
                ("retry", self.retry.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

/// Metadata-only invocation result projection. It retains digests, sizes,
/// status, and bounded usage; never a payload, error body, or log.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvocationResultProjection {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub function: FunctionTarget,
    pub invocation_type: InvocationType,
    pub input_digest: Digest,
    pub input_revision: u64,
    pub config_digest: Digest,
    pub config_revision: u64,
    pub retry_digest: Digest,
    pub retry_revision: u64,
    pub mission: MissionIdentity,
    pub project: ProjectIdentity,
    pub work_product: WorkProductIdentity,
    pub status: InvocationStatus,
    pub failure_code: Option<FailureCode>,
    pub http_status: Option<AwsLambdaHttpStatus>,
    pub function_error: bool,
    pub output_digest: Option<Digest>,
    pub error_digest: Option<Digest>,
    pub usage: UsageEvidence,
    pub response_bytes: u64,
    pub response_truncated: bool,
    pub attempt_number: u8,
    pub observed_at_epoch_seconds: u64,
    pub provenance: TransportProvenance,
    pub completeness: ProjectionCompleteness,
    pub evidence_digest: Digest,
    pub projection_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl InvocationResultProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal: &InvocationProposal,
        status: InvocationStatus,
        failure_code: Option<FailureCode>,
        http_status: Option<AwsLambdaHttpStatus>,
        function_error: bool,
        output_digest: Option<Digest>,
        error_digest: Option<Digest>,
        usage: UsageEvidence,
        response_bytes: u64,
        response_truncated: bool,
        attempt_number: u8,
        observed_at_epoch_seconds: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        proposal.validate_integrity()?;
        output_digest.as_ref().map(Digest::validate).transpose()?;
        error_digest.as_ref().map(Digest::validate).transpose()?;
        usage.validate_against(&AwsLambdaScope::new(
            proposal.function.function_arn.account.clone(),
            proposal.function.function_arn.region.clone(),
            proposal.function.clone(),
            proposal.invocation_type,
            proposal.input.clone(),
            proposal.config.clone(),
            proposal.retry.clone(),
            proposal.mission.clone(),
            proposal.project.clone(),
            proposal.work_product.clone(),
        )?)?;
        if response_bytes > proposal.config.max_response_bytes
            || response_bytes > MAX_RESPONSE_BYTES
            || attempt_number == 0
            || attempt_number > proposal.retry.max_attempts
            || observed_at_epoch_seconds == 0
        {
            return Err(AwsLambdaInvocationResultError::InvalidScope);
        }
        if matches!(status, InvocationStatus::FunctionError) && error_digest.is_none() {
            return Err(AwsLambdaInvocationResultError::MissingFunctionErrorDigest);
        }
        if matches!(status, InvocationStatus::FunctionError) != function_error {
            return Err(AwsLambdaInvocationResultError::InvalidInvocationConfiguration);
        }
        if matches!(status, InvocationStatus::Succeeded)
            && matches!(proposal.invocation_type, InvocationType::RequestResponse)
            && output_digest.is_none()
        {
            return Err(AwsLambdaInvocationResultError::MissingOutputDigest);
        }
        let completeness = if response_truncated || matches!(status, InvocationStatus::Partial) {
            ProjectionCompleteness::Partial
        } else {
            ProjectionCompleteness::Complete
        };
        let mut projection = Self {
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            request_digest: proposal.request_digest.clone(),
            function: proposal.function.clone(),
            invocation_type: proposal.invocation_type,
            input_digest: proposal.input.input_digest.clone(),
            input_revision: proposal.input.revision,
            config_digest: proposal.config.digest(),
            config_revision: proposal.config.revision,
            retry_digest: proposal.retry.digest(),
            retry_revision: proposal.retry.revision,
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            status,
            failure_code,
            http_status,
            function_error,
            output_digest,
            error_digest,
            usage,
            response_bytes,
            response_truncated,
            attempt_number,
            observed_at_epoch_seconds,
            provenance,
            completeness,
            evidence_digest: Digest::from_text("unsealed-aws-lambda-evidence"),
            projection_digest: Digest::from_text("unsealed-aws-lambda-projection"),
            connected: false,
            native: false,
            first_party: false,
        };
        projection.evidence_digest = projection.calculate_evidence_digest();
        projection.projection_digest = projection.calculate_projection_digest();
        Ok(projection)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        self.request_digest.validate()?;
        self.function.validate()?;
        self.input_digest.validate()?;
        self.config_digest.validate()?;
        self.retry_digest.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        self.output_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.error_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.usage.validate_against(&AwsLambdaScope::new(
            self.function.function_arn.account.clone(),
            self.function.function_arn.region.clone(),
            self.function.clone(),
            self.invocation_type,
            InputIdentity::new(
                self.usage_input_id(),
                self.input_revision,
                self.input_digest.clone(),
                self.usage.input_bytes,
            )?,
            InvocationConfig::new(
                self.config_id(),
                self.config_revision,
                1,
                self.response_bytes.max(1),
                LogType::None,
            )?,
            RetryPolicy::new(self.retry_revision, self.attempt_number.max(1), 1, 1, 1)?,
            self.mission.clone(),
            self.project.clone(),
            self.work_product.clone(),
        )?)?;
        if self.connected
            || self.native
            || self.first_party
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.attempt_number == 0
            || self.observed_at_epoch_seconds == 0
            || (matches!(self.status, InvocationStatus::FunctionError) != self.function_error)
            || (matches!(self.status, InvocationStatus::FunctionError)
                && self.error_digest.is_none())
            || self.evidence_digest != self.calculate_evidence_digest()
            || self.projection_digest != self.calculate_projection_digest()
        {
            return Err(AwsLambdaInvocationResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn usage_input_id(&self) -> InputId {
        InputId::new("projection-input", self.input_revision).expect("projection input id")
    }

    fn config_id(&self) -> ConfigId {
        ConfigId::new("projection-config", self.config_revision).expect("projection config id")
    }

    pub fn calculate_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-lambda-invocation-evidence/v1",
            &[
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("function", self.function.digest().as_str().to_owned()),
                ("input", self.input_digest.as_str().to_owned()),
                ("input_revision", self.input_revision.to_string()),
                ("config", self.config_digest.as_str().to_owned()),
                ("config_revision", self.config_revision.to_string()),
                ("retry", self.retry_digest.as_str().to_owned()),
                ("retry_revision", self.retry_revision.to_string()),
                ("status", self.status.as_str().to_owned()),
                ("failure", format!("{:?}", self.failure_code)),
                (
                    "http_status",
                    self.http_status
                        .map_or_else(String::new, |status| status.as_u16().to_string()),
                ),
                ("function_error", self.function_error.to_string()),
                (
                    "output",
                    self.output_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "error",
                    self.error_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("usage", self.usage.digest().as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("truncated", self.response_truncated.to_string()),
                ("attempt", self.attempt_number.to_string()),
                ("observed_at", self.observed_at_epoch_seconds.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    fn calculate_projection_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-lambda-invocation-projection/v1",
            &[
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("status", self.status.as_str().to_owned()),
                ("completeness", format!("{:?}", self.completeness)),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn is_non_adoptable(&self) -> bool {
        self.completeness == ProjectionCompleteness::Partial
            || self.status.is_non_adoptable()
            || self.provenance == TransportProvenance::BlockedEnv
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

/// A stable verification report; verification never mutates a Mission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub verified: bool,
    pub failures: Vec<VerificationFailure>,
}

impl VerificationReport {
    pub fn verified(&self) -> bool {
        self.verified
    }

    pub fn failures(&self) -> &[VerificationFailure] {
        &self.failures
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ScopeDigestMismatch,
    RequestDigestMismatch,
    FunctionArnMismatch,
    FunctionVersionMismatch,
    FunctionAliasMismatch,
    FunctionCodeShaMismatch,
    FunctionRevisionMismatch,
    InputDigestMismatch,
    ConfigDigestMismatch,
    RetryDigestMismatch,
    MissionRevisionMismatch,
    ProjectRevisionMismatch,
    WorkProductRevisionMismatch,
    OutputDigestMismatch,
    ErrorDigestMismatch,
    UsageDigestMismatch,
    EvidenceDigestMismatch,
    PartialEvidence,
    ProviderUnknown,
    ConnectedClaim,
    NativeClaim,
    FirstPartyClaim,
}

impl AwsLambdaHttpStatus {
    pub fn new(status: u16) -> Result<Self> {
        if !(100..=599).contains(&status) {
            return Err(AwsLambdaInvocationResultError::InvalidInvocationConfiguration);
        }
        Ok(Self(status))
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }

    pub const fn is_success(self) -> bool {
        self.0 >= 200 && self.0 <= 299
    }
}

/// HTTP status is kept typed so transport classifications cannot carry raw
/// response bodies or unbounded error text.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsLambdaHttpStatus(pub(crate) u16);

impl fmt::Display for AwsLambdaHttpStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Test-only convenience scope used by unit and contract fixtures.
pub fn fixture_scope() -> AwsLambdaScope {
    let account = AwsAccountId::new("123456789012").expect("fixture account");
    let region = AwsRegion::new("us-east-1").expect("fixture region");
    let arn =
        FunctionArn::new("arn:aws:lambda:us-east-1:123456789012:function:deployment-verifier")
            .expect("fixture ARN");
    let function = FunctionTarget::new(
        arn,
        PublishedVersion::new("7").expect("fixture version"),
        Some(FunctionAlias::new("verification").expect("fixture alias")),
        Digest::from_text("lambda-code-sha256"),
        3,
    )
    .expect("fixture function");
    let input = InputIdentity::from_bounded_bytes(
        InputId::new("deployment-input", 2).expect("fixture input id"),
        4,
        br#"{"deployment":"candidate","revision":4}"#,
    )
    .expect("fixture input");
    AwsLambdaScope::new(
        account,
        region,
        function,
        InvocationType::RequestResponse,
        input,
        InvocationConfig::default_for_revision(
            ConfigId::new("invoke-config", 1).expect("config id"),
            5,
        )
        .expect("config"),
        RetryPolicy::default_for_revision(6).expect("retry"),
        MissionIdentity::new("mission-391", 9).expect("mission"),
        ProjectIdentity::new("project-391", 4).expect("project"),
        WorkProductIdentity::new("work-product-391", 2).expect("work product"),
    )
    .expect("fixture scope")
}
