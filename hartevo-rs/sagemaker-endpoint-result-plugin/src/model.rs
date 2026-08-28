use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{Result, SageMakerEndpointResultError};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SAGEMAKER_NAME_BYTES: usize = 63;
pub const MAX_IMAGE_REFERENCE_BYTES: usize = 2_048;
pub const MAX_METADATA_TEXT_BYTES: usize = 1_024;
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PRODUCTION_VARIANTS: usize = 10;

/// Lowercase hexadecimal SHA-256 used for identity, scope, evidence, and
/// receipt fences. The digest is the only representation used for sensitive
/// references such as credentials and container image URIs.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let digest = Self(value.into().to_ascii_lowercase());
        digest.validate()?;
        Ok(digest)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_str_value(value: impl AsRef<str>) -> Self {
        Self::from_bytes(value.as_ref().as_bytes())
    }

    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("SageMaker contract values serialize");
        Self::from_bytes(&bytes)
    }

    pub fn pending() -> Self {
        Self::from_str_value("pending-sagemaker-endpoint-result-digest")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        if self.0.len() == 64 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(())
        } else {
            Err(SageMakerEndpointResultError::InvalidDigest)
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

impl FromStr for Digest {
    type Err = SageMakerEndpointResultError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Self::new(value)
    }
}

macro_rules! identifier_type {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_identifier(&value, $kind)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<()> {
                validate_identifier(&self.0, $kind)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = SageMakerEndpointResultError;

            fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier_type!(AwsPartition, "AWS partition");
identifier_type!(AwsRegion, "AWS region");
identifier_type!(SageMakerEndpointName, "SageMaker endpoint");
identifier_type!(
    SageMakerEndpointConfigName,
    "SageMaker endpoint configuration"
);
identifier_type!(ProductionVariantName, "production variant");
identifier_type!(ModelName, "SageMaker model");
identifier_type!(ProjectId, "Hartevo Project");
identifier_type!(MissionId, "Mission");
identifier_type!(WorkProductId, "Work Product");
identifier_type!(ObjectiveId, "deployment-verification objective");

pub type HartevoProjectId = ProjectId;

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 12 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(SageMakerEndpointResultError::InvalidIdentifier {
                kind: "AWS account",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Display for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for AwsAccountId {
    type Err = SageMakerEndpointResultError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Self::new(value)
    }
}

fn validate_identifier(value: &str, kind: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
        || value
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'%'))
    {
        Err(SageMakerEndpointResultError::InvalidIdentifier { kind })
    } else {
        Ok(())
    }
}

fn validate_sagemaker_name(value: &str, kind: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_SAGEMAKER_NAME_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        Err(SageMakerEndpointResultError::InvalidIdentifier { kind })
    } else {
        Ok(())
    }
}

fn validate_bounded_text(value: &str, field: &'static str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(SageMakerEndpointResultError::InvalidInput {
            field,
            reason: "must be bounded, non-empty, and free of control characters",
        })
    } else {
        Ok(())
    }
}

fn validate_arn(value: &str, field: &'static str) -> Result<()> {
    validate_bounded_text(value, field, 2_048)?;
    if !value.starts_with("arn:") || value.chars().any(char::is_whitespace) {
        return Err(SageMakerEndpointResultError::InvalidInput {
            field,
            reason: "must be a bounded AWS ARN",
        });
    }
    Ok(())
}

/// A bounded revision label. The original value is not treated as a secret,
/// but it is still restricted so it cannot smuggle an unbounded payload into a
/// digest fence.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ModelRevision(String);

impl ModelRevision {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_bounded_text(&value, "model revision", MAX_IDENTIFIER_BYTES)?;
        if value.chars().any(char::is_whitespace) {
            return Err(SageMakerEndpointResultError::InvalidInput {
                field: "model revision",
                reason: "must not contain whitespace",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Display for ModelRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ModelRevision {
    type Err = SageMakerEndpointResultError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// A container/image reference is accepted only long enough to hash it. The
/// raw URI never appears in a serialized scope, evidence, receipt, or debug
/// projection.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageReference {
    pub reference_digest: Digest,
}

impl fmt::Debug for ImageReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImageReference")
            .field("reference_digest", &self.reference_digest)
            .finish()
    }
}

impl ImageReference {
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let value = value.as_ref();
        validate_bounded_text(
            value,
            "container image reference",
            MAX_IMAGE_REFERENCE_BYTES,
        )?;
        if value.contains("//") && value.contains('@') && value.contains(':') {
            // This is not a complete URI parser; it is a conservative guard
            // against accepting a credential-bearing URL as a model image.
            let authority = value.split("//").nth(1).unwrap_or_default();
            if authority.contains('@') {
                return Err(SageMakerEndpointResultError::InvalidInput {
                    field: "container image reference",
                    reason: "credential-bearing image references are forbidden",
                });
            }
        }
        Ok(Self {
            reference_digest: Digest::from_str_value(value),
        })
    }

    pub fn from_digest(reference_digest: Digest) -> Result<Self> {
        reference_digest.validate()?;
        Ok(Self { reference_digest })
    }

    pub fn digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn validate(&self) -> Result<()> {
        self.reference_digest.validate()
    }
}

/// Bounded failure/status text. Known credential-like tokens are replaced and
/// the original text is represented only by a digest.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureReason {
    pub message: String,
    pub message_digest: Digest,
}

impl fmt::Debug for FailureReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailureReason")
            .field("message", &self.message)
            .field("message_digest", &self.message_digest)
            .finish()
    }
}

impl FailureReason {
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let original = value.as_ref();
        validate_bounded_text(original, "failure reason", MAX_METADATA_TEXT_BYTES)?;
        let lower = original.to_ascii_lowercase();
        let message = if [
            "secret",
            "token",
            "password",
            "credential",
            "private key",
            "access key",
        ]
        .iter()
        .any(|term| lower.contains(term))
        {
            "[REDACTED]".to_owned()
        } else {
            original.to_owned()
        };
        Ok(Self {
            message,
            message_digest: Digest::from_str_value(original),
        })
    }

    pub fn validate(&self) -> Result<()> {
        validate_bounded_text(&self.message, "failure reason", MAX_METADATA_TEXT_BYTES)?;
        self.message_digest.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MetadataTimestamp(String);

impl MetadataTimestamp {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_bounded_text(&value, "metadata timestamp", 64)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrafficWeight {
    /// SageMaker's 0.0..=1.0 weight represented as integer basis points.
    pub basis_points: u16,
}

impl TrafficWeight {
    pub const FULL: Self = Self {
        basis_points: 10_000,
    };

    pub fn new(basis_points: u16) -> Result<Self> {
        if basis_points > 10_000 {
            return Err(SageMakerEndpointResultError::InvalidTraffic);
        }
        Ok(Self { basis_points })
    }

    pub fn from_percent(percent: u8) -> Result<Self> {
        Self::new(u16::from(percent) * 100)
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn from_fraction(fraction: f64) -> Result<Self> {
        if !fraction.is_finite() || !(0.0..=1.0).contains(&fraction) {
            return Err(SageMakerEndpointResultError::InvalidTraffic);
        }
        Self::new((fraction * 10_000.0).round() as u16)
    }

    pub fn as_fraction(self) -> f64 {
        f64::from(self.basis_points) / 10_000.0
    }

    pub fn validate(self) -> Result<()> {
        if self.basis_points <= 10_000 {
            Ok(())
        } else {
            Err(SageMakerEndpointResultError::InvalidTraffic)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrafficAllocation {
    pub variant_name: ProductionVariantName,
    pub weight: TrafficWeight,
}

impl TrafficAllocation {
    pub fn new(variant_name: ProductionVariantName, basis_points: u16) -> Result<Self> {
        let allocation = Self {
            variant_name,
            weight: TrafficWeight::new(basis_points)?,
        };
        allocation.validate()?;
        Ok(allocation)
    }

    pub fn from_percent(variant_name: ProductionVariantName, percent: u8) -> Result<Self> {
        let allocation = Self {
            variant_name,
            weight: TrafficWeight::from_percent(percent)?,
        };
        allocation.validate()?;
        Ok(allocation)
    }

    pub fn from_fraction(variant_name: ProductionVariantName, fraction: f64) -> Result<Self> {
        let weight = TrafficWeight::from_fraction(fraction)?;
        let allocation = Self {
            variant_name,
            weight,
        };
        allocation.validate()?;
        Ok(allocation)
    }

    pub fn validate(&self) -> Result<()> {
        self.variant_name.validate()?;
        self.weight.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrafficSnapshot {
    pub allocations: Vec<TrafficAllocation>,
    pub snapshot_digest: Digest,
}

impl TrafficSnapshot {
    pub fn new(mut allocations: Vec<TrafficAllocation>) -> Result<Self> {
        allocations.sort();
        let snapshot = Self {
            allocations,
            snapshot_digest: Digest::pending(),
        };
        snapshot.validate_without_digest()?;
        let mut snapshot = snapshot;
        snapshot.snapshot_digest = snapshot.computed_digest();
        Ok(snapshot)
    }

    pub fn single(variant_name: ProductionVariantName) -> Result<Self> {
        Self::new(vec![TrafficAllocation {
            variant_name,
            weight: TrafficWeight::FULL,
        }])
    }

    pub fn from_fractions(
        allocations: impl IntoIterator<Item = (ProductionVariantName, f64)>,
    ) -> Result<Self> {
        Self::new(
            allocations
                .into_iter()
                .map(|(variant_name, fraction)| {
                    TrafficAllocation::from_fraction(variant_name, fraction)
                })
                .collect::<Result<Vec<_>>>()?,
        )
    }

    fn validate_without_digest(&self) -> Result<()> {
        if self.allocations.is_empty() || self.allocations.len() > MAX_PRODUCTION_VARIANTS {
            return Err(SageMakerEndpointResultError::InvalidTraffic);
        }
        let mut seen = BTreeSet::new();
        let mut total = 0_u32;
        for allocation in &self.allocations {
            allocation.validate()?;
            if !seen.insert(allocation.variant_name.clone()) {
                return Err(SageMakerEndpointResultError::InvalidTraffic);
            }
            total = total.saturating_add(u32::from(allocation.weight.basis_points));
        }
        if total != 10_000 {
            return Err(SageMakerEndpointResultError::InvalidTraffic);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_without_digest()?;
        self.snapshot_digest.validate()?;
        if self.snapshot_digest != self.computed_digest() {
            return Err(SageMakerEndpointResultError::InvalidTraffic);
        }
        Ok(())
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.snapshot_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn digest(&self) -> &Digest {
        &self.snapshot_digest
    }

    pub fn weight_for(&self, variant_name: &ProductionVariantName) -> Option<TrafficWeight> {
        self.allocations
            .iter()
            .find(|allocation| &allocation.variant_name == variant_name)
            .map(|allocation| allocation.weight)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentVerificationObjective {
    pub objective_id: ObjectiveId,
    pub objective_revision: u64,
    pub objective_digest: Digest,
}

impl DeploymentVerificationObjective {
    pub fn new(
        objective_id: ObjectiveId,
        objective_revision: u64,
        objective_digest: Digest,
    ) -> Result<Self> {
        let objective = Self {
            objective_id,
            objective_revision,
            objective_digest,
        };
        objective.validate()?;
        Ok(objective)
    }

    pub fn validate(&self) -> Result<()> {
        self.objective_id.validate()?;
        self.objective_digest.validate()?;
        if self.objective_revision == 0 {
            return Err(SageMakerEndpointResultError::InvalidInput {
                field: "objective revision",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SageMakerPermission {
    DescribeEndpoint,
    DescribeEndpointConfig,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SageMakerPermissionSnapshot {
    pub revision: String,
    pub permissions: BTreeSet<SageMakerPermission>,
    pub snapshot_digest: Digest,
}

impl SageMakerPermissionSnapshot {
    pub fn new(
        revision: impl Into<String>,
        permissions: impl IntoIterator<Item = SageMakerPermission>,
    ) -> Result<Self> {
        let mut snapshot = Self {
            revision: revision.into(),
            permissions: permissions.into_iter().collect(),
            snapshot_digest: Digest::pending(),
        };
        snapshot.validate_without_digest()?;
        snapshot.snapshot_digest = snapshot.computed_digest();
        Ok(snapshot)
    }

    pub fn read_only_default(revision: impl Into<String>) -> Result<Self> {
        Self::new(
            revision,
            [
                SageMakerPermission::DescribeEndpoint,
                SageMakerPermission::DescribeEndpointConfig,
            ],
        )
    }

    fn validate_without_digest(&self) -> Result<()> {
        validate_bounded_text(&self.revision, "permission snapshot revision", 128)?;
        if self.permissions
            != BTreeSet::from([
                SageMakerPermission::DescribeEndpoint,
                SageMakerPermission::DescribeEndpointConfig,
            ])
        {
            return Err(SageMakerEndpointResultError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_without_digest()?;
        self.snapshot_digest.validate()?;
        if self.snapshot_digest != self.computed_digest() {
            return Err(SageMakerEndpointResultError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.snapshot_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn digest(&self) -> &Digest {
        &self.snapshot_digest
    }
}

/// Exact endpoint/config/model/traffic/Mission binding for one deployment
/// verification objective.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SageMakerScope {
    pub aws_partition: AwsPartition,
    pub aws_account_id: AwsAccountId,
    pub aws_region: AwsRegion,
    pub endpoint_name: SageMakerEndpointName,
    pub endpoint_arn_digest: Digest,
    pub endpoint_config_name: SageMakerEndpointConfigName,
    pub endpoint_config_arn_digest: Digest,
    pub production_variant_name: ProductionVariantName,
    pub model_name: ModelName,
    pub model_revision: ModelRevision,
    pub image_reference: ImageReference,
    pub code_digest: Digest,
    pub config_digest: Digest,
    pub traffic: TrafficSnapshot,
    pub deployment_verification_objective: DeploymentVerificationObjective,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub permission_snapshot: SageMakerPermissionSnapshot,
}

impl SageMakerScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        aws_partition: AwsPartition,
        aws_account_id: AwsAccountId,
        aws_region: AwsRegion,
        endpoint_name: SageMakerEndpointName,
        endpoint_arn: impl AsRef<str>,
        endpoint_config_name: SageMakerEndpointConfigName,
        endpoint_config_arn: impl AsRef<str>,
        production_variant_name: ProductionVariantName,
        model_name: ModelName,
        model_revision: ModelRevision,
        image_reference: ImageReference,
        code_digest: Digest,
        config_digest: Digest,
        traffic: TrafficSnapshot,
        deployment_verification_objective: DeploymentVerificationObjective,
        project_id: ProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        mission_revision: u64,
        work_product_revision: u64,
        permission_snapshot: SageMakerPermissionSnapshot,
    ) -> Result<Self> {
        validate_arn(endpoint_arn.as_ref(), "endpoint ARN")?;
        validate_arn(endpoint_config_arn.as_ref(), "endpoint configuration ARN")?;
        let scope = Self {
            aws_partition,
            aws_account_id,
            aws_region,
            endpoint_name,
            endpoint_arn_digest: Digest::from_str_value(endpoint_arn.as_ref()),
            endpoint_config_name,
            endpoint_config_arn_digest: Digest::from_str_value(endpoint_config_arn.as_ref()),
            production_variant_name,
            model_name,
            model_revision,
            image_reference,
            code_digest,
            config_digest,
            traffic,
            deployment_verification_objective,
            project_id,
            mission_id,
            work_product_id,
            mission_revision,
            work_product_revision,
            permission_snapshot,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        self.aws_partition.validate()?;
        self.aws_account_id.validate()?;
        self.aws_region.validate()?;
        validate_sagemaker_name(self.endpoint_name.as_str(), "SageMaker endpoint")?;
        self.endpoint_arn_digest.validate()?;
        validate_sagemaker_name(
            self.endpoint_config_name.as_str(),
            "SageMaker endpoint configuration",
        )?;
        self.endpoint_config_arn_digest.validate()?;
        validate_sagemaker_name(self.production_variant_name.as_str(), "production variant")?;
        validate_sagemaker_name(self.model_name.as_str(), "SageMaker model")?;
        self.model_revision.validate()?;
        self.image_reference.validate()?;
        self.code_digest.validate()?;
        self.config_digest.validate()?;
        self.traffic.validate()?;
        if self
            .traffic
            .weight_for(&self.production_variant_name)
            .is_none()
        {
            return Err(SageMakerEndpointResultError::InvalidTraffic);
        }
        self.deployment_verification_objective.validate()?;
        self.project_id.validate()?;
        self.mission_id.validate()?;
        self.work_product_id.validate()?;
        self.permission_snapshot.validate()?;
        if self.mission_revision == 0 || self.work_product_revision == 0 {
            return Err(SageMakerEndpointResultError::InvalidInput {
                field: "Mission and Work Product revisions",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn endpoint(&self) -> &SageMakerEndpointName {
        &self.endpoint_name
    }

    pub fn endpoint_config(&self) -> &SageMakerEndpointConfigName {
        &self.endpoint_config_name
    }

    pub fn variant(&self) -> &ProductionVariantName {
        &self.production_variant_name
    }

    pub fn model(&self) -> &ModelName {
        &self.model_name
    }

    pub fn traffic_snapshot(&self) -> &TrafficSnapshot {
        &self.traffic
    }

    pub fn same_mission_scope(&self, other: &Self) -> bool {
        self.project_id == other.project_id
            && self.mission_id == other.mission_id
            && self.work_product_id == other.work_product_id
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigV4AuthMethod {
    AwsSigV4,
}

/// Opaque host-held SigV4 credential identity. Only a digest and scope fence
/// are serialized; access keys, session tokens, and secret keys cannot escape.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    pub reference_digest: Digest,
    pub scope_digest: Digest,
    pub credential_revision: u64,
    pub auth_method: SigV4AuthMethod,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("auth_method", &self.auth_method)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl AsRef<str>,
        scope: &SageMakerScope,
        credential_revision: u64,
    ) -> Result<Self> {
        scope.validate()?;
        Self::for_scope(
            reference_id,
            scope.digest(),
            credential_revision,
            SigV4AuthMethod::AwsSigV4,
        )
    }

    pub fn for_scope(
        reference_id: impl AsRef<str>,
        scope_digest: Digest,
        credential_revision: u64,
        auth_method: SigV4AuthMethod,
    ) -> Result<Self> {
        let reference_id = reference_id.as_ref();
        validate_bounded_text(reference_id, "secret reference", MAX_IDENTIFIER_BYTES)?;
        if reference_id.chars().any(char::is_whitespace) || credential_revision == 0 {
            return Err(SageMakerEndpointResultError::InvalidInput {
                field: "secret reference",
                reason: "must be bounded, whitespace-free, and have a non-zero revision",
            });
        }
        if reference_id.to_ascii_lowercase().contains("access_key")
            || reference_id.to_ascii_lowercase().contains("secret_key")
            || reference_id.to_ascii_lowercase().contains("session_token")
        {
            return Err(SageMakerEndpointResultError::LongLivedCredentialsRejected);
        }
        scope_digest.validate()?;
        Ok(Self {
            reference_digest: Digest::from_str_value(reference_id),
            scope_digest,
            credential_revision,
            auth_method,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.reference_digest.validate()?;
        self.scope_digest.validate()?;
        if self.credential_revision == 0 {
            return Err(SageMakerEndpointResultError::InvalidInput {
                field: "credential revision",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }

    pub fn validate_for_scope(&self, scope: &SageMakerScope) -> Result<()> {
        self.validate()?;
        if self.scope_digest != scope.digest() {
            return Err(SageMakerEndpointResultError::SecretReferenceMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeStatus {
    BlockedEnv,
}

impl NativeStatus {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    OfficialHttps,
    Recording,
    Fake,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        matches!(self, Self::OfficialHttps)
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SageMakerCapability {
    DescribeEndpointMetadata,
    DescribeEndpointConfigMetadata,
    ReadEndpointStatus,
    ReadProductionVariantStatus,
    ReadTrafficWeights,
    ReadModelImageAndRevisionDigests,
    ReadFailureReason,
    DeploymentVerificationProposal,
    ReceiptRecording,
    EndpointConfigVariantRegistration,
    ResultFingerprintVerification,
    ReversibleRegistration,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SageMakerCapabilitySnapshot {
    pub capabilities: BTreeSet<SageMakerCapability>,
    pub read_only: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub native_status: NativeStatus,
}

impl SageMakerCapabilitySnapshot {
    pub fn layer1() -> Self {
        Self {
            capabilities: BTreeSet::from([
                SageMakerCapability::DescribeEndpointMetadata,
                SageMakerCapability::DescribeEndpointConfigMetadata,
                SageMakerCapability::ReadEndpointStatus,
                SageMakerCapability::ReadProductionVariantStatus,
                SageMakerCapability::ReadTrafficWeights,
                SageMakerCapability::ReadModelImageAndRevisionDigests,
                SageMakerCapability::ReadFailureReason,
                SageMakerCapability::DeploymentVerificationProposal,
                SageMakerCapability::ReceiptRecording,
                SageMakerCapability::EndpointConfigVariantRegistration,
                SageMakerCapability::ResultFingerprintVerification,
                SageMakerCapability::ReversibleRegistration,
            ]),
            read_only: true,
            external_writes: false,
            kernel_authority: false,
            native_status: NativeStatus::BlockedEnv,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if *self == Self::layer1() {
            Ok(())
        } else {
            Err(SageMakerEndpointResultError::InvalidRegistration)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SageMakerRegistration {
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub service_id: String,
    pub adapter_revision: u64,
    pub capability_snapshot: SageMakerCapabilitySnapshot,
    pub permission_snapshot_digest: Digest,
    pub scope: SageMakerScope,
    pub scope_digest: Digest,
    pub secret_reference: SecretReference,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
}

impl SageMakerRegistration {
    pub fn new(
        scope: SageMakerScope,
        secret_reference: SecretReference,
        adapter_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            plugin_id: crate::PLUGIN_ID.to_owned(),
            plugin_version: crate::PLUGIN_VERSION,
            contract_version: crate::CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: crate::PROVIDER_ID.to_owned(),
            provider_version: crate::PROVIDER_VERSION,
            service_id: crate::SERVICE_ID.to_owned(),
            adapter_revision,
            capability_snapshot: SageMakerCapabilitySnapshot::layer1(),
            permission_snapshot_digest: scope.permission_snapshot.digest().clone(),
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision: 1,
            status: RegistrationStatus::Active,
            registration_digest: Digest::pending(),
        };
        registration.registration_digest = registration.computed_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<()> {
        if self.plugin_id != crate::PLUGIN_ID
            || self.plugin_version != crate::PLUGIN_VERSION
            || self.contract_version != crate::CONTRACT_VERSION
            || self.provider_id != crate::PROVIDER_ID
            || self.provider_version != crate::PROVIDER_VERSION
            || self.service_id != crate::SERVICE_ID
            || self.adapter_revision == 0
            || self.registration_revision == 0
        {
            return Err(SageMakerEndpointResultError::InvalidRegistration);
        }
        self.plugin_version.validate()?;
        self.provider_version.validate()?;
        self.contract_digest.validate()?;
        self.capability_snapshot.validate()?;
        self.scope.validate()?;
        self.scope_digest.validate()?;
        self.permission_snapshot_digest.validate()?;
        self.secret_reference.validate_for_scope(&self.scope)?;
        if self.contract_digest != crate::contract_digest()
            || self.scope_digest != self.scope.digest()
            || self.permission_snapshot_digest != *self.scope.permission_snapshot.digest()
            || self.registration_digest != self.computed_digest()
        {
            return Err(SageMakerEndpointResultError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.registration_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation> {
        self.validate()?;
        if self.status != RegistrationStatus::Active {
            return Err(SageMakerEndpointResultError::RegistrationRevoked);
        }
        let previous_digest = self.registration_digest.clone();
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(SageMakerEndpointResultError::InvalidRegistration)?;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.computed_digest();
        Ok(RegistrationRevocation {
            previous_digest,
            revoked_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: true,
        })
    }

    pub fn reissue(
        &self,
        scope: SageMakerScope,
        secret_reference: SecretReference,
        adapter_revision: u64,
    ) -> Result<Self> {
        Self::new(scope, secret_reference, adapter_revision)
    }
}

pub type SageMakerPluginRegistration = SageMakerRegistration;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub previous_digest: Digest,
    pub revoked_digest: Digest,
    pub registration_revision: u64,
    pub reversible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionWorkProductBinding {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub mission_revision: u64,
    pub work_product_revision: u64,
}

impl MissionWorkProductBinding {
    pub fn new(scope: &SageMakerScope) -> Result<Self> {
        let binding = Self {
            project_id: scope.project_id.clone(),
            mission_id: scope.mission_id.clone(),
            work_product_id: scope.work_product_id.clone(),
            mission_revision: scope.mission_revision,
            work_product_revision: scope.work_product_revision,
        };
        binding.validate_for(scope)?;
        Ok(binding)
    }

    pub fn validate_for(&self, scope: &SageMakerScope) -> Result<()> {
        if self.project_id != scope.project_id
            || self.mission_id != scope.mission_id
            || self.work_product_id != scope.work_product_id
            || self.mission_revision != scope.mission_revision
            || self.work_product_revision != scope.work_product_revision
        {
            return Err(SageMakerEndpointResultError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SageMakerReadRequest {
    pub scope: SageMakerScope,
    pub mission_revision: u64,
    pub work_product_revision: u64,
}

impl SageMakerReadRequest {
    pub fn new(
        scope: SageMakerScope,
        mission_revision: u64,
        work_product_revision: u64,
    ) -> Result<Self> {
        let request = Self {
            scope,
            mission_revision,
            work_product_revision,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        if self.mission_revision != self.scope.mission_revision {
            return Err(SageMakerEndpointResultError::StaleMissionRevision);
        }
        if self.work_product_revision != self.scope.work_product_revision {
            return Err(SageMakerEndpointResultError::StaleWorkProductRevision);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SageMakerEndpointStatus {
    Creating,
    InService,
    Updating,
    SystemUpdating,
    RollingBack,
    OutOfService,
    Deleting,
    Failed,
    UpdateRollbackFailed,
    ProviderUnknown(String),
}

impl SageMakerEndpointStatus {
    pub fn provider(value: impl AsRef<str>) -> Result<Self> {
        let value = value.as_ref();
        Ok(match value {
            "Creating" => Self::Creating,
            "InService" => Self::InService,
            "Updating" => Self::Updating,
            "SystemUpdating" => Self::SystemUpdating,
            "RollingBack" => Self::RollingBack,
            "OutOfService" => Self::OutOfService,
            "Deleting" => Self::Deleting,
            "Failed" => Self::Failed,
            "UpdateRollbackFailed" => Self::UpdateRollbackFailed,
            other => {
                validate_bounded_text(other, "provider endpoint status", 128)?;
                Self::ProviderUnknown(other.to_owned())
            }
        })
    }

    pub fn validate(&self) -> Result<()> {
        if let Self::ProviderUnknown(value) = self {
            validate_bounded_text(value, "provider endpoint status", 128)?;
        }
        Ok(())
    }

    pub fn is_operational(&self) -> bool {
        matches!(self, Self::InService)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionVariantStatus {
    Creating,
    Deleting,
    Updating,
    ActivatingTraffic,
    Baking,
    Stable,
    ProviderUnknown(String),
}

impl ProductionVariantStatus {
    pub fn provider(value: impl AsRef<str>) -> Result<Self> {
        let value = value.as_ref();
        Ok(match value {
            "Creating" => Self::Creating,
            "Deleting" => Self::Deleting,
            "Updating" => Self::Updating,
            "ActivatingTraffic" => Self::ActivatingTraffic,
            "Baking" => Self::Baking,
            other => {
                validate_bounded_text(other, "provider production variant status", 128)?;
                Self::ProviderUnknown(other.to_owned())
            }
        })
    }

    pub fn stable() -> Self {
        Self::Stable
    }

    pub fn validate(&self) -> Result<()> {
        if let Self::ProviderUnknown(value) = self {
            validate_bounded_text(value, "provider production variant status", 128)?;
        }
        Ok(())
    }

    pub fn is_pending(&self) -> bool {
        matches!(
            self,
            Self::Creating
                | Self::Deleting
                | Self::Updating
                | Self::ActivatingTraffic
                | Self::Baking
        )
    }

    pub fn is_known_operational(&self) -> bool {
        matches!(self, Self::Stable)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SageMakerResultState {
    Ready,
    Creating,
    Updating,
    SystemUpdating,
    RollingBack,
    OutOfService,
    Deleting,
    Failed,
    UpdateRollbackFailed,
    VariantUpdating,
    VariantStatusMismatch,
    TrafficMismatch,
    EndpointConfigDrift,
    SameNameReplacement,
    Partial,
    AccessLost,
    ProviderUnknown,
}

impl SageMakerResultState {
    pub const fn is_adoptable(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// A typed projection of the DescribeEndpoint response. It intentionally has
/// no raw JSON, data-capture payload, log payload, or secret-bearing field.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointProductionVariantRecord {
    pub variant_name: ProductionVariantName,
    pub current_weight: TrafficWeight,
    pub desired_weight: Option<TrafficWeight>,
    pub status: ProductionVariantStatus,
    pub status_message: Option<FailureReason>,
    pub model_name: ModelName,
    pub model_revision: ModelRevision,
    pub image_reference: ImageReference,
    pub code_digest: Digest,
    pub config_digest: Digest,
}

impl EndpointProductionVariantRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        variant_name: ProductionVariantName,
        current_weight: TrafficWeight,
        desired_weight: Option<TrafficWeight>,
        status: ProductionVariantStatus,
        status_message: Option<FailureReason>,
        model_name: ModelName,
        model_revision: ModelRevision,
        image_reference: ImageReference,
        code_digest: Digest,
        config_digest: Digest,
    ) -> Result<Self> {
        let record = Self {
            variant_name,
            current_weight,
            desired_weight,
            status,
            status_message,
            model_name,
            model_revision,
            image_reference,
            code_digest,
            config_digest,
        };
        record.validate()
    }

    pub fn validate(&self) -> Result<Self> {
        self.variant_name.validate()?;
        self.current_weight.validate()?;
        if let Some(weight) = self.desired_weight {
            weight.validate()?;
        }
        self.status.validate()?;
        if let Some(reason) = &self.status_message {
            reason.validate()?;
        }
        self.model_name.validate()?;
        self.model_revision.validate()?;
        self.image_reference.validate()?;
        self.code_digest.validate()?;
        self.config_digest.validate()?;
        Ok(self.clone())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointDescriptionRecord {
    pub aws_account_id: AwsAccountId,
    pub aws_region: AwsRegion,
    pub endpoint_name: SageMakerEndpointName,
    pub endpoint_arn_digest: Digest,
    pub endpoint_config_name: SageMakerEndpointConfigName,
    pub status: SageMakerEndpointStatus,
    pub failure_reason: Option<FailureReason>,
    pub creation_time: Option<MetadataTimestamp>,
    pub last_modified_time: Option<MetadataTimestamp>,
    pub production_variants: Vec<EndpointProductionVariantRecord>,
    pub request_id_digest: Option<Digest>,
    pub partial: bool,
    pub access_lost: bool,
}

impl EndpointDescriptionRecord {
    pub fn validate(&self) -> Result<()> {
        self.aws_account_id.validate()?;
        self.aws_region.validate()?;
        validate_sagemaker_name(self.endpoint_name.as_str(), "SageMaker endpoint")?;
        self.endpoint_arn_digest.validate()?;
        validate_sagemaker_name(
            self.endpoint_config_name.as_str(),
            "SageMaker endpoint configuration",
        )?;
        self.status.validate()?;
        if let Some(reason) = &self.failure_reason {
            reason.validate()?;
        }
        if let Some(timestamp) = &self.creation_time {
            timestamp.validate()?;
        }
        if let Some(timestamp) = &self.last_modified_time {
            timestamp.validate()?;
        }
        if let Some(request_id_digest) = &self.request_id_digest {
            request_id_digest.validate()?;
        }
        if self.production_variants.is_empty()
            || self.production_variants.len() > MAX_PRODUCTION_VARIANTS
        {
            return Err(SageMakerEndpointResultError::PartialResponse);
        }
        for variant in &self.production_variants {
            variant.validate()?;
        }
        Ok(())
    }

    pub fn observation_digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn variant(
        &self,
        name: &ProductionVariantName,
    ) -> Option<&EndpointProductionVariantRecord> {
        self.production_variants
            .iter()
            .find(|variant| &variant.variant_name == name)
    }

    pub fn traffic_snapshot(&self) -> Result<TrafficSnapshot> {
        TrafficSnapshot::new(
            self.production_variants
                .iter()
                .map(|variant| TrafficAllocation {
                    variant_name: variant.variant_name.clone(),
                    weight: variant.current_weight,
                })
                .collect(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointConfigProductionVariantRecord {
    pub variant_name: ProductionVariantName,
    pub initial_weight: TrafficWeight,
    pub model_name: ModelName,
    pub model_revision: ModelRevision,
    pub image_reference: ImageReference,
    pub code_digest: Digest,
}

impl EndpointConfigProductionVariantRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        variant_name: ProductionVariantName,
        initial_weight: TrafficWeight,
        model_name: ModelName,
        model_revision: ModelRevision,
        image_reference: ImageReference,
        code_digest: Digest,
    ) -> Result<Self> {
        let record = Self {
            variant_name,
            initial_weight,
            model_name,
            model_revision,
            image_reference,
            code_digest,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<()> {
        self.variant_name.validate()?;
        self.initial_weight.validate()?;
        self.model_name.validate()?;
        self.model_revision.validate()?;
        self.image_reference.validate()?;
        self.code_digest.validate()
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointConfigDescriptionRecord {
    pub aws_account_id: AwsAccountId,
    pub aws_region: AwsRegion,
    pub endpoint_config_name: SageMakerEndpointConfigName,
    pub endpoint_config_arn_digest: Digest,
    pub config_digest: Digest,
    pub creation_time: Option<MetadataTimestamp>,
    pub execution_role_digest: Option<Digest>,
    pub network_isolation: Option<bool>,
    pub production_variants: Vec<EndpointConfigProductionVariantRecord>,
    pub partial: bool,
    pub access_lost: bool,
}

impl EndpointConfigDescriptionRecord {
    pub fn validate(&self) -> Result<()> {
        self.aws_account_id.validate()?;
        self.aws_region.validate()?;
        validate_sagemaker_name(
            self.endpoint_config_name.as_str(),
            "SageMaker endpoint configuration",
        )?;
        self.endpoint_config_arn_digest.validate()?;
        self.config_digest.validate()?;
        if let Some(timestamp) = &self.creation_time {
            timestamp.validate()?;
        }
        if let Some(execution_role_digest) = &self.execution_role_digest {
            execution_role_digest.validate()?;
        }
        if self.production_variants.is_empty()
            || self.production_variants.len() > MAX_PRODUCTION_VARIANTS
        {
            return Err(SageMakerEndpointResultError::PartialResponse);
        }
        for variant in &self.production_variants {
            variant.validate()?;
        }
        Ok(())
    }

    pub fn observation_digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn variant(
        &self,
        name: &ProductionVariantName,
    ) -> Option<&EndpointConfigProductionVariantRecord> {
        self.production_variants
            .iter()
            .find(|variant| &variant.variant_name == name)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SageMakerEndpointDescription {
    pub scope: SageMakerScope,
    pub endpoint_arn_digest: Digest,
    pub endpoint_config_name: SageMakerEndpointConfigName,
    pub status: SageMakerEndpointStatus,
    pub failure_reason: Option<FailureReason>,
    pub production_variant_count: usize,
    pub creation_time: Option<MetadataTimestamp>,
    pub last_modified_time: Option<MetadataTimestamp>,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub first_party: bool,
    pub read_digest: Digest,
}

impl SageMakerEndpointDescription {
    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.read_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.endpoint_arn_digest.validate()?;
        self.endpoint_config_name.validate()?;
        self.status.validate()?;
        if let Some(reason) = &self.failure_reason {
            reason.validate()?;
        }
        if let Some(timestamp) = &self.creation_time {
            timestamp.validate()?;
        }
        if let Some(timestamp) = &self.last_modified_time {
            timestamp.validate()?;
        }
        if self.native_transport != self.provenance.is_native()
            || self.native_connected
            || self.first_party
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.read_digest != self.computed_digest()
        {
            return Err(SageMakerEndpointResultError::InvalidEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SageMakerEndpointConfigDescription {
    pub scope: SageMakerScope,
    pub endpoint_config_arn_digest: Digest,
    pub config_digest: Digest,
    pub production_variant_count: usize,
    pub creation_time: Option<MetadataTimestamp>,
    pub execution_role_digest: Option<Digest>,
    pub network_isolation: Option<bool>,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub first_party: bool,
    pub read_digest: Digest,
}

impl SageMakerEndpointConfigDescription {
    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.read_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.endpoint_config_arn_digest.validate()?;
        self.config_digest.validate()?;
        if let Some(timestamp) = &self.creation_time {
            timestamp.validate()?;
        }
        if let Some(execution_role_digest) = &self.execution_role_digest {
            execution_role_digest.validate()?;
        }
        if self.native_transport != self.provenance.is_native()
            || self.native_connected
            || self.first_party
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.read_digest != self.computed_digest()
        {
            return Err(SageMakerEndpointResultError::InvalidEvidence);
        }
        Ok(())
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SageMakerDeploymentEvidence {
    pub scope: SageMakerScope,
    pub registration_digest: Digest,
    pub endpoint_digest: Digest,
    pub endpoint_config_digest: Digest,
    pub variant_digest: Digest,
    pub status_digest: Digest,
    pub endpoint_name: SageMakerEndpointName,
    pub endpoint_arn_digest: Digest,
    pub endpoint_config_name: SageMakerEndpointConfigName,
    pub endpoint_config_arn_digest: Digest,
    pub endpoint_status: SageMakerEndpointStatus,
    pub endpoint_failure_reason: Option<FailureReason>,
    pub variant_name: ProductionVariantName,
    pub variant_status: ProductionVariantStatus,
    pub variant_status_message: Option<FailureReason>,
    pub traffic: TrafficSnapshot,
    pub model_name: ModelName,
    pub model_revision: ModelRevision,
    pub image_reference: ImageReference,
    pub code_digest: Digest,
    pub config_digest: Digest,
    pub endpoint_config_metadata_digest: Digest,
    pub endpoint_creation_time: Option<MetadataTimestamp>,
    pub endpoint_last_modified_time: Option<MetadataTimestamp>,
    pub config_creation_time: Option<MetadataTimestamp>,
    pub failure_reason: Option<FailureReason>,
    pub state: SageMakerResultState,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub first_party: bool,
    pub partial: bool,
    pub observed_at: MetadataTimestamp,
    pub evidence_digest: Digest,
}

impl SageMakerDeploymentEvidence {
    pub fn is_adoptable(&self) -> bool {
        self.state.is_adoptable()
            && self.endpoint_status.is_operational()
            && self.variant_status.is_known_operational()
            && self.traffic == self.scope.traffic
            && !self.partial
    }

    pub fn computed_endpoint_digest(&self) -> Digest {
        canonical_digest(&(
            &self.endpoint_name,
            &self.endpoint_arn_digest,
            &self.endpoint_config_name,
            &self.endpoint_status,
            &self.endpoint_failure_reason,
            &self.endpoint_creation_time,
            &self.endpoint_last_modified_time,
        ))
    }

    pub fn computed_variant_digest(&self) -> Digest {
        canonical_digest(&(
            &self.variant_name,
            &self.traffic,
            &self.model_name,
            &self.model_revision,
            &self.image_reference,
            &self.code_digest,
            &self.config_digest,
        ))
    }

    pub fn computed_endpoint_config_metadata_digest(&self) -> Digest {
        canonical_digest(&(
            &self.endpoint_config_name,
            &self.endpoint_config_arn_digest,
            &self.config_digest,
            &self.config_creation_time,
        ))
    }

    pub fn computed_status_digest(&self) -> Digest {
        canonical_digest(&(
            &self.endpoint_status,
            &self.variant_status,
            &self.endpoint_failure_reason,
            &self.variant_status_message,
            &self.state,
        ))
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.evidence_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.registration_digest.validate()?;
        self.endpoint_digest.validate()?;
        self.endpoint_config_digest.validate()?;
        self.variant_digest.validate()?;
        self.status_digest.validate()?;
        self.endpoint_name.validate()?;
        self.endpoint_arn_digest.validate()?;
        self.endpoint_config_name.validate()?;
        self.endpoint_config_arn_digest.validate()?;
        self.endpoint_status.validate()?;
        if let Some(reason) = &self.endpoint_failure_reason {
            reason.validate()?;
        }
        self.variant_name.validate()?;
        self.variant_status.validate()?;
        if let Some(reason) = &self.variant_status_message {
            reason.validate()?;
        }
        self.traffic.validate()?;
        self.model_name.validate()?;
        self.model_revision.validate()?;
        self.image_reference.validate()?;
        self.code_digest.validate()?;
        self.config_digest.validate()?;
        self.endpoint_config_metadata_digest.validate()?;
        if let Some(timestamp) = &self.endpoint_creation_time {
            timestamp.validate()?;
        }
        if let Some(timestamp) = &self.endpoint_last_modified_time {
            timestamp.validate()?;
        }
        if let Some(timestamp) = &self.config_creation_time {
            timestamp.validate()?;
        }
        if let Some(reason) = &self.failure_reason {
            reason.validate()?;
        }
        self.observed_at.validate()?;
        if self.endpoint_name != self.scope.endpoint_name
            || self.endpoint_arn_digest != self.scope.endpoint_arn_digest
            || self.endpoint_config_name != self.scope.endpoint_config_name
            || self.endpoint_config_arn_digest != self.scope.endpoint_config_arn_digest
            || self.variant_name != self.scope.production_variant_name
            || self.model_name != self.scope.model_name
            || self.model_revision != self.scope.model_revision
            || self.image_reference != self.scope.image_reference
            || self.code_digest != self.scope.code_digest
            || self.config_digest != self.scope.config_digest
            || self.endpoint_config_digest != self.scope.config_digest
            || self.endpoint_config_metadata_digest
                != self.computed_endpoint_config_metadata_digest()
            || self.traffic != self.scope.traffic
                && self.state != SageMakerResultState::TrafficMismatch
            || self.endpoint_digest != self.computed_endpoint_digest()
            || self.variant_digest != self.computed_variant_digest()
            || self.status_digest != self.computed_status_digest()
            || self.native_transport != self.provenance.is_native()
            || self.native_connected
            || self.first_party
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.evidence_digest != self.computed_digest()
        {
            return Err(SageMakerEndpointResultError::InvalidEvidence);
        }
        if self.partial && self.state != SageMakerResultState::Partial {
            return Err(SageMakerEndpointResultError::PartialResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultVerificationStatus {
    ProviderFingerprintMatch,
    NotVerified,
    ProviderUnknown,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SageMakerModelDeploymentProposal {
    pub proposal_id: String,
    pub proposal_digest: Digest,
    pub scope: SageMakerScope,
    pub binding: MissionWorkProductBinding,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub endpoint_digest: Digest,
    pub endpoint_config_digest: Digest,
    pub variant_digest: Digest,
    pub status_digest: Digest,
    pub endpoint_status: SageMakerEndpointStatus,
    pub variant_status: ProductionVariantStatus,
    pub traffic_digest: Digest,
    pub model_name: ModelName,
    pub model_revision: ModelRevision,
    pub image_reference: ImageReference,
    pub code_digest: Digest,
    pub config_digest: Digest,
    pub state: SageMakerResultState,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub first_party: bool,
    pub external_effect_performed: bool,
    pub durable_adoption: bool,
    pub kernel_authority: bool,
    pub verification_status: ResultVerificationStatus,
}

impl SageMakerModelDeploymentProposal {
    pub fn from_evidence(
        evidence: &SageMakerDeploymentEvidence,
        registration_digest: Digest,
    ) -> Result<Self> {
        evidence.validate()?;
        registration_digest.validate()?;
        if registration_digest != evidence.registration_digest {
            return Err(SageMakerEndpointResultError::RegistrationDigestMismatch);
        }
        if !evidence.is_adoptable() {
            return Err(SageMakerEndpointResultError::InvalidEvidence);
        }
        let binding = MissionWorkProductBinding::new(&evidence.scope)?;
        let mut proposal = Self {
            proposal_id: format!(
                "sagemaker-deployment-result-{}",
                &evidence.evidence_digest.as_str()[..24]
            ),
            proposal_digest: Digest::pending(),
            scope: evidence.scope.clone(),
            binding,
            registration_digest,
            evidence_digest: evidence.evidence_digest.clone(),
            endpoint_digest: evidence.endpoint_digest.clone(),
            endpoint_config_digest: evidence.endpoint_config_digest.clone(),
            variant_digest: evidence.variant_digest.clone(),
            status_digest: evidence.status_digest.clone(),
            endpoint_status: evidence.endpoint_status.clone(),
            variant_status: evidence.variant_status.clone(),
            traffic_digest: evidence.traffic.digest().clone(),
            model_name: evidence.model_name.clone(),
            model_revision: evidence.model_revision.clone(),
            image_reference: evidence.image_reference.clone(),
            code_digest: evidence.code_digest.clone(),
            config_digest: evidence.config_digest.clone(),
            state: evidence.state,
            provenance: evidence.provenance,
            native_transport: evidence.native_transport,
            native_connected: false,
            first_party: false,
            external_effect_performed: false,
            durable_adoption: false,
            kernel_authority: false,
            verification_status: ResultVerificationStatus::ProviderFingerprintMatch,
        };
        proposal.proposal_digest = proposal.computed_digest();
        proposal.validate_for_registration(&proposal.registration_digest.clone())?;
        Ok(proposal)
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.proposal_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn verified(&self) -> bool {
        self.verification_status == ResultVerificationStatus::ProviderFingerprintMatch
            && self.proposal_digest == self.computed_digest()
    }

    pub fn validate_for_registration(&self, registration_digest: &Digest) -> Result<()> {
        self.scope.validate()?;
        self.binding.validate_for(&self.scope)?;
        self.registration_digest.validate()?;
        self.evidence_digest.validate()?;
        self.endpoint_digest.validate()?;
        self.endpoint_config_digest.validate()?;
        self.variant_digest.validate()?;
        self.status_digest.validate()?;
        self.traffic_digest.validate()?;
        self.model_name.validate()?;
        self.model_revision.validate()?;
        self.image_reference.validate()?;
        self.code_digest.validate()?;
        self.config_digest.validate()?;
        self.endpoint_status.validate()?;
        self.variant_status.validate()?;
        if self.registration_digest != *registration_digest
            || self.state != SageMakerResultState::Ready
            || self.endpoint_config_digest != self.scope.config_digest
            || self.model_name != self.scope.model_name
            || self.model_revision != self.scope.model_revision
            || self.image_reference != self.scope.image_reference
            || self.code_digest != self.scope.code_digest
            || self.config_digest != self.scope.config_digest
            || self.traffic_digest != *self.scope.traffic.digest()
            || self.native_connected
            || self.first_party
            || self.external_effect_performed
            || self.durable_adoption
            || self.kernel_authority
            || self.verification_status != ResultVerificationStatus::ProviderFingerprintMatch
            || self.proposal_digest != self.computed_digest()
        {
            return Err(SageMakerEndpointResultError::InvalidEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SageMakerDeploymentReceipt {
    pub scope: SageMakerScope,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub endpoint_digest: Digest,
    pub endpoint_config_digest: Digest,
    pub variant_digest: Digest,
    pub status_digest: Digest,
    pub state: SageMakerResultState,
    pub provenance: ProviderProvenance,
    pub native_connected: bool,
    pub first_party: bool,
    pub receipt_digest: Digest,
}

impl SageMakerDeploymentReceipt {
    pub fn from_evidence(
        evidence: &SageMakerDeploymentEvidence,
        registration_digest: Digest,
    ) -> Result<Self> {
        evidence.validate()?;
        let mut receipt = Self {
            scope: evidence.scope.clone(),
            registration_digest,
            evidence_digest: evidence.evidence_digest.clone(),
            endpoint_digest: evidence.endpoint_digest.clone(),
            endpoint_config_digest: evidence.endpoint_config_digest.clone(),
            variant_digest: evidence.variant_digest.clone(),
            status_digest: evidence.status_digest.clone(),
            state: evidence.state,
            provenance: evidence.provenance,
            native_connected: false,
            first_party: false,
            receipt_digest: Digest::pending(),
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt.validate_against(evidence, &receipt.registration_digest.clone())?;
        Ok(receipt)
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.receipt_digest = Digest::pending();
        canonical_digest(&value)
    }

    pub fn validate_against(
        &self,
        evidence: &SageMakerDeploymentEvidence,
        registration_digest: &Digest,
    ) -> Result<()> {
        evidence.validate()?;
        self.scope.validate()?;
        self.registration_digest.validate()?;
        self.evidence_digest.validate()?;
        self.endpoint_digest.validate()?;
        self.endpoint_config_digest.validate()?;
        self.variant_digest.validate()?;
        self.status_digest.validate()?;
        self.receipt_digest.validate()?;
        if self.registration_digest != *registration_digest
            || self.registration_digest != evidence.registration_digest
            || self.scope != evidence.scope
            || self.evidence_digest != evidence.evidence_digest
            || self.endpoint_digest != evidence.endpoint_digest
            || self.endpoint_config_digest != evidence.endpoint_config_digest
            || self.variant_digest != evidence.variant_digest
            || self.status_digest != evidence.status_digest
            || self.state != evidence.state
            || self.provenance != evidence.provenance
            || self.native_connected
            || self.first_party
            || self.receipt_digest != self.computed_digest()
        {
            return Err(SageMakerEndpointResultError::ReceiptMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationDigestMismatch,
    ScopeMismatch,
    EvidenceDigestMismatch,
    EndpointDigestMismatch,
    EndpointConfigDigestMismatch,
    VariantDigestMismatch,
    StatusDigestMismatch,
    ReceiptMismatch,
    ProposalDigestMismatch,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SageMakerServiceOperation {
    DescribeEndpoint,
    DescribeEndpointConfig,
    ReadDeploymentEvidence,
    CompileModelDeploymentProposal,
    RecordDeploymentReceipt,
    VerifyDeploymentResult,
    MissionDeploymentProposal,
    Registration,
    Revocation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn validate(self) -> Result<()> {
        if self.major == 0 {
            Err(SageMakerEndpointResultError::InvalidInput {
                field: "plugin version",
                reason: "major version must be non-zero",
            })
        } else {
            Ok(())
        }
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_serializable(value)
}
