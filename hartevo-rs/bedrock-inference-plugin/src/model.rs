use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

use crate::digest::Digest;
use crate::error::{BedrockError, Result};

use super::{
    BEDROCK_CONVERSE_OPERATION, BEDROCK_INFERENCE_CONTRACT_VERSION,
    BEDROCK_INFERENCE_PLUGIN_VERSION, BEDROCK_RUNTIME_SERVICE,
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AwsPartition {
    Aws,
    AwsUsGov,
    AwsChina,
    Custom(String),
}

impl AwsPartition {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 32 || !value.bytes().all(is_partition_byte) {
            return Err(BedrockError::InvalidIdentifier {
                field: "aws_partition",
                reason: "must be a non-empty lowercase AWS partition token",
            });
        }
        Ok(match value.as_str() {
            "aws" => Self::Aws,
            "aws-us-gov" => Self::AwsUsGov,
            "aws-cn" => Self::AwsChina,
            _ => Self::Custom(value),
        })
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Aws => "aws",
            Self::AwsUsGov => "aws-us-gov",
            Self::AwsChina => "aws-cn",
            Self::Custom(value) => value,
        }
    }
}

impl Display for AwsPartition {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 12 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(BedrockError::InvalidAccountId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || !value.bytes().all(is_region_byte)
            || value == "global"
        {
            return Err(BedrockError::InvalidRegion);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProjectId(String);

impl ProjectId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        Ok(Self(validate_id(value.into(), "project_id")?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MissionId(String);

impl MissionId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        Ok(Self(validate_id(value.into(), "mission_id")?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ModelTargetKind {
    ModelId,
    ModelArn,
    InferenceProfileId,
    InferenceProfileArn,
}

impl ModelTargetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelId => "model_id",
            Self::ModelArn => "model_arn",
            Self::InferenceProfileId => "inference_profile_id",
            Self::InferenceProfileArn => "inference_profile_arn",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ModelTarget {
    ModelId(String),
    ModelArn(String),
    InferenceProfileId(String),
    InferenceProfileArn(String),
}

impl ModelTarget {
    pub fn model_id(value: impl Into<String>) -> Result<Self> {
        Self::from_value(ModelTargetKind::ModelId, value.into())
    }

    pub fn model_arn(value: impl Into<String>) -> Result<Self> {
        Self::from_value(ModelTargetKind::ModelArn, value.into())
    }

    pub fn inference_profile_id(value: impl Into<String>) -> Result<Self> {
        Self::from_value(ModelTargetKind::InferenceProfileId, value.into())
    }

    pub fn inference_profile_arn(value: impl Into<String>) -> Result<Self> {
        Self::from_value(ModelTargetKind::InferenceProfileArn, value.into())
    }

    fn from_value(kind: ModelTargetKind, value: String) -> Result<Self> {
        if value.is_empty()
            || value.len() > 512
            || value.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(BedrockError::InvalidModelTarget);
        }
        let is_arn = matches!(
            kind,
            ModelTargetKind::ModelArn | ModelTargetKind::InferenceProfileArn
        );
        if is_arn && !value.starts_with("arn:") {
            return Err(BedrockError::InvalidModelTarget);
        }
        if !is_arn && value.starts_with("arn:") {
            return Err(BedrockError::InvalidModelTarget);
        }
        if matches!(kind, ModelTargetKind::ModelArn) && !value.contains(":foundation-model/") {
            return Err(BedrockError::InvalidModelTarget);
        }
        if matches!(kind, ModelTargetKind::InferenceProfileArn)
            && !value.contains(":inference-profile/")
        {
            return Err(BedrockError::InvalidModelTarget);
        }
        Ok(match kind {
            ModelTargetKind::ModelId => Self::ModelId(value),
            ModelTargetKind::ModelArn => Self::ModelArn(value),
            ModelTargetKind::InferenceProfileId => Self::InferenceProfileId(value),
            ModelTargetKind::InferenceProfileArn => Self::InferenceProfileArn(value),
        })
    }

    pub const fn kind(&self) -> ModelTargetKind {
        match self {
            Self::ModelId(_) => ModelTargetKind::ModelId,
            Self::ModelArn(_) => ModelTargetKind::ModelArn,
            Self::InferenceProfileId(_) => ModelTargetKind::InferenceProfileId,
            Self::InferenceProfileArn(_) => ModelTargetKind::InferenceProfileArn,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::ModelId(value)
            | Self::ModelArn(value)
            | Self::InferenceProfileId(value)
            | Self::InferenceProfileArn(value) => value,
        }
    }

    pub fn is_inference_profile(&self) -> bool {
        matches!(
            self,
            Self::InferenceProfileId(_) | Self::InferenceProfileArn(_)
        )
    }

    pub fn canonical(&self) -> String {
        format!("{}:{}", self.kind().as_str(), self.as_str())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RoutingGeography {
    Regional { regions: Vec<AwsRegion> },
    Global,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RoutingPolicy {
    geography: RoutingGeography,
    digest: Digest,
}

impl RoutingPolicy {
    pub fn regional<I>(regions: I) -> Result<Self>
    where
        I: IntoIterator<Item = AwsRegion>,
    {
        let mut regions: Vec<_> = regions.into_iter().collect();
        regions.sort();
        regions.dedup();
        if regions.is_empty() {
            return Err(BedrockError::InvalidRoutingPolicy);
        }
        let canonical = regions
            .iter()
            .map(AwsRegion::as_str)
            .collect::<Vec<_>>()
            .join(",");
        let digest = Digest::of_str(&format!("regional:{canonical}"));
        Ok(Self {
            geography: RoutingGeography::Regional { regions },
            digest,
        })
    }

    pub fn global() -> Self {
        Self {
            geography: RoutingGeography::Global,
            digest: Digest::of_str("global"),
        }
    }

    pub const fn geography(&self) -> &RoutingGeography {
        &self.geography
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }

    pub fn permits(&self, region: &AwsRegion) -> bool {
        match &self.geography {
            RoutingGeography::Global => true,
            RoutingGeography::Regional { regions } => regions.contains(region),
        }
    }

    pub fn canonical(&self) -> String {
        match &self.geography {
            RoutingGeography::Global => "global".to_owned(),
            RoutingGeography::Regional { regions } => format!(
                "regional:{}",
                regions
                    .iter()
                    .map(AwsRegion::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GuardrailBinding {
    id: String,
    version: String,
    digest: Digest,
}

impl GuardrailBinding {
    pub fn new(id: impl Into<String>, version: impl Into<String>) -> Result<Self> {
        let id = validate_id(id.into(), "guardrail_id")?;
        let version = validate_id(version.into(), "guardrail_version")?;
        let digest = Digest::of_str(&format!("{id}:{version}"));
        Ok(Self {
            id,
            version,
            digest,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BudgetPolicy {
    policy_revision: u64,
    max_input_tokens: u32,
    max_output_tokens: u32,
    max_total_tokens: u32,
    max_latency_ms: u64,
    digest: Digest,
}

impl BudgetPolicy {
    pub fn new(
        policy_revision: u64,
        max_input_tokens: u32,
        max_output_tokens: u32,
        max_total_tokens: u32,
        max_latency_ms: u64,
    ) -> Result<Self> {
        if policy_revision == 0
            || max_input_tokens == 0
            || max_output_tokens == 0
            || max_total_tokens < max_output_tokens
            || max_latency_ms == 0
        {
            return Err(BedrockError::InvalidBudgetPolicy);
        }
        let canonical = format!(
            "revision={policy_revision};input={max_input_tokens};output={max_output_tokens};total={max_total_tokens};latency={max_latency_ms}"
        );
        Ok(Self {
            policy_revision,
            max_input_tokens,
            max_output_tokens,
            max_total_tokens,
            max_latency_ms,
            digest: Digest::of_str(&canonical),
        })
    }

    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    pub const fn max_input_tokens(&self) -> u32 {
        self.max_input_tokens
    }

    pub const fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }

    pub const fn max_total_tokens(&self) -> u32 {
        self.max_total_tokens
    }

    pub const fn max_latency_ms(&self) -> u64 {
        self.max_latency_ms
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ServiceTier {
    Standard,
    Priority,
}

impl ServiceTier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Priority => "priority",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InferenceField {
    Temperature,
    TopP,
    StopSequences,
    ServiceTier,
    UnsupportedModelField,
}

impl InferenceField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Temperature => "temperature",
            Self::TopP => "top_p",
            Self::StopSequences => "stop_sequences",
            Self::ServiceTier => "service_tier",
            Self::UnsupportedModelField => "unsupported_model_field",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InferenceConfig {
    max_tokens: Option<u32>,
    temperature_milli: Option<i32>,
    top_p_milli: Option<u16>,
    stop_sequence_digests: Vec<Digest>,
    service_tier: ServiceTier,
    unsupported_fields: Vec<String>,
    digest: Digest,
}

impl InferenceConfig {
    pub fn new(max_tokens: Option<u32>) -> Self {
        let mut config = Self {
            max_tokens,
            temperature_milli: None,
            top_p_milli: None,
            stop_sequence_digests: Vec::new(),
            service_tier: ServiceTier::Standard,
            unsupported_fields: Vec::new(),
            digest: Digest::ZERO,
        };
        config.refresh_digest();
        config
    }

    pub fn explicit(max_tokens: u32) -> Self {
        Self::new(Some(max_tokens))
    }

    pub fn with_temperature_milli(mut self, value: i32) -> Result<Self> {
        if !(0..=1000).contains(&value) {
            return Err(BedrockError::InvalidInferenceConfig {
                field: InferenceField::Temperature,
            });
        }
        self.temperature_milli = Some(value);
        self.refresh_digest();
        Ok(self)
    }

    pub fn with_top_p_milli(mut self, value: u16) -> Result<Self> {
        if !(1..=1000).contains(&value) {
            return Err(BedrockError::InvalidInferenceConfig {
                field: InferenceField::TopP,
            });
        }
        self.top_p_milli = Some(value);
        self.refresh_digest();
        Ok(self)
    }

    pub fn with_stop_sequences<I, S>(mut self, values: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut digests = Vec::new();
        for value in values {
            let value = value.as_ref();
            if value.is_empty() || value.len() > 256 {
                return Err(BedrockError::InvalidInferenceConfig {
                    field: InferenceField::StopSequences,
                });
            }
            digests.push(Digest::of_str(value));
        }
        if digests.len() > 16 {
            return Err(BedrockError::InvalidInferenceConfig {
                field: InferenceField::StopSequences,
            });
        }
        self.stop_sequence_digests = digests;
        self.refresh_digest();
        Ok(self)
    }

    pub fn with_service_tier(mut self, service_tier: ServiceTier) -> Self {
        self.service_tier = service_tier;
        self.refresh_digest();
        self
    }

    pub fn with_unsupported_field(mut self, field: impl Into<String>) -> Result<Self> {
        let field = validate_id(field.into(), "unsupported_field")?;
        self.unsupported_fields.push(field);
        self.refresh_digest();
        Ok(self)
    }

    pub const fn max_tokens(&self) -> Option<u32> {
        self.max_tokens
    }

    pub const fn temperature_milli(&self) -> Option<i32> {
        self.temperature_milli
    }

    pub const fn top_p_milli(&self) -> Option<u16> {
        self.top_p_milli
    }

    pub fn stop_sequence_digests(&self) -> &[Digest] {
        &self.stop_sequence_digests
    }

    pub const fn service_tier(&self) -> ServiceTier {
        self.service_tier
    }

    pub fn unsupported_fields(&self) -> &[String] {
        &self.unsupported_fields
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }

    pub fn validate(&self, budget: &BudgetPolicy, capability_max_tokens: u32) -> Result<()> {
        let Some(max_tokens) = self.max_tokens else {
            return Err(BedrockError::MaxTokensRequired);
        };
        if max_tokens == 0 {
            return Err(BedrockError::InvalidInferenceConfig {
                field: InferenceField::UnsupportedModelField,
            });
        }
        if max_tokens > budget.max_output_tokens() {
            return Err(BedrockError::MaxTokensExceedsPolicy {
                requested: max_tokens,
                maximum: budget.max_output_tokens(),
            });
        }
        if max_tokens > capability_max_tokens {
            return Err(BedrockError::MaxTokensExceedsCapability {
                requested: max_tokens,
                maximum: capability_max_tokens,
            });
        }
        if !self.unsupported_fields.is_empty() {
            return Err(BedrockError::UnsupportedFields(
                self.unsupported_fields.clone(),
            ));
        }
        Ok(())
    }

    pub fn canonical(&self) -> String {
        let max_tokens = self
            .max_tokens
            .map_or_else(|| "omitted".to_owned(), |value| value.to_string());
        let temperature = self
            .temperature_milli
            .map_or_else(|| "omitted".to_owned(), |value| value.to_string());
        let top_p = self
            .top_p_milli
            .map_or_else(|| "omitted".to_owned(), |value| value.to_string());
        let stop_sequences = self
            .stop_sequence_digests
            .iter()
            .map(Digest::as_hex)
            .collect::<Vec<_>>()
            .join(",");
        let unsupported = self.unsupported_fields.join(",");
        format!(
            "max_tokens={max_tokens};temperature_milli={temperature};top_p_milli={top_p};stop_sequence_digests={stop_sequences};service_tier={};unsupported={unsupported}",
            self.service_tier.as_str()
        )
    }

    fn refresh_digest(&mut self) {
        self.digest = Digest::of_str(&self.canonical());
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ContentRole {
    System,
    User,
    Assistant,
    Tool,
}

impl ContentRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ContentMessageDigest {
    role: ContentRole,
    content_digest: Digest,
    block_count: u16,
}

impl ContentMessageDigest {
    pub fn new(role: ContentRole, content_digest: Digest, block_count: u16) -> Result<Self> {
        if block_count == 0 {
            return Err(BedrockError::InvalidContentDigest);
        }
        Ok(Self {
            role,
            content_digest,
            block_count,
        })
    }

    pub const fn role(&self) -> ContentRole {
        self.role
    }

    pub const fn content_digest(&self) -> Digest {
        self.content_digest
    }

    pub const fn block_count(&self) -> u16 {
        self.block_count
    }

    fn canonical(&self) -> String {
        format!(
            "role={};digest={};blocks={}",
            self.role.as_str(),
            self.content_digest,
            self.block_count
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ContentDigests {
    system_digest: Option<Digest>,
    messages: Vec<ContentMessageDigest>,
    documents_digest: Option<Digest>,
    digest: Digest,
}

impl ContentDigests {
    pub fn new(
        system_digest: Option<Digest>,
        messages: Vec<ContentMessageDigest>,
        documents_digest: Option<Digest>,
    ) -> Result<Self> {
        if messages.is_empty() || messages.len() > 256 {
            return Err(BedrockError::InvalidContentDigest);
        }
        let mut result = Self {
            system_digest,
            messages,
            documents_digest,
            digest: Digest::ZERO,
        };
        result.refresh_digest();
        Ok(result)
    }

    pub const fn system_digest(&self) -> Option<Digest> {
        self.system_digest
    }

    pub fn messages(&self) -> &[ContentMessageDigest] {
        &self.messages
    }

    pub const fn documents_digest(&self) -> Option<Digest> {
        self.documents_digest
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }

    pub fn canonical(&self) -> String {
        let system = self
            .system_digest
            .map_or_else(|| "none".to_owned(), |digest| digest.as_hex());
        let documents = self
            .documents_digest
            .map_or_else(|| "none".to_owned(), |digest| digest.as_hex());
        let messages = self
            .messages
            .iter()
            .map(ContentMessageDigest::canonical)
            .collect::<Vec<_>>()
            .join("|");
        format!("system={system};messages={messages};documents={documents}")
    }

    fn refresh_digest(&mut self) {
        self.digest = Digest::of_str(&self.canonical());
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ToolSchemaDigest {
    digest: Digest,
    tool_count: u16,
}

impl ToolSchemaDigest {
    pub fn new(digest: Digest, tool_count: u16) -> Result<Self> {
        if tool_count == 0 || tool_count > 256 {
            return Err(BedrockError::InvalidToolSchema);
        }
        Ok(Self { digest, tool_count })
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }

    pub const fn tool_count(&self) -> u16 {
        self.tool_count
    }

    pub fn canonical(&self) -> String {
        format!("digest={};tools={}", self.digest, self.tool_count)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MissionContext {
    project_id: ProjectId,
    mission_id: MissionId,
    mission_revision: u64,
    budget_policy: BudgetPolicy,
}

impl MissionContext {
    pub fn new(
        project_id: ProjectId,
        mission_id: MissionId,
        mission_revision: u64,
        budget_policy: BudgetPolicy,
    ) -> Result<Self> {
        if mission_revision == 0 {
            return Err(BedrockError::InvalidMissionRevision);
        }
        Ok(Self {
            project_id,
            mission_id,
            mission_revision,
            budget_policy,
        })
    }

    pub const fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub const fn budget_policy(&self) -> &BudgetPolicy {
        &self.budget_policy
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BedrockScope {
    partition: AwsPartition,
    account_id: AwsAccountId,
    source_region: AwsRegion,
    runtime_service: &'static str,
    model_or_inference_profile: ModelTarget,
    routing_policy: RoutingPolicy,
    guardrail: Option<GuardrailBinding>,
    project_id: ProjectId,
    mission_id: MissionId,
    mission_revision: u64,
    budget_policy: BudgetPolicy,
    digest: Digest,
}

impl BedrockScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        partition: AwsPartition,
        account_id: AwsAccountId,
        source_region: AwsRegion,
        model_or_inference_profile: ModelTarget,
        routing_policy: RoutingPolicy,
        guardrail: Option<GuardrailBinding>,
        project_id: ProjectId,
        mission_id: MissionId,
        mission_revision: u64,
        budget_policy: BudgetPolicy,
    ) -> Result<Self> {
        if mission_revision == 0 {
            return Err(BedrockError::InvalidMissionRevision);
        }
        validate_model_target_scope(
            &model_or_inference_profile,
            &partition,
            &account_id,
            &source_region,
        )?;
        let mut scope = Self {
            partition,
            account_id,
            source_region,
            runtime_service: BEDROCK_RUNTIME_SERVICE,
            model_or_inference_profile,
            routing_policy,
            guardrail,
            project_id,
            mission_id,
            mission_revision,
            budget_policy,
            digest: Digest::ZERO,
        };
        scope.refresh_digest();
        Ok(scope)
    }

    pub fn partition(&self) -> &AwsPartition {
        &self.partition
    }

    pub fn account_id(&self) -> &AwsAccountId {
        &self.account_id
    }

    pub fn source_region(&self) -> &AwsRegion {
        &self.source_region
    }

    pub const fn runtime_service(&self) -> &'static str {
        self.runtime_service
    }

    pub fn model_or_inference_profile(&self) -> &ModelTarget {
        &self.model_or_inference_profile
    }

    pub const fn routing_policy(&self) -> &RoutingPolicy {
        &self.routing_policy
    }

    pub const fn guardrail(&self) -> Option<&GuardrailBinding> {
        self.guardrail.as_ref()
    }

    pub const fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub const fn budget_policy(&self) -> &BudgetPolicy {
        &self.budget_policy
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }

    pub fn canonical(&self) -> String {
        let guardrail = self.guardrail.as_ref().map_or_else(
            || "none".to_owned(),
            |value| format!("{}:{}", value.id(), value.version()),
        );
        format!(
            "partition={};account={};source_region={};service={};target={};routing={};routing_digest={};guardrail={guardrail};project={};mission={};mission_revision={};policy_revision={};budget_digest={}",
            self.partition,
            self.account_id.as_str(),
            self.source_region.as_str(),
            self.runtime_service,
            self.model_or_inference_profile.canonical(),
            self.routing_policy.canonical(),
            self.routing_policy.digest(),
            self.project_id.as_str(),
            self.mission_id.as_str(),
            self.mission_revision,
            self.budget_policy.policy_revision(),
            self.budget_policy.digest(),
        )
    }

    fn refresh_digest(&mut self) {
        self.digest = Digest::of_str(&self.canonical());
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ModelCapabilitySnapshot {
    target: ModelTarget,
    scope_digest: Digest,
    capability_revision: u64,
    supports_converse: bool,
    supports_non_streaming: bool,
    supports_tool_use: bool,
    max_output_tokens: u32,
    digest: Digest,
}

impl ModelCapabilitySnapshot {
    pub fn new(
        scope: &BedrockScope,
        capability_revision: u64,
        supports_tool_use: bool,
        max_output_tokens: u32,
    ) -> Result<Self> {
        if capability_revision == 0 || max_output_tokens == 0 {
            return Err(BedrockError::InvalidCapabilitySnapshot);
        }
        if max_output_tokens > scope.budget_policy().max_output_tokens() {
            return Err(BedrockError::InvalidCapabilitySnapshot);
        }
        let mut snapshot = Self {
            target: scope.model_or_inference_profile().clone(),
            scope_digest: scope.digest(),
            capability_revision,
            supports_converse: true,
            supports_non_streaming: true,
            supports_tool_use,
            max_output_tokens,
            digest: Digest::ZERO,
        };
        snapshot.refresh_digest();
        Ok(snapshot)
    }

    pub fn for_scope(
        scope: &BedrockScope,
        capability_revision: u64,
        supports_tool_use: bool,
        max_output_tokens: u32,
    ) -> Result<Self> {
        Self::new(
            scope,
            capability_revision,
            supports_tool_use,
            max_output_tokens,
        )
    }

    pub fn target(&self) -> &ModelTarget {
        &self.target
    }

    pub const fn scope_digest(&self) -> Digest {
        self.scope_digest
    }

    pub const fn capability_revision(&self) -> u64 {
        self.capability_revision
    }

    pub const fn supports_converse(&self) -> bool {
        self.supports_converse
    }

    pub const fn supports_non_streaming(&self) -> bool {
        self.supports_non_streaming
    }

    pub const fn supports_tool_use(&self) -> bool {
        self.supports_tool_use
    }

    pub const fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }

    fn canonical(&self) -> String {
        format!(
            "target={};scope_digest={};revision={};converse={};non_streaming={};tool_use={};max_output_tokens={}",
            self.target.canonical(),
            self.scope_digest,
            self.capability_revision,
            self.supports_converse,
            self.supports_non_streaming,
            self.supports_tool_use,
            self.max_output_tokens
        )
    }

    fn refresh_digest(&mut self) {
        self.digest = Digest::of_str(&self.canonical());
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct SecretReference {
    opaque_reference: String,
    role_arn: String,
    session_name: String,
    expires_at_epoch_seconds: u64,
}

impl SecretReference {
    pub fn temporary_role_session(
        opaque_reference: impl Into<String>,
        role_arn: impl Into<String>,
        session_name: impl Into<String>,
        expires_at_epoch_seconds: u64,
    ) -> Result<Self> {
        let opaque_reference = opaque_reference.into();
        let role_arn = role_arn.into();
        let session_name = session_name.into();
        if !opaque_reference.starts_with("secret://")
            || opaque_reference.len() > 512
            || contains_credential_material(&opaque_reference)
        {
            return Err(BedrockError::SecretReferenceRejected);
        }
        if !role_arn.starts_with("arn:")
            || !role_arn.contains(":iam::")
            || !role_arn.contains(":role/")
            || contains_credential_material(&role_arn)
        {
            return Err(BedrockError::SecretReferenceRejected);
        }
        if session_name.is_empty()
            || session_name.len() > 128
            || !session_name.bytes().all(is_session_byte)
            || expires_at_epoch_seconds == 0
        {
            return Err(BedrockError::SecretReferenceRejected);
        }
        Ok(Self {
            opaque_reference,
            role_arn,
            session_name,
            expires_at_epoch_seconds,
        })
    }

    pub fn long_lived_iam_user(
        _access_key: impl Into<String>,
        _secret_key: impl Into<String>,
    ) -> Result<Self> {
        Err(BedrockError::LongLivedCredentialsRejected)
    }

    pub fn role_arn(&self) -> &str {
        &self.role_arn
    }

    pub fn session_name(&self) -> &str {
        &self.session_name
    }

    pub const fn expires_at_epoch_seconds(&self) -> u64 {
        self.expires_at_epoch_seconds
    }

    pub const fn is_temporary_role_session(&self) -> bool {
        true
    }

    pub fn is_expired_at(&self, epoch_seconds: u64) -> bool {
        self.expires_at_epoch_seconds <= epoch_seconds
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::of_str(&self.opaque_reference)
    }
}

impl Debug for SecretReference {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &"temporary_role_session")
            .field("opaque_reference", &"[redacted]")
            .field("role_arn", &self.role_arn)
            .field("session_name", &self.session_name)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .finish()
    }
}

impl Display for SecretReference {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str("SecretReference(temporary_role_session:[redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Layer1Provenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl Layer1Provenance {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    pub const fn claims_connected(self) -> bool {
        false
    }

    pub const fn claims_native(self) -> bool {
        false
    }

    pub const fn claims_first_party(self) -> bool {
        false
    }

    pub const fn is_live(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DestinationEvidence {
    NotDisclosed,
    ProviderVerified { region: AwsRegion },
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InferenceRequest {
    content: ContentDigests,
    tool_schema: Option<ToolSchemaDigest>,
    config: InferenceConfig,
    digest: Digest,
}

impl InferenceRequest {
    pub fn new(
        content: ContentDigests,
        tool_schema: Option<ToolSchemaDigest>,
        config: InferenceConfig,
    ) -> Self {
        let mut request = Self {
            content,
            tool_schema,
            config,
            digest: Digest::ZERO,
        };
        request.refresh_digest();
        request
    }

    pub const fn content(&self) -> &ContentDigests {
        &self.content
    }

    pub const fn tool_schema(&self) -> Option<&ToolSchemaDigest> {
        self.tool_schema.as_ref()
    }

    pub const fn config(&self) -> &InferenceConfig {
        &self.config
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }

    pub fn canonical(&self) -> String {
        let tool_schema = self
            .tool_schema
            .as_ref()
            .map_or_else(|| "none".to_owned(), ToolSchemaDigest::canonical);
        format!(
            "content={};tool_schema={tool_schema};config={}",
            self.content.digest(),
            self.config.digest()
        )
    }

    fn refresh_digest(&mut self) {
        self.digest = Digest::of_str(&self.canonical());
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RegistrationId(Digest);

impl RegistrationId {
    pub(crate) fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }

    pub fn as_hex(self) -> String {
        self.0.as_hex()
    }
}

impl Display for RegistrationId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        write!(formatter, "registration:{}", self.0.short_hex())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InvocationProposal {
    registration_id: RegistrationId,
    scope_digest: Digest,
    capability_snapshot_digest: Digest,
    scope: BedrockScope,
    request: InferenceRequest,
    operation: &'static str,
    streaming: bool,
    digest: Digest,
}

impl InvocationProposal {
    pub(crate) fn new(
        registration_id: RegistrationId,
        scope: BedrockScope,
        capability: &ModelCapabilitySnapshot,
        request: InferenceRequest,
    ) -> Result<Self> {
        if scope.digest() != capability.scope_digest()
            || scope.model_or_inference_profile() != capability.target()
            || !capability.supports_converse()
            || !capability.supports_non_streaming()
        {
            return Err(BedrockError::CapabilityScopeMismatch);
        }
        let mut proposal = Self {
            registration_id,
            scope_digest: scope.digest(),
            capability_snapshot_digest: capability.digest(),
            scope,
            request,
            operation: BEDROCK_CONVERSE_OPERATION,
            streaming: false,
            digest: Digest::ZERO,
        };
        proposal.refresh_digest();
        Ok(proposal)
    }

    pub const fn registration_id(&self) -> RegistrationId {
        self.registration_id
    }

    pub const fn scope_digest(&self) -> Digest {
        self.scope_digest
    }

    pub const fn capability_snapshot_digest(&self) -> Digest {
        self.capability_snapshot_digest
    }

    pub const fn scope(&self) -> &BedrockScope {
        &self.scope
    }

    pub const fn request(&self) -> &InferenceRequest {
        &self.request
    }

    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    pub const fn streaming(&self) -> bool {
        self.streaming
    }

    pub const fn request_digest(&self) -> Digest {
        self.digest
    }

    pub const fn content_digest(&self) -> Digest {
        self.request.content().digest()
    }

    pub fn tool_schema_digest(&self) -> Option<Digest> {
        self.request.tool_schema().map(ToolSchemaDigest::digest)
    }

    pub const fn config_digest(&self) -> Digest {
        self.request.config().digest()
    }

    pub fn canonical(&self) -> String {
        format!(
            "plugin={BEDROCK_INFERENCE_PLUGIN_VERSION};contract={BEDROCK_INFERENCE_CONTRACT_VERSION};operation={};streaming={};registration={};scope={};capability={};request={}",
            self.operation,
            self.streaming,
            self.registration_id.digest(),
            self.scope_digest,
            self.capability_snapshot_digest,
            self.request.digest()
        )
    }

    fn refresh_digest(&mut self) {
        self.digest = Digest::of_str(&self.canonical());
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
    StopSequence,
    GuardrailIntervened,
    ContentFiltered,
    Unknown,
}

impl StopReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EndTurn => "end_turn",
            Self::ToolUse => "tool_use",
            Self::MaxTokens => "max_tokens",
            Self::StopSequence => "stop_sequence",
            Self::GuardrailIntervened => "guardrail_intervened",
            Self::ContentFiltered => "content_filtered",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GuardrailProjection {
    NotConfigured,
    NotIntervened,
    Intervened { safety_digest: Digest },
    ContentFiltered { safety_digest: Digest },
    Unknown { safety_digest: Digest },
}

impl GuardrailProjection {
    pub const fn not_configured() -> Self {
        Self::NotConfigured
    }

    pub const fn not_intervened() -> Self {
        Self::NotIntervened
    }

    pub const fn intervened(safety_digest: Digest) -> Self {
        Self::Intervened { safety_digest }
    }

    pub const fn content_filtered(safety_digest: Digest) -> Self {
        Self::ContentFiltered { safety_digest }
    }

    pub const fn unknown(safety_digest: Digest) -> Self {
        Self::Unknown { safety_digest }
    }

    pub fn digest(&self) -> Digest {
        match self {
            Self::NotConfigured => Digest::ZERO,
            Self::NotIntervened => Digest::of_str("not_intervened"),
            Self::Intervened { safety_digest }
            | Self::ContentFiltered { safety_digest }
            | Self::Unknown { safety_digest } => *safety_digest,
        }
    }

    pub const fn is_intervened(&self) -> bool {
        matches!(self, Self::Intervened { .. } | Self::ContentFiltered { .. })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ContentBlockKind {
    Text,
    ToolUse,
    Unknown,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UntrustedToolUseProposal {
    tool_use_digest: Digest,
    tool_name_digest: Digest,
    input_digest: Digest,
}

impl UntrustedToolUseProposal {
    pub(crate) fn new(
        tool_use_digest: Digest,
        tool_name_digest: Digest,
        input_digest: Digest,
    ) -> Self {
        Self {
            tool_use_digest,
            tool_name_digest,
            input_digest,
        }
    }

    pub const fn tool_use_digest(&self) -> Digest {
        self.tool_use_digest
    }

    pub const fn tool_name_digest(&self) -> Digest {
        self.tool_name_digest
    }

    pub const fn input_digest(&self) -> Digest {
        self.input_digest
    }

    pub const fn executed(&self) -> bool {
        false
    }

    pub const fn requires_kernel_consent(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InferenceContentBlock {
    Text { content_digest: Digest },
    ToolUse { proposal: UntrustedToolUseProposal },
    Unknown { block_digest: Digest },
}

impl InferenceContentBlock {
    pub const fn kind(&self) -> ContentBlockKind {
        match self {
            Self::Text { .. } => ContentBlockKind::Text,
            Self::ToolUse { .. } => ContentBlockKind::ToolUse,
            Self::Unknown { .. } => ContentBlockKind::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResultDisposition {
    ProposalOnly,
    NeedsKernelConsent,
    SafetyBlocked,
    Truncated,
    ProviderUnknown,
}

impl ResultDisposition {
    pub const fn is_adoptable(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TokenUsage {
    input_tokens: u32,
    output_tokens: u32,
    total_tokens: u32,
}

impl TokenUsage {
    pub const fn new(input_tokens: u32, output_tokens: u32, total_tokens: u32) -> Self {
        Self {
            input_tokens,
            output_tokens,
            total_tokens,
        }
    }

    pub const fn input_tokens(&self) -> u32 {
        self.input_tokens
    }

    pub const fn output_tokens(&self) -> u32 {
        self.output_tokens
    }

    pub const fn total_tokens(&self) -> u32 {
        self.total_tokens
    }

    pub fn receipt(&self) -> Result<UsageReceipt> {
        if self.input_tokens.saturating_add(self.output_tokens) != self.total_tokens {
            return Err(BedrockError::UsageMismatch);
        }
        Ok(UsageReceipt {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            total_tokens: self.total_tokens,
            digest: Digest::of_str(&format!(
                "input={};output={};total={}",
                self.input_tokens, self.output_tokens, self.total_tokens
            )),
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UsageReceipt {
    input_tokens: u32,
    output_tokens: u32,
    total_tokens: u32,
    digest: Digest,
}

impl UsageReceipt {
    pub const fn input_tokens(&self) -> u32 {
        self.input_tokens
    }

    pub const fn output_tokens(&self) -> u32 {
        self.output_tokens
    }

    pub const fn total_tokens(&self) -> u32 {
        self.total_tokens
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InvocationReceipt {
    registration_id: RegistrationId,
    request_digest: Digest,
    content_digest: Digest,
    tool_schema_digest: Option<Digest>,
    config_digest: Digest,
    scope_digest: Digest,
    capability_snapshot_digest: Digest,
    aws_request_id: Option<String>,
    model_identity: Option<ModelTarget>,
    stop_reason: StopReason,
    usage: UsageReceipt,
    service_tier: ServiceTier,
    latency_ms: u64,
    safety: GuardrailProjection,
    result_digest: Digest,
    result_content_digest: Digest,
    routing: DestinationEvidence,
    provenance: Layer1Provenance,
}

impl InvocationReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        registration_id: RegistrationId,
        request_digest: Digest,
        content_digest: Digest,
        tool_schema_digest: Option<Digest>,
        config_digest: Digest,
        scope_digest: Digest,
        capability_snapshot_digest: Digest,
        aws_request_id: Option<String>,
        model_identity: Option<ModelTarget>,
        stop_reason: StopReason,
        usage: UsageReceipt,
        service_tier: ServiceTier,
        latency_ms: u64,
        safety: GuardrailProjection,
        result_digest: Digest,
        result_content_digest: Digest,
        routing: DestinationEvidence,
        provenance: Layer1Provenance,
    ) -> Self {
        Self {
            registration_id,
            request_digest,
            content_digest,
            tool_schema_digest,
            config_digest,
            scope_digest,
            capability_snapshot_digest,
            aws_request_id,
            model_identity,
            stop_reason,
            usage,
            service_tier,
            latency_ms,
            safety,
            result_digest,
            result_content_digest,
            routing,
            provenance,
        }
    }

    pub const fn registration_id(&self) -> RegistrationId {
        self.registration_id
    }

    pub const fn request_digest(&self) -> Digest {
        self.request_digest
    }

    pub const fn content_digest(&self) -> Digest {
        self.content_digest
    }

    pub const fn tool_schema_digest(&self) -> Option<Digest> {
        self.tool_schema_digest
    }

    pub const fn config_digest(&self) -> Digest {
        self.config_digest
    }

    pub const fn scope_digest(&self) -> Digest {
        self.scope_digest
    }

    pub const fn capability_snapshot_digest(&self) -> Digest {
        self.capability_snapshot_digest
    }

    pub fn aws_request_id(&self) -> Option<&str> {
        self.aws_request_id.as_deref()
    }

    pub const fn model_identity(&self) -> Option<&ModelTarget> {
        self.model_identity.as_ref()
    }

    pub const fn stop_reason(&self) -> StopReason {
        self.stop_reason
    }

    pub const fn usage(&self) -> &UsageReceipt {
        &self.usage
    }

    pub const fn service_tier(&self) -> ServiceTier {
        self.service_tier
    }

    pub const fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    pub const fn safety(&self) -> &GuardrailProjection {
        &self.safety
    }

    pub const fn result_digest(&self) -> Digest {
        self.result_digest
    }

    pub const fn result_content_digest(&self) -> Digest {
        self.result_content_digest
    }

    pub const fn routing(&self) -> &DestinationEvidence {
        &self.routing
    }

    pub const fn provenance(&self) -> Layer1Provenance {
        self.provenance
    }

    pub fn with_result_digest(mut self, result_digest: Digest) -> Self {
        self.result_digest = result_digest;
        self
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InferenceResultProposal {
    registration_id: RegistrationId,
    request_digest: Digest,
    result_digest: Digest,
    content_digest: Digest,
    blocks: Vec<InferenceContentBlock>,
    stop_reason: StopReason,
    usage: UsageReceipt,
    safety: GuardrailProjection,
    disposition: ResultDisposition,
    provenance: Layer1Provenance,
}

impl InferenceResultProposal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        registration_id: RegistrationId,
        request_digest: Digest,
        result_digest: Digest,
        content_digest: Digest,
        blocks: Vec<InferenceContentBlock>,
        stop_reason: StopReason,
        usage: UsageReceipt,
        safety: GuardrailProjection,
        disposition: ResultDisposition,
        provenance: Layer1Provenance,
    ) -> Self {
        Self {
            registration_id,
            request_digest,
            result_digest,
            content_digest,
            blocks,
            stop_reason,
            usage,
            safety,
            disposition,
            provenance,
        }
    }

    pub const fn registration_id(&self) -> RegistrationId {
        self.registration_id
    }

    pub const fn request_digest(&self) -> Digest {
        self.request_digest
    }

    pub const fn result_digest(&self) -> Digest {
        self.result_digest
    }

    pub const fn content_digest(&self) -> Digest {
        self.content_digest
    }

    pub fn blocks(&self) -> &[InferenceContentBlock] {
        &self.blocks
    }

    pub const fn stop_reason(&self) -> StopReason {
        self.stop_reason
    }

    pub const fn usage(&self) -> &UsageReceipt {
        &self.usage
    }

    pub const fn safety(&self) -> &GuardrailProjection {
        &self.safety
    }

    pub const fn disposition(&self) -> ResultDisposition {
        self.disposition
    }

    pub const fn provenance(&self) -> Layer1Provenance {
        self.provenance
    }

    pub const fn adopts_outcome(&self) -> bool {
        false
    }

    pub fn tool_use_proposals(&self) -> Vec<&UntrustedToolUseProposal> {
        self.blocks
            .iter()
            .filter_map(|block| match block {
                InferenceContentBlock::ToolUse { proposal } => Some(proposal),
                InferenceContentBlock::Text { .. } | InferenceContentBlock::Unknown { .. } => None,
            })
            .collect()
    }

    pub fn with_result_digest(mut self, result_digest: Digest) -> Self {
        self.result_digest = result_digest;
        self
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum VerificationFailure {
    RequestDigestMismatch,
    ConfigDigestMismatch,
    ResultDigestMismatch,
    RegistrationInactive,
    ScopeDigestMismatch,
    CapabilityDigestMismatch,
    UsageMismatch,
    OutcomeAdoptionAttempt,
    LiveProvenance,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VerificationReport {
    verified: bool,
    failures: Vec<VerificationFailure>,
}

impl VerificationReport {
    pub(crate) fn new(failures: Vec<VerificationFailure>) -> Self {
        Self {
            verified: failures.is_empty(),
            failures,
        }
    }

    pub const fn verified(&self) -> bool {
        self.verified
    }

    pub fn failures(&self) -> &[VerificationFailure] {
        &self.failures
    }
}

fn validate_id(value: String, field: &'static str) -> Result<String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
    {
        return Err(BedrockError::InvalidIdentifier {
            field,
            reason: "must be a bounded identifier without whitespace",
        });
    }
    Ok(value)
}

fn is_partition_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
}

fn is_region_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
}

fn is_session_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"._-".contains(&byte)
}

fn contains_credential_material(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "accesskeyid",
        "access_key_id",
        "secretaccesskey",
        "secret_access_key",
        "sessiontoken",
        "session_token",
        "long-lived",
        "long_lived",
        "iam-user",
        "iam_user",
        "iam/user",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        || value.starts_with("AKIA")
        || value.starts_with("ASIA")
}

fn validate_model_target_scope(
    target: &ModelTarget,
    partition: &AwsPartition,
    account_id: &AwsAccountId,
    source_region: &AwsRegion,
) -> Result<()> {
    let is_arn = matches!(
        target,
        ModelTarget::ModelArn(_) | ModelTarget::InferenceProfileArn(_)
    );
    if !is_arn {
        return Ok(());
    }
    let parts: Vec<_> = target.as_str().splitn(6, ':').collect();
    if parts.len() != 6
        || parts[0] != "arn"
        || parts[1] != partition.as_str()
        || parts[2] != "bedrock"
        || (!parts[3].is_empty() && parts[3] != "*" && parts[3] != source_region.as_str())
        || (!parts[4].is_empty() && parts[4] != "*" && parts[4] != account_id.as_str())
    {
        return Err(BedrockError::InvalidModelTarget);
    }
    Ok(())
}
