use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimClassification {
    ConfirmedFact,
    ProviderEstimate,
    AgentInference,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Uncertainty {
    None,
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    MarketplaceEstimate,
    PublicSearchSnapshot,
    AiGroundTruthSimulator,
    CompetitorPublicSnapshot,
    SyntheticCounterevidence,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    Go,
    NoGo,
    NeedMoreEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatasetRegistryDocument {
    pub schema_version: String,
    pub registry_version: String,
    #[serde(default)]
    pub dataset_bindings: Vec<DatasetBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatasetBinding {
    pub binding_id: String,
    pub binding_version: String,
    pub dataset_path: String,
    pub dataset_id: String,
    pub dataset_version: String,
    pub mission_id: String,
    pub fixture_id: String,
    pub partition: String,
    pub split: String,
    pub case_count: usize,
    pub raw_digest: String,
    pub isolation_policy: String,
    pub native_receipt_count: usize,
    pub release_decision: String,
    pub private_content: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct Dataset {
    pub schema_version: String,
    pub dataset_id: String,
    pub dataset_version: String,
    pub mission_id: String,
    pub fixture_id: String,
    pub partition: String,
    pub split: String,
    pub data_classification: String,
    pub provenance: Provenance,
    pub world: WorldScope,
    pub isolation: IsolationPolicy,
    pub cases: Vec<ReplayCase>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Provenance {
    pub kind: String,
    pub source: String,
    pub license: String,
    pub private_provider_data: bool,
    pub customer_data: bool,
    pub credential_data: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorldScope {
    pub market: String,
    pub locale: String,
    pub currency: String,
    pub observation_window: ObservationWindow,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationWindow {
    pub start: String,
    pub end: String,
    pub time_zone: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct IsolationPolicy {
    pub execution_mode: String,
    pub partition_visibility: String,
    pub network_policy: String,
    pub private_content_policy: String,
    pub native_execution_allowed: bool,
    pub production_writes_allowed: bool,
    pub native_receipt_count: usize,
    pub release_decision: String,
    pub contains_customer_data: bool,
    pub contains_credentials: bool,
    pub contains_private_provider_data: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplayCase {
    pub case_id: String,
    pub case_version: u32,
    pub deterministic_seed: String,
    pub scope: CaseScope,
    pub observation_window: ObservationWindow,
    pub goal: DecisionGoal,
    pub claims: Vec<Claim>,
    pub counterevidence: Vec<Counterevidence>,
    pub timeline: Vec<TimelineEvent>,
    pub expected: ExpectedDecision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseScope {
    pub tenant_id: String,
    pub project_id: String,
    pub mission_id: String,
    pub market: String,
    pub locale: String,
    pub currency: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecisionGoal {
    pub mode: String,
    pub statement: String,
    pub budget_minor: u64,
    pub currency: String,
    pub forbidden_channels: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct Claim {
    pub claim_id: String,
    pub subject: String,
    pub predicate: String,
    pub value: String,
    pub source_kind: SourceKind,
    pub source_ref: String,
    pub observed_at: String,
    pub valid_from: String,
    pub valid_until: Option<String>,
    pub classification: ClaimClassification,
    pub uncertainty: Uncertainty,
    pub counterevidence_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct Counterevidence {
    pub counterevidence_id: String,
    pub claim_id: String,
    pub subject: String,
    pub predicate: String,
    pub value: String,
    pub source_kind: SourceKind,
    pub source_ref: String,
    pub observed_at: String,
    pub classification: ClaimClassification,
    pub uncertainty: Uncertainty,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimelineEvent {
    pub event_id: String,
    pub kind: String,
    pub at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpectedDecision {
    pub decision: DecisionOutcome,
    pub required_claim_ids: Vec<String>,
    pub required_counterevidence_ids: Vec<String>,
    pub separates_classifications: Vec<ClaimClassification>,
    pub forbidden_effects: Vec<String>,
    pub decision_basis: String,
}

pub fn parse_strict_json<T: DeserializeOwned>(bytes: &[u8]) -> serde_json::Result<T> {
    serde_json::from_slice(bytes)
}
