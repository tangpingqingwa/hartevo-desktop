use std::fmt;

use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentMode {
    Native,
    Simulator,
    Fixture,
    BlockedEnv,
    Missing,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Verified,
    Missing,
    BlockedEnv,
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationStatus {
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogEntryKind {
    Objective,
    MissionComposition,
    Invocation,
    Result,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectStatus {
    Applied,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Verified,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Completed,
    Failed,
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProvenance {
    Native,
    Simulator,
    Fixture,
    BlockedEnv,
    Missing,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionDecision {
    Adopt,
    Reject,
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryHook {
    Unmount,
    Revoke,
    Crash,
    Relaunch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    Recovered,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    pub id: String,
    pub revision: u64,
    pub scope_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub id: String,
    pub revision: u64,
    pub scope_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionScope {
    pub project_id: String,
    pub mission_id: String,
    pub scope_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Objective {
    pub id: String,
    pub text: String,
    pub constraints_digest: String,
    pub source_commit: String,
    pub scope: SessionScope,
    #[serde(rename = "objectiveDigest")]
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionComposition {
    pub objective_id: String,
    pub mission_id: String,
    pub revision: u64,
    pub source_commit: String,
    pub scope: SessionScope,
    pub capability_set_digest: String,
    pub composition_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePlugin {
    pub id: String,
    pub revision: u64,
    pub source_commit: String,
    pub scope: SessionScope,
    pub mode: ComponentMode,
    pub plugin_digest: String,
    pub mounted: bool,
    pub unmounted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelPlugin {
    pub id: String,
    pub provider: String,
    pub model: String,
    pub revision: String,
    pub source_commit: String,
    pub scope: SessionScope,
    pub mode: ComponentMode,
    pub credentials: CredentialStatus,
    pub model_digest: String,
    pub artifact_digest: String,
    pub output_present: bool,
    pub output_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceBinding {
    pub id: String,
    pub source_commit: String,
    pub scope: SessionScope,
    pub mode: ComponentMode,
    pub mounted: bool,
    pub durable_log_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderBinding {
    pub id: String,
    pub source_commit: String,
    pub scope: SessionScope,
    pub mode: ComponentMode,
    pub model_digest: String,
    pub provider_digest: String,
    pub output_present: bool,
    pub output_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsumerBinding {
    pub id: String,
    pub source_commit: String,
    pub scope: SessionScope,
    pub adopted: bool,
    pub selected_result_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityInvocation {
    pub sequence: u64,
    pub capability: String,
    pub plugin_id: String,
    pub source_commit: String,
    pub scope: SessionScope,
    pub request_digest: String,
    pub response_digest: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
    pub status: InvocationStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableLogEntry {
    pub sequence: u64,
    pub kind: LogEntryKind,
    pub source_commit: String,
    pub scope: SessionScope,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub payload_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableLog {
    pub source_commit: String,
    pub scope: SessionScope,
    pub revision: u64,
    pub entries: Vec<DurableLogEntry>,
    pub durable: bool,
    pub model_visible: bool,
    pub log_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectVerification {
    pub sequence: u64,
    pub status: VerificationStatus,
    pub verified_at: chrono::DateTime<chrono::Utc>,
    pub verification_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectReceipt {
    pub sequence: u64,
    pub effect_id: String,
    pub capability: String,
    pub plugin_id: String,
    pub source_commit: String,
    pub scope: SessionScope,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub receipt_at: chrono::DateTime<chrono::Utc>,
    pub status: EffectStatus,
    pub receipt_digest: String,
    pub verification: EffectVerification,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectedResult {
    pub source_commit: String,
    pub scope: SessionScope,
    pub revision: u64,
    pub status: ResultStatus,
    pub provenance: EvidenceProvenance,
    pub result_digest: String,
    pub evidence_root: String,
    pub selected_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdoptionRecord {
    pub source_commit: String,
    pub scope: SessionScope,
    pub revision: u64,
    pub decision: AdoptionDecision,
    pub result_digest: String,
    pub evidence_root: String,
    pub decision_digest: String,
    pub adopted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryReceipt {
    pub sequence: u64,
    pub hook: RecoveryHook,
    pub status: RecoveryStatus,
    pub source_commit: String,
    pub scope: SessionScope,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub receipt_digest: String,
    pub old_plugin_accepted: bool,
    pub old_decision_promotable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginNativeJourney {
    pub schema_version: String,
    pub document_type: String,
    pub authority: String,
    pub release_decision: String,
    pub source_commit: String,
    pub journey_id: String,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub objective: Objective,
    pub composition: MissionComposition,
    pub runtime_plugin: RuntimePlugin,
    pub model_plugin: ModelPlugin,
    pub service: ServiceBinding,
    pub provider: ProviderBinding,
    pub consumer: ConsumerBinding,
    pub invocations: Vec<CapabilityInvocation>,
    pub durable_log: DurableLog,
    pub effects: Vec<EffectReceipt>,
    pub selected_result: SelectedResult,
    pub adoption: AdoptionRecord,
    pub recovery: Vec<RecoveryReceipt>,
    pub evidence_root: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OracleStatus {
    NativePass,
    NotEvaluated,
    BlockedEnv,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OracleReport {
    pub schema_version: &'static str,
    pub authority: &'static str,
    pub release_decision: &'static str,
    pub oracle_status: OracleStatus,
    pub native_pass: bool,
    pub source_commit: String,
    pub journey_id: String,
    pub project_id: String,
    pub mission_id: String,
    pub evidence_root: String,
    pub replay_digest: String,
    pub invocation_count: usize,
    pub effect_count: usize,
    pub recovery_count: usize,
    pub missing_reasons: Vec<String>,
}

pub fn parse_strict_json<T: DeserializeOwned>(input: &[u8]) -> serde_json::Result<T> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let StrictValue(value) = StrictValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    serde_json::from_value(value)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate keys or null values")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }
    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }
    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }
    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }
    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }
    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("JSON null is forbidden"))
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("JSON null is forbidden"))
    }
    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictValue(value)) = sequence.next_element::<StrictValue>()? {
            values.push(value);
        }
        Ok(StrictValue(Value::Array(values)))
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some((key, StrictValue(value))) = map.next_entry::<String, StrictValue>()? {
            if values.insert(key.clone(), value).is_some() {
                return Err(de::Error::custom(format_args!(
                    "duplicate JSON object key: {key}"
                )));
            }
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_strict_json;
    use serde_json::Value;

    #[test]
    fn strict_json_rejects_duplicate_keys_and_nulls() {
        assert!(parse_strict_json::<Value>(br#"{"x":1,"x":2}"#).is_err());
        assert!(parse_strict_json::<Value>(br#"{"x":[null]}"#).is_err());
    }
}
