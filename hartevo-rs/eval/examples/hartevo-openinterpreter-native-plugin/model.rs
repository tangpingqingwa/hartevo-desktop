use std::fmt;

use hartevo_runtime_adapter::RuntimeEndpointClass;
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};

pub const SCHEMA_VERSION: &str = "hartevo.openinterpreter-native-plugin-receipt/v1";
pub const DOCUMENT_TYPE: &str = "openinterpreter_native_plugin_journey";
pub const AUTHORITY: &str = "native_openinterpreter_local_evidence";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const ORACLE_JOURNEY_SCHEMA: &str = "hartevo.plugin-native-journey/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStatus {
    NativePass,
    BlockedEnv,
    NotEvaluated,
    Fail,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    Native,
    Fixture,
    Simulator,
    Ignored,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageName {
    Initialize,
    ProviderSelection,
    ModelSelection,
    HarnessSelection,
    Mount,
    Thread,
    Turn,
    Stream,
    Result,
    Interrupt,
    Cleanup,
}

impl StageName {
    pub const ALL: [Self; 11] = [
        Self::Initialize,
        Self::ProviderSelection,
        Self::ModelSelection,
        Self::HarnessSelection,
        Self::Mount,
        Self::Thread,
        Self::Turn,
        Self::Stream,
        Self::Result,
        Self::Interrupt,
        Self::Cleanup,
    ];
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableEventKind {
    Input,
    AssistantDelta,
    AssistantResult,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupState {
    Revoked,
    Unmounted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct JourneyScope {
    pub project_id: String,
    pub mission_id: String,
    pub session_id: String,
    pub scope_digest: String,
    pub runtime_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceBinding {
    pub source_commit: String,
    pub runtime_commit: String,
    pub runtime_release: String,
    pub app_server_schema_digest: String,
    pub control_plane_contract_digest: String,
    pub binary_digest: String,
    pub tool_digest: String,
    pub command_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SelectionBinding {
    pub service_id: String,
    pub service_revision: String,
    pub provider_id: String,
    pub provider_revision: String,
    pub model_id: String,
    pub model_revision: String,
    pub harness_id: String,
    pub harness_revision: String,
    pub endpoint_class: RuntimeEndpointClass,
    pub manifest_digest: String,
    pub service_definition_digest: String,
    pub catalog_digest: String,
    pub config_digest: String,
    pub policy_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProcessEvidence {
    pub process_id_digest: String,
    pub observed_at_epoch_seconds: u64,
    pub executable_path_digest: String,
    pub runtime_instance_digest: String,
    pub process_binding_digest: String,
    pub binary_digest: String,
    pub runtime_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StageReceipt {
    pub sequence: u64,
    pub name: StageName,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DurableEventReceipt {
    pub sequence: u64,
    pub kind: DurableEventKind,
    pub source_item_id_digest: String,
    pub source_event_digest: String,
    pub content_digest: String,
    pub content_byte_count: u64,
    pub event_digest: String,
    pub scope_digest: String,
    pub provider_manifest_digest: String,
    pub config_digest: String,
    pub catalog_digest: String,
    pub policy_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TurnEvidence {
    pub client_message_id_digest: String,
    pub request_digest: String,
    pub response_digest: String,
    pub thread_id_digest: String,
    pub turn_id_digest: String,
    pub completion_status: String,
    pub turn_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResultEvidence {
    pub schema: String,
    pub authority: String,
    pub result_kind: String,
    pub project_id: String,
    pub mission_id: String,
    pub runtime_generation: u64,
    pub runtime_instance_digest: String,
    pub runtime_commit: String,
    pub runtime_release: String,
    pub mapping_digest: String,
    pub runtime_thread_id_digest: String,
    pub runtime_turn_id_digest: String,
    pub app_server_schema_digest: String,
    pub runtime_config_digest: String,
    pub catalog_digest: String,
    pub source_item_id_digest: String,
    pub source_event_digest: String,
    pub content_digest: String,
    pub content_byte_count: u64,
    pub result_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InterruptEvidence {
    pub request_digest: String,
    pub response_digest: String,
    pub turn_id_digest: String,
    pub acknowledged: bool,
    pub interrupt_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CleanupEvidence {
    pub mount_digest: String,
    pub plugin_state: CleanupState,
    pub stopped_registration_count: u64,
    pub residual_registration_count: u64,
    pub shutdown_success: bool,
    pub shutdown_forced: bool,
    pub exit_code: i32,
    pub cleanup_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OracleInput {
    pub journey_schema: String,
    pub journey_id: String,
    pub source_commit: String,
    pub project_id: String,
    pub mission_id: String,
    pub session_id: String,
    pub runtime_plugin_digest: String,
    pub provider_digest: String,
    pub model_digest: String,
    pub service_digest: String,
    pub consumer_id: String,
    pub consumer_result_digest: String,
    pub durable_log_digest: String,
    pub result_digest: String,
    pub evidence_root: String,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NativePluginReceipt {
    pub schema_version: String,
    pub document_type: String,
    pub authority: String,
    pub release_decision: String,
    pub source_commit: String,
    pub scope: JourneyScope,
    pub source: SourceBinding,
    pub selection: SelectionBinding,
    pub process: ProcessEvidence,
    pub stages: Vec<StageReceipt>,
    pub durable_log: Vec<DurableEventReceipt>,
    pub turn: TurnEvidence,
    pub result: ResultEvidence,
    pub interrupt: InterruptEvidence,
    pub cleanup: CleanupEvidence,
    pub oracle_input: OracleInput,
    pub provenance: Provenance,
    pub evidence_root: String,
    pub receipt_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VerificationReport {
    pub status: EvidenceStatus,
    pub native_pass: bool,
    pub oracle_consumable: bool,
    pub release_decision: String,
    pub source_commit: String,
    pub receipt_digest: String,
    pub evidence_root: String,
    pub reason: String,
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
        formatter.write_str("JSON without duplicate object keys or null values")
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
    use super::{NativePluginReceipt, parse_strict_json};

    #[test]
    fn strict_json_rejects_duplicate_and_null_values() {
        assert!(parse_strict_json::<serde_json::Value>(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse_strict_json::<serde_json::Value>(br#"{"a":[null]}"#).is_err());
    }

    #[test]
    fn receipt_rejects_unknown_fields() {
        let value = serde_json::json!({"unexpected": true});
        let bytes = serde_json::to_vec(&value).expect("json");
        assert!(parse_strict_json::<NativePluginReceipt>(&bytes).is_err());
    }
}
