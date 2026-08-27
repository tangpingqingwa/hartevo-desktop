use std::fmt;

use chrono::{DateTime, Utc};
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    Native,
    Simulator,
    Fixture,
    BlockedEnv,
    Missing,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    NativeProvider,
    Simulator,
    Fixture,
    BlockedEnv,
    Missing,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentStatus {
    Available,
    BlockedEnv,
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Completed,
    Failed,
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Verified,
    NotEvaluated,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionSurface {
    Mission,
    Event,
    Debug,
    Error,
    Receipt,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleHook {
    Rotation,
    Revoke,
    Unmount,
    Crash,
    Replay,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct Scope {
    pub tenant_id: String,
    pub project_id: String,
    pub mission_id: String,
    pub scope_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReferenceEvidence {
    pub reference_digest: String,
    pub service_digest: String,
    pub provider_id: String,
    pub account_digest: String,
    pub capability: String,
    pub credential_revision: u64,
    pub generation: u64,
    pub scope_digest: String,
    pub reference_only: bool,
    pub plaintext_present: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct DispatchEvidence {
    pub mode: String,
    pub reference_digest: String,
    pub scope_digest: String,
    pub contains_handle: bool,
    pub contains_lease: bool,
    pub contains_plaintext: bool,
    pub reauthorization_required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct LeaseEvidence {
    pub lease_digest: String,
    pub scope_digest: String,
    pub generation: u64,
    pub credential_revision: u64,
    pub ttl_seconds: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub reclaimed_at: DateTime<Utc>,
    pub reclaimed: bool,
    pub active_after_reclaim: bool,
    pub provider_boundary: bool,
    pub plaintext_present: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderEvidence {
    pub id: String,
    pub source_commit: String,
    pub scope_digest: String,
    pub mode: ProviderMode,
    pub provenance: ProviderProvenance,
    pub output_present: bool,
    pub output_digest: String,
    pub os_keyring_status: EnvironmentStatus,
    pub real_output_status: EnvironmentStatus,
    pub consumer_used_service: bool,
    pub plaintext_present: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ConsumerEvidence {
    pub id: String,
    pub source_commit: String,
    pub scope_digest: String,
    pub reference_digest: String,
    pub generation: u64,
    pub credential_revision: u64,
    pub service_used: bool,
    pub provider_dispatch_reference_only: bool,
    pub effect_authority_attached: bool,
    pub plaintext_present: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ReceiptEvidence {
    pub status: ReceiptStatus,
    pub source_commit: String,
    pub scope_digest: String,
    pub reference_digest: String,
    pub lease_digest: String,
    pub result_digest: String,
    pub verification_digest: String,
    pub lease_reclaimed: bool,
    pub contains_handle: bool,
    pub plaintext_present: bool,
    pub error_redacted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationEvidence {
    pub status: VerificationStatus,
    pub source_commit: String,
    pub scope_digest: String,
    pub receipt_digest: String,
    pub result_digest: String,
    pub provider_output_digest: String,
    pub verified: bool,
    pub plaintext_present: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSurfaceEvidence {
    pub surface: RedactionSurface,
    pub plaintext_found: bool,
    pub scan_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionEvidence {
    pub source_commit: String,
    pub surfaces: Vec<RedactionSurfaceEvidence>,
    pub all_content_free: bool,
    pub scan_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct LifecycleProof {
    pub hook: LifecycleHook,
    pub source_commit: String,
    pub scope_digest: String,
    pub old_reference_digest: String,
    pub old_generation: u64,
    pub new_generation: u64,
    pub old_lease_digest: String,
    pub old_generation_accepted: bool,
    pub old_lease_accepted: bool,
    pub replay_reference_only: bool,
    pub reauthorization_required: bool,
    pub new_lease_issued: bool,
    pub failure_code: String,
    pub proof_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretBrokerAcceptance {
    pub schema_version: String,
    pub document_type: String,
    pub authority: String,
    pub release_decision: String,
    pub source_commit: String,
    pub scope: Scope,
    pub secret_reference: SecretReferenceEvidence,
    pub dispatch: DispatchEvidence,
    pub lease: LeaseEvidence,
    pub provider: ProviderEvidence,
    pub consumer: ConsumerEvidence,
    pub receipt: ReceiptEvidence,
    pub verification: VerificationEvidence,
    pub redaction: RedactionEvidence,
    pub lifecycle_proofs: Vec<LifecycleProof>,
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
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key: {key}"
                )));
            }
            let StrictValue(value) = map.next_value::<StrictValue>()?;
            values.insert(key, value);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}
