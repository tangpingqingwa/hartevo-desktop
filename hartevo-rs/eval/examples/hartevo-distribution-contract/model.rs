use std::fmt;

use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AdvisoryCategory {
    Notice,
    Unmaintained,
    Unsound,
    Vulnerability,
}

impl AdvisoryCategory {
    pub fn is_release_failure(self, failure_categories: &[Self]) -> bool {
        failure_categories.contains(&self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Disposition {
    CodeFailure,
    InformationalWarning,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseDecision {
    NotEvaluated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseContract {
    pub passed: bool,
    pub deployment: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetGraphPolicy {
    pub id: String,
    pub target: String,
    pub role: TargetRole,
    pub release: bool,
    pub release_roots: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetRole {
    Release,
    Ci,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewedException {
    pub advisory_id: String,
    pub category: AdvisoryCategory,
    pub package_name: String,
    pub package_version: String,
    pub target: String,
    pub owner: String,
    pub reason: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputContract {
    pub required_bindings: Vec<String>,
    pub cargo_metadata_command: String,
    pub cargo_audit_tool: String,
    pub lock_digest_algorithm: String,
    pub metadata_digest_algorithm: String,
    pub audit_receipt_digest_algorithm: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyDocument {
    pub schema_version: String,
    pub policy_id: String,
    pub authority: String,
    pub release_decision: ReleaseDecision,
    pub release: ReleaseContract,
    pub release_targets: Vec<String>,
    pub target_graphs: Vec<TargetGraphPolicy>,
    pub allowed_categories: Vec<AdvisoryCategory>,
    pub failure_categories: Vec<AdvisoryCategory>,
    pub unreachable_disposition: Disposition,
    pub release_failure_disposition: Disposition,
    pub reviewed_exceptions: Vec<ReviewedException>,
    pub input_contract: InputContract,
    pub finding_record_fields: Vec<String>,
    pub no_blanket_ignore: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CargoMetadata {
    pub packages: Vec<CargoPackage>,
    pub workspace_members: Vec<String>,
    pub resolve: Option<CargoResolve>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CargoPackage {
    pub id: String,
    pub name: String,
    pub version: String,
    pub source: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CargoResolve {
    pub nodes: Vec<CargoNode>,
    pub root: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CargoNode {
    pub id: String,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub deps: Vec<CargoDependency>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CargoDependency {
    pub pkg: String,
    #[serde(default)]
    pub dep_kinds: Vec<CargoDependencyKind>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CargoDependencyKind {
    pub kind: Option<String>,
    pub target: Option<String>,
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
        formatter.write_str("JSON without duplicate object keys")
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

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
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
    fn strict_json_rejects_duplicate_keys_but_allows_nulls() {
        assert!(parse_strict_json::<Value>(br#"{"v":1,"v":2}"#).is_err());
        assert!(parse_strict_json::<Value>(br#"{"v":null}"#).is_ok());
    }
}
