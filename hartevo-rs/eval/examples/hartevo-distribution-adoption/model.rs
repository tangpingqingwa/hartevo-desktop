use std::fmt;

use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SbomFormat {
    Cyclonedx,
    Spdx,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceOrigin {
    ExternalSigned,
    UnsignedGenerated,
    TestFixtureOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStatus {
    Verified,
    CodeFailure,
    BlockedEnv,
    NotImplemented,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevocationStatus {
    Active,
    Revoked,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseContract {
    pub passed: bool,
    pub deployment: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactBinding {
    pub version: String,
    pub sha256: String,
    pub platform: String,
    pub target_triple: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SbomEvidence {
    pub format: SbomFormat,
    pub spec_version: String,
    pub document_version: String,
    pub digest: String,
    pub platform: String,
    pub target_triple: String,
    pub artifact_digest: String,
    pub source_commit: String,
    pub lockfile_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttestationEvidence {
    pub predicate_type: String,
    pub version: String,
    pub digest: String,
    pub platform: String,
    pub target_triple: String,
    pub artifact_digest: String,
    pub sbom_digest: String,
    pub source_commit: String,
    pub lockfile_digest: String,
    pub toolchain_version: String,
    pub toolchain_digest: String,
    pub build_manifest_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvenanceBinding {
    pub source_commit: String,
    pub cargo_lock_digest: String,
    pub toolchain_version: String,
    pub toolchain_digest: String,
    pub build_manifest_digest: String,
    pub artifact_digest: String,
    pub sbom_digest: String,
    pub attestation_digest: String,
    pub dependency_evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetBinding {
    pub platform: String,
    pub target_triple: String,
    pub metadata_digest: String,
    pub role: String,
    pub release: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DependencyEvidenceBinding {
    pub report_digest: String,
    pub report_schema_version: String,
    pub policy_id: String,
    pub status: String,
    pub release: bool,
    pub source_commit: String,
    pub lockfile_digest: String,
    pub audit_receipt_digest: String,
    pub finding_digest: String,
    pub code_failure_count: usize,
    pub informational_warning_count: usize,
    pub target_bindings: Vec<TargetBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetachedSignature {
    pub algorithm: String,
    pub detached: bool,
    pub key_reference: Option<String>,
    pub signature_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValidityWindow {
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseEvidence {
    pub schema_version: String,
    pub plugin_id: String,
    pub provider: String,
    pub provider_version: String,
    pub consumer: String,
    pub release_decision: String,
    pub release: ReleaseContract,
    pub evidence_origin: EvidenceOrigin,
    pub version: String,
    pub platform: String,
    pub target_triple: String,
    pub artifact: ArtifactBinding,
    pub sbom: SbomEvidence,
    pub attestation: AttestationEvidence,
    pub provenance: ProvenanceBinding,
    pub dependency_evidence: DependencyEvidenceBinding,
    pub validity: ValidityWindow,
    pub signature: DetachedSignature,
    pub payload_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPayload {
    pub schema_version: String,
    pub plugin_id: String,
    pub provider: String,
    pub provider_version: String,
    pub consumer: String,
    pub release_decision: String,
    pub release: ReleaseContract,
    pub evidence_origin: EvidenceOrigin,
    pub version: String,
    pub platform: String,
    pub target_triple: String,
    pub artifact: ArtifactBinding,
    pub sbom: SbomEvidence,
    pub attestation: AttestationEvidence,
    pub provenance: ProvenanceBinding,
    pub dependency_evidence: DependencyEvidenceBinding,
    pub validity: ValidityWindow,
    pub key_reference: Option<String>,
}

impl ReleaseEvidence {
    pub fn signed_payload(&self) -> SignedPayload {
        SignedPayload {
            schema_version: self.schema_version.clone(),
            plugin_id: self.plugin_id.clone(),
            provider: self.provider.clone(),
            provider_version: self.provider_version.clone(),
            consumer: self.consumer.clone(),
            release_decision: self.release_decision.clone(),
            release: self.release.clone(),
            evidence_origin: self.evidence_origin,
            version: self.version.clone(),
            platform: self.platform.clone(),
            target_triple: self.target_triple.clone(),
            artifact: self.artifact.clone(),
            sbom: self.sbom.clone(),
            attestation: self.attestation.clone(),
            provenance: self.provenance.clone(),
            dependency_evidence: self.dependency_evidence.clone(),
            validity: self.validity.clone(),
            key_reference: self.signature.key_reference.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationKey {
    pub key_reference: String,
    pub algorithm: String,
    pub public_key_hex: String,
    pub valid_from: String,
    pub valid_until: String,
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyRegistry {
    pub schema_version: String,
    pub registry_version: String,
    pub registry_digest: String,
    pub keys: Vec<VerificationKey>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationReceipt {
    pub receipt_version: String,
    pub status: EvidenceStatus,
    pub verified_at: String,
    pub verifier_version: String,
    pub evidence_digest: String,
    pub signed_payload_digest: String,
    pub artifact_digest: String,
    pub sbom_digest: String,
    pub attestation_digest: String,
    pub source_commit: String,
    pub key_reference: Option<String>,
    pub key_revocation_status: RevocationStatus,
    pub key_validity: String,
    pub evidence_expiry_status: String,
    pub failure_codes: Vec<String>,
    pub content_free: bool,
    pub receipt_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePromotionGate {
    pub consumer: String,
    pub decision: String,
    pub promotion_eligible: bool,
    pub release: bool,
    pub deployment: bool,
    pub reason_codes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct VerificationReport {
    pub schema_version: &'static str,
    pub provider: &'static str,
    pub consumer: &'static str,
    pub status: EvidenceStatus,
    pub release_decision: &'static str,
    pub release: bool,
    pub deployment: bool,
    pub evidence_accepted: bool,
    pub promotion_eligible: bool,
    pub contract_digest: String,
    pub contract_schema_digest: String,
    pub evidence_digest: String,
    pub verification_receipt: VerificationReceipt,
    pub gate: ReleasePromotionGate,
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
    fn strict_json_rejects_duplicate_keys() {
        assert!(parse_strict_json::<Value>(br#"{"v":1,"v":2}"#).is_err());
    }
}
