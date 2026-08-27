use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::digest::domain_canonical_json_bytes;

pub const RESULT_ENVELOPE_SCHEMA: &str = "hartevo-federation-result-envelope/v1";
pub const PROVIDER_REGISTRY_SCHEMA: &str = "hartevo-federation-provider-registry/v1";
pub const SIGNATURE_DOMAIN: &str = "hartevo-federation-result-envelope-signature/v1";
pub const CONTENT_DOMAIN: &str = "hartevo-federation-result-envelope-content/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultEnvelope {
    pub schema_version: String,
    pub envelope_id: String,
    pub origin: ResultOrigin,
    pub remote_worker: RemoteWorkerBinding,
    pub roots: ResultRoots,
    pub sequence: u64,
    pub replay_nonce: String,
    pub effect_receipt: ResultLink,
    pub verification: VerificationLink,
    pub outcome: ResultLink,
    pub current_commit: String,
    pub envelope_digest: String,
    pub signature: Option<EnvelopeSignature>,
    pub worker_evidence: Option<WorkerEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultOrigin {
    pub project_id: String,
    pub mission_id: String,
    pub turn: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteWorkerBinding {
    pub worker_id: String,
    pub service_id: String,
    pub provider_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultRoots {
    #[serde(rename = "inputRoot")]
    pub input: String,
    #[serde(rename = "outputRoot")]
    pub output: String,
    #[serde(rename = "evidenceRoot")]
    pub evidence: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultLink {
    pub link_id: String,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationLink {
    pub link_id: String,
    pub digest: String,
    pub state: VerificationState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Verified,
    Pending,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvelopeSignature {
    pub algorithm: SignatureAlgorithm,
    pub public_key_hex: String,
    pub signature_hex: String,
    pub signature_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    Ed25519,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerEvidence {
    pub kind: WorkerEvidenceKind,
    pub worker_id: String,
    pub worker_run_id: String,
    pub attestation_digest: String,
    pub evidence_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerEvidenceKind {
    NativeRemoteWorker,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderRegistry {
    pub schema_version: String,
    pub registry_id: String,
    pub native_worker_verifier_available: bool,
    pub providers: Vec<ProviderRecord>,
    pub release_decision: ReleaseDecision,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderRecord {
    pub provider_id: String,
    pub worker_id: String,
    pub service_id: String,
    pub provider_digest: String,
    pub worker_attestation_digest: String,
    pub status: ProviderStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseDecision {
    NotEvaluated,
}

impl ResultEnvelope {
    pub fn unsigned_value(&self) -> serde_json::Result<Value> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("ResultEnvelope serializes as an object")
            .remove("signature");
        Ok(value)
    }

    pub fn content_value(&self) -> serde_json::Result<Value> {
        let mut value = self.unsigned_value()?;
        value
            .as_object_mut()
            .expect("ResultEnvelope serializes as an object")
            .remove("envelopeDigest");
        Ok(value)
    }

    pub fn signature_message(&self) -> serde_json::Result<Vec<u8>> {
        domain_canonical_json_bytes(SIGNATURE_DOMAIN, &self.unsigned_value()?)
    }

    pub fn computed_envelope_digest(&self) -> serde_json::Result<String> {
        let content = self.content_value()?;
        let message = domain_canonical_json_bytes(CONTENT_DOMAIN, &content)?;
        Ok(crate::digest::sha256_hex(&message))
    }
}
