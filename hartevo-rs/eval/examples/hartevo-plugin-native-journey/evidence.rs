use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::digest::{digest_json, domain_bytes, is_lower_hex, sha256_hex};
use crate::model::{
    AdoptionDecision, ComponentMode, EffectStatus, EvidenceProvenance, LogEntryKind, OracleReport,
    OracleStatus, PluginNativeJourney, RecoveryHook, RecoveryStatus, ResultStatus,
    VerificationStatus,
};
use crate::verifier::{
    AUTHORITY as ORACLE_AUTHORITY, CONTRACT_SCHEMA_VERSION as ORACLE_SCHEMA_VERSION,
    RELEASE_DECISION as ORACLE_RELEASE_DECISION, validate_journey,
};

pub const CONTRACT_PATH: &str = "contracts/plugins/plugin-native-journey-evidence.v1.json";
pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo.plugin-native-journey-evidence/v1";
pub const DOCUMENT_TYPE: &str = "plugin_native_journey_evidence";
pub const AUTHORITY: &str = "plugin_native_journey_evidence_only";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const REPORT_SCHEMA_VERSION: &str = "hartevo-plugin-native-journey-evidence-report/v1";

const MANIFEST_DOMAIN: &str = "hartevo-plugin-native-journey-evidence-manifest/v1";
const SIGNATURE_DOMAIN: &str = "hartevo-plugin-native-journey-evidence-signature/v1";
const CAPTURE_DOMAIN: &str = "hartevo-plugin-native-journey-capture/v1";
const PROCESS_DOMAIN: &str = "hartevo-plugin-native-journey-process-observation/v1";
const ED25519_ALGORITHM: &str = "ed25519";
const CONTRACT_BYTES: &[u8] =
    include_bytes!("../../../../contracts/plugins/plugin-native-journey-evidence.v1.json");

const EXPECTED_LOG_KINDS: [LogEntryKind; 4] = [
    LogEntryKind::Objective,
    LogEntryKind::MissionComposition,
    LogEntryKind::Invocation,
    LogEntryKind::Result,
];
const EXPECTED_RECOVERY_HOOKS: [RecoveryHook; 4] = [
    RecoveryHook::Unmount,
    RecoveryHook::Revoke,
    RecoveryHook::Crash,
    RecoveryHook::Relaunch,
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HonestyClassification {
    NativeVerified,
    NotEvaluated,
    BlockedEnv,
    Fixture,
    Simulator,
    Ignored,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceBlobKind {
    ProcessObservation,
    DurableEvent,
    EffectReceipt,
    RestartReceipt,
    ResultReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Verified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayState {
    Guarded,
    NotGuarded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceVerdict {
    NativePass,
    NotNative,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OracleSnapshot {
    #[serde(rename = "oracleSchemaVersion")]
    pub schema_version: String,
    pub authority: String,
    pub release_decision: String,
    #[serde(rename = "oracleStatus")]
    pub status: OracleStatus,
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
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingSnapshot {
    pub project_id: String,
    pub mission_id: String,
    pub runtime_plugin_id: String,
    pub model_plugin_id: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub runtime_plugin_digest: String,
    pub model_digest: String,
    pub provider_digest: String,
    pub service_log_digest: String,
    pub consumer_result_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeProcessObservation {
    pub id: String,
    pub generation: u64,
    pub mode: ComponentMode,
    pub source_commit: String,
    pub executable_digest: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub exit_code: i32,
    pub observation_digest: String,
    pub blob_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableEventObservation {
    pub sequence: u64,
    pub kind: LogEntryKind,
    #[serde(rename = "eventId")]
    pub id: String,
    pub source_commit: String,
    pub occurred_at: DateTime<Utc>,
    pub payload_digest: String,
    pub blob_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectObservation {
    pub sequence: u64,
    #[serde(rename = "effectId")]
    pub id: String,
    pub source_commit: String,
    pub requested_at: DateTime<Utc>,
    pub receipt_at: DateTime<Utc>,
    pub verified_at: DateTime<Utc>,
    pub receipt_digest: String,
    pub verification_digest: String,
    pub blob_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestartPointObservation {
    pub sequence: u64,
    pub hook: RecoveryHook,
    pub status: RecoveryStatus,
    pub source_commit: String,
    pub occurred_at: DateTime<Utc>,
    pub receipt_digest: String,
    pub old_plugin_accepted: bool,
    pub old_decision_promotable: bool,
    pub blob_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultObservation {
    pub source_commit: String,
    pub revision: u64,
    pub status: ResultStatus,
    pub provenance: EvidenceProvenance,
    #[serde(rename = "resultDigest")]
    pub digest: String,
    pub evidence_root: String,
    pub decision: AdoptionDecision,
    pub selected_at: DateTime<Utc>,
    pub adopted_at: DateTime<Utc>,
    pub blob_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceBlob {
    pub id: String,
    pub kind: EvidenceBlobKind,
    pub bytes_hex: String,
    pub sha256: String,
    pub byte_count: u64,
}

impl EvidenceBlob {
    pub fn from_bytes(id: impl Into<String>, kind: EvidenceBlobKind, bytes: &[u8]) -> Self {
        Self {
            id: id.into(),
            kind,
            bytes_hex: hex::encode(bytes),
            sha256: sha256_hex(bytes),
            byte_count: bytes.len() as u64,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSignature {
    pub algorithm: String,
    pub signer_id: String,
    pub public_key_hex: String,
    pub public_key_digest: String,
    pub signature_hex: String,
    pub signature_digest: String,
    pub signed_manifest_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceManifest {
    pub schema_version: String,
    pub document_type: String,
    pub authority: String,
    pub release_decision: String,
    pub source_commit: String,
    pub journey_id: String,
    pub capture_id: String,
    pub oracle: OracleSnapshot,
    pub bindings: BindingSnapshot,
    pub process: NativeProcessObservation,
    pub events: Vec<DurableEventObservation>,
    pub effects: Vec<EffectObservation>,
    pub restart_points: Vec<RestartPointObservation>,
    pub result: ResultObservation,
    pub blobs: Vec<EvidenceBlob>,
    pub classification: HonestyClassification,
    pub manifest_digest: String,
    pub signature: EvidenceSignature,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceVerificationReport {
    pub schema_version: &'static str,
    pub authority: &'static str,
    pub release_decision: &'static str,
    pub source_commit: String,
    pub journey_id: String,
    pub manifest_digest: String,
    pub signature_status: VerificationState,
    pub content_status: VerificationState,
    pub replay_status: ReplayState,
    pub verdict: EvidenceVerdict,
    pub classification: HonestyClassification,
    pub event_count: usize,
    pub effect_count: usize,
    pub restart_count: usize,
}

#[derive(Default)]
pub struct ReplayGuard {
    seen_manifest_digests: BTreeSet<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessMaterial<'a> {
    id: &'a str,
    generation: u64,
    mode: ComponentMode,
    source_commit: &'a str,
    executable_digest: &'a str,
    started_at: DateTime<Utc>,
    ended_at: DateTime<Utc>,
    exit_code: i32,
    blob_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CaptureMaterial<'a> {
    source_commit: &'a str,
    journey_id: &'a str,
    process_id: &'a str,
    process_generation: u64,
    process_observation_digest: &'a str,
    blob_digests: Vec<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestMaterial<'a> {
    schema_version: &'a str,
    document_type: &'a str,
    authority: &'a str,
    release_decision: &'a str,
    source_commit: &'a str,
    journey_id: &'a str,
    capture_id: &'a str,
    oracle: &'a OracleSnapshot,
    bindings: &'a BindingSnapshot,
    process: &'a NativeProcessObservation,
    events: &'a [DurableEventObservation],
    effects: &'a [EffectObservation],
    restart_points: &'a [RestartPointObservation],
    result: &'a ResultObservation,
    blobs: &'a [EvidenceBlob],
    classification: HonestyClassification,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignatureMaterial<'a> {
    manifest: ManifestMaterial<'a>,
    manifest_digest: &'a str,
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_BYTES)
}

pub fn validate_contract() -> Result<()> {
    let contract: Value = crate::model::parse_strict_json(CONTRACT_BYTES)
        .context("plugin journey evidence contract is not strict JSON")?;
    validate_contract_root(&contract)?;
    validate_contract_defs(&contract)?;
    producer_surface();
    Ok(())
}

fn producer_surface() {
    let _ = build_signed_manifest;
}

fn validate_contract_root(contract: &Value) -> Result<()> {
    ensure!(
        contract.get("$schema").and_then(Value::as_str)
            == Some("https://json-schema.org/draft/2020-12/schema")
            && contract.get("$id").and_then(Value::as_str) == Some(CONTRACT_SCHEMA_VERSION)
            && contract.get("type").and_then(Value::as_str) == Some("object")
            && contract
                .get("additionalProperties")
                .and_then(Value::as_bool)
                == Some(false),
        "plugin journey evidence contract root drifted"
    );
    let expected_root = [
        "schemaVersion",
        "documentType",
        "authority",
        "releaseDecision",
        "sourceCommit",
        "journeyId",
        "captureId",
        "oracle",
        "bindings",
        "process",
        "events",
        "effects",
        "restartPoints",
        "result",
        "blobs",
        "classification",
        "manifestDigest",
        "signature",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    ensure!(
        exact_string_set(contract.get("required").context("evidence required")?)? == expected_root,
        "evidence root required set drifted"
    );
    ensure!(
        contract
            .get("properties")
            .and_then(Value::as_object)
            .context("evidence properties")?
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == expected_root,
        "evidence root property set drifted"
    );
    for (name, value) in [
        ("schemaVersion", CONTRACT_SCHEMA_VERSION),
        ("documentType", DOCUMENT_TYPE),
        ("authority", AUTHORITY),
        ("releaseDecision", RELEASE_DECISION),
    ] {
        ensure!(
            contract["properties"][name]
                .get("const")
                .and_then(Value::as_str)
                == Some(value),
            "evidence constant {name} drifted"
        );
    }
    Ok(())
}

fn validate_contract_defs(contract: &Value) -> Result<()> {
    let expected_defs = [
        "bindings",
        "blob",
        "effect",
        "event",
        "oracle",
        "process",
        "restart",
        "result",
        "signature",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let defs = contract
        .get("$defs")
        .and_then(Value::as_object)
        .context("evidence definitions")?;
    ensure!(
        defs.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected_defs,
        "evidence definition set drifted"
    );
    for (name, definition) in defs {
        ensure!(
            definition.get("type").and_then(Value::as_str) == Some("object")
                && definition
                    .get("additionalProperties")
                    .and_then(Value::as_bool)
                    == Some(false),
            "evidence definition {name} is not closed"
        );
        let properties = definition
            .get("properties")
            .and_then(Value::as_object)
            .with_context(|| format!("evidence definition {name} properties"))?;
        ensure!(
            exact_string_set(
                definition
                    .get("required")
                    .with_context(|| format!("evidence definition {name} required"))?
            )? == properties
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            "evidence definition {name} closure drifted"
        );
    }
    Ok(())
}

fn exact_string_set(value: &Value) -> Result<BTreeSet<&str>> {
    let values = value
        .as_array()
        .context("expected JSON string array")?
        .iter()
        .map(|item| item.as_str().context("expected JSON string"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        "evidence contract string array contains duplicates"
    );
    Ok(values.into_iter().collect())
}

pub fn read_manifest(path: impl AsRef<Path>) -> Result<EvidenceManifest> {
    let path = path.as_ref();
    let bytes =
        fs::read(path).with_context(|| format!("read evidence manifest {}", path.display()))?;
    crate::model::parse_strict_json(&bytes)
        .with_context(|| format!("parse strict evidence manifest {}", path.display()))
}

pub fn build_signed_manifest(
    journey: &PluginNativeJourney,
    oracle: &OracleReport,
    process: NativeProcessObservation,
    blobs: Vec<EvidenceBlob>,
    signer_id: String,
    signer: &Ed25519KeyPair,
) -> Result<EvidenceManifest> {
    validate_contract()?;
    let live_commit = crate::verifier::current_source_commit()?;
    ensure!(
        journey.source_commit == live_commit,
        "cannot produce evidence for a stale source commit"
    );
    ensure!(oracle.source_commit == journey.source_commit);
    ensure!(oracle.journey_id == journey.journey_id);
    ensure!(
        oracle == &validate_journey(journey, &journey.source_commit)?,
        "builder oracle result was not recomputed from the journey"
    );
    let classification = classification_for(oracle, journey.selected_result.provenance);
    let events = journey
        .durable_log
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| DurableEventObservation {
            sequence: index as u64 + 1,
            kind: entry.kind,
            id: format!("durable-event-{}", entry.sequence),
            source_commit: entry.source_commit.clone(),
            occurred_at: entry.occurred_at,
            payload_digest: entry.payload_digest.clone(),
            blob_id: format!("event-blob-{}", entry.sequence),
        })
        .collect::<Vec<_>>();
    let effects = journey
        .effects
        .iter()
        .map(|effect| EffectObservation {
            sequence: effect.sequence,
            id: effect.effect_id.clone(),
            source_commit: effect.source_commit.clone(),
            requested_at: effect.requested_at,
            receipt_at: effect.receipt_at,
            verified_at: effect.verification.verified_at,
            receipt_digest: effect.receipt_digest.clone(),
            verification_digest: effect.verification.verification_digest.clone(),
            blob_id: format!("effect-blob-{}", effect.sequence),
        })
        .collect::<Vec<_>>();
    let restart_points = journey
        .recovery
        .iter()
        .map(|receipt| RestartPointObservation {
            sequence: receipt.sequence,
            hook: receipt.hook,
            status: receipt.status,
            source_commit: receipt.source_commit.clone(),
            occurred_at: receipt.occurred_at,
            receipt_digest: receipt.receipt_digest.clone(),
            old_plugin_accepted: receipt.old_plugin_accepted,
            old_decision_promotable: receipt.old_decision_promotable,
            blob_id: format!("restart-blob-{}", receipt.sequence),
        })
        .collect::<Vec<_>>();
    let result = ResultObservation {
        source_commit: journey.selected_result.source_commit.clone(),
        revision: journey.selected_result.revision,
        status: journey.selected_result.status,
        provenance: journey.selected_result.provenance,
        digest: journey.selected_result.result_digest.clone(),
        evidence_root: journey.selected_result.evidence_root.clone(),
        decision: journey.adoption.decision,
        selected_at: journey.selected_result.selected_at,
        adopted_at: journey.adoption.adopted_at,
        blob_id: "result-blob".into(),
    };
    let bindings = bindings_from(journey);
    let oracle_snapshot = oracle_snapshot_from(oracle);
    let mut manifest = EvidenceManifest {
        schema_version: CONTRACT_SCHEMA_VERSION.into(),
        document_type: DOCUMENT_TYPE.into(),
        authority: AUTHORITY.into(),
        release_decision: RELEASE_DECISION.into(),
        source_commit: journey.source_commit.clone(),
        journey_id: journey.journey_id.clone(),
        capture_id: String::new(),
        oracle: oracle_snapshot,
        bindings,
        process,
        events,
        effects,
        restart_points,
        result,
        blobs,
        classification,
        manifest_digest: String::new(),
        signature: empty_signature(),
    };
    manifest.process.observation_digest = expected_process_digest(&manifest.process)?;
    manifest.capture_id = expected_capture_id(&manifest)?;
    manifest.manifest_digest = expected_manifest_digest(&manifest)?;
    validate_manifest_shape(&manifest, journey, oracle, &journey.source_commit)?;
    manifest.signature = sign_manifest(&manifest, signer_id, signer)?;
    Ok(manifest)
}

fn empty_signature() -> EvidenceSignature {
    EvidenceSignature {
        algorithm: ED25519_ALGORITHM.into(),
        signer_id: String::new(),
        public_key_hex: String::new(),
        public_key_digest: String::new(),
        signature_hex: String::new(),
        signature_digest: String::new(),
        signed_manifest_digest: String::new(),
    }
}

fn sign_manifest(
    manifest: &EvidenceManifest,
    signer_id: String,
    signer: &Ed25519KeyPair,
) -> Result<EvidenceSignature> {
    validate_identifier(&signer_id, "evidence signer id")?;
    let public_key_hex = hex::encode(signer.public_key().as_ref());
    let message = signature_bytes(manifest)?;
    let signature_hex = hex::encode(signer.sign(&message).as_ref());
    Ok(EvidenceSignature {
        algorithm: ED25519_ALGORITHM.into(),
        signer_id,
        public_key_digest: sha256_hex(signer.public_key().as_ref()),
        signature_digest: sha256_hex(&hex::decode(&signature_hex)?),
        public_key_hex,
        signature_hex,
        signed_manifest_digest: manifest.manifest_digest.clone(),
    })
}

pub fn validate_manifest(
    manifest: &EvidenceManifest,
    journey: &PluginNativeJourney,
    oracle: &OracleReport,
    expected_source_commit: &str,
) -> Result<EvidenceVerificationReport> {
    validate_contract()?;
    let computed_oracle = validate_journey(journey, expected_source_commit)?;
    ensure!(
        oracle == &computed_oracle,
        "evidence manifest oracle result was not recomputed from the journey"
    );
    validate_manifest_shape(manifest, journey, oracle, expected_source_commit)?;
    ensure!(
        manifest.manifest_digest == expected_manifest_digest(manifest)?,
        "evidence manifest digest drifted"
    );
    validate_signature(manifest)?;
    let native_pass = manifest.oracle.native_pass
        && manifest.oracle.status == OracleStatus::NativePass
        && manifest.classification == HonestyClassification::NativeVerified
        && manifest.process.mode == ComponentMode::Native;
    Ok(EvidenceVerificationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        authority: AUTHORITY,
        release_decision: RELEASE_DECISION,
        source_commit: expected_source_commit.into(),
        journey_id: manifest.journey_id.clone(),
        manifest_digest: manifest.manifest_digest.clone(),
        signature_status: VerificationState::Verified,
        content_status: VerificationState::Verified,
        replay_status: ReplayState::NotGuarded,
        verdict: if native_pass {
            EvidenceVerdict::NativePass
        } else {
            EvidenceVerdict::NotNative
        },
        classification: manifest.classification,
        event_count: manifest.events.len(),
        effect_count: manifest.effects.len(),
        restart_count: manifest.restart_points.len(),
    })
}

impl ReplayGuard {
    pub fn verify_once(
        &mut self,
        manifest: &EvidenceManifest,
        journey: &PluginNativeJourney,
        oracle: &OracleReport,
        expected_source_commit: &str,
    ) -> Result<EvidenceVerificationReport> {
        let mut report = validate_manifest(manifest, journey, oracle, expected_source_commit)?;
        ensure!(
            self.seen_manifest_digests
                .insert(manifest.manifest_digest.clone()),
            "evidence manifest replay detected"
        );
        report.replay_status = ReplayState::Guarded;
        Ok(report)
    }
}

fn oracle_snapshot_from(oracle: &OracleReport) -> OracleSnapshot {
    OracleSnapshot {
        schema_version: ORACLE_SCHEMA_VERSION.into(),
        authority: ORACLE_AUTHORITY.into(),
        release_decision: ORACLE_RELEASE_DECISION.into(),
        status: oracle.oracle_status,
        native_pass: oracle.native_pass,
        source_commit: oracle.source_commit.clone(),
        journey_id: oracle.journey_id.clone(),
        project_id: oracle.project_id.clone(),
        mission_id: oracle.mission_id.clone(),
        evidence_root: oracle.evidence_root.clone(),
        replay_digest: oracle.replay_digest.clone(),
        invocation_count: oracle.invocation_count,
        effect_count: oracle.effect_count,
        recovery_count: oracle.recovery_count,
    }
}

fn bindings_from(journey: &PluginNativeJourney) -> BindingSnapshot {
    BindingSnapshot {
        project_id: journey.project.id.clone(),
        mission_id: journey.mission.id.clone(),
        runtime_plugin_id: journey.runtime_plugin.id.clone(),
        model_plugin_id: journey.model_plugin.id.clone(),
        service_id: journey.service.id.clone(),
        provider_id: journey.provider.id.clone(),
        consumer_id: journey.consumer.id.clone(),
        runtime_plugin_digest: journey.runtime_plugin.plugin_digest.clone(),
        model_digest: journey.model_plugin.model_digest.clone(),
        provider_digest: journey.provider.provider_digest.clone(),
        service_log_digest: journey.service.durable_log_digest.clone(),
        consumer_result_digest: journey.consumer.selected_result_digest.clone(),
    }
}

fn classification_for(
    oracle: &OracleReport,
    provenance: EvidenceProvenance,
) -> HonestyClassification {
    if oracle.native_pass && oracle.oracle_status == OracleStatus::NativePass {
        return HonestyClassification::NativeVerified;
    }
    match provenance {
        EvidenceProvenance::Fixture => HonestyClassification::Fixture,
        EvidenceProvenance::Simulator => HonestyClassification::Simulator,
        EvidenceProvenance::BlockedEnv | EvidenceProvenance::Missing => {
            HonestyClassification::BlockedEnv
        }
        EvidenceProvenance::Native => match oracle.oracle_status {
            OracleStatus::BlockedEnv => HonestyClassification::BlockedEnv,
            OracleStatus::NotEvaluated | OracleStatus::NativePass => {
                HonestyClassification::NotEvaluated
            }
        },
    }
}

fn expected_process_digest(process: &NativeProcessObservation) -> Result<String> {
    digest_json(
        PROCESS_DOMAIN,
        &ProcessMaterial {
            id: &process.id,
            generation: process.generation,
            mode: process.mode,
            source_commit: &process.source_commit,
            executable_digest: &process.executable_digest,
            started_at: process.started_at,
            ended_at: process.ended_at,
            exit_code: process.exit_code,
            blob_id: &process.blob_id,
        },
    )
    .context("derive native process observation digest")
}

fn expected_capture_id(manifest: &EvidenceManifest) -> Result<String> {
    let mut blob_digests = manifest
        .blobs
        .iter()
        .map(|blob| (blob.id.as_str(), blob.sha256.as_str()))
        .collect::<Vec<_>>();
    blob_digests.sort_unstable_by(|left, right| left.0.cmp(right.0));
    digest_json(
        CAPTURE_DOMAIN,
        &CaptureMaterial {
            source_commit: &manifest.source_commit,
            journey_id: &manifest.journey_id,
            process_id: &manifest.process.id,
            process_generation: manifest.process.generation,
            process_observation_digest: &manifest.process.observation_digest,
            blob_digests: blob_digests.into_iter().map(|(_, digest)| digest).collect(),
        },
    )
    .context("derive evidence capture id")
}

fn manifest_material(manifest: &EvidenceManifest) -> ManifestMaterial<'_> {
    ManifestMaterial {
        schema_version: &manifest.schema_version,
        document_type: &manifest.document_type,
        authority: &manifest.authority,
        release_decision: &manifest.release_decision,
        source_commit: &manifest.source_commit,
        journey_id: &manifest.journey_id,
        capture_id: &manifest.capture_id,
        oracle: &manifest.oracle,
        bindings: &manifest.bindings,
        process: &manifest.process,
        events: &manifest.events,
        effects: &manifest.effects,
        restart_points: &manifest.restart_points,
        result: &manifest.result,
        blobs: &manifest.blobs,
        classification: manifest.classification,
    }
}

fn expected_manifest_digest(manifest: &EvidenceManifest) -> Result<String> {
    digest_json(MANIFEST_DOMAIN, &manifest_material(manifest))
        .context("derive evidence manifest digest")
}

fn signature_bytes(manifest: &EvidenceManifest) -> Result<Vec<u8>> {
    Ok(domain_bytes(
        SIGNATURE_DOMAIN,
        &SignatureMaterial {
            manifest: manifest_material(manifest),
            manifest_digest: &manifest.manifest_digest,
        },
    )?)
}

fn validate_manifest_shape(
    manifest: &EvidenceManifest,
    journey: &PluginNativeJourney,
    oracle: &OracleReport,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(
        manifest.schema_version == CONTRACT_SCHEMA_VERSION
            && manifest.document_type == DOCUMENT_TYPE
            && manifest.authority == AUTHORITY
            && manifest.release_decision == RELEASE_DECISION
            && manifest.source_commit == expected_source_commit
            && manifest.journey_id == journey.journey_id,
        "evidence manifest envelope is stale or invalid"
    );
    validate_commit(expected_source_commit)?;
    validate_identifier(&manifest.journey_id, "evidence journey id")?;
    validate_digest(&manifest.capture_id, "evidence capture id")?;
    validate_digest(&manifest.manifest_digest, "evidence manifest digest")?;
    ensure!(manifest.oracle == oracle_snapshot_from(oracle));
    ensure!(manifest.bindings == bindings_from(journey));
    ensure!(manifest.capture_id == expected_capture_id(manifest)?);
    validate_process(&manifest.process, journey, expected_source_commit)?;
    validate_events(&manifest.events, journey, expected_source_commit)?;
    validate_effects(&manifest.effects, journey, expected_source_commit)?;
    validate_restarts(&manifest.restart_points, journey, expected_source_commit)?;
    validate_result(&manifest.result, journey, expected_source_commit)?;
    validate_blobs(manifest)?;
    let expected_classification = classification_for(oracle, journey.selected_result.provenance);
    ensure!(manifest.classification == expected_classification);
    if oracle.native_pass {
        ensure!(
            oracle.oracle_status == OracleStatus::NativePass
                && manifest.classification == HonestyClassification::NativeVerified
                && manifest.process.mode == ComponentMode::Native
                && manifest.process.exit_code == 0
                && manifest.result.status == ResultStatus::Completed
                && manifest.result.provenance == EvidenceProvenance::Native
                && manifest.result.decision == AdoptionDecision::Adopt,
            "non-native or incomplete evidence cannot claim native pass"
        );
    } else {
        ensure!(
            !manifest.oracle.native_pass
                && manifest.classification != HonestyClassification::NativeVerified,
            "non-native oracle cannot be upgraded by evidence manifest"
        );
    }
    Ok(())
}

fn validate_process(
    process: &NativeProcessObservation,
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    validate_identifier(&process.id, "native process id")?;
    ensure!(process.generation > 0 && process.source_commit == expected_source_commit);
    validate_digest(&process.executable_digest, "native executable digest")?;
    ensure!(process.started_at <= process.ended_at);
    validate_digest(&process.observation_digest, "process observation digest")?;
    ensure!(
        process.observation_digest == expected_process_digest(process)?,
        "native process observation digest drifted"
    );
    ensure!(process.blob_id == "process-blob");
    if journey.runtime_plugin.mode == ComponentMode::Native {
        ensure!(process.mode == ComponentMode::Native);
    }
    Ok(())
}

fn validate_events(
    events: &[DurableEventObservation],
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(events.len() == journey.durable_log.entries.len());
    let mut ids = BTreeSet::new();
    let mut previous = None;
    for (index, (event, entry)) in events.iter().zip(&journey.durable_log.entries).enumerate() {
        ensure!(
            event.sequence == index as u64 + 1
                && event.kind == entry.kind
                && event.id == format!("durable-event-{}", entry.sequence)
                && event.source_commit == expected_source_commit
                && event.occurred_at == entry.occurred_at
                && event.payload_digest == entry.payload_digest
                && event.blob_id == format!("event-blob-{}", entry.sequence)
        );
        ensure!(ids.insert(event.id.as_str()));
        if let Some(prior) = previous {
            ensure!(event.occurred_at > prior);
        }
        previous = Some(event.occurred_at);
    }
    ensure!(events[0].kind == EXPECTED_LOG_KINDS[0]);
    ensure!(events[1].kind == EXPECTED_LOG_KINDS[1]);
    ensure!(events.last().expect("non-empty events").kind == EXPECTED_LOG_KINDS[3]);
    ensure!(
        events[2..events.len() - 1]
            .iter()
            .all(|event| event.kind == EXPECTED_LOG_KINDS[2])
    );
    Ok(())
}

fn validate_effects(
    effects: &[EffectObservation],
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(effects.len() == journey.effects.len() && !effects.is_empty());
    for (index, (observation, effect)) in effects.iter().zip(&journey.effects).enumerate() {
        ensure!(
            observation.sequence == index as u64 + 1
                && observation.id == effect.effect_id
                && observation.source_commit == expected_source_commit
                && observation.requested_at == effect.requested_at
                && observation.receipt_at == effect.receipt_at
                && observation.verified_at == effect.verification.verified_at
                && observation.receipt_digest == effect.receipt_digest
                && observation.verification_digest == effect.verification.verification_digest
                && observation.blob_id == format!("effect-blob-{}", effect.sequence)
                && effect.status == EffectStatus::Applied
                && effect.verification.status == VerificationStatus::Verified
        );
        validate_digest(
            &observation.receipt_digest,
            "evidence effect receipt digest",
        )?;
        validate_digest(
            &observation.verification_digest,
            "evidence effect verification digest",
        )?;
    }
    Ok(())
}

fn validate_restarts(
    restarts: &[RestartPointObservation],
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    ensure!(restarts.len() == EXPECTED_RECOVERY_HOOKS.len());
    let mut hooks = BTreeSet::new();
    for (index, (observation, receipt)) in restarts.iter().zip(&journey.recovery).enumerate() {
        ensure!(
            observation.sequence == index as u64 + 1
                && observation.hook == EXPECTED_RECOVERY_HOOKS[index]
                && observation.hook == receipt.hook
                && observation.status == RecoveryStatus::Recovered
                && observation.status == receipt.status
                && observation.source_commit == expected_source_commit
                && observation.occurred_at == receipt.occurred_at
                && observation.receipt_digest == receipt.receipt_digest
                && !observation.old_plugin_accepted
                && !observation.old_decision_promotable
                && observation.blob_id == format!("restart-blob-{}", receipt.sequence)
        );
        ensure!(hooks.insert(observation.hook));
        validate_digest(
            &observation.receipt_digest,
            "evidence restart receipt digest",
        )?;
    }
    ensure!(hooks == EXPECTED_RECOVERY_HOOKS.into_iter().collect());
    Ok(())
}

fn validate_result(
    result: &ResultObservation,
    journey: &PluginNativeJourney,
    expected_source_commit: &str,
) -> Result<()> {
    let selected = &journey.selected_result;
    ensure!(
        result.source_commit == expected_source_commit
            && result.revision == selected.revision
            && result.status == selected.status
            && result.provenance == selected.provenance
            && result.digest == selected.result_digest
            && result.evidence_root == selected.evidence_root
            && result.decision == journey.adoption.decision
            && result.selected_at == selected.selected_at
            && result.adopted_at == journey.adoption.adopted_at
            && result.blob_id == "result-blob"
    );
    validate_digest(&result.digest, "evidence result digest")?;
    if !result.evidence_root.is_empty() {
        validate_digest(&result.evidence_root, "evidence result root")?;
    }
    Ok(())
}

fn validate_blobs(manifest: &EvidenceManifest) -> Result<()> {
    let mut blobs = BTreeMap::new();
    for blob in &manifest.blobs {
        validate_identifier(&blob.id, "evidence blob id")?;
        ensure!(blobs.insert(blob.id.as_str(), blob.kind).is_none());
        ensure!(!blob.bytes_hex.is_empty() && blob.bytes_hex == blob.bytes_hex.to_lowercase());
        let bytes = hex::decode(&blob.bytes_hex).context("evidence blob bytes are not hex")?;
        let derived = EvidenceBlob::from_bytes(blob.id.clone(), blob.kind, &bytes);
        ensure!(hex::encode(&bytes) == blob.bytes_hex);
        ensure!(blob.byte_count == derived.byte_count && blob.byte_count > 0);
        ensure!(derived.sha256 == blob.sha256);
        validate_digest(&blob.sha256, "evidence blob sha256")?;
    }
    let mut references = BTreeMap::new();
    references.insert("process-blob", EvidenceBlobKind::ProcessObservation);
    for event in &manifest.events {
        references.insert(event.blob_id.as_str(), EvidenceBlobKind::DurableEvent);
    }
    for effect in &manifest.effects {
        references.insert(effect.blob_id.as_str(), EvidenceBlobKind::EffectReceipt);
    }
    for restart in &manifest.restart_points {
        references.insert(restart.blob_id.as_str(), EvidenceBlobKind::RestartReceipt);
    }
    references.insert("result-blob", EvidenceBlobKind::ResultReceipt);
    ensure!(references.len() == manifest.blobs.len());
    for (id, kind) in references {
        ensure!(
            blobs.get(id) == Some(&kind),
            "evidence blob reference missing or kind drifted"
        );
    }
    Ok(())
}

fn validate_signature(manifest: &EvidenceManifest) -> Result<()> {
    let signature = &manifest.signature;
    ensure!(signature.algorithm == ED25519_ALGORITHM);
    validate_identifier(&signature.signer_id, "evidence signer id")?;
    let public_key = decode_hex_exact(&signature.public_key_hex, 32, "evidence public key")?;
    let signature_bytes = decode_hex_exact(&signature.signature_hex, 64, "evidence signature")?;
    ensure!(signature.public_key_digest == sha256_hex(&public_key));
    ensure!(signature.signature_digest == sha256_hex(&signature_bytes));
    ensure!(signature.signed_manifest_digest == manifest.manifest_digest);
    let message = signature_bytes_for_manifest(manifest)?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| anyhow::anyhow!("evidence manifest signature verification failed"))
}

fn signature_bytes_for_manifest(manifest: &EvidenceManifest) -> Result<Vec<u8>> {
    signature_bytes(manifest)
}

fn decode_hex_exact(value: &str, byte_count: usize, label: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(value).with_context(|| format!("{label} is not hexadecimal"))?;
    ensure!(
        bytes.len() == byte_count && value == hex::encode(&bytes),
        "{label} must be canonical lowercase hex"
    );
    Ok(bytes)
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} is required");
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-/".contains(&byte)),
        "{label} contains an unsafe character"
    );
    Ok(())
}

fn validate_commit(value: &str) -> Result<()> {
    ensure!(
        value.len() == 40
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "evidence source commit must be lowercase 40-hex Git commit"
    );
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    ensure!(is_lower_hex(value, 32), "{label} must be lowercase SHA-256");
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};
    use ring::signature::Ed25519KeyPair;

    use super::*;
    use crate::verifier::{current_source_commit, test_journey, validate_journey};

    fn signer() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[83; 32]).expect("fixed evidence signer")
    }

    fn process(source_commit: &str, mode: ComponentMode) -> NativeProcessObservation {
        let started_at = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
        NativeProcessObservation {
            id: "native-process-01".into(),
            generation: 1,
            mode,
            source_commit: source_commit.into(),
            executable_digest: "a".repeat(64),
            started_at,
            ended_at: started_at + Duration::seconds(10),
            exit_code: if mode == ComponentMode::Native { 0 } else { 3 },
            observation_digest: String::new(),
            blob_id: "process-blob".into(),
        }
    }

    fn blobs() -> Vec<EvidenceBlob> {
        let mut blobs = vec![EvidenceBlob::from_bytes(
            "process-blob",
            EvidenceBlobKind::ProcessObservation,
            b"native process observation",
        )];
        for sequence in 1..=4 {
            blobs.push(EvidenceBlob::from_bytes(
                format!("event-blob-{sequence}"),
                EvidenceBlobKind::DurableEvent,
                format!("durable event {sequence}").as_bytes(),
            ));
        }
        blobs.push(EvidenceBlob::from_bytes(
            "effect-blob-1",
            EvidenceBlobKind::EffectReceipt,
            b"effect receipt",
        ));
        for sequence in 1..=4 {
            blobs.push(EvidenceBlob::from_bytes(
                format!("restart-blob-{sequence}"),
                EvidenceBlobKind::RestartReceipt,
                format!("restart receipt {sequence}").as_bytes(),
            ));
        }
        blobs.push(EvidenceBlob::from_bytes(
            "result-blob",
            EvidenceBlobKind::ResultReceipt,
            b"selected result receipt",
        ));
        blobs
    }

    fn native_manifest() -> (EvidenceManifest, PluginNativeJourney, OracleReport) {
        let journey = test_journey(ComponentMode::Native);
        let commit = current_source_commit().unwrap();
        let oracle = validate_journey(&journey, &commit).unwrap();
        let manifest = build_signed_manifest(
            &journey,
            &oracle,
            process(&commit, ComponentMode::Native),
            blobs(),
            "test-signer-01".into(),
            &signer(),
        )
        .unwrap();
        (manifest, journey, oracle)
    }

    #[test]
    fn checked_in_evidence_contract_is_closed_and_signed_native_bundle_verifies() {
        validate_contract().unwrap();
        let (manifest, journey, oracle) = native_manifest();
        let commit = current_source_commit().unwrap();
        let report = validate_manifest(&manifest, &journey, &oracle, &commit).unwrap();
        assert_eq!(report.signature_status, VerificationState::Verified);
        assert_eq!(report.content_status, VerificationState::Verified);
        assert_eq!(report.verdict, EvidenceVerdict::NativePass);
        assert_eq!(report.classification, HonestyClassification::NativeVerified);
        assert!(is_lower_hex(&contract_digest(), 32));
        let contract: Value = crate::model::parse_strict_json(CONTRACT_BYTES).unwrap();
        let value = serde_json::to_value(&manifest).unwrap();
        assert_schema_keys(&value, &contract, None);
        for (field, definition) in [
            ("oracle", "oracle"),
            ("bindings", "bindings"),
            ("process", "process"),
            ("result", "result"),
            ("signature", "signature"),
        ] {
            assert_schema_keys(&value[field], &contract, Some(definition));
        }
        for event in value["events"].as_array().unwrap() {
            assert_schema_keys(event, &contract, Some("event"));
        }
        for effect in value["effects"].as_array().unwrap() {
            assert_schema_keys(effect, &contract, Some("effect"));
        }
        for restart in value["restartPoints"].as_array().unwrap() {
            assert_schema_keys(restart, &contract, Some("restart"));
        }
        for blob in value["blobs"].as_array().unwrap() {
            assert_schema_keys(blob, &contract, Some("blob"));
        }
    }

    #[test]
    fn replay_guard_rejects_second_use_of_same_content_addressed_manifest() {
        let (manifest, journey, oracle) = native_manifest();
        let commit = current_source_commit().unwrap();
        let mut guard = ReplayGuard::default();
        assert_eq!(
            guard
                .verify_once(&manifest, &journey, &oracle, &commit)
                .unwrap()
                .replay_status,
            ReplayState::Guarded
        );
        assert!(
            guard
                .verify_once(&manifest, &journey, &oracle, &commit)
                .is_err()
        );
    }

    #[test]
    fn missing_bytes_digest_drift_and_signature_tampering_are_rejected() {
        let (mut missing, journey, oracle) = native_manifest();
        missing.blobs.pop();
        let commit = current_source_commit().unwrap();
        assert!(validate_manifest(&missing, &journey, &oracle, &commit).is_err());

        let (mut drift, journey, oracle) = native_manifest();
        drift.blobs[0].bytes_hex.push_str("00");
        assert!(validate_manifest(&drift, &journey, &oracle, &commit).is_err());

        let (mut forged, journey, oracle) = native_manifest();
        let replacement = if forged.signature.signature_hex.starts_with('0') {
            '1'
        } else {
            '0'
        };
        forged
            .signature
            .signature_hex
            .replace_range(..1, &replacement.to_string());
        assert!(validate_manifest(&forged, &journey, &oracle, &commit).is_err());
    }

    #[test]
    fn cross_commit_and_replayed_sequence_cannot_claim_native() {
        let (mut stale, journey, oracle) = native_manifest();
        stale.source_commit = "0".repeat(40);
        let commit = current_source_commit().unwrap();
        assert!(validate_manifest(&stale, &journey, &oracle, &commit).is_err());

        let (mut duplicate, journey, oracle) = native_manifest();
        duplicate.events[3].sequence = duplicate.events[2].sequence;
        assert!(validate_manifest(&duplicate, &journey, &oracle, &commit).is_err());
    }

    #[test]
    fn simulator_is_honest_non_native_and_never_passes() {
        let journey = test_journey(ComponentMode::Simulator);
        let commit = current_source_commit().unwrap();
        let oracle = validate_journey(&journey, &commit).unwrap();
        let manifest = build_signed_manifest(
            &journey,
            &oracle,
            process(&commit, ComponentMode::Simulator),
            blobs(),
            "test-signer-01".into(),
            &signer(),
        )
        .unwrap();
        let report = validate_manifest(&manifest, &journey, &oracle, &commit).unwrap();
        assert_eq!(report.verdict, EvidenceVerdict::NotNative);
        assert!(matches!(
            report.classification,
            HonestyClassification::BlockedEnv | HonestyClassification::Simulator
        ));
    }

    fn assert_schema_keys(actual: &Value, contract: &Value, definition: Option<&str>) {
        let schema = definition
            .map(|name| &contract["$defs"][name])
            .unwrap_or(contract);
        let expected = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<BTreeSet<_>>();
        let observed = actual.as_object().unwrap().keys().collect::<BTreeSet<_>>();
        assert_eq!(
            observed, expected,
            "evidence serializer drifted for {definition:?}"
        );
    }
}
