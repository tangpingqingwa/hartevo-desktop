use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};

use crate::digest::is_lower_hex;
use crate::model::{
    EnvelopeSignature, PROVIDER_REGISTRY_SCHEMA, ProviderRecord, ProviderRegistry, ProviderStatus,
    RESULT_ENVELOPE_SCHEMA, ReleaseDecision, ResultEnvelope, VerificationState, WorkerEvidence,
    WorkerEvidenceKind,
};
use crate::signature::{signature_digest, verify_ed25519};

pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const VALIDATION_SCHEMA_VERSION: &str = "hartevo-federation-result-validation/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationStatus {
    Verified,
    Rejected,
    NotEvaluated,
}

impl VerificationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::Rejected => "REJECTED",
            Self::NotEvaluated => "NOT_EVALUATED",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationReason {
    InvalidEnvelope,
    TamperedEnvelope,
    CrossMission,
    UnknownProvider,
    RevokedProvider,
    ProviderBindingMismatch,
    MissingSignature,
    InvalidSignature,
    RealWorkerUnavailable,
    WorkerVerifierUnavailable,
    WorkerEvidenceMismatch,
    CurrentCommitMismatch,
    VerificationNotComplete,
    ReplayNonce,
    SequenceRegression,
    SequenceGap,
}

impl VerificationReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidEnvelope => "INVALID_ENVELOPE",
            Self::TamperedEnvelope => "TAMPERED_ENVELOPE",
            Self::CrossMission => "CROSS_MISSION",
            Self::UnknownProvider => "UNKNOWN_PROVIDER",
            Self::RevokedProvider => "REVOKED_PROVIDER",
            Self::ProviderBindingMismatch => "PROVIDER_BINDING_MISMATCH",
            Self::MissingSignature => "MISSING_SIGNATURE",
            Self::InvalidSignature => "INVALID_SIGNATURE",
            Self::RealWorkerUnavailable => "REAL_WORKER_UNAVAILABLE",
            Self::WorkerVerifierUnavailable => "WORKER_VERIFIER_UNAVAILABLE",
            Self::WorkerEvidenceMismatch => "WORKER_EVIDENCE_MISMATCH",
            Self::CurrentCommitMismatch => "CURRENT_COMMIT_MISMATCH",
            Self::VerificationNotComplete => "VERIFICATION_NOT_COMPLETE",
            Self::ReplayNonce => "REPLAY_NONCE",
            Self::SequenceRegression => "SEQUENCE_REGRESSION",
            Self::SequenceGap => "SEQUENCE_GAP",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationDecision {
    status: VerificationStatus,
    reason: Option<VerificationReason>,
    envelope_id: String,
}

impl VerificationDecision {
    pub const fn status(&self) -> VerificationStatus {
        self.status
    }

    pub const fn reason(&self) -> Option<VerificationReason> {
        self.reason
    }

    pub const fn is_verified(&self) -> bool {
        matches!(self.status, VerificationStatus::Verified)
    }

    pub fn envelope_id(&self) -> &str {
        &self.envelope_id
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReplayKey {
    project_id: String,
    mission_id: String,
    worker_id: String,
    provider_digest: String,
}

#[derive(Clone, Debug)]
pub struct VerificationContext {
    pub expected_project_id: String,
    pub expected_mission_id: String,
    pub current_commit: String,
    pub provider_registry: ProviderRegistry,
    pub worker_attestation_verifier_available: bool,
    seen_replay_nonces: BTreeSet<String>,
    highest_sequences: BTreeMap<ReplayKey, u64>,
}

impl VerificationContext {
    pub fn new(
        expected_project_id: impl Into<String>,
        expected_mission_id: impl Into<String>,
        current_commit: impl Into<String>,
        provider_registry: ProviderRegistry,
        worker_attestation_verifier_available: bool,
    ) -> Self {
        Self {
            expected_project_id: expected_project_id.into(),
            expected_mission_id: expected_mission_id.into(),
            current_commit: current_commit.into(),
            provider_registry,
            worker_attestation_verifier_available,
            seen_replay_nonces: BTreeSet::new(),
            highest_sequences: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct ResultVerifier {
    context: VerificationContext,
}

impl ResultVerifier {
    pub fn new(context: VerificationContext) -> Self {
        Self { context }
    }

    pub fn verify(&mut self, envelope: &ResultEnvelope) -> VerificationDecision {
        let envelope_id = envelope.envelope_id.clone();
        if validate_envelope_shape(envelope).is_err() {
            return rejected(envelope_id, VerificationReason::InvalidEnvelope);
        }
        if envelope.origin.project_id != self.context.expected_project_id
            || envelope.origin.mission_id != self.context.expected_mission_id
        {
            return rejected(envelope_id, VerificationReason::CrossMission);
        }
        let Some(provider) = self
            .context
            .provider_registry
            .providers
            .iter()
            .find(|provider| provider.provider_digest == envelope.remote_worker.provider_digest)
        else {
            return rejected(envelope_id, VerificationReason::UnknownProvider);
        };
        if provider.status == ProviderStatus::Revoked {
            return rejected(envelope_id, VerificationReason::RevokedProvider);
        }
        if provider.worker_id != envelope.remote_worker.worker_id
            || provider.service_id != envelope.remote_worker.service_id
        {
            return rejected(envelope_id, VerificationReason::ProviderBindingMismatch);
        }
        let Some(signature) = envelope.signature.as_ref() else {
            return not_evaluated(envelope_id, VerificationReason::MissingSignature);
        };
        let Some(worker_evidence) = envelope.worker_evidence.as_ref() else {
            return not_evaluated(envelope_id, VerificationReason::RealWorkerUnavailable);
        };
        if envelope.current_commit != self.context.current_commit {
            return rejected(envelope_id, VerificationReason::CurrentCommitMismatch);
        }
        if envelope.computed_envelope_digest().ok().as_deref()
            != Some(envelope.envelope_digest.as_str())
        {
            return rejected(envelope_id, VerificationReason::TamperedEnvelope);
        }
        if verify_signature(envelope, signature).is_err() {
            return rejected(envelope_id, VerificationReason::InvalidSignature);
        }
        if worker_evidence.worker_id != provider.worker_id
            || worker_evidence.attestation_digest != provider.worker_attestation_digest
        {
            return rejected(envelope_id, VerificationReason::WorkerEvidenceMismatch);
        }
        if !self.context.worker_attestation_verifier_available
            || !self
                .context
                .provider_registry
                .native_worker_verifier_available
        {
            return not_evaluated(envelope_id, VerificationReason::WorkerVerifierUnavailable);
        }
        if envelope.verification.state == VerificationState::Pending {
            return not_evaluated(envelope_id, VerificationReason::VerificationNotComplete);
        }
        if envelope.verification.state == VerificationState::Rejected {
            return rejected(envelope_id, VerificationReason::VerificationNotComplete);
        }
        let replay_key = ReplayKey {
            project_id: envelope.origin.project_id.clone(),
            mission_id: envelope.origin.mission_id.clone(),
            worker_id: envelope.remote_worker.worker_id.clone(),
            provider_digest: envelope.remote_worker.provider_digest.clone(),
        };
        if self
            .context
            .seen_replay_nonces
            .contains(&envelope.replay_nonce)
        {
            return rejected(envelope_id, VerificationReason::ReplayNonce);
        }
        if let Some(previous) = self.context.highest_sequences.get(&replay_key) {
            if envelope.sequence <= *previous {
                return rejected(envelope_id, VerificationReason::SequenceRegression);
            }
            if envelope.sequence != previous.saturating_add(1) {
                return rejected(envelope_id, VerificationReason::SequenceGap);
            }
        }
        self.context
            .seen_replay_nonces
            .insert(envelope.replay_nonce.clone());
        self.context
            .highest_sequences
            .insert(replay_key, envelope.sequence);
        verified(envelope_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdoptedResult {
    pub envelope_id: String,
    pub project_id: String,
    pub mission_id: String,
    pub output_root: String,
    pub outcome_link_id: String,
    pub outcome_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionError {
    ResultNotVerified,
    DecisionEnvelopeMismatch,
}

pub struct FederationResultConsumer;

impl FederationResultConsumer {
    pub fn adopt(
        envelope: &ResultEnvelope,
        decision: &VerificationDecision,
    ) -> std::result::Result<AdoptedResult, AdoptionError> {
        if !decision.is_verified() {
            return Err(AdoptionError::ResultNotVerified);
        }
        if decision.envelope_id() != envelope.envelope_id {
            return Err(AdoptionError::DecisionEnvelopeMismatch);
        }
        Ok(AdoptedResult {
            envelope_id: envelope.envelope_id.clone(),
            project_id: envelope.origin.project_id.clone(),
            mission_id: envelope.origin.mission_id.clone(),
            output_root: envelope.roots.output.clone(),
            outcome_link_id: envelope.outcome.link_id.clone(),
            outcome_digest: envelope.outcome.digest.clone(),
        })
    }
}

pub fn validate_envelope_shape(envelope: &ResultEnvelope) -> Result<()> {
    ensure!(
        envelope.schema_version == RESULT_ENVELOPE_SCHEMA,
        "unexpected envelope schema"
    );
    ensure!(valid_token(&envelope.envelope_id), "invalid envelope id");
    ensure!(
        valid_token(&envelope.origin.project_id),
        "invalid Project id"
    );
    ensure!(
        valid_token(&envelope.origin.mission_id),
        "invalid Mission id"
    );
    ensure!(envelope.origin.turn > 0, "turn must be positive");
    ensure!(
        valid_token(&envelope.remote_worker.worker_id),
        "invalid worker id"
    );
    ensure!(
        valid_token(&envelope.remote_worker.service_id),
        "invalid service id"
    );
    ensure!(
        is_lower_hex(&envelope.remote_worker.provider_digest, 32),
        "invalid provider digest"
    );
    ensure!(
        is_lower_hex(&envelope.roots.input, 32),
        "invalid input root"
    );
    ensure!(
        is_lower_hex(&envelope.roots.output, 32),
        "invalid output root"
    );
    ensure!(
        is_lower_hex(&envelope.roots.evidence, 32),
        "invalid evidence root"
    );
    ensure!(envelope.sequence > 0, "sequence must be positive");
    ensure!(
        is_lower_hex(&envelope.replay_nonce, 32),
        "invalid replay nonce"
    );
    validate_link(&envelope.effect_receipt)?;
    validate_link(&envelope.outcome)?;
    ensure!(
        valid_token(&envelope.verification.link_id),
        "invalid verification link id"
    );
    ensure!(
        is_lower_hex(&envelope.verification.digest, 32),
        "invalid verification digest"
    );
    ensure!(
        is_lower_hex(&envelope.current_commit, 20),
        "invalid current commit"
    );
    ensure!(
        is_lower_hex(&envelope.envelope_digest, 32),
        "invalid envelope digest"
    );
    if let Some(signature) = envelope.signature.as_ref() {
        validate_signature_shape(signature)?;
    }
    if let Some(worker_evidence) = envelope.worker_evidence.as_ref() {
        validate_worker_evidence_shape(worker_evidence)?;
    }
    Ok(())
}

pub fn validate_provider_registry(registry: &ProviderRegistry) -> Result<()> {
    ensure!(
        registry.schema_version == PROVIDER_REGISTRY_SCHEMA,
        "unexpected provider registry schema"
    );
    ensure!(
        valid_token(&registry.registry_id),
        "invalid provider registry id"
    );
    ensure!(!registry.providers.is_empty(), "provider registry is empty");
    ensure!(
        registry.release_decision == ReleaseDecision::NotEvaluated,
        "release must remain unevaluated"
    );
    let mut provider_ids = BTreeSet::new();
    let mut provider_digests = BTreeSet::new();
    for provider in &registry.providers {
        validate_provider(provider)?;
        ensure!(
            provider_ids.insert(&provider.provider_id),
            "duplicate provider id"
        );
        ensure!(
            provider_digests.insert(&provider.provider_digest),
            "duplicate provider digest"
        );
    }
    Ok(())
}

fn validate_provider(provider: &ProviderRecord) -> Result<()> {
    ensure!(valid_token(&provider.provider_id), "invalid provider id");
    ensure!(
        valid_token(&provider.worker_id),
        "invalid provider worker id"
    );
    ensure!(
        valid_token(&provider.service_id),
        "invalid provider service id"
    );
    ensure!(
        is_lower_hex(&provider.provider_digest, 32),
        "invalid provider digest"
    );
    ensure!(
        is_lower_hex(&provider.worker_attestation_digest, 32),
        "invalid worker attestation digest"
    );
    Ok(())
}

fn validate_link(link: &crate::model::ResultLink) -> Result<()> {
    ensure!(valid_token(&link.link_id), "invalid result link id");
    ensure!(is_lower_hex(&link.digest, 32), "invalid result link digest");
    Ok(())
}

fn validate_signature_shape(signature: &EnvelopeSignature) -> Result<()> {
    ensure!(
        signature.algorithm == crate::model::SignatureAlgorithm::Ed25519,
        "unsupported signature algorithm"
    );
    ensure!(
        is_lower_hex(&signature.public_key_hex, 32),
        "invalid public key"
    );
    ensure!(
        is_lower_hex(&signature.signature_hex, 64),
        "invalid signature"
    );
    ensure!(
        is_lower_hex(&signature.signature_digest, 32),
        "invalid signature digest"
    );
    ensure!(
        signature_digest(&signature.signature_hex)? == signature.signature_digest,
        "signature digest mismatch"
    );
    Ok(())
}

fn validate_worker_evidence_shape(evidence: &WorkerEvidence) -> Result<()> {
    ensure!(
        evidence.kind == WorkerEvidenceKind::NativeRemoteWorker,
        "unsupported worker evidence kind"
    );
    ensure!(
        valid_token(&evidence.worker_id),
        "invalid worker evidence id"
    );
    ensure!(
        valid_token(&evidence.worker_run_id),
        "invalid worker run id"
    );
    ensure!(
        is_lower_hex(&evidence.attestation_digest, 32),
        "invalid attestation digest"
    );
    ensure!(
        is_lower_hex(&evidence.evidence_digest, 32),
        "invalid worker evidence digest"
    );
    Ok(())
}

fn verify_signature(envelope: &ResultEnvelope, signature: &EnvelopeSignature) -> Result<()> {
    verify_ed25519(
        &signature.public_key_hex,
        &envelope.signature_message()?,
        &signature.signature_hex,
    )
}

fn valid_token(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 {
        return false;
    }
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn verified(envelope_id: String) -> VerificationDecision {
    VerificationDecision {
        status: VerificationStatus::Verified,
        reason: None,
        envelope_id,
    }
}

fn rejected(envelope_id: String, reason: VerificationReason) -> VerificationDecision {
    VerificationDecision {
        status: VerificationStatus::Rejected,
        reason: Some(reason),
        envelope_id,
    }
}

fn not_evaluated(envelope_id: String, reason: VerificationReason) -> VerificationDecision {
    VerificationDecision {
        status: VerificationStatus::NotEvaluated,
        reason: Some(reason),
        envelope_id,
    }
}

#[cfg(test)]
mod tests {
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::{
        AdoptionError, FederationResultConsumer, ResultVerifier, VerificationContext,
        VerificationReason, VerificationStatus,
    };
    use crate::digest::sha256_hex;
    use crate::model::{
        EnvelopeSignature, PROVIDER_REGISTRY_SCHEMA, ProviderRecord, ProviderRegistry,
        ProviderStatus, RESULT_ENVELOPE_SCHEMA, ReleaseDecision, RemoteWorkerBinding,
        ResultEnvelope, ResultLink, ResultOrigin, ResultRoots, VerificationLink, VerificationState,
        WorkerEvidence, WorkerEvidenceKind,
    };

    const PROJECT: &str = "project.test";
    const MISSION: &str = "mission.test";
    const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PROVIDER_DIGEST: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const ATTESTATION_DIGEST: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";

    fn registry(status: ProviderStatus, verifier_available: bool) -> ProviderRegistry {
        ProviderRegistry {
            schema_version: PROVIDER_REGISTRY_SCHEMA.into(),
            registry_id: "registry.test".into(),
            native_worker_verifier_available: verifier_available,
            providers: vec![ProviderRecord {
                provider_id: "provider.test".into(),
                worker_id: "worker.test".into(),
                service_id: "service.test".into(),
                provider_digest: PROVIDER_DIGEST.into(),
                worker_attestation_digest: ATTESTATION_DIGEST.into(),
                status,
            }],
            release_decision: ReleaseDecision::NotEvaluated,
        }
    }

    fn envelope(with_signature: bool, with_worker: bool) -> ResultEnvelope {
        let mut envelope = ResultEnvelope {
            schema_version: RESULT_ENVELOPE_SCHEMA.into(),
            envelope_id: "result.test.1".into(),
            origin: ResultOrigin {
                project_id: PROJECT.into(),
                mission_id: MISSION.into(),
                turn: 1,
            },
            remote_worker: RemoteWorkerBinding {
                worker_id: "worker.test".into(),
                service_id: "service.test".into(),
                provider_digest: PROVIDER_DIGEST.into(),
            },
            roots: ResultRoots {
                input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                output: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                evidence: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            },
            sequence: 1,
            replay_nonce: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
            effect_receipt: ResultLink {
                link_id: "receipt.test".into(),
                digest: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into(),
            },
            verification: VerificationLink {
                link_id: "verification.test".into(),
                digest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
                state: VerificationState::Verified,
            },
            outcome: ResultLink {
                link_id: "outcome.test".into(),
                digest: "9999999999999999999999999999999999999999999999999999999999999999".into(),
            },
            current_commit: COMMIT.into(),
            envelope_digest: String::new(),
            signature: None,
            worker_evidence: with_worker.then(|| WorkerEvidence {
                kind: WorkerEvidenceKind::NativeRemoteWorker,
                worker_id: "worker.test".into(),
                worker_run_id: "worker-run.test".into(),
                attestation_digest: ATTESTATION_DIGEST.into(),
                evidence_digest: "1212121212121212121212121212121212121212121212121212121212121212"
                    .into(),
            }),
        };
        envelope.envelope_digest = envelope.computed_envelope_digest().expect("digest");
        if with_signature {
            let signer = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).expect("signer");
            let signature = signer.sign(&envelope.signature_message().expect("message"));
            let signature_hex = hex::encode(signature.as_ref());
            envelope.signature = Some(EnvelopeSignature {
                algorithm: crate::model::SignatureAlgorithm::Ed25519,
                public_key_hex: hex::encode(signer.public_key().as_ref()),
                signature_digest: sha256_hex(signature.as_ref()),
                signature_hex,
            });
        }
        envelope
    }

    fn make_verifier(status: ProviderStatus, worker_verifier: bool) -> ResultVerifier {
        ResultVerifier::new(VerificationContext::new(
            PROJECT,
            MISSION,
            COMMIT,
            registry(status, worker_verifier),
            worker_verifier,
        ))
    }

    #[test]
    fn missing_signature_is_not_evaluated_and_cannot_be_adopted() {
        let envelope = envelope(false, true);
        let mut verifier = make_verifier(ProviderStatus::Active, true);
        let decision = verifier.verify(&envelope);
        assert_eq!(decision.status(), VerificationStatus::NotEvaluated);
        assert_eq!(
            decision.reason(),
            Some(VerificationReason::MissingSignature)
        );
        assert_eq!(
            FederationResultConsumer::adopt(&envelope, &decision),
            Err(AdoptionError::ResultNotVerified)
        );
    }

    #[test]
    fn missing_real_worker_is_not_evaluated() {
        let envelope = envelope(true, false);
        let mut verifier = make_verifier(ProviderStatus::Active, true);
        let decision = verifier.verify(&envelope);
        assert_eq!(decision.status(), VerificationStatus::NotEvaluated);
        assert_eq!(
            decision.reason(),
            Some(VerificationReason::RealWorkerUnavailable)
        );
    }

    #[test]
    fn tamper_is_rejected_before_adoption() {
        let mut envelope = envelope(true, true);
        envelope.roots.output =
            "abababababababababababababababababababababababababababababababab".into();
        let mut verifier = make_verifier(ProviderStatus::Active, true);
        let decision = verifier.verify(&envelope);
        assert_eq!(decision.status(), VerificationStatus::Rejected);
        assert_eq!(
            decision.reason(),
            Some(VerificationReason::TamperedEnvelope)
        );
        assert_eq!(
            FederationResultConsumer::adopt(&envelope, &decision),
            Err(AdoptionError::ResultNotVerified)
        );
    }

    #[test]
    fn replay_nonce_and_sequence_gap_fail_closed() {
        let first = envelope(true, true);
        let mut verifier = make_verifier(ProviderStatus::Active, true);
        let first_decision = verifier.verify(&first);
        assert_eq!(first_decision.status(), VerificationStatus::Verified);
        let replay_decision = verifier.verify(&first);
        assert_eq!(
            replay_decision.reason(),
            Some(VerificationReason::ReplayNonce)
        );

        let mut gap = envelope(true, true);
        gap.envelope_id = "result.test.3".into();
        gap.sequence = 3;
        gap.replay_nonce =
            "1313131313131313131313131313131313131313131313131313131313131313".into();
        gap.envelope_digest = gap.computed_envelope_digest().expect("digest");
        let signer = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).expect("signer");
        let signature = signer.sign(&gap.signature_message().expect("message"));
        gap.signature = Some(EnvelopeSignature {
            algorithm: crate::model::SignatureAlgorithm::Ed25519,
            public_key_hex: hex::encode(signer.public_key().as_ref()),
            signature_digest: sha256_hex(signature.as_ref()),
            signature_hex: hex::encode(signature.as_ref()),
        });
        let gap_decision = verifier.verify(&gap);
        assert_eq!(gap_decision.reason(), Some(VerificationReason::SequenceGap));
    }

    #[test]
    fn cross_mission_and_revoked_provider_fail_closed() {
        let mut cross_mission = envelope(true, true);
        cross_mission.origin.mission_id = "mission.other".into();
        let mut verifier = make_verifier(ProviderStatus::Active, true);
        let decision = verifier.verify(&cross_mission);
        assert_eq!(decision.reason(), Some(VerificationReason::CrossMission));

        let revoked = envelope(true, true);
        let mut revoked_verifier = make_verifier(ProviderStatus::Revoked, true);
        let revoked_decision = revoked_verifier.verify(&revoked);
        assert_eq!(
            revoked_decision.reason(),
            Some(VerificationReason::RevokedProvider)
        );
    }

    #[test]
    fn only_verified_result_can_be_adopted() {
        let envelope = envelope(true, true);
        let mut verifier = make_verifier(ProviderStatus::Active, true);
        let decision = verifier.verify(&envelope);
        let adopted = FederationResultConsumer::adopt(&envelope, &decision).expect("adopt");
        assert_eq!(adopted.envelope_id, envelope.envelope_id);
        assert_eq!(adopted.mission_id, MISSION);
        assert_eq!(adopted.output_root, envelope.roots.output);
    }

    #[test]
    fn unavailable_native_verifier_stays_not_evaluated() {
        let envelope = envelope(true, true);
        let mut verifier = make_verifier(ProviderStatus::Active, false);
        let decision = verifier.verify(&envelope);
        assert_eq!(decision.status(), VerificationStatus::NotEvaluated);
        assert_eq!(
            decision.reason(),
            Some(VerificationReason::WorkerVerifierUnavailable)
        );
    }
}
