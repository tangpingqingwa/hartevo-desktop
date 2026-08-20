//! Synthetic and recorded provider seams for `OpenAI` Moderation.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::{
    OPENAI_MODERATION_API_HOST, OPENAI_MODERATION_API_PATH, OPENAI_MODERATION_RESULT_PROVIDER_ID,
    digest_serializable,
    model::{
        AuthorityClaims, BlockedEnvCode, CategoryOutcome, Digest, MAX_CATEGORIES,
        MAX_RECORDING_ID_BYTES, MAX_RESPONSE_BYTES, ModelSnapshot, ModerationCategory,
        ModerationInput, ModerationPolicy, ModerationStatus, OpenAiModerationError,
        OpenAiModerationProposal, ProviderFailureKind, ProviderFailureProjection, ProviderMode,
        ResponseId, ScoreProjection,
    },
};

/// Safe payload produced while parsing a fixture or recording. No provider
/// JSON, prompt, image, URL, or credential is retained.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ModerationPayload {
    model_id: String,
    response_id_digest: Option<Digest>,
    flagged: bool,
    categories: Vec<CategoryOutcome>,
}

impl ModerationPayload {
    pub fn new(
        model_id: impl Into<String>,
        response_id: Option<ResponseId>,
        flagged: bool,
        categories: Vec<CategoryOutcome>,
    ) -> Result<Self, OpenAiModerationError> {
        let model_id = model_id.into();
        if model_id.trim().is_empty()
            || model_id.len() > crate::model::MAX_MODEL_BYTES
            || model_id.chars().any(char::is_control)
        {
            return Err(OpenAiModerationError::InvalidField {
                field: "provider_model",
                reason: "must be a bounded provider model",
            });
        }
        validate_category_outcomes(&categories)?;
        Ok(Self {
            model_id,
            response_id_digest: response_id.map(|value| value.digest()),
            flagged,
            categories,
        })
    }

    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub fn response_id_digest(&self) -> Option<&Digest> {
        self.response_id_digest.as_ref()
    }

    pub const fn flagged(&self) -> bool {
        self.flagged
    }

    pub fn categories(&self) -> &[CategoryOutcome] {
        &self.categories
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum ModerationFrameOutcome {
    Success(ModerationPayload),
    HttpStatus(u16),
    Timeout,
    ProviderUnknown,
    BlockedEnv(BlockedEnvCode),
    Malformed,
    Partial,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecordedModerationFrame {
    recording_id: String,
    provider_id: String,
    model_id: String,
    input_digest: Digest,
    latency_ms: u64,
    outcome: ModerationFrameOutcome,
    frame_digest: Digest,
}

impl RecordedModerationFrame {
    pub fn new(
        recording_id: impl Into<String>,
        model_id: impl Into<String>,
        input_digest: Digest,
        outcome: ModerationFrameOutcome,
    ) -> Result<Self, OpenAiModerationError> {
        let recording_id = recording_id.into();
        let model_id = model_id.into();
        if recording_id.trim().is_empty()
            || recording_id.len() > MAX_RECORDING_ID_BYTES
            || recording_id.chars().any(char::is_control)
        {
            return Err(OpenAiModerationError::InvalidField {
                field: "recording_id",
                reason: "must be a bounded non-empty recording identifier",
            });
        }
        if !input_digest.is_sha256() {
            return Err(OpenAiModerationError::InvalidField {
                field: "input_digest",
                reason: "must be a SHA-256 digest",
            });
        }
        let mut frame = Self {
            recording_id,
            provider_id: OPENAI_MODERATION_RESULT_PROVIDER_ID.to_owned(),
            model_id,
            input_digest,
            latency_ms: 0,
            outcome,
            frame_digest: Digest::sha256([]),
        };
        frame.frame_digest = frame.compute_digest();
        Ok(frame)
    }

    pub fn success(
        recording_id: impl Into<String>,
        model_id: impl Into<String>,
        input_digest: Digest,
        response_id: Option<ResponseId>,
        flagged: bool,
        categories: Vec<CategoryOutcome>,
    ) -> Result<Self, OpenAiModerationError> {
        let payload = ModerationPayload::new(model_id, response_id, flagged, categories)?;
        Self::new(
            recording_id,
            payload.model_id().to_owned(),
            input_digest,
            ModerationFrameOutcome::Success(payload),
        )
    }

    pub fn from_json(
        recording_id: impl Into<String>,
        input_digest: Digest,
        body: &[u8],
    ) -> Result<Self, OpenAiModerationError> {
        if body.is_empty() || body.len() > MAX_RESPONSE_BYTES {
            return Err(OpenAiModerationError::ResponseTooLarge);
        }
        let root: Value = serde_json::from_slice(body)
            .map_err(|_| OpenAiModerationError::MalformedProviderResponse)?;
        let object = root
            .as_object()
            .ok_or(OpenAiModerationError::MalformedProviderResponse)?;
        let model_id = required_string(object, "model")?;
        let response_id = ResponseId::new(required_string(object, "id")?)?;
        let results = object
            .get("results")
            .and_then(Value::as_array)
            .ok_or(OpenAiModerationError::MalformedProviderResponse)?;
        if results.len() != 1 {
            return Err(OpenAiModerationError::PartialProviderResponse);
        }
        let result = results[0]
            .as_object()
            .ok_or(OpenAiModerationError::MalformedProviderResponse)?;
        let flagged = result
            .get("flagged")
            .and_then(Value::as_bool)
            .ok_or(OpenAiModerationError::MalformedProviderResponse)?;
        let categories = parse_category_object(result, "categories", false)?;
        let scores = parse_category_object(result, "category_scores", true)?;
        if categories.len() != scores.len()
            || categories.iter().any(|outcome| {
                !scores
                    .iter()
                    .any(|score| score.category() == outcome.category())
            })
        {
            return Err(OpenAiModerationError::PartialProviderResponse);
        }
        let scores: std::collections::BTreeMap<_, _> = scores
            .into_iter()
            .filter_map(|outcome| outcome.score().map(|score| (outcome.category(), score)))
            .collect();
        let categories = categories
            .into_iter()
            .map(|outcome| {
                CategoryOutcome::new(
                    outcome.category(),
                    outcome.flagged(),
                    scores.get(&outcome.category()).copied(),
                )
            })
            .collect();
        let payload =
            ModerationPayload::new(model_id.clone(), Some(response_id), flagged, categories)?;
        Self::new(
            recording_id,
            model_id,
            input_digest,
            ModerationFrameOutcome::Success(payload),
        )
    }

    pub fn http_status(
        recording_id: impl Into<String>,
        model_id: impl Into<String>,
        input_digest: Digest,
        status: u16,
    ) -> Result<Self, OpenAiModerationError> {
        Self::new(
            recording_id,
            model_id,
            input_digest,
            ModerationFrameOutcome::HttpStatus(status),
        )
    }

    pub fn timeout(
        recording_id: impl Into<String>,
        model_id: impl Into<String>,
        input_digest: Digest,
    ) -> Result<Self, OpenAiModerationError> {
        Self::new(
            recording_id,
            model_id,
            input_digest,
            ModerationFrameOutcome::Timeout,
        )
    }

    pub fn provider_unknown(
        recording_id: impl Into<String>,
        model_id: impl Into<String>,
        input_digest: Digest,
    ) -> Result<Self, OpenAiModerationError> {
        Self::new(
            recording_id,
            model_id,
            input_digest,
            ModerationFrameOutcome::ProviderUnknown,
        )
    }

    pub fn blocked_env(
        recording_id: impl Into<String>,
        model_id: impl Into<String>,
        input_digest: Digest,
        code: BlockedEnvCode,
    ) -> Result<Self, OpenAiModerationError> {
        Self::new(
            recording_id,
            model_id,
            input_digest,
            ModerationFrameOutcome::BlockedEnv(code),
        )
    }

    pub fn malformed(
        recording_id: impl Into<String>,
        model_id: impl Into<String>,
        input_digest: Digest,
    ) -> Result<Self, OpenAiModerationError> {
        Self::new(
            recording_id,
            model_id,
            input_digest,
            ModerationFrameOutcome::Malformed,
        )
    }

    pub fn partial(
        recording_id: impl Into<String>,
        model_id: impl Into<String>,
        input_digest: Digest,
    ) -> Result<Self, OpenAiModerationError> {
        Self::new(
            recording_id,
            model_id,
            input_digest,
            ModerationFrameOutcome::Partial,
        )
    }

    #[must_use]
    pub fn with_latency_ms(mut self, latency_ms: u64) -> Self {
        self.latency_ms = latency_ms;
        self.frame_digest = self.compute_digest();
        self
    }

    fn compute_digest(&self) -> Digest {
        digest_serializable(&(
            "hartevo:openai-moderation-frame:v1",
            &self.recording_id,
            &self.provider_id,
            &self.model_id,
            &self.input_digest,
            self.latency_ms,
            &self.outcome,
        ))
    }

    pub fn recording_id(&self) -> &str {
        &self.recording_id
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub fn input_digest(&self) -> &Digest {
        &self.input_digest
    }

    pub const fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    pub fn outcome(&self) -> &ModerationFrameOutcome {
        &self.outcome
    }

    pub fn frame_digest(&self) -> &Digest {
        &self.frame_digest
    }
}

fn validate_category_outcomes(categories: &[CategoryOutcome]) -> Result<(), OpenAiModerationError> {
    if categories.is_empty() || categories.len() > MAX_CATEGORIES {
        return Err(OpenAiModerationError::PartialProviderResponse);
    }
    let mut seen = BTreeSet::new();
    for outcome in categories {
        if !seen.insert(outcome.category()) {
            return Err(OpenAiModerationError::MalformedProviderResponse);
        }
    }
    Ok(())
}

fn required_string(
    object: &Map<String, Value>,
    field: &str,
) -> Result<String, OpenAiModerationError> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(OpenAiModerationError::MalformedProviderResponse)?;
    if value.trim().is_empty() || value.len() > crate::model::MAX_MODEL_BYTES {
        return Err(OpenAiModerationError::MalformedProviderResponse);
    }
    Ok(value.to_owned())
}

fn parse_category_object(
    result: &Map<String, Value>,
    field: &str,
    scores: bool,
) -> Result<Vec<CategoryOutcome>, OpenAiModerationError> {
    let object = result
        .get(field)
        .and_then(Value::as_object)
        .ok_or(OpenAiModerationError::MalformedProviderResponse)?;
    if object.is_empty() || object.len() > MAX_CATEGORIES {
        return Err(OpenAiModerationError::PartialProviderResponse);
    }
    let mut outcomes = Vec::with_capacity(object.len());
    for (name, value) in object {
        let category = ModerationCategory::from_wire(name)
            .ok_or(OpenAiModerationError::MalformedProviderResponse)?;
        if scores {
            let score = value
                .as_f64()
                .ok_or(OpenAiModerationError::MalformedProviderResponse)?;
            outcomes.push(CategoryOutcome::new(
                category,
                false,
                Some(ScoreProjection::from_probability(score)?),
            ));
        } else {
            let flagged = value
                .as_bool()
                .ok_or(OpenAiModerationError::MalformedProviderResponse)?;
            outcomes.push(CategoryOutcome::new(category, flagged, None));
        }
    }
    outcomes.sort_by_key(CategoryOutcome::category);
    Ok(outcomes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAiModerationProviderRead {
    status: ModerationStatus,
    flagged: Option<bool>,
    categories: Vec<CategoryOutcome>,
    response_id_digest: Option<Digest>,
    failure: Option<ProviderFailureProjection>,
    latency_ms: u64,
    frame_digest: Digest,
}

impl OpenAiModerationProviderRead {
    pub const fn status(&self) -> ModerationStatus {
        self.status
    }

    pub const fn flagged(&self) -> Option<bool> {
        self.flagged
    }

    pub fn categories(&self) -> &[CategoryOutcome] {
        &self.categories
    }

    pub fn response_id_digest(&self) -> Option<&Digest> {
        self.response_id_digest.as_ref()
    }

    pub const fn failure(&self) -> Option<ProviderFailureProjection> {
        self.failure
    }

    pub const fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    pub fn frame_digest(&self) -> &Digest {
        &self.frame_digest
    }
}

/// Layer-1 provider adapter. Every available mode is synthetic or replayed;
/// there is intentionally no native mode and no network transport.
#[derive(Clone, Debug)]
pub struct OpenAiModerationProvider {
    mode: ProviderMode,
    response_bound: usize,
}

impl OpenAiModerationProvider {
    pub fn new(mode: ProviderMode) -> Self {
        Self {
            mode,
            response_bound: MAX_RESPONSE_BYTES,
        }
    }

    pub fn fixture() -> Self {
        Self::new(ProviderMode::Fixture)
    }

    pub fn recording() -> Self {
        Self::new(ProviderMode::Recording)
    }

    pub fn loopback() -> Self {
        Self::new(ProviderMode::Loopback)
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderMode::BlockedEnv)
    }

    pub fn with_response_bound(
        mut self,
        response_bound: usize,
    ) -> Result<Self, OpenAiModerationError> {
        if response_bound == 0 || response_bound > MAX_RESPONSE_BYTES {
            return Err(OpenAiModerationError::InvalidField {
                field: "response_bound",
                reason: "must be within the Layer-1 response bound",
            });
        }
        self.response_bound = response_bound;
        Ok(self)
    }

    pub const fn mode(&self) -> ProviderMode {
        self.mode
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }

    pub fn authority(&self) -> AuthorityClaims {
        AuthorityClaims::layer_one()
    }

    pub fn provider_digest(&self) -> Digest {
        digest_serializable(&(
            "hartevo:openai-moderation-provider:v1",
            OPENAI_MODERATION_RESULT_PROVIDER_ID,
            OPENAI_MODERATION_API_HOST,
            OPENAI_MODERATION_API_PATH,
            self.mode,
            self.response_bound,
            self.authority(),
        ))
    }

    pub fn evidence_binding_digest(&self) -> Digest {
        digest_serializable(&(
            "hartevo:openai-moderation-evidence-mode:v1",
            self.mode,
            self.response_bound,
            self.authority(),
        ))
    }

    pub fn read(
        &self,
        proposal: &OpenAiModerationProposal,
        frame: &RecordedModerationFrame,
        model: &ModelSnapshot,
        policy: &ModerationPolicy,
    ) -> Result<OpenAiModerationProviderRead, OpenAiModerationError> {
        proposal.verify_integrity()?;
        policy.validate()?;
        if frame.provider_id() != OPENAI_MODERATION_RESULT_PROVIDER_ID
            || frame.input_digest() != proposal.input_digest()
            || !model.matches_provider_model(frame.model_id())
        {
            return Err(OpenAiModerationError::ProviderIdentityMismatch);
        }
        match frame.outcome() {
            ModerationFrameOutcome::Success(payload) => {
                if !model.matches_provider_model(payload.model_id()) {
                    return Err(OpenAiModerationError::ProviderIdentityMismatch);
                }
                let mut categories = Vec::new();
                for outcome in payload.categories() {
                    if policy.categories().contains(outcome.category()) {
                        let score = match policy.redaction().score_retention() {
                            crate::model::ScoreRetention::None => None,
                            crate::model::ScoreRetention::BasisPoints => outcome.score(),
                        };
                        categories.push(CategoryOutcome::new(
                            outcome.category(),
                            if policy.redaction().retain_flags() {
                                outcome.flagged()
                            } else {
                                false
                            },
                            score,
                        ));
                    }
                }
                let present: BTreeSet<_> =
                    categories.iter().map(CategoryOutcome::category).collect();
                if policy
                    .categories()
                    .categories()
                    .iter()
                    .any(|category| !present.contains(category))
                {
                    return Err(OpenAiModerationError::PartialProviderResponse);
                }
                Ok(OpenAiModerationProviderRead {
                    status: ModerationStatus::Completed,
                    flagged: Some(payload.flagged()),
                    categories,
                    response_id_digest: payload.response_id_digest().cloned(),
                    failure: None,
                    latency_ms: frame.latency_ms(),
                    frame_digest: frame.frame_digest().clone(),
                })
            }
            ModerationFrameOutcome::HttpStatus(status) => {
                let (status_kind, failure) = status_projection(*status);
                Ok(OpenAiModerationProviderRead {
                    status: status_kind,
                    flagged: None,
                    categories: Vec::new(),
                    response_id_digest: None,
                    failure: Some(failure),
                    latency_ms: frame.latency_ms(),
                    frame_digest: frame.frame_digest().clone(),
                })
            }
            ModerationFrameOutcome::Timeout => Ok(failed_read(
                ModerationStatus::Timeout,
                ProviderFailureProjection::new(ProviderFailureKind::Timeout, None),
                frame,
            )),
            ModerationFrameOutcome::ProviderUnknown => Ok(failed_read(
                ModerationStatus::ProviderUnknown,
                ProviderFailureProjection::new(ProviderFailureKind::ProviderUnknown, None),
                frame,
            )),
            ModerationFrameOutcome::BlockedEnv(code) => Ok(failed_read(
                ModerationStatus::BlockedEnv,
                ProviderFailureProjection::new(ProviderFailureKind::BlockedEnv, None),
                frame,
            )
            .with_blocked_code(*code)),
            ModerationFrameOutcome::Malformed => Ok(failed_read(
                ModerationStatus::Malformed,
                ProviderFailureProjection::new(ProviderFailureKind::Malformed, None),
                frame,
            )),
            ModerationFrameOutcome::Partial => Ok(failed_read(
                ModerationStatus::Partial,
                ProviderFailureProjection::new(ProviderFailureKind::Partial, None),
                frame,
            )),
        }
    }

    pub fn read_moderation(
        &self,
        proposal: &OpenAiModerationProposal,
        frame: &RecordedModerationFrame,
        model: &ModelSnapshot,
        policy: &ModerationPolicy,
    ) -> Result<OpenAiModerationProviderRead, OpenAiModerationError> {
        self.read(proposal, frame, model, policy)
    }

    pub fn execute_native(
        &self,
        _input: &ModerationInput,
    ) -> Result<RecordedModerationFrame, OpenAiModerationError> {
        Err(OpenAiModerationError::NativeExecutionUnavailable)
    }
}

fn failed_read(
    status: ModerationStatus,
    failure: ProviderFailureProjection,
    frame: &RecordedModerationFrame,
) -> OpenAiModerationProviderRead {
    OpenAiModerationProviderRead {
        status,
        flagged: None,
        categories: Vec::new(),
        response_id_digest: None,
        failure: Some(failure),
        latency_ms: frame.latency_ms(),
        frame_digest: frame.frame_digest().clone(),
    }
}

trait BlockedCodeExt {
    fn with_blocked_code(self, _code: BlockedEnvCode) -> Self;
}

impl BlockedCodeExt for OpenAiModerationProviderRead {
    fn with_blocked_code(self, _code: BlockedEnvCode) -> Self {
        self
    }
}

fn status_projection(status: u16) -> (ModerationStatus, ProviderFailureProjection) {
    match status {
        401 => (
            ModerationStatus::Unauthorized,
            ProviderFailureProjection::new(ProviderFailureKind::Unauthorized, Some(status)),
        ),
        403 => (
            ModerationStatus::Forbidden,
            ProviderFailureProjection::new(ProviderFailureKind::Forbidden, Some(status)),
        ),
        413 => (
            ModerationStatus::PayloadTooLarge,
            ProviderFailureProjection::new(ProviderFailureKind::PayloadTooLarge, Some(status)),
        ),
        429 => (
            ModerationStatus::RateLimited,
            ProviderFailureProjection::new(ProviderFailureKind::RateLimited, Some(status)),
        ),
        500..=599 => (
            ModerationStatus::ServerError,
            ProviderFailureProjection::new(ProviderFailureKind::ServerError, Some(status)),
        ),
        _ => (
            ModerationStatus::ProviderUnknown,
            ProviderFailureProjection::new(ProviderFailureKind::ProviderUnknown, Some(status)),
        ),
    }
}
