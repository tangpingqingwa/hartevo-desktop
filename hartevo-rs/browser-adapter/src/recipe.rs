use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{
    BrowserProfileId, BrowserRecipeId, BrowserWorkspaceId, Effect, EffectClass, EffectStatus,
    MissionId, ProjectId, TenantId,
};
use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::workspace::{digest, digest_json, is_bounded_identifier, is_sha256};
use crate::{
    BrowserAction, BrowserActionBatch, BrowserActionKind, BrowserActionRisk, BrowserActionSurface,
    BrowserError, BrowserLocatorResolution, BrowserProfile, BrowserWorkspace,
};

#[path = "recipe_authority.rs"]
mod recipe_authority;

const RECIPE_SCHEMA_VERSION: u32 = 1;
const RECIPE_KEY_SCHEMA_VERSION: u32 = 1;
const RECIPE_PROMOTION_SCHEMA_VERSION: u32 = 1;
const RECIPE_ACTIVATION_SCHEMA_VERSION: u32 = 1;
const RECIPE_PLAN_SCHEMA_VERSION: u32 = 1;
const RECIPE_TRUST_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const RECIPE_REGISTRY_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const MAX_RECIPE_STEPS: usize = 32;
const MAX_RECIPE_LIFETIME: Duration = Duration::days(366);
const MAX_PREPARED_PLAN_LIFETIME: Duration = Duration::minutes(15);
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserRecipeKeyPurpose {
    CandidatePublisher,
    ProductionRelease,
}

/// Public, secret-free key role emitted by supplied Recipe authority snapshot
/// validation. It is persistence metadata, not lifecycle admission or dispatch
/// authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserRecipeAuthorityKeyPurpose {
    RootAuthority,
    CandidatePublisher,
    ProductionRelease,
}

/// The permanent blocking fact represented by a durable authority tombstone.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserRecipeAuthorityBlockKind {
    Revoked,
    Compromised,
}

/// Exact active root identity observed after replaying a supplied public
/// authority snapshot. No private root material is present.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserRecipeAuthorityRootHead {
    pub key_id: String,
    pub public_key_digest: String,
    pub generation: u64,
    pub revision: u64,
    pub lineage_digest: String,
}

/// Append-only blocking fact derived from a signed lifecycle mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserRecipeAuthorityTombstone {
    pub key_id: String,
    pub purpose: BrowserRecipeAuthorityKeyPurpose,
    pub public_key_digest: String,
    pub blocked_revision: u64,
    pub lineage_digest: String,
    pub kind: BrowserRecipeAuthorityBlockKind,
    pub effective_at: DateTime<Utc>,
}

/// Secret-free result of validating one exact supplied public authority
/// snapshot. The two false flags are intentional: persistence must not turn a
/// caller-supplied snapshot into current authority or a dispatch permit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserRecipeAuthorityObservation {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub snapshot_revision: u64,
    pub snapshot_as_of: DateTime<Utc>,
    pub validation_at: DateTime<Utc>,
    pub snapshot_digest: String,
    pub state_digest: String,
    pub rotation_epoch: u64,
    pub active_root: Option<BrowserRecipeAuthorityRootHead>,
    pub tombstones: Vec<BrowserRecipeAuthorityTombstone>,
    pub snapshot_freshness_authority: bool,
    pub production_dispatch: bool,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedBrowserRecipeKey {
    pub schema_version: u32,
    pub id: String,
    pub purpose: BrowserRecipeKeyPurpose,
    pub public_key_hex: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revision: u64,
}

impl TrustedBrowserRecipeKey {
    pub fn new(
        id: impl Into<String>,
        purpose: BrowserRecipeKeyPurpose,
        public_key: &[u8],
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let key = Self {
            schema_version: RECIPE_KEY_SCHEMA_VERSION,
            id: id.into(),
            purpose,
            public_key_hex: hex::encode(public_key),
            valid_from,
            valid_until,
            revoked_at: None,
            revision: 1,
        };
        key.validate_shape()?;
        Ok(key)
    }

    pub fn revoke(
        &mut self,
        expected_revision: u64,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.revision != expected_revision {
            return Err(BrowserError::RevisionMismatch {
                expected: expected_revision,
                actual: self.revision,
            });
        }
        if self.revoked_at.is_some()
            || revoked_at < self.valid_from
            || revoked_at >= self.valid_until
        {
            return Err(BrowserError::InvalidRecipeKey);
        }
        self.revoked_at = Some(revoked_at);
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        self.validate_shape()
    }

    fn verify(
        &self,
        expected_purpose: BrowserRecipeKeyPurpose,
        authored_at: DateTime<Utc>,
        now: DateTime<Utc>,
        payload: &[u8],
        signature_hex: &str,
    ) -> Result<(), BrowserError> {
        self.validate_shape()?;
        if self.purpose != expected_purpose
            || authored_at < self.valid_from
            || authored_at >= self.valid_until
            || now < authored_at
            || now >= self.valid_until
        {
            return Err(BrowserError::InvalidRecipeKey);
        }
        if self.revoked_at.is_some_and(|revoked_at| now >= revoked_at) {
            return Err(BrowserError::RecipeKeyRevoked);
        }
        let public_key =
            hex::decode(&self.public_key_hex).map_err(|_| BrowserError::InvalidRecipeKey)?;
        let signature = decode_signature(signature_hex)?;
        UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(payload, &signature)
            .map_err(|_| BrowserError::RecipeSignatureInvalid)
    }

    fn validate_shape(&self) -> Result<(), BrowserError> {
        let public_key =
            hex::decode(&self.public_key_hex).map_err(|_| BrowserError::InvalidRecipeKey)?;
        if self.schema_version != RECIPE_KEY_SCHEMA_VERSION
            || !is_bounded_identifier(&self.id)
            || public_key.len() != ED25519_PUBLIC_KEY_BYTES
            || self.public_key_hex != hex::encode(public_key)
            || self.valid_until <= self.valid_from
            || self.revision == 0
            || self.revoked_at.is_some_and(|revoked_at| {
                revoked_at < self.valid_from || revoked_at >= self.valid_until
            })
        {
            return Err(BrowserError::InvalidRecipeKey);
        }
        Ok(())
    }
}

impl fmt::Debug for TrustedBrowserRecipeKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedBrowserRecipeKey")
            .field("schema_version", &self.schema_version)
            .field("id", &self.id)
            .field("purpose", &self.purpose)
            .field("public_key_digest", &digest(self.public_key_hex.as_bytes()))
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .field("revoked_at", &self.revoked_at)
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct BrowserRecipeTrustStore {
    keys: BTreeMap<String, TrustedBrowserRecipeKey>,
}

impl BrowserRecipeTrustStore {
    /// Validates one supplied root-authority snapshot against an exact caller
    /// expectation. The checked D-01A contract intentionally has no lifecycle
    /// admission registrations, so production calls currently fail closed even
    /// when the public-key snapshot is otherwise well formed.
    pub fn validate_supplied_root_authority_snapshot(
        snapshot_json: &str,
        expected_tenant_id: &TenantId,
        expected_project_id: &ProjectId,
        expected_snapshot_revision: u64,
        expected_snapshot_as_of: DateTime<Utc>,
        expected_snapshot_digest: &str,
        validation_at: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        recipe_authority::validate_supplied_authority_snapshot_json(
            snapshot_json,
            expected_tenant_id,
            expected_project_id,
            expected_snapshot_revision,
            expected_snapshot_as_of,
            expected_snapshot_digest,
            validation_at,
        )
        .map(|_| ())
        .map_err(|_| BrowserError::InvalidRecipeKey)
    }

    /// Returns secret-free lifecycle metadata only after the same checked
    /// admission path used above succeeds. The baseline registration set is
    /// empty, so this currently fails closed before Storage can write.
    pub fn validate_supplied_root_authority_snapshot_for_persistence(
        snapshot_json: &str,
        expected_tenant_id: &TenantId,
        expected_project_id: &ProjectId,
        expected_snapshot_revision: u64,
        expected_snapshot_as_of: DateTime<Utc>,
        expected_snapshot_digest: &str,
        validation_at: DateTime<Utc>,
    ) -> Result<BrowserRecipeAuthorityObservation, BrowserError> {
        recipe_authority::validate_supplied_authority_snapshot_json(
            snapshot_json,
            expected_tenant_id,
            expected_project_id,
            expected_snapshot_revision,
            expected_snapshot_as_of,
            expected_snapshot_digest,
            validation_at,
        )
        .map_err(|_| BrowserError::InvalidRecipeKey)
    }

    pub fn insert(&mut self, key: TrustedBrowserRecipeKey) -> Result<(), BrowserError> {
        key.validate_shape()?;
        match self.keys.get(&key.id) {
            Some(existing) if existing == &key => Ok(()),
            Some(_) => Err(BrowserError::InvalidRecipeKey),
            None => {
                self.keys.insert(key.id.clone(), key);
                Ok(())
            }
        }
    }

    pub fn revoke(
        &mut self,
        key_id: &str,
        expected_revision: u64,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.keys
            .get_mut(key_id)
            .ok_or(BrowserError::RecipeKeyUnavailable)?
            .revoke(expected_revision, revoked_at)
    }

    pub fn trusted_key(&self, key_id: &str) -> Result<&TrustedBrowserRecipeKey, BrowserError> {
        self.keys
            .get(key_id)
            .ok_or(BrowserError::RecipeKeyUnavailable)
    }

    pub fn snapshot(&self) -> BrowserRecipeTrustSnapshot {
        BrowserRecipeTrustSnapshot {
            schema_version: RECIPE_TRUST_SNAPSHOT_SCHEMA_VERSION,
            keys: self.keys.values().cloned().collect(),
        }
    }

    pub fn restore(snapshot: BrowserRecipeTrustSnapshot) -> Result<Self, BrowserError> {
        if snapshot.schema_version != RECIPE_TRUST_SNAPSHOT_SCHEMA_VERSION {
            return Err(BrowserError::InvalidRecipeKey);
        }
        let expected_count = snapshot.keys.len();
        let mut trust = Self::default();
        for key in snapshot.keys {
            trust.insert(key)?;
        }
        if trust.keys.len() != expected_count {
            return Err(BrowserError::InvalidRecipeKey);
        }
        Ok(trust)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserRecipeTrustSnapshot {
    pub schema_version: u32,
    pub keys: Vec<TrustedBrowserRecipeKey>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserRecipeStep {
    pub sequence: u32,
    pub kind: BrowserActionKind,
    pub surface: BrowserActionSurface,
    pub risk: BrowserActionRisk,
    pub selector_digest: String,
}

impl BrowserRecipeStep {
    fn validate(&self) -> Result<(), BrowserError> {
        let supported_shape = matches!(
            (self.kind, self.surface, self.risk),
            (
                BrowserActionKind::Click | BrowserActionKind::KeyboardInput,
                BrowserActionSurface::Semantic,
                BrowserActionRisk::PotentialExternalWrite
            ) | (
                BrowserActionKind::Upload,
                BrowserActionSurface::FileBroker,
                BrowserActionRisk::PotentialExternalWrite
            ) | (
                BrowserActionKind::Verify,
                BrowserActionSurface::Semantic,
                BrowserActionRisk::ReadOnly
            )
        );
        if self.sequence == 0 || !is_sha256(&self.selector_digest) || !supported_shape {
            return Err(BrowserError::InvalidRecipe);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserRecipeManifest {
    pub schema_version: u32,
    pub id: BrowserRecipeId,
    pub version: u32,
    pub provider: String,
    pub origin_digest: String,
    pub capability: String,
    pub effect_class: EffectClass,
    pub steps: Vec<BrowserRecipeStep>,
    pub publisher_key_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl BrowserRecipeManifest {
    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != RECIPE_SCHEMA_VERSION
            || !is_bounded_identifier(self.id.as_str())
            || self.version == 0
            || !is_bounded_identifier(&self.provider)
            || !is_sha256(&self.origin_digest)
            || !is_bounded_identifier(&self.capability)
            || matches!(
                self.effect_class,
                EffectClass::Read | EffectClass::LocalWrite
            )
            || self.steps.is_empty()
            || self.steps.len() > MAX_RECIPE_STEPS
            || !is_bounded_identifier(&self.publisher_key_id)
            || self.expires_at <= self.created_at
            || self.expires_at - self.created_at > MAX_RECIPE_LIFETIME
        {
            return Err(BrowserError::InvalidRecipe);
        }
        let mut contains_write = false;
        for (index, step) in self.steps.iter().enumerate() {
            step.validate()?;
            let expected = u32::try_from(index)
                .map_err(|_| BrowserError::CounterOverflow)?
                .checked_add(1)
                .ok_or(BrowserError::CounterOverflow)?;
            if step.sequence != expected {
                return Err(BrowserError::InvalidRecipe);
            }
            contains_write |= step.risk == BrowserActionRisk::PotentialExternalWrite;
        }
        if !contains_write {
            return Err(BrowserError::InvalidRecipe);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserRecipeCandidate {
    pub manifest: BrowserRecipeManifest,
    pub signature_hex: String,
}

impl BrowserRecipeCandidate {
    pub fn new(
        manifest: BrowserRecipeManifest,
        signature_hex: impl Into<String>,
    ) -> Result<Self, BrowserError> {
        manifest.validate()?;
        let candidate = Self {
            manifest,
            signature_hex: signature_hex.into(),
        };
        decode_signature(&candidate.signature_hex)?;
        Ok(candidate)
    }

    pub fn signing_payload(manifest: &BrowserRecipeManifest) -> Result<Vec<u8>, BrowserError> {
        manifest.validate()?;
        Ok(serde_json::to_vec(&(
            "hartevo-browser-recipe-candidate/v1",
            manifest,
        ))?)
    }

    pub fn verify(
        &self,
        trust: &BrowserRecipeTrustStore,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.manifest.validate()?;
        if now < self.manifest.created_at || now >= self.manifest.expires_at {
            return Err(BrowserError::InvalidRecipe);
        }
        trust.trusted_key(&self.manifest.publisher_key_id)?.verify(
            BrowserRecipeKeyPurpose::CandidatePublisher,
            self.manifest.created_at,
            now,
            &Self::signing_payload(&self.manifest)?,
            &self.signature_hex,
        )
    }

    pub fn digest(&self) -> Result<String, BrowserError> {
        self.manifest.validate()?;
        decode_signature(&self.signature_hex)?;
        digest_json(self)
    }
}

impl fmt::Debug for BrowserRecipeCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserRecipeCandidate")
            .field("manifest", &self.manifest)
            .field("signature_digest", &digest(self.signature_hex.as_bytes()))
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserRecipeEvaluationEvidence {
    pub v1_dataset_revision: String,
    pub v1_result_digest: String,
    pub v1_passed: u32,
    pub v1_total: u32,
    pub v2_dataset_revision: String,
    pub v2_result_digest: String,
    pub v2_passed: u32,
    pub v2_total: u32,
    pub safety_suite_digest: String,
    pub contamination_audit_digest: String,
    pub rollback_strategy_digest: String,
    pub promotion_approval_digest: String,
}

impl BrowserRecipeEvaluationEvidence {
    fn validate(&self) -> Result<(), BrowserError> {
        let v1_gate =
            self.v1_total >= 10 && u64::from(self.v1_passed) * 10 >= u64::from(self.v1_total) * 9;
        let v2_gate =
            self.v2_total >= 5 && u64::from(self.v2_passed) * 5 >= u64::from(self.v2_total) * 4;
        if !is_bounded_identifier(&self.v1_dataset_revision)
            || !is_sha256(&self.v1_result_digest)
            || self.v1_passed > self.v1_total
            || !v1_gate
            || !is_bounded_identifier(&self.v2_dataset_revision)
            || !is_sha256(&self.v2_result_digest)
            || self.v2_passed > self.v2_total
            || !v2_gate
            || !is_sha256(&self.safety_suite_digest)
            || !is_sha256(&self.contamination_audit_digest)
            || !is_sha256(&self.rollback_strategy_digest)
            || !is_sha256(&self.promotion_approval_digest)
        {
            return Err(BrowserError::RecipeEvaluationGateFailed);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserRecipePromotion {
    pub schema_version: u32,
    pub candidate_digest: String,
    pub evidence: BrowserRecipeEvaluationEvidence,
    pub release_key_id: String,
    pub promoted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature_hex: String,
}

impl BrowserRecipePromotion {
    pub fn signing_payload(
        candidate_digest: &str,
        evidence: &BrowserRecipeEvaluationEvidence,
        release_key_id: &str,
        promoted_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Vec<u8>, BrowserError> {
        evidence.validate()?;
        if !is_sha256(candidate_digest)
            || !is_bounded_identifier(release_key_id)
            || expires_at <= promoted_at
        {
            return Err(BrowserError::InvalidRecipePromotion);
        }
        Ok(serde_json::to_vec(&(
            "hartevo-browser-recipe-promotion/v1",
            RECIPE_PROMOTION_SCHEMA_VERSION,
            candidate_digest,
            evidence,
            release_key_id,
            promoted_at,
            expires_at,
        ))?)
    }

    fn validate_for(&self, candidate: &BrowserRecipeCandidate) -> Result<(), BrowserError> {
        candidate.manifest.validate()?;
        self.evidence.validate()?;
        decode_signature(&self.signature_hex)?;
        if self.schema_version != RECIPE_PROMOTION_SCHEMA_VERSION
            || self.candidate_digest != candidate.digest()?
            || !is_bounded_identifier(&self.release_key_id)
            || self.promoted_at < candidate.manifest.created_at
            || self.promoted_at >= candidate.manifest.expires_at
            || self.expires_at <= self.promoted_at
            || self.expires_at > candidate.manifest.expires_at
        {
            return Err(BrowserError::InvalidRecipePromotion);
        }
        Ok(())
    }
}

impl fmt::Debug for BrowserRecipePromotion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserRecipePromotion")
            .field("schema_version", &self.schema_version)
            .field("candidate_digest", &self.candidate_digest)
            .field("evidence", &self.evidence)
            .field("release_key_id", &self.release_key_id)
            .field("promoted_at", &self.promoted_at)
            .field("expires_at", &self.expires_at)
            .field("signature_digest", &digest(self.signature_hex.as_bytes()))
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserRecipeRelease {
    pub candidate: BrowserRecipeCandidate,
    pub promotion: BrowserRecipePromotion,
}

impl BrowserRecipeRelease {
    pub fn verify(
        &self,
        trust: &BrowserRecipeTrustStore,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.candidate.verify(trust, now)?;
        self.promotion.validate_for(&self.candidate)?;
        if now < self.promotion.promoted_at || now >= self.promotion.expires_at {
            return Err(BrowserError::InvalidRecipePromotion);
        }
        let payload = BrowserRecipePromotion::signing_payload(
            &self.promotion.candidate_digest,
            &self.promotion.evidence,
            &self.promotion.release_key_id,
            self.promotion.promoted_at,
            self.promotion.expires_at,
        )?;
        trust.trusted_key(&self.promotion.release_key_id)?.verify(
            BrowserRecipeKeyPurpose::ProductionRelease,
            self.promotion.promoted_at,
            now,
            &payload,
            &self.promotion.signature_hex,
        )
    }

    pub fn digest(&self) -> Result<String, BrowserError> {
        self.promotion.validate_for(&self.candidate)?;
        digest_json(self)
    }
}

impl fmt::Debug for BrowserRecipeRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserRecipeRelease")
            .field("candidate", &self.candidate)
            .field("promotion", &self.promotion)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserRecipeActivation {
    pub schema_version: u32,
    pub recipe_id: BrowserRecipeId,
    pub recipe_version: u32,
    pub release_digest: String,
    pub previous_version: Option<u32>,
    pub activation_evidence_digest: String,
    pub activated_at: DateTime<Utc>,
}

impl BrowserRecipeActivation {
    fn validate_for(&self, release: &BrowserRecipeRelease) -> Result<(), BrowserError> {
        if self.schema_version != RECIPE_ACTIVATION_SCHEMA_VERSION
            || self.recipe_id != release.candidate.manifest.id
            || self.recipe_version != release.candidate.manifest.version
            || self.release_digest != release.digest()?
            || self
                .previous_version
                .is_some_and(|previous| previous >= self.recipe_version)
            || !is_sha256(&self.activation_evidence_digest)
            || self.activated_at < release.promotion.promoted_at
            || self.activated_at >= release.promotion.expires_at
        {
            return Err(BrowserError::RecipeActivationConflict);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, BrowserError> {
        if self.schema_version != RECIPE_ACTIVATION_SCHEMA_VERSION
            || !is_bounded_identifier(self.recipe_id.as_str())
            || self.recipe_version == 0
            || !is_sha256(&self.release_digest)
            || self
                .previous_version
                .is_some_and(|previous| previous >= self.recipe_version)
            || !is_sha256(&self.activation_evidence_digest)
        {
            return Err(BrowserError::RecipeActivationConflict);
        }
        digest_json(self)
    }
}

#[derive(Debug, Default)]
pub struct BrowserRecipeRegistry {
    candidates: BTreeMap<(BrowserRecipeId, u32), BrowserRecipeCandidate>,
    releases: BTreeMap<(BrowserRecipeId, u32), BrowserRecipeRelease>,
    activations: BTreeMap<(BrowserRecipeId, u32), BrowserRecipeActivation>,
    active_versions: BTreeMap<BrowserRecipeId, u32>,
}

impl BrowserRecipeRegistry {
    pub fn register_candidate(
        &mut self,
        candidate: BrowserRecipeCandidate,
        trust: &BrowserRecipeTrustStore,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        candidate.verify(trust, now)?;
        let key = (candidate.manifest.id.clone(), candidate.manifest.version);
        match self.candidates.get(&key) {
            Some(existing) if existing == &candidate => Ok(()),
            Some(_) => Err(BrowserError::RecipeVersionConflict),
            None => {
                self.candidates.insert(key, candidate);
                Ok(())
            }
        }
    }

    pub fn register_release(
        &mut self,
        release: BrowserRecipeRelease,
        trust: &BrowserRecipeTrustStore,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        release.verify(trust, now)?;
        let key = (
            release.candidate.manifest.id.clone(),
            release.candidate.manifest.version,
        );
        let candidate = self
            .candidates
            .get(&key)
            .ok_or(BrowserError::RecipeCandidateNotPromoted)?;
        if candidate.digest()? != release.candidate.digest()? {
            return Err(BrowserError::RecipeVersionConflict);
        }
        match self.releases.get(&key) {
            Some(existing) if existing == &release => Ok(()),
            Some(_) => Err(BrowserError::RecipeVersionConflict),
            None => {
                self.releases.insert(key, release);
                Ok(())
            }
        }
    }

    pub fn activate_release(
        &mut self,
        recipe_id: &BrowserRecipeId,
        version: u32,
        expected_active_version: Option<u32>,
        activation_evidence_digest: &str,
        trust: &BrowserRecipeTrustStore,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if !is_sha256(activation_evidence_digest) {
            return Err(BrowserError::RecipeActivationConflict);
        }
        let release = self
            .releases
            .get(&(recipe_id.clone(), version))
            .ok_or(BrowserError::RecipeCandidateNotPromoted)?;
        release.verify(trust, now)?;
        let active_version = self.active_versions.get(recipe_id).copied();
        if active_version == Some(version) {
            let existing = self
                .activations
                .get(&(recipe_id.clone(), version))
                .ok_or(BrowserError::RecipeActivationConflict)?;
            if existing.previous_version == expected_active_version
                && existing.activation_evidence_digest == activation_evidence_digest
                && existing.release_digest == release.digest()?
            {
                existing.validate_for(release)?;
                return Ok(());
            }
            return Err(BrowserError::RecipeActivationConflict);
        }
        if active_version != expected_active_version
            || expected_active_version.is_some_and(|active| version <= active)
        {
            return Err(BrowserError::RecipeActivationConflict);
        }
        let activation = BrowserRecipeActivation {
            schema_version: RECIPE_ACTIVATION_SCHEMA_VERSION,
            recipe_id: recipe_id.clone(),
            recipe_version: version,
            release_digest: release.digest()?,
            previous_version: expected_active_version,
            activation_evidence_digest: activation_evidence_digest.to_owned(),
            activated_at: now,
        };
        activation.validate_for(release)?;
        self.activations
            .insert((recipe_id.clone(), version), activation);
        self.active_versions.insert(recipe_id.clone(), version);
        Ok(())
    }

    pub fn active_release(
        &self,
        recipe_id: &BrowserRecipeId,
    ) -> Result<&BrowserRecipeRelease, BrowserError> {
        let version = self
            .active_versions
            .get(recipe_id)
            .ok_or(BrowserError::RecipeCandidateNotPromoted)?;
        self.releases
            .get(&(recipe_id.clone(), *version))
            .ok_or(BrowserError::RecipeCandidateNotPromoted)
    }

    pub fn candidate(
        &self,
        recipe_id: &BrowserRecipeId,
        version: u32,
    ) -> Result<&BrowserRecipeCandidate, BrowserError> {
        self.candidates
            .get(&(recipe_id.clone(), version))
            .ok_or(BrowserError::RecipeCandidateNotPromoted)
    }

    pub fn release(
        &self,
        recipe_id: &BrowserRecipeId,
        version: u32,
    ) -> Result<&BrowserRecipeRelease, BrowserError> {
        self.releases
            .get(&(recipe_id.clone(), version))
            .ok_or(BrowserError::RecipeCandidateNotPromoted)
    }

    pub fn activation(
        &self,
        recipe_id: &BrowserRecipeId,
        version: u32,
    ) -> Result<&BrowserRecipeActivation, BrowserError> {
        self.activations
            .get(&(recipe_id.clone(), version))
            .ok_or(BrowserError::RecipeActivationConflict)
    }

    pub fn active_version(&self, recipe_id: &BrowserRecipeId) -> Option<u32> {
        self.active_versions.get(recipe_id).copied()
    }

    pub fn snapshot(&self) -> Result<BrowserRecipeRegistrySnapshot, BrowserError> {
        let active_versions = self
            .active_versions
            .iter()
            .map(|(recipe_id, version)| {
                let activation = self.activation(recipe_id, *version)?;
                Ok(BrowserRecipeActiveVersion {
                    recipe_id: recipe_id.clone(),
                    version: *version,
                    activation_digest: activation.digest()?,
                })
            })
            .collect::<Result<Vec<_>, BrowserError>>()?;
        Ok(BrowserRecipeRegistrySnapshot {
            schema_version: RECIPE_REGISTRY_SNAPSHOT_SCHEMA_VERSION,
            candidates: self.candidates.values().cloned().collect(),
            releases: self.releases.values().cloned().collect(),
            activations: self.activations.values().cloned().collect(),
            active_versions,
        })
    }

    pub fn restore(
        snapshot: BrowserRecipeRegistrySnapshot,
        trust: &BrowserRecipeTrustStore,
    ) -> Result<Self, BrowserError> {
        if snapshot.schema_version != RECIPE_REGISTRY_SNAPSHOT_SCHEMA_VERSION {
            return Err(BrowserError::RecipeActivationConflict);
        }
        let candidate_count = snapshot.candidates.len();
        let release_count = snapshot.releases.len();
        let activation_count = snapshot.activations.len();
        let mut registry = Self::default();
        for candidate in snapshot.candidates {
            let authored_at = candidate.manifest.created_at;
            registry.register_candidate(candidate, trust, authored_at)?;
        }
        if registry.candidates.len() != candidate_count {
            return Err(BrowserError::RecipeVersionConflict);
        }
        for release in snapshot.releases {
            let promoted_at = release.promotion.promoted_at;
            registry.register_release(release, trust, promoted_at)?;
        }
        if registry.releases.len() != release_count {
            return Err(BrowserError::RecipeVersionConflict);
        }
        let mut activations = snapshot.activations;
        activations.sort_by(|left, right| {
            left.activated_at
                .cmp(&right.activated_at)
                .then_with(|| left.recipe_id.cmp(&right.recipe_id))
                .then_with(|| left.recipe_version.cmp(&right.recipe_version))
        });
        for activation in activations {
            registry.restore_activation(activation, trust)?;
        }
        if registry.activations.len() != activation_count {
            return Err(BrowserError::RecipeActivationConflict);
        }
        let active_version_count = snapshot.active_versions.len();
        let expected_active = snapshot
            .active_versions
            .into_iter()
            .map(|head| {
                if head.version == 0 || !is_sha256(&head.activation_digest) {
                    return Err(BrowserError::RecipeActivationConflict);
                }
                let activation = registry.activation(&head.recipe_id, head.version)?;
                if activation.digest()? != head.activation_digest {
                    return Err(BrowserError::RecipeActivationConflict);
                }
                Ok((head.recipe_id, head.version))
            })
            .collect::<Result<BTreeMap<_, _>, BrowserError>>()?;
        if expected_active.len() != active_version_count
            || expected_active.len() != registry.active_versions.len()
            || expected_active != registry.active_versions
        {
            return Err(BrowserError::RecipeActivationConflict);
        }
        Ok(registry)
    }

    fn restore_activation(
        &mut self,
        activation: BrowserRecipeActivation,
        trust: &BrowserRecipeTrustStore,
    ) -> Result<(), BrowserError> {
        let key = (activation.recipe_id.clone(), activation.recipe_version);
        let release = self
            .releases
            .get(&key)
            .ok_or(BrowserError::RecipeCandidateNotPromoted)?;
        release.verify(trust, activation.activated_at)?;
        activation.validate_for(release)?;
        let current = self.active_versions.get(&activation.recipe_id).copied();
        if current != activation.previous_version
            || current.is_some_and(|version| activation.recipe_version <= version)
            || self.activations.contains_key(&key)
        {
            return Err(BrowserError::RecipeActivationConflict);
        }
        self.active_versions
            .insert(activation.recipe_id.clone(), activation.recipe_version);
        self.activations.insert(key, activation);
        Ok(())
    }

    pub fn active_activation(
        &self,
        recipe_id: &BrowserRecipeId,
    ) -> Result<&BrowserRecipeActivation, BrowserError> {
        let version = self
            .active_versions
            .get(recipe_id)
            .ok_or(BrowserError::RecipeCandidateNotPromoted)?;
        self.activations
            .get(&(recipe_id.clone(), *version))
            .ok_or(BrowserError::RecipeActivationConflict)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_active_plan(
        &self,
        recipe_id: &BrowserRecipeId,
        trust: &BrowserRecipeTrustStore,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        policy_digest: String,
        resolved_actions: &[BrowserRecipeResolvedAction<'_>],
        prepared_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<BrowserRecipePreparedPlan, BrowserError> {
        let release = self.active_release(recipe_id)?;
        let activation = self.active_activation(recipe_id)?;
        BrowserRecipePreparedPlan::prepare(
            release,
            activation,
            trust,
            profile,
            workspace,
            policy_digest,
            resolved_actions,
            prepared_at,
            expires_at,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserRecipeActiveVersion {
    pub recipe_id: BrowserRecipeId,
    pub version: u32,
    pub activation_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserRecipeRegistrySnapshot {
    pub schema_version: u32,
    pub candidates: Vec<BrowserRecipeCandidate>,
    pub releases: Vec<BrowserRecipeRelease>,
    pub activations: Vec<BrowserRecipeActivation>,
    pub active_versions: Vec<BrowserRecipeActiveVersion>,
}

pub struct BrowserRecipeResolvedAction<'a> {
    pub action: &'a BrowserAction,
    pub resolution: &'a BrowserLocatorResolution,
}

impl fmt::Debug for BrowserRecipeResolvedAction<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserRecipeResolvedAction")
            .field("action", self.action)
            .field("resolution", self.resolution)
            .finish()
    }
}

fn bind_resolved_recipe_actions(
    manifest: &BrowserRecipeManifest,
    workspace: &BrowserWorkspace,
    policy_digest: &str,
    resolved_actions: &[BrowserRecipeResolvedAction<'_>],
) -> Result<(Vec<BrowserRecipeStepBinding>, Vec<BrowserAction>), BrowserError> {
    let mut step_bindings = Vec::with_capacity(resolved_actions.len());
    let mut actions = Vec::with_capacity(resolved_actions.len());
    for (step, resolved) in manifest.steps.iter().zip(resolved_actions) {
        resolved.action.validate()?;
        resolved.resolution.validate()?;
        if resolved.action.sequence != step.sequence
            || resolved.action.kind != step.kind
            || resolved.action.surface != step.surface
            || resolved.action.risk != step.risk
            || resolved.action.tab_id != resolved.resolution.tab_id
            || resolved.action.snapshot_id.as_ref() != Some(&resolved.resolution.snapshot_id)
            || resolved.action.element_ref.as_deref()
                != Some(resolved.resolution.element_ref.reference.as_str())
            || resolved.action.target_origin_digest != manifest.origin_digest
            || resolved.resolution.origin_digest != manifest.origin_digest
            || resolved.resolution.selector_digest != step.selector_digest
            || resolved.resolution.workspace_id != workspace.id
            || resolved.resolution.lease_generation != workspace.lease_generation
            || resolved.resolution.policy_digest != policy_digest
            || !workspace.tabs.contains(&resolved.action.tab_id)
            || (resolved.action.kind == BrowserActionKind::Click
                && resolved.action.payload_digest != resolved.resolution.evidence_digest()?)
        {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        step_bindings.push(BrowserRecipeStepBinding {
            sequence: step.sequence,
            selector_digest: step.selector_digest.clone(),
            resolution_evidence_digest: resolved.resolution.evidence_digest()?,
            action_payload_digest: resolved.action.payload_digest.clone(),
        });
        actions.push(resolved.action.clone());
    }
    Ok((step_bindings, actions))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserRecipeStepBinding {
    pub sequence: u32,
    pub selector_digest: String,
    pub resolution_evidence_digest: String,
    pub action_payload_digest: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserRecipePreparedPlan {
    pub schema_version: u32,
    pub recipe_id: BrowserRecipeId,
    pub recipe_version: u32,
    pub candidate_digest: String,
    pub release_digest: String,
    pub activation_digest: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub workspace_id: BrowserWorkspaceId,
    pub profile_id: BrowserProfileId,
    pub identity_digest: String,
    pub provider: String,
    pub origin_digest: String,
    pub capability: String,
    pub effect_class: EffectClass,
    pub policy_digest: String,
    pub action_plan_digest: String,
    pub step_bindings: Vec<BrowserRecipeStepBinding>,
    pub binding_digest: String,
    pub effect_payload_digest: String,
    pub prepared_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserRecipeBindingCanonical<'a> {
    schema_version: u32,
    domain: &'static str,
    recipe_id: &'a BrowserRecipeId,
    recipe_version: u32,
    candidate_digest: &'a str,
    release_digest: &'a str,
    activation_digest: &'a str,
    tenant_id: &'a TenantId,
    project_id: &'a ProjectId,
    mission_id: &'a MissionId,
    workspace_id: &'a BrowserWorkspaceId,
    profile_id: &'a BrowserProfileId,
    identity_digest: &'a str,
    provider: &'a str,
    origin_digest: &'a str,
    capability: &'a str,
    effect_class: &'a EffectClass,
    policy_digest: &'a str,
    action_plan_digest: &'a str,
    step_bindings: &'a [BrowserRecipeStepBinding],
    prepared_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl BrowserRecipePreparedPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        release: &BrowserRecipeRelease,
        activation: &BrowserRecipeActivation,
        trust: &BrowserRecipeTrustStore,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        policy_digest: String,
        resolved_actions: &[BrowserRecipeResolvedAction<'_>],
        prepared_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        release.verify(trust, prepared_at)?;
        activation.validate_for(release)?;
        profile.validate()?;
        workspace.validate()?;
        workspace.agent_lease_proof(prepared_at)?;
        let manifest = &release.candidate.manifest;
        if profile.tenant_id != workspace.tenant_id
            || profile.project_id != workspace.project_id
            || profile.id != workspace.profile_id
            || profile.identity.identity_digest != workspace.expected_identity_digest
            || profile.identity.provider != manifest.provider
            || !is_sha256(&policy_digest)
            || resolved_actions.len() != manifest.steps.len()
            || expires_at <= prepared_at
            || expires_at - prepared_at > MAX_PREPARED_PLAN_LIFETIME
            || expires_at > release.promotion.expires_at
            || prepared_at < activation.activated_at
        {
            return Err(BrowserError::RecipeScopeMismatch);
        }

        let (step_bindings, actions) =
            bind_resolved_recipe_actions(manifest, workspace, &policy_digest, resolved_actions)?;
        let action_plan_digest = BrowserActionBatch::plan_digest(&actions)?;
        let candidate_digest = release.candidate.digest()?;
        let release_digest = release.digest()?;
        let activation_digest = activation.digest()?;
        let binding_digest = digest_json(&BrowserRecipeBindingCanonical {
            schema_version: RECIPE_PLAN_SCHEMA_VERSION,
            domain: "hartevo-browser-recipe-binding/v1",
            recipe_id: &manifest.id,
            recipe_version: manifest.version,
            candidate_digest: &candidate_digest,
            release_digest: &release_digest,
            activation_digest: &activation_digest,
            tenant_id: &workspace.tenant_id,
            project_id: &workspace.project_id,
            mission_id: &workspace.mission_id,
            workspace_id: &workspace.id,
            profile_id: &profile.id,
            identity_digest: &profile.identity.identity_digest,
            provider: &manifest.provider,
            origin_digest: &manifest.origin_digest,
            capability: &manifest.capability,
            effect_class: &manifest.effect_class,
            policy_digest: &policy_digest,
            action_plan_digest: &action_plan_digest,
            step_bindings: &step_bindings,
            prepared_at,
            expires_at,
        })?;
        let effect_payload_digest =
            BrowserActionBatch::recipe_plan_digest(&actions, &binding_digest)?;
        let plan = Self {
            schema_version: RECIPE_PLAN_SCHEMA_VERSION,
            recipe_id: manifest.id.clone(),
            recipe_version: manifest.version,
            candidate_digest,
            release_digest,
            activation_digest,
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            workspace_id: workspace.id.clone(),
            profile_id: profile.id.clone(),
            identity_digest: profile.identity.identity_digest.clone(),
            provider: manifest.provider.clone(),
            origin_digest: manifest.origin_digest.clone(),
            capability: manifest.capability.clone(),
            effect_class: manifest.effect_class.clone(),
            policy_digest,
            action_plan_digest,
            step_bindings,
            binding_digest,
            effect_payload_digest,
            prepared_at,
            expires_at,
        };
        plan.validate_for(profile, workspace, &actions, prepared_at)?;
        Ok(plan)
    }

    pub fn validate_for(
        &self,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        actions: &[BrowserAction],
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        profile.validate()?;
        workspace.validate()?;
        self.validate_action_binding(actions, now)?;
        if self.tenant_id != profile.tenant_id
            || self.tenant_id != workspace.tenant_id
            || self.project_id != profile.project_id
            || self.project_id != workspace.project_id
            || self.mission_id != workspace.mission_id
            || self.workspace_id != workspace.id
            || self.profile_id != profile.id
            || self.identity_digest != profile.identity.identity_digest
            || self.identity_digest != workspace.expected_identity_digest
            || self.provider != profile.identity.provider
        {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        Ok(())
    }

    pub fn validate_action_binding(
        &self,
        actions: &[BrowserAction],
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        let expected_binding = digest_json(&BrowserRecipeBindingCanonical {
            schema_version: RECIPE_PLAN_SCHEMA_VERSION,
            domain: "hartevo-browser-recipe-binding/v1",
            recipe_id: &self.recipe_id,
            recipe_version: self.recipe_version,
            candidate_digest: &self.candidate_digest,
            release_digest: &self.release_digest,
            activation_digest: &self.activation_digest,
            tenant_id: &self.tenant_id,
            project_id: &self.project_id,
            mission_id: &self.mission_id,
            workspace_id: &self.workspace_id,
            profile_id: &self.profile_id,
            identity_digest: &self.identity_digest,
            provider: &self.provider,
            origin_digest: &self.origin_digest,
            capability: &self.capability,
            effect_class: &self.effect_class,
            policy_digest: &self.policy_digest,
            action_plan_digest: &self.action_plan_digest,
            step_bindings: &self.step_bindings,
            prepared_at: self.prepared_at,
            expires_at: self.expires_at,
        })?;
        if self.schema_version != RECIPE_PLAN_SCHEMA_VERSION
            || !is_bounded_identifier(self.recipe_id.as_str())
            || self.recipe_version == 0
            || !is_sha256(&self.candidate_digest)
            || !is_sha256(&self.release_digest)
            || !is_sha256(&self.activation_digest)
            || !is_sha256(&self.origin_digest)
            || !is_bounded_identifier(&self.capability)
            || matches!(
                self.effect_class,
                EffectClass::Read | EffectClass::LocalWrite
            )
            || !is_sha256(&self.policy_digest)
            || self.action_plan_digest != BrowserActionBatch::plan_digest(actions)?
            || self.step_bindings.len() != actions.len()
            || self.step_bindings.iter().any(|binding| {
                binding.sequence == 0
                    || !is_sha256(&binding.selector_digest)
                    || !is_sha256(&binding.resolution_evidence_digest)
                    || !is_sha256(&binding.action_payload_digest)
            })
            || self.binding_digest != expected_binding
            || self.effect_payload_digest
                != BrowserActionBatch::recipe_plan_digest(actions, &self.binding_digest)?
            || self.prepared_at > now
            || now >= self.expires_at
            || self.expires_at - self.prepared_at > MAX_PREPARED_PLAN_LIFETIME
        {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        Ok(())
    }

    pub fn validate_active_release(
        &self,
        registry: &BrowserRecipeRegistry,
        trust: &BrowserRecipeTrustStore,
        actions: &[BrowserAction],
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        let release = registry.active_release(&self.recipe_id)?;
        let activation = registry.active_activation(&self.recipe_id)?;
        release.verify(trust, now)?;
        activation.validate_for(release)?;
        let manifest = &release.candidate.manifest;
        if self.recipe_version != manifest.version
            || self.candidate_digest != release.candidate.digest()?
            || self.release_digest != release.digest()?
            || self.activation_digest != activation.digest()?
            || self.provider != manifest.provider
            || self.origin_digest != manifest.origin_digest
            || self.capability != manifest.capability
            || self.effect_class != manifest.effect_class
            || self.prepared_at < activation.activated_at
            || self.expires_at > release.promotion.expires_at
            || manifest.steps.len() != self.step_bindings.len()
            || manifest.steps.len() != actions.len()
        {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        for ((step, binding), action) in manifest.steps.iter().zip(&self.step_bindings).zip(actions)
        {
            if binding.sequence != step.sequence
                || binding.selector_digest != step.selector_digest
                || binding.action_payload_digest != action.payload_digest
                || action.sequence != step.sequence
                || action.kind != step.kind
                || action.surface != step.surface
                || action.risk != step.risk
                || action.target_origin_digest != manifest.origin_digest
            {
                return Err(BrowserError::RecipeScopeMismatch);
            }
        }
        Ok(())
    }

    pub fn validate_resolution_binding(
        &self,
        action: &BrowserAction,
        resolution: &BrowserLocatorResolution,
    ) -> Result<(), BrowserError> {
        action.validate()?;
        resolution.validate()?;
        let binding = self
            .step_bindings
            .iter()
            .find(|binding| binding.sequence == action.sequence)
            .ok_or(BrowserError::RecipeScopeMismatch)?;
        if binding.selector_digest != resolution.selector_digest
            || binding.resolution_evidence_digest != resolution.evidence_digest()?
            || binding.action_payload_digest != action.payload_digest
            || self.workspace_id != resolution.workspace_id
            || self.origin_digest != resolution.origin_digest
            || self.policy_digest != resolution.policy_digest
            || action.tab_id != resolution.tab_id
            || action.snapshot_id.as_ref() != Some(&resolution.snapshot_id)
            || action.element_ref.as_deref() != Some(&resolution.element_ref.reference)
            || action.target_origin_digest != resolution.origin_digest
        {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        Ok(())
    }

    pub fn validate_effect(&self, effect: &Effect, now: DateTime<Utc>) -> Result<(), BrowserError> {
        let approval = effect
            .approval
            .as_ref()
            .ok_or(BrowserError::EffectBrokerRequired)?;
        if effect.tenant_id != self.tenant_id
            || effect.project_id != self.project_id
            || effect.mission_id != self.mission_id
            || effect.provider != self.provider
            || effect.capability != self.capability
            || effect.effect_class != self.effect_class
            || effect.payload_digest != self.effect_payload_digest
            || effect.status != EffectStatus::Approved
            || approval.scope_digest != effect.approval_digest()
            || now >= approval.valid_until
            || now >= effect.expires_at
            || now >= self.expires_at
        {
            return Err(BrowserError::EffectScopeMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for BrowserRecipePreparedPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserRecipePreparedPlan")
            .field("schema_version", &self.schema_version)
            .field("recipe_id", &self.recipe_id)
            .field("recipe_version", &self.recipe_version)
            .field("candidate_digest", &self.candidate_digest)
            .field("release_digest", &self.release_digest)
            .field("activation_digest", &self.activation_digest)
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("workspace_id", &self.workspace_id)
            .field("profile_id", &self.profile_id)
            .field("identity_digest", &self.identity_digest)
            .field("provider", &self.provider)
            .field("origin_digest", &self.origin_digest)
            .field("capability", &self.capability)
            .field("effect_class", &self.effect_class)
            .field("policy_digest", &self.policy_digest)
            .field("action_plan_digest", &self.action_plan_digest)
            .field("step_binding_count", &self.step_bindings.len())
            .field("binding_digest", &self.binding_digest)
            .field("effect_payload_digest", &self.effect_payload_digest)
            .field("prepared_at", &self.prepared_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

pub struct BrowserRecipeExecutionAuthorization<'a> {
    prepared_plan: BrowserRecipePreparedPlan,
    registry: &'a BrowserRecipeRegistry,
    trust: &'a BrowserRecipeTrustStore,
}

impl<'a> BrowserRecipeExecutionAuthorization<'a> {
    pub fn new(
        prepared_plan: BrowserRecipePreparedPlan,
        registry: &'a BrowserRecipeRegistry,
        trust: &'a BrowserRecipeTrustStore,
        batch: &BrowserActionBatch,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let authorization = Self {
            prepared_plan,
            registry,
            trust,
        };
        authorization.validate_batch(batch, now)?;
        Ok(authorization)
    }

    pub fn validate_batch(
        &self,
        batch: &BrowserActionBatch,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.prepared_plan
            .validate_action_binding(&batch.actions, now)?;
        self.prepared_plan.validate_active_release(
            self.registry,
            self.trust,
            &batch.actions,
            now,
        )?;
        if batch.recipe_binding_digest.as_deref()
            != Some(self.prepared_plan.binding_digest.as_str())
            || batch.plan_digest != self.prepared_plan.effect_payload_digest
            || batch.policy_digest != self.prepared_plan.policy_digest
            || batch.tenant_id != self.prepared_plan.tenant_id
            || batch.project_id != self.prepared_plan.project_id
            || batch.mission_id != self.prepared_plan.mission_id
            || batch.workspace_id != self.prepared_plan.workspace_id
            || batch.expected_identity_digest != self.prepared_plan.identity_digest
            || batch.created_at < self.prepared_plan.prepared_at
            || batch.expires_at > self.prepared_plan.expires_at
        {
            return Err(BrowserError::RecipeScopeMismatch);
        }
        Ok(())
    }

    pub fn validate_resolution(
        &self,
        action: &BrowserAction,
        resolution: &BrowserLocatorResolution,
    ) -> Result<(), BrowserError> {
        self.prepared_plan
            .validate_resolution_binding(action, resolution)
    }

    pub fn validate_effect(
        &self,
        batch: &BrowserActionBatch,
        effect: &Effect,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.validate_batch(batch, now)?;
        self.prepared_plan.validate_effect(effect, now)?;
        batch.validate_effect(effect, now)
    }
}

impl fmt::Debug for BrowserRecipeExecutionAuthorization<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserRecipeExecutionAuthorization")
            .field("prepared_plan", &self.prepared_plan)
            .field("runtime_revalidation_required", &true)
            .finish_non_exhaustive()
    }
}

fn decode_signature(signature_hex: &str) -> Result<Vec<u8>, BrowserError> {
    let signature = hex::decode(signature_hex).map_err(|_| BrowserError::RecipeSignatureInvalid)?;
    if signature.len() != ED25519_SIGNATURE_BYTES || signature_hex != hex::encode(&signature) {
        return Err(BrowserError::RecipeSignatureInvalid);
    }
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_domain_kernel::{
        AccountId, ActorId, Approval, ApprovalDecision, ApprovalId, BrowserActionBatchId,
        BrowserControlLeaseId, BrowserProfileId, BrowserSnapshotId, BrowserTabId, ConsentState,
        CurrencyCode, EffectId, EffectRisk, Money, Project, StorageMode,
    };
    use hartevo_effect_broker::EffectExecutor;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;
    use crate::{
        BrowserElementRef, BrowserIdentity, BrowserNavigationPolicy, BrowserStableLocator,
        FakeBrowserEffectExecutor, FakeBrowserHost, FakeBrowserPage,
    };

    struct RecipeFixture {
        now: DateTime<Utc>,
        candidate_signer: Ed25519KeyPair,
        release_signer: Ed25519KeyPair,
        trust: BrowserRecipeTrustStore,
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        policy: BrowserNavigationPolicy,
        resolution: BrowserLocatorResolution,
        action: BrowserAction,
    }

    fn signing_key(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("fixed test signing key")
    }

    fn fixture_trust(
        now: DateTime<Utc>,
        candidate_signer: &Ed25519KeyPair,
        release_signer: &Ed25519KeyPair,
    ) -> BrowserRecipeTrustStore {
        let mut trust = BrowserRecipeTrustStore::default();
        trust
            .insert(
                TrustedBrowserRecipeKey::new(
                    "candidate-key-1",
                    BrowserRecipeKeyPurpose::CandidatePublisher,
                    candidate_signer.public_key().as_ref(),
                    now - Duration::days(1),
                    now + Duration::days(400),
                )
                .expect("candidate trust key"),
            )
            .expect("insert candidate key");
        trust
            .insert(
                TrustedBrowserRecipeKey::new(
                    "release-key-1",
                    BrowserRecipeKeyPurpose::ProductionRelease,
                    release_signer.public_key().as_ref(),
                    now - Duration::days(1),
                    now + Duration::days(400),
                )
                .expect("release trust key"),
            )
            .expect("insert release key");
        trust
    }

    fn fixture_browser_scope(
        now: DateTime<Utc>,
    ) -> (
        BrowserProfile,
        BrowserWorkspace,
        BrowserNavigationPolicy,
        BrowserLocatorResolution,
        BrowserAction,
    ) {
        let project = Project::create_local(
            TenantId::from("tenant-recipe"),
            ProjectId::from("project-recipe"),
            "Recipe",
            "",
            "/tmp/hartevo-recipe",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = hartevo_domain_kernel::Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-recipe"),
            project.id.clone(),
            "Signed recipe",
            hartevo_domain_kernel::MissionContract::bootstrap(
                "Use only promoted browser behavior",
                ["channel.publish".into()],
                now,
            ),
            now,
        )
        .expect("mission");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-recipe"),
            &project,
            "credential-manager://recipe-profile",
            BrowserIdentity::new(
                "fixture-provider",
                AccountId::from("account-recipe"),
                "1".repeat(64),
                "2".repeat(64),
                now,
            )
            .expect("identity"),
            now,
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-recipe"),
            &project,
            &mission,
            &profile,
            BrowserTabId::from("tab-recipe"),
            BrowserControlLeaseId::from("lease-recipe"),
            now + Duration::hours(2),
            "3".repeat(64),
            now,
        )
        .expect("workspace");
        let policy = BrowserNavigationPolicy::https_only(["https://example.com"])
            .expect("exact origin policy");
        let locator = BrowserStableLocator::exact_accessible_name(
            &workspace,
            BrowserTabId::from("tab-recipe"),
            &policy,
            digest(b"https://example.com"),
            "button",
            "Publish draft",
            now,
        )
        .expect("stable locator");
        let resolution = BrowserLocatorResolution::new(
            workspace.id.clone(),
            BrowserTabId::from("tab-recipe"),
            BrowserSnapshotId::from("snapshot-recipe"),
            workspace.lease_generation,
            1,
            locator.evidence_digest().to_owned(),
            locator.selector_digest().to_owned(),
            "4".repeat(64),
            digest(b"https://example.com"),
            policy.evidence_digest().to_owned(),
            BrowserElementRef {
                reference: "ax-publish-draft".into(),
                locator_digest: "5".repeat(64),
                visible: false,
                unique: true,
            },
            now,
        )
        .expect("resolution");
        let action = BrowserAction::semantic_click(1, &resolution).expect("semantic click");
        (profile, workspace, policy, resolution, action)
    }

    fn fixture() -> RecipeFixture {
        let now = Utc
            .with_ymd_and_hms(2026, 8, 11, 8, 0, 0)
            .single()
            .expect("time");
        let candidate_signer = signing_key(7);
        let release_signer = signing_key(9);
        let trust = fixture_trust(now, &candidate_signer, &release_signer);
        let (profile, workspace, policy, resolution, action) = fixture_browser_scope(now);
        RecipeFixture {
            now,
            candidate_signer,
            release_signer,
            trust,
            profile,
            workspace,
            policy,
            resolution,
            action,
        }
    }

    fn candidate(fixture: &RecipeFixture, version: u32) -> BrowserRecipeCandidate {
        let manifest = BrowserRecipeManifest {
            schema_version: RECIPE_SCHEMA_VERSION,
            id: BrowserRecipeId::from("fixture-publish-draft"),
            version,
            provider: fixture.profile.identity.provider.clone(),
            origin_digest: fixture.resolution.origin_digest.clone(),
            capability: "channel.publish".into(),
            effect_class: EffectClass::ExternalWrite,
            steps: vec![BrowserRecipeStep {
                sequence: 1,
                kind: BrowserActionKind::Click,
                surface: BrowserActionSurface::Semantic,
                risk: BrowserActionRisk::PotentialExternalWrite,
                selector_digest: fixture.resolution.selector_digest.clone(),
            }],
            publisher_key_id: "candidate-key-1".into(),
            created_at: fixture.now - Duration::hours(1),
            expires_at: fixture.now + Duration::days(30),
        };
        let payload = BrowserRecipeCandidate::signing_payload(&manifest).expect("candidate bytes");
        BrowserRecipeCandidate::new(
            manifest,
            hex::encode(fixture.candidate_signer.sign(&payload).as_ref()),
        )
        .expect("signed candidate")
    }

    fn evaluation() -> BrowserRecipeEvaluationEvidence {
        BrowserRecipeEvaluationEvidence {
            v1_dataset_revision: "browser-recipe-v1-holdout".into(),
            v1_result_digest: "6".repeat(64),
            v1_passed: 9,
            v1_total: 10,
            v2_dataset_revision: "browser-recipe-v2-shadow".into(),
            v2_result_digest: "7".repeat(64),
            v2_passed: 4,
            v2_total: 5,
            safety_suite_digest: "8".repeat(64),
            contamination_audit_digest: "9".repeat(64),
            rollback_strategy_digest: "a".repeat(64),
            promotion_approval_digest: "b".repeat(64),
        }
    }

    fn release(fixture: &RecipeFixture, version: u32) -> BrowserRecipeRelease {
        let candidate = candidate(fixture, version);
        let evidence = evaluation();
        let candidate_digest = candidate.digest().expect("candidate digest");
        let promoted_at = fixture.now - Duration::minutes(30);
        let expires_at = fixture.now + Duration::days(20);
        let payload = BrowserRecipePromotion::signing_payload(
            &candidate_digest,
            &evidence,
            "release-key-1",
            promoted_at,
            expires_at,
        )
        .expect("promotion bytes");
        BrowserRecipeRelease {
            candidate,
            promotion: BrowserRecipePromotion {
                schema_version: RECIPE_PROMOTION_SCHEMA_VERSION,
                candidate_digest,
                evidence,
                release_key_id: "release-key-1".into(),
                promoted_at,
                expires_at,
                signature_hex: hex::encode(fixture.release_signer.sign(&payload).as_ref()),
            },
        }
    }

    fn approved_effect(fixture: &RecipeFixture, plan: &BrowserRecipePreparedPlan) -> Effect {
        let mut effect = Effect {
            id: EffectId::from("effect-recipe-publish"),
            tenant_id: fixture.workspace.tenant_id.clone(),
            project_id: fixture.workspace.project_id.clone(),
            mission_id: fixture.workspace.mission_id.clone(),
            actor_id: ActorId::from("user-recipe"),
            capability: plan.capability.clone(),
            provider: plan.provider.clone(),
            connection_id: None,
            account_id: Some(fixture.profile.identity.account_id.clone()),
            required_scopes: std::collections::BTreeSet::new(),
            effect_class: plan.effect_class.clone(),
            description: "Publish one already reviewed draft".into(),
            target_resource: "https://example.com/draft/approved".into(),
            audience_digest: Some("c".repeat(64)),
            payload_digest: plan.effect_payload_digest.clone(),
            asset_digests: std::collections::BTreeSet::new(),
            scheduled_for: None,
            timezone: "UTC".into(),
            consent: ConsentState::NotRequired,
            consent_record_id: None,
            consent_requirement: None,
            conversation_guard: None,
            creator_contact_guard: None,
            policy_version: "browser-recipe-policy-v1".into(),
            risk: EffectRisk::Medium,
            idempotency_key: "recipe-publish-v1".into(),
            amount: Money::zero(CurrencyCode::parse("USD").expect("USD")),
            expires_at: fixture.now + Duration::minutes(10),
            status: EffectStatus::Approved,
            approval: None,
            receipt: None,
            verification: None,
        };
        let scope_digest = effect.approval_digest();
        effect.approval = Some(Approval {
            id: ApprovalId::from("approval-recipe-publish"),
            decision: ApprovalDecision::Approved,
            decided_by: ActorId::from("user-recipe"),
            decided_at: fixture.now,
            valid_until: fixture.now + Duration::minutes(10),
            scope_digest,
            permission_digest: "d".repeat(64),
        });
        effect
    }

    #[test]
    fn candidate_and_promotion_canonical_payload_golden_vectors_do_not_change() {
        let fixture = fixture();
        let release = release(&fixture, 1);
        let candidate_payload =
            BrowserRecipeCandidate::signing_payload(&release.candidate.manifest)
                .expect("candidate payload");
        let promotion_payload = BrowserRecipePromotion::signing_payload(
            &release.promotion.candidate_digest,
            &release.promotion.evidence,
            &release.promotion.release_key_id,
            release.promotion.promoted_at,
            release.promotion.expires_at,
        )
        .expect("promotion payload");
        assert_eq!(
            digest(&candidate_payload),
            "76c6dee089bbfab139b11a56c78fccd6c1098b69b107a12fc4483072a4365f7d"
        );
        assert_eq!(
            digest(&promotion_payload),
            "3a15641d1c445c9e0ac4d3b95e77f891d661ce8c60eb34b1111b8499b3feb1d6"
        );
        assert!(candidate_payload.starts_with(b"[\"hartevo-browser-recipe-candidate/v1\","));
        assert!(promotion_payload.starts_with(b"[\"hartevo-browser-recipe-promotion/v1\",1,"));
    }

    #[test]
    fn candidate_signature_is_immutable_redacted_and_never_production_by_itself() {
        let fixture = fixture();
        let candidate = candidate(&fixture, 1);
        candidate
            .verify(&fixture.trust, fixture.now)
            .expect("candidate signature");
        let debug = format!("{candidate:?}");
        assert!(!debug.contains(&candidate.signature_hex));

        let mut tampered = candidate.clone();
        tampered.manifest.capability = "channel.delete".into();
        assert_eq!(
            tampered
                .verify(&fixture.trust, fixture.now)
                .expect_err("signed payload is immutable")
                .code(),
            "BROWSER_RECIPE_SIGNATURE_INVALID"
        );

        let mut registry = BrowserRecipeRegistry::default();
        registry
            .register_candidate(candidate.clone(), &fixture.trust, fixture.now)
            .expect("register candidate");
        assert_eq!(
            registry
                .active_release(&candidate.manifest.id)
                .expect_err("candidate cannot execute as production")
                .code(),
            "BROWSER_RECIPE_CANDIDATE_NOT_PROMOTED"
        );
    }

    #[test]
    fn production_promotion_requires_frozen_v1_v2_safety_contamination_and_rollback_gates() {
        let fixture = fixture();
        let mut insufficient = evaluation();
        insufficient.v1_passed = 8;
        assert_eq!(
            BrowserRecipePromotion::signing_payload(
                &candidate(&fixture, 1).digest().expect("digest"),
                &insufficient,
                "release-key-1",
                fixture.now,
                fixture.now + Duration::days(1),
            )
            .expect_err("V1 gate must be at least 9/10")
            .code(),
            "BROWSER_RECIPE_EVALUATION_GATE_FAILED"
        );

        let release = release(&fixture, 1);
        release
            .verify(&fixture.trust, fixture.now)
            .expect("two independently scoped signatures and evidence gates");
        let mut tampered = release.clone();
        tampered.promotion.evidence.rollback_strategy_digest = "e".repeat(64);
        assert_eq!(
            tampered
                .verify(&fixture.trust, fixture.now)
                .expect_err("promotion evidence is signed")
                .code(),
            "BROWSER_RECIPE_SIGNATURE_INVALID"
        );
    }

    #[test]
    fn revoked_candidate_or_release_key_blocks_new_execution() {
        let mut fixture = fixture();
        let release = release(&fixture, 1);
        release
            .verify(&fixture.trust, fixture.now)
            .expect("release initially valid");
        fixture
            .trust
            .revoke("release-key-1", 1, fixture.now)
            .expect("revoke production key");
        assert_eq!(
            release
                .verify(&fixture.trust, fixture.now)
                .expect_err("revoked key cannot authorize a new run")
                .code(),
            "BROWSER_RECIPE_KEY_REVOKED"
        );
    }

    #[test]
    fn registry_requires_signed_release_explicit_activation_cas_and_monotonic_versions() {
        let fixture = fixture();
        let release_v1 = release(&fixture, 1);
        let release_v2 = release(&fixture, 2);
        let recipe_id = release_v1.candidate.manifest.id.clone();
        let mut registry = BrowserRecipeRegistry::default();
        for release in [&release_v1, &release_v2] {
            registry
                .register_candidate(release.candidate.clone(), &fixture.trust, fixture.now)
                .expect("candidate registered but inactive");
            registry
                .register_release(release.clone(), &fixture.trust, fixture.now)
                .expect("signed production release registered");
        }
        registry
            .activate_release(
                &recipe_id,
                1,
                None,
                &"e".repeat(64),
                &fixture.trust,
                fixture.now,
            )
            .expect("explicit first activation");
        assert_eq!(
            registry
                .activate_release(
                    &recipe_id,
                    2,
                    None,
                    &"f".repeat(64),
                    &fixture.trust,
                    fixture.now,
                )
                .expect_err("lost activation CAS")
                .code(),
            "BROWSER_RECIPE_ACTIVATION_CONFLICT"
        );
        registry
            .activate_release(
                &recipe_id,
                2,
                Some(1),
                &"f".repeat(64),
                &fixture.trust,
                fixture.now,
            )
            .expect("monotonic activation");
        assert_eq!(
            registry
                .activate_release(
                    &recipe_id,
                    1,
                    Some(2),
                    &"f".repeat(64),
                    &fixture.trust,
                    fixture.now,
                )
                .expect_err("downgrade requires a new higher signed version")
                .code(),
            "BROWSER_RECIPE_ACTIVATION_CONFLICT"
        );
        assert_eq!(
            registry
                .active_release(&recipe_id)
                .expect("active release")
                .candidate
                .manifest
                .version,
            2
        );
    }

    struct PreparedRecipeFixture {
        browser: RecipeFixture,
        registry: BrowserRecipeRegistry,
        recipe_id: BrowserRecipeId,
        actions: Vec<BrowserAction>,
        plan: BrowserRecipePreparedPlan,
        effect: Effect,
        batch: BrowserActionBatch,
    }

    fn prepared_recipe_fixture() -> PreparedRecipeFixture {
        let browser = fixture();
        let release_v1 = release(&browser, 1);
        let recipe_id = release_v1.candidate.manifest.id.clone();
        let mut registry = BrowserRecipeRegistry::default();
        registry
            .register_candidate(release_v1.candidate.clone(), &browser.trust, browser.now)
            .expect("candidate");
        registry
            .register_release(release_v1, &browser.trust, browser.now)
            .expect("release");
        registry
            .activate_release(
                &recipe_id,
                1,
                None,
                &"e".repeat(64),
                &browser.trust,
                browser.now,
            )
            .expect("activation");
        let actions = vec![browser.action.clone()];
        let plan = registry
            .prepare_active_plan(
                &recipe_id,
                &browser.trust,
                &browser.profile,
                &browser.workspace,
                browser.policy.evidence_digest().to_owned(),
                &[BrowserRecipeResolvedAction {
                    action: &actions[0],
                    resolution: &browser.resolution,
                }],
                browser.now,
                browser.now + Duration::minutes(10),
            )
            .expect("exact signed production plan");
        let effect = approved_effect(&browser, &plan);
        let batch = BrowserActionBatch::for_recipe_effect(
            BrowserActionBatchId::from("batch-recipe-publish"),
            &browser.profile,
            &browser.workspace,
            browser
                .workspace
                .agent_lease_proof(browser.now)
                .expect("lease"),
            browser.policy.evidence_digest().to_owned(),
            actions.clone(),
            &plan,
            &registry,
            &browser.trust,
            &effect,
            browser.now,
            browser.now + Duration::minutes(10),
        )
        .expect("Effect-bound signed Recipe batch");
        PreparedRecipeFixture {
            browser,
            registry,
            recipe_id,
            actions,
            plan,
            effect,
            batch,
        }
    }

    #[test]
    fn production_recipe_restores_and_dispatches_only_with_current_runtime_authorization() {
        let prepared = prepared_recipe_fixture();
        assert_ne!(
            prepared.plan.effect_payload_digest,
            BrowserActionBatch::plan_digest(&prepared.actions).expect("unbound action plan")
        );
        assert_eq!(
            prepared.batch.recipe_binding_digest,
            Some(prepared.plan.binding_digest.clone())
        );
        let restored_plan: BrowserRecipePreparedPlan = serde_json::from_slice(
            &serde_json::to_vec(&prepared.plan).expect("persist prepared plan"),
        )
        .expect("restore prepared plan");
        let restored_batch: BrowserActionBatch = serde_json::from_slice(
            &serde_json::to_vec(&prepared.batch).expect("persist Recipe batch"),
        )
        .expect("restore Recipe batch");
        let authorization = BrowserRecipeExecutionAuthorization::new(
            restored_plan,
            &prepared.registry,
            &prepared.browser.trust,
            &restored_batch,
            prepared.browser.now,
        )
        .expect("restore and revalidate current signatures");
        authorization
            .validate_resolution(&restored_batch.actions[0], &prepared.browser.resolution)
            .expect("dynamic resolution binding");
        authorization
            .validate_effect(&restored_batch, &prepared.effect, prepared.browser.now)
            .expect("dispatch-time Effect revalidation");

        let mut element = prepared.browser.resolution.element_ref.clone();
        element.visible = true;
        let mut host = FakeBrowserHost::new();
        host.register_workspace(
            prepared.browser.profile.clone(),
            prepared.browser.workspace.clone(),
            vec![FakeBrowserPage {
                tab_id: prepared.browser.resolution.tab_id.clone(),
                identity_digest: prepared.browser.workspace.expected_identity_digest.clone(),
                url_digest: prepared.browser.resolution.url_digest.clone(),
                origin_digest: prepared.browser.resolution.origin_digest.clone(),
                content_digest: "0".repeat(64),
                redaction_digest: "1".repeat(64),
                document_generation: prepared.browser.resolution.document_generation,
                prompt_risk: crate::BrowserPromptRisk::None,
                element_refs: vec![element],
            }],
        )
        .expect("register fake workspace");
        host.observe(
            &prepared.browser.workspace.id,
            &prepared
                .browser
                .workspace
                .agent_lease_proof(prepared.browser.now)
                .expect("live lease"),
            prepared.browser.resolution.snapshot_id.clone(),
            &prepared.browser.resolution.tab_id,
            prepared.browser.now,
        )
        .expect("restore exact snapshot");
        let mut executor = FakeBrowserEffectExecutor::new_for_recipe(
            &mut host,
            restored_batch.clone(),
            prepared.plan,
            &prepared.registry,
            &prepared.browser.trust,
            prepared.browser.now,
        )
        .expect("runtime-authorized executor");
        let receipt = executor.execute(&prepared.effect).expect("dispatch");
        assert_eq!(receipt.request_digest, restored_batch.plan_digest);
    }

    #[test]
    fn production_recipe_rejects_origin_selector_and_approved_payload_substitution() {
        let prepared = prepared_recipe_fixture();
        let mut wrong_origin = prepared.actions.clone();
        wrong_origin[0].target_origin_digest = "f".repeat(64);
        let mut wrong_selector = prepared.browser.resolution.clone();
        wrong_selector.selector_digest = "f".repeat(64);
        for (action, resolution) in [
            (&wrong_origin[0], &prepared.browser.resolution),
            (&prepared.actions[0], &wrong_selector),
        ] {
            assert_eq!(
                prepared
                    .registry
                    .prepare_active_plan(
                        &prepared.recipe_id,
                        &prepared.browser.trust,
                        &prepared.browser.profile,
                        &prepared.browser.workspace,
                        prepared.browser.policy.evidence_digest().to_owned(),
                        &[BrowserRecipeResolvedAction { action, resolution }],
                        prepared.browser.now,
                        prepared.browser.now + Duration::minutes(10),
                    )
                    .expect_err("signed scope substitution")
                    .code(),
                "BROWSER_RECIPE_SCOPE_MISMATCH"
            );
        }
        let mut changed_effect = prepared.effect.clone();
        changed_effect.payload_digest = "0".repeat(64);
        assert_eq!(
            BrowserActionBatch::for_recipe_effect(
                BrowserActionBatchId::from("batch-recipe-tampered"),
                &prepared.browser.profile,
                &prepared.browser.workspace,
                prepared
                    .browser
                    .workspace
                    .agent_lease_proof(prepared.browser.now)
                    .expect("lease"),
                prepared.browser.policy.evidence_digest().to_owned(),
                prepared.actions,
                &prepared.plan,
                &prepared.registry,
                &prepared.browser.trust,
                &changed_effect,
                prepared.browser.now,
                prepared.browser.now + Duration::minutes(10),
            )
            .expect_err("payload substitution after approval")
            .code(),
            "BROWSER_EFFECT_SCOPE_MISMATCH"
        );
    }

    #[test]
    fn recovered_recipe_rechecks_active_version_and_release_key_revocation_before_dispatch() {
        let mut prepared = prepared_recipe_fixture();
        let release_v2 = release(&prepared.browser, 2);
        prepared
            .registry
            .register_candidate(
                release_v2.candidate.clone(),
                &prepared.browser.trust,
                prepared.browser.now,
            )
            .expect("next candidate");
        prepared
            .registry
            .register_release(release_v2, &prepared.browser.trust, prepared.browser.now)
            .expect("next release");
        prepared
            .registry
            .activate_release(
                &prepared.recipe_id,
                2,
                Some(1),
                &"f".repeat(64),
                &prepared.browser.trust,
                prepared.browser.now,
            )
            .expect("activate newer release");
        assert_eq!(
            BrowserRecipeExecutionAuthorization::new(
                prepared.plan.clone(),
                &prepared.registry,
                &prepared.browser.trust,
                &prepared.batch,
                prepared.browser.now,
            )
            .expect_err("old version cannot dispatch")
            .code(),
            "BROWSER_RECIPE_SCOPE_MISMATCH"
        );
        prepared
            .browser
            .trust
            .revoke("release-key-1", 1, prepared.browser.now)
            .expect("revoke production key");
        assert_eq!(
            BrowserRecipeExecutionAuthorization::new(
                prepared.plan,
                &prepared.registry,
                &prepared.browser.trust,
                &prepared.batch,
                prepared.browser.now,
            )
            .expect_err("dispatch must re-read revocation")
            .code(),
            "BROWSER_RECIPE_KEY_REVOKED"
        );
    }
}
