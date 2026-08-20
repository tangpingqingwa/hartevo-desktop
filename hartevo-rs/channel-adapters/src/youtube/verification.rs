//! Read-only receipt and verification for an already-authorized YouTube Effect.
//!
//! The verifier consumes the exact typed Effect boundary and provider receipt
//! from the publish path. It never calls the upload endpoint, never grants
//! authority, and never receives a credential secret in durable evidence.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::provider::{YouTubeDataApiProvider, YouTubeProductionTransport};
use super::{
    YouTubeAuthorizedPublishEffect, YouTubeCredential, YouTubeDispatchOperation, YouTubeError,
    YouTubeEvidenceProvenance, YouTubePluginIdentity, YouTubeProviderReceipt,
    YouTubePublishBinding, YouTubeReadbackReceipt, YouTubeRetryAfterReceipt, YouTubeVideoId,
    is_sha256, sha256_json, valid_id,
};

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct YouTubeEvidenceId(String);

impl YouTubeEvidenceId {
    pub fn new(value: impl Into<String>) -> Result<Self, YouTubeError> {
        Ok(Self(valid_id(value.into(), "YouTube evidence ID", 128)?))
    }

    fn from_digest(digest: String) -> Result<Self, YouTubeError> {
        Self::new(digest)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubeVerificationStatus {
    Confirmed,
    Rejected,
    Inconclusive,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubePublishReceiptEvidence {
    receipt_id: YouTubeEvidenceId,
    plugin: YouTubePluginIdentity,
    effect_id: super::YouTubeEffectId,
    effect_revision: u64,
    effect_digest: String,
    binding: YouTubePublishBinding,
    video_id: YouTubeVideoId,
    idempotency_key: super::YouTubeIdempotencyKey,
    request_digest: String,
    provider_request_digest: String,
    provider_response_digest: String,
    accepted_at: DateTime<Utc>,
    provenance: YouTubeEvidenceProvenance,
}

impl YouTubePublishReceiptEvidence {
    pub fn new(
        effect: &YouTubeAuthorizedPublishEffect,
        provider_receipt: &YouTubeProviderReceipt,
        now: DateTime<Utc>,
    ) -> Result<Self, YouTubeError> {
        effect.validate_at(now)?;
        if provider_receipt.provider() != super::YouTubeProviderId::YouTube
            || provider_receipt.binding() != effect.binding()
            || provider_receipt.request_digest() != effect.request().request_digest()
            || provider_receipt.idempotency_key() != effect.request().idempotency_key()
            || provider_receipt.observed_at() < effect.authorized_at()
            || !is_sha256(provider_receipt.provider_request_digest())
            || !is_sha256(provider_receipt.response_digest())
        {
            return Err(YouTubeError::EffectBoundaryMismatch);
        }
        if provider_receipt.observed_at() >= effect.valid_until() {
            return Err(YouTubeError::EffectExpired);
        }
        let receipt_id = YouTubeEvidenceId::from_digest(sha256_json(&serde_json::json!({
            "schema": "hartevo-youtube-publish-receipt/v1",
            "effect_id": effect.effect_id(),
            "effect_revision": effect.effect_revision(),
            "effect_digest": effect.effect_digest(),
            "provider_request_digest": provider_receipt.provider_request_digest(),
            "provider_response_digest": provider_receipt.response_digest(),
            "video_id": provider_receipt.video_id(),
            "idempotency_key": provider_receipt.idempotency_key(),
        })))?;
        Ok(Self {
            receipt_id,
            plugin: effect.plugin().clone(),
            effect_id: effect.effect_id().clone(),
            effect_revision: effect.effect_revision(),
            effect_digest: effect.effect_digest().to_owned(),
            binding: effect.binding().clone(),
            video_id: provider_receipt.video_id().clone(),
            idempotency_key: provider_receipt.idempotency_key().clone(),
            request_digest: provider_receipt.request_digest().to_owned(),
            provider_request_digest: provider_receipt.provider_request_digest().to_owned(),
            provider_response_digest: provider_receipt.response_digest().to_owned(),
            accepted_at: provider_receipt.observed_at(),
            provenance: provider_receipt.provenance(),
        })
    }

    pub const fn receipt_id(&self) -> &YouTubeEvidenceId {
        &self.receipt_id
    }

    pub const fn plugin(&self) -> &YouTubePluginIdentity {
        &self.plugin
    }

    pub const fn effect_id(&self) -> &super::YouTubeEffectId {
        &self.effect_id
    }

    pub const fn effect_revision(&self) -> u64 {
        self.effect_revision
    }

    pub fn effect_digest(&self) -> &str {
        &self.effect_digest
    }

    pub const fn binding(&self) -> &YouTubePublishBinding {
        &self.binding
    }

    pub const fn video_id(&self) -> &YouTubeVideoId {
        &self.video_id
    }

    pub const fn idempotency_key(&self) -> &super::YouTubeIdempotencyKey {
        &self.idempotency_key
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn provider_request_digest(&self) -> &str {
        &self.provider_request_digest
    }

    pub fn provider_response_digest(&self) -> &str {
        &self.provider_response_digest
    }

    pub const fn accepted_at(&self) -> DateTime<Utc> {
        self.accepted_at
    }

    pub const fn provenance(&self) -> YouTubeEvidenceProvenance {
        self.provenance
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubePublishVerificationEvidence {
    verification_id: YouTubeEvidenceId,
    receipt_id: YouTubeEvidenceId,
    plugin: YouTubePluginIdentity,
    effect_id: super::YouTubeEffectId,
    effect_revision: u64,
    effect_digest: String,
    binding: YouTubePublishBinding,
    video_id: YouTubeVideoId,
    channel_id: super::YouTubeChannelId,
    status: YouTubeVerificationStatus,
    verifier: YouTubePluginIdentity,
    independent: bool,
    readback: YouTubeReadbackReceipt,
    evidence_digest: String,
    observed_at: DateTime<Utc>,
    provenance: YouTubeEvidenceProvenance,
}

impl YouTubePublishVerificationEvidence {
    fn new(
        receipt: &YouTubePublishReceiptEvidence,
        readback: YouTubeReadbackReceipt,
        verifier: YouTubePluginIdentity,
        status: YouTubeVerificationStatus,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, YouTubeError> {
        if readback.binding() != receipt.binding()
            || readback.video_id() != receipt.video_id()
            || readback.channel_id() != receipt.binding().channel_id()
            || readback.provenance() != receipt.provenance()
            || observed_at < receipt.accepted_at()
            || !is_sha256(readback.provider_request_digest())
            || !is_sha256(readback.response_digest())
        {
            return Err(YouTubeError::VerificationRejected);
        }
        let evidence_digest = sha256_json(&serde_json::json!({
            "schema": "hartevo-youtube-publish-verification/v1",
            "receipt_id": receipt.receipt_id(),
            "plugin": receipt.plugin(),
            "verifier": verifier,
            "effect_id": receipt.effect_id(),
            "effect_revision": receipt.effect_revision(),
            "effect_digest": receipt.effect_digest(),
            "binding": receipt.binding(),
            "video_id": receipt.video_id(),
            "channel_id": readback.channel_id(),
            "status": status,
            "readback_provider_request_digest": readback.provider_request_digest(),
            "readback_response_digest": readback.response_digest(),
            "provenance": readback.provenance(),
            "observed_at": observed_at,
        }));
        let verification_id = YouTubeEvidenceId::from_digest(evidence_digest.clone())?;
        Ok(Self {
            verification_id,
            receipt_id: receipt.receipt_id().clone(),
            plugin: receipt.plugin().clone(),
            effect_id: receipt.effect_id().clone(),
            effect_revision: receipt.effect_revision(),
            effect_digest: receipt.effect_digest().to_owned(),
            binding: receipt.binding().clone(),
            video_id: receipt.video_id().clone(),
            channel_id: readback.channel_id().clone(),
            status,
            verifier,
            independent: true,
            provenance: readback.provenance(),
            readback,
            evidence_digest,
            observed_at,
        })
    }

    pub const fn verification_id(&self) -> &YouTubeEvidenceId {
        &self.verification_id
    }

    pub const fn receipt_id(&self) -> &YouTubeEvidenceId {
        &self.receipt_id
    }

    pub const fn plugin(&self) -> &YouTubePluginIdentity {
        &self.plugin
    }

    pub const fn effect_id(&self) -> &super::YouTubeEffectId {
        &self.effect_id
    }

    pub const fn effect_revision(&self) -> u64 {
        self.effect_revision
    }

    pub fn effect_digest(&self) -> &str {
        &self.effect_digest
    }

    pub const fn binding(&self) -> &YouTubePublishBinding {
        &self.binding
    }

    pub const fn video_id(&self) -> &YouTubeVideoId {
        &self.video_id
    }

    pub const fn channel_id(&self) -> &super::YouTubeChannelId {
        &self.channel_id
    }

    pub const fn status(&self) -> YouTubeVerificationStatus {
        self.status
    }

    pub const fn verifier(&self) -> &YouTubePluginIdentity {
        &self.verifier
    }

    pub const fn independent(&self) -> bool {
        self.independent
    }

    pub const fn readback(&self) -> &YouTubeReadbackReceipt {
        &self.readback
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn provenance(&self) -> YouTubeEvidenceProvenance {
        self.provenance
    }

    fn validate_against(
        &self,
        receipt: &YouTubePublishReceiptEvidence,
    ) -> Result<(), YouTubeError> {
        let expected_digest = self.canonical_digest();
        let expected_id = YouTubeEvidenceId::from_digest(expected_digest.clone())?;
        if self.verification_id != expected_id
            || self.evidence_digest != expected_digest
            || self.receipt_id != *receipt.receipt_id()
            || self.plugin != *receipt.plugin()
            || self.effect_id != *receipt.effect_id()
            || self.effect_revision != receipt.effect_revision()
            || self.effect_digest != receipt.effect_digest()
            || self.binding != *receipt.binding()
            || self.video_id != *receipt.video_id()
            || self.channel_id != *self.binding.channel_id()
            || self.provenance != self.readback.provenance()
            || !self.independent
            || !is_sha256(&self.evidence_digest)
        {
            return Err(YouTubeError::InvalidCheckpoint);
        }
        Ok(())
    }

    fn canonical_digest(&self) -> String {
        sha256_json(&serde_json::json!({
            "schema": "hartevo-youtube-publish-verification/v1",
            "receipt_id": self.receipt_id,
            "plugin": self.plugin,
            "verifier": self.verifier,
            "effect_id": self.effect_id,
            "effect_revision": self.effect_revision,
            "effect_digest": self.effect_digest,
            "binding": self.binding,
            "video_id": self.video_id,
            "channel_id": self.channel_id,
            "status": self.status,
            "readback_provider_request_digest": self.readback.provider_request_digest(),
            "readback_response_digest": self.readback.response_digest(),
            "provenance": self.provenance,
            "observed_at": self.observed_at,
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubePublishOutcomeEvidence {
    outcome_id: YouTubeEvidenceId,
    receipt: YouTubePublishReceiptEvidence,
    verification: YouTubePublishVerificationEvidence,
    effect_id: super::YouTubeEffectId,
    effect_revision: u64,
    effect_digest: String,
    binding: YouTubePublishBinding,
    video_id: YouTubeVideoId,
    channel_id: super::YouTubeChannelId,
    title: String,
    visibility: super::YouTubeVisibility,
    schedule: Option<super::YouTubeSchedule>,
    observed_at: DateTime<Utc>,
    outcome_digest: String,
}

impl YouTubePublishOutcomeEvidence {
    fn new(
        receipt: YouTubePublishReceiptEvidence,
        verification: YouTubePublishVerificationEvidence,
    ) -> Result<Self, YouTubeError> {
        if verification.status() != YouTubeVerificationStatus::Confirmed
            || !verification.readback().is_ready()
            || verification.receipt_id() != receipt.receipt_id()
        {
            return Err(YouTubeError::VerificationRejected);
        }
        let readback = verification.readback();
        let outcome_digest = sha256_json(&serde_json::json!({
            "schema": "hartevo-youtube-publish-outcome/v1",
            "receipt_id": receipt.receipt_id(),
            "verification_id": verification.verification_id(),
            "effect_id": receipt.effect_id(),
            "effect_revision": receipt.effect_revision(),
            "effect_digest": receipt.effect_digest(),
            "binding": receipt.binding(),
            "video_id": readback.video_id(),
            "channel_id": readback.channel_id(),
            "title": readback.title(),
            "visibility": readback.visibility(),
            "schedule": readback.schedule(),
            "readback_response_digest": readback.response_digest(),
            "observed_at": readback.observed_at(),
        }));
        let outcome_id = YouTubeEvidenceId::from_digest(outcome_digest.clone())?;
        Ok(Self {
            outcome_id,
            effect_id: receipt.effect_id().clone(),
            effect_revision: receipt.effect_revision(),
            effect_digest: receipt.effect_digest().to_owned(),
            binding: receipt.binding().clone(),
            video_id: readback.video_id().clone(),
            channel_id: readback.channel_id().clone(),
            title: readback.title().to_owned(),
            visibility: readback.visibility().clone(),
            schedule: readback.schedule(),
            observed_at: readback.observed_at(),
            outcome_digest,
            receipt,
            verification,
        })
    }

    pub const fn outcome_id(&self) -> &YouTubeEvidenceId {
        &self.outcome_id
    }

    pub const fn receipt(&self) -> &YouTubePublishReceiptEvidence {
        &self.receipt
    }

    pub const fn verification(&self) -> &YouTubePublishVerificationEvidence {
        &self.verification
    }

    pub const fn effect_id(&self) -> &super::YouTubeEffectId {
        &self.effect_id
    }

    pub const fn effect_revision(&self) -> u64 {
        self.effect_revision
    }

    pub fn effect_digest(&self) -> &str {
        &self.effect_digest
    }

    pub const fn binding(&self) -> &YouTubePublishBinding {
        &self.binding
    }

    pub const fn video_id(&self) -> &YouTubeVideoId {
        &self.video_id
    }

    pub const fn channel_id(&self) -> &super::YouTubeChannelId {
        &self.channel_id
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub const fn visibility(&self) -> &super::YouTubeVisibility {
        &self.visibility
    }

    pub const fn schedule(&self) -> Option<super::YouTubeSchedule> {
        self.schedule
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn outcome_digest(&self) -> &str {
        &self.outcome_digest
    }

    pub const fn provenance(&self) -> YouTubeEvidenceProvenance {
        self.verification.provenance()
    }

    fn validate_against(
        &self,
        receipt: &YouTubePublishReceiptEvidence,
        verification: &YouTubePublishVerificationEvidence,
    ) -> Result<(), YouTubeError> {
        let expected_digest = self.canonical_digest();
        let expected_id = YouTubeEvidenceId::from_digest(expected_digest.clone())?;
        if self.outcome_id != expected_id
            || self.outcome_digest != expected_digest
            || self.receipt != *receipt
            || self.verification != *verification
            || self.effect_id != *receipt.effect_id()
            || self.effect_revision != receipt.effect_revision()
            || self.effect_digest != receipt.effect_digest()
            || self.binding != *receipt.binding()
            || self.video_id != *verification.readback().video_id()
            || self.channel_id != *verification.readback().channel_id()
            || self.title != verification.readback().title()
            || self.visibility != *verification.readback().visibility()
            || self.schedule != verification.readback().schedule()
            || self.observed_at != verification.readback().observed_at()
            || !is_sha256(&self.outcome_digest)
        {
            return Err(YouTubeError::InvalidCheckpoint);
        }
        Ok(())
    }

    fn canonical_digest(&self) -> String {
        let readback = self.verification.readback();
        sha256_json(&serde_json::json!({
            "schema": "hartevo-youtube-publish-outcome/v1",
            "receipt_id": self.receipt.receipt_id(),
            "verification_id": self.verification.verification_id(),
            "effect_id": self.receipt.effect_id(),
            "effect_revision": self.receipt.effect_revision(),
            "effect_digest": self.receipt.effect_digest(),
            "binding": self.receipt.binding(),
            "video_id": readback.video_id(),
            "channel_id": readback.channel_id(),
            "title": readback.title(),
            "visibility": readback.visibility(),
            "schedule": readback.schedule(),
            "readback_response_digest": readback.response_digest(),
            "observed_at": readback.observed_at(),
        }))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubeVerificationInvalidationReason {
    CredentialRotated,
    CredentialRevoked,
    CredentialUnmounted,
    ScopeDrift,
    EffectExpired,
    PluginDrift,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubePublishVerificationPhase {
    AwaitingReadback,
    Pending,
    Completed,
    Rejected {
        at: DateTime<Utc>,
    },
    Invalidated {
        reason: YouTubeVerificationInvalidationReason,
        at: DateTime<Utc>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubePublishVerificationCheckpoint {
    effect: YouTubeAuthorizedPublishEffect,
    provider_receipt: YouTubeProviderReceipt,
    receipt_evidence: YouTubePublishReceiptEvidence,
    phase: YouTubePublishVerificationPhase,
    credential_generation: Option<u64>,
    credential_scope_digest: Option<String>,
    credential_reference_digest: Option<String>,
    readback: Option<YouTubeReadbackReceipt>,
    verification: Option<YouTubePublishVerificationEvidence>,
    outcome: Option<YouTubePublishOutcomeEvidence>,
    retry_after: Option<YouTubeRetryAfterReceipt>,
}

impl YouTubePublishVerificationCheckpoint {
    pub fn new(
        effect: YouTubeAuthorizedPublishEffect,
        provider_receipt: YouTubeProviderReceipt,
    ) -> Result<Self, YouTubeError> {
        let receipt_evidence =
            YouTubePublishReceiptEvidence::new(&effect, &provider_receipt, effect.authorized_at())?;
        let checkpoint = Self {
            effect,
            provider_receipt,
            receipt_evidence,
            phase: YouTubePublishVerificationPhase::AwaitingReadback,
            credential_generation: None,
            credential_scope_digest: None,
            credential_reference_digest: None,
            readback: None,
            verification: None,
            outcome: None,
            retry_after: None,
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub const fn effect(&self) -> &YouTubeAuthorizedPublishEffect {
        &self.effect
    }

    pub const fn provider_receipt(&self) -> &YouTubeProviderReceipt {
        &self.provider_receipt
    }

    pub const fn receipt_evidence(&self) -> &YouTubePublishReceiptEvidence {
        &self.receipt_evidence
    }

    pub const fn phase(&self) -> &YouTubePublishVerificationPhase {
        &self.phase
    }

    pub const fn readback(&self) -> Option<&YouTubeReadbackReceipt> {
        self.readback.as_ref()
    }

    pub const fn verification(&self) -> Option<&YouTubePublishVerificationEvidence> {
        self.verification.as_ref()
    }

    pub const fn outcome(&self) -> Option<&YouTubePublishOutcomeEvidence> {
        self.outcome.as_ref()
    }

    pub const fn retry_after(&self) -> Option<&YouTubeRetryAfterReceipt> {
        self.retry_after.as_ref()
    }

    pub const fn credential_generation(&self) -> Option<u64> {
        self.credential_generation
    }

    pub fn credential_scope_digest(&self) -> Option<&str> {
        self.credential_scope_digest.as_deref()
    }

    pub fn checkpoint_json(&self) -> Result<String, YouTubeError> {
        self.validate()?;
        serde_json::to_string(self).map_err(|_| {
            YouTubeError::InvalidRequest("YouTube verification checkpoint serialization failed")
        })
    }

    pub fn from_checkpoint_json(value: &str) -> Result<Self, YouTubeError> {
        let checkpoint: Self = serde_json::from_str(value)
            .map_err(|_| YouTubeError::InvalidRequest("invalid YouTube verification checkpoint"))?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub fn durable_digest(&self) -> String {
        serde_json::to_value(self)
            .map(|value| sha256_json(&value))
            .unwrap_or_else(|_| "0".repeat(64))
    }

    fn require_dispatchable(&self) -> Result<(), YouTubeError> {
        match self.phase {
            YouTubePublishVerificationPhase::Invalidated { .. } => {
                Err(YouTubeError::VerificationCheckpointInvalidated)
            }
            YouTubePublishVerificationPhase::Rejected { .. } => {
                Err(YouTubeError::VerificationRejected)
            }
            _ => Ok(()),
        }
    }

    fn bind_credential(
        &mut self,
        credential: &YouTubeCredential,
        now: DateTime<Utc>,
    ) -> Result<(), YouTubeError> {
        self.require_dispatchable()?;
        if credential.binding() != self.effect.binding() {
            if credential.binding().tenant_id() == self.effect.binding().tenant_id()
                && credential.binding().business_id() == self.effect.binding().business_id()
                && credential.binding().account_id() == self.effect.binding().account_id()
                && credential.binding().channel_id() == self.effect.binding().channel_id()
            {
                self.invalidate(
                    YouTubeVerificationInvalidationReason::CredentialRotated,
                    now,
                );
                return Err(YouTubeError::VerificationCheckpointInvalidated);
            }
            return Err(YouTubeError::ScopeMismatch);
        }
        let reference_digest = super::credential_reference_digest(credential);
        let scope_digest = credential.scope_digest();
        if scope_digest != self.effect.scope_digest() {
            self.invalidate(YouTubeVerificationInvalidationReason::ScopeDrift, now);
            return Err(YouTubeError::VerificationCheckpointInvalidated);
        }
        let bound = self.credential_generation.is_some();
        if bound
            && (self.credential_generation != Some(credential.generation())
                || self.credential_scope_digest.as_deref() != Some(scope_digest.as_str())
                || self.credential_reference_digest.as_deref() != Some(&reference_digest))
        {
            self.invalidate(
                YouTubeVerificationInvalidationReason::CredentialRotated,
                now,
            );
            return Err(YouTubeError::VerificationCheckpointInvalidated);
        }
        if bound
            && credential
                .unmounted_at()
                .is_some_and(|unmounted_at| unmounted_at <= now)
        {
            self.invalidate(
                YouTubeVerificationInvalidationReason::CredentialUnmounted,
                now,
            );
            return Err(YouTubeError::VerificationCheckpointInvalidated);
        }
        if bound
            && credential
                .revoked_at()
                .is_some_and(|revoked_at| revoked_at <= now)
        {
            self.invalidate(
                YouTubeVerificationInvalidationReason::CredentialRevoked,
                now,
            );
            return Err(YouTubeError::VerificationCheckpointInvalidated);
        }
        if !bound {
            if credential
                .unmounted_at()
                .is_some_and(|unmounted_at| unmounted_at <= now)
            {
                return Err(YouTubeError::CredentialUnmounted);
            }
            if credential
                .revoked_at()
                .is_some_and(|revoked_at| revoked_at <= now)
            {
                return Err(YouTubeError::CredentialRevoked);
            }
            self.credential_generation = Some(credential.generation());
            self.credential_scope_digest = Some(scope_digest);
            self.credential_reference_digest = Some(reference_digest);
        }
        Ok(())
    }

    fn retry_after_if_waiting(&self, now: DateTime<Utc>) -> Option<&YouTubeRetryAfterReceipt> {
        self.retry_after
            .as_ref()
            .filter(|receipt| !receipt.retry_is_due(now))
    }

    fn clear_retry_after(&mut self) {
        self.retry_after = None;
    }

    fn set_retry_after(&mut self, receipt: YouTubeRetryAfterReceipt) {
        self.retry_after = Some(receipt);
    }

    fn set_readback(&mut self, readback: YouTubeReadbackReceipt) {
        self.readback = Some(readback);
        self.phase = YouTubePublishVerificationPhase::Pending;
    }

    fn set_verification(&mut self, verification: YouTubePublishVerificationEvidence) {
        self.verification = Some(verification);
    }

    fn set_outcome(&mut self, outcome: YouTubePublishOutcomeEvidence) {
        self.outcome = Some(outcome);
        self.phase = YouTubePublishVerificationPhase::Completed;
    }

    fn mark_rejected(&mut self, now: DateTime<Utc>) {
        self.phase = YouTubePublishVerificationPhase::Rejected { at: now };
        self.retry_after = None;
        self.readback = None;
        self.verification = None;
        self.outcome = None;
    }

    fn invalidate(&mut self, reason: YouTubeVerificationInvalidationReason, at: DateTime<Utc>) {
        self.phase = YouTubePublishVerificationPhase::Invalidated { reason, at };
        self.retry_after = None;
        self.readback = None;
        self.verification = None;
        self.outcome = None;
    }

    fn validate(&self) -> Result<(), YouTubeError> {
        self.effect.validate_at(self.effect.authorized_at())?;
        let expected_receipt = YouTubePublishReceiptEvidence::new(
            &self.effect,
            &self.provider_receipt,
            self.effect.authorized_at(),
        )?;
        if expected_receipt != self.receipt_evidence
            || self.provider_receipt.binding() != self.effect.binding()
            || self.provider_receipt.request_digest() != self.effect.request().request_digest()
            || self.provider_receipt.idempotency_key() != self.effect.request().idempotency_key()
            || !is_sha256(self.provider_receipt.provider_request_digest())
            || !is_sha256(self.provider_receipt.response_digest())
        {
            return Err(YouTubeError::EffectBoundaryMismatch);
        }
        if self.credential_generation.is_some()
            != (self.credential_scope_digest.is_some()
                && self.credential_reference_digest.is_some())
            || self
                .credential_generation
                .is_some_and(|generation| generation != self.effect.binding().provider_generation())
            || self.credential_scope_digest.as_deref()
                != self
                    .credential_generation
                    .map(|_| self.effect.scope_digest())
            || self
                .credential_scope_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || self
                .credential_reference_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || self
                .retry_after
                .as_ref()
                .is_some_and(|receipt| !is_sha256(receipt.response_digest()))
        {
            return Err(YouTubeError::InvalidCheckpoint);
        }
        if let Some(readback) = &self.readback {
            readback.verify_against(self.effect.request(), &self.provider_receipt)?;
        }
        if let Some(verification) = &self.verification
            && (self.readback.as_ref() != Some(verification.readback())
                || verification.receipt_id() != self.receipt_evidence.receipt_id()
                || verification.effect_id() != self.effect.effect_id()
                || verification.effect_revision() != self.effect.effect_revision()
                || verification.effect_digest() != self.effect.effect_digest()
                || verification.provenance() != self.provider_receipt.provenance()
                || !verification.independent()
                || !is_sha256(verification.evidence_digest()))
        {
            return Err(YouTubeError::InvalidCheckpoint);
        }
        if let Some(verification) = &self.verification {
            verification.validate_against(&self.receipt_evidence)?;
        }
        if let Some(outcome) = &self.outcome
            && (self.verification.as_ref() != Some(outcome.verification())
                || self.receipt_evidence != *outcome.receipt()
                || !is_sha256(outcome.outcome_digest()))
        {
            return Err(YouTubeError::InvalidCheckpoint);
        }
        if let (Some(verification), Some(outcome)) =
            (self.verification.as_ref(), self.outcome.as_ref())
        {
            outcome.validate_against(&self.receipt_evidence, verification)?;
        }
        if let Some(retry_after) = &self.retry_after
            && (retry_after.operation() != YouTubeDispatchOperation::Readback
                || retry_after.binding() != self.effect.binding()
                || retry_after.request_digest() != self.effect.request().request_digest())
        {
            return Err(YouTubeError::InvalidCheckpoint);
        }
        match self.phase {
            YouTubePublishVerificationPhase::AwaitingReadback => {
                if self.readback.is_some() || self.verification.is_some() || self.outcome.is_some()
                {
                    return Err(YouTubeError::InvalidCheckpoint);
                }
            }
            YouTubePublishVerificationPhase::Pending => {
                if self.readback.is_none()
                    || self.verification.as_ref().is_none_or(|verification| {
                        verification.status() != YouTubeVerificationStatus::Inconclusive
                    })
                    || self.outcome.is_some()
                {
                    return Err(YouTubeError::InvalidCheckpoint);
                }
            }
            YouTubePublishVerificationPhase::Completed => {
                if self.readback.is_none()
                    || self.verification.as_ref().is_none_or(|verification| {
                        verification.status() != YouTubeVerificationStatus::Confirmed
                    })
                    || self.outcome.is_none()
                {
                    return Err(YouTubeError::InvalidCheckpoint);
                }
            }
            YouTubePublishVerificationPhase::Rejected { .. }
            | YouTubePublishVerificationPhase::Invalidated { .. } => {
                if self.outcome.is_some()
                    || self.readback.is_some()
                    || self.verification.is_some()
                    || self.retry_after.is_some()
                {
                    return Err(YouTubeError::InvalidCheckpoint);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum YouTubePublishVerificationDispatchResult {
    RetryAfter(YouTubeRetryAfterReceipt),
    Retryable {
        operation: YouTubeDispatchOperation,
        checkpoint_digest: String,
    },
    Pending(YouTubePublishVerificationEvidence),
    Completed(YouTubePublishOutcomeEvidence),
    AlreadyCompleted(YouTubePublishOutcomeEvidence),
}

pub struct YouTubePublishVerificationService<T> {
    provider: YouTubeDataApiProvider<T>,
    quota: super::YouTubeQuotaLedger,
    verifier: YouTubePluginIdentity,
    readback_valid_for: Duration,
}

impl<T> YouTubePublishVerificationService<T> {
    pub fn fixture(transport: T) -> Self {
        Self::with_provider(YouTubeDataApiProvider::fixture(transport))
    }

    pub fn controlled(transport: T) -> Self {
        Self::with_provider(YouTubeDataApiProvider::controlled(transport))
    }

    pub fn fixture_with_quota(transport: T, quota: super::YouTubeQuotaLedger) -> Self {
        let mut service = Self::fixture(transport);
        service.quota = quota;
        service
    }

    fn production(transport: T, gate: super::YouTubeRealPublishGate) -> Self
    where
        T: YouTubeProductionTransport,
    {
        Self::with_provider(YouTubeDataApiProvider::production(
            transport,
            gate.secret_reference().clone(),
        ))
    }

    fn with_provider(provider: YouTubeDataApiProvider<T>) -> Self {
        Self {
            provider,
            quota: super::YouTubeQuotaLedger::default(),
            verifier: YouTubePluginIdentity::youtube_publish_v1(),
            readback_valid_for: Duration::minutes(5),
        }
    }

    pub const fn provenance(&self) -> YouTubeEvidenceProvenance {
        self.provider.provenance()
    }

    pub const fn quota(&self) -> &super::YouTubeQuotaLedger {
        &self.quota
    }

    pub fn quota_mut(&mut self) -> &mut super::YouTubeQuotaLedger {
        &mut self.quota
    }

    pub const fn verifier(&self) -> &YouTubePluginIdentity {
        &self.verifier
    }

    pub fn dispatch(
        &mut self,
        credential: &YouTubeCredential,
        effect: &YouTubeAuthorizedPublishEffect,
        checkpoint: &mut YouTubePublishVerificationCheckpoint,
        now: DateTime<Utc>,
    ) -> Result<YouTubePublishVerificationDispatchResult, YouTubeError>
    where
        T: super::provider::YouTubePublishTransport,
    {
        if checkpoint.effect() != effect {
            if checkpoint.effect().effect_id() == effect.effect_id()
                && checkpoint.effect().effect_revision() != effect.effect_revision()
            {
                return Err(YouTubeError::EffectRevisionMismatch);
            }
            return Err(YouTubeError::EffectBoundaryMismatch);
        }
        if effect.plugin() != &self.verifier {
            checkpoint.invalidate(YouTubeVerificationInvalidationReason::PluginDrift, now);
            return Err(YouTubeError::PluginRevisionMismatch);
        }
        if let Err(error) = effect.validate_at(now) {
            if error == YouTubeError::EffectExpired {
                checkpoint.invalidate(YouTubeVerificationInvalidationReason::EffectExpired, now);
            }
            return Err(error);
        }
        checkpoint.bind_credential(credential, now)?;
        if let Err(error) =
            credential.require_for(YouTubeDispatchOperation::Readback, effect.binding(), now)
        {
            return self.handle_credential_error(checkpoint, error, now);
        }
        if let Some(receipt) = checkpoint.retry_after_if_waiting(now) {
            return Ok(YouTubePublishVerificationDispatchResult::RetryAfter(
                receipt.clone(),
            ));
        }
        checkpoint.clear_retry_after();
        checkpoint.require_dispatchable()?;
        if let YouTubePublishVerificationPhase::Completed = checkpoint.phase() {
            return Ok(YouTubePublishVerificationDispatchResult::AlreadyCompleted(
                checkpoint
                    .outcome()
                    .cloned()
                    .ok_or(YouTubeError::InvalidCheckpoint)?,
            ));
        }

        self.quota.reserve(YouTubeDispatchOperation::Readback)?;
        let provider_receipt = checkpoint.provider_receipt().clone();
        let readback = match self.provider.readback(
            credential,
            effect.request(),
            &provider_receipt,
            self.readback_valid_for,
        ) {
            Ok(readback) => readback,
            Err(error) => {
                if matches!(error, YouTubeError::ReadbackMismatch) {
                    checkpoint.mark_rejected(now);
                }
                return self.handle_provider_error(
                    checkpoint,
                    YouTubeDispatchOperation::Readback,
                    error,
                    now,
                );
            }
        };
        readback.validate_at(now)?;
        if readback.provenance() != provider_receipt.provenance() {
            checkpoint.mark_rejected(now);
            return Err(YouTubeError::ReadbackMismatch);
        }
        if let Err(error) = readback.verify_against(effect.request(), &provider_receipt) {
            checkpoint.mark_rejected(now);
            return Err(error);
        }
        let status = if readback.is_ready() {
            YouTubeVerificationStatus::Confirmed
        } else {
            YouTubeVerificationStatus::Inconclusive
        };
        let verification = YouTubePublishVerificationEvidence::new(
            checkpoint.receipt_evidence(),
            readback.clone(),
            self.verifier.clone(),
            status,
            now,
        )?;
        checkpoint.set_readback(readback);
        checkpoint.set_verification(verification.clone());
        if status == YouTubeVerificationStatus::Inconclusive {
            return Ok(YouTubePublishVerificationDispatchResult::Pending(
                verification,
            ));
        }
        let outcome = YouTubePublishOutcomeEvidence::new(
            checkpoint.receipt_evidence().clone(),
            verification,
        )?;
        checkpoint.set_outcome(outcome.clone());
        Ok(YouTubePublishVerificationDispatchResult::Completed(outcome))
    }

    fn handle_credential_error(
        &self,
        checkpoint: &mut YouTubePublishVerificationCheckpoint,
        error: YouTubeError,
        now: DateTime<Utc>,
    ) -> Result<YouTubePublishVerificationDispatchResult, YouTubeError> {
        match error {
            YouTubeError::CredentialGenerationMismatch => {
                checkpoint.invalidate(
                    YouTubeVerificationInvalidationReason::CredentialRotated,
                    now,
                );
                Err(YouTubeError::VerificationCheckpointInvalidated)
            }
            YouTubeError::CredentialRevoked => {
                checkpoint.invalidate(
                    YouTubeVerificationInvalidationReason::CredentialRevoked,
                    now,
                );
                Err(YouTubeError::VerificationCheckpointInvalidated)
            }
            YouTubeError::CredentialUnmounted => {
                checkpoint.invalidate(
                    YouTubeVerificationInvalidationReason::CredentialUnmounted,
                    now,
                );
                Err(YouTubeError::VerificationCheckpointInvalidated)
            }
            YouTubeError::MissingScope { .. } | YouTubeError::ScopeMismatch => {
                checkpoint.invalidate(YouTubeVerificationInvalidationReason::ScopeDrift, now);
                Err(YouTubeError::VerificationCheckpointInvalidated)
            }
            other => Err(other),
        }
    }

    fn handle_provider_error(
        &self,
        checkpoint: &mut YouTubePublishVerificationCheckpoint,
        operation: YouTubeDispatchOperation,
        error: YouTubeError,
        now: DateTime<Utc>,
    ) -> Result<YouTubePublishVerificationDispatchResult, YouTubeError> {
        match error {
            YouTubeError::RetryAfter(receipt) => {
                let receipt = *receipt;
                checkpoint.set_retry_after(receipt.clone());
                Ok(YouTubePublishVerificationDispatchResult::RetryAfter(
                    receipt,
                ))
            }
            error if error.is_retryable() => {
                Ok(YouTubePublishVerificationDispatchResult::Retryable {
                    operation,
                    checkpoint_digest: checkpoint.durable_digest(),
                })
            }
            YouTubeError::CredentialRevoked => {
                checkpoint.invalidate(
                    YouTubeVerificationInvalidationReason::CredentialRevoked,
                    now,
                );
                Err(YouTubeError::VerificationCheckpointInvalidated)
            }
            error => Err(error),
        }
    }
}

pub fn execute_real_publish_verification_gate<T>(
    transport: T,
) -> Result<YouTubePublishVerificationService<T>, YouTubeError>
where
    T: YouTubeProductionTransport,
{
    let gate = super::YouTubeRealPublishGate::from_env()?;
    Ok(YouTubePublishVerificationService::production(
        transport, gate,
    ))
}
