//! Controlled Reddit post/reply effects over the approved Reddit Data API.
//!
//! This module deliberately keeps the effect boundary local to the Reddit
//! adapter.  `prepare` performs only authenticated reads, `execute` performs
//! at most one provider write, and `reconcile` performs a separate readback.
//! No HTML/browser fallback is available here.  The caller must supply an
//! already authority-bound approval ingress before `execute` can dispatch.

use std::{
    collections::BTreeSet,
    fmt,
    io::Write as _,
    process::{Command, Stdio},
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::{
    identity::{
        AccountIdentity, ContentIdentity, ProviderId, RedditAccountId, RedditAccountIdentity,
        RedditCommunityIdentity, RedditContentIdentity, RedditRevisionIdentity, RedditRevisionKey,
        RedditSubredditId, RedditSubredditName, RedditThingId, RedditThingKind, RevisionIdentity,
    },
    reddit::{
        REDDIT_OAUTH_API_BASE_URL, RedditDataApiApproval, RedditModerationState,
        RedditRemovalReason, RedditScope,
    },
    transport::{
        AuthorizationReason, ChannelAdapterError, CredentialReference, HttpMethod,
        ProviderResponse, ScopeName, TransportError, hex_digest,
    },
};

pub const REDDIT_EFFECT_API_BASE_URL: &str = "https://oauth.reddit.com";
pub const REDDIT_REAL_EFFECT_ENABLE_ENV: &str = "HARTEVO_REDDIT_REAL_EFFECT";
pub const REDDIT_REAL_EFFECT_SECRET_REFERENCE_ENV: &str = "HARTEVO_REDDIT_SECRET_REFERENCE";
pub const REDDIT_REAL_EFFECT_ACCESS_TOKEN_ENV: &str = "HARTEVO_REDDIT_ACCESS_TOKEN";
pub const REDDIT_REAL_EFFECT_APPROVAL_REFERENCE_ENV: &str = "HARTEVO_REDDIT_APPROVAL_REFERENCE";
pub const REDDIT_EFFECT_DEFAULT_QUOTA_PER_MINUTE: u32 = 100;

macro_rules! opaque_identifier {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ChannelAdapterError> {
                let value = value.into();
                validate_opaque(&value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

opaque_identifier!(RedditEffectAppId);
opaque_identifier!(RedditEffectId);
opaque_identifier!(RedditIdempotencyKey);
opaque_identifier!(RedditApprovalRevision);

fn validate_opaque(value: &str) -> Result<(), ChannelAdapterError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_whitespace) {
        return Err(ChannelAdapterError::InvalidRequest(
            "Reddit effect identifiers must be non-empty and opaque",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedditEffectProvenance {
    ProductionApprovedDataApi,
    DeterministicFixture,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedditPublishOperation {
    Post,
    Reply,
}

impl RedditPublishOperation {
    const fn expected_kind(self) -> RedditThingKind {
        match self {
            Self::Post => RedditThingKind::Post,
            Self::Reply => RedditThingKind::Comment,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditEffectScope {
    app: RedditEffectAppId,
    account: RedditAccountIdentity,
    subreddit: RedditCommunityIdentity,
    parent: Option<RedditThingId>,
}

impl RedditEffectScope {
    pub fn new(
        app: RedditEffectAppId,
        account: RedditAccountIdentity,
        subreddit: RedditCommunityIdentity,
        parent: Option<RedditThingId>,
    ) -> Self {
        Self {
            app,
            account,
            subreddit,
            parent,
        }
    }

    pub const fn app(&self) -> &RedditEffectAppId {
        &self.app
    }

    pub const fn account(&self) -> &RedditAccountIdentity {
        &self.account
    }

    pub const fn subreddit(&self) -> &RedditCommunityIdentity {
        &self.subreddit
    }

    pub const fn parent(&self) -> Option<&RedditThingId> {
        self.parent.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditPublishIntent {
    operation: RedditPublishOperation,
    scope: RedditEffectScope,
    title: Option<String>,
    body: String,
    idempotency_key: RedditIdempotencyKey,
}

impl RedditPublishIntent {
    pub fn new(
        operation: RedditPublishOperation,
        scope: RedditEffectScope,
        title: Option<String>,
        body: impl Into<String>,
        idempotency_key: RedditIdempotencyKey,
    ) -> Result<Self, RedditEffectError> {
        let body = body.into();
        if body.is_empty() || body.len() > 40_000 {
            return Err(RedditEffectError::InvalidRequest(
                "Reddit post/reply body must be non-empty and at most 40000 bytes",
            ));
        }
        match operation {
            RedditPublishOperation::Post => {
                let title = title.as_deref().ok_or(RedditEffectError::InvalidRequest(
                    "Reddit posts require a title",
                ))?;
                if title.is_empty() || title.len() > 300 {
                    return Err(RedditEffectError::InvalidRequest(
                        "Reddit post title must be non-empty and at most 300 bytes",
                    ));
                }
                if scope.parent().is_some() {
                    return Err(RedditEffectError::ScopeMismatch(
                        "a post scope cannot bind a parent",
                    ));
                }
            }
            RedditPublishOperation::Reply => {
                if title.is_some() {
                    return Err(RedditEffectError::InvalidRequest(
                        "Reddit replies cannot carry a post title",
                    ));
                }
                if scope.parent().is_none() {
                    return Err(RedditEffectError::ScopeMismatch(
                        "a reply scope must bind a parent fullname",
                    ));
                }
            }
        }
        Ok(Self {
            operation,
            scope,
            title,
            body,
            idempotency_key,
        })
    }

    pub const fn operation(&self) -> RedditPublishOperation {
        self.operation
    }

    pub const fn scope(&self) -> &RedditEffectScope {
        &self.scope
    }

    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    pub fn body(&self) -> &str {
        &self.body
    }

    pub const fn idempotency_key(&self) -> &RedditIdempotencyKey {
        &self.idempotency_key
    }
}

/// This value is created by an authority after approval.  The service accepts
/// it but never derives or manufactures one during preparation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditApprovedEffectIngress {
    effect_id: RedditEffectId,
    scope: RedditEffectScope,
    draft_revision: String,
    content_digest: String,
    idempotency_key: RedditIdempotencyKey,
    credential_generation: u64,
    authorization_digest: String,
    approval_revision: RedditApprovalRevision,
    approved_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl RedditApprovedEffectIngress {
    /// Authority code should call this only after recording an explicit user
    /// approval bound to the exact draft and provider scope.
    #[allow(clippy::too_many_arguments)]
    pub fn new_authority_bound(
        effect_id: RedditEffectId,
        scope: RedditEffectScope,
        draft_revision: impl Into<String>,
        content_digest: impl Into<String>,
        idempotency_key: RedditIdempotencyKey,
        credential_generation: u64,
        authorization_digest: impl Into<String>,
        approval_revision: RedditApprovalRevision,
        approved_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, RedditEffectError> {
        let draft_revision = draft_revision.into();
        let content_digest = content_digest.into();
        let authorization_digest = authorization_digest.into();
        validate_digest(&draft_revision)?;
        validate_digest(&content_digest)?;
        validate_digest(&authorization_digest)?;
        if expires_at <= approved_at {
            return Err(RedditEffectError::InvalidRequest(
                "effect approval expiry must be after approval time",
            ));
        }
        Ok(Self {
            effect_id,
            scope,
            draft_revision,
            content_digest,
            idempotency_key,
            credential_generation,
            authorization_digest,
            approval_revision,
            approved_at,
            expires_at,
        })
    }

    pub const fn effect_id(&self) -> &RedditEffectId {
        &self.effect_id
    }

    pub const fn scope(&self) -> &RedditEffectScope {
        &self.scope
    }

    pub fn draft_revision(&self) -> &str {
        &self.draft_revision
    }

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    pub const fn idempotency_key(&self) -> &RedditIdempotencyKey {
        &self.idempotency_key
    }

    pub const fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    pub fn authorization_digest(&self) -> &str {
        &self.authorization_digest
    }

    pub const fn approval_revision(&self) -> &RedditApprovalRevision {
        &self.approval_revision
    }

    pub const fn approved_at(&self) -> DateTime<Utc> {
        self.approved_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedditCredentialState {
    Active,
    Revoked,
    Unmounted,
}

#[derive(Clone, Debug)]
pub struct RedditEffectCredential {
    app: RedditEffectAppId,
    account: RedditAccountIdentity,
    approval: RedditDataApiApproval,
    granted_scopes: BTreeSet<RedditScope>,
    reference: CredentialReference,
    generation: u64,
    expires_at: Option<DateTime<Utc>>,
    state: RedditCredentialState,
}

impl RedditEffectCredential {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app: RedditEffectAppId,
        account: RedditAccountIdentity,
        approval: RedditDataApiApproval,
        granted_scopes: BTreeSet<RedditScope>,
        reference: CredentialReference,
        generation: u64,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            app,
            account,
            approval,
            granted_scopes,
            reference,
            generation,
            expires_at,
            state: RedditCredentialState::Active,
        }
    }

    pub const fn app(&self) -> &RedditEffectAppId {
        &self.app
    }

    pub const fn account(&self) -> &RedditAccountIdentity {
        &self.account
    }

    pub const fn approval(&self) -> &RedditDataApiApproval {
        &self.approval
    }

    pub const fn granted_scopes(&self) -> &BTreeSet<RedditScope> {
        &self.granted_scopes
    }

    pub const fn reference(&self) -> &CredentialReference {
        &self.reference
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn state(&self) -> RedditCredentialState {
        self.state
    }

    pub const fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    #[must_use]
    pub fn with_state(mut self, state: RedditCredentialState) -> Self {
        self.state = state;
        self
    }

    fn require(&self, scope: RedditScope, now: DateTime<Utc>) -> Result<(), RedditEffectError> {
        self.assert_usable(now)?;
        if !self.approval.scopes().contains(&scope) {
            return Err(RedditEffectError::AuthorizationRequired(
                AuthorizationReason::MissingApproval,
            ));
        }
        if !self.granted_scopes.contains(&scope) {
            return Err(RedditEffectError::Adapter(
                ChannelAdapterError::ScopeNotGranted {
                    provider: ProviderId::Reddit,
                    scope: ScopeName::new(scope.as_str())?,
                },
            ));
        }
        Ok(())
    }

    fn assert_usable(&self, now: DateTime<Utc>) -> Result<(), RedditEffectError> {
        match self.state {
            RedditCredentialState::Active => {}
            RedditCredentialState::Revoked => {
                return Err(RedditEffectError::CredentialRevoked);
            }
            RedditCredentialState::Unmounted => {
                return Err(RedditEffectError::CredentialUnmounted);
            }
        }
        if self.expires_at.is_some_and(|expires_at| now >= expires_at) {
            return Err(RedditEffectError::CredentialExpired);
        }
        Ok(())
    }
}

fn authorization_digest(credential: &RedditEffectCredential) -> String {
    digest_json(&json!({
        "approval_reference": credential.approval.approval_reference(),
        "approval_scopes": credential.approval.scopes(),
        "granted_scopes": &credential.granted_scopes,
    }))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditAccountProbe {
    account: RedditAccountIdentity,
    response_digest: String,
    observed_at: DateTime<Utc>,
}

impl RedditAccountProbe {
    pub const fn account(&self) -> &RedditAccountIdentity {
        &self.account
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::struct_excessive_bools)]
pub struct RedditSubredditPolicy {
    community: RedditCommunityIdentity,
    post_allowed: bool,
    reply_allowed: bool,
    account_banned: bool,
    archived: bool,
    rules_digest: String,
    requirements_digest: String,
    source_digest: String,
    title_min_length: Option<u32>,
    title_max_length: Option<u32>,
    body_min_length: Option<u32>,
    body_max_length: Option<u32>,
    observed_at: DateTime<Utc>,
}

impl RedditSubredditPolicy {
    pub const fn community(&self) -> &RedditCommunityIdentity {
        &self.community
    }

    pub const fn post_allowed(&self) -> bool {
        self.post_allowed
    }

    pub const fn reply_allowed(&self) -> bool {
        self.reply_allowed
    }

    pub const fn account_banned(&self) -> bool {
        self.account_banned
    }

    pub const fn archived(&self) -> bool {
        self.archived
    }

    pub fn rules_digest(&self) -> &str {
        &self.rules_digest
    }

    pub fn requirements_digest(&self) -> &str {
        &self.requirements_digest
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub const fn title_min_length(&self) -> Option<u32> {
        self.title_min_length
    }

    pub const fn title_max_length(&self) -> Option<u32> {
        self.title_max_length
    }

    pub const fn body_min_length(&self) -> Option<u32> {
        self.body_min_length
    }

    pub const fn body_max_length(&self) -> Option<u32> {
        self.body_max_length
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditParentObservation {
    content: ContentIdentity,
    account: Option<AccountIdentity>,
    subreddit: RedditSubredditName,
    parent_fullname: Option<RedditThingId>,
    link_fullname: Option<RedditThingId>,
    body_digest: String,
    title_digest: Option<String>,
    permalink: Option<String>,
    moderation: RedditModerationState,
    removal_reason: Option<RedditRemovalReason>,
    locked: bool,
    archived: bool,
    banned_by: bool,
    revision: RevisionIdentity,
    observed_at: DateTime<Utc>,
}

impl RedditParentObservation {
    pub const fn content(&self) -> &ContentIdentity {
        &self.content
    }

    pub const fn account(&self) -> Option<&AccountIdentity> {
        self.account.as_ref()
    }

    pub const fn subreddit(&self) -> &RedditSubredditName {
        &self.subreddit
    }

    pub const fn parent_fullname(&self) -> Option<&RedditThingId> {
        self.parent_fullname.as_ref()
    }

    pub const fn link_fullname(&self) -> Option<&RedditThingId> {
        self.link_fullname.as_ref()
    }

    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }

    pub fn title_digest(&self) -> Option<&str> {
        self.title_digest.as_deref()
    }

    pub fn permalink(&self) -> Option<&str> {
        self.permalink.as_deref()
    }

    pub const fn moderation(&self) -> RedditModerationState {
        self.moderation
    }

    pub const fn removal_reason(&self) -> Option<RedditRemovalReason> {
        self.removal_reason
    }

    pub const fn locked(&self) -> bool {
        self.locked
    }

    pub const fn archived(&self) -> bool {
        self.archived
    }

    pub const fn banned_by(&self) -> bool {
        self.banned_by
    }

    pub const fn revision(&self) -> &RevisionIdentity {
        &self.revision
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditPublishDraft {
    operation: RedditPublishOperation,
    scope: RedditEffectScope,
    title: Option<String>,
    body: String,
    content_digest: String,
    draft_revision: String,
    idempotency_key: RedditIdempotencyKey,
    credential_generation: u64,
    authorization_digest: String,
    account_probe: RedditAccountProbe,
    subreddit_policy: RedditSubredditPolicy,
    parent: Option<RedditParentObservation>,
    prepared_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    source_digest: String,
    quota: RedditQuotaSnapshot,
}

impl RedditPublishDraft {
    pub const fn operation(&self) -> RedditPublishOperation {
        self.operation
    }

    pub const fn scope(&self) -> &RedditEffectScope {
        &self.scope
    }

    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    pub fn body(&self) -> &str {
        &self.body
    }

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    pub fn draft_revision(&self) -> &str {
        &self.draft_revision
    }

    pub const fn idempotency_key(&self) -> &RedditIdempotencyKey {
        &self.idempotency_key
    }

    pub const fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    pub fn authorization_digest(&self) -> &str {
        &self.authorization_digest
    }

    pub const fn account_probe(&self) -> &RedditAccountProbe {
        &self.account_probe
    }

    pub const fn subreddit_policy(&self) -> &RedditSubredditPolicy {
        &self.subreddit_policy
    }

    pub const fn parent(&self) -> Option<&RedditParentObservation> {
        self.parent.as_ref()
    }

    pub const fn prepared_at(&self) -> DateTime<Utc> {
        self.prepared_at
    }

    pub const fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub const fn quota(&self) -> &RedditQuotaSnapshot {
        &self.quota
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditPublishReadback {
    operation: RedditPublishOperation,
    fullname: RedditThingId,
    permalink: String,
    account: RedditAccountIdentity,
    subreddit: RedditCommunityIdentity,
    content: ContentIdentity,
    parent: Option<RedditThingId>,
    body_digest: String,
    title_digest: Option<String>,
    moderation: RedditModerationState,
    removal_reason: Option<RedditRemovalReason>,
    revision: RevisionIdentity,
    provider_response_digest: String,
    observed_at: DateTime<Utc>,
}

impl RedditPublishReadback {
    pub const fn operation(&self) -> RedditPublishOperation {
        self.operation
    }

    pub const fn fullname(&self) -> &RedditThingId {
        &self.fullname
    }

    pub fn permalink(&self) -> &str {
        &self.permalink
    }

    pub const fn account(&self) -> &RedditAccountIdentity {
        &self.account
    }

    pub const fn subreddit(&self) -> &RedditCommunityIdentity {
        &self.subreddit
    }

    pub const fn content(&self) -> &ContentIdentity {
        &self.content
    }

    pub const fn parent(&self) -> Option<&RedditThingId> {
        self.parent.as_ref()
    }

    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }

    pub fn title_digest(&self) -> Option<&str> {
        self.title_digest.as_deref()
    }

    pub const fn moderation(&self) -> RedditModerationState {
        self.moderation
    }

    pub const fn removal_reason(&self) -> Option<RedditRemovalReason> {
        self.removal_reason
    }

    pub const fn revision(&self) -> &RevisionIdentity {
        &self.revision
    }

    pub fn provider_response_digest(&self) -> &str {
        &self.provider_response_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditProviderReceipt {
    operation: RedditPublishOperation,
    fullname: RedditThingId,
    permalink: String,
    idempotency_key: RedditIdempotencyKey,
    draft_revision: String,
    content_digest: String,
    provider_response_digest: String,
    observed_at: DateTime<Utc>,
}

impl RedditProviderReceipt {
    pub const fn operation(&self) -> RedditPublishOperation {
        self.operation
    }

    pub const fn fullname(&self) -> &RedditThingId {
        &self.fullname
    }

    pub fn permalink(&self) -> &str {
        &self.permalink
    }

    pub const fn idempotency_key(&self) -> &RedditIdempotencyKey {
        &self.idempotency_key
    }

    pub fn draft_revision(&self) -> &str {
        &self.draft_revision
    }

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    pub fn provider_response_digest(&self) -> &str {
        &self.provider_response_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditVerificationEvidence {
    fullname: RedditThingId,
    permalink: String,
    body_digest: String,
    moderation: RedditModerationState,
    removal_reason: Option<RedditRemovalReason>,
    revision: RevisionIdentity,
    source_digest: String,
    evidence_digest: String,
    observed_at: DateTime<Utc>,
}

impl RedditVerificationEvidence {
    pub const fn fullname(&self) -> &RedditThingId {
        &self.fullname
    }

    pub fn permalink(&self) -> &str {
        &self.permalink
    }

    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }

    pub const fn moderation(&self) -> RedditModerationState {
        self.moderation
    }

    pub const fn removal_reason(&self) -> Option<RedditRemovalReason> {
        self.removal_reason
    }

    pub const fn revision(&self) -> &RevisionIdentity {
        &self.revision
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditPublishOutcome {
    provenance: RedditEffectProvenance,
    operation: RedditPublishOperation,
    scope: RedditEffectScope,
    effect_id: RedditEffectId,
    draft_revision: String,
    content_digest: String,
    credential_generation: u64,
    authorization_digest: String,
    approval_revision: RedditApprovalRevision,
    receipt: RedditProviderReceipt,
    verification: RedditVerificationEvidence,
    quota: RedditQuotaSnapshot,
}

impl RedditPublishOutcome {
    pub const fn provenance(&self) -> RedditEffectProvenance {
        self.provenance
    }

    pub const fn operation(&self) -> RedditPublishOperation {
        self.operation
    }

    pub const fn scope(&self) -> &RedditEffectScope {
        &self.scope
    }

    pub const fn effect_id(&self) -> &RedditEffectId {
        &self.effect_id
    }

    pub fn draft_revision(&self) -> &str {
        &self.draft_revision
    }

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    pub const fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    pub fn authorization_digest(&self) -> &str {
        &self.authorization_digest
    }

    pub const fn approval_revision(&self) -> &RedditApprovalRevision {
        &self.approval_revision
    }

    pub const fn receipt(&self) -> &RedditProviderReceipt {
        &self.receipt
    }

    pub const fn verification(&self) -> &RedditVerificationEvidence {
        &self.verification
    }

    pub const fn quota(&self) -> &RedditQuotaSnapshot {
        &self.quota
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditRetryAfterReceipt {
    operation: RedditPublishOperation,
    retry_after_seconds: u64,
    rate_limit_reset: Option<u64>,
    rate_limit_remaining: Option<u64>,
    provider_response_digest: String,
    observed_at: DateTime<Utc>,
}

impl RedditRetryAfterReceipt {
    pub const fn retry_after_seconds(&self) -> u64 {
        self.retry_after_seconds
    }

    pub const fn rate_limit_reset(&self) -> Option<u64> {
        self.rate_limit_reset
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedditPublishDispatch {
    Verified(RedditPublishOutcome),
    DuplicateIdempotency(RedditPublishOutcome),
    RetryAfter(RedditRetryAfterReceipt),
    ReceiptPending,
    NoMatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditReconcileObservation {
    matches: Vec<RedditPublishReadback>,
    source_digest: String,
    observed_at: DateTime<Utc>,
}

impl RedditReconcileObservation {
    pub fn matches(&self) -> &[RedditPublishReadback] {
        &self.matches
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedditQuotaOperation {
    AuthenticatedProbe,
    SubredditAbout,
    SubredditRules,
    PostRequirements,
    ParentRead,
    Reconcile,
    Execute,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditQuotaReceipt {
    operation: RedditQuotaOperation,
    cost_units: u32,
    window_started_at: DateTime<Utc>,
    remaining: u32,
    observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditQuotaSnapshot {
    limit: u32,
    window_started_at: DateTime<Utc>,
    consumed: u32,
    remaining: u32,
}

impl RedditQuotaSnapshot {
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    pub const fn consumed(&self) -> u32 {
        self.consumed
    }

    pub const fn remaining(&self) -> u32 {
        self.remaining
    }
}

#[derive(Clone, Debug)]
pub struct RedditEffectQuotaLedger {
    limit: u32,
    window_started_at: Option<DateTime<Utc>>,
    consumed: u32,
}

impl RedditEffectQuotaLedger {
    pub fn new(limit: u32) -> Result<Self, RedditEffectError> {
        if limit == 0 {
            return Err(RedditEffectError::InvalidRequest(
                "Reddit quota limit must be positive",
            ));
        }
        Ok(Self {
            limit,
            window_started_at: None,
            consumed: 0,
        })
    }

    pub fn with_official_default() -> Self {
        Self::new(REDDIT_EFFECT_DEFAULT_QUOTA_PER_MINUTE)
            .expect("the official Reddit quota default is positive")
    }

    pub fn reserve(
        &mut self,
        operation: RedditQuotaOperation,
        cost_units: u32,
        observed_at: DateTime<Utc>,
    ) -> Result<RedditQuotaReceipt, RedditEffectError> {
        if cost_units == 0 || cost_units > self.limit {
            return Err(RedditEffectError::InvalidRequest(
                "Reddit quota cost must be within the configured limit",
            ));
        }
        let reset = self.window_started_at.is_none_or(|started| {
            observed_at < started || observed_at - started >= Duration::minutes(1)
        });
        if reset {
            self.window_started_at = Some(observed_at);
            self.consumed = 0;
        }
        if self.consumed.saturating_add(cost_units) > self.limit {
            return Err(RedditEffectError::QuotaExhausted);
        }
        self.consumed += cost_units;
        let window_started_at = self
            .window_started_at
            .expect("quota window is initialized before reservation");
        Ok(RedditQuotaReceipt {
            operation,
            cost_units,
            window_started_at,
            remaining: self.limit - self.consumed,
            observed_at,
        })
    }

    pub fn snapshot(&self, observed_at: DateTime<Utc>) -> RedditQuotaSnapshot {
        let window_started_at = self.window_started_at.unwrap_or(observed_at);
        let consumed = if observed_at < window_started_at
            || observed_at - window_started_at >= Duration::minutes(1)
        {
            0
        } else {
            self.consumed
        };
        RedditQuotaSnapshot {
            limit: self.limit,
            window_started_at,
            consumed,
            remaining: self.limit - consumed.min(self.limit),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedditCheckpointPhase {
    Prepared,
    Executing,
    ReceiptPending,
    Uncertain,
    Verified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditPublishCheckpoint {
    scope: RedditEffectScope,
    effect_id: RedditEffectId,
    draft_revision: String,
    content_digest: String,
    idempotency_key: RedditIdempotencyKey,
    credential_generation: u64,
    authorization_digest: String,
    approval_revision: RedditApprovalRevision,
    phase: RedditCheckpointPhase,
    receipt: Option<RedditProviderReceipt>,
    readback: Option<RedditPublishReadback>,
    retry_after: Option<RedditRetryAfterReceipt>,
    quota_receipts: Vec<RedditQuotaReceipt>,
}

impl RedditPublishCheckpoint {
    pub fn new(
        draft: &RedditPublishDraft,
        ingress: &RedditApprovedEffectIngress,
    ) -> Result<Self, RedditEffectError> {
        validate_ingress(draft, ingress)?;
        Ok(Self {
            scope: draft.scope.clone(),
            effect_id: ingress.effect_id.clone(),
            draft_revision: draft.draft_revision.clone(),
            content_digest: draft.content_digest.clone(),
            idempotency_key: draft.idempotency_key.clone(),
            credential_generation: ingress.credential_generation,
            authorization_digest: ingress.authorization_digest.clone(),
            approval_revision: ingress.approval_revision.clone(),
            phase: RedditCheckpointPhase::Prepared,
            receipt: None,
            readback: None,
            retry_after: None,
            quota_receipts: Vec::new(),
        })
    }

    pub const fn phase(&self) -> RedditCheckpointPhase {
        self.phase
    }

    pub const fn receipt(&self) -> Option<&RedditProviderReceipt> {
        self.receipt.as_ref()
    }

    pub const fn readback(&self) -> Option<&RedditPublishReadback> {
        self.readback.as_ref()
    }

    pub const fn retry_after(&self) -> Option<&RedditRetryAfterReceipt> {
        self.retry_after.as_ref()
    }

    pub fn quota_receipts(&self) -> &[RedditQuotaReceipt] {
        &self.quota_receipts
    }

    pub fn durable_json(&self) -> Result<Value, RedditEffectError> {
        serde_json::to_value(self).map_err(|_| RedditEffectError::CheckpointCorrupt)
    }

    pub fn reopen(value: Value) -> Result<Self, RedditEffectError> {
        serde_json::from_value(value).map_err(|_| RedditEffectError::CheckpointCorrupt)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RedditEffectError {
    #[error(transparent)]
    Adapter(#[from] ChannelAdapterError),
    #[error("invalid Reddit effect request: {0}")]
    InvalidRequest(&'static str),
    #[error("Reddit effect authorization required: {0:?}")]
    AuthorizationRequired(AuthorizationReason),
    #[error("Reddit effect credential is revoked")]
    CredentialRevoked,
    #[error("Reddit effect credential is expired")]
    CredentialExpired,
    #[error("Reddit effect credential is unmounted")]
    CredentialUnmounted,
    #[error("Reddit effect credential generation drift")]
    CredentialGenerationDrift,
    #[error("Reddit effect approval drift")]
    ApprovalDrift,
    #[error("Reddit effect scope drift: {0}")]
    ScopeMismatch(&'static str),
    #[error("Reddit account identity drift")]
    AccountMismatch,
    #[error("Reddit subreddit policy rejected the effect: {0}")]
    PolicyRejected(&'static str),
    #[error("Reddit parent is not publishable: {0}")]
    ParentRejected(&'static str),
    #[error("Reddit moderation/removal drift")]
    ModerationDrift,
    #[error("Reddit readback does not exactly match the approved effect")]
    ReadbackMismatch,
    #[error("Reddit provider receipt is incomplete")]
    ReceiptUnavailable,
    #[error("Reddit provider returned more than one idempotency match")]
    DuplicateIdempotency,
    #[error("Reddit execute timed out after dispatch; reconcile is required")]
    TimeoutUncertain,
    #[error("Reddit rate limit response did not provide a reset")]
    RateLimitWithoutReset,
    #[error("Reddit quota exhausted")]
    QuotaExhausted,
    #[error("Reddit durable checkpoint is corrupt")]
    CheckpointCorrupt,
    #[error("Reddit durable checkpoint needs reconciliation before dispatch")]
    CheckpointNeedsRecovery,
    #[error("Reddit provider response is invalid: {0}")]
    InvalidResponse(&'static str),
    #[error("Reddit provider transport unavailable")]
    Disconnected,
    #[error("Reddit provider transport timed out")]
    TransportTimedOut,
    #[error("Reddit effect requires an approved real credential: {0}")]
    BlockedEnvironment(&'static str),
    #[error("Reddit fixture provenance cannot be adopted by Mission")]
    FixtureProvenance,
    #[error("Reddit publish outcome is incomplete")]
    IncompleteOutcome,
}

fn validate_digest(value: &str) -> Result<(), RedditEffectError> {
    if value.len() != 64
        || value
            .chars()
            .any(|character| !character.is_ascii_hexdigit())
    {
        return Err(RedditEffectError::InvalidRequest(
            "Reddit effect digests must be SHA-256 hex",
        ));
    }
    Ok(())
}

fn digest_bytes(value: impl AsRef<[u8]>) -> String {
    let mut digest = Sha256::new();
    digest.update(value.as_ref());
    hex_digest(digest.finalize())
}

fn digest_json(value: &Value) -> String {
    digest_bytes(serde_json::to_vec(value).expect("JSON values are serializable"))
}

#[derive(Clone)]
pub struct RedditEffectRequest {
    operation: RedditQuotaOperation,
    method: HttpMethod,
    url: Url,
    required_scopes: BTreeSet<RedditScope>,
    credential: CredentialReference,
    body: Option<Value>,
}

impl fmt::Debug for RedditEffectRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedditEffectRequest")
            .field("operation", &self.operation)
            .field("method", &self.method)
            .field("url", &self.url)
            .field("required_scopes", &self.required_scopes)
            .field("credential", &self.credential)
            .field("body_present", &self.body.is_some())
            .field("body_digest", &self.body.as_ref().map(digest_json))
            .finish()
    }
}

impl RedditEffectRequest {
    pub fn new(
        operation: RedditQuotaOperation,
        method: HttpMethod,
        url: Url,
        required_scopes: impl IntoIterator<Item = RedditScope>,
        credential: CredentialReference,
        body: Option<Value>,
    ) -> Result<Self, RedditEffectError> {
        if url.scheme() != "https" || url.host_str() != Some("oauth.reddit.com") {
            return Err(RedditEffectError::InvalidRequest(
                "Reddit effect requests must use oauth.reddit.com over HTTPS",
            ));
        }
        if method == HttpMethod::Get && body.is_some() {
            return Err(RedditEffectError::InvalidRequest(
                "Reddit GET effect requests cannot carry a body",
            ));
        }
        Ok(Self {
            operation,
            method,
            url,
            required_scopes: required_scopes.into_iter().collect(),
            credential,
            body,
        })
    }

    pub const fn operation(&self) -> RedditQuotaOperation {
        self.operation
    }

    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn required_scopes(&self) -> &BTreeSet<RedditScope> {
        &self.required_scopes
    }

    pub const fn credential(&self) -> &CredentialReference {
        &self.credential
    }

    pub fn body(&self) -> Option<&Value> {
        self.body.as_ref()
    }

    pub fn body_digest(&self) -> Option<String> {
        self.body.as_ref().map(digest_json)
    }
}

pub trait RedditEffectTransport {
    fn provenance(&self) -> RedditEffectProvenance;

    fn send(&mut self, request: &RedditEffectRequest) -> Result<ProviderResponse, TransportError>;
}

/// OAuth access tokens are intentionally fetched only at send time and never
/// retained in the provider, request, receipt, checkpoint, or debug output.
#[derive(Clone, Debug)]
pub struct RedditEnvironmentOAuthTokenSource {
    environment_variable: String,
}

impl RedditEnvironmentOAuthTokenSource {
    pub fn new(environment_variable: impl Into<String>) -> Result<Self, RedditEffectError> {
        let environment_variable = environment_variable.into();
        if environment_variable.is_empty()
            || environment_variable
                .chars()
                .any(|character| !(character.is_ascii_alphanumeric() || character == '_'))
        {
            return Err(RedditEffectError::InvalidRequest(
                "Reddit OAuth token environment variable name is invalid",
            ));
        }
        Ok(Self {
            environment_variable,
        })
    }

    fn token(&self) -> Result<String, TransportError> {
        let token =
            std::env::var(&self.environment_variable).map_err(|_| TransportError::Unavailable)?;
        if token.is_empty()
            || token
                .chars()
                .any(|character| matches!(character, '"' | '\\' | '\n' | '\r'))
        {
            return Err(TransportError::Unavailable);
        }
        Ok(token)
    }
}

#[derive(Clone, Debug)]
pub struct RedditHttpsTransport<S> {
    token_source: S,
}

impl<S> RedditHttpsTransport<S> {
    pub const fn new(token_source: S) -> Self {
        Self { token_source }
    }
}

impl RedditEffectTransport for RedditHttpsTransport<RedditEnvironmentOAuthTokenSource> {
    fn provenance(&self) -> RedditEffectProvenance {
        RedditEffectProvenance::ProductionApprovedDataApi
    }

    fn send(&mut self, request: &RedditEffectRequest) -> Result<ProviderResponse, TransportError> {
        let token = self.token_source.token()?;
        send_curl_request(request, &token)
    }
}

fn send_curl_request(
    request: &RedditEffectRequest,
    token: &str,
) -> Result<ProviderResponse, TransportError> {
    let marker = "\n__HARTEVO_REDDIT_STATUS__:";
    let mut command = Command::new("curl");
    command
        .arg("--silent")
        .arg("--show-error")
        .arg("--request")
        .arg(request.method().to_string())
        .arg("--url")
        .arg(request.url().as_str())
        .arg("--header")
        .arg("Accept: application/json")
        .arg("--header")
        .arg("User-Agent: Hartevo-channel-adapter/0.1")
        .arg("--header")
        .arg("Content-Type: application/x-www-form-urlencoded")
        .arg("--config")
        .arg("-")
        .arg("--write-out")
        .arg(format!("{marker}%{{http_code}}\n%{{header.x-ratelimit-reset}}\n%{{header.x-ratelimit-remaining}}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(body) = request.body() {
        let encoded = form_encode(body)?;
        command.arg("--data-raw").arg(encoded);
    }
    let mut child = command.spawn().map_err(|_| TransportError::Unavailable)?;
    if let Some(mut stdin) = child.stdin.take() {
        let config = format!("header = \"Authorization: Bearer {token}\"\n");
        stdin
            .write_all(config.as_bytes())
            .map_err(|_| TransportError::Unavailable)?;
    }
    let output = child
        .wait_with_output()
        .map_err(|_| TransportError::Unavailable)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let (body, trailer) = stdout
        .rsplit_once(marker)
        .ok_or(TransportError::Unavailable)?;
    let mut trailer_lines = trailer.lines();
    let status = trailer_lines
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(TransportError::Unavailable)?;
    let reset = trailer_lines.next().unwrap_or_default();
    let remaining = trailer_lines.next().unwrap_or_default();
    let headers = [
        ("x-ratelimit-reset".to_owned(), reset.to_owned()),
        ("x-ratelimit-remaining".to_owned(), remaining.to_owned()),
    ];
    Ok(ProviderResponse::new(
        status,
        headers,
        body.to_owned(),
        Utc::now(),
    ))
}

fn form_encode(body: &Value) -> Result<String, TransportError> {
    let object = body.as_object().ok_or(TransportError::Unavailable)?;
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in object {
        let value = match value {
            Value::Bool(value) => value.to_string(),
            Value::Number(value) => value.to_string(),
            Value::String(value) => value.clone(),
            _ => return Err(TransportError::Unavailable),
        };
        serializer.append_pair(key, &value);
    }
    Ok(serializer.finish())
}

pub trait RedditEffectProvider {
    fn provenance(&self) -> RedditEffectProvenance;

    fn authenticated_probe(
        &mut self,
        credential: &RedditEffectCredential,
        expected_account: &RedditAccountIdentity,
        observed_at: DateTime<Utc>,
    ) -> Result<RedditAccountProbe, RedditEffectError>;

    fn subreddit_policy(
        &mut self,
        credential: &RedditEffectCredential,
        subreddit: &RedditCommunityIdentity,
        observed_at: DateTime<Utc>,
    ) -> Result<RedditSubredditPolicy, RedditEffectError>;

    fn parent_observation(
        &mut self,
        credential: &RedditEffectCredential,
        subreddit: &RedditCommunityIdentity,
        parent: &RedditThingId,
        observed_at: DateTime<Utc>,
    ) -> Result<RedditParentObservation, RedditEffectError>;

    fn reconcile(
        &mut self,
        credential: &RedditEffectCredential,
        draft: &RedditPublishDraft,
        receipt_hint: Option<&RedditThingId>,
        observed_at: DateTime<Utc>,
    ) -> Result<RedditReconcileObservation, RedditEffectError>;

    fn execute(
        &mut self,
        credential: &RedditEffectCredential,
        draft: &RedditPublishDraft,
        ingress: &RedditApprovedEffectIngress,
        observed_at: DateTime<Utc>,
    ) -> Result<ProviderResponse, TransportError>;
}

#[derive(Debug)]
pub struct RedditApprovedDataApiProvider<T> {
    transport: T,
}

impl<T> RedditApprovedDataApiProvider<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    pub const fn transport(&self) -> &T {
        &self.transport
    }

    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T> RedditApprovedDataApiProvider<T>
where
    T: RedditEffectTransport,
{
    fn send(
        &mut self,
        request: &RedditEffectRequest,
    ) -> Result<ProviderResponse, RedditEffectError> {
        self.transport.send(request).map_err(|error| match error {
            TransportError::Unavailable => RedditEffectError::Disconnected,
            TransportError::TimedOut => RedditEffectError::TransportTimedOut,
        })
    }

    fn get(
        &mut self,
        operation: RedditQuotaOperation,
        url: Url,
        scopes: impl IntoIterator<Item = RedditScope>,
        credential: &RedditEffectCredential,
        observed_at: DateTime<Utc>,
    ) -> Result<ProviderResponse, RedditEffectError> {
        credential.assert_usable(observed_at)?;
        let request = RedditEffectRequest::new(
            operation,
            HttpMethod::Get,
            url,
            scopes,
            credential.reference().clone(),
            None,
        )?;
        self.send(&request)
    }
}

fn reddit_url(
    path: &[&str],
    query: impl IntoIterator<Item = (&'static str, String)>,
) -> Result<Url, RedditEffectError> {
    let mut url = Url::parse(REDDIT_OAUTH_API_BASE_URL)
        .map_err(|_| RedditEffectError::InvalidRequest("Reddit API base URL is invalid"))?;
    url.path_segments_mut()
        .map_err(|()| RedditEffectError::InvalidRequest("Reddit API URL cannot be a base URL"))?
        .extend(path.iter().copied());
    url.query_pairs_mut().extend_pairs(query);
    Ok(url)
}

fn response_json(response: &ProviderResponse) -> Result<Value, RedditEffectError> {
    if response.status() >= 400 {
        return Err(response_error(response));
    }
    response
        .json(ProviderId::Reddit)
        .map_err(RedditEffectError::Adapter)
}

fn response_error(response: &ProviderResponse) -> RedditEffectError {
    let code = response
        .json(ProviderId::Reddit)
        .ok()
        .and_then(|body| response_code(&body));
    match response.status() {
        401 => RedditEffectError::CredentialRevoked,
        403 => RedditEffectError::AuthorizationRequired(AuthorizationReason::MissingScope),
        404 => RedditEffectError::Adapter(ChannelAdapterError::ContentNotFound {
            provider: ProviderId::Reddit,
        }),
        429 => response.retry_after_seconds().map_or(
            RedditEffectError::RateLimitWithoutReset,
            |seconds| {
                RedditEffectError::Adapter(ChannelAdapterError::RateLimited {
                    provider: ProviderId::Reddit,
                    retry_after_seconds: Some(seconds),
                })
            },
        ),
        status => RedditEffectError::Adapter(ChannelAdapterError::ProviderRejected {
            provider: ProviderId::Reddit,
            status,
            code,
        }),
    }
}

fn response_code(body: &Value) -> Option<String> {
    body.pointer("/json/errors/0/0")
        .and_then(Value::as_str)
        .or_else(|| body.pointer("/error/code").and_then(Value::as_str))
        .or_else(|| body.get("error").and_then(Value::as_str))
        .map(str::to_owned)
}

trait ResponseRateLimit {
    fn retry_after_seconds(&self) -> Option<u64>;
}

impl ResponseRateLimit for ProviderResponse {
    fn retry_after_seconds(&self) -> Option<u64> {
        self.header("retry-after")
            .or_else(|| self.header("x-ratelimit-reset"))
            .and_then(parse_retry_seconds)
    }
}

fn parse_retry_seconds(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() || value.starts_with('-') {
        return None;
    }
    let (whole, fractional) = value.split_once('.').map_or((value, ""), |parts| parts);
    if fractional
        .chars()
        .any(|character| !character.is_ascii_digit())
    {
        return None;
    }
    let whole = whole.parse::<u64>().ok()?;
    let has_fraction = fractional.chars().any(|character| character != '0');
    whole.checked_add(u64::from(has_fraction))
}

fn required_string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, RedditEffectError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or(RedditEffectError::InvalidResponse("required string"))
}

fn value_bool(value: &Value, pointer: &str) -> bool {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn value_u32(value: &Value, pointer: &str) -> Option<u32> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .and_then(|number| u32::try_from(number).ok())
}

fn parse_account_probe(
    body: &Value,
    response: &ProviderResponse,
) -> Result<RedditAccountProbe, RedditEffectError> {
    let id = RedditAccountId::new(required_string(body, "/id")?.to_owned())
        .map_err(|_| RedditEffectError::InvalidResponse("account id"))?;
    let username = required_string(body, "/name")?.to_owned();
    Ok(RedditAccountProbe {
        account: RedditAccountIdentity::new(id, Some(username)),
        response_digest: response.body_digest(),
        observed_at: response.observed_at(),
    })
}

fn parse_community_from_about(
    body: &Value,
    expected: &RedditCommunityIdentity,
) -> Result<(RedditCommunityIdentity, bool, bool), RedditEffectError> {
    let data = body.get("data").unwrap_or(body);
    let subreddit_id = RedditSubredditId::new(
        data.get("id")
            .and_then(Value::as_str)
            .ok_or(RedditEffectError::InvalidResponse("subreddit id"))?
            .to_owned(),
    )
    .map_err(|_| RedditEffectError::InvalidResponse("subreddit id"))?;
    let name = RedditSubredditName::new(
        data.get("display_name")
            .or_else(|| data.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| expected.name().as_str())
            .to_owned(),
    )
    .map_err(|_| RedditEffectError::InvalidResponse("subreddit name"))?;
    let community = RedditCommunityIdentity::new(subreddit_id, name);
    if community != *expected {
        return Err(RedditEffectError::ScopeMismatch(
            "provider returned a different subreddit",
        ));
    }
    Ok((
        community,
        data.get("user_is_banned")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        data.get("archived")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    ))
}

fn parse_parent_observation(
    body: &Value,
    response: &ProviderResponse,
    expected_subreddit: &RedditCommunityIdentity,
    expected_parent: &RedditThingId,
) -> Result<RedditParentObservation, RedditEffectError> {
    let things = collect_things(body);
    let thing = things
        .first()
        .ok_or(RedditEffectError::InvalidResponse("parent fullname"))?;
    let parsed = parse_thing(
        thing,
        Some(expected_subreddit.name()),
        response.observed_at(),
    )?;
    if parsed.fullname != *expected_parent {
        return Err(RedditEffectError::ScopeMismatch(
            "provider returned a different parent fullname",
        ));
    }
    if parsed.subreddit_id.as_ref() != Some(expected_subreddit.subreddit_id())
        || parsed.subreddit_name.as_ref() != Some(expected_subreddit.name())
    {
        return Err(RedditEffectError::ScopeMismatch(
            "parent belongs to a different subreddit",
        ));
    }
    Ok(RedditParentObservation {
        content: parsed.content,
        account: parsed.account,
        subreddit: parsed
            .subreddit_name
            .ok_or(RedditEffectError::InvalidResponse("parent subreddit"))?,
        parent_fullname: parsed.parent_fullname,
        link_fullname: parsed.link_fullname,
        body_digest: parsed.body_digest,
        title_digest: parsed.title_digest,
        permalink: parsed.permalink,
        moderation: parsed.moderation,
        removal_reason: parsed.removal_reason,
        locked: parsed.locked,
        archived: parsed.archived,
        banned_by: parsed.banned_by,
        revision: parsed.revision,
        observed_at: response.observed_at(),
    })
}

#[derive(Clone, Debug)]
struct ParsedRedditThing {
    fullname: RedditThingId,
    kind: RedditThingKind,
    content: ContentIdentity,
    account: Option<AccountIdentity>,
    subreddit_id: Option<RedditSubredditId>,
    subreddit_name: Option<RedditSubredditName>,
    parent_fullname: Option<RedditThingId>,
    link_fullname: Option<RedditThingId>,
    body_digest: String,
    title_digest: Option<String>,
    permalink: Option<String>,
    moderation: RedditModerationState,
    removal_reason: Option<RedditRemovalReason>,
    locked: bool,
    archived: bool,
    banned_by: bool,
    revision: RevisionIdentity,
}

fn collect_things(value: &Value) -> Vec<&Value> {
    let mut things = Vec::new();
    collect_things_into(value, &mut things);
    things
}

fn collect_things_into<'a>(value: &'a Value, things: &mut Vec<&'a Value>) {
    if value
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind == "t1" || kind == "t3")
        && value.get("data").is_some()
    {
        things.push(value);
    }
    match value {
        Value::Object(object) => object
            .values()
            .for_each(|child| collect_things_into(child, things)),
        Value::Array(array) => array
            .iter()
            .for_each(|child| collect_things_into(child, things)),
        _ => {}
    }
}

#[allow(clippy::too_many_lines)]
fn parse_thing(
    wrapper: &Value,
    fallback_subreddit: Option<&RedditSubredditName>,
    observed_at: DateTime<Utc>,
) -> Result<ParsedRedditThing, RedditEffectError> {
    let data = wrapper.get("data").unwrap_or(wrapper);
    let kind = wrapper
        .get("kind")
        .and_then(Value::as_str)
        .or_else(|| {
            data.get("name")
                .and_then(Value::as_str)
                .and_then(|name| name.get(..2))
        })
        .ok_or(RedditEffectError::InvalidResponse("thing kind"))?;
    let kind = match kind {
        "t1" => RedditThingKind::Comment,
        "t3" => RedditThingKind::Post,
        _ => return Err(RedditEffectError::InvalidResponse("thing kind")),
    };
    let fullname = RedditThingId::new(
        data.get("name")
            .and_then(Value::as_str)
            .ok_or(RedditEffectError::InvalidResponse("thing fullname"))?
            .to_owned(),
    )
    .map_err(|_| RedditEffectError::InvalidResponse("thing fullname"))?;
    let subreddit_id = data
        .get("subreddit_id")
        .and_then(Value::as_str)
        .map(|value| RedditSubredditId::new(value.to_owned()))
        .transpose()
        .map_err(|_| RedditEffectError::InvalidResponse("thing subreddit id"))?;
    let subreddit_name = data
        .get("subreddit")
        .and_then(Value::as_str)
        .map(|value| RedditSubredditName::new(value.to_owned()))
        .transpose()
        .map_err(|_| RedditEffectError::InvalidResponse("thing subreddit name"))?
        .or_else(|| fallback_subreddit.cloned());
    let parent_fullname = data
        .get("parent_id")
        .and_then(Value::as_str)
        .map(|value| RedditThingId::new(value.to_owned()))
        .transpose()
        .map_err(|_| RedditEffectError::InvalidResponse("thing parent"))?;
    let link_fullname = data
        .get("link_id")
        .and_then(Value::as_str)
        .map(|value| RedditThingId::new(value.to_owned()))
        .transpose()
        .map_err(|_| RedditEffectError::InvalidResponse("thing link"))?;
    let subreddit_id_for_identity = subreddit_id.clone();
    let parent_post_id = link_fullname.clone().or_else(|| {
        parent_fullname
            .as_ref()
            .filter(|value| value.as_str().starts_with("t3_"))
            .cloned()
    });
    let content_identity = RedditContentIdentity::new(
        fullname.clone(),
        kind,
        subreddit_id_for_identity,
        parent_post_id,
    );
    let content = ContentIdentity::Reddit(content_identity);
    let (moderation, removal_reason) = moderation_state(data);
    let revision_key = RedditRevisionKey::new(format!(
        "edited-{}-locked-{}-archived-{}-removed-{}",
        scalar_key(data.get("edited")),
        scalar_key(data.get("locked")),
        scalar_key(data.get("archived")),
        removal_reason.map_or("none", removal_reason_code),
    ))
    .map_err(|_| RedditEffectError::InvalidResponse("thing revision"))?;
    let revision = RevisionIdentity::Reddit(
        RedditRevisionIdentity::new(content.clone(), revision_key, observed_at)
            .map_err(|_| RedditEffectError::InvalidResponse("thing revision"))?,
    );
    let body = match kind {
        RedditThingKind::Post => data
            .get("selftext")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        RedditThingKind::Comment => data.get("body").and_then(Value::as_str).unwrap_or_default(),
    };
    let title_digest = if kind == RedditThingKind::Post {
        data.get("title").and_then(Value::as_str).map(digest_bytes)
    } else {
        None
    };
    let account = parse_author(data)?;
    Ok(ParsedRedditThing {
        fullname,
        kind,
        content,
        account,
        subreddit_id,
        subreddit_name,
        parent_fullname,
        link_fullname,
        body_digest: digest_bytes(body),
        title_digest,
        permalink: data
            .get("permalink")
            .and_then(Value::as_str)
            .map(str::to_owned),
        moderation,
        removal_reason,
        locked: value_bool(data, "/locked"),
        archived: value_bool(data, "/archived"),
        banned_by: data.get("banned_by").is_some_and(|value| !value.is_null()),
        revision,
    })
}

fn parse_author(data: &Value) -> Result<Option<AccountIdentity>, RedditEffectError> {
    if data.get("author").is_some_and(Value::is_null) {
        return Ok(None);
    }
    let username = data
        .get("author")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let id = data
        .get("author_fullname")
        .and_then(Value::as_str)
        .or(username.as_deref())
        .ok_or(RedditEffectError::InvalidResponse("thing author"))?;
    let account_id = RedditAccountId::new(id.to_owned())
        .map_err(|_| RedditEffectError::InvalidResponse("thing author id"))?;
    Ok(Some(AccountIdentity::Reddit(RedditAccountIdentity::new(
        account_id, username,
    ))))
}

fn scalar_key(value: Option<&Value>) -> String {
    match value {
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::String(value)) => value.clone(),
        _ => "none".to_owned(),
    }
}

fn moderation_state(data: &Value) -> (RedditModerationState, Option<RedditRemovalReason>) {
    let category = data.get("removed_by_category").and_then(Value::as_str);
    if let Some(category) = category {
        return match category {
            "moderator" => (
                RedditModerationState::RemovedByModerator,
                Some(RedditRemovalReason::Moderator),
            ),
            "reddit" | "content_policy" => (
                RedditModerationState::RemovedByReddit,
                Some(RedditRemovalReason::Reddit),
            ),
            "automod_filtered" => (
                RedditModerationState::Filtered,
                Some(RedditRemovalReason::AutomodFiltered),
            ),
            "author" | "deleted" => (
                RedditModerationState::DeletedByAuthor,
                Some(RedditRemovalReason::AuthorDeleted),
            ),
            "spam" => (
                RedditModerationState::Filtered,
                Some(RedditRemovalReason::Spam),
            ),
            _ => (
                RedditModerationState::Unknown,
                Some(RedditRemovalReason::Other),
            ),
        };
    }
    if data.get("author").is_some_and(Value::is_null)
        || data.get("selftext").and_then(Value::as_str) == Some("[deleted]")
        || data.get("body").and_then(Value::as_str) == Some("[deleted]")
    {
        return (
            RedditModerationState::DeletedByAuthor,
            Some(RedditRemovalReason::AuthorDeleted),
        );
    }
    if data.get("selftext").and_then(Value::as_str) == Some("[removed]")
        || data.get("body").and_then(Value::as_str) == Some("[removed]")
    {
        return (
            RedditModerationState::RemovedByModerator,
            Some(RedditRemovalReason::Moderator),
        );
    }
    (RedditModerationState::Visible, None)
}

fn removal_reason_code(reason: RedditRemovalReason) -> &'static str {
    match reason {
        RedditRemovalReason::Moderator => "moderator",
        RedditRemovalReason::Reddit => "reddit",
        RedditRemovalReason::AutomodFiltered => "automod_filtered",
        RedditRemovalReason::Spam => "spam",
        RedditRemovalReason::AuthorDeleted => "author_deleted",
        RedditRemovalReason::Other => "other",
    }
}

impl<T> RedditEffectProvider for RedditApprovedDataApiProvider<T>
where
    T: RedditEffectTransport,
{
    fn provenance(&self) -> RedditEffectProvenance {
        self.transport.provenance()
    }

    fn authenticated_probe(
        &mut self,
        credential: &RedditEffectCredential,
        expected_account: &RedditAccountIdentity,
        observed_at: DateTime<Utc>,
    ) -> Result<RedditAccountProbe, RedditEffectError> {
        credential.require(RedditScope::Identity, observed_at)?;
        let url = reddit_url(&["api", "v1", "me"], [])?;
        let response = self.get(
            RedditQuotaOperation::AuthenticatedProbe,
            url,
            [RedditScope::Identity],
            credential,
            observed_at,
        )?;
        let probe = parse_account_probe(&response_json(&response)?, &response)?;
        if probe.account() != expected_account {
            return Err(RedditEffectError::AccountMismatch);
        }
        Ok(probe)
    }

    fn subreddit_policy(
        &mut self,
        credential: &RedditEffectCredential,
        subreddit: &RedditCommunityIdentity,
        observed_at: DateTime<Utc>,
    ) -> Result<RedditSubredditPolicy, RedditEffectError> {
        credential.require(RedditScope::Read, observed_at)?;
        let about_url = reddit_url(&["r", subreddit.name().as_str(), "about"], [])?;
        let rules_url = reddit_url(&["r", subreddit.name().as_str(), "about", "rules"], [])?;
        let requirements_url = reddit_url(
            &["api", "v1", "subreddit", "post_requirements"],
            [("sr", subreddit.name().as_str().to_owned())],
        )?;
        let about_response = self.get(
            RedditQuotaOperation::SubredditAbout,
            about_url,
            [RedditScope::Read],
            credential,
            observed_at,
        )?;
        let rules_response = self.get(
            RedditQuotaOperation::SubredditRules,
            rules_url,
            [RedditScope::Read],
            credential,
            observed_at,
        )?;
        let requirements_response = self.get(
            RedditQuotaOperation::PostRequirements,
            requirements_url,
            [RedditScope::Read],
            credential,
            observed_at,
        )?;
        let about = response_json(&about_response)?;
        let (community, account_banned, archived) = parse_community_from_about(&about, subreddit)?;
        let rules = response_json(&rules_response)?;
        let requirements = response_json(&requirements_response)?;
        let source_digest = digest_bytes(format!(
            "{}:{}:{}",
            about_response.body_digest(),
            rules_response.body_digest(),
            requirements_response.body_digest()
        ));
        let requirements_data = requirements.get("data").unwrap_or(&requirements);
        let post_allowed = !account_banned && !archived;
        Ok(RedditSubredditPolicy {
            community,
            post_allowed,
            reply_allowed: post_allowed,
            account_banned,
            archived,
            rules_digest: digest_json(&rules),
            requirements_digest: digest_json(&requirements),
            source_digest,
            title_min_length: value_u32(requirements_data, "/title_text_min_length"),
            title_max_length: value_u32(requirements_data, "/title_text_max_length"),
            body_min_length: value_u32(requirements_data, "/body_text_min_length"),
            body_max_length: value_u32(requirements_data, "/body_text_max_length"),
            observed_at: observed_at.max(
                about_response.observed_at().max(
                    rules_response
                        .observed_at()
                        .max(requirements_response.observed_at()),
                ),
            ),
        })
    }

    fn parent_observation(
        &mut self,
        credential: &RedditEffectCredential,
        subreddit: &RedditCommunityIdentity,
        parent: &RedditThingId,
        observed_at: DateTime<Utc>,
    ) -> Result<RedditParentObservation, RedditEffectError> {
        credential.require(RedditScope::Read, observed_at)?;
        let url = reddit_url(&["api", "info"], [("id", parent.as_str().to_owned())])?;
        let response = self.get(
            RedditQuotaOperation::ParentRead,
            url,
            [RedditScope::Read],
            credential,
            observed_at,
        )?;
        parse_parent_observation(&response_json(&response)?, &response, subreddit, parent)
    }

    fn reconcile(
        &mut self,
        credential: &RedditEffectCredential,
        draft: &RedditPublishDraft,
        receipt_hint: Option<&RedditThingId>,
        observed_at: DateTime<Utc>,
    ) -> Result<RedditReconcileObservation, RedditEffectError> {
        credential.require(RedditScope::Read, observed_at)?;
        let (url, fallback_subreddit) = if let Some(fullname) = receipt_hint {
            (
                reddit_url(&["api", "info"], [("id", fullname.as_str().to_owned())])?,
                None,
            )
        } else {
            match draft.operation {
                RedditPublishOperation::Post => (
                    reddit_url(
                        &["r", draft.scope.subreddit.name().as_str(), "new.json"],
                        [("limit", "100".to_owned())],
                    )?,
                    Some(draft.scope.subreddit.name()),
                ),
                RedditPublishOperation::Reply => {
                    let parent = draft
                        .parent
                        .as_ref()
                        .and_then(RedditParentObservation::link_fullname)
                        .or_else(|| draft.scope.parent())
                        .ok_or(RedditEffectError::InvalidRequest(
                            "reply reconciliation requires a root post fullname",
                        ))?;
                    let article = parent
                        .as_str()
                        .split_once('_')
                        .map_or(parent.as_str(), |(_, id)| id);
                    (
                        reddit_url(
                            &[
                                "r",
                                draft.scope.subreddit.name().as_str(),
                                "comments",
                                article,
                            ],
                            [("limit", "100".to_owned())],
                        )?,
                        Some(draft.scope.subreddit.name()),
                    )
                }
            }
        };
        let response = self.get(
            RedditQuotaOperation::Reconcile,
            url,
            [RedditScope::Read],
            credential,
            observed_at,
        )?;
        let body = response_json(&response)?;
        let mut matches = Vec::new();
        for thing in collect_things(&body) {
            let parsed = parse_thing(thing, fallback_subreddit, response.observed_at())?;
            if let Some(readback) =
                parse_publish_readback(&parsed, &draft.scope, draft.operation, draft, &response)?
            {
                matches.push(readback);
            }
        }
        Ok(RedditReconcileObservation {
            matches,
            source_digest: response.body_digest(),
            observed_at: response.observed_at(),
        })
    }

    fn execute(
        &mut self,
        credential: &RedditEffectCredential,
        draft: &RedditPublishDraft,
        _ingress: &RedditApprovedEffectIngress,
        _observed_at: DateTime<Utc>,
    ) -> Result<ProviderResponse, TransportError> {
        let url = match draft.operation {
            RedditPublishOperation::Post => reddit_url(&["api", "submit"], []),
            RedditPublishOperation::Reply => reddit_url(&["api", "comment"], []),
        }
        .map_err(|_| TransportError::Unavailable)?;
        let body = match draft.operation {
            RedditPublishOperation::Post => json!({
                "api_type": "json",
                "kind": "self",
                "resubmit": false,
                "sr": draft.scope.subreddit.name().as_str(),
                "text": draft.body,
                "title": draft.title.as_deref().unwrap_or_default(),
            }),
            RedditPublishOperation::Reply => json!({
                "api_type": "json",
                "text": draft.body,
                "thing_id": draft.scope.parent().map(RedditThingId::as_str).unwrap_or_default(),
            }),
        };
        let request = RedditEffectRequest::new(
            RedditQuotaOperation::Execute,
            HttpMethod::Post,
            url,
            [RedditScope::Submit],
            credential.reference().clone(),
            Some(body),
        )
        .map_err(|_| TransportError::Unavailable)?;
        self.transport.send(&request)
    }
}

fn parse_publish_readback(
    parsed: &ParsedRedditThing,
    scope: &RedditEffectScope,
    operation: RedditPublishOperation,
    draft: &RedditPublishDraft,
    response: &ProviderResponse,
) -> Result<Option<RedditPublishReadback>, RedditEffectError> {
    if parsed.kind != operation.expected_kind()
        || parsed.subreddit_id.as_ref() != Some(scope.subreddit.subreddit_id())
        || parsed.subreddit_name.as_ref() != Some(scope.subreddit.name())
        || parsed.body_digest != draft.content_digest
    {
        return Ok(None);
    }
    if operation == RedditPublishOperation::Post {
        if parsed.parent_fullname.is_some()
            || parsed.title_digest.as_deref() != draft.title.as_deref().map(digest_bytes).as_deref()
        {
            return Ok(None);
        }
    } else if parsed.parent_fullname.as_ref() != scope.parent() {
        return Ok(None);
    }
    let Some(AccountIdentity::Reddit(account)) = parsed.account.as_ref() else {
        return Ok(None);
    };
    if account != scope.account() {
        return Ok(None);
    }
    let permalink = parsed
        .permalink
        .clone()
        .ok_or(RedditEffectError::InvalidResponse("readback permalink"))?;
    Ok(Some(RedditPublishReadback {
        operation,
        fullname: parsed.fullname.clone(),
        permalink,
        account: account.clone(),
        subreddit: RedditCommunityIdentity::new(
            parsed
                .subreddit_id
                .clone()
                .ok_or(RedditEffectError::InvalidResponse("readback subreddit id"))?,
            parsed
                .subreddit_name
                .clone()
                .ok_or(RedditEffectError::InvalidResponse(
                    "readback subreddit name",
                ))?,
        ),
        content: parsed.content.clone(),
        parent: parsed.parent_fullname.clone(),
        body_digest: parsed.body_digest.clone(),
        title_digest: parsed.title_digest.clone(),
        moderation: parsed.moderation,
        removal_reason: parsed.removal_reason,
        revision: parsed.revision.clone(),
        provider_response_digest: response.body_digest(),
        observed_at: response.observed_at(),
    }))
}

#[derive(Debug)]
pub struct ChannelPublishService<P> {
    provider: P,
    quota: RedditEffectQuotaLedger,
}

impl<P> ChannelPublishService<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            quota: RedditEffectQuotaLedger::with_official_default(),
        }
    }

    pub fn with_quota(provider: P, quota: RedditEffectQuotaLedger) -> Self {
        Self { provider, quota }
    }

    pub const fn provider(&self) -> &P {
        &self.provider
    }

    pub const fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub const fn quota(&self) -> &RedditEffectQuotaLedger {
        &self.quota
    }
}

impl<P> ChannelPublishService<P>
where
    P: RedditEffectProvider,
{
    #[allow(clippy::too_many_lines)]
    pub fn prepare(
        &mut self,
        intent: &RedditPublishIntent,
        credential: &RedditEffectCredential,
        observed_at: DateTime<Utc>,
    ) -> Result<RedditPublishDraft, RedditEffectError> {
        validate_scope_credential(intent.scope(), credential)?;
        credential.require(RedditScope::Identity, observed_at)?;
        credential.require(RedditScope::Read, observed_at)?;
        let account_probe = {
            let _ = self.reserve(RedditQuotaOperation::AuthenticatedProbe, 1, observed_at)?;
            self.provider
                .authenticated_probe(credential, intent.scope().account(), observed_at)?
        };
        let policy = {
            for operation in [
                RedditQuotaOperation::SubredditAbout,
                RedditQuotaOperation::SubredditRules,
                RedditQuotaOperation::PostRequirements,
            ] {
                self.reserve(operation, 1, observed_at)?;
            }
            self.provider
                .subreddit_policy(credential, intent.scope().subreddit(), observed_at)?
        };
        if policy.community() != intent.scope().subreddit() {
            return Err(RedditEffectError::ScopeMismatch(
                "subreddit policy identity drift",
            ));
        }
        match intent.operation() {
            RedditPublishOperation::Post if !policy.post_allowed() => {
                return Err(if policy.account_banned() {
                    RedditEffectError::PolicyRejected("account is banned in subreddit")
                } else if policy.archived() {
                    RedditEffectError::PolicyRejected("subreddit is archived")
                } else {
                    RedditEffectError::PolicyRejected("posts are not allowed")
                });
            }
            RedditPublishOperation::Reply if !policy.reply_allowed() => {
                return Err(if policy.account_banned() {
                    RedditEffectError::PolicyRejected("account is banned in subreddit")
                } else {
                    RedditEffectError::PolicyRejected("replies are not allowed")
                });
            }
            _ => {}
        }
        validate_policy_lengths(intent, &policy)?;
        let parent = if let Some(parent_id) = intent.scope().parent() {
            self.reserve(RedditQuotaOperation::ParentRead, 1, observed_at)?;
            let parent = self.provider.parent_observation(
                credential,
                intent.scope().subreddit(),
                parent_id,
                observed_at,
            )?;
            if parent.moderation() != RedditModerationState::Visible {
                return Err(RedditEffectError::ParentRejected(
                    "parent is removed, filtered, or deleted",
                ));
            }
            if parent.locked() {
                return Err(RedditEffectError::ParentRejected("parent is locked"));
            }
            if parent.archived() {
                return Err(RedditEffectError::ParentRejected("parent is archived"));
            }
            if parent.banned_by() {
                return Err(RedditEffectError::ParentRejected("parent is banned"));
            }
            Some(parent)
        } else {
            None
        };
        let content_digest = digest_bytes(intent.body());
        let authorization_digest = authorization_digest(credential);
        let source_digest = digest_bytes(format!(
            "{}:{}:{}:{}",
            account_probe.response_digest(),
            policy.source_digest(),
            parent
                .as_ref()
                .map_or("none", RedditParentObservation::body_digest),
            intent.idempotency_key().as_str()
        ));
        let draft_revision = digest_json(&json!({
            "operation": intent.operation(),
            "scope": intent.scope(),
            "title_digest": intent.title().map(digest_bytes),
            "content_digest": content_digest,
            "idempotency_key": intent.idempotency_key(),
            "credential_generation": credential.generation(),
            "authorization_digest": authorization_digest.clone(),
            "account_probe": account_probe.response_digest(),
            "policy": policy.source_digest(),
            "parent_revision": parent.as_ref().map(RedditParentObservation::revision),
        }));
        let valid_until = observed_at + Duration::minutes(10);
        Ok(RedditPublishDraft {
            operation: intent.operation(),
            scope: intent.scope().clone(),
            title: intent.title().map(str::to_owned),
            body: intent.body().to_owned(),
            content_digest,
            draft_revision,
            idempotency_key: intent.idempotency_key().clone(),
            credential_generation: credential.generation(),
            authorization_digest,
            account_probe,
            subreddit_policy: policy,
            parent,
            prepared_at: observed_at,
            valid_until,
            source_digest,
            quota: self.quota.snapshot(observed_at),
        })
    }

    pub fn execute(
        &mut self,
        draft: &RedditPublishDraft,
        ingress: &RedditApprovedEffectIngress,
        credential: &RedditEffectCredential,
        checkpoint: &mut RedditPublishCheckpoint,
        observed_at: DateTime<Utc>,
    ) -> Result<RedditPublishDispatch, RedditEffectError> {
        validate_ingress_at(draft, ingress, credential, observed_at)?;
        validate_checkpoint(draft, ingress, credential, checkpoint)?;
        if observed_at >= draft.valid_until {
            return Err(RedditEffectError::ApprovalDrift);
        }
        match checkpoint.phase {
            RedditCheckpointPhase::Verified => {
                let outcome = self.outcome_from_checkpoint(draft, ingress, checkpoint)?;
                return Ok(RedditPublishDispatch::Verified(outcome));
            }
            RedditCheckpointPhase::Uncertain | RedditCheckpointPhase::ReceiptPending => {
                return Err(RedditEffectError::TimeoutUncertain);
            }
            RedditCheckpointPhase::Executing => {
                return Err(RedditEffectError::CheckpointNeedsRecovery);
            }
            RedditCheckpointPhase::Prepared => {}
        }
        credential.require(RedditScope::Submit, observed_at)?;
        let preflight = {
            self.reserve_checkpoint(RedditQuotaOperation::Reconcile, 1, observed_at, checkpoint)?;
            self.provider
                .reconcile(credential, draft, None, observed_at)?
        };
        if preflight.matches().len() > 1 {
            return Err(RedditEffectError::DuplicateIdempotency);
        }
        if let Some(existing) = preflight.matches().first() {
            let receipt = receipt_from_readback(draft, existing);
            checkpoint.receipt = Some(receipt);
            checkpoint.readback = Some(existing.clone());
            checkpoint.phase = RedditCheckpointPhase::Verified;
            let outcome = self.outcome_from_checkpoint(draft, ingress, checkpoint)?;
            return Ok(RedditPublishDispatch::DuplicateIdempotency(outcome));
        }
        self.reserve_checkpoint(RedditQuotaOperation::Execute, 1, observed_at, checkpoint)?;
        checkpoint.phase = RedditCheckpointPhase::Executing;
        let response = match self
            .provider
            .execute(credential, draft, ingress, observed_at)
        {
            Ok(response) => response,
            Err(TransportError::Unavailable | TransportError::TimedOut) => {
                checkpoint.phase = RedditCheckpointPhase::Uncertain;
                return Err(RedditEffectError::TimeoutUncertain);
            }
        };
        if response.status() == 429 {
            let retry = retry_after_receipt(draft.operation(), &response)?;
            checkpoint.phase = RedditCheckpointPhase::Prepared;
            checkpoint.retry_after = Some(retry.clone());
            return Ok(RedditPublishDispatch::RetryAfter(retry));
        }
        if response.status() >= 400 {
            checkpoint.phase = RedditCheckpointPhase::Prepared;
            return Err(response_error(&response));
        }
        let receipt = parse_provider_receipt(&response, draft)?;
        checkpoint.receipt = Some(receipt);
        checkpoint.phase = RedditCheckpointPhase::ReceiptPending;
        self.reserve_checkpoint(RedditQuotaOperation::Reconcile, 1, observed_at, checkpoint)?;
        let readback = self.provider.reconcile(
            credential,
            draft,
            checkpoint
                .receipt
                .as_ref()
                .map(RedditProviderReceipt::fullname),
            observed_at,
        )?;
        self.finish_reconcile(draft, ingress, checkpoint, &readback)
    }

    pub fn reconcile(
        &mut self,
        draft: &RedditPublishDraft,
        ingress: &RedditApprovedEffectIngress,
        credential: &RedditEffectCredential,
        checkpoint: &mut RedditPublishCheckpoint,
        observed_at: DateTime<Utc>,
    ) -> Result<RedditPublishDispatch, RedditEffectError> {
        validate_ingress_at(draft, ingress, credential, observed_at)?;
        validate_checkpoint(draft, ingress, credential, checkpoint)?;
        if checkpoint.phase == RedditCheckpointPhase::Verified {
            return Ok(RedditPublishDispatch::Verified(
                self.outcome_from_checkpoint(draft, ingress, checkpoint)?,
            ));
        }
        self.reserve_checkpoint(RedditQuotaOperation::Reconcile, 1, observed_at, checkpoint)?;
        let scan = self.provider.reconcile(
            credential,
            draft,
            checkpoint
                .receipt
                .as_ref()
                .map(RedditProviderReceipt::fullname),
            observed_at,
        )?;
        if scan.matches().is_empty() {
            return if checkpoint.phase == RedditCheckpointPhase::Uncertain
                || checkpoint.phase == RedditCheckpointPhase::ReceiptPending
            {
                Err(RedditEffectError::TimeoutUncertain)
            } else {
                Ok(RedditPublishDispatch::NoMatch)
            };
        }
        if scan.matches().len() > 1 {
            return Err(RedditEffectError::DuplicateIdempotency);
        }
        self.finish_reconcile(draft, ingress, checkpoint, &scan)
    }

    fn finish_reconcile(
        &self,
        draft: &RedditPublishDraft,
        ingress: &RedditApprovedEffectIngress,
        checkpoint: &mut RedditPublishCheckpoint,
        scan: &RedditReconcileObservation,
    ) -> Result<RedditPublishDispatch, RedditEffectError> {
        let readback = scan
            .matches()
            .first()
            .ok_or(RedditEffectError::ReadbackMismatch)?;
        let receipt = checkpoint
            .receipt
            .clone()
            .unwrap_or_else(|| receipt_from_readback(draft, readback));
        if receipt.fullname() != readback.fullname()
            || receipt.permalink() != readback.permalink()
            || receipt.content_digest() != draft.content_digest()
            || readback.body_digest() != draft.content_digest()
            || readback.operation() != draft.operation()
            || readback.account() != draft.scope().account()
            || readback.subreddit() != draft.scope().subreddit()
            || readback.parent() != draft.scope().parent()
        {
            return Err(RedditEffectError::ReadbackMismatch);
        }
        if readback.moderation() != RedditModerationState::Visible
            || readback.removal_reason().is_some()
        {
            return Err(RedditEffectError::ModerationDrift);
        }
        checkpoint.receipt = Some(receipt);
        checkpoint.readback = Some(readback.clone());
        checkpoint.phase = RedditCheckpointPhase::Verified;
        let outcome = self.outcome_from_checkpoint(draft, ingress, checkpoint)?;
        Ok(RedditPublishDispatch::Verified(outcome))
    }

    fn outcome_from_checkpoint(
        &self,
        draft: &RedditPublishDraft,
        ingress: &RedditApprovedEffectIngress,
        checkpoint: &RedditPublishCheckpoint,
    ) -> Result<RedditPublishOutcome, RedditEffectError> {
        let receipt = checkpoint
            .receipt
            .as_ref()
            .ok_or(RedditEffectError::IncompleteOutcome)?;
        let readback = checkpoint
            .readback
            .as_ref()
            .ok_or(RedditEffectError::IncompleteOutcome)?;
        let verification_source = digest_bytes(format!(
            "{}:{}:{}",
            draft.source_digest,
            receipt.provider_response_digest(),
            readback.provider_response_digest()
        ));
        let evidence_digest = digest_json(&json!({
            "fullname": readback.fullname(),
            "permalink": readback.permalink(),
            "body_digest": readback.body_digest(),
            "moderation": readback.moderation(),
            "removal_reason": readback.removal_reason(),
            "revision": readback.revision(),
            "source_digest": verification_source,
        }));
        Ok(RedditPublishOutcome {
            provenance: self.provider.provenance(),
            operation: draft.operation,
            scope: draft.scope.clone(),
            effect_id: ingress.effect_id.clone(),
            draft_revision: draft.draft_revision.clone(),
            content_digest: draft.content_digest.clone(),
            credential_generation: ingress.credential_generation,
            authorization_digest: ingress.authorization_digest.clone(),
            approval_revision: ingress.approval_revision.clone(),
            receipt: receipt.clone(),
            verification: RedditVerificationEvidence {
                fullname: readback.fullname.clone(),
                permalink: readback.permalink.clone(),
                body_digest: readback.body_digest.clone(),
                moderation: readback.moderation,
                removal_reason: readback.removal_reason,
                revision: readback.revision.clone(),
                source_digest: verification_source,
                evidence_digest,
                observed_at: readback.observed_at,
            },
            quota: self.quota.snapshot(readback.observed_at),
        })
    }

    fn reserve(
        &mut self,
        operation: RedditQuotaOperation,
        cost: u32,
        observed_at: DateTime<Utc>,
    ) -> Result<RedditQuotaReceipt, RedditEffectError> {
        self.quota.reserve(operation, cost, observed_at)
    }

    fn reserve_checkpoint(
        &mut self,
        operation: RedditQuotaOperation,
        cost: u32,
        observed_at: DateTime<Utc>,
        checkpoint: &mut RedditPublishCheckpoint,
    ) -> Result<(), RedditEffectError> {
        let receipt = self.reserve(operation, cost, observed_at)?;
        checkpoint.quota_receipts.push(receipt);
        Ok(())
    }
}

fn validate_scope_credential(
    scope: &RedditEffectScope,
    credential: &RedditEffectCredential,
) -> Result<(), RedditEffectError> {
    if scope.app() != credential.app() {
        return Err(RedditEffectError::ScopeMismatch("app identity drift"));
    }
    if scope.account() != credential.account() {
        return Err(RedditEffectError::AccountMismatch);
    }
    Ok(())
}

fn validate_policy_lengths(
    intent: &RedditPublishIntent,
    policy: &RedditSubredditPolicy,
) -> Result<(), RedditEffectError> {
    if let Some(title) = intent.title() {
        if policy
            .title_min_length()
            .is_some_and(|minimum| title.chars().count() < minimum as usize)
        {
            return Err(RedditEffectError::PolicyRejected(
                "title is below subreddit minimum",
            ));
        }
        if policy
            .title_max_length()
            .is_some_and(|maximum| title.chars().count() > maximum as usize)
        {
            return Err(RedditEffectError::PolicyRejected(
                "title exceeds subreddit maximum",
            ));
        }
    }
    if policy
        .body_min_length()
        .is_some_and(|minimum| intent.body().chars().count() < minimum as usize)
    {
        return Err(RedditEffectError::PolicyRejected(
            "body is below subreddit minimum",
        ));
    }
    if policy
        .body_max_length()
        .is_some_and(|maximum| intent.body().chars().count() > maximum as usize)
    {
        return Err(RedditEffectError::PolicyRejected(
            "body exceeds subreddit maximum",
        ));
    }
    Ok(())
}

fn validate_ingress(
    draft: &RedditPublishDraft,
    ingress: &RedditApprovedEffectIngress,
) -> Result<(), RedditEffectError> {
    if ingress.scope() != draft.scope()
        || ingress.draft_revision() != draft.draft_revision()
        || ingress.content_digest() != draft.content_digest()
        || ingress.idempotency_key() != draft.idempotency_key()
        || ingress.credential_generation() != draft.credential_generation()
        || ingress.authorization_digest() != draft.authorization_digest()
    {
        return Err(RedditEffectError::ApprovalDrift);
    }
    Ok(())
}

fn validate_ingress_at(
    draft: &RedditPublishDraft,
    ingress: &RedditApprovedEffectIngress,
    credential: &RedditEffectCredential,
    observed_at: DateTime<Utc>,
) -> Result<(), RedditEffectError> {
    validate_ingress(draft, ingress)?;
    validate_scope_credential(draft.scope(), credential)?;
    credential.assert_usable(observed_at)?;
    if authorization_digest(credential) != ingress.authorization_digest() {
        return Err(RedditEffectError::ApprovalDrift);
    }
    if credential.generation() != ingress.credential_generation()
        || observed_at < ingress.approved_at()
        || observed_at >= ingress.expires_at()
    {
        return Err(RedditEffectError::CredentialGenerationDrift);
    }
    Ok(())
}

fn validate_checkpoint(
    draft: &RedditPublishDraft,
    ingress: &RedditApprovedEffectIngress,
    credential: &RedditEffectCredential,
    checkpoint: &RedditPublishCheckpoint,
) -> Result<(), RedditEffectError> {
    if checkpoint.scope != *draft.scope()
        || checkpoint.effect_id != *ingress.effect_id()
        || checkpoint.draft_revision != draft.draft_revision()
        || checkpoint.content_digest != draft.content_digest()
        || checkpoint.idempotency_key != *draft.idempotency_key()
        || checkpoint.authorization_digest != draft.authorization_digest()
        || checkpoint.approval_revision != *ingress.approval_revision()
    {
        return Err(RedditEffectError::ApprovalDrift);
    }
    if checkpoint.credential_generation != credential.generation() {
        return Err(RedditEffectError::CredentialGenerationDrift);
    }
    Ok(())
}

fn receipt_from_readback(
    draft: &RedditPublishDraft,
    readback: &RedditPublishReadback,
) -> RedditProviderReceipt {
    RedditProviderReceipt {
        operation: draft.operation,
        fullname: readback.fullname.clone(),
        permalink: readback.permalink.clone(),
        idempotency_key: draft.idempotency_key.clone(),
        draft_revision: draft.draft_revision.clone(),
        content_digest: draft.content_digest.clone(),
        provider_response_digest: readback.provider_response_digest.clone(),
        observed_at: readback.observed_at,
    }
}

fn parse_provider_receipt(
    response: &ProviderResponse,
    draft: &RedditPublishDraft,
) -> Result<RedditProviderReceipt, RedditEffectError> {
    let body = response_json(response)?;
    if body
        .pointer("/json/errors")
        .and_then(Value::as_array)
        .is_some_and(|errors| !errors.is_empty())
        || body
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(|errors| !errors.is_empty())
    {
        return Err(RedditEffectError::Adapter(
            ChannelAdapterError::ProviderRejected {
                provider: ProviderId::Reddit,
                status: response.status(),
                code: response_code(&body),
            },
        ));
    }
    let receipt =
        find_receipt(&body, draft.operation()).ok_or(RedditEffectError::ReceiptUnavailable)?;
    Ok(RedditProviderReceipt {
        operation: draft.operation(),
        fullname: receipt.0,
        permalink: receipt.1,
        idempotency_key: draft.idempotency_key.clone(),
        draft_revision: draft.draft_revision.clone(),
        content_digest: draft.content_digest.clone(),
        provider_response_digest: response.body_digest(),
        observed_at: response.observed_at(),
    })
}

fn find_receipt(
    value: &Value,
    operation: RedditPublishOperation,
) -> Option<(RedditThingId, String)> {
    if let Some(name) = value.get("name").and_then(Value::as_str) {
        let expected_prefix = match operation {
            RedditPublishOperation::Post => "t3_",
            RedditPublishOperation::Reply => "t1_",
        };
        let permalink = value
            .get("permalink")
            .or_else(|| value.get("url"))
            .and_then(Value::as_str)
            .and_then(canonical_permalink);
        if name.starts_with(expected_prefix)
            && let Some(permalink) = permalink
            && let Ok(fullname) = RedditThingId::new(name.to_owned())
        {
            return Some((fullname, permalink));
        }
    }
    match value {
        Value::Object(object) => object
            .values()
            .find_map(|child| find_receipt(child, operation)),
        Value::Array(array) => array
            .iter()
            .find_map(|child| find_receipt(child, operation)),
        _ => None,
    }
}

fn canonical_permalink(value: &str) -> Option<String> {
    if value.starts_with('/') {
        return Some(value.to_owned());
    }
    let url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !matches!(url.host_str(), Some("reddit.com" | "www.reddit.com"))
        || !url.path().starts_with('/')
    {
        return None;
    }
    Some(
        url.path().to_owned()
            + url
                .query()
                .map_or_else(String::new, |query| format!("?{query}"))
                .as_str(),
    )
}

fn retry_after_receipt(
    operation: RedditPublishOperation,
    response: &ProviderResponse,
) -> Result<RedditRetryAfterReceipt, RedditEffectError> {
    let Some(retry_after_seconds) = response.retry_after_seconds() else {
        return Err(RedditEffectError::RateLimitWithoutReset);
    };
    Ok(RedditRetryAfterReceipt {
        operation,
        retry_after_seconds,
        rate_limit_reset: response
            .header("x-ratelimit-reset")
            .and_then(parse_retry_seconds),
        rate_limit_remaining: response
            .header("x-ratelimit-remaining")
            .and_then(|value| value.trim().parse::<u64>().ok()),
        provider_response_digest: response.body_digest(),
        observed_at: response.observed_at(),
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct MissionRedditEffectCapability {
    scope: RedditEffectScope,
    operation: RedditPublishOperation,
    draft_revision: String,
    content_digest: String,
    credential_generation: u64,
    authorization_digest: String,
    approval_revision: RedditApprovalRevision,
}

impl MissionRedditEffectCapability {
    pub fn new(
        scope: RedditEffectScope,
        operation: RedditPublishOperation,
        draft_revision: impl Into<String>,
        content_digest: impl Into<String>,
        credential_generation: u64,
        authorization_digest: impl Into<String>,
        approval_revision: RedditApprovalRevision,
    ) -> Result<Self, RedditEffectError> {
        let draft_revision = draft_revision.into();
        let content_digest = content_digest.into();
        let authorization_digest = authorization_digest.into();
        validate_digest(&draft_revision)?;
        validate_digest(&content_digest)?;
        validate_digest(&authorization_digest)?;
        Ok(Self {
            scope,
            operation,
            draft_revision,
            content_digest,
            credential_generation,
            authorization_digest,
            approval_revision,
        })
    }

    pub const fn scope(&self) -> &RedditEffectScope {
        &self.scope
    }
}

#[derive(Clone, Debug)]
pub struct MissionRedditEffectConsumer {
    capability: MissionRedditEffectCapability,
}

impl MissionRedditEffectConsumer {
    pub fn new(capability: MissionRedditEffectCapability) -> Self {
        Self { capability }
    }

    pub const fn capability(&self) -> &MissionRedditEffectCapability {
        &self.capability
    }

    pub fn accept(
        &self,
        draft: &RedditPublishDraft,
        ingress: &RedditApprovedEffectIngress,
        outcome: RedditPublishOutcome,
        observed_at: DateTime<Utc>,
    ) -> Result<MissionRedditAcceptedOutcome, RedditEffectError> {
        if outcome.provenance() != RedditEffectProvenance::ProductionApprovedDataApi {
            return Err(RedditEffectError::FixtureProvenance);
        }
        if observed_at >= ingress.expires_at()
            || outcome.scope() != self.capability.scope()
            || outcome.scope() != draft.scope()
            || outcome.operation() != self.capability.operation
            || outcome.operation() != draft.operation()
            || outcome.draft_revision() != self.capability.draft_revision
            || outcome.draft_revision() != draft.draft_revision()
            || outcome.content_digest() != self.capability.content_digest
            || outcome.content_digest() != draft.content_digest()
            || outcome.credential_generation() != self.capability.credential_generation
            || outcome.credential_generation() != ingress.credential_generation()
            || outcome.authorization_digest() != self.capability.authorization_digest
            || outcome.authorization_digest() != draft.authorization_digest()
            || outcome.authorization_digest() != ingress.authorization_digest()
            || outcome.approval_revision() != &self.capability.approval_revision
            || outcome.approval_revision() != ingress.approval_revision()
            || outcome.receipt().fullname() != outcome.verification().fullname()
            || outcome.receipt().permalink() != outcome.verification().permalink()
            || outcome.receipt().content_digest() != outcome.verification().body_digest()
            || outcome.verification().moderation() != RedditModerationState::Visible
            || outcome.verification().removal_reason().is_some()
        {
            return Err(RedditEffectError::IncompleteOutcome);
        }
        Ok(MissionRedditAcceptedOutcome {
            outcome,
            accepted_at: observed_at,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionRedditAcceptedOutcome {
    outcome: RedditPublishOutcome,
    accepted_at: DateTime<Utc>,
}

impl MissionRedditAcceptedOutcome {
    pub const fn outcome(&self) -> &RedditPublishOutcome {
        &self.outcome
    }

    pub const fn accepted_at(&self) -> DateTime<Utc> {
        self.accepted_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedditRealEffectGate {
    credential_reference: CredentialReference,
    approval_reference: String,
}

impl RedditRealEffectGate {
    pub fn from_environment() -> Result<Self, RedditEffectError> {
        Self::from_environment_values(
            std::env::var(REDDIT_REAL_EFFECT_ENABLE_ENV).ok().as_deref(),
            std::env::var(REDDIT_REAL_EFFECT_SECRET_REFERENCE_ENV)
                .ok()
                .as_deref(),
            std::env::var(REDDIT_REAL_EFFECT_ACCESS_TOKEN_ENV)
                .ok()
                .as_deref(),
            std::env::var(REDDIT_REAL_EFFECT_APPROVAL_REFERENCE_ENV)
                .ok()
                .as_deref(),
        )
    }

    pub fn from_environment_values(
        enabled: Option<&str>,
        secret_reference: Option<&str>,
        access_token: Option<&str>,
        approval_reference: Option<&str>,
    ) -> Result<Self, RedditEffectError> {
        if enabled != Some("1") {
            return Err(RedditEffectError::BlockedEnvironment(
                "HARTEVO_REDDIT_REAL_EFFECT must be 1",
            ));
        }
        let secret_reference = secret_reference.ok_or(RedditEffectError::BlockedEnvironment(
            "approved Reddit secret reference is missing",
        ))?;
        let access_token = access_token.ok_or(RedditEffectError::BlockedEnvironment(
            "approved Reddit access token is missing",
        ))?;
        if access_token.is_empty()
            || access_token
                .chars()
                .any(|character| matches!(character, '"' | '\\' | '\n' | '\r'))
        {
            return Err(RedditEffectError::BlockedEnvironment(
                "approved Reddit access token is invalid",
            ));
        }
        let approval_reference = approval_reference
            .filter(|value| !value.is_empty() && !value.chars().any(char::is_whitespace))
            .ok_or(RedditEffectError::BlockedEnvironment(
                "approved Reddit Data API reference is missing",
            ))?;
        Ok(Self {
            credential_reference: CredentialReference::new(secret_reference.to_owned())?,
            approval_reference: approval_reference.to_owned(),
        })
    }

    pub const fn credential_reference(&self) -> &CredentialReference {
        &self.credential_reference
    }

    pub fn approval_reference(&self) -> &str {
        &self.approval_reference
    }
}

pub fn execute_real_reddit_probe(
    gate: &RedditRealEffectGate,
    app: RedditEffectAppId,
    account: &RedditAccountIdentity,
    approval: RedditDataApiApproval,
    granted_scopes: BTreeSet<RedditScope>,
    credential_generation: u64,
    observed_at: DateTime<Utc>,
) -> Result<RedditAccountProbe, RedditEffectError> {
    if approval.approval_reference() != gate.approval_reference() {
        return Err(RedditEffectError::ApprovalDrift);
    }
    let source = RedditEnvironmentOAuthTokenSource::new(REDDIT_REAL_EFFECT_ACCESS_TOKEN_ENV)?;
    let transport = RedditHttpsTransport::new(source);
    let mut provider = RedditApprovedDataApiProvider::new(transport);
    let credential = RedditEffectCredential::new(
        app,
        account.clone(),
        approval,
        granted_scopes,
        gate.credential_reference().clone(),
        credential_generation,
        None,
    );
    provider.authenticated_probe(&credential, account, observed_at)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use chrono::TimeZone;

    use super::*;

    #[derive(Debug)]
    struct ScriptedTransport {
        responses: VecDeque<Result<ProviderResponse, TransportError>>,
        requests: Vec<RedditEffectRequest>,
    }

    impl ScriptedTransport {
        fn new(
            responses: impl IntoIterator<Item = Result<ProviderResponse, TransportError>>,
        ) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                requests: Vec::new(),
            }
        }

        fn push(&mut self, response: Result<ProviderResponse, TransportError>) {
            self.responses.push_back(response);
        }
    }

    impl RedditEffectTransport for ScriptedTransport {
        fn provenance(&self) -> RedditEffectProvenance {
            RedditEffectProvenance::DeterministicFixture
        }

        fn send(
            &mut self,
            request: &RedditEffectRequest,
        ) -> Result<ProviderResponse, TransportError> {
            self.requests.push(request.clone());
            self.responses
                .pop_front()
                .expect("fixture has a response for every request")
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5)
            .single()
            .expect("fixture timestamp is valid")
    }

    fn response(body: &str) -> ProviderResponse {
        ProviderResponse::new(
            200,
            [("content-type".to_owned(), "application/json".to_owned())],
            body,
            now(),
        )
    }

    fn response_with_headers(
        status: u16,
        headers: impl IntoIterator<Item = (&'static str, &'static str)>,
        body: &str,
    ) -> ProviderResponse {
        ProviderResponse::new(
            status,
            headers
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .chain([(
                    String::from("content-type"),
                    String::from("application/json"),
                )]),
            body,
            now(),
        )
    }

    fn me() -> ProviderResponse {
        response(r#"{"id":"t2_account01","name":"builder01"}"#)
    }

    fn about() -> ProviderResponse {
        response(
            r#"{"data":{"id":"t5_sub01","display_name":"phaseone","user_is_banned":false,"archived":false}}"#,
        )
    }

    fn rules() -> ProviderResponse {
        response(r#"{"data":{"children":[]}}"#)
    }

    fn requirements() -> ProviderResponse {
        response(
            r#"{"title_text_min_length":1,"title_text_max_length":300,"body_text_min_length":1,"body_text_max_length":40000}"#,
        )
    }

    fn empty_listing() -> ProviderResponse {
        response(r#"{"data":{"children":[]}}"#)
    }

    fn post_listing(body: &str, removed: bool) -> ProviderResponse {
        let mut data = serde_json::json!({
            "name": "t3_post01",
            "subreddit_id": "t5_sub01",
            "subreddit": "phaseone",
            "author": "builder01",
            "author_fullname": "t2_account01",
            "selftext": body,
            "title": "A title",
            "permalink": "/r/phaseone/comments/post01/a-title/",
            "edited": false,
            "locked": false,
            "archived": false,
        });
        if removed {
            data["removed_by_category"] = serde_json::json!("moderator");
        }
        let content = serde_json::json!({
            "data": {"children": [{"kind": "t3", "data": data}]}
        })
        .to_string();
        response(&content)
    }

    fn parent_info(locked: bool) -> ProviderResponse {
        let locked = locked.to_string();
        let content = format!(
            r#"{{"data":[{{"kind":"t3","data":{{"name":"t3_parent01","subreddit_id":"t5_sub01","subreddit":"phaseone","author":"builder01","author_fullname":"t2_account01","selftext":"parent","title":"Parent","permalink":"/r/phaseone/comments/parent01/parent/","edited":false,"locked":{locked},"archived":false}}}}]}}"#
        );
        response(&content)
    }

    fn submit_receipt() -> ProviderResponse {
        response(
            r#"{"json":{"data":{"name":"t3_post01","permalink":"/r/phaseone/comments/post01/a-title/"}}}"#,
        )
    }

    fn reply_submit_receipt() -> ProviderResponse {
        response(
            r#"{"json":{"data":{"things":[{"kind":"t1","data":{"name":"t1_comment01","permalink":"/r/phaseone/comments/parent01/parent/comment01/"}}]}}}"#,
        )
    }

    fn reply_info_readback() -> ProviderResponse {
        response(
            r#"{"data":[{"kind":"t1","data":{"name":"t1_comment01","subreddit_id":"t5_sub01","subreddit":"phaseone","author":"builder01","author_fullname":"t2_account01","body":"reply body","parent_id":"t3_parent01","link_id":"t3_parent01","permalink":"/r/phaseone/comments/parent01/parent/comment01/","edited":false,"locked":false,"archived":false}}]}"#,
        )
    }

    fn info_readback(body: &str, removed: bool) -> ProviderResponse {
        let mut data = serde_json::json!({
            "name": "t3_post01",
            "subreddit_id": "t5_sub01",
            "subreddit": "phaseone",
            "author": "builder01",
            "author_fullname": "t2_account01",
            "selftext": body,
            "title": "A title",
            "permalink": "/r/phaseone/comments/post01/a-title/",
            "edited": false,
            "locked": false,
            "archived": false,
        });
        if removed {
            data["removed_by_category"] = serde_json::json!("moderator");
        }
        let content = serde_json::json!({
            "data": [{"kind": "t3", "data": data}]
        })
        .to_string();
        response(&content)
    }

    fn account() -> RedditAccountIdentity {
        RedditAccountIdentity::new(
            RedditAccountId::new("t2_account01").expect("fixture account id is valid"),
            Some("builder01".to_owned()),
        )
    }

    fn community() -> RedditCommunityIdentity {
        RedditCommunityIdentity::new(
            RedditSubredditId::new("t5_sub01").expect("fixture subreddit id is valid"),
            RedditSubredditName::new("phaseone").expect("fixture subreddit name is valid"),
        )
    }

    fn fixture_credential(
        generation: u64,
        scopes: BTreeSet<RedditScope>,
    ) -> RedditEffectCredential {
        let approval = RedditDataApiApproval::new("approval01", scopes.clone(), now())
            .expect("fixture approval is valid");
        RedditEffectCredential::new(
            RedditEffectAppId::new("app01").expect("fixture app id is valid"),
            account(),
            approval,
            scopes,
            CredentialReference::new("reddit-secret-ref").expect("fixture reference is opaque"),
            generation,
            None,
        )
    }

    fn all_scopes() -> BTreeSet<RedditScope> {
        BTreeSet::from([
            RedditScope::Identity,
            RedditScope::Read,
            RedditScope::Submit,
        ])
    }

    fn post_intent() -> RedditPublishIntent {
        let scope = RedditEffectScope::new(
            RedditEffectAppId::new("app01").expect("fixture app id is valid"),
            account(),
            community(),
            None,
        );
        RedditPublishIntent::new(
            RedditPublishOperation::Post,
            scope,
            Some("A title".to_owned()),
            "hello",
            RedditIdempotencyKey::new("idem01").expect("fixture idempotency key is valid"),
        )
        .expect("fixture intent is valid")
    }

    fn reply_intent() -> RedditPublishIntent {
        let scope = RedditEffectScope::new(
            RedditEffectAppId::new("app01").expect("fixture app id is valid"),
            account(),
            community(),
            Some(RedditThingId::new("t3_parent01").expect("fixture parent is valid")),
        );
        RedditPublishIntent::new(
            RedditPublishOperation::Reply,
            scope,
            None,
            "reply body",
            RedditIdempotencyKey::new("reply-idem01").expect("fixture idempotency key is valid"),
        )
        .expect("fixture reply intent is valid")
    }

    fn prepare_service(
        extra: impl IntoIterator<Item = Result<ProviderResponse, TransportError>>,
    ) -> (
        ChannelPublishService<RedditApprovedDataApiProvider<ScriptedTransport>>,
        RedditEffectCredential,
    ) {
        let responses = [Ok(me()), Ok(about()), Ok(rules()), Ok(requirements())]
            .into_iter()
            .chain(extra)
            .collect::<Vec<_>>();
        (
            ChannelPublishService::new(RedditApprovedDataApiProvider::new(ScriptedTransport::new(
                responses,
            ))),
            fixture_credential(1, all_scopes()),
        )
    }

    fn ingress_for(
        draft: &RedditPublishDraft,
        credential: &RedditEffectCredential,
    ) -> RedditApprovedEffectIngress {
        RedditApprovedEffectIngress::new_authority_bound(
            RedditEffectId::new("effect01").expect("fixture effect id is valid"),
            draft.scope().clone(),
            draft.draft_revision(),
            draft.content_digest(),
            draft.idempotency_key().clone(),
            credential.generation(),
            draft.authorization_digest(),
            RedditApprovalRevision::new("approval-revision01").expect("fixture revision is valid"),
            now(),
            now() + Duration::minutes(30),
        )
        .expect("fixture ingress is valid")
    }

    #[test]
    fn prepare_is_read_only_and_binds_exact_review_fence() {
        let (mut service, credential) = prepare_service([]);
        let draft = service
            .prepare(&post_intent(), &credential, now())
            .expect("draft prepares");
        assert_eq!(draft.content_digest(), digest_bytes("hello"));
        assert_eq!(draft.scope().account(), &account());
        assert_eq!(draft.scope().subreddit(), &community());
        assert_eq!(draft.idempotency_key().as_str(), "idem01");
        assert_eq!(
            service
                .provider()
                .transport()
                .requests
                .iter()
                .map(RedditEffectRequest::method)
                .collect::<Vec<_>>(),
            vec![HttpMethod::Get; 4]
        );
        assert!(
            service
                .provider()
                .transport()
                .requests
                .iter()
                .all(|request| request.body().is_none())
        );
    }

    #[test]
    fn explicit_post_dispatch_has_one_write_and_independent_readback() {
        let (mut service, credential) = prepare_service([
            Ok(empty_listing()),
            Ok(submit_receipt()),
            Ok(info_readback("hello", false)),
        ]);
        let draft = service
            .prepare(&post_intent(), &credential, now())
            .expect("draft prepares");
        let ingress = ingress_for(&draft, &credential);
        let mut checkpoint =
            RedditPublishCheckpoint::new(&draft, &ingress).expect("checkpoint binds exact draft");
        let dispatch = service
            .execute(&draft, &ingress, &credential, &mut checkpoint, now())
            .expect("approved post executes");
        let RedditPublishDispatch::Verified(outcome) = dispatch else {
            panic!("expected verified outcome");
        };
        assert_eq!(checkpoint.phase(), RedditCheckpointPhase::Verified);
        assert_eq!(outcome.receipt().fullname().as_str(), "t3_post01");
        assert_eq!(
            outcome.verification().permalink(),
            "/r/phaseone/comments/post01/a-title/"
        );
        assert_eq!(outcome.verification().body_digest(), draft.content_digest());
        assert_eq!(
            outcome.verification().moderation(),
            RedditModerationState::Visible
        );
        let requests = &service.provider().transport().requests;
        assert_eq!(requests.len(), 7);
        assert_eq!(requests[4].method(), HttpMethod::Get);
        assert_eq!(requests[5].method(), HttpMethod::Post);
        assert_eq!(requests[6].method(), HttpMethod::Get);
        assert_eq!(
            requests[5].body().and_then(|body| body.get("sr")),
            Some(&json!("phaseone"))
        );
        assert_eq!(
            requests[5].body().and_then(|body| body.get("text")),
            Some(&json!("hello"))
        );
        assert_eq!(checkpoint.quota_receipts().len(), 3);
        assert_eq!(outcome.quota().consumed(), 7);
    }

    #[test]
    fn reply_dispatch_binds_parent_and_readback_fullname() {
        let (mut service, credential) = prepare_service([
            Ok(parent_info(false)),
            Ok(response(r"[]")),
            Ok(reply_submit_receipt()),
            Ok(reply_info_readback()),
        ]);
        let draft = service
            .prepare(&reply_intent(), &credential, now())
            .expect("reply draft prepares");
        assert_eq!(
            draft.parent().map(RedditParentObservation::content),
            Some(&ContentIdentity::Reddit(RedditContentIdentity::new(
                RedditThingId::new("t3_parent01").expect("fixture parent is valid"),
                RedditThingKind::Post,
                Some(RedditSubredditId::new("t5_sub01").expect("fixture subreddit id is valid")),
                None,
            )))
        );
        let ingress = ingress_for(&draft, &credential);
        let mut checkpoint =
            RedditPublishCheckpoint::new(&draft, &ingress).expect("checkpoint binds exact reply");
        let dispatch = service
            .execute(&draft, &ingress, &credential, &mut checkpoint, now())
            .expect("approved reply executes");
        let RedditPublishDispatch::Verified(outcome) = dispatch else {
            panic!("expected verified reply");
        };
        assert_eq!(outcome.receipt().fullname().as_str(), "t1_comment01");
        assert_eq!(
            outcome.verification().body_digest(),
            digest_bytes("reply body")
        );
        let requests = &service.provider().transport().requests;
        assert_eq!(requests[6].method(), HttpMethod::Post);
        assert_eq!(
            requests[6].body().and_then(|body| body.get("thing_id")),
            Some(&json!("t3_parent01"))
        );
    }

    #[test]
    fn mission_rejects_deterministic_fixture_outcome() {
        let (mut service, credential) = prepare_service([
            Ok(empty_listing()),
            Ok(submit_receipt()),
            Ok(info_readback("hello", false)),
        ]);
        let draft = service
            .prepare(&post_intent(), &credential, now())
            .expect("draft prepares");
        let ingress = ingress_for(&draft, &credential);
        let mut checkpoint =
            RedditPublishCheckpoint::new(&draft, &ingress).expect("checkpoint binds exact draft");
        let dispatch = service
            .execute(&draft, &ingress, &credential, &mut checkpoint, now())
            .expect("post executes");
        let RedditPublishDispatch::Verified(outcome) = dispatch else {
            panic!("expected verified outcome");
        };
        assert_eq!(
            outcome.provenance(),
            RedditEffectProvenance::DeterministicFixture
        );
        let capability = MissionRedditEffectCapability::new(
            draft.scope().clone(),
            draft.operation(),
            draft.draft_revision().to_owned(),
            draft.content_digest().to_owned(),
            credential.generation(),
            draft.authorization_digest().to_owned(),
            ingress.approval_revision().clone(),
        )
        .expect("capability is exact");
        let consumer = MissionRedditEffectConsumer::new(capability);
        assert_eq!(
            consumer.accept(&draft, &ingress, outcome, now()),
            Err(RedditEffectError::FixtureProvenance)
        );
    }

    #[test]
    fn reply_requires_parent_and_locked_parent_fails_closed() {
        let (mut service, credential) = prepare_service([Ok(parent_info(true))]);
        let error = service
            .prepare(&reply_intent(), &credential, now())
            .expect_err("locked parent must not produce a draft");
        assert_eq!(error, RedditEffectError::ParentRejected("parent is locked"));
        assert!(
            service
                .provider()
                .transport()
                .requests
                .iter()
                .all(|request| request.method() == HttpMethod::Get)
        );
    }

    #[test]
    fn timeout_reopen_reconciles_without_second_write() {
        let (mut service, credential) =
            prepare_service([Ok(empty_listing()), Err(TransportError::TimedOut)]);
        let draft = service
            .prepare(&post_intent(), &credential, now())
            .expect("draft prepares");
        let ingress = ingress_for(&draft, &credential);
        let mut checkpoint =
            RedditPublishCheckpoint::new(&draft, &ingress).expect("checkpoint binds exact draft");
        assert_eq!(
            service.execute(&draft, &ingress, &credential, &mut checkpoint, now()),
            Err(RedditEffectError::TimeoutUncertain)
        );
        assert_eq!(checkpoint.phase(), RedditCheckpointPhase::Uncertain);
        let reopened = RedditPublishCheckpoint::reopen(
            checkpoint.durable_json().expect("checkpoint serializes"),
        )
        .expect("uncertain checkpoint reopens");
        let mut checkpoint = reopened;
        service
            .provider_mut()
            .transport_mut()
            .push(Ok(post_listing("hello", false)));
        let dispatch = service
            .reconcile(&draft, &ingress, &credential, &mut checkpoint, now())
            .expect("independent reconcile succeeds");
        assert!(matches!(dispatch, RedditPublishDispatch::Verified(_)));
        assert_eq!(checkpoint.phase(), RedditCheckpointPhase::Verified);
        assert_eq!(
            service
                .provider()
                .transport()
                .requests
                .iter()
                .filter(|request| request.method() == HttpMethod::Post)
                .count(),
            1
        );
    }

    #[test]
    fn duplicate_preflight_adopts_exact_existing_object_without_write() {
        let (mut service, credential) = prepare_service([Ok(post_listing("hello", false))]);
        let draft = service
            .prepare(&post_intent(), &credential, now())
            .expect("draft prepares");
        let ingress = ingress_for(&draft, &credential);
        let mut checkpoint =
            RedditPublishCheckpoint::new(&draft, &ingress).expect("checkpoint binds exact draft");
        let dispatch = service
            .execute(&draft, &ingress, &credential, &mut checkpoint, now())
            .expect("duplicate is reconciled");
        assert!(matches!(
            dispatch,
            RedditPublishDispatch::DuplicateIdempotency(_)
        ));
        assert_eq!(
            service
                .provider()
                .transport()
                .requests
                .iter()
                .filter(|request| request.method() == HttpMethod::Post)
                .count(),
            0
        );
    }

    #[test]
    fn provider_429_emits_retry_receipt_and_no_reset_blocks() {
        let (mut service, credential) = prepare_service([
            Ok(empty_listing()),
            Ok(response_with_headers(
                429,
                [("x-ratelimit-reset", "7"), ("x-ratelimit-remaining", "0")],
                r#"{"error":"RATELIMIT"}"#,
            )),
        ]);
        let draft = service
            .prepare(&post_intent(), &credential, now())
            .expect("draft prepares");
        let ingress = ingress_for(&draft, &credential);
        let mut checkpoint =
            RedditPublishCheckpoint::new(&draft, &ingress).expect("checkpoint binds exact draft");
        let dispatch = service
            .execute(&draft, &ingress, &credential, &mut checkpoint, now())
            .expect("rate limit becomes durable receipt");
        let RedditPublishDispatch::RetryAfter(receipt) = dispatch else {
            panic!("expected retry receipt");
        };
        assert_eq!(receipt.retry_after_seconds(), 7);
        assert_eq!(checkpoint.phase(), RedditCheckpointPhase::Prepared);

        let (mut service, credential) = prepare_service([
            Ok(empty_listing()),
            Ok(response_with_headers(429, [], r#"{"error":"RATELIMIT"}"#)),
        ]);
        let draft = service
            .prepare(&post_intent(), &credential, now())
            .expect("draft prepares");
        let ingress = ingress_for(&draft, &credential);
        let mut checkpoint =
            RedditPublishCheckpoint::new(&draft, &ingress).expect("checkpoint binds exact draft");
        assert_eq!(
            service.execute(&draft, &ingress, &credential, &mut checkpoint, now()),
            Err(RedditEffectError::RateLimitWithoutReset)
        );
    }

    #[test]
    fn credential_rotation_and_missing_approval_fail_closed() {
        let (mut service, credential) = prepare_service([Ok(empty_listing())]);
        let draft = service
            .prepare(&post_intent(), &credential, now())
            .expect("draft prepares");
        let ingress = ingress_for(&draft, &credential);
        let mut checkpoint =
            RedditPublishCheckpoint::new(&draft, &ingress).expect("checkpoint binds exact draft");
        let rotated = fixture_credential(2, all_scopes());
        assert_eq!(
            service.execute(&draft, &ingress, &rotated, &mut checkpoint, now()),
            Err(RedditEffectError::CredentialGenerationDrift)
        );

        let read_scopes = BTreeSet::from([RedditScope::Identity, RedditScope::Read]);
        let (mut service, _) = prepare_service([Ok(empty_listing())]);
        let read_credential = fixture_credential(1, read_scopes.clone());
        let draft = service
            .prepare(&post_intent(), &read_credential, now())
            .expect("read-only credential can prepare");
        let ingress = ingress_for(&draft, &read_credential);
        let mut checkpoint =
            RedditPublishCheckpoint::new(&draft, &ingress).expect("checkpoint binds exact draft");
        assert_eq!(
            service.execute(&draft, &ingress, &read_credential, &mut checkpoint, now(),),
            Err(RedditEffectError::AuthorizationRequired(
                AuthorizationReason::MissingApproval
            ))
        );
    }

    #[test]
    fn moderation_drift_and_real_gate_are_honest() {
        let (mut service, credential) = prepare_service([
            Ok(empty_listing()),
            Ok(submit_receipt()),
            Ok(info_readback("hello", true)),
        ]);
        let draft = service
            .prepare(&post_intent(), &credential, now())
            .expect("draft prepares");
        let ingress = ingress_for(&draft, &credential);
        let mut checkpoint =
            RedditPublishCheckpoint::new(&draft, &ingress).expect("checkpoint binds exact draft");
        assert_eq!(
            service.execute(&draft, &ingress, &credential, &mut checkpoint, now()),
            Err(RedditEffectError::ModerationDrift)
        );
        assert_eq!(
            RedditRealEffectGate::from_environment_values(None, None, None, None),
            Err(RedditEffectError::BlockedEnvironment(
                "HARTEVO_REDDIT_REAL_EFFECT must be 1"
            ))
        );
        assert_eq!(
            RedditRealEffectGate::from_environment_values(
                Some("1"),
                Some("ref"),
                None,
                Some("approval")
            ),
            Err(RedditEffectError::BlockedEnvironment(
                "approved Reddit access token is missing"
            ))
        );
    }
}
