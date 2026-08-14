//! Mission-log projection for a browser form draft.
//!
//! A result is a typed, redacted proposal.  It is not an approval, a lease,
//! or an input operation.  The provider re-reads the exact frame identity
//! before appending the proposal to its serializable Mission-visible log;
//! Accept/Reject remains the responsibility of a separate consumer boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::workspace::{digest, digest_json, is_bounded_identifier, is_sha256};
use crate::{
    BrowserControlState, BrowserError, BrowserFormActionKind, BrowserFormDraft,
    BrowserFormFieldObservation, BrowserFormFrameSnapshot, BrowserFormScope,
    BrowserFormSecretClass, BrowserProfile, BrowserProfileStatus, BrowserWorkspace,
};

const FORM_RESULT_SCHEMA_VERSION: u32 = 1;
const MAX_RESULT_FIELDS: usize = 512;
const MAX_RESULT_ID_BYTES: usize = 512;

/// Raw, read-only frame evidence supplied by a native or fake host.
///
/// The raw identifiers never appear in a result or its Mission log.  They
/// are reduced to digests after being checked against the draft's exact
/// session/frame/loader, navigation, document, DOM, URL, and origin fence.
#[derive(Clone, Eq, PartialEq)]
pub struct BrowserFormResultFrameEvidence {
    pub session_id: String,
    pub frame_id: String,
    pub loader_id: String,
    pub control_generation: u64,
    pub navigation_revision: u64,
    pub document_generation: u64,
    pub dom_revision: u64,
    pub url: String,
    pub origin: String,
    pub observed_at: DateTime<Utc>,
}

impl BrowserFormResultFrameEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: impl Into<String>,
        frame_id: impl Into<String>,
        loader_id: impl Into<String>,
        control_generation: u64,
        navigation_revision: u64,
        document_generation: u64,
        dom_revision: u64,
        url: impl Into<String>,
        origin: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let evidence = Self {
            session_id: session_id.into(),
            frame_id: frame_id.into(),
            loader_id: loader_id.into(),
            control_generation,
            navigation_revision,
            document_generation,
            dom_revision,
            url: url.into(),
            origin: origin.into(),
            observed_at,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    fn validate(&self) -> Result<(), BrowserError> {
        if !bounded_result_id(&self.session_id)
            || !bounded_result_id(&self.frame_id)
            || !bounded_result_id(&self.loader_id)
            || self.control_generation == 0
            || self.navigation_revision == 0
            || self.document_generation == 0
            || self.dom_revision == 0
            || !is_safe_result_url(&self.url)
            || canonical_result_origin(&self.url).as_deref() != Some(self.origin.as_str())
        {
            return Err(BrowserError::InvalidFormResult);
        }
        Ok(())
    }

    fn validate_against(
        &self,
        scope: &BrowserFormScope,
        draft: &BrowserFormDraft,
    ) -> Result<(), BrowserError> {
        self.validate()?;
        draft.validate()?;
        if self.observed_at < draft.created_at
            || digest(self.session_id.as_bytes()) != draft.frame.session_id_digest
            || digest(self.frame_id.as_bytes()) != draft.frame.frame_id_digest
            || digest(self.loader_id.as_bytes()) != draft.frame.loader_id_digest
            || self.control_generation != draft.frame.control_generation
            || self.navigation_revision != draft.frame.navigation_revision
            || self.document_generation != draft.frame.document_generation
            || self.dom_revision != draft.frame.dom_revision
            || digest(self.url.as_bytes()) != draft.frame.url_digest
            || digest(self.origin.as_bytes()) != draft.frame.origin_digest
            || draft.scope != *scope
        {
            return Err(BrowserError::FormResultSnapshotStale);
        }
        Ok(())
    }

    fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(&(
            "browser-form-result-frame/v1",
            digest(self.session_id.as_bytes()),
            digest(self.frame_id.as_bytes()),
            digest(self.loader_id.as_bytes()),
            self.control_generation,
            self.navigation_revision,
            self.document_generation,
            self.dom_revision,
            digest(self.url.as_bytes()),
            digest(self.origin.as_bytes()),
            self.observed_at,
        ))
    }
}

impl fmt::Debug for BrowserFormResultFrameEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserFormResultFrameEvidence")
            .field("session_id_digest", &digest(self.session_id.as_bytes()))
            .field("frame_id_digest", &digest(self.frame_id.as_bytes()))
            .field("loader_id_digest", &digest(self.loader_id.as_bytes()))
            .field("control_generation", &self.control_generation)
            .field("navigation_revision", &self.navigation_revision)
            .field("document_generation", &self.document_generation)
            .field("dom_revision", &self.dom_revision)
            .field("url_digest", &digest(self.url.as_bytes()))
            .field("origin_digest", &digest(self.origin.as_bytes()))
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

/// Redacted frame identity rendered into the Mission-visible result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormResultFrame {
    pub schema_version: u32,
    pub snapshot: BrowserFormFrameSnapshot,
    pub page_url_digest: String,
    pub origin: String,
    pub frame_evidence_digest: String,
}

impl BrowserFormResultFrame {
    fn from_evidence(
        scope: &BrowserFormScope,
        draft: &BrowserFormDraft,
        evidence: &BrowserFormResultFrameEvidence,
    ) -> Result<Self, BrowserError> {
        evidence.validate_against(scope, draft)?;
        let frame = Self {
            schema_version: FORM_RESULT_SCHEMA_VERSION,
            snapshot: draft.frame.clone(),
            page_url_digest: digest(evidence.url.as_bytes()),
            origin: evidence.origin.clone(),
            frame_evidence_digest: evidence.evidence_digest()?,
        };
        frame.validate(scope)?;
        Ok(frame)
    }

    pub fn validate(&self, scope: &BrowserFormScope) -> Result<(), BrowserError> {
        if self.schema_version != FORM_RESULT_SCHEMA_VERSION
            || !is_sha256(&self.page_url_digest)
            || !is_safe_result_origin(&self.origin)
            || !is_sha256(&self.frame_evidence_digest)
            || self.page_url_digest != self.snapshot.url_digest
            || digest(self.origin.as_bytes()) != self.snapshot.origin_digest
        {
            return Err(BrowserError::InvalidFormResult);
        }
        self.snapshot.validate_for_scope(scope)?;
        let expected_evidence_digest = digest_json(&(
            "browser-form-result-frame/v1",
            &self.snapshot.session_id_digest,
            &self.snapshot.frame_id_digest,
            &self.snapshot.loader_id_digest,
            self.snapshot.control_generation,
            self.snapshot.navigation_revision,
            self.snapshot.document_generation,
            self.snapshot.dom_revision,
            &self.page_url_digest,
            digest(self.origin.as_bytes()),
            self.snapshot.observed_at,
        ))?;
        if expected_evidence_digest != self.frame_evidence_digest {
            return Err(BrowserError::InvalidFormResult);
        }
        Ok(())
    }
}

/// Exact Project/Mission/plugin/invocation/session/draft identity for one
/// result projection.  Plugin and invocation identifiers are opaque bounded
/// references; the browser session is always redacted to a digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormResultIdentity {
    pub schema_version: u32,
    pub scope: BrowserFormScope,
    pub plugin_id: String,
    pub invocation_id: String,
    pub browser_session_id_digest: String,
    pub form_identity_digest: String,
    pub draft_provider_generation: u64,
    pub draft_id: String,
    pub draft_digest: String,
}

impl BrowserFormResultIdentity {
    fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != FORM_RESULT_SCHEMA_VERSION
            || !bounded_result_id(&self.plugin_id)
            || !bounded_result_id(&self.invocation_id)
            || !is_sha256(&self.browser_session_id_digest)
            || !is_sha256(&self.form_identity_digest)
            || self.draft_provider_generation == 0
            || !is_sha256(&self.draft_id)
            || !is_sha256(&self.draft_digest)
        {
            return Err(BrowserError::InvalidFormResult);
        }
        self.scope.validate()
    }
}

/// One proposed field mutation.  Both current and proposed values are
/// digests; this type carries no cleartext and no native locator authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormFieldMutation {
    pub schema_version: u32,
    pub action_id: String,
    pub field_id: String,
    pub kind: BrowserFormActionKind,
    pub locator_digest: String,
    pub secret_class: BrowserFormSecretClass,
    pub field_revision: u64,
    pub before_value_digest: Option<String>,
    pub proposed_value_digest: Option<String>,
    pub human_approval_required: bool,
}

impl BrowserFormFieldMutation {
    fn from_parts(
        field: &BrowserFormFieldObservation,
        action_id: String,
        kind: BrowserFormActionKind,
        proposed_value_digest: Option<String>,
    ) -> Result<Self, BrowserError> {
        let mutation = Self {
            schema_version: FORM_RESULT_SCHEMA_VERSION,
            action_id,
            field_id: field.field_id.clone(),
            kind,
            locator_digest: field.locator_digest.clone(),
            secret_class: field.secret_class,
            field_revision: field.field_revision,
            before_value_digest: field.value_digest.clone(),
            proposed_value_digest,
            human_approval_required: true,
        };
        mutation.validate()?;
        Ok(mutation)
    }

    fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != FORM_RESULT_SCHEMA_VERSION
            || !is_sha256(&self.action_id)
            || !bounded_result_id(&self.field_id)
            || !is_sha256(&self.locator_digest)
            || self.field_revision == 0
            || self
                .before_value_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || self
                .proposed_value_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || matches!(
                self.kind,
                BrowserFormActionKind::Fill | BrowserFormActionKind::Select
            ) && self.proposed_value_digest.is_none()
            || matches!(
                self.kind,
                BrowserFormActionKind::Toggle | BrowserFormActionKind::Submit
            ) && self.proposed_value_digest.is_some()
            || !self.human_approval_required
        {
            return Err(BrowserError::InvalidFormResult);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFormResultPolicyRequirement {
    HumanApproval,
    HumanTakeover,
    CurrentFrameRevalidation,
    SensitiveFieldReview,
    EffectBrokerBoundary,
    NoDirectClickOrSubmit,
}

/// Mandatory policy requirements rendered alongside every proposed result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormResultPolicy {
    pub schema_version: u32,
    pub requirements: Vec<BrowserFormResultPolicyRequirement>,
    pub policy_digest: String,
}

impl BrowserFormResultPolicy {
    fn from_draft(draft: &BrowserFormDraft) -> Result<Self, BrowserError> {
        draft.validate()?;
        let sensitive = draft
            .actions
            .iter()
            .any(|action| action.secret_class.is_sensitive());
        let mut requirements = vec![
            BrowserFormResultPolicyRequirement::HumanApproval,
            BrowserFormResultPolicyRequirement::HumanTakeover,
            BrowserFormResultPolicyRequirement::CurrentFrameRevalidation,
            BrowserFormResultPolicyRequirement::EffectBrokerBoundary,
            BrowserFormResultPolicyRequirement::NoDirectClickOrSubmit,
        ];
        if sensitive {
            requirements.push(BrowserFormResultPolicyRequirement::SensitiveFieldReview);
        }
        requirements.sort_unstable();
        requirements.dedup();
        let policy_digest = digest_json(&("browser-form-result-policy/v1", &requirements))?;
        let policy = Self {
            schema_version: FORM_RESULT_SCHEMA_VERSION,
            requirements,
            policy_digest,
        };
        policy.validate(sensitive)?;
        Ok(policy)
    }

    pub fn validate(&self, sensitive_fields_present: bool) -> Result<(), BrowserError> {
        if self.schema_version != FORM_RESULT_SCHEMA_VERSION
            || !is_sha256(&self.policy_digest)
            || self.requirements.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(BrowserError::InvalidFormResult);
        }
        let required = [
            BrowserFormResultPolicyRequirement::HumanApproval,
            BrowserFormResultPolicyRequirement::HumanTakeover,
            BrowserFormResultPolicyRequirement::CurrentFrameRevalidation,
            BrowserFormResultPolicyRequirement::EffectBrokerBoundary,
            BrowserFormResultPolicyRequirement::NoDirectClickOrSubmit,
        ];
        if required
            .iter()
            .any(|requirement| !self.requirements.contains(requirement))
            || sensitive_fields_present
                != self
                    .requirements
                    .contains(&BrowserFormResultPolicyRequirement::SensitiveFieldReview)
            || digest_json(&("browser-form-result-policy/v1", &self.requirements))?
                != self.policy_digest
        {
            return Err(BrowserError::InvalidFormResult);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFormResultStatus {
    Proposed,
}

/// Typed, model-visible form result.  It contains proposals and evidence
/// only; `dispatch_performed` and `execution_permitted` are permanently false.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormResult {
    pub schema_version: u32,
    pub provider_generation: u64,
    pub sequence: u64,
    pub result_id: String,
    pub identity: BrowserFormResultIdentity,
    pub frame: BrowserFormResultFrame,
    pub mutations: Vec<BrowserFormFieldMutation>,
    pub policy: BrowserFormResultPolicy,
    pub snapshot_digest: String,
    pub secret_classification_digest: String,
    pub created_at: DateTime<Utc>,
    pub status: BrowserFormResultStatus,
    pub dispatch_performed: bool,
    pub execution_permitted: bool,
}

impl BrowserFormResult {
    fn from_draft(
        provider_generation: u64,
        sequence: u64,
        identity: BrowserFormResultIdentity,
        frame: BrowserFormResultFrame,
        draft: &BrowserFormDraft,
        policy: BrowserFormResultPolicy,
        created_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let fields_by_id: BTreeMap<&str, &BrowserFormFieldObservation> = draft
            .fields
            .iter()
            .map(|field| (field.field_id.as_str(), field))
            .collect();
        let mut mutations = Vec::with_capacity(draft.actions.len());
        for action in &draft.actions {
            let field = fields_by_id
                .get(action.field_id.as_str())
                .ok_or(BrowserError::FormResultScopeMismatch)?;
            mutations.push(BrowserFormFieldMutation::from_parts(
                field,
                action.action_id.clone(),
                action.kind,
                action.value_digest.clone(),
            )?);
        }
        if mutations.is_empty() || mutations.len() > MAX_RESULT_FIELDS {
            return Err(BrowserError::InvalidFormResult);
        }
        let result_id = digest_json(&(
            "browser-form-result/v1",
            provider_generation,
            sequence,
            &identity,
            &frame,
            &mutations,
            &policy,
            &draft.snapshot_digest,
            &draft.secret_classification_digest,
            created_at,
        ))?;
        let result = Self {
            schema_version: FORM_RESULT_SCHEMA_VERSION,
            provider_generation,
            sequence,
            result_id,
            identity,
            frame,
            mutations,
            policy,
            snapshot_digest: draft.snapshot_digest.clone(),
            secret_classification_digest: draft.secret_classification_digest.clone(),
            created_at,
            status: BrowserFormResultStatus::Proposed,
            dispatch_performed: false,
            execution_permitted: false,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != FORM_RESULT_SCHEMA_VERSION
            || self.provider_generation == 0
            || self.sequence == 0
            || !is_sha256(&self.result_id)
            || self.mutations.is_empty()
            || self.mutations.len() > MAX_RESULT_FIELDS
            || !is_sha256(&self.snapshot_digest)
            || !is_sha256(&self.secret_classification_digest)
            || self.status != BrowserFormResultStatus::Proposed
            || self.dispatch_performed
            || self.execution_permitted
        {
            return Err(BrowserError::InvalidFormResult);
        }
        self.identity.validate()?;
        self.frame.validate(&self.identity.scope)?;
        let sensitive = self
            .mutations
            .iter()
            .any(|mutation| mutation.secret_class.is_sensitive());
        self.policy.validate(sensitive)?;
        let expected_form_identity_digest = digest_json(&(
            "browser-form-identity/v1",
            &self.identity.scope,
            &self.frame.snapshot.frame_id_digest,
            &self.frame.snapshot.loader_id_digest,
            &self.snapshot_digest,
            &self.secret_classification_digest,
        ))?;
        if expected_form_identity_digest != self.identity.form_identity_digest {
            return Err(BrowserError::InvalidFormResult);
        }
        let mut action_ids = BTreeSet::new();
        for mutation in &self.mutations {
            mutation.validate()?;
            if !action_ids.insert(mutation.action_id.clone()) {
                return Err(BrowserError::InvalidFormResult);
            }
        }
        let expected_id = digest_json(&(
            "browser-form-result/v1",
            self.provider_generation,
            self.sequence,
            &self.identity,
            &self.frame,
            &self.mutations,
            &self.policy,
            &self.snapshot_digest,
            &self.secret_classification_digest,
            self.created_at,
        ))?;
        if expected_id != self.result_id {
            return Err(BrowserError::InvalidFormResult);
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }
}

/// Append-only, serializable Mission-visible result projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormResultLog {
    pub schema_version: u32,
    pub scope: BrowserFormScope,
    pub plugin_id: String,
    pub provider_generation: u64,
    pub entries: Vec<BrowserFormResult>,
}

impl BrowserFormResultLog {
    fn empty(
        scope: BrowserFormScope,
        plugin_id: String,
        provider_generation: u64,
    ) -> Result<Self, BrowserError> {
        let log = Self {
            schema_version: FORM_RESULT_SCHEMA_VERSION,
            scope,
            plugin_id,
            provider_generation,
            entries: Vec::new(),
        };
        log.validate()?;
        Ok(log)
    }

    pub fn restore(
        scope: BrowserFormScope,
        plugin_id: String,
        provider_generation: u64,
        entries: Vec<BrowserFormResult>,
    ) -> Result<Self, BrowserError> {
        let log = Self {
            schema_version: FORM_RESULT_SCHEMA_VERSION,
            scope,
            plugin_id,
            provider_generation,
            entries,
        };
        log.validate()?;
        Ok(log)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != FORM_RESULT_SCHEMA_VERSION
            || !bounded_result_id(&self.plugin_id)
            || self.provider_generation == 0
        {
            return Err(BrowserError::InvalidFormResult);
        }
        self.scope.validate()?;
        let mut result_ids = BTreeSet::new();
        for (index, entry) in self.entries.iter().enumerate() {
            entry.validate()?;
            let expected_sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(BrowserError::CounterOverflow)?;
            if entry.sequence != expected_sequence
                || entry.identity.scope != self.scope
                || entry.identity.plugin_id != self.plugin_id
                || !result_ids.insert(entry.result_id.clone())
            {
                return Err(BrowserError::InvalidFormResult);
            }
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }
}

/// Read-only native/fake host boundary.  No click, submit, or input method
/// exists here; the sole operation re-reads the frame needed for projection.
pub trait BrowserFormResultHost {
    fn observe_result_frame(
        &mut self,
        scope: &BrowserFormScope,
        expected_frame: &BrowserFormFrameSnapshot,
        now: DateTime<Utc>,
    ) -> Result<BrowserFormResultFrameEvidence, BrowserError>;
}

#[derive(Debug, Default)]
pub struct UnavailableBrowserFormResultHost;

impl BrowserFormResultHost for UnavailableBrowserFormResultHost {
    fn observe_result_frame(
        &mut self,
        _scope: &BrowserFormScope,
        _expected_frame: &BrowserFormFrameSnapshot,
        _now: DateTime<Utc>,
    ) -> Result<BrowserFormResultFrameEvidence, BrowserError> {
        Err(BrowserError::ProtocolUnavailable)
    }
}

/// Consumer boundary for a typed proposal.  Implementations own Accept/Reject
/// and any later approval/effect workflow; this trait cannot dispatch input.
pub trait BrowserFormResultConsumer {
    fn receive_form_result(&mut self, result: &BrowserFormResult) -> Result<(), BrowserError>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFormResultProviderState {
    Mounted,
    Invalidated,
    Revoked,
    Restarted,
}

/// Mission-scoped result provider.  It owns only projection, logging, and
/// delivery of a non-authoritative proposal to a separate consumer.
#[derive(Clone, Debug)]
pub struct BrowserFormResultProvider {
    scope: BrowserFormScope,
    plugin_id: String,
    state: BrowserFormResultProviderState,
    provider_generation: u64,
    result_log: BrowserFormResultLog,
    projected: BTreeMap<String, BrowserFormResult>,
    delivered: BTreeSet<String>,
    closed_results: BTreeSet<String>,
    closed_drafts: BTreeSet<String>,
    closed_invocations: BTreeSet<String>,
    next_sequence: u64,
}

impl BrowserFormResultProvider {
    pub fn mount(
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        scope: BrowserFormScope,
        plugin_id: impl Into<String>,
    ) -> Result<Self, BrowserError> {
        validate_provider_scope(profile, workspace, &scope)?;
        let plugin_id = plugin_id.into();
        if !bounded_result_id(&plugin_id) {
            return Err(BrowserError::FormResultScopeMismatch);
        }
        let provider_generation = 1;
        let result_log =
            BrowserFormResultLog::empty(scope.clone(), plugin_id.clone(), provider_generation)?;
        Ok(Self {
            scope,
            plugin_id,
            state: BrowserFormResultProviderState::Mounted,
            provider_generation,
            result_log,
            projected: BTreeMap::new(),
            delivered: BTreeSet::new(),
            closed_results: BTreeSet::new(),
            closed_drafts: BTreeSet::new(),
            closed_invocations: BTreeSet::new(),
            next_sequence: 1,
        })
    }

    /// Restores only the durable Mission log with a new provider generation.
    /// Old result cursors remain evidence and cannot be projected or delivered.
    pub fn remount(
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        scope: BrowserFormScope,
        plugin_id: impl Into<String>,
        log: BrowserFormResultLog,
    ) -> Result<Self, BrowserError> {
        validate_provider_scope(profile, workspace, &scope)?;
        let plugin_id = plugin_id.into();
        log.validate()?;
        if log.scope != scope || log.plugin_id != plugin_id {
            return Err(BrowserError::FormResultScopeMismatch);
        }
        let provider_generation = log
            .provider_generation
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        let closed_results = log
            .entries
            .iter()
            .map(|entry| entry.result_id.clone())
            .collect();
        let closed_drafts = log
            .entries
            .iter()
            .map(|entry| entry.identity.draft_id.clone())
            .collect();
        let closed_invocations = log
            .entries
            .iter()
            .map(|entry| entry.identity.invocation_id.clone())
            .collect();
        let result_log = BrowserFormResultLog {
            schema_version: FORM_RESULT_SCHEMA_VERSION,
            scope: scope.clone(),
            plugin_id: plugin_id.clone(),
            provider_generation,
            entries: log.entries,
        };
        result_log.validate()?;
        let next_sequence = u64::try_from(result_log.entries.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(BrowserError::CounterOverflow)?;
        Ok(Self {
            scope,
            plugin_id,
            state: BrowserFormResultProviderState::Mounted,
            provider_generation,
            result_log,
            projected: BTreeMap::new(),
            delivered: BTreeSet::new(),
            closed_results,
            closed_drafts,
            closed_invocations,
            next_sequence,
        })
    }

    pub fn scope(&self) -> &BrowserFormScope {
        &self.scope
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub fn state(&self) -> BrowserFormResultProviderState {
        self.state
    }

    pub fn result_log(&self) -> &BrowserFormResultLog {
        &self.result_log
    }

    pub fn project_result<H: BrowserFormResultHost>(
        &mut self,
        host: &mut H,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        draft: &BrowserFormDraft,
        invocation_id: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<BrowserFormResult, BrowserError> {
        self.ensure_mounted()?;
        draft.validate()?;
        if let Err(error) = validate_provider_scope(profile, workspace, &self.scope) {
            return Err(self.invalidate(error));
        }
        if draft.scope != self.scope
            || draft.provider_generation == 0
            || workspace.control_state != BrowserControlState::AgentControlled
            || workspace.revision != self.scope.workspace_revision
        {
            return Err(self.invalidate(BrowserError::FormResultScopeMismatch));
        }
        if let Err(error) = workspace.agent_lease_proof(now) {
            return Err(self.invalidate(error));
        }
        let invocation_id = invocation_id.into();
        if !bounded_result_id(&invocation_id)
            || self.closed_drafts.contains(&draft.draft_id)
            || self
                .result_log
                .entries
                .iter()
                .any(|entry| entry.identity.draft_id == draft.draft_id)
            || self.closed_invocations.contains(&invocation_id)
            || self
                .result_log
                .entries
                .iter()
                .any(|entry| entry.identity.invocation_id == invocation_id)
        {
            return Err(BrowserError::FormResultDuplicate);
        }
        let evidence = match host.observe_result_frame(&self.scope, &draft.frame, now) {
            Ok(evidence) => evidence,
            Err(error) => return Err(self.host_failure(error)),
        };
        if evidence.observed_at < now {
            return Err(self.invalidate(BrowserError::FormResultSnapshotStale));
        }
        if let Err(error) = evidence.validate_against(&self.scope, draft) {
            return Err(self.invalidate(error));
        }
        if let Err(error) = workspace.validate() {
            return Err(self.invalidate(error));
        }
        let frame = match BrowserFormResultFrame::from_evidence(&self.scope, draft, &evidence) {
            Ok(frame) => frame,
            Err(error) => return Err(self.invalidate(error)),
        };
        let policy = match BrowserFormResultPolicy::from_draft(draft) {
            Ok(policy) => policy,
            Err(error) => return Err(self.invalidate(error)),
        };
        let form_identity_digest = digest_json(&(
            "browser-form-identity/v1",
            &draft.scope,
            &draft.frame.frame_id_digest,
            &draft.frame.loader_id_digest,
            &draft.snapshot_digest,
            &draft.secret_classification_digest,
        ))?;
        let identity = BrowserFormResultIdentity {
            schema_version: FORM_RESULT_SCHEMA_VERSION,
            scope: self.scope.clone(),
            plugin_id: self.plugin_id.clone(),
            invocation_id,
            browser_session_id_digest: digest(evidence.session_id.as_bytes()),
            form_identity_digest,
            draft_provider_generation: draft.provider_generation,
            draft_id: draft.draft_id.clone(),
            draft_digest: draft.evidence_digest()?,
        };
        identity.validate()?;
        let sequence = self.next_sequence;
        let result = BrowserFormResult::from_draft(
            self.provider_generation,
            sequence,
            identity,
            frame,
            draft,
            policy,
            evidence.observed_at,
        )?;
        if self.closed_results.contains(&result.result_id)
            || self.projected.contains_key(&result.result_id)
        {
            return Err(BrowserError::FormResultDuplicate);
        }
        let mut candidate_log = self.result_log.clone();
        candidate_log.entries.push(result.clone());
        candidate_log.validate()?;
        self.result_log = candidate_log;
        self.projected
            .insert(result.result_id.clone(), result.clone());
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        Ok(result)
    }

    pub fn deliver_result<C: BrowserFormResultConsumer>(
        &mut self,
        result_id: &str,
        consumer: &mut C,
    ) -> Result<(), BrowserError> {
        self.ensure_mounted()?;
        if !is_sha256(result_id) {
            return Err(BrowserError::FormResultScopeMismatch);
        }
        let result = self
            .projected
            .get(result_id)
            .ok_or_else(|| {
                if self.closed_results.contains(result_id) {
                    BrowserError::FormResultReopened
                } else {
                    BrowserError::FormResultScopeMismatch
                }
            })?
            .clone();
        if result.provider_generation != self.provider_generation
            || result.identity.scope != self.scope
            || result.identity.plugin_id != self.plugin_id
        {
            return Err(BrowserError::FormResultProviderRestarted);
        }
        if !self.delivered.insert(result_id.to_owned()) {
            return Err(BrowserError::FormResultDuplicate);
        }
        if let Err(error) = consumer.receive_form_result(&result) {
            self.delivered.remove(result_id);
            return Err(error);
        }
        Ok(())
    }

    pub fn restart(&mut self) -> Result<(), BrowserError> {
        match self.state {
            BrowserFormResultProviderState::Mounted
            | BrowserFormResultProviderState::Invalidated => {
                self.state = BrowserFormResultProviderState::Restarted;
                self.close_pending();
                Ok(())
            }
            BrowserFormResultProviderState::Revoked => Err(BrowserError::FormResultProviderRevoked),
            BrowserFormResultProviderState::Restarted => {
                Err(BrowserError::FormResultProviderRestarted)
            }
        }
    }

    pub fn unmount(&mut self) -> Result<(), BrowserError> {
        self.ensure_mounted()?;
        self.state = BrowserFormResultProviderState::Invalidated;
        self.close_pending();
        Ok(())
    }

    pub fn revoke(
        &mut self,
        profile: &mut BrowserProfile,
        expected_revision: u64,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.ensure_mounted()?;
        if profile.id != self.scope.profile_id || profile.revision != self.scope.profile_revision {
            return Err(BrowserError::FormResultScopeMismatch);
        }
        profile.revoke(expected_revision, evidence_digest, now)?;
        self.state = BrowserFormResultProviderState::Revoked;
        self.close_pending();
        Ok(())
    }

    fn ensure_mounted(&self) -> Result<(), BrowserError> {
        match self.state {
            BrowserFormResultProviderState::Mounted => Ok(()),
            BrowserFormResultProviderState::Invalidated => {
                Err(BrowserError::FormResultProviderInvalidated)
            }
            BrowserFormResultProviderState::Revoked => Err(BrowserError::FormResultProviderRevoked),
            BrowserFormResultProviderState::Restarted => {
                Err(BrowserError::FormResultProviderRestarted)
            }
        }
    }

    fn close_pending(&mut self) {
        self.closed_results.extend(self.projected.keys().cloned());
        self.closed_drafts.extend(
            self.projected
                .values()
                .map(|result| result.identity.draft_id.clone()),
        );
        self.closed_invocations.extend(
            self.projected
                .values()
                .map(|result| result.identity.invocation_id.clone()),
        );
        self.projected.clear();
        self.delivered.clear();
    }

    fn invalidate(&mut self, error: BrowserError) -> BrowserError {
        self.state = BrowserFormResultProviderState::Invalidated;
        self.close_pending();
        error
    }

    fn host_failure(&mut self, error: BrowserError) -> BrowserError {
        if matches!(
            error,
            BrowserError::HostExited | BrowserError::HostRestarted
        ) {
            self.state = BrowserFormResultProviderState::Restarted;
            self.close_pending();
        }
        error
    }
}

fn validate_provider_scope(
    profile: &BrowserProfile,
    workspace: &BrowserWorkspace,
    scope: &BrowserFormScope,
) -> Result<(), BrowserError> {
    profile.validate()?;
    workspace.validate()?;
    scope.validate()?;
    if profile.status != BrowserProfileStatus::Active
        || scope.profile_id != profile.id
        || scope.profile_revision != profile.revision
        || scope.identity_digest != profile.identity.identity_digest
        || scope.tenant_id != workspace.tenant_id
        || scope.project_id != workspace.project_id
        || scope.mission_id != workspace.mission_id
        || scope.workspace_id != workspace.id
        || scope.workspace_revision != workspace.revision
        || scope.tab_id != workspace.active_tab_id
        || workspace.profile_id != profile.id
        || workspace.expected_identity_digest != profile.identity.identity_digest
        || !workspace.tabs.contains(&scope.tab_id)
    {
        return Err(BrowserError::FormResultScopeMismatch);
    }
    Ok(())
}

fn bounded_result_id(value: &str) -> bool {
    is_bounded_identifier(value) && value.len() <= MAX_RESULT_ID_BYTES
}

fn is_safe_result_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.host_str().is_some()
    })
}

fn canonical_result_origin(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    Some(url.origin().ascii_serialization())
}

fn is_safe_result_origin(value: &str) -> bool {
    canonical_result_origin(value).is_some_and(|origin| origin == value)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, BrowserControlLeaseId, BrowserProfileId, BrowserTabId, BrowserWorkspaceId,
        MissionContract, MissionId, ProjectId, StorageMode,
    };

    use super::*;
    use crate::{
        BrowserFormActionIntent, BrowserFormFieldKind, BrowserFormFieldPolicy,
        BrowserFormFrameObservation, BrowserFormHost, BrowserFormObservation, BrowserIdentity,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 9, 0, 0)
            .single()
            .expect("fixed time")
    }

    fn sha(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    struct DraftHost {
        observation: BrowserFormObservation,
    }

    impl BrowserFormHost for DraftHost {
        fn observe_form(
            &mut self,
            _scope: &BrowserFormScope,
            _now: DateTime<Utc>,
        ) -> Result<BrowserFormObservation, BrowserError> {
            Ok(self.observation.clone())
        }

        fn revalidate_form(
            &mut self,
            _scope: &BrowserFormScope,
            _expected_frame: &BrowserFormFrameSnapshot,
            _expected_snapshot_digest: &str,
            _now: DateTime<Utc>,
        ) -> Result<BrowserFormObservation, BrowserError> {
            Ok(self.observation.clone())
        }
    }

    struct FormFixture {
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        draft: BrowserFormDraft,
    }

    fn draft_intents() -> Vec<BrowserFormActionIntent> {
        vec![
            BrowserFormActionIntent::new(
                "field-public",
                BrowserFormActionKind::Fill,
                Some(sha('d')),
            )
            .expect("public intent"),
            BrowserFormActionIntent::new(
                "field-email",
                BrowserFormActionKind::Fill,
                Some(sha('e')),
            )
            .expect("email intent"),
            BrowserFormActionIntent::new(
                "field-password",
                BrowserFormActionKind::Fill,
                Some(sha('f')),
            )
            .expect("password intent"),
        ]
    }

    fn form_fixture() -> FormFixture {
        let timestamp = now();
        let project = hartevo_domain_kernel::Project::create_local(
            "tenant-result".into(),
            ProjectId::from("project-result"),
            "Result project",
            "Result fixture",
            "/tmp/result-project",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = hartevo_domain_kernel::Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-result"),
            project.id.clone(),
            "Result mission",
            MissionContract::bootstrap(
                "project a form result",
                ["browser.read".to_owned()],
                timestamp,
            ),
            timestamp,
        )
        .expect("mission");
        let identity = BrowserIdentity::new(
            "chromium",
            AccountId::from("account-result"),
            sha('a'),
            sha('b'),
            timestamp,
        )
        .expect("identity");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-result"),
            &project,
            "keyring://result",
            identity,
            timestamp,
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-result"),
            &project,
            &mission,
            &profile,
            BrowserTabId::from("tab-result"),
            BrowserControlLeaseId::from("lease-agent-result"),
            timestamp + Duration::hours(1),
            sha('c'),
            timestamp,
        )
        .expect("workspace");
        let scope = BrowserFormScope::from_workspace(
            &profile,
            &workspace,
            BrowserTabId::from("tab-result"),
        )
        .expect("scope");
        let raw_frame = BrowserFormFrameObservation::new(
            "session-result",
            "frame-result",
            "loader-result",
            workspace.lease_generation,
            1,
            1,
            1,
            "https://example.de/account?form=1",
            "https://example.de",
        )
        .expect("frame");
        let frame =
            BrowserFormFrameSnapshot::observed(&scope, &raw_frame, timestamp).expect("snapshot");
        let fields = result_fields();
        let observation = BrowserFormObservation::new(frame, fields).expect("observation");
        let mut draft_service = crate::BrowserFormDraftService::mount(
            &profile,
            &workspace,
            BrowserTabId::from("tab-result"),
        )
        .expect("draft service");
        let mut draft_host = DraftHost { observation };
        let draft = draft_service
            .draft_form(
                &mut draft_host,
                &profile,
                &workspace,
                &draft_intents(),
                timestamp,
            )
            .expect("draft");
        FormFixture {
            profile,
            workspace,
            draft,
        }
    }

    fn result_fields() -> Vec<BrowserFormFieldObservation> {
        vec![
            BrowserFormFieldObservation::new(
                "field-public",
                sha('1'),
                BrowserFormFieldKind::Text,
                BrowserFormSecretClass::Public,
                BrowserFormFieldPolicy {
                    required: false,
                    editable: true,
                },
                1,
                None,
            )
            .expect("public field"),
            BrowserFormFieldObservation::new(
                "field-email",
                sha('2'),
                BrowserFormFieldKind::Email,
                BrowserFormSecretClass::Personal,
                BrowserFormFieldPolicy {
                    required: true,
                    editable: true,
                },
                1,
                None,
            )
            .expect("email field"),
            BrowserFormFieldObservation::new(
                "field-password",
                sha('3'),
                BrowserFormFieldKind::Password,
                BrowserFormSecretClass::Credential,
                BrowserFormFieldPolicy {
                    required: true,
                    editable: true,
                },
                1,
                Some(sha('5')),
            )
            .expect("password field"),
        ]
    }

    struct FakeResultHost {
        evidence: BrowserFormResultFrameEvidence,
        failure: Option<BrowserError>,
    }

    impl BrowserFormResultHost for FakeResultHost {
        fn observe_result_frame(
            &mut self,
            _scope: &BrowserFormScope,
            _expected_frame: &BrowserFormFrameSnapshot,
            _now: DateTime<Utc>,
        ) -> Result<BrowserFormResultFrameEvidence, BrowserError> {
            self.failure
                .take()
                .map_or_else(|| Ok(self.evidence.clone()), Err)
        }
    }

    #[derive(Default)]
    struct FakeResultConsumer {
        received: Vec<String>,
        dispatch_count: usize,
        reject: bool,
    }

    impl BrowserFormResultConsumer for FakeResultConsumer {
        fn receive_form_result(&mut self, result: &BrowserFormResult) -> Result<(), BrowserError> {
            if self.reject {
                return Err(BrowserError::FormResultConsumerRejected);
            }
            self.received.push(result.result_id.clone());
            Ok(())
        }
    }

    fn result_evidence(draft: &BrowserFormDraft) -> BrowserFormResultFrameEvidence {
        BrowserFormResultFrameEvidence::new(
            "session-result",
            "frame-result",
            "loader-result",
            draft.frame.control_generation,
            draft.frame.navigation_revision,
            draft.frame.document_generation,
            draft.frame.dom_revision,
            "https://example.de/account?form=1",
            "https://example.de",
            now(),
        )
        .expect("result evidence")
    }

    fn provider_fixture() -> (
        BrowserFormResultProvider,
        BrowserFormDraft,
        BrowserFormResultFrameEvidence,
        crate::BrowserProfile,
        crate::BrowserWorkspace,
    ) {
        let fixture = form_fixture();
        let draft = fixture.draft;
        let provider = BrowserFormResultProvider::mount(
            &fixture.profile,
            &fixture.workspace,
            draft.scope.clone(),
            "plugin.form-result",
        )
        .expect("provider");
        let evidence = result_evidence(&draft);
        (
            provider,
            draft,
            evidence,
            fixture.profile,
            fixture.workspace,
        )
    }

    #[test]
    fn result_renders_exact_mutations_identity_policy_and_log() {
        let (mut provider, draft, evidence, profile, workspace) = provider_fixture();
        let mut host = FakeResultHost {
            evidence,
            failure: None,
        };
        let result = provider
            .project_result(
                &mut host,
                &profile,
                &workspace,
                &draft,
                "invocation-form-1",
                now(),
            )
            .expect("result");
        assert_eq!(provider.result_log().entries.len(), 1);
        assert_eq!(result.identity.plugin_id, "plugin.form-result");
        assert_eq!(result.identity.invocation_id, "invocation-form-1");
        assert_eq!(result.mutations.len(), 3);
        assert_eq!(
            result.mutations[2].secret_class,
            BrowserFormSecretClass::Credential
        );
        assert!(
            result
                .policy
                .requirements
                .contains(&BrowserFormResultPolicyRequirement::HumanApproval)
        );
        assert!(
            result
                .policy
                .requirements
                .contains(&BrowserFormResultPolicyRequirement::NoDirectClickOrSubmit)
        );
        assert!(!result.dispatch_performed);
        assert!(!result.execution_permitted);
        let serialized = serde_json::to_string(&result).expect("result json");
        assert!(!serialized.contains("password-value"));
        assert!(result.evidence_digest().is_ok());
    }

    #[test]
    fn stale_navigation_reselect_and_duplicate_fail_closed() {
        let (mut provider, draft, mut evidence, profile, workspace) = provider_fixture();
        evidence.navigation_revision += 1;
        let mut host = FakeResultHost {
            evidence,
            failure: None,
        };
        let error = provider
            .project_result(
                &mut host,
                &profile,
                &workspace,
                &draft,
                "invocation-stale",
                now(),
            )
            .expect_err("navigation drift");
        assert!(matches!(error, BrowserError::FormResultSnapshotStale));
        assert_eq!(
            provider.state(),
            BrowserFormResultProviderState::Invalidated
        );

        let (mut provider, draft, evidence, profile, workspace) = provider_fixture();
        let mut revoked_profile = profile.clone();
        let revision = revoked_profile.revision;
        revoked_profile
            .revoke(revision, sha('a'), now() + Duration::seconds(1))
            .expect("revoke reselected profile");
        let mut other_host = FakeResultHost {
            evidence,
            failure: None,
        };
        let error = provider
            .project_result(
                &mut other_host,
                &revoked_profile,
                &workspace,
                &draft,
                "invocation-reselect",
                now(),
            )
            .expect_err("reselected profile or Mission");
        assert!(matches!(error, BrowserError::FormResultScopeMismatch));
        assert_eq!(
            provider.state(),
            BrowserFormResultProviderState::Invalidated
        );

        let (mut provider, draft, evidence, profile, workspace) = provider_fixture();
        let mut host = FakeResultHost {
            evidence,
            failure: None,
        };
        let result = provider
            .project_result(
                &mut host,
                &profile,
                &workspace,
                &draft,
                "invocation-duplicate",
                now(),
            )
            .expect("first result");
        let error = provider
            .project_result(
                &mut host,
                &profile,
                &workspace,
                &draft,
                "invocation-duplicate-2",
                now(),
            )
            .expect_err("same draft duplicate");
        assert!(matches!(error, BrowserError::FormResultDuplicate));
        let mut consumer = FakeResultConsumer::default();
        provider
            .deliver_result(&result.result_id, &mut consumer)
            .expect("deliver");
        assert_eq!(consumer.received, vec![result.result_id.clone()]);
        assert_eq!(consumer.dispatch_count, 0);
        assert!(matches!(
            provider.deliver_result(&result.result_id, &mut consumer),
            Err(BrowserError::FormResultDuplicate)
        ));
    }

    #[test]
    fn restart_remount_and_consumer_failure_never_reopen_old_cursor() {
        let (mut provider, draft, evidence, profile, workspace) = provider_fixture();
        let mut host = FakeResultHost {
            evidence,
            failure: None,
        };
        let result = provider
            .project_result(
                &mut host,
                &profile,
                &workspace,
                &draft,
                "invocation-restart",
                now(),
            )
            .expect("result");
        let log = provider.result_log().clone();
        provider.restart().expect("restart");
        let mut consumer = FakeResultConsumer::default();
        assert!(matches!(
            provider.deliver_result(&result.result_id, &mut consumer),
            Err(BrowserError::FormResultProviderRestarted)
        ));
        let mut remounted = BrowserFormResultProvider::remount(
            &profile,
            &workspace,
            draft.scope.clone(),
            "plugin.form-result",
            log,
        )
        .expect("remount");
        assert!(matches!(
            remounted.deliver_result(&result.result_id, &mut consumer),
            Err(BrowserError::FormResultReopened)
        ));
        let mut new_host = FakeResultHost {
            evidence: result_evidence(&draft),
            failure: None,
        };
        assert!(matches!(
            remounted.project_result(
                &mut new_host,
                &profile,
                &workspace,
                &draft,
                "invocation-restart-new",
                now(),
            ),
            Err(BrowserError::FormResultDuplicate)
        ));

        let (mut provider, draft, evidence, profile, workspace) = provider_fixture();
        let mut host = FakeResultHost {
            evidence,
            failure: None,
        };
        let result = provider
            .project_result(
                &mut host,
                &profile,
                &workspace,
                &draft,
                "invocation-consumer-failure",
                now(),
            )
            .expect("result");
        let mut rejecting_consumer = FakeResultConsumer {
            reject: true,
            ..FakeResultConsumer::default()
        };
        assert!(matches!(
            provider.deliver_result(&result.result_id, &mut rejecting_consumer),
            Err(BrowserError::FormResultConsumerRejected)
        ));
        let mut accepting_consumer = FakeResultConsumer::default();
        provider
            .deliver_result(&result.result_id, &mut accepting_consumer)
            .expect("retry after consumer failure");
    }

    #[test]
    fn unavailable_host_is_not_native_result_evidence() {
        let (mut provider, draft, _evidence, profile, workspace) = provider_fixture();
        let mut host = UnavailableBrowserFormResultHost;
        let error = provider
            .project_result(
                &mut host,
                &profile,
                &workspace,
                &draft,
                "invocation-unavailable",
                now(),
            )
            .expect_err("native host unavailable");
        assert!(matches!(error, BrowserError::ProtocolUnavailable));
        assert_eq!(provider.result_log().entries.len(), 0);
    }

    #[test]
    fn profile_revoke_and_dom_drift_fail_closed_without_dispatch() {
        let (mut provider, draft, mut evidence, profile, workspace) = provider_fixture();
        evidence.dom_revision += 1;
        let mut host = FakeResultHost {
            evidence,
            failure: None,
        };
        assert!(matches!(
            provider.project_result(
                &mut host,
                &profile,
                &workspace,
                &draft,
                "invocation-dom-drift",
                now(),
            ),
            Err(BrowserError::FormResultSnapshotStale)
        ));

        let (mut provider, draft, evidence, mut profile, workspace) = provider_fixture();
        let mut host = FakeResultHost {
            evidence,
            failure: None,
        };
        let result = provider
            .project_result(
                &mut host,
                &profile,
                &workspace,
                &draft,
                "invocation-revoke",
                now(),
            )
            .expect("result");
        let revision = profile.revision;
        provider
            .revoke(
                &mut profile,
                revision,
                sha('a'),
                now() + Duration::seconds(1),
            )
            .expect("revoke");
        let mut consumer = FakeResultConsumer::default();
        assert!(matches!(
            provider.deliver_result(&result.result_id, &mut consumer),
            Err(BrowserError::FormResultProviderRevoked)
        ));
    }

    #[test]
    fn frame_evidence_rejects_cross_origin_and_unknown_session() {
        let (provider, draft, evidence, _profile, _workspace) = provider_fixture();
        let scope = provider.scope().clone();
        let mut changed = evidence.clone();
        changed.origin = "https://other.example".to_owned();
        assert!(matches!(
            changed.validate_against(&scope, &draft),
            Err(BrowserError::FormResultSnapshotStale | BrowserError::InvalidFormResult)
        ));
        let mut unknown = evidence;
        unknown.session_id = "session-unknown".to_owned();
        assert!(matches!(
            unknown.validate_against(&scope, &draft),
            Err(BrowserError::FormResultSnapshotStale)
        ));
    }
}
