//! Mission-scoped, read-only form interaction drafts.
//!
//! This module deliberately stops before dispatch.  A host can provide a
//! redacted form observation and can re-read that observation immediately
//! before a consumer would dispatch, but it cannot be asked to perform an
//! input.  Every public value is bound to the exact Project/Mission/profile,
//! workspace revision, tab, frame, loader, origin, and DOM generation.  Form
//! values are represented only by digests and sensitive-field classification.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    BrowserProfileId, BrowserTabId, BrowserWorkspaceId, MissionId, ProjectId, TenantId,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::workspace::{digest, digest_json, is_bounded_identifier, is_sha256};
use crate::{
    BrowserControlState, BrowserError, BrowserProfile, BrowserProfileStatus, BrowserWorkspace,
};

const FORM_SCHEMA_VERSION: u32 = 1;
const MAX_FIELDS: usize = 512;
const MAX_ACTIONS: usize = 512;
const MAX_ID_BYTES: usize = 512;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormScope {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub profile_id: BrowserProfileId,
    pub profile_revision: u64,
    pub workspace_id: BrowserWorkspaceId,
    pub workspace_revision: u64,
    pub tab_id: BrowserTabId,
    pub identity_digest: String,
}

impl BrowserFormScope {
    pub fn from_workspace(
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        tab_id: BrowserTabId,
    ) -> Result<Self, BrowserError> {
        profile.validate()?;
        workspace.validate()?;
        if profile.status != BrowserProfileStatus::Active
            || profile.tenant_id != workspace.tenant_id
            || profile.project_id != workspace.project_id
            || profile.id != workspace.profile_id
            || profile.identity.identity_digest != workspace.expected_identity_digest
            || !workspace.tabs.contains(&tab_id)
        {
            return Err(BrowserError::FormScopeMismatch);
        }
        let scope = Self {
            schema_version: FORM_SCHEMA_VERSION,
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            profile_id: profile.id.clone(),
            profile_revision: profile.revision,
            workspace_id: workspace.id.clone(),
            workspace_revision: workspace.revision,
            tab_id,
            identity_digest: profile.identity.identity_digest.clone(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != FORM_SCHEMA_VERSION
            || !is_bounded_identifier(self.tenant_id.as_str())
            || !is_bounded_identifier(self.project_id.as_str())
            || !is_bounded_identifier(self.mission_id.as_str())
            || !is_bounded_identifier(self.profile_id.as_str())
            || !is_bounded_identifier(self.workspace_id.as_str())
            || !is_bounded_identifier(self.tab_id.as_str())
            || self.profile_revision == 0
            || self.workspace_revision == 0
            || !is_sha256(&self.identity_digest)
        {
            return Err(BrowserError::InvalidFormDraft);
        }
        Ok(())
    }

    fn validate_immutable_against(
        &self,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
    ) -> Result<(), BrowserError> {
        self.validate()?;
        profile.validate()?;
        workspace.validate()?;
        if profile.status != BrowserProfileStatus::Active
            || self.tenant_id != workspace.tenant_id
            || self.project_id != workspace.project_id
            || self.mission_id != workspace.mission_id
            || self.profile_id != profile.id
            || self.profile_revision != profile.revision
            || self.workspace_id != workspace.id
            || self.tab_id != workspace.active_tab_id
            || self.identity_digest != profile.identity.identity_digest
            || self.identity_digest != workspace.expected_identity_digest
        {
            return Err(BrowserError::FormScopeMismatch);
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BrowserFormFrameObservation {
    session_id: String,
    frame_id: String,
    loader_id: String,
    control_generation: u64,
    navigation_revision: u64,
    document_generation: u64,
    dom_revision: u64,
    url: String,
    origin: String,
}

impl BrowserFormFrameObservation {
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
    ) -> Result<Self, BrowserError> {
        let observation = Self {
            session_id: session_id.into(),
            frame_id: frame_id.into(),
            loader_id: loader_id.into(),
            control_generation,
            navigation_revision,
            document_generation,
            dom_revision,
            url: url.into(),
            origin: origin.into(),
        };
        observation.validate()?;
        Ok(observation)
    }

    fn validate(&self) -> Result<(), BrowserError> {
        if !bounded_form_id(&self.session_id)
            || !bounded_form_id(&self.frame_id)
            || !bounded_form_id(&self.loader_id)
            || self.control_generation == 0
            || self.navigation_revision == 0
            || self.document_generation == 0
            || self.dom_revision == 0
            || !is_safe_page_url(&self.url)
            || canonical_origin(&self.url).as_deref() != Some(self.origin.as_str())
        {
            return Err(BrowserError::InvalidFormDraft);
        }
        Ok(())
    }
}

impl fmt::Debug for BrowserFormFrameObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserFormFrameObservation")
            .field("session_digest", &digest(self.session_id.as_bytes()))
            .field("frame_digest", &digest(self.frame_id.as_bytes()))
            .field("loader_digest", &digest(self.loader_id.as_bytes()))
            .field("control_generation", &self.control_generation)
            .field("navigation_revision", &self.navigation_revision)
            .field("document_generation", &self.document_generation)
            .field("dom_revision", &self.dom_revision)
            .field("url_digest", &digest(self.url.as_bytes()))
            .field("origin_digest", &digest(self.origin.as_bytes()))
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormFrameSnapshot {
    pub schema_version: u32,
    pub scope_digest: String,
    pub tab_id: BrowserTabId,
    pub session_id_digest: String,
    pub frame_id_digest: String,
    pub loader_id_digest: String,
    pub control_generation: u64,
    pub navigation_revision: u64,
    pub document_generation: u64,
    pub dom_revision: u64,
    pub url_digest: String,
    pub origin_digest: String,
    pub observed_at: DateTime<Utc>,
}

impl BrowserFormFrameSnapshot {
    pub fn observed(
        scope: &BrowserFormScope,
        raw: &BrowserFormFrameObservation,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        scope.validate()?;
        raw.validate()?;
        let snapshot = Self {
            schema_version: FORM_SCHEMA_VERSION,
            scope_digest: scope.evidence_digest()?,
            tab_id: scope.tab_id.clone(),
            session_id_digest: digest(raw.session_id.as_bytes()),
            frame_id_digest: digest(raw.frame_id.as_bytes()),
            loader_id_digest: digest(raw.loader_id.as_bytes()),
            control_generation: raw.control_generation,
            navigation_revision: raw.navigation_revision,
            document_generation: raw.document_generation,
            dom_revision: raw.dom_revision,
            url_digest: digest(raw.url.as_bytes()),
            origin_digest: digest(raw.origin.as_bytes()),
            observed_at,
        };
        snapshot.validate_for_scope(scope)?;
        Ok(snapshot)
    }

    pub fn validate_for_scope(&self, scope: &BrowserFormScope) -> Result<(), BrowserError> {
        scope.validate()?;
        if self.schema_version != FORM_SCHEMA_VERSION
            || self.scope_digest != scope.evidence_digest()?
            || self.tab_id != scope.tab_id
            || !is_sha256(&self.session_id_digest)
            || !is_sha256(&self.frame_id_digest)
            || !is_sha256(&self.loader_id_digest)
            || !is_sha256(&self.url_digest)
            || !is_sha256(&self.origin_digest)
            || self.control_generation == 0
            || self.navigation_revision == 0
            || self.document_generation == 0
            || self.dom_revision == 0
        {
            return Err(BrowserError::FormScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFormSecretClass {
    Public,
    Personal,
    Credential,
    Financial,
    Unknown,
}

impl BrowserFormSecretClass {
    pub fn is_sensitive(self) -> bool {
        !matches!(self, Self::Public)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFormFieldKind {
    Text,
    Email,
    Password,
    Token,
    Financial,
    Checkbox,
    Select,
    Submit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormFieldObservation {
    pub schema_version: u32,
    pub field_id: String,
    pub locator_digest: String,
    pub kind: BrowserFormFieldKind,
    pub secret_class: BrowserFormSecretClass,
    pub required: bool,
    pub editable: bool,
    pub field_revision: u64,
    pub value_digest: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormFieldPolicy {
    pub required: bool,
    pub editable: bool,
}

impl BrowserFormFieldObservation {
    pub fn new(
        field_id: impl Into<String>,
        locator_digest: impl Into<String>,
        kind: BrowserFormFieldKind,
        secret_class: BrowserFormSecretClass,
        policy: BrowserFormFieldPolicy,
        field_revision: u64,
        value_digest: Option<String>,
    ) -> Result<Self, BrowserError> {
        let field = Self {
            schema_version: FORM_SCHEMA_VERSION,
            field_id: field_id.into(),
            locator_digest: locator_digest.into(),
            kind,
            secret_class,
            required: policy.required,
            editable: policy.editable,
            field_revision,
            value_digest,
        };
        field.validate()?;
        Ok(field)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != FORM_SCHEMA_VERSION
            || !bounded_form_id(&self.field_id)
            || !is_sha256(&self.locator_digest)
            || self.field_revision == 0
            || self
                .value_digest
                .as_deref()
                .is_some_and(|value| !is_sha256(value))
        {
            return Err(BrowserError::InvalidFormDraft);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFormActionKind {
    Fill,
    Toggle,
    Select,
    Submit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormActionIntent {
    pub field_id: String,
    pub kind: BrowserFormActionKind,
    pub value_digest: Option<String>,
}

impl BrowserFormActionIntent {
    pub fn new(
        field_id: impl Into<String>,
        kind: BrowserFormActionKind,
        value_digest: Option<String>,
    ) -> Result<Self, BrowserError> {
        let intent = Self {
            field_id: field_id.into(),
            kind,
            value_digest,
        };
        intent.validate()?;
        Ok(intent)
    }

    fn validate(&self) -> Result<(), BrowserError> {
        if !bounded_form_id(&self.field_id)
            || self
                .value_digest
                .as_deref()
                .is_some_and(|value| !is_sha256(value))
            || matches!(
                self.kind,
                BrowserFormActionKind::Toggle | BrowserFormActionKind::Submit
            ) && self.value_digest.is_some()
            || matches!(
                self.kind,
                BrowserFormActionKind::Fill | BrowserFormActionKind::Select
            ) && self.value_digest.is_none()
        {
            return Err(BrowserError::InvalidFormDraft);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormActionPlan {
    pub schema_version: u32,
    pub action_id: String,
    pub field_id: String,
    pub kind: BrowserFormActionKind,
    pub value_digest: Option<String>,
    pub field_revision: u64,
    pub locator_digest: String,
    pub secret_class: BrowserFormSecretClass,
    pub human_approval_required: bool,
}

impl BrowserFormActionPlan {
    fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != FORM_SCHEMA_VERSION
            || !is_sha256(&self.action_id)
            || !bounded_form_id(&self.field_id)
            || self
                .value_digest
                .as_deref()
                .is_some_and(|value| !is_sha256(value))
            || self.field_revision == 0
            || !is_sha256(&self.locator_digest)
            || !self.human_approval_required
        {
            return Err(BrowserError::InvalidFormDraft);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormObservation {
    pub schema_version: u32,
    pub frame: BrowserFormFrameSnapshot,
    pub fields: Vec<BrowserFormFieldObservation>,
    pub secret_classification_digest: String,
    pub snapshot_digest: String,
}

impl BrowserFormObservation {
    pub fn new(
        frame: BrowserFormFrameSnapshot,
        mut fields: Vec<BrowserFormFieldObservation>,
    ) -> Result<Self, BrowserError> {
        fields.sort_by(|left, right| left.field_id.cmp(&right.field_id));
        if fields.is_empty() || fields.len() > MAX_FIELDS {
            return Err(BrowserError::InvalidFormDraft);
        }
        if fields
            .windows(2)
            .any(|pair| pair[0].field_id == pair[1].field_id)
        {
            return Err(BrowserError::InvalidFormDraft);
        }
        for field in &fields {
            field.validate()?;
        }
        let secret_classification_digest = digest_json(
            &fields
                .iter()
                .map(|field| (&field.field_id, field.kind, field.secret_class))
                .collect::<Vec<_>>(),
        )?;
        let snapshot_digest = digest_json(&(&frame, &fields, &secret_classification_digest))?;
        let observation = Self {
            schema_version: FORM_SCHEMA_VERSION,
            frame,
            fields,
            secret_classification_digest,
            snapshot_digest,
        };
        observation.validate()?;
        Ok(observation)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != FORM_SCHEMA_VERSION
            || self.fields.is_empty()
            || self.fields.len() > MAX_FIELDS
            || !is_sha256(&self.secret_classification_digest)
            || !is_sha256(&self.snapshot_digest)
        {
            return Err(BrowserError::InvalidFormDraft);
        }
        for field in &self.fields {
            field.validate()?;
        }
        if self
            .fields
            .windows(2)
            .any(|pair| pair[0].field_id >= pair[1].field_id)
        {
            return Err(BrowserError::InvalidFormDraft);
        }
        let expected_classification = digest_json(
            &self
                .fields
                .iter()
                .map(|field| (&field.field_id, field.kind, field.secret_class))
                .collect::<Vec<_>>(),
        )?;
        let expected_snapshot = digest_json(&(
            &self.frame,
            &self.fields,
            &self.secret_classification_digest,
        ))?;
        if expected_classification != self.secret_classification_digest
            || expected_snapshot != self.snapshot_digest
        {
            return Err(BrowserError::InvalidFormDraft);
        }
        Ok(())
    }

    fn validate_for_scope(&self, scope: &BrowserFormScope) -> Result<(), BrowserError> {
        self.validate()?;
        self.frame.validate_for_scope(scope)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFormDraftStatus {
    Draft,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormDraft {
    pub schema_version: u32,
    pub provider_generation: u64,
    pub sequence: u64,
    pub draft_id: String,
    pub scope: BrowserFormScope,
    pub frame: BrowserFormFrameSnapshot,
    pub fields: Vec<BrowserFormFieldObservation>,
    pub actions: Vec<BrowserFormActionPlan>,
    pub snapshot_digest: String,
    pub secret_classification_digest: String,
    pub created_at: DateTime<Utc>,
    pub status: BrowserFormDraftStatus,
    pub dispatch_performed: bool,
    pub execution_permitted: bool,
}

impl BrowserFormDraft {
    fn from_observation(
        scope: BrowserFormScope,
        observation: BrowserFormObservation,
        intents: &[BrowserFormActionIntent],
        provider_generation: u64,
        sequence: u64,
        created_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        scope.validate()?;
        observation.validate_for_scope(&scope)?;
        if provider_generation == 0
            || sequence == 0
            || intents.is_empty()
            || intents.len() > MAX_ACTIONS
        {
            return Err(BrowserError::InvalidFormDraft);
        }
        let fields_by_id: BTreeMap<&str, &BrowserFormFieldObservation> = observation
            .fields
            .iter()
            .map(|field| (field.field_id.as_str(), field))
            .collect();
        let mut used_fields = BTreeSet::new();
        let mut actions = Vec::with_capacity(intents.len());
        for intent in intents {
            intent.validate()?;
            let field = fields_by_id
                .get(intent.field_id.as_str())
                .ok_or(BrowserError::FormScopeMismatch)?;
            if !used_fields.insert(intent.field_id.clone())
                || (matches!(intent.kind, BrowserFormActionKind::Fill) && !field.editable)
                || (matches!(
                    intent.kind,
                    BrowserFormActionKind::Toggle | BrowserFormActionKind::Select
                ) && !field.editable)
                || matches!(intent.kind, BrowserFormActionKind::Submit)
                    && field.kind != BrowserFormFieldKind::Submit
            {
                return Err(BrowserError::InvalidFormDraft);
            }
            if matches!(intent.kind, BrowserFormActionKind::Fill)
                && matches!(
                    field.kind,
                    BrowserFormFieldKind::Password | BrowserFormFieldKind::Token
                )
                && field.secret_class == BrowserFormSecretClass::Public
            {
                return Err(BrowserError::InvalidFormDraft);
            }
            let action_id = digest_json(&(
                "browser-form-action/v1",
                provider_generation,
                &scope,
                &observation.frame,
                &field.field_id,
                intent.kind,
                &intent.value_digest,
                field.field_revision,
                &field.locator_digest,
            ))?;
            let action = BrowserFormActionPlan {
                schema_version: FORM_SCHEMA_VERSION,
                action_id,
                field_id: field.field_id.clone(),
                kind: intent.kind,
                value_digest: intent.value_digest.clone(),
                field_revision: field.field_revision,
                locator_digest: field.locator_digest.clone(),
                secret_class: field.secret_class,
                human_approval_required: true,
            };
            action.validate()?;
            actions.push(action);
        }
        let draft_id = digest_json(&(
            "browser-form-draft/v1",
            provider_generation,
            &scope,
            &observation.snapshot_digest,
            &actions,
        ))?;
        let draft = Self {
            schema_version: FORM_SCHEMA_VERSION,
            provider_generation,
            sequence,
            draft_id,
            scope,
            frame: observation.frame,
            fields: observation.fields,
            actions,
            snapshot_digest: observation.snapshot_digest,
            secret_classification_digest: observation.secret_classification_digest,
            created_at,
            status: BrowserFormDraftStatus::Draft,
            dispatch_performed: false,
            execution_permitted: false,
        };
        draft.validate()?;
        Ok(draft)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != FORM_SCHEMA_VERSION
            || self.provider_generation == 0
            || self.sequence == 0
            || !is_sha256(&self.draft_id)
            || self.actions.is_empty()
            || self.actions.len() > MAX_ACTIONS
            || !is_sha256(&self.snapshot_digest)
            || !is_sha256(&self.secret_classification_digest)
            || self.status != BrowserFormDraftStatus::Draft
            || self.dispatch_performed
            || self.execution_permitted
        {
            return Err(BrowserError::InvalidFormDraft);
        }
        self.scope.validate()?;
        self.frame.validate_for_scope(&self.scope)?;
        let observation = BrowserFormObservation {
            schema_version: FORM_SCHEMA_VERSION,
            frame: self.frame.clone(),
            fields: self.fields.clone(),
            secret_classification_digest: self.secret_classification_digest.clone(),
            snapshot_digest: self.snapshot_digest.clone(),
        };
        observation.validate_for_scope(&self.scope)?;
        let mut ids = BTreeSet::new();
        for action in &self.actions {
            action.validate()?;
            if !ids.insert(action.action_id.clone())
                || !self.fields.iter().any(|field| {
                    field.field_id == action.field_id
                        && field.field_revision == action.field_revision
                        && field.locator_digest == action.locator_digest
                        && field.secret_class == action.secret_class
                })
            {
                return Err(BrowserError::InvalidFormDraft);
            }
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormDraftLog {
    pub schema_version: u32,
    pub scope: BrowserFormScope,
    pub provider_generation: u64,
    pub entries: Vec<BrowserFormDraft>,
}

impl BrowserFormDraftLog {
    fn empty(scope: BrowserFormScope, provider_generation: u64) -> Result<Self, BrowserError> {
        scope.validate()?;
        if provider_generation == 0 {
            return Err(BrowserError::InvalidFormDraft);
        }
        Ok(Self {
            schema_version: FORM_SCHEMA_VERSION,
            scope,
            provider_generation,
            entries: Vec::new(),
        })
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != FORM_SCHEMA_VERSION || self.provider_generation == 0 {
            return Err(BrowserError::InvalidFormDraft);
        }
        self.scope.validate()?;
        for (index, entry) in self.entries.iter().enumerate() {
            entry.validate()?;
            let expected_sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(BrowserError::CounterOverflow)?;
            if entry.sequence != expected_sequence
                || entry.provider_generation != self.provider_generation
                || entry.scope != self.scope
            {
                return Err(BrowserError::InvalidFormDraft);
            }
        }
        Ok(())
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormApproval {
    pub schema_version: u32,
    pub provider_generation: u64,
    pub approval_id: String,
    pub draft_id: String,
    pub draft_digest: String,
    pub scope: BrowserFormScope,
    pub frame: BrowserFormFrameSnapshot,
    pub approval_evidence_digest: String,
    pub control_generation: u64,
    pub workspace_revision: u64,
    pub approved_at: DateTime<Utc>,
    pub human_takeover_confirmed: bool,
    pub dispatch_performed: bool,
    pub execution_permitted: bool,
}

impl BrowserFormApproval {
    fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != FORM_SCHEMA_VERSION
            || self.provider_generation == 0
            || !is_sha256(&self.approval_id)
            || !is_sha256(&self.draft_id)
            || !is_sha256(&self.draft_digest)
            || !is_sha256(&self.approval_evidence_digest)
            || self.control_generation == 0
            || self.workspace_revision == 0
            || !self.human_takeover_confirmed
            || self.dispatch_performed
            || self.execution_permitted
        {
            return Err(BrowserError::InvalidFormDraft);
        }
        self.scope.validate()?;
        self.frame.validate_for_scope(&self.scope)
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormDispatchLease {
    pub schema_version: u32,
    pub provider_generation: u64,
    pub lease_id: String,
    pub draft_id: String,
    pub draft_digest: String,
    pub scope: BrowserFormScope,
    pub frame: BrowserFormFrameSnapshot,
    pub snapshot_digest: String,
    pub secret_classification_digest: String,
    pub approval_digest: String,
    pub control_generation: u64,
    pub workspace_revision: u64,
    pub issued_at: DateTime<Utc>,
    pub used: bool,
    pub dispatch_performed: bool,
    pub execution_permitted: bool,
}

impl BrowserFormDispatchLease {
    fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != FORM_SCHEMA_VERSION
            || self.provider_generation == 0
            || !is_sha256(&self.lease_id)
            || !is_sha256(&self.draft_id)
            || !is_sha256(&self.draft_digest)
            || !is_sha256(&self.snapshot_digest)
            || !is_sha256(&self.secret_classification_digest)
            || !is_sha256(&self.approval_digest)
            || self.control_generation == 0
            || self.workspace_revision == 0
            || self.used
            || self.dispatch_performed
            || self.execution_permitted
        {
            return Err(BrowserError::InvalidFormDraft);
        }
        self.scope.validate()?;
        self.frame.validate_for_scope(&self.scope)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFormDispatchReceipt {
    pub schema_version: u32,
    pub provider_generation: u64,
    pub lease_id: String,
    pub draft_id: String,
    pub draft_digest: String,
    pub approval_digest: String,
    pub scope: BrowserFormScope,
    pub frame: BrowserFormFrameSnapshot,
    pub snapshot_digest: String,
    pub secret_classification_digest: String,
    pub revalidated_at: DateTime<Utc>,
    pub dispatch_performed: bool,
    pub execution_permitted: bool,
}

impl BrowserFormDispatchReceipt {
    fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != FORM_SCHEMA_VERSION
            || self.provider_generation == 0
            || !is_sha256(&self.lease_id)
            || !is_sha256(&self.draft_id)
            || !is_sha256(&self.draft_digest)
            || !is_sha256(&self.approval_digest)
            || !is_sha256(&self.snapshot_digest)
            || !is_sha256(&self.secret_classification_digest)
            || self.dispatch_performed
            || self.execution_permitted
        {
            return Err(BrowserError::InvalidFormDraft);
        }
        self.scope.validate()?;
        self.frame.validate_for_scope(&self.scope)
    }
}

pub trait BrowserFormHost {
    fn observe_form(
        &mut self,
        scope: &BrowserFormScope,
        now: DateTime<Utc>,
    ) -> Result<BrowserFormObservation, BrowserError>;

    fn revalidate_form(
        &mut self,
        scope: &BrowserFormScope,
        expected_frame: &BrowserFormFrameSnapshot,
        expected_snapshot_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<BrowserFormObservation, BrowserError>;
}

#[derive(Debug, Default)]
pub struct UnavailableBrowserFormHost;

impl BrowserFormHost for UnavailableBrowserFormHost {
    fn observe_form(
        &mut self,
        _scope: &BrowserFormScope,
        _now: DateTime<Utc>,
    ) -> Result<BrowserFormObservation, BrowserError> {
        Err(BrowserError::ProtocolUnavailable)
    }

    fn revalidate_form(
        &mut self,
        _scope: &BrowserFormScope,
        _expected_frame: &BrowserFormFrameSnapshot,
        _expected_snapshot_digest: &str,
        _now: DateTime<Utc>,
    ) -> Result<BrowserFormObservation, BrowserError> {
        Err(BrowserError::ProtocolUnavailable)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFormServiceState {
    Mounted,
    Invalidated,
    Revoked,
    Restarted,
}

pub struct BrowserFormDraftService {
    scope: BrowserFormScope,
    state: BrowserFormServiceState,
    provider_generation: u64,
    draft_log: BrowserFormDraftLog,
    drafts: BTreeMap<String, BrowserFormDraft>,
    approvals: BTreeMap<String, BrowserFormApproval>,
    leases: BTreeMap<String, BrowserFormDispatchLease>,
    leased_approvals: BTreeSet<String>,
    used_leases: BTreeSet<String>,
    closed_drafts: BTreeSet<String>,
    closed_approvals: BTreeSet<String>,
    next_sequence: u64,
}

impl fmt::Debug for BrowserFormDraftService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserFormDraftService")
            .field("scope_digest", &self.scope.evidence_digest().ok())
            .field("state", &self.state)
            .field("provider_generation", &self.provider_generation)
            .field("draft_count", &self.drafts.len())
            .field("approval_count", &self.approvals.len())
            .field("pending_lease_count", &self.leases.len())
            .finish_non_exhaustive()
    }
}

impl BrowserFormDraftService {
    pub fn mount(
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        tab_id: BrowserTabId,
    ) -> Result<Self, BrowserError> {
        let scope = BrowserFormScope::from_workspace(profile, workspace, tab_id)?;
        let provider_generation = 1;
        Ok(Self {
            draft_log: BrowserFormDraftLog::empty(scope.clone(), provider_generation)?,
            scope,
            state: BrowserFormServiceState::Mounted,
            provider_generation,
            drafts: BTreeMap::new(),
            approvals: BTreeMap::new(),
            leases: BTreeMap::new(),
            leased_approvals: BTreeSet::new(),
            used_leases: BTreeSet::new(),
            closed_drafts: BTreeSet::new(),
            closed_approvals: BTreeSet::new(),
            next_sequence: 1,
        })
    }

    pub fn scope(&self) -> &BrowserFormScope {
        &self.scope
    }

    pub fn state(&self) -> BrowserFormServiceState {
        self.state
    }

    pub fn draft_log(&self) -> &BrowserFormDraftLog {
        &self.draft_log
    }

    pub fn pending_lease_count(&self) -> usize {
        self.leases.len()
    }

    pub fn draft_form<H: BrowserFormHost>(
        &mut self,
        host: &mut H,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        intents: &[BrowserFormActionIntent],
        now: DateTime<Utc>,
    ) -> Result<BrowserFormDraft, BrowserError> {
        self.ensure_mounted()?;
        self.validate_current_profile(profile)?;
        self.scope.validate_immutable_against(profile, workspace)?;
        if workspace.revision != self.scope.workspace_revision
            || workspace.control_state != BrowserControlState::AgentControlled
        {
            return Err(BrowserError::FormScopeMismatch);
        }
        let proof = workspace.agent_lease_proof(now)?;
        let observation = match host.observe_form(&self.scope, now) {
            Ok(observation) => observation,
            Err(error) => return Err(self.host_error(error)),
        };
        observation.validate_for_scope(&self.scope)?;
        if observation.frame.control_generation != proof.generation {
            return Err(BrowserError::FormSnapshotStale);
        }
        let sequence = self.next_sequence;
        let draft = BrowserFormDraft::from_observation(
            self.scope.clone(),
            observation,
            intents,
            self.provider_generation,
            sequence,
            now,
        )?;
        if self.drafts.contains_key(&draft.draft_id) || self.closed_drafts.contains(&draft.draft_id)
        {
            return Err(BrowserError::FormDraftDuplicate);
        }
        let mut candidate_log = self.draft_log.clone();
        candidate_log.entries.push(draft.clone());
        candidate_log.validate()?;
        self.draft_log = candidate_log;
        self.drafts.insert(draft.draft_id.clone(), draft.clone());
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        Ok(draft)
    }

    pub fn approve_draft(
        &mut self,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        draft_id: &str,
        approval_id: &str,
        approval_evidence_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<BrowserFormApproval, BrowserError> {
        self.ensure_mounted()?;
        self.validate_current_profile(profile)?;
        let draft = self
            .drafts
            .get(draft_id)
            .ok_or_else(|| {
                if self.closed_drafts.contains(draft_id) {
                    BrowserError::FormDraftReopened
                } else {
                    BrowserError::FormScopeMismatch
                }
            })?
            .clone();
        if !bounded_form_id(approval_id) || !is_sha256(approval_evidence_digest) {
            return Err(BrowserError::FormDraftDuplicate);
        }
        let approval_id_digest = digest(approval_id.as_bytes());
        if self.approvals.contains_key(&approval_id_digest)
            || self.closed_approvals.contains(&approval_id_digest)
        {
            return Err(BrowserError::FormDraftDuplicate);
        }
        self.scope.validate_immutable_against(profile, workspace)?;
        if workspace.control_state != BrowserControlState::UserControlled {
            return Err(BrowserError::FormApprovalRequired);
        }
        let Some(transition) = workspace.control_history.last() else {
            return Err(BrowserError::FormApprovalMismatch);
        };
        if workspace.revision != draft.scope.workspace_revision.saturating_add(1)
            || workspace.lease_generation != draft.frame.control_generation.saturating_add(1)
            || transition.state != BrowserControlState::UserControlled
            || transition.generation != workspace.lease_generation
            || draft.provider_generation != self.provider_generation
        {
            return Err(BrowserError::FormApprovalMismatch);
        }
        let approval = BrowserFormApproval {
            schema_version: FORM_SCHEMA_VERSION,
            provider_generation: self.provider_generation,
            approval_id: approval_id_digest,
            draft_id: draft.draft_id.clone(),
            draft_digest: draft.evidence_digest()?,
            scope: draft.scope.clone(),
            frame: draft.frame.clone(),
            approval_evidence_digest: approval_evidence_digest.to_owned(),
            control_generation: workspace.lease_generation,
            workspace_revision: workspace.revision,
            approved_at: now,
            human_takeover_confirmed: true,
            dispatch_performed: false,
            execution_permitted: false,
        };
        approval.validate()?;
        self.approvals
            .insert(approval.approval_id.clone(), approval.clone());
        Ok(approval)
    }

    pub fn acquire_dispatch_lease(
        &mut self,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        approval_id: &str,
        now: DateTime<Utc>,
    ) -> Result<BrowserFormDispatchLease, BrowserError> {
        self.ensure_mounted()?;
        self.validate_current_profile(profile)?;
        let approval = self
            .approvals
            .get(approval_id)
            .ok_or_else(|| {
                if self.closed_approvals.contains(approval_id) {
                    BrowserError::FormDraftReopened
                } else {
                    BrowserError::FormApprovalMismatch
                }
            })?
            .clone();
        self.scope.validate_immutable_against(profile, workspace)?;
        self.validate_takeover_workspace(workspace, &approval)?;
        if self.leased_approvals.contains(approval_id) {
            return Err(BrowserError::FormDispatchLeaseUnavailable);
        }
        let draft = self
            .drafts
            .get(&approval.draft_id)
            .ok_or(BrowserError::FormDraftReopened)?;
        let approval_digest = approval.evidence_digest()?;
        let lease_id = digest_json(&(
            "browser-form-dispatch-lease/v1",
            self.provider_generation,
            approval_id,
            &approval_digest,
            now,
        ))?;
        let lease = BrowserFormDispatchLease {
            schema_version: FORM_SCHEMA_VERSION,
            provider_generation: self.provider_generation,
            lease_id,
            draft_id: draft.draft_id.clone(),
            draft_digest: draft.evidence_digest()?,
            scope: draft.scope.clone(),
            frame: draft.frame.clone(),
            snapshot_digest: draft.snapshot_digest.clone(),
            secret_classification_digest: draft.secret_classification_digest.clone(),
            approval_digest,
            control_generation: workspace.lease_generation,
            workspace_revision: workspace.revision,
            issued_at: now,
            used: false,
            dispatch_performed: false,
            execution_permitted: false,
        };
        lease.validate()?;
        self.leased_approvals.insert(approval_id.to_owned());
        self.leases.insert(lease.lease_id.clone(), lease.clone());
        Ok(lease)
    }

    pub fn revalidate_before_dispatch<H: BrowserFormHost>(
        &mut self,
        host: &mut H,
        profile: &BrowserProfile,
        workspace: &BrowserWorkspace,
        lease_id: &str,
        now: DateTime<Utc>,
    ) -> Result<BrowserFormDispatchReceipt, BrowserError> {
        self.ensure_mounted()?;
        let lease = self
            .leases
            .remove(lease_id)
            .ok_or(BrowserError::FormDispatchLeaseUnavailable)?;
        self.used_leases.insert(lease_id.to_owned());
        let draft = self
            .drafts
            .get(&lease.draft_id)
            .ok_or(BrowserError::FormDraftReopened)?
            .clone();
        self.validate_current_profile(profile)?;
        self.scope.validate_immutable_against(profile, workspace)?;
        self.validate_takeover_workspace(
            workspace,
            &BrowserFormApproval {
                schema_version: FORM_SCHEMA_VERSION,
                provider_generation: lease.provider_generation,
                approval_id: digest(b"synthetic-approved-id"),
                draft_id: lease.draft_id.clone(),
                draft_digest: lease.draft_digest.clone(),
                scope: lease.scope.clone(),
                frame: lease.frame.clone(),
                approval_evidence_digest: digest(b"synthetic-approval-evidence"),
                control_generation: lease.control_generation,
                workspace_revision: lease.workspace_revision,
                approved_at: lease.issued_at,
                human_takeover_confirmed: true,
                dispatch_performed: false,
                execution_permitted: false,
            },
        )?;
        let observation =
            match host.revalidate_form(&self.scope, &lease.frame, &lease.snapshot_digest, now) {
                Ok(observation) => observation,
                Err(error) => return Err(self.host_error(error)),
            };
        observation.validate_for_scope(&self.scope)?;
        if observation.frame != lease.frame {
            return Err(BrowserError::FormSnapshotStale);
        }
        if observation.secret_classification_digest != lease.secret_classification_digest {
            return Err(BrowserError::FormSecretDrift);
        }
        if observation.snapshot_digest != lease.snapshot_digest
            || observation.snapshot_digest != draft.snapshot_digest
        {
            return Err(BrowserError::FormSnapshotStale);
        }
        let receipt = BrowserFormDispatchReceipt {
            schema_version: FORM_SCHEMA_VERSION,
            provider_generation: lease.provider_generation,
            lease_id: lease.lease_id,
            draft_id: lease.draft_id,
            draft_digest: lease.draft_digest,
            approval_digest: lease.approval_digest,
            scope: lease.scope,
            frame: lease.frame,
            snapshot_digest: lease.snapshot_digest,
            secret_classification_digest: lease.secret_classification_digest,
            revalidated_at: now,
            dispatch_performed: false,
            execution_permitted: false,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn restart(&mut self) {
        self.state = BrowserFormServiceState::Restarted;
        self.clear_pending();
    }

    pub fn unmount(&mut self) {
        self.state = BrowserFormServiceState::Invalidated;
        self.clear_pending();
    }

    pub fn revoke(
        &mut self,
        profile: &mut BrowserProfile,
        expected_revision: u64,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.ensure_mounted()?;
        if profile.id != self.scope.profile_id {
            return Err(BrowserError::FormScopeMismatch);
        }
        profile.revoke(expected_revision, evidence_digest, now)?;
        self.state = BrowserFormServiceState::Revoked;
        self.clear_pending();
        Ok(())
    }

    fn ensure_mounted(&self) -> Result<(), BrowserError> {
        match self.state {
            BrowserFormServiceState::Mounted => Ok(()),
            BrowserFormServiceState::Revoked => Err(BrowserError::FormProviderRevoked),
            BrowserFormServiceState::Restarted => Err(BrowserError::FormProviderRestarted),
            BrowserFormServiceState::Invalidated => Err(BrowserError::FormScopeMismatch),
        }
    }

    fn validate_current_profile(&self, profile: &BrowserProfile) -> Result<(), BrowserError> {
        profile.validate()?;
        if profile.status != BrowserProfileStatus::Active {
            return Err(BrowserError::FormProviderRevoked);
        }
        if profile.id != self.scope.profile_id
            || profile.revision != self.scope.profile_revision
            || profile.identity.identity_digest != self.scope.identity_digest
        {
            return Err(BrowserError::FormScopeMismatch);
        }
        Ok(())
    }

    fn validate_takeover_workspace(
        &self,
        workspace: &BrowserWorkspace,
        approval: &BrowserFormApproval,
    ) -> Result<(), BrowserError> {
        workspace.validate()?;
        if workspace.control_state != BrowserControlState::UserControlled {
            return Err(BrowserError::FormApprovalRequired);
        }
        let Some(transition) = workspace.control_history.last() else {
            return Err(BrowserError::FormApprovalMismatch);
        };
        if workspace.revision != approval.workspace_revision
            || workspace.lease_generation != approval.control_generation
            || transition.state != BrowserControlState::UserControlled
            || transition.generation != approval.control_generation
            || approval.scope != self.scope
        {
            return Err(BrowserError::FormApprovalMismatch);
        }
        Ok(())
    }

    fn clear_pending(&mut self) {
        self.closed_drafts.extend(self.drafts.keys().cloned());
        self.closed_approvals.extend(self.approvals.keys().cloned());
        self.drafts.clear();
        self.approvals.clear();
        self.leases.clear();
        self.leased_approvals.clear();
    }

    fn host_error(&mut self, error: BrowserError) -> BrowserError {
        if matches!(
            error,
            BrowserError::HostExited | BrowserError::HostRestarted
        ) {
            self.state = BrowserFormServiceState::Restarted;
            self.clear_pending();
        }
        error
    }
}

fn bounded_form_id(value: &str) -> bool {
    is_bounded_identifier(value) && value.len() <= MAX_ID_BYTES
}

fn is_safe_page_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.host_str().is_some()
    })
}

fn canonical_origin(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    Some(url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, BrowserControlLeaseId, BrowserProfileId, BrowserTabId, BrowserWorkspaceId,
        MissionContract, MissionId, ProjectId, StorageMode,
    };

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 8, 0, 0)
            .single()
            .expect("fixed time")
    }

    fn sha(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    #[derive(Clone)]
    struct Fixture {
        profile: BrowserProfile,
        workspace: BrowserWorkspace,
        observation: BrowserFormObservation,
    }

    fn fixture() -> Fixture {
        let timestamp = now();
        let project = hartevo_domain_kernel::Project::create_local(
            "tenant-form".into(),
            ProjectId::from("project-form"),
            "Form project",
            "Form fixture",
            "/tmp/form-project",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = hartevo_domain_kernel::Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-form"),
            project.id.clone(),
            "Form mission",
            MissionContract::bootstrap("draft a form", ["browser.read".to_owned()], timestamp),
            timestamp,
        )
        .expect("mission");
        let identity = crate::BrowserIdentity::new(
            "chromium",
            AccountId::from("account-form"),
            sha('a'),
            sha('b'),
            timestamp,
        )
        .expect("identity");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-form"),
            &project,
            "keyring://form",
            identity,
            timestamp,
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-form"),
            &project,
            &mission,
            &profile,
            BrowserTabId::from("tab-form"),
            BrowserControlLeaseId::from("lease-agent"),
            timestamp + Duration::hours(1),
            sha('c'),
            timestamp,
        )
        .expect("workspace");
        let scope =
            BrowserFormScope::from_workspace(&profile, &workspace, BrowserTabId::from("tab-form"))
                .expect("scope");
        let raw = BrowserFormFrameObservation::new(
            "session-form",
            "frame-root",
            "loader-1",
            workspace.lease_generation,
            1,
            1,
            1,
            "https://example.de/account?form=1",
            "https://example.de",
        )
        .expect("frame");
        let frame = BrowserFormFrameSnapshot::observed(&scope, &raw, timestamp).expect("snapshot");
        let fields = fixture_fields();
        let observation = BrowserFormObservation::new(frame, fields).expect("observation");
        Fixture {
            profile,
            workspace,
            observation,
        }
    }

    fn fixture_fields() -> Vec<BrowserFormFieldObservation> {
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
            .expect("public"),
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
            .expect("email"),
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
            .expect("password"),
            BrowserFormFieldObservation::new(
                "field-submit",
                sha('4'),
                BrowserFormFieldKind::Submit,
                BrowserFormSecretClass::Public,
                BrowserFormFieldPolicy {
                    required: false,
                    editable: false,
                },
                1,
                None,
            )
            .expect("submit"),
        ]
    }

    struct FakeFormHost {
        observation: BrowserFormObservation,
        revalidated: BrowserFormObservation,
        failure: Option<BrowserError>,
    }

    impl FakeFormHost {
        fn new(observation: BrowserFormObservation) -> Self {
            Self {
                revalidated: observation.clone(),
                observation,
                failure: None,
            }
        }
    }

    impl BrowserFormHost for FakeFormHost {
        fn observe_form(
            &mut self,
            _scope: &BrowserFormScope,
            _now: DateTime<Utc>,
        ) -> Result<BrowserFormObservation, BrowserError> {
            self.failure
                .take()
                .map_or_else(|| Ok(self.observation.clone()), Err)
        }

        fn revalidate_form(
            &mut self,
            _scope: &BrowserFormScope,
            _expected_frame: &BrowserFormFrameSnapshot,
            _expected_snapshot_digest: &str,
            _now: DateTime<Utc>,
        ) -> Result<BrowserFormObservation, BrowserError> {
            self.failure
                .take()
                .map_or_else(|| Ok(self.revalidated.clone()), Err)
        }
    }

    fn intents() -> Vec<BrowserFormActionIntent> {
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

    fn takeover(workspace: &mut BrowserWorkspace, timestamp: DateTime<Utc>) {
        workspace
            .user_takeover(
                workspace.revision,
                workspace.lease_generation,
                BrowserControlLeaseId::from("lease-user"),
                sha('6'),
                timestamp + Duration::seconds(1),
            )
            .expect("takeover");
    }

    fn approved_service(
        fixture: &Fixture,
    ) -> (
        BrowserFormDraftService,
        BrowserFormDraft,
        BrowserFormApproval,
    ) {
        let mut service = BrowserFormDraftService::mount(
            &fixture.profile,
            &fixture.workspace,
            BrowserTabId::from("tab-form"),
        )
        .expect("mount");
        let mut host = FakeFormHost::new(fixture.observation.clone());
        let draft = service
            .draft_form(
                &mut host,
                &fixture.profile,
                &fixture.workspace,
                &intents(),
                now(),
            )
            .expect("draft");
        let mut user_workspace = fixture.workspace.clone();
        takeover(&mut user_workspace, now());
        let approval = service
            .approve_draft(
                &fixture.profile,
                &user_workspace,
                &draft.draft_id,
                "approval-form",
                &sha('7'),
                now() + Duration::seconds(2),
            )
            .expect("approval");
        (service, draft, approval)
    }

    #[test]
    fn draft_is_exactly_scoped_logged_first_and_redacts_sensitive_values() {
        let fixture = fixture();
        let mut service = BrowserFormDraftService::mount(
            &fixture.profile,
            &fixture.workspace,
            BrowserTabId::from("tab-form"),
        )
        .expect("mount");
        let mut host = FakeFormHost::new(fixture.observation.clone());
        let draft = service
            .draft_form(
                &mut host,
                &fixture.profile,
                &fixture.workspace,
                &intents(),
                now(),
            )
            .expect("draft");
        assert_eq!(service.draft_log().entries.len(), 1);
        assert_eq!(draft.status, BrowserFormDraftStatus::Draft);
        assert!(!draft.dispatch_performed);
        assert!(!draft.execution_permitted);
        assert_eq!(
            draft.actions[2].secret_class,
            BrowserFormSecretClass::Credential
        );
        let serialized = serde_json::to_string(&draft).expect("safe json");
        assert!(!serialized.contains("password-value"));
        assert!(draft.evidence_digest().is_ok());
    }

    #[test]
    fn duplicate_observation_is_fail_closed() {
        let fixture = fixture();
        let mut service = BrowserFormDraftService::mount(
            &fixture.profile,
            &fixture.workspace,
            BrowserTabId::from("tab-form"),
        )
        .expect("mount");
        let mut host = FakeFormHost::new(fixture.observation.clone());
        service
            .draft_form(
                &mut host,
                &fixture.profile,
                &fixture.workspace,
                &intents(),
                now(),
            )
            .expect("first draft");
        let error = service
            .draft_form(
                &mut host,
                &fixture.profile,
                &fixture.workspace,
                &intents(),
                now(),
            )
            .expect_err("duplicate");
        assert!(matches!(error, BrowserError::FormDraftDuplicate));
    }

    #[test]
    fn approval_requires_takeover_and_lease_is_single_use() {
        let fixture = fixture();
        let (mut service, draft) = approved_service_without_takeover(&fixture);
        let error = service
            .approve_draft(
                &fixture.profile,
                &fixture.workspace,
                &draft.draft_id,
                "approval-form",
                &sha('7'),
                now(),
            )
            .expect_err("agent cannot approve");
        assert!(matches!(error, BrowserError::FormApprovalRequired));

        let mut user_workspace = fixture.workspace.clone();
        takeover(&mut user_workspace, now());
        let approval = service
            .approve_draft(
                &fixture.profile,
                &user_workspace,
                &draft.draft_id,
                "approval-form",
                &sha('7'),
                now() + Duration::seconds(2),
            )
            .expect("approval");
        assert!(matches!(
            service.approve_draft(
                &fixture.profile,
                &user_workspace,
                &draft.draft_id,
                "approval-form",
                &sha('7'),
                now() + Duration::seconds(3),
            ),
            Err(BrowserError::FormDraftDuplicate)
        ));
        let lease = service
            .acquire_dispatch_lease(
                &fixture.profile,
                &user_workspace,
                &approval.approval_id,
                now() + Duration::seconds(3),
            )
            .expect("lease");
        assert!(matches!(
            service.acquire_dispatch_lease(
                &fixture.profile,
                &user_workspace,
                &approval.approval_id,
                now() + Duration::seconds(3),
            ),
            Err(BrowserError::FormDispatchLeaseUnavailable)
        ));
        let mut host = FakeFormHost::new(fixture.observation.clone());
        let receipt = service
            .revalidate_before_dispatch(
                &mut host,
                &fixture.profile,
                &user_workspace,
                &lease.lease_id,
                now() + Duration::seconds(4),
            )
            .expect("revalidation");
        assert!(!receipt.dispatch_performed);
        assert!(!receipt.execution_permitted);
        assert!(matches!(
            service.revalidate_before_dispatch(
                &mut host,
                &fixture.profile,
                &user_workspace,
                &lease.lease_id,
                now() + Duration::seconds(5),
            ),
            Err(BrowserError::FormDispatchLeaseUnavailable)
        ));
    }

    fn approved_service_without_takeover(
        fixture: &Fixture,
    ) -> (BrowserFormDraftService, BrowserFormDraft) {
        let mut service = BrowserFormDraftService::mount(
            &fixture.profile,
            &fixture.workspace,
            BrowserTabId::from("tab-form"),
        )
        .expect("mount");
        let mut host = FakeFormHost::new(fixture.observation.clone());
        let draft = service
            .draft_form(
                &mut host,
                &fixture.profile,
                &fixture.workspace,
                &intents(),
                now(),
            )
            .expect("draft");
        (service, draft)
    }

    #[test]
    fn dispatch_revalidation_rejects_navigation_dom_and_secret_drift() {
        let fixture = fixture();
        let (mut service, draft, approval) = approved_service(&fixture);
        let mut user_workspace = fixture.workspace.clone();
        takeover(&mut user_workspace, now());
        let lease = service
            .acquire_dispatch_lease(
                &fixture.profile,
                &user_workspace,
                &approval.approval_id,
                now() + Duration::seconds(3),
            )
            .expect("lease");
        let mut changed_frame = fixture.observation.clone();
        changed_frame.frame.navigation_revision += 1;
        changed_frame.frame.url_digest = sha('8');
        changed_frame.snapshot_digest = digest_json(&(
            &changed_frame.frame,
            &changed_frame.fields,
            &changed_frame.secret_classification_digest,
        ))
        .expect("changed digest");
        let mut host = FakeFormHost::new(fixture.observation.clone());
        host.revalidated = changed_frame;
        let error = service
            .revalidate_before_dispatch(
                &mut host,
                &fixture.profile,
                &user_workspace,
                &lease.lease_id,
                now() + Duration::seconds(4),
            )
            .expect_err("DOM drift");
        assert!(
            matches!(error, BrowserError::FormSnapshotStale),
            "{error:?}"
        );

        let (mut service, _draft, approval) = approved_service(&fixture);
        let lease = service
            .acquire_dispatch_lease(
                &fixture.profile,
                &user_workspace,
                &approval.approval_id,
                now() + Duration::seconds(3),
            )
            .expect("lease");
        let mut changed_dom = fixture.observation.clone();
        changed_dom.fields[0].field_revision += 1;
        changed_dom = BrowserFormObservation::new(changed_dom.frame.clone(), changed_dom.fields)
            .expect("changed dom");
        let mut host = FakeFormHost::new(fixture.observation.clone());
        host.revalidated = changed_dom;
        let error = service
            .revalidate_before_dispatch(
                &mut host,
                &fixture.profile,
                &user_workspace,
                &lease.lease_id,
                now() + Duration::seconds(4),
            )
            .expect_err("DOM drift");
        assert!(
            matches!(error, BrowserError::FormSnapshotStale),
            "{error:?}"
        );

        let (mut service, _draft, approval) = approved_service(&fixture);
        let lease = service
            .acquire_dispatch_lease(
                &fixture.profile,
                &user_workspace,
                &approval.approval_id,
                now() + Duration::seconds(3),
            )
            .expect("lease");
        let mut changed_secret = fixture.observation.clone();
        changed_secret.fields[2].secret_class = BrowserFormSecretClass::Unknown;
        changed_secret =
            BrowserFormObservation::new(changed_secret.frame.clone(), changed_secret.fields)
                .expect("changed secret");
        let mut host = FakeFormHost::new(fixture.observation.clone());
        host.revalidated = changed_secret;
        assert!(matches!(
            service.revalidate_before_dispatch(
                &mut host,
                &fixture.profile,
                &user_workspace,
                &lease.lease_id,
                now() + Duration::seconds(4),
            ),
            Err(BrowserError::FormSecretDrift)
        ));
        assert_eq!(draft.sequence, 1);
    }

    #[test]
    fn restart_crash_reopen_and_revoke_fail_closed() {
        let fixture = fixture();
        let (mut service, _draft, approval) = approved_service(&fixture);
        service.restart();
        assert_eq!(service.state(), BrowserFormServiceState::Restarted);
        let mut user_workspace = fixture.workspace.clone();
        takeover(&mut user_workspace, now());
        assert!(matches!(
            service.acquire_dispatch_lease(
                &fixture.profile,
                &user_workspace,
                &approval.approval_id,
                now() + Duration::seconds(3),
            ),
            Err(BrowserError::FormProviderRestarted)
        ));

        let (mut service, _draft, approval) = approved_service(&fixture);
        let mut revoked_profile = fixture.profile.clone();
        let revoked_revision = revoked_profile.revision;
        service
            .revoke(
                &mut revoked_profile,
                revoked_revision,
                sha('9'),
                now() + Duration::seconds(5),
            )
            .expect("revoke");
        assert_eq!(service.state(), BrowserFormServiceState::Revoked);
        assert!(matches!(
            service.acquire_dispatch_lease(
                &fixture.profile,
                &user_workspace,
                &approval.approval_id,
                now() + Duration::seconds(6),
            ),
            Err(BrowserError::FormProviderRevoked)
        ));

        let mut service = BrowserFormDraftService::mount(
            &fixture.profile,
            &fixture.workspace,
            BrowserTabId::from("tab-form"),
        )
        .expect("mount");
        let mut host = FakeFormHost::new(fixture.observation.clone());
        host.failure = Some(BrowserError::HostExited);
        let error = service
            .draft_form(
                &mut host,
                &fixture.profile,
                &fixture.workspace,
                &intents(),
                now(),
            )
            .expect_err("crash");
        assert!(matches!(error, BrowserError::HostExited));
        assert_eq!(service.state(), BrowserFormServiceState::Restarted);
    }

    #[test]
    fn unavailable_host_is_not_product_evidence() {
        let fixture = fixture();
        let mut service = BrowserFormDraftService::mount(
            &fixture.profile,
            &fixture.workspace,
            BrowserTabId::from("tab-form"),
        )
        .expect("mount");
        let mut host = UnavailableBrowserFormHost;
        let error = service
            .draft_form(
                &mut host,
                &fixture.profile,
                &fixture.workspace,
                &intents(),
                now(),
            )
            .expect_err("unavailable");
        assert!(matches!(error, BrowserError::ProtocolUnavailable));
        assert_eq!(service.draft_log().entries.len(), 0);
    }

    #[test]
    fn second_takeover_generation_cannot_reuse_draft_approval() {
        let fixture = fixture();
        let (mut service, draft) = approved_service_without_takeover(&fixture);
        let mut user_workspace = fixture.workspace.clone();
        takeover(&mut user_workspace, now());
        let approval = service
            .approve_draft(
                &fixture.profile,
                &user_workspace,
                &draft.draft_id,
                "approval-form",
                &sha('7'),
                now() + Duration::seconds(2),
            )
            .expect("approval");
        let mut second_user_workspace = user_workspace.clone();
        second_user_workspace
            .continue_agent(
                second_user_workspace.revision,
                second_user_workspace.lease_generation,
                BrowserControlLeaseId::from("lease-agent-2"),
                now() + Duration::hours(1),
                sha('c'),
                now() + Duration::seconds(3),
            )
            .expect("return to agent");
        second_user_workspace
            .user_takeover(
                second_user_workspace.revision,
                second_user_workspace.lease_generation,
                BrowserControlLeaseId::from("lease-user-2"),
                sha('d'),
                now() + Duration::seconds(4),
            )
            .expect("second takeover");
        assert!(matches!(
            service.acquire_dispatch_lease(
                &fixture.profile,
                &second_user_workspace,
                &approval.approval_id,
                now() + Duration::seconds(4),
            ),
            Err(BrowserError::FormApprovalMismatch)
        ));
    }
}
