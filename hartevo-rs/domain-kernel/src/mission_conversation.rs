use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    Mission, MissionCheckpointCompletionPolicy, MissionCheckpointExecutor, MissionCheckpointStatus,
    MissionConversationId, MissionConversationMessageId, MissionStage, ProjectId, TenantId,
    WorkProductId,
};

const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionConversationRole {
    User,
    Assistant,
    System,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionConversationMessageKind {
    Goal,
    Steering,
    Correction,
    Clarification,
    CheckpointConfirmation,
    RuntimeDraft,
    SystemNotice,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionConversationMessage {
    pub id: MissionConversationMessageId,
    pub sequence: u64,
    pub role: MissionConversationRole,
    pub kind: MissionConversationMessageKind,
    pub body: String,
    pub content_digest: String,
    pub idempotency_key: String,
    pub mission_revision: u64,
    pub checkpoint_id: Option<String>,
    pub work_product_id: Option<WorkProductId>,
    pub recorded_at: DateTime<Utc>,
}

impl MissionConversationMessage {
    fn validate_for(
        &self,
        mission: &Mission,
        expected_sequence: u64,
        previous_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), MissionConversationError> {
        let kind_matches_role = matches!(
            (self.role, self.kind),
            (
                MissionConversationRole::User,
                MissionConversationMessageKind::Goal
                    | MissionConversationMessageKind::Steering
                    | MissionConversationMessageKind::Correction
                    | MissionConversationMessageKind::Clarification
                    | MissionConversationMessageKind::CheckpointConfirmation
            ) | (
                MissionConversationRole::Assistant,
                MissionConversationMessageKind::RuntimeDraft
            ) | (
                MissionConversationRole::System,
                MissionConversationMessageKind::SystemNotice
            )
        );
        let work_product_matches = match (self.role, self.kind, &self.work_product_id) {
            (
                MissionConversationRole::Assistant,
                MissionConversationMessageKind::RuntimeDraft,
                Some(work_product_id),
            ) => mission
                .work_products
                .iter()
                .any(|work_product| &work_product.id == work_product_id),
            (MissionConversationRole::User | MissionConversationRole::System, _, None) => true,
            _ => false,
        };
        let checkpoint_matches = match (&self.checkpoint_id, &mission.definition) {
            (Some(checkpoint_id), Some(definition)) => definition
                .checkpoints
                .iter()
                .any(|checkpoint| &checkpoint.id == checkpoint_id),
            (None, None) => true,
            _ => false,
        };
        if self.id.as_str().trim().is_empty()
            || self.sequence != expected_sequence
            || !kind_matches_role
            || self.body.trim().is_empty()
            || self.body.len() > MAX_MESSAGE_BYTES
            || self.content_digest != digest(self.body.as_bytes())
            || self.idempotency_key.trim().is_empty()
            || self.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
            || self.mission_revision == 0
            || self.mission_revision > mission.revision
            || !checkpoint_matches
            || !work_product_matches
            || self.recorded_at < previous_at
            || self.recorded_at > now
        {
            return Err(MissionConversationError::InvalidMessage);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionConversation {
    pub id: MissionConversationId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: crate::MissionId,
    pub messages: Vec<MissionConversationMessage>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl MissionConversation {
    pub fn start(
        id: MissionConversationId,
        message_id: MissionConversationMessageId,
        mission: &Mission,
        goal: impl Into<String>,
        idempotency_key: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, MissionConversationError> {
        if mission.definition.is_none() || now < mission.created_at {
            return Err(MissionConversationError::MissionNotConversable);
        }
        let body = goal.into().trim().to_owned();
        let message = MissionConversationMessage {
            id: message_id,
            sequence: 1,
            role: MissionConversationRole::User,
            kind: MissionConversationMessageKind::Goal,
            content_digest: digest(body.as_bytes()),
            body,
            idempotency_key: idempotency_key.into().trim().to_owned(),
            mission_revision: mission.revision,
            checkpoint_id: current_checkpoint_id(mission),
            work_product_id: None,
            recorded_at: now,
        };
        let conversation = Self {
            id,
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            messages: vec![message],
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        conversation.validate_for(mission, now)?;
        Ok(conversation)
    }

    pub fn append_user_message(
        &mut self,
        id: MissionConversationMessageId,
        kind: MissionConversationMessageKind,
        body: impl Into<String>,
        idempotency_key: impl Into<String>,
        mission: &Mission,
        now: DateTime<Utc>,
    ) -> Result<(MissionConversationMessage, bool), MissionConversationError> {
        self.validate_for(mission, now)?;
        if !matches!(
            mission.stage,
            MissionStage::Running
                | MissionStage::Blocked
                | MissionStage::WaitingUser
                | MissionStage::WaitingApproval
                | MissionStage::Scheduled
                | MissionStage::CycleReviewed
        ) || !matches!(
            kind,
            MissionConversationMessageKind::Steering
                | MissionConversationMessageKind::Correction
                | MissionConversationMessageKind::Clarification
                | MissionConversationMessageKind::CheckpointConfirmation
        ) {
            return Err(MissionConversationError::MissionNotConversable);
        }
        if kind == MissionConversationMessageKind::CheckpointConfirmation
            && !mission.definition.as_ref().is_some_and(|definition| {
                definition.current_checkpoint().is_some_and(|checkpoint| {
                    checkpoint.route.as_ref().is_some_and(|route| {
                        route.executor == MissionCheckpointExecutor::Human
                            && route.completion_policy
                                == Some(MissionCheckpointCompletionPolicy::HumanConfirmation)
                    })
                })
            })
        {
            return Err(MissionConversationError::MissionNotConversable);
        }
        let body = body.into().trim().to_owned();
        let idempotency_key = idempotency_key.into().trim().to_owned();
        if let Some(existing) = self
            .messages
            .iter()
            .find(|message| message.idempotency_key == idempotency_key)
        {
            if existing.id == id
                && existing.role == MissionConversationRole::User
                && existing.kind == kind
                && existing.body == body
            {
                return Ok((existing.clone(), false));
            }
            return Err(MissionConversationError::IdempotencyConflict);
        }
        let sequence = self
            .revision
            .checked_add(1)
            .ok_or(MissionConversationError::RevisionOverflow)?;
        let message = MissionConversationMessage {
            id,
            sequence,
            role: MissionConversationRole::User,
            kind,
            content_digest: digest(body.as_bytes()),
            body,
            idempotency_key,
            mission_revision: mission.revision,
            checkpoint_id: current_checkpoint_id(mission),
            work_product_id: None,
            recorded_at: now,
        };
        message.validate_for(mission, sequence, self.updated_at, now)?;
        let previous = self.clone();
        self.messages.push(message.clone());
        self.revision = sequence;
        self.updated_at = now;
        if self.validate_for(mission, now).is_err() || !self.follows(&previous)? {
            *self = previous;
            return Err(MissionConversationError::InvalidConversation);
        }
        Ok((message, true))
    }

    pub fn append_runtime_draft(
        &mut self,
        id: MissionConversationMessageId,
        body: impl Into<String>,
        work_product_id: WorkProductId,
        idempotency_key: impl Into<String>,
        mission: &Mission,
        now: DateTime<Utc>,
    ) -> Result<(MissionConversationMessage, bool), MissionConversationError> {
        self.validate_for(mission, now)?;
        let body = body.into().trim().to_owned();
        let idempotency_key = idempotency_key.into().trim().to_owned();
        if let Some(existing) = self
            .messages
            .iter()
            .find(|message| message.idempotency_key == idempotency_key)
        {
            if existing.id == id
                && existing.kind == MissionConversationMessageKind::RuntimeDraft
                && existing.body == body
                && existing.work_product_id.as_ref() == Some(&work_product_id)
            {
                return Ok((existing.clone(), false));
            }
            return Err(MissionConversationError::IdempotencyConflict);
        }
        let sequence = self
            .revision
            .checked_add(1)
            .ok_or(MissionConversationError::RevisionOverflow)?;
        let message = MissionConversationMessage {
            id,
            sequence,
            role: MissionConversationRole::Assistant,
            kind: MissionConversationMessageKind::RuntimeDraft,
            content_digest: digest(body.as_bytes()),
            body,
            idempotency_key,
            mission_revision: mission.revision,
            checkpoint_id: current_checkpoint_id(mission),
            work_product_id: Some(work_product_id),
            recorded_at: now,
        };
        message.validate_for(mission, sequence, self.updated_at, now)?;
        let previous = self.clone();
        self.messages.push(message.clone());
        self.revision = sequence;
        self.updated_at = now;
        if self.validate_for(mission, now).is_err() || !self.follows(&previous)? {
            *self = previous;
            return Err(MissionConversationError::InvalidConversation);
        }
        Ok((message, true))
    }

    pub fn validate_for(
        &self,
        mission: &Mission,
        now: DateTime<Utc>,
    ) -> Result<(), MissionConversationError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id != mission.tenant_id
            || self.project_id != mission.project_id
            || self.mission_id != mission.id
            || self.messages.is_empty()
            || self.revision != u64::try_from(self.messages.len()).unwrap_or(u64::MAX)
            || self.created_at < mission.created_at
            || self.updated_at < self.created_at
            || self.updated_at > now
            || self.messages.first().is_none_or(|message| {
                message.role != MissionConversationRole::User
                    || message.kind != MissionConversationMessageKind::Goal
            })
        {
            return Err(MissionConversationError::InvalidConversation);
        }
        let mut message_ids = BTreeSet::new();
        let mut idempotency_keys = BTreeSet::new();
        let mut previous_at = self.created_at;
        for (index, message) in self.messages.iter().enumerate() {
            let sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(MissionConversationError::RevisionOverflow)?;
            message.validate_for(mission, sequence, previous_at, now)?;
            if !message_ids.insert(message.id.clone())
                || !idempotency_keys.insert(message.idempotency_key.clone())
            {
                return Err(MissionConversationError::InvalidConversation);
            }
            previous_at = message.recorded_at;
        }
        if self.updated_at != previous_at {
            return Err(MissionConversationError::InvalidConversation);
        }
        Ok(())
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, MissionConversationError> {
        Ok(self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.mission_id == previous.mission_id
            && self.created_at == previous.created_at
            && previous.revision.checked_add(1) == Some(self.revision)
            && self.messages.len() == previous.messages.len() + 1
            && self.messages.starts_with(&previous.messages)
            && self.updated_at >= previous.updated_at)
    }
}

fn current_checkpoint_id(mission: &Mission) -> Option<String> {
    mission.definition.as_ref().and_then(|definition| {
        definition
            .current_checkpoint()
            .filter(|checkpoint| {
                checkpoint.status != MissionCheckpointStatus::Skipped
                    && checkpoint.status != MissionCheckpointStatus::Completed
            })
            .map(|checkpoint| checkpoint.id.clone())
    })
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionConversationError {
    #[error("Mission Conversation aggregate is invalid")]
    InvalidConversation,
    #[error("Mission Conversation message is invalid")]
    InvalidMessage,
    #[error("Mission is not accepting internal Conversation steering")]
    MissionNotConversable,
    #[error("Mission Conversation idempotency key was reused for different content")]
    IdempotencyConflict,
    #[error("Mission Conversation revision overflow")]
    RevisionOverflow,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use crate::{
        CurrencyCode, MissionDefinition, MissionId, Money, OperatingContract, OperatingMode, Task,
        TaskId, TaskStatus,
    };

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 12, 10, 0, 0)
            .single()
            .expect("valid time")
    }

    fn mission() -> Mission {
        let mut contract =
            OperatingContract::bootstrap("Decide the market", ["research.discover".into()], now());
        contract.mode = OperatingMode::OneOffDecision;
        contract.market = "DE".into();
        contract.language = "de-DE".into();
        contract.audience = "owner".into();
        contract.budget = Money::new(0, CurrencyCode::parse("EUR").expect("EUR"));
        contract
            .forbidden_capabilities
            .insert("payment.execute".into());
        let definition = MissionDefinition::from_linear_manifest(
            "VM-07",
            1,
            "a".repeat(64),
            OperatingMode::OneOffDecision,
            ["research.discover".into()],
            ["market_decision".into()],
            ["goal".into(), "decision".into()],
            ["scope".into(), "decision".into()],
        )
        .expect("definition");
        let mut mission = Mission::compile_catalog(
            TenantId::from("tenant"),
            MissionId::from("mission"),
            ProjectId::from("project"),
            "Market decision",
            contract,
            definition,
            now(),
        )
        .expect("Mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task"),
                    title: "Scope".into(),
                    status: TaskStatus::Running,
                    capability: "research.discover".into(),
                }],
                now(),
            )
            .expect("start");
        mission
    }

    #[test]
    fn user_steering_is_append_only_idempotent_and_does_not_expand_mission_authority() {
        let mission = mission();
        let authority = mission.contract.enabled_capabilities.clone();
        let mut conversation = MissionConversation::start(
            MissionConversationId::from("conversation"),
            MissionConversationMessageId::from("message-goal"),
            &mission,
            mission.contract.goal.clone(),
            "start:mission",
            now(),
        )
        .expect("Conversation");
        let (message, appended) = conversation
            .append_user_message(
                MissionConversationMessageId::from("message-steer"),
                MissionConversationMessageKind::Steering,
                "Only keep German evidence",
                "steer:1",
                &mission,
                now() + chrono::Duration::minutes(1),
            )
            .expect("steering");
        assert!(appended);
        assert_eq!(message.sequence, 2);
        assert_eq!(conversation.revision, 2);
        let replay = conversation.clone();
        let (_, appended) = conversation
            .append_user_message(
                MissionConversationMessageId::from("message-steer"),
                MissionConversationMessageKind::Steering,
                "Only keep German evidence",
                "steer:1",
                &mission,
                now() + chrono::Duration::minutes(2),
            )
            .expect("idempotent replay");
        assert!(!appended);
        assert_eq!(conversation, replay);
        assert_eq!(mission.contract.enabled_capabilities, authority);
        assert!(matches!(
            conversation.append_user_message(
                MissionConversationMessageId::from("message-swap"),
                MissionConversationMessageKind::Steering,
                "Expand to payments",
                "steer:1",
                &mission,
                now() + chrono::Duration::minutes(3),
            ),
            Err(MissionConversationError::IdempotencyConflict)
        ));
    }

    #[test]
    fn checkpoint_confirmation_cannot_be_appended_to_an_uncontracted_or_non_human_route() {
        let mission = mission();
        let mut conversation = MissionConversation::start(
            MissionConversationId::from("conversation-confirmation-boundary"),
            MissionConversationMessageId::from("message-confirmation-goal"),
            &mission,
            mission.contract.goal.clone(),
            "start:confirmation-boundary",
            now(),
        )
        .expect("Conversation");
        let before = conversation.clone();
        assert_eq!(
            conversation.append_user_message(
                MissionConversationMessageId::from("message-forged-confirmation"),
                MissionConversationMessageKind::CheckpointConfirmation,
                "Confirm an unbound route",
                "confirm:unbound",
                &mission,
                now() + chrono::Duration::minutes(1),
            ),
            Err(MissionConversationError::MissionNotConversable)
        );
        assert_eq!(conversation, before);
    }
}
