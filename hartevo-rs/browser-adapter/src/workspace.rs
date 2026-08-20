use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{
    AccountId, BrowserActionBatchId, BrowserControlLeaseId, BrowserProfileId, BrowserTabId,
    BrowserWorkspaceId, Mission, Project, ProjectId, TenantId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{BrowserActionBatch, BrowserBatchReceipt, BrowserError};

const BROWSER_SCHEMA_VERSION: u32 = 1;
const MAX_CONTROL_HISTORY: usize = 4_096;
const MAX_AGENT_LEASE: Duration = Duration::hours(4);
const MAX_TABS: usize = 128;
const MAX_BATCH_RECEIPTS: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserProfileSource {
    Managed,
    ImportedCopy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserProfileStatus {
    Active,
    Revoked,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserIdentity {
    pub provider: String,
    pub account_id: AccountId,
    pub identity_digest: String,
    pub probe_digest: String,
    pub observed_at: DateTime<Utc>,
}

impl BrowserIdentity {
    pub fn new(
        provider: impl Into<String>,
        account_id: AccountId,
        identity_digest: impl Into<String>,
        probe_digest: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let identity = Self {
            provider: provider.into(),
            account_id,
            identity_digest: identity_digest.into(),
            probe_digest: probe_digest.into(),
            observed_at,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        if !is_bounded_identifier(&self.provider)
            || !is_bounded_identifier(self.account_id.as_str())
            || !is_sha256(&self.identity_digest)
            || !is_sha256(&self.probe_digest)
        {
            return Err(BrowserError::InvalidIdentity);
        }
        Ok(())
    }
}

impl fmt::Debug for BrowserIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserIdentity")
            .field("provider_digest", &digest(self.provider.as_bytes()))
            .field(
                "account_id_digest",
                &digest(self.account_id.as_str().as_bytes()),
            )
            .field("identity_digest", &self.identity_digest)
            .field("probe_digest", &self.probe_digest)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserProfile {
    pub schema_version: u32,
    pub id: BrowserProfileId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub source: BrowserProfileSource,
    pub credential_reference: String,
    pub identity: BrowserIdentity,
    pub status: BrowserProfileStatus,
    pub revocation_evidence_digest: Option<String>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl BrowserProfile {
    pub fn create_managed(
        id: BrowserProfileId,
        project: &Project,
        credential_reference: impl Into<String>,
        identity: BrowserIdentity,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let profile = Self {
            schema_version: BROWSER_SCHEMA_VERSION,
            id,
            tenant_id: project.tenant_id.clone(),
            project_id: project.id.clone(),
            source: BrowserProfileSource::Managed,
            credential_reference: credential_reference.into(),
            identity,
            status: BrowserProfileStatus::Active,
            revocation_evidence_digest: None,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn revoke(
        &mut self,
        expected_revision: u64,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.revision != expected_revision {
            return Err(BrowserError::RevisionMismatch {
                expected: expected_revision,
                actual: self.revision,
            });
        }
        if self.status != BrowserProfileStatus::Active
            || !is_sha256(&evidence_digest)
            || now < self.updated_at
        {
            return Err(BrowserError::InvalidProfileTransition);
        }
        self.status = BrowserProfileStatus::Revoked;
        self.revocation_evidence_digest = Some(evidence_digest);
        self.revision = next_revision(self.revision)?;
        self.updated_at = now;
        self.validate()
    }

    pub fn validate(&self) -> Result<(), BrowserError> {
        self.identity.validate()?;
        let revocation_shape = match self.status {
            BrowserProfileStatus::Active => self.revocation_evidence_digest.is_none(),
            BrowserProfileStatus::Revoked => self
                .revocation_evidence_digest
                .as_deref()
                .is_some_and(is_sha256),
        };
        if self.schema_version != BROWSER_SCHEMA_VERSION
            || !is_bounded_identifier(self.id.as_str())
            || !is_bounded_identifier(self.tenant_id.as_str())
            || !is_bounded_identifier(self.project_id.as_str())
            || !is_opaque_reference(&self.credential_reference)
            || self.revision == 0
            || self.updated_at < self.created_at
            || !revocation_shape
        {
            return Err(BrowserError::InvalidProfile);
        }
        Ok(())
    }

    pub fn is_valid_successor_of(&self, previous: &Self) -> Result<bool, BrowserError> {
        self.validate()?;
        previous.validate()?;
        Ok(self.schema_version == previous.schema_version
            && self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.source == previous.source
            && self.credential_reference == previous.credential_reference
            && self.identity == previous.identity
            && previous.status == BrowserProfileStatus::Active
            && self.status == BrowserProfileStatus::Revoked
            && self.revision == previous.revision.saturating_add(1)
            && self.created_at == previous.created_at
            && self.updated_at >= previous.updated_at)
    }

    pub fn digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }
}

impl fmt::Debug for BrowserProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserProfile")
            .field("schema_version", &self.schema_version)
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("source", &self.source)
            .field(
                "credential_reference_digest",
                &digest(self.credential_reference.as_bytes()),
            )
            .field("identity", &self.identity)
            .field("status", &self.status)
            .field(
                "revocation_evidence_digest",
                &self.revocation_evidence_digest,
            )
            .field("revision", &self.revision)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserControlState {
    AgentControlled,
    UserControlled,
    PausedAgent,
    PausedUser,
    Completed,
    KeptForUser,
    Closed,
}

impl BrowserControlState {
    pub fn permits_agent_actions(self) -> bool {
        self == Self::AgentControlled
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::KeptForUser | Self::Closed)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserControlTransition {
    pub generation: u64,
    pub lease_id: BrowserControlLeaseId,
    pub state: BrowserControlState,
    pub evidence_digest: String,
    pub agent_lease_expires_at: Option<DateTime<Utc>>,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserLeaseProof {
    pub workspace_id: BrowserWorkspaceId,
    pub lease_id: BrowserControlLeaseId,
    pub generation: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserWorkspace {
    pub schema_version: u32,
    pub id: BrowserWorkspaceId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: hartevo_domain_kernel::MissionId,
    pub profile_id: BrowserProfileId,
    pub expected_identity_digest: String,
    pub control_state: BrowserControlState,
    pub lease_id: BrowserControlLeaseId,
    pub lease_generation: u64,
    pub agent_lease_expires_at: Option<DateTime<Utc>>,
    pub tabs: BTreeSet<BrowserTabId>,
    pub active_tab_id: BrowserTabId,
    pub control_history: Vec<BrowserControlTransition>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub batch_receipts: BTreeMap<BrowserActionBatchId, BrowserBatchReceipt>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl BrowserWorkspace {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        id: BrowserWorkspaceId,
        project: &Project,
        mission: &Mission,
        profile: &BrowserProfile,
        initial_tab_id: BrowserTabId,
        lease_id: BrowserControlLeaseId,
        lease_expires_at: DateTime<Utc>,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        if mission.tenant_id != project.tenant_id
            || mission.project_id != project.id
            || profile.tenant_id != project.tenant_id
            || profile.project_id != project.id
            || profile.status != BrowserProfileStatus::Active
            || lease_expires_at <= now
            || lease_expires_at - now > MAX_AGENT_LEASE
        {
            return Err(BrowserError::ScopeMismatch);
        }
        let transition = BrowserControlTransition {
            generation: 1,
            lease_id: lease_id.clone(),
            state: BrowserControlState::AgentControlled,
            evidence_digest,
            agent_lease_expires_at: Some(lease_expires_at),
            occurred_at: now,
        };
        let workspace = Self {
            schema_version: BROWSER_SCHEMA_VERSION,
            id,
            tenant_id: project.tenant_id.clone(),
            project_id: project.id.clone(),
            mission_id: mission.id.clone(),
            profile_id: profile.id.clone(),
            expected_identity_digest: profile.identity.identity_digest.clone(),
            control_state: transition.state,
            lease_id,
            lease_generation: 1,
            agent_lease_expires_at: Some(lease_expires_at),
            tabs: BTreeSet::from([initial_tab_id.clone()]),
            active_tab_id: initial_tab_id,
            control_history: vec![transition],
            batch_receipts: BTreeMap::new(),
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        workspace.validate()?;
        Ok(workspace)
    }

    pub fn agent_lease_proof(&self, now: DateTime<Utc>) -> Result<BrowserLeaseProof, BrowserError> {
        self.validate_agent_lease(
            &BrowserLeaseProof {
                workspace_id: self.id.clone(),
                lease_id: self.lease_id.clone(),
                generation: self.lease_generation,
            },
            now,
        )?;
        Ok(BrowserLeaseProof {
            workspace_id: self.id.clone(),
            lease_id: self.lease_id.clone(),
            generation: self.lease_generation,
        })
    }

    pub fn validate_agent_lease(
        &self,
        proof: &BrowserLeaseProof,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.validate()?;
        if self.control_state != BrowserControlState::AgentControlled
            || proof.workspace_id != self.id
            || proof.lease_id != self.lease_id
            || proof.generation != self.lease_generation
            || self
                .agent_lease_expires_at
                .is_none_or(|expires_at| now >= expires_at)
        {
            return Err(BrowserError::ControlLeaseLost);
        }
        Ok(())
    }

    pub fn user_takeover(
        &mut self,
        expected_revision: u64,
        expected_generation: u64,
        new_lease_id: BrowserControlLeaseId,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.control_state != BrowserControlState::AgentControlled {
            return Err(BrowserError::InvalidControlTransition);
        }
        self.push_control_transition(
            expected_revision,
            expected_generation,
            new_lease_id,
            BrowserControlState::UserControlled,
            None,
            evidence_digest,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn continue_agent(
        &mut self,
        expected_revision: u64,
        expected_generation: u64,
        new_lease_id: BrowserControlLeaseId,
        lease_expires_at: DateTime<Utc>,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.control_state != BrowserControlState::UserControlled
            || lease_expires_at <= now
            || lease_expires_at - now > MAX_AGENT_LEASE
        {
            return Err(BrowserError::InvalidControlTransition);
        }
        self.push_control_transition(
            expected_revision,
            expected_generation,
            new_lease_id,
            BrowserControlState::AgentControlled,
            Some(lease_expires_at),
            evidence_digest,
            now,
        )
    }

    pub fn pause(
        &mut self,
        expected_revision: u64,
        expected_generation: u64,
        new_lease_id: BrowserControlLeaseId,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        let state = match self.control_state {
            BrowserControlState::AgentControlled => BrowserControlState::PausedAgent,
            BrowserControlState::UserControlled => BrowserControlState::PausedUser,
            _ => return Err(BrowserError::InvalidControlTransition),
        };
        self.push_control_transition(
            expected_revision,
            expected_generation,
            new_lease_id,
            state,
            None,
            evidence_digest,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resume(
        &mut self,
        expected_revision: u64,
        expected_generation: u64,
        new_lease_id: BrowserControlLeaseId,
        agent_lease_expires_at: Option<DateTime<Utc>>,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        let state = match self.control_state {
            BrowserControlState::PausedAgent => {
                let expires_at = agent_lease_expires_at
                    .filter(|expires_at| *expires_at > now && *expires_at - now <= MAX_AGENT_LEASE)
                    .ok_or(BrowserError::InvalidControlTransition)?;
                return self.push_control_transition(
                    expected_revision,
                    expected_generation,
                    new_lease_id,
                    BrowserControlState::AgentControlled,
                    Some(expires_at),
                    evidence_digest,
                    now,
                );
            }
            BrowserControlState::PausedUser if agent_lease_expires_at.is_none() => {
                BrowserControlState::UserControlled
            }
            _ => return Err(BrowserError::InvalidControlTransition),
        };
        self.push_control_transition(
            expected_revision,
            expected_generation,
            new_lease_id,
            state,
            None,
            evidence_digest,
            now,
        )
    }

    pub fn complete(
        &mut self,
        expected_revision: u64,
        expected_generation: u64,
        new_lease_id: BrowserControlLeaseId,
        verification_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if !matches!(
            self.control_state,
            BrowserControlState::AgentControlled | BrowserControlState::UserControlled
        ) {
            return Err(BrowserError::InvalidControlTransition);
        }
        self.push_control_transition(
            expected_revision,
            expected_generation,
            new_lease_id,
            BrowserControlState::Completed,
            None,
            verification_digest,
            now,
        )
    }

    pub fn keep_for_user(
        &mut self,
        expected_revision: u64,
        expected_generation: u64,
        new_lease_id: BrowserControlLeaseId,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.control_state != BrowserControlState::Completed {
            return Err(BrowserError::InvalidControlTransition);
        }
        self.push_control_transition(
            expected_revision,
            expected_generation,
            new_lease_id,
            BrowserControlState::KeptForUser,
            None,
            evidence_digest,
            now,
        )
    }

    pub fn close(
        &mut self,
        expected_revision: u64,
        expected_generation: u64,
        new_lease_id: BrowserControlLeaseId,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if !matches!(
            self.control_state,
            BrowserControlState::Completed | BrowserControlState::KeptForUser
        ) {
            return Err(BrowserError::InvalidControlTransition);
        }
        self.push_control_transition(
            expected_revision,
            expected_generation,
            new_lease_id,
            BrowserControlState::Closed,
            None,
            evidence_digest,
            now,
        )
    }

    pub fn add_tab(
        &mut self,
        expected_revision: u64,
        expected_generation: u64,
        tab_id: BrowserTabId,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.require_live_control(expected_revision, expected_generation, now)?;
        if self.tabs.len() >= MAX_TABS
            || !is_bounded_identifier(tab_id.as_str())
            || !self.tabs.insert(tab_id.clone())
        {
            return Err(BrowserError::InvalidTabTransition);
        }
        self.active_tab_id = tab_id;
        self.revision = next_revision(self.revision)?;
        self.updated_at = now;
        self.validate()
    }

    pub fn set_active_tab(
        &mut self,
        expected_revision: u64,
        expected_generation: u64,
        tab_id: BrowserTabId,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.require_live_control(expected_revision, expected_generation, now)?;
        if !self.tabs.contains(&tab_id) || tab_id == self.active_tab_id {
            return Err(BrowserError::InvalidTabTransition);
        }
        self.active_tab_id = tab_id;
        self.revision = next_revision(self.revision)?;
        self.updated_at = now;
        self.validate()
    }

    pub fn batch_receipt(&self, batch_id: &BrowserActionBatchId) -> Option<&BrowserBatchReceipt> {
        self.batch_receipts.get(batch_id)
    }

    pub fn acknowledge_batch_receipt(
        &mut self,
        expected_revision: u64,
        batch: &BrowserActionBatch,
        receipt: BrowserBatchReceipt,
        now: DateTime<Utc>,
    ) -> Result<bool, BrowserError> {
        if self.revision != expected_revision {
            return Err(BrowserError::RevisionMismatch {
                expected: expected_revision,
                actual: self.revision,
            });
        }
        receipt.validate_for(batch)?;
        if batch.workspace_id != self.id
            || batch.tenant_id != self.tenant_id
            || batch.project_id != self.project_id
            || batch.mission_id != self.mission_id
            || now < self.updated_at
        {
            return Err(BrowserError::InvalidBatchReceipt);
        }
        match self.batch_receipts.get(&batch.id) {
            Some(previous) if previous == &receipt => return Ok(false),
            Some(previous) if !receipt.is_valid_successor_of(previous, batch)? => {
                return Err(BrowserError::InvalidBatchReceipt);
            }
            None if self.batch_receipts.len() >= MAX_BATCH_RECEIPTS => {
                return Err(BrowserError::InvalidBatchReceipt);
            }
            _ => {}
        }
        self.batch_receipts.insert(batch.id.clone(), receipt);
        self.revision = next_revision(self.revision)?;
        self.updated_at = now;
        self.validate()?;
        Ok(true)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "workspace validation reconstructs the complete control-generation history and current lease shape"
    )]
    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != BROWSER_SCHEMA_VERSION
            || !is_bounded_identifier(self.id.as_str())
            || !is_bounded_identifier(self.tenant_id.as_str())
            || !is_bounded_identifier(self.project_id.as_str())
            || !is_bounded_identifier(self.mission_id.as_str())
            || !is_bounded_identifier(self.profile_id.as_str())
            || !is_sha256(&self.expected_identity_digest)
            || !is_bounded_identifier(self.lease_id.as_str())
            || self.lease_generation == 0
            || self.revision < self.lease_generation
            || self.tabs.is_empty()
            || self.tabs.len() > MAX_TABS
            || self
                .tabs
                .iter()
                .any(|tab_id| !is_bounded_identifier(tab_id.as_str()))
            || !self.tabs.contains(&self.active_tab_id)
            || self.control_history.is_empty()
            || self.control_history.len() > MAX_CONTROL_HISTORY
            || self.batch_receipts.len() > MAX_BATCH_RECEIPTS
            || u64::try_from(self.control_history.len()).ok() != Some(self.lease_generation)
            || self.updated_at < self.created_at
        {
            return Err(BrowserError::InvalidWorkspace);
        }
        for (batch_id, receipt) in &self.batch_receipts {
            receipt.validate_scope()?;
            if *batch_id != receipt.batch_id
                || receipt.tenant_id != self.tenant_id
                || receipt.project_id != self.project_id
                || receipt.mission_id != self.mission_id
                || receipt.workspace_id != self.id
            {
                return Err(BrowserError::InvalidWorkspace);
            }
        }
        let mut previous: Option<&BrowserControlTransition> = None;
        let mut lease_ids = BTreeSet::new();
        for (index, transition) in self.control_history.iter().enumerate() {
            let expected_generation = u64::try_from(index)
                .map_err(|_| BrowserError::CounterOverflow)?
                .checked_add(1)
                .ok_or(BrowserError::CounterOverflow)?;
            let valid_expiry = match transition.state {
                BrowserControlState::AgentControlled => {
                    transition.agent_lease_expires_at.is_some_and(|expires_at| {
                        expires_at > transition.occurred_at
                            && expires_at - transition.occurred_at <= MAX_AGENT_LEASE
                    })
                }
                _ => transition.agent_lease_expires_at.is_none(),
            };
            if transition.generation != expected_generation
                || !is_bounded_identifier(transition.lease_id.as_str())
                || !lease_ids.insert(transition.lease_id.clone())
                || !is_sha256(&transition.evidence_digest)
                || !valid_expiry
                || previous.is_none() && transition.state != BrowserControlState::AgentControlled
                || previous.is_some_and(|prior| {
                    transition.occurred_at < prior.occurred_at
                        || !valid_control_edge(prior.state, transition.state)
                })
            {
                return Err(BrowserError::InvalidWorkspace);
            }
            previous = Some(transition);
        }
        let Some(latest) = self.control_history.last() else {
            return Err(BrowserError::InvalidWorkspace);
        };
        if latest.generation != self.lease_generation
            || latest.lease_id != self.lease_id
            || latest.state != self.control_state
            || latest.agent_lease_expires_at != self.agent_lease_expires_at
            || latest.occurred_at > self.updated_at
        {
            return Err(BrowserError::InvalidWorkspace);
        }
        Ok(())
    }

    pub fn is_valid_successor_of(&self, previous: &Self) -> Result<bool, BrowserError> {
        self.validate()?;
        previous.validate()?;
        let immutable_scope = self.schema_version == previous.schema_version
            && self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.mission_id == previous.mission_id
            && self.profile_id == previous.profile_id
            && self.expected_identity_digest == previous.expected_identity_digest
            && self.created_at == previous.created_at;
        let exact_revision = self.revision == previous.revision.saturating_add(1)
            && self.updated_at >= previous.updated_at;
        let control_change = self.control_history.len() == previous.control_history.len() + 1
            && self.control_history.starts_with(&previous.control_history)
            && self.lease_generation == previous.lease_generation.saturating_add(1)
            && self.tabs == previous.tabs
            && self.active_tab_id == previous.active_tab_id
            && self.batch_receipts == previous.batch_receipts;
        let tab_change = self.control_history == previous.control_history
            && self.control_state == previous.control_state
            && self.lease_id == previous.lease_id
            && self.lease_generation == previous.lease_generation
            && self.agent_lease_expires_at == previous.agent_lease_expires_at
            && self.batch_receipts == previous.batch_receipts
            && (self.tabs != previous.tabs || self.active_tab_id != previous.active_tab_id);
        let batch_receipt_change = self.control_history == previous.control_history
            && self.control_state == previous.control_state
            && self.lease_id == previous.lease_id
            && self.lease_generation == previous.lease_generation
            && self.agent_lease_expires_at == previous.agent_lease_expires_at
            && self.tabs == previous.tabs
            && self.active_tab_id == previous.active_tab_id
            && batch_receipts_follow(&self.batch_receipts, &previous.batch_receipts)?;
        Ok(immutable_scope
            && exact_revision
            && (control_change || tab_change || batch_receipt_change))
    }

    pub fn digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }

    fn require_live_control(
        &self,
        expected_revision: u64,
        expected_generation: u64,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.revision != expected_revision {
            return Err(BrowserError::RevisionMismatch {
                expected: expected_revision,
                actual: self.revision,
            });
        }
        if self.lease_generation != expected_generation
            || self.control_state.is_terminal()
            || matches!(
                self.control_state,
                BrowserControlState::PausedAgent | BrowserControlState::PausedUser
            )
            || now < self.updated_at
        {
            return Err(BrowserError::ControlLeaseLost);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn push_control_transition(
        &mut self,
        expected_revision: u64,
        expected_generation: u64,
        new_lease_id: BrowserControlLeaseId,
        state: BrowserControlState,
        agent_lease_expires_at: Option<DateTime<Utc>>,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        if self.revision != expected_revision {
            return Err(BrowserError::RevisionMismatch {
                expected: expected_revision,
                actual: self.revision,
            });
        }
        if self.lease_generation != expected_generation
            || !valid_control_edge(self.control_state, state)
            || !is_bounded_identifier(new_lease_id.as_str())
            || self
                .control_history
                .iter()
                .any(|transition| transition.lease_id == new_lease_id)
            || !is_sha256(&evidence_digest)
            || now < self.updated_at
        {
            return Err(BrowserError::InvalidControlTransition);
        }
        let generation = self
            .lease_generation
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        self.control_state = state;
        self.lease_id = new_lease_id.clone();
        self.lease_generation = generation;
        self.agent_lease_expires_at = agent_lease_expires_at;
        self.control_history.push(BrowserControlTransition {
            generation,
            lease_id: new_lease_id,
            state,
            evidence_digest,
            agent_lease_expires_at,
            occurred_at: now,
        });
        self.revision = next_revision(self.revision)?;
        self.updated_at = now;
        self.validate()
    }
}

impl fmt::Debug for BrowserWorkspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserWorkspace")
            .field("schema_version", &self.schema_version)
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("profile_id", &self.profile_id)
            .field("expected_identity_digest", &self.expected_identity_digest)
            .field("control_state", &self.control_state)
            .field(
                "lease_id_digest",
                &digest(self.lease_id.as_str().as_bytes()),
            )
            .field("lease_generation", &self.lease_generation)
            .field("agent_lease_expires_at", &self.agent_lease_expires_at)
            .field("tab_count", &self.tabs.len())
            .field(
                "active_tab_id_digest",
                &digest(self.active_tab_id.as_str().as_bytes()),
            )
            .field("control_history_count", &self.control_history.len())
            .field("batch_receipt_count", &self.batch_receipts.len())
            .field("revision", &self.revision)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

fn batch_receipts_follow(
    current: &BTreeMap<BrowserActionBatchId, BrowserBatchReceipt>,
    previous: &BTreeMap<BrowserActionBatchId, BrowserBatchReceipt>,
) -> Result<bool, BrowserError> {
    if current.len() < previous.len() || current.len() > previous.len().saturating_add(1) {
        return Ok(false);
    }
    let mut changes = 0_usize;
    for (batch_id, prior) in previous {
        let Some(next) = current.get(batch_id) else {
            return Ok(false);
        };
        if next != prior {
            if !next.follows_acknowledgement(prior)? {
                return Ok(false);
            }
            changes = changes
                .checked_add(1)
                .ok_or(BrowserError::CounterOverflow)?;
        }
    }
    changes = changes
        .checked_add(
            current
                .keys()
                .filter(|batch_id| !previous.contains_key(*batch_id))
                .count(),
        )
        .ok_or(BrowserError::CounterOverflow)?;
    Ok(changes == 1)
}

fn valid_control_edge(from: BrowserControlState, to: BrowserControlState) -> bool {
    matches!(
        (from, to),
        (
            BrowserControlState::AgentControlled,
            BrowserControlState::UserControlled
                | BrowserControlState::PausedAgent
                | BrowserControlState::Completed
        ) | (
            BrowserControlState::UserControlled,
            BrowserControlState::AgentControlled
                | BrowserControlState::PausedUser
                | BrowserControlState::Completed
        ) | (
            BrowserControlState::PausedAgent,
            BrowserControlState::AgentControlled
        ) | (
            BrowserControlState::PausedUser,
            BrowserControlState::UserControlled
        ) | (
            BrowserControlState::Completed,
            BrowserControlState::KeptForUser | BrowserControlState::Closed
        ) | (
            BrowserControlState::KeptForUser,
            BrowserControlState::Closed
        )
    )
}

fn next_revision(value: u64) -> Result<u64, BrowserError> {
    value.checked_add(1).ok_or(BrowserError::CounterOverflow)
}

pub(crate) fn is_bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_024
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn is_opaque_reference(value: &str) -> bool {
    is_bounded_identifier(value)
        && value.len() <= 2_048
        && !value.contains("token=")
        && !value.contains("password=")
        && !value.contains("cookie=")
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn digest_json(value: &impl Serialize) -> Result<String, BrowserError> {
    Ok(digest(&serde_json::to_vec(value)?))
}

pub(crate) fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_domain_kernel::{MissionContract, MissionId, StorageMode};

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 8, 0, 0)
            .single()
            .expect("fixture time")
    }

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn fixture() -> (BrowserProfile, BrowserWorkspace) {
        let now = now();
        let project = Project::create_local(
            TenantId::from("tenant-browser"),
            ProjectId::from("project-browser"),
            "Browser",
            "",
            "/workspace/browser",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-browser"),
            project.id.clone(),
            "Browser mission",
            MissionContract::bootstrap("Browser safety", ["browser.read".into()], now),
            now,
        )
        .expect("mission");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-browser"),
            &project,
            "credential-manager://profile-browser",
            BrowserIdentity::new(
                "provider-browser",
                AccountId::from("account-browser"),
                sha('1'),
                sha('2'),
                now,
            )
            .expect("identity"),
            now,
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-browser"),
            &project,
            &mission,
            &profile,
            BrowserTabId::from("tab-browser"),
            BrowserControlLeaseId::from("lease-browser-1"),
            now + Duration::hours(1),
            sha('3'),
            now,
        )
        .expect("workspace");
        (profile, workspace)
    }

    #[test]
    fn stale_cas_revision_is_rejected_without_partial_mutation() {
        let (_, mut workspace) = fixture();
        let before = workspace.clone();

        let error = workspace
            .user_takeover(
                99,
                workspace.lease_generation,
                BrowserControlLeaseId::from("lease-browser-2"),
                sha('4'),
                now() + Duration::seconds(1),
            )
            .expect_err("stale revision");

        assert!(matches!(
            error,
            BrowserError::RevisionMismatch {
                expected: 99,
                actual: 1
            }
        ));
        assert_eq!(workspace, before);
    }

    #[test]
    fn successor_requires_exact_append_only_control_history() {
        let (_, mut workspace) = fixture();
        let previous = workspace.clone();
        workspace
            .user_takeover(
                1,
                1,
                BrowserControlLeaseId::from("lease-browser-2"),
                sha('4'),
                now() + Duration::seconds(1),
            )
            .expect("takeover");
        assert!(
            workspace
                .is_valid_successor_of(&previous)
                .expect("valid successor")
        );

        let mut tampered = workspace.clone();
        tampered.control_history[0].evidence_digest = sha('9');
        assert!(
            !tampered
                .is_valid_successor_of(&previous)
                .expect("well-shaped but rewritten history is not a successor")
        );

        let mut malformed = workspace;
        malformed.control_history[1].generation = 7;
        assert_eq!(
            malformed
                .validate()
                .expect_err("generation gap invalidates workspace")
                .code(),
            "BROWSER_INVALID_WORKSPACE"
        );
    }

    #[test]
    fn lease_ids_cannot_be_reused_across_handoff_generations() {
        let (_, mut workspace) = fixture();
        workspace
            .user_takeover(
                1,
                1,
                BrowserControlLeaseId::from("lease-browser-2"),
                sha('4'),
                now() + Duration::seconds(1),
            )
            .expect("takeover");

        assert_eq!(
            workspace
                .continue_agent(
                    2,
                    2,
                    BrowserControlLeaseId::from("lease-browser-1"),
                    now() + Duration::hours(1),
                    sha('5'),
                    now() + Duration::seconds(2),
                )
                .expect_err("old lease id must never be recycled")
                .code(),
            "BROWSER_INVALID_CONTROL_TRANSITION"
        );
    }

    #[test]
    fn terminal_workspace_cannot_resume_or_accept_tab_mutation() {
        let (_, mut workspace) = fixture();
        workspace
            .complete(
                1,
                1,
                BrowserControlLeaseId::from("lease-browser-2"),
                sha('4'),
                now() + Duration::seconds(1),
            )
            .expect("complete");
        assert_eq!(workspace.control_state, BrowserControlState::Completed);
        assert_eq!(
            workspace
                .add_tab(
                    2,
                    2,
                    BrowserTabId::from("tab-after-complete"),
                    now() + Duration::seconds(2),
                )
                .expect_err("terminal state rejects tab work")
                .code(),
            "BROWSER_CONTROL_LEASE_LOST"
        );
        assert_eq!(
            workspace
                .resume(
                    2,
                    2,
                    BrowserControlLeaseId::from("lease-browser-3"),
                    Some(now() + Duration::hours(1)),
                    sha('5'),
                    now() + Duration::seconds(2),
                )
                .expect_err("completed workspace never resumes")
                .code(),
            "BROWSER_INVALID_CONTROL_TRANSITION"
        );
    }

    #[test]
    fn profile_revocation_is_one_way_and_exactly_revisioned() {
        let (mut profile, _) = fixture();
        let previous = profile.clone();
        profile
            .revoke(1, sha('4'), now() + Duration::seconds(1))
            .expect("revoke");
        assert!(
            profile
                .is_valid_successor_of(&previous)
                .expect("revocation successor")
        );
        assert_eq!(profile.status, BrowserProfileStatus::Revoked);
        assert_eq!(
            profile
                .revoke(2, sha('5'), now() + Duration::seconds(2))
                .expect_err("revocation is irreversible")
                .code(),
            "BROWSER_INVALID_PROFILE_TRANSITION"
        );
    }
}
