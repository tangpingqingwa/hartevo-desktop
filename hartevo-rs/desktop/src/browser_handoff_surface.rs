//! Contextual Desktop projection for the Browser human-handoff plugin.
//!
//! The Browser adapter/Application owns leases, snapshots, receipts, and all
//! control transitions. This module only accepts an already typed provider
//! offer/receipt, fences it to the selected Mission, and renders an on-demand
//! inline surface. It never invents a Browser fact, starts a plugin, or writes
//! persistence.

use std::fmt;

use hartevo_domain_kernel::{MissionId, ProjectId, TenantId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserHandoffSurfaceError {
    InvalidOffer,
    InvalidReceipt,
    ScopeMismatch,
    StaleRevision,
    InvalidTransition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserHandoffPhase {
    Offered,
    Paused,
    TakeoverRequested,
    UserControlled,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BrowserTakeoverOfferInput {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub offer_id: String,
    pub profile_id: String,
    pub workspace_id: String,
    pub origin_summary: String,
    pub frame_summary: String,
    pub frame_id_digest: String,
    pub loader_id_digest: String,
    pub offer_digest: String,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub profile_revision: u64,
    pub workspace_revision: u64,
    pub lease_generation: u64,
}

impl fmt::Debug for BrowserTakeoverOfferInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserTakeoverOfferInput")
            .field("has_scope", &true)
            .field("has_origin_summary", &true)
            .field("has_frame_summary", &true)
            .field("project_revision", &self.project_revision)
            .field("mission_revision", &self.mission_revision)
            .field("profile_revision", &self.profile_revision)
            .field("workspace_revision", &self.workspace_revision)
            .field("lease_generation", &self.lease_generation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BrowserTakeoverOffer {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    offer_id: String,
    profile_id: String,
    workspace_id: String,
    origin_summary: String,
    frame_summary: String,
    frame_id_digest: String,
    loader_id_digest: String,
    offer_digest: String,
    project_revision: u64,
    mission_revision: u64,
    profile_revision: u64,
    workspace_revision: u64,
    lease_generation: u64,
}

impl fmt::Debug for BrowserTakeoverOffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserTakeoverOffer")
            .field("has_scope", &true)
            .field("has_origin_summary", &true)
            .field("has_frame_summary", &true)
            .field("project_revision", &self.project_revision)
            .field("mission_revision", &self.mission_revision)
            .field("profile_revision", &self.profile_revision)
            .field("workspace_revision", &self.workspace_revision)
            .field("lease_generation", &self.lease_generation)
            .finish_non_exhaustive()
    }
}

impl BrowserTakeoverOffer {
    pub fn from_typed_contract(
        input: BrowserTakeoverOfferInput,
    ) -> Result<Self, BrowserHandoffSurfaceError> {
        if !valid_identifier(&input.offer_id)
            || !valid_identifier(&input.profile_id)
            || !valid_identifier(&input.workspace_id)
            || !valid_summary(&input.origin_summary)
            || !valid_summary(&input.frame_summary)
            || !valid_digest(&input.frame_id_digest)
            || !valid_digest(&input.loader_id_digest)
            || !valid_digest(&input.offer_digest)
            || input.project_revision == 0
            || input.mission_revision == 0
            || input.profile_revision == 0
            || input.workspace_revision == 0
            || input.lease_generation == 0
        {
            return Err(BrowserHandoffSurfaceError::InvalidOffer);
        }
        Ok(Self {
            tenant_id: input.tenant_id,
            project_id: input.project_id,
            mission_id: input.mission_id,
            offer_id: input.offer_id,
            profile_id: input.profile_id,
            workspace_id: input.workspace_id,
            origin_summary: input.origin_summary,
            frame_summary: input.frame_summary,
            frame_id_digest: input.frame_id_digest,
            loader_id_digest: input.loader_id_digest,
            offer_digest: input.offer_digest,
            project_revision: input.project_revision,
            mission_revision: input.mission_revision,
            profile_revision: input.profile_revision,
            workspace_revision: input.workspace_revision,
            lease_generation: input.lease_generation,
        })
    }

    fn matches_scope(&self, scope: &BrowserMissionHandoffScope<'_>) -> bool {
        self.tenant_id == *scope.tenant_id
            && self.project_id == *scope.project_id
            && self.mission_id == *scope.mission_id
            && self.project_revision == scope.project_revision
            && self.mission_revision == scope.mission_revision
    }

    fn matches_binding(&self, receipt: &BrowserHandoffReceiptInput) -> bool {
        self.offer_id == receipt.offer_id
            && self.profile_id == receipt.profile_id
            && self.workspace_id == receipt.workspace_id
            && self.frame_id_digest == receipt.frame_id_digest
            && self.loader_id_digest == receipt.loader_id_digest
            && self.offer_digest == receipt.offer_digest
            && self.project_revision == receipt.project_revision
            && self.mission_revision == receipt.mission_revision
            && self.profile_revision == receipt.profile_revision
            && self.workspace_revision == receipt.workspace_revision
            && self.lease_generation == receipt.lease_generation
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BrowserHandoffReceiptInput {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub offer_id: String,
    pub takeover_receipt_id: String,
    pub profile_id: String,
    pub workspace_id: String,
    pub frame_id_digest: String,
    pub loader_id_digest: String,
    pub offer_digest: String,
    pub snapshot_digest: String,
    pub evidence_digest: String,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub profile_revision: u64,
    pub workspace_revision: u64,
    pub lease_generation: u64,
    pub new_lease_generation: u64,
}

impl fmt::Debug for BrowserHandoffReceiptInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserHandoffReceiptInput")
            .field("has_scope", &true)
            .field("has_snapshot", &true)
            .field("has_evidence", &true)
            .field("lease_generation", &self.lease_generation)
            .field("new_lease_generation", &self.new_lease_generation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BrowserHandoffReceipt {
    input: BrowserHandoffReceiptInput,
}

impl fmt::Debug for BrowserHandoffReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserHandoffReceipt")
            .field("has_scope", &true)
            .field("has_snapshot", &true)
            .field("has_evidence", &true)
            .field("lease_generation", &self.input.lease_generation)
            .field("new_lease_generation", &self.input.new_lease_generation)
            .finish_non_exhaustive()
    }
}

impl BrowserHandoffReceipt {
    pub fn from_typed_contract(
        input: BrowserHandoffReceiptInput,
    ) -> Result<Self, BrowserHandoffSurfaceError> {
        if !valid_identifier(&input.takeover_receipt_id)
            || !valid_identifier(&input.offer_id)
            || !valid_identifier(&input.profile_id)
            || !valid_identifier(&input.workspace_id)
            || !valid_digest(&input.frame_id_digest)
            || !valid_digest(&input.loader_id_digest)
            || !valid_digest(&input.offer_digest)
            || !valid_digest(&input.snapshot_digest)
            || !valid_digest(&input.evidence_digest)
            || input.project_revision == 0
            || input.mission_revision == 0
            || input.profile_revision == 0
            || input.workspace_revision == 0
            || input.lease_generation == 0
            || input.new_lease_generation <= input.lease_generation
        {
            return Err(BrowserHandoffSurfaceError::InvalidReceipt);
        }
        Ok(Self { input })
    }

    fn matches_scope(&self, scope: &BrowserMissionHandoffScope<'_>) -> bool {
        self.input.tenant_id == *scope.tenant_id
            && self.input.project_id == *scope.project_id
            && self.input.mission_id == *scope.mission_id
            && self.input.project_revision == scope.project_revision
            && self.input.mission_revision == scope.mission_revision
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BrowserMissionHandoffScope<'a> {
    pub tenant_id: &'a TenantId,
    pub project_id: &'a ProjectId,
    pub mission_id: &'a MissionId,
    pub project_revision: u64,
    pub mission_revision: u64,
}

impl fmt::Debug for BrowserMissionHandoffScope<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserMissionHandoffScope")
            .field("has_tenant", &true)
            .field("has_project", &true)
            .field("has_mission", &true)
            .field("project_revision", &self.project_revision)
            .field("mission_revision", &self.mission_revision)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserHandoffAction {
    PauseAgent,
    TakeOver,
    Resume,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserHandoffIntent {
    PauseAgent,
    TakeOver,
    Resume,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BrowserHandoffSurfaceProjection {
    pub phase: BrowserHandoffPhase,
    pub origin_summary: String,
    pub frame_summary: String,
    pub profile_revision: u64,
    pub workspace_revision: u64,
    pub lease_generation: u64,
    pub resume_receipt: Option<BrowserHandoffReceiptProjection>,
}

impl fmt::Debug for BrowserHandoffSurfaceProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserHandoffSurfaceProjection")
            .field("phase", &self.phase)
            .field("has_origin_summary", &!self.origin_summary.is_empty())
            .field("has_frame_summary", &!self.frame_summary.is_empty())
            .field("profile_revision", &self.profile_revision)
            .field("workspace_revision", &self.workspace_revision)
            .field("lease_generation", &self.lease_generation)
            .field("has_resume_receipt", &self.resume_receipt.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BrowserHandoffReceiptProjection {
    pub lease_generation: u64,
    pub new_lease_generation: u64,
    pub snapshot_digest_short: String,
    pub evidence_digest_short: String,
}

impl fmt::Debug for BrowserHandoffReceiptProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserHandoffReceiptProjection")
            .field("lease_generation", &self.lease_generation)
            .field("new_lease_generation", &self.new_lease_generation)
            .field("has_snapshot_digest", &true)
            .field("has_evidence_digest", &true)
            .finish_non_exhaustive()
    }
}

impl BrowserHandoffReceiptProjection {
    fn from_receipt(receipt: &BrowserHandoffReceipt) -> Self {
        Self {
            lease_generation: receipt.input.lease_generation,
            new_lease_generation: receipt.input.new_lease_generation,
            snapshot_digest_short: short_digest(&receipt.input.snapshot_digest),
            evidence_digest_short: short_digest(&receipt.input.evidence_digest),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BrowserHandoffSurfaceState {
    offer: Option<BrowserTakeoverOffer>,
    phase: Option<BrowserHandoffPhase>,
    takeover_receipt: Option<BrowserHandoffReceipt>,
    resume_receipt: Option<BrowserHandoffReceipt>,
}

impl BrowserHandoffSurfaceState {
    pub fn receive_offer(&mut self, offer: BrowserTakeoverOffer) {
        if self.offer.as_ref() == Some(&offer) {
            return;
        }
        self.offer = Some(offer);
        self.phase = Some(BrowserHandoffPhase::Offered);
        self.takeover_receipt = None;
        self.resume_receipt = None;
    }

    pub fn apply_takeover_receipt(
        &mut self,
        receipt: BrowserHandoffReceipt,
    ) -> Result<(), BrowserHandoffSurfaceError> {
        let offer = self
            .offer
            .as_ref()
            .ok_or(BrowserHandoffSurfaceError::InvalidTransition)?;
        if !offer.matches_binding(&receipt.input)
            || receipt.input.tenant_id != offer.tenant_id
            || receipt.input.project_id != offer.project_id
            || receipt.input.mission_id != offer.mission_id
            || receipt.input.new_lease_generation != offer.lease_generation.saturating_add(1)
        {
            return Err(BrowserHandoffSurfaceError::StaleRevision);
        }
        self.takeover_receipt = Some(receipt);
        self.phase = Some(BrowserHandoffPhase::UserControlled);
        Ok(())
    }

    pub fn apply_resume_receipt(
        &mut self,
        receipt: BrowserHandoffReceipt,
    ) -> Result<(), BrowserHandoffSurfaceError> {
        let offer = self
            .offer
            .as_ref()
            .ok_or(BrowserHandoffSurfaceError::InvalidTransition)?;
        let takeover = self
            .takeover_receipt
            .as_ref()
            .ok_or(BrowserHandoffSurfaceError::InvalidTransition)?;
        if !offer.matches_binding(&receipt.input)
            || !takeover.matches_scope(&BrowserMissionHandoffScope {
                tenant_id: &receipt.input.tenant_id,
                project_id: &receipt.input.project_id,
                mission_id: &receipt.input.mission_id,
                project_revision: receipt.input.project_revision,
                mission_revision: receipt.input.mission_revision,
            })
            || receipt.input.new_lease_generation <= takeover.input.new_lease_generation
        {
            return Err(BrowserHandoffSurfaceError::StaleRevision);
        }
        self.resume_receipt = Some(receipt);
        self.offer = None;
        self.phase = None;
        Ok(())
    }

    pub fn dispatch(
        &mut self,
        action: BrowserHandoffAction,
        scope: &BrowserMissionHandoffScope<'_>,
    ) -> Result<BrowserHandoffIntent, BrowserHandoffSurfaceError> {
        let offer = self
            .offer
            .as_ref()
            .ok_or(BrowserHandoffSurfaceError::InvalidTransition)?;
        if !offer.matches_scope(scope) {
            return Err(BrowserHandoffSurfaceError::ScopeMismatch);
        }
        let phase = self
            .phase
            .ok_or(BrowserHandoffSurfaceError::InvalidTransition)?;
        match (phase, action) {
            (BrowserHandoffPhase::Offered, BrowserHandoffAction::PauseAgent) => {
                self.phase = Some(BrowserHandoffPhase::Paused);
                Ok(BrowserHandoffIntent::PauseAgent)
            }
            (
                BrowserHandoffPhase::Offered | BrowserHandoffPhase::Paused,
                BrowserHandoffAction::TakeOver,
            ) => {
                self.phase = Some(BrowserHandoffPhase::TakeoverRequested);
                Ok(BrowserHandoffIntent::TakeOver)
            }
            (BrowserHandoffPhase::UserControlled, BrowserHandoffAction::Resume) => {
                Ok(BrowserHandoffIntent::Resume)
            }
            _ => Err(BrowserHandoffSurfaceError::InvalidTransition),
        }
    }

    pub fn projection_for(
        &self,
        scope: &BrowserMissionHandoffScope<'_>,
    ) -> Option<BrowserHandoffSurfaceProjection> {
        let offer = self.offer.as_ref();
        let receipt = self.resume_receipt.as_ref();
        let offer_visible = offer.filter(|offer| offer.matches_scope(scope));
        let receipt_visible = receipt.filter(|receipt| receipt.matches_scope(scope));
        if offer_visible.is_none() && receipt_visible.is_none() {
            return None;
        }
        let Some(offer) = offer_visible else {
            return Some(BrowserHandoffSurfaceProjection {
                phase: BrowserHandoffPhase::Offered,
                origin_summary: String::new(),
                frame_summary: String::new(),
                profile_revision: 0,
                workspace_revision: 0,
                lease_generation: 0,
                resume_receipt: receipt_visible.map(BrowserHandoffReceiptProjection::from_receipt),
            });
        };
        Some(BrowserHandoffSurfaceProjection {
            phase: self.phase.unwrap_or(BrowserHandoffPhase::Offered),
            origin_summary: offer.origin_summary.clone(),
            frame_summary: offer.frame_summary.clone(),
            profile_revision: offer.profile_revision,
            workspace_revision: offer.workspace_revision,
            lease_generation: offer.lease_generation,
            resume_receipt: receipt_visible.map(BrowserHandoffReceiptProjection::from_receipt),
        })
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.chars().all(|character| {
            !character.is_whitespace()
                && !character.is_control()
                && !matches!(character, '/' | '?' | '#')
        })
}

fn valid_summary(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.chars().all(|character| !character.is_control())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn short_digest(value: &str) -> String {
    value.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> BrowserTakeoverOffer {
        BrowserTakeoverOffer::from_typed_contract(BrowserTakeoverOfferInput {
            tenant_id: "tenant-a".into(),
            project_id: "project-a".into(),
            mission_id: "mission-a".into(),
            offer_id: "offer-a".into(),
            profile_id: "profile-a".into(),
            workspace_id: "workspace-a".into(),
            origin_summary: "https://example.test".into(),
            frame_summary: "main frame · tab-a".into(),
            frame_id_digest: "a".repeat(64),
            loader_id_digest: "b".repeat(64),
            offer_digest: "c".repeat(64),
            project_revision: 3,
            mission_revision: 4,
            profile_revision: 5,
            workspace_revision: 6,
            lease_generation: 7,
        })
        .expect("typed offer")
    }

    fn scope<'a>(
        tenant_id: &'a TenantId,
        project_id: &'a ProjectId,
        mission_id: &'a MissionId,
    ) -> BrowserMissionHandoffScope<'a> {
        BrowserMissionHandoffScope {
            tenant_id,
            project_id,
            mission_id,
            project_revision: 3,
            mission_revision: 4,
        }
    }

    fn receipt(offer: &BrowserTakeoverOffer, new_generation: u64) -> BrowserHandoffReceipt {
        BrowserHandoffReceipt::from_typed_contract(BrowserHandoffReceiptInput {
            tenant_id: offer.tenant_id.clone(),
            project_id: offer.project_id.clone(),
            mission_id: offer.mission_id.clone(),
            offer_id: offer.offer_id.clone(),
            takeover_receipt_id: "receipt-a".into(),
            profile_id: offer.profile_id.clone(),
            workspace_id: offer.workspace_id.clone(),
            frame_id_digest: offer.frame_id_digest.clone(),
            loader_id_digest: offer.loader_id_digest.clone(),
            offer_digest: offer.offer_digest.clone(),
            snapshot_digest: "d".repeat(64),
            evidence_digest: "e".repeat(64),
            project_revision: offer.project_revision,
            mission_revision: offer.mission_revision,
            profile_revision: offer.profile_revision,
            workspace_revision: offer.workspace_revision,
            lease_generation: offer.lease_generation,
            new_lease_generation: new_generation,
        })
        .expect("typed receipt")
    }

    #[test]
    fn no_offer_has_no_surface_and_exact_scope_offer_is_visible() {
        let mut state = BrowserHandoffSurfaceState::default();
        let tenant = TenantId::from("tenant-a");
        let project = ProjectId::from("project-a");
        let mission = MissionId::from("mission-a");
        assert!(
            state
                .projection_for(&scope(&tenant, &project, &mission))
                .is_none()
        );
        state.receive_offer(offer());
        assert!(
            state
                .projection_for(&scope(&tenant, &project, &mission))
                .is_some()
        );
    }

    #[test]
    fn cross_scope_and_stale_revision_are_hidden_or_rejected() {
        let mut state = BrowserHandoffSurfaceState::default();
        state.receive_offer(offer());
        let tenant = TenantId::from("tenant-a");
        let other_project = ProjectId::from("project-b");
        let mission = MissionId::from("mission-a");
        assert!(
            state
                .projection_for(&scope(&tenant, &other_project, &mission))
                .is_none()
        );
        let project = ProjectId::from("project-a");
        let other_mission = MissionId::from("mission-b");
        assert!(
            state
                .projection_for(&scope(&tenant, &project, &other_mission))
                .is_none()
        );
        let wrong_revision = BrowserMissionHandoffScope {
            tenant_id: &tenant,
            project_id: &project,
            mission_id: &mission,
            project_revision: 99,
            mission_revision: 4,
        };
        assert!(state.projection_for(&wrong_revision).is_none());
    }

    #[test]
    fn pause_takeover_and_resume_are_typed_and_receipt_removes_offer() {
        let mut state = BrowserHandoffSurfaceState::default();
        let offer = offer();
        state.receive_offer(offer.clone());
        let tenant = TenantId::from("tenant-a");
        let project = ProjectId::from("project-a");
        let mission = MissionId::from("mission-a");
        let selected = scope(&tenant, &project, &mission);
        assert_eq!(
            state.dispatch(BrowserHandoffAction::PauseAgent, &selected),
            Ok(BrowserHandoffIntent::PauseAgent)
        );
        assert_eq!(
            state.dispatch(BrowserHandoffAction::TakeOver, &selected),
            Ok(BrowserHandoffIntent::TakeOver)
        );
        state
            .apply_takeover_receipt(receipt(&offer, 8))
            .expect("takeover receipt");
        assert_eq!(
            state.dispatch(BrowserHandoffAction::Resume, &selected),
            Ok(BrowserHandoffIntent::Resume)
        );
        state
            .apply_resume_receipt(receipt(&offer, 9))
            .expect("resume receipt");
        let projection = state.projection_for(&selected).expect("receipt projection");
        assert!(projection.resume_receipt.is_some());
        assert!(projection.origin_summary.is_empty());
        let projection_debug = format!("{projection:?}");
        assert!(!projection_debug.contains("https://example.test"));
        assert!(!projection_debug.contains(&"d".repeat(64)));
        assert!(!projection_debug.contains(&"e".repeat(64)));
    }

    #[test]
    fn debug_is_content_free_and_stale_receipt_cannot_cross_offer() {
        let offer = offer();
        let debug = format!("{offer:?}");
        assert!(!debug.contains("project-a"));
        assert!(!debug.contains("offer-a"));
        assert!(!debug.contains(&"a".repeat(64)));
        let mut state = BrowserHandoffSurfaceState::default();
        state.receive_offer(offer.clone());
        let mut tampered_receipt = receipt(&offer, 8);
        tampered_receipt.input.offer_digest = "f".repeat(64);
        assert_eq!(
            state.apply_takeover_receipt(tampered_receipt),
            Err(BrowserHandoffSurfaceError::StaleRevision)
        );
    }

    #[test]
    fn same_process_reselect_and_reopen_reuses_offer_without_restarting_provider_state() {
        let mut state = BrowserHandoffSurfaceState::default();
        let offer = offer();
        state.receive_offer(offer);
        let tenant = TenantId::from("tenant-a");
        let project = ProjectId::from("project-a");
        let mission = MissionId::from("mission-a");
        let selected = scope(&tenant, &project, &mission);
        let first = state.projection_for(&selected);
        let reselected = state.projection_for(&selected);
        assert_eq!(first, reselected);
        assert_eq!(
            state.dispatch(BrowserHandoffAction::Resume, &selected),
            Err(BrowserHandoffSurfaceError::InvalidTransition)
        );
    }

    #[test]
    fn input_and_scope_debug_never_expose_raw_binding_material() {
        let input = BrowserTakeoverOfferInput {
            tenant_id: TenantId::from("tenant-a"),
            project_id: ProjectId::from("project-a"),
            mission_id: MissionId::from("mission-a"),
            offer_id: "offer-a".into(),
            profile_id: "profile-a".into(),
            workspace_id: "workspace-a".into(),
            origin_summary: "https://example.test".into(),
            frame_summary: "main frame".into(),
            frame_id_digest: "a".repeat(64),
            loader_id_digest: "b".repeat(64),
            offer_digest: "c".repeat(64),
            project_revision: 1,
            mission_revision: 1,
            profile_revision: 1,
            workspace_revision: 1,
            lease_generation: 1,
        };
        let scope = BrowserMissionHandoffScope {
            tenant_id: &input.tenant_id,
            project_id: &input.project_id,
            mission_id: &input.mission_id,
            project_revision: input.project_revision,
            mission_revision: input.mission_revision,
        };
        let input_debug = format!("{input:?}");
        let scope_debug = format!("{scope:?}");
        let receipt_input = BrowserHandoffReceiptInput {
            tenant_id: input.tenant_id.clone(),
            project_id: input.project_id.clone(),
            mission_id: input.mission_id.clone(),
            offer_id: input.offer_id.clone(),
            takeover_receipt_id: "receipt-a".into(),
            profile_id: input.profile_id.clone(),
            workspace_id: input.workspace_id.clone(),
            frame_id_digest: input.frame_id_digest.clone(),
            loader_id_digest: input.loader_id_digest.clone(),
            offer_digest: input.offer_digest.clone(),
            snapshot_digest: "d".repeat(64),
            evidence_digest: "e".repeat(64),
            project_revision: 1,
            mission_revision: 1,
            profile_revision: 1,
            workspace_revision: 1,
            lease_generation: 1,
            new_lease_generation: 2,
        };
        let receipt_debug = format!("{receipt_input:?}");
        for rendered in [input_debug, scope_debug] {
            assert!(!rendered.contains("tenant-a"));
            assert!(!rendered.contains("project-a"));
            assert!(!rendered.contains("mission-a"));
            assert!(!rendered.contains(&"a".repeat(64)));
            assert!(!rendered.contains(&"b".repeat(64)));
            assert!(!rendered.contains(&"c".repeat(64)));
        }
        {
            let rendered = receipt_debug;
            assert!(!rendered.contains("tenant-a"));
            assert!(!rendered.contains("project-a"));
            assert!(!rendered.contains("mission-a"));
            assert!(!rendered.contains(&"a".repeat(64)));
            assert!(!rendered.contains(&"d".repeat(64)));
            assert!(!rendered.contains(&"e".repeat(64)));
        }
    }
}
