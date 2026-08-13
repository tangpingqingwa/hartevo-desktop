//! The small, result-first surface that lives inside a Mission Conversation.
//!
//! This module is deliberately a read-model adapter.  It does not own a
//! WorkProduct, an Outcome, or an adoption decision.  The Application service
//! remains the only authority for changing a result; this layer only carries
//! the exact scope and revision fence from the projection to a Desktop action.

use std::fmt;

use hartevo_application::{DesktopProjectProjection, MissionProjection, WorkProductProjection};
use hartevo_domain_kernel::{MissionId, ProjectId, TenantId, WorkProductId, WorkProductStatus};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResultCandidateKind {
    WorkProduct,
}

impl ResultCandidateKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::WorkProduct => "WORK_PRODUCT",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResultEvidenceState {
    Missing,
    Bound(usize),
}

impl ResultEvidenceState {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Missing => "NO_EVIDENCE",
            Self::Bound(_) => "EVIDENCE_BOUND",
        }
    }

    pub(crate) const fn count(self) -> usize {
        match self {
            Self::Missing => 0,
            Self::Bound(count) => count,
        }
    }
}

/// Exact identity and CAS material copied from a `MissionProjection`.
///
/// The fields are intentionally private to this Desktop module.  A custom
/// Debug implementation below keeps raw ids and full digests out of logs,
/// while action handlers still receive the exact values needed by the typed
/// Application consumer.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ResultBinding {
    pub(crate) tenant_id: TenantId,
    pub(crate) project_id: ProjectId,
    pub(crate) mission_id: MissionId,
    pub(crate) result_id: WorkProductId,
    pub(crate) result_revision: u64,
    pub(crate) mission_revision: u64,
    pub(crate) manifest_version: u64,
}

impl fmt::Debug for ResultBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultBinding")
            .field("tenant_id", &"[REDACTED]")
            .field("project_id", &"[REDACTED]")
            .field("mission_id", &"[REDACTED]")
            .field("result_id", &"[REDACTED]")
            .field("result_revision", &self.result_revision)
            .field("mission_revision", &self.mission_revision)
            .field("manifest_version", &self.manifest_version)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum ResultSurfaceAction {
    Adopt(ResultBinding),
    OpenArtifact(ResultBinding),
}

impl ResultSurfaceAction {
    pub(crate) fn binding(&self) -> &ResultBinding {
        match self {
            Self::Adopt(binding) | Self::OpenArtifact(binding) => binding,
        }
    }

    pub(crate) const fn label(&self) -> &'static str {
        match self {
            Self::Adopt(_) => "ADOPT",
            Self::OpenArtifact(_) => "OPEN_ARTIFACT",
        }
    }
}

impl fmt::Debug for ResultSurfaceAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultSurfaceAction")
            .field("action", &self.label())
            .field("binding", self.binding())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SelectedResultProjection {
    pub(crate) kind: ResultCandidateKind,
    pub(crate) binding: ResultBinding,
    pub(crate) title: String,
    pub(crate) result_type: String,
    pub(crate) adoption_status: WorkProductStatus,
    pub(crate) evidence: ResultEvidenceState,
    pub(crate) editable_scope_count: usize,
    pub(crate) preview_media_type: String,
    pub(crate) preview_digest: String,
    pub(crate) manifest_digest: String,
}

impl fmt::Debug for SelectedResultProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedResultProjection")
            .field("kind", &self.kind)
            .field("binding", &self.binding)
            .field("title", &"[REDACTED]")
            .field("result_type", &self.result_type)
            .field("adoption_status", &self.adoption_status)
            .field("evidence", &self.evidence)
            .field("editable_scope_count", &self.editable_scope_count)
            .field("preview_media_type", &self.preview_media_type)
            .field("preview_digest", &short_digest(&self.preview_digest))
            .field("manifest_digest", &short_digest(&self.manifest_digest))
            .finish()
    }
}

impl SelectedResultProjection {
    pub(crate) fn adopt_action(&self) -> ResultSurfaceAction {
        ResultSurfaceAction::Adopt(self.binding.clone())
    }

    pub(crate) fn open_artifact_action(&self) -> ResultSurfaceAction {
        ResultSurfaceAction::OpenArtifact(self.binding.clone())
    }

    pub(crate) const fn can_adopt(&self) -> bool {
        matches!(self.adoption_status, WorkProductStatus::ReadyForReview)
    }

    pub(crate) const fn provenance_label() -> &'static str {
        "APPLICATION_PROJECTION · PERSISTED"
    }
}

/// Selects one result from the exact current Project/Mission projection.
///
/// A supplied result id is never replaced by another result when it is stale;
/// returning `None` is the fail-closed behavior needed after reselect/reopen.
/// With no selection, the newest reviewable/accepted WorkProduct is the one
/// inline candidate.  No body or preview text is copied into this projection.
pub(crate) fn selected_result_projection(
    project: &DesktopProjectProjection,
    mission: &MissionProjection,
    selected_result_id: Option<&WorkProductId>,
) -> Option<SelectedResultProjection> {
    if project.project_id != mission.project_id
        || !project
            .missions
            .iter()
            .any(|candidate| candidate.mission_id == mission.mission_id)
    {
        return None;
    }
    let product = match selected_result_id {
        Some(result_id) => mission
            .work_products
            .iter()
            .find(|candidate| &candidate.work_product_id == result_id)?,
        None => mission
            .work_products
            .iter()
            .filter(|candidate| {
                matches!(
                    candidate.adoption_status,
                    WorkProductStatus::ReadyForReview | WorkProductStatus::Accepted
                )
            })
            .max_by_key(|candidate| candidate.work_product_revision)
            .or_else(|| mission.work_products.last())?,
    };
    Some(result_projection(project, mission, product))
}

fn result_projection(
    project: &DesktopProjectProjection,
    mission: &MissionProjection,
    product: &WorkProductProjection,
) -> SelectedResultProjection {
    let evidence = if product.evidence_count == 0 {
        ResultEvidenceState::Missing
    } else {
        ResultEvidenceState::Bound(product.evidence_count)
    };
    SelectedResultProjection {
        kind: ResultCandidateKind::WorkProduct,
        binding: ResultBinding {
            tenant_id: project.tenant_id.clone(),
            project_id: project.project_id.clone(),
            mission_id: mission.mission_id.clone(),
            result_id: product.work_product_id.clone(),
            result_revision: product.work_product_revision,
            mission_revision: mission.revision,
            manifest_version: product.manifest_version,
        },
        title: product.title.clone(),
        result_type: product.work_product_type.clone(),
        adoption_status: product.adoption_status.clone(),
        evidence,
        editable_scope_count: product.editable_scope_count,
        preview_media_type: product.preview_media_type.clone(),
        preview_digest: product.preview_digest.clone(),
        manifest_digest: product.manifest_digest.clone(),
    }
}

pub(crate) fn action_matches_current_projection(
    action: &ResultSurfaceAction,
    project: &DesktopProjectProjection,
    mission: &MissionProjection,
) -> bool {
    let Some(current) =
        selected_result_projection(project, mission, Some(&action.binding().result_id))
    else {
        return false;
    };
    current.binding == *action.binding()
}

fn short_digest(value: &str) -> String {
    if value.len() <= 12 {
        return value.to_owned();
    }
    format!("{}…{}", &value[..8], &value[value.len() - 4..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use hartevo_application::{DesktopProjectProjection, MissionProjection};
    use hartevo_domain_kernel::{ProjectEncryptionMode, StorageMode};

    fn project_and_mission(
        status: WorkProductStatus,
    ) -> (DesktopProjectProjection, MissionProjection) {
        let project_id = ProjectId::from("project-result-surface");
        let mission_id = MissionId::from("mission-result-surface");
        let tenant_id = TenantId::from("tenant-result-surface");
        let product_id = WorkProductId::from("work-product-result-surface");
        let product = WorkProductProjection {
            work_product_id: product_id,
            title: "德国市场证据包".into(),
            work_product_type: "market_evidence_pack".into(),
            manifest_version: 3,
            work_product_revision: 2,
            preview_media_type: "text/markdown".into(),
            preview_text: "private body must not be copied".into(),
            preview_digest: "a".repeat(64),
            manifest_digest: "b".repeat(64),
            adoption_status: status,
            editable_scope_count: 1,
            evidence_count: 4,
        };
        let mission = MissionProjection {
            surface: "mission".into(),
            project_id: project_id.clone(),
            mission_id,
            title: "德国市场评估".into(),
            goal: "goal".into(),
            manifest_id: Some("VM-07".into()),
            manifest_version: Some(1),
            catalog_digest: Some("c".repeat(64)),
            current_checkpoint_id: None,
            current_checkpoint_status: None,
            current_checkpoint_revision: None,
            current_checkpoint_capability_id: None,
            current_checkpoint_executor: None,
            current_checkpoint_application_handler_status: None,
            current_checkpoint_application_handler_id: None,
            current_checkpoint_oracle_ids: std::collections::BTreeSet::default(),
            current_checkpoint_completion_policy: None,
            completed_checkpoint_count: 0,
            checkpoint_count: 8,
            cycle: 0,
            schedule: None,
            conversation_id: None,
            conversation_revision: None,
            conversation_messages: Vec::new(),
            stage: hartevo_domain_kernel::MissionStage::Running,
            revision: 9,
            evidence_count: 4,
            work_product_count: 1,
            work_products: vec![product],
            pending_approval_count: 0,
            verified_effect_count: 0,
            outcome_summary: None,
            vm11_outcome_review: None,
        };
        let project = DesktopProjectProjection {
            tenant_id,
            project_id,
            name: "project".into(),
            description: String::new(),
            storage_mode: StorageMode::LocalNew,
            data_cell: None,
            revision: 11,
            workspace_root_count: 0,
            encryption: hartevo_application::ProjectEncryptionReadiness::Ready {
                mode: ProjectEncryptionMode::PersonalE2ee,
                active_key_version: 1,
                keyring_revision: 1,
            },
            missions: vec![mission.clone()],
        };
        (project, mission)
    }

    #[test]
    fn selected_result_is_content_free_and_exactly_scoped() {
        let (project, mission) = project_and_mission(WorkProductStatus::ReadyForReview);
        let selected = selected_result_projection(&project, &mission, None).expect("result");
        assert_eq!(selected.kind, ResultCandidateKind::WorkProduct);
        assert_eq!(selected.binding.project_id, project.project_id);
        assert_eq!(selected.binding.mission_id, mission.mission_id);
        assert_eq!(selected.binding.result_revision, 2);
        assert_eq!(selected.evidence, ResultEvidenceState::Bound(4));
        assert!(!format!("{selected:?}").contains("private body"));
        assert!(!format!("{selected:?}").contains("work-product-result-surface"));
    }

    #[test]
    fn stale_result_selection_and_scope_fail_closed() {
        let (project, mission) = project_and_mission(WorkProductStatus::ReadyForReview);
        let stale_id = WorkProductId::from("different-result");
        assert!(selected_result_projection(&project, &mission, Some(&stale_id)).is_none());
        let mut other_project = project.clone();
        other_project.project_id = ProjectId::from("other-project");
        assert!(selected_result_projection(&other_project, &mission, None).is_none());
        let selected = selected_result_projection(&project, &mission, None).expect("result");
        assert!(action_matches_current_projection(
            &selected.open_artifact_action(),
            &project,
            &mission
        ));
        let mut revised_mission = mission.clone();
        revised_mission.revision += 1;
        assert!(!action_matches_current_projection(
            &selected.open_artifact_action(),
            &project,
            &revised_mission
        ));
        let mut other_mission = mission.clone();
        other_mission.mission_id = MissionId::from("other-mission");
        assert!(!action_matches_current_projection(
            &selected.open_artifact_action(),
            &project,
            &other_mission
        ));
        assert!(action_matches_current_projection(
            &selected.open_artifact_action(),
            &project,
            &mission
        ));
        assert!(
            !format!("{:?}", selected.open_artifact_action())
                .contains("work-product-result-surface")
        );
    }

    #[test]
    fn adopt_and_open_are_the_only_supported_result_actions() {
        let (project, mission) = project_and_mission(WorkProductStatus::ReadyForReview);
        let selected = selected_result_projection(&project, &mission, None).expect("result");
        assert!(selected.can_adopt());
        assert_eq!(selected.adopt_action().label(), "ADOPT");
        assert_eq!(selected.open_artifact_action().label(), "OPEN_ARTIFACT");
        let accepted_mission = {
            let mut copy = mission.clone();
            copy.work_products[0].adoption_status = WorkProductStatus::Accepted;
            copy
        };
        let accepted =
            selected_result_projection(&project, &accepted_mission, None).expect("result");
        assert!(!accepted.can_adopt());
    }
}
