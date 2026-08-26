//! Desktop-only Mission lifecycle entry points.
//!
//! This module is deliberately a read-model/navigation boundary. It resolves
//! Project/Mission identities and revision fences, but never starts Runtime,
//! mounts a plugin, writes a Store, or changes Application authority.

use std::{fmt, fmt::Write as _};

use hartevo_application::{
    DesktopInventoryProjection, DesktopProjectProjection, MissionProjection,
};
use hartevo_domain_kernel::{MissionId, ProjectId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MissionLifecycleError {
    InvalidDeepLink,
    InvalidOperatorCommand,
    ProjectNotFound,
    MissionNotFound,
    CrossProjectMission,
    StaleRevision,
}

/// Parsed identity from `hartevo://project/{project}/mission/{mission}`.
/// Optional revision query values are internal stale-action fences; the base
/// URI remains the stable user-facing deep-link shape.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct MissionDeepLink {
    project_id: ProjectId,
    mission_id: MissionId,
    expected_project_revision: Option<u64>,
    expected_mission_revision: Option<u64>,
}

impl fmt::Debug for MissionDeepLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionDeepLink")
            .field("has_project", &true)
            .field("has_mission", &true)
            .field("expected_project_revision", &self.expected_project_revision)
            .field("expected_mission_revision", &self.expected_mission_revision)
            .finish_non_exhaustive()
    }
}

impl MissionDeepLink {
    pub(crate) fn from_ids(project_id: ProjectId, mission_id: MissionId) -> Self {
        Self {
            project_id,
            mission_id,
            expected_project_revision: None,
            expected_mission_revision: None,
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, MissionLifecycleError> {
        let value = value.trim();
        let path = value
            .strip_prefix("hartevo://project/")
            .ok_or(MissionLifecycleError::InvalidDeepLink)?;
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        if path.contains('#') {
            return Err(MissionLifecycleError::InvalidDeepLink);
        }
        let mut segments = path.split('/');
        let project_id = valid_segment(segments.next())?;
        if segments.next() != Some("mission") {
            return Err(MissionLifecycleError::InvalidDeepLink);
        }
        let mission_id = valid_segment(segments.next())?;
        if segments.next().is_some() {
            return Err(MissionLifecycleError::InvalidDeepLink);
        }
        let (expected_project_revision, expected_mission_revision) = parse_revisions(query)?;
        Ok(Self {
            project_id: ProjectId::from(project_id.as_str()),
            mission_id: MissionId::from(mission_id.as_str()),
            expected_project_revision,
            expected_mission_revision,
        })
    }

    pub(crate) fn from_target(target: &MissionOpenTarget) -> Self {
        Self {
            project_id: target.project_id.clone(),
            mission_id: target.mission_id.clone(),
            expected_project_revision: Some(target.project_revision),
            expected_mission_revision: Some(target.mission_revision),
        }
    }

    pub(crate) fn to_uri(&self) -> String {
        let mut uri = format!(
            "hartevo://project/{}/mission/{}",
            self.project_id.as_str(),
            self.mission_id.as_str()
        );
        match (
            self.expected_project_revision,
            self.expected_mission_revision,
        ) {
            (Some(project_revision), Some(mission_revision)) => {
                let _ = write!(
                    uri,
                    "?project_revision={project_revision}&mission_revision={mission_revision}"
                );
            }
            (Some(project_revision), None) => {
                let _ = write!(uri, "?project_revision={project_revision}");
            }
            (None, Some(mission_revision)) => {
                let _ = write!(uri, "?mission_revision={mission_revision}");
            }
            (None, None) => {}
        }
        uri
    }

    pub(crate) fn resolve(
        &self,
        inventory: &DesktopInventoryProjection,
    ) -> Result<MissionOpenTarget, MissionLifecycleError> {
        let project = inventory
            .projects
            .iter()
            .find(|project| project.project_id == self.project_id)
            .ok_or(MissionLifecycleError::ProjectNotFound)?;
        let mission = project
            .missions
            .iter()
            .find(|mission| mission.mission_id == self.mission_id)
            .ok_or_else(|| {
                if inventory.projects.iter().any(|other| {
                    other.project_id != project.project_id
                        && other
                            .missions
                            .iter()
                            .any(|mission| mission.mission_id == self.mission_id)
                }) {
                    MissionLifecycleError::CrossProjectMission
                } else {
                    MissionLifecycleError::MissionNotFound
                }
            })?;
        if mission.project_id != project.project_id {
            return Err(MissionLifecycleError::CrossProjectMission);
        }
        if self
            .expected_project_revision
            .is_some_and(|revision| revision != project.revision)
            || self
                .expected_mission_revision
                .is_some_and(|revision| revision != mission.revision)
        {
            return Err(MissionLifecycleError::StaleRevision);
        }
        Ok(MissionOpenTarget::from_projection(project, mission))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct MissionOpenTarget {
    project_id: ProjectId,
    mission_id: MissionId,
    project_revision: u64,
    mission_revision: u64,
}

impl fmt::Debug for MissionOpenTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionOpenTarget")
            .field("project_revision", &self.project_revision)
            .field("mission_revision", &self.mission_revision)
            .finish_non_exhaustive()
    }
}

impl MissionOpenTarget {
    pub(crate) fn from_projection(
        project: &DesktopProjectProjection,
        mission: &MissionProjection,
    ) -> Self {
        Self {
            project_id: project.project_id.clone(),
            mission_id: mission.mission_id.clone(),
            project_revision: project.revision,
            mission_revision: mission.revision,
        }
    }

    pub(crate) fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub(crate) fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }
}

pub(crate) fn recent_mission_for_project(
    project: &DesktopProjectProjection,
) -> Option<MissionOpenTarget> {
    project
        .missions
        .iter()
        .max_by(|left, right| {
            (left.revision, left.cycle, left.mission_id.as_str()).cmp(&(
                right.revision,
                right.cycle,
                right.mission_id.as_str(),
            ))
        })
        .map(|mission| MissionOpenTarget::from_projection(project, mission))
}

pub(crate) fn parse_operator_command(
    value: &str,
) -> Result<Option<MissionDeepLink>, MissionLifecycleError> {
    let value = value.trim();
    if matches!(value, "open" | "open mission" | "mission") {
        return Err(MissionLifecycleError::InvalidOperatorCommand);
    }
    let payload = if let Some(payload) = value.strip_prefix("open mission ") {
        payload.trim()
    } else if let Some(payload) = value.strip_prefix("mission ") {
        payload.trim()
    } else if let Some(payload) = value.strip_prefix("open ") {
        let payload = payload.trim();
        if payload.starts_with("hartevo://") {
            return MissionDeepLink::parse(payload)
                .map(Some)
                .map_err(|_| MissionLifecycleError::InvalidOperatorCommand);
        }
        return Ok(None);
    } else {
        return Ok(None);
    };
    if payload.is_empty() {
        return Err(MissionLifecycleError::InvalidOperatorCommand);
    }
    if payload.starts_with("hartevo://") {
        return MissionDeepLink::parse(payload)
            .map(Some)
            .map_err(|_| MissionLifecycleError::InvalidOperatorCommand);
    }
    let mut ids = payload.split_whitespace();
    let first = ids
        .next()
        .ok_or(MissionLifecycleError::InvalidOperatorCommand)?;
    let second = ids.next();
    if ids.next().is_some() {
        return Err(MissionLifecycleError::InvalidOperatorCommand);
    }
    let (project, mission) = if let Some(mission) = second {
        (first, mission)
    } else {
        let (project, mission) = first
            .split_once('/')
            .ok_or(MissionLifecycleError::InvalidOperatorCommand)?;
        (project, mission)
    };
    if !is_valid_segment(project) || !is_valid_segment(mission) {
        return Err(MissionLifecycleError::InvalidOperatorCommand);
    }
    MissionDeepLink::parse(&format!("hartevo://project/{project}/mission/{mission}"))
        .map(Some)
        .map_err(|_| MissionLifecycleError::InvalidOperatorCommand)
}

pub(crate) fn startup_deep_link<I>(args: I) -> Option<String>
where
    I: IntoIterator<Item = String>,
{
    args.into_iter()
        .find(|argument| argument.trim_start().starts_with("hartevo://"))
}

fn valid_segment(value: Option<&str>) -> Result<String, MissionLifecycleError> {
    let value = value.ok_or(MissionLifecycleError::InvalidDeepLink)?;
    if is_valid_segment(value) {
        Ok(value.to_owned())
    } else {
        Err(MissionLifecycleError::InvalidDeepLink)
    }
}

fn is_valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains('%')
        && value.chars().all(|character| {
            !character.is_whitespace()
                && !character.is_control()
                && character != '/'
                && character != '?'
                && character != '#'
        })
}

fn parse_revisions(query: &str) -> Result<(Option<u64>, Option<u64>), MissionLifecycleError> {
    let mut project_revision = None;
    let mut mission_revision = None;
    if query.is_empty() {
        return Ok((None, None));
    }
    for pair in query.split('&') {
        let (key, value) = pair
            .split_once('=')
            .ok_or(MissionLifecycleError::InvalidDeepLink)?;
        let revision = value
            .parse::<u64>()
            .map_err(|_| MissionLifecycleError::InvalidDeepLink)?;
        match key {
            "project_revision" if project_revision.is_none() => project_revision = Some(revision),
            "mission_revision" if mission_revision.is_none() => mission_revision = Some(revision),
            _ => return Err(MissionLifecycleError::InvalidDeepLink),
        }
    }
    Ok((project_revision, mission_revision))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_deep_link_and_rejects_ambiguous_shapes() {
        let link = MissionDeepLink::parse("hartevo://project/project-a/mission/mission-a")
            .expect("exact deep link");
        assert_eq!(
            link.to_uri(),
            "hartevo://project/project-a/mission/mission-a"
        );
        assert!(MissionDeepLink::parse("hartevo://mission/mission-a").is_err());
        assert!(MissionDeepLink::parse("hartevo://project/project-a/mission/").is_err());
        assert!(
            MissionDeepLink::parse("hartevo://project/project-a/mission/mission-a/extra").is_err()
        );
        assert!(
            MissionDeepLink::parse("hartevo://project/project-a/mission/mission-a#fragment")
                .is_err()
        );
    }

    #[test]
    fn resolves_project_scope_and_revision_fence_without_raw_debug_material() {
        let project = project_for_test("project-a", "mission-a", 3, 7);
        let inventory = DesktopInventoryProjection {
            projects: vec![project.clone()],
        };
        let link = MissionDeepLink::parse(
            "hartevo://project/project-a/mission/mission-a?project_revision=3&mission_revision=7",
        )
        .expect("fenced link");
        let target = link.resolve(&inventory).expect("resolved target");
        assert_eq!(target.project_id(), &ProjectId::from("project-a"));
        assert_eq!(target.mission_id(), &MissionId::from("mission-a"));
        let debug = format!("{link:?} {target:?}");
        assert!(!debug.contains("project-a"));
        assert!(!debug.contains("mission-a"));
        let stale = MissionDeepLink::parse(
            "hartevo://project/project-a/mission/mission-a?project_revision=2&mission_revision=7",
        )
        .expect("stale link shape");
        assert_eq!(
            stale.resolve(&inventory),
            Err(MissionLifecycleError::StaleRevision)
        );
    }

    #[test]
    fn missing_and_cross_project_targets_fail_closed() {
        let inventory = DesktopInventoryProjection {
            projects: vec![
                project_for_test("project-a", "mission-a", 1, 1),
                project_for_test("project-b", "mission-b", 1, 1),
            ],
        };
        let missing = MissionDeepLink::parse("hartevo://project/project-a/mission/missing")
            .expect("missing link shape");
        assert_eq!(
            missing.resolve(&inventory),
            Err(MissionLifecycleError::MissionNotFound)
        );
        let cross = MissionDeepLink::parse("hartevo://project/project-a/mission/mission-b")
            .expect("cross link shape");
        assert_eq!(
            cross.resolve(&inventory),
            Err(MissionLifecycleError::CrossProjectMission)
        );
        let unknown = MissionDeepLink::parse("hartevo://project/missing/mission/mission-b")
            .expect("unknown project link shape");
        assert_eq!(
            unknown.resolve(&inventory),
            Err(MissionLifecycleError::ProjectNotFound)
        );
    }

    #[test]
    fn operator_commands_are_typed_and_recent_selection_is_deterministic() {
        let command = parse_operator_command("open mission project-a/mission-a")
            .expect("operator command")
            .expect("mission target");
        assert_eq!(
            command.to_uri(),
            "hartevo://project/project-a/mission/mission-a"
        );
        assert!(
            parse_operator_command("show me the latest mission")
                .expect("normal search is not a command")
                .is_none()
        );
        assert_eq!(
            parse_operator_command("open mission").expect_err("incomplete command"),
            MissionLifecycleError::InvalidOperatorCommand
        );
        let mut project = project_for_test("project-a", "mission-old", 1, 1);
        project.missions.push(mission_for_test("mission-new", 2, 1));
        let recent = recent_mission_for_project(&project).expect("recent mission");
        assert_eq!(recent.mission_id(), &MissionId::from("mission-new"));
    }

    #[test]
    fn startup_arguments_accept_only_the_typed_hartevo_scheme() {
        assert_eq!(
            startup_deep_link([
                "hartevo-desktop".to_owned(),
                "hartevo://project/project-a/mission/mission-a".to_owned(),
            ]),
            Some("hartevo://project/project-a/mission/mission-a".to_owned())
        );
        assert_eq!(
            startup_deep_link([
                "hartevo-desktop".to_owned(),
                "https://example.test".to_owned()
            ]),
            None
        );
    }

    fn project_for_test(
        project_id: &str,
        mission_id: &str,
        project_revision: u64,
        mission_revision: u64,
    ) -> DesktopProjectProjection {
        DesktopProjectProjection {
            tenant_id: "tenant-a".into(),
            project_id: project_id.into(),
            name: "Project".into(),
            description: String::new(),
            storage_mode: hartevo_domain_kernel::StorageMode::LocalNew,
            data_cell: None,
            revision: project_revision,
            workspace_root_count: 0,
            encryption: hartevo_application::ProjectEncryptionReadiness::NotProvisioned,
            missions: vec![mission_for_test(mission_id, mission_revision, 1)],
        }
    }

    fn mission_for_test(mission_id: &str, revision: u64, cycle: u64) -> MissionProjection {
        MissionProjection {
            surface: "orchestrator".into(),
            project_id: "project-a".into(),
            mission_id: mission_id.into(),
            title: "Mission".into(),
            goal: String::new(),
            manifest_id: None,
            manifest_version: None,
            catalog_digest: None,
            current_checkpoint_id: None,
            current_checkpoint_status: None,
            current_checkpoint_revision: None,
            current_checkpoint_capability_id: None,
            current_checkpoint_executor: None,
            current_checkpoint_application_handler_status: None,
            current_checkpoint_application_handler_id: None,
            current_checkpoint_oracle_ids: std::collections::BTreeSet::new(),
            current_checkpoint_completion_policy: None,
            completed_checkpoint_count: 0,
            checkpoint_count: 0,
            cycle,
            schedule: None,
            conversation_id: None,
            conversation_revision: None,
            conversation_messages: Vec::new(),
            stage: hartevo_domain_kernel::MissionStage::Draft,
            revision,
            evidence_count: 0,
            work_product_count: 0,
            work_products: Vec::new(),
            pending_approval_count: 0,
            verified_effect_count: 0,
            outcome_summary: None,
            vm11_outcome_review: None,
        }
    }
}
