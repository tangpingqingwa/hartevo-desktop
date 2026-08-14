//! Minimal, Mission-scoped presentation for Application-owned plugin approvals.
//!
//! This module deliberately stops at the Application boundary.  It projects a
//! durable pending request into a content-free inline node and can emit an
//! exact revision-bound command intent when an Application decision port is
//! supplied.  It never constructs an EffectBroker, policy, approval grant, or
//! local terminal state.

use std::fmt;

#[cfg(test)]
use hartevo_application::PendingPluginApprovalDecisionCommand;
use hartevo_application::{
    PendingPluginApprovalDecision, PendingPluginApprovalProjection, PendingPluginApprovalRevisions,
    PendingPluginApprovalScope, PendingPluginApprovalState,
};
#[cfg(test)]
use hartevo_domain_kernel::ActorId;
use hartevo_domain_kernel::{MissionId, ProjectId, TenantId};
use sha2::{Digest, Sha256};

/// A selected projection that is safe to render in the current Mission shell.
///
/// The full Application projection is retained privately so a future
/// Application-owned decision port can receive every exact fence.  The
/// presentation surface exposes only stable labels and short digests.
#[derive(Clone, Eq, PartialEq)]
pub struct PendingPluginApprovalSurfaceProjection {
    projection: PendingPluginApprovalProjection,
    scope_label: String,
    plugin_id: String,
    plugin_version: String,
    plugin_digest_label: String,
    invocation_digest_label: String,
    effect_digest_label: String,
    request_digest_label: String,
    projection_digest_label: String,
    revisions: PendingPluginApprovalRevisions,
    request_event_sequence: u64,
}

impl fmt::Debug for PendingPluginApprovalSurfaceProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingPluginApprovalSurfaceProjection")
            .field("scope_bound", &true)
            .field("plugin_id_present", &!self.plugin_id.is_empty())
            .field("plugin_version_present", &!self.plugin_version.is_empty())
            .field("plugin_digest", &self.plugin_digest_label)
            .field("invocation_digest", &self.invocation_digest_label)
            .field("effect_digest", &self.effect_digest_label)
            .field("request_digest", &self.request_digest_label)
            .field("projection_digest", &self.projection_digest_label)
            .field("request_event_sequence", &self.request_event_sequence)
            .field("mission_revision", &self.revisions.mission_revision())
            .field("effect_revision", &self.revisions.effect_revision())
            .field("invocation_revision", &self.revisions.invocation_revision())
            .field(
                "consent_revision_present",
                &self.revisions.consent_revision().is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl PendingPluginApprovalSurfaceProjection {
    fn from_projection(projection: PendingPluginApprovalProjection) -> Self {
        Self {
            scope_label: opaque_scope_label(projection.scope()),
            plugin_id: projection.plugin_id().to_owned(),
            plugin_version: projection.plugin_version().to_owned(),
            plugin_digest_label: short_digest(projection.plugin_digest()),
            invocation_digest_label: short_digest(projection.invocation_digest()),
            effect_digest_label: short_digest(projection.effect_digest()),
            request_digest_label: short_digest(projection.request_digest()),
            projection_digest_label: short_digest(projection.projection_digest()),
            revisions: projection.revisions(),
            request_event_sequence: projection.request_event_sequence(),
            projection,
        }
    }

    pub fn scope_label(&self) -> &str {
        &self.scope_label
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn plugin_digest_label(&self) -> &str {
        &self.plugin_digest_label
    }

    pub fn invocation_digest_label(&self) -> &str {
        &self.invocation_digest_label
    }

    pub fn effect_digest_label(&self) -> &str {
        &self.effect_digest_label
    }

    pub fn request_digest_label(&self) -> &str {
        &self.request_digest_label
    }

    pub fn projection_digest_label(&self) -> &str {
        &self.projection_digest_label
    }

    pub const fn revisions(&self) -> PendingPluginApprovalRevisions {
        self.revisions
    }

    pub const fn request_event_sequence(&self) -> u64 {
        self.request_event_sequence
    }

    #[cfg(test)]
    pub fn scope(&self) -> &PendingPluginApprovalScope {
        self.projection.scope()
    }

    /// Build the exact Application command without inventing authority.
    ///
    /// The returned command is an intent only.  A caller must still pass it to
    /// `ApplicationService::decide_pending_plugin_approval` through the
    /// Application-owned EffectBroker/decision port.
    #[cfg(test)]
    pub fn application_command(
        &self,
        actor_id: ActorId,
        decision: PendingPluginApprovalDecision,
    ) -> PendingPluginApprovalDecisionCommand {
        let projection = &self.projection;
        PendingPluginApprovalDecisionCommand {
            scope: projection.scope().clone(),
            plugin_id: projection.plugin_id().to_owned(),
            plugin_version: projection.plugin_version().to_owned(),
            plugin_digest: projection.plugin_digest().to_owned(),
            invocation_id: projection.invocation_id().to_owned(),
            invocation_digest: projection.invocation_digest().to_owned(),
            effect_id: projection.effect_id().clone(),
            effect_digest: projection.effect_digest().to_owned(),
            request_digest: projection.request_digest().to_owned(),
            request_event_sequence: projection.request_event_sequence(),
            expected_mission_revision: projection.revisions().mission_revision(),
            expected_effect_revision: projection.revisions().effect_revision(),
            expected_consent_revision: projection.revisions().consent_revision(),
            decision,
            actor_id,
        }
    }
}

/// An exact user intent emitted by the inline node.  It contains the complete
/// Application command fence but has no authority to execute it.
#[derive(Clone, Eq, PartialEq)]
pub struct PendingPluginApprovalAction {
    projection: PendingPluginApprovalSurfaceProjection,
    decision: PendingPluginApprovalDecision,
}

impl fmt::Debug for PendingPluginApprovalAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingPluginApprovalAction")
            .field("decision", &self.decision)
            .field("scope_bound", &true)
            .field(
                "request_event_sequence",
                &self.projection.request_event_sequence,
            )
            .field("request_digest", &self.projection.request_digest_label)
            .field(
                "projection_digest",
                &self.projection.projection_digest_label,
            )
            .finish_non_exhaustive()
    }
}

impl PendingPluginApprovalAction {
    pub fn approve(projection: PendingPluginApprovalSurfaceProjection) -> Self {
        Self {
            projection,
            decision: PendingPluginApprovalDecision::Approve,
        }
    }

    pub fn deny(projection: PendingPluginApprovalSurfaceProjection) -> Self {
        Self {
            projection,
            decision: PendingPluginApprovalDecision::Deny,
        }
    }

    #[cfg(test)]
    pub const fn decision(&self) -> PendingPluginApprovalDecision {
        self.decision
    }

    #[cfg(test)]
    pub fn projection(&self) -> &PendingPluginApprovalSurfaceProjection {
        &self.projection
    }

    #[cfg(test)]
    pub fn application_command(&self, actor_id: ActorId) -> PendingPluginApprovalDecisionCommand {
        self.projection.application_command(actor_id, self.decision)
    }
}

/// Project one durable Application projection only when it matches the exact
/// selected Tenant/Project/Mission and is still Pending.  Stale or terminal
/// requests are intentionally omitted so a reselect cannot display another
/// Mission's consent node.
pub fn project_pending_plugin_approval(
    selected_scope: Option<(&TenantId, &ProjectId, &MissionId)>,
    projection: PendingPluginApprovalProjection,
) -> Option<PendingPluginApprovalSurfaceProjection> {
    let (tenant_id, project_id, mission_id) = selected_scope?;
    let scope = projection.scope();
    if projection.state() != PendingPluginApprovalState::Pending
        || scope.tenant_id() != tenant_id
        || scope.project_id() != project_id
        || scope.mission_id() != mission_id
    {
        return None;
    }
    Some(PendingPluginApprovalSurfaceProjection::from_projection(
        projection,
    ))
}

fn short_digest(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{}…", hex::encode(digest)[..10].to_owned())
}

fn opaque_scope_label(scope: &PendingPluginApprovalScope) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"hartevo.desktop.pending-plugin-approval-scope/v1\0");
    hasher.update(scope.tenant_id().as_str().as_bytes());
    hasher.update([0]);
    hasher.update(scope.project_id().as_str().as_bytes());
    hasher.update([0]);
    hasher.update(scope.mission_id().as_str().as_bytes());
    format!("scope:{}", &hex::encode(hasher.finalize())[..10])
}

#[cfg(test)]
mod tests {
    use super::*;
    use hartevo_application::PendingPluginApprovalDecision;
    use serde_json::json;

    fn digest(letter: char) -> String {
        std::iter::repeat_n(letter, 64).collect()
    }

    fn projection(
        state: &str,
        tenant_id: &str,
        project_id: &str,
        mission_id: &str,
    ) -> PendingPluginApprovalProjection {
        serde_json::from_value(json!({
            "scope": {
                "tenantId": tenant_id,
                "projectId": project_id,
                "missionId": mission_id
            },
            "state": state,
            "pluginId": "plugin.seo",
            "pluginVersion": "1.4.0",
            "pluginDigest": digest('a'),
            "invocationId": "invocation-raw",
            "invocationDigest": digest('b'),
            "effectId": "effect-raw",
            "effectDigest": digest('c'),
            "requestDigest": digest('d'),
            "requestEventSequence": 17,
            "revisions": {
                "missionRevision": 41,
                "effectRevision": 41,
                "invocationRevision": 7,
                "consentRevision": 3
            },
            "currentMissionRevision": 41,
            "projectionDigest": digest('e')
        }))
        .expect("test projection is valid")
    }

    #[test]
    fn exact_pending_scope_projects_and_terminal_or_cross_scope_is_hidden() {
        let pending = projection("pending", "tenant-1", "project-1", "mission-1");
        let selected = (
            &TenantId::from("tenant-1"),
            &ProjectId::from("project-1"),
            &MissionId::from("mission-1"),
        );
        assert!(project_pending_plugin_approval(Some(selected), pending).is_some());
        assert!(
            project_pending_plugin_approval(
                Some((
                    &TenantId::from("tenant-1"),
                    &ProjectId::from("project-1"),
                    &MissionId::from("mission-2"),
                )),
                projection("pending", "tenant-1", "project-1", "mission-1")
            )
            .is_none()
        );
        assert!(
            project_pending_plugin_approval(
                Some(selected),
                projection("approved", "tenant-1", "project-1", "mission-1")
            )
            .is_none()
        );
        assert!(
            project_pending_plugin_approval(
                None,
                projection("pending", "tenant-1", "project-1", "mission-1")
            )
            .is_none()
        );
    }

    #[test]
    fn action_intent_replays_exact_application_fences_without_local_authority() {
        let selected = (
            &TenantId::from("tenant-1"),
            &ProjectId::from("project-1"),
            &MissionId::from("mission-1"),
        );
        let surface = project_pending_plugin_approval(
            Some(selected),
            projection("pending", "tenant-1", "project-1", "mission-1"),
        )
        .expect("exact pending surface");
        let action = PendingPluginApprovalAction::approve(surface.clone());
        let command = action.application_command(ActorId::from_stable("desktop-actor"));
        assert_eq!(action.decision(), PendingPluginApprovalDecision::Approve);
        assert_eq!(action.projection().request_event_sequence(), 17);
        assert_eq!(command.scope, *surface.scope());
        assert_eq!(command.plugin_digest, digest('a'));
        assert_eq!(command.invocation_digest, digest('b'));
        assert_eq!(command.effect_digest, digest('c'));
        assert_eq!(command.request_digest, digest('d'));
        assert_eq!(command.request_event_sequence, 17);
        assert_eq!(command.expected_mission_revision, 41);
        assert_eq!(command.expected_effect_revision, 41);
        assert_eq!(command.expected_consent_revision, Some(3));
        assert!(matches!(
            command.decision,
            PendingPluginApprovalDecision::Approve
        ));
        let deny = PendingPluginApprovalAction::deny(surface);
        let deny_command = deny.application_command(ActorId::from_stable("desktop-actor"));
        assert!(matches!(
            deny_command.decision,
            PendingPluginApprovalDecision::Deny
        ));
    }

    #[test]
    fn surface_debug_is_content_free_and_does_not_expose_raw_ids_or_full_digests() {
        let selected = (
            &TenantId::from("tenant-1"),
            &ProjectId::from("project-1"),
            &MissionId::from("mission-1"),
        );
        let surface = project_pending_plugin_approval(
            Some(selected),
            projection("pending", "tenant-1", "project-1", "mission-1"),
        )
        .expect("exact pending surface");
        let debug = format!("{surface:?}");
        assert!(!debug.contains("invocation-raw"));
        assert!(!debug.contains("effect-raw"));
        assert!(!debug.contains(&digest('a')));
        assert!(!debug.contains(&digest('d')));
        assert!(debug.contains("scope_bound"));
        let action = PendingPluginApprovalAction::deny(surface);
        let action_debug = format!("{action:?}");
        assert!(!action_debug.contains("invocation-raw"));
        assert!(!action_debug.contains(&digest('e')));
    }
}
