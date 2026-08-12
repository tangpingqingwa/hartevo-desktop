use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{BrowserSnapshotId, BrowserTabId, BrowserWorkspaceId};
use serde::Serialize;

use crate::workspace::{digest_json, is_bounded_identifier, is_sha256};
use crate::{
    BrowserElementRef, BrowserError, BrowserLeaseProof, BrowserNavigationPolicy, BrowserWorkspace,
};

const LOCATOR_SCHEMA_VERSION: u32 = 1;
const MAX_LOCATOR_ROLE_BYTES: usize = 128;
const MAX_ACCESSIBLE_NAME_BYTES: usize = 8 * 1_024;
const LOCATOR_LIFETIME: Duration = Duration::hours(1);

/// An in-memory, exact accessible-name locator. The cleartext selector is
/// intentionally neither serializable nor exposed through Debug; signed
/// production Recipes require a separate promotion contract.
#[derive(Clone, Eq, PartialEq)]
pub struct BrowserStableLocator {
    schema_version: u32,
    workspace_id: BrowserWorkspaceId,
    tab_id: BrowserTabId,
    identity_digest: String,
    origin_digest: String,
    policy_digest: String,
    role: String,
    accessible_name: String,
    selector_digest: String,
    evidence_digest: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl BrowserStableLocator {
    pub fn exact_accessible_name(
        workspace: &BrowserWorkspace,
        tab_id: BrowserTabId,
        policy: &BrowserNavigationPolicy,
        origin_digest: String,
        role: impl AsRef<str>,
        accessible_name: impl AsRef<str>,
        now: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        workspace.validate()?;
        let role = canonical_role(role.as_ref())?;
        let accessible_name = canonical_accessible_name(accessible_name.as_ref())?;
        let expires_at = now
            .checked_add_signed(LOCATOR_LIFETIME)
            .ok_or(BrowserError::CounterOverflow)?;
        let selector_digest = digest_json(&(
            LOCATOR_SCHEMA_VERSION,
            "exact_accessible_name",
            &role,
            &accessible_name,
        ))?;
        let evidence_digest = digest_json(&(
            LOCATOR_SCHEMA_VERSION,
            &workspace.id,
            &tab_id,
            &workspace.expected_identity_digest,
            &origin_digest,
            policy.evidence_digest(),
            &selector_digest,
            now,
            expires_at,
        ))?;
        let locator = Self {
            schema_version: LOCATOR_SCHEMA_VERSION,
            workspace_id: workspace.id.clone(),
            tab_id,
            identity_digest: workspace.expected_identity_digest.clone(),
            origin_digest,
            policy_digest: policy.evidence_digest().to_owned(),
            role,
            accessible_name,
            selector_digest,
            evidence_digest,
            created_at: now,
            expires_at,
        };
        locator.validate_shape()?;
        if !workspace.tabs.contains(&locator.tab_id) {
            return Err(BrowserError::StableLocatorInvalid);
        }
        Ok(locator)
    }

    pub fn selector_digest(&self) -> &str {
        &self.selector_digest
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub(crate) fn matches(&self, role: &str, accessible_name: &str) -> bool {
        canonical_role(role).is_ok_and(|role| role == self.role)
            && canonical_accessible_name(accessible_name)
                .is_ok_and(|name| name == self.accessible_name)
    }

    pub(crate) fn validate_for(
        &self,
        workspace: &BrowserWorkspace,
        tab_id: &BrowserTabId,
        proof: &BrowserLeaseProof,
        policy: &BrowserNavigationPolicy,
        current_origin_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<(), BrowserError> {
        self.validate_shape()?;
        workspace.validate_agent_lease(proof, now)?;
        if self.workspace_id != workspace.id
            || &self.tab_id != tab_id
            || self.identity_digest != workspace.expected_identity_digest
            || self.origin_digest != current_origin_digest
            || self.policy_digest != policy.evidence_digest()
            || now < self.created_at
            || now >= self.expires_at
        {
            return Err(if now >= self.expires_at {
                BrowserError::StableLocatorExpired
            } else {
                BrowserError::StableLocatorInvalid
            });
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), BrowserError> {
        let expected_selector = digest_json(&(
            LOCATOR_SCHEMA_VERSION,
            "exact_accessible_name",
            &self.role,
            &self.accessible_name,
        ))?;
        let expected_evidence = digest_json(&(
            LOCATOR_SCHEMA_VERSION,
            &self.workspace_id,
            &self.tab_id,
            &self.identity_digest,
            &self.origin_digest,
            &self.policy_digest,
            &self.selector_digest,
            self.created_at,
            self.expires_at,
        ))?;
        if self.schema_version != LOCATOR_SCHEMA_VERSION
            || !is_bounded_identifier(self.workspace_id.as_str())
            || !is_bounded_identifier(self.tab_id.as_str())
            || !is_sha256(&self.identity_digest)
            || !is_sha256(&self.origin_digest)
            || !is_sha256(&self.policy_digest)
            || !is_sha256(&self.selector_digest)
            || !is_sha256(&self.evidence_digest)
            || self.selector_digest != expected_selector
            || self.evidence_digest != expected_evidence
            || self.expires_at <= self.created_at
            || self.expires_at - self.created_at != LOCATOR_LIFETIME
            || canonical_role(&self.role).ok().as_deref() != Some(self.role.as_str())
            || canonical_accessible_name(&self.accessible_name)
                .ok()
                .as_deref()
                != Some(self.accessible_name.as_str())
        {
            return Err(BrowserError::StableLocatorInvalid);
        }
        Ok(())
    }
}

impl fmt::Debug for BrowserStableLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserStableLocator")
            .field("schema_version", &self.schema_version)
            .field("workspace_id", &self.workspace_id)
            .field("tab_id", &self.tab_id)
            .field("identity_digest", &self.identity_digest)
            .field("origin_digest", &self.origin_digest)
            .field("policy_digest", &self.policy_digest)
            .field("selector_digest", &self.selector_digest)
            .field("evidence_digest", &self.evidence_digest)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserLocatorResolution {
    pub schema_version: u32,
    pub workspace_id: BrowserWorkspaceId,
    pub tab_id: BrowserTabId,
    pub snapshot_id: BrowserSnapshotId,
    pub lease_generation: u64,
    pub document_generation: u64,
    pub locator_evidence_digest: String,
    pub selector_digest: String,
    pub url_digest: String,
    pub origin_digest: String,
    pub policy_digest: String,
    pub element_ref: BrowserElementRef,
    pub resolved_at: DateTime<Utc>,
}

impl BrowserLocatorResolution {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        workspace_id: BrowserWorkspaceId,
        tab_id: BrowserTabId,
        snapshot_id: BrowserSnapshotId,
        lease_generation: u64,
        document_generation: u64,
        locator_evidence_digest: String,
        selector_digest: String,
        url_digest: String,
        origin_digest: String,
        policy_digest: String,
        element_ref: BrowserElementRef,
        resolved_at: DateTime<Utc>,
    ) -> Result<Self, BrowserError> {
        let resolution = Self {
            schema_version: LOCATOR_SCHEMA_VERSION,
            workspace_id,
            tab_id,
            snapshot_id,
            lease_generation,
            document_generation,
            locator_evidence_digest,
            selector_digest,
            url_digest,
            origin_digest,
            policy_digest,
            element_ref,
            resolved_at,
        };
        resolution.validate()?;
        Ok(resolution)
    }

    pub fn evidence_digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }

    pub(crate) fn validate(&self) -> Result<(), BrowserError> {
        if self.schema_version != LOCATOR_SCHEMA_VERSION
            || !is_bounded_identifier(self.workspace_id.as_str())
            || !is_bounded_identifier(self.tab_id.as_str())
            || !is_bounded_identifier(self.snapshot_id.as_str())
            || self.lease_generation == 0
            || self.document_generation == 0
            || !is_sha256(&self.locator_evidence_digest)
            || !is_sha256(&self.selector_digest)
            || !is_sha256(&self.url_digest)
            || !is_sha256(&self.origin_digest)
            || !is_sha256(&self.policy_digest)
            || !is_bounded_identifier(&self.element_ref.reference)
            || !is_sha256(&self.element_ref.locator_digest)
            || !self.element_ref.unique
        {
            return Err(BrowserError::StableLocatorInvalid);
        }
        Ok(())
    }
}

impl fmt::Debug for BrowserLocatorResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserLocatorResolution")
            .field("schema_version", &self.schema_version)
            .field("workspace_id", &self.workspace_id)
            .field("tab_id", &self.tab_id)
            .field("snapshot_id", &self.snapshot_id)
            .field("lease_generation", &self.lease_generation)
            .field("document_generation", &self.document_generation)
            .field("locator_evidence_digest", &self.locator_evidence_digest)
            .field("selector_digest", &self.selector_digest)
            .field("url_digest", &self.url_digest)
            .field("origin_digest", &self.origin_digest)
            .field("policy_digest", &self.policy_digest)
            .field("element_ref", &self.element_ref)
            .field("resolved_at", &self.resolved_at)
            .finish()
    }
}

pub(crate) fn canonical_role(value: &str) -> Result<String, BrowserError> {
    if value.is_empty()
        || value.len() > MAX_LOCATOR_ROLE_BYTES
        || value.trim() != value
        || !value.is_ascii()
        || value.chars().any(char::is_control)
    {
        return Err(BrowserError::StableLocatorInvalid);
    }
    let value = value.to_ascii_lowercase();
    if !matches!(
        value.as_str(),
        "button"
            | "link"
            | "textbox"
            | "searchbox"
            | "checkbox"
            | "radio"
            | "combobox"
            | "menuitem"
            | "tab"
            | "switch"
            | "slider"
            | "spinbutton"
    ) {
        return Err(BrowserError::StableLocatorInvalid);
    }
    Ok(value)
}

pub(crate) fn canonical_accessible_name(value: &str) -> Result<String, BrowserError> {
    if value.is_empty()
        || value.len() > MAX_ACCESSIBLE_NAME_BYTES
        || value
            .chars()
            .any(|character| character.is_control() && !character.is_whitespace())
    {
        return Err(BrowserError::StableLocatorInvalid);
    }
    let canonical = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if canonical.is_empty() || canonical.len() > MAX_ACCESSIBLE_NAME_BYTES {
        return Err(BrowserError::StableLocatorInvalid);
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_domain_kernel::{
        AccountId, BrowserControlLeaseId, BrowserProfileId, Mission, MissionContract, MissionId,
        Project, ProjectId, StorageMode, TenantId,
    };

    use super::*;
    use crate::workspace::digest;
    use crate::{BrowserAction, BrowserIdentity, BrowserProfile, BrowserTextInput};

    fn fixture() -> (BrowserWorkspace, BrowserNavigationPolicy, DateTime<Utc>) {
        let now = Utc
            .with_ymd_and_hms(2026, 8, 11, 8, 0, 0)
            .single()
            .expect("time");
        let project = Project::create_local(
            TenantId::from("tenant-locator"),
            ProjectId::from("project-locator"),
            "Locator",
            "",
            "/workspace/locator",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-locator"),
            project.id.clone(),
            "Locator mission",
            MissionContract::bootstrap("Resolve safely", ["browser.read".into()], now),
            now,
        )
        .expect("mission");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-locator"),
            &project,
            "credential-manager://profile-locator",
            BrowserIdentity::new(
                "provider-locator",
                AccountId::from("account-locator"),
                "1".repeat(64),
                "2".repeat(64),
                now,
            )
            .expect("identity"),
            now,
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-locator"),
            &project,
            &mission,
            &profile,
            BrowserTabId::from("tab-locator"),
            BrowserControlLeaseId::from("lease-locator"),
            now + Duration::hours(2),
            "3".repeat(64),
            now,
        )
        .expect("workspace");
        let policy = BrowserNavigationPolicy::https_only(["https://example.com"]).expect("policy");
        (workspace, policy, now)
    }

    #[test]
    fn exact_locator_is_bounded_scope_and_debug_redacted() {
        let (workspace, policy, now) = fixture();
        let origin_digest = digest(b"https://example.com");
        let locator = BrowserStableLocator::exact_accessible_name(
            &workspace,
            BrowserTabId::from("tab-locator"),
            &policy,
            origin_digest.clone(),
            "BUTTON",
            "  Review\nprivate order  ",
            now,
        )
        .expect("locator");

        assert!(locator.matches("button", "Review private order"));
        assert!(!format!("{locator:?}").contains("private order"));
        assert_eq!(locator.expires_at(), now + Duration::hours(1));
        let proof = workspace.agent_lease_proof(now).expect("lease proof");
        locator
            .validate_for(
                &workspace,
                &BrowserTabId::from("tab-locator"),
                &proof,
                &policy,
                &origin_digest,
                now,
            )
            .expect("current exact scope");
        assert_eq!(
            locator
                .validate_for(
                    &workspace,
                    &BrowserTabId::from("tab-locator"),
                    &proof,
                    &policy,
                    &origin_digest,
                    now + Duration::hours(1),
                )
                .expect_err("locator expires exactly at its deadline")
                .code(),
            "BROWSER_STABLE_LOCATOR_EXPIRED"
        );
    }

    #[test]
    fn locator_rejects_noninteractive_empty_or_unbounded_selectors() {
        let (workspace, policy, now) = fixture();
        for (role, name) in [
            ("heading", "Review"),
            ("button", ""),
            ("button\n", "Review"),
        ] {
            assert_eq!(
                BrowserStableLocator::exact_accessible_name(
                    &workspace,
                    BrowserTabId::from("tab-locator"),
                    &policy,
                    digest(b"https://example.com"),
                    role,
                    name,
                    now,
                )
                .expect_err("invalid selector")
                .code(),
                "BROWSER_STABLE_LOCATOR_INVALID"
            );
        }
    }

    #[test]
    fn semantic_click_binds_the_exact_resolution_without_claiming_visibility() {
        let (workspace, policy, now) = fixture();
        let resolution = BrowserLocatorResolution::new(
            workspace.id.clone(),
            BrowserTabId::from("tab-locator"),
            BrowserSnapshotId::from("snapshot-locator"),
            workspace.lease_generation,
            2,
            "4".repeat(64),
            "5".repeat(64),
            "6".repeat(64),
            digest(b"https://example.com"),
            policy.evidence_digest().to_owned(),
            BrowserElementRef {
                reference: "ax-1-fixture".into(),
                locator_digest: "7".repeat(64),
                visible: false,
                unique: true,
            },
            now,
        )
        .expect("resolution");

        let click = BrowserAction::semantic_click(1, &resolution).expect("semantic click");
        assert_eq!(click.snapshot_id.as_ref(), Some(&resolution.snapshot_id));
        assert_eq!(click.element_ref.as_deref(), Some("ax-1-fixture"));
        assert_eq!(
            click.payload_digest,
            resolution.evidence_digest().expect("resolution digest")
        );
        assert!(!resolution.element_ref.visible);
    }

    #[test]
    fn semantic_text_input_binds_content_without_serializing_or_debugging_cleartext() {
        let (workspace, policy, now) = fixture();
        let resolution = BrowserLocatorResolution::new(
            workspace.id.clone(),
            BrowserTabId::from("tab-locator"),
            BrowserSnapshotId::from("snapshot-text-locator"),
            workspace.lease_generation,
            2,
            "4".repeat(64),
            "5".repeat(64),
            "6".repeat(64),
            digest(b"https://example.com"),
            policy.evidence_digest().to_owned(),
            BrowserElementRef {
                reference: "ax-2-text-fixture".into(),
                locator_digest: "7".repeat(64),
                visible: false,
                unique: true,
            },
            now,
        )
        .expect("resolution");
        let secret = "customer+private@example.com 日本語";
        let input = BrowserTextInput::new(secret).expect("bounded input");
        let action = BrowserAction::semantic_text_input(1, &resolution, &input)
            .expect("semantic text input");
        assert_eq!(action.kind, crate::BrowserActionKind::KeyboardInput);
        assert_eq!(action.surface, crate::BrowserActionSurface::Semantic);
        assert_eq!(
            input.byte_len(),
            u32::try_from(secret.len()).expect("bounded byte length")
        );
        assert_eq!(
            input.utf16_len(),
            u32::try_from(secret.encode_utf16().count()).expect("bounded UTF-16 length")
        );
        assert_eq!(
            action.payload_digest,
            BrowserAction::semantic_text_input_payload_digest(&resolution, &input)
                .expect("payload digest")
        );
        let serialized = serde_json::to_string(&action).expect("serialize action");
        let input_debug = format!("{input:?}");
        assert!(!serialized.contains(secret));
        assert!(!input_debug.contains(secret));
        assert!(input_debug.contains("redacted"));

        for rejected in ["", "line\rbreak", "nul\0byte"] {
            assert_eq!(
                BrowserTextInput::new(rejected)
                    .expect_err("unsupported text")
                    .code(),
                "BROWSER_INVALID_TEXT_INPUT"
            );
        }
    }
}
