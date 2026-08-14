use std::{collections::BTreeSet, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{NetlifyDeploymentError, NetlifyTransportError, Result};
use crate::model::{
    ConsentScope, DeploymentProjection, Digest, MAX_PAGES, MAX_POLL_ATTEMPTS, MissionProjection,
    NetlifyDeploymentEvidenceState, NetlifyDeploymentMetadata, NetlifyDeploymentScope,
    OpaqueCursor, PermissionSnapshot, ProjectProjection, SecretReference, TransportProvenance,
    WorkProductProjection,
};
use crate::provider::{
    NetlifyOperation, NetlifyProvider, NetlifyProviderDefinition, NetlifyTransport,
};
use crate::{
    CONTRACT_DIGEST, CONTRACT_SCHEMA, CONTRACT_VERSION, MISSION_CONSUMER_ID, PLUGIN_VERSION,
    PROVIDER_ID, SERVICE_ID, contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub registration_revision: u64,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        registration_revision: u64,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "netlify-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("new", format!("{new_status:?}")),
                ("revision", registration_revision.to_string()),
                ("registration", registration_digest.as_str().to_owned()),
            ],
        );
        Self {
            previous_status,
            new_status,
            registration_revision,
            registration_digest,
            transition_digest,
        }
    }
}

/// Version, API/provider, permission, consent, exact site/deploy scope, and
/// opaque-secret bound registration.
#[derive(Clone, Eq, PartialEq)]
pub struct NetlifyDeploymentRegistration {
    id_digest: Digest,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_api_revision: String,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: NetlifyDeploymentScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl NetlifyDeploymentRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: NetlifyDeploymentScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &NetlifyProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let id_digest = Digest::from_text(id.into());
        let mut registration = Self {
            id_digest,
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_api_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_snapshot,
            consent,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-netlify-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate()?;
        Ok(registration)
    }

    #[must_use]
    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    #[must_use]
    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    #[must_use]
    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    #[must_use]
    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    #[must_use]
    pub fn provider_release(&self) -> &str {
        &self.provider_release
    }

    #[must_use]
    pub fn provider_api_revision(&self) -> &str {
        &self.provider_api_revision
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    #[must_use]
    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    #[must_use]
    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest()
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    #[must_use]
    pub fn scope(&self) -> &NetlifyDeploymentScope {
        &self.scope
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    #[must_use]
    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    #[must_use]
    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<()> {
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.provider_api_revision != crate::NETLIFY_PROVIDER_API_REVISION
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.calculate_digest()
        {
            return Err(NetlifyDeploymentError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.consent.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        if self
            .permission_snapshot
            .permissions
            .iter()
            .any(|permission| !self.consent.permissions().contains(permission))
        {
            return Err(NetlifyDeploymentError::InvalidConsent);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(NetlifyDeploymentError::RegistrationReversed);
        }
        if matches!(self.status, RegistrationStatus::Revoked) {
            return Err(NetlifyDeploymentError::AlreadyRevoked);
        }
        let previous_status = self.status;
        self.bump_revision()?;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_revision,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(NetlifyDeploymentError::AlreadyReversed);
        }
        let previous_status = self.status;
        self.bump_revision()?;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_revision,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(NetlifyDeploymentError::RegistrationReversed);
        }
        if matches!(self.status, RegistrationStatus::Active) {
            return Err(NetlifyDeploymentError::InvalidRegistration);
        }
        let previous_status = self.status;
        self.bump_revision()?;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.calculate_digest();
        self.validate()?;
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_revision,
            self.registration_digest.clone(),
        ))
    }

    fn bump_revision(&mut self) -> Result<()> {
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(NetlifyDeploymentError::RevisionOverflow)?;
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "netlify-registration/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("plugin", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider_api", self.provider_api_revision.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("consent", self.consent_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "site_allowlist",
                    self.scope.site_allowlist_digest().as_str().to_owned(),
                ),
                (
                    "deploy_allowlist",
                    self.scope.deploy_allowlist_digest().as_str().to_owned(),
                ),
                ("secret", self.secret_reference_digest().as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

impl fmt::Debug for NetlifyDeploymentRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetlifyDeploymentRegistration")
            .field("id_digest", &self.id_digest)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_api_revision", &self.provider_api_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for NetlifyDeploymentRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("NetlifyDeploymentRegistration", 18)?;
        state.serialize_field("idDigest", &self.id_digest)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerApiRevision", &self.provider_api_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("siteAllowlistDigest", &self.scope.site_allowlist_digest())?;
        state.serialize_field(
            "deployAllowlistDigest",
            &self.scope.deploy_allowlist_digest(),
        )?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetlifyDeploymentServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl Default for NetlifyDeploymentServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: MISSION_CONSUMER_ID.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())
                .expect("static Netlify contract digest is valid"),
            read_only: true,
            proposal_only: true,
            live_execution: false,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub outcome_adoption: bool,
    pub max_pages: u16,
    pub max_poll_attempts: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: NetlifyOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn new(operation: NetlifyOperation, error: &NetlifyDeploymentError) -> Self {
        let (category, status_code) = match error {
            NetlifyDeploymentError::Transport(transport) => {
                (transport.category().to_owned(), transport.status_code())
            }
            NetlifyDeploymentError::TamperedEvidence => ("tampered".to_owned(), None),
            NetlifyDeploymentError::ScopeMismatch => ("scope_mismatch".to_owned(), None),
            NetlifyDeploymentError::StaleCommit => ("stale_commit".to_owned(), None),
            NetlifyDeploymentError::PaginationLoop => ("pagination_loop".to_owned(), None),
            NetlifyDeploymentError::InvalidResponse => ("malformed_response".to_owned(), None),
            NetlifyDeploymentError::Expired => ("expired".to_owned(), None),
            _ => ("provider_unknown".to_owned(), None),
        };
        let failure_digest = Digest::from_parts(
            "netlify-failure/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("category", category.clone()),
                (
                    "status",
                    status_code.map_or_else(String::new, |status| status.to_string()),
                ),
            ],
        );
        Self {
            operation,
            status_code,
            category,
            failure_digest,
        }
    }

    #[must_use]
    fn digest(&self) -> Digest {
        Digest::from_parts(
            "netlify-failure-evidence/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                ("category", self.category.clone()),
                (
                    "status",
                    self.status_code
                        .map_or_else(String::new, |status| status.to_string()),
                ),
                ("failure", self.failure_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub site_allowlist_digest: Digest,
    pub deploy_allowlist_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub list_digest: Option<Digest>,
    pub deploy_digest: Option<Digest>,
    pub manifest_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    fn content_digest(&self) -> Digest {
        Digest::from_parts(
            "netlify-evidence-digests/v1",
            &[
                ("plugin", self.plugin_version_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "site_allowlist",
                    self.site_allowlist_digest.as_str().to_owned(),
                ),
                (
                    "deploy_allowlist",
                    self.deploy_allowlist_digest.as_str().to_owned(),
                ),
                (
                    "cursor",
                    self.cursor_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "list",
                    self.list_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "deploy",
                    self.deploy_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "manifest",
                    self.manifest_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetlifyPreviewDecision {
    ReadyForReview,
    Pending,
    Blocked,
}

impl NetlifyPreviewDecision {
    fn from_state(state: NetlifyDeploymentEvidenceState) -> Self {
        if state.is_preview_ready() {
            Self::ReadyForReview
        } else if matches!(
            state,
            NetlifyDeploymentEvidenceState::New
                | NetlifyDeploymentEvidenceState::Preparing
                | NetlifyDeploymentEvidenceState::Prepared
                | NetlifyDeploymentEvidenceState::Uploading
                | NetlifyDeploymentEvidenceState::Uploaded
        ) {
            Self::Pending
        } else {
            Self::Blocked
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetlifyDeploymentEvidence {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub state: NetlifyDeploymentEvidenceState,
    pub preview_decision: NetlifyPreviewDecision,
    pub list_pages: u16,
    pub poll_attempts: u8,
    pub listing_complete: bool,
    pub deployment: Option<DeploymentProjection>,
    pub failure: Option<FailureEvidence>,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub content_verified: bool,
}

impl NetlifyDeploymentEvidence {
    fn new(
        registration: &NetlifyDeploymentRegistration,
        state: NetlifyDeploymentEvidenceState,
        list_pages: u16,
        poll_attempts: u8,
        listing_complete: bool,
        deployment: Option<&NetlifyDeploymentMetadata>,
        failure: Option<FailureEvidence>,
        provenance: TransportProvenance,
        list_digests: &[Digest],
        cursor_digests: &[Digest],
    ) -> Self {
        let list_digest = (!list_digests.is_empty()).then(|| {
            Digest::from_parts(
                "netlify-list-pages/v1",
                &[(
                    "pages",
                    list_digests
                        .iter()
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                )],
            )
        });
        let cursor_digest = (!cursor_digests.is_empty()).then(|| {
            Digest::from_parts(
                "netlify-cursors/v1",
                &[(
                    "cursors",
                    cursor_digests
                        .iter()
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                )],
            )
        });
        let deployment_projection = deployment.map(DeploymentProjection::from);
        let manifest_digest = deployment_projection
            .as_ref()
            .map(|projection| projection.file_manifest.digest());
        let evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: registration.provider_digest.clone(),
            permission_digest: registration.permission_digest(),
            consent_digest: registration.consent_digest(),
            scope_digest: registration.scope_digest.clone(),
            site_allowlist_digest: registration.scope.site_allowlist_digest(),
            deploy_allowlist_digest: registration.scope.deploy_allowlist_digest(),
            cursor_digest,
            list_digest,
            deploy_digest: deployment_projection
                .as_ref()
                .map(|projection| projection.metadata_digest.clone()),
            manifest_digest,
            evidence_digest: Digest::from_text("unsealed-netlify-evidence"),
        };
        let mut result = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: MISSION_CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            project: ProjectProjection::from(registration.scope.project()),
            mission: MissionProjection::from(registration.scope.mission()),
            work_product: WorkProductProjection::from(registration.scope.work_product()),
            state,
            preview_decision: NetlifyPreviewDecision::from_state(state),
            list_pages,
            poll_attempts,
            listing_complete,
            deployment: deployment_projection,
            failure,
            evidence,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            content_verified: false,
        };
        result.evidence.evidence_digest = result.calculate_evidence_digest();
        result
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.evidence.evidence_digest.clone()
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != MISSION_CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.content_verified
            || self.preview_decision != NetlifyPreviewDecision::from_state(self.state)
            || self.evidence.evidence_digest != self.calculate_evidence_digest()
        {
            return Err(NetlifyDeploymentError::TamperedEvidence);
        }
        if let Some(deployment) = &self.deployment {
            if deployment.deploy_url_is_verified
                || deployment.metadata_digest != deployment_projection_metadata_digest(deployment)
            {
                return Err(NetlifyDeploymentError::TamperedEvidence);
            }
            deployment.file_manifest.validate()?;
        }
        if let Some(failure) = &self.failure {
            Digest::parse(failure.failure_digest.as_str().to_owned())?;
        }
        Ok(())
    }

    fn calculate_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "netlify-deployment-evidence/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "project",
                    projection_digest(&self.project).as_str().to_owned(),
                ),
                (
                    "mission",
                    projection_digest(&self.mission).as_str().to_owned(),
                ),
                (
                    "work_product",
                    projection_digest(&self.work_product).as_str().to_owned(),
                ),
                ("state", format!("{:?}", self.state)),
                ("decision", format!("{:?}", self.preview_decision)),
                ("list_pages", self.list_pages.to_string()),
                ("poll_attempts", self.poll_attempts.to_string()),
                ("listing_complete", self.listing_complete.to_string()),
                (
                    "deployment",
                    self.deployment
                        .as_ref()
                        .map_or_else(String::new, |deployment| {
                            projection_digest(deployment).as_str().to_owned()
                        }),
                ),
                (
                    "failure",
                    self.failure
                        .as_ref()
                        .map_or_else(String::new, |failure| failure.digest().as_str().to_owned()),
                ),
                (
                    "digests",
                    self.evidence.content_digest().as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetlifyDeploymentProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub state: NetlifyDeploymentEvidenceState,
    pub preview_decision: NetlifyPreviewDecision,
    pub deployment: Option<DeploymentProjection>,
    pub failure: Option<FailureEvidence>,
    pub evidence: NetlifyDeploymentEvidence,
    pub provenance: TransportProvenance,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub content_verified: bool,
    pub proposal_digest: Digest,
}

impl NetlifyDeploymentProposal {
    fn from_evidence(evidence: NetlifyDeploymentEvidence) -> Self {
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: MISSION_CONSUMER_ID.to_owned(),
            registration_digest: evidence.registration_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            project: evidence.project.clone(),
            mission: evidence.mission.clone(),
            work_product: evidence.work_product.clone(),
            state: evidence.state,
            preview_decision: evidence.preview_decision,
            deployment: evidence.deployment.clone(),
            failure: evidence.failure.clone(),
            provenance: evidence.provenance.clone(),
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            content_verified: false,
            proposal_digest: Digest::from_text("unsealed-netlify-proposal"),
            evidence,
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.proposal_digest.clone()
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate_integrity()?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != MISSION_CONSUMER_ID
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.content_verified
            || self.registration_digest != self.evidence.registration_digest
            || self.scope_digest != self.evidence.scope_digest
            || self.state != self.evidence.state
            || self.preview_decision != self.evidence.preview_decision
            || self.deployment != self.evidence.deployment
            || self.failure != self.evidence.failure
            || self.provenance != self.evidence.provenance
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(NetlifyDeploymentError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "netlify-deployment-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "project",
                    projection_digest(&self.project).as_str().to_owned(),
                ),
                (
                    "mission",
                    projection_digest(&self.mission).as_str().to_owned(),
                ),
                (
                    "work_product",
                    projection_digest(&self.work_product).as_str().to_owned(),
                ),
                ("state", format!("{:?}", self.state)),
                ("decision", format!("{:?}", self.preview_decision)),
                (
                    "deployment",
                    self.deployment
                        .as_ref()
                        .map_or_else(String::new, |deployment| {
                            projection_digest(deployment).as_str().to_owned()
                        }),
                ),
                (
                    "failure",
                    self.failure
                        .as_ref()
                        .map_or_else(String::new, |failure| failure.digest().as_str().to_owned()),
                ),
                ("evidence", self.evidence.digest().as_str().to_owned()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    Tampered,
    RegistrationRevoked,
    ScopeMismatch,
    StaleCommit,
    Partial,
    Expired,
    AccessLoss,
    NotReady,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub proposal_digest: Digest,
    pub integrity_verified: bool,
    pub ready_preview: bool,
    pub content_verified: bool,
    pub adoptable: bool,
    pub failures: Vec<VerificationFailure>,
}

impl VerificationReport {
    #[must_use]
    pub fn verified(&self) -> bool {
        self.integrity_verified && self.ready_preview && self.failures.is_empty()
    }
}

pub struct NetlifyDeploymentService<T: NetlifyTransport> {
    provider: NetlifyProvider<T>,
    registration: NetlifyDeploymentRegistration,
    definition: NetlifyDeploymentServiceDefinition,
}

impl<T: NetlifyTransport> fmt::Debug for NetlifyDeploymentService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetlifyDeploymentService")
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: NetlifyTransport> NetlifyDeploymentService<T> {
    pub fn new(
        provider: NetlifyProvider<T>,
        registration: NetlifyDeploymentRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.scope_digest() != &provider.scope().digest()
            || registration.provider_digest() != &provider.definition().provider_digest
            || registration.secret_reference_digest()
                != provider.secret_reference().reference_digest()
        {
            return Err(NetlifyDeploymentError::InvalidRegistration);
        }
        Ok(Self {
            provider,
            registration,
            definition: NetlifyDeploymentServiceDefinition::default(),
        })
    }

    pub fn register(
        provider: NetlifyProvider<T>,
        registration_id: impl Into<String>,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = NetlifyDeploymentRegistration::new(
            registration_id,
            provider.scope().clone(),
            provider.secret_reference().clone(),
            permission_snapshot,
            consent,
            provider.definition(),
            registration_revision,
        )?;
        Self::new(provider, registration)
    }

    #[must_use]
    pub fn service_definition(&self) -> &NetlifyDeploymentServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider(&self) -> &NetlifyProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut NetlifyProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &NetlifyDeploymentScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &NetlifyDeploymentRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut NetlifyDeploymentRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: MISSION_CONSUMER_ID.to_owned(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "describe_scope".to_owned(),
                "read_site_deploys".to_owned(),
                "read_deploy_state".to_owned(),
                "read_file_manifest_metadata".to_owned(),
                "compile_verified_preview_proposal".to_owned(),
                "record_observation".to_owned(),
                "verify_proposal".to_owned(),
            ],
            permissions: self
                .registration
                .permission_snapshot
                .permissions
                .iter()
                .cloned()
                .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            outcome_adoption: false,
            max_pages: MAX_PAGES,
            max_poll_attempts: MAX_POLL_ATTEMPTS,
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn read(&mut self, observed_at: u64) -> Result<NetlifyDeploymentEvidence> {
        self.read_bounded(observed_at, MAX_PAGES, MAX_POLL_ATTEMPTS)
    }

    pub fn read_bounded(
        &mut self,
        observed_at: u64,
        max_pages: u16,
        max_poll_attempts: u8,
    ) -> Result<NetlifyDeploymentEvidence> {
        self.ensure_active(observed_at)?;
        if max_pages == 0
            || max_pages > MAX_PAGES
            || max_poll_attempts == 0
            || max_poll_attempts > MAX_POLL_ATTEMPTS
        {
            return Err(NetlifyDeploymentError::InvalidRequest);
        }

        for attempt in 1..=max_poll_attempts {
            let scan = self.scan_once(max_pages, attempt);
            if let Some(error) = &scan.error {
                let state = state_for_error(error);
                let failure = FailureEvidence::new(scan.operation, error);
                return Ok(self.build_evidence(state, scan, attempt, None, Some(failure)));
            }
            let Some(deployment) = scan.deployment.clone() else {
                let error = NetlifyDeploymentError::Transport(NetlifyTransportError::NotFound);
                let failure = FailureEvidence::new(NetlifyOperation::ListSiteDeploys, &error);
                return Ok(self.build_evidence(
                    NetlifyDeploymentEvidenceState::NotFound,
                    scan,
                    attempt,
                    None,
                    Some(failure),
                ));
            };
            if deployment.is_expired_at(observed_at) {
                let error = NetlifyDeploymentError::Expired;
                let failure = FailureEvidence::new(NetlifyOperation::GetDeploy, &error);
                return Ok(self.build_evidence(
                    NetlifyDeploymentEvidenceState::Expired,
                    scan,
                    attempt,
                    Some(deployment),
                    Some(failure),
                ));
            }
            if deployment.commit_digest != *self.scope().commit_digest() {
                let error = NetlifyDeploymentError::StaleCommit;
                let failure = FailureEvidence::new(NetlifyOperation::GetDeploy, &error);
                return Ok(self.build_evidence(
                    NetlifyDeploymentEvidenceState::StaleCommit,
                    scan,
                    attempt,
                    Some(deployment),
                    Some(failure),
                ));
            }
            let state = NetlifyDeploymentEvidenceState::from(&deployment.state);
            if !deployment.state.is_pending() {
                return Ok(self.build_evidence(state, scan, attempt, Some(deployment), None));
            }
            if attempt == max_poll_attempts {
                return Ok(self.build_evidence(
                    NetlifyDeploymentEvidenceState::Partial,
                    scan,
                    attempt,
                    Some(deployment),
                    Some(FailureEvidence {
                        operation: NetlifyOperation::GetDeploy,
                        status_code: None,
                        category: "poll_bound".to_owned(),
                        failure_digest: Digest::from_parts(
                            "netlify-failure/v1",
                            &[("category", "poll_bound".to_owned())],
                        ),
                    }),
                ));
            }
        }
        Err(NetlifyDeploymentError::InvalidResponse)
    }

    pub fn compile_proposal(&mut self, observed_at: u64) -> Result<NetlifyDeploymentProposal> {
        let evidence = self.read(observed_at)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: NetlifyDeploymentEvidence,
    ) -> Result<NetlifyDeploymentProposal> {
        self.ensure_registration_active()?;
        evidence.validate_integrity()?;
        if evidence.registration_digest != *self.registration.registration_digest()
            || evidence.scope_digest != *self.registration.scope_digest()
        {
            return Err(NetlifyDeploymentError::ScopeMismatch);
        }
        Ok(NetlifyDeploymentProposal::from_evidence(evidence))
    }

    pub fn verify(&self, proposal: &NetlifyDeploymentProposal) -> VerificationReport {
        let mut failures = Vec::new();
        let integrity_verified = proposal.validate_integrity().is_ok();
        if !integrity_verified {
            failures.push(VerificationFailure::Tampered);
        }
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationRevoked);
        }
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != *self.registration.scope_digest()
        {
            failures.push(VerificationFailure::ScopeMismatch);
        }
        if let Some(deployment) = &proposal.deployment {
            if deployment.commit_digest != *self.scope().commit_digest() {
                failures.push(VerificationFailure::StaleCommit);
            }
            if deployment
                .expires_at
                .is_some_and(|expires_at| expires_at == 0)
            {
                failures.push(VerificationFailure::Expired);
            }
        }
        match proposal.state {
            NetlifyDeploymentEvidenceState::Ready => {}
            NetlifyDeploymentEvidenceState::Expired => failures.push(VerificationFailure::Expired),
            NetlifyDeploymentEvidenceState::AccessLoss => {
                failures.push(VerificationFailure::AccessLoss);
            }
            NetlifyDeploymentEvidenceState::Partial => failures.push(VerificationFailure::Partial),
            NetlifyDeploymentEvidenceState::StaleCommit => {
                failures.push(VerificationFailure::StaleCommit);
            }
            NetlifyDeploymentEvidenceState::Tampered => {
                failures.push(VerificationFailure::Tampered);
            }
            NetlifyDeploymentEvidenceState::ProviderUnknown
            | NetlifyDeploymentEvidenceState::Conflict
            | NetlifyDeploymentEvidenceState::Timeout => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            _ => failures.push(VerificationFailure::NotReady),
        }
        failures.sort_unstable();
        failures.dedup();
        let ready_preview = failures.is_empty() && proposal.state.is_preview_ready();
        VerificationReport {
            proposal_digest: proposal.proposal_digest.clone(),
            integrity_verified,
            ready_preview,
            content_verified: false,
            adoptable: false,
            failures,
        }
    }

    pub fn verify_proposal(
        &self,
        proposal: &NetlifyDeploymentProposal,
    ) -> Result<VerificationReport> {
        let report = self.verify(proposal);
        if report.failures.contains(&VerificationFailure::Tampered) {
            Err(NetlifyDeploymentError::TamperedEvidence)
        } else {
            Ok(report)
        }
    }

    pub fn consumer(&self) -> Result<crate::consumer::MissionNetlifyDeploymentConsumer> {
        crate::consumer::MissionNetlifyDeploymentConsumer::new(
            self.scope().clone(),
            self.registration.clone(),
        )
    }

    fn ensure_registration_active(&self) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            Err(NetlifyDeploymentError::RegistrationInactive)
        } else {
            Ok(())
        }
    }

    fn ensure_active(&self, observed_at: u64) -> Result<()> {
        self.ensure_registration_active()?;
        if !self.registration.consent.is_active_at(observed_at) {
            return Err(NetlifyDeploymentError::ConsentMismatch);
        }
        Ok(())
    }

    fn scan_once(&mut self, max_pages: u16, attempt: u8) -> ScanObservation {
        let mut cursor: Option<OpaqueCursor> = None;
        let mut seen_cursors = BTreeSet::new();
        let mut list_digests = Vec::new();
        let mut cursor_digests = Vec::new();
        let mut target: Option<NetlifyDeploymentMetadata> = None;
        let mut list_pages = 0;
        let mut listing_complete = false;
        let mut error = None;
        let mut operation = NetlifyOperation::ListSiteDeploys;

        for page_number in 1..=max_pages {
            let page = match self.provider.list_site_deploys(cursor.as_ref(), attempt) {
                Ok(page) => page,
                Err(provider_error) => {
                    error = Some(provider_error);
                    break;
                }
            };
            list_pages = page_number;
            list_digests.push(page.response_digest.clone());
            for deployment in &page.deploys {
                if deployment.deploy_id_digest == self.scope().deploy_id().digest() {
                    if let Some(previous) = &target {
                        if previous.identity_digest() != deployment.identity_digest() {
                            error = Some(NetlifyDeploymentError::TamperedEvidence);
                            break;
                        }
                    }
                    target = Some(deployment.clone());
                }
            }
            if error.is_some() {
                break;
            }
            let Some(next_cursor) = page.next_cursor() else {
                listing_complete = true;
                break;
            };
            let cursor_digest = next_cursor.digest().clone();
            if !seen_cursors.insert(cursor_digest.clone()) {
                error = Some(NetlifyDeploymentError::PaginationLoop);
                break;
            }
            cursor_digests.push(cursor_digest);
            if page_number == max_pages {
                error = Some(NetlifyDeploymentError::PaginationLoop);
                break;
            }
            cursor = Some(next_cursor);
        }

        if error.is_none() && !listing_complete {
            error = Some(NetlifyDeploymentError::PaginationLoop);
        }
        if error.is_none() && target.is_some() {
            operation = NetlifyOperation::GetDeploy;
            match self.provider.get_deploy(attempt) {
                Ok(detail) => {
                    if target.as_ref().is_some_and(|summary| {
                        summary.identity_digest() != detail.identity_digest()
                    }) {
                        error = Some(NetlifyDeploymentError::TamperedEvidence);
                    } else {
                        target = Some(detail);
                    }
                }
                Err(provider_error) => error = Some(provider_error),
            }
        }
        ScanObservation {
            list_pages,
            listing_complete,
            deployment: target,
            error,
            operation,
            list_digests,
            cursor_digests,
            provenance: self.provider.provenance(),
        }
    }

    fn build_evidence(
        &self,
        state: NetlifyDeploymentEvidenceState,
        scan: ScanObservation,
        poll_attempts: u8,
        deployment: Option<NetlifyDeploymentMetadata>,
        failure: Option<FailureEvidence>,
    ) -> NetlifyDeploymentEvidence {
        NetlifyDeploymentEvidence::new(
            &self.registration,
            state,
            scan.list_pages,
            poll_attempts,
            scan.listing_complete,
            deployment.as_ref().or(scan.deployment.as_ref()),
            failure,
            scan.provenance,
            &scan.list_digests,
            &scan.cursor_digests,
        )
    }
}

#[derive(Debug)]
struct ScanObservation {
    list_pages: u16,
    listing_complete: bool,
    deployment: Option<NetlifyDeploymentMetadata>,
    error: Option<NetlifyDeploymentError>,
    operation: NetlifyOperation,
    list_digests: Vec<Digest>,
    cursor_digests: Vec<Digest>,
    provenance: TransportProvenance,
}

fn state_for_error(error: &NetlifyDeploymentError) -> NetlifyDeploymentEvidenceState {
    match error {
        NetlifyDeploymentError::Transport(
            NetlifyTransportError::Unauthorized
            | NetlifyTransportError::Forbidden
            | NetlifyTransportError::AccessLost,
        ) => NetlifyDeploymentEvidenceState::AccessLoss,
        NetlifyDeploymentError::Transport(NetlifyTransportError::RateLimited { .. }) => {
            NetlifyDeploymentEvidenceState::Throttled
        }
        NetlifyDeploymentError::Transport(NetlifyTransportError::NotFound) => {
            NetlifyDeploymentEvidenceState::NotFound
        }
        NetlifyDeploymentError::Transport(NetlifyTransportError::Conflict) => {
            NetlifyDeploymentEvidenceState::Conflict
        }
        NetlifyDeploymentError::Transport(NetlifyTransportError::Timeout) => {
            NetlifyDeploymentEvidenceState::Timeout
        }
        NetlifyDeploymentError::Transport(NetlifyTransportError::Partial) => {
            NetlifyDeploymentEvidenceState::Partial
        }
        NetlifyDeploymentError::PaginationLoop => NetlifyDeploymentEvidenceState::Partial,
        NetlifyDeploymentError::StaleCommit => NetlifyDeploymentEvidenceState::StaleCommit,
        NetlifyDeploymentError::TamperedEvidence
        | NetlifyDeploymentError::ScopeMismatch
        | NetlifyDeploymentError::InvalidResponse => NetlifyDeploymentEvidenceState::Tampered,
        NetlifyDeploymentError::Expired => NetlifyDeploymentEvidenceState::Expired,
        _ => NetlifyDeploymentEvidenceState::ProviderUnknown,
    }
}

fn projection_digest<T: Serialize>(projection: &T) -> Digest {
    let bytes = serde_json::to_vec(projection).expect("bounded Netlify projection serializes");
    Digest::from_bytes(&bytes)
}

fn deployment_projection_metadata_digest(projection: &DeploymentProjection) -> Digest {
    let identity_digest = Digest::from_parts(
        "netlify-deployment-identity/v1",
        &[
            ("site", projection.site_id_digest.as_str().to_owned()),
            ("deploy", projection.deploy_id_digest.as_str().to_owned()),
            ("branch", projection.branch_digest.as_str().to_owned()),
            ("commit", projection.commit_digest.as_str().to_owned()),
            ("context", projection.context_digest.as_str().to_owned()),
        ],
    );
    Digest::from_parts(
        "netlify-deployment-metadata/v1",
        &[
            ("identity", identity_digest.as_str().to_owned()),
            ("state", projection.state.as_str().to_owned()),
            (
                "url",
                projection
                    .deploy_url_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "url_verified",
                projection.deploy_url_is_verified.to_string(),
            ),
            (
                "manifest",
                projection.file_manifest.digest().as_str().to_owned(),
            ),
            (
                "expires_at",
                projection
                    .expires_at
                    .map_or_else(String::new, |value| value.to_string()),
            ),
        ],
    )
}
