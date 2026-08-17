use std::fmt;

use serde::{Serialize, ser::SerializeStruct};

use crate::error::{FlyioDeploymentResultError, FlyioTransportError, Result};
use crate::model::{
    AppEvidence, AppProjection, ConsentScope, CostReceipt, CostSummary, Digest, EvidenceDigests,
    EvidenceState, FlyioDeploymentScope, MachineEvidence, MachineProjection, MissionProjection,
    PermissionSnapshot, ProjectProjection, ProviderReadEvidence, SecretReference,
    TransportProvenance, WorkProductProjection, mission_projection, project_projection,
    work_product_projection,
};
use crate::provider::{
    FlyioMachinesProvider, FlyioMachinesProviderDefinition, FlyioTransport, GetAppRequest,
    GetMachineRequest, ListAppsRequest, ListMachinesRequest,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, LAYER1_PERMISSIONS,
    MAX_PAGE_SIZE, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
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
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "flyio-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("new", format!("{new_status:?}")),
                ("registration", registration_digest.as_str().to_owned()),
            ],
        );
        Self {
            previous_status,
            new_status,
            registration_digest,
            transition_digest,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct FlyioDeploymentResultRegistration {
    id: String,
    plugin_version: String,
    version_digest: Digest,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: FlyioDeploymentScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    evidence_binding_digest: Digest,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl FlyioDeploymentResultRegistration {
    pub fn new(
        id: impl Into<String>,
        scope: FlyioDeploymentScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &FlyioMachinesProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let id = id.into();
        if id.is_empty() || id.len() > crate::MAX_IDENTIFIER_BYTES || registration_revision == 0 {
            return Err(FlyioDeploymentResultError::InvalidRegistration);
        }
        let scope_digest = scope.digest();
        let evidence_binding_digest = Digest::from_parts(
            "flyio-registration-evidence-binding/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("app", scope.app().digest().as_str().to_owned()),
                ("machine", scope.machine_id().digest().as_str().to_owned()),
                ("instance", scope.instance_id().digest().as_str().to_owned()),
                ("release", scope.release_id().digest().as_str().to_owned()),
                ("image", scope.image_digest().digest().as_str().to_owned()),
                ("mission", scope.mission_id().digest().as_str().to_owned()),
                ("mission_revision", scope.mission_revision().to_string()),
            ],
        );
        let mut registration = Self {
            id,
            plugin_version: PLUGIN_VERSION.to_owned(),
            version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: Digest::from_text(API_REVISION),
            permission_snapshot,
            consent,
            scope,
            scope_digest,
            secret_reference,
            registration_revision,
            evidence_binding_digest,
            status: RegistrationStatus::Active,
            binding_digest: Digest::from_text("unsealed-flyio-registration"),
        };
        registration.binding_digest = registration.calculate_binding_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn version_digest(&self) -> &Digest {
        &self.version_digest
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub fn provider_release(&self) -> &str {
        &self.provider_release
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest()
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn scope(&self) -> &FlyioDeploymentScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub fn evidence_binding_digest(&self) -> &Digest {
        &self.evidence_binding_digest
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub const fn is_reversible() -> bool {
        true
    }

    pub const fn is_revocable() -> bool {
        true
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.id.len() > crate::MAX_IDENTIFIER_BYTES
            || self.plugin_version != PLUGIN_VERSION
            || self.version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest().as_str()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.api_digest != Digest::from_text(API_REVISION)
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(FlyioDeploymentResultError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.permission_snapshot.validate()?;
        self.consent.validate(&self.scope)?;
        self.secret_reference.validate(&self.scope)?;
        if self
            .permission_snapshot
            .permissions
            .iter()
            .any(|permission| !self.consent.permissions.contains(permission))
        {
            return Err(FlyioDeploymentResultError::InvalidConsent);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(FlyioDeploymentResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(FlyioDeploymentResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(FlyioDeploymentResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "flyio-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("version", self.version_digest.as_str().to_owned()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("consent", self.consent_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                ("evidence", self.evidence_binding_digest.as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

impl fmt::Debug for FlyioDeploymentResultRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlyioDeploymentResultRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("version_digest", &self.version_digest)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("permission_digest", &self.permission_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("evidence_binding_digest", &self.evidence_binding_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for FlyioDeploymentResultRegistration {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("FlyioDeploymentResultRegistration", 18)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("versionDigest", &self.version_digest)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", self.secret_reference_digest())?;
        state.serialize_field("evidenceBindingDigest", &self.evidence_binding_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.binding_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub plugin_id: String,
    pub plugin_version: String,
    pub version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_revision: u64,
    pub provider_release: String,
    pub provider_digest: Digest,
    pub api_revision: String,
    pub api_digest: Digest,
    pub permissions: Vec<String>,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_binding: String,
    pub reversible_registration: bool,
    pub revocable_registration: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlyioEvidenceRequest {
    mission_revision: u64,
    project_revision: u64,
    work_product_revision: u64,
    scope_digest: Digest,
    page_size: u16,
}

impl FlyioEvidenceRequest {
    pub fn for_scope(scope: &FlyioDeploymentScope) -> Self {
        Self {
            mission_revision: scope.mission_revision(),
            project_revision: scope.project_revision(),
            work_product_revision: scope.work_product_revision(),
            scope_digest: scope.digest(),
            page_size: MAX_PAGE_SIZE,
        }
    }

    pub fn new(
        scope: &FlyioDeploymentScope,
        mission_revision: u64,
        project_revision: u64,
        work_product_revision: u64,
        page_size: u16,
    ) -> Result<Self> {
        let request = Self {
            mission_revision,
            project_revision,
            work_product_revision,
            scope_digest: scope.digest(),
            page_size,
        };
        request.validate(scope)?;
        Ok(request)
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub const fn project_revision(&self) -> u64 {
        self.project_revision
    }

    pub const fn work_product_revision(&self) -> u64 {
        self.work_product_revision
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    fn validate(&self, scope: &FlyioDeploymentScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.mission_revision == 0
            || self.project_revision == 0
            || self.work_product_revision == 0
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
        {
            return Err(FlyioDeploymentResultError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlyioDeploymentResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub app: Option<AppProjection>,
    pub machine: Option<MachineProjection>,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: EvidenceState,
    pub evidence: EvidenceDigests,
    pub request_receipts: Vec<crate::model::RequestReceipt>,
    pub cost_receipts: Vec<CostReceipt>,
    pub cost_summary: CostSummary,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub truncated: bool,
    pub proposal_digest: Digest,
}

impl FlyioDeploymentResultProposal {
    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.scope_digest != self.evidence.scope_digest
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(FlyioDeploymentResultError::TamperedEvidence);
        }
        self.evidence.validate()?;
        if let Some(app) = self.app.as_ref()
            && app.app_digest != self.evidence.app_digest
        {
            return Err(FlyioDeploymentResultError::TamperedEvidence);
        }
        if let Some(machine) = self.machine.as_ref()
            && machine.machine_digest != self.evidence.machine_digest
        {
            return Err(FlyioDeploymentResultError::TamperedEvidence);
        }
        if self.request_receipts.iter().any(|receipt| {
            !receipt.redacted
                || receipt.scope_digest != self.scope_digest
                || receipt.request_digest.as_str().len() != 64
        }) {
            return Err(FlyioDeploymentResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn can_be_adopted(&self) -> bool {
        false
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "flyio-deployment-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "app",
                    self.app
                        .as_ref()
                        .map_or_else(String::new, |app| app.app_digest.as_str().to_owned()),
                ),
                (
                    "machine",
                    self.machine.as_ref().map_or_else(String::new, |machine| {
                        machine.machine_digest.as_str().to_owned()
                    }),
                ),
                ("mission", self.mission.id_digest.as_str().to_owned()),
                ("mission_revision", self.mission.revision.to_string()),
                ("project", self.project.id_digest.as_str().to_owned()),
                ("project_revision", self.project.revision.to_string()),
                (
                    "work_product",
                    self.work_product.id_digest.as_str().to_owned(),
                ),
                (
                    "work_product_revision",
                    self.work_product.revision.to_string(),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("truncated", self.truncated.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    ScopeMismatch,
    Tampered,
    Partial,
    AccessLoss,
    StaleMission,
    ProviderUnknown,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub verified: bool,
    pub state: EvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub failure: Option<VerificationFailure>,
}

pub struct FlyioDeploymentResultService<T: FlyioTransport> {
    provider: FlyioMachinesProvider<T>,
    registration: FlyioDeploymentResultRegistration,
}

impl<T: FlyioTransport> fmt::Debug for FlyioDeploymentResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlyioDeploymentResultService")
            .field("scope_digest", &self.provider.scope().digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("provenance", &self.provider.provenance())
            .finish()
    }
}

impl<T: FlyioTransport> FlyioDeploymentResultService<T> {
    pub fn new(
        provider: FlyioMachinesProvider<T>,
        registration: FlyioDeploymentResultRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.scope_digest() != &provider.scope().digest()
            || registration.provider_digest() != &provider.definition().provider_digest
        {
            return Err(FlyioDeploymentResultError::ProviderDrift);
        }
        Ok(Self {
            provider,
            registration,
        })
    }

    pub fn register(
        &self,
        id: impl Into<String>,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        registration_revision: u64,
    ) -> Result<FlyioDeploymentResultRegistration> {
        FlyioDeploymentResultRegistration::new(
            id,
            self.provider.scope().clone(),
            secret_reference,
            permission_snapshot,
            consent,
            self.provider.definition(),
            registration_revision,
        )
    }

    pub fn provider(&self) -> &FlyioMachinesProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut FlyioMachinesProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &FlyioDeploymentResultRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut FlyioDeploymentResultRegistration {
        &mut self.registration
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: self.registration.contract_digest.clone(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision: self.provider.definition().provider_revision,
            provider_release: self.provider.definition().release.clone(),
            provider_digest: self.provider.definition().provider_digest.clone(),
            api_revision: API_REVISION.to_owned(),
            api_digest: Digest::from_text(API_REVISION),
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            permission_digest: self.registration.permission_digest(),
            scope_digest: self.provider.scope().digest(),
            evidence_binding: self
                .registration
                .evidence_binding_digest()
                .as_str()
                .to_owned(),
            reversible_registration: true,
            revocable_registration: true,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
        }
    }

    pub fn propose(
        &mut self,
        request: &FlyioEvidenceRequest,
        prior: Option<&FlyioDeploymentResultProposal>,
    ) -> Result<FlyioDeploymentResultProposal> {
        request.validate(self.provider.scope())?;
        self.registration.validate()?;
        if !self.registration.is_active() {
            return self.proposal_for_state(
                EvidenceState::Revoked,
                None,
                None,
                false,
                Vec::new(),
                Vec::new(),
            );
        }
        let read = match self.read_bounded(request) {
            Ok(read) => read,
            Err(error) => {
                return self.proposal_for_state(
                    state_for_error(&error),
                    None,
                    None,
                    matches!(error, FlyioDeploymentResultError::PartialEvidence),
                    Vec::new(),
                    Vec::new(),
                );
            }
        };
        read.validate()?;
        let mut state = if read.truncated {
            EvidenceState::Partial
        } else if !read.app.matches_scope(self.provider.scope())
            || !read.machine.matches_scope(self.provider.scope())
        {
            EvidenceState::Replaced
        } else {
            read.machine.state().into()
        };
        if request.mission_revision != self.provider.scope().mission_revision()
            || request.project_revision != self.provider.scope().project_revision()
            || request.work_product_revision != self.provider.scope().work_product_revision()
        {
            state = EvidenceState::StaleMission;
        }
        if let Some(prior) = prior {
            prior.validate_integrity()?;
            if prior.scope_digest != self.provider.scope().digest() {
                state = EvidenceState::ScopeDrift;
            } else if let Some(previous_machine) = prior.machine.as_ref()
                && (read.machine.state_sequence() < previous_machine.state_sequence
                    || (read.machine.state_sequence() == previous_machine.state_sequence
                        && read.machine.machine_digest() != previous_machine.machine_digest))
            {
                state = EvidenceState::Tampered;
            }
        }
        self.proposal_for_state(
            state,
            Some(&read.app),
            Some(&read.machine),
            read.truncated,
            read.request_receipts,
            read.cost_receipts,
        )
    }

    pub fn propose_current(&mut self) -> Result<FlyioDeploymentResultProposal> {
        let request = FlyioEvidenceRequest::for_scope(self.provider.scope());
        self.propose(&request, None)
    }

    pub fn verify(
        &self,
        proposal: &FlyioDeploymentResultProposal,
        request: &FlyioEvidenceRequest,
    ) -> Result<VerificationReport> {
        if !self.registration.is_active() {
            return Ok(VerificationReport {
                verified: false,
                state: EvidenceState::Revoked,
                proposal_digest: proposal.proposal_digest.clone(),
                evidence_digest: proposal.evidence.evidence_digest.clone(),
                failure: Some(VerificationFailure::RegistrationInactive),
            });
        }
        if request.validate(self.provider.scope()).is_err()
            || proposal.scope_digest != self.provider.scope().digest()
            || proposal.registration_digest != *self.registration.registration_digest()
        {
            return Ok(VerificationReport {
                verified: false,
                state: EvidenceState::ScopeDrift,
                proposal_digest: proposal.proposal_digest.clone(),
                evidence_digest: proposal.evidence.evidence_digest.clone(),
                failure: Some(VerificationFailure::ScopeMismatch),
            });
        }
        if proposal.validate_integrity().is_err() {
            return Ok(VerificationReport {
                verified: false,
                state: EvidenceState::Tampered,
                proposal_digest: proposal.proposal_digest.clone(),
                evidence_digest: proposal.evidence.evidence_digest.clone(),
                failure: Some(VerificationFailure::Tampered),
            });
        }
        let failure = match proposal.state {
            EvidenceState::Partial | EvidenceState::PaginationLoop => {
                Some(VerificationFailure::Partial)
            }
            EvidenceState::AccessLost | EvidenceState::Unauthorized | EvidenceState::Forbidden => {
                Some(VerificationFailure::AccessLoss)
            }
            EvidenceState::StaleMission => Some(VerificationFailure::StaleMission),
            EvidenceState::ProviderUnknown => Some(VerificationFailure::ProviderUnknown),
            EvidenceState::Revoked => Some(VerificationFailure::Revoked),
            EvidenceState::Tampered => Some(VerificationFailure::Tampered),
            EvidenceState::Created
            | EvidenceState::Starting
            | EvidenceState::Started
            | EvidenceState::Stopping
            | EvidenceState::Stopped
            | EvidenceState::Suspended
            | EvidenceState::Destroyed
            | EvidenceState::Replaced
            | EvidenceState::BadRequest
            | EvidenceState::NotFound
            | EvidenceState::Conflict
            | EvidenceState::Throttled
            | EvidenceState::ServerError
            | EvidenceState::TimedOut
            | EvidenceState::ScopeDrift => None,
        };
        Ok(VerificationReport {
            verified: failure.is_none() && !proposal.truncated,
            state: proposal.state,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            failure,
        })
    }

    fn read_bounded(&mut self, request: &FlyioEvidenceRequest) -> Result<ProviderReadEvidence> {
        let list_apps_request = ListAppsRequest::first(self.provider.scope(), request.page_size)?;
        let app_list = self.provider.list_apps(&list_apps_request)?;
        let get_app_request = GetAppRequest::for_scope(self.provider.scope())?;
        let app_detail = self.provider.get_app(&get_app_request)?;
        let list_machines_request =
            ListMachinesRequest::first(self.provider.scope(), request.page_size)?;
        let machine_list = self.provider.list_machines(&list_machines_request)?;
        let get_machine_request = GetMachineRequest::for_scope(self.provider.scope())?;
        let machine_detail = self.provider.get_machine(&get_machine_request)?;
        let app = app_detail
            .apps
            .iter()
            .find(|app| app.matches_scope(self.provider.scope()))
            .or_else(|| {
                app_list
                    .apps
                    .iter()
                    .find(|app| app.matches_scope(self.provider.scope()))
            })
            .or_else(|| app_detail.apps.first())
            .or_else(|| app_list.apps.first())
            .cloned()
            .ok_or(FlyioDeploymentResultError::Transport(
                FlyioTransportError::NotFound,
            ))?;
        let machine = machine_detail
            .machines
            .iter()
            .find(|machine| machine.matches_scope(self.provider.scope()))
            .or_else(|| {
                machine_list
                    .machines
                    .iter()
                    .find(|machine| machine.matches_scope(self.provider.scope()))
            })
            .or_else(|| machine_detail.machines.first())
            .or_else(|| machine_list.machines.first())
            .cloned()
            .ok_or(FlyioDeploymentResultError::Transport(
                FlyioTransportError::NotFound,
            ))?;
        let truncated = app_list.truncated
            || app_list.next_cursor.is_some()
            || machine_list.truncated
            || machine_list.next_cursor.is_some()
            || app_detail.truncated
            || machine_detail.truncated;
        let request_receipts = vec![
            to_request_receipt(list_apps_request.recorded_request(app_list.response_bytes)),
            to_request_receipt(get_app_request.recorded_request(app_detail.response_bytes)),
            to_request_receipt(list_machines_request.recorded_request(machine_list.response_bytes)),
            to_request_receipt(get_machine_request.recorded_request(machine_detail.response_bytes)),
        ];
        let cost_receipts = request_receipts
            .iter()
            .map(|receipt| CostReceipt {
                operation: receipt.operation.clone(),
                response_bytes: receipt.response_bytes,
                bounded_request_units: 1,
                cost_digest: Digest::from_parts(
                    "flyio-cost/v1",
                    &[
                        ("operation", receipt.operation.clone()),
                        ("bytes", receipt.response_bytes.to_string()),
                    ],
                ),
                estimate_only: true,
            })
            .collect::<Vec<_>>();
        Ok(ProviderReadEvidence {
            app,
            machine,
            request_receipts,
            cost_receipts,
            truncated,
            provenance: self.provider.provenance(),
        })
    }

    fn proposal_for_state(
        &self,
        state: EvidenceState,
        app: Option<&AppEvidence>,
        machine: Option<&MachineEvidence>,
        truncated: bool,
        request_receipts: Vec<crate::model::RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
    ) -> Result<FlyioDeploymentResultProposal> {
        let app_digest =
            app.map_or_else(|| Digest::from_text("missing-app"), AppEvidence::app_digest);
        let machine_digest = machine.map_or_else(
            || Digest::from_text("missing-machine"),
            MachineEvidence::machine_digest,
        );
        let evidence = EvidenceDigests::new(
            self.provider.scope(),
            self.provider.definition().provider_digest.clone(),
            self.registration.permission_digest(),
            app_digest,
            machine_digest,
        );
        let total_response_bytes = request_receipts
            .iter()
            .map(|receipt| receipt.response_bytes)
            .sum();
        let cost_summary = CostSummary {
            total_response_bytes,
            total_request_units: cost_receipts
                .iter()
                .map(|receipt| receipt.bounded_request_units)
                .sum(),
            estimate_only: true,
        };
        let mut proposal = FlyioDeploymentResultProposal {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: self.registration.registration_digest().clone(),
            scope_digest: self.provider.scope().digest(),
            app: app.map(AppProjection::from),
            machine: machine.map(MachineProjection::from),
            mission: mission_projection(self.provider.scope()),
            project: project_projection(self.provider.scope()),
            work_product: work_product_projection(self.provider.scope()),
            state,
            evidence,
            request_receipts,
            cost_receipts,
            cost_summary,
            provenance: self.provider.provenance(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            truncated,
            proposal_digest: Digest::from_text("unsealed-flyio-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.validate_integrity()?;
        Ok(proposal)
    }
}

fn to_request_receipt(recorded: crate::provider::RecordedRequest) -> crate::model::RequestReceipt {
    crate::model::RequestReceipt {
        operation: recorded.operation.as_str().to_owned(),
        request_digest: recorded.request_digest,
        path_digest: recorded.path_digest,
        scope_digest: recorded.scope_digest,
        app_digest: recorded.app_digest,
        machine_digest: recorded.machine_digest,
        cursor_digest: recorded.cursor_digest,
        response_bytes: recorded.response_bytes,
        redacted: recorded.redacted,
    }
}

fn state_for_error(error: &FlyioDeploymentResultError) -> EvidenceState {
    match error {
        FlyioDeploymentResultError::Transport(transport) => match transport {
            FlyioTransportError::BadRequest => EvidenceState::BadRequest,
            FlyioTransportError::Unauthorized => EvidenceState::Unauthorized,
            FlyioTransportError::Forbidden => EvidenceState::Forbidden,
            FlyioTransportError::NotFound => EvidenceState::NotFound,
            FlyioTransportError::Conflict => EvidenceState::Conflict,
            FlyioTransportError::RateLimited { .. } => EvidenceState::Throttled,
            FlyioTransportError::ServerError { .. } => EvidenceState::ServerError,
            FlyioTransportError::Timeout => EvidenceState::TimedOut,
            FlyioTransportError::AccessLost => EvidenceState::AccessLost,
            FlyioTransportError::Partial => EvidenceState::Partial,
            FlyioTransportError::PaginationLoop => EvidenceState::PaginationLoop,
            FlyioTransportError::BlockedEnv
            | FlyioTransportError::Unknown
            | FlyioTransportError::InvalidResponse
            | FlyioTransportError::Tampered => EvidenceState::ProviderUnknown,
        },
        FlyioDeploymentResultError::PartialEvidence => EvidenceState::Partial,
        FlyioDeploymentResultError::ScopeDrift | FlyioDeploymentResultError::ScopeMismatch => {
            EvidenceState::ScopeDrift
        }
        FlyioDeploymentResultError::EvidenceSequenceRegression
        | FlyioDeploymentResultError::TamperedEvidence => EvidenceState::Tampered,
        FlyioDeploymentResultError::RegistrationInactive
        | FlyioDeploymentResultError::RegistrationRevoked
        | FlyioDeploymentResultError::SecretRevoked => EvidenceState::Revoked,
        FlyioDeploymentResultError::ProviderUnknown => EvidenceState::ProviderUnknown,
        _ => EvidenceState::ProviderUnknown,
    }
}

#[allow(dead_code)]
fn _projection_types(
    _: (
        MissionProjection,
        ProjectProjection,
        WorkProductProjection,
        TransportProvenance,
    ),
) {
}
