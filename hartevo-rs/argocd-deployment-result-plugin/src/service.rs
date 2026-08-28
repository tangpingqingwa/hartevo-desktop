use std::fmt;

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionArgoCdDeploymentConsumer;
use crate::error::{ArgoCdDeploymentError, ArgoCdTransportError, Result};
use crate::model::{
    ArgoApplicationProjection, ArgoCdDeploymentScope, ArgoCdDeploymentState, ArgoHealthStatus,
    ArgoOperationPhase, ArgoOperationProjection, ArgoRequestReceipt, ArgoResourceTreeProjection,
    ArgoSyncStatus, ArgoSyncStatusProjection, BackoffReceipt, ConsentScope, Digest,
    MissionProjection, PermissionSnapshot, ProjectProjection, ProviderProvenance, Revision,
    WorkProductProjection,
};
use crate::provider::ArgoCdProvider;
use crate::transport::ArgoCdTransport;
use crate::{
    ARGOCD_API_REVISION, CONTRACT_DIGEST, CONTRACT_SCHEMA, CONTRACT_VERSION, MISSION_CONSUMER_ID,
    PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub previous_revision: Revision,
    pub new_revision: Revision,
    pub previous_digest: Digest,
    pub new_digest: Digest,
    pub transition_digest: Digest,
    pub reversible: bool,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        previous_revision: Revision,
        new_revision: Revision,
        previous_digest: Digest,
        new_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "argocd-registration-transition/v1",
            &[
                ("previous_status", format!("{previous_status:?}")),
                ("new_status", format!("{new_status:?}")),
                ("previous_revision", previous_revision.get().to_string()),
                ("new_revision", new_revision.get().to_string()),
                ("previous_digest", previous_digest.as_str().to_owned()),
                ("new_digest", new_digest.as_str().to_owned()),
            ],
        );
        Self {
            previous_status,
            new_status,
            previous_revision,
            new_revision,
            previous_digest,
            new_digest,
            transition_digest,
            reversible: true,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ArgoCdDeploymentRegistration {
    id_digest: Digest,
    plugin_version: String,
    contract_digest: Digest,
    provider_api_revision: String,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: ArgoCdDeploymentScope,
    secret_reference_digest: Digest,
    registration_revision: Revision,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl fmt::Debug for ArgoCdDeploymentRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArgoCdDeploymentRegistration")
            .field("id_digest", &self.id_digest)
            .field("plugin_version", &self.plugin_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_api_revision", &self.provider_api_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_snapshot.digest())
            .field("consent_digest", &self.consent.digest())
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for ArgoCdDeploymentRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ArgoCdDeploymentRegistration", 13)?;
        state.serialize_field("idDigest", &self.id_digest)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerApiRevision", &self.provider_api_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_snapshot.digest())?;
        state.serialize_field("consentDigest", self.consent.digest())?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.serialize_field("reversible", &true)?;
        state.end()
    }
}

impl ArgoCdDeploymentRegistration {
    pub fn new<T: ArgoCdTransport>(
        id: impl AsRef<str>,
        provider: &ArgoCdProvider<T>,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        registration_revision: u64,
    ) -> Result<Self> {
        let id = crate::model::Identifier::new(id.as_ref())?;
        let registration_revision = Revision::new(registration_revision)?;
        permission_snapshot.validate()?;
        consent.validate()?;
        provider.secret_reference().validate(provider.scope())?;
        let mut registration = Self {
            id_digest: id.digest(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_api_revision: provider.definition().api_revision.clone(),
            provider_digest: provider.provider_digest().clone(),
            permission_snapshot,
            consent,
            scope: provider.scope().clone(),
            secret_reference_digest: provider.secret_reference().reference_digest().clone(),
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::pending(),
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
    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
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
    pub fn consent_digest(&self) -> &Digest {
        self.consent.digest()
    }

    #[must_use]
    pub fn scope(&self) -> &ArgoCdDeploymentScope {
        &self.scope
    }

    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        self.scope.digest()
    }

    #[must_use]
    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    #[must_use]
    pub const fn registration_revision(&self) -> Revision {
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

    #[must_use]
    pub const fn is_reversible() -> bool {
        true
    }

    #[must_use]
    pub const fn is_revocable() -> bool {
        true
    }

    pub fn validate(&self) -> Result<()> {
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_api_revision != ARGOCD_API_REVISION
            || self.provider_digest.validate().is_err()
            || self.secret_reference_digest.validate().is_err()
            || self.registration_revision.get() == 0
            || self.registration_digest != self.calculate_digest()
        {
            return Err(ArgoCdDeploymentError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.consent.validate()?;
        self.scope.validate()?;
        if self
            .permission_snapshot
            .permissions()
            .iter()
            .any(|permission| !self.consent.permissions().contains(permission))
        {
            return Err(ArgoCdDeploymentError::InvalidConsent);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(ArgoCdDeploymentError::RegistrationReversed);
        }
        self.transition(RegistrationStatus::Active)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(ArgoCdDeploymentError::AlreadyReversed);
        }
        self.transition(RegistrationStatus::Reversed)
    }

    fn transition(&mut self, status: RegistrationStatus) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(ArgoCdDeploymentError::RegistrationReversed);
        }
        if self.status == RegistrationStatus::Revoked && status == RegistrationStatus::Revoked {
            return Err(ArgoCdDeploymentError::AlreadyRevoked);
        }
        let previous_status = self.status;
        let previous_revision = self.registration_revision;
        let previous_digest = self.registration_digest.clone();
        self.registration_revision = self.registration_revision.bump()?;
        self.status = status;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            status,
            previous_revision,
            self.registration_revision,
            previous_digest,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "argocd-registration/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_api", self.provider_api_revision.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("consent", self.consent.digest().as_str().to_owned()),
                ("scope", self.scope.digest().as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("revision", self.registration_revision.get().to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArgoCdDeploymentServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub live_external_io: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

impl Default for ArgoCdDeploymentServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: MISSION_CONSUMER_ID.to_owned(),
            contract_digest: Digest::parse(contract_digest()).expect("static contract digest"),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            live_external_io: false,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }
}

pub type ArgoCdServiceDefinition = ArgoCdDeploymentServiceDefinition;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArgoCdCapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub type CapabilityDescription = ArgoCdCapabilityDescription;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureEvidence {
    pub category: String,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_error(error: &ArgoCdDeploymentError) -> Self {
        let (category, status_code, retry_after_seconds) = match error {
            ArgoCdDeploymentError::Transport(transport) => (
                transport.category().to_owned(),
                transport.status_code(),
                match transport {
                    ArgoCdTransportError::RateLimited {
                        retry_after_seconds,
                    } => *retry_after_seconds,
                    _ => None,
                },
            ),
            ArgoCdDeploymentError::TamperedEvidence
            | ArgoCdDeploymentError::InvalidResponse
            | ArgoCdDeploymentError::ResponseTooLarge => ("tampered".to_owned(), None, None),
            ArgoCdDeploymentError::ScopeMismatch => ("scope_mismatch".to_owned(), None, None),
            ArgoCdDeploymentError::StaleRevision => ("stale_revision".to_owned(), None, None),
            ArgoCdDeploymentError::PartialEvidence => ("partial".to_owned(), None, None),
            other => (format!("{other:?}"), None, None),
        };
        let failure_digest = Digest::from_parts(
            "argocd-failure/v1",
            &[
                ("category", category.clone()),
                (
                    "status_code",
                    status_code.map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "retry_after",
                    retry_after_seconds.map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        Self {
            category,
            status_code,
            retry_after_seconds,
            failure_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub application_digest: Digest,
    pub resource_tree_digest: Digest,
    pub sync_status_digest: Digest,
    pub operation_digest: Digest,
    pub request_receipt_digests: Vec<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    fn new(
        registration: &ArgoCdDeploymentRegistration,
        application: Option<&ArgoApplicationProjection>,
        resource_tree: Option<&ArgoResourceTreeProjection>,
        sync_status: Option<&ArgoSyncStatusProjection>,
        operation: Option<&ArgoOperationProjection>,
        request_receipts: &[ArgoRequestReceipt],
    ) -> Self {
        Self {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: registration.provider_digest.clone(),
            permission_digest: registration.permission_snapshot.digest().clone(),
            consent_digest: registration.consent.digest().clone(),
            scope_digest: registration.scope.digest(),
            application_digest: application.map_or_else(Digest::pending, |value| {
                value.application_digest_fence.clone()
            }),
            resource_tree_digest: resource_tree
                .map_or_else(Digest::pending, |value| value.tree_digest.clone()),
            sync_status_digest: sync_status
                .map_or_else(Digest::pending, |value| value.sync_status_digest.clone()),
            operation_digest: operation
                .map_or_else(Digest::pending, |value| value.operation_digest.clone()),
            request_receipt_digests: request_receipts
                .iter()
                .map(|receipt| receipt.receipt_digest.clone())
                .collect(),
            evidence_digest: Digest::pending(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArgoCdDeploymentEvidence {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub application: Option<ArgoApplicationProjection>,
    pub resource_tree: Option<ArgoResourceTreeProjection>,
    pub sync_status: Option<ArgoSyncStatusProjection>,
    pub operation: Option<ArgoOperationProjection>,
    pub state: ArgoCdDeploymentState,
    pub partial: bool,
    pub failure: Option<FailureEvidence>,
    pub request_receipts: Vec<ArgoRequestReceipt>,
    pub backoff: Option<BackoffReceipt>,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub evidence_digests: EvidenceDigests,
    pub evidence_digest: Digest,
}

pub type ArgoCdDeploymentProposal = ArgoCdDeploymentEvidence;
pub type ArgoCdDeploymentResult = ArgoCdDeploymentEvidence;

impl ArgoCdDeploymentEvidence {
    fn new(
        registration: &ArgoCdDeploymentRegistration,
        provenance: ProviderProvenance,
        application: Option<ArgoApplicationProjection>,
        resource_tree: Option<ArgoResourceTreeProjection>,
        sync_status: Option<ArgoSyncStatusProjection>,
        operation: Option<ArgoOperationProjection>,
        state: ArgoCdDeploymentState,
        partial: bool,
        failure: Option<FailureEvidence>,
        request_receipts: Vec<ArgoRequestReceipt>,
        backoff: Option<BackoffReceipt>,
    ) -> Self {
        let mut evidence = Self {
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            scope_digest: registration.scope.digest(),
            permission_digest: registration.permission_snapshot.digest().clone(),
            consent_digest: registration.consent.digest().clone(),
            project: ProjectProjection::from(registration.scope.project_context()),
            mission: MissionProjection::from(registration.scope.mission()),
            work_product: WorkProductProjection::from(registration.scope.work_product()),
            application,
            resource_tree,
            sync_status,
            operation,
            state,
            partial,
            failure,
            request_receipts,
            backoff,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            evidence_digests: EvidenceDigests::new(registration, None, None, None, None, &[]),
            evidence_digest: Digest::pending(),
        };
        evidence.evidence_digests = EvidenceDigests::new(
            registration,
            evidence.application.as_ref(),
            evidence.resource_tree.as_ref(),
            evidence.sync_status.as_ref(),
            evidence.operation.as_ref(),
            &evidence.request_receipts,
        );
        evidence.evidence_digest = evidence.compute_digest();
        evidence.evidence_digests.evidence_digest = evidence.evidence_digest.clone();
        evidence
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.evidence_digest.clone()
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self
                .request_receipts
                .iter()
                .any(|receipt| !receipt.redacted)
            || self.evidence_digests.evidence_digest != self.evidence_digest
            || self.evidence_digests.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.evidence_digests.contract_digest != Self::contract_digest_value()
            || self.evidence_digests.scope_digest != self.scope_digest
            || self.evidence_digests.permission_digest != self.permission_digest
            || self.evidence_digests.consent_digest != self.consent_digest
            || self.evidence_digests.application_digest
                != self
                    .application
                    .as_ref()
                    .map_or_else(Digest::pending, |value| {
                        value.application_digest_fence.clone()
                    })
            || self.evidence_digests.resource_tree_digest
                != self
                    .resource_tree
                    .as_ref()
                    .map_or_else(Digest::pending, |value| value.tree_digest.clone())
            || self.evidence_digests.sync_status_digest
                != self
                    .sync_status
                    .as_ref()
                    .map_or_else(Digest::pending, |value| value.sync_status_digest.clone())
            || self.evidence_digests.operation_digest
                != self
                    .operation
                    .as_ref()
                    .map_or_else(Digest::pending, |value| value.operation_digest.clone())
            || self.evidence_digests.request_receipt_digests
                != self
                    .request_receipts
                    .iter()
                    .map(|receipt| receipt.receipt_digest.clone())
                    .collect::<Vec<_>>()
            || self.evidence_digest != self.compute_digest()
        {
            return Err(ArgoCdDeploymentError::TamperedEvidence);
        }
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        self.permission_digest.validate()?;
        self.consent_digest.validate()?;
        self.evidence_digests.plugin_version_digest.validate()?;
        self.evidence_digests.contract_digest.validate()?;
        self.evidence_digests.provider_digest.validate()?;
        self.evidence_digests.scope_digest.validate()?;
        if self.partial && matches!(self.state, ArgoCdDeploymentState::Ready) {
            return Err(ArgoCdDeploymentError::TamperedEvidence);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut evidence_digests = self.evidence_digests.clone();
        evidence_digests.evidence_digest = Digest::pending();
        let canonical = EvidenceCanonical {
            registration_digest: &self.registration_digest,
            registration_revision: self.registration_revision,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            consent_digest: &self.consent_digest,
            project: &self.project,
            mission: &self.mission,
            work_product: &self.work_product,
            application: &self.application,
            resource_tree: &self.resource_tree,
            sync_status: &self.sync_status,
            operation: &self.operation,
            state: self.state,
            partial: self.partial,
            failure: &self.failure,
            request_receipts: &self.request_receipts,
            backoff: &self.backoff,
            provenance: self.provenance,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            provider_receipt: self.provider_receipt,
            outcome_adopted: self.outcome_adopted,
            work_product_adopted: self.work_product_adopted,
            evidence_digests: &evidence_digests,
        };
        let bytes = serde_json::to_vec(&canonical).expect("bounded Argo CD evidence serializes");
        Digest::from_bytes(&bytes)
    }

    fn contract_digest_value() -> Digest {
        Digest::parse(CONTRACT_DIGEST.to_owned()).expect("static contract digest")
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceCanonical<'a> {
    registration_digest: &'a Digest,
    registration_revision: Revision,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    consent_digest: &'a Digest,
    project: &'a ProjectProjection,
    mission: &'a MissionProjection,
    work_product: &'a WorkProductProjection,
    application: &'a Option<ArgoApplicationProjection>,
    resource_tree: &'a Option<ArgoResourceTreeProjection>,
    sync_status: &'a Option<ArgoSyncStatusProjection>,
    operation: &'a Option<ArgoOperationProjection>,
    state: ArgoCdDeploymentState,
    partial: bool,
    failure: &'a Option<FailureEvidence>,
    request_receipts: &'a Vec<ArgoRequestReceipt>,
    backoff: &'a Option<BackoffReceipt>,
    provenance: ProviderProvenance,
    connected: bool,
    native: bool,
    first_party: bool,
    provider_receipt: bool,
    outcome_adopted: bool,
    work_product_adopted: bool,
    evidence_digests: &'a EvidenceDigests,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArgoCdDeploymentReceipt {
    pub proposal_digest: Digest,
    pub recorded_at: u64,
    pub receipt_digest: Digest,
    pub redacted: bool,
    pub durable_provider_receipt: bool,
}

impl ArgoCdDeploymentReceipt {
    fn new(proposal: &ArgoCdDeploymentProposal, recorded_at: u64) -> Self {
        let receipt_digest = Digest::from_parts(
            "argocd-observation-receipt/v1",
            &[
                ("proposal", proposal.evidence_digest.as_str().to_owned()),
                ("recorded_at", recorded_at.to_string()),
            ],
        );
        Self {
            proposal_digest: proposal.evidence_digest.clone(),
            recorded_at,
            receipt_digest,
            redacted: true,
            durable_provider_receipt: false,
        }
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.redacted
            || self.durable_provider_receipt
            || self.receipt_digest
                != Digest::from_parts(
                    "argocd-observation-receipt/v1",
                    &[
                        ("proposal", self.proposal_digest.as_str().to_owned()),
                        ("recorded_at", self.recorded_at.to_string()),
                    ],
                )
        {
            return Err(ArgoCdDeploymentError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    Tampered,
    RegistrationMismatch,
    ScopeMismatch,
    StaleRevision,
    Partial,
    AccessLoss,
    RateLimited,
    ProviderUnknown,
    NotReady,
    ConsentMismatch,
    NativeClaim,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationReport {
    pub proposal_digest: Digest,
    pub failures: Vec<VerificationFailure>,
    pub valid: bool,
    pub review_eligible: bool,
    pub can_be_adopted: bool,
}

impl VerificationReport {
    fn new(proposal: &ArgoCdDeploymentProposal, failures: Vec<VerificationFailure>) -> Self {
        let valid = failures.is_empty();
        Self {
            proposal_digest: proposal.evidence_digest.clone(),
            failures,
            valid,
            review_eligible: valid && proposal.state == ArgoCdDeploymentState::Ready,
            can_be_adopted: false,
        }
    }

    #[must_use]
    pub const fn verified(&self) -> bool {
        self.valid
    }
}

/// Read fence for callers that need to bind a request to current Mission and
/// Work Product revisions before it reaches the provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArgoCdReadRequest {
    pub scope_digest: Digest,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub target_revision_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
}

impl ArgoCdReadRequest {
    pub fn new(
        scope: &ArgoCdDeploymentScope,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Self {
        Self {
            scope_digest: scope.digest(),
            project_revision: scope.project_context().revision(),
            mission_revision: scope.mission().revision(),
            work_product_revision: scope.work_product().revision(),
            target_revision_digest: scope.target_revision_digest(),
            permission_digest,
            consent_digest,
        }
    }

    fn validate_for(
        &self,
        scope: &ArgoCdDeploymentScope,
        registration: &ArgoCdDeploymentRegistration,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.project_revision != scope.project_context().revision()
            || self.mission_revision != scope.mission().revision()
            || self.work_product_revision != scope.work_product().revision()
            || self.target_revision_digest != scope.target_revision_digest()
            || self.permission_digest != registration.permission_digest()
            || self.consent_digest != *registration.consent_digest()
        {
            return Err(ArgoCdDeploymentError::StaleRevision);
        }
        Ok(())
    }
}

/// Typed Layer-1 service for bounded Argo CD application/resource-tree/
/// sync-status/operation metadata. It has no sync, rollback, terminate,
/// Kubernetes, manifest, secret, log, or generic deployment authority.
pub struct ArgoCdDeploymentResultService<T: ArgoCdTransport> {
    provider: ArgoCdProvider<T>,
    registration: ArgoCdDeploymentRegistration,
    definition: ArgoCdDeploymentServiceDefinition,
}

impl<T: ArgoCdTransport> fmt::Debug for ArgoCdDeploymentResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArgoCdDeploymentResultService")
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: ArgoCdTransport> ArgoCdDeploymentResultService<T> {
    pub fn register(
        provider: ArgoCdProvider<T>,
        registration_id: impl AsRef<str>,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = ArgoCdDeploymentRegistration::new(
            registration_id,
            &provider,
            permission_snapshot,
            consent,
            registration_revision,
        )?;
        Self::new(provider, registration)
    }

    pub fn new(
        provider: ArgoCdProvider<T>,
        registration: ArgoCdDeploymentRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.scope().digest() != provider.scope().digest()
            || registration.provider_digest() != provider.provider_digest()
            || registration.secret_reference_digest()
                != provider.secret_reference().reference_digest()
        {
            return Err(ArgoCdDeploymentError::InvalidRegistration);
        }
        Ok(Self {
            provider,
            registration,
            definition: ArgoCdDeploymentServiceDefinition::default(),
        })
    }

    #[must_use]
    pub fn provider(&self) -> &ArgoCdProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut ArgoCdProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &ArgoCdDeploymentRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut ArgoCdDeploymentRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &ArgoCdDeploymentScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn service_definition(&self) -> &ArgoCdDeploymentServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> ArgoCdCapabilityDescription {
        ArgoCdCapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            api_revision: ARGOCD_API_REVISION.to_owned(),
            operations: vec![
                "read_application_metadata".to_owned(),
                "read_bounded_resource_tree".to_owned(),
                "read_sync_status".to_owned(),
                "read_operation_metadata".to_owned(),
                "compile_deployment_result_proposal".to_owned(),
                "record_observation".to_owned(),
                "verify_proposal".to_owned(),
            ],
            permissions: crate::model::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
        }
    }

    #[must_use]
    pub fn issue_read_consent(&self) -> ConsentScope {
        self.registration.consent().clone()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn read(&mut self, observed_at: u64) -> Result<ArgoCdDeploymentEvidence> {
        self.ensure_readable(observed_at)?;
        let application = match self.provider.read_application() {
            Ok(value) => Some(value.to_projection()),
            Err(error) => {
                let receipts = self.provider.take_request_receipts();
                let backoff = self.provider.take_backoff();
                return self.build_evidence(
                    None,
                    None,
                    None,
                    None,
                    state_for_error(&error),
                    false,
                    Some(FailureEvidence::from_error(&error)),
                    receipts,
                    backoff,
                );
            }
        };
        let mut resource_tree = None;
        let mut sync_status = None;
        let mut operation = None;
        let mut state_override = None;
        let mut failure = None;
        let mut partial = false;
        let mut backoff = self.provider.take_backoff();

        match self.provider.read_resource_tree() {
            Ok(value) => {
                let projection = value.to_projection();
                partial |= projection.partial;
                resource_tree = Some(projection);
            }
            Err(error) => {
                partial = true;
                state_override = Some(follow_up_state(&error));
                failure = Some(FailureEvidence::from_error(&error));
            }
        }
        backoff = self.provider.take_backoff().or(backoff);
        match self.provider.read_sync_status() {
            Ok(value) => sync_status = Some(value.to_projection()),
            Err(error) => {
                partial = true;
                if state_override.is_none() {
                    state_override = Some(follow_up_state(&error));
                    failure = Some(FailureEvidence::from_error(&error));
                }
            }
        }
        backoff = self.provider.take_backoff().or(backoff);
        match self.provider.read_operation() {
            Ok(value) => operation = Some(value.to_projection()),
            Err(error) => {
                partial = true;
                if state_override.is_none() {
                    state_override = Some(follow_up_state(&error));
                    failure = Some(FailureEvidence::from_error(&error));
                }
            }
        }
        backoff = self.provider.take_backoff().or(backoff);
        let derived_state = derive_state(
            application.as_ref(),
            resource_tree.as_ref(),
            sync_status.as_ref(),
            operation.as_ref(),
            partial,
        );
        let state = state_override.unwrap_or(derived_state);
        let receipts = self.provider.take_request_receipts();
        self.build_evidence(
            application,
            resource_tree,
            sync_status,
            operation,
            state,
            partial,
            failure,
            receipts,
            backoff,
        )
    }

    pub fn read_with_fence(
        &mut self,
        request: &ArgoCdReadRequest,
        observed_at: u64,
    ) -> Result<ArgoCdDeploymentEvidence> {
        request.validate_for(self.scope(), &self.registration)?;
        self.read(observed_at)
    }

    pub fn compile_proposal(&mut self, observed_at: u64) -> Result<ArgoCdDeploymentProposal> {
        let evidence = self.read(observed_at)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: ArgoCdDeploymentEvidence,
    ) -> Result<ArgoCdDeploymentProposal> {
        self.registration.validate()?;
        evidence.validate_integrity()?;
        if evidence.registration_digest != *self.registration.registration_digest()
            || evidence.scope_digest != self.scope().digest()
            || evidence.registration_revision != self.registration.registration_revision()
            || evidence.permission_digest != self.registration.permission_digest()
            || evidence.consent_digest != *self.registration.consent_digest()
        {
            return Err(ArgoCdDeploymentError::InvalidProposal);
        }
        Ok(evidence)
    }

    pub fn record_observation(
        &self,
        proposal: &ArgoCdDeploymentProposal,
        recorded_at: u64,
    ) -> Result<ArgoCdDeploymentReceipt> {
        self.verify_proposal(proposal)?;
        let receipt = ArgoCdDeploymentReceipt::new(proposal, recorded_at);
        receipt.validate_integrity()?;
        Ok(receipt)
    }

    #[must_use]
    pub fn verify(&self, proposal: &ArgoCdDeploymentProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::Tampered);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationMismatch);
        }
        if proposal.scope_digest != self.scope().digest() {
            failures.push(VerificationFailure::ScopeMismatch);
        }
        if proposal.registration_revision != self.registration.registration_revision() {
            failures.push(VerificationFailure::StaleRevision);
        }
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationMismatch);
        }
        match proposal.state {
            ArgoCdDeploymentState::Ready => {}
            ArgoCdDeploymentState::Partial => failures.push(VerificationFailure::Partial),
            ArgoCdDeploymentState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            ArgoCdDeploymentState::RateLimited => failures.push(VerificationFailure::RateLimited),
            ArgoCdDeploymentState::StaleRevision => {
                failures.push(VerificationFailure::StaleRevision);
            }
            ArgoCdDeploymentState::RegistrationRevoked | ArgoCdDeploymentState::ConsentDenied => {
                failures.push(VerificationFailure::ConsentMismatch);
            }
            ArgoCdDeploymentState::Syncing
            | ArgoCdDeploymentState::OutOfSync
            | ArgoCdDeploymentState::Failed
            | ArgoCdDeploymentState::Unknown
            | ArgoCdDeploymentState::OperationUnknown => {
                failures.push(VerificationFailure::NotReady);
            }
            ArgoCdDeploymentState::Timeout
            | ArgoCdDeploymentState::NotFound
            | ArgoCdDeploymentState::Conflict
            | ArgoCdDeploymentState::ProviderUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            ArgoCdDeploymentState::Tampered => failures.push(VerificationFailure::Tampered),
        }
        if proposal.connected || proposal.native || proposal.first_party {
            failures.push(VerificationFailure::NativeClaim);
        }
        VerificationReport::new(proposal, failures)
    }

    pub fn verify_proposal(
        &self,
        proposal: &ArgoCdDeploymentProposal,
    ) -> Result<VerificationReport> {
        let report = self.verify(proposal);
        if report.failures.contains(&VerificationFailure::Tampered) {
            Err(ArgoCdDeploymentError::TamperedEvidence)
        } else {
            Ok(report)
        }
    }

    pub fn consumer(&self) -> Result<MissionArgoCdDeploymentConsumer> {
        MissionArgoCdDeploymentConsumer::new(self.scope().clone(), self.registration.clone())
    }

    fn ensure_readable(&self, observed_at: u64) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(ArgoCdDeploymentError::RegistrationInactive);
        }
        if !self.registration.consent().is_active_at(observed_at) {
            return Err(ArgoCdDeploymentError::ConsentMismatch);
        }
        Ok(())
    }

    fn build_evidence(
        &self,
        application: Option<ArgoApplicationProjection>,
        resource_tree: Option<ArgoResourceTreeProjection>,
        sync_status: Option<ArgoSyncStatusProjection>,
        operation: Option<ArgoOperationProjection>,
        state: ArgoCdDeploymentState,
        partial: bool,
        failure: Option<FailureEvidence>,
        request_receipts: Vec<ArgoRequestReceipt>,
        backoff: Option<BackoffReceipt>,
    ) -> Result<ArgoCdDeploymentEvidence> {
        let evidence = ArgoCdDeploymentEvidence::new(
            &self.registration,
            self.provider.provenance(),
            application,
            resource_tree,
            sync_status,
            operation,
            state,
            partial,
            failure,
            request_receipts,
            backoff,
        );
        evidence.validate_integrity()?;
        Ok(evidence)
    }
}

fn derive_state(
    application: Option<&ArgoApplicationProjection>,
    resource_tree: Option<&ArgoResourceTreeProjection>,
    sync_status: Option<&ArgoSyncStatusProjection>,
    operation: Option<&ArgoOperationProjection>,
    partial: bool,
) -> ArgoCdDeploymentState {
    if partial
        || application.is_none()
        || resource_tree.is_none()
        || sync_status.is_none()
        || operation.is_none()
    {
        return ArgoCdDeploymentState::Partial;
    }
    let application = application.expect("checked above");
    let resource_tree = resource_tree.expect("checked above");
    let sync_status = sync_status.expect("checked above");
    let operation = operation.expect("checked above");
    if resource_tree.partial || resource_tree.unknown_count > 0 {
        return ArgoCdDeploymentState::Unknown;
    }
    if application.health_status == ArgoHealthStatus::Unknown
        || sync_status.health_status == ArgoHealthStatus::Unknown
    {
        return ArgoCdDeploymentState::Unknown;
    }
    if operation.phase == ArgoOperationPhase::Running
        || operation.phase == ArgoOperationPhase::Terminating
    {
        return ArgoCdDeploymentState::Syncing;
    }
    if operation.phase == ArgoOperationPhase::Failed || operation.phase == ArgoOperationPhase::Error
    {
        return ArgoCdDeploymentState::Failed;
    }
    if sync_status.sync_status == ArgoSyncStatus::OutOfSync {
        return ArgoCdDeploymentState::OutOfSync;
    }
    if sync_status.sync_status == ArgoSyncStatus::Unknown
        || application.sync_status == ArgoSyncStatus::Unknown
        || operation.phase == ArgoOperationPhase::Unknown
    {
        return ArgoCdDeploymentState::OperationUnknown;
    }
    if application.health_status != ArgoHealthStatus::Healthy
        || sync_status.health_status != ArgoHealthStatus::Healthy
    {
        return ArgoCdDeploymentState::Unknown;
    }
    ArgoCdDeploymentState::Ready
}

fn state_for_error(error: &ArgoCdDeploymentError) -> ArgoCdDeploymentState {
    match error {
        ArgoCdDeploymentError::Transport(ArgoCdTransportError::AccessLost) => {
            ArgoCdDeploymentState::AccessLoss
        }
        ArgoCdDeploymentError::Transport(ArgoCdTransportError::RateLimited { .. }) => {
            ArgoCdDeploymentState::RateLimited
        }
        ArgoCdDeploymentError::Transport(ArgoCdTransportError::Timeout) => {
            ArgoCdDeploymentState::Timeout
        }
        ArgoCdDeploymentError::Transport(ArgoCdTransportError::NotFound) => {
            ArgoCdDeploymentState::NotFound
        }
        ArgoCdDeploymentError::Transport(ArgoCdTransportError::Conflict) => {
            ArgoCdDeploymentState::Conflict
        }
        ArgoCdDeploymentError::StaleRevision => ArgoCdDeploymentState::StaleRevision,
        ArgoCdDeploymentError::ScopeMismatch
        | ArgoCdDeploymentError::InvalidResponse
        | ArgoCdDeploymentError::ResponseTooLarge
        | ArgoCdDeploymentError::TamperedEvidence => ArgoCdDeploymentState::Tampered,
        ArgoCdDeploymentError::RegistrationInactive | ArgoCdDeploymentError::SecretRevoked => {
            ArgoCdDeploymentState::RegistrationRevoked
        }
        ArgoCdDeploymentError::ConsentMismatch | ArgoCdDeploymentError::InvalidConsent => {
            ArgoCdDeploymentState::ConsentDenied
        }
        ArgoCdDeploymentError::PartialEvidence => ArgoCdDeploymentState::Partial,
        _ => ArgoCdDeploymentState::ProviderUnknown,
    }
}

fn follow_up_state(error: &ArgoCdDeploymentError) -> ArgoCdDeploymentState {
    match state_for_error(error) {
        ArgoCdDeploymentState::ProviderUnknown => ArgoCdDeploymentState::Partial,
        state => state,
    }
}
