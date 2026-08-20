//! Typed read-only Azure Container Apps revision result service.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAzureContainerAppsRevisionConsumer;
use crate::error::{
    AzureContainerAppsRevisionResultError, AzureContainerAppsTransportError, Result,
};
use crate::model::{
    AppMetadata, AzureContainerAppsEvidenceState, AzureContainerAppsRevisionProjection,
    AzureContainerAppsRevisionScope, Digest, EvidenceDigests, EvidenceState, FailureCategory,
    FailureEvidence, PermissionSnapshot, RequestReceipt, RevisionHealthState, RevisionMetadata,
    RevisionProvisioningState, RevisionRunningState, SecretReference, TransportProvenance,
    compute_evidence_digest,
};
use crate::provider::{
    AzureContainerAppsOperation, AzureContainerAppsProvider, AzureContainerAppsProviderDefinition,
    AzureContainerAppsTransport, GetContainerAppRequest, GetContainerAppResponse,
    GetRevisionRequest, GetRevisionResponse, ListRevisionsRequest, ListRevisionsResponse,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, EVIDENCE_SCHEMA,
    LAYER1_PERMISSIONS, MAX_PAGE_SIZE, MAX_PAGES, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
    contract_digest,
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
            "azure-container-apps-registration-transition/v1",
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
pub struct AzureContainerAppsRevisionRegistration {
    id: String,
    plugin_version: String,
    plugin_version_digest: Digest,
    contract_version: String,
    contract_version_digest: Digest,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    scope: AzureContainerAppsRevisionScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    evidence_schema_digest: Digest,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl AzureContainerAppsRevisionRegistration {
    pub fn new(
        id: impl Into<String>,
        scope: AzureContainerAppsRevisionScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: &AzureContainerAppsProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let id = id.into();
        provider.validate()?;
        if !valid_registration_id(&id) || registration_revision == 0 {
            return Err(AzureContainerAppsRevisionResultError::InvalidRegistration);
        }
        permission_snapshot.validate()?;
        scope.validate()?;
        secret_reference.validate(&scope)?;
        let mut registration = Self {
            id,
            plugin_version: PLUGIN_VERSION.to_owned(),
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_version_digest: Digest::from_text(CONTRACT_VERSION),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id().to_owned(),
            provider_revision: provider.provider_revision(),
            provider_release: provider.release().to_owned(),
            provider_digest: provider.provider_digest().clone(),
            api_digest: Digest::from_text(API_REVISION),
            permission_snapshot,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            evidence_schema_digest: Digest::from_text(EVIDENCE_SCHEMA),
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-azure-container-apps-registration"),
        };
        registration.registration_digest = registration.calculate_registration_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }
    pub fn plugin_version_digest(&self) -> &Digest {
        &self.plugin_version_digest
    }
    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }
    pub fn contract_version_digest(&self) -> &Digest {
        &self.contract_version_digest
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
    pub fn scope(&self) -> &AzureContainerAppsRevisionScope {
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
    pub fn evidence_schema_digest(&self) -> &Digest {
        &self.evidence_schema_digest
    }
    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }
    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
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
        if !valid_registration_id(&self.id)
            || self.plugin_version != PLUGIN_VERSION
            || self.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_version != CONTRACT_VERSION
            || self.contract_version_digest != Digest::from_text(CONTRACT_VERSION)
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest().as_str()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.provider_digest.validate().is_err()
            || self.api_digest != Digest::from_text(API_REVISION)
            || self.permission_snapshot.validate().is_err()
            || self.scope_digest != self.scope.digest()
            || self.evidence_schema_digest != Digest::from_text(EVIDENCE_SCHEMA)
            || self.registration_revision == 0
            || self.registration_digest != self.calculate_registration_digest()
        {
            return Err(AzureContainerAppsRevisionResultError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AzureContainerAppsRevisionResultError::RegistrationReversed);
        }
        if matches!(self.status, RegistrationStatus::Revoked) {
            return Err(AzureContainerAppsRevisionResultError::RegistrationRevoked);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.calculate_registration_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if !matches!(self.status, RegistrationStatus::Active) {
            return Err(AzureContainerAppsRevisionResultError::InvalidTransition);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.calculate_registration_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if !matches!(self.status, RegistrationStatus::Revoked) {
            return Err(AzureContainerAppsRevisionResultError::RegistrationNotRestorable);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.calculate_registration_digest();
        self.validate()?;
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_registration_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-container-apps-registration/v1",
            &[
                ("id", self.id.clone()),
                (
                    "plugin_version",
                    self.plugin_version_digest.as_str().to_owned(),
                ),
                (
                    "contract_version",
                    self.contract_version_digest.as_str().to_owned(),
                ),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                (
                    "evidence_schema",
                    self.evidence_schema_digest.as_str().to_owned(),
                ),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

impl fmt::Debug for AzureContainerAppsRevisionRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureContainerAppsRevisionRegistration")
            .field("id", &self.id)
            .field("plugin_version_digest", &self.plugin_version_digest)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("permission_digest", &self.permission_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("evidence_schema_digest", &self.evidence_schema_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for AzureContainerAppsRevisionRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state =
            serializer.serialize_struct("AzureContainerAppsRevisionRegistration", 18)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("pluginVersionDigest", &self.plugin_version_digest)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractVersionDigest", &self.contract_version_digest)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field(
            "secretReferenceDigest",
            self.secret_reference.reference_digest(),
        )?;
        state.serialize_field("evidenceSchemaDigest", &self.evidence_schema_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
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
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureContainerAppsRevisionEvidenceRequest {
    pub scope_digest: Digest,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub max_pages: u16,
    pub page_size: u16,
    pub observed_at: DateTime<Utc>,
    pub request_digest: Digest,
}

impl AzureContainerAppsRevisionEvidenceRequest {
    pub fn new(
        scope: &AzureContainerAppsRevisionScope,
        provider_digest: Digest,
        registration_digest: Digest,
        max_pages: u16,
        page_size: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        provider_digest.validate()?;
        registration_digest.validate()?;
        if max_pages == 0 || max_pages > MAX_PAGES || page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(AzureContainerAppsRevisionResultError::TruncatedEvidence);
        }
        let request_digest = Digest::from_parts(
            "azure-container-apps-evidence-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("provider", provider_digest.as_str().to_owned()),
                ("registration", registration_digest.as_str().to_owned()),
                ("max_pages", max_pages.to_string()),
                ("page_size", page_size.to_string()),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            expected_provider_digest: provider_digest,
            expected_registration_digest: registration_digest,
            max_pages,
            page_size,
            observed_at,
            request_digest,
        })
    }

    pub fn validate(&self, scope: &AzureContainerAppsRevisionScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
        {
            return Err(AzureContainerAppsRevisionResultError::StaleEvidence);
        }
        self.expected_provider_digest.validate()?;
        self.expected_registration_digest.validate()?;
        let expected = Digest::from_parts(
            "azure-container-apps-evidence-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "provider",
                    self.expected_provider_digest.as_str().to_owned(),
                ),
                (
                    "registration",
                    self.expected_registration_digest.as_str().to_owned(),
                ),
                ("max_pages", self.max_pages.to_string()),
                ("page_size", self.page_size.to_string()),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        );
        if self.request_digest == expected {
            Ok(())
        } else {
            Err(AzureContainerAppsRevisionResultError::StaleEvidence)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureContainerAppsRevisionProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub api_revision: String,
    pub request_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub evidence: EvidenceDigests,
    pub state: AzureContainerAppsEvidenceState,
    pub projection: Option<AzureContainerAppsRevisionProjection>,
    pub list_pages: u16,
    pub list_complete: bool,
    pub truncated: bool,
    pub provenance: TransportProvenance,
    pub request_receipts: Vec<RequestReceipt>,
    pub failure: Option<FailureEvidence>,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AzureContainerAppsRevisionProposal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        registration: &AzureContainerAppsRevisionRegistration,
        provider: &AzureContainerAppsProviderDefinition,
        request: &AzureContainerAppsRevisionEvidenceRequest,
        state: AzureContainerAppsEvidenceState,
        projection: Option<AzureContainerAppsRevisionProjection>,
        list_pages: u16,
        list_complete: bool,
        truncated: bool,
        app_digest: Option<Digest>,
        revision_digest: Option<Digest>,
        cursor_digest: Option<Digest>,
        list_digest: Option<Digest>,
        get_digest: Option<Digest>,
        request_receipts: Vec<RequestReceipt>,
        failure: Option<FailureEvidence>,
    ) -> Self {
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_version_digest: Digest::from_text(CONTRACT_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: provider.provider_digest().clone(),
            api_digest: Digest::from_text(API_REVISION),
            permission_digest: registration.permission_digest(),
            scope_digest: registration.scope_digest.clone(),
            evidence_schema_digest: Digest::from_text(EVIDENCE_SCHEMA),
            app_digest: app_digest.or_else(|| projection.as_ref().map(|value| value.app.digest())),
            revision_digest: revision_digest
                .or_else(|| projection.as_ref().map(|value| value.revision.digest())),
            list_digest,
            get_digest,
            cursor_digest,
            evidence_digest: Digest::from_text("unsealed-azure-container-apps-evidence"),
        };
        evidence.evidence_digest = compute_evidence_digest(
            &evidence,
            state,
            projection.as_ref(),
            failure.as_ref(),
            list_complete,
            list_pages,
        );
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: registration.contract_digest.clone(),
            api_revision: API_REVISION.to_owned(),
            request_digest: request.request_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            permission_digest: registration.permission_digest(),
            evidence,
            state,
            projection,
            list_pages,
            list_complete,
            truncated,
            provenance: provider.provenance(),
            request_receipts,
            failure,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-azure-container-apps-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_proposal_digest();
        proposal
    }

    #[must_use]
    pub fn with_declared_digest(mut self, proposal_digest: Digest) -> Self {
        self.proposal_digest = proposal_digest;
        self
    }
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_against_scope(&self, scope: &AzureContainerAppsRevisionScope) -> Result<()> {
        if self.scope_digest != scope.digest() {
            return Err(AzureContainerAppsRevisionResultError::ScopeMismatch);
        }
        if let Some(projection) = &self.projection {
            projection.app.validate_against(scope)?;
            projection.revision.validate_against(scope)?;
            if projection.readiness
                != crate::model::ReadinessProjection::from_metadata(
                    &projection.app,
                    &projection.revision,
                )
            {
                return Err(AzureContainerAppsRevisionResultError::TamperedEvidence);
            }
        }
        Ok(())
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.api_revision != API_REVISION
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.truncated && self.list_complete
            || self.list_pages > MAX_PAGES
            || self.evidence.validate().is_err()
            || self.evidence.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.evidence.contract_version_digest != Digest::from_text(CONTRACT_VERSION)
            || self.evidence.contract_digest != self.contract_digest
            || self.evidence.api_digest != Digest::from_text(API_REVISION)
            || self.evidence.evidence_schema_digest != Digest::from_text(EVIDENCE_SCHEMA)
            || self.evidence.scope_digest != self.scope_digest
            || self
                .request_receipts
                .iter()
                .any(|receipt| receipt.validate().is_err())
            || self
                .failure
                .as_ref()
                .is_some_and(|failure| !failure_valid(failure))
            || compute_evidence_digest(
                &self.evidence,
                self.state,
                self.projection.as_ref(),
                self.failure.as_ref(),
                self.list_complete,
                self.list_pages,
            ) != self.evidence.evidence_digest
            || self.proposal_digest != self.calculate_proposal_digest()
        {
            return Err(AzureContainerAppsRevisionResultError::TamperedEvidence);
        }
        self.scope_digest.validate()?;
        self.request_digest.validate()?;
        Ok(())
    }

    pub fn is_review_eligible(&self) -> bool {
        self.validate_integrity().is_ok()
            && self.list_complete
            && !self.truncated
            && self.failure.is_none()
            && self.state.is_review_complete()
    }

    fn calculate_proposal_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-container-apps-revision-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("provider", self.provider_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("request", self.request_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "projection",
                    self.projection
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("list_pages", self.list_pages.to_string()),
                ("list_complete", self.list_complete.to_string()),
                ("truncated", self.truncated.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "receipts",
                    self.request_receipts
                        .iter()
                        .map(|receipt| receipt.request_digest.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        value.failure_digest.as_str().to_owned()
                    }),
                ),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalIntegrityFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    PermissionDigestMismatch,
    ScopeDigestMismatch,
    EvidenceSchemaMismatch,
    TamperedEvidence,
    PartialEvidence,
    TruncatedEvidence,
    AccessLoss,
    ProviderUnknown,
    StaleRequest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalIntegrityReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub adoptable: bool,
    pub failures: Vec<LocalIntegrityFailure>,
}

impl LocalIntegrityReport {
    fn new(mut failures: Vec<LocalIntegrityFailure>, review_eligible: bool) -> Self {
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        Self {
            valid,
            review_eligible: valid && review_eligible,
            adoptable: false,
            failures,
        }
    }
}

pub struct AzureContainerAppsRevisionResultService<T> {
    registration: AzureContainerAppsRevisionRegistration,
    provider: AzureContainerAppsProvider<T>,
}

impl<T: AzureContainerAppsTransport> fmt::Debug for AzureContainerAppsRevisionResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureContainerAppsRevisionResultService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: AzureContainerAppsTransport> AzureContainerAppsRevisionResultService<T> {
    pub fn new(
        scope: AzureContainerAppsRevisionScope,
        secret_reference: SecretReference,
        provider: AzureContainerAppsProvider<T>,
        _registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new_without_time(scope, secret_reference, provider)
    }
    pub fn new_without_time(
        scope: AzureContainerAppsRevisionScope,
        secret_reference: SecretReference,
        provider: AzureContainerAppsProvider<T>,
    ) -> Result<Self> {
        Self::with_registration(
            "azure-container-apps-revision-registration",
            scope,
            secret_reference,
            PermissionSnapshot::for_layer_one(1),
            provider,
            1,
        )
    }
    pub fn with_registration(
        registration_id: impl Into<String>,
        scope: AzureContainerAppsRevisionScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: AzureContainerAppsProvider<T>,
        registration_revision: u64,
    ) -> Result<Self> {
        provider.definition().validate()?;
        let registration = AzureContainerAppsRevisionRegistration::new(
            registration_id,
            scope,
            secret_reference,
            permission_snapshot,
            provider.definition(),
            registration_revision,
        )?;
        Ok(Self {
            registration,
            provider,
        })
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: AzureContainerAppsOperation::ALL
                .into_iter()
                .map(|operation| operation.as_str().to_owned())
                .collect(),
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }
    pub fn scope(&self) -> &AzureContainerAppsRevisionScope {
        self.registration.scope()
    }
    pub fn registration(&self) -> &AzureContainerAppsRevisionRegistration {
        &self.registration
    }
    pub fn registration_mut(&mut self) -> &mut AzureContainerAppsRevisionRegistration {
        &mut self.registration
    }
    pub fn provider(&self) -> &AzureContainerAppsProvider<T> {
        &self.provider
    }
    pub fn provider_mut(&mut self) -> &mut AzureContainerAppsProvider<T> {
        &mut self.provider
    }
    pub fn request(
        &self,
        max_pages: u16,
        page_size: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<AzureContainerAppsRevisionEvidenceRequest> {
        AzureContainerAppsRevisionEvidenceRequest::new(
            self.scope(),
            self.provider.definition().provider_digest().clone(),
            self.registration.registration_digest().clone(),
            max_pages,
            page_size,
            observed_at,
        )
    }
    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<AzureContainerAppsRevisionEvidenceRequest> {
        self.request(MAX_PAGES, 10, observed_at)
    }
    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }
    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.revoke()
    }
    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }
    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.reverse()
    }
    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }
    pub fn consumer(&self) -> Result<MissionAzureContainerAppsRevisionConsumer> {
        MissionAzureContainerAppsRevisionConsumer::new(
            self.scope().clone(),
            self.registration.clone(),
        )
    }

    pub fn verify(&self, proposal: &AzureContainerAppsRevisionProposal) -> LocalIntegrityReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(LocalIntegrityFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(LocalIntegrityFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.provider_digest != *self.provider.definition().provider_digest() {
            failures.push(LocalIntegrityFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.permission_digest != self.registration.permission_digest() {
            failures.push(LocalIntegrityFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.scope_digest != *self.registration.scope_digest() {
            failures.push(LocalIntegrityFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.evidence_schema_digest != *self.registration.evidence_schema_digest() {
            failures.push(LocalIntegrityFailure::EvidenceSchemaMismatch);
        }
        if proposal.validate_against_scope(self.scope()).is_err() {
            failures.push(LocalIntegrityFailure::ScopeDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(LocalIntegrityFailure::TamperedEvidence);
        }
        match proposal.state {
            EvidenceState::Partial | EvidenceState::Truncated => {
                failures.push(LocalIntegrityFailure::PartialEvidence);
            }
            EvidenceState::AccessLost => failures.push(LocalIntegrityFailure::AccessLoss),
            EvidenceState::ProviderUnknown
            | EvidenceState::TimedOut
            | EvidenceState::Throttled
            | EvidenceState::PaginationLoop => {
                failures.push(LocalIntegrityFailure::ProviderUnknown);
            }
            EvidenceState::Tampered => failures.push(LocalIntegrityFailure::TamperedEvidence),
            EvidenceState::Revoked => failures.push(LocalIntegrityFailure::RegistrationInactive),
            EvidenceState::Provisioning
            | EvidenceState::Running
            | EvidenceState::Healthy
            | EvidenceState::Unhealthy
            | EvidenceState::Inactive
            | EvidenceState::Failed
            | EvidenceState::Deprovisioned
            | EvidenceState::NotFound
            | EvidenceState::Conflict => {}
        }
        if proposal.truncated {
            failures.push(LocalIntegrityFailure::TruncatedEvidence);
        }
        LocalIntegrityReport::new(failures, proposal.is_review_eligible())
    }

    pub fn propose(
        &mut self,
        request: AzureContainerAppsRevisionEvidenceRequest,
    ) -> Result<AzureContainerAppsRevisionProposal> {
        self.registration.validate()?;
        self.provider.definition().validate()?;
        if !self.registration.is_active() {
            return Err(AzureContainerAppsRevisionResultError::RegistrationInactive);
        }
        request.validate(self.scope())?;
        if request.expected_provider_digest != *self.provider.definition().provider_digest()
            || request.expected_registration_digest != *self.registration.registration_digest()
        {
            return Err(AzureContainerAppsRevisionResultError::StaleEvidence);
        }

        let app_request = GetContainerAppRequest::for_scope(self.scope())?;
        let app_response = match self.provider.get_container_app(&app_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.proposal_for_failure(
                    &request,
                    AzureContainerAppsEvidenceState::from_transport(&error),
                    0,
                    false,
                    false,
                    None,
                    None,
                    None,
                    None,
                    Vec::new(),
                    Some(failure_from_transport(
                        AzureContainerAppsOperation::GetContainerApp,
                        &error,
                    )),
                ));
            }
        };
        if app_response.validate_integrity(&app_request).is_err()
            || app_response.provenance != self.provider.provenance()
        {
            return Ok(self.proposal_for_failure(
                &request,
                AzureContainerAppsEvidenceState::Tampered,
                0,
                false,
                false,
                Some(app_response.evidence_digest),
                None,
                None,
                None,
                Vec::new(),
                Some(FailureEvidence::new(
                    AzureContainerAppsOperation::GetContainerApp.as_str(),
                    FailureCategory::Tampered,
                    None,
                )),
            ));
        }
        let app = app_response.metadata.clone();
        let app_digest = Some(app_response.evidence_digest.clone());
        let mut receipts = vec![receipt_for_app(&app_request, &app_response)];
        let mut cursor = None;
        let mut list_pages = 0_u16;
        let mut list_complete = false;
        let mut list_digests = Vec::new();
        let mut cursor_digests = BTreeSet::new();
        let mut listed_revision: Option<RevisionMetadata> = None;

        loop {
            if list_pages >= request.max_pages {
                break;
            }
            let list_request =
                ListRevisionsRequest::new(self.scope(), request.page_size, cursor.clone())?;
            let list_response = match self.provider.list_revisions(&list_request) {
                Ok(response) => response,
                Err(error) => {
                    return Ok(self.proposal_for_failure(
                        &request,
                        AzureContainerAppsEvidenceState::from_transport(&error),
                        list_pages,
                        list_complete,
                        false,
                        app_digest,
                        nonempty_digest(&list_digests),
                        None,
                        None,
                        receipts,
                        Some(failure_from_transport(
                            AzureContainerAppsOperation::ListRevisions,
                            &error,
                        )),
                    ));
                }
            };
            if list_response.validate_integrity(&list_request).is_err()
                || list_response.provenance != self.provider.provenance()
            {
                return Ok(self.proposal_for_failure(
                    &request,
                    AzureContainerAppsEvidenceState::Tampered,
                    list_pages,
                    list_complete,
                    false,
                    app_digest,
                    nonempty_digest(&list_digests),
                    None,
                    None,
                    receipts,
                    Some(FailureEvidence::new(
                        AzureContainerAppsOperation::ListRevisions.as_str(),
                        FailureCategory::Tampered,
                        None,
                    )),
                ));
            }
            list_pages = list_pages.saturating_add(1);
            list_digests.push(list_response.evidence_digest.clone());
            receipts.push(receipt_for_list(&list_request, &list_response));
            for revision in &list_response.revisions {
                if revision.revision_digest == self.scope().revision().digest() {
                    if let Some(previous) = &listed_revision
                        && previous.digest() != revision.digest()
                    {
                        return Ok(self.proposal_for_failure(
                            &request,
                            AzureContainerAppsEvidenceState::Partial,
                            list_pages,
                            false,
                            false,
                            app_digest,
                            nonempty_digest(&list_digests),
                            None,
                            None,
                            receipts,
                            Some(FailureEvidence::new(
                                AzureContainerAppsOperation::ListRevisions.as_str(),
                                FailureCategory::RevisionReplaced,
                                None,
                            )),
                        ));
                    }
                    listed_revision = Some(revision.clone());
                }
            }
            if let Some(next_cursor) = &list_response.next_cursor {
                if !cursor_digests.insert(next_cursor.continuation_digest().clone()) {
                    return Ok(self.proposal_for_failure(
                        &request,
                        AzureContainerAppsEvidenceState::PaginationLoop,
                        list_pages,
                        false,
                        false,
                        app_digest,
                        nonempty_digest(&list_digests),
                        Some(next_cursor.token_digest().clone()),
                        None,
                        receipts,
                        Some(FailureEvidence::new(
                            AzureContainerAppsOperation::ListRevisions.as_str(),
                            FailureCategory::PaginationLoop,
                            None,
                        )),
                    ));
                }
                cursor = Some(next_cursor.clone());
            } else {
                list_complete = true;
                break;
            }
        }

        let list_digest = nonempty_digest(&list_digests);
        let cursor_digest = cursor.as_ref().map(|value| value.token_digest().clone());
        if !list_complete {
            return Ok(self.proposal_for_failure(
                &request,
                AzureContainerAppsEvidenceState::Partial,
                list_pages,
                false,
                true,
                app_digest,
                list_digest,
                cursor_digest,
                None,
                receipts,
                Some(FailureEvidence::new(
                    AzureContainerAppsOperation::ListRevisions.as_str(),
                    FailureCategory::Truncated,
                    None,
                )),
            ));
        }
        let Some(listed_revision) = listed_revision else {
            return Ok(self.proposal_for_failure(
                &request,
                AzureContainerAppsEvidenceState::NotFound,
                list_pages,
                true,
                false,
                app_digest,
                list_digest,
                cursor_digest,
                None,
                receipts,
                Some(FailureEvidence::new(
                    AzureContainerAppsOperation::ListRevisions.as_str(),
                    FailureCategory::NotFound,
                    Some(404),
                )),
            ));
        };

        let revision_request = GetRevisionRequest::for_scope(self.scope())?;
        let revision_response = match self.provider.get_revision(&revision_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.proposal_for_failure(
                    &request,
                    AzureContainerAppsEvidenceState::from_transport(&error),
                    list_pages,
                    true,
                    false,
                    app_digest,
                    list_digest,
                    cursor_digest,
                    None,
                    receipts,
                    Some(failure_from_transport(
                        AzureContainerAppsOperation::GetRevision,
                        &error,
                    )),
                ));
            }
        };
        if revision_response
            .validate_integrity(&revision_request)
            .is_err()
            || revision_response.provenance != self.provider.provenance()
        {
            return Ok(self.proposal_for_failure(
                &request,
                AzureContainerAppsEvidenceState::Tampered,
                list_pages,
                true,
                false,
                app_digest,
                list_digest,
                cursor_digest,
                Some(revision_response.evidence_digest),
                receipts,
                Some(FailureEvidence::new(
                    AzureContainerAppsOperation::GetRevision.as_str(),
                    FailureCategory::Tampered,
                    None,
                )),
            ));
        }
        receipts.push(receipt_for_revision(&revision_request, &revision_response));
        let get_digest = Some(revision_response.evidence_digest.clone());
        if listed_revision.digest() != revision_response.metadata.digest() {
            return Ok(self.proposal_for_failure(
                &request,
                AzureContainerAppsEvidenceState::Partial,
                list_pages,
                true,
                false,
                app_digest,
                list_digest,
                cursor_digest,
                get_digest,
                receipts,
                Some(FailureEvidence::new(
                    AzureContainerAppsOperation::GetRevision.as_str(),
                    FailureCategory::RevisionReplaced,
                    None,
                )),
            ));
        }
        let state = match derive_state(&app, &revision_response.metadata) {
            Ok(state) => state,
            Err(category) => {
                return Ok(self.proposal_for_failure(
                    &request,
                    AzureContainerAppsEvidenceState::Conflict,
                    list_pages,
                    true,
                    false,
                    app_digest,
                    list_digest,
                    cursor_digest,
                    get_digest,
                    receipts,
                    Some(FailureEvidence::new(
                        AzureContainerAppsOperation::GetRevision.as_str(),
                        category,
                        None,
                    )),
                ));
            }
        };
        let projection = AzureContainerAppsRevisionProjection::new(app, revision_response.metadata);
        Ok(AzureContainerAppsRevisionProposal::new(
            &self.registration,
            self.provider.definition(),
            &request,
            state,
            Some(projection),
            list_pages,
            true,
            false,
            app_digest,
            get_digest.clone(),
            cursor_digest,
            list_digest,
            get_digest,
            receipts,
            None,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn proposal_for_failure(
        &self,
        request: &AzureContainerAppsRevisionEvidenceRequest,
        state: AzureContainerAppsEvidenceState,
        list_pages: u16,
        list_complete: bool,
        truncated: bool,
        app_digest: Option<Digest>,
        list_digest: Option<Digest>,
        cursor_digest: Option<Digest>,
        get_digest: Option<Digest>,
        request_receipts: Vec<RequestReceipt>,
        failure: Option<FailureEvidence>,
    ) -> AzureContainerAppsRevisionProposal {
        AzureContainerAppsRevisionProposal::new(
            &self.registration,
            self.provider.definition(),
            request,
            state,
            None,
            list_pages,
            list_complete,
            truncated,
            app_digest,
            None,
            cursor_digest,
            list_digest,
            get_digest,
            request_receipts,
            failure,
        )
    }
}

impl AzureContainerAppsEvidenceState {
    fn from_transport(error: &AzureContainerAppsTransportError) -> Self {
        match error {
            AzureContainerAppsTransportError::Unauthorized
            | AzureContainerAppsTransportError::Forbidden
            | AzureContainerAppsTransportError::AccessLost => Self::AccessLost,
            AzureContainerAppsTransportError::NotFound => Self::NotFound,
            AzureContainerAppsTransportError::RateLimited { .. } => Self::Throttled,
            AzureContainerAppsTransportError::Timeout => Self::TimedOut,
            AzureContainerAppsTransportError::Truncated => Self::Truncated,
            AzureContainerAppsTransportError::BadRequest
            | AzureContainerAppsTransportError::Conflict
            | AzureContainerAppsTransportError::ServerFailure { .. }
            | AzureContainerAppsTransportError::InvalidResponse
            | AzureContainerAppsTransportError::BlockedEnv => Self::ProviderUnknown,
        }
    }
}

fn valid_registration_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn nonempty_digest(values: &[Digest]) -> Option<Digest> {
    (!values.is_empty()).then(|| {
        Digest::from_parts(
            "azure-container-apps-list-pages/v1",
            &[(
                "pages",
                values
                    .iter()
                    .map(|digest| digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        )
    })
}

fn failure_from_transport(
    operation: AzureContainerAppsOperation,
    error: &AzureContainerAppsTransportError,
) -> FailureEvidence {
    let category = match error {
        AzureContainerAppsTransportError::Unauthorized => FailureCategory::Unauthorized,
        AzureContainerAppsTransportError::Forbidden => FailureCategory::Forbidden,
        AzureContainerAppsTransportError::AccessLost => FailureCategory::AccessLost,
        AzureContainerAppsTransportError::NotFound => FailureCategory::NotFound,
        AzureContainerAppsTransportError::RateLimited { .. } => FailureCategory::RateLimited,
        AzureContainerAppsTransportError::Timeout => FailureCategory::TimedOut,
        AzureContainerAppsTransportError::BadRequest => FailureCategory::BadRequest,
        AzureContainerAppsTransportError::Conflict => FailureCategory::Conflict,
        AzureContainerAppsTransportError::ServerFailure { .. } => FailureCategory::ServerFailure,
        AzureContainerAppsTransportError::InvalidResponse => FailureCategory::InvalidResponse,
        AzureContainerAppsTransportError::Truncated => FailureCategory::Truncated,
        AzureContainerAppsTransportError::BlockedEnv => FailureCategory::BlockedEnv,
    };
    FailureEvidence::new(operation.as_str(), category, error.status_code())
}

fn failure_valid(failure: &FailureEvidence) -> bool {
    FailureEvidence::new(
        failure.operation.clone(),
        failure.category.clone(),
        failure.status_code,
    )
    .failure_digest
        == failure.failure_digest
}

fn receipt_for_app(
    request: &GetContainerAppRequest,
    response: &GetContainerAppResponse,
) -> RequestReceipt {
    RequestReceipt {
        operation: AzureContainerAppsOperation::GetContainerApp
            .as_str()
            .to_owned(),
        scope_digest: request.scope().digest(),
        page_digest: None,
        request_digest: request.request_digest().clone(),
        path_digest: request.path_digest(),
        response_bytes: Some(response.response_bytes),
        response_digest: Some(response.evidence_digest.clone()),
        redacted: true,
    }
}
fn receipt_for_revision(
    request: &GetRevisionRequest,
    response: &GetRevisionResponse,
) -> RequestReceipt {
    RequestReceipt {
        operation: AzureContainerAppsOperation::GetRevision.as_str().to_owned(),
        scope_digest: request.scope().digest(),
        page_digest: None,
        request_digest: request.request_digest().clone(),
        path_digest: request.path_digest(),
        response_bytes: Some(response.response_bytes),
        response_digest: Some(response.evidence_digest.clone()),
        redacted: true,
    }
}
fn receipt_for_list(
    request: &ListRevisionsRequest,
    response: &ListRevisionsResponse,
) -> RequestReceipt {
    RequestReceipt {
        operation: AzureContainerAppsOperation::ListRevisions
            .as_str()
            .to_owned(),
        scope_digest: request.scope().digest(),
        page_digest: response
            .next_cursor
            .as_ref()
            .map(|value| value.token_digest().clone()),
        request_digest: request.request_digest().clone(),
        path_digest: request.path_digest(),
        response_bytes: Some(response.response_bytes),
        response_digest: Some(response.evidence_digest.clone()),
        redacted: true,
    }
}

fn derive_state(
    app: &AppMetadata,
    revision: &RevisionMetadata,
) -> std::result::Result<AzureContainerAppsEvidenceState, FailureCategory> {
    match app.provisioning_state {
        crate::model::AppProvisioningState::Provisioning => {
            return Ok(AzureContainerAppsEvidenceState::Provisioning);
        }
        crate::model::AppProvisioningState::Failed => {
            return Ok(AzureContainerAppsEvidenceState::Failed);
        }
        crate::model::AppProvisioningState::Deprovisioning
        | crate::model::AppProvisioningState::Deprovisioned => {
            return Ok(AzureContainerAppsEvidenceState::Deprovisioned);
        }
        crate::model::AppProvisioningState::Unknown => {
            return Err(FailureCategory::ProviderUnknown);
        }
        crate::model::AppProvisioningState::Succeeded => {}
    }
    match revision.provisioning_state {
        RevisionProvisioningState::Provisioning => {
            return Ok(AzureContainerAppsEvidenceState::Provisioning);
        }
        RevisionProvisioningState::Failed => return Ok(AzureContainerAppsEvidenceState::Failed),
        RevisionProvisioningState::Deprovisioning | RevisionProvisioningState::Deprovisioned => {
            return Ok(AzureContainerAppsEvidenceState::Deprovisioned);
        }
        RevisionProvisioningState::Unknown => return Err(FailureCategory::ProviderUnknown),
        RevisionProvisioningState::Provisioned => {}
    }
    if !revision.active {
        return Ok(AzureContainerAppsEvidenceState::Inactive);
    }
    if matches!(revision.health_state, RevisionHealthState::Unknown)
        || matches!(revision.running_state, RevisionRunningState::Unknown)
    {
        return Err(FailureCategory::ProviderUnknown);
    }
    if matches!(revision.health_state, RevisionHealthState::Unhealthy) {
        return Ok(AzureContainerAppsEvidenceState::Unhealthy);
    }
    match revision.running_state {
        RevisionRunningState::Running => {
            if matches!(revision.health_state, RevisionHealthState::Healthy) {
                Ok(AzureContainerAppsEvidenceState::Healthy)
            } else {
                Ok(AzureContainerAppsEvidenceState::Running)
            }
        }
        RevisionRunningState::Unknown => Err(FailureCategory::ProviderUnknown),
        _ => Err(FailureCategory::ReadinessConflict),
    }
}
