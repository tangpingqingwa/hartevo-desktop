//! Typed service, registration, evidence proposal, and verification boundary.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::model::{
    Digest, EvidenceState, FailureReceipt, ModelError, PermissionSnapshot, ProjectionCounts,
    Revision, SecretReference, TransportProvenance, VeracodeRead, VeracodeReadPage, VeracodeScope,
    digest_serializable,
};
use crate::provider::{
    VeracodeProviderDefinition, VeracodeProviderError, VeracodeReadRequest,
    VeracodeTransportFailure,
};
use crate::{
    CONSUMER_ID, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum VeracodeServiceError {
    #[error("model validation failed: {0}")]
    Model(#[from] ModelError),
    #[error("provider validation failed: {0}")]
    Provider(#[from] VeracodeProviderError),
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is not active")]
    RegistrationInactive,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("scope or revision fence does not match")]
    ScopeMismatch,
    #[error("evidence is stale")]
    StaleEvidence,
    #[error("evidence is tampered")]
    TamperedEvidence,
    #[error("recording idempotency key conflicts with an existing record")]
    RecordingConflict,
    #[error("registration transition is not permitted")]
    InvalidTransition,
}

pub type ServiceError = VeracodeServiceError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionReceipt {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionReceipt {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        previous_registration_digest: Digest,
        registration_digest: Digest,
    ) -> Result<Self, ModelError> {
        let transition_digest = digest_serializable(&(
            previous_status,
            new_status,
            &previous_registration_digest,
            &registration_digest,
        ))?;
        Ok(Self {
            previous_status,
            new_status,
            previous_registration_digest,
            registration_digest,
            transition_digest,
        })
    }
}

/// A version/contract/provider/permission/scope/secret-bound registration.
///
/// The exact scope and opaque reference are available only through typed
/// in-process accessors. Serialization contains digests and the region only;
/// it never contains raw credential material or a raw scope identifier.
#[derive(Clone, Eq, PartialEq)]
pub struct VeracodeRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    api_revision: String,
    provider_revision: Revision,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    scope: VeracodeScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    evidence_digest: Digest,
    registration_revision: Revision,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl fmt::Debug for VeracodeRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VeracodeRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("contract_digest", &self.contract_digest)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest())
            .field("scope_digest", &self.scope_digest)
            .field(
                "secret_reference_digest",
                self.secret_reference.reference_digest(),
            )
            .field("evidence_digest", &self.evidence_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for VeracodeRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("VeracodeRegistration", 17)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field(
            "secretReferenceDigest",
            self.secret_reference.reference_digest(),
        )?;
        state.serialize_field("region", &self.secret_reference.region())?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

impl VeracodeRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: VeracodeScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: &VeracodeProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self, VeracodeServiceError> {
        let id = id.into();
        validate_registration_id(&id)?;
        scope.validate()?;
        secret_reference.validate()?;
        permission_snapshot.validate()?;
        provider.validate()?;
        let registration_revision = Revision::new(registration_revision)?;
        let evidence_digest =
            evidence_binding_seed(&scope, &secret_reference, &permission_snapshot, provider)?;
        let mut value = Self {
            id,
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            api_revision: provider.api_revision.clone(),
            provider_revision: provider.provider_revision,
            provider_digest: provider.provider_digest.clone(),
            permission_snapshot,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            evidence_digest,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-veracode-registration"),
        };
        value.registration_digest = value.calculate_digest()?;
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
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
    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    #[must_use]
    pub const fn provider_revision(&self) -> Revision {
        self.provider_revision
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
    pub fn scope(&self) -> &VeracodeScope {
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
    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
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
    pub fn evidence_binding_digest(&self, observed_evidence_digest: &Digest) -> Digest {
        evidence_binding_digest(&self.registration_digest, observed_evidence_digest)
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        matches!(self.status, RegistrationStatus::Revoked)
    }

    #[must_use]
    pub const fn is_reversed(&self) -> bool {
        matches!(self.status, RegistrationStatus::Reversed)
    }

    pub fn validate(&self) -> Result<(), VeracodeServiceError> {
        validate_registration_id(&self.id)?;
        self.scope.validate()?;
        self.secret_reference.validate()?;
        self.permission_snapshot.validate()?;
        let provider = VeracodeProviderDefinition::new()?;
        let expected_evidence = evidence_binding_seed(
            &self.scope,
            &self.secret_reference,
            &self.permission_snapshot,
            &provider,
        )?;
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.api_revision != crate::PROVIDER_API_REVISION
            || self.provider_revision != provider.provider_revision
            || self.provider_digest != provider.provider_digest
            || self.scope_digest != self.scope.digest()
            || self.evidence_digest != expected_evidence
            || self.registration_revision.get() == 0
            || self.registration_digest != self.calculate_digest()?
        {
            return Err(VeracodeServiceError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionReceipt, VeracodeServiceError> {
        if self.status == RegistrationStatus::Reversed {
            return Err(VeracodeServiceError::RegistrationReversed);
        }
        if self.status == RegistrationStatus::Revoked {
            return Err(VeracodeServiceError::InvalidTransition);
        }
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionReceipt, VeracodeServiceError> {
        if self.status == RegistrationStatus::Reversed {
            return Err(VeracodeServiceError::RegistrationReversed);
        }
        if self.status != RegistrationStatus::Revoked {
            return Err(VeracodeServiceError::InvalidTransition);
        }
        self.transition(RegistrationStatus::Active)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionReceipt, VeracodeServiceError> {
        if self.status == RegistrationStatus::Reversed {
            return Err(VeracodeServiceError::RegistrationReversed);
        }
        self.transition(RegistrationStatus::Reversed)
    }

    fn transition(
        &mut self,
        new_status: RegistrationStatus,
    ) -> Result<RegistrationTransitionReceipt, VeracodeServiceError> {
        let previous_status = self.status;
        let previous_digest = self.registration_digest.clone();
        self.status = new_status;
        self.registration_digest = self.calculate_digest()?;
        Ok(RegistrationTransitionReceipt::new(
            previous_status,
            new_status,
            previous_digest,
            self.registration_digest.clone(),
        )?)
    }

    fn calculate_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.id,
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            &self.api_revision,
            self.provider_revision,
            &self.provider_digest,
            &self.permission_snapshot,
            &self.scope_digest,
            self.secret_reference.reference_digest(),
            self.secret_reference.region(),
            &self.evidence_digest,
            self.registration_revision,
            self.status,
        ))
    }
}

pub type VeracodeApplicationSecurityRegistration = VeracodeRegistration;
pub type VeracodeSecurityRegistration = VeracodeRegistration;

fn validate_registration_id(value: &str) -> Result<(), VeracodeServiceError> {
    if value.is_empty()
        || value.len() > crate::model::MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(VeracodeServiceError::InvalidRegistration);
    }
    Ok(())
}

fn evidence_binding_seed(
    scope: &VeracodeScope,
    secret_reference: &SecretReference,
    permission_snapshot: &PermissionSnapshot,
    provider: &VeracodeProviderDefinition,
) -> Result<Digest, ModelError> {
    digest_serializable(&serde_json::json!({
        "binding": "veracode-evidence-registration/v1",
        "contractVersion": crate::CONTRACT_VERSION,
        "contractDigest": crate::contract_digest(),
        "providerId": &provider.provider_id,
        "providerRevision": provider.provider_revision,
        "providerDigest": &provider.provider_digest,
        "scopeDigest": scope.digest(),
        "permissionDigest": permission_snapshot.digest(),
        "secretReferenceDigest": secret_reference.reference_digest(),
        "region": secret_reference.region(),
    }))
}

#[must_use]
pub fn evidence_binding_digest(registration_digest: &Digest, evidence_digest: &Digest) -> Digest {
    digest_serializable(&serde_json::json!({
        "binding": "veracode-evidence-proposal/v1",
        "registrationDigest": registration_digest,
        "evidenceDigest": evidence_digest,
    }))
    .expect("Veracode evidence binding is serializable")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VeracodeEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: Revision,
    pub provider_digest: Digest,
    pub api_revision: String,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_binding_digest: Digest,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub evidence_revision: Revision,
    pub state: EvidenceState,
    pub provenance: TransportProvenance,
    pub pages: Vec<VeracodeReadPage>,
    pub counts: ProjectionCounts,
    pub applications: Vec<crate::model::ApplicationProjection>,
    pub builds: Vec<crate::model::BuildProjection>,
    pub scans: Vec<crate::model::ScanProjection>,
    pub findings: Vec<crate::model::FindingProjection>,
    pub policies: Vec<crate::model::PolicyProjection>,
    pub failure: Option<FailureReceipt>,
    pub response_digest: Digest,
    pub evidence_digest: Digest,
    pub observed_at: DateTime<Utc>,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub kernel_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl VeracodeEvidence {
    pub fn from_read(
        registration: &VeracodeRegistration,
        request: &VeracodeReadRequest,
        read: VeracodeRead,
        evidence_revision: u64,
    ) -> Result<Self, VeracodeServiceError> {
        registration.validate()?;
        if !registration.is_active()
            || request.scope_digest != *registration.scope_digest()
            || request.registration_digest != *registration.registration_digest()
            || request.permission_digest != registration.permission_digest()
            || request.provider_revision != registration.provider_revision()
        {
            return Err(VeracodeServiceError::ScopeMismatch);
        }
        let state = if !read.complete {
            EvidenceState::Partial
        } else if read.record_count() == 0 {
            EvidenceState::Empty
        } else {
            EvidenceState::Present
        };
        Self::new(
            registration,
            state,
            read.provenance(),
            read.pages,
            None,
            read.observed_at,
            evidence_revision,
        )
    }

    pub fn from_provider_error(
        registration: &VeracodeRegistration,
        request: &VeracodeReadRequest,
        provenance: TransportProvenance,
        error: &VeracodeProviderError,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, VeracodeServiceError> {
        let state = match error {
            VeracodeProviderError::Transport(transport)
                if matches!(
                    transport.failure,
                    VeracodeTransportFailure::Unauthorized | VeracodeTransportFailure::AccessDenied
                ) =>
            {
                EvidenceState::AccessLoss
            }
            VeracodeProviderError::RegistrationInactive => EvidenceState::Revoked,
            VeracodeProviderError::ScopeMismatch
            | VeracodeProviderError::PermissionMismatch
            | VeracodeProviderError::StaleRequest => EvidenceState::Stale,
            VeracodeProviderError::TamperedResponse => EvidenceState::Tampered,
            _ => EvidenceState::ProviderUnknown,
        };
        let failure = error.failure_receipt(provenance);
        let revision = request.provider_revision;
        Self::new(
            registration,
            state,
            provenance,
            Vec::new(),
            failure,
            observed_at,
            revision.get(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &VeracodeRegistration,
        state: EvidenceState,
        provenance: TransportProvenance,
        pages: Vec<VeracodeReadPage>,
        failure: Option<FailureReceipt>,
        observed_at: DateTime<Utc>,
        evidence_revision: u64,
    ) -> Result<Self, VeracodeServiceError> {
        if pages.len() > usize::from(crate::model::MAX_PAGES) {
            return Err(VeracodeServiceError::Model(ModelError::BoundExceeded {
                field: "evidence pages",
            }));
        }
        for page in &pages {
            page.validate_integrity()?;
        }
        if let Some(failure) = &failure {
            failure.validate()?;
        }
        let (applications, builds, scans, findings, policies) = flatten_unique(&pages)?;
        let counts = ProjectionCounts::from_pages(&pages);
        let response_digest = digest_serializable(&(
            pages
                .iter()
                .map(|page| &page.page_digest)
                .collect::<Vec<_>>(),
            &failure,
        ))?;
        let mut value = Self {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision: registration.provider_revision(),
            provider_digest: registration.provider_digest().clone(),
            api_revision: registration.api_revision().to_owned(),
            permission_digest: registration.permission_digest(),
            scope_digest: registration.scope_digest().clone(),
            registration_digest: registration.registration_digest().clone(),
            evidence_binding_digest: evidence_binding_digest(
                registration.registration_digest(),
                &response_digest,
            ),
            project_revision: registration.scope().project.revision,
            mission_revision: registration.scope().mission.revision,
            work_product_revision: registration.scope().work_product.revision,
            evidence_revision: Revision::new(evidence_revision)?,
            state,
            provenance,
            pages,
            counts,
            applications,
            builds,
            scans,
            findings,
            policies,
            failure,
            response_digest,
            evidence_digest: Digest::from_text("unsealed-veracode-evidence"),
            observed_at,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
            kernel_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        value.evidence_digest = value.calculate_evidence_digest()?;
        value.validate_integrity()?;
        Ok(value)
    }

    fn calculate_evidence_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&serde_json::json!({
            "contractVersion": &self.contract_version,
            "contractDigest": &self.contract_digest,
            "providerId": &self.provider_id,
            "providerRevision": self.provider_revision,
            "providerDigest": &self.provider_digest,
            "apiRevision": &self.api_revision,
            "permissionDigest": &self.permission_digest,
            "scopeDigest": &self.scope_digest,
            "registrationDigest": &self.registration_digest,
            "evidenceBindingDigest": &self.evidence_binding_digest,
            "projectRevision": self.project_revision,
            "missionRevision": self.mission_revision,
            "workProductRevision": self.work_product_revision,
            "evidenceRevision": self.evidence_revision,
            "state": self.state,
            "provenance": self.provenance,
            "counts": &self.counts,
            "responseDigest": &self.response_digest,
            "failure": &self.failure,
            "observedAt": self.observed_at,
            "reviewOnly": self.review_only,
            "connected": self.connected,
            "native": self.native,
            "firstParty": self.first_party,
            "durableProviderReceipt": self.durable_provider_receipt,
            "kernelAuthority": self.kernel_authority,
            "outcomeAdopted": self.outcome_adopted,
            "workProductAdopted": self.work_product_adopted,
        }))
    }

    pub fn validate_integrity(&self) -> Result<(), VeracodeServiceError> {
        if self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.api_revision != crate::PROVIDER_API_REVISION
            || self.provider_digest != VeracodeProviderDefinition::new()?.provider_digest
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.durable_provider_receipt
            || self.kernel_authority
            || self.outcome_adopted
            || self.work_product_adopted
            || self.provider_revision.get() == 0
            || self.evidence_revision.get() == 0
            || self.pages.len() > usize::from(crate::model::MAX_PAGES)
        {
            return Err(VeracodeServiceError::TamperedEvidence);
        }
        for page in &self.pages {
            page.validate_integrity()?;
        }
        let (applications, builds, scans, findings, policies) = flatten_unique(&self.pages)?;
        if applications != self.applications
            || builds != self.builds
            || scans != self.scans
            || findings != self.findings
            || policies != self.policies
            || self.counts != ProjectionCounts::from_pages(&self.pages)
        {
            return Err(VeracodeServiceError::TamperedEvidence);
        }
        if self.state == EvidenceState::Present && self.record_count() == 0 {
            return Err(VeracodeServiceError::TamperedEvidence);
        }
        if self.state == EvidenceState::Empty && self.record_count() != 0 {
            return Err(VeracodeServiceError::TamperedEvidence);
        }
        if let Some(failure) = &self.failure {
            failure.validate()?;
        }
        let response_digest = digest_serializable(&(
            self.pages
                .iter()
                .map(|page| &page.page_digest)
                .collect::<Vec<_>>(),
            &self.failure,
        ))?;
        if response_digest != self.response_digest
            || self.evidence_binding_digest
                != evidence_binding_digest(&self.registration_digest, &self.response_digest)
            || self.evidence_digest != self.calculate_evidence_digest()?
        {
            return Err(VeracodeServiceError::TamperedEvidence);
        }
        Ok(())
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.applications.len()
            + self.builds.len()
            + self.scans.len()
            + self.findings.len()
            + self.policies.len()
    }

    #[must_use]
    pub fn is_non_adoptable(&self) -> bool {
        self.state.is_non_adoptable()
    }

    #[must_use]
    pub fn review_eligible(&self) -> bool {
        self.state.review_eligible() && self.validate_integrity().is_ok()
    }

    #[must_use]
    pub fn with_declared_evidence_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }
}

type ProjectionSets = (
    Vec<crate::model::ApplicationProjection>,
    Vec<crate::model::BuildProjection>,
    Vec<crate::model::ScanProjection>,
    Vec<crate::model::FindingProjection>,
    Vec<crate::model::PolicyProjection>,
);

fn flatten_unique(pages: &[VeracodeReadPage]) -> Result<ProjectionSets, VeracodeServiceError> {
    let mut application_ids = BTreeSet::new();
    let mut build_ids = BTreeSet::new();
    let mut scan_ids = BTreeSet::new();
    let mut finding_ids = BTreeSet::new();
    let mut policy_ids = BTreeSet::new();
    let mut applications = Vec::new();
    let mut builds = Vec::new();
    let mut scans = Vec::new();
    let mut findings = Vec::new();
    let mut policies = Vec::new();
    for page in pages {
        for value in &page.applications {
            if !application_ids.insert(value.application_id.clone()) {
                return Err(VeracodeServiceError::Model(ModelError::Duplicate {
                    field: "application id across pages",
                }));
            }
            applications.push(value.clone());
        }
        for value in &page.builds {
            if !build_ids.insert(value.build_id.clone()) {
                return Err(VeracodeServiceError::Model(ModelError::Duplicate {
                    field: "build id across pages",
                }));
            }
            builds.push(value.clone());
        }
        for value in &page.scans {
            if !scan_ids.insert(value.scan_id.clone()) {
                return Err(VeracodeServiceError::Model(ModelError::Duplicate {
                    field: "scan id across pages",
                }));
            }
            scans.push(value.clone());
        }
        for value in &page.findings {
            if !finding_ids.insert(value.finding_id.clone()) {
                return Err(VeracodeServiceError::Model(ModelError::Duplicate {
                    field: "finding id across pages",
                }));
            }
            findings.push(value.clone());
        }
        for value in &page.policies {
            if !policy_ids.insert(value.policy_id.clone()) {
                return Err(VeracodeServiceError::Model(ModelError::Duplicate {
                    field: "policy id across pages",
                }));
            }
            policies.push(value.clone());
        }
    }
    Ok((applications, builds, scans, findings, policies))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VeracodeCapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VeracodeResultService;

impl Default for VeracodeResultService {
    fn default() -> Self {
        Self::new()
    }
}

impl VeracodeResultService {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> VeracodeCapabilityDescription {
        VeracodeCapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec![
                "GET_APPLICATIONS".to_owned(),
                "GET_BUILDS".to_owned(),
                "GET_SCANS".to_owned(),
                "GET_FINDINGS".to_owned(),
                "GET_POLICIES".to_owned(),
                "compile_proposal".to_owned(),
                "record_observation".to_owned(),
                "verify_evidence".to_owned(),
                "revoke_registration".to_owned(),
                "restore_registration".to_owned(),
                "reverse_registration".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            native: false,
            connected: false,
            first_party: false,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }

    pub fn provider_definition(&self) -> Result<VeracodeProviderDefinition, ServiceError> {
        Ok(VeracodeProviderDefinition::new()?)
    }

    pub fn register(
        &self,
        id: impl Into<String>,
        scope: VeracodeScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        registration_revision: u64,
    ) -> Result<VeracodeRegistration, ServiceError> {
        let provider = self.provider_definition()?;
        VeracodeRegistration::new(
            id,
            scope,
            secret_reference,
            permission_snapshot,
            &provider,
            registration_revision,
        )
    }

    pub fn register_default(
        &self,
        scope: VeracodeScope,
        secret_reference: SecretReference,
    ) -> Result<VeracodeRegistration, ServiceError> {
        let id = format!("veracode-registration-{}", &scope.digest().as_str()[..16]);
        self.register(
            id,
            scope,
            secret_reference,
            PermissionSnapshot::results_read(),
            1,
        )
    }

    pub fn evidence_from_read(
        &self,
        registration: &VeracodeRegistration,
        request: &VeracodeReadRequest,
        read: VeracodeRead,
    ) -> Result<VeracodeEvidence, ServiceError> {
        VeracodeEvidence::from_read(registration, request, read, 1)
    }

    pub fn evidence_from_provider_error(
        &self,
        registration: &VeracodeRegistration,
        request: &VeracodeReadRequest,
        provenance: TransportProvenance,
        error: &VeracodeProviderError,
        observed_at: DateTime<Utc>,
    ) -> Result<VeracodeEvidence, ServiceError> {
        VeracodeEvidence::from_provider_error(registration, request, provenance, error, observed_at)
    }

    pub fn compile_proposal(
        &self,
        registration: &VeracodeRegistration,
        evidence: VeracodeEvidence,
    ) -> Result<VeracodeProposal, ServiceError> {
        registration.validate()?;
        evidence.validate_integrity()?;
        if !registration.is_active() {
            return Err(VeracodeServiceError::RegistrationInactive);
        }
        if evidence.registration_digest != *registration.registration_digest()
            || evidence.scope_digest != *registration.scope_digest()
            || evidence.project_revision != registration.scope().project.revision
            || evidence.mission_revision != registration.scope().mission.revision
            || evidence.work_product_revision != registration.scope().work_product.revision
        {
            return Err(VeracodeServiceError::StaleEvidence);
        }
        VeracodeProposal::new(registration, evidence)
    }

    pub fn verify_evidence(
        &self,
        registration: &VeracodeRegistration,
        evidence: &VeracodeEvidence,
    ) -> VeracodeVerificationReport {
        let mut failures = Vec::new();
        if registration.validate().is_err() {
            failures.push("invalid_registration".to_owned());
        }
        if !registration.is_active() {
            failures.push("registration_revoked_or_reversed".to_owned());
        }
        if evidence.validate_integrity().is_err() {
            failures.push("evidence_tampered".to_owned());
        }
        if evidence.scope_digest != *registration.scope_digest()
            || evidence.registration_digest != *registration.registration_digest()
            || evidence.provider_revision != registration.provider_revision()
            || evidence.permission_digest != registration.permission_digest()
        {
            failures.push("stale_revision_or_scope".to_owned());
        }
        VeracodeVerificationReport {
            valid: failures.is_empty(),
            review_eligible: failures.is_empty() && evidence.review_eligible(),
            state: evidence.state,
            failures,
            connected: false,
            native: false,
            first_party: false,
            kernel_authority: false,
            outcome_adopted: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Present,
    Empty,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    Stale,
    Revoked,
}

impl From<EvidenceState> for ProposalDisposition {
    fn from(value: EvidenceState) -> Self {
        match value {
            EvidenceState::Present => Self::Present,
            EvidenceState::Empty => Self::Empty,
            EvidenceState::Partial => Self::Partial,
            EvidenceState::AccessLoss => Self::AccessLoss,
            EvidenceState::ProviderUnknown => Self::ProviderUnknown,
            EvidenceState::Tampered => Self::Tampered,
            EvidenceState::Stale => Self::Stale,
            EvidenceState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VeracodeProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub state: EvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence_digest: Digest,
    pub evidence_binding_digest: Digest,
    pub evidence: VeracodeEvidence,
    pub proposal_digest: Digest,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl VeracodeProposal {
    fn new(
        registration: &VeracodeRegistration,
        evidence: VeracodeEvidence,
    ) -> Result<Self, VeracodeServiceError> {
        let mut value = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: registration.scope_digest().clone(),
            project_revision: evidence.project_revision,
            mission_revision: evidence.mission_revision,
            work_product_revision: evidence.work_product_revision,
            state: evidence.state,
            disposition: evidence.state.into(),
            evidence_digest: evidence.evidence_digest.clone(),
            evidence_binding_digest: evidence_binding_digest(
                registration.registration_digest(),
                &evidence.evidence_digest,
            ),
            evidence,
            proposal_digest: Digest::from_text("unsealed-veracode-proposal"),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        value.proposal_digest = value.calculate_digest()?;
        value.validate_integrity()?;
        Ok(value)
    }

    fn calculate_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&serde_json::json!({
            "serviceId": &self.service_id,
            "consumerId": &self.consumer_id,
            "registrationDigest": &self.registration_digest,
            "scopeDigest": &self.scope_digest,
            "projectRevision": self.project_revision,
            "missionRevision": self.mission_revision,
            "workProductRevision": self.work_product_revision,
            "state": self.state,
            "disposition": self.disposition,
            "evidenceDigest": &self.evidence_digest,
            "evidenceBindingDigest": &self.evidence_binding_digest,
            "reviewOnly": self.review_only,
            "connected": self.connected,
            "native": self.native,
            "firstParty": self.first_party,
            "providerReceipt": self.provider_receipt,
            "outcomeAdopted": self.outcome_adopted,
            "workProductAdopted": self.work_product_adopted,
        }))
    }

    pub fn validate_integrity(&self) -> Result<(), VeracodeServiceError> {
        self.evidence.validate_integrity()?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.state != self.evidence.state
            || self.disposition != self.evidence.state.into()
            || self.evidence_digest != self.evidence.evidence_digest
            || self.registration_digest != self.evidence.registration_digest
            || self.evidence_binding_digest
                != evidence_binding_digest(&self.registration_digest, &self.evidence_digest)
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.calculate_digest()?
        {
            return Err(VeracodeServiceError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VeracodeVerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub state: EvidenceState,
    pub failures: Vec<String>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub kernel_authority: bool,
    pub outcome_adopted: bool,
}

pub type VeracodeApplicationSecurityResultService = VeracodeResultService;
pub type VeracodeSecurityResultService = VeracodeResultService;
