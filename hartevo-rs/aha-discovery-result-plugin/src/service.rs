//! Typed service, opaque registration, redacted proposals, and reversible revocation.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::model::{
    AhaDiscoveryPage, AhaDiscoveryRequest, AhaDiscoveryResultError, AhaDiscoveryScope, Digest,
    EvidenceDigests, EvidenceFence, InsightState, PermissionSnapshot, valid_identifier,
};
use crate::provider::{
    AhaDiscoveryProvider, AhaDiscoveryProviderDefinition, AhaDiscoveryProviderError,
    AhaDiscoveryTransport, AhaDiscoveryTransportError, TransportProvenance,
};
use crate::{
    AHA_DISCOVERY_RESULT_CONSUMER_ID, AHA_DISCOVERY_RESULT_CONTRACT_VERSION,
    AHA_DISCOVERY_RESULT_PLUGIN_VERSION_TEXT, AHA_DISCOVERY_RESULT_PROVIDER_ID,
    AHA_DISCOVERY_RESULT_SCHEMA_VERSION, AHA_DISCOVERY_RESULT_SERVICE_ID, contract_digest,
};

/// Registration lifecycle with digest-changing reversible transitions.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

impl RegistrationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

/// Transition evidence is deterministic and contains no credential material.
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
            "aha-discovery-registration-transition/v1",
            &[
                ("previous", previous_status.as_str().to_owned()),
                ("new", new_status.as_str().to_owned()),
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

/// Opaque account/workspace-scoped secret handle. The supplied handle is never retained or serialized.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    scope_digest: Digest,
    reference_digest: Digest,
}

impl SecretReference {
    pub fn from_handle(
        handle: impl AsRef<str>,
        scope: &AhaDiscoveryScope,
    ) -> Result<Self, AhaDiscoveryResultError> {
        let handle = handle.as_ref();
        scope.validate()?;
        if handle.is_empty()
            || handle.len() > 256
            || handle.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(AhaDiscoveryResultError::InvalidIdentifier);
        }
        Ok(Self {
            scope_digest: scope.digest(),
            reference_digest: Digest::from_parts(
                "aha-discovery-secret-reference/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("handle", handle.to_owned()),
                ],
            ),
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn validate(&self, scope: &AhaDiscoveryScope) -> Result<(), AhaDiscoveryResultError> {
        scope.validate()?;
        self.scope_digest.validate()?;
        self.reference_digest.validate()?;
        if self.scope_digest != scope.digest() {
            return Err(AhaDiscoveryResultError::SecretScopeMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("scope_digest", &self.scope_digest)
            .field("reference_digest", &self.reference_digest)
            .finish()
    }
}

/// Registration projection suitable for persistence/inspection without the opaque secret object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AhaDiscoveryRegistrationProjection {
    pub id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: u64,
    pub provider_release: String,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope: AhaDiscoveryScope,
    pub scope_digest: Digest,
    pub evidence_fence: EvidenceFence,
    pub secret_reference_digest: Digest,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
}

/// Version/contract/provider/permission/scope/evidence/secret-bound registration.
#[derive(Clone, Eq, PartialEq)]
pub struct AhaDiscoveryRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    permissions: PermissionSnapshot,
    scope: AhaDiscoveryScope,
    scope_digest: Digest,
    evidence_fence: EvidenceFence,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl fmt::Debug for AhaDiscoveryRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AhaDiscoveryRegistration")
            .field("id", &self.id)
            .field("provider_id", &self.provider_id)
            .field("scope_digest", &self.scope_digest)
            .field("evidence_fence", &self.evidence_fence)
            .field(
                "secret_reference_digest",
                &self.secret_reference.reference_digest(),
            )
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish_non_exhaustive()
    }
}

impl AhaDiscoveryRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AhaDiscoveryScope,
        secret_reference: SecretReference,
        permissions: PermissionSnapshot,
        provider: &AhaDiscoveryProviderDefinition,
        evidence_fence: EvidenceFence,
        registration_revision: u64,
    ) -> Result<Self, AhaDiscoveryResultError> {
        let mut registration = Self {
            id: id.into(),
            plugin_version: AHA_DISCOVERY_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: AHA_DISCOVERY_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.digest().clone(),
            permissions,
            scope_digest: scope.digest(),
            scope,
            evidence_fence,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-aha-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
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

    pub fn permissions(&self) -> &PermissionSnapshot {
        &self.permissions
    }

    pub fn permission_digest(&self) -> Digest {
        self.permissions.digest()
    }

    pub fn scope(&self) -> &AhaDiscoveryScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn evidence_fence(&self) -> &EvidenceFence {
        &self.evidence_fence
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

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        if !valid_identifier(&self.id)
            || self.plugin_version != AHA_DISCOVERY_RESULT_PLUGIN_VERSION_TEXT
            || self.contract_version != AHA_DISCOVERY_RESULT_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != AHA_DISCOVERY_RESULT_PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.calculate_digest()
        {
            return Err(AhaDiscoveryResultError::InvalidRegistration);
        }
        self.permissions.validate()?;
        self.scope.validate()?;
        self.evidence_fence.validate()?;
        self.secret_reference.validate(&self.scope)?;
        self.provider_digest.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence, AhaDiscoveryResultError> {
        if matches!(self.status, RegistrationStatus::Revoked) {
            return Err(AhaDiscoveryResultError::RegistrationAlreadyRevoked);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence, AhaDiscoveryResultError> {
        if matches!(self.status, RegistrationStatus::Active) {
            return Err(AhaDiscoveryResultError::RegistrationAlreadyActive);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn redacted_projection(&self) -> AhaDiscoveryRegistrationProjection {
        AhaDiscoveryRegistrationProjection {
            id: self.id.clone(),
            plugin_version: self.plugin_version.clone(),
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            provider_id: self.provider_id.clone(),
            provider_revision: self.provider_revision,
            provider_release: self.provider_release.clone(),
            provider_digest: self.provider_digest.clone(),
            permission_digest: self.permission_digest(),
            scope: self.scope.clone(),
            scope_digest: self.scope_digest.clone(),
            evidence_fence: self.evidence_fence.clone(),
            secret_reference_digest: self.secret_reference_digest().clone(),
            registration_revision: self.registration_revision,
            status: self.status,
            registration_digest: self.registration_digest.clone(),
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permissions.digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("fence", self.evidence_fence.digest().as_str().to_owned()),
                (
                    "secret_reference",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                (
                    "registration_revision",
                    self.registration_revision.to_string(),
                ),
                ("status", self.status.as_str().to_owned()),
            ],
        )
    }
}

/// Service descriptor mirrors the versioned contract and has no execution authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AhaDiscoveryServiceDefinition {
    pub id: String,
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub layer: u8,
    pub read_only: bool,
    pub live_execution: bool,
    pub mutation_authority: bool,
}

impl AhaDiscoveryServiceDefinition {
    pub fn new() -> Self {
        Self {
            id: AHA_DISCOVERY_RESULT_SERVICE_ID.to_owned(),
            schema_version: AHA_DISCOVERY_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: AHA_DISCOVERY_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: AHA_DISCOVERY_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            layer: 1,
            read_only: true,
            live_execution: false,
            mutation_authority: false,
        }
    }
}

impl Default for AhaDiscoveryServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

/// Service errors keep registration lookup separate from provider/contract failures.
#[derive(Debug, Eq, Error, PartialEq)]
pub enum AhaDiscoveryResultServiceError {
    #[error(transparent)]
    Contract(#[from] AhaDiscoveryResultError),
    #[error(transparent)]
    Provider(#[from] AhaDiscoveryProviderError),
}

/// Deterministic redacted result proposal consumed by the Mission boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AhaDiscoveryResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub provider_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page: AhaDiscoveryPage,
    pub state: InsightState,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub redaction: crate::RedactionSummary,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AhaDiscoveryResultProposal {
    pub fn validate_integrity(&self) -> Result<(), AhaDiscoveryResultError> {
        self.page.validate()?;
        self.evidence.validate()?;
        self.redaction.validate()?;
        if self.service_id != AHA_DISCOVERY_RESULT_SERVICE_ID
            || self.consumer_id != AHA_DISCOVERY_RESULT_CONSUMER_ID
            || self.provider_id != AHA_DISCOVERY_RESULT_PROVIDER_ID
            || self.registration_digest.validate().is_err()
            || self.scope_digest != self.page.scope.digest()
            || self.request_digest != self.page.request_digest
            || self.evidence != EvidenceDigests::from_page(&self.page.scope, &self.page)
            || self.redaction != self.page.redaction
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AhaDiscoveryResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    fn from_page(
        registration: &AhaDiscoveryRegistration,
        page: AhaDiscoveryPage,
        state: InsightState,
        provenance: TransportProvenance,
    ) -> Result<Self, AhaDiscoveryResultError> {
        page.validate()?;
        let mut proposal = Self {
            service_id: AHA_DISCOVERY_RESULT_SERVICE_ID.to_owned(),
            consumer_id: AHA_DISCOVERY_RESULT_CONSUMER_ID.to_owned(),
            provider_id: AHA_DISCOVERY_RESULT_PROVIDER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: page.scope.digest(),
            request_digest: page.request_digest.clone(),
            evidence: EvidenceDigests::from_page(&page.scope, &page),
            redaction: page.redaction.clone(),
            page,
            state,
            provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-aha-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.validate_integrity()?;
        Ok(proposal)
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-result-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("provider", self.provider_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page.page_digest.as_str().to_owned()),
                ("state", self.state.as_str().to_owned()),
                ("evidence", self.evidence.digest().as_str().to_owned()),
                ("provenance", self.provenance.as_str().to_owned()),
                ("redaction", self.redaction.digest().as_str().to_owned()),
                ("review_only", self.review_only.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("outcome_adopted", self.outcome_adopted.to_string()),
                (
                    "work_product_adopted",
                    self.work_product_adopted.to_string(),
                ),
            ],
        )
    }
}

/// Registration owner for the standalone Layer-1 service.
pub struct AhaDiscoveryResultService {
    definition: AhaDiscoveryServiceDefinition,
    registrations: BTreeMap<String, AhaDiscoveryRegistration>,
}

impl fmt::Debug for AhaDiscoveryResultService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AhaDiscoveryResultService")
            .field("definition", &self.definition)
            .field("registration_count", &self.registrations.len())
            .finish()
    }
}

impl Default for AhaDiscoveryResultService {
    fn default() -> Self {
        Self::new()
    }
}

impl AhaDiscoveryResultService {
    pub fn new() -> Self {
        Self {
            definition: AhaDiscoveryServiceDefinition::new(),
            registrations: BTreeMap::new(),
        }
    }

    pub fn definition(&self) -> &AhaDiscoveryServiceDefinition {
        &self.definition
    }

    pub fn registration_count(&self) -> usize {
        self.registrations.len()
    }

    pub fn registration(&self, id: &str) -> Option<&AhaDiscoveryRegistration> {
        self.registrations.get(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register(
        &mut self,
        id: impl Into<String>,
        scope: AhaDiscoveryScope,
        secret_reference: SecretReference,
        permissions: PermissionSnapshot,
        provider: &AhaDiscoveryProviderDefinition,
        evidence_fence: EvidenceFence,
        registration_revision: u64,
    ) -> Result<AhaDiscoveryRegistration, AhaDiscoveryResultServiceError> {
        let id = id.into();
        if self.registrations.contains_key(&id) {
            return Err(AhaDiscoveryResultError::DuplicateRegistration.into());
        }
        let registration = AhaDiscoveryRegistration::new(
            id,
            scope,
            secret_reference,
            permissions,
            provider,
            evidence_fence,
            registration_revision,
        )?;
        self.registrations
            .insert(registration.id().to_owned(), registration.clone());
        Ok(registration)
    }

    pub fn revoke(
        &mut self,
        id: &str,
    ) -> Result<RegistrationTransitionEvidence, AhaDiscoveryResultServiceError> {
        let registration = self
            .registrations
            .get_mut(id)
            .ok_or(AhaDiscoveryResultError::RegistrationNotFound)?;
        Ok(registration.revoke()?)
    }

    pub fn restore(
        &mut self,
        id: &str,
    ) -> Result<RegistrationTransitionEvidence, AhaDiscoveryResultServiceError> {
        let registration = self
            .registrations
            .get_mut(id)
            .ok_or(AhaDiscoveryResultError::RegistrationNotFound)?;
        Ok(registration.restore()?)
    }

    pub fn propose<T>(
        &self,
        provider: &AhaDiscoveryProvider<T>,
        registration_id: &str,
        request: AhaDiscoveryRequest,
    ) -> Result<AhaDiscoveryResultProposal, AhaDiscoveryResultServiceError>
    where
        T: AhaDiscoveryTransport,
    {
        request.validate()?;
        let registration = self
            .registrations
            .get(registration_id)
            .ok_or(AhaDiscoveryResultError::RegistrationNotFound)?;
        if request.scope != *registration.scope() {
            return Err(AhaDiscoveryResultError::ScopeMismatch.into());
        }
        if !registration.is_active() {
            let page = AhaDiscoveryPage::empty(&request)?;
            return Ok(AhaDiscoveryResultProposal::from_page(
                registration,
                page,
                InsightState::Revoked,
                TransportProvenance::BlockedEnv,
            )?);
        }

        match provider.query(&request) {
            Ok(response) => {
                let state = if response.page.fence != *registration.evidence_fence() {
                    InsightState::Stale
                } else {
                    derive_page_state(&response.page)
                };
                Ok(AhaDiscoveryResultProposal::from_page(
                    registration,
                    response.page,
                    state,
                    response.provenance,
                )?)
            }
            Err(AhaDiscoveryProviderError::Transport(
                AhaDiscoveryTransportError::BlockedEnvironment
                | AhaDiscoveryTransportError::PageNotFound,
            )) => {
                let page = AhaDiscoveryPage::empty(&request)?;
                Ok(AhaDiscoveryResultProposal::from_page(
                    registration,
                    page,
                    InsightState::ProviderUnknown,
                    provider.provenance(),
                )?)
            }
            Err(error) => Err(error.into()),
        }
    }
}

fn derive_page_state(page: &AhaDiscoveryPage) -> InsightState {
    if page.items.is_empty() {
        return InsightState::ProviderUnknown;
    }
    if page
        .items
        .iter()
        .any(|item| projection_state(item) == InsightState::Tampered)
    {
        return InsightState::Tampered;
    }
    if page
        .items
        .iter()
        .any(|item| projection_state(item) == InsightState::AccessLost)
    {
        return InsightState::AccessLost;
    }
    if page
        .items
        .iter()
        .all(|item| projection_state(item) == InsightState::Archived)
    {
        return InsightState::Archived;
    }
    if page.next_cursor.is_some() {
        InsightState::Partial
    } else {
        InsightState::Present
    }
}

fn projection_state(projection: &crate::AhaDiscoveryProjection) -> InsightState {
    match projection {
        crate::AhaDiscoveryProjection::Study(value) => value.state,
        crate::AhaDiscoveryProjection::Interview(value) => value.state,
        crate::AhaDiscoveryProjection::Question(value) => value.state,
        crate::AhaDiscoveryProjection::Response(value) => value.state,
        crate::AhaDiscoveryProjection::Highlight(value) => value.state,
        crate::AhaDiscoveryProjection::LinkedRecord(value) => value.state,
    }
}
