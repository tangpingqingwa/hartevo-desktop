//! Typed service, proposal, verification, and reversible registration.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsConnectContactConsumer;
use crate::error::{AwsConnectContactResultError, AwsConnectTransportError, Result};
use crate::model::{
    AttributeEvidenceProjection, AttributeKeyClass, AwsConnectContactScope, ConsentScope,
    ContactEvidenceState, ContactProjection, ContactRecord, Digest, EvidenceDigests,
    MissionProjection, PermissionSnapshot, ProjectProjection, ProjectionFailure, ScopeProjection,
    SearchContactsRequest, TransportProvenance, WorkProductProjection, digest_optional,
    mission_projection, project_projection, scope_projection, work_product_projection,
};
use crate::provider::{AwsConnectProvider, AwsConnectProviderDefinition, AwsConnectTransport};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, EVIDENCE_LEVEL, MAX_PAGE_SIZE, PLUGIN_VERSION,
    PROVIDER_API_REVISION, PROVIDER_ID, SERVICE_ID, contract_digest,
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
            "aws-connect-registration-transition/v1",
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

/// Version/contract/provider/API/permission/consent/scope/secret-bound
/// registration. The secret handle itself is never retained or serialized.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsConnectContactResultRegistration {
    id_digest: Digest,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    api_revision: String,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: AwsConnectContactScope,
    scope_digest: Digest,
    secret_reference: crate::model::SecretReference,
    evidence_binding_digest: Digest,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl AwsConnectContactResultRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsConnectContactScope,
        secret_reference: crate::model::SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsConnectProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let id = id.into();
        if !valid_id(&id) || registration_revision == 0 {
            return Err(AwsConnectContactResultError::InvalidRegistration);
        }
        provider.validate()?;
        let mut registration = Self {
            id_digest: Digest::from_text(id),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            api_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_snapshot,
            consent,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            evidence_binding_digest: Digest::from_text("unsealed-aws-connect-evidence-binding"),
            registration_revision,
            status: RegistrationStatus::Active,
            binding_digest: Digest::from_text("unsealed-aws-connect-registration"),
        };
        registration.evidence_binding_digest = registration.calculate_evidence_binding_digest();
        registration.binding_digest = registration.calculate_binding_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
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

    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
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

    pub fn scope(&self) -> &AwsConnectContactScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &crate::model::SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    pub fn evidence_binding_digest(&self) -> &Digest {
        &self.evidence_binding_digest
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
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

    pub fn validate(&self) -> Result<()> {
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_revision != PROVIDER_API_REVISION
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.evidence_binding_digest != self.calculate_evidence_binding_digest()
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(AwsConnectContactResultError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        if self
            .permission_snapshot
            .permissions
            .iter()
            .any(|permission| !self.consent.permissions().contains(permission))
        {
            return Err(AwsConnectContactResultError::InvalidConsent);
        }
        self.consent.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsConnectContactResultError::RegistrationReversed);
        }
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsConnectContactResultError::RegistrationReversed);
        }
        self.transition(RegistrationStatus::Reversed)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsConnectContactResultError::RegistrationReversed);
        }
        self.transition(RegistrationStatus::Active)
    }

    fn transition(&mut self, status: RegistrationStatus) -> Result<RegistrationTransitionEvidence> {
        let previous_status = self.status;
        self.status = status;
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(AwsConnectContactResultError::InvalidRegistration)?;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            status,
            self.registration_revision,
            self.binding_digest.clone(),
        ))
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-connect-registration/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("api_revision", self.api_revision.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("consent", self.consent.digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                (
                    "evidence_binding",
                    self.evidence_binding_digest.as_str().to_owned(),
                ),
                ("evidence_level", EVIDENCE_LEVEL.to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }

    fn calculate_evidence_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-connect-evidence-binding/v1",
            &[
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_revision.clone()),
                (
                    "permission",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("evidence_level", EVIDENCE_LEVEL.to_owned()),
            ],
        )
    }
}

pub type AwsConnectRegistration = AwsConnectContactResultRegistration;

impl fmt::Debug for AwsConnectContactResultRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsConnectContactResultRegistration")
            .field("id_digest", &self.id_digest)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("api_revision", &self.api_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("evidence_binding_digest", &self.evidence_binding_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for AwsConnectContactResultRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsConnectContactResultRegistration", 17)?;
        state.serialize_field("idDigest", &self.id_digest)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("evidenceBindingDigest", &self.evidence_binding_digest)?;
        state.serialize_field("evidenceLevel", EVIDENCE_LEVEL)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.binding_digest)?;
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
pub struct SearchProjection {
    pub pages: u16,
    pub list_complete: bool,
    pub matched_contacts: u16,
    pub target_found: bool,
    pub filter_digest: Digest,
    pub sort_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub search_digest: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsConnectContactResultProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub scope: ScopeProjection,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: ContactEvidenceState,
    pub search: SearchProjection,
    pub contact: Option<ContactProjection>,
    pub attributes: Option<AttributeEvidenceProjection>,
    pub evidence: EvidenceDigests,
    pub failure: Option<ProjectionFailure>,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub durable_receipt: bool,
    pub independent_readback: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsConnectContactResultProposal {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &AwsConnectContactResultRegistration,
        provider: &AwsConnectProviderDefinition,
        request: &SearchContactsRequest,
        state: ContactEvidenceState,
        search: SearchProjection,
        contact: Option<ContactProjection>,
        attributes: Option<AttributeEvidenceProjection>,
        describe_digest: Option<Digest>,
        failure: Option<ProjectionFailure>,
        provenance: TransportProvenance,
    ) -> Self {
        let scope = scope_projection(registration.scope());
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            evidence_binding_digest: registration.evidence_binding_digest.clone(),
            permission_digest: registration.permission_digest(),
            consent_digest: registration.consent_digest(),
            scope_digest: registration.scope_digest.clone(),
            filter_digest: search.filter_digest.clone(),
            sort_digest: search.sort_digest.clone(),
            cursor_digest: search.cursor_digest.clone(),
            search_digest: search.search_digest.clone(),
            describe_digest,
            attributes_digest: attributes
                .as_ref()
                .map(|value| value.evidence_digest.clone()),
            evidence_digest: Digest::from_text("unsealed-aws-connect-evidence"),
        };
        evidence.evidence_digest = calculate_evidence_digest(
            &evidence,
            state,
            &search,
            contact.as_ref(),
            attributes.as_ref(),
            failure.as_ref(),
        );
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: registration.scope_digest().clone(),
            scope,
            mission: mission_projection(registration.scope().mission()),
            project: project_projection(registration.scope().project()),
            work_product: work_product_projection(registration.scope().work_product()),
            state,
            search,
            contact,
            attributes,
            evidence,
            failure,
            provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            durable_receipt: false,
            independent_readback: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-aws-connect-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_proposal_digest();
        let _ = request;
        proposal
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        self.review_only
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.durable_receipt
            || self.independent_readback
            || self.outcome_adopted
            || self.work_product_adopted
            || self.scope_digest != self.scope.scope_digest
            || self.evidence.evidence_digest
                != calculate_evidence_digest(
                    &self.evidence,
                    self.state,
                    &self.search,
                    self.contact.as_ref(),
                    self.attributes.as_ref(),
                    self.failure.as_ref(),
                )
            || self.proposal_digest != self.calculate_proposal_digest()
        {
            return Err(AwsConnectContactResultError::TamperedEvidence);
        }
        self.evidence.contract_digest.validate()?;
        self.evidence.provider_digest.validate()?;
        self.evidence.scope_digest.validate()?;
        Ok(())
    }

    fn calculate_proposal_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-connect-contact-result-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("provider", self.provider_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                (
                    "search",
                    serde_json::to_string(&self.search).expect("search projection serializes"),
                ),
                (
                    "contact",
                    self.contact.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("contact projection serializes")
                    }),
                ),
                (
                    "attributes",
                    self.attributes.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("attribute projection serializes")
                    }),
                ),
                (
                    "evidence",
                    serde_json::to_string(&self.evidence).expect("evidence serializes"),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("failure serializes")
                    }),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    EvidenceBindingDigestMismatch,
    PermissionDigestMismatch,
    ConsentDigestMismatch,
    ScopeDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    RetentionExpired,
    AccessLoss,
    ProviderUnknown,
    StaleMission,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn new(valid: bool, review_eligible: bool, mut failures: Vec<VerificationFailure>) -> Self {
        failures.sort_unstable();
        failures.dedup();
        let verification_digest = Digest::from_parts(
            "aws-connect-verification-report/v1",
            &[
                ("valid", valid.to_string()),
                ("review_eligible", review_eligible.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|failure| format!("{failure:?}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Self {
            valid,
            review_eligible,
            failures,
            verification_digest,
        }
    }
}

pub struct AwsConnectContactResultService<T: AwsConnectTransport> {
    registration: AwsConnectContactResultRegistration,
    provider: AwsConnectProvider<T>,
}

impl<T: AwsConnectTransport> AwsConnectContactResultService<T> {
    pub fn new(
        scope: AwsConnectContactScope,
        secret_reference: crate::model::SecretReference,
        consent: ConsentScope,
        provider: AwsConnectProvider<T>,
        registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        Self::with_registration(
            "aws-connect-contact-registration",
            scope,
            secret_reference,
            PermissionSnapshot::for_layer_one(1),
            consent,
            provider,
            1,
            registration_time,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_registration(
        registration_id: impl Into<String>,
        scope: AwsConnectContactScope,
        secret_reference: crate::model::SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: AwsConnectProvider<T>,
        registration_revision: u64,
        _registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = AwsConnectContactResultRegistration::new(
            registration_id,
            scope,
            secret_reference,
            permission_snapshot,
            consent,
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
            operations: self
                .provider
                .definition()
                .operations
                .iter()
                .map(|operation| operation.as_str().to_owned())
                .collect(),
            permissions: crate::LAYER1_PERMISSIONS
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

    pub fn scope(&self) -> &AwsConnectContactScope {
        self.registration.scope()
    }

    pub fn registration(&self) -> &AwsConnectContactResultRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsConnectContactResultRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsConnectProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsConnectProvider<T> {
        &mut self.provider
    }

    pub fn request(
        &self,
        observed_at: DateTime<Utc>,
        attribute_classes: Vec<AttributeKeyClass>,
    ) -> Result<SearchContactsRequest> {
        SearchContactsRequest::for_scope_with_attributes(
            self.scope(),
            MAX_PAGE_SIZE,
            crate::MAX_PAGES,
            attribute_classes,
            observed_at,
        )
        .map(|request| {
            request.bind(
                self.provider.definition().provider_digest.clone(),
                self.registration.registration_digest().clone(),
            )
        })
    }

    pub fn default_request(&self, observed_at: DateTime<Utc>) -> Result<SearchContactsRequest> {
        self.request(observed_at, Vec::new())
    }

    pub fn request_with_attributes(
        &self,
        observed_at: DateTime<Utc>,
        attribute_classes: Vec<AttributeKeyClass>,
    ) -> Result<SearchContactsRequest> {
        self.request(observed_at, attribute_classes)
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

    pub fn consumer(&self) -> Result<MissionAwsConnectContactConsumer> {
        MissionAwsConnectContactConsumer::new(self.scope().clone(), self.registration.clone())
    }

    pub fn verify(&self, proposal: &AwsConnectContactResultProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.provider_digest != self.provider.definition().provider_digest {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.evidence_binding_digest != *self.registration.evidence_binding_digest()
        {
            failures.push(VerificationFailure::EvidenceBindingDigestMismatch);
        }
        if proposal.evidence.permission_digest != self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.consent_digest != self.registration.consent_digest() {
            failures.push(VerificationFailure::ConsentDigestMismatch);
        }
        if proposal.scope_digest != *self.registration.scope_digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.mission.revision != self.scope().mission().revision()
            || proposal.project.revision != self.scope().project().revision()
            || proposal.work_product.revision != self.scope().work_product().revision()
        {
            failures.push(VerificationFailure::StaleMission);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            ContactEvidenceState::Partial => failures.push(VerificationFailure::PartialEvidence),
            ContactEvidenceState::RetentionExpired => {
                failures.push(VerificationFailure::RetentionExpired);
            }
            ContactEvidenceState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            ContactEvidenceState::ProviderUnknown
            | ContactEvidenceState::NotFound
            | ContactEvidenceState::Throttled
            | ContactEvidenceState::RegistrationRevoked => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            ContactEvidenceState::Completed => {}
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        VerificationReport::new(
            valid,
            valid && proposal.state.is_review_complete(),
            failures,
        )
    }

    pub fn propose(
        &mut self,
        request: SearchContactsRequest,
    ) -> Result<AwsConnectContactResultProposal> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsConnectContactResultError::RegistrationInactive);
        }
        if request.scope_digest() != self.registration.scope_digest()
            || *request.expected_provider_digest() != self.provider.definition().provider_digest
            || request.expected_registration_digest() != self.registration.registration_digest()
        {
            return Err(AwsConnectContactResultError::ScopeMismatch);
        }
        request.validate_against(self.scope())?;
        if self.registration.consent().is_revoked() {
            return Err(AwsConnectContactResultError::ConsentRevoked);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at())
        {
            return Err(AwsConnectContactResultError::ConsentExpired);
        }

        let mut current_request = request.clone();
        let mut seen_tokens = BTreeSet::new();
        let mut page_digests = Vec::new();
        let mut pages = 0_u16;
        let mut list_complete = false;
        let mut target = None;
        let mut matched_contacts = 0_u16;
        let mut final_cursor_digest = request.cursor_digest();
        loop {
            if pages >= request.max_pages() {
                break;
            }
            let response = match self.provider.search_contacts(&current_request) {
                Ok(response) => response,
                Err(error) => {
                    return Ok(self.proposal_with_state(
                        &request,
                        ContactEvidenceState::from_search_transport(&error),
                        pages,
                        false,
                        page_digests,
                        final_cursor_digest,
                        target,
                        None,
                        None,
                        Some(failure_from_transport("search_contacts", &error)),
                    ));
                }
            };
            if response.provenance() != self.provider.provenance() {
                return Err(AwsConnectContactResultError::ProviderDrift);
            }
            response.validate_integrity(&current_request)?;
            pages = pages.saturating_add(1);
            page_digests.push(response.response_digest().clone());
            matched_contacts = matched_contacts
                .saturating_add(u16::try_from(response.contacts().len()).unwrap_or(u16::MAX));
            for contact in response.contacts() {
                contact.validate_against(self.scope())?;
                if let Some(previous) = &target {
                    if previous.digest() != contact.digest() {
                        return Err(AwsConnectContactResultError::ContactReplaced);
                    }
                }
                target = Some(contact.clone());
            }
            let Some(next_token) = response.next_token().cloned() else {
                list_complete = true;
                break;
            };
            let token_digest = next_token.digest();
            if !seen_tokens.insert(token_digest.clone()) {
                return Err(AwsConnectContactResultError::CursorLoop);
            }
            final_cursor_digest = Some(token_digest);
            if pages >= request.max_pages() {
                break;
            }
            let cursor = crate::model::SearchCursor::new(next_token, &current_request, pages + 1)?;
            current_request = current_request.with_cursor(cursor)?;
        }

        let search_digest = nonempty_digest("aws-connect-search-pages/v1", &page_digests);
        let search = SearchProjection {
            pages,
            list_complete,
            matched_contacts,
            target_found: target.is_some(),
            filter_digest: filter_digest(&request),
            sort_digest: request.sort().digest(),
            cursor_digest: final_cursor_digest,
            search_digest,
        };

        let describe_request = crate::model::DescribeContactRequest::for_scope(self.scope())?;
        let describe_response = match self.provider.describe_contact(&describe_request) {
            Ok(response) => response,
            Err(error) => {
                let state = if !list_complete {
                    ContactEvidenceState::Partial
                } else {
                    ContactEvidenceState::from_describe_transport(&error)
                };
                return Ok(self.proposal_with_search(
                    &request,
                    state,
                    search,
                    target.as_ref().map(ContactRecord::projection),
                    None,
                    None,
                    Some(failure_from_transport("describe_contact", &error)),
                ));
            }
        };
        if describe_response.provenance() != self.provider.provenance() {
            return Err(AwsConnectContactResultError::ProviderDrift);
        }
        describe_response.validate_integrity(&describe_request)?;
        describe_response.contact().validate_against(self.scope())?;
        if let Some(listed) = &target {
            if listed.digest() != describe_response.contact().digest() {
                return Err(AwsConnectContactResultError::ContactReplaced);
            }
        }
        let contact_projection = Some(describe_response.contact().projection());
        if target.is_none() {
            return Ok(self.proposal_with_search(
                &request,
                ContactEvidenceState::NotFound,
                search,
                contact_projection,
                Some(describe_response.response_digest().clone()),
                None,
                Some(ProjectionFailure::new(
                    "search_contact_not_found",
                    Some(404),
                    None,
                )),
            ));
        }

        let mut attributes = None;
        if !request.attribute_classes().is_empty() {
            let attribute_request = crate::model::GetContactAttributesRequest::for_scope(
                self.scope(),
                request.attribute_classes().to_vec(),
            )?;
            let attribute_response = match self.provider.get_contact_attributes(&attribute_request)
            {
                Ok(response) => response,
                Err(error) => {
                    let state = if !list_complete {
                        ContactEvidenceState::Partial
                    } else {
                        ContactEvidenceState::from_attribute_transport(&error)
                    };
                    return Ok(self.proposal_with_search(
                        &request,
                        state,
                        search,
                        contact_projection,
                        Some(describe_response.response_digest().clone()),
                        None,
                        Some(failure_from_transport("get_contact_attributes", &error)),
                    ));
                }
            };
            if attribute_response.provenance() != self.provider.provenance() {
                return Err(AwsConnectContactResultError::ProviderDrift);
            }
            attribute_response.validate_integrity(&attribute_request)?;
            attributes = Some(attribute_response.evidence().clone());
        }
        let state = if !list_complete {
            ContactEvidenceState::Partial
        } else {
            ContactEvidenceState::Completed
        };
        Ok(self.proposal_with_search(
            &request,
            state,
            search,
            contact_projection,
            Some(describe_response.response_digest().clone()),
            attributes,
            None,
        ))
    }

    fn proposal_with_state(
        &self,
        request: &SearchContactsRequest,
        state: ContactEvidenceState,
        pages: u16,
        list_complete: bool,
        page_digests: Vec<Digest>,
        cursor_digest: Option<Digest>,
        target: Option<crate::model::ContactRecord>,
        describe_digest: Option<Digest>,
        attributes: Option<AttributeEvidenceProjection>,
        failure: Option<ProjectionFailure>,
    ) -> AwsConnectContactResultProposal {
        let search = SearchProjection {
            pages,
            list_complete,
            matched_contacts: 0,
            target_found: target.is_some(),
            filter_digest: filter_digest(request),
            sort_digest: request.sort().digest(),
            cursor_digest,
            search_digest: nonempty_digest("aws-connect-search-pages/v1", &page_digests),
        };
        self.proposal_with_search(
            request,
            state,
            search,
            target.as_ref().map(crate::model::ContactRecord::projection),
            describe_digest,
            attributes,
            failure,
        )
    }

    fn proposal_with_search(
        &self,
        request: &SearchContactsRequest,
        state: ContactEvidenceState,
        search: SearchProjection,
        contact: Option<ContactProjection>,
        describe_digest: Option<Digest>,
        attributes: Option<AttributeEvidenceProjection>,
        failure: Option<ProjectionFailure>,
    ) -> AwsConnectContactResultProposal {
        AwsConnectContactResultProposal::new(
            &self.registration,
            self.provider.definition(),
            request,
            state,
            search,
            contact,
            attributes,
            describe_digest,
            failure,
            self.provider.provenance().clone(),
        )
    }
}

impl<T: AwsConnectTransport> fmt::Debug for AwsConnectContactResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsConnectContactResultService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

trait TransportState {
    fn from_search_transport(error: &AwsConnectTransportError) -> ContactEvidenceState;
    fn from_describe_transport(error: &AwsConnectTransportError) -> ContactEvidenceState;
    fn from_attribute_transport(error: &AwsConnectTransportError) -> ContactEvidenceState;
}

impl TransportState for ContactEvidenceState {
    fn from_search_transport(error: &AwsConnectTransportError) -> ContactEvidenceState {
        match error {
            AwsConnectTransportError::Unauthorized
            | AwsConnectTransportError::Forbidden
            | AwsConnectTransportError::AccessLost => ContactEvidenceState::AccessLoss,
            AwsConnectTransportError::RateLimited { .. } => ContactEvidenceState::Throttled,
            AwsConnectTransportError::NotFound => ContactEvidenceState::NotFound,
            AwsConnectTransportError::Partial => ContactEvidenceState::Partial,
            AwsConnectTransportError::BlockedEnv
            | AwsConnectTransportError::BadRequest
            | AwsConnectTransportError::ServerError { .. }
            | AwsConnectTransportError::Timeout
            | AwsConnectTransportError::InvalidResponse => ContactEvidenceState::ProviderUnknown,
        }
    }

    fn from_describe_transport(error: &AwsConnectTransportError) -> ContactEvidenceState {
        if matches!(error, AwsConnectTransportError::NotFound) {
            ContactEvidenceState::RetentionExpired
        } else {
            Self::from_search_transport(error)
        }
    }

    fn from_attribute_transport(error: &AwsConnectTransportError) -> ContactEvidenceState {
        Self::from_search_transport(error)
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn nonempty_digest(domain: &str, values: &[Digest]) -> Option<Digest> {
    (!values.is_empty()).then(|| {
        Digest::from_parts(
            domain,
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

fn filter_digest(request: &SearchContactsRequest) -> Digest {
    Digest::from_parts(
        "aws-connect-filter-set/v1",
        &[(
            "filters",
            request
                .filters()
                .iter()
                .map(|filter| filter.digest().as_str().to_owned())
                .collect::<Vec<_>>()
                .join("\n"),
        )],
    )
}

fn failure_from_transport(operation: &str, error: &AwsConnectTransportError) -> ProjectionFailure {
    let category = match error {
        AwsConnectTransportError::BlockedEnv => "blocked_env",
        AwsConnectTransportError::BadRequest => "bad_request",
        AwsConnectTransportError::Unauthorized => "unauthorized",
        AwsConnectTransportError::Forbidden => "forbidden",
        AwsConnectTransportError::NotFound => "retention_or_not_found",
        AwsConnectTransportError::RateLimited { .. } => "throttled",
        AwsConnectTransportError::ServerError { .. } => "provider_server_error",
        AwsConnectTransportError::Timeout => "timeout",
        AwsConnectTransportError::AccessLost => "access_loss",
        AwsConnectTransportError::Partial => "partial",
        AwsConnectTransportError::InvalidResponse => "invalid_response",
    };
    let retry_after_seconds = match error {
        AwsConnectTransportError::RateLimited {
            retry_after_seconds,
        } => *retry_after_seconds,
        _ => None,
    };
    ProjectionFailure::new(
        format!("{operation}:{category}"),
        error.status_code(),
        retry_after_seconds,
    )
}

fn calculate_evidence_digest(
    evidence: &EvidenceDigests,
    state: ContactEvidenceState,
    search: &SearchProjection,
    contact: Option<&ContactProjection>,
    attributes: Option<&AttributeEvidenceProjection>,
    failure: Option<&ProjectionFailure>,
) -> Digest {
    Digest::from_parts(
        "aws-connect-contact-evidence/v1",
        &[
            (
                "plugin_version",
                evidence.plugin_version_digest.as_str().to_owned(),
            ),
            ("contract", evidence.contract_digest.as_str().to_owned()),
            ("provider", evidence.provider_digest.as_str().to_owned()),
            (
                "evidence_binding",
                evidence.evidence_binding_digest.as_str().to_owned(),
            ),
            ("permission", evidence.permission_digest.as_str().to_owned()),
            ("consent", evidence.consent_digest.as_str().to_owned()),
            ("scope", evidence.scope_digest.as_str().to_owned()),
            ("filter", evidence.filter_digest.as_str().to_owned()),
            ("sort", evidence.sort_digest.as_str().to_owned()),
            ("cursor", digest_optional(evidence.cursor_digest.as_ref())),
            ("search", digest_optional(evidence.search_digest.as_ref())),
            (
                "describe",
                digest_optional(evidence.describe_digest.as_ref()),
            ),
            (
                "attributes",
                digest_optional(evidence.attributes_digest.as_ref()),
            ),
            ("state", format!("{state:?}")),
            (
                "search_projection",
                serde_json::to_string(search).expect("search projection serializes"),
            ),
            (
                "contact",
                contact.map_or_else(String::new, |value| {
                    serde_json::to_string(value).expect("contact projection serializes")
                }),
            ),
            (
                "attributes_projection",
                attributes.map_or_else(String::new, |value| {
                    serde_json::to_string(value).expect("attribute projection serializes")
                }),
            ),
            (
                "failure",
                failure.map_or_else(String::new, |value| {
                    serde_json::to_string(value).expect("failure projection serializes")
                }),
            ),
        ],
    )
}
