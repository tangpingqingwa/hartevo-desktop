//! Mission-scoped proposal, recording, and verification for bounded
//! GitHub artifact-attestation metadata.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CONSUMER_ID, CONTRACT_SCHEMA, CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID,
    SERVICE_ID,
    model::{
        AttestationMetadataDigestFence, Digest, GithubArtifactAttestationScope,
        GithubArtifactAttestationScope as Scope, GithubAttestationPage, GithubAttestationRecord,
        GithubRepositoryVisibility, MAX_ATTESTATIONS, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES,
        ModelError, OpaquePageToken, PermissionSnapshot, RegistrationId, RegistrationState,
        Revision, SecretReference, SubjectDigest, TransportProvenance, Version, canonical_digest,
    },
    provider::{
        GithubArtifactAttestationListRequest, GithubArtifactAttestationProvider,
        GithubArtifactAttestationProviderDefinition, GithubArtifactAttestationTransport,
        ProviderErrorKind, TransportError,
    },
};

pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error("model validation failed: {0}")]
    Model(#[from] ModelError),
    #[error("provider definition validation failed: {0}")]
    ProviderDefinition(#[from] crate::provider::ProviderDefinitionError),
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration is invalid or stale")]
    InvalidRegistration,
    #[error("provider permission fence does not match scope")]
    PermissionMismatch,
    #[error("provider evidence is invalid or tampered")]
    TamperedEvidence,
    #[error("provider response is truncated or exceeds the Layer-1 bound")]
    ResponseTooLarge,
    #[error("pagination cursor, page number, or filter changed")]
    PaginationMismatch,
    #[error("duplicate attestation evidence was returned")]
    DuplicateEvidence,
    #[error("idempotency key is invalid")]
    InvalidIdempotencyKey,
    #[error("proposal integrity did not verify")]
    ProposalTampered,
    #[error("recording integrity did not verify")]
    RecordingTampered,
    #[error("recording belongs to a different registration")]
    RegistrationDrift,
    #[error("provider error: {0:?}")]
    Provider(TransportError),
}

pub type Result<T> = std::result::Result<T, ServiceError>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationEvidenceState {
    AttestationEvidence,
    NoAttestationEvidence,
    AccessLoss,
    RepositoryNotFound,
    RepositoryMismatch,
    RepositoryVisibilityMismatch,
    SubjectMismatch,
    PredicateMismatch,
    SignerMismatch,
    CertificateMismatch,
    SignatureMismatch,
    TimestampMismatch,
    Partial,
    RateLimited,
    ProviderRejected,
    ProviderUnknown,
    RegistrationRevoked,
}

impl AttestationEvidenceState {
    #[must_use]
    pub const fn is_adoptable_review(self) -> bool {
        matches!(
            self,
            Self::AttestationEvidence | Self::NoAttestationEvidence
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadLimits {
    pub max_pages: u32,
    pub page_size: u32,
    pub max_attestations: usize,
    pub max_response_bytes: u32,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            page_size: MAX_PAGE_SIZE,
            max_attestations: MAX_ATTESTATIONS,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

impl ReadLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_attestations == 0
            || self.max_attestations > MAX_ATTESTATIONS
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
        {
            Err(ServiceError::ResponseTooLarge)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    pub durable_receipt: bool,
    pub outcome_adoption: bool,
    pub capability_digest: Digest,
}

impl CapabilityDescription {
    #[must_use]
    pub fn layer1() -> Self {
        let mut value = Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "describe_scope".to_owned(),
                "register_scope".to_owned(),
                "list_attestations_by_subject_digest".to_owned(),
                "compile_proposal".to_owned(),
                "record_proposal".to_owned(),
                "verify_proposal".to_owned(),
                "verify_recording".to_owned(),
                "unmount_registration".to_owned(),
                "remount_registration".to_owned(),
                "revoke_registration".to_owned(),
            ],
            permissions: vec!["attestations:read".to_owned(), "metadata:read".to_owned()],
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            durable_receipt: false,
            outcome_adoption: false,
            capability_digest: String::new(),
        };
        value.capability_digest = value.computed_digest();
        value
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        canonical_digest(&(
            &self.service_id,
            &self.provider_id,
            &self.consumer_id,
            &self.operations,
            &self.permissions,
            self.read_only,
            self.proposal_only,
            self.connected,
            self.native,
            self.durable_receipt,
            self.outcome_adoption,
        ))
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::layer1();
        if self != &expected {
            Err(ServiceError::InvalidRegistration)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubArtifactAttestationServiceDefinition {
    pub plugin_id: String,
    pub plugin_version: Version,
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub capability: CapabilityDescription,
}

impl GithubArtifactAttestationServiceDefinition {
    #[must_use]
    pub fn layer1() -> Self {
        Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: Version::new(0, 1, 0),
            schema_version: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            capability: CapabilityDescription::layer1(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version.to_string() != PLUGIN_VERSION
            || self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.contract_digest != crate::contract_digest()
        {
            return Err(ServiceError::InvalidRegistration);
        }
        self.capability.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubArtifactAttestationRegistration {
    pub registration_id: RegistrationId,
    pub plugin_version: Version,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: Version,
    pub provider_digest: Digest,
    pub api_revision: String,
    pub api_digest: Digest,
    pub installation_digest: Digest,
    pub organization_digest: Digest,
    pub repository_digest: Digest,
    pub subject_digest: Digest,
    pub predicate_digest: Digest,
    pub mission_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl GithubArtifactAttestationRegistration {
    pub fn new(
        scope: &GithubArtifactAttestationScope,
        secret: &SecretReference,
        provider: &GithubArtifactAttestationProviderDefinition,
        registration_revision: Revision,
    ) -> Result<Self> {
        let registration_id = RegistrationId::new("github-artifact-attestation-result")?;
        let mut value = Self {
            registration_id,
            plugin_version: Version::new(0, 1, 0),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version,
            provider_digest: provider.provider_digest.clone(),
            api_revision: provider.api_revision.clone(),
            api_digest: provider.api_digest.clone(),
            installation_digest: scope.installation_digest(),
            organization_digest: scope.organization_digest(),
            repository_digest: scope.repository_digest(),
            subject_digest: scope.subject_digest_fence(),
            predicate_digest: scope.predicate_digest(),
            mission_digest: scope.mission_digest(),
            permission_digest: scope.permissions.digest().clone(),
            scope_digest: scope.digest().clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            registration_revision,
            state: RegistrationState::Active,
            registration_digest: String::new(),
        };
        value.registration_digest = value.computed_digest();
        value.validate(scope, secret, provider)?;
        Ok(value)
    }

    pub fn validate(
        &self,
        scope: &GithubArtifactAttestationScope,
        secret: &SecretReference,
        provider: &GithubArtifactAttestationProviderDefinition,
    ) -> Result<()> {
        scope.validate()?;
        secret.validate_for_scope(scope)?;
        Revision::new(self.registration_revision.get())?;
        provider.validate()?;
        if self.registration_id.as_str() != "github-artifact-attestation-result"
            || self.plugin_version.to_string() != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.provider_version
            || self.provider_digest != provider.provider_digest
            || self.api_revision != provider.api_revision
            || self.api_digest != provider.api_digest
            || self.installation_digest != scope.installation_digest()
            || self.organization_digest != scope.organization_digest()
            || self.repository_digest != scope.repository_digest()
            || self.subject_digest != scope.subject_digest_fence()
            || self.predicate_digest != scope.predicate_digest()
            || self.mission_digest != scope.mission_digest()
            || self.permission_digest != *scope.permissions.digest()
            || self.scope_digest != *scope.digest()
            || self.secret_reference_digest != *secret.reference_digest()
            || self.registration_digest != self.computed_digest()
        {
            Err(ServiceError::InvalidRegistration)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        canonical_digest(&(
            (
                &self.registration_id,
                &self.plugin_version,
                &self.contract_version,
                &self.contract_digest,
                &self.provider_id,
                &self.provider_version,
                &self.provider_digest,
                &self.api_revision,
                &self.api_digest,
                &self.installation_digest,
            ),
            (
                &self.organization_digest,
                &self.repository_digest,
                &self.subject_digest,
                &self.predicate_digest,
                &self.mission_digest,
                &self.permission_digest,
                &self.scope_digest,
                &self.secret_reference_digest,
                self.registration_revision,
                self.state,
            ),
        ))
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.state.is_active()
    }

    fn transition(&mut self, state: RegistrationState) -> Result<()> {
        if self.state == RegistrationState::Revoked {
            return Err(ServiceError::RegistrationInactive);
        }
        self.registration_revision = self.registration_revision.next()?;
        self.state = state;
        self.registration_digest = self.computed_digest();
        Ok(())
    }

    pub fn unmount(&mut self) -> Result<()> {
        self.transition(RegistrationState::Unmounted)
    }

    pub fn remount(&mut self) -> Result<()> {
        if self.state == RegistrationState::Active {
            return Err(ServiceError::RegistrationInactive);
        }
        self.transition(RegistrationState::Active)
    }

    pub fn revoke(&mut self) -> Result<()> {
        self.transition(RegistrationState::Revoked)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubArtifactAttestationEvidence {
    pub state: AttestationEvidenceState,
    pub scope_digest: Digest,
    pub installation_digest: Digest,
    pub organization_digest: Digest,
    pub repository_digest: Digest,
    pub repository_visibility: GithubRepositoryVisibility,
    pub subject_digest: SubjectDigest,
    pub predicate_type: crate::PredicateType,
    pub attestations: Vec<GithubAttestationRecord>,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub response_digests: Vec<Digest>,
    pub provider_errors: Vec<TransportError>,
    pub provenance: TransportProvenance,
    pub partial: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub evidence_digest: Digest,
}

impl GithubArtifactAttestationEvidence {
    fn new(
        state: AttestationEvidenceState,
        scope: &GithubArtifactAttestationScope,
        attestations: Vec<GithubAttestationRecord>,
        response_digests: Vec<Digest>,
        provider_errors: Vec<TransportError>,
        provenance: TransportProvenance,
        partial: bool,
        secret_reference_digest: &Digest,
    ) -> Result<Self> {
        let mut value = Self {
            state,
            scope_digest: scope.digest().clone(),
            installation_digest: scope.installation_digest(),
            organization_digest: scope.organization_digest(),
            repository_digest: scope.repository_digest(),
            repository_visibility: scope.repository.visibility,
            subject_digest: scope.subject_digest.clone(),
            predicate_type: scope.predicate_type.clone(),
            attestations,
            permission_digest: scope.permissions.digest().clone(),
            secret_reference_digest: secret_reference_digest.clone(),
            response_digests,
            provider_errors,
            provenance,
            partial,
            connected: false,
            native: false,
            first_party: false,
            evidence_digest: String::new(),
        };
        value.evidence_digest = value.computed_digest();
        value.validate(scope)?;
        Ok(value)
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        canonical_digest(&(
            (
                self.state,
                &self.scope_digest,
                &self.installation_digest,
                &self.organization_digest,
                &self.repository_digest,
                self.repository_visibility,
                &self.subject_digest,
                &self.predicate_type,
                &self.attestations,
            ),
            (
                &self.permission_digest,
                &self.secret_reference_digest,
                &self.response_digests,
                &self.provider_errors,
                self.provenance,
                self.partial,
                self.connected,
                self.native,
                self.first_party,
            ),
        ))
    }

    pub fn validate(&self, scope: &GithubArtifactAttestationScope) -> Result<()> {
        if self.scope_digest != *scope.digest()
            || self.installation_digest != scope.installation_digest()
            || self.organization_digest != scope.organization_digest()
            || self.repository_digest != scope.repository_digest()
            || self.repository_visibility != scope.repository.visibility
            || self.subject_digest != scope.subject_digest
            || self.predicate_type != scope.predicate_type
            || self.permission_digest != *scope.permissions.digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.attestations.len() > MAX_ATTESTATIONS
            || self
                .response_digests
                .iter()
                .any(|digest| !crate::is_digest(digest))
            || self.evidence_digest != self.computed_digest()
        {
            return Err(ServiceError::TamperedEvidence);
        }
        for attestation in &self.attestations {
            attestation
                .validate_digest()
                .map_err(|_| ServiceError::TamperedEvidence)?;
            validate_record_scope(scope, attestation)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubArtifactAttestationProjection {
    pub state: AttestationEvidenceState,
    pub evidence: Option<GithubArtifactAttestationEvidence>,
    pub response_digests: Vec<Digest>,
    pub provider_errors: Vec<TransportError>,
    pub provenance: TransportProvenance,
    pub partial: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub projection_digest: Digest,
}

impl GithubArtifactAttestationProjection {
    fn new(
        state: AttestationEvidenceState,
        evidence: Option<GithubArtifactAttestationEvidence>,
        response_digests: Vec<Digest>,
        provider_errors: Vec<TransportError>,
        provenance: TransportProvenance,
        partial: bool,
    ) -> Self {
        let mut value = Self {
            state,
            evidence,
            response_digests,
            provider_errors,
            provenance,
            partial,
            connected: false,
            native: false,
            first_party: false,
            projection_digest: String::new(),
        };
        value.projection_digest = value.computed_digest();
        value
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        canonical_digest(&(
            self.state,
            &self.evidence,
            &self.response_digests,
            &self.provider_errors,
            self.provenance,
            self.partial,
            self.connected,
            self.native,
            self.first_party,
        ))
    }

    pub fn validate(&self, scope: &GithubArtifactAttestationScope) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.projection_digest != self.computed_digest()
        {
            return Err(ServiceError::TamperedEvidence);
        }
        if let Some(evidence) = &self.evidence {
            evidence.validate(scope)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubArtifactAttestationProposal {
    pub proposal_version: String,
    pub service_id: String,
    pub consumer_id: String,
    pub registration_id: RegistrationId,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub projection: GithubArtifactAttestationProjection,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub proposal_digest: Digest,
}

impl GithubArtifactAttestationProposal {
    fn from_projection(
        scope: &GithubArtifactAttestationScope,
        registration: &GithubArtifactAttestationRegistration,
        projection: GithubArtifactAttestationProjection,
        idempotency_key: &str,
    ) -> Self {
        let mut value = Self {
            proposal_version: format!("{CONTRACT_VERSION}/attestation-proposal"),
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_id: registration.registration_id.clone(),
            registration_revision: registration.registration_revision,
            registration_digest: registration.registration_digest.clone(),
            scope_digest: scope.digest().clone(),
            idempotency_key_digest: crate::metadata_digest_bounded(idempotency_key.as_bytes()),
            projection,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            proposal_digest: String::new(),
        };
        value.proposal_digest = value.computed_digest();
        value
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        canonical_digest(&(
            &self.proposal_version,
            &self.service_id,
            &self.consumer_id,
            &self.registration_id,
            self.registration_revision,
            &self.registration_digest,
            &self.scope_digest,
            &self.idempotency_key_digest,
            &self.projection,
            self.connected,
            self.native,
            self.first_party,
            self.provider_receipt,
            self.outcome_adopted,
        ))
    }

    pub fn validate_integrity(
        &self,
        scope: &GithubArtifactAttestationScope,
        registration: &GithubArtifactAttestationRegistration,
    ) -> Result<()> {
        if self.proposal_version != format!("{CONTRACT_VERSION}/attestation-proposal")
            || self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.registration_id != registration.registration_id
            || self.registration_revision != registration.registration_revision
            || self.registration_digest != registration.registration_digest
            || self.scope_digest != *scope.digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.proposal_digest != self.computed_digest()
        {
            return Err(ServiceError::ProposalTampered);
        }
        self.projection.validate(scope)
    }

    #[must_use]
    pub const fn can_adopt_outcome(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubArtifactAttestationRecording {
    pub recording_version: String,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Option<Digest>,
    pub state: AttestationEvidenceState,
    pub durable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adopted: bool,
    pub recording_digest: Digest,
}

impl GithubArtifactAttestationRecording {
    fn from_proposal(proposal: &GithubArtifactAttestationProposal) -> Self {
        let mut value = Self {
            recording_version: format!("{CONTRACT_VERSION}/attestation-recording"),
            registration_revision: proposal.registration_revision,
            registration_digest: proposal.registration_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal
                .projection
                .evidence
                .as_ref()
                .map(|evidence| evidence.evidence_digest.clone()),
            state: proposal.projection.state,
            durable: false,
            connected: false,
            native: false,
            first_party: false,
            outcome_adopted: false,
            recording_digest: String::new(),
        };
        value.recording_digest = value.computed_digest();
        value
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        canonical_digest(&(
            &self.recording_version,
            self.registration_revision,
            &self.registration_digest,
            &self.proposal_digest,
            &self.evidence_digest,
            self.state,
            self.durable,
            self.connected,
            self.native,
            self.first_party,
            self.outcome_adopted,
        ))
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.recording_version != format!("{CONTRACT_VERSION}/attestation-recording")
            || self.durable
            || self.connected
            || self.native
            || self.first_party
            || self.outcome_adopted
            || self.recording_digest != self.computed_digest()
        {
            Err(ServiceError::RecordingTampered)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationReport {
    pub valid: bool,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Option<Digest>,
    pub verification_digest: Digest,
}

pub struct GithubArtifactAttestationService<T> {
    scope: GithubArtifactAttestationScope,
    secret: SecretReference,
    provider: GithubArtifactAttestationProvider<T>,
    definition: GithubArtifactAttestationServiceDefinition,
    registration: GithubArtifactAttestationRegistration,
    limits: ReadLimits,
}

impl<T: fmt::Debug> fmt::Debug for GithubArtifactAttestationService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubArtifactAttestationService")
            .field("scope", &self.scope)
            .field("secret", &self.secret)
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("limits", &self.limits)
            .finish()
    }
}

impl<T: GithubArtifactAttestationTransport + fmt::Debug> GithubArtifactAttestationService<T> {
    pub fn new(
        scope: GithubArtifactAttestationScope,
        secret: SecretReference,
        provider: GithubArtifactAttestationProvider<T>,
        limits: ReadLimits,
    ) -> Result<Self> {
        scope.validate()?;
        secret.validate_for_scope(&scope)?;
        if secret.is_revoked() {
            return Err(ServiceError::SecretRevoked);
        }
        limits.validate()?;
        provider.definition().validate()?;
        if provider.definition().permissions != scope.permissions {
            return Err(ServiceError::PermissionMismatch);
        }
        let definition = GithubArtifactAttestationServiceDefinition::layer1();
        definition.validate()?;
        let registration = GithubArtifactAttestationRegistration::new(
            &scope,
            &secret,
            provider.definition(),
            Revision::new(1)?,
        )?;
        Ok(Self {
            scope,
            secret,
            provider,
            definition,
            registration,
            limits,
        })
    }

    pub fn with_default_limits(
        scope: GithubArtifactAttestationScope,
        secret: SecretReference,
        provider: GithubArtifactAttestationProvider<T>,
    ) -> Result<Self> {
        Self::new(scope, secret, provider, ReadLimits::default())
    }

    #[must_use]
    pub fn scope(&self) -> &GithubArtifactAttestationScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    #[must_use]
    pub fn provider(&self) -> &GithubArtifactAttestationProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut GithubArtifactAttestationProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn provider_definition(&self) -> &GithubArtifactAttestationProviderDefinition {
        self.provider.definition()
    }

    #[must_use]
    pub fn definition(&self) -> &GithubArtifactAttestationServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn capabilities(&self) -> &CapabilityDescription {
        &self.definition.capability
    }

    #[must_use]
    pub fn registration(&self) -> &GithubArtifactAttestationRegistration {
        &self.registration
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret.is_revoked()
    }

    pub fn unmount_registration(&mut self) -> Result<()> {
        self.registration.unmount()
    }

    pub fn remount_registration(&mut self) -> Result<()> {
        if self.secret.is_revoked() {
            return Err(ServiceError::SecretRevoked);
        }
        self.registration.remount()
    }

    pub fn revoke_registration(&mut self) -> Result<()> {
        self.secret.revoke().map_err(ServiceError::Model)?;
        self.registration.revoke()
    }

    pub fn read_attestation_evidence(&mut self) -> Result<GithubArtifactAttestationProjection> {
        self.read_evidence()
    }

    pub fn read_evidence(&mut self) -> Result<GithubArtifactAttestationProjection> {
        self.ensure_active()?;
        self.registration
            .validate(&self.scope, &self.secret, self.provider.definition())?;

        let mut page_number = 1;
        let mut next_page = None;
        let mut seen_tokens = BTreeSet::new();
        let mut seen_attestations = BTreeSet::new();
        let mut attestations = Vec::new();
        let mut response_digests = Vec::new();
        let mut provider_errors = Vec::new();
        let mut partial = false;

        loop {
            if page_number > self.limits.max_pages {
                return Err(ServiceError::PaginationMismatch);
            }
            let request = GithubArtifactAttestationListRequest::from_scope(
                &self.scope,
                page_number,
                self.limits.page_size,
                next_page.clone(),
            )?;
            let page = match self.provider.list_attestations(&request) {
                Ok(page) => page,
                Err(error) => {
                    if matches!(error.kind, ProviderErrorKind::TamperedEvidence) {
                        return Err(ServiceError::TamperedEvidence);
                    }
                    let state = state_for_provider_error(&error);
                    provider_errors.push(error);
                    partial |= provider_errors.last().is_some_and(|e| e.truncated);
                    return self.make_projection(
                        state,
                        attestations,
                        response_digests,
                        provider_errors,
                        partial,
                    );
                }
            };
            page.validate_digest()
                .map_err(|_| ServiceError::TamperedEvidence)?;
            if page.page != page_number || page.response_bytes > self.limits.max_response_bytes {
                return Err(ServiceError::PaginationMismatch);
            }
            if page.items.len() > self.limits.page_size as usize
                || attestations.len().saturating_add(page.items.len())
                    > self.limits.max_attestations
            {
                return Err(ServiceError::ResponseTooLarge);
            }
            if page.repository_visibility != self.scope.repository.visibility {
                return self.make_projection(
                    AttestationEvidenceState::RepositoryVisibilityMismatch,
                    attestations,
                    response_digests,
                    vec![TransportError::new(
                        ProviderErrorKind::VisibilityMismatch,
                        None,
                        b"repository visibility fence changed",
                    )],
                    partial,
                );
            }
            if !page.repository_access.is_accessible() {
                let state = if matches!(page.repository_access, crate::RepositoryAccess::NotFound) {
                    AttestationEvidenceState::RepositoryNotFound
                } else {
                    AttestationEvidenceState::AccessLoss
                };
                return self.make_projection(
                    state,
                    attestations,
                    response_digests,
                    vec![TransportError::new(
                        ProviderErrorKind::AccessLoss,
                        None,
                        b"repository access is unavailable",
                    )],
                    partial,
                );
            }
            response_digests.push(page.response_digest.clone());
            for attestation in page.items {
                attestation
                    .validate_digest()
                    .map_err(|_| ServiceError::TamperedEvidence)?;
                if let Some(kind) = record_mismatch(&self.scope, &attestation) {
                    return self.make_projection(
                        state_for_provider_kind(kind),
                        attestations,
                        response_digests,
                        vec![TransportError::new(
                            kind,
                            None,
                            b"attestation metadata does not match the scope fence",
                        )],
                        partial,
                    );
                }
                if !seen_attestations.insert(attestation.attestation_digest.clone()) {
                    return Err(ServiceError::DuplicateEvidence);
                }
                attestations.push(attestation);
            }
            if page.truncated {
                partial = true;
                return self.make_projection(
                    AttestationEvidenceState::Partial,
                    attestations,
                    response_digests,
                    provider_errors,
                    partial,
                );
            }
            let returned_token = page.next_page_token;
            if let Some(token) = &returned_token
                && !seen_tokens.insert(token.digest().clone())
            {
                return Err(ServiceError::PaginationMismatch);
            }
            next_page = returned_token;
            if next_page.is_none() {
                let state = if attestations.is_empty() {
                    AttestationEvidenceState::NoAttestationEvidence
                } else {
                    AttestationEvidenceState::AttestationEvidence
                };
                return self.make_projection(
                    state,
                    attestations,
                    response_digests,
                    provider_errors,
                    partial,
                );
            }
            page_number += 1;
        }
    }

    pub fn compile_proposal(
        &mut self,
        idempotency_key: impl AsRef<str>,
    ) -> Result<GithubArtifactAttestationProposal> {
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(ServiceError::InvalidIdempotencyKey);
        }
        let projection = self.read_evidence()?;
        Ok(GithubArtifactAttestationProposal::from_projection(
            &self.scope,
            &self.registration,
            projection,
            idempotency_key,
        ))
    }

    pub fn compile_attestation_proposal(
        &mut self,
        idempotency_key: impl AsRef<str>,
    ) -> Result<GithubArtifactAttestationProposal> {
        self.compile_proposal(idempotency_key)
    }

    pub fn record_proposal(
        &self,
        proposal: &GithubArtifactAttestationProposal,
    ) -> Result<GithubArtifactAttestationRecording> {
        self.ensure_active()?;
        proposal.validate_integrity(&self.scope, &self.registration)?;
        Ok(GithubArtifactAttestationRecording::from_proposal(proposal))
    }

    pub fn record(
        &self,
        proposal: &GithubArtifactAttestationProposal,
    ) -> Result<GithubArtifactAttestationRecording> {
        self.record_proposal(proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &GithubArtifactAttestationProposal,
    ) -> Result<VerificationReport> {
        self.ensure_active()?;
        proposal.validate_integrity(&self.scope, &self.registration)?;
        let evidence_digest = proposal
            .projection
            .evidence
            .as_ref()
            .map(|evidence| evidence.evidence_digest.clone());
        let verification_digest = canonical_digest(&(
            &self.registration.registration_digest,
            &proposal.proposal_digest,
            &evidence_digest,
            false,
        ));
        Ok(VerificationReport {
            valid: true,
            registration_digest: self.registration.registration_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest,
            verification_digest,
        })
    }

    pub fn verify_recording(&self, recording: &GithubArtifactAttestationRecording) -> Result<()> {
        self.ensure_active()?;
        recording.validate_integrity()?;
        if recording.registration_digest != self.registration.registration_digest
            || recording.registration_revision != self.registration.registration_revision
        {
            Err(ServiceError::RegistrationDrift)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub const fn limits(&self) -> ReadLimits {
        self.limits
    }

    fn ensure_active(&self) -> Result<()> {
        if self.secret.is_revoked() {
            Err(ServiceError::SecretRevoked)
        } else if !self.registration.is_active() {
            Err(ServiceError::RegistrationInactive)
        } else {
            Ok(())
        }
    }

    fn make_projection(
        &self,
        state: AttestationEvidenceState,
        attestations: Vec<GithubAttestationRecord>,
        response_digests: Vec<Digest>,
        provider_errors: Vec<TransportError>,
        partial: bool,
    ) -> Result<GithubArtifactAttestationProjection> {
        let evidence = GithubArtifactAttestationEvidence::new(
            state,
            &self.scope,
            attestations,
            response_digests.clone(),
            provider_errors.clone(),
            self.provider.provenance(),
            partial,
            self.secret.reference_digest(),
        )?;
        Ok(GithubArtifactAttestationProjection::new(
            state,
            Some(evidence),
            response_digests,
            provider_errors,
            self.provider.provenance(),
            partial,
        ))
    }
}

fn validate_record_scope(
    scope: &GithubArtifactAttestationScope,
    record: &GithubAttestationRecord,
) -> Result<()> {
    if let Some(kind) = record_mismatch(scope, record) {
        Err(ServiceError::Provider(TransportError::new(
            kind,
            None,
            b"attestation record does not match scope",
        )))
    } else {
        Ok(())
    }
}

fn record_mismatch(
    scope: &GithubArtifactAttestationScope,
    record: &GithubAttestationRecord,
) -> Option<ProviderErrorKind> {
    if record.subject_digest != scope.subject_digest {
        return Some(ProviderErrorKind::SubjectMismatch);
    }
    if record.predicate_type != scope.predicate_type {
        return Some(ProviderErrorKind::PredicateMismatch);
    }
    if scope
        .repository
        .repository_id
        .is_some_and(|repository_id| record.repository_id != repository_id)
    {
        return Some(ProviderErrorKind::RepositoryMismatch);
    }
    if record.repository_visibility != scope.repository.visibility {
        return Some(ProviderErrorKind::VisibilityMismatch);
    }
    if !record.repository_access.is_accessible() {
        return Some(ProviderErrorKind::AccessLoss);
    }
    if let Some(fence) = &scope.metadata_fence {
        if record.signer_identity_digest != fence.signer_identity_digest {
            return Some(ProviderErrorKind::SignerMismatch);
        }
        if record.certificate_digest != fence.certificate_digest {
            return Some(ProviderErrorKind::CertificateMismatch);
        }
        if record.signature_digest != fence.signature_digest {
            return Some(ProviderErrorKind::SignatureMismatch);
        }
        if record.timestamp_digest != fence.timestamp_digest {
            return Some(ProviderErrorKind::TimestampMismatch);
        }
        if record.predicate_metadata_digest != fence.predicate_metadata_digest
            || record.verification_metadata_digest != fence.verification_metadata_digest
        {
            return Some(ProviderErrorKind::PredicateMismatch);
        }
    }
    None
}

fn state_for_provider_error(error: &TransportError) -> AttestationEvidenceState {
    state_for_provider_kind(error.kind)
}

fn state_for_provider_kind(kind: ProviderErrorKind) -> AttestationEvidenceState {
    match kind {
        ProviderErrorKind::Unauthenticated
        | ProviderErrorKind::PermissionDenied
        | ProviderErrorKind::AccessLoss => AttestationEvidenceState::AccessLoss,
        ProviderErrorKind::NotFound => AttestationEvidenceState::RepositoryNotFound,
        ProviderErrorKind::RepositoryMismatch => AttestationEvidenceState::RepositoryMismatch,
        ProviderErrorKind::SubjectMismatch => AttestationEvidenceState::SubjectMismatch,
        ProviderErrorKind::PredicateMismatch => AttestationEvidenceState::PredicateMismatch,
        ProviderErrorKind::VisibilityMismatch => {
            AttestationEvidenceState::RepositoryVisibilityMismatch
        }
        ProviderErrorKind::SignerMismatch => AttestationEvidenceState::SignerMismatch,
        ProviderErrorKind::CertificateMismatch => AttestationEvidenceState::CertificateMismatch,
        ProviderErrorKind::SignatureMismatch => AttestationEvidenceState::SignatureMismatch,
        ProviderErrorKind::TimestampMismatch => AttestationEvidenceState::TimestampMismatch,
        ProviderErrorKind::RateLimited => AttestationEvidenceState::RateLimited,
        ProviderErrorKind::Truncated => AttestationEvidenceState::Partial,
        ProviderErrorKind::BadRequest
        | ProviderErrorKind::Conflict
        | ProviderErrorKind::Unprocessable => AttestationEvidenceState::ProviderRejected,
        _ => AttestationEvidenceState::ProviderUnknown,
    }
}

pub type GithubArtifactAttestationServiceError = ServiceError;
pub type GithubArtifactAttestationRegistrationState = RegistrationState;
pub type GithubArtifactAttestationMetadata = GithubAttestationRecord;
pub type GithubArtifactAttestationMetadataFence = AttestationMetadataDigestFence;
pub type GithubArtifactAttestationScopeRegistration = GithubArtifactAttestationRegistration;
pub type GithubArtifactAttestationScopeType = Scope;
pub type GithubArtifactAttestationSubjectDigest = SubjectDigest;
pub type GithubArtifactAttestationPermissionSnapshot = PermissionSnapshot;
pub type GithubArtifactAttestationPage = GithubAttestationPage;
pub type GithubArtifactAttestationOpaquePageToken = OpaquePageToken;
