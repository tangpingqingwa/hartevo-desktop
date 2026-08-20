use std::{collections::BTreeMap, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{NomadDeploymentResultError, NomadTransportError, Result};
use crate::model::{
    ConsentScope, Digest, EvidenceDigests, FailureEvidence, MAX_METADATA_ITEMS, MAX_PAGES, Mission,
    NomadDeploymentEvidence, NomadDeploymentProposal, NomadDeploymentReceipt, NomadDeploymentScope,
    NomadDeploymentState, NomadProviderScope, NomadReadRequest, PermissionSnapshot, Project,
    RedactionSummary, RegistrationStatus, RegistrationTransitionEvidence, Revision,
    SecretReference, VerificationFailure, WorkProduct,
};
use crate::provider::{NomadProvider, NomadProviderSnapshot, NomadTransport};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NomadDeploymentServiceDefinition {
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
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

impl Default for NomadDeploymentServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: crate::SCHEMA_VERSION.to_owned(),
            contract_version: crate::CONTRACT_VERSION.to_owned(),
            service_id: crate::SERVICE_ID.to_owned(),
            provider_id: crate::PROVIDER_ID.to_owned(),
            consumer_id: crate::CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            live_external_io: false,
            external_writes: false,
            kernel_authority: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }
}

impl NomadDeploymentServiceDefinition {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != crate::SCHEMA_VERSION
            || self.contract_version != crate::CONTRACT_VERSION
            || self.service_id != crate::SERVICE_ID
            || self.provider_id != crate::PROVIDER_ID
            || self.consumer_id != crate::CONSUMER_ID
            || self.contract_digest != crate::contract_digest()
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.live_external_io
            || self.external_writes
            || self.kernel_authority
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_adoption
            || self.work_product_adoption
        {
            return Err(NomadDeploymentResultError::ProviderDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NomadCapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub provider_version: String,
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

/// Version/API/permission/consent/scope/evidence digest-bound registration.
/// The raw SecretReference never appears in its custom serialization.
#[derive(Clone, Eq, PartialEq)]
pub struct NomadDeploymentRegistration {
    id_digest: Digest,
    plugin_version_digest: Digest,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_version: String,
    provider_api_revision: String,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: NomadDeploymentScope,
    secret_reference: SecretReference,
    registration_revision: Revision,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl fmt::Debug for NomadDeploymentRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NomadDeploymentRegistration")
            .field("id_digest", &self.id_digest)
            .field("plugin_version_digest", &self.plugin_version_digest)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_version", &self.provider_version)
            .field("provider_api_revision", &self.provider_api_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", self.permission_snapshot.digest())
            .field("consent_digest", self.consent.digest())
            .field("scope_digest", &self.scope.digest())
            .field(
                "secret_reference_digest",
                self.secret_reference.reference_digest(),
            )
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for NomadDeploymentRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("NomadDeploymentRegistration", 17)?;
        state.serialize_field("idDigest", &self.id_digest)?;
        state.serialize_field("pluginVersionDigest", &self.plugin_version_digest)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerVersion", &self.provider_version)?;
        state.serialize_field("providerApiRevision", &self.provider_api_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", self.permission_snapshot.digest())?;
        state.serialize_field("consentDigest", self.consent.digest())?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field(
            "secretReferenceDigest",
            self.secret_reference.reference_digest(),
        )?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.serialize_field("reversible", &true)?;
        state.serialize_field("revocable", &true)?;
        state.end()
    }
}

impl NomadDeploymentRegistration {
    pub fn new(
        registration_id: impl AsRef<str>,
        scope: NomadDeploymentScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        registration_revision: u64,
    ) -> Result<Self> {
        if registration_id.as_ref().is_empty() {
            return Err(NomadDeploymentResultError::InvalidRegistration);
        }
        scope.validate()?;
        secret_reference.validate(&scope)?;
        permission_snapshot.validate()?;
        consent.validate_for(&scope, consent.issued_at)?;
        let mut value = Self {
            id_digest: Digest::from_text(registration_id.as_ref()),
            plugin_version_digest: Digest::from_text(crate::PLUGIN_VERSION),
            contract_version: crate::CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: crate::PROVIDER_ID.to_owned(),
            provider_version: crate::PROVIDER_VERSION.to_owned(),
            provider_api_revision: crate::PROVIDER_API_REVISION.to_owned(),
            provider_digest: crate::provider_digest(),
            permission_snapshot,
            consent,
            scope,
            secret_reference,
            registration_revision: Revision::new(registration_revision)?,
            status: RegistrationStatus::Active,
            registration_digest: Digest::pending(),
        };
        value.registration_digest = value.compute_digest();
        value.validate()?;
        Ok(value)
    }

    pub fn from_provider<T: NomadTransport>(
        registration_id: impl AsRef<str>,
        provider: &NomadProvider<T>,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = Self::new(
            registration_id,
            provider.scope().clone(),
            provider.secret_reference().clone(),
            permission_snapshot,
            consent,
            registration_revision,
        )?;
        if registration.provider_digest != *provider.provider_digest() {
            return Err(NomadDeploymentResultError::ProviderDrift);
        }
        Ok(registration)
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        self.permission_snapshot.validate()?;
        self.consent
            .validate_for(&self.scope, self.consent.issued_at)?;
        if self.plugin_version_digest != Digest::from_text(crate::PLUGIN_VERSION)
            || self.contract_version != crate::CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != crate::PROVIDER_ID
            || self.provider_version != crate::PROVIDER_VERSION
            || self.provider_api_revision != crate::PROVIDER_API_REVISION
            || self.provider_digest != crate::provider_digest()
            || self.registration_revision.get() == 0
            || self.registration_digest != self.compute_digest()
        {
            return Err(NomadDeploymentResultError::InvalidRegistration);
        }
        Ok(())
    }

    #[must_use]
    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    #[must_use]
    pub fn plugin_version_digest(&self) -> &Digest {
        &self.plugin_version_digest
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
    pub fn provider_version(&self) -> &str {
        &self.provider_version
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
    pub fn permission_digest(&self) -> &Digest {
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
    pub fn scope(&self) -> &NomadDeploymentScope {
        &self.scope
    }

    #[must_use]
    pub fn provider_scope(&self) -> &NomadProviderScope {
        &self.scope.provider
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

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(NomadDeploymentResultError::RegistrationReversed);
        }
        self.transition(RegistrationStatus::Active)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(RegistrationStatus::Reversed)
    }

    fn transition(&mut self, next: RegistrationStatus) -> Result<RegistrationTransitionEvidence> {
        let from = self.status;
        if from == next {
            return match next {
                RegistrationStatus::Revoked => Err(NomadDeploymentResultError::AlreadyRevoked),
                RegistrationStatus::Reversed => Err(NomadDeploymentResultError::AlreadyReversed),
                RegistrationStatus::Active => Err(NomadDeploymentResultError::InvalidRegistration),
            };
        }
        if from == RegistrationStatus::Reversed {
            return Err(NomadDeploymentResultError::RegistrationReversed);
        }
        let next_revision = self
            .registration_revision
            .get()
            .checked_add(1)
            .ok_or(NomadDeploymentResultError::RevisionOverflow)?;
        self.registration_revision = Revision::new(next_revision)?;
        self.status = next;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationTransitionEvidence {
            from,
            to: next,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
        })
    }

    fn compute_digest(&self) -> Digest {
        let input = (
            &self.id_digest,
            &self.plugin_version_digest,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            &self.provider_version,
            &self.provider_api_revision,
            &self.provider_digest,
            self.permission_snapshot.digest(),
            self.consent.digest(),
            self.scope.digest(),
            self.secret_reference.reference_digest(),
            self.registration_revision,
            self.status,
        );
        Digest::from_serializable(&input)
    }
}

/// Typed Layer-1 service for bounded Nomad metadata and redacted proposals.
pub struct NomadDeploymentResultService<T: NomadTransport = crate::FixtureNomadTransport> {
    provider: NomadProvider<T>,
    registration: NomadDeploymentRegistration,
    definition: NomadDeploymentServiceDefinition,
    recordings: BTreeMap<Digest, Digest>,
}

impl<T: NomadTransport> fmt::Debug for NomadDeploymentResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NomadDeploymentResultService")
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("definition", &self.definition)
            .field("recording_count", &self.recordings.len())
            .finish()
    }
}

impl<T: NomadTransport> NomadDeploymentResultService<T> {
    pub fn register(
        provider: NomadProvider<T>,
        registration_id: impl AsRef<str>,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = NomadDeploymentRegistration::from_provider(
            registration_id,
            &provider,
            permission_snapshot,
            consent,
            registration_revision,
        )?;
        Self::new(provider, registration)
    }

    pub fn new(
        provider: NomadProvider<T>,
        registration: NomadDeploymentRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.scope().digest() != provider.scope().digest()
            || registration.provider_digest() != provider.provider_digest()
            || registration.secret_reference_digest()
                != provider.secret_reference().reference_digest()
        {
            return Err(NomadDeploymentResultError::InvalidRegistration);
        }
        let definition = NomadDeploymentServiceDefinition::default();
        definition.validate()?;
        Ok(Self {
            provider,
            registration,
            definition,
            recordings: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn provider(&self) -> &NomadProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut NomadProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &NomadDeploymentRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut NomadDeploymentRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &NomadDeploymentScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn service_definition(&self) -> &NomadDeploymentServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn describe_scope(&self) -> &NomadDeploymentScope {
        self.scope()
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> NomadCapabilityDescription {
        NomadCapabilityDescription {
            service_id: crate::SERVICE_ID.to_owned(),
            provider_id: crate::PROVIDER_ID.to_owned(),
            provider_version: crate::PROVIDER_VERSION.to_owned(),
            api_revision: crate::PROVIDER_API_REVISION.to_owned(),
            operations: vec![
                "read_job_metadata".to_owned(),
                "read_deployment_metadata".to_owned(),
                "read_allocation_metadata".to_owned(),
                "compile_deployment_result_proposal".to_owned(),
                "record_local_observation".to_owned(),
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

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn read(&mut self, observed_at: u64) -> Result<NomadDeploymentEvidence> {
        self.ensure_readable(observed_at)?;
        let result = self.provider.read_snapshot_with_fence(
            Some(self.registration.registration_digest()),
            Some(self.registration.permission_digest()),
            Some(self.registration.consent_digest()),
        );
        match result {
            Ok(snapshot) => {
                snapshot.validate(self.scope())?;
                let state = snapshot.state();
                Ok(self.build_evidence(Some(snapshot), state, None, observed_at))
            }
            Err(error) => Ok(self.build_evidence(
                None,
                state_for_error(&error),
                Some(failure_for_error(&error)),
                observed_at,
            )),
        }
    }

    pub fn read_with_fence(
        &mut self,
        request: &NomadReadRequest,
        observed_at: u64,
    ) -> Result<NomadDeploymentEvidence> {
        request.validate_for(
            self.scope(),
            self.registration.registration_digest(),
            self.registration.permission_digest(),
            self.registration.consent_digest(),
        )?;
        self.read(observed_at)
    }

    pub fn compile_proposal(&mut self, observed_at: u64) -> Result<NomadDeploymentProposal> {
        let evidence = self.read(observed_at)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: NomadDeploymentEvidence,
    ) -> Result<NomadDeploymentProposal> {
        self.registration.validate()?;
        evidence.validate_integrity()?;
        if evidence.registration_digest != *self.registration.registration_digest()
            || evidence.scope.digest() != self.scope().digest()
            || evidence.registration_revision != self.registration.registration_revision()
            || evidence.permission_digest != *self.registration.permission_digest()
            || evidence.consent_digest != *self.registration.consent_digest()
            || evidence.secret_reference_digest != *self.registration.secret_reference_digest()
        {
            return Err(NomadDeploymentResultError::InvalidProposal);
        }
        if matches!(
            evidence.state,
            NomadDeploymentState::Tampered | NomadDeploymentState::Replay
        ) {
            return Err(NomadDeploymentResultError::TamperedEvidence);
        }
        Ok(NomadDeploymentProposal::from_evidence(evidence))
    }

    pub fn record_observation(
        &mut self,
        proposal: &NomadDeploymentProposal,
        idempotency_key: impl AsRef<str>,
        recorded_at: u64,
    ) -> Result<NomadDeploymentReceipt> {
        self.verify_proposal(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::model::MAX_IDENTIFIER_BYTES * 4 {
            return Err(NomadDeploymentResultError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        let replayed = match self.recordings.get(&key_digest) {
            Some(existing) if existing == &proposal.proposal_digest => true,
            Some(_) => return Err(NomadDeploymentResultError::RecordingConflict),
            None => false,
        };
        self.recordings
            .entry(key_digest.clone())
            .or_insert_with(|| proposal.proposal_digest.clone());
        let receipt = NomadDeploymentReceipt::new(proposal, key_digest, recorded_at, replayed);
        receipt.validate_integrity()?;
        Ok(receipt)
    }

    pub fn record_local_observation(
        &mut self,
        proposal: &NomadDeploymentProposal,
        idempotency_key: impl AsRef<str>,
        recorded_at: u64,
    ) -> Result<NomadDeploymentReceipt> {
        self.record_observation(proposal, idempotency_key, recorded_at)
    }

    #[must_use]
    pub fn verify(&self, proposal: &NomadDeploymentProposal) -> crate::NomadDeploymentVerification {
        let mut failures = Vec::new();
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::Tampered);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationMismatch);
        }
        if proposal.scope.digest() != self.scope().digest() {
            failures.push(VerificationFailure::ScopeMismatch);
        }
        if proposal.registration_revision != self.registration.registration_revision() {
            failures.push(VerificationFailure::StaleRevision);
        }
        if !self.registration.is_active() {
            failures.push(match self.registration.status() {
                RegistrationStatus::Revoked => VerificationFailure::RegistrationRevoked,
                RegistrationStatus::Reversed => VerificationFailure::RegistrationReversed,
                RegistrationStatus::Active => VerificationFailure::RegistrationMismatch,
            });
        }
        match proposal.state {
            NomadDeploymentState::Successful => {}
            NomadDeploymentState::Absent => failures.push(VerificationFailure::Absent),
            NomadDeploymentState::Partial => failures.push(VerificationFailure::Partial),
            NomadDeploymentState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            NomadDeploymentState::ProviderUnknown | NomadDeploymentState::BlockedEnv => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            NomadDeploymentState::Tampered => failures.push(VerificationFailure::Tampered),
            NomadDeploymentState::Replay => failures.push(VerificationFailure::Replay),
            NomadDeploymentState::RegistrationRevoked => {
                failures.push(VerificationFailure::RegistrationRevoked);
            }
            NomadDeploymentState::RegistrationReversed => {
                failures.push(VerificationFailure::RegistrationReversed);
            }
            NomadDeploymentState::Pending
            | NomadDeploymentState::Running
            | NomadDeploymentState::Failed
            | NomadDeploymentState::Stopped => failures.push(VerificationFailure::NotSuccessful),
        }
        if proposal.connected || proposal.native || proposal.first_party {
            failures.push(VerificationFailure::NativeClaim);
        }
        crate::NomadDeploymentVerification::new(proposal, failures)
    }

    pub fn verify_proposal(
        &self,
        proposal: &NomadDeploymentProposal,
    ) -> Result<crate::NomadDeploymentVerification> {
        let report = self.verify(proposal);
        if report.failures.contains(&VerificationFailure::Tampered) {
            Err(NomadDeploymentResultError::TamperedEvidence)
        } else {
            Ok(report)
        }
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<()> {
        self.provider.reject_write(operation)
    }

    fn ensure_readable(&self, observed_at: u64) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(NomadDeploymentResultError::RegistrationInactive);
        }
        self.registration
            .consent()
            .validate_for(self.scope(), observed_at)
    }

    fn build_evidence(
        &self,
        snapshot: Option<NomadProviderSnapshot>,
        state: NomadDeploymentState,
        failure: Option<FailureEvidence>,
        observed_at: u64,
    ) -> NomadDeploymentEvidence {
        let (job, deployment, allocation, page_count, item_count, complete, provenance) = snapshot
            .map_or_else(
                || (None, None, None, 0, 0, false, self.provider.provenance()),
                |snapshot| {
                    (
                        Some(snapshot.job),
                        snapshot.deployment,
                        snapshot.allocation,
                        snapshot.page_count,
                        snapshot.item_count,
                        snapshot.complete,
                        snapshot.provenance,
                    )
                },
            );
        let deployment_digest = deployment
            .as_ref()
            .map(|value| value.metadata_digest.clone());
        let allocation_digest = allocation
            .as_ref()
            .map(|value| value.metadata_digest.clone());
        let mut evidence = NomadDeploymentEvidence {
            scope: self.scope().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            registration_revision: self.registration.registration_revision(),
            permission_digest: self.registration.permission_digest().clone(),
            consent_digest: self.registration.consent_digest().clone(),
            secret_reference_digest: self.registration.secret_reference_digest().clone(),
            state,
            job,
            deployment,
            allocation,
            page_count,
            item_count,
            complete,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            redaction: RedactionSummary::default(),
            failure,
            digests: EvidenceDigests {
                plugin_version_digest: Digest::from_text(crate::PLUGIN_VERSION),
                contract_digest: crate::contract_digest(),
                provider_digest: self.registration.provider_digest().clone(),
                api_digest: Digest::from_text(crate::PROVIDER_API_REVISION),
                permission_digest: self.registration.permission_digest().clone(),
                consent_digest: self.registration.consent_digest().clone(),
                scope_digest: self.scope().digest(),
                secret_reference_digest: self.registration.secret_reference_digest().clone(),
                project_digest: self.scope().project_digest(),
                mission_digest: self.scope().mission_digest(),
                work_product_digest: self.scope().work_product_digest(),
                provider_scope_digest: self.scope().provider_scope_digest(),
                job_digest: self.scope().provider.job_digest(),
                deployment_digest,
                allocation_digest,
                evidence_digest: Digest::pending(),
            },
            evidence_digest: Digest::pending(),
            observed_at,
        };
        let digest = evidence.compute_digest();
        evidence.evidence_digest = digest.clone();
        evidence.digests.evidence_digest = digest;
        evidence
    }
}

fn state_for_error(error: &NomadDeploymentResultError) -> NomadDeploymentState {
    match error {
        NomadDeploymentResultError::Transport(transport) => match transport {
            NomadTransportError::NotFound => NomadDeploymentState::Absent,
            NomadTransportError::Partial => NomadDeploymentState::Partial,
            NomadTransportError::Unauthorized
            | NomadTransportError::Forbidden
            | NomadTransportError::AccessLost => NomadDeploymentState::AccessLoss,
            NomadTransportError::BlockedEnv => NomadDeploymentState::BlockedEnv,
            NomadTransportError::Tampered => NomadDeploymentState::Tampered,
            NomadTransportError::ProviderUnknown
            | NomadTransportError::Conflict
            | NomadTransportError::RateLimited { .. }
            | NomadTransportError::Timeout
            | NomadTransportError::InvalidResponse => NomadDeploymentState::ProviderUnknown,
        },
        NomadDeploymentResultError::RegistrationInactive
        | NomadDeploymentResultError::SecretRevoked => NomadDeploymentState::RegistrationRevoked,
        NomadDeploymentResultError::RegistrationReversed => {
            NomadDeploymentState::RegistrationReversed
        }
        NomadDeploymentResultError::TamperedEvidence
        | NomadDeploymentResultError::InvalidResponse
        | NomadDeploymentResultError::ScopeMismatch
        | NomadDeploymentResultError::ProviderDrift
        | NomadDeploymentResultError::InvalidRegistration => NomadDeploymentState::Tampered,
        NomadDeploymentResultError::ReplayDetected => NomadDeploymentState::Replay,
        _ => NomadDeploymentState::ProviderUnknown,
    }
}

fn failure_for_error(error: &NomadDeploymentResultError) -> FailureEvidence {
    if let NomadDeploymentResultError::Transport(transport) = error {
        return FailureEvidence::from_transport(transport);
    }
    let category = match error {
        NomadDeploymentResultError::RegistrationInactive
        | NomadDeploymentResultError::SecretRevoked => "registration_revoked",
        NomadDeploymentResultError::RegistrationReversed => "registration_reversed",
        NomadDeploymentResultError::TamperedEvidence
        | NomadDeploymentResultError::ScopeMismatch
        | NomadDeploymentResultError::ProviderDrift
        | NomadDeploymentResultError::InvalidRegistration => "tampered",
        NomadDeploymentResultError::ReplayDetected => "replay",
        NomadDeploymentResultError::PartialEvidence => "partial",
        _ => "provider_unknown",
    };
    FailureEvidence {
        category: category.to_owned(),
        status_code: None,
        retry_after_seconds: None,
        detail_digest: Digest::from_text(category),
    }
}

#[allow(dead_code)]
fn _scope_parts(scope: &NomadDeploymentScope) -> (&Project, &Mission, &WorkProduct) {
    (&scope.project, &scope.mission, &scope.work_product)
}

#[allow(dead_code)]
fn _provider_scope(scope: &NomadDeploymentScope) -> &NomadProviderScope {
    &scope.provider
}

#[allow(dead_code)]
fn _read_bounds_are_bounded() -> bool {
    MAX_PAGES <= 4 && MAX_METADATA_ITEMS <= 3
}
