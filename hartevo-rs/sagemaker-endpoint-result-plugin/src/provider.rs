use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use crate::error::{Result, SageMakerEndpointResultError};
use crate::model::{
    EndpointConfigDescriptionRecord, EndpointDescriptionRecord, ProductionVariantStatus,
    ProviderProvenance, RegistrationRevocation, RegistrationStatus, ResultVerificationStatus,
    SageMakerDeploymentEvidence, SageMakerDeploymentReceipt, SageMakerEndpointConfigDescription,
    SageMakerEndpointDescription, SageMakerEndpointStatus, SageMakerModelDeploymentProposal,
    SageMakerReadRequest, SageMakerRegistration, SageMakerResultState, SageMakerScope,
    VerificationFailure, VerificationReport,
};
use crate::transport::{
    BlockedEnvCredentialResolver, SageMakerTransport, SageMakerTransportError,
    SigV4CredentialMaterial, SigV4CredentialResolver,
};

/// Provider lifecycle/status projection. It is intentionally below kernel
/// truth, consent, effect, receipt, verification, and Outcome authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SageMakerProviderState {
    Disconnected,
    ReadOnlyAvailable,
    Recording,
    Fake,
    Fixture,
    Loopback,
    BlockedEnv,
    Revoked,
    Creating,
    InService,
    Updating,
    SystemUpdating,
    RollingBack,
    OutOfService,
    Deleting,
    Failed,
    UpdateRollbackFailed,
    VariantUpdating,
    VariantStatusMismatch,
    TrafficMismatch,
    EndpointConfigDrift,
    SameNameReplacement,
    Partial,
    AccessLost,
    ProviderUnknown,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    Timeout,
    ServerError,
}

/// Typed SageMaker endpoint/config read provider. The credential and
/// transport parameters are generic seams so fixtures cannot accidentally
/// become native or connected evidence.
pub struct SageMakerProvider<T, R>
where
    T: SageMakerTransport,
    R: SigV4CredentialResolver,
{
    registration: SageMakerRegistration,
    transport: T,
    credentials: R,
    state: SageMakerProviderState,
    last_endpoint_arn_digest: Option<crate::model::Digest>,
    last_endpoint_config_arn_digest: Option<crate::model::Digest>,
    last_model_revision: Option<crate::model::ModelRevision>,
    receipts: BTreeMap<crate::model::Digest, SageMakerDeploymentReceipt>,
    evidence_fingerprints:
        BTreeMap<(crate::model::Digest, crate::model::Digest), crate::model::Digest>,
}

impl<T, R> fmt::Debug for SageMakerProvider<T, R>
where
    T: SageMakerTransport,
    R: SigV4CredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SageMakerProvider")
            .field("registration", &self.registration)
            .field("transport", &self.transport)
            .field("credentials", &self.credentials)
            .field("state", &self.state)
            .field("last_endpoint_arn_digest", &self.last_endpoint_arn_digest)
            .field(
                "last_endpoint_config_arn_digest",
                &self.last_endpoint_config_arn_digest,
            )
            .field("last_model_revision", &self.last_model_revision)
            .field("receipt_count", &self.receipts.len())
            .field(
                "evidence_fingerprint_count",
                &self.evidence_fingerprints.len(),
            )
            .finish()
    }
}

impl<T, R> SageMakerProvider<T, R>
where
    T: SageMakerTransport,
    R: SigV4CredentialResolver,
{
    pub fn new(registration: SageMakerRegistration, transport: T, credentials: R) -> Result<Self> {
        registration.validate()?;
        if registration.status != RegistrationStatus::Active {
            return Err(SageMakerEndpointResultError::RegistrationRevoked);
        }
        Ok(Self {
            registration,
            transport,
            credentials,
            state: SageMakerProviderState::Disconnected,
            last_endpoint_arn_digest: None,
            last_endpoint_config_arn_digest: None,
            last_model_revision: None,
            receipts: BTreeMap::new(),
            evidence_fingerprints: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &SageMakerRegistration {
        &self.registration
    }

    pub fn state(&self) -> SageMakerProviderState {
        self.state
    }

    pub fn provenance(&self) -> ProviderProvenance {
        if self.state == SageMakerProviderState::BlockedEnv
            || self.state == SageMakerProviderState::Revoked
        {
            ProviderProvenance::BlockedEnv
        } else {
            self.transport.provenance()
        }
    }

    pub fn native_status(&self) -> crate::model::NativeStatus {
        crate::model::NativeStatus::BlockedEnv
    }

    pub fn native_transport(&self) -> bool {
        self.provenance().is_native()
    }

    pub const fn native_connected(&self) -> bool {
        false
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn receipts(&self) -> &BTreeMap<crate::model::Digest, SageMakerDeploymentReceipt> {
        &self.receipts
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation> {
        let revocation = self.registration.revoke()?;
        self.state = SageMakerProviderState::Revoked;
        Ok(revocation)
    }

    pub fn describe_endpoint(&mut self) -> Result<SageMakerEndpointDescription> {
        self.ensure_active()?;
        let credential = self.authenticate()?;
        let record = self
            .transport
            .describe_endpoint(&credential, &self.registration.scope)
            .map_err(|error| self.map_transport_error(&error))?;
        self.validate_endpoint_record(&record)?;
        self.mark_available();
        let mut description = SageMakerEndpointDescription {
            scope: self.registration.scope.clone(),
            endpoint_arn_digest: record.endpoint_arn_digest,
            endpoint_config_name: record.endpoint_config_name,
            status: record.status,
            failure_reason: record.failure_reason,
            production_variant_count: record.production_variants.len(),
            creation_time: record.creation_time,
            last_modified_time: record.last_modified_time,
            provenance: self.provenance(),
            native_transport: self.native_transport(),
            native_connected: false,
            first_party: false,
            read_digest: crate::model::Digest::pending(),
        };
        description.read_digest = description.computed_digest();
        description.validate()?;
        self.set_state_from_endpoint(&description.status);
        Ok(description)
    }

    pub fn describe_endpoint_config(&mut self) -> Result<SageMakerEndpointConfigDescription> {
        self.ensure_active()?;
        let credential = self.authenticate()?;
        let record = self
            .transport
            .describe_endpoint_config(&credential, &self.registration.scope)
            .map_err(|error| self.map_transport_error(&error))?;
        self.validate_endpoint_config_record(&record)?;
        self.mark_available();
        let mut description = SageMakerEndpointConfigDescription {
            scope: self.registration.scope.clone(),
            endpoint_config_arn_digest: record.endpoint_config_arn_digest,
            config_digest: record.config_digest,
            production_variant_count: record.production_variants.len(),
            creation_time: record.creation_time,
            execution_role_digest: record.execution_role_digest,
            network_isolation: record.network_isolation,
            provenance: self.provenance(),
            native_transport: self.native_transport(),
            native_connected: false,
            first_party: false,
            read_digest: crate::model::Digest::pending(),
        };
        description.read_digest = description.computed_digest();
        description.validate()?;
        Ok(description)
    }

    #[allow(clippy::too_many_lines)]
    pub fn read_deployment_evidence(
        &mut self,
        request: &SageMakerReadRequest,
    ) -> Result<SageMakerDeploymentEvidence> {
        request.validate()?;
        self.ensure_active()?;
        self.ensure_scope(&request.scope)?;
        let credential = self.authenticate()?;
        let endpoint = self
            .transport
            .describe_endpoint(&credential, &self.registration.scope)
            .map_err(|error| self.map_transport_error(&error))?;
        self.validate_endpoint_record(&endpoint)?;
        let endpoint_config = self
            .transport
            .describe_endpoint_config(&credential, &self.registration.scope)
            .map_err(|error| self.map_transport_error(&error))?;
        self.validate_endpoint_config_record(&endpoint_config)?;

        let variant = endpoint
            .variant(&self.registration.scope.production_variant_name)
            .cloned()
            .ok_or_else(|| {
                self.state = SageMakerProviderState::Partial;
                SageMakerEndpointResultError::VariantMismatch
            })?;
        let config_variant = endpoint_config
            .variant(&self.registration.scope.production_variant_name)
            .cloned()
            .ok_or_else(|| {
                self.state = SageMakerProviderState::Partial;
                SageMakerEndpointResultError::VariantMismatch
            })?;

        self.validate_variant_scope(&variant)?;
        if config_variant.model_name != variant.model_name
            || config_variant.model_revision != variant.model_revision
            || config_variant.image_reference != variant.image_reference
            || config_variant.code_digest != variant.code_digest
        {
            self.state = SageMakerProviderState::EndpointConfigDrift;
            return Err(SageMakerEndpointResultError::EndpointConfigDrift);
        }

        let traffic = endpoint.traffic_snapshot()?;
        let traffic_matches = traffic == self.registration.scope.traffic;
        let state = Self::result_state(&endpoint, &variant.status, traffic_matches);
        let provenance = self.provenance();
        let mut evidence = SageMakerDeploymentEvidence {
            scope: self.registration.scope.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            endpoint_digest: endpoint_evidence_digest(&endpoint),
            endpoint_config_digest: endpoint_config.config_digest.clone(),
            variant_digest: crate::model::Digest::pending(),
            status_digest: crate::model::Digest::pending(),
            endpoint_name: endpoint.endpoint_name.clone(),
            endpoint_arn_digest: endpoint.endpoint_arn_digest.clone(),
            endpoint_config_name: endpoint.endpoint_config_name.clone(),
            endpoint_config_arn_digest: endpoint_config.endpoint_config_arn_digest.clone(),
            endpoint_status: endpoint.status.clone(),
            endpoint_failure_reason: endpoint.failure_reason.clone(),
            variant_name: variant.variant_name.clone(),
            variant_status: variant.status.clone(),
            variant_status_message: variant.status_message.clone(),
            traffic,
            model_name: variant.model_name.clone(),
            model_revision: variant.model_revision.clone(),
            image_reference: variant.image_reference.clone(),
            code_digest: variant.code_digest.clone(),
            config_digest: variant.config_digest.clone(),
            endpoint_config_metadata_digest: crate::model::canonical_digest(&(
                &endpoint_config.endpoint_config_name,
                &endpoint_config.endpoint_config_arn_digest,
                &endpoint_config.config_digest,
                &endpoint_config.creation_time,
            )),
            endpoint_creation_time: endpoint.creation_time.clone(),
            endpoint_last_modified_time: endpoint.last_modified_time.clone(),
            config_creation_time: endpoint_config.creation_time.clone(),
            failure_reason: endpoint
                .failure_reason
                .clone()
                .or_else(|| variant.status_message.clone()),
            state,
            provenance,
            native_transport: provenance.is_native(),
            native_connected: false,
            first_party: false,
            partial: endpoint.partial || endpoint_config.partial,
            observed_at: crate::model::MetadataTimestamp::new("layer1-recorded")?,
            evidence_digest: crate::model::Digest::pending(),
        };
        evidence.variant_digest = evidence.computed_variant_digest();
        evidence.status_digest = evidence.computed_status_digest();
        evidence.evidence_digest = evidence.computed_digest();
        evidence.validate()?;
        self.last_endpoint_arn_digest = Some(endpoint.endpoint_arn_digest);
        self.last_endpoint_config_arn_digest = Some(endpoint_config.endpoint_config_arn_digest);
        self.last_model_revision = Some(variant.model_revision.clone());
        self.state = provider_state_for_result(state);
        Ok(evidence)
    }

    pub fn read_evidence(&mut self) -> Result<SageMakerDeploymentEvidence> {
        let request = SageMakerReadRequest::new(
            self.registration.scope.clone(),
            self.registration.scope.mission_revision,
            self.registration.scope.work_product_revision,
        )?;
        self.read_deployment_evidence(&request)
    }

    pub fn compile_model_deployment_proposal(
        &self,
        evidence: &SageMakerDeploymentEvidence,
    ) -> Result<SageMakerModelDeploymentProposal> {
        self.ensure_active()?;
        evidence.validate()?;
        if evidence.registration_digest != self.registration.registration_digest {
            return Err(SageMakerEndpointResultError::RegistrationDigestMismatch);
        }
        SageMakerModelDeploymentProposal::from_evidence(
            evidence,
            self.registration.registration_digest.clone(),
        )
    }

    pub fn record_deployment_receipt(
        &mut self,
        evidence: &SageMakerDeploymentEvidence,
    ) -> Result<SageMakerDeploymentReceipt> {
        self.ensure_active()?;
        evidence.validate()?;
        if evidence.registration_digest != self.registration.registration_digest {
            return Err(SageMakerEndpointResultError::RegistrationDigestMismatch);
        }
        let key = (
            evidence.scope.digest(),
            evidence.endpoint_arn_digest.clone(),
        );
        if let Some(previous) = self.evidence_fingerprints.get(&key)
            && previous != &evidence.evidence_digest
        {
            return Err(SageMakerEndpointResultError::DuplicateFingerprint);
        }
        if let Some(receipt) = self.receipts.get(&evidence.evidence_digest) {
            receipt.validate_against(evidence, &self.registration.registration_digest)?;
            return Ok(receipt.clone());
        }
        let receipt = SageMakerDeploymentReceipt::from_evidence(
            evidence,
            self.registration.registration_digest.clone(),
        )?;
        self.evidence_fingerprints
            .insert(key, evidence.evidence_digest.clone());
        self.receipts
            .insert(evidence.evidence_digest.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn verify_deployment_result(
        &self,
        proposal: &SageMakerModelDeploymentProposal,
        evidence: &SageMakerDeploymentEvidence,
        receipt: &SageMakerDeploymentReceipt,
    ) -> Result<SageMakerModelDeploymentProposal> {
        self.ensure_active()?;
        proposal.validate_for_registration(&self.registration.registration_digest)?;
        evidence.validate()?;
        receipt.validate_against(evidence, &self.registration.registration_digest)?;
        if proposal.scope != evidence.scope
            || proposal.evidence_digest != evidence.evidence_digest
            || proposal.endpoint_digest != evidence.endpoint_digest
            || proposal.endpoint_config_digest != evidence.endpoint_config_digest
            || proposal.variant_digest != evidence.variant_digest
            || proposal.status_digest != evidence.status_digest
            || proposal.proposal_digest != proposal.computed_digest()
        {
            return Err(SageMakerEndpointResultError::ReceiptMismatch);
        }
        if !self.receipts.contains_key(&evidence.evidence_digest) {
            return Err(SageMakerEndpointResultError::ReceiptMismatch);
        }
        Ok(proposal.clone())
    }

    pub fn verify_deployment_result_report(
        &self,
        proposal: &SageMakerModelDeploymentProposal,
        evidence: &SageMakerDeploymentEvidence,
        receipt: &SageMakerDeploymentReceipt,
    ) -> VerificationReport {
        let mut failures = Vec::new();
        if proposal.registration_digest != self.registration.registration_digest {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.scope != evidence.scope || receipt.scope != evidence.scope {
            failures.push(VerificationFailure::ScopeMismatch);
        }
        if proposal.evidence_digest != evidence.evidence_digest
            || receipt.evidence_digest != evidence.evidence_digest
        {
            failures.push(VerificationFailure::EvidenceDigestMismatch);
        }
        if proposal.endpoint_digest != evidence.endpoint_digest
            || receipt.endpoint_digest != evidence.endpoint_digest
        {
            failures.push(VerificationFailure::EndpointDigestMismatch);
        }
        if proposal.endpoint_config_digest != evidence.endpoint_config_digest
            || receipt.endpoint_config_digest != evidence.endpoint_config_digest
        {
            failures.push(VerificationFailure::EndpointConfigDigestMismatch);
        }
        if proposal.variant_digest != evidence.variant_digest
            || receipt.variant_digest != evidence.variant_digest
        {
            failures.push(VerificationFailure::VariantDigestMismatch);
        }
        if proposal.status_digest != evidence.status_digest
            || receipt.status_digest != evidence.status_digest
        {
            failures.push(VerificationFailure::StatusDigestMismatch);
        }
        if receipt
            .validate_against(evidence, &self.registration.registration_digest)
            .is_err()
        {
            failures.push(VerificationFailure::ReceiptMismatch);
        }
        if proposal.proposal_digest != proposal.computed_digest() {
            failures.push(VerificationFailure::ProposalDigestMismatch);
        }
        if evidence.state == SageMakerResultState::ProviderUnknown {
            failures.push(VerificationFailure::ProviderUnknown);
        }
        VerificationReport {
            verified: failures.is_empty()
                && proposal.verification_status
                    == ResultVerificationStatus::ProviderFingerprintMatch,
            failures,
        }
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<()> {
        Err(SageMakerEndpointResultError::MutationForbidden { operation })
    }

    fn ensure_active(&self) -> Result<()> {
        if self.registration.status != RegistrationStatus::Active
            || self.state == SageMakerProviderState::Revoked
        {
            Err(SageMakerEndpointResultError::RegistrationRevoked)
        } else {
            Ok(())
        }
    }

    fn authenticate(&mut self) -> Result<SigV4CredentialMaterial> {
        let credential = self
            .credentials
            .resolve(&self.registration.secret_reference)
            .inspect_err(|_| self.state = SageMakerProviderState::BlockedEnv)?;
        if credential.is_empty() {
            self.state = SageMakerProviderState::BlockedEnv;
            return Err(SageMakerEndpointResultError::BlockedEnv);
        }
        Ok(credential)
    }

    fn mark_available(&mut self) {
        self.state = match self.transport.provenance() {
            ProviderProvenance::OfficialHttps => SageMakerProviderState::ReadOnlyAvailable,
            ProviderProvenance::Recording => SageMakerProviderState::Recording,
            ProviderProvenance::Fake => SageMakerProviderState::Fake,
            ProviderProvenance::Fixture => SageMakerProviderState::Fixture,
            ProviderProvenance::Loopback => SageMakerProviderState::Loopback,
            ProviderProvenance::BlockedEnv => SageMakerProviderState::BlockedEnv,
        };
    }

    fn validate_endpoint_record(&mut self, record: &EndpointDescriptionRecord) -> Result<()> {
        record.validate()?;
        let scope = &self.registration.scope;
        if record.aws_account_id != scope.aws_account_id
            || record.aws_region != scope.aws_region
            || record.endpoint_name != scope.endpoint_name
        {
            self.state = SageMakerProviderState::ProviderUnknown;
            return Err(SageMakerEndpointResultError::ScopeMismatch);
        }
        if record.endpoint_config_name != scope.endpoint_config_name {
            self.state = SageMakerProviderState::EndpointConfigDrift;
            return Err(SageMakerEndpointResultError::EndpointConfigDrift);
        }
        if record.endpoint_arn_digest != scope.endpoint_arn_digest {
            self.state = SageMakerProviderState::SameNameReplacement;
            return Err(SageMakerEndpointResultError::SameNameReplacement);
        }
        if let Some(previous) = &self.last_endpoint_arn_digest
            && previous != &record.endpoint_arn_digest
        {
            self.state = SageMakerProviderState::SameNameReplacement;
            return Err(SageMakerEndpointResultError::SameNameReplacement);
        }
        Ok(())
    }

    fn validate_endpoint_config_record(
        &mut self,
        record: &EndpointConfigDescriptionRecord,
    ) -> Result<()> {
        record.validate()?;
        let scope = &self.registration.scope;
        if record.aws_account_id != scope.aws_account_id
            || record.aws_region != scope.aws_region
            || record.endpoint_config_name != scope.endpoint_config_name
        {
            self.state = SageMakerProviderState::ProviderUnknown;
            return Err(SageMakerEndpointResultError::ScopeMismatch);
        }
        if record.endpoint_config_arn_digest != scope.endpoint_config_arn_digest {
            self.state = SageMakerProviderState::EndpointConfigDrift;
            return Err(SageMakerEndpointResultError::EndpointConfigDrift);
        }
        if let Some(previous) = &self.last_endpoint_config_arn_digest
            && previous != &record.endpoint_config_arn_digest
        {
            self.state = SageMakerProviderState::EndpointConfigDrift;
            return Err(SageMakerEndpointResultError::EndpointConfigDrift);
        }
        if record.config_digest != scope.config_digest {
            self.state = SageMakerProviderState::EndpointConfigDrift;
            return Err(SageMakerEndpointResultError::ConfigDigestMismatch);
        }
        Ok(())
    }

    fn validate_variant_scope(
        &mut self,
        variant: &crate::model::EndpointProductionVariantRecord,
    ) -> Result<()> {
        let scope = &self.registration.scope;
        if variant.variant_name != scope.production_variant_name {
            self.state = SageMakerProviderState::VariantStatusMismatch;
            return Err(SageMakerEndpointResultError::VariantMismatch);
        }
        if variant.model_name != scope.model_name {
            self.state = SageMakerProviderState::ProviderUnknown;
            return Err(SageMakerEndpointResultError::ModelDigestMismatch);
        }
        if variant.model_revision != scope.model_revision {
            self.state = SageMakerProviderState::ProviderUnknown;
            return Err(SageMakerEndpointResultError::ModelRevisionDrift);
        }
        if variant.image_reference != scope.image_reference {
            self.state = SageMakerProviderState::ProviderUnknown;
            return Err(SageMakerEndpointResultError::ImageDigestMismatch);
        }
        if variant.code_digest != scope.code_digest {
            self.state = SageMakerProviderState::ProviderUnknown;
            return Err(SageMakerEndpointResultError::CodeDigestMismatch);
        }
        if variant.config_digest != scope.config_digest {
            self.state = SageMakerProviderState::EndpointConfigDrift;
            return Err(SageMakerEndpointResultError::ConfigDigestMismatch);
        }
        Ok(())
    }

    fn result_state(
        endpoint: &EndpointDescriptionRecord,
        variant_status: &ProductionVariantStatus,
        traffic_matches: bool,
    ) -> SageMakerResultState {
        if endpoint.access_lost {
            return SageMakerResultState::AccessLost;
        }
        if endpoint.partial {
            return SageMakerResultState::Partial;
        }
        match &endpoint.status {
            SageMakerEndpointStatus::Creating => SageMakerResultState::Creating,
            SageMakerEndpointStatus::Updating => SageMakerResultState::Updating,
            SageMakerEndpointStatus::SystemUpdating => SageMakerResultState::SystemUpdating,
            SageMakerEndpointStatus::RollingBack => SageMakerResultState::RollingBack,
            SageMakerEndpointStatus::OutOfService => SageMakerResultState::OutOfService,
            SageMakerEndpointStatus::Deleting => SageMakerResultState::Deleting,
            SageMakerEndpointStatus::Failed => SageMakerResultState::Failed,
            SageMakerEndpointStatus::UpdateRollbackFailed => {
                SageMakerResultState::UpdateRollbackFailed
            }
            SageMakerEndpointStatus::ProviderUnknown(_) => SageMakerResultState::ProviderUnknown,
            SageMakerEndpointStatus::InService => {
                if matches!(variant_status, ProductionVariantStatus::ProviderUnknown(_)) {
                    SageMakerResultState::ProviderUnknown
                } else if variant_status.is_pending() {
                    SageMakerResultState::VariantStatusMismatch
                } else if !traffic_matches {
                    SageMakerResultState::TrafficMismatch
                } else {
                    SageMakerResultState::Ready
                }
            }
        }
    }

    fn set_state_from_endpoint(&mut self, status: &SageMakerEndpointStatus) {
        self.state = match status {
            SageMakerEndpointStatus::Creating => SageMakerProviderState::Creating,
            SageMakerEndpointStatus::InService => SageMakerProviderState::InService,
            SageMakerEndpointStatus::Updating => SageMakerProviderState::Updating,
            SageMakerEndpointStatus::SystemUpdating => SageMakerProviderState::SystemUpdating,
            SageMakerEndpointStatus::RollingBack => SageMakerProviderState::RollingBack,
            SageMakerEndpointStatus::OutOfService => SageMakerProviderState::OutOfService,
            SageMakerEndpointStatus::Deleting => SageMakerProviderState::Deleting,
            SageMakerEndpointStatus::Failed => SageMakerProviderState::Failed,
            SageMakerEndpointStatus::UpdateRollbackFailed => {
                SageMakerProviderState::UpdateRollbackFailed
            }
            SageMakerEndpointStatus::ProviderUnknown(_) => SageMakerProviderState::ProviderUnknown,
        };
    }

    fn ensure_scope(&self, scope: &SageMakerScope) -> Result<()> {
        scope.validate()?;
        if scope != &self.registration.scope {
            if scope.project_id != self.registration.scope.project_id
                || scope.mission_id != self.registration.scope.mission_id
            {
                return Err(SageMakerEndpointResultError::ScopeMismatch);
            }
            return Err(SageMakerEndpointResultError::ScopeMismatch);
        }
        Ok(())
    }

    fn map_transport_error(
        &mut self,
        error: &SageMakerTransportError,
    ) -> SageMakerEndpointResultError {
        self.state = match &error {
            SageMakerTransportError::BadRequest => SageMakerProviderState::ProviderUnknown,
            SageMakerTransportError::Unauthorized => SageMakerProviderState::Unauthorized,
            SageMakerTransportError::Forbidden => SageMakerProviderState::Forbidden,
            SageMakerTransportError::NotFound => SageMakerProviderState::NotFound,
            SageMakerTransportError::Conflict => SageMakerProviderState::Conflict,
            SageMakerTransportError::RateLimited { .. } => SageMakerProviderState::RateLimited,
            SageMakerTransportError::Timeout => SageMakerProviderState::Timeout,
            SageMakerTransportError::ServerError { .. } => SageMakerProviderState::ServerError,
            SageMakerTransportError::MalformedResponse
            | SageMakerTransportError::PartialResponse
            | SageMakerTransportError::ResponseTooLarge => SageMakerProviderState::Partial,
            SageMakerTransportError::AccessLost => SageMakerProviderState::AccessLost,
            SageMakerTransportError::BlockedEnv => SageMakerProviderState::BlockedEnv,
        };
        match error {
            SageMakerTransportError::BadRequest => SageMakerEndpointResultError::BadRequest,
            SageMakerTransportError::Unauthorized => SageMakerEndpointResultError::Unauthorized,
            SageMakerTransportError::Forbidden => SageMakerEndpointResultError::Forbidden,
            SageMakerTransportError::NotFound => SageMakerEndpointResultError::NotFound,
            SageMakerTransportError::Conflict => SageMakerEndpointResultError::Conflict,
            SageMakerTransportError::RateLimited {
                retry_after_seconds,
            } => SageMakerEndpointResultError::RateLimited {
                retry_after_seconds: *retry_after_seconds,
            },
            SageMakerTransportError::Timeout => SageMakerEndpointResultError::Timeout,
            SageMakerTransportError::ServerError { status } => {
                SageMakerEndpointResultError::ServerError { status: *status }
            }
            SageMakerTransportError::MalformedResponse => {
                SageMakerEndpointResultError::MalformedResponse
            }
            SageMakerTransportError::PartialResponse => {
                SageMakerEndpointResultError::PartialResponse
            }
            SageMakerTransportError::AccessLost => SageMakerEndpointResultError::AccessLost,
            SageMakerTransportError::ResponseTooLarge => {
                SageMakerEndpointResultError::ResponseTooLarge
            }
            SageMakerTransportError::BlockedEnv => SageMakerEndpointResultError::BlockedEnv,
        }
    }
}

fn endpoint_evidence_digest(record: &EndpointDescriptionRecord) -> crate::model::Digest {
    crate::model::canonical_digest(&(
        &record.endpoint_name,
        &record.endpoint_arn_digest,
        &record.endpoint_config_name,
        &record.status,
        &record.failure_reason,
        &record.creation_time,
        &record.last_modified_time,
    ))
}

fn provider_state_for_result(state: SageMakerResultState) -> SageMakerProviderState {
    match state {
        SageMakerResultState::Ready => SageMakerProviderState::InService,
        SageMakerResultState::Creating => SageMakerProviderState::Creating,
        SageMakerResultState::Updating => SageMakerProviderState::Updating,
        SageMakerResultState::SystemUpdating => SageMakerProviderState::SystemUpdating,
        SageMakerResultState::RollingBack => SageMakerProviderState::RollingBack,
        SageMakerResultState::OutOfService => SageMakerProviderState::OutOfService,
        SageMakerResultState::Deleting => SageMakerProviderState::Deleting,
        SageMakerResultState::Failed => SageMakerProviderState::Failed,
        SageMakerResultState::UpdateRollbackFailed => SageMakerProviderState::UpdateRollbackFailed,
        SageMakerResultState::VariantUpdating => SageMakerProviderState::VariantUpdating,
        SageMakerResultState::VariantStatusMismatch => {
            SageMakerProviderState::VariantStatusMismatch
        }
        SageMakerResultState::TrafficMismatch => SageMakerProviderState::TrafficMismatch,
        SageMakerResultState::EndpointConfigDrift => SageMakerProviderState::EndpointConfigDrift,
        SageMakerResultState::SameNameReplacement => SageMakerProviderState::SameNameReplacement,
        SageMakerResultState::Partial => SageMakerProviderState::Partial,
        SageMakerResultState::AccessLost => SageMakerProviderState::AccessLost,
        SageMakerResultState::ProviderUnknown => SageMakerProviderState::ProviderUnknown,
    }
}

impl<T> SageMakerProvider<T, BlockedEnvCredentialResolver>
where
    T: SageMakerTransport,
{
    pub fn blocked_env(registration: SageMakerRegistration, transport: T) -> Result<Self> {
        Self::new(registration, transport, BlockedEnvCredentialResolver)
    }
}

pub type SageMakerReadOnlyProvider<T, R> = SageMakerProvider<T, R>;
