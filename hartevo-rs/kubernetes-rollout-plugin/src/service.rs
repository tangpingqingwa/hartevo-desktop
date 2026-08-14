use crate::model::{
    ClusterDescription, DeploymentSnapshot, EvidenceProvenance, ImageReference,
    KubernetesRolloutScope, ModelError, RolloutEvidence, RolloutReadRequest, SecretReference,
};
use crate::provider::{
    DryRunEvidence, DryRunProposal, KubernetesApiError, KubernetesProviderError,
    KubernetesRolloutProvider, ProviderDryRunResponse, ProviderReadResponse,
};
use crate::{
    CONTRACT_VERSION, KUBERNETES_API_REVISION, LAYER, PLUGIN_VERSION, SERVICE_ID, contract_digest,
    digest_json, valid_identifier,
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use thiserror::Error;

pub const MAX_RETRY_ATTEMPTS: u8 = 5;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubernetesRolloutRegistration {
    pub plugin_version: String,
    pub contract_digest: String,
    pub adapter_revision: String,
    pub kubernetes_api_revision: String,
    pub rbac_capability_snapshot_digest: String,
    pub scope_digest: String,
    pub registration_revision: u64,
    pub state: RegistrationState,
    pub revocation_reason_digest: Option<String>,
    pub registration_digest: String,
}

impl KubernetesRolloutRegistration {
    pub fn new(
        scope: &KubernetesRolloutScope,
        plugin_version: impl Into<String>,
        adapter_revision: impl Into<String>,
        registration_revision: u64,
    ) -> Result<Self, KubernetesRolloutError> {
        scope.validate()?;
        let registration = Self {
            plugin_version: plugin_version.into(),
            contract_digest: contract_digest(),
            adapter_revision: adapter_revision.into(),
            kubernetes_api_revision: KUBERNETES_API_REVISION.into(),
            rbac_capability_snapshot_digest: scope.rbac.digest().into(),
            scope_digest: scope.digest(),
            registration_revision,
            state: RegistrationState::Active,
            revocation_reason_digest: None,
            registration_digest: String::new(),
        };
        registration.validate_without_digest()?;
        let mut registration = registration;
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    pub fn validate(&self, scope: &KubernetesRolloutScope) -> Result<(), KubernetesRolloutError> {
        scope.validate()?;
        self.validate_without_digest()?;
        if self.contract_digest != contract_digest()
            || self.scope_digest != scope.digest()
            || self.rbac_capability_snapshot_digest != scope.rbac.digest()
            || self.registration_digest != self.compute_digest()
        {
            return Err(KubernetesRolloutError::RegistrationDrift);
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn revoke(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<RevocationReceipt, KubernetesRolloutError> {
        if !self.is_active() {
            return Err(KubernetesRolloutError::RegistrationRevoked);
        }
        let reason = reason.as_ref();
        if !valid_identifier(reason, 256) {
            return Err(KubernetesRolloutError::InvalidRegistration);
        }
        let previous_digest = self.registration_digest.clone();
        self.state = RegistrationState::Revoked;
        self.revocation_reason_digest = Some(crate::digest_text(reason));
        self.registration_digest = self.compute_digest();
        Ok(RevocationReceipt {
            registration_digest_before: previous_digest,
            registration_digest_after: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revocation_reason_digest: self.revocation_reason_digest.clone().unwrap_or_default(),
            reversible: true,
        })
    }

    /// Reissues an active registration with a new revision.  Revocation never
    /// silently reactivates the old digest or mutates a global registry.
    pub fn reissue(
        &self,
        scope: &KubernetesRolloutScope,
        registration_revision: u64,
    ) -> Result<Self, KubernetesRolloutError> {
        if self.scope_digest != scope.digest() || registration_revision == 0 {
            return Err(KubernetesRolloutError::RegistrationDrift);
        }
        Self::new(
            scope,
            self.plugin_version.clone(),
            self.adapter_revision.clone(),
            registration_revision,
        )
    }

    fn validate_without_digest(&self) -> Result<(), KubernetesRolloutError> {
        if !valid_identifier(&self.plugin_version, 64)
            || !valid_identifier(&self.adapter_revision, 128)
            || self.kubernetes_api_revision != KUBERNETES_API_REVISION
            || !crate::valid_sha256_digest(&self.contract_digest)
            || !crate::valid_sha256_digest(&self.rbac_capability_snapshot_digest)
            || !crate::valid_sha256_digest(&self.scope_digest)
            || self.registration_revision == 0
            || self
                .revocation_reason_digest
                .as_ref()
                .is_some_and(|digest| !crate::valid_sha256_digest(digest))
        {
            return Err(KubernetesRolloutError::InvalidRegistration);
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        #[derive(Serialize)]
        struct Material<'a> {
            plugin_version: &'a str,
            contract_digest: &'a str,
            adapter_revision: &'a str,
            kubernetes_api_revision: &'a str,
            rbac_capability_snapshot_digest: &'a str,
            scope_digest: &'a str,
            registration_revision: u64,
            state: RegistrationState,
            revocation_reason_digest: &'a Option<String>,
        }
        digest_json(&Material {
            plugin_version: &self.plugin_version,
            contract_digest: &self.contract_digest,
            adapter_revision: &self.adapter_revision,
            kubernetes_api_revision: &self.kubernetes_api_revision,
            rbac_capability_snapshot_digest: &self.rbac_capability_snapshot_digest,
            scope_digest: &self.scope_digest,
            registration_revision: self.registration_revision,
            state: self.state,
            revocation_reason_digest: &self.revocation_reason_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    pub registration_digest_before: String,
    pub registration_digest_after: String,
    pub scope_digest: String,
    pub revocation_reason_digest: String,
    pub reversible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubernetesRolloutServiceDefinition {
    pub service_id: String,
    pub contract_version: String,
    pub version: String,
    pub contract_digest: String,
    pub access: String,
    pub operations: Vec<String>,
    pub writes_allowed: bool,
    pub layer: u8,
}

impl KubernetesRolloutServiceDefinition {
    pub fn validate(&self) -> Result<(), KubernetesRolloutError> {
        if self.service_id != SERVICE_ID
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.access != "read_only"
            || self.layer != LAYER
            || self.writes_allowed
            || self.operations
                != [
                    "describe_rollout",
                    "read_rollout_evidence",
                    "compile_apply_proposal",
                    "compile_dry_run_proposal",
                    "record_rollout_receipt",
                    "verify_rollout_result",
                ]
        {
            return Err(KubernetesRolloutError::ServiceDefinitionDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubernetesRolloutProviderDefinition {
    pub provider_id: String,
    pub kubernetes_api_revision: String,
    pub transport: String,
    pub native_connected_claim: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionKubernetesRolloutConsumerDefinition {
    pub consumer_id: String,
    pub authority: String,
    pub outcome_adoption: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalOperation {
    ServerSideApply,
    ImageUpdate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalExecution {
    NotExecuted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageUpdateProposal {
    pub proposal_version: String,
    pub operation: ProposalOperation,
    pub scope_digest: String,
    pub registration_digest: String,
    pub object: crate::DeploymentIdentity,
    pub expected_resource_version: String,
    pub expected_generation: u64,
    pub field_manager: String,
    pub current_image_digests: BTreeMap<String, String>,
    pub desired_image_digests: BTreeMap<String, String>,
    pub execution: ProposalExecution,
    pub dry_run: bool,
    pub connected: bool,
    pub native: bool,
    pub idempotency_fingerprint: String,
    pub proposal_digest: String,
}

impl ImageUpdateProposal {
    pub fn validate(&self) -> Result<(), KubernetesRolloutError> {
        if self.proposal_version != "kubernetes-rollout-proposal/v1"
            || !crate::valid_sha256_digest(&self.scope_digest)
            || !crate::valid_sha256_digest(&self.registration_digest)
            || self.object.validate().is_err()
            || !valid_identifier(&self.expected_resource_version, 128)
            || self.expected_generation == 0
            || !valid_identifier(&self.field_manager, 128)
            || self.current_image_digests.is_empty()
            || self.desired_image_digests.is_empty()
            || !crate::valid_digest_map(&self.current_image_digests)
            || !crate::valid_digest_map(&self.desired_image_digests)
            || self
                .current_image_digests
                .keys()
                .ne(self.desired_image_digests.keys())
            || self.execution != ProposalExecution::NotExecuted
            || self.dry_run
            || self.connected
            || self.native
            || !crate::valid_sha256_digest(&self.idempotency_fingerprint)
            || self.proposal_digest != self.compute_digest()
        {
            return Err(KubernetesRolloutError::TamperedProposal);
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        #[derive(Serialize)]
        struct Material<'a> {
            proposal_version: &'a str,
            operation: ProposalOperation,
            scope_digest: &'a str,
            registration_digest: &'a str,
            object: &'a crate::DeploymentIdentity,
            expected_resource_version: &'a str,
            expected_generation: u64,
            field_manager: &'a str,
            current_image_digests: &'a BTreeMap<String, String>,
            desired_image_digests: &'a BTreeMap<String, String>,
            execution: ProposalExecution,
            dry_run: bool,
            idempotency_fingerprint: &'a str,
        }
        digest_json(&Material {
            proposal_version: &self.proposal_version,
            operation: self.operation,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            object: &self.object,
            expected_resource_version: &self.expected_resource_version,
            expected_generation: self.expected_generation,
            field_manager: &self.field_manager,
            current_image_digests: &self.current_image_digests,
            desired_image_digests: &self.desired_image_digests,
            execution: self.execution,
            dry_run: self.dry_run,
            idempotency_fingerprint: &self.idempotency_fingerprint,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    ReadObservation,
    ProposalRecording,
    DryRunAdmission,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubernetesRolloutReceipt {
    pub receipt_version: String,
    pub kind: ReceiptKind,
    pub scope_digest: String,
    pub registration_digest: String,
    pub object_uid: Option<String>,
    pub resource_version: Option<String>,
    pub requested_generation: Option<u64>,
    pub generation: Option<u64>,
    pub observed_generation: Option<u64>,
    pub spec_fingerprint: Option<String>,
    pub template_fingerprint: Option<String>,
    pub exact_image_digests: BTreeMap<String, String>,
    pub conditions_fingerprint: Option<String>,
    pub evidence_digest: Option<String>,
    pub proposal_digest: Option<String>,
    pub dry_run_is_not_write_receipt: bool,
    pub write_receipt: bool,
    pub provenance: EvidenceProvenance,
    pub connected: bool,
    pub native: bool,
    pub idempotency_fingerprint: String,
    pub receipt_digest: String,
}

impl KubernetesRolloutReceipt {
    pub fn validate(&self) -> Result<(), KubernetesRolloutError> {
        if self.receipt_version != "kubernetes-rollout-receipt/v1"
            || !crate::valid_sha256_digest(&self.scope_digest)
            || !crate::valid_sha256_digest(&self.registration_digest)
            || !crate::valid_digest_map(&self.exact_image_digests)
            || self
                .requested_generation
                .is_some_and(|generation| generation == 0)
            || !self.dry_run_is_not_write_receipt
            || self.write_receipt
            || self.connected
            || self.native
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || !crate::valid_sha256_digest(&self.idempotency_fingerprint)
            || self.receipt_digest != self.compute_digest()
        {
            return Err(KubernetesRolloutError::TamperedReceipt);
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        #[derive(Serialize)]
        struct Material<'a> {
            receipt_version: &'a str,
            kind: ReceiptKind,
            scope_digest: &'a str,
            registration_digest: &'a str,
            object_uid: &'a Option<String>,
            resource_version: &'a Option<String>,
            requested_generation: Option<u64>,
            generation: Option<u64>,
            observed_generation: Option<u64>,
            spec_fingerprint: &'a Option<String>,
            template_fingerprint: &'a Option<String>,
            exact_image_digests: &'a BTreeMap<String, String>,
            conditions_fingerprint: &'a Option<String>,
            evidence_digest: &'a Option<String>,
            proposal_digest: &'a Option<String>,
            dry_run_is_not_write_receipt: bool,
            write_receipt: bool,
            provenance: EvidenceProvenance,
            idempotency_fingerprint: &'a str,
        }
        digest_json(&Material {
            receipt_version: &self.receipt_version,
            kind: self.kind,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            object_uid: &self.object_uid,
            resource_version: &self.resource_version,
            requested_generation: self.requested_generation,
            generation: self.generation,
            observed_generation: self.observed_generation,
            spec_fingerprint: &self.spec_fingerprint,
            template_fingerprint: &self.template_fingerprint,
            exact_image_digests: &self.exact_image_digests,
            conditions_fingerprint: &self.conditions_fingerprint,
            evidence_digest: &self.evidence_digest,
            proposal_digest: &self.proposal_digest,
            dry_run_is_not_write_receipt: self.dry_run_is_not_write_receipt,
            write_receipt: self.write_receipt,
            provenance: self.provenance,
            idempotency_fingerprint: &self.idempotency_fingerprint,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RolloutVerification {
    pub verified: bool,
    pub complete: bool,
    pub scope_digest: String,
    pub evidence_digest: String,
    pub receipt_digest: String,
    pub below_kernel_authority: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDisposition {
    Retryable,
    Terminal,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum KubernetesRolloutError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Provider(#[from] KubernetesProviderError),
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration or protected scope drifted")]
    RegistrationDrift,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("service definition drifted")]
    ServiceDefinitionDrift,
    #[error("provider definition drifted")]
    ProviderDefinitionDrift,
    #[error("consumer definition drifted")]
    ConsumerDefinitionDrift,
    #[error("retry budget exhausted after the final Kubernetes API failure: {0}")]
    RetryExhausted(KubernetesApiError),
    #[error("resourceVersion repeated instead of advancing")]
    RepeatedWatchEvent,
    #[error("resourceVersion regressed")]
    ResourceVersionRegression,
    #[error("proposal is not bound to this registration")]
    ProposalBindingMismatch,
    #[error("proposal or receipt was tampered with")]
    TamperedProposal,
    #[error("receipt was tampered with")]
    TamperedReceipt,
    #[error("result verification failed")]
    VerificationFailed,
    #[error("invalid registration operation")]
    InvalidOperation,
}

impl KubernetesRolloutError {
    pub fn retry_disposition(&self) -> RetryDisposition {
        match self {
            Self::Provider(error) if error.api_error().retryable() => RetryDisposition::Retryable,
            _ => RetryDisposition::Terminal,
        }
    }
}

pub struct KubernetesRolloutService<P = crate::KubernetesApiRolloutProvider> {
    provider: P,
    scope: KubernetesRolloutScope,
    auth_reference: SecretReference,
    registration: KubernetesRolloutRegistration,
    last_resource_version: Option<String>,
}

impl<P> fmt::Debug for KubernetesRolloutService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesRolloutService")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("auth_reference", &self.auth_reference)
            .field("last_resource_version", &self.last_resource_version)
            .finish_non_exhaustive()
    }
}

impl<P: KubernetesRolloutProvider> KubernetesRolloutService<P> {
    pub fn new(
        provider: P,
        scope: KubernetesRolloutScope,
        auth_reference: SecretReference,
        registration: KubernetesRolloutRegistration,
    ) -> Result<Self, KubernetesRolloutError> {
        let service = Self {
            provider,
            scope,
            auth_reference,
            registration,
            last_resource_version: None,
        };
        service.ensure_bound()?;
        Ok(service)
    }

    pub fn definition() -> KubernetesRolloutServiceDefinition {
        KubernetesRolloutServiceDefinition {
            service_id: SERVICE_ID.into(),
            contract_version: CONTRACT_VERSION.into(),
            version: PLUGIN_VERSION.into(),
            contract_digest: contract_digest(),
            access: "read_only".into(),
            operations: vec![
                "describe_rollout".into(),
                "read_rollout_evidence".into(),
                "compile_apply_proposal".into(),
                "compile_dry_run_proposal".into(),
                "record_rollout_receipt".into(),
                "verify_rollout_result".into(),
            ],
            writes_allowed: false,
            layer: LAYER,
        }
    }

    pub fn scope(&self) -> &KubernetesRolloutScope {
        &self.scope
    }

    pub fn registration(&self) -> &KubernetesRolloutRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn describe_rollout(&mut self) -> Result<ClusterDescription, KubernetesRolloutError> {
        self.ensure_bound()?;
        let description = self.provider.describe_rollout(
            &self.scope,
            &self.registration,
            &self.auth_reference,
        )?;
        description.validate_against(&self.scope)?;
        Ok(description)
    }

    pub fn read_rollout_evidence(
        &mut self,
        request: &RolloutReadRequest,
    ) -> Result<RolloutEvidence, KubernetesRolloutError> {
        self.ensure_bound()?;
        request.validate_against(&self.scope)?;
        let mut effective_request = request.clone();
        if effective_request.previous_resource_version.is_none() {
            effective_request.previous_resource_version = self.last_resource_version.clone();
        }

        let mut attempt = 0;
        loop {
            attempt += 1;
            match self.provider.read_rollout_evidence(
                &self.scope,
                &self.registration,
                &self.auth_reference,
                &effective_request,
            ) {
                Ok(ProviderReadResponse {
                    snapshot,
                    provenance,
                }) => {
                    Self::check_resource_version(&effective_request, &snapshot)?;
                    let evidence = RolloutEvidence::new(
                        &self.scope,
                        snapshot,
                        &effective_request,
                        provenance,
                    )?;
                    self.last_resource_version = Some(evidence.snapshot.resource_version.clone());
                    return Ok(evidence);
                }
                Err(error) if error.is_retryable() && attempt < effective_request.max_attempts => {}
                Err(error) if error.is_retryable() => {
                    return Err(KubernetesRolloutError::RetryExhausted(error.api_error()));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub fn compile_apply_proposal(
        &self,
        snapshot: &DeploymentSnapshot,
        desired_images: &BTreeMap<String, ImageReference>,
    ) -> Result<ImageUpdateProposal, KubernetesRolloutError> {
        self.ensure_bound()?;
        snapshot.validate()?;
        if snapshot.identity != self.scope.deployment {
            return Err(ModelError::ObjectIdentityMismatch.into());
        }
        if desired_images.is_empty()
            || desired_images.len() != self.scope.allowed_images.len()
            || desired_images
                .keys()
                .any(|name| !self.scope.allowed_images.contains_key(name))
            || desired_images
                .iter()
                .any(|(name, image)| self.scope.allowed_images.get(name) != Some(image))
        {
            return Err(KubernetesRolloutError::InvalidOperation);
        }
        let desired_image_digests = desired_images
            .iter()
            .map(|(name, image)| {
                if image.validate().is_err() {
                    return Err(KubernetesRolloutError::Model(
                        ModelError::ImageMustUseExactDigest,
                    ));
                }
                Ok((name.clone(), image.digest.clone()))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        if desired_image_digests
            .iter()
            .any(|(name, digest)| self.scope.allowed_images[name].digest != *digest)
        {
            return Err(KubernetesRolloutError::InvalidOperation);
        }
        let current_image_digests = snapshot.image_digests.clone();
        if current_image_digests == desired_image_digests {
            return Err(KubernetesRolloutError::InvalidOperation);
        }
        let mut proposal = ImageUpdateProposal {
            proposal_version: "kubernetes-rollout-proposal/v1".into(),
            operation: ProposalOperation::ImageUpdate,
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            object: snapshot.identity.clone(),
            expected_resource_version: snapshot.resource_version.clone(),
            expected_generation: snapshot.generation,
            field_manager: self.scope.field_manager.clone(),
            current_image_digests,
            desired_image_digests,
            execution: ProposalExecution::NotExecuted,
            dry_run: false,
            connected: false,
            native: false,
            idempotency_fingerprint: String::new(),
            proposal_digest: String::new(),
        };
        proposal.idempotency_fingerprint = digest_json(&(
            &proposal.scope_digest,
            &proposal.object,
            &proposal.expected_resource_version,
            &proposal.expected_generation,
            &proposal.field_manager,
            &proposal.current_image_digests,
            &proposal.desired_image_digests,
        ));
        proposal.proposal_digest = proposal.compute_digest();
        Ok(proposal)
    }

    pub fn compile_dry_run_proposal(
        &self,
        proposal: &ImageUpdateProposal,
    ) -> Result<DryRunProposal, KubernetesRolloutError> {
        self.ensure_bound()?;
        proposal.validate()?;
        if proposal.scope_digest != self.scope.digest()
            || proposal.registration_digest != self.registration.registration_digest
        {
            return Err(KubernetesRolloutError::ProposalBindingMismatch);
        }
        Ok(DryRunProposal::from_apply_proposal(
            proposal,
            self.scope.api_server.clone(),
            self.scope.field_manager.clone(),
        ))
    }

    pub fn dry_run(
        &mut self,
        proposal: &DryRunProposal,
    ) -> Result<DryRunEvidence, KubernetesRolloutError> {
        self.ensure_bound()?;
        proposal.validate()?;
        if proposal.scope_digest != self.scope.digest()
            || proposal.registration_digest != self.registration.registration_digest
        {
            return Err(KubernetesRolloutError::ProposalBindingMismatch);
        }
        let ProviderDryRunResponse { evidence } = self.provider.dry_run(
            &self.scope,
            &self.registration,
            &self.auth_reference,
            proposal,
        )?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn record_rollout_receipt(
        &self,
        evidence: &RolloutEvidence,
    ) -> Result<KubernetesRolloutReceipt, KubernetesRolloutError> {
        self.ensure_bound()?;
        evidence.validate_against_scope(&self.scope)?;
        if evidence.scope_digest != self.scope.digest() {
            return Err(KubernetesRolloutError::VerificationFailed);
        }
        Ok(KubernetesRolloutReceipt::from_evidence(
            &self.scope,
            &self.registration,
            evidence,
        ))
    }

    pub fn record_proposal_receipt(
        &self,
        proposal: &ImageUpdateProposal,
    ) -> Result<KubernetesRolloutReceipt, KubernetesRolloutError> {
        self.ensure_bound()?;
        proposal.validate()?;
        if proposal.scope_digest != self.scope.digest()
            || proposal.registration_digest != self.registration.registration_digest
        {
            return Err(KubernetesRolloutError::ProposalBindingMismatch);
        }
        Ok(KubernetesRolloutReceipt::from_proposal(
            &self.scope,
            &self.registration,
            proposal,
        ))
    }

    pub fn record_dry_run_receipt(
        &self,
        evidence: &DryRunEvidence,
    ) -> Result<KubernetesRolloutReceipt, KubernetesRolloutError> {
        self.ensure_bound()?;
        evidence.validate()?;
        if evidence.scope_digest != self.scope.digest()
            || evidence.registration_digest != self.registration.registration_digest
        {
            return Err(KubernetesRolloutError::ProposalBindingMismatch);
        }
        Ok(KubernetesRolloutReceipt::from_dry_run(
            &self.scope,
            &self.registration,
            evidence,
        ))
    }

    pub fn verify_rollout_result(
        &self,
        receipt: &KubernetesRolloutReceipt,
        evidence: &RolloutEvidence,
    ) -> Result<RolloutVerification, KubernetesRolloutError> {
        self.ensure_bound()?;
        receipt.validate()?;
        evidence.validate_against_scope(&self.scope)?;
        if receipt.kind != ReceiptKind::ReadObservation
            || receipt.scope_digest != self.scope.digest()
            || receipt.registration_digest != self.registration.registration_digest
            || receipt.evidence_digest.as_deref() != Some(evidence.evidence_digest.as_str())
            || receipt.object_uid.as_deref() != Some(evidence.snapshot.identity.uid.as_str())
            || receipt.resource_version.as_deref()
                != Some(evidence.snapshot.resource_version.as_str())
            || receipt.requested_generation != Some(evidence.requested_generation)
            || receipt.generation != Some(evidence.snapshot.generation)
            || receipt.observed_generation != Some(evidence.snapshot.observed_generation)
            || receipt.spec_fingerprint.as_deref()
                != Some(evidence.snapshot.spec_fingerprint.as_str())
            || receipt.template_fingerprint.as_deref()
                != Some(evidence.snapshot.template_fingerprint.as_str())
            || receipt.exact_image_digests != evidence.snapshot.image_digests
            || receipt.conditions_fingerprint.as_deref()
                != Some(evidence.snapshot.status_fingerprint().as_str())
            || receipt.provenance != evidence.provenance
        {
            return Err(KubernetesRolloutError::VerificationFailed);
        }
        Ok(RolloutVerification {
            verified: true,
            complete: evidence.observation.complete,
            scope_digest: self.scope.digest(),
            evidence_digest: evidence.evidence_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            below_kernel_authority: true,
        })
    }

    pub fn revoke_registration(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<RevocationReceipt, KubernetesRolloutError> {
        self.registration.revoke(reason)
    }

    fn ensure_bound(&self) -> Result<(), KubernetesRolloutError> {
        self.scope.validate()?;
        self.auth_reference
            .validate_for_scope(&self.scope.digest())?;
        self.registration.validate(&self.scope)?;
        if !self.registration.is_active() {
            return Err(KubernetesRolloutError::RegistrationRevoked);
        }
        Ok(())
    }

    fn check_resource_version(
        request: &RolloutReadRequest,
        snapshot: &DeploymentSnapshot,
    ) -> Result<(), KubernetesRolloutError> {
        if let Some(previous) = request.previous_resource_version.as_deref() {
            match compare_resource_versions(previous, &snapshot.resource_version) {
                Ordering::Equal => return Err(KubernetesRolloutError::RepeatedWatchEvent),
                Ordering::Greater => return Err(KubernetesRolloutError::ResourceVersionRegression),
                Ordering::Less => {}
            }
        }
        Ok(())
    }
}

fn compare_resource_versions(previous: &str, current: &str) -> Ordering {
    match (previous.parse::<u128>(), current.parse::<u128>()) {
        (Ok(previous), Ok(current)) => previous.cmp(&current),
        _ => previous.cmp(current),
    }
}

impl KubernetesRolloutReceipt {
    fn from_evidence(
        scope: &KubernetesRolloutScope,
        registration: &KubernetesRolloutRegistration,
        evidence: &RolloutEvidence,
    ) -> Self {
        let mut receipt = Self {
            receipt_version: "kubernetes-rollout-receipt/v1".into(),
            kind: ReceiptKind::ReadObservation,
            scope_digest: scope.digest(),
            registration_digest: registration.registration_digest.clone(),
            object_uid: Some(evidence.snapshot.identity.uid.clone()),
            resource_version: Some(evidence.snapshot.resource_version.clone()),
            requested_generation: Some(evidence.requested_generation),
            generation: Some(evidence.snapshot.generation),
            observed_generation: Some(evidence.snapshot.observed_generation),
            spec_fingerprint: Some(evidence.snapshot.spec_fingerprint.clone()),
            template_fingerprint: Some(evidence.snapshot.template_fingerprint.clone()),
            exact_image_digests: evidence.snapshot.image_digests.clone(),
            conditions_fingerprint: Some(evidence.snapshot.status_fingerprint()),
            evidence_digest: Some(evidence.evidence_digest.clone()),
            proposal_digest: None,
            dry_run_is_not_write_receipt: true,
            write_receipt: false,
            provenance: evidence.provenance,
            connected: false,
            native: false,
            idempotency_fingerprint: String::new(),
            receipt_digest: String::new(),
        };
        receipt.idempotency_fingerprint = digest_json(&(
            &receipt.scope_digest,
            &receipt.registration_digest,
            &receipt.object_uid,
            &receipt.resource_version,
            &receipt.generation,
            &receipt.observed_generation,
            &receipt.exact_image_digests,
        ));
        receipt.receipt_digest = receipt.compute_digest();
        receipt
    }

    fn from_proposal(
        scope: &KubernetesRolloutScope,
        registration: &KubernetesRolloutRegistration,
        proposal: &ImageUpdateProposal,
    ) -> Self {
        let mut receipt = Self {
            receipt_version: "kubernetes-rollout-receipt/v1".into(),
            kind: ReceiptKind::ProposalRecording,
            scope_digest: scope.digest(),
            registration_digest: registration.registration_digest.clone(),
            object_uid: Some(proposal.object.uid.clone()),
            resource_version: Some(proposal.expected_resource_version.clone()),
            requested_generation: Some(proposal.expected_generation),
            generation: Some(proposal.expected_generation),
            observed_generation: None,
            spec_fingerprint: None,
            template_fingerprint: None,
            exact_image_digests: proposal.desired_image_digests.clone(),
            conditions_fingerprint: None,
            evidence_digest: None,
            proposal_digest: Some(proposal.proposal_digest.clone()),
            dry_run_is_not_write_receipt: true,
            write_receipt: false,
            provenance: EvidenceProvenance::Recording,
            connected: false,
            native: false,
            idempotency_fingerprint: proposal.idempotency_fingerprint.clone(),
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.compute_digest();
        receipt
    }

    fn from_dry_run(
        scope: &KubernetesRolloutScope,
        registration: &KubernetesRolloutRegistration,
        evidence: &DryRunEvidence,
    ) -> Self {
        let mut receipt = Self {
            receipt_version: "kubernetes-rollout-receipt/v1".into(),
            kind: ReceiptKind::DryRunAdmission,
            scope_digest: scope.digest(),
            registration_digest: registration.registration_digest.clone(),
            object_uid: Some(evidence.object.uid.clone()),
            resource_version: Some(evidence.expected_resource_version.clone()),
            requested_generation: Some(evidence.expected_generation),
            generation: Some(evidence.expected_generation),
            observed_generation: None,
            spec_fingerprint: None,
            template_fingerprint: None,
            exact_image_digests: evidence.desired_image_digests.clone(),
            conditions_fingerprint: None,
            evidence_digest: Some(evidence.evidence_digest.clone()),
            proposal_digest: Some(evidence.proposal_digest.clone()),
            dry_run_is_not_write_receipt: true,
            write_receipt: false,
            provenance: evidence.provenance,
            connected: false,
            native: false,
            idempotency_fingerprint: evidence.idempotency_fingerprint.clone(),
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.compute_digest();
        receipt
    }
}
