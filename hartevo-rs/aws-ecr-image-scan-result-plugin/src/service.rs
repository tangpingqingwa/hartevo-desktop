//! Read, proposal, observation, verification, and reversible registration
//! seams for bounded ECR image-scan evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    Digest, EcrImageDescriptor, EcrImageScanEvidence, EcrImageScanScope, EcrOperation,
    EvidenceClassification, EvidenceDigests, InspectorFindingRevision, MAX_FINDINGS, MAX_PAGES,
    ModelError, PAGE_SIZE, PartialReason, PermissionFence, ProviderErrorEvidence, RedactedFinding,
    RedactionSummary, ScanLifecycle, ScanProjection, ScanRevision, Severity, SeverityCount,
    serialized_digest,
};
use crate::provider::{
    DescribeImageScanFindingsRequest, DescribeImagesRequest, EcrProvider, EcrProviderError,
    EcrTransport,
};

pub const ECR_IMAGE_SCAN_SERVICE_ID: &str = "hartevo.aws.ecr.image-scan.result";
pub const ECR_IMAGE_SCAN_SERVICE_NAME: &str = "EcrImageScanResultService";
pub const MISSION_ECR_IMAGE_SCAN_CONSUMER_ID: &str = "mission.aws.ecr.image-scan.result";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("ECR registration binding does not match")]
    BindingMismatch,
    #[error("ECR registration digest is invalid")]
    InvalidDigest,
    #[error("ECR registration is already revoked")]
    AlreadyRevoked,
    #[error("ECR registration is not revoked")]
    NotRevoked,
    #[error("ECR registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcrImageScanRegistration {
    pub plugin_version: String,
    pub version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registry_digest: Digest,
    pub account_digest: Digest,
    pub region_digest: Digest,
    pub repository_digest: Digest,
    pub image_digest: Digest,
    pub scan_type_digest: Digest,
    pub scan_revision_digest: Digest,
    pub finding_revision_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub revision: u64,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

pub type EcrRegistration = EcrImageScanRegistration;

impl EcrImageScanRegistration {
    pub fn new<T: EcrTransport>(
        scope: &EcrImageScanScope,
        secret: &crate::SecretReference,
        provider: &EcrProvider<T>,
    ) -> Result<Self, RegistrationError> {
        if secret.scope_digest() != scope.scope_digest() || secret.is_revoked() {
            return Err(RegistrationError::BindingMismatch);
        }
        let mut registration = Self {
            plugin_version: crate::ECR_IMAGE_SCAN_PLUGIN_VERSION.to_owned(),
            version_digest: crate::version_digest(),
            contract_version: crate::ECR_IMAGE_SCAN_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_digest: provider.provider_digest(),
            permission_digest: scope.permission().digest().clone(),
            scope_digest: scope.scope_digest().clone(),
            secret_reference_digest: secret.digest(),
            registry_digest: scope.registry_digest(),
            account_digest: scope.account_id().digest(),
            region_digest: scope.region().digest(),
            repository_digest: scope.repository_digest(),
            image_digest: scope.image_digest().digest(),
            scan_type_digest: scope.scan_type().digest(),
            scan_revision_digest: scope.scan_revision().digest(),
            finding_revision_digest: scope.inspector_finding_revision().digest(),
            project_digest: scope.project().digest(),
            mission_digest: scope.mission().digest(),
            work_product_digest: scope.work_product().digest(),
            revision: 1,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        matches!(self.state, RegistrationState::Revoked)
    }

    #[must_use]
    pub fn recomputed_digest(&self) -> Digest {
        serialized_digest(&RegistrationDigestMaterial {
            plugin_version: &self.plugin_version,
            version_digest: &self.version_digest,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_digest: &self.provider_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registry_digest: &self.registry_digest,
            account_digest: &self.account_digest,
            region_digest: &self.region_digest,
            repository_digest: &self.repository_digest,
            image_digest: &self.image_digest,
            scan_type_digest: &self.scan_type_digest,
            scan_revision_digest: &self.scan_revision_digest,
            finding_revision_digest: &self.finding_revision_digest,
            project_digest: &self.project_digest,
            mission_digest: &self.mission_digest,
            work_product_digest: &self.work_product_digest,
            revision: self.revision,
            state: self.state,
        })
    }

    pub fn validate<T: EcrTransport>(
        &self,
        scope: &EcrImageScanScope,
        secret: &crate::SecretReference,
        provider: &EcrProvider<T>,
    ) -> Result<(), RegistrationError> {
        if !self.is_active()
            || self.plugin_version != crate::ECR_IMAGE_SCAN_PLUGIN_VERSION
            || self.version_digest != crate::version_digest()
            || self.contract_version != crate::ECR_IMAGE_SCAN_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_digest != provider.provider_digest()
            || self.permission_digest != *scope.permission().digest()
            || self.scope_digest != *scope.scope_digest()
            || self.secret_reference_digest != secret.digest()
            || secret.is_revoked()
            || secret.scope_digest() != scope.scope_digest()
            || self.registry_digest != scope.registry_digest()
            || self.account_digest != scope.account_id().digest()
            || self.region_digest != scope.region().digest()
            || self.repository_digest != scope.repository_digest()
            || self.image_digest != scope.image_digest().digest()
            || self.scan_type_digest != scope.scan_type().digest()
            || self.scan_revision_digest != scope.scan_revision().digest()
            || self.finding_revision_digest != scope.inspector_finding_revision().digest()
            || self.project_digest != scope.project().digest()
            || self.mission_digest != scope.mission().digest()
            || self.work_product_digest != scope.work_product().digest()
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(RegistrationError::BindingMismatch);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), RegistrationError> {
        if self.is_revoked() {
            return Err(RegistrationError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(RegistrationError::RevisionOverflow)?;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), RegistrationError> {
        if self.is_active() {
            return Err(RegistrationError::NotRevoked);
        }
        self.state = RegistrationState::Active;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(RegistrationError::RevisionOverflow)?;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }

    pub fn reverse(&mut self) -> Result<(), RegistrationError> {
        if self.is_active() {
            self.revoke()
        } else {
            self.restore()
        }
    }
}

#[derive(Serialize)]
struct RegistrationDigestMaterial<'a> {
    plugin_version: &'a str,
    version_digest: &'a Digest,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registry_digest: &'a Digest,
    account_digest: &'a Digest,
    region_digest: &'a Digest,
    repository_digest: &'a Digest,
    image_digest: &'a Digest,
    scan_type_digest: &'a Digest,
    scan_revision_digest: &'a Digest,
    finding_revision_digest: &'a Digest,
    project_digest: &'a Digest,
    mission_digest: &'a Digest,
    work_product_digest: &'a Digest,
    revision: u64,
    state: RegistrationState,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EcrImageScanServiceError {
    #[error("ECR registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("ECR SigV4 SecretReference is revoked")]
    SecretRevoked,
    #[error("ECR permission fence is invalid")]
    PermissionMismatch,
    #[error("ECR image-scan scope is invalid")]
    ScopeMismatch,
    #[error("ECR evidence or proposal digest fence failed")]
    ProposalMismatch,
    #[error("ECR record does not match its proposal")]
    RecordMismatch,
    #[error("ECR provider definition drifted")]
    ProviderDrift,
    #[error("ECR registration operation failed")]
    Registration(#[from] RegistrationError),
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("ECR provider operation failed: {0}")]
    Provider(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcrImageScanCapability {
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub native: bool,
    pub connected: bool,
    pub durable_receipt: bool,
    pub independent_readback: bool,
    pub image_mutation: bool,
    pub remediation: bool,
    pub raw_layers: bool,
    pub raw_image_bytes: bool,
    pub raw_pii: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcrImageScanServiceDefinition {
    pub id: String,
    pub implementation: String,
    pub version: String,
    pub operations: Vec<String>,
    pub capability: EcrImageScanCapability,
}

impl Default for EcrImageScanServiceDefinition {
    fn default() -> Self {
        Self {
            id: ECR_IMAGE_SCAN_SERVICE_ID.to_owned(),
            implementation: ECR_IMAGE_SCAN_SERVICE_NAME.to_owned(),
            version: crate::ECR_IMAGE_SCAN_PLUGIN_VERSION.to_owned(),
            operations: vec![
                "describe_images".to_owned(),
                "describe_image_scan_findings".to_owned(),
                "read_scan".to_owned(),
                "propose".to_owned(),
                "record".to_owned(),
                "verify".to_owned(),
            ],
            capability: EcrImageScanCapability {
                read_only: true,
                proposal_only: true,
                live_execution: false,
                external_writes: false,
                native: false,
                connected: false,
                durable_receipt: false,
                independent_readback: false,
                image_mutation: false,
                remediation: false,
                raw_layers: false,
                raw_image_bytes: false,
                raw_pii: false,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcrImageScanProposal {
    pub evidence: EcrImageScanEvidence,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub durable_receipt: bool,
    pub independent_readback: bool,
    pub adopted_outcome: bool,
    pub proposal_digest: Digest,
}

pub type EcrImageScanProposalEnvelope = EcrImageScanProposal;

impl EcrImageScanProposal {
    #[must_use]
    pub fn digest(&self) -> Digest {
        serialized_digest(&ProposalDigestMaterial {
            evidence_digest: &self.evidence.evidence_digest,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            contract_digest: &self.contract_digest,
            permission_digest: &self.permission_digest,
            proposal_only: self.proposal_only,
            native: self.native,
            connected: self.connected,
            durable_receipt: self.durable_receipt,
            independent_readback: self.independent_readback,
            adopted_outcome: self.adopted_outcome,
        })
    }

    pub fn validate_for<T: EcrTransport>(
        &self,
        scope: &EcrImageScanScope,
        registration: &EcrImageScanRegistration,
        provider: &EcrProvider<T>,
    ) -> Result<(), EcrImageScanServiceError> {
        self.evidence
            .validate(scope)
            .map_err(|_| EcrImageScanServiceError::ProposalMismatch)?;
        if self.scope_digest != *scope.scope_digest()
            || self.registration_digest != registration.registration_digest
            || self.provider_digest != provider.provider_digest()
            || self.contract_digest != crate::contract_digest()
            || self.permission_digest != *scope.permission().digest()
            || self.evidence.digests.version_digest != crate::version_digest()
            || self.evidence.digests.contract_digest != self.contract_digest
            || self.evidence.digests.provider_digest != self.provider_digest
            || self.evidence.digests.permission_digest != self.permission_digest
            || self.evidence.digests.registration_digest != self.registration_digest
            || !self.proposal_only
            || self.native
            || self.connected
            || self.durable_receipt
            || self.independent_readback
            || self.adopted_outcome
            || self.proposal_digest != self.digest()
        {
            return Err(EcrImageScanServiceError::ProposalMismatch);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ProposalDigestMaterial<'a> {
    evidence_digest: &'a Digest,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    provider_digest: &'a Digest,
    contract_digest: &'a Digest,
    permission_digest: &'a Digest,
    proposal_only: bool,
    native: bool,
    connected: bool,
    durable_receipt: bool,
    independent_readback: bool,
    adopted_outcome: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcrImageScanRecord {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub record_digest: Digest,
    pub recorded: bool,
    pub durable_receipt: bool,
    pub native: bool,
    pub connected: bool,
    pub adopted_outcome: bool,
}

impl EcrImageScanRecord {
    #[must_use]
    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "ecr-image-scan-observation/v1",
            [
                self.proposal_digest.as_str(),
                self.evidence_digest.as_str(),
                self.recorded.to_string().as_str(),
                self.durable_receipt.to_string().as_str(),
                self.native.to_string().as_str(),
                self.connected.to_string().as_str(),
                self.adopted_outcome.to_string().as_str(),
            ],
        )
    }
}

pub type EcrImageScanObservation = EcrImageScanRecord;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcrImageScanVerification {
    pub verified: bool,
    pub proposal_digest: Digest,
    pub record_digest: Digest,
    pub evidence_digest: Digest,
    pub durable_receipt: bool,
    pub independent_readback: bool,
    pub native: bool,
    pub connected: bool,
    pub adopted_outcome: bool,
}

#[derive(Clone)]
pub struct EcrImageScanResultService<T: EcrTransport> {
    scope: EcrImageScanScope,
    secret: crate::SecretReference,
    permission: PermissionFence,
    provider: EcrProvider<T>,
    registration: EcrImageScanRegistration,
    definition: EcrImageScanServiceDefinition,
}

impl<T: EcrTransport> EcrImageScanResultService<T> {
    pub fn new(
        scope: EcrImageScanScope,
        secret: crate::SecretReference,
        permission: PermissionFence,
        provider: EcrProvider<T>,
    ) -> Result<Self, EcrImageScanServiceError> {
        scope.validate()?;
        permission.validate()?;
        if permission.digest() != scope.permission().digest() {
            return Err(EcrImageScanServiceError::PermissionMismatch);
        }
        if secret.is_revoked() {
            return Err(EcrImageScanServiceError::SecretRevoked);
        }
        if secret.scope_digest() != scope.scope_digest() {
            return Err(EcrImageScanServiceError::ScopeMismatch);
        }
        provider
            .definition()
            .validate()
            .map_err(|_| EcrImageScanServiceError::ProviderDrift)?;
        let registration = EcrImageScanRegistration::new(&scope, &secret, &provider)?;
        Ok(Self {
            scope,
            secret,
            permission,
            provider,
            registration,
            definition: EcrImageScanServiceDefinition::default(),
        })
    }

    pub fn from_parts(
        scope: EcrImageScanScope,
        secret: crate::SecretReference,
        permission: PermissionFence,
        provider: EcrProvider<T>,
    ) -> Result<Self, EcrImageScanServiceError> {
        Self::new(scope, secret, permission, provider)
    }

    #[must_use]
    pub fn scope(&self) -> &EcrImageScanScope {
        &self.scope
    }

    #[must_use]
    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    #[must_use]
    pub fn secret_reference(&self) -> &crate::SecretReference {
        &self.secret
    }

    #[must_use]
    pub fn provider(&self) -> &EcrProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut EcrProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &EcrImageScanRegistration {
        &self.registration
    }

    #[must_use]
    pub fn service_definition(&self) -> &EcrImageScanServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret.is_revoked()
    }

    pub fn register(&mut self) -> Result<&EcrImageScanRegistration, EcrImageScanServiceError> {
        if self.registration.is_active() {
            self.registration
                .validate(&self.scope, &self.secret, &self.provider)?;
            Ok(&self.registration)
        } else {
            self.registration.restore()?;
            Ok(&self.registration)
        }
    }

    pub fn revoke_registration(&mut self) -> Result<(), EcrImageScanServiceError> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn restore_registration(&mut self) -> Result<(), EcrImageScanServiceError> {
        self.registration.restore()?;
        Ok(())
    }

    pub fn read(&mut self) -> Result<EcrImageScanEvidence, EcrImageScanServiceError> {
        self.read_scan()
    }

    pub fn read_scan(&mut self) -> Result<EcrImageScanEvidence, EcrImageScanServiceError> {
        self.ensure_ready()?;
        let images_request = DescribeImagesRequest::new(&self.scope, PAGE_SIZE, MAX_PAGES, None)?;
        let images_request_digest = images_request.request_digest().clone();
        let images = match self.collect_images(images_request) {
            Ok(value) => value,
            Err(failure) => {
                return Ok(self.failure_evidence(
                    failure.state,
                    failure.classification,
                    failure.partial_reason,
                    failure.image_pages,
                    0,
                    images_request_digest,
                    failure.findings_request_digest,
                    failure.response_digest,
                    failure.error,
                ));
            }
        };
        let target_present = images
            .images
            .iter()
            .any(|image| image.image_digest == *self.scope.image_digest());
        if !target_present {
            let findings_request =
                DescribeImageScanFindingsRequest::new(&self.scope, PAGE_SIZE, MAX_PAGES, None)?;
            return Ok(self.failure_evidence(
                ScanProjection::Stale,
                EvidenceClassification::Stale,
                Some(PartialReason::MissingImage),
                images.pages,
                0,
                images_request_digest,
                findings_request.request_digest().clone(),
                images.response_digest,
                None,
            ));
        }
        let findings_request =
            DescribeImageScanFindingsRequest::new(&self.scope, PAGE_SIZE, MAX_PAGES, None)?;
        let findings_request_digest = findings_request.request_digest().clone();
        let findings = match self.collect_findings(findings_request) {
            Ok(value) => value,
            Err(failure) => {
                return Ok(self.failure_evidence(
                    failure.state,
                    failure.classification,
                    failure.partial_reason,
                    images.pages,
                    failure.findings_pages,
                    images_request_digest,
                    findings_request_digest,
                    Digest::from_parts(
                        "ecr-response/v1",
                        [
                            images.response_digest.as_str(),
                            failure.response_digest.as_str(),
                        ],
                    ),
                    failure.error,
                ));
            }
        };
        Ok(self.success_evidence(
            images,
            findings,
            images_request_digest,
            findings_request_digest,
        ))
    }

    pub fn describe_images(&mut self) -> Result<EcrImageScanEvidence, EcrImageScanServiceError> {
        self.read_scan()
    }

    pub fn describe_image_scan_findings(
        &mut self,
    ) -> Result<EcrImageScanEvidence, EcrImageScanServiceError> {
        self.read_scan()
    }

    pub fn propose(&mut self) -> Result<EcrImageScanProposal, EcrImageScanServiceError> {
        let evidence = self.read_scan()?;
        self.propose_from_evidence(evidence)
    }

    pub fn compile_proposal(&mut self) -> Result<EcrImageScanProposal, EcrImageScanServiceError> {
        self.propose()
    }

    pub fn propose_from_evidence(
        &self,
        evidence: EcrImageScanEvidence,
    ) -> Result<EcrImageScanProposal, EcrImageScanServiceError> {
        self.ensure_ready()?;
        evidence
            .validate(&self.scope)
            .map_err(|_| EcrImageScanServiceError::ProposalMismatch)?;
        if evidence.digests.provider_digest != self.provider.provider_digest()
            || evidence.digests.permission_digest != *self.permission.digest()
            || evidence.digests.registration_digest != self.registration.registration_digest
        {
            return Err(EcrImageScanServiceError::ProposalMismatch);
        }
        let mut proposal = EcrImageScanProposal {
            evidence,
            scope_digest: self.scope.scope_digest().clone(),
            registration_digest: self.registration.registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            contract_digest: crate::contract_digest(),
            permission_digest: self.permission.digest().clone(),
            proposal_only: true,
            native: false,
            connected: false,
            durable_receipt: false,
            independent_readback: false,
            adopted_outcome: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.digest();
        Ok(proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &EcrImageScanProposal,
    ) -> Result<(), EcrImageScanServiceError> {
        self.ensure_ready()?;
        proposal.validate_for(&self.scope, &self.registration, &self.provider)
    }

    pub fn record(
        &self,
        proposal: &EcrImageScanProposal,
    ) -> Result<EcrImageScanRecord, EcrImageScanServiceError> {
        self.verify_proposal(proposal)?;
        let mut record = EcrImageScanRecord {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            record_digest: Digest::zero(),
            recorded: true,
            durable_receipt: false,
            native: false,
            connected: false,
            adopted_outcome: false,
        };
        record.record_digest = record.recomputed_digest();
        Ok(record)
    }

    pub fn verify(
        &self,
        record: &EcrImageScanRecord,
        proposal: &EcrImageScanProposal,
    ) -> Result<EcrImageScanVerification, EcrImageScanServiceError> {
        self.verify_proposal(proposal)?;
        if !record.recorded
            || record.proposal_digest != proposal.proposal_digest
            || record.evidence_digest != proposal.evidence.evidence_digest
            || record.record_digest != record.recomputed_digest()
            || record.durable_receipt
            || record.native
            || record.connected
            || record.adopted_outcome
        {
            return Err(EcrImageScanServiceError::RecordMismatch);
        }
        Ok(EcrImageScanVerification {
            verified: true,
            proposal_digest: proposal.proposal_digest.clone(),
            record_digest: record.record_digest.clone(),
            evidence_digest: record.evidence_digest.clone(),
            durable_receipt: false,
            independent_readback: false,
            native: false,
            connected: false,
            adopted_outcome: false,
        })
    }

    fn ensure_ready(&self) -> Result<(), EcrImageScanServiceError> {
        self.scope.validate()?;
        self.permission.validate()?;
        if self.permission.digest() != self.scope.permission().digest() {
            return Err(EcrImageScanServiceError::PermissionMismatch);
        }
        if self.secret.is_revoked() {
            return Err(EcrImageScanServiceError::SecretRevoked);
        }
        if self
            .registration
            .validate(&self.scope, &self.secret, &self.provider)
            .is_err()
        {
            return Err(EcrImageScanServiceError::RegistrationRevoked);
        }
        self.provider
            .definition()
            .validate()
            .map_err(|_| EcrImageScanServiceError::ProviderDrift)
    }

    fn collect_images(
        &mut self,
        initial_request: DescribeImagesRequest,
    ) -> Result<CollectedImages, ReadFailure> {
        let mut request = initial_request;
        let mut pages = 0;
        let mut images = Vec::new();
        let mut visited = BTreeSet::new();
        let mut page_digests = Vec::new();
        loop {
            let page = match self.provider.describe_images(&request) {
                Ok(page) => page,
                Err(error) => {
                    return Err(ReadFailure::from_error(
                        error,
                        pages,
                        0,
                        digest_pages("ecr-images-error/v1", &page_digests),
                    ));
                }
            };
            pages += 1;
            page_digests.push(page.page_digest.clone());
            images.extend(page.images.clone());
            if let Some(token) = page.next_page_token {
                if !visited.insert(token.digest()) {
                    return Err(ReadFailure {
                        state: ScanProjection::Partial,
                        classification: EvidenceClassification::Partial,
                        partial_reason: Some(PartialReason::CursorReplay),
                        image_pages: pages,
                        findings_pages: 0,
                        findings_request_digest: Digest::zero(),
                        response_digest: digest_pages("ecr-images-partial/v1", &page_digests),
                        error: None,
                    });
                }
                if pages >= request.max_pages {
                    return Err(ReadFailure {
                        state: ScanProjection::Partial,
                        classification: EvidenceClassification::Partial,
                        partial_reason: Some(PartialReason::PageLimit),
                        image_pages: pages,
                        findings_pages: 0,
                        findings_request_digest: Digest::zero(),
                        response_digest: digest_pages("ecr-images-partial/v1", &page_digests),
                        error: None,
                    });
                }
                request = DescribeImagesRequest::new(
                    &self.scope,
                    request.page_size,
                    request.max_pages,
                    Some(token),
                )
                .map_err(|_| ReadFailure {
                    state: ScanProjection::Tampered,
                    classification: EvidenceClassification::Tampered,
                    partial_reason: None,
                    image_pages: pages,
                    findings_pages: 0,
                    findings_request_digest: Digest::zero(),
                    response_digest: digest_pages("ecr-images-tampered/v1", &page_digests),
                    error: Some(EcrProviderError::Tampered),
                })?;
            } else {
                return Ok(CollectedImages {
                    images,
                    pages,
                    response_digest: digest_pages("ecr-images/v1", &page_digests),
                });
            }
        }
    }

    fn collect_findings(
        &mut self,
        initial_request: DescribeImageScanFindingsRequest,
    ) -> Result<CollectedFindings, ReadFailure> {
        let mut request = initial_request;
        let mut pages = 0;
        let mut lifecycle = None;
        let mut scan_revision = None;
        let mut finding_revision = None;
        let mut findings = Vec::new();
        let mut severity_counts = BTreeMap::<Severity, u64>::new();
        let mut visited = BTreeSet::new();
        let mut page_digests = Vec::new();
        loop {
            let page = match self.provider.describe_image_scan_findings(&request) {
                Ok(page) => page,
                Err(error) => {
                    return Err(ReadFailure::from_error(
                        error,
                        0,
                        pages,
                        digest_pages("ecr-findings-error/v1", &page_digests),
                    ));
                }
            };
            pages += 1;
            page_digests.push(page.page_digest.clone());
            if lifecycle.is_some_and(|value| value != page.lifecycle)
                || scan_revision.is_some_and(|value| value != page.scan_revision)
                || finding_revision.is_some_and(|value| value != page.inspector_finding_revision)
            {
                return Err(ReadFailure {
                    state: ScanProjection::Tampered,
                    classification: EvidenceClassification::Tampered,
                    partial_reason: None,
                    image_pages: 0,
                    findings_pages: pages,
                    findings_request_digest: request.request_digest().clone(),
                    response_digest: digest_pages("ecr-findings-tampered/v1", &page_digests),
                    error: Some(EcrProviderError::Tampered),
                });
            }
            lifecycle = Some(page.lifecycle);
            scan_revision = Some(page.scan_revision);
            finding_revision = Some(page.inspector_finding_revision);
            if page.findings.len() + findings.len() > MAX_FINDINGS {
                return Err(ReadFailure {
                    state: ScanProjection::Partial,
                    classification: EvidenceClassification::Partial,
                    partial_reason: Some(PartialReason::FindingsLimit),
                    image_pages: 0,
                    findings_pages: pages,
                    findings_request_digest: request.request_digest().clone(),
                    response_digest: digest_pages("ecr-findings-partial/v1", &page_digests),
                    error: None,
                });
            }
            findings.extend(page.findings.clone());
            for entry in page.severity_counts {
                *severity_counts.entry(entry.severity).or_default() += entry.count;
            }
            if let Some(token) = page.next_page_token {
                if !visited.insert(token.digest()) {
                    return Err(ReadFailure {
                        state: ScanProjection::Partial,
                        classification: EvidenceClassification::Partial,
                        partial_reason: Some(PartialReason::CursorReplay),
                        image_pages: 0,
                        findings_pages: pages,
                        findings_request_digest: request.request_digest().clone(),
                        response_digest: digest_pages("ecr-findings-partial/v1", &page_digests),
                        error: None,
                    });
                }
                if pages >= request.max_pages {
                    return Err(ReadFailure {
                        state: ScanProjection::Partial,
                        classification: EvidenceClassification::Partial,
                        partial_reason: Some(PartialReason::PageLimit),
                        image_pages: 0,
                        findings_pages: pages,
                        findings_request_digest: request.request_digest().clone(),
                        response_digest: digest_pages("ecr-findings-partial/v1", &page_digests),
                        error: None,
                    });
                }
                request = DescribeImageScanFindingsRequest::new(
                    &self.scope,
                    request.page_size,
                    request.max_pages,
                    Some(token),
                )
                .map_err(|_| ReadFailure {
                    state: ScanProjection::Tampered,
                    classification: EvidenceClassification::Tampered,
                    partial_reason: None,
                    image_pages: 0,
                    findings_pages: pages,
                    findings_request_digest: request.request_digest().clone(),
                    response_digest: digest_pages("ecr-findings-tampered/v1", &page_digests),
                    error: Some(EcrProviderError::Tampered),
                })?;
            } else {
                let lifecycle = lifecycle.unwrap_or(ScanLifecycle::Unknown);
                let state = match lifecycle {
                    ScanLifecycle::Pending => ScanProjection::Pending,
                    ScanLifecycle::Complete => ScanProjection::Complete,
                    ScanLifecycle::Failed => ScanProjection::Failed,
                    ScanLifecycle::Inactive => ScanProjection::Inactive,
                    ScanLifecycle::Expired => ScanProjection::Expired,
                    ScanLifecycle::Unknown => ScanProjection::ProviderUnknown,
                };
                return Ok(CollectedFindings {
                    lifecycle,
                    state,
                    scan_revision: scan_revision.unwrap_or(request.scan_revision),
                    finding_revision: finding_revision
                        .unwrap_or(request.inspector_finding_revision),
                    severity_counts: severity_counts
                        .into_iter()
                        .map(|(severity, count)| SeverityCount::new(severity, count))
                        .collect(),
                    findings,
                    pages,
                    response_digest: digest_pages("ecr-findings/v1", &page_digests),
                });
            }
        }
    }

    fn success_evidence(
        &self,
        images: CollectedImages,
        findings: CollectedFindings,
        request_digest: Digest,
        findings_request_digest: Digest,
    ) -> EcrImageScanEvidence {
        let state = if findings.scan_revision != self.scope.scan_revision()
            || findings.finding_revision != self.scope.inspector_finding_revision()
        {
            ScanProjection::Stale
        } else {
            findings.state
        };
        let classification = match state {
            ScanProjection::Complete
            | ScanProjection::Pending
            | ScanProjection::Failed
            | ScanProjection::Inactive
            | ScanProjection::Expired => EvidenceClassification::Normalized,
            ScanProjection::Stale => EvidenceClassification::Stale,
            ScanProjection::Partial => EvidenceClassification::Partial,
            ScanProjection::AccessLost => EvidenceClassification::AccessLost,
            ScanProjection::Tampered => EvidenceClassification::Tampered,
            ScanProjection::ProviderUnknown => EvidenceClassification::ProviderUnknown,
        };
        self.make_evidence(
            state,
            Some(findings.lifecycle),
            None,
            classification,
            images.pages,
            findings.pages,
            findings.severity_counts,
            findings.findings,
            request_digest,
            findings_request_digest,
            Digest::from_parts(
                "ecr-response/v1",
                [
                    images.response_digest.as_str(),
                    findings.response_digest.as_str(),
                ],
            ),
            None,
        )
    }

    fn failure_evidence(
        &self,
        state: ScanProjection,
        classification: EvidenceClassification,
        partial_reason: Option<PartialReason>,
        image_pages: u16,
        findings_pages: u16,
        request_digest: Digest,
        findings_request_digest: Digest,
        response_digest: Digest,
        error: Option<EcrProviderError>,
    ) -> EcrImageScanEvidence {
        let lifecycle = match state {
            ScanProjection::Pending => Some(ScanLifecycle::Pending),
            ScanProjection::Complete => Some(ScanLifecycle::Complete),
            ScanProjection::Failed => Some(ScanLifecycle::Failed),
            ScanProjection::Inactive => Some(ScanLifecycle::Inactive),
            ScanProjection::Expired => Some(ScanLifecycle::Expired),
            _ => None,
        };
        let provider_error = error.as_ref().map(|error| {
            ProviderErrorEvidence::new(error_kind(error), error.status_code(), error_kind(error))
        });
        self.make_evidence(
            state,
            lifecycle,
            partial_reason,
            classification,
            image_pages,
            findings_pages,
            Vec::new(),
            Vec::new(),
            request_digest,
            findings_request_digest,
            response_digest,
            provider_error,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn make_evidence(
        &self,
        state: ScanProjection,
        lifecycle: Option<ScanLifecycle>,
        partial_reason: Option<PartialReason>,
        classification: EvidenceClassification,
        image_pages: u16,
        findings_pages: u16,
        severity_counts: Vec<SeverityCount>,
        findings: Vec<RedactedFinding>,
        request_digest: Digest,
        findings_request_digest: Digest,
        response_digest: Digest,
        provider_error: Option<ProviderErrorEvidence>,
    ) -> EcrImageScanEvidence {
        let image = EcrImageDescriptor::new(self.scope.image_digest().clone());
        let findings_digest = serialized_digest(&findings);
        let mut evidence = EcrImageScanEvidence {
            operation: EcrOperation::ReadScan,
            state,
            lifecycle,
            partial_reason,
            classification,
            registry: self.scope.registry().clone(),
            account_id: self.scope.account_id().clone(),
            region: self.scope.region().clone(),
            repository: self.scope.repository().clone(),
            image,
            scan_type: self.scope.scan_type(),
            scan_revision: self.scope.scan_revision(),
            inspector_finding_revision: self.scope.inspector_finding_revision(),
            project: self.scope.project().clone(),
            mission: self.scope.mission().clone(),
            work_product: self.scope.work_product().clone(),
            severity_counts,
            findings,
            image_pages,
            findings_pages,
            provider_error,
            provenance: self.provider.provenance(),
            redactions: RedactionSummary::default(),
            request_digest: request_digest.clone(),
            findings_request_digest: findings_request_digest.clone(),
            response_digest: response_digest.clone(),
            digests: EvidenceDigests {
                version_digest: crate::version_digest(),
                contract_digest: crate::contract_digest(),
                provider_digest: self.provider.provider_digest(),
                permission_digest: self.permission.digest().clone(),
                scope_digest: self.scope.scope_digest().clone(),
                registration_digest: self.registration.registration_digest.clone(),
                describe_images_request_digest: request_digest,
                findings_request_digest,
                image_digest: self.scope.image_digest().digest(),
                findings_digest,
                response_digest,
                evidence_digest: Digest::zero(),
            },
            native: false,
            connected: false,
            durable_receipt: false,
            independent_readback: false,
            adopted_outcome: false,
            evidence_digest: Digest::zero(),
        };
        let digest = evidence.digest();
        evidence.evidence_digest = digest.clone();
        evidence.digests.evidence_digest = digest;
        evidence
    }
}

impl<T: EcrTransport> fmt::Debug for EcrImageScanResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct(ECR_IMAGE_SCAN_SERVICE_NAME)
            .field("scope_digest", self.scope.scope_digest())
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("active", &self.is_active())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
struct CollectedImages {
    images: Vec<EcrImageDescriptor>,
    pages: u16,
    response_digest: Digest,
}

#[derive(Clone, Debug)]
struct CollectedFindings {
    lifecycle: ScanLifecycle,
    state: ScanProjection,
    scan_revision: ScanRevision,
    finding_revision: InspectorFindingRevision,
    severity_counts: Vec<SeverityCount>,
    findings: Vec<RedactedFinding>,
    pages: u16,
    response_digest: Digest,
}

#[derive(Clone, Debug)]
struct ReadFailure {
    state: ScanProjection,
    classification: EvidenceClassification,
    partial_reason: Option<PartialReason>,
    image_pages: u16,
    findings_pages: u16,
    findings_request_digest: Digest,
    response_digest: Digest,
    error: Option<EcrProviderError>,
}

impl ReadFailure {
    fn from_error(
        error: EcrProviderError,
        image_pages: u16,
        findings_pages: u16,
        response_digest: Digest,
    ) -> Self {
        let (state, classification) = if error.is_access_loss() {
            (
                ScanProjection::AccessLost,
                EvidenceClassification::AccessLost,
            )
        } else if error.is_stale() {
            (ScanProjection::Stale, EvidenceClassification::Stale)
        } else if error.is_tampered() {
            (ScanProjection::Tampered, EvidenceClassification::Tampered)
        } else {
            (
                ScanProjection::ProviderUnknown,
                EvidenceClassification::ProviderUnknown,
            )
        };
        Self {
            state,
            classification,
            partial_reason: None,
            image_pages,
            findings_pages,
            findings_request_digest: Digest::zero(),
            response_digest,
            error: Some(error),
        }
    }
}

fn error_kind(error: &EcrProviderError) -> &'static str {
    match error {
        EcrProviderError::Transport(error) => error.kind(),
        EcrProviderError::DefinitionDrift => "definition_drift",
        EcrProviderError::InvalidRequest => "invalid_request",
        EcrProviderError::InvalidResponse => "invalid_response",
        EcrProviderError::ResponseTooLarge => "response_too_large",
        EcrProviderError::PageMismatch => "page_mismatch",
        EcrProviderError::ScopeMismatch => "scope_mismatch",
        EcrProviderError::StaleRevision => "stale_revision",
        EcrProviderError::Tampered => "tampered",
    }
}

fn digest_pages(label: &str, pages: &[Digest]) -> Digest {
    Digest::from_parts(label, pages.iter().map(Digest::as_str))
}

pub type EcrImageScanService<T> = EcrImageScanResultService<T>;
pub type EcrImageScanResultProposal = EcrImageScanProposal;
pub type EcrImageScanResultEvidence = EcrImageScanEvidence;
pub type EcrImageScanResultRecord = EcrImageScanRecord;
pub type EcrImageScanResultVerification = EcrImageScanVerification;
