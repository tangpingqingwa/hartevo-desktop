use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    GCP_CLOUD_DEPLOY_API_VERSION, GCP_CLOUD_DEPLOY_CONTRACT_VERSION,
    GCP_CLOUD_DEPLOY_PLUGIN_VERSION_TEXT, GCP_CLOUD_DEPLOY_SCHEMA_VERSION,
    GCP_CLOUD_DEPLOY_SERVICE_ID, GcpCloudDeployLayer1Authority, MAX_JOB_RUNS_PER_PROPOSAL,
    MAX_ROLLOUTS_PER_PROPOSAL, contract_digest,
    model::{
        CloudDeployPhase, CloudDeployStatus, Digest, EvidenceProjection, GcpCloudDeployApiVersion,
        GcpCloudDeployScope, JobRunId, JobRunSnapshot, ModelError, ProviderErrorKind,
        ProviderErrorSummary, ProviderProvenance, ReleasePhase, ReleaseSnapshot, ReleaseStatus,
        Revision, RolloutId, RolloutSnapshot, SecretReference, registration_digest,
    },
    provider::{GcpCloudDeployProvider, GcpCloudDeployProviderError, GcpCloudDeployTransport},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpCloudDeployServiceDefinition {
    service_id: String,
    service_version: String,
    api_version: GcpCloudDeployApiVersion,
    read_only: bool,
    live_execution: bool,
    service_digest: Digest,
}

impl GcpCloudDeployServiceDefinition {
    pub fn layer1() -> Self {
        let service_digest = Digest::from_fields(
            "gcp-cloud-deploy-service/v1",
            &[
                GCP_CLOUD_DEPLOY_SERVICE_ID.to_owned(),
                GCP_CLOUD_DEPLOY_PLUGIN_VERSION_TEXT.to_owned(),
                GCP_CLOUD_DEPLOY_API_VERSION.to_owned(),
                "read_only".to_owned(),
                "no_live_execution".to_owned(),
            ],
        );
        Self {
            service_id: GCP_CLOUD_DEPLOY_SERVICE_ID.to_owned(),
            service_version: GCP_CLOUD_DEPLOY_PLUGIN_VERSION_TEXT.to_owned(),
            api_version: GcpCloudDeployApiVersion::V1,
            read_only: true,
            live_execution: false,
            service_digest,
        }
    }

    pub fn validate(&self) -> Result<(), GcpCloudDeployServiceError> {
        let expected = Self::layer1();
        if self != &expected {
            Err(GcpCloudDeployServiceError::DefinitionDrift)
        } else {
            Ok(())
        }
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn service_version(&self) -> &str {
        &self.service_version
    }

    pub const fn api_version(&self) -> GcpCloudDeployApiVersion {
        self.api_version
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub const fn live_execution(&self) -> bool {
        self.live_execution
    }

    pub fn service_digest(&self) -> &Digest {
        &self.service_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpCloudDeployRegistration {
    schema_version: String,
    contract_version: String,
    plugin_version: String,
    api_version: GcpCloudDeployApiVersion,
    service_digest: Digest,
    version_digest: Digest,
    api_digest: Digest,
    contract_digest: Digest,
    provider_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    release_digest: Digest,
    registration_digest: Digest,
    revision: Revision,
    state: RegistrationState,
    reversible: bool,
    revocable: bool,
}

impl GcpCloudDeployRegistration {
    fn new<T: GcpCloudDeployTransport>(
        scope: &GcpCloudDeployScope,
        provider: &GcpCloudDeployProvider<T>,
        service: &GcpCloudDeployServiceDefinition,
    ) -> Result<Self, GcpCloudDeployServiceError> {
        let provider_digest = provider.provider_digest().clone();
        let permission_digest = scope.permissions().digest();
        let scope_digest = scope.digest();
        let release_digest = scope.release_digest();
        let version_digest = Digest::from_text(GCP_CLOUD_DEPLOY_PLUGIN_VERSION_TEXT);
        let api_digest = GcpCloudDeployApiVersion::V1.digest();
        let contract_digest_value = contract_digest();
        let registration_digest = registration_digest(
            service.service_digest(),
            &version_digest,
            &api_digest,
            &contract_digest_value,
            &provider_digest,
            &permission_digest,
            &scope_digest,
            &release_digest,
        );
        Ok(Self {
            schema_version: GCP_CLOUD_DEPLOY_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_CLOUD_DEPLOY_CONTRACT_VERSION.to_owned(),
            plugin_version: GCP_CLOUD_DEPLOY_PLUGIN_VERSION_TEXT.to_owned(),
            api_version: GcpCloudDeployApiVersion::V1,
            service_digest: service.service_digest().clone(),
            version_digest,
            api_digest,
            contract_digest: contract_digest_value,
            provider_digest,
            permission_digest,
            scope_digest,
            release_digest,
            registration_digest,
            revision: Revision::new(1)?,
            state: RegistrationState::Active,
            reversible: true,
            revocable: true,
        })
    }

    pub fn validate<T: GcpCloudDeployTransport>(
        &self,
        scope: &GcpCloudDeployScope,
        provider: &GcpCloudDeployProvider<T>,
        service: &GcpCloudDeployServiceDefinition,
    ) -> Result<(), GcpCloudDeployServiceError> {
        service.validate()?;
        let expected = Self::new(scope, provider, service)?;
        if self.schema_version != expected.schema_version
            || self.contract_version != expected.contract_version
            || self.plugin_version != expected.plugin_version
            || self.api_version != expected.api_version
            || self.service_digest != expected.service_digest
            || self.version_digest != expected.version_digest
            || self.api_digest != expected.api_digest
            || self.contract_digest != expected.contract_digest
            || self.provider_digest != expected.provider_digest
            || self.permission_digest != expected.permission_digest
            || self.scope_digest != expected.scope_digest
            || self.release_digest != expected.release_digest
            || self.registration_digest != expected.registration_digest
            || self.revision != expected.revision
            || !self.reversible
            || !self.revocable
        {
            return Err(GcpCloudDeployServiceError::RegistrationMismatch);
        }
        Ok(())
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub const fn api_version(&self) -> GcpCloudDeployApiVersion {
        self.api_version
    }

    pub fn service_digest(&self) -> &Digest {
        &self.service_digest
    }

    pub fn version_digest(&self) -> &Digest {
        &self.version_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn release_digest(&self) -> &Digest {
        &self.release_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub const fn reversible(&self) -> bool {
        self.reversible
    }

    pub const fn revocable(&self) -> bool {
        self.revocable
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, GcpCloudDeployServiceError> {
        if !self.is_active() {
            return Err(GcpCloudDeployServiceError::RegistrationRevoked);
        }
        let prior_digest = self.registration_digest.clone();
        self.state = RegistrationState::Revoked;
        let revocation_digest = Digest::from_fields(
            "gcp-cloud-deploy-registration-revocation/v1",
            &[
                prior_digest.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        );
        Ok(RegistrationRevocation {
            registration_digest: prior_digest,
            revocation_digest,
            reversible: true,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    registration_digest: Digest,
    revocation_digest: Digest,
    reversible: bool,
}

impl RegistrationRevocation {
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn revocation_digest(&self) -> &Digest {
        &self.revocation_digest
    }

    pub const fn reversible(&self) -> bool {
        self.reversible
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpCloudDeployEvidence {
    version_digest: Digest,
    api_digest: Digest,
    contract_digest: Digest,
    provider_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    release_digest: Digest,
    target_digest: Digest,
    commit_digest: Digest,
    mission_digest: Digest,
    project_digest: Digest,
    work_product_digest: Digest,
    registration_digest: Digest,
    provenance: ProviderProvenance,
    projection: EvidenceProjection,
    deployment_success_claimed: bool,
    release_phase: Option<ReleasePhase>,
    release_status: Option<ReleaseStatus>,
    rollout_phases: Vec<CloudDeployPhase>,
    rollout_statuses: Vec<CloudDeployStatus>,
    job_run_phases: Vec<CloudDeployPhase>,
    job_run_statuses: Vec<CloudDeployStatus>,
    rollout_digests: Vec<Digest>,
    job_run_digests: Vec<Digest>,
    log_digests: Vec<Digest>,
    artifact_digests: Vec<Digest>,
    error: Option<ProviderErrorSummary>,
    observed_at: Option<crate::model::Timestamp>,
    evidence_digest: Digest,
}

impl GcpCloudDeployEvidence {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &GcpCloudDeployRegistration,
        scope: &GcpCloudDeployScope,
        provenance: ProviderProvenance,
        projection: EvidenceProjection,
        release: Option<&ReleaseSnapshot>,
        rollouts: &[RolloutSnapshot],
        job_runs: &[JobRunSnapshot],
        error: Option<ProviderErrorSummary>,
    ) -> Self {
        let mut evidence = Self {
            version_digest: registration.version_digest.clone(),
            api_digest: registration.api_digest.clone(),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: registration.provider_digest.clone(),
            permission_digest: registration.permission_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            release_digest: registration.release_digest.clone(),
            target_digest: scope.target_digest(),
            commit_digest: scope.commit_digest(),
            mission_digest: scope.mission_digest(),
            project_digest: scope.project_scope_digest(),
            work_product_digest: scope.work_product_digest(),
            registration_digest: registration.registration_digest.clone(),
            provenance,
            projection,
            deployment_success_claimed: false,
            release_phase: release.map(ReleaseSnapshot::phase),
            release_status: release.map(ReleaseSnapshot::status),
            rollout_phases: rollouts.iter().map(RolloutSnapshot::phase).collect(),
            rollout_statuses: rollouts.iter().map(RolloutSnapshot::status).collect(),
            job_run_phases: job_runs.iter().map(JobRunSnapshot::phase).collect(),
            job_run_statuses: job_runs.iter().map(JobRunSnapshot::status).collect(),
            rollout_digests: rollouts
                .iter()
                .map(|rollout| rollout.snapshot_digest().clone())
                .collect(),
            job_run_digests: job_runs
                .iter()
                .map(|job_run| job_run.snapshot_digest().clone())
                .collect(),
            log_digests: release
                .into_iter()
                .filter_map(ReleaseSnapshot::log_digest)
                .cloned()
                .chain(
                    rollouts
                        .iter()
                        .filter_map(RolloutSnapshot::log_digest)
                        .cloned(),
                )
                .chain(
                    job_runs
                        .iter()
                        .filter_map(JobRunSnapshot::log_digest)
                        .cloned(),
                )
                .collect(),
            artifact_digests: release
                .into_iter()
                .filter_map(ReleaseSnapshot::artifact_digest)
                .cloned()
                .chain(
                    rollouts
                        .iter()
                        .filter_map(RolloutSnapshot::artifact_digest)
                        .cloned(),
                )
                .chain(
                    job_runs
                        .iter()
                        .filter_map(JobRunSnapshot::artifact_digest)
                        .cloned(),
                )
                .collect(),
            error,
            observed_at: release
                .map(ReleaseSnapshot::observed_at)
                .or_else(|| rollouts.iter().map(RolloutSnapshot::observed_at).max()),
            evidence_digest: Digest::from_text("pending"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    fn compute_digest(&self) -> Digest {
        let mut fields = vec![
            self.version_digest.as_str().to_owned(),
            self.api_digest.as_str().to_owned(),
            self.contract_digest.as_str().to_owned(),
            self.provider_digest.as_str().to_owned(),
            self.permission_digest.as_str().to_owned(),
            self.scope_digest.as_str().to_owned(),
            self.release_digest.as_str().to_owned(),
            self.target_digest.as_str().to_owned(),
            self.commit_digest.as_str().to_owned(),
            self.mission_digest.as_str().to_owned(),
            self.project_digest.as_str().to_owned(),
            self.work_product_digest.as_str().to_owned(),
            self.registration_digest.as_str().to_owned(),
            self.provenance.as_str().to_owned(),
            format!("{:?}", self.projection),
            self.deployment_success_claimed.to_string(),
            self.release_phase
                .map_or_else(|| "none".to_owned(), |value| format!("{value:?}")),
            self.release_status
                .map_or_else(|| "none".to_owned(), |value| format!("{value:?}")),
            format!("{:?}", self.rollout_phases),
            format!("{:?}", self.rollout_statuses),
            format!("{:?}", self.job_run_phases),
            format!("{:?}", self.job_run_statuses),
            format!("{:?}", self.error),
            self.observed_at
                .map_or_else(|| "none".to_owned(), |value| value.seconds().to_string()),
        ];
        fields.extend(
            self.rollout_digests
                .iter()
                .map(|digest| digest.as_str().to_owned()),
        );
        fields.extend(
            self.job_run_digests
                .iter()
                .map(|digest| digest.as_str().to_owned()),
        );
        fields.extend(
            self.log_digests
                .iter()
                .map(|digest| digest.as_str().to_owned()),
        );
        fields.extend(
            self.artifact_digests
                .iter()
                .map(|digest| digest.as_str().to_owned()),
        );
        Digest::from_fields("gcp-cloud-deploy-evidence/v1", &fields)
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.evidence_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn version_digest(&self) -> &Digest {
        &self.version_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn release_digest(&self) -> &Digest {
        &self.release_digest
    }

    pub fn target_digest(&self) -> &Digest {
        &self.target_digest
    }

    pub fn commit_digest(&self) -> &Digest {
        &self.commit_digest
    }

    pub fn mission_digest(&self) -> &Digest {
        &self.mission_digest
    }

    pub fn project_digest(&self) -> &Digest {
        &self.project_digest
    }

    pub fn work_product_digest(&self) -> &Digest {
        &self.work_product_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn projection(&self) -> EvidenceProjection {
        self.projection
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub const fn deployment_success_claimed(&self) -> bool {
        self.deployment_success_claimed
    }

    pub fn error(&self) -> Option<&ProviderErrorSummary> {
        self.error.as_ref()
    }

    pub fn rollout_digests(&self) -> &[Digest] {
        &self.rollout_digests
    }

    pub fn job_run_digests(&self) -> &[Digest] {
        &self.job_run_digests
    }

    pub fn log_digests(&self) -> &[Digest] {
        &self.log_digests
    }

    pub fn artifact_digests(&self) -> &[Digest] {
        &self.artifact_digests
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpCloudDeployProposal {
    registration_digest: Digest,
    registration_revision: Revision,
    scope_digest: Digest,
    projection: EvidenceProjection,
    release: Option<ReleaseSnapshot>,
    rollouts: Vec<RolloutSnapshot>,
    job_runs: Vec<JobRunSnapshot>,
    evidence: GcpCloudDeployEvidence,
    proposal_digest: Digest,
}

impl GcpCloudDeployProposal {
    fn new(
        registration: &GcpCloudDeployRegistration,
        projection: EvidenceProjection,
        release: Option<ReleaseSnapshot>,
        rollouts: Vec<RolloutSnapshot>,
        job_runs: Vec<JobRunSnapshot>,
        evidence: GcpCloudDeployEvidence,
    ) -> Self {
        let mut proposal = Self {
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.revision,
            scope_digest: registration.scope_digest.clone(),
            projection,
            release,
            rollouts,
            job_runs,
            evidence,
            proposal_digest: Digest::from_text("pending"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    fn compute_digest(&self) -> Digest {
        let mut fields = vec![
            self.registration_digest.as_str().to_owned(),
            self.registration_revision.get().to_string(),
            self.scope_digest.as_str().to_owned(),
            format!("{:?}", self.projection),
            self.evidence.evidence_digest().as_str().to_owned(),
        ];
        if let Some(release) = &self.release {
            fields.push(release.snapshot_digest().as_str().to_owned());
        }
        fields.extend(
            self.rollouts
                .iter()
                .map(|rollout| rollout.snapshot_digest().as_str().to_owned()),
        );
        fields.extend(
            self.job_runs
                .iter()
                .map(|job_run| job_run.snapshot_digest().as_str().to_owned()),
        );
        Digest::from_fields("gcp-cloud-deploy-proposal/v1", &fields)
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if let Some(release) = &self.release {
            release.validate_digest()?;
        }
        for rollout in &self.rollouts {
            rollout.validate_digest()?;
        }
        for job_run in &self.job_runs {
            job_run.validate_digest()?;
        }
        self.evidence.validate_digest()?;
        if self.proposal_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn registration_revision(&self) -> Revision {
        self.registration_revision
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn projection(&self) -> EvidenceProjection {
        self.projection
    }

    pub const fn deployment_success_claimed(&self) -> bool {
        self.evidence.deployment_success_claimed()
    }

    pub fn release(&self) -> Option<&ReleaseSnapshot> {
        self.release.as_ref()
    }

    pub fn rollouts(&self) -> &[RolloutSnapshot] {
        &self.rollouts
    }

    pub fn job_runs(&self) -> &[JobRunSnapshot] {
        &self.job_runs
    }

    pub fn evidence(&self) -> &GcpCloudDeployEvidence {
        &self.evidence
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub const fn authority(&self) -> GcpCloudDeployLayer1Authority {
        GcpCloudDeployLayer1Authority
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpCloudDeployRecord {
    registration_digest: Digest,
    proposal_digest: Digest,
    evidence_digest: Digest,
    record_digest: Digest,
    reversible: bool,
    connected: bool,
    native: bool,
    durable: bool,
}

impl GcpCloudDeployRecord {
    fn new(proposal: &GcpCloudDeployProposal) -> Self {
        let mut record = Self {
            registration_digest: proposal.registration_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest().clone(),
            record_digest: Digest::from_text("pending"),
            reversible: true,
            connected: false,
            native: false,
            durable: false,
        };
        record.record_digest = record.compute_digest();
        record
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-deploy-record/v1",
            &[
                self.registration_digest.as_str().to_owned(),
                self.proposal_digest.as_str().to_owned(),
                self.evidence_digest.as_str().to_owned(),
                self.reversible.to_string(),
                self.connected.to_string(),
                self.native.to_string(),
                self.durable.to_string(),
            ],
        )
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.record_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn record_digest(&self) -> &Digest {
        &self.record_digest
    }

    pub const fn reversible(&self) -> bool {
        self.reversible
    }

    pub const fn connected(&self) -> bool {
        self.connected
    }

    pub const fn native(&self) -> bool {
        self.native
    }

    pub const fn durable(&self) -> bool {
        self.durable
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Verified,
    Tampered,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpCloudDeployVerification {
    status: VerificationStatus,
    record_digest: Digest,
    proposal_digest: Digest,
    evidence_digest: Digest,
    verification_digest: Digest,
}

impl GcpCloudDeployVerification {
    fn new(
        status: VerificationStatus,
        record: &GcpCloudDeployRecord,
        proposal: &GcpCloudDeployProposal,
    ) -> Self {
        let verification_digest = Digest::from_fields(
            "gcp-cloud-deploy-verification/v1",
            &[
                format!("{status:?}"),
                record.record_digest().as_str().to_owned(),
                proposal.proposal_digest().as_str().to_owned(),
                proposal.evidence().evidence_digest().as_str().to_owned(),
            ],
        );
        Self {
            status,
            record_digest: record.record_digest().clone(),
            proposal_digest: proposal.proposal_digest().clone(),
            evidence_digest: proposal.evidence().evidence_digest().clone(),
            verification_digest,
        }
    }

    pub const fn status(&self) -> VerificationStatus {
        self.status
    }

    pub const fn is_valid(&self) -> bool {
        matches!(self.status, VerificationStatus::Verified)
    }

    pub const fn is_tampered(&self) -> bool {
        matches!(self.status, VerificationStatus::Tampered)
    }

    pub const fn is_revoked(&self) -> bool {
        matches!(self.status, VerificationStatus::Revoked)
    }

    pub fn verification_digest(&self) -> &Digest {
        &self.verification_digest
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GcpCloudDeployServiceError {
    #[error("scope mismatch")]
    ScopeMismatch,
    #[error("registration mismatch")]
    RegistrationMismatch,
    #[error("service definition drift")]
    DefinitionDrift,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("provider read failed: {0}")]
    Provider(#[from] GcpCloudDeployProviderError),
    #[error("phase or status transition is invalid")]
    PhaseRegression,
    #[error("proposal is invalid or tampered")]
    InvalidProposal,
    #[error("record is invalid or tampered")]
    InvalidRecord,
    #[error("model validation failed: {0}")]
    Model(#[from] ModelError),
}

pub struct GcpCloudDeployService<T>
where
    T: GcpCloudDeployTransport,
{
    scope: GcpCloudDeployScope,
    secret: SecretReference,
    provider: GcpCloudDeployProvider<T>,
    definition: GcpCloudDeployServiceDefinition,
    registration: GcpCloudDeployRegistration,
    last_release: Option<(ReleasePhase, ReleaseStatus)>,
    last_rollouts: BTreeMap<RolloutId, (CloudDeployPhase, CloudDeployStatus)>,
    last_job_runs: BTreeMap<JobRunId, (CloudDeployPhase, CloudDeployStatus)>,
}

impl<T> fmt::Debug for GcpCloudDeployService<T>
where
    T: GcpCloudDeployTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpCloudDeployService")
            .field("scope", &self.scope)
            .field("secret", &self.secret)
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("last_release", &self.last_release)
            .field("last_rollouts", &self.last_rollouts)
            .field("last_job_runs", &self.last_job_runs)
            .finish()
    }
}

impl<T> GcpCloudDeployService<T>
where
    T: GcpCloudDeployTransport,
{
    pub fn new(
        scope: GcpCloudDeployScope,
        secret: SecretReference,
        provider: GcpCloudDeployProvider<T>,
    ) -> Result<Self, GcpCloudDeployServiceError> {
        scope.validate()?;
        if secret.scope_digest() != &scope.digest()
            || provider.scope_digest() != scope.digest()
            || provider.permission_digest() != scope.permissions().digest()
        {
            return Err(GcpCloudDeployServiceError::ScopeMismatch);
        }
        let definition = GcpCloudDeployServiceDefinition::layer1();
        let registration = GcpCloudDeployRegistration::new(&scope, &provider, &definition)?;
        registration.validate(&scope, &provider, &definition)?;
        Ok(Self {
            scope,
            secret,
            provider,
            definition,
            registration,
            last_release: None,
            last_rollouts: BTreeMap::new(),
            last_job_runs: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &GcpCloudDeployScope {
        &self.scope
    }

    pub fn secret(&self) -> &SecretReference {
        &self.secret
    }

    pub fn secret_mut(&mut self) -> &mut SecretReference {
        &mut self.secret
    }

    pub fn provider(&self) -> &GcpCloudDeployProvider<T> {
        &self.provider
    }

    pub fn definition(&self) -> &GcpCloudDeployServiceDefinition {
        &self.definition
    }

    pub fn registration(&self) -> &GcpCloudDeployRegistration {
        &self.registration
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, GcpCloudDeployServiceError> {
        self.registration.revoke()
    }

    fn ensure_active(&self) -> Result<(), GcpCloudDeployServiceError> {
        self.definition.validate()?;
        self.registration
            .validate(&self.scope, &self.provider, &self.definition)?;
        if !self.registration.is_active() {
            return Err(GcpCloudDeployServiceError::RegistrationRevoked);
        }
        if self.secret.is_revoked() {
            return Err(GcpCloudDeployServiceError::SecretRevoked);
        }
        Ok(())
    }

    pub fn get_release(&mut self) -> Result<ReleaseSnapshot, GcpCloudDeployServiceError> {
        self.ensure_active()?;
        self.provider.get_release().map_err(Into::into)
    }

    pub fn list_releases(
        &mut self,
        cursor: Option<crate::model::PageCursor>,
    ) -> Result<crate::model::ReleasePage, GcpCloudDeployServiceError> {
        self.ensure_active()?;
        self.provider.list_releases(cursor).map_err(Into::into)
    }

    pub fn get_rollout(
        &mut self,
        rollout_id: RolloutId,
    ) -> Result<RolloutSnapshot, GcpCloudDeployServiceError> {
        self.ensure_active()?;
        self.provider.get_rollout(rollout_id).map_err(Into::into)
    }

    pub fn list_rollouts(
        &mut self,
        cursor: Option<crate::model::PageCursor>,
    ) -> Result<crate::model::RolloutPage, GcpCloudDeployServiceError> {
        self.ensure_active()?;
        self.provider.list_rollouts(cursor).map_err(Into::into)
    }

    pub fn get_job_run(
        &mut self,
        rollout_id: RolloutId,
        job_run_id: JobRunId,
    ) -> Result<JobRunSnapshot, GcpCloudDeployServiceError> {
        self.ensure_active()?;
        self.provider
            .get_job_run(rollout_id, job_run_id)
            .map_err(Into::into)
    }

    pub fn list_job_runs(
        &mut self,
        rollout_id: RolloutId,
        cursor: Option<crate::model::PageCursor>,
    ) -> Result<crate::model::JobRunPage, GcpCloudDeployServiceError> {
        self.ensure_active()?;
        self.provider
            .list_job_runs(rollout_id, cursor)
            .map_err(Into::into)
    }

    pub fn propose(&mut self) -> Result<GcpCloudDeployProposal, GcpCloudDeployServiceError> {
        self.ensure_active()?;
        let (release, mut projection, mut error) = match self.provider.get_release() {
            Ok(release) => (Some(release), EvidenceProjection::Complete, None),
            Err(provider_error) => {
                let summary = provider_error.summary();
                (None, projection_for_error(&summary), Some(summary))
            }
        };
        let mut rollouts = Vec::new();
        let mut job_runs = Vec::new();

        if let Some(release_snapshot) = &release {
            match self.provider.list_rollouts(None) {
                Ok(page) => {
                    rollouts.extend(page.items().iter().cloned());
                    if rollouts.len() > MAX_ROLLOUTS_PER_PROPOSAL {
                        return Err(GcpCloudDeployServiceError::Model(ModelError::BoundExceeded));
                    }
                    if rollouts.is_empty() {
                        projection = EvidenceProjection::Partial;
                    }
                    for rollout in &rollouts {
                        match self
                            .provider
                            .list_job_runs(rollout.identity().rollout_id().clone(), None)
                        {
                            Ok(page) => {
                                if job_runs.len() + page.items().len() > MAX_JOB_RUNS_PER_PROPOSAL {
                                    return Err(GcpCloudDeployServiceError::Model(
                                        ModelError::BoundExceeded,
                                    ));
                                }
                                job_runs.extend(page.items().iter().cloned());
                            }
                            Err(provider_error) => {
                                let summary = provider_error.summary();
                                projection = projection_for_error(&summary);
                                error = Some(summary);
                                break;
                            }
                        }
                    }
                }
                Err(provider_error) => {
                    let summary = provider_error.summary();
                    projection = projection_for_error(&summary);
                    error = Some(summary);
                }
            }
            if error.is_none() && job_runs.is_empty() {
                projection = EvidenceProjection::Partial;
            }
            if error.is_none() {
                projection = projection_for_snapshots(release_snapshot, &rollouts, &job_runs);
            }
        }

        self.validate_phase_memory(release.as_ref(), &rollouts, &job_runs)?;
        let evidence = GcpCloudDeployEvidence::new(
            &self.registration,
            &self.scope,
            self.provider.definition().provenance(),
            projection,
            release.as_ref(),
            &rollouts,
            &job_runs,
            error,
        );
        evidence.validate_digest()?;
        let proposal = GcpCloudDeployProposal::new(
            &self.registration,
            projection,
            release,
            rollouts,
            job_runs,
            evidence,
        );
        proposal.validate_digest()?;
        self.commit_phase_memory(&proposal);
        Ok(proposal)
    }

    pub fn reconcile(&mut self) -> Result<GcpCloudDeployProposal, GcpCloudDeployServiceError> {
        self.propose()
    }

    pub fn record(
        &self,
        proposal: &GcpCloudDeployProposal,
    ) -> Result<GcpCloudDeployRecord, GcpCloudDeployServiceError> {
        self.ensure_active()?;
        self.validate_proposal_fence(proposal)?;
        Ok(GcpCloudDeployRecord::new(proposal))
    }

    pub fn verify(
        &self,
        record: &GcpCloudDeployRecord,
        proposal: &GcpCloudDeployProposal,
    ) -> Result<GcpCloudDeployVerification, GcpCloudDeployServiceError> {
        if !self.registration.is_active() || self.secret.is_revoked() {
            return Ok(GcpCloudDeployVerification::new(
                VerificationStatus::Revoked,
                record,
                proposal,
            ));
        }
        let proposal_valid =
            self.validate_proposal_fence(proposal).is_ok() && proposal.validate_digest().is_ok();
        let record_valid = record.validate_digest().is_ok();
        let expected = GcpCloudDeployRecord::new(proposal);
        let status = if proposal_valid && record_valid && record == &expected {
            VerificationStatus::Verified
        } else {
            VerificationStatus::Tampered
        };
        Ok(GcpCloudDeployVerification::new(status, record, proposal))
    }

    fn validate_proposal_fence(
        &self,
        proposal: &GcpCloudDeployProposal,
    ) -> Result<(), GcpCloudDeployServiceError> {
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.registration_revision != self.registration.revision()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.scope_digest() != &self.scope.digest()
            || proposal.evidence.registration_digest() != self.registration.registration_digest()
            || proposal.evidence.permission_digest() != &self.scope.permissions().digest()
            || proposal.evidence.release_digest() != &self.scope.release_digest()
            || proposal.evidence.target_digest() != &self.scope.target_digest()
            || proposal.evidence.commit_digest() != &self.scope.commit_digest()
            || proposal.evidence.mission_digest() != &self.scope.mission_digest()
            || proposal.evidence.project_digest() != &self.scope.project_scope_digest()
            || proposal.evidence.work_product_digest() != &self.scope.work_product_digest()
        {
            return Err(GcpCloudDeployServiceError::ScopeMismatch);
        }
        if proposal.validate_digest().is_err() {
            return Err(GcpCloudDeployServiceError::InvalidProposal);
        }
        Ok(())
    }

    fn validate_phase_memory(
        &self,
        release: Option<&ReleaseSnapshot>,
        rollouts: &[RolloutSnapshot],
        job_runs: &[JobRunSnapshot],
    ) -> Result<(), GcpCloudDeployServiceError> {
        if let (Some((previous_phase, previous_status)), Some(current)) =
            (self.last_release, release)
            && (!previous_phase.can_transition_to(current.phase())
                || !previous_status.can_transition_to(current.status()))
        {
            return Err(GcpCloudDeployServiceError::PhaseRegression);
        }
        for rollout in rollouts {
            if let Some((previous_phase, previous_status)) =
                self.last_rollouts.get(rollout.identity().rollout_id())
                && (!previous_phase.can_transition_to(rollout.phase())
                    || !previous_status.can_transition_to(rollout.status()))
            {
                return Err(GcpCloudDeployServiceError::PhaseRegression);
            }
        }
        for job_run in job_runs {
            if let Some((previous_phase, previous_status)) =
                self.last_job_runs.get(job_run.identity().job_run_id())
                && (!previous_phase.can_transition_to(job_run.phase())
                    || !previous_status.can_transition_to(job_run.status()))
            {
                return Err(GcpCloudDeployServiceError::PhaseRegression);
            }
        }
        Ok(())
    }

    fn commit_phase_memory(&mut self, proposal: &GcpCloudDeployProposal) {
        if let Some(release) = proposal.release() {
            self.last_release = Some((release.phase(), release.status()));
        }
        for rollout in proposal.rollouts() {
            self.last_rollouts.insert(
                rollout.identity().rollout_id().clone(),
                (rollout.phase(), rollout.status()),
            );
        }
        for job_run in proposal.job_runs() {
            self.last_job_runs.insert(
                job_run.identity().job_run_id().clone(),
                (job_run.phase(), job_run.status()),
            );
        }
    }
}

fn projection_for_error(summary: &ProviderErrorSummary) -> EvidenceProjection {
    match summary.kind {
        ProviderErrorKind::Unauthorized | ProviderErrorKind::Forbidden => {
            EvidenceProjection::AccessLost
        }
        ProviderErrorKind::RateLimited => EvidenceProjection::RateLimited,
        ProviderErrorKind::Server | ProviderErrorKind::Timeout | ProviderErrorKind::Conflict => {
            EvidenceProjection::Partial
        }
        ProviderErrorKind::Transport => EvidenceProjection::Partial,
        ProviderErrorKind::NotFound
        | ProviderErrorKind::Malformed
        | ProviderErrorKind::CursorMismatch
        | ProviderErrorKind::ScopeMismatch
        | ProviderErrorKind::StaleCommit
        | ProviderErrorKind::StaleTarget
        | ProviderErrorKind::SecretRevoked
        | ProviderErrorKind::BlockedEnv
        | ProviderErrorKind::PhaseRegression
        | ProviderErrorKind::Unknown => EvidenceProjection::Unknown,
    }
}

fn projection_for_snapshots(
    release: &ReleaseSnapshot,
    rollouts: &[RolloutSnapshot],
    job_runs: &[JobRunSnapshot],
) -> EvidenceProjection {
    if rollouts.is_empty() || job_runs.is_empty() {
        return EvidenceProjection::Partial;
    }
    if release.phase() == CloudDeployPhase::Unknown
        || release.status() == CloudDeployStatus::Unknown
        || rollouts.iter().any(|rollout| {
            rollout.phase() == CloudDeployPhase::Unknown
                || rollout.status() == CloudDeployStatus::Unknown
        })
        || job_runs.iter().any(|job_run| {
            job_run.phase() == CloudDeployPhase::Unknown
                || job_run.status() == CloudDeployStatus::Unknown
        })
    {
        EvidenceProjection::Unknown
    } else if release.phase() == CloudDeployPhase::Pending
        || release.phase() == CloudDeployPhase::InProgress
        || release.status() == CloudDeployStatus::Pending
        || release.status() == CloudDeployStatus::Running
        || rollouts.iter().any(|rollout| {
            rollout.phase() == CloudDeployPhase::Pending
                || rollout.phase() == CloudDeployPhase::InProgress
                || rollout.status() == CloudDeployStatus::Pending
                || rollout.status() == CloudDeployStatus::Running
        })
        || job_runs.iter().any(|job_run| {
            job_run.phase() == CloudDeployPhase::Pending
                || job_run.phase() == CloudDeployPhase::InProgress
                || job_run.status() == CloudDeployStatus::Pending
                || job_run.status() == CloudDeployStatus::Running
        })
    {
        EvidenceProjection::Partial
    } else {
        EvidenceProjection::Complete
    }
}
