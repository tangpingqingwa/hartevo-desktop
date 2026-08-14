//! Typed Octopus provider for bounded release/deployment result evidence.

use serde::{Deserialize, Serialize};

use crate::model::{
    ChannelPayload, DeploymentPayload, DeploymentProcessPayload, DeploymentProcessTemplatePayload,
    EnvironmentPayload, OctopusScope, ProjectPayload, ReleasePayload, SpacePayload, TaskPayload,
    TenantPayload, validate_collection_len, validate_payload_identifier, validate_payload_name,
    validate_payload_state, validate_targets,
};
use crate::service::OctopusRegistration;
use crate::transport::{
    OctopusEndpoint, OctopusHttpRequest, OctopusReceipt, OctopusResponseBody, OctopusTransport,
    OctopusTransportError, TransportProvenance,
};
use crate::{
    API_REVISION, CONTRACT_VERSION, Digest, MAX_ITEMS_PER_COLLECTION, MAX_PAGES, MAX_RECEIPTS,
    MAX_RESPONSE_BYTES, OctopusReleaseResultError, PLUGIN_VERSION, PROVIDER_ID, PROVIDER_REVISION,
    Result, contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectionStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Canceled,
    Paused,
    Partial,
    RetentionGap,
    AccessLost,
    ProviderUnknown,
}

impl ProjectionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
            Self::Paused => "paused",
            Self::Partial => "partial",
            Self::RetentionGap => "retention-gap",
            Self::AccessLost => "access-lost",
            Self::ProviderUnknown => "provider-unknown",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Canceled | Self::RetentionGap
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionCompleteness {
    Complete,
    Partial,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OctopusReadRequest {
    pub scope: OctopusScope,
    pub max_pages: usize,
    pub max_response_bytes: usize,
}

impl OctopusReadRequest {
    pub fn new(scope: OctopusScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope,
            max_pages: MAX_PAGES,
            max_response_bytes: MAX_RESPONSE_BYTES,
        })
    }

    pub fn with_bounds(
        scope: OctopusScope,
        max_pages: usize,
        max_response_bytes: usize,
    ) -> Result<Self> {
        scope.validate()?;
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(OctopusReleaseResultError::PaginationLimit);
        }
        if max_response_bytes == 0 || max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(OctopusReleaseResultError::ResponseTooLarge);
        }
        Ok(Self {
            scope,
            max_pages,
            max_response_bytes,
        })
    }
}

/// A normalized release-result projection. Provider names and payloads are
/// represented by digests; only the exact opaque scope and redacted receipts
/// cross this boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct OctopusResultProjection {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_api_revision: String,
    pub provider_revision: String,
    pub plugin_version: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub scope: OctopusScope,
    pub status: ProjectionStatus,
    pub completeness: ProjectionCompleteness,
    pub release_metadata_digest: Digest,
    pub deployment_process_metadata_digest: Digest,
    pub deployment_state_digest: Digest,
    pub task_state_digest: Digest,
    pub target_state_digest: Digest,
    pub evidence_digest: Digest,
    pub receipts: Vec<OctopusReceipt>,
    pub provenance: TransportProvenance,
    pub redacted: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub raw_task_logs: bool,
    pub raw_scripts: bool,
    pub package_bytes: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl OctopusResultProjection {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration_digest: Digest,
        scope: OctopusScope,
        status: ProjectionStatus,
        completeness: ProjectionCompleteness,
        release_metadata_digest: Digest,
        deployment_process_metadata_digest: Digest,
        deployment_state_digest: Digest,
        task_state_digest: Digest,
        target_state_digest: Digest,
        receipts: Vec<OctopusReceipt>,
        provenance: TransportProvenance,
    ) -> Self {
        let mut projection = Self {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_api_revision: API_REVISION.to_owned(),
            provider_revision: PROVIDER_REVISION.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            registration_digest,
            scope_digest: scope.digest(),
            scope,
            status,
            completeness,
            release_metadata_digest,
            deployment_process_metadata_digest,
            deployment_state_digest,
            task_state_digest,
            target_state_digest,
            evidence_digest: Digest::from_text("unsealed-octopus-release-result").expect("digest"),
            receipts,
            provenance,
            redacted: true,
            connected: false,
            native: false,
            provider_receipt: false,
            raw_task_logs: false,
            raw_scripts: false,
            package_bytes: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        projection.evidence_digest = projection.calculate_digest();
        projection
    }

    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn is_review_only(&self) -> bool {
        true
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_api_revision != API_REVISION
            || self.provider_revision != PROVIDER_REVISION
            || self.plugin_version != PLUGIN_VERSION
            || self.scope_digest != self.scope.digest()
            || !self.redacted
            || self.connected
            || self.native
            || self.provider_receipt
            || self.raw_task_logs
            || self.raw_scripts
            || self.package_bytes
            || self.outcome_adopted
            || self.work_product_adopted
            || self.receipts.len() > MAX_RECEIPTS
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(OctopusReleaseResultError::TamperedEvidence);
        }
        self.scope.validate()?;
        self.contract_digest.validate()?;
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        self.release_metadata_digest.validate()?;
        self.deployment_process_metadata_digest.validate()?;
        self.deployment_state_digest.validate()?;
        self.task_state_digest.validate()?;
        self.target_state_digest.validate()?;
        self.evidence_digest.validate()?;
        for receipt in &self.receipts {
            receipt.validate()?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "octopus-release-result/projection/v1",
            [
                (
                    "contract".to_owned(),
                    self.contract_digest.as_str().to_owned(),
                ),
                ("provider".to_owned(), self.provider_id.clone()),
                (
                    "provider_revision".to_owned(),
                    self.provider_revision.clone(),
                ),
                (
                    "registration".to_owned(),
                    self.registration_digest.as_str().to_owned(),
                ),
                ("scope".to_owned(), self.scope_digest.as_str().to_owned()),
                ("status".to_owned(), self.status.as_str().to_owned()),
                (
                    "completeness".to_owned(),
                    format!("{:?}", self.completeness),
                ),
                (
                    "release".to_owned(),
                    self.release_metadata_digest.as_str().to_owned(),
                ),
                (
                    "process".to_owned(),
                    self.deployment_process_metadata_digest.as_str().to_owned(),
                ),
                (
                    "deployment".to_owned(),
                    self.deployment_state_digest.as_str().to_owned(),
                ),
                (
                    "task".to_owned(),
                    self.task_state_digest.as_str().to_owned(),
                ),
                (
                    "target".to_owned(),
                    self.target_state_digest.as_str().to_owned(),
                ),
                (
                    "receipts".to_owned(),
                    crate::digest_serialized(&self.receipts),
                ),
                ("provenance".to_owned(), self.provenance.as_str().to_owned()),
            ],
        )
    }
}

pub type OctopusReleaseResultProjection = OctopusResultProjection;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OctopusProviderState {
    Active,
    Revoked,
    Reversed,
    BlockedEnv,
    AccessLost,
}

enum FetchOutcome {
    Body(OctopusResponseBody),
    Status(ProjectionStatus),
}

/// Typed read provider bound to one exact registration. It never resolves the
/// opaque SecretReference and never emits a live/native transport.
#[derive(Clone, Debug)]
pub struct OctopusProvider<T>
where
    T: OctopusTransport,
{
    registration: OctopusRegistration,
    transport: T,
    state: OctopusProviderState,
}

impl<T> OctopusProvider<T>
where
    T: OctopusTransport,
{
    pub fn new(registration: OctopusRegistration, transport: T) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(match registration.status {
                crate::OctopusRegistrationStatus::Revoked => {
                    OctopusReleaseResultError::RegistrationRevoked
                }
                crate::OctopusRegistrationStatus::Reversed => {
                    OctopusReleaseResultError::RegistrationReversed
                }
                crate::OctopusRegistrationStatus::Active => {
                    OctopusReleaseResultError::InvalidRegistration
                }
            });
        }
        let state = if transport.provenance().is_blocked() {
            OctopusProviderState::BlockedEnv
        } else {
            OctopusProviderState::Active
        };
        Ok(Self {
            registration,
            transport,
            state,
        })
    }

    pub fn registration(&self) -> &OctopusRegistration {
        &self.registration
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub const fn state(&self) -> OctopusProviderState {
        self.state
    }

    pub fn revoke(&mut self) -> Result<()> {
        self.registration.revoke()?;
        self.state = OctopusProviderState::Revoked;
        Ok(())
    }

    pub fn reverse(&mut self) -> Result<()> {
        self.registration.reverse()?;
        self.state = OctopusProviderState::Reversed;
        Ok(())
    }

    pub fn read_result(&mut self) -> Result<OctopusResultProjection> {
        let request = OctopusReadRequest::new(self.registration.scope.clone())?;
        self.read_release_result(&request)
    }

    pub fn read_release_result(
        &mut self,
        request: &OctopusReadRequest,
    ) -> Result<OctopusResultProjection> {
        if request.scope != self.registration.scope {
            return Err(OctopusReleaseResultError::ScopeMismatch);
        }
        self.registration.validate()?;
        match self.state {
            OctopusProviderState::Revoked => {
                return Err(OctopusReleaseResultError::RegistrationRevoked);
            }
            OctopusProviderState::Reversed => {
                return Err(OctopusReleaseResultError::RegistrationReversed);
            }
            OctopusProviderState::BlockedEnv => {
                return Ok(self.fallback(ProjectionStatus::ProviderUnknown, Vec::new()));
            }
            OctopusProviderState::AccessLost => {
                return Ok(self.fallback(ProjectionStatus::AccessLost, Vec::new()));
            }
            OctopusProviderState::Active => {}
        }

        let mut receipts = Vec::with_capacity(MAX_RECEIPTS);
        let scope = &request.scope;

        let spaces = match self.fetch(
            OctopusEndpoint::Spaces {
                server: scope.server.origin.clone(),
            },
            &mut receipts,
            request.max_response_bytes,
        )? {
            FetchOutcome::Body(OctopusResponseBody::Spaces(values)) => values,
            FetchOutcome::Body(_) => {
                return Ok(self.fallback(ProjectionStatus::ProviderUnknown, receipts));
            }
            FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        validate_collection_len(&spaces)?;
        let Some(space) = spaces
            .iter()
            .find(|value| value.id == scope.space.id.as_str())
        else {
            return Ok(self.fallback(ProjectionStatus::ProviderUnknown, receipts));
        };
        validate_space(space)?;
        if space.revision != scope.space.revision {
            return Err(OctopusReleaseResultError::OutOfScope);
        }

        let projects = match self.fetch(
            OctopusEndpoint::Projects {
                server: scope.server.origin.clone(),
                space_id: scope.space.id.as_str().to_owned(),
            },
            &mut receipts,
            request.max_response_bytes,
        )? {
            FetchOutcome::Body(OctopusResponseBody::Projects(values)) => values,
            FetchOutcome::Body(_) => {
                return Ok(self.fallback(ProjectionStatus::ProviderUnknown, receipts));
            }
            FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        validate_collection_len(&projects)?;
        let Some(project) = projects
            .iter()
            .find(|value| value.id == scope.project.id.as_str())
        else {
            return Ok(self.fallback(ProjectionStatus::ProviderUnknown, receipts));
        };
        validate_project(project)?;
        if project.project_id_mismatch(scope) {
            return Err(OctopusReleaseResultError::OutOfScope);
        }

        let channels = match self.fetch(
            OctopusEndpoint::Channels {
                server: scope.server.origin.clone(),
                space_id: scope.space.id.as_str().to_owned(),
                project_id: scope.project.id.as_str().to_owned(),
            },
            &mut receipts,
            request.max_response_bytes,
        )? {
            FetchOutcome::Body(OctopusResponseBody::Channels(values)) => values,
            FetchOutcome::Body(_) => {
                return Ok(self.fallback(ProjectionStatus::ProviderUnknown, receipts));
            }
            FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        validate_collection_len(&channels)?;
        let Some(channel) = channels
            .iter()
            .find(|value| value.id == scope.channel.id.as_str())
        else {
            return Ok(self.fallback(ProjectionStatus::ProviderUnknown, receipts));
        };
        validate_channel(channel)?;
        if channel.project_id != scope.project.id.as_str()
            || channel.revision != scope.channel.revision
        {
            return Err(OctopusReleaseResultError::OutOfScope);
        }

        let environments = match self.fetch(
            OctopusEndpoint::Environments {
                server: scope.server.origin.clone(),
                space_id: scope.space.id.as_str().to_owned(),
            },
            &mut receipts,
            request.max_response_bytes,
        )? {
            FetchOutcome::Body(OctopusResponseBody::Environments(values)) => values,
            FetchOutcome::Body(_) => {
                return Ok(self.fallback(ProjectionStatus::ProviderUnknown, receipts));
            }
            FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        validate_collection_len(&environments)?;
        let Some(environment) = environments
            .iter()
            .find(|value| value.id == scope.environment.id.as_str())
        else {
            return Ok(self.fallback(ProjectionStatus::ProviderUnknown, receipts));
        };
        validate_environment(environment)?;
        if environment.revision != scope.environment.revision {
            return Err(OctopusReleaseResultError::OutOfScope);
        }

        if let Some(tenant_id) = &scope.tenant.id {
            let tenants = match self.fetch(
                OctopusEndpoint::Tenants {
                    server: scope.server.origin.clone(),
                    space_id: scope.space.id.as_str().to_owned(),
                },
                &mut receipts,
                request.max_response_bytes,
            )? {
                FetchOutcome::Body(OctopusResponseBody::Tenants(values)) => values,
                FetchOutcome::Body(_) => {
                    return Ok(self.fallback(ProjectionStatus::ProviderUnknown, receipts));
                }
                FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
            };
            validate_collection_len(&tenants)?;
            let Some(tenant) = tenants.iter().find(|value| value.id == tenant_id.as_str()) else {
                return Ok(self.fallback(ProjectionStatus::RetentionGap, receipts));
            };
            validate_tenant(tenant)?;
            if tenant.revision != scope.tenant.revision {
                return Err(OctopusReleaseResultError::OutOfScope);
            }
        }

        let release = match self.fetch(
            OctopusEndpoint::Release {
                server: scope.server.origin.clone(),
                space_id: scope.space.id.as_str().to_owned(),
                release_id: scope.release.id.as_str().to_owned(),
            },
            &mut receipts,
            request.max_response_bytes,
        )? {
            FetchOutcome::Body(OctopusResponseBody::Release(value)) => value,
            FetchOutcome::Body(_) => {
                return Ok(self.fallback(ProjectionStatus::ProviderUnknown, receipts));
            }
            FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        validate_release(&release)?;
        if release.id != scope.release.id.as_str()
            || release.project_id != scope.project.id.as_str()
            || release.channel_id != scope.channel.id.as_str()
            || release.version != scope.release.version.as_str()
            || release.revision != scope.release.revision
        {
            return Err(OctopusReleaseResultError::OutOfScope);
        }

        let process = match self.fetch(
            OctopusEndpoint::DeploymentProcess {
                server: scope.server.origin.clone(),
                space_id: scope.space.id.as_str().to_owned(),
                deployment_process_id: scope.project.deployment_process_id.as_str().to_owned(),
            },
            &mut receipts,
            request.max_response_bytes,
        )? {
            FetchOutcome::Body(OctopusResponseBody::DeploymentProcess(value)) => value,
            FetchOutcome::Body(_) => {
                return Ok(self.fallback(ProjectionStatus::ProviderUnknown, receipts));
            }
            FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        validate_process(&process)?;
        if process.id != scope.project.deployment_process_id.as_str()
            || process.project_id != scope.project.id.as_str()
        {
            return Err(OctopusReleaseResultError::OutOfScope);
        }

        let template = match self.fetch(
            OctopusEndpoint::DeploymentProcessTemplate {
                server: scope.server.origin.clone(),
                space_id: scope.space.id.as_str().to_owned(),
                deployment_process_id: scope.project.deployment_process_id.as_str().to_owned(),
                channel_id: scope.channel.id.as_str().to_owned(),
            },
            &mut receipts,
            request.max_response_bytes,
        )? {
            FetchOutcome::Body(OctopusResponseBody::DeploymentProcessTemplate(value)) => value,
            FetchOutcome::Body(_) => {
                return Ok(self.fallback(ProjectionStatus::ProviderUnknown, receipts));
            }
            FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        validate_template(&template)?;
        if template.process_id != scope.project.deployment_process_id.as_str()
            || template.project_id != scope.project.id.as_str()
            || template.channel_id != scope.channel.id.as_str()
        {
            return Err(OctopusReleaseResultError::OutOfScope);
        }

        let deployment = match self.fetch(
            OctopusEndpoint::Deployment {
                server: scope.server.origin.clone(),
                space_id: scope.space.id.as_str().to_owned(),
                deployment_id: scope.deployment.id.as_str().to_owned(),
            },
            &mut receipts,
            request.max_response_bytes,
        )? {
            FetchOutcome::Body(OctopusResponseBody::Deployment(value)) => value,
            FetchOutcome::Body(_) => {
                return Ok(self.fallback(ProjectionStatus::ProviderUnknown, receipts));
            }
            FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        validate_deployment(&deployment)?;
        if deployment.id != scope.deployment.id.as_str()
            || deployment.release_id != scope.release.id.as_str()
            || deployment.project_id != scope.project.id.as_str()
            || deployment.environment_id != scope.environment.id.as_str()
            || deployment.task_id != scope.deployment.task_id.as_str()
            || deployment.revision != scope.deployment.revision
            || deployment.tenant_id != scope.tenant.id.as_ref().map(ToString::to_string)
        {
            return Err(OctopusReleaseResultError::OutOfScope);
        }

        let task = match self.fetch(
            OctopusEndpoint::Task {
                server: scope.server.origin.clone(),
                task_id: scope.deployment.task_id.as_str().to_owned(),
            },
            &mut receipts,
            request.max_response_bytes,
        )? {
            FetchOutcome::Body(OctopusResponseBody::Task(value)) => value,
            FetchOutcome::Body(_) => {
                return Ok(self.fallback(ProjectionStatus::ProviderUnknown, receipts));
            }
            FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        validate_task(&task)?;
        if task.id != scope.deployment.task_id.as_str()
            || task.deployment_id != scope.deployment.id.as_str()
        {
            return Err(OctopusReleaseResultError::OutOfScope);
        }

        let deployment_status = parse_state(&task.state, task.finished_successfully);
        let mut status = deployment_status;
        let target_match = deployment
            .target_ids
            .iter()
            .any(|target| target == scope.target.id.as_str());
        let task_target_match = task
            .target_ids
            .iter()
            .any(|target| target == scope.target.id.as_str());
        if deployment.target_ids.is_empty()
            || task.target_ids.is_empty()
            || !target_match
            || !task_target_match
        {
            status = ProjectionStatus::Partial;
        }
        if status == ProjectionStatus::ProviderUnknown {
            return Ok(self.fallback(status, receipts));
        }
        let completeness = if status == ProjectionStatus::Partial {
            ProjectionCompleteness::Partial
        } else {
            ProjectionCompleteness::Complete
        };
        let release_metadata_digest = Digest::from_parts(
            "octopus-release-result/release-metadata/v1",
            [
                ("id".to_owned(), release.id),
                ("project".to_owned(), release.project_id),
                ("channel".to_owned(), release.channel_id),
                ("version".to_owned(), release.version),
                (
                    "selected_packages".to_owned(),
                    release.selected_package_count.to_string(),
                ),
                ("revision".to_owned(), release.revision.to_string()),
            ],
        );
        let process_digest = Digest::from_parts(
            "octopus-release-result/process-metadata/v1",
            [
                ("process".to_owned(), process.id),
                ("project".to_owned(), process.project_id),
                ("steps".to_owned(), process.step_count.to_string()),
                ("actions".to_owned(), process.action_count.to_string()),
                ("revision".to_owned(), process.revision.to_string()),
                ("template_channel".to_owned(), template.channel_id),
                (
                    "template_packages".to_owned(),
                    template.package_count.to_string(),
                ),
            ],
        );
        let deployment_digest = Digest::from_parts(
            "octopus-release-result/deployment-state/v1",
            [
                ("deployment".to_owned(), deployment.id),
                ("release".to_owned(), deployment.release_id),
                ("environment".to_owned(), deployment.environment_id),
                (
                    "tenant".to_owned(),
                    deployment.tenant_id.unwrap_or_default(),
                ),
                ("state".to_owned(), deployment.state),
                ("revision".to_owned(), deployment.revision.to_string()),
            ],
        );
        let task_digest = Digest::from_parts(
            "octopus-release-result/task-state/v1",
            [
                ("task".to_owned(), task.id),
                ("deployment".to_owned(), task.deployment_id),
                ("state".to_owned(), task.state),
                (
                    "finished_successfully".to_owned(),
                    task.finished_successfully
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                ("revision".to_owned(), task.revision.to_string()),
            ],
        );
        let target_digest = Digest::from_parts(
            "octopus-release-result/target-state/v1",
            [
                (
                    "deployment_targets".to_owned(),
                    crate::digest_serialized(&deployment.target_ids),
                ),
                (
                    "task_targets".to_owned(),
                    crate::digest_serialized(&task.target_ids),
                ),
                ("target".to_owned(), scope.target.id.as_str().to_owned()),
            ],
        );
        let projection = OctopusResultProjection::new(
            self.registration.registration_digest.clone(),
            scope.clone(),
            status,
            completeness,
            release_metadata_digest,
            process_digest,
            deployment_digest,
            task_digest,
            target_digest,
            receipts,
            self.transport.provenance(),
        );
        projection.validate_integrity()?;
        Ok(projection)
    }

    fn fetch(
        &mut self,
        endpoint: OctopusEndpoint,
        receipts: &mut Vec<OctopusReceipt>,
        max_response_bytes: usize,
    ) -> Result<FetchOutcome> {
        let request = OctopusHttpRequest::new(endpoint, max_response_bytes)?;
        let response = match self.transport.get(&request) {
            Ok(response) => response,
            Err(error) => {
                let status = match error {
                    OctopusTransportError::BlockedEnv
                    | OctopusTransportError::FixtureMissing
                    | OctopusTransportError::Timeout
                    | OctopusTransportError::ServerStatus { .. } => {
                        if matches!(error, OctopusTransportError::BlockedEnv) {
                            self.state = OctopusProviderState::BlockedEnv;
                        }
                        ProjectionStatus::ProviderUnknown
                    }
                    OctopusTransportError::AccessLost => {
                        self.state = OctopusProviderState::AccessLost;
                        ProjectionStatus::AccessLost
                    }
                    OctopusTransportError::ResponseTooLarge => {
                        return Err(OctopusReleaseResultError::ResponseTooLarge);
                    }
                    OctopusTransportError::InvalidEndpoint
                    | OctopusTransportError::MalformedResponse => {
                        return Err(OctopusReleaseResultError::Transport(error));
                    }
                };
                return Ok(FetchOutcome::Status(status));
            }
        };
        response.receipt.validate()?;
        if response.receipt.provenance != self.transport.provenance()
            || response.receipt.method != "GET"
        {
            return Err(OctopusReleaseResultError::TamperedEvidence);
        }
        if receipts.len() >= MAX_RECEIPTS {
            return Err(OctopusReleaseResultError::PaginationLimit);
        }
        receipts.push(response.receipt.clone());
        if !(200..300).contains(&response.status) {
            return Ok(FetchOutcome::Status(match response.status {
                401 | 403 => {
                    self.state = OctopusProviderState::AccessLost;
                    ProjectionStatus::AccessLost
                }
                404 => ProjectionStatus::RetentionGap,
                409 => ProjectionStatus::Partial,
                429 | 500..=599 => ProjectionStatus::ProviderUnknown,
                _ => ProjectionStatus::ProviderUnknown,
            }));
        }
        let Some(body) = response.body else {
            return Ok(FetchOutcome::Status(ProjectionStatus::ProviderUnknown));
        };
        Ok(FetchOutcome::Body(body))
    }

    fn fallback(
        &self,
        status: ProjectionStatus,
        receipts: Vec<OctopusReceipt>,
    ) -> OctopusResultProjection {
        let unavailable = |label: &str| Digest::from_text(label).expect("digest");
        OctopusResultProjection::new(
            self.registration.registration_digest.clone(),
            self.registration.scope.clone(),
            status,
            ProjectionCompleteness::Partial,
            unavailable("octopus-release-result/retention-gap/release"),
            unavailable("octopus-release-result/retention-gap/process"),
            unavailable("octopus-release-result/retention-gap/deployment"),
            unavailable("octopus-release-result/retention-gap/task"),
            unavailable("octopus-release-result/retention-gap/target"),
            receipts,
            self.transport.provenance(),
        )
    }
}

fn validate_space(value: &SpacePayload) -> Result<()> {
    validate_payload_identifier(&value.id, "space id")?;
    validate_payload_name(&value.name, "space name")?;
    if value.revision == 0 {
        return Err(OctopusReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn validate_project(value: &ProjectPayload) -> Result<()> {
    validate_payload_identifier(&value.id, "project id")?;
    validate_payload_name(&value.name, "project name")?;
    validate_payload_identifier(&value.deployment_process_id, "deployment process id")?;
    if value.revision == 0 {
        return Err(OctopusReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

impl ProjectPayload {
    fn project_id_mismatch(&self, scope: &OctopusScope) -> bool {
        self.deployment_process_id != scope.project.deployment_process_id.as_str()
            || self.revision != scope.project.revision
    }
}

fn validate_channel(value: &ChannelPayload) -> Result<()> {
    validate_payload_identifier(&value.id, "channel id")?;
    validate_payload_identifier(&value.project_id, "channel project id")?;
    validate_payload_name(&value.name, "channel name")?;
    if value.revision == 0 {
        return Err(OctopusReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn validate_environment(value: &EnvironmentPayload) -> Result<()> {
    validate_payload_identifier(&value.id, "environment id")?;
    validate_payload_name(&value.name, "environment name")?;
    if value.revision == 0 {
        return Err(OctopusReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn validate_tenant(value: &TenantPayload) -> Result<()> {
    validate_payload_identifier(&value.id, "tenant id")?;
    validate_payload_name(&value.name, "tenant name")?;
    if value.revision == 0 {
        return Err(OctopusReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn validate_release(value: &ReleasePayload) -> Result<()> {
    validate_payload_identifier(&value.id, "release id")?;
    validate_payload_identifier(&value.project_id, "release project id")?;
    validate_payload_identifier(&value.channel_id, "release channel id")?;
    validate_payload_identifier(&value.version, "release version")?;
    if value.revision == 0 || value.selected_package_count > MAX_ITEMS_PER_COLLECTION {
        return Err(OctopusReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn validate_process(value: &DeploymentProcessPayload) -> Result<()> {
    validate_payload_identifier(&value.id, "deployment process id")?;
    validate_payload_identifier(&value.project_id, "deployment process project id")?;
    if value.revision == 0
        || value.step_count > MAX_ITEMS_PER_COLLECTION
        || value.action_count > MAX_ITEMS_PER_COLLECTION
    {
        return Err(OctopusReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn validate_template(value: &DeploymentProcessTemplatePayload) -> Result<()> {
    validate_payload_identifier(&value.process_id, "template process id")?;
    validate_payload_identifier(&value.project_id, "template project id")?;
    validate_payload_identifier(&value.channel_id, "template channel id")?;
    if value.revision == 0 || value.package_count > MAX_ITEMS_PER_COLLECTION {
        return Err(OctopusReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn validate_deployment(value: &DeploymentPayload) -> Result<()> {
    validate_payload_identifier(&value.id, "deployment id")?;
    validate_payload_identifier(&value.release_id, "deployment release id")?;
    validate_payload_identifier(&value.project_id, "deployment project id")?;
    validate_payload_identifier(&value.environment_id, "deployment environment id")?;
    if let Some(tenant_id) = &value.tenant_id {
        validate_payload_identifier(tenant_id, "deployment tenant id")?;
    }
    validate_payload_identifier(&value.task_id, "deployment task id")?;
    validate_payload_state(&value.state)?;
    validate_targets(&value.target_ids)?;
    if value.revision == 0 {
        return Err(OctopusReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn validate_task(value: &TaskPayload) -> Result<()> {
    validate_payload_identifier(&value.id, "task id")?;
    validate_payload_identifier(&value.deployment_id, "task deployment id")?;
    validate_payload_state(&value.state)?;
    validate_targets(&value.target_ids)?;
    if value.revision == 0 {
        return Err(OctopusReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn parse_state(value: &str, finished_successfully: Option<bool>) -> ProjectionStatus {
    let state = value.to_ascii_lowercase();
    match state.as_str() {
        "queued" | "pending" | "waiting" | "dequeued" => ProjectionStatus::Queued,
        "running" | "executing" | "started" => ProjectionStatus::Running,
        "succeeded" | "success" | "successful" | "completed" => {
            if finished_successfully == Some(false) {
                ProjectionStatus::Failed
            } else {
                ProjectionStatus::Succeeded
            }
        }
        "failed" | "failure" | "errored" | "error" => ProjectionStatus::Failed,
        "canceled" | "cancelled" => ProjectionStatus::Canceled,
        "paused" | "pausing" => ProjectionStatus::Paused,
        "partial" | "partially_succeeded" | "partially-succeeded" => ProjectionStatus::Partial,
        _ => ProjectionStatus::ProviderUnknown,
    }
}
