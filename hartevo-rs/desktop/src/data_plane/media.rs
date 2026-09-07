//! Media actions reuse the current encrypted Project context and Application.
use super::{
    ApplicationService, DateTime, DesktopDataError, DesktopDataPlane, DesktopSnapshot,
    DesktopWorkProductAdoptionRequest, MissionId, OS_SECRET_SERVICE, OsSecretStore, ProjectId,
    SecretStore, Utc,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hartevo_application::media_generation::MediaApplicationError;
use hartevo_application::media_provider::{
    MediaConnection, MediaProviderOutput, MediaTransport, NativeMediaTransport,
};
use hartevo_domain_kernel::media_generation::{
    MediaGeneration, MediaGenerationRequest, MediaGenerationState, MediaKind, MediaProvider,
};

#[derive(Clone)]
pub struct DesktopMediaRequest {
    pub id: String,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub expected_mission_revision: u64,
    pub kind: MediaKind,
    pub provider: MediaProvider,
    pub prompt: String,
    pub revises_job_id: Option<String>,
}

impl std::fmt::Debug for DesktopMediaRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DesktopMediaRequest")
            .field("kind", &self.kind)
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct DesktopMediaConfiguration {
    pub connection: MediaConnection,
    pub model: String,
}

impl DesktopMediaConfiguration {
    pub fn discover(kind: MediaKind, provider: MediaProvider) -> Result<Self, DesktopDataError> {
        let base = std::env::var("HARTEVO_MEDIA_API_BASE")
            .or_else(|_| std::env::var("HARTEVO_RUNTIME_API_BASE"))
            .map_err(|_| DesktopDataError::Media("MEDIA_CONFIG_REQUIRED".into()))?;
        let (key_setting, key_default, model_setting, model_default) = match (kind, provider) {
            (MediaKind::Image, MediaProvider::OpenAi) => (
                "HARTEVO_MEDIA_GPT_KEY_ENV",
                "HARTEVO_GPT_API_KEY",
                "HARTEVO_MEDIA_GPT_IMAGE_MODEL",
                "gpt-image-2",
            ),
            (MediaKind::Image, MediaProvider::Grok) => (
                "HARTEVO_MEDIA_GROK_KEY_ENV",
                "HARTEVO_GROK_API_KEY",
                "HARTEVO_MEDIA_GROK_IMAGE_MODEL",
                "grok-imagine-image-2.0",
            ),
            (MediaKind::Video, MediaProvider::Grok) => (
                "HARTEVO_MEDIA_GROK_KEY_ENV",
                "HARTEVO_GROK_API_KEY",
                "HARTEVO_MEDIA_GROK_VIDEO_MODEL",
                "grok-imagine-video-1.5",
            ),
            _ => return Err(DesktopDataError::Media("MEDIA_MODEL_UNSUPPORTED".into())),
        };
        let key_env = std::env::var(key_setting).unwrap_or_else(|_| key_default.into());
        let connection = MediaConnection::new(&base, &key_env)
            .map_err(|e| DesktopDataError::Media(e.code.into()))?;
        if !connection.is_configured() {
            return Err(DesktopDataError::Media("MEDIA_CREDENTIAL_MISSING".into()));
        }
        Ok(Self {
            connection,
            model: std::env::var(model_setting).unwrap_or_else(|_| model_default.into()),
        })
    }
}

impl From<MediaApplicationError> for DesktopDataError {
    fn from(error: MediaApplicationError) -> Self {
        match error {
            MediaApplicationError::Application(error) => Self::Application(error),
            MediaApplicationError::Storage(_) => Self::Media("MEDIA_PERSISTENCE_ERROR".into()),
            other => Self::Media(other.to_string()),
        }
    }
}

impl DesktopDataPlane {
    fn media_service(
        &self,
        secrets: &impl SecretStore,
        project: &ProjectId,
        now: DateTime<Utc>,
    ) -> Result<ApplicationService, DesktopDataError> {
        let secret = self.database_secret(secrets)?;
        let service = self.open_read_application_from_secret(&secret)?;
        self.require_project_context_access(&service, secrets, project, now)?;
        Ok(service)
    }

    pub fn media_generate_os(
        &self,
        request: DesktopMediaRequest,
    ) -> Result<MediaGeneration, DesktopDataError> {
        let secrets = OsSecretStore::new(OS_SECRET_SERVICE)?;
        let config = DesktopMediaConfiguration::discover(request.kind, request.provider)?;
        let transport = NativeMediaTransport {
            connection: config.connection.clone(),
        };
        self.media_generate_with(&secrets, request, &config, &transport)
    }

    pub(super) fn media_generate_with(
        &self,
        secrets: &impl SecretStore,
        request: DesktopMediaRequest,
        config: &DesktopMediaConfiguration,
        transport: &impl MediaTransport,
    ) -> Result<MediaGeneration, DesktopDataError> {
        let mut service = self.media_service(secrets, &request.project_id, Utc::now())?;
        let request = MediaGenerationRequest {
            id: request.id,
            project_id: request.project_id,
            mission_id: request.mission_id,
            expected_mission_revision: request.expected_mission_revision,
            kind: request.kind,
            provider: request.provider,
            model: config.model.clone(),
            endpoint_digest: config.connection.digest(),
            prompt: request.prompt,
            revises_job_id: request.revises_job_id,
        };
        let (job, is_new) = service.begin_media_generation(request, Utc::now())?;
        if !is_new {
            return Ok(job);
        }
        let output = transport.submit(&job.request);
        // Retain the authorized connection to drain the original receipt even
        // if access changes during the network call. No second POST is granted.
        if let Err(access_error) = self.require_project_context_access(
            &service,
            secrets,
            &job.request.project_id,
            Utc::now(),
        ) {
            match output {
                Ok(output) => Self::quarantine_media_output(&mut service, &job, output)?,
                Err(error) => {
                    service.record_media_failure(&job, true, error.code, Utc::now())?;
                }
            }
            return Err(access_error);
        }
        match output {
            Ok(output) => Self::commit_media_output(&mut service, &job, output),
            Err(error) => Ok(service.record_media_failure(&job, true, error.code, Utc::now())?),
        }
    }

    pub fn media_poll_os(
        &self,
        project: &ProjectId,
        mission: &MissionId,
        id: &str,
    ) -> Result<MediaGeneration, DesktopDataError> {
        let secrets = OsSecretStore::new(OS_SECRET_SERVICE)?;
        let service = self.media_service(&secrets, project, Utc::now())?;
        let job = service.media_generation(project, mission, id)?;
        let config = DesktopMediaConfiguration::discover(job.request.kind, job.request.provider)?;
        self.media_poll_with(
            &secrets,
            project,
            mission,
            id,
            &NativeMediaTransport {
                connection: config.connection,
            },
        )
    }

    pub(super) fn media_poll_with(
        &self,
        secrets: &impl SecretStore,
        project: &ProjectId,
        mission: &MissionId,
        id: &str,
        transport: &impl MediaTransport,
    ) -> Result<MediaGeneration, DesktopDataError> {
        let mut service = self.media_service(secrets, project, Utc::now())?;
        let job = service.media_generation(project, mission, id)?;
        if job.state != MediaGenerationState::Submitted {
            return Ok(job);
        }
        // GET only. Transient poll/download failures preserve the original job.
        let output = transport
            .poll(&job)
            .map_err(|e| DesktopDataError::Media(e.code.into()))?;
        if let Err(access_error) =
            self.require_project_context_access(&service, secrets, project, Utc::now())
        {
            Self::quarantine_media_output(&mut service, &job, output)?;
            return Err(access_error);
        }
        Self::commit_media_output(&mut service, &job, output)
    }

    fn quarantine_media_output(
        service: &mut ApplicationService,
        job: &MediaGeneration,
        output: MediaProviderOutput,
    ) -> Result<(), DesktopDataError> {
        match output {
            MediaProviderOutput::Asset { metadata, bytes } => {
                service.quarantine_media_generation(job, metadata, &bytes, Utc::now())?;
            }
            other => {
                Self::commit_media_output(service, job, other)?;
            }
        }
        Ok(())
    }

    fn commit_media_output(
        service: &mut ApplicationService,
        job: &MediaGeneration,
        output: MediaProviderOutput,
    ) -> Result<MediaGeneration, DesktopDataError> {
        Ok(match output {
            MediaProviderOutput::Pending(id) => {
                service.record_media_submission(job, id, Utc::now())?
            }
            MediaProviderOutput::Asset { metadata, bytes } => {
                service.complete_media_generation(job, metadata, &bytes, Utc::now())?
            }
            MediaProviderOutput::Waiting => job.clone(),
            MediaProviderOutput::Failed(code) => {
                service.record_media_failure(job, false, code, Utc::now())?
            }
        })
    }

    pub fn media_jobs_os(
        &self,
        project: &ProjectId,
        mission: &MissionId,
    ) -> Result<Vec<MediaGeneration>, DesktopDataError> {
        let secrets = OsSecretStore::new(OS_SECRET_SERVICE)?;
        Ok(self
            .media_service(&secrets, project, Utc::now())?
            .media_generations(project, mission)?)
    }

    pub(crate) fn media_job_os(
        &self,
        project: &ProjectId,
        mission: &MissionId,
        id: &str,
    ) -> Result<MediaGeneration, DesktopDataError> {
        let secrets = OsSecretStore::new(OS_SECRET_SERVICE)?;
        Ok(self
            .media_service(&secrets, project, Utc::now())?
            .media_generation(project, mission, id)?)
    }

    pub fn media_adopt_os(
        &self,
        id: &str,
        request: DesktopWorkProductAdoptionRequest,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let secrets = OsSecretStore::new(OS_SECRET_SERVICE)?;
        self.media_adopt_with(&secrets, id, request)
    }

    pub(super) fn media_adopt_with(
        &self,
        secrets: &impl SecretStore,
        id: &str,
        request: DesktopWorkProductAdoptionRequest,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        self.adopt_work_product_or_media_with(secrets, request, Utc::now(), Some(id))
    }

    pub fn media_preview_os(
        &self,
        project: &ProjectId,
        mission: &MissionId,
        id: &str,
    ) -> Result<String, DesktopDataError> {
        let secrets = OsSecretStore::new(OS_SECRET_SERVICE)?;
        let (job, bytes) = self
            .media_service(&secrets, project, Utc::now())?
            .media_generation_bytes(project, mission, id)?;
        let metadata = job
            .asset
            .ok_or_else(|| DesktopDataError::Media("MEDIA_ASSET_MISSING".into()))?;
        Ok(format!(
            "data:{};base64,{}",
            metadata.media_type,
            STANDARD.encode(bytes)
        ))
    }
}
