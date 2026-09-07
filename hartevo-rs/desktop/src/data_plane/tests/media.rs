use super::super::media::{DesktopMediaConfiguration, DesktopMediaRequest};
use super::*;
use hartevo_application::media_provider::{
    MediaConnection, MediaProviderError, MediaProviderOutput, MediaTransport, inspect_media,
};
use hartevo_domain_kernel::media_generation::{
    MediaGeneration, MediaGenerationRequest, MediaGenerationState, MediaKind, MediaProvider,
};

#[derive(Default)]
struct Transport {
    posts: std::sync::atomic::AtomicUsize,
    gets: std::sync::atomic::AtomicUsize,
    pending: bool,
}

impl MediaTransport for Transport {
    fn submit(
        &self,
        _: &MediaGenerationRequest,
    ) -> Result<MediaProviderOutput, MediaProviderError> {
        self.posts.fetch_add(1, Ordering::SeqCst);
        if self.pending {
            return Ok(MediaProviderOutput::Pending("original-provider-job".into()));
        }
        let bytes = include_bytes!("fixtures/media-square.png").to_vec();
        Ok(MediaProviderOutput::Asset {
            metadata: inspect_media(&bytes, MediaKind::Image).unwrap(),
            bytes,
        })
    }
    fn poll(&self, job: &MediaGeneration) -> Result<MediaProviderOutput, MediaProviderError> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            job.provider_request_id.as_deref(),
            Some("original-provider-job")
        );
        Err(MediaProviderError {
            code: "MEDIA_TRANSPORT_UNCERTAIN",
        })
    }
}

fn service(plane: &DesktopDataPlane, secrets: &impl SecretStore) -> ApplicationService {
    plane
        .open_read_application_from_secret(&secrets.get(plane.database_key_reference()).unwrap())
        .unwrap()
}

fn scope(plane: &DesktopDataPlane, secrets: &impl SecretStore, project: &ProjectId) -> Mission {
    let application = service(plane, secrets);
    let inventory = application.desktop_inventory().unwrap();
    let id = &inventory
        .projects
        .iter()
        .find(|p| p.project_id == *project)
        .unwrap()
        .missions[0]
        .mission_id;
    application.load_mission(project, id).unwrap()
}

fn request(mission: &Mission, id: &str, parent: Option<&str>) -> DesktopMediaRequest {
    DesktopMediaRequest {
        id: id.into(),
        project_id: mission.project_id.clone(),
        mission_id: mission.id.clone(),
        expected_mission_revision: mission.revision,
        kind: MediaKind::Image,
        provider: MediaProvider::Grok,
        prompt: format!("Synthetic media fixture {id}"),
        revises_job_id: parent.map(str::to_owned),
    }
}

fn configuration() -> DesktopMediaConfiguration {
    DesktopMediaConfiguration {
        connection: MediaConnection::new("https://media.example.com", "MEDIA_TEST_KEY").unwrap(),
        model: "grok-imagine-image-2.0".into(),
    }
}

#[test]
fn media_desktop_requires_live_context_and_adopts_only_the_exact_preview() {
    let (_dir, plane, secrets, project) = ready_personal_fixture();
    let transport = Transport::default();
    let config = configuration();
    let first_request = request(&scope(&plane, &secrets, &project), "initial", None);
    assert!(
        plane
            .media_generate_with(
                &MemorySecretStore::default(),
                first_request.clone(),
                &config,
                &transport
            )
            .is_err()
    );
    let mut foreign = first_request.clone();
    foreign.mission_id = MissionId::from("foreign");
    assert!(
        plane
            .media_generate_with(&secrets, foreign, &config, &transport)
            .is_err()
    );
    assert_eq!(transport.posts.load(Ordering::SeqCst), 0);
    let first = plane
        .media_generate_with(&secrets, first_request.clone(), &config, &transport)
        .unwrap();
    assert_eq!(first.state, MediaGenerationState::Ready);
    assert_eq!(
        plane
            .media_generate_with(&secrets, first_request, &config, &transport)
            .unwrap(),
        first
    );
    let revised = plane
        .media_generate_with(
            &secrets,
            request(
                &scope(&plane, &secrets, &project),
                "revised",
                Some("initial"),
            ),
            &config,
            &transport,
        )
        .unwrap();
    assert_eq!(transport.posts.load(Ordering::SeqCst), 2);
    let mission = scope(&plane, &secrets, &project);
    let product = mission
        .work_products
        .iter()
        .find(|p| p.id == revised.work_product_id)
        .unwrap();
    let manifest = service(&plane, &secrets)
        .load_work_product_manifest(&project, &revised.work_product_id)
        .unwrap();
    let adoption = DesktopWorkProductAdoptionRequest {
        project_id: project.clone(),
        mission_id: mission.id.clone(),
        work_product_id: product.id.clone(),
        expected_mission_revision: mission.revision,
        expected_work_product_revision: product.revision,
        expected_manifest_version: manifest.version,
    };
    assert!(
        plane
            .media_adopt_with(&secrets, "initial", adoption.clone())
            .is_err()
    );
    assert!(
        plane
            .adopt_work_product_with(&secrets, adoption.clone(), Utc::now())
            .is_err(),
        "generic text adoption cannot bypass media review"
    );
    plane
        .media_adopt_with(&secrets, "revised", adoption)
        .unwrap();
    let final_mission = scope(&plane, &secrets, &project);
    assert_eq!(
        final_mission.work_products[0].status,
        hartevo_domain_kernel::WorkProductStatus::Accepted
    );
    assert!(final_mission.effects.is_empty());
    assert_eq!(transport.posts.load(Ordering::SeqCst), 2);
}

#[test]
fn media_desktop_video_recovers_the_same_job_with_get_only_after_restart() {
    let (_dir, plane, secrets, project) = ready_personal_fixture();
    let transport = Transport {
        pending: true,
        ..Transport::default()
    };
    let mut req = request(&scope(&plane, &secrets, &project), "video", None);
    req.kind = MediaKind::Video;
    let config = DesktopMediaConfiguration {
        model: "grok-imagine-video-1.5".into(),
        ..configuration()
    };
    let job = plane
        .media_generate_with(&secrets, req.clone(), &config, &transport)
        .unwrap();
    let root = plane.data_root().to_path_buf();
    drop(plane);
    let cold = DesktopDataPlane::at_data_root(root).unwrap();
    assert!(matches!(
        cold.load_with(&secrets, Utc::now()).unwrap(),
        DesktopLoadState::Ready(_)
    ));
    assert_eq!(
        cold.media_generate_with(&secrets, req, &config, &transport)
            .unwrap(),
        job
    );
    for _ in 0..2 {
        assert!(
            cold.media_poll_with(
                &secrets,
                &project,
                &job.request.mission_id,
                &job.request.id,
                &transport
            )
            .is_err()
        );
    }
    let recovered = service(&cold, &secrets)
        .media_generation(&project, &job.request.mission_id, &job.request.id)
        .unwrap();
    assert_eq!(recovered, job);
    assert_eq!(transport.posts.load(Ordering::SeqCst), 1);
    assert_eq!(transport.gets.load(Ordering::SeqCst), 2);
}

struct RevokingTransport<'a> {
    secrets: &'a MemorySecretStore,
    reference: SecretReference,
    inner: Transport,
}

impl MediaTransport for RevokingTransport<'_> {
    fn submit(
        &self,
        request: &MediaGenerationRequest,
    ) -> Result<MediaProviderOutput, MediaProviderError> {
        self.secrets.delete(&self.reference).unwrap();
        self.inner.submit(request)
    }
    fn poll(&self, job: &MediaGeneration) -> Result<MediaProviderOutput, MediaProviderError> {
        self.inner.poll(job)
    }
}

#[test]
fn media_desktop_revoked_context_drains_receipts_and_quarantines_returned_assets() {
    for pending in [true, false] {
        let (_dir, plane, secrets, project) = ready_personal_fixture();
        let mission = scope(&plane, &secrets, &project);
        let keyring = service(&plane, &secrets)
            .load_project_keyring(&project)
            .unwrap();
        let envelope = keyring
            .envelopes
            .iter()
            .find(|e| {
                e.key_version == keyring.active_key_version
                    && e.recipient == KeyRecipient::Device(plane.device_id.clone())
            })
            .unwrap();
        let reference = SecretReference {
            tenant_id: mission.tenant_id.clone(),
            project_id: project.clone(),
            provider: "os-native".into(),
            account_scope: envelope.recipient.stable_scope(),
            purpose: format!("project_wrapping_key:{}", envelope.id),
            version: envelope.key_version,
        };
        let saved_key = secrets.get(&reference).unwrap();
        let transport = RevokingTransport {
            secrets: &secrets,
            reference: reference.clone(),
            inner: Transport {
                pending,
                ..Transport::default()
            },
        };
        let mut req = request(&mission, "revoked", None);
        let mut config = configuration();
        if pending {
            req.kind = MediaKind::Video;
            config.model = "grok-imagine-video-1.5".into();
        }
        assert!(
            plane
                .media_generate_with(&secrets, req.clone(), &config, &transport)
                .is_err()
        );
        let persisted = service(&plane, &secrets)
            .media_generation(&project, &mission.id, "revoked")
            .unwrap();
        assert_eq!(
            persisted.state,
            if pending {
                MediaGenerationState::Submitted
            } else {
                MediaGenerationState::Rejected
            }
        );
        assert!(scope(&plane, &secrets, &project).work_products.is_empty());
        assert!(
            plane
                .media_generate_with(&secrets, req.clone(), &config, &transport)
                .is_err()
        );
        secrets.put(&reference, &saved_key).unwrap();
        let root = plane.data_root().to_path_buf();
        drop(plane);
        let cold = DesktopDataPlane::at_data_root(root).unwrap();
        assert!(matches!(
            cold.load_with(&secrets, Utc::now()).unwrap(),
            DesktopLoadState::Ready(_)
        ));
        assert_eq!(
            cold.media_generate_with(&secrets, req, &config, &transport)
                .unwrap(),
            persisted
        );
        if pending {
            assert!(
                cold.media_poll_with(&secrets, &project, &mission.id, "revoked", &transport)
                    .is_err()
            );
            assert_eq!(transport.inner.gets.load(Ordering::SeqCst), 1);
        } else {
            let (job, bytes) = service(&cold, &secrets)
                .media_generation_bytes(&project, &mission.id, "revoked")
                .unwrap();
            assert_eq!(job.failure_code.as_deref(), Some("MEDIA_CONTEXT_REVOKED"));
            assert_eq!(bytes, include_bytes!("fixtures/media-square.png"));
        }
        assert_eq!(transport.inner.posts.load(Ordering::SeqCst), 1);
    }
}

#[test]
#[ignore = "creates a private OS-vault fixture; use run-native-media-workspace.py prepare"]
fn live_media_prepare_desktop() {
    assert_eq!(std::env::var("HARTEVO_LIVE_MEDIA_UI").as_deref(), Ok("1"));
    let plane = DesktopDataPlane::persistent().unwrap();
    assert!(
        !plane.database_path.exists(),
        "prepare requires a new private data directory"
    );
    plane.initialize_os(Utc::now()).unwrap();
    let recovery = RecoveryKitDraft::generate().unwrap();
    let output = PathBuf::from(std::env::var_os("HARTEVO_LIVE_OUTPUT").unwrap());
    std::fs::write(
        output.join("recovery.txt"),
        recovery.expose_for_user_export(),
    )
    .unwrap();
    let snapshot = plane
        .create_personal_project_os(
            "NORDLICHT 创意验证",
            "为虚构水瓶品牌准备社交媒体创意素材；检查画面后采用，不发布到外部渠道。",
            recovery.expose_for_user_export(),
            Utc::now(),
        )
        .unwrap();
    let project = &snapshot.inventory.projects[0];
    std::fs::write(output.join("scope.json"),serde_json::to_vec_pretty(&serde_json::json!({"projectId":project.project_id,"missionId":project.missions[0].mission_id})).unwrap()).unwrap();
}

#[test]
#[ignore = "read-only receipts from the private native media window; use run-native-media-workspace.py inspect"]
fn live_media_inspect_desktop() {
    assert_eq!(std::env::var("HARTEVO_LIVE_MEDIA_UI").as_deref(), Ok("1"));
    let plane = DesktopDataPlane::persistent().unwrap();
    let output = PathBuf::from(std::env::var_os("HARTEVO_LIVE_OUTPUT").unwrap());
    let scope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("scope.json")).unwrap()).unwrap();
    let project = ProjectId::from(scope["projectId"].as_str().unwrap());
    let mission_id = MissionId::from(scope["missionId"].as_str().unwrap());
    let secrets = OsSecretStore::new(OS_SECRET_SERVICE).unwrap();
    let service = service(&plane, &secrets);
    let mission = service.load_mission(&project, &mission_id).unwrap();
    let jobs = service.media_generations(&project, &mission_id).unwrap();
    let mut receipts = Vec::new();
    for job in jobs {
        if let Some(asset) = &job.asset {
            let (_, bytes) = service
                .media_generation_bytes(&project, &mission_id, &job.request.id)
                .unwrap();
            let extension = match asset.media_type.as_str() {
                "image/png" => "png",
                "image/jpeg" => "jpg",
                "video/mp4" => "mp4",
                _ => panic!("unsupported asset"),
            };
            std::fs::write(
                output.join(format!("{}.{}", job.request.id, extension)),
                bytes,
            )
            .unwrap();
        }
        let product = mission
            .work_products
            .iter()
            .find(|p| p.id == job.work_product_id);
        let manifest =
            product.map(|p| service.load_work_product_manifest(&project, &p.id).unwrap());
        receipts.push(serde_json::json!({"generationId":job.request.id,"kind":job.request.kind,"provider":job.request.provider,"model":job.request.model,
            "state":job.state,"revisesGenerationId":job.request.revises_job_id,"asset":job.asset,"failureCode":job.failure_code,
            "hasProviderRequestId":job.provider_request_id.is_some(),"currentManifestVersion":manifest.as_ref().map(|m|m.version),
            "isCurrentAsset":manifest.as_ref().is_some_and(|m|m.file_digest.as_ref() == job.asset.as_ref().map(|a|&a.sha256)),
            "currentWorkProductStatus":product.map(|p|&p.status)}));
    }
    assert!(
        mission.effects.is_empty(),
        "creative adoption must not publish"
    );
    std::fs::write(output.join("media-receipts.json"),serde_json::to_vec_pretty(&serde_json::json!({"schemaVersion":"hartevo-native-media-receipts/v1","missionStage":mission.stage,"externalEffects":0,"jobs":receipts})).unwrap()).unwrap();
}
