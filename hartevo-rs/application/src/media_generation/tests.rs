use super::*;
use crate::media_provider::inspect_media;
use crate::{AcceptWorkProduct, CreateProject, ResearchPacket, StartMission};
use hartevo_domain_kernel::media_generation::MediaProvider;
use hartevo_domain_kernel::{MissionTerminalDisposition, StorageMode, TaskId, TenantId};
use hartevo_storage::{DatabaseKey, PendingEvent, ProjectStore};
use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
use std::{io::Cursor, path::Path};

fn open(root: &Path) -> ApplicationService {
    ApplicationService::new(
        ProjectStore::open(&root.join("media.db"), &DatabaseKey::new([23; 32]).unwrap()).unwrap(),
    )
}

fn fixture() -> (tempfile::TempDir, ApplicationService) {
    let dir = tempfile::tempdir().unwrap();
    let mut service = open(dir.path());
    service
        .create_project(
            CreateProject {
                tenant_id: TenantId::from("media-tenant"),
                id: ProjectId::from("media-project"),
                name: "Creative fixture".into(),
                description: "Synthetic product campaign".into(),
                workspace_root: dir.path().into(),
                storage_mode: StorageMode::LocalNew,
            },
            Utc::now(),
        )
        .unwrap();
    service
        .start_mission(
            StartMission {
                id: MissionId::from("media-mission"),
                research_task_id: TaskId::from("media-task"),
                project_id: ProjectId::from("media-project"),
                title: Some("Creative campaign".into()),
                prompt: "Create fictional reusable bottle campaign assets".into(),
            },
            Utc::now(),
        )
        .unwrap();
    (dir, service)
}

fn request(service: &ApplicationService, id: &str, parent: Option<&str>) -> MediaGenerationRequest {
    let mission = service
        .load_mission(
            &ProjectId::from("media-project"),
            &MissionId::from("media-mission"),
        )
        .unwrap();
    MediaGenerationRequest {
        id: id.into(),
        project_id: mission.project_id,
        mission_id: mission.id,
        expected_mission_revision: mission.revision,
        kind: MediaKind::Image,
        provider: MediaProvider::Grok,
        model: "grok-imagine-image-2.0".into(),
        endpoint_digest: "a".repeat(64),
        prompt: format!("Private synthetic creative description {id}"),
        revises_job_id: parent.map(str::to_owned),
    }
}

pub(super) fn png(width: u32, height: u32, color: u8) -> (MediaAssetMetadata, Vec<u8>) {
    let img = DynamicImage::ImageRgb8(RgbImage::from_pixel(width, height, Rgb([color, 120, 60])));
    let mut out = Cursor::new(Vec::new());
    img.write_to(&mut out, ImageFormat::Png).unwrap();
    let bytes = out.into_inner();
    (inspect_media(&bytes, MediaKind::Image).unwrap(), bytes)
}

fn ready(
    service: &mut ApplicationService,
    id: &str,
    parent: Option<&str>,
    color: u8,
) -> MediaGeneration {
    let (job, first) = service
        .begin_media_generation(request(service, id, parent), Utc::now())
        .unwrap();
    assert!(first);
    let (meta, bytes) = png(1024, 1024, color);
    service
        .complete_media_generation(&job, meta, &bytes, Utc::now())
        .unwrap()
}

fn accept(service: &mut ApplicationService, job: &MediaGeneration) {
    let mission = service
        .load_mission(&job.request.project_id, &job.request.mission_id)
        .unwrap();
    let manifest = service
        .load_work_product_manifest(&job.request.project_id, &job.work_product_id)
        .unwrap();
    service
        .accept_work_product(
            &AcceptWorkProduct {
                project_id: mission.project_id,
                mission_id: mission.id,
                work_product_id: job.work_product_id.clone(),
                expected_mission_revision: mission.revision,
                expected_manifest_version: manifest.version,
            },
            Utc::now(),
        )
        .unwrap();
}

#[test]
fn media_revisions_and_encrypted_reopen_preserve_exact_assets_and_reject_old_source() {
    let (dir, mut service) = fixture();
    let first = ready(&mut service, "first", None, 12);
    let initial_bytes = service
        .media_generation_bytes(
            &first.request.project_id,
            &first.request.mission_id,
            &first.request.id,
        )
        .unwrap()
        .1;
    let replay = service
        .begin_media_generation(first.request.clone(), Utc::now())
        .unwrap();
    assert!(!replay.1);
    assert_eq!(replay.0, first);
    let second = ready(&mut service, "second", Some("first"), 24);
    assert_eq!(first.work_product_id, second.work_product_id);
    assert_ne!(first.asset, second.asset);
    assert!(matches!(
        service.begin_media_generation(request(&service, "stale", Some("first")), Utc::now()),
        Err(MediaApplicationError::StaleSource)
    ));
    assert!(
        service
            .media_generations(&ProjectId::from("foreign"), &first.request.mission_id)
            .is_err()
    );
    drop(service);
    let mut reopened = open(dir.path());
    assert_eq!(
        reopened
            .media_generation_bytes(
                &first.request.project_id,
                &first.request.mission_id,
                "first"
            )
            .unwrap()
            .1,
        initial_bytes
    );
    let manifest = reopened
        .load_work_product_manifest(&second.request.project_id, &second.work_product_id)
        .unwrap();
    assert_eq!(manifest.version, 2);
    assert_eq!(
        manifest.file_digest,
        second.asset.as_ref().map(|a| a.sha256.clone())
    );
    accept(&mut reopened, &second);
    let mission = reopened
        .load_mission(&second.request.project_id, &second.request.mission_id)
        .unwrap();
    assert_eq!(mission.work_products[0].status, WorkProductStatus::Accepted);
    assert!(mission.effects.is_empty());
    drop(reopened);
    let ciphertext = std::fs::read(dir.path().join("media.db")).unwrap();
    assert!(
        !ciphertext
            .windows(first.request.prompt.len())
            .any(|w| w == first.request.prompt.as_bytes())
    );
    assert!(!ciphertext.windows(8).any(|w| w == b"\x89PNG\r\n\x1a\n"));
}

#[test]
fn media_wrong_dimensions_retain_bytes_without_an_adoptable_work_product() {
    let (_dir, mut service) = fixture();
    let (job, _) = service
        .begin_media_generation(request(&service, "wrong-size", None), Utc::now())
        .unwrap();
    let (meta, bytes) = png(1122, 1402, 30);
    let rejected = service
        .complete_media_generation(&job, meta, &bytes, Utc::now())
        .unwrap();
    assert_eq!(rejected.state, MediaGenerationState::Rejected);
    assert!(
        service
            .load_mission(&job.request.project_id, &job.request.mission_id)
            .unwrap()
            .work_products
            .is_empty()
    );
    assert_eq!(
        service
            .media_generation_bytes(
                &job.request.project_id,
                &job.request.mission_id,
                &job.request.id
            )
            .unwrap()
            .1,
        bytes
    );
    assert_eq!(
        ready(&mut service, "correct-size", Some("wrong-size"), 44).state,
        MediaGenerationState::Ready
    );
}

#[test]
fn media_rejected_revision_cannot_overwrite_a_newer_successful_candidate() {
    let (_dir, mut service) = fixture();
    let _first = ready(&mut service, "a", None, 12);
    let (b, _) = service
        .begin_media_generation(request(&service, "b", Some("a")), Utc::now())
        .unwrap();
    let (meta, bytes) = png(1100, 1024, 55);
    service
        .complete_media_generation(&b, meta, &bytes, Utc::now())
        .unwrap();
    ready(&mut service, "c", Some("a"), 66);
    assert!(matches!(
        service.begin_media_generation(request(&service, "d", Some("b")), Utc::now()),
        Err(MediaApplicationError::StaleSource)
    ));
    assert_eq!(
        service
            .media_generations(&b.request.project_id, &b.request.mission_id)
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn media_settlement_racing_adoption_retains_received_bytes_without_overwriting_acceptance() {
    let (dir, mut service) = fixture();
    let first = ready(&mut service, "initial", None, 12);
    let (job, _) = service
        .begin_media_generation(request(&service, "racing", Some("initial")), Utc::now())
        .unwrap();
    let mut other = open(dir.path());
    let mut once = false;
    let (meta, bytes) = png(1024, 1024, 80);
    let settled = service
        .complete_media_attempt(&job, meta, &bytes, Utc::now(), 1, &mut || {
            if !once {
                accept(&mut other, &first);
                once = true;
            }
        })
        .unwrap();
    assert!(once);
    assert_eq!(settled.state, MediaGenerationState::Rejected);
    assert_eq!(settled.failure_code.as_deref(), Some("MEDIA_STALE_SOURCE"));
    assert_eq!(
        service
            .media_generation_bytes(
                &job.request.project_id,
                &job.request.mission_id,
                &job.request.id
            )
            .unwrap()
            .1,
        bytes
    );
    assert_eq!(
        other
            .load_work_product_manifest(&first.request.project_id, &first.work_product_id)
            .unwrap()
            .file_digest,
        first.asset.map(|a| a.sha256)
    );
}

#[test]
fn media_mission_cancelled_during_generation_retains_the_returned_asset() {
    let (dir, mut service) = fixture();
    let first = ready(&mut service, "initial", None, 12);
    let (job, _) = service
        .begin_media_generation(request(&service, "cancelled", Some("initial")), Utc::now())
        .unwrap();
    let mut other = open(dir.path());
    let mut mission = other
        .load_mission(&job.request.project_id, &job.request.mission_id)
        .unwrap();
    let revision = mission.revision;
    mission
        .terminate(MissionTerminalDisposition::Cancelled, Utc::now())
        .unwrap();
    other
        .store
        .update_mission_atomic(
            &mission,
            revision,
            &[PendingEvent::new(
                "mission.cancelled",
                serde_json::json!({}),
                Utc::now(),
            )],
        )
        .unwrap();
    let (meta, bytes) = png(1024, 1024, 93);
    let settled = service
        .complete_media_generation(&job, meta, &bytes, Utc::now())
        .unwrap();
    assert_eq!(settled.state, MediaGenerationState::Rejected);
    assert_eq!(
        service
            .media_generation_bytes(
                &job.request.project_id,
                &job.request.mission_id,
                &job.request.id
            )
            .unwrap()
            .1,
        bytes
    );
    assert_eq!(
        service
            .load_work_product_manifest(&first.request.project_id, &first.work_product_id)
            .unwrap()
            .file_digest,
        first.asset.map(|a| a.sha256)
    );
}

#[test]
fn media_new_request_refuses_an_existing_non_media_work_product_id() {
    let (_dir, mut service) = fixture();
    let project = ProjectId::from("media-project");
    let mission = MissionId::from("media-mission");
    service
        .record_research(
            &project,
            &mission,
            ResearchPacket {
                work_product_id: WorkProductId::from("media-collision"),
                title: "Original text".into(),
                body: "Do not overwrite".into(),
                work_product_type: "runtime_draft".into(),
                fact_ids: BTreeSet::new(),
                task_ids: BTreeSet::new(),
                file_digest: None,
                preview_media_type: "text/plain".into(),
                preview: "Do not overwrite".into(),
                editable_scopes: BTreeSet::from(["/body".into()]),
                evidence: vec![],
            },
            Utc::now(),
        )
        .unwrap();
    assert!(matches!(
        service.begin_media_generation(request(&service, "collision", None), Utc::now()),
        Err(MediaApplicationError::RequestConflict)
    ));
    assert!(
        service
            .media_generations(&project, &mission)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        service
            .load_mission(&project, &mission)
            .unwrap()
            .work_products[0]
            .body,
        "Do not overwrite"
    );
}

#[test]
fn media_claim_duplicate_returns_the_durable_submitted_job_and_uncertain_never_reclaims() {
    let (dir, mut service) = fixture();
    let mut req = request(&service, "video", None);
    req.kind = MediaKind::Video;
    req.model = "grok-imagine-video-1.5".into();
    let (claim, _) = service
        .begin_media_generation(req.clone(), Utc::now())
        .unwrap();
    let submitted = service
        .record_media_submission(&claim, "original-job-id".into(), Utc::now())
        .unwrap();
    let mut other = open(dir.path());
    assert!(!other.store.begin_media_generation(&claim).unwrap());
    let replay = other.begin_media_generation(req, Utc::now()).unwrap();
    assert!(!replay.1);
    assert_eq!(replay.0, submitted);
    let request = request(&service, "uncertain", None);
    let (claim, _) = service
        .begin_media_generation(request.clone(), Utc::now())
        .unwrap();
    service
        .record_media_failure(&claim, true, "MEDIA_TRANSPORT_UNCERTAIN", Utc::now())
        .unwrap();
    let duplicate = other.begin_media_generation(request, Utc::now()).unwrap();
    assert!(!duplicate.1);
    assert_eq!(duplicate.0.state, MediaGenerationState::Uncertain);
}

#[test]
fn media_control_character_prompt_is_rejected_before_a_paid_request_claim() {
    let (_dir, mut service) = fixture();
    let mut req = request(&service, "control-characters", None);
    req.prompt = "\u{0001}".repeat(4096);
    assert!(
        service
            .begin_media_generation(req.clone(), Utc::now())
            .is_err()
    );
    assert!(
        service
            .media_generations(&req.project_id, &req.mission_id)
            .unwrap()
            .is_empty()
    );
}
