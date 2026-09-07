//! Explicitly ignored, paid integration journey. Uses the real HTTPS transport
//! and production Desktop/Cordis/Application/SQLCipher code. MemorySecretStore
//! and the test paint acknowledgement are harness boundaries, not UI evidence.

use std::fs;
use std::time::Instant;

use hartevo_application::llm_deepseek::EnvironmentCredentialResolver;
use hartevo_cordis::{SessionEventKind, SessionStore};
use hartevo_domain_kernel::WorkProductStatus;

use super::*;

#[derive(Clone, Default)]
struct LiveTransport {
    requests: Arc<Mutex<Vec<serde_json::Value>>>,
    receipts: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl DeepSeekTransport for LiveTransport {
    fn execute(
        &self,
        connection: &DeepSeekConnection,
        api_key: &str,
        request: &serde_json::Value,
        cancellation: &LifecycleCancellation,
    ) -> Result<DeepSeekWireResponse, SessionLlmFailure> {
        let mut requests = self.requests.lock().unwrap();
        assert!(
            requests.len() < 6,
            "live journey exhausted its six-request limit"
        );
        requests.push(request.clone());
        drop(requests);
        let start = Instant::now();
        let result = UreqDeepSeekTransport.execute(connection, api_key, request, cancellation);
        let mut models = BTreeSet::new();
        let mut usage = serde_json::Value::Null;
        if let Ok(response) = &result {
            for payload in response.payloads() {
                let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
                    continue;
                };
                if let Some(model) = value["model"].as_str()
                    && model.len() < 128
                    && model
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-._/".contains(&byte))
                    && !model.contains(api_key)
                {
                    models.insert(model.to_owned());
                }
                if value["usage"].is_object() {
                    usage = serde_json::json!({
                        "promptTokens": value["usage"]["prompt_tokens"].as_u64(),
                        "completionTokens": value["usage"]["completion_tokens"].as_u64(),
                        "totalTokens": value["usage"]["total_tokens"].as_u64(),
                    });
                }
            }
        }
        self.receipts.lock().unwrap().push(serde_json::json!({
            "elapsedMillis": start.elapsed().as_millis(),
            "returnedModels": models,
            "usage": usage,
            "status": if result.is_ok() { "received" } else { "failed" },
            "errorCode": result.as_ref().err().map(|error| &error.code),
        }));
        result
    }
}

fn source(transport: &LiveTransport) -> DesktopRuntimeSource {
    let discovery = crate::runtime_plane::discover_runtime();
    assert_eq!(
        discovery.projection.status,
        DesktopRuntimeAvailabilityStatus::ReadyDevelopment
    );
    let config = discovery
        .configuration
        .expect("configured native compatible model");
    assert!(config.artifact.is_none());
    let provider = ChatCompletionsProvider::from_id(&config.provider).expect("compatible provider");
    let adapter = OpenAiCompatibleAdapter::new(
        provider,
        config
            .compatible_connection
            .expect("validated HTTPS connection"),
        EnvironmentCredentialResolver,
        transport.clone(),
    );
    DesktopRuntimeSource::NativeCompatible {
        model: config.model,
        adapter,
    }
}

fn draft_id(submission: &DesktopMissionSubmission) -> WorkProductId {
    match &submission.runtime_outcome {
        DesktopMissionRuntimeOutcome::DraftReady { work_product_id } => work_product_id.clone(),
        other => panic!("live model did not produce a durable draft: {other:?}"),
    }
}

#[test]
#[ignore = "paid real-provider journey; run scripts/run-live-model-journeys.py --allow-paid"]
#[allow(
    clippy::too_many_lines,
    reason = "one live journey retains exact revision and cold recovery evidence"
)]
fn live_mission_continuation_adoption_and_recovery() {
    assert_eq!(std::env::var("HARTEVO_LIVE_MODELS").as_deref(), Ok("1"));
    let output = PathBuf::from(std::env::var_os("HARTEVO_LIVE_OUTPUT").expect("receipt directory"));
    fs::create_dir(&output).expect("new private receipt directory");
    let start = Instant::now();
    let now = Utc::now();
    let (_directory, plane, secrets, project_id) = ready_personal_fixture();
    let transport = LiveTransport::default();
    let mut request = catalog_runtime_request(&project_id);
    request.title = Some("Live Nordlicht campaign".into());
    request.goal = "Create three short German campaign headlines for fictional reusable-bottle brand NORDLICHT. Audience: urban commuters. Include NORDLICHT in the draft. No unverified statistics. Use only this supplied brief; do not browse, delegate, run commands or publish. Return the three headlines as the final draft, under 150 words.".into();
    let started = plane
        .start_catalog_mission_execution_with(&secrets, request, now)
        .expect("commit actual catalog Mission before dispatch");
    let initial = plane
        .resume_catalog_mission_runtime_with_cancellation(
            &secrets,
            catalog_runtime_authority(started.handle),
            Some(source(&transport)),
            DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
            now + Duration::seconds(1),
        )
        .expect("real initial provider turn");
    let initial_id = draft_id(&initial);
    let database_secret = secrets.get(plane.database_key_reference()).unwrap();
    let service = plane
        .open_read_application_from_secret(&database_secret)
        .unwrap();
    let first = service
        .mission_conversation(&project_id, &initial.mission_id)
        .unwrap();
    assert_eq!(first.messages.len(), 2);
    let first_body = first.messages[1].body.clone();
    assert!(
        first_body.to_uppercase().contains("NORDLICHT"),
        "brand missing in actual draft"
    );
    assert!(
        first_body.len() > 40,
        "draft must contain usable campaign copy"
    );
    fs::write(output.join("initial-draft.md"), &first_body).unwrap();
    assert_eq!(
        transport.requests.lock().unwrap().len(),
        1,
        "brief needs exactly one model call"
    );
    drop(service);

    let handle = current_catalog_handle(&plane, &secrets, &project_id, &initial.mission_id);
    let correction = DesktopMissionContinuationRequest {
        project_id: project_id.clone(),
        mission_id: initial.mission_id.clone(),
        message_id: MissionConversationMessageId::from("live-campaign-correction"),
        kind: MissionConversationMessageKind::Correction,
        body: "Keep the same brand from the previous draft. Revise for students, with two German headlines and one call to action. Include the exact tag LIVE-CONTINUED at the end. Use only our brief and do not call tools or publish.".into(),
        idempotency_key: "live-campaign-correction-v1".into(),
        expected_conversation_revision: first.revision,
    };
    let continued = plane
        .continue_catalog_mission_and_run_with(
            &secrets,
            correction.clone(),
            catalog_runtime_authority(handle.clone()),
            Some(source(&transport)),
            DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
            now + Duration::minutes(2),
        )
        .expect("real same-Mission continuation");
    let continued_id = draft_id(&continued);
    assert_ne!(initial_id, continued_id);
    let service = plane
        .open_read_application_from_secret(&database_secret)
        .unwrap();
    let conversation = service
        .mission_conversation(&project_id, &initial.mission_id)
        .unwrap();
    assert_eq!(conversation.messages.len(), 4);
    let body = &conversation.messages[3].body;
    assert!(
        body.to_uppercase().contains("NORDLICHT"),
        "model must retain prior brand context"
    );
    assert!(
        body.contains("LIVE-CONTINUED"),
        "model must apply the actual correction"
    );
    fs::write(output.join("continued-draft.md"), body).unwrap();
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[1]["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|message| { message["role"] == "assistant" && message["content"] == first_body }),
        "previous real answer must be sent on continuation"
    );
    assert!(
        requests
            .iter()
            .all(|request| request.get("thinking").is_none())
    );
    drop(requests);
    let events = service
        .mission_events(&project_id, &initial.mission_id)
        .unwrap();
    let event_json = serde_json::to_string(&events).unwrap();
    assert!(!event_json.contains(&first_body));
    assert!(!event_json.contains(body));
    assert!(
        service
            .latest_runtime_turn_for_mission(&project_id, &initial.mission_id)
            .unwrap()
            .is_none()
    );
    drop(service);

    let replay = plane
        .continue_catalog_mission_and_run_with(
            &secrets,
            correction,
            catalog_runtime_authority(handle),
            Some(source(&transport)),
            DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
            now + Duration::minutes(3),
        )
        .expect("idempotent continuation replay");
    assert_eq!(draft_id(&replay), continued_id);
    assert_eq!(
        transport.requests.lock().unwrap().len(),
        2,
        "replay must spend no extra request"
    );
    let session_id = SessionId::new(initial.mission_id.as_str()).unwrap();
    let session_events = plane.with_cordis_host(|host| {
        let session = host
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .get(&session_id)
            .unwrap()
            .unwrap();
        let events = session.events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event.kind, SessionEventKind::AssistantMessage { .. }))
                .count(),
            2
        );
        events
    });
    let data_root = plane.data_root().to_path_buf();
    drop(plane);
    let cold = DesktopDataPlane::at_data_root(data_root).unwrap();
    assert!(matches!(
        cold.load_with(&secrets, now + Duration::minutes(4))
            .unwrap(),
        DesktopLoadState::Ready(_)
    ));
    let recovered = cold
        .resume_mission_runtime_with(
            &secrets,
            &project_id,
            &initial.mission_id,
            Some(source(&transport)),
            DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
            now + Duration::minutes(5),
        )
        .expect("restore persisted real-model result");
    assert_eq!(draft_id(&recovered), continued_id);
    assert_eq!(transport.requests.lock().unwrap().len(), 2);
    cold.with_cordis_host(|host| {
        let session = host
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .get(&session_id)
            .unwrap()
            .unwrap();
        assert_eq!(session.events().unwrap(), session_events);
    });
    let service = cold
        .open_read_application_from_secret(&database_secret)
        .unwrap();
    assert_eq!(
        service
            .mission_events(&project_id, &initial.mission_id)
            .unwrap(),
        events
    );
    assert_eq!(
        service
            .mission_conversation(&project_id, &initial.mission_id)
            .unwrap(),
        conversation
    );
    let mission = service
        .load_mission(&project_id, &initial.mission_id)
        .unwrap();
    assert!(mission.effects.is_empty());
    let product = mission
        .work_products
        .iter()
        .find(|product| product.id == continued_id)
        .unwrap();
    let manifest = service
        .load_work_product_manifest(&project_id, &continued_id)
        .unwrap();
    let adoption = DesktopWorkProductAdoptionRequest {
        project_id: project_id.clone(),
        mission_id: initial.mission_id.clone(),
        work_product_id: continued_id.clone(),
        expected_mission_revision: mission.revision,
        expected_work_product_revision: product.revision,
        expected_manifest_version: manifest.version,
    };
    drop(service);
    cold.adopt_work_product_with(&secrets, adoption.clone(), now + Duration::minutes(6))
        .unwrap();
    assert!(matches!(
        cold.adopt_work_product_with(&secrets, adoption, now + Duration::minutes(7)),
        Err(DesktopDataError::WorkProductActionStale)
    ));
    let service = cold
        .open_read_application_from_secret(&database_secret)
        .unwrap();
    let accepted = service
        .load_mission(&project_id, &initial.mission_id)
        .unwrap();
    assert_eq!(
        accepted
            .work_products
            .iter()
            .find(|product| product.id == continued_id)
            .unwrap()
            .status,
        WorkProductStatus::Accepted
    );
    assert!(accepted.effects.is_empty());
    let receipt = serde_json::json!({
        "schemaVersion": "desktop-live-model-journey/v1", "status": "passed", "observedAt": Utc::now(),
        "provider": std::env::var(crate::runtime_plane::RUNTIME_PROVIDER_ENV).unwrap(),
        "model": std::env::var(crate::runtime_plane::RUNTIME_MODEL_ENV).unwrap(),
        "elapsedMillis": start.elapsed().as_millis(), "modelCalls": transport.receipts.lock().unwrap().clone(),
        "assertions": {"catalogMission": true, "realProviderDraft": true, "sameMissionContinuation": true,
            "contextRetained": true, "idempotentReplay": true, "sqlcipherReopen": true,
            "exactSessionReplay": true, "workProductAdoption": true, "staleAdoptionRejected": true,
            "noPublicationEffects": true},
        "initialDraftSha256": format!("{:x}", Sha256::digest(first_body.as_bytes())),
        "continuedDraftSha256": format!("{:x}", Sha256::digest(body.as_bytes())),
        "notProven": ["native_ui", "os_keychain", "process_restart", "media_generation_workflow", "channel_publication", "business_outcome", "release_readiness"]
    });
    fs::write(
        output.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    println!("live-model journey passed; receipt written without credentials");
}
