use std::{cell::RefCell, collections::VecDeque, rc::Rc};

use chrono::{Duration, Utc};
use hartevo_channel_adapters::youtube::testkit::{
    ambiguous_response, fixed_now, probe_response, rate_limited_response, readback_response,
    upload_complete_response, upload_in_progress_response, upload_session_response,
};
use hartevo_channel_adapters::{
    DraftVideoPublishRequest, MissionYouTubePublishConsumer, TransportError, YouTubeAccountId,
    YouTubeApprovalRevision, YouTubeAssetDescriptor, YouTubeAssetDigest, YouTubeBusinessId,
    YouTubeChannelId, YouTubeCredential, YouTubeDispatchOperation, YouTubeError,
    YouTubeEvidenceProvenance, YouTubeIdempotencyKey, YouTubeOAuthScope, YouTubeProviderRequest,
    YouTubeProviderResponse, YouTubePublishBinding, YouTubePublishCheckpoint,
    YouTubePublishDispatchResult, YouTubePublishPhase, YouTubePublishService, YouTubeQuotaBucket,
    YouTubeQuotaLedger, YouTubeSchedule, YouTubeSecretReference, YouTubeTenantId,
    YouTubeVideoProcessingState, YouTubeVisibility,
};

#[derive(Clone)]
struct ScriptedTransport {
    responses: Rc<RefCell<VecDeque<Result<YouTubeProviderResponse, TransportError>>>>,
    requests: Rc<RefCell<Vec<YouTubeProviderRequest>>>,
}

impl ScriptedTransport {
    fn responses(
        responses: impl IntoIterator<Item = Result<YouTubeProviderResponse, TransportError>>,
    ) -> Self {
        Self {
            responses: Rc::new(RefCell::new(responses.into_iter().collect())),
            requests: Rc::new(RefCell::new(Vec::new())),
        }
    }
}

impl hartevo_channel_adapters::YouTubePublishTransport for ScriptedTransport {
    fn send(
        &mut self,
        request: &YouTubeProviderRequest,
    ) -> Result<YouTubeProviderResponse, TransportError> {
        self.requests.borrow_mut().push(request.clone());
        self.responses
            .borrow_mut()
            .pop_front()
            .unwrap_or(Err(TransportError::Unavailable))
    }
}

fn binding(generation: u64) -> YouTubePublishBinding {
    YouTubePublishBinding::new(
        YouTubeTenantId::new("tenant-01").unwrap(),
        YouTubeBusinessId::new("business-01").unwrap(),
        YouTubeAccountId::new("account-01").unwrap(),
        YouTubeChannelId::new("UCfixture01").unwrap(),
        generation,
    )
    .unwrap()
}

fn credential(binding: &YouTubePublishBinding, now: chrono::DateTime<Utc>) -> YouTubeCredential {
    YouTubeCredential::new(
        YouTubeSecretReference::new("keychain://youtube/account-01").unwrap(),
        binding.clone(),
        [
            YouTubeOAuthScope::YoutubeReadonly,
            YouTubeOAuthScope::YoutubeUpload,
        ]
        .into_iter()
        .collect(),
        now + Duration::hours(1),
        Some(now + Duration::days(30)),
        binding.provider_generation(),
    )
    .unwrap()
}

fn request(
    binding: YouTubePublishBinding,
    now: chrono::DateTime<Utc>,
    schedule: Option<YouTubeSchedule>,
) -> DraftVideoPublishRequest {
    DraftVideoPublishRequest::new(
        binding,
        YouTubeAssetDescriptor::new(
            YouTubeAssetDigest::from_bytes(b"fixture-video-bytes"),
            8,
            "video/mp4",
        )
        .unwrap(),
        "Approved fixture video",
        YouTubeVisibility::Private,
        schedule,
        YouTubeApprovalRevision::new("approval-01", 7, now).unwrap(),
        YouTubeIdempotencyKey::new("publish-idempotency-01").unwrap(),
        now,
    )
    .unwrap()
}

fn normal_responses() -> Vec<Result<YouTubeProviderResponse, TransportError>> {
    vec![
        Ok(probe_response()),
        Ok(upload_session_response()),
        Ok(upload_complete_response()),
        Ok(readback_response(
            "Approved fixture video",
            "private",
            "succeeded",
        )),
    ]
}

#[test]
fn controlled_publish_probes_first_and_requires_receipt_readback_before_completion() {
    let now = fixed_now();
    let binding = binding(1);
    let publish_request = request(binding.clone(), now, None);
    assert_eq!(publish_request.binding(), &binding);
    assert_ne!(
        publish_request.request_digest(),
        request(
            binding.clone(),
            now,
            Some(YouTubeSchedule::new(now + Duration::hours(1))),
        )
        .request_digest()
    );
    let publish_credential = credential(&binding, now);
    let transport = ScriptedTransport::responses(normal_responses());
    let requests = Rc::clone(&transport.requests);
    let mut service = YouTubePublishService::fixture(transport);
    let mut checkpoint = YouTubePublishCheckpoint::new(publish_request.clone()).unwrap();

    let result = service
        .dispatch(&publish_credential, &mut checkpoint, now)
        .unwrap();
    let published = match result.clone() {
        YouTubePublishDispatchResult::Completed(published) => published,
        other => panic!("expected completed publish, got {other:?}"),
    };
    assert_eq!(checkpoint.phase(), &YouTubePublishPhase::Completed);
    assert_eq!(
        published.provider_receipt().video_id().as_str(),
        "fixture-video-01"
    );
    assert_eq!(
        published.readback().processing_state(),
        YouTubeVideoProcessingState::Uploaded
    );
    assert_eq!(service.provenance(), YouTubeEvidenceProvenance::Fixture);
    assert_eq!(
        requests
            .borrow()
            .iter()
            .map(YouTubeProviderRequest::operation)
            .collect::<Vec<_>>(),
        vec![
            YouTubeDispatchOperation::AuthenticatedProbe,
            YouTubeDispatchOperation::BeginResumableUpload,
            YouTubeDispatchOperation::UploadChunk,
            YouTubeDispatchOperation::Readback,
        ]
    );

    let checkpoint_json = checkpoint.checkpoint_json().unwrap();
    assert!(!checkpoint_json.contains("keychain://youtube/account-01"));
    assert_eq!(
        YouTubePublishCheckpoint::from_checkpoint_json(&checkpoint_json).unwrap(),
        checkpoint
    );

    let already = service
        .dispatch(&publish_credential, &mut checkpoint, now)
        .unwrap();
    assert!(matches!(
        already,
        YouTubePublishDispatchResult::AlreadyCompleted(_)
    ));
    assert_eq!(requests.borrow().len(), 4);

    let mission = MissionYouTubePublishConsumer::new(binding, &publish_request).unwrap();
    assert_eq!(
        mission.accept(&publish_request, published, &publish_credential, now),
        Err(YouTubeError::ProviderRejected(
            "Mission requires production YouTube evidence".to_owned()
        ))
    );
}

#[test]
fn restart_resumes_the_durable_upload_session_at_the_exact_offset() {
    let now = fixed_now();
    let binding = binding(1);
    let publish_request = request(binding.clone(), now, None);
    let publish_credential = credential(&binding, now);
    let transport = ScriptedTransport::responses([
        Ok(probe_response()),
        Ok(upload_session_response()),
        Ok(upload_in_progress_response(4)),
    ]);
    let requests = Rc::clone(&transport.requests);
    let mut service = YouTubePublishService::fixture(transport);
    let mut checkpoint = YouTubePublishCheckpoint::new(publish_request.clone()).unwrap();
    assert!(matches!(
        service
            .dispatch(&publish_credential, &mut checkpoint, now)
            .unwrap(),
        YouTubePublishDispatchResult::Uploading {
            uploaded_bytes: 4,
            ..
        }
    ));
    let checkpoint_digest = checkpoint.durable_digest();
    let reopened =
        YouTubePublishCheckpoint::from_checkpoint_json(&checkpoint.checkpoint_json().unwrap())
            .unwrap();
    assert_eq!(reopened.durable_digest(), checkpoint_digest);

    let resumed_transport = ScriptedTransport::responses([
        Ok(upload_complete_response()),
        Ok(readback_response(
            "Approved fixture video",
            "private",
            "succeeded",
        )),
    ]);
    let resumed_requests = Rc::clone(&resumed_transport.requests);
    let mut resumed_service = YouTubePublishService::fixture(resumed_transport);
    let mut reopened = reopened;
    assert!(matches!(
        resumed_service
            .dispatch(&publish_credential, &mut reopened, now)
            .unwrap(),
        YouTubePublishDispatchResult::Completed(_)
    ));
    assert_eq!(
        requests
            .borrow()
            .iter()
            .map(YouTubeProviderRequest::operation)
            .collect::<Vec<_>>(),
        vec![
            YouTubeDispatchOperation::AuthenticatedProbe,
            YouTubeDispatchOperation::BeginResumableUpload,
            YouTubeDispatchOperation::UploadChunk,
        ]
    );
    assert_eq!(
        resumed_requests.borrow()[0].operation(),
        YouTubeDispatchOperation::UploadChunk
    );
    assert_eq!(resumed_requests.borrow()[0].upload_offset(), Some(4));
    assert_eq!(reopened.phase(), &YouTubePublishPhase::Completed);
}

#[test]
fn provider_rate_limit_is_durable_and_does_not_advance_publish_state() {
    let now = fixed_now();
    let binding = binding(1);
    let publish_request = request(binding.clone(), now, None);
    let publish_credential = credential(&binding, now);
    let transport = ScriptedTransport::responses([
        Ok(probe_response()),
        Ok(rate_limited_response()),
        Ok(upload_session_response()),
        Ok(upload_complete_response()),
        Ok(readback_response(
            "Approved fixture video",
            "private",
            "succeeded",
        )),
    ]);
    let requests = Rc::clone(&transport.requests);
    let mut service = YouTubePublishService::fixture(transport);
    let mut checkpoint = YouTubePublishCheckpoint::new(publish_request).unwrap();

    let retry = service
        .dispatch(&publish_credential, &mut checkpoint, now)
        .unwrap();
    let retry_receipt = match &retry {
        YouTubePublishDispatchResult::RetryAfter(receipt) => receipt,
        other => panic!("expected retry receipt, got {other:?}"),
    };
    assert_eq!(retry_receipt.retry_after_seconds(), Some(30));
    assert_eq!(
        retry_receipt.provider_reset_at(),
        Some(now + Duration::seconds(30))
    );
    assert!(matches!(
        checkpoint.phase(),
        YouTubePublishPhase::ProbeVerified
    ));
    assert!(checkpoint.provider_receipt().is_none());

    let reopened =
        YouTubePublishCheckpoint::from_checkpoint_json(&checkpoint.checkpoint_json().unwrap())
            .unwrap();
    let mut reopened = reopened;
    assert_eq!(
        service
            .dispatch(
                &publish_credential,
                &mut reopened,
                now + Duration::seconds(1),
            )
            .unwrap(),
        retry
    );
    assert_eq!(requests.borrow().len(), 2);

    assert!(matches!(
        service
            .dispatch(
                &publish_credential,
                &mut reopened,
                now + Duration::seconds(31),
            )
            .unwrap(),
        YouTubePublishDispatchResult::Completed(_)
    ));
    assert_eq!(requests.borrow().len(), 5);
}

#[test]
fn provider_rate_limit_without_reset_never_invents_a_wait() {
    let now = fixed_now();
    let binding = binding(1);
    let publish_request = request(binding.clone(), now, None);
    let publish_credential = credential(&binding, now);
    let no_reset = YouTubeProviderResponse::new(
        429,
        [("content-type".to_owned(), "application/json".to_owned())],
        r#"{"error":{"errors":[{"reason":"userRateLimitExceeded"}]}}"#,
        now,
    );
    let mut service = YouTubePublishService::fixture(ScriptedTransport::responses([
        Ok(probe_response()),
        Ok(no_reset),
    ]));
    let mut checkpoint = YouTubePublishCheckpoint::new(publish_request).unwrap();

    let result = service
        .dispatch(&publish_credential, &mut checkpoint, now)
        .unwrap();
    let YouTubePublishDispatchResult::RetryAfter(receipt) = result else {
        panic!("expected retry receipt without provider reset");
    };
    assert_eq!(receipt.retry_after_seconds(), None);
    assert_eq!(receipt.provider_reset_at(), None);
    assert!(receipt.retry_is_due(now));
}

#[test]
fn ambiguous_upload_start_is_reconciliation_required_and_not_retried_automatically() {
    let now = fixed_now();
    let binding = binding(1);
    let publish_request = request(binding.clone(), now, None);
    let publish_credential = credential(&binding, now);
    let transport = ScriptedTransport::responses([Ok(probe_response()), Ok(ambiguous_response())]);
    let requests = Rc::clone(&transport.requests);
    let mut service = YouTubePublishService::fixture(transport);
    let mut checkpoint = YouTubePublishCheckpoint::new(publish_request.clone()).unwrap();

    let result = service
        .dispatch(&publish_credential, &mut checkpoint, now)
        .unwrap();
    assert!(matches!(
        result,
        YouTubePublishDispatchResult::ReconciliationRequired(receipt)
            if receipt.request_digest() == publish_request.request_digest()
    ));
    assert!(matches!(
        checkpoint.phase(),
        YouTubePublishPhase::ReconciliationRequired
    ));
    let checkpoint =
        YouTubePublishCheckpoint::from_checkpoint_json(&checkpoint.checkpoint_json().unwrap())
            .unwrap();
    let mut checkpoint = checkpoint;
    assert!(matches!(
        service
            .dispatch(&publish_credential, &mut checkpoint, now)
            .unwrap(),
        YouTubePublishDispatchResult::ReconciliationRequired(_)
    ));
    assert_eq!(requests.borrow().len(), 2);
}

#[test]
fn quota_and_credential_lifecycle_fail_closed() {
    let now = fixed_now();
    let old_binding = binding(1);
    let publish_request = request(old_binding.clone(), now, None);
    let old_credential = credential(&old_binding, now);

    let transport = ScriptedTransport::responses([Err(TransportError::Unavailable)]);
    let mut service = YouTubePublishService::fixture(transport);
    let mut bound_checkpoint = YouTubePublishCheckpoint::new(publish_request.clone()).unwrap();
    assert!(matches!(
        service
            .dispatch(&old_credential, &mut bound_checkpoint, now)
            .unwrap(),
        YouTubePublishDispatchResult::Retryable { .. }
    ));
    let rotated_binding = binding(2);
    let rotated_credential = credential(&rotated_binding, now);
    assert_eq!(
        service
            .dispatch(&rotated_credential, &mut bound_checkpoint, now)
            .unwrap_err(),
        YouTubeError::CheckpointInvalidated
    );
    assert!(matches!(
        bound_checkpoint.phase(),
        YouTubePublishPhase::Invalidated { .. }
    ));

    let mut revoked_checkpoint = YouTubePublishCheckpoint::new(publish_request.clone()).unwrap();
    let mut revoked = old_credential.clone();
    let mut unavailable = YouTubePublishService::fixture(ScriptedTransport::responses([Err(
        TransportError::Unavailable,
    )]));
    let _ = unavailable.dispatch(&revoked, &mut revoked_checkpoint, now);
    revoked.revoke(now);
    assert_eq!(
        unavailable
            .dispatch(&revoked, &mut revoked_checkpoint, now)
            .unwrap_err(),
        YouTubeError::CheckpointInvalidated
    );

    let mut unmounted_checkpoint = YouTubePublishCheckpoint::new(publish_request).unwrap();
    let mut unmounted = old_credential;
    let mut unavailable = YouTubePublishService::fixture(ScriptedTransport::responses([Err(
        TransportError::Unavailable,
    )]));
    let _ = unavailable.dispatch(&unmounted, &mut unmounted_checkpoint, now);
    unmounted.unmount(now);
    assert_eq!(
        unavailable
            .dispatch(&unmounted, &mut unmounted_checkpoint, now)
            .unwrap_err(),
        YouTubeError::CheckpointInvalidated
    );

    let quota_transport = ScriptedTransport::responses([]);
    let mut quota_service = YouTubePublishService::fixture_with_quota(
        quota_transport,
        YouTubeQuotaLedger::new(0, 100, 100),
    );
    let mut quota_checkpoint =
        YouTubePublishCheckpoint::new(request(binding(1), now, None)).unwrap();
    let quota_credential = credential(&binding(1), now);
    assert_eq!(
        quota_service
            .dispatch(&quota_credential, &mut quota_checkpoint, now)
            .unwrap_err(),
        YouTubeError::QuotaExhausted {
            bucket: YouTubeQuotaBucket::Probe,
        }
    );
    assert_eq!(quota_service.quota().consumed(YouTubeQuotaBucket::Probe), 0);
}

#[test]
fn readback_mismatch_never_marks_checkpoint_completed() {
    let now = fixed_now();
    let binding = binding(1);
    let publish_request = request(binding.clone(), now, None);
    let publish_credential = credential(&binding, now);
    let transport = ScriptedTransport::responses([
        Ok(probe_response()),
        Ok(upload_session_response()),
        Ok(upload_complete_response()),
        Ok(readback_response("Different title", "private", "succeeded")),
    ]);
    let mut service = YouTubePublishService::fixture(transport);
    let mut checkpoint = YouTubePublishCheckpoint::new(publish_request).unwrap();
    assert_eq!(
        service
            .dispatch(&publish_credential, &mut checkpoint, now)
            .unwrap_err(),
        YouTubeError::ReadbackMismatch
    );
    assert_eq!(checkpoint.phase(), &YouTubePublishPhase::ReceiptCaptured);
    assert!(checkpoint.provider_receipt().is_some());
}

#[test]
fn fixture_transport_never_becomes_production() {
    let now = fixed_now();
    let binding = binding(1);
    let publish_request = request(binding.clone(), now, None);
    let publish_credential = credential(&binding, now);
    let mut service =
        YouTubePublishService::fixture(ScriptedTransport::responses(normal_responses()));
    let mut checkpoint = YouTubePublishCheckpoint::new(publish_request).unwrap();
    let published = match service
        .dispatch(&publish_credential, &mut checkpoint, now)
        .unwrap()
    {
        YouTubePublishDispatchResult::Completed(published) => published,
        other => panic!("expected completed fixture world, got {other:?}"),
    };
    assert_eq!(published.provenance(), YouTubeEvidenceProvenance::Fixture);
}
