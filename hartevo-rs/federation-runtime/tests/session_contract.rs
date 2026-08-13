use std::collections::BTreeSet;

use hartevo_federation_runtime::{
    DeterministicLocalPeer, Digest, EventId, FederationCapability, FederationCloseReceipt,
    FederationEnvelope, FederationError, FederationScope, FederationSession,
    FederationSessionCheckpoint, FederationSessionLifecycle, FederationTransport, MissionId,
    PluginScope, PluginVersion, ProjectId,
};

fn scope(project: &str, mission: &str) -> FederationScope {
    PluginScope::new(
        ProjectId::new(project).expect("valid project"),
        MissionId::new(mission).expect("valid mission"),
        1,
    )
    .expect("valid scope")
}

fn capabilities() -> BTreeSet<FederationCapability> {
    BTreeSet::from([
        FederationCapability::ReadScopedMissionProjection,
        FederationCapability::ExchangeDurableEventCursor,
    ])
}

fn peer(id: &str, byte: u8) -> DeterministicLocalPeer {
    DeterministicLocalPeer::new(id, PluginVersion::new(1, 0, 0), [byte; 32]).expect("peer")
}

fn stream() -> EventId {
    EventId::new("mission.events").expect("stream")
}

fn event(label: &str) -> Digest {
    Digest::from_text(label)
}

#[test]
fn mount_receipt_and_wire_are_typed_and_bound() {
    let local = peer("peer.local", 1);
    let remote = peer("peer.remote", 2);
    let mut transport = remote;
    let scope = scope("project.alpha", "mission.alpha");
    let parent = capabilities();
    let offered = BTreeSet::from([FederationCapability::ExchangeDurableEventCursor]);

    let session = FederationSession::mount(
        &local,
        &mut transport,
        scope.clone(),
        &parent,
        offered,
        stream(),
    )
    .expect("mount");

    assert_eq!(session.lifecycle(), FederationSessionLifecycle::Active);
    assert_eq!(session.offer().issuer(), local.identity());
    session.offer().validate().expect("signed offer");
    assert_eq!(
        transport
            .deliver(FederationEnvelope::CapabilityOffer(session.offer().clone()))
            .expect_err("offer replay must fail closed"),
        FederationError::OfferReplay
    );
    assert_eq!(
        session.mount_receipt().peer_id(),
        transport.identity().peer_id()
    );
    assert_eq!(
        session.mount_receipt().peer_version(),
        transport.identity().version()
    );
    assert_eq!(
        session.mount_receipt().peer_identity_digest(),
        transport.identity().identity_digest()
    );
    assert_eq!(session.mount_receipt().scope_digest(), &scope.digest());
    session.mount_receipt().validate().expect("receipt");

    let inspection = session.inspection();
    assert_eq!(inspection.plugins.len(), 1);
    assert_eq!(inspection.services.len(), 1);
    assert_eq!(inspection.providers.len(), 1);
    assert_eq!(inspection.consumers.len(), 1);
    assert!(!inspection.is_empty());

    let wire = serde_json::to_string(&FederationEnvelope::CapabilityOffer(
        session.offer().clone(),
    ))
    .expect("wire");
    for forbidden in ["store", "keyring", "browser_profile", "effect_authority"] {
        assert!(!wire.contains(forbidden), "forbidden authority in {wire}");
    }

    let snapshot = transport
        .session_snapshot(session.session_id())
        .expect("remote session");
    assert_eq!(snapshot.scope_digest, scope.digest());
    assert_eq!(snapshot.epoch, 1);
    assert_eq!(snapshot.cursor_position, 0);
}

#[test]
fn capability_escalation_is_rejected_before_mount() {
    let local = peer("peer.local", 3);
    let remote = peer("peer.remote", 4);
    let mut transport = remote;
    let parent = BTreeSet::from([FederationCapability::ReadScopedMissionProjection]);
    let offered = capabilities();

    let error = FederationSession::mount(
        &local,
        &mut transport,
        scope("project.alpha", "mission.alpha"),
        &parent,
        offered,
        stream(),
    )
    .expect_err("authority escalation must fail closed");
    assert_eq!(error, FederationError::CapabilityEscalation);
    assert!(
        transport
            .session_snapshot(&Digest::from_text("unmounted"))
            .is_none()
    );
}

#[test]
fn cross_project_cursor_cannot_enter_another_session() {
    let local = peer("peer.local", 5);
    let remote = peer("peer.remote", 6);
    let mut transport = remote;
    let parent = capabilities();
    let mut alpha = FederationSession::mount(
        &local,
        &mut transport,
        scope("project.alpha", "mission.alpha"),
        &parent,
        capabilities(),
        stream(),
    )
    .expect("alpha mount");
    let beta = FederationSession::mount(
        &local,
        &mut transport,
        scope("project.beta", "mission.beta"),
        &parent,
        capabilities(),
        stream(),
    )
    .expect("beta mount");

    let beta_cursor = beta
        .prepare_cursor(&beta.token(), event("beta-event"))
        .expect("beta cursor");
    let alpha_token = alpha.token();
    let error = alpha
        .publish_cursor(&mut transport, &alpha_token, &beta_cursor)
        .expect_err("cross-project cursor must fail closed");
    assert_eq!(error, FederationError::ScopeMismatch);
    assert_eq!(alpha.cursor_position(), 0);
    assert_eq!(
        transport
            .session_snapshot(alpha.session_id())
            .expect("alpha remote session")
            .cursor_position,
        0
    );
}

#[test]
fn cursor_replay_does_not_advance_the_durable_position() {
    let local = peer("peer.local", 7);
    let remote = peer("peer.remote", 8);
    let mut transport = remote;
    let parent = capabilities();
    let mut session = FederationSession::mount(
        &local,
        &mut transport,
        scope("project.replay", "mission.replay"),
        &parent,
        capabilities(),
        stream(),
    )
    .expect("mount");
    let token = session.token();
    let cursor = session
        .prepare_cursor(&token, event("replay-event"))
        .expect("cursor");
    session
        .publish_cursor(&mut transport, &token, &cursor)
        .expect("first cursor");
    let error = session
        .publish_cursor(&mut transport, &token, &cursor)
        .expect_err("replay must fail closed");
    assert_eq!(error, FederationError::CursorReplay);
    assert_eq!(session.cursor_position(), 1);
    assert_eq!(
        transport
            .session_snapshot(session.session_id())
            .expect("remote session")
            .cursor_position,
        1
    );
}

#[test]
fn unmount_and_revoke_reclaim_both_registries() {
    let parent = capabilities();

    let local = peer("peer.local", 9);
    let remote = peer("peer.remote", 10);
    let mut transport = remote;
    let mut unmounted = FederationSession::mount(
        &local,
        &mut transport,
        scope("project.unmount", "mission.unmount"),
        &parent,
        capabilities(),
        stream(),
    )
    .expect("mount");
    let token = unmounted.token();
    let cursor = unmounted
        .prepare_cursor(&token, event("unmount-event"))
        .expect("cursor");
    let close = unmounted.unmount(&mut transport).expect("unmount");
    assert_eq!(
        close.reason(),
        hartevo_federation_runtime::SessionCloseReason::Unmounted
    );
    assert_eq!(unmounted.lifecycle(), FederationSessionLifecycle::Unmounted);
    assert!(unmounted.inspection().is_empty());
    assert!(transport.session_snapshot(unmounted.session_id()).is_none());
    assert_eq!(
        unmounted
            .publish_cursor(&mut transport, &token, &cursor)
            .expect_err("unmounted token must fail"),
        FederationError::SessionUnmounted
    );

    let local = peer("peer.local.revoke", 11);
    let remote = peer("peer.remote.revoke", 12);
    let mut transport = remote;
    let mut revoked = FederationSession::mount(
        &local,
        &mut transport,
        scope("project.revoke", "mission.revoke"),
        &parent,
        capabilities(),
        stream(),
    )
    .expect("mount");
    let token = revoked.token();
    let cursor = revoked
        .prepare_cursor(&token, event("revoke-event"))
        .expect("cursor");
    let close: FederationCloseReceipt = revoked.revoke(&mut transport).expect("revoke");
    assert_eq!(
        close.reason(),
        hartevo_federation_runtime::SessionCloseReason::Revoked
    );
    assert_eq!(revoked.lifecycle(), FederationSessionLifecycle::Revoked);
    assert!(revoked.inspection().is_empty());
    assert!(transport.session_snapshot(revoked.session_id()).is_none());
    assert_eq!(
        revoked
            .publish_cursor(&mut transport, &token, &cursor)
            .expect_err("revoked token must fail"),
        FederationError::SessionRevoked
    );
}

#[test]
fn crash_recovery_advances_epoch_and_preserves_cursor_fence() {
    let local = peer("peer.local.crash", 13);
    let remote = peer("peer.remote.crash", 14);
    let mut transport = remote;
    let parent = capabilities();
    let mut crashed = FederationSession::mount(
        &local,
        &mut transport,
        scope("project.crash", "mission.crash"),
        &parent,
        capabilities(),
        stream(),
    )
    .expect("mount");
    let old_token = crashed.token();
    let old_cursor = crashed
        .prepare_cursor(&old_token, event("before-crash"))
        .expect("cursor");
    crashed
        .publish_cursor(&mut transport, &old_token, &old_cursor)
        .expect("durable cursor");
    let checkpoint = crashed.crash().expect("crash checkpoint");
    assert_eq!(crashed.lifecycle(), FederationSessionLifecycle::Crashed);
    assert_eq!(checkpoint.epoch(), 1);
    assert_eq!(checkpoint.cursor_position(), 1);

    let checkpoint_json = serde_json::to_vec(&checkpoint).expect("checkpoint serialization");
    let durable_checkpoint: FederationSessionCheckpoint =
        serde_json::from_slice(&checkpoint_json).expect("checkpoint recovery");
    let mut recovered = FederationSession::recover_from_checkpoint(
        &durable_checkpoint,
        &local,
        &parent,
        &mut transport,
    )
    .expect("recovery");
    assert_eq!(recovered.epoch(), 2);
    assert_eq!(recovered.cursor_position(), 1);
    let snapshot = transport
        .session_snapshot(recovered.session_id())
        .expect("recovered remote session");
    assert_eq!(snapshot.epoch, 2);
    assert_eq!(snapshot.cursor_position, 1);

    assert_eq!(
        crashed
            .prepare_cursor(&old_token, event("stale-crashed-session"))
            .expect_err("crashed session must not publish"),
        FederationError::SessionCrashed
    );
    let new_token = recovered.token();
    assert_eq!(
        recovered
            .publish_cursor(&mut transport, &old_token, &old_cursor)
            .expect_err("old token must not publish after recovery"),
        FederationError::StaleSessionToken
    );
    assert_eq!(
        recovered
            .publish_cursor(&mut transport, &new_token, &old_cursor)
            .expect_err("old epoch cursor must not publish"),
        FederationError::StaleEpoch
    );
    let next_cursor = recovered
        .prepare_cursor(&new_token, event("after-recovery"))
        .expect("next cursor");
    recovered
        .publish_cursor(&mut transport, &new_token, &next_cursor)
        .expect("recovered cursor");
    assert_eq!(recovered.cursor_position(), 2);
    assert_eq!(
        transport
            .session_snapshot(recovered.session_id())
            .expect("remote session")
            .cursor_position,
        2
    );
}

#[test]
fn tampered_mount_receipt_is_rejected() {
    let local = peer("peer.local.receipt", 15);
    let remote = peer("peer.remote.receipt", 16);
    let mut transport = remote;
    let parent = capabilities();
    let session = FederationSession::mount(
        &local,
        &mut transport,
        scope("project.receipt", "mission.receipt"),
        &parent,
        capabilities(),
        stream(),
    )
    .expect("mount");
    let mut value = serde_json::to_value(session.mount_receipt()).expect("receipt json");
    value["epoch"] = serde_json::json!(2);
    let tampered: hartevo_federation_runtime::FederationMountReceipt =
        serde_json::from_value(value).expect("receipt shape");
    assert_eq!(
        tampered.validate().expect_err("tampering must fail closed"),
        FederationError::InvalidMountReceipt
    );
}

#[test]
fn envelope_has_no_generic_payload_escape_hatch() {
    fn assert_closed(envelope: &FederationEnvelope) {
        match envelope {
            FederationEnvelope::CapabilityOffer(_) | FederationEnvelope::DurableEventCursor(_) => {}
        }
    }

    let local = peer("peer.local.envelope", 17);
    let remote = peer("peer.remote.envelope", 18);
    let mut transport = remote;
    let parent = capabilities();
    let session = FederationSession::mount(
        &local,
        &mut transport,
        scope("project.envelope", "mission.envelope"),
        &parent,
        capabilities(),
        stream(),
    )
    .expect("mount");
    let envelope = FederationEnvelope::CapabilityOffer(session.offer().clone());
    assert_closed(&envelope);
}
