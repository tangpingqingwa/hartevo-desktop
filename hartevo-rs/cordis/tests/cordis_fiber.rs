use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::FutureExt;
use hartevo_cordis::{
    ActivationEpoch, ConfigValue, CordisError, FiberState, FiberUid, LifecycleCancellation,
    LifecycleDisposer, LifecycleEffect, LifecycleRegistry, PluginFactory, ProviderFingerprint,
    TransitionTicket,
};

#[test]
fn six_states_and_deterministic_activation_epoch_are_public() {
    let states = [
        FiberState::Pending,
        FiberState::Loading,
        FiberState::Active,
        FiberState::Failed,
        FiberState::Disposed,
        FiberState::Unloading,
    ];
    assert_eq!(states.len(), 6);

    let first = ProviderFingerprint::new("root", "tools", FiberUid::ROOT, 2);
    let second = ProviderFingerprint::new("root", "llm", FiberUid::ROOT, 4);
    let left = ActivationEpoch::new(7, [first.clone(), second.clone()]);
    let right = ActivationEpoch::new(7, [second, first]);
    assert_eq!(left, right);

    let ticket = TransitionTicket::new(11, Some(left.clone()));
    assert_eq!(ticket.serial(), 11);
    assert_eq!(ticket.target(), Some(&left));
}

#[tokio::test]
async fn same_owner_generation_zero_reprovide_rebinds_loading_without_reload() {
    let starts = Arc::new(AtomicUsize::new(0));
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("same-epoch-reprovide", {
        let starts = starts.clone();
        let cleanup_calls = cleanup_calls.clone();
        let entered_tx = entered_tx.clone();
        let release = release.clone();
        move |_config, _ctx| {
            starts.fetch_add(1, Ordering::SeqCst);
            if let Some(sender) = entered_tx.lock().unwrap().take() {
                let _ = sender.send(());
            }
            let release = release.clone();
            let cleanup_calls = cleanup_calls.clone();
            LifecycleEffect::future(async move {
                release.wait().await;
                Ok(Some(LifecycleDisposer::sync(move || {
                    cleanup_calls.fetch_add(1, Ordering::SeqCst);
                })))
            })
        }
    })
    .with_inject(["dep"]);
    let registry = LifecycleRegistry::new();
    let first = registry.provide("dep", 1_u32).unwrap();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();

    entered_rx.await.unwrap();
    let removal = registry.begin_remove_provider(&first).unwrap();
    let second = registry.provide("dep", 2_u32).unwrap();
    assert_ne!(first.provider_id(), second.provider_id());
    assert_eq!(first.generation(), 0);
    assert_eq!(second.generation(), 0);
    release.wait().await;
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    removal.await.unwrap();

    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 0);
    assert_eq!(registry.get::<u32>("dep").as_deref(), Some(&2));
    let snapshot = handle.snapshot();
    let dependency = &snapshot.committed_epoch().unwrap().dependencies()[0];
    assert_eq!(dependency.generation(), 0);
}

#[tokio::test]
async fn authorized_generation_bump_during_loading_reloads_latest_epoch_once() {
    let starts = Arc::new(AtomicUsize::new(0));
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("generation-bump", {
        let starts = starts.clone();
        let cleanup_calls = cleanup_calls.clone();
        let entered_tx = entered_tx.clone();
        let release = release.clone();
        move |_config, _ctx| {
            let call = starts.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                if let Some(sender) = entered_tx.lock().unwrap().take() {
                    let _ = sender.send(());
                }
                let release = release.clone();
                let cleanup_calls = cleanup_calls.clone();
                LifecycleEffect::future(async move {
                    release.wait().await;
                    Ok(Some(LifecycleDisposer::sync(move || {
                        cleanup_calls.fetch_add(1, Ordering::SeqCst);
                    })))
                })
            } else {
                LifecycleEffect::none()
            }
        }
    })
    .with_inject(["dep"]);
    let registry = LifecycleRegistry::new();
    let first = registry.provide("dep", 1_u32).unwrap();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();

    entered_rx.await.unwrap();
    let rebound = registry.replace_provider(&first, 2_u32).unwrap();
    assert_eq!(rebound.generation(), 1);
    release.wait().await;
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();

    assert_eq!(starts.load(Ordering::SeqCst), 2);
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 1);
    let snapshot = handle.snapshot();
    let dependency = &snapshot.committed_epoch().unwrap().dependencies()[0];
    assert_eq!(dependency.generation(), 1);
}

#[tokio::test]
async fn stale_context_view_and_dropped_dispose_waiter_cannot_publish_after_tombstone() {
    let (view_tx, view_rx) = tokio::sync::oneshot::channel();
    let view_tx = Arc::new(Mutex::new(Some(view_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("stale-view", {
        let view_tx = view_tx.clone();
        let release = release.clone();
        move |_config, ctx| {
            if let Some(sender) = view_tx.lock().unwrap().take() {
                let _ = sender.send(ctx.clone());
            }
            let release = release.clone();
            LifecycleEffect::future(async move {
                release.wait().await;
                Ok(None)
            })
        }
    });
    let registry = LifecycleRegistry::new();
    registry.provide("stale-read-target", 9_u32).unwrap();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let view = view_rx.await.unwrap();
    assert_eq!(view.get::<u32>("stale-read-target").as_deref(), Some(&9));

    let mut disposal = Box::pin(handle.dispose_async());
    assert!(disposal.as_mut().now_or_never().is_none());
    drop(disposal);
    assert!(handle.fiber().is_disposed());
    assert!(matches!(
        view.set_var("must-not-commit", true),
        Err(CordisError::StaleLifecycleView { .. })
    ));
    assert!(matches!(
        view.provide("must-not-publish", 1_u32),
        Err(CordisError::StaleLifecycleView { .. })
    ));
    assert!(view.get::<u32>("stale-read-target").is_none());

    release.wait().await;
    assert_eq!(
        handle.await_current().await.unwrap().state(),
        FiberState::Disposed
    );
    assert!(registry.get::<u32>("must-not-publish").is_none());
}

#[tokio::test]
async fn context_view_dynamic_read_fails_after_ticket_replacement_without_tombstone() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (view_tx, view_rx) = tokio::sync::oneshot::channel();
    let view_tx = Arc::new(Mutex::new(Some(view_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("stale-read-ticket", {
        let calls = calls.clone();
        let view_tx = view_tx.clone();
        let release = release.clone();
        move |_config, ctx| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                if let Some(sender) = view_tx.lock().unwrap().take() {
                    let _ = sender.send(ctx.clone());
                }
                let release = release.clone();
                LifecycleEffect::future(async move {
                    release.wait().await;
                    Ok(None)
                })
            } else {
                LifecycleEffect::none()
            }
        }
    });
    let registry = LifecycleRegistry::new();
    registry.provide("ticket-read-target", 13_u32).unwrap();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let view = view_rx.await.unwrap();
    assert_eq!(view.get::<u32>("ticket-read-target").as_deref(), Some(&13));

    let mut update = Box::pin(handle.update(ConfigValue::string("new-ticket")));
    assert!(update.as_mut().now_or_never().is_none());
    assert!(!handle.fiber().is_disposed());
    assert!(view.get::<u32>("ticket-read-target").is_none());
    release.wait().await;

    assert_eq!(update.await.unwrap().state(), FiberState::Active);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn cancelled_waiters_do_not_lose_pre_or_concurrent_cancellation() {
    let registry = LifecycleRegistry::new();
    let handle = registry
        .mount(
            PluginFactory::new_lifecycle("cancel-waiters", |_config, _ctx| LifecycleEffect::none())
                .with_inject(["missing"]),
            ConfigValue::default(),
        )
        .unwrap();
    let cancellation = LifecycleCancellation::default();
    cancellation.cancel();
    assert!(matches!(
        handle.fiber().wait_until_active(cancellation.clone()).await,
        Err(CordisError::WaitCancelled { .. })
    ));

    let concurrent = LifecycleCancellation::default();
    let waiters = (0..32)
        .map(|_| {
            let fiber = handle.fiber();
            let cancellation = concurrent.clone();
            tokio::spawn(async move { fiber.wait_until_active(cancellation).await })
        })
        .collect::<Vec<_>>();
    concurrent.cancel();
    for waiter in waiters {
        assert!(matches!(
            waiter.await.unwrap(),
            Err(CordisError::WaitCancelled { .. })
        ));
    }
}

#[tokio::test]
async fn root_restart_preflights_every_child_before_any_ticket_or_cleanup() {
    let repeatable_starts = Arc::new(AtomicUsize::new(0));
    let repeatable_cleanups = Arc::new(AtomicUsize::new(0));
    let repeatable = PluginFactory::new_lifecycle("root-repeatable", {
        let repeatable_starts = repeatable_starts.clone();
        let repeatable_cleanups = repeatable_cleanups.clone();
        move |_config, _ctx| {
            repeatable_starts.fetch_add(1, Ordering::SeqCst);
            let repeatable_cleanups = repeatable_cleanups.clone();
            LifecycleEffect::disposer(LifecycleDisposer::sync(move || {
                repeatable_cleanups.fetch_add(1, Ordering::SeqCst);
            }))
        }
    });
    let one_shot =
        PluginFactory::one_shot_lifecycle("root-one-shot", |_config, _ctx| LifecycleEffect::none());
    let registry = LifecycleRegistry::new();
    let repeatable = registry.mount(repeatable, ConfigValue::default()).unwrap();
    let one_shot = registry.mount(one_shot, ConfigValue::default()).unwrap();
    repeatable
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    one_shot
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    let before_repeatable = repeatable.snapshot();
    let before_one_shot = one_shot.snapshot();
    let before_history = repeatable.fiber().state_history();

    let error = registry.restart_root().await.unwrap_err();
    assert!(matches!(error, CordisError::NonRepeatableFactory { .. }));
    assert_eq!(repeatable.snapshot(), before_repeatable);
    assert_eq!(one_shot.snapshot(), before_one_shot);
    assert_eq!(repeatable.fiber().state_history(), before_history);
    assert_eq!(repeatable_starts.load(Ordering::SeqCst), 1);
    assert_eq!(repeatable_cleanups.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn resolved_handle_dispose_before_root_preflight_leaves_siblings_unchanged() {
    let sibling_starts = Arc::new(AtomicUsize::new(0));
    let sibling_starts_for_factory = sibling_starts.clone();
    let sibling_factory = PluginFactory::new_lifecycle("root-sibling", move |_config, _ctx| {
        sibling_starts_for_factory.fetch_add(1, Ordering::SeqCst);
        LifecycleEffect::none()
    });
    let victim_factory =
        PluginFactory::new_lifecycle("root-victim", |_config, _ctx| LifecycleEffect::none());
    let registry = LifecycleRegistry::new();
    let sibling = registry
        .mount(sibling_factory, ConfigValue::default())
        .unwrap();
    let victim = registry
        .mount(victim_factory, ConfigValue::default())
        .unwrap();
    sibling
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    victim
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    let sibling_before = sibling.snapshot();
    let sibling_history = sibling.fiber().state_history();

    let mut disposal = Box::pin(victim.dispose_async());
    assert!(disposal.as_mut().now_or_never().is_none());
    let error = registry.restart_root().await.unwrap_err();
    assert!(matches!(error, CordisError::FiberDisposed { .. }));
    assert_eq!(sibling.snapshot(), sibling_before);
    assert_eq!(sibling.fiber().state_history(), sibling_history);
    assert_eq!(sibling_starts.load(Ordering::SeqCst), 1);
    disposal.await.unwrap();
}

#[tokio::test]
async fn managed_terminal_snapshot_survives_registry_control_removal() {
    let factory =
        PluginFactory::new_lifecycle("terminal-freeze", |_config, _ctx| LifecycleEffect::none());
    let registry = LifecycleRegistry::new();
    let handle = registry
        .mount(factory.clone(), ConfigValue::default())
        .unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    let fiber = handle.fiber();
    handle.dispose_async().await.unwrap();
    registry.delete_factory(&factory).await.unwrap();
    assert_eq!(registry.runtime_count(), 0);
    drop(handle);
    drop(registry);

    assert!(fiber.is_disposed());
    assert_eq!(fiber.state(), FiberState::Disposed);
    assert_eq!(fiber.snapshot().state(), FiberState::Disposed);
    assert_eq!(fiber.state_history().last(), Some(&FiberState::Disposed));
}

#[tokio::test]
async fn batch_local_catalog_conflict_rejects_every_provisional_child() {
    let first =
        PluginFactory::new_lifecycle("same-child-id", |_config, _ctx| LifecycleEffect::none());
    let second =
        PluginFactory::new_lifecycle("same-child-id", |_config, _ctx| LifecycleEffect::none());
    let (children_tx, children_rx) = tokio::sync::oneshot::channel();
    let children_tx = Arc::new(Mutex::new(Some(children_tx)));
    let parent = PluginFactory::new_lifecycle("batch-parent", {
        let first = first.clone();
        let second = second.clone();
        let children_tx = children_tx.clone();
        move |_config, ctx| {
            let left = ctx.mount(first.clone(), ConfigValue::default())?;
            let right = ctx.mount(second.clone(), ConfigValue::default())?;
            if let Some(sender) = children_tx.lock().unwrap().take() {
                let _ = sender.send((left, right));
            }
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        }
    });
    let registry = LifecycleRegistry::new();
    let parent = registry.mount(parent, ConfigValue::default()).unwrap();
    let (left, right) = children_rx.await.unwrap();
    assert!(matches!(
        parent.await_current().await,
        Err(CordisError::PluginCatalogConflict { .. })
    ));
    assert!(left.is_disposed());
    assert!(right.is_disposed());
    assert_eq!(registry.runtime_count(), 1);

    let child = registry.mount(first, ConfigValue::default()).unwrap();
    child
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    assert_eq!(registry.runtime_count(), 2);
}

#[tokio::test]
async fn dropped_cleanup_waiter_does_not_cancel_registry_owned_driver() {
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("drop-cleanup-waiter", {
        let cleanup_calls = cleanup_calls.clone();
        let entered_tx = entered_tx.clone();
        let release = release.clone();
        move |_config, _ctx| {
            let cleanup_calls = cleanup_calls.clone();
            let entered_tx = entered_tx.clone();
            let release = release.clone();
            LifecycleEffect::disposer(LifecycleDisposer::new(move || async move {
                if let Some(sender) = entered_tx.lock().unwrap().take() {
                    let _ = sender.send(());
                }
                release.wait().await;
                cleanup_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }))
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    let waiter = tokio::spawn({
        let handle = handle.clone();
        async move { handle.dispose_async().await }
    });
    entered_rx.await.unwrap();
    waiter.abort();
    let _ = waiter.await;
    release.wait().await;

    assert_eq!(
        handle.await_current().await.unwrap().state(),
        FiberState::Disposed
    );
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dropped_absence_waiter_still_removes_after_dependent_cleanup() {
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let consumer = PluginFactory::new_lifecycle("drop-absence-waiter", {
        let cleanup_calls = cleanup_calls.clone();
        let entered_tx = entered_tx.clone();
        let release = release.clone();
        move |_config, _ctx| {
            let cleanup_calls = cleanup_calls.clone();
            let entered_tx = entered_tx.clone();
            let release = release.clone();
            LifecycleEffect::disposer(LifecycleDisposer::new(move || async move {
                if let Some(sender) = entered_tx.lock().unwrap().take() {
                    let _ = sender.send(());
                }
                release.wait().await;
                cleanup_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }))
        }
    })
    .with_inject(["dep"]);
    let registry = LifecycleRegistry::new();
    let provider = registry.provide("dep", 1_u32).unwrap();
    let consumer = registry.mount(consumer, ConfigValue::default()).unwrap();
    consumer
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    drop(registry.begin_remove_provider(&provider).unwrap());
    entered_rx.await.unwrap();
    release.wait().await;

    assert_eq!(
        consumer.await_current().await.unwrap().state(),
        FiberState::Pending
    );
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 1);
    assert!(registry.get::<u32>("dep").is_none());
}

#[tokio::test]
async fn failed_restart_retains_error_cleans_partial_registration_and_never_retries() {
    let starts = Arc::new(AtomicUsize::new(0));
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("failed-restart", {
        let starts = starts.clone();
        let cleanup_calls = cleanup_calls.clone();
        let entered_tx = entered_tx.clone();
        let release = release.clone();
        move |_config, ctx| {
            starts.fetch_add(1, Ordering::SeqCst);
            let cleanup_calls = cleanup_calls.clone();
            let entered_tx = entered_tx.clone();
            let release = release.clone();
            ctx.effect(LifecycleEffect::disposer(LifecycleDisposer::new(
                move || async move {
                    if let Some(sender) = entered_tx.lock().unwrap().take() {
                        let _ = sender.send(());
                    }
                    release.wait().await;
                    cleanup_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )))?;
            Err::<LifecycleEffect, CordisError>(CordisError::PayloadType {
                name: "retained-start-error".to_string(),
            })
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let initial_error = handle.await_current().await.unwrap_err();
    assert_eq!(handle.snapshot().state(), FiberState::Failed);
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 0);

    let restart = tokio::spawn({
        let handle = handle.clone();
        async move { handle.restart().await }
    });
    entered_rx.await.unwrap();
    assert_eq!(handle.snapshot().error(), Some(&initial_error));
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    release.wait().await;
    assert_eq!(restart.await.unwrap().unwrap_err(), initial_error);
    assert_eq!(handle.snapshot().state(), FiberState::Failed);
    assert_eq!(handle.snapshot().error(), Some(&initial_error));
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn update_clears_error_before_old_cleanup_then_recovers_with_new_config() {
    let starts = Arc::new(AtomicUsize::new(0));
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("failed-update", {
        let starts = starts.clone();
        let cleanup_calls = cleanup_calls.clone();
        let entered_tx = entered_tx.clone();
        let release = release.clone();
        move |config, ctx| {
            starts.fetch_add(1, Ordering::SeqCst);
            if config.as_str() == Some("good") {
                return Ok(LifecycleEffect::none());
            }
            let cleanup_calls = cleanup_calls.clone();
            let entered_tx = entered_tx.clone();
            let release = release.clone();
            ctx.effect(LifecycleEffect::disposer(LifecycleDisposer::new(
                move || async move {
                    if let Some(sender) = entered_tx.lock().unwrap().take() {
                        let _ = sender.send(());
                    }
                    release.wait().await;
                    cleanup_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )))?;
            Err(CordisError::PayloadType {
                name: "clear-on-update".to_string(),
            })
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::string("bad")).unwrap();
    handle.await_current().await.unwrap_err();
    assert!(handle.snapshot().error().is_some());

    let update = tokio::spawn({
        let handle = handle.clone();
        async move { handle.update(ConfigValue::string("good")).await }
    });
    entered_rx.await.unwrap();
    let during_cleanup = handle.snapshot();
    assert_eq!(during_cleanup.state(), FiberState::Unloading);
    assert!(during_cleanup.error().is_none());
    release.wait().await;
    let active = update.await.unwrap().unwrap();

    assert_eq!(active.state(), FiberState::Active);
    assert!(active.error().is_none());
    assert_eq!(starts.load(Ordering::SeqCst), 2);
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn racing_updates_and_provider_refresh_commit_only_latest_tuple() {
    let observations = Arc::new(Mutex::new(Vec::<(String, u32)>::new()));
    let (cleanup_tx, cleanup_rx) = tokio::sync::oneshot::channel();
    let cleanup_tx = Arc::new(Mutex::new(Some(cleanup_tx)));
    let cleanup_release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("latest-tuple", {
        let observations = observations.clone();
        let cleanup_tx = cleanup_tx.clone();
        let cleanup_release = cleanup_release.clone();
        move |config, ctx| {
            observations.lock().unwrap().push((
                config.as_str().unwrap().to_string(),
                *ctx.get::<u32>("dep").unwrap(),
            ));
            let cleanup_tx = cleanup_tx.clone();
            let cleanup_release = cleanup_release.clone();
            LifecycleEffect::disposer(LifecycleDisposer::new(move || async move {
                let sender = cleanup_tx.lock().unwrap().take();
                if let Some(sender) = sender {
                    let _ = sender.send(());
                    cleanup_release.wait().await;
                }
                Ok(())
            }))
        }
    })
    .with_inject(["dep"]);
    let registry = LifecycleRegistry::new();
    let provider = registry.provide("dep", 1_u32).unwrap();
    let handle = registry
        .mount(factory, ConfigValue::string("zero"))
        .unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();

    let first_update = tokio::spawn({
        let handle = handle.clone();
        async move { handle.update(ConfigValue::string("one")).await }
    });
    cleanup_rx.await.unwrap();
    let second_update = tokio::spawn({
        let handle = handle.clone();
        async move { handle.update(ConfigValue::string("two")).await }
    });
    let provider = registry.replace_provider(&provider, 2_u32).unwrap();
    assert_eq!(provider.generation(), 1);
    cleanup_release.wait().await;
    first_update.await.unwrap().unwrap();
    second_update.await.unwrap().unwrap();

    assert_eq!(
        *observations.lock().unwrap(),
        [("zero".to_string(), 1), ("two".to_string(), 2)]
    );
    let snapshot = handle.snapshot();
    assert_eq!(snapshot.state(), FiberState::Active);
    assert_eq!(snapshot.committed_epoch().unwrap().config_revision(), 2);
    assert_eq!(
        snapshot.committed_epoch().unwrap().dependencies()[0].generation(),
        1
    );
}

#[tokio::test]
async fn stale_guard_result_cannot_overwrite_rebound_provider_fact() {
    let guard_calls = Arc::new(AtomicUsize::new(0));
    let (guard_tx, guard_rx) = tokio::sync::oneshot::channel();
    let guard_tx = Arc::new(Mutex::new(Some(guard_tx)));
    let guard_release = Arc::new(std::sync::Barrier::new(2));
    let registry = LifecycleRegistry::new();
    let provider = registry
        .provide_guarded("dep", 1_u32, {
            let guard_calls = guard_calls.clone();
            let guard_tx = guard_tx.clone();
            let guard_release = guard_release.clone();
            move |_value| {
                if guard_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    if let Some(sender) = guard_tx.lock().unwrap().take() {
                        let _ = sender.send(());
                    }
                    guard_release.wait();
                }
                Ok(true)
            }
        })
        .unwrap();
    let factory =
        PluginFactory::new_lifecycle("guard-consumer", |_config, _ctx| LifecycleEffect::none())
            .with_inject(["dep"]);
    let mount = tokio::task::spawn_blocking({
        let registry = registry.clone();
        move || registry.mount(factory, ConfigValue::default())
    });

    guard_rx.await.unwrap();
    let rebound = registry.replace_provider(&provider, 2_u32).unwrap();
    assert_eq!(rebound.generation(), 1);
    guard_release.wait();
    let handle = mount.await.unwrap().unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();

    let snapshot = handle.snapshot();
    assert_eq!(
        snapshot.committed_epoch().unwrap().dependencies()[0].generation(),
        1
    );
    assert_eq!(registry.get::<u32>("dep").as_deref(), Some(&2));
    assert!(guard_calls.load(Ordering::SeqCst) >= 2);
}

#[tokio::test]
async fn guard_false_and_typed_error_keep_dependency_pending_and_run_lock_free() {
    let registry = LifecycleRegistry::new();
    registry.provide("guard-probe", 7_u8).unwrap();
    let phase = Arc::new(AtomicUsize::new(0));
    let expected = CordisError::PayloadType {
        name: "guard-rejected".to_string(),
    };
    let provider = registry
        .provide_guarded("guarded-dependency", 1_u32, {
            let registry = registry.clone();
            let phase = phase.clone();
            let expected = expected.clone();
            move |_value| {
                // This reacquires the registry from inside user guard code. It
                // would deadlock if reconcile retained the provider lock.
                assert_eq!(registry.get::<u8>("guard-probe").as_deref(), Some(&7));
                if phase.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok(false)
                } else {
                    Err(expected.clone())
                }
            }
        })
        .unwrap();
    let consumer = registry
        .mount(
            PluginFactory::new_lifecycle("guard-pending", |_config, _ctx| LifecycleEffect::none())
                .with_inject(["guarded-dependency"]),
            ConfigValue::default(),
        )
        .unwrap();

    let false_snapshot = consumer.await_current().await.unwrap();
    assert_eq!(false_snapshot.state(), FiberState::Pending);
    assert!(false_snapshot.diagnostics().is_empty());
    assert!(registry.get::<u32>("guarded-dependency").is_none());
    let replacement = registry.replace_provider(&provider, 2_u32).unwrap();
    assert_eq!(replacement.generation(), 1);

    let error_snapshot = consumer.await_current().await.unwrap();
    assert_eq!(error_snapshot.state(), FiberState::Pending);
    assert!(error_snapshot.diagnostics().iter().any(|diagnostic| {
        matches!(
            diagnostic,
            CordisError::ProviderGuard { namespace, key, source }
                if namespace == "root"
                    && key == "guarded-dependency"
                    && source.as_ref() == &expected
        )
    }));
}

#[test]
fn direct_provider_get_enforces_false_error_panic_and_reentrant_guards() {
    let registry = LifecycleRegistry::new();
    registry.provide("guard-reentrant-probe", 7_u8).unwrap();
    registry
        .provide_guarded("guard-false", 1_u32, {
            let registry = registry.clone();
            move |_value| {
                assert_eq!(
                    registry.get::<u8>("guard-reentrant-probe").as_deref(),
                    Some(&7)
                );
                Ok(false)
            }
        })
        .unwrap();
    registry
        .provide_guarded("guard-error", 2_u32, |_value| {
            Err(CordisError::PayloadType {
                name: "direct-get-guard-error".to_string(),
            })
        })
        .unwrap();
    registry
        .provide_guarded("guard-panic", 3_u32, |_value| {
            panic!("direct-get guard panic must be contained")
        })
        .unwrap();

    assert!(registry.get::<u32>("guard-false").is_none());
    assert!(registry.get::<u32>("guard-error").is_none());
    assert!(registry.get::<u32>("guard-panic").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_provider_get_never_returns_a_stale_revision_after_guard_release() {
    let (guard_tx, guard_rx) = tokio::sync::oneshot::channel();
    let guard_tx = Arc::new(Mutex::new(Some(guard_tx)));
    let guard_release = Arc::new(std::sync::Barrier::new(2));
    let registry = LifecycleRegistry::new();
    let provider = registry
        .provide_guarded("guard-revision", 1_u32, {
            let guard_tx = guard_tx.clone();
            let guard_release = guard_release.clone();
            move |_value| {
                if let Some(sender) = guard_tx.lock().unwrap().take() {
                    let _ = sender.send(());
                    guard_release.wait();
                }
                Ok(true)
            }
        })
        .unwrap();
    let read = tokio::task::spawn_blocking({
        let registry = registry.clone();
        move || registry.get::<u32>("guard-revision")
    });

    guard_rx.await.unwrap();
    let replacement = registry.replace_provider(&provider, 2_u32).unwrap();
    guard_release.wait();

    assert!(read.await.unwrap().is_none());
    assert_eq!(replacement.generation(), 1);
    assert_eq!(registry.get::<u32>("guard-revision").as_deref(), Some(&2));
}

#[tokio::test]
async fn dropped_delete_waiter_keeps_runtime_deleting_until_cleanup_then_allows_fresh_generation() {
    let starts = Arc::new(AtomicUsize::new(0));
    let (cleanup_tx, cleanup_rx) = tokio::sync::oneshot::channel();
    let cleanup_tx = Arc::new(Mutex::new(Some(cleanup_tx)));
    let cleanup_release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("delete-race", {
        let starts = starts.clone();
        let cleanup_tx = cleanup_tx.clone();
        let cleanup_release = cleanup_release.clone();
        move |_config, _ctx| {
            starts.fetch_add(1, Ordering::SeqCst);
            let cleanup_tx = cleanup_tx.clone();
            let cleanup_release = cleanup_release.clone();
            LifecycleEffect::disposer(LifecycleDisposer::new(move || async move {
                let sender = cleanup_tx.lock().unwrap().take();
                if let Some(sender) = sender {
                    let _ = sender.send(());
                    cleanup_release.wait().await;
                }
                Ok(())
            }))
        }
    });
    let registry = LifecycleRegistry::new();
    let old = registry
        .mount(factory.clone(), ConfigValue::default())
        .unwrap();
    old.fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    drop(registry.begin_delete_factory(&factory).unwrap());
    cleanup_rx.await.unwrap();
    assert!(matches!(
        registry.mount(factory.clone(), ConfigValue::default()),
        Err(CordisError::RuntimeDeleting { .. })
    ));
    cleanup_release.wait().await;
    registry.delete_factory(&factory).await.unwrap();
    assert_eq!(registry.runtime_count(), 0);

    let fresh = registry
        .mount(factory.clone(), ConfigValue::default())
        .unwrap();
    fresh
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    assert_ne!(old.fiber().uid(), fresh.fiber().uid());
    assert_eq!(starts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn factory_clone_identity_shares_runtime_and_catalog_label_cannot_forge_it() {
    let factory = PluginFactory::new_lifecycle("identity", |_config, _ctx| LifecycleEffect::none());
    let impostor =
        PluginFactory::new_lifecycle("identity", |_config, _ctx| LifecycleEffect::none());
    let registry = LifecycleRegistry::new();
    let left = registry
        .mount(factory.clone(), ConfigValue::default())
        .unwrap();
    let right = registry
        .mount(factory.clone(), ConfigValue::default())
        .unwrap();
    left.fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    right
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    assert_ne!(left.fiber().uid(), right.fiber().uid());
    assert_eq!(registry.runtime_count(), 1);

    assert!(matches!(
        registry.mount(impostor, ConfigValue::default()),
        Err(CordisError::PluginCatalogConflict { .. })
    ));
    assert_eq!(registry.runtime_count(), 1);
}

#[tokio::test]
async fn activation_metadata_is_reset_to_baseline_before_reload() {
    let seen_before_write = Arc::new(Mutex::new(Vec::new()));
    let factory = PluginFactory::new_lifecycle("metadata-epoch", {
        let seen_before_write = seen_before_write.clone();
        move |_config, ctx| {
            seen_before_write
                .lock()
                .unwrap()
                .push(ctx.var("callback-only"));
            ctx.set_var("callback-only", "owned-by-this-epoch")?;
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    handle.update(ConfigValue::default()).await.unwrap();

    assert_eq!(*seen_before_write.lock().unwrap(), [None, None]);
}

#[tokio::test]
async fn successful_provisional_child_mount_reenters_without_lock_and_is_parent_owned() {
    let (child_tx, child_rx) = tokio::sync::oneshot::channel();
    let child_tx = Arc::new(Mutex::new(Some(child_tx)));
    let child_factory =
        PluginFactory::new_lifecycle("nested-child", |_config, _ctx| LifecycleEffect::none());
    let parent_factory = PluginFactory::new_lifecycle("nested-parent", {
        let child_factory = child_factory.clone();
        let child_tx = child_tx.clone();
        move |_config, ctx| {
            let child = ctx.mount(child_factory.clone(), ConfigValue::default())?;
            if let Some(sender) = child_tx.lock().unwrap().take() {
                let _ = sender.send(child);
            }
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        }
    });
    let registry = LifecycleRegistry::new();
    let parent = registry
        .mount(parent_factory, ConfigValue::default())
        .unwrap();
    let child = child_rx.await.unwrap();
    parent
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    child
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    assert_eq!(child.parent_uid(), Some(parent.fiber().uid()));

    parent.dispose_async().await.unwrap();
    assert_eq!(
        child.await_current().await.unwrap().state(),
        FiberState::Disposed
    );
}

#[tokio::test]
async fn one_shot_handle_rejects_restart_and_update_before_state_change() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_factory = calls.clone();
    let factory = PluginFactory::one_shot_lifecycle("one-shot-handle", move |_config, _ctx| {
        calls_for_factory.fetch_add(1, Ordering::SeqCst);
        LifecycleEffect::none()
    });
    let registry = LifecycleRegistry::new();
    let handle = registry
        .mount(factory, ConfigValue::string("initial"))
        .unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    let before = handle.snapshot();
    assert!(matches!(
        handle.restart().await,
        Err(CordisError::NonRepeatableFactory { .. })
    ));
    assert!(matches!(
        handle.update(ConfigValue::string("forbidden")).await,
        Err(CordisError::NonRepeatableFactory { .. })
    ));
    assert_eq!(handle.snapshot(), before);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn repeated_root_restart_keeps_root_and_child_ids_and_reloads_each_time() {
    let calls = Arc::new(AtomicUsize::new(0));
    let cleanups = Arc::new(AtomicUsize::new(0));
    let factory = PluginFactory::new_lifecycle("root-success", {
        let calls = calls.clone();
        let cleanups = cleanups.clone();
        move |_config, _ctx| {
            calls.fetch_add(1, Ordering::SeqCst);
            let cleanups = cleanups.clone();
            LifecycleEffect::disposer(LifecycleDisposer::sync(move || {
                cleanups.fetch_add(1, Ordering::SeqCst);
            }))
        }
    });
    let registry = LifecycleRegistry::new();
    let root_uid = registry.root_fiber().uid();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let child_uid = handle.fiber().uid();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    let first = registry.restart_root().await.unwrap();
    let second = registry.restart_root().await.unwrap();

    assert_eq!(root_uid, FiberUid::ROOT);
    assert_eq!(registry.root_fiber().uid(), root_uid);
    assert_eq!(handle.fiber().uid(), child_uid);
    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
    assert_eq!(first[0].state(), FiberState::Active);
    assert_eq!(second[0].state(), FiberState::Active);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(cleanups.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn dropping_wait_until_active_does_not_cancel_registry_owned_start() {
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("drop-start-waiter", {
        let entered_tx = entered_tx.clone();
        let release = release.clone();
        move |_config, _ctx| {
            if let Some(sender) = entered_tx.lock().unwrap().take() {
                let _ = sender.send(());
            }
            let release = release.clone();
            LifecycleEffect::future(async move {
                release.wait().await;
                Ok(None)
            })
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    entered_rx.await.unwrap();
    let waiter = tokio::spawn({
        let fiber = handle.fiber();
        async move {
            fiber
                .wait_until_active(LifecycleCancellation::default())
                .await
        }
    });
    waiter.abort();
    let _ = waiter.await;
    release.wait().await;

    assert_eq!(
        handle
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap()
            .state(),
        FiberState::Active
    );
}

#[tokio::test]
async fn missing_dependency_then_provider_transitions_pending_loading_active() {
    let starts = Arc::new(AtomicUsize::new(0));
    let starts_for_factory = starts.clone();
    let factory = PluginFactory::new_lifecycle("consumer", move |_config, _ctx| {
        starts_for_factory.fetch_add(1, Ordering::SeqCst);
        LifecycleEffect::none()
    })
    .with_inject(["dep"]);
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();

    assert_eq!(handle.snapshot().state(), FiberState::Pending);
    assert_eq!(
        handle.await_current().await.unwrap().state(),
        FiberState::Pending
    );
    let provider = registry.provide("dep", 7_u32).unwrap();
    let active = handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();

    assert_eq!(active.state(), FiberState::Active);
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(
        handle.fiber().state_history(),
        [FiberState::Pending, FiberState::Loading, FiberState::Active]
    );
    registry.remove_provider(&provider).await.unwrap();
}

#[tokio::test]
async fn provisional_provider_is_never_visible_when_start_fails() {
    let dependent_starts = Arc::new(AtomicUsize::new(0));
    let dependent_starts_for_factory = dependent_starts.clone();
    let dependent = PluginFactory::new_lifecycle("dependent", move |_config, _ctx| {
        dependent_starts_for_factory.fetch_add(1, Ordering::SeqCst);
        LifecycleEffect::none()
    })
    .with_inject(["provisional"]);
    let provider = PluginFactory::new_lifecycle("failing-provider", |_config, ctx| {
        ctx.provide("provisional", 9_u32)?;
        Err::<LifecycleEffect, CordisError>(CordisError::PayloadType {
            name: "intentional-start-failure".to_string(),
        })
    });
    let registry = LifecycleRegistry::new();
    let dependent = registry.mount(dependent, ConfigValue::default()).unwrap();
    let provider = registry.mount(provider, ConfigValue::default()).unwrap();

    assert!(matches!(
        provider.await_current().await,
        Err(CordisError::PayloadType { ref name }) if name == "intentional-start-failure"
    ));
    assert_eq!(provider.snapshot().state(), FiberState::Failed);
    assert!(registry.get::<u32>("provisional").is_none());
    assert_eq!(dependent.snapshot().state(), FiberState::Pending);
    assert_eq!(dependent_starts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn provisional_provider_publishes_only_with_active_commit() {
    let dependent_starts = Arc::new(AtomicUsize::new(0));
    let dependent_starts_for_factory = dependent_starts.clone();
    let dependent = PluginFactory::new_lifecycle("dependent-success", move |_config, _ctx| {
        dependent_starts_for_factory.fetch_add(1, Ordering::SeqCst);
        LifecycleEffect::none()
    })
    .with_inject(["committed"]);

    let (registered_tx, registered_rx) = tokio::sync::oneshot::channel();
    let registered_tx = Arc::new(Mutex::new(Some(registered_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let provider = PluginFactory::new_lifecycle("successful-provider", {
        let registered_tx = registered_tx.clone();
        let release = release.clone();
        move |_config, ctx| {
            ctx.provide("committed", 11_u32)?;
            if let Some(sender) = registered_tx.lock().unwrap().take() {
                let _ = sender.send(());
            }
            let release = release.clone();
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::future(async move {
                release.wait().await;
                Ok(None)
            }))
        }
    });
    let registry = LifecycleRegistry::new();
    let dependent = registry.mount(dependent, ConfigValue::default()).unwrap();
    let provider = registry.mount(provider, ConfigValue::default()).unwrap();

    registered_rx.await.unwrap();
    assert_eq!(provider.snapshot().state(), FiberState::Loading);
    assert!(registry.get::<u32>("committed").is_none());
    assert_eq!(dependent.snapshot().state(), FiberState::Pending);
    release.wait().await;
    provider
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    dependent
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();

    assert_eq!(registry.get::<u32>("committed").as_deref(), Some(&11));
    assert_eq!(dependent_starts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn provider_remove_during_loading_unloads_once_then_pending() {
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("loading-removal", {
        let entered_tx = entered_tx.clone();
        let release = release.clone();
        let cleanup_calls = cleanup_calls.clone();
        move |_config, _ctx| {
            if let Some(sender) = entered_tx.lock().unwrap().take() {
                let _ = sender.send(());
            }
            let release = release.clone();
            let cleanup_calls = cleanup_calls.clone();
            LifecycleEffect::future(async move {
                release.wait().await;
                Ok(Some(LifecycleDisposer::sync(move || {
                    cleanup_calls.fetch_add(1, Ordering::SeqCst);
                })))
            })
        }
    })
    .with_inject(["dep"]);
    let registry = LifecycleRegistry::new();
    let provider = registry.provide("dep", 1_u32).unwrap();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();

    entered_rx.await.unwrap();
    assert_eq!(handle.snapshot().state(), FiberState::Loading);
    let removal = registry.begin_remove_provider(&provider).unwrap();
    release.wait().await;
    removal.await.unwrap();
    let settled = handle.await_current().await.unwrap();

    assert_eq!(settled.state(), FiberState::Pending);
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        handle.fiber().state_history(),
        [
            FiberState::Pending,
            FiberState::Loading,
            FiberState::Unloading,
            FiberState::Pending,
        ]
    );
}

#[tokio::test]
async fn await_current_waiters_capture_distinct_tickets_but_settle_on_latest_commit() {
    let (cleanup_tx, cleanup_rx) = tokio::sync::oneshot::channel();
    let cleanup_tx = Arc::new(Mutex::new(Some(cleanup_tx)));
    let cleanup_release = Arc::new(tokio::sync::Barrier::new(2));
    let starts = Arc::new(AtomicUsize::new(0));
    let factory = PluginFactory::new_lifecycle("await-ticket-linearization", {
        let cleanup_tx = cleanup_tx.clone();
        let cleanup_release = cleanup_release.clone();
        let starts = starts.clone();
        move |_config, _ctx| {
            starts.fetch_add(1, Ordering::SeqCst);
            let cleanup_tx = cleanup_tx.clone();
            let cleanup_release = cleanup_release.clone();
            LifecycleEffect::disposer(LifecycleDisposer::new(move || async move {
                let sender = cleanup_tx.lock().unwrap().take();
                if let Some(sender) = sender {
                    let _ = sender.send(());
                    cleanup_release.wait().await;
                }
                Ok(())
            }))
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry
        .mount(factory, ConfigValue::string("initial"))
        .unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();

    let first_update_handle = handle.clone();
    let mut first_update = Box::pin(first_update_handle.update(ConfigValue::string("first")));
    assert!(first_update.as_mut().now_or_never().is_none());
    cleanup_rx.await.unwrap();
    let first_waiter_handle = handle.clone();
    let mut first_waiter = Box::pin(first_waiter_handle.await_current());
    assert!(first_waiter.as_mut().now_or_never().is_none());
    let first_ticket = handle.snapshot().ticket().unwrap().serial();

    let second_update_handle = handle.clone();
    let mut second_update = Box::pin(second_update_handle.update(ConfigValue::string("second")));
    assert!(second_update.as_mut().now_or_never().is_none());
    let second_waiter_handle = handle.clone();
    let mut second_waiter = Box::pin(second_waiter_handle.await_current());
    assert!(second_waiter.as_mut().now_or_never().is_none());
    let second_ticket = handle.snapshot().ticket().unwrap().serial();
    assert!(second_ticket > first_ticket);
    cleanup_release.wait().await;

    let first_update_snapshot = first_update.await.unwrap();
    let second_update_snapshot = second_update.await.unwrap();
    let first_waiter_snapshot = first_waiter.await.unwrap();
    let second_waiter_snapshot = second_waiter.await.unwrap();
    assert_eq!(first_waiter_snapshot, second_waiter_snapshot);
    assert_eq!(first_update_snapshot, second_update_snapshot);
    assert_eq!(first_waiter_snapshot, second_update_snapshot);
    assert_eq!(first_waiter_snapshot.state(), FiberState::Active);
    assert_eq!(
        first_waiter_snapshot
            .committed_epoch()
            .unwrap()
            .config_revision(),
        2
    );
    assert_eq!(starts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn root_restart_linearizes_before_concurrent_one_shot_mount_without_restarting_it() {
    let repeatable_starts = Arc::new(AtomicUsize::new(0));
    let repeatable_cleanups = Arc::new(AtomicUsize::new(0));
    let repeatable = PluginFactory::new_lifecycle("restart-first-repeatable", {
        let repeatable_starts = repeatable_starts.clone();
        let repeatable_cleanups = repeatable_cleanups.clone();
        move |_config, _ctx| {
            repeatable_starts.fetch_add(1, Ordering::SeqCst);
            let repeatable_cleanups = repeatable_cleanups.clone();
            LifecycleEffect::disposer(LifecycleDisposer::sync(move || {
                repeatable_cleanups.fetch_add(1, Ordering::SeqCst);
            }))
        }
    });
    let one_shot_starts = Arc::new(AtomicUsize::new(0));
    let one_shot = PluginFactory::one_shot_lifecycle("restart-first-one-shot", {
        let one_shot_starts = one_shot_starts.clone();
        move |_config, _ctx| {
            one_shot_starts.fetch_add(1, Ordering::SeqCst);
            LifecycleEffect::none()
        }
    });
    let registry = LifecycleRegistry::new();
    let repeatable = registry.mount(repeatable, ConfigValue::default()).unwrap();
    repeatable
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();

    // Poll once to complete the registry+all-machine linearization without
    // yielding this current-thread runtime to the worker.
    let mut restart = Box::pin(registry.restart_root());
    assert!(restart.as_mut().now_or_never().is_none());
    let one_shot = registry.mount(one_shot, ConfigValue::default()).unwrap();
    assert_eq!(restart.await.unwrap().len(), 1);
    one_shot
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();

    assert_eq!(repeatable_starts.load(Ordering::SeqCst), 2);
    assert_eq!(repeatable_cleanups.load(Ordering::SeqCst), 1);
    assert_eq!(one_shot_starts.load(Ordering::SeqCst), 1);
}

#[test]
fn owned_async_begin_operations_fail_before_mutation_without_a_runtime() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (registry, provider, factory, handle) = runtime.block_on(async {
        let registry = LifecycleRegistry::new();
        let provider = registry.provide("runtime-required", 1_u32).unwrap();
        let factory = PluginFactory::new_lifecycle("runtime-required", |_config, _ctx| {
            LifecycleEffect::none()
        });
        let handle = registry
            .mount(factory.clone(), ConfigValue::default())
            .unwrap();
        handle
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        (registry, provider, factory, handle)
    });
    drop(runtime);
    let before = handle.snapshot();

    assert!(matches!(
        handle.restart().now_or_never(),
        Some(Err(CordisError::AsyncRuntimeUnavailable))
    ));
    assert!(matches!(
        handle
            .update(ConfigValue::string("forbidden"))
            .now_or_never(),
        Some(Err(CordisError::AsyncRuntimeUnavailable))
    ));
    assert!(matches!(
        handle.dispose_async().now_or_never(),
        Some(Err(CordisError::AsyncRuntimeUnavailable))
    ));
    assert!(matches!(
        registry.restart_root().now_or_never(),
        Some(Err(CordisError::AsyncRuntimeUnavailable))
    ));
    assert!(matches!(
        registry.begin_remove_provider(&provider),
        Err(CordisError::AsyncRuntimeUnavailable)
    ));
    assert!(matches!(
        registry.begin_delete_factory(&factory),
        Err(CordisError::AsyncRuntimeUnavailable)
    ));
    assert!(matches!(
        registry.begin_shutdown(),
        Err(CordisError::AsyncRuntimeUnavailable)
    ));
    assert_eq!(handle.snapshot(), before);
    assert_eq!(registry.runtime_count(), 1);
    assert_eq!(registry.get::<u32>("runtime-required").as_deref(), Some(&1));
}

#[test]
fn lifecycle_commands_reject_a_replacement_runtime_without_mutation_or_waiting() {
    let original_runtime = tokio::runtime::Runtime::new().unwrap();
    let (registry, handle) = original_runtime.block_on(async {
        let registry = LifecycleRegistry::new();
        let handle = registry
            .mount(
                PluginFactory::new_lifecycle("runtime-identity", |_config, _ctx| {
                    LifecycleEffect::none()
                }),
                ConfigValue::default(),
            )
            .unwrap();
        handle
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        (registry, handle)
    });
    drop(original_runtime);
    let before = handle.snapshot();
    let runtime_count = registry.runtime_count();

    let replacement_runtime = tokio::runtime::Runtime::new().unwrap();
    replacement_runtime.block_on(async {
        assert!(matches!(
            handle.restart().now_or_never(),
            Some(Err(CordisError::AsyncRuntimeUnavailable))
        ));
        assert!(matches!(
            handle
                .update(ConfigValue::string("must-not-commit"))
                .now_or_never(),
            Some(Err(CordisError::AsyncRuntimeUnavailable))
        ));
        assert!(matches!(
            handle.dispose_async().now_or_never(),
            Some(Err(CordisError::AsyncRuntimeUnavailable))
        ));
        assert!(matches!(
            registry.restart_root().now_or_never(),
            Some(Err(CordisError::AsyncRuntimeUnavailable))
        ));
    });

    assert_eq!(handle.snapshot(), before);
    assert_eq!(registry.runtime_count(), runtime_count);
}
