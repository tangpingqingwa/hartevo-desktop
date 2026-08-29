use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::{FutureExt, stream};
use hartevo_cordis::{
    ConfigValue, Context, CordisError, FiberState, LifecycleCancellation, LifecycleDisposer,
    LifecycleEffect, LifecycleRegistry, PluginFactory,
};

#[tokio::test]
async fn lifecycle_disposer_is_exactly_once_across_clones() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_disposer = Arc::clone(&calls);
    let disposer = LifecycleDisposer::new(move || async move {
        calls_for_disposer.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });

    let (left, right) = tokio::join!(disposer.dispose_async(), disposer.dispose_async());
    left.unwrap();
    right.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(disposer.is_disposed());
}

#[tokio::test]
async fn cancelled_first_waiter_does_not_orphan_the_disposer_future() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_disposer = Arc::clone(&calls);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let disposer = LifecycleDisposer::new(move || async move {
        let _ = started_tx.send(());
        let _ = release_rx.await;
        calls_for_disposer.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });

    let first = tokio::spawn({
        let disposer = disposer.clone();
        async move { disposer.dispose_async().await }
    });
    started_rx.await.unwrap();
    first.abort();
    let _ = first.await;

    release_tx.send(()).unwrap();
    disposer.dispose_async().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(disposer.is_disposed());
}

#[tokio::test]
async fn disposer_panics_are_typed_and_cached_for_later_callers() {
    let sync = LifecycleDisposer::sync(|| panic!("sync cleanup panic"));
    let first = sync.dispose_async().await.unwrap_err();
    let second = sync.dispose_async().await.unwrap_err();
    assert_eq!(first, second);
    assert!(matches!(
        first,
        hartevo_cordis::CordisError::CleanupPanicked { ref message }
            if message == "sync cleanup panic"
    ));

    let asynchronous = LifecycleDisposer::new(|| async {
        panic!("async cleanup panic");
        #[allow(unreachable_code)]
        Ok(())
    });
    assert!(matches!(
        asynchronous.dispose_async().await,
        Err(hartevo_cordis::CordisError::CleanupPanicked { ref message })
            if message == "async cleanup panic"
    ));
}

#[test]
fn lifecycle_effect_exposes_sync_and_async_shapes() {
    let disposer = LifecycleDisposer::sync(|| {});
    assert!(!LifecycleEffect::disposer(disposer.clone()).is_async());
    assert!(!LifecycleEffect::collection([disposer]).is_async());
    assert!(LifecycleEffect::future(async { Ok(None) }).is_async());
}

#[test]
fn legacy_context_accepts_sync_disposer_and_collection_in_reverse_order() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let factory = PluginFactory::new("legacy-sync-effects", {
        let order = order.clone();
        move |_config, _ctx| {
            let first_order = order.clone();
            let second_order = order.clone();
            LifecycleEffect::collection([
                LifecycleDisposer::sync(move || first_order.lock().unwrap().push("first")),
                LifecycleDisposer::sync(move || second_order.lock().unwrap().push("second")),
            ])
        }
    });
    let mut context = Context::new();
    context.mount_pending(factory).unwrap();
    assert!(order.lock().unwrap().is_empty());
    context.teardown();
    assert_eq!(*order.lock().unwrap(), ["second", "first"]);
}

#[test]
fn legacy_context_rejects_future_before_registration_mutation() {
    let mut context = Context::new();
    let before = context.registration_count();
    let factory = PluginFactory::new("legacy-async-rejected", |_config, _ctx| {
        LifecycleEffect::future(async { Ok(None) })
    });
    let error = context.mount_pending(factory).unwrap_err();
    assert!(matches!(
        error,
        CordisError::PluginActivation { source, .. }
            if matches!(*source, CordisError::AsyncEffectRequiresFiber)
    ));
    assert_eq!(context.registration_count(), before);
}

#[tokio::test]
async fn runtime_collection_disposes_nested_newest_first() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let factory = PluginFactory::new_lifecycle("runtime-reverse", {
        let order = order.clone();
        move |_config, _ctx| {
            let first_order = order.clone();
            let second_order = order.clone();
            LifecycleEffect::collection([
                LifecycleDisposer::sync(move || first_order.lock().unwrap().push("first")),
                LifecycleDisposer::sync(move || second_order.lock().unwrap().push("second")),
            ])
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    handle.dispose_async().await.unwrap();
    assert_eq!(*order.lock().unwrap(), ["second", "first"]);
}

#[tokio::test]
async fn distinct_top_level_effects_begin_cleanup_concurrently() {
    let entered = Arc::new(tokio::sync::Barrier::new(3));
    let calls = Arc::new(AtomicUsize::new(0));
    let factory = PluginFactory::new_lifecycle("concurrent-cleanup", {
        let entered = entered.clone();
        let calls = calls.clone();
        move |_config, ctx| {
            let left_entered = entered.clone();
            let left_calls = calls.clone();
            ctx.effect(LifecycleEffect::disposer(LifecycleDisposer::new(
                move || async move {
                    left_entered.wait().await;
                    left_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )))?;
            let right_entered = entered.clone();
            let right_calls = calls.clone();
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::disposer(LifecycleDisposer::new(
                move || async move {
                    right_entered.wait().await;
                    right_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )))
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    let disposal = tokio::spawn({
        let handle = handle.clone();
        async move { handle.dispose_async().await }
    });
    entered.wait().await;
    disposal.await.unwrap().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn stream_cancellation_stops_before_polling_after_next_yield() {
    let cleanup_order = Arc::new(Mutex::new(Vec::new()));
    let third_polls = Arc::new(AtomicUsize::new(0));
    let (second_tx, second_rx) = tokio::sync::oneshot::channel();
    let second_tx = Arc::new(Mutex::new(Some(second_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("stream-cancel", {
        let cleanup_order = cleanup_order.clone();
        let third_polls = third_polls.clone();
        let second_tx = second_tx.clone();
        let release = release.clone();
        move |_config, _ctx| {
            let cleanup_order = cleanup_order.clone();
            let third_polls = third_polls.clone();
            let second_tx = second_tx.clone();
            let release = release.clone();
            LifecycleEffect::stream(stream::unfold(0_u8, move |index| {
                let cleanup_order = cleanup_order.clone();
                let third_polls = third_polls.clone();
                let second_tx = second_tx.clone();
                let release = release.clone();
                async move {
                    match index {
                        0 => {
                            let cleanup_order = cleanup_order.clone();
                            Some((
                                LifecycleDisposer::sync(move || {
                                    cleanup_order.lock().unwrap().push("first");
                                }),
                                1,
                            ))
                        }
                        1 => {
                            let sender = second_tx.lock().unwrap().take();
                            if let Some(sender) = sender {
                                let _ = sender.send(());
                            }
                            release.wait().await;
                            let cleanup_order = cleanup_order.clone();
                            Some((
                                LifecycleDisposer::sync(move || {
                                    cleanup_order.lock().unwrap().push("second");
                                }),
                                2,
                            ))
                        }
                        _ => {
                            third_polls.fetch_add(1, Ordering::SeqCst);
                            None
                        }
                    }
                }
            }))
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    second_rx.await.unwrap();
    let mut disposal = Box::pin(handle.dispose_async());
    assert!(disposal.as_mut().now_or_never().is_none());
    release.wait().await;
    disposal.await.unwrap();

    assert_eq!(third_polls.load(Ordering::SeqCst), 0);
    assert_eq!(*cleanup_order.lock().unwrap(), ["second", "first"]);
}

#[tokio::test]
async fn restart_same_epoch_cancels_old_stream_by_ticket_after_next_yield() {
    let cleanup_order = Arc::new(Mutex::new(Vec::new()));
    let third_polls = Arc::new(AtomicUsize::new(0));
    let activations = Arc::new(AtomicUsize::new(0));
    let (second_tx, second_rx) = tokio::sync::oneshot::channel();
    let second_tx = Arc::new(Mutex::new(Some(second_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("stream-restart-ticket", {
        let cleanup_order = cleanup_order.clone();
        let third_polls = third_polls.clone();
        let activations = activations.clone();
        let second_tx = second_tx.clone();
        let release = release.clone();
        move |_config, _ctx| {
            if activations.fetch_add(1, Ordering::SeqCst) != 0 {
                return LifecycleEffect::none();
            }
            let cleanup_order = cleanup_order.clone();
            let third_polls = third_polls.clone();
            let second_tx = second_tx.clone();
            let release = release.clone();
            LifecycleEffect::stream(stream::unfold(0_u8, move |index| {
                let cleanup_order = cleanup_order.clone();
                let third_polls = third_polls.clone();
                let second_tx = second_tx.clone();
                let release = release.clone();
                async move {
                    match index {
                        0 => {
                            let cleanup_order = cleanup_order.clone();
                            Some((
                                LifecycleDisposer::sync(move || {
                                    cleanup_order.lock().unwrap().push("first");
                                }),
                                1,
                            ))
                        }
                        1 => {
                            if let Some(sender) = second_tx.lock().unwrap().take() {
                                let _ = sender.send(());
                            }
                            release.wait().await;
                            let cleanup_order = cleanup_order.clone();
                            Some((
                                LifecycleDisposer::sync(move || {
                                    cleanup_order.lock().unwrap().push("second");
                                }),
                                2,
                            ))
                        }
                        _ => {
                            third_polls.fetch_add(1, Ordering::SeqCst);
                            None
                        }
                    }
                }
            }))
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    second_rx.await.unwrap();
    let mut restart = Box::pin(handle.restart());
    assert!(restart.as_mut().now_or_never().is_none());
    release.wait().await;

    assert_eq!(restart.await.unwrap().state(), FiberState::Active);
    assert_eq!(activations.load(Ordering::SeqCst), 2);
    assert_eq!(third_polls.load(Ordering::SeqCst), 0);
    assert_eq!(*cleanup_order.lock().unwrap(), ["second", "first"]);
}

#[tokio::test]
async fn cleanup_error_is_retained_as_diagnostic_without_skipping_terminal_state() {
    let expected = CordisError::PayloadType {
        name: "cleanup-diagnostic".to_string(),
    };
    let factory = PluginFactory::new_lifecycle("cleanup-error", {
        let expected = expected.clone();
        move |_config, _ctx| {
            let expected = expected.clone();
            LifecycleEffect::disposer(LifecycleDisposer::new(move || async move { Err(expected) }))
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    let terminal = handle.dispose_async().await.unwrap();

    assert_eq!(terminal.state(), FiberState::Disposed);
    assert!(terminal.diagnostics().contains(&expected));
}

#[tokio::test]
async fn manual_then_owner_disposal_consumes_one_callback_exactly_once() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (manual_tx, manual_rx) = tokio::sync::oneshot::channel();
    let manual_tx = Arc::new(Mutex::new(Some(manual_tx)));
    let factory = PluginFactory::new_lifecycle("manual-owner-idempotence", {
        let calls = calls.clone();
        let manual_tx = manual_tx.clone();
        move |_config, _ctx| {
            let calls = calls.clone();
            let disposer = LifecycleDisposer::sync(move || {
                calls.fetch_add(1, Ordering::SeqCst);
            });
            if let Some(sender) = manual_tx.lock().unwrap().take() {
                let _ = sender.send(disposer.clone());
            }
            LifecycleEffect::disposer(disposer)
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let manual = manual_rx.await.unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    manual.dispose_async().await.unwrap();
    handle.dispose_async().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn pending_future_and_dropped_shutdown_waiter_still_complete_owned_cleanup() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("shutdown-pending-future", {
        let calls = calls.clone();
        let entered_tx = entered_tx.clone();
        let release = release.clone();
        move |_config, _ctx| {
            let calls = calls.clone();
            let entered_tx = entered_tx.clone();
            let release = release.clone();
            LifecycleEffect::future(async move {
                if let Some(sender) = entered_tx.lock().unwrap().take() {
                    let _ = sender.send(());
                }
                release.wait().await;
                Ok(Some(LifecycleDisposer::sync(move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                })))
            })
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    entered_rx.await.unwrap();
    drop(handle);
    drop(registry.begin_shutdown().unwrap());
    release.wait().await;
    registry.shutdown().await.unwrap();

    assert_eq!(registry.runtime_count(), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
