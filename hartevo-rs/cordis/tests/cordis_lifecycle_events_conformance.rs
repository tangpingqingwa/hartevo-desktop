use std::convert::Infallible;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use hartevo_cordis::{
    ConfigValue, CordisError, Emit, EventKey, EventOptions, EventSchemaId, FiberState,
    LifecycleCancellation, LifecycleDisposer, LifecycleEffect, LifecycleEventDispatcher,
    LifecycleRegistry, PluginFactory,
};

const READY: EventKey<Emit, u32, ()> =
    EventKey::new(EventSchemaId::new("lifecycle-ready-v1"), "lifecycle-ready");
const REENTER: EventKey<Emit, u32, ()> = EventKey::new(
    EventSchemaId::new("lifecycle-reenter-v1"),
    "lifecycle-reenter",
);
const RESTARTED: EventKey<Emit, (), ()> = EventKey::new(
    EventSchemaId::new("lifecycle-restarted-v1"),
    "lifecycle-restarted",
);
const SCOPED: EventKey<Emit, (), ()> = EventKey::new(
    EventSchemaId::new("lifecycle-scoped-v1"),
    "lifecycle-scoped",
);
const ONCE: EventKey<Emit, (), ()> =
    EventKey::new(EventSchemaId::new("lifecycle-once-v1"), "lifecycle-once");
const PANICKING: EventKey<Emit, (), ()> = EventKey::new(
    EventSchemaId::new("lifecycle-panicking-v1"),
    "lifecycle-panicking",
);
const PREFLIGHT_U32: EventKey<Emit, u32, ()> = EventKey::new(
    EventSchemaId::new("lifecycle-preflight-u32-v1"),
    "lifecycle-preflight",
);
const PREFLIGHT_STRING: EventKey<Emit, String, ()> = EventKey::new(
    EventSchemaId::new("lifecycle-preflight-string-v1"),
    "lifecycle-preflight",
);
const DROP_REENTRY: EventKey<Emit, (), ()> = EventKey::new(
    EventSchemaId::new("lifecycle-drop-reentry-v1"),
    "lifecycle-drop-reentry",
);

struct DropSignal(Option<std::sync::mpsc::SyncSender<()>>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

struct ReenteringPanicOnDrop {
    dispatcher: LifecycleEventDispatcher,
    drops: Arc<AtomicUsize>,
}

impl Drop for ReenteringPanicOnDrop {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        self.dispatcher.emit(DROP_REENTRY, &()).unwrap();
        panic!("staged lifecycle capture drop panic");
    }
}

async fn bounded<F>(description: &'static str, future: F) -> F::Output
where
    F: Future,
{
    let (expired_tx, expired_rx) = tokio::sync::oneshot::channel();
    let (cancel_tx, cancel_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if matches!(
            cancel_rx.recv_timeout(Duration::from_secs(3)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            let _ = expired_tx.send(());
        }
    });
    tokio::pin!(future);
    tokio::select! {
        output = &mut future => {
            let _ = cancel_tx.send(());
            output
        }
        _ = expired_rx => panic!("timed out waiting for {description}"),
    }
}

#[tokio::test]
async fn loading_registration_is_invisible_until_active_then_owned_emit_runs() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (dispatcher_tx, dispatcher_rx) = tokio::sync::oneshot::channel();
    let dispatcher_tx = Arc::new(Mutex::new(Some(dispatcher_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("lifecycle-event-loading", {
        let calls = calls.clone();
        let dispatcher_tx = dispatcher_tx.clone();
        let release = release.clone();
        move |_, view| {
            let dispatcher = view.event_dispatcher()?;
            dispatcher.on_emit(READY, {
                let calls = calls.clone();
                move |value| {
                    calls.fetch_add(*value as usize, Ordering::SeqCst);
                }
            })?;
            if let Some(sender) = dispatcher_tx.lock().unwrap().take() {
                let _ = sender.send(dispatcher);
            }
            let release = release.clone();
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::future(async move {
                release.wait().await;
                Ok(None)
            }))
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let dispatcher = dispatcher_rx.await.unwrap();

    assert!(matches!(
        dispatcher.emit(READY, &1),
        Err(CordisError::StaleLifecycleView { .. })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    release.wait().await;
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    dispatcher.emit(READY, &3).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn same_generation_loading_reprovide_preserves_staged_event_identity() {
    let starts = Arc::new(AtomicUsize::new(0));
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let staged_calls = Arc::new(AtomicUsize::new(0));
    let dynamic_calls = Arc::new(AtomicUsize::new(0));
    let (dispatcher_tx, dispatcher_rx) = tokio::sync::oneshot::channel();
    let dispatcher_tx = Arc::new(Mutex::new(Some(dispatcher_tx)));
    let release = Arc::new(tokio::sync::Barrier::new(2));
    let factory = PluginFactory::new_lifecycle("lifecycle-event-loading-reprovide", {
        let starts = starts.clone();
        let cleanup_calls = cleanup_calls.clone();
        let staged_calls = staged_calls.clone();
        let dispatcher_tx = dispatcher_tx.clone();
        let release = release.clone();
        move |_, view| {
            starts.fetch_add(1, Ordering::SeqCst);
            let dispatcher = view.event_dispatcher()?;
            dispatcher.once_emit(READY, {
                let staged_calls = staged_calls.clone();
                move |_| {
                    staged_calls.fetch_add(1, Ordering::SeqCst);
                }
            })?;
            if let Some(sender) = dispatcher_tx.lock().unwrap().take() {
                let _ = sender.send(dispatcher);
            }
            let cleanup_calls = cleanup_calls.clone();
            let release = release.clone();
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::future(async move {
                release.wait().await;
                Ok(Some(LifecycleDisposer::sync(move || {
                    cleanup_calls.fetch_add(1, Ordering::SeqCst);
                })))
            }))
        }
    })
    .with_inject(["dep"]);
    let registry = LifecycleRegistry::new();
    let first = registry.provide("dep", 1_u32).unwrap();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let dispatcher = dispatcher_rx.await.unwrap();

    let removal = registry.begin_remove_provider(&first).unwrap();
    let second = registry.provide("dep", 2_u32).unwrap();
    assert_ne!(first.provider_id(), second.provider_id());
    assert_eq!(first.generation(), 0);
    assert_eq!(second.generation(), 0);

    release.wait().await;
    bounded(
        "same-generation Loading reprovide activation",
        handle
            .fiber()
            .wait_until_active(LifecycleCancellation::default()),
    )
    .await
    .unwrap();
    bounded("same-generation provider removal", removal)
        .await
        .unwrap();

    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(cleanup_calls.load(Ordering::SeqCst), 0);
    assert_eq!(registry.get::<u32>("dep").as_deref(), Some(&2));

    dispatcher
        .once_emit(READY, {
            let dynamic_calls = dynamic_calls.clone();
            move |_| {
                dynamic_calls.fetch_add(1, Ordering::SeqCst);
            }
        })
        .unwrap();
    dispatcher.emit(READY, &1).unwrap();
    dispatcher.emit(READY, &1).unwrap();
    assert_eq!(staged_calls.load(Ordering::SeqCst), 1);
    assert_eq!(dynamic_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn callback_reregistration_and_recursive_emit_use_the_next_snapshot() {
    let first_calls = Arc::new(AtomicUsize::new(0));
    let late_calls = Arc::new(AtomicUsize::new(0));
    let (dispatcher_tx, dispatcher_rx) = tokio::sync::oneshot::channel();
    let dispatcher_tx = Arc::new(Mutex::new(Some(dispatcher_tx)));
    let factory = PluginFactory::new_lifecycle("lifecycle-event-reentry", {
        let first_calls = first_calls.clone();
        let late_calls = late_calls.clone();
        let dispatcher_tx = dispatcher_tx.clone();
        move |_, view| {
            let dispatcher = view.event_dispatcher()?;
            let reentry = dispatcher.clone();
            dispatcher.on_emit(REENTER, {
                let first_calls = first_calls.clone();
                let late_calls = late_calls.clone();
                move |value| {
                    first_calls.fetch_add(1, Ordering::SeqCst);
                    if *value == 1 {
                        reentry
                            .try_on_emit(REENTER, {
                                let late_calls = late_calls.clone();
                                move |_| {
                                    late_calls.fetch_add(1, Ordering::SeqCst);
                                    Ok::<(), Infallible>(())
                                }
                            })
                            .unwrap();
                        reentry.emit(REENTER, &2).unwrap();
                    }
                }
            })?;
            if let Some(sender) = dispatcher_tx.lock().unwrap().take() {
                let _ = sender.send(dispatcher);
            }
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let dispatcher = dispatcher_rx.await.unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();

    dispatcher.emit(REENTER, &1).unwrap();
    assert_eq!(first_calls.load(Ordering::SeqCst), 2);
    assert_eq!(late_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn lifecycle_once_is_claimed_before_recursive_emit() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (dispatcher_tx, dispatcher_rx) = tokio::sync::oneshot::channel();
    let factory = PluginFactory::new_lifecycle("lifecycle-event-once", {
        let calls = calls.clone();
        let dispatcher_tx = Arc::new(Mutex::new(Some(dispatcher_tx)));
        move |_, view| {
            let dispatcher = view.event_dispatcher()?;
            let recursive = dispatcher.clone();
            dispatcher.once_emit(ONCE, {
                let calls = calls.clone();
                move |()| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    recursive.emit(ONCE, &()).unwrap();
                }
            })?;
            if let Some(sender) = dispatcher_tx.lock().unwrap().take() {
                let _ = sender.send(dispatcher);
            }
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let dispatcher = dispatcher_rx.await.unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();

    dispatcher.emit(ONCE, &()).unwrap();
    dispatcher.emit(ONCE, &()).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn callback_panic_releases_permits_and_a_restart_completes() {
    let (dispatchers_tx, mut dispatchers_rx) = tokio::sync::mpsc::unbounded_channel();
    let factory = PluginFactory::new_lifecycle("lifecycle-event-panic", move |_, view| {
        let dispatcher = view.event_dispatcher()?;
        dispatcher.on_emit(PANICKING, |()| panic!("lifecycle callback panic"))?;
        dispatchers_tx.send(dispatcher).unwrap();
        Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let first = dispatchers_rx.recv().await.unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();

    assert!(catch_unwind(AssertUnwindSafe(|| first.emit(PANICKING, &()))).is_err());
    bounded("restart after callback panic", handle.restart())
        .await
        .unwrap();
    let _second = dispatchers_rx.recv().await.unwrap();
    assert!(matches!(
        first.emit(PANICKING, &()),
        Err(CordisError::StaleLifecycleView { .. })
    ));
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one transaction oracle proves event, provider, mount, destructor, and recovery boundaries"
)]
async fn event_preflight_failure_rolls_back_provider_mount_and_panicking_captures() {
    let existing_calls = Arc::new(AtomicUsize::new(0));
    let drop_reentries = Arc::new(AtomicUsize::new(0));
    let (existing_tx, existing_rx) = tokio::sync::oneshot::channel();
    let existing_factory = PluginFactory::new_lifecycle("event-preflight-existing", {
        let existing_calls = existing_calls.clone();
        let drop_reentries = drop_reentries.clone();
        let sender = Arc::new(Mutex::new(Some(existing_tx)));
        move |_, view| {
            let dispatcher = view.event_dispatcher()?;
            dispatcher.on_emit(PREFLIGHT_U32, {
                let calls = existing_calls.clone();
                move |value| {
                    calls.fetch_add(*value as usize, Ordering::SeqCst);
                }
            })?;
            dispatcher.on_emit(DROP_REENTRY, {
                let calls = drop_reentries.clone();
                move |()| {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            })?;
            if let Some(sender) = sender.lock().unwrap().take() {
                let _ = sender.send(dispatcher);
            }
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        }
    });
    let registry = LifecycleRegistry::new();
    let existing_handle = registry
        .mount(existing_factory, ConfigValue::default())
        .unwrap();
    let existing = existing_rx.await.unwrap();
    existing_handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();

    let drops = Arc::new(AtomicUsize::new(0));
    let attempts = Arc::new(AtomicUsize::new(0));
    let (child_tx, child_rx) = tokio::sync::oneshot::channel();
    let child_tx = Arc::new(Mutex::new(Some(child_tx)));
    let (recovered_tx, mut recovered_rx) = tokio::sync::mpsc::unbounded_channel();
    let provisional_child = PluginFactory::new_lifecycle("event-preflight-child", |_, _| {
        Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
    });
    let failing_factory = PluginFactory::new_lifecycle("event-preflight-owner", {
        let drops = drops.clone();
        let attempts = attempts.clone();
        let existing = existing.clone();
        let child_tx = child_tx.clone();
        let provisional_child = provisional_child.clone();
        move |_, view| {
            let dispatcher = view.event_dispatcher()?;
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                view.provide("event-preflight-provider", 41_u32)?;
                let child = view.mount(provisional_child.clone(), ConfigValue::default())?;
                if let Some(sender) = child_tx.lock().unwrap().take() {
                    let _ = sender.send(child);
                }
                for _ in 0..2 {
                    let guard = ReenteringPanicOnDrop {
                        dispatcher: existing.clone(),
                        drops: drops.clone(),
                    };
                    dispatcher.on_emit(PREFLIGHT_STRING, move |_: &String| {
                        let _guard = &guard;
                    })?;
                }
            } else {
                dispatcher.on_emit(PREFLIGHT_U32, |_| {})?;
                recovered_tx.send(dispatcher).unwrap();
            }
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        }
    });
    let failing_handle = registry
        .mount(failing_factory.clone(), ConfigValue::default())
        .unwrap();
    let provisional_child = child_rx.await.unwrap();
    let failure = bounded(
        "event descriptor preflight failure",
        failing_handle.await_current(),
    )
    .await
    .unwrap_err();
    assert!(matches!(failure, CordisError::SchemaConflict { .. }));
    assert!(provisional_child.is_disposed());
    assert!(registry.get::<u32>("event-preflight-provider").is_none());
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert_eq!(drop_reentries.load(Ordering::SeqCst), 2);
    assert!(
        failing_handle
            .snapshot()
            .diagnostics()
            .iter()
            .any(|error| matches!(error, CordisError::CleanupPanicked { .. }))
    );
    existing.emit(PREFLIGHT_U32, &2).unwrap();
    assert_eq!(existing_calls.load(Ordering::SeqCst), 2);

    let delete_result = bounded(
        "delete failed event-preflight runtime",
        registry.delete_factory(&failing_factory),
    )
    .await;
    assert!(matches!(
        delete_result,
        Err(CordisError::SchemaConflict { .. })
    ));
    let recovered_handle = registry
        .mount(failing_factory, ConfigValue::default())
        .unwrap();
    let recovered = recovered_rx.recv().await.unwrap();
    bounded(
        "activation after event preflight rollback",
        recovered_handle
            .fiber()
            .wait_until_active(LifecycleCancellation::default()),
    )
    .await
    .unwrap();
    recovered.emit(PREFLIGHT_U32, &1).unwrap();
    assert_eq!(existing_calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn plain_restart_replaces_same_value_epoch_and_old_dispatcher_stays_stale() {
    let starts = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let (dispatchers_tx, mut dispatchers_rx) = tokio::sync::mpsc::unbounded_channel();
    let factory = PluginFactory::new_lifecycle("lifecycle-event-restart", {
        let starts = starts.clone();
        let calls = calls.clone();
        move |_, view| {
            starts.fetch_add(1, Ordering::SeqCst);
            let dispatcher = view.event_dispatcher()?;
            dispatcher.on_emit(RESTARTED, {
                let calls = calls.clone();
                move |()| {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            })?;
            dispatchers_tx.send(dispatcher).unwrap();
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::disposer(LifecycleDisposer::sync(
                || {},
            )))
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let first = dispatchers_rx.recv().await.unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    first.emit(RESTARTED, &()).unwrap();

    handle.restart().await.unwrap();
    let second = dispatchers_rx.recv().await.unwrap();
    assert!(matches!(
        first.emit(RESTARTED, &()),
        Err(CordisError::StaleLifecycleView { .. })
    ));
    second.emit(RESTARTED, &()).unwrap();
    assert_eq!(starts.load(Ordering::SeqCst), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn isolate_shared_and_global_filtering_matches_the_context_event_contract() {
    let (dispatchers_tx, mut dispatchers_rx) = tokio::sync::mpsc::unbounded_channel();
    let factory = PluginFactory::new_lifecycle("lifecycle-event-scope", move |_, view| {
        dispatchers_tx.send(view.event_dispatcher()?).unwrap();
        Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
    });
    let registry = LifecycleRegistry::new();
    let first_handle = registry
        .mount(factory.clone(), ConfigValue::default())
        .unwrap();
    let second_handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let first = dispatchers_rx.recv().await.unwrap();
    let second = dispatchers_rx.recv().await.unwrap();
    first_handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    second_handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();

    let default_first_calls = Arc::new(AtomicUsize::new(0));
    let default_second_calls = Arc::new(AtomicUsize::new(0));
    first
        .on_emit(SCOPED, {
            let calls = default_first_calls.clone();
            move |()| {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        })
        .unwrap();
    second
        .on_emit(SCOPED, {
            let calls = default_second_calls.clone();
            move |()| {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        })
        .unwrap();
    first.emit(SCOPED, &()).unwrap();
    assert_eq!(default_first_calls.load(Ordering::SeqCst), 1);
    assert_eq!(default_second_calls.load(Ordering::SeqCst), 1);

    let shared_first = first.clone().isolate("first").share_label("bridge");
    let shared_second = second.clone().isolate("second").share_label("bridge");
    let unrelated = second.isolate("unrelated");
    let shared_calls = Arc::new(AtomicUsize::new(0));
    let unrelated_calls = Arc::new(AtomicUsize::new(0));
    let global_calls = Arc::new(AtomicUsize::new(0));
    shared_first
        .on_emit(SCOPED, {
            let shared_calls = shared_calls.clone();
            move |()| {
                shared_calls.fetch_add(1, Ordering::SeqCst);
            }
        })
        .unwrap();
    unrelated
        .on_emit(SCOPED, {
            let unrelated_calls = unrelated_calls.clone();
            move |()| {
                unrelated_calls.fetch_add(1, Ordering::SeqCst);
            }
        })
        .unwrap();
    unrelated
        .on_emit_with_options(
            SCOPED,
            EventOptions {
                prepend: false,
                global: true,
            },
            {
                let global_calls = global_calls.clone();
                move |()| {
                    global_calls.fetch_add(1, Ordering::SeqCst);
                }
            },
        )
        .unwrap();

    shared_second.emit(SCOPED, &()).unwrap();
    assert_eq!(shared_calls.load(Ordering::SeqCst), 1);
    assert_eq!(unrelated_calls.load(Ordering::SeqCst), 0);
    assert_eq!(global_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn registries_with_the_same_default_namespace_remain_event_isolated() {
    let first_calls = Arc::new(AtomicUsize::new(0));
    let second_calls = Arc::new(AtomicUsize::new(0));
    let (first_tx, first_rx) = tokio::sync::oneshot::channel();
    let first_factory = PluginFactory::new_lifecycle("first-event-registry", {
        let calls = first_calls.clone();
        let sender = Arc::new(Mutex::new(Some(first_tx)));
        move |_, view| {
            let dispatcher = view.event_dispatcher()?;
            dispatcher.on_emit(SCOPED, {
                let calls = calls.clone();
                move |()| {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            })?;
            if let Some(sender) = sender.lock().unwrap().take() {
                let _ = sender.send(dispatcher);
            }
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        }
    });
    let (second_tx, second_rx) = tokio::sync::oneshot::channel();
    let second_factory = PluginFactory::new_lifecycle("second-event-registry", {
        let calls = second_calls.clone();
        let sender = Arc::new(Mutex::new(Some(second_tx)));
        move |_, view| {
            let dispatcher = view.event_dispatcher()?;
            dispatcher.on_emit(SCOPED, {
                let calls = calls.clone();
                move |()| {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            })?;
            if let Some(sender) = sender.lock().unwrap().take() {
                let _ = sender.send(dispatcher);
            }
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        }
    });
    let first_registry = LifecycleRegistry::new();
    let second_registry = LifecycleRegistry::new();
    let first_handle = first_registry
        .mount(first_factory, ConfigValue::default())
        .unwrap();
    let second_handle = second_registry
        .mount(second_factory, ConfigValue::default())
        .unwrap();
    let first = first_rx.await.unwrap();
    let second = second_rx.await.unwrap();
    first_handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    second_handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();

    first.emit(SCOPED, &()).unwrap();
    assert_eq!(first_calls.load(Ordering::SeqCst), 1);
    assert_eq!(second_calls.load(Ordering::SeqCst), 0);
    second.emit(SCOPED, &()).unwrap();
    assert_eq!(second_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn restart_waits_for_a_winning_emit_and_close_first_rejects_old_authority() {
    let entered = Arc::new(Mutex::new(None::<tokio::sync::oneshot::Sender<()>>));
    let release = Arc::new(Barrier::new(2));
    let (dispatchers_tx, mut dispatchers_rx) = tokio::sync::mpsc::unbounded_channel();
    let factory = PluginFactory::new_lifecycle("lifecycle-event-drain", {
        let entered = entered.clone();
        let release = release.clone();
        move |_, view| {
            let dispatcher = view.event_dispatcher()?;
            let entered = entered.clone();
            let release = release.clone();
            dispatcher.on_emit(RESTARTED, move |()| {
                if let Some(sender) = entered.lock().unwrap().take() {
                    let _ = sender.send(());
                }
                release.wait();
            })?;
            dispatchers_tx.send(dispatcher).unwrap();
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let first = dispatchers_rx.recv().await.unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    *entered.lock().unwrap() = Some(entered_tx);
    let emit = tokio::task::spawn_blocking({
        let first = first.clone();
        move || first.emit(RESTARTED, &())
    });
    entered_rx.await.unwrap();
    let restart = tokio::spawn({
        let handle = handle.clone();
        async move { handle.restart().await }
    });
    for _ in 0..8 {
        tokio::task::yield_now().await;
        assert!(!restart.is_finished());
    }
    tokio::task::spawn_blocking({
        let release = release.clone();
        move || release.wait()
    })
    .await
    .unwrap();
    emit.await.unwrap().unwrap();
    restart.await.unwrap().unwrap();
    let _second: LifecycleEventDispatcher = dispatchers_rx.recv().await.unwrap();
    assert!(matches!(
        first.emit(RESTARTED, &()),
        Err(CordisError::StaleLifecycleView { .. })
    ));
}

#[tokio::test]
async fn callback_reregistration_after_restart_close_fails_without_blocking_drain() {
    let entered = Arc::new(Mutex::new(None::<tokio::sync::oneshot::Sender<()>>));
    let attempt = Arc::new(Barrier::new(2));
    let registration_result = Arc::new(Mutex::new(
        None::<tokio::sync::oneshot::Sender<Result<(), CordisError>>>,
    ));
    let (dispatcher_tx, dispatcher_rx) = tokio::sync::oneshot::channel();
    let factory = PluginFactory::new_lifecycle("lifecycle-event-close-reentry", {
        let entered = entered.clone();
        let attempt = attempt.clone();
        let registration_result = registration_result.clone();
        let sender = Arc::new(Mutex::new(Some(dispatcher_tx)));
        move |_, view| {
            let dispatcher = view.event_dispatcher()?;
            let reentry = dispatcher.clone();
            dispatcher.on_emit(RESTARTED, {
                let entered = entered.clone();
                let attempt = attempt.clone();
                let registration_result = registration_result.clone();
                move |()| {
                    if let Some(sender) = entered.lock().unwrap().take() {
                        let _ = sender.send(());
                    }
                    attempt.wait();
                    let result = reentry.on_emit(RESTARTED, |()| {});
                    if let Some(sender) = registration_result.lock().unwrap().take() {
                        let _ = sender.send(result);
                    }
                }
            })?;
            if let Some(sender) = sender.lock().unwrap().take() {
                let _ = sender.send(dispatcher);
            }
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let dispatcher = dispatcher_rx.await.unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    *entered.lock().unwrap() = Some(entered_tx);
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    *registration_result.lock().unwrap() = Some(result_tx);
    let emit = tokio::task::spawn_blocking({
        let dispatcher = dispatcher.clone();
        move || dispatcher.emit(RESTARTED, &())
    });
    entered_rx.await.unwrap();
    let restart = tokio::spawn({
        let handle = handle.clone();
        async move { handle.restart().await }
    });
    bounded("restart entering event drain", async {
        loop {
            if handle.snapshot().state() == FiberState::Unloading {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    tokio::task::spawn_blocking(move || attempt.wait())
        .await
        .unwrap();
    assert!(matches!(
        result_rx.await.unwrap(),
        Err(CordisError::StaleLifecycleView { .. })
    ));
    emit.await.unwrap().unwrap();
    bounded("restart after closed callback reentry", restart)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn dispose_delete_remount_and_registry_drop_all_fail_old_dispatchers_closed() {
    let (dispose_tx, dispose_rx) = tokio::sync::oneshot::channel();
    let dispose_factory = PluginFactory::new_lifecycle("lifecycle-event-dispose", {
        let sender = Arc::new(Mutex::new(Some(dispose_tx)));
        move |_, view| {
            let dispatcher = view.event_dispatcher()?;
            dispatcher.on_emit(RESTARTED, |()| {})?;
            if let Some(sender) = sender.lock().unwrap().take() {
                let _ = sender.send(dispatcher);
            }
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        }
    });
    let dispose_registry = LifecycleRegistry::new();
    let dispose_handle = dispose_registry
        .mount(dispose_factory, ConfigValue::default())
        .unwrap();
    let disposed = dispose_rx.await.unwrap();
    dispose_handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    bounded("event owner disposal", dispose_handle.dispose_async())
        .await
        .unwrap();
    assert!(matches!(
        disposed.emit(RESTARTED, &()),
        Err(CordisError::StaleLifecycleView { .. })
    ));

    let (generation_tx, mut generation_rx) = tokio::sync::mpsc::unbounded_channel();
    let generation_factory =
        PluginFactory::new_lifecycle("lifecycle-event-generation", move |_, view| {
            let dispatcher = view.event_dispatcher()?;
            dispatcher.on_emit(RESTARTED, |()| {})?;
            generation_tx.send(dispatcher).unwrap();
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        });
    let generation_registry = LifecycleRegistry::new();
    let first_handle = generation_registry
        .mount(generation_factory.clone(), ConfigValue::default())
        .unwrap();
    let first = generation_rx.recv().await.unwrap();
    first_handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    bounded(
        "factory deletion",
        generation_registry.delete_factory(&generation_factory),
    )
    .await
    .unwrap();
    let second_handle = generation_registry
        .mount(generation_factory.clone(), ConfigValue::default())
        .unwrap();
    let second = generation_rx.recv().await.unwrap();
    second_handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    assert!(matches!(
        first.emit(RESTARTED, &()),
        Err(CordisError::StaleLifecycleView { .. })
    ));
    second.emit(RESTARTED, &()).unwrap();

    let (drop_tx, drop_rx) = tokio::sync::oneshot::channel();
    let drop_factory = PluginFactory::new_lifecycle("lifecycle-event-registry-drop", {
        let sender = Arc::new(Mutex::new(Some(drop_tx)));
        move |_, view| {
            let dispatcher = view.event_dispatcher()?;
            dispatcher.on_emit(RESTARTED, |()| {})?;
            if let Some(sender) = sender.lock().unwrap().take() {
                let _ = sender.send(dispatcher);
            }
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        }
    });
    let drop_registry = LifecycleRegistry::new();
    let drop_handle = drop_registry
        .mount(drop_factory, ConfigValue::default())
        .unwrap();
    let dropped = drop_rx.await.unwrap();
    drop_handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    drop(drop_handle);
    drop(drop_registry);
    assert!(matches!(
        dropped.emit(RESTARTED, &()),
        Err(CordisError::StaleLifecycleView { .. })
    ));
}

#[tokio::test]
async fn shutdown_waits_for_inflight_emit_then_clears_dispatch_authority() {
    let entered = Arc::new(Mutex::new(None::<tokio::sync::oneshot::Sender<()>>));
    let release = Arc::new(Barrier::new(2));
    let (dispatcher_tx, dispatcher_rx) = tokio::sync::oneshot::channel();
    let factory = PluginFactory::new_lifecycle("lifecycle-event-shutdown", {
        let entered = entered.clone();
        let release = release.clone();
        let sender = Arc::new(Mutex::new(Some(dispatcher_tx)));
        move |_, view| {
            let dispatcher = view.event_dispatcher()?;
            dispatcher.on_emit(RESTARTED, {
                let entered = entered.clone();
                let release = release.clone();
                move |()| {
                    if let Some(sender) = entered.lock().unwrap().take() {
                        let _ = sender.send(());
                    }
                    release.wait();
                }
            })?;
            if let Some(sender) = sender.lock().unwrap().take() {
                let _ = sender.send(dispatcher);
            }
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let dispatcher = dispatcher_rx.await.unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    *entered.lock().unwrap() = Some(entered_tx);
    let emit = tokio::task::spawn_blocking({
        let dispatcher = dispatcher.clone();
        move || dispatcher.emit(RESTARTED, &())
    });
    entered_rx.await.unwrap();
    let shutdown = tokio::spawn({
        let registry = registry.clone();
        async move { registry.shutdown().await }
    });
    for _ in 0..8 {
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished());
    }
    tokio::task::spawn_blocking({
        let release = release.clone();
        move || release.wait()
    })
    .await
    .unwrap();
    emit.await.unwrap().unwrap();
    bounded("shutdown after in-flight emit", shutdown)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        dispatcher.emit(RESTARTED, &()),
        Err(CordisError::StaleLifecycleView { .. })
    ));
}

#[tokio::test]
async fn emit_operation_lease_outlives_the_last_external_registry_handle() {
    let entered = Arc::new(Mutex::new(None::<tokio::sync::oneshot::Sender<()>>));
    let release = Arc::new(Barrier::new(2));
    let (capture_dropped_tx, capture_dropped_rx) = std::sync::mpsc::sync_channel(1);
    let capture = Arc::new(Mutex::new(Some(DropSignal(Some(capture_dropped_tx)))));
    let (dispatcher_tx, dispatcher_rx) = tokio::sync::oneshot::channel();
    let factory = PluginFactory::new_lifecycle("lifecycle-event-operation-lease", {
        let entered = entered.clone();
        let release = release.clone();
        let capture = capture.clone();
        let sender = Arc::new(Mutex::new(Some(dispatcher_tx)));
        move |_, view| {
            let dispatcher = view.event_dispatcher()?;
            let capture = capture
                .lock()
                .unwrap()
                .take()
                .expect("the first activation owns the drop signal");
            dispatcher.on_emit(RESTARTED, {
                let entered = entered.clone();
                let release = release.clone();
                move |()| {
                    let _capture = &capture;
                    if let Some(sender) = entered.lock().unwrap().take() {
                        let _ = sender.send(());
                    }
                    release.wait();
                }
            })?;
            if let Some(sender) = sender.lock().unwrap().take() {
                let _ = sender.send(dispatcher);
            }
            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
        }
    });
    let registry = LifecycleRegistry::new();
    let handle = registry.mount(factory, ConfigValue::default()).unwrap();
    let dispatcher = dispatcher_rx.await.unwrap();
    handle
        .fiber()
        .wait_until_active(LifecycleCancellation::default())
        .await
        .unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    *entered.lock().unwrap() = Some(entered_tx);
    let emit = tokio::task::spawn_blocking({
        let dispatcher = dispatcher.clone();
        move || dispatcher.emit(RESTARTED, &())
    });
    entered_rx.await.unwrap();
    drop(handle);
    drop(registry);
    assert!(matches!(
        capture_dropped_rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    tokio::task::spawn_blocking(move || release.wait())
        .await
        .unwrap();
    emit.await.unwrap().unwrap();
    tokio::task::spawn_blocking(move || {
        capture_dropped_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("callback capture must drop when the operation lease releases");
    })
    .await
    .unwrap();
    assert!(matches!(
        dispatcher.emit(RESTARTED, &()),
        Err(CordisError::StaleLifecycleView { .. })
    ));
}
