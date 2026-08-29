//! Public N0 attack and lifecycle oracles.
//!
//! This integration crate intentionally imports only the public API. Private
//! surface mapping and authority tokens are exercised by in-crate unit tests.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{Duration, TimeZone, Utc};
use hartevo_cordis::{
    Context, CordisError, DomainSurface, EffectBrokerSurface, FiberState, KernelApproval,
    KernelApprovalDecision, KernelConsentState, PluginFactory, SurfaceOwner, keys,
};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 25, 13, 34, 33).unwrap()
}

#[test]
fn public_context_cannot_replace_hartevo_domain_or_effect() {
    let mut host = hartevo_cordis::CordisHost::boot(true).unwrap();
    host.bind_domain_kernel(
        KernelConsentState::Confirmed,
        None,
        Some(KernelApproval {
            decision: KernelApprovalDecision::Approved,
            valid_until: now() + Duration::minutes(5),
        }),
        now(),
    )
    .unwrap();
    let before_domain = host.context().domain::<DomainSurface>().unwrap();
    let before_broker = host
        .context()
        .effect_broker::<EffectBrokerSurface>()
        .unwrap();
    let before_runtime = host
        .context()
        .runtime::<hartevo_cordis::RuntimeSurface>()
        .unwrap();

    for key in [
        keys::DOMAIN,
        keys::EFFECT_BROKER,
        keys::RUNTIME,
        keys::DESKTOP,
    ] {
        let result = host.context_mut().provide(key, "forged");
        assert!(matches!(
            result,
            Err(CordisError::ReservedServiceKey { .. })
        ));
    }
    let child = host.context_mut().new_fiber().unwrap();
    {
        let mut view = host.context_mut().with_fiber(&child);
        for key in [keys::DOMAIN, keys::EFFECT_BROKER] {
            assert!(matches!(
                view.provide(key, "forged-from-view"),
                Err(CordisError::ReservedServiceKey { .. })
            ));
        }
    }
    assert_eq!(
        host.context().domain::<DomainSurface>().as_deref(),
        Some(before_domain.as_ref())
    );
    assert_eq!(
        host.context()
            .effect_broker::<EffectBrokerSurface>()
            .as_deref(),
        Some(before_broker.as_ref())
    );
    assert_eq!(
        host.context()
            .runtime::<hartevo_cordis::RuntimeSurface>()
            .as_deref(),
        Some(before_runtime.as_ref())
    );
    assert_eq!(before_domain.owner(), SurfaceOwner::Hartevo);
    assert_eq!(before_broker.owner(), SurfaceOwner::Hartevo);
}

#[test]
fn public_handles_require_their_owner_and_current_generation() {
    let mut context = Context::new();
    let handle = context.provide("ordinary", 1_u32).unwrap();
    let root = context.root_fiber();
    assert_eq!(root.uid().as_u64(), 0);
    assert_eq!(handle.generation(), 0);
    assert_eq!(handle.owner_uid(), root.uid());

    let child = context.new_fiber().unwrap();
    assert!(child.uid().as_u64() > root.uid().as_u64());
    {
        let mut view = context.with_fiber(&child);
        assert_eq!(
            view.replace_provider(&handle, 2_u32).unwrap_err(),
            CordisError::ProviderOwnerMismatch {
                key: "ordinary".to_string()
            }
        );
    }
    assert_eq!(context.get::<u32>("ordinary").as_deref(), Some(&1));

    let current = context.replace_provider(&handle, 2_u32).unwrap();
    assert_eq!(current.generation(), 1);
    assert_eq!(context.get::<u32>("ordinary").as_deref(), Some(&2));
    assert_eq!(
        context.replace_provider(&handle, 3_u32).unwrap_err(),
        CordisError::StaleProviderHandle {
            key: "ordinary".to_string()
        }
    );
    assert_eq!(context.get::<u32>("ordinary").as_deref(), Some(&2));
}

#[test]
fn handles_and_views_are_bound_to_their_context() {
    let mut left = Context::new();
    left.set_var("left-secret", "private");
    let handle = left.provide("ordinary", 1_u32).unwrap();
    let mut right = Context::new();
    right.provide("ordinary", 10_u32).unwrap();

    assert_eq!(
        right.replace_provider(&handle, 11_u32).unwrap_err(),
        CordisError::FiberContextMismatch {
            uid: handle.owner_uid()
        }
    );
    assert_eq!(right.get::<u32>("ordinary").as_deref(), Some(&10));

    let foreign_root = left.root_fiber();
    let mut foreign_view = right.with_fiber(&foreign_root);
    assert!(!foreign_view.is_valid());
    assert!(!foreign_view.has("ordinary"));
    assert!(foreign_view.var("left-secret").is_none());
    assert!(foreign_view.plugin_interpolation_source().is_none());
    assert_eq!(
        foreign_view.provide("other", true).unwrap_err(),
        CordisError::FiberContextMismatch {
            uid: foreign_root.uid()
        }
    );
}

#[test]
fn pending_and_disposed_views_are_read_fail_closed() {
    let mut context = Context::new();
    context.set_var("root-secret", "private");
    context.provide("root-only", 1_u32).unwrap();

    let pending = context
        .mount_pending(
            PluginFactory::new("pending-view", |_config, _context| ()).with_inject(["missing"]),
        )
        .unwrap();
    {
        let pending_view = context.with_fiber(&pending.fiber());
        assert!(!pending_view.is_valid());
        assert!(!pending_view.has("root-only"));
        assert!(pending_view.get::<u32>("root-only").is_none());
        assert!(pending_view.var("root-secret").is_none());
        assert!(pending_view.plugin_interpolation_source().is_none());
    }

    let child = context.new_fiber().unwrap();
    context.dispose_fiber(&child).unwrap();
    let mut disposed_view = context.with_fiber(&child);
    assert!(!disposed_view.is_valid());
    assert!(!disposed_view.has("root-only"));
    assert!(disposed_view.get::<u32>("root-only").is_none());
    assert!(disposed_view.var("root-secret").is_none());
    assert!(disposed_view.plugin_interpolation_source().is_none());
    assert!(matches!(
        disposed_view.provide("escaped", true),
        Err(CordisError::FiberDisposed { .. })
    ));
}

#[test]
fn pending_factory_is_publicly_retained_and_activates_once() {
    let mut context = Context::new();
    let starts = Arc::new(AtomicUsize::new(0));
    let starts_for_factory = Arc::clone(&starts);
    let output = Arc::new(Mutex::new(Vec::new()));
    let output_for_factory = Arc::clone(&output);
    let factory = PluginFactory::new("consumer", move |_config, context| {
        starts_for_factory.fetch_add(1, Ordering::SeqCst);
        output_for_factory.lock().expect("output").push("started");
        context.provide("consumer-output", "ready").map(|_| ())
    })
    .with_inject(["dependency"]);
    let clone = factory.clone();
    assert_eq!(factory.id(), clone.id());

    let pending = context.mount_pending(factory).unwrap();
    assert_eq!(pending.state(), FiberState::Pending);
    assert_eq!(context.pending_count(), 1);
    assert_eq!(starts.load(Ordering::SeqCst), 0);

    context.provide("dependency", true).unwrap();
    assert_eq!(pending.state(), FiberState::Active);
    assert_eq!(context.pending_count(), 0);
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(*output.lock().expect("output"), ["started"]);

    // A new provider cannot duplicate an already active factory.
    let replacement = context.provide("other", true).unwrap();
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    drop(replacement);
}

#[test]
fn child_metadata_and_registration_are_isolated_from_parent() {
    let mut context = Context::new();
    context.set_var("scope", "parent");
    let parent_registration = Arc::new(AtomicUsize::new(0));
    let parent_registration_for_disposer = Arc::clone(&parent_registration);
    let _parent_handle = context.effect(move || {
        parent_registration_for_disposer.fetch_add(1, Ordering::SeqCst);
    });
    let child = context.new_fiber().unwrap();
    {
        let mut view = context.with_fiber(&child);
        assert_eq!(view.var("scope"), Some(&"parent".into()));
        view.set_var("scope", "child");
        view.provide("child-only", 42_u32).unwrap();
    }
    assert_eq!(context.var("scope"), Some(&"parent".into()));
    assert!(context.get::<u32>("child-only").is_some());
    context.dispose_fiber(&child).unwrap();
    assert!(context.get::<u32>("child-only").is_none());
    assert_eq!(parent_registration.load(Ordering::SeqCst), 0);
    context.teardown();
    assert_eq!(parent_registration.load(Ordering::SeqCst), 1);
}

#[test]
fn isolated_views_require_explicit_shared_namespace_lookup() {
    let mut context = Context::new();
    context.provide("root-only", 1_u32).unwrap();
    let child = context.new_fiber().unwrap();

    {
        let isolated = context.with_fiber(&child).isolate("tenant");
        assert!(!isolated.has("root-only"));
    }
    {
        let shared = context
            .with_fiber(&child)
            .isolate("tenant")
            .share_label("root");
        assert_eq!(shared.get::<u32>("root-only").as_deref(), Some(&1));
    }
    {
        let mut isolated = context.with_fiber(&child).isolate("tenant");
        isolated.provide("local-only", 2_u32).unwrap();
        assert!(isolated.has("local-only"));
    }
    assert!(!context.has("local-only"));
    context.dispose_fiber(&child).unwrap();
}

#[test]
fn isolated_views_require_explicit_sharing_for_hartevo_surfaces() {
    let mut host = hartevo_cordis::CordisHost::boot(false).unwrap();
    let child = host.context_mut().new_fiber().unwrap();
    {
        let isolated = host.context_mut().with_fiber(&child).isolate("tenant");
        assert!(isolated.domain::<DomainSurface>().is_none());
        assert!(isolated.effect_broker::<EffectBrokerSurface>().is_none());
    }
    {
        let shared = host
            .context_mut()
            .with_fiber(&child)
            .isolate("tenant")
            .share_label("root");
        assert!(shared.domain::<DomainSurface>().is_some());
        assert!(shared.effect_broker::<EffectBrokerSurface>().is_some());
    }
}
