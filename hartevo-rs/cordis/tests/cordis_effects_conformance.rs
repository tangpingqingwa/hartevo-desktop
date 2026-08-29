use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hartevo_cordis::{LifecycleDisposer, LifecycleEffect};

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
