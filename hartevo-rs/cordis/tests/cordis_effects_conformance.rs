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

#[test]
fn lifecycle_effect_exposes_sync_and_async_shapes() {
    let disposer = LifecycleDisposer::sync(|| {});
    assert!(!LifecycleEffect::disposer(disposer.clone()).is_async());
    assert!(!LifecycleEffect::collection([disposer]).is_async());
    assert!(LifecycleEffect::future(async { Ok(None) }).is_async());
}
