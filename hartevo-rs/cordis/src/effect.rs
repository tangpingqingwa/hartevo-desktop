use std::any::Any;
use std::sync::Arc;

/// Cleanup callback registered via [`crate::Context::effect`].
pub type Disposer = Box<dyn FnOnce() + Send + 'static>;

/// One reversible registration. Teardown runs these newest-first.
pub(crate) enum Registration {
    Disposer(Disposer),
    Service {
        key: String,
        previous: Option<Arc<dyn Any + Send + Sync>>,
    },
    Listener {
        name: String,
        id: u64,
    },
}
