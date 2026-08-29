use crate::context::{Context, CordisError};

/// Plugin host contract: declare inject keys, then `apply` the current context.
///
/// This consuming form is the strict one-shot compatibility adapter. Repeatable
/// pending activation uses [`crate::PluginFactory`] and does not claim
/// reload/update/restart parity.
pub trait Service {
    fn inject() -> &'static [&'static str] {
        &[]
    }

    fn apply(self, ctx: &mut Context) -> Result<(), CordisError>;
}
