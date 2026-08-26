use crate::context::Context;

/// Plugin host contract: declare inject keys, then `apply` the current context.
pub trait Service {
    fn inject() -> &'static [&'static str] {
        &[]
    }

    fn apply(self, ctx: &mut Context);
}
