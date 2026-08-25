//! Host-side Domain Kernel invariants. Cordis is the plugin host, not a
//! license to bypass consent, approval, Receipt ≠ Verification, SQLCipher,
//! eval gates, or local-first.

use crate::context::{Context, CordisError, keys};
use crate::service::Service;
use crate::surface::{DomainSurface, EffectBrokerSurface, SurfaceOwner};

/// Optional adapter plugin key. Never a Domain/Effect owner and never a write path.
pub const OPENINTERPRETER: &str = "openinterpreter";

/// Missing-dependency names for host-side invariant failures.
pub mod missing {
    pub const CONSENT: &str = "consent";
    pub const APPROVAL: &str = "approval";
    pub const VERIFICATION: &str = "verification";
    pub const LOCAL_FIRST: &str = "local-first";
    pub const SQLCIPHER: &str = "sqlcipher";
    pub const EVAL: &str = "eval";
}

/// Looks up Domain and Effect Broker. Enforcement happens at
/// [`enforce_invariants`] / [`apply_effect`] / [`crate::run_agent_step`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InvariantGate;

impl Service for InvariantGate {
    fn inject() -> &'static [&'static str] {
        &[keys::DOMAIN, keys::EFFECT_BROKER]
    }

    fn apply(self, ctx: &mut Context) {
        let _ = ctx.domain::<DomainSurface>();
        let _ = ctx.effect_broker::<EffectBrokerSurface>();
    }
}

/// Fail closed if the host is missing Hartevo-owned surfaces or tries to
/// bypass Domain Kernel invariants.
///
/// Consent and approval are live kernel facts, not a `desktop_surfaces` stamp.
/// A host bool of `true` without matching kernel records still fail-closes.
pub fn enforce_invariants(ctx: &Context) -> Result<(), CordisError> {
    let Some(domain) = ctx.domain::<DomainSurface>() else {
        return Err(missing_dep(keys::DOMAIN));
    };
    if domain.owner != SurfaceOwner::Hartevo {
        return Err(missing_dep(keys::DOMAIN));
    }

    let Some(broker) = ctx.effect_broker::<EffectBrokerSurface>() else {
        return Err(missing_dep(keys::EFFECT_BROKER));
    };
    if broker.owner != SurfaceOwner::Hartevo {
        return Err(missing_dep(keys::EFFECT_BROKER));
    }

    if broker.receipt_is_verification {
        return Err(missing_dep(missing::VERIFICATION));
    }
    if !domain.kernel_consent_permits() {
        return Err(missing_dep(missing::CONSENT));
    }
    if !domain.kernel_approval_permits() {
        return Err(missing_dep(missing::APPROVAL));
    }
    if !domain.local_first {
        return Err(missing_dep(missing::LOCAL_FIRST));
    }
    if !domain.sqlcipher {
        return Err(missing_dep(missing::SQLCIPHER));
    }
    if !domain.eval_gate {
        return Err(missing_dep(missing::EVAL));
    }
    Ok(())
}

/// External write path. Invariants must pass; OpenInterpreter cannot write.
pub fn apply_effect(ctx: &Context) -> Result<(), CordisError> {
    enforce_invariants(ctx)?;
    if ctx.get::<DomainSurface>(OPENINTERPRETER).is_some() {
        return Err(missing_dep(keys::DOMAIN));
    }
    if ctx.get::<EffectBrokerSurface>(OPENINTERPRETER).is_some() {
        return Err(missing_dep(keys::EFFECT_BROKER));
    }
    Ok(())
}

fn missing_dep(key: &str) -> CordisError {
    CordisError::MissingDependencies(vec![key.to_string()])
}
