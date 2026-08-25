//! One-call-site Cordis mount for the desktop shell.
//!
//! The live loop is [`hartevo_cordis::CordisHost::step`] → `run_agent_step`
//! after `enforce_invariants`. OpenInterpreter may occupy
//! `RuntimeSurface.plugin`; it is never the loop and never owns Domain or
//! Effect.

use hartevo_cordis::{CordisError, CordisHost, desktop_surfaces, host_is_cordis_loop};

use crate::runtime_plane::{DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection};

/// Whether OpenInterpreter is configured as an optional runtime adapter.
#[must_use]
fn openinterpreter_runtime_plugin(runtime: &DesktopRuntimeProjection) -> bool {
    matches!(
        runtime.status,
        DesktopRuntimeAvailabilityStatus::ReadyDevelopment
            | DesktopRuntimeAvailabilityStatus::ReadyDistribution
    )
}

/// Boot SurfaceMapping + AgentLoop + InvariantGate for this desktop process.
pub fn mount_cordis_host(runtime: &DesktopRuntimeProjection) -> Result<CordisHost, CordisError> {
    let host = CordisHost::boot(desktop_surfaces(openinterpreter_runtime_plugin(runtime)))?;
    host_is_cordis_loop(&host)?;
    Ok(host)
}

#[cfg(test)]
mod tests {
    use hartevo_cordis::{
        AgentStep, DomainSurface, OPENINTERPRETER, SurfaceOwner, enforce_invariants, keys,
    };
    use hartevo_runtime_adapter::OPENINTERPRETER_RELEASE;

    use super::{mount_cordis_host, openinterpreter_runtime_plugin};
    use crate::runtime_plane::{DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection};

    fn projection(status: DesktopRuntimeAvailabilityStatus) -> DesktopRuntimeProjection {
        DesktopRuntimeProjection {
            status,
            target: Some("aarch64-apple-darwin".into()),
            release: OPENINTERPRETER_RELEASE.into(),
            program_sha256: None,
            provider: None,
            model: None,
            distribution_signature_evidence: None,
            exact_tokenizer_evidence: false,
        }
    }

    #[test]
    fn not_configured_runtime_does_not_name_openinterpreter_plugin() {
        assert!(!openinterpreter_runtime_plugin(&projection(
            DesktopRuntimeAvailabilityStatus::NotConfigured
        )));
        let host = mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
            .unwrap();
        assert_eq!(host.runtime_plugin(), None);
        assert_eq!(
            host.context().domain::<DomainSurface>().unwrap().owner,
            SurfaceOwner::Hartevo
        );
        assert!(host.context().get::<String>(OPENINTERPRETER).is_none());
    }

    #[test]
    fn ready_runtime_keeps_openinterpreter_as_optional_plugin() {
        let host = mount_cordis_host(&projection(
            DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
        ))
        .unwrap();
        assert!(openinterpreter_runtime_plugin(&projection(
            DesktopRuntimeAvailabilityStatus::ReadyDevelopment
        )));
        assert_eq!(host.runtime_plugin(), Some(OPENINTERPRETER));
        assert_eq!(
            host.context()
                .runtime::<hartevo_cordis::RuntimeSurface>()
                .unwrap()
                .owner,
            SurfaceOwner::Hartevo
        );
        enforce_invariants(host.context()).unwrap();
        host.apply_effect().unwrap();
    }

    #[test]
    fn desktop_step_is_cordis_hosted() {
        let mut host = mount_cordis_host(&projection(
            DesktopRuntimeAvailabilityStatus::ReadyDistribution,
        ))
        .unwrap();
        let out = host
            .step(AgentStep::new("mission-desktop", "plan"))
            .unwrap();
        assert_eq!(out.id, "mission-desktop");
        for key in [
            keys::TOOLS,
            keys::LLM,
            keys::AGENTS,
            keys::DOMAIN,
            keys::EFFECT_BROKER,
        ] {
            assert!(host.context().has(key), "{key} must stay mounted");
        }
    }
}
