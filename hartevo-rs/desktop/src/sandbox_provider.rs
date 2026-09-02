use std::ffi::OsString;
use std::path::{Path, PathBuf};

use hartevo_cordis::{
    ConfinedArgv, ConfinedSandboxMode, ConfinedSandboxPolicy, CordisError, CordisHost,
    SandboxEnforcement, SandboxProvider, SandboxProviderUnavailable, SandboxRunnerFailureRule,
    register_sandbox_provider,
};

const SEATBELT_EXEC: &str = "/usr/bin/sandbox-exec";
const SEATBELT_READ_ONLY_PROFILE: &str =
    "(version 1) (allow default) (deny file-write*) (allow file-write* (literal \"/dev/null\"))";

#[derive(Debug, Default)]
pub(crate) struct MacosSeatbeltSandboxProvider;

impl SandboxProvider for MacosSeatbeltSandboxProvider {
    fn confine(
        &self,
        argv: &[OsString],
        policy: &ConfinedSandboxPolicy,
    ) -> Result<ConfinedArgv, SandboxProviderUnavailable> {
        let profile = seatbelt_profile(policy)?;
        let mut wrapped = Vec::with_capacity(argv.len() + 4);
        wrapped.extend([
            OsString::from(SEATBELT_EXEC),
            OsString::from("-p"),
            OsString::from(profile),
            OsString::from("--"),
        ]);
        wrapped.extend_from_slice(argv);
        Ok(ConfinedArgv::new(
            wrapped,
            SandboxEnforcement::Full,
            vec!["operation not permitted".to_string()],
            vec![SandboxRunnerFailureRule::new(["sandbox-exec: "])],
        ))
    }
}

pub(crate) fn mount_macos_sandbox_provider(host: &mut CordisHost) -> Result<(), CordisError> {
    register_sandbox_provider(host.context_mut(), MacosSeatbeltSandboxProvider).map(|_| ())
}

fn seatbelt_profile(policy: &ConfinedSandboxPolicy) -> Result<String, SandboxProviderUnavailable> {
    let mut profile = SEATBELT_READ_ONLY_PROFILE.to_string();
    if policy.mode() == ConfinedSandboxMode::WorkspaceWrite {
        let grants = writable_roots(policy.workspace_root())
            .iter()
            .map(|root| sbpl_string(root).map(|root| format!("(subpath {root})")))
            .collect::<Result<Vec<_>, _>>()?;
        profile.push_str(" (allow file-write* ");
        profile.push_str(&grants.join(" "));
        profile.push(')');
    }
    Ok(profile)
}

fn writable_roots(workspace_root: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::with_capacity(3);
    for root in [
        workspace_root.to_path_buf(),
        PathBuf::from("/tmp"),
        std::env::temp_dir(),
    ] {
        let root = std::fs::canonicalize(&root).unwrap_or(root);
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    roots
}

fn sbpl_string(path: &Path) -> Result<String, SandboxProviderUnavailable> {
    let path = path.to_str().ok_or_else(|| {
        SandboxProviderUnavailable::new("Seatbelt cannot encode a non-UTF-8 writable root")
    })?;
    Ok(format!(
        "\"{}\"",
        path.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    #[cfg(target_os = "macos")]
    use std::process::{Command, Output};

    #[cfg(unix)]
    use hartevo_cordis::SANDBOX_UNAVAILABLE;
    use hartevo_cordis::{
        Context, CordisHost, SandboxEnforcement, SandboxExecutionPlan, SandboxMode,
        SandboxPolicyRequest, SandboxPolicyService, SandboxProviderService, keys,
        prepare_sandbox_execution, register_sandbox_provider, resolve_sandbox_policy,
    };
    #[cfg(target_os = "macos")]
    use hartevo_cordis::{SandboxProcessClassification, classify_sandbox_process};

    use super::{
        MacosSeatbeltSandboxProvider, SEATBELT_EXEC, SEATBELT_READ_ONLY_PROFILE,
        mount_macos_sandbox_provider, sbpl_string,
    };

    fn argv(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    fn desktop_runtime_projection() -> crate::runtime_plane::DesktopRuntimeProjection {
        use crate::runtime_plane::{DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection};

        DesktopRuntimeProjection {
            status: DesktopRuntimeAvailabilityStatus::NotConfigured,
            target: None,
            release: "test".to_string(),
            program_sha256: None,
            provider: None,
            model: None,
            distribution_signature_evidence: None,
            exact_tokenizer_evidence: false,
        }
    }

    fn context(mode: SandboxMode, root: &std::path::Path) -> Context {
        let mut ctx = Context::new();
        ctx.provide(
            keys::SANDBOX_POLICY,
            SandboxPolicyService::new(mode, root).unwrap(),
        )
        .unwrap();
        register_sandbox_provider(&mut ctx, MacosSeatbeltSandboxProvider).unwrap();
        ctx
    }

    fn plan(
        ctx: &Context,
        argv: Vec<OsString>,
    ) -> Result<SandboxExecutionPlan, hartevo_cordis::SandboxError> {
        prepare_sandbox_execution(
            ctx,
            argv,
            resolve_sandbox_policy(ctx, SandboxPolicyRequest::default()).unwrap(),
        )
    }

    #[test]
    fn desktop_mount_registers_exact_read_only_seatbelt_wrap() {
        let mut host = CordisHost::boot(false).unwrap();
        mount_macos_sandbox_provider(&mut host).unwrap();
        assert!(host.context().sandbox::<SandboxProviderService>().is_some());
        let original = argv(&["tool", "", "literal argument"]);

        let wrapped = plan(host.context(), original.clone()).unwrap();

        assert!(matches!(wrapped, SandboxExecutionPlan::Confined { .. }));
        assert_eq!(wrapped.mode(), SandboxMode::ReadOnly);
        assert_eq!(wrapped.enforcement(), Some(SandboxEnforcement::Full));
        assert_eq!(
            wrapped.argv(),
            [
                OsString::from(SEATBELT_EXEC),
                OsString::from("-p"),
                OsString::from(SEATBELT_READ_ONLY_PROFILE),
                OsString::from("--"),
                original[0].clone(),
                original[1].clone(),
                original[2].clone(),
            ]
        );
        let command = wrapped.confined_command().unwrap();
        assert_eq!(command.denial_signatures(), ["operation not permitted"]);
        assert_eq!(command.runner_failure_rules().len(), 1);
        assert_eq!(
            command.runner_failure_rules()[0].fatal_signatures(),
            ["sandbox-exec: "]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn production_desktop_host_mounts_the_macos_provider() {
        let host = crate::cordis_host::mount_cordis_host(&desktop_runtime_projection()).unwrap();

        assert!(host.context().sandbox::<SandboxProviderService>().is_some());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn production_desktop_does_not_advertise_the_macos_provider_elsewhere() {
        let host = crate::cordis_host::mount_cordis_host(&desktop_runtime_projection()).unwrap();

        assert!(host.context().sandbox::<SandboxProviderService>().is_none());
    }

    #[test]
    fn workspace_write_profile_canonicalizes_deduplicates_and_escapes_roots() {
        let current = std::env::current_dir().unwrap();
        let workspace = tempfile::Builder::new()
            .prefix("n88-quoted\"slash\\")
            .tempdir_in(current)
            .unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let ctx = context(SandboxMode::WorkspaceWrite, workspace.path());

        let wrapped = plan(&ctx, argv(&["tool"])).unwrap();

        let profile = wrapped.argv()[2].to_str().unwrap();
        let workspace_grant = format!("(subpath {})", sbpl_string(&canonical_workspace).unwrap());
        assert!(profile.starts_with(SEATBELT_READ_ONLY_PROFILE));
        assert_eq!(profile.matches(&workspace_grant).count(), 1);
        for root in [std::path::Path::new("/tmp"), std::env::temp_dir().as_path()] {
            let canonical = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
            let grant = format!("(subpath {})", sbpl_string(&canonical).unwrap());
            assert_eq!(profile.matches(&grant).count(), 1);
        }
        assert!(profile.contains("quoted\\\"slash\\\\"));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_workspace_root_fails_closed_without_lossy_grant() {
        use std::os::unix::ffi::OsStringExt;

        let root = std::path::PathBuf::from(OsString::from_vec(vec![b'/', b'n', b'8', b'8', 0xff]));
        let ctx = context(SandboxMode::WorkspaceWrite, &root);

        let error = plan(&ctx, argv(&["tool"])).unwrap_err();

        assert_eq!(error.code(), Some(SANDBOX_UNAVAILABLE));
        assert!(error.to_string().contains("non-UTF-8 writable root"));
    }

    #[cfg(target_os = "macos")]
    fn run(plan: &SandboxExecutionPlan) -> Output {
        let (program, args) = plan.argv().split_first().unwrap();
        Command::new(program).args(args).output().unwrap()
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_seatbelt_enforces_read_only_and_workspace_write_boundaries() {
        let current = std::env::current_dir().unwrap();
        let workspace = tempfile::tempdir_in(&current).unwrap();
        let outside = tempfile::tempdir_in(&current).unwrap();
        let denied_read_only = workspace.path().join("read-only-denied");
        let allowed = workspace.path().join("workspace-allowed");
        let denied_outside = outside.path().join("outside-denied");

        let read_only = context(SandboxMode::ReadOnly, workspace.path());
        let read_only_plan = plan(
            &read_only,
            vec![
                OsString::from("/usr/bin/touch"),
                denied_read_only.clone().into(),
            ],
        )
        .unwrap();
        let read_only_output = run(&read_only_plan);
        assert!(!read_only_output.status.success());
        assert!(!denied_read_only.exists());
        assert_eq!(
            classify_sandbox_process(
                read_only_output.status.code(),
                &String::from_utf8_lossy(&read_only_output.stderr),
                read_only_plan.confined_command().unwrap(),
            ),
            SandboxProcessClassification::Denied
        );

        let workspace_write = context(SandboxMode::WorkspaceWrite, workspace.path());
        let allowed_plan = plan(
            &workspace_write,
            vec![OsString::from("/usr/bin/touch"), allowed.clone().into()],
        )
        .unwrap();
        assert!(run(&allowed_plan).status.success());
        assert!(allowed.exists());

        let denied_plan = plan(
            &workspace_write,
            vec![
                OsString::from("/usr/bin/touch"),
                denied_outside.clone().into(),
            ],
        )
        .unwrap();
        let denied_output = run(&denied_plan);
        assert!(!denied_output.status.success());
        assert!(!denied_outside.exists());
        assert_eq!(
            classify_sandbox_process(
                denied_output.status.code(),
                &String::from_utf8_lossy(&denied_output.stderr),
                denied_plan.confined_command().unwrap(),
            ),
            SandboxProcessClassification::Denied
        );
    }
}
