use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hartevo_cordis::{
    ConfinedArgv, ConfinedSandboxMode, ConfinedSandboxPolicy, Context, CordisError,
    SANDBOX_UNAVAILABLE, SandboxEnforcement, SandboxError, SandboxExecutionPlan, SandboxMode,
    SandboxPolicyRequest, SandboxPolicyService, SandboxProcessClassification, SandboxProvider,
    SandboxProviderService, SandboxProviderUnavailable, SandboxRunnerFailureRule,
    classify_sandbox_process, keys, prepare_sandbox_execution, register_sandbox_provider,
    resolve_sandbox_policy,
};

fn argv(parts: &[&str]) -> Vec<OsString> {
    parts.iter().map(OsString::from).collect()
}

fn context_with_policy(mode: SandboxMode) -> Context {
    let mut ctx = Context::new();
    let root = std::env::current_dir()
        .unwrap()
        .join("n87-provider-workspace");
    let policy = SandboxPolicyService::new(mode, root).unwrap();
    ctx.provide(keys::SANDBOX_POLICY, policy).unwrap();
    ctx
}

fn resolved(ctx: &Context, call_id: &str) -> hartevo_cordis::SandboxExecutionPolicy {
    resolve_sandbox_policy(
        ctx,
        SandboxPolicyRequest::default()
            .with_call_id(call_id)
            .unwrap(),
    )
    .unwrap()
}

struct CountingProvider {
    calls: Arc<AtomicUsize>,
}

impl SandboxProvider for CountingProvider {
    fn confine(
        &self,
        _argv: &[OsString],
        _policy: &ConfinedSandboxPolicy,
    ) -> Result<ConfinedArgv, SandboxProviderUnavailable> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(SandboxProviderUnavailable::new("must not be called"))
    }
}

#[test]
fn danger_full_access_bypasses_the_provider_and_preserves_exact_argv() {
    let mut ctx = context_with_policy(SandboxMode::DangerFullAccess);
    let calls = Arc::new(AtomicUsize::new(0));
    register_sandbox_provider(
        &mut ctx,
        CountingProvider {
            calls: Arc::clone(&calls),
        },
    )
    .unwrap();
    let original = argv(&["tool", "", "literal argument"]);
    let root = resolved(&ctx, "danger-call").workspace_root().to_path_buf();

    let plan =
        prepare_sandbox_execution(&ctx, original.clone(), resolved(&ctx, "danger-call")).unwrap();

    assert!(matches!(plan, SandboxExecutionPlan::Unconfined { .. }));
    assert_eq!(plan.mode(), SandboxMode::DangerFullAccess);
    assert_eq!(plan.argv(), original);
    assert_eq!(plan.workspace_root(), root);
    assert_eq!(plan.enforcement(), None);
    assert!(plan.confined_policy().is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

struct RejectingProvider;

impl SandboxProvider for RejectingProvider {
    fn confine(
        &self,
        _argv: &[OsString],
        _policy: &ConfinedSandboxPolicy,
    ) -> Result<ConfinedArgv, SandboxProviderUnavailable> {
        Err(SandboxProviderUnavailable::new(
            "functional probe found no enforcing runner",
        ))
    }
}

#[test]
fn confined_modes_fail_closed_when_the_provider_is_missing_or_refuses() {
    let ctx = context_with_policy(SandboxMode::ReadOnly);
    let missing =
        prepare_sandbox_execution(&ctx, argv(&["tool"]), resolved(&ctx, "missing")).unwrap_err();
    assert_eq!(missing.code(), Some(SANDBOX_UNAVAILABLE));
    assert!(matches!(
        missing,
        SandboxError::ProviderUnavailable {
            mode: SandboxMode::ReadOnly,
            ref detail,
        } if detail.contains(keys::SANDBOX)
    ));

    let mut ctx = context_with_policy(SandboxMode::WorkspaceWrite);
    register_sandbox_provider(&mut ctx, RejectingProvider).unwrap();
    let refused =
        prepare_sandbox_execution(&ctx, argv(&["tool"]), resolved(&ctx, "refused")).unwrap_err();
    assert_eq!(refused.code(), Some(SANDBOX_UNAVAILABLE));
    assert!(matches!(
        refused,
        SandboxError::ProviderUnavailable {
            mode: SandboxMode::WorkspaceWrite,
            ref detail,
        } if detail == "functional probe found no enforcing runner"
    ));
}

#[derive(Debug, PartialEq, Eq)]
struct SeenCall {
    argv: Vec<OsString>,
    mode: ConfinedSandboxMode,
    workspace_root: PathBuf,
    call_id: Option<String>,
}

struct VaryingProvider {
    calls: Arc<Mutex<Vec<SeenCall>>>,
    generation: AtomicUsize,
}

impl SandboxProvider for VaryingProvider {
    fn confine(
        &self,
        original_argv: &[OsString],
        policy: &ConfinedSandboxPolicy,
    ) -> Result<ConfinedArgv, SandboxProviderUnavailable> {
        self.calls.lock().unwrap().push(SeenCall {
            argv: original_argv.to_vec(),
            mode: policy.mode(),
            workspace_root: policy.workspace_root().to_path_buf(),
            call_id: policy.call_id().map(str::to_string),
        });
        let generation = self.generation.fetch_add(1, Ordering::SeqCst);
        let mut wrapped = argv(&[
            if generation == 0 {
                "runner-partial"
            } else {
                "runner-full"
            },
            "--",
        ]);
        wrapped.extend_from_slice(original_argv);
        Ok(ConfinedArgv::new(
            wrapped,
            if generation == 0 {
                SandboxEnforcement::Partial
            } else {
                SandboxEnforcement::Full
            },
            vec![format!("denial-{generation}")],
            Vec::new(),
        ))
    }
}

#[test]
fn provider_receives_exact_per_call_policy_and_returns_detached_facts() {
    let mut ctx = context_with_policy(SandboxMode::WorkspaceWrite);
    let calls = Arc::new(Mutex::new(Vec::new()));
    register_sandbox_provider(
        &mut ctx,
        VaryingProvider {
            calls: Arc::clone(&calls),
            generation: AtomicUsize::new(0),
        },
    )
    .unwrap();
    let first_argv = argv(&["tool", "first"]);
    let second_argv = argv(&["tool", "second"]);

    let first =
        prepare_sandbox_execution(&ctx, first_argv.clone(), resolved(&ctx, "call-1")).unwrap();
    let second =
        prepare_sandbox_execution(&ctx, second_argv.clone(), resolved(&ctx, "call-2")).unwrap();

    assert_eq!(first.enforcement(), Some(SandboxEnforcement::Partial));
    assert_eq!(second.enforcement(), Some(SandboxEnforcement::Full));
    assert_eq!(
        first.confined_command().unwrap().denial_signatures(),
        ["denial-0"]
    );
    assert_eq!(
        second.confined_command().unwrap().denial_signatures(),
        ["denial-1"]
    );
    assert_eq!(
        first.argv(),
        argv(&["runner-partial", "--", "tool", "first"])
    );
    assert_eq!(
        second.argv(),
        argv(&["runner-full", "--", "tool", "second"])
    );

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].argv, first_argv);
    assert_eq!(calls[0].mode, ConfinedSandboxMode::WorkspaceWrite);
    assert_eq!(calls[0].call_id.as_deref(), Some("call-1"));
    assert_eq!(calls[1].argv, second_argv);
    assert_eq!(calls[1].call_id.as_deref(), Some("call-2"));
    assert_eq!(calls[0].workspace_root, calls[1].workspace_root);
    assert!(calls[0].workspace_root.is_absolute());
}

struct EmptyArgvProvider;

impl SandboxProvider for EmptyArgvProvider {
    fn confine(
        &self,
        _argv: &[OsString],
        _policy: &ConfinedSandboxPolicy,
    ) -> Result<ConfinedArgv, SandboxProviderUnavailable> {
        Ok(ConfinedArgv::new(
            Vec::new(),
            SandboxEnforcement::Full,
            Vec::new(),
            Vec::new(),
        ))
    }
}

#[test]
fn invalid_input_stops_before_provider_and_invalid_wrapped_argv_is_unavailable() {
    let mut ctx = context_with_policy(SandboxMode::ReadOnly);
    let calls = Arc::new(AtomicUsize::new(0));
    register_sandbox_provider(
        &mut ctx,
        CountingProvider {
            calls: Arc::clone(&calls),
        },
    )
    .unwrap();
    assert!(matches!(
        prepare_sandbox_execution(&ctx, Vec::new(), resolved(&ctx, "empty-argv")),
        Err(SandboxError::EmptyCommandArgv)
    ));
    assert!(matches!(
        prepare_sandbox_execution(&ctx, vec![OsString::new()], resolved(&ctx, "empty-program")),
        Err(SandboxError::EmptyCommandProgram)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let mut ctx = context_with_policy(SandboxMode::ReadOnly);
    register_sandbox_provider(&mut ctx, EmptyArgvProvider).unwrap();
    let error =
        prepare_sandbox_execution(&ctx, argv(&["tool"]), resolved(&ctx, "bad-wrap")).unwrap_err();
    assert_eq!(error.code(), Some(SANDBOX_UNAVAILABLE));
    assert!(matches!(
        error,
        SandboxError::ProviderUnavailable { ref detail, .. }
            if detail.contains("provider returned unusable argv")
    ));
}

#[test]
fn runner_failure_precedes_denial_and_requires_exact_structured_evidence() {
    let rule = SandboxRunnerFailureRule::new(["runner: fatal", "   "])
        .with_allowed_exit_codes([125])
        .with_informational_lines(["runner: partial enforcement"]);
    let command = ConfinedArgv::new(
        argv(&["runner", "--", "tool"]),
        SandboxEnforcement::Partial,
        vec!["permission denied".to_string()],
        vec![rule],
    );

    assert_eq!(
        classify_sandbox_process(
            Some(125),
            "RUNNER: PARTIAL ENFORCEMENT\r\nRunner: Fatal while probing\npermission denied",
            &command,
        ),
        SandboxProcessClassification::RunnerFailure {
            detail: "Runner: Fatal while probing".to_string(),
        }
    );
    assert_eq!(
        classify_sandbox_process(
            Some(1),
            "Runner: Fatal while probing\nPermission Denied",
            &command,
        ),
        SandboxProcessClassification::Denied
    );
    assert_eq!(
        classify_sandbox_process(Some(125), "runner: partial enforcement", &command),
        SandboxProcessClassification::CommandFailure
    );
}

#[test]
fn success_signal_and_unmatched_failure_are_not_mislabeled() {
    let command = ConfinedArgv::new(
        argv(&["runner", "--", "tool"]),
        SandboxEnforcement::Full,
        vec!["permission denied".to_string()],
        vec![SandboxRunnerFailureRule::new(["runner: fatal"])],
    );

    assert_eq!(
        classify_sandbox_process(Some(0), "runner: fatal permission denied", &command),
        SandboxProcessClassification::Success
    );
    assert_eq!(
        classify_sandbox_process(None, "runner: fatal permission denied", &command),
        SandboxProcessClassification::Signalled
    );
    assert_eq!(
        classify_sandbox_process(Some(2), "ordinary child failure", &command),
        SandboxProcessClassification::CommandFailure
    );
}

#[test]
fn sandbox_registration_is_typed_unique_and_fiber_owned() {
    let mut ctx = context_with_policy(SandboxMode::ReadOnly);
    register_sandbox_provider(&mut ctx, RejectingProvider).unwrap();
    assert!(ctx.sandbox::<SandboxProviderService>().is_some());
    assert!(matches!(
        register_sandbox_provider(&mut ctx, RejectingProvider),
        Err(CordisError::DuplicateProvider { ref key, .. }) if key == keys::SANDBOX
    ));

    ctx.teardown();
    assert!(ctx.sandbox::<SandboxProviderService>().is_none());
}
