mod digest;
mod model;
mod oracle;
mod verifier;

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use hartevo_runtime_adapter::{
    APP_SERVER_SCHEMA_SHA256, AdapterError, DurableModelVisibleEvent, DurableModelVisibleEventKind,
    MissionSessionLog, OPENINTERPRETER_COMMIT, OPENINTERPRETER_RELEASE,
    OpenInterpreterRuntimeProvider, ResolvedSecret, RuntimeBudget, RuntimeCatalog, RuntimeCommand,
    RuntimeDataBoundary, RuntimeExecutionConfig, RuntimeMapping, RuntimePluginMountState,
    RuntimePluginScope, RuntimeProtocolWriteReceipt, RuntimeProviderPolicy, RuntimeProviderSession,
    RuntimeProviderStreamEvent, RuntimeResultPacket, RuntimeTurnCompletionStatus,
    RuntimeTurnDispatch, SecretReference, SecretResolver, StdioRuntime, VerifiedRuntimeArtifact,
    control_plane_contract_digest, host_openinterpreter_target, pinned_runtime_artifact,
    verify_pinned_runtime_artifact,
};
use serde_json::json;

use crate::digest::{domain_digest, sha256_json, sha256_text};
use crate::model::{
    AUTHORITY, CleanupEvidence, CleanupState, DOCUMENT_TYPE, DurableEventKind, EvidenceStatus,
    InterruptEvidence, JourneyScope, NativePluginReceipt, OracleInput, ProcessEvidence, Provenance,
    RELEASE_DECISION, ResultEvidence, SCHEMA_VERSION, SelectionBinding, SourceBinding, StageName,
    StageReceipt, TurnEvidence,
};
use crate::verifier::{
    CONTRACT_RELATIVE_PATH, cleanup_digest_for_receipt, current_source_commit,
    not_evaluated_report, receipt_digest, result_digest_for_receipt, stage_digest,
    validate_contract_bytes, validate_receipt_bytes,
};

const EXACT_REQUEST: &str = "Evaluate whether our product should enter the German market.";
const CLIENT_MESSAGE_ID: &str = "openinterpreter-native-plugin-germany-01";
const SERVICE_ID: &str = "runtime.execution";
const SERVICE_REVISION: &str = "v1";
const ORACLE_CONSUMER_ID: &str = "hartevo-plugin-native-journey-oracle";
const RUN_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_STREAM_EVENTS: usize = 1_024;

fn main() {
    if let Err(error) = dispatch() {
        eprintln!("native OpenInterpreter plugin journey failed: {error:#}");
        std::process::exit(2);
    }
}

fn dispatch() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [] => print_help(),
        [command] if command == "--help" || command == "-h" => print_help(),
        [command] if command == "validate-contract" => validate_contract_command()?,
        [command, path] if command == "verify" => verify_command(Path::new(path))?,
        [command, rest @ ..] if command == "run" => {
            let (output, oracle_output) = run_options(rest)?;
            run_command(output, oracle_output.as_ref())?;
        }
        _ => bail!("unsupported command; use --help"),
    }
    Ok(())
}

fn print_help() {
    println!(
        "hartevo-openinterpreter-native-plugin [validate-contract | run [--output PATH] [--oracle-output PATH] | verify RECEIPT]"
    );
    println!(
        "run launches only the pinned App Server through the production provider seam; missing credentials or runtime output is non-zero BLOCKED_ENV/NOT_EVALUATED."
    );
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn validate_contract_command() -> Result<()> {
    let path = repository_root().join(CONTRACT_RELATIVE_PATH);
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let value = validate_contract_bytes(&bytes)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "validationSchema": verifier::VALIDATION_SCHEMA,
            "contractPath": CONTRACT_RELATIVE_PATH,
            "contractDigest": crate::digest::sha256_hex(&bytes),
            "schemaVersionPropertyPresent": value.get("properties").and_then(|p| p.get("schemaVersion")).is_some(),
            "status": "VALID",
            "releaseDecision": RELEASE_DECISION,
        }))?
    );
    Ok(())
}

fn verify_command(path: &Path) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("read receipt {}", path.display()))?;
    let expected_commit = current_source_commit(&repository_root())?;
    let report = validate_receipt_bytes(&bytes, &expected_commit)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    ensure!(
        report.status == EvidenceStatus::NativePass,
        "receipt is not native-pass"
    );
    Ok(())
}

fn run_options(args: &[String]) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    let mut output = None;
    let mut oracle_output = None;
    let mut index = 0;
    while index < args.len() {
        let target = args.get(index + 1).context("run option requires a path")?;
        match args[index].as_str() {
            "--output" => output = Some(PathBuf::from(target)),
            "--oracle-output" => oracle_output = Some(PathBuf::from(target)),
            _ => bail!("unsupported run option"),
        }
        index += 2;
    }
    Ok((output, oracle_output))
}

fn run_command(output: Option<PathBuf>, oracle_output: Option<&PathBuf>) -> Result<()> {
    let missing = required_environment();
    if !missing.is_empty() {
        println!(
            "{}",
            serde_json::to_string_pretty(&verifier::blocked_env_report(&missing))?
        );
        std::process::exit(3);
    }
    let receipt = match run_native() {
        Ok(receipt) => receipt,
        Err(error) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&not_evaluated_report(&format!(
                    "native execution did not produce a complete receipt: {error:#}"
                )))?
            );
            std::process::exit(4);
        }
    };
    if let Some(path) = oracle_output {
        let journey = oracle::build(&receipt)?;
        atomic_write_new(path, &serde_json::to_vec_pretty(&journey)?)?;
    }
    let bytes = serde_json::to_vec_pretty(&receipt)?;
    if let Some(path) = output {
        atomic_write_new(&path, &bytes)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": EvidenceStatus::NativePass,
                "receiptPath": path,
                "receiptDigest": receipt.receipt_digest,
                "evidenceRoot": receipt.evidence_root,
                "oracleConsumable": true,
                "oracleJourneyPath": oracle_output,
                "releaseDecision": RELEASE_DECISION,
            }))?
        );
    } else {
        println!("{}", String::from_utf8(bytes)?);
    }
    Ok(())
}

fn required_environment() -> Vec<String> {
    required_environment_with(|name| env::var(name).ok())
}

const REQUIRED_ENVIRONMENT: &[&str] = &[
    "HARTEVO_OPENINTERPRETER_BIN",
    "HARTEVO_TEST_OPENINTERPRETER_HOME",
    "HARTEVO_RUNTIME_PROVIDER",
    "HARTEVO_RUNTIME_MODEL",
    "HARTEVO_NATIVE_PROJECT_ID",
    "HARTEVO_NATIVE_MISSION_ID",
    "HARTEVO_NATIVE_SESSION_ID",
];

fn required_environment_with<F>(mut get: F) -> Vec<String>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut missing = REQUIRED_ENVIRONMENT
        .iter()
        .filter_map(|name| {
            if get(name)
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
            {
                Some((*name).to_owned())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let local_provider =
        get("HARTEVO_RUNTIME_OSS_PROVIDER").filter(|value| !value.trim().is_empty());
    let secret_environment =
        get("HARTEVO_RUNTIME_SECRET_ENV").filter(|value| !value.trim().is_empty());
    if local_provider.is_none() && secret_environment.is_none() {
        missing.push("HARTEVO_RUNTIME_SECRET_ENV".to_owned());
    } else if let Some(secret_environment) = secret_environment
        && get(&secret_environment)
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        && !missing.iter().any(|name| name == &secret_environment)
    {
        missing.push(secret_environment);
    }
    if local_provider.is_some()
        && get("HARTEVO_RUNTIME_MODEL_CATALOG")
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
    {
        missing.push("HARTEVO_RUNTIME_MODEL_CATALOG".to_owned());
    }

    missing
}

struct EnvironmentSecretResolver {
    environment_key: Option<String>,
}

impl SecretResolver for EnvironmentSecretResolver {
    fn resolve(&self, _reference: &SecretReference) -> Result<ResolvedSecret, AdapterError> {
        let environment_key = self
            .environment_key
            .as_deref()
            .ok_or(AdapterError::InvalidSecretMaterial)?;
        let value = env::var(environment_key).map_err(|_| AdapterError::InvalidSecretMaterial)?;
        ResolvedSecret::new(value)
    }
}

struct NativeInputs {
    project_id: String,
    mission_id: String,
    session_id: String,
    provider_id: String,
    model_id: String,
    harness_id: Option<String>,
    local_provider: Option<String>,
    model_catalog_path: Option<PathBuf>,
    secret_environment_key: Option<String>,
    workspace_root: PathBuf,
    runtime_home: PathBuf,
    program: PathBuf,
}

fn native_inputs() -> Result<NativeInputs> {
    let value = |name: &str| -> Result<String> {
        env::var(name).with_context(|| format!("environment variable {name} is required"))
    };
    let workspace_root = env::var_os("HARTEVO_NATIVE_WORKSPACE").map_or(
        env::current_dir().context("current directory")?,
        PathBuf::from,
    );
    Ok(NativeInputs {
        project_id: value("HARTEVO_NATIVE_PROJECT_ID")?,
        mission_id: value("HARTEVO_NATIVE_MISSION_ID")?,
        session_id: value("HARTEVO_NATIVE_SESSION_ID")?,
        provider_id: value("HARTEVO_RUNTIME_PROVIDER")?,
        model_id: value("HARTEVO_RUNTIME_MODEL")?,
        harness_id: env::var("HARTEVO_RUNTIME_HARNESS").ok(),
        local_provider: env::var("HARTEVO_RUNTIME_OSS_PROVIDER")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        model_catalog_path: env::var("HARTEVO_RUNTIME_MODEL_CATALOG")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from),
        secret_environment_key: env::var("HARTEVO_RUNTIME_SECRET_ENV")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        workspace_root,
        runtime_home: PathBuf::from(value("HARTEVO_TEST_OPENINTERPRETER_HOME")?),
        program: PathBuf::from(value("HARTEVO_OPENINTERPRETER_BIN")?),
    })
}

struct NativeMountPlan {
    inputs: NativeInputs,
    artifact: VerifiedRuntimeArtifact,
    source_commit: String,
    scope: RuntimePluginScope,
    catalog: RuntimeCatalog,
    config: RuntimeExecutionConfig,
    policy: RuntimeProviderPolicy,
    provider: OpenInterpreterRuntimeProvider,
    resolver: EnvironmentSecretResolver,
    command: RuntimeCommand,
    command_digest: String,
    control_plane_digest: String,
}

struct MountedJourney {
    inputs: NativeInputs,
    source_commit: String,
    scope: RuntimePluginScope,
    session: RuntimeProviderSession,
    log_events: Arc<Mutex<Vec<DurableModelVisibleEvent>>>,
    source: SourceBinding,
    selection: SelectionBinding,
    process: ProcessEvidence,
}

struct TurnCapture {
    dispatch: RuntimeTurnDispatch,
    packet: RuntimeResultPacket,
    completion_status: RuntimeTurnCompletionStatus,
    interrupt: RuntimeProtocolWriteReceipt,
    mapping: RuntimeMapping,
}

fn run_native() -> Result<NativePluginReceipt> {
    let plan = build_mount_plan()?;
    let mut mounted = mount_native_session(plan)?;
    let capture = capture_turn(&mut mounted)?;
    finish_native_journey(mounted, &capture)
}

fn build_mount_plan() -> Result<NativeMountPlan> {
    let inputs = native_inputs()?;
    let target = host_openinterpreter_target()?.to_owned();
    let pinned = pinned_runtime_artifact(&target)?;
    let artifact = verify_pinned_runtime_artifact(&inputs.program, &target)?;
    ensure!(artifact.target == pinned.target);
    ensure!(artifact.release == OPENINTERPRETER_RELEASE);
    ensure!(artifact.tag_commit == OPENINTERPRETER_COMMIT);
    let source_commit = current_source_commit(&repository_root())?;
    let resolver = EnvironmentSecretResolver {
        environment_key: inputs.secret_environment_key.clone(),
    };
    let scope = RuntimePluginScope::new(
        inputs.project_id.clone(),
        inputs.mission_id.clone(),
        inputs.session_id.clone(),
    )?;
    let catalog = discover_catalog(&artifact, &inputs, &resolver)?;
    let provider = catalog
        .provider(&inputs.provider_id)
        .context("requested provider is absent from native catalog")?;
    ensure!(provider.configured, "requested provider is not configured");
    let model = catalog
        .model(&inputs.provider_id, &inputs.model_id)
        .context("requested model is absent from native catalog")?;
    let harness = select_harness(&catalog, &inputs)?;
    let credential = SecretReference::new(
        inputs.provider_id.clone(),
        "native-acceptance",
        inputs.secret_environment_key.as_deref().map_or_else(
            || "local:no-credential".to_owned(),
            |key| format!("env:{key}"),
        ),
        scope.scope_digest.clone(),
        1,
    )?;
    let config = RuntimeExecutionConfig::new(
        inputs.provider_id.clone(),
        provider.revision.clone(),
        inputs.model_id.clone(),
        model.revision.clone(),
        harness.id.clone(),
        harness.revision.clone(),
        env::var("HARTEVO_RUNTIME_REASONING_EFFORT").ok(),
        env::var("HARTEVO_RUNTIME_SERVICE_TIER").ok(),
        provider.endpoint_class,
        RuntimeBudget::new(8_192, 4_096, 8, 60_000)?,
        RuntimeDataBoundary::ProjectLocal,
        credential.clone(),
        catalog.digest()?,
    )?;
    catalog.validate_config(&config)?;
    let command = configured_command(&artifact, &inputs, &catalog, &config, credential)?;
    let command_digest = command.intent_digest()?;
    Ok(NativeMountPlan {
        inputs,
        artifact,
        source_commit,
        scope,
        catalog,
        config,
        policy: RuntimeProviderPolicy::new(1_024, 4 * 1024 * 1024, 0, "USD")?,
        provider: OpenInterpreterRuntimeProvider::new()?,
        resolver,
        command,
        command_digest,
        control_plane_digest: control_plane_contract_digest()?,
    })
}

fn mount_native_session(plan: NativeMountPlan) -> Result<MountedJourney> {
    let NativeMountPlan {
        inputs,
        artifact,
        source_commit,
        scope,
        catalog,
        config,
        policy,
        provider,
        resolver,
        command,
        command_digest,
        control_plane_digest,
    } = plan;
    let log_events = Arc::new(Mutex::new(Vec::<DurableModelVisibleEvent>::new()));
    let log_sink = Arc::clone(&log_events);
    let log: Box<dyn MissionSessionLog> = Box::new(move |event: DurableModelVisibleEvent| {
        log_sink
            .lock()
            .map_err(|_| "durable log lock poisoned".to_owned())?
            .push(event);
        Ok(())
    });
    let session = provider.mount(
        command,
        &inputs.workspace_root,
        scope.clone(),
        catalog,
        config.clone(),
        policy.clone(),
        &resolver,
        log,
        1,
        RUN_TIMEOUT,
    )?;
    let instance_digest = session.mapping().runtime_instance_digest.clone();
    let process_binding_digest = domain_digest(
        "hartevo.openinterpreter-native-plugin-process/v1",
        &[&instance_digest, &command_digest, &artifact.program_sha256],
    );
    let observed_at_epoch_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before Unix epoch")?
        .as_secs();
    let source = SourceBinding {
        source_commit: source_commit.clone(),
        runtime_commit: OPENINTERPRETER_COMMIT.to_owned(),
        runtime_release: OPENINTERPRETER_RELEASE.to_owned(),
        app_server_schema_digest: format!("sha256:{APP_SERVER_SCHEMA_SHA256}"),
        control_plane_contract_digest: control_plane_digest,
        binary_digest: artifact.program_sha256.clone(),
        tool_digest: domain_digest(
            "hartevo.openinterpreter-native-plugin-tool/v1",
            &[
                OPENINTERPRETER_COMMIT,
                OPENINTERPRETER_RELEASE,
                APP_SERVER_SCHEMA_SHA256,
            ],
        ),
        command_digest,
    };
    let selection = SelectionBinding {
        service_id: SERVICE_ID.to_owned(),
        service_revision: SERVICE_REVISION.to_owned(),
        provider_id: config.provider_id.clone(),
        provider_revision: config.provider_revision.clone(),
        model_id: config.model_id.clone(),
        model_revision: config.model_revision.clone(),
        harness_id: config.harness_id.clone(),
        harness_revision: config.harness_revision.clone(),
        endpoint_class: config.endpoint_class,
        manifest_digest: provider.manifest().digest()?,
        service_definition_digest: provider.manifest().service_definition_digest.clone(),
        catalog_digest: config.catalog_digest.clone(),
        config_digest: config.digest()?,
        policy_digest: policy.digest()?,
    };
    let process = ProcessEvidence {
        process_id_digest: instance_digest.clone(),
        observed_at_epoch_seconds,
        executable_path_digest: sha256_text(&artifact.program.to_string_lossy()),
        runtime_instance_digest: instance_digest,
        process_binding_digest,
        binary_digest: artifact.program_sha256.clone(),
        runtime_generation: 1,
    };
    Ok(MountedJourney {
        inputs,
        source_commit,
        scope,
        session,
        log_events,
        source,
        selection,
        process,
    })
}

fn capture_turn(mounted: &mut MountedJourney) -> Result<TurnCapture> {
    let dispatch = mounted
        .session
        .start_turn(CLIENT_MESSAGE_ID, EXACT_REQUEST, RUN_TIMEOUT)?;
    let mut packet = None;
    let mut saw_delta = false;
    let mut completion_status = None;
    let mut interrupt = None;
    for _ in 0..MAX_STREAM_EVENTS {
        match mounted.session.stream_next(RUN_TIMEOUT)? {
            RuntimeProviderStreamEvent::AgentMessageDelta { .. } => saw_delta = true,
            RuntimeProviderStreamEvent::ItemCompleted { result, .. } => {
                if let Some(value) = result {
                    packet = Some(*value);
                    if interrupt.is_none() {
                        interrupt = Some(mounted.session.interrupt(RUN_TIMEOUT)?);
                    }
                }
            }
            RuntimeProviderStreamEvent::TurnCompleted { status, .. } => {
                completion_status = Some(status);
                break;
            }
            RuntimeProviderStreamEvent::LocalApprovalRequested { .. } => {
                bail!("native journey requires an unambiguous approval policy")
            }
            RuntimeProviderStreamEvent::TurnStarted { .. }
            | RuntimeProviderStreamEvent::ItemStarted { .. }
            | RuntimeProviderStreamEvent::Diagnostic { .. }
            | RuntimeProviderStreamEvent::Other { .. } => {}
        }
    }
    ensure!(
        saw_delta,
        "native runtime produced no streamed assistant delta"
    );
    Ok(TurnCapture {
        dispatch,
        packet: packet.context("native runtime produced no typed result packet")?,
        completion_status: completion_status.context("native runtime produced no terminal turn")?,
        interrupt: interrupt.context("native runtime interrupt was not acknowledged")?,
        mapping: mounted.session.mapping().clone(),
    })
}

struct ReceiptParts {
    source_commit: String,
    scope: JourneyScope,
    source: SourceBinding,
    selection: SelectionBinding,
    process: ProcessEvidence,
    durable_log: Vec<crate::model::DurableEventReceipt>,
    turn: TurnEvidence,
    result: ResultEvidence,
    interrupt: InterruptEvidence,
    cleanup: CleanupEvidence,
}

fn finish_native_journey(
    mounted: MountedJourney,
    capture: &TurnCapture,
) -> Result<NativePluginReceipt> {
    let teardown = mounted.session.revoke()?;
    ensure!(teardown.shutdown.success && !teardown.shutdown.forced);
    let exit_code = teardown
        .shutdown
        .exit_code
        .context("runtime exit code missing")?;
    ensure!(exit_code == 0);
    let events = mounted
        .log_events
        .lock()
        .map_err(|_| anyhow::anyhow!("durable log lock poisoned"))?
        .clone();
    let durable_log = events.iter().map(durable_event_receipt).collect::<Vec<_>>();
    let turn_id = capture
        .mapping
        .runtime_turn_id
        .as_deref()
        .context("turn id missing")?;
    let turn = turn_evidence(capture, &capture.mapping, turn_id);
    let result = result_evidence(&capture.packet)?;
    let interrupt = interrupt_evidence(&capture.interrupt, turn_id);
    let cleanup = cleanup_evidence(teardown, exit_code)?;
    let scope = JourneyScope {
        project_id: mounted.inputs.project_id,
        mission_id: mounted.inputs.mission_id,
        session_id: mounted.inputs.session_id,
        scope_digest: mounted.scope.scope_digest,
        runtime_generation: 1,
    };
    assemble_receipt(ReceiptParts {
        source_commit: mounted.source_commit,
        scope,
        source: mounted.source,
        selection: mounted.selection,
        process: mounted.process,
        durable_log,
        turn,
        result,
        interrupt,
        cleanup,
    })
}

fn assemble_receipt(parts: ReceiptParts) -> Result<NativePluginReceipt> {
    let result_digest = parts.result.result_digest.clone();
    let durable_log_digest = sha256_json(&parts.durable_log)?;
    let evidence_root = domain_digest(
        "hartevo.openinterpreter-native-plugin-evidence-root/v1",
        &[
            &parts.source_commit,
            &parts.scope.scope_digest,
            &sha256_json(&parts.selection)?,
            &sha256_json(&parts.process)?,
            &durable_log_digest,
            &result_digest,
            &parts.cleanup.cleanup_digest,
        ],
    );
    let provider_digest = sha256_text(&format!(
        "{}@{}",
        parts.selection.provider_id, parts.selection.provider_revision
    ));
    let model_digest = sha256_text(&format!(
        "{}@{}",
        parts.selection.model_id, parts.selection.model_revision
    ));
    let oracle_input = OracleInput {
        journey_schema: crate::model::ORACLE_JOURNEY_SCHEMA.to_owned(),
        journey_id: domain_digest(
            "hartevo.openinterpreter-native-plugin-oracle-input/v1",
            &[
                &parts.source_commit,
                &parts.scope.scope_digest,
                &result_digest,
            ],
        ),
        source_commit: parts.source_commit.clone(),
        project_id: parts.scope.project_id.clone(),
        mission_id: parts.scope.mission_id.clone(),
        session_id: parts.scope.session_id.clone(),
        runtime_plugin_digest: parts.selection.manifest_digest.clone(),
        provider_digest,
        model_digest,
        service_digest: parts.selection.service_definition_digest.clone(),
        consumer_id: ORACLE_CONSUMER_ID.to_owned(),
        consumer_result_digest: result_digest.clone(),
        durable_log_digest,
        result_digest,
        evidence_root: evidence_root.clone(),
        provenance: Provenance::Native,
    };
    let stages = StageName::ALL
        .iter()
        .enumerate()
        .map(|(index, name)| StageReceipt {
            sequence: index as u64 + 1,
            name: *name,
            evidence_digest: stage_digest(
                index as u64 + 1,
                *name,
                &parts.scope.scope_digest,
                &parts.source_commit,
            ),
        })
        .collect();
    let mut receipt = NativePluginReceipt {
        schema_version: SCHEMA_VERSION.to_owned(),
        document_type: DOCUMENT_TYPE.to_owned(),
        authority: AUTHORITY.to_owned(),
        release_decision: RELEASE_DECISION.to_owned(),
        source_commit: parts.source_commit,
        scope: parts.scope,
        source: parts.source,
        selection: parts.selection,
        process: parts.process,
        stages,
        durable_log: parts.durable_log,
        turn: parts.turn,
        result: parts.result,
        interrupt: parts.interrupt,
        cleanup: parts.cleanup,
        oracle_input,
        provenance: Provenance::Native,
        evidence_root,
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = receipt_digest(&receipt)?;
    Ok(receipt)
}

fn turn_evidence(capture: &TurnCapture, mapping: &RuntimeMapping, turn_id: &str) -> TurnEvidence {
    let request_digest = capture.dispatch.request_digest.clone();
    let response_digest = capture.dispatch.response_digest.clone();
    let thread_id_digest = sha256_text(&mapping.runtime_thread_id);
    let turn_id_digest = sha256_text(turn_id);
    let completion_status = match capture.completion_status {
        RuntimeTurnCompletionStatus::Completed => "completed",
        RuntimeTurnCompletionStatus::Interrupted => "interrupted",
        RuntimeTurnCompletionStatus::Failed => "failed",
    };
    TurnEvidence {
        client_message_id_digest: sha256_text(CLIENT_MESSAGE_ID),
        request_digest: request_digest.clone(),
        response_digest: response_digest.clone(),
        thread_id_digest: thread_id_digest.clone(),
        turn_id_digest: turn_id_digest.clone(),
        completion_status: completion_status.to_owned(),
        turn_digest: domain_digest(
            "hartevo.openinterpreter-native-plugin-turn/v1",
            &[
                CLIENT_MESSAGE_ID,
                &request_digest,
                &response_digest,
                &thread_id_digest,
                &turn_id_digest,
            ],
        ),
    }
}

fn interrupt_evidence(receipt: &RuntimeProtocolWriteReceipt, turn_id: &str) -> InterruptEvidence {
    let turn_id_digest = sha256_text(turn_id);
    InterruptEvidence {
        request_digest: receipt.request_digest.clone(),
        response_digest: receipt.response_digest.clone(),
        turn_id_digest: turn_id_digest.clone(),
        acknowledged: true,
        interrupt_digest: domain_digest(
            "hartevo.openinterpreter-native-plugin-interrupt/v1",
            &[
                &receipt.request_digest,
                &receipt.response_digest,
                &turn_id_digest,
            ],
        ),
    }
}

fn cleanup_evidence(
    teardown: hartevo_runtime_adapter::RuntimeProviderTeardown,
    exit_code: i32,
) -> Result<CleanupEvidence> {
    let plugin_state = match teardown.plugin.state {
        RuntimePluginMountState::Revoked => CleanupState::Revoked,
        RuntimePluginMountState::Unmounted => CleanupState::Unmounted,
        RuntimePluginMountState::Mounted => bail!("runtime mount remained active"),
    };
    let mut cleanup = CleanupEvidence {
        mount_digest: teardown.plugin.mount_digest,
        plugin_state,
        stopped_registration_count: teardown.plugin.stopped_registration_count as u64,
        residual_registration_count: teardown.plugin.residual_registration_count as u64,
        shutdown_success: teardown.shutdown.success,
        shutdown_forced: teardown.shutdown.forced,
        exit_code,
        cleanup_digest: String::new(),
    };
    cleanup.cleanup_digest = cleanup_digest_for_receipt(&cleanup)?;
    Ok(cleanup)
}

fn discover_catalog(
    artifact: &VerifiedRuntimeArtifact,
    inputs: &NativeInputs,
    resolver: &dyn SecretResolver,
) -> Result<RuntimeCatalog> {
    let command = configured_runtime_command(artifact, inputs)?;
    let mut runtime = StdioRuntime::spawn_with_secret_resolver(&command, resolver)?;
    let result = runtime.discover_runtime_catalog("native-acceptance-probe", RUN_TIMEOUT);
    let shutdown = runtime.shutdown();
    let catalog = result?;
    shutdown?;
    Ok(catalog)
}

fn select_harness<'a>(
    catalog: &'a RuntimeCatalog,
    inputs: &NativeInputs,
) -> Result<&'a hartevo_runtime_adapter::RuntimeHarnessDescriptor> {
    if let Some(id) = inputs.harness_id.as_deref() {
        return catalog
            .harness(&inputs.provider_id, &inputs.model_id, id)
            .context("requested harness is absent from native catalog");
    }
    catalog
        .harnesses
        .iter()
        .find(|harness| {
            harness.provider_id == inputs.provider_id
                && harness
                    .model_id
                    .as_deref()
                    .is_none_or(|model| model == inputs.model_id)
                && harness.recommended
        })
        .or_else(|| {
            catalog.harnesses.iter().find(|harness| {
                harness.provider_id == inputs.provider_id
                    && harness
                        .model_id
                        .as_deref()
                        .is_none_or(|model| model == inputs.model_id)
            })
        })
        .context("native catalog has no harness for selected provider/model")
}

fn configured_command(
    artifact: &VerifiedRuntimeArtifact,
    inputs: &NativeInputs,
    catalog: &RuntimeCatalog,
    config: &RuntimeExecutionConfig,
    credential: SecretReference,
) -> Result<RuntimeCommand> {
    let mut command = configured_runtime_command(artifact, inputs)?;
    if let Some(environment_key) = catalog
        .provider(&config.provider_id)
        .and_then(|provider| provider.credential_environment_key.clone())
    {
        ensure!(
            inputs.secret_environment_key.as_deref() == Some(environment_key.as_str()),
            "configured secret environment does not match the provider catalog"
        );
        command.add_secret_binding(environment_key, credential)?;
    }
    Ok(command)
}

fn configured_runtime_command(
    artifact: &VerifiedRuntimeArtifact,
    inputs: &NativeInputs,
) -> Result<RuntimeCommand> {
    let mut command = artifact.runtime_command(&inputs.workspace_root, &inputs.runtime_home)?;
    command.environment.insert(
        "HOME".to_owned(),
        inputs.runtime_home.to_string_lossy().into_owned(),
    );
    if let Some(local_provider) = inputs.local_provider.as_deref() {
        ensure!(
            !local_provider.trim().is_empty(),
            "local provider selection must not be empty"
        );
        ensure!(
            inputs.provider_id == local_provider,
            "local provider must match the selected runtime provider"
        );
        command.args = vec![
            "app-server".to_owned(),
            "--stdio".to_owned(),
            "-c".to_owned(),
            format!("oss_provider=\"{local_provider}\""),
            "-c".to_owned(),
            format!("model_provider=\"{local_provider}\""),
        ];
        let model_catalog_path = inputs
            .model_catalog_path
            .as_deref()
            .context("local provider requires an explicit model catalog path")?;
        ensure!(
            model_catalog_path.is_absolute() && model_catalog_path.is_file(),
            "local model catalog path must be an existing absolute file"
        );
        command.args.extend([
            "-c".to_owned(),
            format!(
                "model_catalog_json={}",
                model_catalog_path.to_string_lossy()
            ),
        ]);
    }
    Ok(command)
}

fn durable_event_receipt(event: &DurableModelVisibleEvent) -> crate::model::DurableEventReceipt {
    let kind = match event.kind {
        DurableModelVisibleEventKind::Input => DurableEventKind::Input,
        DurableModelVisibleEventKind::AssistantDelta => DurableEventKind::AssistantDelta,
        DurableModelVisibleEventKind::AssistantResult => DurableEventKind::AssistantResult,
    };
    crate::model::DurableEventReceipt {
        sequence: event.sequence,
        kind,
        source_item_id_digest: event.source_item_id_digest.clone(),
        source_event_digest: event.source_event_digest.clone(),
        content_digest: event.content_digest.clone(),
        content_byte_count: event.content_byte_count,
        event_digest: event.event_digest.clone(),
        scope_digest: event.scope_digest.clone(),
        provider_manifest_digest: event.provider_manifest_digest.clone(),
        config_digest: event.runtime_config_digest.clone(),
        catalog_digest: event.catalog_digest.clone(),
        policy_digest: event.policy_digest.clone(),
    }
}

fn result_evidence(packet: &RuntimeResultPacket) -> Result<ResultEvidence> {
    packet.validate()?;
    let mut result = ResultEvidence {
        schema: packet.schema.clone(),
        authority: serde_json::to_string(&packet.authority)?
            .trim_matches('"')
            .to_owned(),
        result_kind: serde_json::to_string(&packet.result_kind)?
            .trim_matches('"')
            .to_owned(),
        project_id: packet.project_id.clone(),
        mission_id: packet.mission_id.clone(),
        runtime_generation: packet.runtime_generation,
        runtime_instance_digest: packet.runtime_instance_digest.clone(),
        runtime_commit: packet.runtime_commit.clone(),
        runtime_release: packet.runtime_release.clone(),
        mapping_digest: packet.mapping_digest.clone(),
        runtime_thread_id_digest: packet.runtime_thread_id_digest.clone(),
        runtime_turn_id_digest: packet.runtime_turn_id_digest.clone(),
        app_server_schema_digest: packet.app_server_schema_digest.clone(),
        runtime_config_digest: packet.runtime_config_digest.clone(),
        catalog_digest: packet.catalog_digest.clone(),
        source_item_id_digest: packet.source_item_id_digest.clone(),
        source_event_digest: packet.source_event_digest.clone(),
        content_digest: packet.content_digest.clone(),
        content_byte_count: packet.content_byte_count,
        result_digest: String::new(),
    };
    result.result_digest = result_digest_for_receipt(&result)?;
    Ok(result)
}

fn atomic_write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure!(path.is_absolute(), "receipt output path must be absolute");
    ensure!(!path.exists(), "receipt output already exists");
    let parent = path.parent().context("receipt output has no parent")?;
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .context("receipt output has no filename")?
        .to_string_lossy();
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    OpenOptions::new().read(true).open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::required_environment_with;

    #[test]
    fn missing_secret_reference_environment_is_blocked_before_native_launch() {
        let mut values = BTreeMap::new();
        for name in [
            "HARTEVO_OPENINTERPRETER_BIN",
            "HARTEVO_TEST_OPENINTERPRETER_HOME",
            "HARTEVO_RUNTIME_PROVIDER",
            "HARTEVO_RUNTIME_MODEL",
            "HARTEVO_RUNTIME_SECRET_ENV",
            "HARTEVO_NATIVE_PROJECT_ID",
            "HARTEVO_NATIVE_MISSION_ID",
            "HARTEVO_NATIVE_SESSION_ID",
        ] {
            values.insert(name, name.to_owned());
        }
        values.insert("HARTEVO_RUNTIME_SECRET_ENV", "OPENAI_API_KEY".to_owned());

        let missing = required_environment_with(|name| values.get(name).cloned());

        assert_eq!(missing, vec!["OPENAI_API_KEY"]);
    }

    #[test]
    fn populated_secret_reference_environment_is_not_reported_missing() {
        let mut values = BTreeMap::new();
        for name in [
            "HARTEVO_OPENINTERPRETER_BIN",
            "HARTEVO_TEST_OPENINTERPRETER_HOME",
            "HARTEVO_RUNTIME_PROVIDER",
            "HARTEVO_RUNTIME_MODEL",
            "HARTEVO_RUNTIME_SECRET_ENV",
            "HARTEVO_NATIVE_PROJECT_ID",
            "HARTEVO_NATIVE_MISSION_ID",
            "HARTEVO_NATIVE_SESSION_ID",
        ] {
            values.insert(name, name.to_owned());
        }
        values.insert("HARTEVO_RUNTIME_SECRET_ENV", "OPENAI_API_KEY".to_owned());
        values.insert("OPENAI_API_KEY", "redacted-test-secret".to_owned());

        assert!(required_environment_with(|name| values.get(name).cloned()).is_empty());
    }

    #[test]
    fn local_provider_does_not_require_secret_material() {
        let mut values = BTreeMap::new();
        for name in [
            "HARTEVO_OPENINTERPRETER_BIN",
            "HARTEVO_TEST_OPENINTERPRETER_HOME",
            "HARTEVO_RUNTIME_PROVIDER",
            "HARTEVO_RUNTIME_MODEL",
            "HARTEVO_NATIVE_PROJECT_ID",
            "HARTEVO_NATIVE_MISSION_ID",
            "HARTEVO_NATIVE_SESSION_ID",
        ] {
            values.insert(name, name.to_owned());
        }
        values.insert("HARTEVO_RUNTIME_OSS_PROVIDER", "ollama".to_owned());
        values.insert(
            "HARTEVO_RUNTIME_MODEL_CATALOG",
            "/tmp/local-model-catalog.json".to_owned(),
        );

        assert!(required_environment_with(|name| values.get(name).cloned()).is_empty());
    }

    #[test]
    fn local_provider_without_model_catalog_is_blocked() {
        let mut values = BTreeMap::new();
        for name in [
            "HARTEVO_OPENINTERPRETER_BIN",
            "HARTEVO_TEST_OPENINTERPRETER_HOME",
            "HARTEVO_RUNTIME_PROVIDER",
            "HARTEVO_RUNTIME_MODEL",
            "HARTEVO_NATIVE_PROJECT_ID",
            "HARTEVO_NATIVE_MISSION_ID",
            "HARTEVO_NATIVE_SESSION_ID",
        ] {
            values.insert(name, name.to_owned());
        }
        values.insert("HARTEVO_RUNTIME_OSS_PROVIDER", "ollama".to_owned());

        assert_eq!(
            required_environment_with(|name| values.get(name).cloned()),
            vec!["HARTEVO_RUNTIME_MODEL_CATALOG"]
        );
    }
}
