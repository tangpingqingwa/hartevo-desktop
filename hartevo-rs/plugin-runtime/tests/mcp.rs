use std::{
    collections::{BTreeSet, VecDeque},
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

use hartevo_plugin_runtime::mcp::{
    McpAuditEntry, McpAuditEventKind, McpAuditLog, McpAuditLogError, McpCapabilities, McpError,
    McpInvocationReceipt, McpInvocationStatus, McpJson, McpMissionContext, McpProtocolVersion,
    McpResourceDefinition, McpResourceUri, McpServerBinding, McpServerIdentity, McpSessionStatus,
    McpStdioChannel, McpStdioJsonRpcHostAdapter, McpTimeout, McpToolConsumer, McpToolDefinition,
    McpToolEffectClass, McpToolInput, McpToolName, McpToolPlugin, McpToolPolicy, McpToolProvider,
    MemoryMcpAuditLog,
};
use hartevo_plugin_runtime::{
    Digest, MissionId, PluginId, PluginRuntime, PluginScope, PluginVersion, ProjectId,
};
use serde_json::{Value, json};

#[derive(Clone, Copy)]
enum Fault {
    None,
    UnknownMethod,
    LateResponse,
    MalformedFrame,
    ServerCrashed,
    Timeout,
}

struct FakeStdioChannel {
    binding: McpServerBinding,
    fault: Fault,
    fault_used: u8,
    schema_drift: bool,
    duplicate_tool: bool,
    external_effect: bool,
    tool_list_count: usize,
    calls: usize,
    cancel_count: usize,
    writes: Vec<Value>,
    responses: VecDeque<String>,
}

impl FakeStdioChannel {
    fn new(
        binding: McpServerBinding,
        fault: Fault,
        schema_drift: bool,
        duplicate_tool: bool,
        external_effect: bool,
    ) -> Self {
        Self {
            binding,
            fault,
            fault_used: 0,
            schema_drift,
            duplicate_tool,
            external_effect,
            tool_list_count: 0,
            calls: 0,
            cancel_count: 0,
            writes: Vec::new(),
            responses: VecDeque::new(),
        }
    }

    fn response(&self, id: &Value, result: &Value) -> String {
        let response_id = if matches!(self.fault, Fault::LateResponse) {
            json!(999_999_u64)
        } else {
            id.clone()
        };
        serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": response_id,
            "result": result,
        }))
        .expect("fake response serializes")
    }

    fn initialize_result(&self) -> Value {
        let capabilities = self.binding.capabilities();
        json!({
            "protocolVersion": self.binding.identity().protocol_version().as_str(),
            "capabilities": {
                "tools": if capabilities.tools { json!({}) } else { json!(false) },
                "resources": if capabilities.resources { json!({}) } else { json!(false) },
                "cancellation": capabilities.cancellation,
            },
            "serverInfo": {
                "name": self.binding.identity().server_id().as_str(),
                "version": format!("{}.{}.{}", self.binding.identity().version().major(), self.binding.identity().version().minor(), self.binding.identity().version().patch()),
            },
        })
    }

    fn tools_result(&mut self) -> Value {
        self.tool_list_count += 1;
        let input_schema = if self.schema_drift && self.tool_list_count > 1 {
            json!({
                "type": "object",
                "properties": {"city": {"type": "number"}},
                "required": ["city"],
            })
        } else {
            json!({
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"],
            })
        };
        let effect_class = if self.external_effect {
            "external_effect"
        } else {
            "read_only"
        };
        let tool = json!({
            "name": "weather.read",
            "description": "private model-visible description",
            "inputSchema": input_schema,
            "effectClass": effect_class,
        });
        let mut tools = vec![tool.clone()];
        tools.push(json!({
            "name": "weather.secret",
            "description": "policy-denied tool",
            "inputSchema": {"type": "object"},
            "effectClass": "external_effect",
        }));
        if self.duplicate_tool {
            tools.push(tool);
        }
        json!({"tools": tools})
    }

    fn resources_result() -> Value {
        json!({
            "resources": [{
                "uri": "file:///mission/weather",
                "name": "private resource name",
                "mimeType": "application/json",
            }, {
                "uri": "file:///mission/secret",
                "name": "policy-denied resource",
                "mimeType": "application/json",
            }]
        })
    }

    fn call_result() -> Value {
        json!({
            "content": [{"type": "text", "text": "private weather result"}],
            "isError": false,
        })
    }
}

impl McpStdioChannel for FakeStdioChannel {
    fn write_frame(
        &mut self,
        frame: &str,
    ) -> Result<(), hartevo_plugin_runtime::mcp::McpTransportError> {
        let value: Value = serde_json::from_str(frame)
            .map_err(|_| hartevo_plugin_runtime::mcp::McpTransportError::MalformedFrame)?;
        self.writes.push(value.clone());
        let method = value
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if method == "notifications/initialized" {
            return Ok(());
        }
        if method == "notifications/cancelled" {
            self.cancel_count += 1;
            return Ok(());
        }
        let id = value
            .get("id")
            .cloned()
            .ok_or(hartevo_plugin_runtime::mcp::McpTransportError::MalformedFrame)?;
        if self.fault_used == 0 {
            self.fault_used = 1;
            match self.fault {
                Fault::UnknownMethod => {
                    self.responses.push_back(
                        serde_json::to_string(&json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "method": "server/unknown",
                            "params": {},
                        }))
                        .expect("fake unknown method serializes"),
                    );
                    return Ok(());
                }
                Fault::MalformedFrame => {
                    self.responses.push_back("not-json".into());
                    return Ok(());
                }
                Fault::ServerCrashed | Fault::Timeout => return Ok(()),
                Fault::LateResponse | Fault::None => {}
            }
        }
        let result = match method {
            "initialize" => self.initialize_result(),
            "tools/list" => self.tools_result(),
            "resources/list" => Self::resources_result(),
            "tools/call" => {
                self.calls += 1;
                Self::call_result()
            }
            _ => return Err(hartevo_plugin_runtime::mcp::McpTransportError::UnknownMethod),
        };
        self.responses.push_back(self.response(&id, &result));
        Ok(())
    }

    fn read_frame(
        &mut self,
        _timeout: McpTimeout,
    ) -> Result<String, hartevo_plugin_runtime::mcp::McpTransportError> {
        if matches!(self.fault, Fault::ServerCrashed) && self.fault_used != 0 {
            return Err(hartevo_plugin_runtime::mcp::McpTransportError::ServerCrashed);
        }
        if matches!(self.fault, Fault::Timeout) && self.fault_used != 0 {
            return Err(hartevo_plugin_runtime::mcp::McpTransportError::Timeout);
        }
        self.responses
            .pop_front()
            .ok_or(hartevo_plugin_runtime::mcp::McpTransportError::Closed)
    }
}

fn digest(value: &str) -> Digest {
    Digest::from_text(value)
}

fn scope(mission: &str, generation: u64) -> PluginScope {
    PluginScope::new(
        ProjectId::new("project.mcp").expect("project"),
        MissionId::new(mission).expect("mission"),
        generation,
    )
    .expect("scope")
}

fn binding() -> McpServerBinding {
    let capabilities = McpCapabilities::new(true, true, true);
    let identity = McpServerIdentity::new(
        hartevo_plugin_runtime::mcp::McpServerId::new("local.weather").expect("server"),
        PluginVersion::new(1, 2, 3),
        McpProtocolVersion::new("2025-06-18").expect("protocol"),
        capabilities.digest(),
    )
    .expect("identity");
    let launch = hartevo_plugin_runtime::mcp::McpStdioLaunchSpec::new(
        digest("local-weather-command"),
        vec![digest("--stdio")],
        vec![digest("MCP_ENV")],
        vec![
            hartevo_plugin_runtime::mcp::McpSecretReference::new(digest("secret-ref"))
                .expect("secret reference"),
        ],
    )
    .expect("launch spec");
    McpServerBinding::new(identity, launch, capabilities).expect("binding")
}

type FakeAdapter = McpStdioJsonRpcHostAdapter<FakeStdioChannel>;
type FakeProvider = McpToolProvider<FakeAdapter>;

fn setup(
    fault: Fault,
    schema_drift: bool,
    duplicate_tool: bool,
    external_effect: bool,
) -> (
    PluginRuntime,
    PluginScope,
    FakeProvider,
    McpToolConsumer,
    MemoryMcpAuditLog,
) {
    let scope = scope("mission.weather", 4);
    let server_binding = binding();
    let plugin = McpToolPlugin::new(
        PluginId::new("mcp.weather.plugin").expect("plugin"),
        PluginVersion::new(1, 0, 0),
        scope.clone(),
        server_binding.clone(),
    )
    .expect("plugin definition");
    let mut runtime = PluginRuntime::new();
    let mount = plugin.mount(&mut runtime).expect("mount");
    let channel = FakeStdioChannel::new(
        server_binding,
        fault,
        schema_drift,
        duplicate_tool,
        external_effect,
    );
    let provider = McpToolProvider::new(
        mount,
        digest("session-nonce"),
        McpToolPolicy::new(
            [McpToolName::new("weather.read").expect("tool name")]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            BTreeSet::new(),
            [McpResourceUri::new("file:///mission/weather").expect("resource URI")]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            external_effect,
        )
        .expect("policy"),
        McpStdioJsonRpcHostAdapter::new(channel),
    )
    .expect("provider");
    (
        runtime,
        scope,
        provider,
        McpToolConsumer::new(),
        MemoryMcpAuditLog::default(),
    )
}

fn discover(
    runtime: &PluginRuntime,
    provider: &mut FakeProvider,
    consumer: McpToolConsumer,
    log: &mut MemoryMcpAuditLog,
) -> (McpToolDefinition, McpResourceDefinition) {
    let context =
        McpMissionContext::new(provider.mount().plugin().scope().clone()).expect("mission context");
    consumer
        .initialize(&context, provider, runtime, log, 1, McpTimeout::default())
        .expect("initialize");
    let tools = consumer
        .list_tools(&context, provider, runtime, log, 2, McpTimeout::default())
        .expect("list tools");
    let resources = consumer
        .list_resources(&context, provider, runtime, log, 3, McpTimeout::default())
        .expect("list resources");
    (
        tools.into_iter().next().expect("tool"),
        resources.into_iter().next().expect("resource"),
    )
}

#[test]
fn fake_stdio_discovers_and_invokes_with_durable_content_free_receipt() {
    let (runtime, scope, mut provider, consumer, mut log) = setup(Fault::None, false, false, false);
    let context = McpMissionContext::new(scope).expect("mission context");
    assert!(provider.validate_scope(&context).is_ok());
    let (tool, resource) = discover(&runtime, &mut provider, consumer, &mut log);
    assert_eq!(tool.name().as_str(), "weather.read");
    assert_eq!(resource.uri().as_str(), "file:///mission/weather");
    assert_eq!(provider.tools().len(), 1);
    assert_eq!(provider.resources().len(), 1);
    assert!(
        provider
            .tools()
            .iter()
            .all(|definition| definition.name().as_str() != "weather.secret")
    );
    assert!(
        provider
            .resources()
            .iter()
            .all(|definition| definition.uri().as_str() != "file:///mission/secret")
    );
    let input = McpToolInput::for_definition(
        &tool,
        McpJson::parse_str(r#"{"city":"private city"}"#).expect("input"),
    )
    .expect("typed input");
    let outcome = consumer
        .call_tool(
            &context,
            &mut provider,
            &runtime,
            &tool.name().clone(),
            &input,
            &mut log,
            4,
            McpTimeout::default(),
        )
        .expect("typed call");
    assert_eq!(outcome.receipt.status(), McpInvocationStatus::Completed);
    assert!(outcome.receipt.validate().is_ok());
    assert!(
        log.entries()
            .iter()
            .all(|entry| entry.policy_digest == *provider.policy().policy_digest())
    );
    assert!(outcome.result.effect_proposal().is_none());
    assert_eq!(provider.status(), McpSessionStatus::Ready);
    assert_eq!(provider.transport().channel().calls, 1);
    assert_eq!(log.len(), 7);
    assert!(log.entries().iter().any(|entry| entry.kind
        == McpAuditEventKind::ToolDefinitionVisible
        && entry.model_visible));
    assert!(
        log.entries()
            .iter()
            .any(|entry| entry.kind == McpAuditEventKind::InvocationStarted && entry.model_visible)
    );
    assert!(
        log.entries().iter().any(
            |entry| entry.kind == McpAuditEventKind::InvocationCompleted && entry.model_visible
        )
    );
    let debug = format!("{provider:?} {outcome:?} {log:?}");
    assert!(!debug.contains("private city"));
    assert!(!debug.contains("private weather result"));
    let encoded = serde_json::to_string(&log).expect("audit JSON");
    assert!(!encoded.contains("private city"));
    assert!(!encoded.contains("private weather result"));
    assert!(!format!("{:?}", provider.policy()).contains("weather.read"));

    let mut tampered_receipt = serde_json::to_value(&outcome.receipt).expect("receipt JSON");
    tampered_receipt["policyDigest"] = json!(digest("tampered-policy").as_str());
    let tampered_receipt: McpInvocationReceipt =
        serde_json::from_value(tampered_receipt).expect("tampered receipt shape");
    assert_eq!(tampered_receipt.validate(), Err(McpError::ReceiptInvalid));
    let mut tampered_entry = log.entries()[0].clone();
    tampered_entry.policy_digest = digest("tampered-policy");
    assert_eq!(tampered_entry.validate(), Err(McpError::InvalidSchema));

    let pending = provider
        .reserve_request_id(&context)
        .expect("reserve cancellation");
    let cancellation = consumer
        .cancel(
            &context,
            &mut provider,
            &runtime,
            &pending,
            &mut log,
            5,
            McpTimeout::default(),
        )
        .expect("cancel");
    assert_eq!(cancellation.request_id_digest, pending.digest());
    assert_eq!(provider.transport().channel().cancel_count, 1);
}

#[test]
fn external_effect_tool_returns_only_a_proposal() {
    let (runtime, scope, mut provider, consumer, mut log) = setup(Fault::None, false, false, true);
    let context = McpMissionContext::new(scope).expect("mission context");
    let (tool, _) = discover(&runtime, &mut provider, consumer, &mut log);
    assert_eq!(tool.effect_class(), McpToolEffectClass::ExternalEffect);
    let input = McpToolInput::for_definition(
        &tool,
        McpJson::parse_str(r#"{"city":"proposal city"}"#).expect("input"),
    )
    .expect("typed input");
    let outcome = consumer
        .call_tool(
            &context,
            &mut provider,
            &runtime,
            &tool.name().clone(),
            &input,
            &mut log,
            4,
            McpTimeout::default(),
        )
        .expect("proposal result");
    assert!(outcome.result.effect_proposal().is_some());
    assert!(outcome.receipt.validate().is_ok());
}

#[test]
fn unknown_method_late_response_crash_timeout_and_malformed_frame_fail_closed() {
    for (fault, expected) in [
        (Fault::UnknownMethod, McpError::UnknownMethod),
        (Fault::LateResponse, McpError::LateResponse),
        (Fault::MalformedFrame, McpError::Transport),
        (Fault::ServerCrashed, McpError::ServerCrashed),
        (Fault::Timeout, McpError::Timeout),
    ] {
        let (runtime, scope, mut provider, consumer, mut log) = setup(fault, false, false, false);
        let context = McpMissionContext::new(scope).expect("mission context");
        assert_eq!(
            consumer.initialize(
                &context,
                &mut provider,
                &runtime,
                &mut log,
                1,
                McpTimeout::default(),
            ),
            Err(expected)
        );
        assert_ne!(provider.status(), McpSessionStatus::Ready);
    }
}

#[test]
fn duplicate_ids_duplicate_tools_and_schema_drift_fail_closed() {
    let (runtime, scope, mut provider, consumer, mut log) = setup(Fault::None, true, false, false);
    let context = McpMissionContext::new(scope).expect("mission context");
    consumer
        .initialize(
            &context,
            &mut provider,
            &runtime,
            &mut log,
            1,
            McpTimeout::default(),
        )
        .expect("init");
    let first = consumer
        .list_tools(
            &context,
            &mut provider,
            &runtime,
            &mut log,
            2,
            McpTimeout::default(),
        )
        .expect("first list");
    let input = McpToolInput::for_definition(
        &first[0],
        McpJson::parse_str(r#"{"city":"drift city"}"#).expect("input"),
    )
    .expect("input");
    assert_eq!(
        consumer.list_tools(
            &context,
            &mut provider,
            &runtime,
            &mut log,
            3,
            McpTimeout::default()
        ),
        Err(McpError::SchemaDrift)
    );
    assert_eq!(provider.status(), McpSessionStatus::Failed);
    let _ = input;

    let (runtime, scope, mut provider, consumer, mut log) = setup(Fault::None, false, true, false);
    let context = McpMissionContext::new(scope).expect("mission context");
    consumer
        .initialize(
            &context,
            &mut provider,
            &runtime,
            &mut log,
            1,
            McpTimeout::default(),
        )
        .expect("init");
    assert_eq!(
        consumer.list_tools(
            &context,
            &mut provider,
            &runtime,
            &mut log,
            2,
            McpTimeout::default()
        ),
        Err(McpError::DuplicateTool)
    );
}

#[test]
fn revoke_unmount_cross_mission_and_duplicate_dispatch_leave_no_use_path() {
    let (mut runtime, mission_scope, mut provider, consumer, mut log) =
        setup(Fault::None, false, false, false);
    let context = McpMissionContext::new(mission_scope.clone()).expect("mission context");
    let (tool, _) = discover(&runtime, &mut provider, consumer, &mut log);
    let other_context = McpMissionContext::new(scope("mission.other", 4)).expect("other context");
    assert_eq!(
        provider.validate_scope(&other_context),
        Err(McpError::ScopeMismatch)
    );
    let input = McpToolInput::for_definition(
        &tool,
        McpJson::parse_str(r#"{"city":"duplicate city"}"#).expect("input"),
    )
    .expect("input");
    assert_eq!(
        consumer.call_tool(
            &other_context,
            &mut provider,
            &runtime,
            tool.name(),
            &input,
            &mut log,
            4,
            McpTimeout::default(),
        ),
        Err(McpError::ScopeMismatch)
    );
    assert_eq!(provider.transport().channel().calls, 0);
    let id = provider.reserve_request_id(&context).expect("request id");
    let first = provider
        .call_tool_with_id(
            &context,
            &runtime,
            &id,
            tool.name(),
            &input,
            &mut log,
            4,
            McpTimeout::default(),
        )
        .expect("first call");
    assert!(first.receipt.validate().is_ok());
    assert_eq!(
        provider.call_tool_with_id(
            &context,
            &runtime,
            &id,
            tool.name(),
            &input,
            &mut log,
            5,
            McpTimeout::default(),
        ),
        Err(McpError::DuplicateRequestId)
    );
    assert_eq!(provider.transport().channel().calls, 1);

    provider
        .unmount(&context, &mut runtime, &mut log, 6)
        .expect("unmount");
    assert!(runtime.inspect(&mission_scope).is_empty());
    assert_eq!(provider.status(), McpSessionStatus::Unmounted);
    assert!(provider.tools().is_empty());
    assert!(provider.resources().is_empty());
    assert_eq!(
        consumer.list_tools(
            &context,
            &mut provider,
            &runtime,
            &mut log,
            7,
            McpTimeout::default()
        ),
        Err(McpError::PluginUnmounted)
    );

    let (mut runtime, scope, mut provider, consumer, mut log) =
        setup(Fault::None, false, false, false);
    let context = McpMissionContext::new(scope.clone()).expect("mission context");
    discover(&runtime, &mut provider, consumer, &mut log);
    provider
        .revoke(&context, &mut runtime, &mut log, 8)
        .expect("revoke");
    assert!(runtime.inspect(&scope).is_empty());
    assert_eq!(provider.status(), McpSessionStatus::Revoked);
    assert!(provider.tools().is_empty());
    assert!(provider.resources().is_empty());
}

struct FailingAuditLog {
    fail_kind: McpAuditEventKind,
    entries: Vec<McpAuditEntry>,
}

impl McpAuditLog for FailingAuditLog {
    fn append(&mut self, entry: McpAuditEntry) -> Result<(), McpAuditLogError> {
        if entry.kind == self.fail_kind {
            Err(McpAuditLogError::Unavailable)
        } else {
            self.entries.push(entry);
            Ok(())
        }
    }
}

#[test]
fn audit_commit_failure_prevents_dispatch_and_result_release() {
    let (runtime, scope, mut provider, consumer, _log) = setup(Fault::None, false, false, false);
    let context = McpMissionContext::new(scope).expect("mission context");
    let mut log = FailingAuditLog {
        fail_kind: McpAuditEventKind::SessionBound,
        entries: Vec::new(),
    };
    assert_eq!(
        consumer.initialize(
            &context,
            &mut provider,
            &runtime,
            &mut log,
            1,
            McpTimeout::default(),
        ),
        Err(McpError::AuditCommitFailed)
    );
    assert_eq!(provider.transport().channel().writes.len(), 0);

    let (runtime, scope, mut provider, consumer, mut memory_log) =
        setup(Fault::None, false, false, false);
    let context = McpMissionContext::new(scope).expect("mission context");
    let (tool, _) = discover(&runtime, &mut provider, consumer, &mut memory_log);
    let input = McpToolInput::for_definition(
        &tool,
        McpJson::parse_str(r#"{"city":"commit city"}"#).expect("input"),
    )
    .expect("input");
    let mut log = FailingAuditLog {
        fail_kind: McpAuditEventKind::InvocationCompleted,
        entries: Vec::new(),
    };
    assert_eq!(
        consumer.call_tool(
            &context,
            &mut provider,
            &runtime,
            tool.name(),
            &input,
            &mut log,
            4,
            McpTimeout::default(),
        ),
        Err(McpError::AuditCommitFailed)
    );
    assert_eq!(provider.transport().channel().calls, 1);
    assert_eq!(provider.status(), McpSessionStatus::Failed);
}

struct ChildChannel {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl McpStdioChannel for ChildChannel {
    fn write_frame(
        &mut self,
        frame: &str,
    ) -> Result<(), hartevo_plugin_runtime::mcp::McpTransportError> {
        writeln!(self.stdin, "{frame}")
            .map_err(|_| hartevo_plugin_runtime::mcp::McpTransportError::Io)?;
        self.stdin
            .flush()
            .map_err(|_| hartevo_plugin_runtime::mcp::McpTransportError::Io)
    }

    fn read_frame(
        &mut self,
        _timeout: McpTimeout,
    ) -> Result<String, hartevo_plugin_runtime::mcp::McpTransportError> {
        let mut line = String::new();
        let count = self
            .stdout
            .read_line(&mut line)
            .map_err(|_| hartevo_plugin_runtime::mcp::McpTransportError::Io)?;
        if count == 0 {
            return Err(hartevo_plugin_runtime::mcp::McpTransportError::ServerCrashed);
        }
        Ok(line.trim_end().to_owned())
    }
}

impl Drop for ChildChannel {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn parse_version(value: &str) -> Option<PluginVersion> {
    let parts: Vec<u16> = value
        .split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    match parts.as_slice() {
        [major, minor, patch] => Some(PluginVersion::new(*major, *minor, *patch)),
        _ => None,
    }
}

#[test]
fn real_mcp_stdio_smoke_is_environment_gated() {
    let required = [
        "HARTEVO_MCP_STDIO_COMMAND",
        "HARTEVO_MCP_SERVER_ID",
        "HARTEVO_MCP_SERVER_VERSION",
        "HARTEVO_MCP_PROTOCOL_VERSION",
    ];
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|name| std::env::var_os(name).is_none())
        .collect();
    if !missing.is_empty() {
        println!("BLOCKED_ENV: missing {}", missing.join(","));
        return;
    }
    let command = std::env::var("HARTEVO_MCP_STDIO_COMMAND").expect("command checked");
    let server_id = std::env::var("HARTEVO_MCP_SERVER_ID").expect("server checked");
    let version =
        parse_version(&std::env::var("HARTEVO_MCP_SERVER_VERSION").expect("version checked"))
            .expect("server version is semver");
    let protocol = McpProtocolVersion::new(
        std::env::var("HARTEVO_MCP_PROTOCOL_VERSION").expect("protocol checked"),
    )
    .expect("protocol");
    let capabilities = McpCapabilities::new(true, true, true);
    let identity = McpServerIdentity::new(
        hartevo_plugin_runtime::mcp::McpServerId::new(server_id).expect("server id"),
        version,
        protocol,
        capabilities.digest(),
    )
    .expect("identity");
    let launch = hartevo_plugin_runtime::mcp::McpStdioLaunchSpec::new(
        digest(&command),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("launch");
    let binding = McpServerBinding::new(identity, launch, capabilities).expect("binding");
    let mut child = Command::new(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn env-gated MCP server");
    let channel = ChildChannel {
        stdin: child.stdin.take().expect("stdin"),
        stdout: BufReader::new(child.stdout.take().expect("stdout")),
        child,
    };
    let scope = scope("mission.real.smoke", 1);
    let context = McpMissionContext::new(scope.clone()).expect("mission context");
    let plugin = McpToolPlugin::new(
        PluginId::new("mcp.real.smoke").expect("plugin"),
        PluginVersion::new(1, 0, 0),
        scope,
        binding,
    )
    .expect("plugin");
    let mut runtime = PluginRuntime::new();
    let mount = plugin.mount(&mut runtime).expect("mount");
    let mut provider = McpToolProvider::new(
        mount,
        digest("real-smoke-session"),
        McpToolPolicy::new(BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), false)
            .expect("smoke policy"),
        McpStdioJsonRpcHostAdapter::new(channel),
    )
    .expect("provider");
    let consumer = McpToolConsumer::new();
    let mut log = MemoryMcpAuditLog::default();
    consumer
        .initialize(
            &context,
            &mut provider,
            &runtime,
            &mut log,
            1,
            McpTimeout::default(),
        )
        .expect("real MCP initialize");
    println!("MCP_REAL_SMOKE_OK");
}
