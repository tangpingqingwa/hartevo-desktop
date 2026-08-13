use std::collections::BTreeSet;
use std::env;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use hartevo_context_fabric::RuntimeIdentity;
use hartevo_runtime_adapter::{
    AdapterError, MappedTurnEvent, MappedTurnEventKind, OPENINTERPRETER_RELEASE, ResolvedSecret,
    RuntimeBudget, RuntimeCapabilities, RuntimeCatalog, RuntimeCommand, RuntimeDataBoundary,
    RuntimeEndpointClass, RuntimeExecutionConfig, RuntimeMapping, RuntimePluginError,
    RuntimePluginMount, RuntimePluginMountState, RuntimePluginRegistrationKind,
    RuntimePluginRegistrationStopper, RuntimePluginScope, RuntimeResultPacket,
    RuntimeServiceCapability, RuntimeServiceDefinition, RuntimeServiceProviderManifest,
    RuntimeTurnCompletionStatus, SecretReference, SecretResolver, StdioRuntime,
    host_openinterpreter_target, verify_pinned_runtime_artifact,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DISPATCH_REPORT_SCHEMA: &str = "hartevo.runtime-dispatch-report/v1";
const DISPATCH_JOURNAL_SCHEMA: &str = "hartevo.runtime-dispatch-journal/v1";
const FAKE_SECRET: &str = "oi02-fake-secret";
const FAKE_PROVIDER: &str = "openai";
const FAKE_MODEL: &str = "gpt-5.6";
const FAKE_HARNESS: &str = "native";
const FAKE_EFFORT: &str = "medium";
const FAKE_SERVICE_TIER: &str = "default";
const FAKE_THREAD_ID: &str = "thread-oi02";
const CLIENT_TURN_ID: &str = "oi02-client-turn";
const RUNTIME_PLUGIN_SERVICE_ID: &str = "runtime.execution";
const RUNTIME_PLUGIN_SERVICE_REVISION: &str = "v1";

#[derive(Debug, Default)]
struct EvalRegistrationStopper {
    streams: BTreeSet<String>,
    tools: BTreeSet<String>,
    hooks: BTreeSet<String>,
}

impl RuntimePluginRegistrationStopper for EvalRegistrationStopper {
    fn stop_stream(&mut self, registration_digest: &str) -> Result<(), RuntimePluginError> {
        self.streams.insert(registration_digest.to_owned());
        Ok(())
    }

    fn unregister_tool(&mut self, registration_digest: &str) -> Result<(), RuntimePluginError> {
        self.tools.insert(registration_digest.to_owned());
        Ok(())
    }

    fn remove_hook(&mut self, registration_digest: &str) -> Result<(), RuntimePluginError> {
        self.hooks.insert(registration_digest.to_owned());
        Ok(())
    }
}

#[derive(Debug)]
struct OpenInterpreterRuntimePlugin {
    mount: RuntimePluginMount,
    stopper: EvalRegistrationStopper,
}

impl OpenInterpreterRuntimePlugin {
    fn new(project_id: &str, mission_id: &str, session_id: &str) -> Result<Self> {
        let service_definition = RuntimeServiceDefinition::new(
            RUNTIME_PLUGIN_SERVICE_ID,
            RUNTIME_PLUGIN_SERVICE_REVISION,
            vec![
                RuntimeServiceCapability::Initialize,
                RuntimeServiceCapability::Thread,
                RuntimeServiceCapability::Turn,
                RuntimeServiceCapability::ItemStream,
                RuntimeServiceCapability::Interrupt,
                RuntimeServiceCapability::Resume,
                RuntimeServiceCapability::TypedResultPacket,
                RuntimeServiceCapability::ModelVisibleSessionLog,
            ],
        )?;
        let provider_manifest = RuntimeServiceProviderManifest::new(
            "openinterpreter",
            OPENINTERPRETER_RELEASE,
            &service_definition,
        )?;
        let scope = RuntimePluginScope::new(project_id, mission_id, session_id)?;
        let mut plugin = Self {
            mount: RuntimePluginMount::new(provider_manifest, scope)?,
            stopper: EvalRegistrationStopper::default(),
        };
        plugin.mount.register(
            RuntimePluginRegistrationKind::Stream,
            "openinterpreter-item-stream",
        )?;
        plugin.mount.register(
            RuntimePluginRegistrationKind::Tool,
            "openinterpreter-runtime-tool",
        )?;
        plugin.mount.register(
            RuntimePluginRegistrationKind::Hook,
            "openinterpreter-session-hook",
        )?;
        Ok(plugin)
    }

    fn unmount(&mut self) -> Result<bool> {
        let receipt = self.mount.unmount(&mut self.stopper)?;
        self.verify_teardown(&receipt, RuntimePluginMountState::Unmounted)
    }

    fn revoke(&mut self) -> Result<bool> {
        let receipt = self.mount.revoke(&mut self.stopper)?;
        self.verify_teardown(&receipt, RuntimePluginMountState::Revoked)
    }

    fn residual_registration_count(&self) -> u32 {
        u32::try_from(self.mount.active_registration_count()).unwrap_or(u32::MAX)
    }

    fn verify_teardown(
        &self,
        receipt: &hartevo_runtime_adapter::RuntimePluginTeardownReceipt,
        expected_state: RuntimePluginMountState,
    ) -> Result<bool> {
        ensure!(
            receipt.state == expected_state,
            "plugin teardown state drift"
        );
        ensure!(
            receipt.residual_registration_count == 0
                && self.mount.active_registration_count() == 0
                && self.stopper.streams.len() == 1
                && self.stopper.tools.len() == 1
                && self.stopper.hooks.len() == 1,
            "plugin teardown left registration residue"
        );
        Ok(true)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionDispatchIdentity {
    pub schema: String,
    pub project_id: String,
    pub mission_id: String,
    pub runtime_generation: u64,
    pub runtime_instance_digest: String,
    pub mapping_digest: String,
    pub runtime_thread_id_digest: String,
    pub runtime_turn_id_digest: String,
    pub runtime_identity_digest: String,
    pub runtime_identity: RuntimeIdentity,
}

impl MissionDispatchIdentity {
    pub fn from_mapping(mapping: &RuntimeMapping) -> Result<Self> {
        mapping.validate()?;
        let config = mapping
            .runtime_config
            .as_ref()
            .context("configured runtime mapping is required")?;
        config.validate()?;
        let turn_id = mapping
            .runtime_turn_id
            .as_deref()
            .context("a turn-scoped mapping is required")?;
        let config_digest = config.digest()?;
        let runtime_identity = RuntimeIdentity::new(
            config.provider_id.clone(),
            config.provider_revision.clone(),
            config.model_id.clone(),
            config.model_revision.clone(),
            config.harness_id.clone(),
            config.harness_revision.clone(),
            config.reasoning_effort.clone(),
            config.service_tier.clone(),
            endpoint_name(config.endpoint_class),
            config.catalog_digest.clone(),
            config_digest,
        )?;
        let identity = Self {
            schema: "hartevo.mission-dispatch-identity/v1".to_owned(),
            project_id: mapping.project_id.clone(),
            mission_id: mapping.mission_id.clone(),
            runtime_generation: mapping.runtime_generation,
            runtime_instance_digest: mapping.runtime_instance_digest.clone(),
            mapping_digest: mapping.digest()?,
            runtime_thread_id_digest: digest_hex(mapping.runtime_thread_id.as_bytes()),
            runtime_turn_id_digest: digest_hex(turn_id.as_bytes()),
            runtime_identity_digest: runtime_identity.digest()?,
            runtime_identity,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "hartevo.mission-dispatch-identity/v1",
            "dispatch identity schema drift"
        );
        ensure!(
            bounded_identifier(&self.project_id) && bounded_identifier(&self.mission_id),
            "dispatch identity scope is empty"
        );
        ensure!(self.runtime_generation > 0, "dispatch generation is zero");
        for digest in [
            &self.runtime_instance_digest,
            &self.mapping_digest,
            &self.runtime_thread_id_digest,
            &self.runtime_turn_id_digest,
            &self.runtime_identity_digest,
        ] {
            ensure!(is_hex_digest(digest), "dispatch identity digest is invalid");
        }
        self.runtime_identity.validate()?;
        Ok(())
    }
}

const MODEL_VISIBLE_LOG_SCHEMA: &str = "hartevo.mission-session-model-visible-log-entry/v1";
const MAX_MODEL_VISIBLE_LOG_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelVisibleLogDirection {
    Input,
    Output,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelVisibleLogKind {
    TurnInput,
    AgentMessageDelta,
    AgentMessageCompleted,
}

/// Content-bearing records that a Mission/session consumer must durably append before it can
/// claim that a model-visible input or output was observed. Debug remains content-free while
/// JSON persistence retains the bounded body for replay.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ModelVisibleLogEntry {
    pub schema: String,
    pub sequence: u64,
    pub direction: ModelVisibleLogDirection,
    pub kind: ModelVisibleLogKind,
    pub event_digest: String,
    pub item_id_digest: Option<String>,
    pub content_digest: String,
    pub content_byte_count: u64,
    pub content: String,
}

impl fmt::Debug for ModelVisibleLogEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelVisibleLogEntry")
            .field("schema", &self.schema)
            .field("sequence", &self.sequence)
            .field("direction", &self.direction)
            .field("kind", &self.kind)
            .field("event_digest", &self.event_digest)
            .field("item_id_digest", &self.item_id_digest)
            .field("content_digest", &self.content_digest)
            .field("content_byte_count", &self.content_byte_count)
            .finish_non_exhaustive()
    }
}

impl ModelVisibleLogEntry {
    fn input(sequence: u64, client_message_id: &str, content: &str) -> Result<Self> {
        let content_digest = digest_hex(content.as_bytes());
        let event_digest = digest_hex(
            format!("mission-session-input:{client_message_id}:{content_digest}").as_bytes(),
        );
        let entry = Self {
            schema: MODEL_VISIBLE_LOG_SCHEMA.to_owned(),
            sequence,
            direction: ModelVisibleLogDirection::Input,
            kind: ModelVisibleLogKind::TurnInput,
            event_digest,
            item_id_digest: None,
            content_digest,
            content_byte_count: u64::try_from(content.len())
                .context("model input byte count overflow")?,
            content: content.to_owned(),
        };
        entry.validate()?;
        Ok(entry)
    }

    fn output(
        sequence: u64,
        kind: ModelVisibleLogKind,
        event_digest: &str,
        item_id_digest: &str,
        content: &str,
    ) -> Result<Self> {
        let entry = Self {
            schema: MODEL_VISIBLE_LOG_SCHEMA.to_owned(),
            sequence,
            direction: ModelVisibleLogDirection::Output,
            kind,
            event_digest: event_digest.to_owned(),
            item_id_digest: Some(item_id_digest.to_owned()),
            content_digest: digest_hex(content.as_bytes()),
            content_byte_count: u64::try_from(content.len())
                .context("model output byte count overflow")?,
            content: content.to_owned(),
        };
        entry.validate()?;
        Ok(entry)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == MODEL_VISIBLE_LOG_SCHEMA && self.sequence > 0,
            "model-visible log entry schema is invalid"
        );
        ensure!(
            is_hex_digest(&self.event_digest) && is_hex_digest(&self.content_digest),
            "model-visible log entry digest is invalid"
        );
        let content_byte_count =
            u64::try_from(self.content.len()).context("model-visible content byte overflow")?;
        ensure!(
            !self.content.is_empty()
                && self.content.len() <= MAX_MODEL_VISIBLE_LOG_BYTES
                && self.content_byte_count == content_byte_count
                && self.content_digest == digest_hex(self.content.as_bytes()),
            "model-visible log content is invalid"
        );
        match (self.direction, self.kind, self.item_id_digest.as_ref()) {
            (ModelVisibleLogDirection::Input, ModelVisibleLogKind::TurnInput, None) => {}
            (
                ModelVisibleLogDirection::Output,
                ModelVisibleLogKind::AgentMessageDelta | ModelVisibleLogKind::AgentMessageCompleted,
                Some(item_id_digest),
            ) => ensure!(
                is_hex_digest(item_id_digest),
                "model item digest is invalid"
            ),
            _ => bail!("model-visible log direction/kind mismatch"),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchJournal {
    pub schema: String,
    pub client_user_message_id: String,
    pub logical_turn_id_digest: String,
    pub model_visible_log: Vec<ModelVisibleLogEntry>,
    pub mapping_digests: BTreeSet<String>,
    pub seen_item_id_digests: BTreeSet<String>,
    pub duplicate_item_count: u32,
    pub stream_event_count: u32,
    pub terminal: Option<RuntimeTurnCompletionStatus>,
    pub result_packet: Option<RuntimeResultPacket>,
    pub adoption_count: u32,
}

impl DispatchJournal {
    pub fn new(client_user_message_id: impl Into<String>, prompt: &str) -> Result<Self> {
        let client_user_message_id = client_user_message_id.into();
        ensure!(
            bounded_identifier(&client_user_message_id),
            "client message id is invalid"
        );
        let model_visible_log = vec![ModelVisibleLogEntry::input(
            1,
            &client_user_message_id,
            prompt,
        )?];
        let journal = Self {
            schema: DISPATCH_JOURNAL_SCHEMA.to_owned(),
            logical_turn_id_digest: digest_hex(client_user_message_id.as_bytes()),
            client_user_message_id,
            model_visible_log,
            mapping_digests: BTreeSet::new(),
            seen_item_id_digests: BTreeSet::new(),
            duplicate_item_count: 0,
            stream_event_count: 0,
            terminal: None,
            result_packet: None,
            adoption_count: 0,
        };
        journal.validate()?;
        Ok(journal)
    }

    pub fn bind_dispatch(&mut self, identity: &MissionDispatchIdentity) -> Result<()> {
        identity.validate()?;
        ensure!(
            digest_hex(self.client_user_message_id.as_bytes()) == self.logical_turn_id_digest,
            "logical turn identity drift"
        );
        self.mapping_digests.insert(identity.mapping_digest.clone());
        self.validate()
    }

    /// Record one adapter event. A false return means the completed item was a duplicate already
    /// present in the persisted journal and was intentionally suppressed.
    pub fn record_event(
        &mut self,
        mapping: &RuntimeMapping,
        event: &MappedTurnEvent,
    ) -> Result<bool> {
        let identity = MissionDispatchIdentity::from_mapping(mapping)?;
        ensure!(
            self.mapping_digests.contains(&identity.mapping_digest),
            "event arrived from an unbound runtime mapping"
        );
        self.stream_event_count = self
            .stream_event_count
            .checked_add(1)
            .context("stream event counter overflow")?;

        if let Some(delta) = event.agent_message_delta.as_ref() {
            self.append_model_visible_output(
                ModelVisibleLogKind::AgentMessageDelta,
                &event.event_digest,
                &delta.item_id_digest,
                delta.as_str(),
            )?;
        }
        if let Some(message) = event.agent_message.as_ref() {
            self.append_model_visible_output(
                ModelVisibleLogKind::AgentMessageCompleted,
                &event.event_digest,
                &message.item_id_digest,
                message.as_str(),
            )?;
        }

        if matches!(&event.kind, MappedTurnEventKind::ItemCompleted) {
            let Some(packet) = RuntimeResultPacket::from_mapped_event(mapping, event)? else {
                return Ok(false);
            };
            if self
                .seen_item_id_digests
                .contains(&packet.source_item_id_digest)
            {
                self.duplicate_item_count = self
                    .duplicate_item_count
                    .checked_add(1)
                    .context("duplicate item counter overflow")?;
                let prior = self
                    .result_packet
                    .as_ref()
                    .context("duplicate item has no prior packet")?;
                ensure!(
                    prior.content_digest == packet.content_digest
                        && prior.content_byte_count == packet.content_byte_count,
                    "duplicate item content drift"
                );
                self.validate()?;
                return Ok(false);
            }
            self.seen_item_id_digests
                .insert(packet.source_item_id_digest.clone());
            if let Some(prior) = self.result_packet.as_ref() {
                ensure!(
                    prior.content_digest == packet.content_digest,
                    "multiple distinct result items are ambiguous"
                );
            } else {
                self.result_packet = Some(packet);
            }
        }

        if let MappedTurnEventKind::TurnCompleted(status) = event.kind {
            if let Some(prior) = self.terminal {
                ensure!(prior == status, "terminal status drift");
            } else {
                self.terminal = Some(status);
            }
        }
        self.validate()?;
        Ok(true)
    }

    pub fn adopt_result(&mut self) -> Result<Option<RuntimeResultPacket>> {
        ensure!(
            self.terminal == Some(RuntimeTurnCompletionStatus::Completed),
            "only a completed runtime turn can be adopted"
        );
        let packet = self
            .result_packet
            .as_ref()
            .context("completed turn has no supported result packet")?;
        if self.adoption_count > 0 {
            return Ok(None);
        }
        self.adoption_count = 1;
        self.validate()?;
        Ok(Some(packet.clone()))
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == DISPATCH_JOURNAL_SCHEMA,
            "journal schema drift"
        );
        ensure!(
            bounded_identifier(&self.client_user_message_id)
                && is_hex_digest(&self.logical_turn_id_digest)
                && digest_hex(self.client_user_message_id.as_bytes())
                    == self.logical_turn_id_digest,
            "journal logical turn identity is invalid"
        );
        ensure!(
            self.mapping_digests
                .iter()
                .all(|digest| is_hex_digest(digest)),
            "journal mapping identity is invalid"
        );
        ensure!(
            self.seen_item_id_digests
                .iter()
                .all(|digest| is_hex_digest(digest)),
            "journal item identity is invalid"
        );
        ensure!(
            !self.model_visible_log.is_empty()
                && self.model_visible_log.len() <= 4_096
                && self
                    .model_visible_log
                    .iter()
                    .enumerate()
                    .all(|(index, entry)| {
                        entry.sequence == u64::try_from(index + 1).unwrap_or(u64::MAX)
                    }),
            "journal model-visible log sequence is invalid"
        );
        for entry in &self.model_visible_log {
            entry.validate()?;
        }
        ensure!(
            self.model_visible_log.first().is_some_and(|entry| {
                entry.direction == ModelVisibleLogDirection::Input
                    && entry.kind == ModelVisibleLogKind::TurnInput
            }) && self
                .model_visible_log
                .iter()
                .skip(1)
                .all(|entry| { entry.direction == ModelVisibleLogDirection::Output }),
            "journal model-visible log input/output boundary is invalid"
        );
        ensure!(self.adoption_count <= 1, "result adoption was duplicated");
        if let Some(packet) = self.result_packet.as_ref() {
            packet.validate()?;
            ensure!(
                self.seen_item_id_digests
                    .contains(&packet.source_item_id_digest),
                "journal packet is not backed by a seen item"
            );
            ensure!(
                self.terminal == Some(RuntimeTurnCompletionStatus::Completed)
                    || self.terminal.is_none(),
                "packet exists for a non-completed turn"
            );
        }
        Ok(())
    }

    pub fn terminal(&self) -> Option<RuntimeTurnCompletionStatus> {
        self.terminal
    }

    pub fn durable_model_visible_log_digest(&self) -> Result<String> {
        Ok(digest_hex(&serde_json::to_vec(&self.model_visible_log)?))
    }

    fn append_model_visible_output(
        &mut self,
        kind: ModelVisibleLogKind,
        event_digest: &str,
        item_id_digest: &str,
        content: &str,
    ) -> Result<()> {
        let sequence = u64::try_from(self.model_visible_log.len())
            .context("model-visible log sequence overflow")?
            .checked_add(1)
            .context("model-visible log sequence overflow")?;
        self.model_visible_log.push(ModelVisibleLogEntry::output(
            sequence,
            kind,
            event_digest,
            item_id_digest,
            content,
        )?);
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the report exposes independent authority and lifecycle assertions for eval evidence"
)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDispatchReport {
    pub schema: String,
    pub status: String,
    pub native_probe: bool,
    pub stream_event_count: u32,
    pub durable_model_visible_entry_count: u32,
    pub durable_session_log_digest: String,
    pub interrupt_terminal: Option<RuntimeTurnCompletionStatus>,
    pub restart_verified: bool,
    pub duplicate_item_suppressed: bool,
    pub adopted_result: bool,
    pub plugin_lifecycle_verified: bool,
    pub residual_plugin_registration_count: u32,
    pub effect_authority: bool,
    pub outcome_authority: bool,
    pub dispatch_identity: Option<MissionDispatchIdentity>,
    pub restart_identity: Option<MissionDispatchIdentity>,
    pub result_packet: Option<RuntimeResultPacket>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the ready report is boxed at the CLI boundary only after the result is materialized"
)]
pub enum NativeProbeOutcome {
    Ready(Box<RuntimeDispatchReport>),
    BlockedEnvironment { missing_env: Vec<String> },
}

pub fn run_fake_dispatch(workspace: &Path) -> Result<RuntimeDispatchReport> {
    let interrupt = run_interrupt_case(workspace)?;
    let restart = run_restart_case(workspace)?;
    let durable_model_visible_entry_count = interrupt
        .durable_log_entry_count
        .checked_add(restart.durable_log_entry_count)
        .context("durable model-visible log count overflow")?;
    let durable_session_log_digest = digest_hex(&serde_json::to_vec(&[
        interrupt.durable_log_digest.as_str(),
        restart.durable_log_digest.as_str(),
    ])?);
    let report = RuntimeDispatchReport {
        schema: DISPATCH_REPORT_SCHEMA.to_owned(),
        status: "PASS".to_owned(),
        native_probe: false,
        stream_event_count: interrupt.event_count + restart.event_count,
        durable_model_visible_entry_count,
        durable_session_log_digest,
        interrupt_terminal: Some(interrupt.terminal),
        restart_verified: restart.restart_verified,
        duplicate_item_suppressed: restart.duplicate_suppressed,
        adopted_result: restart.adopted_result,
        plugin_lifecycle_verified: interrupt.plugin_lifecycle_verified
            && restart.plugin_lifecycle_verified,
        residual_plugin_registration_count: interrupt.residual_plugin_registration_count
            + restart.residual_plugin_registration_count,
        effect_authority: false,
        outcome_authority: false,
        dispatch_identity: Some(restart.initial_identity),
        restart_identity: Some(restart.restart_identity),
        result_packet: Some(restart.packet),
    };
    ensure!(
        report.interrupt_terminal == Some(RuntimeTurnCompletionStatus::Interrupted),
        "fake interrupt vertical slice did not terminate as interrupted"
    );
    ensure!(
        report.restart_verified,
        "fake restart vertical slice was not verified"
    );
    ensure!(
        report.duplicate_item_suppressed,
        "fake restart did not suppress the duplicate item"
    );
    ensure!(
        report.adopted_result,
        "fake result packet was not adopted once"
    );
    ensure!(
        report.durable_model_visible_entry_count > 0
            && is_hex_digest(&report.durable_session_log_digest),
        "fake model-visible Mission/session log was not durably bound"
    );
    ensure!(
        report.plugin_lifecycle_verified && report.residual_plugin_registration_count == 0,
        "fake provider plugin lifecycle was not fully reversed"
    );
    Ok(report)
}

#[derive(Debug)]
struct InterruptCase {
    event_count: u32,
    terminal: RuntimeTurnCompletionStatus,
    durable_log_entry_count: u32,
    durable_log_digest: String,
    plugin_lifecycle_verified: bool,
    residual_plugin_registration_count: u32,
}

#[derive(Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the restart case exposes independent duplicate, adoption, and lifecycle assertions"
)]
struct RestartCase {
    event_count: u32,
    restart_verified: bool,
    duplicate_suppressed: bool,
    adopted_result: bool,
    initial_identity: MissionDispatchIdentity,
    restart_identity: MissionDispatchIdentity,
    packet: RuntimeResultPacket,
    durable_log_entry_count: u32,
    durable_log_digest: String,
    plugin_lifecycle_verified: bool,
    residual_plugin_registration_count: u32,
}

fn run_interrupt_case(workspace: &Path) -> Result<InterruptCase> {
    let (mut runtime, capabilities, catalog, config) = spawn_fake_runtime(workspace, "interrupt")?;
    let mut plugin = OpenInterpreterRuntimePlugin::new(
        "project-oi02",
        "mission-interrupt",
        "session-interrupt",
    )?;
    let prompt = "Return a bounded local execution message.";
    let mut journal = DispatchJournal::new(CLIENT_TURN_ID, prompt)?;
    let mapping = runtime.start_mapped_thread_with_config(
        "project-oi02",
        "mission-interrupt",
        1,
        workspace,
        &capabilities,
        &catalog,
        &config,
        Duration::from_secs(2),
    )?;
    let dispatch = runtime.start_mapped_turn_with_config(
        &mapping,
        &config,
        CLIENT_TURN_ID,
        prompt,
        Duration::from_secs(2),
    )?;
    let identity = MissionDispatchIdentity::from_mapping(&dispatch.mapping)?;
    journal.bind_dispatch(&identity)?;
    runtime.interrupt_mapped_turn(&dispatch.mapping, Duration::from_secs(2))?;

    for _ in 0..8 {
        let event = runtime.next_mapped_turn_event(&dispatch.mapping, Duration::from_secs(2))?;
        journal.record_event(&dispatch.mapping, &event)?;
        if journal.terminal().is_some() {
            break;
        }
    }
    ensure!(
        journal.terminal() == Some(RuntimeTurnCompletionStatus::Interrupted),
        "fake interrupt did not produce an interrupted terminal event"
    );
    ensure!(
        journal.adopt_result().is_err(),
        "interrupted turn produced an adoptable result"
    );
    let event_count = journal.stream_event_count;
    let terminal = journal
        .terminal()
        .context("interrupt terminal disappeared")?;
    let durable_log_entry_count = u32::try_from(journal.model_visible_log.len())
        .context("interrupt durable log count overflow")?;
    let durable_log_digest = journal.durable_model_visible_log_digest()?;
    let plugin_lifecycle_verified = plugin.unmount()?;
    let residual_plugin_registration_count = plugin.residual_registration_count();
    runtime
        .shutdown()
        .context("shutdown fake interrupt runtime")?;
    Ok(InterruptCase {
        event_count,
        terminal,
        durable_log_entry_count,
        durable_log_digest,
        plugin_lifecycle_verified,
        residual_plugin_registration_count,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "restart validation keeps persisted journal reload, resume, duplicate suppression, and single adoption together"
)]
fn run_restart_case(workspace: &Path) -> Result<RestartCase> {
    let (mut first_runtime, capabilities, catalog, config) =
        spawn_fake_runtime(workspace, "restart-1")?;
    let mut first_plugin = OpenInterpreterRuntimePlugin::new(
        "project-oi02",
        "mission-restart",
        "session-restart-generation-1",
    )?;
    let prompt = "Return one bounded local execution message.";
    let mut journal = DispatchJournal::new(CLIENT_TURN_ID, prompt)?;
    let first_mapping = first_runtime.start_mapped_thread_with_config(
        "project-oi02",
        "mission-restart",
        1,
        workspace,
        &capabilities,
        &catalog,
        &config,
        Duration::from_secs(2),
    )?;
    let first_dispatch = first_runtime.start_mapped_turn_with_config(
        &first_mapping,
        &config,
        CLIENT_TURN_ID,
        prompt,
        Duration::from_secs(2),
    )?;
    let initial_identity = MissionDispatchIdentity::from_mapping(&first_dispatch.mapping)?;
    journal.bind_dispatch(&initial_identity)?;
    for _ in 0..8 {
        let event = first_runtime
            .next_mapped_turn_event(&first_dispatch.mapping, Duration::from_secs(2))?;
        journal.record_event(&first_dispatch.mapping, &event)?;
        if journal.result_packet.is_some() {
            break;
        }
    }
    ensure!(
        journal.result_packet.is_some(),
        "first runtime did not produce a typed item stream result"
    );
    drop(first_runtime);
    let first_plugin_lifecycle_verified = first_plugin.unmount()?;
    let persisted_journal = serde_json::to_vec(&journal).context("persist dispatch journal")?;
    journal = serde_json::from_slice(&persisted_journal).context("reopen dispatch journal")?;
    journal.validate()?;

    let (mut restarted_runtime, restarted_capabilities, _, _) =
        spawn_fake_runtime(workspace, "restart-2")?;
    let mut restarted_plugin = OpenInterpreterRuntimePlugin::new(
        "project-oi02",
        "mission-restart",
        "session-restart-generation-2",
    )?;
    let resumed_mapping = restarted_runtime.resume_mapped_thread_with_config(
        "project-oi02",
        "mission-restart",
        2,
        FAKE_THREAD_ID,
        workspace,
        &restarted_capabilities,
        &catalog,
        &config,
        Duration::from_secs(2),
    )?;
    let restarted_dispatch = restarted_runtime.start_mapped_turn_with_config(
        &resumed_mapping,
        &config,
        CLIENT_TURN_ID,
        prompt,
        Duration::from_secs(2),
    )?;
    let restart_identity = MissionDispatchIdentity::from_mapping(&restarted_dispatch.mapping)?;
    journal.bind_dispatch(&restart_identity)?;
    ensure!(
        initial_identity.mapping_digest != restart_identity.mapping_digest,
        "restart did not create a new runtime mapping identity"
    );
    ensure!(
        restart_identity.runtime_generation == 2,
        "restart did not advance the runtime generation"
    );
    for _ in 0..8 {
        let event = restarted_runtime
            .next_mapped_turn_event(&restarted_dispatch.mapping, Duration::from_secs(2))?;
        journal.record_event(&restarted_dispatch.mapping, &event)?;
        if journal.terminal().is_some() {
            break;
        }
    }
    ensure!(
        journal.terminal() == Some(RuntimeTurnCompletionStatus::Completed),
        "restarted runtime did not complete"
    );
    ensure!(
        journal.duplicate_item_count == 1,
        "restarted runtime did not replay exactly one duplicate item"
    );
    let adopted = journal
        .adopt_result()?
        .context("completed result was not adoptable")?;
    ensure!(
        journal.adopt_result()?.is_none(),
        "adopted result was not duplicate-suppressed"
    );
    let event_count = journal.stream_event_count;
    let duplicate_suppressed = journal.duplicate_item_count == 1;
    let adopted_result = journal.adoption_count == 1;
    let durable_log_entry_count = u32::try_from(journal.model_visible_log.len())
        .context("restart durable log count overflow")?;
    let durable_log_digest = journal.durable_model_visible_log_digest()?;
    let restarted_plugin_lifecycle_verified = restarted_plugin.revoke()?;
    let plugin_lifecycle_verified =
        first_plugin_lifecycle_verified && restarted_plugin_lifecycle_verified;
    let residual_plugin_registration_count =
        first_plugin.residual_registration_count() + restarted_plugin.residual_registration_count();
    journal.validate()?;
    restarted_runtime
        .shutdown()
        .context("shutdown fake restarted runtime")?;
    Ok(RestartCase {
        event_count,
        restart_verified: duplicate_suppressed && adopted_result,
        duplicate_suppressed,
        adopted_result,
        initial_identity,
        restart_identity,
        packet: adopted,
        durable_log_entry_count,
        durable_log_digest,
        plugin_lifecycle_verified,
        residual_plugin_registration_count,
    })
}

fn spawn_fake_runtime(
    workspace: &Path,
    mode: &str,
) -> Result<(
    StdioRuntime,
    RuntimeCapabilities,
    RuntimeCatalog,
    RuntimeExecutionConfig,
)> {
    let reference = fake_secret_reference()?;
    let mut command = RuntimeCommand::new("/bin/sh", workspace);
    command.args = vec!["-c".to_owned(), fake_runtime_script(workspace)];
    command.shutdown_grace = Duration::from_millis(100);
    command
        .environment
        .insert("HARTEVO_FAKE_MODE".to_owned(), mode.to_owned());
    command.add_secret_binding("OPENAI_API_KEY", reference.clone())?;
    let resolver = FakeSecretResolver { reference };
    let mut runtime = StdioRuntime::spawn_with_secret_resolver(&command, &resolver)
        .context("spawn deterministic fake App Server")?;
    let capabilities = runtime
        .negotiate_capabilities(Duration::from_secs(2))
        .context("negotiate fake runtime capabilities")?;
    let catalog = runtime
        .discover_runtime_catalog("oi02-fake-catalog", Duration::from_secs(2))
        .context("discover fake runtime catalog")?;
    let config = config_for_selection(
        &catalog,
        FAKE_PROVIDER,
        FAKE_MODEL,
        FAKE_HARNESS,
        Some(FAKE_EFFORT.to_owned()),
        Some(FAKE_SERVICE_TIER.to_owned()),
        fake_secret_reference()?,
    )?;
    Ok((runtime, capabilities, catalog, config))
}

fn config_for_selection(
    catalog: &RuntimeCatalog,
    provider_id: &str,
    model_id: &str,
    harness_id: &str,
    reasoning_effort: Option<String>,
    service_tier: Option<String>,
    credential_reference: SecretReference,
) -> Result<RuntimeExecutionConfig> {
    let provider = catalog
        .provider(provider_id)
        .with_context(|| format!("provider {provider_id} is absent from catalog"))?;
    let model = catalog
        .model(provider_id, model_id)
        .with_context(|| format!("model {provider_id}/{model_id} is absent from catalog"))?;
    let harness = catalog
        .harness(provider_id, model_id, harness_id)
        .with_context(|| format!("harness {provider_id}/{model_id}/{harness_id} is absent"))?;
    let budget = RuntimeBudget::new(8_192, 4_096, 8, 60_000)?;
    RuntimeExecutionConfig::new(
        provider.id.clone(),
        provider.revision.clone(),
        model.id.clone(),
        model.revision.clone(),
        harness.id.clone(),
        harness.revision.clone(),
        reasoning_effort,
        service_tier,
        provider.endpoint_class,
        budget,
        RuntimeDataBoundary::ProviderDeclared,
        credential_reference,
        catalog.digest()?,
    )
    .context("construct exact runtime execution configuration")
}

fn fake_secret_reference() -> Result<SecretReference> {
    SecretReference::new(
        FAKE_PROVIDER,
        "oi02-fake-account",
        "keyring/oi02/fake",
        digest_hex(b"project-oi02"),
        1,
    )
    .context("construct fake secret reference")
}

#[derive(Debug)]
struct FakeSecretResolver {
    reference: SecretReference,
}

impl SecretResolver for FakeSecretResolver {
    fn resolve(&self, reference: &SecretReference) -> Result<ResolvedSecret, AdapterError> {
        if reference != &self.reference {
            return Err(AdapterError::InvalidSecretReference);
        }
        ResolvedSecret::new(FAKE_SECRET)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the fake App Server is an explicit deterministic protocol fixture for the whole OI-02 lifecycle"
)]
fn fake_runtime_script(workspace: &Path) -> String {
    let workspace_json = serde_json::to_string(&workspace.to_string_lossy().to_string())
        .expect("workspace path must serialize");
    let script = r#"
request_id() {
  id_part=__DOLLAR_LBRACE__1#*\"id\":}
  id_part=__DOLLAR_LBRACE__id_part%%,*}
  printf '%s' "$id_part"
}
while IFS= read -r request; do
  rid=$(request_id "$request")
  case "$request" in
    *'"method":"initialize"'*)
      if [ "$OPENAI_API_KEY" != "oi02-fake-secret" ]; then exit 42; fi
      printf '%s\n' '{"id":'"$rid"',"result":{}}'
      ;;
    *'"method":"interpreter/provider/list"'*)
      printf '%s\n' '{"id":'"$rid"',"result":{"data":[{"id":"openai","revision":"1111111111111111111111111111111111111111111111111111111111111111","wireApi":"responses","envKey":"OPENAI_API_KEY","configured":true}]}}'
      ;;
    *'"method":"interpreter/model/list"'*)
      printf '%s\n' '{"id":'"$rid"',"result":{"data":[{"model":"gpt-5.6","revision":"2222222222222222222222222222222222222222222222222222222222222222","supportedReasoningEfforts":[{"reasoningEffort":"medium"}],"serviceTiers":[{"id":"default","revision":"3333333333333333333333333333333333333333333333333333333333333333"}]}]}}'
      ;;
    *'"method":"interpreter/harness/list"'*)
      printf '%s\n' '{"id":'"$rid"',"result":{"data":[{"id":"native","revision":"4444444444444444444444444444444444444444444444444444444444444444","isRecommended":true}]}}'
      ;;
    *'"method":"interpreter/provider/set"'*)
      case "$request" in *'"providerId":"openai"'*) ;; *) exit 43 ;; esac
      printf '%s\n' '{"id":'"$rid"',"result":{}}'
      ;;
    *'"method":"interpreter/model/set"'*)
      case "$request" in *'"model":"gpt-5.6"'*'"reasoningEffort":"medium"'*) ;; *) exit 44 ;; esac
      printf '%s\n' '{"id":'"$rid"',"result":{}}'
      ;;
    *'"method":"interpreter/harness/set"'*)
      case "$request" in *'"harness":null'*) ;; *) exit 45 ;; esac
      printf '%s\n' '{"id":'"$rid"',"result":{}}'
      ;;
    *'"method":"thread/start"'*)
      case "$request" in *'"model":"gpt-5.6"'*) ;; *) exit 46 ;; esac
      printf '%s\n' '{"id":'"$rid"',"result":{"thread":{"id":"thread-oi02"},"cwd":__WORKSPACE__,"model":"gpt-5.6","modelProvider":"openai","approvalPolicy":"on-request","approvalsReviewer":"user","sandbox":"workspace-write"}}'
      ;;
    *'"method":"thread/resume"'*)
      case "$request" in *'"threadId":"thread-oi02"'*) ;; *) exit 47 ;; esac
      printf '%s\n' '{"id":'"$rid"',"result":{"thread":{"id":"thread-oi02"},"cwd":__WORKSPACE__,"model":"gpt-5.6","modelProvider":"openai","approvalPolicy":"on-request","approvalsReviewer":"user","sandbox":"workspace-write"}}'
      ;;
    *'"method":"turn/start"'*)
      case "$request" in *'"clientUserMessageId":"oi02-client-turn"'*) ;; *) exit 48 ;; esac
      printf '%s\n' '{"id":'"$rid"',"result":{"turn":{"id":"turn-oi02","status":"inProgress"}}}'
      printf '%s\n' '{"method":"turn/started","params":{"threadId":"thread-oi02","turn":{"id":"turn-oi02","status":"inProgress"}}}'
      printf '%s\n' '{"method":"item/started","params":{"threadId":"thread-oi02","turnId":"turn-oi02","item":{"id":"item-oi02","type":"agentMessage"}}}'
      printf '%s\n' '{"method":"item/agentMessage/delta","params":{"threadId":"thread-oi02","turnId":"turn-oi02","itemId":"item-oi02","delta":"fake "}}'
      case "$HARTEVO_FAKE_MODE" in
        interrupt) ;;
        restart-1)
          printf '%s\n' '{"method":"item/completed","params":{"threadId":"thread-oi02","turnId":"turn-oi02","item":{"id":"item-oi02","type":"agentMessage","text":"fake OI-02 result"}}}'
          exit 0
          ;;
        restart-2)
          printf '%s\n' '{"method":"item/completed","params":{"threadId":"thread-oi02","turnId":"turn-oi02","item":{"id":"item-oi02","type":"agentMessage","text":"fake OI-02 result"}}}'
          printf '%s\n' '{"method":"turn/completed","params":{"threadId":"thread-oi02","turn":{"id":"turn-oi02","status":"completed","items":[]}}}'
          ;;
        *) exit 49 ;;
      esac
      ;;
    *'"method":"turn/interrupt"'*)
      case "$request" in *'"threadId":"thread-oi02"'*'"turnId":"turn-oi02"'*) ;; *) exit 50 ;; esac
      printf '%s\n' '{"id":'"$rid"',"result":{}}'
      printf '%s\n' '{"method":"turn/completed","params":{"threadId":"thread-oi02","turn":{"id":"turn-oi02","status":"interrupted"}}}'
      ;;
    *) exit 51 ;;
  esac
done
"#;
    script
        .replace("__WORKSPACE__", &workspace_json)
        .replace("__DOLLAR_LBRACE__", "${")
}
#[allow(
    clippy::too_many_lines,
    reason = "the native probe keeps preflight, exact catalog selection, execution, and report admission auditable in one boundary"
)]
pub fn run_native_probe() -> Result<NativeProbeOutcome> {
    let provider_id = env::var("HARTEVO_TEST_PROVIDER")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "openai".to_owned());
    let credential_env = env::var("HARTEVO_TEST_CREDENTIAL_ENV")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default_credential_env(&provider_id).to_owned());
    let mut missing_env = Vec::new();
    let program = required_file_env("HARTEVO_TEST_OPENINTERPRETER_BIN", &mut missing_env);
    let runtime_home =
        required_directory_env("HARTEVO_TEST_OPENINTERPRETER_HOME", &mut missing_env);
    if !valid_environment_key(&credential_env) {
        missing_env.push("HARTEVO_TEST_CREDENTIAL_ENV".to_owned());
    } else if env::var(&credential_env)
        .ok()
        .is_none_or(|value| value.is_empty())
    {
        missing_env.push(credential_env.clone());
    }
    if !missing_env.is_empty() {
        missing_env.sort();
        missing_env.dedup();
        return Ok(NativeProbeOutcome::BlockedEnvironment { missing_env });
    }
    let program = program.context("native binary disappeared after preflight")?;
    let runtime_home = runtime_home.context("native runtime home disappeared after preflight")?;
    let workspace = env::current_dir()
        .context("read native probe workspace")?
        .canonicalize()
        .context("canonicalize native probe workspace")?;
    let target = host_openinterpreter_target()?;
    let verified = verify_pinned_runtime_artifact(&program, target)
        .context("verify exact pinned OpenInterpreter artifact")?;
    let mut command = verified
        .runtime_command(&workspace, &runtime_home)
        .context("construct isolated native runtime command")?;
    let reference = SecretReference::new(
        provider_id.clone(),
        env::var("HARTEVO_TEST_ACCOUNT_ID")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "native-probe-account".to_owned()),
        format!("os-keyring/{provider_id}/native-probe"),
        digest_hex(b"native-probe-project"),
        1,
    )?;
    command.add_secret_binding(&credential_env, reference.clone())?;
    let resolver = EnvironmentSecretResolver {
        environment_key: credential_env.clone(),
    };
    let mut runtime = StdioRuntime::spawn_with_secret_resolver(&command, &resolver)
        .context("spawn credentialed pinned native App Server")?;
    let capabilities = runtime
        .negotiate_capabilities(Duration::from_secs(15))
        .context("negotiate native runtime capabilities")?;
    let catalog = runtime
        .discover_runtime_catalog("oi02-native-probe", Duration::from_secs(15))
        .context("discover native runtime catalog")?;
    let provider = catalog
        .provider(&provider_id)
        .with_context(|| format!("native provider {provider_id} is absent from catalog"))?;
    ensure!(provider.configured, "native provider is not configured");
    ensure!(
        provider.credential_environment_key.as_deref() == Some(credential_env.as_str()),
        "native provider credential environment does not match the selected secret reference"
    );
    let model_id = env::var("HARTEVO_TEST_MODEL")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            catalog
                .models
                .iter()
                .find(|model| model.provider_id == provider_id)
                .map(|model| model.id.clone())
        })
        .context("native provider has no selectable model")?;
    let model = catalog
        .model(&provider_id, &model_id)
        .with_context(|| format!("native model {provider_id}/{model_id} is absent"))?;
    let harness_id = env::var("HARTEVO_TEST_HARNESS")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            catalog
                .harnesses
                .iter()
                .find(|harness| {
                    harness.provider_id == provider_id
                        && harness
                            .model_id
                            .as_deref()
                            .is_none_or(|candidate| candidate == model_id)
                        && harness.recommended
                })
                .or_else(|| {
                    catalog.harnesses.iter().find(|harness| {
                        harness.provider_id == provider_id
                            && harness
                                .model_id
                                .as_deref()
                                .is_none_or(|candidate| candidate == model_id)
                    })
                })
                .map(|harness| harness.id.clone())
        })
        .context("native route has no selectable harness")?;
    let reasoning_effort = env::var("HARTEVO_TEST_REASONING_EFFORT")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| model.supported_reasoning_efforts.first().cloned());
    let service_tier = env::var("HARTEVO_TEST_SERVICE_TIER")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| model.service_tiers.first().map(|tier| tier.id.clone()));
    let config = config_for_selection(
        &catalog,
        &provider_id,
        &model_id,
        &harness_id,
        reasoning_effort,
        service_tier,
        reference,
    )?;
    let mut plugin = OpenInterpreterRuntimePlugin::new(
        "native-probe-project",
        "native-probe-mission",
        "native-probe-session",
    )?;
    let prompt = "Return a short plain-text runtime readiness response without using tools.";
    let mut journal = DispatchJournal::new("hartevo-native-probe-turn", prompt)?;
    let mapping = runtime.start_mapped_thread_with_config(
        "native-probe-project",
        "native-probe-mission",
        1,
        &workspace,
        &capabilities,
        &catalog,
        &config,
        Duration::from_secs(15),
    )?;
    let dispatch = runtime.start_mapped_turn_with_config(
        &mapping,
        &config,
        "hartevo-native-probe-turn",
        prompt,
        Duration::from_secs(30),
    )?;
    let identity = MissionDispatchIdentity::from_mapping(&dispatch.mapping)?;
    journal.bind_dispatch(&identity)?;
    for _ in 0..256 {
        let event = runtime.next_mapped_turn_event(&dispatch.mapping, Duration::from_secs(30))?;
        if matches!(&event.kind, MappedTurnEventKind::LocalApprovalRequested(_)) {
            bail!("native probe encountered an approval request and cannot grant an effect");
        }
        journal.record_event(&dispatch.mapping, &event)?;
        if journal.terminal().is_some() {
            break;
        }
    }
    let terminal = journal
        .terminal()
        .context("native runtime did not emit a terminal event")?;
    if terminal == RuntimeTurnCompletionStatus::Completed {
        ensure!(
            journal.result_packet.is_some(),
            "native completed turn had no bounded typed result item"
        );
    }
    let result_packet = journal.result_packet.clone();
    let durable_model_visible_entry_count = u32::try_from(journal.model_visible_log.len())
        .context("native durable log count overflow")?;
    let durable_session_log_digest = journal.durable_model_visible_log_digest()?;
    journal.validate()?;
    let plugin_lifecycle_verified = plugin.revoke()?;
    let residual_plugin_registration_count = plugin.residual_registration_count();
    runtime
        .shutdown()
        .context("shutdown native probe runtime")?;
    Ok(NativeProbeOutcome::Ready(Box::new(RuntimeDispatchReport {
        schema: DISPATCH_REPORT_SCHEMA.to_owned(),
        status: if terminal == RuntimeTurnCompletionStatus::Completed {
            "PASS".to_owned()
        } else {
            "FAIL".to_owned()
        },
        native_probe: true,
        stream_event_count: journal.stream_event_count,
        durable_model_visible_entry_count,
        durable_session_log_digest,
        interrupt_terminal: None,
        restart_verified: false,
        duplicate_item_suppressed: false,
        adopted_result: false,
        plugin_lifecycle_verified,
        residual_plugin_registration_count,
        effect_authority: false,
        outcome_authority: false,
        dispatch_identity: Some(identity),
        restart_identity: None,
        result_packet,
    })))
}

#[derive(Debug)]
struct EnvironmentSecretResolver {
    environment_key: String,
}

impl SecretResolver for EnvironmentSecretResolver {
    fn resolve(&self, reference: &SecretReference) -> Result<ResolvedSecret, AdapterError> {
        let reference_digest = reference.digest()?;
        let value = env::var(&self.environment_key)
            .map_err(|_| AdapterError::SecretResolutionFailed { reference_digest })?;
        ResolvedSecret::new(value)
    }
}

fn required_file_env(key: &str, missing_env: &mut Vec<String>) -> Option<PathBuf> {
    let Some(value) = env::var_os(key).filter(|value| !value.is_empty()) else {
        missing_env.push(key.to_owned());
        return None;
    };
    let path = PathBuf::from(value);
    if path.is_file() {
        Some(path)
    } else {
        missing_env.push(key.to_owned());
        None
    }
}

fn required_directory_env(key: &str, missing_env: &mut Vec<String>) -> Option<PathBuf> {
    let Some(value) = env::var_os(key).filter(|value| !value.is_empty()) else {
        missing_env.push(key.to_owned());
        return None;
    };
    let path = PathBuf::from(value);
    if path.is_dir() {
        Some(path)
    } else {
        missing_env.push(key.to_owned());
        None
    }
}

fn default_credential_env(provider_id: &str) -> &'static str {
    match provider_id {
        "anthropic" => "ANTHROPIC_API_KEY",
        "openai" => "OPENAI_API_KEY",
        _ => "HARTEVO_TEST_API_KEY",
    }
}

fn endpoint_name(endpoint_class: RuntimeEndpointClass) -> &'static str {
    match endpoint_class {
        RuntimeEndpointClass::Responses => "responses",
        RuntimeEndpointClass::Chat => "chat",
        RuntimeEndpointClass::Messages => "messages",
        RuntimeEndpointClass::Local => "local",
    }
}

fn valid_environment_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0)
}

fn is_hex_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn digest_hex(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_fake_runtime_proves_stream_interrupt_restart_and_adoption() {
        let workspace = env::current_dir()
            .expect("eval workspace")
            .canonicalize()
            .expect("canonical eval workspace");
        let report = run_fake_dispatch(&workspace).expect("fake OI-02 dispatch");
        assert_eq!(report.status, "PASS");
        assert_eq!(
            report.interrupt_terminal,
            Some(RuntimeTurnCompletionStatus::Interrupted)
        );
        assert!(report.restart_verified);
        assert!(report.duplicate_item_suppressed);
        assert!(report.adopted_result);
        assert!(report.durable_model_visible_entry_count >= 5);
        assert!(is_hex_digest(&report.durable_session_log_digest));
        assert!(report.plugin_lifecycle_verified);
        assert_eq!(report.residual_plugin_registration_count, 0);
        assert!(!report.effect_authority);
        assert!(!report.outcome_authority);
        let packet = report.result_packet.as_ref().expect("result packet");
        assert_eq!(packet.content, "fake OI-02 result");
        assert!(!format!("{packet:?}").contains("fake OI-02 result"));
    }
}
