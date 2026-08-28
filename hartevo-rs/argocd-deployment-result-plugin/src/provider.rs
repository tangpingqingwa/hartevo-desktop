use std::{fmt, mem};

use serde::Deserialize;

use crate::error::{ArgoCdDeploymentError, ArgoCdTransportError, Result};
use crate::model::{
    ArgoApplicationSnapshot, ArgoCdApplicationId, ArgoCdClusterId, ArgoCdDeploymentScope,
    ArgoCdInstanceId, ArgoCdNamespace, ArgoCdProjectId, ArgoHealthStatus, ArgoOperationPhase,
    ArgoOperationSnapshot, ArgoRequestReceipt, ArgoResourceTreeSnapshot, ArgoSyncStatus,
    ArgoSyncStatusSnapshot, Digest, Identifier, MAX_RESOURCE_NODES, MAX_RETRY_ATTEMPTS,
    ProviderProvenance, Revision, SecretReference,
};
use crate::transport::{
    ArgoCdOperation, ArgoCdRequest, ArgoCdResponse, ArgoCdTransport, RetryPolicy,
};
use crate::{ARGOCD_API_REVISION, CONSUMER_ID, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID};

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArgoCdProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub consumer_id: String,
    pub service_id: String,
}

impl Default for ArgoCdProviderDefinition {
    fn default() -> Self {
        let permissions = crate::model::LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<Vec<_>>();
        let provider_digest = Digest::from_parts(
            "argocd-provider/v1",
            &[
                ("id", PROVIDER_ID.to_owned()),
                ("version", PLUGIN_VERSION.to_owned()),
                ("api", ARGOCD_API_REVISION.to_owned()),
                ("permissions", permissions.join("\u{1f}")),
            ],
        );
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PLUGIN_VERSION.to_owned(),
            api_revision: ARGOCD_API_REVISION.to_owned(),
            provider_digest,
            permissions,
            read_only: true,
            recording_only: true,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
            consumer_id: CONSUMER_ID.to_owned(),
            service_id: SERVICE_ID.to_owned(),
        }
    }
}

impl ArgoCdProviderDefinition {
    #[must_use]
    pub const fn is_layer_one_honest(&self) -> bool {
        self.read_only
            && self.recording_only
            && !self.external_writes
            && !self.connected
            && !self.native
            && !self.first_party
    }
}

/// Standalone typed Argo CD provider. It has no native HTTP client, credential
/// resolver, Kubernetes client, or write operation.
pub struct ArgoCdProvider<T: ArgoCdTransport> {
    scope: ArgoCdDeploymentScope,
    secret_reference: SecretReference,
    transport: T,
    definition: ArgoCdProviderDefinition,
    retry_policy: RetryPolicy,
    last_backoff: Option<crate::model::BackoffReceipt>,
    request_receipts: Vec<ArgoRequestReceipt>,
}

impl<T: ArgoCdTransport> fmt::Debug for ArgoCdProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArgoCdProvider")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("transport", &self.transport)
            .field("definition", &self.definition)
            .field("retry_policy", &self.retry_policy)
            .field("last_backoff", &self.last_backoff)
            .field("request_receipt_count", &self.request_receipts.len())
            .finish()
    }
}

impl<T: ArgoCdTransport> ArgoCdProvider<T> {
    pub fn new(
        transport: T,
        scope: ArgoCdDeploymentScope,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        secret_reference.validate(&scope)?;
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition: ArgoCdProviderDefinition::default(),
            retry_policy: RetryPolicy::default(),
            last_backoff: None,
            request_receipts: Vec::new(),
        })
    }

    pub fn with_scope(
        scope: ArgoCdDeploymentScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self> {
        Self::new(transport, scope, secret_reference)
    }

    #[must_use]
    pub fn scope(&self) -> &ArgoCdDeploymentScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &ArgoCdProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.definition.provider_digest
    }

    #[must_use]
    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn set_retry_policy(&mut self, retry_policy: RetryPolicy) -> Result<()> {
        if retry_policy.max_attempts == 0 || retry_policy.max_attempts > MAX_RETRY_ATTEMPTS {
            return Err(ArgoCdDeploymentError::InvalidRequest);
        }
        self.retry_policy = retry_policy;
        Ok(())
    }

    #[must_use]
    pub fn take_backoff(&mut self) -> Option<crate::model::BackoffReceipt> {
        self.last_backoff.take()
    }

    #[must_use]
    pub fn take_request_receipts(&mut self) -> Vec<ArgoRequestReceipt> {
        mem::take(&mut self.request_receipts)
    }

    pub fn read_application(&mut self) -> Result<ArgoApplicationSnapshot> {
        let response = self.execute_request(ArgoCdOperation::ReadApplication)?;
        let wire: ApplicationWire = parse_json(&response)?;
        self.snapshot_application(wire)
    }

    pub fn read_resource_tree(&mut self) -> Result<ArgoResourceTreeSnapshot> {
        let response = self.execute_request(ArgoCdOperation::ReadResourceTree)?;
        let wire: ResourceTreeWire = parse_json(&response)?;
        self.snapshot_resource_tree(wire)
    }

    pub fn read_sync_status(&mut self) -> Result<ArgoSyncStatusSnapshot> {
        let response = self.execute_request(ArgoCdOperation::ReadSyncStatus)?;
        let wire: SyncStatusWire = parse_json(&response)?;
        self.snapshot_sync_status(wire)
    }

    pub fn read_operation(&mut self) -> Result<ArgoOperationSnapshot> {
        let response = self.execute_request(ArgoCdOperation::ReadOperation)?;
        let wire: OperationWire = parse_json(&response)?;
        self.snapshot_operation(wire)
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<()> {
        Err(ArgoCdDeploymentError::MutationForbidden { operation })
    }

    fn execute_request(&mut self, operation: ArgoCdOperation) -> Result<ArgoCdResponse> {
        let request = ArgoCdRequest::for_scope(&self.scope, operation);
        if !request.is_allowlisted() {
            return Err(ArgoCdDeploymentError::InvalidRequest);
        }
        self.last_backoff = None;
        let mut attempt = 1;
        loop {
            let response = match self.transport.execute(&request) {
                Ok(response) => response,
                Err(ArgoCdTransportError::RateLimited {
                    retry_after_seconds,
                }) if attempt < self.retry_policy.max_attempts => {
                    self.request_receipts.push(ArgoRequestReceipt::new(
                        operation.as_str(),
                        request.method(),
                        request.request_digest().clone(),
                        Some(429),
                        None,
                        None,
                    ));
                    self.last_backoff = Some(crate::model::BackoffReceipt::new(
                        attempt + 1,
                        retry_after_seconds
                            .unwrap_or_else(|| self.retry_policy.backoff_seconds(attempt)),
                    ));
                    attempt += 1;
                    continue;
                }
                Err(error) => {
                    self.request_receipts.push(ArgoRequestReceipt::new(
                        operation.as_str(),
                        request.method(),
                        request.request_digest().clone(),
                        error.status_code(),
                        None,
                        None,
                    ));
                    return Err(ArgoCdDeploymentError::Transport(error));
                }
            };
            if response.status() == 429 && attempt < self.retry_policy.max_attempts {
                self.request_receipts.push(ArgoRequestReceipt::new(
                    operation.as_str(),
                    request.method(),
                    request.request_digest().clone(),
                    Some(response.status()),
                    Some(response.response_bytes()),
                    Some(response.response_digest()),
                ));
                self.last_backoff = Some(crate::model::BackoffReceipt::new(
                    attempt + 1,
                    self.retry_policy.backoff_seconds(attempt),
                ));
                attempt += 1;
                continue;
            }
            let receipt = ArgoRequestReceipt::new(
                operation.as_str(),
                request.method(),
                request.request_digest().clone(),
                Some(response.status()),
                Some(response.response_bytes()),
                Some(response.response_digest()),
            );
            let validation = response.validate_size_and_digest();
            self.request_receipts.push(receipt);
            validation?;
            if response.status() != 200 {
                return Err(ArgoCdDeploymentError::Transport(status_error(
                    response.status(),
                )));
            }
            return Ok(response);
        }
    }

    fn snapshot_application(&self, wire: ApplicationWire) -> Result<ArgoApplicationSnapshot> {
        let metadata = wire.metadata.unwrap_or_default();
        let spec = wire.spec.unwrap_or_default();
        let status = wire.status.unwrap_or_default();
        let destination = spec.destination.unwrap_or_default();
        let source = spec.source.unwrap_or_default();
        let status_sync = status.sync.unwrap_or_default();
        let status_health = status.health.unwrap_or_default();
        let status_operation = status.operation_state.unwrap_or_default();
        let instance = identifier_or_scope(wire.instance_id, &self.scope.instance)?;
        let project = identifier_or_scope(wire.project.or(spec.project), &self.scope.project)?;
        let application =
            identifier_or_scope(wire.application.or(metadata.name), &self.scope.application)?;
        let cluster =
            identifier_or_scope(wire.cluster.or(destination.server), &self.scope.cluster)?;
        let namespace = identifier_or_scope(
            wire.namespace.or(destination.namespace),
            &self.scope.namespace,
        )?;
        let target_revision = identifier_or_scope(
            wire.target_revision.or(source.target_revision),
            &self.scope.target_revision,
        )?;
        let sync_operation = wire
            .sync_operation
            .or(status_operation.operation_id)
            .map(Identifier::new)
            .transpose()?;
        validate_scope_identity(
            &self.scope,
            &instance,
            &project,
            &application,
            &cluster,
            &namespace,
        )?;
        if target_revision != *self.scope.target_revision() {
            return Err(ArgoCdDeploymentError::StaleRevision);
        }
        if sync_operation
            .as_ref()
            .is_some_and(|value| value != &self.scope.sync_operation)
        {
            return Err(ArgoCdDeploymentError::StaleRevision);
        }
        let observed_revision = Revision::new(
            wire.observed_revision
                .or(status.observed_revision)
                .unwrap_or(1)
                .max(1),
        )?;
        Ok(ArgoApplicationSnapshot {
            instance,
            project,
            application,
            cluster,
            namespace,
            target_revision,
            sync_operation,
            sync_status: ArgoSyncStatus::from_wire(
                &wire
                    .sync_status
                    .or(status_sync.status)
                    .unwrap_or_else(|| "Unknown".to_owned()),
            ),
            health_status: ArgoHealthStatus::from_wire(
                &wire
                    .health_status
                    .or(status_health.status)
                    .unwrap_or_else(|| "Unknown".to_owned()),
            ),
            observed_revision,
        })
    }

    fn snapshot_resource_tree(&self, wire: ResourceTreeWire) -> Result<ArgoResourceTreeSnapshot> {
        let instance = identifier_or_scope(wire.instance_id, &self.scope.instance)?;
        let project = identifier_or_scope(wire.project, &self.scope.project)?;
        let application = identifier_or_scope(wire.application, &self.scope.application)?;
        let cluster = identifier_or_scope(wire.cluster, &self.scope.cluster)?;
        let namespace = identifier_or_scope(wire.namespace, &self.scope.namespace)?;
        validate_scope_identity(
            &self.scope,
            &instance,
            &project,
            &application,
            &cluster,
            &namespace,
        )?;
        if wire.nodes.len() > MAX_RESOURCE_NODES {
            return Err(ArgoCdDeploymentError::ResourceBound);
        }
        let mut healthy_count = 0_u32;
        let mut synced_count = 0_u32;
        let mut unknown_count = 0_u32;
        let mut node_components = Vec::with_capacity(wire.nodes.len());
        for node in wire.nodes {
            let group = node.group.unwrap_or_default();
            let version = node.version.unwrap_or_else(|| "v1".to_owned());
            let kind = node.kind.ok_or(ArgoCdDeploymentError::InvalidResponse)?;
            let node_namespace = node.namespace.unwrap_or_default();
            let name = node.name.ok_or(ArgoCdDeploymentError::InvalidResponse)?;
            if !valid_wire_text(&group)
                || !valid_wire_text(&version)
                || !valid_wire_text(&kind)
                || !valid_wire_text(&node_namespace)
                || !valid_wire_text(&name)
            {
                return Err(ArgoCdDeploymentError::InvalidResponse);
            }
            let health = ArgoHealthStatus::from_wire(
                node.health
                    .and_then(|health| health.status)
                    .as_deref()
                    .or(node.health_status.as_deref())
                    .unwrap_or("Unknown"),
            );
            let sync = ArgoSyncStatus::from_wire(
                node.sync_status
                    .as_deref()
                    .or(node.status.as_deref())
                    .unwrap_or("Unknown"),
            );
            if health == ArgoHealthStatus::Healthy {
                healthy_count = healthy_count.saturating_add(1);
            }
            if sync == ArgoSyncStatus::Synced {
                synced_count = synced_count.saturating_add(1);
            }
            if health == ArgoHealthStatus::Unknown || sync == ArgoSyncStatus::Unknown {
                unknown_count = unknown_count.saturating_add(1);
            }
            node_components.push(format!(
                "{group}|{version}|{kind}|{node_namespace}|{name}|{health:?}|{sync:?}|{}",
                node.resource_version.unwrap_or_default()
            ));
        }
        node_components.sort_unstable();
        Ok(ArgoResourceTreeSnapshot {
            node_count: u32::try_from(node_components.len()).unwrap_or(u32::MAX),
            healthy_count,
            synced_count,
            unknown_count,
            partial: wire.partial.unwrap_or(false),
            tree_digest: Digest::from_parts(
                "argocd-resource-tree/v1",
                &[
                    ("scope", self.scope.digest().as_str().to_owned()),
                    ("nodes", node_components.join("\u{1f}")),
                ],
            ),
        })
    }

    fn snapshot_sync_status(&self, wire: SyncStatusWire) -> Result<ArgoSyncStatusSnapshot> {
        let status = wire.status.unwrap_or_default();
        let instance = identifier_or_scope(wire.instance_id, &self.scope.instance)?;
        let project = identifier_or_scope(wire.project, &self.scope.project)?;
        let application = identifier_or_scope(wire.application, &self.scope.application)?;
        let cluster = identifier_or_scope(wire.cluster, &self.scope.cluster)?;
        let namespace = identifier_or_scope(wire.namespace, &self.scope.namespace)?;
        let target_revision = identifier_or_scope(
            wire.target_revision.or(status.target_revision),
            &self.scope.target_revision,
        )?;
        let sync_operation = wire
            .sync_operation
            .or(status.sync_operation)
            .map(Identifier::new)
            .transpose()?;
        validate_scope_identity(
            &self.scope,
            &instance,
            &project,
            &application,
            &cluster,
            &namespace,
        )?;
        if target_revision != *self.scope.target_revision() {
            return Err(ArgoCdDeploymentError::StaleRevision);
        }
        if sync_operation
            .as_ref()
            .is_some_and(|value| value != &self.scope.sync_operation)
        {
            return Err(ArgoCdDeploymentError::StaleRevision);
        }
        let observed_revision = Revision::new(
            wire.observed_revision
                .or(status.observed_revision)
                .unwrap_or(1)
                .max(1),
        )?;
        let sync_status = ArgoSyncStatus::from_wire(
            &wire
                .sync_status
                .or(status.sync_status)
                .unwrap_or_else(|| "Unknown".to_owned()),
        );
        let health_status = ArgoHealthStatus::from_wire(
            &wire
                .health_status
                .or(status.health_status)
                .unwrap_or_else(|| "Unknown".to_owned()),
        );
        let sync_status_digest = Digest::from_parts(
            "argocd-sync-status/v1",
            &[
                ("scope", self.scope.digest().as_str().to_owned()),
                (
                    "target_revision",
                    target_revision.digest().as_str().to_owned(),
                ),
                ("sync_status", format!("{sync_status:?}")),
                ("health_status", format!("{health_status:?}")),
                ("observed_revision", observed_revision.get().to_string()),
                (
                    "sync_operation",
                    sync_operation
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
            ],
        );
        Ok(ArgoSyncStatusSnapshot {
            sync_status,
            health_status,
            target_revision,
            observed_revision,
            sync_operation,
            sync_status_digest,
        })
    }

    fn snapshot_operation(&self, wire: OperationWire) -> Result<ArgoOperationSnapshot> {
        let state = wire.operation_state.unwrap_or_default();
        let instance = identifier_or_scope(wire.instance_id, &self.scope.instance)?;
        let project = identifier_or_scope(wire.project, &self.scope.project)?;
        let application = identifier_or_scope(wire.application, &self.scope.application)?;
        let cluster = identifier_or_scope(wire.cluster, &self.scope.cluster)?;
        let namespace = identifier_or_scope(wire.namespace, &self.scope.namespace)?;
        let sync_operation = identifier_or_scope(
            wire.sync_operation
                .or(state.operation_id)
                .or_else(|| wire.metadata.and_then(|metadata| metadata.name)),
            &self.scope.sync_operation,
        )?;
        let target_revision = identifier_or_scope(
            wire.target_revision.or(state.target_revision),
            &self.scope.target_revision,
        )?;
        validate_scope_identity(
            &self.scope,
            &instance,
            &project,
            &application,
            &cluster,
            &namespace,
        )?;
        if target_revision != *self.scope.target_revision()
            || sync_operation != *self.scope.sync_operation()
        {
            return Err(ArgoCdDeploymentError::StaleRevision);
        }
        let detail_digest = wire
            .detail
            .or(state.message)
            .filter(|value| !value.is_empty())
            .map(Digest::from_text);
        let phase = ArgoOperationPhase::from_wire(
            &wire
                .phase
                .or(state.phase)
                .unwrap_or_else(|| "Unknown".to_owned()),
        );
        let operation_digest = Digest::from_parts(
            "argocd-operation/v1",
            &[
                ("scope", self.scope.digest().as_str().to_owned()),
                ("operation", sync_operation.digest().as_str().to_owned()),
                (
                    "target_revision",
                    target_revision.digest().as_str().to_owned(),
                ),
                ("phase", format!("{phase:?}")),
                (
                    "started_at",
                    wire.started_at
                        .or(state.started_at)
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "finished_at",
                    wire.finished_at
                        .or(state.finished_at)
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "detail",
                    detail_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        );
        Ok(ArgoOperationSnapshot {
            sync_operation,
            target_revision,
            phase,
            started_at: wire.started_at.or(state.started_at),
            finished_at: wire.finished_at.or(state.finished_at),
            detail_digest,
            operation_digest,
        })
    }
}

fn parse_json<T: for<'de> Deserialize<'de>>(response: &ArgoCdResponse) -> Result<T> {
    serde_json::from_slice(response.body()).map_err(|_| ArgoCdDeploymentError::InvalidResponse)
}

fn status_error(status: u16) -> ArgoCdTransportError {
    match status {
        401 | 403 => ArgoCdTransportError::AccessLost,
        404 => ArgoCdTransportError::NotFound,
        409 => ArgoCdTransportError::Conflict,
        429 => ArgoCdTransportError::RateLimited {
            retry_after_seconds: None,
        },
        408 => ArgoCdTransportError::Timeout,
        status if (500..=599).contains(&status) => ArgoCdTransportError::ProviderUnknown,
        _ => ArgoCdTransportError::ProviderUnknown,
    }
}

fn identifier_or_scope(value: Option<String>, fallback: &Identifier) -> Result<Identifier> {
    value.map_or_else(|| Ok(fallback.clone()), Identifier::new)
}

fn valid_wire_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::model::MAX_IDENTIFIER_BYTES
        && !value.chars().any(char::is_control)
}

fn validate_scope_identity(
    scope: &ArgoCdDeploymentScope,
    instance: &ArgoCdInstanceId,
    project: &ArgoCdProjectId,
    application: &ArgoCdApplicationId,
    cluster: &ArgoCdClusterId,
    namespace: &ArgoCdNamespace,
) -> Result<()> {
    if instance != scope.instance()
        || project != scope.project()
        || application != scope.application()
        || cluster != scope.cluster()
        || namespace != scope.namespace()
        || !scope.application_is_allowed(application)
    {
        return Err(ArgoCdDeploymentError::ScopeMismatch);
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationWire {
    #[serde(alias = "instance")]
    instance_id: Option<String>,
    project: Option<String>,
    application: Option<String>,
    cluster: Option<String>,
    namespace: Option<String>,
    target_revision: Option<String>,
    sync_status: Option<String>,
    health_status: Option<String>,
    observed_revision: Option<u64>,
    sync_operation: Option<String>,
    metadata: Option<MetadataWire>,
    spec: Option<ApplicationSpecWire>,
    status: Option<ApplicationStatusWire>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MetadataWire {
    name: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationSpecWire {
    project: Option<String>,
    destination: Option<DestinationWire>,
    source: Option<SourceWire>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DestinationWire {
    server: Option<String>,
    namespace: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceWire {
    target_revision: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationStatusWire {
    sync: Option<SyncWire>,
    health: Option<HealthWire>,
    operation_state: Option<OperationStateWire>,
    observed_revision: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncWire {
    status: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HealthWire {
    status: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OperationStateWire {
    phase: Option<String>,
    message: Option<String>,
    operation_id: Option<String>,
    target_revision: Option<String>,
    started_at: Option<u64>,
    finished_at: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResourceTreeWire {
    instance_id: Option<String>,
    project: Option<String>,
    application: Option<String>,
    cluster: Option<String>,
    namespace: Option<String>,
    nodes: Vec<ResourceNodeWire>,
    partial: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResourceNodeWire {
    group: Option<String>,
    version: Option<String>,
    kind: Option<String>,
    namespace: Option<String>,
    name: Option<String>,
    health_status: Option<String>,
    sync_status: Option<String>,
    status: Option<String>,
    health: Option<HealthWire>,
    resource_version: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncStatusWire {
    instance_id: Option<String>,
    project: Option<String>,
    application: Option<String>,
    cluster: Option<String>,
    namespace: Option<String>,
    target_revision: Option<String>,
    sync_status: Option<String>,
    health_status: Option<String>,
    observed_revision: Option<u64>,
    sync_operation: Option<String>,
    status: Option<SyncStatusBodyWire>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncStatusBodyWire {
    sync_status: Option<String>,
    health_status: Option<String>,
    target_revision: Option<String>,
    observed_revision: Option<u64>,
    sync_operation: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OperationWire {
    instance_id: Option<String>,
    project: Option<String>,
    application: Option<String>,
    cluster: Option<String>,
    namespace: Option<String>,
    sync_operation: Option<String>,
    target_revision: Option<String>,
    phase: Option<String>,
    started_at: Option<u64>,
    finished_at: Option<u64>,
    detail: Option<String>,
    metadata: Option<MetadataWire>,
    operation_state: Option<OperationStateWire>,
}
