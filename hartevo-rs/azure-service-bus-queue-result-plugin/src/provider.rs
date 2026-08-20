//! Read-only Azure Service Bus ARM provider boundary.
//!
//! Only the documented queue description and namespace queue-list operations
//! are represented. There is intentionally no Azure SDK, Entra resolver,
//! signer, native HTTP client, message operation, authorization-rule reader,
//! or raw provider-payload return type.

use std::{collections::VecDeque, fmt};

use serde_json::Value;
use thiserror::Error;

use crate::{
    AZURE_SERVICE_BUS_API_VERSION, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID,
    model::{
        AzureServiceBusReadOperation, AzureServiceBusReadPage, AzureServiceBusReadRequest,
        AzureServiceBusScope, Digest, ModelError, OpaqueContinuation, ProviderErrorKind,
        ProviderId, ProviderRevision, QueueConfigurationProjection, QueueCountProjection,
        QueuePostureProjection, QueueStatus, TransportError, TransportProvenance,
    },
};

pub const ARM_QUEUE_GET_PATH_TEMPLATE: &str = "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}/queues/{queueName}";
pub const ARM_QUEUE_LIST_PATH_TEMPLATE: &str = "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}/queues";

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("Azure Service Bus provider model error: {0}")]
    Model(#[from] ModelError),
    #[error("Azure Service Bus provider revision is incompatible")]
    RevisionMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureServiceBusProviderIdentity {
    pub provider_id: ProviderId,
    pub version: String,
    pub api_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AzureServiceBusProviderIdentity {
    pub fn for_provenance(
        provenance: TransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_id = ProviderId::new(PROVIDER_ID)?;
        let api_revision = ProviderRevision::new(PROVIDER_API_REVISION)?;
        let provider_digest = Digest::from_fields(
            "hartevo-azure-service-bus-provider/v1",
            &[
                ("provider", provider_id.as_str().to_owned()),
                ("version", PLUGIN_VERSION.to_owned()),
                ("api_revision", api_revision.as_str().to_owned()),
                ("provenance", format!("{provenance:?}")),
            ],
        );
        let api_digest = Digest::from_fields(
            "hartevo-azure-service-bus-api-allowlist/v1",
            &[
                (
                    "get",
                    "GET Microsoft.ServiceBus/namespaces/queues/read".to_owned(),
                ),
                (
                    "list",
                    "GET Microsoft.ServiceBus/namespaces/queues/list".to_owned(),
                ),
                ("api_version", AZURE_SERVICE_BUS_API_VERSION.to_owned()),
                ("data_plane", "false".to_owned()),
            ],
        );
        Ok(Self {
            provider_id,
            version: PLUGIN_VERSION.to_owned(),
            api_revision,
            provider_digest,
            api_digest,
            provenance,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub const fn is_layer_one(&self) -> bool {
        !self.connected && !self.native && !self.first_party
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AzureServiceBusProviderError {
    #[error("Azure Service Bus provider request is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("Azure Service Bus provider transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("Azure Service Bus provider page binding or digest is invalid")]
    PageBinding,
    #[error("Azure Service Bus provider page revision is incompatible")]
    ProviderRevision,
    #[error("Azure Service Bus provider provenance or native flags are invalid")]
    Provenance,
}

/// A Layer-1 transport can be fixture, recording, loopback, or BLOCKED_ENV.
/// It has no native credential or HTTP client contract.
pub trait AzureServiceBusTransport: Send + fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read(
        &mut self,
        request: &AzureServiceBusReadRequest,
    ) -> Result<AzureServiceBusReadPage, TransportError>;
}

#[derive(Clone)]
pub struct AzureServiceBusProvider<T> {
    transport: T,
    identity: AzureServiceBusProviderIdentity,
}

impl<T> fmt::Debug for AzureServiceBusProvider<T>
where
    T: AzureServiceBusTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureServiceBusProvider")
            .field("provider_id", &self.identity.provider_id)
            .field("version", &self.identity.version)
            .field("api_revision", &self.identity.api_revision)
            .field("provider_digest", &self.identity.provider_digest)
            .field("api_digest", &self.identity.api_digest)
            .field("provenance", &self.identity.provenance)
            .field("connected", &self.identity.connected)
            .field("native", &self.identity.native)
            .field("first_party", &self.identity.first_party)
            .finish_non_exhaustive()
    }
}

impl<T> AzureServiceBusProvider<T>
where
    T: AzureServiceBusTransport,
{
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let identity = AzureServiceBusProviderIdentity::for_provenance(transport.provenance())?;
        Ok(Self {
            transport,
            identity,
        })
    }

    pub fn identity(&self) -> &AzureServiceBusProviderIdentity {
        &self.identity
    }

    pub fn definition(&self) -> &AzureServiceBusProviderIdentity {
        self.identity()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        request: &AzureServiceBusReadRequest,
    ) -> Result<AzureServiceBusReadPage, AzureServiceBusProviderError> {
        if let Some(continuation) = request.continuation()
            && continuation.binding_digest() != Some(&request.query_digest())
        {
            return Err(AzureServiceBusProviderError::Model(
                ModelError::ScopeMismatch {
                    field: "continuation query binding",
                },
            ));
        }
        let page = self.transport.read(request)?;
        if page.provenance != self.identity.provenance
            || page.connected
            || page.native
            || page.first_party
            || page.provider_receipt
            || !self.identity.is_layer_one()
        {
            return Err(AzureServiceBusProviderError::Provenance);
        }
        page.validate_for(request)
            .map_err(|_| AzureServiceBusProviderError::PageBinding)?;
        if page.provider_revision != self.identity.api_revision {
            return Err(AzureServiceBusProviderError::ProviderRevision);
        }
        Ok(page)
    }

    /// Parse only the documented queue description/list fields from a bounded
    /// ARM response. Unknown fields, including resource IDs, endpoint details,
    /// authorization data, and message data, are ignored and never retained.
    pub fn parse_json_page(
        request: &AzureServiceBusReadRequest,
        status_code: u16,
        body: &[u8],
        provider_revision: ProviderRevision,
        provenance: TransportProvenance,
    ) -> Result<AzureServiceBusReadPage, AzureServiceBusProviderError> {
        Self::parse_json_page_with_page_number(
            request,
            status_code,
            body,
            provider_revision,
            provenance,
        )
    }

    pub fn parse_json_page_with_page_number(
        request: &AzureServiceBusReadRequest,
        status_code: u16,
        body: &[u8],
        provider_revision: ProviderRevision,
        provenance: TransportProvenance,
    ) -> Result<AzureServiceBusReadPage, AzureServiceBusProviderError> {
        if status_code != 200 {
            return Err(AzureServiceBusProviderError::Transport(
                transport_error_for_status(status_code),
            ));
        }
        if body.is_empty() || body.len() > request.max_response_bytes() {
            return Err(AzureServiceBusProviderError::Transport(
                TransportError::BoundExceeded,
            ));
        }
        let value = serde_json::from_slice::<Value>(body).map_err(|_| {
            AzureServiceBusProviderError::Transport(TransportError::MalformedResponse)
        })?;
        let (queues, next_continuation) = match request.operation() {
            AzureServiceBusReadOperation::GetQueue => {
                let queue = parse_queue_projection(request.scope(), &value)?;
                let next = parse_continuation(&value)?;
                if next.is_some() {
                    return Err(AzureServiceBusProviderError::Transport(
                        TransportError::MalformedResponse,
                    ));
                }
                (vec![queue], None)
            }
            AzureServiceBusReadOperation::ListQueues => parse_queue_list(request.scope(), &value)?,
        };
        AzureServiceBusReadPage::new(
            request,
            queues,
            next_continuation,
            body.len(),
            provider_revision,
            provenance,
        )
        .map_err(AzureServiceBusProviderError::Model)
    }

    pub fn parse_json_response(
        request: &AzureServiceBusReadRequest,
        response: &AzureServiceBusHttpResponse,
        provider_revision: ProviderRevision,
        provenance: TransportProvenance,
    ) -> Result<AzureServiceBusReadPage, AzureServiceBusProviderError> {
        if response.status_code != 200 {
            return Err(AzureServiceBusProviderError::Transport(
                transport_error_for_status_with_retry(
                    response.status_code,
                    response.retry_after_seconds,
                ),
            ));
        }
        Self::parse_json_page(
            request,
            response.status_code,
            &response.body,
            provider_revision,
            provenance,
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AzureServiceBusHttpResponse {
    pub status_code: u16,
    pub body: Vec<u8>,
    pub retry_after_seconds: Option<u64>,
}

impl fmt::Debug for AzureServiceBusHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureServiceBusHttpResponse")
            .field("status_code", &self.status_code)
            .field("body_bytes", &self.body.len())
            .field("retry_after_seconds", &self.retry_after_seconds)
            .finish()
    }
}

impl AzureServiceBusHttpResponse {
    pub fn new(status_code: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status_code,
            body: body.into(),
            retry_after_seconds: None,
        }
    }

    pub fn with_retry_after(mut self, seconds: Option<u64>) -> Self {
        self.retry_after_seconds = seconds;
        self
    }
}

fn transport_error_for_status(status_code: u16) -> TransportError {
    transport_error_for_status_with_retry(status_code, None)
}

fn transport_error_for_status_with_retry(
    status_code: u16,
    retry_after_seconds: Option<u64>,
) -> TransportError {
    match status_code {
        400 => TransportError::InvalidRequest,
        401 => TransportError::Unauthorized,
        403 => TransportError::Forbidden,
        404 => TransportError::NotFound,
        409 => TransportError::Conflict,
        429 => TransportError::RateLimited {
            retry_after_seconds,
        },
        500..=599 => TransportError::ServerFailure {
            status_code: Some(status_code),
        },
        _ => TransportError::Unknown,
    }
}

fn parse_queue_list(
    scope: &AzureServiceBusScope,
    value: &Value,
) -> Result<(Vec<QueuePostureProjection>, Option<OpaqueContinuation>), AzureServiceBusProviderError>
{
    let items = value.get("value").and_then(Value::as_array).ok_or(
        AzureServiceBusProviderError::Transport(TransportError::MalformedResponse),
    )?;
    if items.len() > crate::model::MAX_QUEUES_PER_PAGE {
        return Err(AzureServiceBusProviderError::Transport(
            TransportError::BoundExceeded,
        ));
    }
    let mut queues = Vec::new();
    for item in items {
        let Some(name) = item.get("name").and_then(Value::as_str) else {
            return Err(AzureServiceBusProviderError::Transport(
                TransportError::MalformedResponse,
            ));
        };
        if name.eq_ignore_ascii_case(scope.queue().name.as_str()) {
            if !queues.is_empty() {
                return Err(AzureServiceBusProviderError::Transport(
                    TransportError::ScopeDrift,
                ));
            }
            queues.push(parse_queue_projection(scope, item)?);
        }
    }
    Ok((queues, parse_continuation(value)?))
}

fn parse_queue_projection(
    scope: &AzureServiceBusScope,
    value: &Value,
) -> Result<QueuePostureProjection, AzureServiceBusProviderError> {
    let name = value.get("name").and_then(Value::as_str).ok_or(
        AzureServiceBusProviderError::Transport(TransportError::MalformedResponse),
    )?;
    if !name.eq_ignore_ascii_case(scope.queue().name.as_str()) {
        return Err(AzureServiceBusProviderError::Transport(
            TransportError::ScopeDrift,
        ));
    }
    if let Some(resource_id) = value.get("id").and_then(Value::as_str)
        && !resource_id_matches_scope(resource_id, scope)
    {
        return Err(AzureServiceBusProviderError::Transport(
            TransportError::ScopeDrift,
        ));
    }
    let properties = value.get("properties").and_then(Value::as_object).ok_or(
        AzureServiceBusProviderError::Transport(TransportError::MalformedResponse),
    )?;
    let status = properties.get("status").and_then(Value::as_str).ok_or(
        AzureServiceBusProviderError::Transport(TransportError::MalformedResponse),
    )?;
    let status = QueueStatus::parse_api(status);
    let (message_count, message_count_present) = optional_u64(properties, "messageCount")?;
    let (size_in_bytes, size_present) = optional_u64(properties, "sizeInBytes")?;
    let count_details = properties
        .get("countDetails")
        .map(|value| {
            value
                .as_object()
                .ok_or(AzureServiceBusProviderError::Transport(
                    TransportError::MalformedResponse,
                ))
        })
        .transpose()?;
    let counts = QueueCountProjection {
        message_count,
        active_message_count: optional_nested_u64(count_details, "activeMessageCount")?,
        dead_letter_message_count: optional_nested_u64(count_details, "deadLetterMessageCount")?,
        scheduled_message_count: optional_nested_u64(count_details, "scheduledMessageCount")?,
        transfer_dead_letter_message_count: optional_nested_u64(
            count_details,
            "transferDeadLetterMessageCount",
        )?,
        transfer_message_count: optional_nested_u64(count_details, "transferMessageCount")?,
    };
    let count_details_complete = count_details.is_some()
        && counts.active_message_count.is_some()
        && counts.dead_letter_message_count.is_some()
        && counts.scheduled_message_count.is_some()
        && counts.transfer_dead_letter_message_count.is_some()
        && counts.transfer_message_count.is_some();
    let (default_message_ttl_seconds, default_ttl_present) =
        optional_duration(properties, "defaultMessageTimeToLive")?;
    let (auto_delete_on_idle_seconds, auto_delete_present) =
        optional_duration(properties, "autoDeleteOnIdle")?;
    let (duplicate_detection_history_window_seconds, duplicate_detection_present) =
        optional_duration(properties, "duplicateDetectionHistoryTimeWindow")?;
    let (lock_duration_seconds, lock_duration_present) =
        optional_duration(properties, "lockDuration")?;
    let (requires_session, requires_session_present) =
        optional_bool(properties, "requiresSession")?;
    let (enable_partitioning, partitioning_present) =
        optional_bool(properties, "enablePartitioning")?;
    let (requires_duplicate_detection, duplicate_present) =
        optional_bool(properties, "requiresDuplicateDetection")?;
    let (dead_lettering_on_message_expiration, dead_letter_present) =
        optional_bool(properties, "deadLetteringOnMessageExpiration")?;
    let (max_delivery_count, max_delivery_present) = optional_u32(properties, "maxDeliveryCount")?;
    let (max_size_in_megabytes, max_size_present) = optional_u32(properties, "maxSizeInMegabytes")?;
    let (max_message_size_in_kilobytes, max_message_size_present) =
        optional_u64(properties, "maxMessageSizeInKilobytes")?;
    let configuration = QueueConfigurationProjection {
        default_message_ttl_seconds,
        auto_delete_on_idle_seconds,
        duplicate_detection_history_window_seconds,
        lock_duration_seconds,
        requires_session,
        enable_partitioning,
        requires_duplicate_detection,
        dead_lettering_on_message_expiration,
        max_delivery_count,
        max_size_in_megabytes,
        max_message_size_in_kilobytes,
    };
    let (revision_digest, revision_present) = revision_digest(properties)?;
    let complete = message_count_present
        && size_present
        && count_details_complete
        && default_ttl_present
        && auto_delete_present
        && duplicate_detection_present
        && lock_duration_present
        && requires_session_present
        && partitioning_present
        && duplicate_present
        && dead_letter_present
        && max_delivery_present
        && max_size_present
        && max_message_size_present
        && revision_present
        && status.is_supported_state();
    QueuePostureProjection::new(
        scope,
        status,
        size_in_bytes,
        counts,
        configuration,
        revision_digest,
        complete,
    )
    .map_err(AzureServiceBusProviderError::Model)
}

fn resource_id_matches_scope(value: &str, scope: &AzureServiceBusScope) -> bool {
    let parts = value
        .trim_matches('/')
        .split('/')
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    parts.len() == 10
        && parts[0] == "subscriptions"
        && parts[1] == scope.subscription_id().as_str().to_ascii_lowercase()
        && parts[2] == "resourcegroups"
        && parts[3] == scope.resource_group_name().as_str().to_ascii_lowercase()
        && parts[4] == "providers"
        && parts[5] == "microsoft.servicebus"
        && parts[6] == "namespaces"
        && parts[7] == scope.namespace().name.as_str().to_ascii_lowercase()
        && parts[8] == "queues"
        && parts[9] == scope.queue().name.as_str().to_ascii_lowercase()
}

fn parse_continuation(
    value: &Value,
) -> Result<Option<OpaqueContinuation>, AzureServiceBusProviderError> {
    let Some(raw) = value
        .get("nextLink")
        .or_else(|| value.get("nextToken"))
        .or_else(|| value.get("continuationToken"))
    else {
        return Ok(None);
    };
    let token = raw.as_str().ok_or(AzureServiceBusProviderError::Transport(
        TransportError::MalformedResponse,
    ))?;
    if token.is_empty() {
        return Err(AzureServiceBusProviderError::Transport(
            TransportError::MalformedResponse,
        ));
    }
    OpaqueContinuation::new(token)
        .map(Some)
        .map_err(AzureServiceBusProviderError::Model)
}

fn optional_u64(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(Option<u64>, bool), AzureServiceBusProviderError> {
    let Some(value) = object.get(field) else {
        return Ok((None, false));
    };
    let number = value
        .as_u64()
        .ok_or(AzureServiceBusProviderError::Transport(
            TransportError::MalformedResponse,
        ))?;
    if number > crate::model::MAX_COUNT && field != "sizeInBytes" {
        return Err(AzureServiceBusProviderError::Transport(
            TransportError::BoundExceeded,
        ));
    }
    if field == "sizeInBytes" && number > crate::model::MAX_SIZE_BYTES {
        return Err(AzureServiceBusProviderError::Transport(
            TransportError::BoundExceeded,
        ));
    }
    Ok((Some(number), true))
}

fn optional_nested_u64(
    object: Option<&serde_json::Map<String, Value>>,
    field: &'static str,
) -> Result<Option<u64>, AzureServiceBusProviderError> {
    let Some(object) = object else {
        return Ok(None);
    };
    optional_u64(object, field).map(|(value, _)| value)
}

fn optional_u32(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(Option<u32>, bool), AzureServiceBusProviderError> {
    let Some(value) = object.get(field) else {
        return Ok((None, false));
    };
    let number = value
        .as_u64()
        .ok_or(AzureServiceBusProviderError::Transport(
            TransportError::MalformedResponse,
        ))?;
    let number = u32::try_from(number)
        .map_err(|_| AzureServiceBusProviderError::Transport(TransportError::BoundExceeded))?;
    if field == "maxDeliveryCount" && number > crate::model::MAX_DELIVERY_COUNT {
        return Err(AzureServiceBusProviderError::Transport(
            TransportError::BoundExceeded,
        ));
    }
    if field == "maxSizeInMegabytes" && number > crate::model::MAX_SIZE_MEGABYTES {
        return Err(AzureServiceBusProviderError::Transport(
            TransportError::BoundExceeded,
        ));
    }
    Ok((Some(number), true))
}

fn optional_bool(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(Option<bool>, bool), AzureServiceBusProviderError> {
    let Some(value) = object.get(field) else {
        return Ok((None, false));
    };
    value
        .as_bool()
        .map(|value| (Some(value), true))
        .ok_or(AzureServiceBusProviderError::Transport(
            TransportError::MalformedResponse,
        ))
}

fn optional_duration(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<(Option<u64>, bool), AzureServiceBusProviderError> {
    let Some(value) = object.get(field) else {
        return Ok((None, false));
    };
    let value = value
        .as_str()
        .ok_or(AzureServiceBusProviderError::Transport(
            TransportError::MalformedResponse,
        ))?;
    parse_iso8601_duration_seconds(value)
        .map(|seconds| (Some(seconds), true))
        .map_err(|()| AzureServiceBusProviderError::Transport(TransportError::MalformedResponse))
}

fn parse_iso8601_duration_seconds(value: &str) -> Result<u64, ()> {
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'P' || value.chars().any(char::is_control) {
        return Err(());
    }
    let mut index = 1;
    let mut in_time = false;
    let mut total = 0_u64;
    let mut found_component = false;
    while index < bytes.len() {
        if bytes[index] == b'T' {
            if in_time {
                return Err(());
            }
            in_time = true;
            index += 1;
            continue;
        }
        let start = index;
        let mut has_fraction = false;
        while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'.') {
            if bytes[index] == b'.' {
                if has_fraction {
                    return Err(());
                }
                has_fraction = true;
            }
            index += 1;
        }
        if start == index || index >= bytes.len() {
            return Err(());
        }
        let unit = bytes[index];
        index += 1;
        let number = &value[start..index - 1];
        let whole = number
            .split('.')
            .next()
            .ok_or(())?
            .parse::<u64>()
            .map_err(|_| ())?;
        let multiplier = match unit {
            b'D' if !in_time => 86_400,
            b'H' if in_time => 3_600,
            b'M' if in_time => 60,
            b'S' if in_time => 1,
            _ => return Err(()),
        };
        total = total
            .checked_add(whole.checked_mul(multiplier).ok_or(())?)
            .ok_or(())?;
        if total > crate::model::MAX_DURATION_SECONDS {
            return Err(());
        }
        found_component = true;
    }
    if found_component { Ok(total) } else { Err(()) }
}

fn revision_digest(
    properties: &serde_json::Map<String, Value>,
) -> Result<(Digest, bool), AzureServiceBusProviderError> {
    let (created, created_present) = match properties.get("createdAt") {
        None => ("missing", false),
        Some(Value::String(value)) => (value.as_str(), true),
        Some(_) => {
            return Err(AzureServiceBusProviderError::Transport(
                TransportError::MalformedResponse,
            ));
        }
    };
    let (updated, updated_present) = match properties.get("updatedAt") {
        None => ("missing", false),
        Some(Value::String(value)) => (value.as_str(), true),
        Some(_) => {
            return Err(AzureServiceBusProviderError::Transport(
                TransportError::MalformedResponse,
            ));
        }
    };
    for (value, present) in [(created, created_present), (updated, updated_present)] {
        if present && (value.is_empty() || value.len() > 128 || value.chars().any(char::is_control))
        {
            return Err(AzureServiceBusProviderError::Transport(
                TransportError::MalformedResponse,
            ));
        }
    }
    Ok((
        Digest::from_fields(
            "hartevo-azure-service-bus-queue-revision/v1",
            &[
                ("created", created.to_owned()),
                ("updated", updated.to_owned()),
            ],
        ),
        created_present && updated_present,
    ))
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AzureServiceBusReadOperation,
    pub scope_digest: Digest,
    pub continuation_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

impl RecordedRequest {
    fn from_request(request: &AzureServiceBusReadRequest) -> Self {
        Self {
            operation: request.operation(),
            scope_digest: request.scope().digest(),
            continuation_digest: request
                .continuation()
                .map(|continuation| continuation.token_digest().clone()),
            request_digest: request.request_digest(),
            path_digest: Digest::from_fields(
                "hartevo-azure-service-bus-path/v1",
                &[
                    ("template", request.path_template().to_owned()),
                    ("scope", request.scope().digest().to_string()),
                    ("request", request.request_digest().to_string()),
                ],
            ),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingAzureServiceBusTransport {
    responses: VecDeque<Result<AzureServiceBusReadPage, TransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingAzureServiceBusTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(&mut self, response: Result<AzureServiceBusReadPage, TransportError>) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl AzureServiceBusTransport for RecordingAzureServiceBusTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn read(
        &mut self,
        request: &AzureServiceBusReadRequest,
    ) -> Result<AzureServiceBusReadPage, TransportError> {
        self.requests.push(RecordedRequest::from_request(request));
        self.responses
            .pop_front()
            .unwrap_or(Err(TransportError::Timeout))
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureAzureServiceBusTransport;

impl FixtureAzureServiceBusTransport {
    pub const fn new() -> Self {
        Self
    }
}

impl AzureServiceBusTransport for FixtureAzureServiceBusTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn read(
        &mut self,
        request: &AzureServiceBusReadRequest,
    ) -> Result<AzureServiceBusReadPage, TransportError> {
        AzureServiceBusReadPage::new(
            request,
            vec![QueuePostureProjection::fixture(
                request.scope(),
                QueueStatus::Active,
            )],
            None,
            512,
            ProviderRevision::new(PROVIDER_API_REVISION).map_err(|_| TransportError::Unknown)?,
            TransportProvenance::Fixture,
        )
        .map_err(|_| TransportError::MalformedResponse)
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackAzureServiceBusTransport;

impl LoopbackAzureServiceBusTransport {
    pub const fn new() -> Self {
        Self
    }
}

impl AzureServiceBusTransport for LoopbackAzureServiceBusTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read(
        &mut self,
        request: &AzureServiceBusReadRequest,
    ) -> Result<AzureServiceBusReadPage, TransportError> {
        AzureServiceBusReadPage::new(
            request,
            vec![QueuePostureProjection::fixture(
                request.scope(),
                QueueStatus::Active,
            )],
            None,
            512,
            ProviderRevision::new(PROVIDER_API_REVISION).map_err(|_| TransportError::Unknown)?,
            TransportProvenance::Loopback,
        )
        .map_err(|_| TransportError::MalformedResponse)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAzureServiceBusTransport;

impl AzureServiceBusTransport for BlockedEnvAzureServiceBusTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read(
        &mut self,
        _request: &AzureServiceBusReadRequest,
    ) -> Result<AzureServiceBusReadPage, TransportError> {
        Err(TransportError::BlockedEnvironment)
    }
}

pub type FakeAzureServiceBusTransport = FixtureAzureServiceBusTransport;
pub type BlockedEnvTransport = BlockedEnvAzureServiceBusTransport;
pub type ProviderProvenance = TransportProvenance;

pub fn is_access_loss(error: &TransportError) -> bool {
    matches!(
        error.kind(),
        ProviderErrorKind::Unauthorized
            | ProviderErrorKind::Forbidden
            | ProviderErrorKind::NotFound
    )
}
