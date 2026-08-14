//! Read-only AWS MSK provider boundary.
//!
//! The provider exposes only the four documented MSK read operations. A
//! transport receives a typed request and returns an already-redacted page.
//! There is deliberately no signer, credential resolver, HTTP client, topic
//! API, broker endpoint API, or arbitrary AWS operation escape hatch here.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::{
    AWS_MSK_API_REVISION, AWS_MSK_PROVIDER_ID, AWS_MSK_PROVIDER_VERSION,
    model::{
        AwsMskReadOperation, AwsMskReadPage, AwsMskReadRequest, BrokerCountClass, ClusterArn,
        ClusterName, ClusterState, ClusterType, ConfigurationArn, ConfigurationProjection, Digest,
        MskClusterObservation, MskConfigurationObservation, MskOperationObservation,
        OpaquePageMarker, OperationId, OperationState, OperationType, PropertyCountClass,
        ProviderErrorKind, ProviderId, ProviderRevision, ReadinessState, SecurityPosture,
        TransportError, TransportProvenance, TriState,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("AWS MSK provider id is invalid: {0}")]
    Model(#[from] crate::model::ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsMskProviderIdentity {
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

impl AwsMskProviderIdentity {
    pub fn for_provenance(
        provenance: TransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_id = ProviderId::new(AWS_MSK_PROVIDER_ID)?;
        let api_revision = ProviderRevision::new(AWS_MSK_API_REVISION)?;
        let provider_digest = Digest::from_parts(
            "hartevo-aws-msk-provider/v1",
            &[
                provider_id.as_str().to_owned(),
                AWS_MSK_PROVIDER_VERSION.to_owned(),
                api_revision.as_str().to_owned(),
            ],
        );
        let api_digest = Digest::from_parts(
            "hartevo-aws-msk-api-allowlist/v1",
            &[
                "ListClustersV2".to_owned(),
                "DescribeClusterV2".to_owned(),
                "DescribeConfigurationRevision".to_owned(),
                "ListClusterOperations".to_owned(),
                "GET".to_owned(),
            ],
        );
        Ok(Self {
            provider_id,
            version: AWS_MSK_PROVIDER_VERSION.to_owned(),
            api_revision,
            provider_digest,
            api_digest,
            provenance,
            connected: false,
            native: false,
            first_party: false,
        })
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsMskProviderError {
    #[error("AWS MSK provider request is invalid: {0}")]
    Model(#[from] crate::model::ModelError),
    #[error("AWS MSK provider transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("AWS MSK provider page binding or digest is invalid")]
    PageBinding,
    #[error("AWS MSK provider page revision is incompatible")]
    ProviderRevision,
}

/// A Layer-1 transport can be fixture, fake, recording, loopback, or
/// BLOCKED_ENV. It has no native credential or HTTP client contract.
pub trait AwsMskTransport: Send {
    fn provenance(&self) -> TransportProvenance;

    fn read(&mut self, request: &AwsMskReadRequest) -> Result<AwsMskReadPage, TransportError>;
}

#[derive(Clone)]
pub struct AwsMskProvider<T> {
    transport: T,
    identity: AwsMskProviderIdentity,
}

impl<T> fmt::Debug for AwsMskProvider<T>
where
    T: AwsMskTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsMskProvider")
            .field("provider_id", &self.identity.provider_id)
            .field("version", &self.identity.version)
            .field("api_revision", &self.identity.api_revision)
            .field("provider_digest", &self.identity.provider_digest)
            .field("api_digest", &self.identity.api_digest)
            .field("provenance", &self.identity.provenance)
            .field("connected", &false)
            .field("native", &false)
            .field("first_party", &false)
            .finish_non_exhaustive()
    }
}

impl<T> AwsMskProvider<T>
where
    T: AwsMskTransport,
{
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let identity = AwsMskProviderIdentity::for_provenance(transport.provenance())?;
        Ok(Self {
            transport,
            identity,
        })
    }

    pub fn identity(&self) -> &AwsMskProviderIdentity {
        &self.identity
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        request: &AwsMskReadRequest,
    ) -> Result<AwsMskReadPage, AwsMskProviderError> {
        if let Some(marker) = &request.marker {
            if marker.binding_digest() != Some(&request.query_digest()) {
                return Err(AwsMskProviderError::Model(
                    crate::model::ModelError::ScopeMismatch {
                        field: "marker query binding",
                    },
                ));
            }
            if marker.is_expired(Utc::now()) {
                return Err(AwsMskProviderError::Transport(
                    TransportError::MarkerExpired,
                ));
            }
        }
        let page = self.transport.read(request)?;
        page.validate_for(request)
            .map_err(|_| AwsMskProviderError::PageBinding)?;
        if page.provider_revision != self.identity.api_revision {
            return Err(AwsMskProviderError::ProviderRevision);
        }
        Ok(page)
    }

    /// Parse only the bounded, non-sensitive MSK fields needed for readiness
    /// posture. Unknown fields, including endpoint and message fields, are
    /// ignored and never retained.
    pub fn parse_json_page(
        request: &AwsMskReadRequest,
        page_number: u16,
        status_code: u16,
        body: &[u8],
        provider_revision: ProviderRevision,
    ) -> Result<AwsMskReadPage, AwsMskProviderError> {
        if status_code != 200 {
            return Err(AwsMskProviderError::Transport(transport_error_for_status(
                status_code,
            )));
        }
        if body.is_empty() || body.len() > request.max_response_bytes {
            return Err(AwsMskProviderError::Model(
                crate::model::ModelError::Invalid {
                    field: "MSK provider response bytes",
                },
            ));
        }
        let value = serde_json::from_slice::<Value>(body)
            .map_err(|_| AwsMskProviderError::Transport(TransportError::MalformedResponse))?;
        let next_marker = optional_string(
            &value,
            &["NextToken", "nextToken", "NextMarker", "nextMarker"],
        )
        .map(OpaquePageMarker::new)
        .transpose()?;
        match request.operation {
            AwsMskReadOperation::ListClustersV2 => {
                let items =
                    array_field(&value, &["ClusterInfoList", "clusterInfoList", "clusters"])?;
                let clusters = items
                    .iter()
                    .map(parse_cluster)
                    .collect::<Result<Vec<_>, _>>()?;
                AwsMskReadPage::list_clusters(
                    request,
                    page_number,
                    clusters,
                    next_marker,
                    body.len(),
                    provider_revision,
                )
                .map_err(AwsMskProviderError::Model)
            }
            AwsMskReadOperation::DescribeClusterV2 => {
                let cluster_value =
                    object_field(&value, &["ClusterInfo", "clusterInfo", "cluster"])?;
                let cluster = parse_cluster(cluster_value)?;
                AwsMskReadPage::describe_cluster(
                    request,
                    page_number,
                    cluster,
                    body.len(),
                    provider_revision,
                )
                .map_err(AwsMskProviderError::Model)
            }
            AwsMskReadOperation::DescribeConfigurationRevision => {
                let configuration_arn =
                    request
                        .configuration_arn
                        .clone()
                        .ok_or(AwsMskProviderError::Model(
                            crate::model::ModelError::Invalid {
                                field: "configuration request ARN",
                            },
                        ))?;
                let requested_revision =
                    request
                        .configuration_revision
                        .ok_or(AwsMskProviderError::Model(
                            crate::model::ModelError::Invalid {
                                field: "configuration request revision",
                            },
                        ))?;
                let observed_revision = optional_u64(&value, &["Revision", "revision"])
                    .map(crate::model::Revision::new)
                    .transpose()?
                    .unwrap_or(requested_revision);
                let properties = value
                    .get("ServerProperties")
                    .or_else(|| value.get("serverProperties"));
                let (properties_present, property_count_class) =
                    properties.map_or((false, PropertyCountClass::Unknown), |properties| {
                        if let Some(properties) = properties.as_object() {
                            (true, PropertyCountClass::from_count(properties.len()))
                        } else if properties
                            .as_str()
                            .is_some_and(|properties| !properties.is_empty())
                        {
                            // AWS returns this field as base64/plaintext. The
                            // contents are intentionally never decoded or retained.
                            (true, PropertyCountClass::Unknown)
                        } else {
                            (false, PropertyCountClass::Unknown)
                        }
                    });
                let readiness = if observed_revision != requested_revision {
                    ReadinessState::Partial
                } else if properties_present {
                    ReadinessState::Ready
                } else {
                    ReadinessState::Partial
                };
                let configuration = MskConfigurationObservation::new(
                    configuration_arn,
                    observed_revision,
                    properties_present,
                    property_count_class,
                    readiness,
                );
                AwsMskReadPage::describe_configuration_revision(
                    request,
                    page_number,
                    configuration,
                    body.len(),
                    provider_revision,
                )
                .map_err(AwsMskProviderError::Model)
            }
            AwsMskReadOperation::ListClusterOperations => {
                let items = array_field(
                    &value,
                    &[
                        "ClusterOperationInfoList",
                        "clusterOperationInfoList",
                        "operations",
                    ],
                )?;
                let operations = items
                    .iter()
                    .map(parse_operation)
                    .collect::<Result<Vec<_>, _>>()?;
                AwsMskReadPage::list_cluster_operations(
                    request,
                    page_number,
                    operations,
                    next_marker,
                    body.len(),
                    provider_revision,
                )
                .map_err(AwsMskProviderError::Model)
            }
        }
    }
}

fn transport_error_for_status(status_code: u16) -> TransportError {
    match status_code {
        400 => TransportError::InvalidRequest,
        401 => TransportError::Unauthorized,
        403 => TransportError::Forbidden,
        404 => TransportError::NotFound,
        429 => TransportError::RateLimited {
            retry_after_seconds: None,
        },
        500..=599 => TransportError::ServerFailure {
            status_code: Some(status_code),
        },
        _ => TransportError::Unknown,
    }
}

fn array_field<'a>(value: &'a Value, names: &[&str]) -> Result<&'a [Value], AwsMskProviderError> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_array))
        .map(Vec::as_slice)
        .ok_or(AwsMskProviderError::Transport(
            TransportError::MalformedResponse,
        ))
}

fn object_field<'a>(value: &'a Value, names: &[&str]) -> Result<&'a Value, AwsMskProviderError> {
    names
        .iter()
        .find_map(|name| value.get(*name).filter(|value| value.is_object()))
        .ok_or(AwsMskProviderError::Transport(
            TransportError::MalformedResponse,
        ))
}

fn optional_string(value: &Value, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_str).map(str::to_owned))
}

fn required_string(
    value: &Value,
    names: &[&str],
    field: &'static str,
) -> Result<String, AwsMskProviderError> {
    optional_string(value, names).ok_or(AwsMskProviderError::Model(
        crate::model::ModelError::Invalid { field },
    ))
}

fn optional_u64(value: &Value, names: &[&str]) -> Option<u64> {
    names.iter().find_map(|name| {
        value.get(*name).and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))
        })
    })
}

fn optional_u32(value: &Value, names: &[&str]) -> Option<u32> {
    optional_u64(value, names).and_then(|value| u32::try_from(value).ok())
}

fn optional_bool(value: &Value, names: &[&str]) -> Option<bool> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_bool))
}

fn optional_timestamp(
    value: &Value,
    names: &[&str],
) -> Result<Option<DateTime<Utc>>, AwsMskProviderError> {
    let Some(raw) = optional_string(value, names) else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(&raw)
        .map(|timestamp| Some(timestamp.with_timezone(&Utc)))
        .map_err(|_| AwsMskProviderError::Transport(TransportError::MalformedResponse))
}

fn parse_cluster(value: &Value) -> Result<MskClusterObservation, AwsMskProviderError> {
    let arn = ClusterArn::new(required_string(
        value,
        &["ClusterArn", "clusterArn", "arn"],
        "MSK cluster ARN",
    )?)?;
    let name = ClusterName::new(required_string(
        value,
        &["ClusterName", "clusterName", "name"],
        "MSK cluster name",
    )?)?;
    let cluster_type = ClusterType::parse_api(&required_string(
        value,
        &["ClusterType", "clusterType", "type"],
        "MSK cluster type",
    )?)?;
    let kafka_version = crate::model::KafkaVersion::new(required_string(
        value,
        &["KafkaVersion", "kafkaVersion"],
        "Kafka version",
    )?)?;
    let provisioned = value
        .get("Provisioned")
        .or_else(|| value.get("provisioned"))
        .filter(|value| value.is_object())
        .unwrap_or(value);
    let state = ClusterState::parse_api(
        optional_string(value, &["State", "state"])
            .or_else(|| optional_string(provisioned, &["State", "state"]))
            .as_deref()
            .unwrap_or("UNKNOWN"),
    );
    let broker_count = optional_u32(value, &["NumberOfBrokerNodes", "numberOfBrokerNodes"])
        .or_else(|| optional_u32(provisioned, &["NumberOfBrokerNodes", "numberOfBrokerNodes"]))
        .or_else(|| {
            provisioned
                .get("BrokerNodeGroupInfo")
                .or_else(|| provisioned.get("brokerNodeGroupInfo"))
                .and_then(|value| {
                    optional_u32(value, &["NumberOfBrokerNodes", "numberOfBrokerNodes"])
                })
        });
    let security_posture = parse_security(value, provisioned);
    let configuration = parse_configuration_projection(value, provisioned)?;
    let creation_time = optional_timestamp(value, &["CreationTime", "creationTime"])?;
    Ok(MskClusterObservation::new(
        arn,
        name,
        cluster_type,
        kafka_version,
        state,
        BrokerCountClass::from_count(broker_count),
        security_posture,
        configuration,
        creation_time,
    ))
}

fn parse_configuration_projection(
    value: &Value,
    provisioned: &Value,
) -> Result<ConfigurationProjection, AwsMskProviderError> {
    let software = value
        .get("CurrentBrokerSoftwareInfo")
        .or_else(|| value.get("currentBrokerSoftwareInfo"))
        .or_else(|| provisioned.get("CurrentBrokerSoftwareInfo"))
        .or_else(|| provisioned.get("currentBrokerSoftwareInfo"));
    let Some(software) = software.filter(|value| value.is_object()) else {
        return Ok(ConfigurationProjection::default());
    };
    let arn = optional_string(software, &["ConfigurationArn", "configurationArn"])
        .map(ConfigurationArn::new)
        .transpose()?;
    let revision = optional_u64(
        software,
        &["ConfigurationRevision", "configurationRevision"],
    )
    .map(crate::model::Revision::new)
    .transpose()?;
    let readiness = if arn.is_some() && revision.is_some() {
        ReadinessState::Ready
    } else {
        ReadinessState::Partial
    };
    Ok(ConfigurationProjection {
        arn,
        revision,
        readiness,
    })
}

fn parse_security(value: &Value, provisioned: &Value) -> SecurityPosture {
    let encryption = value
        .get("EncryptionInfo")
        .or_else(|| value.get("encryptionInfo"))
        .or_else(|| provisioned.get("EncryptionInfo"))
        .or_else(|| provisioned.get("encryptionInfo"));
    let encryption_at_rest = encryption
        .and_then(|value| {
            value
                .get("EncryptionAtRest")
                .or_else(|| value.get("encryptionAtRest"))
        })
        .and_then(|value| {
            optional_string(
                value,
                &["DataVolumeKMSKey", "dataVolumeKMSKey", "dataVolumeKmsKey"],
            )
            .map(|_| TriState::Enabled)
        })
        .unwrap_or(TriState::Unknown);
    let in_cluster_encryption = encryption
        .and_then(|value| {
            optional_bool(value, &["InCluster", "inCluster"]).or_else(|| {
                value
                    .get("EncryptionInTransit")
                    .or_else(|| value.get("encryptionInTransit"))
                    .and_then(|value| optional_bool(value, &["InCluster", "inCluster"]))
            })
        })
        .map_or(TriState::Unknown, |enabled| {
            if enabled {
                TriState::Enabled
            } else {
                TriState::Disabled
            }
        });
    let client_broker_encryption = encryption
        .and_then(|value| optional_string(value, &["EncryptionInTransit.ClientBroker"]))
        .or_else(|| {
            encryption.and_then(|value| {
                value
                    .get("EncryptionInTransit")
                    .or_else(|| value.get("encryptionInTransit"))
                    .and_then(|value| optional_string(value, &["ClientBroker", "clientBroker"]))
            })
        })
        .map_or(crate::model::ClientBrokerEncryption::Unknown, |value| {
            crate::model::ClientBrokerEncryption::parse_api(&value)
        });
    let auth = value
        .get("ClientAuthentication")
        .or_else(|| value.get("clientAuthentication"))
        .or_else(|| provisioned.get("ClientAuthentication"))
        .or_else(|| provisioned.get("clientAuthentication"));
    let tls_authentication = auth
        .and_then(|value| value.get("Tls").or_else(|| value.get("tls")))
        .and_then(|value| optional_bool(value, &["Enabled", "enabled"]))
        .map_or(TriState::Unknown, enabled_state);
    let sasl_iam_authentication = auth
        .and_then(|value| value.get("Sasl").or_else(|| value.get("sasl")))
        .and_then(|value| value.get("Iam").or_else(|| value.get("iam")))
        .and_then(|value| optional_bool(value, &["Enabled", "enabled"]))
        .map_or(TriState::Unknown, enabled_state);
    let sasl_scram_authentication = auth
        .and_then(|value| value.get("Sasl").or_else(|| value.get("sasl")))
        .and_then(|value| value.get("Scram").or_else(|| value.get("scram")))
        .and_then(|value| optional_bool(value, &["Enabled", "enabled"]))
        .map_or(TriState::Unknown, enabled_state);
    let unauthenticated_access = auth
        .and_then(|value| {
            value
                .get("Unauthenticated")
                .or_else(|| value.get("unauthenticated"))
        })
        .and_then(|value| optional_bool(value, &["Enabled", "enabled"]))
        .map_or(TriState::Unknown, enabled_state);
    SecurityPosture {
        encryption_at_rest,
        in_cluster_encryption,
        client_broker_encryption,
        tls_authentication,
        sasl_iam_authentication,
        sasl_scram_authentication,
        unauthenticated_access,
    }
}

const fn enabled_state(enabled: bool) -> TriState {
    if enabled {
        TriState::Enabled
    } else {
        TriState::Disabled
    }
}

fn parse_operation(value: &Value) -> Result<MskOperationObservation, AwsMskProviderError> {
    let id = OperationId::new(required_string(
        value,
        &[
            "ClusterOperationArn",
            "clusterOperationArn",
            "OperationArn",
            "operationArn",
            "id",
        ],
        "MSK operation id",
    )?)?;
    let operation_type = OperationType::new(
        optional_string(value, &["OperationType", "operationType", "type"])
            .unwrap_or_else(|| "UNKNOWN".to_owned()),
    )?;
    let state = OperationState::parse_api(
        optional_string(
            value,
            &["OperationState", "operationState", "State", "state"],
        )
        .as_deref()
        .unwrap_or("UNKNOWN"),
    );
    let start_time = optional_timestamp(value, &["StartTime", "startTime"])?;
    let end_time = optional_timestamp(value, &["EndTime", "endTime"])?;
    let error_present = value
        .get("ErrorInfo")
        .or_else(|| value.get("errorInfo"))
        .is_some_and(Value::is_object);
    Ok(MskOperationObservation::new(
        id,
        operation_type,
        state,
        start_time,
        end_time,
        error_present,
    ))
}

#[derive(Clone)]
struct QueuedTransport {
    provenance: TransportProvenance,
    responses: VecDeque<Result<AwsMskReadPage, TransportError>>,
    requests: Vec<AwsMskReadRequest>,
}

impl QueuedTransport {
    fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    fn push_response(&mut self, response: Result<AwsMskReadPage, TransportError>) {
        self.responses.push_back(response);
    }

    fn requests(&self) -> &[AwsMskReadRequest] {
        &self.requests
    }

    fn read(&mut self, request: &AwsMskReadRequest) -> Result<AwsMskReadPage, TransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(TransportError::Unknown))
    }
}

#[derive(Clone)]
pub struct FixtureAwsMskTransport {
    inner: QueuedTransport,
}

impl fmt::Debug for FixtureAwsMskTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureAwsMskTransport")
            .field("queued_responses", &self.inner.responses.len())
            .field("request_count", &self.inner.requests.len())
            .finish()
    }
}

impl FixtureAwsMskTransport {
    pub fn fixture() -> Self {
        Self {
            inner: QueuedTransport::new(TransportProvenance::Fixture),
        }
    }

    pub fn fake() -> Self {
        Self {
            inner: QueuedTransport::new(TransportProvenance::Fake),
        }
    }

    pub fn push_response(&mut self, response: Result<AwsMskReadPage, TransportError>) {
        self.inner.push_response(response);
    }

    pub fn queue_list_clusters(&mut self, response: Result<AwsMskReadPage, TransportError>) {
        self.push_response(response);
    }

    pub fn queue_describe_cluster(&mut self, response: Result<AwsMskReadPage, TransportError>) {
        self.push_response(response);
    }

    pub fn queue_describe_configuration_revision(
        &mut self,
        response: Result<AwsMskReadPage, TransportError>,
    ) {
        self.push_response(response);
    }

    pub fn queue_list_cluster_operations(
        &mut self,
        response: Result<AwsMskReadPage, TransportError>,
    ) {
        self.push_response(response);
    }

    pub fn requests(&self) -> &[AwsMskReadRequest] {
        self.inner.requests()
    }
}

impl AwsMskTransport for FixtureAwsMskTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance
    }

    fn read(&mut self, request: &AwsMskReadRequest) -> Result<AwsMskReadPage, TransportError> {
        self.inner.read(request)
    }
}

#[derive(Clone)]
pub struct RecordingAwsMskTransport {
    inner: QueuedTransport,
}

impl fmt::Debug for RecordingAwsMskTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingAwsMskTransport")
            .field("queued_responses", &self.inner.responses.len())
            .field("request_count", &self.inner.requests.len())
            .finish()
    }
}

impl Default for RecordingAwsMskTransport {
    fn default() -> Self {
        Self {
            inner: QueuedTransport::new(TransportProvenance::Recording),
        }
    }
}

impl RecordingAwsMskTransport {
    pub fn push_response(&mut self, response: Result<AwsMskReadPage, TransportError>) {
        self.inner.push_response(response);
    }

    pub fn requests(&self) -> &[AwsMskReadRequest] {
        self.inner.requests()
    }
}

impl AwsMskTransport for RecordingAwsMskTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance
    }

    fn read(&mut self, request: &AwsMskReadRequest) -> Result<AwsMskReadPage, TransportError> {
        self.inner.read(request)
    }
}

#[derive(Clone)]
pub struct LoopbackAwsMskTransport {
    inner: QueuedTransport,
}

impl fmt::Debug for LoopbackAwsMskTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackAwsMskTransport")
            .field("queued_responses", &self.inner.responses.len())
            .field("request_count", &self.inner.requests.len())
            .finish()
    }
}

impl Default for LoopbackAwsMskTransport {
    fn default() -> Self {
        Self {
            inner: QueuedTransport::new(TransportProvenance::Loopback),
        }
    }
}

impl LoopbackAwsMskTransport {
    pub fn push_response(&mut self, response: Result<AwsMskReadPage, TransportError>) {
        self.inner.push_response(response);
    }

    pub fn requests(&self) -> &[AwsMskReadRequest] {
        self.inner.requests()
    }
}

impl AwsMskTransport for LoopbackAwsMskTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance
    }

    fn read(&mut self, request: &AwsMskReadRequest) -> Result<AwsMskReadPage, TransportError> {
        self.inner.read(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsMskTransport;

impl AwsMskTransport for BlockedEnvAwsMskTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read(&mut self, _request: &AwsMskReadRequest) -> Result<AwsMskReadPage, TransportError> {
        Err(TransportError::BlockedEnvironment)
    }
}

pub type FakeAwsMskTransport = FixtureAwsMskTransport;
pub type BlockedEnvTransport = BlockedEnvAwsMskTransport;
pub type ProviderProvenance = TransportProvenance;

pub fn is_access_loss(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::Unauthorized | TransportError::Forbidden | TransportError::NotFound
    )
}

pub fn provider_error_kind(error: &TransportError) -> ProviderErrorKind {
    error.kind()
}
