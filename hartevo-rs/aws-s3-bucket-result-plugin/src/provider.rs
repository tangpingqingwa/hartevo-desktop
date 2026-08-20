//! Read-only AWS S3 provider and non-native transport seams.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use serde_json::Value;

use crate::error::{AwsS3BucketError, AwsS3TransportError};
use crate::model::{
    AwsS3BucketScope, AwsS3Observation, AwsS3ProviderScope, AwsS3ReadRequest,
    BucketEncryptionObservation, BucketLifecycleObservation, BucketLocationObservation,
    BucketReplicationObservation, BucketVersioningObservation, Digest, EncryptionAlgorithm,
    EncryptionPosture, LifecyclePosture, ReplicationPosture, Revision, TransportProvenance,
    VersioningPosture,
};
use crate::{
    API_VERSION, LAYER1_PERMISSIONS, MAX_MARKER_BYTES, MAX_RESPONSE_BYTES, PLUGIN_VERSION,
    PROVIDER_API_REVISION, PROVIDER_ID, PROVIDER_VERSION,
};

pub use crate::model::AwsS3Operation;

/// A marker never exposes its raw token. Only a digest and a request binding
/// cross the provider boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueMarker {
    token_digest: Digest,
    binding_digest: Option<Digest>,
}

impl OpaqueMarker {
    pub fn new(value: impl AsRef<str>) -> std::result::Result<Self, AwsS3BucketError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_MARKER_BYTES || value.chars().any(char::is_control)
        {
            return Err(AwsS3BucketError::InvalidRequest(
                "opaque S3 marker".to_owned(),
            ));
        }
        Ok(Self {
            token_digest: Digest::from_parts("aws-s3-marker/v1", &[("token", value.to_owned())]),
            binding_digest: None,
        })
    }

    pub fn from_digest(token_digest: Digest) -> std::result::Result<Self, AwsS3BucketError> {
        token_digest.validate()?;
        Ok(Self {
            token_digest,
            binding_digest: None,
        })
    }

    pub fn bind(&self, binding_digest: &Digest) -> Self {
        Self {
            token_digest: self.token_digest.clone(),
            binding_digest: Some(binding_digest.clone()),
        }
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn marker_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }
}

impl fmt::Debug for OpaqueMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueMarker")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for OpaqueMarker {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("OpaqueMarker", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3OperationRequest {
    #[serde(skip)]
    provider_scope: AwsS3ProviderScope,
    pub scope_digest: Digest,
    pub provider_scope_digest: Digest,
    pub bucket_digest: Digest,
    pub resource_revision: Revision,
    pub operation: AwsS3Operation,
    pub page_number: u16,
    pub marker: Option<OpaqueMarker>,
    pub max_page_size: u16,
    pub max_response_bytes: u64,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub request_digest: Digest,
}

impl AwsS3OperationRequest {
    pub fn new(
        request: &AwsS3ReadRequest,
        operation: AwsS3Operation,
        page_number: u16,
        marker: Option<OpaqueMarker>,
    ) -> std::result::Result<Self, AwsS3BucketError> {
        if !request.operations().contains(&operation) || page_number == 0 {
            return Err(AwsS3BucketError::InvalidRequest(
                "S3 operation request binding".to_owned(),
            ));
        }
        let binding_digest = Self::operation_query_digest(request, operation);
        let marker = marker.map(|value| value.bind(&binding_digest));
        let marker_digest = marker
            .as_ref()
            .map_or_else(Digest::zero, |value| value.token_digest().clone());
        let request_digest = Digest::from_parts(
            "aws-s3-operation-request/v1",
            &[
                ("query", binding_digest.to_string()),
                ("page", page_number.to_string()),
                ("marker", marker_digest.to_string()),
            ],
        );
        Ok(Self {
            provider_scope: request.scope().provider_scope().clone(),
            scope_digest: request.scope_digest().clone(),
            provider_scope_digest: request.scope().provider_scope().digest().clone(),
            bucket_digest: request.scope().bucket_digest(),
            resource_revision: request.scope().resource_revision(),
            operation,
            page_number,
            marker,
            max_page_size: request.max_page_size,
            max_response_bytes: request.max_response_bytes,
            observed_at: request.observed_at,
            expires_at: request.expires_at,
            request_digest,
        })
    }

    pub fn query_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-operation-query/v1",
            &[
                ("scope", self.scope_digest.to_string()),
                ("provider_scope", self.provider_scope_digest.to_string()),
                ("bucket", self.bucket_digest.to_string()),
                ("revision", self.resource_revision.get().to_string()),
                ("operation", self.operation.as_str().to_owned()),
                ("page_size", self.max_page_size.to_string()),
                ("response_bytes", self.max_response_bytes.to_string()),
                ("expires_at", self.expires_at.to_rfc3339()),
            ],
        )
    }

    pub fn marker_digest(&self) -> Option<&Digest> {
        self.marker.as_ref().map(OpaqueMarker::token_digest)
    }

    pub fn validate(&self) -> std::result::Result<(), AwsS3BucketError> {
        self.scope_digest.validate()?;
        self.provider_scope_digest.validate()?;
        self.bucket_digest.validate()?;
        if self.page_number == 0
            || self.max_page_size == 0
            || self.max_page_size > crate::MAX_PAGE_SIZE
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.expires_at <= self.observed_at
            || self.request_digest
                != Digest::from_parts(
                    "aws-s3-operation-request/v1",
                    &[
                        ("query", self.query_digest().to_string()),
                        ("page", self.page_number.to_string()),
                        (
                            "marker",
                            self.marker_digest()
                                .map_or_else(Digest::zero, Clone::clone)
                                .to_string(),
                        ),
                    ],
                )
        {
            return Err(AwsS3BucketError::InvalidRequest(
                "S3 operation request bounds or digest".to_owned(),
            ));
        }
        if let Some(marker) = &self.marker
            && marker.binding_digest() != Some(&self.query_digest())
        {
            return Err(AwsS3BucketError::ScopeMismatch(
                "S3 marker query binding".to_owned(),
            ));
        }
        Ok(())
    }

    fn operation_query_digest(request: &AwsS3ReadRequest, operation: AwsS3Operation) -> Digest {
        Digest::from_parts(
            "aws-s3-operation-query/v1",
            &[
                ("scope", request.scope_digest().to_string()),
                (
                    "provider_scope",
                    request.scope().provider_scope().digest().to_string(),
                ),
                ("bucket", request.scope().bucket_digest().to_string()),
                (
                    "revision",
                    request.scope().resource_revision().get().to_string(),
                ),
                ("operation", operation.as_str().to_owned()),
                ("page_size", request.max_page_size.to_string()),
                ("response_bytes", request.max_response_bytes.to_string()),
                ("expires_at", request.expires_at.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3ReadPage {
    pub scope_digest: Digest,
    pub provider_scope_digest: Digest,
    pub bucket_digest: Digest,
    pub resource_revision: Revision,
    pub operation: AwsS3Operation,
    pub page_number: u16,
    pub observation: AwsS3Observation,
    pub next_marker: Option<OpaqueMarker>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3ProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_version: String,
    pub api_revision: String,
    pub operations: Vec<AwsS3Operation>,
    pub allowed_permissions: Vec<String>,
    pub accepted_provenance: Vec<TransportProvenance>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub provider_receipt: bool,
    pub provider_digest: Digest,
}

impl AwsS3ProviderDefinition {
    pub fn new() -> Self {
        let mut definition = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PROVIDER_VERSION.to_owned(),
            api_version: API_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            operations: AwsS3Operation::all().to_vec(),
            allowed_permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            accepted_provenance: vec![
                TransportProvenance::Recording,
                TransportProvenance::Fixture,
                TransportProvenance::Fake,
                TransportProvenance::Loopback,
                TransportProvenance::BlockedEnv,
            ],
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            provider_receipt: false,
            provider_digest: Digest::zero(),
        };
        definition.provider_digest = definition.recomputed_digest();
        definition
    }

    pub fn validate(&self) -> std::result::Result<(), AwsS3BucketError> {
        if self.provider_id != PROVIDER_ID
            || self.provider_version != PROVIDER_VERSION
            || self.api_version != API_VERSION
            || self.api_revision != PROVIDER_API_REVISION
            || self.operations.as_slice() != AwsS3Operation::all().as_slice()
            || self.allowed_permissions
                != LAYER1_PERMISSIONS
                    .iter()
                    .map(|permission| (*permission).to_owned())
                    .collect::<Vec<_>>()
            || self.accepted_provenance
                != vec![
                    TransportProvenance::Recording,
                    TransportProvenance::Fixture,
                    TransportProvenance::Fake,
                    TransportProvenance::Loopback,
                    TransportProvenance::BlockedEnv,
                ]
            || self.connected
            || self.native
            || self.first_party
            || self.external_writes
            || self.provider_receipt
            || self.provider_digest != self.recomputed_digest()
        {
            Err(AwsS3BucketError::ProviderDrift)
        } else {
            Ok(())
        }
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-provider-definition/v1",
            &[
                ("provider_id", self.provider_id.clone()),
                ("provider_version", self.provider_version.clone()),
                ("api_version", self.api_version.clone()),
                ("api_revision", self.api_revision.clone()),
                (
                    "operations",
                    self.operations
                        .iter()
                        .map(|operation| operation.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("permissions", self.allowed_permissions.join(",")),
                (
                    "provenance",
                    self.accepted_provenance
                        .iter()
                        .map(|provenance| provenance.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("external_writes", self.external_writes.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("plugin_version", PLUGIN_VERSION.to_owned()),
            ],
        )
    }
}

impl Default for AwsS3ProviderDefinition {
    fn default() -> Self {
        Self::new()
    }
}

pub trait AwsS3Transport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read(
        &mut self,
        request: &AwsS3OperationRequest,
    ) -> std::result::Result<AwsS3ReadPage, AwsS3TransportError>;
}

#[derive(Clone)]
pub struct AwsS3Provider<T> {
    transport: T,
    definition: AwsS3ProviderDefinition,
}

impl<T: fmt::Debug> fmt::Debug for AwsS3Provider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsS3Provider")
            .field("transport", &self.transport)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: AwsS3Transport> AwsS3Provider<T> {
    pub fn new(transport: T) -> std::result::Result<Self, AwsS3BucketError> {
        let definition = AwsS3ProviderDefinition::new();
        definition.validate()?;
        if !definition
            .accepted_provenance
            .contains(&transport.provenance())
        {
            return Err(AwsS3BucketError::ProviderDrift);
        }
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn with_definition(
        transport: T,
        definition: AwsS3ProviderDefinition,
    ) -> std::result::Result<Self, AwsS3BucketError> {
        definition.validate()?;
        if !definition
            .accepted_provenance
            .contains(&transport.provenance())
        {
            return Err(AwsS3BucketError::ProviderDrift);
        }
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsS3ProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        request: &AwsS3OperationRequest,
    ) -> std::result::Result<AwsS3ReadPage, AwsS3BucketError> {
        request.validate()?;
        let page = self.transport.read(request)?;
        if page.provenance != self.provenance() {
            return Err(AwsS3TransportError::ScopeDrift.into());
        }
        page.validate_for(request)?;
        Ok(page)
    }

    pub fn get_bucket_versioning(
        &mut self,
        request: &AwsS3OperationRequest,
    ) -> std::result::Result<AwsS3ReadPage, AwsS3BucketError> {
        self.read_for(AwsS3Operation::GetBucketVersioning, request)
    }

    pub fn get_bucket_encryption(
        &mut self,
        request: &AwsS3OperationRequest,
    ) -> std::result::Result<AwsS3ReadPage, AwsS3BucketError> {
        self.read_for(AwsS3Operation::GetBucketEncryption, request)
    }

    pub fn get_bucket_lifecycle_configuration(
        &mut self,
        request: &AwsS3OperationRequest,
    ) -> std::result::Result<AwsS3ReadPage, AwsS3BucketError> {
        self.read_for(AwsS3Operation::GetBucketLifecycleConfiguration, request)
    }

    pub fn get_bucket_replication(
        &mut self,
        request: &AwsS3OperationRequest,
    ) -> std::result::Result<AwsS3ReadPage, AwsS3BucketError> {
        self.read_for(AwsS3Operation::GetBucketReplication, request)
    }

    pub fn get_bucket_location(
        &mut self,
        request: &AwsS3OperationRequest,
    ) -> std::result::Result<AwsS3ReadPage, AwsS3BucketError> {
        self.read_for(AwsS3Operation::GetBucketLocation, request)
    }

    fn read_for(
        &mut self,
        operation: AwsS3Operation,
        request: &AwsS3OperationRequest,
    ) -> std::result::Result<AwsS3ReadPage, AwsS3BucketError> {
        if request.operation != operation {
            return Err(AwsS3BucketError::ScopeMismatch(
                "S3 operation request".to_owned(),
            ));
        }
        self.read(request)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    pub fn parse_json_page(
        request: &AwsS3OperationRequest,
        page_number: u16,
        status_code: u16,
        body: &[u8],
    ) -> std::result::Result<AwsS3ReadPage, AwsS3TransportError> {
        Self::parse_json_page_with_provenance(
            request,
            page_number,
            status_code,
            body,
            TransportProvenance::Recording,
        )
    }

    pub fn parse_json_page_with_provenance(
        request: &AwsS3OperationRequest,
        page_number: u16,
        status_code: u16,
        body: &[u8],
        provenance: TransportProvenance,
    ) -> std::result::Result<AwsS3ReadPage, AwsS3TransportError> {
        if status_code != 200 {
            return Err(transport_error_for_status(status_code));
        }
        if page_number != request.page_number {
            return Err(AwsS3TransportError::ScopeDrift);
        }
        if body.is_empty() || body.len() as u64 > request.max_response_bytes {
            return Err(AwsS3TransportError::MalformedResponse);
        }
        let value = serde_json::from_slice::<Value>(body)
            .map_err(|_| AwsS3TransportError::MalformedResponse)?;
        let observation = parse_observation(request, &value)?;
        AwsS3ReadPage::new(request, observation, None, body.len() as u64, provenance)
    }
}

impl Default for AwsS3Provider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked S3 provider definition")
    }
}

fn transport_error_for_status(status_code: u16) -> AwsS3TransportError {
    match status_code {
        400 => AwsS3TransportError::BadRequest,
        401 => AwsS3TransportError::Unauthorized,
        403 => AwsS3TransportError::Forbidden,
        404 => AwsS3TransportError::NotFound,
        429 => AwsS3TransportError::Throttled {
            retry_after_seconds: None,
        },
        500..=599 => AwsS3TransportError::ServerFailure {
            status_code: Some(status_code),
        },
        _ => AwsS3TransportError::Unknown,
    }
}

fn parse_observation(
    request: &AwsS3OperationRequest,
    value: &Value,
) -> std::result::Result<AwsS3Observation, AwsS3TransportError> {
    let bucket_digest = request.bucket_digest.clone();
    let revision = request.resource_revision;
    match request.operation {
        AwsS3Operation::GetBucketVersioning => {
            let object = value
                .as_object()
                .ok_or(AwsS3TransportError::MalformedResponse)?;
            let posture = match object.get("Status").and_then(Value::as_str) {
                None => VersioningPosture::NeverEnabled,
                Some("Enabled") => VersioningPosture::Enabled,
                Some("Suspended") => VersioningPosture::Suspended,
                Some(_) => return Err(AwsS3TransportError::MalformedResponse),
            };
            Ok(AwsS3Observation::GetBucketVersioning(
                BucketVersioningObservation::new(bucket_digest, revision, posture)
                    .map_err(|_| AwsS3TransportError::MalformedResponse)?,
            ))
        }
        AwsS3Operation::GetBucketEncryption => {
            let rules = value
                .get("ServerSideEncryptionConfiguration")
                .and_then(|configuration| configuration.get("Rules"))
                .or_else(|| value.get("Rules"))
                .and_then(Value::as_array)
                .ok_or(AwsS3TransportError::MalformedResponse)?;
            let rule_count =
                u16::try_from(rules.len()).map_err(|_| AwsS3TransportError::MalformedResponse)?;
            let mut algorithms = Vec::new();
            for rule in rules {
                let algorithm = rule
                    .get("ApplyServerSideEncryptionByDefault")
                    .and_then(|value| value.get("SSEAlgorithm"))
                    .or_else(|| rule.get("SSEAlgorithm"))
                    .and_then(Value::as_str)
                    .map_or(EncryptionAlgorithm::Unknown, parse_encryption_algorithm);
                algorithms.push(algorithm);
            }
            let algorithm = algorithms
                .first()
                .copied()
                .filter(|first| algorithms.iter().all(|value| value == first))
                .unwrap_or(EncryptionAlgorithm::Unknown);
            let posture = if rule_count == 0 || matches!(algorithm, EncryptionAlgorithm::Unknown) {
                EncryptionPosture::Unknown
            } else {
                EncryptionPosture::Encrypted
            };
            Ok(AwsS3Observation::GetBucketEncryption(
                BucketEncryptionObservation::new(
                    bucket_digest,
                    revision,
                    posture,
                    algorithm,
                    rule_count,
                )
                .map_err(|_| AwsS3TransportError::MalformedResponse)?,
            ))
        }
        AwsS3Operation::GetBucketLifecycleConfiguration => {
            let rules = value
                .get("Rules")
                .and_then(Value::as_array)
                .ok_or(AwsS3TransportError::MalformedResponse)?;
            let rule_count =
                u16::try_from(rules.len()).map_err(|_| AwsS3TransportError::MalformedResponse)?;
            let mut enabled_rule_count = 0_u16;
            for rule in rules {
                match rule.get("Status").and_then(Value::as_str) {
                    Some("Enabled") => enabled_rule_count = enabled_rule_count.saturating_add(1),
                    Some("Disabled") => {}
                    _ => return Err(AwsS3TransportError::MalformedResponse),
                }
            }
            let posture = if rule_count == 0 {
                LifecyclePosture::NotConfigured
            } else {
                LifecyclePosture::Configured
            };
            Ok(AwsS3Observation::GetBucketLifecycleConfiguration(
                BucketLifecycleObservation::new(
                    bucket_digest,
                    revision,
                    posture,
                    rule_count,
                    enabled_rule_count,
                )
                .map_err(|_| AwsS3TransportError::MalformedResponse)?,
            ))
        }
        AwsS3Operation::GetBucketReplication => {
            let rules = value
                .get("Rules")
                .and_then(Value::as_array)
                .ok_or(AwsS3TransportError::MalformedResponse)?;
            let rule_count =
                u16::try_from(rules.len()).map_err(|_| AwsS3TransportError::MalformedResponse)?;
            let mut enabled_rule_count = 0_u16;
            for rule in rules {
                match rule.get("Status").and_then(Value::as_str) {
                    Some("Enabled") => enabled_rule_count = enabled_rule_count.saturating_add(1),
                    Some("Disabled") => {}
                    _ => return Err(AwsS3TransportError::MalformedResponse),
                }
            }
            let posture = if rule_count == 0 {
                ReplicationPosture::NotConfigured
            } else {
                ReplicationPosture::Configured
            };
            Ok(AwsS3Observation::GetBucketReplication(
                BucketReplicationObservation::new(
                    bucket_digest,
                    revision,
                    posture,
                    rule_count,
                    enabled_rule_count,
                )
                .map_err(|_| AwsS3TransportError::MalformedResponse)?,
            ))
        }
        AwsS3Operation::GetBucketLocation => {
            let raw_region = value
                .get("LocationConstraint")
                .and_then(Value::as_str)
                .unwrap_or("us-east-1");
            let region = match raw_region {
                "" | "us-east-1" => "us-east-1".to_owned(),
                "EU" => "eu-west-1".to_owned(),
                value => value.to_owned(),
            };
            let region = crate::model::AwsRegion::new(region)
                .map_err(|_| AwsS3TransportError::MalformedResponse)?;
            Ok(AwsS3Observation::GetBucketLocation(
                BucketLocationObservation::new(
                    bucket_digest,
                    revision,
                    region,
                    &request.provider_scope.region().clone(),
                )
                .map_err(|_| AwsS3TransportError::MalformedResponse)?,
            ))
        }
    }
}

fn parse_encryption_algorithm(value: &str) -> EncryptionAlgorithm {
    match value {
        "AES256" => EncryptionAlgorithm::Aes256,
        "aws:kms" | "aws:kms:dsse" => EncryptionAlgorithm::AwsKms,
        _ => EncryptionAlgorithm::Unknown,
    }
}

fn fixture_observation(
    request: &AwsS3OperationRequest,
    loopback: bool,
) -> std::result::Result<AwsS3Observation, AwsS3TransportError> {
    let bucket = request.bucket_digest.clone();
    let revision = request.resource_revision;
    let scope_region = request.provider_scope.region().clone();
    let observation = match request.operation {
        AwsS3Operation::GetBucketVersioning => BucketVersioningObservation::new(
            bucket,
            revision,
            if loopback {
                VersioningPosture::Suspended
            } else {
                VersioningPosture::Enabled
            },
        )
        .map(AwsS3Observation::GetBucketVersioning),
        AwsS3Operation::GetBucketEncryption => BucketEncryptionObservation::new(
            bucket,
            revision,
            EncryptionPosture::Encrypted,
            if loopback {
                EncryptionAlgorithm::AwsKms
            } else {
                EncryptionAlgorithm::Aes256
            },
            1,
        )
        .map(AwsS3Observation::GetBucketEncryption),
        AwsS3Operation::GetBucketLifecycleConfiguration => BucketLifecycleObservation::new(
            bucket,
            revision,
            if loopback {
                LifecyclePosture::NotConfigured
            } else {
                LifecyclePosture::Configured
            },
            u16::from(!loopback),
            u16::from(!loopback),
        )
        .map(AwsS3Observation::GetBucketLifecycleConfiguration),
        AwsS3Operation::GetBucketReplication => BucketReplicationObservation::new(
            bucket,
            revision,
            if loopback {
                ReplicationPosture::Configured
            } else {
                ReplicationPosture::NotConfigured
            },
            u16::from(loopback),
            u16::from(loopback),
        )
        .map(AwsS3Observation::GetBucketReplication),
        AwsS3Operation::GetBucketLocation => {
            BucketLocationObservation::new(bucket, revision, scope_region.clone(), &scope_region)
                .map(AwsS3Observation::GetBucketLocation)
        }
    };
    observation.map_err(|_| AwsS3TransportError::MalformedResponse)
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    provider_scope: AwsS3ProviderScope,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsS3BucketScope) -> Self {
        Self {
            provider_scope: scope.provider_scope().clone(),
        }
    }

    pub fn for_provider_scope(scope: &AwsS3ProviderScope) -> Self {
        Self {
            provider_scope: scope.clone(),
        }
    }

    pub fn new(scope: &AwsS3ProviderScope) -> Self {
        Self::for_provider_scope(scope)
    }
}

impl AwsS3Transport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn read(
        &mut self,
        request: &AwsS3OperationRequest,
    ) -> std::result::Result<AwsS3ReadPage, AwsS3TransportError> {
        if request.provider_scope.digest() != &self.provider_scope.digest().clone() {
            return Err(AwsS3TransportError::ScopeDrift);
        }
        AwsS3ReadPage::new(
            request,
            fixture_observation(request, false)?,
            None,
            512,
            self.provenance(),
        )
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    provider_scope: AwsS3ProviderScope,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsS3BucketScope) -> Self {
        Self {
            provider_scope: scope.provider_scope().clone(),
        }
    }

    pub fn for_provider_scope(scope: &AwsS3ProviderScope) -> Self {
        Self {
            provider_scope: scope.clone(),
        }
    }
}

impl AwsS3Transport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read(
        &mut self,
        request: &AwsS3OperationRequest,
    ) -> std::result::Result<AwsS3ReadPage, AwsS3TransportError> {
        if request.provider_scope.digest() != &self.provider_scope.digest().clone() {
            return Err(AwsS3TransportError::ScopeDrift);
        }
        AwsS3ReadPage::new(
            request,
            fixture_observation(request, true)?,
            None,
            640,
            self.provenance(),
        )
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    responses: VecDeque<std::result::Result<AwsS3ReadPage, AwsS3TransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(
        &mut self,
        response: std::result::Result<AwsS3ReadPage, AwsS3TransportError>,
    ) {
        self.responses.push_back(response);
    }

    pub fn push(&mut self, response: std::result::Result<AwsS3ReadPage, AwsS3TransportError>) {
        self.push_response(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl AwsS3Transport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn read(
        &mut self,
        request: &AwsS3OperationRequest,
    ) -> std::result::Result<AwsS3ReadPage, AwsS3TransportError> {
        self.requests.push(RecordedRequest::from_request(request));
        self.responses
            .pop_front()
            .unwrap_or(Err(AwsS3TransportError::Timeout))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsS3Transport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read(
        &mut self,
        _request: &AwsS3OperationRequest,
    ) -> std::result::Result<AwsS3ReadPage, AwsS3TransportError> {
        Err(AwsS3TransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsS3Operation,
    pub scope_digest: Digest,
    pub bucket_digest: Digest,
    pub resource_revision: Revision,
    pub page_number: u16,
    pub marker_digest: Option<Digest>,
    pub request_digest: Digest,
}

impl RecordedRequest {
    fn from_request(request: &AwsS3OperationRequest) -> Self {
        Self {
            operation: request.operation,
            scope_digest: request.scope_digest.clone(),
            bucket_digest: request.bucket_digest.clone(),
            resource_revision: request.resource_revision,
            page_number: request.page_number,
            marker_digest: request.marker_digest().cloned(),
            request_digest: request.request_digest.clone(),
        }
    }
}

pub type FixtureAwsS3Transport = FixtureTransport;
pub type FakeAwsS3Transport = FixtureTransport;
pub type LoopbackAwsS3Transport = LoopbackTransport;
pub type RecordingAwsS3Transport = RecordingTransport;
pub type BlockedEnvAwsS3Transport = BlockedEnvTransport;
pub type FakeTransport = FixtureTransport;

impl AwsS3ReadPage {
    pub fn new(
        request: &AwsS3OperationRequest,
        observation: AwsS3Observation,
        next_marker: Option<OpaqueMarker>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> std::result::Result<Self, AwsS3TransportError> {
        if observation.operation() != request.operation
            || response_bytes == 0
            || response_bytes > request.max_response_bytes
            || !provenance.is_non_native()
        {
            return Err(AwsS3TransportError::MalformedResponse);
        }
        let next_marker = next_marker.map(|value| value.bind(&request.query_digest()));
        let mut page = Self {
            scope_digest: request.scope_digest.clone(),
            provider_scope_digest: request.provider_scope_digest.clone(),
            bucket_digest: request.bucket_digest.clone(),
            resource_revision: request.resource_revision,
            operation: request.operation,
            page_number: request.page_number,
            observation,
            next_marker,
            response_bytes,
            provenance,
            response_digest: Digest::zero(),
        };
        page.response_digest = page.recomputed_digest();
        Ok(page)
    }

    pub fn validate_for(
        &self,
        request: &AwsS3OperationRequest,
    ) -> std::result::Result<(), AwsS3TransportError> {
        if request.validate().is_err()
            || self.scope_digest != request.scope_digest
            || self.provider_scope_digest != request.provider_scope_digest
            || self.bucket_digest != request.bucket_digest
            || self.resource_revision != request.resource_revision
            || self.operation != request.operation
            || self.page_number != request.page_number
            || self.response_bytes == 0
            || self.response_bytes > request.max_response_bytes
            || !self.provenance.is_non_native()
            || self.response_digest != self.recomputed_digest()
            || self.observation.operation() != self.operation
        {
            return Err(AwsS3TransportError::ScopeDrift);
        }
        if self
            .observation
            .validate_against(&request.provider_scope)
            .is_err()
        {
            return Err(AwsS3TransportError::ScopeDrift);
        }
        if let Some(marker) = &self.next_marker
            && marker.binding_digest() != Some(&request.query_digest())
        {
            return Err(AwsS3TransportError::MarkerReplay);
        }
        Ok(())
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-read-page/v1",
            &[
                ("scope", self.scope_digest.to_string()),
                ("provider_scope", self.provider_scope_digest.to_string()),
                ("bucket", self.bucket_digest.to_string()),
                ("revision", self.resource_revision.get().to_string()),
                ("operation", self.operation.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                ("observation", self.observation.digest().to_string()),
                (
                    "next_marker",
                    self.next_marker
                        .as_ref()
                        .map_or_else(String::new, |value| value.token_digest().to_string()),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}
