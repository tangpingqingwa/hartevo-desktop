use std::{
    fmt,
    sync::{Arc, Mutex},
};

use thiserror::Error;

use crate::error::{Result, SageMakerEndpointResultError};
use crate::model::{
    EndpointConfigDescriptionRecord, EndpointDescriptionRecord, ProviderProvenance, SageMakerScope,
    SecretReference,
};

/// The in-memory credential value is only a host-side input to a transport
/// seam. It has no serialization and its Debug representation is redacted.
#[derive(Clone)]
pub struct SigV4CredentialMaterial(String);

impl SigV4CredentialMaterial {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl fmt::Debug for SigV4CredentialMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SigV4CredentialMaterial(<redacted>)")
    }
}

/// Host authority for resolving an opaque SigV4 SecretReference. Layer 1
/// ships a blocked resolver and a test-only static resolver; native AWS
/// resolution is intentionally a Layer-2 gap.
pub trait SigV4CredentialResolver: fmt::Debug + Send + Sync {
    fn resolve(&self, reference: &SecretReference) -> Result<SigV4CredentialMaterial>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl SigV4CredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(&self, _reference: &SecretReference) -> Result<SigV4CredentialMaterial> {
        Err(SageMakerEndpointResultError::BlockedEnv)
    }
}

/// A fixture-only resolver. The value is never serialized or included in
/// provider Debug output, and using it never changes Layer-1 provenance.
#[derive(Clone)]
pub struct StaticSigV4CredentialResolver {
    material: SigV4CredentialMaterial,
}

impl fmt::Debug for StaticSigV4CredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticSigV4CredentialResolver(<redacted>)")
    }
}

impl StaticSigV4CredentialResolver {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            material: SigV4CredentialMaterial::new(value),
        }
    }
}

impl SigV4CredentialResolver for StaticSigV4CredentialResolver {
    fn resolve(&self, _reference: &SecretReference) -> Result<SigV4CredentialMaterial> {
        if self.material.is_empty() {
            Err(SageMakerEndpointResultError::BlockedEnv)
        } else {
            Ok(self.material.clone())
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SageMakerTransportError {
    #[error("AWS request was malformed")]
    BadRequest,
    #[error("AWS credentials were rejected")]
    Unauthorized,
    #[error("AWS permission was denied")]
    Forbidden,
    #[error("SageMaker resource was not found")]
    NotFound,
    #[error("SageMaker request conflicted")]
    Conflict,
    #[error("SageMaker request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("SageMaker request timed out")]
    Timeout,
    #[error("SageMaker service returned a server error")]
    ServerError { status: u16 },
    #[error("SageMaker response was malformed")]
    MalformedResponse,
    #[error("SageMaker response was partial")]
    PartialResponse,
    #[error("SageMaker access was lost")]
    AccessLost,
    #[error("SageMaker response exceeded the bounded limit")]
    ResponseTooLarge,
    #[error("SageMaker transport is blocked by the environment gate")]
    BlockedEnv,
}

impl SageMakerTransportError {
    pub fn from_http_status(status: u16, retry_after_seconds: Option<u64>) -> Self {
        match status {
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            409 => Self::Conflict,
            429 => Self::RateLimited {
                retry_after_seconds,
            },
            500..=599 => Self::ServerError { status },
            _ => Self::MalformedResponse,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SageMakerTransportOperation {
    DescribeEndpoint,
    DescribeEndpointConfig,
}

/// Read-only transport seam for the two exact SageMaker APIs used by this
/// plugin. No method can create, update, delete, invoke, scale, or discover an
/// endpoint.
pub trait SageMakerTransport: fmt::Debug + Send {
    fn describe_endpoint(
        &mut self,
        credential: &SigV4CredentialMaterial,
        scope: &SageMakerScope,
    ) -> std::result::Result<EndpointDescriptionRecord, SageMakerTransportError>;

    fn describe_endpoint_config(
        &mut self,
        credential: &SigV4CredentialMaterial,
        scope: &SageMakerScope,
    ) -> std::result::Result<EndpointConfigDescriptionRecord, SageMakerTransportError>;

    fn provenance(&self) -> ProviderProvenance;
}

/// The native SigV4/HTTPS seam is present as an explicit Layer-2 boundary but
/// never performs a live request in this Layer-1 crate.
#[derive(Clone, Debug, Default)]
pub struct SigV4SageMakerTransport;

impl SageMakerTransport for SigV4SageMakerTransport {
    fn describe_endpoint(
        &mut self,
        _credential: &SigV4CredentialMaterial,
        _scope: &SageMakerScope,
    ) -> std::result::Result<EndpointDescriptionRecord, SageMakerTransportError> {
        Err(SageMakerTransportError::BlockedEnv)
    }

    fn describe_endpoint_config(
        &mut self,
        _credential: &SigV4CredentialMaterial,
        _scope: &SageMakerScope,
    ) -> std::result::Result<EndpointConfigDescriptionRecord, SageMakerTransportError> {
        Err(SageMakerTransportError::BlockedEnv)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }
}

#[derive(Clone, Debug)]
struct RecordingState {
    endpoint: Option<EndpointDescriptionRecord>,
    endpoint_config: Option<EndpointConfigDescriptionRecord>,
    fault: Option<SageMakerTransportError>,
    seen_operations: Vec<SageMakerTransportOperation>,
}

/// Deterministic fixture/fake/recording/loopback transport. All variants are
/// explicitly non-connected and non-native; the variant label only describes
/// how the test evidence was produced.
#[derive(Clone)]
pub struct RecordingSageMakerTransport {
    state: Arc<Mutex<RecordingState>>,
    provenance: ProviderProvenance,
}

impl fmt::Debug for RecordingSageMakerTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingSageMakerTransport")
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

impl RecordingSageMakerTransport {
    pub fn new(
        endpoint: EndpointDescriptionRecord,
        endpoint_config: EndpointConfigDescriptionRecord,
        provenance: ProviderProvenance,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(RecordingState {
                endpoint: Some(endpoint),
                endpoint_config: Some(endpoint_config),
                fault: None,
                seen_operations: Vec::new(),
            })),
            provenance,
        }
    }

    pub fn recording(
        endpoint: EndpointDescriptionRecord,
        endpoint_config: EndpointConfigDescriptionRecord,
    ) -> Self {
        Self::new(endpoint, endpoint_config, ProviderProvenance::Recording)
    }

    pub fn fake(
        endpoint: EndpointDescriptionRecord,
        endpoint_config: EndpointConfigDescriptionRecord,
    ) -> Self {
        Self::new(endpoint, endpoint_config, ProviderProvenance::Fake)
    }

    pub fn fixture(
        endpoint: EndpointDescriptionRecord,
        endpoint_config: EndpointConfigDescriptionRecord,
    ) -> Self {
        Self::new(endpoint, endpoint_config, ProviderProvenance::Fixture)
    }

    pub fn loopback(
        endpoint: EndpointDescriptionRecord,
        endpoint_config: EndpointConfigDescriptionRecord,
    ) -> Self {
        Self::new(endpoint, endpoint_config, ProviderProvenance::Loopback)
    }

    pub fn blocked_env(
        endpoint: EndpointDescriptionRecord,
        endpoint_config: EndpointConfigDescriptionRecord,
    ) -> Self {
        Self::new(endpoint, endpoint_config, ProviderProvenance::BlockedEnv)
    }

    pub fn set_endpoint(&self, endpoint: EndpointDescriptionRecord) {
        self.state
            .lock()
            .expect("recording transport lock")
            .endpoint = Some(endpoint);
    }

    pub fn set_endpoint_config(&self, endpoint_config: EndpointConfigDescriptionRecord) {
        self.state
            .lock()
            .expect("recording transport lock")
            .endpoint_config = Some(endpoint_config);
    }

    pub fn set_fault(&self, fault: SageMakerTransportError) {
        self.state.lock().expect("recording transport lock").fault = Some(fault);
    }

    pub fn clear_fault(&self) {
        self.state.lock().expect("recording transport lock").fault = None;
    }

    pub fn seen_operations(&self) -> Vec<SageMakerTransportOperation> {
        self.state
            .lock()
            .expect("recording transport lock")
            .seen_operations
            .clone()
    }

    fn fault_or<T>(
        state: &mut RecordingState,
        operation: SageMakerTransportOperation,
        value: Option<T>,
    ) -> std::result::Result<T, SageMakerTransportError> {
        state.seen_operations.push(operation);
        if let Some(fault) = &state.fault {
            return Err(fault.clone());
        }
        value.ok_or(SageMakerTransportError::MalformedResponse)
    }
}

impl SageMakerTransport for RecordingSageMakerTransport {
    fn describe_endpoint(
        &mut self,
        _credential: &SigV4CredentialMaterial,
        _scope: &SageMakerScope,
    ) -> std::result::Result<EndpointDescriptionRecord, SageMakerTransportError> {
        if self.provenance == ProviderProvenance::BlockedEnv {
            return Err(SageMakerTransportError::BlockedEnv);
        }
        let mut state = self.state.lock().expect("recording transport lock");
        let endpoint = state.endpoint.clone();
        Self::fault_or(
            &mut state,
            SageMakerTransportOperation::DescribeEndpoint,
            endpoint,
        )
    }

    fn describe_endpoint_config(
        &mut self,
        _credential: &SigV4CredentialMaterial,
        _scope: &SageMakerScope,
    ) -> std::result::Result<EndpointConfigDescriptionRecord, SageMakerTransportError> {
        if self.provenance == ProviderProvenance::BlockedEnv {
            return Err(SageMakerTransportError::BlockedEnv);
        }
        let mut state = self.state.lock().expect("recording transport lock");
        let endpoint_config = state.endpoint_config.clone();
        Self::fault_or(
            &mut state,
            SageMakerTransportOperation::DescribeEndpointConfig,
            endpoint_config,
        )
    }

    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }
}

pub type FakeSageMakerTransport = RecordingSageMakerTransport;
pub type FixtureSageMakerTransport = RecordingSageMakerTransport;
pub type LoopbackSageMakerTransport = RecordingSageMakerTransport;
pub type BlockedEnvSageMakerTransport = RecordingSageMakerTransport;
