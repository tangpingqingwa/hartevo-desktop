//! Non-native provider and transport seams for bounded AWS KMS reads.

use std::{collections::BTreeSet, fmt, num::NonZeroU16, vec::Vec};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_KMS_API_REVISION, AWS_KMS_API_VERSION, AWS_KMS_KEY_POSTURE_PROVIDER_ID,
    AWS_KMS_PROVIDER_VERSION, contract_digest,
    model::{
        AwsKmsReadOperation, AwsKmsScope, ConsistencyState, CostReceipt, Digest, KmsAliasSummary,
        KmsGrantSummary, KmsKeyMetadata, KmsKeyReference, KmsKeySummary, MAX_ALIASES, MAX_GRANTS,
        MAX_KEYS, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, ModelError, OpaqueMarker,
        PermissionFence, ProviderProvenance, RedactedRequestReceipt, RotationStatus,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportFailure {
    BadRequest,
    Unauthorized,
    AccessDenied,
    NotFound,
    Throttled,
    Server,
    Timeout,
    EventualConsistency,
    BlockedEnv,
    Malformed,
}

impl TransportFailure {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::Throttled => Some(429),
            Self::Server => Some(500),
            Self::Timeout | Self::EventualConsistency | Self::BlockedEnv | Self::Malformed => None,
        }
    }

    pub const fn from_status(status: u16) -> Self {
        match status {
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::AccessDenied,
            404 => Self::NotFound,
            429 => Self::Throttled,
            500..=599 => Self::Server,
            _ => Self::Malformed,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::BadRequest => "400",
            Self::Unauthorized => "401",
            Self::AccessDenied => "403",
            Self::NotFound => "404",
            Self::Throttled => "429",
            Self::Server => "500",
            Self::Timeout => "timeout",
            Self::EventualConsistency => "eventual-consistency",
            Self::BlockedEnv => "BLOCKED_ENV",
            Self::Malformed => "malformed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[error("AWS KMS transport failure: {failure:?}")]
#[serde(rename_all = "camelCase")]
pub struct TransportError {
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

impl TransportError {
    pub fn new(failure: TransportFailure) -> Self {
        Self {
            status_code: failure.status_code(),
            error_digest: Digest::from_text(failure.label()),
            failure,
        }
    }

    pub fn from_status(status: u16) -> Self {
        Self::new(TransportFailure::from_status(status))
    }

    pub fn blocked_env() -> Self {
        Self::new(TransportFailure::BlockedEnv)
    }

    pub fn timeout() -> Self {
        Self::new(TransportFailure::Timeout)
    }

    pub fn eventual_consistency() -> Self {
        Self::new(TransportFailure::EventualConsistency)
    }

    pub fn malformed() -> Self {
        Self::new(TransportFailure::Malformed)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsKmsProviderError {
    #[error("AWS KMS transport error: {0}")]
    Transport(TransportError),
    #[error("AWS KMS model error: {0}")]
    Model(ModelError),
    #[error("AWS KMS provider definition is invalid")]
    InvalidDefinition,
    #[error("AWS KMS request drifted")]
    RequestDrift,
    #[error("AWS KMS scope drifted")]
    ScopeDrift,
    #[error("AWS KMS permission drifted or was lost")]
    PermissionLoss,
    #[error("AWS KMS key drifted")]
    KeyDrift,
    #[error("AWS KMS marker loop detected")]
    MarkerLoop,
    #[error("AWS KMS pagination is incomplete")]
    PaginationIncomplete,
    #[error("AWS KMS response exceeded its bound")]
    ResponseTooLarge,
    #[error("AWS KMS duplicate item detected")]
    DuplicateItem,
    #[error("AWS KMS record is tampered")]
    RecordTampered,
    #[error("AWS KMS response is partial or eventually consistent")]
    Partial,
}

impl From<ModelError> for AwsKmsProviderError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsKmsProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_version: String,
    pub api_revision: String,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub allowlisted_operations: Vec<AwsKmsReadOperation>,
    pub api_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
}

impl Default for AwsKmsProviderDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsKmsProviderDefinition {
    pub fn new() -> Self {
        let allowlisted_operations = AwsKmsReadOperation::API.to_vec();
        let api_digest = Digest::from_parts(
            "aws-kms-api/v1",
            &[
                ("version", AWS_KMS_API_VERSION.to_owned()),
                ("revision", AWS_KMS_API_REVISION.to_owned()),
                (
                    "operations",
                    allowlisted_operations
                        .iter()
                        .map(|operation| format!("{operation:?}"))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        let provider_digest = Digest::from_parts(
            "aws-kms-provider/v1",
            &[
                ("id", AWS_KMS_KEY_POSTURE_PROVIDER_ID.to_owned()),
                ("version", AWS_KMS_PROVIDER_VERSION.to_owned()),
                ("api", api_digest.as_str().to_owned()),
                ("read_only", "true".to_owned()),
                ("native", "false".to_owned()),
                ("connected", "false".to_owned()),
                ("first_party", "false".to_owned()),
            ],
        );
        Self {
            provider_id: AWS_KMS_KEY_POSTURE_PROVIDER_ID.to_owned(),
            provider_version: AWS_KMS_PROVIDER_VERSION.to_owned(),
            api_version: AWS_KMS_API_VERSION.to_owned(),
            api_revision: AWS_KMS_API_REVISION.to_owned(),
            read_only: true,
            native: false,
            connected: false,
            first_party: false,
            allowlisted_operations,
            api_digest,
            provider_digest,
            contract_digest: contract_digest(),
        }
    }

    pub fn validate(&self) -> Result<(), AwsKmsProviderError> {
        if self != &Self::new() {
            Err(AwsKmsProviderError::InvalidDefinition)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KmsReadBounds {
    pub max_page_size: u16,
    pub max_pages: u16,
    pub max_keys: usize,
    pub max_aliases: usize,
    pub max_grants: usize,
    pub max_response_bytes: u64,
}

impl Default for KmsReadBounds {
    fn default() -> Self {
        Self {
            max_page_size: MAX_PAGE_SIZE,
            max_pages: MAX_PAGES,
            max_keys: MAX_KEYS,
            max_aliases: MAX_ALIASES,
            max_grants: MAX_GRANTS,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

impl KmsReadBounds {
    pub fn validate(&self) -> Result<(), AwsKmsProviderError> {
        if self.max_page_size == 0
            || self.max_page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_keys == 0
            || self.max_keys > MAX_KEYS
            || self.max_aliases == 0
            || self.max_aliases > MAX_ALIASES
            || self.max_grants == 0
            || self.max_grants > MAX_GRANTS
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
        {
            Err(AwsKmsProviderError::ResponseTooLarge)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListKeysPage {
    pub keys: Vec<KmsKeySummary>,
    #[serde(skip)]
    pub next_marker: Option<OpaqueMarker>,
    pub next_marker_digest: Option<Digest>,
    pub response_bytes: u64,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consistency: ConsistencyState,
}

impl ListKeysPage {
    pub fn new(
        scope_digest: Digest,
        permission_digest: Digest,
        keys: Vec<KmsKeySummary>,
        next_marker: Option<OpaqueMarker>,
        response_bytes: u64,
    ) -> Self {
        let next_marker_digest = next_marker.as_ref().map(OpaqueMarker::digest);
        Self {
            keys,
            next_marker,
            next_marker_digest,
            response_bytes,
            scope_digest,
            permission_digest,
            consistency: ConsistencyState::Stable,
        }
    }

    pub fn with_consistency(mut self, consistency: ConsistencyState) -> Self {
        self.consistency = consistency;
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeKeyResponse {
    pub metadata: KmsKeyMetadata,
    pub key_digest: Digest,
    pub response_bytes: u64,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

impl DescribeKeyResponse {
    pub fn new(
        scope_digest: Digest,
        permission_digest: Digest,
        key_digest: Digest,
        metadata: KmsKeyMetadata,
        response_bytes: u64,
    ) -> Self {
        Self {
            metadata,
            key_digest,
            response_bytes,
            scope_digest,
            permission_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RotationStatusResponse {
    pub status: RotationStatus,
    pub key_digest: Digest,
    pub response_bytes: u64,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

impl RotationStatusResponse {
    pub fn new(
        scope_digest: Digest,
        permission_digest: Digest,
        key_digest: Digest,
        status: RotationStatus,
        response_bytes: u64,
    ) -> Self {
        Self {
            status,
            key_digest,
            response_bytes,
            scope_digest,
            permission_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListAliasesPage {
    pub aliases: Vec<KmsAliasSummary>,
    #[serde(skip)]
    pub next_marker: Option<OpaqueMarker>,
    pub next_marker_digest: Option<Digest>,
    pub key_digest: Digest,
    pub response_bytes: u64,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consistency: ConsistencyState,
}

impl ListAliasesPage {
    pub fn new(
        scope_digest: Digest,
        permission_digest: Digest,
        key_digest: Digest,
        aliases: Vec<KmsAliasSummary>,
        next_marker: Option<OpaqueMarker>,
        response_bytes: u64,
    ) -> Self {
        let next_marker_digest = next_marker.as_ref().map(OpaqueMarker::digest);
        Self {
            aliases,
            next_marker,
            next_marker_digest,
            key_digest,
            response_bytes,
            scope_digest,
            permission_digest,
            consistency: ConsistencyState::Stable,
        }
    }

    pub fn with_consistency(mut self, consistency: ConsistencyState) -> Self {
        self.consistency = consistency;
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListGrantsPage {
    pub grants: Vec<KmsGrantSummary>,
    #[serde(skip)]
    pub next_marker: Option<OpaqueMarker>,
    pub next_marker_digest: Option<Digest>,
    pub key_digest: Digest,
    pub response_bytes: u64,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consistency: ConsistencyState,
}

impl ListGrantsPage {
    pub fn new(
        scope_digest: Digest,
        permission_digest: Digest,
        key_digest: Digest,
        grants: Vec<KmsGrantSummary>,
        next_marker: Option<OpaqueMarker>,
        response_bytes: u64,
    ) -> Self {
        let next_marker_digest = next_marker.as_ref().map(OpaqueMarker::digest);
        Self {
            grants,
            next_marker,
            next_marker_digest,
            key_digest,
            response_bytes,
            scope_digest,
            permission_digest,
            consistency: ConsistencyState::Stable,
        }
    }

    pub fn with_consistency(mut self, consistency: ConsistencyState) -> Self {
        self.consistency = consistency;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListKeysRequest {
    pub account_id: String,
    pub region: String,
    pub limit: u16,
    pub marker: Option<OpaqueMarker>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

impl ListKeysRequest {
    pub fn new(scope: &AwsKmsScope, bounds: &KmsReadBounds) -> Result<Self, AwsKmsProviderError> {
        bounds.validate()?;
        Ok(Self {
            account_id: scope.account_id.as_str().to_owned(),
            region: scope.region.as_str().to_owned(),
            limit: bounds.max_page_size,
            marker: None,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permission_digest.clone(),
        })
    }

    pub fn with_marker(&self, marker: Option<OpaqueMarker>) -> Self {
        let mut value = self.clone();
        value.marker = marker;
        value
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-list-keys-request/v1",
            &[
                (
                    "account",
                    Digest::from_text(&self.account_id).as_str().to_owned(),
                ),
                (
                    "region",
                    Digest::from_text(&self.region).as_str().to_owned(),
                ),
                ("limit", self.limit.to_string()),
                (
                    "marker",
                    self.marker
                        .as_ref()
                        .map_or_else(String::new, |marker| marker.digest().as_str().to_owned()),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescribeKeyRequest {
    pub key: KmsKeyReference,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

impl DescribeKeyRequest {
    pub fn new(scope: &AwsKmsScope, key: KmsKeyReference) -> Self {
        Self {
            key,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permission_digest.clone(),
        }
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-describe-key-request/v1",
            &[
                ("key", self.key.digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetKeyRotationStatusRequest {
    pub key: KmsKeyReference,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

impl GetKeyRotationStatusRequest {
    pub fn new(scope: &AwsKmsScope, key: KmsKeyReference) -> Self {
        Self {
            key,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permission_digest.clone(),
        }
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-get-key-rotation-status-request/v1",
            &[
                ("key", self.key.digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListAliasesRequest {
    pub key: KmsKeyReference,
    pub limit: u16,
    pub marker: Option<OpaqueMarker>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

impl ListAliasesRequest {
    pub fn new(
        scope: &AwsKmsScope,
        key: KmsKeyReference,
        bounds: &KmsReadBounds,
    ) -> Result<Self, AwsKmsProviderError> {
        bounds.validate()?;
        Ok(Self {
            key,
            limit: bounds.max_page_size,
            marker: None,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permission_digest.clone(),
        })
    }

    pub fn with_marker(&self, marker: Option<OpaqueMarker>) -> Self {
        let mut value = self.clone();
        value.marker = marker;
        value
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-list-aliases-request/v1",
            &[
                ("key", self.key.digest().as_str().to_owned()),
                ("limit", self.limit.to_string()),
                (
                    "marker",
                    self.marker
                        .as_ref()
                        .map_or_else(String::new, |marker| marker.digest().as_str().to_owned()),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListGrantsRequest {
    pub key: KmsKeyReference,
    pub limit: u16,
    pub marker: Option<OpaqueMarker>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

impl ListGrantsRequest {
    pub fn new(
        scope: &AwsKmsScope,
        key: KmsKeyReference,
        bounds: &KmsReadBounds,
    ) -> Result<Self, AwsKmsProviderError> {
        bounds.validate()?;
        Ok(Self {
            key,
            limit: bounds.max_page_size,
            marker: None,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permission_digest.clone(),
        })
    }

    pub fn with_marker(&self, marker: Option<OpaqueMarker>) -> Self {
        let mut value = self.clone();
        value.marker = marker;
        value
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kms-list-grants-request/v1",
            &[
                ("key", self.key.digest().as_str().to_owned()),
                ("limit", self.limit.to_string()),
                (
                    "marker",
                    self.marker
                        .as_ref()
                        .map_or_else(String::new, |marker| marker.digest().as_str().to_owned()),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
            ],
        )
    }
}

pub trait AwsKmsTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn list_keys(&mut self, request: &ListKeysRequest) -> Result<ListKeysPage, TransportError>;

    fn describe_key(
        &mut self,
        request: &DescribeKeyRequest,
    ) -> Result<DescribeKeyResponse, TransportError>;

    fn get_key_rotation_status(
        &mut self,
        request: &GetKeyRotationStatusRequest,
    ) -> Result<RotationStatusResponse, TransportError>;

    fn list_aliases(
        &mut self,
        request: &ListAliasesRequest,
    ) -> Result<ListAliasesPage, TransportError>;

    fn list_grants(
        &mut self,
        request: &ListGrantsRequest,
    ) -> Result<ListGrantsPage, TransportError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsKmsTransport;

impl AwsKmsTransport for BlockedEnvAwsKmsTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn list_keys(&mut self, _request: &ListKeysRequest) -> Result<ListKeysPage, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn describe_key(
        &mut self,
        _request: &DescribeKeyRequest,
    ) -> Result<DescribeKeyResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn get_key_rotation_status(
        &mut self,
        _request: &GetKeyRotationStatusRequest,
    ) -> Result<RotationStatusResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn list_aliases(
        &mut self,
        _request: &ListAliasesRequest,
    ) -> Result<ListAliasesPage, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn list_grants(
        &mut self,
        _request: &ListGrantsRequest,
    ) -> Result<ListGrantsPage, TransportError> {
        Err(TransportError::blocked_env())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportCall {
    pub operation: AwsKmsReadOperation,
    pub request_digest: Digest,
    pub marker_digest: Option<Digest>,
}

#[derive(Clone, Debug)]
pub struct RecordingAwsKmsTransport {
    provenance: ProviderProvenance,
    list_keys: std::collections::VecDeque<Result<ListKeysPage, TransportError>>,
    describe_keys: std::collections::VecDeque<Result<DescribeKeyResponse, TransportError>>,
    rotation_statuses: std::collections::VecDeque<Result<RotationStatusResponse, TransportError>>,
    aliases: std::collections::VecDeque<Result<ListAliasesPage, TransportError>>,
    grants: std::collections::VecDeque<Result<ListGrantsPage, TransportError>>,
    calls: Vec<TransportCall>,
}

pub type FixtureAwsKmsTransport = RecordingAwsKmsTransport;
pub type LoopbackAwsKmsTransport = RecordingAwsKmsTransport;

impl Default for RecordingAwsKmsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingAwsKmsTransport {
    pub fn new() -> Self {
        Self {
            provenance: ProviderProvenance::Recording,
            list_keys: std::collections::VecDeque::new(),
            describe_keys: std::collections::VecDeque::new(),
            rotation_statuses: std::collections::VecDeque::new(),
            aliases: std::collections::VecDeque::new(),
            grants: std::collections::VecDeque::new(),
            calls: Vec::new(),
        }
    }

    pub fn fixture() -> Self {
        Self {
            provenance: ProviderProvenance::Fixture,
            ..Self::new()
        }
    }

    pub fn loopback() -> Self {
        Self {
            provenance: ProviderProvenance::Loopback,
            ..Self::new()
        }
    }

    pub fn push_list_keys(&mut self, response: Result<ListKeysPage, TransportError>) {
        self.list_keys.push_back(response);
    }

    pub fn push_describe_key(&mut self, response: Result<DescribeKeyResponse, TransportError>) {
        self.describe_keys.push_back(response);
    }

    pub fn push_rotation_status(
        &mut self,
        response: Result<RotationStatusResponse, TransportError>,
    ) {
        self.rotation_statuses.push_back(response);
    }

    pub fn push_list_aliases(&mut self, response: Result<ListAliasesPage, TransportError>) {
        self.aliases.push_back(response);
    }

    pub fn push_list_grants(&mut self, response: Result<ListGrantsPage, TransportError>) {
        self.grants.push_back(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }

    fn call(
        operation: AwsKmsReadOperation,
        request_digest: Digest,
        marker: Option<&OpaqueMarker>,
    ) -> TransportCall {
        TransportCall {
            operation,
            request_digest,
            marker_digest: marker.map(OpaqueMarker::digest),
        }
    }
}

impl AwsKmsTransport for RecordingAwsKmsTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance.clone()
    }

    fn list_keys(&mut self, request: &ListKeysRequest) -> Result<ListKeysPage, TransportError> {
        self.calls.push(Self::call(
            AwsKmsReadOperation::ListKeys,
            request.request_digest(),
            request.marker.as_ref(),
        ));
        self.list_keys
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::malformed()))
    }

    fn describe_key(
        &mut self,
        request: &DescribeKeyRequest,
    ) -> Result<DescribeKeyResponse, TransportError> {
        self.calls.push(Self::call(
            AwsKmsReadOperation::DescribeKey,
            request.request_digest(),
            None,
        ));
        self.describe_keys
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::malformed()))
    }

    fn get_key_rotation_status(
        &mut self,
        request: &GetKeyRotationStatusRequest,
    ) -> Result<RotationStatusResponse, TransportError> {
        self.calls.push(Self::call(
            AwsKmsReadOperation::GetKeyRotationStatus,
            request.request_digest(),
            None,
        ));
        self.rotation_statuses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::malformed()))
    }

    fn list_aliases(
        &mut self,
        request: &ListAliasesRequest,
    ) -> Result<ListAliasesPage, TransportError> {
        self.calls.push(Self::call(
            AwsKmsReadOperation::ListAliases,
            request.request_digest(),
            request.marker.as_ref(),
        ));
        self.aliases
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::malformed()))
    }

    fn list_grants(
        &mut self,
        request: &ListGrantsRequest,
    ) -> Result<ListGrantsPage, TransportError> {
        self.calls.push(Self::call(
            AwsKmsReadOperation::ListGrants,
            request.request_digest(),
            request.marker.as_ref(),
        ));
        self.grants
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::malformed()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsKmsListKeysRecordPage {
    pub keys: Vec<KmsKeySummary>,
    pub next_marker_digest: Option<Digest>,
    pub response_bytes: u64,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consistency: ConsistencyState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsKmsDescribeKeyRecord {
    pub request_digest: Digest,
    pub metadata: KmsKeyMetadata,
    pub key_digest: Digest,
    pub response_bytes: u64,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub receipt: RedactedRequestReceipt,
    pub cost: CostReceipt,
    pub record_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsKmsListKeysRecord {
    pub request_digest: Digest,
    pub pages: Vec<AwsKmsListKeysRecordPage>,
    pub item_count: usize,
    pub complete: bool,
    pub provider_digest: Digest,
    pub receipts: Vec<RedactedRequestReceipt>,
    pub cost: CostReceipt,
    pub record_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsKmsRotationRecord {
    pub request_digest: Digest,
    pub status: RotationStatus,
    pub key_digest: Digest,
    pub response_bytes: u64,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub receipt: RedactedRequestReceipt,
    pub cost: CostReceipt,
    pub record_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsKmsListAliasesRecordPage {
    pub aliases: Vec<KmsAliasSummary>,
    pub next_marker_digest: Option<Digest>,
    pub key_digest: Digest,
    pub response_bytes: u64,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consistency: ConsistencyState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsKmsListAliasesRecord {
    pub request_digest: Digest,
    pub pages: Vec<AwsKmsListAliasesRecordPage>,
    pub item_count: usize,
    pub complete: bool,
    pub provider_digest: Digest,
    pub receipts: Vec<RedactedRequestReceipt>,
    pub cost: CostReceipt,
    pub record_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsKmsListGrantsRecordPage {
    pub grants: Vec<KmsGrantSummary>,
    pub next_marker_digest: Option<Digest>,
    pub key_digest: Digest,
    pub response_bytes: u64,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consistency: ConsistencyState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsKmsListGrantsRecord {
    pub request_digest: Digest,
    pub pages: Vec<AwsKmsListGrantsRecordPage>,
    pub item_count: usize,
    pub complete: bool,
    pub provider_digest: Digest,
    pub receipts: Vec<RedactedRequestReceipt>,
    pub cost: CostReceipt,
    pub record_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AwsKmsReadRecord {
    ListKeys(AwsKmsListKeysRecord),
    DescribeKey(AwsKmsDescribeKeyRecord),
    GetKeyRotationStatus(AwsKmsRotationRecord),
    ListAliases(AwsKmsListAliasesRecord),
    ListGrants(AwsKmsListGrantsRecord),
}

pub type AwsKmsKeyPostureProvider<T = BlockedEnvAwsKmsTransport> = AwsKmsProvider<T>;
pub type GetKeyRotationStatusResponse = RotationStatusResponse;

#[derive(Clone, Debug)]
pub struct AwsKmsProvider<T = BlockedEnvAwsKmsTransport> {
    transport: T,
    definition: AwsKmsProviderDefinition,
    bounds: KmsReadBounds,
}

impl Default for AwsKmsProvider<BlockedEnvAwsKmsTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvAwsKmsTransport)
    }
}

impl<T: AwsKmsTransport> AwsKmsProvider<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            definition: AwsKmsProviderDefinition::new(),
            bounds: KmsReadBounds::default(),
        }
    }

    pub fn with_bounds(transport: T, bounds: KmsReadBounds) -> Self {
        Self {
            transport,
            definition: AwsKmsProviderDefinition::new(),
            bounds,
        }
    }

    pub fn definition(&self) -> &AwsKmsProviderDefinition {
        &self.definition
    }

    pub fn bounds(&self) -> &KmsReadBounds {
        &self.bounds
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn validate(&self) -> Result<(), AwsKmsProviderError> {
        self.definition.validate()?;
        self.bounds.validate()?;
        if self.provenance().connected()
            || self.provenance().native()
            || self.provenance().first_party()
            || self.definition.connected
            || self.definition.native
            || self.definition.first_party
        {
            return Err(AwsKmsProviderError::InvalidDefinition);
        }
        Ok(())
    }

    pub fn list_keys(
        &mut self,
        request: ListKeysRequest,
    ) -> Result<AwsKmsListKeysRecord, AwsKmsProviderError> {
        self.validate_request(
            AwsKmsReadOperation::ListKeys,
            &request.scope_digest,
            &request.permission_digest,
        )?;
        let request_digest = request.request_digest();
        let mut marker = request.marker.clone();
        let mut seen_markers = BTreeSet::new();
        if let Some(value) = &marker {
            seen_markers.insert(value.digest());
        }
        let mut pages = Vec::new();
        let mut receipts = Vec::new();
        let mut seen_keys = BTreeSet::new();
        let mut item_count = 0_usize;
        let mut response_bytes = 0_u64;
        let mut complete = false;

        for page_number in 0..self.bounds.max_pages {
            let page_request = request.with_marker(marker.clone());
            let page_request_digest = page_request.request_digest();
            let page = self
                .transport
                .list_keys(&page_request)
                .map_err(AwsKmsProviderError::Transport)?;
            Self::validate_page(
                &page.scope_digest,
                &page.permission_digest,
                page.consistency,
                &request.scope_digest,
                &request.permission_digest,
            )?;
            self.validate_response_size(page.response_bytes)?;
            if page.keys.len() > usize::from(request.limit) {
                return Err(AwsKmsProviderError::ResponseTooLarge);
            }
            item_count += page.keys.len();
            response_bytes = response_bytes.saturating_add(page.response_bytes);
            if item_count > self.bounds.max_keys || response_bytes > self.bounds.max_response_bytes
            {
                return Err(AwsKmsProviderError::ResponseTooLarge);
            }
            let mut keys = page.keys;
            keys.sort_by_key(KmsKeySummary::key_digest);
            for key in &keys {
                key.validate()?;
                if !seen_keys.insert(key.key_digest()) {
                    return Err(AwsKmsProviderError::DuplicateItem);
                }
            }
            let next_marker = page.next_marker;
            let next_marker_digest = next_marker.as_ref().map(OpaqueMarker::digest);
            receipts.push(Self::receipt(
                AwsKmsReadOperation::ListKeys,
                page_request_digest,
                &keys,
                page.response_bytes,
            ));
            pages.push(AwsKmsListKeysRecordPage {
                keys,
                next_marker_digest,
                response_bytes: page.response_bytes,
                scope_digest: page.scope_digest,
                permission_digest: page.permission_digest,
                consistency: page.consistency,
            });
            if let Some(next) = next_marker {
                if !seen_markers.insert(next.digest()) {
                    return Err(AwsKmsProviderError::MarkerLoop);
                }
                marker = Some(next);
            } else {
                complete = true;
                break;
            }
            if page_number + 1 == self.bounds.max_pages {
                return Err(AwsKmsProviderError::PaginationIncomplete);
            }
        }
        if !complete {
            return Err(AwsKmsProviderError::PaginationIncomplete);
        }
        let cost = CostReceipt::new(receipts.len() as u32, response_bytes);
        let mut record = AwsKmsListKeysRecord {
            request_digest,
            pages,
            item_count,
            complete,
            provider_digest: self.definition.provider_digest.clone(),
            receipts,
            cost,
            record_digest: Digest::zero(),
        };
        record.record_digest = digest_record(&(
            &record.request_digest,
            &record.pages,
            record.item_count,
            record.complete,
            &record.provider_digest,
            &record.receipts,
            &record.cost,
        ));
        Ok(record)
    }

    pub fn describe_key(
        &mut self,
        request: DescribeKeyRequest,
    ) -> Result<AwsKmsDescribeKeyRecord, AwsKmsProviderError> {
        self.validate_request(
            AwsKmsReadOperation::DescribeKey,
            &request.scope_digest,
            &request.permission_digest,
        )?;
        let request_digest = request.request_digest();
        let response = self
            .transport
            .describe_key(&request)
            .map_err(AwsKmsProviderError::Transport)?;
        Self::validate_page(
            &response.scope_digest,
            &response.permission_digest,
            response.metadata.consistency,
            &request.scope_digest,
            &request.permission_digest,
        )?;
        self.validate_response_size(response.response_bytes)?;
        if response.key_digest != request.key.digest()
            || response.metadata.key_id_digest != request.key.key_id_digest()
            || response.metadata.key_arn_digest != request.key.key_arn_digest()
        {
            return Err(AwsKmsProviderError::KeyDrift);
        }
        response.metadata.key_id_digest.validate()?;
        if let Some(arn) = &response.metadata.key_arn_digest {
            arn.validate()?;
        }
        let response_digest = response.metadata.key_digest();
        let receipt = Self::receipt(
            AwsKmsReadOperation::DescribeKey,
            request_digest.clone(),
            &response_digest,
            response.response_bytes,
        );
        let cost = CostReceipt::new(1, response.response_bytes);
        let mut record = AwsKmsDescribeKeyRecord {
            request_digest,
            metadata: response.metadata,
            key_digest: response.key_digest,
            response_bytes: response.response_bytes,
            scope_digest: response.scope_digest,
            permission_digest: response.permission_digest,
            provider_digest: self.definition.provider_digest.clone(),
            receipt,
            cost,
            record_digest: Digest::zero(),
        };
        record.record_digest = digest_record(&(
            &record.request_digest,
            &record.metadata,
            &record.key_digest,
            record.response_bytes,
            &record.scope_digest,
            &record.permission_digest,
            &record.provider_digest,
            &record.receipt,
            &record.cost,
        ));
        Ok(record)
    }

    pub fn get_key_rotation_status(
        &mut self,
        request: GetKeyRotationStatusRequest,
    ) -> Result<AwsKmsRotationRecord, AwsKmsProviderError> {
        self.validate_request(
            AwsKmsReadOperation::GetKeyRotationStatus,
            &request.scope_digest,
            &request.permission_digest,
        )?;
        let request_digest = request.request_digest();
        let response = self
            .transport
            .get_key_rotation_status(&request)
            .map_err(AwsKmsProviderError::Transport)?;
        Self::validate_page(
            &response.scope_digest,
            &response.permission_digest,
            response.status.consistency,
            &request.scope_digest,
            &request.permission_digest,
        )?;
        self.validate_response_size(response.response_bytes)?;
        if response.key_digest != request.key.digest() {
            return Err(AwsKmsProviderError::KeyDrift);
        }
        response.status.validate()?;
        let response_digest = response.status.digest();
        let receipt = Self::receipt(
            AwsKmsReadOperation::GetKeyRotationStatus,
            request_digest.clone(),
            &response_digest,
            response.response_bytes,
        );
        let cost = CostReceipt::new(1, response.response_bytes);
        let mut record = AwsKmsRotationRecord {
            request_digest,
            status: response.status,
            key_digest: response.key_digest,
            response_bytes: response.response_bytes,
            scope_digest: response.scope_digest,
            permission_digest: response.permission_digest,
            provider_digest: self.definition.provider_digest.clone(),
            receipt,
            cost,
            record_digest: Digest::zero(),
        };
        record.record_digest = digest_record(&(
            &record.request_digest,
            &record.status,
            &record.key_digest,
            record.response_bytes,
            &record.scope_digest,
            &record.permission_digest,
            &record.provider_digest,
            &record.receipt,
            &record.cost,
        ));
        Ok(record)
    }

    pub fn list_aliases(
        &mut self,
        request: ListAliasesRequest,
    ) -> Result<AwsKmsListAliasesRecord, AwsKmsProviderError> {
        self.validate_request(
            AwsKmsReadOperation::ListAliases,
            &request.scope_digest,
            &request.permission_digest,
        )?;
        let request_digest = request.request_digest();
        let mut marker = request.marker.clone();
        let mut seen_markers = BTreeSet::new();
        if let Some(value) = &marker {
            seen_markers.insert(value.digest());
        }
        let mut pages = Vec::new();
        let mut receipts = Vec::new();
        let mut seen_aliases = BTreeSet::new();
        let mut item_count = 0_usize;
        let mut response_bytes = 0_u64;
        let mut complete = false;

        for page_number in 0..self.bounds.max_pages {
            let page_request = request.with_marker(marker.clone());
            let page_request_digest = page_request.request_digest();
            let page = self
                .transport
                .list_aliases(&page_request)
                .map_err(AwsKmsProviderError::Transport)?;
            Self::validate_page(
                &page.scope_digest,
                &page.permission_digest,
                page.consistency,
                &request.scope_digest,
                &request.permission_digest,
            )?;
            self.validate_response_size(page.response_bytes)?;
            if page.aliases.len() > usize::from(request.limit) {
                return Err(AwsKmsProviderError::ResponseTooLarge);
            }
            if page.key_digest != request.key.digest() {
                return Err(AwsKmsProviderError::KeyDrift);
            }
            item_count += page.aliases.len();
            response_bytes = response_bytes.saturating_add(page.response_bytes);
            if item_count > self.bounds.max_aliases
                || response_bytes > self.bounds.max_response_bytes
            {
                return Err(AwsKmsProviderError::ResponseTooLarge);
            }
            let mut aliases = page.aliases;
            aliases.sort_by_key(KmsAliasSummary::digest);
            for alias in &aliases {
                alias.validate()?;
                if !seen_aliases.insert(alias.digest()) {
                    return Err(AwsKmsProviderError::DuplicateItem);
                }
            }
            let next_marker = page.next_marker;
            let next_marker_digest = next_marker.as_ref().map(OpaqueMarker::digest);
            receipts.push(Self::receipt(
                AwsKmsReadOperation::ListAliases,
                page_request_digest,
                &aliases,
                page.response_bytes,
            ));
            pages.push(AwsKmsListAliasesRecordPage {
                aliases,
                next_marker_digest,
                key_digest: page.key_digest,
                response_bytes: page.response_bytes,
                scope_digest: page.scope_digest,
                permission_digest: page.permission_digest,
                consistency: page.consistency,
            });
            if let Some(next) = next_marker {
                if !seen_markers.insert(next.digest()) {
                    return Err(AwsKmsProviderError::MarkerLoop);
                }
                marker = Some(next);
            } else {
                complete = true;
                break;
            }
            if page_number + 1 == self.bounds.max_pages {
                return Err(AwsKmsProviderError::PaginationIncomplete);
            }
        }
        if !complete {
            return Err(AwsKmsProviderError::PaginationIncomplete);
        }
        let cost = CostReceipt::new(receipts.len() as u32, response_bytes);
        let mut record = AwsKmsListAliasesRecord {
            request_digest,
            pages,
            item_count,
            complete,
            provider_digest: self.definition.provider_digest.clone(),
            receipts,
            cost,
            record_digest: Digest::zero(),
        };
        record.record_digest = digest_record(&(
            &record.request_digest,
            &record.pages,
            record.item_count,
            record.complete,
            &record.provider_digest,
            &record.receipts,
            &record.cost,
        ));
        Ok(record)
    }

    pub fn list_grants(
        &mut self,
        request: ListGrantsRequest,
    ) -> Result<AwsKmsListGrantsRecord, AwsKmsProviderError> {
        self.validate_request(
            AwsKmsReadOperation::ListGrants,
            &request.scope_digest,
            &request.permission_digest,
        )?;
        let request_digest = request.request_digest();
        let mut marker = request.marker.clone();
        let mut seen_markers = BTreeSet::new();
        if let Some(value) = &marker {
            seen_markers.insert(value.digest());
        }
        let mut pages = Vec::new();
        let mut receipts = Vec::new();
        let mut seen_grants = BTreeSet::new();
        let mut item_count = 0_usize;
        let mut response_bytes = 0_u64;
        let mut complete = false;

        for page_number in 0..self.bounds.max_pages {
            let page_request = request.with_marker(marker.clone());
            let page_request_digest = page_request.request_digest();
            let page = self
                .transport
                .list_grants(&page_request)
                .map_err(AwsKmsProviderError::Transport)?;
            Self::validate_page(
                &page.scope_digest,
                &page.permission_digest,
                page.consistency,
                &request.scope_digest,
                &request.permission_digest,
            )?;
            self.validate_response_size(page.response_bytes)?;
            if page.grants.len() > usize::from(request.limit) {
                return Err(AwsKmsProviderError::ResponseTooLarge);
            }
            if page.key_digest != request.key.digest() {
                return Err(AwsKmsProviderError::KeyDrift);
            }
            item_count += page.grants.len();
            response_bytes = response_bytes.saturating_add(page.response_bytes);
            if item_count > self.bounds.max_grants
                || response_bytes > self.bounds.max_response_bytes
            {
                return Err(AwsKmsProviderError::ResponseTooLarge);
            }
            let mut grants = page.grants;
            grants.sort_by_key(KmsGrantSummary::digest);
            for grant in &grants {
                grant.validate()?;
                if !seen_grants.insert(grant.digest()) {
                    return Err(AwsKmsProviderError::DuplicateItem);
                }
            }
            let next_marker = page.next_marker;
            let next_marker_digest = next_marker.as_ref().map(OpaqueMarker::digest);
            receipts.push(Self::receipt(
                AwsKmsReadOperation::ListGrants,
                page_request_digest,
                &grants,
                page.response_bytes,
            ));
            pages.push(AwsKmsListGrantsRecordPage {
                grants,
                next_marker_digest,
                key_digest: page.key_digest,
                response_bytes: page.response_bytes,
                scope_digest: page.scope_digest,
                permission_digest: page.permission_digest,
                consistency: page.consistency,
            });
            if let Some(next) = next_marker {
                if !seen_markers.insert(next.digest()) {
                    return Err(AwsKmsProviderError::MarkerLoop);
                }
                marker = Some(next);
            } else {
                complete = true;
                break;
            }
            if page_number + 1 == self.bounds.max_pages {
                return Err(AwsKmsProviderError::PaginationIncomplete);
            }
        }
        if !complete {
            return Err(AwsKmsProviderError::PaginationIncomplete);
        }
        let cost = CostReceipt::new(receipts.len() as u32, response_bytes);
        let mut record = AwsKmsListGrantsRecord {
            request_digest,
            pages,
            item_count,
            complete,
            provider_digest: self.definition.provider_digest.clone(),
            receipts,
            cost,
            record_digest: Digest::zero(),
        };
        record.record_digest = digest_record(&(
            &record.request_digest,
            &record.pages,
            record.item_count,
            record.complete,
            &record.provider_digest,
            &record.receipts,
            &record.cost,
        ));
        Ok(record)
    }

    fn validate_request(
        &self,
        operation: AwsKmsReadOperation,
        scope_digest: &Digest,
        permission_digest: &Digest,
    ) -> Result<(), AwsKmsProviderError> {
        self.validate()?;
        if !self.definition.allowlisted_operations.contains(&operation)
            || scope_digest == &Digest::zero()
            || permission_digest == &Digest::zero()
        {
            return Err(AwsKmsProviderError::RequestDrift);
        }
        Ok(())
    }

    fn validate_page(
        page_scope_digest: &Digest,
        page_permission_digest: &Digest,
        consistency: ConsistencyState,
        scope_digest: &Digest,
        permission_digest: &Digest,
    ) -> Result<(), AwsKmsProviderError> {
        if page_scope_digest != scope_digest {
            return Err(AwsKmsProviderError::ScopeDrift);
        }
        if page_permission_digest != permission_digest {
            return Err(AwsKmsProviderError::PermissionLoss);
        }
        if !consistency.is_stable() {
            return Err(AwsKmsProviderError::Partial);
        }
        Ok(())
    }

    fn validate_response_size(&self, bytes: u64) -> Result<(), AwsKmsProviderError> {
        if bytes > self.bounds.max_response_bytes {
            Err(AwsKmsProviderError::ResponseTooLarge)
        } else {
            Ok(())
        }
    }

    fn receipt<S: Serialize>(
        operation: AwsKmsReadOperation,
        request_digest: Digest,
        response: &S,
        response_bytes: u64,
    ) -> RedactedRequestReceipt {
        RedactedRequestReceipt {
            operation,
            request_digest,
            response_digest: digest_record(response),
            response_bytes,
            attempts: 1,
            status: crate::model::ReceiptStatus::BoundedSuccess,
        }
    }
}

fn digest_record<T: Serialize>(value: &T) -> Digest {
    Digest::from_text(serde_json::to_vec(value).expect("redacted KMS record is serializable"))
}

impl AwsKmsListKeysRecord {
    pub fn key_items(&self) -> impl Iterator<Item = &KmsKeySummary> {
        self.pages.iter().flat_map(|page| page.keys.iter())
    }

    pub fn marker_digests(&self) -> Vec<Digest> {
        self.pages
            .iter()
            .filter_map(|page| page.next_marker_digest.clone())
            .collect()
    }

    pub fn verify(&self) -> Result<(), AwsKmsProviderError> {
        if self.pages.is_empty()
            || !self.complete
            || self.item_count != self.pages.iter().map(|page| page.keys.len()).sum::<usize>()
            || self.record_digest
                != digest_record(&(
                    &self.request_digest,
                    &self.pages,
                    self.item_count,
                    self.complete,
                    &self.provider_digest,
                    &self.receipts,
                    &self.cost,
                ))
        {
            Err(AwsKmsProviderError::RecordTampered)
        } else {
            Ok(())
        }
    }
}

impl AwsKmsDescribeKeyRecord {
    pub fn verify(&self) -> Result<(), AwsKmsProviderError> {
        if self.record_digest
            != digest_record(&(
                &self.request_digest,
                &self.metadata,
                &self.key_digest,
                self.response_bytes,
                &self.scope_digest,
                &self.permission_digest,
                &self.provider_digest,
                &self.receipt,
                &self.cost,
            ))
        {
            Err(AwsKmsProviderError::RecordTampered)
        } else {
            Ok(())
        }
    }
}

impl AwsKmsRotationRecord {
    pub fn verify(&self) -> Result<(), AwsKmsProviderError> {
        if self.record_digest
            != digest_record(&(
                &self.request_digest,
                &self.status,
                &self.key_digest,
                self.response_bytes,
                &self.scope_digest,
                &self.permission_digest,
                &self.provider_digest,
                &self.receipt,
                &self.cost,
            ))
        {
            Err(AwsKmsProviderError::RecordTampered)
        } else {
            Ok(())
        }
    }
}

impl AwsKmsListAliasesRecord {
    pub fn alias_items(&self) -> impl Iterator<Item = &KmsAliasSummary> {
        self.pages.iter().flat_map(|page| page.aliases.iter())
    }

    pub fn marker_digests(&self) -> Vec<Digest> {
        self.pages
            .iter()
            .filter_map(|page| page.next_marker_digest.clone())
            .collect()
    }

    pub fn verify(&self) -> Result<(), AwsKmsProviderError> {
        if self.pages.is_empty()
            || !self.complete
            || self.item_count
                != self
                    .pages
                    .iter()
                    .map(|page| page.aliases.len())
                    .sum::<usize>()
            || self.record_digest
                != digest_record(&(
                    &self.request_digest,
                    &self.pages,
                    self.item_count,
                    self.complete,
                    &self.provider_digest,
                    &self.receipts,
                    &self.cost,
                ))
        {
            Err(AwsKmsProviderError::RecordTampered)
        } else {
            Ok(())
        }
    }
}

impl AwsKmsListGrantsRecord {
    pub fn grant_items(&self) -> impl Iterator<Item = &KmsGrantSummary> {
        self.pages.iter().flat_map(|page| page.grants.iter())
    }

    pub fn marker_digests(&self) -> Vec<Digest> {
        self.pages
            .iter()
            .filter_map(|page| page.next_marker_digest.clone())
            .collect()
    }

    pub fn verify(&self) -> Result<(), AwsKmsProviderError> {
        if self.pages.is_empty()
            || !self.complete
            || self.item_count
                != self
                    .pages
                    .iter()
                    .map(|page| page.grants.len())
                    .sum::<usize>()
            || self.record_digest
                != digest_record(&(
                    &self.request_digest,
                    &self.pages,
                    self.item_count,
                    self.complete,
                    &self.provider_digest,
                    &self.receipts,
                    &self.cost,
                ))
        {
            Err(AwsKmsProviderError::RecordTampered)
        } else {
            Ok(())
        }
    }
}

impl AwsKmsReadRecord {
    pub fn operation(&self) -> AwsKmsReadOperation {
        match self {
            Self::ListKeys(_) => AwsKmsReadOperation::ListKeys,
            Self::DescribeKey(_) => AwsKmsReadOperation::DescribeKey,
            Self::GetKeyRotationStatus(_) => AwsKmsReadOperation::GetKeyRotationStatus,
            Self::ListAliases(_) => AwsKmsReadOperation::ListAliases,
            Self::ListGrants(_) => AwsKmsReadOperation::ListGrants,
        }
    }

    pub fn verify(&self) -> Result<(), AwsKmsProviderError> {
        match self {
            Self::ListKeys(record) => record.verify(),
            Self::DescribeKey(record) => record.verify(),
            Self::GetKeyRotationStatus(record) => record.verify(),
            Self::ListAliases(record) => record.verify(),
            Self::ListGrants(record) => record.verify(),
        }
    }
}

// Keep these imports part of the provider's public API without exposing raw
// credential or marker material.
pub use crate::model::ProviderProvenance as ProviderProvenanceAlias;
pub type NonZeroPageCount = NonZeroU16;
pub type KeyPostureScope = AwsKmsScope;
pub type KeyPosturePermissionFence = PermissionFence;
