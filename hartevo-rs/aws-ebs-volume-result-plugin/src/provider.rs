//! Provider and transport seams for bounded, read-only EC2 EBS calls.

use std::{collections::VecDeque, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};
use zeroize::Zeroize;

use crate::error::{AwsEbsTransportError, AwsEbsVolumeError, Result};
use crate::model::AwsEbsOperation::{
    DescribeFastSnapshotRestores, DescribeSnapshots, DescribeVolumeStatus, DescribeVolumes,
};
use crate::model::{
    AttachmentObservation, AttachmentState, AwsEbsOperation, AwsEbsVolumeScope, Digest,
    FastSnapshotRestoreInput, FastSnapshotRestoreState, PageCursor, SnapshotMetadataInput,
    SnapshotState, SnapshotStorageTier, TransportProvenance, VolumeMetadataInput, VolumeState,
    VolumeStatusInput, VolumeStatusState, VolumeType, validate_observation_time,
    validate_page_size, validate_response_bounds,
};
use crate::{
    API_REVISION, CONTRACT_DIGEST, CONTRACT_VERSION, EVIDENCE_SCHEMA_DIGEST, PLUGIN_VERSION,
    PROVIDER_ID,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestFence {
    operation: AwsEbsOperation,
    scope_digest: Digest,
    volume_allowlist_digest: Digest,
    snapshot_allowlist_digest: Digest,
    filter_digest: Digest,
    max_results: u16,
    observed_at: i64,
    cursor: Option<PageCursor>,
}

impl RequestFence {
    pub fn new(
        operation: AwsEbsOperation,
        scope: &AwsEbsVolumeScope,
        max_results: u16,
        cursor: Option<PageCursor>,
        observed_at: i64,
    ) -> Result<Self> {
        validate_page_size(max_results)?;
        validate_observation_time(observed_at)?;
        let filter_digest = filter_digest(operation, scope);
        if let Some(cursor) = &cursor {
            cursor.validate_against(operation, scope, &filter_digest)?;
        }
        Ok(Self {
            operation,
            scope_digest: scope.digest(),
            volume_allowlist_digest: scope.volume_allowlist_digest(),
            snapshot_allowlist_digest: scope.snapshot_allowlist_digest(),
            filter_digest,
            max_results,
            observed_at,
            cursor,
        })
    }

    fn from_existing(
        operation: AwsEbsOperation,
        scope_digest: Digest,
        volume_allowlist_digest: Digest,
        snapshot_allowlist_digest: Digest,
        filter_digest: Digest,
        max_results: u16,
        observed_at: i64,
        cursor: Option<PageCursor>,
    ) -> Self {
        Self {
            operation,
            scope_digest,
            volume_allowlist_digest,
            snapshot_allowlist_digest,
            filter_digest,
            max_results,
            observed_at,
            cursor,
        }
    }

    pub fn operation(&self) -> AwsEbsOperation {
        self.operation
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn volume_allowlist_digest(&self) -> &Digest {
        &self.volume_allowlist_digest
    }

    pub fn snapshot_allowlist_digest(&self) -> &Digest {
        &self.snapshot_allowlist_digest
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub const fn max_results(&self) -> u16 {
        self.max_results
    }

    pub const fn observed_at(&self) -> i64 {
        self.observed_at
    }

    pub fn cursor(&self) -> Option<&PageCursor> {
        self.cursor.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-ebs-request-fence/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "volume_allowlist",
                    self.volume_allowlist_digest.as_str().to_owned(),
                ),
                (
                    "snapshot_allowlist",
                    self.snapshot_allowlist_digest.as_str().to_owned(),
                ),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("max_results", self.max_results.to_string()),
                ("observed_at", self.observed_at.to_string()),
                (
                    "cursor",
                    self.cursor.as_ref().map_or_else(String::new, |value| {
                        value.token_digest().as_str().to_owned()
                    }),
                ),
            ],
        )
    }

    fn next_cursor(&self, opaque_token: impl Into<String>) -> Result<PageCursor> {
        let next_page = self
            .cursor
            .as_ref()
            .map_or(2, |cursor| cursor.page_number().saturating_add(1));
        if next_page > crate::MAX_PAGES {
            return Err(AwsEbsVolumeError::PartialEvidence);
        }
        PageCursor::from_fence(
            opaque_token,
            self.operation,
            self.scope_digest.clone(),
            self.volume_allowlist_digest.clone(),
            self.snapshot_allowlist_digest.clone(),
            self.filter_digest.clone(),
            next_page,
        )
    }

    fn validate(&self) -> Result<()> {
        validate_page_size(self.max_results)?;
        validate_observation_time(self.observed_at)?;
        if let Some(cursor) = &self.cursor {
            if cursor.operation() != self.operation
                || cursor.scope_digest() != &self.scope_digest
                || cursor.volume_allowlist_digest() != &self.volume_allowlist_digest
                || cursor.snapshot_allowlist_digest() != &self.snapshot_allowlist_digest
                || cursor.filter_digest() != &self.filter_digest
            {
                return Err(AwsEbsVolumeError::CursorMismatch);
            }
        }
        Ok(())
    }
}

impl Serialize for RequestFence {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("RequestFence", 8)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("volumeAllowlistDigest", &self.volume_allowlist_digest)?;
        state.serialize_field("snapshotAllowlistDigest", &self.snapshot_allowlist_digest)?;
        state.serialize_field("filterDigest", &self.filter_digest)?;
        state.serialize_field("maxResults", &self.max_results)?;
        state.serialize_field("observedAt", &self.observed_at)?;
        state.serialize_field("cursor", &self.cursor)?;
        state.end()
    }
}

pub fn filter_digest(operation: AwsEbsOperation, scope: &AwsEbsVolumeScope) -> Digest {
    Digest::from_parts(
        "aws-ebs-filter/v1",
        &[
            ("operation", operation.as_str().to_owned()),
            ("account", scope.account().digest().as_str().to_owned()),
            ("region", scope.region().digest().as_str().to_owned()),
            (
                "volume_allowlist",
                scope.volume_allowlist_digest().as_str().to_owned(),
            ),
            (
                "snapshot_allowlist",
                scope.snapshot_allowlist_digest().as_str().to_owned(),
            ),
            ("scope", scope.digest().as_str().to_owned()),
            ("include_managed_resources", "false".to_owned()),
        ],
    )
}

macro_rules! request_type {
    (
        $name:ident,
        $id_type:ty,
        $ids:ident,
        $operation:expr,
        $allow_empty:expr,
        $allowlist_domain:literal
    ) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            pub $ids: Vec<$id_type>,
            fence: RequestFence,
        }

        impl $name {
            pub fn for_scope(
                scope: &AwsEbsVolumeScope,
                max_results: u16,
                cursor: Option<PageCursor>,
                observed_at: i64,
            ) -> Result<Self> {
                let request = Self {
                    $ids: scope.$ids(),
                    fence: RequestFence::new($operation, scope, max_results, cursor, observed_at)?,
                };
                request.validate()?;
                Ok(request)
            }

            pub fn with_cursor(&self, cursor: Option<PageCursor>) -> Result<Self> {
                let fence = RequestFence::from_existing(
                    self.fence.operation,
                    self.fence.scope_digest.clone(),
                    self.fence.volume_allowlist_digest.clone(),
                    self.fence.snapshot_allowlist_digest.clone(),
                    self.fence.filter_digest.clone(),
                    self.fence.max_results,
                    self.fence.observed_at,
                    cursor,
                );
                let request = Self {
                    $ids: self.$ids.clone(),
                    fence,
                };
                request.validate()?;
                Ok(request)
            }

            pub fn operation(&self) -> AwsEbsOperation {
                self.fence.operation()
            }

            pub fn fence(&self) -> &RequestFence {
                &self.fence
            }

            pub fn cursor(&self) -> Option<&PageCursor> {
                self.fence.cursor()
            }

            pub fn request_digest(&self) -> Digest {
                Digest::from_parts(
                    "aws-ebs-request/v1",
                    &[
                        ("fence", self.fence.digest().as_str().to_owned()),
                        (
                            "ids",
                            self.$ids
                                .iter()
                                .map(|value| value.digest().as_str().to_owned())
                                .collect::<Vec<_>>()
                                .join("\n"),
                        ),
                    ],
                )
            }

            pub fn allowlist_digest(&self) -> Digest {
                Digest::from_parts(
                    $allowlist_domain,
                    &[(
                        "ids",
                        self.$ids
                            .iter()
                            .map(|value| value.digest().as_str().to_owned())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    )],
                )
            }

            fn validate(&self) -> Result<()> {
                self.fence.validate()?;
                if ((!$allow_empty && self.$ids.is_empty())
                    || self.$ids.len() > crate::model::MAX_POSTURE_ITEMS
                    || self.$ids.windows(2).any(|pair| pair[0] >= pair[1]))
                {
                    return Err(AwsEbsVolumeError::InvalidRequest);
                }
                Ok(())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                let mut state = serializer.serialize_struct(stringify!($name), 3)?;
                state.serialize_field("operation", &self.operation())?;
                state.serialize_field("fence", &self.fence)?;
                state.serialize_field(
                    "idDigests",
                    &self
                        .$ids
                        .iter()
                        .map(|value| value.digest())
                        .collect::<Vec<_>>(),
                )?;
                state.end()
            }
        }
    };
}

request_type!(
    DescribeVolumesRequest,
    crate::model::VolumeId,
    volume_allowlist,
    DescribeVolumes,
    false,
    "aws-ebs-volume-allowlist/v1"
);
request_type!(
    DescribeVolumeStatusRequest,
    crate::model::VolumeId,
    volume_allowlist,
    DescribeVolumeStatus,
    false,
    "aws-ebs-volume-allowlist/v1"
);
request_type!(
    DescribeSnapshotsRequest,
    crate::model::SnapshotId,
    snapshot_allowlist,
    DescribeSnapshots,
    true,
    "aws-ebs-snapshot-allowlist/v1"
);
request_type!(
    DescribeFastSnapshotRestoresRequest,
    crate::model::SnapshotId,
    snapshot_allowlist,
    DescribeFastSnapshotRestores,
    true,
    "aws-ebs-snapshot-allowlist/v1"
);

macro_rules! response_type {
    ($name:ident, $request:ty, $item:ty, $items:ident, $operation:expr, $request_ids:ident, $id:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            pub scope_digest: Digest,
            pub request_digest: Digest,
            pub $items: Vec<$item>,
            pub next_cursor: Option<PageCursor>,
            pub response_bytes: u64,
            pub provenance: TransportProvenance,
            pub read_digest: Digest,
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                let mut state = serializer.serialize_struct(stringify!($name), 7)?;
                state.serialize_field("scopeDigest", &self.scope_digest)?;
                state.serialize_field("requestDigest", &self.request_digest)?;
                state.serialize_field(
                    "itemResourceDigests",
                    &self
                        .$items
                        .iter()
                        .map(|item| item.resource_digest.clone())
                        .collect::<Vec<_>>(),
                )?;
                state.serialize_field("nextCursor", &self.next_cursor)?;
                state.serialize_field("responseBytes", &self.response_bytes)?;
                state.serialize_field("provenance", &self.provenance)?;
                state.serialize_field("readDigest", &self.read_digest)?;
                state.end()
            }
        }

        impl $name {
            pub fn new(
                request: &$request,
                items: Vec<$item>,
                opaque_next_token: Option<String>,
                response_bytes: u64,
                provenance: TransportProvenance,
            ) -> Result<Self> {
                validate_response_bounds(response_bytes, items.len())?;
                let next_cursor = opaque_next_token
                    .map(|token| request.fence.next_cursor(token))
                    .transpose()?;
                let read_digest = read_digest(
                    $operation,
                    &request.request_digest(),
                    items.iter().map(|item| item.resource_digest.clone()),
                    next_cursor.as_ref(),
                );
                Ok(Self {
                    scope_digest: request.fence.scope_digest.clone(),
                    request_digest: request.request_digest(),
                    $items: items,
                    next_cursor,
                    response_bytes,
                    provenance,
                    read_digest,
                })
            }

            pub fn validate_against(&self, request: &$request) -> Result<()> {
                request.validate()?;
                if self.scope_digest != *request.fence.scope_digest()
                    || self.request_digest != request.request_digest()
                {
                    return Err(AwsEbsVolumeError::ScopeMismatch);
                }
                validate_response_bounds(self.response_bytes, self.$items.len())?;
                let mut seen = std::collections::BTreeSet::new();
                for item in &self.$items {
                    if !request.$request_ids.contains(&item.$id) || !seen.insert(item.$id.clone()) {
                        return Err(AwsEbsVolumeError::VolumeAllowlistMismatch);
                    }
                }
                if let Some(cursor) = &self.next_cursor {
                    cursor.validate_against_request(&request.fence)?;
                }
                let expected = read_digest(
                    $operation,
                    &request.request_digest(),
                    self.$items.iter().map(|item| item.resource_digest.clone()),
                    self.next_cursor.as_ref(),
                );
                if self.read_digest != expected {
                    return Err(AwsEbsVolumeError::TamperedEvidence);
                }
                Ok(())
            }
        }
    };
}

impl PageCursor {
    fn from_fence(
        opaque_token: impl Into<String>,
        operation: AwsEbsOperation,
        scope_digest: Digest,
        volume_allowlist_digest: Digest,
        snapshot_allowlist_digest: Digest,
        filter_digest: Digest,
        page_number: u16,
    ) -> Result<Self> {
        let mut token = opaque_token.into();
        if token.is_empty()
            || token.len() > crate::MAX_IDENTIFIER_BYTES
            || token.trim() != token
            || token.chars().any(char::is_control)
            || !(2..=crate::MAX_PAGES).contains(&page_number)
        {
            token.zeroize();
            return Err(AwsEbsVolumeError::InvalidRequest);
        }
        let token_digest =
            Digest::from_parts("aws-ebs-opaque-next-token/v1", &[("token", token.clone())]);
        token.zeroize();
        Ok(Self {
            operation,
            scope_digest,
            volume_allowlist_digest,
            snapshot_allowlist_digest,
            filter_digest,
            token_digest,
            page_number,
        })
    }

    fn validate_against_request(&self, request: &RequestFence) -> Result<()> {
        if self.operation != request.operation
            || self.scope_digest != request.scope_digest
            || self.volume_allowlist_digest != request.volume_allowlist_digest
            || self.snapshot_allowlist_digest != request.snapshot_allowlist_digest
            || self.filter_digest != request.filter_digest
            || self.page_number
                != request
                    .cursor
                    .as_ref()
                    .map_or(2, |cursor| cursor.page_number().saturating_add(1))
        {
            return Err(AwsEbsVolumeError::CursorMismatch);
        }
        Ok(())
    }
}

fn read_digest<I>(
    operation: AwsEbsOperation,
    request_digest: &Digest,
    resource_digests: I,
    cursor: Option<&PageCursor>,
) -> Digest
where
    I: IntoIterator<Item = Digest>,
{
    let resources = resource_digests
        .into_iter()
        .map(|digest| digest.as_str().to_owned())
        .collect::<Vec<_>>()
        .join("\n");
    Digest::from_parts(
        "aws-ebs-read-page/v1",
        &[
            ("operation", operation.as_str().to_owned()),
            ("request", request_digest.as_str().to_owned()),
            ("resources", resources),
            (
                "cursor",
                cursor.map_or_else(String::new, |value| {
                    value.token_digest().as_str().to_owned()
                }),
            ),
        ],
    )
}

response_type!(
    DescribeVolumesResponse,
    DescribeVolumesRequest,
    VolumeMetadataInput,
    volume_metadata,
    DescribeVolumes,
    volume_allowlist,
    volume_id
);
response_type!(
    DescribeVolumeStatusResponse,
    DescribeVolumeStatusRequest,
    VolumeStatusInput,
    volume_status,
    DescribeVolumeStatus,
    volume_allowlist,
    volume_id
);
response_type!(
    DescribeSnapshotsResponse,
    DescribeSnapshotsRequest,
    SnapshotMetadataInput,
    snapshots,
    DescribeSnapshots,
    snapshot_allowlist,
    snapshot_id
);
response_type!(
    DescribeFastSnapshotRestoresResponse,
    DescribeFastSnapshotRestoresRequest,
    FastSnapshotRestoreInput,
    fast_snapshot_restores,
    DescribeFastSnapshotRestores,
    snapshot_allowlist,
    snapshot_id
);

pub trait AwsEbsTransport {
    fn describe_volumes(
        &mut self,
        request: &DescribeVolumesRequest,
    ) -> std::result::Result<DescribeVolumesResponse, AwsEbsTransportError>;

    fn describe_volume_status(
        &mut self,
        request: &DescribeVolumeStatusRequest,
    ) -> std::result::Result<DescribeVolumeStatusResponse, AwsEbsTransportError>;

    fn describe_snapshots(
        &mut self,
        request: &DescribeSnapshotsRequest,
    ) -> std::result::Result<DescribeSnapshotsResponse, AwsEbsTransportError>;

    fn describe_fast_snapshot_restores(
        &mut self,
        request: &DescribeFastSnapshotRestoresRequest,
    ) -> std::result::Result<DescribeFastSnapshotRestoresResponse, AwsEbsTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsEbsProviderDefinition {
    pub provider_id: String,
    pub api_revision: String,
    pub provider_revision: u64,
    pub provider_release: String,
    pub provider_digest: Digest,
    pub evidence_schema_digest: Digest,
}

impl Default for AwsEbsProviderDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsEbsProviderDefinition {
    pub fn new() -> Self {
        let evidence_schema_digest = Digest::parse(EVIDENCE_SCHEMA_DIGEST.to_owned())
            .expect("frozen EBS evidence schema digest");
        let provider_digest = Digest::from_parts(
            "aws-ebs-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("api_revision", API_REVISION.to_owned()),
                ("provider_revision", "1".to_owned()),
                ("provider_release", PLUGIN_VERSION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("contract_digest", CONTRACT_DIGEST.to_owned()),
                (
                    "evidence_schema_digest",
                    evidence_schema_digest.as_str().to_owned(),
                ),
            ],
        );
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            api_revision: API_REVISION.to_owned(),
            provider_revision: 1,
            provider_release: PLUGIN_VERSION.to_owned(),
            provider_digest,
            evidence_schema_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.api_revision != API_REVISION
            || self.provider_revision == 0
            || self.provider_release != PLUGIN_VERSION
            || self.provider_digest != Self::new().provider_digest
            || self.evidence_schema_digest.as_str() != EVIDENCE_SCHEMA_DIGEST
        {
            return Err(AwsEbsVolumeError::ProviderDrift);
        }
        Ok(())
    }
}

pub struct AwsEbsProvider<T = BlockedEnvTransport> {
    definition: AwsEbsProviderDefinition,
    transport: T,
}

impl<T> fmt::Debug for AwsEbsProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEbsProvider")
            .field("definition", &self.definition)
            .field("transport", &"opaque")
            .finish()
    }
}

impl Default for AwsEbsProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport)
    }
}

impl<T: AwsEbsTransport> AwsEbsProvider<T> {
    pub fn new(transport: T) -> Self {
        Self {
            definition: AwsEbsProviderDefinition::new(),
            transport,
        }
    }

    pub fn with_definition(transport: T, definition: AwsEbsProviderDefinition) -> Result<Self> {
        definition.validate()?;
        Ok(Self {
            definition,
            transport,
        })
    }

    pub fn definition(&self) -> &AwsEbsProviderDefinition {
        &self.definition
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn describe_volumes(
        &mut self,
        request: &DescribeVolumesRequest,
    ) -> Result<DescribeVolumesResponse> {
        request.validate()?;
        let response = self.transport.describe_volumes(request)?;
        response.validate_against(request)?;
        Ok(response)
    }

    pub fn describe_volume_status(
        &mut self,
        request: &DescribeVolumeStatusRequest,
    ) -> Result<DescribeVolumeStatusResponse> {
        request.validate()?;
        let response = self.transport.describe_volume_status(request)?;
        response.validate_against(request)?;
        Ok(response)
    }

    pub fn describe_snapshots(
        &mut self,
        request: &DescribeSnapshotsRequest,
    ) -> Result<DescribeSnapshotsResponse> {
        request.validate()?;
        let response = self.transport.describe_snapshots(request)?;
        response.validate_against(request)?;
        Ok(response)
    }

    pub fn describe_fast_snapshot_restores(
        &mut self,
        request: &DescribeFastSnapshotRestoresRequest,
    ) -> Result<DescribeFastSnapshotRestoresResponse> {
        request.validate()?;
        let response = self.transport.describe_fast_snapshot_restores(request)?;
        response.validate_against(request)?;
        Ok(response)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportCall {
    pub operation: AwsEbsOperation,
    pub request_digest: Digest,
    pub cursor_digest: Option<Digest>,
}

#[derive(Debug, Default)]
pub struct RecordingTransport {
    volume_responses: VecDeque<std::result::Result<DescribeVolumesResponse, AwsEbsTransportError>>,
    status_responses:
        VecDeque<std::result::Result<DescribeVolumeStatusResponse, AwsEbsTransportError>>,
    snapshot_responses:
        VecDeque<std::result::Result<DescribeSnapshotsResponse, AwsEbsTransportError>>,
    fast_restore_responses:
        VecDeque<std::result::Result<DescribeFastSnapshotRestoresResponse, AwsEbsTransportError>>,
    calls: Vec<TransportCall>,
}

impl RecordingTransport {
    pub fn push_volumes_response(
        &mut self,
        response: std::result::Result<DescribeVolumesResponse, AwsEbsTransportError>,
    ) {
        self.volume_responses.push_back(response);
    }

    pub fn push_volume_status_response(
        &mut self,
        response: std::result::Result<DescribeVolumeStatusResponse, AwsEbsTransportError>,
    ) {
        self.status_responses.push_back(response);
    }

    pub fn push_snapshots_response(
        &mut self,
        response: std::result::Result<DescribeSnapshotsResponse, AwsEbsTransportError>,
    ) {
        self.snapshot_responses.push_back(response);
    }

    pub fn push_fast_snapshot_restores_response(
        &mut self,
        response: std::result::Result<DescribeFastSnapshotRestoresResponse, AwsEbsTransportError>,
    ) {
        self.fast_restore_responses.push_back(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }

    fn record_call(&mut self, operation: AwsEbsOperation, request: &RequestFence) {
        self.calls.push(TransportCall {
            operation,
            request_digest: request.digest(),
            cursor_digest: request.cursor().map(|cursor| cursor.token_digest().clone()),
        });
    }
}

impl AwsEbsTransport for RecordingTransport {
    fn describe_volumes(
        &mut self,
        request: &DescribeVolumesRequest,
    ) -> std::result::Result<DescribeVolumesResponse, AwsEbsTransportError> {
        self.record_call(AwsEbsOperation::DescribeVolumes, request.fence());
        self.volume_responses
            .pop_front()
            .unwrap_or(Err(AwsEbsTransportError::InvalidResponse))
    }

    fn describe_volume_status(
        &mut self,
        request: &DescribeVolumeStatusRequest,
    ) -> std::result::Result<DescribeVolumeStatusResponse, AwsEbsTransportError> {
        self.record_call(AwsEbsOperation::DescribeVolumeStatus, request.fence());
        self.status_responses
            .pop_front()
            .unwrap_or(Err(AwsEbsTransportError::InvalidResponse))
    }

    fn describe_snapshots(
        &mut self,
        request: &DescribeSnapshotsRequest,
    ) -> std::result::Result<DescribeSnapshotsResponse, AwsEbsTransportError> {
        self.record_call(AwsEbsOperation::DescribeSnapshots, request.fence());
        self.snapshot_responses
            .pop_front()
            .unwrap_or(Err(AwsEbsTransportError::InvalidResponse))
    }

    fn describe_fast_snapshot_restores(
        &mut self,
        request: &DescribeFastSnapshotRestoresRequest,
    ) -> std::result::Result<DescribeFastSnapshotRestoresResponse, AwsEbsTransportError> {
        self.record_call(
            AwsEbsOperation::DescribeFastSnapshotRestores,
            request.fence(),
        );
        self.fast_restore_responses
            .pop_front()
            .unwrap_or(Err(AwsEbsTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsEbsVolumeScope,
    observed_at: i64,
    provenance: TransportProvenance,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsEbsVolumeScope, observed_at: i64) -> Result<Self> {
        validate_observation_time(observed_at)?;
        Ok(Self {
            scope: scope.clone(),
            observed_at,
            provenance: TransportProvenance::Fixture,
        })
    }

    fn volume(&self, request: &DescribeVolumesRequest) -> Result<VolumeMetadataInput> {
        let volume_id = request
            .volume_allowlist
            .first()
            .cloned()
            .ok_or(AwsEbsVolumeError::InvalidRequest)?;
        let snapshot_id = self.scope.snapshot_allowlist().first().cloned();
        let attachments = self
            .scope
            .attachment_allowlist()
            .first()
            .cloned()
            .map(|instance_id| {
                AttachmentObservation::new(
                    instance_id,
                    AttachmentState::Attached,
                    Some(self.observed_at.saturating_sub(600)),
                    false,
                )
            })
            .transpose()?;
        VolumeMetadataInput::new(
            volume_id,
            snapshot_id,
            VolumeState::InUse,
            VolumeType::Gp3,
            100,
            true,
            false,
            self.observed_at.saturating_sub(86_400),
            attachments.into_iter().collect(),
            self.observed_at,
        )
    }

    fn snapshot(&self, request: &DescribeSnapshotsRequest) -> Result<SnapshotMetadataInput> {
        let snapshot_id = request
            .snapshot_allowlist
            .first()
            .cloned()
            .ok_or(AwsEbsVolumeError::InvalidRequest)?;
        SnapshotMetadataInput::new(
            snapshot_id,
            self.scope.volume_allowlist().first().cloned(),
            SnapshotState::Completed,
            self.observed_at.saturating_sub(86_400),
            Some(self.observed_at.saturating_sub(86_000)),
            self.scope.account().clone(),
            true,
            SnapshotStorageTier::Standard,
            self.observed_at,
        )
    }
}

impl AwsEbsTransport for FixtureTransport {
    fn describe_volumes(
        &mut self,
        request: &DescribeVolumesRequest,
    ) -> std::result::Result<DescribeVolumesResponse, AwsEbsTransportError> {
        let item = self
            .volume(request)
            .map_err(|_| AwsEbsTransportError::InvalidResponse)?;
        DescribeVolumesResponse::new(request, vec![item], None, 512, self.provenance.clone())
            .map_err(|_| AwsEbsTransportError::InvalidResponse)
    }

    fn describe_volume_status(
        &mut self,
        request: &DescribeVolumeStatusRequest,
    ) -> std::result::Result<DescribeVolumeStatusResponse, AwsEbsTransportError> {
        let volume_request = DescribeVolumesRequest::for_scope(
            &self.scope,
            request.fence.max_results,
            None,
            request.fence.observed_at,
        )
        .map_err(|_| AwsEbsTransportError::InvalidResponse)?;
        let volume = self
            .volume(&volume_request)
            .map_err(|_| AwsEbsTransportError::InvalidResponse)?;
        let status = VolumeStatusInput::new(
            request
                .volume_allowlist
                .first()
                .cloned()
                .ok_or(AwsEbsTransportError::InvalidResponse)?,
            "us-east-1a",
            VolumeStatusState::Ok,
            vec![("io-enabled".to_owned(), "passed".to_owned())],
            Vec::new(),
            Vec::new(),
            self.observed_at,
            volume.resource_digest,
        )
        .map_err(|_| AwsEbsTransportError::InvalidResponse)?;
        DescribeVolumeStatusResponse::new(request, vec![status], None, 512, self.provenance.clone())
            .map_err(|_| AwsEbsTransportError::InvalidResponse)
    }

    fn describe_snapshots(
        &mut self,
        request: &DescribeSnapshotsRequest,
    ) -> std::result::Result<DescribeSnapshotsResponse, AwsEbsTransportError> {
        if request.snapshot_allowlist.is_empty() {
            return DescribeSnapshotsResponse::new(
                request,
                Vec::new(),
                None,
                128,
                self.provenance.clone(),
            )
            .map_err(|_| AwsEbsTransportError::InvalidResponse);
        }
        let item = self
            .snapshot(request)
            .map_err(|_| AwsEbsTransportError::InvalidResponse)?;
        DescribeSnapshotsResponse::new(request, vec![item], None, 512, self.provenance.clone())
            .map_err(|_| AwsEbsTransportError::InvalidResponse)
    }

    fn describe_fast_snapshot_restores(
        &mut self,
        request: &DescribeFastSnapshotRestoresRequest,
    ) -> std::result::Result<DescribeFastSnapshotRestoresResponse, AwsEbsTransportError> {
        let items = request
            .snapshot_allowlist
            .first()
            .cloned()
            .map(|snapshot_id| {
                FastSnapshotRestoreInput::new(
                    snapshot_id,
                    "us-east-1a",
                    FastSnapshotRestoreState::Enabled,
                    self.scope.account().clone(),
                    self.observed_at,
                )
            })
            .transpose()
            .map_err(|_| AwsEbsTransportError::InvalidResponse)?
            .into_iter()
            .collect();
        DescribeFastSnapshotRestoresResponse::new(
            request,
            items,
            None,
            256,
            self.provenance.clone(),
        )
        .map_err(|_| AwsEbsTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport(FixtureTransport);

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsEbsVolumeScope, observed_at: i64) -> Result<Self> {
        let mut fixture = FixtureTransport::for_scope(scope, observed_at)?;
        fixture.provenance = TransportProvenance::Loopback;
        Ok(Self(fixture))
    }
}

impl AwsEbsTransport for LoopbackTransport {
    fn describe_volumes(
        &mut self,
        request: &DescribeVolumesRequest,
    ) -> std::result::Result<DescribeVolumesResponse, AwsEbsTransportError> {
        self.0.describe_volumes(request)
    }

    fn describe_volume_status(
        &mut self,
        request: &DescribeVolumeStatusRequest,
    ) -> std::result::Result<DescribeVolumeStatusResponse, AwsEbsTransportError> {
        self.0.describe_volume_status(request)
    }

    fn describe_snapshots(
        &mut self,
        request: &DescribeSnapshotsRequest,
    ) -> std::result::Result<DescribeSnapshotsResponse, AwsEbsTransportError> {
        self.0.describe_snapshots(request)
    }

    fn describe_fast_snapshot_restores(
        &mut self,
        request: &DescribeFastSnapshotRestoresRequest,
    ) -> std::result::Result<DescribeFastSnapshotRestoresResponse, AwsEbsTransportError> {
        self.0.describe_fast_snapshot_restores(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsEbsTransport for BlockedEnvTransport {
    fn describe_volumes(
        &mut self,
        _request: &DescribeVolumesRequest,
    ) -> std::result::Result<DescribeVolumesResponse, AwsEbsTransportError> {
        Err(AwsEbsTransportError::BlockedEnv)
    }

    fn describe_volume_status(
        &mut self,
        _request: &DescribeVolumeStatusRequest,
    ) -> std::result::Result<DescribeVolumeStatusResponse, AwsEbsTransportError> {
        Err(AwsEbsTransportError::BlockedEnv)
    }

    fn describe_snapshots(
        &mut self,
        _request: &DescribeSnapshotsRequest,
    ) -> std::result::Result<DescribeSnapshotsResponse, AwsEbsTransportError> {
        Err(AwsEbsTransportError::BlockedEnv)
    }

    fn describe_fast_snapshot_restores(
        &mut self,
        _request: &DescribeFastSnapshotRestoresRequest,
    ) -> std::result::Result<DescribeFastSnapshotRestoresResponse, AwsEbsTransportError> {
        Err(AwsEbsTransportError::BlockedEnv)
    }
}
