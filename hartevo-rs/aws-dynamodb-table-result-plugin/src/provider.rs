//! Bounded, non-native DynamoDB provider seams.
//!
//! A transport can only be recording, fixture, loopback, or BLOCKED_ENV. No
//! transport in this crate resolves credentials or performs live HTTPS.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};

use crate::error::AwsDynamoDbTransportError;
use crate::model::{
    AwsDynamoDbTableScope, BackupPosture, Digest, EventualConsistencyFence, OpaquePageToken,
    ReadBounds, TablePosture, TableSummary, TagKeyPosture, TransportProvenance, TtlPosture,
};
use crate::{
    CONTRACT_VERSION, LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, PLUGIN_VERSION,
    PROVIDER_API_REVISION, PROVIDER_ID,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsDynamoDbOperation {
    ListTables,
    DescribeTable,
    DescribeContinuousBackups,
    DescribeTimeToLive,
    ListTagsOfResource,
}

impl AwsDynamoDbOperation {
    pub const ALL: [Self; 5] = [
        Self::ListTables,
        Self::DescribeTable,
        Self::DescribeContinuousBackups,
        Self::DescribeTimeToLive,
        Self::ListTagsOfResource,
    ];

    pub const fn permission(self) -> &'static str {
        match self {
            Self::ListTables => "dynamodb:ListTables",
            Self::DescribeTable => "dynamodb:DescribeTable",
            Self::DescribeContinuousBackups => "dynamodb:DescribeContinuousBackups",
            Self::DescribeTimeToLive => "dynamodb:DescribeTimeToLive",
            Self::ListTagsOfResource => "dynamodb:ListTagsOfResource",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsDynamoDbOperation,
    pub scope_digest: Digest,
    pub table_digest: Digest,
    pub allowlist_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListTablesRequest {
    scope: AwsDynamoDbTableScope,
    bounds: ReadBounds,
    cursor: Option<OpaquePageToken>,
    request_digest: Digest,
}

impl ListTablesRequest {
    pub fn new(
        scope: &AwsDynamoDbTableScope,
        bounds: ReadBounds,
        cursor: Option<OpaquePageToken>,
    ) -> crate::error::Result<Self> {
        scope.validate()?;
        bounds.validate()?;
        let expected_page = cursor.as_ref().map_or(1, OpaquePageToken::page_number);
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, expected_page)?;
        }
        let request_digest = Digest::from_parts(
            "aws-dynamodb-list-tables-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("table", scope.table_digest().as_str().to_owned()),
                ("allowlist", scope.allowlist_digest().as_str().to_owned()),
                ("pages", bounds.max_pages.to_string()),
                ("size", bounds.page_size.to_string()),
                (
                    "cursor",
                    cursor.as_ref().map_or_else(String::new, |value| {
                        value.token_digest().as_str().to_owned()
                    }),
                ),
                ("page", expected_page.to_string()),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            bounds,
            cursor,
            request_digest,
        })
    }

    pub fn for_scope(scope: &AwsDynamoDbTableScope) -> crate::error::Result<Self> {
        Self::new(scope, ReadBounds::layer1(), None)
    }

    pub fn scope(&self) -> &AwsDynamoDbTableScope {
        &self.scope
    }

    pub const fn bounds(&self) -> ReadBounds {
        self.bounds
    }

    pub fn cursor(&self) -> Option<&OpaquePageToken> {
        self.cursor.as_ref()
    }

    pub const fn page_number(&self) -> u16 {
        match &self.cursor {
            Some(cursor) => cursor.page_number(),
            None => 1,
        }
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsDynamoDbOperation::ListTables,
            scope_digest: self.scope.digest(),
            table_digest: self.scope.table_digest(),
            allowlist_digest: self.scope.allowlist_digest().clone(),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: self.request_digest.clone(),
        }
    }
}

impl fmt::Debug for ListTablesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListTablesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("bounds", &self.bounds)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

macro_rules! describe_request {
    ($name:ident, $operation:expr, $domain:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            scope: AwsDynamoDbTableScope,
            fence: EventualConsistencyFence,
            request_digest: Digest,
        }

        impl $name {
            pub fn for_scope(
                scope: &AwsDynamoDbTableScope,
                fence: EventualConsistencyFence,
            ) -> crate::error::Result<Self> {
                scope.validate()?;
                fence.validate(scope)?;
                let request_digest = Digest::from_parts(
                    $domain,
                    &[
                        ("scope", scope.digest().as_str().to_owned()),
                        ("table", scope.table_digest().as_str().to_owned()),
                        ("fence", fence.digest().as_str().to_owned()),
                    ],
                );
                Ok(Self {
                    scope: scope.clone(),
                    fence,
                    request_digest,
                })
            }

            pub fn scope(&self) -> &AwsDynamoDbTableScope {
                &self.scope
            }

            pub fn fence(&self) -> &EventualConsistencyFence {
                &self.fence
            }

            pub fn request_digest(&self) -> &Digest {
                &self.request_digest
            }

            pub fn recorded_request(&self) -> RecordedRequest {
                RecordedRequest {
                    operation: $operation,
                    scope_digest: self.scope.digest(),
                    table_digest: self.scope.table_digest(),
                    allowlist_digest: self.scope.allowlist_digest().clone(),
                    cursor_digest: None,
                    request_digest: self.request_digest.clone(),
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("scope_digest", &self.scope.digest())
                    .field("fence_digest", &self.fence.digest())
                    .field("request_digest", &self.request_digest)
                    .finish()
            }
        }
    };
}

describe_request!(
    DescribeTableRequest,
    AwsDynamoDbOperation::DescribeTable,
    "aws-dynamodb-describe-table-request/v1"
);
describe_request!(
    DescribeContinuousBackupsRequest,
    AwsDynamoDbOperation::DescribeContinuousBackups,
    "aws-dynamodb-describe-continuous-backups-request/v1"
);
describe_request!(
    DescribeTimeToLiveRequest,
    AwsDynamoDbOperation::DescribeTimeToLive,
    "aws-dynamodb-describe-time-to-live-request/v1"
);
describe_request!(
    ListTagsOfResourceRequest,
    AwsDynamoDbOperation::ListTagsOfResource,
    "aws-dynamodb-list-tags-of-resource-request/v1"
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTablesResponse {
    pub scope_digest: Digest,
    pub table_digest: Digest,
    pub allowlist_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub tables: Vec<TableSummary>,
    pub next_cursor: Option<OpaquePageToken>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListTablesResponse {
    pub fn new(
        request: &ListTablesRequest,
        tables: Vec<TableSummary>,
        next_cursor: Option<OpaquePageToken>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> crate::error::Result<Self> {
        if tables.len() > usize::from(request.bounds.page_size)
            || response_bytes > crate::MAX_RESPONSE_BYTES
        {
            return Err(crate::error::AwsDynamoDbTableError::PartialEvidence);
        }
        for table in &tables {
            table.validate_against(request.scope())?;
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate_against(request.scope(), request.page_number() + 1)?;
        }
        let mut response = Self {
            scope_digest: request.scope.digest(),
            table_digest: request.scope.table_digest(),
            allowlist_digest: request.scope.allowlist_digest().clone(),
            request_digest: request.request_digest.clone(),
            page_number: request.page_number(),
            tables,
            next_cursor,
            response_bytes,
            provenance,
            response_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.response_digest = response.calculate_digest();
        Ok(response)
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dynamodb-list-tables-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("table", self.table_digest.as_str().to_owned()),
                ("allowlist", self.allowlist_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "tables",
                    serde_json::to_string(&self.tables).expect("safe table summaries serialize"),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
                        }),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_integrity(&self, request: &ListTablesRequest) -> crate::error::Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.table_digest != request.scope().table_digest()
            || self.allowlist_digest != *request.scope().allowlist_digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.tables.len() > usize::from(request.bounds().page_size)
            || self.response_bytes > crate::MAX_RESPONSE_BYTES
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.response_digest != self.calculate_digest()
        {
            return Err(crate::error::AwsDynamoDbTableError::TamperedEvidence);
        }
        for table in &self.tables {
            table.validate_against(request.scope())?;
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(request.scope(), request.page_number() + 1)?;
        }
        Ok(())
    }
}

macro_rules! posture_response {
    ($name:ident, $request:ty, $field:ident, $posture:ty, $operation:expr, $domain:literal) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            pub scope_digest: Digest,
            pub table_digest: Digest,
            pub request_digest: Digest,
            pub $field: $posture,
            pub response_bytes: u64,
            pub provenance: TransportProvenance,
            pub response_digest: Digest,
            pub connected: bool,
            pub native: bool,
            pub first_party: bool,
            pub provider_receipt: bool,
        }

        impl $name {
            pub fn new(
                request: &$request,
                posture: $posture,
                response_bytes: u64,
                provenance: TransportProvenance,
            ) -> crate::error::Result<Self> {
                if response_bytes > crate::MAX_RESPONSE_BYTES {
                    return Err(crate::error::AwsDynamoDbTableError::ResponseTooLarge);
                }
                let mut response = Self {
                    scope_digest: request.scope().digest(),
                    table_digest: request.scope().table_digest(),
                    request_digest: request.request_digest().clone(),
                    $field: posture,
                    response_bytes,
                    provenance,
                    response_digest: Digest::zero(),
                    connected: false,
                    native: false,
                    first_party: false,
                    provider_receipt: false,
                };
                response.response_digest = response.calculate_digest();
                Ok(response)
            }

            fn calculate_digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        ("scope", self.scope_digest.as_str().to_owned()),
                        ("table", self.table_digest.as_str().to_owned()),
                        ("request", self.request_digest.as_str().to_owned()),
                        (
                            "posture",
                            serde_json::to_string(&self.$field)
                                .expect("safe DynamoDB posture serializes"),
                        ),
                        ("bytes", self.response_bytes.to_string()),
                        ("provenance", self.provenance.as_str().to_owned()),
                    ],
                )
            }

            pub fn validate_integrity(&self, request: &$request) -> crate::error::Result<()> {
                if self.scope_digest != request.scope().digest()
                    || self.table_digest != request.scope().table_digest()
                    || self.request_digest != *request.request_digest()
                    || self.response_bytes > crate::MAX_RESPONSE_BYTES
                    || self.connected
                    || self.native
                    || self.first_party
                    || self.provider_receipt
                    || self.response_digest != self.calculate_digest()
                {
                    return Err(crate::error::AwsDynamoDbTableError::TamperedEvidence);
                }
                Ok(())
            }
        }
    };
}

posture_response!(
    DescribeTableResponse,
    DescribeTableRequest,
    table,
    TablePosture,
    AwsDynamoDbOperation::DescribeTable,
    "aws-dynamodb-describe-table-response/v1"
);
posture_response!(
    DescribeContinuousBackupsResponse,
    DescribeContinuousBackupsRequest,
    backup,
    BackupPosture,
    AwsDynamoDbOperation::DescribeContinuousBackups,
    "aws-dynamodb-describe-continuous-backups-response/v1"
);
posture_response!(
    DescribeTimeToLiveResponse,
    DescribeTimeToLiveRequest,
    ttl,
    TtlPosture,
    AwsDynamoDbOperation::DescribeTimeToLive,
    "aws-dynamodb-describe-time-to-live-response/v1"
);
posture_response!(
    ListTagsOfResourceResponse,
    ListTagsOfResourceRequest,
    tags,
    TagKeyPosture,
    AwsDynamoDbOperation::ListTagsOfResource,
    "aws-dynamodb-list-tags-of-resource-response/v1"
);

#[derive(Clone, Debug)]
pub struct AwsDynamoDbProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub contract_version: String,
    pub release: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsDynamoDbProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> crate::error::Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() || release.len() > MAX_IDENTIFIER_BYTES {
            return Err(crate::error::AwsDynamoDbTableError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "aws-dynamodb-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "aws-dynamodb-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("revision", provider_revision.to_string()),
                ("api", PROVIDER_API_REVISION.to_owned()),
                ("contract", CONTRACT_VERSION.to_owned()),
                ("plugin", PLUGIN_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate(&self) -> crate::error::Result<()> {
        let expected = Self::new(self.provider_revision, self.release.clone())?;
        if self.provider_id != PROVIDER_ID
            || self.api_revision != PROVIDER_API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.connected
            || self.native
            || self.first_party
            || self.provider_digest != expected.provider_digest
        {
            return Err(crate::error::AwsDynamoDbTableError::ProviderDrift);
        }
        Ok(())
    }
}

impl Serialize for AwsDynamoDbProviderDefinition {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("AwsDynamoDbProviderDefinition", 10)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("release", &self.release)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("connected", &self.connected)?;
        state.serialize_field("native", &self.native)?;
        state.serialize_field("firstParty", &self.first_party)?;
        state.end()
    }
}

pub trait AwsDynamoDbTransport: Send {
    fn provenance(&self) -> TransportProvenance;

    fn list_tables(
        &mut self,
        request: &ListTablesRequest,
    ) -> std::result::Result<ListTablesResponse, AwsDynamoDbTransportError>;

    fn describe_table(
        &mut self,
        request: &DescribeTableRequest,
    ) -> std::result::Result<DescribeTableResponse, AwsDynamoDbTransportError>;

    fn describe_continuous_backups(
        &mut self,
        request: &DescribeContinuousBackupsRequest,
    ) -> std::result::Result<DescribeContinuousBackupsResponse, AwsDynamoDbTransportError>;

    fn describe_time_to_live(
        &mut self,
        request: &DescribeTimeToLiveRequest,
    ) -> std::result::Result<DescribeTimeToLiveResponse, AwsDynamoDbTransportError>;

    fn list_tags_of_resource(
        &mut self,
        request: &ListTagsOfResourceRequest,
    ) -> std::result::Result<ListTagsOfResourceResponse, AwsDynamoDbTransportError>;
}

pub struct AwsDynamoDbProvider<T = BlockedEnvTransport> {
    transport: T,
    definition: AwsDynamoDbProviderDefinition,
}

impl<T: AwsDynamoDbTransport> fmt::Debug for AwsDynamoDbProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDynamoDbProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsDynamoDbTransport> AwsDynamoDbProvider<T> {
    pub fn new(transport: T) -> crate::error::Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> crate::error::Result<Self> {
        let definition = AwsDynamoDbProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsDynamoDbProviderDefinition {
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

    pub fn list_tables(
        &mut self,
        request: &ListTablesRequest,
    ) -> std::result::Result<ListTablesResponse, AwsDynamoDbTransportError> {
        let response = self.transport.list_tables(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsDynamoDbTransportError::InvalidResponse)?;
        ensure_provenance(&response.provenance, &self.provenance())?;
        Ok(response)
    }

    pub fn describe_table(
        &mut self,
        request: &DescribeTableRequest,
    ) -> std::result::Result<DescribeTableResponse, AwsDynamoDbTransportError> {
        let response = self.transport.describe_table(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsDynamoDbTransportError::InvalidResponse)?;
        ensure_provenance(&response.provenance, &self.provenance())?;
        Ok(response)
    }

    pub fn describe_continuous_backups(
        &mut self,
        request: &DescribeContinuousBackupsRequest,
    ) -> std::result::Result<DescribeContinuousBackupsResponse, AwsDynamoDbTransportError> {
        let response = self.transport.describe_continuous_backups(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsDynamoDbTransportError::InvalidResponse)?;
        ensure_provenance(&response.provenance, &self.provenance())?;
        Ok(response)
    }

    pub fn describe_time_to_live(
        &mut self,
        request: &DescribeTimeToLiveRequest,
    ) -> std::result::Result<DescribeTimeToLiveResponse, AwsDynamoDbTransportError> {
        let response = self.transport.describe_time_to_live(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsDynamoDbTransportError::InvalidResponse)?;
        ensure_provenance(&response.provenance, &self.provenance())?;
        Ok(response)
    }

    pub fn list_tags_of_resource(
        &mut self,
        request: &ListTagsOfResourceRequest,
    ) -> std::result::Result<ListTagsOfResourceResponse, AwsDynamoDbTransportError> {
        let response = self.transport.list_tags_of_resource(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsDynamoDbTransportError::InvalidResponse)?;
        ensure_provenance(&response.provenance, &self.provenance())?;
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl Default for AwsDynamoDbProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked DynamoDB provider definition")
    }
}

fn ensure_provenance(
    response: &TransportProvenance,
    expected: &TransportProvenance,
) -> std::result::Result<(), AwsDynamoDbTransportError> {
    if response != expected || response.connected() || response.native() || response.first_party() {
        Err(AwsDynamoDbTransportError::InvalidResponse)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QueuedTransport {
    provenance: TransportProvenance,
    list_tables: VecDeque<std::result::Result<ListTablesResponse, AwsDynamoDbTransportError>>,
    describe_table: VecDeque<std::result::Result<DescribeTableResponse, AwsDynamoDbTransportError>>,
    describe_continuous_backups:
        VecDeque<std::result::Result<DescribeContinuousBackupsResponse, AwsDynamoDbTransportError>>,
    describe_time_to_live:
        VecDeque<std::result::Result<DescribeTimeToLiveResponse, AwsDynamoDbTransportError>>,
    list_tags: VecDeque<std::result::Result<ListTagsOfResourceResponse, AwsDynamoDbTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl QueuedTransport {
    fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            list_tables: VecDeque::new(),
            describe_table: VecDeque::new(),
            describe_continuous_backups: VecDeque::new(),
            describe_time_to_live: VecDeque::new(),
            list_tags: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    fn push_list_tables(
        &mut self,
        response: std::result::Result<ListTablesResponse, AwsDynamoDbTransportError>,
    ) {
        self.list_tables.push_back(response);
    }

    fn push_describe_table(
        &mut self,
        response: std::result::Result<DescribeTableResponse, AwsDynamoDbTransportError>,
    ) {
        self.describe_table.push_back(response);
    }

    fn push_describe_continuous_backups(
        &mut self,
        response: std::result::Result<DescribeContinuousBackupsResponse, AwsDynamoDbTransportError>,
    ) {
        self.describe_continuous_backups.push_back(response);
    }

    fn push_describe_time_to_live(
        &mut self,
        response: std::result::Result<DescribeTimeToLiveResponse, AwsDynamoDbTransportError>,
    ) {
        self.describe_time_to_live.push_back(response);
    }

    fn push_list_tags(
        &mut self,
        response: std::result::Result<ListTagsOfResourceResponse, AwsDynamoDbTransportError>,
    ) {
        self.list_tags.push_back(response);
    }
}

macro_rules! queued_transport_type {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            inner: QueuedTransport,
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            pub fn new() -> Self {
                Self {
                    inner: QueuedTransport::new($provenance),
                }
            }

            pub fn push_list_tables_response(
                &mut self,
                response: std::result::Result<ListTablesResponse, AwsDynamoDbTransportError>,
            ) {
                self.inner.push_list_tables(response);
            }

            pub fn push_list_response(
                &mut self,
                response: std::result::Result<ListTablesResponse, AwsDynamoDbTransportError>,
            ) {
                self.push_list_tables_response(response);
            }

            pub fn push_describe_table_response(
                &mut self,
                response: std::result::Result<DescribeTableResponse, AwsDynamoDbTransportError>,
            ) {
                self.inner.push_describe_table(response);
            }

            pub fn push_describe_continuous_backups_response(
                &mut self,
                response: std::result::Result<
                    DescribeContinuousBackupsResponse,
                    AwsDynamoDbTransportError,
                >,
            ) {
                self.inner.push_describe_continuous_backups(response);
            }

            pub fn push_describe_time_to_live_response(
                &mut self,
                response: std::result::Result<
                    DescribeTimeToLiveResponse,
                    AwsDynamoDbTransportError,
                >,
            ) {
                self.inner.push_describe_time_to_live(response);
            }

            pub fn push_list_tags_of_resource_response(
                &mut self,
                response: std::result::Result<
                    ListTagsOfResourceResponse,
                    AwsDynamoDbTransportError,
                >,
            ) {
                self.inner.push_list_tags(response);
            }

            pub fn push_list_tags_response(
                &mut self,
                response: std::result::Result<
                    ListTagsOfResourceResponse,
                    AwsDynamoDbTransportError,
                >,
            ) {
                self.push_list_tags_of_resource_response(response);
            }

            pub fn requests(&self) -> &[RecordedRequest] {
                &self.inner.requests
            }
        }

        impl AwsDynamoDbTransport for $name {
            fn provenance(&self) -> TransportProvenance {
                self.inner.provenance.clone()
            }

            fn list_tables(
                &mut self,
                request: &ListTablesRequest,
            ) -> std::result::Result<ListTablesResponse, AwsDynamoDbTransportError> {
                self.inner.requests.push(request.recorded_request());
                self.inner
                    .list_tables
                    .pop_front()
                    .unwrap_or(Err(AwsDynamoDbTransportError::InvalidResponse))
            }

            fn describe_table(
                &mut self,
                request: &DescribeTableRequest,
            ) -> std::result::Result<DescribeTableResponse, AwsDynamoDbTransportError> {
                self.inner.requests.push(request.recorded_request());
                self.inner
                    .describe_table
                    .pop_front()
                    .unwrap_or(Err(AwsDynamoDbTransportError::InvalidResponse))
            }

            fn describe_continuous_backups(
                &mut self,
                request: &DescribeContinuousBackupsRequest,
            ) -> std::result::Result<DescribeContinuousBackupsResponse, AwsDynamoDbTransportError>
            {
                self.inner.requests.push(request.recorded_request());
                self.inner
                    .describe_continuous_backups
                    .pop_front()
                    .unwrap_or(Err(AwsDynamoDbTransportError::InvalidResponse))
            }

            fn describe_time_to_live(
                &mut self,
                request: &DescribeTimeToLiveRequest,
            ) -> std::result::Result<DescribeTimeToLiveResponse, AwsDynamoDbTransportError> {
                self.inner.requests.push(request.recorded_request());
                self.inner
                    .describe_time_to_live
                    .pop_front()
                    .unwrap_or(Err(AwsDynamoDbTransportError::InvalidResponse))
            }

            fn list_tags_of_resource(
                &mut self,
                request: &ListTagsOfResourceRequest,
            ) -> std::result::Result<ListTagsOfResourceResponse, AwsDynamoDbTransportError> {
                self.inner.requests.push(request.recorded_request());
                self.inner
                    .list_tags
                    .pop_front()
                    .unwrap_or(Err(AwsDynamoDbTransportError::InvalidResponse))
            }
        }
    };
}

queued_transport_type!(RecordingTransport, TransportProvenance::Recording);
queued_transport_type!(FixtureTransport, TransportProvenance::Fixture);
queued_transport_type!(LoopbackTransport, TransportProvenance::Loopback);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvTransport;

impl AwsDynamoDbTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_tables(
        &mut self,
        _request: &ListTablesRequest,
    ) -> std::result::Result<ListTablesResponse, AwsDynamoDbTransportError> {
        Err(AwsDynamoDbTransportError::BlockedEnv)
    }

    fn describe_table(
        &mut self,
        _request: &DescribeTableRequest,
    ) -> std::result::Result<DescribeTableResponse, AwsDynamoDbTransportError> {
        Err(AwsDynamoDbTransportError::BlockedEnv)
    }

    fn describe_continuous_backups(
        &mut self,
        _request: &DescribeContinuousBackupsRequest,
    ) -> std::result::Result<DescribeContinuousBackupsResponse, AwsDynamoDbTransportError> {
        Err(AwsDynamoDbTransportError::BlockedEnv)
    }

    fn describe_time_to_live(
        &mut self,
        _request: &DescribeTimeToLiveRequest,
    ) -> std::result::Result<DescribeTimeToLiveResponse, AwsDynamoDbTransportError> {
        Err(AwsDynamoDbTransportError::BlockedEnv)
    }

    fn list_tags_of_resource(
        &mut self,
        _request: &ListTagsOfResourceRequest,
    ) -> std::result::Result<ListTagsOfResourceResponse, AwsDynamoDbTransportError> {
        Err(AwsDynamoDbTransportError::BlockedEnv)
    }
}

pub type RecordingAwsDynamoDbTransport = RecordingTransport;
pub type FixtureAwsDynamoDbTransport = FixtureTransport;
pub type LoopbackAwsDynamoDbTransport = LoopbackTransport;

pub fn is_access_loss(error: &AwsDynamoDbTransportError) -> bool {
    error.is_access_loss()
}
