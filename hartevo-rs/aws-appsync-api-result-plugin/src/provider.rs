use std::{collections::VecDeque, fmt, ops::Deref};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{AwsAppSyncApiResultError, AwsAppSyncTransportError, Result};
use crate::model::{
    ApiLifecycleState, ApiMetadata, ApiSummary, AppSyncApiType, AssociationKind, AssociationPage,
    AwsAppSyncApiScope, CostReceipt, DeploymentState, Digest, SchemaCreationStatus,
    SchemaDeploymentMetadata, TransportProvenance, digest_items, validate_page_number,
    validate_page_size, validate_response_bytes,
};
use crate::{API_REVISION, CONTRACT_VERSION, LAYER1_PERMISSIONS, PROVIDER_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsAppSyncOperation {
    ListGraphqlApis,
    GetApi,
    GetSchemaCreationStatus,
    ListDataSources,
    ListResolvers,
}

impl AwsAppSyncOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListGraphqlApis => "ListGraphqlApis",
            Self::GetApi => "GetApi",
            Self::GetSchemaCreationStatus => "GetSchemaCreationStatus",
            Self::ListDataSources => "ListDataSources",
            Self::ListResolvers => "ListResolvers",
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cursor {
    marker_digest: Digest,
    scope_digest: Digest,
    operation: AwsAppSyncOperation,
    page_number: u16,
}

impl Cursor {
    pub fn new(
        opaque_marker: impl Into<String>,
        scope: &AwsAppSyncApiScope,
        operation: AwsAppSyncOperation,
        page_number: u16,
    ) -> Result<Self> {
        let marker = opaque_marker.into();
        if marker.is_empty() || marker.len() > crate::MAX_IDENTIFIER_BYTES || page_number < 2 {
            return Err(AwsAppSyncApiResultError::InvalidRequest);
        }
        let cursor = Self {
            marker_digest: Digest::from_parts(
                "aws-appsync-opaque-next-token/v1",
                &[
                    ("marker", marker),
                    ("scope", scope.digest().as_str().to_owned()),
                    ("operation", operation.as_str().to_owned()),
                ],
            ),
            scope_digest: scope.digest(),
            operation,
            page_number,
        };
        cursor.validate(scope, operation)?;
        Ok(cursor)
    }

    pub fn marker_digest(&self) -> &Digest {
        &self.marker_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn operation(&self) -> AwsAppSyncOperation {
        self.operation
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub(crate) fn validate(
        &self,
        scope: &AwsAppSyncApiScope,
        operation: AwsAppSyncOperation,
    ) -> Result<()> {
        validate_page_number(self.page_number)?;
        if self.scope_digest != scope.digest() || self.operation != operation {
            return Err(AwsAppSyncApiResultError::CursorMismatch);
        }
        self.marker_digest.validate()
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("marker_digest", &self.marker_digest)
            .field("scope_digest", &self.scope_digest)
            .field("operation", &self.operation)
            .field("page_number", &self.page_number)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsAppSyncOperation,
    pub scope_digest: Digest,
    pub api_digest: Digest,
    pub page_number: Option<u16>,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub redacted: bool,
}

impl RecordedRequest {
    pub fn receipt(&self) -> crate::model::RequestReceipt {
        crate::model::RequestReceipt::new(
            self.operation.as_str(),
            self.request_digest.clone(),
            self.path_digest.clone(),
        )
    }

    fn validate(&self) -> Result<()> {
        if !self.redacted {
            return Err(AwsAppSyncApiResultError::TamperedEvidence);
        }
        self.scope_digest.validate()?;
        self.api_digest.validate()?;
        self.cursor_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.request_digest.validate()?;
        self.path_digest.validate()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListGraphqlApisRequest {
    scope: AwsAppSyncApiScope,
    page_size: u16,
    page_number: u16,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl ListGraphqlApisRequest {
    pub fn new(scope: &AwsAppSyncApiScope, page_size: u16, cursor: Option<Cursor>) -> Result<Self> {
        scope.validate()?;
        validate_page_size(page_size)?;
        let page_number = cursor.as_ref().map_or(1, Cursor::page_number);
        if let Some(cursor) = cursor.as_ref() {
            cursor.validate(scope, AwsAppSyncOperation::ListGraphqlApis)?;
        }
        let request_digest = Digest::from_parts(
            "aws-appsync-list-graphql-apis-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("page_size", page_size.to_string()),
                ("page_number", page_number.to_string()),
                (
                    "cursor",
                    cursor.as_ref().map_or_else(String::new, |value| {
                        value.marker_digest().as_str().to_owned()
                    }),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            page_size,
            page_number,
            cursor,
            request_digest,
        })
    }

    pub fn first(scope: &AwsAppSyncApiScope, page_size: u16) -> Result<Self> {
        Self::new(scope, page_size, None)
    }

    pub fn scope(&self) -> &AwsAppSyncApiScope {
        &self.scope
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/v1/apis?maxResults={}&nextToken={}",
            self.page_size,
            self.cursor
                .as_ref()
                .map_or_else(String::new, |cursor| cursor.marker_digest().as_str()[..16]
                    .to_owned())
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsAppSyncOperation::ListGraphqlApis,
            scope_digest: self.scope.digest(),
            api_digest: self.scope.api().digest(),
            page_number: Some(self.page_number),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.marker_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
            redacted: true,
        }
    }
}

impl fmt::Debug for ListGraphqlApisRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListGraphqlApisRequest")
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("page_number", &self.page_number)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

macro_rules! single_request {
    ($name:ident, $operation:ident, $domain:literal, $path:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            scope: AwsAppSyncApiScope,
            request_digest: Digest,
        }

        impl $name {
            pub fn for_scope(scope: &AwsAppSyncApiScope) -> Result<Self> {
                scope.validate()?;
                Ok(Self {
                    scope: scope.clone(),
                    request_digest: Digest::from_parts(
                        $domain,
                        &[
                            ("scope", scope.digest().as_str().to_owned()),
                            ("api", scope.api().digest().as_str().to_owned()),
                        ],
                    ),
                })
            }

            pub fn scope(&self) -> &AwsAppSyncApiScope {
                &self.scope
            }

            pub fn request_digest(&self) -> &Digest {
                &self.request_digest
            }

            pub fn path_and_query(&self) -> String {
                format!($path, &self.scope.api().id_digest().as_str()[..16])
            }

            pub fn recorded_request(&self) -> RecordedRequest {
                RecordedRequest {
                    operation: AwsAppSyncOperation::$operation,
                    scope_digest: self.scope.digest(),
                    api_digest: self.scope.api().digest(),
                    page_number: None,
                    cursor_digest: None,
                    request_digest: self.request_digest.clone(),
                    path_digest: Digest::from_text(self.path_and_query()),
                    redacted: true,
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("scope_digest", &self.scope.digest())
                    .field("request_digest", &self.request_digest)
                    .finish()
            }
        }
    };
}

single_request!(
    GetApiRequest,
    GetApi,
    "aws-appsync-get-api-request/v1",
    "/v2/apis/{}"
);
single_request!(
    GetSchemaCreationStatusRequest,
    GetSchemaCreationStatus,
    "aws-appsync-get-schema-status-request/v1",
    "/v1/apis/{}/schemacreation"
);

#[derive(Clone, Eq, PartialEq)]
pub struct AssociationListRequest {
    scope: AwsAppSyncApiScope,
    kind: AssociationKind,
    page_size: u16,
    page_number: u16,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl AssociationListRequest {
    fn new(
        scope: &AwsAppSyncApiScope,
        kind: AssociationKind,
        page_size: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        scope.validate()?;
        validate_page_size(page_size)?;
        let operation = match kind {
            AssociationKind::DataSource => AwsAppSyncOperation::ListDataSources,
            AssociationKind::Resolver => AwsAppSyncOperation::ListResolvers,
        };
        let page_number = cursor.as_ref().map_or(1, Cursor::page_number);
        if let Some(cursor) = &cursor {
            cursor.validate(scope, operation)?;
        }
        Ok(Self {
            scope: scope.clone(),
            kind,
            page_size,
            page_number,
            request_digest: Digest::from_parts(
                "aws-appsync-association-list-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("kind", kind.as_str().to_owned()),
                    ("page_size", page_size.to_string()),
                    ("page_number", page_number.to_string()),
                    (
                        "cursor",
                        cursor.as_ref().map_or_else(String::new, |value| {
                            value.marker_digest().as_str().to_owned()
                        }),
                    ),
                ],
            ),
            cursor,
        })
    }

    fn scope(&self) -> &AwsAppSyncApiScope {
        &self.scope
    }

    const fn kind(&self) -> AssociationKind {
        self.kind
    }

    const fn page_size(&self) -> u16 {
        self.page_size
    }

    const fn page_number(&self) -> u16 {
        self.page_number
    }

    fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    fn path_and_query(&self) -> String {
        let suffix = match self.kind {
            AssociationKind::DataSource => "datasources",
            AssociationKind::Resolver => "resolvers",
        };
        format!(
            "/v1/apis/{}/{}?maxResults={}&nextToken={}",
            &self.scope.api().id_digest().as_str()[..16],
            suffix,
            self.page_size,
            self.cursor
                .as_ref()
                .map_or_else(String::new, |cursor| cursor.marker_digest().as_str()[..16]
                    .to_owned())
        )
    }

    fn recorded_request(&self) -> RecordedRequest {
        let operation = match self.kind {
            AssociationKind::DataSource => AwsAppSyncOperation::ListDataSources,
            AssociationKind::Resolver => AwsAppSyncOperation::ListResolvers,
        };
        RecordedRequest {
            operation,
            scope_digest: self.scope.digest(),
            api_digest: self.scope.api().digest(),
            page_number: Some(self.page_number),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.marker_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
            redacted: true,
        }
    }
}

impl fmt::Debug for AssociationListRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssociationListRequest")
            .field("scope_digest", &self.scope.digest())
            .field("kind", &self.kind)
            .field("page_size", &self.page_size)
            .field("page_number", &self.page_number)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

macro_rules! association_request {
    ($name:ident, $kind:ident) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            inner: AssociationListRequest,
        }

        impl $name {
            pub fn first(scope: &AwsAppSyncApiScope, page_size: u16) -> Result<Self> {
                Self::new_with_cursor(scope, page_size, None)
            }

            pub fn new_with_cursor(
                scope: &AwsAppSyncApiScope,
                page_size: u16,
                cursor: Option<Cursor>,
            ) -> Result<Self> {
                Ok(Self {
                    inner: AssociationListRequest::new(
                        scope,
                        AssociationKind::$kind,
                        page_size,
                        cursor,
                    )?,
                })
            }

            pub fn scope(&self) -> &AwsAppSyncApiScope {
                self.inner.scope()
            }

            pub const fn page_size(&self) -> u16 {
                self.inner.page_size()
            }

            pub const fn page_number(&self) -> u16 {
                self.inner.page_number()
            }

            pub fn cursor(&self) -> Option<&Cursor> {
                self.inner.cursor()
            }

            pub fn request_digest(&self) -> &Digest {
                self.inner.request_digest()
            }

            pub fn recorded_request(&self) -> RecordedRequest {
                self.inner.recorded_request()
            }

            pub(crate) fn inner(&self) -> &AssociationListRequest {
                &self.inner
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.inner.fmt(formatter)
            }
        }
    };
}

association_request!(ListDataSourcesRequest, DataSource);
association_request!(ListResolversRequest, Resolver);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListGraphqlApisResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub apis: Vec<ApiSummary>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub request_receipt: crate::model::RequestReceipt,
    pub cost_receipt: CostReceipt,
}

impl ListGraphqlApisResponse {
    pub fn new(
        request: &ListGraphqlApisRequest,
        apis: Vec<ApiSummary>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if apis.len() > request.page_size() as usize {
            return Err(AwsAppSyncApiResultError::PartialEvidence);
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate(request.scope(), AwsAppSyncOperation::ListGraphqlApis)?;
            if cursor.page_number() != request.page_number().saturating_add(1)
                || request
                    .cursor()
                    .is_some_and(|previous| previous.marker_digest() == cursor.marker_digest())
            {
                return Err(AwsAppSyncApiResultError::PaginationLoop);
            }
        }
        for api in &apis {
            api.validate_against(request.scope())?;
        }
        let request_record = request.recorded_request();
        request_record.validate()?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            apis,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-appsync-list-apis-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            request_receipt: request_record.receipt(),
            cost_receipt: CostReceipt::new(
                AwsAppSyncOperation::ListGraphqlApis.as_str(),
                response_bytes,
            )?,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &ListGraphqlApisRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.apis.len() > request.page_size() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsAppSyncApiResultError::TamperedEvidence);
        }
        self.request_receipt.validate_integrity()?;
        self.cost_receipt.validate_integrity()?;
        for api in &self.apis {
            api.validate_against(request.scope())?;
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate(request.scope(), AwsAppSyncOperation::ListGraphqlApis)?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appsync-list-graphql-apis-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "apis",
                    crate::model::join_digests(
                        self.apis.iter().map(|api| api.summary_digest.clone()),
                    ),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.marker_digest().as_str().to_owned()
                        }),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "request_receipt",
                    self.request_receipt.receipt_digest.as_str().to_owned(),
                ),
                (
                    "cost_receipt",
                    self.cost_receipt.receipt_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

macro_rules! single_response {
    ($name:ident, $request:ident, $field:ident, $type:ty, $operation:path, $domain:literal) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            pub scope_digest: Digest,
            pub request_digest: Digest,
            pub $field: $type,
            pub response_bytes: u64,
            pub provenance: TransportProvenance,
            pub evidence_digest: Digest,
            pub connected: bool,
            pub native: bool,
            pub first_party: bool,
            pub provider_receipt: bool,
            pub request_receipt: crate::model::RequestReceipt,
            pub cost_receipt: CostReceipt,
        }

        impl $name {
            pub fn new(
                request: &$request,
                value: $type,
                response_bytes: u64,
                provenance: TransportProvenance,
            ) -> Result<Self> {
                validate_response_bytes(response_bytes)?;
                let request_record = request.recorded_request();
                request_record.validate()?;
                let mut response = Self {
                    scope_digest: request.scope().digest(),
                    request_digest: request.request_digest().clone(),
                    $field: value,
                    response_bytes,
                    provenance,
                    evidence_digest: Digest::from_text(concat!("unsealed-", $domain, "-response")),
                    connected: false,
                    native: false,
                    first_party: false,
                    provider_receipt: false,
                    request_receipt: request_record.receipt(),
                    cost_receipt: CostReceipt::new($operation.as_str(), response_bytes)?,
                };
                response.evidence_digest = response.calculate_digest();
                Ok(response)
            }

            pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
                self.evidence_digest = evidence_digest;
                self
            }

            pub fn validate_integrity(&self, request: &$request) -> Result<()> {
                validate_response_bytes(self.response_bytes)?;
                if self.scope_digest != request.scope().digest()
                    || self.request_digest != *request.request_digest()
                    || self.connected
                    || self.native
                    || self.first_party
                    || self.provider_receipt
                    || self.provenance.is_native()
                    || self.provenance.is_connected()
                    || self.provenance.is_first_party()
                    || self.evidence_digest != self.calculate_digest()
                {
                    return Err(AwsAppSyncApiResultError::TamperedEvidence);
                }
                self.request_receipt.validate_integrity()?;
                self.cost_receipt.validate_integrity()?;
                Ok(())
            }

            fn calculate_digest(&self) -> Digest {
                Digest::from_parts(
                    concat!($domain, "-response/v1"),
                    &[
                        ("scope", self.scope_digest.as_str().to_owned()),
                        ("request", self.request_digest.as_str().to_owned()),
                        (
                            "value",
                            crate::model::Digest::from_text(
                                serde_json::to_vec(&self.$field).expect("metadata serializes"),
                            )
                            .as_str()
                            .to_owned(),
                        ),
                        ("response_bytes", self.response_bytes.to_string()),
                        ("provenance", self.provenance.as_str().to_owned()),
                        (
                            "request_receipt",
                            self.request_receipt.receipt_digest.as_str().to_owned(),
                        ),
                        (
                            "cost_receipt",
                            self.cost_receipt.receipt_digest.as_str().to_owned(),
                        ),
                    ],
                )
            }
        }
    };
}

single_response!(
    GetApiResponse,
    GetApiRequest,
    api,
    ApiMetadata,
    AwsAppSyncOperation::GetApi,
    "aws-appsync-get-api"
);
single_response!(
    GetSchemaCreationStatusResponse,
    GetSchemaCreationStatusRequest,
    schema,
    SchemaDeploymentMetadata,
    AwsAppSyncOperation::GetSchemaCreationStatus,
    "aws-appsync-get-schema-status"
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssociationResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page: AssociationPage,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub request_receipt: crate::model::RequestReceipt,
    pub cost_receipt: CostReceipt,
}

impl AssociationResponse {
    fn new(
        request: &AssociationListRequest,
        identifiers: impl IntoIterator<Item = String>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        let identifiers = identifiers.into_iter().collect::<Vec<_>>();
        let identifier_count = identifiers.len();
        if identifier_count > request.page_size() as usize {
            return Err(AwsAppSyncApiResultError::PartialEvidence);
        }
        let operation = match request.kind() {
            AssociationKind::DataSource => AwsAppSyncOperation::ListDataSources,
            AssociationKind::Resolver => AwsAppSyncOperation::ListResolvers,
        };
        if let Some(cursor) = &next_cursor {
            cursor.validate(request.scope(), operation)?;
            if cursor.page_number() != request.page_number().saturating_add(1)
                || request
                    .cursor()
                    .is_some_and(|previous| previous.marker_digest() == cursor.marker_digest())
            {
                return Err(AwsAppSyncApiResultError::PaginationLoop);
            }
        }
        let items_digest = digest_items(
            match request.kind() {
                AssociationKind::DataSource => "aws-appsync-data-source-identifiers/v1",
                AssociationKind::Resolver => "aws-appsync-resolver-identifiers/v1",
            },
            identifiers,
        );
        let page = AssociationPage::new(
            request.scope(),
            request.kind(),
            request.page_number(),
            items_digest,
            identifier_count,
            next_cursor
                .as_ref()
                .map(|cursor| cursor.marker_digest().clone()),
        )?;
        let request_record = request.recorded_request();
        request_record.validate()?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            page,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-appsync-association-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            request_receipt: request_record.receipt(),
            cost_receipt: CostReceipt::new(operation.as_str(), response_bytes)?,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    fn validate_integrity(&self, request: &AssociationListRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsAppSyncApiResultError::TamperedEvidence);
        }
        self.page.validate(request.scope(), request.kind())?;
        if self.page.page_number != request.page_number() {
            return Err(AwsAppSyncApiResultError::ScopeMismatch);
        }
        if self.next_cursor.as_ref().map(Cursor::marker_digest)
            != self.page.next_cursor_digest.as_ref()
        {
            return Err(AwsAppSyncApiResultError::TamperedEvidence);
        }
        if let Some(cursor) = &self.next_cursor {
            let operation = match request.kind() {
                AssociationKind::DataSource => AwsAppSyncOperation::ListDataSources,
                AssociationKind::Resolver => AwsAppSyncOperation::ListResolvers,
            };
            cursor.validate(request.scope(), operation)?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsAppSyncApiResultError::CursorMismatch);
            }
        }
        self.request_receipt.validate_integrity()?;
        self.cost_receipt.validate_integrity()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appsync-association-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page.page_digest.as_str().to_owned()),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.marker_digest().as_str().to_owned()
                        }),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "request_receipt",
                    self.request_receipt.receipt_digest.as_str().to_owned(),
                ),
                (
                    "cost_receipt",
                    self.cost_receipt.receipt_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ListDataSourcesResponse {
    inner: AssociationResponse,
}

impl Deref for ListDataSourcesResponse {
    type Target = AssociationResponse;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl ListDataSourcesResponse {
    pub fn new<I, S>(
        request: &ListDataSourcesRequest,
        identifiers: I,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Ok(Self {
            inner: AssociationResponse::new(
                request.inner(),
                identifiers.into_iter().map(Into::into),
                next_cursor,
                response_bytes,
                provenance,
            )?,
        })
    }

    pub fn page(&self) -> &AssociationPage {
        &self.page
    }

    pub fn validate_integrity(&self, request: &ListDataSourcesRequest) -> Result<()> {
        self.inner.validate_integrity(request.inner())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ListResolversResponse {
    inner: AssociationResponse,
}

impl Deref for ListResolversResponse {
    type Target = AssociationResponse;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl ListResolversResponse {
    pub fn new<I, S>(
        request: &ListResolversRequest,
        identifiers: I,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Ok(Self {
            inner: AssociationResponse::new(
                request.inner(),
                identifiers.into_iter().map(Into::into),
                next_cursor,
                response_bytes,
                provenance,
            )?,
        })
    }

    pub fn page(&self) -> &AssociationPage {
        &self.page
    }

    pub fn validate_integrity(&self, request: &ListResolversRequest) -> Result<()> {
        self.inner.validate_integrity(request.inner())
    }
}

#[derive(Clone, Debug)]
pub struct AwsAppSyncProviderDefinition {
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
    pub arbitrary_graphql: bool,
    pub mutation_authority: bool,
}

impl AwsAppSyncProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || !crate::valid_release(&release) {
            return Err(AwsAppSyncApiResultError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "aws-appsync-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "aws-appsync-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
                ("arbitrary_graphql", "false".to_owned()),
                ("mutation_authority", "false".to_owned()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
            arbitrary_graphql: false,
            mutation_authority: false,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_revision != API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || !crate::valid_release(&self.release)
            || self.connected
            || self.native
            || self.first_party
            || self.arbitrary_graphql
            || self.mutation_authority
            || self.provider_digest
                != Self::new(self.provider_revision, self.release.clone())?.provider_digest
        {
            Err(AwsAppSyncApiResultError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AwsAppSyncProviderDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsAppSyncProviderDefinition", 12)?;
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
        state.serialize_field("arbitraryGraphql", &self.arbitrary_graphql)?;
        state.serialize_field("mutationAuthority", &self.mutation_authority)?;
        state.end()
    }
}

pub trait AwsAppSyncTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_graphql_apis(
        &mut self,
        request: &ListGraphqlApisRequest,
    ) -> std::result::Result<ListGraphqlApisResponse, AwsAppSyncTransportError>;

    fn get_api(
        &mut self,
        request: &GetApiRequest,
    ) -> std::result::Result<GetApiResponse, AwsAppSyncTransportError>;

    fn get_schema_creation_status(
        &mut self,
        request: &GetSchemaCreationStatusRequest,
    ) -> std::result::Result<GetSchemaCreationStatusResponse, AwsAppSyncTransportError>;

    fn list_data_sources(
        &mut self,
        request: &ListDataSourcesRequest,
    ) -> std::result::Result<ListDataSourcesResponse, AwsAppSyncTransportError>;

    fn list_resolvers(
        &mut self,
        request: &ListResolversRequest,
    ) -> std::result::Result<ListResolversResponse, AwsAppSyncTransportError>;
}

pub struct AwsAppSyncProvider<T> {
    transport: T,
    definition: AwsAppSyncProviderDefinition,
}

impl<T: AwsAppSyncTransport> fmt::Debug for AwsAppSyncProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAppSyncProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsAppSyncTransport> AwsAppSyncProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AwsAppSyncProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsAppSyncProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn list_graphql_apis(
        &mut self,
        request: &ListGraphqlApisRequest,
    ) -> std::result::Result<ListGraphqlApisResponse, AwsAppSyncTransportError> {
        let response = self.transport.list_graphql_apis(request)?;
        validate_response(
            response.validate_integrity(request),
            response.provenance,
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn get_api(
        &mut self,
        request: &GetApiRequest,
    ) -> std::result::Result<GetApiResponse, AwsAppSyncTransportError> {
        let response = self.transport.get_api(request)?;
        response
            .api
            .validate_against(request.scope())
            .map_err(|_| AwsAppSyncTransportError::Tampered)?;
        validate_response(
            response.validate_integrity(request),
            response.provenance,
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn get_schema_creation_status(
        &mut self,
        request: &GetSchemaCreationStatusRequest,
    ) -> std::result::Result<GetSchemaCreationStatusResponse, AwsAppSyncTransportError> {
        let response = self.transport.get_schema_creation_status(request)?;
        response
            .schema
            .validate_against(request.scope())
            .map_err(|error| match error {
                AwsAppSyncApiResultError::RevisionDrift => AwsAppSyncTransportError::ConfigDrift,
                _ => AwsAppSyncTransportError::Tampered,
            })?;
        validate_response(
            response.validate_integrity(request),
            response.provenance,
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn list_data_sources(
        &mut self,
        request: &ListDataSourcesRequest,
    ) -> std::result::Result<ListDataSourcesResponse, AwsAppSyncTransportError> {
        let response = self.transport.list_data_sources(request)?;
        validate_response(
            response.validate_integrity(request),
            response.provenance,
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn list_resolvers(
        &mut self,
        request: &ListResolversRequest,
    ) -> std::result::Result<ListResolversResponse, AwsAppSyncTransportError> {
        let response = self.transport.list_resolvers(request)?;
        validate_response(
            response.validate_integrity(request),
            response.provenance,
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

fn validate_response(
    validation: Result<()>,
    response_provenance: TransportProvenance,
    expected_provenance: TransportProvenance,
    connected: bool,
    native: bool,
    first_party: bool,
    provider_receipt: bool,
) -> std::result::Result<(), AwsAppSyncTransportError> {
    match validation {
        Ok(()) => {}
        Err(AwsAppSyncApiResultError::RevisionDrift) => {
            return Err(AwsAppSyncTransportError::ConfigDrift);
        }
        Err(AwsAppSyncApiResultError::PaginationLoop) => {
            return Err(AwsAppSyncTransportError::PaginationLoop);
        }
        Err(AwsAppSyncApiResultError::TamperedEvidence) => {
            return Err(AwsAppSyncTransportError::Tampered);
        }
        Err(_) => return Err(AwsAppSyncTransportError::InvalidResponse),
    }
    if response_provenance != expected_provenance
        || connected
        || native
        || first_party
        || provider_receipt
        || response_provenance.is_native()
        || response_provenance.is_connected()
        || response_provenance.is_first_party()
    {
        return Err(AwsAppSyncTransportError::InvalidResponse);
    }
    Ok(())
}

impl Default for AwsAppSyncProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked AppSync provider definition")
    }
}

impl<T: AwsAppSyncTransport> AwsAppSyncProvider<T> {
    pub fn from_registration(
        registration: &crate::service::AwsAppSyncApiResultRegistration,
        transport: T,
    ) -> Result<Self> {
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(AwsAppSyncApiResultError::ProviderDrift);
        }
        Ok(provider)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    list_responses:
        VecDeque<std::result::Result<ListGraphqlApisResponse, AwsAppSyncTransportError>>,
    get_responses: VecDeque<std::result::Result<GetApiResponse, AwsAppSyncTransportError>>,
    schema_responses:
        VecDeque<std::result::Result<GetSchemaCreationStatusResponse, AwsAppSyncTransportError>>,
    data_source_responses:
        VecDeque<std::result::Result<ListDataSourcesResponse, AwsAppSyncTransportError>>,
    resolver_responses:
        VecDeque<std::result::Result<ListResolversResponse, AwsAppSyncTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            list_responses: VecDeque::new(),
            get_responses: VecDeque::new(),
            schema_responses: VecDeque::new(),
            data_source_responses: VecDeque::new(),
            resolver_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListGraphqlApisResponse, AwsAppSyncTransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_get_response(
        &mut self,
        response: std::result::Result<GetApiResponse, AwsAppSyncTransportError>,
    ) {
        self.get_responses.push_back(response);
    }

    pub fn push_schema_response(
        &mut self,
        response: std::result::Result<GetSchemaCreationStatusResponse, AwsAppSyncTransportError>,
    ) {
        self.schema_responses.push_back(response);
    }

    pub fn push_data_source_response(
        &mut self,
        response: std::result::Result<ListDataSourcesResponse, AwsAppSyncTransportError>,
    ) {
        self.data_source_responses.push_back(response);
    }

    pub fn push_resolver_response(
        &mut self,
        response: std::result::Result<ListResolversResponse, AwsAppSyncTransportError>,
    ) {
        self.resolver_responses.push_back(response);
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

impl AwsAppSyncTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn list_graphql_apis(
        &mut self,
        request: &ListGraphqlApisRequest,
    ) -> std::result::Result<ListGraphqlApisResponse, AwsAppSyncTransportError> {
        self.requests.push(request.recorded_request());
        self.list_responses
            .pop_front()
            .unwrap_or(Err(AwsAppSyncTransportError::InvalidResponse))
    }

    fn get_api(
        &mut self,
        request: &GetApiRequest,
    ) -> std::result::Result<GetApiResponse, AwsAppSyncTransportError> {
        self.requests.push(request.recorded_request());
        self.get_responses
            .pop_front()
            .unwrap_or(Err(AwsAppSyncTransportError::InvalidResponse))
    }

    fn get_schema_creation_status(
        &mut self,
        request: &GetSchemaCreationStatusRequest,
    ) -> std::result::Result<GetSchemaCreationStatusResponse, AwsAppSyncTransportError> {
        self.requests.push(request.recorded_request());
        self.schema_responses
            .pop_front()
            .unwrap_or(Err(AwsAppSyncTransportError::InvalidResponse))
    }

    fn list_data_sources(
        &mut self,
        request: &ListDataSourcesRequest,
    ) -> std::result::Result<ListDataSourcesResponse, AwsAppSyncTransportError> {
        self.requests.push(request.recorded_request());
        self.data_source_responses
            .pop_front()
            .unwrap_or(Err(AwsAppSyncTransportError::InvalidResponse))
    }

    fn list_resolvers(
        &mut self,
        request: &ListResolversRequest,
    ) -> std::result::Result<ListResolversResponse, AwsAppSyncTransportError> {
        self.requests.push(request.recorded_request());
        self.resolver_responses
            .pop_front()
            .unwrap_or(Err(AwsAppSyncTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsAppSyncApiScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsAppSyncApiScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn summary(&self) -> Result<ApiSummary> {
        ApiSummary::new(
            self.scope.api().clone(),
            self.scope.api_type(),
            ApiLifecycleState::Active,
            true,
            self.observed_at - Duration::minutes(5),
            "fixture-api-revision-1",
        )
    }

    fn metadata(&self) -> Result<ApiMetadata> {
        ApiMetadata::new(
            &self.scope,
            "https://fixture.appsync-api.example/graphql",
            ["API_KEY".to_owned(), "AWS_IAM".to_owned()],
            if self.scope.api_type() == AppSyncApiType::Event {
                Some("fixture-event-configuration".to_owned())
            } else {
                None
            },
            "GLOBAL",
            Some("arn:aws:wafv2:fixture:webacl/appsync".to_owned()),
            true,
            false,
            "fixture-config-revision-1",
            self.observed_at - Duration::minutes(5),
        )
    }

    fn schema(&self) -> Result<SchemaDeploymentMetadata> {
        SchemaDeploymentMetadata::new(
            &self.scope,
            "fixture-schema-revision-1",
            "fixture-schema-hash",
            SchemaCreationStatus::Active,
            DeploymentState::Active,
            "fixture-deployment-revision-1",
            self.observed_at - Duration::minutes(4),
        )
    }

    fn list_response(
        &self,
        request: &ListGraphqlApisRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<ListGraphqlApisResponse, AwsAppSyncTransportError> {
        ListGraphqlApisResponse::new(
            request,
            vec![
                self.summary()
                    .map_err(|_| AwsAppSyncTransportError::InvalidResponse)?,
            ],
            None,
            2_048,
            provenance,
        )
        .map_err(|_| AwsAppSyncTransportError::InvalidResponse)
    }

    fn get_response(
        &self,
        request: &GetApiRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<GetApiResponse, AwsAppSyncTransportError> {
        GetApiResponse::new(
            request,
            self.metadata()
                .map_err(|_| AwsAppSyncTransportError::InvalidResponse)?,
            2_048,
            provenance,
        )
        .map_err(|_| AwsAppSyncTransportError::InvalidResponse)
    }

    fn schema_response(
        &self,
        request: &GetSchemaCreationStatusRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<GetSchemaCreationStatusResponse, AwsAppSyncTransportError> {
        GetSchemaCreationStatusResponse::new(
            request,
            self.schema().map_err(|error| match error {
                AwsAppSyncApiResultError::RevisionDrift => AwsAppSyncTransportError::ConfigDrift,
                _ => AwsAppSyncTransportError::InvalidResponse,
            })?,
            1_024,
            provenance,
        )
        .map_err(|_| AwsAppSyncTransportError::InvalidResponse)
    }

    fn data_response(
        request: &ListDataSourcesRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<ListDataSourcesResponse, AwsAppSyncTransportError> {
        ListDataSourcesResponse::new(
            request,
            ["fixture-data-source-primary", "fixture-data-source-audit"],
            None,
            1_024,
            provenance,
        )
        .map_err(|_| AwsAppSyncTransportError::InvalidResponse)
    }

    fn resolver_response(
        request: &ListResolversRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<ListResolversResponse, AwsAppSyncTransportError> {
        ListResolversResponse::new(
            request,
            ["Query.get", "Mutation.put"],
            None,
            1_024,
            provenance,
        )
        .map_err(|_| AwsAppSyncTransportError::InvalidResponse)
    }
}

impl AwsAppSyncTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_graphql_apis(
        &mut self,
        request: &ListGraphqlApisRequest,
    ) -> std::result::Result<ListGraphqlApisResponse, AwsAppSyncTransportError> {
        self.list_response(request, TransportProvenance::Fixture)
    }

    fn get_api(
        &mut self,
        request: &GetApiRequest,
    ) -> std::result::Result<GetApiResponse, AwsAppSyncTransportError> {
        self.get_response(request, TransportProvenance::Fixture)
    }

    fn get_schema_creation_status(
        &mut self,
        request: &GetSchemaCreationStatusRequest,
    ) -> std::result::Result<GetSchemaCreationStatusResponse, AwsAppSyncTransportError> {
        self.schema_response(request, TransportProvenance::Fixture)
    }

    fn list_data_sources(
        &mut self,
        request: &ListDataSourcesRequest,
    ) -> std::result::Result<ListDataSourcesResponse, AwsAppSyncTransportError> {
        Self::data_response(request, TransportProvenance::Fixture)
    }

    fn list_resolvers(
        &mut self,
        request: &ListResolversRequest,
    ) -> std::result::Result<ListResolversResponse, AwsAppSyncTransportError> {
        Self::resolver_response(request, TransportProvenance::Fixture)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsAppSyncApiScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AwsAppSyncTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_graphql_apis(
        &mut self,
        request: &ListGraphqlApisRequest,
    ) -> std::result::Result<ListGraphqlApisResponse, AwsAppSyncTransportError> {
        self.inner
            .list_response(request, TransportProvenance::Loopback)
    }

    fn get_api(
        &mut self,
        request: &GetApiRequest,
    ) -> std::result::Result<GetApiResponse, AwsAppSyncTransportError> {
        self.inner
            .get_response(request, TransportProvenance::Loopback)
    }

    fn get_schema_creation_status(
        &mut self,
        request: &GetSchemaCreationStatusRequest,
    ) -> std::result::Result<GetSchemaCreationStatusResponse, AwsAppSyncTransportError> {
        self.inner
            .schema_response(request, TransportProvenance::Loopback)
    }

    fn list_data_sources(
        &mut self,
        request: &ListDataSourcesRequest,
    ) -> std::result::Result<ListDataSourcesResponse, AwsAppSyncTransportError> {
        FixtureTransport::data_response(request, TransportProvenance::Loopback)
    }

    fn list_resolvers(
        &mut self,
        request: &ListResolversRequest,
    ) -> std::result::Result<ListResolversResponse, AwsAppSyncTransportError> {
        FixtureTransport::resolver_response(request, TransportProvenance::Loopback)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsAppSyncTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_graphql_apis(
        &mut self,
        _request: &ListGraphqlApisRequest,
    ) -> std::result::Result<ListGraphqlApisResponse, AwsAppSyncTransportError> {
        Err(AwsAppSyncTransportError::BlockedEnv)
    }

    fn get_api(
        &mut self,
        _request: &GetApiRequest,
    ) -> std::result::Result<GetApiResponse, AwsAppSyncTransportError> {
        Err(AwsAppSyncTransportError::BlockedEnv)
    }

    fn get_schema_creation_status(
        &mut self,
        _request: &GetSchemaCreationStatusRequest,
    ) -> std::result::Result<GetSchemaCreationStatusResponse, AwsAppSyncTransportError> {
        Err(AwsAppSyncTransportError::BlockedEnv)
    }

    fn list_data_sources(
        &mut self,
        _request: &ListDataSourcesRequest,
    ) -> std::result::Result<ListDataSourcesResponse, AwsAppSyncTransportError> {
        Err(AwsAppSyncTransportError::BlockedEnv)
    }

    fn list_resolvers(
        &mut self,
        _request: &ListResolversRequest,
    ) -> std::result::Result<ListResolversResponse, AwsAppSyncTransportError> {
        Err(AwsAppSyncTransportError::BlockedEnv)
    }
}

pub type ProviderProvenance = TransportProvenance;
pub type FakeAwsAppSyncTransport = FixtureTransport;
