use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{
    MAX_MODEL_RELATIONS, MAX_MODEL_TYPES, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, MAX_TUPLES,
    PROVIDER_API_REVISION, PROVIDER_ID,
    error::{OpenFgaAuthorizationResultError, OpenFgaTransportError, Result},
    model::{
        AuthorizationCheckScope, AuthorizationDecision, CheckEvidence, CostReceipt, Digest,
        ModelEvidence, OpenFgaScope, RequestReceipt, TransportProvenance, TupleEvidence, TupleKey,
        TupleScope,
    },
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenFgaOperation {
    ReadAuthorizationModel,
    Check,
    ReadTuples,
}

impl OpenFgaOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadAuthorizationModel => "ReadAuthorizationModel",
            Self::Check => "Check",
            Self::ReadTuples => "ReadTuples",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ModelReadRequest {
    scope: OpenFgaScope,
    request_digest: Digest,
}

impl ModelReadRequest {
    pub fn for_scope(scope: &OpenFgaScope) -> Result<Self> {
        scope.validate()?;
        let request_digest = Digest::from_parts(
            "openfga-read-model-request/v1",
            &[
                ("scope", scope.digest().to_string()),
                ("store", scope.store().id_digest().to_string()),
                ("model", scope.authorization_model().id_digest().to_string()),
                (
                    "revision",
                    scope.authorization_model().revision().get().to_string(),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            request_digest,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &OpenFgaScope {
        &self.scope
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest::new(
            OpenFgaOperation::ReadAuthorizationModel,
            self.request_digest.clone(),
            self.scope.digest(),
            self.scope.authorization_model().digest(),
            Digest::from_text("openfga-no-check"),
            Digest::from_text("openfga-no-tuple-query"),
            None,
        )
    }
}

impl fmt::Debug for ModelReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelReadRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizationCheckRequest {
    scope: OpenFgaScope,
    check: AuthorizationCheckScope,
    request_digest: Digest,
}

impl AuthorizationCheckRequest {
    pub fn new(
        scope: &OpenFgaScope,
        user: impl Into<String>,
        relation: impl Into<String>,
        object: impl Into<String>,
        revision: u64,
    ) -> Result<Self> {
        Self::from_scope(
            scope,
            AuthorizationCheckScope::new(user, relation, object, revision)?,
        )
    }

    pub fn from_scope(scope: &OpenFgaScope, check: AuthorizationCheckScope) -> Result<Self> {
        scope.validate()?;
        let request_digest = Digest::from_parts(
            "openfga-check-request/v1",
            &[
                ("scope", scope.digest().to_string()),
                ("check", check.digest().to_string()),
                (
                    "model_revision",
                    scope.authorization_model().revision().get().to_string(),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            check,
            request_digest,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &OpenFgaScope {
        &self.scope
    }

    #[must_use]
    pub fn check(&self) -> &AuthorizationCheckScope {
        &self.check
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest::new(
            OpenFgaOperation::Check,
            self.request_digest.clone(),
            self.scope.digest(),
            self.scope.authorization_model().digest(),
            self.check.digest(),
            Digest::from_text("openfga-no-tuple-query"),
            None,
        )
    }
}

impl fmt::Debug for AuthorizationCheckRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationCheckRequest")
            .field("scope_digest", &self.scope.digest())
            .field("check", &self.check)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cursor {
    pub cursor_digest: Digest,
    pub scope_digest: Digest,
    pub tuple_query_digest: Digest,
    pub page_size: u16,
    pub page_number: u16,
}

impl Cursor {
    pub fn new(
        opaque_cursor: impl Into<String>,
        scope: &OpenFgaScope,
        tuple_query_digest: Digest,
        page_size: u16,
        page_number: u16,
    ) -> Result<Self> {
        let opaque_cursor = opaque_cursor.into();
        if opaque_cursor.is_empty()
            || opaque_cursor.len() > crate::MAX_IDENTIFIER_BYTES
            || !(2..=MAX_PAGES).contains(&page_number)
            || page_size == 0
            || page_size > MAX_PAGE_SIZE
        {
            return Err(OpenFgaAuthorizationResultError::InvalidRequest);
        }
        let cursor = Self {
            cursor_digest: Digest::from_parts(
                "openfga-opaque-cursor/v1",
                &[
                    ("cursor", opaque_cursor),
                    ("scope", scope.digest().to_string()),
                    ("query", tuple_query_digest.to_string()),
                    ("page_size", page_size.to_string()),
                    ("page_number", page_number.to_string()),
                ],
            ),
            scope_digest: scope.digest(),
            tuple_query_digest,
            page_size,
            page_number,
        };
        cursor.validate(scope, &cursor.tuple_query_digest, page_size)?;
        Ok(cursor)
    }

    fn validate(
        &self,
        scope: &OpenFgaScope,
        tuple_query_digest: &Digest,
        page_size: u16,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.tuple_query_digest != *tuple_query_digest
            || self.page_size != page_size
            || !(2..=MAX_PAGES).contains(&self.page_number)
        {
            return Err(OpenFgaAuthorizationResultError::CursorMismatch);
        }
        self.cursor_digest.validate()
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("cursor_digest", &self.cursor_digest)
            .field("scope_digest", &self.scope_digest)
            .field("tuple_query_digest", &self.tuple_query_digest)
            .field("page_size", &self.page_size)
            .field("page_number", &self.page_number)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TupleReadRequest {
    scope: OpenFgaScope,
    tuple_scope: TupleScope,
    page_size: u16,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl TupleReadRequest {
    pub fn new(
        scope: &OpenFgaScope,
        tuple_scope: TupleScope,
        page_size: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        scope.validate()?;
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(OpenFgaAuthorizationResultError::InvalidRequest);
        }
        if let Some(cursor) = cursor.as_ref() {
            cursor.validate(scope, &tuple_scope.digest(), page_size)?;
        }
        let page_number = cursor.as_ref().map_or(1, |value| value.page_number);
        let request_digest = Digest::from_parts(
            "openfga-read-tuples-request/v1",
            &[
                ("scope", scope.digest().to_string()),
                ("tuple_scope", tuple_scope.digest().to_string()),
                ("page_size", page_size.to_string()),
                ("page_number", page_number.to_string()),
                (
                    "cursor",
                    cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.cursor_digest.to_string()),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            tuple_scope,
            page_size,
            cursor,
            request_digest,
        })
    }

    pub fn first(scope: &OpenFgaScope, tuple_scope: TupleScope, page_size: u16) -> Result<Self> {
        Self::new(scope, tuple_scope, page_size, None)
    }

    fn with_cursor(&self, cursor: Cursor) -> Result<Self> {
        Self::new(
            &self.scope,
            self.tuple_scope.clone(),
            self.page_size,
            Some(cursor),
        )
    }

    #[must_use]
    pub fn scope(&self) -> &OpenFgaScope {
        &self.scope
    }

    #[must_use]
    pub fn tuple_scope(&self) -> &TupleScope {
        &self.tuple_scope
    }

    #[must_use]
    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    #[must_use]
    pub const fn page_number(&self) -> u16 {
        match &self.cursor {
            Some(cursor) => cursor.page_number,
            None => 1,
        }
    }

    #[must_use]
    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest::new(
            OpenFgaOperation::ReadTuples,
            self.request_digest.clone(),
            self.scope.digest(),
            self.scope.authorization_model().digest(),
            Digest::from_text("openfga-no-check"),
            self.tuple_scope.digest(),
            self.cursor
                .as_ref()
                .map(|value| value.cursor_digest.clone()),
        )
    }
}

impl fmt::Debug for TupleReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TupleReadRequest")
            .field("scope_digest", &self.scope.digest())
            .field("tuple_scope", &self.tuple_scope)
            .field("page_size", &self.page_size)
            .field("page_number", &self.page_number())
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelReadResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub model_digest: Digest,
    pub model_revision_digest: Digest,
    pub type_count: u16,
    pub relation_count: u16,
    pub rules_digest: Digest,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
}

impl ModelReadResponse {
    pub fn new(
        request: &ModelReadRequest,
        type_count: u16,
        relation_count: u16,
        rules_digest: Digest,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if type_count > MAX_MODEL_TYPES
            || relation_count > MAX_MODEL_RELATIONS
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(OpenFgaAuthorizationResultError::InvalidProviderResponse);
        }
        Ok(Self {
            scope_digest: request.scope.digest(),
            request_digest: request.request_digest.clone(),
            model_digest: request.scope.authorization_model().digest(),
            model_revision_digest: Digest::from_text(format!(
                "openfga-model-revision/v1|{}",
                request.scope.authorization_model().revision().get()
            )),
            type_count,
            relation_count,
            rules_digest,
            response_bytes,
            provenance,
        })
    }

    fn validate(&self, request: &ModelReadRequest, expected: TransportProvenance) -> Result<()> {
        if self.scope_digest != request.scope.digest()
            || self.request_digest != *request.request_digest()
            || self.model_digest != request.scope.authorization_model().digest()
            || self.model_revision_digest
                != Digest::from_text(format!(
                    "openfga-model-revision/v1|{}",
                    request.scope.authorization_model().revision().get()
                ))
            || self.type_count > MAX_MODEL_TYPES
            || self.relation_count > MAX_MODEL_RELATIONS
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.provenance != expected
        {
            return Err(OpenFgaAuthorizationResultError::InvalidProviderResponse);
        }
        self.rules_digest.validate()
    }

    fn evidence(&self) -> ModelEvidence {
        ModelEvidence::new(
            self.model_digest.clone(),
            self.model_revision_digest.clone(),
            self.type_count,
            self.relation_count,
            self.rules_digest.clone(),
            self.response_bytes,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationCheckResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub decision: AuthorizationDecision,
    pub user_digest: Digest,
    pub object_digest: Digest,
    pub relation_digest: Digest,
    pub model_digest: Digest,
    pub check_revision_digest: Digest,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
}

impl AuthorizationCheckResponse {
    pub fn new(
        request: &AuthorizationCheckRequest,
        decision: AuthorizationDecision,
        model_digest: Digest,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(OpenFgaAuthorizationResultError::InvalidProviderResponse);
        }
        Ok(Self {
            scope_digest: request.scope.digest(),
            request_digest: request.request_digest.clone(),
            decision,
            user_digest: request.check.user.digest(),
            object_digest: request.check.object.digest(),
            relation_digest: request.check.relation.digest(),
            model_digest,
            check_revision_digest: Digest::from_text(format!(
                "openfga-check-revision/v1|{}",
                request.check.revision.get()
            )),
            response_bytes,
            provenance,
        })
    }

    fn validate(
        &self,
        request: &AuthorizationCheckRequest,
        expected: TransportProvenance,
    ) -> Result<()> {
        if self.scope_digest != request.scope.digest()
            || self.request_digest != *request.request_digest()
            || self.user_digest != request.check.user.digest()
            || self.object_digest != request.check.object.digest()
            || self.relation_digest != request.check.relation.digest()
            || self.check_revision_digest
                != Digest::from_text(format!(
                    "openfga-check-revision/v1|{}",
                    request.check.revision.get()
                ))
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.provenance != expected
        {
            return Err(OpenFgaAuthorizationResultError::InvalidProviderResponse);
        }
        self.model_digest.validate()
    }

    fn evidence(&self) -> CheckEvidence {
        CheckEvidence::new(
            self.decision,
            self.user_digest.clone(),
            self.object_digest.clone(),
            self.relation_digest.clone(),
            self.model_digest.clone(),
            self.check_revision_digest.clone(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TupleReadResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub tuple_query_digest: Digest,
    pub tuples: Vec<TupleKey>,
    pub next_cursor: Option<Cursor>,
    pub tuple_revision_digest: Digest,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
}

impl TupleReadResponse {
    pub fn new(
        request: &TupleReadRequest,
        tuples: Vec<TupleKey>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if tuples.len() > MAX_TUPLES || response_bytes > MAX_RESPONSE_BYTES {
            return Err(OpenFgaAuthorizationResultError::InvalidProviderResponse);
        }
        if let Some(cursor) = next_cursor.as_ref() {
            cursor.validate(
                &request.scope,
                &request.tuple_scope.digest(),
                request.page_size,
            )?;
        }
        if tuples
            .iter()
            .any(|tuple| !tuple.matches(&request.tuple_scope))
        {
            return Err(OpenFgaAuthorizationResultError::InvalidProviderResponse);
        }
        Ok(Self {
            scope_digest: request.scope.digest(),
            request_digest: request.request_digest.clone(),
            tuple_query_digest: request.tuple_scope.digest(),
            tuples,
            next_cursor,
            tuple_revision_digest: Digest::from_text(format!(
                "openfga-tuple-revision/v1|{}",
                request.tuple_scope.revision.get()
            )),
            response_bytes,
            provenance,
        })
    }

    fn validate(&self, request: &TupleReadRequest, expected: TransportProvenance) -> Result<()> {
        if self.scope_digest != request.scope.digest()
            || self.request_digest != *request.request_digest()
            || self.tuple_query_digest != request.tuple_scope.digest()
            || self.tuples.len() > MAX_TUPLES
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.tuple_revision_digest
                != Digest::from_text(format!(
                    "openfga-tuple-revision/v1|{}",
                    request.tuple_scope.revision.get()
                ))
            || self.provenance != expected
            || self
                .tuples
                .iter()
                .any(|tuple| !tuple.matches(&request.tuple_scope))
        {
            return Err(OpenFgaAuthorizationResultError::InvalidProviderResponse);
        }
        if let Some(cursor) = self.next_cursor.as_ref() {
            cursor.validate(
                &request.scope,
                &request.tuple_scope.digest(),
                request.page_size,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: OpenFgaOperation,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub scope_digest: Digest,
    pub model_digest: Digest,
    pub check_digest: Digest,
    pub tuple_query_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub redacted: bool,
}

impl RecordedRequest {
    fn new(
        operation: OpenFgaOperation,
        request_digest: Digest,
        scope_digest: Digest,
        model_digest: Digest,
        check_digest: Digest,
        tuple_query_digest: Digest,
        cursor_digest: Option<Digest>,
    ) -> Self {
        let path_digest = Digest::from_parts(
            "openfga-redacted-path/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("scope", scope_digest.to_string()),
                ("model", model_digest.to_string()),
                ("check", check_digest.to_string()),
                ("tuple_query", tuple_query_digest.to_string()),
                (
                    "cursor",
                    cursor_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
            ],
        );
        Self {
            operation,
            request_digest,
            path_digest,
            scope_digest,
            model_digest,
            check_digest,
            tuple_query_digest,
            cursor_digest,
            redacted: true,
        }
    }

    fn receipt(&self) -> RequestReceipt {
        RequestReceipt {
            operation: self.operation.as_str().to_owned(),
            request_digest: self.request_digest.clone(),
            path_digest: self.path_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            model_digest: self.model_digest.clone(),
            check_digest: self.check_digest.clone(),
            tuple_query_digest: self.tuple_query_digest.clone(),
            cursor_digest: self.cursor_digest.clone(),
            redacted: self.redacted,
        }
    }
}

fn cost_receipt(
    operation: OpenFgaOperation,
    response_bytes: u64,
    bounded_request_units: u16,
) -> CostReceipt {
    let cost_digest = Digest::from_parts(
        "openfga-cost/v1",
        &[
            ("operation", operation.as_str().to_owned()),
            ("bytes", response_bytes.to_string()),
            ("units", bounded_request_units.to_string()),
        ],
    );
    CostReceipt {
        operation: operation.as_str().to_owned(),
        response_bytes,
        bounded_request_units,
        cost_digest,
        redacted: true,
        estimate_only: true,
        durable_provider_receipt: false,
    }
}

pub trait OpenFgaTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read_model(
        &mut self,
        request: &ModelReadRequest,
    ) -> std::result::Result<ModelReadResponse, OpenFgaTransportError>;

    fn check(
        &mut self,
        request: &AuthorizationCheckRequest,
    ) -> std::result::Result<AuthorizationCheckResponse, OpenFgaTransportError>;

    fn read_tuples(
        &mut self,
        request: &TupleReadRequest,
    ) -> std::result::Result<TupleReadResponse, OpenFgaTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenFgaProviderDefinition {
    pub id: String,
    pub api_revision: String,
    pub provenance: TransportProvenance,
    pub operations: Vec<String>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub external_writes: bool,
    pub tuple_writes: bool,
    pub authorization_authority: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenFgaObservation {
    pub model: ModelEvidence,
    pub check: CheckEvidence,
    pub tuples: Vec<TupleEvidence>,
    pub tuple_complete: bool,
    pub provenance: TransportProvenance,
    pub request_receipts: Vec<RequestReceipt>,
    pub cost_receipts: Vec<CostReceipt>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenFgaProviderFailure {
    pub operation: OpenFgaOperation,
    pub error: OpenFgaTransportError,
    pub provenance: TransportProvenance,
    pub request_receipts: Vec<RequestReceipt>,
    pub cost_receipts: Vec<CostReceipt>,
}

impl OpenFgaProviderFailure {
    fn new(
        operation: OpenFgaOperation,
        error: OpenFgaTransportError,
        provenance: TransportProvenance,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
    ) -> Self {
        Self {
            operation,
            error,
            provenance,
            request_receipts,
            cost_receipts,
        }
    }
}

pub struct OpenFgaProvider<T> {
    transport: T,
    provider_digest: Digest,
}

impl<T: OpenFgaTransport> fmt::Debug for OpenFgaProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenFgaProvider")
            .field("provider_digest", &self.provider_digest)
            .field("provenance", &self.provenance())
            .finish()
    }
}

impl<T: OpenFgaTransport> OpenFgaProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        let provider_digest = Digest::from_parts(
            "openfga-provider/v1",
            &[
                ("id", PROVIDER_ID.to_owned()),
                ("api", PROVIDER_API_REVISION.to_owned()),
                ("provenance", transport.provenance().as_str().to_owned()),
            ],
        );
        Ok(Self {
            transport,
            provider_digest,
        })
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn definition(&self) -> OpenFgaProviderDefinition {
        OpenFgaProviderDefinition {
            id: PROVIDER_ID.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            provenance: self.provenance(),
            operations: vec![
                OpenFgaOperation::ReadAuthorizationModel.as_str().to_owned(),
                OpenFgaOperation::Check.as_str().to_owned(),
                OpenFgaOperation::ReadTuples.as_str().to_owned(),
            ],
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            external_writes: false,
            tuple_writes: false,
            authorization_authority: false,
        }
    }

    pub fn read_authorization_model(
        &mut self,
        request: &ModelReadRequest,
    ) -> std::result::Result<ModelReadResponse, OpenFgaTransportError> {
        let response = self.transport.read_model(request)?;
        response
            .validate(request, self.provenance())
            .map_err(|_| OpenFgaTransportError::Malformed)?;
        Ok(response)
    }

    pub fn check(
        &mut self,
        request: &AuthorizationCheckRequest,
    ) -> std::result::Result<AuthorizationCheckResponse, OpenFgaTransportError> {
        let response = self.transport.check(request)?;
        response
            .validate(request, self.provenance())
            .map_err(|_| OpenFgaTransportError::Malformed)?;
        Ok(response)
    }

    pub fn read_tuples(
        &mut self,
        request: &TupleReadRequest,
    ) -> std::result::Result<TupleReadResponse, OpenFgaTransportError> {
        let response = self.transport.read_tuples(request)?;
        response
            .validate(request, self.provenance())
            .map_err(|_| OpenFgaTransportError::Malformed)?;
        Ok(response)
    }

    pub fn observe(
        &mut self,
        model_request: &ModelReadRequest,
        check_request: &AuthorizationCheckRequest,
        tuple_request: &TupleReadRequest,
    ) -> std::result::Result<OpenFgaObservation, OpenFgaProviderFailure> {
        if model_request.scope().digest() != check_request.scope().digest()
            || model_request.scope().digest() != tuple_request.scope().digest()
            || check_request.check().user.digest() != tuple_request.tuple_scope().user.digest()
            || check_request.check().object.digest() != tuple_request.tuple_scope().object.digest()
            || check_request.check().relation.digest()
                != tuple_request.tuple_scope().relation.digest()
        {
            return Err(OpenFgaProviderFailure::new(
                OpenFgaOperation::ReadAuthorizationModel,
                OpenFgaTransportError::Malformed,
                self.provenance(),
                Vec::new(),
                Vec::new(),
            ));
        }
        let provenance = self.provenance();
        let mut request_receipts = Vec::new();
        let mut cost_receipts = Vec::new();

        let model_response = match self.transport.read_model(model_request) {
            Ok(response) => response,
            Err(error) => {
                request_receipts.push(model_request.recorded_request().receipt());
                return Err(OpenFgaProviderFailure::new(
                    OpenFgaOperation::ReadAuthorizationModel,
                    error,
                    provenance,
                    request_receipts,
                    cost_receipts,
                ));
            }
        };
        if model_response.validate(model_request, provenance).is_err() {
            request_receipts.push(model_request.recorded_request().receipt());
            return Err(OpenFgaProviderFailure::new(
                OpenFgaOperation::ReadAuthorizationModel,
                OpenFgaTransportError::Malformed,
                provenance,
                request_receipts,
                cost_receipts,
            ));
        }
        request_receipts.push(model_request.recorded_request().receipt());
        cost_receipts.push(cost_receipt(
            OpenFgaOperation::ReadAuthorizationModel,
            model_response.response_bytes,
            1,
        ));

        let check_response = match self.transport.check(check_request) {
            Ok(response) => response,
            Err(error) => {
                request_receipts.push(check_request.recorded_request().receipt());
                return Err(OpenFgaProviderFailure::new(
                    OpenFgaOperation::Check,
                    error,
                    provenance,
                    request_receipts,
                    cost_receipts,
                ));
            }
        };
        if check_response.validate(check_request, provenance).is_err() {
            request_receipts.push(check_request.recorded_request().receipt());
            return Err(OpenFgaProviderFailure::new(
                OpenFgaOperation::Check,
                OpenFgaTransportError::Malformed,
                provenance,
                request_receipts,
                cost_receipts,
            ));
        }
        if check_response.model_digest != model_response.model_digest {
            request_receipts.push(check_request.recorded_request().receipt());
            return Err(OpenFgaProviderFailure::new(
                OpenFgaOperation::Check,
                OpenFgaTransportError::Stale,
                provenance,
                request_receipts,
                cost_receipts,
            ));
        }
        request_receipts.push(check_request.recorded_request().receipt());
        cost_receipts.push(cost_receipt(
            OpenFgaOperation::Check,
            check_response.response_bytes,
            1,
        ));

        let mut current_request = tuple_request.clone();
        let mut seen_cursors = BTreeSet::new();
        let mut seen_tuples = BTreeSet::new();
        let mut tuples = Vec::new();
        let tuple_complete =
            loop {
                let tuple_response = match self.transport.read_tuples(&current_request) {
                    Ok(response) => response,
                    Err(error) => {
                        request_receipts.push(current_request.recorded_request().receipt());
                        return Err(OpenFgaProviderFailure::new(
                            OpenFgaOperation::ReadTuples,
                            error,
                            provenance,
                            request_receipts,
                            cost_receipts,
                        ));
                    }
                };
                if tuple_response
                    .validate(&current_request, provenance)
                    .is_err()
                {
                    request_receipts.push(current_request.recorded_request().receipt());
                    return Err(OpenFgaProviderFailure::new(
                        OpenFgaOperation::ReadTuples,
                        OpenFgaTransportError::Malformed,
                        provenance,
                        request_receipts,
                        cost_receipts,
                    ));
                }
                let response_bytes = tuple_response.response_bytes;
                if tuple_response
                    .tuples
                    .iter()
                    .any(|tuple| !seen_tuples.insert(tuple.digest()))
                {
                    request_receipts.push(current_request.recorded_request().receipt());
                    return Err(OpenFgaProviderFailure::new(
                        OpenFgaOperation::ReadTuples,
                        OpenFgaTransportError::Malformed,
                        provenance,
                        request_receipts,
                        cost_receipts,
                    ));
                }
                tuples.extend(tuple_response.tuples.iter().map(|tuple| {
                    TupleEvidence::new(tuple, current_request.tuple_scope().revision)
                }));
                if tuples.len() > MAX_TUPLES {
                    request_receipts.push(current_request.recorded_request().receipt());
                    return Err(OpenFgaProviderFailure::new(
                        OpenFgaOperation::ReadTuples,
                        OpenFgaTransportError::Partial,
                        provenance,
                        request_receipts,
                        cost_receipts,
                    ));
                }
                request_receipts.push(current_request.recorded_request().receipt());
                cost_receipts.push(cost_receipt(
                    OpenFgaOperation::ReadTuples,
                    response_bytes,
                    current_request.page_number(),
                ));
                if let Some(next_cursor) = tuple_response.next_cursor {
                    if current_request.page_number() >= MAX_PAGES
                        || next_cursor.page_number
                            != current_request.page_number().saturating_add(1)
                        || !seen_cursors.insert(next_cursor.cursor_digest.clone())
                    {
                        return Err(OpenFgaProviderFailure::new(
                            OpenFgaOperation::ReadTuples,
                            OpenFgaTransportError::Partial,
                            provenance,
                            request_receipts,
                            cost_receipts,
                        ));
                    }
                    current_request = match current_request.with_cursor(next_cursor) {
                        Ok(request) => request,
                        Err(_) => {
                            return Err(OpenFgaProviderFailure::new(
                                OpenFgaOperation::ReadTuples,
                                OpenFgaTransportError::Malformed,
                                provenance,
                                request_receipts,
                                cost_receipts,
                            ));
                        }
                    };
                } else {
                    break true;
                }
            };

        let model = model_response.evidence();
        let check = check_response.evidence();
        let tuple_digest = Digest::from_parts(
            "openfga-tuples/v1",
            &[
                (
                    "tuples",
                    tuples
                        .iter()
                        .map(|tuple| tuple.evidence_digest.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("complete", tuple_complete.to_string()),
            ],
        );
        let evidence_digest = Digest::from_parts(
            "openfga-observation/v1",
            &[
                ("model", model.evidence_digest.to_string()),
                ("check", check.check_digest.to_string()),
                ("tuples", tuple_digest.to_string()),
                ("provenance", provenance.as_str().to_owned()),
            ],
        );
        Ok(OpenFgaObservation {
            model,
            check,
            tuples,
            tuple_complete,
            provenance,
            request_receipts,
            cost_receipts,
            evidence_digest,
        })
    }
}

#[derive(Clone, Debug)]
struct FixtureState {
    scope_digest: Digest,
    rules_digest: Digest,
    decision: AuthorizationDecision,
}

impl FixtureState {
    fn new(scope: &OpenFgaScope, decision: AuthorizationDecision) -> Result<Self> {
        Ok(Self {
            scope_digest: scope.digest(),
            rules_digest: Digest::from_text("openfga-fixture-rules/v1"),
            decision,
        })
    }

    fn validate_scope(
        &self,
        scope: &OpenFgaScope,
    ) -> std::result::Result<(), OpenFgaTransportError> {
        if self.scope_digest == scope.digest() {
            Ok(())
        } else {
            Err(OpenFgaTransportError::Conflict)
        }
    }

    fn model(
        &self,
        request: &ModelReadRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<ModelReadResponse, OpenFgaTransportError> {
        ModelReadResponse::new(request, 3, 5, self.rules_digest.clone(), 512, provenance)
            .map_err(|_| OpenFgaTransportError::Malformed)
    }

    fn check(
        &self,
        request: &AuthorizationCheckRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<AuthorizationCheckResponse, OpenFgaTransportError> {
        let model_digest = request.scope().authorization_model().digest();
        AuthorizationCheckResponse::new(request, self.decision, model_digest, 384, provenance)
            .map_err(|_| OpenFgaTransportError::Malformed)
    }

    fn tuples(
        request: &TupleReadRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<TupleReadResponse, OpenFgaTransportError> {
        let tuple = TupleKey::new(
            request.tuple_scope().user.raw().to_owned(),
            request.tuple_scope().relation.raw().to_owned(),
            request.tuple_scope().object.raw().to_owned(),
        )
        .map_err(|_| OpenFgaTransportError::Malformed)?;
        TupleReadResponse::new(request, vec![tuple], None, 256, provenance)
            .map_err(|_| OpenFgaTransportError::Malformed)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    state: FixtureState,
}

impl FixtureTransport {
    pub fn for_scope(scope: &OpenFgaScope, _observed_at: DateTime<Utc>) -> Result<Self> {
        Ok(Self {
            state: FixtureState::new(scope, AuthorizationDecision::Allowed)?,
        })
    }

    pub fn for_scope_default(scope: &OpenFgaScope) -> Result<Self> {
        Self::for_scope(scope, Utc::now())
    }

    pub fn with_decision(scope: &OpenFgaScope, decision: AuthorizationDecision) -> Result<Self> {
        Ok(Self {
            state: FixtureState::new(scope, decision)?,
        })
    }
}

impl Default for FixtureTransport {
    fn default() -> Self {
        let scope = OpenFgaScope::from_parts(
            "store:fixture",
            1,
            "model:fixture",
            1,
            "project:fixture",
            1,
            "mission:fixture",
            1,
            "work-product:fixture",
            1,
        )
        .expect("fixture scope");
        Self::for_scope(&scope, Utc::now()).expect("fixture transport")
    }
}

impl OpenFgaTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn read_model(
        &mut self,
        request: &ModelReadRequest,
    ) -> std::result::Result<ModelReadResponse, OpenFgaTransportError> {
        self.state.validate_scope(request.scope())?;
        self.state.model(request, self.provenance())
    }

    fn check(
        &mut self,
        request: &AuthorizationCheckRequest,
    ) -> std::result::Result<AuthorizationCheckResponse, OpenFgaTransportError> {
        self.state.validate_scope(request.scope())?;
        self.state.check(request, self.provenance())
    }

    fn read_tuples(
        &mut self,
        request: &TupleReadRequest,
    ) -> std::result::Result<TupleReadResponse, OpenFgaTransportError> {
        self.state.validate_scope(request.scope())?;
        FixtureState::tuples(request, self.provenance())
    }
}

#[derive(Clone, Debug)]
pub struct FakeTransport {
    state: FixtureState,
}

impl FakeTransport {
    pub fn for_scope(scope: &OpenFgaScope, _observed_at: DateTime<Utc>) -> Result<Self> {
        Self::with_decision(scope, AuthorizationDecision::Allowed)
    }

    pub fn for_scope_default(scope: &OpenFgaScope) -> Result<Self> {
        Self::for_scope(scope, Utc::now())
    }

    pub fn with_decision(scope: &OpenFgaScope, decision: AuthorizationDecision) -> Result<Self> {
        Ok(Self {
            state: FixtureState::new(scope, decision)?,
        })
    }
}

impl Default for FakeTransport {
    fn default() -> Self {
        Self {
            state: FixtureState::new(
                &OpenFgaScope::from_parts(
                    "store:fake",
                    1,
                    "model:fake",
                    1,
                    "project:fake",
                    1,
                    "mission:fake",
                    1,
                    "work-product:fake",
                    1,
                )
                .expect("fake scope"),
                AuthorizationDecision::Allowed,
            )
            .expect("fake state"),
        }
    }
}

impl OpenFgaTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn read_model(
        &mut self,
        request: &ModelReadRequest,
    ) -> std::result::Result<ModelReadResponse, OpenFgaTransportError> {
        self.state.validate_scope(request.scope())?;
        self.state.model(request, self.provenance())
    }

    fn check(
        &mut self,
        request: &AuthorizationCheckRequest,
    ) -> std::result::Result<AuthorizationCheckResponse, OpenFgaTransportError> {
        self.state.validate_scope(request.scope())?;
        self.state.check(request, self.provenance())
    }

    fn read_tuples(
        &mut self,
        request: &TupleReadRequest,
    ) -> std::result::Result<TupleReadResponse, OpenFgaTransportError> {
        self.state.validate_scope(request.scope())?;
        FixtureState::tuples(request, self.provenance())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    state: FixtureState,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &OpenFgaScope, _observed_at: DateTime<Utc>) -> Result<Self> {
        Ok(Self {
            state: FixtureState::new(scope, AuthorizationDecision::Allowed)?,
        })
    }

    pub fn for_scope_default(scope: &OpenFgaScope) -> Result<Self> {
        Self::for_scope(scope, Utc::now())
    }
}

impl Default for LoopbackTransport {
    fn default() -> Self {
        Self {
            state: FixtureState::new(
                &OpenFgaScope::from_parts(
                    "store:loopback",
                    1,
                    "model:loopback",
                    1,
                    "project:loopback",
                    1,
                    "mission:loopback",
                    1,
                    "work-product:loopback",
                    1,
                )
                .expect("loopback scope"),
                AuthorizationDecision::Allowed,
            )
            .expect("loopback state"),
        }
    }
}

impl OpenFgaTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read_model(
        &mut self,
        request: &ModelReadRequest,
    ) -> std::result::Result<ModelReadResponse, OpenFgaTransportError> {
        self.state.validate_scope(request.scope())?;
        self.state.model(request, self.provenance())
    }

    fn check(
        &mut self,
        request: &AuthorizationCheckRequest,
    ) -> std::result::Result<AuthorizationCheckResponse, OpenFgaTransportError> {
        self.state.validate_scope(request.scope())?;
        self.state.check(request, self.provenance())
    }

    fn read_tuples(
        &mut self,
        request: &TupleReadRequest,
    ) -> std::result::Result<TupleReadResponse, OpenFgaTransportError> {
        self.state.validate_scope(request.scope())?;
        FixtureState::tuples(request, self.provenance())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvTransport;

impl OpenFgaTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_model(
        &mut self,
        _request: &ModelReadRequest,
    ) -> std::result::Result<ModelReadResponse, OpenFgaTransportError> {
        Err(OpenFgaTransportError::BlockedEnvironment(
            crate::BLOCKED_ENV,
        ))
    }

    fn check(
        &mut self,
        _request: &AuthorizationCheckRequest,
    ) -> std::result::Result<AuthorizationCheckResponse, OpenFgaTransportError> {
        Err(OpenFgaTransportError::BlockedEnvironment(
            crate::BLOCKED_ENV,
        ))
    }

    fn read_tuples(
        &mut self,
        _request: &TupleReadRequest,
    ) -> std::result::Result<TupleReadResponse, OpenFgaTransportError> {
        Err(OpenFgaTransportError::BlockedEnvironment(
            crate::BLOCKED_ENV,
        ))
    }
}

#[derive(Debug, Default)]
pub struct RecordingTransport {
    model_responses: VecDeque<std::result::Result<ModelReadResponse, OpenFgaTransportError>>,
    check_responses:
        VecDeque<std::result::Result<AuthorizationCheckResponse, OpenFgaTransportError>>,
    tuple_responses: VecDeque<std::result::Result<TupleReadResponse, OpenFgaTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn push_model_response(
        &mut self,
        response: std::result::Result<ModelReadResponse, OpenFgaTransportError>,
    ) {
        self.model_responses.push_back(response);
    }

    pub fn push_check_response(
        &mut self,
        response: std::result::Result<AuthorizationCheckResponse, OpenFgaTransportError>,
    ) {
        self.check_responses.push_back(response);
    }

    pub fn push_tuple_response(
        &mut self,
        response: std::result::Result<TupleReadResponse, OpenFgaTransportError>,
    ) {
        self.tuple_responses.push_back(response);
    }

    #[must_use]
    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl OpenFgaTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn read_model(
        &mut self,
        request: &ModelReadRequest,
    ) -> std::result::Result<ModelReadResponse, OpenFgaTransportError> {
        self.requests.push(request.recorded_request());
        self.model_responses
            .pop_front()
            .unwrap_or(Err(OpenFgaTransportError::NoRecording))
    }

    fn check(
        &mut self,
        request: &AuthorizationCheckRequest,
    ) -> std::result::Result<AuthorizationCheckResponse, OpenFgaTransportError> {
        self.requests.push(request.recorded_request());
        self.check_responses
            .pop_front()
            .unwrap_or(Err(OpenFgaTransportError::NoRecording))
    }

    fn read_tuples(
        &mut self,
        request: &TupleReadRequest,
    ) -> std::result::Result<TupleReadResponse, OpenFgaTransportError> {
        self.requests.push(request.recorded_request());
        self.tuple_responses
            .pop_front()
            .unwrap_or(Err(OpenFgaTransportError::NoRecording))
    }
}
