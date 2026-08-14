//! Recording-only Shopify Admin provider boundary.
//!
//! The provider accepts a borrowed response body, projects the allowlisted
//! fields, and drops the bytes before returning. No HTTP client, token
//! resolver, mutation operation, or native Connected state exists here.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    Digest, FulfillmentOrderProjection, FulfillmentProjection, FulfillmentState,
    MAX_FULFILLMENT_ORDERS, MAX_FULFILLMENTS, MAX_REFUNDS, MAX_RESPONSE_BYTES,
    MAX_RETRY_AFTER_MILLISECONDS, MAX_TRANSACTIONS, Money, PAGE_SIZE, PartialReason,
    ProjectionState, ProviderRevision, RefundProjection, RetryEvidence, RevisionStamp, ShopifyId,
    ShopifyOrderProjection, ShopifyOrderProjectionInput, TransactionProjection, TransactionState,
    provider_revision_digest,
};
use crate::service::ShopifyOrderReadProposal;
use crate::{
    Layer1Authority, SHOPIFY_ADMIN_API_VERSION, SHOPIFY_ADMIN_PROVIDER_ID,
    SHOPIFY_ADMIN_PROVIDER_NAME, SHOPIFY_ORDER_RESULT_CONTRACT_JSON,
    SHOPIFY_ORDER_RESULT_PLUGIN_VERSION, SHOPIFY_ORDER_RESULT_QUERY_DOCUMENT,
    SHOPIFY_ORDER_RESULT_SCHEMA_VERSION,
};

pub const SHOPIFY_PROVIDER_REVISION: &str = "shopify-admin-graphql-2026-07-r1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderMode {
    pub const fn provenance(self) -> ProviderProvenance {
        match self {
            Self::Fixture => ProviderProvenance::Fixture,
            Self::Recording => ProviderProvenance::Recording,
            Self::Loopback => ProviderProvenance::Loopback,
            Self::BlockedEnv => ProviderProvenance::BlockedEnv,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyAdminProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub implementation: String,
    pub provider_version: String,
    pub api_version: String,
    pub query_digest: Digest,
    pub contract_digest: Digest,
    pub implementation_digest: Digest,
    pub provider_digest: Digest,
    pub provenance: ProviderProvenance,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub mutating_operations: Vec<String>,
}

impl ShopifyAdminProviderDefinition {
    pub fn new(mode: ProviderMode) -> Self {
        let query_digest = Digest::sha256(SHOPIFY_ORDER_RESULT_QUERY_DOCUMENT.as_bytes());
        let contract_digest = Digest::sha256(SHOPIFY_ORDER_RESULT_CONTRACT_JSON.as_bytes());
        let implementation_digest = Digest::from_fields(
            "hartevo:shopify-admin-provider-implementation/v1",
            &[
                SHOPIFY_ADMIN_PROVIDER_NAME.to_owned(),
                SHOPIFY_ADMIN_API_VERSION.to_owned(),
                query_digest.as_str().to_owned(),
                "no_native_transport".to_owned(),
                "no_mutations".to_owned(),
                "no_raw_body_retention".to_owned(),
            ],
        );
        let provider_digest = Digest::from_fields(
            "hartevo:shopify-admin-provider/v1",
            &[
                SHOPIFY_ADMIN_PROVIDER_ID.to_owned(),
                SHOPIFY_ORDER_RESULT_PLUGIN_VERSION.to_owned(),
                SHOPIFY_ADMIN_API_VERSION.to_owned(),
                mode.provenance().to_string(),
                query_digest.as_str().to_owned(),
                contract_digest.as_str().to_owned(),
                implementation_digest.as_str().to_owned(),
            ],
        );
        Self {
            schema_version: SHOPIFY_ORDER_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: SHOPIFY_ADMIN_PROVIDER_ID.to_owned(),
            implementation: SHOPIFY_ADMIN_PROVIDER_NAME.to_owned(),
            provider_version: SHOPIFY_ORDER_RESULT_PLUGIN_VERSION.to_owned(),
            api_version: SHOPIFY_ADMIN_API_VERSION.to_owned(),
            query_digest,
            contract_digest,
            implementation_digest,
            provider_digest,
            provenance: mode.provenance(),
            native: false,
            connected: false,
            first_party: false,
            external_writes: false,
            mutating_operations: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), ShopifyProviderError> {
        if self.provider_id != SHOPIFY_ADMIN_PROVIDER_ID
            || self.implementation != SHOPIFY_ADMIN_PROVIDER_NAME
            || self.api_version != SHOPIFY_ADMIN_API_VERSION
            || self.provider_version != SHOPIFY_ORDER_RESULT_PLUGIN_VERSION
            || self.native
            || self.connected
            || self.first_party
            || self.external_writes
            || !self.mutating_operations.is_empty()
        {
            return Err(ShopifyProviderError::DefinitionDrift);
        }
        Ok(())
    }
}

impl fmt::Display for ProviderProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        })
    }
}

/// Response metadata is safe to retain: identifiers are hashed and provider
/// bodies are never copied into it.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseMetadata {
    pub request_id_digest: Option<Digest>,
    pub rate_limit_remaining: Option<u32>,
    pub retry_after_milliseconds: Option<u64>,
    pub attempt: u8,
}

impl ResponseMetadata {
    pub fn new(
        request_id: Option<&str>,
        rate_limit_remaining: Option<u32>,
        retry_after_milliseconds: Option<u64>,
        attempt: u8,
    ) -> Result<Self, ShopifyProviderError> {
        if attempt > crate::model::MAX_RETRY_ATTEMPTS {
            return Err(ShopifyProviderError::RetryLimitExceeded);
        }
        if retry_after_milliseconds.is_some_and(|value| value > MAX_RETRY_AFTER_MILLISECONDS) {
            return Err(ShopifyProviderError::RetryAfterExceeded);
        }
        Ok(Self {
            request_id_digest: request_id.map(Digest::from_text),
            rate_limit_remaining,
            retry_after_milliseconds,
            attempt,
        })
    }

    pub fn fixture() -> Self {
        Self {
            request_id_digest: None,
            rate_limit_remaining: None,
            retry_after_milliseconds: None,
            attempt: 0,
        }
    }
}

/// Borrowed GraphQL response envelope. It intentionally cannot be serialized
/// and its Debug output exposes only response metadata and a digest.
pub struct GraphqlResponse<'a> {
    status: u16,
    body: &'a [u8],
    metadata: ResponseMetadata,
}

impl<'a> GraphqlResponse<'a> {
    pub fn new(status: u16, body: &'a [u8]) -> Self {
        Self {
            status,
            body,
            metadata: ResponseMetadata::fixture(),
        }
    }

    #[must_use]
    pub fn with_metadata(mut self, metadata: ResponseMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub fn body_digest(&self) -> Digest {
        Digest::sha256(self.body)
    }

    pub const fn body_size_bytes(&self) -> usize {
        self.body.len()
    }

    pub const fn metadata(&self) -> &ResponseMetadata {
        &self.metadata
    }
}

impl fmt::Debug for GraphqlResponse<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GraphqlResponse")
            .field("status", &self.status)
            .field("body_size_bytes", &self.body.len())
            .field("body_digest", &self.body_digest())
            .field("metadata", &self.metadata)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedEnvReason {
    NativeCredentialResolutionUnavailable,
    NativeTransportUnavailable,
    NativeReceiptUnavailable,
    PermissionExpired,
}

impl BlockedEnvReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::NativeCredentialResolutionUnavailable => {
                "native_credential_resolution_unavailable"
            }
            Self::NativeTransportUnavailable => "native_transport_unavailable",
            Self::NativeReceiptUnavailable => "native_receipt_unavailable",
            Self::PermissionExpired => "permission_expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureClass {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    Graphql,
    Malformed,
    ResponseTooLarge,
    BlockedEnv,
    PermissionExpired,
    ScopeMismatch,
    UnexpectedStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderFailure {
    pub class: ProviderFailureClass,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub diagnostic_digest: Digest,
    pub retry_after_milliseconds: Option<u64>,
    pub blocked_env: bool,
}

impl ProviderFailure {
    fn new(
        class: ProviderFailureClass,
        status_code: Option<u16>,
        retryable: bool,
        diagnostic: impl AsRef<str>,
        retry_after_milliseconds: Option<u64>,
        blocked_env: bool,
    ) -> Self {
        Self {
            class,
            status_code,
            retryable,
            diagnostic_digest: Digest::from_text(diagnostic.as_ref()),
            retry_after_milliseconds,
            blocked_env,
        }
    }

    pub fn class(&self) -> ProviderFailureClass {
        self.class
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseReceipt {
    pub response_status: Option<u16>,
    pub response_size_bytes: usize,
    pub response_digest: Digest,
    pub request_id_digest: Option<Digest>,
    pub rate_limit_remaining: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageInfo {
    pub has_next_page: bool,
    pub end_cursor_digest: Option<Digest>,
}

impl PageInfo {
    pub const fn complete() -> Self {
        Self {
            has_next_page: false,
            end_cursor_digest: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDisposition {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
    ProviderFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShopifyOrderEvidence {
    pub provenance: ProviderProvenance,
    pub disposition: EvidenceDisposition,
    pub projection_state: ProjectionState,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub provider_revision_digest: Digest,
    pub response: ResponseReceipt,
    pub page_info: PageInfo,
    pub projection: Option<ShopifyOrderProjection>,
    pub failure: Option<ProviderFailure>,
    pub partial_reasons: Vec<PartialReason>,
    pub retry: Option<RetryEvidence>,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_native_receipt: bool,
    pub independent_read_back: bool,
    pub verified_work_product_adoption: bool,
}

#[derive(Clone, Debug, Serialize)]
struct EvidenceFingerprint<'a> {
    provenance: ProviderProvenance,
    disposition: EvidenceDisposition,
    projection_state: ProjectionState,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    registration_digest: &'a Digest,
    provider_digest: &'a Digest,
    provider_revision: &'a ProviderRevision,
    provider_revision_digest: &'a Digest,
    response: &'a ResponseReceipt,
    page_info: &'a PageInfo,
    projection: &'a Option<ShopifyOrderProjection>,
    failure: &'a Option<ProviderFailure>,
    partial_reasons: &'a [PartialReason],
    retry: &'a Option<RetryEvidence>,
}

impl ShopifyOrderEvidence {
    fn new(
        provenance: ProviderProvenance,
        disposition: EvidenceDisposition,
        projection_state: ProjectionState,
        proposal: &ShopifyOrderReadProposal,
        provider_definition: &ShopifyAdminProviderDefinition,
        response: ResponseReceipt,
        page_info: PageInfo,
        projection: Option<ShopifyOrderProjection>,
        failure: Option<ProviderFailure>,
        partial_reasons: Vec<PartialReason>,
        retry: Option<RetryEvidence>,
    ) -> Self {
        let provider_revision = ProviderRevision::new(SHOPIFY_PROVIDER_REVISION)
            .expect("static Shopify provider revision");
        let provider_revision_digest = provider_revision_digest(&provider_revision);
        let mut evidence = Self {
            provenance,
            disposition,
            projection_state,
            scope_digest: proposal.scope_digest().clone(),
            permission_digest: proposal.permission_digest().clone(),
            registration_digest: proposal.registration_digest().clone(),
            provider_digest: provider_definition.provider_digest.clone(),
            provider_revision,
            provider_revision_digest,
            response,
            page_info,
            projection,
            failure,
            partial_reasons,
            retry,
            evidence_digest: Digest::from_text("uncomputed"),
            connected: false,
            native: false,
            first_party: false,
            durable_native_receipt: false,
            independent_read_back: false,
            verified_work_product_adoption: false,
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&EvidenceFingerprint {
            provenance: self.provenance,
            disposition: self.disposition,
            projection_state: self.projection_state,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            provider_revision: &self.provider_revision,
            provider_revision_digest: &self.provider_revision_digest,
            response: &self.response,
            page_info: &self.page_info,
            projection: &self.projection,
            failure: &self.failure,
            partial_reasons: &self.partial_reasons,
            retry: &self.retry,
        })
    }

    pub fn verify_digest(&self) -> bool {
        self.evidence_digest == self.compute_digest()
            && self
                .projection
                .as_ref()
                .is_none_or(ShopifyOrderProjection::verify_revision_digest)
    }

    pub const fn authority(&self) -> Layer1Authority {
        Layer1Authority
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self.projection_state, ProjectionState::Complete)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ShopifyProviderError {
    #[error("provider definition drifted from the Layer-1 baseline")]
    DefinitionDrift,
    #[error("read proposal is invalid or tampered")]
    ProposalTampered,
    #[error("provider response body exceeds the Layer-1 response bound")]
    ResponseTooLarge,
    #[error("provider response is malformed: {0}")]
    MalformedResponse(&'static str),
    #[error("provider response has an invalid scope")]
    ScopeMismatch,
    #[error("retry attempt exceeds the Layer-1 retry bound")]
    RetryLimitExceeded,
    #[error("retry-after exceeds the Layer-1 bound")]
    RetryAfterExceeded,
    #[error("page request exceeds the Layer-1 pagination bound")]
    PaginationBoundExceeded,
    #[error("provider response collection is malformed")]
    CollectionMalformed,
}

#[derive(Clone, Debug)]
pub struct ShopifyAdminProvider {
    definition: ShopifyAdminProviderDefinition,
    max_response_bytes: usize,
    max_pages: u16,
    page_size: u16,
}

impl ShopifyAdminProvider {
    pub fn new(mode: ProviderMode) -> Result<Self, ShopifyProviderError> {
        let definition = ShopifyAdminProviderDefinition::new(mode);
        definition.validate()?;
        Ok(Self {
            definition,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_pages: crate::model::MAX_PAGES,
            page_size: PAGE_SIZE,
        })
    }

    pub fn fixture() -> Result<Self, ShopifyProviderError> {
        Self::new(ProviderMode::Fixture)
    }

    pub fn recording() -> Result<Self, ShopifyProviderError> {
        Self::new(ProviderMode::Recording)
    }

    pub fn loopback() -> Result<Self, ShopifyProviderError> {
        Self::new(ProviderMode::Loopback)
    }

    pub fn blocked_env() -> Result<Self, ShopifyProviderError> {
        Self::new(ProviderMode::BlockedEnv)
    }

    pub fn definition(&self) -> &ShopifyAdminProviderDefinition {
        &self.definition
    }

    pub fn mode(&self) -> ProviderMode {
        match self.definition.provenance {
            ProviderProvenance::Fixture => ProviderMode::Fixture,
            ProviderProvenance::Recording => ProviderMode::Recording,
            ProviderProvenance::Loopback => ProviderMode::Loopback,
            ProviderProvenance::BlockedEnv => ProviderMode::BlockedEnv,
        }
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.definition.provider_digest
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.definition.implementation_digest
    }

    pub fn with_response_bound(
        mut self,
        max_response_bytes: usize,
    ) -> Result<Self, ShopifyProviderError> {
        if max_response_bytes == 0 || max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(ShopifyProviderError::ResponseTooLarge);
        }
        self.max_response_bytes = max_response_bytes;
        Ok(self)
    }

    pub fn record_order_response(
        &self,
        proposal: &ShopifyOrderReadProposal,
        response: GraphqlResponse<'_>,
    ) -> Result<ShopifyOrderEvidence, ShopifyProviderError> {
        self.definition.validate()?;
        if !proposal.verify_digest() {
            return Err(ShopifyProviderError::ProposalTampered);
        }
        if proposal.page_number() > self.max_pages || proposal.page_size() > self.page_size {
            return Err(ShopifyProviderError::PaginationBoundExceeded);
        }
        if self.definition.provenance == ProviderProvenance::BlockedEnv {
            return self.record_blocked_env(proposal, BlockedEnvReason::NativeTransportUnavailable);
        }
        let response_receipt = ResponseReceipt {
            response_status: Some(response.status),
            response_size_bytes: response.body.len(),
            response_digest: response.body_digest(),
            request_id_digest: response.metadata.request_id_digest.clone(),
            rate_limit_remaining: response.metadata.rate_limit_remaining,
        };
        let retry = retry_evidence(&response.metadata)?;
        if response.body.len() > self.max_response_bytes {
            return Ok(ShopifyOrderEvidence::new(
                self.definition.provenance,
                EvidenceDisposition::ProviderFailure,
                ProjectionState::ProviderUnknown,
                proposal,
                &self.definition,
                response_receipt,
                PageInfo::complete(),
                None,
                Some(ProviderFailure::new(
                    ProviderFailureClass::ResponseTooLarge,
                    Some(response.status),
                    false,
                    "response_too_large",
                    response.metadata.retry_after_milliseconds,
                    false,
                )),
                vec![],
                retry,
            ));
        }
        if response.status != 200 {
            let (class, state, retryable) = status_failure(response.status);
            return Ok(ShopifyOrderEvidence::new(
                self.definition.provenance,
                EvidenceDisposition::ProviderFailure,
                state,
                proposal,
                &self.definition,
                response_receipt,
                PageInfo::complete(),
                None,
                Some(ProviderFailure::new(
                    class,
                    Some(response.status),
                    retryable,
                    format!("http_status_{}", response.status),
                    response.metadata.retry_after_milliseconds,
                    false,
                )),
                vec![],
                retry,
            ));
        }

        let value = serde_json::from_slice::<Value>(response.body)
            .map_err(|_| ShopifyProviderError::MalformedResponse("invalid JSON"))?;
        let graphql_errors = graphql_error_summary(value.get("errors"));
        let data = value
            .get("data")
            .ok_or(ShopifyProviderError::MalformedResponse("missing data"))?;
        let order = data.get("order");
        let Some(order) = order else {
            return Err(ShopifyProviderError::MalformedResponse("missing order"));
        };
        if order.is_null() {
            let failure = ProviderFailure::new(
                ProviderFailureClass::NotFound,
                Some(404),
                false,
                "order_not_found_or_deleted",
                None,
                false,
            );
            return Ok(ShopifyOrderEvidence::new(
                self.definition.provenance,
                EvidenceDisposition::ProviderFailure,
                ProjectionState::Deleted,
                proposal,
                &self.definition,
                response_receipt,
                PageInfo::complete(),
                None,
                Some(failure),
                graphql_errors
                    .map(|_| vec![PartialReason::GraphqlErrors])
                    .unwrap_or_default(),
                retry,
            ));
        }
        let expected_order_id =
            ShopifyId::new(proposal.order_id()).map_err(|_| ShopifyProviderError::ScopeMismatch)?;
        let (projection, page_info, mut partial_reasons) = parse_order(order, &expected_order_id)?;
        if graphql_errors.is_some() {
            partial_reasons.push(PartialReason::GraphqlErrors);
        }
        let state = if partial_reasons.is_empty() {
            ProjectionState::Complete
        } else {
            ProjectionState::Partial
        };
        let disposition = if partial_reasons.is_empty() {
            match self.definition.provenance {
                ProviderProvenance::Fixture => EvidenceDisposition::Fixture,
                ProviderProvenance::Recording => EvidenceDisposition::Recording,
                ProviderProvenance::Loopback => EvidenceDisposition::Loopback,
                ProviderProvenance::BlockedEnv => EvidenceDisposition::BlockedEnv,
            }
        } else {
            EvidenceDisposition::ProviderFailure
        };
        let failure = graphql_errors.map(|summary| {
            ProviderFailure::new(
                ProviderFailureClass::Graphql,
                Some(response.status),
                false,
                format!("graphql_errors_{}", summary.count),
                None,
                false,
            )
        });
        Ok(ShopifyOrderEvidence::new(
            self.definition.provenance,
            disposition,
            state,
            proposal,
            &self.definition,
            response_receipt,
            page_info,
            Some(projection),
            failure,
            partial_reasons,
            retry,
        ))
    }

    pub fn record_blocked_env(
        &self,
        proposal: &ShopifyOrderReadProposal,
        reason: BlockedEnvReason,
    ) -> Result<ShopifyOrderEvidence, ShopifyProviderError> {
        self.definition.validate()?;
        if !proposal.verify_digest() {
            return Err(ShopifyProviderError::ProposalTampered);
        }
        let response_digest = Digest::from_text(format!("BLOCKED_ENV:{}", reason.as_str()));
        let response = ResponseReceipt {
            response_status: None,
            response_size_bytes: 0,
            response_digest,
            request_id_digest: None,
            rate_limit_remaining: None,
        };
        let class = if matches!(reason, BlockedEnvReason::PermissionExpired) {
            ProviderFailureClass::PermissionExpired
        } else {
            ProviderFailureClass::BlockedEnv
        };
        let state = if matches!(reason, BlockedEnvReason::PermissionExpired) {
            ProjectionState::Expired
        } else {
            ProjectionState::BlockedEnv
        };
        Ok(ShopifyOrderEvidence::new(
            ProviderProvenance::BlockedEnv,
            EvidenceDisposition::BlockedEnv,
            state,
            proposal,
            &self.definition,
            response,
            PageInfo::complete(),
            None,
            Some(ProviderFailure::new(
                class,
                None,
                false,
                reason.as_str(),
                None,
                true,
            )),
            vec![],
            None,
        ))
    }
}

fn retry_evidence(
    metadata: &ResponseMetadata,
) -> Result<Option<RetryEvidence>, ShopifyProviderError> {
    if metadata.attempt > crate::model::MAX_RETRY_ATTEMPTS {
        return Err(ShopifyProviderError::RetryLimitExceeded);
    }
    let Some(retry_after) = metadata.retry_after_milliseconds else {
        return Ok((metadata.attempt > 0).then(|| RetryEvidence {
            attempt: metadata.attempt,
            retry_after_milliseconds: None,
            backoff_milliseconds: backoff_milliseconds(metadata.attempt),
        }));
    };
    if retry_after > MAX_RETRY_AFTER_MILLISECONDS {
        return Err(ShopifyProviderError::RetryAfterExceeded);
    }
    Ok(Some(RetryEvidence {
        attempt: metadata.attempt,
        retry_after_milliseconds: Some(retry_after),
        backoff_milliseconds: backoff_milliseconds(metadata.attempt),
    }))
}

fn backoff_milliseconds(attempt: u8) -> u64 {
    let exponent = u32::from(attempt.min(10));
    250_u64
        .saturating_mul(2_u64.saturating_pow(exponent))
        .min(MAX_RETRY_AFTER_MILLISECONDS)
}

fn status_failure(status: u16) -> (ProviderFailureClass, ProjectionState, bool) {
    match status {
        401 => (
            ProviderFailureClass::Unauthorized,
            ProjectionState::AccessLost,
            false,
        ),
        403 => (
            ProviderFailureClass::Forbidden,
            ProjectionState::AccessLost,
            false,
        ),
        404 => (
            ProviderFailureClass::NotFound,
            ProjectionState::Deleted,
            false,
        ),
        409 => (
            ProviderFailureClass::Conflict,
            ProjectionState::Conflict,
            true,
        ),
        429 => (
            ProviderFailureClass::RateLimited,
            ProjectionState::RateLimited,
            true,
        ),
        500..=599 => (
            ProviderFailureClass::ServerFailure,
            ProjectionState::ProviderUnknown,
            true,
        ),
        _ => (
            ProviderFailureClass::UnexpectedStatus,
            ProjectionState::ProviderUnknown,
            false,
        ),
    }
}

#[derive(Clone, Copy, Debug)]
struct GraphqlErrorSummary {
    count: usize,
}

fn graphql_error_summary(value: Option<&Value>) -> Option<GraphqlErrorSummary> {
    let errors = value?.as_array()?;
    if errors.is_empty() {
        None
    } else {
        Some(GraphqlErrorSummary {
            count: errors.len(),
        })
    }
}

fn parse_order(
    order: &Value,
    expected_order_id: &ShopifyId,
) -> Result<(ShopifyOrderProjection, PageInfo, Vec<PartialReason>), ShopifyProviderError> {
    let order_id = string_value(order, "id")
        .ok_or(ShopifyProviderError::MalformedResponse("order id missing"))?;
    let order_id = ShopifyId::new(order_id).map_err(|_| ShopifyProviderError::ScopeMismatch)?;
    if &order_id != expected_order_id {
        return Err(ShopifyProviderError::ScopeMismatch);
    }
    let updated_at = string_value(order, "updatedAt").ok_or(
        ShopifyProviderError::MalformedResponse("order updatedAt missing"),
    )?;
    let updated_at = RevisionStamp::new(updated_at)
        .map_err(|_| ShopifyProviderError::MalformedResponse("order updatedAt invalid"))?;
    let created_at = optional_stamp(order, "createdAt");
    let mut partial_reasons = Vec::new();
    let currency_code = safe_currency(string_value(order, "currencyCode"), &mut partial_reasons);
    let financial_state = transaction_state(
        string_value(order, "displayFinancialStatus").as_deref(),
        &mut partial_reasons,
    );
    let fulfillment_state = fulfillment_state(
        string_value(order, "displayFulfillmentStatus").as_deref(),
        &mut partial_reasons,
    );
    let current_total = optional_money(order.get("currentTotalPriceSet"), &mut partial_reasons);
    let total_refunded = optional_money(order.get("totalRefundedSet"), &mut partial_reasons);

    let (fulfillment_orders, page_info) =
        parse_fulfillment_orders(order.get("fulfillmentOrders"), &mut partial_reasons)?;
    let fulfillments = parse_fulfillments(order.get("fulfillments"), &mut partial_reasons)?;
    let refunds = parse_refunds(order.get("refunds"), &mut partial_reasons)?;
    let transactions = parse_transactions(order.get("transactions"), &mut partial_reasons)?;

    let projection = ShopifyOrderProjection::new(ShopifyOrderProjectionInput {
        order_id,
        updated_at,
        created_at,
        currency_code,
        financial_state,
        fulfillment_state,
        current_total,
        total_refunded,
        fulfillment_orders,
        fulfillments,
        refunds,
        transactions,
        partial_reasons: partial_reasons.clone(),
    });
    Ok((projection, page_info, partial_reasons))
}

fn parse_fulfillment_orders(
    value: Option<&Value>,
    partial_reasons: &mut Vec<PartialReason>,
) -> Result<(Vec<FulfillmentOrderProjection>, PageInfo), ShopifyProviderError> {
    let Some(connection) = value else {
        partial_reasons.push(PartialReason::MissingField);
        return Ok((Vec::new(), PageInfo::complete()));
    };
    let nodes = connection
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or(ShopifyProviderError::CollectionMalformed)?;
    let mut projections = Vec::new();
    for node in nodes.iter().take(MAX_FULFILLMENT_ORDERS) {
        let Some(id) = string_value(node, "id") else {
            partial_reasons.push(PartialReason::MissingField);
            continue;
        };
        let Ok(id) = ShopifyId::new(id) else {
            partial_reasons.push(PartialReason::MissingField);
            continue;
        };
        let status = safe_enum(string_value(node, "status"), partial_reasons);
        let request_status = safe_enum(string_value(node, "requestStatus"), partial_reasons);
        let state = fulfillment_state(Some(status.as_str()), partial_reasons);
        projections.push(FulfillmentOrderProjection {
            id,
            status,
            request_status,
            created_at: optional_stamp(node, "createdAt"),
            updated_at: optional_stamp(node, "updatedAt"),
            state,
        });
    }
    if nodes.len() > MAX_FULFILLMENT_ORDERS {
        partial_reasons.push(PartialReason::CollectionBound);
    }
    let page_info = parse_page_info(connection, partial_reasons);
    if page_info.has_next_page {
        partial_reasons.push(PartialReason::MorePages);
    }
    Ok((projections, page_info))
}

fn parse_fulfillments(
    value: Option<&Value>,
    partial_reasons: &mut Vec<PartialReason>,
) -> Result<Vec<FulfillmentProjection>, ShopifyProviderError> {
    let Some(items) = value else {
        partial_reasons.push(PartialReason::MissingField);
        return Ok(Vec::new());
    };
    let items = items
        .as_array()
        .ok_or(ShopifyProviderError::CollectionMalformed)?;
    let mut projections = Vec::new();
    for item in items.iter().take(MAX_FULFILLMENTS) {
        let Some(id) = string_value(item, "id") else {
            partial_reasons.push(PartialReason::MissingField);
            continue;
        };
        let Ok(id) = ShopifyId::new(id) else {
            partial_reasons.push(PartialReason::MissingField);
            continue;
        };
        let status = safe_enum(string_value(item, "status"), partial_reasons);
        let state = fulfillment_state(Some(status.as_str()), partial_reasons);
        projections.push(FulfillmentProjection {
            id,
            status,
            created_at: optional_stamp(item, "createdAt"),
            updated_at: optional_stamp(item, "updatedAt"),
            state,
        });
    }
    if items.len() > MAX_FULFILLMENTS {
        partial_reasons.push(PartialReason::CollectionBound);
    }
    Ok(projections)
}

fn parse_refunds(
    value: Option<&Value>,
    partial_reasons: &mut Vec<PartialReason>,
) -> Result<Vec<RefundProjection>, ShopifyProviderError> {
    let Some(items) = value else {
        partial_reasons.push(PartialReason::MissingField);
        return Ok(Vec::new());
    };
    let items = items
        .as_array()
        .ok_or(ShopifyProviderError::CollectionMalformed)?;
    let mut projections = Vec::new();
    for item in items.iter().take(MAX_REFUNDS) {
        let Some(id) = string_value(item, "id") else {
            partial_reasons.push(PartialReason::MissingField);
            continue;
        };
        let Ok(id) = ShopifyId::new(id) else {
            partial_reasons.push(PartialReason::MissingField);
            continue;
        };
        let transaction_connection = item.get("transactions");
        let nested_transactions = transaction_connection
            .and_then(|transactions| transactions.get("nodes"))
            .and_then(Value::as_array)
            .map_or(&[][..], |items| items.as_slice());
        let state = refund_state(
            nested_transactions,
            transaction_connection.is_some(),
            partial_reasons,
        );
        if transaction_connection
            .and_then(|transactions| transactions.get("pageInfo"))
            .and_then(|page_info| page_info.get("hasNextPage"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            partial_reasons.push(PartialReason::MorePages);
        }
        projections.push(RefundProjection {
            id,
            created_at: optional_stamp(item, "createdAt"),
            processed_at: optional_stamp(item, "processedAt"),
            updated_at: optional_stamp(item, "updatedAt"),
            total_refunded: optional_money(item.get("totalRefundedSet"), partial_reasons),
            state,
        });
    }
    if items.len() > MAX_REFUNDS {
        partial_reasons.push(PartialReason::CollectionBound);
    }
    Ok(projections)
}

fn parse_transactions(
    value: Option<&Value>,
    partial_reasons: &mut Vec<PartialReason>,
) -> Result<Vec<TransactionProjection>, ShopifyProviderError> {
    let Some(items) = value else {
        partial_reasons.push(PartialReason::MissingField);
        return Ok(Vec::new());
    };
    let items = items
        .as_array()
        .ok_or(ShopifyProviderError::CollectionMalformed)?;
    let mut projections = Vec::new();
    for item in items.iter().take(MAX_TRANSACTIONS) {
        let Some(id) = string_value(item, "id") else {
            partial_reasons.push(PartialReason::MissingField);
            continue;
        };
        let Ok(id) = ShopifyId::new(id) else {
            partial_reasons.push(PartialReason::MissingField);
            continue;
        };
        let kind = safe_enum(string_value(item, "kind"), partial_reasons);
        let state = transaction_state(string_value(item, "status").as_deref(), partial_reasons);
        projections.push(TransactionProjection {
            id,
            kind,
            state,
            amount: optional_money(item.get("amountSet"), partial_reasons),
            created_at: optional_stamp(item, "createdAt"),
            processed_at: optional_stamp(item, "processedAt"),
        });
    }
    if items.len() > MAX_TRANSACTIONS {
        partial_reasons.push(PartialReason::CollectionBound);
    }
    Ok(projections)
}

fn refund_state(
    items: &[Value],
    transaction_connection_present: bool,
    partial_reasons: &mut Vec<PartialReason>,
) -> TransactionState {
    if !transaction_connection_present || items.is_empty() {
        partial_reasons.push(PartialReason::MissingField);
        return TransactionState::Unknown;
    }
    let mut saw_success = false;
    let mut saw_failure = false;
    let mut saw_pending = false;
    let mut saw_authorized = false;
    for item in items {
        match transaction_state(string_value(item, "status").as_deref(), partial_reasons) {
            TransactionState::Succeeded => saw_success = true,
            TransactionState::Failed => saw_failure = true,
            TransactionState::Pending => saw_pending = true,
            TransactionState::Authorized => saw_authorized = true,
            TransactionState::PartiallyRefunded
            | TransactionState::Refunded
            | TransactionState::Unknown => {}
        }
    }
    if saw_failure && saw_success {
        TransactionState::PartiallyRefunded
    } else if saw_failure {
        TransactionState::Failed
    } else if saw_pending {
        TransactionState::Pending
    } else if saw_authorized {
        TransactionState::Authorized
    } else if saw_success {
        TransactionState::Succeeded
    } else {
        TransactionState::Unknown
    }
}

fn transaction_state(
    value: Option<&str>,
    partial_reasons: &mut Vec<PartialReason>,
) -> TransactionState {
    match value.map(str::to_ascii_uppercase).as_deref() {
        Some("PENDING") => TransactionState::Pending,
        Some("AUTHORIZED") => TransactionState::Authorized,
        Some("SUCCESS" | "SUCCEEDED" | "PAID") => TransactionState::Succeeded,
        Some("FAILURE" | "FAILED" | "ERROR") => TransactionState::Failed,
        Some("PARTIALLY_REFUNDED" | "PARTIAL_REFUND") => TransactionState::PartiallyRefunded,
        Some("REFUNDED") => TransactionState::Refunded,
        Some("VOIDED") => TransactionState::Failed,
        Some(_) | None => {
            partial_reasons.push(PartialReason::UnknownStatus);
            TransactionState::Unknown
        }
    }
}

fn fulfillment_state(
    value: Option<&str>,
    partial_reasons: &mut Vec<PartialReason>,
) -> FulfillmentState {
    match value.map(str::to_ascii_uppercase).as_deref() {
        Some("UNFULFILLED") => FulfillmentState::Unfulfilled,
        Some("SCHEDULED" | "ON_HOLD") => FulfillmentState::Pending,
        Some("OPEN" | "IN_PROGRESS" | "IN_PROGRESS_FULFILLMENT") => FulfillmentState::InProgress,
        Some("PARTIALLY_FULFILLED") => FulfillmentState::PartiallyFulfilled,
        Some("FULFILLED" | "SUCCESS") => FulfillmentState::Fulfilled,
        Some("CANCELLED" | "CANCELED") => FulfillmentState::Cancelled,
        Some(_) | None => {
            partial_reasons.push(PartialReason::UnknownStatus);
            FulfillmentState::Unknown
        }
    }
}

fn optional_stamp(value: &Value, field: &str) -> Option<RevisionStamp> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(|value| RevisionStamp::new(value.to_owned()).ok())
}

fn optional_money(
    value: Option<&Value>,
    partial_reasons: &mut Vec<PartialReason>,
) -> Option<Money> {
    let Some(value) = value else {
        partial_reasons.push(PartialReason::MissingField);
        return None;
    };
    let shop_money = value.get("shopMoney").unwrap_or(value);
    let amount = shop_money.get("amount").and_then(Value::as_str);
    let currency = shop_money.get("currencyCode").and_then(Value::as_str);
    if let (Some(amount), Some(currency)) = (amount, currency)
        && let Ok(money) = Money::new(amount, currency)
    {
        return Some(money);
    }
    partial_reasons.push(PartialReason::MissingField);
    None
}

fn parse_page_info(value: &Value, partial_reasons: &mut Vec<PartialReason>) -> PageInfo {
    let Some(page_info) = value.get("pageInfo") else {
        partial_reasons.push(PartialReason::MissingField);
        return PageInfo::complete();
    };
    let has_next_page = page_info
        .get("hasNextPage")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let end_cursor_digest = page_info
        .get("endCursor")
        .and_then(Value::as_str)
        .map(Digest::from_text);
    PageInfo {
        has_next_page,
        end_cursor_digest,
    }
}

fn string_value(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn safe_enum(value: Option<String>, partial_reasons: &mut Vec<PartialReason>) -> String {
    let Some(value) = value else {
        partial_reasons.push(PartialReason::MissingField);
        return "UNKNOWN".to_owned();
    };
    let normalized = value.to_ascii_uppercase();
    if normalized.len() <= 64
        && !normalized.is_empty()
        && normalized
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        normalized
    } else {
        partial_reasons.push(PartialReason::MissingField);
        "UNKNOWN".to_owned()
    }
}

fn safe_currency(value: Option<String>, partial_reasons: &mut Vec<PartialReason>) -> String {
    let Some(value) = value else {
        partial_reasons.push(PartialReason::MissingField);
        return "UNK".to_owned();
    };
    let normalized = value.to_ascii_uppercase();
    if normalized.len() == 3 && normalized.bytes().all(|byte| byte.is_ascii_uppercase()) {
        normalized
    } else {
        partial_reasons.push(PartialReason::MissingField);
        "UNK".to_owned()
    }
}
