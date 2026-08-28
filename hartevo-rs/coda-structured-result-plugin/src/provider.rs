use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::CodaProviderError;
use crate::model::{
    CodaEvidenceClassification, CodaEvidenceState, CodaMetadataRecord, CodaPageToken,
    CodaRateLimitReceipt, CodaReadOperation, CodaReadRequest, CodaRegistration,
    CodaRegistrationRevocation, CodaResourceKind, CodaResponse, CodaStructuredResultEvidence,
    CodaStructuredResultProposal, CodaStructuredResultScope, CodaTransportProvenance, Digest,
    MAX_METADATA_RECORDS, MAX_RESPONSE_BYTES, Revision, SecretReference, canonical_digest,
    digest_parts,
};
use crate::transport::CodaTransport;

/// The provider manifest is itself typed and digest-bound to registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodaProviderDefinition {
    pub id: String,
    pub version: String,
    pub api_revision: String,
    pub api_reference: String,
    pub base_url: String,
    pub allowlisted_operations: Vec<CodaReadOperation>,
    pub read_only: bool,
    pub external_writes: bool,
    pub formula_execution: bool,
    pub raw_rich_text: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl CodaProviderDefinition {
    #[must_use]
    pub fn layer1() -> Self {
        Self {
            id: crate::CODA_PROVIDER_ID.to_owned(),
            version: crate::CODA_STRUCTURED_RESULT_PLUGIN_VERSION.to_owned(),
            api_revision: crate::CODA_PROVIDER_REVISION.to_owned(),
            api_reference: crate::CODA_API_REFERENCE_URL.to_owned(),
            base_url: crate::CODA_API_BASE_URL.to_owned(),
            allowlisted_operations: vec![
                CodaReadOperation::DocMetadata,
                CodaReadOperation::PageMetadata,
                CodaReadOperation::TableMetadata,
                CodaReadOperation::ViewMetadata,
                CodaReadOperation::ColumnMetadata,
                CodaReadOperation::RowMetadata,
            ],
            read_only: true,
            external_writes: false,
            formula_execution: false,
            raw_rich_text: false,
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub fn validate(&self) -> Result<(), CodaProviderError> {
        let expected = Self::layer1();
        if self != &expected {
            return Err(CodaProviderError::ProviderDrift);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub const fn native_connected(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodaProviderCall {
    Read {
        operation: CodaReadOperation,
        request_digest: Digest,
        resource_digest: Digest,
        page_token_digest: Option<Digest>,
    },
    Record {
        proposal_digest: Digest,
        idempotency_key: Digest,
    },
}

/// Typed Layer-1 Coda provider. It owns no credential resolver and therefore
/// cannot turn an opaque SecretReference into an API token or open HTTPS.
#[derive(Clone, Debug)]
pub struct CodaProvider<T>
where
    T: CodaTransport,
{
    scope: CodaStructuredResultScope,
    secret_reference: SecretReference,
    registration: CodaRegistration,
    definition: CodaProviderDefinition,
    transport: T,
    calls: Vec<CodaProviderCall>,
    recorded_receipts: BTreeMap<Digest, crate::model::CodaRecordingReceipt>,
}

impl<T> CodaProvider<T>
where
    T: CodaTransport,
{
    pub fn new(
        scope: CodaStructuredResultScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, crate::error::CodaStructuredResultError> {
        scope.validate()?;
        let definition = CodaProviderDefinition::layer1();
        definition.validate()?;
        if secret_reference.is_revoked() {
            return Err(CodaProviderError::SecretRevoked.into());
        }
        let registration = CodaRegistration::new(
            crate::plugin_version_digest(),
            crate::contract_digest(),
            definition.digest(),
            scope.digest(),
            secret_reference.digest(),
        );
        Self::from_registration(scope, secret_reference, registration, transport)
    }

    pub fn from_registration(
        scope: CodaStructuredResultScope,
        secret_reference: SecretReference,
        registration: CodaRegistration,
        transport: T,
    ) -> Result<Self, crate::error::CodaStructuredResultError> {
        scope.validate()?;
        registration.validate()?;
        let definition = CodaProviderDefinition::layer1();
        definition.validate()?;
        if registration.scope_digest != scope.digest()
            || registration.secret_reference_digest != secret_reference.digest()
            || registration.provider_digest != definition.digest()
            || registration.contract_digest != crate::contract_digest()
            || registration.plugin_version_digest != crate::plugin_version_digest()
        {
            return Err(CodaProviderError::RegistrationDrift.into());
        }
        Ok(Self {
            scope,
            secret_reference,
            registration,
            definition,
            transport,
            calls: Vec::new(),
            recorded_receipts: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &CodaStructuredResultScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn registration(&self) -> &CodaRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut CodaRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn definition(&self) -> &CodaProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.digest()
    }

    #[must_use]
    pub fn provenance(&self) -> CodaTransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(&self) -> bool {
        false
    }

    #[must_use]
    pub fn calls(&self) -> &[CodaProviderCall] {
        &self.calls
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn revoke(
        &mut self,
    ) -> Result<CodaRegistrationRevocation, crate::error::CodaStructuredResultError> {
        self.ensure_registration()?;
        Ok(self.registration.revoke()?)
    }

    pub fn restore(
        &mut self,
    ) -> Result<CodaRegistrationRevocation, crate::error::CodaStructuredResultError> {
        if self.secret_reference.is_revoked() {
            self.secret_reference.restore()?;
        }
        Ok(self.registration.restore()?)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<CodaRegistrationRevocation, crate::error::CodaStructuredResultError> {
        self.revoke()
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<CodaRegistrationRevocation, crate::error::CodaStructuredResultError> {
        self.restore()
    }

    pub fn read(
        &mut self,
        request: &CodaReadRequest,
    ) -> Result<CodaStructuredResultEvidence, CodaProviderError> {
        self.ensure_registration()?;
        request
            .validate_for_scope(&self.scope)
            .map_err(|_| CodaProviderError::ScopeMismatch)?;
        let response = match self.transport.execute(request) {
            Ok(response) => response,
            Err(error) => {
                let provider_error = CodaProviderError::from(error);
                let rate_limit = match &provider_error {
                    CodaProviderError::RateLimited {
                        retry_after_seconds,
                    } => CodaRateLimitReceipt::new(
                        crate::MAX_REQUESTS_PER_MINUTE,
                        Some(0),
                        *retry_after_seconds,
                        true,
                    )
                    .unwrap_or_default(),
                    _ => CodaRateLimitReceipt::default(),
                };
                let evidence = self.status_evidence(
                    request,
                    status_for_provider_error(&provider_error),
                    classification_for_provider_error(&provider_error),
                    Digest::from("0".repeat(64)),
                    0,
                    rate_limit,
                    provider_error == CodaProviderError::Partial,
                )?;
                self.calls.push(CodaProviderCall::Read {
                    operation: request.operation(),
                    request_digest: request.digest().clone(),
                    resource_digest: request.resource_digest().clone(),
                    page_token_digest: request.page_token().map(|token| token.digest().clone()),
                });
                return Ok(evidence);
            }
        };
        let evidence = self.project_response(request, response)?;
        self.calls.push(CodaProviderCall::Read {
            operation: request.operation(),
            request_digest: request.digest().clone(),
            resource_digest: request.resource_digest().clone(),
            page_token_digest: request.page_token().map(|token| token.digest().clone()),
        });
        Ok(evidence)
    }

    pub fn read_metadata(
        &mut self,
        request: &CodaReadRequest,
    ) -> Result<CodaStructuredResultEvidence, CodaProviderError> {
        self.read(request)
    }

    pub fn record_proposal(
        &mut self,
        proposal: &CodaStructuredResultProposal,
    ) -> Result<crate::model::CodaRecordingReceipt, CodaProviderError> {
        self.ensure_registration()?;
        proposal
            .validate()
            .map_err(|_| CodaProviderError::Tampered)?;
        if proposal.scope_digest != self.scope.digest()
            || proposal.provider_digest != self.provider_digest()
            || proposal.registration_digest != self.registration.registration_digest
        {
            return Err(CodaProviderError::RegistrationDrift);
        }
        if let Some(existing) = self.recorded_receipts.get(&proposal.idempotency_key) {
            if existing.proposal_digest == proposal.proposal_digest {
                return Ok(existing.clone());
            }
            return Err(CodaProviderError::IdempotencyConflict);
        }
        let receipt = crate::model::CodaRecordingReceipt::build(proposal);
        receipt
            .validate()
            .map_err(|_| CodaProviderError::InvalidResponse)?;
        self.recorded_receipts
            .insert(proposal.idempotency_key.clone(), receipt.clone());
        self.calls.push(CodaProviderCall::Record {
            proposal_digest: proposal.proposal_digest.clone(),
            idempotency_key: proposal.idempotency_key.clone(),
        });
        Ok(receipt)
    }

    fn ensure_registration(&self) -> Result<(), CodaProviderError> {
        self.definition.validate()?;
        self.registration
            .validate()
            .map_err(|_| CodaProviderError::RegistrationDrift)?;
        if !self.registration.is_active() {
            return Err(CodaProviderError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(CodaProviderError::SecretRevoked);
        }
        if self.registration.scope_digest != self.scope.digest()
            || self.registration.provider_digest != self.definition.digest()
            || self.registration.secret_reference_digest != self.secret_reference.digest()
        {
            return Err(CodaProviderError::RegistrationDrift);
        }
        Ok(())
    }

    fn status_evidence(
        &self,
        request: &CodaReadRequest,
        state: CodaEvidenceState,
        classification: CodaEvidenceClassification,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: CodaRateLimitReceipt,
        partial: bool,
    ) -> Result<CodaStructuredResultEvidence, CodaProviderError> {
        CodaStructuredResultEvidence::build(
            request.operation(),
            state,
            classification,
            request.scope_digest().clone(),
            request.digest().clone(),
            digest_for_kind(CodaResourceKind::Doc, &[]),
            digest_for_kind(CodaResourceKind::Table, &[]),
            digest_for_kind(CodaResourceKind::Row, &[]),
            request.revision().digest(),
            self.provider_digest(),
            self.registration.registration_digest.clone(),
            response_digest,
            response_bytes,
            Vec::new(),
            None,
            rate_limit,
            self.provenance(),
            partial,
        )
        .map_err(|_| CodaProviderError::InvalidResponse)
    }

    fn project_response(
        &self,
        request: &CodaReadRequest,
        response: CodaResponse,
    ) -> Result<CodaStructuredResultEvidence, CodaProviderError> {
        if response.response_bytes() > MAX_RESPONSE_BYTES {
            return Err(CodaProviderError::ResponseTooLarge);
        }
        let response_digest = response.response_digest();
        if response
            .reported_response_digest()
            .is_some_and(|reported| reported != response_digest)
        {
            return Err(CodaProviderError::Tampered);
        }
        let status = response.status();
        let rate_limit = response.rate_limit().clone();
        if status == 429 {
            return self.status_evidence(
                request,
                CodaEvidenceState::RateLimited,
                CodaEvidenceClassification::RateLimit,
                response_digest,
                response.response_bytes(),
                rate_limit,
                false,
            );
        }
        if matches!(status, 401 | 403 | 404) {
            return self.status_evidence(
                request,
                CodaEvidenceState::Denied,
                CodaEvidenceClassification::Denied,
                response_digest,
                response.response_bytes(),
                rate_limit,
                false,
            );
        }
        if !(200..=299).contains(&status) {
            return self.status_evidence(
                request,
                CodaEvidenceState::ProviderUnknown,
                CodaEvidenceClassification::ProviderUnknown,
                response_digest,
                response.response_bytes(),
                rate_limit,
                false,
            );
        }
        if status == 204 || response.body().is_empty() {
            return self.status_evidence(
                request,
                CodaEvidenceState::Empty,
                CodaEvidenceClassification::Empty,
                response_digest,
                response.response_bytes(),
                rate_limit,
                false,
            );
        }
        let root: Value = serde_json::from_slice(response.body())
            .map_err(|_| CodaProviderError::InvalidResponse)?;
        let mut partial = status == 206
            || root
                .get("partial")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        let items = if let Some(items) = root.get("items").and_then(Value::as_array) {
            items.iter().collect::<Vec<_>>()
        } else if let Some(item) = root.get("item") {
            vec![item]
        } else if root.get("id").and_then(Value::as_str).is_some() {
            vec![&root]
        } else {
            Vec::new()
        };
        if items.len() > MAX_METADATA_RECORDS {
            return Err(CodaProviderError::ResponseTooLarge);
        }
        let mut metadata = Vec::with_capacity(items.len());
        for item in items {
            metadata.push(self.project_item(request, item)?);
        }
        let next_raw = response
            .next_page_token()
            .or_else(|| root.get("nextPageToken").and_then(Value::as_str));
        let next_page_token = if let Some(raw) = next_raw {
            if request.page_number() >= crate::MAX_PAGES {
                partial = true;
                None
            } else {
                let token = CodaPageToken::new(
                    raw,
                    request.scope_digest().clone(),
                    request.operation(),
                    request.page_number(),
                )
                .map_err(|_| CodaProviderError::InvalidResponse)?;
                if request
                    .page_token()
                    .is_some_and(|previous| previous.raw_digest() == token.raw_digest())
                {
                    return Err(CodaProviderError::PageTokenLoop);
                }
                Some(token)
            }
        } else {
            None
        };
        let state = if partial {
            CodaEvidenceState::Partial
        } else if metadata.is_empty() {
            CodaEvidenceState::Empty
        } else {
            CodaEvidenceState::Present
        };
        let classification = match state {
            CodaEvidenceState::Present => CodaEvidenceClassification::Present,
            CodaEvidenceState::Empty => CodaEvidenceClassification::Empty,
            CodaEvidenceState::Partial => CodaEvidenceClassification::Partial,
            _ => CodaEvidenceClassification::ProviderUnknown,
        };
        CodaStructuredResultEvidence::build(
            request.operation(),
            state,
            classification,
            request.scope_digest().clone(),
            request.digest().clone(),
            digest_for_kind(CodaResourceKind::Doc, &metadata),
            digest_for_kind(CodaResourceKind::Table, &metadata),
            digest_for_kind(CodaResourceKind::Row, &metadata),
            request.revision().digest(),
            self.provider_digest(),
            self.registration.registration_digest.clone(),
            response_digest,
            response.response_bytes(),
            metadata,
            next_page_token,
            rate_limit,
            self.provenance(),
            partial,
        )
        .map_err(|_| CodaProviderError::InvalidResponse)
    }

    fn project_item(
        &self,
        request: &CodaReadRequest,
        item: &Value,
    ) -> Result<CodaMetadataRecord, CodaProviderError> {
        let kind = request.operation().resource_kind();
        let identifier = item
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_else(|| request.resource_id());
        if !self.scope.allows(kind, identifier) {
            return Err(CodaProviderError::ItemOutsideScope);
        }
        let revision = item
            .get("revision")
            .and_then(value_as_u64)
            .map(Revision::new)
            .transpose()
            .map_err(|_| CodaProviderError::InvalidResponse)?
            .unwrap_or(request.revision());
        if revision != request.revision() {
            return Err(CodaProviderError::RevisionDrift { resource: kind });
        }
        let parent = item
            .get("parent")
            .and_then(Value::as_object)
            .and_then(|parent| parent.get("id"))
            .and_then(Value::as_str);
        let name = item.get("name").and_then(Value::as_str);
        let type_name = item
            .get("type")
            .and_then(Value::as_str)
            .or_else(|| item.get("tableType").and_then(Value::as_str));
        let item_count = item
            .get("itemCount")
            .and_then(value_as_u64)
            .unwrap_or(1)
            .min(u64::from(u32::MAX)) as u32;
        let row_count = item.get("rowCount").and_then(value_as_u64);
        let column_count = item
            .get("columnCount")
            .and_then(value_as_u64)
            .map(|value| value.min(u64::from(u32::MAX)) as u32);
        let value_count = item
            .get("values")
            .and_then(Value::as_object)
            .map(|values| values.len().min(u32::MAX as usize) as u32);
        Ok(CodaMetadataRecord::from_safe_fields(
            kind,
            identifier,
            parent,
            name,
            type_name,
            item_count,
            row_count,
            column_count,
            value_count,
            item.get("createdAt").and_then(Value::as_str),
            item.get("updatedAt").and_then(Value::as_str),
            revision,
        ))
    }
}

fn value_as_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
}

fn digest_for_kind(kind: CodaResourceKind, records: &[CodaMetadataRecord]) -> Digest {
    let mut values = records
        .iter()
        .filter(|record| record.kind == kind)
        .map(|record| record.metadata_digest.as_str())
        .collect::<Vec<_>>();
    values.sort_unstable();
    if values.is_empty() {
        digest_parts(["coda-no-metadata", kind.label()])
    } else {
        digest_parts(values)
    }
}

impl CodaResourceKind {
    #[must_use]
    const fn label(self) -> &'static str {
        match self {
            Self::Doc => "doc",
            Self::Page => "page",
            Self::Table => "table",
            Self::View => "view",
            Self::Column => "column",
            Self::Row => "row",
        }
    }
}

fn status_for_provider_error(error: &CodaProviderError) -> CodaEvidenceState {
    match error {
        CodaProviderError::RateLimited { .. } => CodaEvidenceState::RateLimited,
        CodaProviderError::Partial => CodaEvidenceState::Partial,
        CodaProviderError::Denied | CodaProviderError::BlockedEnv => CodaEvidenceState::Denied,
        CodaProviderError::RegistrationRevoked => CodaEvidenceState::RegistrationRevoked,
        CodaProviderError::RevisionDrift { .. } => CodaEvidenceState::RevisionDrift,
        CodaProviderError::Tampered => CodaEvidenceState::Tampered,
        _ => CodaEvidenceState::ProviderUnknown,
    }
}

fn classification_for_provider_error(error: &CodaProviderError) -> CodaEvidenceClassification {
    match error {
        CodaProviderError::RateLimited { .. } => CodaEvidenceClassification::RateLimit,
        CodaProviderError::Partial => CodaEvidenceClassification::Partial,
        CodaProviderError::Denied => CodaEvidenceClassification::Denied,
        CodaProviderError::BlockedEnv => CodaEvidenceClassification::BlockedEnv,
        CodaProviderError::RegistrationRevoked => CodaEvidenceClassification::RegistrationRevoked,
        CodaProviderError::RevisionDrift { .. } => CodaEvidenceClassification::RevisionDrift,
        CodaProviderError::Tampered => CodaEvidenceClassification::Tamper,
        _ => CodaEvidenceClassification::ProviderUnknown,
    }
}
