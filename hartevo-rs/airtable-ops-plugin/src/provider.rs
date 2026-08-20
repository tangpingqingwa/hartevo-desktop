use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{AirtableError, AirtableProviderError};
use crate::model::{
    AirtableOffset, AirtableProviderManifest, AirtableProviderProvenance, AirtableRecordId,
    AirtableRecordPage, AirtableScope, AirtableTableSchema, ListRecordsRequest, ReceiptKind,
    RecordReadback, RecordReceipt, SecretReference,
};

/// The environment variable intentionally names a reference, not a token.  A
/// later native layer may resolve it at the provider boundary.
pub const AIRTABLE_PAT_ENV: &str = "HARTEVO_AIRTABLE_PAT";

/// A provider can read schema/records and record fixtures, but it has no create
/// or update method in Layer 1.  This is the compile-time write fence.
pub trait AirtableOpsProvider: fmt::Debug {
    fn manifest(&self) -> &AirtableProviderManifest;

    fn describe_schema(
        &mut self,
        scope: &AirtableScope,
        secret: &SecretReference,
    ) -> Result<AirtableTableSchema, AirtableProviderError>;

    fn list_records(
        &mut self,
        scope: &AirtableScope,
        request: &ListRecordsRequest,
        secret: &SecretReference,
    ) -> Result<AirtableRecordPage, AirtableProviderError>;

    fn read_record(
        &mut self,
        scope: &AirtableScope,
        record_id: &AirtableRecordId,
        field_ids: &[crate::model::AirtableFieldId],
        secret: &SecretReference,
    ) -> Result<RecordReadback, AirtableProviderError>;

    fn provenance(&self) -> AirtableProviderProvenance {
        self.manifest().provenance
    }

    fn writes_enabled(&self) -> bool {
        false
    }
}

/// Compatibility spelling for consumers that refer to the boundary as an
/// Airtable provider rather than an operations provider.
pub use AirtableOpsProvider as AirtableProvider;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AirtableProviderOperation {
    DescribeSchema,
    ListRecords,
    ReadRecord,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedProviderRequest {
    pub operation: AirtableProviderOperation,
    pub scope: AirtableScope,
    pub offset: Option<AirtableOffset>,
    pub page_size: Option<usize>,
    pub record_id: Option<AirtableRecordId>,
    pub field_count: usize,
    pub secret_reference_digest: String,
}

/// Deterministic fake provider used by the Layer 1 tests and by callers that
/// want recording without pretending to be Connected/native.
#[derive(Clone, Debug)]
pub struct RecordingAirtableProvider {
    manifest: AirtableProviderManifest,
    schema: AirtableTableSchema,
    pages: BTreeMap<Option<AirtableOffset>, AirtableRecordPage>,
    readbacks: BTreeMap<AirtableRecordId, RecordReadback>,
    queued_errors: VecDeque<AirtableProviderError>,
    requests: Vec<RecordedProviderRequest>,
}

impl RecordingAirtableProvider {
    pub fn new(scope: AirtableScope, schema: AirtableTableSchema) -> Result<Self, AirtableError> {
        Self::with_provenance(scope, schema, AirtableProviderProvenance::Recording)
    }

    pub fn fixture(
        scope: AirtableScope,
        schema: AirtableTableSchema,
    ) -> Result<Self, AirtableError> {
        Self::with_provenance(scope, schema, AirtableProviderProvenance::Fixture)
    }

    fn with_provenance(
        scope: AirtableScope,
        schema: AirtableTableSchema,
        provenance: AirtableProviderProvenance,
    ) -> Result<Self, AirtableError> {
        if schema.scope != scope {
            return Err(AirtableError::ScopeMismatch {
                expected: Box::new(scope),
                observed: Box::new(schema.scope),
            });
        }
        Ok(Self {
            manifest: AirtableProviderManifest::baseline(scope, provenance),
            schema,
            pages: BTreeMap::new(),
            readbacks: BTreeMap::new(),
            queued_errors: VecDeque::new(),
            requests: Vec::new(),
        })
    }

    pub fn set_schema(&mut self, schema: AirtableTableSchema) -> Result<(), AirtableError> {
        if schema.scope != self.manifest.scope {
            return Err(AirtableError::ScopeMismatch {
                expected: Box::new(self.manifest.scope.clone()),
                observed: Box::new(schema.scope),
            });
        }
        self.schema = schema;
        Ok(())
    }

    pub fn set_page(
        &mut self,
        offset: Option<AirtableOffset>,
        page: AirtableRecordPage,
    ) -> Result<(), AirtableError> {
        for record in &page.records {
            if record.scope != self.manifest.scope {
                return Err(AirtableError::ScopeMismatch {
                    expected: Box::new(self.manifest.scope.clone()),
                    observed: Box::new(record.scope.clone()),
                });
            }
        }
        self.pages.insert(offset, page);
        Ok(())
    }

    pub fn set_readback(&mut self, readback: RecordReadback) -> Result<(), AirtableError> {
        if readback.scope != self.manifest.scope {
            return Err(AirtableError::ScopeMismatch {
                expected: Box::new(self.manifest.scope.clone()),
                observed: Box::new(readback.scope),
            });
        }
        self.readbacks.insert(readback.record_id.clone(), readback);
        Ok(())
    }

    pub fn push_error(&mut self, error: AirtableProviderError) {
        self.queued_errors.push_back(error);
    }

    pub fn requests(&self) -> &[RecordedProviderRequest] {
        &self.requests
    }

    pub fn manifest_mut(&mut self) -> &mut AirtableProviderManifest {
        &mut self.manifest
    }

    pub fn record_receipt(
        &self,
        proposal: &crate::model::RecordProposal,
        record_id: AirtableRecordId,
    ) -> Result<RecordReceipt, AirtableError> {
        RecordReceipt::from_proposal(
            proposal,
            record_id,
            self.manifest.provenance,
            match self.manifest.provenance {
                AirtableProviderProvenance::Recording => ReceiptKind::Recording,
                AirtableProviderProvenance::Fixture => ReceiptKind::Fixture,
                AirtableProviderProvenance::BlockedEnv
                | AirtableProviderProvenance::NativeHttps => {
                    return Err(AirtableError::ContractDrift {
                        expected: "recording or fixture receipt".to_owned(),
                        observed: format!("{:?}", self.manifest.provenance),
                    });
                }
            },
        )
    }

    fn next_error(&mut self) -> Result<(), AirtableProviderError> {
        self.queued_errors.pop_front().map_or(Ok(()), Err)
    }

    fn record_request(&mut self, request: RecordedProviderRequest) {
        self.requests.push(request);
    }

    fn check_scope(&self, scope: &AirtableScope) -> Result<(), AirtableProviderError> {
        if self.manifest.scope != *scope {
            return Err(AirtableProviderError::ScopeMismatch);
        }
        Ok(())
    }
}

impl AirtableOpsProvider for RecordingAirtableProvider {
    fn manifest(&self) -> &AirtableProviderManifest {
        &self.manifest
    }

    fn describe_schema(
        &mut self,
        scope: &AirtableScope,
        secret: &SecretReference,
    ) -> Result<AirtableTableSchema, AirtableProviderError> {
        self.check_scope(scope)?;
        self.record_request(RecordedProviderRequest {
            operation: AirtableProviderOperation::DescribeSchema,
            scope: scope.clone(),
            offset: None,
            page_size: None,
            record_id: None,
            field_count: 0,
            secret_reference_digest: secret.digest(),
        });
        self.next_error()?;
        Ok(self.schema.clone())
    }

    fn list_records(
        &mut self,
        scope: &AirtableScope,
        request: &ListRecordsRequest,
        secret: &SecretReference,
    ) -> Result<AirtableRecordPage, AirtableProviderError> {
        self.check_scope(scope)?;
        if request.page_size > self.manifest.max_page_size {
            return Err(AirtableProviderError::InvalidRequest {
                message: "requested page size exceeds provider manifest".to_owned(),
            });
        }
        self.record_request(RecordedProviderRequest {
            operation: AirtableProviderOperation::ListRecords,
            scope: scope.clone(),
            offset: request.offset.clone(),
            page_size: Some(request.page_size),
            record_id: None,
            field_count: 0,
            secret_reference_digest: secret.digest(),
        });
        self.next_error()?;
        self.pages
            .get(&request.offset)
            .cloned()
            .ok_or(AirtableProviderError::NotFound { status: 404 })
    }

    fn read_record(
        &mut self,
        scope: &AirtableScope,
        record_id: &AirtableRecordId,
        field_ids: &[crate::model::AirtableFieldId],
        secret: &SecretReference,
    ) -> Result<RecordReadback, AirtableProviderError> {
        self.check_scope(scope)?;
        self.record_request(RecordedProviderRequest {
            operation: AirtableProviderOperation::ReadRecord,
            scope: scope.clone(),
            offset: None,
            page_size: None,
            record_id: Some(record_id.clone()),
            field_count: field_ids.len(),
            secret_reference_digest: secret.digest(),
        });
        self.next_error()?;
        self.readbacks
            .get(record_id)
            .cloned()
            .ok_or(AirtableProviderError::NotFound { status: 404 })
    }
}

/// A fake-provider spelling kept separate in the public API so tests can make
/// their non-native provenance explicit.
pub type FakeAirtableProvider = RecordingAirtableProvider;

#[derive(Clone, Debug)]
pub struct BlockedEnvAirtableProvider {
    manifest: AirtableProviderManifest,
}

impl BlockedEnvAirtableProvider {
    pub fn new(scope: AirtableScope) -> Self {
        Self {
            manifest: AirtableProviderManifest::baseline(
                scope,
                AirtableProviderProvenance::BlockedEnv,
            ),
        }
    }
}

impl AirtableOpsProvider for BlockedEnvAirtableProvider {
    fn manifest(&self) -> &AirtableProviderManifest {
        &self.manifest
    }

    fn describe_schema(
        &mut self,
        _scope: &AirtableScope,
        _secret: &SecretReference,
    ) -> Result<AirtableTableSchema, AirtableProviderError> {
        Err(AirtableProviderError::BlockedEnv {
            variable: AIRTABLE_PAT_ENV.to_owned(),
        })
    }

    fn list_records(
        &mut self,
        _scope: &AirtableScope,
        _request: &ListRecordsRequest,
        _secret: &SecretReference,
    ) -> Result<AirtableRecordPage, AirtableProviderError> {
        Err(AirtableProviderError::BlockedEnv {
            variable: AIRTABLE_PAT_ENV.to_owned(),
        })
    }

    fn read_record(
        &mut self,
        _scope: &AirtableScope,
        _record_id: &AirtableRecordId,
        _field_ids: &[crate::model::AirtableFieldId],
        _secret: &SecretReference,
    ) -> Result<RecordReadback, AirtableProviderError> {
        Err(AirtableProviderError::BlockedEnv {
            variable: AIRTABLE_PAT_ENV.to_owned(),
        })
    }
}

pub fn native_provider_from_environment() -> Result<BlockedEnvAirtableProvider, AirtableError> {
    Err(AirtableError::BlockedEnv {
        variable: AIRTABLE_PAT_ENV.to_owned(),
    })
}
