use std::fmt;
use std::sync::{Arc, Mutex};

use crate::error::{NotionProviderError, NotionResultError};
use crate::model::{
    Digest, NativeStatus, NotionCursor, NotionDescribeRequest, NotionEvidenceSource, NotionPageId,
    NotionPageReceipt, NotionPageUrl, NotionPaginationReceipt, NotionProviderManifest,
    NotionPublishOperation, NotionPublishProposal, NotionReadRequest, NotionReadback,
    NotionResourceKind, NotionScopeDescription, canonical_digest,
};

/// Opaque secret reference accepted only at a provider boundary.  The token is
/// never stored in this type, serialized, or printed; native lookup remains a
/// future Integration Manager responsibility.
#[derive(Clone)]
pub struct SecretReference {
    reference: String,
}

impl SecretReference {
    pub fn new(reference: impl Into<String>) -> Result<Self, NotionResultError> {
        let reference = reference.into();
        if reference.trim().is_empty() || reference.len() > 256 {
            return Err(NotionResultError::InvalidInput {
                field: "secret reference",
                reason: String::from("must be non-empty and bounded"),
            });
        }
        Ok(Self { reference })
    }

    pub fn digest(&self) -> Digest {
        crate::model::sha256_digest(self.reference.as_bytes())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("digest", &self.digest())
            .finish_non_exhaustive()
    }
}

/// The Layer 1 provider seam has read/describe plus local proposal recording;
/// it intentionally has no create/update/append method.
pub trait NotionResultProvider: fmt::Debug + Send + Sync {
    fn manifest(&self) -> NotionProviderManifest;

    fn describe(
        &self,
        request: &NotionDescribeRequest,
    ) -> Result<NotionScopeDescription, NotionProviderError>;

    fn read(&self, request: &NotionReadRequest) -> Result<NotionReadback, NotionProviderError>;

    fn record_proposal(
        &self,
        proposal: &NotionPublishProposal,
    ) -> Result<NotionPageReceipt, NotionProviderError>;

    fn external_write_available(&self) -> bool {
        false
    }
}

/// A content-free record of which provider boundary was exercised.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotionProviderCall {
    Describe {
        scope_digest: Digest,
        page_size: u32,
    },
    Read {
        page_id: NotionPageId,
        scope_digest: Digest,
        page_size: u32,
        cursor_digest: Option<Digest>,
    },
    RecordProposal {
        proposal_digest: Digest,
        idempotency_key: String,
        operation: NotionPublishOperation,
        content_fingerprint: Digest,
    },
}

#[derive(Debug, Default)]
struct RecordingState {
    calls: Vec<NotionProviderCall>,
    receipt: Option<NotionPageReceipt>,
    readback: Option<NotionReadback>,
    fault: Option<NotionProviderError>,
}

/// Deterministic fake/recording provider used by Layer 1 tests and future
/// contract simulations.  It never contacts Notion and never stores raw page
/// content in its call log or receipts.
#[derive(Clone, Debug)]
pub struct RecordingNotionProvider {
    manifest: Arc<Mutex<NotionProviderManifest>>,
    state: Arc<Mutex<RecordingState>>,
    secret_reference: Option<SecretReference>,
}

impl RecordingNotionProvider {
    pub fn new(manifest: NotionProviderManifest) -> Self {
        Self {
            manifest: Arc::new(Mutex::new(manifest)),
            state: Arc::new(Mutex::new(RecordingState::default())),
            secret_reference: None,
        }
    }

    #[must_use]
    pub fn with_secret_reference(mut self, reference: SecretReference) -> Self {
        self.secret_reference = Some(reference);
        self
    }

    #[must_use]
    pub fn with_fault(self, fault: NotionProviderError) -> Self {
        self.set_fault(fault);
        self
    }

    pub fn set_fault(&self, fault: NotionProviderError) {
        self.state.lock().expect("recording state lock").fault = Some(fault);
    }

    pub fn set_manifest(&self, manifest: NotionProviderManifest) {
        *self.manifest.lock().expect("manifest lock") = manifest;
    }

    pub fn calls(&self) -> Vec<NotionProviderCall> {
        self.state
            .lock()
            .expect("recording state lock")
            .calls
            .clone()
    }

    pub fn last_receipt(&self) -> Option<NotionPageReceipt> {
        self.state
            .lock()
            .expect("recording state lock")
            .receipt
            .clone()
    }

    pub fn last_readback(&self) -> Option<NotionReadback> {
        self.state
            .lock()
            .expect("recording state lock")
            .readback
            .clone()
    }

    fn fault(&self) -> Option<NotionProviderError> {
        self.state
            .lock()
            .expect("recording state lock")
            .fault
            .clone()
    }

    fn ensure_manifest(&self) -> Result<NotionProviderManifest, NotionProviderError> {
        let manifest = self.manifest();
        manifest
            .validate()
            .map_err(|_| NotionProviderError::ManifestMismatch)?;
        Ok(manifest)
    }
}

impl NotionResultProvider for RecordingNotionProvider {
    fn manifest(&self) -> NotionProviderManifest {
        self.manifest.lock().expect("manifest lock").clone()
    }

    fn describe(
        &self,
        request: &NotionDescribeRequest,
    ) -> Result<NotionScopeDescription, NotionProviderError> {
        if let Some(fault) = self.fault() {
            return Err(fault);
        }
        let manifest = self.ensure_manifest()?;
        if request.scope != manifest.scope {
            return Err(NotionProviderError::ManifestMismatch);
        }
        let resource_kind = match request.scope.parent {
            crate::model::NotionParent::Page { .. } => NotionResourceKind::Page,
            crate::model::NotionParent::DataSource { .. } => NotionResourceKind::DataSource,
        };
        self.state
            .lock()
            .expect("recording state lock")
            .calls
            .push(NotionProviderCall::Describe {
                scope_digest: request.scope.digest(),
                page_size: request.pagination.page_size,
            });
        Ok(NotionScopeDescription {
            scope: request.scope.clone(),
            resource_kind,
            resource_id: request.scope.parent.resource_id().to_owned(),
            schema_digest: match resource_kind {
                NotionResourceKind::Page => None,
                NotionResourceKind::DataSource => Some(canonical_digest(&request.scope.parent)),
            },
            pagination: NotionPaginationReceipt::one_page(),
            provider_manifest_digest: manifest.digest(),
            evidence: NotionEvidenceSource::Fake,
            native_status: NativeStatus::BlockedEnv,
        })
    }

    fn read(&self, request: &NotionReadRequest) -> Result<NotionReadback, NotionProviderError> {
        if let Some(fault) = self.fault() {
            return Err(fault);
        }
        let manifest = self.ensure_manifest()?;
        if request.scope != manifest.scope {
            return Err(NotionProviderError::ManifestMismatch);
        }
        let mut state = self.state.lock().expect("recording state lock");
        state.calls.push(NotionProviderCall::Read {
            page_id: request.page_id.clone(),
            scope_digest: request.scope.digest(),
            page_size: request.pagination.page_size,
            cursor_digest: request.cursor.as_ref().map(NotionCursor::digest),
        });
        let readback = state
            .readback
            .clone()
            .filter(|readback| readback.page_id == request.page_id)
            .ok_or(NotionProviderError::NoRecordedPage)?;
        Ok(readback)
    }

    fn record_proposal(
        &self,
        proposal: &NotionPublishProposal,
    ) -> Result<NotionPageReceipt, NotionProviderError> {
        if let Some(fault) = self.fault() {
            return Err(fault);
        }
        let manifest = self.ensure_manifest()?;
        if proposal.provider_manifest_digest != manifest.digest()
            || proposal.scope != manifest.scope
        {
            return Err(NotionProviderError::ManifestMismatch);
        }
        proposal
            .validate()
            .map_err(|_| NotionProviderError::InvalidResponse {
                field: "publish proposal",
            })?;
        let page_id = proposal
            .operation
            .target_page_id()
            .cloned()
            .unwrap_or_else(|| {
                let digest = proposal.calculate_digest();
                NotionPageId::new(format!("recorded-{}", &digest[..24]))
                    .expect("recorded page ID is bounded")
            });
        let page_url = NotionPageUrl::new(format!("https://www.notion.so/{page_id}"))
            .expect("recorded Notion URL is valid");
        let revision = crate::model::NotionRevision::new(format!(
            "recorded-{}",
            &proposal.proposal_digest[..16]
        ))
        .expect("recorded revision is bounded");
        let receipt = NotionPageReceipt {
            page_id: page_id.clone(),
            page_url,
            parent: proposal.scope.parent.clone(),
            revision,
            content_fingerprint: proposal.content_fingerprint.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            idempotency_key: proposal.idempotency_key.clone(),
            provider_manifest_digest: manifest.digest(),
            operation: proposal.operation.clone(),
            evidence: NotionEvidenceSource::Recording,
            native_status: NativeStatus::BlockedEnv,
        };
        let readback = NotionReadback {
            page_id: receipt.page_id.clone(),
            page_url: receipt.page_url.clone(),
            parent: receipt.parent.clone(),
            revision: receipt.revision.clone(),
            content_fingerprint: receipt.content_fingerprint.clone(),
            proposal_digest: receipt.proposal_digest.clone(),
            idempotency_key: receipt.idempotency_key.clone(),
            provider_manifest_digest: receipt.provider_manifest_digest.clone(),
            pagination: NotionPaginationReceipt::one_page(),
            evidence: NotionEvidenceSource::Recording,
            native_status: NativeStatus::BlockedEnv,
        };
        let mut state = self.state.lock().expect("recording state lock");
        state.calls.push(NotionProviderCall::RecordProposal {
            proposal_digest: proposal.proposal_digest.clone(),
            idempotency_key: proposal.idempotency_key.clone(),
            operation: proposal.operation.clone(),
            content_fingerprint: proposal.content_fingerprint.clone(),
        });
        state.receipt = Some(receipt.clone());
        state.readback = Some(readback);
        Ok(receipt)
    }
}

/// A named alias makes test/future simulator intent explicit without adding a
/// second provider implementation that could be mistaken for native Notion.
pub type FakeNotionProvider = RecordingNotionProvider;
