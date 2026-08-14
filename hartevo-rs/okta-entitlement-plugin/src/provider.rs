use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;

use crate::canonical::digest_parts;
use crate::model::{
    CapabilityDescription, CapabilityOperation, EntitlementBinding, EntitlementPageCursor,
    EvidenceProvenance, GrantReceipt, LogAvailability, OktaApplicationRecord, OktaGroupRecord,
    OktaScope, OktaUserRecord, Provenance, ReadBounds, SystemLogCursor, SystemLogEvent,
    SystemLogWindowRequest,
};
use crate::{
    CAPABILITY_ID, CONTRACT_VERSION, MAX_PAGE_SIZE, MAX_RESPONSE_BYTES, MAX_SYSTEM_LOG_EVENTS,
    PLUGIN_ID, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID,
};

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ProviderError {
    #[error("Okta environment is unavailable: {reason}")]
    BlockedEnv { reason: String },
    #[error("Okta permission or grant was denied")]
    PermissionDenied,
    #[error("Okta rate limit encountered; retry after {retry_after_seconds}s")]
    RateLimited { retry_after_seconds: u64 },
    #[error("Okta redirected to a different org or custom domain")]
    CrossOrgRedirect,
    #[error("provider scope does not match this request")]
    ScopeMismatch,
    #[error("required provider field or schema drifted: {field}")]
    SchemaDrift { field: String },
    #[error("provider returned an invalid or tampered opaque cursor")]
    CursorInvalid,
    #[error("provider direct-read revision is stale or changed mid-snapshot")]
    StaleDirectRead,
    #[error("provider response exceeded the configured byte bound")]
    ResponseTooLarge { response_bytes: usize },
    #[error("provider recording is incomplete and cannot form a bounded page")]
    IncompletePage,
    #[error("provider transport failed: {0}")]
    Transport(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordingFault {
    RateLimited { retry_after_seconds: u64 },
    PermissionDenied,
    CrossOrgRedirect,
    RequiredFieldDrift { field: String },
    AdditiveField,
    StaleDirectRead,
    DuplicateAssignment,
    AssignmentDisagreement,
    ReorderedAssignments,
    MissingPage,
    OpaqueCursorTampered,
    RetentionGap,
    ResponseTooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntitlementPageRequest {
    pub scope_digest: String,
    pub page_size: usize,
    pub after: Option<EntitlementPageCursor>,
    pub expected_provider_revision: String,
}

impl EntitlementPageRequest {
    pub fn new(scope: &OktaScope, bounds: ReadBounds, expected_provider_revision: &str) -> Self {
        Self {
            scope_digest: scope.digest(),
            page_size: bounds.page_size,
            after: None,
            expected_provider_revision: expected_provider_revision.to_owned(),
        }
    }

    #[must_use]
    pub fn with_after(mut self, after: &EntitlementPageCursor) -> Self {
        self.after = Some(after.clone());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntitlementPage {
    pub provider_revision: String,
    pub direct_read_revision: String,
    pub users: Vec<OktaUserRecord>,
    pub groups: Vec<OktaGroupRecord>,
    pub applications: Vec<OktaApplicationRecord>,
    pub assignments: Vec<EntitlementBinding>,
    pub next: Option<EntitlementPageCursor>,
    pub complete: bool,
    pub response_bytes: usize,
    pub additive_fields: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemLogPage {
    pub provider_revision: String,
    pub current_cursor: SystemLogCursor,
    pub next_after: Option<SystemLogCursor>,
    pub events: Vec<SystemLogEvent>,
    pub availability: LogAvailability,
    pub complete: bool,
    pub response_bytes: usize,
    pub link_digest: String,
    pub additive_fields: BTreeSet<String>,
}

/// The only provider seam exposed by Layer 1.  Implementations return typed
/// evidence and never receive or return private JWKs, JWT assertions, access
/// tokens, raw profiles, or mutation requests.
pub trait OktaEntitlementTransport: fmt::Debug {
    fn provenance(&self) -> Provenance;

    fn describe_capabilities(&self) -> CapabilityDescription;

    fn probe_registration(
        &mut self,
        scope: &OktaScope,
        observed_at: DateTime<Utc>,
    ) -> Result<GrantReceipt, ProviderError>;

    fn read_entitlement_page(
        &mut self,
        request: &EntitlementPageRequest,
    ) -> Result<EntitlementPage, ProviderError>;

    fn read_system_log_page(
        &mut self,
        request: &SystemLogWindowRequest,
    ) -> Result<SystemLogPage, ProviderError>;
}

/// Typed provider wrapper used by the evidence service and Mission consumer.
pub struct OktaEntitlementProvider {
    backend: Box<dyn OktaEntitlementTransport>,
}

impl fmt::Debug for OktaEntitlementProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OktaEntitlementProvider")
            .field("provenance", &self.provenance())
            .finish_non_exhaustive()
    }
}

impl OktaEntitlementProvider {
    pub fn new(backend: impl OktaEntitlementTransport + 'static) -> Self {
        Self {
            backend: Box::new(backend),
        }
    }

    pub fn from_recording(dataset: RecordingDataset) -> Result<Self, ProviderError> {
        Ok(Self::new(RecordingTransport::new(dataset)?))
    }

    pub fn from_fixture(dataset: RecordingDataset) -> Result<Self, ProviderError> {
        Ok(Self::new(RecordingTransport::fixture(dataset)?))
    }

    pub fn from_loopback(dataset: RecordingDataset) -> Result<Self, ProviderError> {
        Ok(Self::new(RecordingTransport::loopback(dataset)?))
    }

    pub fn blocked_env(reason: impl Into<String>) -> Self {
        Self::new(BlockedEnvTransport::new(reason))
    }

    pub fn provenance(&self) -> Provenance {
        self.backend.provenance()
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        self.backend.describe_capabilities()
    }

    pub fn probe_registration(
        &mut self,
        scope: &OktaScope,
        observed_at: DateTime<Utc>,
    ) -> Result<GrantReceipt, ProviderError> {
        self.backend.probe_registration(scope, observed_at)
    }

    pub fn read_entitlement_page(
        &mut self,
        request: &EntitlementPageRequest,
    ) -> Result<EntitlementPage, ProviderError> {
        self.backend.read_entitlement_page(request)
    }

    pub fn read_system_log_page(
        &mut self,
        request: &SystemLogWindowRequest,
    ) -> Result<SystemLogPage, ProviderError> {
        self.backend.read_system_log_page(request)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingDataset {
    pub org_id: String,
    pub custom_domain: String,
    pub service_app_client_id: String,
    pub granted_scopes: BTreeSet<String>,
    pub admin_resource_set_digest: String,
    pub provider_api_revision: String,
    pub direct_read_revision: String,
    pub users: Vec<OktaUserRecord>,
    pub groups: Vec<OktaGroupRecord>,
    pub applications: Vec<OktaApplicationRecord>,
    pub assignments: Vec<EntitlementBinding>,
    pub system_log_events: Vec<SystemLogEvent>,
    pub retention_start: DateTime<Utc>,
    pub fault: Option<RecordingFault>,
}

impl RecordingDataset {
    pub fn for_scope(scope: &OktaScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            org_id: scope.org_id.clone(),
            custom_domain: scope.custom_domain.clone(),
            service_app_client_id: scope.service_app_client_id.clone(),
            granted_scopes: scope.granted_scopes.clone(),
            admin_resource_set_digest: scope.admin_resource_set_digest.clone(),
            provider_api_revision: PROVIDER_API_REVISION.to_owned(),
            direct_read_revision: "direct-read-1".to_owned(),
            users: Vec::new(),
            groups: Vec::new(),
            applications: Vec::new(),
            assignments: Vec::new(),
            system_log_events: Vec::new(),
            retention_start: observed_at - Duration::days(7),
            fault: None,
        }
    }

    #[must_use]
    pub fn with_fault(mut self, fault: RecordingFault) -> Self {
        self.fault = Some(fault);
        self
    }

    pub fn source_digest(&self, provenance: Provenance) -> String {
        digest_parts(&[
            &self.org_id,
            &self.custom_domain,
            &self.service_app_client_id,
            &self.provider_api_revision,
            provenance.status(),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    dataset: RecordingDataset,
    provenance: Provenance,
}

impl RecordingTransport {
    pub fn new(dataset: RecordingDataset) -> Result<Self, ProviderError> {
        Self::with_provenance(dataset, Provenance::Recording)
    }

    pub fn fixture(dataset: RecordingDataset) -> Result<Self, ProviderError> {
        Self::with_provenance(dataset, Provenance::Fixture)
    }

    pub fn loopback(dataset: RecordingDataset) -> Result<Self, ProviderError> {
        Self::with_provenance(dataset, Provenance::Loopback)
    }

    fn with_provenance(
        dataset: RecordingDataset,
        provenance: Provenance,
    ) -> Result<Self, ProviderError> {
        if dataset.provider_api_revision.is_empty() || dataset.direct_read_revision.is_empty() {
            return Err(ProviderError::Transport(
                "recording provider revision is empty".to_owned(),
            ));
        }
        Ok(Self {
            dataset,
            provenance,
        })
    }

    fn evidence_provenance(&self) -> Result<EvidenceProvenance, ProviderError> {
        EvidenceProvenance::new(self.provenance, self.dataset.source_digest(self.provenance))
            .map_err(|error| ProviderError::Transport(error.to_string()))
    }

    fn fault(&self) -> Option<&RecordingFault> {
        self.dataset.fault.as_ref()
    }

    fn check_common_fault(&self) -> Result<(), ProviderError> {
        match self.fault() {
            Some(RecordingFault::RateLimited {
                retry_after_seconds,
            }) => Err(ProviderError::RateLimited {
                retry_after_seconds: *retry_after_seconds,
            }),
            Some(RecordingFault::PermissionDenied) => Err(ProviderError::PermissionDenied),
            Some(RecordingFault::RequiredFieldDrift { field }) => Err(ProviderError::SchemaDrift {
                field: field.clone(),
            }),
            _ => Ok(()),
        }
    }
}

impl OktaEntitlementTransport for RecordingTransport {
    fn provenance(&self) -> Provenance {
        self.provenance
    }

    fn describe_capabilities(&self) -> CapabilityDescription {
        capability_description(self.provenance)
    }

    fn probe_registration(
        &mut self,
        scope: &OktaScope,
        observed_at: DateTime<Utc>,
    ) -> Result<GrantReceipt, ProviderError> {
        self.check_common_fault()?;
        if matches!(self.fault(), Some(RecordingFault::CrossOrgRedirect))
            || self.dataset.org_id != scope.org_id
            || self.dataset.custom_domain != scope.custom_domain
        {
            return Err(ProviderError::CrossOrgRedirect);
        }
        let response_digest = digest_parts(&[
            &self.dataset.org_id,
            &self.dataset.custom_domain,
            &self.dataset.service_app_client_id,
            &self
                .dataset
                .granted_scopes
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
            &self.dataset.admin_resource_set_digest,
        ]);
        GrantReceipt::new(
            self.dataset.org_id.clone(),
            self.dataset.custom_domain.clone(),
            self.dataset.service_app_client_id.clone(),
            self.dataset.granted_scopes.clone(),
            self.dataset.admin_resource_set_digest.clone(),
            self.dataset.provider_api_revision.clone(),
            observed_at,
            self.evidence_provenance()?,
            response_digest,
        )
        .map_err(|error| ProviderError::Transport(error.to_string()))
    }

    fn read_entitlement_page(
        &mut self,
        request: &EntitlementPageRequest,
    ) -> Result<EntitlementPage, ProviderError> {
        self.check_common_fault()?;
        if request.page_size == 0 || request.page_size > MAX_PAGE_SIZE {
            return Err(ProviderError::Transport(
                "invalid entitlement page size".to_owned(),
            ));
        }
        let offset = if let Some(cursor) = &request.after {
            if !cursor.validate(&request.scope_digest) {
                return Err(ProviderError::CursorInvalid);
            }
            cursor.offset()
        } else {
            0
        };
        let max_len = self
            .dataset
            .users
            .len()
            .max(self.dataset.groups.len())
            .max(self.dataset.applications.len())
            .max(self.dataset.assignments.len());
        if offset > max_len {
            return Err(ProviderError::CursorInvalid);
        }
        let users = slice_page(&self.dataset.users, offset, request.page_size);
        let groups = slice_page(&self.dataset.groups, offset, request.page_size);
        let applications = slice_page(&self.dataset.applications, offset, request.page_size);
        let mut assignments = slice_page(&self.dataset.assignments, offset, request.page_size);
        if let Some(RecordingFault::DuplicateAssignment) = self.fault()
            && let Some(first) = assignments.first().cloned()
        {
            assignments.push(first);
        }
        if let Some(RecordingFault::AssignmentDisagreement) = self.fault()
            && let Some(first) = assignments.first().cloned()
        {
            let mut conflicting = first;
            conflicting.state = match conflicting.state {
                crate::model::AssignmentState::Assigned => {
                    crate::model::AssignmentState::Unassigned
                }
                crate::model::AssignmentState::Unassigned => {
                    crate::model::AssignmentState::Assigned
                }
            };
            assignments.push(conflicting);
        }
        if matches!(self.fault(), Some(RecordingFault::AdditiveField)) {
            // Unknown additive fields are intentionally not surfaced in the typed page.
        }
        if matches!(self.fault(), Some(RecordingFault::ReorderedAssignments)) {
            assignments.reverse();
        }
        let next_offset = offset.saturating_add(request.page_size);
        let has_more = next_offset < max_len;
        let next = if has_more && !matches!(self.fault(), Some(RecordingFault::MissingPage)) {
            if matches!(self.fault(), Some(RecordingFault::OpaqueCursorTampered)) {
                Some(EntitlementPageCursor::tampered(
                    &request.scope_digest,
                    next_offset,
                ))
            } else {
                Some(EntitlementPageCursor::new(
                    PROVIDER_ID,
                    &request.scope_digest,
                    next_offset,
                ))
            }
        } else {
            None
        };
        let mut response_bytes =
            512 + (users.len() + groups.len() + applications.len() + assignments.len()) * 256;
        if matches!(self.fault(), Some(RecordingFault::ResponseTooLarge)) {
            response_bytes = MAX_RESPONSE_BYTES + 1;
        }
        Ok(EntitlementPage {
            provider_revision: if matches!(self.fault(), Some(RecordingFault::StaleDirectRead)) {
                "stale-direct-read".to_owned()
            } else {
                self.dataset.provider_api_revision.clone()
            },
            direct_read_revision: if matches!(self.fault(), Some(RecordingFault::StaleDirectRead)) {
                "stale-direct-read".to_owned()
            } else {
                self.dataset.direct_read_revision.clone()
            },
            users,
            groups,
            applications,
            assignments,
            next,
            complete: !matches!(self.fault(), Some(RecordingFault::MissingPage)),
            response_bytes,
            additive_fields: if matches!(self.fault(), Some(RecordingFault::AdditiveField)) {
                BTreeSet::from(["future_additive_field".to_owned()])
            } else {
                BTreeSet::new()
            },
        })
    }

    fn read_system_log_page(
        &mut self,
        request: &SystemLogWindowRequest,
    ) -> Result<SystemLogPage, ProviderError> {
        self.check_common_fault()?;
        if request.scope_digest.len() != 64 {
            return Err(ProviderError::ScopeMismatch);
        }
        let window_digest = request.window_digest();
        let offset = if let Some(cursor) = request.after() {
            if !cursor.validate(&request.scope_digest, &window_digest) {
                return Err(ProviderError::CursorInvalid);
            }
            cursor.offset()
        } else {
            0
        };
        let (since, until) = match request.mode {
            crate::model::LogWindowMode::Polling { since } => (since, None),
            crate::model::LogWindowMode::Bounded { since, until } => (since, Some(until)),
        };
        let retention_gap = matches!(self.fault(), Some(RecordingFault::RetentionGap))
            || since < self.dataset.retention_start;
        let mut events = self
            .dataset
            .system_log_events
            .iter()
            .filter(|event| {
                event.published_at >= since && until.is_none_or(|until| event.published_at <= until)
            })
            .cloned()
            .collect::<Vec<_>>();
        if retention_gap {
            events.clear();
        }
        if offset > events.len() {
            return Err(ProviderError::CursorInvalid);
        }
        let page_size = request.max_events.min(MAX_SYSTEM_LOG_EVENTS);
        let page_events = slice_page(&events, offset, page_size);
        let next_offset = offset.saturating_add(page_size);
        let has_more = next_offset < events.len();
        let next_after = if has_more {
            if matches!(self.fault(), Some(RecordingFault::OpaqueCursorTampered)) {
                Some(SystemLogCursor::tampered(
                    &request.scope_digest,
                    &window_digest,
                    next_offset,
                ))
            } else {
                Some(SystemLogCursor::new(
                    PROVIDER_ID,
                    &request.scope_digest,
                    &window_digest,
                    next_offset,
                ))
            }
        } else {
            None
        };
        let current_cursor =
            SystemLogCursor::new(PROVIDER_ID, &request.scope_digest, &window_digest, offset);
        let response_bytes = 256 + page_events.len() * 384;
        Ok(SystemLogPage {
            provider_revision: self.dataset.provider_api_revision.clone(),
            current_cursor,
            next_after,
            events: page_events,
            availability: if retention_gap {
                LogAvailability::Unavailable {
                    reason: "outside provider retention window".to_owned(),
                }
            } else {
                LogAvailability::Complete
            },
            complete: !matches!(self.fault(), Some(RecordingFault::MissingPage)),
            response_bytes,
            link_digest: digest_parts(&[
                &request.scope_digest,
                &window_digest,
                &offset.to_string(),
                &events.len().to_string(),
            ]),
            additive_fields: if matches!(self.fault(), Some(RecordingFault::AdditiveField)) {
                BTreeSet::from(["future_additive_field".to_owned()])
            } else {
                BTreeSet::new()
            },
        })
    }
}

#[derive(Clone, Debug)]
pub struct BlockedEnvTransport {
    reason: String,
}

impl BlockedEnvTransport {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl OktaEntitlementTransport for BlockedEnvTransport {
    fn provenance(&self) -> Provenance {
        Provenance::BlockedEnv
    }

    fn describe_capabilities(&self) -> CapabilityDescription {
        capability_description(Provenance::BlockedEnv)
    }

    fn probe_registration(
        &mut self,
        _scope: &OktaScope,
        _observed_at: DateTime<Utc>,
    ) -> Result<GrantReceipt, ProviderError> {
        Err(ProviderError::BlockedEnv {
            reason: self.reason.clone(),
        })
    }

    fn read_entitlement_page(
        &mut self,
        _request: &EntitlementPageRequest,
    ) -> Result<EntitlementPage, ProviderError> {
        Err(ProviderError::BlockedEnv {
            reason: self.reason.clone(),
        })
    }

    fn read_system_log_page(
        &mut self,
        _request: &SystemLogWindowRequest,
    ) -> Result<SystemLogPage, ProviderError> {
        Err(ProviderError::BlockedEnv {
            reason: self.reason.clone(),
        })
    }
}

fn capability_description(provenance: Provenance) -> CapabilityDescription {
    CapabilityDescription {
        plugin_id: PLUGIN_ID.to_owned(),
        plugin_version: PLUGIN_VERSION.to_owned(),
        contract_version: CONTRACT_VERSION.to_owned(),
        contract_digest: crate::contract_digest(),
        provider_id: PROVIDER_ID.to_owned(),
        provider_api_revision: PROVIDER_API_REVISION.to_owned(),
        capability_id: CAPABILITY_ID.to_owned(),
        operations: BTreeSet::from([
            CapabilityOperation::DescribeCapabilities,
            CapabilityOperation::ProbeRegistration,
            CapabilityOperation::ReadEntitlementSnapshot,
            CapabilityOperation::ReadSystemLogWindow,
            CapabilityOperation::CompileAccessChangeProposal,
            CapabilityOperation::VerifyEntitlementEvidence,
        ]),
        authentication_method: "oauth2_service_app_private_key_jwt".to_owned(),
        read_only: true,
        connected: false,
        native: false,
        mutation_authority: false,
        provenance,
    }
}

fn slice_page<T: Clone>(values: &[T], offset: usize, page_size: usize) -> Vec<T> {
    let start = offset.min(values.len());
    let end = start.saturating_add(page_size).min(values.len());
    values[start..end].to_vec()
}
