use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::canonical::digest_parts;
use crate::model::{
    AccessChangeOperation, AccessChangeProposal, CapabilityRegistration, DirectReadReceipt,
    EntitlementBinding, EntitlementEvidenceProposal, EntitlementEvidenceStatus,
    EntitlementSnapshot, ModelError, OktaScope, ReadBounds, RegistrationProbe, SystemLogReceipt,
    SystemLogWindowRequest,
};
use crate::provider::{EntitlementPageRequest, OktaEntitlementProvider, ProviderError};
use crate::{
    MAX_PAGES, REQUIRED_APPLICATION_READ_SCOPE, REQUIRED_GROUP_READ_SCOPE,
    REQUIRED_SYSTEM_LOG_READ_SCOPE, REQUIRED_USER_READ_SCOPE,
};

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum OktaEntitlementError {
    #[error("model validation failed: {0}")]
    Model(String),
    #[error("registration is not active")]
    RegistrationInactive,
    #[error("registration contract, grant, or scope drifted")]
    RegistrationDrift,
    #[error("required read scope is not granted: {0}")]
    MissingReadScope(String),
    #[error("mission/project/consent scope does not match the registration")]
    MissionScopeMismatch,
    #[error("provider error: {0}")]
    Provider(ProviderError),
    #[error("provider returned a different direct-read revision during the snapshot")]
    DirectReadRevisionDrift,
    #[error("provider returned a duplicate entitlement assignment")]
    DuplicateAssignment,
    #[error("provider returned conflicting assignment state for one immutable target")]
    AssignmentDisagreement,
    #[error("provider page set ended without a complete snapshot")]
    IncompleteSnapshot,
    #[error("configured evidence bounds were exceeded")]
    BoundsExceeded,
    #[error("provider returned duplicate System Log event IDs")]
    DuplicateSystemLogEvent,
    #[error("snapshot or supplemental System Log receipt is outside this registration")]
    EvidenceScopeMismatch,
}

impl From<ModelError> for OktaEntitlementError {
    fn from(error: ModelError) -> Self {
        Self::Model(error.to_string())
    }
}

impl From<ProviderError> for OktaEntitlementError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

/// Service-owned typed Layer-1 boundary.  Its methods are read/proposal-only;
/// no provider mutation method exists on this type.
pub struct OktaEntitlementEvidenceService {
    provider: OktaEntitlementProvider,
    registration: CapabilityRegistration,
    grant: crate::OAuthServiceAppGrant,
}

impl fmt::Debug for OktaEntitlementEvidenceService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OktaEntitlementEvidenceService")
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("grant", &self.grant)
            .finish()
    }
}

impl OktaEntitlementEvidenceService {
    pub fn new(
        provider: OktaEntitlementProvider,
        registration: CapabilityRegistration,
        grant: crate::OAuthServiceAppGrant,
    ) -> Result<Self, OktaEntitlementError> {
        registration
            .scope
            .validate()
            .map_err(|_| OktaEntitlementError::RegistrationDrift)?;
        registration
            .assert_fences(&registration.scope, &grant)
            .map_err(|_| OktaEntitlementError::RegistrationDrift)?;
        if grant.authentication().secret_reference().scope_digest() != registration.scope_digest {
            return Err(OktaEntitlementError::RegistrationDrift);
        }
        Ok(Self {
            provider,
            registration,
            grant,
        })
    }

    pub fn register(
        provider: OktaEntitlementProvider,
        registration_id: impl Into<String>,
        scope: OktaScope,
        grant: crate::OAuthServiceAppGrant,
    ) -> Result<Self, OktaEntitlementError> {
        let registration = CapabilityRegistration::new(registration_id, scope, &grant)?;
        Self::new(provider, registration, grant)
    }

    pub fn provider(&self) -> &OktaEntitlementProvider {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut OktaEntitlementProvider {
        &mut self.provider
    }

    pub fn registration(&self) -> &CapabilityRegistration {
        &self.registration
    }

    pub fn grant(&self) -> &crate::OAuthServiceAppGrant {
        &self.grant
    }

    pub fn scope(&self) -> &OktaScope {
        &self.registration.scope
    }

    pub fn describe_capabilities(&self) -> crate::CapabilityDescription {
        self.provider.describe_capabilities()
    }

    pub fn reverse_registration(&mut self) -> Result<(), OktaEntitlementError> {
        self.registration.reverse()?;
        Ok(())
    }

    pub fn restore_registration(&mut self) -> Result<(), OktaEntitlementError> {
        self.registration.restore()?;
        Ok(())
    }

    pub fn revoke_registration(&mut self) -> Result<(), OktaEntitlementError> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn probe_registration(
        &mut self,
        observed_at: DateTime<Utc>,
    ) -> Result<RegistrationProbe, OktaEntitlementError> {
        self.ensure_active()?;
        let scope = self.scope().clone();
        let grant_receipt = self.provider.probe_registration(&scope, observed_at)?;
        grant_receipt.assert_matches(&scope, &self.grant)?;
        RegistrationProbe::new(&self.registration, grant_receipt).map_err(Into::into)
    }

    pub fn read_entitlement_snapshot(
        &mut self,
        observed_at: DateTime<Utc>,
    ) -> Result<EntitlementSnapshot, OktaEntitlementError> {
        self.read_entitlement_snapshot_with_bounds(observed_at, ReadBounds::default())
    }

    #[allow(clippy::too_many_lines)]
    pub fn read_entitlement_snapshot_with_bounds(
        &mut self,
        observed_at: DateTime<Utc>,
        bounds: ReadBounds,
    ) -> Result<EntitlementSnapshot, OktaEntitlementError> {
        self.ensure_active()?;
        bounds.validate()?;
        self.require_scopes(&[
            REQUIRED_USER_READ_SCOPE,
            REQUIRED_GROUP_READ_SCOPE,
            REQUIRED_APPLICATION_READ_SCOPE,
        ])?;
        self.probe_registration(observed_at)?;

        let mut request = EntitlementPageRequest::new(
            self.scope(),
            bounds,
            &self.registration.provider_api_revision,
        );
        let mut users = BTreeMap::new();
        let mut groups = BTreeMap::new();
        let mut applications = BTreeMap::new();
        let mut assignments = BTreeMap::new();
        let mut pages: usize = 0;
        let mut response_bytes = 0usize;
        let mut direct_revision: Option<String> = None;
        let complete = loop {
            pages = pages.saturating_add(1);
            if pages > bounds.max_pages {
                return Err(OktaEntitlementError::BoundsExceeded);
            }
            let page = self.provider.read_entitlement_page(&request)?;
            response_bytes = response_bytes
                .checked_add(page.response_bytes)
                .ok_or(OktaEntitlementError::BoundsExceeded)?;
            if response_bytes > bounds.max_response_bytes {
                return Err(OktaEntitlementError::BoundsExceeded);
            }
            if page.provider_revision != self.registration.provider_api_revision {
                return Err(OktaEntitlementError::DirectReadRevisionDrift);
            }
            if let Some(existing) = &direct_revision {
                if existing != &page.direct_read_revision {
                    return Err(OktaEntitlementError::DirectReadRevisionDrift);
                }
            } else {
                direct_revision = Some(page.direct_read_revision.clone());
            }
            for user in page.users {
                users.insert(user.id.clone(), user);
            }
            for group in page.groups {
                groups.insert(group.id.clone(), group);
            }
            for application in page.applications {
                applications.insert(application.id.clone(), application);
            }
            for assignment in page.assignments {
                assignment.validate()?;
                let key = assignment.key();
                if let Some(existing) = assignments.get(&key) {
                    if existing == &assignment {
                        return Err(OktaEntitlementError::DuplicateAssignment);
                    }
                    return Err(OktaEntitlementError::AssignmentDisagreement);
                }
                assignments.insert(key, assignment);
            }
            let item_count = users.len() + groups.len() + applications.len() + assignments.len();
            if item_count > bounds.max_items {
                return Err(OktaEntitlementError::BoundsExceeded);
            }
            match page.next {
                Some(after) => request = request.with_after(&after),
                None => {
                    break page.complete;
                }
            }
        };
        if !complete {
            return Err(OktaEntitlementError::IncompleteSnapshot);
        }

        let provider_revision = self.registration.provider_api_revision.clone();
        let users = users.into_values().collect::<Vec<_>>();
        let groups = groups.into_values().collect::<Vec<_>>();
        let applications = applications.into_values().collect::<Vec<_>>();
        let mut assignments = assignments.into_values().collect::<Vec<_>>();
        assignments.sort_by_key(EntitlementBinding::key);
        let provenance = crate::EvidenceProvenance::new(
            self.provider.provenance(),
            digest_parts(&[
                &self.registration.registration_digest,
                self.provider.provenance().status(),
            ]),
        )?;
        let assignment_set_digest = crate::canonical::canonical_digest(&assignments)
            .map_err(|error| OktaEntitlementError::Model(error.to_string()))?;
        let direct_read = DirectReadReceipt::new(
            provider_revision.clone(),
            direct_revision
                .clone()
                .ok_or(OktaEntitlementError::IncompleteSnapshot)?,
            observed_at,
            pages,
            users.len() + groups.len() + applications.len() + assignments.len(),
            response_bytes,
            self.scope().digest(),
            assignment_set_digest,
            provenance,
        )?;
        EntitlementSnapshot::new(
            self.scope().clone(),
            provider_revision,
            observed_at,
            users,
            groups,
            applications,
            assignments,
            direct_read,
        )
        .map_err(Into::into)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn read_system_log_window(
        &mut self,
        request: SystemLogWindowRequest,
    ) -> Result<SystemLogReceipt, OktaEntitlementError> {
        self.ensure_active()?;
        request.validate()?;
        self.require_scopes(&[REQUIRED_SYSTEM_LOG_READ_SCOPE])?;
        if request.scope_digest != self.scope().digest() {
            return Err(OktaEntitlementError::EvidenceScopeMismatch);
        }
        self.probe_registration(request_time(&request))?;

        let mut current_request = request.clone();
        let mut events = Vec::new();
        let mut event_ids = BTreeSet::new();
        let mut pages: usize = 0;
        let mut response_bytes = 0usize;
        let mut next_after = None;
        let mut link_digests = Vec::new();
        let mut provider_revision: Option<String> = None;
        let (availability, next_after) = loop {
            pages = pages.saturating_add(1);
            if pages > MAX_PAGES {
                return Err(OktaEntitlementError::BoundsExceeded);
            }
            let page = self.provider.read_system_log_page(&current_request)?;
            response_bytes = response_bytes
                .checked_add(page.response_bytes)
                .ok_or(OktaEntitlementError::BoundsExceeded)?;
            if response_bytes > current_request.max_response_bytes {
                return Err(OktaEntitlementError::BoundsExceeded);
            }
            if page.provider_revision != self.registration.provider_api_revision {
                return Err(OktaEntitlementError::DirectReadRevisionDrift);
            }
            if let Some(existing) = &provider_revision {
                if existing != &page.provider_revision {
                    return Err(OktaEntitlementError::DirectReadRevisionDrift);
                }
            } else {
                provider_revision = Some(page.provider_revision.clone());
            }
            link_digests.push(page.link_digest);
            if matches!(
                &page.availability,
                crate::LogAvailability::Unavailable { .. }
            ) {
                break (page.availability, next_after);
            }
            for event in page.events {
                event.verify_integrity()?;
                if !event_ids.insert(event.event_id.clone()) {
                    return Err(OktaEntitlementError::DuplicateSystemLogEvent);
                }
                events.push(event);
            }
            if let Some(after) = page.next_after {
                next_after = Some(after.clone());
                current_request = current_request.with_after(&after);
            } else {
                if !page.complete {
                    return Err(OktaEntitlementError::IncompleteSnapshot);
                }
                break (page.availability, next_after);
            }
        };
        let provider_revision =
            provider_revision.ok_or(OktaEntitlementError::IncompleteSnapshot)?;
        let link_digest =
            digest_parts(&link_digests.iter().map(String::as_str).collect::<Vec<_>>());
        let provenance = crate::EvidenceProvenance::new(
            self.provider.provenance(),
            digest_parts(&[
                &self.registration.registration_digest,
                self.provider.provenance().status(),
            ]),
        )?;
        SystemLogReceipt::new(
            provider_revision,
            &request,
            events,
            availability,
            pages,
            response_bytes,
            link_digest,
            next_after,
            provenance,
        )
        .map_err(Into::into)
    }

    pub fn compile_access_change_proposal(
        &self,
        operation: AccessChangeOperation,
        expected_snapshot_digest: impl Into<String>,
    ) -> Result<AccessChangeProposal, OktaEntitlementError> {
        self.ensure_active()?;
        AccessChangeProposal::new(self.scope(), operation, expected_snapshot_digest)
            .map_err(Into::into)
    }

    pub fn verify_entitlement_evidence(
        &self,
        snapshot: EntitlementSnapshot,
        supplemental_system_log: Option<SystemLogReceipt>,
    ) -> Result<EntitlementEvidenceProposal, OktaEntitlementError> {
        self.ensure_active()?;
        snapshot.verify_integrity()?;
        if snapshot.scope != *self.scope()
            || snapshot.direct_read.provider_revision != self.registration.provider_api_revision
        {
            return Err(OktaEntitlementError::EvidenceScopeMismatch);
        }
        let status = match &supplemental_system_log {
            Some(receipt) => {
                receipt.verify_integrity()?;
                if receipt.scope_digest != self.scope().digest()
                    || receipt.provider_revision != self.registration.provider_api_revision
                {
                    return Err(OktaEntitlementError::EvidenceScopeMismatch);
                }
                match &receipt.availability {
                    crate::LogAvailability::Complete => {
                        EntitlementEvidenceStatus::DirectReadWithSupplementalLog
                    }
                    crate::LogAvailability::Unavailable { .. } => {
                        EntitlementEvidenceStatus::DirectReadWithLogUnavailable
                    }
                }
            }
            None => EntitlementEvidenceStatus::DirectReadAuthoritative,
        };
        EntitlementEvidenceProposal::new(snapshot, supplemental_system_log, status)
            .map_err(Into::into)
    }

    fn ensure_active(&self) -> Result<(), OktaEntitlementError> {
        if !self.registration.is_active() {
            return Err(OktaEntitlementError::RegistrationInactive);
        }
        self.registration
            .assert_fences(self.scope(), &self.grant)
            .map_err(|_| OktaEntitlementError::RegistrationDrift)
    }

    fn require_scopes(&self, required: &[&str]) -> Result<(), OktaEntitlementError> {
        if let Some(missing) = required
            .iter()
            .find(|scope| !self.scope().granted_scopes.contains(**scope))
        {
            return Err(OktaEntitlementError::MissingReadScope(
                (*missing).to_owned(),
            ));
        }
        Ok(())
    }
}

fn request_time(request: &SystemLogWindowRequest) -> DateTime<Utc> {
    match &request.mode {
        crate::LogWindowMode::Polling { since } | crate::LogWindowMode::Bounded { since, .. } => {
            *since
        }
    }
}
