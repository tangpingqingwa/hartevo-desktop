use chrono::{DateTime, Utc};

use crate::model::{
    AccessChangeOperation, AccessChangeProposal, EntitlementEvidenceProposal, EntitlementSnapshot,
    MissionScope, SystemLogReceipt, SystemLogWindowRequest,
};
use crate::service::{OktaEntitlementError, OktaEntitlementEvidenceService};

/// Mission-facing consumer for external Okta entitlement evidence.
///
/// The consumer checks the exact Project/Mission/revision/Consent scope before
/// delegating to the service.  It has no identity, consent, effect, receipt,
/// verification, or outcome authority of its own.
pub struct MissionOktaEntitlementConsumer {
    service: OktaEntitlementEvidenceService,
}

impl std::fmt::Debug for MissionOktaEntitlementConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionOktaEntitlementConsumer")
            .field("service", &self.service)
            .finish()
    }
}

impl MissionOktaEntitlementConsumer {
    pub fn new(service: OktaEntitlementEvidenceService) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &OktaEntitlementEvidenceService {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut OktaEntitlementEvidenceService {
        &mut self.service
    }

    pub fn into_service(self) -> OktaEntitlementEvidenceService {
        self.service
    }

    pub fn is_connected(&self) -> bool {
        false
    }

    pub fn is_native(&self) -> bool {
        false
    }

    pub fn inspect_entitlements(
        &mut self,
        mission: &MissionScope,
        observed_at: DateTime<Utc>,
    ) -> Result<EntitlementSnapshot, OktaEntitlementError> {
        self.ensure_mission(mission)?;
        self.service.read_entitlement_snapshot(observed_at)
    }

    pub fn inspect_entitlements_with_bounds(
        &mut self,
        mission: &MissionScope,
        observed_at: DateTime<Utc>,
        bounds: crate::ReadBounds,
    ) -> Result<EntitlementSnapshot, OktaEntitlementError> {
        self.ensure_mission(mission)?;
        self.service
            .read_entitlement_snapshot_with_bounds(observed_at, bounds)
    }

    pub fn inspect_system_log(
        &mut self,
        mission: &MissionScope,
        request: SystemLogWindowRequest,
    ) -> Result<SystemLogReceipt, OktaEntitlementError> {
        self.ensure_mission(mission)?;
        self.service.read_system_log_window(request)
    }

    pub fn propose_access_change(
        &self,
        mission: &MissionScope,
        operation: AccessChangeOperation,
        expected_snapshot_digest: impl Into<String>,
    ) -> Result<AccessChangeProposal, OktaEntitlementError> {
        self.ensure_mission(mission)?;
        self.service
            .compile_access_change_proposal(operation, expected_snapshot_digest)
    }

    pub fn verify_entitlement_evidence(
        &self,
        mission: &MissionScope,
        snapshot: EntitlementSnapshot,
        supplemental_system_log: Option<SystemLogReceipt>,
    ) -> Result<EntitlementEvidenceProposal, OktaEntitlementError> {
        self.ensure_mission(mission)?;
        if self.service.scope() != &snapshot.scope {
            return Err(OktaEntitlementError::MissionScopeMismatch);
        }
        self.service
            .verify_entitlement_evidence(snapshot, supplemental_system_log)
    }

    fn ensure_mission(&self, mission: &MissionScope) -> Result<(), OktaEntitlementError> {
        if self.service.scope().matches_mission(mission) {
            Ok(())
        } else {
            Err(OktaEntitlementError::MissionScopeMismatch)
        }
    }
}
