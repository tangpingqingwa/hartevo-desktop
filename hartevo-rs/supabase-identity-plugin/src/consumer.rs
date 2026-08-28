use chrono::{DateTime, Utc};

use crate::SupabaseIdentityError;
use crate::model::{
    DatabasePrivilege, IdentityProjection, MissionScope, MissionSupabaseIdentityResult,
    PolicyDecision, PolicyDecisionProposal, PolicyProjection, SupabaseEvidencePack, TableScope,
};
use crate::service::SupabaseIdentityService;

/// Mission-facing consumer.  It binds provider evidence and a policy
/// proposal to an exact Mission/Project/Work Product/Consent scope while
/// retaining no Hartevo identity, consent, effect, receipt, verification, or
/// outcome authority.
pub struct MissionSupabaseIdentityConsumer {
    service: SupabaseIdentityService,
}

impl std::fmt::Debug for MissionSupabaseIdentityConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionSupabaseIdentityConsumer")
            .field("service", &self.service)
            .finish()
    }
}

impl MissionSupabaseIdentityConsumer {
    pub fn new(service: SupabaseIdentityService) -> Self {
        Self { service }
    }

    pub fn with_service(service: SupabaseIdentityService) -> Self {
        Self::new(service)
    }

    pub fn service(&self) -> &SupabaseIdentityService {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut SupabaseIdentityService {
        &mut self.service
    }

    pub fn into_service(self) -> SupabaseIdentityService {
        self.service
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub fn inspect_identity(
        &self,
        mission: &MissionScope,
        observed_at: DateTime<Utc>,
    ) -> Result<IdentityProjection, SupabaseIdentityError> {
        self.ensure_mission(mission)?;
        self.service.read_identity(observed_at)
    }

    pub fn inspect_policy(
        &self,
        mission: &MissionScope,
        observed_at: DateTime<Utc>,
    ) -> Result<PolicyProjection, SupabaseIdentityError> {
        self.ensure_mission(mission)?;
        self.service.read_policy(observed_at)
    }

    pub fn inspect(
        &self,
        mission: &MissionScope,
        observed_at: DateTime<Utc>,
    ) -> Result<MissionSupabaseIdentityResult, SupabaseIdentityError> {
        self.ensure_mission(mission)?;
        let evidence = self.service.read_evidence(observed_at)?;
        Ok(MissionSupabaseIdentityResult {
            mission: mission.clone(),
            evidence,
            proposal: None,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the Mission seam keeps the proposal inputs explicit and typed"
    )]
    pub fn inspect_and_propose(
        &self,
        mission: &MissionScope,
        observed_at: DateTime<Utc>,
        requested_decision: PolicyDecision,
        table: TableScope,
        role: impl Into<String>,
        privilege: DatabasePrivilege,
        reason_code: impl Into<String>,
    ) -> Result<MissionSupabaseIdentityResult, SupabaseIdentityError> {
        self.ensure_mission(mission)?;
        let evidence = self.service.read_evidence(observed_at)?;
        let proposal = self.service.compile_policy_decision_proposal(
            mission,
            &evidence,
            requested_decision,
            table,
            role,
            privilege,
            reason_code,
        )?;
        Ok(MissionSupabaseIdentityResult {
            mission: mission.clone(),
            evidence,
            proposal: Some(proposal),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the Mission seam keeps the proposal inputs explicit and typed"
    )]
    pub fn propose_policy_decision(
        &self,
        mission: &MissionScope,
        evidence: &SupabaseEvidencePack,
        requested_decision: PolicyDecision,
        table: TableScope,
        role: impl Into<String>,
        privilege: DatabasePrivilege,
        reason_code: impl Into<String>,
    ) -> Result<PolicyDecisionProposal, SupabaseIdentityError> {
        self.ensure_mission(mission)?;
        self.service.compile_policy_decision_proposal(
            mission,
            evidence,
            requested_decision,
            table,
            role,
            privilege,
            reason_code,
        )
    }

    fn ensure_mission(&self, mission: &MissionScope) -> Result<(), SupabaseIdentityError> {
        mission.validate()?;
        if self.service.scope().matches_mission(mission) {
            Ok(())
        } else {
            Err(SupabaseIdentityError::MissionScopeMismatch)
        }
    }
}

/// Issue-compatible alias for the policy-oriented name.
pub type MissionSupabasePolicyConsumer = MissionSupabaseIdentityConsumer;
