//! VM-03 reuses the existing Cordis proposal, approval, execution and recovery seams.

use chrono::{DateTime, Duration, Utc};
use hartevo_application::{
    ApplicationError, CompleteVm03DomainPurchase, ProposeVm03DomainPurchase,
    VM03_DOMAIN_PURCHASE_CHECKPOINT_ID, vm03_domain_purchase_effect_policy,
    vm03_domain_purchase_verified_receipt,
};
use hartevo_cordis::{CordisError, DomainCommandBinding, DomainCommandKind};
use hartevo_domain_kernel::{Effect, EffectStatus, Mission};
use hartevo_effect_broker::{EffectBroker, EffectExecutor, EffectVerifier, ExecutionDisposition};
use sha2::{Digest, Sha256};

use super::{
    DesktopApprovedEffectExecution, DesktopApprovedEffectExecutionRequest, DesktopDataError,
    DesktopDataPlane, DesktopDomainCommandAuthorization, DesktopSnapshot, OS_SECRET_SERVICE,
    OsSecretStore, SecretStore, dispatch_live_domain_command, effect_proposal_authority_field,
    is_canonical_sha256, live_domain_kernel_facts, load_product_evidence,
    map_domain_command_dispatch_result, mission_authority_scope,
};

impl DesktopDataPlane {
    pub fn propose_vm03_domain_purchase_os(
        &self,
        command: &ProposeVm03DomainPurchase,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        self.propose_vm03_domain_purchase_with(
            &OsSecretStore::new(OS_SECRET_SERVICE)?,
            command,
            now,
        )
    }

    /// A proposal freezes the adopted quote and stops at WaitingApproval.
    pub fn propose_vm03_domain_purchase_with(
        &self,
        secret_store: &impl SecretStore,
        command: &ProposeVm03DomainPurchase,
        now: DateTime<Utc>,
    ) -> Result<DesktopSnapshot, DesktopDataError> {
        let (mut service, runtime_reconciliation, _context_session) =
            self.open_ready_runtime_project(secret_store, &command.project_id, now)?;
        let scope = mission_authority_scope(&service, &command.project_id, &command.mission_id)?;
        if scope.mission_revision() != command.expected_mission_revision {
            return Err(ApplicationError::MissionRevisionMismatch {
                expected: command.expected_mission_revision,
                actual: scope.mission_revision(),
            }
            .into());
        }
        let mut hasher = Sha256::new();
        effect_proposal_authority_field(
            &mut hasher,
            "domain",
            b"hartevo.cordis.vm03-domain-purchase/v1",
        );
        effect_proposal_authority_field(&mut hasher, "tenant", scope.tenant_id().as_bytes());
        effect_proposal_authority_field(&mut hasher, "project", scope.project_id().as_bytes());
        effect_proposal_authority_field(&mut hasher, "mission", scope.mission_id().as_bytes());
        effect_proposal_authority_field(
            &mut hasher,
            "mission_revision",
            &scope.mission_revision().to_be_bytes(),
        );
        effect_proposal_authority_field(&mut hasher, "proposed_at", now.to_rfc3339().as_bytes());
        effect_proposal_authority_field(
            &mut hasher,
            "proposal",
            &command.authority_payload_bytes()?,
        );
        let proposal_digest = format!("{:x}", hasher.finalize());
        let facts =
            live_domain_kernel_facts(&service, &command.project_id, &command.mission_id, now)?;
        let binding = DomainCommandBinding::propose_effect(
            command.effect_id.as_str(),
            proposal_digest.clone(),
        )?;
        map_domain_command_dispatch_result(dispatch_live_domain_command(
            &self.cordis,
            DesktopDomainCommandAuthorization::new(scope, binding),
            &facts.consent,
            facts.record.as_ref(),
            facts.approval.as_ref(),
            now,
            |permit| {
                let current =
                    mission_authority_scope(&service, &command.project_id, &command.mission_id)?;
                if &current != permit.scope()
                    || permit.command().kind() != DomainCommandKind::ProposeEffect
                    || permit.command().effect_id() != command.effect_id.as_str()
                    || permit.command().proposal_digest() != Some(proposal_digest.as_str())
                    || permit.command().approval_scope_digest().is_some()
                {
                    return Err(CordisError::DomainCommandPermitMismatch.into());
                }
                if service.propose_vm03_domain_purchase(command, now)? != command.effect_id {
                    return Err(CordisError::DomainCommandPermitMismatch.into());
                }
                Ok(())
            },
        ))?;
        self.build_snapshot(
            &service,
            secret_store,
            runtime_reconciliation,
            load_product_evidence(now)?,
            now,
        )
    }

    pub(super) fn vm03_domain_purchase_broker(
        mission: &Mission,
        effect: &Effect,
    ) -> Result<EffectBroker, DesktopDataError> {
        Ok(EffectBroker::new(
            vm03_domain_purchase_effect_policy(mission, effect)?,
            "desktop-vm03-domain-purchase-worker",
        )
        .with_lease_for(Duration::days(36_500)))
    }

    /// No default registrar is wired here. Callers must supply an executor and an independent verifier.
    /// Verified recovery skips the executor, including after the quote has expired.
    #[allow(
        clippy::too_many_lines,
        reason = "first execution and durable verification recovery converge on one exact Application completion boundary"
    )]
    pub fn execute_vm03_domain_purchase_with<Executor: EffectExecutor, Verifier: EffectVerifier>(
        &self,
        secret_store: &impl SecretStore,
        request: &DesktopApprovedEffectExecutionRequest,
        executor: &mut Executor,
        verifier: &mut Verifier,
        now: DateTime<Utc>,
    ) -> Result<DesktopApprovedEffectExecution, DesktopDataError> {
        if request.expected_mission_revision == 0
            || request.effect_id.as_str().trim().is_empty()
            || !is_canonical_sha256(&request.expected_scope_digest)
            || !is_canonical_sha256(&request.expected_broker_authorization_digest)
        {
            return Err(DesktopDataError::InvalidApprovedEffectExecution);
        }
        let (service, _, context_session) =
            self.open_ready_runtime_project(secret_store, &request.project_id, now)?;
        let mission = service.load_mission(&request.project_id, &request.mission_id)?;
        let effect = mission
            .effect(&request.effect_id)
            .map_err(ApplicationError::from)?;
        let disposition = if effect.status == EffectStatus::Verified {
            ExecutionDisposition::AlreadyVerified
        } else {
            let mut broker = Self::vm03_domain_purchase_broker(&mission, effect)?;
            drop(service);
            drop(context_session);
            self.execute_approved_effect_with(
                secret_store,
                request.clone(),
                &mut broker,
                executor,
                verifier,
                now,
            )?
            .disposition
        };
        let (mut service, runtime_reconciliation, _context_session) =
            self.open_ready_runtime_project(secret_store, &request.project_id, now)?;
        let mission = service.load_mission(&request.project_id, &request.mission_id)?;
        let effect = mission
            .effect(&request.effect_id)
            .map_err(ApplicationError::from)?;
        let (receipt, verification) = vm03_domain_purchase_verified_receipt(&mission, effect)?;
        let approval = effect
            .approval
            .as_ref()
            .ok_or(DesktopDataError::InvalidApprovedEffectExecution)?;
        if approval.scope_digest != request.expected_scope_digest
            || approval.permission_digest != request.expected_broker_authorization_digest
        {
            return Err(DesktopDataError::InvalidApprovedEffectExecution);
        }
        let receipt_id = receipt.id.clone();
        let verification_id = verification.id.clone();
        let verification_status = verification.status.clone();
        let verification_independent = verification.independent;
        let completed_at = std::cmp::max(now, verification.observed_at);
        let checkpoint_revision = mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == VM03_DOMAIN_PURCHASE_CHECKPOINT_ID)
            })
            .map(|checkpoint| checkpoint.revision)
            .ok_or(ApplicationError::Vm03DomainPurchaseMismatch)?;
        service.complete_vm03_domain_purchase(
            &CompleteVm03DomainPurchase {
                project_id: request.project_id.clone(),
                mission_id: request.mission_id.clone(),
                effect_id: request.effect_id.clone(),
                expected_mission_revision: mission.revision,
                expected_checkpoint_revision: checkpoint_revision,
            },
            completed_at,
        )?;
        Ok(DesktopApprovedEffectExecution {
            snapshot: self.build_snapshot(
                &service,
                secret_store,
                runtime_reconciliation,
                load_product_evidence(completed_at)?,
                completed_at,
            )?,
            disposition,
            receipt_id,
            verification_id,
            verification_status,
            verification_independent,
        })
    }
}
