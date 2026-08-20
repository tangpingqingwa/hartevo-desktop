//! Mission-facing consumer that keeps Application Signals evidence outside
//! kernel Truth/Outcome authority.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AwsApplicationSignalsEvidence, AwsApplicationSignalsReadRequest,
    AwsApplicationSignalsReadResult, AwsApplicationSignalsScope, AwsApplicationSignalsService,
    AwsApplicationSignalsTransport, Digest, EvidenceStatus,
    MISSION_AWS_APPLICATION_SIGNALS_CONSUMER_ID, Registration, RegistrationState, ServiceError,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("the Mission consumer registration is revoked")]
    Revoked,
    #[error("the Application Signals evidence is outside the exact Mission/Project scope")]
    ScopeMismatch,
    #[error("the Application Signals permission fence was lost")]
    PermissionLoss,
    #[error("the Application Signals registration digest does not match")]
    RegistrationMismatch,
    #[error("the Application Signals evidence or receipt was tampered")]
    TamperedEvidence,
    #[error("the same Application Signals proposal was already consumed")]
    Replay,
    #[error("Layer-1 evidence attempted to claim native/connected authority")]
    NativeClaim,
    #[error("the service failed while producing evidence: {0}")]
    Service(String),
}

impl From<ServiceError> for ConsumerError {
    fn from(value: ServiceError) -> Self {
        Self::Service(value.to_string())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsApplicationSignalsResult {
    pub consumer_id: String,
    pub mission: crate::MissionBinding,
    pub evidence_status: EvidenceStatus,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub receipt: crate::AwsApplicationSignalsReceipt,
    pub evidence: AwsApplicationSignalsEvidence,
    pub accepted: bool,
    pub connected: bool,
    pub native: bool,
    pub truth_authority: bool,
    pub adopted_outcome: bool,
}

#[derive(Debug)]
pub struct MissionAwsApplicationSignalsConsumer {
    scope: AwsApplicationSignalsScope,
    registration_digest: Option<Digest>,
    consumed: BTreeSet<Digest>,
    revoked: bool,
}

impl MissionAwsApplicationSignalsConsumer {
    #[must_use]
    pub fn new(scope: AwsApplicationSignalsScope) -> Self {
        Self {
            scope,
            registration_digest: None,
            consumed: BTreeSet::new(),
            revoked: false,
        }
    }

    pub fn with_registration(
        scope: AwsApplicationSignalsScope,
        registration: &Registration,
    ) -> Result<Self, ConsumerError> {
        let mut consumer = Self::new(scope);
        consumer.bind_registration(registration)?;
        Ok(consumer)
    }

    pub fn bind_registration(&mut self, registration: &Registration) -> Result<(), ConsumerError> {
        if self.revoked || registration.state != RegistrationState::Active {
            return Err(ConsumerError::Revoked);
        }
        registration
            .verify()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        if registration.scope_digest != *self.scope.digest()
            || registration.permission_digest != self.scope.permissions.permission_digest
            || registration.window_digest != self.scope.window_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        self.registration_digest = Some(registration.registration_digest.clone());
        Ok(())
    }

    #[must_use]
    pub fn scope(&self) -> &AwsApplicationSignalsScope {
        &self.scope
    }

    #[must_use]
    pub fn registration_digest(&self) -> Option<&Digest> {
        self.registration_digest.as_ref()
    }

    #[must_use]
    pub fn consumed_count(&self) -> usize {
        self.consumed.len()
    }

    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn consume(
        &mut self,
        result: &AwsApplicationSignalsReadResult,
    ) -> Result<MissionAwsApplicationSignalsResult, ConsumerError> {
        self.ensure_available()?;
        if let Some(registration_digest) = &self.registration_digest
            && registration_digest != &result.proposal.registration_digest
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        self.verify_scope(result)?;
        if self.consumed.contains(&result.proposal.proposal_digest) {
            return Err(ConsumerError::Replay);
        }
        result
            .proposal
            .verify()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        result
            .record
            .verify()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        result
            .evidence
            .verify()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        result
            .receipt
            .verify()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        if result.receipt.proposal_digest != result.proposal.proposal_digest
            || result.receipt.record_digest != result.record.record_digest
            || result.receipt.evidence_digest != result.evidence.digests.evidence_digest
            || result.receipt.registration_digest != result.proposal.registration_digest
            || result.receipt.native
            || result.receipt.connected
            || result.receipt.adopted_outcome
            || result.receipt.truth_authority
            || !result.receipt.read_only
        {
            return Err(ConsumerError::NativeClaim);
        }
        self.consumed
            .insert(result.proposal.proposal_digest.clone());
        Ok(MissionAwsApplicationSignalsResult {
            consumer_id: MISSION_AWS_APPLICATION_SIGNALS_CONSUMER_ID.to_owned(),
            mission: self.scope.mission.clone(),
            evidence_status: result.evidence.status,
            proposal_digest: result.proposal.proposal_digest.clone(),
            evidence_digest: result.evidence.digests.evidence_digest.clone(),
            receipt: result.receipt.clone(),
            evidence: result.evidence.clone(),
            accepted: true,
            connected: false,
            native: false,
            truth_authority: false,
            adopted_outcome: false,
        })
    }

    pub fn consume_evidence(
        &self,
        evidence: &AwsApplicationSignalsEvidence,
    ) -> Result<(), ConsumerError> {
        self.ensure_available()?;
        if evidence.mission != self.scope.mission
            || evidence.account_id != self.scope.account_id
            || evidence.region != self.scope.region
            || evidence.time_window != self.scope.time_window
            || evidence.digests.scope_digest != *self.scope.digest()
            || evidence.digests.permission_digest != self.scope.permissions.permission_digest
            || evidence.digests.window_digest != self.scope.window_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        evidence
            .verify()
            .map_err(|_| ConsumerError::TamperedEvidence)
    }

    pub fn read<T>(
        &mut self,
        service: &mut AwsApplicationSignalsService<T>,
        request: AwsApplicationSignalsReadRequest,
    ) -> Result<MissionAwsApplicationSignalsResult, ConsumerError>
    where
        T: AwsApplicationSignalsTransport,
    {
        if service.scope().digest() != self.scope.digest() {
            return Err(ConsumerError::ScopeMismatch);
        }
        if self.registration_digest.is_none() {
            self.registration_digest = Some(service.registration().registration_digest.clone());
        }
        let result = service.read(request).map_err(ConsumerError::from)?;
        self.consume(&result)
    }

    fn ensure_available(&self) -> Result<(), ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        self.scope
            .validate()
            .map_err(|_| ConsumerError::ScopeMismatch)
    }

    fn verify_scope(&self, result: &AwsApplicationSignalsReadResult) -> Result<(), ConsumerError> {
        let evidence = &result.evidence;
        if evidence.mission != self.scope.mission
            || evidence.account_id != self.scope.account_id
            || evidence.region != self.scope.region
            || evidence.time_window != self.scope.time_window
            || evidence.digests.scope_digest != *self.scope.digest()
            || evidence.digests.permission_digest != self.scope.permissions.permission_digest
            || evidence.digests.window_digest != self.scope.window_digest
            || result.proposal.scope_digest != *self.scope.digest()
            || result.proposal.permission_digest != self.scope.permissions.permission_digest
            || result.proposal.window_digest != self.scope.window_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if result.proposal.request.operation() != result.evidence.operation {
            return Err(ConsumerError::TamperedEvidence);
        }
        if self
            .registration_digest
            .as_ref()
            .is_some_and(|expected| expected != &result.proposal.registration_digest)
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(())
    }
}
