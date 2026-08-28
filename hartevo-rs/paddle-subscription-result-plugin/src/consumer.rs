use serde::{Deserialize, Serialize};

use crate::{
    error::Result,
    model::{
        AccountId, Digest, EvidenceDisposition, HartevoProjectId, MissionId, PaddleBillingEvidence,
        PaddleBillingRegistration, PaddleBillingScope, ProviderProvenance, Revision,
        SubscriptionId, SubscriptionStatus, TransactionId, TransactionStatus, WorkProductId,
    },
    provider::PaddleBillingProvider,
    service::{PaddleBillingResultProposal, PaddleSubscriptionResultService},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionResultState {
    SubscriptionActive,
    SubscriptionTrialing,
    SubscriptionPastDue,
    SubscriptionPaused,
    SubscriptionCanceled,
    RenewalEvidence,
    TransactionReady,
    TransactionPaid,
    TransactionCompleted,
    TransactionFailed,
    TransactionRefunded,
    MetadataAvailable,
    AccessLost,
    ProviderUnknown,
    CursorExpired,
    BlockedEnv,
}

/// Mission-facing projection. It binds redacted evidence to exact
/// Mission/Project/Work Product revisions but cannot adopt a Work Product or
/// mint kernel authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionPaddleSubscriptionResult {
    pub account_id: AccountId,
    pub subscription_id: SubscriptionId,
    pub transaction_ids: Vec<TransactionId>,
    pub event_ids: Vec<crate::EventId>,
    pub hartevo_project_id: HartevoProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub evidence_digest: Digest,
    pub disposition: EvidenceDisposition,
    pub state: MissionResultState,
    pub renewal_evidence: bool,
    pub provenance: ProviderProvenance,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub work_product_adopted: bool,
    pub kernel_authority: bool,
}

impl MissionPaddleSubscriptionResult {
    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        self.subscription_id.validate()?;
        for transaction_id in &self.transaction_ids {
            transaction_id.validate()?;
        }
        for event_id in &self.event_ids {
            event_id.validate()?;
        }
        self.hartevo_project_id.validate()?;
        self.mission_id.validate()?;
        self.work_product_id.validate()?;
        self.evidence_digest.validate("evidence_digest")?;
        for revision in [
            self.project_revision,
            self.mission_revision,
            self.work_product_revision,
        ] {
            Revision::new(revision.get())?;
        }
        if !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.work_product_adopted
            || self.kernel_authority
        {
            return Err(crate::PaddleSubscriptionResultError::EvidenceTampered);
        }
        Ok(())
    }
}

/// Mission consumer for one exact Paddle account/subscription and Hartevo
/// Mission/Project/Work Product binding.
#[derive(Clone, Debug)]
pub struct MissionPaddleSubscriptionConsumer {
    service: PaddleSubscriptionResultService,
}

impl MissionPaddleSubscriptionConsumer {
    pub fn new(scope: PaddleBillingScope, provider: PaddleBillingProvider) -> Result<Self> {
        Ok(Self {
            service: PaddleSubscriptionResultService::new(scope, provider)?,
        })
    }

    #[must_use]
    pub fn from_service(service: PaddleSubscriptionResultService) -> Self {
        Self { service }
    }

    #[must_use]
    pub fn service(&self) -> &PaddleSubscriptionResultService {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut PaddleSubscriptionResultService {
        &mut self.service
    }

    #[must_use]
    pub fn registration(&self) -> &PaddleBillingRegistration {
        self.service.registration()
    }

    pub fn consume(
        &self,
        evidence: &PaddleBillingEvidence,
    ) -> Result<MissionPaddleSubscriptionResult> {
        self.service.verify_evidence(evidence)?;
        let result = MissionPaddleSubscriptionResult {
            account_id: self.service.scope().identity().account_id.clone(),
            subscription_id: self.service.scope().identity().subscription_id.clone(),
            transaction_ids: evidence
                .transactions
                .iter()
                .map(|transaction| transaction.transaction_id.clone())
                .collect(),
            event_ids: evidence
                .events
                .iter()
                .map(|event| event.event_id.clone())
                .collect(),
            hartevo_project_id: self.service.scope().identity().hartevo_project_id.clone(),
            mission_id: self.service.scope().identity().mission_id.clone(),
            work_product_id: self.service.scope().identity().work_product_id.clone(),
            project_revision: self.service.scope().identity().project_revision,
            mission_revision: self.service.scope().identity().mission_revision,
            work_product_revision: self.service.scope().identity().work_product_revision,
            evidence_digest: evidence.evidence_digest.clone(),
            disposition: evidence.disposition,
            state: mission_state(evidence),
            renewal_evidence: evidence.has_renewal_evidence(),
            provenance: evidence.provenance,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            work_product_adopted: false,
            kernel_authority: false,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn consume_proposal(
        &self,
        proposal: &PaddleBillingResultProposal,
        evidence: &PaddleBillingEvidence,
    ) -> Result<MissionPaddleSubscriptionResult> {
        self.service.verify_result_proposal(proposal, evidence)?;
        self.consume(evidence)
    }

    pub fn read_and_consume_subscription(
        &mut self,
        minimum_observed_at: u64,
    ) -> Result<MissionPaddleSubscriptionResult> {
        let subscription_id = self.service.scope().identity().subscription_id.clone();
        let evidence = self
            .service
            .read_subscription(subscription_id, minimum_observed_at)?;
        self.consume(&evidence)
    }

    pub fn read_and_consume_transaction(
        &mut self,
        transaction_id: TransactionId,
        minimum_observed_at: u64,
    ) -> Result<MissionPaddleSubscriptionResult> {
        let evidence = self
            .service
            .read_transaction(transaction_id, minimum_observed_at)?;
        self.consume(&evidence)
    }

    pub fn read_and_consume_transactions(
        &mut self,
        limit: u32,
        minimum_observed_at: u64,
    ) -> Result<MissionPaddleSubscriptionResult> {
        let evidence = self
            .service
            .paginate_transactions(limit, minimum_observed_at)?;
        self.consume(&evidence)
    }

    pub fn read_and_consume_events(
        &mut self,
        limit: u32,
        minimum_observed_at: u64,
    ) -> Result<MissionPaddleSubscriptionResult> {
        let evidence = self.service.paginate_events(limit, minimum_observed_at)?;
        self.consume(&evidence)
    }
}

fn mission_state(evidence: &PaddleBillingEvidence) -> MissionResultState {
    match evidence.disposition {
        BlockedEnv => MissionResultState::BlockedEnv,
        AccessLost => MissionResultState::AccessLost,
        CursorExpired => MissionResultState::CursorExpired,
        ProviderUnknown | Partial => MissionResultState::ProviderUnknown,
        Empty => MissionResultState::MetadataAvailable,
        Present => {
            if evidence.has_renewal_evidence() {
                return MissionResultState::RenewalEvidence;
            }
            if let Some(subscription) = &evidence.subscription {
                return match subscription.status {
                    SubscriptionStatus::Active => MissionResultState::SubscriptionActive,
                    SubscriptionStatus::Trialing => MissionResultState::SubscriptionTrialing,
                    SubscriptionStatus::PastDue => MissionResultState::SubscriptionPastDue,
                    SubscriptionStatus::Paused => MissionResultState::SubscriptionPaused,
                    SubscriptionStatus::Canceled => MissionResultState::SubscriptionCanceled,
                    SubscriptionStatus::ProviderUnknown => MissionResultState::ProviderUnknown,
                };
            }
            if let Some(transaction) = evidence.transactions.first() {
                return match transaction.status {
                    TransactionStatus::Draft | TransactionStatus::Ready => {
                        MissionResultState::TransactionReady
                    }
                    TransactionStatus::Billed | TransactionStatus::Paid => {
                        MissionResultState::TransactionPaid
                    }
                    TransactionStatus::Completed => MissionResultState::TransactionCompleted,
                    TransactionStatus::Canceled => MissionResultState::MetadataAvailable,
                    TransactionStatus::PastDue | TransactionStatus::Failed => {
                        MissionResultState::TransactionFailed
                    }
                    TransactionStatus::Refunded => MissionResultState::TransactionRefunded,
                    TransactionStatus::ProviderUnknown => MissionResultState::ProviderUnknown,
                };
            }
            evidence
                .events
                .first()
                .and_then(|event| event.transaction_status)
                .map_or(
                    MissionResultState::MetadataAvailable,
                    |status| match status {
                        TransactionStatus::Completed => MissionResultState::TransactionCompleted,
                        TransactionStatus::Paid | TransactionStatus::Billed => {
                            MissionResultState::TransactionPaid
                        }
                        TransactionStatus::PastDue | TransactionStatus::Failed => {
                            MissionResultState::TransactionFailed
                        }
                        TransactionStatus::Refunded => MissionResultState::TransactionRefunded,
                        _ => MissionResultState::MetadataAvailable,
                    },
                )
        }
    }
}

use EvidenceDisposition::{
    AccessLost, BlockedEnv, CursorExpired, Empty, Partial, Present, ProviderUnknown,
};
