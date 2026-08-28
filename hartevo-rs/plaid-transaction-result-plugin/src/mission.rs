//! Proposal-only Mission/Project/Work Product consumer projection.

use serde::Serialize;

use crate::{
    PLAID_TRANSACTION_RESULT_CONSUMER_ID, PLAID_TRANSACTION_RESULT_CONTRACT_VERSION,
    PLAID_TRANSACTION_RESULT_PLUGIN_VERSION, PLAID_TRANSACTION_RESULT_PROVIDER_ID,
    digest_serializable,
    model::{
        Digest, EvidenceDisposition, EvidenceProvenance, EvidenceStatus,
        PlaidTransactionResultError, PlaidTransactionResultEvidence, PlaidTransactionsScope,
    },
};

/// A Mission consumer that can propose a redacted transaction result for a
/// bound Work Product. It never adopts the Work Product or issues kernel
/// Truth, Verification, Receipt, Outcome, Consent, or Effect authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionPlaidTransactionConsumer {
    scope: PlaidTransactionsScope,
    consumer_digest: Digest,
}

impl MissionPlaidTransactionConsumer {
    pub fn new(scope: PlaidTransactionsScope) -> Result<Self, PlaidTransactionResultError> {
        scope.validate()?;
        let consumer_digest = digest_serializable(&(
            PLAID_TRANSACTION_RESULT_CONSUMER_ID,
            scope.digest(),
            scope.project().digest(),
            scope.mission().digest(),
            scope.work_product().digest(),
        ));
        Ok(Self {
            scope,
            consumer_digest,
        })
    }

    pub fn scope(&self) -> &PlaidTransactionsScope {
        &self.scope
    }

    pub fn consumer_digest(&self) -> &Digest {
        &self.consumer_digest
    }

    pub fn consume(
        &self,
        evidence: &PlaidTransactionResultEvidence,
    ) -> Result<MissionPlaidTransactionProposal, PlaidTransactionResultError> {
        evidence.verify_integrity()?;
        if evidence.schema_version != crate::PLAID_TRANSACTION_RESULT_SCHEMA_VERSION
            || evidence.contract_version != PLAID_TRANSACTION_RESULT_CONTRACT_VERSION
            || evidence.plugin_version != PLAID_TRANSACTION_RESULT_PLUGIN_VERSION
            || evidence.provider_id != PLAID_TRANSACTION_RESULT_PROVIDER_ID
            || evidence.scope_digest != self.scope.digest()
            || evidence.permission_digest != self.scope.permission_digest()
            || evidence.contract_digest != self.scope.contract_digest()
            || evidence.provider_digest != self.scope.provider_digest()
            || evidence.authority.connected
            || evidence.authority.native
            || evidence.authority.external_writes
            || evidence.authority.durable_provider_receipt
            || evidence.authority.independent_read_back
            || evidence.authority.financial_advice
            || evidence.authority.kernel_authority
        {
            return Err(PlaidTransactionResultError::ScopeMismatch(
                "evidence is not bound to this Mission consumer",
            ));
        }
        let adoption_candidate = evidence.status == EvidenceStatus::Ready
            && evidence.disposition == EvidenceDisposition::Proposal;
        let mut proposal = MissionPlaidTransactionProposal {
            consumer_id: PLAID_TRANSACTION_RESULT_CONSUMER_ID.to_owned(),
            consumer_digest: self.consumer_digest.clone(),
            project_id: self.scope.project().id().to_owned(),
            project_revision: self.scope.project().revision(),
            mission_id: self.scope.mission().id().to_owned(),
            mission_revision: self.scope.mission().revision(),
            work_product_id: self.scope.work_product().id().to_owned(),
            work_product_revision: self.scope.work_product().revision(),
            evidence_digest: evidence.evidence_digest.clone(),
            status: evidence.status,
            disposition: evidence.disposition,
            provenance: evidence.provenance,
            transaction_count: evidence.transaction_count,
            pending_or_posted_count: evidence.added_count,
            modified_count: evidence.modified_count,
            removed_count: evidence.removed_count,
            adoption_candidate,
            proposal_only: true,
            non_mutating: true,
            connected: false,
            native: false,
            kernel_authority: false,
            financial_advice: false,
            proposal_digest: Digest::sha256(b"uninitialized-plaid-mission-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        Ok(proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &MissionPlaidTransactionProposal,
    ) -> Result<(), PlaidTransactionResultError> {
        if proposal.consumer_digest != self.consumer_digest
            || proposal.project_id != self.scope.project().id()
            || proposal.project_revision != self.scope.project().revision()
            || proposal.mission_id != self.scope.mission().id()
            || proposal.mission_revision != self.scope.mission().revision()
            || proposal.work_product_id != self.scope.work_product().id()
            || proposal.work_product_revision != self.scope.work_product().revision()
            || !proposal.proposal_only
            || !proposal.non_mutating
            || proposal.connected
            || proposal.native
            || proposal.kernel_authority
            || proposal.financial_advice
        {
            return Err(PlaidTransactionResultError::ScopeMismatch(
                "Mission proposal is not bound to the registered Project, Mission, or Work Product",
            ));
        }
        proposal.verify_integrity()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct MissionPlaidTransactionProposal {
    pub consumer_id: String,
    pub consumer_digest: Digest,
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub evidence_digest: Digest,
    pub status: EvidenceStatus,
    pub disposition: EvidenceDisposition,
    pub provenance: EvidenceProvenance,
    pub transaction_count: usize,
    pub pending_or_posted_count: usize,
    pub modified_count: usize,
    pub removed_count: usize,
    pub adoption_candidate: bool,
    pub proposal_only: bool,
    pub non_mutating: bool,
    pub connected: bool,
    pub native: bool,
    pub kernel_authority: bool,
    pub financial_advice: bool,
    pub proposal_digest: Digest,
}

impl MissionPlaidTransactionProposal {
    fn calculate_digest(&self) -> Digest {
        digest_serializable(&MissionProposalDigestMaterial {
            consumer_id: &self.consumer_id,
            consumer_digest: &self.consumer_digest,
            project_id: &self.project_id,
            project_revision: self.project_revision,
            mission_id: &self.mission_id,
            mission_revision: self.mission_revision,
            work_product_id: &self.work_product_id,
            work_product_revision: self.work_product_revision,
            evidence_digest: &self.evidence_digest,
            status: self.status,
            disposition: self.disposition,
            provenance: self.provenance,
            transaction_count: self.transaction_count,
            pending_or_posted_count: self.pending_or_posted_count,
            modified_count: self.modified_count,
            removed_count: self.removed_count,
            adoption_candidate: self.adoption_candidate,
            proposal_only: self.proposal_only,
            non_mutating: self.non_mutating,
            connected: self.connected,
            native: self.native,
            kernel_authority: self.kernel_authority,
            financial_advice: self.financial_advice,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), PlaidTransactionResultError> {
        if self.proposal_digest != self.calculate_digest() {
            return Err(PlaidTransactionResultError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct MissionProposalDigestMaterial<'a> {
    consumer_id: &'a str,
    consumer_digest: &'a Digest,
    project_id: &'a str,
    project_revision: u64,
    mission_id: &'a str,
    mission_revision: u64,
    work_product_id: &'a str,
    work_product_revision: u64,
    evidence_digest: &'a Digest,
    status: EvidenceStatus,
    disposition: EvidenceDisposition,
    provenance: EvidenceProvenance,
    transaction_count: usize,
    pending_or_posted_count: usize,
    modified_count: usize,
    removed_count: usize,
    adoption_candidate: bool,
    proposal_only: bool,
    non_mutating: bool,
    connected: bool,
    native: bool,
    kernel_authority: bool,
    financial_advice: bool,
}
