use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    CONTRACT_VERSION, SERVICE_ID,
    error::{PaddleBillingProviderError, PaddleSubscriptionResultError, Result},
    model::{
        CursorKind, Digest, EvidenceDisposition, MAX_EVENT_PAGE_LIMIT, MAX_PAGES,
        MAX_RESPONSE_BYTES, MAX_TRANSACTION_PAGE_LIMIT, NativeStatus, PaddleBillingEvidence,
        PaddleBillingRegistration, PaddleBillingScope, PaddleCursor, PaddleEventListRequest,
        PaddleReadTarget, PaddleSubscriptionReadRequest, PaddleTransactionListRequest,
        PaddleTransactionReadRequest, ProviderErrorProjection, ProviderProvenance,
        RegistrationRevocation, RegistrationStatus, Revision, SubscriptionId, TransactionId,
        validate_event_scope, validate_subscription_scope, validate_transaction_scope,
    },
    provider::{
        PaddleBillingProvider, PaddleEventListResponse, PaddleSubscriptionResponse,
        PaddleTransactionListResponse, PaddleTransactionResponse,
    },
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaddleBillingServicePolicy {
    pub max_transaction_page_limit: u32,
    pub max_event_page_limit: u32,
    pub max_pages: u32,
    pub max_response_bytes: usize,
}

impl Default for PaddleBillingServicePolicy {
    fn default() -> Self {
        Self {
            max_transaction_page_limit: MAX_TRANSACTION_PAGE_LIMIT,
            max_event_page_limit: MAX_EVENT_PAGE_LIMIT,
            max_pages: MAX_PAGES as u32,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

impl PaddleBillingServicePolicy {
    pub fn new(
        max_transaction_page_limit: u32,
        max_event_page_limit: u32,
        max_pages: u32,
        max_response_bytes: usize,
    ) -> Result<Self> {
        if !(1..=MAX_TRANSACTION_PAGE_LIMIT).contains(&max_transaction_page_limit)
            || !(1..=MAX_EVENT_PAGE_LIMIT).contains(&max_event_page_limit)
            || max_pages == 0
            || max_pages > MAX_PAGES as u32
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(PaddleSubscriptionResultError::InvalidRequest(
                "service policy",
            ));
        }
        Ok(Self {
            max_transaction_page_limit,
            max_event_page_limit,
            max_pages,
            max_response_bytes,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(
            self.max_transaction_page_limit,
            self.max_event_page_limit,
            self.max_pages,
            self.max_response_bytes,
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaddleBillingCapabilities {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub source: ProviderProvenance,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub payment_initiation: bool,
    pub durable_native_receipt: bool,
    pub independent_readback: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
    pub secret_reference_required: bool,
    pub operations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaddleBillingReadProposal {
    pub target: PaddleReadTarget,
    pub minimum_observed_at: u64,
    pub registration_digest: Digest,
    pub implementation_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub proposal_digest: Digest,
}

impl PaddleBillingReadProposal {
    fn new(
        target: PaddleReadTarget,
        minimum_observed_at: u64,
        registration: &PaddleBillingRegistration,
        scope: &PaddleBillingScope,
        provider: &PaddleBillingProvider,
    ) -> Self {
        let mut proposal = Self {
            target,
            minimum_observed_at,
            registration_digest: registration.registration_digest.clone(),
            implementation_digest: registration.implementation_digest.clone(),
            provider_digest: provider.provider_digest(),
            api_digest: scope.identity().api.digest(),
            permission_digest: scope.identity().permission.digest.clone(),
            scope_digest: scope.scope_digest(),
            revision_digest: scope.revision_digest(),
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            proposal_digest: Digest::pending(),
        };
        proposal.proposal_digest = proposal.computed_digest();
        proposal
    }

    pub fn validate(
        &self,
        registration: &PaddleBillingRegistration,
        scope: &PaddleBillingScope,
        provider: &PaddleBillingProvider,
    ) -> Result<()> {
        registration.validate_for(scope, &provider.provider_digest())?;
        for (field, digest) in [
            ("registration_digest", &self.registration_digest),
            ("implementation_digest", &self.implementation_digest),
            ("provider_digest", &self.provider_digest),
            ("api_digest", &self.api_digest),
            ("permission_digest", &self.permission_digest),
            ("scope_digest", &self.scope_digest),
            ("revision_digest", &self.revision_digest),
        ] {
            digest.validate(field)?;
        }
        if self.registration_digest != registration.registration_digest
            || self.implementation_digest != registration.implementation_digest
            || self.provider_digest != provider.provider_digest()
            || self.api_digest != scope.identity().api.digest()
            || self.permission_digest != scope.identity().permission.digest
            || self.scope_digest != scope.scope_digest()
            || self.revision_digest != scope.revision_digest()
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.external_writes
            || self.proposal_digest != self.computed_digest()
        {
            return Err(PaddleSubscriptionResultError::ProposalTampered);
        }
        Ok(())
    }

    #[must_use]
    fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.proposal_digest = Digest::pending();
        Digest::from_serializable(&value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaddleBillingResultProposal {
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub implementation_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub disposition: EvidenceDisposition,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub payment_initiation: bool,
    pub adopted: bool,
    pub proposal_digest: Digest,
}

impl PaddleBillingResultProposal {
    fn new(evidence: &PaddleBillingEvidence, registration: &PaddleBillingRegistration) -> Self {
        let mut proposal = Self {
            evidence_digest: evidence.evidence_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            implementation_digest: evidence.implementation_digest.clone(),
            provider_digest: evidence.provider_digest.clone(),
            api_digest: evidence.api_digest.clone(),
            permission_digest: evidence.permission_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            revision_digest: evidence.revision_digest.clone(),
            disposition: evidence.disposition,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            payment_initiation: false,
            adopted: false,
            proposal_digest: Digest::pending(),
        };
        proposal.proposal_digest = proposal.computed_digest();
        proposal
    }

    pub fn validate(
        &self,
        evidence: &PaddleBillingEvidence,
        registration: &PaddleBillingRegistration,
    ) -> Result<()> {
        evidence.validate()?;
        registration.validate()?;
        for (field, digest) in [
            ("evidence_digest", &self.evidence_digest),
            ("registration_digest", &self.registration_digest),
            ("implementation_digest", &self.implementation_digest),
            ("provider_digest", &self.provider_digest),
            ("api_digest", &self.api_digest),
            ("permission_digest", &self.permission_digest),
            ("scope_digest", &self.scope_digest),
            ("revision_digest", &self.revision_digest),
        ] {
            digest.validate(field)?;
        }
        if self.evidence_digest != evidence.evidence_digest
            || self.registration_digest != registration.registration_digest
            || self.implementation_digest != evidence.implementation_digest
            || self.provider_digest != evidence.provider_digest
            || self.api_digest != evidence.api_digest
            || self.permission_digest != evidence.permission_digest
            || self.scope_digest != evidence.scope_digest
            || self.revision_digest != evidence.revision_digest
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.external_writes
            || self.payment_initiation
            || self.adopted
            || self.proposal_digest != self.computed_digest()
        {
            return Err(PaddleSubscriptionResultError::ProposalTampered);
        }
        Ok(())
    }

    #[must_use]
    fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.proposal_digest = Digest::pending();
        Digest::from_serializable(&value)
    }
}

/// Typed service that owns registration, bounded reads, cursor pagination,
/// proposal verification, replay fencing, and reversible revocation. It has
/// no payment or mutation authority.
#[derive(Clone, Debug)]
pub struct PaddleSubscriptionResultService {
    scope: PaddleBillingScope,
    provider: PaddleBillingProvider,
    registration: PaddleBillingRegistration,
    policy: PaddleBillingServicePolicy,
    replay_guard: BTreeMap<Digest, Digest>,
}

impl PaddleSubscriptionResultService {
    pub fn new(scope: PaddleBillingScope, provider: PaddleBillingProvider) -> Result<Self> {
        Self::with_policy(scope, provider, PaddleBillingServicePolicy::default())
    }

    pub fn with_policy(
        scope: PaddleBillingScope,
        provider: PaddleBillingProvider,
        policy: PaddleBillingServicePolicy,
    ) -> Result<Self> {
        scope.validate()?;
        provider.definition().validate()?;
        policy.validate()?;
        let registration = PaddleBillingRegistration::new(
            &scope,
            provider.provider_digest(),
            provider.definition().version().to_owned(),
            crate::contract_digest(),
        )?;
        registration.validate_for(&scope, &provider.provider_digest())?;
        Ok(Self {
            scope,
            provider,
            registration,
            policy,
            replay_guard: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &PaddleBillingScope {
        &self.scope
    }

    #[must_use]
    pub fn provider(&self) -> &PaddleBillingProvider {
        &self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &PaddleBillingRegistration {
        &self.registration
    }

    #[must_use]
    pub fn policy(&self) -> &PaddleBillingServicePolicy {
        &self.policy
    }

    pub fn describe_capabilities(&self) -> Result<PaddleBillingCapabilities> {
        self.ensure_active()?;
        Ok(PaddleBillingCapabilities {
            schema_version: String::from(crate::SCHEMA_VERSION),
            contract_version: String::from(CONTRACT_VERSION),
            service_id: String::from(SERVICE_ID),
            provider_id: String::from(crate::PROVIDER_ID),
            source: self.provider.provenance(),
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            payment_initiation: false,
            durable_native_receipt: false,
            independent_readback: false,
            kernel_authority: false,
            outcome_adoption: false,
            secret_reference_required: true,
            operations: vec![
                String::from("describe_capabilities"),
                String::from("compile_bounded_subscription_read"),
                String::from("compile_bounded_transaction_read"),
                String::from("compile_bounded_event_read"),
                String::from("read_subscription"),
                String::from("read_transaction"),
                String::from("read_transactions"),
                String::from("read_events"),
                String::from("paginate_transactions"),
                String::from("paginate_events"),
                String::from("compile_result_proposal"),
                String::from("verify_result_proposal"),
                String::from("revoke_registration"),
                String::from("restore_registration"),
                String::from("revoke_secret"),
                String::from("restore_secret"),
            ],
        })
    }

    pub fn compile_bounded_subscription_read(
        &self,
        subscription_id: SubscriptionId,
        minimum_observed_at: u64,
    ) -> Result<PaddleBillingReadProposal> {
        self.ensure_active()?;
        if subscription_id != self.scope.identity().subscription_id {
            return Err(PaddleSubscriptionResultError::SubscriptionMismatch);
        }
        let proposal = PaddleBillingReadProposal::new(
            PaddleReadTarget::Subscription { subscription_id },
            minimum_observed_at,
            &self.registration,
            &self.scope,
            &self.provider,
        );
        proposal.validate(&self.registration, &self.scope, &self.provider)?;
        Ok(proposal)
    }

    pub fn compile_bounded_transaction_read(
        &self,
        transaction_id: TransactionId,
        minimum_observed_at: u64,
    ) -> Result<PaddleBillingReadProposal> {
        self.ensure_active()?;
        if let Some(expected) = &self.scope.identity().transaction_id
            && transaction_id != *expected
        {
            return Err(PaddleSubscriptionResultError::TransactionMismatch);
        }
        let proposal = PaddleBillingReadProposal::new(
            PaddleReadTarget::Transaction { transaction_id },
            minimum_observed_at,
            &self.registration,
            &self.scope,
            &self.provider,
        );
        proposal.validate(&self.registration, &self.scope, &self.provider)?;
        Ok(proposal)
    }

    pub fn compile_bounded_transaction_list_read(
        &self,
        limit: u32,
        cursor: Option<&PaddleCursor>,
        minimum_observed_at: u64,
    ) -> Result<PaddleBillingReadProposal> {
        self.ensure_active()?;
        if limit > self.policy.max_transaction_page_limit {
            return Err(PaddleSubscriptionResultError::InvalidRequest(
                "transaction limit",
            ));
        }
        if let Some(cursor) = cursor {
            cursor.validate_for(
                &self.scope.scope_digest(),
                CursorKind::Transactions,
                minimum_observed_at,
            )?;
        }
        let proposal = PaddleBillingReadProposal::new(
            PaddleReadTarget::Transactions {
                subscription_id: self.scope.identity().subscription_id.clone(),
                limit,
                cursor_digest: cursor.map(PaddleCursor::digest),
            },
            minimum_observed_at,
            &self.registration,
            &self.scope,
            &self.provider,
        );
        proposal.validate(&self.registration, &self.scope, &self.provider)?;
        Ok(proposal)
    }

    pub fn compile_bounded_event_read(
        &self,
        limit: u32,
        cursor: Option<&PaddleCursor>,
        minimum_observed_at: u64,
    ) -> Result<PaddleBillingReadProposal> {
        self.ensure_active()?;
        if limit > self.policy.max_event_page_limit {
            return Err(PaddleSubscriptionResultError::InvalidRequest("event limit"));
        }
        if let Some(cursor) = cursor {
            cursor.validate_for(
                &self.scope.scope_digest(),
                CursorKind::Events,
                minimum_observed_at,
            )?;
        }
        let proposal = PaddleBillingReadProposal::new(
            PaddleReadTarget::Events {
                limit,
                cursor_digest: cursor.map(PaddleCursor::digest),
            },
            minimum_observed_at,
            &self.registration,
            &self.scope,
            &self.provider,
        );
        proposal.validate(&self.registration, &self.scope, &self.provider)?;
        Ok(proposal)
    }

    pub fn read_subscription(
        &mut self,
        subscription_id: SubscriptionId,
        minimum_observed_at: u64,
    ) -> Result<PaddleBillingEvidence> {
        let proposal =
            self.compile_bounded_subscription_read(subscription_id.clone(), minimum_observed_at)?;
        let request = PaddleSubscriptionReadRequest::new(subscription_id, minimum_observed_at)?;
        match self.provider.get_subscription(&self.scope, &request) {
            Ok(response) => {
                self.validate_subscription_response(&proposal, &request, &response)?;
                self.remember_response(&proposal, &response.response_digest)?;
                self.evidence(
                    proposal.target,
                    Some(response.subscription),
                    Vec::new(),
                    Vec::new(),
                    None,
                    Some(response.response_digest),
                    EvidenceDisposition::Present,
                    None,
                    response.observed_at,
                    response.snapshot_revision,
                )
            }
            Err(PaddleSubscriptionResultError::Provider(error))
                if is_evidence_provider_error(&error) =>
            {
                self.provider_failure_evidence(proposal.target, minimum_observed_at, error)
            }
            Err(error) => Err(error),
        }
    }

    pub fn read_transaction(
        &mut self,
        transaction_id: TransactionId,
        minimum_observed_at: u64,
    ) -> Result<PaddleBillingEvidence> {
        let proposal =
            self.compile_bounded_transaction_read(transaction_id.clone(), minimum_observed_at)?;
        let request = PaddleTransactionReadRequest::new(transaction_id, minimum_observed_at)?;
        match self.provider.get_transaction(&self.scope, &request) {
            Ok(response) => {
                self.validate_transaction_response(&proposal, &request, &response)?;
                self.remember_response(&proposal, &response.response_digest)?;
                self.evidence(
                    proposal.target,
                    None,
                    vec![response.transaction],
                    Vec::new(),
                    None,
                    Some(response.response_digest),
                    EvidenceDisposition::Present,
                    None,
                    response.observed_at,
                    response.snapshot_revision,
                )
            }
            Err(PaddleSubscriptionResultError::Provider(error))
                if is_evidence_provider_error(&error) =>
            {
                self.provider_failure_evidence(proposal.target, minimum_observed_at, error)
            }
            Err(error) => Err(error),
        }
    }

    pub fn read_transactions(
        &mut self,
        limit: u32,
        cursor: Option<PaddleCursor>,
        minimum_observed_at: u64,
    ) -> Result<PaddleBillingEvidence> {
        let proposal = self.compile_bounded_transaction_list_read(
            limit,
            cursor.as_ref(),
            minimum_observed_at,
        )?;
        let request = PaddleTransactionListRequest::new(
            self.scope.identity().subscription_id.clone(),
            limit,
            cursor,
            minimum_observed_at,
        )?;
        match self.provider.list_transactions(&self.scope, &request) {
            Ok(response) => {
                self.validate_transaction_list_response(&proposal, &request, &response)?;
                self.remember_response(&proposal, &response.response_digest)?;
                let disposition = if response.transactions.is_empty() {
                    EvidenceDisposition::Empty
                } else {
                    EvidenceDisposition::Present
                };
                self.evidence(
                    proposal.target,
                    None,
                    response.transactions,
                    Vec::new(),
                    response.next_cursor.as_ref().map(PaddleCursor::digest),
                    Some(response.response_digest),
                    disposition,
                    None,
                    response.observed_at,
                    response.snapshot_revision,
                )
            }
            Err(PaddleSubscriptionResultError::Provider(error))
                if is_evidence_provider_error(&error) =>
            {
                self.provider_failure_evidence(proposal.target, minimum_observed_at, error)
            }
            Err(error) => Err(error),
        }
    }

    pub fn read_events(
        &mut self,
        limit: u32,
        cursor: Option<PaddleCursor>,
        minimum_observed_at: u64,
    ) -> Result<PaddleBillingEvidence> {
        let proposal =
            self.compile_bounded_event_read(limit, cursor.as_ref(), minimum_observed_at)?;
        let request = PaddleEventListRequest::new(limit, cursor, minimum_observed_at)?;
        match self.provider.list_events(&self.scope, &request) {
            Ok(response) => {
                self.validate_event_list_response(&proposal, &request, &response)?;
                self.remember_response(&proposal, &response.response_digest)?;
                let disposition = if response.events.is_empty() {
                    EvidenceDisposition::Empty
                } else {
                    EvidenceDisposition::Present
                };
                self.evidence(
                    proposal.target,
                    None,
                    Vec::new(),
                    response.events,
                    response.next_cursor.as_ref().map(PaddleCursor::digest),
                    Some(response.response_digest),
                    disposition,
                    None,
                    response.observed_at,
                    response.snapshot_revision,
                )
            }
            Err(PaddleSubscriptionResultError::Provider(error))
                if is_evidence_provider_error(&error) =>
            {
                self.provider_failure_evidence(proposal.target, minimum_observed_at, error)
            }
            Err(error) => Err(error),
        }
    }

    pub fn paginate_transactions(
        &mut self,
        limit: u32,
        minimum_observed_at: u64,
    ) -> Result<PaddleBillingEvidence> {
        if limit > self.policy.max_transaction_page_limit {
            return Err(PaddleSubscriptionResultError::InvalidRequest(
                "transaction limit",
            ));
        }
        let mut cursor = None;
        let mut seen = BTreeSet::new();
        let mut transactions = Vec::new();
        let mut response_digests = Vec::new();
        let mut page_count = 0_u32;
        let mut observed_at = minimum_observed_at;
        let snapshot_revision = self.scope.identity().scope_revision;
        let final_target = loop {
            if page_count >= self.policy.max_pages {
                return Err(PaddleSubscriptionResultError::PageLimitExceeded);
            }
            let evidence = self.read_transactions(limit, cursor.clone(), minimum_observed_at)?;
            page_count = page_count.saturating_add(1);
            observed_at = observed_at.max(evidence.observed_at);
            if let Some(error) = &evidence.provider_error {
                return self.evidence_with_page_count(
                    evidence.target,
                    None,
                    transactions,
                    Vec::new(),
                    None,
                    combined_digest(&response_digests, evidence.response_digest),
                    page_count,
                    evidence.disposition,
                    Some(error.clone()),
                    observed_at,
                    evidence.snapshot_revision,
                );
            }
            if let Some(response_digest) = evidence.response_digest.clone() {
                response_digests.push(response_digest);
            }
            transactions.extend(evidence.transactions);
            let Some(cursor_digest) = evidence.next_cursor_digest else {
                break evidence.target;
            };
            let Some(last) = transactions.last() else {
                return Err(PaddleSubscriptionResultError::InvalidResponse(
                    "transaction cursor without transaction",
                ));
            };
            let response_digest = evidence.response_digest.clone().ok_or(
                PaddleSubscriptionResultError::InvalidResponse(
                    "transaction cursor response digest",
                ),
            )?;
            let next = PaddleCursor::new(
                last.transaction_id.as_str(),
                CursorKind::Transactions,
                self.scope.scope_digest(),
                response_digest,
                evidence.observed_at,
                evidence
                    .observed_at
                    .saturating_add(crate::EVENT_RETENTION_SECONDS),
            )?;
            if next.digest() != cursor_digest || !seen.insert(next.digest()) {
                return Err(PaddleSubscriptionResultError::CursorLoop);
            }
            cursor = Some(next);
        };
        self.evidence_with_page_count(
            final_target,
            None,
            transactions,
            Vec::new(),
            None,
            combined_digest(&response_digests, None),
            page_count,
            if response_digests.is_empty() {
                EvidenceDisposition::Empty
            } else {
                EvidenceDisposition::Present
            },
            None,
            observed_at,
            snapshot_revision,
        )
    }

    pub fn paginate_events(
        &mut self,
        limit: u32,
        minimum_observed_at: u64,
    ) -> Result<PaddleBillingEvidence> {
        if limit > self.policy.max_event_page_limit {
            return Err(PaddleSubscriptionResultError::InvalidRequest("event limit"));
        }
        let mut cursor = None;
        let mut seen = BTreeSet::new();
        let mut events = Vec::new();
        let mut response_digests = Vec::new();
        let mut page_count = 0_u32;
        let mut observed_at = minimum_observed_at;
        let snapshot_revision = self.scope.identity().scope_revision;
        let final_target = loop {
            if page_count >= self.policy.max_pages {
                return Err(PaddleSubscriptionResultError::PageLimitExceeded);
            }
            let evidence = self.read_events(limit, cursor.clone(), minimum_observed_at)?;
            page_count = page_count.saturating_add(1);
            observed_at = observed_at.max(evidence.observed_at);
            if let Some(error) = &evidence.provider_error {
                return self.evidence_with_page_count(
                    evidence.target,
                    None,
                    Vec::new(),
                    events,
                    None,
                    combined_digest(&response_digests, evidence.response_digest),
                    page_count,
                    evidence.disposition,
                    Some(error.clone()),
                    observed_at,
                    evidence.snapshot_revision,
                );
            }
            if let Some(response_digest) = evidence.response_digest.clone() {
                response_digests.push(response_digest);
            }
            events.extend(evidence.events);
            let Some(cursor_digest) = evidence.next_cursor_digest else {
                break evidence.target;
            };
            let Some(last) = events.last() else {
                return Err(PaddleSubscriptionResultError::InvalidResponse(
                    "event cursor without event",
                ));
            };
            let response_digest = evidence.response_digest.clone().ok_or(
                PaddleSubscriptionResultError::InvalidResponse("event cursor response digest"),
            )?;
            let next = PaddleCursor::new(
                last.event_id.as_str(),
                CursorKind::Events,
                self.scope.scope_digest(),
                response_digest,
                evidence.observed_at,
                evidence
                    .observed_at
                    .saturating_add(crate::EVENT_RETENTION_SECONDS),
            )?;
            if next.digest() != cursor_digest || !seen.insert(next.digest()) {
                return Err(PaddleSubscriptionResultError::CursorLoop);
            }
            cursor = Some(next);
        };
        self.evidence_with_page_count(
            final_target,
            None,
            Vec::new(),
            events,
            None,
            combined_digest(&response_digests, None),
            page_count,
            if response_digests.is_empty() {
                EvidenceDisposition::Empty
            } else {
                EvidenceDisposition::Present
            },
            None,
            observed_at,
            snapshot_revision,
        )
    }

    pub fn compile_result_proposal(
        &self,
        evidence: &PaddleBillingEvidence,
    ) -> Result<PaddleBillingResultProposal> {
        self.ensure_active()?;
        self.verify_evidence(evidence)?;
        Ok(PaddleBillingResultProposal::new(
            evidence,
            &self.registration,
        ))
    }

    pub fn verify_result_proposal(
        &self,
        proposal: &PaddleBillingResultProposal,
        evidence: &PaddleBillingEvidence,
    ) -> Result<()> {
        self.ensure_active()?;
        self.verify_evidence(evidence)?;
        proposal.validate(evidence, &self.registration)
    }

    pub fn verify_evidence(&self, evidence: &PaddleBillingEvidence) -> Result<()> {
        self.ensure_active()?;
        evidence.validate()?;
        if evidence.registration_digest != self.registration.registration_digest
            || evidence.implementation_digest != self.registration.implementation_digest
            || evidence.provider_digest != self.provider.provider_digest()
            || evidence.api_digest != self.scope.identity().api.digest()
            || evidence.permission_digest != self.scope.identity().permission.digest
            || evidence.scope_digest != self.scope.scope_digest()
            || evidence.revision_digest != self.scope.revision_digest()
            || evidence.provenance != self.provider.provenance()
            || evidence.connected
            || evidence.native
            || evidence.first_party
        {
            return Err(PaddleSubscriptionResultError::ScopeMismatch(
                "evidence is not bound to the active registration",
            ));
        }
        self.validate_evidence_scope(evidence)?;
        Ok(())
    }

    fn validate_evidence_scope(&self, evidence: &PaddleBillingEvidence) -> Result<()> {
        if evidence.disposition != EvidenceDisposition::Present {
            return Ok(());
        }
        match &evidence.target {
            PaddleReadTarget::Subscription { subscription_id } => {
                let subscription = evidence.subscription.as_ref().ok_or(
                    PaddleSubscriptionResultError::InvalidResponse(
                        "subscription evidence missing subscription",
                    ),
                )?;
                if subscription.subscription_id != *subscription_id
                    || !evidence.transactions.is_empty()
                    || !evidence.events.is_empty()
                    || evidence.next_cursor_digest.is_some()
                {
                    return Err(PaddleSubscriptionResultError::ScopeMismatch(
                        "subscription evidence target",
                    ));
                }
                validate_subscription_scope(subscription, &self.scope)
            }
            PaddleReadTarget::Transaction { transaction_id } => {
                if evidence.subscription.is_some()
                    || !evidence.events.is_empty()
                    || evidence.transactions.len() != 1
                    || evidence.next_cursor_digest.is_some()
                {
                    return Err(PaddleSubscriptionResultError::ScopeMismatch(
                        "transaction evidence target",
                    ));
                }
                let transaction = evidence.transactions.first().ok_or(
                    PaddleSubscriptionResultError::InvalidResponse(
                        "transaction evidence missing transaction",
                    ),
                )?;
                if transaction.transaction_id != *transaction_id {
                    return Err(PaddleSubscriptionResultError::TransactionMismatch);
                }
                validate_transaction_scope(transaction, &self.scope)
            }
            PaddleReadTarget::Transactions {
                subscription_id,
                limit,
                ..
            } => {
                if *subscription_id != self.scope.identity().subscription_id
                    || !(1..=self.policy.max_transaction_page_limit).contains(limit)
                    || evidence.subscription.is_some()
                    || !evidence.events.is_empty()
                {
                    return Err(PaddleSubscriptionResultError::ScopeMismatch(
                        "transaction-list evidence target",
                    ));
                }
                for transaction in &evidence.transactions {
                    validate_transaction_scope(transaction, &self.scope)?;
                }
                Ok(())
            }
            PaddleReadTarget::Events { limit, .. } => {
                if !(1..=self.policy.max_event_page_limit).contains(limit)
                    || evidence.subscription.is_some()
                    || !evidence.transactions.is_empty()
                {
                    return Err(PaddleSubscriptionResultError::ScopeMismatch(
                        "event evidence target",
                    ));
                }
                for event in &evidence.events {
                    validate_event_scope(event, &self.scope)?;
                }
                Ok(())
            }
        }
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationRevocation> {
        self.registration.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<()> {
        self.registration.restore()
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation> {
        self.revoke_registration()
    }

    pub fn restore(&mut self) -> Result<()> {
        self.restore_registration()
    }

    pub fn revoke_secret(&mut self) -> Result<()> {
        self.scope.revoke_secret()
    }

    pub fn restore_secret(&mut self) -> Result<()> {
        self.scope.restore_secret()
    }

    fn ensure_active(&self) -> Result<()> {
        self.registration
            .validate_for(&self.scope, &self.provider.provider_digest())?;
        if self.registration.status != RegistrationStatus::Active {
            return Err(PaddleSubscriptionResultError::RegistrationRevoked);
        }
        self.scope.validate()
    }

    fn validate_snapshot(
        &self,
        observed_at: u64,
        snapshot_revision: Revision,
        minimum_observed_at: u64,
    ) -> Result<()> {
        if observed_at < minimum_observed_at {
            return Err(PaddleSubscriptionResultError::StaleResult);
        }
        if snapshot_revision != self.scope.identity().scope_revision {
            return Err(PaddleSubscriptionResultError::RevisionDrift);
        }
        Ok(())
    }

    fn validate_subscription_response(
        &self,
        proposal: &PaddleBillingReadProposal,
        request: &PaddleSubscriptionReadRequest,
        response: &PaddleSubscriptionResponse,
    ) -> Result<()> {
        self.validate_snapshot(
            response.observed_at,
            response.snapshot_revision,
            request.minimum_observed_at,
        )?;
        if response.response_bytes > self.policy.max_response_bytes {
            return Err(PaddleSubscriptionResultError::ResponseTooLarge {
                actual: response.response_bytes,
                maximum: self.policy.max_response_bytes,
            });
        }
        validate_subscription_scope(&response.subscription, &self.scope)?;
        proposal.validate(&self.registration, &self.scope, &self.provider)
    }

    fn validate_transaction_response(
        &self,
        proposal: &PaddleBillingReadProposal,
        request: &PaddleTransactionReadRequest,
        response: &PaddleTransactionResponse,
    ) -> Result<()> {
        self.validate_snapshot(
            response.observed_at,
            response.snapshot_revision,
            request.minimum_observed_at,
        )?;
        if response.response_bytes > self.policy.max_response_bytes {
            return Err(PaddleSubscriptionResultError::ResponseTooLarge {
                actual: response.response_bytes,
                maximum: self.policy.max_response_bytes,
            });
        }
        if response.transaction.transaction_id != request.transaction_id {
            return Err(PaddleSubscriptionResultError::TransactionMismatch);
        }
        validate_transaction_scope(&response.transaction, &self.scope)?;
        proposal.validate(&self.registration, &self.scope, &self.provider)
    }

    fn validate_transaction_list_response(
        &self,
        proposal: &PaddleBillingReadProposal,
        request: &PaddleTransactionListRequest,
        response: &PaddleTransactionListResponse,
    ) -> Result<()> {
        self.validate_snapshot(
            response.observed_at,
            response.snapshot_revision,
            request.minimum_observed_at,
        )?;
        if response.response_bytes > self.policy.max_response_bytes
            || response.transactions.len() > self.policy.max_transaction_page_limit as usize
        {
            return Err(PaddleSubscriptionResultError::InvalidResponse(
                "bounded transaction response",
            ));
        }
        if response.has_more != response.next_cursor.is_some() {
            return Err(PaddleSubscriptionResultError::InvalidResponse(
                "transaction cursor/has_more",
            ));
        }
        for transaction in &response.transactions {
            validate_transaction_scope(transaction, &self.scope)?;
        }
        if let Some(cursor) = &response.next_cursor {
            cursor.validate_for(
                &self.scope.scope_digest(),
                CursorKind::Transactions,
                response.observed_at,
            )?;
        }
        proposal.validate(&self.registration, &self.scope, &self.provider)
    }

    fn validate_event_list_response(
        &self,
        proposal: &PaddleBillingReadProposal,
        request: &PaddleEventListRequest,
        response: &PaddleEventListResponse,
    ) -> Result<()> {
        self.validate_snapshot(
            response.observed_at,
            response.snapshot_revision,
            request.minimum_observed_at,
        )?;
        if response.response_bytes > self.policy.max_response_bytes
            || response.events.len() > self.policy.max_event_page_limit as usize
        {
            return Err(PaddleSubscriptionResultError::InvalidResponse(
                "bounded event response",
            ));
        }
        if response.has_more != response.next_cursor.is_some() {
            return Err(PaddleSubscriptionResultError::InvalidResponse(
                "event cursor/has_more",
            ));
        }
        for event in &response.events {
            validate_event_scope(event, &self.scope)?;
        }
        if let Some(cursor) = &response.next_cursor {
            cursor.validate_for(
                &self.scope.scope_digest(),
                CursorKind::Events,
                response.observed_at,
            )?;
        }
        proposal.validate(&self.registration, &self.scope, &self.provider)
    }

    fn remember_response(
        &mut self,
        proposal: &PaddleBillingReadProposal,
        digest: &Digest,
    ) -> Result<()> {
        if let Some(existing) = self.replay_guard.get(&proposal.proposal_digest)
            && existing != digest
        {
            return Err(PaddleSubscriptionResultError::ReplayDetected);
        }
        self.replay_guard
            .insert(proposal.proposal_digest.clone(), digest.clone());
        Ok(())
    }

    fn evidence(
        &self,
        target: PaddleReadTarget,
        subscription: Option<crate::PaddleSubscriptionSummary>,
        transactions: Vec<crate::PaddleTransactionSummary>,
        events: Vec<crate::PaddleEventSummary>,
        next_cursor_digest: Option<Digest>,
        response_digest: Option<Digest>,
        disposition: EvidenceDisposition,
        provider_error: Option<ProviderErrorProjection>,
        observed_at: u64,
        snapshot_revision: Revision,
    ) -> Result<PaddleBillingEvidence> {
        self.evidence_with_page_count(
            target,
            subscription,
            transactions,
            events,
            next_cursor_digest,
            response_digest,
            1,
            disposition,
            provider_error,
            observed_at,
            snapshot_revision,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn evidence_with_page_count(
        &self,
        target: PaddleReadTarget,
        subscription: Option<crate::PaddleSubscriptionSummary>,
        transactions: Vec<crate::PaddleTransactionSummary>,
        events: Vec<crate::PaddleEventSummary>,
        next_cursor_digest: Option<Digest>,
        response_digest: Option<Digest>,
        page_count: u32,
        disposition: EvidenceDisposition,
        provider_error: Option<ProviderErrorProjection>,
        observed_at: u64,
        snapshot_revision: Revision,
    ) -> Result<PaddleBillingEvidence> {
        PaddleBillingEvidence::new(
            target,
            subscription,
            transactions,
            events,
            next_cursor_digest,
            response_digest,
            page_count,
            disposition,
            provider_error,
            self.provider.provenance(),
            observed_at,
            snapshot_revision,
            self.registration.registration_digest.clone(),
            self.registration.implementation_digest.clone(),
            self.provider.provider_digest(),
            self.scope.identity().api.digest(),
            self.scope.identity().permission.digest.clone(),
            self.scope.scope_digest(),
            self.scope.revision_digest(),
        )
    }

    fn provider_failure_evidence(
        &self,
        target: PaddleReadTarget,
        observed_at: u64,
        error: PaddleBillingProviderError,
    ) -> Result<PaddleBillingEvidence> {
        let disposition = if matches!(error, PaddleBillingProviderError::BlockedEnv) {
            EvidenceDisposition::BlockedEnv
        } else if error.is_access_loss() {
            EvidenceDisposition::AccessLost
        } else {
            EvidenceDisposition::ProviderUnknown
        };
        self.evidence(
            target,
            None,
            Vec::new(),
            Vec::new(),
            None,
            None,
            disposition,
            Some(ProviderErrorProjection::from_error(&error, None)),
            observed_at,
            self.scope.identity().scope_revision,
        )
    }
}

fn combined_digest(digests: &[Digest], last: Option<Digest>) -> Option<Digest> {
    if let Some(last) = last {
        if digests.is_empty() {
            Some(last)
        } else {
            let mut values = digests.to_vec();
            values.push(last);
            Some(Digest::from_serializable(&values))
        }
    } else if digests.len() == 1 {
        digests.first().cloned()
    } else if digests.is_empty() {
        None
    } else {
        Some(Digest::from_serializable(digests))
    }
}

fn is_evidence_provider_error(error: &PaddleBillingProviderError) -> bool {
    matches!(
        error,
        PaddleBillingProviderError::BlockedEnv
            | PaddleBillingProviderError::Unauthorized
            | PaddleBillingProviderError::Forbidden
            | PaddleBillingProviderError::NotFound
            | PaddleBillingProviderError::Conflict
            | PaddleBillingProviderError::AccessLoss
            | PaddleBillingProviderError::Timeout
            | PaddleBillingProviderError::TransportUnavailable
            | PaddleBillingProviderError::RateLimited { .. }
            | PaddleBillingProviderError::ServerError { .. }
    )
}
