//! Ramp provider: official read routes, pagination, parsing, redaction, and
//! fail-closed evidence normalization.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Arc, Mutex, OnceLock},
};

use crate::model::{
    ActorClass, AuditEventEvidence, Capabilities, DateWindow, EvidenceReceipt,
    EvidenceVerification, MerchantEvidence, OutcomeProposal, RampReadScope, RampSpendScope,
    RegistrationReceipt, ReplayFenceDurability, ResourceKind, RevocationReceipt, SpendEvidence,
    TransactionEvidence, TransactionState, amount_evidence, canonical_digest, refund_state,
};
use crate::transport::{
    BlockedEnvRampTransport, RampApiPage, RampEndpoint, RampTransport, RampTransportError,
    ReadOperation, RetryPolicy,
};
use crate::{
    RAMP_PLUGIN_VERSION, RAMP_PROVIDER_ID, RAMP_SPEND_OUTCOME_SERVICE_ID, RampSpendOutcomeError,
    RampSpendOutcomePluginDefinition,
};

/// Typed Ramp Developer API provider for Layer 1.  `T` is a transport seam;
/// the default is permanently `BLOCKED_ENV`, and every available transport is
/// explicitly non-native/non-connected until a later authorized layer adds
/// host credential and HTTPS authority.
pub struct RampProvider<T = BlockedEnvRampTransport>
where
    T: RampTransport,
{
    transport: T,
    definition: RampSpendOutcomePluginDefinition,
    scope: RampSpendScope,
    secret_reference: crate::SecretReference,
    retry_policy: RetryPolicy,
    registration: Arc<Mutex<RegistrationReceipt>>,
    replay_lease: ReplayLease,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReplayKey {
    resource: ResourceKind,
    identity_digest: String,
}

#[derive(Default)]
struct ReplayScopeState {
    records: BTreeMap<ReplayKey, String>,
    receipts: BTreeSet<String>,
}

static REPLAY_REGISTRY: OnceLock<Mutex<BTreeMap<String, ReplayScopeState>>> = OnceLock::new();

struct ReplayLease {
    scope_digest: String,
}

#[derive(Default)]
struct ReadBudget {
    pages: usize,
    response_bytes: usize,
    record_bytes: usize,
    raw_record_bytes: usize,
}

impl ReadBudget {
    fn consume(&mut self, page: &RampApiPage) -> Result<(), RampSpendOutcomeError> {
        let next_pages = self.pages.saturating_add(1);
        let next_response_bytes = self
            .response_bytes
            .saturating_add(page.response_byte_count()?);
        let next_record_bytes = self.record_bytes.saturating_add(page.record_byte_count());
        let next_raw_record_bytes = self
            .raw_record_bytes
            .saturating_add(page.raw_record_byte_count()?);
        if next_pages > crate::MAX_PAGES {
            return Err(RampSpendOutcomeError::BoundExceeded {
                field: "total pages",
                maximum: crate::MAX_PAGES,
            });
        }
        if next_response_bytes > crate::MAX_TOTAL_RESPONSE_BYTES {
            return Err(RampSpendOutcomeError::BoundExceeded {
                field: "total response bytes",
                maximum: crate::MAX_TOTAL_RESPONSE_BYTES,
            });
        }
        if next_record_bytes > crate::MAX_TOTAL_RECORD_BYTES
            || next_raw_record_bytes > crate::MAX_TOTAL_RECORD_BYTES
        {
            return Err(RampSpendOutcomeError::BoundExceeded {
                field: "total record bytes",
                maximum: crate::MAX_TOTAL_RECORD_BYTES,
            });
        }
        self.pages = next_pages;
        self.response_bytes = next_response_bytes;
        self.record_bytes = next_record_bytes;
        self.raw_record_bytes = next_raw_record_bytes;
        Ok(())
    }
}

impl ReplayLease {
    fn acquire(scope_digest: String) -> Result<Self, RampSpendOutcomeError> {
        let registry = REPLAY_REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()));
        let mut registry = registry
            .lock()
            .map_err(|_| RampSpendOutcomeError::TransportPoisoned)?;
        if !registry.contains_key(&scope_digest) && registry.len() >= crate::MAX_REPLAY_SCOPES {
            return Err(RampSpendOutcomeError::BoundExceeded {
                field: "replay scopes",
                maximum: crate::MAX_REPLAY_SCOPES,
            });
        }
        registry.entry(scope_digest.clone()).or_default();
        Ok(Self { scope_digest })
    }

    fn observe_record(
        &self,
        resource: ResourceKind,
        identity_digest: String,
        fingerprint: String,
    ) -> Result<ReplayKey, RampSpendOutcomeError> {
        let registry = REPLAY_REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()));
        let mut registry = registry
            .lock()
            .map_err(|_| RampSpendOutcomeError::TransportPoisoned)?;
        let state = registry
            .get_mut(&self.scope_digest)
            .ok_or(RampSpendOutcomeError::ReplayDetected)?;
        let key = ReplayKey {
            resource,
            identity_digest,
        };
        if !state.records.contains_key(&key) && state.records.len() >= crate::MAX_REPLAY_IDENTITIES
        {
            return Err(RampSpendOutcomeError::BoundExceeded {
                field: "replay identities",
                maximum: crate::MAX_REPLAY_IDENTITIES,
            });
        }
        if state.records.insert(key.clone(), fingerprint).is_some() {
            return Err(RampSpendOutcomeError::ReplayDetected);
        }
        Ok(key)
    }

    fn observe_receipt(&self, receipt_digest: String) -> Result<(), RampSpendOutcomeError> {
        let registry = REPLAY_REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()));
        let mut registry = registry
            .lock()
            .map_err(|_| RampSpendOutcomeError::TransportPoisoned)?;
        let state = registry
            .get_mut(&self.scope_digest)
            .ok_or(RampSpendOutcomeError::ReplayDetected)?;
        if !state.receipts.contains(&receipt_digest)
            && state.receipts.len() >= crate::MAX_REPLAY_RECEIPTS
        {
            return Err(RampSpendOutcomeError::BoundExceeded {
                field: "replay receipts",
                maximum: crate::MAX_REPLAY_RECEIPTS,
            });
        }
        if !state.receipts.insert(receipt_digest) {
            return Err(RampSpendOutcomeError::ReplayDetected);
        }
        Ok(())
    }

    fn rollback_records(&self, keys: &[ReplayKey]) {
        let Some(registry) = REPLAY_REGISTRY.get() else {
            return;
        };
        let Ok(mut registry) = registry.lock() else {
            return;
        };
        if let Some(state) = registry.get_mut(&self.scope_digest) {
            for key in keys {
                state.records.remove(key);
            }
        }
    }
}

impl<T> fmt::Debug for RampProvider<T>
where
    T: RampTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RampProvider")
            .field("transport", &self.transport)
            .field("definition", &self.definition)
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("retry_policy", &self.retry_policy)
            .field("registration", &"<redacted-registration>")
            .finish_non_exhaustive()
    }
}

impl<T> RampProvider<T>
where
    T: RampTransport,
{
    pub fn new(
        transport: T,
        scope: RampSpendScope,
        secret_reference: crate::SecretReference,
        provider_revision: u64,
        registration_revision: u64,
    ) -> Result<Self, RampSpendOutcomeError> {
        let definition = RampSpendOutcomePluginDefinition::layer1()?;
        scope.validate()?;
        if secret_reference.kind() != scope.secret_kind
            || secret_reference.revision() != scope.secret_revision
            || secret_reference.digest() != scope.secret_reference_digest
        {
            return Err(RampSpendOutcomeError::RegistrationMismatch);
        }
        let registration = RegistrationReceipt::bind(
            definition.contract_digest.clone(),
            definition.provider_digest(),
            &scope,
            provider_revision,
            registration_revision,
        )?;
        let replay_lease = ReplayLease::acquire(scope.digest())?;
        Ok(Self {
            transport,
            definition,
            scope,
            secret_reference,
            retry_policy: RetryPolicy::default(),
            registration: Arc::new(Mutex::new(registration)),
            replay_lease,
        })
    }

    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    #[must_use]
    pub fn definition(&self) -> &RampSpendOutcomePluginDefinition {
        &self.definition
    }

    #[must_use]
    pub fn scope(&self) -> &RampSpendScope {
        &self.scope
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn provenance(&self) -> crate::TransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn capabilities(&self) -> Capabilities {
        Capabilities {
            service_id: RAMP_SPEND_OUTCOME_SERVICE_ID.to_owned(),
            provider_id: RAMP_PROVIDER_ID.to_owned(),
            version: RAMP_PLUGIN_VERSION.to_owned(),
            read_only: true,
            proposal_only: true,
            native: false,
            connected: false,
            operations: vec![
                "describe_capabilities".to_owned(),
                "read_transactions".to_owned(),
                "read_merchants".to_owned(),
                "read_audit_logs".to_owned(),
                "compile_outcome_proposal".to_owned(),
                "record_evidence_receipt".to_owned(),
                "verify_evidence".to_owned(),
            ],
            transport: self.provenance(),
            replay_fence_durability: ReplayFenceDurability::ProcessSharedNonDurable,
        }
    }

    pub fn registration(&self) -> Result<RegistrationReceipt, RampSpendOutcomeError> {
        self.registration
            .lock()
            .map(|registration| registration.clone())
            .map_err(|_| RampSpendOutcomeError::TransportPoisoned)
    }

    pub fn revoke(&self) -> Result<RevocationReceipt, RampSpendOutcomeError> {
        let mut registration = self
            .registration
            .lock()
            .map_err(|_| RampSpendOutcomeError::TransportPoisoned)?;
        registration.revoke()
    }

    pub fn read_evidence(
        &self,
        window: DateWindow,
    ) -> Result<SpendEvidence, RampSpendOutcomeError> {
        let mut observed_records = Vec::new();
        let result = self.read_evidence_inner(window, &mut observed_records);
        if result.is_err() {
            self.replay_lease.rollback_records(&observed_records);
        }
        result
    }

    fn read_evidence_inner(
        &self,
        window: DateWindow,
        observed_records: &mut Vec<ReplayKey>,
    ) -> Result<SpendEvidence, RampSpendOutcomeError> {
        let registration = self.active_registration()?;
        window.validate()?;
        if window != self.scope.date_window {
            return Err(RampSpendOutcomeError::DateWindowMismatch);
        }

        let mut budget = ReadBudget::default();
        let transactions = self.read_endpoint(
            ReadOperation::ReadTransactions,
            &mut budget,
            observed_records,
        )?;
        let merchants =
            self.read_endpoint(ReadOperation::ReadMerchants, &mut budget, observed_records)?;
        let audit_events =
            self.read_endpoint(ReadOperation::ReadAuditLogs, &mut budget, observed_records)?;

        let page_count =
            transactions.pages.len() + merchants.pages.len() + audit_events.pages.len();
        if page_count == 0 || page_count > crate::MAX_PAGES {
            return Err(RampSpendOutcomeError::BoundExceeded {
                field: "pages",
                maximum: crate::MAX_PAGES,
            });
        }
        let all_pages = transactions
            .pages
            .iter()
            .chain(merchants.pages.iter())
            .chain(audit_events.pages.iter())
            .collect::<Vec<_>>();
        let request_digests = transactions
            .request_digests
            .iter()
            .chain(merchants.request_digests.iter())
            .chain(audit_events.request_digests.iter())
            .cloned()
            .collect::<Vec<_>>();
        let response_digests = all_pages
            .iter()
            .map(|page| page.response_digest.clone())
            .collect::<Vec<_>>();
        let high_water_mark_digest = canonical_digest(&(
            transactions.high_water_mark,
            merchants.high_water_mark,
            audit_events.high_water_mark,
        ));
        let request_receipt_digest = canonical_digest(&request_digests);
        let response_receipt_digest = canonical_digest(&response_digests);

        let transaction_evidence = transactions
            .pages
            .iter()
            .flat_map(|page| page.transactions.iter())
            .map(|item| self.normalize_transaction(item, &window))
            .collect::<Result<Vec<_>, _>>()?;
        let merchant_evidence = merchants
            .pages
            .iter()
            .flat_map(|page| page.merchants.iter())
            .map(|item| self.normalize_merchant(item))
            .collect::<Result<Vec<_>, _>>()?;
        let audit_evidence = audit_events
            .pages
            .iter()
            .flat_map(|page| page.audit_events.iter())
            .map(|item| self.normalize_audit_event(item, &window))
            .collect::<Result<Vec<_>, _>>()?;

        let spend_total_minor = transactions
            .pages
            .iter()
            .flat_map(|page| page.transactions.iter())
            .try_fold(0_i64, |total, item| {
                let amount = item
                    .amount_minor()
                    .ok_or(RampSpendOutcomeError::PartialEvidence)?;
                total
                    .checked_add(amount)
                    .ok_or(RampSpendOutcomeError::ContradictoryEvidence)
            })?;
        let mut currency_codes = BTreeSet::new();
        for transaction in &transaction_evidence {
            currency_codes.insert(transaction.currency_code.clone());
        }
        if currency_codes.len() > 1 {
            return Err(RampSpendOutcomeError::ContradictoryEvidence);
        }
        if !transaction_evidence.is_empty() && currency_codes.contains(&None) {
            return Err(RampSpendOutcomeError::PartialEvidence);
        }
        let currency_code = currency_codes.into_iter().flatten().next();
        let category_id_digests = transaction_evidence
            .iter()
            .filter_map(|item| item.category_id_digest.clone())
            .collect::<Vec<_>>();
        let category_name_digests = transaction_evidence
            .iter()
            .filter_map(|item| item.category_name_digest.clone())
            .chain(
                merchant_evidence
                    .iter()
                    .filter_map(|item| item.category_name_digest.clone()),
            )
            .collect::<Vec<_>>();

        self.require_exact_bindings(&transaction_evidence, &merchant_evidence, &audit_evidence)?;
        SpendEvidence::new(
            self.scope.digest(),
            registration.registration_digest,
            self.definition.provider_digest(),
            self.definition.contract_digest.clone(),
            &self.scope.spend_constraints,
            currency_code,
            category_id_digests,
            category_name_digests,
            spend_total_minor,
            transaction_evidence,
            merchant_evidence,
            audit_evidence,
            high_water_mark_digest,
            page_count as u16,
            crate::SourceEnvelopeStatus::Present,
            budget.response_bytes,
            budget.record_bytes,
            budget.raw_record_bytes,
            request_receipt_digest,
            response_receipt_digest,
            self.provenance(),
        )
    }

    pub fn compile_outcome_proposal(
        &self,
        evidence: &SpendEvidence,
    ) -> Result<OutcomeProposal, RampSpendOutcomeError> {
        let registration = self.active_registration()?;
        evidence.validate_against_scope(&self.scope)?;
        if evidence.registration_digest != registration.registration_digest
            || evidence.provider_digest != self.definition.provider_digest()
            || evidence.contract_digest != self.definition.contract_digest
        {
            return Err(RampSpendOutcomeError::RegistrationMismatch);
        }
        crate::OutcomeProposal::from_evidence(evidence, &self.scope)
    }

    pub fn record_evidence_receipt(
        &self,
        evidence: &SpendEvidence,
    ) -> Result<EvidenceReceipt, RampSpendOutcomeError> {
        let registration = self.active_registration()?;
        evidence.validate_against_scope(&self.scope)?;
        if evidence.registration_digest != registration.registration_digest {
            return Err(RampSpendOutcomeError::RegistrationMismatch);
        }
        let receipt = EvidenceReceipt::from_evidence(evidence)?;
        self.replay_lease
            .observe_receipt(receipt.receipt_digest.clone())?;
        Ok(receipt)
    }

    pub fn verify_evidence(
        &self,
        receipt: &EvidenceReceipt,
        evidence: &SpendEvidence,
    ) -> Result<EvidenceVerification, RampSpendOutcomeError> {
        let registration = self.active_registration()?;
        evidence.validate_against_scope(&self.scope)?;
        receipt.validate_against(evidence)?;
        if receipt.scope_digest != self.scope.digest()
            || receipt.registration_digest != registration.registration_digest
            || receipt.provider_digest != self.definition.provider_digest()
            || receipt.contract_digest != self.definition.contract_digest
        {
            return Err(RampSpendOutcomeError::ReceiptTampered);
        }
        Ok(EvidenceVerification {
            receipt_digest: receipt.receipt_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            registration_digest: registration.registration_digest,
            scope_digest: evidence.scope_digest.clone(),
            provider_digest: evidence.provider_digest.clone(),
            contract_digest: evidence.contract_digest.clone(),
            evidence_status: evidence.status,
            source_envelope: evidence.source_envelope,
            response_bytes: evidence.response_bytes,
            record_bytes: evidence.record_bytes,
            raw_record_bytes: evidence.raw_record_bytes,
            provenance: evidence.provenance,
            independent_state_valid: true,
            verified: true,
            native: false,
            connected: false,
            adoptable: false,
            verification_digest: String::new(),
        }
        .seal())
    }

    fn active_registration(&self) -> Result<RegistrationReceipt, RampSpendOutcomeError> {
        let registration = self.registration()?;
        if !registration.is_active() {
            return Err(RampSpendOutcomeError::RegistrationRevoked);
        }
        registration.validate(
            &self.definition.contract_digest,
            &self.definition.provider_digest(),
            &self.scope,
        )?;
        Ok(registration)
    }

    fn read_endpoint(
        &self,
        operation: ReadOperation,
        budget: &mut ReadBudget,
        observed_records: &mut Vec<ReplayKey>,
    ) -> Result<EndpointRead, RampSpendOutcomeError> {
        let endpoint = operation.endpoint();
        self.scope.permissions.require(endpoint.required_scope())?;
        let mut pages = Vec::new();
        let mut request_digests = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        let mut cursor = None;
        let mut high_water_mark = None;
        loop {
            if pages.len() >= crate::MAX_PAGES {
                return Err(RampSpendOutcomeError::BoundExceeded {
                    field: "pages",
                    maximum: crate::MAX_PAGES,
                });
            }
            let (page, request) =
                self.read_page_with_retry(operation, cursor.clone(), high_water_mark.clone())?;
            if page.endpoint != endpoint
                || page.business_id.digest() != self.scope.business_id.digest()
            {
                return Err(RampSpendOutcomeError::ScopeMismatch);
            }
            page.validate()?;
            if page.source_envelope != crate::SourceEnvelopeStatus::Present {
                return Err(RampSpendOutcomeError::PartialEvidence);
            }
            budget.consume(&page)?;
            for item in &page.transactions {
                observed_records.push(self.replay_lease.observe_record(
                    ResourceKind::Transaction,
                    sha256_digest(item.id().as_bytes()),
                    item.fingerprint_digest(),
                )?);
            }
            for item in &page.merchants {
                observed_records.push(self.replay_lease.observe_record(
                    ResourceKind::VendorMerchant,
                    sha256_digest(item.id().as_bytes()),
                    item.fingerprint_digest(),
                )?);
            }
            for item in &page.audit_events {
                observed_records.push(self.replay_lease.observe_record(
                    ResourceKind::AuditEvent,
                    sha256_digest(item.id().as_bytes()),
                    item.fingerprint_digest(),
                )?);
            }
            if let Some(previous) = &high_water_mark
                && page.high_water_mark != *previous
            {
                return Err(RampSpendOutcomeError::HighWaterMarkDrift);
            }
            if let Some(current) = &cursor
                && !seen_cursors.insert(current.clone())
            {
                return Err(RampSpendOutcomeError::CursorLoop);
            }
            request_digests.push(request.request_digest);
            high_water_mark = Some(page.high_water_mark.clone());
            let next_cursor = page.next_cursor.clone();
            if let Some(next) = &next_cursor
                && (next.is_empty() || seen_cursors.contains(next))
            {
                return Err(RampSpendOutcomeError::CursorLoop);
            }
            pages.push(page);
            cursor.clone_from(&next_cursor);
            if cursor.is_none() {
                break;
            }
        }
        let high_water_mark = high_water_mark.ok_or(RampSpendOutcomeError::RetentionGap)?;
        Ok(EndpointRead {
            pages,
            request_digests,
            high_water_mark,
        })
    }

    fn read_page_with_retry(
        &self,
        operation: ReadOperation,
        cursor: Option<String>,
        high_water_mark: Option<String>,
    ) -> Result<(RampApiPage, crate::RampReadRequest), RampSpendOutcomeError> {
        let mut attempt = 1;
        let mut backoff_seconds = 0;
        loop {
            let request = crate::RampReadRequest::new(
                &self.scope,
                operation,
                cursor.clone(),
                high_water_mark.clone(),
                attempt,
                backoff_seconds,
            )?;
            match self.transport.read(&request) {
                Ok(page) => return Ok((page, request)),
                Err(error) if error.retryable() && attempt < self.retry_policy.max_attempts => {
                    backoff_seconds = self.retry_policy.delay_seconds(attempt, &error);
                    attempt = attempt.saturating_add(1);
                }
                Err(error) => return Err(map_transport_error(error)),
            }
        }
    }

    fn normalize_transaction(
        &self,
        item: &crate::RampTransactionInput,
        window: &DateWindow,
    ) -> Result<TransactionEvidence, RampSpendOutcomeError> {
        if !window.contains(item.transaction_time())
            || !self
                .scope
                .matches_identifier(&self.scope.entity_id, item.entity_id())
            || !self
                .scope
                .matches_identifier(&self.scope.spend_program_id, item.spend_program_id())
            || !self
                .scope
                .matches_identifier(&self.scope.card_id, item.card_id())
            || !self
                .scope
                .matches_identifier(&self.scope.vendor_id, item.merchant_id())
            || (self.scope.transaction_id.is_some()
                && self
                    .scope
                    .transaction_id
                    .as_ref()
                    .is_some_and(|id| id.raw() != item.id()))
        {
            return Err(RampSpendOutcomeError::ScopeMismatch);
        }
        let state = TransactionState::parse(item.state());
        if state == TransactionState::ProviderUnknown {
            return Err(RampSpendOutcomeError::ProviderUnknown);
        }
        let (amount_bucket, amount_digest, currency_code) =
            amount_evidence(item.amount_minor(), item.currency_code())?;
        if let Some(expected_currency) = &self.scope.spend_constraints.currency_code
            && currency_code.as_deref() != Some(expected_currency.as_str())
        {
            return Err(RampSpendOutcomeError::ContradictoryEvidence);
        }
        if let Some(expected_category_id) = &self.scope.spend_constraints.category_id
            && item.category_id() != Some(expected_category_id.as_str())
        {
            return Err(RampSpendOutcomeError::ContradictoryEvidence);
        }
        if let Some(expected_category_name) = &self.scope.spend_constraints.category_name
            && item.category_name() != Some(expected_category_name.as_str())
        {
            return Err(RampSpendOutcomeError::ContradictoryEvidence);
        }
        let refund_state = refund_state(state, item.amount_minor(), item.refund_state());
        if refund_state == crate::RefundState::ProviderUnknown {
            return Err(RampSpendOutcomeError::ProviderUnknown);
        }
        Ok(TransactionEvidence {
            transaction_id_digest: sha256_digest(item.id().as_bytes()),
            state,
            refund_state,
            amount_bucket,
            amount_digest,
            currency_code,
            entity_id_digest: item.entity_id().map(digest_text),
            spend_program_id_digest: item.spend_program_id().map(digest_text),
            card_id_digest: item.card_id().map(digest_text),
            vendor_id_digest: item.merchant_id().map(digest_text),
            vendor_name_digest: item.merchant_name().map(digest_text),
            category_id_digest: item.category_id().map(digest_text),
            category_name_digest: item.category_name().map(digest_text),
            original_transaction_id_digest: item.original_transaction_id().map(digest_text),
            transaction_time: item.transaction_time(),
            updated_at: item.updated_at(),
            settlement_date: item.settlement_date(),
        })
    }

    fn normalize_merchant(
        &self,
        item: &crate::RampMerchantInput,
    ) -> Result<MerchantEvidence, RampSpendOutcomeError> {
        if let Some(expected) = &self.scope.vendor_id
            && expected.raw() != item.id()
        {
            return Err(RampSpendOutcomeError::ScopeMismatch);
        }
        if let Some(expected_category_name) = &self.scope.spend_constraints.category_name
            && item.category_name() != Some(expected_category_name.as_str())
        {
            return Err(RampSpendOutcomeError::ContradictoryEvidence);
        }
        Ok(MerchantEvidence {
            merchant_id_digest: sha256_digest(item.id().as_bytes()),
            merchant_name_digest: sha256_digest(item.merchant_name().as_bytes()),
            category_name_digest: item.category_name().map(digest_text),
        })
    }

    fn normalize_audit_event(
        &self,
        item: &crate::RampAuditEventInput,
        window: &DateWindow,
    ) -> Result<AuditEventEvidence, RampSpendOutcomeError> {
        if !window.contains(item.event_time())
            || (self.scope.audit_event_id.is_some()
                && self
                    .scope
                    .audit_event_id
                    .as_ref()
                    .is_some_and(|id| id.raw() != item.id()))
        {
            return Err(RampSpendOutcomeError::ScopeMismatch);
        }
        let actor_class = ActorClass::parse(item.actor_type());
        let resource_kind = ResourceKind::parse(item.resource_name());
        if actor_class == ActorClass::ProviderUnknown
            || resource_kind == ResourceKind::ProviderUnknown
        {
            return Err(RampSpendOutcomeError::ProviderUnknown);
        }
        Ok(AuditEventEvidence {
            audit_event_id_digest: sha256_digest(item.id().as_bytes()),
            event_type_digest: sha256_digest(item.event_type().as_bytes()),
            actor_class,
            resource_kind,
            resource_id_digest: item.resource_id().map(digest_text),
            event_time: item.event_time(),
        })
    }

    fn require_exact_bindings(
        &self,
        transactions: &[TransactionEvidence],
        merchants: &[MerchantEvidence],
        audits: &[AuditEventEvidence],
    ) -> Result<(), RampSpendOutcomeError> {
        if let Some(expected) = &self.scope.transaction_id
            && !transactions
                .iter()
                .any(|item| item.transaction_id_digest == expected.digest())
        {
            return Err(RampSpendOutcomeError::RetentionGap);
        }
        if let Some(expected) = &self.scope.audit_event_id
            && !audits
                .iter()
                .any(|item| item.audit_event_id_digest == expected.digest())
        {
            return Err(RampSpendOutcomeError::RetentionGap);
        }
        if let Some(expected) = &self.scope.vendor_id
            && !merchants
                .iter()
                .any(|item| item.merchant_id_digest == expected.digest())
            && !transactions
                .iter()
                .any(|item| item.vendor_id_digest.as_deref() == Some(expected.digest().as_str()))
        {
            return Err(RampSpendOutcomeError::RetentionGap);
        }
        if transactions.is_empty() && merchants.is_empty() && audits.is_empty() {
            return Err(RampSpendOutcomeError::EmptyEvidence);
        }
        Ok(())
    }
}

struct EndpointRead {
    pages: Vec<RampApiPage>,
    request_digests: Vec<String>,
    high_water_mark: String,
}

fn map_transport_error(error: RampTransportError) -> RampSpendOutcomeError {
    match error {
        RampTransportError::RetentionGap => RampSpendOutcomeError::RetentionGap,
        RampTransportError::AccessLost
        | RampTransportError::Unauthorized401
        | RampTransportError::Forbidden403 => RampSpendOutcomeError::AccessLost,
        RampTransportError::PartialResponse => RampSpendOutcomeError::PartialEvidence,
        RampTransportError::ResponseTampered => RampSpendOutcomeError::ResponseTampered,
        RampTransportError::ProviderUnknown => RampSpendOutcomeError::ProviderUnknown,
        other => RampSpendOutcomeError::Transport(other),
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    crate::sha256_digest(bytes)
}

fn digest_text(value: &str) -> String {
    sha256_digest(value.as_bytes())
}

#[allow(dead_code)]
fn _provider_scope_labels() -> [&'static str; 4] {
    [
        RampReadScope::TransactionsRead.label(),
        RampReadScope::MerchantsRead.label(),
        RampReadScope::AuditLogsRead.label(),
        RampEndpoint::Transactions.path(),
    ]
}
