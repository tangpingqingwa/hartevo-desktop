use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::consumer::MissionMailgunDeliveryConsumer;
use crate::error::{
    MailgunDeliveryResultServiceError, MailgunProviderError, MailgunTransportError, ModelError,
    ServiceResult,
};
use crate::model::{
    BackoffReceipt, Cursor, DeliveryStatus, Digest, EvidenceClassification, EvidenceState,
    IdempotencyKey, MailgunDeliveryEvidence, MailgunDeliveryResultProposal,
    MailgunDeliveryResultRecord, MailgunDeliveryResultScope, MailgunEvidenceDigests,
    MailgunRegistration, MailgunRequestReceipt, MailgunWebhookEnvelope, MailgunWebhookEvidence,
    RateLimitReceipt, RegistrationRevocationReceipt, VerificationFailure, VerificationReport,
    WebhookVerificationState, canonical_digest, record_digest,
};
use crate::provider::{MailgunEventsRequest, MailgunProvider, MailgunTransport};
use crate::{
    CONSUMER_ID, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, api_digest, contract_digest,
    plugin_version_digest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailgunDeliveryResultRequest {
    pub page_size: u16,
    pub max_pages: u16,
    pub cursor: Option<Cursor>,
    pub expected_scope_digest: Digest,
    pub expected_revision_digest: Digest,
    pub expected_consent_digest: Digest,
    pub idempotency_digest: Option<Digest>,
    pub now_seconds: u64,
    pub include_suppressions: bool,
    pub webhook: Option<MailgunWebhookEnvelope>,
}

impl MailgunDeliveryResultRequest {
    #[must_use]
    pub fn new(scope: &MailgunDeliveryResultScope, now_seconds: u64) -> Self {
        Self {
            page_size: MAX_PAGE_SIZE,
            max_pages: MAX_PAGES,
            cursor: None,
            expected_scope_digest: scope.scope_digest().clone(),
            expected_revision_digest: scope.revision_digest().clone(),
            expected_consent_digest: scope.consent_digest().clone(),
            idempotency_digest: None,
            now_seconds,
            include_suppressions: true,
            webhook: None,
        }
    }

    #[must_use]
    pub fn first(scope: &MailgunDeliveryResultScope, now_seconds: u64) -> Self {
        Self::new(scope, now_seconds)
    }

    pub fn with_idempotency(mut self, value: impl Into<String>) -> Result<Self, ModelError> {
        self.idempotency_digest = Some(IdempotencyKey::new(value)?.digest().clone());
        Ok(self)
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: Cursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    #[must_use]
    pub const fn with_page_bounds(mut self, page_size: u16, max_pages: u16) -> Self {
        self.page_size = page_size;
        self.max_pages = max_pages;
        self
    }

    #[must_use]
    pub fn with_webhook(mut self, webhook: MailgunWebhookEnvelope) -> Self {
        self.webhook = Some(webhook);
        self
    }

    #[must_use]
    pub const fn without_suppressions(mut self) -> Self {
        self.include_suppressions = false;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailgunServiceDefinition {
    pub id: &'static str,
    pub consumer_id: &'static str,
    pub operations: Vec<&'static str>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl Default for MailgunServiceDefinition {
    fn default() -> Self {
        Self {
            id: crate::SERVICE_ID,
            consumer_id: CONSUMER_ID,
            operations: vec![
                "read_events",
                "read_delivery_status",
                "read_retry_metadata",
                "read_suppression_metadata",
                "verify_webhook_event",
                "propose",
                "record",
                "verify",
                "revoke_registration",
                "restore_registration",
            ],
            read_only: true,
            proposal_only: true,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }
}

pub struct MailgunDeliveryResultService<T: MailgunTransport> {
    provider: MailgunProvider<T>,
    registration: MailgunRegistration,
    definition: MailgunServiceDefinition,
    records: BTreeMap<Digest, MailgunDeliveryResultRecord>,
    webhook_replays: BTreeSet<Digest>,
}

impl<T: MailgunTransport> std::fmt::Debug for MailgunDeliveryResultService<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MailgunDeliveryResultService")
            .field("scope_digest", &self.provider.scope().scope_digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("registration_state", &self.registration.state)
            .field("record_count", &self.records.len())
            .field("webhook_replay_count", &self.webhook_replays.len())
            .finish()
    }
}

impl<T: MailgunTransport> MailgunDeliveryResultService<T> {
    pub fn new(provider: MailgunProvider<T>) -> ServiceResult<Self> {
        let registration = MailgunRegistration::new(
            plugin_version_digest(),
            contract_digest(),
            provider.provider_digest(),
            api_digest(),
            provider.scope().scope_digest().clone(),
            provider.scope().revision_digest().clone(),
            provider.scope().consent_digest().clone(),
            provider.secret_reference().digest(),
        )?;
        Ok(Self {
            provider,
            registration,
            definition: MailgunServiceDefinition::default(),
            records: BTreeMap::new(),
            webhook_replays: BTreeSet::new(),
        })
    }

    pub fn from_parts(
        scope: MailgunDeliveryResultScope,
        secret_reference: crate::SecretReference,
        transport: T,
    ) -> ServiceResult<Self> {
        Self::new(MailgunProvider::new(scope, secret_reference, transport)?)
    }

    #[must_use]
    pub fn scope(&self) -> &MailgunDeliveryResultScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn provider(&self) -> &MailgunProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut MailgunProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &MailgunRegistration {
        &self.registration
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> &MailgunServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn default_request(&self, now_seconds: u64) -> MailgunDeliveryResultRequest {
        MailgunDeliveryResultRequest::new(self.scope(), now_seconds)
    }

    pub fn read(&mut self) -> ServiceResult<MailgunDeliveryEvidence> {
        self.read_with_request(self.default_request(0))
    }

    pub fn read_at(&mut self, now_seconds: u64) -> ServiceResult<MailgunDeliveryEvidence> {
        self.read_with_request(self.default_request(now_seconds))
    }

    pub fn read_with_request(
        &mut self,
        request: MailgunDeliveryResultRequest,
    ) -> ServiceResult<MailgunDeliveryEvidence> {
        self.ensure_registration()?;
        self.ensure_request_fence(&request)?;
        if self.scope().consent.is_expired(request.now_seconds) {
            return Ok(self.failure_evidence(
                EvidenceState::Expired,
                EvidenceClassification::Expired,
                request,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                RateLimitReceipt::default(),
                BackoffReceipt::none(),
                None,
                None,
            ));
        }

        let mut events = Vec::new();
        let mut suppression = Vec::new();
        let mut request_receipts = Vec::new();
        let mut seen_events = BTreeSet::new();
        let mut seen_cursors = BTreeSet::new();
        let mut current_cursor = request.cursor.clone();
        let mut pages = 0_u16;
        let mut complete = false;
        let mut state = EvidenceState::Ready;
        let mut classification = EvidenceClassification::Normalized;
        let mut rate_limit = RateLimitReceipt::default();
        let mut backoff = BackoffReceipt::none();
        if let Some(cursor) = &current_cursor {
            seen_cursors.insert(cursor.digest().clone());
        }

        while pages < request.max_pages {
            pages += 1;
            let page_request = MailgunEventsRequest::new(
                self.scope(),
                current_cursor.clone(),
                pages,
                request.page_size,
                request.idempotency_digest.clone(),
            )?;
            match self.provider.events_page(&page_request) {
                Ok(page) => {
                    rate_limit = page.rate_limit.clone();
                    request_receipts.push(MailgunRequestReceipt {
                        operation: format_operation(&page_request),
                        request_digest: page_request.request_digest.clone(),
                        scope_digest: self.scope().scope_digest().clone(),
                        cursor_digest: page_request
                            .cursor
                            .as_ref()
                            .map(|cursor| cursor.digest().clone()),
                        page: pages,
                        response_digest: page.response_digest.clone(),
                        status_code: Some(page.status_code),
                        response_bytes: page.response_bytes,
                        redacted: true,
                    });
                    if page.response_bytes > MAX_RESPONSE_BYTES {
                        state = if events.is_empty() {
                            EvidenceState::ProviderUnknown
                        } else {
                            EvidenceState::Partial
                        };
                        classification = EvidenceClassification::ProviderUnknown;
                        break;
                    }
                    for event in page.events {
                        if events.len() >= crate::MAX_TOTAL_EVENTS {
                            state = EvidenceState::Partial;
                            classification = EvidenceClassification::Partial;
                            break;
                        }
                        if !seen_events.insert(event.event_digest.clone()) {
                            state = EvidenceState::ReplayRejected;
                            classification = EvidenceClassification::Replay;
                            break;
                        }
                        events.push(event);
                    }
                    for value in page.suppression {
                        if suppression.len() >= crate::MAX_TOTAL_EVENTS {
                            state = EvidenceState::Partial;
                            classification = EvidenceClassification::Partial;
                            break;
                        }
                        suppression.push(value);
                    }
                    if matches!(state, EvidenceState::ReplayRejected) {
                        break;
                    }
                    if matches!(state, EvidenceState::Partial) {
                        break;
                    }
                    if let Some(next_cursor) = page.next_cursor {
                        if !seen_cursors.insert(next_cursor.digest().clone()) {
                            state = EvidenceState::PaginationLoop;
                            classification = EvidenceClassification::PaginationLoop;
                            break;
                        }
                        if pages == request.max_pages {
                            state = EvidenceState::Partial;
                            classification = EvidenceClassification::Partial;
                            current_cursor = Some(next_cursor);
                            break;
                        }
                        current_cursor = Some(next_cursor);
                    } else {
                        complete = true;
                        break;
                    }
                }
                Err(error) => {
                    let (
                        failure_state,
                        failure_classification,
                        failure_rate_limit,
                        failure_backoff,
                    ) = normalize_provider_error(&error, events.is_empty());
                    state = failure_state;
                    classification = failure_classification;
                    rate_limit = failure_rate_limit;
                    backoff = failure_backoff;
                    request_receipts.push(failure_receipt(
                        &page_request,
                        &error,
                        pages,
                        self.scope(),
                    ));
                    break;
                }
            }
        }

        if request.include_suppressions
            && !matches!(state, EvidenceState::Denied | EvidenceState::Expired)
        {
            let suppression_request = crate::provider::MailgunSuppressionRequest::new(self.scope());
            match self.provider.suppression_metadata(&suppression_request) {
                Ok(mut values) => suppression.append(&mut values),
                Err(error) => {
                    if matches!(state, EvidenceState::Ready) {
                        state = if events.is_empty() {
                            EvidenceState::ProviderUnknown
                        } else {
                            EvidenceState::Partial
                        };
                        classification = EvidenceClassification::ProviderUnknown;
                    }
                    let _ = error;
                }
            }
        }

        let webhook = self.verify_webhook_for_request(&request, &mut state, &mut classification)?;
        let cursor_digest = current_cursor
            .as_ref()
            .map(|cursor| cursor.digest().clone());
        if !complete && matches!(state, EvidenceState::Ready) {
            state = EvidenceState::Partial;
            classification = EvidenceClassification::Partial;
        }
        if complete
            && events.is_empty()
            && suppression.is_empty()
            && matches!(state, EvidenceState::Ready)
        {
            state = EvidenceState::Empty;
            classification = EvidenceClassification::Empty;
        }
        Ok(self.make_evidence(
            state,
            classification,
            events,
            suppression,
            pages,
            complete,
            cursor_digest,
            request_receipts,
            rate_limit,
            backoff,
            webhook,
        ))
    }

    pub fn propose(&mut self) -> ServiceResult<MailgunDeliveryResultProposal> {
        self.propose_with_request(self.default_request(0))
    }

    pub fn propose_at(&mut self, now_seconds: u64) -> ServiceResult<MailgunDeliveryResultProposal> {
        self.propose_with_request(self.default_request(now_seconds))
    }

    pub fn propose_with_request(
        &mut self,
        request: MailgunDeliveryResultRequest,
    ) -> ServiceResult<MailgunDeliveryResultProposal> {
        let evidence = self.read_with_request(request)?;
        let mut proposal = MailgunDeliveryResultProposal {
            project: self.scope().project.clone(),
            mission: self.scope().mission.clone(),
            work_product: self.scope().work_product.clone(),
            scope_digest: self.scope().scope_digest().clone(),
            revision_digest: self.scope().revision_digest().clone(),
            consent_digest: self.scope().consent_digest().clone(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence,
            proposal_digest: String::new(),
            review_only: true,
            native: false,
            connected: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        proposal.proposal_digest = crate::model::proposal_digest_for_service(&proposal);
        Ok(proposal)
    }

    pub fn verify(&self, proposal: &MailgunDeliveryResultProposal) -> VerificationReport {
        let failure = if let Err(error) = proposal.validate_integrity() {
            Some(VerificationFailure {
                code: "proposal_integrity".to_owned(),
                detail_digest: canonical_digest(&error.to_string()),
            })
        } else if proposal.registration_digest != self.registration.registration_digest {
            Some(VerificationFailure {
                code: "registration_mismatch".to_owned(),
                detail_digest: canonical_digest(&proposal.registration_digest),
            })
        } else if proposal.scope_digest != *self.scope().scope_digest()
            || proposal.revision_digest != *self.scope().revision_digest()
            || proposal.consent_digest != *self.scope().consent_digest()
        {
            Some(VerificationFailure {
                code: "scope_or_revision_mismatch".to_owned(),
                detail_digest: canonical_digest(&(
                    &proposal.scope_digest,
                    &proposal.revision_digest,
                    &proposal.consent_digest,
                )),
            })
        } else if proposal.evidence.digests.plugin_version_digest != plugin_version_digest()
            || proposal.evidence.digests.provider_digest != self.provider.provider_digest()
            || proposal.evidence.digests.contract_digest != contract_digest()
            || proposal.evidence.digests.api_digest != api_digest()
            || proposal.evidence.digests.scope_digest != proposal.scope_digest
            || proposal.evidence.digests.revision_digest != proposal.revision_digest
            || proposal.evidence.digests.consent_digest != proposal.consent_digest
            || proposal.evidence.digests.registration_digest != proposal.registration_digest
            || proposal.evidence.digests.events_digest
                != canonical_digest(
                    &proposal
                        .evidence
                        .events
                        .iter()
                        .map(|event| event.event_digest.clone())
                        .collect::<Vec<_>>(),
                )
            || proposal.evidence.evidence_digest != proposal.evidence.digest()
        {
            Some(VerificationFailure {
                code: "evidence_digest_mismatch".to_owned(),
                detail_digest: canonical_digest(&proposal.evidence.digests),
            })
        } else {
            None
        };
        let valid = failure.is_none();
        VerificationReport {
            valid,
            review_eligible: valid && matches!(proposal.evidence.state, EvidenceState::Ready),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            checked_registration_digest: self.registration.registration_digest.clone(),
            failure,
        }
    }

    pub fn verify_proposal(
        &self,
        proposal: &MailgunDeliveryResultProposal,
    ) -> ServiceResult<VerificationReport> {
        let report = self.verify(proposal);
        if report.valid {
            Ok(report)
        } else {
            Err(MailgunDeliveryResultServiceError::EvidenceMismatch)
        }
    }

    pub fn record(
        &mut self,
        proposal: &MailgunDeliveryResultProposal,
        idempotency_key: impl Into<String>,
    ) -> ServiceResult<MailgunDeliveryResultRecord> {
        self.ensure_registration()?;
        self.verify_proposal(proposal)?;
        let key = IdempotencyKey::new(idempotency_key)
            .map_err(|_| MailgunDeliveryResultServiceError::InvalidIdempotencyKey)?;
        if let Some(existing) = self.records.get(key.digest()) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(MailgunDeliveryResultServiceError::IdempotencyConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.record_digest = record_digest(&replay);
            return Ok(replay);
        }
        let mut record = MailgunDeliveryResultRecord {
            project: proposal.project.clone(),
            mission: proposal.mission.clone(),
            work_product: proposal.work_product.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            revision_digest: proposal.revision_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            idempotency_digest: key.digest().clone(),
            recorded_at_seconds: 0,
            replayed: false,
            review_only: true,
            native: false,
            connected: false,
            record_digest: String::new(),
        };
        record.record_digest = record_digest(&record);
        self.records.insert(key.digest().clone(), record.clone());
        Ok(record)
    }

    pub fn record_proposal(
        &mut self,
        proposal: &MailgunDeliveryResultProposal,
        idempotency_key: impl Into<String>,
    ) -> ServiceResult<MailgunDeliveryResultRecord> {
        self.record(proposal, idempotency_key)
    }

    pub fn revoke_registration(&mut self) -> ServiceResult<RegistrationRevocationReceipt> {
        self.registration
            .revoke()
            .map_err(MailgunDeliveryResultServiceError::from)
    }

    pub fn restore_registration(&mut self) -> ServiceResult<()> {
        self.registration
            .restore()
            .map_err(MailgunDeliveryResultServiceError::from)
    }

    pub fn revoke(&mut self) -> ServiceResult<RegistrationRevocationReceipt> {
        self.revoke_registration()
    }

    pub fn restore(&mut self) -> ServiceResult<()> {
        self.restore_registration()
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn into_consumer(self) -> MissionMailgunDeliveryConsumer<T> {
        MissionMailgunDeliveryConsumer::from_service(self)
    }

    fn ensure_registration(&self) -> ServiceResult<()> {
        if self.registration.is_active() {
            Ok(())
        } else {
            Err(MailgunDeliveryResultServiceError::RegistrationRevoked)
        }
    }

    fn ensure_request_fence(&self, request: &MailgunDeliveryResultRequest) -> ServiceResult<()> {
        if request.page_size == 0
            || request.page_size > MAX_PAGE_SIZE
            || request.max_pages == 0
            || request.max_pages > MAX_PAGES
        {
            return Err(MailgunDeliveryResultServiceError::Model(
                ModelError::InvalidScope("pagination request"),
            ));
        }
        if request.expected_scope_digest != *self.scope().scope_digest() {
            return Err(MailgunDeliveryResultServiceError::RegistrationMismatch);
        }
        if request.expected_revision_digest != *self.scope().revision_digest() {
            return Err(MailgunDeliveryResultServiceError::RevisionMismatch);
        }
        if request.expected_consent_digest != *self.scope().consent_digest() {
            return Err(MailgunDeliveryResultServiceError::ConsentMismatch);
        }
        if let Some(cursor) = &request.cursor {
            cursor
                .validate()
                .map_err(MailgunDeliveryResultServiceError::from)?;
        }
        Ok(())
    }

    fn verify_webhook_for_request(
        &mut self,
        request: &MailgunDeliveryResultRequest,
        state: &mut EvidenceState,
        classification: &mut EvidenceClassification,
    ) -> ServiceResult<Option<MailgunWebhookEvidence>> {
        let Some(envelope) = &request.webhook else {
            return Ok(None);
        };
        if self.webhook_replays.contains(envelope.replay_key_digest()) {
            *state = EvidenceState::ReplayRejected;
            *classification = EvidenceClassification::Replay;
            return Ok(Some(MailgunWebhookEvidence {
                state: WebhookVerificationState::Replay,
                envelope_digest: envelope.digest(),
                event_id_digest: String::new(),
                payload_digest: String::new(),
                signature_digest: String::new(),
                replay_key_digest: envelope.replay_key_digest().clone(),
                verified: false,
            }));
        }
        let evidence = match self.provider.verify_webhook(envelope, request.now_seconds) {
            Ok(evidence) => evidence,
            Err(MailgunProviderError::WebhookTampered) => {
                *state = EvidenceState::Tampered;
                *classification = EvidenceClassification::Tampered;
                MailgunWebhookEvidence::from_envelope(envelope, request.now_seconds)
            }
            Err(error) => return Err(error.into()),
        };
        self.webhook_replays
            .insert(envelope.replay_key_digest().clone());
        if matches!(evidence.state, WebhookVerificationState::Expired) {
            *state = EvidenceState::Expired;
            *classification = EvidenceClassification::Expired;
        }
        Ok(Some(evidence))
    }

    fn make_evidence(
        &self,
        state: EvidenceState,
        classification: EvidenceClassification,
        events: Vec<crate::MailgunDeliveryEvent>,
        suppression: Vec<crate::SuppressionMetadata>,
        pages: u16,
        complete: bool,
        cursor_digest: Option<Digest>,
        request_receipts: Vec<MailgunRequestReceipt>,
        rate_limit: RateLimitReceipt,
        backoff: BackoffReceipt,
        webhook: Option<MailgunWebhookEvidence>,
    ) -> MailgunDeliveryEvidence {
        let events_digest = canonical_digest(
            &events
                .iter()
                .map(|event| event.event_digest.clone())
                .collect::<Vec<_>>(),
        );
        let webhook_digest = webhook.as_ref().map(|value| value.envelope_digest.clone());
        let mut evidence = MailgunDeliveryEvidence {
            state,
            classification,
            delivery_status: delivery_status(&events),
            events,
            suppression,
            pages,
            complete,
            cursor_digest: cursor_digest.clone(),
            request_receipts,
            rate_limit,
            backoff,
            webhook,
            digests: MailgunEvidenceDigests {
                plugin_version_digest: plugin_version_digest(),
                contract_digest: contract_digest(),
                provider_digest: self.provider.provider_digest(),
                api_digest: api_digest(),
                scope_digest: self.scope().scope_digest().clone(),
                revision_digest: self.scope().revision_digest().clone(),
                consent_digest: self.scope().consent_digest().clone(),
                registration_digest: self.registration.registration_digest.clone(),
                events_digest,
                cursor_digest,
                webhook_digest,
                evidence_digest: String::new(),
            },
            provenance: self.provider.provenance(),
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            provider_receipt: false,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.digest();
        evidence.digests.evidence_digest = evidence.evidence_digest.clone();
        evidence
    }

    #[allow(clippy::too_many_arguments)]
    fn failure_evidence(
        &self,
        state: EvidenceState,
        classification: EvidenceClassification,
        request: MailgunDeliveryResultRequest,
        events: Vec<crate::MailgunDeliveryEvent>,
        suppression: Vec<crate::SuppressionMetadata>,
        request_receipts: Vec<MailgunRequestReceipt>,
        rate_limit: RateLimitReceipt,
        backoff: BackoffReceipt,
        webhook: Option<MailgunWebhookEvidence>,
        _failure: Option<Digest>,
    ) -> MailgunDeliveryEvidence {
        self.make_evidence(
            state,
            classification,
            events,
            suppression,
            0,
            false,
            request
                .cursor
                .as_ref()
                .map(|cursor| cursor.digest().clone()),
            request_receipts,
            rate_limit,
            backoff,
            webhook,
        )
    }
}

fn format_operation(request: &MailgunEventsRequest) -> String {
    match request.operation {
        crate::MailgunOperation::ListEvents => "list_events".to_owned(),
        crate::MailgunOperation::GetEvent => "get_event".to_owned(),
        crate::MailgunOperation::ReadSuppressionMetadata => "read_suppression_metadata".to_owned(),
        crate::MailgunOperation::VerifyWebhookEvent => "verify_webhook_event".to_owned(),
    }
}

fn delivery_status(events: &[crate::MailgunDeliveryEvent]) -> DeliveryStatus {
    if events
        .iter()
        .any(|event| event.status() == DeliveryStatus::Delivered)
    {
        DeliveryStatus::Delivered
    } else if events
        .iter()
        .any(|event| event.status() == DeliveryStatus::PermanentFailure)
    {
        DeliveryStatus::PermanentFailure
    } else if events
        .iter()
        .any(|event| event.status() == DeliveryStatus::TemporaryFailure)
    {
        DeliveryStatus::TemporaryFailure
    } else if events
        .iter()
        .any(|event| event.status() == DeliveryStatus::Suppressed)
    {
        DeliveryStatus::Suppressed
    } else if events
        .iter()
        .any(|event| event.status() == DeliveryStatus::Accepted)
    {
        DeliveryStatus::Accepted
    } else {
        DeliveryStatus::Unknown
    }
}

fn failure_receipt(
    request: &MailgunEventsRequest,
    error: &MailgunProviderError,
    page: u16,
    scope: &MailgunDeliveryResultScope,
) -> MailgunRequestReceipt {
    MailgunRequestReceipt {
        operation: format_operation(request),
        request_digest: request.request_digest.clone(),
        scope_digest: scope.scope_digest().clone(),
        cursor_digest: request
            .cursor
            .as_ref()
            .map(|cursor| cursor.digest().clone()),
        page,
        response_digest: canonical_digest(&("mailgun-provider-error/v1", error.to_string())),
        status_code: status_code(error),
        response_bytes: 0,
        redacted: true,
    }
}

fn status_code(error: &MailgunProviderError) -> Option<u16> {
    match error {
        MailgunProviderError::Transport(MailgunTransportError::Denied) => Some(403),
        MailgunProviderError::Transport(MailgunTransportError::NotFound) => Some(404),
        MailgunProviderError::Transport(MailgunTransportError::RateLimited { .. }) => Some(429),
        _ => None,
    }
}

fn normalize_provider_error(
    error: &MailgunProviderError,
    no_events: bool,
) -> (
    EvidenceState,
    EvidenceClassification,
    RateLimitReceipt,
    BackoffReceipt,
) {
    match error {
        MailgunProviderError::Transport(MailgunTransportError::RateLimited {
            retry_after_seconds,
            attempt,
        }) => {
            let retry_after_seconds = *retry_after_seconds;
            (
                EvidenceState::RateLimited,
                EvidenceClassification::RateLimited,
                RateLimitReceipt {
                    limit: 1,
                    remaining: Some(0),
                    retry_after_seconds,
                    throttled: true,
                },
                BackoffReceipt::new(*attempt, true, retry_after_seconds)
                    .unwrap_or_else(|_| BackoffReceipt::none()),
            )
        }
        MailgunProviderError::Transport(MailgunTransportError::Denied)
        | MailgunProviderError::SecretRevoked => (
            EvidenceState::Denied,
            EvidenceClassification::Denied,
            RateLimitReceipt::default(),
            BackoffReceipt::none(),
        ),
        MailgunProviderError::Transport(MailgunTransportError::Tampered)
        | MailgunProviderError::WebhookTampered => (
            EvidenceState::Tampered,
            EvidenceClassification::Tampered,
            RateLimitReceipt::default(),
            BackoffReceipt::none(),
        ),
        MailgunProviderError::Transport(MailgunTransportError::Replay)
        | MailgunProviderError::WebhookReplay => (
            EvidenceState::ReplayRejected,
            EvidenceClassification::Replay,
            RateLimitReceipt::default(),
            BackoffReceipt::none(),
        ),
        MailgunProviderError::Transport(MailgunTransportError::BlockedEnv) => (
            if no_events {
                EvidenceState::ProviderUnknown
            } else {
                EvidenceState::Partial
            },
            EvidenceClassification::BlockedEnv,
            RateLimitReceipt::default(),
            BackoffReceipt::none(),
        ),
        _ => (
            if no_events {
                EvidenceState::ProviderUnknown
            } else {
                EvidenceState::Partial
            },
            EvidenceClassification::ProviderUnknown,
            RateLimitReceipt::default(),
            BackoffReceipt::none(),
        ),
    }
}
