use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    Digest, MAX_DIAGNOSTICS, MAX_PAGE_SIZE, MAX_PAGES_PER_OPERATION, MAX_PLAN_EVENT_SPECS,
    SnowplowDiagnostic, SnowplowEvidenceDigests, SnowplowEvidenceState, SnowplowHistoryOrder,
    SnowplowModelError, SnowplowObservationReceipt, SnowplowRegistration,
    SnowplowRegistrationState, SnowplowTrackingPlanEvidence, SnowplowTrackingPlanProjection,
    SnowplowTrackingPlanScope, canonical_digest, sha256_digest,
};
use crate::provider::{
    SnowplowProvider, SnowplowProviderError, SnowplowProviderPage, SnowplowTransport,
};
use crate::{
    CONSUMER_ID, CONTRACT_SCHEMA, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SnowplowServiceError {
    #[error("Snowplow registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Snowplow SecretReference is revoked")]
    SecretRevoked,
    #[error("Snowplow permission or scope does not match")]
    ScopeMismatch,
    #[error("Snowplow evidence or proposal digest fence failed")]
    EvidenceMismatch,
    #[error("Snowplow proposal replay conflicts with an existing observation")]
    ReplayConflict,
    #[error("Snowplow proposal was already consumed")]
    ReplayDetected,
    #[error("Snowplow read options are outside the Layer-1 bound")]
    InvalidReadOptions,
    #[error(transparent)]
    Model(#[from] SnowplowModelError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowReadOptions {
    pub page_size: u16,
    pub max_pages_per_operation: u16,
    pub history_before: Option<String>,
    pub history_order: SnowplowHistoryOrder,
    pub expected_plan_revision: Option<u64>,
    pub include_event_specs: bool,
    pub include_history: bool,
}

impl Default for SnowplowReadOptions {
    fn default() -> Self {
        Self {
            page_size: MAX_PAGE_SIZE,
            max_pages_per_operation: MAX_PAGES_PER_OPERATION,
            history_before: None,
            history_order: SnowplowHistoryOrder::Desc,
            expected_plan_revision: None,
            include_event_specs: true,
            include_history: true,
        }
    }
}

impl SnowplowReadOptions {
    pub fn validate(&self) -> Result<(), SnowplowServiceError> {
        if self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages_per_operation == 0
            || self.max_pages_per_operation > MAX_PAGES_PER_OPERATION
            || self
                .history_before
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 64 || value.trim() != value)
        {
            return Err(SnowplowServiceError::InvalidReadOptions);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnowplowTrackingPlanServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub emits_outcome: bool,
}

impl Default for SnowplowTrackingPlanServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            read_only: true,
            live_execution: false,
            external_writes: false,
            emits_outcome: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnowplowProposalDisposition {
    Draft,
    Active,
    Archived,
    Missing,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tamper,
    Stale,
    Revoked,
}

impl From<SnowplowEvidenceState> for SnowplowProposalDisposition {
    fn from(state: SnowplowEvidenceState) -> Self {
        match state {
            SnowplowEvidenceState::Draft => Self::Draft,
            SnowplowEvidenceState::Active => Self::Active,
            SnowplowEvidenceState::Archived => Self::Archived,
            SnowplowEvidenceState::Missing => Self::Missing,
            SnowplowEvidenceState::Partial => Self::Partial,
            SnowplowEvidenceState::AccessLoss => Self::AccessLoss,
            SnowplowEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            SnowplowEvidenceState::Tamper => Self::Tamper,
            SnowplowEvidenceState::Stale => Self::Stale,
            SnowplowEvidenceState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowTrackingPlanProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub source_evidence_digest: Digest,
    pub evidence: SnowplowTrackingPlanEvidence,
    pub state: SnowplowEvidenceState,
    pub disposition: SnowplowProposalDisposition,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
    pub proposal_digest: Digest,
}

impl SnowplowTrackingPlanProposal {
    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&serde_json::json!([
            &self.service_id,
            &self.consumer_id,
            &self.scope_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.contract_digest,
            &self.permission_digest,
            &self.source_evidence_digest,
            &self.evidence,
            self.state,
            self.disposition,
            self.proposal_only,
            self.connected,
            self.native,
            self.first_party,
            self.adopts_outcome,
            self.adopts_work_product,
        ]))
    }

    pub fn validate_integrity(&self) -> Result<(), SnowplowServiceError> {
        self.evidence
            .validate_integrity()
            .map_err(|_| SnowplowServiceError::EvidenceMismatch)?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.scope_digest != self.evidence.scope_digest
            || self.source_evidence_digest != *self.evidence.digest()
            || self.state != self.evidence.state
            || self.disposition != self.state.into()
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.adopts_outcome
            || self.adopts_work_product
            || self.provider_digest != self.evidence.evidence_digests.provider_digest
            || self.contract_digest != self.evidence.evidence_digests.contract_digest
            || self.permission_digest != self.evidence.evidence_digests.permission_digest
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(SnowplowServiceError::EvidenceMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowVerificationReport {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub verified: bool,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub kernel_receipt: bool,
    pub outcome_adopted: bool,
}

/// Layer-1 typed service for bounded Snowplow tracking-plan evidence.
pub struct SnowplowTrackingPlanService<T: SnowplowTransport> {
    provider: SnowplowProvider<T>,
    definition: SnowplowTrackingPlanServiceDefinition,
    records: BTreeMap<Digest, SnowplowObservationReceipt>,
}

impl<T: SnowplowTransport> fmt::Debug for SnowplowTrackingPlanService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnowplowTrackingPlanService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T: SnowplowTransport> SnowplowTrackingPlanService<T> {
    pub fn new(provider: SnowplowProvider<T>) -> Result<Self, SnowplowServiceError> {
        provider
            .registration()
            .validate(
                provider.scope(),
                provider.secret_reference(),
                &provider.provider_digest(),
            )
            .map_err(|_| SnowplowServiceError::RegistrationRevoked)?;
        Ok(Self {
            provider,
            definition: SnowplowTrackingPlanServiceDefinition::default(),
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn from_provider(provider: SnowplowProvider<T>) -> Self {
        Self {
            provider,
            definition: SnowplowTrackingPlanServiceDefinition::default(),
            records: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &SnowplowProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut SnowplowProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &SnowplowTrackingPlanScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &SnowplowRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &SnowplowTrackingPlanServiceDefinition {
        &self.definition
    }

    pub fn read(&mut self) -> Result<SnowplowTrackingPlanEvidence, SnowplowServiceError> {
        self.read_with_options(&SnowplowReadOptions::default())
    }

    pub fn read_with_options(
        &mut self,
        options: &SnowplowReadOptions,
    ) -> Result<SnowplowTrackingPlanEvidence, SnowplowServiceError> {
        options.validate()?;
        self.provider.reset_read_budget();
        if self.provider.registration().state != SnowplowRegistrationState::Active {
            return self.terminal_evidence(
                SnowplowEvidenceState::Revoked,
                vec![SnowplowDiagnostic::RegistrationRevoked],
            );
        }
        if self.provider.secret_reference().is_revoked() {
            return self.terminal_evidence(
                SnowplowEvidenceState::Revoked,
                vec![SnowplowDiagnostic::RegistrationRevoked],
            );
        }

        let mut accumulator = ReadAccumulator::default();
        self.collect_plan(&mut accumulator)?;
        if options.include_event_specs {
            self.collect_event_specs(&mut accumulator, options)?;
        }
        if options.include_history {
            self.collect_history(&mut accumulator, options)?;
        }
        let mut state = accumulator.state.unwrap_or_else(|| {
            accumulator
                .plan
                .as_ref()
                .map_or(SnowplowEvidenceState::Missing, |plan| plan.status.into())
        });
        if let Some(expected) = options.expected_plan_revision
            && accumulator
                .plan
                .as_ref()
                .is_some_and(|plan| plan.revision != expected)
        {
            state = SnowplowEvidenceState::Stale;
            accumulator
                .diagnostics
                .push(SnowplowDiagnostic::StaleRevision);
        }
        if accumulator.partial
            && matches!(
                state,
                SnowplowEvidenceState::Draft
                    | SnowplowEvidenceState::Active
                    | SnowplowEvidenceState::Archived
            )
        {
            state = SnowplowEvidenceState::Partial;
        }
        if accumulator.event_specs.len() > MAX_PLAN_EVENT_SPECS {
            state = SnowplowEvidenceState::Partial;
            accumulator.event_specs.truncate(MAX_PLAN_EVENT_SPECS);
        }
        accumulator.diagnostics.sort_unstable();
        accumulator.diagnostics.dedup();
        accumulator.diagnostics.truncate(MAX_DIAGNOSTICS);
        let mut evidence = self.make_evidence(state, accumulator);
        let evidence_digest = evidence.calculate_digest();
        evidence
            .evidence_digests
            .evidence_digest
            .clone_from(&evidence_digest);
        self.provider
            .bind_evidence_digest(evidence_digest)
            .map_err(map_provider_error)?;
        evidence
            .registration_digest
            .clone_from(&self.provider.registration().registration_digest);
        evidence.validate_integrity()?;
        Ok(evidence)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<SnowplowTrackingPlanProposal, SnowplowServiceError> {
        let evidence = self.read()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: SnowplowTrackingPlanEvidence,
    ) -> Result<SnowplowTrackingPlanProposal, SnowplowServiceError> {
        self.ensure_registration()?;
        evidence.validate_integrity()?;
        if evidence.evidence_digests.evidence_digest != self.provider.registration().evidence_digest
            || evidence.scope_digest != *self.scope().digest()
            || evidence.evidence_digests.provider_digest != self.provider.provider_digest()
        {
            return Err(SnowplowServiceError::EvidenceMismatch);
        }
        let mut proposal = SnowplowTrackingPlanProposal {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            scope_digest: self.scope().digest().clone(),
            registration_digest: self.provider.registration().registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            contract_digest: crate::contract_digest(),
            permission_digest: self.scope().permissions().digest(),
            source_evidence_digest: evidence.evidence_digests.evidence_digest.clone(),
            state: evidence.state,
            disposition: evidence.state.into(),
            evidence,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            adopts_outcome: false,
            adopts_work_product: false,
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        Ok(proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &SnowplowTrackingPlanProposal,
    ) -> Result<(), SnowplowServiceError> {
        let _ = self.verify(proposal)?;
        Ok(())
    }

    pub fn verify(
        &self,
        proposal: &SnowplowTrackingPlanProposal,
    ) -> Result<SnowplowVerificationReport, SnowplowServiceError> {
        self.ensure_registration()?;
        proposal.validate_integrity()?;
        if proposal.registration_digest != self.provider.registration().registration_digest
            || proposal.provider_digest != self.provider.provider_digest()
            || proposal.contract_digest != crate::contract_digest()
            || proposal.permission_digest != self.scope().permissions().digest()
            || proposal.scope_digest != *self.scope().digest()
        {
            return Err(SnowplowServiceError::EvidenceMismatch);
        }
        Ok(SnowplowVerificationReport {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.source_evidence_digest.clone(),
            verified: true,
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            kernel_receipt: false,
            outcome_adopted: false,
        })
    }

    pub fn record_observation(
        &mut self,
        proposal: &SnowplowTrackingPlanProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<SnowplowObservationReceipt, SnowplowServiceError> {
        self.verify(proposal)?;
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty() || idempotency_key.len() > crate::model::MAX_IDENTIFIER_BYTES
        {
            return Err(SnowplowServiceError::Model(
                SnowplowModelError::InvalidIdentifier("idempotency key"),
            ));
        }
        let key_digest =
            sha256_digest(format!("snowplow-idempotency/v1|{idempotency_key}").as_bytes());
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(SnowplowServiceError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = recording_digest(&replay);
            return Ok(replay);
        }
        let mut receipt = SnowplowObservationReceipt {
            idempotency_key_digest: key_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.source_evidence_digest.clone(),
            state: proposal.state,
            provenance: proposal.evidence.provenance,
            replayed: false,
            connected: false,
            native: false,
            first_party: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: String::new(),
        };
        receipt.recording_digest = recording_digest(&receipt);
        self.records.insert(key_digest, receipt.clone());
        Ok(receipt)
    }

    pub fn revoke(
        &mut self,
    ) -> Result<crate::SnowplowRegistrationRevocationReceipt, SnowplowServiceError> {
        self.provider.revoke().map_err(map_provider_error)
    }

    pub fn restore(&mut self) -> Result<(), SnowplowServiceError> {
        self.provider.restore().map_err(map_provider_error)
    }

    pub fn revoke_secret(&mut self) -> Result<(), SnowplowServiceError> {
        self.provider.revoke_secret().map_err(map_provider_error)
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    fn ensure_registration(&self) -> Result<(), SnowplowServiceError> {
        if self.provider.registration().state != SnowplowRegistrationState::Active {
            return Err(SnowplowServiceError::RegistrationRevoked);
        }
        if self.provider.secret_reference().is_revoked() {
            return Err(SnowplowServiceError::SecretRevoked);
        }
        self.provider
            .registration()
            .validate(
                self.provider.scope(),
                self.provider.secret_reference(),
                &self.provider.provider_digest(),
            )
            .map_err(|_| SnowplowServiceError::RegistrationRevoked)
    }

    fn collect_plan(
        &mut self,
        accumulator: &mut ReadAccumulator,
    ) -> Result<(), SnowplowServiceError> {
        match self.provider.read_tracking_plan() {
            Ok(page) => {
                accumulator.absorb(page);
                if accumulator.plan.is_none() {
                    accumulator.state = Some(SnowplowEvidenceState::Missing);
                    accumulator.diagnostics.push(SnowplowDiagnostic::Missing);
                }
            }
            Err(error) => accumulator.absorb_error(error),
        }
        Ok(())
    }

    fn collect_event_specs(
        &mut self,
        accumulator: &mut ReadAccumulator,
        options: &SnowplowReadOptions,
    ) -> Result<(), SnowplowServiceError> {
        let mut cursor = None;
        let mut seen = BTreeSet::new();
        for _ in 0..options.max_pages_per_operation {
            let page = match self
                .provider
                .read_event_specs(options.page_size, cursor.clone())
            {
                Ok(page) => page,
                Err(error) => {
                    accumulator.absorb_error(error);
                    break;
                }
            };
            let next = page.next_cursor.clone();
            accumulator.absorb(page);
            if let Some(next_cursor) = next {
                if !seen.insert(next_cursor.digest().clone()) {
                    accumulator.state = Some(SnowplowEvidenceState::Stale);
                    accumulator
                        .diagnostics
                        .push(SnowplowDiagnostic::StaleCursor);
                    break;
                }
                cursor = Some(next_cursor);
            } else {
                break;
            }
            if cursor
                .as_ref()
                .is_some_and(|value| value.page_number() > options.max_pages_per_operation)
            {
                accumulator.partial = true;
                accumulator
                    .diagnostics
                    .push(SnowplowDiagnostic::PartialPages);
                break;
            }
        }
        Ok(())
    }

    fn collect_history(
        &mut self,
        accumulator: &mut ReadAccumulator,
        options: &SnowplowReadOptions,
    ) -> Result<(), SnowplowServiceError> {
        let mut cursor = None;
        let mut seen = BTreeSet::new();
        for _ in 0..options.max_pages_per_operation {
            let page = match self.provider.read_history(
                options.page_size,
                cursor.clone(),
                options.history_before.as_deref(),
                options.history_order,
            ) {
                Ok(page) => page,
                Err(error) => {
                    accumulator.absorb_error(error);
                    break;
                }
            };
            let next = page.next_cursor.clone();
            accumulator.absorb(page);
            if let Some(next_cursor) = next {
                if !seen.insert(next_cursor.digest().clone()) {
                    accumulator.state = Some(SnowplowEvidenceState::Stale);
                    accumulator
                        .diagnostics
                        .push(SnowplowDiagnostic::StaleCursor);
                    break;
                }
                cursor = Some(next_cursor);
            } else {
                break;
            }
            if cursor
                .as_ref()
                .is_some_and(|value| value.page_number() > options.max_pages_per_operation)
            {
                accumulator.partial = true;
                accumulator
                    .diagnostics
                    .push(SnowplowDiagnostic::PartialPages);
                break;
            }
        }
        Ok(())
    }

    fn make_evidence(
        &self,
        state: SnowplowEvidenceState,
        mut accumulator: ReadAccumulator,
    ) -> SnowplowTrackingPlanEvidence {
        accumulator
            .event_specs
            .sort_by(|left, right| left.id_digest.cmp(&right.id_digest));
        accumulator.event_specs.dedup_by(|left, right| {
            left.id_digest == right.id_digest && left.revision == right.revision
        });
        accumulator.history.sort_by(|left, right| {
            left.resource_digest
                .cmp(&right.resource_digest)
                .then(left.revision.cmp(&right.revision))
        });
        accumulator.history.dedup_by(|left, right| {
            left.resource_digest == right.resource_digest && left.revision == right.revision
        });
        accumulator.page_receipts.sort_by(|left, right| {
            left.operation
                .cmp(&right.operation)
                .then(left.page_number.cmp(&right.page_number))
        });
        let mut schemas = Vec::new();
        let mut revisions = Vec::new();
        if let Some(plan) = &accumulator.plan {
            schemas.push(plan.schema_digest.clone());
            revisions.push(plan.revision_digest.clone());
        }
        for event_spec in &accumulator.event_specs {
            schemas.push(event_spec.schema_digest.clone());
            revisions.push(event_spec.revision_digest.clone());
        }
        for history in &accumulator.history {
            schemas.push(history.schema_digest.clone());
            revisions.push(history.revision_digest.clone());
        }
        schemas.sort_unstable();
        revisions.sort_unstable();
        let response_digests = accumulator
            .page_receipts
            .iter()
            .map(|receipt| receipt.response_digest.clone())
            .collect::<Vec<_>>();
        let digests = SnowplowEvidenceDigests {
            version_digest: canonical_digest(&(PLUGIN_VERSION, CONTRACT_VERSION)),
            contract_digest: crate::contract_digest(),
            provider_digest: self.provider.provider_digest(),
            permission_digest: self.scope().permissions().digest(),
            scope_digest: self.scope().digest().clone(),
            privacy_digest: self.scope().privacy_digest().clone(),
            schema_digest: canonical_digest(&schemas),
            revision_digest: canonical_digest(&revisions),
            response_digest: canonical_digest(&response_digests),
            evidence_digest: sha256_digest(b"snowplow-unsealed-evidence/v1"),
        };
        SnowplowTrackingPlanEvidence {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            registration_digest: self.provider.registration().registration_digest.clone(),
            scope_digest: self.scope().digest().clone(),
            state,
            plan: accumulator.plan,
            event_specs: accumulator.event_specs,
            history: accumulator.history,
            page_receipts: accumulator.page_receipts,
            rate_limit_receipts: accumulator.rate_limit_receipts,
            diagnostics: accumulator.diagnostics,
            provenance: self.provider.transport_provenance(),
            connected: false,
            native: false,
            first_party: false,
            evidence_digests: digests,
        }
    }

    fn terminal_evidence(
        &self,
        state: SnowplowEvidenceState,
        diagnostics: Vec<SnowplowDiagnostic>,
    ) -> Result<SnowplowTrackingPlanEvidence, SnowplowServiceError> {
        let evidence = self.make_evidence(
            state,
            ReadAccumulator {
                state: Some(state),
                diagnostics,
                ..ReadAccumulator::default()
            },
        );
        let evidence_digest = evidence.calculate_digest();
        let mut evidence = evidence;
        evidence.evidence_digests.evidence_digest = evidence_digest;
        evidence.validate_integrity()?;
        Ok(evidence)
    }
}

#[derive(Default)]
struct ReadAccumulator {
    plan: Option<SnowplowTrackingPlanProjection>,
    event_specs: Vec<crate::SnowplowEventSpecProjection>,
    history: Vec<crate::SnowplowHistoryProjection>,
    page_receipts: Vec<crate::SnowplowPageReceipt>,
    rate_limit_receipts: Vec<crate::SnowplowRateLimitReceipt>,
    diagnostics: Vec<SnowplowDiagnostic>,
    state: Option<SnowplowEvidenceState>,
    partial: bool,
}

impl ReadAccumulator {
    fn absorb(&mut self, page: SnowplowProviderPage) {
        if let Some(plan) = page.plan {
            self.plan = Some(plan);
        }
        self.event_specs.extend(page.event_specs);
        self.history.extend(page.history);
        self.page_receipts.push(page.page_receipt);
        self.rate_limit_receipts.push(page.rate_limit);
    }

    fn absorb_error(&mut self, error: SnowplowProviderError) {
        let (state, diagnostic) = match &error {
            SnowplowProviderError::RegistrationRevoked | SnowplowProviderError::SecretRevoked => (
                SnowplowEvidenceState::Revoked,
                SnowplowDiagnostic::RegistrationRevoked,
            ),
            SnowplowProviderError::RateLimited { .. } => (
                SnowplowEvidenceState::Partial,
                SnowplowDiagnostic::RateLimited,
            ),
            SnowplowProviderError::HttpStatus { status_code, .. } => match status_code {
                401 | 403 => (
                    SnowplowEvidenceState::AccessLoss,
                    SnowplowDiagnostic::AccessLoss,
                ),
                404 => (SnowplowEvidenceState::Missing, SnowplowDiagnostic::Missing),
                _ => (
                    SnowplowEvidenceState::ProviderUnknown,
                    SnowplowDiagnostic::ProviderUnknown,
                ),
            },
            SnowplowProviderError::ResponseTooLarge { .. } => (
                SnowplowEvidenceState::ProviderUnknown,
                SnowplowDiagnostic::ResponseTooLarge,
            ),
            SnowplowProviderError::MalformedResponse { .. } => (
                SnowplowEvidenceState::ProviderUnknown,
                SnowplowDiagnostic::MalformedResponse,
            ),
            SnowplowProviderError::TamperedResponse { .. } => {
                (SnowplowEvidenceState::Tamper, SnowplowDiagnostic::Tamper)
            }
            SnowplowProviderError::StaleCursor => (
                SnowplowEvidenceState::Stale,
                SnowplowDiagnostic::StaleCursor,
            ),
            SnowplowProviderError::Transport { error, .. } => match error {
                crate::SnowplowTransportError::BlockedEnv => (
                    SnowplowEvidenceState::AccessLoss,
                    SnowplowDiagnostic::BlockedEnv,
                ),
                crate::SnowplowTransportError::ProviderUnknown => (
                    SnowplowEvidenceState::ProviderUnknown,
                    SnowplowDiagnostic::ProviderUnknown,
                ),
            },
            SnowplowProviderError::RequestBudgetExceeded => (
                SnowplowEvidenceState::Partial,
                SnowplowDiagnostic::PartialPages,
            ),
            SnowplowProviderError::MissingPermission | SnowplowProviderError::ScopeMismatch => (
                SnowplowEvidenceState::AccessLoss,
                SnowplowDiagnostic::AccessLoss,
            ),
            SnowplowProviderError::Model(_) => (
                SnowplowEvidenceState::ProviderUnknown,
                SnowplowDiagnostic::MalformedResponse,
            ),
        };
        self.state = Some(match (self.state, state) {
            (Some(SnowplowEvidenceState::Tamper), _) | (_, SnowplowEvidenceState::Tamper) => {
                SnowplowEvidenceState::Tamper
            }
            (Some(SnowplowEvidenceState::Stale), _) | (_, SnowplowEvidenceState::Stale) => {
                SnowplowEvidenceState::Stale
            }
            (Some(SnowplowEvidenceState::Revoked), _) | (_, SnowplowEvidenceState::Revoked) => {
                SnowplowEvidenceState::Revoked
            }
            (Some(SnowplowEvidenceState::AccessLoss), _)
            | (_, SnowplowEvidenceState::AccessLoss) => SnowplowEvidenceState::AccessLoss,
            (Some(SnowplowEvidenceState::Missing), _) | (_, SnowplowEvidenceState::Missing) => {
                SnowplowEvidenceState::Missing
            }
            (Some(SnowplowEvidenceState::ProviderUnknown), _)
            | (_, SnowplowEvidenceState::ProviderUnknown) => SnowplowEvidenceState::ProviderUnknown,
            _ => state,
        });
        self.diagnostics.push(diagnostic);
        self.partial = true;
    }
}

fn map_provider_error(error: SnowplowProviderError) -> SnowplowServiceError {
    match error {
        SnowplowProviderError::RegistrationRevoked => SnowplowServiceError::RegistrationRevoked,
        SnowplowProviderError::SecretRevoked => SnowplowServiceError::SecretRevoked,
        SnowplowProviderError::MissingPermission | SnowplowProviderError::ScopeMismatch => {
            SnowplowServiceError::ScopeMismatch
        }
        SnowplowProviderError::Model(error) => SnowplowServiceError::Model(error),
        _ => SnowplowServiceError::EvidenceMismatch,
    }
}

fn recording_digest(receipt: &SnowplowObservationReceipt) -> Digest {
    canonical_digest(&(
        "snowplow-recording/v1",
        &receipt.idempotency_key_digest,
        &receipt.proposal_digest,
        &receipt.evidence_digest,
        receipt.state,
        receipt.provenance,
        receipt.replayed,
    ))
}
