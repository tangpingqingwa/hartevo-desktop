use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::Serialize;
use thiserror::Error;

use crate::{
    KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_JSON, KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_VERSION,
    KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_ID, KLAVIYO_CAMPAIGN_OUTCOME_SCHEMA_VERSION,
    KLAVIYO_CAMPAIGN_OUTCOME_SERVICE_ID,
    model::{
        AdoptionAvailability, AggregateValue, CostEvidence, DeliveryState, Digest, EvidenceDigests,
        KlaviyoRegistration, KlaviyoScope, MessageChannel, ModelError, ProviderErrorEvidence,
        ProviderErrorKind, RedactionEvidence, ReportKind, ReportPage, ReportRow, ResourceId,
        Revision, SecretReference, Statistic,
    },
    provider::{
        CampaignMetadataRequest, CampaignMetadataResponse, KlaviyoProviderDefinition,
        KlaviyoProviderPort, ProviderDefinitionError, ProviderProvenance, ReportRequest,
        TransportError,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AuthorityClassification {
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_native_receipt: bool,
    pub independent_write_readback: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
}

impl AuthorityClassification {
    pub const fn layer1() -> Self {
        Self {
            connected: false,
            native: false,
            first_party: false,
            durable_native_receipt: false,
            independent_write_readback: false,
            adopted_outcome: false,
            truth_authority: false,
        }
    }

    pub const fn connected(self) -> bool {
        self.connected
    }

    pub const fn native(self) -> bool {
        self.native
    }

    pub const fn first_party(self) -> bool {
        self.first_party
    }

    pub const fn truth(self) -> bool {
        self.truth_authority
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeProjection {
    Complete,
    NoData,
    Partial,
    Expired,
    ProviderUnknown,
}

impl OutcomeProjection {
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Partial)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RetryPolicyError {
    #[error("retry attempts must be between one and four")]
    InvalidAttempts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RetryPolicy {
    max_attempts: u8,
}

impl RetryPolicy {
    pub fn new(max_attempts: u8) -> Result<Self, RetryPolicyError> {
        if !(1..=crate::model::MAX_RETRIES).contains(&max_attempts) {
            Err(RetryPolicyError::InvalidAttempts)
        } else {
            Ok(Self { max_attempts })
        }
    }

    pub const fn max_attempts(self) -> u8 {
        self.max_attempts
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_attempts: 3 }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryEvidence {
    pub operation: String,
    pub attempt: u8,
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KlaviyoOutcomeRequest {
    pub report_kind: ReportKind,
    pub page_size: u16,
    pub max_pages: u8,
    pub scope_digest: Digest,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub account_revision: Revision,
    pub resource_revision: Revision,
    pub window_digest: Digest,
    pub metric_digest: Digest,
    pub variation_digest: Digest,
    pub request_digest: Digest,
}

impl KlaviyoOutcomeRequest {
    pub fn new(
        scope: &KlaviyoScope,
        report_kind: ReportKind,
        page_size: u16,
        max_pages: u8,
    ) -> Result<Self, ModelError> {
        scope.window.validate()?;
        if page_size == 0
            || page_size > crate::model::MAX_PAGE_SIZE
            || max_pages == 0
            || max_pages > crate::model::MAX_PAGES
        {
            return Err(ModelError::InvalidReport);
        }
        if report_kind == ReportKind::Series
            && scope
                .window
                .estimated_series_points()
                .is_some_and(|points| points > crate::model::MAX_SERIES_POINTS)
        {
            return Err(ModelError::InvalidSeriesResolution);
        }
        let mut request = Self {
            report_kind,
            page_size,
            max_pages,
            scope_digest: scope.scope_digest(),
            project_revision: scope.project_revision(),
            mission_revision: scope.mission_revision(),
            work_product_revision: scope.work_product_revision(),
            account_revision: scope.account_revision(),
            resource_revision: scope.resource_revision(),
            window_digest: scope.window.window_digest.clone(),
            metric_digest: scope.metrics.metric_digest.clone(),
            variation_digest: scope.variation.digest(),
            request_digest: Digest::from_text("uninitialized-outcome-request"),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    pub fn values(scope: &KlaviyoScope, page_size: u16, max_pages: u8) -> Result<Self, ModelError> {
        Self::new(scope, ReportKind::Values, page_size, max_pages)
    }

    pub fn series(scope: &KlaviyoScope, page_size: u16, max_pages: u8) -> Result<Self, ModelError> {
        Self::new(scope, ReportKind::Series, page_size, max_pages)
    }

    pub fn validate_against(&self, scope: &KlaviyoScope) -> Result<(), ModelError> {
        scope.validate()?;
        if self.scope_digest != scope.scope_digest()
            || self.project_revision != scope.project_revision()
            || self.mission_revision != scope.mission_revision()
            || self.work_product_revision != scope.work_product_revision()
            || self.account_revision != scope.account_revision()
            || self.resource_revision != scope.resource_revision()
            || self.window_digest != scope.window.window_digest
            || self.metric_digest != scope.metrics.metric_digest
            || self.variation_digest != scope.variation.digest()
            || self.page_size == 0
            || self.page_size > crate::model::MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > crate::model::MAX_PAGES
            || self.request_digest != self.compute_digest()
        {
            return Err(ModelError::DigestMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "klaviyo-outcome-request/v1",
            &[
                format!("{:?}", self.report_kind),
                self.page_size.to_string(),
                self.max_pages.to_string(),
                self.scope_digest.as_str().to_owned(),
                self.project_revision.get().to_string(),
                self.mission_revision.get().to_string(),
                self.work_product_revision.get().to_string(),
                self.account_revision.get().to_string(),
                self.resource_revision.get().to_string(),
                self.window_digest.as_str().to_owned(),
                self.metric_digest.as_str().to_owned(),
                self.variation_digest.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportWindowReceipt {
    pub report_kind: ReportKind,
    pub requested_window_digest: Digest,
    pub observed_window_digest: Digest,
    pub pages: u8,
    pub complete: bool,
    pub expired: bool,
    pub receipt_digest: Digest,
}

impl ReportWindowReceipt {
    fn new(
        report_kind: ReportKind,
        requested_window_digest: Digest,
        observed_window_digest: Digest,
        pages: u8,
        complete: bool,
        expired: bool,
    ) -> Self {
        let receipt_digest = Digest::from_fields(
            "klaviyo-window-receipt/v1",
            &[
                format!("{report_kind:?}"),
                requested_window_digest.as_str().to_owned(),
                observed_window_digest.as_str().to_owned(),
                pages.to_string(),
                complete.to_string(),
                expired.to_string(),
            ],
        );
        Self {
            report_kind,
            requested_window_digest,
            observed_window_digest,
            pages,
            complete,
            expired,
            receipt_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KlaviyoCampaignOutcomeEvidence {
    pub resource: ResourceId,
    pub delivery_state: DeliveryState,
    pub projection: OutcomeProjection,
    pub metrics: BTreeMap<Statistic, AggregateValue>,
    pub spend_minor_units: BTreeMap<crate::CurrencyCode, i64>,
    pub variation_digests: BTreeSet<Digest>,
    pub channels: BTreeSet<MessageChannel>,
    pub rows_observed: usize,
    pub pages_observed: u8,
    pub redaction: RedactionEvidence,
    pub window_receipt: ReportWindowReceipt,
    pub cost: CostEvidence,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub retries: Vec<RetryEvidence>,
    pub digests: EvidenceDigests,
    pub provider_provenance: ProviderProvenance,
    pub authority: AuthorityClassification,
    pub adoption: AdoptionAvailability,
}

impl KlaviyoCampaignOutcomeEvidence {
    pub fn metric(&self, statistic: Statistic) -> Option<&AggregateValue> {
        self.metrics.get(&statistic)
    }

    pub fn count(&self, statistic: Statistic) -> Option<u64> {
        self.metric(statistic).and_then(AggregateValue::as_count)
    }

    pub fn spend(&self, currency: &crate::CurrencyCode) -> Option<i64> {
        self.spend_minor_units.get(currency).copied()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KlaviyoCampaignOutcomeProposal {
    pub request: KlaviyoOutcomeRequest,
    pub projection: OutcomeProjection,
    pub evidence: KlaviyoCampaignOutcomeEvidence,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_definition_digest: Digest,
    pub proposal_digest: Digest,
}

impl KlaviyoCampaignOutcomeProposal {
    pub const fn status(&self) -> OutcomeProjection {
        self.projection
    }

    pub const fn is_adopted(&self) -> bool {
        false
    }

    pub const fn authority(&self) -> AuthorityClassification {
        self.evidence.authority
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KlaviyoServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub emits_outcome: bool,
}

impl KlaviyoServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: KLAVIYO_CAMPAIGN_OUTCOME_SCHEMA_VERSION.to_owned(),
            contract_version: KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_VERSION.to_owned(),
            service_id: KLAVIYO_CAMPAIGN_OUTCOME_SERVICE_ID.to_owned(),
            provider_id: KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_ID.to_owned(),
            contract_digest: Digest::from_text(KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_JSON),
            read_only: true,
            live_execution: false,
            emits_outcome: false,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum KlaviyoServiceError {
    #[error("Klaviyo registration is revoked")]
    RegistrationRevoked,
    #[error("Klaviyo SecretReference is revoked")]
    SecretRevoked,
    #[error("Klaviyo scope or SecretReference binding does not match")]
    ScopeMismatch,
    #[error("the outcome request does not match the exact registered scope")]
    RequestMismatch,
    #[error("provider definition is invalid")]
    ProviderDefinition(#[from] ProviderDefinitionError),
    #[error("provider evidence is tampered, stale, or outside the registered scope")]
    TamperedEvidence,
    #[error("provider returned a different account or campaign/flow")]
    ResourceMismatch,
    #[error("provider revision or permission fence changed")]
    FenceViolation,
    #[error("provider returned a different report, window, metric, or variation")]
    ReportMismatch,
    #[error("provider returned a repeated page cursor")]
    PageLoop,
    #[error("provider response exceeded the bounded Layer-1 evidence shape")]
    InvalidResponseShape,
    #[error("raw profile or message content crossed the redaction boundary")]
    RedactionViolation,
    #[error(transparent)]
    Model(#[from] ModelError),
}

pub struct KlaviyoCampaignOutcomeService<P> {
    scope: KlaviyoScope,
    secret_reference: SecretReference,
    provider: P,
    service_definition: KlaviyoServiceDefinition,
    registration: KlaviyoRegistration,
    retry_policy: RetryPolicy,
}

impl<P: KlaviyoProviderPort> fmt::Debug for KlaviyoCampaignOutcomeService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KlaviyoCampaignOutcomeService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .field("retry_policy", &self.retry_policy)
            .finish_non_exhaustive()
    }
}

impl<P: KlaviyoProviderPort> KlaviyoCampaignOutcomeService<P> {
    pub fn new(
        scope: KlaviyoScope,
        secret_reference: SecretReference,
        provider: P,
        retry_policy: RetryPolicy,
    ) -> Result<Self, KlaviyoServiceError> {
        scope.validate()?;
        if secret_reference.scope_digest() != scope.digest() {
            return Err(KlaviyoServiceError::ScopeMismatch);
        }
        if secret_reference.is_revoked() {
            return Err(KlaviyoServiceError::SecretRevoked);
        }
        let service_definition = KlaviyoServiceDefinition::layer1();
        let provider_definition = provider.definition();
        provider_definition.validate()?;
        if provider_definition.api_revision != scope.api_revision
            || provider_definition.provenance.connected()
            || provider_definition.provenance.is_native()
            || provider_definition.provenance.first_party()
        {
            return Err(KlaviyoServiceError::ScopeMismatch);
        }
        let registration = KlaviyoRegistration::new(
            provider_definition.provider_digest(),
            provider_definition.implementation_digest.clone(),
            scope.scope_digest(),
            scope.permission_digest().clone(),
            secret_reference.reference_digest().clone(),
            Revision::new(1)?,
            service_definition.contract_digest.clone(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            service_definition,
            registration,
            retry_policy,
        })
    }

    pub fn service_definition(&self) -> &KlaviyoServiceDefinition {
        &self.service_definition
    }

    pub fn provider_definition(&self) -> &KlaviyoProviderDefinition {
        self.provider.definition()
    }

    pub fn registration(&self) -> &KlaviyoRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &KlaviyoScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<crate::RegistrationRevocation, KlaviyoServiceError> {
        self.registration
            .revoke()
            .map_err(KlaviyoServiceError::from)
    }

    pub fn unmount(&mut self) -> Result<crate::RegistrationRevocation, KlaviyoServiceError> {
        self.revoke_registration()
    }

    pub fn revoke_secret(&mut self) -> Result<(), KlaviyoServiceError> {
        self.secret_reference
            .revoke()
            .map_err(KlaviyoServiceError::from)
    }

    pub fn propose(
        &mut self,
        request: KlaviyoOutcomeRequest,
    ) -> Result<KlaviyoCampaignOutcomeProposal, KlaviyoServiceError> {
        self.registration
            .ensure_active()
            .map_err(|_| KlaviyoServiceError::RegistrationRevoked)?;
        if self.secret_reference.is_revoked() {
            return Err(KlaviyoServiceError::SecretRevoked);
        }
        if self.secret_reference.kind() != self.scope.permission_snapshot.auth_kind {
            return Err(KlaviyoServiceError::ScopeMismatch);
        }
        request
            .validate_against(&self.scope)
            .map_err(|_| KlaviyoServiceError::RequestMismatch)?;
        self.provider.definition().validate()?;
        if self.provider.definition().provider_digest() != self.registration.provider_digest
            || self.provider.definition().implementation_digest
                != self.registration.implementation_digest
        {
            return Err(KlaviyoServiceError::TamperedEvidence);
        }

        let mut accumulator = EvidenceAccumulator::new(
            &self.scope,
            &request,
            self.provider.provenance(),
            self.retry_policy,
            self.provider.definition().provider_digest(),
            self.provider.definition().implementation_digest.clone(),
            self.service_definition.contract_digest.clone(),
        );
        let metadata_request =
            CampaignMetadataRequest::from_scope(&self.scope, &self.secret_reference);
        let Ok(metadata) = self.read_metadata_with_retry(&metadata_request, &mut accumulator)
        else {
            let projection = accumulator.provider_errors.last().map_or(
                OutcomeProjection::ProviderUnknown,
                |error| match error.kind {
                    ProviderErrorKind::NotFound404 | ProviderErrorKind::Conflict409 => {
                        OutcomeProjection::NoData
                    }
                    _ => OutcomeProjection::ProviderUnknown,
                },
            );
            return Ok(self.finish_proposal(
                request,
                projection,
                accumulator.finish(projection, None),
            ));
        };
        Self::validate_metadata(&self.scope, &metadata)?;
        accumulator.metadata_digest = metadata.metadata.metadata_digest.clone();
        accumulator.delivery_state = metadata.metadata.state;
        accumulator.redaction = metadata.redaction.clone();

        let mut report_request = ReportRequest::from_scope(
            &self.scope,
            &self.secret_reference,
            request.report_kind,
            request.page_size,
            request.max_pages,
        )?;
        report_request.validate()?;
        accumulator.report_digest = report_request.report_digest().clone();
        let mut seen_cursors = BTreeSet::new();
        let mut last_page: Option<ReportPage> = None;
        let projection = loop {
            let page = match self.query_report_with_retry(&report_request, &mut accumulator) {
                Ok(page) => page,
                Err(error) => {
                    break if accumulator.rows.is_empty() {
                        projection_for_transport_error(&error)
                    } else {
                        OutcomeProjection::Partial
                    };
                }
            };
            Self::validate_page(&self.scope, &report_request, &page)?;
            accumulator.add_page(&page)?;
            last_page = Some(page.clone());
            if page.expired {
                break OutcomeProjection::Expired;
            }
            if page.no_data && accumulator.rows.is_empty() {
                break OutcomeProjection::NoData;
            }
            let Some(cursor) = page.next_cursor_digest() else {
                break if page.complete {
                    OutcomeProjection::Complete
                } else {
                    OutcomeProjection::Partial
                };
            };
            if !seen_cursors.insert(cursor.clone()) {
                return Err(KlaviyoServiceError::PageLoop);
            }
            if report_request.page_number() >= request.max_pages {
                break OutcomeProjection::Partial;
            }
            report_request =
                report_request.next_page(report_request.page_number().saturating_add(1), cursor);
        };

        let projection = if projection == OutcomeProjection::Complete && accumulator.rows.is_empty()
        {
            OutcomeProjection::NoData
        } else {
            projection
        };
        let evidence = accumulator.finish(projection, last_page.as_ref());
        Ok(self.finish_proposal(request, projection, evidence))
    }

    fn finish_proposal(
        &self,
        request: KlaviyoOutcomeRequest,
        projection: OutcomeProjection,
        evidence: KlaviyoCampaignOutcomeEvidence,
    ) -> KlaviyoCampaignOutcomeProposal {
        let provider_definition_digest = self.provider.definition().provider_digest();
        let proposal_digest = Digest::from_fields(
            "klaviyo-campaign-outcome-proposal/v1",
            &[
                self.registration.registration_digest.as_str().to_owned(),
                self.registration.registration_revision.get().to_string(),
                provider_definition_digest.as_str().to_owned(),
                request.request_digest.as_str().to_owned(),
                format!("{projection:?}"),
                evidence.digests.result_digest.as_str().to_owned(),
            ],
        );
        KlaviyoCampaignOutcomeProposal {
            request,
            projection,
            evidence,
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.registration_revision,
            provider_definition_digest,
            proposal_digest,
        }
    }

    fn read_metadata_with_retry(
        &mut self,
        request: &CampaignMetadataRequest,
        accumulator: &mut EvidenceAccumulator,
    ) -> Result<CampaignMetadataResponse, TransportError> {
        for attempt in 1..=self.retry_policy.max_attempts() {
            match self.provider.read_campaign_or_flow_metadata(request) {
                Ok(response) => return Ok(response),
                Err(error) if error.retryable && attempt < self.retry_policy.max_attempts() => {
                    accumulator.record_retry("campaigns.get", attempt, &error);
                }
                Err(error) => {
                    accumulator.record_provider_error(&error, attempt);
                    return Err(error);
                }
            }
        }
        unreachable!("bounded metadata retry loop always returns")
    }

    fn query_report_with_retry(
        &mut self,
        request: &ReportRequest,
        accumulator: &mut EvidenceAccumulator,
    ) -> Result<ReportPage, TransportError> {
        for attempt in 1..=self.retry_policy.max_attempts() {
            let response = match request.report_kind {
                ReportKind::Values => self.provider.query_values(request),
                ReportKind::Series => self.provider.query_series(request),
            };
            match response {
                Ok(response) => return Ok(response),
                Err(error) if error.retryable && attempt < self.retry_policy.max_attempts() => {
                    accumulator.record_retry("reports.query", attempt, &error);
                }
                Err(error) => {
                    accumulator.record_provider_error(&error, attempt);
                    return Err(error);
                }
            }
        }
        unreachable!("bounded report retry loop always returns")
    }

    fn validate_metadata(
        scope: &KlaviyoScope,
        response: &CampaignMetadataResponse,
    ) -> Result<(), KlaviyoServiceError> {
        match response.validate() {
            Ok(()) => {}
            Err(ModelError::RawProfileOrContent) => {
                return Err(KlaviyoServiceError::RedactionViolation);
            }
            Err(_) => return Err(KlaviyoServiceError::TamperedEvidence),
        }
        if response.account_id != scope.account_id || response.metadata.resource != scope.resource {
            return Err(KlaviyoServiceError::ResourceMismatch);
        }
        if response.observed_fence != scope.fence()
            || response.metadata.resource_revision != scope.resource_revision()
        {
            return Err(KlaviyoServiceError::FenceViolation);
        }
        response
            .redaction
            .validate()
            .map_err(|_| KlaviyoServiceError::RedactionViolation)?;
        Ok(())
    }

    fn validate_page(
        scope: &KlaviyoScope,
        request: &ReportRequest,
        page: &ReportPage,
    ) -> Result<(), KlaviyoServiceError> {
        match page.validate() {
            Ok(()) => {}
            Err(ModelError::RawProfileOrContent) => {
                return Err(KlaviyoServiceError::RedactionViolation);
            }
            Err(_) => return Err(KlaviyoServiceError::TamperedEvidence),
        }
        if page.account_id != scope.account_id || page.resource != scope.resource {
            return Err(KlaviyoServiceError::ResourceMismatch);
        }
        if page.report_kind != request.report_kind
            || page.report_digest != *request.report_digest()
            || page.page_number != request.page_number()
            || page.observed_window_digest != scope.window.window_digest
            || page.observed_metric_digest != scope.metrics.metric_digest
            || page.observed_variation_digest != scope.variation.digest()
        {
            return Err(KlaviyoServiceError::ReportMismatch);
        }
        if page.observed_fence != request.observed_fence
            || page.cost.window_digest != scope.window.window_digest
        {
            return Err(KlaviyoServiceError::FenceViolation);
        }
        page.redaction
            .validate()
            .map_err(|_| KlaviyoServiceError::RedactionViolation)?;
        if page.rows.len() > request.page_size as usize {
            return Err(KlaviyoServiceError::InvalidResponseShape);
        }
        for row in &page.rows {
            Self::validate_row(scope, row)?;
        }
        Ok(())
    }

    fn validate_row(scope: &KlaviyoScope, row: &ReportRow) -> Result<(), KlaviyoServiceError> {
        if row
            .statistics
            .keys()
            .any(|statistic| !scope.metrics.contains(*statistic))
        {
            return Err(KlaviyoServiceError::ReportMismatch);
        }
        if let crate::VariationSelector::Id(expected) = &scope.variation
            && row.variation_digest.as_ref() != Some(expected)
        {
            return Err(KlaviyoServiceError::ReportMismatch);
        }
        Ok(())
    }
}

fn projection_for_transport_error(error: &TransportError) -> OutcomeProjection {
    match error.kind {
        ProviderErrorKind::NotFound404 | ProviderErrorKind::Conflict409 => {
            OutcomeProjection::NoData
        }
        ProviderErrorKind::Unauthorized401
        | ProviderErrorKind::Forbidden403
        | ProviderErrorKind::RateLimited429
        | ProviderErrorKind::Server5xx
        | ProviderErrorKind::Timeout
        | ProviderErrorKind::BlockedEnv
        | ProviderErrorKind::InvalidResponse
        | ProviderErrorKind::Unknown => OutcomeProjection::ProviderUnknown,
    }
}

struct EvidenceAccumulator {
    resource: ResourceId,
    request: KlaviyoOutcomeRequest,
    provenance: ProviderProvenance,
    provider_digest: Digest,
    implementation_digest: Digest,
    contract_digest: Digest,
    permission_digest: Digest,
    metadata_digest: Digest,
    report_digest: Digest,
    delivery_state: DeliveryState,
    rows: Vec<ReportRow>,
    pages: u8,
    total_request_units: u32,
    total_response_units: u32,
    rate_limit_per_minute: Option<u16>,
    redaction: RedactionEvidence,
    provider_errors: Vec<ProviderErrorEvidence>,
    retries: Vec<RetryEvidence>,
}

impl EvidenceAccumulator {
    fn new(
        scope: &KlaviyoScope,
        request: &KlaviyoOutcomeRequest,
        provenance: ProviderProvenance,
        _retry_policy: RetryPolicy,
        provider_digest: Digest,
        implementation_digest: Digest,
        contract_digest: Digest,
    ) -> Self {
        Self {
            resource: scope.resource.clone(),
            request: request.clone(),
            provenance,
            provider_digest,
            implementation_digest,
            contract_digest,
            permission_digest: scope.permission_digest().clone(),
            metadata_digest: Digest::from_text("metadata-absent"),
            report_digest: request.request_digest.clone(),
            delivery_state: DeliveryState::Unknown,
            rows: Vec::new(),
            pages: 0,
            total_request_units: 0,
            total_response_units: 0,
            rate_limit_per_minute: None,
            redaction: RedactionEvidence::clean(),
            provider_errors: Vec::new(),
            retries: Vec::new(),
        }
    }

    fn record_retry(&mut self, operation: &str, attempt: u8, error: &TransportError) {
        self.retries.push(RetryEvidence {
            operation: operation.to_owned(),
            attempt,
            kind: error.kind,
            status_code: error.status_code,
            error_digest: error.diagnostic_digest().clone(),
        });
    }

    fn record_provider_error(&mut self, error: &TransportError, attempt: u8) {
        if self.provider_errors.len() < crate::model::MAX_ERRORS {
            self.provider_errors.push(ProviderErrorEvidence::new(
                error.kind,
                error.status_code,
                error.retryable,
                attempt,
                error.blocked_env,
                error.diagnostic_digest(),
            ));
        }
    }

    fn add_page(&mut self, page: &ReportPage) -> Result<(), KlaviyoServiceError> {
        self.pages = self.pages.saturating_add(1);
        if self.pages > self.request.max_pages {
            return Err(KlaviyoServiceError::InvalidResponseShape);
        }
        if self.rows.len().saturating_add(page.rows.len())
            > self.request.max_pages as usize * self.request.page_size as usize
        {
            return Err(KlaviyoServiceError::InvalidResponseShape);
        }
        if self.request.report_kind == ReportKind::Series
            && self.rows.len().saturating_add(page.rows.len()) > crate::model::MAX_SERIES_POINTS
        {
            return Err(KlaviyoServiceError::InvalidResponseShape);
        }
        let request_units = self
            .total_request_units
            .saturating_add(page.cost.request_units);
        let response_units = self
            .total_response_units
            .saturating_add(page.cost.response_units);
        if request_units > crate::model::MAX_COST_UNITS
            || response_units > crate::model::MAX_COST_UNITS
        {
            return Err(KlaviyoServiceError::InvalidResponseShape);
        }
        self.rows.extend(page.rows.iter().cloned());
        self.total_request_units = request_units;
        self.total_response_units = response_units;
        self.rate_limit_per_minute = page
            .cost
            .rate_limit_per_minute
            .or(self.rate_limit_per_minute);
        self.redaction.profile_fields_redacted = self
            .redaction
            .profile_fields_redacted
            .saturating_add(page.redaction.profile_fields_redacted);
        self.redaction.content_fields_redacted = self
            .redaction
            .content_fields_redacted
            .saturating_add(page.redaction.content_fields_redacted);
        self.redaction.redaction_digest = RedactionEvidence::new(
            self.redaction.profile_fields_redacted,
            self.redaction.content_fields_redacted,
        )
        .redaction_digest;
        Ok(())
    }

    fn finish(
        self,
        projection: OutcomeProjection,
        last_page: Option<&ReportPage>,
    ) -> KlaviyoCampaignOutcomeEvidence {
        let mut metrics: BTreeMap<Statistic, AggregateValue> = BTreeMap::new();
        let mut spend_minor_units: BTreeMap<crate::CurrencyCode, i64> = BTreeMap::new();
        let mut variation_digests = BTreeSet::new();
        let mut channels = BTreeSet::new();
        for row in &self.rows {
            if let Some(variation) = &row.variation_digest {
                variation_digests.insert(variation.clone());
            }
            if let Some(channel) = &row.channel {
                channels.insert(channel.clone());
            }
            for (statistic, value) in &row.statistics {
                match metrics.get(statistic) {
                    Some(existing) => {
                        if let Ok(combined) = existing.combine(value) {
                            metrics.insert(*statistic, combined);
                        }
                    }
                    None => {
                        metrics.insert(*statistic, value.clone());
                    }
                }
                if statistic.is_spend()
                    && let Some((minor_units, currency)) = value.as_money()
                {
                    let entry = spend_minor_units.entry(currency.clone()).or_insert(0);
                    *entry = (*entry).saturating_add(minor_units);
                }
            }
        }
        let last_page = last_page.cloned();
        let observed_window_digest = last_page.as_ref().map_or_else(
            || self.request.window_digest.clone(),
            |page| page.observed_window_digest.clone(),
        );
        let expired = last_page.as_ref().is_some_and(|page| page.expired);
        let complete = matches!(
            projection,
            OutcomeProjection::Complete | OutcomeProjection::NoData
        );
        let cost = CostEvidence::new(
            self.total_request_units.max(1),
            self.total_response_units.min(crate::model::MAX_COST_UNITS),
            self.pages.max(1),
            self.rate_limit_per_minute,
            self.request.window_digest.clone(),
        )
        .expect("accumulator keeps bounded cost evidence");
        let redaction = RedactionEvidence::new(
            self.redaction.profile_fields_redacted,
            self.redaction.content_fields_redacted,
        );
        let window_receipt = ReportWindowReceipt::new(
            self.request.report_kind,
            self.request.window_digest.clone(),
            observed_window_digest,
            self.pages.max(1),
            complete,
            expired,
        );
        let metadata_digest = self.metadata_digest;
        let report_digest = self.report_digest;
        let result_digest = Digest::from_fields(
            "klaviyo-campaign-outcome-evidence/v1",
            &[
                self.resource.kind().label().to_owned(),
                self.resource.id().to_owned(),
                format!("{projection:?}"),
                serde_json::to_string(&metrics).expect("aggregate metrics serialize"),
                serde_json::to_string(&spend_minor_units).expect("spend aggregates serialize"),
                metadata_digest.as_str().to_owned(),
                self.request.scope_digest.as_str().to_owned(),
                self.request.window_digest.as_str().to_owned(),
                self.request.metric_digest.as_str().to_owned(),
                cost.cost_digest.as_str().to_owned(),
                window_receipt.receipt_digest.as_str().to_owned(),
                self.provider_errors
                    .iter()
                    .map(|error| error.error_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                self.retries
                    .iter()
                    .map(|retry| retry.error_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        );
        let digests = EvidenceDigests {
            metadata_digest,
            query_digest: self.request.request_digest.clone(),
            report_digest,
            window_digest: self.request.window_digest.clone(),
            metric_digest: self.request.metric_digest.clone(),
            cost_digest: cost.cost_digest.clone(),
            permission_digest: self.permission_digest,
            scope_digest: self.request.scope_digest.clone(),
            provider_digest: self.provider_digest,
            implementation_digest: self.implementation_digest,
            contract_digest: self.contract_digest,
            result_digest,
        };
        KlaviyoCampaignOutcomeEvidence {
            resource: self.resource,
            delivery_state: self.delivery_state,
            projection,
            metrics,
            spend_minor_units,
            variation_digests,
            channels,
            rows_observed: self.rows.len(),
            pages_observed: self.pages,
            redaction,
            window_receipt,
            cost,
            provider_errors: self.provider_errors,
            retries: self.retries,
            digests,
            provider_provenance: self.provenance,
            authority: AuthorityClassification::layer1(),
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        }
    }
}
