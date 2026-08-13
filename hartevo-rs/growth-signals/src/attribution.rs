//! Attribution-spine projection for the read-only growth signal seams.
//!
//! Provider rows are observations, not outcomes.  They are projected as
//! account-scoped impression events with explicit provenance and a durable
//! [`ProviderCursor`].  No provider payload is promoted to business truth here.

use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    AttributionError, ConnectorObservationSource, CorrectionLineage, ObservationOrigin,
    ObservationProvenance, ProviderCursor, ProviderEntityRef, ProviderEventIdentity,
    SourceEntityKind, SourceEvent, SourceEventId, SourceEventKind, SourceEventLinks,
    SourceObservationBatch,
};
use thiserror::Error;

use crate::common::{Freshness, ReadScope, canonical_digest};
use crate::dataforseo::{DataForSeoClient, DataForSeoSearchRequest, DataForSeoTransport};
use crate::google_ads::{GoogleAdsClient, GoogleAdsReadRequest, GoogleAdsTransport};
use crate::google_analytics::{
    AnalyticsReportRequest, GoogleAnalyticsClient, GoogleAnalyticsTransport,
};
use crate::search_console::{
    SearchConsoleClient, SearchConsoleQueryRequest, SearchConsoleTransport,
};

#[derive(Debug, Error)]
pub enum AttributionSourceError {
    #[error("provider read failed: {0}")]
    Provider(String),
    #[error(transparent)]
    Attribution(#[from] AttributionError),
}

impl AttributionSourceError {
    fn provider(error: impl fmt::Display) -> Self {
        Self::Provider(error.to_string())
    }
}

fn validate_cursor(
    cursor: Option<&ProviderCursor>,
    provider: &str,
    account_id: &str,
) -> Result<(), AttributionSourceError> {
    if cursor.is_some_and(|cursor| cursor.provider != provider || cursor.account_id != account_id) {
        return Err(AttributionError::CursorScopeMismatch.into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn impression_batch(
    scope: &ReadScope,
    provider: &str,
    account_id: &str,
    request_digest: &str,
    response_digest: &str,
    freshness: &Freshness,
    origin: ObservationOrigin,
    cursor_before: Option<&ProviderCursor>,
    external_ids: impl IntoIterator<Item = String>,
) -> Result<SourceObservationBatch, AttributionSourceError> {
    validate_cursor(cursor_before, provider, account_id)?;
    let sequence = cursor_before.map_or(1, |cursor| cursor.sequence.saturating_add(1));
    let cursor_after = ProviderCursor {
        provider: provider.to_owned(),
        account_id: account_id.to_owned(),
        sequence,
        token: format!("{request_digest}:{sequence}"),
        observed_through: freshness.observed_at(),
        ingested_at: freshness.observed_at(),
        batch_digest: response_digest.to_owned(),
    };
    let account =
        ProviderEntityRef::new(SourceEntityKind::Account, provider, account_id, account_id)?;
    let links = SourceEventLinks::new(account)?;
    let mut provenance =
        ObservationProvenance::new(origin, request_digest, freshness.observed_at())?;
    provenance.fresh_until = Some(freshness.valid_until());
    let events = external_ids
        .into_iter()
        .map(|external_id| {
            let identity = ProviderEventIdentity::new(provider, account_id, external_id.clone())?;
            let id = SourceEventId::from_stable(format!(
                "growth-signal:{provider}:{account_id}:{}",
                canonical_digest(&external_id)
            ));
            Ok(SourceEvent {
                id: id.clone(),
                tenant_id: scope.tenant_id().clone(),
                project_id: scope.project_id().clone(),
                mission_id: None,
                identity,
                kind: SourceEventKind::Impression,
                links: links.clone(),
                provider_occurred_at: freshness.observed_at(),
                observed_at: freshness.observed_at(),
                ingested_at: freshness.observed_at(),
                amount: None,
                fx_quote: None,
                provenance: provenance.clone(),
                lineage: CorrectionLineage::original(id),
                payload_digest: canonical_digest(&external_id),
            })
        })
        .collect::<Result<Vec<_>, AttributionError>>()?;
    let batch = SourceObservationBatch {
        tenant_id: scope.tenant_id().clone(),
        project_id: scope.project_id().clone(),
        mission_id: None,
        provider: provider.to_owned(),
        account_id: account_id.to_owned(),
        cursor_before: cursor_before.cloned(),
        cursor_after,
        events,
    };
    batch.validate()?;
    Ok(batch)
}

#[derive(Debug)]
pub struct DataForSeoAttributionSource<T: DataForSeoTransport> {
    client: DataForSeoClient<T>,
    request: DataForSeoSearchRequest,
    observed_at: DateTime<Utc>,
}

impl<T: DataForSeoTransport> DataForSeoAttributionSource<T> {
    pub fn new(
        client: DataForSeoClient<T>,
        request: DataForSeoSearchRequest,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            client,
            request,
            observed_at,
        }
    }

    pub fn client(&self) -> &DataForSeoClient<T> {
        &self.client
    }
}

impl<T: DataForSeoTransport> ConnectorObservationSource for DataForSeoAttributionSource<T> {
    type Error = AttributionSourceError;

    fn read_observations(
        &mut self,
        cursor: Option<&ProviderCursor>,
    ) -> Result<SourceObservationBatch, Self::Error> {
        let account_id = crate::dataforseo::dataforseo_scope(self.client.secret_reference())
            .map_err(AttributionSourceError::provider)?
            .account_id()
            .to_owned();
        let observation = self
            .client
            .read_live(&self.request, self.observed_at)
            .map_err(AttributionSourceError::provider)?;
        impression_batch(
            self.request.scope(),
            crate::dataforseo::DATAFORSEO_PROVIDER_ID,
            &account_id,
            observation.receipt_reference().request_digest(),
            observation.response_digest(),
            observation.freshness(),
            ObservationOrigin::Estimate,
            cursor,
            observation.items().iter().enumerate().map(|(index, item)| {
                item.url().map_or_else(
                    || format!("{}:{index}", self.request.keyword()),
                    str::to_owned,
                )
            }),
        )
    }
}

#[derive(Debug)]
pub struct GoogleAdsAttributionSource<T: GoogleAdsTransport> {
    client: GoogleAdsClient<T>,
    request: GoogleAdsReadRequest,
    observed_at: DateTime<Utc>,
}

impl<T: GoogleAdsTransport> GoogleAdsAttributionSource<T> {
    pub fn new(
        client: GoogleAdsClient<T>,
        request: GoogleAdsReadRequest,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            client,
            request,
            observed_at,
        }
    }
}

impl<T: GoogleAdsTransport> ConnectorObservationSource for GoogleAdsAttributionSource<T> {
    type Error = AttributionSourceError;

    fn read_observations(
        &mut self,
        cursor: Option<&ProviderCursor>,
    ) -> Result<SourceObservationBatch, Self::Error> {
        let account_id = self
            .client
            .auth()
            .oauth_access_reference()
            .scope()
            .account_id()
            .to_owned();
        let observation = self
            .client
            .read_gaql(&self.request, self.observed_at)
            .map_err(AttributionSourceError::provider)?;
        impression_batch(
            self.request.scope(),
            crate::google_ads::GOOGLE_ADS_PROVIDER_ID,
            &account_id,
            observation.request_digest(),
            observation.receipt_reference().response_digest(),
            observation.freshness(),
            ObservationOrigin::FirstParty,
            cursor,
            observation.rows().iter().enumerate().map(|(index, row)| {
                row.resource_name()
                    .map_or_else(|| format!("row:{index}"), str::to_owned)
            }),
        )
    }
}

#[derive(Debug)]
pub struct SearchConsoleAttributionSource<T: SearchConsoleTransport> {
    client: SearchConsoleClient<T>,
    request: SearchConsoleQueryRequest,
    observed_at: DateTime<Utc>,
}

impl<T: SearchConsoleTransport> SearchConsoleAttributionSource<T> {
    pub fn new(
        client: SearchConsoleClient<T>,
        request: SearchConsoleQueryRequest,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            client,
            request,
            observed_at,
        }
    }
}

impl<T: SearchConsoleTransport> ConnectorObservationSource for SearchConsoleAttributionSource<T> {
    type Error = AttributionSourceError;

    fn read_observations(
        &mut self,
        cursor: Option<&ProviderCursor>,
    ) -> Result<SourceObservationBatch, Self::Error> {
        let account_id = self.client.connector_scope().account_id().to_owned();
        let observation = self
            .client
            .query(&self.request, self.observed_at)
            .map_err(AttributionSourceError::provider)?;
        impression_batch(
            self.request.scope(),
            crate::search_console::GOOGLE_SEARCH_CONSOLE_PROVIDER_ID,
            &account_id,
            observation.receipt_reference().request_digest(),
            observation.receipt_reference().response_digest(),
            observation.freshness(),
            ObservationOrigin::FirstParty,
            cursor,
            observation
                .rows()
                .iter()
                .enumerate()
                .map(|(index, row)| format!("{}:{index}", row.keys().join("|"))),
        )
    }
}

#[derive(Debug)]
pub struct GoogleAnalyticsAttributionSource<T: GoogleAnalyticsTransport> {
    client: GoogleAnalyticsClient<T>,
    request: AnalyticsReportRequest,
    observed_at: DateTime<Utc>,
}

impl<T: GoogleAnalyticsTransport> GoogleAnalyticsAttributionSource<T> {
    pub fn new(
        client: GoogleAnalyticsClient<T>,
        request: AnalyticsReportRequest,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            client,
            request,
            observed_at,
        }
    }
}

impl<T: GoogleAnalyticsTransport> ConnectorObservationSource
    for GoogleAnalyticsAttributionSource<T>
{
    type Error = AttributionSourceError;

    fn read_observations(
        &mut self,
        cursor: Option<&ProviderCursor>,
    ) -> Result<SourceObservationBatch, Self::Error> {
        let account_id = self.client.connector_scope().account_id().to_owned();
        let observation = self
            .client
            .run_report(&self.request, self.observed_at)
            .map_err(AttributionSourceError::provider)?;
        impression_batch(
            self.request.scope(),
            crate::google_analytics::GOOGLE_ANALYTICS_PROVIDER_ID,
            &account_id,
            observation.receipt_reference().request_digest(),
            observation.receipt_reference().response_digest(),
            observation.freshness(),
            ObservationOrigin::FirstParty,
            cursor,
            observation
                .rows()
                .iter()
                .enumerate()
                .map(|(index, row)| format!("{}:{index}", row.dimension_values().join("|"))),
        )
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_connector_sdk::{ConnectorScope, SecretReference};
    use hartevo_domain_kernel::{ConnectorObservationSource, ProjectId, TenantId};
    use rust_decimal::Decimal;

    use super::*;
    use crate::common::{CalendarDateRange, LanguageCode, MarketCode, parse_date};
    use crate::dataforseo::{
        DataForSeoDevice, DataForSeoMode, DataForSeoWorldScenario, FakeDataForSeoTransport,
    };
    use crate::google_analytics::{
        AnalyticsFieldName, FakeGoogleAnalyticsTransport, GoogleAnalyticsAuthReference,
        GoogleAnalyticsPropertyId, GoogleAnalyticsWorldScenario,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 0, 0, 0)
            .single()
            .expect("time")
    }

    fn scope() -> ReadScope {
        ReadScope::new(
            TenantId::from("tenant-signal"),
            ProjectId::from("project-signal"),
            MarketCode::new("US").expect("market"),
            LanguageCode::new("en").expect("language"),
            CalendarDateRange::new(
                parse_date("2026-08-01").expect("date"),
                parse_date("2026-08-07").expect("date"),
            )
            .expect("window"),
        )
    }

    fn secret(provider: &str, account: &str, scope_name: &str) -> SecretReference {
        SecretReference::new(
            format!("secret-ref-{provider}"),
            ConnectorScope::new(
                "tenant-signal",
                "project-signal",
                provider,
                account,
                [scope_name.to_owned()],
            )
            .expect("connector scope"),
            1,
        )
        .expect("secret reference")
    }

    #[test]
    fn estimate_source_uses_attribution_cursor_without_a_second_billable_read() {
        let request = DataForSeoSearchRequest::new(
            scope(),
            "kaffee filter",
            2276,
            DataForSeoDevice::Desktop,
            10,
            DataForSeoMode::Live,
            Decimal::new(10, 2),
            Some(Decimal::new(20, 2)),
        )
        .expect("request");
        let client = DataForSeoClient::new(
            secret("dataforseo", "dataforseo-account", "serp.read"),
            FakeDataForSeoTransport::new(DataForSeoWorldScenario::Results),
        )
        .expect("client");
        let mut source = DataForSeoAttributionSource::new(client, request, now());
        let first = source.read_observations(None).expect("first batch");
        assert_eq!(first.cursor_after.sequence, 1);
        assert_eq!(first.events.len(), 1);
        assert_eq!(
            first.events[0].provenance.origin,
            ObservationOrigin::Estimate
        );

        let replay = source
            .read_observations(Some(&first.cursor_after))
            .expect("replay batch");
        assert_eq!(replay.cursor_after.sequence, 2);
        assert_eq!(replay.events[0].id, first.events[0].id);
        assert_eq!(source.client().replay_ledger().observation_count(), 1);
    }

    #[test]
    fn analytics_source_emits_first_party_account_events() {
        let request = AnalyticsReportRequest::new(
            scope(),
            GoogleAnalyticsPropertyId::new("123456789").expect("property"),
            vec![AnalyticsFieldName::new("date").expect("dimension")],
            vec![AnalyticsFieldName::new("activeUsers").expect("metric")],
            10,
            None,
        )
        .expect("request");
        let client = GoogleAnalyticsClient::new(
            GoogleAnalyticsAuthReference::new(secret(
                "google-analytics",
                "google-account",
                crate::google_analytics::GOOGLE_ANALYTICS_READONLY_SCOPE,
            ))
            .expect("auth"),
            FakeGoogleAnalyticsTransport::new(GoogleAnalyticsWorldScenario::Results),
        );
        let mut source = GoogleAnalyticsAttributionSource::new(client, request, now());
        let batch = source.read_observations(None).expect("batch");
        assert!(!batch.events.is_empty());
        assert_eq!(
            batch.events[0].provenance.origin,
            ObservationOrigin::FirstParty
        );
        assert!(batch.validate().is_ok());
    }
}
