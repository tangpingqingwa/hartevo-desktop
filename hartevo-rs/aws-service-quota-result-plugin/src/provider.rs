//! Bounded, read-only AWS Service Quotas provider and non-native transports.
//!
//! There is intentionally no signer, credential resolver, HTTP client, write
//! operation, quota-template type, support-case type, or raw provider-payload
//! return path in this module. A transport returns already-normalised pages;
//! JSON parsing reduces provider values to digests before constructing one.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
};

use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::{
    AWS_SERVICE_QUOTA_API_REVISION, AWS_SERVICE_QUOTA_PROVIDER_ID,
    AWS_SERVICE_QUOTA_PROVIDER_VERSION,
    model::{
        AwsServiceQuotaOperation, AwsServiceQuotaReadPage, AwsServiceQuotaReadRequest, Digest,
        ModelError, OpaqueCursor, ProviderErrorEvidence, ProviderId, ProviderRevision,
        QuotaPostureDigest, ServiceQuotaIdentity, TransportError, TransportErrorKind,
        TransportProvenance,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("AWS Service Quotas provider definition is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("AWS Service Quotas provider revision is incompatible")]
    RevisionMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsServiceQuotaProviderIdentity {
    pub provider_id: ProviderId,
    pub version: String,
    pub api_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub provenance: TransportProvenance,
}

impl AwsServiceQuotaProviderIdentity {
    pub fn for_provenance(
        provenance: TransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_id = ProviderId::new(AWS_SERVICE_QUOTA_PROVIDER_ID)?;
        let api_revision = ProviderRevision::new(AWS_SERVICE_QUOTA_API_REVISION)?;
        let provider_digest = Digest::from_parts(
            "hartevo-aws-service-quota-provider/v1",
            &[
                provider_id.as_str().to_owned(),
                AWS_SERVICE_QUOTA_PROVIDER_VERSION.to_owned(),
                api_revision.as_str().to_owned(),
                provenance.as_str().to_owned(),
            ],
        );
        let api_digest = Digest::from_parts(
            "hartevo-aws-service-quota-api-allowlist/v1",
            &[
                "POST".to_owned(),
                "2019-06-24".to_owned(),
                "ListServiceQuotas".to_owned(),
                "GetServiceQuota".to_owned(),
                "GetAWSDefaultServiceQuota".to_owned(),
                "ListRequestedServiceQuotaChangeHistoryByQuota".to_owned(),
            ],
        );
        Ok(Self {
            provider_id,
            version: AWS_SERVICE_QUOTA_PROVIDER_VERSION.to_owned(),
            api_revision,
            provider_digest,
            api_digest,
            provenance,
        })
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsServiceQuotaProviderError {
    #[error("AWS Service Quotas provider request is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("AWS Service Quotas provider transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("AWS Service Quotas provider page binding or digest is invalid")]
    PageBinding,
    #[error("AWS Service Quotas provider revision is incompatible")]
    ProviderRevision,
    #[error("AWS Service Quotas transport provenance is not the provider provenance")]
    ProvenanceMismatch,
}

/// Layer-1 transports are fixture, recording, loopback, or BLOCKED_ENV only.
pub trait AwsServiceQuotaTransport: Send {
    fn provenance(&self) -> TransportProvenance;

    fn read(
        &mut self,
        request: &AwsServiceQuotaReadRequest,
    ) -> Result<AwsServiceQuotaReadPage, TransportError>;
}

#[derive(Clone)]
pub struct AwsServiceQuotaProvider<T> {
    transport: T,
    identity: AwsServiceQuotaProviderIdentity,
}

impl<T> fmt::Debug for AwsServiceQuotaProvider<T>
where
    T: AwsServiceQuotaTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsServiceQuotaProvider")
            .field("provider_id", &self.identity.provider_id)
            .field("version", &self.identity.version)
            .field("api_revision", &self.identity.api_revision)
            .field("provider_digest", &self.identity.provider_digest)
            .field("api_digest", &self.identity.api_digest)
            .field("provenance", &self.identity.provenance)
            .finish_non_exhaustive()
    }
}

impl<T> AwsServiceQuotaProvider<T>
where
    T: AwsServiceQuotaTransport,
{
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let identity = AwsServiceQuotaProviderIdentity::for_provenance(transport.provenance())?;
        Ok(Self {
            transport,
            identity,
        })
    }

    pub fn identity(&self) -> &AwsServiceQuotaProviderIdentity {
        &self.identity
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.identity.provenance
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    pub fn read(
        &mut self,
        request: &AwsServiceQuotaReadRequest,
    ) -> Result<AwsServiceQuotaReadPage, AwsServiceQuotaProviderError> {
        let page = self.transport.read(request)?;
        if page.provenance != self.identity.provenance
            || page.connected
            || page.native
            || page.first_party
            || page.provider_receipt
        {
            return Err(AwsServiceQuotaProviderError::ProvenanceMismatch);
        }
        page.validate_integrity(request)
            .map_err(|_| AwsServiceQuotaProviderError::PageBinding)?;
        if page.provider_revision != self.identity.api_revision {
            return Err(AwsServiceQuotaProviderError::ProviderRevision);
        }
        Ok(page)
    }

    /// Parse an already-bounded AWS JSON response. Only digest components and
    /// bounded timestamps/revisions are retained in the returned page.
    pub fn parse_json_page(
        request: &AwsServiceQuotaReadRequest,
        page_number: u16,
        status_code: u16,
        body: &[u8],
        provider_revision: ProviderRevision,
    ) -> Result<AwsServiceQuotaReadPage, AwsServiceQuotaProviderError> {
        Self::parse_json_page_with_usage_revision(
            request,
            page_number,
            status_code,
            body,
            provider_revision,
            None,
        )
    }

    pub fn parse_json_page_with_usage_revision(
        request: &AwsServiceQuotaReadRequest,
        page_number: u16,
        status_code: u16,
        body: &[u8],
        provider_revision: ProviderRevision,
        usage_revision: Option<u64>,
    ) -> Result<AwsServiceQuotaReadPage, AwsServiceQuotaProviderError> {
        if page_number != request.page_number {
            return Err(AwsServiceQuotaProviderError::PageBinding);
        }
        if status_code != 200 {
            return Err(AwsServiceQuotaProviderError::Transport(
                transport_error_for_status(status_code),
            ));
        }
        if body.is_empty() || body.len() > request.max_response_bytes {
            return Err(AwsServiceQuotaProviderError::Model(ModelError::Invalid {
                field: "provider response bytes",
            }));
        }
        let value = serde_json::from_slice::<Value>(body)
            .map_err(|_| AwsServiceQuotaProviderError::Transport(TransportError::malformed()))?;
        let next_cursor = value
            .get("NextToken")
            .and_then(Value::as_str)
            .map(|token| {
                OpaqueCursor::new(
                    token,
                    &request.filter_digest,
                    request.page_number.saturating_add(1),
                )
            })
            .transpose()?;
        let observations = match request.operation {
            AwsServiceQuotaOperation::ListServiceQuotas => {
                let items = value
                    .get("Quotas")
                    .or_else(|| value.get("quotas"))
                    .and_then(Value::as_array)
                    .ok_or(AwsServiceQuotaProviderError::Transport(
                        TransportError::malformed(),
                    ))?;
                items
                    .iter()
                    .map(|item| {
                        parse_quota_observation(
                            request,
                            item,
                            usage_revision,
                            None,
                            request.operation,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?
            }
            AwsServiceQuotaOperation::GetServiceQuota
            | AwsServiceQuotaOperation::GetAWSDefaultServiceQuota => {
                let item = value.get("Quota").or_else(|| value.get("quota")).ok_or(
                    AwsServiceQuotaProviderError::Transport(TransportError::malformed()),
                )?;
                vec![parse_quota_observation(
                    request,
                    item,
                    usage_revision,
                    None,
                    request.operation,
                )?]
            }
            AwsServiceQuotaOperation::ListRequestedServiceQuotaChangeHistoryByQuota => {
                parse_history_observations(request, &value, usage_revision)?
            }
        };
        AwsServiceQuotaReadPage::new_with_provider_revision(
            request,
            observations,
            next_cursor,
            body.len(),
            TransportProvenance::Recording,
            provider_revision,
        )
        .map_err(AwsServiceQuotaProviderError::Model)
    }
}

impl Default for AwsServiceQuotaProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked AWS Service Quotas provider definition")
    }
}

fn transport_error_for_status(status_code: u16) -> TransportError {
    let kind = match status_code {
        400 => TransportErrorKind::BadRequest,
        401 => TransportErrorKind::Unauthorized,
        403 => TransportErrorKind::Forbidden,
        404 => TransportErrorKind::NotFound,
        409 => TransportErrorKind::Conflict,
        429 => TransportErrorKind::RateLimited,
        500..=599 => TransportErrorKind::ServerFailure,
        _ => TransportErrorKind::Unknown,
    };
    TransportError::new(kind)
}

fn required_string<'a>(
    value: &'a Value,
    field: &'static str,
) -> Result<&'a str, AwsServiceQuotaProviderError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(AwsServiceQuotaProviderError::Transport(
            TransportError::malformed(),
        ))
}

fn string_or<'a>(value: &'a Value, field: &str, fallback: &'a str) -> &'a str {
    value.get(field).and_then(Value::as_str).unwrap_or(fallback)
}

fn parse_revision(
    value: &Value,
    field: &'static str,
    fallback: Option<u64>,
) -> Result<crate::Revision, AwsServiceQuotaProviderError> {
    let revision = value
        .get(field)
        .and_then(Value::as_u64)
        .or(fallback)
        .unwrap_or(1);
    crate::Revision::new(revision).map_err(AwsServiceQuotaProviderError::Model)
}

fn parse_timestamp(
    value: &Value,
    field: &'static str,
    fallback: DateTime<Utc>,
) -> Result<DateTime<Utc>, AwsServiceQuotaProviderError> {
    let Some(value) = value.get(field) else {
        return Ok(fallback);
    };
    if let Some(text) = value.as_str() {
        return DateTime::parse_from_rfc3339(text)
            .map(|timestamp| timestamp.with_timezone(&Utc))
            .map_err(|_| AwsServiceQuotaProviderError::Transport(TransportError::malformed()));
    }
    let Some(seconds) = value.as_f64() else {
        return Err(AwsServiceQuotaProviderError::Transport(
            TransportError::malformed(),
        ));
    };
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(AwsServiceQuotaProviderError::Transport(
            TransportError::malformed(),
        ));
    }
    let whole_seconds = seconds.trunc() as i64;
    let nanos = ((seconds.fract()) * 1_000_000_000.0).round() as u32;
    Utc.timestamp_opt(whole_seconds, nanos)
        .single()
        .ok_or(AwsServiceQuotaProviderError::Transport(
            TransportError::malformed(),
        ))
}

fn value_digest(
    value: Option<&Value>,
    field: &'static str,
) -> Result<Option<Digest>, AwsServiceQuotaProviderError> {
    value
        .map(|value| {
            serde_json::to_vec(value)
                .map(|bytes| {
                    Digest::from_parts(
                        "hartevo-aws-service-quota-component/v1",
                        &[
                            field.to_owned(),
                            String::from_utf8_lossy(&bytes).into_owned(),
                        ],
                    )
                })
                .map_err(|_| AwsServiceQuotaProviderError::Transport(TransportError::malformed()))
        })
        .transpose()
}

fn required_bool_digest(
    value: &Value,
    field: &'static str,
) -> Result<Digest, AwsServiceQuotaProviderError> {
    let value = value.get(field).and_then(Value::as_bool).ok_or(
        AwsServiceQuotaProviderError::Transport(TransportError::malformed()),
    )?;
    Ok(Digest::from_text(format!("{field}={value}")))
}

fn parse_quota_observation(
    request: &AwsServiceQuotaReadRequest,
    value: &Value,
    usage_revision_override: Option<u64>,
    history_digest: Option<Digest>,
    operation: AwsServiceQuotaOperation,
) -> Result<QuotaPostureDigest, AwsServiceQuotaProviderError> {
    let fallback_quota = request.quota.as_ref();
    let service_code = string_or(
        value,
        "ServiceCode",
        fallback_quota.map_or(request.service_code.as_str(), |quota| {
            quota.service_code.as_str()
        }),
    );
    let quota_code = value
        .get("QuotaCode")
        .and_then(Value::as_str)
        .or_else(|| fallback_quota.map(|quota| quota.quota_code.as_str()))
        .ok_or(AwsServiceQuotaProviderError::Transport(
            TransportError::malformed(),
        ))?;
    let identity = ServiceQuotaIdentity::new(service_code, quota_code)
        .map_err(AwsServiceQuotaProviderError::Model)?;
    if identity.service_code != request.service_code
        || !request
            .allowed_quota_digests
            .iter()
            .any(|digest| digest == &identity.digest())
    {
        return Err(AwsServiceQuotaProviderError::Model(
            ModelError::ScopeMismatch {
                field: "provider quota identity",
            },
        ));
    }
    if let Some(quota) = fallback_quota
        && quota != &identity
    {
        return Err(AwsServiceQuotaProviderError::Model(
            ModelError::ScopeMismatch {
                field: "provider quota selector",
            },
        ));
    }
    let unit = required_string(value, "Unit")?;
    let unit_digest = Digest::from_text(unit);
    let applied_value_digest = if matches!(
        operation,
        AwsServiceQuotaOperation::ListServiceQuotas | AwsServiceQuotaOperation::GetServiceQuota
    ) {
        value_digest(value.get("Value"), "applied_value")?
    } else {
        None
    };
    let default_value_digest = if matches!(
        operation,
        AwsServiceQuotaOperation::GetAWSDefaultServiceQuota
    ) {
        value_digest(value.get("Value"), "default_value")?
    } else {
        value_digest(value.get("DefaultValue"), "default_value")?
    };
    let adjustable_digest = required_bool_digest(value, "Adjustable")?;
    let global_digest = required_bool_digest(value, "GlobalQuota")?;
    let usage_metric_digest = value_digest(value.get("UsageMetric"), "usage_metric")?;
    let usage_revision = parse_revision(value, "UsageRevision", usage_revision_override)?;
    let observed_at = parse_timestamp(value, "ObservedAt", request.observed_at)?;
    QuotaPostureDigest::from_component_digests(
        &identity,
        unit_digest,
        applied_value_digest,
        default_value_digest,
        adjustable_digest,
        global_digest,
        usage_metric_digest,
        history_digest,
        usage_revision,
        observed_at,
    )
    .map_err(AwsServiceQuotaProviderError::Model)
}

fn parse_history_observations(
    request: &AwsServiceQuotaReadRequest,
    value: &Value,
    usage_revision_override: Option<u64>,
) -> Result<Vec<QuotaPostureDigest>, AwsServiceQuotaProviderError> {
    let items = value
        .get("RequestedQuotas")
        .or_else(|| value.get("requestedQuotas"))
        .and_then(Value::as_array)
        .ok_or(AwsServiceQuotaProviderError::Transport(
            TransportError::malformed(),
        ))?;
    let window = request
        .history_window
        .as_ref()
        .ok_or(AwsServiceQuotaProviderError::Model(ModelError::Invalid {
            field: "history window",
        }))?;
    if items.len() > usize::from(window.max_entries) {
        return Err(AwsServiceQuotaProviderError::Model(ModelError::TooMany {
            field: "request history entries",
        }));
    }
    let mut grouped: BTreeMap<Digest, (ServiceQuotaIdentity, Vec<String>, DateTime<Utc>)> =
        BTreeMap::new();
    for item in items {
        let fallback = request
            .quota
            .as_ref()
            .ok_or(AwsServiceQuotaProviderError::Model(ModelError::Invalid {
                field: "history quota selector",
            }))?;
        let identity = ServiceQuotaIdentity::new(
            string_or(item, "ServiceCode", fallback.service_code.as_str()),
            item.get("QuotaCode")
                .and_then(Value::as_str)
                .unwrap_or(fallback.quota_code.as_str()),
        )
        .map_err(AwsServiceQuotaProviderError::Model)?;
        if identity != *fallback || identity.service_code != request.service_code {
            return Err(AwsServiceQuotaProviderError::Model(
                ModelError::ScopeMismatch {
                    field: "history quota identity",
                },
            ));
        }
        let created = parse_timestamp(item, "Created", request.observed_at)?;
        let updated = parse_timestamp(item, "LastUpdated", created)?;
        if !window.contains(created) || !window.contains(updated) {
            return Err(AwsServiceQuotaProviderError::Model(
                ModelError::OutsideHistoryWindow {
                    field: "request history timestamp",
                },
            ));
        }
        let status = item
            .get("Status")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN");
        let desired_digest = value_digest(item.get("DesiredValue"), "desired_value")?
            .map_or_else(String::new, |digest| digest.to_string());
        let entry_digest = Digest::from_parts(
            "hartevo-aws-service-quota-history-entry/v1",
            &[
                status.to_owned(),
                desired_digest,
                created.to_rfc3339(),
                updated.to_rfc3339(),
            ],
        );
        let key = identity.digest();
        let entry = grouped
            .entry(key)
            .or_insert_with(|| (identity.clone(), Vec::new(), updated));
        entry.1.push(entry_digest.to_string());
        if updated > entry.2 {
            entry.2 = updated;
        }
    }
    if grouped.is_empty() {
        let fallback = request
            .quota
            .clone()
            .ok_or(AwsServiceQuotaProviderError::Model(ModelError::Invalid {
                field: "history quota selector",
            }))?;
        grouped.insert(
            fallback.digest(),
            (
                fallback,
                vec![Digest::from_text("empty-history").to_string()],
                request.observed_at,
            ),
        );
    }
    grouped
        .into_values()
        .map(|(identity, mut entries, observed_at)| {
            entries.sort();
            let history_digest =
                Digest::from_parts("hartevo-aws-service-quota-history/v1", &entries);
            let mut synthetic = serde_json::Map::new();
            synthetic.insert(
                "ServiceCode".to_owned(),
                Value::String(identity.service_code.as_str().to_owned()),
            );
            synthetic.insert(
                "QuotaCode".to_owned(),
                Value::String(identity.quota_code.as_str().to_owned()),
            );
            synthetic.insert("Unit".to_owned(), Value::String("history".to_owned()));
            synthetic.insert("Adjustable".to_owned(), Value::Bool(false));
            synthetic.insert("GlobalQuota".to_owned(), Value::Bool(false));
            synthetic.insert(
                "ObservedAt".to_owned(),
                Value::String(observed_at.to_rfc3339()),
            );
            parse_quota_observation(
                request,
                &Value::Object(synthetic),
                usage_revision_override,
                Some(history_digest),
                AwsServiceQuotaOperation::ListRequestedServiceQuotaChangeHistoryByQuota,
            )
        })
        .collect()
}

#[derive(Clone, Debug, Default)]
struct QueuedTransport {
    responses: VecDeque<Result<AwsServiceQuotaReadPage, TransportError>>,
    requests: Vec<AwsServiceQuotaReadRequest>,
}

impl QueuedTransport {
    fn push_response(&mut self, response: Result<AwsServiceQuotaReadPage, TransportError>) {
        self.responses.push_back(response);
    }

    fn requests(&self) -> &[AwsServiceQuotaReadRequest] {
        &self.requests
    }

    fn read(
        &mut self,
        request: &AwsServiceQuotaReadRequest,
    ) -> Result<AwsServiceQuotaReadPage, TransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::timeout()))
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    queue: QueuedTransport,
}

impl RecordingTransport {
    pub fn push_response(&mut self, response: Result<AwsServiceQuotaReadPage, TransportError>) {
        self.queue.push_response(response);
    }

    pub fn requests(&self) -> &[AwsServiceQuotaReadRequest] {
        self.queue.requests()
    }
}

impl AwsServiceQuotaTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn read(
        &mut self,
        request: &AwsServiceQuotaReadRequest,
    ) -> Result<AwsServiceQuotaReadPage, TransportError> {
        self.queue.read(request)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: crate::AwsServiceQuotaScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &crate::AwsServiceQuotaScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn observations(
        &self,
        request: &AwsServiceQuotaReadRequest,
    ) -> Result<Vec<QuotaPostureDigest>, TransportError> {
        let identities = request.quota.clone().into_iter().collect::<Vec<_>>();
        let identities = if identities.is_empty() {
            self.scope.quota_identities()
        } else {
            identities
        };
        identities
            .into_iter()
            .take(usize::from(request.max_results))
            .map(|identity| {
                let usage_revision = self
                    .scope
                    .usage_revision(&identity)
                    .unwrap_or(crate::Revision::new(1).expect("fixture revision"));
                QuotaPostureDigest::fixture(&identity, usage_revision, self.observed_at)
                    .map_err(|_| TransportError::malformed())
            })
            .collect()
    }
}

impl AwsServiceQuotaTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn read(
        &mut self,
        request: &AwsServiceQuotaReadRequest,
    ) -> Result<AwsServiceQuotaReadPage, TransportError> {
        let observations = self.observations(request)?;
        let identities_count = if request.quota.is_some() {
            1
        } else {
            self.scope.quotas.len()
        };
        let next_cursor = if request.is_paginated()
            && usize::from(request.page_number) == 1
            && identities_count > usize::from(request.max_results)
        {
            Some(
                OpaqueCursor::new(
                    "fixture-next-token",
                    &request.filter_digest,
                    request.page_number.saturating_add(1),
                )
                .map_err(|_| TransportError::malformed())?,
            )
        } else {
            None
        };
        AwsServiceQuotaReadPage::new_with_provider_revision(
            request,
            observations,
            next_cursor,
            512,
            TransportProvenance::Fixture,
            ProviderRevision::new(AWS_SERVICE_QUOTA_API_REVISION)
                .map_err(|_| TransportError::malformed())?,
        )
        .map_err(|_| TransportError::malformed())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    fixture: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &crate::AwsServiceQuotaScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            fixture: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AwsServiceQuotaTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read(
        &mut self,
        request: &AwsServiceQuotaReadRequest,
    ) -> Result<AwsServiceQuotaReadPage, TransportError> {
        let observations = self.fixture.observations(request)?;
        AwsServiceQuotaReadPage::new_with_provider_revision(
            request,
            observations,
            None,
            512,
            TransportProvenance::Loopback,
            ProviderRevision::new(AWS_SERVICE_QUOTA_API_REVISION)
                .map_err(|_| TransportError::malformed())?,
        )
        .map_err(|_| TransportError::malformed())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsServiceQuotaTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read(
        &mut self,
        _request: &AwsServiceQuotaReadRequest,
    ) -> Result<AwsServiceQuotaReadPage, TransportError> {
        Err(TransportError::blocked_env())
    }
}

pub type RecordingAwsServiceQuotaTransport = RecordingTransport;
pub type FixtureAwsServiceQuotaTransport = FixtureTransport;
pub type LoopbackAwsServiceQuotaTransport = LoopbackTransport;
pub type BlockedEnvAwsServiceQuotaTransport = BlockedEnvTransport;
pub type FakeAwsServiceQuotaTransport = FixtureTransport;
pub type BlockedEnvTransportAlias = BlockedEnvTransport;
pub type ProviderProvenance = TransportProvenance;

pub fn is_access_loss(error: &TransportError) -> bool {
    error.is_access_loss()
}

pub fn provider_error_evidence(error: &TransportError) -> ProviderErrorEvidence {
    error.evidence()
}
