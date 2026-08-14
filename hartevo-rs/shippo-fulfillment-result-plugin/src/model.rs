//! Bounded, provider-neutral Shippo projections.
//!
//! Provider JSON is normalized at the transport boundary into the payload
//! types below.  Public evidence types contain identifiers, counts, states,
//! timestamps, and digests only; they never contain labels, addresses, names,
//! phone numbers, email addresses, customs values, URLs, tokens, or raw
//! tracking text.

use std::{fmt, str::FromStr};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::transport::TransportProvenance;
use crate::{
    SHIPPO_API_VERSION, SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION,
    SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT, SHIPPO_MAX_CARRIER_EVIDENCE,
    SHIPPO_MAX_CURSOR_BYTES, SHIPPO_MAX_RETRIES, SHIPPO_MAX_TRACKING_EVENTS,
    SHIPPO_MAX_WINDOW_DAYS, SHIPPO_PROVIDER_ID,
};

pub const MAX_IDENTIFIER_LENGTH: usize = 256;
pub const MAX_ORGANIZATION_LENGTH: usize = 256;
pub const MAX_REASON_LENGTH: usize = 256;
pub const MAX_STATUS_DETAIL_LENGTH: usize = 256;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character")]
    ControlCharacter { field: &'static str },
    #[error("{field} is not a valid bounded value")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is outside the allowed bound")]
    OutOfBounds { field: &'static str },
    #[error("Shippo API version must be {expected}")]
    InvalidApiVersion { expected: &'static str },
}

fn validate_text(
    value: &str,
    field: &'static str,
    max: usize,
    allow_internal_whitespace: bool,
) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ModelError::Invalid { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_string {
    ($name:ident, $field:literal, $max:expr, $allow_internal_whitespace:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, $max, $allow_internal_whitespace)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }
    };
}

bounded_string!(AccountId, "Shippo account id", MAX_IDENTIFIER_LENGTH, false);
bounded_string!(
    OrganizationId,
    "Shippo organization id",
    MAX_ORGANIZATION_LENGTH,
    true
);
bounded_string!(CarrierCode, "carrier code", MAX_IDENTIFIER_LENGTH, false);
bounded_string!(ShipmentId, "shipment id", MAX_IDENTIFIER_LENGTH, false);
bounded_string!(
    TransactionId,
    "transaction id",
    MAX_IDENTIFIER_LENGTH,
    false
);
bounded_string!(
    TrackingNumber,
    "tracking number",
    MAX_IDENTIFIER_LENGTH,
    false
);
bounded_string!(ProjectId, "Project id", MAX_IDENTIFIER_LENGTH, false);
bounded_string!(MissionId, "Mission id", MAX_IDENTIFIER_LENGTH, false);
bounded_string!(
    WorkProductId,
    "Work Product id",
    MAX_IDENTIFIER_LENGTH,
    false
);
bounded_string!(
    ConsentScopeId,
    "Consent scope id",
    MAX_IDENTIFIER_LENGTH,
    false
);
bounded_string!(
    ProviderRevision,
    "provider revision",
    MAX_IDENTIFIER_LENGTH,
    false
);

#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    reference_id: String,
    credential_revision: u64,
}

impl SecretReference {
    /// Creates an opaque host-owned reference.  This type has no field in
    /// which an API token can be stored.
    pub fn new(
        reference_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_text(
            &reference_id,
            "Shippo secret reference id",
            MAX_IDENTIFIER_LENGTH,
            false,
        )?;
        validate_positive(credential_revision, "credential revision")?;
        Ok(Self {
            reference_id,
            credential_revision,
        })
    }

    /// Returns only the host reference identifier, never credential material.
    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_id", &"<opaque>")
            .field("credential_revision", &self.credential_revision)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShippoScopeInput {
    pub account_id: String,
    pub organization_id: String,
    pub carrier: String,
    pub shipment_id: String,
    pub transaction_id: Option<String>,
    pub tracking_number: Option<String>,
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub consent_scope: String,
    pub consent_revision: u64,
}

impl ShippoScopeInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: impl Into<String>,
        organization_id: impl Into<String>,
        carrier: impl Into<String>,
        shipment_id: impl Into<String>,
        transaction_id: Option<impl Into<String>>,
        tracking_number: Option<impl Into<String>>,
        project_id: impl Into<String>,
        project_revision: u64,
        mission_id: impl Into<String>,
        mission_revision: u64,
        work_product_id: impl Into<String>,
        work_product_revision: u64,
        consent_scope: impl Into<String>,
        consent_revision: u64,
    ) -> Self {
        Self {
            account_id: account_id.into(),
            organization_id: organization_id.into(),
            carrier: carrier.into(),
            shipment_id: shipment_id.into(),
            transaction_id: transaction_id.map(Into::into),
            tracking_number: tracking_number.map(Into::into),
            project_id: project_id.into(),
            project_revision,
            mission_id: mission_id.into(),
            mission_revision,
            work_product_id: work_product_id.into(),
            work_product_revision,
            consent_scope: consent_scope.into(),
            consent_revision,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShippoScope {
    account_id: AccountId,
    organization_id: OrganizationId,
    carrier: CarrierCode,
    shipment_id: ShipmentId,
    transaction_id: Option<TransactionId>,
    tracking_number: Option<TrackingNumber>,
    project_id: ProjectId,
    project_revision: u64,
    mission_id: MissionId,
    mission_revision: u64,
    work_product_id: WorkProductId,
    work_product_revision: u64,
    consent_scope: ConsentScopeId,
    consent_revision: u64,
}

impl ShippoScope {
    pub fn new(input: ShippoScopeInput) -> Result<Self, ModelError> {
        validate_positive(input.project_revision, "Project revision")?;
        validate_positive(input.mission_revision, "Mission revision")?;
        validate_positive(input.work_product_revision, "Work Product revision")?;
        validate_positive(input.consent_revision, "Consent revision")?;
        Ok(Self {
            account_id: AccountId::parse(input.account_id)?,
            organization_id: OrganizationId::parse(input.organization_id)?,
            carrier: CarrierCode::parse(input.carrier.to_ascii_lowercase())?,
            shipment_id: ShipmentId::parse(input.shipment_id)?,
            transaction_id: input.transaction_id.map(TransactionId::parse).transpose()?,
            tracking_number: input
                .tracking_number
                .map(TrackingNumber::parse)
                .transpose()?,
            project_id: ProjectId::parse(input.project_id)?,
            project_revision: input.project_revision,
            mission_id: MissionId::parse(input.mission_id)?,
            mission_revision: input.mission_revision,
            work_product_id: WorkProductId::parse(input.work_product_id)?,
            work_product_revision: input.work_product_revision,
            consent_scope: ConsentScopeId::parse(input.consent_scope)?,
            consent_revision: input.consent_revision,
        })
    }

    pub fn account_id(&self) -> &str {
        self.account_id.as_str()
    }

    pub fn organization_id(&self) -> &str {
        self.organization_id.as_str()
    }

    pub fn carrier(&self) -> &str {
        self.carrier.as_str()
    }

    pub fn shipment_id(&self) -> &str {
        self.shipment_id.as_str()
    }

    pub fn transaction_id(&self) -> Option<&str> {
        self.transaction_id.as_ref().map(TransactionId::as_str)
    }

    pub fn tracking_number(&self) -> Option<&str> {
        self.tracking_number.as_ref().map(TrackingNumber::as_str)
    }

    pub fn project_id(&self) -> &str {
        self.project_id.as_str()
    }

    pub const fn project_revision(&self) -> u64 {
        self.project_revision
    }

    pub fn mission_id(&self) -> &str {
        self.mission_id.as_str()
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub fn work_product_id(&self) -> &str {
        self.work_product_id.as_str()
    }

    pub const fn work_product_revision(&self) -> u64 {
        self.work_product_revision
    }

    pub fn consent_scope(&self) -> &str {
        self.consent_scope.as_str()
    }

    pub const fn consent_revision(&self) -> u64 {
        self.consent_revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("Shippo scope serializes")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShippoReadRequest {
    pub expected_shipment_revision: Option<u64>,
    pub expected_transaction_revision: Option<u64>,
    pub expected_tracking_revision: Option<u64>,
    pub cursor: Option<String>,
    pub window_start: Option<DateTime<Utc>>,
    pub window_end: Option<DateTime<Utc>>,
    pub max_tracking_events: usize,
    pub max_carrier_evidence: usize,
    pub max_retries: u8,
}

impl Default for ShippoReadRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl ShippoReadRequest {
    pub fn new() -> Self {
        Self {
            expected_shipment_revision: None,
            expected_transaction_revision: None,
            expected_tracking_revision: None,
            cursor: None,
            window_start: None,
            window_end: None,
            max_tracking_events: SHIPPO_MAX_TRACKING_EVENTS,
            max_carrier_evidence: SHIPPO_MAX_CARRIER_EVIDENCE,
            max_retries: SHIPPO_MAX_RETRIES,
        }
    }

    pub fn with_expected_shipment_revision(mut self, revision: u64) -> Result<Self, ModelError> {
        validate_positive(revision, "expected shipment revision")?;
        self.expected_shipment_revision = Some(revision);
        Ok(self)
    }

    pub fn with_expected_transaction_revision(mut self, revision: u64) -> Result<Self, ModelError> {
        validate_positive(revision, "expected transaction revision")?;
        self.expected_transaction_revision = Some(revision);
        Ok(self)
    }

    pub fn with_expected_tracking_revision(mut self, revision: u64) -> Result<Self, ModelError> {
        validate_positive(revision, "expected tracking revision")?;
        self.expected_tracking_revision = Some(revision);
        Ok(self)
    }

    pub fn with_cursor(mut self, cursor: impl Into<String>) -> Result<Self, ModelError> {
        let cursor = cursor.into();
        validate_text(&cursor, "cursor", SHIPPO_MAX_CURSOR_BYTES, false)?;
        self.cursor = Some(cursor);
        Ok(self)
    }

    pub fn with_time_window(
        mut self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        if end < start || end.signed_duration_since(start) > Duration::days(SHIPPO_MAX_WINDOW_DAYS)
        {
            return Err(ModelError::OutOfBounds {
                field: "time window",
            });
        }
        self.window_start = Some(start);
        self.window_end = Some(end);
        Ok(self)
    }

    pub fn with_max_tracking_events(mut self, max: usize) -> Result<Self, ModelError> {
        if max == 0 || max > SHIPPO_MAX_TRACKING_EVENTS {
            return Err(ModelError::OutOfBounds {
                field: "max tracking events",
            });
        }
        self.max_tracking_events = max;
        Ok(self)
    }

    pub fn with_max_carrier_evidence(mut self, max: usize) -> Result<Self, ModelError> {
        if max == 0 || max > SHIPPO_MAX_CARRIER_EVIDENCE {
            return Err(ModelError::OutOfBounds {
                field: "max carrier evidence",
            });
        }
        self.max_carrier_evidence = max;
        Ok(self)
    }

    pub fn with_max_retries(mut self, max: u8) -> Result<Self, ModelError> {
        if max > SHIPPO_MAX_RETRIES {
            return Err(ModelError::OutOfBounds {
                field: "max retries",
            });
        }
        self.max_retries = max;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if let Some(cursor) = &self.cursor {
            validate_text(cursor, "cursor", SHIPPO_MAX_CURSOR_BYTES, false)?;
        }
        if self.max_tracking_events == 0 || self.max_tracking_events > SHIPPO_MAX_TRACKING_EVENTS {
            return Err(ModelError::OutOfBounds {
                field: "max tracking events",
            });
        }
        if self.max_carrier_evidence == 0 || self.max_carrier_evidence > SHIPPO_MAX_CARRIER_EVIDENCE
        {
            return Err(ModelError::OutOfBounds {
                field: "max carrier evidence",
            });
        }
        if self.max_retries > SHIPPO_MAX_RETRIES {
            return Err(ModelError::OutOfBounds {
                field: "max retries",
            });
        }
        if let (Some(start), Some(end)) = (self.window_start, self.window_end) {
            if end < start
                || end.signed_duration_since(start) > Duration::days(SHIPPO_MAX_WINDOW_DAYS)
            {
                return Err(ModelError::OutOfBounds {
                    field: "time window",
                });
            }
        } else if self.window_start.is_some() || self.window_end.is_some() {
            return Err(ModelError::Invalid {
                field: "time window",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShippoObjectState {
    Valid,
    Invalid,
    Pending,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Waiting,
    Queued,
    Success,
    Error,
    Refunded,
    RefundPending,
    RefundRejected,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTrackingStatus {
    LabelCreated,
    PreTransit,
    Transit,
    Delivered,
    Returned,
    Failure,
    Unknown,
    Unrecognized,
}

impl ProviderTrackingStatus {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_uppercase().as_str() {
            "LABEL_CREATED" | "CREATED" => Self::LabelCreated,
            "PRE_TRANSIT" | "PRETRANSIT" => Self::PreTransit,
            "TRANSIT" | "IN_TRANSIT" => Self::Transit,
            "DELIVERED" => Self::Delivered,
            "RETURNED" => Self::Returned,
            "FAILURE" | "EXCEPTION" | "CANCELLED" => Self::Failure,
            "UNKNOWN" => Self::Unknown,
            _ => Self::Unrecognized,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FulfillmentStatus {
    LabelCreated,
    InTransit,
    Delivered,
    Exception,
    Returned,
    Unknown,
    Partial,
    RetentionGap,
    AccessLost,
    ProviderUnknown,
}

impl FulfillmentStatus {
    pub const fn is_delivery_claim(self) -> bool {
        matches!(self, Self::Delivered)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShippoShipmentPayload {
    pub shipment_id: ShipmentId,
    pub account_id: Option<AccountId>,
    pub object_state: Option<ShippoObjectState>,
    pub parcel_count: usize,
    pub has_origin_address: bool,
    pub has_destination_address: bool,
    pub has_customs_data: bool,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShippoTransactionPayload {
    pub transaction_id: TransactionId,
    pub account_id: Option<AccountId>,
    pub shipment_id: Option<ShipmentId>,
    pub status: TransactionStatus,
    pub tracking_number: Option<TrackingNumber>,
    pub tracking_status: Option<ProviderTrackingStatus>,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShippoTrackingEventPayload {
    pub status: ProviderTrackingStatus,
    pub status_at: Option<DateTime<Utc>>,
    pub location_present: bool,
    pub status_detail_present: bool,
    pub action_required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShippoTrackingPayload {
    pub carrier: CarrierCode,
    pub tracking_number: TrackingNumber,
    pub latest_status: Option<ProviderTrackingStatus>,
    pub events: Vec<ShippoTrackingEventPayload>,
    pub eta: Option<DateTime<Utc>>,
    pub original_eta: Option<DateTime<Utc>>,
    pub has_sender_address: bool,
    pub has_recipient_address: bool,
    pub service_level_present: bool,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShipmentEvidence {
    pub shipment_id: ShipmentId,
    pub object_state: Option<ShippoObjectState>,
    pub parcel_count: usize,
    pub origin_address_present: bool,
    pub destination_address_present: bool,
    pub customs_data_present: bool,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransactionEvidence {
    pub transaction_id: TransactionId,
    pub shipment_id: Option<ShipmentId>,
    pub status: TransactionStatus,
    pub label_created: bool,
    pub tracking_number: Option<TrackingNumber>,
    pub tracking_status: Option<ProviderTrackingStatus>,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrackingEventEvidence {
    pub status: ProviderTrackingStatus,
    pub status_at: Option<DateTime<Utc>>,
    pub location_present: bool,
    pub status_detail_present: bool,
    pub action_required: bool,
    pub event_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct TrackingEvidence {
    pub carrier: CarrierCode,
    pub tracking_number: TrackingNumber,
    pub status: Option<ProviderTrackingStatus>,
    pub event_count: usize,
    pub events: Vec<TrackingEventEvidence>,
    pub eta: Option<DateTime<Utc>>,
    pub original_eta: Option<DateTime<Utc>>,
    pub sender_address_present: bool,
    pub recipient_address_present: bool,
    pub service_level_present: bool,
    pub history_complete: bool,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CarrierEvidence {
    pub carrier: CarrierCode,
    pub tracking_supported: bool,
    pub service_level_present: bool,
    pub event_count: usize,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ShippoReadReceipt {
    pub method: String,
    pub path_and_query: String,
    pub api_version: String,
    pub response_status: u16,
    pub response_size: usize,
    pub response_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub raw_payload_retained: bool,
    pub raw_label_retained: bool,
    pub raw_tracking_payload_retained: bool,
    pub recipient_pii_retained: bool,
    pub credential_material_retained: bool,
    pub retry_index: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ShippoFulfillmentEvidence {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub scope: ShippoScope,
    pub scope_digest: Digest,
    pub shipment: Option<ShipmentEvidence>,
    pub transaction: Option<TransactionEvidence>,
    pub tracking: Option<TrackingEvidence>,
    pub carrier_evidence: Vec<CarrierEvidence>,
    pub status: FulfillmentStatus,
    pub status_reasons: Vec<String>,
    pub receipts: Vec<ShippoReadReceipt>,
    pub provenance: TransportProvenance,
    pub native_evidence: bool,
    pub connected: bool,
    pub external_write_performed: bool,
    pub outcome_authority: bool,
    pub evidence_digest: Digest,
}

pub type FulfillmentEvidence = ShippoFulfillmentEvidence;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShippoFulfillmentResultProposal {
    pub proposal_version: String,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub status: FulfillmentStatus,
    pub decision_hint: String,
    pub requested_effects: Vec<String>,
    pub forbidden_effects: Vec<String>,
    pub proposal_digest: Digest,
}

pub type FulfillmentResultProposal = ShippoFulfillmentResultProposal;

impl ShippoFulfillmentResultProposal {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.proposal_version != SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION
            || !self.requested_effects.is_empty()
            || self.forbidden_effects.is_empty()
            || self.decision_hint.is_empty()
        {
            return Err(ModelError::Invalid {
                field: "fulfillment-result proposal",
            });
        }
        if compute_proposal_digest(self)? != self.proposal_digest {
            return Err(ModelError::Invalid {
                field: "proposal digest",
            });
        }
        Ok(())
    }
}

pub fn compute_evidence_digest(value: &ShippoFulfillmentEvidence) -> Result<Digest, ModelError> {
    let mut without_digest = value.clone();
    without_digest.evidence_digest = zero_digest();
    digest_serializable(&without_digest)
}

pub fn expected_provider_digest(scope: &ShippoScope, revision: &ProviderRevision) -> Digest {
    digest_serializable(&(SHIPPO_PROVIDER_ID, revision, scope))
        .expect("Shippo provider binding serializes")
}

pub fn compute_proposal_digest(
    value: &ShippoFulfillmentResultProposal,
) -> Result<Digest, ModelError> {
    let mut without_digest = value.clone();
    without_digest.proposal_digest = zero_digest();
    digest_serializable(&without_digest)
}

pub fn zero_digest() -> Digest {
    Digest("0000000000000000000000000000000000000000000000000000000000000000".to_owned())
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest(format!("{:x}", Sha256::digest(bytes)))
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::Invalid {
        field: "canonical digest input",
    })?;
    Ok(sha256_digest(&bytes))
}

pub fn map_tracking_status(status: Option<ProviderTrackingStatus>) -> FulfillmentStatus {
    match status {
        Some(ProviderTrackingStatus::LabelCreated | ProviderTrackingStatus::PreTransit) => {
            FulfillmentStatus::LabelCreated
        }
        Some(ProviderTrackingStatus::Transit) => FulfillmentStatus::InTransit,
        Some(ProviderTrackingStatus::Delivered) => FulfillmentStatus::Delivered,
        Some(ProviderTrackingStatus::Returned) => FulfillmentStatus::Returned,
        Some(ProviderTrackingStatus::Failure) => FulfillmentStatus::Exception,
        Some(ProviderTrackingStatus::Unknown) | None => FulfillmentStatus::Unknown,
        Some(ProviderTrackingStatus::Unrecognized) => FulfillmentStatus::ProviderUnknown,
    }
}

pub fn status_reason(value: impl Into<String>) -> Result<String, ModelError> {
    let value = value.into();
    validate_text(&value, "status reason", MAX_REASON_LENGTH, true)?;
    Ok(value)
}

pub fn validate_api_version(value: &str) -> Result<(), ModelError> {
    if value == SHIPPO_API_VERSION {
        Ok(())
    } else {
        Err(ModelError::InvalidApiVersion {
            expected: SHIPPO_API_VERSION,
        })
    }
}

pub fn validate_revision(value: u64, field: &'static str) -> Result<(), ModelError> {
    validate_positive(value, field)
}

pub fn validate_provider_revision(
    value: impl Into<String>,
) -> Result<ProviderRevision, ModelError> {
    ProviderRevision::parse(value)
}

pub fn default_plugin_version() -> &'static str {
    SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT
}

pub fn default_api_version() -> &'static str {
    SHIPPO_API_VERSION
}

pub fn filter_tracking_event(
    event: &ShippoTrackingEventPayload,
    request: &ShippoReadRequest,
) -> bool {
    match (request.window_start, request.window_end, event.status_at) {
        (Some(start), Some(end), Some(at)) => at >= start && at <= end,
        (None, None, _) => true,
        _ => false,
    }
}

pub fn tracking_event_evidence(
    event: &ShippoTrackingEventPayload,
) -> Result<TrackingEventEvidence, ModelError> {
    let event_digest = digest_serializable(event)?;
    Ok(TrackingEventEvidence {
        status: event.status,
        status_at: event.status_at,
        location_present: event.location_present,
        status_detail_present: event.status_detail_present,
        action_required: event.action_required,
        event_digest,
    })
}

pub fn carrier_evidence(
    carrier: CarrierCode,
    tracking_supported: bool,
    service_level_present: bool,
    event_count: usize,
) -> Result<CarrierEvidence, ModelError> {
    if event_count > SHIPPO_MAX_TRACKING_EVENTS {
        return Err(ModelError::OutOfBounds {
            field: "carrier event count",
        });
    }
    let evidence_digest = digest_serializable(&(
        &carrier,
        tracking_supported,
        service_level_present,
        event_count,
    ))?;
    Ok(CarrierEvidence {
        carrier,
        tracking_supported,
        service_level_present,
        event_count,
        evidence_digest,
    })
}

pub fn validate_evidence_redaction(evidence: &ShippoFulfillmentEvidence) -> Result<(), ModelError> {
    if evidence.native_evidence
        || evidence.connected
        || evidence.external_write_performed
        || evidence.outcome_authority
        || evidence.receipts.iter().any(|receipt| {
            receipt.raw_payload_retained
                || receipt.raw_label_retained
                || receipt.raw_tracking_payload_retained
                || receipt.recipient_pii_retained
                || receipt.credential_material_retained
        })
    {
        return Err(ModelError::Invalid {
            field: "redaction or authority fence",
        });
    }
    Ok(())
}
