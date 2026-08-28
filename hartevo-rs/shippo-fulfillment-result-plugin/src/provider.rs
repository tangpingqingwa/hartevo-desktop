//! Shippo registration, opaque credential resolution, and bounded reads.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::model::{
    CarrierCode, Digest, FulfillmentStatus, ProviderRevision, SecretReference, ShipmentEvidence,
    ShippoFulfillmentEvidence, ShippoReadReceipt, ShippoReadRequest, ShippoScope, TrackingEvidence,
    TrackingNumber, TransactionEvidence, carrier_evidence, compute_evidence_digest,
    expected_provider_digest, filter_tracking_event, map_tracking_status, status_reason,
    tracking_event_evidence, validate_evidence_redaction,
};
use crate::service::ShippoFulfillmentResultService;
use crate::transport::{
    ShippoEndpoint, ShippoHttpRequest, ShippoHttpResponse, ShippoResponseBody, ShippoTransport,
    ShippoTransportError,
};
use crate::{
    SHIPPO_API_VERSION, SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION,
    SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT, SHIPPO_MAX_CARRIER_EVIDENCE,
    SHIPPO_MAX_TRACKING_EVENTS, SHIPPO_NATIVE_PROBE_ENV, SHIPPO_PROVIDER_ID,
    SHIPPO_PROVIDER_REVISION, ShippoFulfillmentError, contract_digest,
};

#[derive(Clone, Error, Eq, PartialEq)]
pub enum CredentialError {
    #[error("BLOCKED_ENV: native Shippo credential authority is unavailable")]
    BlockedEnv,
    #[error("Shippo credential is unavailable")]
    Unavailable,
    #[error("Shippo credential is invalid")]
    Invalid,
    #[error("Shippo credential lease is expired")]
    Expired,
}

impl fmt::Debug for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

#[derive(Clone)]
pub struct ShippoCredential {
    value: String,
}

impl ShippoCredential {
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(CredentialError::Invalid);
        }
        Ok(Self { value })
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for ShippoCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShippoCredential")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Drop for ShippoCredential {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Clone)]
pub struct CredentialLease {
    lease_id: String,
    secret_reference: SecretReference,
    lease_revision: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    credential: ShippoCredential,
}

impl fmt::Debug for CredentialLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialLease")
            .field("lease_id", &"<opaque>")
            .field("secret_reference", &self.secret_reference)
            .field("lease_revision", &self.lease_revision)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl CredentialLease {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lease_id: impl Into<String>,
        secret_reference: SecretReference,
        lease_revision: u64,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        credential: ShippoCredential,
    ) -> Result<Self, CredentialError> {
        let lease_id = lease_id.into();
        if lease_id.trim().is_empty()
            || lease_id.chars().any(char::is_control)
            || lease_revision == 0
            || expires_at <= issued_at
        {
            return Err(CredentialError::Invalid);
        }
        if secret_reference.credential_revision() == 0 {
            return Err(CredentialError::Invalid);
        }
        Ok(Self {
            lease_id,
            secret_reference,
            lease_revision,
            issued_at,
            expires_at,
            credential,
        })
    }

    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub const fn lease_revision(&self) -> u64 {
        self.lease_revision
    }

    pub const fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn validate_at(&self, at: DateTime<Utc>) -> Result<(), CredentialError> {
        if at < self.issued_at || at >= self.expires_at {
            Err(CredentialError::Expired)
        } else {
            Ok(())
        }
    }

    pub(crate) fn credential(&self) -> &ShippoCredential {
        &self.credential
    }
}

pub trait SecretReferenceResolver: fmt::Debug {
    fn resolve(
        &self,
        secret_reference: &SecretReference,
        at: DateTime<Utc>,
    ) -> Result<CredentialLease, CredentialError>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvCredentialResolver;

impl SecretReferenceResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &self,
        _secret_reference: &SecretReference,
        _at: DateTime<Utc>,
    ) -> Result<CredentialLease, CredentialError> {
        Err(CredentialError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentCredentialResolver {
    gate_env: String,
    token_env: String,
}

impl Default for EnvironmentCredentialResolver {
    fn default() -> Self {
        Self::new(SHIPPO_NATIVE_PROBE_ENV, crate::SHIPPO_API_TOKEN_ENV)
    }
}

impl EnvironmentCredentialResolver {
    pub fn new(gate_env: impl Into<String>, token_env: impl Into<String>) -> Self {
        Self {
            gate_env: gate_env.into(),
            token_env: token_env.into(),
        }
    }
}

impl SecretReferenceResolver for EnvironmentCredentialResolver {
    fn resolve(
        &self,
        secret_reference: &SecretReference,
        at: DateTime<Utc>,
    ) -> Result<CredentialLease, CredentialError> {
        if std::env::var(&self.gate_env).ok().as_deref() != Some("1") {
            return Err(CredentialError::BlockedEnv);
        }
        let token = std::env::var(&self.token_env).map_err(|_| CredentialError::Unavailable)?;
        let credential = ShippoCredential::new(token)?;
        CredentialLease::new(
            format!("env-{}", secret_reference.credential_revision()),
            secret_reference.clone(),
            secret_reference.credential_revision(),
            at,
            at + chrono::Duration::minutes(5),
            credential,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeProbeStatus {
    BlockedEnv,
    CredentialGatePresent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeProbe {
    pub status: NativeProbeStatus,
    pub native_connected_claim: bool,
    pub credential_material_available: bool,
    pub note: String,
}

impl NativeProbe {
    pub fn from_environment() -> Self {
        let gate_present = std::env::var(SHIPPO_NATIVE_PROBE_ENV).ok().as_deref() == Some("1");
        Self {
            status: if gate_present {
                NativeProbeStatus::CredentialGatePresent
            } else {
                NativeProbeStatus::BlockedEnv
            },
            native_connected_claim: false,
            credential_material_available: false,
            note: "probe metadata is not native Connected evidence".to_owned(),
        }
    }
}

pub fn native_probe_from_environment() -> NativeProbe {
    NativeProbe::from_environment()
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShippoRegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShippoRegistrationRequest {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub scope: ShippoScope,
    pub secret_reference: SecretReference,
    pub registered_at: DateTime<Utc>,
}

impl ShippoRegistrationRequest {
    pub fn baseline(
        scope: ShippoScope,
        secret_reference: SecretReference,
        registered_at: DateTime<Utc>,
    ) -> Result<Self, ShippoFulfillmentError> {
        let provider_revision = ProviderRevision::parse(SHIPPO_PROVIDER_REVISION)?;
        let provider_digest = expected_provider_digest(&scope, &provider_revision);
        Ok(Self {
            plugin_version: SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: SHIPPO_PROVIDER_ID.to_owned(),
            provider_revision,
            provider_digest,
            scope,
            secret_reference,
            registered_at,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShippoRegistration {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: ProviderRevision,
    provider_digest: Digest,
    scope: ShippoScope,
    secret_reference: SecretReference,
    registered_at: DateTime<Utc>,
    state: ShippoRegistrationState,
    revoked_at: Option<DateTime<Utc>>,
    registration_digest: Digest,
}

impl ShippoRegistration {
    pub fn new(request: ShippoRegistrationRequest) -> Result<Self, ShippoFulfillmentError> {
        if request.plugin_version != SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT {
            return Err(ShippoFulfillmentError::VersionMismatch);
        }
        if request.contract_version != SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION {
            return Err(ShippoFulfillmentError::VersionMismatch);
        }
        if request.contract_digest != contract_digest() {
            return Err(ShippoFulfillmentError::ContractDigestMismatch);
        }
        if request.provider_id != SHIPPO_PROVIDER_ID {
            return Err(ShippoFulfillmentError::ProviderIdMismatch);
        }
        if request.provider_revision.as_str() != SHIPPO_PROVIDER_REVISION {
            return Err(ShippoFulfillmentError::ProviderRevisionMismatch);
        }
        if request.provider_digest
            != expected_provider_digest(&request.scope, &request.provider_revision)
        {
            return Err(ShippoFulfillmentError::RegistrationDrift(
                "provider digest does not bind the registered scope and revision".to_owned(),
            ));
        }
        let mut registration = Self {
            plugin_version: request.plugin_version,
            contract_version: request.contract_version,
            contract_digest: request.contract_digest,
            provider_id: request.provider_id,
            provider_revision: request.provider_revision,
            provider_digest: request.provider_digest,
            scope: request.scope,
            secret_reference: request.secret_reference,
            registered_at: request.registered_at,
            state: ShippoRegistrationState::Active,
            revoked_at: None,
            registration_digest: crate::model::zero_digest(),
        };
        registration.registration_digest = registration.compute_digest()?;
        Ok(registration)
    }

    fn compute_digest(&self) -> Result<Digest, ShippoFulfillmentError> {
        crate::model::digest_serializable(&(
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            &self.provider_revision,
            &self.provider_digest,
            &self.scope,
            &self.secret_reference,
            self.registered_at,
            self.state,
            self.revoked_at,
        ))
        .map_err(ShippoFulfillmentError::from)
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.provider_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn scope(&self) -> &ShippoScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub const fn state(&self) -> ShippoRegistrationState {
        self.state
    }

    pub fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.revoked_at
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<(), ShippoFulfillmentError> {
        if self.state == ShippoRegistrationState::Revoked {
            return Err(ShippoFulfillmentError::RegistrationRevoked);
        }
        if at < self.registered_at {
            return Err(ShippoFulfillmentError::RegistrationDrift(
                "revocation predates registration".to_owned(),
            ));
        }
        self.state = ShippoRegistrationState::Revoked;
        self.revoked_at = Some(at);
        self.registration_digest = self.compute_digest()?;
        Ok(())
    }

    fn validate_at(&self, at: DateTime<Utc>) -> Result<(), ShippoFulfillmentError> {
        if self.state == ShippoRegistrationState::Revoked {
            return Err(ShippoFulfillmentError::RegistrationRevoked);
        }
        if self.plugin_version != SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT
            || self.contract_version != SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != SHIPPO_PROVIDER_ID
            || self.provider_revision.as_str() != SHIPPO_PROVIDER_REVISION
            || self.provider_digest
                != expected_provider_digest(&self.scope, &self.provider_revision)
            || self.compute_digest()? != self.registration_digest
            || at < self.registered_at
        {
            return Err(ShippoFulfillmentError::RegistrationDrift(
                "version, provider, scope, secret, or registration digest drifted".to_owned(),
            ));
        }
        Ok(())
    }
}

pub struct ShippoProvider<T, R>
where
    T: ShippoTransport,
    R: SecretReferenceResolver,
{
    service: ShippoFulfillmentResultService,
    registration: ShippoRegistration,
    transport: T,
    resolver: R,
}

impl<T, R> fmt::Debug for ShippoProvider<T, R>
where
    T: ShippoTransport,
    R: SecretReferenceResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShippoProvider")
            .field("service", &self.service)
            .field("registration", &self.registration)
            .field("transport", &self.transport)
            .field("resolver", &self.resolver)
            .finish()
    }
}

impl<T, R> ShippoProvider<T, R>
where
    T: ShippoTransport,
    R: SecretReferenceResolver,
{
    pub fn new(
        scope: ShippoScope,
        secret_reference: SecretReference,
        transport: T,
        resolver: R,
        at: DateTime<Utc>,
    ) -> Result<Self, ShippoFulfillmentError> {
        let request = ShippoRegistrationRequest::baseline(scope, secret_reference, at)?;
        Self::from_registration_request(request, transport, resolver)
    }

    pub fn from_registration_request(
        request: ShippoRegistrationRequest,
        transport: T,
        resolver: R,
    ) -> Result<Self, ShippoFulfillmentError> {
        let registration = ShippoRegistration::new(request)?;
        Ok(Self {
            service: ShippoFulfillmentResultService::new(),
            registration,
            transport,
            resolver,
        })
    }

    pub fn service(&self) -> &ShippoFulfillmentResultService {
        &self.service
    }

    pub fn registration(&self) -> &ShippoRegistration {
        &self.registration
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn resolver(&self) -> &R {
        &self.resolver
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<(), ShippoFulfillmentError> {
        self.registration.revoke(at)
    }

    #[allow(clippy::too_many_lines)]
    pub fn read(
        &mut self,
        request: &ShippoReadRequest,
        at: DateTime<Utc>,
    ) -> Result<ShippoFulfillmentEvidence, ShippoFulfillmentError> {
        request.validate()?;
        self.registration.validate_at(at)?;
        let lease = self
            .resolver
            .resolve(self.registration.secret_reference(), at)
            .map_err(|error| match error {
                CredentialError::BlockedEnv => ShippoFulfillmentError::BlockedEnv,
                CredentialError::Expired => ShippoFulfillmentError::CredentialExpired,
                other => ShippoFulfillmentError::Credential(other.to_string()),
            })?;
        if lease.secret_reference() != self.registration.secret_reference() {
            return Err(ShippoFulfillmentError::RegistrationDrift(
                "credential lease secret reference drifted".to_owned(),
            ));
        }
        lease.validate_at(at).map_err(|error| match error {
            CredentialError::Expired => ShippoFulfillmentError::CredentialExpired,
            other => ShippoFulfillmentError::Credential(other.to_string()),
        })?;

        let mut receipts = Vec::new();
        let shipment_response = match self.read_endpoint(
            ShippoEndpoint::shipment(self.registration.scope().shipment_id())
                .map_err(ShippoFulfillmentError::from)?,
            request,
            lease.credential(),
            &mut receipts,
        ) {
            Ok(response) => response,
            Err(ShippoFulfillmentError::AccessLost) => {
                return self.access_lost_evidence(request, receipts);
            }
            Err(error) => return Err(error),
        };
        Self::validate_response_revision(
            "shipment",
            request.expected_shipment_revision,
            &shipment_response,
        )?;
        let shipment = match &shipment_response.body {
            ShippoResponseBody::Shipment(payload) => {
                self.validate_shipment_payload(payload)?;
                Some(ShipmentEvidence {
                    shipment_id: payload.shipment_id.clone(),
                    object_state: payload.object_state,
                    parcel_count: payload.parcel_count,
                    origin_address_present: payload.has_origin_address,
                    destination_address_present: payload.has_destination_address,
                    customs_data_present: payload.has_customs_data,
                    revision: payload.revision,
                })
            }
            other => {
                return Err(ShippoFulfillmentError::Decode(format!(
                    "shipment request returned {} payload",
                    other.kind()
                )));
            }
        };

        let transaction = if let Some(transaction_id) = self.registration.scope().transaction_id() {
            let response = match self.read_endpoint(
                ShippoEndpoint::transaction(transaction_id)
                    .map_err(ShippoFulfillmentError::from)?,
                request,
                lease.credential(),
                &mut receipts,
            ) {
                Ok(response) => response,
                Err(ShippoFulfillmentError::AccessLost) => {
                    return self.access_lost_evidence(request, receipts);
                }
                Err(error) => return Err(error),
            };
            Self::validate_response_revision(
                "transaction",
                request.expected_transaction_revision,
                &response,
            )?;
            match &response.body {
                ShippoResponseBody::Transaction(payload) => {
                    self.validate_transaction_payload(payload)?;
                    Some(TransactionEvidence {
                        transaction_id: payload.transaction_id.clone(),
                        shipment_id: payload.shipment_id.clone(),
                        status: payload.status,
                        label_created: matches!(
                            payload.status,
                            crate::model::TransactionStatus::Success
                        ),
                        tracking_number: payload.tracking_number.clone(),
                        tracking_status: payload.tracking_status,
                        revision: payload.revision,
                    })
                }
                other => {
                    return Err(ShippoFulfillmentError::Decode(format!(
                        "transaction request returned {} payload",
                        other.kind()
                    )));
                }
            }
        } else {
            None
        };

        let tracking = if let Some(tracking_number) = self.registration.scope().tracking_number() {
            let response = match self.read_endpoint(
                ShippoEndpoint::tracking(self.registration.scope().carrier(), tracking_number)
                    .map_err(ShippoFulfillmentError::from)?,
                request,
                lease.credential(),
                &mut receipts,
            ) {
                Ok(response) => response,
                Err(ShippoFulfillmentError::AccessLost) => {
                    return self.access_lost_evidence(request, receipts);
                }
                Err(error) => return Err(error),
            };
            Self::validate_response_revision(
                "tracking",
                request.expected_tracking_revision,
                &response,
            )?;
            match &response.body {
                ShippoResponseBody::Tracking(payload) => {
                    self.validate_tracking_payload(payload)?;
                    Some(Self::tracking_evidence(payload, request)?)
                }
                other => {
                    return Err(ShippoFulfillmentError::Decode(format!(
                        "tracking request returned {} payload",
                        other.kind()
                    )));
                }
            }
        } else {
            None
        };

        let carrier = CarrierCode::parse(self.registration.scope().carrier())?;
        let event_count = tracking.as_ref().map_or(0, |value| value.event_count);
        if 1 > request.max_carrier_evidence {
            return Err(ShippoFulfillmentError::CarrierEvidenceBoundExceeded);
        }
        let carrier_evidence = vec![carrier_evidence(
            carrier,
            tracking.is_some(),
            tracking
                .as_ref()
                .is_some_and(|value| value.service_level_present),
            event_count,
        )?];
        let (status, mut status_reasons) =
            Self::normalize_status(shipment.as_ref(), transaction.as_ref(), tracking.as_ref());
        if request.cursor.is_some() {
            status_reasons.push(status_reason("opaque cursor was bound to the read digest")?);
        }
        if request.window_start.is_some() {
            status_reasons.push(status_reason(
                "tracking events were bounded to the requested time window",
            )?);
        }
        if status == FulfillmentStatus::RetentionGap {
            status_reasons.push(status_reason(
                "absence of tracking events is not evidence of delivery or carrier success",
            )?);
        }
        let mut evidence = ShippoFulfillmentEvidence {
            plugin_version: SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: SHIPPO_PROVIDER_ID.to_owned(),
            provider_revision: ProviderRevision::parse(SHIPPO_PROVIDER_REVISION)?,
            provider_digest: self.registration.provider_digest().clone(),
            scope: self.registration.scope().clone(),
            scope_digest: self.registration.scope().digest(),
            shipment,
            transaction,
            tracking,
            carrier_evidence,
            status,
            status_reasons,
            receipts,
            provenance: self.transport.provenance(),
            native_evidence: false,
            connected: false,
            external_write_performed: false,
            outcome_authority: false,
            evidence_digest: crate::model::zero_digest(),
        };
        evidence.evidence_digest = compute_evidence_digest(&evidence)?;
        self.validate_evidence(&evidence)?;
        Ok(evidence)
    }

    pub fn read_fulfillment_result(
        &mut self,
        request: &ShippoReadRequest,
        at: DateTime<Utc>,
    ) -> Result<ShippoFulfillmentEvidence, ShippoFulfillmentError> {
        self.read(request, at)
    }

    #[allow(clippy::needless_continue, clippy::needless_pass_by_value)]
    fn read_endpoint(
        &mut self,
        endpoint: ShippoEndpoint,
        request: &ShippoReadRequest,
        credential: &ShippoCredential,
        receipts: &mut Vec<ShippoReadReceipt>,
    ) -> Result<ShippoHttpResponse, ShippoFulfillmentError> {
        for retry_index in 0..=request.max_retries {
            let http_request = ShippoHttpRequest::new(endpoint.clone(), request, retry_index)
                .map_err(ShippoFulfillmentError::from)?;
            let response = match self.transport.execute(credential, &http_request) {
                Ok(response) => response,
                Err(ShippoTransportError::RateLimited {
                    retry_after_seconds,
                }) if retry_index < request.max_retries && retry_after_seconds <= 60 => continue,
                Err(error) => return Err(error.into()),
            };
            if response.request_digest() != http_request.request_digest() {
                return Err(ShippoFulfillmentError::Transport(
                    "response request digest mismatch".to_owned(),
                ));
            }
            if response.api_version != SHIPPO_API_VERSION {
                return Err(ShippoFulfillmentError::ApiVersionDrift {
                    expected: SHIPPO_API_VERSION.to_owned(),
                    actual: response.api_version,
                });
            }
            if response.provider_revision.as_str() != SHIPPO_PROVIDER_REVISION {
                return Err(ShippoFulfillmentError::ProviderRevisionMismatch);
            }
            receipts.push(ShippoReadReceipt {
                method: http_request.method.clone(),
                path_and_query: http_request
                    .path_and_query()
                    .map_err(ShippoFulfillmentError::from)?,
                api_version: response.api_version.clone(),
                response_status: response.status,
                response_size: response.response_size,
                response_digest: response.response_digest.clone(),
                provider_revision: response.provider_revision.clone(),
                raw_payload_retained: false,
                raw_label_retained: false,
                raw_tracking_payload_retained: false,
                recipient_pii_retained: false,
                credential_material_retained: false,
                retry_index,
            });
            match response.status {
                200..=299 => return Ok(response),
                401 | 403 => return Err(ShippoFulfillmentError::AccessLost),
                429 if retry_index < request.max_retries => continue,
                429 => return Err(ShippoFulfillmentError::RateLimitExceeded),
                status => return Err(ShippoFulfillmentError::UnexpectedStatus { status }),
            }
        }
        Err(ShippoFulfillmentError::RateLimitExceeded)
    }

    fn validate_response_revision(
        resource: &str,
        expected: Option<u64>,
        response: &ShippoHttpResponse,
    ) -> Result<(), ShippoFulfillmentError> {
        let observed = match &response.body {
            ShippoResponseBody::Shipment(payload) => payload.revision,
            ShippoResponseBody::Transaction(payload) => payload.revision,
            ShippoResponseBody::Tracking(payload) => payload.revision,
            ShippoResponseBody::Empty => return Ok(()),
        };
        if let Some(expected) = expected
            && expected != observed
        {
            return Err(ShippoFulfillmentError::RevisionMismatch {
                resource: resource.to_owned(),
                expected,
                observed,
            });
        }
        Ok(())
    }

    fn validate_shipment_payload(
        &self,
        payload: &crate::model::ShippoShipmentPayload,
    ) -> Result<(), ShippoFulfillmentError> {
        if payload.shipment_id.as_str() != self.registration.scope().shipment_id() {
            return Err(ShippoFulfillmentError::ShipmentIdMismatch);
        }
        if let Some(account_id) = &payload.account_id
            && account_id.as_str() != self.registration.scope().account_id()
        {
            return Err(ShippoFulfillmentError::AccountMismatch);
        }
        if payload.parcel_count > SHIPPO_MAX_TRACKING_EVENTS {
            return Err(ShippoFulfillmentError::TrackingEventBoundExceeded);
        }
        Ok(())
    }

    fn validate_transaction_payload(
        &self,
        payload: &crate::model::ShippoTransactionPayload,
    ) -> Result<(), ShippoFulfillmentError> {
        if payload.transaction_id.as_str()
            != self.registration.scope().transaction_id().unwrap_or("")
        {
            return Err(ShippoFulfillmentError::TransactionIdMismatch);
        }
        if let Some(account_id) = &payload.account_id
            && account_id.as_str() != self.registration.scope().account_id()
        {
            return Err(ShippoFulfillmentError::AccountMismatch);
        }
        if let Some(shipment_id) = &payload.shipment_id
            && shipment_id.as_str() != self.registration.scope().shipment_id()
        {
            return Err(ShippoFulfillmentError::ShipmentIdMismatch);
        }
        if let (Some(expected), Some(observed)) = (
            self.registration.scope().tracking_number(),
            payload.tracking_number.as_ref().map(TrackingNumber::as_str),
        ) && expected != observed
        {
            return Err(ShippoFulfillmentError::TrackingNumberMismatch);
        }
        Ok(())
    }

    fn validate_tracking_payload(
        &self,
        payload: &crate::model::ShippoTrackingPayload,
    ) -> Result<(), ShippoFulfillmentError> {
        if payload.carrier.as_str() != self.registration.scope().carrier() {
            return Err(ShippoFulfillmentError::CarrierMismatch);
        }
        if payload.tracking_number.as_str()
            != self.registration.scope().tracking_number().unwrap_or("")
        {
            return Err(ShippoFulfillmentError::TrackingNumberMismatch);
        }
        if payload.events.len() > SHIPPO_MAX_TRACKING_EVENTS {
            return Err(ShippoFulfillmentError::TrackingEventBoundExceeded);
        }
        Ok(())
    }

    fn tracking_evidence(
        payload: &crate::model::ShippoTrackingPayload,
        request: &ShippoReadRequest,
    ) -> Result<TrackingEvidence, ShippoFulfillmentError> {
        let selected = payload
            .events
            .iter()
            .filter(|event| filter_tracking_event(event, request))
            .collect::<Vec<_>>();
        if selected.len() > request.max_tracking_events {
            return Err(ShippoFulfillmentError::TrackingEventBoundExceeded);
        }
        let events = selected
            .iter()
            .map(|event| tracking_event_evidence(event))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TrackingEvidence {
            carrier: payload.carrier.clone(),
            tracking_number: payload.tracking_number.clone(),
            status: payload
                .latest_status
                .or_else(|| selected.last().map(|event| event.status)),
            event_count: events.len(),
            events,
            eta: payload.eta,
            original_eta: payload.original_eta,
            sender_address_present: payload.has_sender_address,
            recipient_address_present: payload.has_recipient_address,
            service_level_present: payload.service_level_present,
            history_complete: selected.len() == payload.events.len(),
            revision: payload.revision,
        })
    }

    fn normalize_status(
        shipment: Option<&ShipmentEvidence>,
        transaction: Option<&TransactionEvidence>,
        tracking: Option<&TrackingEvidence>,
    ) -> (FulfillmentStatus, Vec<String>) {
        let mut reasons = Vec::new();
        if shipment.is_none() {
            reasons.push("shipment evidence is absent".to_owned());
            return (FulfillmentStatus::Partial, reasons);
        }
        if let Some(tracking) = tracking {
            if tracking.event_count == 0 {
                reasons.push("tracking response contains no status or events".to_owned());
                return (FulfillmentStatus::RetentionGap, reasons);
            }
            let status = map_tracking_status(tracking.status);
            if status == FulfillmentStatus::ProviderUnknown {
                reasons
                    .push("Shippo returned a status outside the normalized vocabulary".to_owned());
            }
            return (status, reasons);
        }
        if let Some(transaction) = transaction {
            let status = match transaction.status {
                crate::model::TransactionStatus::Success => FulfillmentStatus::LabelCreated,
                crate::model::TransactionStatus::Error => FulfillmentStatus::Exception,
                crate::model::TransactionStatus::Refunded
                | crate::model::TransactionStatus::RefundPending
                | crate::model::TransactionStatus::RefundRejected => FulfillmentStatus::Returned,
                crate::model::TransactionStatus::Unknown => FulfillmentStatus::ProviderUnknown,
                crate::model::TransactionStatus::Waiting
                | crate::model::TransactionStatus::Queued => FulfillmentStatus::Partial,
            };
            if transaction.tracking_number.is_some() {
                reasons.push("tracking evidence was not requested in the bound scope".to_owned());
                if status == FulfillmentStatus::LabelCreated {
                    return (FulfillmentStatus::RetentionGap, reasons);
                }
            } else if status == FulfillmentStatus::LabelCreated {
                reasons.push("transaction has no tracking number".to_owned());
            }
            return (status, reasons);
        }
        reasons.push("only shipment metadata was requested".to_owned());
        (FulfillmentStatus::Partial, reasons)
    }

    fn access_lost_evidence(
        &self,
        request: &ShippoReadRequest,
        receipts: Vec<ShippoReadReceipt>,
    ) -> Result<ShippoFulfillmentEvidence, ShippoFulfillmentError> {
        let mut evidence = ShippoFulfillmentEvidence {
            plugin_version: SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: SHIPPO_PROVIDER_ID.to_owned(),
            provider_revision: ProviderRevision::parse(SHIPPO_PROVIDER_REVISION)?,
            provider_digest: self.registration.provider_digest().clone(),
            scope: self.registration.scope().clone(),
            scope_digest: self.registration.scope().digest(),
            shipment: None,
            transaction: None,
            tracking: None,
            carrier_evidence: Vec::new(),
            status: FulfillmentStatus::AccessLost,
            status_reasons: vec![status_reason(
                "Shippo access was lost; no provider payload was retained",
            )?],
            receipts,
            provenance: self.transport.provenance(),
            native_evidence: false,
            connected: false,
            external_write_performed: false,
            outcome_authority: false,
            evidence_digest: crate::model::zero_digest(),
        };
        if request.max_carrier_evidence == 0 {
            return Err(ShippoFulfillmentError::CarrierEvidenceBoundExceeded);
        }
        evidence.evidence_digest = compute_evidence_digest(&evidence)?;
        self.validate_evidence(&evidence)?;
        Ok(evidence)
    }

    fn validate_evidence(
        &self,
        evidence: &ShippoFulfillmentEvidence,
    ) -> Result<(), ShippoFulfillmentError> {
        if evidence.scope != *self.registration.scope()
            || evidence.scope_digest != self.registration.scope().digest()
            || evidence.contract_digest != contract_digest()
            || evidence.contract_version != SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION
            || evidence.plugin_version != SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT
            || evidence.provider_id != SHIPPO_PROVIDER_ID
            || evidence.provider_revision.as_str() != SHIPPO_PROVIDER_REVISION
            || evidence.provider_digest
                != expected_provider_digest(&evidence.scope, &evidence.provider_revision)
            || evidence.provenance.is_native()
            || evidence.provenance.is_connected()
            || compute_evidence_digest(evidence)? != evidence.evidence_digest
        {
            return Err(ShippoFulfillmentError::StaleEvidence);
        }
        validate_evidence_redaction(evidence)?;
        if evidence.carrier_evidence.len() > SHIPPO_MAX_CARRIER_EVIDENCE
            || evidence
                .tracking
                .as_ref()
                .is_some_and(|tracking| tracking.events.len() > SHIPPO_MAX_TRACKING_EVENTS)
        {
            return Err(ShippoFulfillmentError::CarrierEvidenceBoundExceeded);
        }
        Ok(())
    }
}

impl<T, R> ShippoProvider<T, R>
where
    T: ShippoTransport,
    R: SecretReferenceResolver,
{
    pub fn compile_proposal(
        &self,
        evidence: &ShippoFulfillmentEvidence,
    ) -> Result<crate::model::ShippoFulfillmentResultProposal, ShippoFulfillmentError> {
        self.service.compile_proposal(evidence)
    }
}
