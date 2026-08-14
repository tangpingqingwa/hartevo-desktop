//! Xero provider and credential-resolution boundary.

use std::{env, fmt};

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::model::{
    Digest, OAuth2SecretReference, XeroAccountingEvidence, XeroAccountingScope, XeroEndpoint,
    XeroInvoiceRecord, XeroPaymentRecord, XeroReadRequest, XeroRegistration,
};
use crate::transport::{XeroHttpRequest, XeroResponsePayload, XeroTransport, parse_payload};
use crate::{XERO_ACCOUNTING_API_REVISION, XeroAccountingError};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum XeroCredentialError {
    #[error("BLOCKED_ENV: native OAuth2 resolution is unavailable")]
    BlockedEnv,
    #[error("OAuth2 credential lease is invalid")]
    InvalidLease,
    #[error("OAuth2 credential lease is expired")]
    Expired,
    #[error("OAuth2 credential is unavailable")]
    Unavailable,
}

impl From<XeroCredentialError> for XeroAccountingError {
    fn from(error: XeroCredentialError) -> Self {
        match error {
            XeroCredentialError::BlockedEnv => Self::BlockedEnv,
            XeroCredentialError::InvalidLease | XeroCredentialError::Expired => {
                Self::Credential(error.to_string())
            }
            XeroCredentialError::Unavailable => Self::Credential(error.to_string()),
        }
    }
}

/// A short-lived OAuth2 bearer lease. It is intentionally neither Serialize
/// nor Deserialize, and its Debug output contains no bearer material.
pub struct OAuth2CredentialLease {
    token: Zeroizing<String>,
    secret_reference_digest: Digest,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

pub type CredentialLease = OAuth2CredentialLease;

impl fmt::Debug for OAuth2CredentialLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuth2CredentialLease")
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl OAuth2CredentialLease {
    pub fn new(
        token: impl Into<String>,
        secret_reference: &OAuth2SecretReference,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, XeroCredentialError> {
        let token = token.into();
        if token.trim().is_empty() || token.chars().any(char::is_control) || expires_at <= issued_at
        {
            return Err(XeroCredentialError::InvalidLease);
        }
        Ok(Self {
            token: Zeroizing::new(token),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            issued_at,
            expires_at,
        })
    }

    pub fn validate_at(
        &self,
        secret_reference: &OAuth2SecretReference,
        at: DateTime<Utc>,
    ) -> Result<(), XeroCredentialError> {
        if self.secret_reference_digest != *secret_reference.reference_digest() {
            return Err(XeroCredentialError::InvalidLease);
        }
        if at < self.issued_at || at >= self.expires_at {
            return Err(XeroCredentialError::Expired);
        }
        Ok(())
    }

    pub(crate) fn is_usable(&self) -> bool {
        !self.token.is_empty()
    }
}

pub trait OAuth2CredentialResolver: fmt::Debug {
    fn resolve(
        &mut self,
        reference: &OAuth2SecretReference,
        at: DateTime<Utc>,
    ) -> Result<OAuth2CredentialLease, XeroCredentialError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl OAuth2CredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &mut self,
        _reference: &OAuth2SecretReference,
        _at: DateTime<Utc>,
    ) -> Result<OAuth2CredentialLease, XeroCredentialError> {
        Err(XeroCredentialError::BlockedEnv)
    }
}

/// Test-only in-memory resolver. It is deliberately named fixture and never
/// changes the evidence authority to Connected/native.
pub struct FixtureCredentialResolver {
    token: Zeroizing<String>,
}

impl fmt::Debug for FixtureCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureCredentialResolver")
            .field("token", &"<redacted>")
            .finish()
    }
}

impl FixtureCredentialResolver {
    pub fn new(token: impl Into<String>) -> Result<Self, XeroCredentialError> {
        let token = token.into();
        if token.trim().is_empty() || token.chars().any(char::is_control) {
            return Err(XeroCredentialError::Unavailable);
        }
        Ok(Self {
            token: Zeroizing::new(token),
        })
    }
}

impl OAuth2CredentialResolver for FixtureCredentialResolver {
    fn resolve(
        &mut self,
        reference: &OAuth2SecretReference,
        at: DateTime<Utc>,
    ) -> Result<OAuth2CredentialLease, XeroCredentialError> {
        OAuth2CredentialLease::new(
            self.token.as_str(),
            reference,
            at - Duration::seconds(1),
            at + Duration::minutes(5),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProbeStatus {
    BlockedEnv,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProbe {
    pub status: NativeProbeStatus,
    pub native_credentials_resolved: bool,
    pub live_https_verified: bool,
    pub native_connected_claim: bool,
    pub reason: String,
}

impl NativeProbe {
    pub fn from_environment() -> Self {
        let reason = if env::var("HARTEVO_XERO_NATIVE_PROBE").ok().as_deref() == Some("1") {
            "HARTEVO_XERO_NATIVE_PROBE is present, but Layer-1 has no native OAuth2 authority"
                .to_owned()
        } else {
            "HARTEVO_XERO_NATIVE_PROBE is not enabled".to_owned()
        };
        Self {
            status: NativeProbeStatus::BlockedEnv,
            native_credentials_resolved: false,
            live_https_verified: false,
            native_connected_claim: false,
            reason,
        }
    }
}

pub fn native_probe_from_environment() -> NativeProbe {
    NativeProbe::from_environment()
}

pub struct XeroProvider<T, R = BlockedEnvCredentialResolver>
where
    T: XeroTransport,
    R: OAuth2CredentialResolver,
{
    transport: T,
    resolver: R,
    definition: crate::XeroProviderDefinition,
}

impl<T, R> fmt::Debug for XeroProvider<T, R>
where
    T: XeroTransport,
    R: OAuth2CredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XeroProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .field("resolver", &self.resolver)
            .finish_non_exhaustive()
    }
}

impl<T, R> XeroProvider<T, R>
where
    T: XeroTransport,
    R: OAuth2CredentialResolver,
{
    pub fn new(transport: T, resolver: R) -> Self {
        Self {
            transport,
            resolver,
            definition: crate::XeroProviderDefinition::baseline(),
        }
    }

    pub fn definition(&self) -> &crate::XeroProviderDefinition {
        &self.definition
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

    pub fn resolver_mut(&mut self) -> &mut R {
        &mut self.resolver
    }

    #[allow(clippy::too_many_lines)]
    pub fn read(
        &mut self,
        scope: &XeroAccountingScope,
        secret_reference: &OAuth2SecretReference,
        registration: &XeroRegistration,
        request: &XeroReadRequest,
        at: DateTime<Utc>,
    ) -> Result<XeroAccountingEvidence, XeroAccountingError> {
        registration.validate_active(scope, secret_reference, &self.definition)?;
        if request.include_contacts() && !scope.permissions().contacts_read() {
            return Err(XeroAccountingError::PermissionDrift);
        }
        let credential = match self.resolver.resolve(secret_reference, at) {
            Ok(credential) => {
                credential
                    .validate_at(secret_reference, at)
                    .map_err(XeroAccountingError::from)?;
                credential
            }
            Err(XeroCredentialError::BlockedEnv) => {
                let request_digest = request_digest(scope, request)?;
                return Ok(XeroAccountingEvidence::blocked_env(
                    scope,
                    registration,
                    &request_digest,
                ));
            }
            Err(error) => return Err(error.into()),
        };

        let mut invoices = Vec::new();
        let mut payments = Vec::new();
        let mut contacts = Vec::new();
        let mut request_frames = Vec::new();
        let mut response_frames = Vec::new();

        for endpoint in request.endpoints() {
            let mut endpoint_records = 0_usize;
            let mut page_digests = Vec::new();
            let mut completed = false;
            for page in 1..=request.bounds().pages.max_pages() {
                let http_request = XeroHttpRequest::new(
                    endpoint,
                    scope,
                    request.date_bounds(),
                    request.bounds(),
                    page,
                )?;
                request_frames.push(http_request.clone());
                let response = self
                    .transport
                    .get(&credential, &http_request)
                    .map_err(|error| match error {
                        crate::XeroTransportError::BlockedEnv => XeroAccountingError::BlockedEnv,
                        other => XeroAccountingError::Transport(other.to_string()),
                    })?;
                validate_response_fences(&response, scope, &self.definition)?;
                if response.response_size() > http_request.max_response_bytes {
                    return Err(XeroAccountingError::ResponseTooLarge);
                }
                match response.status() {
                    200..=299 => {}
                    401 | 403 => return Err(XeroAccountingError::AccessLost),
                    404 => return Err(XeroAccountingError::NotFound),
                    status => return Err(XeroAccountingError::UnexpectedStatus(status)),
                }
                let payload = parse_payload(endpoint, response.body(), scope.currency())?;
                let page_digest = payload.redacted_digest();
                if page_digests.contains(&page_digest) {
                    return Err(XeroAccountingError::EvidenceTampered);
                }
                page_digests.push(page_digest.clone());
                endpoint_records = endpoint_records
                    .checked_add(payload.len())
                    .ok_or(XeroAccountingError::RecordBoundExceeded)?;
                if endpoint_records > request.bounds().max_records {
                    return Err(XeroAccountingError::RecordBoundExceeded);
                }
                append_payload(
                    endpoint,
                    payload,
                    scope,
                    &mut invoices,
                    &mut payments,
                    &mut contacts,
                )?;
                if page_digests
                    .last()
                    .is_some_and(|_| endpoint_records < request.bounds().pages.page_size() as usize)
                {
                    completed = true;
                    break;
                }
            }
            if !completed {
                return Err(XeroAccountingError::PageBoundExceeded);
            }
            response_frames.push((endpoint, page_digests));
        }

        let request_digest = Digest::from_serializable(&request_frames);
        let response_digest = Digest::from_serializable(&response_frames);
        XeroAccountingEvidence::complete(
            self.transport.provenance(),
            scope,
            registration,
            request_digest,
            response_digest,
            invoices,
            payments,
            contacts,
        )
    }
}

fn request_digest(
    scope: &XeroAccountingScope,
    request: &XeroReadRequest,
) -> Result<Digest, XeroAccountingError> {
    let frames = request
        .endpoints()
        .into_iter()
        .map(|endpoint| {
            XeroHttpRequest::new(endpoint, scope, request.date_bounds(), request.bounds(), 1)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Digest::from_serializable(&frames))
}

fn validate_response_fences(
    response: &crate::XeroHttpResponse,
    scope: &XeroAccountingScope,
    definition: &crate::XeroProviderDefinition,
) -> Result<(), XeroAccountingError> {
    if response.api_revision() != XERO_ACCOUNTING_API_REVISION
        || response.provider_revision() != XERO_ACCOUNTING_API_REVISION
    {
        return Err(XeroAccountingError::ProviderRevisionDrift);
    }
    if response
        .scope_digest()
        .is_some_and(|digest| digest != &scope.digest())
    {
        return Err(XeroAccountingError::ScopeMismatch(
            "response scope digest differs from the registered scope",
        ));
    }
    if response
        .permission_digest()
        .is_some_and(|digest| digest != &scope.permission_digest())
    {
        return Err(XeroAccountingError::PermissionDrift);
    }
    if definition.api_digest != crate::api_digest() {
        return Err(XeroAccountingError::ProviderRevisionDrift);
    }
    Ok(())
}

fn append_payload(
    endpoint: XeroEndpoint,
    payload: XeroResponsePayload,
    scope: &XeroAccountingScope,
    invoices: &mut Vec<XeroInvoiceRecord>,
    payments: &mut Vec<XeroPaymentRecord>,
    contacts: &mut Vec<crate::XeroContactRecord>,
) -> Result<(), XeroAccountingError> {
    match (endpoint, payload) {
        (XeroEndpoint::Invoices, XeroResponsePayload::Invoices(records)) => {
            for record in records {
                if record.id != *scope.invoice_or_bill().id()
                    || record.kind != scope.invoice_or_bill().kind()
                {
                    return Err(XeroAccountingError::OutOfScopeRecord);
                }
                if record.currency != *scope.currency() {
                    return Err(XeroAccountingError::CurrencyMismatch {
                        field: "invoice_currency",
                    });
                }
                if record.updated_revision != *scope.updated_revision() {
                    return Err(XeroAccountingError::UpdatedRevisionMismatch);
                }
                invoices.push(record);
            }
        }
        (XeroEndpoint::Payments, XeroResponsePayload::Payments(records)) => {
            for record in records {
                if record.id != *scope.payment_id()
                    || record.invoice_or_bill_id != *scope.invoice_or_bill().id()
                    || record.account.id != *scope.account_id()
                {
                    return Err(XeroAccountingError::OutOfScopeRecord);
                }
                if record.amount.currency() != scope.currency() {
                    return Err(XeroAccountingError::CurrencyMismatch {
                        field: "payment_currency",
                    });
                }
                if record.updated_revision != *scope.updated_revision() {
                    return Err(XeroAccountingError::UpdatedRevisionMismatch);
                }
                payments.push(record);
            }
        }
        (XeroEndpoint::Contacts, XeroResponsePayload::Contacts(records)) => {
            for record in records {
                if record.id != *scope.contact_id() {
                    return Err(XeroAccountingError::OutOfScopeRecord);
                }
                if record.updated_revision != *scope.updated_revision() {
                    return Err(XeroAccountingError::UpdatedRevisionMismatch);
                }
                contacts.push(record);
            }
        }
        _ => {
            return Err(XeroAccountingError::Decode(
                "endpoint payload mismatch".to_owned(),
            ));
        }
    }
    Ok(())
}
