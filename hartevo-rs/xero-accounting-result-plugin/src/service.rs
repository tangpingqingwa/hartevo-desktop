//! Mission-scoped Xero Accounting result service.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, OAuth2SecretReference, Revision, XeroAccountingEvidence, XeroAccountingScope,
    XeroReadRequest, XeroRegistration,
};
use crate::provider::{OAuth2CredentialResolver, XeroProvider};
use crate::transport::XeroTransport;
use crate::{
    XERO_ACCOUNTING_RESULT_CONTRACT_VERSION, XERO_ACCOUNTING_RESULT_PLUGIN_VERSION,
    XERO_ACCOUNTING_RESULT_SERVICE_ID, XeroAccountingError,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XeroAccountingOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    RevokeSecret,
    ReadInvoices,
    ReadPayments,
    ReadContacts,
    ConsumeObservation,
}

impl XeroAccountingOperation {
    pub const fn all() -> [Self; 8] {
        [
            Self::DescribeCapabilities,
            Self::Register,
            Self::RevokeRegistration,
            Self::RevokeSecret,
            Self::ReadInvoices,
            Self::ReadPayments,
            Self::ReadContacts,
            Self::ConsumeObservation,
        ]
    }

    pub const fn is_read_only(self) -> bool {
        true
    }

    pub const fn mutates_xero(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct XeroAccountingCapability {
    pub operation: XeroAccountingOperation,
    pub read_only: bool,
    pub mutates_xero: bool,
    pub native: bool,
    pub connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct XeroAccountingServiceDefinition {
    pub service_id: String,
    pub implementation: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub kernel_authority: bool,
}

impl Default for XeroAccountingServiceDefinition {
    fn default() -> Self {
        Self {
            service_id: XERO_ACCOUNTING_RESULT_SERVICE_ID.to_owned(),
            implementation: "XeroAccountingResultService".to_owned(),
            plugin_version: XERO_ACCOUNTING_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: XERO_ACCOUNTING_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            read_only: true,
            connected: false,
            native: false,
            kernel_authority: false,
        }
    }
}

pub struct XeroAccountingResultService<T, R = crate::BlockedEnvCredentialResolver>
where
    T: XeroTransport,
    R: OAuth2CredentialResolver,
{
    scope: XeroAccountingScope,
    secret_reference: OAuth2SecretReference,
    provider: XeroProvider<T, R>,
    registration: XeroRegistration,
    definition: XeroAccountingServiceDefinition,
}

impl<T, R> fmt::Debug for XeroAccountingResultService<T, R>
where
    T: XeroTransport,
    R: OAuth2CredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XeroAccountingResultService")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("definition", &self.definition)
            .finish_non_exhaustive()
    }
}

impl<T, R> XeroAccountingResultService<T, R>
where
    T: XeroTransport,
    R: OAuth2CredentialResolver,
{
    pub fn new(
        scope: XeroAccountingScope,
        secret_reference: OAuth2SecretReference,
        provider: XeroProvider<T, R>,
    ) -> Result<Self, XeroAccountingError> {
        crate::XeroAccountingContract::baseline()?;
        let registration = XeroRegistration::new(&scope, &secret_reference, provider.definition())?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
            definition: XeroAccountingServiceDefinition::default(),
        })
    }

    pub fn scope(&self) -> &XeroAccountingScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &OAuth2SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &XeroProvider<T, R> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut XeroProvider<T, R> {
        &mut self.provider
    }

    pub fn registration(&self) -> &XeroRegistration {
        &self.registration
    }

    pub fn definition(&self) -> &XeroAccountingServiceDefinition {
        &self.definition
    }

    pub fn capabilities(&self) -> Vec<XeroAccountingCapability> {
        XeroAccountingOperation::all()
            .into_iter()
            .map(|operation| XeroAccountingCapability {
                operation,
                read_only: operation.is_read_only(),
                mutates_xero: operation.mutates_xero(),
                native: false,
                connected: false,
            })
            .collect()
    }

    pub fn read(
        &mut self,
        request: &XeroReadRequest,
        at: DateTime<Utc>,
    ) -> Result<XeroAccountingEvidence, XeroAccountingError> {
        self.provider.read(
            &self.scope,
            &self.secret_reference,
            &self.registration,
            request,
            at,
        )
    }

    pub fn revoke_registration(
        &mut self,
        revision: Revision,
    ) -> Result<crate::RevocationReceipt, XeroAccountingError> {
        self.registration.revoke(revision)
    }

    pub fn revoke_secret(
        &mut self,
        revision: Revision,
    ) -> Result<crate::SecretRevocationReceipt, XeroAccountingError> {
        self.registration.revoke_secret(revision)
    }
}
