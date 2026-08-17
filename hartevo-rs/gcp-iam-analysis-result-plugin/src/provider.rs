//! Cloud Asset read/proposal provider.
//!
//! The provider owns only deterministic transport seams. It never resolves a
//! SecretReference, sends credentials, mutates IAM, or reports Connected.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    GcpCloudAssetOperation, GcpCloudAssetReceipt, GcpIamAnalysisEvidence, GcpIamModelError,
    GcpIamReadRequest, GcpIamScope, IamPolicyMatch, ProviderProvenance, SecretReference,
};
use crate::transport::{
    GcpCloudAssetPayload, GcpCloudAssetRequest, GcpCloudAssetResponse, GcpCloudAssetTransport,
    GcpTransportError,
};
use crate::{
    GCP_IAM_ANALYSIS_API_VERSION, GCP_IAM_ANALYSIS_CONTRACT_VERSION, GCP_IAM_ANALYSIS_PROVIDER_ID,
    GCP_IAM_ANALYSIS_PROVIDER_REVISION, GCP_IAM_ANALYSIS_PROVIDER_SCHEMA,
    GCP_IAM_ANALYSIS_PROVIDER_VERSION, GCP_IAM_ANALYSIS_SERVICE_ID,
    GCP_IAM_ANALYSIS_SERVICE_VERSION, contract_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpProviderDefinitionError {
    #[error("the provider version is empty")]
    EmptyVersion,
    #[error("native or mutating Cloud Asset provider flags are forbidden in Layer 1")]
    NativeProviderForbidden,
    #[error("the Cloud Asset provider revision or API version drifted")]
    RevisionDrift,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpCloudAssetProviderError {
    #[error("the GCP IAM registration is revoked")]
    RegistrationRevoked,
    #[error("the GCP IAM registration no longer matches the exact scope")]
    RegistrationDrift,
    #[error("the Cloud Asset provider definition drifted")]
    ProviderRevisionMismatch,
    #[error("the Cloud Asset API version drifted")]
    ApiVersionDrift,
    #[error("the Cloud Asset request digest was tampered")]
    RequestTampered,
    #[error("the Cloud Asset response digest was tampered")]
    ResponseTampered,
    #[error("the Cloud Asset response status was HTTP {status}")]
    UnexpectedStatus {
        operation: GcpCloudAssetOperation,
        status: u16,
    },
    #[error("the Cloud Asset response exceeded a bounded limit")]
    ResponseLimitExceeded,
    #[error("the Cloud Asset response was partial or its graph was truncated")]
    PartialGraph,
    #[error("the Cloud Asset response reported access loss")]
    AccessLoss,
    #[error("the hierarchy revision did not match the registered scope")]
    HierarchyRevisionMismatch,
    #[error("the policy revision did not match the registered scope")]
    PolicyRevisionMismatch,
    #[error("the analysis query did not match the registered scope")]
    QueryMismatch,
    #[error("the principal class or digest did not match the registered query")]
    PrincipalMismatch,
    #[error("the opaque page cursor was replayed or returned out of sequence")]
    CursorReplay,
    #[error("the Cloud Asset pagination limit was exceeded")]
    PaginationLimit,
    #[error("the provider returned a response with the wrong operation payload")]
    OperationPayloadMismatch,
    #[error("the bounded Cloud Asset response is invalid")]
    InvalidResponse,
    #[error(transparent)]
    Model(#[from] GcpIamModelError),
    #[error(transparent)]
    Transport(#[from] GcpTransportError),
}

impl From<GcpProviderDefinitionError> for GcpCloudAssetProviderError {
    fn from(_: GcpProviderDefinitionError) -> Self {
        Self::ProviderRevisionMismatch
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpCloudAssetProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub api_version: String,
    pub capability_digest: crate::model::Digest,
    pub provider_digest: crate::model::Digest,
    pub provenance: ProviderProvenance,
    pub native: bool,
    pub connected: bool,
    pub secret_values_read: bool,
    pub credential_material_retained: bool,
    pub live_credential_resolution: bool,
    pub service_account_creation: bool,
    pub policy_mutation: bool,
    pub role_grant_revoke: bool,
    pub effective_authorization_claim: bool,
}

impl GcpCloudAssetProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, GcpProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(GcpProviderDefinitionError::EmptyVersion);
        }
        if provider_version != GCP_IAM_ANALYSIS_PROVIDER_VERSION {
            return Err(GcpProviderDefinitionError::RevisionDrift);
        }
        if provenance.is_native() {
            return Err(GcpProviderDefinitionError::NativeProviderForbidden);
        }
        let capability_digest = crate::provider_capability_digest();
        let provider_digest = crate::provider_definition_digest_for(provenance);
        Ok(Self {
            schema_version: GCP_IAM_ANALYSIS_PROVIDER_SCHEMA.to_owned(),
            provider_id: GCP_IAM_ANALYSIS_PROVIDER_ID.to_owned(),
            provider_version,
            provider_revision: GCP_IAM_ANALYSIS_PROVIDER_REVISION.to_owned(),
            api_version: GCP_IAM_ANALYSIS_API_VERSION.to_owned(),
            capability_digest,
            provider_digest,
            provenance,
            native: false,
            connected: false,
            secret_values_read: false,
            credential_material_retained: false,
            live_credential_resolution: false,
            service_account_creation: false,
            policy_mutation: false,
            role_grant_revoke: false,
            effective_authorization_claim: false,
        })
    }

    pub fn validate(&self) -> Result<(), GcpProviderDefinitionError> {
        if self.provider_id != GCP_IAM_ANALYSIS_PROVIDER_ID
            || self.schema_version != GCP_IAM_ANALYSIS_PROVIDER_SCHEMA
            || self.provider_version != GCP_IAM_ANALYSIS_PROVIDER_VERSION
            || self.provider_revision != GCP_IAM_ANALYSIS_PROVIDER_REVISION
            || self.api_version != GCP_IAM_ANALYSIS_API_VERSION
            || self.capability_digest != crate::provider_capability_digest()
            || self.provider_digest != crate::provider_definition_digest_for(self.provenance)
            || self.native
            || self.connected
            || self.secret_values_read
            || self.credential_material_retained
            || self.live_credential_resolution
            || self.service_account_creation
            || self.policy_mutation
            || self.role_grant_revoke
            || self.effective_authorization_claim
            || self.provenance.is_native()
        {
            return Err(GcpProviderDefinitionError::NativeProviderForbidden);
        }
        Ok(())
    }

    #[must_use]
    pub fn provider_digest(&self) -> &crate::model::Digest {
        &self.provider_digest
    }
}

/// A reversible registration bound to every digest that can change the
/// meaning of an IAM analysis. It is intentionally not serializable because
/// it contains the opaque SecretReference authority object.
pub struct GcpIamRegistration {
    plugin_version: String,
    contract_version: String,
    contract_digest: crate::model::Digest,
    scope: GcpIamScope,
    secret_reference: SecretReference,
    provider_definition: GcpCloudAssetProviderDefinition,
    registration_digest: crate::model::Digest,
    state: RegistrationState,
    revoked_at_unix_seconds: Option<u64>,
}

impl Clone for GcpIamRegistration {
    fn clone(&self) -> Self {
        Self {
            plugin_version: self.plugin_version.clone(),
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            scope: self.scope.clone(),
            secret_reference: self.secret_reference.clone(),
            provider_definition: self.provider_definition.clone(),
            registration_digest: self.registration_digest.clone(),
            state: self.state,
            revoked_at_unix_seconds: self.revoked_at_unix_seconds,
        }
    }
}

impl fmt::Debug for GcpIamRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpIamRegistration")
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("scope_digest", &self.scope.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("provider_digest", &self.provider_definition.provider_digest)
            .field("registration_digest", &self.registration_digest)
            .field("state", &self.state)
            .field("revoked_at_unix_seconds", &self.revoked_at_unix_seconds)
            .finish()
    }
}

impl PartialEq for GcpIamRegistration {
    fn eq(&self, other: &Self) -> bool {
        self.plugin_version == other.plugin_version
            && self.contract_version == other.contract_version
            && self.contract_digest == other.contract_digest
            && self.scope == other.scope
            && self.secret_reference == other.secret_reference
            && self.provider_definition == other.provider_definition
            && self.registration_digest == other.registration_digest
            && self.state == other.state
            && self.revoked_at_unix_seconds == other.revoked_at_unix_seconds
    }
}

impl Eq for GcpIamRegistration {}

impl GcpIamRegistration {
    pub fn new(
        scope: GcpIamScope,
        secret_reference: SecretReference,
        provider_definition: GcpCloudAssetProviderDefinition,
    ) -> Result<Self, GcpCloudAssetProviderError> {
        scope.validate()?;
        provider_definition
            .validate()
            .map_err(|_| GcpCloudAssetProviderError::ProviderRevisionMismatch)?;
        if secret_reference.scope_digest() != &scope.scope_digest || secret_reference.is_revoked() {
            return Err(GcpCloudAssetProviderError::RegistrationDrift);
        }
        let contract_digest = contract_digest();
        let registration_digest = crate::model::Digest::from_fields(
            "gcp-iam-analysis-registration/v1",
            &[
                crate::GCP_IAM_ANALYSIS_PLUGIN_VERSION.to_owned(),
                GCP_IAM_ANALYSIS_CONTRACT_VERSION.to_owned(),
                contract_digest.as_str().to_owned(),
                provider_definition.provider_digest.as_str().to_owned(),
                provider_definition.api_version.clone(),
                scope.permission_digest.as_str().to_owned(),
                scope.scope_digest.as_str().to_owned(),
                scope.policy_digest().as_str().to_owned(),
                scope.query_digest.as_str().to_owned(),
                secret_reference.reference_digest().as_str().to_owned(),
                secret_reference.credential_revision().get().to_string(),
            ],
        );
        Ok(Self {
            plugin_version: crate::GCP_IAM_ANALYSIS_PLUGIN_VERSION.to_owned(),
            contract_version: GCP_IAM_ANALYSIS_CONTRACT_VERSION.to_owned(),
            contract_digest,
            scope,
            secret_reference,
            provider_definition,
            registration_digest,
            state: RegistrationState::Active,
            revoked_at_unix_seconds: None,
        })
    }

    #[must_use]
    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    #[must_use]
    pub fn plugin_version_digest(&self) -> crate::model::Digest {
        crate::plugin_version_digest()
    }

    #[must_use]
    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    #[must_use]
    pub fn contract_digest(&self) -> &crate::model::Digest {
        &self.contract_digest
    }

    #[must_use]
    pub fn scope(&self) -> &GcpIamScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn provider_definition(&self) -> &GcpCloudAssetProviderDefinition {
        &self.provider_definition
    }

    #[must_use]
    pub fn registration_digest(&self) -> &crate::model::Digest {
        &self.registration_digest
    }

    #[must_use]
    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    #[must_use]
    pub const fn revoked_at_unix_seconds(&self) -> Option<u64> {
        self.revoked_at_unix_seconds
    }

    pub fn revoke(&mut self, at_unix_seconds: u64) -> Result<(), GcpCloudAssetProviderError> {
        if self.state == RegistrationState::Revoked {
            return Err(GcpCloudAssetProviderError::RegistrationRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.revoked_at_unix_seconds = Some(at_unix_seconds);
        Ok(())
    }

    fn validate_active(&self, scope: &GcpIamScope) -> Result<(), GcpCloudAssetProviderError> {
        if self.state == RegistrationState::Revoked {
            return Err(GcpCloudAssetProviderError::RegistrationRevoked);
        }
        if &self.scope != scope || self.contract_digest != contract_digest() {
            return Err(GcpCloudAssetProviderError::RegistrationDrift);
        }
        self.provider_definition
            .validate()
            .map_err(|_| GcpCloudAssetProviderError::ProviderRevisionMismatch)
    }
}

pub type GcpCloudAssetRegistration = GcpIamRegistration;

pub struct GcpCloudAssetProvider<T>
where
    T: GcpCloudAssetTransport,
{
    registration: GcpIamRegistration,
    transport: T,
}

impl<T> fmt::Debug for GcpCloudAssetProvider<T>
where
    T: GcpCloudAssetTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpCloudAssetProvider")
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("scope_digest", &self.registration.scope.scope_digest)
            .field(
                "provider_digest",
                &self.registration.provider_definition.provider_digest,
            )
            .field("provenance", &self.transport.provenance())
            .field("connected", &false)
            .finish_non_exhaustive()
    }
}

impl<T> GcpCloudAssetProvider<T>
where
    T: GcpCloudAssetTransport,
{
    pub fn new(
        scope: GcpIamScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, GcpCloudAssetProviderError> {
        let provider_definition = GcpCloudAssetProviderDefinition::new(
            GCP_IAM_ANALYSIS_PROVIDER_VERSION,
            transport.provenance(),
        )?;
        let registration = GcpIamRegistration::new(scope, secret_reference, provider_definition)?;
        Ok(Self {
            registration,
            transport,
        })
    }

    pub fn from_registration(
        registration: GcpIamRegistration,
        transport: T,
    ) -> Result<Self, GcpCloudAssetProviderError> {
        registration
            .provider_definition
            .validate()
            .map_err(|_| GcpCloudAssetProviderError::ProviderRevisionMismatch)?;
        if registration.provider_definition.provenance != transport.provenance() {
            return Err(GcpCloudAssetProviderError::RegistrationDrift);
        }
        Ok(Self {
            registration,
            transport,
        })
    }

    #[must_use]
    pub fn registration(&self) -> &GcpIamRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        false
    }

    pub fn revoke_registration(
        &mut self,
        at_unix_seconds: u64,
    ) -> Result<(), GcpCloudAssetProviderError> {
        self.registration.revoke(at_unix_seconds)
    }

    pub fn read(
        &mut self,
        request: &GcpIamReadRequest,
    ) -> Result<GcpIamAnalysisEvidence, GcpCloudAssetProviderError> {
        self.registration
            .validate_active(&self.registration.scope)?;
        request.validate_for_scope(&self.registration.scope)?;
        let scope = self.registration.scope.clone();
        let mut operations = Vec::new();
        let mut receipts = Vec::new();
        let mut search_pages = Vec::new();
        let mut analysis_pages = Vec::new();
        let mut partial = false;
        let mut access_loss = false;

        if request.include_policy_search {
            operations.push(GcpCloudAssetOperation::SearchAllIamPolicies);
            let (pages, page_receipts, was_partial, lost_access) =
                self.collect_search_pages(&scope, request)?;
            partial |= was_partial;
            access_loss |= lost_access;
            search_pages = pages;
            receipts.extend(page_receipts);
        }
        if request.include_access_analysis {
            operations.push(GcpCloudAssetOperation::AnalyzeIamPolicy);
            let (pages, page_receipts, was_partial, lost_access) =
                self.collect_analysis_pages(&scope, request)?;
            partial |= was_partial;
            access_loss |= lost_access;
            analysis_pages = pages;
            receipts.extend(page_receipts);
        }
        if operations.is_empty() {
            return Err(GcpCloudAssetProviderError::InvalidResponse);
        }
        let evidence = GcpIamAnalysisEvidence::from_pages_with_provider_digest(
            &scope,
            self.registration.registration_digest.clone(),
            self.registration
                .provider_definition
                .provider_digest
                .clone(),
            self.transport.provenance(),
            operations,
            receipts,
            search_pages,
            analysis_pages,
            partial,
            access_loss,
        );
        evidence.validate_for_scope(&scope, Some(&self.registration.registration_digest))?;
        Ok(evidence)
    }

    pub fn analyze_iam(
        &mut self,
        request: &GcpIamReadRequest,
    ) -> Result<GcpIamAnalysisEvidence, GcpCloudAssetProviderError> {
        self.read(request)
    }

    fn collect_search_pages(
        &mut self,
        scope: &GcpIamScope,
        request: &GcpIamReadRequest,
    ) -> Result<
        (
            Vec<crate::model::SearchAllIamPoliciesPage>,
            Vec<GcpCloudAssetReceipt>,
            bool,
            bool,
        ),
        GcpCloudAssetProviderError,
    > {
        let mut pages = Vec::new();
        let mut receipts = Vec::new();
        let mut cursor = None;
        let mut seen = BTreeSet::new();
        let mut partial = false;
        let mut access_loss = false;
        for page_number in 1..=request.max_pages {
            let asset_request = GcpCloudAssetRequest::new(
                scope,
                GcpCloudAssetOperation::SearchAllIamPolicies,
                request.page_size,
                page_number,
                cursor.clone(),
            )?;
            let response = self.execute_checked(scope, &asset_request)?;
            let page = match response.payload.clone() {
                GcpCloudAssetPayload::SearchAllIamPolicies(page) => page,
                GcpCloudAssetPayload::AnalyzeIamPolicy(_) => {
                    return Err(GcpCloudAssetProviderError::OperationPayloadMismatch);
                }
            };
            page.validate_for_scope(scope)?;
            for item in &page.matches {
                validate_match(scope, item)?;
            }
            partial |= page.partial;
            access_loss |= page.access_loss;
            receipts.push(receipt(&asset_request, &response, &page.page_digest));
            let next = page.next_page_token.clone();
            pages.push(page);
            match next {
                Some(next) => {
                    if !seen.insert(next.digest.clone()) {
                        return Err(GcpCloudAssetProviderError::CursorReplay);
                    }
                    cursor = Some(next);
                }
                None => return Ok((pages, receipts, partial, access_loss)),
            }
        }
        Err(GcpCloudAssetProviderError::PaginationLimit)
    }

    fn collect_analysis_pages(
        &mut self,
        scope: &GcpIamScope,
        request: &GcpIamReadRequest,
    ) -> Result<
        (
            Vec<crate::model::AccessAnalysisPage>,
            Vec<GcpCloudAssetReceipt>,
            bool,
            bool,
        ),
        GcpCloudAssetProviderError,
    > {
        let mut pages = Vec::new();
        let mut receipts = Vec::new();
        let mut cursor = None;
        let mut seen = BTreeSet::new();
        let mut partial = false;
        let mut access_loss = false;
        for page_number in 1..=request.max_pages {
            let asset_request = GcpCloudAssetRequest::new(
                scope,
                GcpCloudAssetOperation::AnalyzeIamPolicy,
                request.page_size,
                page_number,
                cursor.clone(),
            )?;
            let response = self.execute_checked(scope, &asset_request)?;
            let page = match response.payload.clone() {
                GcpCloudAssetPayload::AnalyzeIamPolicy(page) => page,
                GcpCloudAssetPayload::SearchAllIamPolicies(_) => {
                    return Err(GcpCloudAssetProviderError::OperationPayloadMismatch);
                }
            };
            page.validate_for_scope(scope)?;
            if page.principal.principal_digest != scope.query.principal_digest
                || page.principal.principal_class != scope.query.principal_class
            {
                return Err(GcpCloudAssetProviderError::PrincipalMismatch);
            }
            if page.nodes.len() > request.max_analysis_nodes
                || page.edges.len() > request.max_analysis_edges
            {
                return Err(GcpCloudAssetProviderError::PartialGraph);
            }
            partial |= page.partial;
            access_loss |= page.access_loss;
            receipts.push(receipt(&asset_request, &response, &page.page_digest));
            let next = page.next_page_token.clone();
            pages.push(page);
            match next {
                Some(next) => {
                    if !seen.insert(next.digest.clone()) {
                        return Err(GcpCloudAssetProviderError::CursorReplay);
                    }
                    cursor = Some(next);
                }
                None => return Ok((pages, receipts, partial, access_loss)),
            }
        }
        Err(GcpCloudAssetProviderError::PaginationLimit)
    }

    fn execute_checked(
        &mut self,
        scope: &GcpIamScope,
        request: &GcpCloudAssetRequest,
    ) -> Result<GcpCloudAssetResponse, GcpCloudAssetProviderError> {
        request.validate_for_scope(scope)?;
        let response = self.transport.execute(request)?;
        if response.request_digest != request.request_digest {
            return Err(GcpCloudAssetProviderError::RequestTampered);
        }
        if response.provider_revision != GCP_IAM_ANALYSIS_PROVIDER_REVISION {
            return Err(GcpCloudAssetProviderError::ProviderRevisionMismatch);
        }
        if response.response_size > crate::model::MAX_RESPONSE_BYTES {
            return Err(GcpCloudAssetProviderError::ResponseLimitExceeded);
        }
        if !response.verify_digest() {
            return Err(GcpCloudAssetProviderError::ResponseTampered);
        }
        if response.status != 200 {
            return Err(GcpCloudAssetProviderError::UnexpectedStatus {
                operation: response.operation,
                status: response.status,
            });
        }
        if response.operation != request.operation {
            return Err(GcpCloudAssetProviderError::OperationPayloadMismatch);
        }
        if request.api_version != GCP_IAM_ANALYSIS_API_VERSION {
            return Err(GcpCloudAssetProviderError::ApiVersionDrift);
        }
        Ok(response)
    }
}

fn receipt(
    request: &GcpCloudAssetRequest,
    response: &GcpCloudAssetResponse,
    page_digest: &crate::model::Digest,
) -> GcpCloudAssetReceipt {
    GcpCloudAssetReceipt {
        operation: request.operation,
        request_digest: request.request_digest.clone(),
        response_digest: response.response_digest.clone(),
        status: response.status,
        response_size: response.response_size,
        provider_revision: response.provider_revision.clone(),
        page_digest: page_digest.clone(),
        raw_provider_payload_retained: false,
        raw_page_token_retained: false,
    }
}

fn validate_match(
    scope: &GcpIamScope,
    item: &IamPolicyMatch,
) -> Result<(), GcpCloudAssetProviderError> {
    if item.principal.principal_digest != scope.query.principal_digest
        || item.principal.principal_class != scope.query.principal_class
    {
        return Err(GcpCloudAssetProviderError::PrincipalMismatch);
    }
    if item.resource_digest != scope.resource_name.digest() {
        return Err(GcpCloudAssetProviderError::QueryMismatch);
    }
    if item.ancestry != scope.resource_ancestry()
        || item.binding.resource_digest != scope.resource_name.digest()
    {
        return Err(GcpCloudAssetProviderError::HierarchyRevisionMismatch);
    }
    if item.binding.binding_fingerprint != scope.policy_binding.binding_fingerprint
        || item.binding.role_fingerprint != scope.policy_binding.role_fingerprint
        || item.binding.policy_digest != scope.policy_digest()
    {
        return Err(GcpCloudAssetProviderError::PolicyRevisionMismatch);
    }
    if item.binding.policy_revision != scope.policy_revision {
        return Err(GcpCloudAssetProviderError::PolicyRevisionMismatch);
    }
    Ok(())
}

pub type GcpIamProviderError = GcpCloudAssetProviderError;

/// A stable service/provider API pair for callers that do not need generic
/// access to the transport implementation.
pub type GcpCloudAssetProviderTransport = dyn GcpCloudAssetTransport;

#[allow(dead_code)]
const _DECLARED_CONTRACT_VERSION: &str = GCP_IAM_ANALYSIS_CONTRACT_VERSION;
#[allow(dead_code)]
const _DECLARED_SERVICE_ID: &str = GCP_IAM_ANALYSIS_SERVICE_ID;
#[allow(dead_code)]
const _DECLARED_SERVICE_VERSION: &str = GCP_IAM_ANALYSIS_SERVICE_VERSION;
