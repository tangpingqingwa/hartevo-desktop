use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{AwsMarketplaceEntitlementError, AwsMarketplaceTransportError, Result};
use crate::model::{
    AwsMarketplaceEntitlementScope, Digest, EntitlementProjection, GetEntitlementsFilter,
    PageTokenReference, TransportProvenance,
};
use crate::service::AwsMarketplaceEntitlementRegistration;
use crate::{API_REVISION, CONTRACT_VERSION, LAYER1_PERMISSIONS, MAX_PAGE_SIZE, PROVIDER_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsMarketplaceOperation {
    GetEntitlements,
}

impl AwsMarketplaceOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetEntitlements => "GetEntitlements",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsMarketplaceOperation,
    pub request_digest: Digest,
    pub filter_digest: Digest,
    pub page_number: u8,
    pub page_size: u8,
    pub next_token_digest: Option<Digest>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetEntitlementsRequest {
    scope_digest: Digest,
    filter: GetEntitlementsFilter,
    page_size: u8,
    page_number: u8,
    next_token: Option<PageTokenReference>,
    request_digest: Digest,
}

impl GetEntitlementsRequest {
    pub fn new(
        scope: &AwsMarketplaceEntitlementScope,
        filter: GetEntitlementsFilter,
        page_size: u8,
        page_number: u8,
        next_token: Option<PageTokenReference>,
    ) -> Result<Self> {
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) || page_number == 0 {
            return Err(AwsMarketplaceEntitlementError::InvalidRequest);
        }
        filter.validate_against(scope)?;
        if let Some(token) = &next_token {
            token.validate()?;
        }
        let mut request = Self {
            scope_digest: scope.digest(),
            filter,
            page_size,
            page_number,
            next_token,
            request_digest: Digest::from_text("unsealed-aws-marketplace-get-entitlements-request"),
        };
        request.request_digest = request.calculate_digest();
        Ok(request)
    }

    pub fn first(scope: &AwsMarketplaceEntitlementScope, page_size: u8) -> Result<Self> {
        Self::new(
            scope,
            GetEntitlementsFilter::for_scope(scope)?,
            page_size,
            1,
            None,
        )
    }

    pub fn for_scope(scope: &AwsMarketplaceEntitlementScope, page_size: u8) -> Result<Self> {
        Self::first(scope, page_size)
    }

    pub fn next_page(
        &self,
        scope: &AwsMarketplaceEntitlementScope,
        token: PageTokenReference,
        page_number: u8,
    ) -> Result<Self> {
        Self::new(
            scope,
            self.filter.clone(),
            self.page_size,
            page_number,
            Some(token),
        )
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn filter(&self) -> &GetEntitlementsFilter {
        &self.filter
    }

    pub const fn page_size(&self) -> u8 {
        self.page_size
    }

    pub const fn page_number(&self) -> u8 {
        self.page_number
    }

    pub fn next_token(&self) -> Option<&PageTokenReference> {
        self.next_token.as_ref()
    }

    pub const fn has_more(&self) -> bool {
        self.next_token.is_some()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "Action=GetEntitlements&Version=2017-01-11&ProductCode={}&FilterDigest={}&LicenseDigest={}&MaxResults={}&Page={}&NextTokenDigest={}",
            self.filter.product_code().as_str(),
            self.filter.digest().as_str(),
            self.filter.license_digest().as_str(),
            self.page_size,
            self.page_number,
            self.next_token
                .as_ref()
                .map_or("none", |token| token.digest().as_str()),
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsMarketplaceOperation::GetEntitlements,
            request_digest: self.request_digest.clone(),
            filter_digest: self.filter.digest(),
            page_number: self.page_number,
            page_size: self.page_size,
            next_token_digest: self.next_token.as_ref().map(|token| token.digest().clone()),
        }
    }

    pub(crate) fn validate(&self, scope: &AwsMarketplaceEntitlementScope) -> Result<()> {
        if self.scope_digest != scope.digest() {
            return Err(AwsMarketplaceEntitlementError::ScopeMismatch);
        }
        self.filter.validate_against(scope)?;
        if self.request_digest != self.calculate_digest() {
            return Err(AwsMarketplaceEntitlementError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-marketplace-get-entitlements-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter.digest().as_str().to_owned()),
                ("page_size", self.page_size.to_string()),
                ("page_number", self.page_number.to_string()),
                (
                    "next_token",
                    self.next_token
                        .as_ref()
                        .map_or_else(String::new, |token| token.digest().as_str().to_owned()),
                ),
            ],
        )
    }
}

impl fmt::Debug for GetEntitlementsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetEntitlementsRequest")
            .field("scope_digest", &self.scope_digest)
            .field("filter_digest", &self.filter.digest())
            .field("page_size", &self.page_size)
            .field("page_number", &self.page_number)
            .field("next_token", &self.next_token)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetEntitlementsResponse {
    request_digest: Digest,
    filter_digest: Digest,
    page_number: u8,
    entitlements: Vec<EntitlementProjection>,
    next_token: Option<PageTokenReference>,
    response_digest: Digest,
}

impl GetEntitlementsResponse {
    pub fn new(
        request: &GetEntitlementsRequest,
        entitlements: Vec<EntitlementProjection>,
        next_token: Option<PageTokenReference>,
    ) -> Result<Self> {
        if entitlements.len() > request.page_size as usize {
            return Err(AwsMarketplaceEntitlementError::InvalidResponse);
        }
        if let Some(token) = &next_token {
            token.validate()?;
        }
        let mut response = Self {
            request_digest: request.request_digest.clone(),
            filter_digest: request.filter.digest(),
            page_number: request.page_number,
            entitlements,
            next_token,
            response_digest: Digest::from_text(
                "unsealed-aws-marketplace-get-entitlements-response",
            ),
        };
        response.response_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn empty(
        request: &GetEntitlementsRequest,
        next_token: Option<PageTokenReference>,
    ) -> Result<Self> {
        Self::new(request, Vec::new(), next_token)
    }

    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub const fn page_number(&self) -> u8 {
        self.page_number
    }

    pub fn entitlements(&self) -> &[EntitlementProjection] {
        &self.entitlements
    }

    pub fn next_token(&self) -> Option<&PageTokenReference> {
        self.next_token.as_ref()
    }

    pub const fn has_more(&self) -> bool {
        self.next_token.is_some()
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn validate_integrity(&self, request: &GetEntitlementsRequest) -> Result<()> {
        if self.request_digest != *request.request_digest()
            || self.filter_digest != request.filter().digest()
            || self.page_number != request.page_number()
            || self.entitlements.len() > request.page_size() as usize
            || self.response_digest != self.calculate_digest()
        {
            return Err(AwsMarketplaceEntitlementError::TamperedEvidence);
        }
        for entitlement in &self.entitlements {
            entitlement.validate_integrity()?;
        }
        if let Some(token) = &self.next_token {
            token.validate()?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-marketplace-get-entitlements-response/v1",
            &[
                ("request", self.request_digest.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "entitlements",
                    self.entitlements
                        .iter()
                        .map(EntitlementProjection::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "next_token",
                    self.next_token
                        .as_ref()
                        .map_or_else(String::new, |token| token.digest().as_str().to_owned()),
                ),
            ],
        )
    }
}

impl fmt::Debug for GetEntitlementsResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetEntitlementsResponse")
            .field("request_digest", &self.request_digest)
            .field("filter_digest", &self.filter_digest)
            .field("page_number", &self.page_number)
            .field("entitlement_count", &self.entitlements.len())
            .field("next_token", &self.next_token)
            .field("response_digest", &self.response_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsMarketplaceEntitlementProviderDefinition {
    pub(crate) provider_id: String,
    pub(crate) provider_revision: u64,
    pub(crate) api_revision: String,
    pub(crate) contract_version: String,
    pub(crate) release: String,
    pub(crate) capability_digest: Digest,
    pub(crate) provider_digest: Digest,
    pub(crate) connected: bool,
    pub(crate) native: bool,
    pub(crate) first_party: bool,
}

impl AwsMarketplaceEntitlementProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0
            || release.is_empty()
            || release.len() > usize::from(MAX_PAGE_SIZE) * 10
        {
            return Err(AwsMarketplaceEntitlementError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "aws-marketplace-entitlement-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "aws-marketplace-entitlement-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.provider_revision, self.release.clone())?;
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_revision != API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.connected
            || self.native
            || self.first_party
            || self.provider_digest != expected.provider_digest
            || self.capability_digest != expected.capability_digest
        {
            Err(AwsMarketplaceEntitlementError::ProviderDrift)
        } else {
            Ok(())
        }
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn release(&self) -> &str {
        &self.release
    }

    pub fn capability_digest(&self) -> &Digest {
        &self.capability_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub const fn connected(&self) -> bool {
        self.connected
    }

    pub const fn native(&self) -> bool {
        self.native
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }
}

impl Serialize for AwsMarketplaceEntitlementProviderDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state =
            serializer.serialize_struct("AwsMarketplaceEntitlementProviderDefinition", 10)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("release", &self.release)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("connected", &self.connected)?;
        state.serialize_field("native", &self.native)?;
        state.serialize_field("firstParty", &self.first_party)?;
        state.end()
    }
}

pub trait AwsMarketplaceEntitlementTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get_entitlements(
        &mut self,
        request: &GetEntitlementsRequest,
    ) -> std::result::Result<GetEntitlementsResponse, AwsMarketplaceTransportError>;
}

pub struct AwsMarketplaceEntitlementProvider<T: AwsMarketplaceEntitlementTransport> {
    transport: T,
    definition: AwsMarketplaceEntitlementProviderDefinition,
}

impl<T: AwsMarketplaceEntitlementTransport> fmt::Debug for AwsMarketplaceEntitlementProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsMarketplaceEntitlementProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.provenance())
            .finish()
    }
}

impl<T: AwsMarketplaceEntitlementTransport> AwsMarketplaceEntitlementProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "1.0.0")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition =
            AwsMarketplaceEntitlementProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsMarketplaceEntitlementProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn get_entitlements(
        &mut self,
        request: &GetEntitlementsRequest,
    ) -> std::result::Result<GetEntitlementsResponse, AwsMarketplaceTransportError> {
        self.transport.get_entitlements(request)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    pub fn from_registration(
        registration: &AwsMarketplaceEntitlementRegistration,
        transport: T,
    ) -> Result<Self> {
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(AwsMarketplaceEntitlementError::ProviderDrift);
        }
        Ok(provider)
    }
}

impl Default for AwsMarketplaceEntitlementProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked AWS Marketplace provider definition")
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    responses: VecDeque<std::result::Result<GetEntitlementsResponse, AwsMarketplaceTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(
        &mut self,
        response: std::result::Result<GetEntitlementsResponse, AwsMarketplaceTransportError>,
    ) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl AwsMarketplaceEntitlementTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn get_entitlements(
        &mut self,
        request: &GetEntitlementsRequest,
    ) -> std::result::Result<GetEntitlementsResponse, AwsMarketplaceTransportError> {
        self.requests.push(request.recorded_request());
        self.responses
            .pop_front()
            .unwrap_or(Err(AwsMarketplaceTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsMarketplaceEntitlementScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsMarketplaceEntitlementScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn response(
        &self,
        scope: &AwsMarketplaceEntitlementScope,
        request: &GetEntitlementsRequest,
    ) -> std::result::Result<GetEntitlementsResponse, AwsMarketplaceTransportError> {
        if request.scope_digest() != &self.scope.digest() {
            return Err(AwsMarketplaceTransportError::InvalidResponse);
        }
        let expiration = scope
            .expiry()
            .required_until()
            .max(self.observed_at + Duration::hours(1));
        let entitlements = if request.page_number() == 1 {
            vec![EntitlementProjection::for_scope(
                scope,
                expiration,
                Digest::from_text("fixture-entitlement-value"),
            )]
        } else {
            Vec::new()
        };
        GetEntitlementsResponse::new(request, entitlements, None)
            .map_err(|_| AwsMarketplaceTransportError::InvalidResponse)
    }
}

impl AwsMarketplaceEntitlementTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn get_entitlements(
        &mut self,
        request: &GetEntitlementsRequest,
    ) -> std::result::Result<GetEntitlementsResponse, AwsMarketplaceTransportError> {
        self.response(&self.scope, request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    scope: AwsMarketplaceEntitlementScope,
    observed_at: DateTime<Utc>,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsMarketplaceEntitlementScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }
}

impl AwsMarketplaceEntitlementTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn get_entitlements(
        &mut self,
        request: &GetEntitlementsRequest,
    ) -> std::result::Result<GetEntitlementsResponse, AwsMarketplaceTransportError> {
        if request.scope_digest() != &self.scope.digest() {
            return Err(AwsMarketplaceTransportError::InvalidResponse);
        }
        let _ = self.observed_at;
        GetEntitlementsResponse::new(request, Vec::new(), None)
            .map_err(|_| AwsMarketplaceTransportError::InvalidResponse)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsMarketplaceEntitlementTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get_entitlements(
        &mut self,
        _request: &GetEntitlementsRequest,
    ) -> std::result::Result<GetEntitlementsResponse, AwsMarketplaceTransportError> {
        Err(AwsMarketplaceTransportError::BlockedEnv)
    }
}
