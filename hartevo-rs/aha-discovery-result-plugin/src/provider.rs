//! Read-only provider boundary with fixture, recording, loopback, and blocked transports.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{AhaDiscoveryPage, AhaDiscoveryRequest, AhaDiscoveryResultError, Digest};
use crate::{
    AHA_DISCOVERY_MAX_PAGE_SIZE, AHA_DISCOVERY_PROVIDER_RELEASE, AHA_DISCOVERY_PROVIDER_REVISION,
    AHA_DISCOVERY_RESULT_PLUGIN_VERSION_TEXT, AHA_DISCOVERY_RESULT_PROVIDER_ID,
};

/// Provenance labels are descriptive only; none imply a connected or native provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

/// Transport failures stay in the Layer-1 boundary and never become native claims.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AhaDiscoveryTransportError {
    #[error("transport is blocked in Layer 1")]
    BlockedEnvironment,
    #[error("recorded provider page is not available")]
    PageNotFound,
}

/// Errors from provider definition validation or a bounded transport read.
#[derive(Debug, Eq, Error, PartialEq)]
pub enum AhaDiscoveryProviderError {
    #[error(transparent)]
    Contract(#[from] AhaDiscoveryResultError),
    #[error(transparent)]
    Transport(#[from] AhaDiscoveryTransportError),
}

/// A transport can only return an already-bounded, redacted page.
pub trait AhaDiscoveryTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn fetch(
        &self,
        request: &AhaDiscoveryRequest,
    ) -> Result<AhaDiscoveryPage, AhaDiscoveryTransportError>;
}

/// Versioned provider definition. Native, HTTPS, read-back, and mutation flags are fixed false.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaDiscoveryProviderDefinition {
    pub id: String,
    pub plugin_version: String,
    pub provider_revision: u64,
    pub release: String,
    pub provider_digest: Digest,
    pub read_only: bool,
    pub native: bool,
    pub https_transport: bool,
    pub readback: bool,
    pub first_party: bool,
    pub mutation_authority: bool,
    pub transport: TransportProvenance,
    pub max_page_size: u16,
}

impl AhaDiscoveryProviderDefinition {
    pub fn new(transport: TransportProvenance) -> Result<Self, AhaDiscoveryResultError> {
        let mut definition = Self {
            id: AHA_DISCOVERY_RESULT_PROVIDER_ID.to_owned(),
            plugin_version: AHA_DISCOVERY_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            provider_revision: AHA_DISCOVERY_PROVIDER_REVISION,
            release: AHA_DISCOVERY_PROVIDER_RELEASE.to_owned(),
            provider_digest: Digest::from_text("unsealed-aha-provider"),
            read_only: true,
            native: false,
            https_transport: false,
            readback: false,
            first_party: false,
            mutation_authority: false,
            transport,
            max_page_size: AHA_DISCOVERY_MAX_PAGE_SIZE,
        };
        definition.provider_digest = definition.calculate_digest();
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        if self.id != AHA_DISCOVERY_RESULT_PROVIDER_ID
            || self.plugin_version != AHA_DISCOVERY_RESULT_PLUGIN_VERSION_TEXT
            || self.provider_revision != AHA_DISCOVERY_PROVIDER_REVISION
            || self.release != AHA_DISCOVERY_PROVIDER_RELEASE
            || !self.read_only
            || self.native
            || self.https_transport
            || self.readback
            || self.first_party
            || self.mutation_authority
            || self.max_page_size != AHA_DISCOVERY_MAX_PAGE_SIZE
            || self.provider_digest != self.calculate_digest()
        {
            return Err(AhaDiscoveryResultError::InvalidProviderDefinition);
        }
        self.provider_digest.validate()
    }

    pub fn digest(&self) -> &Digest {
        &self.provider_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-provider-definition/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("revision", self.provider_revision.to_string()),
                ("release", self.release.clone()),
                ("read_only", self.read_only.to_string()),
                ("native", self.native.to_string()),
                ("https", self.https_transport.to_string()),
                ("readback", self.readback.to_string()),
                ("first_party", self.first_party.to_string()),
                ("mutation_authority", self.mutation_authority.to_string()),
                ("transport", self.transport.as_str().to_owned()),
                ("max_page_size", self.max_page_size.to_string()),
            ],
        )
    }
}

/// Provider response with a digest fence and explicit negative native claims.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaDiscoveryProviderResponse {
    pub provider_id: String,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub page: AhaDiscoveryPage,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub response_digest: Digest,
}

impl AhaDiscoveryProviderResponse {
    pub fn validate(&self) -> Result<(), AhaDiscoveryResultError> {
        self.page.validate()?;
        self.request_digest.validate()?;
        self.scope_digest.validate()?;
        if self.provider_id != AHA_DISCOVERY_RESULT_PROVIDER_ID
            || self.request_digest != self.page.request_digest
            || self.scope_digest != self.page.scope.digest()
            || self.connected
            || self.native
            || self.first_party
            || self.response_digest != self.calculate_digest()
        {
            return Err(AhaDiscoveryResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.response_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-provider-response/v1",
            &[
                ("provider", self.provider_id.clone()),
                ("request", self.request_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("page", self.page.page_digest.as_str().to_owned()),
                ("provenance", self.provenance.as_str().to_owned()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
            ],
        )
    }
}

/// Typed provider wrapper. The default transport is BLOCKED_ENV and cannot make network calls.
pub struct AhaDiscoveryProvider<T = BlockedEnvTransport> {
    definition: AhaDiscoveryProviderDefinition,
    transport: T,
}

impl<T> fmt::Debug for AhaDiscoveryProvider<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AhaDiscoveryProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T> AhaDiscoveryProvider<T>
where
    T: AhaDiscoveryTransport,
{
    pub fn new(transport: T) -> Result<Self, AhaDiscoveryProviderError> {
        let definition = AhaDiscoveryProviderDefinition::new(transport.provenance())?;
        Ok(Self {
            definition,
            transport,
        })
    }

    pub fn definition(&self) -> &AhaDiscoveryProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.definition.transport
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }

    pub fn query(
        &self,
        request: &AhaDiscoveryRequest,
    ) -> Result<AhaDiscoveryProviderResponse, AhaDiscoveryProviderError> {
        request.validate()?;
        let page = self.transport.fetch(request)?;
        page.validate()?;
        if page.request_digest != *request.digest()
            || page.scope != request.scope
            || page.resource != request.resource
            || page.cursor != request.cursor
            || page.items.len() > usize::from(request.page_size)
        {
            return Err(AhaDiscoveryResultError::TamperedEvidence.into());
        }
        let mut response = AhaDiscoveryProviderResponse {
            provider_id: self.definition.id.clone(),
            request_digest: request.digest().clone(),
            scope_digest: request.scope.digest(),
            page,
            provenance: self.definition.transport,
            connected: false,
            native: false,
            first_party: false,
            response_digest: Digest::from_text("unsealed-aha-provider-response"),
        };
        response.response_digest = response.calculate_digest();
        response.validate()?;
        Ok(response)
    }
}

/// A deterministic page transport for tests and local contract verification.
#[derive(Clone, Debug)]
pub struct FixtureAhaDiscoveryTransport {
    page: AhaDiscoveryPage,
}

impl FixtureAhaDiscoveryTransport {
    pub fn new(page: AhaDiscoveryPage) -> Result<Self, AhaDiscoveryResultError> {
        page.validate()?;
        Ok(Self { page })
    }

    pub fn page(&self) -> &AhaDiscoveryPage {
        &self.page
    }
}

impl AhaDiscoveryTransport for FixtureAhaDiscoveryTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn fetch(
        &self,
        request: &AhaDiscoveryRequest,
    ) -> Result<AhaDiscoveryPage, AhaDiscoveryTransportError> {
        if self.page.request_digest == *request.digest() {
            Ok(self.page.clone())
        } else {
            Err(AhaDiscoveryTransportError::PageNotFound)
        }
    }
}

/// A deterministic replay transport keyed by the exact request digest.
#[derive(Clone, Debug, Default)]
pub struct RecordingAhaDiscoveryTransport {
    pages: BTreeMap<Digest, AhaDiscoveryPage>,
}

impl RecordingAhaDiscoveryTransport {
    pub fn from_pages(
        pages: impl IntoIterator<Item = AhaDiscoveryPage>,
    ) -> Result<Self, AhaDiscoveryResultError> {
        let mut recorded = Self::default();
        for page in pages {
            page.validate()?;
            recorded.pages.insert(page.request_digest.clone(), page);
        }
        Ok(recorded)
    }

    pub fn page_count(&self) -> usize {
        self.pages.len()
    }
}

impl AhaDiscoveryTransport for RecordingAhaDiscoveryTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn fetch(
        &self,
        request: &AhaDiscoveryRequest,
    ) -> Result<AhaDiscoveryPage, AhaDiscoveryTransportError> {
        self.pages
            .get(request.digest())
            .cloned()
            .ok_or(AhaDiscoveryTransportError::PageNotFound)
    }
}

/// Loopback is a named non-native transport and always remains unavailable to Layer 1.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoopbackAhaDiscoveryTransport;

impl AhaDiscoveryTransport for LoopbackAhaDiscoveryTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn fetch(
        &self,
        _request: &AhaDiscoveryRequest,
    ) -> Result<AhaDiscoveryPage, AhaDiscoveryTransportError> {
        Err(AhaDiscoveryTransportError::BlockedEnvironment)
    }
}

/// Explicit BLOCKED_ENV transport. It does not resolve credentials or perform HTTPS.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AhaDiscoveryTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn fetch(
        &self,
        _request: &AhaDiscoveryRequest,
    ) -> Result<AhaDiscoveryPage, AhaDiscoveryTransportError> {
        Err(AhaDiscoveryTransportError::BlockedEnvironment)
    }
}
