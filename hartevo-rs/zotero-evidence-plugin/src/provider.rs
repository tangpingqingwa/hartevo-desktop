use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::error::{ZoteroEvidenceError, ZoteroProviderError};
use crate::model::{
    Digest, ZOTERO_LOCAL_API_BASE_URL, ZOTERO_WEB_API_BASE_URL, ZOTERO_WEB_API_VERSION,
    ZoteroApiVersion, ZoteroAuthenticationMode, ZoteroCapabilityProbeRequest,
    ZoteroCapabilityProbeResponse, ZoteroCitationRequest, ZoteroCitationResponse,
    ZoteroEvidenceScope, ZoteroHttpMethod, ZoteroItemEvidence, ZoteroItemKey, ZoteroProvenance,
    ZoteroProviderManifest, ZoteroReadRequest, ZoteroReadResponse, ZoteroReadTarget,
    ZoteroTransportKind, ZoteroTransportOperation, ZoteroVersion,
};

/// A token/key reference that is opaque at the provider boundary. The raw
/// value is never serialized, logged, or included in a request plan.
#[derive(Clone)]
pub struct SecretReference {
    reference: String,
}

impl SecretReference {
    pub fn new(reference: impl Into<String>) -> Result<Self, ZoteroEvidenceError> {
        let reference = reference.into();
        if reference.trim().is_empty() || reference.len() > 256 {
            return Err(ZoteroEvidenceError::InvalidInput {
                field: "secret_reference",
                reason: String::from("must be non-empty and bounded"),
            });
        }
        Ok(Self { reference })
    }

    pub fn digest(&self) -> Digest {
        crate::model::sha256_digest(self.reference.as_bytes())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("digest", &self.digest())
            .finish_non_exhaustive()
    }
}

/// A network-free, typed request plan. It is a future integration seam, not a
/// live HTTP client and contains no secret header or raw provider body.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ZoteroRequestPlan {
    pub transport: ZoteroTransportKind,
    pub provenance: ZoteroProvenance,
    pub api_version: ZoteroApiVersion,
    pub method: ZoteroHttpMethod,
    pub endpoint: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub authentication: ZoteroAuthenticationMode,
    pub secret_reference_required: bool,
}

/// Explicit Web API v3 and official localhost API v3 planning seams.
pub trait ZoteroApiTransport: fmt::Debug + Send + Sync {
    fn kind(&self) -> ZoteroTransportKind;

    fn provenance(&self) -> ZoteroProvenance;

    fn base_url(&self) -> &'static str;

    fn plan(
        &self,
        operation: &ZoteroTransportOperation,
        authentication: ZoteroAuthenticationMode,
    ) -> Result<ZoteroRequestPlan, ZoteroEvidenceError>;
}

/// HTTPS Zotero Web API v3 seam. Only bounded GET plans are emitted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ZoteroWebApiV3Transport;

/// Official Zotero desktop localhost API v3 seam with distinct provenance.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ZoteroOfficialLocalApiV3Transport;

impl ZoteroApiTransport for ZoteroWebApiV3Transport {
    fn kind(&self) -> ZoteroTransportKind {
        ZoteroTransportKind::WebApiV3
    }

    fn provenance(&self) -> ZoteroProvenance {
        ZoteroProvenance::WebApiV3
    }

    fn base_url(&self) -> &'static str {
        ZOTERO_WEB_API_BASE_URL
    }

    fn plan(
        &self,
        operation: &ZoteroTransportOperation,
        authentication: ZoteroAuthenticationMode,
    ) -> Result<ZoteroRequestPlan, ZoteroEvidenceError> {
        plan_operation(
            self.kind(),
            self.provenance(),
            self.base_url(),
            operation,
            authentication,
        )
    }
}

impl ZoteroApiTransport for ZoteroOfficialLocalApiV3Transport {
    fn kind(&self) -> ZoteroTransportKind {
        ZoteroTransportKind::OfficialLocalApiV3
    }

    fn provenance(&self) -> ZoteroProvenance {
        ZoteroProvenance::OfficialLocalApiV3
    }

    fn base_url(&self) -> &'static str {
        ZOTERO_LOCAL_API_BASE_URL
    }

    fn plan(
        &self,
        operation: &ZoteroTransportOperation,
        authentication: ZoteroAuthenticationMode,
    ) -> Result<ZoteroRequestPlan, ZoteroEvidenceError> {
        plan_operation(
            self.kind(),
            self.provenance(),
            self.base_url(),
            operation,
            authentication,
        )
    }
}

fn plan_operation(
    transport: ZoteroTransportKind,
    provenance: ZoteroProvenance,
    base_url: &str,
    operation: &ZoteroTransportOperation,
    authentication: ZoteroAuthenticationMode,
) -> Result<ZoteroRequestPlan, ZoteroEvidenceError> {
    let (scope, path, page, since, conditional, server_id, citation) = match operation {
        ZoteroTransportOperation::Probe(request) => (
            &request.scope,
            request.scope.library.path_prefix(),
            None,
            None,
            None,
            None,
            None,
        ),
        ZoteroTransportOperation::Read(request) => (
            &request.scope,
            read_path(&request.scope, &request.target),
            Some(request.page),
            request.since.as_ref().map(|cursor| cursor.version),
            request.conditional.as_ref(),
            request.server_id.as_ref(),
            None,
        ),
        ZoteroTransportOperation::Citation(request) => (
            &request.scope,
            format!(
                "{}/items/{}",
                request.scope.library.path_prefix(),
                request.item_key
            ),
            None,
            None,
            None,
            request.server_id.as_ref(),
            Some(request),
        ),
    };
    scope.validate()?;
    let mut query = BTreeMap::from([(String::from("format"), String::from("json"))]);
    if let Some(page) = page {
        query.insert(String::from("limit"), page.limit.to_string());
        query.insert(String::from("start"), page.start.to_string());
    }
    if let Some(since) = since {
        query.insert(String::from("since"), since.to_string());
    }
    if let Some(conditional) = conditional {
        conditional.validate_for(scope)?;
    }
    if let Some(citation) = citation {
        query.insert(String::from("include"), String::from("citation"));
        query.insert(String::from("style"), citation.style.as_str().to_owned());
        query.insert(String::from("locale"), citation.locale.as_str().to_owned());
        query.insert(String::from("format"), String::from("json"));
    }
    let mut headers = BTreeMap::from([(
        String::from("Zotero-API-Version"),
        ZOTERO_WEB_API_VERSION.to_string(),
    )]);
    if let Some(conditional) = conditional {
        headers.insert(
            String::from("If-Modified-Since-Version"),
            conditional.if_modified_since_version.to_string(),
        );
    }
    if let Some(server_id) = server_id {
        headers.insert(
            String::from("Zotero-Server-ID"),
            server_id.as_str().to_owned(),
        );
    }
    Ok(ZoteroRequestPlan {
        transport,
        provenance,
        api_version: ZoteroApiVersion::v3(),
        method: ZoteroHttpMethod::Get,
        endpoint: format!("{base_url}{path}"),
        query,
        headers,
        authentication,
        secret_reference_required: matches!(
            authentication,
            ZoteroAuthenticationMode::SecretReference
        ),
    })
}

fn read_path(scope: &ZoteroEvidenceScope, target: &ZoteroReadTarget) -> String {
    match target {
        ZoteroReadTarget::Library => format!("{}/items", scope.library.path_prefix()),
        ZoteroReadTarget::Collection { collection_key } => format!(
            "{}/collections/{collection_key}/items",
            scope.library.path_prefix()
        ),
        ZoteroReadTarget::Item { item_key } => {
            format!("{}/items/{item_key}", scope.library.path_prefix())
        }
    }
}

/// Provider boundary consumed by the typed service and Mission consumer.
pub trait ZoteroEvidenceProvider: fmt::Debug + Send + Sync {
    fn manifest(&self) -> ZoteroProviderManifest;

    fn probe(
        &self,
        request: &ZoteroCapabilityProbeRequest,
    ) -> Result<ZoteroCapabilityProbeResponse, ZoteroProviderError>;

    fn read(&self, request: &ZoteroReadRequest) -> Result<ZoteroReadResponse, ZoteroProviderError>;

    fn citation(
        &self,
        request: &ZoteroCitationRequest,
    ) -> Result<ZoteroCitationResponse, ZoteroProviderError>;

    fn external_write_available(&self) -> bool {
        false
    }
}

/// Content-free recording of provider boundary calls.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ZoteroProviderCall {
    Probe {
        scope_digest: Digest,
        transport: ZoteroTransportKind,
        provenance: ZoteroProvenance,
    },
    Read {
        scope_digest: Digest,
        target: ZoteroReadTarget,
        since_version: Option<ZoteroVersion>,
        conditional_version: Option<ZoteroVersion>,
    },
    Citation {
        scope_digest: Digest,
        item_key: ZoteroItemKey,
        style_digest: Digest,
        locale_digest: Digest,
    },
}

#[derive(Clone, Debug, Default)]
struct RecordingState {
    calls: Vec<ZoteroProviderCall>,
    probe: Option<Result<ZoteroCapabilityProbeResponse, ZoteroProviderError>>,
    read: Option<Result<ZoteroReadResponse, ZoteroProviderError>>,
    citation: Option<Result<ZoteroCitationResponse, ZoteroProviderError>>,
    fault: Option<ZoteroProviderError>,
}

/// Deterministic fixture/recording provider. It performs no network call and
/// never creates a Connected/native claim.
#[derive(Clone, Debug)]
pub struct RecordingZoteroProvider {
    manifest: Arc<Mutex<ZoteroProviderManifest>>,
    state: Arc<Mutex<RecordingState>>,
    secret_reference: Option<SecretReference>,
}

impl RecordingZoteroProvider {
    pub fn new(manifest: ZoteroProviderManifest) -> Self {
        Self {
            manifest: Arc::new(Mutex::new(manifest)),
            state: Arc::new(Mutex::new(RecordingState::default())),
            secret_reference: None,
        }
    }

    pub fn fixture(scope: ZoteroEvidenceScope) -> Result<Self, ZoteroEvidenceError> {
        Ok(Self::new(ZoteroProviderManifest::fixture(scope)?))
    }

    pub fn recording(scope: ZoteroEvidenceScope) -> Result<Self, ZoteroEvidenceError> {
        Ok(Self::new(ZoteroProviderManifest::recording(scope)?))
    }

    pub fn loopback(scope: ZoteroEvidenceScope) -> Result<Self, ZoteroEvidenceError> {
        Ok(Self::new(ZoteroProviderManifest::loopback(scope)?))
    }

    #[must_use]
    pub fn with_secret_reference(mut self, reference: SecretReference) -> Self {
        self.secret_reference = Some(reference);
        self
    }

    #[must_use]
    pub fn with_probe_response(self, response: ZoteroCapabilityProbeResponse) -> Self {
        self.set_probe_response(Ok(response));
        self
    }

    #[must_use]
    pub fn with_read_response(self, response: ZoteroReadResponse) -> Self {
        self.set_read_response(Ok(response));
        self
    }

    #[must_use]
    pub fn with_citation_response(self, response: ZoteroCitationResponse) -> Self {
        self.set_citation_response(Ok(response));
        self
    }

    #[must_use]
    pub fn with_fault(self, fault: ZoteroProviderError) -> Self {
        self.set_fault(fault);
        self
    }

    pub fn set_probe_response(
        &self,
        response: Result<ZoteroCapabilityProbeResponse, ZoteroProviderError>,
    ) {
        self.state.lock().expect("recording state lock").probe = Some(response);
    }

    pub fn set_read_response(&self, response: Result<ZoteroReadResponse, ZoteroProviderError>) {
        self.state.lock().expect("recording state lock").read = Some(response);
    }

    pub fn set_citation_response(
        &self,
        response: Result<ZoteroCitationResponse, ZoteroProviderError>,
    ) {
        self.state.lock().expect("recording state lock").citation = Some(response);
    }

    pub fn set_fault(&self, fault: ZoteroProviderError) {
        self.state.lock().expect("recording state lock").fault = Some(fault);
    }

    pub fn set_manifest(&self, manifest: ZoteroProviderManifest) {
        *self.manifest.lock().expect("manifest lock") = manifest;
    }

    pub fn current_manifest(&self) -> ZoteroProviderManifest {
        self.manifest.lock().expect("manifest lock").clone()
    }

    pub fn calls(&self) -> Vec<ZoteroProviderCall> {
        self.state
            .lock()
            .expect("recording state lock")
            .calls
            .clone()
    }

    fn fault(&self) -> Option<ZoteroProviderError> {
        self.state
            .lock()
            .expect("recording state lock")
            .fault
            .clone()
    }

    fn check_request_scope(
        &self,
        scope: &ZoteroEvidenceScope,
    ) -> Result<ZoteroProviderManifest, ZoteroProviderError> {
        let manifest = self.current_manifest();
        manifest
            .validate()
            .map_err(|_| ZoteroProviderError::ManifestMismatch)?;
        if &manifest.scope != scope {
            return Err(ZoteroProviderError::ScopeMismatch);
        }
        if matches!(
            manifest.authentication,
            ZoteroAuthenticationMode::SecretReference
        ) && self.secret_reference.is_none()
        {
            return Err(ZoteroProviderError::SecretReferenceRequired);
        }
        Ok(manifest)
    }

    fn default_item(
        scope: &ZoteroEvidenceScope,
    ) -> Result<ZoteroItemEvidence, ZoteroEvidenceError> {
        let metadata = crate::model::ZoteroMetadataDigests::from_parts(
            "Ada Lovelace",
            "A bounded research source",
            "1843",
            "doi:10.0000/fixture",
        )?;
        ZoteroItemEvidence::new(
            scope
                .item_key
                .clone()
                .unwrap_or_else(|| ZoteroItemKey::new("FIXTUREITEM").expect("fixture item key")),
            ZoteroVersion::new(11),
            scope.collection_key.clone().into_iter().collect(),
            crate::model::ZoteroObjectLifecycle::Present,
            metadata,
            crate::model::ZoteroAttachmentReferences::empty(),
        )
    }

    fn default_read(
        request: &ZoteroReadRequest,
        manifest: &ZoteroProviderManifest,
    ) -> Result<ZoteroReadResponse, ZoteroEvidenceError> {
        if request.conditional.as_ref().is_some_and(|conditional| {
            conditional.if_modified_since_version == ZoteroVersion::new(17)
        }) {
            return ZoteroReadResponse::new_304(request, manifest, ZoteroVersion::new(17));
        }
        let item = Self::default_item(&request.scope)?;
        ZoteroReadResponse::new_200(
            request,
            manifest,
            ZoteroVersion::new(17),
            ZoteroVersion::new(11),
            vec![item],
            None,
        )
    }

    fn default_citation(
        request: &ZoteroCitationRequest,
        manifest: &ZoteroProviderManifest,
    ) -> Result<ZoteroCitationResponse, ZoteroEvidenceError> {
        let item = Self::default_item(&request.scope)?;
        let metadata = crate::model::ZoteroCitationMetadata::from_item(
            &request.scope,
            ZoteroVersion::new(17),
            ZoteroVersion::new(11),
            &item,
        )?;
        ZoteroCitationResponse::recorded(
            request,
            manifest,
            metadata,
            "Lovelace, Ada. A bounded research source (1843).",
        )
    }
}

impl ZoteroEvidenceProvider for RecordingZoteroProvider {
    fn manifest(&self) -> ZoteroProviderManifest {
        self.current_manifest()
    }

    fn probe(
        &self,
        request: &ZoteroCapabilityProbeRequest,
    ) -> Result<ZoteroCapabilityProbeResponse, ZoteroProviderError> {
        if let Some(fault) = self.fault() {
            return Err(fault);
        }
        let manifest = self.check_request_scope(&request.scope)?;
        self.state
            .lock()
            .expect("recording state lock")
            .calls
            .push(ZoteroProviderCall::Probe {
                scope_digest: request.scope.digest(),
                transport: manifest.transport,
                provenance: manifest.provenance,
            });
        let configured = self
            .state
            .lock()
            .expect("recording state lock")
            .probe
            .clone();
        configured.unwrap_or_else(|| {
            Ok(ZoteroCapabilityProbeResponse::recorded(
                request,
                &manifest,
                if matches!(
                    manifest.authentication,
                    ZoteroAuthenticationMode::SecretReference
                ) {
                    crate::model::ZoteroLibraryVisibility::Private
                } else {
                    crate::model::ZoteroLibraryVisibility::Public
                },
                ZoteroVersion::new(17),
                None,
            ))
        })
    }

    fn read(&self, request: &ZoteroReadRequest) -> Result<ZoteroReadResponse, ZoteroProviderError> {
        if let Some(fault) = self.fault() {
            return Err(fault);
        }
        let manifest = self.check_request_scope(&request.scope)?;
        self.state
            .lock()
            .expect("recording state lock")
            .calls
            .push(ZoteroProviderCall::Read {
                scope_digest: request.scope.digest(),
                target: request.target.clone(),
                since_version: request.since.as_ref().map(|cursor| cursor.version),
                conditional_version: request
                    .conditional
                    .as_ref()
                    .map(|conditional| conditional.if_modified_since_version),
            });
        let configured = self
            .state
            .lock()
            .expect("recording state lock")
            .read
            .clone();
        configured.unwrap_or_else(|| {
            Self::default_read(request, &manifest)
                .map_err(|_| ZoteroProviderError::InvalidResponse { field: "read" })
        })
    }

    fn citation(
        &self,
        request: &ZoteroCitationRequest,
    ) -> Result<ZoteroCitationResponse, ZoteroProviderError> {
        if let Some(fault) = self.fault() {
            return Err(fault);
        }
        let manifest = self.check_request_scope(&request.scope)?;
        self.state
            .lock()
            .expect("recording state lock")
            .calls
            .push(ZoteroProviderCall::Citation {
                scope_digest: request.scope.digest(),
                item_key: request.item_key.clone(),
                style_digest: crate::model::sha256_digest(request.style.as_str().as_bytes()),
                locale_digest: crate::model::sha256_digest(request.locale.as_str().as_bytes()),
            });
        let configured = self
            .state
            .lock()
            .expect("recording state lock")
            .citation
            .clone();
        configured.unwrap_or_else(|| {
            Self::default_citation(request, &manifest)
                .map_err(|_| ZoteroProviderError::InvalidResponse { field: "citation" })
        })
    }
}

/// Named aliases make test intent explicit without creating a native client.
pub type FakeZoteroProvider = RecordingZoteroProvider;
pub type FixtureZoteroProvider = RecordingZoteroProvider;
pub type LoopbackZoteroProvider = RecordingZoteroProvider;
