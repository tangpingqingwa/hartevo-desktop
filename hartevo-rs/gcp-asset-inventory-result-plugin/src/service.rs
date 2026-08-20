//! Read-only Cloud Asset Inventory service and governed proposal lifecycle.

use std::{collections::BTreeMap, fmt};

use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginVersion, ProviderCardinality,
    ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AssetAnomaly, AssetInventoryEvidence, AssetInventoryEvidenceDigests, AssetInventoryQuery,
    AssetProjection, AssetType, Digest, EffectObservation, GcpAssetInventoryScope, ModelError,
    PartialReason, RedactedAsset, Revision, SearchBounds, SecretReference, contract_version_digest,
    plugin_version_digest,
};
use crate::provider::{
    GcpAssetInventoryProvider, GcpAssetInventoryProviderDefinition, GcpAssetInventoryProviderError,
    GcpAssetInventoryTransport, OpaquePageToken, ProviderFailureClass, ProviderProvenance,
    SearchAllResourcesPage, SearchAllResourcesProposal, SearchAllResourcesRecord,
    SearchAllResourcesRequest, SearchResponseStatus,
};
use crate::{
    GCP_ASSET_INVENTORY_CONTRACT_JSON, GCP_ASSET_INVENTORY_CONTRACT_VERSION,
    GCP_ASSET_INVENTORY_PLUGIN_VERSION_TEXT, GCP_ASSET_INVENTORY_PROVIDER_ID,
    GCP_ASSET_INVENTORY_PROVIDER_REVISION, GCP_ASSET_INVENTORY_PROVIDER_SCHEMA,
    GCP_ASSET_INVENTORY_SCHEMA_VERSION, GCP_ASSET_INVENTORY_SERVICE_ID,
    GCP_ASSET_INVENTORY_SERVICE_NAME, GCP_ASSET_INVENTORY_SERVICE_SCHEMA,
    MISSION_GCP_ASSET_INVENTORY_CONSUMER_ID,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpAssetInventoryOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ProposeSearchAllResources,
    ReadSearchAllResources,
    RecordSearchAllResources,
    VerifySearchAllResources,
    ConsumeObservation,
}

impl GcpAssetInventoryOperation {
    pub const ALL: [Self; 8] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ProposeSearchAllResources,
        Self::ReadSearchAllResources,
        Self::RecordSearchAllResources,
        Self::VerifySearchAllResources,
        Self::ConsumeObservation,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpAssetInventoryCapability {
    pub capability_id: String,
    pub operation: GcpAssetInventoryOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpAssetInventoryServiceDefinition {
    service_id: String,
    service_name: String,
    version: PluginVersion,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<GcpAssetInventoryCapability>,
}

impl Default for GcpAssetInventoryServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl GcpAssetInventoryServiceDefinition {
    pub fn new() -> Self {
        let capabilities = [
            (
                "gcp.asset-inventory.register",
                GcpAssetInventoryOperation::Register,
            ),
            (
                "gcp.asset-inventory.revoke_registration",
                GcpAssetInventoryOperation::RevokeRegistration,
            ),
            (
                "gcp.asset-inventory.propose_search_all_resources",
                GcpAssetInventoryOperation::ProposeSearchAllResources,
            ),
            (
                "gcp.asset-inventory.read_search_all_resources",
                GcpAssetInventoryOperation::ReadSearchAllResources,
            ),
            (
                "gcp.asset-inventory.record_search_all_resources",
                GcpAssetInventoryOperation::RecordSearchAllResources,
            ),
            (
                "gcp.asset-inventory.verify_search_all_resources",
                GcpAssetInventoryOperation::VerifySearchAllResources,
            ),
            (
                "gcp.asset-inventory.consume_observation",
                GcpAssetInventoryOperation::ConsumeObservation,
            ),
        ]
        .into_iter()
        .map(|(capability_id, operation)| GcpAssetInventoryCapability {
            capability_id: capability_id.to_owned(),
            operation,
            read_only: true,
            mutates_provider: false,
            native_evidence: false,
        })
        .collect();
        Self {
            service_id: GCP_ASSET_INVENTORY_SERVICE_ID.to_owned(),
            service_name: GCP_ASSET_INVENTORY_SERVICE_NAME.to_owned(),
            version: PluginVersion::new(1, 0, 0),
            read_only: true,
            native_connected: false,
            capabilities,
        }
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub const fn native_connected(&self) -> bool {
        self.native_connected
    }

    pub fn capabilities(&self) -> &[GcpAssetInventoryCapability] {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Vec<GcpAssetInventoryCapability> {
        self.capabilities.clone()
    }

    pub fn runtime_definition(&self) -> Result<ServiceDefinition, GcpAssetInventoryServiceError> {
        let service_id = ServiceId::new(self.service_id.clone())
            .map_err(GcpAssetInventoryServiceError::Plugin)?;
        ServiceDefinition::read_only(
            service_id,
            self.version,
            RuntimeDigest::from_text(GCP_ASSET_INVENTORY_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(GcpAssetInventoryServiceError::Plugin)
    }

    pub fn validate(&self) -> Result<(), GcpAssetInventoryServiceError> {
        if self.service_id != GCP_ASSET_INVENTORY_SERVICE_ID
            || self.service_name != GCP_ASSET_INVENTORY_SERVICE_NAME
            || self.version != PluginVersion::new(1, 0, 0)
            || !self.read_only
            || self.native_connected
            || self.capabilities.is_empty()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only || capability.mutates_provider || capability.native_evidence
            })
        {
            return Err(GcpAssetInventoryServiceError::ContractDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("GCP Asset Inventory registration is already revoked")]
    AlreadyRevoked,
}

/// Reversible registration binding all version, provider, permission, scope,
/// query, and opaque credential-reference digests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpAssetInventoryRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub version_digest: Digest,
    pub scope_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub query_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
}

impl GcpAssetInventoryRegistration {
    fn new(
        scope: &GcpAssetInventoryScope,
        secret: &SecretReference,
        provider: &GcpAssetInventoryProviderDefinition,
        query: &AssetInventoryQuery,
    ) -> Result<Self, ModelError> {
        let revision = Revision::new(1)?;
        let contract_digest = crate::contract_digest();
        let version_digest = plugin_version_digest();
        let permission_digest = query.permission_digest.clone();
        let provider_digest = provider.provider_digest();
        let registration_digest = Digest::from_serializable(&(
            GCP_ASSET_INVENTORY_PLUGIN_VERSION_TEXT,
            GCP_ASSET_INVENTORY_CONTRACT_VERSION,
            &contract_digest,
            &version_digest,
            &scope.scope_digest(),
            &provider.provider_id,
            &provider.provider_version,
            &provider.provider_revision,
            &provider_digest,
            &permission_digest,
            &query.query_digest,
            secret.reference_digest(),
            secret.revision(),
            revision,
        ));
        Ok(Self {
            plugin_version: GCP_ASSET_INVENTORY_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: GCP_ASSET_INVENTORY_CONTRACT_VERSION.to_owned(),
            contract_digest,
            version_digest,
            scope_digest: scope.scope_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_revision: provider.provider_revision.clone(),
            provider_digest,
            permission_digest,
            query_digest: query.query_digest.clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.revision(),
            revision,
            registration_digest,
            state: RegistrationState::Active,
        })
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn revoke(&mut self) -> Result<(), RegistrationError> {
        if !self.is_active() {
            return Err(RegistrationError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        Ok(())
    }

    pub fn verify_digest(&self) -> bool {
        let expected = Digest::from_serializable(&(
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.version_digest,
            &self.scope_digest,
            &self.provider_id,
            &self.provider_version,
            &self.provider_revision,
            &self.provider_digest,
            &self.permission_digest,
            &self.query_digest,
            &self.secret_reference_digest,
            self.credential_revision,
            self.revision,
        ));
        self.registration_digest == expected
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GcpAssetInventoryServiceError {
    #[error("GCP Asset Inventory registration is revoked")]
    RegistrationRevoked,
    #[error("GCP OAuth or service-account SecretReference is revoked")]
    SecretRevoked,
    #[error("GCP Asset Inventory scope or SecretReference binding does not match")]
    ScopeMismatch,
    #[error("GCP Asset Inventory service or provider definition drifted")]
    ContractDrift,
    #[error("GCP Asset Inventory registration is stale or tampered")]
    RegistrationTampered,
    #[error("GCP Asset Inventory proposal is stale or tampered")]
    ProposalTampered,
    #[error("GCP Asset Inventory searchAllResources response is stale or tampered")]
    RecordTampered,
    #[error("GCP Asset Inventory asset does not match the exact registered scope")]
    AssetScopeMismatch,
    #[error("GCP Asset Inventory cursor binding changed")]
    CursorMismatch,
    #[error("GCP Asset Inventory provider error: {0}")]
    Provider(#[from] GcpAssetInventoryProviderError),
    #[error("GCP Asset Inventory model error: {0}")]
    Model(#[from] ModelError),
    #[error("plugin runtime rejected the GCP Asset Inventory definition: {0}")]
    Plugin(#[from] hartevo_plugin_runtime::PluginError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchAllResourcesRead {
    pub record: SearchAllResourcesRecord,
    pub next_page_token: Option<OpaquePageToken>,
}

pub struct GcpAssetInventoryService<T>
where
    T: GcpAssetInventoryTransport,
{
    scope: GcpAssetInventoryScope,
    secret_reference: SecretReference,
    provider: GcpAssetInventoryProvider<T>,
    definition: GcpAssetInventoryServiceDefinition,
    registration: GcpAssetInventoryRegistration,
    query: AssetInventoryQuery,
    bounds: SearchBounds,
}

impl<T> fmt::Debug for GcpAssetInventoryService<T>
where
    T: GcpAssetInventoryTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpAssetInventoryService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("query_digest", &self.query.query_digest)
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

impl<T> GcpAssetInventoryService<T>
where
    T: GcpAssetInventoryTransport,
{
    pub fn new(
        scope: GcpAssetInventoryScope,
        secret_reference: SecretReference,
        provider: GcpAssetInventoryProvider<T>,
    ) -> Result<Self, GcpAssetInventoryServiceError> {
        Self::with_bounds(scope, secret_reference, provider, SearchBounds::default())
    }

    pub fn with_bounds(
        scope: GcpAssetInventoryScope,
        secret_reference: SecretReference,
        provider: GcpAssetInventoryProvider<T>,
        bounds: SearchBounds,
    ) -> Result<Self, GcpAssetInventoryServiceError> {
        if secret_reference.is_revoked() {
            return Err(GcpAssetInventoryServiceError::SecretRevoked);
        }
        if let Some(bound_scope_digest) = secret_reference.scope_digest()
            && bound_scope_digest != &scope.scope_digest()
        {
            return Err(GcpAssetInventoryServiceError::ScopeMismatch);
        }
        let definition = GcpAssetInventoryServiceDefinition::new();
        definition.validate()?;
        let provider_definition = provider.definition();
        if provider_definition.provider_id != GCP_ASSET_INVENTORY_PROVIDER_ID
            || provider_definition.schema_version != GCP_ASSET_INVENTORY_PROVIDER_SCHEMA
            || !provider_definition.search_all_resources
            || provider_definition.live_execution
            || provider_definition.native
            || provider_definition.bigquery_export
            || provider_definition.resource_mutation
            || provider.is_native()
        {
            return Err(GcpAssetInventoryServiceError::ContractDrift);
        }
        let permission_digest = scope.permission_digest();
        let query = AssetInventoryQuery::new(
            &scope,
            permission_digest,
            secret_reference.reference_digest().clone(),
            bounds,
        );
        let registration = GcpAssetInventoryRegistration::new(
            &scope,
            &secret_reference,
            provider_definition,
            &query,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            definition,
            registration,
            query,
            bounds,
        })
    }

    pub fn definition(&self) -> &GcpAssetInventoryServiceDefinition {
        &self.definition
    }

    pub fn scope(&self) -> &GcpAssetInventoryScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &GcpAssetInventoryProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut GcpAssetInventoryProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &GcpAssetInventoryRegistration {
        &self.registration
    }

    pub fn query(&self) -> &AssetInventoryQuery {
        &self.query
    }

    pub const fn bounds(&self) -> SearchBounds {
        self.bounds
    }

    pub fn is_registered(&self) -> bool {
        self.registration.is_active() && !self.secret_reference.is_revoked()
    }

    pub fn register(
        &mut self,
    ) -> Result<&GcpAssetInventoryRegistration, GcpAssetInventoryServiceError> {
        if self.secret_reference.is_revoked() {
            return Err(GcpAssetInventoryServiceError::SecretRevoked);
        }
        if matches!(self.registration.state, RegistrationState::Revoked) {
            self.registration.state = RegistrationState::Active;
        }
        Ok(&self.registration)
    }

    pub fn revoke_registration(&mut self) -> Result<(), GcpAssetInventoryServiceError> {
        self.registration
            .revoke()
            .map_err(|_| GcpAssetInventoryServiceError::RegistrationRevoked)
    }

    pub fn revoke_secret_reference(&mut self) {
        self.secret_reference.revoke();
        self.registration.state = RegistrationState::Revoked;
    }

    fn validate_active(&self) -> Result<(), GcpAssetInventoryServiceError> {
        if !self.registration.is_active() {
            return Err(GcpAssetInventoryServiceError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(GcpAssetInventoryServiceError::SecretRevoked);
        }
        if !self.registration.verify_digest()
            || self.registration.scope_digest != self.scope.scope_digest()
            || self.registration.query_digest != self.query.query_digest
            || self.registration.permission_digest != self.query.permission_digest
        {
            return Err(GcpAssetInventoryServiceError::RegistrationTampered);
        }
        Ok(())
    }

    pub fn propose_search_all_resources(
        &self,
        page_number: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<SearchAllResourcesProposal, GcpAssetInventoryServiceError> {
        self.validate_active()?;
        let request = SearchAllResourcesRequest::new(
            self.query.clone(),
            self.provider.definition().provider_digest(),
            self.provider.definition().provider_revision.clone(),
            page_number,
            page_token,
        )?;
        Ok(SearchAllResourcesProposal::new(
            self.registration.registration_digest.clone(),
            self.registration.revision,
            request,
        ))
    }

    pub fn read_search_all_resources(
        &mut self,
        proposal: &SearchAllResourcesProposal,
    ) -> Result<SearchAllResourcesRecord, GcpAssetInventoryServiceError> {
        Ok(self.read_search_all_resources_with_token(proposal)?.record)
    }

    pub fn read_search_all_resources_with_token(
        &mut self,
        proposal: &SearchAllResourcesProposal,
    ) -> Result<SearchAllResourcesRead, GcpAssetInventoryServiceError> {
        self.validate_proposal(proposal)?;
        let page = self.provider.read(proposal.request())?;
        let next_page_token = page.next_page_token().cloned();
        let record = self.record_search_all_resources(proposal, &page)?;
        self.verify_search_all_resources(proposal, &record)?;
        Ok(SearchAllResourcesRead {
            record,
            next_page_token,
        })
    }

    pub fn record_search_all_resources(
        &self,
        proposal: &SearchAllResourcesProposal,
        page: &SearchAllResourcesPage,
    ) -> Result<SearchAllResourcesRecord, GcpAssetInventoryServiceError> {
        self.validate_proposal(proposal)?;
        if !page.verify_digest(proposal.request()) {
            return Err(GcpAssetInventoryServiceError::RecordTampered);
        }
        if page
            .assets
            .iter()
            .any(|asset| !asset.matches_scope(&self.scope))
        {
            return Err(GcpAssetInventoryServiceError::AssetScopeMismatch);
        }
        Ok(self.provider.record(proposal, page)?)
    }

    pub fn verify_search_all_resources(
        &self,
        proposal: &SearchAllResourcesProposal,
        record: &SearchAllResourcesRecord,
    ) -> Result<(), GcpAssetInventoryServiceError> {
        self.validate_proposal(proposal)?;
        self.provider.verify(proposal, record)?;
        if record.scope_digest != self.scope.scope_digest()
            || record.permission_digest != self.query.permission_digest
            || record.secret_reference_digest != self.query.secret_reference_digest
            || record
                .assets
                .iter()
                .any(|asset| !asset.matches_scope(&self.scope))
        {
            return Err(GcpAssetInventoryServiceError::RecordTampered);
        }
        Ok(())
    }

    fn validate_proposal(
        &self,
        proposal: &SearchAllResourcesProposal,
    ) -> Result<(), GcpAssetInventoryServiceError> {
        self.validate_active()?;
        if !proposal.verify_digest()
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
            || proposal.provider_digest != self.registration.provider_digest
            || proposal.provider_revision != self.registration.provider_revision
            || proposal.query.query_digest != self.query.query_digest
            || !proposal.query.verify_digest()
        {
            return Err(GcpAssetInventoryServiceError::ProposalTampered);
        }
        Ok(())
    }

    /// Read a bounded sequence of `searchAllResources` pages and return
    /// content-free, deduplicated, deterministically ordered evidence.
    pub fn read_bounded(
        &mut self,
    ) -> Result<AssetInventoryEvidence, GcpAssetInventoryServiceError> {
        self.validate_active()?;
        let mut page_number = 1;
        let mut page_token = None;
        let mut reads = Vec::new();
        let mut projection = AssetProjection::Complete;
        let mut anomalies = Vec::new();
        let mut failure_digest = None;

        loop {
            if page_number > self.bounds.max_pages {
                projection = AssetProjection::Partial(PartialReason::PageCap);
                break;
            }
            let proposal = self.propose_search_all_resources(page_number, page_token.clone())?;
            match self.read_search_all_resources_with_token(&proposal) {
                Ok(read) => {
                    let has_more = read.next_page_token.is_some();
                    if read.record.response_status == SearchResponseStatus::Warning {
                        projection = AssetProjection::Partial(PartialReason::ProviderWarning);
                    }
                    reads.push(read);
                    if !has_more {
                        break;
                    }
                    page_token = reads.last().and_then(|read| read.next_page_token.clone());
                    page_number = page_number.saturating_add(1);
                }
                Err(GcpAssetInventoryServiceError::Provider(error)) => {
                    let class = error.class();
                    projection = class.projection();
                    failure_digest = Some(error.diagnostic_digest());
                    if class == ProviderFailureClass::ReplayDetected {
                        anomalies.push(AssetAnomaly::ReplayDetected);
                    }
                    break;
                }
                Err(error) => return Err(error),
            }
        }

        let mut evidence = self.build_evidence(&reads, projection, anomalies, failure_digest)?;
        if evidence.unique_asset_count > self.bounds.max_assets {
            evidence
                .assets
                .truncate(usize::from(self.bounds.max_assets));
            evidence.unique_asset_count = self.bounds.max_assets;
            evidence.projection = AssetProjection::Partial(PartialReason::AssetCap);
            evidence.digests.evidence_digest = evidence.compute_evidence_digest();
        }
        Ok(evidence)
    }

    pub fn build_evidence(
        &self,
        reads: &[SearchAllResourcesRead],
        mut projection: AssetProjection,
        mut anomalies: Vec<AssetAnomaly>,
        provider_failure_digest: Option<Digest>,
    ) -> Result<AssetInventoryEvidence, GcpAssetInventoryServiceError> {
        let mut asset_map: BTreeMap<Digest, RedactedAsset> = BTreeMap::new();
        let mut raw_asset_count: u16 = 0;
        let mut duplicate_asset_count: u16 = 0;
        let mut original_order = Vec::new();
        let mut record_digests = Vec::new();
        let mut page_token_chain = Vec::new();

        for read in reads {
            self.validate_record_without_proposal(&read.record)?;
            record_digests.push(read.record.record_digest.clone());
            page_token_chain.push(read.record.next_page_token_digest.clone());
            for asset in &read.record.assets {
                raw_asset_count = raw_asset_count.saturating_add(1);
                original_order.push((asset.asset_type.clone(), asset.resource_name_digest.clone()));
                if let Some(previous) = asset_map.get(&asset.resource_name_digest) {
                    if previous.asset_digest != asset.asset_digest {
                        return Err(GcpAssetInventoryServiceError::RecordTampered);
                    }
                    duplicate_asset_count = duplicate_asset_count.saturating_add(1);
                    if !anomalies.contains(&AssetAnomaly::DuplicateAsset) {
                        anomalies.push(AssetAnomaly::DuplicateAsset);
                    }
                } else {
                    asset_map.insert(asset.resource_name_digest.clone(), asset.clone());
                }
            }
        }

        let mut assets: Vec<_> = asset_map.into_values().collect();
        assets.sort_by(|left, right| {
            (&left.asset_type, &left.resource_name_digest)
                .cmp(&(&right.asset_type, &right.resource_name_digest))
        });
        let sorted_order: Vec<_> = assets
            .iter()
            .map(|asset| (asset.asset_type.clone(), asset.resource_name_digest.clone()))
            .collect();
        if original_order != sorted_order && !assets.is_empty() {
            anomalies.push(AssetAnomaly::OrderNormalized);
        }
        if reads
            .iter()
            .any(|read| read.record.response_status == SearchResponseStatus::Warning)
        {
            projection = AssetProjection::Partial(PartialReason::ProviderWarning);
        }
        let page_token_chain_digest = Digest::from_serializable(&page_token_chain);
        let mut evidence = AssetInventoryEvidence {
            schema_version: GCP_ASSET_INVENTORY_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_ASSET_INVENTORY_CONTRACT_VERSION.to_owned(),
            plugin_version: GCP_ASSET_INVENTORY_PLUGIN_VERSION_TEXT.to_owned(),
            scope_digest: self.scope.scope_digest(),
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            provider_id: GCP_ASSET_INVENTORY_PROVIDER_ID.to_owned(),
            provider_version: self.registration.provider_version.clone(),
            provider_revision: self.registration.provider_revision.clone(),
            page_count: u16::try_from(reads.len()).unwrap_or(u16::MAX),
            raw_asset_count,
            unique_asset_count: u16::try_from(assets.len()).unwrap_or(u16::MAX),
            duplicate_asset_count,
            projection,
            assets,
            record_digests,
            page_token_chain_digest,
            anomalies,
            effect_observation: EffectObservation::NoExternalEffectClaim,
            provider_failure_digest,
            digests: AssetInventoryEvidenceDigests {
                version_digest: plugin_version_digest(),
                provider_digest: self.registration.provider_digest.clone(),
                contract_digest: crate::contract_digest(),
                permission_digest: self.query.permission_digest.clone(),
                scope_digest: self.scope.scope_digest(),
                query_digest: self.query.query_digest.clone(),
                evidence_digest: Digest::from_text("placeholder"),
            },
        };
        evidence.digests.evidence_digest = evidence.compute_evidence_digest();
        Ok(evidence)
    }

    fn validate_record_without_proposal(
        &self,
        record: &SearchAllResourcesRecord,
    ) -> Result<(), GcpAssetInventoryServiceError> {
        if !record.verify_integrity()
            || record.registration_digest != self.registration.registration_digest
            || record.registration_revision != self.registration.revision
            || record.provider_digest != self.registration.provider_digest
            || record.provider_revision != self.registration.provider_revision
            || record.query_digest != self.query.query_digest
            || record.scope_digest != self.scope.scope_digest()
            || record.permission_digest != self.query.permission_digest
            || record.secret_reference_digest != self.query.secret_reference_digest
            || record
                .assets
                .iter()
                .any(|asset| !asset.matches_scope(&self.scope))
        {
            return Err(GcpAssetInventoryServiceError::RecordTampered);
        }
        Ok(())
    }
}

impl<T> GcpAssetInventoryService<T>
where
    T: GcpAssetInventoryTransport,
{
    pub fn provider_definition(&self) -> &GcpAssetInventoryProviderDefinition {
        self.provider.definition()
    }

    pub fn provider_provenance(&self) -> ProviderProvenance {
        self.provider.provenance()
    }
}

pub fn contract_json_is_embedded() -> bool {
    !GCP_ASSET_INVENTORY_CONTRACT_JSON.trim().is_empty()
        && contract_version_digest() != Digest::from_text("placeholder")
}

pub fn consumer_id() -> &'static str {
    MISSION_GCP_ASSET_INVENTORY_CONSUMER_ID
}

pub fn provider_revision() -> &'static str {
    GCP_ASSET_INVENTORY_PROVIDER_REVISION
}

#[allow(dead_code)]
fn _typed_asset_fields(_: &AssetType) {}
