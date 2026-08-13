use std::fmt;

use super::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId as PluginConsumerId, ConsumerKind,
    Digest as PluginDigest, PLUGIN_INSPECTION_SCHEMA, PluginContributions, PluginDefinition,
    PluginDefinitionHandle, PluginError, PluginId, PluginRuntime, PluginScope, PluginVersion,
    ProviderCardinality, ProviderDefinition, ProviderId as PluginProviderId, RegistrationReceipt,
    RevocationReceipt as PluginRevocationReceipt, RuntimeInspection, ServiceAccess,
    ServiceDefinition, ServiceId as PluginServiceId, UnmountReceipt as PluginUnmountReceipt,
};
use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use hartevo_capability_gateway::{
    CAPABILITY_REQUEST_SCHEMA, CapabilityAdapter, CapabilityClass, CapabilityGateway,
    CapabilityManifest, CapabilityRequest, CapabilityResult, Digest, GatewayError,
    InvocationLedger, InvocationPermit, SignedCapabilityManifest, digest_serialized,
};

pub const CAPABILITY_PLUGIN_INSPECTION_SCHEMA: &str = "hartevo.capability-plugin-inspection/v1";
pub const CAPABILITY_MOUNT_RECEIPT_SCHEMA: &str = "hartevo.capability-mount-receipt/v1";
pub const CAPABILITY_INVOCATION_RECEIPT_SCHEMA: &str = "hartevo.capability-invocation-receipt/v1";

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CapabilityPluginError {
    #[error("plugin runtime error: {0}")]
    Plugin(#[from] PluginError),
    #[error("capability gateway error: {0}")]
    Gateway(#[from] GatewayError),
    #[error("read-only capability plugin requires a Read manifest")]
    NotReadOnly,
    #[error("plugin capability scope does not match the manifest")]
    ScopeMismatch,
    #[error("mounted capability contributions are unavailable")]
    CompositionUnavailable,
    #[error("capability invocation receipt does not match mounted composition")]
    InvocationReceiptMismatch,
    #[error("capability plugin binding drifted")]
    BindingDrift,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MountReceiptBody<'a> {
    schema: &'static str,
    plugin_registration_digest: &'a PluginDigest,
    plugin_digest: &'a PluginDigest,
    scope_digest: &'a PluginDigest,
    manifest_digest: &'a Digest,
    manifest_version: u32,
    adapter_binding_digest: &'a Digest,
    adapter_registry_revision: u64,
    revocation_epoch: u64,
    service_id_digest: &'a PluginDigest,
    provider_id_digest: &'a PluginDigest,
    consumer_id_digest: &'a PluginDigest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityMountReceipt {
    plugin_receipt: RegistrationReceipt,
    plugin_digest: PluginDigest,
    scope_digest: PluginDigest,
    manifest_digest: Digest,
    manifest_version: u32,
    adapter_binding_digest: Digest,
    adapter_registry_revision: u64,
    revocation_epoch: u64,
    service_id_digest: PluginDigest,
    provider_id_digest: PluginDigest,
    consumer_id_digest: PluginDigest,
    receipt_digest: Digest,
}

impl CapabilityMountReceipt {
    fn new(
        plugin_receipt: RegistrationReceipt,
        manifest: &CapabilityManifest,
        plugin_digest: PluginDigest,
        service_id: &PluginServiceId,
        provider_id: &PluginProviderId,
        consumer_id: &PluginConsumerId,
    ) -> Result<Self, CapabilityPluginError> {
        let scope_digest = plugin_receipt.scope_digest();
        let manifest_digest = manifest.digest()?;
        let adapter_binding_digest = manifest.adapter.digest();
        let service_id_digest = PluginDigest::from_text(service_id.as_str());
        let provider_id_digest = PluginDigest::from_text(provider_id.as_str());
        let consumer_id_digest = PluginDigest::from_text(consumer_id.as_str());
        let mut receipt = Self {
            plugin_digest,
            scope_digest,
            manifest_digest,
            manifest_version: manifest.manifest_version,
            adapter_binding_digest,
            adapter_registry_revision: manifest.revocation.registry_revision,
            revocation_epoch: manifest.revocation.revocation_epoch,
            service_id_digest,
            provider_id_digest,
            consumer_id_digest,
            plugin_receipt,
            receipt_digest: Digest::from_text("unsealed-capability-mount-receipt"),
        };
        receipt.receipt_digest = receipt.computed_digest();
        Ok(receipt)
    }

    pub fn digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub fn plugin_digest(&self) -> &PluginDigest {
        &self.plugin_digest
    }

    pub fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }

    pub fn scope_digest(&self) -> &PluginDigest {
        &self.scope_digest
    }

    pub const fn adapter_registry_revision(&self) -> u64 {
        self.adapter_registry_revision
    }

    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    pub const fn generation(&self) -> u64 {
        self.plugin_receipt.generation()
    }

    fn computed_digest(&self) -> Digest {
        let body = MountReceiptBody {
            schema: CAPABILITY_MOUNT_RECEIPT_SCHEMA,
            plugin_registration_digest: self.plugin_receipt.digest(),
            plugin_digest: &self.plugin_digest,
            scope_digest: &self.scope_digest,
            manifest_digest: &self.manifest_digest,
            manifest_version: self.manifest_version,
            adapter_binding_digest: &self.adapter_binding_digest,
            adapter_registry_revision: self.adapter_registry_revision,
            revocation_epoch: self.revocation_epoch,
            service_id_digest: &self.service_id_digest,
            provider_id_digest: &self.provider_id_digest,
            consumer_id_digest: &self.consumer_id_digest,
        };
        digest_serialized(&body)
    }

    fn validate(&self) -> bool {
        self.receipt_digest == self.computed_digest()
            && self.plugin_receipt.plugin_digest() == &self.plugin_digest
            && self.plugin_receipt.scope_digest() == self.scope_digest
            && self.plugin_receipt.generation() == self.generation()
            && self.plugin_receipt.registry_revision() > 0
            && self.adapter_registry_revision > 0
            && self.revocation_epoch > 0
    }
}

impl Serialize for CapabilityMountReceipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityMountReceipt", 14)?;
        state.serialize_field("schema", CAPABILITY_MOUNT_RECEIPT_SCHEMA)?;
        state.serialize_field("receiptDigest", &self.receipt_digest)?;
        state.serialize_field("pluginRegistrationDigest", self.plugin_receipt.digest())?;
        state.serialize_field("pluginDigest", &self.plugin_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("manifestDigest", &self.manifest_digest)?;
        state.serialize_field("manifestVersion", &self.manifest_version)?;
        state.serialize_field("adapterBindingDigest", &self.adapter_binding_digest)?;
        state.serialize_field("adapterRegistryRevision", &self.adapter_registry_revision)?;
        state.serialize_field("revocationEpoch", &self.revocation_epoch)?;
        state.serialize_field("generation", &self.generation())?;
        state.serialize_field("serviceIdDigest", &self.service_id_digest)?;
        state.serialize_field("providerIdDigest", &self.provider_id_digest)?;
        state.serialize_field("consumerIdDigest", &self.consumer_id_digest)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityMountReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityMountReceipt")
            .field("receipt_digest", &self.receipt_digest)
            .field("plugin_registration_digest", self.plugin_receipt.digest())
            .field("plugin_digest", &self.plugin_digest)
            .field("scope_digest", &self.scope_digest)
            .field("manifest_digest", &self.manifest_digest)
            .field("manifest_version", &self.manifest_version)
            .field("adapter_binding_digest", &self.adapter_binding_digest)
            .field("adapter_registry_revision", &self.adapter_registry_revision)
            .field("revocation_epoch", &self.revocation_epoch)
            .field("generation", &self.generation())
            .field("service_id_digest", &self.service_id_digest)
            .field("provider_id_digest", &self.provider_id_digest)
            .field("consumer_id_digest", &self.consumer_id_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct InvocationReceiptBody<'a> {
    schema: &'static str,
    mount_receipt_digest: &'a PluginDigest,
    plugin_digest: &'a PluginDigest,
    scope_digest: &'a PluginDigest,
    manifest_digest: &'a Digest,
    request_digest: &'a Digest,
    class: CapabilityClass,
    generation: u64,
    adapter_registry_revision: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityInvocationReceipt {
    mount_receipt_digest: PluginDigest,
    plugin_digest: PluginDigest,
    scope_digest: PluginDigest,
    manifest_digest: Digest,
    request_digest: Digest,
    class: CapabilityClass,
    generation: u64,
    adapter_registry_revision: u64,
    permit: InvocationPermit,
    receipt_digest: Digest,
}

impl CapabilityInvocationReceipt {
    fn new(mount: &CapabilityMountReceipt, permit: InvocationPermit) -> Self {
        let mut receipt = Self {
            mount_receipt_digest: PluginDigest::from_text("pending-mount-receipt"),
            plugin_digest: mount.plugin_digest.clone(),
            scope_digest: mount.scope_digest.clone(),
            manifest_digest: permit.manifest_digest.clone(),
            request_digest: permit.request_digest.clone(),
            class: permit.class,
            generation: permit.generation,
            adapter_registry_revision: mount.adapter_registry_revision,
            permit,
            receipt_digest: Digest::from_text("unsealed-capability-invocation-receipt"),
        };
        receipt.mount_receipt_digest = PluginDigest::from_text(mount.digest().as_str());
        receipt.receipt_digest = receipt.computed_digest();
        receipt
    }

    pub fn digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }

    pub fn mount_receipt_digest(&self) -> &PluginDigest {
        &self.mount_receipt_digest
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn class(&self) -> CapabilityClass {
        self.class
    }

    fn computed_digest(&self) -> Digest {
        let body = InvocationReceiptBody {
            schema: CAPABILITY_INVOCATION_RECEIPT_SCHEMA,
            mount_receipt_digest: &self.mount_receipt_digest,
            plugin_digest: &self.plugin_digest,
            scope_digest: &self.scope_digest,
            manifest_digest: &self.manifest_digest,
            request_digest: &self.request_digest,
            class: self.class,
            generation: self.generation,
            adapter_registry_revision: self.adapter_registry_revision,
        };
        digest_serialized(&body)
    }
}

impl Serialize for CapabilityInvocationReceipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CapabilityInvocationReceipt", 10)?;
        state.serialize_field("schema", CAPABILITY_INVOCATION_RECEIPT_SCHEMA)?;
        state.serialize_field("receiptDigest", &self.receipt_digest)?;
        state.serialize_field("mountReceiptDigest", &self.mount_receipt_digest)?;
        state.serialize_field("pluginDigest", &self.plugin_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("manifestDigest", &self.manifest_digest)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("class", &self.class)?;
        state.serialize_field("generation", &self.generation)?;
        state.serialize_field("adapterRegistryRevision", &self.adapter_registry_revision)?;
        state.end()
    }
}

impl fmt::Debug for CapabilityInvocationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityInvocationReceipt")
            .field("receipt_digest", &self.receipt_digest)
            .field("mount_receipt_digest", &self.mount_receipt_digest)
            .field("plugin_digest", &self.plugin_digest)
            .field("scope_digest", &self.scope_digest)
            .field("manifest_digest", &self.manifest_digest)
            .field("request_digest", &self.request_digest)
            .field("class", &self.class)
            .field("generation", &self.generation)
            .field("adapter_registry_revision", &self.adapter_registry_revision)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityPluginInspection {
    pub schema: String,
    pub mounted: bool,
    pub plugin_digest: PluginDigest,
    pub registration_digest: PluginDigest,
    pub scope_digest: PluginDigest,
    pub manifest_digest: Digest,
    pub generation: u64,
    pub adapter_registry_revision: u64,
    pub revocation_epoch: u64,
    pub service_id_digest: PluginDigest,
    pub provider_id_digest: PluginDigest,
    pub consumer_id_digest: PluginDigest,
    pub provider_count: usize,
    pub consumer_count: usize,
}

/// A capability-gateway facade backed by the plugin runtime's existing
/// service/provider/consumer composition. It stores the trusted adapter as a
/// generic typed value; the plugin registry only receives descriptors and
/// never a host handle, Secret, executable callback, or arbitrary command.
pub struct MountedReadOnlyCapability<A> {
    runtime: PluginRuntime,
    gateway: CapabilityGateway,
    signed_manifest: SignedCapabilityManifest,
    adapter: A,
    definition: PluginDefinitionHandle,
    plugin_receipt: RegistrationReceipt,
    scope: PluginScope,
    mount_receipt: CapabilityMountReceipt,
    service_id: PluginServiceId,
    provider_id: PluginProviderId,
    consumer_id: PluginConsumerId,
}

impl<A: CapabilityAdapter> fmt::Debug for MountedReadOnlyCapability<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inspection = self.inspection();
        formatter
            .debug_struct("MountedReadOnlyCapability")
            .field("mounted", &inspection.mounted)
            .field("manifest_digest", &inspection.manifest_digest)
            .field("plugin_digest", &inspection.plugin_digest)
            .field("scope_digest", &inspection.scope_digest)
            .field("generation", &inspection.generation)
            .field(
                "adapter_registry_revision",
                &inspection.adapter_registry_revision,
            )
            .field("mount_receipt_digest", self.mount_receipt.digest())
            .finish_non_exhaustive()
    }
}

impl<A: CapabilityAdapter> MountedReadOnlyCapability<A> {
    pub fn mount(
        mut runtime: PluginRuntime,
        gateway: CapabilityGateway,
        signed_manifest: SignedCapabilityManifest,
        adapter: A,
        version: PluginVersion,
        scope: PluginScope,
        now: DateTime<Utc>,
    ) -> Result<Self, CapabilityPluginError> {
        signed_manifest.verify(now)?;
        let manifest = &signed_manifest.manifest;
        if manifest.class != CapabilityClass::Read {
            return Err(CapabilityPluginError::NotReadOnly);
        }
        let manifest_scope = plugin_scope(manifest)?;
        if manifest_scope != scope {
            return Err(CapabilityPluginError::ScopeMismatch);
        }
        if adapter.binding() != &manifest.adapter
            || gateway.registry().revision != manifest.revocation.registry_revision
        {
            return Err(CapabilityPluginError::BindingDrift);
        }
        gateway.registry().authorize(
            &manifest.adapter,
            &manifest.capability_id,
            &manifest.revocation,
        )?;

        let manifest_digest = signed_manifest.digest()?;
        let plugin_manifest_digest = PluginDigest::parse(manifest_digest.as_str())?;
        let implementation_digest =
            PluginDigest::parse(manifest.adapter.implementation_digest.as_str())?;
        let plugin_id = PluginId::new(format!("capability.plugin.d{}", manifest_digest.as_str()))?;
        let service_id =
            PluginServiceId::new(format!("capability.service.d{}", manifest_digest.as_str()))?;
        let provider_id =
            PluginProviderId::new(format!("capability.provider.d{}", manifest_digest.as_str()))?;
        let consumer_id =
            PluginConsumerId::new(format!("mission.consumer.d{}", manifest_digest.as_str()))?;
        let service = ServiceDefinition::read_only(
            service_id.clone(),
            version,
            plugin_manifest_digest.clone(),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::Exact,
        )?;
        let provider = ProviderDefinition::new(
            provider_id.clone(),
            service_id.clone(),
            version,
            implementation_digest,
        )?;
        let consumer = ConsumerDefinition::tool(
            consumer_id.clone(),
            service_id.clone(),
            version,
            PluginDigest::from_text(CAPABILITY_REQUEST_SCHEMA),
        )?;
        let definition = PluginDefinition::new(
            plugin_id,
            version,
            scope.clone(),
            PluginContributions {
                services: vec![service],
                providers: vec![provider],
                consumers: vec![consumer],
                events: Vec::new(),
                ui_surfaces: Vec::new(),
            },
        )?;
        let definition_handle = runtime.define(definition)?;
        let plugin_receipt = runtime.mount_in_scope(&definition_handle, &scope)?;
        let composition = runtime.inspect(&scope);
        if !composition_matches(
            &composition,
            &scope,
            plugin_receipt.plugin_digest(),
            plugin_receipt.digest(),
            &service_id,
            &provider_id,
            &consumer_id,
            &plugin_manifest_digest,
            &PluginDigest::parse(manifest.adapter.implementation_digest.as_str())?,
            version,
        ) {
            let _ = runtime.unmount(&plugin_receipt);
            return Err(CapabilityPluginError::CompositionUnavailable);
        }
        let mount_receipt = CapabilityMountReceipt::new(
            plugin_receipt.clone(),
            manifest,
            plugin_receipt.plugin_digest().clone(),
            &service_id,
            &provider_id,
            &consumer_id,
        )?;
        Ok(Self {
            runtime,
            gateway,
            signed_manifest,
            adapter,
            definition: definition_handle,
            plugin_receipt,
            scope,
            mount_receipt,
            service_id,
            provider_id,
            consumer_id,
        })
    }

    pub fn resolve(
        &self,
        request: &CapabilityRequest,
        now: DateTime<Utc>,
    ) -> Result<CapabilityInvocationReceipt, CapabilityPluginError> {
        self.ensure_composition()?;
        let permit = self
            .gateway
            .authorize(&self.signed_manifest, request, now)?;
        if permit.class != CapabilityClass::Read
            || permit.generation != self.mount_receipt.generation()
            || permit.manifest_digest != *self.mount_receipt.manifest_digest()
        {
            return Err(CapabilityPluginError::InvocationReceiptMismatch);
        }
        Ok(CapabilityInvocationReceipt::new(
            &self.mount_receipt,
            permit,
        ))
    }

    pub fn invoke_resolved<L>(
        &self,
        receipt: &CapabilityInvocationReceipt,
        request: &CapabilityRequest,
        ledger: &mut L,
        now: DateTime<Utc>,
    ) -> Result<CapabilityResult, CapabilityPluginError>
    where
        L: InvocationLedger,
    {
        if !self.receipt_matches(receipt, request) {
            return Err(CapabilityPluginError::InvocationReceiptMismatch);
        }
        Ok(CapabilityGateway::dispatch_with_permit(
            &self.signed_manifest,
            &receipt.permit,
            request,
            &self.adapter,
            ledger,
            now,
        )?)
    }

    pub fn unmount(&mut self) -> Result<PluginUnmountReceipt, CapabilityPluginError> {
        Ok(self.runtime.unmount(&self.plugin_receipt)?)
    }

    pub fn revoke(&mut self) -> Result<PluginRevocationReceipt, CapabilityPluginError> {
        Ok(self.runtime.revoke(&self.definition)?)
    }

    pub fn mount_receipt(&self) -> &CapabilityMountReceipt {
        &self.mount_receipt
    }

    pub fn inspection(&self) -> CapabilityPluginInspection {
        let composition = self.runtime.inspect(&self.scope);
        CapabilityPluginInspection {
            schema: CAPABILITY_PLUGIN_INSPECTION_SCHEMA.into(),
            mounted: composition_matches(
                &composition,
                &self.scope,
                self.plugin_receipt.plugin_digest(),
                self.plugin_receipt.digest(),
                &self.service_id,
                &self.provider_id,
                &self.consumer_id,
                &PluginDigest::parse(self.mount_receipt.manifest_digest.as_str())
                    .unwrap_or_else(|_| PluginDigest::from_text("invalid-manifest-digest")),
                &PluginDigest::parse(
                    self.signed_manifest
                        .manifest
                        .adapter
                        .implementation_digest
                        .as_str(),
                )
                .unwrap_or_else(|_| PluginDigest::from_text("invalid-implementation-digest")),
                self.definition.version(),
            ),
            plugin_digest: self.plugin_receipt.plugin_digest().clone(),
            registration_digest: self.plugin_receipt.digest().clone(),
            scope_digest: self.scope.digest(),
            manifest_digest: self
                .signed_manifest
                .digest()
                .unwrap_or_else(|_| Digest::from_text("invalid-manifest-digest")),
            generation: self.scope.generation(),
            adapter_registry_revision: self.mount_receipt.adapter_registry_revision,
            revocation_epoch: self.mount_receipt.revocation_epoch,
            service_id_digest: PluginDigest::from_text(self.service_id.as_str()),
            provider_id_digest: PluginDigest::from_text(self.provider_id.as_str()),
            consumer_id_digest: PluginDigest::from_text(self.consumer_id.as_str()),
            provider_count: composition.providers.len(),
            consumer_count: composition.consumers.len(),
        }
    }

    pub fn composition_inspection(&self) -> RuntimeInspection {
        self.runtime.inspect(&self.scope)
    }

    pub fn inspect_scope(&self, scope: &PluginScope) -> RuntimeInspection {
        self.runtime.inspect(scope)
    }

    fn ensure_composition(&self) -> Result<(), CapabilityPluginError> {
        let manifest = &self.signed_manifest.manifest;
        if self.gateway.registry().revision != manifest.revocation.registry_revision
            || self.adapter.binding() != &manifest.adapter
            || !self.mount_receipt.validate()
        {
            return Err(CapabilityPluginError::BindingDrift);
        }
        let composition = self.runtime.inspect(&self.scope);
        if !composition_matches(
            &composition,
            &self.scope,
            self.plugin_receipt.plugin_digest(),
            self.plugin_receipt.digest(),
            &self.service_id,
            &self.provider_id,
            &self.consumer_id,
            &PluginDigest::parse(manifest.digest()?.as_str())?,
            &PluginDigest::parse(manifest.adapter.implementation_digest.as_str())?,
            self.definition.version(),
        ) {
            return Err(CapabilityPluginError::CompositionUnavailable);
        }
        Ok(())
    }

    fn receipt_matches(
        &self,
        receipt: &CapabilityInvocationReceipt,
        request: &CapabilityRequest,
    ) -> bool {
        receipt.receipt_digest == receipt.computed_digest()
            && receipt.mount_receipt_digest
                == PluginDigest::from_text(self.mount_receipt.digest().as_str())
            && receipt.plugin_digest == *self.plugin_receipt.plugin_digest()
            && receipt.scope_digest == self.scope.digest()
            && receipt.manifest_digest == self.mount_receipt.manifest_digest
            && receipt.request_digest == request.digest()
            && receipt.class == request.class
            && receipt.class == CapabilityClass::Read
            && receipt.generation == request.generation
            && receipt.generation == self.mount_receipt.generation()
            && receipt.adapter_registry_revision == self.mount_receipt.adapter_registry_revision
            && receipt.permit.request_digest == receipt.request_digest
            && receipt.permit.manifest_digest == receipt.manifest_digest
            && receipt.permit.class == receipt.class
            && receipt.permit.generation == receipt.generation
    }
}

fn plugin_scope(manifest: &CapabilityManifest) -> Result<PluginScope, CapabilityPluginError> {
    Ok(PluginScope::new(
        super::ProjectId::new(manifest.mission.project_id.as_str().to_owned())?,
        super::MissionId::new(manifest.mission.mission_id.as_str().to_owned())?,
        manifest.mission.generation,
    )?)
}

#[allow(clippy::too_many_arguments)]
fn composition_matches(
    inspection: &RuntimeInspection,
    scope: &PluginScope,
    plugin_digest: &PluginDigest,
    registration_digest: &PluginDigest,
    service_id: &PluginServiceId,
    provider_id: &PluginProviderId,
    consumer_id: &PluginConsumerId,
    contract_digest: &PluginDigest,
    implementation_digest: &PluginDigest,
    version: PluginVersion,
) -> bool {
    let service_id_digest = PluginDigest::from_text(service_id.as_str());
    let provider_id_digest = PluginDigest::from_text(provider_id.as_str());
    let consumer_id_digest = PluginDigest::from_text(consumer_id.as_str());
    inspection.schema == PLUGIN_INSPECTION_SCHEMA
        && inspection.scope_digest == scope.digest()
        && inspection.generation == scope.generation()
        && inspection.plugins.len() == 1
        && inspection.services.len() == 1
        && inspection.providers.len() == 1
        && inspection.consumers.len() == 1
        && inspection.events.is_empty()
        && inspection.ui_surfaces.is_empty()
        && inspection.plugins[0].plugin_digest == *plugin_digest
        && inspection.plugins[0].scope_digest == scope.digest()
        && inspection.plugins[0].receipt_digest == *registration_digest
        && inspection.plugins[0].version == version
        && inspection.plugins[0].contribution_count == 3
        && inspection.services[0].service_id_digest == service_id_digest
        && inspection.services[0].owner_plugin_digest == *plugin_digest
        && inspection.services[0].version == version
        && inspection.services[0].access == ServiceAccess::ReadOnly
        && inspection.services[0].cardinality == ProviderCardinality::Singleton
        && inspection.services[0].compatibility == CompatibilityPolicy::Exact
        && inspection.services[0].contract_digest == *contract_digest
        && inspection.services[0].provider_count == 1
        && inspection.providers[0].provider_id_digest == provider_id_digest
        && inspection.providers[0].service_id_digest == service_id_digest
        && inspection.providers[0].owner_plugin_digest == *plugin_digest
        && inspection.providers[0].version == version
        && inspection.providers[0].implementation_digest == *implementation_digest
        && inspection.consumers[0].consumer_id_digest == consumer_id_digest
        && inspection.consumers[0].service_id_digest == service_id_digest
        && inspection.consumers[0].owner_plugin_digest == *plugin_digest
        && inspection.consumers[0].kind == ConsumerKind::Tool
        && inspection.consumers[0].required_version == version
        && inspection.consumers[0].descriptor_digest
            == PluginDigest::from_text(CAPABILITY_REQUEST_SCHEMA)
}
