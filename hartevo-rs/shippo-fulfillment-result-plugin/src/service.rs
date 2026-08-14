//! Typed, read-only service descriptor and proposal compiler.

use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginVersion, ProviderCardinality,
    ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};

use crate::model::{
    FulfillmentStatus, ShippoFulfillmentEvidence, ShippoFulfillmentResultProposal,
    compute_evidence_digest, compute_proposal_digest, digest_serializable,
    expected_provider_digest, validate_evidence_redaction,
};
use crate::{
    MISSION_SHIPPO_FULFILLMENT_CONSUMER_ID, MISSION_SHIPPO_FULFILLMENT_CONSUMER_SCHEMA,
    SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION, SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT,
    SHIPPO_FULFILLMENT_RESULT_SERVICE_ID, SHIPPO_FULFILLMENT_RESULT_SERVICE_NAME,
    SHIPPO_FULFILLMENT_RESULT_SERVICE_SCHEMA, SHIPPO_PROVIDER_ID, ShippoFulfillmentError,
    contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShippoFulfillmentResultOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ReadShipment,
    ReadTransaction,
    ReadTracking,
    CompileProposal,
    ConsumeObservation,
}

impl ShippoFulfillmentResultOperation {
    pub const ALL: [Self; 8] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ReadShipment,
        Self::ReadTransaction,
        Self::ReadTracking,
        Self::CompileProposal,
        Self::ConsumeObservation,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ShippoCapability {
    pub capability_id: String,
    pub operation: ShippoFulfillmentResultOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
    pub connected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShippoFulfillmentResultService {
    service_id: String,
    service_name: String,
    version: PluginVersion,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<ShippoCapability>,
}

impl Default for ShippoFulfillmentResultService {
    fn default() -> Self {
        Self::new()
    }
}

impl ShippoFulfillmentResultService {
    pub fn new() -> Self {
        let capability_names = [
            (
                "shippo.fulfillment-result.register",
                ShippoFulfillmentResultOperation::Register,
            ),
            (
                "shippo.fulfillment-result.revoke_registration",
                ShippoFulfillmentResultOperation::RevokeRegistration,
            ),
            (
                "shippo.fulfillment-result.read_shipment",
                ShippoFulfillmentResultOperation::ReadShipment,
            ),
            (
                "shippo.fulfillment-result.read_transaction",
                ShippoFulfillmentResultOperation::ReadTransaction,
            ),
            (
                "shippo.fulfillment-result.read_tracking",
                ShippoFulfillmentResultOperation::ReadTracking,
            ),
            (
                "shippo.fulfillment-result.compile_proposal",
                ShippoFulfillmentResultOperation::CompileProposal,
            ),
            (
                "shippo.fulfillment-result.consume_observation",
                ShippoFulfillmentResultOperation::ConsumeObservation,
            ),
        ];
        let capabilities = capability_names
            .into_iter()
            .map(|(capability_id, operation)| ShippoCapability {
                capability_id: capability_id.to_owned(),
                operation,
                read_only: true,
                mutates_provider: false,
                native_evidence: false,
                connected: false,
            })
            .collect();
        Self {
            service_id: SHIPPO_FULFILLMENT_RESULT_SERVICE_ID.to_owned(),
            service_name: SHIPPO_FULFILLMENT_RESULT_SERVICE_NAME.to_owned(),
            version: crate::plugin_version(),
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

    pub fn capabilities(&self) -> &[ShippoCapability] {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Vec<ShippoCapability> {
        self.capabilities.clone()
    }

    pub fn runtime_definition(&self) -> Result<ServiceDefinition, ShippoFulfillmentError> {
        let service_id =
            ServiceId::new(self.service_id.clone()).map_err(ShippoFulfillmentError::Plugin)?;
        ServiceDefinition::read_only(
            service_id,
            self.version,
            RuntimeDigest::from_text(SHIPPO_FULFILLMENT_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(ShippoFulfillmentError::Plugin)
    }

    pub fn validate(&self) -> Result<(), ShippoFulfillmentError> {
        if self.service_id != SHIPPO_FULFILLMENT_RESULT_SERVICE_ID
            || self.service_name != SHIPPO_FULFILLMENT_RESULT_SERVICE_NAME
            || self.version != crate::plugin_version()
            || !self.read_only
            || self.native_connected
            || self.capabilities.is_empty()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only
                    || capability.mutates_provider
                    || capability.native_evidence
                    || capability.connected
                    || !capability.operation.is_read_only()
            })
        {
            return Err(ShippoFulfillmentError::InvalidInput(
                "Shippo fulfillment-result service descriptor drifted".to_owned(),
            ));
        }
        Ok(())
    }

    /// Compiles an inert, canonical proposal for the next Mission decision.
    /// The returned proposal has no effect request and cannot purchase,
    /// download, create, mutate, register, pay, or command anything.
    pub fn compile_proposal(
        &self,
        evidence: &ShippoFulfillmentEvidence,
    ) -> Result<ShippoFulfillmentResultProposal, ShippoFulfillmentError> {
        self.validate()?;
        validate_evidence_redaction(evidence)?;
        evidence
            .scope
            .digest()
            .as_str()
            .eq(evidence.scope_digest.as_str())
            .then_some(())
            .ok_or(ShippoFulfillmentError::EvidenceDigestMismatch)?;
        if evidence.plugin_version != SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT
            || evidence.contract_version != SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION
            || evidence.contract_digest != contract_digest()
            || evidence.provider_id != SHIPPO_PROVIDER_ID
            || evidence.provider_revision.as_str() != crate::SHIPPO_PROVIDER_REVISION
            || evidence.provider_digest
                != expected_provider_digest(&evidence.scope, &evidence.provider_revision)
        {
            return Err(ShippoFulfillmentError::StaleEvidence);
        }
        if compute_evidence_digest(evidence)? != evidence.evidence_digest {
            return Err(ShippoFulfillmentError::EvidenceDigestMismatch);
        }
        let decision_hint = match evidence.status {
            FulfillmentStatus::LabelCreated => "review carrier transit readback",
            FulfillmentStatus::InTransit => "wait for bounded provider status readback",
            FulfillmentStatus::Delivered => {
                "review provider-delivered evidence; no compliance claim"
            }
            FulfillmentStatus::Exception => "review bounded provider exception evidence",
            FulfillmentStatus::Returned => "review bounded returned-shipment evidence",
            FulfillmentStatus::Unknown => "request a later bounded provider read",
            FulfillmentStatus::Partial => "treat the fulfillment result as incomplete",
            FulfillmentStatus::RetentionGap => "treat missing tracking history as a retention gap",
            FulfillmentStatus::AccessLost => "restore host-owned access before another read",
            FulfillmentStatus::ProviderUnknown => "treat the provider status as unknown",
        }
        .to_owned();
        let forbidden_effects = vec![
            "create_shipment".to_owned(),
            "create_transaction".to_owned(),
            "purchase_label".to_owned(),
            "download_label".to_owned(),
            "mutate_address_or_parcel".to_owned(),
            "register_webhook".to_owned(),
            "payment_or_refund".to_owned(),
            "carrier_command".to_owned(),
            "adopt_kernel_outcome".to_owned(),
        ];
        let mut proposal = ShippoFulfillmentResultProposal {
            proposal_version: SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION.to_owned(),
            scope_digest: evidence.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            status: evidence.status,
            decision_hint,
            requested_effects: Vec::new(),
            forbidden_effects,
            proposal_digest: crate::model::zero_digest(),
        };
        proposal.proposal_digest = compute_proposal_digest(&proposal)?;
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn implementation_digest(&self) -> crate::model::Digest {
        digest_serializable(&(
            self.service_id(),
            self.service_name(),
            SHIPPO_PROVIDER_ID,
            MISSION_SHIPPO_FULFILLMENT_CONSUMER_ID,
            MISSION_SHIPPO_FULFILLMENT_CONSUMER_SCHEMA,
            SHIPPO_FULFILLMENT_RESULT_PLUGIN_VERSION_TEXT,
        ))
        .expect("Shippo service descriptor serializes")
    }

    pub fn contract_version(&self) -> &'static str {
        SHIPPO_FULFILLMENT_RESULT_CONTRACT_VERSION
    }

    pub fn contract_digest(&self) -> crate::model::Digest {
        contract_digest()
    }
}
