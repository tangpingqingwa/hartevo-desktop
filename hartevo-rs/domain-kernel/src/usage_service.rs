//! Mission usage service definitions and provider-accounted receipts.
//!
//! This boundary owns pricing metadata, the accounting-provider result, and
//! the Mission consumer that turns that result into a reservation commit. It
//! deliberately binds to the existing capability-adapter registry metadata;
//! it does not load plugins or grant runtime/provider execution authority.

use std::{collections::BTreeMap, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    EffectStatus, MissionId, MissionUsageLedger, MissionUsageReservation, Money, ProjectId,
    ReceiptId, TenantId, UsageCommitEvidence, UsageLedgerError, UsageLedgerMutation,
    UsageReservationId,
};

pub const MISSION_USAGE_SERVICE_SCHEMA_VERSION: &str = "hartevo-mission-usage-service/v1";
pub const MISSION_USAGE_RECEIPT_SCHEMA_VERSION: &str = "hartevo-mission-usage-receipt/v1";
pub const MISSION_USAGE_RESULT_PACKET_SCHEMA_VERSION: &str = "hartevo-mission-usage-result/v1";
pub const CAPABILITY_ADAPTER_REGISTRY_SCHEMA: &str = "hartevo.capability-adapter-registry/v1";
pub const PROVIDER_ADAPTER_REGISTRY_SCHEMA: &str = "hartevo-provider-adapter-contract/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageUnit {
    Request,
    Token,
    Byte,
    Millisecond,
    Item,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageMeasurement {
    pub unit: UsageUnit,
    pub quantity: u64,
}

impl UsageMeasurement {
    pub fn new(unit: UsageUnit, quantity: u64) -> Result<Self, UsageServiceError> {
        if quantity == 0 {
            return Err(UsageServiceError::InvalidMeasurement);
        }
        Ok(Self { unit, quantity })
    }
}

/// Binding to the existing adapter registry. The lifecycle methods on
/// [`MissionUsageServiceRegistry`] are only a domain projection of this
/// binding; they do not mount code, create a process, or touch secrets.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageProviderRegistryBinding {
    pub registry_schema: String,
    pub registry_version: String,
    pub registry_revision: u64,
    pub adapter_id: String,
    pub adapter_version: u32,
    pub registration_digest: String,
}

impl UsageProviderRegistryBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry_schema: impl Into<String>,
        registry_version: impl Into<String>,
        registry_revision: u64,
        adapter_id: impl Into<String>,
        adapter_version: u32,
        registration_digest: impl Into<String>,
    ) -> Result<Self, UsageServiceError> {
        let binding = Self {
            registry_schema: registry_schema.into(),
            registry_version: registry_version.into(),
            registry_revision,
            adapter_id: adapter_id.into(),
            adapter_version,
            registration_digest: registration_digest.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), UsageServiceError> {
        if !matches!(
            self.registry_schema.as_str(),
            CAPABILITY_ADAPTER_REGISTRY_SCHEMA | PROVIDER_ADAPTER_REGISTRY_SCHEMA
        ) || self.registry_version.trim().is_empty()
            || self.registry_version.len() > 96
            || self.registry_revision == 0
            || self.adapter_id.trim().is_empty()
            || self.adapter_id.len() > 256
            || self.adapter_version == 0
            || !is_sha256(&self.registration_digest)
        {
            return Err(UsageServiceError::InvalidRegistryBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionUsageServiceDefinition {
    pub schema_version: String,
    pub service_id: String,
    pub service_version: u32,
    pub provider_id: String,
    pub capability: String,
    pub unit: UsageUnit,
    pub unit_price: Money,
    pub registry_binding: UsageProviderRegistryBinding,
    pub definition_digest: String,
}

impl MissionUsageServiceDefinition {
    pub fn new(
        service_id: impl Into<String>,
        service_version: u32,
        provider_id: impl Into<String>,
        capability: impl Into<String>,
        unit: UsageUnit,
        unit_price: Money,
        registry_binding: UsageProviderRegistryBinding,
    ) -> Result<Self, UsageServiceError> {
        let mut definition = Self {
            schema_version: MISSION_USAGE_SERVICE_SCHEMA_VERSION.into(),
            service_id: service_id.into(),
            service_version,
            provider_id: provider_id.into(),
            capability: capability.into(),
            unit,
            unit_price,
            registry_binding,
            definition_digest: String::new(),
        };
        definition.definition_digest = definition.computed_digest();
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), UsageServiceError> {
        if self.schema_version != MISSION_USAGE_SERVICE_SCHEMA_VERSION
            || !valid_namespaced_id(&self.service_id)
            || self.service_version == 0
            || !valid_provider_id(&self.provider_id)
            || !valid_namespaced_id(&self.capability)
            || self.unit_price.amount_minor < 0
            || self.definition_digest != self.computed_digest()
        {
            return Err(UsageServiceError::InvalidServiceDefinition);
        }
        self.registry_binding.validate()
    }

    pub fn digest(&self) -> &str {
        &self.definition_digest
    }

    fn computed_digest(&self) -> String {
        digest_serialized(&(
            &self.schema_version,
            &self.service_id,
            self.service_version,
            &self.provider_id,
            &self.capability,
            self.unit,
            &self.unit_price,
            &self.registry_binding,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "reasonDigest")]
pub enum MissionUsageServiceStatus {
    Mounted,
    Unmounted,
    Revoked(String),
}

impl MissionUsageServiceStatus {
    fn validate(&self) -> Result<(), UsageServiceError> {
        if let Self::Revoked(reason_digest) = self
            && !is_sha256(reason_digest)
        {
            return Err(UsageServiceError::InvalidRegistryBinding);
        }
        Ok(())
    }

    pub const fn is_mounted(&self) -> bool {
        matches!(self, Self::Mounted)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionUsageServiceRegistration {
    pub definition: MissionUsageServiceDefinition,
    pub status: MissionUsageServiceStatus,
    pub registry_revision: u64,
    pub record_digest: String,
}

impl MissionUsageServiceRegistration {
    fn new(
        definition: MissionUsageServiceDefinition,
        status: MissionUsageServiceStatus,
        registry_revision: u64,
    ) -> Result<Self, UsageServiceError> {
        let registration = Self {
            definition,
            status,
            registry_revision,
            record_digest: String::new(),
        };
        let record_digest = registration.computed_digest();
        let registration = Self {
            record_digest,
            ..registration
        };
        registration.validate()?;
        Ok(registration)
    }

    fn validate(&self) -> Result<(), UsageServiceError> {
        self.definition.validate()?;
        self.status.validate()?;
        if self.registry_revision == 0 || self.record_digest != self.computed_digest() {
            return Err(UsageServiceError::RegistryIntegrityFailure);
        }
        Ok(())
    }

    fn computed_digest(&self) -> String {
        digest_serialized(&(
            &self.definition.definition_digest,
            &self.status,
            self.registry_revision,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionUsageServiceRegistry {
    pub schema_version: String,
    pub revision: u64,
    pub registrations: BTreeMap<String, MissionUsageServiceRegistration>,
}

impl MissionUsageServiceRegistry {
    pub fn new() -> Self {
        Self {
            schema_version: "hartevo-mission-usage-registry/v1".into(),
            revision: 1,
            registrations: BTreeMap::new(),
        }
    }

    pub fn mount(
        &mut self,
        definition: MissionUsageServiceDefinition,
    ) -> Result<UsageRegistryMutation<MissionUsageServiceRegistration>, UsageServiceError> {
        definition.validate()?;
        let service_id = definition.service_id.clone();
        if let Some(existing) = self.registrations.get(&service_id) {
            if existing.definition != definition {
                return Err(UsageServiceError::ServiceConflict);
            }
            if existing.status.is_mounted() {
                return Ok(UsageRegistryMutation::Replayed(existing.clone()));
            }
            if matches!(existing.status, MissionUsageServiceStatus::Revoked(_)) {
                return Err(UsageServiceError::ServiceRevoked);
            }
        }
        let revision = self.next_revision()?;
        let registration = MissionUsageServiceRegistration::new(
            definition,
            MissionUsageServiceStatus::Mounted,
            revision,
        )?;
        self.registrations.insert(service_id, registration.clone());
        Ok(UsageRegistryMutation::Applied(registration))
    }

    pub fn unmount(
        &mut self,
        service_id: &str,
    ) -> Result<UsageRegistryMutation<MissionUsageServiceRegistration>, UsageServiceError> {
        let (definition, status, existing) = {
            let existing = self
                .registrations
                .get(service_id)
                .ok_or(UsageServiceError::ServiceNotFound)?;
            (
                existing.definition.clone(),
                existing.status.clone(),
                existing.clone(),
            )
        };
        if matches!(status, MissionUsageServiceStatus::Unmounted) {
            return Ok(UsageRegistryMutation::Replayed(existing));
        }
        if matches!(status, MissionUsageServiceStatus::Revoked(_)) {
            return Err(UsageServiceError::ServiceRevoked);
        }
        let revision = self.next_revision()?;
        let registration = MissionUsageServiceRegistration::new(
            definition,
            MissionUsageServiceStatus::Unmounted,
            revision,
        )?;
        self.registrations
            .insert(service_id.to_owned(), registration.clone());
        Ok(UsageRegistryMutation::Applied(registration))
    }

    pub fn revoke(
        &mut self,
        service_id: &str,
        reason_digest: impl Into<String>,
    ) -> Result<UsageRegistryMutation<MissionUsageServiceRegistration>, UsageServiceError> {
        let reason_digest = reason_digest.into();
        if !is_sha256(&reason_digest) {
            return Err(UsageServiceError::InvalidRevocation);
        }
        let (definition, status) = {
            let existing = self
                .registrations
                .get(service_id)
                .ok_or(UsageServiceError::ServiceNotFound)?;
            (existing.definition.clone(), existing.status.clone())
        };
        if let MissionUsageServiceStatus::Revoked(existing_reason) = &status {
            if existing_reason == &reason_digest {
                let existing = self
                    .registrations
                    .get(service_id)
                    .ok_or(UsageServiceError::ServiceNotFound)?;
                return Ok(UsageRegistryMutation::Replayed(existing.clone()));
            }
            return Err(UsageServiceError::RevocationConflict);
        }
        let revision = self.next_revision()?;
        let registration = MissionUsageServiceRegistration::new(
            definition,
            MissionUsageServiceStatus::Revoked(reason_digest),
            revision,
        )?;
        self.registrations
            .insert(service_id.to_owned(), registration.clone());
        Ok(UsageRegistryMutation::Applied(registration))
    }

    pub fn registration(&self, service_id: &str) -> Option<&MissionUsageServiceRegistration> {
        self.registrations.get(service_id)
    }

    pub fn authorize(
        &self,
        service_id: &str,
        definition_digest: &str,
    ) -> Result<&MissionUsageServiceDefinition, UsageServiceError> {
        self.validate()?;
        let registration = self
            .registrations
            .get(service_id)
            .ok_or(UsageServiceError::ServiceNotFound)?;
        if !registration.status.is_mounted() {
            return Err(
                if matches!(&registration.status, MissionUsageServiceStatus::Revoked(_)) {
                    UsageServiceError::ServiceRevoked
                } else {
                    UsageServiceError::ServiceNotMounted
                },
            );
        }
        if registration.definition.digest() != definition_digest {
            return Err(UsageServiceError::ServiceDefinitionMismatch);
        }
        Ok(&registration.definition)
    }

    pub fn validate(&self) -> Result<(), UsageServiceError> {
        if self.schema_version != "hartevo-mission-usage-registry/v1" || self.revision == 0 {
            return Err(UsageServiceError::RegistryIntegrityFailure);
        }
        for (service_id, registration) in &self.registrations {
            if service_id != &registration.definition.service_id {
                return Err(UsageServiceError::RegistryIntegrityFailure);
            }
            registration.validate()?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, UsageServiceError> {
        self.validate()?;
        Ok(digest_serialized(self))
    }

    fn next_revision(&mut self) -> Result<u64, UsageServiceError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(UsageServiceError::RegistryRevisionOverflow)?;
        Ok(self.revision)
    }
}

impl Default for MissionUsageServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UsageRegistryMutation<T> {
    Applied(T),
    Replayed(T),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountingProviderReceipt {
    pub provider_id: String,
    pub service_definition_digest: String,
    pub measurement: UsageMeasurement,
    pub cost: Money,
    pub evidence_digest: String,
    pub observed_at: DateTime<Utc>,
    pub receipt_digest: String,
}

impl AccountingProviderReceipt {
    pub fn new(
        provider_id: impl Into<String>,
        service_definition_digest: impl Into<String>,
        measurement: UsageMeasurement,
        cost: Money,
        evidence_digest: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, UsageServiceError> {
        let mut receipt = Self {
            provider_id: provider_id.into(),
            service_definition_digest: service_definition_digest.into(),
            measurement,
            cost,
            evidence_digest: evidence_digest.into(),
            observed_at,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), UsageServiceError> {
        if !valid_provider_id(&self.provider_id)
            || !is_sha256(&self.service_definition_digest)
            || self.measurement.quantity == 0
            || self.cost.amount_minor < 0
            || !is_sha256(&self.evidence_digest)
            || self.observed_at.timestamp() < 0
            || !is_sha256(&self.receipt_digest)
            || self.receipt_digest != self.computed_digest()
        {
            return Err(UsageServiceError::InvalidProviderReceipt);
        }
        Ok(())
    }

    pub fn digest(&self) -> &str {
        &self.receipt_digest
    }

    fn computed_digest(&self) -> String {
        digest_serialized(&(
            &self.provider_id,
            &self.service_definition_digest,
            &self.measurement,
            &self.cost,
            &self.evidence_digest,
            self.observed_at,
        ))
    }
}

/// An accounting provider is a pure typed boundary. It returns a provider
/// accounting observation; it cannot mutate a Mission or claim payment.
pub trait MissionAccountingProvider: fmt::Debug + Send + Sync {
    fn provider_id(&self) -> &str;

    fn account(
        &self,
        definition: &MissionUsageServiceDefinition,
        measurement: UsageMeasurement,
        evidence_digest: &str,
        observed_at: DateTime<Utc>,
    ) -> Result<AccountingProviderReceipt, UsageServiceError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitPriceAccountingProvider {
    provider_id: String,
}

impl UnitPriceAccountingProvider {
    pub fn new(provider_id: impl Into<String>) -> Result<Self, UsageServiceError> {
        let provider = Self {
            provider_id: provider_id.into(),
        };
        if !valid_provider_id(&provider.provider_id) {
            return Err(UsageServiceError::InvalidProviderId);
        }
        Ok(provider)
    }
}

impl MissionAccountingProvider for UnitPriceAccountingProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn account(
        &self,
        definition: &MissionUsageServiceDefinition,
        measurement: UsageMeasurement,
        evidence_digest: &str,
        observed_at: DateTime<Utc>,
    ) -> Result<AccountingProviderReceipt, UsageServiceError> {
        definition.validate()?;
        if definition.provider_id != self.provider_id {
            return Err(UsageServiceError::ProviderMismatch);
        }
        if measurement.unit != definition.unit || measurement.quantity == 0 {
            return Err(UsageServiceError::InvalidMeasurement);
        }
        let quantity = i64::try_from(measurement.quantity)
            .map_err(|_| UsageServiceError::AccountingOverflow)?;
        let amount_minor = definition
            .unit_price
            .amount_minor
            .checked_mul(quantity)
            .ok_or(UsageServiceError::AccountingOverflow)?;
        AccountingProviderReceipt::new(
            self.provider_id.clone(),
            definition.definition_digest.clone(),
            measurement,
            Money::new(amount_minor, definition.unit_price.currency.clone()),
            evidence_digest,
            observed_at,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionUsageReceipt {
    pub schema_version: String,
    pub receipt_id: ReceiptId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub effect_id: crate::EffectId,
    pub reservation_id: UsageReservationId,
    pub effect_scope_digest: String,
    pub service_definition_digest: String,
    pub provider_id: String,
    pub provider_receipt_digest: String,
    pub measurement: UsageMeasurement,
    pub cost: Money,
    pub evidence_digest: String,
    pub observed_at: DateTime<Utc>,
    pub receipt_digest: String,
}

impl MissionUsageReceipt {
    pub fn from_provider(
        reservation: &MissionUsageReservation,
        definition: &MissionUsageServiceDefinition,
        provider_receipt: &AccountingProviderReceipt,
    ) -> Result<Self, UsageServiceError> {
        reservation.validate(&reservation.amount.currency)?;
        definition.validate()?;
        provider_receipt.validate()?;
        if provider_receipt.service_definition_digest != definition.definition_digest
            || provider_receipt.provider_id != definition.provider_id
            || provider_receipt.measurement.unit != definition.unit
            || provider_receipt.cost != reservation.amount
            || provider_receipt.observed_at < reservation.reserved_at
            || provider_receipt.observed_at > reservation.expires_at
        {
            return Err(UsageServiceError::ReceiptBindingMismatch);
        }
        let mut receipt = Self {
            schema_version: MISSION_USAGE_RECEIPT_SCHEMA_VERSION.into(),
            receipt_id: ReceiptId::from_stable(format!(
                "usage:{}:{}",
                reservation.id.as_str(),
                provider_receipt.receipt_digest
            )),
            tenant_id: reservation.tenant_id.clone(),
            project_id: reservation.project_id.clone(),
            mission_id: reservation.mission_id.clone(),
            effect_id: reservation.effect_id.clone(),
            reservation_id: reservation.id.clone(),
            effect_scope_digest: reservation.effect_scope_digest.clone(),
            service_definition_digest: definition.definition_digest.clone(),
            provider_id: provider_receipt.provider_id.clone(),
            provider_receipt_digest: provider_receipt.receipt_digest.clone(),
            measurement: provider_receipt.measurement.clone(),
            cost: provider_receipt.cost.clone(),
            evidence_digest: provider_receipt.evidence_digest.clone(),
            observed_at: provider_receipt.observed_at,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), UsageServiceError> {
        if self.schema_version != MISSION_USAGE_RECEIPT_SCHEMA_VERSION
            || self.receipt_id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.effect_id.as_str().trim().is_empty()
            || self.reservation_id.as_str().trim().is_empty()
            || !is_sha256(&self.effect_scope_digest)
            || !is_sha256(&self.service_definition_digest)
            || !valid_provider_id(&self.provider_id)
            || !is_sha256(&self.provider_receipt_digest)
            || self.measurement.quantity == 0
            || self.cost.amount_minor < 0
            || !is_sha256(&self.evidence_digest)
            || self.observed_at.timestamp() < 0
            || !is_sha256(&self.receipt_digest)
            || self.receipt_digest != self.computed_digest()
        {
            return Err(UsageServiceError::InvalidUsageReceipt);
        }
        Ok(())
    }

    pub fn digest(&self) -> &str {
        &self.receipt_digest
    }

    pub fn result_packet(&self) -> MissionUsageResultPacket {
        MissionUsageResultPacket {
            schema_version: MISSION_USAGE_RESULT_PACKET_SCHEMA_VERSION.into(),
            mission_id: self.mission_id.clone(),
            usage_receipt: self.clone(),
        }
    }

    fn computed_digest(&self) -> String {
        digest_serialized(&(
            &self.schema_version,
            &self.receipt_id,
            &self.tenant_id,
            &self.project_id,
            &self.mission_id,
            &self.effect_id,
            &self.reservation_id,
            &self.effect_scope_digest,
            &self.service_definition_digest,
            &self.provider_id,
            &self.provider_receipt_digest,
            &self.measurement,
            &self.cost,
            &self.evidence_digest,
            self.observed_at,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionUsageResultPacket {
    pub schema_version: String,
    pub mission_id: MissionId,
    pub usage_receipt: MissionUsageReceipt,
}

impl MissionUsageResultPacket {
    pub fn validate(&self) -> Result<(), UsageServiceError> {
        if self.schema_version != MISSION_USAGE_RESULT_PACKET_SCHEMA_VERSION
            || self.mission_id != self.usage_receipt.mission_id
        {
            return Err(UsageServiceError::InvalidResultPacket);
        }
        self.usage_receipt.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionUsageConsumption {
    pub mutation: UsageLedgerMutation<MissionUsageReservation>,
    pub usage_receipt: MissionUsageReceipt,
    pub result_packet: MissionUsageResultPacket,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionUsageConsumeRequest {
    pub reservation_id: UsageReservationId,
    pub mission_revision: u64,
    pub effect_scope_digest: String,
    pub effect_status: EffectStatus,
    pub provider_receipt: AccountingProviderReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionUsageConsumer {
    service_id: String,
    service_definition_digest: String,
}

impl MissionUsageConsumer {
    pub fn new(
        registry: &MissionUsageServiceRegistry,
        service_id: impl Into<String>,
    ) -> Result<Self, UsageServiceError> {
        let service_id = service_id.into();
        let definition = registry.authorize(
            &service_id,
            registry
                .registration(&service_id)
                .ok_or(UsageServiceError::ServiceNotFound)?
                .definition
                .digest(),
        )?;
        Ok(Self {
            service_id,
            service_definition_digest: definition.digest().to_owned(),
        })
    }

    pub fn service_definition_digest(&self) -> &str {
        &self.service_definition_digest
    }

    pub fn consume(
        &self,
        registry: &MissionUsageServiceRegistry,
        ledger: &mut MissionUsageLedger,
        request: &MissionUsageConsumeRequest,
    ) -> Result<MissionUsageConsumption, UsageServiceError> {
        let definition = registry.authorize(&self.service_id, &self.service_definition_digest)?;
        if let Some(existing) = ledger.committed_usage_receipt(&request.reservation_id) {
            request.provider_receipt.validate()?;
            if request.provider_receipt.receipt_digest != existing.provider_receipt_digest
                || request.provider_receipt.service_definition_digest
                    != existing.service_definition_digest
                || request.provider_receipt.provider_id != existing.provider_id
                || request.provider_receipt.cost != existing.cost
                || request.provider_receipt.measurement != existing.measurement
                || request.provider_receipt.observed_at != existing.observed_at
                || request.provider_receipt.evidence_digest != existing.evidence_digest
            {
                return Err(UsageServiceError::ReceiptConflict);
            }
            let reservation = ledger.reservation(&request.reservation_id).ok_or_else(|| {
                UsageLedgerError::UnknownReservation(request.reservation_id.clone())
            })?;
            let result_packet = existing.result_packet();
            result_packet.validate()?;
            return Ok(MissionUsageConsumption {
                mutation: UsageLedgerMutation::Replayed(reservation),
                usage_receipt: existing,
                result_packet,
            });
        }
        let reservation = ledger
            .reservation(&request.reservation_id)
            .ok_or_else(|| UsageLedgerError::UnknownReservation(request.reservation_id.clone()))?;
        let usage_receipt = MissionUsageReceipt::from_provider(
            &reservation,
            definition,
            &request.provider_receipt,
        )?;
        let evidence = UsageCommitEvidence {
            receipt_id: usage_receipt.receipt_id.clone(),
            effect_status: request.effect_status.clone(),
            evidence_digest: usage_receipt.evidence_digest.clone(),
            observed_at: usage_receipt.observed_at,
            usage_receipt: Some(usage_receipt.clone()),
        };
        let mutation = ledger.commit(
            &request.reservation_id,
            request.mission_revision,
            &request.effect_scope_digest,
            evidence,
        )?;
        let result_packet = usage_receipt.result_packet();
        result_packet.validate()?;
        Ok(MissionUsageConsumption {
            mutation,
            usage_receipt,
            result_packet,
        })
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum UsageServiceError {
    #[error("Mission usage service definition is invalid")]
    InvalidServiceDefinition,
    #[error("Mission usage provider registry binding is invalid")]
    InvalidRegistryBinding,
    #[error("Mission usage provider id is invalid")]
    InvalidProviderId,
    #[error("Mission usage service is already registered with different metadata")]
    ServiceConflict,
    #[error("Mission usage service is not registered")]
    ServiceNotFound,
    #[error("Mission usage service is not mounted")]
    ServiceNotMounted,
    #[error("Mission usage service has been revoked")]
    ServiceRevoked,
    #[error("Mission usage service definition does not match the mounted registry record")]
    ServiceDefinitionMismatch,
    #[error("Mission usage provider registry is internally inconsistent")]
    RegistryIntegrityFailure,
    #[error("Mission usage provider registry revision overflowed")]
    RegistryRevisionOverflow,
    #[error("Mission usage revocation reason is invalid")]
    InvalidRevocation,
    #[error("Mission usage revocation conflicts with an existing reason")]
    RevocationConflict,
    #[error("Mission usage measurement is invalid")]
    InvalidMeasurement,
    #[error("Mission accounting provider does not match the service definition")]
    ProviderMismatch,
    #[error("Mission accounting provider cost overflowed")]
    AccountingOverflow,
    #[error("Mission accounting provider receipt is invalid")]
    InvalidProviderReceipt,
    #[error("Mission usage receipt is not bound to the exact reservation and service")]
    ReceiptBindingMismatch,
    #[error("Mission usage receipt is invalid")]
    InvalidUsageReceipt,
    #[error("Mission usage receipt conflicts with an existing committed receipt")]
    ReceiptConflict,
    #[error("Mission usage result packet is invalid")]
    InvalidResultPacket,
    #[error(transparent)]
    Ledger(#[from] UsageLedgerError),
}

fn digest_serialized<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("usage service values are serializable");
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
}

fn valid_provider_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn valid_namespaced_id(value: &str) -> bool {
    if value.len() < 2 || value.len() > 96 {
        return false;
    }
    let mut segments = value.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    if !valid_segment(first) {
        return false;
    }
    segments.all(valid_segment)
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
        && !matches!(value.as_bytes().first(), Some(b'-' | b'_'))
        && !matches!(value.as_bytes().last(), Some(b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;
    use crate::{CreditGrantId, CurrencyCode, EffectId, UsageReservationStatus};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 3, 0, 0)
            .single()
            .expect("time")
    }

    fn binding() -> UsageProviderRegistryBinding {
        UsageProviderRegistryBinding::new(
            CAPABILITY_ADAPTER_REGISTRY_SCHEMA,
            "desktop-test-v1",
            7,
            "accounting.local",
            1,
            "a".repeat(64),
        )
        .expect("binding")
    }

    fn definition() -> MissionUsageServiceDefinition {
        MissionUsageServiceDefinition::new(
            "mission.usage",
            1,
            "accounting-local",
            "mission.usage.account",
            UsageUnit::Token,
            Money::new(2, CurrencyCode::parse("USD").expect("USD")),
            binding(),
        )
        .expect("definition")
    }

    fn reservation() -> MissionUsageReservation {
        MissionUsageReservation {
            id: UsageReservationId::from("reservation-service"),
            tenant_id: TenantId::from("tenant-money"),
            project_id: ProjectId::from("project-money"),
            mission_id: MissionId::from("mission-money"),
            effect_id: EffectId::from("effect-money"),
            mission_revision: 4,
            effect_scope_digest: "b".repeat(64),
            amount: Money::new(100, CurrencyCode::parse("USD").expect("USD")),
            idempotency_key: "reservation-service-1".into(),
            reserved_at: now(),
            expires_at: now() + Duration::minutes(10),
            status: UsageReservationStatus::Reserved,
        }
    }

    #[test]
    fn registry_lifecycle_is_mount_unmount_and_irreversible_revoke() {
        let mut registry = MissionUsageServiceRegistry::new();
        let definition = definition();
        assert!(matches!(
            registry.mount(definition.clone()),
            Ok(UsageRegistryMutation::Applied(_))
        ));
        let consumer = MissionUsageConsumer::new(&registry, "mission.usage").expect("consumer");
        assert!(registry.unmount("mission.usage").is_ok());
        assert_eq!(
            MissionUsageConsumer::new(&registry, "mission.usage"),
            Err(UsageServiceError::ServiceNotMounted)
        );
        assert!(registry.mount(definition.clone()).is_ok());
        assert!(registry.revoke("mission.usage", "c".repeat(64)).is_ok());
        assert_eq!(
            registry.mount(definition),
            Err(UsageServiceError::ServiceRevoked)
        );
        assert_eq!(
            registry.authorize("mission.usage", consumer.service_definition_digest()),
            Err(UsageServiceError::ServiceRevoked)
        );
    }

    #[test]
    fn provider_cost_and_consumer_emit_adoptable_typed_result() {
        let mut registry = MissionUsageServiceRegistry::new();
        let definition = definition();
        registry.mount(definition.clone()).expect("mount");
        let provider = UnitPriceAccountingProvider::new("accounting-local").expect("provider");
        let provider_receipt = provider
            .account(
                &definition,
                UsageMeasurement::new(UsageUnit::Token, 50).expect("measurement"),
                &"d".repeat(64),
                now() + Duration::minutes(1),
            )
            .expect("provider receipt");
        let mut ledger = MissionUsageLedger::new(
            TenantId::from("tenant-money"),
            ProjectId::from("project-money"),
            CurrencyCode::parse("USD").expect("USD"),
        );
        ledger
            .grant_credit(
                CreditGrantId::from("grant-service"),
                "e".repeat(64),
                Money::new(100, CurrencyCode::parse("USD").expect("USD")),
                now(),
            )
            .expect("credit");
        let reservation = reservation();
        ledger.reserve(reservation.clone()).expect("reserve");
        let consumer = MissionUsageConsumer::new(&registry, "mission.usage").expect("consumer");
        let request = MissionUsageConsumeRequest {
            reservation_id: reservation.id.clone(),
            mission_revision: reservation.mission_revision,
            effect_scope_digest: reservation.effect_scope_digest.clone(),
            effect_status: EffectStatus::Verified,
            provider_receipt: provider_receipt.clone(),
        };
        let consumption = consumer
            .consume(&registry, &mut ledger, &request)
            .expect("consume");
        assert_eq!(consumption.usage_receipt.cost.amount_minor, 100);
        consumption.result_packet.validate().expect("packet");
        assert_eq!(
            ledger
                .committed_usage_receipt(&reservation.id)
                .expect("receipt"),
            consumption.usage_receipt
        );
        let replay = consumer
            .consume(&registry, &mut ledger, &request)
            .expect("replay");
        assert!(matches!(replay.mutation, UsageLedgerMutation::Replayed(_)));
    }

    #[test]
    fn consumer_rejects_cost_or_provider_receipt_swap() {
        let mut registry = MissionUsageServiceRegistry::new();
        let definition = definition();
        registry.mount(definition.clone()).expect("mount");
        let provider = UnitPriceAccountingProvider::new("accounting-local").expect("provider");
        let provider_receipt = provider
            .account(
                &definition,
                UsageMeasurement::new(UsageUnit::Token, 40).expect("measurement"),
                &"d".repeat(64),
                now() + Duration::minutes(1),
            )
            .expect("provider receipt");
        let mut ledger = MissionUsageLedger::new(
            TenantId::from("tenant-money"),
            ProjectId::from("project-money"),
            CurrencyCode::parse("USD").expect("USD"),
        );
        ledger
            .grant_credit(
                CreditGrantId::from("grant-service"),
                "e".repeat(64),
                Money::new(100, CurrencyCode::parse("USD").expect("USD")),
                now(),
            )
            .expect("credit");
        let reservation = reservation();
        ledger.reserve(reservation.clone()).expect("reserve");
        let consumer = MissionUsageConsumer::new(&registry, "mission.usage").expect("consumer");
        let request = MissionUsageConsumeRequest {
            reservation_id: reservation.id.clone(),
            mission_revision: reservation.mission_revision,
            effect_scope_digest: reservation.effect_scope_digest.clone(),
            effect_status: EffectStatus::Verified,
            provider_receipt,
        };
        assert_eq!(
            consumer.consume(&registry, &mut ledger, &request),
            Err(UsageServiceError::ReceiptBindingMismatch)
        );
    }
}
