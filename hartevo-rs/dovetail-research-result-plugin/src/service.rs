use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::DovetailResearchResultError;
use crate::model::{
    Digest, DovetailPermissionSnapshot, DovetailProviderIdentity, DovetailResearchObservation,
    DovetailResearchReadRequest, DovetailResearchScope, RegistrationId, SecretReference,
    TransportProvenance,
};
use crate::provider::{DovetailProvider, DovetailTransport};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DovetailRegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DovetailRegistration {
    pub registration_id: RegistrationId,
    pub scope: DovetailResearchScope,
    pub secret_reference: SecretReference,
    pub permission_snapshot: DovetailPermissionSnapshot,
    pub provider: DovetailProviderIdentity,
    pub status: DovetailRegistrationStatus,
    pub registration_digest: Digest,
}

impl DovetailRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registration_id: RegistrationId,
        scope: DovetailResearchScope,
        secret_reference: SecretReference,
        permission_snapshot: DovetailPermissionSnapshot,
        provider: DovetailProviderIdentity,
    ) -> crate::Result<Self> {
        registration_id.validate()?;
        scope.validate()?;
        secret_reference.validate()?;
        permission_snapshot.validate()?;
        provider.validate()?;
        if scope.provider.digest != provider.digest
            || scope.permission_digest != permission_snapshot.digest
        {
            return Err(DovetailResearchResultError::RegistrationDrift);
        }
        let registration_digest = Self::calculate_digest(
            &registration_id,
            &scope,
            &secret_reference,
            &permission_snapshot,
            &provider,
            DovetailRegistrationStatus::Active,
        );
        Ok(Self {
            registration_id,
            scope,
            secret_reference,
            permission_snapshot,
            provider,
            status: DovetailRegistrationStatus::Active,
            registration_digest,
        })
    }

    pub fn layer1(scope: DovetailResearchScope) -> crate::Result<Self> {
        let permission_snapshot = DovetailPermissionSnapshot::read_only(1)?;
        if scope.permission_digest != permission_snapshot.digest {
            return Err(DovetailResearchResultError::PermissionMismatch);
        }
        let provider = scope.provider.clone();
        let registration_id = RegistrationId::new(format!(
            "dovetail-registration-{}",
            &scope.scope_digest.as_str()[..16]
        ))?;
        Self::new(
            registration_id,
            scope,
            SecretReference::api_token("opaque-dovetail-api-token-reference", 1)?,
            permission_snapshot,
            provider,
        )
    }

    fn calculate_digest(
        registration_id: &RegistrationId,
        scope: &DovetailResearchScope,
        secret_reference: &SecretReference,
        permission_snapshot: &DovetailPermissionSnapshot,
        provider: &DovetailProviderIdentity,
        status: DovetailRegistrationStatus,
    ) -> Digest {
        Digest::from_serialized(&(
            registration_id,
            &scope.scope_digest,
            secret_reference.reference_digest(),
            secret_reference.revision(),
            permission_snapshot,
            provider,
            status,
        ))
    }

    pub fn validate(&self) -> crate::Result<()> {
        self.scope.validate()?;
        self.secret_reference.validate()?;
        self.permission_snapshot.validate()?;
        self.provider.validate()?;
        self.registration_id.validate()?;
        if self.scope.provider.digest != self.provider.digest
            || self.scope.permission_digest != self.permission_snapshot.digest
        {
            return Err(DovetailResearchResultError::RegistrationDrift);
        }
        let expected = Self::calculate_digest(
            &self.registration_id,
            &self.scope,
            &self.secret_reference,
            &self.permission_snapshot,
            &self.provider,
            self.status,
        );
        if expected == self.registration_digest {
            Ok(())
        } else {
            Err(DovetailResearchResultError::RegistrationDrift)
        }
    }

    pub fn ensure_active(&self) -> crate::Result<()> {
        self.validate()?;
        match self.status {
            DovetailRegistrationStatus::Active => Ok(()),
            DovetailRegistrationStatus::Revoked => {
                Err(DovetailResearchResultError::RegistrationRevoked)
            }
            DovetailRegistrationStatus::Reversed => {
                Err(DovetailResearchResultError::RegistrationReversed)
            }
        }
    }

    pub fn revoke(&mut self) -> crate::Result<RegistrationReceipt> {
        self.validate()?;
        if self.status != DovetailRegistrationStatus::Active {
            return Err(DovetailResearchResultError::RegistrationRevoked);
        }
        self.status = DovetailRegistrationStatus::Revoked;
        self.secret_reference.revoke();
        self.registration_digest = Self::calculate_digest(
            &self.registration_id,
            &self.scope,
            &self.secret_reference,
            &self.permission_snapshot,
            &self.provider,
            self.status,
        );
        Ok(self.receipt())
    }

    pub fn reverse(&mut self) -> crate::Result<RegistrationReceipt> {
        self.validate()?;
        if self.status != DovetailRegistrationStatus::Active {
            return Err(DovetailResearchResultError::RegistrationReversed);
        }
        self.status = DovetailRegistrationStatus::Reversed;
        self.registration_digest = Self::calculate_digest(
            &self.registration_id,
            &self.scope,
            &self.secret_reference,
            &self.permission_snapshot,
            &self.provider,
            self.status,
        );
        Ok(self.receipt())
    }

    pub fn receipt(&self) -> RegistrationReceipt {
        RegistrationReceipt {
            registration_id: self.registration_id.clone(),
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope.scope_digest.clone(),
            provider_digest: self.provider.digest.clone(),
            permission_digest: self.permission_snapshot.digest.clone(),
            secret_reference_digest: self.secret_reference.reference_digest().clone(),
            status: self.status,
            provenance: None,
            connected: false,
            native: false,
            reversible: true,
            revocable: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub registration_id: RegistrationId,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub status: DovetailRegistrationStatus,
    pub provenance: Option<TransportProvenance>,
    pub connected: bool,
    pub native: bool,
    pub reversible: bool,
    pub revocable: bool,
}

impl RegistrationReceipt {
    pub fn validate(&self) -> crate::Result<()> {
        self.registration_digest.validate("registrationDigest")?;
        self.scope_digest.validate("scopeDigest")?;
        self.provider_digest.validate("providerDigest")?;
        self.permission_digest.validate("permissionDigest")?;
        self.secret_reference_digest
            .validate("secretReferenceDigest")?;
        if self.connected || self.native || !self.reversible || !self.revocable {
            return Err(DovetailResearchResultError::TamperedResult);
        }
        if self
            .provenance
            .is_some_and(|provenance| provenance.is_connected() || provenance.is_native())
        {
            return Err(DovetailResearchResultError::TamperedResult);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct DovetailRegistrationRegistry {
    registrations: BTreeMap<RegistrationId, DovetailRegistration>,
}

impl DovetailRegistrationRegistry {
    pub fn register(
        &mut self,
        registration: DovetailRegistration,
    ) -> crate::Result<RegistrationReceipt> {
        registration.validate()?;
        if self
            .registrations
            .contains_key(&registration.registration_id)
        {
            return Err(DovetailResearchResultError::RegistrationAlreadyExists);
        }
        let receipt = registration.receipt();
        self.registrations
            .insert(registration.registration_id.clone(), registration);
        Ok(receipt)
    }

    pub fn revoke(&mut self, id: &RegistrationId) -> crate::Result<RegistrationReceipt> {
        let registration = self
            .registrations
            .get_mut(id)
            .ok_or(DovetailResearchResultError::RegistrationUnknown)?;
        registration.revoke()
    }

    pub fn get(&self, id: &RegistrationId) -> Option<&DovetailRegistration> {
        self.registrations.get(id)
    }

    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DovetailResearchResultServiceOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ReadBoundedMetadata,
    CompileResearchResultProposal,
    RecordResearchResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DovetailResearchResultServiceDefinition {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_version: String,
    pub operations: Vec<DovetailResearchResultServiceOperation>,
    pub read_only: bool,
    pub external_writes: bool,
    pub export_or_download: bool,
    pub webhooks: bool,
    pub transcript_access: bool,
    pub media_access: bool,
    pub kernel_authority: bool,
    pub connected_authority: bool,
}

impl DovetailResearchResultServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            service_id: String::from(crate::SERVICE_ID),
            provider_id: String::from(crate::PROVIDER_ID),
            consumer_id: String::from(crate::CONSUMER_ID),
            contract_version: String::from(crate::CONTRACT_VERSION),
            operations: vec![
                DovetailResearchResultServiceOperation::DescribeCapabilities,
                DovetailResearchResultServiceOperation::Register,
                DovetailResearchResultServiceOperation::RevokeRegistration,
                DovetailResearchResultServiceOperation::ReadBoundedMetadata,
                DovetailResearchResultServiceOperation::CompileResearchResultProposal,
                DovetailResearchResultServiceOperation::RecordResearchResult,
            ],
            read_only: true,
            external_writes: false,
            export_or_download: false,
            webhooks: false,
            transcript_access: false,
            media_access: false,
            kernel_authority: false,
            connected_authority: false,
        }
    }

    pub fn validate(&self) -> crate::Result<()> {
        let expected = Self::layer1();
        if self == &expected {
            Ok(())
        } else {
            Err(DovetailResearchResultError::InvalidContract)
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// Typed Layer-1 service. Provider reads are bounded; proposal and recording
/// operations are delegated to the Mission consumer so no kernel adoption path
/// is accidentally implied by the service itself.
#[derive(Clone, Debug)]
pub struct DovetailResearchResultService<T: DovetailTransport = crate::DovetailFixtureTransport> {
    provider: DovetailProvider<T>,
    definition: DovetailResearchResultServiceDefinition,
}

impl<T> DovetailResearchResultService<T>
where
    T: DovetailTransport,
{
    pub fn new(provider: DovetailProvider<T>) -> crate::Result<Self> {
        let definition = DovetailResearchResultServiceDefinition::layer1();
        definition.validate()?;
        Ok(Self {
            provider,
            definition,
        })
    }

    pub fn definition(&self) -> &DovetailResearchResultServiceDefinition {
        &self.definition
    }

    pub fn provider(&self) -> &DovetailProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut DovetailProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &DovetailRegistration {
        self.provider.registration()
    }

    pub fn registration_receipt(&self) -> RegistrationReceipt {
        self.registration().receipt()
    }

    pub fn read(
        &mut self,
        request: &DovetailResearchReadRequest,
    ) -> crate::Result<DovetailResearchObservation> {
        self.provider.read(request)
    }

    pub fn current_registration_digest(&self) -> Digest {
        self.registration().registration_digest.clone()
    }

    pub fn current_scope_digest(&self) -> Digest {
        self.registration().scope.scope_digest.clone()
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.provider.provenance()
    }

    pub fn connected(&self) -> bool {
        false
    }

    pub fn native(&self) -> bool {
        false
    }
}
