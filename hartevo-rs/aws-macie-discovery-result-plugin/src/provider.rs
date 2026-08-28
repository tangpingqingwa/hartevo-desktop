//! Scope-bound, non-native Macie provider seam.

use std::fmt;

use crate::model::{
    Digest, FindingIdAllowlist, GetFindingsPage, GetFindingsRequest, ListFindingsPage,
    ListFindingsRequest, MacieDiscoveryScope, MacieReadRequest, ProviderProvenance, Revision,
    SigV4SecretReference,
};
use crate::transport::MacieTransport;
use crate::{
    AWS_MACIE_CONTRACT_VERSION, AWS_MACIE_GET_FINDINGS_PERMISSION,
    AWS_MACIE_LIST_FINDINGS_PERMISSION, AWS_MACIE_PLUGIN_VERSION_TEXT, AWS_MACIE_PROVIDER_ID,
    AWS_MACIE_PROVIDER_REVISION, MacieDiscoveryResultError, Result, contract_digest,
    permission_digest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderRegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacieRegistrationRequest {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope: MacieDiscoveryScope,
    pub secret_reference: SigV4SecretReference,
}

impl MacieRegistrationRequest {
    pub fn new(
        scope: MacieDiscoveryScope,
        secret_reference: SigV4SecretReference,
        permission_digest_value: Digest,
        provider_revision: impl Into<String>,
        provider_digest_value: Digest,
    ) -> Result<Self> {
        let provider_revision = provider_revision.into();
        if provider_revision.trim().is_empty()
            || provider_revision.chars().any(char::is_control)
            || provider_revision != AWS_MACIE_PROVIDER_REVISION
            || secret_reference.scope_digest() != &scope.digest()
            || permission_digest_value != permission_digest()
            || provider_digest_value != provider_digest_for_revision(&provider_revision)
        {
            return Err(MacieDiscoveryResultError::InvalidRegistration);
        }
        Ok(Self {
            plugin_version: AWS_MACIE_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: AWS_MACIE_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_revision,
            provider_digest: provider_digest_value,
            permission_digest: permission_digest_value,
            scope,
            secret_reference,
        })
    }

    pub fn baseline(
        scope: MacieDiscoveryScope,
        secret_reference: SigV4SecretReference,
    ) -> Result<Self> {
        Self::new(
            scope,
            secret_reference,
            permission_digest(),
            AWS_MACIE_PROVIDER_REVISION,
            provider_digest(),
        )
    }
}

pub struct MacieRegistration {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_revision: String,
    provider_digest: Digest,
    permission_digest: Digest,
    scope: MacieDiscoveryScope,
    secret_reference: SigV4SecretReference,
    registration_digest: Digest,
    state: ProviderRegistrationState,
    revocation_revision: Option<Revision>,
}

impl fmt::Debug for MacieRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacieRegistration")
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest)
            .field("scope", &self.scope)
            .field(
                "secret_reference_digest",
                &self.secret_reference.reference_digest(),
            )
            .field("registration_digest", &self.registration_digest)
            .field("state", &self.state)
            .field("revocation_revision", &self.revocation_revision)
            .finish()
    }
}

impl Clone for MacieRegistration {
    fn clone(&self) -> Self {
        Self {
            plugin_version: self.plugin_version.clone(),
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            provider_revision: self.provider_revision.clone(),
            provider_digest: self.provider_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            scope: self.scope.clone(),
            secret_reference: self.secret_reference.clone(),
            registration_digest: self.registration_digest.clone(),
            state: self.state,
            revocation_revision: self.revocation_revision,
        }
    }
}

impl PartialEq for MacieRegistration {
    fn eq(&self, other: &Self) -> bool {
        self.plugin_version == other.plugin_version
            && self.contract_version == other.contract_version
            && self.contract_digest == other.contract_digest
            && self.provider_revision == other.provider_revision
            && self.provider_digest == other.provider_digest
            && self.permission_digest == other.permission_digest
            && self.scope == other.scope
            && self.secret_reference == other.secret_reference
            && self.registration_digest == other.registration_digest
            && self.state == other.state
            && self.revocation_revision == other.revocation_revision
    }
}

impl Eq for MacieRegistration {}

impl MacieRegistration {
    pub fn new(request: MacieRegistrationRequest) -> Result<Self> {
        if request.plugin_version != AWS_MACIE_PLUGIN_VERSION_TEXT
            || request.contract_version != AWS_MACIE_CONTRACT_VERSION
            || request.contract_digest != contract_digest()
            || request.provider_revision != AWS_MACIE_PROVIDER_REVISION
            || request.provider_digest != provider_digest_for_revision(&request.provider_revision)
            || request.permission_digest != permission_digest()
            || request.secret_reference.scope_digest() != &request.scope.digest()
        {
            return Err(MacieDiscoveryResultError::InvalidRegistration);
        }
        request.scope.validate()?;
        let registration_digest = Digest::from_fields(
            "hartevo.aws-macie-registration/v1",
            &[
                request.plugin_version.clone(),
                request.contract_version.clone(),
                request.contract_digest.as_str().to_owned(),
                request.provider_revision.clone(),
                request.provider_digest.as_str().to_owned(),
                request.permission_digest.as_str().to_owned(),
                request.scope.digest().as_str().to_owned(),
                request
                    .secret_reference
                    .reference_digest()
                    .as_str()
                    .to_owned(),
            ],
        );
        Ok(Self {
            plugin_version: request.plugin_version,
            contract_version: request.contract_version,
            contract_digest: request.contract_digest,
            provider_revision: request.provider_revision,
            provider_digest: request.provider_digest,
            permission_digest: request.permission_digest,
            scope: request.scope,
            secret_reference: request.secret_reference,
            registration_digest,
            state: ProviderRegistrationState::Active,
            revocation_revision: None,
        })
    }

    pub fn validate_for(
        &self,
        provider_revision: &str,
        provider_digest_value: &Digest,
    ) -> Result<()> {
        if self.plugin_version != AWS_MACIE_PLUGIN_VERSION_TEXT
            || self.contract_version != AWS_MACIE_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_revision != provider_revision
            || &self.provider_digest != provider_digest_value
            || self.permission_digest != permission_digest()
            || self.secret_reference.scope_digest() != &self.scope.digest()
        {
            return Err(MacieDiscoveryResultError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn revoke(&mut self, revision: Revision) -> Result<()> {
        if self.state == ProviderRegistrationState::Revoked {
            return Err(MacieDiscoveryResultError::RegistrationRevoked);
        }
        self.state = ProviderRegistrationState::Revoked;
        self.revocation_revision = Some(revision);
        Ok(())
    }

    pub const fn state(&self) -> ProviderRegistrationState {
        self.state
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, ProviderRegistrationState::Active)
    }

    pub fn scope(&self) -> &MacieDiscoveryScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SigV4SecretReference {
        &self.secret_reference
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn revocation_revision(&self) -> Option<Revision> {
        self.revocation_revision
    }
}

pub fn provider_digest() -> Digest {
    provider_digest_for_revision(AWS_MACIE_PROVIDER_REVISION)
}

fn provider_digest_for_revision(provider_revision: &str) -> Digest {
    Digest::from_fields(
        "hartevo.aws-macie-provider/v1",
        &[
            AWS_MACIE_PROVIDER_ID.to_owned(),
            provider_revision.to_owned(),
            crate::AWS_MACIE_API_VERSION.to_owned(),
            AWS_MACIE_LIST_FINDINGS_PERMISSION.to_owned(),
            AWS_MACIE_GET_FINDINGS_PERMISSION.to_owned(),
            "ListFindings".to_owned(),
            "GetFindings".to_owned(),
        ],
    )
}

pub struct MacieProvider<T> {
    transport: T,
    provider_revision: String,
    provider_digest: Digest,
    provenance: ProviderProvenance,
    registration: Option<MacieRegistration>,
}

impl<T> fmt::Debug for MacieProvider<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacieProvider")
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("provenance", &self.provenance)
            .field("registration", &self.registration)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T> MacieProvider<T>
where
    T: MacieTransport,
{
    pub fn new(
        transport: T,
        provider_revision: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        let provider_revision = provider_revision.into();
        if provider_revision.trim().is_empty()
            || provider_revision.chars().any(char::is_control)
            || provider_revision != AWS_MACIE_PROVIDER_REVISION
            || transport.is_native()
            || transport.is_connected()
            || transport.is_first_party()
            || provenance.is_native()
            || provenance.is_connected()
            || provenance.is_first_party()
        {
            return Err(MacieDiscoveryResultError::ProviderDrift);
        }
        Ok(Self {
            transport,
            provider_digest: provider_digest_for_revision(&provider_revision),
            provider_revision,
            provenance,
            registration: None,
        })
    }

    pub fn baseline(transport: T) -> Result<Self> {
        let provenance = transport.provenance();
        Self::new(transport, AWS_MACIE_PROVIDER_REVISION, provenance)
    }

    pub fn register(&mut self, request: MacieRegistrationRequest) -> Result<MacieRegistration> {
        if request.provider_revision != self.provider_revision
            || request.provider_digest != self.provider_digest
        {
            return Err(MacieDiscoveryResultError::ProviderDrift);
        }
        let registration = MacieRegistration::new(request)?;
        registration.validate_for(&self.provider_revision, &self.provider_digest)?;
        self.registration = Some(registration.clone());
        Ok(registration)
    }

    pub fn register_scope(
        &mut self,
        scope: MacieDiscoveryScope,
        secret_reference: SigV4SecretReference,
    ) -> Result<MacieRegistration> {
        let request = MacieRegistrationRequest::new(
            scope,
            secret_reference,
            permission_digest(),
            self.provider_revision.clone(),
            self.provider_digest.clone(),
        )?;
        self.register(request)
    }

    pub fn revoke_registration(&mut self, revision: Revision) -> Result<()> {
        self.registration_mut()?.revoke(revision)
    }

    pub fn registration(&self) -> Option<&MacieRegistration> {
        self.registration.as_ref()
    }

    pub fn registration_mut(&mut self) -> Result<&mut MacieRegistration> {
        self.registration
            .as_mut()
            .ok_or(MacieDiscoveryResultError::RegistrationMissing)
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn list_findings(&mut self, request: &ListFindingsRequest) -> Result<ListFindingsPage> {
        self.execute_list(request)
    }

    pub fn get_findings(&mut self, request: &GetFindingsRequest) -> Result<GetFindingsPage> {
        self.execute_get(request)
    }

    pub fn read_list_findings(&mut self, request: &MacieReadRequest) -> Result<ListFindingsPage> {
        let scope = self
            .registration()
            .ok_or(MacieDiscoveryResultError::RegistrationMissing)?
            .scope()
            .clone();
        let request = request.first_list_page(&scope)?;
        self.list_findings(&request)
    }

    fn execute_list(&mut self, request: &ListFindingsRequest) -> Result<ListFindingsPage> {
        self.assert_active_registration()?;
        let registration = self
            .registration
            .as_ref()
            .ok_or(MacieDiscoveryResultError::RegistrationMissing)?;
        if request.scope_digest() != &registration.scope().digest() {
            return Err(MacieDiscoveryResultError::ScopeMismatch);
        }
        let page = self.transport.list_findings(request)?;
        page.validate_for(request)
            .map_err(|_| MacieDiscoveryResultError::PageBindingMismatch)?;
        if page.provider_revision != self.provider_revision {
            return Err(MacieDiscoveryResultError::ProviderDrift);
        }
        Ok(page)
    }

    fn execute_get(&mut self, request: &GetFindingsRequest) -> Result<GetFindingsPage> {
        self.assert_active_registration()?;
        let registration = self
            .registration
            .as_ref()
            .ok_or(MacieDiscoveryResultError::RegistrationMissing)?;
        if request.scope_digest() != &registration.scope().digest() {
            return Err(MacieDiscoveryResultError::ScopeMismatch);
        }
        let page = self.transport.get_findings(request)?;
        page.validate_for(request)
            .map_err(|_| MacieDiscoveryResultError::PageBindingMismatch)?;
        if page.provider_revision != self.provider_revision {
            return Err(MacieDiscoveryResultError::ProviderDrift);
        }
        Ok(page)
    }

    fn assert_active_registration(&self) -> Result<()> {
        let registration = self
            .registration
            .as_ref()
            .ok_or(MacieDiscoveryResultError::RegistrationMissing)?;
        if !registration.is_active() {
            return Err(MacieDiscoveryResultError::RegistrationRevoked);
        }
        registration.validate_for(&self.provider_revision, &self.provider_digest)
    }

    pub fn allowlist_for_get(&self, list_page: &ListFindingsPage) -> Result<FindingIdAllowlist> {
        FindingIdAllowlist::for_get(list_page.finding_ids.as_slice().to_vec())
            .map_err(MacieDiscoveryResultError::from)
    }
}
