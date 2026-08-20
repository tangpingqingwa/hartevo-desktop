//! Scope-bound AWS Security Hub provider seam.

use crate::model::{
    AwsSecurityHubScope, Digest, FindingsReadRequest, GetFindingsApi, GetFindingsPage,
    GetFindingsRequest, ProviderProvenance, Revision, SigV4SecretReference,
};
use crate::transport::AwsSecurityHubTransport;
use crate::{
    AWS_SECURITY_HUB_CONTRACT_VERSION, AWS_SECURITY_HUB_IAM_PERMISSION,
    AWS_SECURITY_HUB_PLUGIN_VERSION_TEXT, AWS_SECURITY_HUB_PROVIDER_ID,
    AWS_SECURITY_HUB_PROVIDER_REVISION, AwsSecurityHubError, contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsSecurityHubRegistrationRequest {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope: AwsSecurityHubScope,
    pub secret_reference: SigV4SecretReference,
}

impl AwsSecurityHubRegistrationRequest {
    pub fn new(
        scope: AwsSecurityHubScope,
        secret_reference: SigV4SecretReference,
        permission_digest: Digest,
        provider_revision: impl Into<String>,
        provider_digest: Digest,
    ) -> Result<Self, AwsSecurityHubError> {
        let provider_revision = provider_revision.into();
        if provider_revision.trim().is_empty()
            || provider_revision.chars().any(char::is_control)
            || secret_reference.scope_digest() != &scope.digest()
        {
            return Err(AwsSecurityHubError::InvalidRegistration);
        }
        Ok(Self {
            plugin_version: AWS_SECURITY_HUB_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: AWS_SECURITY_HUB_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_revision,
            provider_digest,
            permission_digest,
            scope,
            secret_reference,
        })
    }

    pub fn baseline(
        scope: AwsSecurityHubScope,
        secret_reference: SigV4SecretReference,
        permission_digest: Digest,
    ) -> Result<Self, AwsSecurityHubError> {
        Self::new(
            scope,
            secret_reference,
            permission_digest,
            AWS_SECURITY_HUB_PROVIDER_REVISION,
            provider_digest(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsSecurityHubRegistration {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_revision: String,
    provider_digest: Digest,
    permission_digest: Digest,
    scope: AwsSecurityHubScope,
    secret_reference: SigV4SecretReference,
    registration_digest: Digest,
    state: RegistrationState,
    revocation_revision: Option<Revision>,
}

impl AwsSecurityHubRegistration {
    pub fn new(request: AwsSecurityHubRegistrationRequest) -> Result<Self, AwsSecurityHubError> {
        if request.plugin_version != AWS_SECURITY_HUB_PLUGIN_VERSION_TEXT
            || request.contract_version != AWS_SECURITY_HUB_CONTRACT_VERSION
            || request.contract_digest != contract_digest()
            || request.secret_reference.scope_digest() != &request.scope.digest()
        {
            return Err(AwsSecurityHubError::InvalidRegistration);
        }
        let registration_digest = Digest::from_fields(
            "hartevo.aws-security-hub-registration/v1",
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
            state: RegistrationState::Active,
            revocation_revision: None,
        })
    }

    pub fn validate_for(
        &self,
        provider_revision: &str,
        provider_digest_value: &Digest,
    ) -> Result<(), AwsSecurityHubError> {
        if self.plugin_version != AWS_SECURITY_HUB_PLUGIN_VERSION_TEXT
            || self.contract_version != AWS_SECURITY_HUB_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_revision != provider_revision
            || &self.provider_digest != provider_digest_value
            || self.secret_reference.scope_digest() != &self.scope.digest()
        {
            return Err(AwsSecurityHubError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn revoke(&mut self, revision: Revision) -> Result<(), AwsSecurityHubError> {
        if self.state == RegistrationState::Revoked {
            return Err(AwsSecurityHubError::RegistrationRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.revocation_revision = Some(revision);
        Ok(())
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn scope(&self) -> &AwsSecurityHubScope {
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
    provider_digest_for_revision(AWS_SECURITY_HUB_PROVIDER_REVISION)
}

fn provider_digest_for_revision(provider_revision: &str) -> Digest {
    Digest::from_fields(
        "hartevo.aws-security-hub-provider/v1",
        &[
            AWS_SECURITY_HUB_PROVIDER_ID.to_owned(),
            provider_revision.to_owned(),
            crate::AWS_SECURITY_HUB_API_VERSION.to_owned(),
            AWS_SECURITY_HUB_IAM_PERMISSION.to_owned(),
            "GetFindings".to_owned(),
            "GetFindingsV2".to_owned(),
        ],
    )
}

pub struct AwsSecurityHubProvider<T> {
    transport: T,
    provider_revision: String,
    provider_digest: Digest,
    provenance: ProviderProvenance,
    registration: Option<AwsSecurityHubRegistration>,
}

impl<T> std::fmt::Debug for AwsSecurityHubProvider<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AwsSecurityHubProvider")
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("provenance", &self.provenance)
            .field("registration", &self.registration)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T> AwsSecurityHubProvider<T>
where
    T: AwsSecurityHubTransport,
{
    pub fn new(
        transport: T,
        provider_revision: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, AwsSecurityHubError> {
        let provider_revision = provider_revision.into();
        if provider_revision.trim().is_empty()
            || provider_revision.chars().any(char::is_control)
            || transport.is_native()
            || provenance.is_native()
        {
            return Err(AwsSecurityHubError::ProviderDrift);
        }
        Ok(Self {
            transport,
            provider_digest: provider_digest_for_revision(&provider_revision),
            provider_revision,
            provenance,
            registration: None,
        })
    }

    pub fn baseline(transport: T) -> Result<Self, AwsSecurityHubError> {
        Self::new(
            transport,
            AWS_SECURITY_HUB_PROVIDER_REVISION,
            ProviderProvenance::Recording,
        )
    }

    pub fn register(
        &mut self,
        request: AwsSecurityHubRegistrationRequest,
    ) -> Result<AwsSecurityHubRegistration, AwsSecurityHubError> {
        if request.provider_revision != self.provider_revision
            || request.provider_digest != self.provider_digest
        {
            return Err(AwsSecurityHubError::ProviderDrift);
        }
        let registration = AwsSecurityHubRegistration::new(request)?;
        registration.validate_for(&self.provider_revision, &self.provider_digest)?;
        self.registration = Some(registration.clone());
        Ok(registration)
    }

    pub fn register_scope(
        &mut self,
        scope: AwsSecurityHubScope,
        secret_reference: SigV4SecretReference,
        permission_digest: Digest,
    ) -> Result<AwsSecurityHubRegistration, AwsSecurityHubError> {
        let request = AwsSecurityHubRegistrationRequest::new(
            scope,
            secret_reference,
            permission_digest,
            self.provider_revision.clone(),
            self.provider_digest.clone(),
        )?;
        self.register(request)
    }

    pub fn revoke_registration(&mut self, revision: Revision) -> Result<(), AwsSecurityHubError> {
        self.registration_mut()?.revoke(revision)
    }

    pub fn registration(&self) -> Option<&AwsSecurityHubRegistration> {
        self.registration.as_ref()
    }

    pub fn registration_mut(
        &mut self,
    ) -> Result<&mut AwsSecurityHubRegistration, AwsSecurityHubError> {
        self.registration
            .as_mut()
            .ok_or(AwsSecurityHubError::RegistrationMissing)
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

    pub fn get_findings(
        &mut self,
        request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, AwsSecurityHubError> {
        self.execute(request, GetFindingsApi::GetFindings)
    }

    pub fn get_findings_v2(
        &mut self,
        request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, AwsSecurityHubError> {
        self.execute(request, GetFindingsApi::GetFindingsV2)
    }

    pub fn read_page(
        &mut self,
        request: &GetFindingsRequest,
    ) -> Result<GetFindingsPage, AwsSecurityHubError> {
        match request.api() {
            GetFindingsApi::GetFindings => self.get_findings(request),
            GetFindingsApi::GetFindingsV2 => self.get_findings_v2(request),
        }
    }

    pub fn read_request(
        &mut self,
        request: &FindingsReadRequest,
    ) -> Result<GetFindingsPage, AwsSecurityHubError> {
        let scope = self
            .registration()
            .ok_or(AwsSecurityHubError::RegistrationMissing)?
            .scope()
            .clone();
        let request = request.first_page(&scope)?;
        self.read_page(&request)
    }

    fn execute(
        &mut self,
        request: &GetFindingsRequest,
        expected_api: GetFindingsApi,
    ) -> Result<GetFindingsPage, AwsSecurityHubError> {
        let registration = self
            .registration
            .as_ref()
            .ok_or(AwsSecurityHubError::RegistrationMissing)?;
        if !registration.is_active() {
            return Err(AwsSecurityHubError::RegistrationRevoked);
        }
        registration.validate_for(&self.provider_revision, &self.provider_digest)?;
        if request.api() != expected_api || request.scope_digest() != &registration.scope().digest()
        {
            return Err(AwsSecurityHubError::ScopeMismatch);
        }
        let page = match expected_api {
            GetFindingsApi::GetFindings => self.transport.get_findings(request),
            GetFindingsApi::GetFindingsV2 => self.transport.get_findings_v2(request),
        }?;
        page.validate_for(request)
            .map_err(|_| AwsSecurityHubError::PageBindingMismatch)?;
        if page.provider_revision != self.provider_revision {
            return Err(AwsSecurityHubError::ProviderDrift);
        }
        Ok(page)
    }
}
