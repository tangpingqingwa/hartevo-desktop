//! Scope-bound, non-native AWS License Manager provider seams.

use std::{collections::VecDeque, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{AwsLicenseManagerError, AwsLicenseManagerTransportError, Result};
use crate::model::{
    AwsLicenseManagerScope, Digest, LicenseConfigurationMetadata, LicenseUsageItem,
    ProviderProvenance, SecretReference, UsageWindow,
};
use crate::service::{
    AwsLicenseManagerRegistration, AwsLicenseManagerRegistrationRequest, RegistrationState,
};
use crate::{
    AWS_LICENSE_MANAGER_API_VERSION, AWS_LICENSE_MANAGER_MAX_PAGE_SIZE,
    AWS_LICENSE_MANAGER_MAX_PAGES, AWS_LICENSE_MANAGER_MAX_RESPONSE_BYTES,
    AWS_LICENSE_MANAGER_MAX_USAGE_ITEMS, AWS_LICENSE_MANAGER_PERMISSIONS,
    AWS_LICENSE_MANAGER_PROVIDER_ID, AWS_LICENSE_MANAGER_PROVIDER_REVISION,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsLicenseManagerOperation {
    ListLicenseConfigurations,
    GetLicenseConfiguration,
    ListUsageForLicenseConfiguration,
}

impl AwsLicenseManagerOperation {
    pub const ALL: [Self; 3] = [
        Self::ListLicenseConfigurations,
        Self::GetLicenseConfiguration,
        Self::ListUsageForLicenseConfiguration,
    ];

    pub const fn as_api_name(self) -> &'static str {
        match self {
            Self::ListLicenseConfigurations => "ListLicenseConfigurations",
            Self::GetLicenseConfiguration => "GetLicenseConfiguration",
            Self::ListUsageForLicenseConfiguration => "ListUsageForLicenseConfiguration",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsLicenseManagerProviderDefinition {
    pub provider_id: String,
    pub provider_revision: String,
    pub api_version: String,
    pub provider_digest: Digest,
    pub operations: Vec<AwsLicenseManagerOperation>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
}

impl Default for AwsLicenseManagerProviderDefinition {
    fn default() -> Self {
        Self::baseline()
    }
}

impl AwsLicenseManagerProviderDefinition {
    pub fn baseline() -> Self {
        Self::for_revision(AWS_LICENSE_MANAGER_PROVIDER_REVISION)
    }

    pub fn for_revision(provider_revision: impl Into<String>) -> Self {
        let provider_revision = provider_revision.into();
        Self {
            provider_id: AWS_LICENSE_MANAGER_PROVIDER_ID.to_owned(),
            provider_revision: provider_revision.clone(),
            api_version: AWS_LICENSE_MANAGER_API_VERSION.to_owned(),
            provider_digest: Digest::from_fields(
                "hartevo.aws-license-manager-provider/v1",
                &[
                    AWS_LICENSE_MANAGER_PROVIDER_ID.to_owned(),
                    provider_revision,
                    AWS_LICENSE_MANAGER_API_VERSION.to_owned(),
                    AWS_LICENSE_MANAGER_PERMISSIONS.join("\n"),
                    "ListLicenseConfigurations".to_owned(),
                    "GetLicenseConfiguration".to_owned(),
                    "ListUsageForLicenseConfiguration".to_owned(),
                ],
            ),
            operations: AwsLicenseManagerOperation::ALL.to_vec(),
            permissions: AWS_LICENSE_MANAGER_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != AWS_LICENSE_MANAGER_PROVIDER_ID
            || self.api_version != AWS_LICENSE_MANAGER_API_VERSION
            || self.operations != AwsLicenseManagerOperation::ALL
            || self.permissions
                != AWS_LICENSE_MANAGER_PERMISSIONS
                    .iter()
                    .map(|permission| (*permission).to_owned())
                    .collect::<Vec<_>>()
            || self.provider_digest
                != Self::for_revision(self.provider_revision.clone()).provider_digest
            || !self.read_only
            || self.connected
            || self.native
            || self.first_party
            || self.external_writes
        {
            return Err(AwsLicenseManagerError::ProviderDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    material: Zeroizing<String>,
    token_digest: Digest,
    scope_digest: Digest,
    filter_digest: Digest,
    page_number: u16,
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("token_digest", &self.token_digest)
            .field("scope_digest", &self.scope_digest)
            .field("filter_digest", &self.filter_digest)
            .field("page_number", &self.page_number)
            .field("opaque", &true)
            .finish()
    }
}

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let material = value.into();
        if material.is_empty() || material.len() > 512 || material.chars().any(char::is_control) {
            return Err(AwsLicenseManagerError::InvalidRequest);
        }
        Ok(Self {
            token_digest: Digest::from_fields("aws-license-manager-page-token/v1", &[&material]),
            material: Zeroizing::new(material),
            scope_digest: Digest::zero(),
            filter_digest: Digest::zero(),
            page_number: 0,
        })
    }

    pub fn for_request(
        value: impl Into<String>,
        scope: &AwsLicenseManagerScope,
        filter_digest: &Digest,
        page_number: u16,
    ) -> Result<Self> {
        let mut token = Self::new(value)?;
        token.bind(scope, filter_digest, page_number)?;
        Ok(token)
    }

    pub fn bind(
        &mut self,
        scope: &AwsLicenseManagerScope,
        filter_digest: &Digest,
        page_number: u16,
    ) -> Result<()> {
        if page_number == 0 || page_number > crate::AWS_LICENSE_MANAGER_MAX_PAGES {
            return Err(AwsLicenseManagerError::InvalidRequest);
        }
        self.scope_digest = scope.digest();
        self.filter_digest = filter_digest.clone();
        self.page_number = page_number;
        Ok(())
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn digest(&self) -> &Digest {
        self.token_digest()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    fn validate_for(
        &self,
        scope: &AwsLicenseManagerScope,
        filter_digest: &Digest,
        expected_page: u16,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.filter_digest != *filter_digest
            || self.page_number != expected_page
        {
            return Err(AwsLicenseManagerError::CursorMismatch);
        }
        Ok(())
    }
}

impl Serialize for OpaquePageToken {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OpaquePageToken", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

impl Drop for OpaquePageToken {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListLicenseConfigurationsRequest {
    pub scope: AwsLicenseManagerScope,
    pub page_size: u16,
    pub page_number: u16,
    pub cursor: Option<OpaquePageToken>,
    pub filter_digest: Digest,
    pub request_digest: Digest,
}

impl ListLicenseConfigurationsRequest {
    pub fn new(
        scope: &AwsLicenseManagerScope,
        page_size: u16,
        cursor: Option<OpaquePageToken>,
    ) -> Result<Self> {
        let filter_digest = Digest::from_fields(
            "aws-license-manager-list-configurations-filter/v1",
            &[
                scope.account_id().digest().to_string(),
                scope.region().digest().to_string(),
                scope.license_configuration().digest().to_string(),
                scope
                    .managed_resource()
                    .resource_type()
                    .digest()
                    .to_string(),
            ],
        );
        let page_number = cursor.as_ref().map_or(1, |cursor| {
            if cursor.scope_digest().is_zero() {
                2
            } else {
                cursor.page_number()
            }
        });
        if page_size == 0 || page_size > AWS_LICENSE_MANAGER_MAX_PAGE_SIZE {
            return Err(AwsLicenseManagerError::InvalidRequest);
        }
        let cursor = cursor.map(|mut cursor| {
            if cursor.scope_digest().is_zero() {
                let _ = cursor.bind(scope, &filter_digest, page_number);
            }
            cursor
        });
        if let Some(cursor) = &cursor {
            cursor.validate_for(scope, &filter_digest, page_number)?;
        }
        let request_digest = Digest::from_fields(
            "aws-license-manager-list-configurations-request/v1",
            &[
                scope.digest().to_string(),
                filter_digest.to_string(),
                page_size.to_string(),
                page_number.to_string(),
                cursor
                    .as_ref()
                    .map_or_else(String::new, |cursor| cursor.token_digest().to_string()),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            page_size,
            page_number,
            cursor,
            filter_digest,
            request_digest,
        })
    }

    pub fn for_scope(scope: &AwsLicenseManagerScope, page_size: u16) -> Result<Self> {
        Self::new(scope, page_size, None)
    }

    pub fn next_page(&self, token: OpaquePageToken) -> Result<Self> {
        Self::new(&self.scope, self.page_size, Some(token))
    }

    pub fn scope(&self) -> &AwsLicenseManagerScope {
        &self.scope
    }

    pub fn cursor(&self) -> Option<&OpaquePageToken> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/license-configurations?operation=ListLicenseConfigurations&scopeDigest={}&page={}&pageSize={}",
            self.scope.digest(),
            self.page_number,
            self.page_size
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetLicenseConfigurationRequest {
    pub scope: AwsLicenseManagerScope,
    pub request_digest: Digest,
}

impl GetLicenseConfigurationRequest {
    pub fn for_scope(scope: &AwsLicenseManagerScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_fields(
                "aws-license-manager-get-configuration-request/v1",
                &[scope.digest().to_string()],
            ),
        })
    }

    pub fn new(scope: &AwsLicenseManagerScope) -> Result<Self> {
        Self::for_scope(scope)
    }

    pub fn scope(&self) -> &AwsLicenseManagerScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/license-configuration?operation=GetLicenseConfiguration&scopeDigest={}",
            self.scope.digest()
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUsageForLicenseConfigurationRequest {
    pub scope: AwsLicenseManagerScope,
    pub usage_window: UsageWindow,
    pub page_size: u16,
    pub page_number: u16,
    pub cursor: Option<OpaquePageToken>,
    pub filter_digest: Digest,
    pub request_digest: Digest,
}

impl ListUsageForLicenseConfigurationRequest {
    pub fn new(
        scope: &AwsLicenseManagerScope,
        usage_window: UsageWindow,
        page_size: u16,
        cursor: Option<OpaquePageToken>,
    ) -> Result<Self> {
        scope.validate()?;
        usage_window.validate()?;
        if usage_window != *scope.usage_window() {
            return Err(AwsLicenseManagerError::UsageWindowDrift);
        }
        if page_size == 0 || page_size > AWS_LICENSE_MANAGER_MAX_PAGE_SIZE {
            return Err(AwsLicenseManagerError::InvalidRequest);
        }
        let filter_digest = Digest::from_fields(
            "aws-license-manager-list-usage-filter/v1",
            &[
                scope.digest().to_string(),
                usage_window.digest().to_string(),
                scope
                    .managed_resource()
                    .resource_type()
                    .digest()
                    .to_string(),
            ],
        );
        let page_number = cursor.as_ref().map_or(1, |cursor| {
            if cursor.scope_digest().is_zero() {
                2
            } else {
                cursor.page_number()
            }
        });
        let cursor = cursor.map(|mut cursor| {
            if cursor.scope_digest().is_zero() {
                let _ = cursor.bind(scope, &filter_digest, page_number);
            }
            cursor
        });
        if let Some(cursor) = &cursor {
            cursor.validate_for(scope, &filter_digest, page_number)?;
        }
        let request_digest = Digest::from_fields(
            "aws-license-manager-list-usage-request/v1",
            &[
                scope.digest().to_string(),
                filter_digest.to_string(),
                page_size.to_string(),
                page_number.to_string(),
                cursor
                    .as_ref()
                    .map_or_else(String::new, |cursor| cursor.token_digest().to_string()),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            usage_window,
            page_size,
            page_number,
            cursor,
            filter_digest,
            request_digest,
        })
    }

    pub fn for_scope(scope: &AwsLicenseManagerScope, page_size: u16) -> Result<Self> {
        Self::new(scope, scope.usage_window().clone(), page_size, None)
    }

    pub fn next_page(&self, token: OpaquePageToken) -> Result<Self> {
        Self::new(
            &self.scope,
            self.usage_window.clone(),
            self.page_size,
            Some(token),
        )
    }

    pub fn scope(&self) -> &AwsLicenseManagerScope {
        &self.scope
    }

    pub fn usage_window(&self) -> &UsageWindow {
        &self.usage_window
    }

    pub fn cursor(&self) -> Option<&OpaquePageToken> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/license-configuration-usage?operation=ListUsageForLicenseConfiguration&scopeDigest={}&windowDigest={}&page={}&pageSize={}",
            self.scope.digest(),
            self.usage_window.digest(),
            self.page_number,
            self.page_size
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsLicenseManagerOperation,
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub page_number: u16,
    pub page_size: u16,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
}

impl From<&ListLicenseConfigurationsRequest> for RecordedRequest {
    fn from(request: &ListLicenseConfigurationsRequest) -> Self {
        Self {
            operation: AwsLicenseManagerOperation::ListLicenseConfigurations,
            scope_digest: request.scope.digest(),
            filter_digest: request.filter_digest.clone(),
            page_number: request.page_number,
            page_size: request.page_size,
            cursor_digest: request
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: request.request_digest.clone(),
        }
    }
}

impl From<&GetLicenseConfigurationRequest> for RecordedRequest {
    fn from(request: &GetLicenseConfigurationRequest) -> Self {
        Self {
            operation: AwsLicenseManagerOperation::GetLicenseConfiguration,
            scope_digest: request.scope.digest(),
            filter_digest: request.scope.license_configuration().digest(),
            page_number: 1,
            page_size: 1,
            cursor_digest: None,
            request_digest: request.request_digest.clone(),
        }
    }
}

impl From<&ListUsageForLicenseConfigurationRequest> for RecordedRequest {
    fn from(request: &ListUsageForLicenseConfigurationRequest) -> Self {
        Self {
            operation: AwsLicenseManagerOperation::ListUsageForLicenseConfiguration,
            scope_digest: request.scope.digest(),
            filter_digest: request.filter_digest.clone(),
            page_number: request.page_number,
            page_size: request.page_size,
            cursor_digest: request
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: request.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListLicenseConfigurationsPage {
    pub request_digest: Digest,
    pub page_number: u16,
    pub items: Vec<LicenseConfigurationMetadata>,
    pub next_token: Option<OpaquePageToken>,
    pub response_bytes: u64,
    pub provider_revision: String,
    pub provenance: ProviderProvenance,
    pub partial: bool,
    pub page_digest: Digest,
}

impl ListLicenseConfigurationsPage {
    pub fn new(
        request: &ListLicenseConfigurationsRequest,
        items: Vec<LicenseConfigurationMetadata>,
        next_token: Option<OpaquePageToken>,
        response_bytes: u64,
        provider_revision: impl Into<String>,
    ) -> Result<Self> {
        if items.len() > request.page_size as usize
            || response_bytes > AWS_LICENSE_MANAGER_MAX_RESPONSE_BYTES
        {
            return Err(AwsLicenseManagerError::InvalidRequest);
        }
        let page_number = request.page_number;
        let mut next_token = next_token;
        if let Some(token) = &mut next_token {
            if token.scope_digest().is_zero() {
                token.bind(
                    request.scope(),
                    &request.filter_digest,
                    page_number.saturating_add(1),
                )?;
            }
            token.validate_for(
                request.scope(),
                &request.filter_digest,
                page_number.saturating_add(1),
            )?;
        }
        let provider_revision = provider_revision.into();
        if provider_revision.trim().is_empty() {
            return Err(AwsLicenseManagerError::ProviderDrift);
        }
        let page_digest = configuration_page_digest(
            request.request_digest(),
            page_number,
            &items,
            next_token.as_ref(),
            response_bytes,
            &provider_revision,
            false,
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            page_number,
            items,
            next_token,
            response_bytes,
            provider_revision,
            provenance: ProviderProvenance::Recording,
            partial: false,
            page_digest,
        })
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: ProviderProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    #[must_use]
    pub fn with_partial(mut self, partial: bool) -> Self {
        self.partial = partial;
        self.page_digest = configuration_page_digest(
            &self.request_digest,
            self.page_number,
            &self.items,
            self.next_token.as_ref(),
            self.response_bytes,
            &self.provider_revision,
            self.partial,
        );
        self
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.page_digest = digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_token.is_some()
    }

    pub fn validate_integrity(&self, request: &ListLicenseConfigurationsRequest) -> Result<()> {
        if self.request_digest != *request.request_digest()
            || self.page_number != request.page_number
            || self.items.len() > request.page_size as usize
            || self.response_bytes > AWS_LICENSE_MANAGER_MAX_RESPONSE_BYTES
            || self.provider_revision.is_empty()
        {
            return Err(AwsLicenseManagerError::TamperedEvidence);
        }
        for item in &self.items {
            item.validate_for(request.scope())?;
        }
        if let Some(token) = &self.next_token {
            token.validate_for(
                request.scope(),
                &request.filter_digest,
                self.page_number.saturating_add(1),
            )?;
        }
        let expected = configuration_page_digest(
            request.request_digest(),
            self.page_number,
            &self.items,
            self.next_token.as_ref(),
            self.response_bytes,
            &self.provider_revision,
            self.partial,
        );
        if self.page_digest != expected {
            return Err(AwsLicenseManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetLicenseConfigurationPage {
    pub request_digest: Digest,
    pub configuration: LicenseConfigurationMetadata,
    pub response_bytes: u64,
    pub provider_revision: String,
    pub provenance: ProviderProvenance,
    pub page_digest: Digest,
}

pub type GetLicenseConfigurationResponse = GetLicenseConfigurationPage;

impl GetLicenseConfigurationPage {
    pub fn new(
        request: &GetLicenseConfigurationRequest,
        configuration: LicenseConfigurationMetadata,
        response_bytes: u64,
        provider_revision: impl Into<String>,
    ) -> Result<Self> {
        if response_bytes > AWS_LICENSE_MANAGER_MAX_RESPONSE_BYTES {
            return Err(AwsLicenseManagerError::InvalidRequest);
        }
        let provider_revision = provider_revision.into();
        if provider_revision.trim().is_empty() {
            return Err(AwsLicenseManagerError::ProviderDrift);
        }
        configuration.validate_for(request.scope())?;
        let page_digest =
            get_page_digest(request, &configuration, response_bytes, &provider_revision);
        Ok(Self {
            request_digest: request.request_digest.clone(),
            configuration,
            response_bytes,
            provider_revision,
            provenance: ProviderProvenance::Recording,
            page_digest,
        })
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: ProviderProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.page_digest = digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetLicenseConfigurationRequest) -> Result<()> {
        if self.request_digest != *request.request_digest()
            || self.response_bytes > AWS_LICENSE_MANAGER_MAX_RESPONSE_BYTES
        {
            return Err(AwsLicenseManagerError::TamperedEvidence);
        }
        self.configuration.validate_for(request.scope())?;
        if self.page_digest
            != get_page_digest(
                request,
                &self.configuration,
                self.response_bytes,
                &self.provider_revision,
            )
        {
            return Err(AwsLicenseManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUsageForLicenseConfigurationPage {
    pub request_digest: Digest,
    pub page_number: u16,
    pub items: Vec<LicenseUsageItem>,
    pub next_token: Option<OpaquePageToken>,
    pub response_bytes: u64,
    pub provider_revision: String,
    pub provenance: ProviderProvenance,
    pub partial: bool,
    pub page_digest: Digest,
}

impl ListUsageForLicenseConfigurationPage {
    pub fn new(
        request: &ListUsageForLicenseConfigurationRequest,
        items: Vec<LicenseUsageItem>,
        next_token: Option<OpaquePageToken>,
        response_bytes: u64,
        provider_revision: impl Into<String>,
    ) -> Result<Self> {
        if items.len() > request.page_size as usize
            || items.len() > AWS_LICENSE_MANAGER_MAX_USAGE_ITEMS
            || response_bytes > AWS_LICENSE_MANAGER_MAX_RESPONSE_BYTES
        {
            return Err(AwsLicenseManagerError::InvalidRequest);
        }
        let page_number = request.page_number;
        let mut next_token = next_token;
        if let Some(token) = &mut next_token {
            if token.scope_digest().is_zero() {
                token.bind(
                    request.scope(),
                    &request.filter_digest,
                    page_number.saturating_add(1),
                )?;
            }
            token.validate_for(
                request.scope(),
                &request.filter_digest,
                page_number.saturating_add(1),
            )?;
        }
        let provider_revision = provider_revision.into();
        if provider_revision.trim().is_empty() {
            return Err(AwsLicenseManagerError::ProviderDrift);
        }
        let page_digest = usage_page_digest(
            request.request_digest(),
            page_number,
            &items,
            next_token.as_ref(),
            response_bytes,
            &provider_revision,
            false,
        );
        Ok(Self {
            request_digest: request.request_digest.clone(),
            page_number,
            items,
            next_token,
            response_bytes,
            provider_revision,
            provenance: ProviderProvenance::Recording,
            partial: false,
            page_digest,
        })
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: ProviderProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    #[must_use]
    pub fn with_partial(mut self, partial: bool) -> Self {
        self.partial = partial;
        self.page_digest = usage_page_digest(
            &self.request_digest,
            self.page_number,
            &self.items,
            self.next_token.as_ref(),
            self.response_bytes,
            &self.provider_revision,
            self.partial,
        );
        self
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.page_digest = digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_token.is_some()
    }

    pub fn validate_integrity(
        &self,
        request: &ListUsageForLicenseConfigurationRequest,
    ) -> Result<()> {
        if self.request_digest != *request.request_digest()
            || self.page_number != request.page_number
            || self.items.len() > request.page_size as usize
            || self.items.len() > AWS_LICENSE_MANAGER_MAX_USAGE_ITEMS
            || self.response_bytes > AWS_LICENSE_MANAGER_MAX_RESPONSE_BYTES
            || self.provider_revision.is_empty()
        {
            return Err(AwsLicenseManagerError::TamperedEvidence);
        }
        for item in &self.items {
            item.validate_for(request.scope())?;
            if !request.usage_window.contains(item.association_time()) {
                return Err(AwsLicenseManagerError::UsageWindowDrift);
            }
        }
        if let Some(token) = &self.next_token {
            token.validate_for(
                request.scope(),
                &request.filter_digest,
                request.page_number.saturating_add(1),
            )?;
        }
        let expected = usage_page_digest(
            request.request_digest(),
            request.page_number,
            &self.items,
            self.next_token.as_ref(),
            self.response_bytes,
            &self.provider_revision,
            self.partial,
        );
        if self.page_digest != expected {
            return Err(AwsLicenseManagerError::TamperedEvidence);
        }
        Ok(())
    }
}

pub trait AwsLicenseManagerTransport: fmt::Debug {
    fn list_license_configurations(
        &mut self,
        request: &ListLicenseConfigurationsRequest,
    ) -> std::result::Result<ListLicenseConfigurationsPage, AwsLicenseManagerTransportError>;

    fn get_license_configuration(
        &mut self,
        request: &GetLicenseConfigurationRequest,
    ) -> std::result::Result<GetLicenseConfigurationPage, AwsLicenseManagerTransportError>;

    fn list_usage_for_license_configuration(
        &mut self,
        request: &ListUsageForLicenseConfigurationRequest,
    ) -> std::result::Result<ListUsageForLicenseConfigurationPage, AwsLicenseManagerTransportError>;

    fn provenance(&self) -> ProviderProvenance;

    fn is_native(&self) -> bool {
        false
    }
}

pub struct AwsLicenseManagerProvider<T = BlockedEnvTransport> {
    transport: T,
    definition: AwsLicenseManagerProviderDefinition,
    provenance: ProviderProvenance,
    registration: Option<AwsLicenseManagerRegistration>,
}

impl<T> fmt::Debug for AwsLicenseManagerProvider<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsLicenseManagerProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.provenance)
            .field("registration", &self.registration)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T> AwsLicenseManagerProvider<T>
where
    T: AwsLicenseManagerTransport,
{
    pub fn new(transport: T) -> Result<Self> {
        let provenance = transport.provenance();
        Self::with_identity(transport, AWS_LICENSE_MANAGER_PROVIDER_REVISION, provenance)
    }

    pub fn baseline(transport: T) -> Result<Self> {
        Self::new(transport)
    }

    pub fn with_identity(
        transport: T,
        provider_revision: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        if transport.is_native() || provenance.native() || transport.provenance() != provenance {
            return Err(AwsLicenseManagerError::ProviderDrift);
        }
        let definition = AwsLicenseManagerProviderDefinition::for_revision(provider_revision);
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
            provenance,
            registration: None,
        })
    }

    pub fn definition(&self) -> &AwsLicenseManagerProviderDefinition {
        &self.definition
    }

    pub fn provider_revision(&self) -> &str {
        &self.definition.provider_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.definition.provider_digest
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

    pub fn registration(&self) -> Option<&AwsLicenseManagerRegistration> {
        self.registration.as_ref()
    }

    pub fn registration_mut(&mut self) -> Result<&mut AwsLicenseManagerRegistration> {
        self.registration
            .as_mut()
            .ok_or(AwsLicenseManagerError::InvalidRegistration)
    }

    pub fn register_scope(
        &mut self,
        scope: AwsLicenseManagerScope,
        secret_reference: SecretReference,
        permission_snapshot: crate::model::PermissionSnapshot,
    ) -> Result<AwsLicenseManagerRegistration> {
        let request = AwsLicenseManagerRegistrationRequest::baseline(
            scope,
            secret_reference,
            permission_snapshot,
            self.definition.clone(),
        )?;
        self.register(request)
    }

    pub fn register(
        &mut self,
        request: AwsLicenseManagerRegistrationRequest,
    ) -> Result<AwsLicenseManagerRegistration> {
        if request.provider_revision != self.definition.provider_revision
            || request.provider_digest != self.definition.provider_digest
        {
            return Err(AwsLicenseManagerError::ProviderDrift);
        }
        let registration = AwsLicenseManagerRegistration::new(request)?;
        self.registration = Some(registration.clone());
        Ok(registration)
    }

    pub fn bind_registration(&mut self, registration: AwsLicenseManagerRegistration) -> Result<()> {
        registration.validate_for(&self.definition)?;
        self.registration = Some(registration);
        Ok(())
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<crate::service::RegistrationTransitionEvidence> {
        self.registration_mut()?.revoke()
    }

    pub fn reverse_registration(
        &mut self,
    ) -> Result<crate::service::RegistrationTransitionEvidence> {
        self.registration_mut()?.reverse()
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<crate::service::RegistrationTransitionEvidence> {
        self.registration_mut()?.restore()
    }

    pub fn list_license_configurations(
        &mut self,
        request: &ListLicenseConfigurationsRequest,
    ) -> Result<ListLicenseConfigurationsPage> {
        self.execute_list_configurations(request)
    }

    pub fn get_license_configuration(
        &mut self,
        request: &GetLicenseConfigurationRequest,
    ) -> Result<GetLicenseConfigurationPage> {
        let registration = self.active_registration()?;
        registration.validate_for(&self.definition)?;
        if request.scope().digest() != registration.scope_digest().clone() {
            return Err(AwsLicenseManagerError::ScopeMismatch);
        }
        let page = self.transport.get_license_configuration(request)?;
        page.validate_integrity(request)?;
        if page.provider_revision != self.provider_revision() || page.provenance != self.provenance
        {
            return Err(AwsLicenseManagerError::ProviderDrift);
        }
        Ok(page)
    }

    pub fn list_usage_for_license_configuration(
        &mut self,
        request: &ListUsageForLicenseConfigurationRequest,
    ) -> Result<ListUsageForLicenseConfigurationPage> {
        let registration = self.active_registration()?;
        registration.validate_for(&self.definition)?;
        if request.scope().digest() != registration.scope_digest().clone()
            || request.usage_window != *registration.scope().usage_window()
        {
            return Err(AwsLicenseManagerError::ScopeMismatch);
        }
        let page = self
            .transport
            .list_usage_for_license_configuration(request)?;
        page.validate_integrity(request)?;
        if page.provider_revision != self.provider_revision() || page.provenance != self.provenance
        {
            return Err(AwsLicenseManagerError::ProviderDrift);
        }
        Ok(page)
    }

    fn execute_list_configurations(
        &mut self,
        request: &ListLicenseConfigurationsRequest,
    ) -> Result<ListLicenseConfigurationsPage> {
        let registration = self.active_registration()?;
        registration.validate_for(&self.definition)?;
        if request.scope().digest() != registration.scope_digest().clone() {
            return Err(AwsLicenseManagerError::ScopeMismatch);
        }
        let page = self.transport.list_license_configurations(request)?;
        page.validate_integrity(request)?;
        if page.provider_revision != self.provider_revision() || page.provenance != self.provenance
        {
            return Err(AwsLicenseManagerError::ProviderDrift);
        }
        Ok(page)
    }

    fn active_registration(&self) -> Result<&AwsLicenseManagerRegistration> {
        let registration = self
            .registration
            .as_ref()
            .ok_or(AwsLicenseManagerError::InvalidRegistration)?;
        if registration.state() != RegistrationState::Active {
            return Err(AwsLicenseManagerError::RegistrationRevoked);
        }
        Ok(registration)
    }
}

impl Default for AwsLicenseManagerProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked environment provider definition")
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    list_configurations: VecDeque<
        std::result::Result<ListLicenseConfigurationsPage, AwsLicenseManagerTransportError>,
    >,
    get_configuration:
        VecDeque<std::result::Result<GetLicenseConfigurationPage, AwsLicenseManagerTransportError>>,
    usage: VecDeque<
        std::result::Result<ListUsageForLicenseConfigurationPage, AwsLicenseManagerTransportError>,
    >,
    requests: Vec<RecordedRequest>,
    provenance: ProviderProvenance,
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingTransport {
    pub fn new() -> Self {
        Self {
            list_configurations: VecDeque::new(),
            get_configuration: VecDeque::new(),
            usage: VecDeque::new(),
            requests: Vec::new(),
            provenance: ProviderProvenance::Recording,
        }
    }

    pub fn fixture(
        scope: &AwsLicenseManagerScope,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self::for_scope(scope, observed_at, ProviderProvenance::Fixture)
    }

    pub fn loopback(
        scope: &AwsLicenseManagerScope,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self::for_scope(scope, observed_at, ProviderProvenance::Loopback)
    }

    pub fn for_scope(
        scope: &AwsLicenseManagerScope,
        observed_at: chrono::DateTime<chrono::Utc>,
        provenance: ProviderProvenance,
    ) -> Self {
        let list_request =
            ListLicenseConfigurationsRequest::for_scope(scope, 10).expect("fixture list request");
        let get_request =
            GetLicenseConfigurationRequest::for_scope(scope).expect("fixture get request");
        let usage_request = ListUsageForLicenseConfigurationRequest::for_scope(scope, 10)
            .expect("fixture usage request");
        let configuration = LicenseConfigurationMetadata::fixture(scope, observed_at)
            .expect("fixture configuration");
        let usage_item = LicenseUsageItem::new(
            scope,
            scope.usage_window().start,
            u64::from(provenance != ProviderProvenance::Loopback),
            if provenance == ProviderProvenance::Loopback {
                crate::model::ManagedResourceStatus::Unknown
            } else {
                crate::model::ManagedResourceStatus::Active
            },
        )
        .expect("fixture usage");
        let list_page = ListLicenseConfigurationsPage::new(
            &list_request,
            vec![configuration.clone()],
            None,
            512,
            AWS_LICENSE_MANAGER_PROVIDER_REVISION,
        )
        .expect("fixture list page")
        .with_provenance(provenance);
        let get_page = GetLicenseConfigurationPage::new(
            &get_request,
            configuration,
            512,
            AWS_LICENSE_MANAGER_PROVIDER_REVISION,
        )
        .expect("fixture get page")
        .with_provenance(provenance);
        let usage_page = ListUsageForLicenseConfigurationPage::new(
            &usage_request,
            vec![usage_item],
            None,
            512,
            AWS_LICENSE_MANAGER_PROVIDER_REVISION,
        )
        .expect("fixture usage page")
        .with_provenance(provenance);
        let mut transport = Self::new();
        transport.provenance = provenance;
        transport.list_configurations.push_back(Ok(list_page));
        transport.get_configuration.push_back(Ok(get_page));
        transport.usage.push_back(Ok(usage_page));
        transport
    }

    pub fn push_list_license_configurations(
        &mut self,
        response: std::result::Result<
            ListLicenseConfigurationsPage,
            AwsLicenseManagerTransportError,
        >,
    ) {
        self.list_configurations.push_back(response);
    }

    pub fn push_list_response(
        &mut self,
        response: std::result::Result<
            ListLicenseConfigurationsPage,
            AwsLicenseManagerTransportError,
        >,
    ) {
        self.push_list_license_configurations(response);
    }

    pub fn push_get_license_configuration(
        &mut self,
        response: std::result::Result<GetLicenseConfigurationPage, AwsLicenseManagerTransportError>,
    ) {
        self.get_configuration.push_back(response);
    }

    pub fn push_get_response(
        &mut self,
        response: std::result::Result<GetLicenseConfigurationPage, AwsLicenseManagerTransportError>,
    ) {
        self.push_get_license_configuration(response);
    }

    pub fn push_list_usage_for_license_configuration(
        &mut self,
        response: std::result::Result<
            ListUsageForLicenseConfigurationPage,
            AwsLicenseManagerTransportError,
        >,
    ) {
        self.usage.push_back(response);
    }

    pub fn push_usage_response(
        &mut self,
        response: std::result::Result<
            ListUsageForLicenseConfigurationPage,
            AwsLicenseManagerTransportError,
        >,
    ) {
        self.push_list_usage_for_license_configuration(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    pub fn call_count(&self) -> usize {
        self.requests.len()
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: ProviderProvenance) -> Self {
        self.provenance = provenance;
        self
    }
}

impl AwsLicenseManagerTransport for RecordingTransport {
    fn list_license_configurations(
        &mut self,
        request: &ListLicenseConfigurationsRequest,
    ) -> std::result::Result<ListLicenseConfigurationsPage, AwsLicenseManagerTransportError> {
        self.requests.push(request.into());
        self.list_configurations
            .pop_front()
            .ok_or(AwsLicenseManagerTransportError::QueueExhausted)?
    }

    fn get_license_configuration(
        &mut self,
        request: &GetLicenseConfigurationRequest,
    ) -> std::result::Result<GetLicenseConfigurationPage, AwsLicenseManagerTransportError> {
        self.requests.push(request.into());
        self.get_configuration
            .pop_front()
            .ok_or(AwsLicenseManagerTransportError::QueueExhausted)?
    }

    fn list_usage_for_license_configuration(
        &mut self,
        request: &ListUsageForLicenseConfigurationRequest,
    ) -> std::result::Result<ListUsageForLicenseConfigurationPage, AwsLicenseManagerTransportError>
    {
        self.requests.push(request.into());
        self.usage
            .pop_front()
            .ok_or(AwsLicenseManagerTransportError::QueueExhausted)?
    }

    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    inner: RecordingTransport,
}

impl FixtureTransport {
    pub fn for_scope(
        scope: &AwsLicenseManagerScope,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            inner: RecordingTransport::fixture(scope, observed_at),
        }
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        self.inner.requests()
    }
}

impl AwsLicenseManagerTransport for FixtureTransport {
    fn list_license_configurations(
        &mut self,
        request: &ListLicenseConfigurationsRequest,
    ) -> std::result::Result<ListLicenseConfigurationsPage, AwsLicenseManagerTransportError> {
        self.inner.list_license_configurations(request)
    }

    fn get_license_configuration(
        &mut self,
        request: &GetLicenseConfigurationRequest,
    ) -> std::result::Result<GetLicenseConfigurationPage, AwsLicenseManagerTransportError> {
        self.inner.get_license_configuration(request)
    }

    fn list_usage_for_license_configuration(
        &mut self,
        request: &ListUsageForLicenseConfigurationRequest,
    ) -> std::result::Result<ListUsageForLicenseConfigurationPage, AwsLicenseManagerTransportError>
    {
        self.inner.list_usage_for_license_configuration(request)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: RecordingTransport,
}

impl LoopbackTransport {
    pub fn for_scope(
        scope: &AwsLicenseManagerScope,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            inner: RecordingTransport::loopback(scope, observed_at),
        }
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        self.inner.requests()
    }
}

impl AwsLicenseManagerTransport for LoopbackTransport {
    fn list_license_configurations(
        &mut self,
        request: &ListLicenseConfigurationsRequest,
    ) -> std::result::Result<ListLicenseConfigurationsPage, AwsLicenseManagerTransportError> {
        self.inner.list_license_configurations(request)
    }

    fn get_license_configuration(
        &mut self,
        request: &GetLicenseConfigurationRequest,
    ) -> std::result::Result<GetLicenseConfigurationPage, AwsLicenseManagerTransportError> {
        self.inner.get_license_configuration(request)
    }

    fn list_usage_for_license_configuration(
        &mut self,
        request: &ListUsageForLicenseConfigurationRequest,
    ) -> std::result::Result<ListUsageForLicenseConfigurationPage, AwsLicenseManagerTransportError>
    {
        self.inner.list_usage_for_license_configuration(request)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }
}

pub type RecordingAwsLicenseManagerTransport = RecordingTransport;
pub type FixtureAwsLicenseManagerTransport = FixtureTransport;
pub type LoopbackAwsLicenseManagerTransport = LoopbackTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

pub type BlockedEnvAwsLicenseManagerTransport = BlockedEnvTransport;

impl AwsLicenseManagerTransport for BlockedEnvTransport {
    fn list_license_configurations(
        &mut self,
        _request: &ListLicenseConfigurationsRequest,
    ) -> std::result::Result<ListLicenseConfigurationsPage, AwsLicenseManagerTransportError> {
        Err(AwsLicenseManagerTransportError::BlockedEnv)
    }

    fn get_license_configuration(
        &mut self,
        _request: &GetLicenseConfigurationRequest,
    ) -> std::result::Result<GetLicenseConfigurationPage, AwsLicenseManagerTransportError> {
        Err(AwsLicenseManagerTransportError::BlockedEnv)
    }

    fn list_usage_for_license_configuration(
        &mut self,
        _request: &ListUsageForLicenseConfigurationRequest,
    ) -> std::result::Result<ListUsageForLicenseConfigurationPage, AwsLicenseManagerTransportError>
    {
        Err(AwsLicenseManagerTransportError::BlockedEnv)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }
}

fn configuration_page_digest(
    request_digest: &Digest,
    page_number: u16,
    items: &[LicenseConfigurationMetadata],
    next_token: Option<&OpaquePageToken>,
    response_bytes: u64,
    provider_revision: &str,
    partial: bool,
) -> Digest {
    Digest::from_fields(
        "aws-license-manager-list-configurations-page/v1",
        &[
            request_digest.to_string(),
            page_number.to_string(),
            items
                .iter()
                .map(|item| item.digest().to_string())
                .collect::<Vec<_>>()
                .join("\n"),
            next_token.map_or_else(String::new, |token| token.token_digest().to_string()),
            response_bytes.to_string(),
            provider_revision.to_owned(),
            partial.to_string(),
        ],
    )
}

fn get_page_digest(
    request: &GetLicenseConfigurationRequest,
    configuration: &LicenseConfigurationMetadata,
    response_bytes: u64,
    provider_revision: &str,
) -> Digest {
    Digest::from_fields(
        "aws-license-manager-get-configuration-page/v1",
        &[
            request.request_digest.to_string(),
            configuration.digest().to_string(),
            response_bytes.to_string(),
            provider_revision.to_owned(),
        ],
    )
}

fn usage_page_digest(
    request_digest: &Digest,
    page_number: u16,
    items: &[LicenseUsageItem],
    next_token: Option<&OpaquePageToken>,
    response_bytes: u64,
    provider_revision: &str,
    partial: bool,
) -> Digest {
    Digest::from_fields(
        "aws-license-manager-usage-page/v1",
        &[
            request_digest.to_string(),
            page_number.to_string(),
            items
                .iter()
                .map(|item| item.digest().to_string())
                .collect::<Vec<_>>()
                .join("\n"),
            next_token.map_or_else(String::new, |token| token.token_digest().to_string()),
            response_bytes.to_string(),
            provider_revision.to_owned(),
            partial.to_string(),
        ],
    )
}

// Keep provider-level names available to contract and downstream audit code.
pub const MAX_PAGES: u16 = AWS_LICENSE_MANAGER_MAX_PAGES;
pub const MAX_PAGE_SIZE: u16 = AWS_LICENSE_MANAGER_MAX_PAGE_SIZE;
pub const MAX_RESPONSE_BYTES: u64 = AWS_LICENSE_MANAGER_MAX_RESPONSE_BYTES;
pub const MAX_USAGE_ITEMS: usize = AWS_LICENSE_MANAGER_MAX_USAGE_ITEMS;
