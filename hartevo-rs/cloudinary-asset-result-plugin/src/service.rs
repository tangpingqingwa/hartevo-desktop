use std::{collections::BTreeSet, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionCloudinaryAssetConsumer;
use crate::error::{CloudinaryAssetResultError, CloudinaryTransportError, Result};
use crate::model::{
    AssetProjection, CloudinaryEvidenceState, CloudinaryOperation, CloudinaryScope, CostReceipt,
    DeliveryProjection, Digest, EvidenceDigests, FailureEvidence, MissionProjection,
    ProjectProjection, RequestReceipt, SecretReference, TransformationProjection,
    TransportProvenance, UsageProjection, mission_projection, project_projection,
    work_product_projection,
};
use crate::provider::{
    CloudinaryProvider, CloudinaryProviderDefinition, CloudinaryProviderFailure,
    CloudinaryProviderResponse, CloudinaryReadRequest, CloudinaryRetryPolicy, CloudinaryTransport,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_RESPONSE_BYTES, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
    plugin_version_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "cloudinary-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("new", format!("{new_status:?}")),
                ("registration", registration_digest.as_str().to_owned()),
            ],
        );
        Self {
            previous_status,
            new_status,
            registration_digest,
            transition_digest,
        }
    }
}

/// The permission snapshot is deliberately an allowlist, never a credential
/// or provider-issued authorization receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let snapshot = Self {
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn for_layer_one(revision: u64) -> Self {
        Self {
            revision,
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "cloudinary-permissions/v1",
            &[
                ("revision", self.revision.to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        if self.revision == 0
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !crate::LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            Err(CloudinaryAssetResultError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CloudinaryAssetResultRegistration {
    id: String,
    plugin_version: String,
    version_digest: Digest,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    scope: CloudinaryScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

pub type CloudinaryAssetResultRegistrationBinding = CloudinaryAssetResultRegistration;
pub type CloudinaryRegistration = CloudinaryAssetResultRegistration;

impl CloudinaryAssetResultRegistration {
    pub fn new(
        id: impl Into<String>,
        scope: CloudinaryScope,
        secret_reference: SecretReference,
        provider: &CloudinaryProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            version_digest: plugin_version_digest(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: Digest::from_text(API_REVISION),
            permission_snapshot: PermissionSnapshot::for_layer_one(1),
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-cloudinary-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn for_scope(
        id: impl Into<String>,
        scope: CloudinaryScope,
        provider: &CloudinaryProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        Self::new(
            id,
            scope.clone(),
            scope.secret().clone(),
            provider,
            registration_revision,
        )
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn version_digest(&self) -> &Digest {
        &self.version_digest
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub fn provider_release(&self) -> &str {
        &self.provider_release
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest()
    }

    pub fn scope(&self) -> &CloudinaryScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub const fn is_reversible() -> bool {
        true
    }

    pub const fn is_revocable() -> bool {
        true
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_registration_id(&self.id)
            || self.plugin_version != PLUGIN_VERSION
            || self.version_digest != plugin_version_digest()
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.api_digest != Digest::from_text(API_REVISION)
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.calculate_digest()
        {
            return Err(CloudinaryAssetResultError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope_digest)?;
        if self.secret_reference.reference_digest() != self.scope.secret().reference_digest() {
            return Err(CloudinaryAssetResultError::InvalidSecretReference);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(CloudinaryAssetResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(CloudinaryAssetResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(CloudinaryAssetResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "cloudinary-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("version", self.version_digest.as_str().to_owned()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

impl fmt::Debug for CloudinaryAssetResultRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudinaryAssetResultRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("version_digest", &self.version_digest)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_release", &self.provider_release)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("permission_snapshot", &self.permission_snapshot)
            .field("scope", &self.scope)
            .field("permission_digest", &self.permission_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for CloudinaryAssetResultRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("CloudinaryAssetResultRegistration", 19)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("versionDigest", &self.version_digest)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("reversible", &true)?;
        state.serialize_field("revocable", &true)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

fn valid_registration_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub raw_media_download: bool,
    pub signed_url_execution: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudinaryVerificationRequest {
    pub scope_digest: Digest,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudinaryAssetResultProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub cloud_digest: Digest,
    pub folder_digest: Digest,
    pub asset_digest: Digest,
    pub public_id_digest: Digest,
    pub version_digest: Digest,
    pub transformation_digest: Digest,
    pub delivery_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: crate::model::WorkProductProjection,
    pub state: CloudinaryEvidenceState,
    pub attempts: u8,
    pub backoff_seconds: u64,
    pub asset: Option<AssetProjection>,
    pub usage: Option<UsageProjection>,
    pub transformation: Option<TransformationProjection>,
    pub delivery: Option<DeliveryProjection>,
    pub failure: Option<FailureEvidence>,
    pub request_receipts: Vec<RequestReceipt>,
    pub cost_receipts: Vec<CostReceipt>,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub signed_url_execution: bool,
    pub delivery_guarantee: bool,
    pub media_bytes_retained: bool,
    pub raw_url_retained: bool,
    pub pii_retained: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

pub type CloudinaryAssetResult = CloudinaryAssetResultProposal;
pub type CloudinaryAssetResultEvidence = CloudinaryAssetResultProposal;

impl CloudinaryAssetResultProposal {
    fn from_response(
        registration: &CloudinaryAssetResultRegistration,
        provider: &CloudinaryProviderDefinition,
        request: &CloudinaryReadRequest,
        response: CloudinaryProviderResponse,
        scope: &CloudinaryScope,
        attempts: u8,
        backoff_seconds: u64,
    ) -> Result<Self> {
        let (asset, usage, transformation, delivery) = response.projections(scope)?;
        let effective_attempts = attempts.max(response.attempts);
        let state = match asset.as_ref().map(|value| value.state) {
            Some(crate::model::AssetState::Present)
                if usage.is_some() && transformation.is_some() && delivery.is_some() =>
            {
                CloudinaryEvidenceState::Present
            }
            Some(crate::model::AssetState::Present) => CloudinaryEvidenceState::Partial,
            Some(crate::model::AssetState::Deleted) => CloudinaryEvidenceState::Deleted,
            Some(crate::model::AssetState::Invalid) => CloudinaryEvidenceState::Invalid,
            Some(crate::model::AssetState::Partial) => CloudinaryEvidenceState::Partial,
            Some(crate::model::AssetState::ProviderUnknown) | None => {
                CloudinaryEvidenceState::ProviderUnknown
            }
        };
        Ok(Self::new(
            registration,
            provider,
            request,
            scope,
            state,
            effective_attempts,
            backoff_seconds,
            asset,
            usage,
            transformation,
            delivery,
            None,
            vec![response.request_receipt],
            vec![response.cost_receipt],
            response.provenance,
        ))
    }

    fn from_failure(
        registration: &CloudinaryAssetResultRegistration,
        provider: &CloudinaryProviderDefinition,
        request: &CloudinaryReadRequest,
        scope: &CloudinaryScope,
        failure: &CloudinaryProviderFailure,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let operation = CloudinaryOperation::ResourceMetadata;
        let recorded = request.recorded_request(operation);
        let request_receipt = recorded.receipt(failure.attempts.max(1));
        let cost_receipt = CostReceipt::new(operation, 0)?;
        Ok(Self::new(
            registration,
            provider,
            request,
            scope,
            state_for_transport(&failure.error),
            failure.attempts,
            failure.backoff_seconds,
            None,
            None,
            None,
            None,
            Some(FailureEvidence::from_transport(operation, &failure.error)),
            vec![request_receipt],
            vec![cost_receipt],
            provenance,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &CloudinaryAssetResultRegistration,
        provider: &CloudinaryProviderDefinition,
        request: &CloudinaryReadRequest,
        scope: &CloudinaryScope,
        state: CloudinaryEvidenceState,
        attempts: u8,
        backoff_seconds: u64,
        asset: Option<AssetProjection>,
        usage: Option<UsageProjection>,
        transformation: Option<TransformationProjection>,
        delivery: Option<DeliveryProjection>,
        failure: Option<FailureEvidence>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
        provenance: TransportProvenance,
    ) -> Self {
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: scope.digest(),
            request_digest: request.request_digest.clone(),
            cloud_digest: scope.cloud_digest(),
            folder_digest: scope.folder_digest(),
            asset_digest: scope.asset_digest(),
            public_id_digest: scope.public_id_digest(),
            version_digest: scope.version_digest(),
            transformation_digest: scope.transformation_digest(),
            delivery_digest: scope.delivery_digest(),
            mission: mission_projection(scope),
            project: project_projection(scope),
            work_product: work_product_projection(scope),
            state,
            attempts,
            backoff_seconds,
            asset,
            usage,
            transformation,
            delivery,
            failure,
            request_receipts,
            cost_receipts,
            evidence: EvidenceDigests {
                plugin_version_digest: plugin_version_digest(),
                contract_digest: contract_digest(),
                provider_digest: provider.provider_digest.clone(),
                api_digest: Digest::from_text(API_REVISION),
                permission_digest: registration.permission_digest(),
                scope_digest: scope.digest(),
                cloud_digest: scope.cloud_digest(),
                folder_digest: scope.folder_digest(),
                asset_digest: scope.asset_digest(),
                public_id_digest: scope.public_id_digest(),
                version_digest: scope.version_digest(),
                transformation_digest: scope.transformation_digest(),
                delivery_digest: scope.delivery_digest(),
                resource_digest: None,
                usage_digest: None,
                transformation_metadata_digest: None,
                delivery_metadata_digest: None,
                evidence_digest: Digest::from_text("unsealed-cloudinary-evidence"),
            },
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            signed_url_execution: false,
            delivery_guarantee: false,
            media_bytes_retained: false,
            raw_url_retained: false,
            pii_retained: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-cloudinary-proposal"),
        };
        proposal.evidence.resource_digest = proposal.asset.as_ref().map(AssetProjection::digest);
        proposal.evidence.usage_digest = proposal.usage.as_ref().map(UsageProjection::digest);
        proposal.evidence.transformation_metadata_digest = proposal
            .transformation
            .as_ref()
            .map(TransformationProjection::digest);
        proposal.evidence.delivery_metadata_digest =
            proposal.delivery.as_ref().map(DeliveryProjection::digest);
        proposal.evidence.evidence_digest = proposal.calculate_evidence_digest();
        proposal.proposal_digest = proposal.calculate_proposal_digest();
        proposal
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || !matches!(
                self.provenance,
                TransportProvenance::Recording
                    | TransportProvenance::Fixture
                    | TransportProvenance::Loopback
                    | TransportProvenance::BlockedEnv
            )
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.signed_url_execution
            || self.delivery_guarantee
            || self.media_bytes_retained
            || self.raw_url_retained
            || self.pii_retained
            || self.outcome_adopted
            || self.work_product_adopted
            || self.evidence.evidence_digest != self.calculate_evidence_digest()
            || self.proposal_digest != self.calculate_proposal_digest()
        {
            return Err(CloudinaryAssetResultError::TamperedEvidence);
        }
        self.evidence.validate()?;
        for receipt in &self.request_receipts {
            receipt.validate_integrity()?;
        }
        for receipt in &self.cost_receipts {
            receipt.validate_integrity()?;
        }
        if let Some(asset) = &self.asset {
            asset.validate_integrity()?;
        }
        if let Some(usage) = &self.usage {
            usage.validate_integrity()?;
        }
        if let Some(transformation) = &self.transformation {
            transformation.validate_integrity()?;
        }
        if let Some(delivery) = &self.delivery {
            delivery.validate_integrity()?;
        }
        if self.state.is_present()
            && (self.asset.is_none()
                || self.usage.is_none()
                || self.transformation.is_none()
                || self.delivery.is_none())
        {
            return Err(CloudinaryAssetResultError::PartialEvidence);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    fn calculate_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "cloudinary-evidence/v1",
            &[
                (
                    "plugin",
                    self.evidence.plugin_version_digest.as_str().to_owned(),
                ),
                (
                    "contract",
                    self.evidence.contract_digest.as_str().to_owned(),
                ),
                (
                    "provider",
                    self.evidence.provider_digest.as_str().to_owned(),
                ),
                ("api", self.evidence.api_digest.as_str().to_owned()),
                (
                    "permission",
                    self.evidence.permission_digest.as_str().to_owned(),
                ),
                ("scope", self.evidence.scope_digest.as_str().to_owned()),
                ("cloud", self.evidence.cloud_digest.as_str().to_owned()),
                ("folder", self.evidence.folder_digest.as_str().to_owned()),
                ("asset", self.evidence.asset_digest.as_str().to_owned()),
                (
                    "public_id",
                    self.evidence.public_id_digest.as_str().to_owned(),
                ),
                ("version", self.evidence.version_digest.as_str().to_owned()),
                (
                    "transformation",
                    self.evidence.transformation_digest.as_str().to_owned(),
                ),
                (
                    "delivery",
                    self.evidence.delivery_digest.as_str().to_owned(),
                ),
                (
                    "resource",
                    self.evidence
                        .resource_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "usage",
                    self.evidence
                        .usage_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "transformation_metadata",
                    self.evidence
                        .transformation_metadata_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "delivery_metadata",
                    self.evidence
                        .delivery_metadata_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("state", format!("{:?}", self.state)),
                ("attempts", self.attempts.to_string()),
                ("backoff", self.backoff_seconds.to_string()),
                (
                    "asset_projection",
                    self.asset.as_ref().map_or_else(String::new, |value| {
                        value.projection_digest.as_str().to_owned()
                    }),
                ),
                (
                    "usage_projection",
                    self.usage.as_ref().map_or_else(String::new, |value| {
                        value.projection_digest.as_str().to_owned()
                    }),
                ),
                (
                    "transformation_projection",
                    self.transformation
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            value.metadata_digest.as_str().to_owned()
                        }),
                ),
                (
                    "delivery_projection",
                    self.delivery.as_ref().map_or_else(String::new, |value| {
                        value.projection_digest.as_str().to_owned()
                    }),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        value.failure_digest.as_str().to_owned()
                    }),
                ),
                (
                    "requests",
                    self.request_receipts
                        .iter()
                        .map(|receipt| receipt.receipt_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "costs",
                    self.cost_receipts
                        .iter()
                        .map(|receipt| receipt.receipt_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        )
    }

    fn calculate_proposal_digest(&self) -> Digest {
        Digest::from_parts(
            "cloudinary-asset-result-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("provider", self.provider_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("cloud", self.cloud_digest.as_str().to_owned()),
                ("folder", self.folder_digest.as_str().to_owned()),
                ("asset", self.asset_digest.as_str().to_owned()),
                ("public_id", self.public_id_digest.as_str().to_owned()),
                ("version", self.version_digest.as_str().to_owned()),
                (
                    "transformation",
                    self.transformation_digest.as_str().to_owned(),
                ),
                ("delivery", self.delivery_digest.as_str().to_owned()),
                (
                    "mission",
                    serde_json::to_string(&self.mission).unwrap_or_default(),
                ),
                (
                    "project",
                    serde_json::to_string(&self.project).unwrap_or_default(),
                ),
                (
                    "work_product",
                    serde_json::to_string(&self.work_product).unwrap_or_default(),
                ),
                ("state", format!("{:?}", self.state)),
                ("attempts", self.attempts.to_string()),
                ("backoff", self.backoff_seconds.to_string()),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

pub struct CloudinaryAssetResultService<T: CloudinaryTransport> {
    registration: CloudinaryAssetResultRegistration,
    provider: CloudinaryProvider<T>,
}

pub type CloudinaryService<T> = CloudinaryAssetResultService<T>;

impl<T: CloudinaryTransport> fmt::Debug for CloudinaryAssetResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudinaryAssetResultService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: CloudinaryTransport> CloudinaryAssetResultService<T> {
    pub fn new(scope: CloudinaryScope, provider: CloudinaryProvider<T>) -> Result<Self> {
        let registration = CloudinaryAssetResultRegistration::for_scope(
            "cloudinary-asset-result-registration",
            scope,
            provider.definition(),
            1,
        )?;
        Ok(Self {
            registration,
            provider,
        })
    }

    pub fn new_with_secret(
        scope: CloudinaryScope,
        secret_reference: SecretReference,
        provider: CloudinaryProvider<T>,
    ) -> Result<Self> {
        let registration = CloudinaryAssetResultRegistration::new(
            "cloudinary-asset-result-registration",
            scope,
            secret_reference,
            provider.definition(),
            1,
        )?;
        Ok(Self {
            registration,
            provider,
        })
    }

    pub fn with_registration(
        registration: CloudinaryAssetResultRegistration,
        provider: CloudinaryProvider<T>,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.provider_digest() != &provider.definition().provider_digest {
            return Err(CloudinaryAssetResultError::ProviderDrift);
        }
        Ok(Self {
            registration,
            provider,
        })
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            api_revision: API_REVISION.to_owned(),
            operations: vec![
                CloudinaryOperation::ResourceMetadata.as_str().to_owned(),
                CloudinaryOperation::UsageMetadata.as_str().to_owned(),
                CloudinaryOperation::TransformationMetadata
                    .as_str()
                    .to_owned(),
                CloudinaryOperation::DeliveryMetadata.as_str().to_owned(),
            ],
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            raw_media_download: false,
            signed_url_execution: false,
            outcome_adoption: false,
        }
    }

    pub fn scope(&self) -> &CloudinaryScope {
        self.registration.scope()
    }

    pub fn registration(&self) -> &CloudinaryAssetResultRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut CloudinaryAssetResultRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &CloudinaryProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut CloudinaryProvider<T> {
        &mut self.provider
    }

    pub fn default_request(&self) -> Result<CloudinaryReadRequest> {
        self.request(
            MAX_PAGE_SIZE,
            MAX_PAGES,
            MAX_RESPONSE_BYTES,
            CloudinaryRetryPolicy::default(),
        )
    }

    pub fn request(
        &self,
        page_size: u16,
        max_pages: u16,
        max_response_bytes: u64,
        retry_policy: CloudinaryRetryPolicy,
    ) -> Result<CloudinaryReadRequest> {
        CloudinaryReadRequest::new(
            self.scope(),
            page_size,
            max_pages,
            max_response_bytes,
            retry_policy,
            self.provider.definition().provider_digest.clone(),
            self.registration.registration_digest().clone(),
        )
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn consumer(&self) -> Result<MissionCloudinaryAssetConsumer> {
        MissionCloudinaryAssetConsumer::new(self.scope().clone(), self.registration.clone())
    }

    pub fn propose(
        &mut self,
        request: CloudinaryReadRequest,
    ) -> Result<CloudinaryAssetResultProposal> {
        self.validate_request(&request)?;
        match self.provider.read_detailed(&request) {
            Ok(response) => {
                let attempts = response.attempts;
                match CloudinaryAssetResultProposal::from_response(
                    &self.registration,
                    self.provider.definition(),
                    &request,
                    response,
                    self.scope(),
                    attempts,
                    0,
                ) {
                    Ok(proposal) => Ok(proposal),
                    Err(error) => CloudinaryAssetResultProposal::from_failure(
                        &self.registration,
                        self.provider.definition(),
                        &request,
                        self.scope(),
                        &CloudinaryProviderFailure {
                            error: proposal_error_to_transport(&error),
                            attempts,
                            backoff_seconds: 0,
                        },
                        self.provider.provenance(),
                    ),
                }
            }
            Err(failure) => CloudinaryAssetResultProposal::from_failure(
                &self.registration,
                self.provider.definition(),
                &request,
                self.scope(),
                &failure,
                self.provider.provenance(),
            ),
        }
    }

    pub fn verify(&self, proposal: &CloudinaryAssetResultProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.scope_digest != *self.registration.scope_digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.provider_digest != self.provider.definition().provider_digest {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.api_digest != *self.registration.api_digest() {
            failures.push(VerificationFailure::ApiDigestMismatch);
        }
        if proposal.evidence.permission_digest != self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            CloudinaryEvidenceState::Present => {}
            CloudinaryEvidenceState::Deleted => failures.push(VerificationFailure::Deleted),
            CloudinaryEvidenceState::Invalid => failures.push(VerificationFailure::Invalid),
            CloudinaryEvidenceState::Partial => failures.push(VerificationFailure::PartialEvidence),
            CloudinaryEvidenceState::Denied => failures.push(VerificationFailure::Denied),
            CloudinaryEvidenceState::RateLimited => failures.push(VerificationFailure::RateLimited),
            CloudinaryEvidenceState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            CloudinaryEvidenceState::ProviderUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            CloudinaryEvidenceState::Tampered => {
                failures.push(VerificationFailure::TamperedEvidence);
            }
            CloudinaryEvidenceState::RegistrationRevoked => {
                failures.push(VerificationFailure::RegistrationInactive);
            }
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        let review_eligible = valid
            && proposal.state.is_present()
            && proposal.asset.is_some()
            && proposal.usage.is_some()
            && proposal.transformation.is_some()
            && proposal.delivery.is_some()
            && !proposal.connected
            && !proposal.native
            && !proposal.first_party
            && !proposal.provider_receipt
            && !proposal.signed_url_execution
            && !proposal.delivery_guarantee;
        VerificationReport::new(valid, review_eligible, failures)
    }

    fn validate_request(&self, request: &CloudinaryReadRequest) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(CloudinaryAssetResultError::RegistrationInactive);
        }
        request.validate(self.scope())?;
        if request.expected_provider_digest != self.provider.definition().provider_digest
            || request.expected_registration_digest != *self.registration.registration_digest()
        {
            return Err(CloudinaryAssetResultError::ScopeMismatch);
        }
        Ok(())
    }
}

pub fn state_for_transport(error: &CloudinaryTransportError) -> CloudinaryEvidenceState {
    match error {
        CloudinaryTransportError::BadRequest => CloudinaryEvidenceState::Invalid,
        CloudinaryTransportError::Unauthorized | CloudinaryTransportError::Forbidden => {
            CloudinaryEvidenceState::Denied
        }
        CloudinaryTransportError::NotFound | CloudinaryTransportError::Deleted => {
            CloudinaryEvidenceState::Deleted
        }
        CloudinaryTransportError::RateLimited { .. }
        | CloudinaryTransportError::BackoffExhausted => CloudinaryEvidenceState::RateLimited,
        CloudinaryTransportError::AccessLost => CloudinaryEvidenceState::AccessLoss,
        CloudinaryTransportError::Partial => CloudinaryEvidenceState::Partial,
        CloudinaryTransportError::Tampered => CloudinaryEvidenceState::Tampered,
        CloudinaryTransportError::BlockedEnv
        | CloudinaryTransportError::Conflict
        | CloudinaryTransportError::ServerError { .. }
        | CloudinaryTransportError::Timeout
        | CloudinaryTransportError::ProviderUnknown => CloudinaryEvidenceState::ProviderUnknown,
        CloudinaryTransportError::InvalidResponse => CloudinaryEvidenceState::Invalid,
    }
}

fn proposal_error_to_transport(error: &CloudinaryAssetResultError) -> CloudinaryTransportError {
    match error {
        CloudinaryAssetResultError::TamperedEvidence => CloudinaryTransportError::Tampered,
        CloudinaryAssetResultError::PartialEvidence => CloudinaryTransportError::Partial,
        CloudinaryAssetResultError::ProviderUnknown => CloudinaryTransportError::ProviderUnknown,
        CloudinaryAssetResultError::RevisionDrift | CloudinaryAssetResultError::ScopeMismatch => {
            CloudinaryTransportError::InvalidResponse
        }
        _ => CloudinaryTransportError::InvalidResponse,
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    ApiDigestMismatch,
    PermissionDigestMismatch,
    ScopeDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    AccessLoss,
    Denied,
    Deleted,
    Invalid,
    RateLimited,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn new(valid: bool, review_eligible: bool, failures: Vec<VerificationFailure>) -> Self {
        let verification_digest = Digest::from_parts(
            "cloudinary-verification-report/v1",
            &[
                ("valid", valid.to_string()),
                ("review_eligible", review_eligible.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|failure| format!("{failure:?}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Self {
            valid,
            review_eligible,
            failures,
            verification_digest,
        }
    }
}
