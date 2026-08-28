//! Typed App Store Connect provider for bounded release-result evidence.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize, de::Error as _};

use crate::model::{
    AppPayload, AppStoreConnectResponseBody, AppStoreConnectScope, AppStoreState,
    BetaAppReviewSubmissionPayload, BetaGroupPayload, BetaReviewState, BuildPayload,
    BuildProcessingState, Digest, LinkagePayload, Page, PageToken, PreReleaseVersionPayload,
    ReleaseState, ReviewState, ReviewSubmissionPayload, validate_collection_len,
    validate_payload_identifier, validate_payload_state, validate_relationships,
};
use crate::service::AppStoreConnectRegistration;
use crate::transport::{
    AppStoreConnectEndpoint, AppStoreConnectHttpRequest, AppStoreConnectReceipt,
    AppStoreConnectTransport, AppStoreConnectTransportError, JwtRedaction, TransportProvenance,
};
use crate::{
    API_REVISION, AppStoreConnectReleaseResultError, CONTRACT_VERSION, MAX_PAGES, MAX_RECEIPTS,
    MAX_RELATIONSHIP_DEPTH, MAX_RESPONSE_BYTES, PLUGIN_VERSION, PROVIDER_ID, PROVIDER_REVISION,
    Result, contract_digest, provider_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionStatus {
    Processing,
    Ready,
    InReview,
    BetaPending,
    BetaApproved,
    BetaRejected,
    Released,
    Expired,
    Removed,
    Partial,
    AccessLost,
    ProviderUnknown,
}

impl ProjectionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Processing => "processing",
            Self::Ready => "ready",
            Self::InReview => "in_review",
            Self::BetaPending => "beta_pending",
            Self::BetaApproved => "beta_approved",
            Self::BetaRejected => "beta_rejected",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Removed => "removed",
            Self::Partial => "partial",
            Self::AccessLost => "access_lost",
            Self::ProviderUnknown => "provider_unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionCompleteness {
    Complete,
    Partial,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppStoreConnectReadRequest {
    pub scope: AppStoreConnectScope,
    pub max_pages: usize,
    pub max_response_bytes: usize,
    pub max_relationship_depth: usize,
}

impl AppStoreConnectReadRequest {
    pub fn new(scope: AppStoreConnectScope) -> Result<Self> {
        Self::with_bounds_and_relationship_depth(
            scope,
            MAX_PAGES,
            MAX_RESPONSE_BYTES,
            MAX_RELATIONSHIP_DEPTH,
        )
    }

    pub fn with_bounds(
        scope: AppStoreConnectScope,
        max_pages: usize,
        max_response_bytes: usize,
    ) -> Result<Self> {
        Self::with_bounds_and_relationship_depth(
            scope,
            max_pages,
            max_response_bytes,
            MAX_RELATIONSHIP_DEPTH,
        )
    }

    pub fn with_bounds_and_relationship_depth(
        scope: AppStoreConnectScope,
        max_pages: usize,
        max_response_bytes: usize,
        max_relationship_depth: usize,
    ) -> Result<Self> {
        scope.validate()?;
        if max_pages == 0
            || max_pages > MAX_PAGES
            || max_relationship_depth == 0
            || max_relationship_depth > MAX_RELATIONSHIP_DEPTH
        {
            return Err(AppStoreConnectReleaseResultError::PaginationLimit);
        }
        if max_response_bytes == 0 || max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(AppStoreConnectReleaseResultError::ResponseTooLarge);
        }
        let request = Self {
            scope,
            max_pages,
            max_response_bytes,
            max_relationship_depth,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        if self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_relationship_depth == 0
            || self.max_relationship_depth > MAX_RELATIONSHIP_DEPTH
        {
            return Err(AppStoreConnectReleaseResultError::PaginationLimit);
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(AppStoreConnectReleaseResultError::ResponseTooLarge);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AppStoreConnectReadRequestWire {
    scope: AppStoreConnectScope,
    max_pages: usize,
    max_response_bytes: usize,
    max_relationship_depth: usize,
}

impl<'de> Deserialize<'de> for AppStoreConnectReadRequest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = AppStoreConnectReadRequestWire::deserialize(deserializer)?;
        Self::with_bounds_and_relationship_depth(
            value.scope,
            value.max_pages,
            value.max_response_bytes,
            value.max_relationship_depth,
        )
        .map_err(|error| D::Error::custom(error.to_string()))
    }
}

/// Normalized App Store Connect evidence.  Provider payload values are not
/// retained; each metadata group is represented by a deterministic digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppStoreConnectResultProjection {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_api_revision: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub plugin_version: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub scope: AppStoreConnectScope,
    pub status: ProjectionStatus,
    pub completeness: ProjectionCompleteness,
    pub app_metadata_digest: Digest,
    pub pre_release_metadata_digest: Digest,
    pub build_processing_digest: Digest,
    pub app_store_version_digest: Digest,
    pub beta_group_digest: Digest,
    pub beta_review_digest: Digest,
    pub review_digest: Digest,
    pub release_digest: Digest,
    pub artifact_digest: Digest,
    pub evidence_digest: Digest,
    pub receipts: Vec<AppStoreConnectReceipt>,
    pub provenance: TransportProvenance,
    pub redacted: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub jwt_serialized: bool,
    pub private_key_material: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl AppStoreConnectResultProjection {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration_digest: Digest,
        scope: AppStoreConnectScope,
        status: ProjectionStatus,
        completeness: ProjectionCompleteness,
        app_metadata_digest: Digest,
        pre_release_metadata_digest: Digest,
        build_processing_digest: Digest,
        app_store_version_digest: Digest,
        beta_group_digest: Digest,
        beta_review_digest: Digest,
        review_digest: Digest,
        release_digest: Digest,
        artifact_digest: Digest,
        receipts: Vec<AppStoreConnectReceipt>,
        provenance: TransportProvenance,
    ) -> Self {
        let mut projection = Self {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_api_revision: API_REVISION.to_owned(),
            provider_revision: PROVIDER_REVISION.to_owned(),
            provider_digest: provider_digest(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            registration_digest,
            scope_digest: scope.digest(),
            scope,
            status,
            completeness,
            app_metadata_digest,
            pre_release_metadata_digest,
            build_processing_digest,
            app_store_version_digest,
            beta_group_digest,
            beta_review_digest,
            review_digest,
            release_digest,
            artifact_digest,
            evidence_digest: Digest::from_text("unsealed-appstoreconnect-release-result")
                .expect("digest"),
            receipts,
            provenance,
            redacted: true,
            connected: false,
            native: false,
            provider_receipt: false,
            jwt_serialized: false,
            private_key_material: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        projection.evidence_digest = projection.calculate_digest();
        projection
    }

    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_api_revision != API_REVISION
            || self.provider_revision != PROVIDER_REVISION
            || self.provider_digest != provider_digest()
            || self.plugin_version != PLUGIN_VERSION
            || self.scope_digest != self.scope.digest()
            || !self.redacted
            || self.connected
            || self.native
            || self.provider_receipt
            || self.jwt_serialized
            || self.private_key_material
            || self.outcome_adopted
            || self.work_product_adopted
            || self.receipts.len() > MAX_RECEIPTS
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AppStoreConnectReleaseResultError::TamperedEvidence);
        }
        self.scope.validate()?;
        self.contract_digest.validate()?;
        self.provider_digest.validate()?;
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        for digest in [
            &self.app_metadata_digest,
            &self.pre_release_metadata_digest,
            &self.build_processing_digest,
            &self.app_store_version_digest,
            &self.beta_group_digest,
            &self.beta_review_digest,
            &self.review_digest,
            &self.release_digest,
            &self.artifact_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        for receipt in &self.receipts {
            receipt.validate()?;
            if receipt.provenance != self.provenance {
                return Err(AppStoreConnectReleaseResultError::TamperedEvidence);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "appstoreconnect-release-result/projection/v1",
            [
                ("contract".to_owned(), self.contract_digest.to_string()),
                ("provider".to_owned(), self.provider_id.clone()),
                (
                    "provider_revision".to_owned(),
                    self.provider_revision.clone(),
                ),
                (
                    "provider_digest".to_owned(),
                    self.provider_digest.to_string(),
                ),
                (
                    "registration".to_owned(),
                    self.registration_digest.to_string(),
                ),
                ("scope".to_owned(), self.scope_digest.to_string()),
                ("status".to_owned(), self.status.as_str().to_owned()),
                (
                    "completeness".to_owned(),
                    format!("{:?}", self.completeness),
                ),
                ("app".to_owned(), self.app_metadata_digest.to_string()),
                (
                    "pre_release".to_owned(),
                    self.pre_release_metadata_digest.to_string(),
                ),
                ("build".to_owned(), self.build_processing_digest.to_string()),
                (
                    "app_store_version".to_owned(),
                    self.app_store_version_digest.to_string(),
                ),
                ("beta_group".to_owned(), self.beta_group_digest.to_string()),
                (
                    "beta_review".to_owned(),
                    self.beta_review_digest.to_string(),
                ),
                ("review".to_owned(), self.review_digest.to_string()),
                ("release".to_owned(), self.release_digest.to_string()),
                ("artifact".to_owned(), self.artifact_digest.to_string()),
                (
                    "receipts".to_owned(),
                    crate::digest_serialized(&self.receipts),
                ),
                ("provenance".to_owned(), self.provenance.as_str().to_owned()),
            ],
        )
    }
}

pub type AppStoreConnectReleaseResultProjection = AppStoreConnectResultProjection;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppStoreConnectProviderState {
    Active,
    Revoked,
    Reversed,
    BlockedEnv,
    AccessLost,
    Expired,
    Removed,
}

enum FetchOutcome {
    Body(AppStoreConnectResponseBody),
    Status(ProjectionStatus),
}

enum CollectionOutcome<T> {
    Values(Vec<T>),
    Status(ProjectionStatus),
}

struct LinkageOutcome {
    target_id: Option<String>,
    revision: u64,
}

/// Typed provider bound to one exact registration. It never resolves the
/// opaque SecretReference and never emits a live/native transport.
#[derive(Clone, Debug)]
pub struct AppStoreConnectProvider<T>
where
    T: AppStoreConnectTransport,
{
    registration: AppStoreConnectRegistration,
    transport: T,
    state: AppStoreConnectProviderState,
}

impl<T> AppStoreConnectProvider<T>
where
    T: AppStoreConnectTransport,
{
    pub fn new(registration: AppStoreConnectRegistration, transport: T) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(match registration.status {
                crate::AppStoreConnectRegistrationStatus::Revoked => {
                    AppStoreConnectReleaseResultError::RegistrationRevoked
                }
                crate::AppStoreConnectRegistrationStatus::Reversed => {
                    AppStoreConnectReleaseResultError::RegistrationReversed
                }
                crate::AppStoreConnectRegistrationStatus::Active => {
                    AppStoreConnectReleaseResultError::InvalidRegistration
                }
            });
        }
        let state = if transport.provenance().is_blocked() {
            AppStoreConnectProviderState::BlockedEnv
        } else {
            AppStoreConnectProviderState::Active
        };
        Ok(Self {
            registration,
            transport,
            state,
        })
    }

    pub fn registration(&self) -> &AppStoreConnectRegistration {
        &self.registration
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub const fn state(&self) -> AppStoreConnectProviderState {
        self.state
    }

    pub fn revoke(&mut self) -> Result<()> {
        self.registration.revoke()?;
        self.state = AppStoreConnectProviderState::Revoked;
        Ok(())
    }

    pub fn reverse(&mut self) -> Result<()> {
        self.registration.reverse()?;
        self.state = AppStoreConnectProviderState::Reversed;
        Ok(())
    }

    pub fn read_result(&mut self) -> Result<AppStoreConnectResultProjection> {
        let request = AppStoreConnectReadRequest::new(self.registration.scope.clone())?;
        self.read_release_result(&request)
    }

    pub fn read_release_result(
        &mut self,
        request: &AppStoreConnectReadRequest,
    ) -> Result<AppStoreConnectResultProjection> {
        request.validate()?;
        if request.scope != self.registration.scope {
            return Err(AppStoreConnectReleaseResultError::ScopeMismatch);
        }
        self.registration.validate()?;
        match self.state {
            AppStoreConnectProviderState::Revoked => {
                return Err(AppStoreConnectReleaseResultError::RegistrationRevoked);
            }
            AppStoreConnectProviderState::Reversed => {
                return Err(AppStoreConnectReleaseResultError::RegistrationReversed);
            }
            AppStoreConnectProviderState::BlockedEnv => {
                return Ok(self.fallback(ProjectionStatus::ProviderUnknown, Vec::new()));
            }
            AppStoreConnectProviderState::AccessLost => {
                return Ok(self.fallback(ProjectionStatus::AccessLost, Vec::new()));
            }
            AppStoreConnectProviderState::Expired => {
                return Ok(self.fallback(ProjectionStatus::Expired, Vec::new()));
            }
            AppStoreConnectProviderState::Removed => {
                return Ok(self.fallback(ProjectionStatus::Removed, Vec::new()));
            }
            AppStoreConnectProviderState::Active => {}
        }

        let mut receipts = Vec::with_capacity(MAX_RECEIPTS);
        let scope = &request.scope;
        let origin = scope.api_origin.origin.clone();

        let apps = match self.collect_pages(
            AppStoreConnectEndpoint::Apps {
                origin: origin.clone(),
                bundle_id: scope.app.bundle_id.as_str().to_owned(),
            },
            request,
            &mut receipts,
            |body| match body {
                AppStoreConnectResponseBody::Apps(page) => Some(page),
                _ => None,
            },
        )? {
            CollectionOutcome::Values(values) => values,
            CollectionOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        let Some(app) = apps.iter().find(|value| value.id == scope.app.id.as_str()) else {
            self.state = AppStoreConnectProviderState::Removed;
            return Ok(self.fallback(ProjectionStatus::Removed, receipts));
        };
        validate_app(app)?;
        if app.team_id != scope.team.id.as_str() || app.bundle_id != scope.app.bundle_id.as_str() {
            return Err(AppStoreConnectReleaseResultError::OutOfScope);
        }
        if app.revision != scope.app.revision {
            return Err(AppStoreConnectReleaseResultError::RevisionMismatch);
        }
        if app.removed {
            self.state = AppStoreConnectProviderState::Removed;
            return Ok(self.fallback(ProjectionStatus::Removed, receipts));
        }
        let app_digest = Digest::from_parts(
            "appstoreconnect-release-result/app/v1",
            [
                ("id".to_owned(), app.id.clone()),
                ("team".to_owned(), app.team_id.clone()),
                ("bundle".to_owned(), app.bundle_id.clone()),
                ("revision".to_owned(), app.revision.to_string()),
            ],
        );

        let app_response = self.fetch_one(
            AppStoreConnectEndpoint::App {
                origin: origin.clone(),
                app_id: scope.app.id.as_str().to_owned(),
            },
            request,
            &mut receipts,
        )?;
        let app_from_read = match app_response {
            FetchOutcome::Body(AppStoreConnectResponseBody::App(value)) => value,
            FetchOutcome::Body(_) => {
                return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
            }
            FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        validate_app(&app_from_read)?;
        if app_from_read != *app {
            if app_from_read.revision != app.revision {
                return Err(AppStoreConnectReleaseResultError::RevisionMismatch);
            }
            return Err(AppStoreConnectReleaseResultError::TamperedEvidence);
        }

        let pre_release_response = self.fetch_one(
            AppStoreConnectEndpoint::PreReleaseVersion {
                origin: origin.clone(),
                pre_release_version_id: scope.pre_release_version.id.as_str().to_owned(),
            },
            request,
            &mut receipts,
        )?;
        let pre_release = match pre_release_response {
            FetchOutcome::Body(AppStoreConnectResponseBody::PreReleaseVersion(value)) => value,
            FetchOutcome::Body(_) => {
                return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
            }
            FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        validate_pre_release(&pre_release)?;
        if pre_release.id != scope.pre_release_version.id.as_str()
            || pre_release.app_id != scope.app.id.as_str()
            || pre_release.version != scope.app_store_version.version.as_str()
            || pre_release.platform != scope.platform
        {
            return Err(AppStoreConnectReleaseResultError::OutOfScope);
        }
        if pre_release.revision != scope.pre_release_version.revision {
            return Err(AppStoreConnectReleaseResultError::RevisionMismatch);
        }
        if pre_release.removed {
            self.state = AppStoreConnectProviderState::Removed;
            return Ok(self.fallback(ProjectionStatus::Removed, receipts));
        }
        if pre_release.expired {
            self.state = AppStoreConnectProviderState::Expired;
            return Ok(self.fallback(ProjectionStatus::Expired, receipts));
        }
        let pre_release_digest = Digest::from_parts(
            "appstoreconnect-release-result/pre-release-version/v1",
            [
                ("id".to_owned(), pre_release.id.clone()),
                ("app".to_owned(), pre_release.app_id.clone()),
                ("version".to_owned(), pre_release.version.clone()),
                (
                    "platform".to_owned(),
                    pre_release.platform.as_str().to_owned(),
                ),
                ("revision".to_owned(), pre_release.revision.to_string()),
            ],
        );

        let pre_release_builds = match self.collect_pages(
            AppStoreConnectEndpoint::PreReleaseVersionBuilds {
                origin: origin.clone(),
                pre_release_version_id: scope.pre_release_version.id.as_str().to_owned(),
            },
            request,
            &mut receipts,
            |body| match body {
                AppStoreConnectResponseBody::Builds(page) => Some(page),
                _ => None,
            },
        )? {
            CollectionOutcome::Values(values) => values,
            CollectionOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        if !pre_release_builds
            .iter()
            .any(|value| value.id == scope.build.id.as_str())
        {
            return Err(AppStoreConnectReleaseResultError::OutOfScope);
        }

        let build_response = self.fetch_one(
            AppStoreConnectEndpoint::Build {
                origin: origin.clone(),
                build_id: scope.build.id.as_str().to_owned(),
            },
            request,
            &mut receipts,
        )?;
        let build = match build_response {
            FetchOutcome::Body(AppStoreConnectResponseBody::Build(value)) => value,
            FetchOutcome::Body(_) => {
                return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
            }
            FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        validate_build(&build)?;
        if build.id != scope.build.id.as_str()
            || build.app_id != scope.app.id.as_str()
            || build.pre_release_version_id != scope.pre_release_version.id.as_str()
            || build.version != scope.build.version.as_str()
            || build.build_number != scope.build.build_number.as_str()
        {
            return Err(AppStoreConnectReleaseResultError::OutOfScope);
        }
        if build.revision != scope.build.revision {
            return Err(AppStoreConnectReleaseResultError::RevisionMismatch);
        }
        if build.artifact_digest != scope.artifact.digest {
            return Err(AppStoreConnectReleaseResultError::ArtifactMismatch);
        }
        if build.removed {
            self.state = AppStoreConnectProviderState::Removed;
            return Ok(self.fallback(ProjectionStatus::Removed, receipts));
        }
        if build.expired {
            self.state = AppStoreConnectProviderState::Expired;
            return Ok(self.fallback(ProjectionStatus::Expired, receipts));
        }
        let build_digest = Digest::from_parts(
            "appstoreconnect-release-result/build-processing/v1",
            [
                ("id".to_owned(), build.id.clone()),
                ("app".to_owned(), build.app_id.clone()),
                (
                    "pre_release".to_owned(),
                    build.pre_release_version_id.clone(),
                ),
                ("version".to_owned(), build.version.clone()),
                ("build_number".to_owned(), build.build_number.clone()),
                (
                    "processing_state".to_owned(),
                    build.processing_state.as_str().to_owned(),
                ),
                (
                    "beta_review_state".to_owned(),
                    build.beta_review_state.as_str().to_owned(),
                ),
                ("artifact".to_owned(), build.artifact_digest.to_string()),
                ("revision".to_owned(), build.revision.to_string()),
            ],
        );

        let mut relationship_keys = BTreeSet::new();
        let build_pre_release = self.read_linkage(
            AppStoreConnectEndpoint::BuildPreReleaseVersion {
                origin: origin.clone(),
                build_id: scope.build.id.as_str().to_owned(),
            },
            request,
            &mut receipts,
            &mut relationship_keys,
        )?;
        if build_pre_release.target_id.as_deref() != Some(scope.pre_release_version.id.as_str()) {
            return Err(AppStoreConnectReleaseResultError::OutOfScope);
        }
        if build_pre_release.revision != scope.pre_release_version.revision {
            return Err(AppStoreConnectReleaseResultError::RevisionMismatch);
        }

        let build_version_link = self.read_linkage(
            AppStoreConnectEndpoint::BuildAppStoreVersion {
                origin: origin.clone(),
                build_id: scope.build.id.as_str().to_owned(),
            },
            request,
            &mut receipts,
            &mut relationship_keys,
        )?;
        if build_version_link.target_id.as_deref() != Some(scope.app_store_version.id.as_str()) {
            return Err(AppStoreConnectReleaseResultError::OutOfScope);
        }
        if build_version_link.revision != scope.app_store_version.revision {
            return Err(AppStoreConnectReleaseResultError::RevisionMismatch);
        }

        let versions = match self.collect_pages(
            AppStoreConnectEndpoint::AppStoreVersions {
                origin: origin.clone(),
                app_id: scope.app.id.as_str().to_owned(),
            },
            request,
            &mut receipts,
            |body| match body {
                AppStoreConnectResponseBody::AppStoreVersions(page) => Some(page),
                _ => None,
            },
        )? {
            CollectionOutcome::Values(values) => values,
            CollectionOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        let Some(version_from_list) = versions
            .iter()
            .find(|value| value.id == scope.app_store_version.id.as_str())
        else {
            self.state = AppStoreConnectProviderState::Removed;
            return Ok(self.fallback(ProjectionStatus::Removed, receipts));
        };
        validate_app_store_version(version_from_list)?;
        validate_version_scope(version_from_list, scope)?;

        let version_response = self.fetch_one(
            AppStoreConnectEndpoint::AppStoreVersion {
                origin: origin.clone(),
                app_store_version_id: scope.app_store_version.id.as_str().to_owned(),
            },
            request,
            &mut receipts,
        )?;
        let version = match version_response {
            FetchOutcome::Body(AppStoreConnectResponseBody::AppStoreVersion(value)) => value,
            FetchOutcome::Body(_) => {
                return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
            }
            FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        validate_app_store_version(&version)?;
        validate_version_scope(&version, scope)?;
        if version != *version_from_list {
            return Err(AppStoreConnectReleaseResultError::TamperedEvidence);
        }
        if version.removed {
            self.state = AppStoreConnectProviderState::Removed;
            return Ok(self.fallback(ProjectionStatus::Removed, receipts));
        }
        if version.expired {
            self.state = AppStoreConnectProviderState::Expired;
            return Ok(self.fallback(ProjectionStatus::Expired, receipts));
        }
        let version_digest = Digest::from_parts(
            "appstoreconnect-release-result/app-store-version/v1",
            [
                ("id".to_owned(), version.id.clone()),
                ("app".to_owned(), version.app_id.clone()),
                (
                    "pre_release".to_owned(),
                    version.pre_release_version_id.clone(),
                ),
                ("version".to_owned(), version.version.clone()),
                ("platform".to_owned(), version.platform.as_str().to_owned()),
                (
                    "app_store_state".to_owned(),
                    version.app_store_state.as_str().to_owned(),
                ),
                (
                    "review_state".to_owned(),
                    version.review_state.as_str().to_owned(),
                ),
                (
                    "release_state".to_owned(),
                    version.release_state.as_str().to_owned(),
                ),
                ("release_id".to_owned(), version.release_id.clone()),
                (
                    "build".to_owned(),
                    version.build_id.clone().unwrap_or_default(),
                ),
                ("revision".to_owned(), version.revision.to_string()),
            ],
        );

        let version_build_response = self.fetch_one(
            AppStoreConnectEndpoint::AppStoreVersionBuild {
                origin: origin.clone(),
                app_store_version_id: scope.app_store_version.id.as_str().to_owned(),
            },
            request,
            &mut receipts,
        )?;
        let version_build = match version_build_response {
            FetchOutcome::Body(AppStoreConnectResponseBody::Build(value)) => value,
            FetchOutcome::Body(_) => {
                return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
            }
            FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
        };
        validate_build(&version_build)?;
        if version_build.id != scope.build.id.as_str()
            || version_build.artifact_digest != scope.artifact.digest
        {
            return Err(AppStoreConnectReleaseResultError::ArtifactMismatch);
        }
        let version_build_link = self.read_linkage(
            AppStoreConnectEndpoint::AppStoreVersionBuildRelationship {
                origin: origin.clone(),
                app_store_version_id: scope.app_store_version.id.as_str().to_owned(),
            },
            request,
            &mut receipts,
            &mut relationship_keys,
        )?;
        if version_build_link.target_id.as_deref() != Some(scope.build.id.as_str()) {
            return Err(AppStoreConnectReleaseResultError::OutOfScope);
        }

        let mut beta_group_digest = unavailable_digest("beta-group-not-scoped");
        let mut beta_review_digest = Digest::from_parts(
            "appstoreconnect-release-result/beta-review/v1",
            [
                ("build".to_owned(), build.id.clone()),
                (
                    "state".to_owned(),
                    build.beta_review_state.as_str().to_owned(),
                ),
            ],
        );
        let mut completeness = ProjectionCompleteness::Complete;
        let mut beta_status = None;
        if let Some(beta_group_id) = scope.beta_group.id.as_ref() {
            let groups = match self.collect_pages(
                AppStoreConnectEndpoint::BetaGroups {
                    origin: origin.clone(),
                    app_id: scope.app.id.as_str().to_owned(),
                },
                request,
                &mut receipts,
                |body| match body {
                    AppStoreConnectResponseBody::BetaGroups(page) => Some(page),
                    _ => None,
                },
            )? {
                CollectionOutcome::Values(values) => values,
                CollectionOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
            };
            let Some(beta_group) = groups
                .iter()
                .find(|value| value.id == beta_group_id.as_str())
            else {
                self.state = AppStoreConnectProviderState::Removed;
                return Ok(self.fallback(ProjectionStatus::Removed, receipts));
            };
            validate_beta_group(beta_group)?;
            if beta_group.app_id != scope.app.id.as_str() {
                return Err(AppStoreConnectReleaseResultError::OutOfScope);
            }
            if beta_group.revision != scope.beta_group.revision {
                return Err(AppStoreConnectReleaseResultError::RevisionMismatch);
            }
            if beta_group.removed {
                self.state = AppStoreConnectProviderState::Removed;
                return Ok(self.fallback(ProjectionStatus::Removed, receipts));
            }
            let beta_group_response = self.fetch_one(
                AppStoreConnectEndpoint::BetaGroup {
                    origin: origin.clone(),
                    beta_group_id: beta_group_id.as_str().to_owned(),
                },
                request,
                &mut receipts,
            )?;
            let beta_group_read = match beta_group_response {
                FetchOutcome::Body(AppStoreConnectResponseBody::BetaGroup(value)) => value,
                FetchOutcome::Body(_) => {
                    return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
                }
                FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
            };
            validate_beta_group(&beta_group_read)?;
            if beta_group_read != *beta_group {
                return Err(AppStoreConnectReleaseResultError::TamperedEvidence);
            }
            let group_builds = match self.collect_pages(
                AppStoreConnectEndpoint::BetaGroupBuilds {
                    origin: origin.clone(),
                    beta_group_id: beta_group_id.as_str().to_owned(),
                },
                request,
                &mut receipts,
                |body| match body {
                    AppStoreConnectResponseBody::Builds(page) => Some(page),
                    _ => None,
                },
            )? {
                CollectionOutcome::Values(values) => values,
                CollectionOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
            };
            if !group_builds.iter().any(|value| value.id == build.id) {
                completeness = ProjectionCompleteness::Partial;
            }
            beta_group_digest = Digest::from_parts(
                "appstoreconnect-release-result/beta-group/v1",
                [
                    ("id".to_owned(), beta_group_read.id.clone()),
                    ("app".to_owned(), beta_group_read.app_id.clone()),
                    (
                        "builds".to_owned(),
                        crate::digest_serialized(&beta_group_read.build_ids),
                    ),
                    ("revision".to_owned(), beta_group_read.revision.to_string()),
                ],
            );
            beta_status = Some(build.beta_review_state);

            let beta_review_response = self.fetch_one(
                AppStoreConnectEndpoint::BuildBetaAppReviewSubmission {
                    origin: origin.clone(),
                    build_id: build.id.clone(),
                },
                request,
                &mut receipts,
            )?;
            match beta_review_response {
                FetchOutcome::Body(AppStoreConnectResponseBody::BetaReviewSubmission(value)) => {
                    validate_beta_review(&value)?;
                    if value.build_id != build.id || value.app_id != scope.app.id.as_str() {
                        return Err(AppStoreConnectReleaseResultError::OutOfScope);
                    }
                    if value.removed {
                        self.state = AppStoreConnectProviderState::Removed;
                        return Ok(self.fallback(ProjectionStatus::Removed, receipts));
                    }
                    if value.expired {
                        self.state = AppStoreConnectProviderState::Expired;
                        return Ok(self.fallback(ProjectionStatus::Expired, receipts));
                    }
                    beta_review_digest = Digest::from_parts(
                        "appstoreconnect-release-result/beta-review/v1",
                        [
                            ("id".to_owned(), value.id),
                            ("build".to_owned(), value.build_id),
                            ("app".to_owned(), value.app_id),
                            ("state".to_owned(), value.state.as_str().to_owned()),
                            ("revision".to_owned(), value.revision.to_string()),
                        ],
                    );
                    beta_status = Some(value.state);
                }
                FetchOutcome::Status(ProjectionStatus::Removed) => {
                    completeness = ProjectionCompleteness::Partial;
                }
                FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
                FetchOutcome::Body(_) => {
                    return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
                }
            }
        }

        let mut review_digest = unavailable_digest("review-not-scoped");
        let mut review_status = None;
        if let Some(review_id) = scope.review.id.as_ref() {
            let reviews = match self.collect_pages(
                AppStoreConnectEndpoint::ReviewSubmissions {
                    origin: origin.clone(),
                    app_id: scope.app.id.as_str().to_owned(),
                },
                request,
                &mut receipts,
                |body| match body {
                    AppStoreConnectResponseBody::ReviewSubmissions(page) => Some(page),
                    _ => None,
                },
            )? {
                CollectionOutcome::Values(values) => values,
                CollectionOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
            };
            let Some(review) = reviews.iter().find(|value| value.id == review_id.as_str()) else {
                self.state = AppStoreConnectProviderState::Removed;
                return Ok(self.fallback(ProjectionStatus::Removed, receipts));
            };
            validate_review(review)?;
            validate_review_scope(review, scope)?;
            if review.revision != scope.review.revision {
                return Err(AppStoreConnectReleaseResultError::RevisionMismatch);
            }
            let review_response = self.fetch_one(
                AppStoreConnectEndpoint::ReviewSubmission {
                    origin: origin.clone(),
                    review_submission_id: review_id.as_str().to_owned(),
                },
                request,
                &mut receipts,
            )?;
            let review_read = match review_response {
                FetchOutcome::Body(AppStoreConnectResponseBody::ReviewSubmission(value)) => value,
                FetchOutcome::Body(_) => {
                    return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
                }
                FetchOutcome::Status(status) => return Ok(self.fallback(status, receipts)),
            };
            validate_review(&review_read)?;
            validate_review_scope(&review_read, scope)?;
            if review_read != *review {
                return Err(AppStoreConnectReleaseResultError::TamperedEvidence);
            }
            if review_read.removed {
                self.state = AppStoreConnectProviderState::Removed;
                return Ok(self.fallback(ProjectionStatus::Removed, receipts));
            }
            if review_read.expired {
                self.state = AppStoreConnectProviderState::Expired;
                return Ok(self.fallback(ProjectionStatus::Expired, receipts));
            }
            review_status = Some(review_read.state);
            review_digest = Digest::from_parts(
                "appstoreconnect-release-result/review/v1",
                [
                    ("id".to_owned(), review_read.id.clone()),
                    ("app".to_owned(), review_read.app_id.clone()),
                    (
                        "version".to_owned(),
                        review_read.app_store_version_id.clone().unwrap_or_default(),
                    ),
                    (
                        "platform".to_owned(),
                        review_read.platform.as_str().to_owned(),
                    ),
                    ("state".to_owned(), review_read.state.as_str().to_owned()),
                    ("revision".to_owned(), review_read.revision.to_string()),
                ],
            );
        }

        let release_digest = Digest::from_parts(
            "appstoreconnect-release-result/release/v1",
            [
                ("id".to_owned(), scope.release.id.as_str().to_owned()),
                ("version".to_owned(), version.id.clone()),
                (
                    "state".to_owned(),
                    version.release_state.as_str().to_owned(),
                ),
                ("revision".to_owned(), scope.release.revision.to_string()),
            ],
        );
        if scope.release.revision != version.revision {
            return Err(AppStoreConnectReleaseResultError::RevisionMismatch);
        }

        let status = project_status(&build, &version, beta_status, review_status, completeness);
        if matches!(status, ProjectionStatus::Partial) {
            completeness = ProjectionCompleteness::Partial;
        }
        let projection = AppStoreConnectResultProjection::new(
            self.registration.registration_digest.clone(),
            scope.clone(),
            status,
            completeness,
            app_digest,
            pre_release_digest,
            build_digest,
            version_digest,
            beta_group_digest,
            beta_review_digest,
            review_digest,
            release_digest,
            scope.artifact.digest.clone(),
            receipts,
            self.transport.provenance(),
        );
        projection.validate_integrity()?;
        Ok(projection)
    }

    fn fetch_one(
        &mut self,
        endpoint: AppStoreConnectEndpoint,
        request: &AppStoreConnectReadRequest,
        receipts: &mut Vec<AppStoreConnectReceipt>,
    ) -> Result<FetchOutcome> {
        self.fetch(endpoint, request, 0, None, receipts)
    }

    fn fetch(
        &mut self,
        endpoint: AppStoreConnectEndpoint,
        request: &AppStoreConnectReadRequest,
        page_index: usize,
        page_token: Option<PageToken>,
        receipts: &mut Vec<AppStoreConnectReceipt>,
    ) -> Result<FetchOutcome> {
        let authorization = JwtRedaction::for_secret_reference(&self.registration.secret_reference);
        let mut http_request =
            AppStoreConnectHttpRequest::new(endpoint, request.max_response_bytes, authorization)?;
        if page_index > 0 {
            http_request = http_request.with_page(page_index, page_token)?;
        }
        http_request.validate()?;
        let response = match self.transport.get(&http_request) {
            Ok(response) => response,
            Err(error) => {
                let status = match error {
                    AppStoreConnectTransportError::BlockedEnv => {
                        self.state = AppStoreConnectProviderState::BlockedEnv;
                        ProjectionStatus::ProviderUnknown
                    }
                    AppStoreConnectTransportError::AccessLost => {
                        self.state = AppStoreConnectProviderState::AccessLost;
                        ProjectionStatus::AccessLost
                    }
                    AppStoreConnectTransportError::ResponseTooLarge => {
                        return Err(AppStoreConnectReleaseResultError::ResponseTooLarge);
                    }
                    AppStoreConnectTransportError::InvalidEndpoint
                    | AppStoreConnectTransportError::MalformedResponse
                    | AppStoreConnectTransportError::PaginationLimit
                    | AppStoreConnectTransportError::InvalidAuthorization
                    | AppStoreConnectTransportError::InvalidRequest => {
                        return Err(AppStoreConnectReleaseResultError::Transport(error));
                    }
                    AppStoreConnectTransportError::FixtureMissing
                    | AppStoreConnectTransportError::Timeout
                    | AppStoreConnectTransportError::ServerStatus { .. } => {
                        ProjectionStatus::ProviderUnknown
                    }
                };
                return Ok(FetchOutcome::Status(status));
            }
        };
        response.validate_against(&http_request)?;
        response.receipt.validate()?;
        if response.receipt.provenance != self.transport.provenance()
            || response.receipt.method != "GET"
            || response.receipt.request_digest != http_request.request_digest
        {
            return Err(AppStoreConnectReleaseResultError::TamperedEvidence);
        }
        if receipts.len() >= MAX_RECEIPTS {
            return Err(AppStoreConnectReleaseResultError::PaginationLimit);
        }
        receipts.push(response.receipt.clone());
        if !(200..300).contains(&response.status) {
            return Ok(FetchOutcome::Status(match response.status {
                401 | 403 => {
                    self.state = AppStoreConnectProviderState::AccessLost;
                    ProjectionStatus::AccessLost
                }
                404 => {
                    self.state = AppStoreConnectProviderState::Removed;
                    ProjectionStatus::Removed
                }
                409 | 422 => ProjectionStatus::Partial,
                429 | 500..=599 => ProjectionStatus::ProviderUnknown,
                _ => ProjectionStatus::ProviderUnknown,
            }));
        }
        let Some(body) = response.body else {
            return Ok(FetchOutcome::Status(ProjectionStatus::ProviderUnknown));
        };
        Ok(FetchOutcome::Body(body))
    }

    fn collect_pages<U, F>(
        &mut self,
        endpoint: AppStoreConnectEndpoint,
        request: &AppStoreConnectReadRequest,
        receipts: &mut Vec<AppStoreConnectReceipt>,
        extract: F,
    ) -> Result<CollectionOutcome<U>>
    where
        U: Clone,
        F: Fn(&AppStoreConnectResponseBody) -> Option<&Page<U>>,
    {
        let mut page_index = 0;
        let mut token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut values = Vec::new();
        loop {
            let response = self.fetch(
                endpoint.clone(),
                request,
                page_index,
                token.clone(),
                receipts,
            )?;
            let (items, next) = match response {
                FetchOutcome::Body(body) => {
                    let page = extract(&body)
                        .ok_or(AppStoreConnectReleaseResultError::MalformedProviderData)?;
                    validate_collection_len(&page.items)?;
                    (page.items.clone(), page.next.clone())
                }
                FetchOutcome::Status(status) => return Ok(CollectionOutcome::Status(status)),
            };
            values.extend(items);
            let Some(next) = next else {
                return Ok(CollectionOutcome::Values(values));
            };
            if !seen_tokens.insert(next.digest().clone()) {
                return Err(AppStoreConnectReleaseResultError::RelationshipLoop);
            }
            if page_index + 1 >= request.max_pages {
                return Err(AppStoreConnectReleaseResultError::PaginationLimit);
            }
            page_index += 1;
            token = Some(next);
        }
    }

    fn read_linkage(
        &mut self,
        endpoint: AppStoreConnectEndpoint,
        request: &AppStoreConnectReadRequest,
        receipts: &mut Vec<AppStoreConnectReceipt>,
        visited: &mut BTreeSet<String>,
    ) -> Result<LinkageOutcome> {
        let mut page_index = 0;
        let mut token = None;
        let mut seen_tokens = BTreeSet::new();
        loop {
            if page_index >= request.max_relationship_depth {
                return Err(AppStoreConnectReleaseResultError::RelationshipLoop);
            }
            let response = self.fetch(
                endpoint.clone(),
                request,
                page_index,
                token.clone(),
                receipts,
            )?;
            match response {
                FetchOutcome::Body(AppStoreConnectResponseBody::Linkage(value)) => {
                    validate_linkage(&value)?;
                    let key = format!(
                        "{}\0{}\0{}\0{}",
                        value.source_type,
                        value.source_id,
                        value.relationship,
                        value.target_id.clone().unwrap_or_default()
                    );
                    if !visited.insert(key) {
                        return Err(AppStoreConnectReleaseResultError::RelationshipLoop);
                    }
                    return Ok(LinkageOutcome {
                        target_id: value.target_id,
                        revision: value.revision,
                    });
                }
                FetchOutcome::Body(AppStoreConnectResponseBody::Relationships(value)) => {
                    validate_relationships(&value)?;
                    let source_key = format!(
                        "{}\0{}\0{}",
                        value.source_type, value.source_id, value.relationship
                    );
                    if !visited.insert(source_key) {
                        return Err(AppStoreConnectReleaseResultError::RelationshipLoop);
                    }
                    for link in &value.links {
                        if link.resource_id == value.source_id {
                            return Err(AppStoreConnectReleaseResultError::RelationshipLoop);
                        }
                    }
                    let Some(next) = value.next.clone() else {
                        let target = value.links.first().map(|link| link.resource_id.clone());
                        return Ok(LinkageOutcome {
                            target_id: target,
                            revision: request.scope.app_store_version.revision,
                        });
                    };
                    if !seen_tokens.insert(next.digest().clone()) {
                        return Err(AppStoreConnectReleaseResultError::RelationshipLoop);
                    }
                    if page_index + 1 >= request.max_pages {
                        return Err(AppStoreConnectReleaseResultError::PaginationLimit);
                    }
                    page_index += 1;
                    token = Some(next);
                }
                FetchOutcome::Body(_) => {
                    return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
                }
                FetchOutcome::Status(status) => {
                    return match status {
                        ProjectionStatus::Removed => Ok(LinkageOutcome {
                            target_id: None,
                            revision: 0,
                        }),
                        _ => Err(AppStoreConnectReleaseResultError::ProviderUnknown),
                    };
                }
            }
        }
    }

    fn fallback(
        &self,
        status: ProjectionStatus,
        receipts: Vec<AppStoreConnectReceipt>,
    ) -> AppStoreConnectResultProjection {
        let unavailable = |label: &str| unavailable_digest(label);
        AppStoreConnectResultProjection::new(
            self.registration.registration_digest.clone(),
            self.registration.scope.clone(),
            status,
            ProjectionCompleteness::Partial,
            unavailable("app-unavailable"),
            unavailable("pre-release-unavailable"),
            unavailable("build-unavailable"),
            unavailable("app-store-version-unavailable"),
            unavailable("beta-group-unavailable"),
            unavailable("beta-review-unavailable"),
            unavailable("review-unavailable"),
            unavailable("release-unavailable"),
            self.registration.scope.artifact.digest.clone(),
            receipts,
            self.transport.provenance(),
        )
    }
}

fn unavailable_digest(label: &str) -> Digest {
    Digest::from_text(label).expect("digest")
}

fn validate_app(value: &AppPayload) -> Result<()> {
    validate_payload_identifier(&value.id, "app id")?;
    validate_payload_identifier(&value.team_id, "team id")?;
    validate_payload_identifier(&value.bundle_id, "bundle id")?;
    if value.revision == 0 {
        return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn validate_pre_release(value: &PreReleaseVersionPayload) -> Result<()> {
    validate_payload_identifier(&value.id, "pre-release version id")?;
    validate_payload_identifier(&value.app_id, "pre-release app id")?;
    validate_payload_identifier(&value.version, "pre-release version")?;
    if value.revision == 0 {
        return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn validate_build(value: &BuildPayload) -> Result<()> {
    validate_payload_identifier(&value.id, "build id")?;
    validate_payload_identifier(&value.app_id, "build app id")?;
    validate_payload_identifier(&value.pre_release_version_id, "build pre-release id")?;
    validate_payload_identifier(&value.version, "build version")?;
    validate_payload_identifier(&value.build_number, "build number")?;
    value.artifact_digest.validate()?;
    validate_payload_state(value.processing_state.as_str())?;
    validate_payload_state(value.beta_review_state.as_str())?;
    if let Some(version_id) = &value.app_store_version_id {
        validate_payload_identifier(version_id, "build app-store-version id")?;
    }
    if value.revision == 0 {
        return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn validate_app_store_version(value: &crate::model::AppStoreVersionPayload) -> Result<()> {
    validate_payload_identifier(&value.id, "app-store-version id")?;
    validate_payload_identifier(&value.app_id, "app-store-version app id")?;
    validate_payload_identifier(
        &value.pre_release_version_id,
        "app-store-version pre-release id",
    )?;
    validate_payload_identifier(&value.version, "app-store-version version")?;
    validate_payload_identifier(&value.release_id, "release id")?;
    validate_payload_state(value.app_store_state.as_str())?;
    validate_payload_state(value.review_state.as_str())?;
    validate_payload_state(value.release_state.as_str())?;
    if let Some(build_id) = &value.build_id {
        validate_payload_identifier(build_id, "app-store-version build id")?;
    }
    if value.revision == 0 {
        return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn validate_beta_group(value: &BetaGroupPayload) -> Result<()> {
    value.validate()
}

fn validate_beta_review(value: &BetaAppReviewSubmissionPayload) -> Result<()> {
    validate_payload_identifier(&value.id, "beta review id")?;
    validate_payload_identifier(&value.build_id, "beta review build id")?;
    validate_payload_identifier(&value.app_id, "beta review app id")?;
    validate_payload_state(value.state.as_str())?;
    if value.revision == 0 {
        return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn validate_review(value: &ReviewSubmissionPayload) -> Result<()> {
    validate_payload_identifier(&value.id, "review submission id")?;
    validate_payload_identifier(&value.app_id, "review submission app id")?;
    validate_payload_state(value.state.as_str())?;
    if let Some(version_id) = &value.app_store_version_id {
        validate_payload_identifier(version_id, "review app-store-version id")?;
    }
    if value.revision == 0 {
        return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn validate_linkage(value: &LinkagePayload) -> Result<()> {
    validate_payload_identifier(&value.source_type, "linkage source type")?;
    validate_payload_identifier(&value.source_id, "linkage source id")?;
    validate_payload_identifier(&value.relationship, "linkage relationship")?;
    validate_payload_identifier(&value.target_type, "linkage target type")?;
    if let Some(target_id) = &value.target_id {
        validate_payload_identifier(target_id, "linkage target id")?;
    }
    if value.revision == 0 {
        return Err(AppStoreConnectReleaseResultError::MalformedProviderData);
    }
    Ok(())
}

fn validate_version_scope(
    value: &crate::model::AppStoreVersionPayload,
    scope: &AppStoreConnectScope,
) -> Result<()> {
    if value.id != scope.app_store_version.id.as_str()
        || value.app_id != scope.app.id.as_str()
        || value.pre_release_version_id != scope.pre_release_version.id.as_str()
        || value.version != scope.app_store_version.version.as_str()
        || value.platform != scope.platform
        || value.release_id != scope.release.id.as_str()
    {
        return Err(AppStoreConnectReleaseResultError::OutOfScope);
    }
    if value.revision != scope.app_store_version.revision {
        return Err(AppStoreConnectReleaseResultError::RevisionMismatch);
    }
    if value.build_id.as_deref() != Some(scope.build.id.as_str()) {
        return Err(AppStoreConnectReleaseResultError::ArtifactMismatch);
    }
    Ok(())
}

fn validate_review_scope(
    value: &ReviewSubmissionPayload,
    scope: &AppStoreConnectScope,
) -> Result<()> {
    if value.app_id != scope.app.id.as_str()
        || value.platform != scope.platform
        || value.app_store_version_id.as_deref() != Some(scope.app_store_version.id.as_str())
    {
        return Err(AppStoreConnectReleaseResultError::OutOfScope);
    }
    Ok(())
}

fn project_status(
    build: &BuildPayload,
    version: &crate::model::AppStoreVersionPayload,
    beta: Option<BetaReviewState>,
    review: Option<ReviewState>,
    completeness: ProjectionCompleteness,
) -> ProjectionStatus {
    if build.removed
        || version.removed
        || matches!(build.processing_state, BuildProcessingState::Removed)
        || matches!(
            version.app_store_state,
            AppStoreState::DeveloperRemovedFromSale
                | AppStoreState::RemovedFromSale
                | AppStoreState::Removed
        )
        || matches!(
            version.release_state,
            ReleaseState::DeveloperRemovedFromSale
                | ReleaseState::RemovedFromSale
                | ReleaseState::Removed
        )
    {
        return ProjectionStatus::Removed;
    }
    if build.expired
        || version.expired
        || matches!(build.processing_state, BuildProcessingState::Expired)
        || matches!(version.app_store_state, AppStoreState::Expired)
        || matches!(version.release_state, ReleaseState::Expired)
    {
        return ProjectionStatus::Expired;
    }
    if matches!(build.processing_state, BuildProcessingState::Processing) {
        return ProjectionStatus::Processing;
    }
    if matches!(
        build.processing_state,
        BuildProcessingState::Failed | BuildProcessingState::Invalid
    ) {
        return ProjectionStatus::Partial;
    }
    if matches!(completeness, ProjectionCompleteness::Partial) {
        return ProjectionStatus::Partial;
    }
    if matches!(version.app_store_state, AppStoreState::InReview)
        || matches!(review, Some(ReviewState::InReview))
    {
        return ProjectionStatus::InReview;
    }
    match beta.unwrap_or(build.beta_review_state) {
        BetaReviewState::WaitingForReview | BetaReviewState::InReview => {
            return ProjectionStatus::BetaPending;
        }
        BetaReviewState::Approved => return ProjectionStatus::BetaApproved,
        BetaReviewState::Rejected => return ProjectionStatus::BetaRejected,
        BetaReviewState::Expired | BetaReviewState::Removed => return ProjectionStatus::Expired,
        BetaReviewState::None | BetaReviewState::Unknown => {}
    }
    if matches!(
        version.release_state,
        ReleaseState::Released | ReleaseState::ReadyForSale
    ) {
        return ProjectionStatus::Released;
    }
    if matches!(version.app_store_state, AppStoreState::PrepareForSubmission)
        && matches!(build.processing_state, BuildProcessingState::Complete)
    {
        return ProjectionStatus::Ready;
    }
    ProjectionStatus::Ready
}
