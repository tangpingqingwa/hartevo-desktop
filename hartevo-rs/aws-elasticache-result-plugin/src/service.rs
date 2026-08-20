//! Typed service, read/proposal/verify seams, and reversible registration.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsElastiCacheConsumer;
use crate::error::{AwsElastiCacheError, AwsElastiCacheTransportError, Result};
use crate::model::{
    AwsElastiCacheScope, CacheClusterMetadata, CacheClusterProjection, CacheEvent, Digest,
    EvidenceDigests, EvidenceState, FailoverPosture, HealthState, OpaqueMarker, PaginationStatus,
    PermissionSnapshot, ReplicationGroupMetadata, ReplicationGroupProjection, SecretReference,
    ServiceUpdateMetadata, ServiceUpdateProjection, TransportProvenance, UpdatePosture,
    default_evidence_expiry, validate_collection_bounds, validate_page_count, validate_page_size,
};
use crate::provider::{
    AwsElastiCacheOperation, AwsElastiCacheProvider, AwsElastiCacheProviderDefinition,
    AwsElastiCacheTransport, DescribeCacheClustersRequest, DescribeEventsRequest,
    DescribeReplicationGroupsRequest, DescribeServiceUpdatesRequest,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, LAYER1_PERMISSIONS,
    PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
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
            "aws-elasticache-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("new", format!("{new_status:?}")),
                ("registration", registration_digest.to_string()),
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

/// A version/provider/API/permission/scope/evidence/secret-bound registration.
/// The secret handle is held only in the opaque `SecretReference` and is never
/// serialized or included in a debug representation.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsElastiCacheRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    api_revision: String,
    api_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: crate::model::ConsentScope,
    scope: AwsElastiCacheScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    secret_reference_digest: Digest,
    evidence_digest: Digest,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl AwsElastiCacheRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsElastiCacheScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: crate::model::ConsentScope,
        provider: &AwsElastiCacheProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let id = id.into();
        if id.is_empty() || id.len() > crate::MAX_IDENTIFIER_BYTES || registration_revision == 0 {
            return Err(AwsElastiCacheError::InvalidRegistration);
        }
        provider.validate()?;
        scope.validate()?;
        secret_reference.validate_against(&scope)?;
        permission_snapshot.validate()?;
        if permission_snapshot.permissions().len() != LAYER1_PERMISSIONS.len()
            || permission_snapshot
                .permissions()
                .iter()
                .map(String::as_str)
                .ne(LAYER1_PERMISSIONS)
        {
            return Err(AwsElastiCacheError::InvalidPermissionSnapshot);
        }
        if consent.scope_digest() != &scope.digest() {
            return Err(AwsElastiCacheError::InvalidConsent);
        }
        let mut registration = Self {
            id,
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_revision: provider.api_revision.clone(),
            api_digest: provider.api_digest.clone(),
            permission_snapshot,
            consent,
            scope_digest: scope.digest(),
            scope,
            secret_reference_digest: secret_reference.digest(),
            secret_reference,
            evidence_digest: Digest::zero(),
            registration_revision,
            status: RegistrationStatus::Active,
            binding_digest: Digest::zero(),
        };
        registration.evidence_digest = registration.calculate_evidence_digest();
        registration.binding_digest = registration.calculate_binding_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn id(&self) -> &str {
        &self.id
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

    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> &Digest {
        self.permission_snapshot.digest()
    }

    pub fn consent(&self) -> &crate::model::ConsentScope {
        &self.consent
    }

    pub fn scope(&self) -> &AwsElastiCacheScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<()> {
        let expected_provider = AwsElastiCacheProviderDefinition::new(
            self.provider_revision,
            self.provider_release.clone(),
        )
        .map_err(|_| AwsElastiCacheError::InvalidRegistration)?;
        if self.id.is_empty()
            || self.id.len() > crate::MAX_IDENTIFIER_BYTES
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || contract_digest() != CONTRACT_DIGEST
            || self.provider_id != PROVIDER_ID
            || self.api_revision != API_REVISION
            || self.api_digest != expected_provider.api_digest
            || self.provider_digest != expected_provider.provider_digest
            || self.scope_digest != self.scope.digest()
            || self.secret_reference_digest != self.secret_reference.digest()
            || self.evidence_digest != self.calculate_evidence_digest()
            || self.binding_digest != self.calculate_binding_digest()
            || self.registration_revision == 0
        {
            return Err(AwsElastiCacheError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.permission_snapshot.validate()?;
        self.secret_reference.validate_against(&self.scope)?;
        if self.consent.scope_digest() != &self.scope_digest {
            return Err(AwsElastiCacheError::InvalidConsent);
        }
        Ok(())
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<()> {
        self.validate()?;
        match self.status {
            RegistrationStatus::Active => {}
            RegistrationStatus::Revoked => return Err(AwsElastiCacheError::RegistrationRevoked),
            RegistrationStatus::Reversed => return Err(AwsElastiCacheError::RegistrationReversed),
        }
        self.consent.validate_for(&self.scope, now)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(RegistrationStatus::Reversed)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Active) {
            return Err(AwsElastiCacheError::InvalidRegistration);
        }
        if self.consent.revoked() {
            return Err(AwsElastiCacheError::ConsentRevoked);
        }
        self.transition(RegistrationStatus::Active)
    }

    pub fn revoke_consent(&mut self) -> Result<RegistrationTransitionEvidence> {
        if !self.is_active() {
            return Err(AwsElastiCacheError::RegistrationInactive);
        }
        let previous = self.status;
        self.consent.revoke();
        self.status = RegistrationStatus::Revoked;
        self.binding_digest = self.calculate_binding_digest();
        self.validate()?;
        Ok(RegistrationTransitionEvidence::new(
            previous,
            RegistrationStatus::Revoked,
            self.binding_digest.clone(),
        ))
    }

    fn transition(
        &mut self,
        new_status: RegistrationStatus,
    ) -> Result<RegistrationTransitionEvidence> {
        if self.status == new_status {
            return Err(AwsElastiCacheError::InvalidRegistration);
        }
        let previous = self.status;
        self.status = new_status;
        self.binding_digest = self.calculate_binding_digest();
        self.validate()?;
        Ok(RegistrationTransitionEvidence::new(
            previous,
            new_status,
            self.binding_digest.clone(),
        ))
    }

    fn calculate_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-registration-evidence-binding/v1",
            &[
                ("plugin", self.plugin_version.clone()),
                ("contract", self.contract_version.clone()),
                ("contract_digest", self.contract_digest.to_string()),
                ("provider", self.provider_digest.to_string()),
                ("api", self.api_digest.to_string()),
                ("permission", self.permission_snapshot.digest().to_string()),
                ("scope", self.scope_digest.to_string()),
                ("secret", self.secret_reference_digest.to_string()),
            ],
        )
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin", self.plugin_version.clone()),
                ("contract", self.contract_version.clone()),
                ("contract_digest", self.contract_digest.to_string()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider_digest", self.provider_digest.to_string()),
                ("api_revision", self.api_revision.clone()),
                ("api_digest", self.api_digest.to_string()),
                ("permission", self.permission_snapshot.digest().to_string()),
                ("consent", self.consent.digest().to_string()),
                ("scope", self.scope_digest.to_string()),
                ("secret", self.secret_reference_digest.to_string()),
                ("evidence", self.evidence_digest.to_string()),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

impl fmt::Debug for AwsElastiCacheRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsElastiCacheRegistration")
            .field("id", &self.id)
            .field("plugin_version", &self.plugin_version)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("permission_digest", &self.permission_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("evidence_digest", &self.evidence_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for AwsElastiCacheRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsElastiCacheRegistration", 19)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionSnapshot", &self.permission_snapshot)?;
        state.serialize_field("consent", &self.consent)?;
        state.serialize_field("scope", &self.scope)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.binding_digest)?;
        state.serialize_field("secretReference", &self.secret_reference)?;
        state.end()
    }
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
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsElastiCacheReadRequest {
    scope: AwsElastiCacheScope,
    page_size: u16,
    max_pages: u16,
    include_events: bool,
    include_service_updates: bool,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    request_digest: Digest,
}

impl AwsElastiCacheReadRequest {
    pub fn new(
        scope: &AwsElastiCacheScope,
        page_size: u16,
        max_pages: u16,
        include_events: bool,
        include_service_updates: bool,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        validate_page_size(page_size)?;
        validate_page_count(max_pages)?;
        scope.validate()?;
        let expires_at = default_evidence_expiry(observed_at);
        let request = Self {
            scope: scope.clone(),
            page_size,
            max_pages,
            include_events,
            include_service_updates,
            start_time: scope.event_window.start_time(),
            end_time: scope.event_window.end_time(),
            observed_at,
            expires_at,
            request_digest: Digest::zero(),
        };
        Ok(Self {
            request_digest: request.calculate_digest(),
            ..request
        })
    }

    pub fn for_scope(scope: &AwsElastiCacheScope, observed_at: DateTime<Utc>) -> Result<Self> {
        Self::new(scope, 100, 4, true, true, observed_at)
    }

    pub fn with_window(
        mut self,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) -> Result<Self> {
        if let (Some(start), Some(end)) = (start_time, end_time)
            && (start > end || end - start > chrono::Duration::days(31))
        {
            return Err(AwsElastiCacheError::InvalidRequest);
        }
        self.start_time = start_time;
        self.end_time = end_time;
        self.request_digest = self.calculate_digest();
        Ok(self)
    }

    pub fn scope(&self) -> &AwsElastiCacheScope {
        &self.scope
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn max_pages(&self) -> u16 {
        self.max_pages
    }

    pub const fn include_events(&self) -> bool {
        self.include_events
    }

    pub const fn include_service_updates(&self) -> bool {
        self.include_service_updates
    }

    pub fn start_time(&self) -> Option<DateTime<Utc>> {
        self.start_time
    }

    pub fn end_time(&self) -> Option<DateTime<Utc>> {
        self.end_time
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<()> {
        if self.scope.validate().is_err()
            || self.page_size == 0
            || self.page_size > crate::MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > crate::MAX_PAGES
            || self.request_digest != self.calculate_digest()
        {
            return Err(AwsElastiCacheError::InvalidRequest);
        }
        if self.expires_at <= now {
            return Err(AwsElastiCacheError::ConsentExpired);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-read-request/v1",
            &[
                ("scope", self.scope.digest().to_string()),
                ("page_size", self.page_size.to_string()),
                ("max_pages", self.max_pages.to_string()),
                ("events", self.include_events.to_string()),
                ("updates", self.include_service_updates.to_string()),
                (
                    "start",
                    self.start_time
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "end",
                    self.end_time
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                ("observed", self.observed_at.to_rfc3339()),
                ("expires", self.expires_at.to_rfc3339()),
            ],
        )
    }
}

impl Serialize for AwsElastiCacheReadRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsElastiCacheReadRequest", 10)?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field("pageSize", &self.page_size)?;
        state.serialize_field("maxPages", &self.max_pages)?;
        state.serialize_field("includeEvents", &self.include_events)?;
        state.serialize_field("includeServiceUpdates", &self.include_service_updates)?;
        state.serialize_field("startTime", &self.start_time)?;
        state.serialize_field("endTime", &self.end_time)?;
        state.serialize_field("observedAt", &self.observed_at)?;
        state.serialize_field("expiresAt", &self.expires_at)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    ServerFailure,
    Timeout,
    AccessLoss,
    Partial,
    Expired,
    Stale,
    BlockedEnv,
    InvalidResponse,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub kind: FailureKind,
    pub status_code: Option<u16>,
    pub operation: Option<AwsElastiCacheOperation>,
    pub error_digest: Digest,
}

impl FailureEvidence {
    fn from_error(
        operation: Option<AwsElastiCacheOperation>,
        error: &AwsElastiCacheTransportError,
    ) -> Self {
        let kind = match error {
            AwsElastiCacheTransportError::BadRequest => FailureKind::BadRequest,
            AwsElastiCacheTransportError::Unauthorized => FailureKind::Unauthorized,
            AwsElastiCacheTransportError::Forbidden => FailureKind::Forbidden,
            AwsElastiCacheTransportError::NotFound => FailureKind::NotFound,
            AwsElastiCacheTransportError::RateLimited { .. } => FailureKind::RateLimited,
            AwsElastiCacheTransportError::ServerError { .. } => FailureKind::ServerFailure,
            AwsElastiCacheTransportError::Timeout => FailureKind::Timeout,
            AwsElastiCacheTransportError::AccessLost => FailureKind::AccessLoss,
            AwsElastiCacheTransportError::Partial => FailureKind::Partial,
            AwsElastiCacheTransportError::ExpiredMarker => FailureKind::Expired,
            AwsElastiCacheTransportError::StaleEvidence => FailureKind::Stale,
            AwsElastiCacheTransportError::MarkerLoop
            | AwsElastiCacheTransportError::InvalidResponse => FailureKind::InvalidResponse,
            AwsElastiCacheTransportError::BlockedEnv => FailureKind::BlockedEnv,
            AwsElastiCacheTransportError::Unknown => FailureKind::ProviderUnknown,
        };
        Self {
            kind,
            status_code: error.status_code(),
            operation,
            error_digest: Digest::from_parts(
                "aws-elasticache-redacted-error/v1",
                &[
                    ("kind", format!("{kind:?}")),
                    (
                        "operation",
                        operation.map_or_else(String::new, |value| value.as_str().to_owned()),
                    ),
                    (
                        "status",
                        error
                            .status_code()
                            .map_or_else(String::new, |value| value.to_string()),
                    ),
                ],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElastiCacheReadResult {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub cluster: Option<CacheClusterMetadata>,
    pub replication_group: Option<ReplicationGroupMetadata>,
    pub events: Vec<CacheEvent>,
    pub service_updates: Vec<ServiceUpdateMetadata>,
    pub cluster_pagination: PaginationStatus,
    pub replication_group_pagination: PaginationStatus,
    pub events_pagination: PaginationStatus,
    pub service_updates_pagination: PaginationStatus,
    pub provenance: TransportProvenance,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl AwsElastiCacheReadResult {
    fn empty(request: &AwsElastiCacheReadRequest, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope_digest: request.scope.digest(),
            request_digest: request.request_digest.clone(),
            cluster: None,
            replication_group: None,
            events: Vec::new(),
            service_updates: Vec::new(),
            cluster_pagination: PaginationStatus::complete(0),
            replication_group_pagination: PaginationStatus::complete(0),
            events_pagination: PaginationStatus::complete(0),
            service_updates_pagination: PaginationStatus::complete(0),
            provenance: TransportProvenance::Recording,
            observed_at,
            expires_at: request.expires_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElastiCacheEvidence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub state: EvidenceState,
    pub cluster: Option<CacheClusterProjection>,
    pub replication_group: Option<ReplicationGroupProjection>,
    pub events: Vec<crate::model::EventProjection>,
    pub service_updates: Vec<ServiceUpdateProjection>,
    pub cluster_pagination: PaginationStatus,
    pub replication_group_pagination: PaginationStatus,
    pub events_pagination: PaginationStatus,
    pub service_updates_pagination: PaginationStatus,
    pub provenance: TransportProvenance,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub failure: Option<FailureEvidence>,
    pub digests: EvidenceDigests,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsElastiCacheEvidence {
    fn from_read(
        read: &AwsElastiCacheReadResult,
        state: EvidenceState,
        permission_digest: Digest,
        provider: &AwsElastiCacheProviderDefinition,
    ) -> Self {
        Self::from_parts(
            read.scope_digest.clone(),
            permission_digest,
            provider,
            state,
            read.cluster.as_ref(),
            read.replication_group.as_ref(),
            &read.events,
            &read.service_updates,
            read.cluster_pagination.clone(),
            read.replication_group_pagination.clone(),
            read.events_pagination.clone(),
            read.service_updates_pagination.clone(),
            read.provenance.clone(),
            read.observed_at,
            read.expires_at,
            None,
        )
    }

    fn failure(
        request: &AwsElastiCacheReadRequest,
        state: EvidenceState,
        permission_digest: Digest,
        provider: &AwsElastiCacheProviderDefinition,
        provenance: TransportProvenance,
        operation: Option<AwsElastiCacheOperation>,
        error: &AwsElastiCacheTransportError,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let failure = FailureEvidence::from_error(operation, error);
        Self::from_parts(
            request.scope.digest(),
            permission_digest,
            provider,
            state,
            None,
            None,
            &[],
            &[],
            PaginationStatus::complete(0),
            PaginationStatus::complete(0),
            PaginationStatus::complete(0),
            PaginationStatus::complete(0),
            provenance,
            observed_at,
            request.expires_at,
            Some(failure),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        scope_digest: Digest,
        permission_digest: Digest,
        provider: &AwsElastiCacheProviderDefinition,
        state: EvidenceState,
        cluster: Option<&CacheClusterMetadata>,
        replication_group: Option<&ReplicationGroupMetadata>,
        events: &[CacheEvent],
        service_updates: &[ServiceUpdateMetadata],
        cluster_pagination: PaginationStatus,
        replication_group_pagination: PaginationStatus,
        events_pagination: PaginationStatus,
        service_updates_pagination: PaginationStatus,
        provenance: TransportProvenance,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        failure: Option<FailureEvidence>,
    ) -> Self {
        let cluster_projection = cluster.map(CacheClusterProjection::from);
        let replication_projection = replication_group.map(ReplicationGroupProjection::from);
        let event_projections = events
            .iter()
            .map(CacheEvent::projection)
            .collect::<Vec<_>>();
        let update_projections = service_updates
            .iter()
            .map(ServiceUpdateMetadata::projection)
            .collect::<Vec<_>>();
        let cluster_digest = cluster.map(CacheClusterMetadata::digest);
        let replication_group_digest = replication_group.map(ReplicationGroupMetadata::digest);
        let events_digest = Digest::from_parts(
            "aws-elasticache-events-evidence/v1",
            &[(
                "items",
                events
                    .iter()
                    .map(CacheEvent::digest)
                    .map(|value| value.to_string())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        );
        let service_updates_digest = Digest::from_parts(
            "aws-elasticache-service-updates-evidence/v1",
            &[(
                "items",
                service_updates
                    .iter()
                    .map(ServiceUpdateMetadata::digest)
                    .map(|value| value.to_string())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        );
        let mut evidence = Self {
            scope_digest: scope_digest.clone(),
            permission_digest: permission_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            state,
            cluster: cluster_projection,
            replication_group: replication_projection,
            events: event_projections,
            service_updates: update_projections,
            cluster_pagination,
            replication_group_pagination,
            events_pagination,
            service_updates_pagination,
            provenance,
            observed_at,
            expires_at,
            failure,
            digests: EvidenceDigests {
                plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
                contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())
                    .expect("contract digest is checked"),
                provider_digest: provider.provider_digest.clone(),
                api_digest: provider.api_digest.clone(),
                permission_digest,
                scope_digest,
                cluster_digest,
                replication_group_digest,
                events_digest,
                service_updates_digest,
                evidence_digest: Digest::zero(),
            },
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        evidence.digests.evidence_digest = evidence.calculate_digest();
        evidence
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.is_native()
            || self.provenance.first_party()
            || self.digests.evidence_digest != self.calculate_digest()
        {
            Err(AwsElastiCacheError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.digests.evidence_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-evidence/v1",
            &[
                ("scope", self.scope_digest.to_string()),
                ("permission", self.permission_digest.to_string()),
                ("provider", self.provider_digest.to_string()),
                ("api", self.api_digest.to_string()),
                (
                    "plugin_version_digest",
                    self.digests.plugin_version_digest.to_string(),
                ),
                ("contract_digest", self.digests.contract_digest.to_string()),
                (
                    "provider_digest_field",
                    self.digests.provider_digest.to_string(),
                ),
                ("api_digest_field", self.digests.api_digest.to_string()),
                (
                    "permission_digest_field",
                    self.digests.permission_digest.to_string(),
                ),
                ("scope_digest_field", self.digests.scope_digest.to_string()),
                (
                    "cluster_digest",
                    self.digests
                        .cluster_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                (
                    "replication_group_digest",
                    self.digests
                        .replication_group_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                ("events_digest", self.digests.events_digest.to_string()),
                (
                    "service_updates_digest",
                    self.digests.service_updates_digest.to_string(),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "cluster",
                    self.cluster.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("cluster projection serializes")
                    }),
                ),
                (
                    "replication_group",
                    self.replication_group
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            serde_json::to_string(value)
                                .expect("replication-group projection serializes")
                        }),
                ),
                (
                    "events",
                    serde_json::to_string(&self.events).expect("event projections serialize"),
                ),
                (
                    "updates",
                    serde_json::to_string(&self.service_updates)
                        .expect("service-update projections serialize"),
                ),
                (
                    "cluster_pages",
                    self.cluster_pagination.digest().to_string(),
                ),
                (
                    "replication_group_pages",
                    self.replication_group_pagination.digest().to_string(),
                ),
                ("events_pages", self.events_pagination.digest().to_string()),
                (
                    "service_updates_pages",
                    self.service_updates_pagination.digest().to_string(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("observed_at", self.observed_at.to_rfc3339()),
                ("expires_at", self.expires_at.to_rfc3339()),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("failure evidence serializes")
                    }),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElastiCacheProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub evidence: AwsElastiCacheEvidence,
    pub state: EvidenceState,
    pub provenance: TransportProvenance,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub certification_claim: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsElastiCacheProposal {
    fn new(
        registration: &AwsElastiCacheRegistration,
        request: &AwsElastiCacheReadRequest,
        evidence: AwsElastiCacheEvidence,
    ) -> Self {
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: request.scope.digest(),
            request_digest: request.request_digest.clone(),
            state: evidence.state,
            provenance: evidence.provenance.clone(),
            observed_at: evidence.observed_at,
            expires_at: evidence.expires_at,
            evidence,
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            certification_claim: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.scope_digest != self.evidence.scope_digest
            || self.state != self.evidence.state
            || self.provenance != self.evidence.provenance
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.certification_claim
            || self.outcome_adopted
            || self.work_product_adopted
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.evidence.validate_integrity().is_err()
            || self.proposal_digest != self.calculate_digest()
        {
            Err(AwsElastiCacheError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    pub fn evidence(&self) -> &AwsElastiCacheEvidence {
        &self.evidence
    }

    pub fn can_be_adopted(&self) -> bool {
        false
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("provider", self.provider_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                ("request", self.request_digest.to_string()),
                ("evidence", self.evidence.evidence_digest().to_string()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("observed_at", self.observed_at.to_rfc3339()),
                ("expires_at", self.expires_at.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsElastiCacheResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub state: EvidenceState,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedAwsElastiCacheResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsElastiCacheProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest().clone(),
            state: proposal.state,
            provenance: proposal.provenance.clone(),
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::zero(),
        };
        result.recording_digest = result.calculate_digest();
        result
    }

    pub(crate) fn new_for_consumer(
        idempotency_key_digest: Digest,
        proposal: &AwsElastiCacheProposal,
    ) -> Self {
        Self::new(idempotency_key_digest, proposal, false)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            Err(AwsElastiCacheError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-recording/v1",
            &[
                ("idempotency", self.idempotency_key_digest.to_string()),
                ("proposal", self.proposal_digest.to_string()),
                ("evidence", self.evidence_digest.to_string()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }

    pub(crate) fn replayed(&self) -> Self {
        let mut replay = self.clone();
        replay.replayed = true;
        replay.recording_digest = replay.calculate_digest();
        replay
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
    EvidenceDigestMismatch,
    ProposalDigestMismatch,
    ExpiredEvidence,
    NotFound,
    PartialEvidence,
    AccessLoss,
    Throttled,
    StaleEvidence,
    ProviderUnknown,
    TamperedEvidence,
    ReplayConflict,
    RevokedRegistration,
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
            "aws-elasticache-verification-report/v1",
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

pub struct AwsElastiCacheService<T: AwsElastiCacheTransport> {
    registration: AwsElastiCacheRegistration,
    provider: AwsElastiCacheProvider<T>,
    records: BTreeMap<Digest, RecordedAwsElastiCacheResult>,
}

impl<T: AwsElastiCacheTransport> fmt::Debug for AwsElastiCacheService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsElastiCacheService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T: AwsElastiCacheTransport> AwsElastiCacheService<T> {
    pub fn new(
        scope: AwsElastiCacheScope,
        secret_reference: SecretReference,
        provider: AwsElastiCacheProvider<T>,
    ) -> Result<Self> {
        let now = Utc::now();
        let permission = PermissionSnapshot::for_layer_one(1)?;
        let consent = crate::model::ConsentScope::valid_for(&scope, now)?;
        Self::with_registration(
            "aws-elasticache-registration",
            scope,
            secret_reference,
            permission,
            consent,
            provider,
            1,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_registration(
        registration_id: impl Into<String>,
        scope: AwsElastiCacheScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: crate::model::ConsentScope,
        provider: AwsElastiCacheProvider<T>,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = AwsElastiCacheRegistration::new(
            registration_id,
            scope,
            secret_reference,
            permission_snapshot,
            consent,
            provider.definition(),
            registration_revision,
        )?;
        Ok(Self {
            registration,
            provider,
            records: BTreeMap::new(),
        })
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            api_revision: API_REVISION.to_owned(),
            operations: [
                AwsElastiCacheOperation::DescribeCacheClusters,
                AwsElastiCacheOperation::DescribeReplicationGroups,
                AwsElastiCacheOperation::DescribeEvents,
                AwsElastiCacheOperation::DescribeServiceUpdates,
            ]
            .into_iter()
            .map(|operation| operation.as_str().to_owned())
            .collect(),
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }

    pub fn scope(&self) -> &AwsElastiCacheScope {
        self.registration.scope()
    }

    pub fn registration(&self) -> &AwsElastiCacheRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsElastiCacheRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsElastiCacheProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsElastiCacheProvider<T> {
        &mut self.provider
    }

    pub fn secret_reference(&self) -> &SecretReference {
        self.registration.secret_reference()
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn read_bounded(
        &mut self,
        request: &AwsElastiCacheReadRequest,
        observed_at: DateTime<Utc>,
    ) -> std::result::Result<AwsElastiCacheReadResult, AwsElastiCacheTransportError> {
        self.registration
            .validate_at(observed_at)
            .map_err(|_| AwsElastiCacheTransportError::AccessLost)?;
        if request.scope.digest() != self.scope().digest() {
            return Err(AwsElastiCacheTransportError::InvalidResponse);
        }
        request
            .validate_at(observed_at)
            .map_err(map_read_request_error)?;
        let mut result = AwsElastiCacheReadResult::empty(request, observed_at);
        result.provenance = self.provider.provenance();

        match &request.scope.resource {
            crate::model::ElastiCacheResource::CacheCluster { .. } => {
                let (cluster, pagination) = self.read_clusters(request)?;
                result.cluster = cluster;
                result.cluster_pagination = pagination;
            }
            crate::model::ElastiCacheResource::ReplicationGroup { .. } => {
                let (group, pagination) = self.read_replication_groups(request)?;
                result.replication_group = group;
                result.replication_group_pagination = pagination;
            }
        }
        if request.include_events {
            let (events, pagination) = self.read_events(request)?;
            result.events = events;
            result.events_pagination = pagination;
        }
        if request.include_service_updates {
            let (updates, pagination) = self.read_service_updates(request)?;
            result.service_updates = updates;
            result.service_updates_pagination = pagination;
        }
        validate_collection_bounds(result.events.len(), result.service_updates.len())
            .map_err(|_| AwsElastiCacheTransportError::Partial)?;
        Ok(result)
    }

    pub fn read(
        &mut self,
        request: &AwsElastiCacheReadRequest,
        observed_at: DateTime<Utc>,
    ) -> std::result::Result<AwsElastiCacheReadResult, AwsElastiCacheTransportError> {
        self.read_bounded(request, observed_at)
    }

    fn read_clusters(
        &mut self,
        request: &AwsElastiCacheReadRequest,
    ) -> std::result::Result<
        (Option<CacheClusterMetadata>, PaginationStatus),
        AwsElastiCacheTransportError,
    > {
        let mut marker: Option<OpaqueMarker> = None;
        let mut seen_markers = BTreeSet::new();
        let mut pages: u16 = 0;
        let mut first = None;
        loop {
            if let Some(current) = &marker
                && !seen_markers.insert(current.token_digest().clone())
            {
                return Err(AwsElastiCacheTransportError::MarkerLoop);
            }
            pages = pages.saturating_add(1);
            let page_request = DescribeCacheClustersRequest::new(
                request.scope(),
                request.page_size(),
                marker.clone(),
            )
            .map_err(map_read_request_error)?;
            let response = self.provider.describe_cache_clusters(&page_request)?;
            for cluster in &response.clusters {
                ensure_fresh(cluster.observed_at, request.observed_at())
                    .map_err(map_read_model_error)?;
            }
            if first.is_none() {
                first = response.clusters.first().cloned();
            }
            marker = response.next_marker.clone();
            if marker.is_none() {
                return Ok((first, PaginationStatus::complete(pages)));
            }
            if pages >= request.max_pages() {
                return Ok((
                    first,
                    PaginationStatus::bounded(
                        pages,
                        marker.as_ref().map(OpaqueMarker::token_digest).cloned(),
                    ),
                ));
            }
        }
    }

    fn read_replication_groups(
        &mut self,
        request: &AwsElastiCacheReadRequest,
    ) -> std::result::Result<
        (Option<ReplicationGroupMetadata>, PaginationStatus),
        AwsElastiCacheTransportError,
    > {
        let mut marker: Option<OpaqueMarker> = None;
        let mut seen_markers = BTreeSet::new();
        let mut pages: u16 = 0;
        let mut first = None;
        loop {
            if let Some(current) = &marker
                && !seen_markers.insert(current.token_digest().clone())
            {
                return Err(AwsElastiCacheTransportError::MarkerLoop);
            }
            pages = pages.saturating_add(1);
            let page_request = DescribeReplicationGroupsRequest::new(
                request.scope(),
                request.page_size(),
                marker.clone(),
            )
            .map_err(map_read_request_error)?;
            let response = self.provider.describe_replication_groups(&page_request)?;
            for group in &response.replication_groups {
                ensure_fresh(group.observed_at, request.observed_at())
                    .map_err(map_read_model_error)?;
            }
            if first.is_none() {
                first = response.replication_groups.first().cloned();
            }
            marker = response.next_marker.clone();
            if marker.is_none() {
                return Ok((first, PaginationStatus::complete(pages)));
            }
            if pages >= request.max_pages() {
                return Ok((
                    first,
                    PaginationStatus::bounded(
                        pages,
                        marker.as_ref().map(OpaqueMarker::token_digest).cloned(),
                    ),
                ));
            }
        }
    }

    fn read_events(
        &mut self,
        request: &AwsElastiCacheReadRequest,
    ) -> std::result::Result<(Vec<CacheEvent>, PaginationStatus), AwsElastiCacheTransportError>
    {
        let mut marker: Option<OpaqueMarker> = None;
        let mut seen_markers = BTreeSet::new();
        let mut pages: u16 = 0;
        let mut events = Vec::new();
        loop {
            if let Some(current) = &marker
                && !seen_markers.insert(current.token_digest().clone())
            {
                return Err(AwsElastiCacheTransportError::MarkerLoop);
            }
            pages = pages.saturating_add(1);
            let page_request = DescribeEventsRequest::new(
                request.scope(),
                request.page_size(),
                request.start_time(),
                request.end_time(),
                marker.clone(),
            )
            .map_err(map_read_request_error)?;
            let response = self.provider.describe_events(&page_request)?;
            for event in &response.events {
                if request
                    .start_time()
                    .is_some_and(|start| event.occurred_at < start)
                    || request
                        .end_time()
                        .is_some_and(|end| event.occurred_at > end)
                {
                    return Err(AwsElastiCacheTransportError::InvalidResponse);
                }
            }
            events.extend(response.events);
            marker = response.next_marker;
            if marker.is_none() {
                return Ok((events, PaginationStatus::complete(pages)));
            }
            if pages >= request.max_pages() {
                return Ok((
                    events,
                    PaginationStatus::bounded(
                        pages,
                        marker.as_ref().map(OpaqueMarker::token_digest).cloned(),
                    ),
                ));
            }
        }
    }

    fn read_service_updates(
        &mut self,
        request: &AwsElastiCacheReadRequest,
    ) -> std::result::Result<
        (Vec<ServiceUpdateMetadata>, PaginationStatus),
        AwsElastiCacheTransportError,
    > {
        let mut marker: Option<OpaqueMarker> = None;
        let mut seen_markers = BTreeSet::new();
        let mut pages: u16 = 0;
        let mut updates = Vec::new();
        loop {
            if let Some(current) = &marker
                && !seen_markers.insert(current.token_digest().clone())
            {
                return Err(AwsElastiCacheTransportError::MarkerLoop);
            }
            pages = pages.saturating_add(1);
            let page_request = DescribeServiceUpdatesRequest::new(
                request.scope(),
                request.page_size(),
                marker.clone(),
            )
            .map_err(map_read_request_error)?;
            let response = self.provider.describe_service_updates(&page_request)?;
            updates.extend(response.service_updates);
            marker = response.next_marker;
            if marker.is_none() {
                return Ok((updates, PaginationStatus::complete(pages)));
            }
            if pages >= request.max_pages() {
                return Ok((
                    updates,
                    PaginationStatus::bounded(
                        pages,
                        marker.as_ref().map(OpaqueMarker::token_digest).cloned(),
                    ),
                ));
            }
        }
    }

    pub fn propose(
        &mut self,
        request: &AwsElastiCacheReadRequest,
        observed_at: DateTime<Utc>,
    ) -> Result<AwsElastiCacheProposal> {
        self.registration.validate_at(observed_at)?;
        if request.scope.digest() != self.scope().digest() {
            return Err(AwsElastiCacheError::ScopeMismatch);
        }
        request.validate_at(observed_at)?;
        let permission_digest = self.registration.permission_digest().clone();
        let evidence = match self.read_bounded(request, observed_at) {
            Ok(read) => {
                let state = derive_state(&read);
                AwsElastiCacheEvidence::from_read(
                    &read,
                    state,
                    permission_digest,
                    self.provider.definition(),
                )
            }
            Err(error) => {
                let (state, operation) = state_from_error(&error);
                AwsElastiCacheEvidence::failure(
                    request,
                    state,
                    permission_digest,
                    self.provider.definition(),
                    self.provider.provenance(),
                    operation,
                    &error,
                    observed_at,
                )
            }
        };
        let proposal = AwsElastiCacheProposal::new(&self.registration, request, evidence);
        proposal.validate_integrity()?;
        Ok(proposal)
    }

    pub fn compile_proposal(
        &mut self,
        request: &AwsElastiCacheReadRequest,
        observed_at: DateTime<Utc>,
    ) -> Result<AwsElastiCacheProposal> {
        self.propose(request, observed_at)
    }

    pub fn verify(
        &self,
        proposal: &AwsElastiCacheProposal,
        now: DateTime<Utc>,
    ) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
            failures.push(VerificationFailure::RevokedRegistration);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.scope_digest != *self.registration.scope_digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.provider_digest != *self.registration.provider_digest() {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.api_digest != *self.registration.api_digest() {
            failures.push(VerificationFailure::ApiDigestMismatch);
        }
        if proposal.evidence.permission_digest != *self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.expires_at <= now {
            failures.push(VerificationFailure::ExpiredEvidence);
        }
        if proposal.validate_integrity().is_err() || proposal.evidence.validate_integrity().is_err()
        {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            EvidenceState::NotFound => failures.push(VerificationFailure::NotFound),
            EvidenceState::Partial => failures.push(VerificationFailure::PartialEvidence),
            EvidenceState::Expired => failures.push(VerificationFailure::ExpiredEvidence),
            EvidenceState::Stale => failures.push(VerificationFailure::StaleEvidence),
            EvidenceState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            EvidenceState::Throttled => failures.push(VerificationFailure::Throttled),
            EvidenceState::ProviderUnknown => failures.push(VerificationFailure::ProviderUnknown),
            _ => {}
        }
        failures.sort_unstable();
        failures.dedup();
        VerificationReport::new(
            failures.is_empty(),
            failures.is_empty() && proposal.state.is_review_complete(),
            failures,
        )
    }

    pub fn verify_evidence(
        &self,
        evidence: &AwsElastiCacheEvidence,
        now: DateTime<Utc>,
    ) -> VerificationReport {
        let mut proposal = AwsElastiCacheProposal {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: self.registration.registration_digest().clone(),
            scope_digest: self.registration.scope_digest().clone(),
            request_digest: Digest::zero(),
            state: evidence.state,
            provenance: evidence.provenance.clone(),
            observed_at: evidence.observed_at,
            expires_at: evidence.expires_at,
            evidence: evidence.clone(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            certification_claim: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        self.verify(&proposal, now)
    }

    pub fn record(
        &mut self,
        proposal: &AwsElastiCacheProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsElastiCacheResult> {
        self.registration.validate_at(Utc::now())?;
        proposal.validate_integrity()?;
        if proposal.expires_at <= Utc::now() {
            return Err(AwsElastiCacheError::ConsentExpired);
        }
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != *self.registration.scope_digest()
            || proposal.evidence.provider_digest != *self.registration.provider_digest()
            || proposal.evidence.api_digest != *self.registration.api_digest()
            || proposal.evidence.permission_digest != *self.registration.permission_digest()
        {
            return Err(AwsElastiCacheError::ScopeMismatch);
        }
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsElastiCacheError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsElastiCacheError::RecordingConflict);
            }
            return Ok(existing.replayed());
        }
        let result = RecordedAwsElastiCacheResult::new(key_digest.clone(), proposal, false);
        result.validate_integrity()?;
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }

    pub fn record_at(
        &mut self,
        proposal: &AwsElastiCacheProposal,
        idempotency_key: impl AsRef<str>,
        _recorded_at: DateTime<Utc>,
    ) -> Result<RecordedAwsElastiCacheResult> {
        self.record(proposal, idempotency_key)
    }

    pub fn record_evidence(
        &mut self,
        proposal: &AwsElastiCacheProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsElastiCacheResult> {
        self.record(proposal, idempotency_key)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn mission_consumer(&self) -> Result<MissionAwsElastiCacheConsumer> {
        MissionAwsElastiCacheConsumer::new(
            self.registration.scope().clone(),
            self.registration.clone(),
        )
        .map_err(|_| AwsElastiCacheError::InvalidRegistration)
    }
}

impl<T: AwsElastiCacheTransport> AwsElastiCacheService<T> {
    pub fn into_provider(self) -> AwsElastiCacheProvider<T> {
        self.provider
    }
}

fn derive_state(read: &AwsElastiCacheReadResult) -> EvidenceState {
    if !read.cluster_pagination.complete
        || !read.replication_group_pagination.complete
        || !read.events_pagination.complete
        || !read.service_updates_pagination.complete
    {
        return if read.cluster_pagination.expired
            || read.replication_group_pagination.expired
            || read.events_pagination.expired
            || read.service_updates_pagination.expired
        {
            EvidenceState::Expired
        } else {
            EvidenceState::Partial
        };
    }
    let health = read
        .cluster
        .as_ref()
        .map(|value| value.health)
        .or_else(|| read.replication_group.as_ref().map(|value| value.health));
    let failover = read
        .cluster
        .as_ref()
        .map(|value| value.failover)
        .or_else(|| read.replication_group.as_ref().map(|value| value.failover));
    let update = read
        .cluster
        .as_ref()
        .map(|value| value.update)
        .or_else(|| read.replication_group.as_ref().map(|value| value.update));
    if read.cluster.is_none() && read.replication_group.is_none() {
        return EvidenceState::NotFound;
    }
    if matches!(
        failover,
        Some(FailoverPosture::InProgress | FailoverPosture::Failover)
    ) {
        EvidenceState::FailoverInProgress
    } else if matches!(
        update,
        Some(
            UpdatePosture::Pending
                | UpdatePosture::InProgress
                | UpdatePosture::Required
                | UpdatePosture::Failed,
        )
    ) || read.service_updates.iter().any(|value| {
        matches!(
            value.update_posture,
            UpdatePosture::Pending
                | UpdatePosture::InProgress
                | UpdatePosture::Required
                | UpdatePosture::Failed
        )
    }) {
        EvidenceState::UpdateRequired
    } else {
        match health {
            Some(HealthState::Healthy | HealthState::Available) => EvidenceState::Healthy,
            Some(HealthState::Creating) => EvidenceState::Creating,
            Some(HealthState::Modifying) => EvidenceState::Modifying,
            Some(HealthState::Failing) => EvidenceState::Failing,
            Some(HealthState::Replication) => EvidenceState::Replication,
            Some(HealthState::Degraded) => EvidenceState::Degraded,
            Some(HealthState::Unavailable) => EvidenceState::Unavailable,
            _ => EvidenceState::ProviderUnknown,
        }
    }
}

fn state_from_error(
    error: &AwsElastiCacheTransportError,
) -> (EvidenceState, Option<AwsElastiCacheOperation>) {
    let state = match error {
        AwsElastiCacheTransportError::NotFound => EvidenceState::NotFound,
        AwsElastiCacheTransportError::Unauthorized
        | AwsElastiCacheTransportError::Forbidden
        | AwsElastiCacheTransportError::AccessLost => EvidenceState::AccessLoss,
        AwsElastiCacheTransportError::RateLimited { .. } => EvidenceState::Throttled,
        AwsElastiCacheTransportError::Partial => EvidenceState::Partial,
        AwsElastiCacheTransportError::ExpiredMarker => EvidenceState::Expired,
        AwsElastiCacheTransportError::StaleEvidence => EvidenceState::Stale,
        AwsElastiCacheTransportError::BadRequest
        | AwsElastiCacheTransportError::ServerError { .. }
        | AwsElastiCacheTransportError::Timeout
        | AwsElastiCacheTransportError::MarkerLoop
        | AwsElastiCacheTransportError::BlockedEnv
        | AwsElastiCacheTransportError::InvalidResponse
        | AwsElastiCacheTransportError::Unknown => EvidenceState::ProviderUnknown,
    };
    (state, None)
}

fn ensure_fresh(observed_at: DateTime<Utc>, expected_at: DateTime<Utc>) -> Result<()> {
    let staleness_seconds = i64::try_from(crate::MAX_STALENESS_SECONDS)
        .expect("bounded staleness fits in chrono duration");
    let lower_bound = expected_at - chrono::Duration::seconds(staleness_seconds);
    let upper_bound = expected_at + chrono::Duration::minutes(5);
    if observed_at < lower_bound || observed_at > upper_bound {
        Err(AwsElastiCacheError::StaleEvidence)
    } else {
        Ok(())
    }
}

fn map_read_model_error(error: AwsElastiCacheError) -> AwsElastiCacheTransportError {
    match error {
        AwsElastiCacheError::StaleEvidence => AwsElastiCacheTransportError::StaleEvidence,
        AwsElastiCacheError::PartialEvidence => AwsElastiCacheTransportError::Partial,
        AwsElastiCacheError::MarkerExpired => AwsElastiCacheTransportError::ExpiredMarker,
        _ => AwsElastiCacheTransportError::InvalidResponse,
    }
}

fn map_read_request_error(error: AwsElastiCacheError) -> AwsElastiCacheTransportError {
    match error {
        AwsElastiCacheError::MarkerExpired | AwsElastiCacheError::ConsentExpired => {
            AwsElastiCacheTransportError::ExpiredMarker
        }
        _ => AwsElastiCacheTransportError::InvalidResponse,
    }
}
