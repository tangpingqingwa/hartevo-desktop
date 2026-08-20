//! Bounded, metadata-only AWS ElastiCache provider seams.
//!
//! This module intentionally has no AWS SDK, signer, credential resolver, HTTP
//! client, endpoint/node-address field, mutation API, or raw-provider-payload
//! retention path. A Layer-2 host may implement the transport trait later.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{AwsElastiCacheError, AwsElastiCacheTransportError, Result};
use crate::model::{
    AwsElastiCacheScope, CacheClusterMetadata, CacheEvent, Digest, OpaqueMarker,
    ReplicationGroupMetadata, ServiceUpdateMetadata, TransportProvenance, validate_page_size,
    validate_response_bytes,
};
use crate::service::AwsElastiCacheRegistration;
use crate::{API_REVISION, CONTRACT_VERSION, LAYER1_PERMISSIONS, PROVIDER_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsElastiCacheOperation {
    DescribeCacheClusters,
    DescribeReplicationGroups,
    DescribeEvents,
    DescribeServiceUpdates,
}

impl AwsElastiCacheOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescribeCacheClusters => "DescribeCacheClusters",
            Self::DescribeReplicationGroups => "DescribeReplicationGroups",
            Self::DescribeEvents => "DescribeEvents",
            Self::DescribeServiceUpdates => "DescribeServiceUpdates",
        }
    }

    pub fn digest(self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-api-operation/v1",
            &[("operation", self.as_str().to_owned())],
        )
    }
}

pub trait AwsElastiCacheTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn describe_cache_clusters(
        &mut self,
        request: &DescribeCacheClustersRequest,
    ) -> std::result::Result<DescribeCacheClustersResponse, AwsElastiCacheTransportError>;

    fn describe_replication_groups(
        &mut self,
        request: &DescribeReplicationGroupsRequest,
    ) -> std::result::Result<DescribeReplicationGroupsResponse, AwsElastiCacheTransportError>;

    fn describe_events(
        &mut self,
        request: &DescribeEventsRequest,
    ) -> std::result::Result<DescribeEventsResponse, AwsElastiCacheTransportError>;

    fn describe_service_updates(
        &mut self,
        request: &DescribeServiceUpdatesRequest,
    ) -> std::result::Result<DescribeServiceUpdatesResponse, AwsElastiCacheTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsElastiCacheOperation,
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub marker_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeCacheClustersRequest {
    scope: AwsElastiCacheScope,
    page_size: u16,
    marker: Option<OpaqueMarker>,
    filter_digest: Digest,
    request_digest: Digest,
}

impl DescribeCacheClustersRequest {
    pub fn new(
        scope: &AwsElastiCacheScope,
        page_size: u16,
        marker: Option<OpaqueMarker>,
    ) -> Result<Self> {
        Self::new_with_page_size(scope, page_size, marker)
    }

    pub fn for_scope(scope: &AwsElastiCacheScope) -> Result<Self> {
        Self::new_with_page_size(scope, 100, None)
    }

    fn new_with_page_size(
        scope: &AwsElastiCacheScope,
        page_size: u16,
        marker: Option<OpaqueMarker>,
    ) -> Result<Self> {
        scope.validate()?;
        validate_page_size(page_size)?;
        let filter_digest = Digest::from_parts(
            "aws-elasticache-cache-cluster-filter/v1",
            &[
                ("resource", scope.resource.digest().to_string()),
                ("page_size", page_size.to_string()),
            ],
        );
        if let Some(marker) = &marker {
            marker.validate_for(
                AwsElastiCacheOperation::DescribeCacheClusters.as_str(),
                scope,
                &filter_digest,
                Utc::now(),
            )?;
        }
        let request_digest = request_digest(
            AwsElastiCacheOperation::DescribeCacheClusters,
            scope,
            &filter_digest,
            marker.as_ref(),
        );
        Ok(Self {
            scope: scope.clone(),
            page_size,
            marker,
            filter_digest: filter_digest.clone(),
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsElastiCacheScope {
        &self.scope
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn marker(&self) -> Option<&OpaqueMarker> {
        self.marker.as_ref()
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.marker.as_ref().map_or(1, OpaqueMarker::page_number)
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        recorded_request(
            AwsElastiCacheOperation::DescribeCacheClusters,
            &self.scope,
            &self.filter_digest,
            self.marker.as_ref(),
            &self.request_digest,
        )
    }
}

impl fmt::Debug for DescribeCacheClustersRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeCacheClustersRequest")
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("marker", &self.marker)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeReplicationGroupsRequest {
    scope: AwsElastiCacheScope,
    page_size: u16,
    marker: Option<OpaqueMarker>,
    filter_digest: Digest,
    request_digest: Digest,
}

impl DescribeReplicationGroupsRequest {
    pub fn new(
        scope: &AwsElastiCacheScope,
        page_size: u16,
        marker: Option<OpaqueMarker>,
    ) -> Result<Self> {
        scope.validate()?;
        validate_page_size(page_size)?;
        let filter_digest = Digest::from_parts(
            "aws-elasticache-replication-group-filter/v1",
            &[
                ("resource", scope.resource.digest().to_string()),
                ("page_size", page_size.to_string()),
            ],
        );
        if let Some(marker) = &marker {
            marker.validate_for(
                AwsElastiCacheOperation::DescribeReplicationGroups.as_str(),
                scope,
                &filter_digest,
                Utc::now(),
            )?;
        }
        let request_digest = request_digest(
            AwsElastiCacheOperation::DescribeReplicationGroups,
            scope,
            &filter_digest,
            marker.as_ref(),
        );
        Ok(Self {
            scope: scope.clone(),
            page_size,
            marker,
            filter_digest: filter_digest.clone(),
            request_digest,
        })
    }

    pub fn for_scope(scope: &AwsElastiCacheScope) -> Result<Self> {
        Self::new(scope, 100, None)
    }

    pub fn scope(&self) -> &AwsElastiCacheScope {
        &self.scope
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn marker(&self) -> Option<&OpaqueMarker> {
        self.marker.as_ref()
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.marker.as_ref().map_or(1, OpaqueMarker::page_number)
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        recorded_request(
            AwsElastiCacheOperation::DescribeReplicationGroups,
            &self.scope,
            &self.filter_digest,
            self.marker.as_ref(),
            &self.request_digest,
        )
    }
}

impl fmt::Debug for DescribeReplicationGroupsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeReplicationGroupsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("marker", &self.marker)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeEventsRequest {
    scope: AwsElastiCacheScope,
    page_size: u16,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    marker: Option<OpaqueMarker>,
    filter_digest: Digest,
    request_digest: Digest,
}

impl DescribeEventsRequest {
    pub fn new(
        scope: &AwsElastiCacheScope,
        page_size: u16,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        marker: Option<OpaqueMarker>,
    ) -> Result<Self> {
        scope.validate()?;
        validate_page_size(page_size)?;
        if let (Some(start), Some(end)) = (start_time, end_time)
            && (start > end || end - start > chrono::Duration::days(31))
        {
            return Err(AwsElastiCacheError::InvalidRequest);
        }
        let filter_digest = Digest::from_parts(
            "aws-elasticache-events-filter/v1",
            &[
                ("resource", scope.resource.digest().to_string()),
                (
                    "start",
                    start_time.map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "end",
                    end_time.map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                ("page_size", page_size.to_string()),
            ],
        );
        if let Some(marker) = &marker {
            marker.validate_for(
                AwsElastiCacheOperation::DescribeEvents.as_str(),
                scope,
                &filter_digest,
                Utc::now(),
            )?;
        }
        let request_digest = request_digest(
            AwsElastiCacheOperation::DescribeEvents,
            scope,
            &filter_digest,
            marker.as_ref(),
        );
        Ok(Self {
            scope: scope.clone(),
            page_size,
            start_time,
            end_time,
            marker,
            filter_digest: filter_digest.clone(),
            request_digest,
        })
    }

    pub fn for_scope(scope: &AwsElastiCacheScope) -> Result<Self> {
        Self::new(
            scope,
            100,
            scope.event_window.start_time(),
            scope.event_window.end_time(),
            None,
        )
    }

    pub fn scope(&self) -> &AwsElastiCacheScope {
        &self.scope
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn start_time(&self) -> Option<DateTime<Utc>> {
        self.start_time
    }

    pub fn end_time(&self) -> Option<DateTime<Utc>> {
        self.end_time
    }

    pub fn marker(&self) -> Option<&OpaqueMarker> {
        self.marker.as_ref()
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.marker.as_ref().map_or(1, OpaqueMarker::page_number)
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        recorded_request(
            AwsElastiCacheOperation::DescribeEvents,
            &self.scope,
            &self.filter_digest,
            self.marker.as_ref(),
            &self.request_digest,
        )
    }
}

impl fmt::Debug for DescribeEventsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeEventsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("start_time", &self.start_time)
            .field("end_time", &self.end_time)
            .field("marker", &self.marker)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeServiceUpdatesRequest {
    scope: AwsElastiCacheScope,
    page_size: u16,
    marker: Option<OpaqueMarker>,
    filter_digest: Digest,
    request_digest: Digest,
}

impl DescribeServiceUpdatesRequest {
    pub fn new(
        scope: &AwsElastiCacheScope,
        page_size: u16,
        marker: Option<OpaqueMarker>,
    ) -> Result<Self> {
        scope.validate()?;
        validate_page_size(page_size)?;
        let filter_digest = Digest::from_parts(
            "aws-elasticache-service-updates-filter/v1",
            &[
                ("resource", scope.resource.digest().to_string()),
                ("page_size", page_size.to_string()),
            ],
        );
        if let Some(marker) = &marker {
            marker.validate_for(
                AwsElastiCacheOperation::DescribeServiceUpdates.as_str(),
                scope,
                &filter_digest,
                Utc::now(),
            )?;
        }
        let request_digest = request_digest(
            AwsElastiCacheOperation::DescribeServiceUpdates,
            scope,
            &filter_digest,
            marker.as_ref(),
        );
        Ok(Self {
            scope: scope.clone(),
            page_size,
            marker,
            filter_digest: filter_digest.clone(),
            request_digest,
        })
    }

    pub fn for_scope(scope: &AwsElastiCacheScope) -> Result<Self> {
        Self::new(scope, 100, None)
    }

    pub fn scope(&self) -> &AwsElastiCacheScope {
        &self.scope
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn marker(&self) -> Option<&OpaqueMarker> {
        self.marker.as_ref()
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.marker.as_ref().map_or(1, OpaqueMarker::page_number)
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        recorded_request(
            AwsElastiCacheOperation::DescribeServiceUpdates,
            &self.scope,
            &self.filter_digest,
            self.marker.as_ref(),
            &self.request_digest,
        )
    }
}

impl fmt::Debug for DescribeServiceUpdatesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeServiceUpdatesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("marker", &self.marker)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeCacheClustersResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub clusters: Vec<CacheClusterMetadata>,
    pub next_marker: Option<OpaqueMarker>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeCacheClustersResponse {
    pub fn new(
        request: &DescribeCacheClustersRequest,
        clusters: Vec<CacheClusterMetadata>,
        next_marker: Option<OpaqueMarker>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if clusters.len() > request.page_size() as usize || clusters.len() > 1 {
            return Err(AwsElastiCacheError::PartialEvidence);
        }
        for cluster in &clusters {
            cluster.validate(request.scope())?;
        }
        validate_next_marker(
            next_marker.as_ref(),
            AwsElastiCacheOperation::DescribeCacheClusters,
            request,
        )?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter_digest().clone(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            clusters,
            next_marker,
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_marker.is_some()
    }

    pub fn validate_integrity(
        &self,
        request: &DescribeCacheClustersRequest,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != *request.filter_digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.is_native()
            || self.provenance.first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsElastiCacheError::TamperedEvidence);
        }
        for cluster in &self.clusters {
            cluster.validate(request.scope())?;
        }
        if let Some(marker) = &self.next_marker {
            marker.validate_for(
                AwsElastiCacheOperation::DescribeCacheClusters.as_str(),
                request.scope(),
                request.filter_digest(),
                now,
            )?;
            if marker.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsElastiCacheError::MarkerMismatch);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-describe-cache-clusters-response/v1",
            &[
                ("scope", self.scope_digest.to_string()),
                ("filter", self.filter_digest.to_string()),
                ("request", self.request_digest.to_string()),
                ("page", self.page_number.to_string()),
                (
                    "clusters",
                    self.clusters
                        .iter()
                        .map(CacheClusterMetadata::digest)
                        .map(|digest| digest.to_string())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("marker", marker_digest(self.next_marker.as_ref())),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeReplicationGroupsResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub replication_groups: Vec<ReplicationGroupMetadata>,
    pub next_marker: Option<OpaqueMarker>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeReplicationGroupsResponse {
    pub fn new(
        request: &DescribeReplicationGroupsRequest,
        replication_groups: Vec<ReplicationGroupMetadata>,
        next_marker: Option<OpaqueMarker>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if replication_groups.len() > request.page_size() as usize || replication_groups.len() > 1 {
            return Err(AwsElastiCacheError::PartialEvidence);
        }
        for group in &replication_groups {
            group.validate(request.scope())?;
        }
        validate_next_marker(
            next_marker.as_ref(),
            AwsElastiCacheOperation::DescribeReplicationGroups,
            request,
        )?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter_digest().clone(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            replication_groups,
            next_marker,
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_marker.is_some()
    }

    pub fn validate_integrity(
        &self,
        request: &DescribeReplicationGroupsRequest,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != *request.filter_digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.is_native()
            || self.provenance.first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsElastiCacheError::TamperedEvidence);
        }
        for group in &self.replication_groups {
            group.validate(request.scope())?;
        }
        if let Some(marker) = &self.next_marker {
            marker.validate_for(
                AwsElastiCacheOperation::DescribeReplicationGroups.as_str(),
                request.scope(),
                request.filter_digest(),
                now,
            )?;
            if marker.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsElastiCacheError::MarkerMismatch);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-describe-replication-groups-response/v1",
            &[
                ("scope", self.scope_digest.to_string()),
                ("filter", self.filter_digest.to_string()),
                ("request", self.request_digest.to_string()),
                ("page", self.page_number.to_string()),
                (
                    "groups",
                    self.replication_groups
                        .iter()
                        .map(ReplicationGroupMetadata::digest)
                        .map(|digest| digest.to_string())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("marker", marker_digest(self.next_marker.as_ref())),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeEventsResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub events: Vec<CacheEvent>,
    pub next_marker: Option<OpaqueMarker>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeEventsResponse {
    pub fn new(
        request: &DescribeEventsRequest,
        events: Vec<CacheEvent>,
        next_marker: Option<OpaqueMarker>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if events.len() > request.page_size() as usize || events.len() > crate::MAX_EVENTS {
            return Err(AwsElastiCacheError::PartialEvidence);
        }
        for event in &events {
            event.validate(request.scope())?;
        }
        validate_next_marker(
            next_marker.as_ref(),
            AwsElastiCacheOperation::DescribeEvents,
            request,
        )?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter_digest().clone(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            events,
            next_marker,
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_marker.is_some()
    }

    pub fn validate_integrity(
        &self,
        request: &DescribeEventsRequest,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != *request.filter_digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.is_native()
            || self.provenance.first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsElastiCacheError::TamperedEvidence);
        }
        for event in &self.events {
            event.validate(request.scope())?;
        }
        if let Some(marker) = &self.next_marker {
            marker.validate_for(
                AwsElastiCacheOperation::DescribeEvents.as_str(),
                request.scope(),
                request.filter_digest(),
                now,
            )?;
            if marker.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsElastiCacheError::MarkerMismatch);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-describe-events-response/v1",
            &[
                ("scope", self.scope_digest.to_string()),
                ("filter", self.filter_digest.to_string()),
                ("request", self.request_digest.to_string()),
                ("page", self.page_number.to_string()),
                (
                    "events",
                    self.events
                        .iter()
                        .map(CacheEvent::digest)
                        .map(|digest| digest.to_string())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("marker", marker_digest(self.next_marker.as_ref())),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeServiceUpdatesResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub service_updates: Vec<ServiceUpdateMetadata>,
    pub next_marker: Option<OpaqueMarker>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeServiceUpdatesResponse {
    pub fn new(
        request: &DescribeServiceUpdatesRequest,
        service_updates: Vec<ServiceUpdateMetadata>,
        next_marker: Option<OpaqueMarker>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if service_updates.len() > request.page_size() as usize
            || service_updates.len() > crate::MAX_SERVICE_UPDATES
        {
            return Err(AwsElastiCacheError::PartialEvidence);
        }
        for update in &service_updates {
            update.validate(request.scope())?;
        }
        validate_next_marker(
            next_marker.as_ref(),
            AwsElastiCacheOperation::DescribeServiceUpdates,
            request,
        )?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter_digest().clone(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            service_updates,
            next_marker,
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_marker.is_some()
    }

    pub fn validate_integrity(
        &self,
        request: &DescribeServiceUpdatesRequest,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != *request.filter_digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.is_native()
            || self.provenance.first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsElastiCacheError::TamperedEvidence);
        }
        for update in &self.service_updates {
            update.validate(request.scope())?;
        }
        if let Some(marker) = &self.next_marker {
            marker.validate_for(
                AwsElastiCacheOperation::DescribeServiceUpdates.as_str(),
                request.scope(),
                request.filter_digest(),
                now,
            )?;
            if marker.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsElastiCacheError::MarkerMismatch);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elasticache-describe-service-updates-response/v1",
            &[
                ("scope", self.scope_digest.to_string()),
                ("filter", self.filter_digest.to_string()),
                ("request", self.request_digest.to_string()),
                ("page", self.page_number.to_string()),
                (
                    "updates",
                    self.service_updates
                        .iter()
                        .map(ServiceUpdateMetadata::digest)
                        .map(|digest| digest.to_string())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("marker", marker_digest(self.next_marker.as_ref())),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug)]
pub struct AwsElastiCacheProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub api_digest: Digest,
    pub contract_version: String,
    pub release: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsElastiCacheProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() || release.len() > 128 {
            return Err(AwsElastiCacheError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "aws-elasticache-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let api_digest = Digest::from_parts(
            "aws-elasticache-api/v1",
            &[
                ("revision", API_REVISION.to_owned()),
                (
                    "operations",
                    [
                        AwsElastiCacheOperation::DescribeCacheClusters,
                        AwsElastiCacheOperation::DescribeReplicationGroups,
                        AwsElastiCacheOperation::DescribeEvents,
                        AwsElastiCacheOperation::DescribeServiceUpdates,
                    ]
                    .into_iter()
                    .map(AwsElastiCacheOperation::as_str)
                    .collect::<Vec<_>>()
                    .join("\n"),
                ),
            ],
        );
        let provider_digest = Digest::from_parts(
            "aws-elasticache-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", API_REVISION.to_owned()),
                ("api_digest", api_digest.to_string()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.to_string()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: API_REVISION.to_owned(),
            api_digest,
            contract_version: CONTRACT_VERSION.to_owned(),
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.provider_revision, self.release.clone())?;
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_revision != API_REVISION
            || self.api_digest != expected.api_digest
            || self.contract_version != CONTRACT_VERSION
            || self.release.is_empty()
            || self.connected
            || self.native
            || self.first_party
            || self.capability_digest != expected.capability_digest
            || self.provider_digest != expected.provider_digest
        {
            Err(AwsElastiCacheError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AwsElastiCacheProviderDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsElastiCacheProviderDefinition", 11)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("release", &self.release)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("connected", &false)?;
        state.serialize_field("native", &false)?;
        state.serialize_field("firstParty", &false)?;
        state.end()
    }
}

pub struct AwsElastiCacheProvider<T> {
    transport: T,
    definition: AwsElastiCacheProviderDefinition,
}

impl<T: AwsElastiCacheTransport> fmt::Debug for AwsElastiCacheProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsElastiCacheProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsElastiCacheTransport> AwsElastiCacheProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AwsElastiCacheProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn from_registration(
        registration: &AwsElastiCacheRegistration,
        transport: T,
    ) -> Result<Self> {
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(AwsElastiCacheError::ProviderDrift);
        }
        Ok(provider)
    }

    pub fn definition(&self) -> &AwsElastiCacheProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn describe_cache_clusters(
        &mut self,
        request: &DescribeCacheClustersRequest,
    ) -> std::result::Result<DescribeCacheClustersResponse, AwsElastiCacheTransportError> {
        let response = self.transport.describe_cache_clusters(request)?;
        response
            .validate_integrity(request, Utc::now())
            .map_err(map_response_validation_error)?;
        validate_provenance(response.provenance.clone(), self.provenance())?;
        Ok(response)
    }

    pub fn describe_replication_groups(
        &mut self,
        request: &DescribeReplicationGroupsRequest,
    ) -> std::result::Result<DescribeReplicationGroupsResponse, AwsElastiCacheTransportError> {
        let response = self.transport.describe_replication_groups(request)?;
        response
            .validate_integrity(request, Utc::now())
            .map_err(map_response_validation_error)?;
        validate_provenance(response.provenance.clone(), self.provenance())?;
        Ok(response)
    }

    pub fn describe_events(
        &mut self,
        request: &DescribeEventsRequest,
    ) -> std::result::Result<DescribeEventsResponse, AwsElastiCacheTransportError> {
        let response = self.transport.describe_events(request)?;
        response
            .validate_integrity(request, Utc::now())
            .map_err(map_response_validation_error)?;
        validate_provenance(response.provenance.clone(), self.provenance())?;
        Ok(response)
    }

    pub fn describe_service_updates(
        &mut self,
        request: &DescribeServiceUpdatesRequest,
    ) -> std::result::Result<DescribeServiceUpdatesResponse, AwsElastiCacheTransportError> {
        let response = self.transport.describe_service_updates(request)?;
        response
            .validate_integrity(request, Utc::now())
            .map_err(map_response_validation_error)?;
        validate_provenance(response.provenance.clone(), self.provenance())?;
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl Default for AwsElastiCacheProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked AWS ElastiCache provider definition")
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    cache_cluster_responses:
        VecDeque<std::result::Result<DescribeCacheClustersResponse, AwsElastiCacheTransportError>>,
    replication_group_responses: VecDeque<
        std::result::Result<DescribeReplicationGroupsResponse, AwsElastiCacheTransportError>,
    >,
    event_responses:
        VecDeque<std::result::Result<DescribeEventsResponse, AwsElastiCacheTransportError>>,
    service_update_responses:
        VecDeque<std::result::Result<DescribeServiceUpdatesResponse, AwsElastiCacheTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            cache_cluster_responses: VecDeque::new(),
            replication_group_responses: VecDeque::new(),
            event_responses: VecDeque::new(),
            service_update_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_cache_cluster_response(
        &mut self,
        response: std::result::Result<DescribeCacheClustersResponse, AwsElastiCacheTransportError>,
    ) {
        self.cache_cluster_responses.push_back(response);
    }

    pub fn push_replication_group_response(
        &mut self,
        response: std::result::Result<
            DescribeReplicationGroupsResponse,
            AwsElastiCacheTransportError,
        >,
    ) {
        self.replication_group_responses.push_back(response);
    }

    pub fn push_events_response(
        &mut self,
        response: std::result::Result<DescribeEventsResponse, AwsElastiCacheTransportError>,
    ) {
        self.event_responses.push_back(response);
    }

    pub fn push_service_updates_response(
        &mut self,
        response: std::result::Result<DescribeServiceUpdatesResponse, AwsElastiCacheTransportError>,
    ) {
        self.service_update_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl AwsElastiCacheTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance.clone()
    }

    fn describe_cache_clusters(
        &mut self,
        request: &DescribeCacheClustersRequest,
    ) -> std::result::Result<DescribeCacheClustersResponse, AwsElastiCacheTransportError> {
        self.requests.push(request.recorded_request());
        self.cache_cluster_responses
            .pop_front()
            .unwrap_or(Err(AwsElastiCacheTransportError::InvalidResponse))
    }

    fn describe_replication_groups(
        &mut self,
        request: &DescribeReplicationGroupsRequest,
    ) -> std::result::Result<DescribeReplicationGroupsResponse, AwsElastiCacheTransportError> {
        self.requests.push(request.recorded_request());
        self.replication_group_responses
            .pop_front()
            .unwrap_or(Err(AwsElastiCacheTransportError::InvalidResponse))
    }

    fn describe_events(
        &mut self,
        request: &DescribeEventsRequest,
    ) -> std::result::Result<DescribeEventsResponse, AwsElastiCacheTransportError> {
        self.requests.push(request.recorded_request());
        self.event_responses
            .pop_front()
            .unwrap_or(Err(AwsElastiCacheTransportError::InvalidResponse))
    }

    fn describe_service_updates(
        &mut self,
        request: &DescribeServiceUpdatesRequest,
    ) -> std::result::Result<DescribeServiceUpdatesResponse, AwsElastiCacheTransportError> {
        self.requests.push(request.recorded_request());
        self.service_update_responses
            .pop_front()
            .unwrap_or(Err(AwsElastiCacheTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsElastiCacheScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsElastiCacheScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn cluster(&self) -> Result<CacheClusterMetadata> {
        CacheClusterMetadata::for_scope(
            &self.scope,
            crate::model::HealthState::Healthy,
            crate::model::FailoverPosture::NotApplicable,
            crate::model::UpdatePosture::Current,
            1,
            self.observed_at,
            Some("fixture-status".to_owned()),
        )
    }

    fn group(&self) -> Result<ReplicationGroupMetadata> {
        ReplicationGroupMetadata::for_scope(
            &self.scope,
            crate::model::HealthState::Healthy,
            crate::model::FailoverPosture::Enabled,
            crate::model::UpdatePosture::Current,
            2,
            self.observed_at,
            Some("fixture-status".to_owned()),
        )
    }

    fn event(&self) -> Result<CacheEvent> {
        CacheEvent::new(
            &self.scope.resource,
            "fixture-event-1",
            "cache-health-observed",
            crate::model::EventSeverity::Info,
            self.observed_at,
            Some("fixture event body is digest-only".to_owned()),
        )
    }

    fn update(&self) -> Result<ServiceUpdateMetadata> {
        ServiceUpdateMetadata::new(
            &self.scope.resource,
            "fixture-update-1",
            crate::model::ServiceUpdateStatus::Complete,
            crate::model::EventSeverity::Info,
            crate::model::UpdatePosture::Current,
            Some(self.observed_at - Duration::days(1)),
            None,
            Some("fixture update description is digest-only".to_owned()),
        )
    }
}

impl AwsElastiCacheTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn describe_cache_clusters(
        &mut self,
        request: &DescribeCacheClustersRequest,
    ) -> std::result::Result<DescribeCacheClustersResponse, AwsElastiCacheTransportError> {
        let cluster = self
            .cluster()
            .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)?;
        DescribeCacheClustersResponse::new(
            request,
            vec![cluster],
            None,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)
    }

    fn describe_replication_groups(
        &mut self,
        request: &DescribeReplicationGroupsRequest,
    ) -> std::result::Result<DescribeReplicationGroupsResponse, AwsElastiCacheTransportError> {
        let group = self
            .group()
            .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)?;
        DescribeReplicationGroupsResponse::new(
            request,
            vec![group],
            None,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)
    }

    fn describe_events(
        &mut self,
        request: &DescribeEventsRequest,
    ) -> std::result::Result<DescribeEventsResponse, AwsElastiCacheTransportError> {
        let event = self
            .event()
            .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)?;
        DescribeEventsResponse::new(
            request,
            vec![event],
            None,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)
    }

    fn describe_service_updates(
        &mut self,
        request: &DescribeServiceUpdatesRequest,
    ) -> std::result::Result<DescribeServiceUpdatesResponse, AwsElastiCacheTransportError> {
        let update = self
            .update()
            .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)?;
        DescribeServiceUpdatesResponse::new(
            request,
            vec![update],
            None,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct FakeTransport {
    inner: FixtureTransport,
}

impl FakeTransport {
    pub fn for_scope(scope: &AwsElastiCacheScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AwsElastiCacheTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn describe_cache_clusters(
        &mut self,
        request: &DescribeCacheClustersRequest,
    ) -> std::result::Result<DescribeCacheClustersResponse, AwsElastiCacheTransportError> {
        let cluster = self
            .inner
            .cluster()
            .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)?;
        DescribeCacheClustersResponse::new(
            request,
            vec![cluster],
            None,
            512,
            TransportProvenance::Fake,
        )
        .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)
    }

    fn describe_replication_groups(
        &mut self,
        request: &DescribeReplicationGroupsRequest,
    ) -> std::result::Result<DescribeReplicationGroupsResponse, AwsElastiCacheTransportError> {
        let group = self
            .inner
            .group()
            .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)?;
        DescribeReplicationGroupsResponse::new(
            request,
            vec![group],
            None,
            512,
            TransportProvenance::Fake,
        )
        .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)
    }

    fn describe_events(
        &mut self,
        request: &DescribeEventsRequest,
    ) -> std::result::Result<DescribeEventsResponse, AwsElastiCacheTransportError> {
        let event = self
            .inner
            .event()
            .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)?;
        DescribeEventsResponse::new(request, vec![event], None, 512, TransportProvenance::Fake)
            .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)
    }

    fn describe_service_updates(
        &mut self,
        request: &DescribeServiceUpdatesRequest,
    ) -> std::result::Result<DescribeServiceUpdatesResponse, AwsElastiCacheTransportError> {
        let update = self
            .inner
            .update()
            .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)?;
        DescribeServiceUpdatesResponse::new(
            request,
            vec![update],
            None,
            512,
            TransportProvenance::Fake,
        )
        .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsElastiCacheScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AwsElastiCacheTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn describe_cache_clusters(
        &mut self,
        request: &DescribeCacheClustersRequest,
    ) -> std::result::Result<DescribeCacheClustersResponse, AwsElastiCacheTransportError> {
        let cluster = self
            .inner
            .cluster()
            .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)?;
        DescribeCacheClustersResponse::new(
            request,
            vec![cluster],
            None,
            512,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)
    }

    fn describe_replication_groups(
        &mut self,
        request: &DescribeReplicationGroupsRequest,
    ) -> std::result::Result<DescribeReplicationGroupsResponse, AwsElastiCacheTransportError> {
        let group = self
            .inner
            .group()
            .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)?;
        DescribeReplicationGroupsResponse::new(
            request,
            vec![group],
            None,
            512,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)
    }

    fn describe_events(
        &mut self,
        request: &DescribeEventsRequest,
    ) -> std::result::Result<DescribeEventsResponse, AwsElastiCacheTransportError> {
        let event = self
            .inner
            .event()
            .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)?;
        DescribeEventsResponse::new(
            request,
            vec![event],
            None,
            512,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)
    }

    fn describe_service_updates(
        &mut self,
        request: &DescribeServiceUpdatesRequest,
    ) -> std::result::Result<DescribeServiceUpdatesResponse, AwsElastiCacheTransportError> {
        let update = self
            .inner
            .update()
            .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)?;
        DescribeServiceUpdatesResponse::new(
            request,
            vec![update],
            None,
            512,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsElastiCacheTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

pub type RecordingAwsElastiCacheTransport = RecordingTransport;
pub type FixtureAwsElastiCacheTransport = FixtureTransport;
pub type FakeAwsElastiCacheTransport = FakeTransport;
pub type LoopbackAwsElastiCacheTransport = LoopbackTransport;

impl AwsElastiCacheTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn describe_cache_clusters(
        &mut self,
        _request: &DescribeCacheClustersRequest,
    ) -> std::result::Result<DescribeCacheClustersResponse, AwsElastiCacheTransportError> {
        Err(AwsElastiCacheTransportError::BlockedEnv)
    }

    fn describe_replication_groups(
        &mut self,
        _request: &DescribeReplicationGroupsRequest,
    ) -> std::result::Result<DescribeReplicationGroupsResponse, AwsElastiCacheTransportError> {
        Err(AwsElastiCacheTransportError::BlockedEnv)
    }

    fn describe_events(
        &mut self,
        _request: &DescribeEventsRequest,
    ) -> std::result::Result<DescribeEventsResponse, AwsElastiCacheTransportError> {
        Err(AwsElastiCacheTransportError::BlockedEnv)
    }

    fn describe_service_updates(
        &mut self,
        _request: &DescribeServiceUpdatesRequest,
    ) -> std::result::Result<DescribeServiceUpdatesResponse, AwsElastiCacheTransportError> {
        Err(AwsElastiCacheTransportError::BlockedEnv)
    }
}

pub fn transport_error_for_status(status_code: u16) -> AwsElastiCacheTransportError {
    match status_code {
        400 => AwsElastiCacheTransportError::BadRequest,
        401 => AwsElastiCacheTransportError::Unauthorized,
        403 => AwsElastiCacheTransportError::Forbidden,
        404 => AwsElastiCacheTransportError::NotFound,
        429 => AwsElastiCacheTransportError::RateLimited {
            retry_after_seconds: None,
        },
        500..=599 => AwsElastiCacheTransportError::ServerError {
            status: status_code,
        },
        _ => AwsElastiCacheTransportError::Unknown,
    }
}

fn request_digest(
    operation: AwsElastiCacheOperation,
    scope: &AwsElastiCacheScope,
    filter_digest: &Digest,
    marker: Option<&OpaqueMarker>,
) -> Digest {
    Digest::from_parts(
        "aws-elasticache-request/v1",
        &[
            ("operation", operation.as_str().to_owned()),
            ("scope", scope.digest().to_string()),
            ("filter", filter_digest.to_string()),
            ("marker", marker_digest(marker)),
            (
                "page",
                marker.map_or_else(|| "1".to_owned(), |value| value.page_number().to_string()),
            ),
        ],
    )
}

fn recorded_request(
    operation: AwsElastiCacheOperation,
    scope: &AwsElastiCacheScope,
    filter_digest: &Digest,
    marker: Option<&OpaqueMarker>,
    request_digest: &Digest,
) -> RecordedRequest {
    RecordedRequest {
        operation,
        scope_digest: scope.digest(),
        filter_digest: filter_digest.clone(),
        marker_digest: marker.map(OpaqueMarker::token_digest).cloned(),
        request_digest: request_digest.clone(),
        path_digest: Digest::from_parts(
            "aws-elasticache-redacted-path/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("scope", scope.digest().to_string()),
                ("filter", filter_digest.to_string()),
                ("marker", marker_digest(marker)),
            ],
        ),
    }
}

fn marker_digest(marker: Option<&OpaqueMarker>) -> String {
    marker.map_or_else(String::new, |value| value.token_digest().to_string())
}

fn validate_next_marker<R>(
    marker: Option<&OpaqueMarker>,
    operation: AwsElastiCacheOperation,
    request: &R,
) -> Result<()>
where
    R: RequestBinding,
{
    if let Some(marker) = marker {
        marker.validate_for(
            operation.as_str(),
            request.scope_binding(),
            request.filter_binding(),
            Utc::now(),
        )?;
        if marker.page_number() != request.page_binding().saturating_add(1) {
            return Err(AwsElastiCacheError::MarkerMismatch);
        }
    }
    Ok(())
}

trait RequestBinding {
    fn scope_binding(&self) -> &AwsElastiCacheScope;
    fn filter_binding(&self) -> &Digest;
    fn page_binding(&self) -> u16;
}

macro_rules! request_binding {
    ($type:ty) => {
        impl RequestBinding for $type {
            fn scope_binding(&self) -> &AwsElastiCacheScope {
                self.scope()
            }

            fn filter_binding(&self) -> &Digest {
                self.filter_digest()
            }

            fn page_binding(&self) -> u16 {
                self.page_number()
            }
        }
    };
}

request_binding!(DescribeCacheClustersRequest);
request_binding!(DescribeReplicationGroupsRequest);
request_binding!(DescribeEventsRequest);
request_binding!(DescribeServiceUpdatesRequest);

fn validate_provenance(
    response_provenance: TransportProvenance,
    expected: TransportProvenance,
) -> std::result::Result<(), AwsElastiCacheTransportError> {
    if response_provenance != expected
        || response_provenance.connected()
        || response_provenance.is_native()
        || response_provenance.first_party()
    {
        Err(AwsElastiCacheTransportError::InvalidResponse)
    } else {
        Ok(())
    }
}

fn map_response_validation_error(error: AwsElastiCacheError) -> AwsElastiCacheTransportError {
    match error {
        AwsElastiCacheError::MarkerExpired => AwsElastiCacheTransportError::ExpiredMarker,
        AwsElastiCacheError::PartialEvidence => AwsElastiCacheTransportError::Partial,
        _ => AwsElastiCacheTransportError::InvalidResponse,
    }
}
