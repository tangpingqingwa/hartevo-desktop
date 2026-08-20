//! Redacted, deterministic ELBv2 provider boundary.
//!
//! The provider exposes only the three allowlisted read operations.  It does
//! not own HTTP, SigV4, credential resolution, or any ELB mutation.  Fixture,
//! recording, loopback, and `BLOCKED_ENV` transports are intentionally marked
//! disconnected, non-native, and non-first-party.

use std::{collections::VecDeque, fmt};

use chrono::Utc;
use serde::Serialize;
use thiserror::Error;

use crate::model::{
    AwsElbReadRequest, AwsElbScope, DescribeLoadBalancersRequest, DescribeTargetGroupsRequest,
    DescribeTargetHealthRequest, Digest, ElbProtocol, EvidenceState, HealthCheckSummary,
    LoadBalancerScheme, LoadBalancerState, LoadBalancerSummary, LoadBalancerType,
    MAX_LOAD_BALANCERS, MAX_PAGES, MAX_RESPONSE_BYTES, MAX_TARGET_GROUPS, MAX_TARGETS,
    OpaqueMarker, ProviderProvenance, ReadOperation, TargetGroupState, TargetGroupSummary,
    TargetHealthCollectionState, TargetHealthObservation, TargetHealthState, TransportError,
    TransportFailure,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("AWS ELB provider definition is invalid")]
    Invalid,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    #[error("AWS ELB transport failed")]
    Transport(TransportError),
    #[error("AWS ELB provider request operation does not match the endpoint")]
    RequestMismatch,
    #[error("AWS ELB provider scope binding does not match the request")]
    ScopeMismatch,
    #[error("AWS ELB provider target-group binding does not match the request")]
    TargetGroupMismatch,
    #[error("AWS ELB provider page digest is invalid")]
    PageTampered,
    #[error("AWS ELB provider response exceeded the bounded byte budget")]
    ResponseTooLarge,
    #[error("AWS ELB provider page number is outside the bounded page budget")]
    PageBudget,
    #[error("AWS ELB provider page marker was replayed")]
    MarkerReplay,
    #[error("AWS ELB provider does not support this operation")]
    UnsupportedOperation,
}

impl ProviderError {
    pub const fn failure(&self) -> Option<TransportFailure> {
        match self {
            Self::Transport(error) => Some(error.failure),
            _ => None,
        }
    }

    pub const fn evidence_state(&self) -> EvidenceState {
        match self {
            Self::Transport(error) => error.failure.evidence_state(),
            Self::ResponseTooLarge | Self::PageBudget => EvidenceState::Partial,
            Self::MarkerReplay => EvidenceState::Replay,
            Self::PageTampered => EvidenceState::Tampered,
            Self::ScopeMismatch => EvidenceState::ScopeDrift,
            Self::TargetGroupMismatch => EvidenceState::TargetGroupDrift,
            Self::RequestMismatch | Self::UnsupportedOperation => EvidenceState::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElbProviderDefinition {
    pub id: String,
    pub version: String,
    pub api_revision: String,
    pub operations: [ReadOperation; 3],
    pub provider_digest: Digest,
    pub api_digest: Digest,
}

impl AwsElbProviderDefinition {
    pub fn baseline() -> Self {
        let operations = [
            ReadOperation::DescribeLoadBalancers,
            ReadOperation::DescribeTargetGroups,
            ReadOperation::DescribeTargetHealth,
        ];
        let id = crate::PROVIDER_ID.to_owned();
        let version = crate::PROVIDER_VERSION.to_owned();
        let api_revision = crate::PROVIDER_API_REVISION.to_owned();
        let provider_digest = Digest::from_parts(
            "aws-elb-provider/v1",
            &[
                ("id", id.clone()),
                ("version", version.clone()),
                ("api_revision", api_revision.clone()),
                (
                    "operations",
                    operations
                        .iter()
                        .map(|operation| operation.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        let api_digest = Digest::from_text(api_revision.clone());
        Self {
            id,
            version,
            api_revision,
            operations,
            provider_digest,
            api_digest,
        }
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        let expected = Self::baseline();
        if self != &expected {
            Err(ProviderDefinitionError::Invalid)
        } else {
            Ok(())
        }
    }
}

pub type AwsElbProviderIdentity = AwsElbProviderDefinition;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeLoadBalancersPage {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub page_number: u16,
    pub load_balancers: Vec<LoadBalancerSummary>,
    pub next_marker: Option<OpaqueMarker>,
    pub response_bytes: usize,
    pub provider_revision: String,
    pub page_digest: Digest,
}

impl DescribeLoadBalancersPage {
    pub fn new(
        request: &DescribeLoadBalancersRequest,
        page_number: u16,
        load_balancers: Vec<LoadBalancerSummary>,
        next_marker: Option<OpaqueMarker>,
        response_bytes: usize,
    ) -> Result<Self, ProviderError> {
        if request.operation != ReadOperation::DescribeLoadBalancers {
            return Err(ProviderError::RequestMismatch);
        }
        if page_number == 0 || page_number > MAX_PAGES || load_balancers.len() > MAX_LOAD_BALANCERS
        {
            return Err(ProviderError::PageBudget);
        }
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge);
        }
        let mut value = Self {
            request_digest: request.request_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            page_number,
            load_balancers,
            next_marker,
            response_bytes,
            provider_revision: crate::PROVIDER_API_REVISION.to_owned(),
            page_digest: Digest::zero(),
        };
        value.page_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn validate(&self, request: &DescribeLoadBalancersRequest) -> Result<(), ProviderError> {
        if request.operation != ReadOperation::DescribeLoadBalancers {
            return Err(ProviderError::RequestMismatch);
        }
        if self.request_digest != request.request_digest
            || self.scope_digest != request.scope_digest
        {
            return Err(ProviderError::ScopeMismatch);
        }
        if self.page_number != request.page_number
            || self.page_number == 0
            || self.page_number > request.max_pages
        {
            return Err(ProviderError::PageBudget);
        }
        if self.response_bytes > MAX_RESPONSE_BYTES
            || self.load_balancers.len() > MAX_LOAD_BALANCERS
            || self.provider_revision != crate::PROVIDER_API_REVISION
            || self.load_balancers.iter().any(|load_balancer| {
                load_balancer.summary_digest != load_balancer.recomputed_digest()
            })
        {
            return Err(ProviderError::PageTampered);
        }
        if self.page_digest != self.recomputed_digest() {
            return Err(ProviderError::PageTampered);
        }
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&(
            &self.request_digest,
            &self.scope_digest,
            self.page_number,
            &self.load_balancers,
            &self.next_marker,
            self.response_bytes,
            &self.provider_revision,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeTargetGroupsPage {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub page_number: u16,
    pub target_groups: Vec<TargetGroupSummary>,
    pub next_marker: Option<OpaqueMarker>,
    pub response_bytes: usize,
    pub provider_revision: String,
    pub page_digest: Digest,
}

impl DescribeTargetGroupsPage {
    pub fn new(
        request: &DescribeTargetGroupsRequest,
        page_number: u16,
        target_groups: Vec<TargetGroupSummary>,
        next_marker: Option<OpaqueMarker>,
        response_bytes: usize,
    ) -> Result<Self, ProviderError> {
        if request.operation != ReadOperation::DescribeTargetGroups {
            return Err(ProviderError::RequestMismatch);
        }
        if page_number == 0 || page_number > MAX_PAGES || target_groups.len() > MAX_TARGET_GROUPS {
            return Err(ProviderError::PageBudget);
        }
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge);
        }
        let mut value = Self {
            request_digest: request.request_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            page_number,
            target_groups,
            next_marker,
            response_bytes,
            provider_revision: crate::PROVIDER_API_REVISION.to_owned(),
            page_digest: Digest::zero(),
        };
        value.page_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn validate(&self, request: &DescribeTargetGroupsRequest) -> Result<(), ProviderError> {
        if request.operation != ReadOperation::DescribeTargetGroups {
            return Err(ProviderError::RequestMismatch);
        }
        if self.request_digest != request.request_digest
            || self.scope_digest != request.scope_digest
        {
            return Err(ProviderError::ScopeMismatch);
        }
        if self.page_number != request.page_number
            || self.page_number == 0
            || self.page_number > request.max_pages
        {
            return Err(ProviderError::PageBudget);
        }
        if self.response_bytes > MAX_RESPONSE_BYTES
            || self.target_groups.len() > MAX_TARGET_GROUPS
            || self.provider_revision != crate::PROVIDER_API_REVISION
            || self.target_groups.iter().any(|target_group| {
                target_group.summary_digest != target_group.recomputed_digest()
                    || target_group.health_check.summary_digest
                        != target_group.health_check.recomputed_digest()
            })
        {
            return Err(ProviderError::PageTampered);
        }
        if self.page_digest != self.recomputed_digest() {
            return Err(ProviderError::PageTampered);
        }
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&(
            &self.request_digest,
            &self.scope_digest,
            self.page_number,
            &self.target_groups,
            &self.next_marker,
            self.response_bytes,
            &self.provider_revision,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeTargetHealthPage {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub target_group_digest: Digest,
    pub target_group_revision: crate::model::Revision,
    pub observations: Vec<TargetHealthObservation>,
    pub collection_state: TargetHealthCollectionState,
    pub observed_at: chrono::DateTime<Utc>,
    pub response_bytes: usize,
    pub provider_revision: String,
    pub page_digest: Digest,
}

impl DescribeTargetHealthPage {
    pub fn new(
        request: &DescribeTargetHealthRequest,
        target_group_revision: crate::model::Revision,
        observations: Vec<TargetHealthObservation>,
        collection_state: TargetHealthCollectionState,
        response_bytes: usize,
    ) -> Result<Self, ProviderError> {
        Self::with_observed_at(
            request,
            target_group_revision,
            observations,
            collection_state,
            Utc::now(),
            response_bytes,
        )
    }

    pub fn with_observed_at(
        request: &DescribeTargetHealthRequest,
        target_group_revision: crate::model::Revision,
        observations: Vec<TargetHealthObservation>,
        collection_state: TargetHealthCollectionState,
        observed_at: chrono::DateTime<Utc>,
        response_bytes: usize,
    ) -> Result<Self, ProviderError> {
        if request.operation != ReadOperation::DescribeTargetHealth {
            return Err(ProviderError::RequestMismatch);
        }
        if observations.len() > MAX_TARGETS {
            return Err(ProviderError::PageBudget);
        }
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge);
        }
        let mut value = Self {
            request_digest: request.request_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            target_group_digest: request.target_group_digest.clone(),
            target_group_revision,
            observations,
            collection_state,
            observed_at,
            response_bytes,
            provider_revision: crate::PROVIDER_API_REVISION.to_owned(),
            page_digest: Digest::zero(),
        };
        value.page_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn validate(&self, request: &DescribeTargetHealthRequest) -> Result<(), ProviderError> {
        if request.operation != ReadOperation::DescribeTargetHealth {
            return Err(ProviderError::RequestMismatch);
        }
        if self.request_digest != request.request_digest
            || self.scope_digest != request.scope_digest
            || self.target_group_digest != request.target_group_digest
        {
            return Err(ProviderError::TargetGroupMismatch);
        }
        if self.response_bytes > MAX_RESPONSE_BYTES
            || self.observations.len() > MAX_TARGETS
            || self.provider_revision != crate::PROVIDER_API_REVISION
            || self.observations.iter().any(|observation| {
                observation.observation_digest != observation.recomputed_digest()
            })
        {
            return Err(ProviderError::PageTampered);
        }
        if self.page_digest != self.recomputed_digest() {
            return Err(ProviderError::PageTampered);
        }
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&(
            &self.request_digest,
            &self.scope_digest,
            &self.target_group_digest,
            self.target_group_revision,
            &self.observations,
            self.collection_state,
            self.observed_at,
            self.response_bytes,
            &self.provider_revision,
        ))
    }
}

pub trait AwsElbTransport: Clone + fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn describe_load_balancers(
        &mut self,
        request: &DescribeLoadBalancersRequest,
    ) -> Result<DescribeLoadBalancersPage, TransportError>;

    fn describe_target_groups(
        &mut self,
        request: &DescribeTargetGroupsRequest,
    ) -> Result<DescribeTargetGroupsPage, TransportError>;

    fn describe_target_health(
        &mut self,
        request: &DescribeTargetHealthRequest,
    ) -> Result<DescribeTargetHealthPage, TransportError>;
}

#[derive(Clone, Debug)]
pub struct AwsElbProvider<T>
where
    T: AwsElbTransport,
{
    transport: T,
    definition: AwsElbProviderDefinition,
}

impl<T> AwsElbProvider<T>
where
    T: AwsElbTransport,
{
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let definition = AwsElbProviderDefinition::baseline();
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn identity(&self) -> &AwsElbProviderDefinition {
        &self.definition
    }

    pub fn definition(&self) -> &AwsElbProviderDefinition {
        self.identity()
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn describe_load_balancers(
        &mut self,
        request: &DescribeLoadBalancersRequest,
    ) -> Result<DescribeLoadBalancersPage, ProviderError> {
        let page = self
            .transport
            .describe_load_balancers(request)
            .map_err(ProviderError::Transport)?;
        page.validate(request)?;
        Ok(page)
    }

    pub fn describe_target_groups(
        &mut self,
        request: &DescribeTargetGroupsRequest,
    ) -> Result<DescribeTargetGroupsPage, ProviderError> {
        let page = self
            .transport
            .describe_target_groups(request)
            .map_err(ProviderError::Transport)?;
        page.validate(request)?;
        Ok(page)
    }

    pub fn describe_target_health(
        &mut self,
        request: &DescribeTargetHealthRequest,
    ) -> Result<DescribeTargetHealthPage, ProviderError> {
        let page = self
            .transport
            .describe_target_health(request)
            .map_err(ProviderError::Transport)?;
        page.validate(request)?;
        Ok(page)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    load_balancers: VecDeque<Result<DescribeLoadBalancersPage, TransportError>>,
    target_groups: VecDeque<Result<DescribeTargetGroupsPage, TransportError>>,
    target_health: VecDeque<Result<DescribeTargetHealthPage, TransportError>>,
    request_digests: Vec<Digest>,
}

impl RecordingTransport {
    pub fn push_load_balancers(
        &mut self,
        response: Result<DescribeLoadBalancersPage, TransportError>,
    ) {
        self.load_balancers.push_back(response);
    }

    pub fn queue_describe_load_balancers(
        &mut self,
        response: Result<DescribeLoadBalancersPage, TransportError>,
    ) {
        self.push_load_balancers(response);
    }

    pub fn push_target_groups(
        &mut self,
        response: Result<DescribeTargetGroupsPage, TransportError>,
    ) {
        self.target_groups.push_back(response);
    }

    pub fn queue_describe_target_groups(
        &mut self,
        response: Result<DescribeTargetGroupsPage, TransportError>,
    ) {
        self.push_target_groups(response);
    }

    pub fn push_target_health(
        &mut self,
        response: Result<DescribeTargetHealthPage, TransportError>,
    ) {
        self.target_health.push_back(response);
    }

    pub fn queue_describe_target_health(
        &mut self,
        response: Result<DescribeTargetHealthPage, TransportError>,
    ) {
        self.push_target_health(response);
    }

    pub fn request_digests(&self) -> &[Digest] {
        &self.request_digests
    }

    pub fn requests(&self) -> &[Digest] {
        self.request_digests()
    }

    fn record(&mut self, request: &AwsElbReadRequest) {
        self.request_digests.push(request.request_digest.clone());
    }

    fn no_response() -> Result<DescribeLoadBalancersPage, TransportError> {
        Err(TransportError::new(TransportFailure::ProviderUnknown))
    }
}

impl AwsElbTransport for RecordingTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Recording
    }

    fn describe_load_balancers(
        &mut self,
        request: &DescribeLoadBalancersRequest,
    ) -> Result<DescribeLoadBalancersPage, TransportError> {
        self.record(request);
        self.load_balancers
            .pop_front()
            .unwrap_or_else(Self::no_response)
    }

    fn describe_target_groups(
        &mut self,
        request: &DescribeTargetGroupsRequest,
    ) -> Result<DescribeTargetGroupsPage, TransportError> {
        self.record(request);
        self.target_groups
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::new(TransportFailure::ProviderUnknown)))
    }

    fn describe_target_health(
        &mut self,
        request: &DescribeTargetHealthRequest,
    ) -> Result<DescribeTargetHealthPage, TransportError> {
        self.record(request);
        self.target_health
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::new(TransportFailure::ProviderUnknown)))
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureTransport {
    inner: RecordingTransport,
}

impl FixtureTransport {
    pub fn fixture() -> Self {
        Self::default()
    }

    pub fn for_scope(
        scope: &AwsElbScope,
        observed_at: chrono::DateTime<Utc>,
    ) -> Result<Self, ProviderError> {
        let load_balancer_name = crate::model::LoadBalancerName::aws("fixture-elb")
            .map_err(|_| ProviderError::RequestMismatch)?;
        let target_group_name = crate::model::TargetGroupName::aws("fixture-targets")
            .map_err(|_| ProviderError::RequestMismatch)?;
        let health_check = HealthCheckSummary::new(
            ElbProtocol::Http,
            Some(80),
            Some("/health"),
            30,
            5,
            3,
            3,
            Some("200"),
        )
        .map_err(|_| ProviderError::RequestMismatch)?;
        let lb = LoadBalancerSummary::new(
            &scope.load_balancer.arn,
            &load_balancer_name,
            LoadBalancerType::Application,
            LoadBalancerScheme::InternetFacing,
            LoadBalancerState::Active,
            scope.load_balancer.revision,
        );
        let lb = scope
            .availability_zones
            .as_ref()
            .map_or(lb.clone(), |zones| {
                lb.with_availability_zones(zones.clone())
            });
        let tg = TargetGroupSummary::new(
            &scope.target_group.arn,
            &target_group_name,
            scope.target_group.target_group_type,
            ElbProtocol::Http,
            Some(80),
            TargetGroupState::Active,
            [scope.load_balancer.arn.clone()],
            health_check,
            scope.target_group.revision,
        );
        let observation = TargetHealthObservation::new(
            "fixture-target-1",
            Some(80),
            TargetHealthState::Healthy,
            crate::model::TargetHealthReasonClass::None,
            Some("fixture health detail is hashed"),
            observed_at,
        )
        .map_err(|_| ProviderError::RequestMismatch)?;
        let observation = scope
            .availability_zones
            .as_ref()
            .and_then(|zones| zones.iter().next())
            .map_or(observation.clone(), |zone| {
                observation.with_availability_zone(zone)
            });
        let mut transport = Self::default();
        let bounds = crate::model::ReadBounds::default();
        let lb_request = AwsElbReadRequest::describe_load_balancers(scope, bounds, None)
            .map_err(|_| ProviderError::RequestMismatch)?;
        transport
            .inner
            .push_load_balancers(Ok(DescribeLoadBalancersPage::new(
                &lb_request,
                1,
                vec![lb],
                None,
                512,
            )?));
        let tg_request = AwsElbReadRequest::describe_target_groups(scope, bounds, None)
            .map_err(|_| ProviderError::RequestMismatch)?;
        transport
            .inner
            .push_target_groups(Ok(DescribeTargetGroupsPage::new(
                &tg_request,
                1,
                vec![tg],
                None,
                768,
            )?));
        let health_request = AwsElbReadRequest::describe_target_health(scope, bounds)
            .map_err(|_| ProviderError::RequestMismatch)?;
        transport
            .inner
            .push_target_health(Ok(DescribeTargetHealthPage::with_observed_at(
                &health_request,
                scope.target_group.revision,
                vec![observation],
                TargetHealthCollectionState::Fresh,
                observed_at,
                512,
            )?));
        Ok(transport)
    }

    pub fn push_load_balancers(
        &mut self,
        response: Result<DescribeLoadBalancersPage, TransportError>,
    ) {
        self.inner.push_load_balancers(response);
    }

    pub fn push_target_groups(
        &mut self,
        response: Result<DescribeTargetGroupsPage, TransportError>,
    ) {
        self.inner.push_target_groups(response);
    }

    pub fn push_target_health(
        &mut self,
        response: Result<DescribeTargetHealthPage, TransportError>,
    ) {
        self.inner.push_target_health(response);
    }

    pub fn request_digests(&self) -> &[Digest] {
        self.inner.request_digests()
    }
}

impl AwsElbTransport for FixtureTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn describe_load_balancers(
        &mut self,
        request: &DescribeLoadBalancersRequest,
    ) -> Result<DescribeLoadBalancersPage, TransportError> {
        self.inner.describe_load_balancers(request)
    }

    fn describe_target_groups(
        &mut self,
        request: &DescribeTargetGroupsRequest,
    ) -> Result<DescribeTargetGroupsPage, TransportError> {
        self.inner.describe_target_groups(request)
    }

    fn describe_target_health(
        &mut self,
        request: &DescribeTargetHealthRequest,
    ) -> Result<DescribeTargetHealthPage, TransportError> {
        self.inner.describe_target_health(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(
        scope: &AwsElbScope,
        observed_at: chrono::DateTime<Utc>,
    ) -> Result<Self, ProviderError> {
        Ok(Self {
            inner: FixtureTransport::for_scope(scope, observed_at)?,
        })
    }

    pub fn request_digests(&self) -> &[Digest] {
        self.inner.request_digests()
    }
}

impl AwsElbTransport for LoopbackTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn describe_load_balancers(
        &mut self,
        request: &DescribeLoadBalancersRequest,
    ) -> Result<DescribeLoadBalancersPage, TransportError> {
        self.inner.describe_load_balancers(request)
    }

    fn describe_target_groups(
        &mut self,
        request: &DescribeTargetGroupsRequest,
    ) -> Result<DescribeTargetGroupsPage, TransportError> {
        self.inner.describe_target_groups(request)
    }

    fn describe_target_health(
        &mut self,
        request: &DescribeTargetHealthRequest,
    ) -> Result<DescribeTargetHealthPage, TransportError> {
        self.inner.describe_target_health(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsElbTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn describe_load_balancers(
        &mut self,
        _request: &DescribeLoadBalancersRequest,
    ) -> Result<DescribeLoadBalancersPage, TransportError> {
        Err(TransportError::new(TransportFailure::ProviderUnknown))
    }

    fn describe_target_groups(
        &mut self,
        _request: &DescribeTargetGroupsRequest,
    ) -> Result<DescribeTargetGroupsPage, TransportError> {
        Err(TransportError::new(TransportFailure::ProviderUnknown))
    }

    fn describe_target_health(
        &mut self,
        _request: &DescribeTargetHealthRequest,
    ) -> Result<DescribeTargetHealthPage, TransportError> {
        Err(TransportError::new(TransportFailure::ProviderUnknown))
    }
}

pub type FakeTransport = RecordingTransport;
pub type FixtureAwsElbTransport = FixtureTransport;
pub type RecordingAwsElbTransport = RecordingTransport;
pub type LoopbackAwsElbTransport = LoopbackTransport;
pub type BlockedEnvAwsElbTransport = BlockedEnvTransport;
pub type AwsElbTransportError = TransportError;
pub type AwsElbProviderError = ProviderError;

pub fn is_access_loss(error: &ProviderError) -> bool {
    matches!(
        error.failure(),
        Some(
            TransportFailure::Unauthorized
                | TransportFailure::Forbidden
                | TransportFailure::NotFound
        )
    )
}

pub fn is_timeout(error: &ProviderError) -> bool {
    matches!(error.failure(), Some(TransportFailure::Timeout))
}

pub fn is_throttle(error: &ProviderError) -> bool {
    matches!(error.failure(), Some(TransportFailure::Throttled))
}

#[allow(dead_code)]
fn _keep_provider_surface_typed() {
    let _ = (
        MAX_PAGES,
        MAX_RESPONSE_BYTES,
        MAX_LOAD_BALANCERS,
        MAX_TARGET_GROUPS,
        MAX_TARGETS,
    );
}
