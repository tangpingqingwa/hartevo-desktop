use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};

use crate::error::{NomadDeploymentResultError, NomadTransportError, Result};
use crate::model::{
    Digest, MAX_METADATA_ITEMS, MAX_RESPONSE_BYTES, NomadAddress, NomadAllocationId,
    NomadAllocationProjection, NomadAllocationStatus, NomadDatacenter, NomadDeploymentId,
    NomadDeploymentProjection, NomadDeploymentScope, NomadDeploymentState, NomadDeploymentStatus,
    NomadJobId, NomadJobProjection, NomadJobState, NomadReadOperation, NomadReadRequest,
    ProviderProvenance, SecretReference,
};

/// Official Nomad metadata paths used by this Layer-1 provider.
pub const JOB_METADATA_PATH: &str = "/v1/job/{jobID}";
pub const DEPLOYMENT_METADATA_PATH: &str = "/v1/deployment/{deploymentID}";
pub const ALLOCATION_METADATA_PATH: &str = "/v1/allocation/{allocationID}";

/// A response used by deterministic transports. The body is private so raw
/// provider payloads cannot accidentally cross a serialized evidence boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct NomadApiResponse {
    status: u16,
    body: Vec<u8>,
    body_digest: Digest,
}

impl fmt::Debug for NomadApiResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NomadApiResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .field("body_digest", &self.body_digest)
            .finish()
    }
}

impl NomadApiResponse {
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        let body_digest = Digest::from_bytes(&body);
        Self {
            status,
            body,
            body_digest,
        }
    }

    pub fn json<T: Serialize>(status: u16, value: &T) -> Result<Self> {
        let body =
            serde_json::to_vec(value).map_err(|_| NomadDeploymentResultError::InvalidResponse)?;
        Ok(Self::new(status, body))
    }

    #[must_use]
    pub fn with_digest(status: u16, body: Vec<u8>, body_digest: Digest) -> Self {
        Self {
            status,
            body,
            body_digest,
        }
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn body_digest(&self) -> &Digest {
        &self.body_digest
    }

    pub fn validate_size_and_digest(&self) -> Result<()> {
        if self.body.len() > MAX_RESPONSE_BYTES
            || self.body_digest != Digest::from_bytes(&self.body)
        {
            return Err(NomadDeploymentResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn body(&self) -> &[u8] {
        &self.body
    }
}

/// A deliberately small wire representation. Unknown Nomad fields are
/// ignored; only bounded metadata is projected below.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NomadWireJob {
    #[serde(rename = "ID", alias = "id")]
    pub id: String,
    #[serde(rename = "Namespace", alias = "namespace", default)]
    pub namespace: String,
    #[serde(rename = "Region", alias = "region", default)]
    pub region: String,
    #[serde(rename = "Status", alias = "status", default)]
    pub status: String,
    #[serde(rename = "Version", alias = "version", default)]
    pub version: u64,
    #[serde(rename = "CreateIndex", alias = "createIndex", default)]
    pub create_index: u64,
    #[serde(rename = "ModifyIndex", alias = "modifyIndex", default)]
    pub modify_index: u64,
    #[serde(rename = "Datacenters", alias = "datacenters", default)]
    pub datacenters: Vec<String>,
    #[serde(rename = "TaskGroups", alias = "taskGroups", default)]
    pub task_groups: Vec<NomadWireTaskGroup>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NomadWireTaskGroup {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NomadWireDeployment {
    #[serde(rename = "ID", alias = "id")]
    pub id: String,
    #[serde(rename = "JobID", alias = "jobId", default)]
    pub job_id: String,
    #[serde(rename = "JobVersion", alias = "jobVersion", default)]
    pub job_version: u64,
    #[serde(rename = "Status", alias = "status", default)]
    pub status: String,
    #[serde(rename = "DesiredTotal", alias = "desiredTotal", default)]
    pub desired_total: u16,
    #[serde(rename = "PlacedAllocs", alias = "placedAllocs", default)]
    pub placed_allocations: u16,
    #[serde(rename = "HealthyAllocs", alias = "healthyAllocs", default)]
    pub healthy_allocations: u16,
    #[serde(rename = "UnhealthyAllocs", alias = "unhealthyAllocs", default)]
    pub unhealthy_allocations: u16,
    #[serde(rename = "CreateIndex", alias = "createIndex", default)]
    pub create_index: u64,
    #[serde(rename = "ModifyIndex", alias = "modifyIndex", default)]
    pub modify_index: u64,
    #[serde(rename = "Namespace", alias = "namespace", default)]
    pub namespace: String,
    #[serde(rename = "Region", alias = "region", default)]
    pub region: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NomadWireAllocation {
    #[serde(rename = "ID", alias = "id")]
    pub id: String,
    #[serde(rename = "JobID", alias = "jobId", default)]
    pub job_id: String,
    #[serde(rename = "DeploymentID", alias = "deploymentId", default)]
    pub deployment_id: Option<String>,
    #[serde(rename = "NodeID", alias = "nodeId", default)]
    pub node_id: Option<String>,
    #[serde(rename = "TaskGroup", alias = "taskGroup", default)]
    pub task_group: String,
    #[serde(rename = "DesiredStatus", alias = "desiredStatus", default)]
    pub desired_status: String,
    #[serde(rename = "ClientStatus", alias = "clientStatus", default)]
    pub client_status: String,
    #[serde(rename = "CreateIndex", alias = "createIndex", default)]
    pub create_index: u64,
    #[serde(rename = "ModifyIndex", alias = "modifyIndex", default)]
    pub modify_index: u64,
    #[serde(rename = "Namespace", alias = "namespace", default)]
    pub namespace: String,
    #[serde(rename = "Region", alias = "region", default)]
    pub region: String,
}

/// Transport is intentionally narrower than a Nomad client. It only accepts
/// the three typed GET metadata requests and has no write method.
pub trait NomadTransport: fmt::Debug + Send {
    fn execute(
        &mut self,
        request: &NomadReadRequest,
    ) -> std::result::Result<NomadApiResponse, NomadTransportError>;

    fn provenance(&self) -> ProviderProvenance;

    fn requests(&self) -> &[NomadReadRequest];
}

#[derive(Clone, Debug)]
struct QueuedTransport {
    responses: VecDeque<std::result::Result<NomadApiResponse, NomadTransportError>>,
    requests: Vec<NomadReadRequest>,
    provenance: ProviderProvenance,
}

impl QueuedTransport {
    fn new<I>(responses: I, provenance: ProviderProvenance) -> Self
    where
        I: IntoIterator<Item = NomadApiResponse>,
    {
        Self {
            responses: responses.into_iter().map(Ok).collect(),
            requests: Vec::new(),
            provenance,
        }
    }

    fn from_results<I>(responses: I, provenance: ProviderProvenance) -> Self
    where
        I: IntoIterator<Item = std::result::Result<NomadApiResponse, NomadTransportError>>,
    {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance,
        }
    }

    fn execute(
        &mut self,
        request: &NomadReadRequest,
    ) -> std::result::Result<NomadApiResponse, NomadTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(NomadTransportError::ProviderUnknown))
    }
}

macro_rules! queued_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            inner: QueuedTransport,
        }

        impl $name {
            pub fn new<I>(responses: I) -> Self
            where
                I: IntoIterator<Item = NomadApiResponse>,
            {
                Self {
                    inner: QueuedTransport::new(responses, $provenance),
                }
            }

            pub fn from_results<I>(responses: I) -> Self
            where
                I: IntoIterator<Item = std::result::Result<NomadApiResponse, NomadTransportError>>,
            {
                Self {
                    inner: QueuedTransport::from_results(responses, $provenance),
                }
            }

            #[must_use]
            pub fn requests(&self) -> &[NomadReadRequest] {
                &self.inner.requests
            }

            #[must_use]
            pub fn provenance(&self) -> ProviderProvenance {
                self.inner.provenance
            }
        }

        impl NomadTransport for $name {
            fn execute(
                &mut self,
                request: &NomadReadRequest,
            ) -> std::result::Result<NomadApiResponse, NomadTransportError> {
                self.inner.execute(request)
            }

            fn provenance(&self) -> ProviderProvenance {
                self.inner.provenance
            }

            fn requests(&self) -> &[NomadReadRequest] {
                &self.inner.requests
            }
        }
    };
}

queued_transport!(NomadRecordingTransport, ProviderProvenance::Recording);
queued_transport!(FixtureNomadTransport, ProviderProvenance::Fixture);
queued_transport!(FakeNomadTransport, ProviderProvenance::Fake);
queued_transport!(LoopbackNomadTransport, ProviderProvenance::Loopback);

impl NomadRecordingTransport {
    pub fn fixture<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = NomadApiResponse>,
    {
        FixtureNomadTransport::new(responses).into_recording_shape()
    }

    pub fn recording<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = NomadApiResponse>,
    {
        Self::new(responses)
    }
}

impl FixtureNomadTransport {
    fn into_recording_shape(self) -> NomadRecordingTransport {
        NomadRecordingTransport { inner: self.inner }
    }
}

/// Compatibility alias used by the sibling Layer-1 plugin tests.
pub type RecordingTransport = NomadRecordingTransport;
pub type RecordingNomadTransport = NomadRecordingTransport;
pub type NomadFixtureTransport = FixtureNomadTransport;
pub type NomadFakeTransport = FakeNomadTransport;
pub type NomadLoopbackTransport = LoopbackNomadTransport;
pub type NomadBlockedEnvTransport = BlockedEnvNomadTransport;

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvNomadTransport {
    requests: Vec<NomadReadRequest>,
}

impl BlockedEnvNomadTransport {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub const fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    #[must_use]
    pub fn requests(&self) -> &[NomadReadRequest] {
        &self.requests
    }
}

impl NomadTransport for BlockedEnvNomadTransport {
    fn execute(
        &mut self,
        request: &NomadReadRequest,
    ) -> std::result::Result<NomadApiResponse, NomadTransportError> {
        self.requests.push(request.clone());
        Err(NomadTransportError::BlockedEnv)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn requests(&self) -> &[NomadReadRequest] {
        &self.requests
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NomadProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_digest: Digest,
}

impl Default for NomadProviderDefinition {
    fn default() -> Self {
        let operations = vec![
            JOB_METADATA_PATH.to_owned(),
            DEPLOYMENT_METADATA_PATH.to_owned(),
            ALLOCATION_METADATA_PATH.to_owned(),
        ];
        let provider_digest = Digest::from_serializable(&(
            crate::PROVIDER_ID,
            crate::PROVIDER_VERSION,
            crate::PROVIDER_API_REVISION,
            &operations,
        ));
        Self {
            provider_id: crate::PROVIDER_ID.to_owned(),
            provider_version: crate::PROVIDER_VERSION.to_owned(),
            api_revision: crate::PROVIDER_API_REVISION.to_owned(),
            operations,
            read_only: true,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
            provider_digest,
        }
    }
}

impl NomadProviderDefinition {
    pub fn validate(&self) -> Result<()> {
        if self.provider_id != crate::PROVIDER_ID
            || self.provider_version != crate::PROVIDER_VERSION
            || self.api_revision != crate::PROVIDER_API_REVISION
            || self.operations.len() != 3
            || !self.read_only
            || self.external_writes
            || self.connected
            || self.native
            || self.first_party
            || self.provider_digest != Self::default().provider_digest
        {
            return Err(NomadDeploymentResultError::ProviderDrift);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.provider_digest
    }
}

#[derive(Clone)]
pub struct NomadProvider<T: NomadTransport = FixtureNomadTransport> {
    transport: T,
    scope: NomadDeploymentScope,
    secret_reference: SecretReference,
    definition: NomadProviderDefinition,
}

impl<T: NomadTransport> fmt::Debug for NomadProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NomadProvider")
            .field("transport", &self.transport)
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("definition", &self.definition)
            .field("provenance", &self.provenance())
            .finish()
    }
}

impl<T: NomadTransport> NomadProvider<T> {
    pub fn new(
        transport: T,
        scope: NomadDeploymentScope,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        scope.validate()?;
        secret_reference.validate(&scope)?;
        let definition = NomadProviderDefinition::default();
        definition.validate()?;
        Ok(Self {
            transport,
            scope,
            secret_reference,
            definition,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &NomadDeploymentScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &NomadProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        self.definition.digest()
    }

    #[must_use]
    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read_snapshot(&mut self) -> Result<NomadProviderSnapshot> {
        self.read_snapshot_with_fence(None, None, None)
    }

    pub fn read_snapshot_with_fence(
        &mut self,
        registration_digest: Option<&Digest>,
        permission_digest: Option<&Digest>,
        consent_digest: Option<&Digest>,
    ) -> Result<NomadProviderSnapshot> {
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        let job = self.read_job_metadata(registration_digest, permission_digest, consent_digest)?;
        let deployment = if self.scope.provider.deployment_id.is_some() {
            Some(self.read_deployment_metadata(
                registration_digest,
                permission_digest,
                consent_digest,
            )?)
        } else {
            None
        };
        let allocation = if self.scope.provider.allocation_id.is_some() {
            Some(self.read_allocation_metadata(
                registration_digest,
                permission_digest,
                consent_digest,
            )?)
        } else {
            None
        };
        let item_count = 1_u8
            .saturating_add(u8::from(deployment.is_some()))
            .saturating_add(u8::from(allocation.is_some()));
        let complete = deployment.is_some() == self.scope.provider.deployment_id.is_some()
            && allocation.is_some() == self.scope.provider.allocation_id.is_some();
        if item_count == 0 || usize::from(item_count) > MAX_METADATA_ITEMS {
            return Err(NomadDeploymentResultError::InvalidResponse);
        }
        let response_digest = Digest::from_parts(
            "nomad-provider-snapshot/v1",
            &[
                ("job", job.metadata_digest.as_str().to_owned()),
                (
                    "deployment",
                    deployment.as_ref().map_or_else(
                        || "absent".to_owned(),
                        |value| value.metadata_digest.as_str().to_owned(),
                    ),
                ),
                (
                    "allocation",
                    allocation.as_ref().map_or_else(
                        || "absent".to_owned(),
                        |value| value.metadata_digest.as_str().to_owned(),
                    ),
                ),
            ],
        );
        Ok(NomadProviderSnapshot {
            job,
            deployment,
            allocation,
            page_count: 1,
            item_count,
            complete,
            response_digest,
            provenance: self.provenance(),
        })
    }

    pub fn read_job_metadata(
        &mut self,
        registration_digest: Option<&Digest>,
        permission_digest: Option<&Digest>,
        consent_digest: Option<&Digest>,
    ) -> Result<NomadJobProjection> {
        let request = self.request(
            NomadReadOperation::ReadJobMetadata,
            registration_digest,
            permission_digest,
            consent_digest,
        )?;
        let response = self.execute(request)?;
        let wire: NomadWireJob = parse_json(&response)?;
        let job_id = NomadJobId::new(wire.id)?;
        if job_id != self.scope.provider.job_id
            || (!wire.namespace.is_empty()
                && wire.namespace != self.scope.provider.namespace.as_str())
            || (!wire.region.is_empty() && wire.region != self.scope.provider.region.as_str())
            || (self.scope.provider.datacenter.is_some()
                && !wire.datacenters.is_empty()
                && !wire.datacenters.iter().any(|value| {
                    Some(value.as_str())
                        == self
                            .scope
                            .provider
                            .datacenter
                            .as_ref()
                            .map(NomadDatacenter::as_str)
                }))
        {
            return Err(NomadDeploymentResultError::ScopeMismatch);
        }
        let metadata_digest = Digest::from_parts(
            "nomad-job-metadata/v1",
            &[
                ("status", wire.status.clone()),
                ("version", wire.version.to_string()),
                ("create_index", wire.create_index.to_string()),
                ("modify_index", wire.modify_index.to_string()),
                ("datacenters", wire.datacenters.len().to_string()),
                ("task_groups", wire.task_groups.len().to_string()),
            ],
        );
        Ok(NomadJobProjection {
            id_digest: job_id_digest(&job_id),
            namespace_digest: Digest::from_text(self.scope.provider.namespace.as_str()),
            region_digest: Digest::from_text(self.scope.provider.region.as_str()),
            status: NomadJobState::from_wire(&wire.status),
            version: wire.version,
            create_index: wire.create_index,
            modify_index: wire.modify_index,
            datacenter_count: u16::try_from(wire.datacenters.len()).unwrap_or(u16::MAX),
            task_group_count: u16::try_from(wire.task_groups.len()).unwrap_or(u16::MAX),
            metadata_digest,
        })
    }

    pub fn read_deployment_metadata(
        &mut self,
        registration_digest: Option<&Digest>,
        permission_digest: Option<&Digest>,
        consent_digest: Option<&Digest>,
    ) -> Result<NomadDeploymentProjection> {
        let deployment_id = self
            .scope
            .provider
            .deployment_id
            .as_ref()
            .ok_or(NomadDeploymentResultError::InvalidRequest)?
            .clone();
        let request = self.request(
            NomadReadOperation::ReadDeploymentMetadata,
            registration_digest,
            permission_digest,
            consent_digest,
        )?;
        let response = self.execute(request)?;
        let wire: NomadWireDeployment = parse_json(&response)?;
        if wire.id != deployment_id.as_str()
            || (!wire.job_id.is_empty() && wire.job_id != self.scope.provider.job_id.as_str())
            || (!wire.namespace.is_empty()
                && wire.namespace != self.scope.provider.namespace.as_str())
            || (!wire.region.is_empty() && wire.region != self.scope.provider.region.as_str())
        {
            return Err(NomadDeploymentResultError::ScopeMismatch);
        }
        let id = NomadDeploymentId::new(wire.id)?;
        let metadata_digest = Digest::from_parts(
            "nomad-deployment-metadata/v1",
            &[
                ("status", wire.status.clone()),
                ("job_version", wire.job_version.to_string()),
                ("desired_total", wire.desired_total.to_string()),
                ("placed", wire.placed_allocations.to_string()),
                ("healthy", wire.healthy_allocations.to_string()),
                ("unhealthy", wire.unhealthy_allocations.to_string()),
                ("create_index", wire.create_index.to_string()),
                ("modify_index", wire.modify_index.to_string()),
            ],
        );
        Ok(NomadDeploymentProjection {
            id_digest: Digest::from_text(id.as_str()),
            job_id_digest: Digest::from_text(self.scope.provider.job_id.as_str()),
            job_version: wire.job_version,
            status: NomadDeploymentStatus::from_wire(&wire.status),
            desired_total: wire.desired_total,
            placed_allocations: wire.placed_allocations,
            healthy_allocations: wire.healthy_allocations,
            unhealthy_allocations: wire.unhealthy_allocations,
            create_index: wire.create_index,
            modify_index: wire.modify_index,
            metadata_digest,
        })
    }

    pub fn read_allocation_metadata(
        &mut self,
        registration_digest: Option<&Digest>,
        permission_digest: Option<&Digest>,
        consent_digest: Option<&Digest>,
    ) -> Result<NomadAllocationProjection> {
        let allocation_id = self
            .scope
            .provider
            .allocation_id
            .as_ref()
            .ok_or(NomadDeploymentResultError::InvalidRequest)?
            .clone();
        let request = self.request(
            NomadReadOperation::ReadAllocationMetadata,
            registration_digest,
            permission_digest,
            consent_digest,
        )?;
        let response = self.execute(request)?;
        let wire: NomadWireAllocation = parse_json(&response)?;
        if wire.id != allocation_id.as_str()
            || (!wire.job_id.is_empty() && wire.job_id != self.scope.provider.job_id.as_str())
            || (wire.deployment_id.as_deref().is_some_and(|value| {
                Some(value)
                    != self
                        .scope
                        .provider
                        .deployment_id
                        .as_ref()
                        .map(NomadDeploymentId::as_str)
            }))
            || (!wire.namespace.is_empty()
                && wire.namespace != self.scope.provider.namespace.as_str())
            || (!wire.region.is_empty() && wire.region != self.scope.provider.region.as_str())
        {
            return Err(NomadDeploymentResultError::ScopeMismatch);
        }
        let id = NomadAllocationId::new(wire.id)?;
        let deployment_id_digest = wire.deployment_id.as_deref().map(Digest::from_text);
        let node_id_digest = wire.node_id.as_deref().map(Digest::from_text);
        let metadata_digest = Digest::from_parts(
            "nomad-allocation-metadata/v1",
            &[
                ("desired", wire.desired_status.clone()),
                ("client", wire.client_status.clone()),
                ("task_group", wire.task_group.clone()),
                ("create_index", wire.create_index.to_string()),
                ("modify_index", wire.modify_index.to_string()),
            ],
        );
        Ok(NomadAllocationProjection {
            id_digest: Digest::from_text(id.as_str()),
            job_id_digest: Digest::from_text(self.scope.provider.job_id.as_str()),
            deployment_id_digest,
            node_id_digest,
            task_group_digest: Digest::from_text(&wire.task_group),
            desired_status: NomadAllocationStatus::from_wire(&wire.desired_status),
            client_status: NomadAllocationStatus::from_wire(&wire.client_status),
            create_index: wire.create_index,
            modify_index: wire.modify_index,
            metadata_digest,
        })
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<()> {
        Err(NomadDeploymentResultError::MutationForbidden { operation })
    }

    fn request(
        &self,
        operation: NomadReadOperation,
        registration_digest: Option<&Digest>,
        permission_digest: Option<&Digest>,
        consent_digest: Option<&Digest>,
    ) -> Result<NomadReadRequest> {
        let mut request = NomadReadRequest::new(operation, &self.scope)?;
        request.registration_digest = registration_digest.cloned();
        request.permission_digest = permission_digest.cloned();
        request.consent_digest = consent_digest.cloned();
        Ok(request)
    }

    fn execute(&mut self, request: NomadReadRequest) -> Result<NomadApiResponse> {
        if !NomadReadOperation::ALL.contains(&request.operation) {
            return Err(NomadDeploymentResultError::InvalidRequest);
        }
        let response = self.transport.execute(&request)?;
        match response.status() {
            200..=202 => {
                response.validate_size_and_digest()?;
                Ok(response)
            }
            206 => Err(NomadTransportError::Partial.into()),
            401 | 403 => Err(NomadTransportError::AccessLost.into()),
            404 => Err(NomadTransportError::NotFound.into()),
            409 | 412 => Err(NomadTransportError::Conflict.into()),
            429 => Err(NomadTransportError::RateLimited {
                retry_after_seconds: None,
            }
            .into()),
            408 | 504 => Err(NomadTransportError::Timeout.into()),
            _ => Err(NomadTransportError::ProviderUnknown.into()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NomadProviderSnapshot {
    pub job: NomadJobProjection,
    pub deployment: Option<NomadDeploymentProjection>,
    pub allocation: Option<NomadAllocationProjection>,
    pub page_count: u8,
    pub item_count: u8,
    pub complete: bool,
    pub response_digest: Digest,
    pub provenance: ProviderProvenance,
}

impl NomadProviderSnapshot {
    pub fn validate(&self, scope: &NomadDeploymentScope) -> Result<()> {
        scope.validate()?;
        if self.page_count == 0
            || self.page_count > crate::model::MAX_PAGES
            || self.item_count == 0
            || self.item_count > MAX_METADATA_ITEMS as u8
            || self.job.id_digest != scope.provider.job_id_digest()
            || (scope.provider.deployment_id.is_some() != self.deployment.is_some())
            || (scope.provider.allocation_id.is_some() != self.allocation.is_some())
        {
            return Err(NomadDeploymentResultError::InvalidResponse);
        }
        Ok(())
    }

    #[must_use]
    pub fn state(&self) -> NomadDeploymentState {
        if self
            .deployment
            .as_ref()
            .is_some_and(|deployment| matches!(deployment.status, NomadDeploymentStatus::Failed))
            || self.allocation.as_ref().is_some_and(|allocation| {
                matches!(
                    allocation.client_status,
                    NomadAllocationStatus::Failed | NomadAllocationStatus::Lost
                )
            })
        {
            return NomadDeploymentState::Failed;
        }
        if self.deployment.as_ref().is_some_and(|deployment| {
            matches!(deployment.status, NomadDeploymentStatus::Successful)
        }) {
            return NomadDeploymentState::Successful;
        }
        if self
            .deployment
            .as_ref()
            .is_some_and(|deployment| matches!(deployment.status, NomadDeploymentStatus::Stopped))
        {
            return NomadDeploymentState::Stopped;
        }
        if self
            .deployment
            .as_ref()
            .is_some_and(|deployment| matches!(deployment.status, NomadDeploymentStatus::Running))
        {
            return NomadDeploymentState::Running;
        }
        NomadDeploymentState::Pending
    }
}

fn parse_json<T: for<'de> Deserialize<'de>>(response: &NomadApiResponse) -> Result<T> {
    response.validate_size_and_digest()?;
    serde_json::from_slice(response.body()).map_err(|_| NomadDeploymentResultError::InvalidResponse)
}

fn job_id_digest(id: &NomadJobId) -> Digest {
    Digest::from_text(id.as_str())
}

#[allow(dead_code)]
fn _address_is_typed(address: &NomadAddress) -> bool {
    !address.as_str().is_empty()
}

#[allow(dead_code)]
fn _deployment_id_is_typed(id: &NomadDeploymentId) -> bool {
    !id.as_str().is_empty()
}

#[allow(dead_code)]
fn _allocation_id_is_typed(id: &NomadAllocationId) -> bool {
    !id.as_str().is_empty()
}
