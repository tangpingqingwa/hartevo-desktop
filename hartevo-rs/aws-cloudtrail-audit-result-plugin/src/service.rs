//! Read-only CloudTrail audit service and governed proposal lifecycle.

use std::{collections::BTreeMap, fmt};

use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginVersion, ProviderCardinality,
    ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AuditAnomaly, AuditBounds, AuditEvidence, AuditEvidenceDigests, AuditProjection, AuditQuery,
    AwsCloudTrailAuditScope, Digest, EffectObservation, ModelError, PartialReason,
    RedactedEventMetadata, Revision, SigV4SecretReference, contract_version_digest,
    plugin_version_digest,
};
use crate::provider::{
    AwsCloudTrailLookupTransport, AwsCloudTrailProvider, AwsCloudTrailProviderDefinition,
    AwsCloudTrailProviderError, LookupEventsPage, LookupEventsProposal, LookupEventsRecord,
    LookupResponseStatus, OpaqueCursor, ProviderFailureClass, ProviderProvenance,
};
use crate::{
    AWS_CLOUDTRAIL_AUDIT_CONTRACT_JSON, AWS_CLOUDTRAIL_AUDIT_CONTRACT_VERSION,
    AWS_CLOUDTRAIL_AUDIT_PLUGIN_VERSION_TEXT, AWS_CLOUDTRAIL_AUDIT_PROVIDER_ID,
    AWS_CLOUDTRAIL_AUDIT_PROVIDER_REVISION, AWS_CLOUDTRAIL_AUDIT_PROVIDER_SCHEMA,
    AWS_CLOUDTRAIL_AUDIT_SCHEMA_VERSION, AWS_CLOUDTRAIL_AUDIT_SERVICE_ID,
    AWS_CLOUDTRAIL_AUDIT_SERVICE_NAME, AWS_CLOUDTRAIL_AUDIT_SERVICE_SCHEMA,
    MISSION_CLOUDTRAIL_AUDIT_CONSUMER_ID,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsCloudTrailAuditOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ProposeLookupEvents,
    ReadLookupEvents,
    RecordLookupEvents,
    VerifyLookupEvents,
    ConsumeObservation,
}

impl AwsCloudTrailAuditOperation {
    pub const ALL: [Self; 8] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ProposeLookupEvents,
        Self::ReadLookupEvents,
        Self::RecordLookupEvents,
        Self::VerifyLookupEvents,
        Self::ConsumeObservation,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsCloudTrailCapability {
    pub capability_id: String,
    pub operation: AwsCloudTrailAuditOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsCloudTrailAuditServiceDefinition {
    service_id: String,
    service_name: String,
    version: PluginVersion,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<AwsCloudTrailCapability>,
}

impl Default for AwsCloudTrailAuditServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsCloudTrailAuditServiceDefinition {
    pub fn new() -> Self {
        let capabilities = [
            (
                "aws.cloudtrail.audit.register",
                AwsCloudTrailAuditOperation::Register,
            ),
            (
                "aws.cloudtrail.audit.revoke_registration",
                AwsCloudTrailAuditOperation::RevokeRegistration,
            ),
            (
                "aws.cloudtrail.audit.propose_lookup_events",
                AwsCloudTrailAuditOperation::ProposeLookupEvents,
            ),
            (
                "aws.cloudtrail.audit.read_lookup_events",
                AwsCloudTrailAuditOperation::ReadLookupEvents,
            ),
            (
                "aws.cloudtrail.audit.record_lookup_events",
                AwsCloudTrailAuditOperation::RecordLookupEvents,
            ),
            (
                "aws.cloudtrail.audit.verify_lookup_events",
                AwsCloudTrailAuditOperation::VerifyLookupEvents,
            ),
            (
                "aws.cloudtrail.audit.consume_observation",
                AwsCloudTrailAuditOperation::ConsumeObservation,
            ),
        ]
        .into_iter()
        .map(|(capability_id, operation)| AwsCloudTrailCapability {
            capability_id: capability_id.to_owned(),
            operation,
            read_only: true,
            mutates_provider: false,
            native_evidence: false,
        })
        .collect();
        Self {
            service_id: AWS_CLOUDTRAIL_AUDIT_SERVICE_ID.to_owned(),
            service_name: AWS_CLOUDTRAIL_AUDIT_SERVICE_NAME.to_owned(),
            version: PluginVersion::new(1, 0, 0),
            read_only: true,
            native_connected: false,
            capabilities,
        }
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub const fn native_connected(&self) -> bool {
        self.native_connected
    }

    pub fn capabilities(&self) -> &[AwsCloudTrailCapability] {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Vec<AwsCloudTrailCapability> {
        self.capabilities.clone()
    }

    pub fn runtime_definition(&self) -> Result<ServiceDefinition, AwsCloudTrailServiceError> {
        let service_id =
            ServiceId::new(self.service_id.clone()).map_err(AwsCloudTrailServiceError::Plugin)?;
        ServiceDefinition::read_only(
            service_id,
            self.version,
            RuntimeDigest::from_text(AWS_CLOUDTRAIL_AUDIT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(AwsCloudTrailServiceError::Plugin)
    }

    pub fn validate(&self) -> Result<(), AwsCloudTrailServiceError> {
        if self.service_id != AWS_CLOUDTRAIL_AUDIT_SERVICE_ID
            || self.service_name != AWS_CLOUDTRAIL_AUDIT_SERVICE_NAME
            || self.version != PluginVersion::new(1, 0, 0)
            || !self.read_only
            || self.native_connected
            || self.capabilities.is_empty()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only || capability.mutates_provider || capability.native_evidence
            })
        {
            return Err(AwsCloudTrailServiceError::ContractDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("CloudTrail registration is already revoked")]
    AlreadyRevoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsCloudTrailRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub version_digest: Digest,
    pub scope_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub query_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
}

impl AwsCloudTrailRegistration {
    fn new(
        scope: &AwsCloudTrailAuditScope,
        secret: &SigV4SecretReference,
        provider: &AwsCloudTrailProviderDefinition,
        query: &AuditQuery,
    ) -> Result<Self, ModelError> {
        let revision = Revision::new(1)?;
        let contract_digest = crate::contract_digest();
        let version_digest = plugin_version_digest();
        let permission_digest = query.permission_digest.clone();
        let registration_digest = Digest::from_serializable(&(
            AWS_CLOUDTRAIL_AUDIT_PLUGIN_VERSION_TEXT,
            AWS_CLOUDTRAIL_AUDIT_CONTRACT_VERSION,
            &contract_digest,
            &version_digest,
            &scope.scope_digest(),
            &provider.provider_id,
            &provider.provider_version,
            &provider.provider_revision,
            &provider.provider_digest(),
            &permission_digest,
            &query.query_digest,
            secret.reference_digest(),
            secret.revision(),
            revision,
        ));
        Ok(Self {
            plugin_version: AWS_CLOUDTRAIL_AUDIT_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: AWS_CLOUDTRAIL_AUDIT_CONTRACT_VERSION.to_owned(),
            contract_digest,
            version_digest,
            scope_digest: scope.scope_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_revision: provider.provider_revision.clone(),
            provider_digest: provider.provider_digest(),
            permission_digest,
            query_digest: query.query_digest.clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.revision(),
            revision,
            registration_digest,
            state: RegistrationState::Active,
        })
    }

    pub fn revoke(&mut self) -> Result<(), RegistrationError> {
        if self.state == RegistrationState::Revoked {
            return Err(RegistrationError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn verify_digest(&self) -> bool {
        let expected = Digest::from_serializable(&(
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.version_digest,
            &self.scope_digest,
            &self.provider_id,
            &self.provider_version,
            &self.provider_revision,
            &self.provider_digest,
            &self.permission_digest,
            &self.query_digest,
            &self.secret_reference_digest,
            self.credential_revision,
            self.revision,
        ));
        self.registration_digest == expected
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCloudTrailServiceError {
    #[error("CloudTrail registration is revoked")]
    RegistrationRevoked,
    #[error("CloudTrail SigV4 SecretReference is revoked")]
    SecretRevoked,
    #[error("CloudTrail scope or secret binding does not match")]
    ScopeMismatch,
    #[error("CloudTrail service or provider definition drifted")]
    ContractDrift,
    #[error("CloudTrail registration is stale or tampered")]
    RegistrationTampered,
    #[error("CloudTrail proposal is stale or tampered")]
    ProposalTampered,
    #[error("CloudTrail LookupEvents response is stale or tampered")]
    RecordTampered,
    #[error("CloudTrail event does not match the exact registered scope")]
    EventScopeMismatch,
    #[error("CloudTrail event metadata is invalid")]
    EventMetadataInvalid,
    #[error("CloudTrail cursor binding changed")]
    CursorMismatch,
    #[error("CloudTrail provider error: {0}")]
    Provider(#[from] AwsCloudTrailProviderError),
    #[error("CloudTrail model error: {0}")]
    Model(#[from] ModelError),
    #[error("plugin runtime rejected the CloudTrail definition: {0}")]
    Plugin(#[from] hartevo_plugin_runtime::PluginError),
}

/// A page record plus its opaque continuation cursor.  The cursor is not
/// serializable and is exposed only as an opaque typed value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LookupEventsRead {
    pub record: LookupEventsRecord,
    pub next_cursor: Option<OpaqueCursor>,
}

pub struct AwsCloudTrailAuditService<T>
where
    T: AwsCloudTrailLookupTransport,
{
    scope: AwsCloudTrailAuditScope,
    secret_reference: SigV4SecretReference,
    provider: AwsCloudTrailProvider<T>,
    definition: AwsCloudTrailAuditServiceDefinition,
    registration: AwsCloudTrailRegistration,
    query: AuditQuery,
    bounds: AuditBounds,
}

impl<T> fmt::Debug for AwsCloudTrailAuditService<T>
where
    T: AwsCloudTrailLookupTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCloudTrailAuditService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("query_digest", &self.query.query_digest)
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

impl<T> AwsCloudTrailAuditService<T>
where
    T: AwsCloudTrailLookupTransport,
{
    pub fn new(
        scope: AwsCloudTrailAuditScope,
        secret_reference: SigV4SecretReference,
        provider: AwsCloudTrailProvider<T>,
    ) -> Result<Self, AwsCloudTrailServiceError> {
        Self::with_bounds(scope, secret_reference, provider, AuditBounds::default())
    }

    pub fn with_bounds(
        scope: AwsCloudTrailAuditScope,
        secret_reference: SigV4SecretReference,
        provider: AwsCloudTrailProvider<T>,
        bounds: AuditBounds,
    ) -> Result<Self, AwsCloudTrailServiceError> {
        if secret_reference.is_revoked()
            || secret_reference.account_digest()
                != Some(&Digest::from_text(scope.account_id.as_str()))
                && secret_reference.account_digest().is_some()
            || secret_reference.region_digest() != Some(&Digest::from_text(scope.region.as_str()))
                && secret_reference.region_digest().is_some()
        {
            return Err(if secret_reference.is_revoked() {
                AwsCloudTrailServiceError::SecretRevoked
            } else {
                AwsCloudTrailServiceError::ScopeMismatch
            });
        }
        let definition = AwsCloudTrailAuditServiceDefinition::new();
        definition.validate()?;
        let provider_definition = provider.definition();
        if provider_definition.provider_id != AWS_CLOUDTRAIL_AUDIT_PROVIDER_ID
            || provider_definition.schema_version != AWS_CLOUDTRAIL_AUDIT_PROVIDER_SCHEMA
            || !provider_definition.management_events_only
            || provider_definition.live_execution
            || provider.is_native()
        {
            return Err(AwsCloudTrailServiceError::ContractDrift);
        }
        let permission_digest = Digest::from_serializable(&(
            "hartevo:aws-cloudtrail-permission-binding:v1",
            scope.permission.digest(),
            secret_reference.reference_digest(),
            secret_reference.revision(),
            &scope.account_id,
            &scope.region,
        ));
        let query = AuditQuery::new(
            &scope,
            permission_digest,
            secret_reference.reference_digest().clone(),
            bounds,
        );
        let registration =
            AwsCloudTrailRegistration::new(&scope, &secret_reference, provider_definition, &query)?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            definition,
            registration,
            query,
            bounds,
        })
    }

    pub fn definition(&self) -> &AwsCloudTrailAuditServiceDefinition {
        &self.definition
    }

    pub fn scope(&self) -> &AwsCloudTrailAuditScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SigV4SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsCloudTrailProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsCloudTrailProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsCloudTrailRegistration {
        &self.registration
    }

    pub fn query(&self) -> &AuditQuery {
        &self.query
    }

    pub fn bounds(&self) -> AuditBounds {
        self.bounds
    }

    pub fn is_registered(&self) -> bool {
        self.registration.is_active() && !self.secret_reference.is_revoked()
    }

    pub fn register(&mut self) -> Result<&AwsCloudTrailRegistration, AwsCloudTrailServiceError> {
        if self.secret_reference.is_revoked() {
            return Err(AwsCloudTrailServiceError::SecretRevoked);
        }
        if self.registration.state == RegistrationState::Revoked {
            self.registration.state = RegistrationState::Active;
        }
        Ok(&self.registration)
    }

    pub fn revoke_registration(&mut self) -> Result<(), AwsCloudTrailServiceError> {
        self.registration
            .revoke()
            .map_err(|_| AwsCloudTrailServiceError::RegistrationRevoked)
    }

    pub fn revoke_secret_reference(&mut self) {
        self.secret_reference.revoke();
        self.registration.state = RegistrationState::Revoked;
    }

    fn validate_active(&self) -> Result<(), AwsCloudTrailServiceError> {
        if !self.registration.is_active() {
            return Err(AwsCloudTrailServiceError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(AwsCloudTrailServiceError::SecretRevoked);
        }
        if !self.registration.verify_digest()
            || self.registration.scope_digest != self.scope.scope_digest()
            || self.registration.query_digest != self.query.query_digest
            || self.registration.permission_digest != self.query.permission_digest
        {
            return Err(AwsCloudTrailServiceError::RegistrationTampered);
        }
        Ok(())
    }

    pub fn propose_lookup_events(
        &self,
        page_number: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<LookupEventsProposal, AwsCloudTrailServiceError> {
        self.validate_active()?;
        let request = crate::provider::LookupEventsRequest::new(
            self.query.clone(),
            self.provider.definition().provider_digest(),
            self.provider.definition().provider_revision.clone(),
            page_number,
            cursor,
        )?;
        Ok(LookupEventsProposal::new(
            self.registration.registration_digest.clone(),
            self.registration.revision,
            request,
        ))
    }

    pub fn read_lookup_events(
        &mut self,
        proposal: &LookupEventsProposal,
    ) -> Result<LookupEventsRecord, AwsCloudTrailServiceError> {
        Ok(self.read_lookup_events_with_cursor(proposal)?.record)
    }

    pub fn read_lookup_events_with_cursor(
        &mut self,
        proposal: &LookupEventsProposal,
    ) -> Result<LookupEventsRead, AwsCloudTrailServiceError> {
        self.validate_proposal(proposal)?;
        let page = self.provider.read(proposal.request())?;
        let next_cursor = page.next_cursor().cloned();
        let record = self.record_lookup_events(proposal, &page)?;
        self.verify_lookup_events(proposal, &record)?;
        Ok(LookupEventsRead {
            record,
            next_cursor,
        })
    }

    pub fn record_lookup_events(
        &self,
        proposal: &LookupEventsProposal,
        page: &LookupEventsPage,
    ) -> Result<LookupEventsRecord, AwsCloudTrailServiceError> {
        self.validate_proposal(proposal)?;
        if !page.verify_digest(proposal.request()) {
            return Err(AwsCloudTrailServiceError::RecordTampered);
        }
        if page
            .events
            .iter()
            .any(|event| !event.matches_scope(&self.scope))
        {
            return Err(AwsCloudTrailServiceError::EventScopeMismatch);
        }
        let record = self.provider.record(proposal, page)?;
        Ok(record)
    }

    pub fn verify_lookup_events(
        &self,
        proposal: &LookupEventsProposal,
        record: &LookupEventsRecord,
    ) -> Result<(), AwsCloudTrailServiceError> {
        self.validate_proposal(proposal)?;
        self.provider.verify(proposal, record)?;
        if record.scope_digest != self.scope.scope_digest()
            || record.permission_digest != self.query.permission_digest
            || record.secret_reference_digest != self.query.secret_reference_digest
            || record
                .events
                .iter()
                .any(|event| !event.matches_scope(&self.scope))
        {
            return Err(AwsCloudTrailServiceError::RecordTampered);
        }
        Ok(())
    }

    fn validate_proposal(
        &self,
        proposal: &LookupEventsProposal,
    ) -> Result<(), AwsCloudTrailServiceError> {
        self.validate_active()?;
        if !proposal.verify_digest()
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
            || proposal.provider_digest != self.registration.provider_digest
            || proposal.provider_revision != self.registration.provider_revision
            || proposal.query.query_digest != self.query.query_digest
            || !proposal.query.verify_digest()
        {
            return Err(AwsCloudTrailServiceError::ProposalTampered);
        }
        Ok(())
    }

    /// Executes a bounded sequence of LookupEvents calls and returns a
    /// content-free, deduplicated, deterministically ordered evidence result.
    /// Provider availability states are returned as typed projections rather
    /// than being upgraded into a successful external-effect claim.
    pub fn read_bounded(&mut self) -> Result<AuditEvidence, AwsCloudTrailServiceError> {
        self.validate_active()?;
        let mut page_number = 1;
        let mut cursor = None;
        let mut reads = Vec::new();
        let mut projection = AuditProjection::Complete;
        let mut anomalies = Vec::new();
        let mut failure_digest = None;

        loop {
            if page_number > self.bounds.max_pages {
                projection = AuditProjection::Partial(PartialReason::PageCap);
                break;
            }
            let proposal = self.propose_lookup_events(page_number, cursor.clone())?;
            match self.read_lookup_events_with_cursor(&proposal) {
                Ok(read) => {
                    let has_more = read.next_cursor.is_some();
                    if read.record.response_status == LookupResponseStatus::Warning {
                        projection = AuditProjection::Partial(PartialReason::ProviderWarning);
                    }
                    reads.push(read);
                    if !has_more {
                        break;
                    }
                    cursor = reads.last().and_then(|read| read.next_cursor.clone());
                    page_number = page_number.saturating_add(1);
                }
                Err(AwsCloudTrailServiceError::Provider(error)) => {
                    let class = error.class();
                    projection = class.projection();
                    failure_digest = Some(error.diagnostic_digest());
                    if class == ProviderFailureClass::ReplayDetected {
                        anomalies.push(AuditAnomaly::ReplayDetected);
                    }
                    break;
                }
                Err(error) => return Err(error),
            }
        }

        let mut evidence = self.build_evidence(&reads, projection, anomalies, failure_digest)?;
        if evidence.unique_event_count > self.bounds.max_events {
            evidence
                .events
                .truncate(usize::from(self.bounds.max_events));
            evidence.unique_event_count = self.bounds.max_events;
            evidence.projection = AuditProjection::Partial(PartialReason::EventCap);
            evidence.digests.evidence_digest = evidence.compute_evidence_digest();
        }
        Ok(evidence)
    }

    pub fn build_evidence(
        &self,
        reads: &[LookupEventsRead],
        mut projection: AuditProjection,
        mut anomalies: Vec<AuditAnomaly>,
        provider_failure_digest: Option<Digest>,
    ) -> Result<AuditEvidence, AwsCloudTrailServiceError> {
        let mut event_map: BTreeMap<Digest, RedactedEventMetadata> = BTreeMap::new();
        let mut raw_event_count: u16 = 0;
        let mut duplicate_event_count: u16 = 0;
        let mut original_order = Vec::new();
        let mut record_digests = Vec::new();
        let mut cursor_chain = Vec::new();

        for read in reads {
            self.validate_record_without_proposal(&read.record)?;
            record_digests.push(read.record.record_digest.clone());
            cursor_chain.push(read.record.next_cursor_digest.clone());
            for event in &read.record.events {
                raw_event_count = raw_event_count.saturating_add(1);
                original_order.push((event.event_time, event.event_id_digest.clone()));
                if let Some(previous) = event_map.get(&event.event_id_digest) {
                    if previous.event_digest != event.event_digest {
                        return Err(AwsCloudTrailServiceError::RecordTampered);
                    }
                    duplicate_event_count = duplicate_event_count.saturating_add(1);
                    if !anomalies.contains(&AuditAnomaly::DuplicateEvent) {
                        anomalies.push(AuditAnomaly::DuplicateEvent);
                    }
                } else {
                    event_map.insert(event.event_id_digest.clone(), event.clone());
                }
            }
        }

        let mut events: Vec<_> = event_map.into_values().collect();
        events.sort_by(|left, right| {
            (left.event_time, &left.event_id_digest)
                .cmp(&(right.event_time, &right.event_id_digest))
        });
        let sorted_order: Vec<_> = events
            .iter()
            .map(|event| (event.event_time, event.event_id_digest.clone()))
            .collect();
        if original_order != sorted_order && !events.is_empty() {
            anomalies.push(AuditAnomaly::OrderNormalized);
        }
        if reads
            .iter()
            .any(|read| read.record.response_status == LookupResponseStatus::Warning)
        {
            projection = AuditProjection::Partial(PartialReason::ProviderWarning);
        }
        let cursor_chain_digest = Digest::from_serializable(&cursor_chain);
        let mut evidence = AuditEvidence {
            schema_version: AWS_CLOUDTRAIL_AUDIT_SCHEMA_VERSION.to_owned(),
            contract_version: AWS_CLOUDTRAIL_AUDIT_CONTRACT_VERSION.to_owned(),
            plugin_version: AWS_CLOUDTRAIL_AUDIT_PLUGIN_VERSION_TEXT.to_owned(),
            scope_digest: self.scope.scope_digest(),
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            provider_id: AWS_CLOUDTRAIL_AUDIT_PROVIDER_ID.to_owned(),
            provider_version: self.registration.provider_version.clone(),
            provider_revision: self.registration.provider_revision.clone(),
            page_count: u16::try_from(reads.len()).unwrap_or(u16::MAX),
            raw_event_count,
            unique_event_count: u16::try_from(events.len()).unwrap_or(u16::MAX),
            duplicate_event_count,
            projection,
            events,
            record_digests,
            cursor_chain_digest,
            anomalies,
            effect_observation: EffectObservation::NoExternalEffectClaim,
            provider_failure_digest,
            digests: AuditEvidenceDigests {
                version_digest: plugin_version_digest(),
                provider_digest: self.registration.provider_digest.clone(),
                contract_digest: crate::contract_digest(),
                permission_digest: self.query.permission_digest.clone(),
                query_digest: self.query.query_digest.clone(),
                evidence_digest: Digest::from_text("placeholder"),
            },
        };
        evidence.digests.evidence_digest = evidence.compute_evidence_digest();
        Ok(evidence)
    }

    fn validate_record_without_proposal(
        &self,
        record: &LookupEventsRecord,
    ) -> Result<(), AwsCloudTrailServiceError> {
        if !record.verify_integrity()
            || record.registration_digest != self.registration.registration_digest
            || record.registration_revision != self.registration.revision
            || record.provider_digest != self.registration.provider_digest
            || record.provider_revision != self.registration.provider_revision
            || record.query_digest != self.query.query_digest
            || record.scope_digest != self.scope.scope_digest()
            || record.permission_digest != self.query.permission_digest
            || record.secret_reference_digest != self.query.secret_reference_digest
            || record
                .events
                .iter()
                .any(|event| !event.matches_scope(&self.scope))
        {
            return Err(AwsCloudTrailServiceError::RecordTampered);
        }
        Ok(())
    }
}

impl<T> AwsCloudTrailAuditService<T>
where
    T: AwsCloudTrailLookupTransport,
{
    pub fn provider_definition(&self) -> &AwsCloudTrailProviderDefinition {
        self.provider.definition()
    }

    pub fn provider_provenance(&self) -> ProviderProvenance {
        self.provider.provenance()
    }
}

pub fn provider_failure_projection(error: &AwsCloudTrailProviderError) -> AuditProjection {
    error.class().projection()
}

pub fn contract_json_is_embedded() -> bool {
    !AWS_CLOUDTRAIL_AUDIT_CONTRACT_JSON.trim().is_empty()
        && contract_version_digest() != Digest::from_text("placeholder")
}

pub fn consumer_id() -> &'static str {
    MISSION_CLOUDTRAIL_AUDIT_CONSUMER_ID
}

pub fn provider_revision() -> &'static str {
    AWS_CLOUDTRAIL_AUDIT_PROVIDER_REVISION
}
