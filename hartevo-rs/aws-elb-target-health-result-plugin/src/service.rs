//! Typed Layer-1 AWS ELB target-health service, registration, evidence, and
//! review-only proposal boundary.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::{
    CONSUMER_ID, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_API_REVISION,
    model::{
        AwsElbReadRequest, AwsElbScope, CostReceipt, Digest, EvidenceAuthority, EvidenceDigests,
        EvidenceState, HealthCheckSummary, LoadBalancerState, LoadBalancerSummary, PartialReason,
        PermissionFence, ProviderErrorReceipt, ProviderProvenance, ReadBounds, ReadOperation,
        RegistrationState, RequestReceipt, Revision, SigV4SecretReference, TargetGroupState,
        TargetGroupSummary, TargetHealthCollectionState, TargetHealthObservation,
        TargetHealthState, TransportFailure, digest_serialized,
    },
    provider::{
        AwsElbProvider, AwsElbProviderDefinition, AwsElbTransport, DescribeLoadBalancersPage,
        DescribeTargetGroupsPage, DescribeTargetHealthPage, ProviderDefinitionError, ProviderError,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsElbTargetHealthServiceError {
    #[error("AWS ELB scope is invalid: {0}")]
    Scope(String),
    #[error("AWS ELB permission fence is incomplete or drifted")]
    PermissionLoss,
    #[error("AWS ELB SigV4 secret reference is invalid or drifted")]
    SecretReferenceMismatch,
    #[error("AWS ELB registration is revoked")]
    RegistrationRevoked,
    #[error("AWS ELB registration is reversed")]
    RegistrationReversed,
    #[error("AWS ELB registration is tampered")]
    RegistrationTampered,
    #[error("AWS ELB registration transition is invalid")]
    InvalidRegistrationTransition,
    #[error("AWS ELB provider definition is invalid")]
    ProviderDefinition,
    #[error("AWS ELB provider failed: {0}")]
    Provider(ProviderError),
    #[error("AWS ELB evidence is tampered")]
    EvidenceTampered,
    #[error("AWS ELB proposal is tampered")]
    ProposalTampered,
    #[error("AWS ELB record is tampered")]
    RecordTampered,
    #[error("AWS ELB proposal or request was replayed")]
    Replay,
    #[error("AWS ELB scope or target-group projection drifted")]
    ProjectionDrift,
    #[error("AWS ELB request is invalid: {0}")]
    Request(String),
}

impl From<ProviderDefinitionError> for AwsElbTargetHealthServiceError {
    fn from(_: ProviderDefinitionError) -> Self {
        Self::ProviderDefinition
    }
}

impl From<crate::model::ModelError> for AwsElbTargetHealthServiceError {
    fn from(error: crate::model::ModelError) -> Self {
        Self::Scope(error.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElbTargetHealthCapabilities {
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub target_registration_mutation: bool,
    pub health_check_mutation: bool,
    pub failover_mutation: bool,
    pub target_execution: bool,
    pub availability_certification: bool,
    pub allowed_operations: [ReadOperation; 3],
}

impl AwsElbTargetHealthCapabilities {
    pub const fn layer_one() -> Self {
        Self {
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            target_registration_mutation: false,
            health_check_mutation: false,
            failover_mutation: false,
            target_execution: false,
            availability_certification: false,
            allowed_operations: [
                ReadOperation::DescribeLoadBalancers,
                ReadOperation::DescribeTargetGroups,
                ReadOperation::DescribeTargetHealth,
            ],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub from: RegistrationState,
    pub to: RegistrationState,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElbRegistration {
    pub plugin_version: String,
    pub plugin_version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub target_group_digest: Digest,
    pub target_group_revision: Revision,
    pub target_health_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
    pub registration_digest: Digest,
}

impl AwsElbRegistration {
    pub fn new(
        scope: &AwsElbScope,
        secret_reference: &SigV4SecretReference,
        provider: &AwsElbProviderDefinition,
    ) -> Result<Self, AwsElbTargetHealthServiceError> {
        let mut value = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: provider.id.clone(),
            provider_version: provider.version.clone(),
            provider_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: scope.permission_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            target_group_digest: scope.target_group.digest(),
            target_group_revision: scope.target_group.revision,
            target_health_digest: scope.target_health_digest(),
            secret_reference_digest: secret_reference.digest(),
            registration_revision: Revision::new(1)?,
            state: RegistrationState::Active,
            reversible: true,
            revocable: true,
            registration_digest: Digest::zero(),
        };
        value.registration_digest = value.recomputed_digest();
        Ok(value)
    }

    pub const fn is_active(&self) -> bool {
        self.state.is_active()
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-elb-registration/v1",
            &[
                ("plugin_version", self.plugin_version.clone()),
                (
                    "plugin_version_digest",
                    self.plugin_version_digest.to_string(),
                ),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.to_string()),
                ("provider_id", self.provider_id.clone()),
                ("provider_version", self.provider_version.clone()),
                ("provider_revision", self.provider_revision.clone()),
                ("provider", self.provider_digest.to_string()),
                ("api", self.api_digest.to_string()),
                ("permission", self.permission_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                ("target_group", self.target_group_digest.to_string()),
                (
                    "target_group_revision",
                    self.target_group_revision.get().to_string(),
                ),
                ("target_health", self.target_health_digest.to_string()),
                ("secret_reference", self.secret_reference_digest.to_string()),
                (
                    "registration_revision",
                    self.registration_revision.get().to_string(),
                ),
                ("state", format!("{:?}", self.state)),
                ("reversible", self.reversible.to_string()),
                ("revocable", self.revocable.to_string()),
            ],
        )
    }

    pub fn verify(&self) -> Result<(), AwsElbTargetHealthServiceError> {
        let expected_provider = AwsElbProviderDefinition::baseline();
        if self.registration_digest != self.recomputed_digest()
            || self.plugin_version != PLUGIN_VERSION
            || self.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != expected_provider.id
            || self.provider_version != expected_provider.version
            || self.provider_revision != PROVIDER_API_REVISION
            || self.provider_digest != expected_provider.provider_digest
            || self.api_digest != expected_provider.api_digest
            || !self.reversible
            || !self.revocable
        {
            Err(AwsElbTargetHealthServiceError::RegistrationTampered)
        } else {
            Ok(())
        }
    }

    fn transition(
        &mut self,
        to: RegistrationState,
    ) -> Result<RegistrationTransitionEvidence, AwsElbTargetHealthServiceError> {
        let from = self.state;
        let valid = matches!(
            (from, to),
            (
                RegistrationState::Active,
                RegistrationState::Reversed | RegistrationState::Revoked
            ) | (
                RegistrationState::Reversed,
                RegistrationState::Active | RegistrationState::Revoked
            )
        );
        if !valid {
            return Err(AwsElbTargetHealthServiceError::InvalidRegistrationTransition);
        }
        self.registration_revision = Revision::new(self.registration_revision.get() + 1)?;
        self.state = to;
        self.registration_digest = self.recomputed_digest();
        let transition_digest = digest_serialized(&(
            from,
            to,
            self.registration_revision,
            &self.registration_digest,
        ));
        Ok(RegistrationTransitionEvidence {
            from,
            to,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
            transition_digest,
        })
    }

    pub fn reverse(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AwsElbTargetHealthServiceError> {
        self.transition(RegistrationState::Reversed)
    }

    pub fn restore(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AwsElbTargetHealthServiceError> {
        self.transition(RegistrationState::Active)
    }

    pub fn revoke(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AwsElbTargetHealthServiceError> {
        self.transition(RegistrationState::Revoked)
    }
}

pub type AwsElbTargetHealthRegistration = AwsElbRegistration;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElbTargetHealthEvidence {
    pub state: EvidenceState,
    pub complete: bool,
    pub partial_reason: Option<PartialReason>,
    pub provenance: ProviderProvenance,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub scope_target_health_digest: Digest,
    pub load_balancers: Vec<LoadBalancerSummary>,
    pub target_groups: Vec<TargetGroupSummary>,
    pub target_health: Vec<TargetHealthObservation>,
    pub target_health_digest: Digest,
    pub topology_digest: Digest,
    pub health_digest: Digest,
    pub request_receipts: Vec<RequestReceipt>,
    pub cost_receipt: CostReceipt,
    pub provider_errors: Vec<ProviderErrorReceipt>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub evidence_digest: Digest,
    pub evidence_digests: EvidenceDigests,
    pub digests: EvidenceDigests,
    pub authority: EvidenceAuthority,
}

#[derive(Serialize)]
struct EvidenceBody<'a> {
    state: &'a EvidenceState,
    complete: bool,
    partial_reason: &'a Option<PartialReason>,
    provenance: ProviderProvenance,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_target_health_digest: &'a Digest,
    load_balancers: &'a [LoadBalancerSummary],
    target_groups: &'a [TargetGroupSummary],
    target_health: &'a [TargetHealthObservation],
    target_health_digest: &'a Digest,
    topology_digest: &'a Digest,
    health_digest: &'a Digest,
    request_receipts: &'a [RequestReceipt],
    cost_receipt: &'a CostReceipt,
    provider_errors: &'a [ProviderErrorReceipt],
    connected: bool,
    native: bool,
    first_party: bool,
    authority: &'a EvidenceAuthority,
}

impl AwsElbTargetHealthEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: EvidenceState,
        partial_reason: Option<PartialReason>,
        provenance: ProviderProvenance,
        scope: &AwsElbScope,
        registration: &AwsElbRegistration,
        load_balancers: Vec<LoadBalancerSummary>,
        target_groups: Vec<TargetGroupSummary>,
        target_health: Vec<TargetHealthObservation>,
        request_receipts: Vec<RequestReceipt>,
        provider_errors: Vec<ProviderErrorReceipt>,
    ) -> Self {
        let mut load_balancers = load_balancers;
        let mut target_groups = target_groups;
        let mut target_health = target_health;
        load_balancers.sort_by(|left, right| left.summary_digest.cmp(&right.summary_digest));
        target_groups.sort_by(|left, right| left.summary_digest.cmp(&right.summary_digest));
        target_health.sort_by(|left, right| left.observation_digest.cmp(&right.observation_digest));
        let topology_digest = digest_serialized(&(&load_balancers, &target_groups));
        let health_digest = digest_serialized(&target_health);
        let target_health_digest = Digest::from_parts(
            "aws-elb-target-health-evidence/v1",
            &[
                ("target_group", scope.target_group.digest().to_string()),
                ("health", health_digest.to_string()),
            ],
        );
        let request_digest = digest_serialized(
            &request_receipts
                .iter()
                .map(|receipt| receipt.request_digest.clone())
                .collect::<Vec<_>>(),
        );
        let cost_receipt = CostReceipt::from_requests(&request_receipts);
        let authority = EvidenceAuthority::layer_one();
        let complete = state.is_complete();
        let mut evidence = Self {
            state,
            complete,
            partial_reason,
            provenance,
            scope_digest: scope.scope_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            scope_target_health_digest: scope.target_health_digest.clone(),
            load_balancers,
            target_groups,
            target_health,
            target_health_digest: target_health_digest.clone(),
            topology_digest,
            health_digest,
            request_receipts,
            cost_receipt,
            provider_errors,
            connected: false,
            native: false,
            first_party: false,
            evidence_digest: Digest::zero(),
            evidence_digests: EvidenceDigests {
                plugin_version_digest: Digest::zero(),
                contract_digest: Digest::zero(),
                provider_digest: Digest::zero(),
                api_digest: Digest::zero(),
                permission_digest: Digest::zero(),
                scope_digest: Digest::zero(),
                load_balancer_digest: Digest::zero(),
                target_group_digest: Digest::zero(),
                target_health_digest: Digest::zero(),
                topology_digest: Digest::zero(),
                health_digest: Digest::zero(),
                request_digest: Digest::zero(),
                cost_digest: Digest::zero(),
                evidence_digest: Digest::zero(),
            },
            digests: EvidenceDigests {
                plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
                contract_digest: registration.contract_digest.clone(),
                provider_digest: registration.provider_digest.clone(),
                api_digest: registration.api_digest.clone(),
                permission_digest: scope.permission_digest.clone(),
                scope_digest: scope.scope_digest.clone(),
                load_balancer_digest: scope.load_balancer.digest(),
                target_group_digest: scope.target_group.digest(),
                target_health_digest,
                topology_digest: Digest::zero(),
                health_digest: Digest::zero(),
                request_digest,
                cost_digest: Digest::zero(),
                evidence_digest: Digest::zero(),
            },
            authority,
        };
        evidence.digests.topology_digest = evidence.topology_digest.clone();
        evidence.digests.health_digest = evidence.health_digest.clone();
        evidence.digests.cost_digest = evidence.cost_receipt.cost_digest.clone();
        evidence.evidence_digests = evidence.digests.clone();
        evidence.evidence_digest = evidence.recomputed_digest();
        evidence.evidence_digests.evidence_digest = evidence.evidence_digest.clone();
        evidence.digests.evidence_digest = evidence.evidence_digest.clone();
        evidence
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&EvidenceBody {
            state: &self.state,
            complete: self.complete,
            partial_reason: &self.partial_reason,
            provenance: self.provenance,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            scope_target_health_digest: &self.scope_target_health_digest,
            load_balancers: &self.load_balancers,
            target_groups: &self.target_groups,
            target_health: &self.target_health,
            target_health_digest: &self.target_health_digest,
            topology_digest: &self.topology_digest,
            health_digest: &self.health_digest,
            request_receipts: &self.request_receipts,
            cost_receipt: &self.cost_receipt,
            provider_errors: &self.provider_errors,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            authority: &self.authority,
        })
    }

    pub fn validate(
        &self,
        scope: &AwsElbScope,
        registration: &AwsElbRegistration,
    ) -> Result<(), AwsElbTargetHealthServiceError> {
        if self.evidence_digest != self.recomputed_digest()
            || self.evidence_digests != self.digests
            || self.evidence_digests.evidence_digest != self.evidence_digest
            || self.digests.evidence_digest != self.evidence_digest
            || self.scope_digest != scope.scope_digest
            || self.registration_digest != registration.registration_digest
            || self.scope_target_health_digest != scope.target_health_digest
            || self.scope_target_health_digest != registration.target_health_digest
            || self.digests.scope_digest != scope.scope_digest
            || self.digests.permission_digest != scope.permission_digest
            || self.digests.provider_digest != registration.provider_digest
            || self.digests.api_digest != registration.api_digest
            || self.digests.contract_digest != registration.contract_digest
            || self.digests.target_group_digest != scope.target_group.digest()
            || self.digests.load_balancer_digest != scope.load_balancer.digest()
            || self.target_health_digest != self.digests.target_health_digest
            || self.digests.target_health_digest.is_zero()
            || self.topology_digest != self.digests.topology_digest
            || self.health_digest != self.digests.health_digest
            || self.cost_receipt.cost_digest != self.digests.cost_digest
            || self.cost_receipt.cost_digest != self.cost_receipt.recomputed_digest()
            || !self.cost_receipt.redacted
            || self.cost_receipt.connected
            || self.cost_receipt.native
            || self.cost_receipt.first_party
            || self.complete != self.state.is_complete()
            || self.connected
            || self.native
            || self.first_party
        {
            return Err(AwsElbTargetHealthServiceError::EvidenceTampered);
        }
        if !self.authority.read_only
            || !self.authority.proposal_only
            || self.authority.external_writes
            || self.authority.connected
            || self.authority.native
            || self.authority.first_party
            || self.authority.availability_certification
            || self.authority.truth_authority
            || self.authority.durable_receipt
            || self.authority.work_product_adoption
        {
            return Err(AwsElbTargetHealthServiceError::EvidenceTampered);
        }
        if self.request_receipts.iter().any(|receipt| {
            !receipt.redacted
                || receipt.response_bytes > crate::model::MAX_RESPONSE_BYTES
                || receipt.raw_path_retained
                || receipt.raw_headers_retained
                || receipt.raw_body_retained
                || receipt.connected
                || receipt.native
                || receipt.first_party
                || receipt.receipt_digest != receipt.recomputed_digest()
        }) || self
            .provider_errors
            .iter()
            .any(|error| error.raw_error_retained)
        {
            return Err(AwsElbTargetHealthServiceError::EvidenceTampered);
        }
        if self
            .load_balancers
            .iter()
            .any(|load_balancer| load_balancer.summary_digest != load_balancer.recomputed_digest())
            || self.target_groups.iter().any(|target_group| {
                target_group.summary_digest != target_group.recomputed_digest()
                    || target_group.health_check.summary_digest
                        != target_group.health_check.recomputed_digest()
            })
            || self.target_health.iter().any(|observation| {
                observation.observation_digest != observation.recomputed_digest()
            })
        {
            return Err(AwsElbTargetHealthServiceError::EvidenceTampered);
        }
        if let Some(targets) = &scope.target_allowlist
            && self
                .target_health
                .iter()
                .any(|observation| !targets.contains(&observation.target_id_digest))
        {
            return Err(AwsElbTargetHealthServiceError::ProjectionDrift);
        }
        if self.target_health.len() > crate::model::MAX_TARGETS
            || self.load_balancers.len() > crate::model::MAX_LOAD_BALANCERS
            || self.target_groups.len() > crate::model::MAX_TARGET_GROUPS
        {
            return Err(AwsElbTargetHealthServiceError::EvidenceTampered);
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElbReadResult {
    pub evidence: AwsElbTargetHealthEvidence,
    pub read_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElbTargetHealthProposal {
    pub state: EvidenceState,
    pub evidence: AwsElbTargetHealthEvidence,
    pub proposed_at: DateTime<Utc>,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub availability_certification: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
}

#[derive(Serialize)]
struct ProposalBody<'a> {
    state: &'a EvidenceState,
    evidence: &'a AwsElbTargetHealthEvidence,
    proposed_at: &'a DateTime<Utc>,
    registration_digest: &'a Digest,
    read_only: bool,
    live_execution: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    availability_certification: bool,
    adopted_outcome: bool,
    truth_authority: bool,
}

impl AwsElbTargetHealthProposal {
    fn new(
        evidence: AwsElbTargetHealthEvidence,
        proposed_at: DateTime<Utc>,
        registration_digest: Digest,
    ) -> Self {
        let mut value = Self {
            state: evidence.state.clone(),
            evidence,
            proposed_at,
            registration_digest,
            proposal_digest: Digest::zero(),
            read_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            availability_certification: false,
            adopted_outcome: false,
            truth_authority: false,
        };
        value.proposal_digest = value.recomputed_digest();
        value
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&ProposalBody {
            state: &self.state,
            evidence: &self.evidence,
            proposed_at: &self.proposed_at,
            registration_digest: &self.registration_digest,
            read_only: self.read_only,
            live_execution: self.live_execution,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            availability_certification: self.availability_certification,
            adopted_outcome: self.adopted_outcome,
            truth_authority: self.truth_authority,
        })
    }

    pub fn validate(
        &self,
        scope: &AwsElbScope,
        registration: &AwsElbRegistration,
    ) -> Result<(), AwsElbTargetHealthServiceError> {
        self.evidence.validate(scope, registration)?;
        if self.state != self.evidence.state
            || self.registration_digest != registration.registration_digest
            || !self.read_only
            || self.live_execution
            || self.connected
            || self.native
            || self.first_party
            || self.availability_certification
            || self.adopted_outcome
            || self.truth_authority
            || self.proposal_digest != self.recomputed_digest()
        {
            Err(AwsElbTargetHealthServiceError::ProposalTampered)
        } else {
            Ok(())
        }
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElbRecordReceipt {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub state: EvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub cost_digest: Digest,
    pub raw_provider_payload_retained: bool,
    pub durable_provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub availability_certification: bool,
    pub receipt_digest: Digest,
}

#[derive(Serialize)]
struct RecordBody<'a> {
    recorded: bool,
    recorded_at: &'a DateTime<Utc>,
    state: &'a EvidenceState,
    proposal_digest: &'a Digest,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    request_digest: &'a Digest,
    cost_digest: &'a Digest,
    raw_provider_payload_retained: bool,
    durable_provider_receipt: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    availability_certification: bool,
}

impl AwsElbRecordReceipt {
    fn new(proposal: &AwsElbTargetHealthProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut value = Self {
            recorded: true,
            recorded_at,
            state: proposal.state.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digests.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.evidence.digests.scope_digest.clone(),
            request_digest: proposal.evidence.digests.request_digest.clone(),
            cost_digest: proposal.evidence.digests.cost_digest.clone(),
            raw_provider_payload_retained: false,
            durable_provider_receipt: false,
            connected: false,
            native: false,
            first_party: false,
            availability_certification: false,
            receipt_digest: Digest::zero(),
        };
        value.receipt_digest = value.recomputed_digest();
        value
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serialized(&RecordBody {
            recorded: self.recorded,
            recorded_at: &self.recorded_at,
            state: &self.state,
            proposal_digest: &self.proposal_digest,
            evidence_digest: &self.evidence_digest,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            request_digest: &self.request_digest,
            cost_digest: &self.cost_digest,
            raw_provider_payload_retained: self.raw_provider_payload_retained,
            durable_provider_receipt: self.durable_provider_receipt,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            availability_certification: self.availability_certification,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElbVerifiedRecord {
    pub verified: bool,
    pub state: EvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub availability_certification: bool,
    pub adopted_outcome: bool,
}

#[derive(Clone)]
pub struct AwsElbTargetHealthService<T>
where
    T: AwsElbTransport,
{
    scope: AwsElbScope,
    secret_reference: SigV4SecretReference,
    permission: PermissionFence,
    provider: AwsElbProvider<T>,
    registration: AwsElbRegistration,
    recorded_proposals: BTreeSet<Digest>,
}

impl<T> fmt::Debug for AwsElbTargetHealthService<T>
where
    T: AwsElbTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsElbTargetHealthService")
            .field("scope_digest", &self.scope.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("permission_digest", &self.permission.digest())
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("recorded_proposals", &self.recorded_proposals)
            .finish()
    }
}

impl<T> AwsElbTargetHealthService<T>
where
    T: AwsElbTransport,
{
    pub fn register(
        scope: AwsElbScope,
        secret_reference: SigV4SecretReference,
        permission: PermissionFence,
        provider: AwsElbProvider<T>,
    ) -> Result<Self, AwsElbTargetHealthServiceError> {
        Self::new(scope, secret_reference, permission, provider)
    }

    pub fn new(
        scope: AwsElbScope,
        secret_reference: SigV4SecretReference,
        permission: PermissionFence,
        provider: AwsElbProvider<T>,
    ) -> Result<Self, AwsElbTargetHealthServiceError> {
        scope
            .validate()
            .map_err(|error| AwsElbTargetHealthServiceError::Scope(error.to_string()))?;
        if !permission.is_layer_one_complete() || permission.digest() != scope.permission_digest {
            return Err(AwsElbTargetHealthServiceError::PermissionLoss);
        }
        if secret_reference.service() != "elasticloadbalancing"
            || secret_reference.region() != &scope.region
            || secret_reference.digest() != scope.secret_reference_digest
            || (!secret_reference.scope_binding_digest().is_zero()
                && secret_reference.scope_binding_digest() != &scope.scope_digest)
        {
            return Err(AwsElbTargetHealthServiceError::SecretReferenceMismatch);
        }
        provider.definition().validate()?;
        let registration =
            AwsElbRegistration::new(&scope, &secret_reference, provider.definition())?;
        Ok(Self {
            scope,
            secret_reference,
            permission,
            provider,
            registration,
            recorded_proposals: BTreeSet::new(),
        })
    }

    pub const fn describe_capabilities() -> AwsElbTargetHealthCapabilities {
        AwsElbTargetHealthCapabilities::layer_one()
    }

    pub fn capabilities(&self) -> AwsElbTargetHealthCapabilities {
        Self::describe_capabilities()
    }

    pub fn scope(&self) -> &AwsElbScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SigV4SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsElbProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsElbProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsElbRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn reverse_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AwsElbTargetHealthServiceError> {
        self.registration.reverse()
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AwsElbTargetHealthServiceError> {
        self.registration.restore()
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AwsElbTargetHealthServiceError> {
        self.registration.revoke()
    }

    pub fn read(&mut self) -> Result<AwsElbReadResult, AwsElbTargetHealthServiceError> {
        self.read_with_bounds(ReadBounds::default())
    }

    pub fn read_bounded(
        &mut self,
        max_pages: u16,
    ) -> Result<AwsElbReadResult, AwsElbTargetHealthServiceError> {
        let bounds = ReadBounds {
            max_pages,
            ..ReadBounds::default()
        };
        self.read_with_bounds(bounds)
    }

    pub fn read_with_bounds(
        &mut self,
        bounds: ReadBounds,
    ) -> Result<AwsElbReadResult, AwsElbTargetHealthServiceError> {
        bounds
            .validate()
            .map_err(|error| AwsElbTargetHealthServiceError::Request(error.to_string()))?;
        self.ensure_active()?;
        let provenance = self.provider.provenance();
        let mut requests = Vec::new();
        let mut provider_errors = Vec::new();

        let mut load_balancers = Vec::new();
        let mut marker = None;
        let mut seen_markers = BTreeSet::new();
        let mut previous_request = None;
        loop {
            let request =
                AwsElbReadRequest::describe_load_balancers(&self.scope, bounds, marker.clone())?;
            if requests.len() >= usize::from(bounds.max_requests) {
                return Ok(self.failure_result(
                    EvidenceState::Partial,
                    Some(PartialReason::PageBudget),
                    provenance,
                    requests,
                    provider_errors,
                    load_balancers,
                    Vec::new(),
                    Vec::new(),
                ));
            }
            if let Some(previous) = previous_request.as_ref()
                && request
                    .marker
                    .as_ref()
                    .and_then(|value| value.binding_digest())
                    != Some(previous)
            {
                return Ok(self.failure_result(
                    EvidenceState::Replay,
                    Some(PartialReason::MarkerReplay),
                    provenance,
                    requests,
                    provider_errors,
                    load_balancers,
                    Vec::new(),
                    Vec::new(),
                ));
            }
            match self.provider.describe_load_balancers(&request) {
                Ok(page) => {
                    requests.push(RequestReceipt::new(
                        &request,
                        page.response_bytes,
                        provenance,
                    ));
                    if page.response_bytes > bounds.max_response_bytes {
                        return Ok(self.failure_result(
                            EvidenceState::Partial,
                            Some(PartialReason::ResponseTooLarge),
                            provenance,
                            requests,
                            provider_errors,
                            load_balancers,
                            Vec::new(),
                            Vec::new(),
                        ));
                    }
                    load_balancers.extend(page.load_balancers);
                    if load_balancers.len() > crate::model::MAX_LOAD_BALANCERS {
                        return Ok(self.failure_result(
                            EvidenceState::Partial,
                            Some(PartialReason::PageBudget),
                            provenance,
                            requests,
                            provider_errors,
                            load_balancers,
                            Vec::new(),
                            Vec::new(),
                        ));
                    }
                    previous_request = Some(request.request_digest.clone());
                    marker = page
                        .next_marker
                        .map(|value| value.bind(&request.request_digest, page.page_number))
                        .transpose()?;
                    if let Some(marker_value) = &marker {
                        if !seen_markers.insert(marker_value.digest()) {
                            return Ok(self.failure_result(
                                EvidenceState::Partial,
                                Some(PartialReason::MarkerLoop),
                                provenance,
                                requests,
                                provider_errors,
                                load_balancers,
                                Vec::new(),
                                Vec::new(),
                            ));
                        }
                        if page.page_number >= bounds.max_pages {
                            return Ok(self.failure_result(
                                EvidenceState::Partial,
                                Some(PartialReason::PageBudget),
                                provenance,
                                requests,
                                provider_errors,
                                load_balancers,
                                Vec::new(),
                                Vec::new(),
                            ));
                        }
                    } else {
                        break;
                    }
                }
                Err(error) => {
                    provider_errors.push(provider_error_receipt(&request, &error));
                    return Ok(self.failure_result(
                        error.evidence_state(),
                        partial_reason_for_provider_error(&error),
                        provenance,
                        requests,
                        provider_errors,
                        load_balancers,
                        Vec::new(),
                        Vec::new(),
                    ));
                }
            }
        }

        if let Err(reason) = self.validate_load_balancer_projection(&load_balancers) {
            return Ok(self.failure_result(
                EvidenceState::ScopeDrift,
                Some(reason),
                provenance,
                requests,
                provider_errors,
                load_balancers,
                Vec::new(),
                Vec::new(),
            ));
        }

        let mut target_groups = Vec::new();
        marker = None;
        seen_markers.clear();
        previous_request = None;
        loop {
            let request =
                AwsElbReadRequest::describe_target_groups(&self.scope, bounds, marker.clone())?;
            if requests.len() >= usize::from(bounds.max_requests) {
                return Ok(self.failure_result(
                    EvidenceState::Partial,
                    Some(PartialReason::PageBudget),
                    provenance,
                    requests,
                    provider_errors,
                    load_balancers,
                    target_groups,
                    Vec::new(),
                ));
            }
            if let Some(previous) = previous_request.as_ref()
                && request
                    .marker
                    .as_ref()
                    .and_then(|value| value.binding_digest())
                    != Some(previous)
            {
                return Ok(self.failure_result(
                    EvidenceState::Replay,
                    Some(PartialReason::MarkerReplay),
                    provenance,
                    requests,
                    provider_errors,
                    load_balancers,
                    target_groups,
                    Vec::new(),
                ));
            }
            match self.provider.describe_target_groups(&request) {
                Ok(page) => {
                    requests.push(RequestReceipt::new(
                        &request,
                        page.response_bytes,
                        provenance,
                    ));
                    if page.response_bytes > bounds.max_response_bytes {
                        return Ok(self.failure_result(
                            EvidenceState::Partial,
                            Some(PartialReason::ResponseTooLarge),
                            provenance,
                            requests,
                            provider_errors,
                            load_balancers,
                            target_groups,
                            Vec::new(),
                        ));
                    }
                    target_groups.extend(page.target_groups);
                    if target_groups.len() > crate::model::MAX_TARGET_GROUPS {
                        return Ok(self.failure_result(
                            EvidenceState::Partial,
                            Some(PartialReason::PageBudget),
                            provenance,
                            requests,
                            provider_errors,
                            load_balancers,
                            target_groups,
                            Vec::new(),
                        ));
                    }
                    previous_request = Some(request.request_digest.clone());
                    marker = page
                        .next_marker
                        .map(|value| value.bind(&request.request_digest, page.page_number))
                        .transpose()?;
                    if let Some(marker_value) = &marker {
                        if !seen_markers.insert(marker_value.digest()) {
                            return Ok(self.failure_result(
                                EvidenceState::Partial,
                                Some(PartialReason::MarkerLoop),
                                provenance,
                                requests,
                                provider_errors,
                                load_balancers,
                                target_groups,
                                Vec::new(),
                            ));
                        }
                        if page.page_number >= bounds.max_pages {
                            return Ok(self.failure_result(
                                EvidenceState::Partial,
                                Some(PartialReason::PageBudget),
                                provenance,
                                requests,
                                provider_errors,
                                load_balancers,
                                target_groups,
                                Vec::new(),
                            ));
                        }
                    } else {
                        break;
                    }
                }
                Err(error) => {
                    provider_errors.push(provider_error_receipt(&request, &error));
                    return Ok(self.failure_result(
                        error.evidence_state(),
                        partial_reason_for_provider_error(&error),
                        provenance,
                        requests,
                        provider_errors,
                        load_balancers,
                        target_groups,
                        Vec::new(),
                    ));
                }
            }
        }

        if let Err(reason) = self.validate_target_group_projection(&target_groups) {
            return Ok(self.failure_result(
                EvidenceState::TargetGroupDrift,
                Some(reason),
                provenance,
                requests,
                provider_errors,
                load_balancers,
                target_groups,
                Vec::new(),
            ));
        }

        let health_request = AwsElbReadRequest::describe_target_health(&self.scope, bounds)?;
        if requests.len() >= usize::from(bounds.max_requests) {
            return Ok(self.failure_result(
                EvidenceState::Partial,
                Some(PartialReason::PageBudget),
                provenance,
                requests,
                provider_errors,
                load_balancers,
                target_groups,
                Vec::new(),
            ));
        }
        let health_page = match self.provider.describe_target_health(&health_request) {
            Ok(page) => {
                requests.push(RequestReceipt::new(
                    &health_request,
                    page.response_bytes,
                    provenance,
                ));
                page
            }
            Err(error) => {
                provider_errors.push(provider_error_receipt(&health_request, &error));
                return Ok(self.failure_result(
                    error.evidence_state(),
                    partial_reason_for_provider_error(&error),
                    provenance,
                    requests,
                    provider_errors,
                    load_balancers,
                    target_groups,
                    Vec::new(),
                ));
            }
        };
        if health_page.response_bytes > bounds.max_response_bytes {
            return Ok(self.failure_result(
                EvidenceState::Partial,
                Some(PartialReason::ResponseTooLarge),
                provenance,
                requests,
                provider_errors,
                load_balancers,
                target_groups,
                Vec::new(),
            ));
        }
        if health_page.target_group_revision != self.scope.target_group.revision {
            return Ok(self.failure_result(
                EvidenceState::TargetGroupDrift,
                Some(PartialReason::TargetGroupDrift),
                provenance,
                requests,
                provider_errors,
                load_balancers,
                target_groups,
                health_page.observations,
            ));
        }
        if let Some(targets) = &self.scope.target_allowlist
            && health_page
                .observations
                .iter()
                .any(|observation| !targets.contains(&observation.target_id_digest))
        {
            return Ok(self.failure_result(
                EvidenceState::ScopeDrift,
                Some(PartialReason::ScopeDrift),
                provenance,
                requests,
                provider_errors,
                load_balancers,
                target_groups,
                health_page.observations,
            ));
        }
        if health_page.observations.len() > bounds.max_targets {
            return Ok(self.failure_result(
                EvidenceState::Partial,
                Some(PartialReason::PageBudget),
                provenance,
                requests,
                provider_errors,
                load_balancers,
                target_groups,
                health_page.observations,
            ));
        }

        let state = health_state(&health_page, bounds.max_observation_age_seconds);
        let reason = match state {
            EvidenceState::Stale => Some(PartialReason::Stale),
            EvidenceState::Initial => Some(PartialReason::Initial),
            EvidenceState::Unavailable => Some(PartialReason::Unavailable),
            EvidenceState::Partial => Some(PartialReason::PartialHealth),
            _ => None,
        };
        let result = self.success_result(
            state,
            reason,
            provenance,
            requests,
            provider_errors,
            load_balancers,
            target_groups,
            health_page.observations,
        );
        Ok(result)
    }

    pub fn read_request(
        &mut self,
        bounds: ReadBounds,
    ) -> Result<AwsElbReadResult, AwsElbTargetHealthServiceError> {
        self.read_with_bounds(bounds)
    }

    pub fn propose(
        &mut self,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsElbTargetHealthProposal, AwsElbTargetHealthServiceError> {
        let read = self.read()?;
        Ok(AwsElbTargetHealthProposal::new(
            read.evidence,
            proposed_at,
            self.registration.registration_digest.clone(),
        ))
    }

    pub fn propose_at(
        &mut self,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsElbTargetHealthProposal, AwsElbTargetHealthServiceError> {
        self.propose(proposed_at)
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsElbTargetHealthProposal,
    ) -> Result<(), AwsElbTargetHealthServiceError> {
        self.ensure_active()?;
        self.registration.verify()?;
        proposal.validate(&self.scope, &self.registration)
    }

    pub fn record_at(
        &mut self,
        proposal: &AwsElbTargetHealthProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsElbRecordReceipt, AwsElbTargetHealthServiceError> {
        self.verify_proposal(proposal)?;
        if !self
            .recorded_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(AwsElbTargetHealthServiceError::Replay);
        }
        Ok(AwsElbRecordReceipt::new(proposal, recorded_at))
    }

    pub fn record(
        &mut self,
        proposal: &AwsElbTargetHealthProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsElbRecordReceipt, AwsElbTargetHealthServiceError> {
        self.record_at(proposal, recorded_at)
    }

    pub fn verify(
        &self,
        receipt: &AwsElbRecordReceipt,
    ) -> Result<AwsElbVerifiedRecord, AwsElbTargetHealthServiceError> {
        self.ensure_active()?;
        self.registration.verify()?;
        if receipt.receipt_digest != receipt.recomputed_digest()
            || !receipt.recorded
            || receipt.connected
            || receipt.native
            || receipt.first_party
            || receipt.raw_provider_payload_retained
            || receipt.durable_provider_receipt
            || receipt.availability_certification
            || receipt.registration_digest != self.registration.registration_digest
            || receipt.scope_digest != self.scope.scope_digest
        {
            return Err(AwsElbTargetHealthServiceError::RecordTampered);
        }
        let verification_digest = digest_serialized(&(
            &receipt.receipt_digest,
            &receipt.proposal_digest,
            &receipt.evidence_digest,
            &self.registration.registration_digest,
        ));
        Ok(AwsElbVerifiedRecord {
            verified: true,
            state: receipt.state.clone(),
            proposal_digest: receipt.proposal_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            verification_digest,
            connected: false,
            native: false,
            first_party: false,
            availability_certification: false,
            adopted_outcome: false,
        })
    }

    fn ensure_active(&self) -> Result<(), AwsElbTargetHealthServiceError> {
        self.registration.verify()?;
        let provider = self.provider.definition();
        if self.registration.permission_digest != self.permission.digest()
            || self.registration.permission_digest != self.scope.permission_digest
            || self.registration.scope_digest != self.scope.scope_digest
            || self.registration.target_group_digest != self.scope.target_group.digest()
            || self.registration.target_group_revision != self.scope.target_group.revision
            || self.registration.target_health_digest != self.scope.target_health_digest
            || self.registration.secret_reference_digest != self.secret_reference.digest()
            || self.registration.provider_digest != provider.provider_digest
            || self.registration.api_digest != provider.api_digest
        {
            return Err(AwsElbTargetHealthServiceError::RegistrationTampered);
        }
        match self.registration.state {
            RegistrationState::Active => Ok(()),
            RegistrationState::Reversed => {
                Err(AwsElbTargetHealthServiceError::RegistrationReversed)
            }
            RegistrationState::Revoked => Err(AwsElbTargetHealthServiceError::RegistrationRevoked),
        }
    }

    fn validate_load_balancer_projection(
        &self,
        load_balancers: &[LoadBalancerSummary],
    ) -> Result<(), PartialReason> {
        let expected = self.scope.load_balancer.arn.digest();
        let matches = load_balancers
            .iter()
            .filter(|load_balancer| load_balancer.arn_digest == expected)
            .collect::<Vec<_>>();
        if matches.len() != 1 || matches[0].revision != self.scope.load_balancer.revision {
            return Err(PartialReason::ScopeDrift);
        }
        if matches[0].state != LoadBalancerState::Active {
            return Err(PartialReason::Unavailable);
        }
        if let Some(zones) = &self.scope.availability_zones
            && zones.iter().any(|zone| {
                !matches[0]
                    .availability_zone_digests
                    .contains(&zone.digest())
            })
        {
            return Err(PartialReason::ScopeDrift);
        }
        Ok(())
    }

    fn validate_target_group_projection(
        &self,
        target_groups: &[TargetGroupSummary],
    ) -> Result<(), PartialReason> {
        let expected = self.scope.target_group.arn.digest();
        let matches = target_groups
            .iter()
            .filter(|target_group| target_group.arn_digest == expected)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(PartialReason::TargetGroupDrift);
        }
        let target_group = matches[0];
        if target_group.revision != self.scope.target_group.revision
            || target_group.target_group_type != self.scope.target_group.target_group_type
            || !target_group
                .load_balancer_arn_digests
                .contains(&self.scope.load_balancer.arn.digest())
            || self
                .scope
                .target_port
                .is_some_and(|port| target_group.port != Some(port))
            || (!self.scope.health_check_digest.is_zero()
                && target_group.health_check.summary_digest != self.scope.health_check_digest)
        {
            return Err(PartialReason::TargetGroupDrift);
        }
        if target_group.state != TargetGroupState::Active {
            return Err(PartialReason::Unavailable);
        }
        Ok(())
    }

    fn success_result(
        &self,
        state: EvidenceState,
        reason: Option<PartialReason>,
        provenance: ProviderProvenance,
        requests: Vec<RequestReceipt>,
        provider_errors: Vec<ProviderErrorReceipt>,
        load_balancers: Vec<LoadBalancerSummary>,
        target_groups: Vec<TargetGroupSummary>,
        target_health: Vec<TargetHealthObservation>,
    ) -> AwsElbReadResult {
        let evidence = AwsElbTargetHealthEvidence::new(
            state,
            reason,
            provenance,
            &self.scope,
            &self.registration,
            load_balancers,
            target_groups,
            target_health,
            requests,
            provider_errors,
        );
        let read_digest = evidence.digests.evidence_digest.clone();
        AwsElbReadResult {
            evidence,
            read_digest,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn failure_result(
        &self,
        state: EvidenceState,
        reason: Option<PartialReason>,
        provenance: ProviderProvenance,
        requests: Vec<RequestReceipt>,
        provider_errors: Vec<ProviderErrorReceipt>,
        load_balancers: Vec<LoadBalancerSummary>,
        target_groups: Vec<TargetGroupSummary>,
        target_health: Vec<TargetHealthObservation>,
    ) -> AwsElbReadResult {
        self.success_result(
            state,
            reason,
            provenance,
            requests,
            provider_errors,
            load_balancers,
            target_groups,
            target_health,
        )
    }
}

pub type AwsElbService<T> = AwsElbTargetHealthService<T>;
pub type AwsElbTargetHealthServiceDefinition = AwsElbTargetHealthCapabilities;
pub type AwsElbHealthProposal = AwsElbTargetHealthProposal;
pub type AwsElbHealthEvidence = AwsElbTargetHealthEvidence;

fn provider_error_receipt(
    request: &AwsElbReadRequest,
    error: &ProviderError,
) -> ProviderErrorReceipt {
    match error {
        ProviderError::Transport(transport) => ProviderErrorReceipt {
            operation: request.operation,
            failure: transport.failure,
            status_code: transport.status_code,
            request_digest: request.request_digest.clone(),
            error_digest: transport.error_digest.clone(),
            raw_error_retained: false,
        },
        _ => ProviderErrorReceipt {
            operation: request.operation,
            failure: TransportFailure::ProviderUnknown,
            status_code: None,
            request_digest: request.request_digest.clone(),
            error_digest: Digest::from_text(error.to_string()),
            raw_error_retained: false,
        },
    }
}

fn partial_reason_for_provider_error(error: &ProviderError) -> Option<PartialReason> {
    match error {
        ProviderError::Transport(transport) => Some(match transport.failure {
            TransportFailure::BadRequest => PartialReason::BadRequest,
            TransportFailure::Unauthorized => PartialReason::Unauthorized,
            TransportFailure::Forbidden => PartialReason::Forbidden,
            TransportFailure::NotFound => PartialReason::NotFound,
            TransportFailure::Conflict => PartialReason::Conflict,
            TransportFailure::Throttled => PartialReason::Throttled,
            TransportFailure::ServerFailure => PartialReason::ServerFailure,
            TransportFailure::Timeout => PartialReason::Timeout,
            TransportFailure::ProviderUnknown => PartialReason::ProviderUnknown,
        }),
        ProviderError::RequestMismatch | ProviderError::UnsupportedOperation => {
            Some(PartialReason::ProviderUnknown)
        }
        ProviderError::ScopeMismatch => Some(PartialReason::ScopeDrift),
        ProviderError::TargetGroupMismatch => Some(PartialReason::TargetGroupDrift),
        ProviderError::PageTampered => Some(PartialReason::Tampered),
        ProviderError::ResponseTooLarge => Some(PartialReason::ResponseTooLarge),
        ProviderError::PageBudget => Some(PartialReason::PageBudget),
        ProviderError::MarkerReplay => Some(PartialReason::MarkerReplay),
    }
}

fn health_state(page: &DescribeTargetHealthPage, max_age_seconds: i64) -> EvidenceState {
    if page.collection_state == TargetHealthCollectionState::Stale
        || (Utc::now() - page.observed_at).num_seconds() > max_age_seconds
    {
        return EvidenceState::Stale;
    }
    match page.collection_state {
        TargetHealthCollectionState::Initial => EvidenceState::Initial,
        TargetHealthCollectionState::Unavailable => EvidenceState::Unavailable,
        TargetHealthCollectionState::Partial => EvidenceState::Partial,
        TargetHealthCollectionState::Stale => EvidenceState::Stale,
        TargetHealthCollectionState::Fresh => {
            if page.observations.is_empty() {
                EvidenceState::Unavailable
            } else if page
                .observations
                .iter()
                .any(|observation| observation.state == TargetHealthState::Initial)
            {
                EvidenceState::Initial
            } else if page
                .observations
                .iter()
                .any(|observation| observation.state.is_fail_closed())
            {
                EvidenceState::Unavailable
            } else if page
                .observations
                .iter()
                .any(|observation| observation.state == TargetHealthState::Unhealthy)
            {
                EvidenceState::Unhealthy
            } else {
                EvidenceState::Healthy
            }
        }
    }
}

#[allow(dead_code)]
fn _keep_service_surface_typed(
    _scope: &AwsElbScope,
    _health_check: Option<&HealthCheckSummary>,
    _page: Option<&DescribeLoadBalancersPage>,
    _groups: Option<&DescribeTargetGroupsPage>,
) {
    let _ = (CONSUMER_ID, PLUGIN_VERSION);
}
