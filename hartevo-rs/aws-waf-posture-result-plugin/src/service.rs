//! Bounded AWS WAF read, proposal, recording, and verification service.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_WAF_POSTURE_API_REVISION, AWS_WAF_POSTURE_CONSUMER_ID, AWS_WAF_POSTURE_CONTRACT_VERSION,
    AWS_WAF_POSTURE_PLUGIN_VERSION, AWS_WAF_POSTURE_PROVIDER_ID, AWS_WAF_POSTURE_SCHEMA_VERSION,
    AWS_WAF_POSTURE_SERVICE_VERSION, MAX_PAGES, MAX_REQUESTS_PER_READ, MAX_RESPONSE_BYTES,
    model::{
        AssociationProjection, AwsWafPostureScope, Digest, EvidenceState, ModelError,
        RedactionSummary, ResourceReference, RuleActionEvidence, SecretReference,
        TransportProvenance, WafDecisionState, WafDeploymentDecision, WebAclPostureProjection,
        WebAclReference, digest_serializable,
    },
    provider::{
        AwsWafPostureProvider, AwsWafProviderDefinition, AwsWafProviderError, AwsWafTransport,
        GetWebAclRequest, ListResourcesForWebAclRequest, ListWebAclsRequest, TransportError,
    },
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityBoundary {
    pub truth: bool,
    pub consent: bool,
    pub effect: bool,
    pub receipt: bool,
    pub verification: bool,
    pub outcome: bool,
    pub credential_resolution: bool,
    pub native_sigv4: bool,
    pub live_https: bool,
    pub waf_mutation: bool,
    pub sampled_request_read: bool,
}

impl AuthorityBoundary {
    pub const fn layer_one() -> Self {
        Self {
            truth: false,
            consent: false,
            effect: false,
            receipt: false,
            verification: false,
            outcome: false,
            credential_resolution: false,
            native_sigv4: false,
            live_https: false,
            waf_mutation: false,
            sampled_request_read: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsWafPostureServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub operations: [String; 7],
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub authority: AuthorityBoundary,
}

pub type ServiceDefinition = AwsWafPostureServiceDefinition;

impl Default for AwsWafPostureServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: AWS_WAF_POSTURE_SCHEMA_VERSION.to_owned(),
            contract_version: AWS_WAF_POSTURE_CONTRACT_VERSION.to_owned(),
            version: AWS_WAF_POSTURE_SERVICE_VERSION.to_owned(),
            service_id: crate::AWS_WAF_POSTURE_SERVICE_ID.to_owned(),
            provider_id: AWS_WAF_POSTURE_PROVIDER_ID.to_owned(),
            consumer_id: AWS_WAF_POSTURE_CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            operations: [
                "describe_capabilities".to_owned(),
                "register".to_owned(),
                "revoke_registration".to_owned(),
                "read_bounded".to_owned(),
                "propose".to_owned(),
                "record".to_owned(),
                "verify".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            live_execution: false,
            external_writes: false,
            authority: AuthorityBoundary::layer_one(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error("AWS WAF service model error: {0}")]
    Model(#[from] ModelError),
    #[error("AWS WAF provider error: {0}")]
    Provider(#[from] AwsWafProviderError),
    #[error("AWS WAF registration is revoked")]
    RegistrationRevoked,
    #[error("AWS WAF SecretReference is revoked")]
    SecretRevoked,
    #[error("AWS WAF registration digest or binding drifted")]
    RegistrationDrift,
    #[error("AWS WAF scope or permission fence failed")]
    ScopeMismatch,
    #[error("AWS WAF evidence is tampered or stale")]
    EvidenceTampered,
    #[error("AWS WAF proposal is tampered or stale")]
    ProposalTampered,
    #[error("AWS WAF record is tampered or stale")]
    RecordTampered,
    #[error("AWS WAF pagination cursor replay or loop was detected")]
    PaginationLoop,
    #[error("AWS WAF pagination exceeded the Layer-1 bound")]
    PaginationBound,
    #[error("AWS WAF recording idempotency key conflicts with another proposal")]
    RecordingConflict,
    #[error("AWS WAF registration lifecycle operation is not reversible")]
    NotReversible,
    #[error("AWS WAF registration lifecycle revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsWafPostureRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: crate::Revision,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
    pub registration_digest: Digest,
}

pub type AwsWafRegistration = AwsWafPostureRegistration;
pub type Registration = AwsWafPostureRegistration;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationMaterial<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a str,
    provider_version: &'a str,
    api_revision: &'a str,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    evidence_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: crate::Revision,
    state: RegistrationState,
    reversible: bool,
    revocable: bool,
}

impl AwsWafPostureRegistration {
    pub fn bind(
        scope: &AwsWafPostureScope,
        secret: &SecretReference,
        provider: &AwsWafProviderDefinition,
    ) -> Result<Self, ServiceError> {
        scope.validate()?;
        if secret.scope_digest() != &scope.digest() || secret.region() != &scope.region {
            return Err(ServiceError::ScopeMismatch);
        }
        let evidence_digest = Digest::from_parts(
            "aws-waf-posture-evidence-policy/v1",
            &[
                AWS_WAF_POSTURE_CONTRACT_VERSION.to_owned(),
                MAX_RESPONSE_BYTES.to_string(),
                MAX_PAGES.to_string(),
                MAX_REQUESTS_PER_READ.to_string(),
                "default_action_rule_class_association_digests_only".to_owned(),
            ],
        );
        let mut registration = Self {
            plugin_version: AWS_WAF_POSTURE_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_WAF_POSTURE_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            api_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest(),
            api_digest: Digest::from_text(AWS_WAF_POSTURE_API_REVISION),
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.digest(),
            evidence_digest,
            secret_reference_digest: secret.digest(),
            registration_revision: crate::Revision::new(1)?,
            state: RegistrationState::Active,
            reversible: true,
            revocable: true,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serializable(&RegistrationMaterial {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_version: &self.provider_version,
            api_revision: &self.api_revision,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            evidence_digest: &self.evidence_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registration_revision: self.registration_revision,
            state: self.state,
            reversible: self.reversible,
            revocable: self.revocable,
        })
    }

    pub fn validate(
        &self,
        scope: &AwsWafPostureScope,
        secret: &SecretReference,
        provider: &AwsWafProviderDefinition,
    ) -> Result<(), ServiceError> {
        scope.validate()?;
        if self.state != RegistrationState::Active {
            return Err(ServiceError::RegistrationRevoked);
        }
        if self.plugin_version != AWS_WAF_POSTURE_PLUGIN_VERSION
            || self.contract_version != AWS_WAF_POSTURE_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.provider_version
            || self.api_revision != provider.api_revision
            || self.provider_digest != provider.provider_digest()
            || self.api_digest != Digest::from_text(AWS_WAF_POSTURE_API_REVISION)
            || self.permission_digest != *scope.permission_digest()
            || self.scope_digest != scope.digest()
            || self.secret_reference_digest != secret.digest()
            || !self.reversible
            || !self.revocable
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(ServiceError::RegistrationDrift);
        }
        if secret.is_revoked() {
            return Err(ServiceError::SecretRevoked);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ServiceError> {
        if !self.revocable {
            return Err(ServiceError::NotReversible);
        }
        if self.state == RegistrationState::Revoked {
            return Err(ServiceError::RegistrationRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = self
            .registration_revision
            .next()
            .map_err(|_| ServiceError::RevisionOverflow)?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationRevocation {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: self.reversible,
            revocable: self.revocable,
            connected: false,
            native: false,
        })
    }

    pub fn restore(&mut self) -> Result<(), ServiceError> {
        if !self.reversible {
            return Err(ServiceError::NotReversible);
        }
        if self.state != RegistrationState::Revoked {
            return Err(ServiceError::RegistrationDrift);
        }
        self.registration_revision = self
            .registration_revision
            .next()
            .map_err(|_| ServiceError::RevisionOverflow)?;
        self.state = RegistrationState::Active;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRevocation {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: crate::Revision,
    pub reversible: bool,
    pub revocable: bool,
    pub connected: bool,
    pub native: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationEvidence {
    pub web_acl_pages_observed: u16,
    pub resource_pages_observed: u16,
    pub complete: bool,
    pub cursor_digests: Vec<Digest>,
    pub pagination_digest: Digest,
}

impl PaginationEvidence {
    fn new(
        web_acl_pages_observed: u16,
        resource_pages_observed: u16,
        complete: bool,
        cursor_digests: Vec<Digest>,
    ) -> Self {
        let pagination_digest = Digest::from_parts(
            "aws-waf-pagination/v1",
            &[
                web_acl_pages_observed.to_string(),
                resource_pages_observed.to_string(),
                complete.to_string(),
                cursor_digests
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        );
        Self {
            web_acl_pages_observed,
            resource_pages_observed,
            complete,
            cursor_digests,
            pagination_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub secret_reference_digest: Digest,
    pub list_digest: Digest,
    pub get_digest: Digest,
    pub association_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsWafPostureEvidence {
    pub state: EvidenceState,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub secret_reference_digest: Digest,
    pub provenance: TransportProvenance,
    pub web_acls: Vec<WebAclPostureProjection>,
    pub associations: Vec<AssociationProjection>,
    pub pagination: PaginationEvidence,
    pub page_digests: Vec<Digest>,
    pub digests: EvidenceDigests,
    pub redaction: RedactionSummary,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub can_be_adopted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceMaterial<'a> {
    state: EvidenceState,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    registration_digest: &'a Digest,
    provider_digest: &'a Digest,
    contract_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    provenance: TransportProvenance,
    web_acls: &'a [WebAclPostureProjection],
    associations: &'a [AssociationProjection],
    pagination: &'a PaginationEvidence,
    page_digests: &'a [Digest],
    plugin_version_digest: &'a Digest,
    api_digest: &'a Digest,
    list_digest: &'a Digest,
    get_digest: &'a Digest,
    association_digest: &'a Digest,
    redaction: &'a RedactionSummary,
    connected: bool,
    native: bool,
    first_party: bool,
    provider_receipt: bool,
    can_be_adopted: bool,
}

impl AwsWafPostureEvidence {
    fn recomputed_digest(&self) -> Digest {
        digest_serializable(&EvidenceMaterial {
            state: self.state.clone(),
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            contract_digest: &self.contract_digest,
            secret_reference_digest: &self.secret_reference_digest,
            provenance: self.provenance,
            web_acls: &self.web_acls,
            associations: &self.associations,
            pagination: &self.pagination,
            page_digests: &self.page_digests,
            plugin_version_digest: &self.digests.plugin_version_digest,
            api_digest: &self.digests.api_digest,
            list_digest: &self.digests.list_digest,
            get_digest: &self.digests.get_digest,
            association_digest: &self.digests.association_digest,
            redaction: &self.redaction,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            provider_receipt: self.provider_receipt,
            can_be_adopted: self.can_be_adopted,
        })
    }

    pub fn digest(&self) -> Digest {
        self.digests.evidence_digest.clone()
    }

    pub fn validate_integrity(&self) -> Result<(), ServiceError> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.can_be_adopted
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.digests.evidence_digest != self.recomputed_digest()
            || self.digests.scope_digest != self.scope_digest
            || self.digests.permission_digest != self.permission_digest
            || self.digests.registration_digest != self.registration_digest
            || self.digests.provider_digest != self.provider_digest
            || self.digests.contract_digest != self.contract_digest
            || self.digests.secret_reference_digest != self.secret_reference_digest
            || self.redaction != RedactionSummary::layer_one()
        {
            return Err(ServiceError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn review_eligible(&self) -> bool {
        self.state.clone().review_eligible() && self.pagination.complete
    }
}

pub type EvidenceStatus = EvidenceState;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsWafPostureReadResult {
    pub evidence: AwsWafPostureEvidence,
    pub page_digests: Vec<Digest>,
    pub read_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsWafPostureProposal {
    pub state: EvidenceState,
    pub decision_state: WafDecisionState,
    pub deployment_decision: WafDeploymentDecision,
    pub evidence: AwsWafPostureEvidence,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalMaterial<'a> {
    state: EvidenceState,
    decision_state: WafDecisionState,
    deployment_decision: WafDeploymentDecision,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    proposal_only: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    adopts_outcome: bool,
}

impl AwsWafPostureProposal {
    fn recomputed_digest(&self) -> Digest {
        digest_serializable(&ProposalMaterial {
            state: self.state.clone(),
            decision_state: self.decision_state,
            deployment_decision: self.deployment_decision,
            evidence_digest: &self.evidence_digest,
            registration_digest: &self.registration_digest,
            proposal_only: self.proposal_only,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            adopts_outcome: self.adopts_outcome,
        })
    }

    pub fn digest(&self) -> Digest {
        self.proposal_digest.clone()
    }

    pub fn validate_integrity(&self) -> Result<(), ServiceError> {
        if self.state != self.evidence.state
            || self.evidence_digest != self.evidence.digest()
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.adopts_outcome
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(ServiceError::ProposalTampered);
        }
        self.evidence.validate_integrity()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsWafPostureRecord {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub state: EvidenceState,
    pub recording_digest: Digest,
    pub replayed: bool,
    pub durable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsWafPostureRecord {
    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-waf-recording/v1",
            &[
                self.idempotency_key_digest.to_string(),
                self.proposal_digest.to_string(),
                self.evidence_digest.to_string(),
                format!("{:?}", self.state),
                self.replayed.to_string(),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<(), ServiceError> {
        if self.durable
            || self.connected
            || self.native
            || self.first_party
            || self.recording_digest != self.recomputed_digest()
        {
            return Err(ServiceError::RecordTampered);
        }
        Ok(())
    }
}

pub struct AwsWafPostureService<T: AwsWafTransport> {
    provider: AwsWafPostureProvider<T>,
    definition: AwsWafPostureServiceDefinition,
    registration: AwsWafPostureRegistration,
    records: BTreeMap<Digest, AwsWafPostureRecord>,
}

impl<T: AwsWafTransport> fmt::Debug for AwsWafPostureService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsWafPostureService")
            .field("scope_digest", &self.scope().digest())
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T: AwsWafTransport> AwsWafPostureService<T> {
    pub fn new(
        scope: AwsWafPostureScope,
        secret: SecretReference,
        transport: T,
    ) -> Result<Self, ServiceError> {
        let provider = AwsWafPostureProvider::new(scope, secret, transport)?;
        Self::from_provider(provider)
    }

    pub fn from_provider(provider: AwsWafPostureProvider<T>) -> Result<Self, ServiceError> {
        let registration = AwsWafPostureRegistration::bind(
            provider.scope(),
            provider.secret_reference(),
            provider.definition(),
        )?;
        Ok(Self {
            provider,
            definition: AwsWafPostureServiceDefinition::default(),
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn provider(&self) -> &AwsWafPostureProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsWafPostureProvider<T> {
        &mut self.provider
    }

    pub fn scope(&self) -> &AwsWafPostureScope {
        self.provider.scope()
    }

    pub fn registration(&self) -> &AwsWafPostureRegistration {
        &self.registration
    }

    pub fn service_definition(&self) -> &AwsWafPostureServiceDefinition {
        &self.definition
    }

    pub fn describe_capabilities(&self) -> AwsWafPostureServiceDefinition {
        self.definition.clone()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationRevocation, ServiceError> {
        self.registration.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<(), ServiceError> {
        self.registration.restore()
    }

    pub fn revoke_secret(&mut self) -> Result<(), ServiceError> {
        self.provider.revoke_secret().map_err(ServiceError::Model)
    }

    pub fn restore_secret(&mut self) -> Result<(), ServiceError> {
        self.provider.restore_secret().map_err(ServiceError::Model)
    }

    pub fn read(&mut self) -> Result<AwsWafPostureReadResult, ServiceError> {
        self.read_bounded()
    }

    pub fn read_bounded(&mut self) -> Result<AwsWafPostureReadResult, ServiceError> {
        self.ensure_registration()?;
        let mut web_acl_cursor = None;
        let mut seen_web_acl_cursors = BTreeSet::new();
        let mut web_acl_pages = 0_u16;
        let mut resource_pages = 0_u16;
        let mut request_count = 0_u16;
        let mut page_digests = Vec::new();
        let mut cursor_digests = Vec::new();
        let mut acl_candidates = Vec::new();
        let mut pagination_complete = true;

        loop {
            web_acl_pages = web_acl_pages.saturating_add(1);
            if web_acl_pages > MAX_PAGES {
                return Err(ServiceError::PaginationBound);
            }
            let request = ListWebAclsRequest::new(self.scope(), web_acl_cursor.clone())?;
            consume_request_budget(&mut request_count)?;
            let page = match self.provider.list_web_acls(&request) {
                Ok(page) => page,
                Err(error) => return self.failure_or_error(error, page_digests),
            };
            page_digests.push(page.page_digest.clone());
            if page.partial {
                pagination_complete = false;
            }
            for item in page.items {
                if let Some(allowed) = self.scope().web_acl_allowlist.iter().find(|allowed| {
                    allowed.id() == item.identity.id()
                        && allowed.arn() == item.identity.arn()
                        && allowed.revision() == item.identity.revision()
                }) && !acl_candidates
                    .iter()
                    .any(|candidate: &WebAclReference| candidate.digest() == allowed.digest())
                {
                    acl_candidates.push(allowed.clone());
                }
            }
            match page.next_token {
                Some(next) => {
                    if !seen_web_acl_cursors.insert(next.token_digest.clone()) {
                        return Err(ServiceError::PaginationLoop);
                    }
                    cursor_digests.push(next.token_digest.clone());
                    if web_acl_pages == MAX_PAGES {
                        return Err(ServiceError::PaginationBound);
                    }
                    web_acl_cursor = Some(next);
                }
                None => break,
            }
        }

        let mut projections = Vec::new();
        let mut associations = Vec::new();
        let mut get_digests = Vec::new();
        let mut association_digests = Vec::new();
        let mut list_digests = page_digests.clone();

        if acl_candidates.is_empty() {
            let evidence = self.build_evidence(
                if pagination_complete {
                    EvidenceState::NoMatchingAcl
                } else {
                    EvidenceState::Partial
                },
                projections,
                associations,
                PaginationEvidence::new(
                    web_acl_pages,
                    resource_pages,
                    pagination_complete,
                    cursor_digests,
                ),
                page_digests,
                &[],
                &[],
                &[],
            );
            return Ok(Self::read_result(evidence));
        }

        let matched_acl_count = acl_candidates.len();
        for acl in acl_candidates {
            let get_request = GetWebAclRequest::new(self.scope(), acl.clone())?;
            consume_request_budget(&mut request_count)?;
            let get_response = match self.provider.get_web_acl(&get_request) {
                Ok(response) => response,
                Err(error) => return self.failure_or_error(error, page_digests),
            };
            get_digests.push(get_response.response_digest.clone());
            let rules = get_response
                .details
                .rules
                .iter()
                .map(|rule| RuleActionEvidence {
                    action_class: rule.action_class,
                    rule_count: rule.rule_count,
                })
                .collect::<Vec<_>>();
            if rules.len() > crate::MAX_RULE_SUMMARIES {
                return Err(ServiceError::EvidenceTampered);
            }
            let mut resource_cursor = None;
            let mut seen_resource_cursors = BTreeSet::new();
            let mut associated = Vec::new();
            loop {
                resource_pages = resource_pages.saturating_add(1);
                if resource_pages > MAX_PAGES {
                    return Err(ServiceError::PaginationBound);
                }
                let request = ListResourcesForWebAclRequest::new(
                    self.scope(),
                    acl.clone(),
                    resource_cursor.clone(),
                )?;
                consume_request_budget(&mut request_count)?;
                let page = match self.provider.list_resources_for_web_acl(&request) {
                    Ok(page) => page,
                    Err(error) => return self.failure_or_error(error, page_digests),
                };
                page_digests.push(page.page_digest.clone());
                list_digests.push(page.page_digest.clone());
                if page.partial {
                    pagination_complete = false;
                }
                for association in page.associations {
                    if let Some(allowed) = self.scope().resource_for_arn(association.resource.arn())
                    {
                        if allowed.revision() != association.resource.revision() {
                            return Err(ServiceError::ScopeMismatch);
                        }
                        if !associated
                            .iter()
                            .any(|item: &ResourceReference| item.digest() == allowed.digest())
                        {
                            associated.push(allowed.clone());
                            let association_digest = association.digest(&acl);
                            association_digests.push(association_digest.clone());
                            associations.push(AssociationProjection {
                                web_acl_digest: acl.digest(),
                                resource_digest: allowed.digest(),
                                association_identity_digest: association_digest,
                                resource_revision_digest: Digest::from_parts(
                                    "aws-waf-resource-revision/v1",
                                    &[
                                        allowed.digest().to_string(),
                                        allowed.revision().get().to_string(),
                                    ],
                                ),
                                associated: true,
                            });
                        }
                    }
                }
                match page.next_token {
                    Some(next) => {
                        if !seen_resource_cursors.insert(next.token_digest.clone()) {
                            return Err(ServiceError::PaginationLoop);
                        }
                        cursor_digests.push(next.token_digest.clone());
                        if resource_pages >= MAX_PAGES {
                            return Err(ServiceError::PaginationBound);
                        }
                        resource_cursor = Some(next);
                    }
                    None => break,
                }
            }
            for resource in &self.scope().resource_allowlist {
                if !associated
                    .iter()
                    .any(|item| item.digest() == resource.digest())
                {
                    let association_digest = Digest::from_parts(
                        "aws-waf-association/v1",
                        &[
                            acl.digest().to_string(),
                            resource.digest().to_string(),
                            "not-associated".to_owned(),
                        ],
                    );
                    association_digests.push(association_digest.clone());
                    associations.push(AssociationProjection {
                        web_acl_digest: acl.digest(),
                        resource_digest: resource.digest(),
                        association_identity_digest: association_digest,
                        resource_revision_digest: Digest::from_parts(
                            "aws-waf-resource-revision/v1",
                            &[
                                resource.digest().to_string(),
                                resource.revision().get().to_string(),
                            ],
                        ),
                        associated: false,
                    });
                }
            }
            projections.push(WebAclPostureProjection {
                web_acl_digest: acl.digest(),
                default_action: get_response.details.default_action,
                rules,
                lock_token_digest: get_response.details.lock_token_digest(),
                revision_digest: get_response.details.revision_digest(),
                associated_resource_digests: associated
                    .iter()
                    .map(ResourceReference::digest)
                    .collect(),
            });
        }

        let state = if !pagination_complete {
            EvidenceState::Partial
        } else if matched_acl_count != self.scope().web_acl_allowlist.len() {
            EvidenceState::NoMatchingAcl
        } else {
            EvidenceState::Complete
        };
        let evidence = self.build_evidence(
            state,
            projections,
            associations,
            PaginationEvidence::new(
                web_acl_pages,
                resource_pages,
                pagination_complete,
                cursor_digests,
            ),
            page_digests,
            &list_digests,
            &get_digests,
            &association_digests,
        );
        Ok(Self::read_result(evidence))
    }

    pub fn propose(&mut self) -> Result<AwsWafPostureProposal, ServiceError> {
        let read = self.read_bounded()?;
        self.propose_from_evidence(read.evidence)
    }

    pub fn propose_from_evidence(
        &self,
        evidence: AwsWafPostureEvidence,
    ) -> Result<AwsWafPostureProposal, ServiceError> {
        self.ensure_registration()?;
        self.verify_evidence(&evidence)?;
        let decision_state = decision_state(&evidence);
        let deployment_decision = deployment_decision(decision_state);
        let mut proposal = AwsWafPostureProposal {
            state: evidence.state.clone(),
            decision_state,
            deployment_decision,
            evidence_digest: evidence.digest(),
            evidence,
            registration_digest: self.registration.registration_digest.clone(),
            proposal_digest: Digest::zero(),
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            adopts_outcome: false,
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        Ok(proposal)
    }

    pub fn verify(&self, proposal: &AwsWafPostureProposal) -> Result<(), ServiceError> {
        self.verify_proposal(proposal)
    }

    pub fn verify_proposal(&self, proposal: &AwsWafPostureProposal) -> Result<(), ServiceError> {
        self.ensure_registration()?;
        if proposal.registration_digest != self.registration.registration_digest {
            return Err(ServiceError::ScopeMismatch);
        }
        proposal.validate_integrity()?;
        self.verify_evidence(&proposal.evidence)
    }

    pub fn verify_evidence(&self, evidence: &AwsWafPostureEvidence) -> Result<(), ServiceError> {
        self.ensure_registration()?;
        if evidence.scope_digest != self.scope().digest()
            || evidence.permission_digest != *self.scope().permission_digest()
            || evidence.registration_digest != self.registration.registration_digest
            || evidence.provider_digest != self.provider.provider_digest()
            || evidence.contract_digest != crate::contract_digest()
            || evidence.secret_reference_digest != self.provider.secret_reference().digest()
            || evidence.digests.api_digest != Digest::from_text(AWS_WAF_POSTURE_API_REVISION)
            || evidence.digests.plugin_version_digest
                != Digest::from_text(AWS_WAF_POSTURE_PLUGIN_VERSION)
        {
            return Err(ServiceError::ScopeMismatch);
        }
        evidence.validate_integrity()
    }

    pub fn record(
        &mut self,
        proposal: &AwsWafPostureProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<AwsWafPostureRecord, ServiceError> {
        self.verify_proposal(proposal)?;
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty()
            || idempotency_key.len() > crate::MAX_IDENTIFIER_BYTES
            || idempotency_key.trim() != idempotency_key
            || idempotency_key.chars().any(char::is_control)
        {
            return Err(ServiceError::Model(ModelError::Invalid {
                field: "idempotency key",
            }));
        }
        let key_digest = Digest::from_text(idempotency_key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ServiceError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.recomputed_digest();
            return Ok(replay);
        }
        let mut record = AwsWafPostureRecord {
            idempotency_key_digest: key_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digest(),
            state: proposal.state.clone(),
            recording_digest: Digest::zero(),
            replayed: false,
            durable: false,
            connected: false,
            native: false,
            first_party: false,
        };
        record.recording_digest = record.recomputed_digest();
        self.records.insert(key_digest, record.clone());
        Ok(record)
    }

    pub fn verify_record(&self, record: &AwsWafPostureRecord) -> Result<(), ServiceError> {
        record.validate_integrity()
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    fn read_result(evidence: AwsWafPostureEvidence) -> AwsWafPostureReadResult {
        let page_digests = evidence.page_digests.clone();
        let read_digest = Digest::from_parts(
            "aws-waf-read/v1",
            &[
                evidence.digests.evidence_digest.to_string(),
                page_digests
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        );
        AwsWafPostureReadResult {
            evidence,
            page_digests,
            read_digest,
        }
    }

    fn build_evidence(
        &self,
        state: EvidenceState,
        web_acls: Vec<WebAclPostureProjection>,
        associations: Vec<AssociationProjection>,
        pagination: PaginationEvidence,
        page_digests: Vec<Digest>,
        list_digests: &[Digest],
        get_digests: &[Digest],
        association_digests: &[Digest],
    ) -> AwsWafPostureEvidence {
        let list_digest = Digest::from_parts(
            "aws-waf-list-evidence/v1",
            &[list_digests
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")],
        );
        let get_digest = Digest::from_parts(
            "aws-waf-get-evidence/v1",
            &[get_digests
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")],
        );
        let association_digest = Digest::from_parts(
            "aws-waf-association-evidence/v1",
            &[association_digests
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")],
        );
        let mut evidence = AwsWafPostureEvidence {
            state,
            scope_digest: self.scope().digest(),
            permission_digest: self.scope().permission_digest().clone(),
            registration_digest: self.registration.registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            contract_digest: crate::contract_digest(),
            secret_reference_digest: self.provider.secret_reference().digest(),
            provenance: self.provider.provenance(),
            web_acls,
            associations,
            pagination,
            page_digests,
            digests: EvidenceDigests {
                plugin_version_digest: Digest::from_text(AWS_WAF_POSTURE_PLUGIN_VERSION),
                contract_digest: crate::contract_digest(),
                provider_digest: self.provider.provider_digest(),
                api_digest: Digest::from_text(AWS_WAF_POSTURE_API_REVISION),
                permission_digest: self.scope().permission_digest().clone(),
                scope_digest: self.scope().digest(),
                registration_digest: self.registration.registration_digest.clone(),
                secret_reference_digest: self.provider.secret_reference().digest(),
                list_digest,
                get_digest,
                association_digest,
                evidence_digest: Digest::zero(),
            },
            redaction: RedactionSummary::layer_one(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            can_be_adopted: false,
        };
        evidence.digests.evidence_digest = evidence.recomputed_digest();
        evidence
    }

    fn ensure_registration(&self) -> Result<(), ServiceError> {
        if !self.registration.is_active() {
            return Err(ServiceError::RegistrationRevoked);
        }
        self.registration.validate(
            self.scope(),
            self.provider.secret_reference(),
            self.provider.definition(),
        )
    }

    fn failure_or_error(
        &self,
        error: AwsWafProviderError,
        page_digests: Vec<Digest>,
    ) -> Result<AwsWafPostureReadResult, ServiceError> {
        match error {
            AwsWafProviderError::Transport(transport) => {
                let state = match transport {
                    TransportError::BlockedEnv | TransportError::HttpStatus(401 | 403 | 404) => {
                        EvidenceState::AccessLoss
                    }
                    TransportError::Throttled | TransportError::HttpStatus(429) => {
                        EvidenceState::Throttled
                    }
                    TransportError::Timeout => EvidenceState::Timeout,
                    TransportError::ProviderUnknown
                    | TransportError::HttpStatus(_)
                    | TransportError::ResponseTooLarge
                    | TransportError::MalformedResponse => EvidenceState::ProviderUnknown,
                };
                let evidence = self.build_evidence(
                    state,
                    Vec::new(),
                    Vec::new(),
                    PaginationEvidence::new(0, 0, false, Vec::new()),
                    page_digests,
                    &[],
                    &[],
                    &[],
                );
                Ok(Self::read_result(evidence))
            }
            AwsWafProviderError::SecretRevoked => Err(ServiceError::SecretRevoked),
            AwsWafProviderError::RegistrationRevoked => Err(ServiceError::RegistrationRevoked),
            AwsWafProviderError::ScopeMismatch
            | AwsWafProviderError::LockTokenDrift
            | AwsWafProviderError::RevisionDrift
            | AwsWafProviderError::PaginationDrift => Err(ServiceError::ScopeMismatch),
            AwsWafProviderError::ResponseTooLarge | AwsWafProviderError::MalformedResponse => {
                Err(ServiceError::EvidenceTampered)
            }
            AwsWafProviderError::Model(error) => Err(ServiceError::Model(error)),
        }
    }
}

fn decision_state(evidence: &AwsWafPostureEvidence) -> WafDecisionState {
    match evidence.state {
        EvidenceState::AccessLoss => WafDecisionState::AccessLoss,
        EvidenceState::Throttled => WafDecisionState::Throttled,
        EvidenceState::Timeout => WafDecisionState::Timeout,
        EvidenceState::ProviderUnknown | EvidenceState::RegistrationRevoked => {
            WafDecisionState::ProviderUnknown
        }
        EvidenceState::ScopeDrift => WafDecisionState::ScopeDrift,
        EvidenceState::RevisionDrift => WafDecisionState::RevisionDrift,
        EvidenceState::Partial | EvidenceState::NoMatchingAcl => WafDecisionState::InsufficientData,
        EvidenceState::Complete => {
            let mut resource_associations = BTreeMap::<Digest, bool>::new();
            for association in &evidence.associations {
                resource_associations
                    .entry(association.resource_digest.clone())
                    .and_modify(|associated| *associated |= association.associated)
                    .or_insert(association.associated);
            }
            let all_resources_associated = !resource_associations.is_empty()
                && resource_associations.values().all(|associated| *associated);
            if all_resources_associated {
                WafDecisionState::Protected
            } else {
                WafDecisionState::NotProtected
            }
        }
    }
}

fn consume_request_budget(request_count: &mut u16) -> Result<(), ServiceError> {
    *request_count = request_count.saturating_add(1);
    if *request_count > MAX_REQUESTS_PER_READ {
        Err(ServiceError::PaginationBound)
    } else {
        Ok(())
    }
}

fn deployment_decision(state: WafDecisionState) -> WafDeploymentDecision {
    match state {
        WafDecisionState::NotProtected => WafDeploymentDecision::Block,
        WafDecisionState::Protected => WafDeploymentDecision::Review,
        WafDecisionState::InsufficientData
        | WafDecisionState::AccessLoss
        | WafDecisionState::Throttled
        | WafDecisionState::Timeout
        | WafDecisionState::ProviderUnknown
        | WafDecisionState::RevisionDrift
        | WafDecisionState::ScopeDrift => WafDeploymentDecision::InsufficientEvidence,
    }
}

pub type AwsWafPostureProposalResult = AwsWafPostureProposal;
pub type AwsWafPostureRecordReceipt = AwsWafPostureRecord;
pub type AwsWafPostureRegistrationReceipt = RegistrationRevocation;
pub type AwsWafService<T> = AwsWafPostureService<T>;
pub type AwsWafPostureServiceError = ServiceError;
