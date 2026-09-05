//! Typed service, proposal, verification, and reversible registration.

use std::fmt;

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsEntityResolutionConsumer;
use crate::error::{AwsEntityResolutionError, AwsEntityResolutionTransportError, Result};
use crate::model::{
    AwsEntityResolutionScope, Digest, EvidenceDigests, MatchStatus, PermissionSnapshot,
    ProjectScope, SecretReference, TransportProvenance,
};
use crate::provider::{
    AwsEntityResolutionOperation, AwsEntityResolutionProvider,
    AwsEntityResolutionProviderDefinition, AwsEntityResolutionTransport, GetIdNamespaceRequest,
    GetMatchIdRequest, GetMatchIdResponse, GetMatchingWorkflowRequest, GetSchemaMappingRequest,
    IdNamespaceResponse, ListIdNamespacesRequest, MatchingWorkflowResponse, SchemaMappingResponse,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_VERSION, PROVIDER_ID,
    SERVICE_ID, contract_digest, evidence_contract_digest,
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
            "aws-entity-resolution-registration-transition/v1",
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

/// Version/contract/provider/permission/evidence/scope/secret-bound
/// registration. The secret handle itself is never retained or serialized.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsEntityResolutionRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    evidence_contract_digest: Digest,
    scope: AwsEntityResolutionScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl AwsEntityResolutionRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsEntityResolutionScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: &AwsEntityResolutionProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_snapshot,
            evidence_contract_digest: evidence_contract_digest(),
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-aws-entity-resolution-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
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

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_snapshot.permission_digest
    }

    pub fn evidence_contract_digest(&self) -> &Digest {
        &self.evidence_contract_digest
    }

    pub fn scope(&self) -> &AwsEntityResolutionScope {
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

    pub fn validate(&self) -> Result<()> {
        if !valid_registration_id(&self.id)
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.registration_revision == 0
            || self.evidence_contract_digest != evidence_contract_digest()
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.calculate_digest()
        {
            return Err(AwsEntityResolutionError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        let mut expected_permissions = crate::LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<Vec<_>>();
        expected_permissions.sort();
        if self.permission_snapshot.permissions != expected_permissions {
            return Err(AwsEntityResolutionError::PermissionDrift);
        }
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsEntityResolutionError::RegistrationReversed);
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
            return Err(AwsEntityResolutionError::RegistrationReversed);
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
            return Err(AwsEntityResolutionError::RegistrationReversed);
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
            "aws-entity-resolution-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot
                        .permission_digest
                        .as_str()
                        .to_owned(),
                ),
                (
                    "evidence",
                    self.evidence_contract_digest.as_str().to_owned(),
                ),
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

impl fmt::Debug for AwsEntityResolutionRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEntityResolutionRegistration")
            .field("id", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest())
            .field("evidence_contract_digest", &self.evidence_contract_digest)
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for AwsEntityResolutionRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsEntityResolutionRegistration", 16)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", self.permission_digest())?;
        state.serialize_field("evidenceContractDigest", &self.evidence_contract_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

fn valid_registration_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub evidence_level: String,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub identity_mutation: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityResolutionEvidenceRequest {
    pub scope_digest: Digest,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub apply_normalization: bool,
    pub max_pages: u16,
}

impl EntityResolutionEvidenceRequest {
    pub fn new(
        scope: &AwsEntityResolutionScope,
        provider: &AwsEntityResolutionProviderDefinition,
        registration: &AwsEntityResolutionRegistration,
        apply_normalization: bool,
        max_pages: u16,
    ) -> Result<Self> {
        scope.validate()?;
        provider.validate()?;
        registration.validate()?;
        if max_pages == 0 || max_pages > crate::MAX_PAGES {
            return Err(AwsEntityResolutionError::InvalidRequest);
        }
        if scope.source_record_fingerprint().apply_normalization != apply_normalization {
            return Err(AwsEntityResolutionError::ScopeMismatch);
        }
        Ok(Self {
            scope_digest: scope.digest(),
            expected_provider_digest: provider.provider_digest.clone(),
            expected_registration_digest: registration.registration_digest.clone(),
            apply_normalization,
            max_pages,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-entity-resolution-evidence-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "provider",
                    self.expected_provider_digest.as_str().to_owned(),
                ),
                (
                    "registration",
                    self.expected_registration_digest.as_str().to_owned(),
                ),
                ("normalization", self.apply_normalization.to_string()),
                ("max_pages", self.max_pages.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: AwsEntityResolutionOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(
        operation: AwsEntityResolutionOperation,
        error: &AwsEntityResolutionTransportError,
    ) -> Self {
        Self {
            operation,
            status_code: error.status_code(),
            category: error.category().to_owned(),
            failure_digest: Digest::from_parts(
                "aws-entity-resolution-failure/v1",
                &[
                    ("operation", operation.as_str().to_owned()),
                    ("category", error.category().to_owned()),
                    (
                        "status",
                        error
                            .status_code()
                            .map_or_else(String::new, |status| status.to_string()),
                    ),
                ],
            ),
        }
    }

    fn internal(operation: AwsEntityResolutionOperation, category: &'static str) -> Self {
        Self {
            operation,
            status_code: None,
            category: category.to_owned(),
            failure_digest: Digest::from_parts(
                "aws-entity-resolution-failure/v1",
                &[
                    ("operation", operation.as_str().to_owned()),
                    ("category", category.to_owned()),
                ],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsEntityResolutionResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub project: ProjectScope,
    pub mission: crate::model::MissionScope,
    pub work_product: crate::model::WorkProductScope,
    pub namespace_metadata: Option<crate::model::IdNamespaceMetadata>,
    pub workflow_metadata: Option<crate::model::MatchingWorkflowMetadata>,
    pub schema_metadata: Option<crate::model::SchemaMappingMetadata>,
    pub source_record_fingerprint_digest: Digest,
    pub status: MatchStatus,
    pub namespace_pages: u16,
    pub namespace_complete: bool,
    pub evidence: EvidenceDigests,
    pub failure: Option<FailureEvidence>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub identity_certainty: bool,
    pub causal_attribution: bool,
    pub identity_map_retained: bool,
    pub s3_output_retained: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsEntityResolutionResultProposal {
    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.identity_certainty
            || self.causal_attribution
            || self.identity_map_retained
            || self.s3_output_retained
            || self.outcome_adopted
            || self.work_product_adopted
            || self.source_record_fingerprint_digest
                != self.evidence.source_record_fingerprint_digest
            || (!self.namespace_complete
                && matches!(
                    self.status,
                    MatchStatus::Matched | MatchStatus::Unmatched | MatchStatus::Ambiguous
                ))
        {
            return Err(AwsEntityResolutionError::TamperedEvidence);
        }
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        self.evidence.validate()?;
        for metadata in [
            self.namespace_metadata
                .as_ref()
                .map(|value| value.validate()),
            self.workflow_metadata
                .as_ref()
                .map(|value| value.validate()),
            self.schema_metadata.as_ref().map(|value| value.validate()),
        ]
        .into_iter()
        .flatten()
        {
            metadata?;
        }
        let expected_evidence = calculate_evidence_digest(
            &self.evidence,
            self.status,
            self.provenance,
            self.namespace_pages,
            self.namespace_complete,
            self.failure.as_ref(),
        );
        if expected_evidence != self.evidence.evidence_digest {
            return Err(AwsEntityResolutionError::EvidenceDrift);
        }
        if self.proposal_digest != calculate_proposal_digest(self) {
            return Err(AwsEntityResolutionError::TamperedEvidence);
        }
        Ok(())
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

fn calculate_evidence_digest(
    evidence: &EvidenceDigests,
    status: MatchStatus,
    provenance: TransportProvenance,
    namespace_pages: u16,
    namespace_complete: bool,
    failure: Option<&FailureEvidence>,
) -> Digest {
    Digest::from_parts(
        "aws-entity-resolution-evidence/v1",
        &[
            ("plugin", evidence.plugin_version_digest.as_str().to_owned()),
            ("contract", evidence.contract_digest.as_str().to_owned()),
            ("provider", evidence.provider_digest.as_str().to_owned()),
            ("permission", evidence.permission_digest.as_str().to_owned()),
            ("scope", evidence.scope_digest.as_str().to_owned()),
            (
                "namespace",
                evidence
                    .namespace_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "workflow",
                evidence
                    .workflow_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "schema",
                evidence
                    .schema_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "record",
                evidence
                    .source_record_fingerprint_digest
                    .as_str()
                    .to_owned(),
            ),
            ("request", evidence.request_digest.as_str().to_owned()),
            (
                "group",
                evidence
                    .match_group_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "rule",
                evidence
                    .match_rule_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            ("result", evidence.result_digest.as_str().to_owned()),
            ("status", format!("{status:?}")),
            ("provenance", provenance.as_str().to_owned()),
            ("pages", namespace_pages.to_string()),
            ("complete", namespace_complete.to_string()),
            (
                "failure",
                failure.map_or_else(String::new, |value| {
                    value.failure_digest.as_str().to_owned()
                }),
            ),
        ],
    )
}

fn calculate_proposal_digest(proposal: &AwsEntityResolutionResultProposal) -> Digest {
    Digest::from_parts(
        "aws-entity-resolution-proposal/v1",
        &[
            ("service", proposal.service_id.clone()),
            ("consumer", proposal.consumer_id.clone()),
            (
                "registration",
                proposal.registration_digest.as_str().to_owned(),
            ),
            ("scope", proposal.scope_digest.as_str().to_owned()),
            ("project", proposal.project.digest().as_str().to_owned()),
            ("mission", proposal.mission.digest().as_str().to_owned()),
            (
                "work_product",
                proposal.work_product.digest().as_str().to_owned(),
            ),
            ("status", format!("{:?}", proposal.status)),
            (
                "namespace",
                proposal
                    .namespace_metadata
                    .as_ref()
                    .map_or_else(String::new, |value| {
                        value.metadata_digest.as_str().to_owned()
                    }),
            ),
            (
                "workflow",
                proposal
                    .workflow_metadata
                    .as_ref()
                    .map_or_else(String::new, |value| {
                        value.metadata_digest.as_str().to_owned()
                    }),
            ),
            (
                "schema",
                proposal
                    .schema_metadata
                    .as_ref()
                    .map_or_else(String::new, |value| {
                        value.metadata_digest.as_str().to_owned()
                    }),
            ),
            (
                "record",
                proposal
                    .source_record_fingerprint_digest
                    .as_str()
                    .to_owned(),
            ),
            (
                "evidence",
                proposal.evidence.evidence_digest.as_str().to_owned(),
            ),
            ("provenance", proposal.provenance.as_str().to_owned()),
        ],
    )
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    InvalidIntegrity,
    RegistrationDrift,
    ScopeDrift,
    PermissionDrift,
    ProviderDrift,
    PartialEvidence,
    AccessLoss,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
}

impl VerificationReport {
    fn invalid(failure: VerificationFailure) -> Self {
        Self {
            valid: false,
            review_eligible: false,
            failures: vec![failure],
        }
    }
}

/// Typed service facade for one exact Entity Resolution scope.
pub struct AwsEntityResolutionResultService<T: AwsEntityResolutionTransport> {
    scope: AwsEntityResolutionScope,
    registration: AwsEntityResolutionRegistration,
    provider: AwsEntityResolutionProvider<T>,
}

impl<T: AwsEntityResolutionTransport> fmt::Debug for AwsEntityResolutionResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEntityResolutionResultService")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: AwsEntityResolutionTransport> AwsEntityResolutionResultService<T> {
    pub fn new(
        scope: AwsEntityResolutionScope,
        secret_reference: SecretReference,
        provider: AwsEntityResolutionProvider<T>,
        registration_revision: u64,
    ) -> Result<Self> {
        let permission_snapshot = PermissionSnapshot::for_layer_one(registration_revision)?;
        let registration = AwsEntityResolutionRegistration::new(
            format!("aws-entity-resolution-{registration_revision}"),
            scope.clone(),
            secret_reference,
            permission_snapshot,
            provider.definition(),
            registration_revision,
        )?;
        Ok(Self {
            scope,
            registration,
            provider,
        })
    }

    pub fn scope(&self) -> &AwsEntityResolutionScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsEntityResolutionRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &AwsEntityResolutionProvider<T> {
        &self.provider
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec![
                "ListIdNamespaces".to_owned(),
                "GetIdNamespace".to_owned(),
                "GetMatchingWorkflow".to_owned(),
                "GetSchemaMapping".to_owned(),
                "GetMatchId".to_owned(),
            ],
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            evidence_level: EVIDENCE_LEVEL.to_owned(),
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            identity_mutation: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }

    pub fn default_request(&self) -> Result<EntityResolutionEvidenceRequest> {
        EntityResolutionEvidenceRequest::new(
            &self.scope,
            self.provider.definition(),
            &self.registration,
            self.scope.source_record_fingerprint().apply_normalization,
            crate::MAX_PAGES,
        )
    }

    pub fn request(
        &self,
        apply_normalization: bool,
        max_pages: u16,
    ) -> Result<EntityResolutionEvidenceRequest> {
        EntityResolutionEvidenceRequest::new(
            &self.scope,
            self.provider.definition(),
            &self.registration,
            apply_normalization,
            max_pages,
        )
    }

    pub fn propose(
        &mut self,
        request: EntityResolutionEvidenceRequest,
    ) -> Result<AwsEntityResolutionResultProposal> {
        self.validate_request(&request)?;
        if !self.registration.is_active() {
            return Err(AwsEntityResolutionError::RegistrationRevoked);
        }
        let mut namespaces = Vec::new();
        let mut next_token_digest = None;
        let mut list_pages = 0;
        let mut list_complete = false;
        let mut list_digest = None;
        loop {
            list_pages += 1;
            let list_request = ListIdNamespacesRequest::new(
                &self.scope,
                crate::MAX_PAGE_SIZE,
                list_pages,
                next_token_digest.clone(),
            )?;
            let response = match self.provider.list_id_namespaces(&list_request) {
                Ok(response) => response,
                Err(error) => {
                    return Ok(self.failure_proposal(
                        &request,
                        MatchStatus::from_transport(&error),
                        FailureEvidence::from_transport(
                            AwsEntityResolutionOperation::ListIdNamespaces,
                            &error,
                        ),
                        list_pages,
                        list_complete,
                        list_digest,
                        self.provider.provenance(),
                    ));
                }
            };
            if response.provenance != self.provider.provenance() {
                return Ok(self.failure_proposal(
                    &request,
                    MatchStatus::Tampered,
                    FailureEvidence::internal(
                        AwsEntityResolutionOperation::ListIdNamespaces,
                        "provenance_drift",
                    ),
                    list_pages,
                    list_complete,
                    list_digest,
                    response.provenance,
                ));
            }
            if response.validate_integrity(&list_request).is_err() {
                return Ok(self.failure_proposal(
                    &request,
                    MatchStatus::Tampered,
                    FailureEvidence::internal(
                        AwsEntityResolutionOperation::ListIdNamespaces,
                        "tampered_response",
                    ),
                    list_pages,
                    list_complete,
                    list_digest,
                    response.provenance,
                ));
            }
            namespaces.extend(response.namespaces);
            list_digest = Some(response.response_digest);
            next_token_digest = response.next_token_digest;
            if next_token_digest.is_none() {
                list_complete = true;
                break;
            }
            if list_pages >= request.max_pages {
                break;
            }
        }
        if !list_complete {
            return Ok(self.failure_proposal(
                &request,
                MatchStatus::Partial,
                FailureEvidence::internal(
                    AwsEntityResolutionOperation::ListIdNamespaces,
                    "page_bound_reached",
                ),
                list_pages,
                false,
                list_digest,
                self.provider.provenance(),
            ));
        }

        let target_namespace_name_digest = self.scope.id_namespace().name().digest();
        if namespaces
            .iter()
            .all(|namespace| namespace.name_digest != target_namespace_name_digest)
        {
            return Ok(self.failure_proposal(
                &request,
                MatchStatus::ProviderUnknown,
                FailureEvidence::internal(
                    AwsEntityResolutionOperation::ListIdNamespaces,
                    "target_namespace_absent",
                ),
                list_pages,
                list_complete,
                list_digest,
                self.provider.provenance(),
            ));
        }

        let namespace_request = GetIdNamespaceRequest::for_scope(&self.scope)?;
        let namespace_response = match self.provider.get_id_namespace(&namespace_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.failure_proposal(
                    &request,
                    MatchStatus::from_transport(&error),
                    FailureEvidence::from_transport(
                        AwsEntityResolutionOperation::GetIdNamespace,
                        &error,
                    ),
                    list_pages,
                    list_complete,
                    list_digest,
                    self.provider.provenance(),
                ));
            }
        };
        if namespace_response.provenance != self.provider.provenance()
            || namespace_response
                .validate_integrity(&namespace_request)
                .is_err()
        {
            return Ok(self.failure_proposal(
                &request,
                MatchStatus::Tampered,
                FailureEvidence::internal(
                    AwsEntityResolutionOperation::GetIdNamespace,
                    "tampered_response",
                ),
                list_pages,
                list_complete,
                list_digest,
                namespace_response.provenance,
            ));
        }

        let workflow_request = GetMatchingWorkflowRequest::for_scope(&self.scope)?;
        let workflow_response = match self.provider.get_matching_workflow(&workflow_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.failure_proposal(
                    &request,
                    MatchStatus::from_transport(&error),
                    FailureEvidence::from_transport(
                        AwsEntityResolutionOperation::GetMatchingWorkflow,
                        &error,
                    ),
                    list_pages,
                    list_complete,
                    list_digest,
                    self.provider.provenance(),
                ));
            }
        };
        if workflow_response.provenance != self.provider.provenance()
            || workflow_response
                .validate_integrity(&workflow_request)
                .is_err()
        {
            return Ok(self.failure_proposal(
                &request,
                MatchStatus::Tampered,
                FailureEvidence::internal(
                    AwsEntityResolutionOperation::GetMatchingWorkflow,
                    "tampered_response",
                ),
                list_pages,
                list_complete,
                list_digest,
                workflow_response.provenance,
            ));
        }

        let schema_request = GetSchemaMappingRequest::for_scope(&self.scope)?;
        let schema_response = match self.provider.get_schema_mapping(&schema_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.failure_proposal(
                    &request,
                    MatchStatus::from_transport(&error),
                    FailureEvidence::from_transport(
                        AwsEntityResolutionOperation::GetSchemaMapping,
                        &error,
                    ),
                    list_pages,
                    list_complete,
                    list_digest,
                    self.provider.provenance(),
                ));
            }
        };
        if schema_response.provenance != self.provider.provenance()
            || schema_response.validate_integrity(&schema_request).is_err()
        {
            return Ok(self.failure_proposal(
                &request,
                MatchStatus::Tampered,
                FailureEvidence::internal(
                    AwsEntityResolutionOperation::GetSchemaMapping,
                    "tampered_response",
                ),
                list_pages,
                list_complete,
                list_digest,
                schema_response.provenance,
            ));
        }
        if namespace_response.metadata.name_digest != self.scope.id_namespace().name().digest()
            || workflow_response.metadata.name_digest
                != self.scope.matching_workflow().name().digest()
            || schema_response.metadata.name_digest != self.scope.schema_mapping().name().digest()
            || workflow_response.metadata.schema_mapping_digest
                != schema_response.metadata.metadata_digest
            || workflow_response.metadata.id_namespace_digest.as_ref()
                != Some(&namespace_response.metadata.metadata_digest)
        {
            return Ok(self.failure_proposal(
                &request,
                MatchStatus::Tampered,
                FailureEvidence::internal(
                    AwsEntityResolutionOperation::GetSchemaMapping,
                    "metadata_scope_drift",
                ),
                list_pages,
                list_complete,
                list_digest,
                self.provider.provenance(),
            ));
        }

        let match_request = GetMatchIdRequest::for_scope(&self.scope, request.apply_normalization)?;
        let match_response = match self.provider.get_match_id(&match_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.failure_proposal(
                    &request,
                    MatchStatus::from_transport(&error),
                    FailureEvidence::from_transport(
                        AwsEntityResolutionOperation::GetMatchId,
                        &error,
                    ),
                    list_pages,
                    list_complete,
                    list_digest,
                    self.provider.provenance(),
                ));
            }
        };
        if match_response.provenance != self.provider.provenance()
            || match_response.validate_integrity(&match_request).is_err()
        {
            return Ok(self.failure_proposal(
                &request,
                MatchStatus::Tampered,
                FailureEvidence::internal(
                    AwsEntityResolutionOperation::GetMatchId,
                    "tampered_response",
                ),
                list_pages,
                list_complete,
                list_digest,
                match_response.provenance,
            ));
        }

        Ok(self.success_proposal(
            &request,
            namespace_response,
            workflow_response,
            schema_response,
            match_response,
            list_pages,
            list_complete,
            list_digest,
        ))
    }

    pub fn verify(&self, proposal: &AwsEntityResolutionResultProposal) -> VerificationReport {
        if !self.registration.is_active() {
            return VerificationReport::invalid(VerificationFailure::Revoked);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            return VerificationReport::invalid(VerificationFailure::RegistrationDrift);
        }
        if proposal.scope_digest != self.scope.digest()
            || proposal.project != *self.scope.project()
            || proposal.mission != *self.scope.mission()
            || proposal.work_product != *self.scope.work_product()
        {
            return VerificationReport::invalid(VerificationFailure::ScopeDrift);
        }
        if proposal.status == MatchStatus::Partial {
            return VerificationReport::invalid(VerificationFailure::PartialEvidence);
        }
        if proposal.status == MatchStatus::AccessLost {
            return VerificationReport::invalid(VerificationFailure::AccessLoss);
        }
        if proposal.status == MatchStatus::Tampered {
            return VerificationReport::invalid(VerificationFailure::InvalidIntegrity);
        }
        if proposal.validate_integrity().is_err() {
            return VerificationReport::invalid(VerificationFailure::InvalidIntegrity);
        }
        VerificationReport {
            valid: true,
            review_eligible: true,
            failures: Vec::new(),
        }
    }

    pub fn consumer(&self) -> Result<MissionAwsEntityResolutionConsumer> {
        MissionAwsEntityResolutionConsumer::new(self.scope.clone(), self.registration.clone())
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

    fn validate_request(&self, request: &EntityResolutionEvidenceRequest) -> Result<()> {
        if request.scope_digest != self.scope.digest()
            || request.expected_provider_digest != self.provider.definition().provider_digest
            || request.expected_registration_digest != *self.registration.registration_digest()
        {
            return Err(AwsEntityResolutionError::ScopeMismatch);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn success_proposal(
        &self,
        request: &EntityResolutionEvidenceRequest,
        namespace_response: IdNamespaceResponse,
        workflow_response: MatchingWorkflowResponse,
        schema_response: SchemaMappingResponse,
        match_response: GetMatchIdResponse,
        namespace_pages: u16,
        namespace_complete: bool,
        list_digest: Option<Digest>,
    ) -> AwsEntityResolutionResultProposal {
        let status = match_response.status;
        let evidence = evidence_for(
            &self.registration,
            &self.scope,
            request,
            Some(namespace_response.metadata.metadata_digest.clone()),
            Some(workflow_response.metadata.metadata_digest.clone()),
            Some(schema_response.metadata.metadata_digest.clone()),
            match_response,
            namespace_pages,
            namespace_complete,
            list_digest,
            None,
            self.provider.provenance(),
            status,
        );
        let mut proposal = AwsEntityResolutionResultProposal {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: self.registration.registration_digest.clone(),
            scope_digest: self.scope.digest(),
            project: self.scope.project().clone(),
            mission: self.scope.mission().clone(),
            work_product: self.scope.work_product().clone(),
            namespace_metadata: Some(namespace_response.metadata),
            workflow_metadata: Some(workflow_response.metadata),
            schema_metadata: Some(schema_response.metadata),
            source_record_fingerprint_digest: self.scope.source_record_fingerprint().digest(),
            status,
            namespace_pages,
            namespace_complete,
            evidence,
            failure: None,
            provenance: self.provider.provenance(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            identity_certainty: false,
            causal_attribution: false,
            identity_map_retained: false,
            s3_output_retained: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-aws-entity-resolution-proposal"),
        };
        proposal.proposal_digest = calculate_proposal_digest(&proposal);
        proposal
    }

    #[allow(clippy::too_many_arguments)]
    fn failure_proposal(
        &self,
        request: &EntityResolutionEvidenceRequest,
        status: MatchStatus,
        failure: FailureEvidence,
        namespace_pages: u16,
        namespace_complete: bool,
        list_digest: Option<Digest>,
        provenance: TransportProvenance,
    ) -> AwsEntityResolutionResultProposal {
        let match_response = GetMatchIdResponse::new(
            &GetMatchIdRequest::for_scope(
                &self.scope,
                self.scope.source_record_fingerprint().apply_normalization,
            )
            .expect("validated scope request"),
            status,
            None,
            None,
            1,
            provenance,
        )
        .expect("bounded failure response");
        let evidence = evidence_for(
            &self.registration,
            &self.scope,
            request,
            None,
            None,
            None,
            match_response,
            namespace_pages,
            namespace_complete,
            list_digest,
            Some(&failure),
            provenance,
            status,
        );
        let mut proposal = AwsEntityResolutionResultProposal {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: self.registration.registration_digest.clone(),
            scope_digest: self.scope.digest(),
            project: self.scope.project().clone(),
            mission: self.scope.mission().clone(),
            work_product: self.scope.work_product().clone(),
            namespace_metadata: None,
            workflow_metadata: None,
            schema_metadata: None,
            source_record_fingerprint_digest: self.scope.source_record_fingerprint().digest(),
            status,
            namespace_pages,
            namespace_complete,
            evidence,
            failure: Some(failure),
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            identity_certainty: false,
            causal_attribution: false,
            identity_map_retained: false,
            s3_output_retained: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-aws-entity-resolution-proposal"),
        };
        proposal.proposal_digest = calculate_proposal_digest(&proposal);
        proposal
    }
}

#[allow(clippy::too_many_arguments)]
fn evidence_for(
    registration: &AwsEntityResolutionRegistration,
    scope: &AwsEntityResolutionScope,
    request: &EntityResolutionEvidenceRequest,
    namespace_digest: Option<Digest>,
    workflow_digest: Option<Digest>,
    schema_digest: Option<Digest>,
    match_response: GetMatchIdResponse,
    namespace_pages: u16,
    namespace_complete: bool,
    list_digest: Option<Digest>,
    failure: Option<&FailureEvidence>,
    provenance: TransportProvenance,
    status: MatchStatus,
) -> EvidenceDigests {
    let mut evidence = EvidenceDigests {
        plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
        contract_digest: registration.contract_digest.clone(),
        provider_digest: registration.provider_digest.clone(),
        permission_digest: registration.permission_snapshot.permission_digest.clone(),
        scope_digest: scope.digest(),
        namespace_digest,
        workflow_digest,
        schema_digest,
        source_record_fingerprint_digest: scope.source_record_fingerprint().digest(),
        request_digest: Digest::from_parts(
            "aws-entity-resolution-read-request/v1",
            &[
                ("evidence", request.digest().as_str().to_owned()),
                (
                    "list",
                    list_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("match", match_response.request_digest.as_str().to_owned()),
            ],
        ),
        match_group_digest: match_response.match_group_digest,
        match_rule_digest: match_response.match_rule_digest,
        result_digest: match_response.result_digest,
        evidence_digest: Digest::from_text("unsealed-aws-entity-resolution-evidence"),
    };
    evidence.evidence_digest = calculate_evidence_digest(
        &evidence,
        status,
        provenance,
        namespace_pages,
        namespace_complete,
        failure,
    );
    evidence
}

impl MatchStatus {
    fn from_transport(error: &AwsEntityResolutionTransportError) -> Self {
        if error.is_access_loss() {
            Self::AccessLost
        } else if matches!(error, AwsEntityResolutionTransportError::Partial) {
            Self::Partial
        } else {
            Self::ProviderUnknown
        }
    }
}

pub type AwsEntityResolutionRegistrationAlias = AwsEntityResolutionRegistration;
pub type AwsEntityResolutionResult = AwsEntityResolutionResultProposal;
